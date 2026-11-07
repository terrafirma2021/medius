/* Medius v3.4.7 device: NVS handle, partition and iterator lifetimes. */
#include "../include/types.h"

/* Native entry: 0x42012a0c. */
/* Original function-byte SHA-256:
 * fc20eafec374f8550ff8b6cb49ce919b7ef5bcf86951657c17825129ad410b3d. */
/* Open implementation reached after the default wrapper checks Lock::init.
 * Construct NVS lock, obtain manager and call open_handle with all five
 * arguments, including local object-out. Propagate error without touching
 * caller output. Success allocates20 bytes for NVSHandleEntry. Allocation
 * failure deletes the saved nonnull object via virtual slot4 and returns101.
 * No independent partition/namespace/mode/output validation or manager check.
 * On allocation success read serial WORD then tail pointer, increment serial
 * modulo32, store object, global serial, entry handle, partition-name pointer.
 * The partition name is borrowed. Link old-tail->next if present, store prev,
 * sample HEAD, store next=NULL, publish TAIL, publish HEAD only if sampled
 * NULL, increment LIVE list-count WORD, then publish caller handle. Do not
 * skip serial0 after wrap or make output atomic. Unlock before return. */
int nvs_open_from_partition(const char *partition,const char *namespace_name,
    int mode,NvsHandle *handle_out)
{
    NvsLockScope lock;
    nvs_lock_construct(&lock);
    NvsObject *object;
    NvsPartitionManager *manager = nvs_partition_manager_get();
    int result = nvs_manager_open_handle(manager,partition,namespace_name,mode,&object);
    if (result == 0) {
        volatile NvsHandleEntryView *entry = malloc(20);
        NvsObject *opened_object = object; /* Native reload follows malloc. */
        if (entry == NULL) {
            if (opened_object != NULL)
                opened_object->vtable->deleting_destructor(opened_object);
            result = 0x101;
        } else {
            unsigned int serial = NVS_NEXT_HANDLE;
            NvsHandleEntryView *tail = NVS_HANDLE_TAIL;
            ++serial;
            entry->object = opened_object;
            NVS_NEXT_HANDLE = serial;
            entry->handle = serial;
            entry->partition_name = partition;
            if (tail != NULL)
                ((volatile NvsHandleEntryView *)tail)->next = (NvsHandleEntryView *)entry;
            entry->previous = tail;
            NvsHandleEntryView *head = NVS_OPEN_HANDLES;
            entry->next = NULL;
            NVS_HANDLE_TAIL = (NvsHandleEntryView *)entry;
            if (head == NULL)
                NVS_OPEN_HANDLES = (NvsHandleEntryView *)entry;
            NVS_HANDLE_COUNT = NVS_HANDLE_COUNT + 1U;
            *handle_out = serial;
        }
    }
    nvs_lock_destroy(&lock);
    return result;
}

/* Native entry: 0x42012a80. */
/* Original function-byte SHA-256:
 * b9ff9aefdea6b7e7ce70d5b2489b67bee771a7df174263d1c2512b7ca62e4175. */
/* Walk live open-handle list and compare each object's partition name with
 * requested name using strncmp16. Obtain name through object->storage->
 * partition virtual callback; stored entry partition-name pointer is unused.
 * Match snapshots previous then next. If previous exists, reload HEAD BEFORE
 * changing previous->next and restart there; otherwise publish HEAD=next and
 * restart at next. Then update next->previous or TAIL, decrement LIVE count.
 * No entry free, object destructor or handle-counter change occurs here.
 * This differs from nvs_close; do not insert the close cleanup sequence.
 * Resume scanning and finally call manager deinit_partition even with no
 * matching entries. Caller supplies shared NVS lock; no local lock/validation,
 * iteration cap, rollback, object/partition null check or string copy. */
int nvs_unlink_handles_and_deinit_partition(const char *partition)
{
    volatile NvsHandleEntryView *entry = NVS_OPEN_HANDLES;
    while (entry != NULL) {
        const char *name = nvs_simple_get_partition_name(
            (const NvsSimpleObjectView *)entry->object);
        if (strncmp(name,partition,16) != 0) {
            entry = entry->next;
            continue;
        }
        NvsHandleEntryView *previous = entry->previous;
        NvsHandleEntryView *next = entry->next;
        if (previous != NULL) {
            entry = NVS_OPEN_HANDLES;
            ((volatile NvsHandleEntryView *)previous)->next = next;
        } else {
            NVS_OPEN_HANDLES = next;
            entry = next;
        }
        if (next != NULL)
            ((volatile NvsHandleEntryView *)next)->previous = previous;
        else
            NVS_HANDLE_TAIL = previous;
        NVS_HANDLE_COUNT = NVS_HANDLE_COUNT - 1U;
    }
    NvsPartitionManager *manager = nvs_partition_manager_get();
    return nvs_manager_deinit_partition(manager,partition);
}

/* Native entry: 0x42012b64. */
/* Original function-byte SHA-256:
 * 2202876fbecd391440a1b9710d3003e49fac0b1e284c6b136201f0513823248e. */
/* Check SDK Lock::init result and propagate failure before constructing
 * scope. On0, lock, obtain partition manager and initialize default partition
 * nvs. Unlock and return manager result unchanged. No automatic erase/retry
 * or encryption/security-key operation appears in this native build. */
int nvs_flash_init(void)
{
    int result = nvs_lock_initialize();
    if (result != 0)
        return result;
    NvsLockScope lock;
    nvs_lock_construct(&lock);
    NvsPartitionManager *manager = nvs_partition_manager_get();
    result = nvs_manager_init_partition(manager,"nvs");
    nvs_lock_destroy(&lock);
    return result;
}

/* Native entry: 0x42012b88. */
/* Original function-byte SHA-256:
 * f10c585573bd271a5106eac67e0fd645e0d36dec9b841a9b8c3d864d5c4e2edc. */
/* Check Lock::init, then hold NVS lock across lookup/deinit/flash erase.
 * If manager lookup returns storage, unlink its handles and deinitialize;
 * nonzero deinit result skips physical erase. Look up first DATA1/NVS2
 * partition with supplied label; absent returns105. Otherwise erase range
 * offset0 with partition->size WORD+16. Propagate erase result, unlock every
 * ordinary locked return. No label/output validation, ready/started updates,
 * reinitialize, security check, size cap or transactional rollback is added. */
int nvs_flash_erase_partition(const char *partition)
{
    int result = nvs_lock_initialize();
    if (result != 0)
        return result;
    NvsLockScope lock;
    nvs_lock_construct(&lock);
    NvsPartitionManager *manager = nvs_partition_manager_get();
    if (nvs_manager_lookup_storage(manager,partition) != NULL) {
        result = nvs_unlink_handles_and_deinit_partition(partition);
        if (result != 0)
            goto unlock;
    }
    const EspPartition *flash = esp_partition_find_first(1,2,partition);
    result = 0x105;
    if (flash != NULL)
        result = esp_partition_erase_range(flash,0,flash->size);
unlock:
    nvs_lock_destroy(&lock);
    return result;
}

/* Native entry: 0x42012bdc. */
/* Original function-byte SHA-256:
 * c167ebe4e43e212200bbc5ad96c4bdf7b526ece6503b444db0e93021c32d30d5. */
/* Forward default partition name nvs to nvs_flash_erase_partition and
 * return its exact status. The callee owns SDK locking/deinit/physical erase;
 * this wrapper does not reset application persistence state or reinitialize. */
int nvs_flash_erase(void)
{
    return nvs_flash_erase_partition("nvs");
}

/* Native entry: 0x42012bec. */
/* Original function-byte SHA-256:
 * d907c722c0008b9d57cee98be2c4e3c023a00917c8d4342337a715de29b50ccf. */
/* Call Lock::init first. On0 forward default partition nvs, namespace,
 * full32 mode and handle-output pointer to the lock-owning implementation.
 * Propagate status. No local pointer/mode check, output initialization,
 * namespace copy or separate scope construction occurs in this wrapper. */
int nvs_open(const char *namespace_name,int mode,NvsHandle *handle)
{
    int result = nvs_lock_initialize();
    if (result == 0)
        result = nvs_open_from_partition("nvs",namespace_name,mode,handle);
    return result;
}

/* Native entry: 0x42012c0c. */
/* Original function-byte SHA-256:
 * 19676768ec3defc9819b875fce4d0a7fe693b5be046970bb1a37d7908f688e68. */
/* Lock and scan full32 handle. Missing handle silently unlocks/returns.
 * First match snapshots previous then next; unlink via previous->next or
 * HEAD, then next->previous or TAIL. Read LIVE list count, read saved entry
 * object pointer BEFORE publishing count-1, call deleting destructor slot4
 * with that object if nonnull, then free the saved20-byte entry. Destructor
 * receives this (lost by Ghidra). Mutating destructor does not trigger a
 * second lookup or undo prior unlink. Unlock afterward. No handle-output
 * clearing, serial decrement, ready change or application-profile lock. */
void nvs_close(NvsHandle handle)
{
    NvsLockScope lock;
    nvs_lock_construct(&lock);
    volatile NvsHandleEntryView *entry = NVS_OPEN_HANDLES;
    while (entry != NULL) {
        if (entry->handle == handle) {
            NvsHandleEntryView *previous = entry->previous;
            NvsHandleEntryView *next = entry->next;
            if (previous != NULL)
                ((volatile NvsHandleEntryView *)previous)->next = next;
            else
                NVS_OPEN_HANDLES = next;
            if (next != NULL)
                ((volatile NvsHandleEntryView *)next)->previous = previous;
            else
                NVS_HANDLE_TAIL = previous;
            unsigned int count = NVS_HANDLE_COUNT;
            NvsObject *object = entry->object;
            NVS_HANDLE_COUNT = count - 1U;
            if (object != NULL)
                object->vtable->deleting_destructor(object);
            free((void *)entry);
            break;
        }
        entry = entry->next;
    }
    nvs_lock_destroy(&lock);
}

/* Native entry: 0x42012f38. */
/* Original function-byte SHA-256:
 * 3eef8b1e35a5b1f14ad8165e194eaad20c148cd9f48d1183d708c301d8330cfe. */
/* Require nonnull partition/output pointer; invalid102 leaves output
 * unchanged. NULL namespace remains permitted. Check Lock::init; failure
 * writes NULL output then returns it. Lock, get manager/storage. Missing
 * storage gives1102/NULL. Allocate one zeroed56-byte iterator; failed101/NULL.
 * Store storage pointer+12, then FULL32 type+0 (no enum narrowing), and call
 * storage findEntry with iterator and namespace. Any nonzero method return
 * succeeds with iterator0status; zero frees allocation and returns1102/NULL.
 * Publish output BEFORE unlock. No initialized-iterator reuse, type checking,
 * namespace copy, application-profile lock or output-lifetime validation. */
int nvs_entry_find(const char *partition,const char *namespace_name,unsigned int type,
    NvsIterator *output)
{
    if (partition == NULL || output == NULL)
        return 0x102;
    int result = nvs_lock_initialize();
    if (result != 0) {
        *output = NULL;
        return result;
    }
    NvsLockScope lock;
    nvs_lock_construct(&lock);
    NvsPartitionManager *manager = nvs_partition_manager_get();
    NvsStorageView *storage = nvs_manager_lookup_storage(manager,partition);
    NvsIteratorPrefix *iterator = NULL;
    result = 0x1102;
    if (storage != NULL) {
        iterator = calloc(1,56);
        if (iterator == NULL) {
            result = 0x101;
        } else {
            volatile NvsIteratorPrefix *created = iterator;
            created->storage = storage;
            created->type = type;
            if (nvs_storage_find_entry(storage,iterator,namespace_name) != 0) {
                result = 0;
            } else {
                free(iterator);
                iterator = NULL;
            }
        }
    }
    *output = iterator;
    nvs_lock_destroy(&lock);
    return result;
}

/* Native entry: 0x42012fb4. */
/* Original function-byte SHA-256:
 * 2b12fa47da52e389c4356813a56a1cd0925d912216028a09be506e42fed88111. */
/* Reject NULL iterator-pointer102; do not validate *iterator. Lock, snapshot
 * *iterator and load its storage+12 unchecked, call nextEntry(storage,snapshot)
 * with the SECOND iterator argument omitted by Ghidra. Any nonzero method
 * return means success0, without publishing a new pointer. On zero, RELOAD
 * *iterator after callback, free that fresh pointer, then store NULL AFTER
 * free and return1102. Thus callback mutation may change which object is
 * freed; do not free the old snapshot or clear before free. Unlock afterward.
 * No magic/type/lifetime check, extra iterator allocation or payload copy. */
int nvs_entry_next(NvsIterator *iterator)
{
    if (iterator == NULL)
        return 0x102;
    NvsLockScope lock;
    nvs_lock_construct(&lock);
    NvsIteratorPrefix *current = *iterator;
    int result = 0;
    if (nvs_storage_next_entry(current->storage,current) == 0) {
        free(*iterator);
        *iterator = NULL;
        result = 0x1102;
    }
    nvs_lock_destroy(&lock);
    return result;
}

/* Native entry: 0x42014b24. */
/* Original function-byte SHA-256:
 * abece583855e58e5ae77204260a6a42ad2572a732b9ef829b6a2b6dfe683273c. */
/* Ignore empty RAII scope pointer and acquire the fixed newlib lock word
 * at3fcd86c0. No per-object state, explicit MEMW, Lock::init call, timeout or
 * return-value check. Actual lazy allocation/blocking lives in _lock_acquire;
 * this constructor is a call-through, not evidence of runtime lock timing. */
void nvs_lock_construct(NvsLockScope *scope)
{
    (void)scope;
    _lock_acquire((NewlibLock *)0x3fcd86c0U);
}

/* Native entry: 0x42014b34. */
/* Original function-byte SHA-256:
 * 6f5c300d14c8daeb27729c318ae9fdf29892eb0fbd7c6224856f5e0018238a6d. */
/* Ignore empty RAII scope pointer and release fixed newlib lock word
 * at3fcd86c0. No instance access, lock deletion/reinitialization, explicit
 * MEMW or ownership/status check is supplied by this five-instruction body. */
void nvs_lock_destroy(NvsLockScope *scope)
{
    (void)scope;
    _lock_release((NewlibLock *)0x3fcd86c0U);
}

/* Native entry: 0x420211b8. */
/* Original function-byte SHA-256:
 * e40d1c943b8a9b1be4dc3c1c8eb0ac64c00041cef4c161bdc29362981c2e4a4c. */
/* Follow handle storage pointer+12, storage partition pointer+8, then
 * call partition virtual slot8 with partition this. Return borrowed name
 * unchanged. No null/validity check, handle-entry name lookup, namespace
 * extraction, copy or lock. Raw Ghidra lost the implicit partition argument. */
const char *nvs_simple_get_partition_name(const NvsSimpleObjectView *handle)
{
    NvsStorageView *storage = handle->storage;
    NvsPartitionObject *partition = storage->partition;
    return partition->vtable->get_partition_name(partition);
}

/* Native entry: 0x42021204. */
/* Original function-byte SHA-256:
 * 92c9598ac7519d458b9e367d0d7b28064c9bff38bae50b088825d1dda27f16a4. */
/* Return ESP_OK0 unconditionally. This compiled Lock::init body allocates
 * nothing, reads/writes no shared state and acquires no mutex. The newlib
 * acquisition used by the constructor owns lazy initialization instead. */
int nvs_lock_initialize(void)
{
    return 0;
}
