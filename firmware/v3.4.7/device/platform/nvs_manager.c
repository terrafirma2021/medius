/* Medius v3.4.7 device: NVS partition manager and owned-object lists. */
#include "../include/types.h"

/* Native entry: 0x42014674. */
/* Original function-byte SHA-256:
 * 0db1ee09780955f0ff6f49310191d9ed8d51d46d8b472b0b5cedf1f24e8e0a85. */
/* Return the cached manager pointer, correcting Ghidra's false void return.
 * If absent allocate40 bytes, set native vtable, clear the nine list-state
 * WORDs in increasing order, THEN publish singleton pointer once. Allocation
 * failure still publishes NULL and returnsNULL; later calls may retry. No
 * reload after publication, lock, CAS or separate initialization flag. Caller
 * synchronization is required; this function does not prove thread safety. */
NvsPartitionManager *nvs_partition_manager_get(void)
{
    NvsPartitionManager *manager = NVS_MANAGER;
    if (manager == NULL) {
        manager = malloc(40);
        if (manager != NULL) {
            volatile NvsPartitionManager *state = manager;
            state->vtable = NVS_MANAGER_VTABLE;
            state->handle_head = NULL;
            state->handle_tail = NULL;
            state->handle_count = 0;
            state->storage_head = NULL;
            state->storage_tail = NULL;
            state->storage_count = 0;
            state->partition_head = NULL;
            state->partition_tail = NULL;
            state->partition_count = 0;
        }
        NVS_MANAGER = manager;
    }
    return manager;
}

/* Native entry: 0x420146a8. */
/* Original function-byte SHA-256:
 * 9aac4f5cf1ded870e198fe0a904a775a726511f5984b217c6806105963c94b93. */
/* Scan manager's handle-object list by POINTER identity, sampling each next
 * link BEFORE comparing the current node. First match unlinks via prev+4 and
 * saved next+8, updates head/tail and decrements live countWORD, returns0.
 * No match1107. Do not free/delete object, clear valid BYTE or node links,
 * alter API-entry list or acquire lock. NULL manager is unchecked. */
int nvs_manager_close_handle(NvsPartitionManager *manager,
    NvsSimpleObjectView *handle)
{
    volatile NvsPartitionManager *state = manager;
    volatile NvsSimpleObjectView *entry = state->handle_head;
    while (entry != NULL) {
        NvsSimpleObjectView *next = entry->next;
        if (entry == handle) {
            NvsSimpleObjectView *previous = ((volatile NvsSimpleObjectView *)handle)->previous;
            if (previous != NULL)
                ((volatile NvsSimpleObjectView *)previous)->next = next;
            else
                state->handle_head = next;
            if (next != NULL)
                ((volatile NvsSimpleObjectView *)next)->previous = previous;
            else
                state->handle_tail = previous;
            state->handle_count = state->handle_count - 1U;
            return 0;
        }
        entry = next;
    }
    return 0x1107;
}

/* Native entry: 0x420146e0. */
/* Original function-byte SHA-256:
 * f4d23a0b85c31e8af4c130914735e1d3821cba7c65867e47e4bd83e3c0ccb796. */
/* Scan storage list from manager+16. For each entry load partition+8 and
 * call its virtual get_partition_name slot8 with this, then strcmp with
 * requested name. Return first matching storage pointer; otherwise reload
 * next+4 AFTER callbacks/comparison and continue, returningNULL at end.
 * No lock, label truncation, NULL/string checks, type filter or count bound. */
NvsStorageView *nvs_manager_lookup_storage(NvsPartitionManager *manager,
    const char *name)
{
    volatile NvsStorageView *storage = ((volatile NvsPartitionManager *)manager)->storage_head;
    while (storage != NULL) {
        NvsPartitionObject *partition = storage->partition;
        const char *partition_name = partition->vtable->get_partition_name(partition);
        if (strcmp(partition_name,name) == 0)
            return (NvsStorageView *)storage;
        storage = storage->next;
    }
    return NULL;
}

/* Native entry: 0x42014704. */
/* Original function-byte SHA-256:
 * b10921632e76896754fddf744af84a224d1b2889fcf47d5e00d268e4f9a341fc. */
/* Get supplied partition's virtual name, find existing storage by that name.
 * With no storage allocate104 bytes; initialize prev/next, two page-list
 * triples, pages pointer, namespace-list triple and stateWORD0 in the exact
 * constructor order, then partition pointer. Do not memset the allocation:
 * page_count, page-manager sector/count/sequence and namespace-usage bytes
 * remain untouched here. Call storage init(base_sector,sector_count).
 * Init0 links new storage to tail (head sampled before nextNULL/tail writes)
 * and increments live storage count. Error calls storage destructor then free,
 * preserving error; allocation failure101.
 * With existing storage scan owned partition list by POINTER, sampling next
 * before comparing. If supplied pointer is owned, unlink it, snapshot deleting
 * destructor BEFORE count-1 publication, invoke destructor, then initialize
 * EXISTING storage. If unowned do not delete it. Both paths return storage-init
 * status; do not add ownership repair, storage rollback or local lock. */
int nvs_manager_init_custom(NvsPartitionManager *manager,
    NvsPartitionObject *partition,unsigned int base_sector,unsigned int sector_count)
{
    volatile NvsPartitionManager *state = manager;
    const char *name = partition->vtable->get_partition_name(partition);
    NvsStorageView *storage = nvs_manager_lookup_storage(manager,name);
    if (storage != NULL) {
        volatile NvsPartitionObject *entry = state->partition_head;
        while (entry != NULL) {
            NvsPartitionObject *next = entry->next;
            if (entry == partition) {
                NvsPartitionObject *previous = ((volatile NvsPartitionObject *)partition)->previous;
                if (previous != NULL)
                    ((volatile NvsPartitionObject *)previous)->next = next;
                else
                    state->partition_head = next;
                if (next != NULL)
                    ((volatile NvsPartitionObject *)next)->previous = previous;
                else
                    state->partition_tail = previous;
                unsigned int count = state->partition_count;
                void (*destroy)(NvsPartitionObject *) = partition->vtable->deleting_destructor;
                state->partition_count = count - 1U;
                destroy(partition);
                break;
            }
            entry = next;
        }
        return nvs_storage_initialize(storage,base_sector,sector_count);
    }
    volatile NvsStorageView *created = malloc(104);
    if (created == NULL)
        return 0x101;
    created->previous = NULL;
    created->next = NULL;
    created->pages.head = NULL;
    created->pages.tail = NULL;
    created->pages.count = 0;
    created->free_pages.head = NULL;
    created->free_pages.tail = NULL;
    created->free_pages.count = 0;
    created->page_array = NULL;
    created->namespaces.head = NULL;
    created->namespaces.tail = NULL;
    created->namespaces.count = 0;
    created->storage_state = 0;
    created->partition = partition;
    int result = nvs_storage_initialize((NvsStorageView *)created,base_sector,sector_count);
    if (result != 0) {
        nvs_storage_destroy((NvsStorageView *)created);
        free((void *)created);
        return result;
    }
    NvsStorageView *tail = state->storage_tail;
    if (tail != NULL)
        ((volatile NvsStorageView *)tail)->next = (NvsStorageView *)created;
    created->previous = tail;
    NvsStorageView *head = state->storage_head;
    created->next = NULL;
    state->storage_tail = (NvsStorageView *)created;
    if (head == NULL)
        state->storage_head = (NvsStorageView *)created;
    state->storage_count = state->storage_count + 1U;
    return 0;
}

/* Native entry: 0x420147d0. */
/* Original function-byte SHA-256:
 * 44ad8fdf9cfa275403969f2bd825231d82f3750b42e2e2a34dce35cc45913978. */
/* strlen(label)>16 returns102 before sector-size query. No NULL-label guard.
 * Query main-flash sector size BEFORE storage lookup. Existing storage returns0
 * even with sector size0. Absent storage with sector0 returnsESP_FAIL(-1).
 * Otherwise local partition pointer startsNULL; resolve named NVS partition.
 * Success invokes partition virtual get_size slot36 with this; reload local
 * partition pointer AFTER callback, initialize custom at sector0 with unsigned
 * size/sector_size quotient. Error deletes current nonnull local partition
 * via slot4, preserving status. Success samples owned-list tail BEFORE reading
 * current local partition again, appends it, samples head AFTER prev/next
 * stores but BEFORE tail publication, increments live count, returns0.
 * Borrowed label, size rounding and caller-owned lock remain unchanged. */
int nvs_manager_init_partition(NvsPartitionManager *manager,const char *label)
{
    if (strlen(label) > 16)
        return 0x102;
    unsigned int sector_size = esp_partition_get_main_flash_sector_size();
    if (nvs_manager_lookup_storage(manager,label) != NULL)
        return 0;
    if (sector_size == 0)
        return -1;
    NvsPartitionObject *volatile partition = NULL;
    int result = nvs_lookup_partition(label,&partition);
    if (result == 0) {
        NvsPartitionObject *for_size = partition;
        unsigned int size = for_size->vtable->get_size(for_size);
        NvsPartitionObject *for_init = partition;
        result = nvs_manager_init_custom(manager,for_init,0,size / sector_size);
        if (result == 0) {
            volatile NvsPartitionManager *state = manager;
            NvsPartitionObject *tail = state->partition_tail;
            volatile NvsPartitionObject *created = partition;
            if (tail != NULL)
                ((volatile NvsPartitionObject *)tail)->next = (NvsPartitionObject *)created;
            created->previous = tail;
            created->next = NULL;
            NvsPartitionObject *head = state->partition_head;
            state->partition_tail = (NvsPartitionObject *)created;
            if (head == NULL)
                state->partition_head = (NvsPartitionObject *)created;
            state->partition_count = state->partition_count + 1U;
            return 0;
        }
    }
    NvsPartitionObject *failed = partition;
    if (failed != NULL)
        failed->vtable->deleting_destructor(failed);
    return result;
}

/* Native entry: 0x42014854. */
/* Original function-byte SHA-256:
 * b45302726eae460bb5dbea0c021215dc9bf9bc6a7cff709978c4bce092206f80. */
/* Lookup storage; missing1101. Scan manager handle objects, reading storage
 * then next BEFORE comparison. Matching objects get valid BYTE18=0 and unlink
 * from this manager's list; no object free/destructor here. In the nonnull-prev
 * path reload CURRENT entry->next AFTER writing previous->next; use saved next
 * for backlink/tail update. Decrement live handle count. API entries remain a
 * separate outer caller concern. Unlink storage, decrement storage count,
 * destroy storage then free saved pointer. Scan owned partitions by virtual
 * name/strcmp; read next AFTER comparison on every entry. First match unlinks;
 * snapshot vtable BEFORE count read, deleting callback BEFORE count-1 store,
 * invoke with saved partition this, stop. No owned match still returns0.
 * No lock, extra validation, handle revalidation or rollback is introduced. */
int nvs_manager_deinit_partition(NvsPartitionManager *manager,const char *name)
{
    volatile NvsPartitionManager *state = manager;
    NvsStorageView *storage = nvs_manager_lookup_storage(manager,name);
    if (storage == NULL)
        return 0x1101;
    volatile NvsSimpleObjectView *handle = state->handle_head;
    while (handle != NULL) {
        NvsStorageView *bound_storage = handle->storage;
        NvsSimpleObjectView *next = handle->next;
        if (bound_storage != storage) {
            handle = next;
            continue;
        }
        NvsSimpleObjectView *previous = handle->previous;
        handle->valid = 0;
        if (previous != NULL) {
            ((volatile NvsSimpleObjectView *)previous)->next = next;
            handle = handle->next;
        } else {
            state->handle_head = next;
            handle = next;
        }
        if (next != NULL)
            ((volatile NvsSimpleObjectView *)next)->previous = previous;
        else
            state->handle_tail = previous;
        state->handle_count = state->handle_count - 1U;
    }
    volatile NvsStorageView *removed = storage;
    NvsStorageView *previous_storage = removed->previous;
    NvsStorageView *next_storage = removed->next;
    if (previous_storage != NULL)
        ((volatile NvsStorageView *)previous_storage)->next = next_storage;
    else
        state->storage_head = next_storage;
    if (next_storage != NULL)
        ((volatile NvsStorageView *)next_storage)->previous = previous_storage;
    else
        state->storage_tail = previous_storage;
    state->storage_count = state->storage_count - 1U;
    nvs_storage_destroy(storage);
    free(storage);
    volatile NvsPartitionObject *partition = state->partition_head;
    while (partition != NULL) {
        const char *partition_name = partition->vtable->get_partition_name((NvsPartitionObject *)partition);
        int comparison = strcmp(partition_name,name);
        NvsPartitionObject *next = partition->next;
        if (comparison != 0) {
            partition = next;
            continue;
        }
        NvsPartitionObject *previous = partition->previous;
        if (previous != NULL)
            ((volatile NvsPartitionObject *)previous)->next = next;
        else
            state->partition_head = next;
        if (next != NULL)
            ((volatile NvsPartitionObject *)next)->previous = previous;
        else
            state->partition_tail = previous;
        const NvsPartitionVtable *vtable = partition->vtable;
        unsigned int count = state->partition_count;
        void (*destroy)(NvsPartitionObject *) = vtable->deleting_destructor;
        state->partition_count = count - 1U;
        destroy((NvsPartitionObject *)partition);
        break;
    }
    return 0;
}

/* Native entry: 0x42014918. */
/* Original function-byte SHA-256:
 * 5a76b8cd9fd9931708e6e2b9047cb09de4fbcdc78581c6f5306e981ae8699747. */
/* NULL object-output102. Storage countWORD0 gives1101 before label lookup;
 * missing named storage110f. Only mode EXACTLY1 invokes partition get_readonly
 * slot40; any nonzero result10d. Namespace helper gets create=(mode==1) and
 * local namespace-BYTE output. Error propagates; no caller-output initialization.
 * Allocate20 after namespace success. Failed101. After malloc read namespace
 * BYTE and store namespace|(mode==0)<<8 as ONE HALFWORD at+16; sample manager
 * tail BEFORE vtable/store/storage/valid writes. Set native simple-handle vtable,
 * storage+12, validBYTE18=1; retain uninitialized paddingBYTE19. Link old tail,
 * previous+4, sample head, next+8=NULL, publish tail/head/count, then output.
 * Invalid enum values are not rejected: create0 but read_only0 when mode is
 * neither0 nor1. No new local lock, mode normalization or failure cleanup. */
int nvs_manager_open_handle(NvsPartitionManager *manager,const char *partition,
    const char *namespace_name,int mode,NvsObject **output)
{
    if (output == NULL)
        return 0x102;
    volatile NvsPartitionManager *state = manager;
    if (state->storage_count == 0)
        return 0x1101;
    NvsStorageView *storage = nvs_manager_lookup_storage(manager,partition);
    if (storage == NULL)
        return 0x110f;
    if (mode == 1) {
        NvsPartitionObject *backing = ((volatile NvsStorageView *)storage)->partition;
        if (backing->vtable->get_readonly(backing) != 0)
            return 0x10d;
    }
    volatile unsigned char namespace_index;
    int result = nvs_storage_open_namespace(storage,namespace_name,mode == 1,&namespace_index);
    if (result != 0)
        return result;
    volatile NvsSimpleObjectView *created = malloc(20);
    if (created == NULL)
        return 0x101;
    created->namespace_and_read_only = (unsigned short)(namespace_index | ((mode == 0) << 8));
    NvsSimpleObjectView *tail = state->handle_tail;
    created->base.vtable = NVS_SIMPLE_VTABLE;
    created->storage = storage;
    created->valid = 1;
    if (tail != NULL)
        ((volatile NvsSimpleObjectView *)tail)->next = (NvsSimpleObjectView *)created;
    created->previous = tail;
    NvsSimpleObjectView *head = state->handle_head;
    created->next = NULL;
    state->handle_tail = (NvsSimpleObjectView *)created;
    if (head == NULL)
        state->handle_head = (NvsSimpleObjectView *)created;
    state->handle_count = state->handle_count + 1U;
    *output = (NvsObject *)created;
    return 0;
}

/* Native entry: 0x420211fc. */
/* Original function-byte SHA-256:
 * a50f595a12cc6e7e90d28fa2424790fbfac53a684610d6fe5637b2112f16f23d. */
/*
 * nvs::NVSPartitionManager complete/base destructor, vtable 0x3c047288 slot 0.
 * Native body returns without any loads, stores or calls. It does not close
 * handles, delete storages/partitions, clear the singleton, unlink lists or
 * free the manager. The separate deleting-destructor slot releases memory.
 * object is unused and may be NULL; there is no implicit teardown here.
 */
void nvs_partition_manager_destroy(NvsPartitionManager *object)
{
    (void)object;
}
