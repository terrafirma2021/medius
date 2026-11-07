/* Medius v3.4.7 device: concrete ESP-IDF NVSHandleSimple methods. */
#include "../include/types.h"

/* Native entry: 0x420143c0. */
/* Original function-byte SHA-256:
 * 27903c78ba952a60754f1a455d8e3ebcaa2a58b73f1b23e4b8f289e603109b51. */
/* Read handle valid BYTE18 once; zero gives INVALID_HANDLE1107, any
 * nonzero gives0. This concrete commit performs no flash write, flush, queue,
 * lock or read-only check. A success result here alone does not demonstrate
 * durability; the storage write implementation is a separate native body. */
int nvs_simple_commit(NvsObject *object)
{
    const volatile NvsSimpleObjectView *handle = (const void *)object;
    return handle->valid == 0 ? 0x1107 : 0;
}

/* Native entry: 0x420143d0. */
/* Original function-byte SHA-256:
 * ede5609cf94140c83cc2943f91b32c3a91a9b8e73c0ac38c0d65b38ce24ceb81. */
/* Reset this object's vtable WORD to the native simple-handle table BEFORE
 * obtaining manager. Call manager close_handle(this), ignoring its result.
 * Do not free the object. This is the complete destructor slot0;
 * no valid flag clear, storage deletion or NULL guard.
 * No local SDK/application lock is acquired; caller owns synchronization. */
void nvs_simple_destroy(NvsObject *object)
{
    object->vtable = NVS_SIMPLE_VTABLE;
    NvsPartitionManager *manager = nvs_partition_manager_get();
    nvs_manager_close_handle(manager,(NvsSimpleObjectView *)object);
}

/* Native entry: 0x420145ac. */
/* Original function-byte SHA-256:
 * 90bb7f15e45577420e4cf96f0a355a034da261fcee1c17b1ea656bcaed57840d. */
/* Reset this object's vtable WORD to the native simple-handle table BEFORE
 * obtaining manager. Call manager close_handle(this), ignoring its result.
 * Then free this same object even if removal failed. This is the deleting
 * destructor slot4; no valid flag clear or NULL guard.
 * No local SDK/application lock is acquired; caller owns synchronization. */
void nvs_simple_delete(NvsObject *object)
{
    object->vtable = NVS_SIMPLE_VTABLE;
    NvsPartitionManager *manager = nvs_partition_manager_get();
    nvs_manager_close_handle(manager,(NvsSimpleObjectView *)object);
    free(object);
}

/* Native entry: 0x420143e4. */
/* Original function-byte SHA-256:
 * 91266daadd10b359e588378ddf5881b34cf1b1ebd7f77a2dba807c3bb767c9d6. */
/* Store output WORD0 BEFORE checking valid BYTE18. On invalid return1107.
 * Otherwise sample namespace BYTE16, then storage pointer12; count entries
 * through storage into an uninitialized local WORD. Method0 copies that WORD
 * to output; errors leave its initial0. No output/null guard or lock. Aliasing
 * the output with handle fields can affect the subsequent validity/snapshots. */
int nvs_simple_get_used_entry_count(NvsObject *object,size_t *output)
{
    *output = 0;
    const volatile NvsSimpleObjectView *handle = (const void *)object;
    if (handle->valid == 0)
        return 0x1107;
    unsigned int namespace_index = handle->namespace_index;
    NvsStorageView *storage = handle->storage;
    size_t count;
    int result = nvs_storage_count_entries(storage,namespace_index,&count);
    if (result == 0)
        *output = count;
    return result;
}

/* Native entry: 0x4201440c. */
/* Original function-byte SHA-256:
 * 16a27032304c33a19fbcf0556811f819ab1dfcf58846791c10145a5c2ead9feb. */
/* Erase key with native ANY typeff. No local key validation, commit or buffer copy.
 * Read valid BYTE18 first (zero1107), then read_only BYTE17 (nonzero1104).
 * Only admitted path reads namespace BYTE16 THEN storage WORD12 and forwards
 * to storage. Return exact storage status; no local lock or extra validation. */
int nvs_simple_erase_item(NvsObject *object,const char *key)
{
    const volatile NvsSimpleObjectView *handle = (const void *)object;
    if (handle->valid == 0)
        return 0x1107;
    if (handle->read_only != 0)
        return 0x1104;
    unsigned int namespace_index = handle->namespace_index;
    NvsStorageView *storage = handle->storage;
    return nvs_storage_erase_item(storage,namespace_index,0xff,key);
}

/* Native entry: 0x42014434. */
/* Original function-byte SHA-256:
 * b2a537328f17f9429b5fc0f05298601f6d888c83562028094902fe5df82f94ba. */
/* Erase namespace using its saved BYTE index. No partition erase, local commit or handle invalidation.
 * Read valid BYTE18 first (zero1107), then read_only BYTE17 (nonzero1104).
 * Only admitted path reads namespace BYTE16 THEN storage WORD12 and forwards
 * to storage. Return exact storage status; no local lock or extra validation. */
int nvs_simple_erase_all(NvsObject *object)
{
    const volatile NvsSimpleObjectView *handle = (const void *)object;
    if (handle->valid == 0)
        return 0x1107;
    if (handle->read_only != 0)
        return 0x1104;
    unsigned int namespace_index = handle->namespace_index;
    NvsStorageView *storage = handle->storage;
    return nvs_storage_erase_namespace(storage,namespace_index);
}

/* Native entry: 0x42014458. */
/* Original function-byte SHA-256:
 * a32d952ea986569cdb3b67ee075696456186e545963b823495b3a2ae58e99131. */
/* Invalid valid BYTE18 returns1107 without output store. Otherwise read
 * namespace BYTE16 before storage WORD12 and ask findKey for a local type
 * BYTE. Error propagates without output change. On0 promote BYTE, map internal
 * BLOB41 or BLOB_IDX48 to public BLOB42, write one output WORD. Other type
 * bytes pass unchanged. No local-byte initialization or output/null check. */
int nvs_simple_find_key(NvsObject *object,const char *key,unsigned int *output)
{
    const volatile NvsSimpleObjectView *handle = (const void *)object;
    if (handle->valid == 0)
        return 0x1107;
    unsigned int namespace_index = handle->namespace_index;
    NvsStorageView *storage = handle->storage;
    unsigned char type;
    int result = nvs_storage_find_key(storage,namespace_index,key,&type);
    if (result == 0) {
        unsigned int public_type = type;
        if (public_type == 0x41 || public_type == 0x48)
            public_type = 0x42;
        *output = public_type;
    }
    return result;
}

/* Native entry: 0x4201448c. */
/* Original function-byte SHA-256:
 * 9fb875aea4a364d9b5078afe234810856693c26456bc76a869fba916d6f0b73e. */
/* Reject valid BYTE18=0 with1107; no read-only gate. Snapshot namespace
 * BYTE16 then storage WORD12 and forward LOW8(type), key and caller size
 * pointer directly to storage. No size initialization, null check, local
 * staging or lock. Return exact status; callee may change size on failure. */
int nvs_simple_get_item_size(NvsObject *object,unsigned int type,
    const char *key,size_t *size)
{
    const volatile NvsSimpleObjectView *handle = (const void *)object;
    if (handle->valid == 0)
        return 0x1107;
    unsigned int namespace_index = handle->namespace_index;
    NvsStorageView *storage = handle->storage;
    return nvs_storage_get_item_size(storage,namespace_index,(unsigned char)type,key,size);
}

/* Native entry: 0x420144b0. */
/* Original function-byte SHA-256:
 * f5b33965e159925f4a9b48fc218f08008b480d1cefcee0351cfc326c989aee22. */
/* Check valid BYTE18 then read_only BYTE17 (1107/1104 respectively).
 * Only then strlen(value); save full32 length, read namespace BYTE16 then
 * storage WORD12 and write internal SZ21 including terminator: length+1 with
 * unsigned32 wrap. No local NULL/key/length check, lock, separate commit or
 * buffer copy. Return storage status; rejected path never scans value. */
int nvs_simple_set_string(NvsObject *object,const char *key,const char *value)
{
    const volatile NvsSimpleObjectView *handle = (const void *)object;
    if (handle->valid == 0)
        return 0x1107;
    if (handle->read_only != 0)
        return 0x1104;
    size_t length = strlen(value);
    unsigned int namespace_index = handle->namespace_index;
    NvsStorageView *storage = handle->storage;
    return nvs_storage_write_item(storage,namespace_index,0x21,key,value,length + 1U);
}

/* Native entry: 0x420144e8. */
/* Original function-byte SHA-256:
 * 7004a96f461a93ea3896579f3b22d1edda11b1ac31b1b917dfb4f0ab644c5747. */
/* Check valid BYTE18 only; invalid1107 leaves caller buffer untouched here.
 * Read namespace BYTE16 BEFORE storage WORD12, then call readItem with SIX
 * arguments: storage, namespace, internal type0x41, key, output, full32 size.
 * No read-only restriction, length query, null/termination check, copy, lock,
 * commit or rollback. Propagate storage status and any callee buffer changes. */
int nvs_simple_get_blob(NvsObject *object,const char *key,void *output,size_t size)
{
    const volatile NvsSimpleObjectView *handle = (const void *)object;
    if (handle->valid == 0)
        return 0x1107;
    unsigned int namespace_index = handle->namespace_index;
    NvsStorageView *storage = handle->storage;
    return nvs_storage_read_item(storage,namespace_index,0x41,key,output,size);
}

/* Native entry: 0x4201450c. */
/* Original function-byte SHA-256:
 * e873a9b3df83dc96d5a8a13d55ec15636796b2760c983f3804988d7fc554668b. */
/* Check valid BYTE18 only; invalid1107 leaves caller buffer untouched here.
 * Read namespace BYTE16 BEFORE storage WORD12, then call readItem with SIX
 * arguments: storage, namespace, internal type0x21, key, output, full32 size.
 * No read-only restriction, length query, null/termination check, copy, lock,
 * commit or rollback. Propagate storage status and any callee buffer changes. */
int nvs_simple_get_string(NvsObject *object,const char *key,char *output,size_t size)
{
    const volatile NvsSimpleObjectView *handle = (const void *)object;
    if (handle->valid == 0)
        return 0x1107;
    unsigned int namespace_index = handle->namespace_index;
    NvsStorageView *storage = handle->storage;
    return nvs_storage_read_item(storage,namespace_index,0x21,key,output,size);
}

/* Native entry: 0x42014530. */
/* Original function-byte SHA-256:
 * 591f73abab84ee98973e08d689845371913ed6841f3b6cd5c2a9832780ace831. */
/* Check valid BYTE18 only; invalid1107 leaves caller buffer untouched here.
 * Read namespace BYTE16 BEFORE storage WORD12, then call readItem with SIX
 * arguments: storage, namespace, LOW8(type), key, output, full32 size.
 * No read-only restriction, length query, null/termination check, copy, lock,
 * commit or rollback. Propagate storage status and any callee buffer changes. */
int nvs_simple_get_typed_item(NvsObject *object,unsigned int type,const char *key,void *output,size_t size)
{
    const volatile NvsSimpleObjectView *handle = (const void *)object;
    if (handle->valid == 0)
        return 0x1107;
    unsigned int namespace_index = handle->namespace_index;
    NvsStorageView *storage = handle->storage;
    return nvs_storage_read_item(storage,namespace_index,(unsigned char)type,key,output,size);
}

/* Native entry: 0x42014554. */
/* Original function-byte SHA-256:
 * 0c050bc41c03caa6ada175120975221e254527f47bab60a2d21799c115ef3041. */
/* Read valid BYTE18 first (zero1107), then read_only BYTE17 (nonzero1104).
 * Read namespace BYTE16 BEFORE storage WORD12; writeItem receives SIX arguments
 * including internal BLOB41 and full32 size. No local data/key/size checks, copy,
 * lock or separate commit. Return exact storage status; no caller-output state. */
int nvs_simple_set_blob(NvsObject *object,const char *key,const void *value,size_t size)
{
    const volatile NvsSimpleObjectView *handle = (const void *)object;
    if (handle->valid == 0)
        return 0x1107;
    if (handle->read_only != 0)
        return 0x1104;
    unsigned int namespace_index = handle->namespace_index;
    NvsStorageView *storage = handle->storage;
    return nvs_storage_write_item(storage,namespace_index,0x41,key,value,size);
}

/* Native entry: 0x42014580. */
/* Original function-byte SHA-256:
 * 242cdfa61e580bf48655628f79048b6380cec276669a069258c80af57c8dca7a. */
/* Read valid BYTE18 first (zero1107), then read_only BYTE17 (nonzero1104).
 * Read namespace BYTE16 BEFORE storage WORD12; writeItem receives SIX arguments
 * including LOW8(type) and full32 size. No local data/key/size checks, copy,
 * lock or separate commit. Return exact storage status; no caller-output state. */
int nvs_simple_set_typed_item(NvsObject *object,unsigned int type,const char *key,const void *value,size_t size)
{
    const volatile NvsSimpleObjectView *handle = (const void *)object;
    if (handle->valid == 0)
        return 0x1107;
    if (handle->read_only != 0)
        return 0x1104;
    unsigned int namespace_index = handle->namespace_index;
    NvsStorageView *storage = handle->storage;
    return nvs_storage_write_item(storage,namespace_index,(unsigned char)type,key,value,size);
}
