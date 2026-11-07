/* Medius v3.4.7 device: ESP-IDF NVS API and reconstruction utilities.
 * Inline handle lookup represents the native inlined list scan, not a new
 * firmware entry. SDK names identify recovered native implementations.
 * A matched entry's object is used unchecked, including a NULL object; only
 * absence of the handle entry produces INVALID_HANDLE. */
#include "../include/types.h"

static __inline__ __attribute__((always_inline)) const volatile NvsHandleEntryView *
nvs_lookup_open_handle(NvsHandle handle)
{
    const volatile NvsHandleEntryView *entry = NVS_OPEN_HANDLES;
    while (entry != NULL) {
        if (entry->handle == handle)
            return entry;
        entry = entry->next;
    }
    return NULL;
}

/* Native entry: 0x42012af0. */
/* Original function-byte SHA-256:
 * daa654974643a9340c608de055da50f5672944453fd0771fe9acb16f7c60e217. */
/* Construct the NVS lock scope before scanning open handles (handle WORD+12,
 * next pointer+4, object pointer+8). Missing handle returns1107 after unlock.
 * On a match call virtual get_item_size+24 with this/type/key/local-size32.
 * Propagate its error BEFORE checking length/output. Local size is not
 * initialized here; a successful method must supply it. NULL length yields
 * 110c. With NULL output write required size and return0. Insufficient unsigned
 * capacity writes required size and returns110c; no payload call. Sufficient
 * capacity snapshots virtual get_typed_item+52 BEFORE writing required size
 * through length, then calls saved method with this,type,key,output,required
 * (FIVE arguments: Ghidra lost the size argument). Reload the cached object's
 * vtable after size callback, without relooking up the handle. Output/length
 * may alias; no additional checks, copies, terminator or rollback. Every
 * ordinary return destroys the same lock scope and preserves method status. */
int nvs_get_str_or_blob(NvsHandle handle,unsigned int type,const char *key,
    void *output,size_t *length)
{
    NvsLockScope lock;
    nvs_lock_construct(&lock);
    const volatile NvsHandleEntryView *entry = nvs_lookup_open_handle(handle);
    int result = 0x1107;
    if (entry != NULL) {
        NvsObject *object = entry->object;
        size_t required;
        result = object->vtable->get_item_size(object,type,key,&required);
        if (result == 0) {
            if (length == NULL) {
                result = 0x110c;
            } else if (output == NULL) {
                *length = required;
            } else if (*length < required) {
                *length = required;
                result = 0x110c;
            } else {
                NvsGetTyped get = object->vtable->get_typed_item;
                *length = required;
                result = get(object,type,key,output,required);
            }
        }
    }
    nvs_lock_destroy(&lock);
    return result;
}

/* Native entry: 0x42012c6c. */
/* Original function-byte SHA-256:
 * dac2f325ab81f45c3e18c1ccc22c58210dfb7f16ded499ca83b1d1ec5c523ecb. */
/* Lock, scan open handles by full32 handle, call find_key virtual slot28
 * with this/key/local type WORD. On method0 and nonnull type_out copy that
 * WORD BEFORE unlock. NULL output still performs lookup. No key validation
 * or local-type initialization. Missing handle1107; other statuses propagate.
 * Always destroy scope on ordinary return; no application-profile lock. */
int nvs_find_key(NvsHandle handle,const char *key,unsigned int *type_out)
{
    NvsLockScope lock;
    nvs_lock_construct(&lock);
    const volatile NvsHandleEntryView *entry = nvs_lookup_open_handle(handle);
    int result = 0x1107;
    if (entry != NULL) {
        NvsObject *object = entry->object;
        unsigned int type;
        result = object->vtable->find_key(object,key,&type);
        if (result == 0 && type_out != NULL)
            *type_out = type;
    }
    nvs_lock_destroy(&lock);
    return result;
}

/* Native entry: 0x42012cb4. */
/* Original function-byte SHA-256:
 * 620608272de6cfe0eb56e4a57c299a51ff3c20b5e341f0b82bb47a269565ca28. */
/* Erase key through virtual slot32; do not commit automatically or validate key locally.
 * Construct NVS scope, scan full32 handle; missing handle1107. Hold lock
 * across virtual method, preserve its status, destroy scope before returning. */
int nvs_erase_key(NvsHandle handle,const char *key)
{
    NvsLockScope lock;
    nvs_lock_construct(&lock);
    const volatile NvsHandleEntryView *entry = nvs_lookup_open_handle(handle);
    int result = 0x1107;
    if (entry != NULL) {
        NvsObject *object = entry->object;
        result = object->vtable->erase_item(object,key);
    }
    nvs_lock_destroy(&lock);
    return result;
}

/* Native entry: 0x42012db0. */
/* Original function-byte SHA-256:
 * 1db804ec1ab3ef29f10e99110a3b690244c2dd993e8ffc6c9b5569e1b48bf6d2. */
/* Commit through virtual slot40 with the actual this pointer, lost in raw Ghidra. Do not replace the virtual call with an assumed SDK no-op.
 * Construct NVS scope, scan full32 handle; missing handle1107. Hold lock
 * across virtual method, preserve its status, destroy scope before returning. */
int nvs_commit(NvsHandle handle)
{
    NvsLockScope lock;
    nvs_lock_construct(&lock);
    const volatile NvsHandleEntryView *entry = nvs_lookup_open_handle(handle);
    int result = 0x1107;
    if (entry != NULL) {
        NvsObject *object = entry->object;
        result = object->vtable->commit(object);
    }
    nvs_lock_destroy(&lock);
    return result;
}

/* Native entry: 0x42012de8. */
/* Original function-byte SHA-256:
 * a71e40a7cbf782c2225f0823c6da69cec34e1f62f2956cff9dcaf51a66aadb64. */
/* Set string through virtual slot8 with this/key/value; no local strlen, limit, null checks, commit or error translation.
 * Construct NVS scope, scan full32 handle; missing handle1107. Hold lock
 * across virtual method, preserve its status, destroy scope before returning. */
int nvs_set_str(NvsHandle handle,const char *key,const char *value)
{
    NvsLockScope lock;
    nvs_lock_construct(&lock);
    const volatile NvsHandleEntryView *entry = nvs_lookup_open_handle(handle);
    int result = 0x1107;
    if (entry != NULL) {
        NvsObject *object = entry->object;
        result = object->vtable->set_string(object,key,value);
    }
    nvs_lock_destroy(&lock);
    return result;
}

/* Native entry: 0x42012e20. */
/* Original function-byte SHA-256:
 * cb8f224835f7bd5a3cb630fae6911a1d0724576198372e0e619c31f8a89e80c7. */
/* Set blob through virtual slot12 with this/key/value/full32 length. No local buffer copy, length/pointer checks or commit.
 * Construct NVS scope, scan full32 handle; missing handle1107. Hold lock
 * across virtual method, preserve its status, destroy scope before returning. */
int nvs_set_blob(NvsHandle handle,const char *key,const void *value,size_t length)
{
    NvsLockScope lock;
    nvs_lock_construct(&lock);
    const volatile NvsHandleEntryView *entry = nvs_lookup_open_handle(handle);
    int result = 0x1107;
    if (entry != NULL) {
        NvsObject *object = entry->object;
        result = object->vtable->set_blob(object,key,value,length);
    }
    nvs_lock_destroy(&lock);
    return result;
}

/* Native entry: 0x42012ce8. */
/* Original function-byte SHA-256:
 * 5b493669799dd4472a756dba7438a00487c665e7bdd737a48cd166dc25862bcc. */
/* Construct NVS lock, scan handle; missing handle1107. On match read the
 * object's vtable, store LOW8(value), then read virtual set_typed_item slot48,
 * then call with this/type1/key/local-address/size1. The fifth size
 * argument is explicit in native a14; it was omitted in Ghidra. Local storage
 * is written only on found path. Return method status after scope destruction.
 * No independent key validation, commit, mutex recreation or error handling. */
int nvs_set_u8(NvsHandle handle,const char *key,unsigned char value)
{
    NvsLockScope lock;
    nvs_lock_construct(&lock);
    const volatile NvsHandleEntryView *entry = nvs_lookup_open_handle(handle);
    int result = 0x1107;
    if (entry != NULL) {
        NvsObject *object = entry->object;
        const volatile NvsVtable *vtable = object->vtable;
        volatile unsigned char stored_value = value;
        NvsSetTyped set = vtable->set_typed_item;
        result = set(object,1,key,(const void *)&stored_value,1);
    }
    nvs_lock_destroy(&lock);
    return result;
}

/* Native entry: 0x42012d2c. */
/* Original function-byte SHA-256:
 * 089596e375e0c0639a0da5402fa47a59346133500501bd7b00e84ef550bc7247. */
/* Construct NVS lock, scan handle; missing handle1107. On match read the
 * object's vtable, store LOW16(value), then read virtual set_typed_item slot48,
 * then call with this/type2/key/local-address/size2. The fifth size
 * argument is explicit in native a14; it was omitted in Ghidra. Local storage
 * is written only on found path. Return method status after scope destruction.
 * No independent key validation, commit, mutex recreation or error handling. */
int nvs_set_u16(NvsHandle handle,const char *key,unsigned short value)
{
    NvsLockScope lock;
    nvs_lock_construct(&lock);
    const volatile NvsHandleEntryView *entry = nvs_lookup_open_handle(handle);
    int result = 0x1107;
    if (entry != NULL) {
        NvsObject *object = entry->object;
        const volatile NvsVtable *vtable = object->vtable;
        volatile unsigned short stored_value = value;
        NvsSetTyped set = vtable->set_typed_item;
        result = set(object,2,key,(const void *)&stored_value,2);
    }
    nvs_lock_destroy(&lock);
    return result;
}

/* Native entry: 0x42012d70. */
/* Original function-byte SHA-256:
 * f471e0fd8f007471f924ff8da47cd5be037a9117a82295dd67d5a69a35a865ed. */
/* Construct NVS lock, scan handle; missing handle1107. On match read the
 * object's vtable, store LOW32(value), then read virtual set_typed_item slot48,
 * then call with this/type4/key/local-address/size4. The fifth size
 * argument is explicit in native a14; it was omitted in Ghidra. Local storage
 * is written only on found path. Return method status after scope destruction.
 * No independent key validation, commit, mutex recreation or error handling. */
int nvs_set_u32(NvsHandle handle,const char *key,unsigned int value)
{
    NvsLockScope lock;
    nvs_lock_construct(&lock);
    const volatile NvsHandleEntryView *entry = nvs_lookup_open_handle(handle);
    int result = 0x1107;
    if (entry != NULL) {
        NvsObject *object = entry->object;
        const volatile NvsVtable *vtable = object->vtable;
        volatile unsigned int stored_value = value;
        NvsSetTyped set = vtable->set_typed_item;
        result = set(object,4,key,(const void *)&stored_value,4);
    }
    nvs_lock_destroy(&lock);
    return result;
}

/* Native entry: 0x42012e5c. */
/* Original function-byte SHA-256:
 * 86711ff03e308a485c39f1c0f2ea610e299a707d2e340be01018cb6c7c1c0258. */
/* Construct NVS lock, scan full32 handle. Match calls get_typed_item
 * virtual slot52 with this/type1/key/output/size1; Ghidra dropped
 * the fifth argument. Caller buffer passes directly, without null checks,
 * initial zero, staging copy or rollback. Missing handle1107; method status
 * survives scope destruction. No application-profile lock or local commit. */
int nvs_get_u8(NvsHandle handle,const char *key,unsigned char *output)
{
    NvsLockScope lock;
    nvs_lock_construct(&lock);
    const volatile NvsHandleEntryView *entry = nvs_lookup_open_handle(handle);
    int result = 0x1107;
    if (entry != NULL) {
        NvsObject *object = entry->object;
        result = object->vtable->get_typed_item(object,1,key,output,1);
    }
    nvs_lock_destroy(&lock);
    return result;
}

/* Native entry: 0x42012e98. */
/* Original function-byte SHA-256:
 * 793b7e69c8e155abb63fe6510def8daba83b6606c56251cf7f5198b252246f24. */
/* Construct NVS lock, scan full32 handle. Match calls get_typed_item
 * virtual slot52 with this/type2/key/output/size2; Ghidra dropped
 * the fifth argument. Caller buffer passes directly, without null checks,
 * initial zero, staging copy or rollback. Missing handle1107; method status
 * survives scope destruction. No application-profile lock or local commit. */
int nvs_get_u16(NvsHandle handle,const char *key,unsigned short *output)
{
    NvsLockScope lock;
    nvs_lock_construct(&lock);
    const volatile NvsHandleEntryView *entry = nvs_lookup_open_handle(handle);
    int result = 0x1107;
    if (entry != NULL) {
        NvsObject *object = entry->object;
        result = object->vtable->get_typed_item(object,2,key,output,2);
    }
    nvs_lock_destroy(&lock);
    return result;
}

/* Native entry: 0x42012ed4. */
/* Original function-byte SHA-256:
 * e0ebbe44dd5e299cb982a4887441b16418e86b822a2af31c723c66fce62b3c42. */
/* Construct NVS lock, scan full32 handle. Match calls get_typed_item
 * virtual slot52 with this/type4/key/output/size4; Ghidra dropped
 * the fifth argument. Caller buffer passes directly, without null checks,
 * initial zero, staging copy or rollback. Missing handle1107; method status
 * survives scope destruction. No application-profile lock or local commit. */
int nvs_get_u32(NvsHandle handle,const char *key,unsigned int *output)
{
    NvsLockScope lock;
    nvs_lock_construct(&lock);
    const volatile NvsHandleEntryView *entry = nvs_lookup_open_handle(handle);
    int result = 0x1107;
    if (entry != NULL) {
        NvsObject *object = entry->object;
        result = object->vtable->get_typed_item(object,4,key,output,4);
    }
    nvs_lock_destroy(&lock);
    return result;
}

/* Native entry: 0x42012f10. */
/* Original function-byte SHA-256:
 * 22a833cb153e286deafbbb48457f4ce341c06ebbef53e5976503688f6cdea02c. */
/* String wrapper passes native internal ItemType0x21 to the common
 * size-query/read implementation, retaining all pointers/full32 handle.
 * Internal blob41 differs from public nvs_type_t BLOB42; do not substitute
 * the public enumeration here. Return common-helper status unchanged. */
int nvs_get_str(NvsHandle handle,const char *key,char *output,size_t *length)
{
    return nvs_get_str_or_blob(handle,0x21,key,output,length);
}

/* Native entry: 0x42012f24. */
/* Original function-byte SHA-256:
 * 7323160be10b5632c2e8d7c12ea96b1d26090e004d7ec5dbdcac2087e2c4cf6c. */
/* Blob wrapper passes native internal ItemType0x41 to the common
 * size-query/read implementation, retaining all pointers/full32 handle.
 * Internal blob41 differs from public nvs_type_t BLOB42; do not substitute
 * the public enumeration here. Return common-helper status unchanged. */
int nvs_get_blob(NvsHandle handle,const char *key,void *output,size_t *length)
{
    return nvs_get_str_or_blob(handle,0x41,key,output,length);
}

/* Native entry: 0x42012fec. */
/* Original function-byte SHA-256:
 * 67432d0ba1a4d678a1dffc292f8ae14499e62d0b263cc1e67cae2e75d0ee29a0. */
/* Reject NULL iterator or info with INVALID_ARG102. Otherwise memcpy
 * exactly36 bytes from iterator+20 to info and return0. Source metadata is
 * namespace16/key16/typeWORD. No lock, iterator lifetime/magic/type check,
 * overlap-safe move, fieldwise conversion or string termination is added. */
int nvs_entry_info(NvsIterator iterator,NvsEntryInfo *info)
{
    if (iterator == NULL || info == NULL)
        return 0x102;
    const NvsIteratorPrefix *view = iterator;
    memcpy(info,&view->entry_info,36);
    return 0;
}

/* Native entry: 0x42013018. */
/* Original function-byte SHA-256:
 * e9a4572068083260c80868a2f7623d6bf87c4f775d4575bd81e4ce7c9f5c4463. */
/* Pass iterator directly to the native free implementation, including
 * NULL. No lock, caller pointer clearing, traversal or validation is supplied.
 * This is iterator ownership release, not nvs_entry_next or handle close. */
void nvs_release_iterator(NvsIterator iterator)
{
    free(iterator);
}
