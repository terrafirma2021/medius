/* Medius v3.4.7 device: NVS storage lookup, reads and erasure. */
#include "../include/types.h"

/* Native entry: 0x42013fbc. */
/* Original function-byte SHA-256:
 * 35954ddde4d521be83d7a4ec405464347547e47625eebdb51f16bf3ca4ce9f56. */
/* Require storage-state WORD100 EXACTLY1; otherwise1101, output untouched.
 * Forward namespace name, LOW8(create) and caller BYTE-output pointer to the
 * namespace implementation. Return exact result. No independent name/output
 * check, create canonicalization, initialization, locking or commit. */
int nvs_storage_open_namespace(NvsStorageView *storage,const char *name,
    unsigned int create,volatile unsigned char *namespace_index)
{
    if (((const volatile NvsStorageView *)storage)->storage_state != NVS_STORAGE_STATE_ACTIVE)
        return 0x1101;
    return nvs_storage_open_namespace_impl(storage,name,(unsigned char)create,namespace_index);
}

/* Native entry: 0x42013fd8. */
/* Original function-byte SHA-256:
 * 2b0c5473671decb9a0ba331a901dce33e8c0959ca97cf490734023f72428f9f3. */
/* Require stateWORD100==1 or return1101. Namespace/type narrow toBYTE.
 * Internal BLOB41 first calls multi-page reader with original output/full32
 * size; any status except NOT_FOUND1102 returns immediately. Only1102 falls
 * back to legacy41 scan, potentially retaining callee buffer changes.
 * Walk pages from storage+16, initialize local position0 on each page, find
 * item with key/type/ns and chunk/versionff (eight arguments). Ignore EVERY
 * nonzero page-find result and follow next+4 AFTER callback; not just1102.
 * First find0 calls that page's readItem with original output/size and two
 * trailingff arguments, returning its status without trying later pages.
 * No match1102. No payload staging, pointer check, terminator, lock or rollback. */
int nvs_storage_read_item(NvsStorageView *storage,unsigned int namespace_index,
    unsigned int type,const char *key,void *output,size_t size)
{
    const volatile NvsStorageView *state = storage;
    if (state->storage_state != NVS_STORAGE_STATE_ACTIVE)
        return 0x1101;
    namespace_index &= 255U;
    type &= 255U;
    if (type == NVS_ITEM_TYPE_BLOB) {
        int result = nvs_storage_read_multi_page_blob(storage,namespace_index,key,output,size);
        if (result != 0x1102)
            return result;
    }
    volatile NvsPage *page = state->pages.head;
    while (page != NULL) {
        size_t position = 0;
        NvsItem item;
        if (nvs_page_find_item((NvsPage *)page,namespace_index,type,key,
                &position,&item,NVS_ITEM_CHUNK_ANY,NVS_ITEM_VERSION_ANY) == 0)
            return nvs_page_read_item((NvsPage *)page,namespace_index,type,
                key,output,size,NVS_ITEM_CHUNK_ANY,NVS_ITEM_VERSION_ANY);
        page = page->next;
    }
    return 0x1102;
}

/* Native entry: 0x42014068. */
/* Original function-byte SHA-256:
 * 2f4287c36491487fd24c319ab3feb8c252d78ee2647495525c484f77845c4516. */
/* Require stateWORD==1, narrow namespace/typeBYTE. Scan pages/find from
 * local position0 with chunk/versionff, ignoring all page-find errors.
 * On first match sample item typeBYTE then returned positionWORD even if
 * branch will use the blob path. Non-BLOB_IDX calls page eraseEntryAndSpan
 * with that saved position. BLOB_IDX48 instead RECHECKS live stateWORD==1;
 * if active read blob chunk-start BYTE29 and call multi-page erasure, else
 * return1101. No match1102. No local readonly/lock/commit checks or rollback. */
int nvs_storage_erase_item(NvsStorageView *storage,unsigned int namespace_index,
    unsigned int type,const char *key)
{
    const volatile NvsStorageView *state = storage;
    if (state->storage_state != NVS_STORAGE_STATE_ACTIVE)
        return 0x1101;
    namespace_index &= 255U;
    type &= 255U;
    volatile NvsPage *page = state->pages.head;
    while (page != NULL) {
        size_t position = 0;
        NvsItem item;
        if (nvs_page_find_item((NvsPage *)page,namespace_index,type,key,
                &position,&item,NVS_ITEM_CHUNK_ANY,NVS_ITEM_VERSION_ANY) == 0) {
            const volatile NvsItem *match = &item;
            unsigned int found_type = match->type;
            size_t found_position = *(volatile size_t *)&position;
            if (found_type != NVS_ITEM_TYPE_BLOB_INDEX)
                return nvs_page_erase_entry_and_span((NvsPage *)page,found_position);
            if (state->storage_state != NVS_STORAGE_STATE_ACTIVE)
                return 0x1101;
            return nvs_storage_erase_multi_page_blob(storage,namespace_index,key,
                match->blob_index.chunk_start);
        }
        page = page->next;
    }
    return 0x1102;
}

/* Native entry: 0x420140ec. */
/* Original function-byte SHA-256:
 * 298c2354c610a276b377f2af5d4d3f5acf077bd7138c2a9c33ba74bec5f409c8. */
/* Require stateWORD100==1, narrow namespaceBYTE. For each page repeatedly
 * eraseItem(ns,ANYff,NULL,chunkff,versionff) while result0. NOT_FOUND1102
 * advances via fresh next+4; other errors return immediately after any prior
 * deletions. Empty/exhausted page list returns0. No state recheck in loop,
 * retry count, rollback, lock or separate commit. A page reporting perpetual
 * success keeps this loop running; no invented timeout or progress guard. */
int nvs_storage_erase_namespace(NvsStorageView *storage,unsigned int namespace_index)
{
    const volatile NvsStorageView *state = storage;
    if (state->storage_state != NVS_STORAGE_STATE_ACTIVE)
        return 0x1101;
    namespace_index &= 255U;
    volatile NvsPage *page = state->pages.head;
    while (page != NULL) {
        int result;
        do {
            result = nvs_page_erase_item((NvsPage *)page,namespace_index,
                NVS_ITEM_TYPE_ANY,NULL,NVS_ITEM_CHUNK_ANY,NVS_ITEM_VERSION_ANY);
        } while (result == 0);
        if (result != 0x1102)
            return result;
        page = page->next;
    }
    return 0;
}

/* Native entry: 0x42014134. */
/* Original function-byte SHA-256:
 * 2a7682c9c3f3a4426d2d9e54a37a2623929b3d69f904e3f1e2bdf16883ccc37a. */
/* Require stateWORD==1 or1101. Narrow namespaceBYTE, scan pages with
 * ANYff type, the caller's key and local position0 per page; chunk/versionff. Ignore all
 * nonzero find results. First0 optionally copies item typeBYTE to nonnull
 * caller output and returns0; NULL output still performs search. No match1102.
 * Output otherwise untouched; no type translation, lock or key validation. */
int nvs_storage_find_key(NvsStorageView *storage,unsigned int namespace_index,
    const char *key,unsigned char *type)
{
    const volatile NvsStorageView *state = storage;
    if (state->storage_state != NVS_STORAGE_STATE_ACTIVE)
        return 0x1101;
    namespace_index &= 255U;
    volatile NvsPage *page = state->pages.head;
    while (page != NULL) {
        size_t position = 0;
        NvsItem item;
        if (nvs_page_find_item((NvsPage *)page,namespace_index,NVS_ITEM_TYPE_ANY,key,
                &position,&item,NVS_ITEM_CHUNK_ANY,NVS_ITEM_VERSION_ANY) == 0) {
            if (type != NULL)
                *type = item.type;
            return 0;
        }
        page = page->next;
    }
    return 0x1102;
}

/* Native entry: 0x42014188. */
/* Original function-byte SHA-256:
 * 92a15366faf78cc45299fc8d5893fd775c177fc43b53e4bb444efd26fd9fe665. */
/* Require stateWORD==1 or1101; namespace/type narrow toBYTE. For internal
 * BLOB41 scan for BLOB_IDX48 first; find0 reads FULL32 item data_size+24 and
 * writes caller sizeWORD, returns0. Ignore all find errors across pages. If
 * first-pass head wasNULL return1102 directly; otherwise an exhausted first
 * pass RELOADS current pages head and scans legacy41. Other types scan directly.
 * Legacy/direct find0 reads HALFWORD data_size+24 then zero-extends into size
 * WORD; this is not a WORD read masked afterward. Position resets0 each page,
 * chunk/versionff. No result beyond first match; failures1102 leave size
 * untouched. No output-pointer check, size-type validation, lock or rollback. */
int nvs_storage_get_item_size(NvsStorageView *storage,unsigned int namespace_index,
    unsigned int type,const char *key,size_t *size)
{
    const volatile NvsStorageView *state = storage;
    if (state->storage_state != NVS_STORAGE_STATE_ACTIVE)
        return 0x1101;
    namespace_index &= 255U;
    type &= 255U;
    NvsItem item;
    if (type == NVS_ITEM_TYPE_BLOB) {
        volatile NvsPage *page = state->pages.head;
        if (page == NULL)
            return 0x1102;
        do {
            size_t position = 0;
            if (nvs_page_find_item((NvsPage *)page,namespace_index,NVS_ITEM_TYPE_BLOB_INDEX,key,
                    &position,&item,NVS_ITEM_CHUNK_ANY,NVS_ITEM_VERSION_ANY) == 0) {
                *size = ((const volatile NvsItem *)&item)->blob_index.data_size;
                return 0;
            }
            page = page->next;
        } while (page != NULL);
    }
    volatile NvsPage *page = state->pages.head;
    while (page != NULL) {
        size_t position = 0;
        if (nvs_page_find_item((NvsPage *)page,namespace_index,type,key,
                &position,&item,NVS_ITEM_CHUNK_ANY,NVS_ITEM_VERSION_ANY) == 0) {
            *size = ((const volatile NvsItem *)&item)->variable.data_size;
            return 0;
        }
        page = page->next;
    }
    return 0x1102;
}

/* Native entry: 0x42014244. */
/* Original function-byte SHA-256:
 * fdf736b45fbb72ae90fcf8d789a97ce7e723cc541d3730b8704c2faba0347bfa. */
/* Snapshot storage-state WORD BEFORE zeroing caller countWORD; gate on
 * saved state==1 (otherwise1101). Narrow namespaceBYTE. For every page start
 * position0; find ANY type with NULL key/chunk/versionff. NOT_FOUND1102
 * advances page, other nonzero statuses return with partial count retained.
 * Success samples spanBYTE2, LIVE caller countWORD, returned positionWORD,
 * stores count+span THEN position+span, unsigned32 wrap. Continue same page
 * while new position<=125; otherwise advance. Zero span/progress is unchecked.
 * Page next is read after callback. No output/null guard, normalization or lock. */
int nvs_storage_count_entries(NvsStorageView *storage,unsigned int namespace_index,
    size_t *output)
{
    const volatile NvsStorageView *state = storage;
    unsigned int saved_state = state->storage_state;
    *output = 0;
    if (saved_state != NVS_STORAGE_STATE_ACTIVE)
        return 0x1101;
    namespace_index &= 255U;
    volatile NvsPage *page = state->pages.head;
    while (page != NULL) {
        size_t position = 0;
        for (;;) {
            NvsItem item;
            int result = nvs_page_find_item((NvsPage *)page,namespace_index,
                NVS_ITEM_TYPE_ANY,NULL,&position,&item,NVS_ITEM_CHUNK_ANY,NVS_ITEM_VERSION_ANY);
            if (result == 0x1102)
                break;
            if (result != 0)
                return result;
            unsigned int span = ((const volatile NvsItem *)&item)->span;
            size_t total = *(volatile size_t *)output;
            size_t found_position = *(volatile size_t *)&position;
            *(volatile size_t *)output = total + span;
            size_t next_position = found_position + span;
            *(volatile size_t *)&position = next_position;
            if (next_position >= NVS_PAGE_ENTRY_COUNT)
                break;
        }
        page = page->next;
    }
    return 0;
}

/* Native entry: 0x4201437c. */
/* Original function-byte SHA-256:
 * b2f5aac715432dd6df320fd55397666e6e019414ca9efde8ff47609db1fcbec0. */
/* Initialize iterator namespaceBYTE4=ff, sample storage pages-head pointer,
 * set iterator indexWORD8=0 then pageWORD16=saved head, in that order. Leave
 * type/storage/metadata fields alone. NULL namespace calls nextEntry directly
 * WITHOUT checking storage-state. Nonnull namespace requires live state==1,
 * calls internal namespace lookup(create0, output=&iterator.namespace_index),
 * then nextEntry only on result0. Other results return0 with initialized
 * iterator fields retained. Return nextEntry's native register result unchanged.
 * No iterator/null guard, lock, fresh page-head lookup or cleanup here. */
unsigned int nvs_storage_find_entry(NvsStorageView *storage,
    NvsIteratorPrefix *iterator,const char *namespace_name)
{
    volatile NvsIteratorPrefix *cursor = iterator;
    cursor->namespace_index = NVS_NAMESPACE_ANY;
    void *page = ((const volatile NvsStorageView *)storage)->pages.head;
    cursor->entry_index = 0;
    cursor->page = page;
    if (namespace_name != NULL) {
        if (((const volatile NvsStorageView *)storage)->storage_state != NVS_STORAGE_STATE_ACTIVE)
            return 0;
        if (nvs_storage_open_namespace_impl(storage,namespace_name,0,&cursor->namespace_index) != 0)
            return 0;
    }
    return nvs_storage_next_entry(storage,iterator);
}
