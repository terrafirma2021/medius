/* Medius v3.4.7 device: NVS namespace registry and entry enumeration. */
#include "../include/types.h"

/* Native entry: 0x42013ec4. */
/* Original function-byte SHA-256:
 * d173e34e8f6ddfdfe9c9bff58994948782d567bbfd24f6503be21dc0c9a3750d. */
/* Search namespace list using strncmp(name,stored_name,15); first match
 * copies stored indexBYTE24 to caller and returns0. Compare only15 bytes;
 * no state or input/output-pointer check here. Missing+FULL32 create0 gives
 * 1102. Otherwise scan bitmap indices1..254, fresh aligned WORD read per
 * index, first clear bit wins; all occupied1105. Local selected BYTE starts1,
 * changed to later candidate after scan. Write namespace definition as U8 in
 * namespace0 using SIX arguments, size1; error returns without bitmap/output.
 * Success RELOADS selected BYTE after write, caches it, sets corresponding
 * bitmap bit by WORD RMW, publishes caller BYTE BEFORE malloc28. Allocation
 * failure101 leaves persisted definition, bitmap and caller output changed.
 * New entry prev/nextWORD0, cached indexBYTE24, strncpy15 name; sample TAIL
 * BEFORE name[15]NUL. If tail nonnull link tail->next then RELOAD TAIL for
 * created->previous; absent tail remainsNULL. Sample HEAD before nextNULL,
 * publish TAIL/conditionalHEAD/live count+1. Padding25..27 remains untouched.
 * No new local lock, rollback, serial/name normalization or bitmap atomicity. */
int nvs_storage_open_namespace_impl(NvsStorageView *storage,const char *name,
    unsigned int create,volatile unsigned char *namespace_index)
{
    volatile NvsStorageView *state = storage;
    volatile NvsNamespaceEntry *entry = state->namespaces.head;
    while (entry != NULL) {
        if (strncmp(name,(const char *)entry->name,15) == 0) {
            *namespace_index = entry->index;
            return 0;
        }
        entry = entry->next;
    }
    if (create == 0)
        return 0x1102;
    volatile unsigned char selected = 1;
    volatile unsigned int *usage = (volatile void *)state->namespace_usage;
    unsigned int candidate;
    for (candidate = 1; candidate < 255; ++candidate) {
        unsigned int word = usage[candidate >> 5];
        if (((word >> (candidate & 31U)) & 1U) == 0)
            break;
    }
    if (candidate == 255)
        return 0x1105;
    if (candidate != 1)
        selected = (unsigned char)candidate;
    int result = nvs_storage_write_item(storage,0,NVS_ITEM_TYPE_U8,name,(const void *)&selected,1);
    if (result != 0)
        return result;
    unsigned char saved = selected;
    unsigned int word = usage[saved >> 5];
    usage[saved >> 5] = word | (1U << (saved & 31U));
    *namespace_index = saved;
    volatile NvsNamespaceEntry *created = malloc(28);
    if (created == NULL)
        return 0x101;
    created->previous = NULL;
    created->next = NULL;
    created->index = saved;
    strncpy((char *)created->name,name,15);
    NvsNamespaceEntry *tail = state->namespaces.tail;
    created->name[15] = '\0';
    if (tail != NULL) {
        ((volatile NvsNamespaceEntry *)tail)->next = (NvsNamespaceEntry *)created;
        tail = state->namespaces.tail;
    }
    created->previous = tail;
    void *head = state->namespaces.head;
    created->next = NULL;
    state->namespaces.tail = (NvsNamespaceEntry *)created;
    if (head == NULL)
        state->namespaces.head = (NvsNamespaceEntry *)created;
    state->namespaces.count = state->namespaces.count + 1U;
    return 0;
}

/* Native entry: 0x420142b4. */
/* Original function-byte SHA-256:
 * ea8c3b28a31606699687973e623c43990355449900b535b9637235a3098e86e5. */
/* Start from iterator pageWORD16; NULL returns0 without metadata/page changes.
 * Each find reads type LOW BYTE0 BEFORE namespaceBYTE4; use live indexWORD8
 * pointer, NULL key/chunk/versionff, eight arguments. AFTER EVERY result,
 * read live indexWORD, then item.spanBYTE and publish index+span, even on
 * errors. Item is not initialized; a failing page call may leave stale or
 * indeterminate span. Do not zero it or condition this update on success.
 * NOT_FOUND1102 reads next page then clears indexWORD0; exhausted returns0
 * while leaving iterator page unchanged. Other errors retry SAME page after
 * the span increment, without error return or retry/progress limit.
 * Successful matches skip namespace0, internal BLOB41/BLOB_IDX48, and BLOB_DATA42
 * chunks with nonzero low7 chunk-index bits. Other entries are visible. Store
 * metadata typeWORD first, strncpy15 key, force key[15]NUL. Then walk namespace
 * registry by BYTE index; only a match strlcpy16 updates namespace name, so
 * missing registry leaves prior name bytes intact. Publish saved page LAST,
 * return1. No state check, null/magic guards, local lock, rollback or output
 * initialization. This retains the native retry and indeterminate-read paths. */
unsigned int nvs_storage_next_entry(NvsStorageView *storage,
    NvsIteratorPrefix *iterator)
{
    volatile NvsIteratorPrefix *cursor = iterator;
    volatile NvsPage *page = cursor->page;
    volatile NvsItem item;
    while (page != NULL) {
        unsigned int type = cursor->type_low_byte;
        unsigned int namespace_index = cursor->namespace_index;
        int result = nvs_page_find_item((NvsPage *)page,namespace_index,type,
            NULL,(size_t *)&cursor->entry_index,(NvsItem *)&item,NVS_ITEM_CHUNK_ANY,NVS_ITEM_VERSION_ANY);
        size_t position = cursor->entry_index;
        unsigned int span = item.span;
        cursor->entry_index = position + span;
        if (result != 0) {
            if (result == 0x1102) {
                page = page->next;
                cursor->entry_index = 0;
            }
            continue;
        }
        if (item.namespace_index == 0)
            continue;
        unsigned int found_type = item.type;
        if (found_type == NVS_ITEM_TYPE_BLOB || found_type == NVS_ITEM_TYPE_BLOB_INDEX)
            continue;
        if (found_type == NVS_ITEM_TYPE_BLOB_DATA && (item.chunk_index & NVS_ITEM_CHUNK_NUMBER_MASK) != 0)
            continue;
        cursor->entry_info.type = found_type;
        strncpy((char *)cursor->entry_info.key,(const char *)item.key,15);
        cursor->entry_info.key[15] = '\0';
        volatile NvsNamespaceEntry *entry = ((const volatile NvsStorageView *)storage)->namespaces.head;
        if (entry != NULL) {
            unsigned int found_namespace = item.namespace_index;
            do {
                if (entry->index == found_namespace) {
                    strlcpy((char *)cursor->entry_info.namespace_name,(const char *)entry->name,16);
                    break;
                }
                entry = entry->next;
            } while (entry != NULL);
        }
        cursor->page = (NvsPage *)page;
        return 1;
    }
    return 0;
}
