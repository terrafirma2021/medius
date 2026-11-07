/* Medius v3.4.7 device: NVS namespaces and interrupted blob-write recovery. */
#include "../include/types.h"

/* Inline reconstruction utilities for native inlined container operations.
 * These are not additional firmware entry points. */
/* Unlink each namespace, decrement the live count, then free it. The next
 * iteration reloads the head after free; an empty list keeps its old count. */
static __inline__ __attribute__((always_inline)) void
nvs_storage_clear_namespaces(volatile NvsStorageView *storage)
{
    NvsNamespaceEntry *entry = storage->namespaces.head;
    while (entry != NULL) {
        volatile NvsNamespaceEntry *node = entry;
        NvsNamespaceEntry *previous = node->previous;
        NvsNamespaceEntry *next = node->next;
        if (previous != NULL)
            ((volatile NvsNamespaceEntry *)previous)->next = next;
        else
            storage->namespaces.head = next;
        if (next != NULL)
            ((volatile NvsNamespaceEntry *)next)->previous = previous;
        else
            storage->namespaces.tail = previous;
        unsigned int count = storage->namespaces.count;
        storage->namespaces.count = count - 1U;
        free(entry);
        entry = storage->namespaces.head;
    }
}

/* The C++ algorithm copied its by-value predicate through several wrappers.
 * Retain its seven32-byte memcpy calls and distinguish the captured item from
 * the original item, whose span/length are read after the search callbacks. */
typedef struct NvsBlobSearchFrame {
    NvsItem predicate,iterator_copy,algorithm_copy,closure_copy,item_copy,item;
    size_t position;
} NvsBlobSearchFrame;
_Static_assert(sizeof(NvsBlobSearchFrame) == 196,"blob predicate frame view");
_Static_assert(__builtin_offsetof(NvsBlobSearchFrame,item) == 160,"native item offset");
_Static_assert(__builtin_offsetof(NvsBlobSearchFrame,position) == 192,"native position offset");
static __inline__ __attribute__((always_inline)) void
nvs_blob_capture_predicate(NvsBlobSearchFrame *frame)
{
    memcpy(&frame->item_copy,&frame->item,sizeof(frame->item));
    memcpy(&frame->closure_copy,&frame->item_copy,sizeof(frame->item));
    memcpy(&frame->iterator_copy,&frame->closure_copy,sizeof(frame->item));
    memcpy(&frame->predicate,&frame->iterator_copy,sizeof(frame->item));
    memcpy(&frame->algorithm_copy,&frame->predicate,sizeof(frame->item));
    memcpy(&frame->iterator_copy,&frame->algorithm_copy,sizeof(frame->item));
    memcpy(&frame->predicate,&frame->iterator_copy,sizeof(frame->item));
}

/* Native entry: 0x420131ac. */
/* Original function-byte SHA-256:
 * 4b22c2f4b509b2a3d2916c8740346f23df0a254a327f530d3c3736c42eee3c11. */
/* Destroy the storage's namespace nodes, then its Page[] allocation. Namespace
 * removal reloads the list head after each free and decrements the live count.
 * Page[] has a32-bit count cookie immediately before its84-byte elements;
 * destroy each page's hash list in reverse order and free the cookie address.
 * Does not free storage or its partition, clear page_array/state, validate the
 * cookie, reset an already-empty list, or acquire a lock. */
void nvs_storage_destroy(NvsStorageView *storage)
{
    volatile NvsStorageView *state = storage;
    nvs_storage_clear_namespaces(state);
    void *pages = state->page_array;
    if (pages != NULL) {
        uintptr_t first = (uintptr_t)pages;
        unsigned int count = ((const volatile NvsPageArrayAllocation *)
            (first - offsetof(NvsPageArrayAllocation,pages)))->count;
        uintptr_t current = first + count * sizeof(NvsPage);
        while (current != first) {
            current -= sizeof(NvsPage);
            nvs_hash_list_destroy((NvsObjectList *)(current + offsetof(NvsPage,hash_blocks)));
        }
        free((void *)(first - offsetof(NvsPageArrayAllocation,pages)));
    }
}

/* Native entry: 0x4201320c. */
/* Original function-byte SHA-256:
 * 66d2fde257bdca246646fd01fad07e85c0d2805ae1c1d425e19c24bb0237b63d. */
/* Append every BLOB_IDX item found on storage's pages to the supplied RAM list.
 * Copy/terminate its key, namespace, version start, chunk count and total size;
 * initialize observed size/count to zero. The caller owns existing/new nodes.
 * A failed find ends that page regardless of its error. malloc failure returns
 * 0x101 with earlier nodes retained. Success returns0, including no pages.
 * Each page starts at position0; found-item span advances the live position.
 * No duplicate merge, span validation, list repair, rollback or local lock. */
int nvs_storage_populate_blob_indexes(NvsStorageView *storage,
    NvsObjectList *indexes)
{
    volatile NvsObjectList *list = indexes;
    NvsPage *page = ((volatile NvsStorageView *)storage)->pages.head;
    NvsItem item;
    const volatile NvsItem *metadata = &item;
    volatile size_t position;
    while (page != NULL) {
        position = 0;
        while (nvs_page_find_item(page,NVS_NAMESPACE_ANY,NVS_ITEM_TYPE_BLOB_INDEX,NULL,
                (size_t *)&position,&item,NVS_ITEM_CHUNK_ANY,NVS_ITEM_VERSION_ANY) == 0) {
            NvsBlobIndexNode *entry = malloc(sizeof(*entry));
            if (entry == NULL)
                return 0x101;
            volatile NvsBlobIndexNode *node = entry;
            node->previous = NULL;
            node->next = NULL;
            strncpy(entry->key,item.key,16);
            unsigned int namespace_index = metadata->namespace_index;
            NvsBlobIndexNode *tail = list->tail;
            node->namespace_index = namespace_index;
            unsigned int chunk_start = metadata->blob_index.chunk_start;
            node->key[15] = '\0';
            node->chunk_start = chunk_start;
            unsigned int chunk_count = metadata->blob_index.chunk_count;
            node->observed_data_size = 0;
            node->chunk_count = chunk_count;
            unsigned int data_size = metadata->blob_index.data_size;
            node->observed_chunk_count = 0;
            node->data_size = data_size;
            if (tail != NULL) {
                ((volatile NvsBlobIndexNode *)tail)->next = entry;
                tail = list->tail;
            }
            void *head = list->head;
            node->previous = tail;
            node->next = NULL;
            list->tail = entry;
            if (head == NULL)
                list->head = entry;
            unsigned int count = list->count;
            size_t item_position = position;
            unsigned int span = metadata->span;
            list->count = count + 1U;
            position = item_position + span;
        }
        page = ((volatile NvsPage *)page)->next;
    }
    return 0;
}

/* Native entry: 0x420132b4. */
/* Original function-byte SHA-256:
 * f611c6092bf384a0b40a99e1b49ce5711b22612dd6daad1a34b0c07b6dacef43. */
/* Reconcile each RAM blob index against matching BLOB_DATA items. Match the
 * first node with equal key's first15 bytes, namespace and chunk-version band:
 * [0,128) for start0, otherwise [start,255). This pass does not use chunk_count
 * as the upper bound. Accumulate the original item's HALFWORD payload length
 * and one full32-bit chunk count; existing totals are not reset here.
 * If either observed total differs, search eligible pages to erase its index,
 * then unlink/free the RAM node even if all erase attempts fail. Skip states
 * INVALID0, CORRUPT0xfffffff0 and UNINITIALIZED0xffffffff only. Ignore find
 * errors as page termination. Span0 can prevent forward progress. No status,
 * rollback, list repair, byte-count overflow checks or local synchronization. */
void nvs_storage_erase_mismatched_blob_indexes(NvsStorageView *storage,
    NvsObjectList *indexes)
{
    volatile NvsObjectList *list = indexes;
    volatile NvsStorageView *state = storage;
    NvsPage *page = state->pages.head;
    NvsBlobSearchFrame frame;
    const volatile NvsItem *original = &frame.item;
    const volatile NvsItem *captured = &frame.predicate;
    volatile size_t *position = &frame.position;
    while (page != NULL) {
        *position = 0;
        while (nvs_page_find_item(page,NVS_NAMESPACE_ANY,NVS_ITEM_TYPE_BLOB_DATA,NULL,
                &frame.position,&frame.item,NVS_ITEM_CHUNK_ANY,NVS_ITEM_VERSION_ANY) == 0) {
            NvsBlobIndexNode *entry = list->head;
            nvs_blob_capture_predicate(&frame);
            if (entry != NULL) {
                unsigned int namespace_index = captured->namespace_index;
                unsigned int chunk = captured->chunk_index;
                do {
                    volatile NvsBlobIndexNode *node = entry;
                    if (strncmp(frame.predicate.key,entry->key,15) == 0 &&
                        node->namespace_index == namespace_index) {
                        unsigned int start = node->chunk_start;
                        unsigned int end = start == NVS_BLOB_VERSION_0_OFFSET
                            ? NVS_BLOB_VERSION_1_OFFSET : NVS_ITEM_VERSION_ANY;
                        if (chunk >= start && chunk < end) {
                            unsigned int size = node->observed_data_size;
                            unsigned int count = node->observed_chunk_count;
                            unsigned int payload_length = original->variable.data_size;
                            node->observed_data_size = size + payload_length;
                            node->observed_chunk_count = count + 1U;
                            break;
                        }
                    }
                    entry = node->next;
                } while (entry != NULL);
            }
            size_t item_position = *position;
            unsigned int span = original->span;
            *position = item_position + span;
        }
        page = ((volatile NvsPage *)page)->next;
    }

    NvsBlobIndexNode *entry = list->head;
    while (entry != NULL) {
        volatile NvsBlobIndexNode *node = entry;
        unsigned int observed_size = node->observed_data_size;
        unsigned int expected_size = node->data_size;
        if (observed_size == expected_size) {
            unsigned int expected_count = node->chunk_count;
            unsigned int observed_count = node->observed_chunk_count;
            if (observed_count == expected_count) {
                entry = node->next;
                continue;
            }
        }
        page = state->pages.head;
        while (page != NULL) {
            unsigned int page_state = ((volatile NvsPage *)page)->state;
            if (page_state != NVS_PAGE_STATE_INVALID && page_state != NVS_PAGE_STATE_CORRUPT
                    && page_state != NVS_PAGE_STATE_UNINITIALIZED) {
                unsigned int version = node->chunk_start;
                unsigned int namespace_index = node->namespace_index;
                if (nvs_page_erase_item(page,namespace_index,NVS_ITEM_TYPE_BLOB_INDEX,
                        entry->key,NVS_ITEM_CHUNK_ANY,version) == 0)
                    break;
            }
            page = ((volatile NvsPage *)page)->next;
        }
        NvsBlobIndexNode *previous = node->previous;
        NvsBlobIndexNode *next = node->next;
        if (previous != NULL)
            ((volatile NvsBlobIndexNode *)previous)->next = next;
        else
            list->head = next;
        unsigned int count = list->count;
        if (next != NULL)
            ((volatile NvsBlobIndexNode *)next)->previous = previous;
        else
            list->tail = previous;
        list->count = count - 1U;
        free(entry);
        entry = next;
    }
}

/* Native entry: 0x42013474. */
/* Original function-byte SHA-256:
 * e9ffcdb8c3094b76e035d1b7e1fa94b3bf062c345212ac896ebf91c28ce3020e. */
/* Erase BLOB_DATA items lacking a matching surviving RAM index. Compare key's
 * first15 bytes and namespace, then require start<=chunk<start+chunk_count;
 * this upper sum is32-bit, not byte-wrapped or merely a version-band limit.
 * The predicate uses a copied item; erase uses the original item's freshly
 * read chunk/type/namespace and key. Ignore erase errors, and treat every find
 * error as end of page. Advance by the original span even after failed erasure.
 * No page-state gate, return status, rollback, span validation or local lock. */
void nvs_storage_erase_orphan_blob_data(NvsStorageView *storage,
    NvsObjectList *indexes)
{
    volatile NvsObjectList *list = indexes;
    NvsPage *page = ((volatile NvsStorageView *)storage)->pages.head;
    NvsBlobSearchFrame frame;
    const volatile NvsItem *original = &frame.item;
    const volatile NvsItem *captured = &frame.predicate;
    volatile size_t *position = &frame.position;
    while (page != NULL) {
        *position = 0;
        while (nvs_page_find_item(page,NVS_NAMESPACE_ANY,NVS_ITEM_TYPE_BLOB_DATA,NULL,
                &frame.position,&frame.item,NVS_ITEM_CHUNK_ANY,NVS_ITEM_VERSION_ANY) == 0) {
            NvsBlobIndexNode *entry = list->head;
            nvs_blob_capture_predicate(&frame);
            if (entry != NULL) {
                unsigned int namespace_index = captured->namespace_index;
                unsigned int chunk = captured->chunk_index;
                do {
                    volatile NvsBlobIndexNode *node = entry;
                    if (strncmp(frame.predicate.key,entry->key,15) == 0 &&
                        node->namespace_index == namespace_index) {
                        unsigned int start = node->chunk_start;
                        if (chunk >= start) {
                            unsigned int count = node->chunk_count;
                            if (chunk < start + count)
                                break;
                        }
                    }
                    entry = node->next;
                } while (entry != NULL);
            }
            if (entry == NULL) {
                unsigned int chunk = original->chunk_index;
                unsigned int type = original->type;
                unsigned int namespace_index = original->namespace_index;
                (void)nvs_page_erase_item(page,namespace_index,type,frame.item.key,
                    chunk,NVS_ITEM_VERSION_ANY);
            }
            size_t item_position = *position;
            unsigned int span = original->span;
            *position = item_position + span;
        }
        page = ((volatile NvsPage *)page)->next;
    }
}

/* Native entry: 0x42013580. */
/* Original function-byte SHA-256:
 * d4cc2ae48c07097b6b6692426ab807d69d23ebf1b1fa08c36e59d5bbb3cdcd70. */
/* Initialize storage over the specified sectors. Propagate page-manager load
 * errors after marking INVALID. On success free old namespace nodes, clear
 * the256-bit usage map bytewise, then rebuild namespaces from namespace0/U8
 * items. Terminate keys, mark each index bit and append28-byte RAM nodes.
 * Ignore all find errors as page termination. Reserve namespace bits0/255,
 * collect blob indexes, discard mismatched indexes and erase orphan chunks,
 * then free surviving temporary nodes and mark ACTIVE1. Success returns0.
 * Namespace allocation or index-collection failure marks INVALID/returns0x101;
 * prior namespace/page changes remain, and partial blob nodes are not freed
 * on collection failure. A found non-U8 item frees its node/returns-1 without
 * changing storage_state. Native final cleanup assumes a valid list head:
 * its corrupt non-NULL-previous branch frees without advancing the cursor.
 * No rollback, bounds/duplicate checks, startup flash verification or lock. */
int nvs_storage_initialize(NvsStorageView *storage,
    unsigned int base_sector,unsigned int sector_count)
{
    volatile NvsStorageView *state = storage;
    int result = nvs_page_manager_load(&storage->page_manager,state->partition,base_sector,sector_count);
    if (result != 0) {
        state->storage_state = NVS_STORAGE_STATE_INVALID;
        return result;
    }
    nvs_storage_clear_namespaces(state);
    for (unsigned int byte = 0; byte != sizeof(state->namespace_usage); ++byte)
        state->namespace_usage[byte] = 0;

    NvsPage *page = state->pages.head;
    NvsItem item;
    const volatile NvsItem *metadata = &item;
    volatile size_t position;
    while (page != NULL) {
        position = 0;
        while (nvs_page_find_item(page,0,NVS_ITEM_TYPE_U8,NULL,(size_t *)&position,
                &item,NVS_ITEM_CHUNK_ANY,NVS_ITEM_VERSION_ANY) == 0) {
            NvsNamespaceEntry *entry = malloc(sizeof(*entry));
            if (entry == NULL) {
                state->storage_state = NVS_STORAGE_STATE_INVALID;
                return 0x101;
            }
            volatile NvsNamespaceEntry *node = entry;
            node->previous = NULL;
            node->next = NULL;
            strncpy(entry->name,item.key,16);
            unsigned int type = metadata->type;
            node->name[15] = '\0';
            if (type != NVS_ITEM_TYPE_U8) {
                free(entry);
                return -1;
            }
            unsigned int index = metadata->data[0];
            NvsNamespaceEntry *tail = state->namespaces.tail;
            unsigned int word = index >> 5;
            unsigned int usage = state->namespace_usage_words[word];
            state->namespace_usage_words[word] = usage | (1U << (index & 31U));
            node->index = index;
            if (tail != NULL) {
                ((volatile NvsNamespaceEntry *)tail)->next = entry;
                tail = state->namespaces.tail;
            }
            void *head = state->namespaces.head;
            node->previous = tail;
            node->next = NULL;
            state->namespaces.tail = entry;
            if (head == NULL)
                state->namespaces.head = entry;
            unsigned int count = state->namespaces.count;
            size_t item_position = position;
            unsigned int span = metadata->span;
            state->namespaces.count = count + 1U;
            position = item_position + span;
        }
        page = ((volatile NvsPage *)page)->next;
    }
    unsigned int first_word = state->namespace_usage_words[0];
    unsigned int last_word = state->namespace_usage_words[7];
    state->namespace_usage_words[0] = first_word | 1U;
    state->namespace_usage_words[7] = last_word | 0x80000000U;
    NvsObjectList indexes;
    volatile NvsObjectList *list = &indexes;
    list->tail = NULL;
    list->head = NULL;
    list->count = 0;
    result = nvs_storage_populate_blob_indexes(storage,&indexes);
    if (result != 0) {
        state->storage_state = NVS_STORAGE_STATE_INVALID;
        return 0x101;
    }
    nvs_storage_erase_mismatched_blob_indexes(storage,&indexes);
    NvsBlobIndexNode *entry = list->head;
    nvs_storage_erase_orphan_blob_data(storage,&indexes);
    while (entry != NULL) {
        volatile NvsBlobIndexNode *node = entry;
        NvsBlobIndexNode *previous = node->previous;
        NvsBlobIndexNode *next = node->next;
        if (previous != NULL) {
            ((volatile NvsBlobIndexNode *)previous)->next = next;
            if (next != NULL)
                ((volatile NvsBlobIndexNode *)next)->previous = previous;
            else
                list->tail = previous;
            free(entry);
            /* Native corrupt-list branch repeats the same cursor. */
            continue;
        }
        if (next != NULL)
            ((volatile NvsBlobIndexNode *)next)->previous = NULL;
        free(entry);
        entry = next;
    }
    state->storage_state = NVS_STORAGE_STATE_ACTIVE;
    return 0;
}
