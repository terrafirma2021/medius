/* Medius v3.4.7 device: page-array loading and interrupted-move recovery. */
#include "../include/types.h"

/* Inline reconstruction utilities for native inlined list/array operations.
 * They represent no additional firmware functions or review entries. */
/* Unlink until the head is NULL, keeping the count in a register. A node
 * with a previous link selects the next iteration's node from the current
 * head before writing previous->next. No nodes are destroyed here. */
static __inline__ __attribute__((always_inline)) void
nvs_page_manager_clear_list_links(volatile NvsObjectList *list,NvsPage *first)
{
    volatile NvsPage *page = first;
    if (page == NULL)
        return;
    unsigned int count = list->count;
    do {
        NvsPage *previous = page->previous;
        NvsPage *next = page->next;
        if (previous != NULL) {
            page = list->head;
            ((volatile NvsPage *)previous)->next = next;
        } else {
            list->head = next;
            page = next;
        }
        if (next != NULL)
            ((volatile NvsPage *)next)->previous = previous;
        else
            list->tail = previous;
        --count;
    } while (page != NULL);
    list->count = count;
}

/* pages addresses the first element, not its four-byte allocation cookie.
 * Destroy per-page hash lists from last to first, then free the cookie base.
 * The caller supplies a non-NULL array; cookie and links are not validated. */
static __inline__ __attribute__((always_inline)) void
nvs_page_array_destroy(void *pages)
{
    uintptr_t start = (uintptr_t)pages;
    unsigned int count = ((const volatile NvsPageArrayAllocation *)
        (start - offsetof(NvsPageArrayAllocation,pages)))->count;
    uintptr_t cursor = start + count * sizeof(NvsPage);
    while (cursor != start) {
        cursor -= sizeof(NvsPage);
        nvs_hash_list_destroy((NvsObjectList *)(cursor + offsetof(NvsPage,hash_blocks)));
    }
    free((void *)(start - offsetof(NvsPageArrayAllocation,pages)));
}

/* This loader's append order is previous, then next=NULL. Other native
 * list operations may use a different order; do not replace them wholesale. */
static __inline__ __attribute__((always_inline)) unsigned int
nvs_page_manager_move_active_to_free(volatile NvsPageManagerView *state,
    NvsPage *page)
{
    volatile NvsPage *node = page;
    NvsPage *previous = node->previous;
    NvsPage *next = node->next;
    if (previous != NULL)
        ((volatile NvsPage *)previous)->next = next;
    else
        state->pages.head = next;
    if (next != NULL)
        ((volatile NvsPage *)next)->previous = previous;
    else
        state->pages.tail = previous;
    unsigned int active_count = state->pages.count;
    NvsPage *tail = state->free_pages.tail;
    state->pages.count = active_count - 1U;
    if (tail != NULL)
        ((volatile NvsPage *)tail)->next = page;
    node->previous = tail;
    node->next = NULL;
    void *head = state->free_pages.head;
    state->free_pages.tail = page;
    if (head == NULL)
        state->free_pages.head = page;
    unsigned int free_count = state->free_pages.count + 1U;
    state->free_pages.count = free_count;
    return free_count;
}

/* Native entry: 0x42015ecc. */
/* Original function-byte SHA-256:
 * da370d508630d9edf9f095ee81644a8dce0b28bd7479f69554f68206bca96aae. */
/* Load a partition's page manager. NULL partition returns0x102 untouched.
 * Store base/count, unlink both lists using cached counts, allocate Page[]
 * with a count cookie and construct84-byte elements. Counts>0x1861861 request
 * malloc(0xffffffff); constructor iteration uses signed(count-1). Publish the
 * new array before destroying the old array's hash lists in reverse order.
 * Allocation failure still drops/destroys the old array; return0x101 unless
 * cleanup has published a replacement pointer. Zero pages can reach activation.
 * Load each page and sort valid sequences; other pages enter the free list.
 * Empty active count sets sequence0 and returns activation's status directly.
 * Otherwise advance the last sequence, remove older matching last-page items
 * and recover the first FREEING page, optionally discarding an ACTIVE tail.
 * Duplicate cleanup uses the metadata left by the final lookup; a failed
 * lookup can leave a different item there than the last successful match.
 * Several duplicate-search/erase errors are ignored; recovery errors return
 * after any prior changes. Require a nonzero final free count or0x110d.
 * No rollback, list repair, pointer/count bounds validation or local lock. */
int nvs_page_manager_load(NvsPageManagerView *manager,
    NvsPartitionObject *partition,unsigned int base_sector,unsigned int sector_count)
{
    if (partition == NULL)
        return 0x102;
    volatile NvsPageManagerView *state = manager;
    NvsPage *head = state->pages.head;
    state->base_sector = base_sector;
    state->managed_page_count = sector_count;
    nvs_page_manager_clear_list_links(&state->pages,head);
    head = state->free_pages.head;
    nvs_page_manager_clear_list_links(&state->free_pages,head);

    size_t allocation_size = sector_count <= NVS_PAGE_ARRAY_MAX_COUNT
        ? sector_count * sizeof(NvsPage) + offsetof(NvsPageArrayAllocation,pages)
        : 0xffffffffU;
    NvsPageArrayAllocation *allocation = malloc(allocation_size);
    void *pages = NULL;
    void *old_pages;
    if (allocation != NULL) {
        ((volatile NvsPageArrayAllocation *)allocation)->count = sector_count;
        pages = (void *)((uintptr_t)allocation + offsetof(NvsPageArrayAllocation,pages));
        int remaining = (int)(sector_count - 1U);
        if (remaining >= 0) {
            uintptr_t current = (uintptr_t)pages;
            do {
                --remaining;
                nvs_page_construct((NvsPage *)current);
                current += sizeof(NvsPage);
            } while (remaining != -1);
        }
        old_pages = state->page_array;
        state->page_array = pages;
    } else {
        old_pages = state->page_array;
        state->page_array = NULL;
    }
    if (old_pages != NULL) {
        nvs_page_array_destroy(old_pages);
        pages = state->page_array;
        if (pages == NULL)
            return 0x101;
    } else if (allocation == NULL) {
        return 0x101;
    }

    NvsItem item;
    const volatile NvsItem *metadata = &item;
    volatile size_t position;
    int result;
    if (sector_count != 0) {
        unsigned int sector = base_sector;
        unsigned int end_sector = base_sector + sector_count;
        unsigned int offset = 0;
        do {
            NvsPage *page = (NvsPage *)((uintptr_t)pages + offset);
            result = nvs_page_load(page,partition,sector);
            if (result != 0)
                return result;
            page = (NvsPage *)((uintptr_t)state->page_array + offset);
            result = nvs_page_get_sequence(page,(unsigned int *)&position);
            if (result != 0) {
                page = (NvsPage *)((uintptr_t)state->page_array + offset);
                NvsPage *tail = state->free_pages.tail;
                if (tail != NULL)
                    ((volatile NvsPage *)tail)->next = page;
                ((volatile NvsPage *)page)->previous = tail;
                ((volatile NvsPage *)page)->next = NULL;
                void *free_head = state->free_pages.head;
                state->free_pages.tail = page;
                if (free_head == NULL)
                    state->free_pages.head = page;
                state->free_pages.count = state->free_pages.count + 1U;
            } else {
                volatile NvsPage *existing = state->pages.head;
                unsigned int sequence = position;
                bool initially_empty = existing == NULL;
                while (existing != NULL) {
                    result = nvs_page_get_sequence((NvsPage *)existing,&item.header);
                    if (result == 0 && metadata->header > sequence)
                        break;
                    existing = existing->next;
                }
                page = (NvsPage *)((uintptr_t)state->page_array + offset);
                if (existing != NULL) {
                    unsigned int count = state->pages.count;
                    NvsPage *previous = existing->previous;
                    if (previous != NULL) {
                        ((volatile NvsPage *)previous)->next = page;
                        existing->previous = page;
                        ((volatile NvsPage *)page)->next = (NvsPage *)existing;
                        ((volatile NvsPage *)page)->previous = previous;
                    } else {
                        NvsPage *current_head = state->pages.head;
                        ((volatile NvsPage *)page)->previous = NULL;
                        ((volatile NvsPage *)page)->next = current_head;
                        if (current_head != NULL)
                            ((volatile NvsPage *)current_head)->previous = page;
                        void *tail = state->pages.tail;
                        state->pages.head = page;
                        if (tail == NULL)
                            state->pages.tail = page;
                    }
                    state->pages.count = count + 1U;
                } else {
                    NvsPage *tail = state->pages.tail;
                    void *current_head = NULL;
                    if (!initially_empty)
                        current_head = state->pages.head;
                    if (tail != NULL)
                        ((volatile NvsPage *)tail)->next = page;
                    ((volatile NvsPage *)page)->previous = tail;
                    ((volatile NvsPage *)page)->next = NULL;
                    state->pages.tail = page;
                    if (initially_empty || current_head == NULL)
                        state->pages.head = page;
                    state->pages.count = state->pages.count + 1U;
                }
            }
            ++sector;
            offset += sizeof(NvsPage);
            if (sector == end_sector)
                break;
            pages = state->page_array;
        } while (true);
    }

    unsigned int active_count = state->pages.count;
    if (active_count == 0) {
        state->page_sequence = 0;
        return nvs_page_manager_activate_page(manager);
    }
    NvsPage *last_page = state->pages.tail;
    result = nvs_page_get_sequence(last_page,&item.header);
    if (result != 0)
        return result;
    unsigned int last_sequence = metadata->header;
    last_page = state->pages.tail;
    state->page_sequence = last_sequence + 1U;
    size_t after_last_item = NVS_PAGE_INVALID_ENTRY;
    position = 0;
    for (;;) {
        result = nvs_page_find_item(last_page,NVS_NAMESPACE_ANY,NVS_ITEM_TYPE_ANY,NULL,
            (size_t *)&position,&item,NVS_ITEM_CHUNK_ANY,NVS_ITEM_VERSION_ANY);
        if (result != 0)
            break;
        size_t found_position = position;
        unsigned int span = metadata->span;
        after_last_item = found_position + span;
        position = after_last_item;
    }

    NvsPage *recovery = state->pages.head;
    if (after_last_item != NVS_PAGE_INVALID_ENTRY && recovery != last_page) {
        NvsPage *scan = recovery;
        while (scan != last_page) {
            if (((const volatile NvsPage *)scan)->state != NVS_PAGE_STATE_FREEING) {
                unsigned int chunk = metadata->chunk_index;
                unsigned int type = metadata->type;
                unsigned int namespace_index = metadata->namespace_index;
                if (nvs_page_erase_item(scan,namespace_index,type,item.key,chunk,NVS_ITEM_VERSION_ANY) == 0)
                    break;
            }
            scan = ((const volatile NvsPage *)scan)->next;
        }
        recovery = state->pages.head;
        if (scan == last_page && metadata->type == NVS_ITEM_TYPE_BLOB_INDEX
                && recovery != last_page) {
            scan = recovery;
            while (scan != last_page) {
                if (((const volatile NvsPage *)scan)->state != NVS_PAGE_STATE_FREEING) {
                    unsigned int chunk = metadata->chunk_index;
                    unsigned int namespace_index = metadata->namespace_index;
                    if (nvs_page_erase_item(scan,namespace_index,NVS_ITEM_TYPE_BLOB,
                            item.key,chunk,NVS_ITEM_VERSION_ANY) == 0)
                        break;
                }
                scan = ((const volatile NvsPage *)scan)->next;
            }
            recovery = state->pages.head;
        }
    }

    while (recovery != NULL) {
        if (((const volatile NvsPage *)recovery)->state == NVS_PAGE_STATE_FREEING) {
            NvsPage *tail = state->pages.tail;
            if (((const volatile NvsPage *)tail)->state == NVS_PAGE_STATE_ACTIVE) {
                result = nvs_page_erase(tail);
                if (result != 0)
                    return result;
                (void)nvs_page_manager_move_active_to_free(state,tail);
            }
            result = nvs_page_manager_activate_page(manager);
            if (result != 0)
                return result;
            tail = state->pages.tail;
            result = nvs_page_copy_items(recovery,tail);
            if (result != 0 && result != 0x1102)
                return result;
            result = nvs_page_erase(recovery);
            if (result != 0)
                return result;
            unsigned int free_count = nvs_page_manager_move_active_to_free(state,recovery);
            return free_count == 0 ? 0x110d : 0;
        }
        recovery = ((const volatile NvsPage *)recovery)->next;
    }
    return state->free_pages.count == 0 ? 0x110d : 0;
}
