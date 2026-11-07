/* Medius v3.4.7 device: page loading, copying and space reclamation. */
#include "../include/types.h"

/* Inline reconstruction utilities for the native packed table operations;
 * these are not additional native functions or review entries. */
static __inline__ __attribute__((always_inline)) unsigned int
nvs_recovery_entry_state(const volatile NvsPage *page,size_t position)
{
    unsigned int word = page->entry_state_table[position >> 4];
    return (word >> ((position & 15U) * 2U)) & 3U;
}

/* Native entry: 0x42014ddc. */
/* Original function-byte SHA-256:
 * b12aef98c38b5d3cf055defe59a44273c748814b637375b5325136aefada371a. */
/* Copy WRITTEN entries and their data spans into destination, beginning at
 * source's first-used cursor. A0xffffffff cursor returns NOT_FOUND. Initialize
 * an UNINITIALIZED destination, then re-read source's first-used cursor.
 * Other starting cursors>125 return success. Scan through entry125, ignoring
 * source next-free. A non-WRITTEN current first-used entry returns -1.
 * Cache and write each header before checking its span end<=126; copy every
 * following32-byte entry without header/data CRC or table-state validation.
 * Errors retain destination cache/flash changes. Source is not invalidated
 * or erased here. A zero span can repeat indefinitely; no guard is added. */
int nvs_page_copy_items(NvsPage *source,
    NvsPage *destination)
{
    const volatile NvsPage *from = source;
    const volatile NvsPage *to = destination;
    size_t cursor = from->first_used_entry;
    if (cursor == NVS_PAGE_INVALID_ENTRY)
        return 0x1102;
    if (to->state == NVS_PAGE_STATE_UNINITIALIZED) {
        int result = nvs_page_initialize(destination);
        if (result != 0)
            return result;
        cursor = from->first_used_entry;
    }
    if (cursor >= NVS_PAGE_ENTRY_COUNT)
        return 0;
    do {
        if (nvs_recovery_entry_state(from,cursor) != NVS_ENTRY_STATE_WRITTEN) {
            if (from->first_used_entry == cursor)
                return -1;
            ++cursor;
            continue;
        }
        NvsItem item;
        NvsPartitionObject *partition = from->partition;
        unsigned int base_address = from->base_address;
        const volatile NvsPartitionVtable *vtable = partition->vtable;
        NvsPartitionRead read = vtable->read;
        int result = read(partition,base_address + NVS_PAGE_ENTRY_DATA_OFFSET
            + cursor * NVS_PAGE_ENTRY_SIZE,&item,sizeof(item));
        if (result != 0)
            return result;
        size_t next_free = to->next_free_entry;
        result = nvs_hash_list_insert(&destination->hash_blocks,&item,next_free);
        if (result != 0)
            return result;
        result = nvs_page_write_entry(destination,&item);
        if (result != 0)
            return result;
        unsigned int span = ((const volatile NvsItem *)&item)->span;
        size_t end = cursor + span;
        if (end > NVS_PAGE_ENTRY_COUNT)
            return -1;
        size_t payload = cursor + 1U;
        while (payload < end) {
            partition = from->partition;
            base_address = from->base_address;
            vtable = partition->vtable;
            read = vtable->read;
            result = read(partition,base_address + NVS_PAGE_ENTRY_DATA_OFFSET
                + payload * NVS_PAGE_ENTRY_SIZE,&item,sizeof(item));
            if (result != 0)
                return result;
            result = nvs_page_write_entry(destination,&item);
            if (result != 0)
                return result;
            ++payload;
        }
        cursor = end;
    } while (cursor != NVS_PAGE_ENTRY_COUNT);
    return 0;
}

/* Native entry: 0x42015b30. */
/* Original function-byte SHA-256:
 * ac29608bcfdee34e5517163038a1563155d954c02bdb2ed877b36f4546872ac0. */
/* Load a page header using read_raw. NULL partition returns0x102. Publish
 * partition, zero both counters and set the wrapped sector address first.
 * An erased header triggers512-byte raw reads to check the entire sector;
 * dirty data marks CORRUPT, read errors mark INVALID, allocation failure101
 * leaves UNINITIALIZED. Sector size is read live between blocks.
 * A bad header CRC changes only the LOCAL header state; dispatch uses the
 * page's previous state. A valid header publishes sequence/state before
 * rejecting versions<0xfe with0x1110. Load the table for ACTIVE/FULL/FREEING;
 * retain UNINITIALIZED and otherwise mark CORRUPT. Prior cursors/hash remain
 * until the table loader acts. No erase, rollback or independent lock. */
int nvs_page_load(NvsPage *page,
    NvsPartitionObject *partition,unsigned int sector_number)
{
    if (partition == NULL)
        return 0x102;
    volatile NvsPage *state = page;
    state->partition = partition;
    unsigned int sector_size = NVS_SECTOR_SIZE;
    unsigned int base_address = sector_number * sector_size;
    state->entry_counts = 0;
    state->base_address = base_address;
    NvsPageHeader header;
    volatile NvsPageHeader *local = &header;
    for (unsigned int i = 0; i != 19U; ++i)
        local->reserved[i] = 0xff;
    const volatile NvsPartitionVtable *vtable = partition->vtable;
    NvsPartitionRead read_raw = vtable->read_raw;
    int result = read_raw(partition,base_address,&header,sizeof(header));
    if (result != 0) {
        state->state = NVS_PAGE_STATE_INVALID;
        return result;
    }
    unsigned int page_state;
    if (local->state == NVS_PAGE_STATE_UNINITIALIZED) {
        state->state = NVS_PAGE_STATE_UNINITIALIZED;
        unsigned int *buffer = cxx_operator_new_array_nothrow(NVS_PAGE_ERASE_SCAN_SIZE,CXX_NOTHROW_TAG);
        if (buffer == NULL)
            return 0x101;
        unsigned int offset = 0;
        sector_size = NVS_SECTOR_SIZE;
        while (offset < sector_size) {
            partition = state->partition;
            base_address = state->base_address;
            vtable = partition->vtable;
            read_raw = vtable->read_raw;
            result = read_raw(partition,base_address + offset,buffer,NVS_PAGE_ERASE_SCAN_SIZE);
            if (result != 0) {
                state->state = NVS_PAGE_STATE_INVALID;
                cxx_operator_delete_array(buffer);
                return result;
            }
            bool empty = true;
            for (unsigned int word = 0; word != NVS_PAGE_ERASE_SCAN_SIZE / sizeof(*buffer); ++word) {
                if (((const volatile unsigned int *)buffer)[word] != 0xffffffffU) {
                    empty = false;
                    break;
                }
            }
            if (!empty) {
                state->state = NVS_PAGE_STATE_CORRUPT;
                break;
            }
            sector_size = NVS_SECTOR_SIZE;
            offset += NVS_PAGE_ERASE_SCAN_SIZE;
        }
        cxx_operator_delete_array(buffer);
        page_state = state->state;
    } else {
        unsigned int expected_crc = local->crc32;
        unsigned int crc = esp_rom_crc32_le(0xffffffffU,&header.sequence,
            offsetof(NvsPageHeader,crc32) - offsetof(NvsPageHeader,sequence));
        if (expected_crc != crc) {
            page_state = state->state;
            local->state = NVS_PAGE_STATE_CORRUPT;
        } else {
            unsigned int sequence = local->sequence;
            page_state = local->state;
            unsigned int version = local->version;
            state->sequence = sequence;
            state->state = page_state;
            if (version < NVS_PAGE_FORMAT_VERSION)
                return 0x1110;
            state->version = (unsigned char)version;
        }
    }
    if (page_state == NVS_PAGE_STATE_UNINITIALIZED)
        return 0;
    if (page_state == NVS_PAGE_STATE_FULL || page_state == NVS_PAGE_STATE_FREEING
            || page_state == NVS_PAGE_STATE_ACTIVE)
        return nvs_page_load_entry_table(page);
    state->state = NVS_PAGE_STATE_CORRUPT;
    return 0;
}

/* Native entry: 0x42015e04. */
/* Original function-byte SHA-256:
 * 68472f71f6176d71ae4a36d02e2100d0bc97c2a91504cc04e786e29845fb4e2d. */
/* Request an active page. No free pages returns0x110b; at least two delegates
 * directly to activation. With one free page, select the first active-list
 * page maximizing unsigned(126-used_count), mark FREEING, activate another
 * page, copy items and erase the selected page. Copy NOT_FOUND is tolerated.
 * After erasure require the destination's used count to match the selected
 * count sampled before marking; mismatch returns -1 before list movement.
 * Then move the erased page to the free-list tail. Partial failures retain
 * prior state/flash/list effects. Corrupt counts can underflow the selection
 * score. No rollback, state filtering during selection or local lock. */
int nvs_page_manager_request_new_page(NvsPageManagerView *manager)
{
    volatile NvsPageManagerView *state = manager;
    unsigned int free_count = state->free_pages.count;
    if (free_count == 0)
        return 0x110b;
    if (free_count != 1)
        return nvs_page_manager_activate_page(manager);
    volatile NvsPage *candidate = state->pages.head;
    if (candidate == NULL)
        return 0x1105;
    NvsPage *selected = NULL;
    unsigned int most_unused = 0;
    do {
        unsigned int unused = NVS_PAGE_ENTRY_COUNT - candidate->used_entry_count;
        if (unused > most_unused) {
            selected = (NvsPage *)candidate;
            most_unused = unused;
        }
        candidate = candidate->next;
    } while (candidate != NULL);
    if (most_unused == 0)
        return 0x1105;
    unsigned int previous_used = ((const volatile NvsPage *)selected)->used_entry_count;
    int result = nvs_page_mark_freeing(selected);
    if (result != 0)
        return result;
    result = nvs_page_manager_activate_page(manager);
    if (result != 0)
        return result;
    NvsPage *destination = state->pages.tail;
    result = nvs_page_copy_items(selected,destination);
    if (result != 0 && result != 0x1102)
        return result;
    result = nvs_page_erase(selected);
    if (result != 0)
        return result;
    if (((const volatile NvsPage *)destination)->used_entry_count != previous_used)
        return -1;

    NvsPage *previous = ((volatile NvsPage *)selected)->previous;
    NvsPage *next = ((volatile NvsPage *)selected)->next;
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
        ((volatile NvsPage *)tail)->next = selected;
    ((volatile NvsPage *)selected)->next = NULL;
    ((volatile NvsPage *)selected)->previous = tail;
    void *head = state->free_pages.head;
    state->free_pages.tail = selected;
    if (head == NULL)
        state->free_pages.head = selected;
    state->free_pages.count = state->free_pages.count + 1U;
    return result;
}

/* Native entry: 0x4201577c. */
/* Original function-byte SHA-256:
 * 03968ec5f6e9bc2aa9e42fc26922fe54d8f3b184aeab4f862e4c6c9032dd37a7. */
/* Recover a page's entry table, counters and hash cache. ACTIVE/FULL/FREEING
 * read the32-byte table through read_raw; other states count the existing
 * table without reading flash. Reset both counters, but retain an existing
 * first-used cursor and hash list. Count all126 packed entry states.
 * ACTIVE finds the first EMPTY slot, erases partially written entries beyond
 * it, checks item headers/spans, inserts hashes and removes earlier cached
 * hash matches. Several duplicate/incomplete-span erasures ignore errors.
 * FULL/FREEING rebuild hashes from first-used and skip each validated span.
 * Read, hash-insert and selected cleanup errors mark INVALID; bounds failures
 * return -1 without that extra write. Preserve partial updates, live field
 * reads and zero-span retry behavior. No rollback, timeout or local lock. */
int nvs_page_load_entry_table(NvsPage *page)
{
    volatile NvsPage *state = page;
    unsigned int page_state = state->state;
    int result;
    if (page_state == NVS_PAGE_STATE_FREEING || page_state == NVS_PAGE_STATE_FULL
            || page_state == NVS_PAGE_STATE_ACTIVE) {
        NvsPartitionObject *partition = state->partition;
        unsigned int base_address = state->base_address;
        const volatile NvsPartitionVtable *vtable = partition->vtable;
        NvsPartitionRead read_raw = vtable->read_raw;
        result = read_raw(partition,base_address + NVS_PAGE_ENTRY_TABLE_OFFSET,
            page->entry_state_table,sizeof(page->entry_state_table));
        if (result != 0)
            goto invalid;
        page_state = state->state;
    }
    state->entry_counts = 0;
    for (size_t cursor = 0; cursor != NVS_PAGE_ENTRY_COUNT; ++cursor) {
        unsigned int entry_state = nvs_recovery_entry_state(state,cursor);
        if (entry_state == NVS_ENTRY_STATE_WRITTEN) {
            if (state->first_used_entry == NVS_PAGE_INVALID_ENTRY)
                state->first_used_entry = cursor;
            unsigned int used = state->used_entry_count;
            state->used_entry_count = (unsigned short)(used + 1U);
        } else if (entry_state == NVS_ENTRY_STATE_ERASED) {
            unsigned int erased = state->erased_entry_count;
            state->erased_entry_count = (unsigned short)(erased + 1U);
        }
    }

    NvsItem scratch_item;
    if (page_state == NVS_PAGE_STATE_ACTIVE) {
        size_t next_free = 0;
        bool found_empty = false;
        for (; next_free != NVS_PAGE_ENTRY_COUNT; ++next_free) {
            if (nvs_recovery_entry_state(state,next_free) == NVS_ENTRY_STATE_EMPTY) {
                state->next_free_entry = next_free;
                found_empty = true;
                break;
            }
        }
        if (!found_empty)
            next_free = state->next_free_entry;
        size_t scan_end = NVS_PAGE_ENTRY_COUNT;
        while (next_free < NVS_PAGE_ENTRY_COUNT) {
            NvsPartitionObject *partition = state->partition;
            unsigned int base_address = state->base_address;
            const volatile NvsPartitionVtable *vtable = partition->vtable;
            NvsPartitionRead read_raw = vtable->read_raw;
            result = read_raw(partition,base_address + NVS_PAGE_ENTRY_DATA_OFFSET
                + next_free * NVS_PAGE_ENTRY_SIZE,&scratch_item.header,sizeof(scratch_item.header));
            if (result != 0)
                goto invalid;
            unsigned int header = ((const volatile NvsItem *)&scratch_item)->header;
            next_free = state->next_free_entry;
            if (header == 0xffffffffU) {
                scan_end = next_free < NVS_PAGE_ENTRY_COUNT ? next_free : NVS_PAGE_ENTRY_COUNT;
                if (next_free == 0)
                    return 0;
                break;
            }
            if (next_free >= NVS_PAGE_ENTRY_COUNT)
                return -1;
            unsigned int old_state = nvs_recovery_entry_state(state,next_free);
            result = nvs_page_alter_entry_state(page,next_free,NVS_ENTRY_STATE_ERASED);
            if (result != 0)
                goto invalid;
            next_free = state->next_free_entry + 1U;
            state->next_free_entry = next_free;
            if (old_state == NVS_ENTRY_STATE_WRITTEN) {
                unsigned int used = state->used_entry_count;
                state->used_entry_count = (unsigned short)(used - 1U);
            }
            unsigned int erased = state->erased_entry_count;
            state->erased_entry_count = (unsigned short)(erased + 1U);
        }

        NvsItem item;
        const volatile NvsItem *value = &item;
        size_t cursor = 0;
        size_t last_item = NVS_PAGE_INVALID_ENTRY;
        do {
            unsigned int entry_state = nvs_recovery_entry_state(state,cursor);
            if (entry_state == NVS_ENTRY_STATE_ERASED) {
                ++cursor;
                last_item = NVS_PAGE_INVALID_ENTRY;
                continue;
            }
            if (entry_state == NVS_ENTRY_STATE_ILLEGAL) {
                result = nvs_page_erase_entry_and_span(page,cursor);
                if (result != 0)
                    goto invalid;
                ++cursor;
                last_item = NVS_PAGE_INVALID_ENTRY;
                continue;
            }
            NvsPartitionObject *partition = state->partition;
            unsigned int base_address = state->base_address;
            const volatile NvsPartitionVtable *vtable = partition->vtable;
            NvsPartitionRead read = vtable->read;
            result = read(partition,base_address + NVS_PAGE_ENTRY_DATA_OFFSET
                + cursor * NVS_PAGE_ENTRY_SIZE,&item,sizeof(item));
            if (result != 0)
                goto invalid;
            if (!nvs_item_header_is_consistent(&item,cursor)) {
                result = nvs_page_erase_entry_and_span(page,cursor);
                if (result != 0)
                    goto invalid;
                last_item = cursor;
                ++cursor;
                continue;
            }
            result = nvs_hash_list_insert(&page->hash_blocks,&item,cursor);
            if (result != 0)
                goto invalid;
            size_t duplicate = nvs_hash_list_find(&page->hash_blocks,0,&item);
            unsigned int type = value->type;
            size_t end = cursor + 1U;
            if (type == NVS_ITEM_TYPE_STRING || type == NVS_ITEM_TYPE_BLOB
                    || type == NVS_ITEM_TYPE_BLOB_DATA) {
                end = cursor + value->span;
                bool incomplete = false;
                for (size_t check = cursor; check < end; ++check) {
                    if (check == NVS_PAGE_ENTRY_COUNT)
                        return -1;
                    if (nvs_recovery_entry_state(state,check) != NVS_ENTRY_STATE_WRITTEN) {
                        incomplete = true;
                        break;
                    }
                }
                if (incomplete) {
                    (void)nvs_page_erase_entry_and_span(page,cursor);
                    cursor = end;
                    last_item = NVS_PAGE_INVALID_ENTRY;
                    continue;
                }
            }
            if (duplicate < cursor)
                (void)nvs_page_erase_entry_and_span(page,duplicate);
            last_item = cursor;
            cursor = end;
        } while (cursor < scan_end);
        if (last_item != NVS_PAGE_INVALID_ENTRY) {
            unsigned int type = value->type;
            unsigned int namespace_index = value->namespace_index;
            size_t position = 0;
            result = nvs_page_find_item(page,namespace_index,type,item.key,
                &position,&scratch_item,NVS_ITEM_CHUNK_ANY,NVS_ITEM_VERSION_ANY);
            if (result == 0) {
                size_t earlier = *(volatile size_t *)&position;
                if (earlier < last_item) {
                    result = nvs_page_erase_entry_and_span(page,earlier);
                    if (result != 0)
                        goto invalid;
                }
            }
        }
        return 0;
    }

    if (page_state != NVS_PAGE_STATE_FULL && page_state != NVS_PAGE_STATE_FREEING)
        return 0;
    size_t cursor = state->first_used_entry;
    if (cursor >= NVS_PAGE_ENTRY_COUNT)
        return 0;
    const volatile NvsItem *value = &scratch_item;
    do {
        if (nvs_recovery_entry_state(state,cursor) != NVS_ENTRY_STATE_WRITTEN) {
            ++cursor;
            continue;
        }
        NvsPartitionObject *partition = state->partition;
        unsigned int base_address = state->base_address;
        const volatile NvsPartitionVtable *vtable = partition->vtable;
        NvsPartitionRead read = vtable->read;
        result = read(partition,base_address + NVS_PAGE_ENTRY_DATA_OFFSET
            + cursor * NVS_PAGE_ENTRY_SIZE,&scratch_item,sizeof(scratch_item));
        if (result != 0)
            goto invalid;
        if (!nvs_item_header_is_consistent(&scratch_item,cursor)) {
            result = nvs_page_erase_entry_and_span(page,cursor);
            if (result != 0)
                goto invalid;
            ++cursor;
            continue;
        }
        if (value->span == 0)
            return -1;
        result = nvs_hash_list_insert(&page->hash_blocks,&scratch_item,cursor);
        if (result != 0)
            goto invalid;
        unsigned int type = value->type;
        unsigned int span = value->span;
        if (type == NVS_ITEM_TYPE_STRING || type == NVS_ITEM_TYPE_BLOB
                || type == NVS_ITEM_TYPE_BLOB_DATA) {
            size_t end = cursor + span;
            for (size_t check = cursor + 1U; check < end; ++check) {
                if (check == NVS_PAGE_ENTRY_COUNT)
                    return -1;
                if (nvs_recovery_entry_state(state,check) != NVS_ENTRY_STATE_WRITTEN) {
                    (void)nvs_page_erase_entry_and_span(page,cursor);
                    break;
                }
            }
        }
        cursor += span;
    } while (cursor < NVS_PAGE_ENTRY_COUNT);
    return 0;

invalid:
    state->state = NVS_PAGE_STATE_INVALID;
    return result;
}
