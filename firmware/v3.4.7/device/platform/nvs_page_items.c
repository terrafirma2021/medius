/* Medius v3.4.7 device: NVS page item write, erase, lookup and comparison. */
#include "../include/types.h"

/* Inline reconstruction utilities for native inlined operations; these are
 * not additional firmware functions or native review entries. */
/* Read one cached two-bit state. The caller supplies a validated position;
 * this inlined operation adds no bounds check or flash access. */
static __inline__ __attribute__((always_inline)) unsigned int
nvs_page_entry_state(const volatile NvsPage *page,size_t position)
{
    unsigned int word = page->entry_state_table[position >> 4];
    return (word >> ((position & 15U) * 2U)) & 3U;
}

static __inline__ __attribute__((always_inline)) bool
nvs_item_type_is_variable(unsigned int type)
{
    return type == NVS_ITEM_TYPE_STRING || type == NVS_ITEM_TYPE_BLOB
        || type == NVS_ITEM_TYPE_BLOB_DATA;
}

/* Native entry: 0x42014f44. */
/* Original function-byte SHA-256:
 * 792d763c9d145f8562981795da53e8021cb099556cc95befff4e03cb9629932d. */
/* Write an item and any following data entries. Reject INVALID, initialize
 * UNINITIALIZED, then reject FULL. Key length is limited to15 and all values
 * to4000 bytes. Fixed types accept sizes0..8; variable types21/41/42 reserve
 * a header entry plus rounded32-byte payload entries. Namespace/type/chunk
 * narrow to bytes. Cursor addition is unsigned and is not overflow-checked.
 * Insert the hash before calculating/storing data and header CRCs or writing
 * flash; later errors leave that cache entry and any partial writes in place.
 * Full payload blocks use the bulk writer; a partial last block is padded
 * with0xff. Return the first failure without rollback, flush or local lock. */
int nvs_page_write_item(NvsPage *page,
    unsigned int namespace_index,unsigned int type,const char *key,
    const void *value,size_t size,unsigned int chunk_index)
{
    volatile NvsPage *state = page;
    unsigned int page_state = state->state;
    namespace_index &= 255U;
    type &= 255U;
    chunk_index &= 255U;
    if (page_state == NVS_PAGE_STATE_INVALID)
        return 0x110b;
    int result;
    if (page_state == NVS_PAGE_STATE_UNINITIALIZED) {
        result = nvs_page_initialize(page);
        if (result != 0)
            return result;
        page_state = state->state;
    }
    if (page_state == NVS_PAGE_STATE_FULL)
        return 0x110a;
    if (strlen(key) > 15U)
        return 0x1109;
    if (size > (NVS_PAGE_ENTRY_COUNT - 1U) * NVS_PAGE_ENTRY_SIZE)
        return 0x110e;

    bool variable = nvs_item_type_is_variable(type);
    unsigned int entry_count = 1;
    unsigned int total_bytes = NVS_PAGE_ENTRY_SIZE;
    if (variable) {
        unsigned int rounded = (size + NVS_PAGE_ENTRY_SIZE - 1U)
            & ~(NVS_PAGE_ENTRY_SIZE - 1U);
        total_bytes = rounded + NVS_PAGE_ENTRY_SIZE;
        if (rounded != 0)
            entry_count = ((size + 31U) >> 5) + 1U;
    } else if (size > 8U) {
        return 0x102;
    }
    size_t next_free = state->next_free_entry;
    if (next_free == NVS_PAGE_INVALID_ENTRY
            || next_free + entry_count > NVS_PAGE_ENTRY_COUNT)
        return 0x110a;

    NvsItem constructed;
    NvsItem item;
    volatile NvsItem *build = &constructed;
    build->header = namespace_index | (type << 8) |
        (((total_bytes >> 5) & 255U) << 16) | (chunk_index << 24);
    for (unsigned int word = 0; word != 6U; ++word)
        *(volatile unsigned int *)((uintptr_t)&constructed + 8U + 4U * word) = 0xffffffffU;
    strncpy(constructed.key,key,15);
    build->key[15] = 0;
    /* The constructor's CRC word remains uninitialized in this native copy.
     * The hash ignores it; it is replaced before the header is written. */
    memcpy(&item,&constructed,sizeof(item));
    next_free = state->next_free_entry;
    result = nvs_hash_list_insert(&page->hash_blocks,&item,next_free);
    if (result != 0)
        return result;

    volatile NvsItem *stored = &item;
    if (!variable) {
        memcpy(item.data,value,size);
        unsigned int crc = nvs_item_crc32(&item);
        stored->crc32 = crc;
        return nvs_page_write_entry(page,&item);
    }
    unsigned int crc = nvs_crc32_data(value,size,NULL);
    stored->variable.data_crc32 = crc;
    stored->variable.data_size = (unsigned short)size;
    stored->variable.reserved = 0xffff;
    crc = nvs_item_crc32(&item);
    stored->crc32 = crc;
    result = nvs_page_write_entry(page,&item);
    if (result != 0)
        return result;

    size_t tail_size = size & 31U;
    size_t whole_size = size - tail_size;
    if (whole_size != 0) {
        result = nvs_page_write_entry_data(page,value,whole_size);
        if (result != 0)
            return result;
    }
    if (tail_size == 0)
        return 0;
    for (unsigned int word = 0; word != 8U; ++word)
        *(volatile unsigned int *)((uintptr_t)&item + 4U * word) = 0xffffffffU;
    memcpy(&item,(const void *)((uintptr_t)value + whole_size),tail_size);
    return nvs_page_write_entry(page,&item);
}

/* Native entry: 0x42015108. */
/* Original function-byte SHA-256:
 * f19bb4e6a14f2179d45b57e915759545ea46e1c4d6d34825e45ff9b09e3d6998. */
/* Erase an entry and its validated span; index>125 returns -1. A WRITTEN
 * entry is read and checked, then removed from the hash. Invalid headers
 * erase only one entry, updating both16-bit counters even if erasure fails.
 * Valid spans update counters in reverse order before changing flash state;
 * a later failure retains those changes. Other entry states erase one slot
 * without counter updates. After success, find the next first-used entry if
 * necessary and advance next-free past the span. No rollback/state gate/lock. */
int nvs_page_erase_entry_and_span(NvsPage *page,size_t position)
{
    volatile NvsPage *state = page;
    if (position >= NVS_PAGE_ENTRY_COUNT)
        return -1;
    size_t end;
    int result;
    if (nvs_page_entry_state(state,position) == NVS_ENTRY_STATE_WRITTEN) {
        NvsItem item;
        NvsPartitionObject *partition = state->partition;
        unsigned int base_address = state->base_address;
        const volatile NvsPartitionVtable *vtable = partition->vtable;
        NvsPartitionRead read = vtable->read;
        result = read(partition,base_address + NVS_PAGE_ENTRY_DATA_OFFSET
            + position * NVS_PAGE_ENTRY_SIZE,&item,sizeof(item));
        if (result != 0)
            return result;
        bool consistent = nvs_item_header_is_consistent(&item,position);
        (void)nvs_hash_list_erase(&page->hash_blocks,position);
        if (!consistent) {
            result = nvs_page_alter_entry_state(page,position,NVS_ENTRY_STATE_ERASED);
            unsigned int used = state->used_entry_count;
            unsigned int erased = state->erased_entry_count;
            state->used_entry_count = (unsigned short)(used - 1U);
            state->erased_entry_count = (unsigned short)(erased + 1U);
            if (result != 0)
                return result;
            end = position + 1U;
        } else {
            unsigned int span = ((const volatile NvsItem *)&item)->span;
            end = position + span;
            int reverse = (int)(end - 1U);
            if (reverse >= (int)position) {
                if ((unsigned int)reverse >= NVS_PAGE_ENTRY_COUNT)
                    return -1;
                unsigned int erased = state->erased_entry_count;
                do {
                    unsigned int entry_state = nvs_page_entry_state(state,(size_t)reverse);
                    ++erased;
                    --reverse;
                    if (entry_state == NVS_ENTRY_STATE_WRITTEN) {
                        unsigned int used = state->used_entry_count;
                        state->used_entry_count = (unsigned short)(used - 1U);
                    }
                    state->erased_entry_count = (unsigned short)erased;
                } while (reverse >= (int)position);
            }
            if (span == 1)
                result = nvs_page_alter_entry_state(page,position,NVS_ENTRY_STATE_ERASED);
            else
                result = nvs_page_alter_entry_range(page,position,end,NVS_ENTRY_STATE_ERASED);
            if (result != 0)
                return result;
        }
    } else {
        result = nvs_page_alter_entry_state(page,position,NVS_ENTRY_STATE_ERASED);
        if (result != 0)
            return result;
        end = position + 1U;
    }

    size_t first_used = state->first_used_entry;
    size_t next_free = state->next_free_entry;
    if (first_used == position) {
        state->first_used_entry = NVS_PAGE_INVALID_ENTRY;
        size_t limit = next_free < NVS_PAGE_ENTRY_COUNT ? next_free : NVS_PAGE_ENTRY_COUNT;
        for (size_t cursor = end; cursor < limit; ++cursor) {
            if (nvs_page_entry_state(state,cursor) == NVS_ENTRY_STATE_WRITTEN) {
                state->first_used_entry = cursor;
                break;
            }
        }
    }
    if (next_free < end)
        state->next_free_entry = end;
    return 0;
}

/* Native entry: 0x420152f8. */
/* Original function-byte SHA-256:
 * 712d44ab87b7d797bf2c8037ed6751649c0c4ddae5801a52cfd3218111d44980. */
/* Find an item from the caller's cursor. INVALID/CORRUPT/UNINITIALIZED or
 * cursor>125 returns NOT_FOUND without reading an item. Sample first/next
 * cursors once; use the hash candidate only for a specific namespace/key,
 * except an all-chunks BLOB_DATA search. Read WRITTEN entries into output,
 * erase inconsistent headers, and skip variable data spans. Read/cleanup
 * errors mark the page INVALID. Compare15 key bytes and byte selectors.
 * Publish the cursor on success and type mismatches, including an exact
 * chunk match of the wrong type. A legacy BLOB search finding BLOB_INDEX
 * returns0x1103 without publishing it. Failed searches can
 * leave the last item in output. No lock, fresh-end sampling or retry bound. */
int nvs_page_find_item(NvsPage *page,
    unsigned int namespace_index,unsigned int type,const char *key,size_t *position,
    NvsItem *item,unsigned int chunk_index,unsigned int version_offset)
{
    volatile NvsPage *state = page;
    unsigned int page_state = state->state;
    namespace_index &= 255U;
    type &= 255U;
    chunk_index &= 255U;
    version_offset &= 255U;
    if (page_state == NVS_PAGE_STATE_INVALID || page_state == NVS_PAGE_STATE_CORRUPT
            || page_state == NVS_PAGE_STATE_UNINITIALIZED)
        return 0x1102;
    size_t cursor = *(volatile size_t *)position;
    if (cursor >= NVS_PAGE_ENTRY_COUNT)
        return 0x1102;
    size_t first_used = state->first_used_entry;
    size_t next_free = state->next_free_entry;
    if (cursor < first_used)
        cursor = first_used;
    size_t end = next_free < NVS_PAGE_ENTRY_COUNT ? next_free : NVS_PAGE_ENTRY_COUNT;
    if (namespace_index != NVS_NAMESPACE_ANY && key != NULL
            && (type != NVS_ITEM_TYPE_BLOB_DATA || chunk_index != NVS_ITEM_CHUNK_ANY)) {
        NvsItem probe;
        volatile NvsItem *query = &probe;
        query->chunk_index = (unsigned char)chunk_index;
        for (unsigned int word = 0; word != 6U; ++word)
            *(volatile unsigned int *)((uintptr_t)&probe + 8U + 4U * word) = 0xffffffffU;
        query->namespace_and_type = (unsigned short)(namespace_index | (type << 8));
        query->span = 0;
        strncpy(probe.key,key,15);
        query->key[15] = 0;
        cursor = nvs_hash_list_find(&page->hash_blocks,cursor,&probe);
        if (cursor >= NVS_PAGE_ENTRY_COUNT)
            return 0x1102;
    }

    const volatile NvsItem *found = item;
    while (cursor < end) {
        size_t next = cursor + 1U;
        if (nvs_page_entry_state(state,cursor) != NVS_ENTRY_STATE_WRITTEN)
            goto advance;
        NvsPartitionObject *partition = state->partition;
        unsigned int base_address = state->base_address;
        const volatile NvsPartitionVtable *vtable = partition->vtable;
        NvsPartitionRead read = vtable->read;
        int result = read(partition,base_address + NVS_PAGE_ENTRY_DATA_OFFSET
            + cursor * NVS_PAGE_ENTRY_SIZE,item,sizeof(*item));
        if (result != 0) {
            state->state = NVS_PAGE_STATE_INVALID;
            return result;
        }
        if (!nvs_item_header_is_consistent(item,cursor)) {
            result = nvs_page_erase_entry_and_span(page,cursor);
            if (result != 0) {
                state->state = NVS_PAGE_STATE_INVALID;
                return result;
            }
            goto advance;
        }
        unsigned int found_type = found->type;
        if (nvs_item_type_is_variable(found_type))
            next = cursor + found->span;
        if (namespace_index != NVS_NAMESPACE_ANY && found->namespace_index != namespace_index)
            goto advance;
        if (key != NULL && strncmp(key,item->key,15) != 0)
            goto advance;
        if (type == NVS_ITEM_TYPE_BLOB_DATA && chunk_index != NVS_ITEM_CHUNK_ANY) {
            if (found->chunk_index != chunk_index)
                goto advance;
            *(volatile size_t *)position = cursor;
            return found_type == NVS_ITEM_TYPE_BLOB_DATA ? 0 : 0x1103;
        }
        if (type == NVS_ITEM_TYPE_BLOB_DATA && chunk_index == NVS_ITEM_CHUNK_ANY
                && found_type != NVS_ITEM_TYPE_BLOB_DATA)
            goto advance;
        if (type == NVS_ITEM_TYPE_BLOB && chunk_index == NVS_ITEM_CHUNK_ANY) {
            if (found_type == NVS_ITEM_TYPE_BLOB_INDEX)
                return 0x1103;
            if (found_type == NVS_ITEM_TYPE_BLOB_DATA)
                goto advance;
        }
        if (type == NVS_ITEM_TYPE_BLOB_INDEX) {
            if (found->chunk_index != NVS_ITEM_CHUNK_ANY)
                goto advance;
            if (version_offset != NVS_ITEM_VERSION_ANY && found->blob_index.chunk_start != version_offset)
                goto advance;
        }
        if (type != NVS_ITEM_TYPE_ANY && found_type != type) {
            if (namespace_index == NVS_NAMESPACE_ANY && chunk_index == NVS_ITEM_CHUNK_ANY
                    && key == NULL)
                goto advance;
            *(volatile size_t *)position = cursor;
            return 0x1103;
        }
        *(volatile size_t *)position = cursor;
        return 0;
advance:
        cursor = next;
    }
    return 0x1102;
}

/* Native entry: 0x42015600. */
/* Original function-byte SHA-256:
 * dc598cbe030d4e0562a9fd47fdc19424f404b0c4625ed2ab9bf11e4de1fbd2cf. */
/* Compare an item without erasing it. Reject only INVALID; narrow selectors
 * to bytes and propagate lookup errors. Fixed types require size==(type&15)
 * or0x1103, then compare their bytes (including unchecked adjacent stack bytes
 * for sizes>8). Variable types require sufficient capacity or0x110c, first
 * compare input CRC, then read/compare every spanned32-byte entry and chain
 * its data CRC. Differences return0x1118; read errors return unchanged.
 * Re-read span after every CRC call, even with zero bytes remaining. If the
 * copy loop never runs, native compares an uninitialized running-CRC word;
 * retain that unknown stack read. No cleanup, independent lock or state retry. */
int nvs_page_compare_item(NvsPage *page,
    unsigned int namespace_index,unsigned int type,const char *key,const void *value,
    size_t size,unsigned int chunk_index,unsigned int version_offset)
{
    const volatile NvsPage *state = page;
    NvsPageCompareFrame frame;
    volatile NvsPageCompareFrame *local = &frame;
    unsigned int page_state = state->state;
    local->capacity = size;
    local->position = 0;
    namespace_index &= 255U;
    type &= 255U;
    chunk_index &= 255U;
    version_offset &= 255U;
    if (page_state == NVS_PAGE_STATE_INVALID)
        return 0x110b;
    int result = nvs_page_find_item(page,namespace_index,type,key,
        &frame.position,&frame.item,chunk_index,version_offset);
    if (result != 0)
        return result;
    size_t capacity = local->capacity;
    if (!nvs_item_type_is_variable(type)) {
        if (capacity != (type & 15U))
            return 0x1103;
        return memcmp(value,(const unsigned char *)&frame
            + offsetof(NvsPageCompareFrame,item.data),capacity) == 0 ? 0 : 0x1118;
    }
    unsigned int length = local->item.variable.data_size;
    if (capacity < length)
        return 0x110c;
    unsigned int crc = nvs_crc32_data(value,length,NULL);
    unsigned int expected_crc = local->item.variable.data_crc32;
    if (crc != expected_crc)
        return 0x1118;
    size_t found_position = local->position;
    unsigned int span = local->item.span;
    size_t first = found_position + 1U;
    size_t entry = first;
    size_t end = found_position + span;
    size_t remaining = local->item.variable.data_size;
    uintptr_t input = (uintptr_t)value;
    int success_status = 0;
    if (entry < end) {
        local->success_status = 0;
        local->capacity = found_position;
        do {
            if (entry >= NVS_PAGE_ENTRY_COUNT)
                return -1;
            NvsPartitionObject *partition = state->partition;
            unsigned int base_address = state->base_address;
            const volatile NvsPartitionVtable *vtable = partition->vtable;
            NvsPartitionRead read = vtable->read;
            result = read(partition,base_address + NVS_PAGE_ENTRY_DATA_OFFSET
                + entry * NVS_PAGE_ENTRY_SIZE,frame.scratch,NVS_PAGE_ENTRY_SIZE);
            size_t compare_size = remaining < NVS_PAGE_ENTRY_SIZE
                ? remaining : NVS_PAGE_ENTRY_SIZE;
            if (result != 0)
                return result;
            if (memcmp((const void *)input,frame.scratch,compare_size) != 0)
                return 0x1118;
            const unsigned int *seed = entry == first ? NULL : &frame.running_crc;
            crc = nvs_crc32_data(frame.scratch,compare_size,seed);
            span = local->item.span;
            size_t base_position = local->capacity;
            local->running_crc = crc;
            ++entry;
            end = base_position + span;
            remaining -= compare_size;
            input += compare_size;
        } while (entry < end);
        success_status = (int)local->success_status;
        expected_crc = local->item.variable.data_crc32;
    } else {
        crc = local->running_crc;
    }
    return crc == expected_crc ? success_status : 0x1118;
}
