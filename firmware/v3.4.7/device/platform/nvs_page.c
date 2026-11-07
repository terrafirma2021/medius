/* Medius v3.4.7 device: NVS page state, erase and activation. */
#include "../include/types.h"

/* Native entry: 0x42014ce8. */
/* Original function-byte SHA-256:
 * 10b97cd5a2b010b1fc25ccd7eb277fed1db63041804d7d73ec120bc20b564e80. */
/* Construct a Page: clear links/base/state, set sequence and cursors to
 * 0xffffffff, set version byte to 0xfe and clear both counters with one word
 * store. Construct the hash list, then clear the partition pointer. Reserved
 * bytes and the compressed entry-state table stay uninitialized. This does
 * not load, initialize or erase a flash page, nor release prior contents. */
void nvs_page_construct(NvsPage *page)
{
    volatile NvsPage *state = page;
    state->previous = NULL;
    state->next = NULL;
    state->base_address = 0;
    state->state = NVS_PAGE_STATE_INVALID;
    state->sequence = 0xffffffffU;
    state->version = NVS_PAGE_FORMAT_VERSION;
    state->next_free_entry = NVS_PAGE_INVALID_ENTRY;
    state->first_used_entry = NVS_PAGE_INVALID_ENTRY;
    state->entry_counts = 0;
    nvs_hash_list_construct(&page->hash_blocks);
    state->partition = NULL;
}

/* Native entry: 0x42015264. */
/* Original function-byte SHA-256:
 * 0dd0440eae4222154d97cca1a87ceed4f71408f0efe94d390f9bac70b3f55d1f. */
/* Read the variable item's following entries in full 32-byte blocks, copying
 * min(bytes_left,32) into output. The live span controls every iteration,
 * even after bytes_left reaches zero. Only INVALID state is rejected; an
 * entry index above125 returns -1. Partition read errors return directly.
 * Check output CRC using the item's length, reloading it after any copy loop.
 * On mismatch erase the item/span: propagate an erase error, otherwise return
 * NOT_FOUND (0x1102). Keep partial output; no capacity check or output clearing. */
int nvs_page_read_variable_data(NvsPage *page,
    const NvsItem *item,size_t position,void *output)
{
    const volatile NvsPage *state = page;
    const volatile NvsItem *value = item;
    if (state->state == NVS_PAGE_STATE_INVALID)
        return 0x110b;
    unsigned int span = value->span;
    size_t entry = position + 1U;
    size_t end = position + span;
    size_t remaining = value->variable.data_size;
    size_t checksum_size = remaining;
    uintptr_t destination = (uintptr_t)output;
    if (entry < end) {
        do {
            unsigned char scratch[NVS_PAGE_ENTRY_SIZE];
            if (entry >= NVS_PAGE_ENTRY_COUNT)
                return -1;
            NvsPartitionObject *partition = state->partition;
            unsigned int base_address = state->base_address;
            const volatile NvsPartitionVtable *vtable = partition->vtable;
            NvsPartitionRead read = vtable->read;
            unsigned int address = base_address + NVS_PAGE_ENTRY_DATA_OFFSET
                + entry * NVS_PAGE_ENTRY_SIZE;
            int result = read(partition,address,scratch,NVS_PAGE_ENTRY_SIZE);
            size_t copy_size = remaining < NVS_PAGE_ENTRY_SIZE
                ? remaining : NVS_PAGE_ENTRY_SIZE;
            if (result != 0)
                return result;
            memcpy((void *)destination,scratch,copy_size);
            span = value->span;
            ++entry;
            end = position + span;
            remaining -= copy_size;
            destination += copy_size;
        } while (entry < end);
        checksum_size = value->variable.data_size;
    }
    unsigned int crc = nvs_crc32_data(output,checksum_size,NULL);
    if (crc == value->variable.data_crc32)
        return 0;
    int result = nvs_page_erase_entry_and_span(page,position);
    return result == 0 ? 0x1102 : result;
}

/* Native entry: 0x42015564. */
/* Original function-byte SHA-256:
 * 6a10663c7d4edb901d7c8f5bd436a8565cbcd31bd920d7bbea1d08631f9468be. */
/* Find and read an item. Reject only INVALID state with0x110b; narrow the
 * namespace, type, chunk and version to bytes. Propagate find errors.
 * Variable types21/41/42 require capacity >= the stored HALFWORD length, else
 * 0x110c, then use the variable-data reader. Other types require capacity
 * exactly(type&15), else TYPE_MISMATCH (0x1103), then copy from item byte24.
 * Unusual fixed-type sizes >8 also copy adjacent cursor/uninitialized stack
 * bytes; the explicit frame retains this unchecked native behavior. */
int nvs_page_read_item(NvsPage *page,
    unsigned int namespace_index,unsigned int type,const char *key,void *output,
    size_t size,unsigned int chunk_index,unsigned int version_offset)
{
    NvsPageReadFrame frame;
    volatile NvsPageReadFrame *local = &frame;
    unsigned int page_state = ((const volatile NvsPage *)page)->state;
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
    if (type == NVS_ITEM_TYPE_STRING || type == NVS_ITEM_TYPE_BLOB
            || type == NVS_ITEM_TYPE_BLOB_DATA) {
        if (capacity < local->item.variable.data_size)
            return 0x110c;
        size_t position = local->position;
        return nvs_page_read_variable_data(page,&frame.item,position,output);
    }
    if (capacity != (type & 15U))
        return 0x1103;
    memcpy(output,(const unsigned char *)&frame + offsetof(NvsPageReadFrame,item.data),capacity);
    return result;
}

/* Native entry: 0x42015740. */
/* Original function-byte SHA-256:
 * f62dd5b770ec1a0e848d66526fa126cbbc2af7a5d56c5d55ef21d4472bb8507e. */
/* Narrow namespace/type/chunk/version to bytes and find from cursor zero.
 * A find error returns unchanged. On success read its returned cursor word
 * and erase that entry and its span, returning the erase status. No separate
 * page-state validation, iterator loop, lock or rollback is supplied. */
int nvs_page_erase_item(NvsPage *page,
    unsigned int namespace_index,unsigned int type,const char *key,
    unsigned int chunk_index,unsigned int version_offset)
{
    size_t position = 0;
    NvsItem item;
    int result = nvs_page_find_item(page,namespace_index & 255U,type & 255U,
        key,&position,&item,chunk_index & 255U,version_offset & 255U);
    if (result != 0)
        return result;
    size_t found_position = *(volatile size_t *)&position;
    return nvs_page_erase_entry_and_span(page,found_position);
}

/* Native entry: 0x42015c78. */
/* Original function-byte SHA-256:
 * d72a9ab2eec7be24eefe602abaeb3f9292a44e15669c3a5d6906d06814011c9f. */
/* Copy the page sequence word unless state is INVALID (0), UNINITIALIZED
 * (0xffffffff) or CORRUPT (0xfffffff0). Those states return 0x1101 without
 * touching output. Other state values are accepted, including values outside
 * the named state enum. No output pointer check, lock or flash read occurs. */
int nvs_page_get_sequence(NvsPage *page,unsigned int *sequence)
{
    const volatile NvsPage *state = page;
    unsigned int page_state = state->state;
    if (page_state == NVS_PAGE_STATE_INVALID
            || page_state == NVS_PAGE_STATE_UNINITIALIZED
            || page_state == NVS_PAGE_STATE_CORRUPT)
        return 0x1101;
    unsigned int value = state->sequence;
    *(volatile unsigned int *)sequence = value;
    return 0;
}

/* Native entry: 0x42015ca4. */
/* Original function-byte SHA-256:
 * ae353fa1acefec94270c02c2ad3688ad1dd8fc8fbde3cff0c924dde04d422b2c. */
/* Set the in-memory sequence only while UNINITIALIZED. Any other state
 * returns INVALID_STATE (0x110b) without writing. No flash access occurs. */
int nvs_page_set_sequence(NvsPage *page,unsigned int sequence)
{
    volatile NvsPage *state = page;
    if (state->state != NVS_PAGE_STATE_UNINITIALIZED)
        return 0x110b;
    state->sequence = sequence;
    return 0;
}

/* Native entry: 0x42015cb8. */
/* Original function-byte SHA-256:
 * 5ea8d7754537c6f983473aab141d3df83d989fd58b9e3ccfb100f063031de85f. */
/* Erase one cached sector through the partition's erase_range virtual slot.
 * Failure sets only the page state to INVALID and returns the exact status.
 * Success clears both entry counters with one word store, sets first-used
 * then next-free to 0xffffffff, marks UNINITIALIZED and clears the hash list.
 * Sequence, links, version and entry-state table are retained. No state gate,
 * sector-size validation or independent lock is supplied. */
int nvs_page_erase(NvsPage *page)
{
    volatile NvsPage *state = page;
    NvsPartitionObject *partition = state->partition;
    const volatile NvsPartitionVtable *vtable = partition->vtable;
    unsigned int base_address = state->base_address;
    unsigned int sector_size = NVS_SECTOR_SIZE;
    NvsPartitionEraseRange erase_range = vtable->erase_range;
    int result = erase_range(partition,base_address,sector_size);
    if (result != 0) {
        state->state = NVS_PAGE_STATE_INVALID;
        return result;
    }
    state->entry_counts = 0;
    state->first_used_entry = NVS_PAGE_INVALID_ENTRY;
    state->next_free_entry = NVS_PAGE_INVALID_ENTRY;
    state->state = NVS_PAGE_STATE_UNINITIALIZED;
    nvs_hash_list_clear(&page->hash_blocks);
    return result;
}

/* Native entry: 0x42015cf0. */
/* Original function-byte SHA-256:
 * 36637fd6d4742e073625581d6eeb6caa901744c0760662c4e40448c7756c2877. */
/* ACTIVE and FULL pages may transition to FREEING. Other states return
 * 0x110b untouched. Write the four-byte 0xfffffff8 state at the page base
 * through partition write_raw; success publishes FREEING in memory, while
 * any write error publishes INVALID (0) and returns that error. No retry. */
int nvs_page_mark_freeing(NvsPage *page)
{
    volatile NvsPage *state = page;
    unsigned int page_state = state->state;
    if (page_state != NVS_PAGE_STATE_FULL && page_state != NVS_PAGE_STATE_ACTIVE)
        return 0x110b;
    NvsPartitionObject *partition = state->partition;
    const volatile NvsPartitionVtable *vtable = partition->vtable;
    unsigned int base_address = state->base_address;
    NvsPartitionWriteRaw write_raw = vtable->write_raw;
    volatile unsigned int target_state = NVS_PAGE_STATE_FREEING;
    int result = write_raw(partition,base_address,(const void *)&target_state,4);
    state->state = result == 0 ? NVS_PAGE_STATE_FREEING : NVS_PAGE_STATE_INVALID;
    return result;
}

/* Native entry: 0x42015d24. */
/* Original function-byte SHA-256:
 * 858da93e913b6f463d810f929327908edd0ed6fb57a216a865ea7321307cca40. */
/* Require exactly ACTIVE (0xfffffffe), otherwise return 0x110b untouched.
 * Write the four-byte FULL state (0xfffffffc) at the page base through the
 * partition write_raw slot. Publish FULL on success or INVALID on error,
 * returning the callback status. No extra flush, retry or local lock. */
int nvs_page_mark_full(NvsPage *page)
{
    volatile NvsPage *state = page;
    if (state->state != NVS_PAGE_STATE_ACTIVE)
        return 0x110b;
    NvsPartitionObject *partition = state->partition;
    const volatile NvsPartitionVtable *vtable = partition->vtable;
    unsigned int base_address = state->base_address;
    NvsPartitionWriteRaw write_raw = vtable->write_raw;
    volatile unsigned int target_state = NVS_PAGE_STATE_FULL;
    int result = write_raw(partition,base_address,(const void *)&target_state,4);
    state->state = result == 0 ? NVS_PAGE_STATE_FULL : NVS_PAGE_STATE_INVALID;
    return result;
}

/* Native entry: 0x42015d54. */
/* Original function-byte SHA-256:
 * fdb1c99c2ba736698961ea0d39f0278375d12ba8bc95318b8b46731dbc78e7a2. */
/* Return 4000 bytes for UNINITIALIZED and zero for FULL. Otherwise sample
 * next-free once: indices 0..124 yield (125-index)*32 bytes, reserving an item
 * entry; larger indices yield zero. INVALID/CORRUPT states take this same
 * cursor calculation. No state validation, flash read or allocation occurs. */
unsigned int nvs_page_get_variable_tailroom(NvsPage *page)
{
    const volatile NvsPage *state = page;
    unsigned int page_state = state->state;
    if (page_state == NVS_PAGE_STATE_UNINITIALIZED)
        return (NVS_PAGE_ENTRY_COUNT - 1U) * NVS_PAGE_ENTRY_SIZE;
    if (page_state == NVS_PAGE_STATE_FULL)
        return 0;
    size_t next_free = state->next_free_entry;
    return next_free < NVS_PAGE_ENTRY_COUNT - 1U
        ? (((NVS_PAGE_ENTRY_COUNT - 1U) - next_free) & 0xffffU)
            * NVS_PAGE_ENTRY_SIZE
        : 0;
}

/* Native entry: 0x42015d84. */
/* Original function-byte SHA-256:
 * fe595237d75ef2a10a53939ede7523f95f831f24d4adec7218601784ba994033. */
/* Initialize the NVS page sector-size word from the main-flash sector-size
 * getter. Store its full return value without validation or a fallback. */
void nvs_page_initialize_sector_size(void)
{
    NVS_SECTOR_SIZE = esp_partition_get_main_flash_sector_size();
}

/* Native entry: 0x42015d94. */
/* Original function-byte SHA-256:
 * 7484cd753c2fe20eaa1f2c6ea5463a2f33821eaf4a3f8b04e892f5459a87f513. */
/* Move the first free page to the active-list tail; an empty free count
 * returns 0x1105. Erase a CORRUPT page first and propagate erase errors.
 * After successful erase, reload the free head/count for removal but append
 * the originally captured page. Preserve this distinction if callbacks alter
 * the lists. Assign the current sequence, ignore set-sequence errors, then
 * increment a freshly read manager sequence with 32-bit wrap. No rollback,
 * list-consistency validation, state initialization or local lock is added. */
int nvs_page_manager_activate_page(NvsPageManagerView *manager)
{
    volatile NvsPageManagerView *state = manager;
    unsigned int free_count = state->free_pages.count;
    if (free_count == 0)
        return 0x1105;
    NvsPage *selected = state->free_pages.head;
    volatile NvsPage *removed = selected;
    if (((volatile NvsPage *)selected)->state == NVS_PAGE_STATE_CORRUPT) {
        int result = nvs_page_erase(selected);
        if (result != 0)
            return result;
        removed = state->free_pages.head;
        free_count = state->free_pages.count;
    }
    NvsPage *previous = removed->previous;
    NvsPage *next = removed->next;
    if (previous != NULL)
        ((volatile NvsPage *)previous)->next = next;
    else
        state->free_pages.head = next;
    if (next != NULL)
        ((volatile NvsPage *)next)->previous = previous;
    else
        state->free_pages.tail = previous;

    NvsPage *tail = state->pages.tail;
    state->free_pages.count = free_count - 1U;
    if (tail != NULL)
        ((volatile NvsPage *)tail)->next = selected;
    ((volatile NvsPage *)selected)->next = NULL;
    ((volatile NvsPage *)selected)->previous = tail;
    void *head = state->pages.head;
    state->pages.tail = selected;
    if (head == NULL)
        state->pages.head = selected;
    unsigned int active_count = state->pages.count;
    unsigned int sequence = state->page_sequence;
    state->pages.count = active_count + 1U;
    (void)nvs_page_set_sequence(selected,sequence);
    state->page_sequence = state->page_sequence + 1U;
    return 0;
}
