/* Medius v3.4.7 device: NVS page header, data and entry-state writes. */
#include "../include/types.h"

/* Native entry: 0x42014d14. */
/* Original function-byte SHA-256:
 * c07fe66f278f1038617dc5753d313a493b733bbf71418d37e4ff2c8822cad3c5. */
/* Require UNINITIALIZED or return -1. Publish ACTIVE in memory before making
 * a32-byte flash header: reserved19 bytes0xff, sampled sequence/version and
 * CRC32 of bytes4..27. Write it through partition write_raw. Failure marks
 * INVALID and returns the callback error. Success sets next-free0 and fills
 * the32-byte entry-state table with individual0xff byte stores. Other page
 * fields remain as they were; no rollback, implicit erase or lock occurs. */
int nvs_page_initialize(NvsPage *page)
{
    volatile NvsPage *state = page;
    if (state->state != NVS_PAGE_STATE_UNINITIALIZED)
        return -1;
    state->state = NVS_PAGE_STATE_ACTIVE;
    NvsPageHeader header;
    volatile NvsPageHeader *local = &header;
    for (unsigned int i = 0; i != 19U; ++i)
        local->reserved[i] = 0xff;
    unsigned int sequence = state->sequence;
    unsigned int version = state->version;
    local->state = NVS_PAGE_STATE_ACTIVE;
    local->sequence = sequence;
    local->version = (unsigned char)version;
    unsigned int crc = esp_rom_crc32_le(0xffffffffU,&header.sequence,
        offsetof(NvsPageHeader,crc32) - offsetof(NvsPageHeader,sequence));
    NvsPartitionObject *partition = state->partition;
    unsigned int base_address = state->base_address;
    const volatile NvsPartitionVtable *vtable = partition->vtable;
    NvsPartitionWriteRaw write_raw = vtable->write_raw;
    local->crc32 = crc;
    int result = write_raw(partition,base_address,&header,sizeof(header));
    if (result != 0) {
        state->state = NVS_PAGE_STATE_INVALID;
        return result;
    }
    state->next_free_entry = 0;
    volatile unsigned char *entry_bytes = (volatile unsigned char *)page->entry_state_table;
    for (unsigned int i = 0; i != sizeof(page->entry_state_table); ++i)
        entry_bytes[i] = 0xff;
    return result;
}

/* Native entry: 0x42014d80. */
/* Original function-byte SHA-256:
 * 43e1749c5a6a8e18813880e5e7d93828f113d1182c7295071f9d6634c371d7a0. */
/* Write32 bytes at next-free through the partition's normal write slot.
 * Cursor>125 returns -1 without marking INVALID; a write error does mark it.
 * After writing, re-read next-free for the entry-state update to WRITTEN.
 * On success sample first-used, then next-free; initialize first-used only
 * if0xffffffff, increment the16-bit used count, then advance that sampled
 * cursor. State-write errors return before counter updates. No state gate,
 * data-size check, rollback or independent lock is supplied. */
int nvs_page_write_entry(NvsPage *page,const void *entry32)
{
    volatile NvsPage *state = page;
    size_t cursor = state->next_free_entry;
    if (cursor >= NVS_PAGE_ENTRY_COUNT)
        return -1;
    NvsPartitionObject *partition = state->partition;
    unsigned int base_address = state->base_address;
    const volatile NvsPartitionVtable *vtable = partition->vtable;
    NvsPartitionWrite write = vtable->write;
    int result = write(partition,base_address + NVS_PAGE_ENTRY_DATA_OFFSET
        + cursor * NVS_PAGE_ENTRY_SIZE,entry32,NVS_PAGE_ENTRY_SIZE);
    if (result != 0) {
        state->state = NVS_PAGE_STATE_INVALID;
        return result;
    }
    cursor = state->next_free_entry;
    result = nvs_page_alter_entry_state(page,cursor,NVS_ENTRY_STATE_WRITTEN);
    if (result != 0)
        return result;
    size_t first_used = state->first_used_entry;
    cursor = state->next_free_entry;
    if (first_used == NVS_PAGE_INVALID_ENTRY)
        state->first_used_entry = cursor;
    unsigned int used = state->used_entry_count;
    state->used_entry_count = (unsigned short)(used + 1U);
    state->next_free_entry = cursor + 1U;
    return result;
}

/* Native entry: 0x42014ecc. */
/* Original function-byte SHA-256:
 * d2782566f3f738e2fdcf3259e3f369dbf4fb77eb9216e80811121bb14136c6c4. */
/* Write a whole-entry payload. Reject size not divisible by32, next-free
 *0xffffffff or first-used0xffffffff with -1 and no mutation. Other cursors
 *>125 mark INVALID; normal-write errors do likewise. Write the full input
 * size before validating the entry-state range. Range count is the low16
 * bits of size/32; a zero size still calls write and then fails the empty
 * range check. On range success increment used count and next-free using
 * freshly sampled fields. Range errors return without a local INVALID write
 * or rollback; this differs from normal-write failure. No local lock. */
int nvs_page_write_entry_data(NvsPage *page,
    const void *data,size_t size)
{
    volatile NvsPage *state = page;
    if ((size & (NVS_PAGE_ENTRY_SIZE - 1U)) != 0)
        return -1;
    size_t cursor = state->next_free_entry;
    if (cursor == NVS_PAGE_INVALID_ENTRY)
        return -1;
    if (state->first_used_entry == NVS_PAGE_INVALID_ENTRY)
        return -1;
    int result;
    if (cursor >= NVS_PAGE_ENTRY_COUNT) {
        result = -1;
    } else {
        NvsPartitionObject *partition = state->partition;
        unsigned int base_address = state->base_address;
        const volatile NvsPartitionVtable *vtable = partition->vtable;
        NvsPartitionWrite write = vtable->write;
        result = write(partition,base_address + NVS_PAGE_ENTRY_DATA_OFFSET
            + cursor * NVS_PAGE_ENTRY_SIZE,data,size);
    }
    if (result != 0) {
        state->state = NVS_PAGE_STATE_INVALID;
        return result;
    }
    cursor = state->next_free_entry;
    unsigned int count = (size >> 5) & 0xffffU;
    result = nvs_page_alter_entry_range(page,cursor,cursor + count,NVS_ENTRY_STATE_WRITTEN);
    if (result != 0)
        return result;
    unsigned int used = state->used_entry_count;
    cursor = state->next_free_entry;
    state->used_entry_count = (unsigned short)(used + (size >> 5));
    state->next_free_entry = cursor + count;
    return result;
}

/* Native entry: 0x4202121c. */
/* Original function-byte SHA-256:
 * 5b7cd7ed69a4e4d4ef2a3e12a5862b56b1b282b73fe990a7afa12595fbcb7491. */
/* Change an entry's packed two-bit state in memory, then write its four-byte
 * table word through write_raw at base+32+4*word_index. Index>125 returns -1.
 * The incoming state is NOT masked to two bits; higher bits can affect other
 * entries. Sample partition before publishing the table word. A write error
 * marks the page INVALID but retains the table change. No retry or rollback. */
int nvs_page_alter_entry_state(NvsPage *page,
    size_t position,unsigned int entry_state)
{
    volatile NvsPage *state = page;
    if (position >= NVS_PAGE_ENTRY_COUNT)
        return -1;
    unsigned int word_index = (position >> 4) & 0xffffU;
    unsigned int shift = (position & 15U) * 2U;
    unsigned int previous = state->entry_state_table[word_index];
    unsigned int updated = (previous & ~(3U << shift)) | (entry_state << shift);
    NvsPartitionObject *partition = state->partition;
    state->entry_state_table[word_index] = updated;
    const volatile NvsPartitionVtable *vtable = partition->vtable;
    unsigned int base_address = state->base_address;
    NvsPartitionWriteRaw write_raw = vtable->write_raw;
    volatile unsigned int snapshot = updated;
    int result = write_raw(partition,base_address + NVS_PAGE_ENTRY_TABLE_OFFSET
        + sizeof(snapshot) * word_index,(const void *)&snapshot,sizeof(snapshot));
    if (result != 0)
        state->state = NVS_PAGE_STATE_INVALID;
    return result;
}

/* Native entry: 0x42021274. */
/* Original function-byte SHA-256:
 * f2a7617f1731baf0bbd3bbc915cb87a21244908034c6968082c2c37d22fb47c4. */
/* Change [first,end) in descending entry order. Require first<end<=126 or
 * return -1. Update packed table words in memory and write each completed
 * word once, in descending order, including the final partial word. As with
 * the single-entry setter, state bits are not masked. Re-read a word for its
 * flash snapshot after loading partition/base/vtable. Write errors return
 * unchanged, retaining prior flash/table changes; this routine does NOT mark
 * the page INVALID. No counter updates, rollback, state gate or lock. */
int nvs_page_alter_entry_range(NvsPage *page,
    size_t first,size_t end,unsigned int entry_state)
{
    volatile NvsPage *state = page;
    if (first >= end || end > NVS_PAGE_ENTRY_COUNT)
        return -1;
    int cursor = (int)(end - 1U);
    unsigned int pending_word = (end - 1U) >> 4;
    do {
        unsigned int word_index = ((unsigned int)cursor >> 4) & 0xffffU;
        unsigned int shift = ((unsigned int)cursor & 15U) * 2U;
        unsigned int previous = state->entry_state_table[word_index];
        unsigned int updated = (previous & ~(3U << shift)) | (entry_state << shift);
        state->entry_state_table[word_index] = updated;
        unsigned int next_word = (size_t)cursor == first ? 0xffffffffU :
            (unsigned int)(cursor - 1) >> 4;
        if (next_word != pending_word) {
            NvsPartitionObject *partition = state->partition;
            unsigned int base_address = state->base_address;
            const volatile NvsPartitionVtable *vtable = partition->vtable;
            unsigned int word = state->entry_state_table[pending_word];
            NvsPartitionWriteRaw write_raw = vtable->write_raw;
            volatile unsigned int snapshot = word;
            int result = write_raw(partition,base_address + NVS_PAGE_ENTRY_TABLE_OFFSET
                + sizeof(snapshot) * pending_word,(const void *)&snapshot,sizeof(snapshot));
            if (result != 0)
                return result;
        }
        pending_word = next_word;
        --cursor;
    } while (cursor >= (int)first);
    return 0;
}
