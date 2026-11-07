/* Medius v3.4.7 device — descriptor patch mutation and payload compaction. */
#include "../include/types.h"

/* Native entry: 0x42029ad8. */
/* Original function-byte SHA-256:
 * 8c99c5ed7bed223e190850e0be48260850ab402f3f374ab9ab671984d82eb3cb. */
/*
 * Repack stored descriptor-patch payloads through an uninitialized1056-byte
 * stack area. A zero initial count writes used HALFWORD0 without reading records
 * or copying the pool. Otherwise walk records with a wrapping BYTE index and
 * reread the count after each record. A zero length sets its offset HALFWORD0.
 * Nonzero length copies cached length bytes, rereads length HALFWORD, writes
 * the old cursor as payload offset, then adds the reread length modulo65536.
 *
 * After the scan copy the compacted prefix back only if cursor!=0; always store
 * cursor to payload_used HALFWORD. Tail bytes, count, generation and error flag
 * stay untouched. No MEMW, lock, allocation or capacity/pointer validation.
 * Caller must serialize storage and enforce counts/offsets/total size; corruption
 * can exceed either native payload storage or temporary stack capacity.
 */
void medius_descriptor_patch_compact_payloads(void)
{
    volatile DescriptorPatchTable *table = MEDIUS_DESCRIPTOR_PATCH_STORED_RW;
    unsigned int used = table->count;
    if (used != 0) {
        unsigned char compacted[1056];
        unsigned char index = 0;
        used = 0;
        volatile DescriptorPatchRecord *record = table->records;
        do {
            unsigned int length = record->length;
            if (length == 0) {
                record->payload_offset = 0;
            } else {
                unsigned int old_offset = record->payload_offset;
                memcpy(compacted + used,(const void *)(table->payload + old_offset),length);
                unsigned int current_length = record->length;
                record->payload_offset = (unsigned short)used;
                used = (unsigned short)(used + current_length);
            }
            index = (unsigned char)(index + 1U);
            unsigned int count = table->count;
            ++record;
            if (index >= count)
                break;
        } while (1);
        if (used != 0)
            memcpy((void *)table->payload,compacted,used);
    }
    table->payload_used = (unsigned short)used;
}

/* Native entry: 0x42029c14. */
/* Original function-byte SHA-256:
 * ceba1fc73b512f0ae9089d1dc2a2f89fb8cc6659fc7a83fdaad8505c5337168d. */
/*
 * Mutate one stored descriptor patch. First four arguments are full WORDs:
 * reject kind>4; compare kind/config/index with zero-extended BYTEs and offset
 * with a HALFWORD. Only length is narrowed16 on entry. Cache initial count BYTE
 * and find its first exact key. Invalid kind or absent deletion returns UINT_MAX
 * without changing the table/error flag. No identity, lock or pointer checks.
 *
 * Matching length0 deletes: shift later ten-byte records forward with memcpy,
 * store cached count-1 BYTE, clear the old last record, compact payloads, then
 * reread/increment generation BYTE modulo256 and clear admission_failed BYTE.
 * Return original match index. Equal nonzero length and equal payload return
 * that index without clearing an earlier admission error or changing generation.
 *
 * Changed replacement requires unsigned32(used+new_length-old_length)<=1024;
 * remove/clear/compact without incrementing generation, then reload used HALFWORD
 * and count BYTE and append at the new tail. A new key requires used+length<=1024
 * and cached count!=16; equality is the only record-count cap. Failure sets
 * admission_failed1 and returns0xfffffffe, retaining previous storage.
 *
 * Append stores identity HALFWORD(kind OR config<<8), length HALFWORD,pool-offset
 * HALFWORD,index BYTE and offset HALFWORD, then copies length bytes. Reread
 * generation BYTE,count BYTE,used HALFWORD in that order; publish incremented
 * count/generation together as one HALFWORD, then used+length HALFWORD,error0.
 * Return the freshly incremented count BYTE minus1 as WORD (wrap-to0 returns
 * UINT_MAX). Other keys/index/offset narrow only at their stores. No persistence,
 * refresh, rollback or source-alias protection; replacement compaction may change
 * a borrowed source pointing into this same table. Caller owns admission/lifetime.
 */
unsigned int medius_descriptor_patch_mutate(unsigned int kind,unsigned int configuration,
    unsigned int index,unsigned int offset,const void *bytes,unsigned short length)
{
    if (kind > 4U)
        return 0xffffffffU;
    volatile DescriptorPatchTable *table = MEDIUS_DESCRIPTOR_PATCH_STORED_RW;
    unsigned int count = table->count;
    unsigned int selected = 0xffffffffU;
    for (unsigned int candidate = 0; candidate < count; ++candidate) {
        volatile DescriptorPatchRecord *record = &table->records[candidate];
        if (record->kind == kind && record->configuration == configuration &&
                record->descriptor_index == index && record->offset == offset) {
            selected = candidate;
            break;
        }
    }
    unsigned int used;
    if (selected != 0xffffffffU) {
        if (length == 0) {
            for (unsigned int source = selected + 1U; source < count; ++source)
                memcpy((void *)&table->records[source - 1U],
                    (const void *)&table->records[source],10);
            unsigned char remaining = (unsigned char)(count - 1U);
            table->count = remaining;
            memset((void *)&table->records[remaining],0,10);
            medius_descriptor_patch_compact_payloads();
            unsigned int generation = table->generation;
            table->generation = (unsigned char)(generation + 1U);
            table->admission_failed = 0;
            return selected;
        }
        volatile DescriptorPatchRecord *record = &table->records[selected];
        unsigned int previous_length = record->length;
        if (previous_length == length) {
            unsigned int pool_offset = record->payload_offset;
            if (memcmp((const void *)(table->payload + pool_offset),bytes,length) == 0)
                return selected;
        }
        used = table->payload_used;
        if (used + length - previous_length > 1024U)
            goto full;
        for (unsigned int source = selected + 1U; source < count; ++source)
            memcpy((void *)&table->records[source - 1U],
                (const void *)&table->records[source],10);
        unsigned char remaining = (unsigned char)(count - 1U);
        table->count = remaining;
        memset((void *)&table->records[remaining],0,10);
        medius_descriptor_patch_compact_payloads();
        used = table->payload_used;
        count = table->count;
    } else {
        if (length == 0)
            return 0xffffffffU;
        used = table->payload_used;
        if (used + length > 1024U || count == 16U)
            goto full;
    }
    volatile DescriptorPatchRecord *record = &table->records[count];
    record->identity = (unsigned short)(kind | (configuration << 8));
    record->length = length;
    record->payload_offset = (unsigned short)used;
    record->descriptor_index = (unsigned char)index;
    record->offset = (unsigned short)offset;
    memcpy((void *)(table->payload + used),bytes,length);
    unsigned int generation = table->generation;
    unsigned int current_count = table->count;
    unsigned char next_generation = (unsigned char)(generation + 1U);
    unsigned char next_count = (unsigned char)(current_count + 1U);
    unsigned int current_used = table->payload_used;
    table->count_and_generation = (unsigned short)(next_count | (next_generation << 8));
    table->payload_used = (unsigned short)(current_used + length);
    table->admission_failed = 0;
    return (unsigned int)next_count - 1U;
full:
    table->admission_failed = 1;
    return 0xfffffffeU;
}
