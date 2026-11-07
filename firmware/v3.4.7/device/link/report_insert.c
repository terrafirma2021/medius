/* Medius v3.4.7 device: recovered queue record insertion. */

#include "../include/types.h"

/* Native entry: 0x40377790. */
/* Original function-byte SHA-256:
 * 3f12a68271bb7556a1660ba57e96ac30ff0fd620c625a3edfb025757a3b126a7. */

/*
 * queue/index: writable queue and insertion index; report/length: copy source.
 * kind: low byte stored beside LOW8(length). Other metadata bytes/words are
 * stored at their named record offsets; score is reset. A negative signed epoch
 * stores 0xffff; otherwise store LOW16(epoch). Returns no value.
 *
 * Cache initial byte count. If index < count, memmove records[index..count-1]
 * one 84-byte slot forward. Copy FULL length without a 64-byte payload clamp,
 * then publish length/kind, metadata42, score0, metadata48, metadata44,
 * metadata50, special and epoch in that order. Finally reread count and store
 * count+1, wrapping to a byte. No capacity/index repair, lock, fence or allocation.
 * Caller must provide enough backing storage for both shift and copy and must
 * serialize queue changes. Writes beyond declared record capacity are not fixed.
 */
void report_insert_record(CreditInterfaceQueue *queue,unsigned int index,
    const unsigned char *report,unsigned int length,unsigned int kind,
    unsigned char metadata42,unsigned char metadata44,unsigned int metadata48,
    unsigned char special,unsigned int metadata50,int epoch)
{
    volatile CreditInterfaceQueue *queue_state = queue;
    unsigned int queue_address = (unsigned int)queue;
    unsigned int count = queue_state->record_count;
    if (index < count)
        memmove((void *)(queue_address + (index + 1U) * 84U),
                (const void *)(queue_address + index * 84U),(count - index) * 84U);
    unsigned char *record_bytes = (unsigned char *)(queue_address + index * 84U);
    memcpy(record_bytes,report,length);
    volatile CreditInterfaceRecord *record = (volatile CreditInterfaceRecord *)record_bytes;
    record->length_and_kind = (length & 255U) | (kind << 8);
    record->metadata42 = metadata42;
    record->score = 0;
    record->metadata48 = metadata48;
    record->metadata44 = metadata44;
    record->metadata50 = metadata50;
    record->special = special;
    record->epoch_tag = epoch < 0 ? 0xffffU : (unsigned short)epoch;
    count = queue_state->record_count;
    queue_state->record_count = count + 1U;
}
