/* Medius v3.4.7 host — link/control.c.
 * Recovered C and native assembly, grouped for source navigation.
 * Original entry addresses, firmware-byte hashes and function comments follow.
 */

#include "../include/types.h"

/* Native entry: 0x4200eda8. */
/* Original function-byte SHA-256:
 * 682bcbae3f24b207b7b2d1cc08b65c9a710ea202556eec475482526f0925500c. */
/* Accept one total/offset/count/data fragment into a shared assembly record.
 * assembly: Writable2064-byte record. fragment: Borrowed header+data bytes.
 * length: Native low16 byte count. No NULL, alignment or lifetime check.
 * Return1 on completion,0 otherwise. Require length>=6 and low16(count+6)
 * equal length. Read count HIGH/LOW, then offset HIGH,total HIGH,offset LOW,
 * total LOW. Offset0 starts/restarts only when total<=2057; publish total,
 * used0 and the halfword active1/error0. Other offsets return0 unchanged when
 * inactive; active continuations require the same total and offset==used.
 * Require offset+count<=cached total before copying. After a nonempty copy,
 * reread used THEN total; publish used+count modulo16. Equality clears only
 * active and returns1. Empty total0 completes without a copy. Invalid input
 * stores the halfword active0/error1; lengths/payload remain unchanged.
 * No sequence/endpoint correlation, timeout, lock or capacity revalidation
 * after memcpy. Corrupt assembly invariants or concurrent mutation can bypass
 * the bounds established by an ordinary admitted start. */
int control_fragment_accept(ControlAssembly *assembly,
    const unsigned char *fragment,unsigned short length)
{
    volatile ControlAssembly *state = assembly;
    const volatile unsigned char *input = fragment;
    if (length < 6) goto invalid;
    unsigned int count_high = input[5];
    unsigned int count_low = input[4];
    unsigned int count = (count_high << 8) | count_low;
    if (((count + 6U) & 65535U) != length) goto invalid;
    unsigned int offset_high = input[3];
    unsigned int total_high = input[1];
    unsigned int offset_low = input[2];
    unsigned int total_low = input[0];
    unsigned int offset = (offset_high << 8) | offset_low;
    unsigned int total = (total_high << 8) | total_low;
    if (offset == 0) {
        if (total > 2057) goto invalid;
        state->total = (unsigned short)total;
        state->used = 0;
        state->flags = 1;
    } else {
        if (state->active == 0) return 0;
        if (total != state->total) goto invalid;
    }
    unsigned int used = state->used;
    if (used != offset || offset + count > total) goto invalid;
    if (count != 0) {
        memcpy(assembly->payload + offset,fragment + 6,count);
        used = state->used;
        total = state->total;
    }
    unsigned short next_used = (unsigned short)(used + count);
    state->used = next_used;
    if (next_used == total) {
        state->active = 0;
        return 1;
    }
    return 0;
invalid:
    state->flags = 0x100;
    return 0;
}

/* Native entry: 0x4200ee54. */
/* Original function-byte SHA-256:
 * 196e9cee9d947f5e65bffc482b86082f052e6b2f8b04219fa10e8e0de449affe. */
/* Synchronously emit total/offset/count LE16 headers and borrowed payloads.
 * data: Readable total-byte source; not accessed for total0. total/chunk_limit
 * narrow16 at the ABI. callback/context are passed without NULL validation.
 * Effective chunk=max(1,min(chunk_limit,506)). Construct the total/offset
 * word then count halfword in a512-byte stack frame; copy only nonzero data.
 * Invoke callback(frame,count+6,context), then advance offset modulo16 using
 * the cached count, unaffected by callback changes to the frame header.
 * Total0 still invokes one six-byte empty fragment. The same frame storage
 * is reused on each call; a callback retaining data must copy it before return.
 * No allocation, retry, callback status or transport acknowledgement occurs. */
void control_fragment_emit(const unsigned char *data,unsigned short total,
    unsigned short chunk_limit,FragmentCallback callback,void *context)
{
    unsigned int chunk_size = chunk_limit;
    if (chunk_size > 506) chunk_size = 506;
    if (chunk_size == 0) chunk_size = 1;
    unsigned int offset = 0;
    ControlFragmentFrame frame;
    do {
        unsigned int count = ((unsigned int)total - offset) & 65535U;
        if (count > chunk_size) count = chunk_size;
        frame.total_and_offset = (unsigned int)total | (offset << 16);
        frame.count = (unsigned short)count;
        if (count != 0) memcpy(frame.data,data + offset,count);
        callback((const unsigned char *)&frame,(unsigned short)(count + 6U),context);
        offset = (offset + count) & 65535U;
    } while (offset < total);
}

/* Native entry: 0x42026b14. */
/* Original function-byte SHA-256:
 * cd33af5e0bdbe999b6040f439772b688ebe1b2044a729817b837dcec5f108cc0. */
/* Stamp and nonblocking-enqueue one2068-byte control work item.
 * work: Writable even when the queue is absent; generation is always stored.
 * Fence, sample current generation, THEN cache queue before publishing the
 * sampled generation. NULL queue or send result!=1 returns0. Only exact1
 * samples the current worker handle; nonNULL notifies index0,value0,action2,
 * previous-value NULL. Ignore notification result and return1 either way.
 * Queue send copies the item before return under its separate contract.
 * No generation lock, retry, queue/worker lifetime retention or rollback. */
int medius_control_work_enqueue(MediusControlWork *work)
{
    memw(); unsigned int generation = MEDIUS_HOST_CURRENT_GENERATION;
    RtosQueue *queue = MEDIUS_HOST_CONTROL_WORK_QUEUE;
    ((volatile MediusControlWork *)work)->generation = generation;
    if (queue == NULL || xQueueGenericSend(queue,work,0,0) != 1) return 0;
    RtosTask *worker = MEDIUS_HOST_CONTROL_WORKER_TASK;
    if (worker != NULL) xTaskGenericNotify(worker,0,0,2,NULL);
    return 1;
}

