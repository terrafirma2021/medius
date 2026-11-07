/* Device queued playback control requests. */
#include "../include/types.h"

/* Playback queue reconstruction utilities: inline native ring-header copies,
 * not additional native entries. Capacity masking assumes a power-of-two ring
 * but performs no validation. Even first==0 issues the native zero-length copy.
 * Only the first peek samples staging, before the first memcpy; pop rereads
 * the record header without resampling staging. No fence or lock is added.
 */
static __attribute__((always_inline)) inline unsigned short playback_control_peek_length(
    volatile ImperfectClipQueue *queue,unsigned char **staging)
{
    unsigned int capacity = queue->capacity;
    unsigned int read_cursor = queue->read_cursor;
    unsigned int offset = (capacity - 1U) & read_cursor;
    unsigned int available = capacity - offset;
    unsigned char *base = queue->storage;
    unsigned int first = available < 2U ? available : 2U;
    unsigned short length;
    if (staging != NULL)
        *staging = PLAYBACK_CONTROL_STAGING;
    memcpy(&length,base + offset,first);
    if (available < 2U)
        memcpy((unsigned char *)&length + first,queue->storage,2U - first);
    return length;
}

/* Native entry: 0x4202ac84. */
/* Original function-byte SHA-256:
 * 48da095045af5b26cb0ac204faa2d361510614d86fd24123db399de08d5d4813. */
/*
 * Try to start the next queued playback control request. Busy or no pending
 * records returns without touching time or queue. If imperfect mode is disabled,
 * read write_cursor then dropped count, copy write_cursor to read_cursor, clear
 * pending HALFWORD, and add the entry pending snapshot to dropped modulo65536.
 *
 * Otherwise MEMW/read forwarded generation before MEMW/current generation;
 * return while forwarding lags. Peek a two-byte little-endian record length
 * with one/two ring copies; cache staging pointer before the first copy. A
 * length<=510 causes a fresh capacity/cursor/base sample and copies that many
 * packet bytes into cached staging, handling one wrap. Length<=8 is invalid
 * after copying; length>510 is invalid without payload copy. If pending remains,
 * invalid records are popped by rereading their header, then freshly sampled
 * cursor/pending; cursor advances without masking, pending wraps16 on subtract.
 * Invalid-record removal does not increment drops or update timestamp.
 *
 * For a valid packet, reload staging pointer, read sequence BYTE then endpoint
 * BYTE, allocate low8((sequence+1)|0x80), and enqueue opcode0x31 for endpoint0 or
 *0x33 otherwise, passing the fresh pointer AND cached full record length. Failed
 * enqueue keeps queue, sequence, request metadata and time unchanged. Success
 * optionally pops a freshly read pending record with the same header reread,
 * then reloads staging once, publishes endpoint BYTE, sequence BYTE and eight
 * SETUP bytes. Sample clock; store start low WORD/high WORD, then waiting BYTE1.
 *
 * No lock, capacity/power-of-two/pointer check, queue repair, send retry or
 * firmware delivery/timing guarantee. Header and cursor can change between
 * copies; stored generation/sequence do not establish atomic ownership. The
 * Ghidra-inferred unconditional timestamp rewrites do not exist in native code.
 */
void playback_control_try_start(void)
{
    volatile PlaybackControlRequest *request = PLAYBACK_CONTROL_REQUEST;
    if (request->waiting != 0)
        return;
    volatile ImperfectClipQueue *queue = IMPERFECT_CLIP_QUEUE;
    unsigned int initial_pending = queue->pending_count;
    if (initial_pending == 0)
        return;
    unsigned char allow = IMPERFECT_FORWARDING_ALLOWED;
    if (allow == 0) {
        unsigned int write_cursor = queue->write_cursor;
        unsigned int dropped = IMPERFECT_CLIP_DROPPED;
        queue->read_cursor = write_cursor;
        queue->pending_count = 0;
        IMPERFECT_CLIP_DROPPED = (unsigned short)(dropped + initial_pending);
        return;
    }
    memw();
    unsigned int forwarded = CONTROL_FORWARDED_GENERATION;
    memw();
    unsigned int generation = DEVICE_OUT_GENERATION;
    if (forwarded < generation)
        return;
    unsigned char *staging;
    unsigned int length = playback_control_peek_length(queue,&staging);
    if (length <= 510U) {
        unsigned int capacity = queue->capacity;
        unsigned int read_cursor = queue->read_cursor;
        unsigned int offset = (read_cursor + 2U) & (capacity - 1U);
        unsigned char *base = queue->storage;
        unsigned int available = capacity - offset;
        unsigned int first = length < available ? length : available;
        memcpy(staging,base + offset,first);
        if (available < length)
            memcpy(staging + first,queue->storage,length - first);
        if (length > 8U) {
            unsigned char *packet = PLAYBACK_CONTROL_STAGING;
            unsigned int previous_sequence = PLAYBACK_CONTROL_SEQUENCE;
            unsigned int endpoint = *(const volatile unsigned char *)packet;
            unsigned char sequence = (unsigned char)((previous_sequence + 1U) | 0x80U);
            unsigned char opcode = endpoint == 0 ? 0x31 : 0x33;
            if (link_enqueue_nowait_silent(opcode,sequence,packet,
                    (unsigned short)length) == 0)
                return;
            if (queue->pending_count != 0) {
                unsigned short popped_length = playback_control_peek_length(queue,NULL);
                unsigned int cursor = queue->read_cursor;
                unsigned int pending = queue->pending_count;
                queue->read_cursor = cursor + 2U + popped_length;
                queue->pending_count = (unsigned short)(pending - 1U);
            }
            packet = PLAYBACK_CONTROL_STAGING;
            request->endpoint = *(const volatile unsigned char *)packet;
            PLAYBACK_CONTROL_SEQUENCE = sequence;
            memcpy((void *)request->setup,packet + 1,8);
            unsigned long long now = (unsigned long long)esp_timer_get_time();
            request->started.low = (unsigned int)now;
            request->started.high = (unsigned int)(now >> 32);
            request->waiting = 1;
            return;
        }
    }
    if (queue->pending_count != 0) {
        unsigned short popped_length = playback_control_peek_length(queue,NULL);
        unsigned int cursor = queue->read_cursor;
        unsigned int pending = queue->pending_count;
        queue->read_cursor = cursor + 2U + popped_length;
        queue->pending_count = (unsigned short)(pending - 1U);
    }
}
