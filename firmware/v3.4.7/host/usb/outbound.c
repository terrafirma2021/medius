/* Medius v3.4.7 host — usb/outbound.c.
 * Recovered C and native assembly, grouped for source navigation.
 * Original entry addresses, firmware-byte hashes and function comments follow.
 */

#include "../include/types.h"

/* Inline reconstruction utilities preserve native payload access widths/order.
 * They are not additional firmware entries. Neither copy is overlap-safe.
 * Source/destination addresses use native 32-bit wrapping arithmetic. */
static __inline__ __attribute__((always_inline)) void
out_enqueue_copy(unsigned int destination,unsigned int source,unsigned int length)
{
    /* Caller supplies 1..64 bytes. Equal alignment always copies at least one
     * byte before reaching the aligned WORD path, just as the native routine. */
    if (((destination ^ source) & 3U) == 0) {
        do {
            unsigned int byte = *(const volatile unsigned char *)source;
            source += 1;
            *(volatile unsigned char *)destination = (unsigned char)byte;
            destination += 1;
            length -= 1;
            if ((destination & 3U) == 0)
                break;
        } while (length != 0);
        while (length >= 16) {
            unsigned int word = *(const volatile unsigned int *)source;
            *(volatile unsigned int *)destination = word;
            word = *(const volatile unsigned int *)(source + 4U);
            *(volatile unsigned int *)(destination + 4U) = word;
            word = *(const volatile unsigned int *)(source + 8U);
            *(volatile unsigned int *)(destination + 8U) = word;
            word = *(const volatile unsigned int *)(source + 12U);
            *(volatile unsigned int *)(destination + 12U) = word;
            source += 16;
            destination += 16;
            length -= 16;
        }
        while (length >= 4) {
            unsigned int word = *(const volatile unsigned int *)source;
            source += 4;
            *(volatile unsigned int *)destination = word;
            destination += 4;
            length -= 4;
        }
    } else {
        while ((source & 3U) != 0) {
            unsigned int byte = *(const volatile unsigned char *)source;
            source += 1;
            *(volatile unsigned char *)destination = (unsigned char)byte;
            destination += 1;
            if (--length == 0)
                return;
        }
        while (length >= 16) {
            for (unsigned int index = 0; index < 4; ++index) {
                unsigned int word = *(const volatile unsigned int *)(source + index * 4U);
                volatile unsigned char *output = (volatile unsigned char *)(destination + index * 4U);
                if (index != 3) {
                    output[1] = (unsigned char)(word >> 8);
                    output[2] = (unsigned char)(word >> 16);
                    output[3] = (unsigned char)(word >> 24);
                    output[0] = (unsigned char)word;
                } else {
                    output[0] = (unsigned char)word;
                    output[1] = (unsigned char)(word >> 8);
                    output[2] = (unsigned char)(word >> 16);
                    output[3] = (unsigned char)(word >> 24);
                }
            }
            source += 16;
            destination += 16;
            length -= 16;
        }
        while (length >= 4) {
            unsigned int word = *(const volatile unsigned int *)source;
            volatile unsigned char *output = (volatile unsigned char *)destination;
            source += 4;
            output[0] = (unsigned char)word;
            output[1] = (unsigned char)(word >> 8);
            output[2] = (unsigned char)(word >> 16);
            output[3] = (unsigned char)(word >> 24);
            destination += 4;
            length -= 4;
        }
    }
    while (length != 0) {
        unsigned int byte = *(const volatile unsigned char *)source;
        source += 1;
        *(volatile unsigned char *)destination = (unsigned char)byte;
        destination += 1;
        length -= 1;
    }
}

static __inline__ __attribute__((always_inline)) void
out_worker_copy(unsigned int destination,unsigned int source,unsigned int length)
{
    if (length == 0)
        return;
    while ((source & 3U) != 0) {
        unsigned int byte = *(const volatile unsigned char *)source;
        source += 1;
        *(volatile unsigned char *)destination = (unsigned char)byte;
        destination += 1;
        if (--length == 0)
            return;
    }
    while (length >= 16) {
        /* Native reads +4,+8,+12,+0 before any destination write. */
        unsigned int second = *(const volatile unsigned int *)(source + 4U);
        unsigned int third = *(const volatile unsigned int *)(source + 8U);
        unsigned int fourth = *(const volatile unsigned int *)(source + 12U);
        unsigned int first = *(const volatile unsigned int *)source;
        volatile unsigned char *output = (volatile unsigned char *)destination;
        output[7] = (unsigned char)(second >> 24);
        output[4] = (unsigned char)second;
        output[9] = (unsigned char)(third >> 8);
        output[10] = (unsigned char)(third >> 16);
        output[11] = (unsigned char)(third >> 24);
        output[8] = (unsigned char)third;
        output[0] = (unsigned char)first;
        output[1] = (unsigned char)(first >> 8);
        output[2] = (unsigned char)(first >> 16);
        output[3] = (unsigned char)(first >> 24);
        output[5] = (unsigned char)(second >> 8);
        output[6] = (unsigned char)(second >> 16);
        output[12] = (unsigned char)fourth;
        output[13] = (unsigned char)(fourth >> 8);
        output[14] = (unsigned char)(fourth >> 16);
        output[15] = (unsigned char)(fourth >> 24);
        source += 16;
        destination += 16;
        length -= 16;
    }
    while (length >= 4) {
        unsigned int word = *(const volatile unsigned int *)source;
        source += 4;
        volatile unsigned char *output = (volatile unsigned char *)destination;
        output[0] = (unsigned char)word;
        output[1] = (unsigned char)(word >> 8);
        output[2] = (unsigned char)(word >> 16);
        output[3] = (unsigned char)(word >> 24);
        destination += 4;
        length -= 4;
    }
    if (length != 0)
        memcpy((void *)destination,(const void *)source,length);
}

/* Native entry: 0x4200b14c. */
/* Original function-byte SHA-256:
 * 91d32bdd2bf9fd9b66e49d673340deec49458e39a6d686147d0268ace9a68d37. */
/* Publish result32 after MEMW, then pending byte 1 after a second MEMW.
 * Exact status -13 returns without notifying. Otherwise sample the wake handle,
 * initialize one task-woken word to 0 and give from ISR, ignoring its return.
 * A nonzero task-woken result yields through the port switch entry. No state,
 * handle or context validation; this callback never pops a queued packet. */
void medius_out_complete(MediusOutRelayState *state,int result)
{
    volatile MediusOutRelayState *relay = state;
    memw();
    relay->completion_result = result;
    memw();
    relay->completion_pending = 1;
    if (result == -13)
        return;
    RtosQueue *wake = MEDIUS_OUT_WAKE;
    int higher_priority_woken = 0;
    xQueueGiveFromISR(wake,&higher_priority_woken);
    if (higher_priority_woken != 0)
        _frxt_setup_switch();
}

/* Native entry: 0x4200b184. */
/* Original function-byte SHA-256:
 * 2d7b728e9a95168178d14e35dba3cbdca0c9b0173f4518d009abf4e27a407a65. */
/* Drop the prefix whose generations report applied, with a minimum of one.
 * Reload head before each generation lookup and count after each callback;
 * the drop cursor wraps to a byte. Initial count 0 still drops one, producing
 * count 255. Read the final dropped slot modulo 4 using the freshly loaded
 * head, store last_ack, then write head/count together as one halfword and
 * clear both retry bytes with one halfword store. Emit {endpoint,last_ack,1}
 * to the three-byte ACK queue, then wake the worker; both sends are wait0/back0
 * with ignored results. No local mutex, active-state, capacity or underflow check. */
void medius_out_drop_stalled(MediusOutRelayState *state)
{
    volatile MediusOutRelayState *relay = state;
    unsigned int count = relay->count;
    unsigned int dropped = 0;
    if (count == 0) {
        dropped = 1;
    } else {
        do {
            unsigned int head = relay->head;
            unsigned int generation = relay->packets[(head + dropped) & 3U].generation;
            unsigned int applied = medius_host_generation_is_applied(generation);
            count = relay->count;
            if (applied == 0) {
                if (dropped == 0)
                    dropped = 1;
                break;
            }
            dropped = (dropped + 1U) & 0xffU;
        } while (dropped < count);
    }
    unsigned int head = relay->head;
    unsigned int sequence = relay->packets[(head + dropped - 1U) & 3U].sequence;
    relay->last_ack = (unsigned char)sequence;
    relay->head_count = (unsigned short)(((head + dropped) & 3U) |
        (((count - dropped) & 0xffU) << 8));
    relay->retry_counts = 0;
    unsigned int endpoint = relay->endpoint;
    MediusOutAckStorage ack;
    ack.endpoint_sequence = (unsigned short)(endpoint | (sequence << 8));
    ack.status = 1;
    xQueueGenericSend(MEDIUS_OUT_ACK_QUEUE,&ack,0,0);
    xQueueGenericSend(MEDIUS_OUT_WAKE,(void *)0,0,0);
}

/* Native entry: 0x4200b22c. */
/* Original function-byte SHA-256:
 * a971c74932cb022fe0904b32ea0c24a4f9ee50f99cca42559ca56ef87b874785. */
/* Initial count 0 returns unchanged. Cutoff FFFFFFFF discards everything,
 * taking last_ack from (head+count-1)&3 and clearing head/count together.
 * Otherwise scan the cached-count prefix from the initial head while unsigned
 * packet generation <= cutoff; first greater generation stops the scan. Zero
 * dropped returns unchanged. Commit last_ack, packed head/count and zero retry
 * halfword, then send {endpoint,last_ack,2} and wake, wait0/back0, ignoring both
 * results. Scan cursor/count are bytes; no local lock, active cancellation,
 * generation-wrap ordering or validation of the trusted four-slot ring. */
void medius_out_discard_through(MediusOutRelayState *state,unsigned int generation)
{
    volatile MediusOutRelayState *relay = state;
    unsigned int count = relay->count;
    if (count == 0)
        return;
    unsigned int head = relay->head;
    unsigned int sequence;
    if (generation == 0xffffffffU) {
        sequence = relay->packets[(head + count - 1U) & 3U].sequence;
        relay->last_ack = (unsigned char)sequence;
        relay->head_count = 0;
    } else {
        unsigned int dropped = 0;
        do {
            unsigned int queued_generation = relay->packets[(head + dropped) & 3U].generation;
            if (queued_generation > generation)
                break;
            dropped = (dropped + 1U) & 0xffU;
        } while (dropped != count);
        if (dropped == 0)
            return;
        sequence = relay->packets[(head + dropped - 1U) & 3U].sequence;
        relay->last_ack = (unsigned char)sequence;
        relay->head_count = (unsigned short)(((head + dropped) & 3U) |
            (((count - dropped) & 0xffU) << 8));
    }
    relay->retry_counts = 0;
    unsigned int endpoint = relay->endpoint;
    MediusOutAckStorage ack;
    ack.endpoint_sequence = (unsigned short)(endpoint | (sequence << 8));
    ack.status = 2;
    xQueueGenericSend(MEDIUS_OUT_ACK_QUEUE,&ack,0,0);
    xQueueGenericSend(MEDIUS_OUT_WAKE,(void *)0,0,0);
}

/* Native entry: 0x4200b2f0. */
/* Original function-byte SHA-256:
 * 37de76111874c54fe396624f016cbdd6eac429c143eb4bf42e2cf206bfa5d391. */
/* Queue one generation-stamped OUT packet. Null mutex returns without an ACK;
 * otherwise take its sampled handle indefinitely and ignore the result.
 * Endpoint0 rejects. Match an existing endpoint BYTE against the full32 argument;
 * no direction/range narrowing occurs before lookup. With no match, sample
 * current generation: already-applied rejects; future generation may allocate
 * the first endpoint0 record, clear392 bytes and store only low8(endpoint).
 * Thus a future full-width endpoint can allocate with a truncated/zero identity.
 * Exact count4 rejects and writes low8(sequence) to last_ack; other counts pass.
 * Select tail=(head+count)&3 before sampling current generation again. Store
 * generation WORD then low16(sequence | (min(unsigned length,64)<<8)) HALF.
 * Sequence bits8..15 can enlarge stored length beyond copied bytes; retain them.
 * Original length0 performs no payload access. Otherwise copy clipped1..64 bytes
 * with the native alignment-dependent forward BYTE/WORD access ordering.
 * Reload count, sample mutex BEFORE storing incremented count byte, give that
 * saved mutex and wake. Rejection sends low16(endpoint | sequence<<8), status2
 * and wake while holding the mutex, then gives current mutex. Ignore all sends.
 * No null payload, duplicate sequence, count>4, generation-wrap, overlap or
 * pointer/extent validation; partial copies and counter wrap remain native. */
void medius_out_enqueue(unsigned int endpoint,unsigned int sequence,
    unsigned char *payload,unsigned int length)
{
    RtosQueue *mutex = MEDIUS_OUT_MUTEX;
    if (mutex == 0)
        return;
    xQueueSemaphoreTake(mutex,0xffffffffU);
    if (endpoint == 0)
        goto rejected;
    MediusOutRelayState *state = 0;
    for (unsigned int index = 0; index < 10; ++index) {
        volatile MediusOutRelayState *candidate = &MEDIUS_OUT_RELAYS[index];
        if (candidate->endpoint == endpoint) {
            state = &MEDIUS_OUT_RELAYS[index];
            break;
        }
    }
    if (state == 0) {
        unsigned int generation = medius_host_get_current_generation();
        if (medius_host_generation_is_applied(generation) != 0)
            goto rejected;
        for (unsigned int index = 0; index < 10; ++index) {
            volatile MediusOutRelayState *candidate = &MEDIUS_OUT_RELAYS[index];
            if (candidate->endpoint == 0) {
                state = &MEDIUS_OUT_RELAYS[index];
                memset(state,0,392);
                ((volatile MediusOutRelayState *)state)->endpoint = (unsigned char)endpoint;
                break;
            }
        }
        if (state == 0)
            goto rejected;
    }
    volatile MediusOutRelayState *relay = state;
    unsigned int count = relay->count;
    if (count == 4) {
        relay->last_ack = (unsigned char)sequence;
        goto rejected;
    }
    unsigned int head = relay->head;
    unsigned int tail = (head + count) & 3U;
    unsigned int copied = length < 64U ? length : 64U;
    unsigned int generation = medius_host_get_current_generation();
    volatile MediusOutRelayPacket *packet = &relay->packets[tail];
    packet->generation = generation;
    packet->sequence_length = (unsigned short)(sequence | (copied << 8));
    if (length != 0)
        out_enqueue_copy((unsigned int)packet->payload,(unsigned int)payload,copied);
    count = relay->count;
    mutex = MEDIUS_OUT_MUTEX;
    relay->count = (unsigned char)(count + 1U);
    xQueueGenericSend(mutex,(void *)0,0,0);
    xQueueGenericSend(MEDIUS_OUT_WAKE,(void *)0,0,0);
    return;

rejected:;
    MediusOutAckStorage ack;
    ack.status = 2;
    ack.endpoint_sequence = (unsigned short)(endpoint | (sequence << 8));
    xQueueGenericSend(MEDIUS_OUT_ACK_QUEUE,&ack,0,0);
    xQueueGenericSend(MEDIUS_OUT_WAKE,(void *)0,0,0);
    xQueueGenericSend(MEDIUS_OUT_MUTEX,(void *)0,0,0);
}

/* Native entry: 0x4200b5f8. */
/* Original function-byte SHA-256:
 * 42ccdb4d5408ed4d2035bc8d34789f4bd4b6aa93327affb5b0c562f9b5a5209a. */
/* MEMW/read result32, MEMW/clear pending, then MEMW/read in-flight and count.
 * Clear active before a further MEMW/store of decremented in-flight byte.
 * Accounting wraps even if count is 0; empty count returns afterwards.
 * Nonnegative result pops the unmasked head slot, publishes last_ack and packed
 * head/count, clears retry halfword and sends status0 ACK plus wake.
 * -10 (NAK) on bulk increments nak_retry modulo256: values below8 retry at now,
 * otherwise now+1000us; nonbulk -10 uses now+1000 without incrementing NAK retry.
 * -8 (stall) sets halted1 and delegates stalled-prefix drop. Other negative
 * results increment error_retry modulo256: values >=3 pop/ACK status2, smaller
 * values retry at now+1000. Retry time addition wraps64 and stores LOW then HIGH.
 * No mutex acquisition, result/actual-length cross-check, descriptor/head bound
 * checks or guaranteed deadline. Queue-send results are ignored. */
void medius_out_consume_completion(MediusOutRelayState *state,long long now_us)
{
    volatile MediusOutRelayState *relay = state;
    memw();
    int result = relay->completion_result;
    memw();
    relay->completion_pending = 0;
    memw();
    unsigned int inflight = MEDIUS_OUT_INFLIGHT;
    unsigned int count = relay->count;
    relay->active = 0;
    memw();
    MEDIUS_OUT_INFLIGHT = (unsigned char)(inflight - 1U);
    if (count == 0)
        return;
    unsigned int ack_status = 0;
    if (result < 0) {
        unsigned long long retry = (unsigned long long)now_us;
        if (result == -10) {
            const volatile unsigned char *descriptor = relay->descriptor;
            if ((descriptor[3] & 3U) == 2) {
                unsigned int attempts = (relay->nak_retry + 1U) & 0xffU;
                relay->nak_retry = (unsigned char)attempts;
                if (attempts >= 8)
                    retry += 1000U;
            } else {
                retry += 1000U;
            }
        } else if (result == -8) {
            relay->halted = 1;
            medius_out_drop_stalled(state);
            return;
        } else {
            unsigned int attempts = (relay->error_retry + 1U) & 0xffU;
            relay->error_retry = (unsigned char)attempts;
            if (attempts >= 3) {
                ack_status = 2;
                goto pop_packet;
            }
            retry += 1000U;
        }
        volatile unsigned int *deadline = (volatile unsigned int *)&relay->retry_at_us;
        deadline[0] = (unsigned int)retry;
        deadline[1] = (unsigned int)(retry >> 32);
        return;
    }
pop_packet:;
    unsigned int head = relay->head;
    unsigned int sequence = relay->packets[head].sequence;
    relay->last_ack = (unsigned char)sequence;
    relay->head_count = (unsigned short)(((head + 1U) & 3U) |
        (((count - 1U) & 0xffU) << 8));
    relay->retry_counts = 0;
    unsigned int endpoint = relay->endpoint;
    MediusOutAckStorage ack;
    ack.endpoint_sequence = (unsigned short)(endpoint | (sequence << 8));
    ack.status = (unsigned char)ack_status;
    xQueueGenericSend(MEDIUS_OUT_ACK_QUEUE,&ack,0,0);
    xQueueGenericSend(MEDIUS_OUT_WAKE,(void *)0,0,0);
}

/* Native entry: 0x4200b738. */
/* Original function-byte SHA-256:
 * 0aca461238b34c17276bc5709ecc7095912d705f29cd4f73c27936a08c78da0b. */
/* OUT worker: priority6/core0/stack4096, created by medius_out_start_worker.
 * Ignore the task argument and loop forever. Take current OUT mutex indefinitely
 * without checking; sample one64-bit time. Scan10 nonzero-endpoint/active records,
 * MEMW/read pending, and consume completions with that same sampled time.
 * Read HID then vendor reservation bytes; budget=max(8-(1+HID+vendor),0), <=7.
 * In ascending table order admit nonzero endpoint, inactive, nonempty, MEMW/pause0.
 * Test generation at the raw unmasked head. Future generation requests short wait.
 * Applied but detached queues re-read count, ACK last slot status2 if nonempty,
 * clear packed head/count and separate retry bytes, wake, then clear392 bytes.
 * Halted delegates stalled-prefix drop. MEMW/inhibit, HIGH-first signed64 retry
 * comparison, MEMW/in-flight>=budget or disconnected port postpones submission.
 * Each blocked branch replaces the short-wait byte; successful admission later
 * ORs it with (fresh active BYTE XOR1), truncated to8 bits.
 * Reload raw head; copy raw packet length BYTE, without clamping, into this
 * record's64-byte DMA slot. The inline utility preserves source alignment,
 * prefetched WORD/BYTE store order and ROM memcpy tail. Zero length retains a
 * nonnull DMA pointer. Oversized length/head remain unchecked and can cross slots.
 * Cache port/descriptor across copy, sample endpoint type, then write only URB
 * setup0/buffer/timeout0/port/endpoint/remaining/callback/context in native order.
 * Bulk preserves interval. Other types read port speed then descriptor interval:
 * speed<3 uses interval*1000us; otherwise unsigned32(125<<low5(interval-1)).
 * MEMW/clear pending; MEMW/read in-flight, set active1, MEMW/store incremented byte
 * before submit. Every negative submit clears active, MEMW/read then MEMW/store
 * decremented byte and records fresh wrapping(time+1000us), LOW then HIGH.
 * Submission itself never pops or ACKs. Release current mutex; drain three-byte
 * ACKs while receive(wait0)==1, sending link opcode0x3d/flags0/length3. Ignore
 * transport results. Wait one RTOS tick when short-wait byte!=0, otherwise forever.
 * No dedicated timer, deadline guarantee, fairness rotation, lock-result handling,
 * actual-length validation or runtime/concurrency equivalence is implied. */
void medius_task_outrelay(void *unused_argument)
{
    (void)unused_argument;
    for (;;) {
        xQueueSemaphoreTake(MEDIUS_OUT_MUTEX,0xffffffffU);
        unsigned long long sampled_time = (unsigned long long)esp_timer_get_time();
        for (unsigned int index = 0; index < 10; ++index) {
            MediusOutRelayState *state = &MEDIUS_OUT_RELAYS[index];
            volatile MediusOutRelayState *relay = state;
            if (relay->endpoint != 0 && relay->active != 0) {
                memw();
                if (relay->completion_pending != 0)
                    medius_out_consume_completion(state,(long long)sampled_time);
            }
        }
        unsigned int reserved = (unsigned int)medius_hid_reserved_slots() + 1U;
        reserved += (unsigned int)medius_vendor_reserved_slots();
        unsigned int budget = reserved < 8U ? 8U - reserved : 0;
        unsigned int short_wait = 0;
        for (unsigned int index = 0; index < 10; ++index) {
            MediusOutRelayState *state = &MEDIUS_OUT_RELAYS[index];
            volatile MediusOutRelayState *relay = state;
            if (relay->endpoint == 0 || relay->active != 0 || relay->count == 0)
                continue;
            memw();
            if (MEDIUS_OUT_PAUSE != 0)
                continue;
            unsigned int generation_head = relay->head;
            const volatile MediusOutRelayPacket *generation_packet =
                (const volatile MediusOutRelayPacket *)((unsigned int)state +
                    __builtin_offsetof(MediusOutRelayState,packets) + generation_head * 72U);
            unsigned int generation = generation_packet->generation;
            unsigned int applied = medius_host_generation_is_applied(generation);
            if (applied == 0) {
                short_wait = 1;
                continue;
            }
            MediusHostHubPortPrefix *port = relay->hubport;
            unsigned char *descriptor = 0;
            if (port != 0)
                descriptor = relay->descriptor;
            if (port == 0 || descriptor == 0) {
                unsigned int count = relay->count;
                if (count != 0) {
                    unsigned int head = relay->head;
                    unsigned int sequence = relay->packets[(head + count - 1U) & 3U].sequence;
                    relay->last_ack = (unsigned char)sequence;
                    relay->head_count = 0;
                    relay->nak_retry = 0;
                    unsigned int endpoint = relay->endpoint;
                    MediusOutAckStorage ack;
                    ack.endpoint_sequence = (unsigned short)(endpoint | (sequence << 8));
                    RtosQueue *ack_queue = MEDIUS_OUT_ACK_QUEUE;
                    relay->error_retry = 0;
                    ack.status = 2;
                    xQueueGenericSend(ack_queue,&ack,0,0);
                    xQueueGenericSend(MEDIUS_OUT_WAKE,(void *)0,0,0);
                }
                memset(state,0,392);
                continue;
            }
            if (relay->halted != 0) {
                medius_out_drop_stalled(state);
                continue;
            }
            memw();
            unsigned int inhibited = relay->submission_inhibited;
            if (inhibited != 0) {
                short_wait = inhibited;
                continue;
            }
            const volatile unsigned int *retry_words = (const volatile unsigned int *)&relay->retry_at_us;
            int retry_high = (int)retry_words[1];
            int now_high = (int)(sampled_time >> 32);
            if (now_high < retry_high) {
                short_wait = applied;
                continue;
            }
            if (now_high == retry_high) {
                unsigned int retry_low = retry_words[0];
                if ((unsigned int)sampled_time < retry_low) {
                    short_wait = applied;
                    continue;
                }
            }
            memw();
            unsigned int inflight = MEDIUS_OUT_INFLIGHT;
            if (inflight >= budget) {
                short_wait = applied;
                continue;
            }
            if (((const volatile MediusHostHubPortPrefix *)port)->connected == 0) {
                short_wait = applied;
                continue;
            }
            unsigned int head = relay->head;
            volatile MediusOutRelayPacket *packet = (volatile MediusOutRelayPacket *)
                ((unsigned int)state + __builtin_offsetof(MediusOutRelayState,packets) + head * 72U);
            unsigned int length = packet->length;
            unsigned char *dma_buffer = MEDIUS_OUT_DMA_SLOTS[index];
            out_worker_copy((unsigned int)dma_buffer,(unsigned int)packet->payload,length);
            const volatile unsigned char *endpoint_descriptor = descriptor;
            unsigned int endpoint_type = endpoint_descriptor[3] & 3U;
            volatile MediusHostUrb *urb = &relay->urb;
            urb->setup = 0;
            urb->buffer = dma_buffer;
            urb->timeout = 0;
            urb->hubport = port;
            urb->endpoint = descriptor;
            urb->remaining = length;
            urb->complete = medius_out_urb_completion;
            urb->context = state;
            if (endpoint_type != 2) {
                unsigned int speed = ((const volatile MediusHostHubPortPrefix *)port)->speed;
                unsigned int interval = endpoint_descriptor[6];
                urb->interval_us = speed < 3 ? interval * 1000U :
                    125U << ((interval - 1U) & 31U);
            }
            memw();
            relay->completion_pending = 0;
            memw();
            inflight = MEDIUS_OUT_INFLIGHT;
            relay->active = 1;
            memw();
            MEDIUS_OUT_INFLIGHT = (unsigned char)(inflight + 1U);
            int result = usbh_submit_urb(&state->urb);
            if (result < 0) {
                relay->active = 0;
                memw();
                inflight = MEDIUS_OUT_INFLIGHT;
                memw();
                MEDIUS_OUT_INFLIGHT = (unsigned char)(inflight - 1U);
                unsigned long long retry = (unsigned long long)esp_timer_get_time() + 1000U;
                volatile unsigned int *deadline = (volatile unsigned int *)&relay->retry_at_us;
                deadline[0] = (unsigned int)retry;
                deadline[1] = (unsigned int)(retry >> 32);
            }
            unsigned int active = relay->active;
            short_wait = (short_wait | (active ^ 1U)) & 0xffU;
        }
        xQueueGenericSend(MEDIUS_OUT_MUTEX,(void *)0,0,0);
        MediusOutAckStorage ack;
        while (xQueueReceive(MEDIUS_OUT_ACK_QUEUE,&ack,0) == 1)
            link_send_wait100(0x3d,0,&ack,3);
        RtosQueue *wake = MEDIUS_OUT_WAKE;
        xQueueSemaphoreTake(wake,short_wait != 0 ? 1U : 0xffffffffU);
    }
}

/* Native entry: 0x4200bc4c. */
/* Original function-byte SHA-256:
 * 67bedefc52720ecaf34c6eb2b70fb8397eca5696e2277e5f59174f6e9860be11. */
/* Inactive returns unchanged. Set actual-out word0 and call kill-with-actual
 * for the embedded URB, ignoring status. MEMW/read pending and, if nonzero,
 * MEMW/read completion result. Pending with result != -13 samples time and
 * delegates completion consumption, disregarding cancellation actual length.
 * Otherwise MEMW/clear pending; MEMW/read in-flight and actual; clear active,
 * then MEMW/store decremented in-flight byte. Nonzero actual pops exactly one
 * unmasked-head packet, updates last_ack/packed head-count, clears retry halfword
 * and emits status0 ACK plus wake. Zero actual preserves queue/retry fields.
 * No queue-count check, local lock, waiting loop or independent timeout. */
void medius_out_cancel(MediusOutRelayState *state)
{
    volatile MediusOutRelayState *relay = state;
    if (relay->active == 0)
        return;
    unsigned int actual = 0;
    medius_usbh_kill_urb_with_actual(&state->urb,&actual);
    memw();
    if (relay->completion_pending != 0) {
        memw();
        if (relay->completion_result != -13) {
            long long now = esp_timer_get_time();
            medius_out_consume_completion(state,now);
            return;
        }
    }
    memw();
    relay->completion_pending = 0;
    memw();
    unsigned int inflight = MEDIUS_OUT_INFLIGHT;
    unsigned int transferred = *(volatile unsigned int *)&actual;
    relay->active = 0;
    memw();
    MEDIUS_OUT_INFLIGHT = (unsigned char)(inflight - 1U);
    if (transferred == 0)
        return;
    unsigned int head = relay->head;
    unsigned int count = relay->count;
    unsigned int sequence = relay->packets[head].sequence;
    relay->last_ack = (unsigned char)sequence;
    relay->head_count = (unsigned short)(((head + 1U) & 3U) |
        (((count - 1U) & 0xffU) << 8));
    relay->retry_counts = 0;
    unsigned int endpoint = relay->endpoint;
    MediusOutAckStorage ack;
    ack.endpoint_sequence = (unsigned short)(endpoint | (sequence << 8));
    ack.status = 0;
    xQueueGenericSend(MEDIUS_OUT_ACK_QUEUE,&ack,0,0);
    xQueueGenericSend(MEDIUS_OUT_WAKE,(void *)0,0,0);
}

/* Native entry: 0x4200bd10. */
/* Original function-byte SHA-256:
 * 356b45a296af29f63ba2dc7521f5e22b37e8db7d06715b21e839635b4e0c807c. */
/* MEMW/set pause1, sample time and MEMW/read in-flight. Wait while its raw
 * byte is nonzero and signed64 current time < wrapping(start+60000us), delaying
 * one RTOS tick before each MEMW/reload. Then sample control generation once
 * and take the current OUT mutex indefinitely, ignoring result. Scan all10
 * nonzero-endpoint records: active+MEMW/pending consumes completion with a fresh
 * timestamp; cancel each record afterwards regardless of active. Nonzero full32
 * discard argument discards through the sampled cutoff. Give the reread mutex.
 * Pause stays set. No initial mutex check, guaranteed wait duration, unconditional
 * final wake or handling of cancellation/queue/tick errors. */
void medius_out_pause_and_reconcile(unsigned int discard_queued)
{
    memw();
    MEDIUS_OUT_PAUSE = 1;
    unsigned long long start = (unsigned long long)esp_timer_get_time();
    memw();
    unsigned int inflight = MEDIUS_OUT_INFLIGHT;
    unsigned long long deadline = start + 60000U;
    while (inflight != 0) {
        long long now = esp_timer_get_time();
        if (now >= (long long)deadline)
            break;
        vTaskDelay(1);
        memw();
        inflight = MEDIUS_OUT_INFLIGHT;
    }
    unsigned int generation = medius_host_get_control_generation();
    xQueueSemaphoreTake(MEDIUS_OUT_MUTEX,0xffffffffU);
    for (unsigned int index = 0; index < 10; ++index) {
        MediusOutRelayState *state = &MEDIUS_OUT_RELAYS[index];
        volatile MediusOutRelayState *relay = state;
        if (relay->endpoint == 0)
            continue;
        if (relay->active != 0) {
            memw();
            if (relay->completion_pending != 0) {
                long long now = esp_timer_get_time();
                medius_out_consume_completion(state,now);
            }
        }
        medius_out_cancel(state);
        if (discard_queued != 0)
            medius_out_discard_through(state,generation);
    }
    xQueueGenericSend(MEDIUS_OUT_MUTEX,(void *)0,0,0);
}

/* Native entry: 0x4200bdf0. */
/* Original function-byte SHA-256:
 * 571d8f9659435bf56caba5267074e9583ce0ad1a8130c6021a201d38acf7963a. */
/* Create/store mutex(type1), then wake queue(capacity1,item0,type3), then ACK
 * queue(capacity32,item3,type0). Create outrelay on core0 with stack4096 bytes,
 * priority6, NULL argument and NULL task-handle output. Preserve the constructor
 * type arguments in the outgoing ABI even though generic recovered declarations
 * omit them. Every returned handle/status is accepted without checking, cleanup,
 * singleton guard or rollback; repeated calls can leak previous resources.
 * Task entry is a separately reviewed-or-queued native identity, not inlined. */
void medius_out_start_worker(void)
{
    MEDIUS_OUT_MUTEX = medius_out_create_mutex(1);
    MEDIUS_OUT_WAKE = medius_out_create_queue(1,0,3);
    MEDIUS_OUT_ACK_QUEUE = medius_out_create_queue(32,3,0);
    xTaskCreatePinnedToCore(medius_out_task_entry,"outrelay",4096,(void *)0,6,
        (RtosTask **)0,0);
}

/* Native entry: 0x4200be44. */
/* Original function-byte SHA-256:
 * 75c519a43534fe6b89ec44609ed2f4f4aa014ce54d419358968f1ee5a37c3270. */
/* Require sampled mutex, hubport and descriptor nonnull and initial endpoint
 * byte2 without IN bit7. Take sampled mutex indefinitely, ignoring result, then
 * reload endpoint. Nonzero endpoint reuses the first exact match among10 records,
 * without checking hubport. Otherwise use first endpoint0 slot, memset392 and
 * reload descriptor endpoint again. Full table gives current mutex, then logs
 * with a fresh descriptor endpoint read. On success write endpoint/port/descriptor;
 * sample active BEFORE clearing halted, then sample mutex BEFORE optionally
 * clearing URB toggle when sampled active==0. Give that sampled mutex.
 * Reused records retain packets, URB and other state. Descriptor changes after
 * the initial direction check are not revalidated. No wake or submission. */
void medius_out_register(void *hubport,unsigned char *descriptor)
{
    RtosQueue *mutex = MEDIUS_OUT_MUTEX;
    if (mutex == 0 || hubport == 0 || descriptor == 0)
        return;
    const volatile unsigned char *endpoint_descriptor = descriptor;
    if ((endpoint_descriptor[2] & 0x80U) != 0)
        return;
    xQueueSemaphoreTake(mutex,0xffffffffU);
    unsigned int endpoint = endpoint_descriptor[2];
    MediusOutRelayState *state = 0;
    if (endpoint != 0) {
        for (unsigned int index = 0; index < 10; ++index) {
            volatile MediusOutRelayState *candidate = &MEDIUS_OUT_RELAYS[index];
            if (candidate->endpoint == endpoint) {
                state = &MEDIUS_OUT_RELAYS[index];
                break;
            }
        }
    }
    if (state == 0) {
        for (unsigned int index = 0; index < 10; ++index) {
            volatile MediusOutRelayState *candidate = &MEDIUS_OUT_RELAYS[index];
            if (candidate->endpoint == 0) {
                state = &MEDIUS_OUT_RELAYS[index];
                memset(state,0,392);
                endpoint = endpoint_descriptor[2];
                break;
            }
        }
    }
    if (state == 0) {
        xQueueGenericSend(MEDIUS_OUT_MUTEX,(void *)0,0,0);
        unsigned int logged_endpoint = endpoint_descriptor[2];
        medius_host_log_formatted("OUT %02x: no relay slot",logged_endpoint);
        return;
    }
    volatile MediusOutRelayState *relay = state;
    relay->endpoint = (unsigned char)endpoint;
    relay->hubport = hubport;
    relay->descriptor = descriptor;
    unsigned int active = relay->active;
    relay->halted = 0;
    mutex = MEDIUS_OUT_MUTEX;
    if (active == 0)
        relay->urb.toggle = 0;
    xQueueGenericSend(mutex,(void *)0,0,0);
}

/* Native entry: 0x4200bf34. */
/* Original function-byte SHA-256:
 * 3ff28a07819a46832817c6e381872af225856e6eababa6e426aaf83998489541. */
/* Keep low8(endpoint). Null sampled mutex returns. Endpoint0 uses cutoff
 * FFFFFFFF and the sampled mutex; other endpoints sample control generation,
 * then reload mutex before taking it indefinitely. Ignore take status. For all10
 * records require nonzero endpoint, matching hubport, and exact endpoint or the
 * requested wildcard0. Cancel then discard-through(cutoff). Reload count: zero
 * clears all392 bytes; nonzero clears only port/descriptor WORDs, preserving
 * future-generation packets and endpoint identity. Give current mutex after
 * scanning. No direct wake, endpoint-direction validation or creation. */
void medius_out_unregister(void *hubport,unsigned int endpoint)
{
    unsigned int requested_endpoint = endpoint & 0xffU;
    RtosQueue *mutex = MEDIUS_OUT_MUTEX;
    if (mutex == 0)
        return;
    unsigned int generation = 0xffffffffU;
    if (requested_endpoint != 0) {
        generation = medius_host_get_control_generation();
        mutex = MEDIUS_OUT_MUTEX;
    }
    xQueueSemaphoreTake(mutex,0xffffffffU);
    for (unsigned int index = 0; index < 10; ++index) {
        MediusOutRelayState *state = &MEDIUS_OUT_RELAYS[index];
        volatile MediusOutRelayState *relay = state;
        unsigned int current_endpoint = relay->endpoint;
        if (current_endpoint == 0 || relay->hubport != hubport)
            continue;
        if (current_endpoint != requested_endpoint && requested_endpoint != 0)
            continue;
        medius_out_cancel(state);
        medius_out_discard_through(state,generation);
        if (relay->count == 0) {
            memset(state,0,392);
        } else {
            relay->hubport = 0;
            relay->descriptor = 0;
        }
    }
    xQueueGenericSend(MEDIUS_OUT_MUTEX,(void *)0,0,0);
}

/* Native entry: 0x4200bfc8. */
/* Original function-byte SHA-256:
 * d442464e53ebc222e8606a4ef7f7ed372cad969768e20883d36a340974970296. */
/* Consume low16(length). Below2 returns without payload reads. Otherwise read
 * sequence byte1 before endpoint byte0 and enqueue payload+2 with low16 length-2.
 * No null/extent validation, timestamp interpretation or return-status check. */
void medius_out_handle_short(unsigned char *payload,unsigned int length)
{
    unsigned int size = length & 0xffffU;
    if (size < 2)
        return;
    const volatile unsigned char *header = payload;
    unsigned int sequence = header[1];
    unsigned int endpoint = header[0];
    medius_out_enqueue(endpoint,sequence,payload + 2,(size - 2U) & 0xffffU);
}

/* Native entry: 0x4200bfe4. */
/* Original function-byte SHA-256:
 * 8a07d4469797e3b3efcf8e22faf2eb247695ce64a316b09018f3c460a74b6a07. */
/* Consume low16(length). Below8 returns without payload reads. Otherwise read
 * sequence byte5 before endpoint byte0 and enqueue payload+8 with low16 length-8.
 * Prefix bytes1..4 and6..7 are ignored here. No timestamp conversion, null/extent
 * validation or return-status check occurs in this message0x1d wrapper. */
void medius_out_handle_timed(unsigned char *payload,unsigned int length)
{
    unsigned int size = length & 0xffffU;
    if (size < 8)
        return;
    const volatile unsigned char *header = payload;
    unsigned int sequence = header[5];
    unsigned int endpoint = header[0];
    medius_out_enqueue(endpoint,sequence,payload + 8,(size - 8U) & 0xffffU);
}

/* Native entry: 0x4200c000. */
/* Original function-byte SHA-256:
 * 9fb1e19b5bd952afb7fb61dd453b1e2a0fa5aca7aecac5f95652496f25223204. */
/* Require low16 length>=2 and sampled mutex nonnull; take indefinitely and
 * ignore result. Read endpoint byte0 then sequence byte1. Endpoint0 or no match
 * among10 records replies {endpoint,sequence,2}. First matching record with
 * count!=0 or active!=0 suppresses the reply and stops lookup. Idle match with
 * equal last_ack replies status0. Unequal sequence writes last_ack, rereads
 * payload endpoint and replies status2. ACK uses HALF prefix then status BYTE;
 * send to ACK queue and wake, wait0/back0, ignoring results. Always give reread
 * mutex afterwards. No null payload check, retries, cancellation or local wait. */
void medius_out_handle_status_query(unsigned char *payload,unsigned short length)
{
    if (length < 2)
        return;
    RtosQueue *mutex = MEDIUS_OUT_MUTEX;
    if (mutex == 0)
        return;
    xQueueSemaphoreTake(mutex,0xffffffffU);
    const volatile unsigned char *request = payload;
    unsigned int endpoint = request[0];
    unsigned int sequence = request[1];
    unsigned int status = 2;
    if (endpoint != 0) {
        for (unsigned int index = 0; index < 10; ++index) {
            volatile MediusOutRelayState *relay = &MEDIUS_OUT_RELAYS[index];
            if (relay->endpoint != endpoint)
                continue;
            if (relay->count != 0 || relay->active != 0)
                goto release_mutex;
            if (relay->last_ack == sequence) {
                status = 0;
            } else {
                relay->last_ack = (unsigned char)sequence;
                endpoint = request[0];
            }
            break;
        }
    }
    MediusOutAckStorage ack;
    ack.endpoint_sequence = (unsigned short)(endpoint | (sequence << 8));
    ack.status = (unsigned char)status;
    xQueueGenericSend(MEDIUS_OUT_ACK_QUEUE,&ack,0,0);
    xQueueGenericSend(MEDIUS_OUT_WAKE,(void *)0,0,0);
release_mutex:
    xQueueGenericSend(MEDIUS_OUT_MUTEX,(void *)0,0,0);
}

/* Native entry: 0x4200c0c4. */
/* Original function-byte SHA-256:
 * fea3c8a01217b3337e4006b2a207558b7d036d5e29aee66e6fd0c3e633063510. */
/* Null mutex returns0. Otherwise take its sampled handle with FFFFFFFF,
 * ignoring result, and scan all10 records without endpoint/port/activity filters.
 * Read each count once. For nonempty records read head once; a byte cursor
 * visits through low8(head+count-1), indexing packet slots with cursor&3.
 * First unsigned generation<=cutoff returns1 after giving the reread mutex;
 * otherwise give that mutex and return0. No table writes, ACK, wake, bounds
 * checks or wrap-aware generation comparison; lock ownership is assumed. */
unsigned char medius_out_has_queued_through(unsigned int generation)
{
    RtosQueue *mutex = MEDIUS_OUT_MUTEX;
    if (mutex == 0)
        return 0;
    xQueueSemaphoreTake(mutex,0xffffffffU);
    unsigned char found = 0;
    for (unsigned int index = 0; index < 10; ++index) {
        const volatile MediusOutRelayState *relay = &MEDIUS_OUT_RELAYS[index];
        unsigned int count = relay->count;
        if (count == 0)
            continue;
        unsigned int cursor = relay->head;
        unsigned int last = (cursor + count - 1U) & 0xffU;
        for (;;) {
            unsigned int queued_generation = relay->packets[cursor & 3U].generation;
            if (queued_generation <= generation) {
                found = 1;
                goto release_mutex;
            }
            if (cursor == last)
                break;
            cursor = (cursor + 1U) & 0xffU;
        }
    }
release_mutex:
    xQueueGenericSend(MEDIUS_OUT_MUTEX,(void *)0,0,0);
    return found;
}

/* Native entry: 0x4200c150. */
/* Original function-byte SHA-256:
 * b39f93bbdeeeff3c538ffe9c8f202b6c08f850b6244b51d63fa36d01cfed53e9. */
/* If the sampled OUT mutex is nonnull, delegate pause/reconcile with full32
 * argument1. Null mutex returns without changing pause, queues or notifications.
 * The delegated implementation is a separate native entry. */
void medius_out_pause_discard(void)
{
    if (MEDIUS_OUT_MUTEX != 0)
        medius_out_pause_and_reconcile(1);
}

/* Native entry: 0x4200c164. */
/* Original function-byte SHA-256:
 * 9a8ad874048a142025e7bc705c87099cc327c2ddc070cec45edb09f88b80f19e. */
/* If the sampled OUT mutex is nonnull, delegate pause/reconcile with argument0.
 * Null mutex returns without effects. The wrapper supplies no independent lock,
 * wait, queued-generation discard or wake. */
void medius_out_pause_preserve(void)
{
    if (MEDIUS_OUT_MUTEX != 0)
        medius_out_pause_and_reconcile(0);
}

/* Native entry: 0x4200c178. */
/* Original function-byte SHA-256:
 * 8f4f8476f216a32cf7cd8c5e72291ea62518799a6fa6181cea7ed212c19e60d1. */
/* Null OUT mutex returns. Otherwise sample wake handle BEFORE MEMW/store of
 * pause byte0, then send that saved handle a NULL item with wait0/back0, ignoring
 * result. No mutex take, record reset, handle resampling or creation. */
void medius_out_resume(void)
{
    if (MEDIUS_OUT_MUTEX == 0)
        return;
    RtosQueue *wake = MEDIUS_OUT_WAKE;
    memw();
    MEDIUS_OUT_PAUSE = 0;
    xQueueGenericSend(wake,(void *)0,0,0);
}

/* Native entry: 0x4200c1a0. */
/* Original function-byte SHA-256:
 * 87710762a092c470abdd9ffe3f2ffbf7321f20b44a92afab40a07b43c3e81e52. */
/* Null mutex returns. Otherwise take sampled mutex with FFFFFFFF, ignoring
 * result, and clear each of10 records' URB toggle byte+24 then halted byte+371,
 * including unused/active records. Sample mutex again BEFORE MEMW/store pause0,
 * give that sampled mutex, then give freshly loaded wake. Both sends wait0/back0
 * and ignore results. No accounting, queued-packet, pending or other URB reset. */
void medius_out_reset_toggles_resume(void)
{
    RtosQueue *mutex = MEDIUS_OUT_MUTEX;
    if (mutex == 0)
        return;
    xQueueSemaphoreTake(mutex,0xffffffffU);
    for (unsigned int index = 0; index < 10; ++index) {
        volatile MediusOutRelayState *relay = &MEDIUS_OUT_RELAYS[index];
        relay->urb.toggle = 0;
        relay->halted = 0;
    }
    mutex = MEDIUS_OUT_MUTEX;
    memw();
    MEDIUS_OUT_PAUSE = 0;
    xQueueGenericSend(mutex,(void *)0,0,0);
    xQueueGenericSend(MEDIUS_OUT_WAKE,(void *)0,0,0);
}

/* Native entry: 0x4200c1f8. */
/* Original function-byte SHA-256:
 * 5ac8578c0213aba3fe673380e202cfa83b79c2dd758d0d417f04be61153ffe08. */
/* Truncate all arguments to bytes. Null mutex or endpoint128..255 returns.
 * Take sampled mutex indefinitely, ignoring result. Nonzero endpoint scans10
 * records for first exact match and writes raw halted byte. Only halted!=1
 * and reset_toggle!=0 clears its URB toggle; noncanonical halted values remain
 * significant. Endpoint0 and a missing match still give reread mutex then wake,
 * wait0/back0, ignoring results. No transfer cancellation or other field update. */
void medius_out_set_halted(unsigned char endpoint,unsigned char halted,
    unsigned char reset_toggle)
{
    RtosQueue *mutex = MEDIUS_OUT_MUTEX;
    if (mutex == 0 || (signed char)endpoint < 0)
        return;
    xQueueSemaphoreTake(mutex,0xffffffffU);
    if (endpoint != 0) {
        for (unsigned int index = 0; index < 10; ++index) {
            volatile MediusOutRelayState *relay = &MEDIUS_OUT_RELAYS[index];
            if (relay->endpoint == endpoint) {
                relay->halted = halted;
                if (halted != 1 && reset_toggle != 0)
                    relay->urb.toggle = 0;
                break;
            }
        }
    }
    xQueueGenericSend(MEDIUS_OUT_MUTEX,(void *)0,0,0);
    xQueueGenericSend(MEDIUS_OUT_WAKE,(void *)0,0,0);
}

/* Native entry: 0x4200c27c. */
/* Original function-byte SHA-256:
 * 5581709a6d34ed5423489134c11fc6299cad3f26933be36cf0d0fc26b524a149. */
/* Accept only endpoint byte1..127 and nonnull sampled mutex. Take it forever,
 * ignore result and find first exact endpoint among10 records. Missing match
 * gives current mutex and returns without timer/wake. Found match samples mutex
 * BEFORE MEMW/set submission_inhibited1, then gives that saved handle. Sample
 * time, form wrapping(start+3000us), and wait on that original record while active
 * and MEMW/pending0; signed64 now<deadline permits one-tick delay then active
 * reload. Retake current mutex, search anew from record0, cancel/discard through
 * cutoff for the first current match, then MEMW/clear its inhibit byte. Give
 * current mutex and wake even if no second match. Other state may change while
 * unlocked; original and final matching records can differ. No deadline guarantee,
 * result handling, port ownership check or cleanup of an unmatched old record. */
void medius_out_drain_endpoint(unsigned char endpoint,unsigned int generation)
{
    RtosQueue *mutex = MEDIUS_OUT_MUTEX;
    if (mutex == 0 || (signed char)endpoint <= 0)
        return;
    xQueueSemaphoreTake(mutex,0xffffffffU);
    MediusOutRelayState *original = 0;
    for (unsigned int index = 0; index < 10; ++index) {
        if (((volatile MediusOutRelayState *)&MEDIUS_OUT_RELAYS[index])->endpoint == endpoint) {
            original = &MEDIUS_OUT_RELAYS[index];
            break;
        }
    }
    if (original == 0) {
        xQueueGenericSend(MEDIUS_OUT_MUTEX,(void *)0,0,0);
        return;
    }
    volatile MediusOutRelayState *relay = original;
    mutex = MEDIUS_OUT_MUTEX;
    memw();
    relay->submission_inhibited = 1;
    xQueueGenericSend(mutex,(void *)0,0,0);
    unsigned long long deadline = (unsigned long long)esp_timer_get_time() + 3000U;
    unsigned int active = relay->active;
    while (active != 0) {
        memw();
        if (relay->completion_pending != 0)
            break;
        long long now = esp_timer_get_time();
        if (now >= (long long)deadline)
            break;
        vTaskDelay(1);
        active = relay->active;
    }
    xQueueSemaphoreTake(MEDIUS_OUT_MUTEX,0xffffffffU);
    for (unsigned int index = 0; index < 10; ++index) {
        MediusOutRelayState *state = &MEDIUS_OUT_RELAYS[index];
        volatile MediusOutRelayState *current = state;
        if (current->endpoint == endpoint) {
            medius_out_cancel(state);
            medius_out_discard_through(state,generation);
            memw();
            current->submission_inhibited = 0;
            break;
        }
    }
    xQueueGenericSend(MEDIUS_OUT_MUTEX,(void *)0,0,0);
    xQueueGenericSend(MEDIUS_OUT_WAKE,(void *)0,0,0);
}

/* Native entry: 0x4200c3d0. */
/* Original function-byte SHA-256:
 * d458a5e585bcc678a67fe2042d586588b912ea1cc489a81f6666197a3eef5317. */
/* Load wake handle once. A nonnull handle receives NULL/wait0/back0; ignore
 * send result. No mutex, pause/state check, worker creation or retries. */
void medius_out_wake_worker(void)
{
    RtosQueue *wake = MEDIUS_OUT_WAKE;
    if (wake != 0)
        xQueueGenericSend(wake,(void *)0,0,0);
}
