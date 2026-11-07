/* Medius v3.4.7 host — usb/vendor.c.
 * Recovered C and native assembly, grouped for source navigation.
 * Original entry addresses, firmware-byte hashes and function comments follow.
 */

#include "../include/types.h"

/* Source reconstruction utilities for the repeated credit scan in native
 * 4038a2b4. No additional native entry. Caller holds the credit lock.
 * Preserve separate LOW/HIGH reads and conditional reference/duration LOW
 * reads; unsigned arithmetic supplies the native modulo64 additions/subtracts. */
static int vendor_credit_allows(volatile MediusVendorEndpointState *state,unsigned long long now)
{
    unsigned int retained = state->retained_credit_valid;
    unsigned int sequence = state->report_sequence;
    unsigned int count = 0,scan = 8;
    if (retained != 0) {
        unsigned int base = state->credit_sequence_base;
        scan = (sequence-base) & 255U;
        count = state->retained_credit_count;
        if (scan > 8) scan = 8;
        if (sequence == base) goto boost_limit;
    }
    unsigned int stop = (sequence-scan) & 255U;
    unsigned int protection = state->history_protection_active; /* Cached once. */
    do {
        const volatile ClockWords *entry = (const volatile void *)&state->report_history[sequence & 7U];
        unsigned int low = entry->low;
        unsigned int high = entry->high;
        unsigned int protected_entry = 0;
        if (protection != 0) {
            unsigned int base = state->protection_base_sequence;
            protected_entry = base != sequence && ((sequence-base) & 255U) <= 8U;
        }
        if ((low | high) != 0) {
            if (protected_entry) ++count;
            else {
                unsigned int window = (unsigned int)state->history_window_us;
                const volatile ClockWords *reference = (const volatile void *)&state->credit_reference_us;
                unsigned int reference_high = reference->high;
                unsigned int sum_low = low+window;
                unsigned int sum_high = high+((int)window < 0 ? 0xffffffffU : 0U)+(sum_low < window);
                if ((int)reference_high < (int)sum_high ||
                    (reference_high == sum_high && reference->low < sum_low)) ++count;
            }
        }
        sequence = (sequence-1U) & 255U;
    } while (sequence != stop);
boost_limit:;
    const volatile ClockWords *boost = (const volatile void *)&state->boost_started_us;
    unsigned int start_low = boost->low;
    unsigned int start_high = boost->high;
    unsigned int limit = state->credit_limit;
    if (count > 255U) count = 255U;
    if ((start_low | start_high) != 0) {
        unsigned int now_low = (unsigned int)now;
        unsigned int elapsed_low = now_low-start_low;
        unsigned int elapsed_high = (unsigned int)(now >> 32)-start_high-(now_low < start_low);
        const volatile ClockWords *duration = (const volatile void *)&state->boost_duration_us;
        unsigned int duration_high = duration->high;
        if ((int)elapsed_high < (int)duration_high ||
            (elapsed_high == duration_high && elapsed_low < duration->low)) ++limit;
    }
    return count < limit;
}


/* Native entry: 0x4038a2b4. */
/* Original function-byte SHA-256:
 * adff12fb1053f27d549a340701f0ba63c97bae1fe10d0cc646e8fa378fc1928f. */
/* Cache endpoint and its low-nibble DMA slot before any timer/lock call. OUT
 * skips credit processing. IN samples the timer before querying ISR context
 * and taking the vendor credit lock; the source utility below represents the
 * complete native history/retained-credit/boost scan, including separate word
 * reads. Publish credit_blocked as 0/1. Denial clears armed, unlocks and returns
 * 0 without submission. Credit acceptance is not a submission-success result.
 *
 * After unlocking, cache record.hubport and state.descriptor; NULL or fenced
 * submission_inhibited returns -1. Inhibit89 and global pause are not checked here. Cache
 * length, clear setup/timeout, then cache type and write the embedded URB's
 * port, descriptor, cached DMA buffer, length, callback and context. For type
 * other than 2, read port speed then descriptor interval: speed<3 uses interval
 * times 1000; otherwise use 125<<((interval-1)&31), including native shift wrap.
 * Bulk retains its old interval. Other URB fields, including scheduling flags
 * and actual/error, remain untouched. Submit outside the lock and return its
 * result unchanged. No descriptor length, connection, capacity or pointer-life
 * check. Caller owns admission and armed state on other errors. */
int medius_vendor_rearm(MediusVendorInterface *record, MediusVendorEndpointState *endpoint)
{
    volatile MediusVendorEndpointState *state = endpoint;
    unsigned int address = state->endpoint;
    unsigned int dma_slot = address & 15U;
    if ((address & 128U) != 0) {
        unsigned long long now = (unsigned long long)esp_timer_get_time();
        xPortInIsrContext();
        xPortEnterCriticalTimeout(&MEDIUS_VENDOR_CREDIT_LOCK, -1);
        int allowed = vendor_credit_allows(state, now);
        memw(); state->credit_blocked = !allowed;
        if (!allowed) {
            memw(); state->armed = 0;
            xPortInIsrContext();
            vPortExitCritical(&MEDIUS_VENDOR_CREDIT_LOCK);
            return 0;
        }
        xPortInIsrContext();
        vPortExitCritical(&MEDIUS_VENDOR_CREDIT_LOCK);
    }
    MediusHostHubPortPrefix *port = ((volatile MediusVendorInterface *)record)->hubport;
    if (port == NULL) return -1;
    unsigned char *descriptor = state->descriptor;
    if (descriptor == NULL) return -1;
    memw(); if (state->submission_inhibited != 0) return -1;
    unsigned int length = state->transfer_length;
    state->urb.setup = NULL;
    state->urb.timeout = 0;
    unsigned int type = state->transfer_type;
    state->urb.hubport = port;
    state->urb.endpoint = descriptor;
    state->urb.buffer = (void *)MEDIUS_VENDOR_TRANSFER_SLOTS[dma_slot];
    state->urb.remaining = length;
    state->urb.complete = medius_vendor_complete;
    state->urb.context = endpoint;
    if (type != 2) {
        unsigned int speed = ((const volatile MediusHostHubPortPrefix *)port)->speed;
        unsigned int interval = ((const volatile unsigned char *)descriptor)[6];
        state->urb.interval_us = speed < 3 ? interval * 1000U : 125U << ((interval - 1U) & 31U);
    }
    return usbh_submit_urb((MediusHostUrb *)&state->urb);
}

/* Native entry: 0x4038a478. */
/* Original function-byte SHA-256:
 * e304b56e1a76f0d4b5d57feed0ef0f5227455fe8f491943bfc4a46324b73577a. */
/* Append one timestamp under the vendor credit lock. Query ISR context before
 * entering and before leaving. Sample the timer inside the lock, then read and
 * increment report_sequence modulo 256. Zero time is represented by 1; all
 * other 64-bit bit patterns are retained. Publish the sequence byte, then the
 * history entry's low and high words in that order. Return the new byte widened
 * to unsigned int. No generation, endpoint, pointer or ownership validation. */
unsigned int medius_vendor_history_append(MediusVendorEndpointState *endpoint)
{
    volatile MediusVendorEndpointState *state = endpoint;
    xPortInIsrContext();
    xPortEnterCriticalTimeout(&MEDIUS_VENDOR_CREDIT_LOCK, -1);
    unsigned long long timestamp = (unsigned long long)esp_timer_get_time();
    unsigned int sequence = (state->report_sequence + 1U) & 255U;
    if (timestamp == 0) timestamp = 1;
    state->report_sequence = (unsigned char)sequence;
    volatile ClockWords *history = (volatile void *)&state->report_history[sequence & 7U];
    history->low = (unsigned int)timestamp;
    history->high = (unsigned int)(timestamp >> 32);
    xPortInIsrContext();
    vPortExitCritical(&MEDIUS_VENDOR_CREDIT_LOCK);
    return sequence;
}

/* Native entry: 0x4038a4bc. */
/* Original function-byte SHA-256:
 * ddec978d4f2a504916e8e74e718f6f2201f47eadf2adc184201a350a5d3ae9a3. */
/* Under the vendor credit lock, clear history[sequence & 7] only when the
 * current report sequence is fewer than eight steps ahead modulo 256. Ignore
 * input sequence bits above bit 7. Clear low then high word; preserve sequence
 * and all other entries. ISR queries bracket the lock on every path. There is
 * no timestamp/generation check or pointer validation. */
void medius_vendor_history_drop(MediusVendorEndpointState *endpoint, unsigned int sequence)
{
    volatile MediusVendorEndpointState *state = endpoint;
    xPortInIsrContext();
    xPortEnterCriticalTimeout(&MEDIUS_VENDOR_CREDIT_LOCK, -1);
    unsigned int sent = sequence & 255U;
    if (((state->report_sequence - sent) & 255U) < 8U) {
        volatile ClockWords *history = (volatile void *)&state->report_history[sent & 7U];
        history->low = 0;
        history->high = 0;
    }
    xPortInIsrContext();
    vPortExitCritical(&MEDIUS_VENDOR_CREDIT_LOCK);
}

/* Native entry: 0x4038a4f8. */
/* Original function-byte SHA-256:
 * e66b7c1294707b29b5936e997d320fef248b0d8210a2ff17decc9dab3c3b8bb7. */
/* Vendor URB callback; context is a live endpoint state. Cache interface_slot,
 * fence/set activity, then sample that interface's active byte. An inactive
 * interface only clears activity, preserving armed. Read submission_inhibited then, only
 * when clear, callback_rearm_inhibited. An inhibited negative result clears armed/activity
 * without reading global pause. Other paths test global pause; nonzero stops
 * likewise. An uninhibited -13 also deactivates the cached interface. An
 * uninhibited -8 clears armed, marks stall_pending, samples ack, then sequence,
 * then timer; snapshots endpoint/type together, publishes special_time_us and
 * rereads special_sequence. Build a zero-padded special report, flag3 for bulk
 * or flag4 otherwise, length1/ack, and ISR-enqueue. Failure sets special_retry;
 * success leaves its previous value. Clear activity before any wake yield.
 *
 * Nonnegative results store the frame low16, sample report time, snapshot
 * endpoint/type together, and append history with a separate timer sample.
 * Length clips to 64. Fresh type/length set flags: bulk uses clipped mismatch,
 * nonbulk zero uses 2, other nonbulk uses 0. Positive copies use a fresh DMA
 * endpoint; queue choice reads type again after copy. Zero bulk goes straight
 * to its queue; zero nonbulk goes through the interrupt path. Report padding
 * and unused normal payload retain stack bytes, as native does.
 *
 * Interrupt path tries direct UART only when queue depth and forwarding inhibit
 * are both zero. Write the shared packet as a word plus halfword header, copy
 * payload, then ISR-send opcode 0x10/sequence-low8. Nonzero accepts; zero falls
 * back to the queue chosen by a fresh type read. Queue failure reads type again:
 * bulk copies all 80 report bytes into a fresh endpoint cache slot, clears armed,
 * sets pending and clears activity before optional yield; other types drop the
 * fresh stack sequence's history. Normal wake yield precedes optional rearm.
 * Inhibited completions never rearm. Other negative results go directly to
 * rearm. Any negative rearm result clears armed, including -6; always clear
 * activity afterward. No local endpoint/interface bounds or lifetime checks. */
void medius_vendor_complete(void *context, int result)
{
    MediusVendorEndpointState *endpoint = context;
    volatile MediusVendorEndpointState *state = endpoint;
    unsigned int slot = state->interface_slot;
    volatile MediusVendorInterface *record = (volatile void *)
        ((unsigned int)MEDIUS_VENDOR_INTERFACES + slot * 2504U);
    memw(); state->activity = 1;
    memw(); if (record->active == 0) { memw(); state->activity = 0; return; }
    int inhibited = 0;
    memw();
    if (state->submission_inhibited != 0) inhibited = 1;
    else { memw(); if (state->callback_rearm_inhibited != 0) inhibited = 1; }
    if (inhibited && result < 0) goto stop;
    memw(); if (MEDIUS_VENDOR_GLOBAL_PAUSE != 0) goto stop;
    volatile MediusVendorReport report;
    int woken;
    RtosQueue *queue;
    if (!inhibited) {
        if (result == -13) {
            memw(); state->armed = 0;
            memw(); record->active = 0;
            memw(); state->activity = 0;
            return;
        }
        if (result == -8) {
            memw(); state->armed = 0;
            memw(); state->stall_pending = 1;
            unsigned char ack = medius_ordered_get_last_ack();
            state->special_sequence = state->report_sequence;
            unsigned int timestamp = (unsigned int)esp_timer_get_time();
            unsigned short endpoint_type = *(volatile unsigned short *)&state->endpoint;
            state->special_time_us = timestamp;
            unsigned int sequence = state->special_sequence;
            for (unsigned int i = 3; i < 80; ++i) ((volatile unsigned char *)&report)[i] = 0;
            report.endpoint_type = endpoint_type;
            queue = (endpoint_type >> 8) == 2 ? MEDIUS_VENDOR_BULK_QUEUE : MEDIUS_VENDOR_INTERRUPT_QUEUE;
            report.timestamp_us = timestamp;
            report.length = 1;
            report.flags = (endpoint_type >> 8) == 2 ? 3 : 4;
            report.sequence = (unsigned short)sequence;
            report.payload[0] = ack;
            woken = 0;
            if (xQueueGenericSendFromISR(queue, (const void *)&report, &woken, 0) != 1) {
                memw(); state->special_retry = 1;
            }
            memw(); state->activity = 0;
            if (woken != 0) _frxt_setup_switch();
            return;
        }
        if (result < 0) goto rearm;
    }
    unsigned int frame = medius_host_get_frame();
    memw(); state->last_report_frame = (unsigned short)frame;
    unsigned int timestamp = (unsigned int)esp_timer_get_time();
    report.endpoint_type = *(volatile unsigned short *)&state->endpoint;
    report.timestamp_us = timestamp;
    report.sequence = (unsigned short)medius_vendor_history_append(endpoint);
    unsigned int type = state->transfer_type;
    unsigned int length = (unsigned int)result > 64U ? 64U : (unsigned int)result;
    report.length = (unsigned short)length;
    if (result == 0) {
        if (type != 2) { report.flags = 2; woken = 0; goto interrupt_path; }
        report.flags = state->transfer_length != 0;
        woken = 0;
        goto bulk_queue;
    }
    unsigned char flags = 0;
    if (type == 2) flags = state->transfer_length != length;
    unsigned int dma_slot = state->endpoint & 15U;
    report.flags = flags;
    medius_copy_bytes((void *)report.payload, (void *)MEDIUS_VENDOR_TRANSFER_SLOTS[dma_slot], length);
    type = state->transfer_type;
    woken = 0;
    if (type == 2) goto bulk_queue;
interrupt_path:
    woken = 0;
    if (uxQueueMessagesWaitingFromISR(MEDIUS_VENDOR_INTERRUPT_QUEUE) == 0 &&
            medius_host_get_forwarding_inhibit() == 0) {
        unsigned int time = report.timestamp_us;
        unsigned int address = report.endpoint;
        unsigned int packet_flags = report.flags;
        MEDIUS_VENDOR_DIRECT_PREFIX = address | (time << 8);
        MEDIUS_VENDOR_DIRECT_TAIL = (unsigned short)((time >> 24) | (packet_flags << 8));
        medius_copy_bytes((void *)(MEDIUS_VENDOR_DIRECT_PACKET + 6), (void *)report.payload, report.length);
        unsigned int direct_length = report.length;
        unsigned char direct_sequence = report.sequence_low;
        if (medius_link_send_from_isr(MEDIUS_VENDOR_TX_SCRATCH, 0x10,
                direct_sequence, (void *)MEDIUS_VENDOR_DIRECT_PACKET,
                (direct_length + 6U) & 65535U, &woken) != 0) goto delivered;
    }
    type = state->transfer_type;
    if (type != 2) { queue = MEDIUS_VENDOR_INTERRUPT_QUEUE; goto send_queue; }
bulk_queue:
    queue = MEDIUS_VENDOR_BULK_QUEUE;
send_queue:
    if (xQueueGenericSendFromISR(queue, (const void *)&report, &woken, 0) != 1) {
        if (state->transfer_type == 2) {
            unsigned int cache_slot = state->endpoint & 15U;
            memcpy((void *)&MEDIUS_VENDOR_REPORT_CACHE[cache_slot], (const void *)&report, 80);
            memw(); state->armed = 0;
            memw(); state->queued_report_pending = 1;
            memw(); state->activity = 0;
            if (woken != 0) _frxt_setup_switch();
            return;
        }
        medius_vendor_history_drop(endpoint, report.sequence);
    }
delivered:
    if (woken != 0) _frxt_setup_switch();
    if (inhibited) goto stop;
rearm:
    if (medius_vendor_rearm((MediusVendorInterface *)record, endpoint) < 0) {
        memw(); state->armed = 0;
    }
    memw(); state->activity = 0;
    return;
stop:
    memw(); state->armed = 0;
    memw(); state->activity = 0;
}

/* Native entry: 0x4038a814. */
/* Original function-byte SHA-256:
 * de09a1a81033257f4a214a9201832673844261a65656c0fad4d19272845f7704. */
/* Interrupt-report worker: priority14, stack3072 bytes, core0. Ignore argument.
 * Forever peek with 10 ticks; any nonzero result is treated as a report. With
 * forwarding enabled, delegate formatting through this task's dedicated
 * 72-byte scratch. Otherwise normal reports drop history on the first matching
 * endpoint of an active interface; special flag2/bulk or flag4/nonbulk skips
 * that drop. Search all 12 interfaces without allocation-mask checks, with raw
 * cached endpoint counts. Always consume using the CURRENT interrupt queue,
 * nonblocking, after processing a peek; ignore receive result.
 *
 * After every iteration, sample timer low32 and ack once. Before each interface
 * call recovery_gate; nonzero abandons this scan. For an active interface, cache
 * its endpoint count. Each endpoint tests fenced stall_pending, submission_inhibited and
 * special_retry in order. Emit if retry is nonzero or unsigned32(scan_time-
 * special_time_us)>99999. The scan time stays cached across endpoints. Each
 * emission samples a fresh timer, snapshots endpoint/type together, stores
 * special_time_us and reads saved special_sequence. Zero bytes3..79, select
 * queue from the snapshotted type, build flag3/bulk or flag4/nonbulk, length1,
 * scan-sampled ack, and send without waiting. Result1 clears special_retry;
 * failure retains it. Refresh count only after an attempted send. No cap at12,
 * lock, watchdog feed, dedicated timer instance or exact wake-time guarantee. */
void medius_task_vintr(void *unused)
{
    (void)unused;
    MediusVendorReport received;
    volatile MediusVendorReport special;
    for (;;) {
        if (xQueuePeek(MEDIUS_VENDOR_INTERRUPT_QUEUE, &received, 10) != 0) {
            if (medius_host_get_forwarding_inhibit() == 0)
                medius_vendor_forward_report(&received, (unsigned char *)MEDIUS_VENDOR_INTERRUPT_PACKET);
            else {
                unsigned int special_flag = received.transfer_type == 2 ? 2U : 4U;
                if ((received.flags & special_flag) == 0) {
                    unsigned int wanted_endpoint = received.endpoint;
                    for (unsigned int slot = 0; slot < 12; ++slot) {
                        volatile MediusVendorInterface *record = &MEDIUS_VENDOR_INTERFACES[slot];
                        memw(); if (record->active == 0) continue;
                        unsigned int count = record->endpoint_count;
                        for (unsigned int index = 0; index < count; ++index) {
                            MediusVendorEndpointState *state = (void *)
                                ((unsigned int)record + 8U + index * 208U);
                            if (((volatile MediusVendorEndpointState *)state)->endpoint == wanted_endpoint) {
                                medius_vendor_history_drop(state, received.sequence);
                                goto consume;
                            }
                        }
                    }
                }
            }
consume:
            xQueueReceive(MEDIUS_VENDOR_INTERRUPT_QUEUE, &received, 0);
        }
        unsigned int scan_time = (unsigned int)esp_timer_get_time();
        unsigned char ack = medius_ordered_get_last_ack();
        for (unsigned int slot = 0; slot < 12; ++slot) {
            if (medius_host_recovery_gate() != 0) break;
            volatile MediusVendorInterface *record = &MEDIUS_VENDOR_INTERFACES[slot];
            memw(); if (record->active == 0) continue;
            unsigned int count = record->endpoint_count;
            if (count == 0) continue;
            unsigned int index = 0;
            do {
                volatile MediusVendorEndpointState *state = (volatile void *)
                    ((unsigned int)record + 8U + index * 208U);
                memw(); if (state->stall_pending == 0) goto next_endpoint;
                memw(); if (state->submission_inhibited != 0) goto next_endpoint;
                memw();
                if (state->special_retry != 0 || scan_time - state->special_time_us > 99999U) {
                    unsigned int timestamp = (unsigned int)esp_timer_get_time();
                    unsigned short endpoint_type = *(volatile unsigned short *)&state->endpoint;
                    state->special_time_us = timestamp;
                    unsigned int sequence = state->special_sequence;
                    for (unsigned int i = 3; i < 80; ++i) ((volatile unsigned char *)&special)[i] = 0;
                    RtosQueue *queue = (endpoint_type >> 8) == 2 ? MEDIUS_VENDOR_BULK_QUEUE : MEDIUS_VENDOR_INTERRUPT_QUEUE;
                    special.endpoint_type = endpoint_type;
                    special.flags = (endpoint_type >> 8) == 2 ? 3 : 4;
                    special.timestamp_us = timestamp;
                    special.length = 1;
                    special.sequence = (unsigned short)sequence;
                    special.payload[0] = ack;
                    if (xQueueGenericSend(queue, (const void *)&special, 0, 0) == 1) {
                        memw(); state->special_retry = 0;
                    }
                    count = record->endpoint_count;
                }
next_endpoint:
                ++index;
            } while ((index & 255U) < count);
        }
    }
}

/* Native entry: 0x4038aa0c. */
/* Original function-byte SHA-256:
 * ededf955841455a4bc17da9f238e986be34b69b65ac9574e7eadf6545ce84659. */
/* Apply credits to IN endpoints in all12 active vendor records, ignoring the
 * allocation mask. Counts are raw bytes, not capped12; OUT skips retain the
 * cached count, IN processing refreshes it. Cache endpoint BEFORE parsing.
 * Length truncates16, initial phase truncates8. Zero length avoids payload
 * access; otherwise cache count byte once and select first full endpoint match
 * among complete four-byte records. Lock after selection and read sequence/load
 * THEN. Missing records clear retained valid/base/count, preserve progress and
 * history, and publish reference now-or1 LOW/HIGH.
 *
 * A match publishes progress=(sequence-load)mod256, valid/base/count and reference.
 * Initial open phase plus type3/non-NULL descriptor/interval<2 and positive signed8
 * progress delta grows boost first. Growth uses modulo64 signed age comparisons,
 * reset100000 after zero start or age>duration+999999, otherwise double signed
 * duration<1500000 or clamp3000000. Same epoch does not grow. Fast growth reads
 * duration HIGH/LOW and writes LOW/HIGH. Flag bit0 independently retests type and
 * descriptor and grows with LOW/HIGH reads, HIGH/LOW writes. The special now0,
 * old-start1 fast path stores reference LOW before base/count and HIGH afterward,
 * and its flag path reuses the earlier descriptor without retesting type.
 *
 * Only fenced blocked&&!armed computes occupancy. The common source utility
 * retains cached packet load/reference, live valid/sequence/base, cached protection,
 * separate history words, signed window arithmetic, saturate255 and limit+boost
 * up to256. Acceptance clears blocked and sets armed under lock. Unlock, set
 * activity, then recheck active/stall/flag89/flag88/pending/globalpause/port/connected
 * in native order. Failed gates clear armed. Fast interrupt endpoints may grow
 * again under a second lock if phase opens OR the frame helper says next; neither
 * timing condition is required for rearm itself. Any negative rearm result clears
 * armed, including-6. Always clear activity after that branch. No local bounds,
 * lifetime or physical timing guarantee. Utility sequences are defined in types.h. */
void medius_vendor_apply_credit_records(unsigned char *payload, int length,
    long long now_us, int initial_phase_open)
{
    unsigned int bounded_length = (unsigned int)length & 65535U;
    unsigned int initial = (unsigned int)initial_phase_open & 255U;
    unsigned long long now = (unsigned long long)now_us;
    unsigned long long reference = now == 0 ? 1 : now;
    for (unsigned int slot = 0; slot < 12; ++slot) {
        volatile MediusVendorInterface *interface = &MEDIUS_VENDOR_INTERFACES[slot];
        memw(); if (interface->active == 0) continue;
        unsigned int count = interface->endpoint_count;
        if (count == 0) continue;
        unsigned int index = 0;
        do {
            volatile MediusVendorEndpointState *state = (volatile void *)
                ((unsigned int)interface + 8U + index * 208U);
            unsigned int endpoint = state->endpoint;
            if ((endpoint & 128U) == 0) goto next_endpoint;
            const volatile CreditRecord *record = NULL;
            if (bounded_length != 0) {
                unsigned int records = ((const volatile unsigned char *)payload)[0];
                record = medius_credit_find_record(payload, (int)bounded_length, records, endpoint);
            }
            volatile MediusCreditState *credit = (volatile void *)&state->report_sequence;
            xPortEnterCriticalTimeout(&MEDIUS_VENDOR_CREDIT_LOCK, -1);
            unsigned int seed = 0;
            volatile ClockWords *reference_words = (volatile void *)&credit->credit_reference_us;
            if (record != NULL) {
                unsigned int sequence = record->sequence;
                seed = record->load;
                unsigned int progress = (sequence - seed) & 255U;
                const volatile unsigned char *cached_descriptor = NULL;
                int special_zero_epoch = 0;
                if (initial != 0 && state->transfer_type == 3) {
                    cached_descriptor = state->descriptor;
                    if (cached_descriptor != NULL && cached_descriptor[6] < 2 &&
                            (signed char)(progress - credit->credit_progress_sequence) > 0) {
                        const volatile ClockWords *start = (const volatile void *)&credit->boost_started_us;
                        unsigned int low = start->low;
                        unsigned int high = start->high;
                        special_zero_epoch = now == 0 && low == 1 && high == 0;
                        if (!special_zero_epoch)
                            medius_credit_grow_from(credit, now, reference, low, high, 1, 0);
                    }
                }
                credit->credit_progress_sequence = (unsigned char)progress;
                credit->retained_credit_valid = 1;
                if (special_zero_epoch) reference_words->low = 1;
                credit->credit_sequence_base = (unsigned char)sequence;
                credit->retained_credit_count = (unsigned char)seed;
                if (!special_zero_epoch) reference_words->low = (unsigned int)reference;
                reference_words->high = (unsigned int)(reference >> 32);
                if ((record->flags & 1U) != 0) {
                    const volatile unsigned char *descriptor = cached_descriptor;
                    if (!special_zero_epoch) descriptor = state->transfer_type == 3 ? state->descriptor : NULL;
                    if (descriptor != NULL && descriptor[6] < 2) medius_credit_grow(credit, now, reference, 1);
                }
            } else {
                credit->retained_credit_valid = 0;
                credit->credit_sequence_base = 0;
                credit->retained_credit_count = 0;
                reference_words->low = (unsigned int)reference;
                reference_words->high = (unsigned int)(reference >> 32);
            }
            memw();
            if (state->credit_blocked != 0) {
                memw();
                if (state->armed == 0 && medius_credit_can_unblock(credit, now, reference, seed, 0)) {
                    memw(); state->credit_blocked = 0;
                    memw(); state->armed = 1;
                    vPortExitCritical(&MEDIUS_VENDOR_CREDIT_LOCK);
                    memw(); state->activity = 1;
                    memw(); if (interface->active == 0) goto cancel_rearm;
                    memw(); if (state->stall_pending != 0) goto cancel_rearm;
                    memw(); if (state->callback_rearm_inhibited != 0) goto cancel_rearm;
                    memw(); if (state->submission_inhibited != 0) goto cancel_rearm;
                    memw(); if (state->queued_report_pending != 0) goto cancel_rearm;
                    memw(); if (MEDIUS_VENDOR_GLOBAL_PAUSE != 0) goto cancel_rearm;
                    const volatile MediusHostHubPortPrefix *port = interface->hubport;
                    if (port == NULL || port->connected == 0) goto cancel_rearm;
                    if (state->transfer_type == 3) {
                        const volatile unsigned char *descriptor = state->descriptor;
                        if (descriptor != NULL && descriptor[6] < 2) {
                            int phase = medius_host_phase_gate_open();
                            if (phase == 0) { memw(); phase = medius_host_frame_is_next(state->last_report_frame); }
                            if (phase != 0) {
                                xPortEnterCriticalTimeout(&MEDIUS_VENDOR_CREDIT_LOCK, -1);
                                medius_credit_grow(credit, now, reference, 1);
                                vPortExitCritical(&MEDIUS_VENDOR_CREDIT_LOCK);
                            }
                        }
                    }
                    if (medius_vendor_rearm((MediusVendorInterface *)interface, (MediusVendorEndpointState *)state) < 0) {
cancel_rearm:
                        memw(); state->armed = 0;
                    }
                    memw(); state->activity = 0;
                    count = interface->endpoint_count;
                    goto next_endpoint;
                }
            }
            vPortExitCritical(&MEDIUS_VENDOR_CREDIT_LOCK);
            count = interface->endpoint_count;
next_endpoint:
            ++index;
        } while ((index & 255U) < count);
    }
}

/* Native entry: 0x4038b064. */
/* Original function-byte SHA-256:
 * c389f4ada05d604b3e090b50c1b8fabf4cda5638c4f563192c44cadc473ae18c. */
/* Snapshot the interface mask once and scan its low12 bits in ascending order.
 * Each selected 2504-byte interface gets a fenced raw active-byte sample. If
 * nonzero,cache endpoint_count once; scan that many 208-byte endpoint records,
 * reading stored transfer_type before endpoint. Exact type3 and endpoint bit7
 * return the SAVED raw active byte,not a boolean/fresh active read. Otherwise0.
 * Count is not capped12: corrupt larger counts walk beyond the declared array.
 * No lock,descriptor dereference,pause/halt/credit test or USB activity check. */
unsigned char medius_vendor_has_interrupt_in(void)
{
    unsigned int mask = MEDIUS_VENDOR_INTERFACE_MASK;
    for (unsigned int slot = 0; slot < 12; ++slot) {
        if ((mask & (1U << slot)) == 0) continue;
        const volatile MediusVendorInterface *interface = &MEDIUS_VENDOR_INTERFACES[slot];
        memw(); unsigned char active = interface->active;
        if (active == 0) continue;
        unsigned int count = interface->endpoint_count;
        if (count == 0) continue;
        for (unsigned int index = 0; index < count; ++index) {
            const volatile MediusVendorEndpointState *endpoint = (const volatile void *)
                ((unsigned int)interface+8U+index*208U);
            if (endpoint->transfer_type == 3 && (endpoint->endpoint & 128U) != 0)
                return active;
        }
    }
    return 0;
}

/* Native entry: 0x4202f3c8. */
/* Original function-byte SHA-256:
 * 56fa8f521648802be20d7f5fdcab8f5a71fd38e48906a96ccf06d568c610d27f. */
/* Claim armed state under the vendor credit lock. Fence and read the raw
 * armed byte, XOR it with 1, and return that byte unchanged. A nonzero result
 * causes a fenced armed=1 store. This is not a boolean conversion: old armed
 * values 2..255 return 3..254 and still store 1. Old armed=1 causes no store.
 * ISR queries bracket the lock. No activity/descriptor/admission check. */
unsigned char medius_vendor_claim_arm(MediusVendorEndpointState *endpoint)
{
    volatile MediusVendorEndpointState *state = endpoint;
    xPortInIsrContext();
    xPortEnterCriticalTimeout(&MEDIUS_VENDOR_CREDIT_LOCK, -1);
    memw();
    unsigned char claimed = state->armed ^ 1U;
    if (claimed != 0) {
        memw();
        state->armed = 1;
    }
    xPortInIsrContext();
    vPortExitCritical(&MEDIUS_VENDOR_CREDIT_LOCK);
    return claimed;
}

/* Native entry: 0x4202f40c. */
/* Original function-byte SHA-256:
 * 03e97897e4f1ce0dc4140700e6652500345296c141c7fc596a48ef03341540ee. */
/* Wait for a scan of all 144 vendor activity bytes to find only zeros. Ignore
 * interface mask, interface active and endpoint counts. At the first busy byte,
 * sample time: return if signed 64-bit now >= the wrapped start+50000 deadline;
 * otherwise delay one RTOS tick and restart at interface 0, endpoint 0. An idle
 * scan returns without checking the deadline again. The deadline is a stop
 * condition, not a guaranteed return time: task scheduling, timer reads and
 * activity changes affect completion. No lock is acquired or state cleared. */
void medius_vendor_wait_activity(void)
{
    unsigned long long deadline = (unsigned long long)esp_timer_get_time() + 50000U;
    for (;;) {
        for (unsigned int slot = 0; slot < 12; ++slot) {
            for (unsigned int index = 0; index < 12; ++index) {
                memw();
                if (MEDIUS_VENDOR_INTERFACES[slot].endpoints[index].activity != 0) {
                    unsigned long long now = (unsigned long long)esp_timer_get_time();
                    if ((long long)now >= (long long)deadline) return;
                    vTaskDelay(1);
                    goto restart_scan;
                }
            }
        }
        return;
restart_scan:;
    }
}

/* Native entry: 0x4202f478. */
/* Original function-byte SHA-256:
 * 7f49d695632c04ed30e824ff4f6df56bac8dd40289289e951bf1737b0497aba4. */
/* Unregister OUT endpoints, clear this record's allocation bit, and zero its
 * 2504 bytes. Cache endpoint_count, but refresh it after each OUT unregister
 * call; IN endpoints retain the cached count. Endpoint 0 is passed through.
 * Cache each endpoint byte before the call and read hubport anew for each OUT.
 * The byte count is not capped at 12. Endpoint walking uses native byte strides.
 *
 * Retain native index arithmetic even for malformed record pointers: subtract
 * table base modulo 32 bits, arithmetic-shift by 3, multiply by the modular
 * inverse of 313, then test only the low byte <12. Clear the bit selected by
 * the result's low five bits. For valid table elements this gives their slot.
 * No NULL, alignment, table-membership, locking or cancellation check is added. */
void medius_vendor_clear_interface(MediusVendorInterface *record)
{
    volatile MediusVendorInterface *live = record;
    unsigned int count = live->endpoint_count;
    unsigned int address = (unsigned int)record + 80U;
    unsigned int index = 0;
    if (count != 0) {
        do {
            unsigned int endpoint = *(volatile unsigned char *)address;
            if ((endpoint & 128U) == 0) {
                medius_out_unregister(live->hubport, endpoint);
                count = live->endpoint_count;
            }
            index = (index + 1U) & 255U;
            address += 208U;
        } while (index < count);
    }
    unsigned int offset = (unsigned int)record - (unsigned int)MEDIUS_VENDOR_INTERFACES;
    unsigned int slot = (unsigned int)((int)offset >> 3) * 0x39409d09U;
    if ((slot & 255U) < 12U)
        MEDIUS_VENDOR_INTERFACE_MASK &= ~(1U << (slot & 31U));
    memset(record, 0, 2504);
}

/* Native entry: 0x4202f4dc. */
/* Original function-byte SHA-256:
 * a83abed110dc60d98133db4a8c73bad37448c0f479b6e9532a50e412774c78cc. */
/* Disconnect the vendor handle at low8(interface_number) without validating
 * port, interface table or index. A NULL handle returns 0 before reading the
 * global mutex. Otherwise sample that mutex once; if present, take it for 600
 * ticks and remember only whether the result equals 1. Failed acquisition still
 * proceeds. Fence/store record.active=0 and run the global activity wait.
 *
 * Kill every descriptor-present endpoint URB, ignoring the return. Refresh the
 * byte endpoint count after kill calls only; no cap at 12. Clear private_data
 * through the port's CURRENT interface table, then clear the cached record.
 * If acquisition succeeded, give the CURRENT global mutex with no wait, even
 * if it changed meanwhile. Return 0 on all normal paths. No report drain/save,
 * cancellation-success guarantee or ownership validation is supplied here. */
int medius_vendor_disconnect(void *hubport, unsigned int interface_number)
{
    volatile MediusHostHubPortPrefix *port = hubport;
    unsigned int slot = interface_number & 255U;
    volatile MediusHostInterfacePrefix *interfaces = port->interfaces;
    MediusVendorInterface *record = interfaces[slot].private_data;
    if (record == NULL) return 0;
    RtosQueue *mutex = MEDIUS_VENDOR_MUTEX;
    int acquired = 0;
    if (mutex != NULL) acquired = xQueueSemaphoreTake(mutex, 600) == 1;
    volatile MediusVendorInterface *live = record;
    memw(); live->active = 0;
    medius_vendor_wait_activity();
    unsigned int count = live->endpoint_count;
    unsigned int index = 0;
    unsigned int address = (unsigned int)record + 8U;
    if (count != 0) {
        do {
            volatile MediusVendorEndpointState *endpoint = (volatile void *)address;
            if (endpoint->descriptor != NULL) {
                usbh_kill_urb((MediusHostUrb *)&endpoint->urb);
                count = live->endpoint_count;
            }
            index = (index + 1U) & 255U;
            address += 208U;
        } while (index < count);
    }
    interfaces = port->interfaces;
    interfaces[slot].private_data = NULL;
    medius_vendor_clear_interface(record);
    if (acquired) xQueueGenericSend(MEDIUS_VENDOR_MUTEX, NULL, 0, 0);
    return 0;
}

/* Native entry: 0x4202f590. */
/* Original function-byte SHA-256:
 * 44dd87c3152bbebc53e09f08a713fdd6025b31e575777090fca2764f6d4b912c. */
/* Queue a partial report using an 80-byte stack record. Sample timer low32,
 * then snapshot endpoint/type together in one halfword. Append history using
 * its own timer sample and put the returned low16 sequence into the report.
 * Clip UNSIGNED actual to 64. A fresh type==2 sample sets flag1 iff clipped
 * length differs from the current transfer_length; all other cases use flag0.
 * Copy that many bytes from the DMA slot selected by a FRESH endpoint low nibble.
 * After copy, a FRESH type==2 selects the bulk queue; otherwise use interrupt.
 * Send at the back with a 20-tick wait. Result other than 1 drops the sequence
 * reread from the stack report. Report padding and unused payload are not
 * initialized; the whole queue item may therefore retain stack bytes. No
 * persistent report cache or transfer-state changes are made directly here. */
void medius_vendor_queue_partial(MediusVendorEndpointState *endpoint, unsigned int actual)
{
    volatile MediusVendorEndpointState *state = endpoint;
    volatile MediusVendorReport report;
    unsigned int timestamp = (unsigned int)esp_timer_get_time();
    unsigned short endpoint_type = *(volatile unsigned short *)&state->endpoint;
    report.timestamp_us = timestamp;
    report.endpoint_type = endpoint_type;
    report.sequence = (unsigned short)medius_vendor_history_append(endpoint);
    unsigned int length = actual < 64U ? actual : 64U;
    report.length = (unsigned short)length;
    unsigned int type = state->transfer_type;
    unsigned char flags = 0;
    if (type == 2) flags = state->transfer_length != length;
    unsigned int dma_slot = state->endpoint & 15U;
    report.flags = flags;
    medius_copy_bytes((void *)report.payload, (void *)MEDIUS_VENDOR_TRANSFER_SLOTS[dma_slot], length);
    RtosQueue *queue = state->transfer_type == 2 ? MEDIUS_VENDOR_BULK_QUEUE : MEDIUS_VENDOR_INTERRUPT_QUEUE;
    if (xQueueGenericSend(queue, (const void *)&report, 20, 0) != 1)
        medius_vendor_history_drop(endpoint, report.sequence);
}

/* Native entry: 0x4202f61c. */
/* Original function-byte SHA-256:
 * 2da287b45bebb6306ad2d2a063424d36c6c52f7918c344c8fe780a4ab9307a07. */
/* Fence/set callback_rearm_inhibited=1. Sample time, then fence/read armed and
 * wait while nonzero and signed64 now < wrapped(start+3000), delaying one RTOS
 * tick between fenced armed reads. Independently reread armed after that loop:
 * a fresh nonzero value invokes kill_urb_with_actual with actual initialized0.
 * Ignore cancellation result. Sample a NEW start time and similarly wait for
 * activity with a 20000-us deadline. Cache actual, fence/clear armed regardless
 * of either timeout, then emit queue_partial if cached actual is nonzero.
 * Does not clear activity or the inhibit flag, test direction or lock. Timing
 * limits are loop stop conditions, not scheduling/completion guarantees; signed
 * comparison and modulo64 deadline addition retain native rollover behavior. */
void medius_vendor_pause_endpoint(MediusVendorEndpointState *endpoint)
{
    volatile MediusVendorEndpointState *state = endpoint;
    memw(); state->callback_rearm_inhibited = 1;
    unsigned long long start = (unsigned long long)esp_timer_get_time();
    memw(); unsigned int armed = state->armed;
    unsigned long long deadline = start + 3000U;
    while (armed != 0) {
        unsigned long long now = (unsigned long long)esp_timer_get_time();
        if ((long long)now >= (long long)deadline) break;
        vTaskDelay(1);
        memw(); armed = state->armed;
    }
    memw(); unsigned int still_armed = state->armed;
    unsigned int actual = 0;
    if (still_armed != 0)
        medius_usbh_kill_urb_with_actual((MediusHostUrb *)&state->urb, &actual);
    start = (unsigned long long)esp_timer_get_time();
    memw(); unsigned int active = state->activity;
    deadline = start + 20000U;
    while (active != 0) {
        unsigned long long now = (unsigned long long)esp_timer_get_time();
        if ((long long)now >= (long long)deadline) break;
        vTaskDelay(1);
        memw(); active = state->activity;
    }
    unsigned int completed = actual;
    memw(); state->armed = 0;
    if (completed != 0) medius_vendor_queue_partial(endpoint, completed);
}

/* Native entry: 0x4202f6e8. */
/* Original function-byte SHA-256:
 * de36891313e5617bba7ad67af3023b04d908eff74aa02bac7a26608b5c3360af. */
/* Release every currently allocated vendor record whose interface byte equals
 * the FULL unsigned interface_number. Reload the mask before each of 12 slots.
 * Deactivate matches, run the global activity wait, then walk raw endpoint_count
 * with no cap at12. NULL descriptors skip cancellation AND count refresh. For
 * present descriptors initialize actual0, cancel the URB and ignore status.
 * Fresh OUT with nonzero actual performs a fenced UNUSED pending-byte read,
 * refreshes count and skips the rest. Fresh IN with actual queues a partial
 * report, then rereads its endpoint. Fence/read queued_report_pending even on
 * ordinary OUT paths. Pending IN sends its cached report to BULK with20 ticks,
 * regardless of stored type. After send, reread endpoint; failure reads that
 * endpoint's cached sequence, drops history, then rereads endpoint again.
 *
 * If that saved endpoint is still IN, enter credit lock and reread endpoint
 * low nibble for the save slot WITHOUT another direction check. Copy exactly
 * state bytes96..199 (104 bytes), then read validity16 and type, publish type
 * BEFORE validity16, and unlock. Refresh count after every handled descriptor.
 * Cache hubport/mode afterward. Mode0 may clear private_data through a cached
 * interface table only if non-NULL, equal to a second pointer read, full input
 * below the cached count16, and alternate_count nonzero. Count is read between
 * two fences BEFORE the pointer recheck, including when the cached table is
 * NULL. Always clear the record afterward, then continue to later mask slots.
 * No mutex, record lifetime validation, rollback, queued-pending clear or
 * cancellation-success guarantee is supplied by this helper. */
void medius_vendor_release_saved(unsigned int interface_number)
{
    for (unsigned int slot = 0; slot < 12; ++slot) {
        if ((MEDIUS_VENDOR_INTERFACE_MASK & (1U << slot)) == 0) continue;
        volatile MediusVendorInterface *record = &MEDIUS_VENDOR_INTERFACES[slot];
        if (record->interface_number != interface_number) continue;
        memw(); record->active = 0;
        medius_vendor_wait_activity();
        unsigned int count = record->endpoint_count;
        unsigned int index = 0;
        if (count != 0) {
            do {
                volatile MediusVendorEndpointState *state = (volatile void *)
                    ((unsigned int)record + 8U + index * 208U);
                if (state->descriptor != NULL) {
                    unsigned int actual = 0;
                    medius_usbh_kill_urb_with_actual((MediusHostUrb *)&state->urb, &actual);
                    unsigned int address = state->endpoint;
                    if (actual != 0) {
                        if ((address & 128U) == 0) {
                            memw(); (void)state->queued_report_pending;
                            count = record->endpoint_count;
                            goto next_endpoint;
                        }
                        medius_vendor_queue_partial((MediusVendorEndpointState *)state, actual);
                        address = state->endpoint;
                    }
                    memw(); unsigned int pending = state->queued_report_pending;
                    if (pending != 0 && (address & 128U) != 0) {
                        int sent = xQueueGenericSend(MEDIUS_VENDOR_BULK_QUEUE,
                            (const void *)&MEDIUS_VENDOR_REPORT_CACHE[address & 15U], 20, 0);
                        address = state->endpoint;
                        if (sent != 1) {
                            unsigned int sequence = MEDIUS_VENDOR_REPORT_CACHE[address & 15U].sequence;
                            medius_vendor_history_drop((MediusVendorEndpointState *)state, sequence);
                            address = state->endpoint;
                        }
                    }
                    if ((address & 128U) != 0) {
                        xPortEnterCriticalTimeout(&MEDIUS_VENDOR_CREDIT_LOCK, -1);
                        unsigned int saved_slot = state->endpoint & 15U;
                        memcpy((void *)&MEDIUS_VENDOR_SAVED_CREDITS[saved_slot],
                            (const void *)&state->report_sequence, 104);
                        unsigned int valid = MEDIUS_VENDOR_SAVED_ENDPOINT_VALID;
                        unsigned int type = state->transfer_type;
                        MEDIUS_VENDOR_SAVED_TYPES[saved_slot] = (unsigned char)type;
                        MEDIUS_VENDOR_SAVED_ENDPOINT_VALID = (unsigned short)(valid | (1U << saved_slot));
                        vPortExitCritical(&MEDIUS_VENDOR_CREDIT_LOCK);
                    }
                    count = record->endpoint_count;
                }
next_endpoint:
                ++index;
            } while ((index & 255U) < count);
        }
        volatile MediusHostHubPortPrefix *port = record->hubport;
        if (port != NULL && record->mode == 0) {
            volatile MediusHostInterfacePrefix *interfaces = port->interfaces;
            memw(); unsigned int interface_count = port->interface_count;
            memw();
            if (interfaces != NULL && interfaces == port->interfaces &&
                    interface_number < interface_count && interfaces[interface_number].alternate_count != 0)
                interfaces[interface_number].private_data = NULL;
        }
        medius_vendor_clear_interface((MediusVendorInterface *)record);
    }
}

/* Native entry: 0x4202f8b8. */
/* Original function-byte SHA-256:
 * 3c37d14604428fb7cbed7309d9fe841f032f716eb5f623e690ad3257c5e02eea. */
/* Retry a pending cached report before claiming another USB transfer. Fence
 * and read queued_report_pending. If nonzero, select cache[endpoint & 15] and
 * send to the bulk queue at the back without waiting. Only result 1 clears
 * pending; every other result returns before the claim. Then claim armed state
 * through its locked helper. A nonzero raw claim result calls rearm(record,
 * endpoint); any negative rearm result clears armed with a fence, including -6.
 * No local activity/inhibit checks, cache erase, history adjustment or yield.
 * Pointers must remain valid across the delegated queue/claim/rearm calls. */
void medius_vendor_retry_cached(MediusVendorInterface *record, MediusVendorEndpointState *endpoint)
{
    volatile MediusVendorEndpointState *state = endpoint;
    memw();
    if (state->queued_report_pending != 0) {
        unsigned int slot = state->endpoint & 15U;
        if (xQueueGenericSend(MEDIUS_VENDOR_BULK_QUEUE,
                (const void *)&MEDIUS_VENDOR_REPORT_CACHE[slot], 0, 0) != 1)
            return;
        memw(); state->queued_report_pending = 0;
    }
    if (medius_vendor_claim_arm(endpoint) != 0 && medius_vendor_rearm(record, endpoint) < 0) {
        memw(); state->armed = 0;
    }
}

/* Native entry: 0x4202fb4c. */
/* Original function-byte SHA-256:
 * 5618cc53ef4ff1c25f51e61cc663d37dbfb72dc0cef8d4ed38a94cdce61614c2. */
/* Build vendor forwarding for one interface/alternate. hubport must be valid;
 * there is no NULL-port guard. Cache its interface table, fence/read count16,
 * fence and require non-NULL unchanged table plus FULL unsigned index<count.
 * Search the cached alternate count of 16-byte records for FULL alternate equality.
 * Missing interface/alternate returns-1; zero endpoints returns0. Preflight the
 * captured byte descriptor count at7-byte stride, excluding exact pointers and
 * accepting attributes&3 of2/3. None eligible returns0 without allocation.
 * Cache allocation mask ONCE, select first free low12 bit, publish mask then
 * clear2504 bytes. No free slot logs and returns-1; there is no allocation lock.
 *
 * Store low8 interface/mode, port and count0. Reload descriptor base for build;
 * after every NONEXCLUDED descriptor advance, check extent/count12 and reload
 * base if continuing. Excluded descriptors advance without reload or count12
 * check. Unsupported types log and reread count. Accepted entries use cached
 * type from BEFORE diagnostic calls, but fresh address/MPS after them. Store
 * endpoint/type and interface/dense-slot as halfwords. Length=min(MPS&2047,64).
 *
 * Cache validity BIT from that address before credit lock. Inside, reread state
 * address: an IN with cached bit valid and saved type at FRESH low nibble equal
 * cached type restores104 bytes. Clear cached bit using the mask sampled BEFORE
 * copy. Fresh defaults clear26 words; bulk gets limit8/window200000/protection1,
 * interrupt samples now-or1 BEFORE clear and gets limit1/boost3000000/window5000.
 * Fresh paths reread address and validity before conditionally clearing cached
 * bit; OUT normally leaves validity unchanged. Unlock, snapshot count, fence/
 * clear blocked, armed and pending, then publish incremented byte count.
 *
 * FULL mode0 publishes private_data through CURRENT port.interfaces without
 * revalidation; stored mode itself is low8. Zero cached count activates/logs
 * directly. Otherwise register OUT endpoints before active=1, refreshing count
 * after EVERY visit. Then IN endpoints with fenced global-pause0 set armed and
 * invoke rearm; negative results clear armed and log, including-6. Refresh count
 * each visit. Log claimed/adopted with final cached count and return0 despite
 * delegated failures. No pointer lifetime/descriptor-length/rollback guarantee. */
int medius_vendor_initialize_interface(void *hubport, unsigned int interface_number,
    unsigned int alternate, int mode, unsigned char *exclude1, unsigned char *exclude2)
{
    volatile MediusHostHubPortPrefix *port = hubport;
    volatile MediusHostInterfacePrefix *interfaces = port->interfaces;
    memw(); unsigned int count = port->interface_count;
    memw();
    if (interfaces == NULL || interfaces != port->interfaces || interface_number >= count) return -1;
    volatile MediusHostInterfacePrefix *interface = &interfaces[interface_number];
    unsigned int alternatives = interface->alternate_count;
    if (alternatives == 0) return -1;
    volatile MediusHostAlternatePrefix *selected = interface->alternates;
    unsigned int i;
    for (i = 0; i < alternatives; ++i, ++selected)
        if (selected->alternate_setting == alternate) break;
    if (i == alternatives) return -1;
    unsigned int descriptors = selected->endpoint_count;
    if (descriptors == 0) return 0;
    unsigned int extent = descriptors * 7U;
    unsigned int base = (unsigned int)selected->endpoints;
    unsigned int eligible = 0;
    for (i = 0; i < descriptors; ++i) {
        const volatile MediusHostEndpointDescriptor *descriptor = (const volatile void *)(base + i * 7U);
        if ((const void *)descriptor == exclude1 || (const void *)descriptor == exclude2) continue;
        unsigned int type = descriptor->attributes & 3U;
        if (type == 2 || type == 3) eligible = (eligible + 1U) & 255U;
    }
    if (eligible == 0) return 0;
    unsigned int mask = MEDIUS_VENDOR_INTERFACE_MASK;
    unsigned int slot;
    for (slot = 0; slot < 12; ++slot) if ((mask & (1U << slot)) == 0) break;
    if (slot == 12) {
        medius_host_log_formatted("intf %u: no free relay slot (endpoints will not be relayed)", interface_number);
        return -1;
    }
    MEDIUS_VENDOR_INTERFACE_MASK = mask | (1U << slot);
    volatile MediusVendorInterface *record = &MEDIUS_VENDOR_INTERFACES[slot];
    memset((void *)record, 0, 2504);
    record->endpoint_count = 0;
    record->interface_number = (unsigned char)interface_number;
    base = (unsigned int)selected->endpoints;
    record->mode = (unsigned char)mode;
    record->hubport = hubport;
    unsigned int offset = 0, dense = 0;
    for (;;) {
        volatile MediusHostEndpointDescriptor *descriptor = (volatile void *)(base + offset);
        if ((void *)descriptor == exclude1 || (void *)descriptor == exclude2) {
            offset += 7U;
            if (offset == extent) break;
            continue;
        }
        unsigned int type = descriptor->attributes & 3U;
        if (type != 2 && type != 3) {
            medius_host_log_formatted("intf %u ep 0x%02X: xfer %u not relayed", interface_number,
                (unsigned int)descriptor->address, type);
            dense = record->endpoint_count;
        } else {
            volatile MediusVendorEndpointState *state = (volatile void *)
                ((unsigned int)record + 8U + dense * 208U);
            state->descriptor = (unsigned char *)descriptor;
            ets_printf("\033[32m[I/USB] ");
            unsigned int debug_high = descriptor->max_packet[1];
            unsigned int debug_low = descriptor->max_packet[0];
            unsigned int debug_interval = descriptor->interval;
            unsigned int debug_attributes = descriptor->attributes;
            unsigned int debug_address = descriptor->address;
            ets_printf("Ep=%02x Attr=%02u Mps=%d Interval=%02u Mult=%02u\r\n", debug_address,
                debug_attributes, (debug_low | (debug_high << 8)) & 2047U, debug_interval, (debug_high >> 3) & 3U);
            ets_printf("\033[0m");
            unsigned int address = descriptor->address;
            state->endpoint_type = (unsigned short)(address | (type << 8));
            unsigned int high = descriptor->max_packet[1];
            unsigned int low = descriptor->max_packet[0];
            unsigned int packet_size = (low | (high << 8)) & 2047U;
            unsigned int published_count = record->endpoint_count;
            state->transfer_length = (unsigned short)(packet_size < 64U ? packet_size : 64U);
            state->interface_endpoint_slots = (unsigned short)(slot | (published_count << 8));
            unsigned int bit = 1U << (address & 15U);
            xPortEnterCriticalTimeout(&MEDIUS_VENDOR_CREDIT_LOCK, -1);
            unsigned int live_address = state->endpoint;
            unsigned int valid = 0;
            int restored = 0;
            if ((live_address & 128U) != 0) {
                valid = MEDIUS_VENDOR_SAVED_ENDPOINT_VALID;
                unsigned int saved_slot = live_address & 15U;
                if ((valid & bit) != 0 && MEDIUS_VENDOR_SAVED_TYPES[saved_slot] == type) {
                    memcpy((void *)&state->report_sequence, (const void *)&MEDIUS_VENDOR_SAVED_CREDITS[saved_slot], 104);
                    MEDIUS_VENDOR_SAVED_ENDPOINT_VALID = (unsigned short)(valid & ~bit);
                    restored = 1;
                }
            }
            if (!restored) {
                unsigned long long now = 0;
                if (type != 2) { now = (unsigned long long)esp_timer_get_time(); if (now == 0) now = 1; }
                volatile unsigned int *credit = (volatile void *)&state->report_sequence;
                for (unsigned int word = 0; word < 26; ++word) credit[word] = 0;
                if (type == 2) {
                    state->credit_limit = 8;
                    state->history_window_us = 200000;
                    state->history_protection_active = 1;
                } else {
                    state->credit_limit = 1;
                    volatile ClockWords *start = (volatile void *)&state->boost_started_us;
                    volatile ClockWords *duration = (volatile void *)&state->boost_duration_us;
                    start->low = (unsigned int)now;
                    duration->low = 3000000;
                    duration->high = 0;
                    start->high = (unsigned int)(now >> 32);
                    state->history_window_us = 5000;
                }
                if ((state->endpoint & 128U) != 0) {
                    valid = MEDIUS_VENDOR_SAVED_ENDPOINT_VALID;
                    MEDIUS_VENDOR_SAVED_ENDPOINT_VALID = (unsigned short)(valid & ~bit);
                }
            }
            vPortExitCritical(&MEDIUS_VENDOR_CREDIT_LOCK);
            published_count = record->endpoint_count;
            memw(); state->credit_blocked = 0;
            memw(); state->armed = 0;
            memw(); state->queued_report_pending = 0;
            dense = (published_count + 1U) & 255U;
            record->endpoint_count = (unsigned char)dense;
        }
        offset += 7U;
        if (offset == extent || dense > 11U) break;
        base = (unsigned int)selected->endpoints;
    }
    if (mode == 0) {
        volatile MediusHostInterfacePrefix *current = port->interfaces;
        current[interface_number].private_data = (void *)record;
    }
    unsigned int current_count = dense;
    if (dense != 0) {
        i = 0;
        do {
            volatile MediusVendorEndpointState *state = (volatile void *)
                ((unsigned int)record + 8U + i * 208U);
            if ((state->endpoint & 128U) == 0) medius_out_register(hubport, state->descriptor);
            i = (i + 1U) & 255U;
            current_count = record->endpoint_count;
        } while (i < current_count);
    }
    memw(); record->active = 1;
    if (dense != 0 && current_count != 0) {
        i = 0;
        do {
            volatile MediusVendorEndpointState *state = (volatile void *)
                ((unsigned int)record + 8U + i * 208U);
            if ((state->endpoint & 128U) != 0) {
                memw();
                if (MEDIUS_VENDOR_GLOBAL_PAUSE == 0) {
                    memw(); state->armed = 1;
                    if (medius_vendor_rearm((MediusVendorInterface *)record, (MediusVendorEndpointState *)state) < 0) {
                        memw(); state->armed = 0;
                        medius_host_log_formatted("intf %u ep 0x%02X submit fail", interface_number,
                            (unsigned int)state->endpoint);
                    }
                }
            }
            ++i;
            current_count = record->endpoint_count;
        } while ((i & 255U) < current_count);
    }
    medius_host_log_formatted("intf %u %s, %u ep", interface_number, mode == 0 ? "claimed" : "adopted", current_count);
    return 0;
}

/* Native entry: 0x42030044. */
/* Original function-byte SHA-256:
 * 00585d94a74ba3edbf65859fc7982bf6bced6662052a28a288b45fd834e9dd34. */
/* Clear the selected-alternate byte at low8(interface_number), then delegate
 * initialize_interface(hubport, index, 0, 0, NULL, NULL). Return its signed
 * result unchanged. The selection write happens before delegated validation
 * and is not rolled back on failure. No local pointer/interface-count check. */
int medius_vendor_claim_interface(void *hubport, unsigned int interface_number)
{
    unsigned int index = interface_number & 255U;
    MEDIUS_VENDOR_SELECTED_ALTERNATES[index] = 0;
    return medius_vendor_initialize_interface(hubport, index, 0, 0, NULL, NULL);
}

/* Native entry: 0x42030068. */
/* Original function-byte SHA-256:
 * 618dc1443be7ef54928e2bf9aa9f238cd8d50df214ba127bf73c6bf0b12c20e2. */
/* Format one queued report into caller-owned scratch. Store endpoint, then
 * timestamp bytes using TWO word reads, one high-halfword read and one high-byte
 * read, preserving native widths/snapshots. Cache type once. Bulk writes sequence
 * low/high with separate halfword reads, flags at7 and payload at8; sends opcode
 * 0x1c/flags0. Other types write flags5/payload6 and send opcode0x10 with a fresh
 * sequence-low-byte read after copy. Length is a fresh halfword for copy and
 * again for send, whose header-added length wraps16. No local cap or capacity
 * check: caller must provide readable payload and enough nonoverlapping scratch.
 *
 * After send, bulk checks fresh flag bit1 regardless of result. Nonbulk only
 * checks flag bit2 on result0; other results return. Special reports skip history.
 * Cache fresh endpoint, search all12 active records with cached uncapped counts,
 * and stop at first full endpoint-byte match, without mask/type checks. Nonbulk
 * invokes guarded history_drop with fresh sequence16. Bulk enters credit lock
 * without ISR queries and reads fresh sequence LOW BYTE after lock. Result0
 * clears low/high history words only if modulo256 distance<8. Nonzero result
 * samples timer BEFORE current sequence, then requires that distance and a
 * nonzero low/high history entry. Store now-or1 LOW then HIGH and update the
 * protection-base sequence byte. Unlock and return even when the entry is stale
 * or zero. No rearm, credit-count change, queue retry or local serialization of
 * scratch/report lifetime. */
void medius_vendor_forward_report(MediusVendorReport *report, unsigned char *scratch)
{
    const volatile MediusVendorReport *live = report;
    volatile unsigned char *output = scratch;
    output[0] = live->endpoint;
    output[1] = (unsigned char)live->timestamp_us;
    output[2] = (unsigned char)(live->timestamp_us >> 8);
    output[3] = (unsigned char)live->timestamp_halves[1];
    output[4] = live->timestamp_bytes[3];
    int bulk = live->transfer_type == 2;
    int sent;
    if (bulk) {
        output[5] = (unsigned char)live->sequence;
        output[6] = (unsigned char)(live->sequence >> 8);
        output[7] = live->flags;
        medius_copy_bytes(scratch + 8, (void *)live->payload, live->length);
        unsigned int length = live->length;
        sent = link_send_wait100(0x1c, 0, scratch, (unsigned short)(length + 8U));
        if ((live->flags & 2U) != 0) return;
    } else {
        output[5] = live->flags;
        medius_copy_bytes(scratch + 6, (void *)live->payload, live->length);
        unsigned int length = live->length;
        unsigned char sequence = live->sequence_low;
        sent = link_send_wait100(0x10, sequence, scratch, (unsigned short)(length + 6U));
        if (sent != 0 || (live->flags & 4U) != 0) return;
    }
    unsigned int wanted = live->endpoint;
    for (unsigned int slot = 0; slot < 12; ++slot) {
        const volatile MediusVendorInterface *record = &MEDIUS_VENDOR_INTERFACES[slot];
        memw(); if (record->active == 0) continue;
        unsigned int count = record->endpoint_count;
        for (unsigned int index = 0; index < count; ++index) {
            volatile MediusVendorEndpointState *state = (volatile void *)
                ((unsigned int)record + 8U + index * 208U);
            if (state->endpoint != wanted) continue;
            if (!bulk) {
                medius_vendor_history_drop((MediusVendorEndpointState *)state, live->sequence);
                return;
            }
            xPortEnterCriticalTimeout(&MEDIUS_VENDOR_CREDIT_LOCK, -1);
            unsigned int sequence = live->sequence_low;
            if (sent == 0) {
                if (((state->report_sequence - sequence) & 255U) < 8U) {
                    volatile ClockWords *history = (volatile void *)&state->report_history[sequence & 7U];
                    history->low = 0;
                    history->high = 0;
                }
            } else {
                unsigned long long now = (unsigned long long)esp_timer_get_time();
                if (((state->report_sequence - sequence) & 255U) < 8U) {
                    volatile ClockWords *history = (volatile void *)&state->report_history[sequence & 7U];
                    unsigned int low = history->low;
                    unsigned int high = history->high;
                    if ((low | high) != 0) {
                        if (now == 0) now = 1;
                        history->low = (unsigned int)now;
                        history->high = (unsigned int)(now >> 32);
                        state->protection_base_sequence = (unsigned char)sequence;
                    }
                }
            }
            vPortExitCritical(&MEDIUS_VENDOR_CREDIT_LOCK);
            return;
        }
    }
}

/* Native entry: 0x42030244. */
/* Original function-byte SHA-256:
 * e5d6079a6677e027b4c7b83760fce51ec080fcd9a17df7c55a92b53e71343167. */
/* Bulk forwarding worker: priority6, stack3072 bytes, core0. Ignore argument.
 * Forever receive80 bytes with infinite tick wait; only result0 retries. With
 * forwarding enabled, delegate using this task's dedicated72-byte scratch.
 * Otherwise special flag2/bulk or4/other skips history disposal; normal reports
 * search all12 active interfaces with uncapped cached counts and drop history
 * of the FIRST endpoint-byte match. No interface-mask or stored-type filtering.
 *
 * After the report, sample vendor mutex once. NULL or take(50 ticks)!=1 returns
 * to receive. Under the acquired mutex, each interface requires fenced active,
 * cached non-NULL hubport and connected byte; cache endpoint_count. Each endpoint
 * tests fenced pending, global pause, callback-rearm inhibit and submission
 * inhibit in that order. Eligible entries invoke retry_cached and refresh count
 * afterward; ineligible entries retain cached count. Walk byte-index comparisons
 * without cap12. Give the CURRENT global mutex, ignoring result, then repeat.
 * No dedicated timer, watchdog feed, direct USB operation or local give safety
 * fallback. Mutex identity and endpoint/port lifetime remain external duties. */
void medius_task_vendfwd(void *unused)
{
    (void)unused;
    MediusVendorReport report;
    for (;;) {
        if (xQueueReceive(MEDIUS_VENDOR_BULK_QUEUE, &report, 0xffffffffU) == 0) continue;
        if (medius_host_get_forwarding_inhibit() == 0)
            medius_vendor_forward_report(&report, (unsigned char *)MEDIUS_VENDOR_BULK_PACKET);
        else {
            unsigned int special_flag = report.transfer_type == 2 ? 2U : 4U;
            if ((report.flags & special_flag) == 0) {
                unsigned int wanted = report.endpoint;
                for (unsigned int slot = 0; slot < 12; ++slot) {
                    volatile MediusVendorInterface *record = &MEDIUS_VENDOR_INTERFACES[slot];
                    memw(); if (record->active == 0) continue;
                    unsigned int count = record->endpoint_count;
                    for (unsigned int index = 0; index < count; ++index) {
                        volatile MediusVendorEndpointState *state = (volatile void *)
                            ((unsigned int)record + 8U + index * 208U);
                        if (state->endpoint == wanted) {
                            medius_vendor_history_drop((MediusVendorEndpointState *)state, report.sequence);
                            goto service_cache;
                        }
                    }
                }
            }
        }
service_cache:;
        RtosQueue *mutex = MEDIUS_VENDOR_MUTEX;
        if (mutex == NULL || xQueueSemaphoreTake(mutex, 50) != 1) continue;
        for (unsigned int slot = 0; slot < 12; ++slot) {
            volatile MediusVendorInterface *record = &MEDIUS_VENDOR_INTERFACES[slot];
            memw(); if (record->active == 0) continue;
            const volatile MediusHostHubPortPrefix *port = record->hubport;
            if (port == NULL || port->connected == 0) continue;
            unsigned int count = record->endpoint_count;
            if (count == 0) continue;
            unsigned int index = 0;
            do {
                volatile MediusVendorEndpointState *state = (volatile void *)
                    ((unsigned int)record + 8U + index * 208U);
                memw(); if (state->queued_report_pending == 0) goto next_endpoint;
                memw(); if (MEDIUS_VENDOR_GLOBAL_PAUSE != 0) goto next_endpoint;
                memw(); if (state->callback_rearm_inhibited != 0) goto next_endpoint;
                memw(); if (state->submission_inhibited != 0) goto next_endpoint;
                medius_vendor_retry_cached((MediusVendorInterface *)record, (MediusVendorEndpointState *)state);
                count = record->endpoint_count;
next_endpoint:
                ++index;
            } while ((index & 255U) < count);
        }
        xQueueGenericSend(MEDIUS_VENDOR_MUTEX, NULL, 0, 0);
    }
}

/* Native entry: 0x420303b0. */
/* Original function-byte SHA-256:
 * 907c5592fce65dc8dba97f6c0b484e6c9073361146aa7cd5d130cf657bca4a3d. */
/* Create and immediately publish the bulk queue (32 x 80 bytes), interrupt
 * queue (16 x 80 bytes), then vendor mutex, in that order. Native passes queue
 * type registers 0/0/1, but these specialized, previously reviewed allocation
 * entries do not consume those arguments. Attempt vendfwd then vintr creation,
 * both with 3072-byte stacks, NULL argument/handle output and core 0; priorities
 * are 6 and 14 respectively. Ignore all creation results except the stored
 * resource handles, including NULL. No failure cleanup, retry or repeat-call
 * guard: workers are attempted even after allocation failure, and a repeated
 * call overwrites the handles without deleting the old resources. */
void medius_vendor_start_workers(void)
{
    MEDIUS_VENDOR_BULK_QUEUE = xQueueGenericCreate(32, 80);
    MEDIUS_VENDOR_INTERRUPT_QUEUE = xQueueGenericCreate(16, 80);
    MEDIUS_VENDOR_MUTEX = xQueueCreateMutex();
    xTaskCreatePinnedToCore(medius_task_vendfwd, "vendfwd", 3072, NULL, 6, NULL, 0);
    xTaskCreatePinnedToCore(medius_task_vintr, "vintr", 3072, NULL, 14, NULL, 0);
}

/* Native entry: 0x42030420. */
/* Original function-byte SHA-256:
 * 40c893863fcb26b23aa899266030f2da26818731fa313f93b02ac17b4c126927. */
/* Initialize the vendor remainder of a HID interface. Narrow index to low8,
 * then call initialize_interface(port,index,0,1,exclude_in,exclude_out) once.
 * Forward every pointer unchanged, including NULL, and ignore the signed result.
 * No local state write, validation, alternate selection reset or rollback. */
void medius_vendor_initialize_hid_remainder(MediusHostHubPortPrefix *port,
    unsigned int interface_index, unsigned char *exclude_in, unsigned char *exclude_out)
{
    medius_vendor_initialize_interface(port, interface_index & 255U, 0, 1, exclude_in, exclude_out);
}

/* Native entry: 0x420306c4. */
/* Original function-byte SHA-256:
 * c4941df29061d5fc02c2effc2814700592f0eea6dbc9fe3743ba3405f98a71c4. */
/* After caller's SET_INTERFACE, rebuild local vendor forwarding. Narrow index
 * and alternate to bytes. NULL port returns. Cache interface table, fence/read
 * count16, fence, then require table non-NULL/unchanged, index in that cached
 * count and nonzero alternate_count; first-stage failure is silent. Repeat
 * fenced count/pointer checks and read alternate_count again. Failure here or
 * no matching descriptor alternate logs not-enumerated with a FRESH count byte.
 * Search cached 16-byte descriptor records by byte3. On match, RELOAD the first
 * alternate pointer and test its class byte5, not the matching record's class;
 * first class3 returns without vendor work. No NULL descriptor-table check.
 *
 * Sample vendor mutex once. Non-NULL take waits600 ticks; result other than1
 * logs busy and returns. NULL skips acquisition. If connected, publish selected
 * alternate before release_saved; only a fresh connected byte permits rebuild.
 * Ignore rebuild result and do not roll selection back. Finally give the CURRENT
 * mutex unconditionally, even after disconnected/initially-NULL paths. A NULL
 * give can assert in FreeRTOS; this is not repaired. No lock protects descriptor
 * validation, and no USB request is issued here. Only three inputs are consumed. */
void medius_vendor_restore_alternate(MediusHostHubPortPrefix *hubport,
    unsigned int interface_number, unsigned int alternate)
{
    unsigned int index = interface_number & 255U;
    unsigned int selection = alternate & 255U;
    volatile MediusHostHubPortPrefix *port = hubport;
    if (port == NULL) return;
    volatile MediusHostInterfacePrefix *interfaces = port->interfaces;
    memw(); unsigned int count = port->interface_count;
    memw();
    if (interfaces == NULL || interfaces != port->interfaces || index >= count) return;
    volatile MediusHostInterfacePrefix *interface = &interfaces[index];
    if (interface->alternate_count == 0) return;
    memw(); count = port->interface_count;
    memw();
    if (interfaces != port->interfaces || index >= count) goto not_enumerated;
    count = interface->alternate_count;
    if (count == 0) goto not_enumerated;
    unsigned int descriptors = (unsigned int)interface->alternates;
    unsigned int found = 0;
    for (unsigned int i = 0; i < count; ++i) {
        if (*(volatile unsigned char *)(descriptors + i * 16U + 3U) == selection) { found = 1; break; }
    }
    if (!found) goto not_enumerated;
    unsigned int first = (unsigned int)interface->alternates;
    if (*(volatile unsigned char *)(first + 5U) == 3) return;
    RtosQueue *mutex = MEDIUS_VENDOR_MUTEX;
    if (mutex != NULL && xQueueSemaphoreTake(mutex, 600) != 1) {
        medius_host_log_formatted("intf %u alt %u: relay busy, endpoints not re-claimed", index, selection);
        return;
    }
    if (port->connected != 0) {
        MEDIUS_VENDOR_SELECTED_ALTERNATES[index] = (unsigned char)selection;
        medius_vendor_release_saved(index);
        if (port->connected != 0)
            medius_vendor_initialize_interface(hubport, index, selection, 0, NULL, NULL);
    }
    xQueueGenericSend(MEDIUS_VENDOR_MUTEX, NULL, 0, 0);
    return;
not_enumerated:
    medius_host_log_formatted("intf %u alt %u not enumerated (%u known)", index, selection,
        (unsigned int)interface->alternate_count);
}

/* Native entry: 0x42030a90. */
/* Original function-byte SHA-256:
 * beda8f07cbfefe49914db2d2d0730ba5e6ee66e1c44c705d808f3f1aebb02087. */
/* Invalidate one saved endpoint under the vendor credit lock by clearing bit
 * (endpoint & 15) in the 16-bit validity mask. Read that mask only after lock
 * entry and write a halfword back. Direction and higher endpoint bits are
 * ignored. Preserve every other bit and the saved payload/type storage. No ISR
 * queries, descriptor lookup, cancellation or data erasure is performed. */
void medius_vendor_discard_saved_endpoint_state(unsigned int endpoint)
{
    xPortEnterCriticalTimeout(&MEDIUS_VENDOR_CREDIT_LOCK, -1);
    unsigned int valid = MEDIUS_VENDOR_SAVED_ENDPOINT_VALID;
    MEDIUS_VENDOR_SAVED_ENDPOINT_VALID = (unsigned short)(valid & ~(1U << (endpoint & 15U)));
    vPortExitCritical(&MEDIUS_VENDOR_CREDIT_LOCK);
}

/* Native entry: 0x42030ac4. */
/* Original function-byte SHA-256:
 * 92415fc02e3f80537603bf0a31b2880b75f1a6028fcfb6b8ca60b42dd0dc15e9. */
/* Fence/clear global pause, then memset exactly256 selected-alternate bytes.
 * Only afterward enter the vendor credit lock indefinitely, clear the validity
 * HALFWORD, and unlock. Ignore entry result; no ISR-context query. The earlier
 * pause/selection writes are outside the lock. Saved credit/type storage, live
 * interfaces, queues and URBs remain untouched; this is not an atomic teardown. */
void medius_vendor_reset_selection_state(void)
{
    memw(); MEDIUS_VENDOR_GLOBAL_PAUSE = 0;
    memset((void *)MEDIUS_VENDOR_SELECTED_ALTERNATES, 0, 256);
    xPortEnterCriticalTimeout(&MEDIUS_VENDOR_CREDIT_LOCK, -1);
    MEDIUS_VENDOR_SAVED_ENDPOINT_VALID = 0;
    vPortExitCritical(&MEDIUS_VENDOR_CREDIT_LOCK);
}

/* Native entry: 0x42030e14. */
/* Original function-byte SHA-256:
 * 83092af7414469dab4e110a45006d7fe28dc0935f2569dd3cf493073638c9894. */
/* Return the modulo-256 reservation sum used by OUT admission. Cache the
 * interface mask once and scan its low 12 bits. Selected interfaces require a
 * fenced nonzero active byte; cache their raw endpoint count once, without a
 * cap at 12. For each endpoint whose address has bit 7 set, fence/read armed:
 * nonzero adds exactly 1, otherwise a SECOND fence precedes adding the RAW
 * credit_blocked byte. OUT endpoints add nothing and do not read either flag.
 * Truncate after each addition. No lock or atomic aggregate snapshot: counts
 * are cached while endpoint/flag reads can observe later state changes. */
unsigned char medius_vendor_reserved_slots(void)
{
    unsigned int mask = MEDIUS_VENDOR_INTERFACE_MASK;
    unsigned int reserved = 0;
    for (unsigned int slot = 0; slot < 12; ++slot) {
        if ((mask & (1U << slot)) == 0) continue;
        const volatile MediusVendorInterface *record = &MEDIUS_VENDOR_INTERFACES[slot];
        memw(); if (record->active == 0) continue;
        unsigned int count = record->endpoint_count;
        for (unsigned int index = 0; index < count; ++index) {
            const volatile MediusVendorEndpointState *state = (const volatile void *)
                ((unsigned int)record + 8U + index * 208U);
            if ((state->endpoint & 128U) == 0) continue;
            memw(); unsigned int armed = state->armed;
            unsigned int contribution = 1;
            if (armed == 0) { memw(); contribution = state->credit_blocked; }
            reserved = (reserved + contribution) & 255U;
        }
    }
    return (unsigned char)reserved;
}

/* Native entry: 0x42030e90. */
/* Original function-byte SHA-256:
 * 064a264444d37b35df3eea39a4ee49d1500d95fa9f6413d29c882db2b822a66a. */
/* Stop allocated mode!=0 interfaces, scanning12 slots with a FRESH allocation
 * mask per slot. Active is not an admission condition. Cache each mutex handle;
 * NULL skips acquisition, otherwise take with600 ticks and remember exact1.
 * Regardless of take outcome, fence/clear active and wait for activity. Walk
 * the raw endpoint count without cap12. Non-NULL descriptor invokes kill_urb on
 * the embedded URB and refreshes count; NULL skips retain cached count. Ignore
 * cancellation results, increment index modulo256 and advance208-byte slots.
 * Clear the record even when count0. Only a remembered successful take gives
 * the CURRENT global mutex with NULL item/zero wait/back position, ignoring
 * result. Continue after all failures. No save/drain, rollback, atomic mask scan
 * or proof of callback/DMA quiescence; delegated helpers own those effects. */
void medius_vendor_stop_mode_interfaces(void)
{
    for (unsigned int slot = 0; slot < 12; ++slot) {
        volatile MediusVendorInterface *record = &MEDIUS_VENDOR_INTERFACES[slot];
        unsigned int mask = MEDIUS_VENDOR_INTERFACE_MASK;
        if ((mask & (1U << slot)) == 0 || record->mode == 0) continue;
        RtosQueue *mutex = MEDIUS_VENDOR_MUTEX;
        int acquired = 0;
        if (mutex != NULL) acquired = xQueueSemaphoreTake(mutex, 600) == 1;
        memw(); record->active = 0;
        medius_vendor_wait_activity();
        unsigned int count = record->endpoint_count;
        if (count != 0) {
            unsigned int address = (unsigned int)record + 8U;
            unsigned int index = 0;
            do {
                volatile MediusVendorEndpointState *state = (volatile void *)address;
                if (state->descriptor != NULL) {
                    usbh_kill_urb((MediusHostUrb *)&state->urb);
                    count = record->endpoint_count;
                }
                index = (index + 1U) & 255U;
                address += 208U;
            } while (index < count);
        }
        medius_vendor_clear_interface((MediusVendorInterface *)record);
        if (acquired) xQueueGenericSend(MEDIUS_VENDOR_MUTEX, NULL, 0, 0);
    }
}

/* Native entry: 0x420307a0. */
/* Original function-byte SHA-256:
 * 29547803fa5aa5e9442bbc0753b249fde1bf06a157203847bbed4511cbe233cf. */
/* Cache vendor mutex BEFORE fenced global-pause1. Optionally take100 ticks,
 * remember exact1, then wait for activity regardless of outcome. Scan12 slots
 * with live mask and fenced active; raw counts have no cap12. Only IN endpoints
 * with descriptors are killed; ignore result, fence/clear armed and refresh
 * count afterward. Skips retain count. Give CURRENT mutex only if take succeeded.
 * No record deactivation, queued-history drain or OUT cancellation here. */
void medius_vendor_pause_all(void)
{
    RtosQueue *mutex = MEDIUS_VENDOR_MUTEX;
    memw(); MEDIUS_VENDOR_GLOBAL_PAUSE = 1;
    int acquired = mutex != NULL && xQueueSemaphoreTake(mutex, 100) == 1;
    medius_vendor_wait_activity();
    for (unsigned int slot = 0; slot < 12; ++slot) {
        if ((MEDIUS_VENDOR_INTERFACE_MASK & (1U << slot)) == 0) continue;
        volatile MediusVendorInterface *record = &MEDIUS_VENDOR_INTERFACES[slot];
        memw(); if (record->active == 0) continue;
        unsigned int count = record->endpoint_count, index = 0;
        if (count == 0) continue;
        do {
            volatile MediusVendorEndpointState *state = (volatile void *)
                ((unsigned int)record + 8U + index * 208U);
            if ((state->endpoint & 128U) != 0 && state->descriptor != NULL) {
                usbh_kill_urb((MediusHostUrb *)&state->urb);
                memw(); state->armed = 0;
                count = record->endpoint_count;
            }
            ++index;
        } while ((index & 255U) < count);
    }
    if (acquired) xQueueGenericSend(MEDIUS_VENDOR_MUTEX, NULL, 0, 0);
}

/* Native entry: 0x420305f0. */
/* Original function-byte SHA-256:
 * db029432677a6d28f4e30a5706a17db152c05095ff82f4c6e01f9b6b67e9aa73. */
/* Cache mutex; only non-NULL take600 result1 delegates set_paused_locked(0).
 * That helper gives the current mutex. Other outcomes return without a give or
 * fallback. Does NOT clear global vendor pause; delegated admission still tests it. */
void medius_vendor_resume_all(void)
{
    RtosQueue *mutex = MEDIUS_VENDOR_MUTEX;
    if (mutex != NULL && xQueueSemaphoreTake(mutex, 600) == 1) medius_vendor_set_paused_locked(0);
}

/* Native entry: 0x42030438. */
/* Original function-byte SHA-256:
 * 2914dc254611f538add857d84143789256f1b3e22423fbcc2fe8be0c4f92ae89. */
/* Narrow interface/alternate to bytes. Optional cached mutex take600; failure
 * other than1 logs busy and returns. Absence bypasses take. Release saved vendor
 * records BEFORE testing port.connected. Connected ports initialize mode1 with
 * unchanged exclusion pointers; ignore result. Unconditionally give CURRENT
 * global mutex afterward, even if initially absent/disconnected. NULL give may
 * assert in FreeRTOS. No selection update, pointer guard, rollback or USB request. */
void medius_vendor_rebuild_hid_remainder(MediusHostHubPortPrefix *hubport,
    unsigned int interface_number, unsigned int alternate, unsigned char *exclude_in, unsigned char *exclude_out)
{
    unsigned int index = interface_number & 255U;
    unsigned int selection = alternate & 255U;
    RtosQueue *mutex = MEDIUS_VENDOR_MUTEX;
    if (mutex != NULL && xQueueSemaphoreTake(mutex, 600) != 1) {
        medius_host_log_formatted("intf %u alt %u: relay busy, endpoints not re-claimed", index, selection);
        return;
    }
    medius_vendor_release_saved(index);
    if (((const volatile MediusHostHubPortPrefix *)hubport)->connected != 0)
        medius_vendor_initialize_interface(hubport, index, selection, 1, exclude_in, exclude_out);
    xQueueGenericSend(MEDIUS_VENDOR_MUTEX, NULL, 0, 0);
}

/* Native entry: 0x4202f918. */
/* Original function-byte SHA-256:
 * 56dd89f3cdb970a14cbb552eb65e9b7e3527fbf7db063869e1bf80547298477c. */
/* Caller holds vendor mutex; scan live allocation mask over12 fenced-active
 * records, uncapped byte endpoint counts. OUT and fenced submission-inhibited
 * entries skip without count refresh. pause!=0: descriptor-present IN invokes
 * pause_endpoint and refreshes count; NULL skips. pause0: fence/clear callback
 * inhibit, then test fenced armed/globalpause/stall and cached port.connected;
 * eligible entries retry cached reports. Refresh count on EVERY pause0 admitted
 * IN path, even if retry gates fail. Global vendor pause is not changed. Finally
 * give CURRENT mutex unconditionally, including empty mask; no internal take.
 * No local pointer lifetime validation, timeout or rollback. */
void medius_vendor_set_paused_locked(int pause)
{
    for (unsigned int slot = 0; slot < 12; ++slot) {
        if ((MEDIUS_VENDOR_INTERFACE_MASK & (1U << slot)) == 0) continue;
        volatile MediusVendorInterface *record = &MEDIUS_VENDOR_INTERFACES[slot];
        memw(); if (record->active == 0) continue;
        unsigned int count = record->endpoint_count, index = 0;
        if (count == 0) continue;
        do {
            volatile MediusVendorEndpointState *state = (volatile void *)
                ((unsigned int)record + 8U + index * 208U);
            if ((state->endpoint & 128U) == 0) goto next_endpoint;
            memw(); if (state->submission_inhibited != 0) goto next_endpoint;
            if (pause != 0) {
                if (state->descriptor != NULL) {
                    medius_vendor_pause_endpoint((MediusVendorEndpointState *)state);
                    count = record->endpoint_count;
                }
            } else {
                memw(); state->callback_rearm_inhibited = 0;
                memw(); if (state->armed != 0) goto refresh_count;
                memw(); if (MEDIUS_VENDOR_GLOBAL_PAUSE != 0) goto refresh_count;
                memw(); if (state->stall_pending != 0) goto refresh_count;
                const volatile MediusHostHubPortPrefix *port = record->hubport;
                if (port == NULL || port->connected == 0) goto refresh_count;
                medius_vendor_retry_cached((MediusVendorInterface *)record, (MediusVendorEndpointState *)state);
refresh_count:
                count = record->endpoint_count;
            }
next_endpoint:
            ++index;
        } while ((index & 255U) < count);
    }
    xQueueGenericSend(MEDIUS_VENDOR_MUTEX, NULL, 0, 0);
}

/* Native entry: 0x4202fa24. */
/* Original function-byte SHA-256:
 * f4b12a41e23936db16124fb4b9d3f5fd10cf08e6e71194fec94e6496925c9de9. */
/* Caller owns any vendor mutex; pause/resume every selected, fenced-active
 * mode0 record matching the FULL32 interface number. Walk uncapped byte counts
 * with low8 continuation and native208-byte stride; only IN is handled.
 * Pause!=0 calls pause_endpoint only for descriptor-present entries, then
 * refreshes count. No submission-inhibit gate on this pause path. Resume clears
 * callback-rearm inhibit, then fences/tests armed, global pause, submission
 * inhibit and stall in order, followed by cached port/nonzero connected. Retry
 * cached reports only if all pass; EVERY resume IN path refreshes count.
 * OUT and pause-with-NULL-descriptor retain the cached count. Finally sample
 * CURRENT mutex once and give it if nonNULL; this helper never takes it.
 * No global pause change, status, count cap or borrowed-pointer guarantee. */
void medius_vendor_set_interface_paused_locked(unsigned int interface_number,int pause)
{
    for (unsigned int slot = 0; slot < 12; ++slot) {
        if ((MEDIUS_VENDOR_INTERFACE_MASK & (1U << slot)) == 0) continue;
        volatile MediusVendorInterface *record = &MEDIUS_VENDOR_INTERFACES[slot];
        memw(); if (record->active == 0) continue;
        if (record->interface_number != interface_number || record->mode != 0) continue;
        unsigned int count = record->endpoint_count, index = 0;
        if (count == 0) continue;
        do {
            volatile MediusVendorEndpointState *state = (volatile void *)
                ((unsigned int)record + 8U + index * 208U);
            if ((state->endpoint & 128U) == 0) goto next_endpoint;
            if (pause != 0) {
                if (state->descriptor != NULL) {
                    medius_vendor_pause_endpoint((MediusVendorEndpointState *)state);
                    count = record->endpoint_count;
                }
            } else {
                memw(); state->callback_rearm_inhibited = 0;
                memw(); if (state->armed != 0) goto refresh_count;
                memw(); if (MEDIUS_VENDOR_GLOBAL_PAUSE != 0) goto refresh_count;
                memw(); if (state->submission_inhibited != 0) goto refresh_count;
                memw(); if (state->stall_pending != 0) goto refresh_count;
                const volatile MediusHostHubPortPrefix *port = record->hubport;
                if (port == NULL || port->connected == 0) goto refresh_count;
                medius_vendor_retry_cached((MediusVendorInterface *)record,(MediusVendorEndpointState *)state);
refresh_count:
                count = record->endpoint_count;
            }
next_endpoint:
            ++index;
        } while ((index & 255U) < count);
    }
    RtosQueue *mutex = MEDIUS_VENDOR_MUTEX;
    if (mutex != NULL) xQueueGenericSend(mutex,NULL,0,0);
}

/* Native entry: 0x42030490. */
/* Original function-byte SHA-256:
 * 342b544872d601624e13a1817db7da167bdfeb9440504af08839c2175a96be90. */
/* Retry idle, unqueued, uninhibited IN streams in selected active records.
 * Cache mutex; nonNULL and exact take(mutex,50)==1 are required. Fence global
 * pause once; nonzero skips scanning but still gives the CURRENT mutex.
 * Reload allocation mask per12 slots; fence active then require cached port
 * nonNULL/connected and raw endpoint count. IN eligibility fences armed,
 * queued-report-pending, callback inhibit, stall and credit-blocked in order.
 * Submission inhibit is delegated to retry_cached, not checked locally.
 * Refresh count only after retry; other paths retain the cached byte count.
 * Counts are uncapped, endpoint continuation compares low8 index. No local
 * cancellation, global pause update, retry success or lock-lifetime guarantee. */
void medius_vendor_service_idle_streams(void)
{
    RtosQueue *mutex = MEDIUS_VENDOR_MUTEX;
    if (mutex == NULL || xQueueSemaphoreTake(mutex,50) != 1) return;
    memw();
    if (MEDIUS_VENDOR_GLOBAL_PAUSE == 0) {
        for (unsigned int slot = 0; slot < 12; ++slot) {
            if ((MEDIUS_VENDOR_INTERFACE_MASK & (1U << slot)) == 0) continue;
            volatile MediusVendorInterface *record = &MEDIUS_VENDOR_INTERFACES[slot];
            memw(); if (record->active == 0) continue;
            const volatile MediusHostHubPortPrefix *port = record->hubport;
            if (port == NULL || port->connected == 0) continue;
            unsigned int count = record->endpoint_count, index = 0;
            if (count == 0) continue;
            do {
                volatile MediusVendorEndpointState *state = (volatile void *)
                    ((unsigned int)record + 8U + index * 208U);
                if ((state->endpoint & 128U) == 0) goto next_endpoint;
                memw(); if (state->armed != 0) goto next_endpoint;
                memw(); if (state->queued_report_pending != 0) goto next_endpoint;
                memw(); if (state->callback_rearm_inhibited != 0) goto next_endpoint;
                memw(); if (state->stall_pending != 0) goto next_endpoint;
                memw(); if (state->credit_blocked != 0) goto next_endpoint;
                medius_vendor_retry_cached((MediusVendorInterface *)record,(MediusVendorEndpointState *)state);
                count = record->endpoint_count;
next_endpoint:
                ++index;
            } while ((index & 255U) < count);
        }
    }
    xQueueGenericSend(MEDIUS_VENDOR_MUTEX,NULL,0,0);
}

/* Native entry: 0x42030584. */
/* Original function-byte SHA-256:
 * 2b51fdbf07eb55e966580015a5b814026da6359673ec576831a682201495c9e4. */
/* Narrow interface index to8 bits before caching mutex. NULL mutex bypasses
 * take; otherwise require exact take(mutex,600)==1. Delegate pause1 to the
 * interface helper, which owns any final give. No local give/status/retry. */
void medius_vendor_pause_interface(unsigned char index)
{
    RtosQueue *mutex = MEDIUS_VENDOR_MUTEX;
    if (mutex == NULL || xQueueSemaphoreTake(mutex,600) == 1)
        medius_vendor_set_interface_paused_locked(index,1);
}

/* Native entry: 0x420305ac. */
/* Original function-byte SHA-256:
 * 14b99ed781a1ee212e9083f9d142bd669b7828d88f25eda9e5fab5f441ae8e0e. */
/* Narrow interface index to8 bits before caching mutex. NULL mutex bypasses
 * take; otherwise require exact take(mutex,600)==1. Delegate pause0 to the
 * interface helper, which owns any final give. No local give/status/retry. */
void medius_vendor_resume_interface(unsigned char index)
{
    RtosQueue *mutex = MEDIUS_VENDOR_MUTEX;
    if (mutex == NULL || xQueueSemaphoreTake(mutex,600) == 1)
        medius_vendor_set_interface_paused_locked(index,0);
}

/* Native entry: 0x420305d4. */
/* Original function-byte SHA-256:
 * 92a9a87dd08b19b083118a8a44ca90099f37e2ff34c055cb20482a3a3d54e8e1. */
/* Cache mutex; require nonNULL and exact take(mutex,600)==1. Delegate the
 * retained successful result1 as pause to set_paused_locked, including its
 * final CURRENT-mutex give. NULL does nothing. Does not set global pause. */
void medius_vendor_pause_streams(void)
{
    RtosQueue *mutex = MEDIUS_VENDOR_MUTEX;
    if (mutex != NULL && xQueueSemaphoreTake(mutex,600) == 1)
        medius_vendor_set_paused_locked(1);
}

/* Native entry: 0x42030610. */
/* Original function-byte SHA-256:
 * 2b2f87f68548e307b5d053a5f48dd26576bce17b64d03cc77c8b4414dc75c8d2. */
/* Before CLEAR_FEATURE(ENDPOINT_HALT), pause matching IN vendor streams.
 * endpoint is low8; OUT returns before mutex access. Cache nonNULL mutex and
 * require exact take(mutex,100)==1. Reload mask per12 records and fence active.
 * Scan uncapped counts; endpoint match then fenced submission-inhibit0 and
 * nonNULL descriptor delegates pause_endpoint. Only that call refreshes count.
 * No mode/port/global-pause/armed admission gate; other matches still scan.
 * Give freshly sampled mutex even if it became NULL; ignore delegated status.
 * No endpoint validation, rollback or object/lock lifetime guarantee. */
void medius_vendor_prepare_clear_halt(unsigned char endpoint)
{
    if ((endpoint & 128U) == 0) return;
    RtosQueue *mutex = MEDIUS_VENDOR_MUTEX;
    if (mutex == NULL || xQueueSemaphoreTake(mutex,100) != 1) return;
    for (unsigned int slot = 0; slot < 12; ++slot) {
        if ((MEDIUS_VENDOR_INTERFACE_MASK & (1U << slot)) == 0) continue;
        volatile MediusVendorInterface *record = &MEDIUS_VENDOR_INTERFACES[slot];
        memw(); if (record->active == 0) continue;
        unsigned int count = record->endpoint_count, index = 0;
        if (count == 0) continue;
        do {
            volatile MediusVendorEndpointState *state = (volatile void *)
                ((unsigned int)record + 8U + index * 208U);
            if (state->endpoint == endpoint) {
                memw();
                if (state->submission_inhibited == 0 && state->descriptor != NULL) {
                    medius_vendor_pause_endpoint((MediusVendorEndpointState *)state);
                    count = record->endpoint_count;
                }
            }
            ++index;
        } while ((index & 255U) < count);
    }
    xQueueGenericSend(MEDIUS_VENDOR_MUTEX,NULL,0,0);
}

/* Native entry: 0x42030a60. */
/* Original function-byte SHA-256:
 * f5aec814e2ec5592138b837649863d0491399145a122308c91b0cee2d06b247a. */
/* Snapshot the allocation mask ONCE, then scan12 records in slot order.
 * For selected slots fence/sample active ONCE and return the first raw nonzero
 * byte; otherwise0. No boolean normalization, mutex, endpoint or port check.
 * Concurrent mask changes do not alter this scan's cached selection. */
unsigned char medius_vendor_first_active(void)
{
    unsigned int mask = MEDIUS_VENDOR_INTERFACE_MASK;
    for (unsigned int slot = 0; slot < 12; ++slot) {
        if ((mask & (1U << slot)) == 0) continue;
        memw(); unsigned char active = MEDIUS_VENDOR_INTERFACES[slot].active;
        if (active != 0) return active;
    }
    return 0;
}

/* Native entry: 0x42030b00. */
/* Original function-byte SHA-256:
 * 6db202c7ed96192d44ed43a3f2547a836e77ececb0ca02f01b374d7282aecfe0. */
/* For all12 records, cache raw endpoint_count once and clear fenced stall
 * and special-retry bytes on EVERY matching low8 endpoint. No allocation mask,
 * active/mode/direction/descriptor/port/global-pause gate, mutex or count cap.
 * Count is a descending32 loop bound, without callback count refresh. Other
 * fields, including halt/submission-inhibit and data toggle, remain unchanged. */
void medius_vendor_clear_stall_notifications(unsigned char endpoint)
{
    for (unsigned int slot = 0; slot < 12; ++slot) {
        volatile MediusVendorInterface *record = &MEDIUS_VENDOR_INTERFACES[slot];
        unsigned int remaining = record->endpoint_count, index = 0;
        while (remaining != 0) {
            volatile MediusVendorEndpointState *state = (volatile void *)
                ((unsigned int)record + 8U + index * 208U);
            if (state->endpoint == endpoint) {
                memw(); state->stall_pending = 0;
                memw(); state->special_retry = 0;
            }
            ++index;
            --remaining;
        }
    }
}

/* Native entry: 0x42030b5c. */
/* Original function-byte SHA-256:
 * a75936ac4603d9864861ea5bdb8a1ef3411e0a8d1eccf13adb5619fbf651ee92. */
/* Set/clear local halt inhibition for matching IN endpoints, not a USB
 * request itself. Cache low8(endpoint,halted,reset_toggle); OUT returns. Require
 * cached nonNULL mutex and exact take(mutex,100)==1. Reload allocation mask per
 *12 records; fence active, then walk uncapped raw byte counts/208-byte stride.
 * No interface-mode, descriptor or port admission check here.
 *
 * halted low8!=0: fence/set submission-inhibit1; sample time then fenced armed.
 * Wait while armed and signed64 now is before modulo64(start+3000), delaying
 * one scheduler tick between fenced rechecks. Independently reread armed after
 * the loop; if nonzero cancel URB with actual initialized0, ignoring status.
 * Sample time AGAIN, then wait on fenced activity with a fresh20000us deadline.
 * Cache actual BEFORE fenced unconditional armed0; queue partial if nonzero,
 * regardless of cancel status or wait timeout. Does not clear callback inhibit,
 * stall, special retry, activity or data toggle on this path.
 *
 * clear: fence/clear submission inhibit, callback inhibit, special retry, stall
 * in that order. Nonzero reset_toggle low8 clears URB toggle without a fence.
 * Fence/test armed then global pause; if both0 retry_cached (its own admission
 * remains delegated). Every matching path refreshes count, including skipped
 * retry/zero actual; nonmatches retain the cached count. Give CURRENT mutex
 * unconditionally after successful take, including NULL if changed. No status,
 * timeout failure, physical delay or callback/lifetime/quiescence guarantee. */
void medius_vendor_set_endpoint_halt(unsigned int endpoint,unsigned int halted,unsigned int reset_toggle)
{
    unsigned char address = (unsigned char)endpoint;
    unsigned char set_halt = (unsigned char)halted;
    unsigned char reset = (unsigned char)reset_toggle;
    if ((address & 128U) == 0) return;
    RtosQueue *mutex = MEDIUS_VENDOR_MUTEX;
    if (mutex == NULL || xQueueSemaphoreTake(mutex,100) != 1) return;
    for (unsigned int slot = 0; slot < 12; ++slot) {
        if ((MEDIUS_VENDOR_INTERFACE_MASK & (1U << slot)) == 0) continue;
        volatile MediusVendorInterface *record = &MEDIUS_VENDOR_INTERFACES[slot];
        memw(); if (record->active == 0) continue;
        unsigned int count = record->endpoint_count, index = 0;
        if (count == 0) continue;
        do {
            volatile MediusVendorEndpointState *state = (volatile void *)
                ((unsigned int)record + 8U + index * 208U);
            if (state->endpoint != address) goto next_endpoint;
            if (set_halt != 0) {
                memw(); state->submission_inhibited = 1;
                unsigned long long start = (unsigned long long)esp_timer_get_time();
                memw(); unsigned int armed = state->armed;
                unsigned long long deadline = start + 3000U;
                while (armed != 0) {
                    unsigned long long now = (unsigned long long)esp_timer_get_time();
                    if ((long long)now >= (long long)deadline) break;
                    vTaskDelay(1);
                    memw(); armed = state->armed;
                }
                memw(); unsigned int still_armed = state->armed;
                unsigned int actual = 0;
                if (still_armed != 0)
                    medius_usbh_kill_urb_with_actual((MediusHostUrb *)&state->urb,&actual);
                start = (unsigned long long)esp_timer_get_time();
                memw(); unsigned int active = state->activity;
                deadline = start + 20000U;
                while (active != 0) {
                    unsigned long long now = (unsigned long long)esp_timer_get_time();
                    if ((long long)now >= (long long)deadline) break;
                    vTaskDelay(1);
                    memw(); active = state->activity;
                }
                unsigned int completed = actual;
                memw(); state->armed = 0;
                if (completed != 0) medius_vendor_queue_partial((MediusVendorEndpointState *)state,completed);
            } else {
                memw(); state->submission_inhibited = 0;
                memw(); state->callback_rearm_inhibited = 0;
                memw(); state->special_retry = 0;
                memw(); state->stall_pending = 0;
                if (reset != 0) state->urb.toggle = 0;
                memw();
                if (state->armed == 0) {
                    memw();
                    if (MEDIUS_VENDOR_GLOBAL_PAUSE == 0)
                        medius_vendor_retry_cached((MediusVendorInterface *)record,(MediusVendorEndpointState *)state);
                }
            }
            count = record->endpoint_count;
next_endpoint:
            ++index;
        } while ((index & 255U) < count);
    }
    xQueueGenericSend(MEDIUS_VENDOR_MUTEX,NULL,0,0);
}

/* Native entry: 0x42030860. */
/* Original function-byte SHA-256:
 * d0a9df0440f5e12cd17a9b3151c67aba7281acbaf502000570a375a37ac4ac87. */
/* Restore vendor alternate0 and endpoint state for the supplied live port.
 * Cache mutex; if present attempt100-tick take. ALWAYS fence/clear global pause,
 * including NULL mutex or failed take. Only exact successful take scans256
 * saved selection bytes: nonzero is cleared BEFORE checking port.connected.
 * Cache table, fence/read count16, fence/recheck table even if NULL; stable
 * in-range entries with alternates and FIRST class!=3 release saved interface,
 * then recheck connected before initialize(port,index,0,0,NULL,NULL).
 * The supplied port is not locally NULL-validated; scans may dereference it.
 *
 * Regardless of mutex outcome, reload allocation mask per12 records, fence
 * active and require record.hubport==port, then uncapped raw endpoint counts.
 * Cache endpoint byte per iteration. IN fences armed; nonzero skips without
 * count refresh. Otherwise clear URB toggle and fenced special-retry,stall,
 * callback-inhibit,submission-inhibit in order. Fence/read pending; when set,
 * drop history using the ORIGINAL cached endpoint low4 report-cache sequence,
 * even if callbacks changed endpoint. Cache port.connected BEFORE fenced
 * pending0. If connected and claim_arm returns nonzero, rearm; ANY negative
 * result, including-6, fences armed0. Every handled unarmed IN refreshes count.
 * OUT resets toggle/refreshes count only when mutex take succeeded. Finally
 * successful take gives CURRENT mutex, even if now NULL. No rollback, status,
 * bounds check, coherent snapshot or concurrent lifetime guarantee. */
void medius_vendor_restore_configuration(MediusHostHubPortPrefix *port)
{
    RtosQueue *mutex = MEDIUS_VENDOR_MUTEX;
    int held = 0;
    if (mutex != NULL) held = xQueueSemaphoreTake(mutex,100) == 1;
    memw(); MEDIUS_VENDOR_GLOBAL_PAUSE = 0;
    volatile MediusHostHubPortPrefix *live_port = port;
    if (held) {
        for (unsigned int index = 0; index < 256; ++index) {
            if (MEDIUS_VENDOR_SELECTED_ALTERNATES[index] == 0) continue;
            MEDIUS_VENDOR_SELECTED_ALTERNATES[index] = 0;
            if (live_port->connected == 0) continue;
            MediusHostInterfacePrefix *table = live_port->interfaces;
            memw(); unsigned int count = live_port->interface_count;
            memw();
            if (table == NULL || live_port->interfaces != table || index >= count) continue;
            volatile MediusHostInterfacePrefix *entry = &table[index];
            if (entry->alternate_count == 0) continue;
            const volatile unsigned char *alternate = (const volatile void *)entry->alternates;
            if (alternate[5] == 3) continue;
            medius_vendor_release_saved(index);
            if (live_port->connected != 0)
                medius_vendor_initialize_interface(port,index,0,0,NULL,NULL);
        }
    }
    for (unsigned int slot = 0; slot < 12; ++slot) {
        if ((MEDIUS_VENDOR_INTERFACE_MASK & (1U << slot)) == 0) continue;
        volatile MediusVendorInterface *record = &MEDIUS_VENDOR_INTERFACES[slot];
        memw(); if (record->active == 0) continue;
        if (record->hubport != port) continue;
        unsigned int count = record->endpoint_count, index = 0;
        if (count == 0) continue;
        do {
            volatile MediusVendorEndpointState *state = (volatile void *)
                ((unsigned int)record + 8U + index * 208U);
            unsigned char address = state->endpoint;
            if ((address & 128U) != 0) {
                memw(); if (state->armed != 0) goto next_endpoint;
                state->urb.toggle = 0;
                memw(); state->special_retry = 0;
                memw(); state->stall_pending = 0;
                memw(); state->callback_rearm_inhibited = 0;
                memw(); state->submission_inhibited = 0;
                memw();
                if (state->queued_report_pending != 0) {
                    unsigned int sequence = MEDIUS_VENDOR_REPORT_CACHE[address & 15U].sequence;
                    medius_vendor_history_drop((MediusVendorEndpointState *)state,sequence);
                }
                unsigned char connected = live_port->connected;
                memw(); state->queued_report_pending = 0;
                if (connected != 0 && medius_vendor_claim_arm((MediusVendorEndpointState *)state) != 0 &&
                    medius_vendor_rearm((MediusVendorInterface *)record,(MediusVendorEndpointState *)state) < 0) {
                    memw(); state->armed = 0;
                }
                count = record->endpoint_count;
            } else if (held) {
                state->urb.toggle = 0;
                count = record->endpoint_count;
            }
next_endpoint:
            ++index;
        } while ((index & 255U) < count);
    }
    if (held) xQueueGenericSend(MEDIUS_VENDOR_MUTEX,NULL,0,0);
}
