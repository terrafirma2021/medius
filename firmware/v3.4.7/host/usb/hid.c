/* Medius v3.4.7 host — usb/hid.c.
 * Recovered C and native assembly, grouped for source navigation.
 * Original entry addresses, firmware-byte hashes and function comments follow.
 */

#include "../include/types.h"

/* Source reconstruction utilities for the repeated credit scan in native
 * 40389918/40389d44. No additional native entry. Caller holds the credit lock.
 * Preserve separate LOW/HIGH reads and conditional reference/duration LOW
 * reads; unsigned arithmetic supplies the native modulo64 additions/subtracts. */
static int hid_credit_allows(volatile MediusHidEndpointState *state,unsigned long long now)
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


/* Native entry: 0x40389530. */
/* Original function-byte SHA-256:
 * 0897638a3e1d09755b9496e8e9617cb6830c15e2d2e9a95564e405a33cda759c. */
/* HID forwarding task (3072-byte stack,priority15,core0). Ignore task argument,
 * subscribe to the shared watchdog once, then feed before every queue receive
 * with1000-tick timeout. Only receive result0 retries; any other result consumes
 * the 80-byte record. A fenced forwarding-inhibit sample discards normal work
 * with credit release, or marks special work retryable when generation still
 * matches and halted remains nonzero. No slot/length/queue validation is added.
 *
 * Build the shared UART frame's endpoint/stamp prefix. Normal records have a
 * six-byte header; a nonzero metadata formatter result adds26 bytes and flag1.
 * Nonzero report_flag adds flag2. Copy exactly the current length and send
 * type10hex,record sequence,low16(header+length). Failed send0 releases credit
 * then restores motion deltas iff metadata was attached. Nonzero send succeeds.
 * Special frames have flag4,prefix byte and length+7 truncated16. Suppression
 * caches slot before time/predicate calls. Predicate0 clears its timestamp;
 * otherwise start0 becomes low32(now)|1, and elapsed<450000 retries. The odd
 * forced timestamp deliberately retains unsigned underflow: an even initial
 * now can immediately pass the threshold. Suppressed/failed special work uses
 * fresh record slot/generation and fenced halted before setting special_retry.
 * Successful sends do not independently release credits or clear retries.
 * Transform,transport,watchdog timing and queue/DMA ownership remain callees'
 * responsibilities; this task supplies no atomic state snapshot. */
void medius_task_hidfwd(void *unused_argument)
{
    (void)unused_argument;
    MediusHidWork work;
    unsigned char metadata[32];
    volatile MediusHidForwardFrame *frame = MEDIUS_HID_FORWARD_FRAME;
    medius_worker_watchdog_add();
    for (;;) {
        int received;
        do {
            medius_worker_watchdog_feed();
            received = xQueueReceive(MEDIUS_HID_REPORT_QUEUE,&work,1000);
        } while (received == 0);
        memw();
        unsigned int inhibited = MEDIUS_HOST_FORWARDING_INHIBIT;
        unsigned int special = work.special;
        if (inhibited != 0) {
            if (special == 0) { medius_hid_credit_release(&work); continue; }
            goto special_retry;
        }
        unsigned int stamp = work.source_stamp;
        unsigned int endpoint = work.endpoint;
        frame->endpoint_and_stamp_low24 = endpoint | (stamp << 8);
        frame->stamp_high = (unsigned char)(stamp >> 24);
        if (special == 0) {
            unsigned int copy_length = work.length;
            unsigned int header_length = 6;
            if (copy_length != 0 && medius_motion_prepare_hid_metadata(endpoint,stamp,work.data,copy_length,metadata) != 0) {
                frame->flags = 1;
                memcpy((void *)frame->payload,metadata,26);
                header_length = 32;
                copy_length = work.length;
            } else {
                copy_length = work.length;
                frame->flags = 0;
            }
            if (work.report_flag != 0) frame->flags = frame->flags | 2U;
            memcpy((unsigned char *)frame+header_length,work.data,copy_length);
            int sent = link_send_wait100(0x10,work.sequence,(const void *)frame,
                (unsigned short)(header_length+work.length));
            if (sent == 0) {
                medius_hid_credit_release(&work);
                if (header_length != 6) medius_motion_delta_restore(metadata);
            }
            continue;
        }
        unsigned int slot = work.slot;
        unsigned int now = (unsigned int)esp_timer_get_time();
        int suppressed = medius_endpoint_suppression_active(work.endpoint);
        volatile MediusHidEndpointState *state = &MEDIUS_HOST_HID_ENDPOINTS[slot];
        if (suppressed == 0) state->suppressed_since_us = 0;
        else {
            unsigned int started = state->suppressed_since_us;
            if (started == 0) { started = now | 1U; state->suppressed_since_us = started; }
            if (now-started < 450000U) goto special_retry;
        }
        frame->flags = 4;
        frame->payload[0] = work.special_prefix;
        memcpy((void *)(frame->payload+1),work.data,work.length);
        if (link_send_wait100(0x10,work.sequence,(const void *)frame,(unsigned short)(work.length+7U)) != 0) continue;
special_retry:;
        volatile MediusHidEndpointState *retry = &MEDIUS_HOST_HID_ENDPOINTS[work.slot];
        if (work.generation == retry->generation) {
            memw();
            if (retry->halted != 0) { memw(); retry->special_retry = 1; }
        }
    }
}

/* Native entry: 0x403896d4. */
/* Original function-byte SHA-256:
 * 0f827e86eca141407c4d37bf55ae8e824fcebafd7bcb5b3c655dfd82d3b3e0ee. */
/* Completion context is a live HID endpoint state. Set in_callback and sample
 * low16 HFNUM into last_callback_frame. Inactive state only releases frame
 * participation and clears in_callback, leaving armed unchanged. Fully eligible
 * (unhalted,locally/globally unpaused) cancellation-13 clears armed/active;
 * STALL-8 clears armed,sets halted/special_valid,clamps unsigned URB.actual to64,
 * caches the ordered-ack byte and enqueues special work from ISR,then releases.
 * Other eligible negative results can rearm without reporting. Successful data
 * forwards even when locally halted/paused,provided global pause0. Cache MPS
 * before writing last_report_frame; report flag uses low16(result),shorter than
 * transfer_length and divisible by nonzero MPS (including result0). Forward the
 * FULL result to normal enqueue. Fresh unhalted/unpaused period<2 delegates
 * credit-gated rearm; result1 retains participation,others release. Negative
 * except-6 marks needs_rearm/global retry. This branch leaves armed to rearm.
 * Remaining active paths clear armed before release. No state/URB lifetime or
 * bounds validation,global-pause recheck after enqueue,or atomic callback handoff. */
void medius_hid_transfer_complete(void *context,int result)
{
    volatile MediusHidEndpointState *state = context;
    memw(); state->in_callback = 1;
    memw(); unsigned int frame = MEDIUS_HOST_USB_REGISTERS->frame_number;
    memw(); state->last_callback_frame = (unsigned short)frame;
    memw(); if (state->active == 0) goto release_only;
    memw();
    if (state->halted == 0) {
        memw();
        if (state->paused == 0) {
            memw(); if (MEDIUS_HOST_HID_PAUSED != 0) goto clear_armed;
            if (result == -13) {
                memw(); state->armed = 0;
                memw(); state->active = 0;
                goto release_only;
            }
            if (result == -8) {
                const volatile MediusHidInterface *interface = state->interface_handle;
                memw(); state->armed = 0;
                unsigned int actual = interface->urb.actual;
                memw(); state->halted = 1;
                memw(); state->special_valid = 1;
                memw(); unsigned char prefix = MEDIUS_HOST_ORDERED_LAST_ACK;
                state->special_length = (unsigned char)(actual > 64U ? 64U : actual);
                state->suppressed_since_us = 0;
                medius_hid_special_enqueue((MediusHidEndpointState *)state,1,prefix);
                goto release_only;
            }
            if (result >= 0) goto report_data;
            goto try_rearm;
        }
    }
    if (result >= 0) { memw(); if (MEDIUS_HOST_HID_PAUSED == 0) goto report_data; }
    goto clear_armed;
report_data:
    memw(); frame = MEDIUS_HOST_USB_REGISTERS->frame_number;
    unsigned int max_packet = state->max_packet;
    memw(); state->last_report_frame = (unsigned short)frame;
    unsigned char report_flag = 0;
    if (max_packet != 0 && ((unsigned int)result & 65535U) < state->transfer_length)
        report_flag = (unsigned char)(((unsigned int)result & 65535U)%max_packet == 0);
    medius_hid_report_enqueue((MediusHidEndpointState *)state,result,report_flag,1);
try_rearm:
    memw();
    if (state->halted == 0) {
        memw();
        if (state->paused == 0) {
            memw();
            if (state->poll_period < 2) {
                int rearmed = medius_hid_rearm_with_credit_gate((MediusHidEndpointState *)state);
                if (rearmed != 1) {
                    medius_hid_release_frame_participation((MediusHidEndpointState *)state);
                    if (rearmed < 0 && rearmed != -6) {
                        memw(); state->needs_rearm = 1;
                        memw(); MEDIUS_HID_RETRY_PENDING = 1;
                    }
                }
                memw(); state->in_callback = 0;
                return;
            }
        }
    }
clear_armed:
    memw(); state->armed = 0;
release_only:
    medius_hid_release_frame_participation((MediusHidEndpointState *)state);
    memw(); state->in_callback = 0;
}

/* Native entry: 0x40389864. */
/* Original function-byte SHA-256:
 * 26150ab41975136d607d96efdb7fd95e91c80aac66d16974364d66a25601f689. */
/* Fenced halted/paused samples return0 before touching the interface. Cache
 * interface,hubport,endpoint; any NULL returns-1. Snapshot slot/transfer length
 * and populate the embedded asynchronous URB: setupNULL,timeout0,hub/endpoint,
 * DMA base+slot*128,length,callback/context. Interval is descriptor.interval*1000
 * for speed<3,otherwise125<<((interval-1)&31),retaining native shift wrapping.
 * Store the FULL scheduling preference,not a normalized bit. Sample HFNUM before
 * and after submit,regardless of its result; equal low16 readings publish
 * low14(before+(preference XOR1)),otherwiseFFFF. Return submit's result unchanged.
 * No buffer/slot/descriptor-length/connection check or local armed change. */
int medius_hid_submit_read(MediusHidEndpointState *endpoint_state,int keep_frame_parity)
{
    volatile MediusHidEndpointState *state = endpoint_state;
    memw(); if (state->halted != 0) return 0;
    memw(); if (state->paused != 0) return 0;
    volatile MediusHidInterface *interface = state->interface_handle;
    if (interface == 0) return -1;
    MediusHostHubPortPrefix *hubport = interface->hubport;
    if (hubport == 0) return -1;
    MediusHostEndpointDescriptor *endpoint = interface->endpoint;
    if (endpoint == 0) return -1;
    unsigned int slot = state->slot;
    unsigned int length = state->transfer_length;
    interface->urb.setup = 0;
    interface->urb.timeout = 0;
    interface->urb.hubport = hubport;
    interface->urb.endpoint = (unsigned char *)endpoint;
    interface->urb.buffer = MEDIUS_HID_DMA_BASE+slot*128U;
    interface->urb.remaining = length;
    interface->urb.complete = medius_hid_transfer_complete;
    interface->urb.context = endpoint_state;
    unsigned int speed = ((const volatile MediusHostHubPortPrefix *)hubport)->speed;
    unsigned int interval = ((const volatile MediusHostEndpointDescriptor *)endpoint)->interval;
    interface->urb.interval_us = speed < 3 ? interval*1000U : 125U << ((interval-1U) & 31U);
    interface->urb.scheduling_flags = (unsigned int)keep_frame_parity;
    memw(); unsigned int before = MEDIUS_HOST_USB_REGISTERS->frame_number;
    int submitted = usbh_submit_urb((MediusHostUrb *)&interface->urb);
    memw(); unsigned int after = MEDIUS_HOST_USB_REGISTERS->frame_number;
    unsigned short scheduled = 65535;
    if ((before & 65535U) == (after & 65535U))
        scheduled = (unsigned short)((before+((unsigned int)keep_frame_parity ^ 1U)) & 16383U);
    memw(); state->scheduled_frame = scheduled;
    return submitted;
}

/* Native entry: 0x40389918. */
/* Original function-byte SHA-256:
 * 4fab17681d376ed7d15b4ff11f71d356ba4050af9a719a31ab889d4af785c102. */
/* Slow-poll eligibility is sampled in order: active,period>=2,!needs_rearm,
 * !armed,!paused,!halted,!global_pause. Failures return before timer/lock.
 * Snapshot time; query ISR context,lock credit,scan using hid_credit_allows,
 * query ISR context and unlock. Credit denial changes no endpoint/history data.
 * If allowed,optional phase samples HFNUM then HFIR and selects preference1
 * when upper16(HFNUM)>=((HFIR>>1)&7fff),otherwise0. Set armed before submission.
 * Negative result except-6 clears armed and sets needs_rearm/global retry;
 * success and-6 preserve armed1. No credit_blocked mutation or eligibility
 * recheck after unlock,or atomic coordination with reset/callback,occurs here. */
void medius_hid_try_slow_poll(MediusHidEndpointState *endpoint_state,int use_frame_phase)
{
    volatile MediusHidEndpointState *state = endpoint_state;
    memw(); if (state->active == 0) return;
    memw(); if (state->poll_period < 2) return;
    memw(); if (state->needs_rearm != 0) return;
    memw(); if (state->armed != 0) return;
    memw(); if (state->paused != 0) return;
    memw(); if (state->halted != 0) return;
    memw(); if (MEDIUS_HOST_HID_PAUSED != 0) return;
    unsigned long long now = (unsigned long long)esp_timer_get_time();
    xPortInIsrContext();
    xPortEnterCriticalTimeout(&MEDIUS_HID_CREDIT_LOCK,-1);
    int allowed = hid_credit_allows(state,now);
    xPortInIsrContext();
    vPortExitCritical(&MEDIUS_HID_CREDIT_LOCK);
    if (!allowed) return;
    int preference = 0;
    if (use_frame_phase != 0) {
        memw(); unsigned int frame = MEDIUS_HOST_USB_REGISTERS->frame_number;
        memw(); unsigned int interval = MEDIUS_HOST_USB_REGISTERS->frame_interval;
        preference = (frame >> 16) >= ((interval >> 1) & 32767U);
    }
    memw(); state->armed = 1;
    int submitted = medius_hid_submit_read(endpoint_state,preference);
    if (submitted < 0 && submitted != -6) {
        memw(); state->armed = 0;
        memw(); state->needs_rearm = 1;
        memw(); MEDIUS_HID_RETRY_PENDING = 1;
    }
}

/* Native entry: 0x40389ad0. */
/* Original function-byte SHA-256:
 * 1d0f540249c28a64a87d98ee2587d1b30bf40f7e29967fac363dbff3e848dbeb. */
/* Zero record bytes2..79 with39 halfword stores,then write endpoint/slot as a
 * halfword (slot sampled first). Sample source time,then fresh slot/length;
 * store length,low32 stamp,special1,prefix and copy special_length DMA bytes.
 * No independent length/slot clamp. Sample a second time into last_special_us.
 * Under credit lock after ISR query,sample generation then sequence as a
 * halfword;query ISR and unlock. Clear special_retry before reading queue handle.
 * Task send is nonblocking; nonzero from_isr uses ISR send with wake initially0
 * and copy-position0. Send result!=1 sets special_retry1. Yield on nonzero wake
 * even when send failed. Does not increment report sequence/history/drop count. */
void medius_hid_special_enqueue(MediusHidEndpointState *endpoint_state,int from_isr,unsigned char prefix)
{
    volatile MediusHidEndpointState *state = endpoint_state;
    MediusHidWork work;
    volatile unsigned short *clear = (volatile void *)((unsigned char *)&work+2);
    for (unsigned int halfword = 0; halfword < 39; ++halfword) clear[halfword] = 0;
    unsigned int slot = state->slot;
    unsigned int endpoint = state->endpoint;
    work.endpoint_slot = (unsigned short)(endpoint | (slot << 8));
    unsigned int stamp = (unsigned int)esp_timer_get_time();
    slot = state->slot;
    unsigned int length = state->special_length;
    work.length = (unsigned short)length;
    work.source_stamp = stamp;
    work.special = 1;
    work.special_prefix = prefix;
    memcpy(work.data,MEDIUS_HID_DMA_BASE+slot*128U,length);
    state->last_special_us = (unsigned int)esp_timer_get_time();
    xPortInIsrContext();
    xPortEnterCriticalTimeout(&MEDIUS_HID_CREDIT_LOCK,-1);
    unsigned int generation = state->generation;
    unsigned int sequence = state->report_sequence;
    work.sequence_generation = (unsigned short)(sequence | (generation << 8));
    xPortInIsrContext();
    vPortExitCritical(&MEDIUS_HID_CREDIT_LOCK);
    int wake = 0;
    memw(); state->special_retry = 0;
    RtosQueue *queue = MEDIUS_HID_REPORT_QUEUE;
    int sent = from_isr == 0 ? xQueueGenericSend(queue,&work,0,0) : xQueueGenericSendFromISR(queue,&work,&wake,0);
    if (sent != 1) { memw(); state->special_retry = 1; }
    if (wake != 0) _frxt_setup_switch();
}

/* Native entry: 0x40389b88. */
/* Original function-byte SHA-256:
 * af0b7c4e12f38f7537c86c500ffc484b516b4b7e20db01b92b8df68fb71be613. */
/* Sample time before credit lock; store its raw low32 in the80-byte record.
 * Increment sequence modulo256,publish history LOW then HIGH (zero time becomes1),
 * and sample generation into a header halfword. ISR queries surround this lock.
 * Cache slot,then positive lengths update inter-report minimum/sample statistics;
 * the16-bit sample increment wraps and publishes/resets only above255.
 *
 * Copy count is low16(min_signed(length,64)),NOT a negative-length rejection:
 * -1 requests65535,-65535 requests1,-65536/INT_MIN request0. Preserve this native
 * unsafe count. Endpoint and old slot form the record; clear needs_rearm before
 * copying. Nonempty data may publish a matching endpoint/report-ID activity stamp,
 * then copies cache at a FRESH slot and stores length using ANOTHER fresh slot.
 * Zero-length data leaves cache unchanged. Byte12,unused data suffix and three
 * tail bytes retain stack contents copied by the fixed80-byte queue item.
 *
 * Task/ISR send is nonblocking with wake0/copy-position0. Failure increments the
 * shared32-bit drop counter,then under credit lock clears the sent history slot
 * only when modulo256(current_sequence-sent_sequence)<8;generation is unchecked.
 * Cache/statistics already published are not undone. Yield for nonzero wake even
 * on failure. No pointer/slot/capacity checks or DMA ownership/lifetime lock. */
void medius_hid_report_enqueue(MediusHidEndpointState *endpoint_state,int length,unsigned char report_flag,int from_isr)
{
    volatile MediusHidEndpointState *state = endpoint_state;
    MediusHidWork work; /* Native normal records leave unused bytes untouched. */
    unsigned long long now = (unsigned long long)esp_timer_get_time();
    work.source_stamp = (unsigned int)now;
    xPortInIsrContext();
    xPortEnterCriticalTimeout(&MEDIUS_HID_CREDIT_LOCK,-1);
    unsigned int sequence = (state->report_sequence+1U) & 255U;
    state->report_sequence = (unsigned char)sequence;
    volatile ClockWords *history = (volatile void *)&state->report_history[sequence & 7U];
    unsigned long long stamp = now == 0 ? 1 : now;
    history->low = (unsigned int)stamp;
    history->high = (unsigned int)(stamp >> 32);
    unsigned int generation = state->generation;
    work.sequence_generation = (unsigned short)(sequence | (generation << 8));
    xPortInIsrContext();
    vPortExitCritical(&MEDIUS_HID_CREDIT_LOCK);
    unsigned int slot = state->slot;
    work.slot = (unsigned char)slot;
    if (length > 0) {
        memw(); unsigned int previous = MEDIUS_HID_LAST_REPORT_US;
        memw(); MEDIUS_HID_LAST_REPORT_US = work.source_stamp;
        memw(); unsigned int minimum = MEDIUS_HID_MIN_REPORT_DELTA;
        unsigned int elapsed = work.source_stamp-previous;
        if (elapsed < minimum) { memw(); MEDIUS_HID_MIN_REPORT_DELTA = elapsed; }
        memw(); unsigned short samples = (unsigned short)(MEDIUS_HID_TIMING_SAMPLES+1U);
        memw(); MEDIUS_HID_TIMING_SAMPLES = samples;
        if (samples > 255) {
            memw(); minimum = MEDIUS_HID_MIN_REPORT_DELTA;
            memw(); MEDIUS_HID_PUBLISHED_REPORT_DELTA = minimum;
            memw(); MEDIUS_HID_MIN_REPORT_DELTA = 0xffffffffU;
            memw(); MEDIUS_HID_TIMING_SAMPLES = 0;
        }
    }
    int bounded = length < 64 ? length : 64;
    unsigned int copy_length = (unsigned short)bounded;
    unsigned int endpoint = state->endpoint;
    memw(); state->needs_rearm = 0;
    work.endpoint = (unsigned char)endpoint;
    work.length = (unsigned short)bounded;
    work.report_flag = report_flag;
    work.special = 0;
    memcpy(work.data,MEDIUS_HID_DMA_BASE+slot*128U,copy_length);
    if (work.length != 0) {
        memw(); unsigned int selector = MEDIUS_HID_ACTIVITY_SELECTOR;
        if (selector != 0 && work.endpoint == (selector & 255U) &&
            ((selector >> 8) == 0 || work.data[0] == (selector >> 8))) {
            memw(); MEDIUS_HID_ACTIVITY_TIME = work.source_stamp;
        }
        unsigned int cache_slot = state->slot;
        memcpy(MEDIUS_HID_CACHED_REPORTS[cache_slot],work.data,work.length);
        unsigned int length_slot = state->slot;
        unsigned short cache_length = work.length;
        memw(); MEDIUS_HID_CACHED_LENGTHS[length_slot] = cache_length;
    }
    int wake = 0;
    RtosQueue *queue = MEDIUS_HID_REPORT_QUEUE;
    int sent = from_isr == 0 ? xQueueGenericSend(queue,&work,0,0) : xQueueGenericSendFromISR(queue,&work,&wake,0);
    if (sent != 1) {
        memw(); unsigned int dropped = MEDIUS_HID_DROP_COUNT;
        memw(); MEDIUS_HID_DROP_COUNT = dropped+1U;
        xPortInIsrContext();
        xPortEnterCriticalTimeout(&MEDIUS_HID_CREDIT_LOCK,-1);
        unsigned int sent_sequence = work.sequence;
        unsigned int current_sequence = state->report_sequence;
        if (((current_sequence-sent_sequence) & 255U) < 8U) {
            history = (volatile void *)&state->report_history[sent_sequence & 7U];
            history->low = 0;
            history->high = 0;
        }
        xPortInIsrContext();
        vPortExitCritical(&MEDIUS_HID_CREDIT_LOCK);
    }
    if (wake != 0) _frxt_setup_switch();
}

/* Native entry: 0x40389d44. */
/* Original function-byte SHA-256:
 * 42a1cd90c63b899ecea2413e34de538df0403df48636420de828c60dabf5b88e. */
/* Snapshot time,query ISR context and enter credit lock. The shared scan caches
 * retained-valid then sequence; retained entries start the count and restrict
 * scanning to min(modulo256(seq-base),8),otherwise scan all8. Cache protection
 * flag once; reached nonzero history entries count when distance to the live
 * protection base is1..8,or signed64(entry+sign_extended window)>reference.
 * Saturate count255. Limit is raw credit_limit plus1 when nonzero boost start
 * has signed64(now-start)<duration; future times/negative windows are retained.
 *
 * Count>=limit clears armed,sets credit_blocked,queries ISR,unlocks and returns1.
 * Otherwise clear credit_blocked,query ISR,unlock,set armed and submit with
 * preference0. Return its result; negative except-6 clears armed only. This
 * function has no eligibility gates and does not set retry/needs_rearm on error
 * or mutate history/sequence/retained metadata. Caller decides frame release. */
int medius_hid_rearm_with_credit_gate(MediusHidEndpointState *endpoint_state)
{
    volatile MediusHidEndpointState *state = endpoint_state;
    unsigned long long now = (unsigned long long)esp_timer_get_time();
    xPortInIsrContext();
    xPortEnterCriticalTimeout(&MEDIUS_HID_CREDIT_LOCK,-1);
    if (!hid_credit_allows(state,now)) {
        memw(); state->armed = 0;
        memw(); state->credit_blocked = 1;
        xPortInIsrContext();
        vPortExitCritical(&MEDIUS_HID_CREDIT_LOCK);
        return 1;
    }
    memw(); state->credit_blocked = 0;
    xPortInIsrContext();
    vPortExitCritical(&MEDIUS_HID_CREDIT_LOCK);
    memw(); state->armed = 1;
    int submitted = medius_hid_submit_read(endpoint_state,0);
    if (submitted < 0 && submitted != -6) { memw(); state->armed = 0; }
    return submitted;
}

/* Native entry: 0x40389f70. */
/* Original function-byte SHA-256:
 * efdbad488251c6b298b3c737071671b9a3f26f7359fd77f82f66f26fcd5a409b. */
/* SOF scheduling has two outside-lock polling phases. An initial fenced
 * nonzero pending-mask sample enters the frame lock,refreshes/snapshots that
 * mask,clears it and the participant byte,then unlocks and calls the selected
 * low6 slow-poll slots with preference1. High mask bits are discarded. Only
 * afterward sample low16 HFNUM; callbacks can therefore advance this frame.
 *
 * Mode1 is selected by the first active period<2,unpaused,unhalted HID state;
 * otherwise query the vendor interrupt-IN detector. After locking,nonzero
 * vendor result also becomes mode1. In that mode,write all six participation
 * fields: current raw16 frame only for active fast,armed,!needs_rearm,!paused,
 * !halted,single-packet (or MPS0),scheduled==current and callback!=current;
 * otherwiseFFFF. Count them LOCALLY. Mode0 leaves those fields untouched.
 * Publish the current frame halfword. No global pending-mask/count publication
 * is performed during these scans,contrary to the old decompiler expression.
 *
 * Scan slow slots by cached period>1 then active. Read poll_phase once to test
 * bit15: set means phase0; clear means a SECOND fenced raw16 phase read. Use
 * period-1 as a mask,without enforcing a power of two. With participants,or
 * in mode0,match next raw16 frame but deduplicate/stamp next frame masked14.
 * In mode1 without participants,match/deduplicate/stamp current raw16 frame.
 * No paused/halted/armed checks are performed for selecting slow slots here.
 *
 * Finally publish selected pending bits and participant count only when fast
 * participants AND slow selections exist. Otherwise participants becomes0;
 * no-participant paths also clear pending then unlock and poll selected slots
 * immediately with preference=mode. Participant paths never poll immediately.
 * All critical sections retain ISR-context queries; every poll is outside the
 * frame lock. Callback/state/frame changes between phases are not an atomic
 * snapshot. No bounds/admission/period normalization or hardware timing promise. */
void medius_hid_sof_schedule(void)
{
    memw();
    if (MEDIUS_HID_PENDING_POLLS != 0) {
        xPortInIsrContext();
        xPortEnterCriticalTimeout(&MEDIUS_HID_FRAME_LOCK,-1);
        memw(); unsigned int pending = MEDIUS_HID_PENDING_POLLS;
        memw(); MEDIUS_HID_PENDING_POLLS = 0;
        memw(); MEDIUS_HID_FRAME_PARTICIPANTS = 0;
        xPortInIsrContext();
        vPortExitCritical(&MEDIUS_HID_FRAME_LOCK);
        for (unsigned int slot = 0; slot < 6; ++slot)
            if ((pending & (1U << slot)) != 0)
                medius_hid_try_slow_poll((MediusHidEndpointState *)&MEDIUS_HOST_HID_ENDPOINTS[slot],1);
    }
    memw(); unsigned int current = MEDIUS_HOST_USB_REGISTERS->frame_number & 65535U;
    unsigned int next = (current+1U) & 65535U;
    unsigned int next_stamp = (current+1U) & 16383U;
    unsigned int mode = 0;
    for (unsigned int slot = 0; slot < 6; ++slot) {
        volatile MediusHidEndpointState *state = &MEDIUS_HOST_HID_ENDPOINTS[slot];
        memw(); if (state->active == 0) continue;
        memw(); if (state->poll_period >= 2) continue;
        memw(); if (state->paused != 0) continue;
        memw(); if (state->halted != 0) continue;
        mode = 1;
        break;
    }
    if (mode == 0) mode = medius_vendor_has_interrupt_in();
    xPortInIsrContext();
    xPortEnterCriticalTimeout(&MEDIUS_HID_FRAME_LOCK,-1);
    unsigned int participants = 0;
    if (mode != 0) {
        for (unsigned int slot = 0; slot < 6; ++slot) {
            volatile MediusHidEndpointState *state = &MEDIUS_HOST_HID_ENDPOINTS[slot];
            unsigned short participation = 65535;
            memw(); if (state->active == 0) goto publish_participation;
            memw(); if (state->poll_period >= 2) goto publish_participation;
            memw(); if (state->armed == 0) goto publish_participation;
            memw(); if (state->needs_rearm != 0) goto publish_participation;
            memw(); if (state->paused != 0) goto publish_participation;
            memw(); if (state->halted != 0) goto publish_participation;
            unsigned int max_packet = state->max_packet;
            if (max_packet != 0) {
                unsigned int length = state->transfer_length;
                /* Both inputs are16-bit; numerator is nonnegative and<=131069.
                 * Thus this quotient equals the native signed QUOS result. */
                if (((length+max_packet-1U)/max_packet & 65535U) != 1U) goto publish_participation;
            }
            memw(); if (state->scheduled_frame != current) goto publish_participation;
            memw(); if (state->last_callback_frame == current) goto publish_participation;
            participants = (participants+1U) & 255U;
            participation = (unsigned short)current;
publish_participation:
            memw(); state->participation_frame = participation;
        }
        mode = 1;
    }
    memw(); MEDIUS_HID_PARTICIPATION_FRAME = (unsigned short)current;
    unsigned int selected = 0;
    for (unsigned int slot = 0; slot < 6; ++slot) {
        volatile MediusHidEndpointState *state = &MEDIUS_HOST_HID_ENDPOINTS[slot];
        memw(); unsigned int period = state->poll_period;
        if (period < 2) continue;
        memw(); if (state->active == 0) continue;
        memw(); unsigned int first_phase = state->poll_phase;
        unsigned int phase = 0;
        if ((first_phase & 32768U) == 0) { memw(); phase = state->poll_phase; }
        unsigned int mask = (period-1U) & 65535U;
        unsigned int match_frame,stamp;
        if (participants != 0 || mode == 0) { match_frame = next; stamp = next_stamp; }
        else { match_frame = current; stamp = current; }
        if (phase != (match_frame & mask)) continue;
        memw(); if (state->slow_poll_frame == stamp) continue;
        memw(); state->slow_poll_frame = (unsigned short)stamp;
        selected |= 1U << slot;
    }
    memw(); MEDIUS_HID_PENDING_POLLS = participants == 0 ? 0 : selected;
    memw(); MEDIUS_HID_FRAME_PARTICIPANTS = selected == 0 ? 0 : (unsigned char)participants;
    xPortInIsrContext();
    vPortExitCritical(&MEDIUS_HID_FRAME_LOCK);
    if (participants == 0) {
        for (unsigned int slot = 0; slot < 6; ++slot)
            if ((selected & (1U << slot)) != 0)
                medius_hid_try_slow_poll((MediusHidEndpointState *)&MEDIUS_HOST_HID_ENDPOINTS[slot],(int)mode);
    }
}

/* Native entry: 0x42009574. */
/* Original function-byte SHA-256:
 * da49e0aaa3dfd8e93faae6af7984e225ca787895246097091f349608a63dbc8d. */
/* Build the interface GET_DESCRIPTOR(report) request and forward the control result.
 * hid: Optional class; NULL class or cached port returns -2 before any write.
 * buffer: Borrowed data buffer passed unchanged to the control-transfer helper.
 * length: Only its low 16 bits enter wLength; 65536 therefore requests zero.
 * Cache port/setup once. Write eight individual SETUP bytes, sampling the
 * interface index after the first four writes. SETUP mutation precedes the
 * delegated control lock; there is no local buffer/setup/connection check.
 * Return the helper's signed result unchanged, including its SETUP overhead. */
int usbh_hid_get_report_descriptor(MediusHostHidClass *hid,uchar *buffer,uint length)
{
    if (hid == NULL)
        return -2;
    MediusHostHubPortPrefix *port = ((const volatile MediusHostHidClass *)hid)->port;
    if (port == NULL)
        return -2;
    volatile uchar *setup = ((const volatile MediusHostHubPortPrefix *)port)->setup;
    setup[0] = 0x81;
    setup[1] = 0x06;
    setup[2] = 0;
    setup[3] = 0x22;
    setup[4] = ((const volatile MediusHostHidClass *)hid)->interface_index;
    setup[5] = 0;
    setup[6] = (uchar)length;
    setup[7] = (uchar)(length >> 8);
    return usbh_control_transfer(port,(uchar *)setup,buffer);
}

/* Native entry: 0x420095bc. */
/* Original function-byte SHA-256:
 * 6880575a7c5461c3fe59f2f7ef870d26928bb1f1ddcf0effe2983c2b90b1cdc0. */
/* Build SET_IDLE for one interface, with no data phase, and return its result.
 * hid: Optional class; NULL class or cached port returns -2 without writes.
 * report_id/duration: Raw bytes placed in wValue low/high; no conversion here.
 * Cache port/setup once, write eight individual SETUP bytes, and sample the
 * interface index after the request/value writes. Call control transfer once
 * with NULL data. No local connection/setup check, lock or retry is provided;
 * SETUP writes occur before the delegated control lock. */
int usbh_hid_set_idle(MediusHostHidClass *hid,uchar report_id,uchar duration)
{
    if (hid == NULL)
        return -2;
    MediusHostHubPortPrefix *port = ((const volatile MediusHostHidClass *)hid)->port;
    if (port == NULL)
        return -2;
    volatile uchar *setup = ((const volatile MediusHostHubPortPrefix *)port)->setup;
    setup[0] = 0x21;
    setup[1] = 0x0a;
    setup[2] = report_id;
    setup[3] = duration;
    setup[4] = ((const volatile MediusHostHidClass *)hid)->interface_index;
    setup[5] = 0;
    setup[6] = 0;
    setup[7] = 0;
    return usbh_control_transfer(port,(uchar *)setup,NULL);
}

/* Native entry: 0x42009600. */
/* Original function-byte SHA-256:
 * 6da93f017c124f88850aa013a597572065de1272142cb4f075c2798e2f33d211. */
/* Reserve a HID class slot, extract report metadata and attach the interface.
 * port/interface_index: Live parsed port and raw byte index; unchecked here.
 * Return -1 if snapshot mask bits 0..5 are occupied, otherwise 0 even if
 * formatting or application attachment fails. No reservation rollback occurs.
 *
 * Reserve the first free bit from one mask snapshot, zero the 160-byte class,
 * and publish its minor/interface/port/private binding before parsing. Raw
 * wTotalLength is read HIGH then LOW; its allocation span is not validated.
 * Scan for the requested interface at alternate zero, recording protocol.
 * A matching interface rereads bLength after protocol publication. Types
 * CONFIGURATION, INTERFACE and IAD stop a matched scan. The first following
 * HID descriptor ends the search even when invalid; select its first bounded
 * REPORT subentry, reading report length HIGH then LOW. Missing metadata is 0.
 *
 * Reload the parsed interface table before HID validation or after scan end;
 * total<2 retains the original entry. Cache its first alternate BEFORE storing
 * report length. Scan its cached endpoint count in seven-byte strides: address
 * bit 7 alone selects direction and the last endpoint of each direction wins.
 * No class, transfer-type, MPS or alternate correspondence check is added.
 * Format the entry's 16-byte name using the fresh minor, then attach once.
 * The formatter is a typed native callee boundary, not a reviewed body here.
 * No local locking, pointer/index/lifetime checks or atomic mask update exist;
 * malformed input can leave the slot reserved and private_data published. */
int medius_host_hid_class_connect(MediusHostHubPortPrefix *port,uchar interface_index)
{
    uint mask = MEDIUS_HOST_HID_CLASS_MASK;
    uint slot;
    for (slot = 0; slot < 6; ++slot) {
        if ((mask & (1U << slot)) == 0)
            break;
    }
    if (slot == 6)
        return -1;
    MediusHostHidClass *hid = &MEDIUS_HOST_HID_CLASSES[slot];
    MEDIUS_HOST_HID_CLASS_MASK = mask | (1U << slot);
    memset(hid,0,160);
    volatile MediusHostHidClass *state = hid;
    state->minor = (uchar)slot;
    state->interface_index = interface_index;
    MediusHostInterfacePrefix *interfaces =
        *(MediusHostInterfacePrefix * const volatile *)&port->interfaces;
    const volatile uchar *raw = *(uchar * const volatile *)&port->raw_configuration;
    state->port = port;
    MediusHostInterfacePrefix *entry =
        (MediusHostInterfacePrefix *)((uint)interfaces + (uint)interface_index * 32U);
    *(void * volatile *)&entry->private_data = hid;
    uint total_high = raw[3];
    uint total_low = raw[2];
    uint total_length = (total_high << 8) | total_low;
    ushort report_length = 0;
    if (total_length >= 2) {
        uint offset = 0;
        int interface_found = 0;
        do {
            const volatile uchar *descriptor = (const volatile uchar *)((uint)raw + offset);
            uint descriptor_length = descriptor[0];
            uint next_offset = offset + descriptor_length;
            if (descriptor_length < 2 || next_offset > total_length)
                break;
            uchar type = descriptor[1];
            if (type == 2 || type == 4 || type == 11) {
                if (interface_found)
                    break;
                if (type == 4 && descriptor_length >= 9 &&
                    descriptor[2] == interface_index && descriptor[3] == 0) {
                    state->protocol = descriptor[7];
                    next_offset = offset + descriptor[0];
                    interface_found = 1;
                }
            } else if (type == 0x21 && interface_found) {
                /* Native reload happens BEFORE HID length/type/count validation. */
                interfaces = *(MediusHostInterfacePrefix * const volatile *)&port->interfaces;
                entry = (MediusHostInterfacePrefix *)((uint)interfaces + (uint)interface_index * 32U);
                if (descriptor_length >= 6 && descriptor[1] == 0x21) {
                    uint declared_entries = descriptor[5];
                    for (uint subentry = 0; subentry < declared_entries; ++subentry) {
                        uint entry_offset = subentry * 3U;
                        if (entry_offset + 9U > descriptor_length)
                            break;
                        if (descriptor[entry_offset + 6U] == 0x22) {
                            uint report_high = descriptor[entry_offset + 8U];
                            uint report_low = descriptor[entry_offset + 7U];
                            report_length = (ushort)((report_high << 8) | report_low);
                            break;
                        }
                    }
                }
                goto select_endpoints;
            }
            offset = next_offset & 0xffffU;
        } while (offset + 2U <= total_length);
        interfaces = *(MediusHostInterfacePrefix * const volatile *)&port->interfaces;
        entry = (MediusHostInterfacePrefix *)((uint)interfaces + (uint)interface_index * 32U);
    }

select_endpoints:
    MediusHostAlternatePrefix *alternate =
        *(MediusHostAlternatePrefix * const volatile *)&entry->alternates;
    state->report_length = report_length;
    uint endpoint_count = *(const volatile uchar *)&alternate->endpoint_count;
    if (endpoint_count != 0) {
        const volatile uchar *endpoint = *(uchar * const volatile *)&alternate->endpoints;
        for (uint remaining = endpoint_count; remaining != 0; --remaining) {
            uchar address = endpoint[2];
            if ((address & 0x80U) != 0)
                state->in_endpoint = (uchar *)endpoint;
            else
                state->out_endpoint = (uchar *)endpoint;
            endpoint = (const volatile uchar *)((uint)endpoint + 7U);
        }
    }
    uchar minor = state->minor;
    MEDIUS_HOST_SNPRINTF((char *)entry->name,16,"/dev/input%d",(int)minor);
    medius_hid_attach_interface(hid);
    return 0;
}

/* Native entry: 0x420097c4. */
/* Original function-byte SHA-256:
 * c335dd894dc785d6f971434963db9343047f19b536b14c755fe56fa3b4d88748. */
/* Cancel one cached HID class, notify removal when named, then release its slot.
 * port/interface_index: Live parsed port and raw byte index; unchecked here.
 * Return 0, including when private_data is NULL. Cache that private pointer
 * once. IN presence gates cancellation of embedded in_urb; then a fresh OUT
 * presence gates out_urb. Ignore both results. Reload the port's interface
 * table/name after cancellation. A nonempty name causes a scheduling yield
 * followed by application removal on the cached class, with no name recheck.
 * Read minor after callbacks; values<32 clear that bit in the current mask,
 * even though allocation only uses six bits. Then zero exactly 160 bytes.
 * Name, class_driver and private_data remain untouched; a repeated call can
 * reach cleared/reused storage. No lock, lifetime retention or callback/DMA
 * quiescence guarantee is supplied by these ignored cancellation results. */
int medius_host_hid_class_disconnect(MediusHostHubPortPrefix *port,uchar interface_index)
{
    volatile MediusHostHubPortPrefix *live_port = port;
    MediusHostInterfacePrefix *interfaces = live_port->interfaces;
    MediusHostHidClass *hid = ((volatile MediusHostInterfacePrefix *)interfaces)[interface_index].private_data;
    if (hid == NULL)
        return 0;
    volatile MediusHostHidClass *state = hid;
    if (state->in_endpoint != NULL)
        usbh_kill_urb(&hid->in_urb);
    if (state->out_endpoint != NULL)
        usbh_kill_urb(&hid->out_urb);
    interfaces = live_port->interfaces;
    if (((volatile MediusHostInterfacePrefix *)interfaces)[interface_index].name[0] != 0) {
        usb_osal_thread_schedule_other();
        medius_hid_on_class_removed(hid);
    }
    uchar minor = state->minor;
    if (minor < 32)
        MEDIUS_HOST_HID_CLASS_MASK &= ~(1U << minor);
    memset(hid,0,160);
    return 0;
}

/* Native entry: 0x4202648c. */
/* Original function-byte SHA-256:
 * 5ade3a2c10c944092bd1ba84d1bcd97869177fe96b863bad3942bdf6a7a801e6. */
/* Cache work.slot BEFORE entering the credit lock. On that slot,sample state
 * generation then live work generation. Equality permits a live work sequence
 * read followed by current state sequence. If their modulo256 distance<8,
 * clear the sent sequence's history LOW then HIGH words. Always unlock; do not
 * query ISR context,change sequence/credits or inspect timestamps. No slot/
 * pointer validation. A slot mutation during lock entry does not retarget the
 * state,while generation/sequence mutations remain visible after lock entry. */
void medius_hid_credit_release(MediusHidWork *work)
{
    const volatile MediusHidWork *live_work = work;
    unsigned int slot = live_work->slot;
    xPortEnterCriticalTimeout(&MEDIUS_HID_CREDIT_LOCK,-1);
    volatile MediusHidEndpointState *state = &MEDIUS_HOST_HID_ENDPOINTS[slot];
    unsigned int generation = state->generation;
    if (generation == live_work->generation) {
        unsigned int sent = live_work->sequence;
        unsigned int current = state->report_sequence;
        if (((current-sent) & 255U) < 8U) {
            volatile ClockWords *history = (volatile void *)&state->report_history[sent & 7U];
            history->low = 0;
            history->high = 0;
        }
    }
    vPortExitCritical(&MEDIUS_HID_CREDIT_LOCK);
}

/* Native entry: 0x42026858. */
/* Original function-byte SHA-256:
 * 6e932f444020a7669d36e4c818467a2aaeda804dd1907737cb028f6ff42274ef. */
/* Fence/set global HID pause, then pause vendor forwarding BEFORE starting a
 * fresh50000-us deadline. Short-circuit fenced shared-busy bytes9735,9736,credit,
 * then all six callback flags, including inactive slots. Busy scans sample time
 * and either stop at signed64 wrapped deadline or delay one tick/restart. Idle
 * scans need no extra clock sample. Cancel every active/non-NULL interface's
 * embedded IN URB, ignoring results, then pause/discard OUT and fence/clear all
 * six armed bytes. Preserve callback/paused fields. Deadline does not cover the
 * vendor/OUT helpers and cannot guarantee callback/DMA quiescence or wake time. */
void medius_host_pause_all_hid(void)
{
    memw(); MEDIUS_HOST_HID_PAUSED = 1;
    medius_vendor_pause_all();
    unsigned long long deadline = (unsigned long long)esp_timer_get_time() + 50000U;
    for (;;) {
        memw(); unsigned int busy = MEDIUS_HID_SHARED_BUSY_FLAGS[0];
        if (busy == 0) { memw(); busy = MEDIUS_HID_SHARED_BUSY_FLAGS[1]; }
        if (busy == 0) { memw(); busy = MEDIUS_HID_CREDIT_BUSY; }
        if (busy == 0) {
            for (unsigned int slot = 0; slot < 6; ++slot) {
                memw(); busy = MEDIUS_HOST_HID_ENDPOINTS[slot].in_callback;
                if (busy != 0) break;
            }
        }
        if (busy == 0) break;
        if (!medius_credit_signed_less((unsigned long long)esp_timer_get_time(), deadline)) break;
        vTaskDelay(1);
    }
    for (unsigned int slot = 0; slot < 6; ++slot) {
        volatile MediusHidEndpointState *state = &MEDIUS_HOST_HID_ENDPOINTS[slot];
        memw(); if (state->active == 0) continue;
        MediusHostHidClass *interface = state->interface_handle;
        if (interface != NULL) usbh_kill_urb(&interface->in_urb);
    }
    medius_out_pause_discard();
    for (unsigned int slot = 0; slot < 6; ++slot) { memw(); MEDIUS_HOST_HID_ENDPOINTS[slot].armed = 0; }
}

/* Native entry: 0x42026954. */
/* Original function-byte SHA-256:
 * d89f5190df511a36997b31e31d2fb2dd9538eb1b1a58464b0d74ab78579e0749. */
/* Search the cached POSITIVE signed HID count for the first matching handle;
 * no count<=6, active or NULL-handle guard. Fence/set paused. Independently wait
 * for shared busy flags(50000us), armed(3000us), then after UNCONDITIONAL IN-URB
 * cancellation, in_callback(50000us). Each phase gets a fresh start and uses
 * signed64 comparison against a modulo64 deadline, one tick per busy retry.
 * Cancel receives actual initialized0; its return is ignored even if not armed.
 * Nonzero actual is forwarded FULL32 as an int. Read max_packet even for a
 * negative actual; flag is true only for nonnegative actual, nonzero MPS,
 * low16(actual)<transfer_length and zero unsigned remainder by MPS. Enqueue
 * uses low16(found slot), ISR argument0. Finally fence/clear the original slot's
 * armed byte, retaining paused. No lock, timeout rollback or quiescence proof;
 * producer validity of negative/oversized actual remains a delegated obligation. */
void medius_host_pause_hid_interface(MediusHostHidClass *interface)
{
    int count = MEDIUS_HID_ENDPOINT_COUNT;
    if (count <= 0) return;
    for (unsigned int slot = 0; slot < (unsigned int)count; ++slot) {
        volatile MediusHidEndpointState *state = (volatile void *)
            ((unsigned int)MEDIUS_HOST_HID_ENDPOINTS + slot * 176U);
        if (state->interface_handle != interface) continue;
        memw(); state->paused = 1;
        unsigned long long deadline = (unsigned long long)esp_timer_get_time() + 50000U;
        for (;;) {
            memw(); unsigned int busy = MEDIUS_HID_SHARED_BUSY_FLAGS[0];
            if (busy == 0) { memw(); busy = MEDIUS_HID_SHARED_BUSY_FLAGS[1]; }
            if (busy == 0) { memw(); busy = MEDIUS_HID_CREDIT_BUSY; }
            if (busy == 0 || !medius_credit_signed_less((unsigned long long)esp_timer_get_time(), deadline)) break;
            vTaskDelay(1);
        }
        unsigned long long start = (unsigned long long)esp_timer_get_time();
        memw(); unsigned int armed = state->armed;
        deadline = start + 3000U;
        while (armed != 0) {
            if (!medius_credit_signed_less((unsigned long long)esp_timer_get_time(), deadline)) break;
            vTaskDelay(1);
            memw(); armed = state->armed;
        }
        unsigned int actual = 0;
        medius_usbh_kill_urb_with_actual(&interface->in_urb, &actual);
        start = (unsigned long long)esp_timer_get_time();
        memw(); unsigned int callback = state->in_callback;
        deadline = start + 50000U;
        while (callback != 0) {
            if (!medius_credit_signed_less((unsigned long long)esp_timer_get_time(), deadline)) break;
            vTaskDelay(1);
            memw(); callback = state->in_callback;
        }
        if (actual != 0) {
            unsigned int packet = state->max_packet;
            unsigned int flag = 0;
            if ((int)actual >= 0 && packet != 0) {
                unsigned int length = state->transfer_length;
                unsigned int low_actual = actual & 65535U;
                if (low_actual < length) flag = low_actual % packet == 0;
            }
            MediusHidEndpointState *reported = (void *)
                ((unsigned int)MEDIUS_HOST_HID_ENDPOINTS + (slot & 65535U) * 176U);
            medius_hid_report_enqueue(reported, (int)actual, (unsigned char)flag, 0);
        }
        memw(); state->armed = 0;
        return;
    }
}

/* Native entry: 0x42026bec. */
/* Original function-byte SHA-256:
 * 8b1a404e9226d8584c9b63479ba608ef95f129ce35ff73dfa7d8df2f6cf99400. */
/* Query ISR context and lock frame state. Fence/sample GLOBAL frame before
 * the state's first participation read. A non-FFFF first sample permits a
 * SECOND fenced participation read; only that saved value equal to the cached
 * global frame enters release. Always clear participation toFFFF. In release,
 * fence/sample count; nonzero permits a SECOND fenced byte read,decrement
 * modulo256,and fenced publication. Branch on that computed byte,not a third
 * shared read. Thus changing the second count to0 can underflow to255.
 *
 * Only a computed0 snapshots the pending word (after decrement),then clears it.
 * Query ISR,unlock and sample low16 HFNUM. Dispatch the saved low6 mask bits
 * outside lock,with preference1 iff this sample differs from the second saved
 * participation value. High mask bits are discarded. Other paths still query
 * ISR,unlock and perform the fenced HFNUM read,even though its value is unused.
 * No active/pause/slot/NULL checks or atomic snapshot across those repeated
 * field reads; delegated slow polling owns admission and USB effects. */
void medius_hid_release_frame_participation(MediusHidEndpointState *endpoint_state)
{
    volatile MediusHidEndpointState *state = endpoint_state;
    xPortInIsrContext();
    xPortEnterCriticalTimeout(&MEDIUS_HID_FRAME_LOCK,-1);
    memw(); unsigned int current = MEDIUS_HID_PARTICIPATION_FRAME;
    memw(); unsigned int first = state->participation_frame;
    if (first != 65535U) {
        memw(); unsigned int saved = state->participation_frame;
        if (saved == current) {
            memw(); state->participation_frame = 65535;
            memw(); unsigned int first_count = MEDIUS_HID_FRAME_PARTICIPANTS;
            if (first_count != 0) {
                memw(); unsigned int count = (MEDIUS_HID_FRAME_PARTICIPANTS-1U) & 255U;
                memw(); MEDIUS_HID_FRAME_PARTICIPANTS = (unsigned char)count;
                if (count == 0) {
                    memw(); unsigned int pending = MEDIUS_HID_PENDING_POLLS;
                    memw(); MEDIUS_HID_PENDING_POLLS = 0;
                    xPortInIsrContext();
                    vPortExitCritical(&MEDIUS_HID_FRAME_LOCK);
                    memw(); unsigned int frame = MEDIUS_HOST_USB_REGISTERS->frame_number & 65535U;
                    if (pending == 0) return;
                    int changed = frame != saved;
                    for (unsigned int slot = 0; slot < 6; ++slot)
                        if ((pending & (1U << slot)) != 0)
                            medius_hid_try_slow_poll((MediusHidEndpointState *)&MEDIUS_HOST_HID_ENDPOINTS[slot],changed);
                    return;
                }
            }
            goto unlock;
        }
    }
    memw(); state->participation_frame = 65535;
unlock:
    xPortInIsrContext();
    vPortExitCritical(&MEDIUS_HID_FRAME_LOCK);
    memw(); (void)MEDIUS_HOST_USB_REGISTERS->frame_number;
}

/* Native entry: 0x420270c4. */
/* Original function-byte SHA-256:
 * a6f6b60ab842b4f624de6e94be7633b04818ae84dfa92f56cacfd4aa895e463b. */
/* Find first handle in cached positive signed count. Require fenced active and
 * a live IN descriptor in the supplied class, then fence/clear paused and armed.
 * Fenced period>=2 or global pause leaves those cleared without immediate rearm.
 * Otherwise call credit rearm using low16(found slot). Every negative result,
 * INCLUDING-6, clears armed and sets needs/global retry. Success state changes
 * belong to the callee. No NULL/count<=6/lifetime checks or local lock. */
void medius_host_restore_hid_interface(MediusHostHidClass *interface)
{
    int count = MEDIUS_HID_ENDPOINT_COUNT;
    if (count <= 0) return;
    for (unsigned int slot = 0; slot < (unsigned int)count; ++slot) {
        volatile MediusHidEndpointState *state = (volatile void *)
            ((unsigned int)MEDIUS_HOST_HID_ENDPOINTS + slot * 176U);
        if (state->interface_handle != interface) continue;
        memw(); if (state->active == 0) return;
        if (((volatile MediusHostHidClass *)interface)->in_endpoint == NULL) return;
        memw(); state->paused = 0;
        memw(); state->armed = 0;
        memw(); if (state->poll_period >= 2) return;
        memw(); if (MEDIUS_HOST_HID_PAUSED != 0) return;
        MediusHidEndpointState *selected = (void *)
            ((unsigned int)MEDIUS_HOST_HID_ENDPOINTS + (slot & 65535U) * 176U);
        if (medius_hid_rearm_with_credit_gate(selected) < 0) {
            memw(); state->armed = 0;
            memw(); state->needs_rearm = 1;
            memw(); MEDIUS_HID_RETRY_PENDING = 1;
        }
        return;
    }
}

/* Native entry: 0x42027168. */
/* Original function-byte SHA-256:
 * 7a0e650a3d70bbd031de5bd8120420f27960766fdef6414bc451d52dcdefef16. */
/* Fence/clear global HID pause, then scan six slots with a FRESH restore-mask
 * word per slot. A selected non-NULL class is restored without local active
 * checks. Clear the ENTIRE mask afterward, discarding upper bits, then invoke
 * vendor resume and OUT resume even for an empty mask. No mutex or atomic mask
 * snapshot. Vendor resume owns its mutex operation; this helper does not clear
 * the distinct global vendor pause byte. */
void medius_host_restore_suspended_hid(void)
{
    memw(); MEDIUS_HOST_HID_PAUSED = 0;
    for (unsigned int slot = 0; slot < 6; ++slot) {
        if ((MEDIUS_HID_SUSPEND_RESTORE_MASK & (1U << slot)) == 0) continue;
        MediusHostHidClass *interface = MEDIUS_HOST_HID_ENDPOINTS[slot].interface_handle;
        if (interface != NULL) medius_host_restore_hid_interface(interface);
    }
    MEDIUS_HID_SUSPEND_RESTORE_MASK = 0;
    medius_vendor_resume_all();
    medius_out_resume();
}

/* Native entry: 0x42028e1c. */
/* Original function-byte SHA-256:
 * 3511b534649471ccbf0c316502f861219a36565f3045805e1d6f2bf8f2cfd871. */
/* Read previous endpoint BEFORE caching class handle. Only endpoint0 resets the
 * 104 credit bytes under the credit lock: timer sampled BEFORE entry, zero->1,
 * limit1, duration LOW/HIGH3000000, generation+1 modulo256, start LOW/HIGH,
 * window5000, fenced blocked0. Existing endpoint retains that state. Read fresh
 * class IN address, store endpoint and discard vendor saved validity. Reload IN
 * pointer and read MPS HIGH BYTE then LOW, mask11/store. report_length<=64 uses
 * max(MPS,report); larger logs and keeps old MPS, reloading ONLY the descriptor
 * used for interval after logging. No local MPS<=64 or NULL checks.
 *
 * Read descriptor interval BEFORE fenced override sample; store original byte,
 * then if override nonzero fence/read it AGAIN. Round chosen byte down to power2,
 * 0/1->1. Fence/publish period, clear needs/special-valid/halted/retry, set poll/
 * participation/slow/scheduled/callback frame sentinels, clear two opaque words.
 * ISR queries bracket frame-lock entry/exit. Read slot BEFORE fenced pending
 * snapshot, fence/store mask with low5(slot) bit cleared. Recompute packet count
 * from fresh MPS/length. Period is separately fenced/read for threshold selection,
 * again for slow comparison, and BEFORE credit-limit store for SOF admission.
 * Threshold is1/2; zero MPS is treated as one packet. Slow period requests SOF.
 * Finally fence/set armed1, paused0, active1; no URB submission occurs here. */
void medius_hid_initialize_endpoint(MediusHidEndpointState *endpoint, unsigned int report_length)
{
    volatile MediusHidEndpointState *state = endpoint;
    unsigned int previous_endpoint = state->endpoint;
    volatile MediusHostHidClass *interface = state->interface_handle;
    if (previous_endpoint == 0) {
        unsigned long long now = (unsigned long long)esp_timer_get_time();
        xPortEnterCriticalTimeout(&MEDIUS_HID_CREDIT_LOCK, -1);
        if (now == 0) now = 1;
        volatile unsigned int *credit = (volatile void *)&state->report_sequence;
        for (unsigned int i = 0; i < 26; ++i) credit[i] = 0;
        state->credit_limit = 1;
        unsigned int generation = state->generation;
        volatile ClockWords *duration = (volatile void *)&state->boost_duration_us;
        duration->low = 3000000;
        duration->high = 0;
        state->generation = (unsigned char)(generation + 1U);
        volatile ClockWords *start = (volatile void *)&state->boost_started_us;
        start->low = (unsigned int)now;
        start->high = (unsigned int)(now >> 32);
        state->history_window_us = 5000;
        memw(); state->credit_blocked = 0;
        vPortExitCritical(&MEDIUS_HID_CREDIT_LOCK);
    }
    const volatile MediusHostEndpointDescriptor *descriptor = (const volatile void *)interface->in_endpoint;
    unsigned int address = descriptor->address;
    state->endpoint = (unsigned char)address;
    medius_vendor_discard_saved_endpoint_state(address);
    descriptor = (const volatile void *)interface->in_endpoint;
    unsigned int high = descriptor->max_packet[1];
    unsigned int low = descriptor->max_packet[0];
    unsigned int packet = (low | (high << 8)) & 2047U;
    state->max_packet = (unsigned short)packet;
    unsigned int length = packet;
    if (report_length <= 64) { if (length < report_length) length = report_length; }
    else {
        medius_host_log_formatted("intf %u report %uB > buf, fragmenting", (unsigned int)interface->interface_index, report_length);
        descriptor = (const volatile void *)interface->in_endpoint;
    }
    state->transfer_length = (unsigned short)length;
    unsigned int interval = descriptor->interval;
    memw(); unsigned int override = MEDIUS_HID_POLL_OVERRIDE;
    state->descriptor_interval = (unsigned char)interval;
    if (override != 0) { memw(); interval = MEDIUS_HID_POLL_OVERRIDE; }
    unsigned int period = 1;
    if (interval > 1) do { period = (period * 2U) & 65535U; } while (period * 2U <= interval);
    memw(); state->poll_period = (unsigned short)period;
    memw(); state->needs_rearm = 0;
    memw(); state->special_valid = 0;
    memw(); state->halted = 0;
    memw(); state->special_retry = 0;
    memw(); state->poll_phase = 65535;
    memw(); state->participation_frame = 65535;
    memw(); state->slow_poll_frame = 65535;
    memw(); state->scheduled_frame = 65535;
    state->rearm_after_us_low = 0;
    state->rearm_after_us_high = 0;
    memw(); state->last_callback_frame = 65535;
    xPortInIsrContext();
    xPortEnterCriticalTimeout(&MEDIUS_HID_FRAME_LOCK, -1);
    unsigned int slot = state->slot;
    memw(); unsigned int pending = MEDIUS_HID_PENDING_POLLS;
    memw(); MEDIUS_HID_PENDING_POLLS = pending & ~(1U << (slot & 31U));
    xPortInIsrContext();
    vPortExitCritical(&MEDIUS_HID_FRAME_LOCK);
    packet = state->max_packet;
    unsigned int packets = 1, limit;
    if (packet == 0) {
        memw(); period = state->poll_period;
        if (period < 2) { limit = 1; goto publish_limit; }
    } else {
        length = state->transfer_length;
        memw(); period = state->poll_period;
        packets = ((length + packet - 1U) / packet) & 65535U;
        if (period < 2) { limit = (packets > 1U) + 1U; goto publish_limit; }
    }
    memw(); period = state->poll_period;
    limit = (packets >= period) + 1U;
publish_limit:
    memw(); period = state->poll_period;
    state->credit_limit = (unsigned char)limit;
    if (period >= 2) medius_host_set_sof_interrupt(1);
    memw(); state->armed = 1;
    memw(); state->paused = 0;
    memw(); state->active = 1;
}

/* Native entry: 0x42028ff8. */
/* Original function-byte SHA-256:
 * 56a8c3e07877d1952315c3bd532d185567da26819c7e58920d0cdc31698beb34. */
/* Rebuild one HID alternate after caller's USB control request. Cache class
 * interface byte, then port table; fence/read count, fence/recheck pointer and
 * require matching FULL alternate in cached16-byte descriptors. Reset/ready/
 * connected gates precede pause. Search cached positive signed HID count for old
 * handle, using low16(found index). Unregister old OUT only if BOTH old IN/OUT
 * exist. Picker updates class pointers; clear both URB toggle bytes, publish
 * alternate byte, then rebuild vendor remainder excluding OUT only if IN exists.
 * Repeat lifecycle gates AFTER those writes/calls. With new IN/OUT register OUT
 * and reread IN; accept MPS masked11<=64, including0. Missing/oversized IN clears
 * ONLY the old state's endpoint byte, preserving other flags.
 *
 * No old state: signed count>=6 returns after earlier publications; negative
 * count is NOT guarded and would address before the table. Publish class and
 * slot/interface HALFWORD, fence/clear cache length, load report length, clear
 * endpoint, increment count BEFORE initialize. After that call select state from
 * FRESH(count-1), not the original slot. Existing state stays cached. No rearm
 * when disallowed/globalpaused: clear armed. Otherwise rearm; every negative
 * including-6 clears armed and sets needs/global retry. No rollback, class NULL
 * guard, descriptor lifetime lock or guarantee that earlier forwarding changes
 * are undone by a later failed gate. */
void medius_host_restore_hid_alternate(MediusHostHubPortPrefix *hubport,
    MediusHostHidClass *hid_class, unsigned int alternate, int allow_rearm)
{
    volatile MediusHostHidClass *interface = hid_class;
    volatile MediusHostHubPortPrefix *port = hubport;
    unsigned int interface_number = interface->interface_index;
    volatile MediusHostInterfacePrefix *interfaces = port->interfaces;
    memw(); unsigned int count = port->interface_count;
    memw();
    if (interfaces == NULL || interfaces != port->interfaces || interface_number >= count) return;
    unsigned int alternatives = interfaces[interface_number].alternate_count;
    if (alternatives == 0) return;
    const volatile MediusHostAlternatePrefix *descriptors = interfaces[interface_number].alternates;
    unsigned int i;
    for (i = 0; i < alternatives; ++i) if (descriptors[i].alternate_setting == alternate) break;
    if (i == alternatives) return;
    memw(); if (MEDIUS_HOST_RESET_PENDING != 0) return;
    if (MEDIUS_HOST_DESCRIPTORS_READY == 0 || port->connected == 0) return;
    medius_host_pause_hid_interface(hid_class);
    MediusHidEndpointState *state = NULL;
    int slots = MEDIUS_HID_ENDPOINT_COUNT;
    if (slots > 0) {
        for (unsigned int index = 0; index < (unsigned int)slots; ++index) {
            volatile MediusHidEndpointState *candidate = (volatile void *)
                ((unsigned int)MEDIUS_HOST_HID_ENDPOINTS + index * 176U);
            if (candidate->interface_handle == hid_class) {
                state = (void *)((unsigned int)MEDIUS_HOST_HID_ENDPOINTS + (index & 65535U) * 176U);
                break;
            }
        }
    }
    if (interface->in_endpoint != NULL) {
        const volatile unsigned char *out = interface->out_endpoint;
        if (out != NULL) medius_out_unregister(hubport, out[2]);
    }
    medius_host_pick_interrupt_endpoints(hubport, interface_number, alternate,
        (unsigned char **)&interface->in_endpoint, (unsigned char **)&interface->out_endpoint);
    interface->in_urb.toggle = 0;
    interface->out_urb.toggle = 0;
    MEDIUS_HID_ALTERNATE_SELECTIONS[interface_number] = (unsigned char)alternate;
    unsigned char *in = interface->in_endpoint;
    unsigned char *out = in != NULL ? interface->out_endpoint : NULL;
    medius_vendor_rebuild_hid_remainder(hubport, interface_number, alternate, in, out);
    memw(); if (MEDIUS_HOST_RESET_PENDING != 0) return;
    if (MEDIUS_HOST_DESCRIPTORS_READY == 0 || port->connected == 0) return;
    const volatile MediusHostEndpointDescriptor *descriptor = (const volatile void *)interface->in_endpoint;
    if (descriptor == NULL) goto no_in;
    out = interface->out_endpoint;
    if (out != NULL) {
        medius_out_register(hubport, out);
        descriptor = (const volatile void *)interface->in_endpoint;
        if (descriptor == NULL) goto no_in;
    }
    unsigned int high = descriptor->max_packet[1];
    unsigned int low = descriptor->max_packet[0];
    if (((low | (high << 8)) & 2047U) > 64) goto no_in;
    if (state == NULL) {
        int used = MEDIUS_HID_ENDPOINT_COUNT;
        if (used >= 6) return;
        volatile MediusHidEndpointState *created = (volatile void *)
            ((unsigned int)MEDIUS_HOST_HID_ENDPOINTS + (unsigned int)used * 176U);
        created->interface_handle = hid_class;
        unsigned int fresh_interface = interface->interface_index;
        created->slot_and_interface = (unsigned short)(((unsigned int)used & 255U) | (fresh_interface << 8));
        memw(); *(volatile unsigned short *)((unsigned int)MEDIUS_HID_CACHED_LENGTHS + (unsigned int)used * 2U) = 0;
        unsigned int report_length = MEDIUS_HID_REPORT_LENGTHS[interface_number];
        created->endpoint = 0;
        MEDIUS_HID_ENDPOINT_COUNT = used + 1;
        medius_hid_initialize_endpoint((MediusHidEndpointState *)created, report_length);
        unsigned int last = (unsigned int)MEDIUS_HID_ENDPOINT_COUNT - 1U;
        state = (void *)((unsigned int)MEDIUS_HOST_HID_ENDPOINTS + (unsigned int)last * 176U);
    } else medius_hid_initialize_endpoint(state, MEDIUS_HID_REPORT_LENGTHS[interface_number]);
    if (allow_rearm == 0) { memw(); ((volatile MediusHidEndpointState *)state)->armed = 0; return; }
    memw();
    if (MEDIUS_HOST_HID_PAUSED != 0) { memw(); ((volatile MediusHidEndpointState *)state)->armed = 0; return; }
    if (medius_hid_rearm_with_credit_gate(state) < 0) {
        memw(); ((volatile MediusHidEndpointState *)state)->armed = 0;
        memw(); ((volatile MediusHidEndpointState *)state)->needs_rearm = 1;
        memw(); MEDIUS_HID_RETRY_PENDING = 1;
    }
    return;
no_in:
    if (state != NULL) ((volatile MediusHidEndpointState *)state)->endpoint = 0;
}

/* Native entry: 0x4202d720. */
/* Original function-byte SHA-256:
 * 9758bec47f9671592926a967a928639b58d8de1e8bb34a58aca83ee50a65e662. */
/* Read active byte+15 from each of six 176-byte HID endpoint states, fencing
 * each read. Add raw bytes with truncation to8 bits after each addition.
 * No boolean/count normalization or connection/armed/paused filtering occurs;
 * this is an unlocked sequence of six samples, used for OUT slot admission. */
unsigned char medius_hid_reserved_slots(void)
{
    unsigned char reserved = 0;
    for (unsigned int endpoint = 0; endpoint < 6; ++endpoint) {
        memw();
        unsigned char active = MEDIUS_HOST_HID_ENDPOINTS[endpoint].active;
        reserved = (unsigned char)(reserved+active);
    }
    return reserved;
}

/* Native entry: 0x4202da18. */
/* Original function-byte SHA-256:
 * 36a01dc01ac662dbb52dbf5dffacebffb1a8af416048f89eba174ee73c9c8da7. */
/* Sample timer once, then full initial phase result, then fence/set busy. For
 * six fenced active HID slots, read payload count even for length0/negative,
 * then cache endpoint and find first complete four-byte match using FULL SIGNED
 * length. Caller must supply a readable count byte for every active slot.
 * Lock after search. Match reads sequence/load inside lock, applies signed8
 * progress boost only when initial phase nonzero, fenced period<=2 and MPS0 or
 * rounded packet count1. Store progress/retained fields/reference now-or1 LOW/HIGH.
 * Fresh flag bit0 independently repeats period/packet checks and boost growth.
 * HID growth reads/writes duration LOW/HIGH and start LOW/HIGH, unlike vendor's
 * fast/read and flag/write variants. Epoch dedup and signed modulo64 arithmetic
 * are retained by the shared source utilities in types.h.
 *
 * Missing record optionally performs a fenced UNUSED period read when initial
 * phase nonzero, clears retained valid/base/count, fences/samples blocked BEFORE
 * reference stores, and forces an eight-history scan if blocked. Matched blocked
 * paths read sequence/base/valid in that order. Occupancy uses cached packet load
 * and applied reference, not reread retained count/reference. Strict count below
 * byte limit plus live boost (up to256), after saturation255, clears blocked.
 * Unlock before all rearm gates: active, period<2, !needs, !armed, !paused,
 * !halted, !globalpaused. A second fenced period/packet test permits optional
 * growth when phase opens OR low11(HFNUM-last_report_frame)==1. Read fenced
 * last_report_frame BEFORE fenced HFNUM. Closed phase never prevents submit.
 * Set armed, submit(state,0); negative except-6 clears armed and sets needs plus
 * global retry. Every newly unblocked slot releases frame participation even if
 * gates fail. Others only unlock. Clear busy before delegating original payload,
 * full signed length, original timer bits and FULL initial gate to vendor; that
 * callee separately narrows gate8/length16. No local payload/lifetime validation. */
void medius_hid_apply_credit_records(unsigned char *payload, int length)
{
    unsigned long long now = (unsigned long long)esp_timer_get_time();
    int initial_phase = medius_host_phase_gate_open();
    unsigned long long reference = now == 0 ? 1 : now;
    memw(); MEDIUS_HID_CREDIT_BUSY = 1;
    for (unsigned int slot = 0; slot < 6; ++slot) {
        volatile MediusHidEndpointState *state = &MEDIUS_HOST_HID_ENDPOINTS[slot];
        memw(); if (state->active == 0) continue;
        unsigned int records = ((const volatile unsigned char *)payload)[0];
        unsigned int endpoint = state->endpoint;
        const volatile CreditRecord *record = medius_credit_find_record(payload, length, records, endpoint);
        volatile MediusCreditState *credit = (volatile void *)&state->report_sequence;
        volatile ClockWords *reference_words = (volatile void *)&credit->credit_reference_us;
        xPortEnterCriticalTimeout(&MEDIUS_HID_CREDIT_LOCK, -1);
        unsigned int seed = 0, blocked;
        if (record != NULL) {
            unsigned int sequence = record->sequence;
            seed = record->load;
            unsigned int progress = (sequence - seed) & 255U;
            if (initial_phase != 0) {
                memw();
                if (state->poll_period <= 2 && medius_hid_credit_single_packet(state) &&
                        (signed char)(progress - credit->credit_progress_sequence) > 0) {
                    const volatile ClockWords *start = (const volatile void *)&credit->boost_started_us;
                    unsigned int low = start->low;
                    unsigned int high = start->high;
                    medius_credit_grow_from(credit, now, reference, low, high, 0, 0);
                }
            }
            credit->credit_progress_sequence = (unsigned char)progress;
            credit->retained_credit_valid = 1;
            credit->credit_sequence_base = (unsigned char)sequence;
            credit->retained_credit_count = (unsigned char)seed;
            reference_words->low = (unsigned int)reference;
            reference_words->high = (unsigned int)(reference >> 32);
            if ((record->flags & 1U) != 0) {
                memw();
                if (state->poll_period < 3 && medius_hid_credit_single_packet(state))
                    medius_credit_grow(credit, now, reference, 0);
            }
            memw(); blocked = state->credit_blocked;
        } else {
            if (initial_phase != 0) { memw(); (void)state->poll_period; }
            credit->retained_credit_valid = 0;
            credit->credit_sequence_base = 0;
            credit->retained_credit_count = 0;
            memw(); blocked = state->credit_blocked;
            reference_words->low = (unsigned int)reference;
            reference_words->high = (unsigned int)(reference >> 32);
        }
        if (blocked != 0 && medius_credit_can_unblock(credit, now, reference, seed, record != NULL ? 1 : 2)) {
            memw(); state->credit_blocked = 0;
            vPortExitCritical(&MEDIUS_HID_CREDIT_LOCK);
            memw(); if (state->active == 0) goto release_frame;
            memw(); if (state->poll_period >= 2) goto release_frame;
            memw(); if (state->needs_rearm != 0) goto release_frame;
            memw(); if (state->armed != 0) goto release_frame;
            memw(); if (state->paused != 0) goto release_frame;
            memw(); if (state->halted != 0) goto release_frame;
            memw(); if (MEDIUS_HOST_HID_PAUSED != 0) goto release_frame;
            memw();
            if (state->poll_period < 3 && medius_hid_credit_single_packet(state)) {
                int phase = medius_host_phase_gate_open();
                if (phase == 0) {
                    memw(); unsigned int previous = state->last_report_frame;
                    memw(); unsigned int current = MEDIUS_HOST_USB_REGISTERS->frame_number;
                    phase = ((current - previous) & 2047U) == 1U;
                }
                if (phase != 0) {
                    xPortEnterCriticalTimeout(&MEDIUS_HID_CREDIT_LOCK, -1);
                    medius_credit_grow(credit, now, reference, 0);
                    vPortExitCritical(&MEDIUS_HID_CREDIT_LOCK);
                }
            }
            memw(); state->armed = 1;
            int result = medius_hid_submit_read((MediusHidEndpointState *)state, 0);
            if (result < 0 && result != -6) {
                memw(); state->armed = 0;
                memw(); state->needs_rearm = 1;
                memw(); MEDIUS_HID_RETRY_PENDING = 1;
            }
release_frame:
            medius_hid_release_frame_participation((MediusHidEndpointState *)state);
        } else vPortExitCritical(&MEDIUS_HID_CREDIT_LOCK);
    }
    memw(); MEDIUS_HID_CREDIT_BUSY = 0;
    medius_vendor_apply_credit_records(payload, length, (long long)now, initial_phase);
}

/* Native entry: 0x4202ece0. */
/* Original function-byte SHA-256:
 * cf709d547258fa4ff69c0109d5bf0d80f81301c1c283df658f82300974fbf0b6. */
/* Fetch/archive a report descriptor, estimate input bytes, and start HID polling.
 * hid: Live 160-byte class; port is cached once, other reads remain fresh as
 * shown. Returns no value; admission failures do not fail class connection.
 *
 * If descriptors are not ready, capture on the cached port. Then choose fresh
 * report_length 1..2048, or 2048 otherwise. Zero scratch before each of at most
 * three fetches. Exact -8 (STALL) stops immediately; other signed results<=7
 * retry with ten scheduler ticks between attempts. Positive payload length is
 * min(limit,max(result,7)-8). Success appends interface/LE16 length/data if the
 * old used+3+length fits 6144; publish header-used before memcpy, then add to
 * freshly read used/count. STALL appends a zero-length record, caching count
 * after the interface write, then publishes used before count. Full archives
 * only drop the copy. Invalid used=0 can alias interface and count; retain it.
 *
 * Pick alternate-zero endpoints, then clear the fresh interface's selection.
 * The limited estimator reads unsigned short items of 0/1/2/4 bytes, skips
 * bounded long items, tracks global size/count/report ID and sums INPUT bits.
 * Initial ID 0 occupies one of 16 slots; any ID item adds one output byte.
 * Constant INPUT flags are ignored. Malformed spans, PUSH/POP, a seventeenth
 * ID, product high32/nonzero or product/per-ID sum>8192 give estimate zero.
 * Otherwise use ceil(maximum bits/8)+ID-present, at most 1025. This estimates
 * length only; it does not implement collection/usage/report semantics.
 *
 * Publish estimate with fresh interface and cached IN before vendor setup;
 * exclude OUT only when IN exists. Reread IN after setup and after optional
 * OUT registration. Read MPS HIGH then LOW, retaining low11. MPS>64 logs and
 * returns before reading count; MPS0 is admitted. Signed count<6 reserves raw
 * 176-byte storage: handle, slot/interface halfword, fresh estimate, fenced
 * cache0, count+1, endpoint0, then initialize. Negative count is not rejected
 * by native code; callers must maintain 0..5 for safe indexed access.
 * SET_IDLE(0,0), then fenced period-before-length snapshots for logging.
 * Negative rearm publishes needs_rearm, fresh interface, fenced global retry1
 * and logs. No count rollback or success guarantee is added. The selected
 * polling record and initial port remain cached across delegated calls.
 * Shared scratch/blob/tables have no local lock or pointer/lifetime checks;
 * helper mutations can affect explicitly fresh reads. Ten ticks are a task
 * delay, not a measured wall-clock deadline. USB delivery/DMA remain callees'
 * responsibilities; static review does not verify physical execution. */
void medius_hid_attach_interface(MediusHostHidClass *hid)
{
    volatile MediusHostHidClass *interface = hid;
    MediusHostHubPortPrefix *port = interface->port;
    uchar enabled = MEDIUS_HOST_DESCRIPTORS_READY;
    if (enabled == 0)
        medius_host_capture_descriptors_and_probe_controls(port);
    uint limit = interface->report_length;
    if (((limit - 1U) & 0xffffU) > 2047)
        limit = 2048;
    int result;
    uint attempts = 0;
    do {
        memset(MEDIUS_HID_DESCRIPTOR_SCRATCH,0,limit);
        result = usbh_hid_get_report_descriptor(hid,MEDIUS_HID_DESCRIPTOR_SCRATCH,limit);
        ++attempts;
        if (result == -8 || result > 7 || attempts == 3)
            break;
        vTaskDelay(10);
    } while (1);
    int descriptor_length = 0;
    if (result == -8) {
        uint used = MEDIUS_HID_DESCRIPTOR_BLOB_USED;
        uchar interface_id = interface->interface_index;
        if (used + 3U <= 6144) {
            ((volatile uchar *)MEDIUS_HID_DESCRIPTOR_BLOB)[used] = interface_id;
            uchar old_count = ((const volatile uchar *)MEDIUS_HID_DESCRIPTOR_BLOB)[0];
            ((volatile uchar *)MEDIUS_HID_DESCRIPTOR_BLOB)[(used + 1U) & 0xffffU] = 0;
            ((volatile uchar *)MEDIUS_HID_DESCRIPTOR_BLOB)[(used + 2U) & 0xffffU] = 0;
            uchar logged_interface = interface->interface_index;
            MEDIUS_HID_DESCRIPTOR_BLOB_USED = (ushort)(used + 3U);
            ((volatile uchar *)MEDIUS_HID_DESCRIPTOR_BLOB)[0] = (uchar)(old_count + 1U);
            medius_host_log_formatted("intf %u STALLs its report descriptor",logged_interface);
        } else {
            ushort advertised = interface->report_length;
            medius_host_log_formatted("rptdesc fail intf %u: report_size=%u r=%d",
                                      interface_id,advertised,result);
        }
    } else {
        descriptor_length = (result < 7 ? 7 : result) - 8;
        if (descriptor_length > (int)limit)
            descriptor_length = (int)limit;
        uchar interface_id = interface->interface_index;
        if (descriptor_length > 0) {
            uint used = MEDIUS_HID_DESCRIPTOR_BLOB_USED;
            if (used + 3U + (uint)descriptor_length <= 6144) {
                ((volatile uchar *)MEDIUS_HID_DESCRIPTOR_BLOB)[used] = interface_id;
                ((volatile uchar *)MEDIUS_HID_DESCRIPTOR_BLOB)[(used + 1U) & 0xffffU] =
                    (uchar)descriptor_length;
                ((volatile uchar *)MEDIUS_HID_DESCRIPTOR_BLOB)[(used + 2U) & 0xffffU] =
                    (uchar)((uint)descriptor_length >> 8);
                MEDIUS_HID_DESCRIPTOR_BLOB_USED = (ushort)(used + 3U);
                memcpy((uchar *)((uint)MEDIUS_HID_DESCRIPTOR_BLOB + used + 3U),
                       MEDIUS_HID_DESCRIPTOR_SCRATCH,(uint)descriptor_length);
                ushort fresh_used = MEDIUS_HID_DESCRIPTOR_BLOB_USED;
                uchar fresh_count = ((const volatile uchar *)MEDIUS_HID_DESCRIPTOR_BLOB)[0];
                MEDIUS_HID_DESCRIPTOR_BLOB_USED =
                    (ushort)(fresh_used + (uint)descriptor_length);
                ((volatile uchar *)MEDIUS_HID_DESCRIPTOR_BLOB)[0] = (uchar)(fresh_count + 1U);
            } else {
                medius_host_log_formatted("blob full; intf %u report dropped",interface_id);
            }
        } else {
            ushort advertised = interface->report_length;
            medius_host_log_formatted("rptdesc fail intf %u: report_size=%u r=%d",
                                      interface_id,advertised,result);
        }
    }
    uchar picked_interface = interface->interface_index;
    medius_host_pick_interrupt_endpoints(port,picked_interface,0,&hid->in_endpoint,&hid->out_endpoint);
    uchar selected_interface = interface->interface_index;
    *(volatile uchar *)((uint)MEDIUS_HID_ALTERNATE_SELECTIONS + selected_interface) = 0;
    ushort estimate = 0;
    if (descriptor_length > 0) {
        volatile uint report_bits[16];
        for (uint index = 0; index < 16; ++index)
            report_bits[index] = 0;
        volatile uint report_id_storage[4];
        for (uint index = 0; index < 4; ++index)
            report_id_storage[index] = 0;
        volatile uchar *report_ids = (volatile uchar *)report_id_storage;
        uint id_count = 1;
        uint current_id = 0;
        uint report_size = 0;
        uint report_count = 0;
        uint ids_present = 0;
        const volatile uchar *bytes = MEDIUS_HID_DESCRIPTOR_SCRATCH;
        uint offset = 0;
        do {
            uchar prefix = bytes[offset];
            if (prefix == 0xfe) {
                if (offset + 2U >= (uint)descriptor_length)
                    goto estimate_done;
                uchar long_length = bytes[offset + 1U];
                uint end = offset + 3U + long_length;
                if (end > (uint)descriptor_length)
                    goto estimate_done;
                offset = end & 0xffffU;
                continue;
            }
            uint size_code = prefix & 3U;
            uint type = (prefix >> 2) & 3U;
            uint tag = prefix >> 4;
            uint byte_count = size_code == 3 ? 4 : size_code;
            if (offset + 1U + byte_count > (uint)descriptor_length)
                goto estimate_done;
            uint value_offset = (offset + 1U) & 0xffffU;
            uint value = 0;
            for (uint index = 0; index < byte_count; ++index)
                value |= (uint)bytes[value_offset + index] << (index * 8U);
            offset = (value_offset + byte_count) & 0xffffU;
            if (type == 1) {
                if (tag == 7)
                    report_size = value;
                else if (tag == 9)
                    report_count = value;
                else if (tag == 8) {
                    current_id = value & 255U;
                    ids_present = 1;
                } else if (tag == 10 || tag == 11) {
                    goto estimate_done;
                }
            } else if (type == 0 && tag == 8) {
                uint slot = 0;
                while (slot < id_count && report_ids[slot] != current_id)
                    ++slot;
                if (slot == id_count) {
                    if (id_count == 16)
                        goto estimate_done;
                    report_ids[id_count] = (uchar)current_id;
                    report_bits[id_count] = 0;
                    ++id_count;
                }
                ulonglong added = (ulonglong)report_size * report_count;
                if ((added >> 32) != 0 || (uint)added > 8192)
                    goto estimate_done;
                uint bits = report_bits[slot] + (uint)added;
                report_bits[slot] = bits;
                if (bits > 8192)
                    goto estimate_done;
            }
        } while (offset < (uint)descriptor_length);
        uint maximum = 0;
        for (uint index = 0; index < id_count; ++index) {
            uint bits = report_bits[index];
            if (bits > maximum)
                maximum = bits;
        }
        uint length = ((maximum + 7U) >> 3) + ids_present;
        if (maximum != 0 && length <= 65535)
            estimate = (ushort)length;
    }
estimate_done:
    {
        uchar interface_id = interface->interface_index;
        uchar *input = interface->in_endpoint;
        *(volatile ushort *)((uint)MEDIUS_HID_REPORT_LENGTHS + (uint)interface_id * 2U) = estimate;
        uchar *excluded_output = input != 0 ? interface->out_endpoint : 0;
        medius_vendor_initialize_hid_remainder(port,interface_id,input,excluded_output);
        input = interface->in_endpoint;
        if (input == 0)
            goto missing_input;
        uchar *output = interface->out_endpoint;
        if (output != 0) {
            medius_out_register(port,output);
            input = interface->in_endpoint;
            if (input == 0)
                goto missing_input;
        }
        uchar high = ((const volatile uchar *)input)[5];
        uchar low = ((const volatile uchar *)input)[4];
        uint max_packet = (((uint)high << 8) | low) & 0x7ffU;
        if (max_packet > 64) {
            uchar logged_interface = interface->interface_index;
            medius_host_log_formatted("intf %u interrupt IN packet %uB > %u, not polled",
                                      logged_interface,max_packet,64);
            return;
        }
        int count = MEDIUS_HID_ENDPOINT_COUNT;
        if (count >= 6)
            return;
        uchar admitted_interface = interface->interface_index;
        MediusHidEndpointState *record = (MediusHidEndpointState *)
            ((uint)MEDIUS_HOST_HID_ENDPOINTS + (uint)count * 176U);
        volatile MediusHidEndpointState *state = record;
        state->interface_handle = hid;
        state->slot_and_interface =
            (ushort)(((uint)count & 255U) | ((uint)admitted_interface << 8));
        ushort current_estimate = *(const volatile ushort *)
            ((uint)MEDIUS_HID_REPORT_LENGTHS + (uint)admitted_interface * 2U);
        memw();
        *(volatile ushort *)((uint)MEDIUS_HID_CACHED_LENGTHS + (uint)count * 2U) = 0;
        MEDIUS_HID_ENDPOINT_COUNT = count + 1;
        state->endpoint = 0;
        medius_hid_initialize_endpoint(record,current_estimate);
        int idle_result = usbh_hid_set_idle(hid,0,0);
        memw();
        ushort poll_period = state->poll_period;
        ushort transfer_length = state->transfer_length;
        uchar logged_interface = interface->interface_index;
        medius_host_log_formatted("intf %u set_idle=%d xfer=%uB poll=%ums",
                                  logged_interface,idle_result,transfer_length,poll_period);
        if (medius_hid_rearm_with_credit_gate(record) < 0) {
            memw();
            state->needs_rearm = 1;
            uchar failed_interface = interface->interface_index;
            memw();
            MEDIUS_HID_RETRY_PENDING = 1;
            medius_host_log_formatted("intf %u submit fail",failed_interface);
        }
        return;
    }
missing_input:
    {
        uchar logged_interface = interface->interface_index;
        medius_host_log_formatted("intf %u has no interrupt-IN ep",logged_interface);
    }
}

/* Native entry: 0x4202f1b4. */
/* Original function-byte SHA-256:
 * bcde311bab78838be0d2fad8d25bf361bc15050c08abe3f69995bf866d804c71. */
/* Clear descriptor-clone activity and conditionally tear down all interfaces.
 * ignored: Unused class argument; this callback is global, not per-interface.
 * Cache descriptors-ready BEFORE the fence and clone-active=0 publication.
 * If that snapshot and the fresh signed endpoint count are both zero, return
 * without changing reset_pending. Every nonzero count, including negative,
 * admits teardown. Cache the snapshot timer BEFORE fenced reset_pending=1;
 * stop that cached timer, ignore its result, then call global teardown.
 * No timer NULL check, post-stop admission recheck or local lock is present.
 * Cancellation and quiescence remain the teardown/timer callees' obligations. */
void medius_hid_on_class_removed(MediusHostHidClass *ignored)
{
    (void)ignored;
    uchar enabled = MEDIUS_HOST_DESCRIPTORS_READY;
    memw();
    MEDIUS_HOST_CLONE_ACTIVE = 0;
    if (enabled == 0 && MEDIUS_HID_ENDPOINT_COUNT == 0)
        return;
    EspTimer *timer = MEDIUS_HOST_SNAPSHOT_TIMER;
    memw();
    MEDIUS_HOST_RESET_PENDING = 1;
    esp_timer_stop(timer);
    medius_host_teardown_interfaces();
}

/* Native entry: 0x42027c88. */
/* Original function-byte SHA-256:
 * 08a176a60531b29f5b103d71e8a997561ff088c8253541aaf5e1300cbc1949fb. */
/*
 * Publish the HID activity selector from low8 endpoint/report_id. Endpoint0
 * disables it (HALFWORD0), otherwise low byte is endpoint, high byte report id.
 * Fence BEFORE the single HALFWORD store; no initial zero store, lock, endpoint
 * validation, activity timestamp clear or status. Consumers treat report id0
 * as a wildcard; this setter merely packs the two bytes.
 */
void medius_hid_set_activity_selector(unsigned char endpoint,unsigned char report_id)
{
    unsigned short selector = endpoint == 0 ? 0 : endpoint | ((unsigned short)report_id << 8);
    memw(); MEDIUS_HID_ACTIVITY_SELECTOR = selector;
}

/* Native entry: 0x40387510. */
/* Original function-byte SHA-256:
 * 838d9c76e4c851960124655623cf23bfee28d1815838e087725b2ea95b5861ef. */
/* Extract an LSB-first signed HID field; return its sign-extended32-bit
 * value, or0 for a rejected gate or ANY unavailable byte, discarding partial
 * bits. No NULL check: report must cover every accessed byte below length.
 * Require low8(bit_width-1)<32 and signed_field exactly1. For ordinary widths
 * 1..32, sample each requested bit and sign-extend widths<32. Bit addresses wrap
 * at16 bits before selecting byte/bit; source bytes are reloaded for every bit.
 *
 * Preserve the native full-WORD width comparison and low8 loop-counter test.
 * Widths with high bits set can pass the initial gate but never satisfy that
 * loop test; they return0 only on a missing byte, or loop indefinitely when
 * all8192 wrapped byte addresses are available. Callers supply normal widths;
 * no extra validation is invented here. Shift counts wrap at five bits.
 */
int medius_hid_extract_signed_field(const unsigned char *report,unsigned int length,
    unsigned int bit_offset,unsigned int bit_width,int signed_field)
{
    if ((unsigned char)(bit_width - 1U) >= 32U || signed_field != 1) return 0;
    unsigned int value = 0;
    unsigned int processed = 0;
    do {
        unsigned int address = bit_offset + processed;
        unsigned int byte_index = (address >> 3) & 8191U;
        unsigned int mask = 1U << (processed & 31U);
        ++processed;
        if (byte_index >= length) return 0;
        unsigned char source = ((const volatile unsigned char *)report)[byte_index];
        if (((source >> (address & 7U)) & 1U) != 0) value |= mask;
    } while ((unsigned char)processed < bit_width);
    if (bit_width != 32U && (value & (1U << ((bit_width - 1U) & 31U))) != 0)
        value |= 0U - (1U << (bit_width & 31U));
    return (int)value;
}

/* Native entry: 0x40389ea4. */
/* Original function-byte SHA-256:
 * a47f1f6edde2f154d1ae4ef113082a74e56ce0ac92b48f41251440af0562dce2. */
/* Fence before one32-bit load of the HID activity time low word.
 * Return that snapshot unchanged. No clock sample, elapsed calculation,
 * conversion, lock, high-word read or zero interpretation is performed.
 */
unsigned int medius_hid_get_activity_time(void)
{
    memw();
    return MEDIUS_HID_ACTIVITY_TIME;
}
