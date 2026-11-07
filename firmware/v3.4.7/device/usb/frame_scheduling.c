/* Medius v3.4.7 device — frame phase tracking and report scheduling. */
#include "../include/types.h"

/* Local reconstruction utilities: phases of native 0x4037b3c4. Inline names
 * describe recovered branches; they are not additional native entries. */
static __inline__ __attribute__((always_inline))
unsigned long long frame_time(unsigned int low,unsigned int high)
{
    return ((unsigned long long)high << 32) | low;
}

static __inline__ __attribute__((always_inline))
int frame_before(unsigned long long first,unsigned long long second)
{
    /* Native absolute timestamp ordering is signed HIGH, then unsigned LOW.
     * It is distinct from testing the sign of a wrapping difference. */
    return (long long)first < (long long)second;
}

static __inline__ __attribute__((always_inline))
void frame_write_reference(unsigned long long value)
{
    USB_FRAME_PHASE.reference_ns.low = (unsigned int)value;
    USB_FRAME_PHASE.reference_ns.high = (unsigned int)(value >> 32);
}

static __inline__ __attribute__((always_inline))
int frame_update_phase(unsigned long long now_us,unsigned int *current_frame)
{
    volatile UsbFramePhaseState *phase = &USB_FRAME_PHASE;
    unsigned int now_low = (unsigned int)now_us;
    unsigned int now_high = (unsigned int)(now_us >> 32);
    memw();
    unsigned int dsts = MEDIUS_HID_COMPLETION_DSTS;
    unsigned short previous_frame = phase->frame;
    unsigned int frame = (dsts >> 8) & 0x7ffU;
    unsigned int raw_delta = (frame - previous_frame) & 0xffffU;
    unsigned int delta = raw_delta & 0x7ffU;
    unsigned int previous_low = phase->last_frame_time.low;
    memw();
    MEDIUS_USB_FRAME_RECOVERY_EPOCH.low = now_low;
    unsigned int previous_high = phase->last_frame_time.high;
    unsigned char was_valid = phase->valid;
    memw();
    MEDIUS_USB_FRAME_RECOVERY_EPOCH.high = now_high;
    unsigned char duplicate_latch = phase->duplicate_latch;
    phase->duplicate_latch = 0;
    phase->valid = 1;
    phase->last_frame_time.low = now_low;
    phase->last_frame_time.high = now_high;
    long long elapsed_us = (long long)(now_us - frame_time(previous_low,previous_high));
    unsigned int duplicate = was_valid & (delta == 0);
    unsigned long long now_ns = now_us * 1000ULL;
    *current_frame = frame;

    if (duplicate != 0) {
        if (elapsed_us < 1500LL && duplicate_latch != 0) {
            /* This comparison samples HIGH first, LOW only on a high tie. */
            unsigned int reference_high = phase->reference_ns.high;
            if ((int)(now_ns >> 32) < (int)reference_high ||
                ((unsigned int)(now_ns >> 32) == reference_high &&
                 (unsigned int)now_ns < phase->reference_ns.low))
                frame_write_reference(now_ns);
            return 1;
        }
        if (elapsed_us >= 700LL) {
            unsigned char mode = phase->recovery_mode;
            if (mode != 255) phase->recovery_mode = (unsigned char)(mode + 1U);
            frame_write_reference(now_ns);
            phase->samples = 0;
        }
        return 0;
    }

    phase->recovery_mode = (unsigned char)duplicate;
    int permit = 0;
    unsigned long long candidate;
    if (delta == 2 && elapsed_us < 1500LL) {
        if (was_valid == 1) {
            unsigned char deferrals = phase->double_frame_deferrals;
            if (deferrals < 8) {
                unsigned int adjusted = (frame - 1U) & 0x7ffU;
                raw_delta = (adjusted - previous_frame) & 0xffffU;
                delta = raw_delta & 0x7ffU;
                phase->frame = (unsigned short)adjusted;
                phase->double_frame_deferrals = (unsigned char)(deferrals + 1U);
                goto advance_reference;
            }
            unsigned int low = phase->reference_ns.low;
            unsigned int high = phase->reference_ns.high;
            candidate = frame_time(low,high) + 2000400ULL;
            phase->frame = (unsigned short)frame;
            permit = 1;
            if ((raw_delta & 0x7c0U) != 0) goto reset_reference;
            goto reconcile_reference;
        }
        phase->frame = (unsigned short)frame;
        permit = 1;
        goto advance_reference;
    }

    phase->double_frame_deferrals = 0;
    if (delta == 1 || was_valid != 1) {
        phase->frame = (unsigned short)frame;
        permit = 1;
        goto advance_reference;
    }
    permit = delta == 2;
    phase->frame = (unsigned short)frame;
    if ((raw_delta & 0x7c0U) != 0) goto reset_reference;
    {
        unsigned int low = phase->reference_ns.low;
        unsigned int high = phase->reference_ns.high;
        candidate = frame_time(low,high) + delta * 1000200ULL;
    }
    if (frame_before(now_ns,candidate - 50000ULL)) {
        frame_write_reference(candidate);
        phase->samples_and_latch = 0x100;
        return 0;
    }
    if (delta != 0) goto reconcile_reference;
    permit = 0;
    goto reset_reference;

advance_reference:
    if (delta == 0 || was_valid == 0) goto reset_reference;
    {
        unsigned int low = phase->reference_ns.low;
        unsigned int high = phase->reference_ns.high;
        candidate = frame_time(low,high) + delta * 1000200ULL;
    }
    if ((raw_delta & 0x7c0U) != 0) goto reset_reference;
reconcile_reference:
    if ((long long)(now_ns - candidate) >= 300000LL) goto reset_reference;
    if (frame_before(candidate,now_ns)) {
        frame_write_reference(candidate);
    } else {
        unsigned long long lead = candidate - now_ns;
        frame_write_reference(now_ns);
        if ((long long)lead > 49999LL) {
            phase->samples = 0;
            return permit;
        }
    }
    if (permit) {
        unsigned char samples = phase->samples;
        if (samples != 255) phase->samples = (unsigned char)(samples + 1U);
        return 1;
    }
    return 0;
reset_reference:
    frame_write_reference(now_ns);
    phase->samples = 0;
    return permit;
}

static __inline__ __attribute__((always_inline))
volatile CreditInterfaceQueue *frame_queue(unsigned int slot)
{
    return (volatile CreditInterfaceQueue *)
        ((unsigned int)REPORT_INTERFACE_QUEUES_WRITABLE + slot * 960U);
}

static __inline__ __attribute__((always_inline))
void frame_age_deferred(volatile CreditInterfaceQueue *queue,
    unsigned int narrow_slot)
{
    unsigned char deferred = queue->deferred;
    if (deferred == 0) {
        queue->deferred_frame_count = 0;
        return;
    }
    unsigned char inhibited = queue->combine_deadline_inhibited;
    if (inhibited != 0) {
        queue->deferred_frame_count = 0;
        return;
    }
    unsigned char frames = queue->deferred_frame_count;
    if (frames != 255) {
        frames = (unsigned char)(frames + 1U);
        queue->deferred_frame_count = frames;
        if (frames == 1) return;
    }
    unsigned char count = queue->record_count;
    if (count == 0) return;
    /* Native loop end uses LOW16(slot), but its start uses the full slot.
     * Keep the modulo32 pointer-distance/count arithmetic for oversized slots. */
    unsigned int end = (unsigned int)frame_queue(narrow_slot) + count * 84U;
    unsigned int iterations =
        ((((end - (unsigned int)queue - 84U) >> 2) * 0x3cf3cf3dU) & 0x3fffffffU) + 1U;
    volatile CreditInterfaceRecord *record = (volatile CreditInterfaceRecord *)queue;
    for (unsigned int index = 0; index < iterations; ++index) {
        unsigned char kind = record->kind;
        if (kind != 0) {
            unsigned char score = record->score;
            if (score != 255) record->score = (unsigned char)(score + 1U);
        }
        record = (volatile CreditInterfaceRecord *)((unsigned int)record + 84U);
    }
}

static __inline__ __attribute__((always_inline))
int frame_candidate_ready(volatile CreditInterfaceQueue *queue,
    unsigned int narrow_slot,unsigned int selected,unsigned long long now_us,
    unsigned short packet_size,unsigned short scale)
{
    volatile CreditInterfaceRecord *record =
        (volatile CreditInterfaceRecord *)((unsigned int)queue + selected * 84U);
    unsigned char kind = record->kind;
    if (kind == 0) return 1;
    unsigned char score = record->score;
    unsigned char length = record->length;
    if (packet_size != 0 && length > packet_size) return score >= 12;
    unsigned char special = record->special;
    if (special != 0 && length != 0) return score >= 12;
    if (kind == 1) {
        unsigned char sample_mode = queue->sample_mode;
        unsigned char sample = 0;
        if (sample_mode != 0 && length != 0) {
            const volatile unsigned char *payload = (const volatile unsigned char *)
                ((unsigned int)frame_queue(narrow_slot) + (unsigned short)selected * 84U);
            sample = *payload;
        }
        for (unsigned int index = 0; index < 4; ++index) {
            unsigned int low = queue->recent_time[index].low;
            unsigned int high = queue->recent_time[index].high;
            if ((low | high) == 0) continue;
            unsigned char recent_id = queue->recent_ids[index];
            if (recent_id != sample) continue;
            long long age = (long long)(now_us - frame_time(low,high));
            unsigned int window_us = (unsigned int)scale * 2500U;
            if (age < (long long)window_us) {
                unsigned int minimum = queue->recent_minimum[index];
                if (minimum < window_us) return score == 255;
            }
            break;
        }
    }
    unsigned char mode_count = queue->mode_count;
    if (mode_count >= 8) {
        unsigned int low = queue->last_history_time.low;
        unsigned int high = queue->last_history_time.high;
        long long age = (long long)(now_us - frame_time(low,high));
        if (age < (long long)((unsigned int)scale * 1500U)) {
            unsigned char empty_run = queue->empty_run;
            if (empty_run > 1) return 1;
        }
    }
    return score >= 2;
}

static __inline__ __attribute__((always_inline))
void frame_collect_deadline(volatile CreditInterfaceQueue *queue,
    unsigned long long now_us,unsigned long long *earliest)
{
    if (queue->extra_pending != 0) return;
    if (!report_prefix_has_pending_kind((const CreditInterfaceQueue *)queue)) return;
    unsigned int high = queue->window_start.high;
    unsigned int low = queue->window_start.low;
    unsigned long long candidate = frame_time(low,high);
    if (!frame_before(now_us,candidate)) {
        if (queue->reservation == 0) return;
        high = queue->window_strict.high;
        low = queue->window_strict.low;
        candidate = frame_time(low,high);
        if (!frame_before(now_us,candidate)) return;
    }
    if ((low | high) != 0 && frame_before(candidate,*earliest)) *earliest = candidate;
}

/* Native entry: 0x4037b3c4. */
/* Original function-byte SHA-256:
 * ad64e7cb28f401a1ce38eb3d2eceb98256a313e4e136576f74f5b258205c86e0. */
/*
 * DWC2 EOPF application callback; bus is ignored. Enter the credit lock with
 * infinite timeout, ignore its result, sample the clock, and track frame phase
 * using DSTS bits8..18. Publish recovery epoch LOW/HIGH with separate MEMW.
 * The inline phase retains the 1000200ns frame estimate, duplicate latch,
 * saturating counters, up-to-eight double-frame deferrals, 50us lead/300us lag
 * reconciliation and raw frame-delta bits6..10 rejection. These are firmware
 * timing heuristics, not hardware timing guarantees.
 *
 * Fenced fast-enabled and deduction gates precede a positive interface count.
 * Every admitted pass clears each queue's old window, publishes frame epoch,
 * ages eligible deferred records, clears three scheduling flags and records
 * pending-prefix presence. A permitted frame aligned to the learned interval
 * tries immediate candidate scheduling, then may establish a timed window.
 * Kind/score/sample gates are 12/255/2 with a recent mode/empty-run bypass.
 * Scheduler arguments omitted by Ghidra are restored: queue, now, deadline,
 * packet size, full slot and strict flag. No guessed argument is supplied.
 *
 * Deadline uses phase reference/1000 plus the learned minimum, or 150us when
 * unset, minus15us. Nominal start uses that minimum or50us; window end is
 * nominal-30us and strict boundary is nominal-34us. Effective delay shifts the
 * opening; a missing hardware alarm clamps a future opening to now. Preserve
 * two distinct window publication orders, fresh pending checks after scheduling
 * and HIGH-before-LOW deadline reads. Earliest uses signed INT64_MAX as sentinel.
 *
 * Read interface count anew BEFORE incrementing each slot; sample a new clock
 * only when another interface remains. Direct queue fields use full slot;
 * learned minima, packet-size and certain payload/end addresses narrow slot
 * to16 bits. Oversized-slot deferred aging retains native modulo32 arithmetic.
 * Unlock before arming the earliest alarm. Afterwards, a pending-endpoint
 * counter reaching10 marks credit dirty and resets; queued-dirty or that event
 * clears queued-dirty and wakes link TX through its ISR API. The forced path
 * still performs the native discarded queued-dirty read.
 *
 * No local allocation, software-timer precision promise, table-length repair
 * or coherent concurrent snapshot. Native widths, barriers, wrapping arithmetic
 * and negative-age cases are retained. Static reconstruction only.
 */
void medius_usb_frame_schedule_reports(unsigned char bus)
{
    (void)bus;
    (void)xPortEnterCriticalTimeout(&CREDIT_LOCK,-1);
    unsigned long long now_us = (unsigned long long)esp_timer_get_time();
    unsigned int frame;
    int permit = frame_update_phase(now_us,&frame);
    unsigned long long earliest = 0x7fffffffffffffffULL;
    memw();
    if (REPORT_FAST_ENABLED == 0) goto unlock;
    memw();
    if (USB_SUSPENDED != 0 || USB_INTERFACE_COUNT < 1) goto unlock;

    unsigned int slot = 0;
    for (;;) {
        unsigned int narrow_slot = (unsigned short)slot;
        volatile CreditInterfaceQueue *queue = frame_queue(slot);
        unsigned int effective_delay = queue->effective_delay;
        unsigned int reference_low = USB_FRAME_PHASE.reference_ns.low;
        unsigned int reference_high = USB_FRAME_PHASE.reference_ns.high;
        const volatile ReportIntervalLearner *learner =
            (const volatile ReportIntervalLearner *)
            ((unsigned int)REPORT_INTERVAL_LEARNERS + narrow_slot * 12U);
        unsigned int minimum_us = learner->minimum_us;
        unsigned long long reference_us = (unsigned long long)
            ((long long)frame_time(reference_low,reference_high) / 1000LL);
        unsigned long long nominal = reference_us + (minimum_us != 0 ? minimum_us : 50U);
        unsigned long long deadline = reference_us + (minimum_us != 0 ? minimum_us : 150U) - 15ULL;
        void *alarm = DECISION_TIMER_HANDLE;
        unsigned long long start = deadline - effective_delay;
        if (alarm == 0 && frame_before(now_us,start)) start = now_us;
        queue->window_active = 0;
        queue->epoch_tag = (unsigned short)frame;
        unsigned short packet_size = REPORT_INTERFACE_PERIODS[narrow_slot];
        unsigned char combine_enabled = queue->combine_window_enabled;
        queue->epoch_gate = 1;
        if (combine_enabled != 0) frame_age_deferred(queue,narrow_slot);
        queue->deferred = 0;
        queue->combine_deadline_inhibited = 0;
        queue->combine_window_enabled = 0;
        int pending = report_prefix_has_pending_kind((const CreditInterfaceQueue *)queue);
        queue->expiry_defer_enabled = (unsigned char)pending;
        if (!permit) goto next_interface;
        unsigned char frame_valid = queue->frame_number_valid;
        unsigned short scale = queue->interval_scale;
        if (frame_valid == 1 && scale >= 2) {
            unsigned short previous_frame = queue->last_frame_number;
            if (((frame + 1U - previous_frame) & 0x7ffU) % scale != 0) goto next_interface;
        }
        unsigned long long end = nominal - 30ULL;
        unsigned char extra = queue->extra_pending;
        queue->combine_window_enabled = 1;
        queue->window_deadline.low = (unsigned int)deadline;
        queue->window_deadline.high = (unsigned int)(deadline >> 32);
        if (extra == 0) {
            unsigned int selected = report_select_candidate(
                (CreditInterfaceQueue *)queue,packet_size,now_us);
            if (selected != 0xffffffffU && frame_candidate_ready(queue,narrow_slot,
                    selected,now_us,packet_size,scale)) {
                report_schedule_candidate((CreditInterfaceQueue *)queue,
                    now_us,now_us,packet_size,slot,0);
                goto after_schedule;
            }
            if (!frame_before(now_us,end)) {
                if (pending) queue->deferred = 1;
                goto next_interface;
            }
        } else if (!frame_before(now_us,end)) {
            goto next_interface;
        }

        unsigned long long strict_boundary = nominal - 34ULL;
        if (frame_before(start,end)) {
            queue->window_start.low = (unsigned int)start;
            queue->window_active = 1;
            queue->window_start.high = (unsigned int)(start >> 32);
            queue->window_end.low = (unsigned int)end;
            queue->window_end.high = (unsigned int)(end >> 32);
            queue->reservation = 0;
            queue->window_strict.low = (unsigned int)strict_boundary;
            queue->window_strict.high = (unsigned int)(strict_boundary >> 32);
            if (frame_before(now_us,start)) goto collect_deadline;
        } else {
            if (queue->record_count == 0) goto next_interface;
            unsigned int selected = report_select_candidate(
                (CreditInterfaceQueue *)queue,packet_size,now_us);
            /* The selector still runs when cached extra is nonzero. */
            if (selected == 0xffffffffU || extra != 0) goto next_interface;
            if (!frame_candidate_ready(queue,narrow_slot,selected,now_us,packet_size,scale)) {
                queue->deferred = 1;
                goto next_interface;
            }
            queue->window_active = 1;
            queue->window_start.low = (unsigned int)now_us;
            queue->window_start.high = (unsigned int)(now_us >> 32);
            queue->window_end.low = (unsigned int)end;
            queue->window_end.high = (unsigned int)(end >> 32);
            queue->window_strict.low = (unsigned int)strict_boundary;
            queue->window_strict.high = (unsigned int)(strict_boundary >> 32);
            queue->reservation = 0;
        }
        report_schedule_candidate((CreditInterfaceQueue *)queue,
            now_us,deadline,packet_size,slot,(unsigned char)!frame_before(now_us,strict_boundary));
after_schedule:
        if (queue->window_active == 0) goto next_interface;
collect_deadline:
        frame_collect_deadline(queue,now_us,&earliest);
next_interface:
        {
            int count = USB_INTERFACE_COUNT;
            ++slot;
            if ((int)slot >= count) break;
        }
        now_us = (unsigned long long)esp_timer_get_time();
    }
unlock:
    vPortExitCritical(&CREDIT_LOCK);
    if (earliest != 0x7fffffffffffffffULL)
        decision_timer_arm((unsigned int)earliest,(int)(earliest >> 32));
    if (MEDIUS_REPORT_PENDING_ENDPOINTS != 0) {
        unsigned char count = MEDIUS_USB_FRAME_CREDIT_COUNTDOWN;
        count = (unsigned char)(count + 1U);
        MEDIUS_USB_FRAME_CREDIT_COUNTDOWN = count;
        if (count >= 10) {
            memw();
            USB_FRAME_CREDIT_DIRTY = 1;
            memw();
            (void)REPORT_QUEUES_DIRTY;
            MEDIUS_USB_FRAME_CREDIT_COUNTDOWN = 0;
            goto wake_link;
        }
    }
    memw();
    if (REPORT_QUEUES_DIRTY == 0) return;
wake_link:
    memw();
    REPORT_QUEUES_DIRTY = 0;
    link_wake_fast_transmit_from_isr();
}
