/* Medius v3.4.7 device — HID IN completion and next-report gating. */
#include "../include/types.h"

/* Local reconstruction utilities: inline phases of native 0x4037ac24, not extra
 * recovered firmware entries. Volatile views preserve sampled widths/order;
 * only the explicitly shown MEMW operations are native barriers. */
static __inline__ __attribute__((always_inline))
unsigned long long hid_completion_time(unsigned int low,unsigned int high)
{
    return ((unsigned long long)high << 32) | low;
}

static __inline__ __attribute__((always_inline))
volatile CreditInterfaceQueue *hid_completion_queue(unsigned int slot)
{
    return (volatile CreditInterfaceQueue *)
        ((unsigned int)REPORT_INTERFACE_QUEUES_WRITABLE + slot * 960U);
}

static __inline__ __attribute__((always_inline))
void hid_completion_learn_phase(unsigned int slot,unsigned long long now_us,
    unsigned char phase_valid)
{
    if (phase_valid == 0) return;
    unsigned char phase_samples = MEDIUS_REPORT_COMPLETION_PHASE_SAMPLES;
    if (phase_samples <= 15) return;
    unsigned int reference_low = MEDIUS_REPORT_COMPLETION_PHASE_REFERENCE.low;
    unsigned int reference_high = MEDIUS_REPORT_COMPLETION_PHASE_REFERENCE.high;
    long long reference_us =
        (long long)hid_completion_time(reference_low,reference_high) / 1000LL;
    unsigned long long phase = now_us - (unsigned long long)reference_us;
    if (phase - 40ULL >= 960ULL) return;

    volatile ReportIntervalLearner *learner =
        (volatile ReportIntervalLearner *)
        ((unsigned int)REPORT_INTERVAL_LEARNERS + slot * 12U);
    unsigned int phase_us = (unsigned int)phase;
    unsigned char samples = learner->sample_count;
    if (samples == 0) {
        learner->candidate_minimum_us = phase_us;
        learner->sample_count = 1;
    } else {
        unsigned int candidate = learner->candidate_minimum_us;
        if (phase_us < candidate)
            learner->candidate_minimum_us = phase_us;
        samples = (unsigned char)(samples + 1U);
        learner->sample_count = samples;
        if (samples > 31) {
            unsigned int learned_minimum = learner->candidate_minimum_us;
            learner->minimum_us = learned_minimum;
            learner->sample_count = 0;
        }
    }
    unsigned int minimum = learner->minimum_us;
    /* Keep the subtract-one wrap: minimum==0 admits every accepted phase. */
    if (phase_us <= minimum - 1U)
        learner->minimum_us = phase_us;
}

static __inline__ __attribute__((always_inline))
void hid_completion_age_records(volatile CreditInterfaceQueue *fields,
    volatile CreditInterfaceQueue *records)
{
    short pending_sample = (short)fields->pending_sample;
    unsigned char sample_mode = fields->sample_mode;
    unsigned char count = fields->record_count;
    for (unsigned int index = 0; index < count; ++index) {
        volatile CreditInterfaceRecord *record =
            (volatile CreditInterfaceRecord *)
            ((unsigned int)records + index * 84U);
        unsigned char kind = record->kind;
        if (kind == 0) continue;
        unsigned char score = record->score;
        if (score == 255) continue;
        if (kind != 2 && pending_sample >= 0) {
            unsigned char length = record->length;
            unsigned char sample = 0;
            if (length != 0 && sample_mode != 0)
                sample = record->data[0];
            if (sample == pending_sample) continue;
        }
        record->score = (unsigned char)(score + 1U);
    }
}

static __inline__ __attribute__((always_inline))
unsigned short hid_completion_learn_frames(
    volatile CreditInterfaceQueue *queue,unsigned int dsts)
{
    unsigned char valid = queue->frame_number_valid;
    unsigned short scale = queue->interval_scale;
    unsigned int frame = (dsts >> 8) & 0x7ffU;
    if (valid != 0) {
        unsigned short previous = queue->last_frame_number;
        unsigned int delta = (frame - previous) & 0x7ffU;
        if (delta == 0 || delta >= scale || (delta & (delta - 1U)) != 0) {
            queue->short_interval_candidate = 0;
        } else {
            unsigned short candidate = queue->short_interval_candidate;
            if (delta == candidate)
                scale = (unsigned short)delta;
            else
                queue->short_interval_candidate = (unsigned short)delta;
        }
    }
    /* One native WORD publication packs scale and current frame together. */
    *(volatile unsigned int *)&queue->interval_scale = scale | (frame << 16);
    queue->frame_number_valid = 1;
    return scale;
}

static __inline__ __attribute__((always_inline))
int hid_completion_candidate_ready(volatile CreditInterfaceQueue *fields,
    volatile CreditInterfaceQueue *queue,unsigned long long now_us,
    unsigned short packet_size,unsigned short scale)
{
    unsigned int selected = report_select_candidate(
        (CreditInterfaceQueue *)queue,packet_size,now_us);
    if (selected == 0xffffffffU) return 0;
    volatile CreditInterfaceRecord *record =
        (volatile CreditInterfaceRecord *)
        ((unsigned int)fields + selected * 84U);
    unsigned char kind = record->kind;
    if (kind == 0) return 1;
    unsigned char score = record->score;
    unsigned char length = record->length;
    if (packet_size != 0 && length > packet_size) return score >= 12;
    unsigned char special = record->special;
    if (special != 0 && length != 0) return score >= 12;

    if (kind == 1) {
        unsigned char sample_mode = fields->sample_mode;
        unsigned char sample = 0;
        if (sample_mode != 0 && length != 0) {
            /* This payload address, unlike the kind/score above, narrows
             * both the interface slot and selected record index to 16 bits. */
            const volatile unsigned char *payload =
                (const volatile unsigned char *)
                ((unsigned int)queue + (unsigned short)selected * 84U);
            sample = *payload;
        }
        for (unsigned int index = 0; index < 4; ++index) {
            unsigned int low = queue->recent_time[index].low;
            unsigned int high = queue->recent_time[index].high;
            if ((low | high) == 0) continue;
            unsigned char recent_id = queue->recent_ids[index];
            if (recent_id != sample) continue;
            long long age = (long long)(now_us - hid_completion_time(low,high));
            unsigned int window_us = (unsigned int)scale * 2500U;
            if (age < (long long)window_us) {
                unsigned int minimum = fields->recent_minimum[index];
                if (minimum < window_us) return score == 255;
            }
            break; /* The first matching ID ends the search even when old. */
        }
    }

    unsigned char mode_count = fields->mode_count;
    if (mode_count >= 8) {
        unsigned int low = fields->last_history_time.low;
        unsigned int high = fields->last_history_time.high;
        long long age = (long long)(now_us - hid_completion_time(low,high));
        if (age < (long long)((unsigned int)scale * 1500U)) {
            unsigned char empty_run = fields->empty_run;
            if (empty_run > 1) return 1;
        }
    }
    return score >= 2;
}

/* Native entry: 0x4037ac24. */
/* Original function-byte SHA-256:
 * a560bbfc75cb0d1af2f1feef343fb6a24660cc101f71f7711abab3278529a597. */
/*
 * Complete the first exact endpoint match in the cached signed HID interface
 * count; ignore bus. No six-interface cap is applied. Sample one microsecond
 * clock and one DWC2 DSTS WORD. Optional class9 capture is assembled before
 * locking, except a deferred split report can replace it later under the lock.
 *
 * Ignore lock-entry status, then return immediately if interface-blocked.
 * Publish completing=1. Kind0 updates endpoint credit using both full 64-bit
 * times and final packet length: actual==0 skips the packet-size read; a
 * nonzero size uses ((actual-1)%size)+1. Learn 40..999us phase minima in
 * 32-sample windows, then record completion LOW/HIGH and actual's LOW16.
 *
 * Split1 requests a zero-length packet on bus0 and changes split to2. A
 * nonnegative submit result unlocks and returns, retaining split2 and skipping
 * every final notification. Blocked/failed ZLP instead optionally rebuilds the
 * capture with the saved report length. Common completion clears split, submits
 * a ready capture, detaches the submitted input state and services the interface.
 *
 * Only a nonzero recovery epoch with signed wrapping age<3000us and mode<=1
 * enables candidate gating. Negative ages pass. Age queued scores unless a
 * pending kind exists; kind2 always ages, matching nonnegative sample skips
 * aging, and score255 is retained. Learn shorter power-of-two DSTS frame
 * intervals after two equal candidates, publishing scale/frame with one WORD.
 * Candidate gating uses thresholds12,255,2 or a recent mode/empty-run bypass;
 * see the inline phase for exact reads and first-matching-ID behavior.
 *
 * Schedule with now_us as both time and deadline, the packet size, full slot
 * and strict=0. Unlock; kind0 wakes link TX through its ISR API, successful
 * capture submission notifies capture task, and a detached input is marked
 * dirty. These notifications also occur when candidate scheduling is gated.
 *
 * Native indexing differs deliberately: direct field updates use full slot;
 * capture storage, record aging and selector/scheduler queue narrow slot to16
 * bits. No count/index validation, timeout, allocation or stable concurrent
 * snapshot is added. Explicit barriers and BYTE/HALFWORD/WORD accesses survive;
 * this static reconstruction does not verify wire timing or execution races.
 */
void medius_hid_device_in_complete(unsigned char bus,unsigned char endpoint,
    unsigned int actual)
{
    (void)bus;
    int count = USB_INTERFACE_COUNT;
    if (count <= 0) return;
    /* Native LBEG/LEND setup supplies the cached-count search and ISYNC. */
    __asm__ volatile("isync" : : : "memory");
    unsigned int slot = 0;
    for (; slot < (unsigned int)count; ++slot) {
        if (USB_INTERFACE_ENDPOINTS[slot] == endpoint) break;
    }
    if (slot == (unsigned int)count) return;

    unsigned long long now_us = (unsigned long long)esp_timer_get_time();
    memw();
    unsigned int dsts = MEDIUS_HID_COMPLETION_DSTS;
    unsigned char split = REPORT_SUBMIT_SPLIT[slot];
    CaptureEvent capture;
    capture.ready = 0;
    unsigned char *storage = (unsigned char *)
        ((unsigned int)REPORT_SUBMIT_STORAGE + (unsigned short)slot * 64U);
    if (split != 1) {
        memw();
        unsigned short classes = CAPTURE_ENABLED_CLASSES;
        if ((classes & 0x200U) != 0) {
            unsigned int number = USB_INTERFACE_ENDPOINTS[slot] & 15U;
            memw();
            unsigned char flags = REPORT_SUBMIT_METADATA42[slot];
            unsigned int length;
            if (split == 2) {
                length = REPORT_SUBMIT_LENGTH[slot];
                flags |= 2U;
            } else {
                length = actual <= 64U ? actual : 64U;
                if (actual == 0) flags |= 2U;
            }
            capture_event_build(&capture,9,1,number,flags,
                (unsigned int)now_us,storage,(unsigned short)length);
        }
    }

    (void)xPortEnterCriticalTimeout(&CREDIT_LOCK,-1);
    memw();
    if (REPORT_INTERFACE_BLOCKED[slot] != 0) {
        vPortExitCritical(&CREDIT_LOCK);
        return;
    }
    unsigned char submit_kind = REPORT_SUBMIT_KIND[slot];
    memw();
    REPORT_INTERFACE_COMPLETING[slot] = 1;
    if (submit_kind == 0) {
        memw();
        unsigned int submitted_low = REPORT_SUBMIT_TIME[slot].low;
        memw();
        unsigned int submitted_high = REPORT_SUBMIT_TIME[slot].high;
        unsigned int tail_length = actual;
        if (actual != 0) {
            unsigned short packet_size = REPORT_INTERFACE_PERIODS[slot];
            if (packet_size != 0) tail_length = ((actual - 1U) % packet_size) + 1U;
        }
        credit_observe_in_completion(endpoint & 15U,now_us,
            hid_completion_time(submitted_low,submitted_high),tail_length);
    }

    unsigned char phase_valid = MEDIUS_REPORT_COMPLETION_PHASE_VALID;
    REPORT_SUBMIT_CLEAR[slot] = 0;
    hid_completion_learn_phase(slot,now_us,phase_valid);
    split = REPORT_SUBMIT_SPLIT[slot];
    REPORT_LAST_IN_COMPLETION[slot].low = (unsigned int)now_us;
    REPORT_LAST_IN_COMPLETION[slot].high = (unsigned int)(now_us >> 32);
    REPORT_LAST_IN_LENGTH[slot] = (unsigned short)actual;
    volatile CreditInterfaceQueue *fields = hid_completion_queue(slot);
    if (split == 1) {
        memw();
        REPORT_SUBMIT_TIME[slot].low = (unsigned int)now_us;
        memw();
        REPORT_SUBMIT_TIME[slot].high = (unsigned int)(now_us >> 32);
        memw();
        unsigned char blocked = REPORT_SUBMIT_BLOCKED[slot];
        REPORT_SUBMIT_SPLIT[slot] = 2;
        fields->combine_deadline_inhibited = 1;
        if (blocked == 0 && usb_device_write_aligned(0,endpoint,storage,0) >= 0) {
            vPortExitCritical(&CREDIT_LOCK);
            return;
        }
        memw();
        unsigned short classes = CAPTURE_ENABLED_CLASSES;
        if ((classes & 0x200U) != 0) {
            memw();
            unsigned char flags = REPORT_SUBMIT_METADATA42[slot];
            unsigned int number = USB_INTERFACE_ENDPOINTS[slot] & 15U;
            unsigned char length = REPORT_SUBMIT_LENGTH[slot];
            capture_event_build(&capture,9,1,number,flags,
                (unsigned int)now_us,storage,length);
        }
    }

    unsigned char capture_ready = capture.ready;
    REPORT_SUBMIT_SPLIT[slot] = 0;
    unsigned int capture_submitted = 0;
    if (capture_ready != 0)
        capture_submitted = capture_submit_event(9,capture.subscriptions,
            0x16,&capture.wire,capture.wire_length);
    InputStateView *input = REPORT_SUBMIT_INPUT_STATES[slot];
    REPORT_SUBMIT_INPUT_STATES[slot] = 0;
    report_service_interface(slot,1);

    volatile CreditInterfaceQueue *queue =
        hid_completion_queue((unsigned short)slot);
    memw();
    unsigned int epoch_low = REPORT_RECOVERY_EPOCH.low;
    memw();
    unsigned int epoch_high = REPORT_RECOVERY_EPOCH.high;
    int gate_candidates = 0;
    if ((epoch_low | epoch_high) != 0) {
        /* The second native pair is HIGH then LOW, each separately fenced. */
        memw();
        epoch_high = REPORT_RECOVERY_EPOCH.high;
        memw();
        epoch_low = REPORT_RECOVERY_EPOCH.low;
        long long age = (long long)(now_us - hid_completion_time(epoch_low,epoch_high));
        if (age < 3000LL)
            gate_candidates = REPORT_RECOVERY_MODE <= 1;
    }
    unsigned char pending_kind = fields->pending_kind;
    fields->extra_pending = 0;
    fields->combine_deadline_inhibited = 1;
    unsigned short packet_size = REPORT_INTERFACE_PERIODS[slot];
    if (pending_kind == 0) hid_completion_age_records(fields,queue);
    unsigned short scale = hid_completion_learn_frames(fields,dsts);
    if (!gate_candidates ||
        hid_completion_candidate_ready(fields,queue,now_us,packet_size,scale)) {
        report_schedule_candidate((CreditInterfaceQueue *)queue,
            now_us,now_us,packet_size,slot,0);
    }

    vPortExitCritical(&CREDIT_LOCK);
    if (submit_kind == 0) link_wake_fast_transmit_from_isr();
    if (capture_submitted != 0) capture_notify_task();
    if (input != 0) input_mark_dirty(input);
}
