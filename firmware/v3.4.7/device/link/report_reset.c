/* Medius v3.4.7 device: report queue discard and interface runtime reset. */

#include "../include/types.h"

/* Native entry: 0x40395268. */
/* Original function-byte SHA-256:
 * af47e7014280284b1b65bf788301f15c48828a9426fa8cf1899c2abc987a2046. */
/* Mark queued report states dirty, then discard their pending records.
 * Snapshot count BYTE at the FULL32 interface's wrapping960-byte stride BEFORE
 * MEMW/store global queues-dirty1. If that saved count was nonzero, walk records
 * at the LOW16 interface's queue, reading each input-state WORD at record+80.
 * Mark nonnull states dirty, then reload the FULL32 queue count each iteration;
 * the record cursor advances84 bytes while its comparison index wraps8 bits.
 * Clear FULL32 record-count BYTE. If clear_submitted!=0, mark its current
 * submitted input state dirty and clear that pointer WORD if nonnull, then
 * clear split BYTE, extra-pending BYTE, window-active BYTE and short-multiple
 * BYTE in order. No record payloads, queue cursors or other fields are erased.
 * Indices/counts are trusted; full/LOW16 addressing intentionally differs.
 * No local lock, bounds clamp or controller/queue submission call is added. */
void report_discard_interface_pending(unsigned int interface,int clear_submitted)
{
    volatile CreditInterfaceQueue *full_index_queue = (volatile void *)
        ((unsigned int)(uintptr_t)REPORT_HISTORY_QUEUES + interface * 960U);
    unsigned char record_count = full_index_queue->record_count;
    memw();
    REPORT_QUEUES_DIRTY = 1;
    if (record_count != 0) {
        unsigned int record_address = (unsigned int)(uintptr_t)REPORT_HISTORY_QUEUES +
            (interface & 65535U) * 960U;
        unsigned int record_index = 0;
        do {
            const volatile CreditInterfaceRecord *record = (const volatile void *)record_address;
            InputStateView *state = record->input_state;
            if (state != NULL)
                input_mark_dirty(state);
            ++record_index;
            record_count = full_index_queue->record_count;
            record_index &= 255U;
            record_address += 84U;
        } while (record_index < record_count);
    }
    full_index_queue->record_count = 0;
    if (clear_submitted != 0) {
        InputStateView *state = REPORT_SUBMIT_INPUT_STATES[interface];
        if (state != NULL) {
            input_mark_dirty(state);
            REPORT_SUBMIT_INPUT_STATES[interface] = NULL;
        }
        REPORT_SUBMIT_SPLIT[interface] = 0;
        full_index_queue->extra_pending = 0;
        full_index_queue->window_active = 0;
        full_index_queue->pending_short_multiple = 0;
    }
}

/* Native entry: 0x42029228. */
/* Original function-byte SHA-256:
 * 80b2ae3713c77f1df3b2a96c9254f143ef6e55493c4ec2b8fbcffe0b485f026c. */
/* Discard this interface's queued/submitted work, then reset credit/interval
 * runtime. Most queue fields use LOW16(interface)*960; the initial configured
 * period read, comparison-limit destination and final timestamp/clear arrays
 * use the FULL32 argument with wrapping address arithmetic. No index clamp.
 * Period0 gives nominal1ms; nonzero<256000us gives LOW16(period/1000), including
 * zero for1..999us; larger periods give255. Interval scale is the largest
 * power of two not exceeding that nominal value, with a minimum of1.
 * Clear only the listed fields, not the complete queue. Fenced history-write
 * count snapshot becomes history-read count. Set empty-run255, pending-sample
 *65535, effective-delay25 and minimum-delayUINT_MAX. Clear recent timestamps32
 * bytes, pending-start LOW/HIGH WORDs and four minimum-hit bytes. Reset frame
 * candidate/validity, mode, reservation and combination state in native
 * width/order. Read comparison limit BEFORE resetting validity/window/scale,
 * and store it at the FULL32 queue's comparison-limit field.
 * Clear12-byte learned interval state at LOW16 index, then full-index last-IN
 * completion LOW/HIGH, last activity LOW/HIGH and submit-clear BYTE. No local
 * lock, timer stop, queue allocation or confirmation of discarded delivery. */
void report_reset_interface_runtime(unsigned int interface)
{
    report_discard_interface_pending(interface,1);
    unsigned int storage_interface = interface & 65535U;
    unsigned int queue_address = (unsigned int)(uintptr_t)REPORT_HISTORY_QUEUES + storage_interface * 960U;
    volatile CreditInterfaceQueue *storage_queue = (volatile void *)queue_address;
    unsigned int period_us = REPORT_CONFIGURED_PERIOD_US[interface];
    unsigned int period_ms = 1;
    if (period_us != 0)
        period_ms = period_us < 256000U ? (period_us / 1000U) & 65535U : 255U;
    unsigned int interval_scale = 1;
    unsigned int next_scale;
    do {
        next_scale = (interval_scale * 2U) & 65535U;
        if (next_scale > period_ms)
            break;
        interval_scale = next_scale;
    } while (1);
    storage_queue->record_count = 0;
    memw();
    unsigned int write_count = storage_queue->history_write_count;
    memw();
    storage_queue->history_read_count = write_count;
    storage_queue->empty_run = 255;
    storage_queue->mode_count = 0;
    storage_queue->combine_window_flags = 0;
    storage_queue->pending_sample = 65535;
    storage_queue->pending_split_flags = 0;
    storage_queue->deferred = 0;
    storage_queue->combine_deadline_inhibited = 0;
    memset((void *)storage_queue->recent_time,0,32);
    storage_queue->effective_delay = 25;
    storage_queue->minimum_delay = 0xffffffffU;
    storage_queue->history_hits = 0;
    storage_queue->pending_start.low = 0;
    storage_queue->pending_start.high = 0;
    memset((void *)storage_queue->minimum_hits,0,4);
    storage_queue->reservation = 0;
    storage_queue->frame_number_valid = 0;
    storage_queue->short_interval_candidate = 0;
    storage_queue->extra_pending = 0;
    unsigned short comparison_limit = REPORT_COMPARISON_LIMITS[interface];
    storage_queue->frame_validity_flags = 0;
    storage_queue->window_active = 0;
    storage_queue->interval_scale = (unsigned short)interval_scale;
    volatile CreditInterfaceQueue *full_index_queue = (volatile void *)
        ((unsigned int)(uintptr_t)REPORT_HISTORY_QUEUES + interface * 960U);
    full_index_queue->comparison_limit = comparison_limit;
    memset(REPORT_INTERVAL_LEARNERS + storage_interface,0,12);
    REPORT_LAST_IN_COMPLETION[interface].low = 0;
    REPORT_LAST_IN_COMPLETION[interface].high = 0;
    REPORT_LAST_IN_ACTIVITY[interface].low = 0;
    REPORT_LAST_IN_ACTIVITY[interface].high = 0;
    REPORT_SUBMIT_CLEAR[interface] = 0;
}
