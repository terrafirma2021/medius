/* Medius v3.4.7 device: recovered link/report_worker.c. */

#include "../include/types.h"

/* Local reconstruction utilities: configured counts are trusted. Keep
 * full-width native address arithmetic; only the failure queue index is
 * explicitly narrowed to 16 bits by its caller below. */
static inline __attribute__((always_inline)) const volatile CreditBinding *
report_worker_binding(unsigned int index)
{
    return (const volatile CreditBinding *)
        ((unsigned int)&CREDIT_BINDINGS + index * 8U);
}

static inline __attribute__((always_inline)) volatile CreditInterfaceQueue *
report_worker_queue(unsigned int interface)
{
    return (volatile CreditInterfaceQueue *)
        ((unsigned int)REPORT_HISTORY_QUEUES + interface * 960U);
}

/* Native entry: 0x40394518. */
/* Original function-byte SHA-256:
 * 1323a6304e606ec9cfaea584b72e72eee9448048d76e8276f731f462387af8ff. */

/*
 * unused_argument: ignored startup context. Returns: never normally returns.
 * Registered as rptfast: priority23,4096-byte stack,core0. Waits on notification
 * (index0,clear1,UINT32_MAX), drains work, then waits again only on an empty ring.
 * No software timer or guaranteed deadline is created by this task.
 *
 * Under the credit lock, searches for classification0 using fresh fenced ring
 * head/count reads. If the selected byte offset equals a freshly read count,
 * copies the current head instead. Otherwise copies that slot's entire99 bytes
 * into shared scratch and shifts preceding records FORWARD to remove it. Each
 * shift reads head TWICE, separately fenced, for source and destination. Head
 * publication and count decrement each have fenced read/write; count can wrap
 * if external mutation violates invariants. A second observed count0 still
 * follows the native extra count read and head-copy path; it is not repaired.
 *
 * Caches sequence,length and endpoint nibble after unlock. Reenters lock,
 * samples clock, reads scratch endpoint BEFORE fenced LOW/HIGH activity stores,
 * tests pending endpoint/interface work, then unlocks. Pending work goes to
 * normal RX fallback. Otherwise recomputes strong eligibility; a passing path
 * sets active1 and recomputes it AGAIN. Strong rejection/failed submission clears
 * active and tries weak eligibility. Weak success calls report_decode, ignoring
 * its result, then completes locally. Weak rejection uses normal RX fallback.
 *
 * Strong secondary IN/slot<6 routes keep the untruncated(length-6)&65535 and
 * cached32-bit source stamp; flags comes from a fresh BYTE
 * scratch read at +8. Primary routing reads the WORD at +8, clamps report bytes to64, uses flag bit1,
 * conditionally timestamps unmatched history, builds an88-byte capture event,
 * and calls the13-argument submit interface. Its output-status byte is zeroed
 * after MEMW but never read here. The event and its padding are not pre-cleared.
 * Nonzero submit result optionally emits capture
 * data (class4,record0x16,wire pointer+10) and wakes capture; capture failure does
 * not undo the successful report. Helpers must copy borrowed stack data before
 * return. Their scheduling and submission behavior is described in the
 * corresponding source modules.
 *
 * Fallback saturates pending count, unlocks and enqueues a type0x10 RX copy with
 * cached sequence/length. SUCCESS restarts draining WITHOUT releasing load:
 * normal consumer owns that accounting. Failure samples clock BEFORE locking,
 * decrements the current pending count if nonzero, even when the increment had
 * saturated at255; it does not restore a saved count. Increments a fenced secondary/primary drop
 * counter, and runs first-matching-interface recovery. Recovery uses cached
 * failure time, two fenced snapshots of a global epoch, signed64 wrapping age
 * <3000us (negative passes), and mode<=1. The recovery call's sixth native word is
 * the interface index; Ghidra omitted it. Locally completed/failed fallback work
 * decrements load if nonzero, samples current clock, checks changed credits under
 * lock, unlocks, then kicks fast TX only for a nonzero cached result.
 *
 * Requires sole scratch consumer,valid16x99 ring/task/kernel and initialized
 * shared tables. No local record-length/pointer/count bounds, handler lifetime,
 * coherent cross-core snapshot, peer delivery or physical timing guarantee.
 * Ring/task reconfiguration must be externally serialized. Runtime callbacks
 * can prevent progress; sustained input can keep this task running above the
 * shared priority22 ESP timer dispatcher.
 */
void report_fast_task(void *unused_argument)
{
    (void)unused_argument;
    FastReportRingItem *scratch = REPORT_FAST_SCRATCH;
    for (;;) {
        ulTaskGenericNotifyTake(0, 1, 0xffffffffU);
drain_next:
        xPortEnterCriticalTimeout(&CREDIT_LOCK, 0xffffffffU);
        memw();
        if (REPORT_FAST_RING_COUNT == 0) {
            vPortExitCritical(&CREDIT_LOCK);
            continue;
        }
        unsigned int selected_offset = 0;
        memw();
        if (REPORT_FAST_RING_COUNT == 0) {
            memw();
            (void)REPORT_FAST_RING_COUNT;
            goto copy_head;
        }
        for (;;) {
            memw();
            unsigned int head = REPORT_FAST_RING_HEAD;
            unsigned int ring_slot = (selected_offset + head) & 15U;
            if (REPORT_FAST_RING[ring_slot].classification == 0)
                break;
            memw();
            unsigned int count = REPORT_FAST_RING_COUNT;
            selected_offset = (unsigned char)(selected_offset + 1U);
            if (selected_offset >= count)
                break;
        }
        memw();
        if (selected_offset == REPORT_FAST_RING_COUNT)
            goto copy_head;
        memw();
        unsigned int selected_head = REPORT_FAST_RING_HEAD;
        memcpy(scratch, &REPORT_FAST_RING[(selected_offset + selected_head) & 15U],
               sizeof(*scratch));
        while ((unsigned char)selected_offset != 0) {
            memw();
            unsigned int source_head = REPORT_FAST_RING_HEAD;
            memw();
            unsigned int destination_head = REPORT_FAST_RING_HEAD;
            unsigned int source_slot = (source_head + selected_offset - 1U) & 15U;
            unsigned int destination_slot = (destination_head + selected_offset) & 15U;
            memcpy(&REPORT_FAST_RING[destination_slot],
                   &REPORT_FAST_RING[source_slot], sizeof(*scratch));
            --selected_offset;
        }
        goto release_ring;
copy_head:
        memw();
        unsigned int head = REPORT_FAST_RING_HEAD & 15U;
        memcpy(scratch, &REPORT_FAST_RING[head], sizeof(*scratch));
release_ring:
        memw();
        unsigned char next_head = (REPORT_FAST_RING_HEAD + 1U) & 15U;
        memw();
        REPORT_FAST_RING_HEAD = next_head;
        memw();
        unsigned char next_count = (unsigned char)(REPORT_FAST_RING_COUNT - 1U);
        memw();
        REPORT_FAST_RING_COUNT = next_count;
        vPortExitCritical(&CREDIT_LOCK);

        unsigned int sequence = REPORT_FAST_SCRATCH_WORDS.sequence;
        unsigned int endpoint_number = REPORT_FAST_SCRATCH_WORDS.endpoint & 15U;
        unsigned int length = REPORT_FAST_SCRATCH_WORDS.length;
        xPortEnterCriticalTimeout(&CREDIT_LOCK, 0xffffffffU);
        unsigned long long activity_time_us = (unsigned long long)esp_timer_get_time();
        unsigned int pending_endpoint = REPORT_FAST_SCRATCH_WORDS.endpoint;
        memw();
        REPORT_LAST_WORKER_TIME.low = (unsigned int)activity_time_us;
        memw();
        REPORT_LAST_WORKER_TIME.high = (unsigned int)(activity_time_us >> 32);
        int endpoint_pending = report_pending_for_endpoint(pending_endpoint);
        vPortExitCritical(&CREDIT_LOCK);
        if (endpoint_pending != 0)
            goto fallback_rx;

        if (report_fast_route_allowed(scratch->payload, length) == 0)
            goto weak_route;
        memw();
        REPORT_FAST_ACTIVE = 1;
        if (report_fast_route_allowed(scratch->payload, length) == 0)
            goto clear_active_then_weak;

        unsigned int report_length = (length - 6U) & 65535U;
        unsigned int source_stamp = REPORT_FAST_SCRATCH_WORDS.source_stamp;
        unsigned int endpoint = REPORT_FAST_SCRATCH_WORDS.endpoint;
        int binding_count = CREDIT_BINDINGS.count;
        for (int binding_index = 0; binding_index < binding_count; ++binding_index) {
            if (report_worker_binding((unsigned int)binding_index)->endpoint != endpoint)
                continue;
            if ((endpoint & 128U) != 0 &&
                report_worker_binding((unsigned int)binding_index)->queue_slot < 6) {
                unsigned int flags = REPORT_FAST_FLAGS_BYTE;
                int submitted = report_intercept_secondary(
                    (unsigned char)endpoint, source_stamp, scratch->payload + 6,
                    (unsigned short)report_length, flags);
                memw();
                REPORT_FAST_ACTIVE = 0;
                if (submitted != 0)
                    goto complete_local;
                goto weak_route;
            }
            break;
        }
        int interface = report_find_fast_interface(endpoint);
        if (interface == -1)
            goto clear_active_then_weak;
        unsigned int flag_bit1 = (REPORT_FAST_SCRATCH_WORDS.flags_and_prefix >> 1) & 1U;
        unsigned int primary_length = report_length < 64 ? report_length : 64;
        xPortEnterCriticalTimeout(&CREDIT_LOCK, 0xffffffffU);
        unsigned long long pending_started_us = (unsigned long long)esp_timer_get_time();
        volatile CreditInterfaceQueue *queue_state = report_worker_queue((unsigned int)interface);
        memw();
        unsigned int history_write = queue_state->history_write_count;
        memw();
        unsigned int history_read = queue_state->history_read_count;
        if (history_write != history_read) {
            unsigned int low = queue_state->pending_start.low;
            unsigned int high = queue_state->pending_start.high;
            if ((low | high) == 0) {
                queue_state->pending_start.low = (unsigned int)pending_started_us;
                queue_state->pending_start.high = (unsigned int)(pending_started_us >> 32);
            }
        }
        vPortExitCritical(&CREDIT_LOCK);
        CaptureEvent event;
        capture_event_build(&event, 4, 0,
            REPORT_CAPTURE_INTERFACE_IDS[interface], (unsigned char)(flag_bit1 * 2U),
            source_stamp, scratch->payload + 6, (unsigned short)primary_length);
        unsigned char submission_status;
        memw();
        submission_status = 0;
        unsigned int submitted = report_process_interface(interface,
            scratch->payload + 6, primary_length, 0, 0, 0,
            &event, 0, 0, (unsigned char)flag_bit1, &submission_status, 1, 0xffffffffU);
        if (submitted == 0)
            goto clear_active_then_weak;
        if (event.ready != 0 && capture_submit_event(4, event.subscriptions,
                0x16, &event.wire, event.wire_length) != 0)
            capture_notify_task();
        memw();
        REPORT_FAST_ACTIVE = 0;
        goto complete_local;

clear_active_then_weak:
        memw();
        REPORT_FAST_ACTIVE = 0;
weak_route:
        if (report_fast_fallback_allowed(scratch->payload, length) == 0)
            goto fallback_rx;
        link_report_decode(scratch->payload, length);
        goto complete_local;

fallback_rx:
        xPortEnterCriticalTimeout(&CREDIT_LOCK, 0xffffffffU);
        unsigned char pending_before = REPORT_PENDING[endpoint_number];
        if (pending_before != 255)
            REPORT_PENDING[endpoint_number] = pending_before + 1U;
        vPortExitCritical(&CREDIT_LOCK);
        if (link_enqueue_rx_copy(0x10, (unsigned char)sequence,
                                       scratch->payload, (unsigned short)length) != 0)
            goto drain_next;

        unsigned long long failed_at_us = (unsigned long long)esp_timer_get_time();
        xPortEnterCriticalTimeout(&CREDIT_LOCK, 0xffffffffU);
        unsigned char pending_now = REPORT_PENDING[endpoint_number];
        if (pending_now != 0)
            REPORT_PENDING[endpoint_number] = pending_now - 1U;
        unsigned int failed_endpoint = REPORT_FAST_SCRATCH_WORDS.endpoint;
        int failure_binding_count = CREDIT_BINDINGS.count;
        int secondary_drop = 0;
        for (int binding_index = 0; binding_index < failure_binding_count; ++binding_index) {
            if (report_worker_binding((unsigned int)binding_index)->endpoint != failed_endpoint)
                continue;
            secondary_drop = (failed_endpoint & 128U) != 0 &&
                report_worker_binding((unsigned int)binding_index)->queue_slot < 6;
            break;
        }
        if (secondary_drop) {
            memw();
            unsigned int drop_count = REPORT_SECONDARY_FALLBACK_DROPS;
            memw();
            REPORT_SECONDARY_FALLBACK_DROPS = drop_count + 1U;
        } else {
            memw();
            unsigned int drop_count = REPORT_PRIMARY_FALLBACK_DROPS;
            memw();
            REPORT_PRIMARY_FALLBACK_DROPS = drop_count + 1U;
        }
        unsigned int canonical_endpoint = endpoint_canonicalize(failed_endpoint);
        int interface_count = CREDIT_INTERFACES.count;
        for (int failed_interface = 0; failed_interface < interface_count; ++failed_interface) {
            const volatile unsigned char *endpoint_address =
                (const volatile unsigned char *)
                ((unsigned int)&CREDIT_INTERFACES + (unsigned int)failed_interface);
            unsigned int configured_endpoint = *endpoint_address;
            if (configured_endpoint != canonical_endpoint)
                continue;
            CreditInterfaceQueue *failed_queue =
                (CreditInterfaceQueue *)report_worker_queue((unsigned short)failed_interface);
            report_history_retire(failed_queue,failed_at_us,0);
            report_service_interface((unsigned int)failed_interface,0);
            memw();
            unsigned int initial_low = REPORT_RECOVERY_EPOCH.low;
            memw();
            unsigned int initial_high = REPORT_RECOVERY_EPOCH.high;
            int allow_recovery = 0;
            if ((initial_low | initial_high) != 0) {
                memw();
                unsigned int epoch_low = REPORT_RECOVERY_EPOCH.low;
                memw();
                unsigned int epoch_high = REPORT_RECOVERY_EPOCH.high;
                unsigned int low = (unsigned int)failed_at_us;
                unsigned int high = (unsigned int)(failed_at_us >> 32);
                int high_difference = (int)(high - epoch_high - (low < epoch_low));
                unsigned int low_difference = low - epoch_low;
                if (high_difference < 0 || (high_difference == 0 && low_difference < 3000U))
                    allow_recovery = REPORT_RECOVERY_MODE <= 1;
            }
            report_try_schedule(failed_queue,allow_recovery,failed_at_us,
                REPORT_INTERFACE_PERIODS[failed_interface],(unsigned int)failed_interface);
            break;
        }
        vPortExitCritical(&CREDIT_LOCK);

complete_local:
        xPortEnterCriticalTimeout(&CREDIT_LOCK, 0xffffffffU);
        unsigned char endpoint_load = CREDIT_STATE.load_observations[endpoint_number];
        if (endpoint_load != 0)
            CREDIT_STATE.load_observations[endpoint_number] = endpoint_load - 1U;
        unsigned long long completed_at_us = (unsigned long long)esp_timer_get_time();
        int credit_changed = credit_state_changed(completed_at_us);
        vPortExitCritical(&CREDIT_LOCK);
        if (credit_changed != 0)
            link_kick_fast_tx();
        goto drain_next;
    }
}
