/* Medius v3.4.7 device: recovered report admission and scheduling pass. */

#include "../include/types.h"

/* Native entry: 0x4037a754. */
/* Original function-byte SHA-256:
 * d69c77d595178719a9c879777e0fc30fd604ae907c9a970c6914d47e5e980cdb. */

/*
 * Processes one interface report, then services active scheduling windows.
 *
 * interface: configured index; report/length: readable report span.
 * force_kind2: nonzero selects kind 2; otherwise derive_kind1 selects kind 1,
 * else kind 0. record_metadata_byte: low byte forwarded; record_metadata_word: full word forwarded.
 * event: optional capture event, also enables history retirement and status write.
 * options: byte forwarded and enables normalization/hash work when nonzero.
 * short_multiple: forwarded for kind 0; recomputed for kind 1/2 from length and
 * configured period/comparison limit. status: writable if event != NULL.
 * reject_if_inhibited: test the fenced inhibit byte before admission.
 * epoch: forwarded for nonzero kind; kind 0 forces UINT_MAX.
 *
 * Returns 0 only for that inhibit gate, 1 after normal processing, including a
 * queue-update drop. This is not a USB delivery result. No allocation is local.
 * Requires valid queue/global indices, stable readable descriptors and caller
 * storage. Enters the credit lock with infinite timeout and ignores its result;
 * every admitted path unlocks before timer arming/capture notification.
 *
 * Before locking, derive the kind and optional short-multiple flag. If kind-1
 * derivation or options request hashing, input-0 must be active for this exact
 * interface: copy min(length,64), clear described bits using that BYTE BOUND,
 * optionally zero two configured bytes, then FNV-1a hash the normalized copy.
 * Empty input hashes to the FNV seed; unmatched/disabled input hashes to 0.
 *
 * Under lock: clock sample, optional history retirement, mode and two independent
 * fenced epoch snapshots, then queue update. Its four-word result supplies drop
 * flags and a dirty-state pointer; that pointer is marked, never freed here.
 * On a drop, increment the selected drop counter, mark queues dirty and service
 * this interface. High-water tracking uses ONE cached count before its fence.
 * Publish any ready capture event, fence/read fast_enabled BEFORE clearing ready,
 * then test inhibition and signed interface count before a scheduling pass.
 *
 * That pass samples a fresh clock per interface and a fresh count at each tail.
 * Compare window HIGH before conditional LOW reads; strict HIGH/LOW are cached
 * together. Restore omitted scheduler arguments: queue, now, deadline, period,
 * interface and strict flag. Expiry may set deferred, then clears window_active
 * and reservation. Only empty-extra queues with a pending prefix contribute a
 * nonzero start/strict deadline; keep the earliest signed timestamp, ties first.
 * Read orders, byte flags and negative modular ages are retained. Queue admission
 * is recovered in report_queue.c; no physical timing/concurrent execution claim.
 */
unsigned int report_process_interface(unsigned int interface,
    const unsigned char *report,unsigned int length,int force_kind2,int derive_kind1,
    unsigned int record_metadata_byte,CaptureEvent *event,unsigned int record_metadata_word,
    unsigned char options,unsigned char short_multiple,unsigned char *status,
    unsigned char reject_if_inhibited,unsigned int epoch)
{
    unsigned int kind = force_kind2 != 0 ? 2U : derive_kind1 != 0 ? 1U : 0U;
    unsigned int multiple = short_multiple;
    if (kind != 0) {
        multiple = 0;
        if (length != 0) {
            unsigned int period = REPORT_INTERFACE_PERIODS[interface];
            unsigned int limit = REPORT_COMPARISON_LIMITS[interface];
            if (limit < period)
                limit = period;
            if (length < limit && period != 0)
                multiple = length % period == 0;
        }
    }
    unsigned int normalized_hash = 0;
    if ((derive_kind1 != 0 || options != 0) && REPORT_BLOCK0_ACTIVE != 0 &&
        REPORT_BLOCK0_INTERFACE == (int)interface) {
        unsigned char normalized[64];
        unsigned int copy_length = length < 64 ? length : 64;
        memcpy(normalized,report,copy_length);
        const volatile InputStateView *input = INPUT0_STATE;
        const ReportNormalizationView *descriptor = input->descriptor;
        if (descriptor != NULL) {
            report_clear_layout_bits((const BitClearLayout *)descriptor,
                normalized,copy_length);
            const volatile ReportNormalizationView *normalization = descriptor;
            unsigned int mode = normalization->mode;
            if (mode != 0) {
                unsigned int primary_byte = normalization->primary_byte;
                unsigned int primary_flags = input->primary_normalization_flags;
                if ((primary_flags & 0x80U) == 0 && primary_byte < copy_length)
                    normalized[primary_byte] = 0;
                if (mode != 1) {
                    unsigned int secondary_flags = input->secondary_normalization_flags;
                    unsigned int secondary_byte = normalization->secondary_byte;
                    if ((secondary_flags & 0x80U) == 0 && secondary_byte < copy_length)
                        normalized[secondary_byte] = 0;
                }
            }
        }
        normalized_hash = 0x811c9dc5U;
        if (length != 0)
            for (unsigned int byte = 0; byte < copy_length; ++byte)
                normalized_hash = (normalized_hash ^ normalized[byte]) * 0x01000193U;
    }

    xPortEnterCriticalTimeout(&CREDIT_LOCK,0xffffffffU);
    if (reject_if_inhibited != 0) {
        memw();
        if (USB_SUSPENDED != 0) {
            vPortExitCritical(&CREDIT_LOCK);
            return 0;
        }
    }
    unsigned long long now = esp_timer_get_time();
    /* Native indexing wraps at 32 bits and has no local interface bound. */
    unsigned int queue_address = (unsigned int)REPORT_HISTORY_QUEUES + interface * 960U;
    volatile CreditInterfaceQueue *queue_state = (volatile CreditInterfaceQueue *)queue_address;
    if (event != NULL) {
        report_history_retire((CreditInterfaceQueue *)queue_state,now,length != 0);
        memw();
        *(volatile unsigned char *)status = 1;
    }
    const volatile ReportInterfaceMode *interface_mode =
        (const volatile ReportInterfaceMode *)((unsigned int)REPORT_INTERFACE_MODES + interface * 304U);
    unsigned int mode = interface_mode->block4 != 0 || interface_mode->block_db != 0 || interface_mode->block_11f != 0;
    unsigned int allow_recovery = 0;
    memw();
    unsigned int first_low = REPORT_RECOVERY_EPOCH.low;
    memw();
    unsigned int first_high = REPORT_RECOVERY_EPOCH.high;
    if ((first_low | first_high) != 0) {
        memw();
        unsigned int low = REPORT_RECOVERY_EPOCH.low;
        memw();
        unsigned int high = REPORT_RECOVERY_EPOCH.high;
        unsigned long long recovery_epoch = ((unsigned long long)high << 32) | low;
        if ((long long)(now - recovery_epoch) < 3000)
            allow_recovery = REPORT_RECOVERY_MODE <= 1;
    }
    unsigned int period = REPORT_INTERFACE_PERIODS[interface];
    ReportQueueResult result = report_queue_update(
        (CreditInterfaceQueue *)queue_state,report,length,kind,record_metadata_byte & 255U,
        record_metadata_word,mode,options,normalized_hash,multiple,interface,allow_recovery,
        now,period,interface,kind != 0 ? epoch : 0xffffffffU);
    if (result.dropped != 0) {
        volatile unsigned int *counter = result.secondary != 0 ?
            &REPORT_SECONDARY_FALLBACK_DROPS : &REPORT_PRIMARY_FALLBACK_DROPS;
        memw();
        unsigned int drops = *counter;
        memw();
        *counter = drops + 1U;
        memw();
        REPORT_QUEUES_DIRTY = 1;
        if (result.dirty_state != NULL)
            input_mark_dirty(result.dirty_state);
        report_service_interface(interface,0);
    }
    unsigned int depth = queue_state->record_count;
    memw();
    unsigned int high_water = REPORT_DEPTH_HIGH_WATER;
    if (high_water < depth) {
        memw();
        REPORT_DEPTH_HIGH_WATER = depth;
    }
    unsigned int capture_submitted = 0;
    unsigned long long earliest = 0;
    volatile CaptureEvent *capture_event = event;
    if (capture_event != NULL && capture_event->ready != 0) {
        unsigned int subscribers = capture_event->subscriptions;
        unsigned int wire_length = capture_event->wire_length;
        capture_submitted = capture_submit_event(4,subscribers,0x16,
            &event->wire,wire_length);
        memw();
        unsigned int enabled = REPORT_FAST_ENABLED;
        capture_event->ready = 0;
        if (enabled == 0)
            goto unlock;
    } else {
        memw();
        if (REPORT_FAST_ENABLED == 0)
            goto unlock;
    }
    memw();
    if (USB_SUSPENDED != 0 || CREDIT_INTERFACES.count < 1)
        goto unlock;

    unsigned int current_interface = 0;
    do {
        unsigned long long current_time = esp_timer_get_time();
        unsigned int now_low = (unsigned int)current_time;
        unsigned int now_high = (unsigned int)(current_time >> 32);
        volatile CreditInterfaceQueue *active = (volatile CreditInterfaceQueue *)(
            (unsigned int)REPORT_HISTORY_QUEUES + current_interface * 960U);
        if (active->window_active != 0) {
            unsigned int start_high = active->window_start.high;
            if ((int)now_high < (int)start_high ||
                (now_high == start_high && now_low < active->window_start.low))
                goto consider_deadline;
            unsigned int strict_high = active->window_strict.high;
            unsigned int strict_low = active->window_strict.low;
            unsigned int strict = (int)now_high > (int)strict_high ||
                (now_high == strict_high && now_low >= strict_low);
            unsigned int end_high = active->window_end.high;
            if ((int)now_high < (int)end_high ||
                (now_high == end_high && now_low < active->window_end.low)) {
                unsigned int current_period = REPORT_INTERFACE_PERIODS[current_interface];
                if (strict != 0)
                    active->reservation = 0;
                unsigned int deadline_low = active->window_deadline.low;
                unsigned int deadline_high = active->window_deadline.high;
                unsigned long long deadline = ((unsigned long long)deadline_high << 32) | deadline_low;
                report_schedule_candidate((CreditInterfaceQueue *)active,
                    current_time,deadline,current_period,current_interface,strict);
                if (active->window_active == 0)
                    goto next_interface;
            } else {
                if (active->extra_pending == 0 &&
                    report_prefix_has_pending_kind((const CreditInterfaceQueue *)active) != 0 &&
                    active->expiry_defer_enabled != 0)
                    active->deferred = 1;
                active->window_active = 0;
                active->reservation = 0;
                goto next_interface;
            }
consider_deadline:
            if (active->extra_pending == 0 &&
                report_prefix_has_pending_kind((const CreditInterfaceQueue *)active) != 0) {
                unsigned int high = active->window_start.high;
                unsigned int low = active->window_start.low;
                if ((int)now_high > (int)high || (now_high == high && now_low >= low)) {
                    if (active->reservation == 0)
                        goto next_interface;
                    high = active->window_strict.high;
                    low = active->window_strict.low;
                    if ((int)now_high > (int)high || (now_high == high && now_low >= low))
                        goto next_interface;
                }
                unsigned long long candidate = ((unsigned long long)high << 32) | low;
                if ((low | high) != 0 && (earliest == 0 || (long long)candidate < (long long)earliest))
                    earliest = candidate;
            }
        }
next_interface:
        ++current_interface;
    } while ((int)current_interface < CREDIT_INTERFACES.count);
unlock:
    vPortExitCritical(&CREDIT_LOCK);
    if (earliest != 0)
        decision_timer_arm((unsigned int)earliest,(int)(earliest >> 32));
    if (capture_submitted != 0)
        capture_notify_task();
    return 1;
}
