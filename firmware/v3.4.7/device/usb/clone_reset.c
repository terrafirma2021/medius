/* Medius v3.4.7 device: clone reset and host notification. */

#include "../include/types.h"

/* Native entry: 0x4203550c. */
/* Original function-byte SHA-256:
 * 35ea64f44e1913c52c4030d217b60a57629e5ffd6fd0e571abaabb33fd222be9. */
/* Take the initially sampled report mutex indefinitely if present; ignore
 * take result. MEMW then read clone-active BYTE ONCE (raw Ghidra showed a
 * spurious extra read). Inactive: clear runtime bindings, publish configuration
 * count1 then index0. Active: MEMW/store quiescing1, then call the separately
 * identified quiesce/teardown boundary. No local retry or error result.
 * Clear archive-used HALFWORD, snapshot patch/rewrite mutex BEFORE clearing
 * report-descriptor assembly pointer, then optionally take that saved mutex.
 * Zero all1190 bytes of the served patch table, clear refused-patch BYTE,
 * RELOAD inner mutex BEFORE clearing identity-ready BYTE, then conditionally
 * release it. Reload/release outer report mutex too. These handles can differ
 * from the ones acquired if changed concurrently; all queue results ignored.
 * Finally MEMW/read the served interval BYTE AFTER releasing both locks; send
 * it as host opcode0x30/flags0/length1, ignoring enqueue status. Archive storage,
 * pending descriptor bytes and allocated patch buffers are not freed here.
 * No guarantee that teardown completed, host received the byte, or mutex
 * acquisition succeeded. Callee internals remain separate native reviews. */
void clone_reset_and_notify_host(void)
{
    RtosQueue *report_mutex = REPORT_MUTEX;
    if (report_mutex != NULL)
        xQueueSemaphoreTake(report_mutex,0xffffffffU);
    memw();
    unsigned char active = CLONE_ACTIVE;
    if (active == 0) {
        usb_clone_clear_runtime_state();
        MEDIUS_CLONE_CONFIGURATION_COUNT = 1;
        MEDIUS_CLONE_CONFIGURATION_INDEX = active; /* saved zero */
    }
    else {
        memw();
        CLONE_QUIESCING = 1;
        medius_usb_clone_quiesce_and_clear();
    }
    MEDIUS_REPORT_ARCHIVE->used = 0;
    RtosQueue *patch_mutex = REWRITE_MUTEX;
    MEDIUS_CLONE_REPORT_ASSEMBLY = NULL;
    if (patch_mutex != NULL)
        xQueueSemaphoreTake(patch_mutex,0xffffffffU);
    memset(MEDIUS_CLONE_SERVED_PATCH,0,sizeof(*MEDIUS_CLONE_SERVED_PATCH));
    CLONE_PATCH_REFUSED = 0;
    patch_mutex = REWRITE_MUTEX;
    MEDIUS_CLONE_PATCH_IDENTITY_READY = 0;
    if (patch_mutex != NULL)
        xQueueGenericSend(patch_mutex,NULL,0,0);
    report_mutex = REPORT_MUTEX;
    if (report_mutex != NULL)
        xQueueGenericSend(report_mutex,NULL,0,0);
    memw();
    unsigned char served_interval = EMISSION_OPTIONS.served_interval;
    link_send_wait100(0x30,0,&served_interval,1);
}


/* Native entry: 0x4202a820. */
/* Original function-byte SHA-256:
 * 62945bb15bee507222afd551c39907b31f679b3404db9314762d6e8e8e0f6df3. */
/* Clear clone endpoint-table counts and descriptor diagnostics in native order.
 * Clear the seven endpoint/report failure BYTE flags first, then auxiliary
 * noncontrol count WORD, capacity BYTE, auxiliary control count WORD, its
 * bulk/iso HALFWORD and conflict BYTE. Repeat those four table stores for the
 * served vendor/control table. Clear all six retained IN binding records
 * (24 bytes), then chain-truncation, high-speed, missing-configuration and
 * imperfect BYTE flags; finally clear the three excess-endpoint bytes.
 * Table record payloads, control endpoints/MPS, allow-imperfect and low-speed
 * policy bytes are retained. This is bookkeeping only: no controller call,
 * free, lock, explicit MEMW, worker stop or completion wait is performed.
 * Callers must serialize incompatible changes; this helper does not do so. */
void usb_clone_clear_runtime_state(void)
{
    MEDIUS_CLONE_ENDPOINT_INDEX_EXCEEDED = 0;
    MEDIUS_CLONE_PACKET_SIZE_EXCEEDED = 0;
    MEDIUS_CLONE_OUT_ENDPOINT_CONFLICT = 0;
    MEDIUS_CLONE_BAD_CONFIGURATION_CHAIN = 0;
    MEDIUS_CLONE_HID_ISOCHRONOUS = 0;
    MEDIUS_CLONE_REPORT_CAPTURE_EXCEEDED = 0;
    MEDIUS_CLONE_REPORT_MISSING = 0;
    MEDIUS_CLONE_AUX_ENDPOINTS->noncontrol_count = 0;
    CLONE_CAPACITY_EXCEEDED = 0;
    MEDIUS_CLONE_AUX_ENDPOINTS->control_count = 0;
    MEDIUS_CLONE_AUX_ENDPOINTS->transfer_flags = 0;
    MEDIUS_CLONE_AUX_ENDPOINTS->conflict = 0;
    MEDIUS_CLONE_SERVED_ENDPOINTS->noncontrol_count = 0;
    MEDIUS_CLONE_SERVED_ENDPOINTS->control_count = 0;
    MEDIUS_CLONE_SERVED_ENDPOINTS->transfer_flags = 0;
    MEDIUS_CLONE_SERVED_ENDPOINTS->conflict = 0;
    memset(MEDIUS_CLONE_RETAINED_IN_BINDINGS,0,24);
    MEDIUS_CLONE_CONFIGURATION_TRUNCATED = 0;
    MEDIUS_CLONE_HIGH_SPEED = 0;
    MEDIUS_CLONE_CONFIGURATIONS_MISSING = 0;
    CLONE_IMPERFECT = 0;
    memset(MEDIUS_CLONE_EXCESS_ENDPOINT_INFO,0,3);
}

/* Native entry: 0x4202d3c0. */
/* Original function-byte SHA-256:
 * 866d8f2df5b055ea05de41d45107a03e30ba186b67acfca9a261bbe46632fe5e. */
/* Quiesce and clear a running clone. Increment both nonzero-control generation
 * BYTEs modulo256 and clear their state BYTEs with native MEMWs. Snapshot the
 * nonzero-worker signal BETWEEN the second generation read and write. Wake it
 * if nonnull. If EP0 reply waiting is set, snapshot its signal BEFORE clearing
 * waiting and publishing resultUINT_MAX, then give that saved signal unchecked.
 * Clear reply assembly length/state. Poll seven flags in short-circuit order,
 * fencing each tested BYTE; while any is set, compare a fresh signed64 clock
 * against saved(now+300000), then delay1 tick if still earlier. Expiry proceeds
 * with teardown, without a success result or proof all workers stopped.
 *
 * Deinitialize bus0, then clear clone-active/quiescing, endpoint table counts
 * and failure flags in the interleaved native order. Keep endpoint records and
 * imperfect/allow-imperfect/low-speed policy bytes. Clear retained IN bindings24
 * bytes and all256 alternate settings. Restore configuration count1/index0 and
 * reconcile OUT endpoints. Clear six report blocks with separate fences, then
 * deduct-one, wake and other report gates; notify motion configuration changed.
 * Under the credit spinlock clear16 completion-bucket bytes, all16 endpoint-map
 * BYTEs to255 and pending-endpoint HALFWORD. Take optional rewrite mutex, then
 * credit lock, reset six interface runtimes and mark three fixed states dirty.
 * Outside credit lock reset primary, keyboard and consumer input runtime, fixed
 * bindings and all live dynamic states. Dynamic count is reloaded before each
 * observed-valid BYTE clear; no capacity clamp. Clear dynamic count last.
 *
 * Snapshot change-sequence and acknowledgement WORDs with two then one MEMWs;
 * if different increment epoch HALFWORD, then acknowledge the saved sequence.
 * Reset subscriptions, invalidate capture baselines, clear3592 rewrite bytes
 * and258 observed-rule bytes, clear saved button/control state and persistence
 * identity/gates. Clear interval-learning flags and788 history bytes. Zero
 * learned-period WORD, MEMW/read pace BYTE ONCE, then set first-frequent bin128.
 * Pace1 rereads the just-cleared learned period; pace2 uses1000us unless the
 * configured-Hz HALFWORD test succeeds, in which case MEMW/read it AGAIN and
 * divide1000000 by min(freshHz,1000). A concurrent second read0 yields the native
 * IntegerDivideByZero exception. Keep QUOU explicit rather than inventing a
 * fallback value or relying on C division-by-zero behavior. Other pace values
 * select0. Publish
 * period WORD only ONCE after calculation: raw Ghidra introduced false stores
 * and rereads here. Notify motion change, reset playback, advance render token
 * modulo256 skipping0 and notify motion change again. Release freshly read
 * rewrite mutex if nonnull. Under event lock clear each ring's cursor/count
 * pair with one WORD store, leaving ring contents/stride/capacity intact.
 *
 * If timer mutex was initially nonnull, take it ignoring status, fence/read
 * armed BYTE and stop a currently nonnull timer only when armed. Clear armed
 * AFTER stop even if it failed. Give a freshly reloaded timer mutex WITHOUT a
 * second null check. Log clone-down warning and return. No driver, lock, queue
 * or timer error is propagated; earlier callbacks may mutate shared storage.
 * This recovers native sequencing, not runtime/USB/concurrency equivalence. */
void medius_usb_clone_quiesce_and_clear(void)
{
    volatile MediusNonzeroControlState *control = MEDIUS_NONZERO_CONTROL_STATES;
    memw();
    unsigned char generation = control[0].generation;
    memw();
    control[0].generation = (unsigned char)(generation + 1U);
    memw();
    control[0].state = 0;
    memw();
    generation = control[1].generation;
    RtosQueue *signal = NONZERO_CONTROL_WORKER_SIGNAL;
    memw();
    control[1].generation = (unsigned char)(generation + 1U);
    memw();
    control[1].state = 0;
    if (signal != NULL)
        xQueueGenericSend(signal,NULL,0,0);
    memw();
    if (EP0_REPLY_WAITING != 0) {
        signal = CONTROL_ENDPOINT_REPLY_SIGNAL;
        memw();
        EP0_REPLY_WAITING = 0;
        memw();
        MEDIUS_EP0_REPLY_RESULT = 0xffffffffU;
        xQueueGenericSend(signal,NULL,0,0);
    }
    MEDIUS_EP0_REPLY_ASSEMBLY->length = 0;
    MEDIUS_EP0_REPLY_ASSEMBLY->state = 0;
    unsigned long long deadline = (unsigned long long)esp_timer_get_time() + 300000U;
    while ((memw(),MEDIUS_EP0_WORKER_BUSY) != 0 ||
           (memw(),REPORT_FAST_BLOCK98) != 0 ||
           (memw(),REPORT_FAST_BLOCK97) != 0 ||
           (memw(),NONZERO_CONTROL_WORKER_BUSY) != 0 ||
           (memw(),MEDIUS_REPORT_FAST_WORKER_BUSY) != 0 ||
           (memw(),REPORT_MAINTENANCE_BUSY) != 0 ||
           (memw(),REPORT_FAST_ACTIVE) != 0) {
        if (esp_timer_get_time() >= (long long)deadline)
            break;
        vTaskDelay(1);
    }
    usbd_deinitialize(0);
    memw();
    CLONE_ACTIVE = 0;
    memw();
    CLONE_QUIESCING = 0;
    MEDIUS_CLONE_ENDPOINT_INDEX_EXCEEDED = 0;
    MEDIUS_CLONE_PACKET_SIZE_EXCEEDED = 0;
    MEDIUS_CLONE_OUT_ENDPOINT_CONFLICT = 0;
    MEDIUS_CLONE_BAD_CONFIGURATION_CHAIN = 0;
    MEDIUS_CLONE_SERVED_ENDPOINTS->noncontrol_count = 0;
    MEDIUS_CLONE_HID_ISOCHRONOUS = 0;
    MEDIUS_CLONE_SERVED_ENDPOINTS->control_count = 0;
    MEDIUS_CLONE_REPORT_CAPTURE_EXCEEDED = 0;
    MEDIUS_CLONE_SERVED_ENDPOINTS->transfer_flags = 0;
    MEDIUS_CLONE_REPORT_MISSING = 0;
    MEDIUS_CLONE_SERVED_ENDPOINTS->conflict = 0;
    CLONE_CAPACITY_EXCEEDED = 0;
    MEDIUS_CLONE_AUX_ENDPOINTS->noncontrol_count = 0;
    MEDIUS_CLONE_AUX_ENDPOINTS->control_count = 0;
    MEDIUS_CLONE_AUX_ENDPOINTS->transfer_flags = 0;
    MEDIUS_CLONE_AUX_ENDPOINTS->conflict = 0;
    memset(MEDIUS_CLONE_RETAINED_IN_BINDINGS,0,24);
    memset(CLONE_ALTERNATE_SETTINGS,0,256);
    memw();
    CLONE_ALTERNATE_PENDING = 0;
    memw();
    EMISSION_OPTIONS.served_interval = 0;
    memw();
    EMISSION_OPTIONS.unknown4 = 0;
    MEDIUS_CLONE_CONFIGURATION_TRUNCATED = 0;
    MEDIUS_CLONE_HIGH_SPEED = 0;
    MEDIUS_CLONE_CONFIGURATIONS_MISSING = 0;
    memw();
    EMISSION_OPTIONS.learned_period = 0;
    memset(MEDIUS_CLONE_EXCESS_ENDPOINT_INFO,0,3);
    MEDIUS_CLONE_CONFIGURATION_COUNT = 1;
    MEDIUS_CLONE_CONFIGURATION_INDEX = 0;
    medius_out_reconcile_endpoints(NULL,NULL,0);
    for (unsigned int index = 0; index < 6; ++index) {
        memw();
        REPORT_INTERFACE_BLOCKED[index] = 0;
    }
    memw();
    USB_SUSPENDED = 0;
    motion_configuration_changed();
    memw();
    REPORT_QUEUES_DIRTY = 1;
    memw();
    REPORT_WAKE_REQUEST = 0;
    memw();
    REPORT_FAST_GATE96 = 0;
    memw();
    MEDIUS_USB_REMOTE_WAKE_ENABLED = 0;
    xPortEnterCriticalTimeout(&CREDIT_LOCK,-1);
    memset(MEDIUS_REPORT_COMPLETION_BUCKETS,0,16);
    for (unsigned int endpoint = 0; endpoint < 16; ++endpoint) {
        memw();
        CREDIT_ENDPOINT_INTERFACE[endpoint] = -1;
    }
    MEDIUS_REPORT_PENDING_ENDPOINTS = 0;
    vPortExitCritical(&CREDIT_LOCK);
    RtosQueue *mutex = REWRITE_MUTEX;
    if (mutex != NULL)
        xQueueSemaphoreTake(mutex,0xffffffffU);
    xPortEnterCriticalTimeout(&CREDIT_LOCK,-1);
    for (unsigned int index = 0; index < 6; ++index) {
        report_reset_interface_runtime(index);
        memw();
        REPORT_INTERFACE_COMPLETING[index] = 0;
    }
    input_mark_dirty(INPUT0_STATE);
    input_mark_dirty(INPUT1_STATE);
    input_mark_dirty(INPUT2_STATE);
    vPortExitCritical(&CREDIT_LOCK);
    input_reset_runtime(INPUT0_STATE);
    memw();
    FIXED_INPUTS[0].idle_motion_anchor.low = 0;
    memw();
    FIXED_INPUTS[0].idle_motion_anchor.high = 0;
    FIXED_INPUTS[0].enabled = 0;
    FIXED_INPUTS[0].interface = -1;
    input_reset_runtime(INPUT1_STATE);
    FIXED_INPUTS[1].enabled = 0;
    FIXED_INPUTS[1].interface = -1;
    input_reset_runtime(INPUT2_STATE);
    int binding_count = REPORT_BINDING_COUNT;
    FIXED_INPUTS[2].enabled = 0;
    FIXED_INPUTS[2].interface = -1;
    if (binding_count > 0) {
        unsigned int index = 0;
        volatile ReportLayoutBinding *binding = REPORT_BINDINGS;
        do {
            input_reset_runtime((InputStateView *)&binding->state);
            binding->interface = -1;
            binding_count = REPORT_BINDING_COUNT;
            binding->observed_buttons_valid = 0;
            ++index;
            ++binding;
        } while ((int)index < binding_count);
    }
    REPORT_BINDING_COUNT = 0;
    memw();
    memw();
    unsigned int sequence = INPUT_CHANGE_SEQUENCE;
    memw();
    unsigned int acknowledged = INPUT_CHANGE_ACKNOWLEDGED;
    if (sequence != acknowledged)
        INPUT_CHANGE_EPOCH = (unsigned short)(INPUT_CHANGE_EPOCH + 1U);
    INPUT_CHANGE_ACKNOWLEDGED = sequence;
    capture_clear_subscriptions();
    memw();
    REPORT_CAPTURE_BUTTONS_VALID = 0;
    memw();
    REPORT_KEYBOARD_CAPTURE.valid = 0;
    memw();
    REPORT_CONSUMER_CAPTURE.valid = 0;
    memset((void *)REWRITE_RULES,0,3592);
    memset((void *)OBSERVED_BUTTON_RULES,0,258);
    input_clear_last_controls();
    memw();
    PROFILE_BASELINE_PENDING = 0;
    memw();
    PROFILE_NORMALIZATION_PENDING = 0;
    memw();
    FIXED_INPUTS[0].motion_seen = 0;
    memw();
    INPUT_ACTIVE_IDENTITY[1] = 0;
    memw();
    INPUT_ACTIVE_IDENTITY[0] = 0;
    memw();
    INPUT_IDENTITY_LOADED = 0;
    memw();
    INPUT_IDENTITY_PENDING = 0;
    memw();
    INPUT_PENDING_IDENTITY[1] = 0;
    memw();
    INPUT_PENDING_IDENTITY[0] = 0;
    memw();
    PROFILE_PERIOD_PENDING = 0;
    memw();
    REPORT_LEARNED_PERIOD = 0;
    memw();
    REPORT_INTERVAL_SEEN = 0;
    memw();
    REPORT_ACTIVE_THRESHOLD = 0;
    memw();
    REPORT_PENDING_THRESHOLD = 0;
    memw();
    REPORT_PERIOD_DEBOUNCE = 0;
    memset((void *)&REPORT_INTERVAL_HISTORY,0,788);
    memw();
    EMISSION_OPTIONS.learned_period_us = 0;
    memw();
    unsigned char pace = EMISSION_OPTIONS.pace;
    REPORT_INTERVAL_HISTORY.first_frequent = 128;
    unsigned int period_us = 0;
    if (pace == 1) {
        memw();
        period_us = EMISSION_OPTIONS.learned_period_us;
    } else if (pace == 2) {
        period_us = 1000;
        memw();
        if (EMISSION_OPTIONS.configured_hz != 0) {
            memw();
            unsigned int hz = EMISSION_OPTIONS.configured_hz;
            unsigned int limited_hz = hz < 1000 ? hz : 1000;
            period_us = xtensa_unsigned_divide(1000000U,limited_hz);
        }
    }
    memw();
    EMISSION_OPTIONS.period_us = period_us;
    motion_configuration_changed();
    playback_reset_runtime();
    unsigned char token = (unsigned char)(MOTION_RENDER_TOKEN + 1U);
    MOTION_RENDER_TOKEN = token == 0 ? 1 : token;
    motion_configuration_changed();
    mutex = REWRITE_MUTEX;
    if (mutex != NULL)
        xQueueGenericSend(mutex,NULL,0,0);
    xPortEnterCriticalTimeout(&MEDIUS_CAPTURE_LOCK,-1);
    CONTROL_EVENT_RINGS[0].cursor_and_count = 0;
    CONTROL_EVENT_RINGS[1].cursor_and_count = 0;
    CONTROL_EVENT_RINGS[2].cursor_and_count = 0;
    CONTROL_EVENT_RINGS[3].cursor_and_count = 0;
    vPortExitCritical(&MEDIUS_CAPTURE_LOCK);
    mutex = INPUT_TIMER_MUTEX;
    if (mutex != NULL) {
        xQueueSemaphoreTake(mutex,0xffffffffU);
        memw();
        if (INPUT_TIMER_ARMED != 0) {
            EspTimer *timer = INPUT_TIMER_HANDLE;
            if (timer != NULL) {
                esp_timer_stop(timer);
                memw();
                INPUT_TIMER_ARMED = 0;
            }
        }
        xQueueGenericSend(INPUT_TIMER_MUTEX,NULL,0,0);
    }
    unsigned int timestamp = esp_log_timestamp();
    esp_log_write(2,"usbdev","W (%lu) %s: clone down\n",timestamp,"usbdev");
}
