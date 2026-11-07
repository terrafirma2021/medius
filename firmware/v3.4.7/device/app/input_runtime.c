/* Device output caches, endpoint priorities and input service. */

#include "../include/types.h"

/* Native entry: 0x42029128. */
/* Original function-byte SHA-256:
 * a68c1bc25f6219e236468f563cb25befe830d3b6989d9b288771fade821ccca8. */
/* Clear the reset request, then reset all three fixed cached output reports,
 * valid bytes, unchanged counters and suppression latches. Clear their bits
 * in the shared output mask using a fresh byte read per binding. Restore
 * nonzero report IDs from primary/keyboard/consumer layout offsets4/db/11f.
 * The consumer's two suppression bytes are cleared by ONE halfword store
 * when its layout is present. Dynamic 904-byte bindings similarly reset 64
 * output bytes, optional layout report ID and three status bytes. Dynamic
 * count is sampled initially, then after each layout pointer load, before
 * reading its report ID. No bounds repair, lock or notification; only the
 * initial reset-request store has a native memory fence. */
void input_reset_output_reports(void)
{
    memw();
    OUTPUT_RESET_PENDING = 0;
    for (unsigned int index = 0; index < 3; ++index) {
        volatile FixedInputBinding *binding = FIXED_INPUTS+index;
        memset((void *)binding->previous_output,0,64);
        unsigned int output_mask = FIXED_OUTPUT_MASK;
        HidReportLayout *layout = binding->state.hid_layout;
        binding->output_valid = 0;
        FIXED_OUTPUT_MASK = (unsigned char)(output_mask & ~(1U << index));
        if (layout != 0) {
            const volatile HidReportLayout *view = layout;
            unsigned int report_id = index == 0 ? view->report_id :
                index == 1 ? view->keyboard.report_id : view->consumer.report_id;
            if (report_id != 0)
                binding->previous_output[0] = (unsigned char)report_id;
            if (index == 2) {
                binding->suppression_pair = 0;
                continue;
            }
        }
        binding->unchanged_count = 0;
        binding->suppress_until_change = 0;
    }
    int count = REPORT_BINDING_COUNT;
    for (int index = 0; index < count; ++index) {
        volatile ReportLayoutBinding *binding = REPORT_BINDINGS+index;
        memset((void *)binding->previous_output,0,64);
        const volatile HidReportLayout *layout = binding->state.hid_layout;
        count = REPORT_BINDING_COUNT;
        if (layout != 0) {
            unsigned int report_id = layout->report_id;
            if (report_id != 0)
                binding->previous_output[0] = (unsigned char)report_id;
        }
        binding->last_input_valid = 0;
        binding->unchanged_count = 0;
        binding->suppress_until_change = 0;
    }
}

/* Native entry: 0x42028c30. */
/* Original function-byte SHA-256:
 * b5a497562ae1c99e720696577f9dfa4a53a09086b11a041cb5159d50ab408043. */
/* Build DWC2 bus0's priority mask from the three fixed interface indices,
 * followed by at most six dynamic indices. Cache dynamic count before the
 * copy and interface count before selection. Skip negative/out-of-range
 * interfaces, endpoint0 and duplicate LOW4 endpoint numbers. Stop after
 * three distinct endpoints or the copied list. An empty result clears the
 * priority mask. No input-state reset, allocation, lock or memory fence. */
void input_refresh_endpoint_priorities(void)
{
    int interfaces[9];
    interfaces[0] = FIXED_INPUTS[0].interface;
    interfaces[1] = FIXED_INPUTS[1].interface;
    interfaces[2] = FIXED_INPUTS[2].interface;
    int dynamic_count = REPORT_BINDING_COUNT;
    unsigned int length = 3;
    for (int index = 0; index < dynamic_count && index < 6; ++index)
        interfaces[length++] = ((volatile ReportLayoutBinding *)REPORT_BINDINGS)[index].interface;
    int interface_count = USB_INTERFACE_COUNT;
    unsigned int mask = 0;
    unsigned int selected = 0;
    for (unsigned int index = 0; index < length && selected != 3; ++index) {
        int interface = interfaces[index];
        if (interface < 0 || interface >= interface_count)
            continue;
        unsigned int endpoint = USB_INTERFACE_ENDPOINTS[interface] & 15U;
        unsigned int bit = 1U << endpoint;
        if (endpoint != 0 && (mask & bit) == 0) {
            ++selected;
            mask = (mask | bit) & 65535U;
        }
    }
    dwc2_set_priority_mask(0,(unsigned short)mask);
}

/* Native entry: 0x4202d948. */
/* Original function-byte SHA-256:
 * 752481ab5acad7283b40dcae55e5f3562075531ee0608bb0dbe2a4d2d82bc521. */
/* Combine observed buttons from the enabled fixed primary and every dynamic
 * binding with a layout. Limit each to its layout's button count when <16;
 * counts>=16 retain the full 16-bit mask. Dynamic count is cached; its native
 * optimized loop reduces a positive count to ((count-1)&0x1fffffff)+1.
 * Walk the eight-byte mapping table with a fresh byte count after each row,
 * comparing LOW8(index). Only source_kind 0 and target_kind 1(keyboard)/2
 * (consumer) participate, when the corresponding fixed binding is enabled.
 * Button >= 16 requests release, otherwise use its aggregate bit. Apply the
 * target usage through the saved-control updater; cache which target classes
 * changed. Service changed states only if needs_service, passing UINT_MAX.
 * Neither table counts nor usage values are validated here. No local lock,
 * fence or time read; the called updater/service supplies its own behavior. */
void input_update_button_mappings(void)
{
    unsigned int buttons = 0;
    volatile FixedInputBinding *primary = FIXED_INPUTS;
    if (primary->enabled != 0) {
        const volatile HidReportLayout *layout = primary->state.hid_layout;
        if (layout != 0) {
            unsigned int count = layout->button_count;
            buttons = primary->last_buttons;
            if (count < 16)
                buttons &= (1U << count)-1U;
        }
    }
    int dynamic_count = REPORT_BINDING_COUNT;
    if (dynamic_count > 0) {
        unsigned int iterations = (((unsigned int)dynamic_count-1U) & 0x1fffffffU)+1U;
        for (unsigned int index = 0; index < iterations; ++index) {
            const volatile ReportLayoutBinding *binding = REPORT_BINDINGS+index;
            const volatile HidReportLayout *layout = binding->state.hid_layout;
            if (layout != 0) {
                unsigned int count = layout->button_count;
                unsigned int observed = binding->last_buttons;
                if (count < 16)
                    observed &= (1U << count)-1U;
                buttons |= observed;
            }
        }
    }
    unsigned int count = OBSERVED_BUTTON_RULE_COUNT;
    if (count == 0)
        return;
    unsigned char changed[3] = {0,0,0};
    unsigned int index = 0;
    do {
        const volatile ObservedButtonRule *rule = OBSERVED_BUTTON_RULES+index;
        if (rule->source_kind == 0) {
            unsigned int target = rule->target_kind;
            if ((target == 1 || target == 2) && FIXED_INPUTS[target].enabled != 0) {
                unsigned int button = rule->button;
                unsigned int pressed = button < 16 ? (buttons >> button) & 1U : 0;
                unsigned int usage = rule->target_usage;
                InputStateView *state = target == 1 ? INPUT1_STATE : INPUT2_STATE;
                if (input_update_saved_control(state,target,usage,pressed) != 0)
                    changed[target] = 1;
            }
        }
        ++index;
        count = OBSERVED_BUTTON_RULE_COUNT;
    } while ((unsigned char)index < count);
    if (changed[1] != 0 && input_needs_service(INPUT1_STATE) != 0)
        fixed_input_service(1,0xffffffffU);
    if (changed[2] != 0 && input_needs_service(INPUT2_STATE) != 0)
        fixed_input_service(2,0xffffffffU);
}

/* Native entry: 0x4202ac40. */
/* Original function-byte SHA-256:
 * 3f58f2c205fa0a496a3a4d76f2c8d22f51b7375fbcab11c7b57771bd970b0f4c. */
/* With a non-NULL input timer handle and mutex, take the mutex indefinitely,
 * ignoring take status. Fence/read armed; if zero, fence/store1 BEFORE calling
 * the timer rearm routine. Give a freshly reloaded mutex via queue send(NULL,
 * wait0,back), ignoring its status too. No retry or armed rollback if rearm
 * fails. This wrapper does not create a timer or read the clock itself. */
void input_ensure_timer_armed(void)
{
    if (INPUT_TIMER_HANDLE == NULL)
        return;
    RtosQueue *mutex = INPUT_TIMER_MUTEX;
    if (mutex == 0)
        return;
    (void)xQueueSemaphoreTake(mutex,0xffffffffU);
    memw();
    if (INPUT_TIMER_ARMED == 0) {
        memw();
        INPUT_TIMER_ARMED = 1;
        input_timer_rearm();
    }
    (void)xQueueGenericSend(INPUT_TIMER_MUTEX,0,0,0);
}

/* Native entry: 0x42033bb4. */
/* Original function-byte SHA-256:
 * 0dcd6f176c9e0dbd32fc3135a1e281e5b41cdd2d781d7c3b118a0f2980ed21ff. */
/* Store the optional no-argument reader returning LOW32 timestamp bits.
 * Input wrappers can use it instead of a fresh clock read. NULL disables the
 * override. No lock, MEMW, callback invocation or lifetime pin. */
void input_set_receive_timestamp_reader(ReceiveTimestampReader reader)
{
    INPUT_RECEIVE_TIMESTAMP_READER = reader;
}


/* Native entry: 0x42033bc0. */
/* Original function-byte SHA-256:
 * d145ab78ea0fccc187423ab868f217d6ca954bcd05465600f55d7159000e82a4. */
/* Flush pending input first. MEMW/read the rearm-coalescing BYTE; if nonzero,
 * MEMW/clear it BEFORE calling the separately reviewed ensure-timer-armed
 * wrapper. Clear is not rolled back on failure. This RX idle hook can also run
 * after an empty-ring notification timeout; it is not a dedicated timer or
 * exclusively a nonempty-to-empty transition. No local lock or result. */
void control_rx_idle_service(void)
{
    input_flush_pending();
    memw();
    if (INPUT_REARM_COALESCED != 0) {
        memw();
        INPUT_REARM_COALESCED = 0;
        input_ensure_timer_armed();
    }
}


/* Native entry: 0x4202b100. */
/* Original function-byte SHA-256:
 * edc71a12681c696c72f7adfc9cdaea29ff4128605b1908bab94d92deff75d65e. */
/* Snapshot report mutex. If present, query its holder BEFORE obtaining the
 * current task, then call the pending-publication boundary with holder==current;
 * absent mutex passes0. A nonzero publication result returns. On zero, reload
 * mutex and take it indefinitely if non-NULL (result ignored), retry publication
 * with1, then reload/release mutex if non-NULL, ignoring both results. A NULL
 * mutex does not prevent that retry with1. Even a current owner can reach the
 * second take if publication returns0; no recursive-lock avoidance is added.
 * No own lock, timer, bounded wait or result; publication internals remain a
 * separate native review. The flag authorizes reading report state there. */
void input_flush_pending(void)
{
    int may_read_report_state = 0;
    RtosQueue *mutex = REWRITE_MUTEX;
    if (mutex != NULL) {
        RtosTask *holder = xQueueGetMutexHolder(mutex);
        RtosTask *current = xTaskGetCurrentTaskHandle();
        may_read_report_state = holder == current;
    }
    if (input_publish_pending(may_read_report_state) != 0)
        return;
    mutex = REWRITE_MUTEX;
    if (mutex != NULL)
        xQueueSemaphoreTake(mutex,0xffffffffU);
    input_publish_pending(1);
    mutex = REWRITE_MUTEX;
    if (mutex != NULL)
        xQueueGenericSend(mutex,NULL,0,0);
}

/* Native entry: 0x4202caa8. */
/* Original function-byte SHA-256:
 * e6d7614b47c7cab6e00e99e673653913c0873e99c11c10c4806b63c9fa909436. */
/* Clear last-buttons HALFWORD for the fixed primary binding, then last-buttons
 * HALFWORD for all six dynamic bindings, regardless of live count.
 * Clear saved keys/consumers in fixed keyboard state first; only if that helper
 * reports a change, the keyboard binding is currently enabled and its state
 * needs service, call fixed service(1,UINT_MAX). Repeat for consumer state with
 * fixed service(2,UINT_MAX). Helper results short-circuit fresh flag reads.
 * Service may itself reset output or refuse emission. No primary service,
 * dynamic-state clear, local lock, MEMW or submission status is supplied. */
void input_clear_last_controls(void)
{
    FIXED_INPUTS[0].last_buttons = 0;
    for (unsigned int index = 0; index < 6; ++index)
        ((volatile ReportLayoutBinding *)REPORT_BINDINGS)[index].last_buttons = 0;
    if (input_clear_saved_controls(INPUT1_STATE) != 0 &&
        INPUT1_ENABLED != 0 && input_needs_service(INPUT1_STATE) != 0)
        fixed_input_service(1,0xffffffffU);
    if (input_clear_saved_controls(INPUT2_STATE) != 0 &&
        INPUT2_ENABLED != 0 && input_needs_service(INPUT2_STATE) != 0)
        fixed_input_service(2,0xffffffffU);
}

/* Native entry: 0x420363a0. */
/* Original function-byte SHA-256:
 * 30955bddbe7c5a44a0f0568f9af5b5d890d84dda79710856b0f8f49a41210f4d. */
/*
 * RESET external session under an optional configuration-mutex take(UINT_MAX
 * ticks,ignored result). Fence twice/read input sequence, fence/read ack; if
 * unequal increment HALFWORD epoch, then acknowledge sampled sequence. Clear
 * capture subscriptions, full 0xe08 rewrite storage and 258-byte button mapping;
 * notify motion-configuration change, clear last controls, MEMW/clear mouse,
 * keyboard and consumer capture-valid BYTEs. Clear 16/32-byte motion history
 * buffers and notify configuration change AGAIN. No persistent NVS erase.
 *
 * Enabled mouse: reset runtime, send render state 0, fence/clear idle anchor
 * LOW/HIGH, sample time, fence/store extension LOW, read changed BYTE, then
 * fence/store HIGH. Start post-service change=1; only a zero changed BYTE calls
 * the activity helper with freshly fenced extension LOW/HIGH samples.
 * Enabled keyboard then consumer: reset runtime; if service needed, fence/test
 * pending report reset and perform it if set. Emit that fixed input only when
 * its interface>=0, fenced last-input-valid!=0 and fenced USB-suspended==0;
 * epoch is UINT_MAX. No configured-bus test is added to these caller branches.
 *
 * Reset every dynamic binding's input runtime and observed-buttons-valid BYTE,
 * rereading binding count AFTER each reset but BEFORE clearing that byte. Then
 * reset playback and release freshly sampled mutex. MEMW/test render bit0;
 * if set, sample time and queue four zero axes/flags 4/time LOW through pending
 * motion router. Finally service the saved primary change value. No extra
 * timestamp rewrites from the old decompiler are real. No local bounds checks,
 * cleanup rollback, take/send status handling or timing/atomicity guarantee.
 */
void session_reset(void)
{
    RtosQueue *mutex = REWRITE_MUTEX;
    if (mutex != 0) (void)xQueueSemaphoreTake(mutex,0xffffffffU);
    memw();
    memw(); unsigned int sequence = INPUT_CHANGE_SEQUENCE;
    memw(); unsigned int acknowledged = INPUT_CHANGE_ACKNOWLEDGED;
    if (acknowledged != sequence)
        INPUT_CHANGE_EPOCH = (unsigned short)(INPUT_CHANGE_EPOCH + 1U);
    INPUT_CHANGE_ACKNOWLEDGED = sequence;
    capture_clear_subscriptions();
    memset(IMPERFECT_REWRITE_STORAGE,0,0xe08);
    memset(SESSION_BUTTON_MAP,0,258);
    motion_configuration_changed();
    input_clear_last_controls();
    memw(); REPORT_CAPTURE_BUTTONS_VALID = 0;
    memw(); REPORT_KEYBOARD_CAPTURE.valid = 0;
    memw(); REPORT_CONSUMER_CAPTURE.valid = 0;
    memset((unsigned char *)MOTION_HISTORY.history16,0,16);
    memset((unsigned char *)MOTION_HISTORY.history32,0,32);
    motion_configuration_changed();
    int primary_changed = 0;
    if (FIXED_INPUTS[0].enabled != 0) {
        input_reset_runtime((InputStateView *)&FIXED_INPUTS[0].state);
        motion_send_render_state(0);
        memw(); FIXED_INPUTS[0].idle_motion_anchor.low = 0;
        memw(); FIXED_INPUTS[0].idle_motion_anchor.high = 0;
        unsigned long long now_us = esp_timer_get_time();
        memw(); FIXED_INPUTS[0].extension_event_time.low = (unsigned int)now_us;
        unsigned char changed = FIXED_INPUTS[0].state.changed;
        memw(); FIXED_INPUTS[0].extension_event_time.high = (unsigned int)(now_us >> 32);
        primary_changed = 1;
        if (changed == 0) {
            memw(); unsigned int low = FIXED_INPUTS[0].extension_event_time.low;
            memw(); unsigned int high = FIXED_INPUTS[0].extension_event_time.high;
            primary_changed = primary_input_refresh_activity_time((unsigned long long)low | (unsigned long long)high << 32);
        }
    }
    for (unsigned int index = 1; index < 3; ++index) {
        volatile FixedInputBinding *binding = &FIXED_INPUTS[index];
        if (binding->enabled == 0) continue;
        InputStateView *state = (InputStateView *)&binding->state;
        input_reset_runtime(state);
        if (input_needs_service(state) == 0) continue;
        memw();
        if (OUTPUT_RESET_PENDING != 0) input_reset_output_reports();
        if (binding->interface < 0) continue;
        memw();
        if (binding->last_input_valid == 0) continue;
        memw();
        if (USB_SUSPENDED == 0) fixed_input_emit(index,0xffffffffU);
    }
    int count = REPORT_BINDING_COUNT;
    if (count > 0) {
        int index = 0;
        do {
            volatile ReportLayoutBinding *binding = &REPORT_BINDINGS[index];
            input_reset_runtime((InputStateView *)&binding->state);
            count = REPORT_BINDING_COUNT;
            binding->observed_buttons_valid = 0;
            ++index;
        } while (index < count);
    }
    playback_reset_runtime();
    mutex = REWRITE_MUTEX;
    if (mutex != 0) (void)xQueueGenericSend(mutex,0,0,0);
    memw();
    if ((MOTION_RENDER_STATE & 1U) != 0) {
        unsigned long long now_us = esp_timer_get_time();
        input_queue_motion(0,0,0,0,4,(unsigned int)now_us);
    }
    input_service_after_change(primary_changed);
}
