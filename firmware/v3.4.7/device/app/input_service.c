/* Device fixed-input emission and primary change service. */

#include "../include/types.h"

/* Native entry: 0x4202ca54. */
/* Original function-byte SHA-256:
 * fb3c5a1c08319c1056362a7ca3cbcbf9fc191a1116799d437e9c57fe0b403eec. */
/* Service an initialized fixed binding only while USB is not suspended. First
 * honor the fenced global output-reset flag, even for an unusable binding.
 * Then test signed interface>=0, fenced input-valid and fenced USB-suspend state in
 * order. Forward the full32 index/epoch to emission. Index arithmetic wraps32
 * at1000-byte stride; it is not restricted to the three normal fixed slots.
 * Caller supplies serialization; this wrapper does not lock or validate. */
void fixed_input_service(unsigned int index,unsigned int epoch)
{
    memw();
    if (OUTPUT_RESET_PENDING != 0)
        input_reset_output_reports();
    const volatile FixedInputBinding *binding = (const volatile void *)
        ((unsigned int)(uintptr_t)FIXED_INPUTS+index*1000U);
    if (binding->interface < 0)
        return;
    memw();
    if (binding->last_input_valid == 0)
        return;
    memw();
    if (USB_SUSPENDED == 0)
        fixed_input_emit(index,epoch);
}

/* Native entry: 0x4202dd98. */
/* Original function-byte SHA-256:
 * d1012a5d0029978a66c8dd76c0404a2f6117930b6bf0198dd551d916b446eef0. */
/* After a nonzero input change, rate-limit bus0 wake attempts to 50 ms using
 * signed wrapped age; retain separate clock samples for wake and processing.
 * Store wake time before fenced request1. A ZERO wake return increments the
 * resume counter and calls resume handling; nonzero clears request.
 *
 * Compare time since primary last_processed against a rounded period minus
 * 500 us (minimum 500, default 900). A zero configured period can instead select
 * 500 via motion profile/render bit1, or use a freshly sampled learned period.
 * Rounding additions wrap32. Once due, arm input work BEFORE taking the rewrite
 * mutex, honor reset, then emit primary only when fast-enabled, interface and
 * input valid, binding enabled, USB not suspended and bus0 configured. Pass a
 * fresh emission time, mode 0 and epoch UINT_MAX. Take and release each use one saved mutex sample; release reloads it.
 * No local index validation, timeout handling or return status. */
void input_service_after_change(int changed)
{
    if (changed == 0)
        return;
    memw();
    unsigned int suspended = USB_SUSPENDED;
    if (suspended != 0) {
        memw();
        if (REPORT_WAKE_REQUEST == 0) {
            unsigned long long now = (unsigned long long)esp_timer_get_time();
            unsigned int low = INPUT_CHANGE_WAKE_TIME.low;
            unsigned int high = INPUT_CHANGE_WAKE_TIME.high;
            unsigned long long previous = ((unsigned long long)high << 32) | low;
            if (previous == 0 || (long long)(now-previous) >= 50000) {
                INPUT_CHANGE_WAKE_TIME.low = (unsigned int)now;
                INPUT_CHANGE_WAKE_TIME.high = (unsigned int)(now >> 32);
                memw();
                REPORT_WAKE_REQUEST = 1;
                if (usbd_send_remote_wakeup(0) != 0) {
                    memw();
                    REPORT_WAKE_REQUEST = 0;
                } else {
                    memw();
                    unsigned int resumes = REPORT_WAKE_RESUMES;
                    memw();
                    REPORT_WAKE_RESUMES = resumes+1U;
                    usbd_event_resume_handler(0);
                }
            }
        }
    }
    unsigned long long now = (unsigned long long)esp_timer_get_time();
    memw();
    unsigned int low = FIXED_INPUTS[0].last_processed.low;
    memw();
    unsigned int high = FIXED_INPUTS[0].last_processed.high;
    memw();
    unsigned int period = EMISSION_OPTIONS.period_us;
    unsigned long long threshold;
    if (period == 0) {
        memw();
        unsigned int profile = MOTION_OPTIONS.profile;
        if (profile != 0) {
            memw();
            if ((MOTION_RENDER_STATE & 2U) != 0) {
                threshold = 500;
                goto compare_age;
            }
        }
        memw();
        if (REPORT_LEARNED_PERIOD == 0) {
            threshold = 900;
            goto compare_age;
        }
        memw();
        period = REPORT_LEARNED_PERIOD;
    }
    {
        unsigned int rounded = period+500U;
        threshold = rounded < 1000 ? 500 : (unsigned long long)(rounded/1000U)*1000U-500U;
    }
compare_age:
    if ((long long)(now-(((unsigned long long)high << 32) | low)) < (long long)threshold)
        return;
    input_ensure_timer_armed();
    RtosQueue *mutex = REWRITE_MUTEX;
    if (mutex != NULL)
        (void)xQueueSemaphoreTake(mutex,0xffffffffU);
    memw();
    if (OUTPUT_RESET_PENDING != 0)
        input_reset_output_reports();
    memw();
    if (REPORT_FAST_ENABLED != 0 && FIXED_INPUTS[0].interface >= 0 &&
        FIXED_INPUTS[0].enabled != 0) {
        memw();
        if (FIXED_INPUTS[0].last_input_valid != 0) {
            memw();
            if (USB_SUSPENDED == 0 && usb_device_is_configured(0)) {
                unsigned long long emit_time = (unsigned long long)esp_timer_get_time();
                primary_input_emit(emit_time,0,0xffffffffU);
            }
        }
    }
    mutex = REWRITE_MUTEX;
    if (mutex != NULL)
        (void)xQueueGenericSend(mutex,NULL,0,0);
}

/* Native entry: 0x4202c8d8. */
/* Original function-byte SHA-256:
 * 9a61969cc52234a57c04bd587a400b07c093076e2d05f1b841566d8556997e71. */
/* Rewrite one fixed input and emit its changed output. Native addressing uses
 * LOW16(index) for state, cached input and previous-output bytes, but FULL32
 * wrapped1000-byte addressing for expected length, validity, layout, interface
 * and last_processed. These differing views are intentional here.
 *
 * Rewrite from cached input, cache/clear full-index output-valid, then publish
 * events. Apply output rules using freshly read interface/length. Drop marks
 * the low-index state dirty only when events were published. Otherwise semantic
 * update OR (cached validity AND bytewise difference) emits with derive-kind1,
 * pointer-change bit7, optional published-state metadata and supplied epoch.
 * Copy selected output even if submission rejects it. An unchanged published
 * state is marked dirty instead. Every path stamps a fresh clock LOW then HIGH
 * with separate fences. Caller supplies valid descriptors/buffers and locking;
 * no index/length cap, capture event, timer arm or submission-status handling. */
void fixed_input_emit(unsigned int index,unsigned int epoch)
{
    volatile FixedInputBinding *full_index_binding = (volatile void *)
        ((unsigned int)(uintptr_t)FIXED_INPUTS+index*1000U);
    volatile FixedInputBinding *low_index_binding = FIXED_INPUTS+(index & 65535U);
    InputStateView *state = (InputStateView *)&low_index_binding->state;
    unsigned char rewritten[64],scratch[64];
    input_rewrite_report_defaults(state,(const unsigned char *)low_index_binding->last_input,
        full_index_binding->expected_length,rewritten);
    unsigned int previous_valid = full_index_binding->output_valid;
    full_index_binding->output_valid = 0;
    (void)input_publish_events(state);
    unsigned int published = input_events_were_published(state);
    unsigned int length = full_index_binding->expected_length;
    unsigned int interface = (unsigned int)full_index_binding->interface;
    const unsigned char *selected;
    unsigned short selected_length;
    unsigned int drop = report_apply_output_rules(interface,rewritten,length,
        scratch,&selected,&selected_length);
    InputStateView *published_state = published != 0 ? state : 0;
    if (drop != 1) {
        const HidReportLayout *layout = full_index_binding->state.hid_layout;
        unsigned char *previous = (unsigned char *)low_index_binding->previous_output;
        unsigned int size = selected_length;
        if (hid_report_needs_update(layout,selected,previous,size) != 0 ||
            (previous_valid != 0 && memcmp(selected,previous,size) != 0)) {
            (void)report_process_interface((unsigned int)full_index_binding->interface,selected,size,0,1,
                (unsigned int)(selected != rewritten) << 7,0,
                (unsigned int)(uintptr_t)published_state,0,0,&REPORT_PROCESS_STATUS,0,epoch);
            memcpy(previous,selected,size);
        } else if (published_state != 0) {
            input_mark_dirty(published_state);
        }
    } else if (published_state != 0) {
        input_mark_dirty(published_state);
    }
    unsigned long long now = (unsigned long long)esp_timer_get_time();
    memw();
    full_index_binding->last_processed.low = (unsigned int)now;
    memw();
    full_index_binding->last_processed.high = (unsigned int)(now >> 32);
}

/* Native entry: 0x4202dab0. */
/* Original function-byte SHA-256:
 * 8f30709f9202a54dfe05a90c11276b3bcd9ec3e8f48a5a0d8169524cc661db5e. */
/* Service accumulated primary input at the caller's 64-bit time. Force bypasses
 * only the initial period gate. Otherwise sample last_processed LOW/HIGH then
 * period with fences; compare signed wrapped age against rounded period-500us
 * (minimum500, default900). Profile/render mode can select500, and learned
 * period is sampled independently for presence and calculation. Adds wrap32.
 *
 * Drain pending merged motion before querying needs-service, cached validity
 * and activity. With no secondary activity, a zero movement window permits a
 * primary-activity query; otherwise cached service/validity alone decides early
 * return. Once admitted, cache expected length and a FRESH window, clear output
 * validity, copy input and clear numeric layout fields in the copy. Cache layout
 * after the copy, then sample output_count after field clearing. Clear up to two
 * selected normalization bytes in bounds, according to fresh selector sign bits.
 *
 * Refresh motion references at caller time and timed-rewrite with flags 1 for
 * a nonzero cached window, else 3. Publish events, apply output rules, then emit
 * on semantic update or cached-valid control difference. An unchanged/dropped
 * published state is marked dirty. Submission copies output and increments a
 * fenced wrapping counter regardless of its result. Admitted paths stamp the
 * supplied LOW then HIGH with separate fences; early returns do not stamp.
 * No clock call, local lock, index validation, output bounds cap or capture.
 */
void primary_input_emit(unsigned long long now_us,int force,unsigned int epoch)
{
    volatile FixedInputBinding *binding = FIXED_INPUTS;
    if (force == 0) {
        memw();
        unsigned int low = binding->last_processed.low;
        memw();
        unsigned int high = binding->last_processed.high;
        memw();
        unsigned int period = EMISSION_OPTIONS.period_us;
        unsigned long long threshold;
        if (period == 0) {
            memw();
            unsigned int profile = MOTION_OPTIONS.profile;
            if (profile != 0) {
                memw();
                if ((MOTION_RENDER_STATE & 2U) != 0) {
                    threshold = 500;
                    goto compare_age;
                }
            }
            memw();
            if (REPORT_LEARNED_PERIOD == 0) {
                threshold = 900;
                goto compare_age;
            }
            memw();
            period = REPORT_LEARNED_PERIOD;
        }
        {
            unsigned int rounded = period+500U;
            threshold = rounded < 1000 ? 500 : (unsigned long long)(rounded/1000U)*1000U-500U;
        }
compare_age:
        if ((long long)(now_us-(((unsigned long long)high << 32) | low)) < (long long)threshold)
            return;
    }
    memw();
    if (REPORT_MERGE_PENDING != 0)
        report_merge_drain_motion();
    unsigned int needs_service = input_needs_service(INPUT0_STATE);
    unsigned int previous_valid = binding->output_valid;
    if (input_has_secondary_activity(INPUT0_STATE) == 0) {
        memw();
        unsigned int window = MOVEMENT_RIDING_US;
        if (window != 0 || input_has_primary_activity(INPUT0_STATE) == 0) {
            if (needs_service == 0 && previous_valid == 0)
                return;
        }
    }
    unsigned int length = binding->expected_length;
    memw();
    unsigned int window = MOVEMENT_RIDING_US;
    binding->output_valid = 0;
    unsigned char base[64],rewritten[64],scratch[64];
    memcpy(base,(const void *)binding->last_input,length);
    const HidReportLayout *layout = binding->state.hid_layout;
    report_clear_layout_bits((const BitClearLayout *)layout,base,length);
    const volatile HidReportLayout *descriptor = layout;
    unsigned int count = descriptor->output_count;
    if (count != 0) {
        unsigned int selector = binding->state.primary_normalization_flags;
        if ((selector & 128U) == 0) {
            unsigned int byte = descriptor->byte_clamps[0].byte_offset;
            if (byte < length)
                base[byte] = 0;
        }
        if (count != 1) {
            selector = binding->state.secondary_normalization_flags;
            if ((selector & 128U) == 0) {
                unsigned int byte = descriptor->byte_clamps[1].byte_offset;
                if (byte < length)
                    base[byte] = 0;
            }
        }
    }
    input_refresh_motion_reference(INPUT0_STATE,now_us);
    input_rewrite_report_timed(INPUT0_STATE,base,length,rewritten,
        window != 0 ? 1U : 3U,now_us);
    (void)input_publish_events(INPUT0_STATE);
    unsigned int published = input_events_were_published(INPUT0_STATE);
    unsigned int interface = (unsigned int)binding->interface;
    const unsigned char *selected;
    unsigned short selected_length;
    unsigned int drop = report_apply_output_rules(interface,rewritten,length,
        scratch,&selected,&selected_length);
    InputStateView *published_state = published != 0 ? INPUT0_STATE : 0;
    if (drop != 1) {
        unsigned int size = selected_length;
        unsigned char *previous = (unsigned char *)binding->previous_output;
        layout = binding->state.hid_layout;
        if (hid_report_needs_update(layout,selected,previous,size) != 0 ||
            (previous_valid != 0 && report_controls_differ(INPUT0_STATE,selected,previous,size) != 0)) {
            (void)report_process_interface((unsigned int)binding->interface,selected,size,0,1,
                (unsigned int)(selected != rewritten) << 7,0,
                (unsigned int)(uintptr_t)published_state,0,0,&REPORT_PROCESS_STATUS,0,epoch);
            memcpy(previous,selected,size);
            memw();
            unsigned int emitted = PRIMARY_INPUT_EMISSIONS;
            memw();
            PRIMARY_INPUT_EMISSIONS = emitted+1U;
        } else if (published_state != 0) {
            input_mark_dirty(published_state);
        }
    } else if (published_state != 0) {
        input_mark_dirty(published_state);
    }
    memw();
    binding->last_processed.low = (unsigned int)now_us;
    memw();
    binding->last_processed.high = (unsigned int)(now_us >> 32);
}
