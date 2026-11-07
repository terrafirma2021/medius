/* Device report/input binding refresh and USB interface initialization. */
#include "../include/types.h"

/* Binding-refresh reconstruction utilities: native inlined offset operations,
 * not additional firmware entries. */
static __attribute__((always_inline)) inline void binding_read_axes(
    unsigned int words[12], const volatile HidReportLayout *layout)
{
    for (unsigned int axis = 0; axis < 4; ++axis) {
        words[axis * 3] = layout->axes[axis].packed;
        words[axis * 3 + 1] = layout->axes[axis].minimum;
        words[axis * 3 + 2] = layout->axes[axis].maximum;
    }
}

/* Native entry: 0x4202cb20. */
/* Original function-byte SHA-256:
 * 12c20607c5123748118fde84a8fba2cd32f72f5d2deaa970471f0c4837743130. */
/* Rebuild primary/auxiliary/keyboard/consumer input bindings from live layouts.
 * reset is a full WORD, not a boolean: nonzero initializes state/scales, while
 * the primary reuse test separately uses LOW8(reset ^ 1). preserve_pending==0
 * discards each interface's queued work under the credit lock; pass the raw
 * reset word as the discard helper's submitted-state selector.
 *
 * Refresh HID layouts, choose a primary among six, snapshot old primary scales
 * or defaults, clear binding identities/validity, then walk the live interface
 * count. Preserve a compatible primary layout when allowed; otherwise rebind
 * or initialize it. Compare the twelve axis WORDs, advancing a nonzero BYTE
 * render token and copying the snapshot when changed (always on cold init).
 * Reset report history only on the native reset path, derive histogram base
 * from raw bInterval, and publish first-frequent once after scanning bins.
 * Retained unchanged axes have a distinct identity/history read order.
 *
 * Add up to six other eligible primary layouts, restoring the scale snapshot;
 * choose the first keyboard and consumer layouts outside the primary branch.
 * Halfword resets are kept as halfwords. Reset inactive fixed states, retaining
 * repeated activity predicates and fresh render-state reads; advance the input
 * change epoch only when their native change accumulator is nonzero.
 * Broadcast secondary-enable bits, refresh poll timing/priorities, and rebuild
 * all six report buffers. Preserve live count/length reads, borrowed pointers,
 * conditional payload clears and callback-clear/interface-ID publication order.
 * No aggregate lock, allocation, bounds repair, timer start, rollback or delivery
 * guarantee is supplied. Unused fields and unselected buffers remain untouched.
 */
void clone_refresh_report_bindings(unsigned int reset, int preserve_pending)
{
    motion_configuration_changed();
    volatile FixedInputBinding *primary = &FIXED_INPUTS[0];
    unsigned int old_length = primary->expected_length;
    unsigned int old_report_id = 0;
    unsigned int old_active = primary->enabled;
    if (old_active != 0) {
        if (primary->interface < 0) {
            old_active = 0;
        } else {
            const volatile HidReportLayout *old_layout = primary->state.hid_layout;
            if (old_layout == NULL)
                old_active = 0;
            else
                old_report_id = old_layout->report_id;
        }
    }
    hid_refresh_reports();
    ReportInterfaceSelection selection;
    report_choose_primary_interface(HID_REPORT_LAYOUTS,
        REPORT_PRIMARY_PREFERENCES, USB_INTERFACE_COUNT, &selection);
    int selected_primary = selection.primary;
    InputScaleSnapshot scales;
    if (reset == 0)
        input_copy_scales((const InputStateView *)&primary->state, &scales);
    else
        input_scale_snapshot_defaults(&scales);

    FIXED_INPUTS[1].enabled = 0;
    memw();
    REPORT_CAPTURE_BUTTONS_VALID = 0;
    FIXED_INPUTS[2].interface = -1;
    FIXED_INPUTS[2].enabled = 0;
    primary->interface = -1;
    FIXED_INPUTS[1].interface = -1;
    for (unsigned int index = 0; index < 6; ++index)
        ((volatile ReportLayoutBinding *)REPORT_BINDINGS)[index].interface = -1;
    REPORT_BINDING_COUNT = 0;
    memw();
    REPORT_KEYBOARD_CAPTURE.valid = 0;
    memw();
    REPORT_CONSUMER_CAPTURE.valid = 0;
    REPORT_TRIGGER_BUTTONS_VALID = 0;
    int initial_count = USB_INTERFACE_COUNT;
    primary->enabled = 0;
    REPORT_KEYBOARD_TRIGGERS.valid = 0;
    REPORT_CONSUMER_TRIGGERS.valid = 0;

    if (initial_count > 0) {
        int interface = 0;
        do {
            volatile HidReportLayout *layout = (volatile void *)
                ((unsigned int)(uintptr_t)HID_REPORT_LAYOUTS +
                 (unsigned int)interface * 304U);
            if (preserve_pending == 0) {
                (void)xPortEnterCriticalTimeout(&CREDIT_LOCK, -1);
                report_discard_interface_pending(interface, (int)reset);
                vPortExitCritical(&CREDIT_LOCK);
            }

            if (interface == selected_primary) {
                bool reuse_allowed = ((reset ^ 1U) & 255U) != 0 && old_active != 0;
                bool retained = false;
                bool cold_initialize = !reuse_allowed && reset != 0;
                if (reuse_allowed) {
                    if (layout->expected_length == old_length && layout->report_id == old_report_id) {
                        primary->interface = selected_primary;
                        primary->state.hid_layout = (HidReportLayout *)layout;
                        input_update_axis_limits((InputStateView *)&primary->state);
                        retained = true;
                    } else {
                        primary->interface = selected_primary;
                        input_bind_layout((InputStateView *)&primary->state,
                            (HidReportLayout *)layout);
                    }
                } else {
                    primary->interface = interface;
                    if (reset != 0) {
                        input_initialize((InputStateView *)&primary->state,
                            (HidReportLayout *)layout);
                        input_bind_event_storage((InputStateView *)&primary->state,
                            &FIXED_INPUT_EVENT_STORAGE[0]);
                    } else {
                        input_bind_layout((InputStateView *)&primary->state,
                            (HidReportLayout *)layout);
                    }
                }
                primary->expected_length = layout->expected_length;
                primary->state.mapping_table = INPUT_GLOBAL_MAP;
                motion_configuration_changed();
                unsigned int axes[12];
                binding_read_axes(axes, layout);
                bool axes_changed = cold_initialize ||
                    memcmp(REPORT_PRIMARY_AXIS_SNAPSHOT, axes, 48) != 0;
                if (axes_changed) {
                    unsigned char next = MOTION_RENDER_TOKEN + 1;
                    MOTION_RENDER_TOKEN = next == 0 ? 1 : next;
                    motion_configuration_changed();
                    memcpy(REPORT_PRIMARY_AXIS_SNAPSHOT, axes, 48);
                }
                if (!retained) {
                    motion_configuration_changed();
                    memset((void *)primary->last_input, 0, 64);
                    unsigned char report_id = layout->report_id;
                    if (report_id != 0)
                        primary->last_input[0] = report_id;
                    memw();
                    primary->last_input_valid = 1;
                    memw();
                    primary->updated = 0;
                    memcpy((void *)primary->previous_output, (const void *)primary->last_input, 64);
                    memw();
                    primary->motion_seen = 0;
                    memw();
                    PROFILE_NORMALIZATION_PENDING = 0;
                    unsigned char output_mask = FIXED_OUTPUT_MASK;
                    memw();
                    unsigned int epoch = REPORT_NORMALIZATION_EPOCH;
                    primary->output_valid = 0;
                    FIXED_OUTPUT_MASK = output_mask & 0xfeU;
                    memw();
                    REPORT_NORMALIZATION_EPOCH = epoch + 1;
                }

                memw();
                unsigned short identity_high = INPUT_REQUESTED_IDENTITY[1];
                memw();
                INPUT_ACTIVE_IDENTITY[1] = identity_high;
                memw();
                unsigned short identity_low = INPUT_REQUESTED_IDENTITY[0];
                unsigned int first_frequent;
                bool keep_history = retained && !axes_changed;
                if (keep_history)
                    first_frequent = REPORT_INTERVAL_HISTORY.first_frequent;
                memw();
                INPUT_ACTIVE_IDENTITY[0] = identity_low;
                if (keep_history || reset == 0) {
                    if (!keep_history)
                        first_frequent = REPORT_INTERVAL_HISTORY.first_frequent;
                    unsigned int endpoint = USB_INTERFACE_ENDPOINTS[interface];
                    memw();
                    REPORT_INTERVAL_SEEN = 0;
                    unsigned int interval = clone_endpoint_interval_byte(endpoint);
                    unsigned int base = 4;
                    if (interval > 1) {
                        unsigned int scale = 1;
                        do { scale = (scale * 2U) & 65535U; }
                        while (scale * 2U <= interval);
                        base = scale * 1000U <= 31999U ? (scale << 2) & 65535U : 127U;
                    }
                    REPORT_INTERVAL_HISTORY.base_bucket = base;
                    if (first_frequent < base) {
                        unsigned int candidate = base;
                        while (candidate <= 127 && REPORT_INTERVAL_HISTORY.histogram[candidate] < 8)
                            ++candidate;
                        REPORT_INTERVAL_HISTORY.first_frequent = candidate;
                    }
                } else {
                    memw();
                    PROFILE_BASELINE_PENDING = 0;
                    memset((void *)&REPORT_INTERVAL_HISTORY, 0, 0x314);
                    memw();
                    REPORT_ACTIVE_THRESHOLD = 0;
                    memw();
                    REPORT_PENDING_THRESHOLD = 0;
                    memw();
                    REPORT_PERIOD_DEBOUNCE = 0;
                    REPORT_INTERVAL_HISTORY.first_frequent = 128;
                    unsigned int endpoint = USB_INTERFACE_ENDPOINTS[interface];
                    memw();
                    REPORT_INTERVAL_SEEN = 0;
                    unsigned int interval = clone_endpoint_interval_byte(endpoint);
                    unsigned int base = 4;
                    if (interval > 1) {
                        unsigned int scale = 1;
                        do { scale = (scale * 2U) & 65535U; }
                        while (scale * 2U <= interval);
                        base = scale * 1000U <= 31999U ? (scale << 2) & 65535U : 127U;
                    }
                    REPORT_INTERVAL_HISTORY.base_bucket = base;
                }
                primary->suppression_pair = 0;
                primary->enabled = 1;
            } else {
                if (layout->enabled != 0 && layout->axes[0].enabled != 0) {
                    int count = REPORT_BINDING_COUNT;
                    if (count < 6) {
                        volatile ReportLayoutBinding *binding = (volatile void *)
                            ((unsigned int)(uintptr_t)REPORT_BINDINGS + (unsigned int)count * 904U);
                        unsigned short length = layout->expected_length;
                        REPORT_BINDING_COUNT = count + 1;
                        binding->expected_length = length;
                        binding->interface = interface;
                        input_initialize((InputStateView *)&binding->state,
                            (HidReportLayout *)layout);
                        binding->state.mapping_table = INPUT_GLOBAL_MAP;
                        binding->state.normalization_flags = 65535;
                        input_restore_scales((InputStateView *)&binding->state, &scales);
                        binding->observed_buttons_valid = 0;
                        binding->observed_buttons = 0;
                        memset((void *)binding->previous_output, 0, 64);
                        unsigned char report_id = layout->report_id;
                        if (report_id != 0)
                            binding->previous_output[0] = report_id;
                        binding->last_input_valid = 0;
                        binding->suppression_pair = 0;
                    }
                }
                if (layout->keyboard.enabled != 0 && FIXED_INPUTS[1].interface < 0) {
                    volatile FixedInputBinding *binding = &FIXED_INPUTS[1];
                    unsigned short length = layout->keyboard.expected_length;
                    binding->interface = interface;
                    binding->expected_length = length;
                    if (reset == 0) {
                        input_bind_layout((InputStateView *)&binding->state,
                            (HidReportLayout *)layout);
                    } else {
                        input_initialize((InputStateView *)&binding->state,
                            (HidReportLayout *)layout);
                        input_bind_event_storage((InputStateView *)&binding->state,
                            &FIXED_INPUT_EVENT_STORAGE[1]);
                    }
                    memset((void *)binding->last_input, 0, 64);
                    unsigned char report_id = layout->keyboard.report_id;
                    if (report_id != 0)
                        binding->last_input[0] = report_id;
                    memw();
                    binding->last_input_valid = 1;
                    memw();
                    binding->updated = 0;
                    memcpy((void *)binding->previous_output, (const void *)binding->last_input, 64);
                    unsigned char mask = FIXED_OUTPUT_MASK;
                    FIXED_OUTPUT_MASK = mask & 0xfdU;
                    binding->output_valid = 0;
                    binding->suppression_pair = 0;
                    binding->enabled = 1;
                }
                if (FIXED_INPUTS[2].interface < 0 && layout->consumer.enabled != 0) {
                    volatile FixedInputBinding *binding = &FIXED_INPUTS[2];
                    unsigned short length = layout->consumer.expected_length;
                    binding->interface = interface;
                    binding->expected_length = length;
                    if (reset == 0) {
                        input_bind_layout((InputStateView *)&binding->state,
                            (HidReportLayout *)layout);
                    } else {
                        input_initialize((InputStateView *)&binding->state,
                            (HidReportLayout *)layout);
                        input_bind_event_storage((InputStateView *)&binding->state,
                            &FIXED_INPUT_EVENT_STORAGE[2]);
                    }
                    memset((void *)binding->last_input, 0, 64);
                    unsigned char report_id = layout->consumer.report_id;
                    if (report_id != 0)
                        binding->last_input[0] = report_id;
                    memw();
                    binding->last_input_valid = 1;
                    memw();
                    binding->updated = 0;
                    memcpy((void *)binding->previous_output, (const void *)binding->last_input, 64);
                    unsigned char mask = FIXED_OUTPUT_MASK;
                    FIXED_OUTPUT_MASK = mask & 0xfbU;
                    binding->output_valid = 0;
                    binding->suppression_pair = 0;
                    binding->enabled = 1;
                }
            }
            ++interface;
        } while (interface < USB_INTERFACE_COUNT);
    }

    unsigned int changed = 0;
    for (unsigned int slot = 0; slot < 3; ++slot) {
        volatile FixedInputBinding *binding = &FIXED_INPUTS[slot];
        if (binding->interface >= 0)
            continue;
        InputStateView *state = (InputStateView *)&binding->state;
        if (reset == 0) {
            if (input_has_transforms(state) != 0 ||
                input_has_forced_controls(state) != 0 ||
                input_has_button_overrides(state) != 0 ||
                input_has_primary_activity(state) != 0 ||
                input_has_secondary_activity(state) != 0) {
                changed = 1;
            } else if (slot == 0) {
                memw();
                unsigned char render = MOTION_RENDER_STATE;
                if ((render & 1U) != 0) {
                    memw();
                    changed = (changed | ((MOTION_RENDER_STATE >> 3) & 1U)) & 255U;
                } else {
                    unsigned int active = input_has_primary_activity(
                        (const InputStateView *)&primary->state);
                    if (active != 0)
                        changed = active;
                    else
                        changed = (changed | input_has_secondary_activity(
                            (const InputStateView *)&primary->state)) & 255U;
                }
            }
        }
        input_reset_runtime(state);
    }
    if (changed != 0)
        INPUT_CHANGE_EPOCH = INPUT_CHANGE_EPOCH + 1;
    if (primary->interface < 0) {
        memw();
        primary->idle_motion_anchor.low = 0;
        memw();
        primary->idle_motion_anchor.high = 0;
    }
    input_clear_last_controls();
    unsigned int consumer_enabled = FIXED_INPUTS[2].enabled;
    unsigned int keyboard_enabled = FIXED_INPUTS[1].enabled;
    unsigned char secondary_mask = (consumer_enabled * 2U) | keyboard_enabled;
    int binding_count = REPORT_BINDING_COUNT;
    primary->state.mapping_conditions = secondary_mask;
    if (binding_count > 0) {
        /* Preserve the native modular stride/inverse count calculation. */
        unsigned int iterations = ((((unsigned int)binding_count * 904U - 904U) >> 3) *
            0x0fdbc091U) & 0x1fffffffU;
        ++iterations;
        unsigned int address = (unsigned int)(uintptr_t)REPORT_BINDINGS;
        do {
            volatile ReportLayoutBinding *binding = (volatile void *)address;
            binding->state.mapping_conditions = secondary_mask;
            address += 904U;
        } while (--iterations != 0);
    }
    report_refresh_poll_timing(selected_primary);
    input_refresh_endpoint_priorities();
    for (unsigned int interface = 0; interface < 6; ++interface) {
        UsbdInterface *buffer_state = &HID_INTERFACES[interface];
        unsigned char interface_id = 255;
        if ((int)interface < USB_INTERFACE_COUNT) {
            unsigned int length = USB_INTERFACE_REPORT_LENGTHS[interface];
            unsigned char *storage = NULL;
            bool initialize = true;
            if (length != 0)
                storage = REPORT_BUFFER_STORAGE + interface * 2048U;
            else if (REPORT_BUFFER_ENABLED[interface] == 0)
                initialize = false;
            usbd_hid_init_intf(0, buffer_state,
                initialize ? storage : NULL, initialize ? length : 0);
            if (initialize)
                interface_id = REPORT_CAPTURE_INTERFACE_IDS[interface];
        } else {
            usbd_hid_init_intf(0, buffer_state, NULL, 0);
        }
        volatile UsbdInterface *state = buffer_state;
        state->class_interface_handler = NULL;
        state->intf_num = interface_id;
        state->vendor_handler = NULL;
    }
}

/* Native entry: 0x42033c94. */
/* Original function-byte SHA-256:
 * bcf03b9da6116078ebc9317429247a3249ea1f57a92a727cd839f1976f572222. */
/*
 * MEMW then return the full report-normalization epoch WORD once. Binding
 * publication increments it when normalization state changes; app_main uses
 * changes to refresh its local generation state. No increment, clear, lock,
 * wrap handling or assertion that associated bindings form an atomic snapshot.
 */
unsigned int report_get_normalization_epoch(void)
{
    memw();
    return REPORT_NORMALIZATION_EPOCH;
}
