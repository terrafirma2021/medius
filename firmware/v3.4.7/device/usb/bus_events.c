/* Medius v3.4.7 device — USB lifecycle and configuration transitions. */
#include "../include/types.h"

/* USB bus-event reconstruction utilities: repeated inline paths, not extra
 * native entries. These preserve the owning callback's access/call order. */
static __attribute__((always_inline)) inline void bus_event_clear_completion_history(void)
{
    MEDIUS_REPORT_COMPLETION_PHASE_VALID = 0;
    memset(REPORT_INTERVAL_LEARNERS, 0, 72);
    memset((void *)REPORT_LAST_IN_COMPLETION, 0, 48);
    memset((void *)REPORT_LAST_IN_ACTIVITY, 0, 48);
}

static __attribute__((always_inline)) inline void bus_event_notify_motion_watchdog(
    RtosTask *observed_task)
{
    if (observed_task == NULL)
        return;
    int from_isr = xPortInIsrContext();
    RtosTask *task = MOTION_TXWD_TASK; /* fresh after context query */
    if (from_isr == 0) {
        xTaskGenericNotify(task, 0, 4, 1, NULL); /* index0, eSetBits */
    } else {
        int higher_priority_task_woken = 0;
        xTaskGenericNotifyFromISR(task, 0, 4, 1, NULL, &higher_priority_task_woken);
        if (higher_priority_task_woken != 0)
            _frxt_setup_switch();
    }
}

/* Native entry: 0x4202fec8. */
/* Original function-byte SHA-256:
 * 48f9536b414c7de3eb6bc0638414275282f1772ae9c2ee77369454d55057b630. */
/* Handle the application's USB lifecycle callback. bus is ignored, event uses
 * its low BYTE; all controller work addresses bus0. Return no value. Event1
 * resets report/OUT accounting, configuration overrides, remote wake state and
 * both nonzero-control generations, cancels a waiting EP0 reply only when its
 * sampled signal is nonnull, wakes eligible nonzero and reset-relay workers.
 * The cancellation uses FromISR APIs unconditionally; retain that native choice.
 * The reset does not choose a configuration or clear the alternate-setting table.
 *
 * Event7 searches captured configuration headers for the requested bConfigurationValue.
 * Requested value is sampled twice, count once; failed search still clears report
 * queues/merge state and records capture event3/4 using the current index. A match
 * records one sequence. Equal selected index only enqueues control0x24. A changed
 * index takes the optional report mutex, blocks fast reports, busy-polls their
 * active BYTE until zero or signed64 modular elapsed>999us, then proceeds either
 * way. Publish offset/index/length/pointer in native order, clear all256 alternates,
 * close old endpoints, close then open default-alternate endpoints of the new
 * configuration. Clear retained bindings/endpoint map, take optional rewrite
 * mutex, reparse reports, invalidate six protocol/idle WORDs and refresh bindings.
 * Register callbacks and reset/drain OUT state before enqueueing the two-BYTE
 * configuration index/zero. Only a successful enqueue publishes index then saved
 * request generation. Read the release mutex BEFORE clearing fast-report block.
 * Always log a changed index and interface slots, regardless of helper results.
 * A final clear alternate-pending flag causes another reset/drain pass. Alternate
 * scanning sets the flag on nonzero bytes; an all-zero table leaves it unchanged.
 *
 * Events3/4 capture8/9. Suspend5 sets deduct-one, refreshes motion, clears wake,
 * notifies watchdog bits4, kicks fast TX and clears completion history/merge state.
 * Resume6 clears deduct-one, marks queues dirty, notifies watchdog and clears
 * completion history; it stamps both six-slot timestamp arrays with one sampled
 * time using separate LOW/HIGH WORD writes. Events9/10 publish remote-wake1/0 and
 * enqueue control0x42; every other event is ignored. No pointer/count validation,
 * helper-status propagation, rollback, wait-success, delivery or timing guarantee.
 * Locks/take results and mutable handles retain the native sampled/fresh behavior;
 * no claim that the callback is safe in every ISR or concurrent context.
 */
void medius_usb_device_event(unsigned int bus, unsigned int event)
{
    (void)bus;
    event = (unsigned char)event;
    if (event == 1) {
        memw();
        MEDIUS_EP0_UNCONFIGURED_DESCRIPTOR_REFUSED = 0;
        unsigned int low_speed = CLONE_LOW_SPEED;
        memw();
        MEDIUS_REPORT_ENDPOINT_TRANSITION_PENDING = 0;
        if (low_speed == 1) {
            memw();
            unsigned int mask = MEDIUS_USB_DEVICE_IN_INTERRUPT_MASK;
            memw();
            MEDIUS_USB_DEVICE_IN_INTERRUPT_MASK = mask | 0x2000U;
        }
        memw();
        unsigned int generation = DEVICE_OUT_GENERATION_RW;
        memw();
        DEVICE_OUT_GENERATION_RW = generation + 1U;
        (void)xPortInIsrContext();
        xPortEnterCriticalTimeout(MEDIUS_CLONE_CONFIGURATION_LOCK, -1);
        memw();
        MEDIUS_CLONE_CONFIGURATION_OVERRIDE_COUNT = 0;
        memw();
        MEDIUS_CLONE_VIRTUAL_CONFIGURATION = 0;
        (void)xPortInIsrContext();
        vPortExitCritical(MEDIUS_CLONE_CONFIGURATION_LOCK);
        medius_out_rebase_accounting();
        capture_usb_bus_event(0, 0, 0);
        memw();
        unsigned int resets = MEDIUS_USB_RESET_COUNT;
        memw();
        MEDIUS_USB_RESET_COUNT = resets + 1U;
        memw();
        OUTPUT_RESET_PENDING = 1;
        memw();
        CLIP_RULES_RESET_PENDING = 1;
        memw();
        USB_SUSPENDED = 0;
        motion_configuration_changed();
        memw();
        REPORT_QUEUES_DIRTY = 1;
        memw();
        REPORT_WAKE_REQUEST = 0;
        memw();
        MEDIUS_USB_REMOTE_WAKE_ENABLED = 0;
        xPortEnterCriticalTimeout(&CREDIT_LOCK, -1);
        for (unsigned int interface = 0; interface != 6; ++interface) {
            report_reset_interface_runtime(interface);
            memw();
            REPORT_INTERFACE_COMPLETING[interface] = 0;
        }
        bus_event_clear_completion_history();
        input_mark_dirty(INPUT0_STATE);
        input_mark_dirty(INPUT1_STATE);
        input_mark_dirty(INPUT2_STATE);
        memset((void *)REPORT_MERGE_ACCUMULATORS, 0, 16);
        memw();
        REPORT_MERGE_PENDING = 0;
        for (unsigned int interface = 0; interface != 6; ++interface)
            medius_interface_clear_runtime_flags(interface);
        memw();
        REPORT_QUEUES_DIRTY = 1;
        for (unsigned int interface = 0; interface != 6; ++interface) {
            memw();
            REPORT_SECONDARY_STALLED[interface] = 0;
            memw();
            REPORT_SECONDARY_STALL_PENDING[interface] = 0;
        }
        for (unsigned int interface = 0; interface != 6; ++interface) {
            memw();
            REPORT_SUBMIT_BLOCKED_WRITABLE[interface] = 0;
            memw();
            REPORT_SERVICE_ACTIVE[interface] = 0;
        }
        vPortExitCritical(&CREDIT_LOCK);
        memw();
        if (EP0_REPLY_WAITING != 0) {
            RtosQueue *signal = CONTROL_ENDPOINT_REPLY_SIGNAL;
            if (signal != NULL) {
                memw();
                EP0_REPLY_WAITING = 0;
                memw();
                MEDIUS_EP0_REPLY_RESULT = 0xffffffffU;
                MEDIUS_EP0_REPLY_ASSEMBLY->state = 0;
                int higher_priority_task_woken = 0;
                MEDIUS_EP0_REPLY_ASSEMBLY->length = 0;
                xQueueGiveFromISR(signal, &higher_priority_task_woken);
                if (higher_priority_task_woken != 0)
                    _frxt_setup_switch();
            }
        }
        volatile MediusNonzeroControlState *controls = MEDIUS_NONZERO_CONTROL_STATES;
        memw();
        unsigned int request_generation = controls[0].generation;
        memw();
        controls[0].generation = (unsigned char)(request_generation + 1U);
        memw();
        controls[0].state = 0;
        memw();
        request_generation = controls[1].generation;
        memw();
        controls[1].generation = (unsigned char)(request_generation + 1U);
        memw();
        controls[1].state = 0;
        memw();
        if ((MEDIUS_NONZERO_ACTIVE_SLOT & 0x80U) == 0) {
            RtosQueue *signal = NONZERO_CONTROL_WORKER_SIGNAL;
            if (signal != NULL) {
                memw();
                MEDIUS_NONZERO_REPLY->status = 0xfe;
                int higher_priority_task_woken = 0;
                xQueueGiveFromISR(signal, &higher_priority_task_woken);
                if (higher_priority_task_woken != 0)
                    _frxt_setup_switch();
            }
        }
        RtosTask *reset_relay = RESET_RELAY_TASK;
        if (reset_relay != NULL) {
            int higher_priority_task_woken = 0;
            vTaskGenericNotifyGiveFromISR(reset_relay, 0, &higher_priority_task_woken);
            if (higher_priority_task_woken != 0)
                _frxt_setup_switch();
        }
        return;
    }
    if (event == 7) {
        memw();
        unsigned int generation = MEDIUS_EP0_REPLY_LIFETIME->request_generation;
        memw();
        unsigned int requested = MEDIUS_CLONE_REQUESTED_CONFIGURATION;
        unsigned int selected = 0xffffffffU;
        unsigned int wire_index = 255;
        unsigned int sequence = 0xffffffffU;
        if (requested != 0) {
            memw();
            requested = MEDIUS_CLONE_REQUESTED_CONFIGURATION;
            unsigned int count = MEDIUS_CLONE_CONFIGURATION_COUNT;
            for (unsigned int index = 0; (unsigned char)index < count; ++index) {
                unsigned int length = MEDIUS_CLONE_CONFIGURATION_LENGTHS[index];
                if (length < 6)
                    continue;
                unsigned int offset = MEDIUS_CLONE_CONFIGURATION_OFFSETS[index];
                if (MEDIUS_CLONE_CONFIGURATION_POOL[offset + 5U] == requested) {
                    selected = index;
                    wire_index = (unsigned char)index;
                    sequence = medius_report_record_sequence_event(0);
                    break;
                }
            }
        }
        unsigned int current = MEDIUS_CLONE_CONFIGURATION_INDEX;
        capture_usb_bus_event(current == 0 ? 4 : 3, current, 0);
        memw();
        unsigned int configurations = MEDIUS_USB_CONFIGURATION_EVENT_COUNT;
        memw();
        MEDIUS_USB_CONFIGURATION_EVENT_COUNT = configurations + 1U;
        memw();
        USB_SUSPENDED = 0;
        motion_configuration_changed();
        memw();
        REPORT_QUEUES_DIRTY = 1;
        xPortEnterCriticalTimeout(&CREDIT_LOCK, -1);
        for (unsigned int interface = 0; interface != 6; ++interface) {
            report_reset_interface_runtime(interface);
            memw();
            REPORT_INTERFACE_COMPLETING[interface] = 0;
        }
        for (unsigned int interface = 0; interface != 6; ++interface)
            medius_interface_clear_runtime_flags(interface);
        input_mark_dirty(INPUT0_STATE);
        input_mark_dirty(INPUT1_STATE);
        input_mark_dirty(INPUT2_STATE);
        memset((void *)REPORT_MERGE_ACCUMULATORS, 0, 16);
        memw();
        REPORT_MERGE_PENDING = 0;
        vPortExitCritical(&CREDIT_LOCK);
        const volatile unsigned char *alternates = CLONE_ALTERNATE_SETTINGS;
        for (unsigned int interface = 0; interface != 256; ++interface) {
            if (alternates[interface] != 0) {
                memw();
                CLONE_ALTERNATE_PENDING = 1;
                break;
            }
        }
        if (selected != 0xffffffffU) {
            if (MEDIUS_CLONE_CONFIGURATION_INDEX != selected) {
                RtosQueue *report_mutex = REPORT_MUTEX;
                if (report_mutex != NULL)
                    xQueueSemaphoreTake(report_mutex, 0xffffffffU);
                unsigned char *old_configuration = MEDIUS_CLONE_SELECTED_CONFIGURATION;
                unsigned int old_length = MEDIUS_CLONE_SELECTED_LENGTH;
                memw();
                MEDIUS_REPORT_FAST_BLOCK97_RW = 1;
                unsigned long long started = (unsigned long long)esp_timer_get_time();
                for (;;) {
                    memw();
                    if (REPORT_FAST_ACTIVE == 0)
                        break;
                    unsigned long long elapsed = (unsigned long long)esp_timer_get_time() - started;
                    if ((long long)elapsed > 999)
                        break;
                }
                unsigned int offset = MEDIUS_CLONE_CONFIGURATION_OFFSETS[selected];
                MEDIUS_CLONE_CONFIGURATION_INDEX = (unsigned char)wire_index;
                unsigned char *configuration = MEDIUS_CLONE_CONFIGURATION_BYTES + offset;
                unsigned int length = MEDIUS_CLONE_CONFIGURATION_LENGTHS[selected];
                MEDIUS_CLONE_SELECTED_CONFIGURATION = configuration;
                MEDIUS_CLONE_SELECTED_LENGTH = (unsigned short)length;
                memset(CLONE_ALTERNATE_SETTINGS, 0, 256);
                memw();
                CLONE_ALTERNATE_PENDING = 0;
                memw();
                OUTPUT_RESET_PENDING = 1;
                configuration = MEDIUS_CLONE_SELECTED_CONFIGURATION;
                length = MEDIUS_CLONE_SELECTED_LENGTH;
                memw();
                CLIP_RULES_RESET_PENDING = 1;
                medius_clone_transition_configuration_endpoints(old_configuration, (int)old_length, 0, 0);
                medius_clone_transition_configuration_endpoints(configuration, (int)length, 1, 0);
                medius_clone_transition_configuration_endpoints(configuration, (int)length, 1, 1);
                memset(MEDIUS_CLONE_RETAINED_IN_BINDINGS, 0, 24);
                xPortEnterCriticalTimeout(&CREDIT_LOCK, -1);
                for (unsigned int endpoint = 0; endpoint != 16; ++endpoint) {
                    memw();
                    CREDIT_ENDPOINT_INTERFACE[endpoint] = -2;
                }
                vPortExitCritical(&CREDIT_LOCK);
                RtosQueue *rewrite_mutex = REWRITE_MUTEX;
                if (rewrite_mutex != NULL)
                    xQueueSemaphoreTake(rewrite_mutex, 0xffffffffU);
                medius_clone_parse_configuration_reports(1);
                for (unsigned int interface = 0; interface != 6; ++interface)
                    MEDIUS_EP0_HID_CACHE[interface].pair = 0xffffffffU;
                clone_refresh_report_bindings(0, 0);
                rewrite_mutex = REWRITE_MUTEX;
                if (rewrite_mutex != NULL)
                    xQueueGenericSend(rewrite_mutex, NULL, 0, 0);
                medius_usb_register_clone_endpoints();
                usb_clone_reset_transfer_accounting();
                out_drain_all_served_endpoints();
                volatile unsigned char message[2];
                message[0] = (unsigned char)wire_index;
                message[1] = 0;
                if (medius_out_enqueue_control_message(0x24, (const void *)message, 2,
                        generation, sequence) != 0) {
                    memw();
                    USB_PUBLISHED_CONFIGURATION_INDEX = (unsigned char)wire_index;
                    memw();
                    USB_PUBLISHED_CONFIGURATION_GENERATION = generation;
                }
                report_mutex = REPORT_MUTEX;
                memw();
                MEDIUS_REPORT_FAST_BLOCK97_RW = 0;
                if (report_mutex != NULL)
                    xQueueGenericSend(report_mutex, NULL, 0, 0);
                unsigned int logged_at = esp_log_timestamp();
                esp_log_write(3, "usbdev", "I (%lu) %s: configuration -> index %d\n",
                    logged_at, "usbdev", selected);
                medius_usb_log_interface_slots("rebound");
            } else {
                volatile unsigned char message[2];
                message[0] = (unsigned char)wire_index;
                message[1] = 0;
                if (medius_out_enqueue_control_message(0x24, (const void *)message, 2,
                        generation, sequence) != 0) {
                    memw();
                    USB_PUBLISHED_CONFIGURATION_INDEX = (unsigned char)wire_index;
                    memw();
                    USB_PUBLISHED_CONFIGURATION_GENERATION = generation;
                }
            }
        }
        memw();
        if (CLONE_ALTERNATE_PENDING == 0) {
            usb_clone_reset_transfer_accounting();
            out_drain_all_served_endpoints();
        }
        memw();
        MEDIUS_REPORT_ENDPOINT_TRANSITION_PENDING = 0;
        return;
    }
    if (event == 3 || event == 4) {
        capture_usb_bus_event(event == 3 ? 8 : 9, 0, 0);
        return;
    }
    if (event == 5) {
        capture_usb_bus_event(1, 0, 0);
        memw();
        USB_SUSPENDED = 1;
        motion_configuration_changed();
        RtosTask *observed_task = MOTION_TXWD_TASK;
        memw();
        REPORT_WAKE_REQUEST = 0;
        bus_event_notify_motion_watchdog(observed_task);
        if (xPortInIsrContext() == 0)
            link_kick_fast_tx();
        else
            link_wake_fast_transmit_from_isr();
        xPortEnterCriticalTimeout(&CREDIT_LOCK, -1);
        memset((void *)REPORT_MERGE_ACCUMULATORS, 0, 16);
        memw();
        REPORT_MERGE_PENDING = 0;
        bus_event_clear_completion_history();
        vPortExitCritical(&CREDIT_LOCK);
        return;
    }
    if (event == 6) {
        capture_usb_bus_event(2, 0, 0);
        memw();
        USB_SUSPENDED = 0;
        motion_configuration_changed();
        RtosTask *observed_task = MOTION_TXWD_TASK;
        memw();
        REPORT_QUEUES_DIRTY = 1;
        bus_event_notify_motion_watchdog(observed_task);
        unsigned long long now = (unsigned long long)esp_timer_get_time();
        xPortEnterCriticalTimeout(&CREDIT_LOCK, -1);
        bus_event_clear_completion_history();
        for (unsigned int interface = 0; interface != 6; ++interface) {
            memw();
            REPORT_SUBMIT_TIME[interface].low = (unsigned int)now;
            memw();
            REPORT_SUBMIT_TIME[interface].high = (unsigned int)(now >> 32);
        }
        for (unsigned int interface = 0; interface != 6; ++interface) {
            memw();
            REPORT_SECONDARY_TIME[interface].low = (unsigned int)now;
            memw();
            REPORT_SECONDARY_TIME[interface].high = (unsigned int)(now >> 32);
        }
        vPortExitCritical(&CREDIT_LOCK);
        return;
    }
    if ((unsigned char)(event - 9U) < 2) {
        unsigned int enabled = event == 9;
        memw();
        MEDIUS_USB_REMOTE_WAKE_ENABLED = (unsigned char)enabled;
        memw();
        unsigned int generation = MEDIUS_EP0_REPLY_LIFETIME->request_generation;
        volatile unsigned char message = (unsigned char)enabled;
        medius_out_enqueue_control_message(0x42, (const void *)&message, 1,
            generation, 0xffffffffU);
    }
}

/* Native entry: 0x42033ca4. */
/* Original function-byte SHA-256:
 * dccd261ab46d3ef305d4874527066f5319605bb058a30fd1b12fe497a32605f2. */
/*
 * MEMW then return the device USB reset-event counter as one unchanged WORD.
 * Used in the control status response. No count clear, event acknowledgement,
 * bus operation, lock or coherent snapshot with configuration/drop counters.
 */
unsigned int usbd_get_reset_count(void)
{
    memw();
    return MEDIUS_USB_RESET_COUNT;
}

/* Native entry: 0x42033cb4. */
/* Original function-byte SHA-256:
 * 5f07300f12d6b928a9ae60dc5c4fc57a7a4baf6307edc6634cda1e594efd59a0. */
/*
 * MEMW then return the USB configuration-event counter as one unchanged WORD.
 * Used in the control status response. No count clear, configuration change,
 * lock, saturation or coherent snapshot with other status fields.
 */
unsigned int usbd_get_configuration_event_count(void)
{
    memw();
    return MEDIUS_USB_CONFIGURATION_EVENT_COUNT;
}
