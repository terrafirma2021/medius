/* Device application: startup, clone events, link monitoring and maintenance. */

#include "../include/types.h"

/* Native entry: 0x420242b8. */
/* Original function-byte SHA-256:
 * d2c660fb2b5b410a77a926bb83d0e61172c300a162c0effb91464851a5d22faf. */

/*
 * unused_argument: Unused FreeRTOS task-entry argument; accepted without dereference.
 * Returns: No value. Normally transfers to the application or current-task deletion; native RET
 *   remains if deletion unexpectedly returns.
 * Requirements/effects: FreeRTOS task entry, created with a 4,096-byte stack, priority 1 and CPU0
 *   affinity by esp_startup_start_app. Logs startup using a timestamp and a fresh PRID bit 13
 *   snapshot. Reads PRID again to register the bool(void) startup idle callback on the other core;
 *   registration status is ignored. Polls the raw completion byte until any nonzero value, with
 *   fresh MEMW-ordered reads and no yield, delay or timeout. A full hook table can leave this wait
 *   indefinite. The flag is not cleared on entry. Reads PRID a third time for callback removal,
 *   independently of the registration snapshot, then enables the released startup-stack heaps.
 *   Passes a 12-byte watchdog configuration: 5,000 ms timeout, idle-core mask 0, panic enabled and
 *   three zero tail bytes. Any nonzero 32-bit initialization status aborts, retaining prior side
 *   effects. Main and idle tasks are not subscribed to the task watchdog here. On success, logs
 *   Calling app_main() and invokes the application. Only if it returns does this task log Returned
 *   from app_main() and delete itself using a NULL task handle. Scheduling, dependency lifetimes
 *   and real watchdog timing are supplied by the separate implementations.
 */

void main_task(void *unused_argument)
{
    (void)unused_argument; /* FreeRTOS task-entry ABI; the native body never reads it. */

    unsigned int started_at = esp_log_timestamp();
    unsigned int logged_core = (xtensa_read_prid() >> 13) & 1U;
    esp_log_write(3, "main_task", "I (%lu) %s: Started on CPU%d\n",
        started_at, "main_task", logged_core);

    unsigned int registration_core =
        ((xtensa_read_prid() >> 13) & 1U) ^ 1U;
    (void)esp_register_freertos_idle_hook_for_cpu(
        other_cpu_startup_idle_hook_cb, registration_core);

    /* The other core must reach idle before its startup stack becomes heap.
     * A failed hook registration still enters this unbounded polling loop. */
    do {
        memw();
    } while (OTHER_CPU_STARTUP_DONE == 0);

    unsigned int removal_core =
        ((xtensa_read_prid() >> 13) & 1U) ^ 1U;
    esp_deregister_freertos_idle_hook_for_cpu(
        other_cpu_startup_idle_hook_cb, removal_core);
    heap_caps_enable_nonos_stack_heaps();

    const TaskWatchdogConfig watchdog = {
        .timeout_ms = 5000U,
        .idle_core_mask = 0U,
        .trigger_panic = true,
        .reserved9 = { 0, 0, 0 }
    };
    int watchdog_status = esp_task_wdt_init(&watchdog);
    if (watchdog_status != 0)
        abort();

    unsigned int calling_at = esp_log_timestamp();
    esp_log_write(3, "main_task", "I (%lu) %s: Calling app_main()\n",
        calling_at, "main_task");
    app_main();

    /* This epilogue is reached only if the application returns. */
    unsigned int returned_at = esp_log_timestamp();
    esp_log_write(3, "main_task", "I (%lu) %s: Returned from app_main()\n",
        returned_at, "main_task");
    vTaskDelete(0);
}

/* Native entry: 0x42027538. */
/* Original function-byte SHA-256:
 * 685d0601b29ebb5ea68c0a53d23d50d96891b1246c460077d5d6efec555723b0. */
/*
 * Initialize device services, then run the clone-event and maintenance loop.
 * No parameters or normal return. Queue creation, most service calls and
 * transport results are unchecked; no cleanup or transactional rollback occurs.
 *
 * Startup caches PSRAM size/error results, installs control/link/log callbacks,
 * starts workers and LED output, and allocates an eight-entry byte-event queue.
 * Initialize the shared link monitor with a 500000-us timeout and no activity.
 * Cache/log the startup banner and previous panic text, send the initial clone
 * request, raise this task to priority 14 and register its watchdog service.
 *
 * Event 2 resets the session and sets a 250000-us detach deadline. Event 1,
 * when clone updates are allowed, hashes section-presence/length headers and
 * borrowed payloads in order, excluding section 6. Include absent sections 8/9.
 * Reuse an identical snapshot or fetch sections in native order and configure
 * USB from their borrowed buffers. Only device/config pointers are mandatory.
 * Cache the digest before releasing assembly, including missing-pointer paths.
 * Failed clone startup during OTA probation polls readiness up to 100 times,
 * then reports failure even when readiness ended that wait early.
 *
 * Drain deferred retry/log/bounce diagnostics and enforce the detach deadline.
 * Under the link-monitor lock, compare signed timestamp high words and unsigned
 * low words; publish newer activity and test signed wrapping age against the
 * configured timeout (normal mode) or 15000000 us (alternate mode). Preserve
 * live rereads, raw seen/up bytes and paired startup clear. Release the lock
 * before link transition logs, notifications and safety resets.
 *
 * Service updates using the low 32-bit clock word, reclone requests and
 * profile persistence. Preserve repeated
 * mode queries and raw configuration/request results. Clone requests run on
 * iteration multiples of 3 or 16; request count 6 uses only multiples of 16
 * without incrementing. Refresh admission uses byte-masked bit operations and
 * a signed iteration-gap test greater than 15, with native notification gates.
 * Periodic work uses signed wrapped elapsed time greater than 1000000 us.
 * Generation changes reset notices; eligible profile notices wait for their
 * signed iteration threshold and a multiple of 10, then increment the fresh
 * counter regardless of transport success. Relevant tails normalize configured
 * state to 1. DeviceMainLoopState is reconstructed local storage; current_up's
 * original stack slot becomes the next iteration count after its last use.
 *
 * Software scheduling, borrowed-buffer lifetime and concurrent service behavior
 * are supplied by the callees. Hardware timing and concurrency are unverified.
 */
void app_main(void)
{
    char diagnostics[256];
    Sha256Context hash_context;
    unsigned char digest[32];
    unsigned short section_length[17];
    unsigned char *section[17];
    union { unsigned int word; unsigned char bytes[4]; } header;
    volatile DeviceMainLoopState state;
    volatile DeviceLinkMonitor *monitor = DEVICE_LINK_MONITOR;

    unsigned int psram_capacity = esp_psram_get_size();
    DEVICE_CACHED_PSRAM_BYTES = psram_capacity;
    if (psram_capacity == 0) {
        unsigned int initialization_error = esp_psram_init();
        DEVICE_PSRAM_INIT_ERROR = initialization_error;
        if (initialization_error == 0) {
            esp_psram_extram_add_to_heap_allocator();
            DEVICE_CACHED_PSRAM_BYTES = esp_psram_get_size();
        } else {
            xPortEnterCriticalTimeout(&DEVICE_PSRAM_SETUP_LOCK, 0xffffffffU);
            mspi_timing_change_speed_mode_cache_safe(0);
            vPortExitCritical(&DEVICE_PSRAM_SETUP_LOCK);
        }
    }
    control_uart_init();
    identity_initialize();
    ota_start_grace(30000);
    control_protocol_init();
    device_update_session_init();
    /* This linked startup hook is empty; the callback is ignored. */
    startup_reboot_callback_noop(reboot_to_download);
    control_set_first_frame_hook(control_send_initial_version);
    device_workers_init();
    led_initialize(9, 1);
    DEVICE_CLONE_EVENT_QUEUE = rtos_create_queue_type(8, 1, 0);
    clone_assembly_reset(DEVICE_CLONE_ASSEMBLY);
    monitor->timeout_low = 500000;
    monitor->timeout_high = 0;
    monitor->activity_low = 0;
    monitor->activity_high = 0;
    monitor->seen_and_up = 0;
    esp_log_set_vprintf(device_log_hook);

    int has_diagnostics = boot_read_previous_panic(diagnostics, sizeof(diagnostics));
    const char *version = device_version_string();
    unsigned int reset_reason = esp_reset_reason();
    newlib_snprintf(DEVICE_STARTUP_BANNER, 320,
        "medius device %s starting, reset=%d%s%s", version, reset_reason,
        has_diagnostics != 0 ? " | " : "",
        has_diagnostics != 0 ? (const char *)diagnostics : "");
    unsigned int log_time = esp_log_timestamp();
    esp_log_write(3, "device", "I (%lu) %s: %s\n", log_time, "device", DEVICE_STARTUP_BANNER);
    unsigned int ring_capacity = clip_get_allocation_capacity();
    const char *ring_storage = ring_capacity == 65536 ? "psram" :
        ring_capacity == 0 ? "none" : "internal";
    if (DEVICE_CACHED_PSRAM_BYTES == 0) {
        log_time = esp_log_timestamp();
        esp_log_write(2, "device", "W (%lu) %s: psram: none (err 0x%x), clip ring %u (%s)\n",
            log_time, "device", DEVICE_PSRAM_INIT_ERROR, ring_capacity, ring_storage);
    } else {
        log_time = esp_log_timestamp();
        esp_log_write(3, "device", "I (%lu) %s: psram: %u bytes, clip ring %u (%s)\n",
            log_time, "device", DEVICE_CACHED_PSRAM_BYTES, ring_capacity, ring_storage);
    }
    control_send_initial_version();
    link_set_frame_handler(device_link_message_boundary, 0);
    link_init(0);
    link_start_sync_task(1);
    link_send_wait100(0x15, 0, 0, 0);
    state.generation = report_get_normalization_epoch();
    state.last_periodic = (unsigned long long)esp_timer_get_time();
    vTaskPrioritySet(0, 14);
    watch_current_task();
    state.request_count = 1;
    state.iteration = 0;
    state.notification_threshold = 0;
    state.previous_up = 0;
    state.detach_deadline = 0;
    state.pending = 0;
    state.last_refresh_iteration = 0;
    state.refresh = 0;
    state.configuration_result = 0;

    for (;;) {
        /* Clone events and descriptor snapshots. */
        feed_current_task_watchdog();
        unsigned char event;
        int received = xQueueReceive(DEVICE_CLONE_EVENT_QUEUE, &event, 50);
        if (received != 0) {
            unsigned int mode = update_clone_is_suspended();
            if (mode != 0) {
                if (event == 1)
                    clone_release_assembly(0);
            } else if (event == 2) {
                session_reset();
                unsigned long long detach_time = (unsigned long long)esp_timer_get_time();
                memw();
                state.detach_deadline = detach_time + 250000ULL;
                memw();
                DEVICE_REFRESH_REQUESTED = 0;
            } else if (event == 1) {
                mbedtls_sha256_init(&hash_context);
                mbedtls_sha256_starts(&hash_context, 0);
                for (unsigned int id = 0; id < 17; id++) {
                    if (id == 6)
                        id = 7;
                    unsigned short length = 0;
                    unsigned char *data = clone_section_get(
                        DEVICE_CLONE_ASSEMBLY, id, &length);
                    *(unsigned short *)header.bytes = (unsigned short)((data != 0) | ((length & 255U) << 8));
                    header.bytes[2] = length >> 8;
                    mbedtls_sha256_update(&hash_context, header.bytes, 3);
                    if (data != 0 && length != 0)
                        mbedtls_sha256_update(&hash_context, data, length);
                }
                mbedtls_sha256_finish(&hash_context, digest);
                mbedtls_sha256_free(&hash_context);
                state.configuration_result &= (state.refresh ^ 1U) & 255U;
                if (state.configuration_result != 0 && memcmp(digest, DEVICE_CACHED_CLONE_DIGEST, 32) == 0) {
                    log_time = esp_log_timestamp();
                    esp_log_write(3, "device", "I (%lu) %s: re-attach identical (unchanged)\n",
                        log_time, "device");
                    state.pending = clone_release_assembly(1);
                } else {
                    /* Section order is significant at the borrowed getter boundary. */
                    section[0] = clone_section_get(DEVICE_CLONE_ASSEMBLY,0,&section_length[0]);
                    section[1] = clone_section_get(DEVICE_CLONE_ASSEMBLY,1,&section_length[1]);
                    section[2] = clone_section_get(DEVICE_CLONE_ASSEMBLY,2,&section_length[2]);
                    section[3] = clone_section_get(DEVICE_CLONE_ASSEMBLY,3,&section_length[3]);
                    section[4] = clone_section_get(DEVICE_CLONE_ASSEMBLY,4,&section_length[4]);
                    section[5] = clone_section_get(DEVICE_CLONE_ASSEMBLY,5,&section_length[5]);
                    section[7] = clone_section_get(DEVICE_CLONE_ASSEMBLY,7,&section_length[7]);
                    section[13] = clone_section_get(DEVICE_CLONE_ASSEMBLY,13,&section_length[13]);
                    section[14] = clone_section_get(DEVICE_CLONE_ASSEMBLY,14,&section_length[14]);
                    section[10] = clone_section_get(DEVICE_CLONE_ASSEMBLY,10,&section_length[10]);
                    unsigned char speed = section[10] != 0 && section_length[10] != 0 ?
                        *(volatile unsigned char *)section[10] : 0;
                    section[11] = clone_section_get(DEVICE_CLONE_ASSEMBLY,11,&section_length[11]);
                    section[12] = clone_section_get(DEVICE_CLONE_ASSEMBLY,12,&section_length[12]);
                    unsigned char configuration_value = section[12] != 0 && section_length[12] != 0 ?
                        *(volatile unsigned char *)section[12] : 0;
                    state.configuration_result = section[0] == 0 || section[1] == 0;
                    if (state.configuration_result != 0) {
                        log_time = esp_log_timestamp();
                        esp_log_write(1, "device", "E (%lu) %s: snapshot missing device/config\n",
                            log_time, "device");
                        memcpy(DEVICE_CACHED_CLONE_DIGEST, digest, 32);
                        state.pending = clone_release_assembly(1);
                    } else {
                        section[15] = clone_section_get(
                            DEVICE_CLONE_ASSEMBLY, 15, &section_length[15]);
                        section[16] = clone_section_get(
                            DEVICE_CLONE_ASSEMBLY, 16, &section_length[16]);
                        unsigned int configured = usb_clone_configure(
                            section[0],section_length[0],section[1],section_length[1],
                            section[11],section_length[11],section[2],section_length[2],
                            (char *)section[3],(char *)section[4],(char *)section[5],
                            section[7],section_length[7],section[13],section_length[13],
                            section[14],section_length[14],speed,configuration_value,
                            section[15],section_length[15],section[16],section_length[16]);
                        state.configuration_result = configured;
                        memcpy(DEVICE_CACHED_CLONE_DIGEST, digest, 32);
                        state.pending = clone_release_assembly(1);
                        if (configured == 0 && ota_running_image_is_pending() != 0) {
                            for (unsigned int attempts = 100; attempts != 0; attempts--) {
                                if (control_pc_has_sent_frame() != 0)
                                    break;
                                feed_current_task_watchdog();
                                vTaskDelay(50);
                            }
                            ota_fail_probation("the clone cannot start");
                        }
                    }
                }
                state.refresh = 0;
                state.detach_deadline = 0;
            }
        }

        /* Deferred startup, panic and USB-buffer diagnostics. */
        unsigned int exchanged = atomic_exchange_byte(DEVICE_RETRY_FLAG, 0, 4);
        state.pending = (state.pending | (exchanged != 0)) & 255U;
        if (DEVICE_STARTUP_LOG_EMITTED == 0 && control_pc_has_sent_frame() != 0) {
            DEVICE_STARTUP_LOG_EMITTED = 1;
            log_time = esp_log_timestamp();
            esp_log_write(3, "device", "I (%lu) %s: %s\n", log_time, "device", DEVICE_STARTUP_BANNER);
        }
        if (DEVICE_HOST_PANIC_LOG[0] != 0 && control_pc_has_sent_frame() != 0) {
            log_time = esp_log_timestamp();
            esp_log_write(3, DEVICE_HOST_LOG_TAG, "I (%lu) %s: %s\n",
                log_time, DEVICE_HOST_LOG_TAG, DEVICE_HOST_PANIC_LOG);
            DEVICE_HOST_PANIC_LOG[0] = 0;
        }
        unsigned int bounce_count = usbd_get_unaligned_write_count();
        if (DEVICE_LOGGED_BOUNCE_COUNT != bounce_count) {
            unsigned char endpoint;
            unsigned int pointer, length;
            DEVICE_LOGGED_BOUNCE_COUNT = bounce_count;
            usbd_read_last_unaligned_write(&endpoint, &pointer, &length);
            log_time = esp_log_timestamp();
            esp_log_write(2, "device",
                "W (%lu) %s: unaligned USB transfer bounced (%u so far, last ep=%02x ptr=0x%08x len=%u)\n",
                log_time, "device", bounce_count, (unsigned char)endpoint, pointer, length);
        }
        if (state.detach_deadline != 0 &&
                (long long)(unsigned long long)esp_timer_get_time() >= (long long)state.detach_deadline) {
            clone_reset_and_notify_host();
            memset(DEVICE_CACHED_CLONE_DIGEST, 0, 32);
            memw();
            memw();
            DEVICE_REFRESH_REQUESTED = 0;
            state.detach_deadline = 0;
            state.refresh = 0;
            state.configuration_result = 0;
        }

        /* Shared activity timestamp and link transitions. */
        state.now = (unsigned long long)esp_timer_get_time();
        unsigned int mode = update_clone_is_suspended();
        unsigned long long timestamp = fast_report_get_activity_time();
        xPortEnterCriticalTimeout(&DEVICE_LINK_MONITOR_LOCK, 0xffffffffU);
        unsigned int saved_high = monitor->activity_high;
        unsigned int saved_low = 0;
        if (saved_high == (unsigned int)(timestamp >> 32))
            saved_low = monitor->activity_low;
        int newer = (int)saved_high < (int)(unsigned int)(timestamp >> 32) ||
            (saved_high == (unsigned int)(timestamp >> 32) && saved_low < (unsigned int)timestamp);
        unsigned int timeout_low, timeout_high;
        unsigned char seen;
        if (newer) {
            if (mode == 0) {
                timeout_low = monitor->timeout_low;
                timeout_high = monitor->timeout_high;
            } else {
                timeout_low = 15000000;
                timeout_high = 0;
            }
            monitor->activity_low = (unsigned int)timestamp;
            monitor->activity_high = timestamp >> 32;
            monitor->seen = 1;
            seen = 1;
        } else {
            seen = monitor->seen;
            if (mode == 0) {
                timeout_low = monitor->timeout_low;
                timeout_high = monitor->timeout_high;
            } else {
                timeout_low = 15000000;
                timeout_high = 0;
            }
        }
        unsigned int up = 0;
        if (seen != 0) {
            if (newer && mode != 0) {
                saved_low = (unsigned int)timestamp;
                saved_high = timestamp >> 32;
            } else {
                saved_low = monitor->activity_low;
                saved_high = monitor->activity_high;
            }
            unsigned long long saved = ((unsigned long long)saved_high << 32) | saved_low;
            unsigned long long timeout = ((unsigned long long)timeout_high << 32) | timeout_low;
            up = (long long)(state.now - saved) < (long long)timeout;
        }
        unsigned char was_up = monitor->up;
        if (up != 0) {
            if (was_up == 0) {
                monitor->up = 1;
                vPortExitCritical(&DEVICE_LINK_MONITOR_LOCK);
                log_time = esp_log_timestamp();
                esp_log_write(3, "device", "I (%lu) %s: inter-chip link up\n", log_time, "device");
                link_publish_poll_interval();
            } else {
                vPortExitCritical(&DEVICE_LINK_MONITOR_LOCK);
            }
            state.rising = state.previous_up ^ 1U;
            state.current_up = 1;
            state.previous_up = 1;
        } else {
            if (was_up != 0) {
                monitor->up = 0;
                vPortExitCritical(&DEVICE_LINK_MONITOR_LOCK);
                motion_reset_host_session();
                session_reset();
                log_time = esp_log_timestamp();
                esp_log_write(2, "device", "W (%lu) %s: inter-chip link lost -> safety clear\n",
                    log_time, "device");
            } else {
                vPortExitCritical(&DEVICE_LINK_MONITOR_LOCK);
            }
            state.current_up = 0;
            state.previous_up = 0;
            state.rising = 0;
        }

        /* Update, request, refresh and profile maintenance. */
        unsigned int auxiliary = state.configuration_result != 0 ? primary_input_interface_is_selected() : 0;
        unsigned int current_up = state.current_up;
        control_publish_link_and_interface_state(current_up, auxiliary);
        update_set_host_link_state(current_up);
        update_service((unsigned int)state.now);
        unsigned int reset = update_take_reclone_request();
        if (reset != 0) {
            memset(DEVICE_CACHED_CLONE_DIGEST, 0, 32);
            memw();
            memw();
            DEVICE_REFRESH_REQUESTED = 0;
            link_send_wait100(0x15, 0, 0, 0);
        }
        if ((long long)state.now > 10000000LL)
            confirm_running_image();
        unsigned int first_mode = update_clone_is_suspended();
        unsigned int request;
        if (reset != 0) {
            request = reset;
            if (first_mode == 0) {
                state.configuration_result = 0;
                state.refresh = 0;
                state.request_count = 0;
                state.detach_deadline = 0;
                led_set_status(state.previous_up);
            }
        } else if (first_mode != 0) {
            request = (state.pending | (state.configuration_result ^ 1U)) & 255U;
        } else {
            unsigned int configured_up = state.configuration_result & state.previous_up;
            if (configured_up == 0) {
                request = (state.pending | (state.configuration_result ^ 1U)) & 255U;
                led_set_status(state.previous_up);
            } else {
                unsigned int probe = clone_is_configured();
                state.configuration_result = probe != 0 ? probe : configured_up;
                request = state.pending;
                led_set_status(probe != 0 ? 2 : state.previous_up);
            }
        }
        control_service_led_expiry((unsigned int)state.now, (unsigned int)(state.now >> 32), state.current_up);
        profile_persistence_service();
        unsigned int next = state.iteration + 1U;
        state.current_up = next; /* Original stack slot is reused after its last link-up use. */
        unsigned int allowed = 0;
        int evaluate_refresh = 1;
        int schedule = 0;
        int slow = 0;
        if (reset != 0 && first_mode != 0) {
            if (state.rising != 0) {
                state.configuration_result = 0;
                state.refresh = 0;
                state.detach_deadline = 0;
                state.request_count = 0;
                allowed = state.rising;
                schedule = update_clone_is_suspended() == 0;
            } else if (state.previous_up == 0) {
                state.configuration_result = 0;
                state.refresh = 0;
                state.detach_deadline = 0;
                state.request_count = 0;
                evaluate_refresh = 0;
            } else {
                unsigned int second_mode = update_clone_is_suspended();
                state.configuration_result = 0;
                state.refresh = 0;
                state.detach_deadline = 0;
                state.request_count = 0;
                allowed = second_mode == 0 ? state.previous_up : second_mode;
                schedule = second_mode == 0;
            }
        } else if (state.rising != 0) {
            state.request_count = 0;
            allowed = state.detach_deadline == 0;
            if (request != 0) {
                unsigned int second_mode = update_clone_is_suspended();
                state.request_count = 0;
                schedule = second_mode == 0;
            }
        } else if (state.previous_up == 0) {
            evaluate_refresh = 0;
        } else {
            allowed = state.detach_deadline == 0;
            if (request != 0 && update_clone_is_suspended() == 0) {
                schedule = 1;
                slow = state.request_count == 6;
            }
        }
        if (schedule && (next % 16U == 0 || (!slow && next % 3U == 0))) {
            link_send_wait100(0x15, 0, 0, 0);
            if (!slow)
                state.request_count++;
        }
        int notify = 1;
        if (evaluate_refresh) {
            unsigned int refresh_enabled = (allowed & (update_clone_is_suspended() ^ 1U)) & 255U;
            if (refresh_enabled != 0) {
                unsigned int dirty = descriptor_service_patch_refresh();
                if ((dirty != 0 && state.configuration_result != 0) ||
                    (dirty == 0 && state.refresh != 0 && state.configuration_result != 0 &&
                        (int)(next - state.last_refresh_iteration) > 15)) {
                    memw();
                    memw();
                    DEVICE_REFRESH_REQUESTED = 1;
                    link_send_wait100(0x15, 0, 0, 0);
                    state.last_refresh_iteration = next;
                    state.refresh = state.configuration_result;
                } else if (state.refresh != 0 && state.configuration_result == 0) {
                    state.refresh = refresh_enabled;
                    state.configuration_result = 0;
                    notify = 0;
                } else if (dirty != 0 && state.configuration_result == 0) {
                    state.configuration_result = 0;
                    notify = 0;
                } else if (dirty == 0 && state.refresh != 0) {
                    state.refresh = state.configuration_result;
                }
            }
        }
        if ((long long)(state.now - state.last_periodic) > 1000000LL) {
            link_publish_poll_interval();
            if (update_clone_is_suspended() == 0) {
                device_relay_current_configuration();
                request_power_state_publish();
            }
            state.last_periodic = state.now;
        }
        unsigned int generation = report_get_normalization_epoch();
        if (state.generation != generation) {
            DEVICE_PROFILE_NOTICE_COUNT = 0;
            state.notification_threshold = state.iteration + 11U;
            profile_refresh_capture_flag();
        }
        if (state.configuration_result != 0 && notify) {
            if ((int)DEVICE_PROFILE_NOTICE_COUNT < 1 && (int)next >= (int)state.notification_threshold && next % 10U == 0) {
                unsigned char first, second;
                unsigned short value;
                if (profile_request_baseline(&first, &second, &value) != 0) {
                    unsigned int notification = first | ((unsigned int)second << 8) | ((unsigned int)value << 16);
                    control_forward_pending_generation();
                    link_send_wait100(0x16, 0, &notification, 4);
                    DEVICE_PROFILE_NOTICE_COUNT = DEVICE_PROFILE_NOTICE_COUNT + 1U;
                }
            }
            state.configuration_result = 1;
        }
        state.iteration = next;
        state.generation = generation;
    }
}
