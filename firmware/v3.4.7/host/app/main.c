/* Medius v3.4.7 host — app/main.c.
 * Recovered C and native assembly, grouped for source navigation.
 * Original entry addresses, firmware-byte hashes and function comments follow.
 */

#include "../include/types.h"

/* Native entry: 0x42023988. */
/*
 * Medius v3.4.7 — host application; 0x42023988.
 *
 * Waits for other-core startup, releases startup-stack heaps, configures the task watchdog, and invokes app_main.
 *
 * Calls: vTaskDelete, esp_log_timestamp, esp_log_write, esp_register_freertos_idle_hook_for_cpu, esp_deregister_freertos_idle_hook_for_cpu, heap_caps_enable_nonos_stack_heaps,
 * abort, app_main, esp_task_wdt_init.
 *
 * Original function-byte SHA-256:
 * 6bf76426cc07b023622cce904012d31180a3f4be0201d3a8976ee3ebca9dbbce.
 */

/*
 * argument: Unused FreeRTOS task-entry argument; accepted without dereference.
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

void main_task(void *argument)
{
    (void)argument; /* FreeRTOS task-entry ABI; the native body never reads it. */

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

/* Native entry: 0x42024358. */
/* Original function-byte SHA-256:
 * 3e63a9570559d808eb512c38f4c0bf81f605a621c5fad0b4863086fc32b35e6f. */
/* Start the host application, then run its maintenance loop indefinitely.
 * In native call order: start a 40000-ms OTA probation grace period; initialize
 * update-session state, UART link role1 and host logging; start link sync with
 * argument0, set its period input20 and register the host message handler with
 * NULL context; start host/vendor/OUT workers; initialize active-high GPIO9 LED.
 * Format any retained panic into the 176-byte stack buffer and log it only
 * when its helper returns nonzero. Initialize USB bus0 at60080000 with the
 * host event callback. Cache that result, then get firmware label, then reset
 * reason, and log all three. A failed USB start does not stop initialization.
 * Release a SOF gate level, initialize motion, then create link_hb with a
 * 2560-byte stack, priority5, core0 and NULL argument/output handle. Its task
 * creation result, like the other startup status results, is ignored here.
 *
 * Each iteration delays1000 FreeRTOS ticks (not a wall-clock deadline), clears
 * ONLY sync.ready, and requests six outputs in their native scratch offsets.
 * Any nonzero ready byte calls OTA confirmation; other outputs are unused here.
 * Then service recovery and update inactivity. A fresh forwarding-inhibit0
 * permits the LED update, using twice the indicator helper's RAW byte; otherwise
 * leave the LED alone. Independently sample the full32-bit report-drop counter.
 * Increment the unsigned iteration counter; every fifth value, including0 at
 * wraparound, log changed totals and their unsigned delta from the LAST LOGGED
 * total, then update that baseline. No change means no log/baseline write.
 * No yield beyond the task delay, aggregate status snapshot, timeout, startup
 * rollback, retry-on-startup-error or task-deletion path is added. Scheduling,
 * hardware effects and dependency lifetimes belong to the called functions.
 */
void app_main(void)
{
    MediusHostMainScratch scratch; /* Native stack contents are not pre-zeroed. */
    ota_start_grace(40000);
    medius_host_update_session_init();
    link_init(1);
    medius_host_log_init();
    link_start_sync_task(0);
    medius_link_set_sync_period(20);
    medius_link_register_application_handler(medius_host_link_message,0);
    medius_host_workers_init();
    medius_vendor_start_workers();
    medius_out_start_worker();
    led_initialize(9,1);
    if (boot_read_previous_panic(scratch.previous_panic,sizeof(scratch.previous_panic)) != 0)
        medius_host_log_formatted("%s",scratch.previous_panic);
    int usb_status = usbh_initialize(0,0x60080000U,medius_usb_host_event_callback);
    const char *firmware_label = medius_get_firmware_label();
    int reset_reason = esp_reset_reason();
    medius_host_log_formatted("medius host %s: usbh_initialize rc=%d reset=%d",
                              firmware_label,usb_status,reset_reason);
    medius_host_release_sof_gate();
    medius_host_motion_init();
    xTaskCreatePinnedToCore(medius_host_heartbeat_task,"link_hb",2560,0,5,0,0);

    unsigned int last_logged_drops = 0;
    unsigned int iterations = 0;
    for (;;) {
        vTaskDelay(1000);
        scratch.sync.ready = 0;
        link_read_sync_status(&scratch.sync.offset_us,&scratch.sync.drift_ppb,
            &scratch.sync.round_trip_us,&scratch.sync.sample_age_ms,
            &scratch.sync.ready,&scratch.sync.drift_valid);
        if (scratch.sync.ready != 0)
            medius_ota_confirm_image();
        medius_host_recovery_service();
        medius_host_update_check_timeout();
        if (medius_host_get_forwarding_inhibit() == 0) {
            unsigned int indicator = medius_host_forwarding_indicator();
            led_set_status(indicator*2U);
        }
        unsigned int dropped_reports = medius_host_report_drop_count();
        ++iterations;
        if (iterations%5U == 0 && last_logged_drops != dropped_reports) {
            medius_host_log_formatted("report queue full: %u reports dropped, %u since boot",
                                      dropped_reports-last_logged_drops,dropped_reports);
            last_logged_drops = dropped_reports;
        }
    }
}

