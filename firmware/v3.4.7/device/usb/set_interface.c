/* Medius v3.4.7 device — SET_INTERFACE transitions and transfer reset. */
#include "../include/types.h"

/* Native entry: 0x403954d8. */
/* Original function-byte SHA-256:
 * e4bcb80ddcaefab8674bad1f4ebaf7766ce3dde8f369fe9f2e439381d83f5b8a. */
/*
 * Observe SET_INTERFACE and, for bus0 with cloning active, apply its low8
 * interface/alternate values. Native arguments are narrowed to BYTEs. Snapshot
 * request generation under a fence, then emit capture event5 even for a bus
 * that will be ignored. Return0 for another bus/inactive clone; otherwise return
 * the sampled active BYTE, including invalid-alternate and timeout cases.
 *
 * Invalid alternate logs a warning and leaves endpoints alone. Valid requests
 * wait for the nonzero worker until a signed64-bit clock deadline of now+80000,
 * delaying one RTOS tick per retry; expiry still proceeds. Record a sequence,
 * take report mutex then rewrite mutex (forever, results ignored), snapshot old
 * alternate and all256 live alternate BYTEs into shared staging. A pending reset
 * clears its flag, selects/zeros every nonzero old alternate and resets transfer
 * accounting; the requested alternate is then staged and the selected set applied.
 * Release freshly loaded rewrite then report mutexes, log the change and enqueue
 * control0x1f with a two-BYTE pair, captured generation and recorded sequence.
 *
 * No enqueue-result check, rollback, timing guarantee or coherent configuration
 * snapshot. Shared staging and live descriptors require external serialization.
 * The selection bitset is eight WORDs covering all256 possible BYTE interfaces.
 */
unsigned int medius_clone_handle_set_interface(unsigned char bus,
    unsigned int interface_value, unsigned char alternate)
{
    unsigned int interface = (unsigned char)interface_value;
    memw();
    unsigned int generation = MEDIUS_EP0_REPLY_LIFETIME->request_generation;
    capture_usb_bus_event(5, interface, alternate);
    if (bus != 0)
        return 0;
    memw();
    unsigned int active = CLONE_ACTIVE;
    if (active == 0)
        return 0;
    if (!medius_clone_interface_alternate_exists((unsigned char)interface, alternate)) {
        unsigned int logged_at = esp_log_timestamp();
        esp_log_write(2, "usbdev", "W (%lu) %s: intf %u has no alt %u -> endpoints left alone\n",
            logged_at, "usbdev", interface, (unsigned int)alternate);
        return active;
    }
    unsigned long long deadline = (unsigned long long)esp_timer_get_time() + 80000ULL;
    memw();
    unsigned int worker_busy = NONZERO_CONTROL_WORKER_BUSY;
    while (worker_busy != 0) {
        long long now = esp_timer_get_time();
        if (now >= (long long)deadline)
            break;
        vTaskDelay(1);
        memw();
        worker_busy = NONZERO_CONTROL_WORKER_BUSY;
    }
    unsigned int sequence = medius_report_record_sequence_event(0);
    RtosQueue *mutex = REPORT_MUTEX;
    if (mutex != NULL)
        xQueueSemaphoreTake(mutex, 0xffffffffU);
    mutex = REWRITE_MUTEX;
    if (mutex != NULL)
        xQueueSemaphoreTake(mutex, 0xffffffffU);
    const volatile unsigned char *live_alternates = CLONE_ALTERNATE_SETTINGS;
    unsigned int previous = live_alternates[interface];
    UsbInterfaceSelection selected;
    for (unsigned int word = 0; word != 8; ++word)
        selected.words[word] = 0;
    selected.words[interface >> 5] = 1U << (interface & 31U);
    memcpy(MEDIUS_CLONE_ALTERNATE_REQUEST_STAGING, CLONE_ALTERNATE_SETTINGS, 256);
    memw();
    if (CLONE_ALTERNATE_PENDING != 0) {
        memw();
        CLONE_ALTERNATE_PENDING = 0;
        for (unsigned int index = 0; index != 256; ++index) {
            if (live_alternates[index] != 0) {
                unsigned int word = selected.words[index >> 5];
                MEDIUS_CLONE_ALTERNATE_REQUEST_STAGING[index] = 0;
                selected.words[index >> 5] = word | (1U << (index & 31U));
            }
        }
        usb_clone_reset_transfer_accounting();
    }
    MEDIUS_CLONE_ALTERNATE_REQUEST_STAGING[interface] = alternate;
    usb_clone_apply_alternate_changes(&selected, MEDIUS_CLONE_ALTERNATE_REQUEST_STAGING);
    mutex = REWRITE_MUTEX;
    if (mutex != NULL)
        xQueueGenericSend(mutex, NULL, 0, 0);
    mutex = REPORT_MUTEX;
    if (mutex != NULL)
        xQueueGenericSend(mutex, NULL, 0, 0);
    unsigned int logged_at = esp_log_timestamp();
    esp_log_write(3, "usbdev", "I (%lu) %s: intf %u alt %u -> %u\n",
        logged_at, "usbdev", interface, previous, (unsigned int)alternate);
    unsigned short pair = (unsigned short)(interface | ((unsigned int)alternate << 8));
    medius_out_enqueue_control_message(0x1f, &pair, 2, generation, sequence);
    return active;
}

/* Native entry: 0x40393484. */
/* Original function-byte SHA-256:
 * 4d81476c66f8ac720e94396116fff1c36703593420a2383127547982abc7fc5d. */
/*
 * Reset transfer accounting without stopping the hardware. Rebase all ten OUT
 * slots through the reviewed helper, then under the OUT spinlock discard all
 * pending OUT queue entries. Release that lock before entering the report/credit
 * spinlock. Publish queues-dirty1; for all six secondary slots clear stalled
 * then stall-pending BYTEs; for all six primary slots clear submit-blocked then
 * service-active BYTEs. Each published BYTE store retains its own MEMW fence.
 * Return no value. Ignore lock-entry results, do not nest these two locks, and
 * leave payloads, queued IN entries and hardware endpoint state untouched here.
 */
void usb_clone_reset_transfer_accounting(void)
{
    medius_out_rebase_accounting();
    xPortEnterCriticalTimeout(DEVICE_OUT_LOCK, -1);
    medius_out_filter_pending(1);
    vPortExitCritical(DEVICE_OUT_LOCK);
    xPortEnterCriticalTimeout(&CREDIT_LOCK, -1);
    memw();
    REPORT_QUEUES_DIRTY = 1;
    for (unsigned int slot = 0; slot != 6; ++slot) {
        memw();
        REPORT_SECONDARY_STALLED[slot] = 0;
        memw();
        REPORT_SECONDARY_STALL_PENDING[slot] = 0;
    }
    for (unsigned int slot = 0; slot != 6; ++slot) {
        memw();
        REPORT_SUBMIT_BLOCKED_WRITABLE[slot] = 0;
        memw();
        REPORT_SERVICE_ACTIVE[slot] = 0;
    }
    vPortExitCritical(&CREDIT_LOCK);
}
