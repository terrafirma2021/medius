/* Medius v3.4.7 device — alternate-setting report/capture support. */
#include "../include/types.h"

/* Native entry: 0x4202a620. */
/* Original function-byte SHA-256:
 * 4adaaf225424d890bb67cbff3997e65ac380b192aa8cdb310bf2ec6760bd4490. */
/* Recompute report scheduling values from raw descriptor bInterval BYTEs.
 * A nonnegative selected interface is indexed without bounds validation; its
 * interval times 1000 becomes the selected period, else selected period is 0.
 * For all six slots, use interval 1 when absent/zero, store interval*1000, then
 * under the credit lock update the largest power-of-two scale <= interval.
 * Clear frame-number-valid BYTE only when that HALFWORD scale changes.
 *
 * Derive rate as 1000/raw_interval for the selected endpoint, or first nonzero
 * endpoint in a single count snapshot when selection is negative; missing/zero
 * interval gives rate 0. This is the firmware's raw arithmetic, not USB speed
 * dependent bInterval decoding. Mode 1 uses a fresh selected period; mode 2
 * defaults to 1000us or 1000000/min(fresh_rate,1000). Preserve two fenced rate
 * reads: a second read of 0 can reach unsigned division by zero. Other modes
 * give period 0. Publish once and invalidate motion configuration. No timer is
 * started here, and these values do not establish actual scheduling precision.
 */
void report_refresh_poll_timing(int selected_interface)
{
    unsigned int selected_period = 0;
    if (selected_interface >= 0)
        selected_period = (unsigned int)clone_endpoint_interval_byte(
            USB_INTERFACE_ENDPOINTS[selected_interface]) * 1000U;
    memw();
    REPORT_SELECTED_PERIOD_US = selected_period;

    for (unsigned int interface = 0; interface < 6; ++interface) {
        unsigned int interval = 1;
        if ((int)interface < USB_INTERFACE_COUNT) {
            interval = clone_endpoint_interval_byte(
                USB_INTERFACE_ENDPOINTS[interface]);
            if (interval == 0)
                interval = 1;
        }
        REPORT_CONFIGURED_PERIOD_WRITABLE[interface] = interval * 1000U;
        unsigned int scale = 1;
        unsigned int doubled;
        do {
            doubled = (scale * 2U) & 65535U;
            if (doubled > interval)
                break;
            scale = doubled;
        } while (1);
        (void)xPortEnterCriticalTimeout(&CREDIT_LOCK, -1);
        volatile CreditInterfaceQueue *queue = &REPORT_HISTORY_QUEUES[interface];
        if (queue->interval_scale != scale) {
            queue->interval_scale = (unsigned short)scale;
            queue->frame_number_valid = 0;
        }
        vPortExitCritical(&CREDIT_LOCK);
    }

    unsigned int endpoint;
    unsigned int interval = 0;
    if (selected_interface >= 0) {
        endpoint = USB_INTERFACE_ENDPOINTS[selected_interface];
        interval = clone_endpoint_interval_byte(endpoint);
    } else {
        int count = USB_INTERFACE_COUNT;
        for (int index = 0; index < count; ++index) {
            endpoint = USB_INTERFACE_ENDPOINTS[index];
            if (endpoint != 0) {
                interval = clone_endpoint_interval_byte(endpoint);
                break;
            }
        }
    }
    unsigned int rate = interval == 0 ? 0 : xtensa_unsigned_divide(1000U, interval);
    memw();
    REPORT_DESCRIPTOR_RATE_HZ = (unsigned short)rate;
    memw();
    unsigned int mode = REPORT_POLL_PERIOD_MODE;
    unsigned int period = 0;
    if (mode == 1) {
        memw();
        period = REPORT_SELECTED_PERIOD_US;
    } else if (mode == 2) {
        period = 1000;
        memw();
        unsigned int guard_rate = REPORT_REQUESTED_RATE_HZ;
        if (guard_rate != 0) {
            memw();
            unsigned int current_rate = REPORT_REQUESTED_RATE_HZ;
            unsigned int divisor = current_rate < 1000 ? current_rate : 1000;
            period = xtensa_unsigned_divide(1000000U, divisor);
        }
    }
    memw();
    REPORT_EFFECTIVE_PERIOD_US = period;
    motion_configuration_changed();
}
