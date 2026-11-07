/* Medius v3.4.7 device: recovered special primary-report buffering. */

#include "../include/types.h"

/* Native entry: 0x420334c4. */
/* Original function-byte SHA-256:
 * 9ad9857c921d0ed994c10997d2ca707c8ae9657e6259afd0b5eb4fe4ba0c2979. */

/*
 * endpoint: low byte is canonicalized; report/length: borrowed readable span.
 * Returns no value. Requires fast mode and configured bus 0. Nonempty input
 * must pass sequence admission using report[0]. Under the credit lock, scan one
 * cached signed interface count and use ONLY the first canonical endpoint match.
 * Separately fence/test submit-blocked, interface-blocked and service-active.
 * Strip the first byte, copy min(length-1,64) when length >= 2, else copy zero
 * bytes from the wrapping32-bit address report+1, even for an empty input.
 * Publish buffered length, clock LOW then HIGH without fences, then fence/set
 * service-active and service that interface with force=0 while still locked.
 * Ignore lock status, always unlock; no allocation, USB delivery result or
 * additional count/bounds repair is provided here.
 */
void report_buffer_primary(unsigned int endpoint,unsigned char *report,unsigned short length)
{
    memw();
    if (REPORT_FAST_ENABLED == 0 || !usb_device_is_configured(0))
        return;
    unsigned int canonical = endpoint_canonicalize(endpoint & 255U);
    if (length != 0 && report_sequence_allowed(canonical,
            ((const volatile unsigned char *)report)[0]) == 0)
        return;
    xPortEnterCriticalTimeout(&CREDIT_LOCK,0xffffffffU);
    int interface_count = CREDIT_INTERFACES.count;
    for (int interface_index = 0; interface_index < interface_count; ++interface_index) {
        unsigned char mapped_endpoint = *(const volatile unsigned char *)(
            (unsigned int)CREDIT_INTERFACES.endpoint + (unsigned int)interface_index);
        if (mapped_endpoint != canonical)
            continue;
        memw();
        if (REPORT_SUBMIT_BLOCKED[interface_index] != 0)
            break;
        memw();
        if (REPORT_INTERFACE_BLOCKED[interface_index] != 0)
            break;
        memw();
        if (REPORT_SERVICE_ACTIVE[interface_index] != 0)
            break;
        unsigned int copy_length = length < 2 ? 0U : length - 1U;
        if (copy_length > 64)
            copy_length = 64;
        memcpy(REPORT_BUFFERED_STORAGE + (unsigned short)interface_index * 64U,
            (const void *)((unsigned int)report + 1U),copy_length);
        REPORT_BUFFERED_LENGTH[interface_index] = copy_length;
        unsigned long long now = esp_timer_get_time();
        REPORT_LAST_INPUT[interface_index].low = (unsigned int)now;
        REPORT_LAST_INPUT[interface_index].high = (unsigned int)(now >> 32);
        memw();
        REPORT_SERVICE_ACTIVE[interface_index] = 1;
        report_service_interface(interface_index,0);
        break;
    }
    vPortExitCritical(&CREDIT_LOCK);
}
