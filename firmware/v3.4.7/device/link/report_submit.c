/* Medius v3.4.7 device: recovered report submission to the USB device. */

#include "../include/types.h"

/* Native entry: 0x40377938. */
/* Original function-byte SHA-256:
 * caa542fadbf93d7f5033e65beb34294e8ff80c43bef2d4387604de91f2181b52. */

/*
 * Copies a queued record to the interface TX storage and starts USB IN.
 *
 * interface: configured index; no bounds check is supplied here.
 * record: readable 84-byte report with a valid payload length. Length <= 64 is
 * required for the interface's separate 64-byte buffer; the native byte length
 * is not clamped. Caller supplies serialization and stable record/storage.
 * Returns 1 for a nonnegative USB write result, 0 for a gate or negative result.
 * Acceptance does not establish completed USB delivery.
 *
 * Requires a nonzero mapped endpoint, then separately fences/tests two block
 * bytes. Copies the FIRST length sample. Publishes metadata in native order,
 * including special & (cached_length != 0), so only special's low bit matters.
 * Samples the clock, fences/stores LOW, rereads record length and endpoint,
 * then fences/stores HIGH. Clears the interface byte at 0x3fcc1064 and starts
 * bus-0 IN using the fresh length. Length samples are deliberately independent.
 *
 * A failed start clears only metadata50; other metadata/time/clear side effects
 * remain. Five explicit fences, no local lock, allocation or queue removal.
 * Global views retain the native addresses/strides without assuming disjoint
 * arrays for arbitrary out-of-range interface values.
 */
int report_submit_record(unsigned int interface,
    const CreditInterfaceRecord *record)
{
    const volatile CreditInterfaceRecord *record_view = record;
    const volatile unsigned char *endpoint_address =
        (const volatile unsigned char *)((unsigned int)&CREDIT_INTERFACES + interface);
    if (*endpoint_address == 0)
        return 0;
    memw();
    if (REPORT_SUBMIT_BLOCKED[interface] != 0)
        return 0;
    memw();
    if (REPORT_INTERFACE_BLOCKED[interface] != 0)
        return 0;

    unsigned char *transmit_buffer = (unsigned char *)
        ((unsigned int)REPORT_SUBMIT_STORAGE + interface * 64U);
    unsigned int copy_length = record_view->length;
    memcpy(transmit_buffer,record,copy_length);
    unsigned int metadata42 = record_view->metadata42;
    memw();
    REPORT_SUBMIT_METADATA42[interface] = metadata42;
    unsigned int kind = record_view->kind;
    unsigned int metadata_length = record_view->length;
    unsigned int special = record_view->special;
    REPORT_SUBMIT_KIND[interface] = kind;
    unsigned int metadata44 = record_view->metadata44;
    REPORT_SUBMIT_METADATA44[interface] = metadata44;
    unsigned int metadata48 = record_view->metadata48;
    REPORT_SUBMIT_METADATA48[interface] = metadata48;
    unsigned int metadata50 = record_view->metadata50;
    REPORT_SUBMIT_SPECIAL[interface] = special;
    REPORT_SUBMIT_METADATA50[interface] = metadata50;
    REPORT_SUBMIT_LENGTH[interface] = metadata_length;
    REPORT_SUBMIT_SPLIT[interface] = special & (metadata_length != 0);

    unsigned long long submitted_at_us = esp_timer_get_time();
    memw();
    REPORT_SUBMIT_TIME[interface].low = (unsigned int)submitted_at_us;
    unsigned int write_length = record_view->length;
    unsigned int endpoint = *endpoint_address;
    memw();
    REPORT_SUBMIT_TIME[interface].high = (unsigned int)(submitted_at_us >> 32);
    REPORT_SUBMIT_CLEAR[interface] = 0;
    if (usb_device_write_aligned(0,endpoint,transmit_buffer,write_length) >= 0)
        return 1;
    REPORT_SUBMIT_METADATA50[interface] = 0;
    return 0;
}
