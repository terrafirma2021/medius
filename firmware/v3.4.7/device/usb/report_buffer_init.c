/* Medius v3.4.7 device — report binding primitives. */
#include "../include/types.h"

/* Native entry: 0x4200d110. */
/* Original function-byte SHA-256:
 * f34248a8d1887ecccc66cd77f6f0398765d4280283928273ead0f195063da7fb. */
/* Initialize six WORDs of the supplied report-buffer record and return it.
 * The leading argument is unused. Store the native control callback, zero
 * WORDs +4/+8/+12, then borrow buffer and store its full-WORD size. Leave the
 * caller-managed interface BYTE +24 and padding untouched. No allocation,
 * buffer clearing, validation, callback invocation, lock or fence occurs.
 */
UsbdInterface *usbd_hid_init_intf(unsigned int unused,
    UsbdInterface *buffer_state, const unsigned char *report_descriptor, unsigned int descriptor_length)
{
    (void)unused;
    volatile UsbdInterface *state = buffer_state;
    state->class_interface_handler = medius_report_buffer_control_boundary;
    state->class_endpoint_handler = NULL;
    state->vendor_handler = NULL;
    state->notify_handler = NULL;
    state->hid_report_descriptor = report_descriptor;
    state->hid_report_descriptor_len = descriptor_length;
    return buffer_state;
}
