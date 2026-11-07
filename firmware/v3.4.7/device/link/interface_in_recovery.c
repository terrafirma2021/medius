/* Medius v3.4.7 device — alternate-setting report/capture support. */
#include "../include/types.h"

/* Native entry: 0x40395318. */
/* Original function-byte SHA-256:
 * bd9e6fc88cf79ee618031f32729802f3bbfdfc87cb9a43ea76edb1ca82b7c54f. */
/* Recover an interface submission after endpoint cancellation. Always clear
 * flags_out first; require extra_pending == 1 and nonzero endpoint low nibble.
 * Mark queues dirty, read DIEPTSIZ, then acknowledge DIEPINT bits 0/1. Cache
 * split BYTE and input-state pointer before testing DIEPTSIZ bits19..25 only;
 * the upper packet-count bits do not participate in this native branch.
 *
 * With no packets left, clear the pointer, mark interface completing and clear
 * split. Report flags 2 for split == 2 or current length == 0; mark a nonnull
 * input state dirty, clear extra_pending/window_active, return true.
 * With packets left, clear pointer/split and either mark the state dirty
 * (split == 2 or queued count >= 8), or prepend the saved report with native
 * metadata to record 0. Then clear extra_pending/window_active/short-multiple;
 * return whether the saved split was exactly 2. No local lock, copy-length cap,
 * interface bounds check, controller abort or completion wait is supplied.
 */
bool report_recover_interface_in(unsigned int interface,
    unsigned char *flags_out)
{
    unsigned int queue_address = (unsigned int)(uintptr_t)REPORT_HISTORY_QUEUES +
        interface * 960U;
    volatile CreditInterfaceQueue *queue = (volatile void *)queue_address;
    unsigned char endpoint = USB_INTERFACE_ENDPOINTS[interface];
    *(volatile unsigned char *)flags_out = 0;
    unsigned char pending = queue->extra_pending;
    unsigned int endpoint_number = endpoint & 15U;
    if (pending != 1 || endpoint_number == 0)
        return false;

    memw();
    REPORT_QUEUES_DIRTY = 1;
    volatile Dwc2InEndpointRegisters *registers =
        &DEVICE_DWC2_IN_REGISTERS[endpoint_number];
    memw();
    unsigned int transfer_size = registers->transfer_size;
    memw();
    registers->interrupt_status = 3;
    unsigned char split = REPORT_SUBMIT_SPLIT[interface];
    InputStateView *state = REPORT_SUBMIT_INPUT_STATES[interface];

    if (((transfer_size >> 19) & 127U) == 0) {
        REPORT_SUBMIT_INPUT_STATES[interface] = NULL;
        memw();
        REPORT_INTERFACE_COMPLETING[interface] = 1;
        REPORT_SUBMIT_SPLIT[interface] = 0;
        if (split == 2 || REPORT_SUBMIT_LENGTH[interface] == 0)
            *(volatile unsigned char *)flags_out = 2;
        if (state != NULL)
            input_mark_dirty(state);
        queue->extra_pending = 0;
        queue->window_active = 0;
        return true;
    }

    REPORT_SUBMIT_INPUT_STATES[interface] = NULL;
    REPORT_SUBMIT_SPLIT[interface] = 0;
    if (split == 2 || queue->record_count >= 8) {
        if (state != NULL)
            input_mark_dirty(state);
    } else {
        unsigned int length = REPORT_SUBMIT_LENGTH[interface];
        unsigned int kind = REPORT_SUBMIT_KIND[interface];
        memw();
        unsigned char metadata42 = REPORT_SUBMIT_METADATA42[interface];
        unsigned char special = REPORT_SUBMIT_SPECIAL[interface];
        unsigned int metadata48 = REPORT_SUBMIT_METADATA48[interface];
        unsigned char metadata44 = REPORT_SUBMIT_METADATA44[interface];
        report_insert_record((CreditInterfaceQueue *)queue, 0,
            REPORT_SUBMIT_STORAGE + interface * 64U, length, kind,
            metadata42, metadata44, metadata48, special,
            (unsigned int)(uintptr_t)state, -1);
    }
    queue->extra_pending = 0;
    queue->window_active = 0;
    queue->pending_short_multiple = 0;
    return split == 2;
}
