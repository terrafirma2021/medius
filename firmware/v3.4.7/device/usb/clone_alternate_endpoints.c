/* Medius v3.4.7 device — alternate endpoint transition/recovery. */
#include "../include/types.h"

/* Native entry: 0x40391bc0. */
/* Original function-byte SHA-256:
 * 4a654223061e11a01c97621cb8c14f8a2210cb043f572d0cd42dca5ea014f975. */
/* Walk the live configuration for one full-width interface/alternate pair.
 * phase 0 closes endpoints and reconciles OUT accounting; phase 1 opens them;
 * every other phase clears secondary-IN stall flags for matching bindings.
 * Control endpoints also open/close their opposite direction. USB and lock
 * results are ignored, and there is no rollback or controller-completion wait.
 *
 * Read descriptor length/type before rejecting malformed records. Short
 * interface records retain the previous match. Reload the shared configuration
 * pointer each iteration and its HALFWORD length after each record/callback;
 * advance the cursor modulo 65536. Interface/alternate inputs are not truncated.
 * The two copies retain the descriptor attributes sampled between them and
 * the address sampled after the second copy; later branches reload as native.
 */
void medius_clone_apply_interface_alternate_endpoints(
    unsigned int interface_number, unsigned int alternate_setting,
    unsigned int phase)
{
    unsigned int configuration_length = QUERY_CONFIGURATION_LENGTH;
    unsigned short offset = 0;
    bool matching_interface = false;

    if (configuration_length < 2)
        return;

    do {
        const volatile unsigned char *raw = QUERY_CONFIGURATION + offset;
        unsigned int descriptor_length = raw[0];
        unsigned int descriptor_type = raw[1];

        if (descriptor_length < 2 ||
            offset + descriptor_length > configuration_length)
            return;

        if (descriptor_type == 4 && descriptor_length >= 9) {
            matching_interface = false;
            if (raw[2] == interface_number)
                matching_interface = raw[3] == alternate_setting;
        } else if (descriptor_type == 5 && descriptor_length >= 7 &&
                   matching_interface) {
            MediusUsbEndpointDescriptor descriptor, opposite;
            volatile MediusUsbEndpointDescriptor *current = &descriptor;
            memcpy(&descriptor, (const void *)raw, 7);
            unsigned char attributes = current->attributes;
            memcpy(&opposite, &descriptor, 7);
            unsigned char endpoint = current->address;
            opposite.address = endpoint ^ 0x80U;
            unsigned int transfer_type = attributes & 3U;

            if (phase == 0) {
                (void)medius_usbd_close_endpoint(0, endpoint);
                if (transfer_type == 0) {
                    (void)medius_usbd_close_endpoint(0, opposite.address);
                } else {
                    endpoint = current->address;
                    if ((endpoint & 0x80U) == 0) {
                        (void)xPortInIsrContext();
                        (void)xPortEnterCriticalTimeout(DEVICE_OUT_LOCK, -1);
                        /* EP0 still takes/releases the lock but is not searched. */
                        if (endpoint != 0) {
                            for (unsigned int index = 0; index < 10; ++index) {
                                if (DEVICE_OUT_ENDPOINTS[index].endpoint != endpoint)
                                    continue;
                                DEVICE_OUT_ENDPOINTS[index].armed = 0;
                                volatile DeviceOutEndpoint *state =
                                    &DEVICE_OUT_ENDPOINTS[(unsigned short)index];
                                unsigned char rebase = state->rebase_sequence;
                                unsigned char produced = state->produced;
                                unsigned char acknowledged = state->acknowledged;
                                unsigned char sent = state->sent_sequence;
                                unsigned char debt = rebase + produced - acknowledged - sent;
                                state->sequence_and_debt = sent | ((unsigned int)debt << 8);
                                state->reset_flag14 = rebase != sent || debt != 0;
                                state->reset_flag13 = 0;
                                break;
                            }
                        }
                        (void)xPortInIsrContext();
                        vPortExitCritical(DEVICE_OUT_LOCK);
                    }
                }
            } else if (phase == 1) {
                (void)medius_usbd_open_endpoint(0, &descriptor);
                if (transfer_type == 0)
                    (void)medius_usbd_open_endpoint(0, &opposite);
            } else if ((endpoint & 0x80U) != 0) {
                (void)xPortEnterCriticalTimeout(&CREDIT_LOCK, -1);
                endpoint = current->address;
                int binding_count = CREDIT_BINDINGS.count;
                for (int index = 0; index < binding_count; ++index) {
                    if (CREDIT_BINDING_RECORDS[index].endpoint != endpoint)
                        continue;
                    if ((endpoint & 0x80U) != 0) {
                        unsigned int slot = CREDIT_BINDING_RECORDS[index].queue_slot;
                        if (slot < 6) {
                            memw();
                            REPORT_SECONDARY_STALLED[slot] = 0;
                            memw();
                            REPORT_SECONDARY_STALL_PENDING[slot] = 0;
                        }
                    }
                    break;
                }
                vPortExitCritical(&CREDIT_LOCK);
            }
        }

        offset = (unsigned short)(offset + descriptor_length);
        configuration_length = QUERY_CONFIGURATION_LENGTH;
    } while ((unsigned int)offset + 1 < configuration_length);
}
