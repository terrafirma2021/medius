/* Medius v3.4.7 device — Qualifier and other-speed descriptor policy. */
#include "../include/types.h"

/* Native entry: 0x40395180. */
/* Original function-byte SHA-256:
 * 5190f2361c4ff8dca130c21bd6d23295f5f3354525e6304994e20e887493d179. */
/*
 * Apply the two-record device-qualifier/other-speed descriptor policy blob.
 * The caller selects first for descriptor type6, second for type7. bus is a WORD;
 * setup is borrowed and only its low wValue BYTE is inspected here. use_second
 * selects the second record for any nonzero WORD, otherwise the first. data and
 * length point to caller-owned pointer/WORD slots. Returns 0 for a local copy,
 * the relay's signed result for forwarding, or -1 for invalid/rejected policy.
 *
 * Blob length is an unsigned HALFWORD. The first BYTE-length must be<=10;
 * the second little-endian length is read HIGH BYTE then LOW BYTE, must be<=1024,
 * and total length must equal first_length+second_length+5. Both records are
 * parsed before selection. Action0 copies that record without a wLength/capacity
 * clamp; action2 clears/consumes the stall then fails. Action3, or any nonzero
 * low wValue BYTE, relays only if bus0 is configured. ActionFF consults the
 * unknown-descriptor mode:3 clears/consumes then rereads it,1/4 relay regardless
 * of configured state. Other actions reject. No lock or generation snapshot
 * protects the blob/policy reads; callers supply valid storage and serialization.
 */
int medius_ep0_apply_descriptor_policy(unsigned int bus,
    const MediusUsbSetupPacket *setup, unsigned char **data, unsigned int *length,
    unsigned int use_second)
{
    const volatile MediusEp0DescriptorPolicyStorage *storage = MEDIUS_EP0_DESCRIPTOR_POLICY;
    unsigned int total = storage->length;
    if (total < 2)
        return -1;
    const volatile unsigned char *bytes = storage->bytes;
    unsigned int first_length = bytes[1];
    if (first_length > 10 || first_length + 5U > total)
        return -1;
    unsigned int second_high = bytes[first_length + 4U];
    unsigned int second_low = bytes[first_length + 3U];
    unsigned int second_length = second_low | (second_high << 8);
    unsigned int first_action = bytes[0];
    MediusEp0DescriptorPolicyReply first = {
        (unsigned char)first_action, 0, (unsigned short)first_length,
        (const unsigned char *)(bytes + 2)
    };
    if (second_length > 1024 || total != first_length + second_length + 5U)
        return -1;
    unsigned int second_action = bytes[first_length + 2U];
    MediusEp0DescriptorPolicyReply second = {
        (unsigned char)second_action, 0, (unsigned short)second_length,
        (const unsigned char *)(bytes + first_length + 5U)
    };
    const MediusEp0DescriptorPolicyReply *reply = use_second != 0 ? &second : &first;
    if (setup->bytes[2] != 0 || reply->action == 3) {
        if (!usb_device_is_configured(0))
            return -1;
        return medius_ep0_relay_request(bus, setup, data, length);
    }
    if (reply->action == 0) {
        unsigned int copied = reply->length;
        memcpy(*data, reply->payload, copied);
        *length = copied;
        return 0;
    }
    if (reply->action == 2) {
        medius_ep0_clear_stall_and_consume((unsigned char)bus);
        return -1;
    }
    if (reply->action == 255) {
        unsigned int mode = MEDIUS_EP0_REQUEST_POLICY->unknown_descriptor_mode;
        if (mode == 3) {
            medius_ep0_clear_stall_and_consume((unsigned char)bus);
            mode = MEDIUS_EP0_REQUEST_POLICY->unknown_descriptor_mode;
        }
        if (mode == 1 || mode == 4)
            return medius_ep0_relay_request(bus, setup, data, length);
    }
    return -1;
}
