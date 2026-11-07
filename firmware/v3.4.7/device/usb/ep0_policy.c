/* Medius v3.4.7 device — EP0 policy routing and recipient normalization. */
#include "../include/types.h"

/* Native entry: 0x4037eed0. */
/* Original function-byte SHA-256:
 * 2775dd9071909fffd3d626d01a30e7381597a55520703b20033c8c4f060ad9d5. */
/*
 * Read one policy BYTE at the full 32-bit offset. Values 1 and 4..6 retain the
 * supplied default route; value3 selects route4; every other BYTE selects
 * route1. No offset mask/range check, global-mode read, MEMW or side effect.
 * The native address addition wraps; caller supplies readable policy storage.
 */
unsigned int medius_ep0_policy_route_or_default(
    const volatile MediusEp0RequestPolicy *policy, unsigned int offset,
    unsigned int default_route)
{
    unsigned char mode = *(const volatile unsigned char *)((unsigned int)policy + offset);
    if (mode == 1 || (unsigned char)(mode - 4U) <= 2U) return default_route;
    return mode == 3 ? 4U : 1U;
}

/* Native entry: 0x4037eef4. */
/* Original function-byte SHA-256:
 * eff47d1d5186a44cf9e5d221d05e7c3bf327b220cb5cafbbed918728dae0df69. */
/*
 * Resolve this standard request's noncanonical-length policy. Nonzero length
 * reads only the full-offset fallback BYTE: 2->route1,3->4,4->6,others->0.
 * A zero length first checks GET_STATUS for the selected recipient (0 device,
 * 1 interface, every other value endpoint), GET_CONFIGURATION/device,
 * GET_INTERFACE/interface, or the generic zero-length request policy.
 *
 * For a primary policy of3, read global zero-length-IN mode: a value other than
 * 3 returns route4. With global3, GET_STATUS proceeds to its fallback BYTE;
 * GET_INTERFACE/interface returns0; GET_CONFIGURATION/device and generic
 * GET_CONFIGURATION return6 only if device short-length policy==4. Primary0
 * follows those same neutral paths without reading global mode. Other primary
 * values map4->6,2->1,all others->0. Generic requests other than8 use neutral0.
 * No request/recipient truncation, fallback-offset clamp, NULL check, MEMW,
 * state write or lock. Length is a full signed WORD at this boundary; the
 * caller sometimes sign-extends wire wLength, and this helper tests only zero.
 */
unsigned int medius_ep0_policy_route_for_length(
    const volatile MediusEp0RequestPolicy *policy, unsigned int request,
    unsigned int recipient, int length, unsigned int fallback_offset)
{
    unsigned char mode;
    if (length != 0) goto fallback;
    if (request == 0) {
        if (recipient == 0) mode = policy->zero_length_status_device;
        else if (recipient == 1) mode = policy->zero_length_status_interface;
        else mode = policy->zero_length_status_endpoint;
        if (mode == 0) goto fallback;
        if (mode == 3) {
            if (policy->zero_length_in_mode != 3) return 4;
            goto fallback;
        }
    } else if (request == 8 && recipient == 0) {
        mode = policy->zero_length_get_configuration;
        if (mode == 0) goto device_short;
        if (mode == 3) {
            if (policy->zero_length_in_mode != 3) return 4;
            goto device_short;
        }
    } else if (request == 10 && recipient == 1) {
        mode = policy->zero_length_get_interface;
        if (mode == 0) return 0;
        if (mode == 3) return policy->zero_length_in_mode != 3 ? 4U : 0U;
    } else {
        mode = policy->zero_length_other_request;
        if (mode == 0) {
            if (request == 8) goto device_short;
            return 0;
        }
        if (mode == 3) {
            if (policy->zero_length_in_mode != 3) return 4;
            if (request == 8) goto device_short;
            return 0;
        }
    }
    if (mode == 4) return 6;
    return (unsigned char)(mode - 2U) <= 1U ? 1U : 0U;

fallback:
    mode = *(const volatile unsigned char *)((unsigned int)policy + fallback_offset);
    if (mode == 4) return 6;
    if (mode == 3) return 4;
    return mode == 2 ? 1U : 0U;
device_short:
    return policy->short_length_device == 4 ? 6U : 0U;
}

/* Native entry: 0x4037efec. */
/* Original function-byte SHA-256:
 * 99711f0ca3c6a0a2bb51b91f102e95138e082f8cbd6ad8dab1138883ca2bafc6. */
/*
 * Refine only incoming route7; other routes return unchanged without reading
 * policy memory. Truncate fallback offset to its low BYTE. For GET_INTERFACE
 * (request10), nonzero length keeps7; zero length uses its interface primary
 * policy for recipient1, otherwise the generic primary. Primary0 keeps7;
 * primary3 returns4 unless global mode==3, which keeps7;4->8,2->1,others->7.
 *
 * For every other request, signed length>=2 keeps7. Length0 consults GET_STATUS
 * interface policy for recipient1, endpoint policy for all other recipients.
 * Primary0, or3 with global3, falls through to the indexed fallback; primary3
 * with other global mode returns4,4->8,2->1,others->7. Length1 or negative
 * signed lengths go directly to fallback. Fallback2->1,3->4,4->8,others->7.
 * No MEMW, validation, state write, lock or request/recipient normalization.
 */
unsigned int medius_ep0_policy_refine_unavailable_route(unsigned int route,
    const volatile MediusEp0RequestPolicy *policy, unsigned int request,
    unsigned int recipient, int length, unsigned int fallback_offset)
{
    if (route != 7U) return route;
    unsigned char mode;
    if (request == 10) {
        if (length != 0) return 7;
        mode = recipient == 1 ? policy->zero_length_get_interface
                              : policy->zero_length_other_request;
        if (mode == 0) return 7;
        if (mode == 3) return policy->zero_length_in_mode == 3 ? 7U : 4U;
        if (mode == 4) return 8;
        return (unsigned char)(mode - 2U) <= 1U ? 1U : 7U;
    }
    if (length >= 2) return 7;
    if (length == 0) {
        mode = recipient == 1 ? policy->zero_length_status_interface
                              : policy->zero_length_status_endpoint;
        if (mode != 0) {
            if (mode == 3) {
                if (policy->zero_length_in_mode != 3) return 4;
            } else {
                if (mode == 4) return 8;
                return (unsigned char)(mode - 2U) <= 1U ? 1U : 7U;
            }
        }
    }
    mode = ((const volatile unsigned char *)policy)[(unsigned char)fallback_offset];
    if (mode == 4) return 8;
    if (mode == 3) return 4;
    return mode == 2 ? 1U : 7U;
}

/* Native entry: 0x40396108. */
/* Original function-byte SHA-256:
 * c88f1785b4cb8542c299f0dbc2ab827f6d63457ec694718abff9d00e2bd0d59d. */
/*
 * Derive the effective USB recipient from setup->bmRequestType. Begin with
 * low5 bits. Only for standard type0 and requests5/8/9, read policy byte6;
 * exact value1 forces recipient0 and returns before the reserved-bit rules.
 * Otherwise, if recipient bits2..4 are nonzero, read policy byte2; exact2 then
 * reads byte3, whose exact1 selects the low2 recipient bits. Retain the initial
 * low5 bits on every other path. Bus is unused; length/value/index/direction
 * do not affect admission. No MEMW, setup mutation, pointer check or lock.
 */
unsigned char medius_ep0_effective_recipient(unsigned int unused_bus,
                                            const volatile MediusUsbSetupPacket *setup)
{
    unsigned char request_type = setup->request_type;
    unsigned char recipient = request_type & 0x1fU;
    if ((request_type & 0x60U) == 0) {
        unsigned char request = setup->request;
        if ((unsigned char)(request - 8U) <= 1U || request == 5) {
            if (MEDIUS_EP0_REQUEST_POLICY->standard_device_recipient == 1) return 0;
        }
    }
    if ((request_type & 0x1cU) != 0 &&
        MEDIUS_EP0_REQUEST_POLICY->reserved_recipient_mode == 2 &&
        MEDIUS_EP0_REQUEST_POLICY->reserved_recipient_action == 1)
        recipient = request_type & 3U;
    return recipient;
}
