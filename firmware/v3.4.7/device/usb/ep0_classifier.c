/* Medius v3.4.7 device — standard USB control-request classification. */
#include "../include/types.h"

/* Inline reconstruction utilities for native inlined policy tests. These are
 * source helpers, not additional firmware function identities. */
static __inline__ __attribute__((always_inline))
unsigned char medius_ep0_policy_byte(const volatile MediusEp0RequestPolicy *policy,
                                     unsigned int offset)
{
    return *(const volatile unsigned char *)((unsigned int)policy + offset);
}
static __inline__ __attribute__((always_inline))
bool medius_ep0_mode_keeps_route(unsigned char mode)
{
    return mode == 1 || (unsigned char)(mode - 4U) <= 2U;
}
static __inline__ __attribute__((always_inline))
unsigned int medius_ep0_mode_route(unsigned char mode, unsigned int default_route)
{
    return medius_ep0_mode_keeps_route(mode) ? default_route : mode == 3 ? 4U : 1U;
}

/* Native entry: 0x4037bd98. */
/* Original function-byte SHA-256:
 * 0b04173ac75ae752804c46c978c7e01e28f3cafdc8d9d623ad34745745c8b61f. */
/*
 * Classify a USB SETUP request into this image's native route numbers. Reserved
 * request type0x60 returns1; class/vendor types return0 before reading context
 * or the remaining setup bytes. For standard requests, load HIGH value/index/
 * length bytes, then LOW value/index/length bytes, then request BYTE. Cache the
 * context policy pointer for the entire invocation, including delegated calls.
 *
 * Requests0/6/8/10/12 normally require IN;1/3/5/7/9/11 require OUT. Reserved
 * recipient bits and recipient3 use distinct policy controls; forced-device
 * handling for5/8/9 bypasses recipient checks. SET_DESCRIPTOR's special gates
 * run before direction handling. Wrong direction may stall/consume, fall back,
 * or reach the special IN-request/OUT-length rule. A nonempty OUT request other
 * than SET_ADDRESS can be retried recursively after copying6 setup bytes and
 * storing a zero HALFWORD length; policy43==2 rejects before that copy. The
 * retry never changes the caller's setup, and normally terminates after one
 * level. Feature SET endpoint-halt can promote a successful retry to route3.
 *
 * Device/interface/endpoint branches retain the linked request whitelist,
 * descriptor-presence calls, configuration/alternate admission, exact policy
 * offsets and reply-length modes. Only context callbacks interface_exists and
 * endpoint_active are called indirectly here; other presence tests call their
 * fixed native entries. Context masks and flags are read only on their native
 * paths, except the missing-endpoint mask intentionally loads before rejecting
 * an unsupported small request. Missing targets and oversize replies use the
 * separately reviewed policy helpers, including fresh policy reads after an
 * initial mode test. Route results remain full WORDs, not a guessed enum.
 *
 * No explicit MEMW, logging, hardware access, lock, payload allocation or reply
 * transmission. Descriptor callbacks read shared clone state independently;
 * they do not establish a coherent snapshot. Raw previous-stall BYTE indexes
 * SET_DESCRIPTOR policy at wrapping offset57-byte without normalization. Policy
 * storage, setup, context and installed callbacks must remain valid throughout.
 */
unsigned int medius_ep0_classify_standard_request(
    const volatile MediusUsbSetupPacket *setup, MediusEp0PolicyContext *context)
{
    unsigned char request_type = setup->request_type;
    unsigned int type = request_type & 0x60U;
    if (type == 0x60U) return 1;
    if (type != 0) return 0;
    unsigned int value_high = setup->bytes[3];
    unsigned int index_high = setup->bytes[5];
    unsigned int length_high = setup->bytes[7];
    unsigned int value_low = setup->bytes[2];
    unsigned int index_low = setup->bytes[4];
    unsigned int length_low = setup->bytes[6];
    unsigned int request = setup->request;
    unsigned int value = (value_high << 8) | value_low;
    const volatile MediusEp0RequestPolicy *policy =
        ((volatile MediusEp0PolicyContext *)context)->policy;
    unsigned int index = (index_high << 8) | index_low;
    unsigned int length = (length_high << 8) | length_low;
    unsigned int recipient = request_type & 0x1fU;
    unsigned int direction_rule; /* 0 OUT, 0x80 IN, UINT_MAX unknown request */
    unsigned char mode;
    unsigned char recipient_mode;
    unsigned int policy_offset;
    unsigned int route;

    if (request <= 12U && ((1U << request) & 0xaaaU) != 0) direction_rule = 0;
    else if (request <= 12U && ((1U << request) & 0x1541U) != 0) direction_rule = 0x80U;
    else direction_rule = 0xffffffffU;
    if (request == 5 || request == 8 || request == 9) {
        if (policy->standard_device_recipient == 1) {
            recipient = 0;
            goto direction_check;
        }
    }
    if ((request_type & 0x1cU) != 0) {
        recipient_mode = policy->reserved_recipient_mode;
        if (recipient_mode == 2) {
            unsigned char action = policy->reserved_recipient_action;
            if (action == 1) {
                recipient = request_type & 3U;
                if (recipient == 3) goto invalid_out_recipient;
            } else if (recipient >= 3U) goto invalid_recipient_loaded;
        } else if (recipient >= 3U) goto invalid_recipient_loaded;
    } else if (recipient >= 3U) {
        if (request == 0) goto invalid_status_recipient;
        recipient_mode = policy->reserved_recipient_mode;
        goto invalid_recipient_loaded;
    }
    if (request == 7) goto set_descriptor_policy;
    if (direction_rule == 0xffffffffU) goto unknown_request_policy;
    goto direction_check;

invalid_recipient_loaded:
    if (request == 0) goto invalid_status_recipient;
invalid_recipient_policy:
    if (recipient_mode == 1 ||
        (recipient_mode == 3 && policy->reserved_recipient_action == 1)) {
        if (direction_rule == 0x80U ||
            (direction_rule == 0xffffffffU && (request_type & 0x80U) != 0)) return 2;
    }
    goto invalid_out_recipient;
invalid_status_recipient:
    if (medius_ep0_policy_byte(policy, recipient == 3U ? 2U : 3U) == 3) return 4;
    recipient_mode = policy->reserved_recipient_mode;
    goto invalid_recipient_policy;
invalid_out_recipient:
    if ((request_type & 0x80U) != 0) return 1;
    policy_offset = 4;
    if (length != 0 && policy->invalid_recipient_out_data_mode != 0) policy_offset = 5;
    return medius_ep0_mode_route(medius_ep0_policy_byte(policy, policy_offset), 3);
unknown_request_policy:
    return medius_ep0_mode_route(policy->unknown_request_mode, 3);
set_descriptor_policy:
    if (policy->set_descriptor_gate != 0 && policy->set_descriptor_mode != 0) {
        if ((request_type & 0x80U) == 0 && length != 0 && policy->set_descriptor_out_data_mode != 0)
            policy_offset = 58;
        else
            policy_offset = 57U - ((volatile MediusEp0PolicyContext *)context)->previous_in_stall;
        return medius_ep0_mode_route(medius_ep0_policy_byte(policy, policy_offset), 3);
    }
    goto unknown_request_policy;
direction_check:
    if ((request_type & 0x80U) != direction_rule && policy->zero_length_in_mode != 2) {
        mode = policy->wrong_direction_mode;
        if (mode == 2) return 1;
        if (mode == 3) return 4;
    }
    if (direction_rule == 0x80U && (request_type & 0x80U) == 0 && length != 0) return 2;
    if (direction_rule == 0 && (request_type & 0x80U) == 0 && length != 0 && request != 5) {
        if (policy->out_data_suppression_mode == 2) return 1;
        MediusUsbSetupPacket retry;
        memcpy(&retry, (const void *)setup, 6);
        retry.length = 0;
        route = medius_ep0_classify_standard_request(&retry, context);
        if (request == 3 && recipient == 2 && value == 0 && (index & 0x7fU) != 0 &&
            policy->clear_feature_device_mode == 3)
            return route == 0 ? 3U : route;
        return route;
    }
    if (request == 12) {
        unsigned char configured = ((volatile MediusEp0PolicyContext *)context)->configured;
        mode = configured != 0 ? policy->configured_synch_frame_mode : policy->unconfigured_synch_frame_mode;
        return medius_ep0_mode_route(mode, 2);
    }
    int signed_length = (short)length;
    if (recipient != 0) goto interface_or_endpoint;

    /* Device recipient. */
    switch (request) {
    case 0:
    case 8: {
        unsigned int expected_length = request == 0 ? 2U : 1U;
        if (length == expected_length) return 0;
        if (length < expected_length)
            return medius_ep0_policy_route_for_length(policy, request, 0, signed_length, 13);
        policy_offset = request == 0 ? 15U : 16U;
        mode = medius_ep0_policy_byte(policy, policy_offset);
        if (mode == 5) return 12;
        if (mode == 6) return 2;
        return (unsigned char)(mode - 2U) < 2U
            ? medius_ep0_policy_route_or_default(policy, policy_offset, 0) : 0U;
    }
    case 5:
        return ((volatile MediusEp0PolicyContext *)context)->configured != 0 ? 3U : 0U;
    case 6: {
        unsigned int descriptor_type = value >> 8;
        if ((unsigned char)(descriptor_type - 0x21U) < 3U)
            return medius_ep0_mode_route(policy->device_hid_descriptor_recipient_mode, 2);
        if (descriptor_type == 2) {
            if ((unsigned char)value < ((volatile MediusEp0PolicyContext *)context)->configuration_count) return 0;
            mode = policy->configuration_index_fallback;
            if (mode == 1) return 0;
            return medius_ep0_policy_route_or_default(policy, mode == 0 ? 8U : 9U, 2);
        }
        if ((unsigned short)(descriptor_type - 6U) < 2U ||
            (unsigned char)(descriptor_type - 1U) < 3U) return 0;
        if (descriptor_type == 15 && ((volatile MediusEp0PolicyContext *)context)->bos_present != 0) return 0;
        return medius_ep0_policy_route_or_default(policy, 8, 2);
    }
    case 9:
        if (medius_clone_configuration_value_exists((unsigned char)value) != 0) return 0;
        mode = policy->missing_configuration_mode;
        if (medius_ep0_mode_keeps_route(mode))
            return policy->missing_configuration_followup == 2 ? 3U : 11U;
        return mode == 3 ? 4U : 1U;
    case 10:
        return medius_ep0_mode_route(policy->device_interface_request_mode, 7);
    case 11:
        return medius_ep0_mode_route(policy->device_interface_request_mode, 3);
    case 1:
    case 3:
        if (value == 1) {
            if (((volatile MediusEp0PolicyContext *)context)->remote_wakeup == 0) {
                route = medius_ep0_policy_route_or_default(policy, 40, 0);
                if (route != 0) return route;
            }
            if (index == 0) return 0;
            mode = policy->remote_wakeup_nonzero_index_mode;
            return (unsigned char)(mode - 2U) < 2U
                ? medius_ep0_policy_route_or_default(policy, 41, 0) : 0U;
        }
        if (request == 3 && value == 2) {
            if (policy->clear_feature_device_mode == 3 && policy->set_feature_device_mode == 2) return 3;
            return medius_ep0_mode_route(policy->set_feature_device_mode, 3);
        }
        return medius_ep0_mode_route(request == 1 ? policy->clear_feature_device_mode
                                                 : policy->set_feature_device_mode, 3);
    default:
        return 1;
    }

interface_or_endpoint: ;
    unsigned char configured = ((volatile MediusEp0PolicyContext *)context)->configured;
    unsigned char target = (unsigned char)index;
    if (recipient != 1) goto endpoint_recipient;
    /* Interface recipient. */
    if (configured == 0) {
        if (request == 6) {
            unsigned int descriptor_type = value >> 8;
            if (descriptor_type == 0x22) {
                if (!medius_clone_has_report_descriptor(target)) return 1;
            } else if (descriptor_type != 0x21) return 1;
            return medius_ep0_mode_route(policy->unconfigured_hid_descriptor_mode, 9);
        }
        if (request != 0 && request != 10) return 1;
        if (!medius_clone_interface_exists(target)) return 1;
        route = medius_ep0_mode_route(policy->unconfigured_interface_mode, 7);
        return medius_ep0_policy_refine_unavailable_route(route, policy, request, 1, (int)length, 19);
    }
    switch (request) {
    case 6: {
        unsigned int descriptor_type = value >> 8;
        if (descriptor_type == 0x22) {
            if (medius_clone_has_report_descriptor(target)) return 0;
        } else if (descriptor_type == 0x21) {
            if (medius_clone_has_hid_descriptor(target) != 0) return 0;
        } else return 0;
        return medius_ep0_policy_route_or_default(policy, 8, 2);
    }
    case 1:
        return medius_ep0_mode_route(policy->clear_feature_interface_mode, 3);
    case 3:
        return medius_ep0_mode_route(policy->set_feature_interface_mode, 3);
    case 11:
        if (medius_clone_interface_alternate_exists(target, (unsigned char)value)) {
            if (target >= 16U) return 0;
            unsigned short mask = ((volatile MediusEp0PolicyContext *)context)->set_interface_stall_mask;
            return (mask >> target) & 1U;
        }
        if (!((volatile MediusEp0PolicyContext *)context)->interface_exists(target)) return 1;
        route = medius_ep0_policy_route_or_default(policy, 32, 10);
        if (route != 10) return route;
        return policy->missing_alternate_followup == 2 ? 3U : 10U;
    case 0:
    case 10: {
        policy_offset = request == 0 ? 18U : 21U;
        mode = medius_ep0_policy_byte(policy, policy_offset);
        if ((unsigned char)(mode - 2U) < 2U)
            return medius_ep0_policy_route_or_default(policy, policy_offset, 0);
        if (!medius_clone_interface_exists(target)) {
            if (target < 16U) {
                unsigned short mask = ((volatile MediusEp0PolicyContext *)context)->missing_interface_default_mask;
                route = (mask & (1U << target)) != 0 ? 7U
                    : medius_ep0_policy_route_or_default(policy, 25, 7);
            } else route = medius_ep0_policy_route_or_default(policy, 26, 7);
            return medius_ep0_policy_refine_unavailable_route(route, policy, request, 1, (int)length, 19);
        }
        unsigned int expected_length = request == 0 ? 2U : 1U;
        if (length == expected_length) return 0;
        if (length < expected_length)
            return medius_ep0_policy_route_for_length(policy, request, 1, signed_length, 19);
        policy_offset = request == 0 ? 53U : 54U;
        mode = medius_ep0_policy_byte(policy, policy_offset);
        if ((unsigned char)(mode - 5U) < 2U) return 2;
        return (unsigned char)(mode - 2U) < 2U
            ? medius_ep0_policy_route_or_default(policy, policy_offset, 0) : 0U;
    }
    default:
        return 1;
    }

endpoint_recipient: ;
    unsigned int endpoint_number = target & 0x7fU;
    if (configured == 0) {
        if (endpoint_number != 0) return 1;
        mode = policy->unconfigured_ep0_mode;
        if ((unsigned char)(mode - 2U) < 2U) return mode == 3 ? 4U : 1U;
    } else if (endpoint_number != 0 && medius_clone_endpoint_is_in_active_alternate(target) == 0) {
        if (request == 6)
            return medius_ep0_mode_route(policy->endpoint_get_descriptor_mode, 2);
        if (request >= 7U) goto endpoint_interface_requests;
        unsigned short mask = ((volatile MediusEp0PolicyContext *)context)->endpoint_status_stall_mask;
        unsigned int masked = (mask >> (target & 0xfU)) & 1U;
        if (request == 0) {
            policy_offset = 27;
            if (policy->reverse_endpoint_status_mode != 0) {
                unsigned char reverse_exists = ((volatile MediusEp0PolicyContext *)context)->endpoint_active(target ^ 0x80U);
                if (reverse_exists != 0) policy_offset = 29;
            }
            route = masked != 0 ? 7U : medius_ep0_policy_route_or_default(policy, policy_offset, 7);
            return medius_ep0_policy_refine_unavailable_route(route, policy, 0, 2, (int)length, 23);
        }
        if (request != 1 && request != 3) return 1;
        if (value == 0) return masked != 0 ? 3U : medius_ep0_policy_route_or_default(policy, 28, 3);
        return medius_ep0_policy_route_or_default(policy, request == 1 ? 38U : 39U, 3);
    }
    switch (request) {
    case 6:
        return medius_ep0_mode_route(policy->endpoint_get_descriptor_mode, 2);
    case 0:
        if (length == 2U) return 0;
        if (length < 3U)
            return medius_ep0_policy_route_for_length(policy, request, 2, signed_length, 23);
        mode = policy->long_status_endpoint;
        if ((unsigned char)(mode - 5U) < 2U) return 2;
        return (unsigned char)(mode - 2U) < 2U
            ? medius_ep0_policy_route_or_default(policy, 55, 0) : 0U;
    case 1:
    case 3:
        if (value != 0)
            return medius_ep0_policy_route_or_default(policy, request == 1 ? 38U : 39U, 3);
        if (endpoint_number != 0) return 0;
        policy_offset = request == 1 ? 50U : 51U;
        if (request == 3 && (index & 0x80U) != 0 && policy->set_ep0_in_halt_mode != 0) policy_offset = 52;
        return medius_ep0_policy_route_or_default(policy, policy_offset, 3);
    default:
        break;
    }
endpoint_interface_requests:
    if (request == 10) return medius_ep0_mode_route(policy->standard_device_recipient, 7);
    if (request == 11) return medius_ep0_mode_route(policy->standard_device_recipient, 3);
    return 1;
}
