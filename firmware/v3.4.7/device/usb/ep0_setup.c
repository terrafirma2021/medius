/* Medius v3.4.7 device — SETUP policy context and controller dispatch. */
#include "../include/types.h"

/* Native entry: 0x403917c0. */
/* Original function-byte SHA-256:
 * 4fdef1266f234aee4891200cf560d91c1055dc824479b93f50878165f41bc207. */
/*
 * Receive SETUP for the low-byte bus. First cancel a pending host reply and
 * clear the fast report transition gate. Snapshot request type/request and
 * derive recipient with policy byte6's standard5/8/9 device override, then
 * policy2/3 reserved-recipient handling. Retain both device-recipient admission
 * and configuration-descriptor admission across the route resolver call.
 * Capture wValue by reading HIGH then LOW bytes; retain its original LOW as
 * the SET_CONFIGURATION value while the resolver may remap a separate index.
 *
 * Freshly read setup direction, MEMW/publish previous_in, then MEMW/publish
 * stall policy: routes4/5 clear it, other routes use suppressed^1. Select the
 * descriptor pointer mode even if later stalling: configuration GET_DESCRIPTOR
 * uses indexed mode2; device SET_CONFIGURATION uses first-pool mode1; otherwise
 * use mode0. Both mode/index arguments are explicitly zero on that default.
 * OUT length>2048 without suppression, or route1, stalls EP0 OUT then IN.
 * Route4 returns without publishing route/suppression or invoking CherryUSB.
 *
 * Otherwise MEMW/publish low-byte route then MEMW/publish suppression. A nonzero
 * suppression zeros wLength HIGH byte then LOW byte. For routes0/5, device
 * SET_CONFIGURATION records the ORIGINAL low value, then marks a transition
 * only for a nonzero accepted configuration. Endpoint SET_FEATURE(value0) with
 * an IN nonzero endpoint also marks it, using a fresh low wIndex byte. Finally
 * call the ordinary setup handler with the same setup pointer and low-byte bus.
 * No NULL validation, lock, coherent policy snapshot or hardware completion
 * guarantee. Nonstandard requests retain request sentinel0xff for these tests.
 */
void medius_ep0_process_setup(unsigned int bus, volatile MediusUsbSetupPacket *setup)
{
    unsigned char bus_id = (unsigned char)bus;
    medius_ep0_cancel_pending_reply();
    medius_report_set_endpoint_transition_pending(0);
    unsigned char request_type = setup->request_type;
    unsigned char recipient = request_type & 0x1fU;
    unsigned char request;
    const volatile MediusEp0RequestPolicy *policy;
    bool force_device = false;
    bool descriptor_candidate = false;
    if ((request_type & 0x60U) == 0) {
        request = setup->request;
        policy = medius_ep0_get_request_policy();
        bool special_device = request == 5 || (unsigned char)(request - 8U) <= 1U;
        descriptor_candidate = request == 6;
        if (special_device && policy->standard_device_recipient == 1) force_device = true;
    } else {
        policy = medius_ep0_get_request_policy();
        request = 0xffU;
    }
    bool device_recipient;
    if (force_device) {
        recipient = 0;
        device_recipient = true;
        descriptor_candidate = false;
    } else {
        if ((request_type & 0x1cU) != 0 && policy->reserved_recipient_mode == 2 &&
            policy->reserved_recipient_action == 1)
            recipient = request_type & 3U;
        device_recipient = recipient == 0;
        descriptor_candidate = descriptor_candidate && device_recipient;
    }
    unsigned char value_high = setup->bytes[3];
    unsigned char original_value_low = setup->bytes[2];
    unsigned int value = ((unsigned int)value_high << 8) | original_value_low;
    unsigned char selected_index = original_value_low;
    unsigned char suppressed;
    unsigned int route = medius_ep0_resolve_setup_policy(setup, &suppressed, &selected_index);
    unsigned char previous_in = setup->request_type >> 7;
    memw();
    MEDIUS_EP0_REQUEST_STATE->previous_in = previous_in;
    unsigned char stall = (route - 4U) < 2U ? 0 : (unsigned char)(suppressed ^ 1U);
    memw();
    MEDIUS_EP0_REQUEST_STATE->stall = stall;
    if (descriptor_candidate && (value >> 8) == 2U)
        medius_clone_set_descriptor_selection(2, selected_index);
    else if (!descriptor_candidate && request == 9 && device_recipient)
        medius_clone_set_descriptor_selection(1, 0);
    else
        medius_clone_set_descriptor_selection(0, 0);
    bool oversized_out = false;
    if ((setup->request_type & 0x80U) == 0) {
        unsigned int high = setup->bytes[7];
        unsigned int low = setup->bytes[6];
        oversized_out = ((high << 8) | low) > 2048U && suppressed == 0;
    }
    if (oversized_out || route == 1) {
        (void)usb_device_set_stall(bus_id, 0);
        (void)usb_device_set_stall(bus_id, 0x80U);
        return;
    }
    if (route == 4) return;
    memw();
    MEDIUS_EP0_REQUEST_STATE->route = (unsigned char)route;
    memw();
    MEDIUS_EP0_REQUEST_STATE->out_payload_suppressed = suppressed;
    if (suppressed != 0) {
        setup->bytes[7] = 0;
        setup->bytes[6] = 0;
    }
    if (route == 0 || route == 5) {
        if (request == 9 && device_recipient) {
            medius_clone_note_set_configuration(original_value_low);
            if (original_value_low != 0 && medius_clone_configuration_value_exists(original_value_low) != 0)
                medius_report_set_endpoint_transition_pending(1);
        } else if (recipient == 2 && request == 3 && value == 0) {
            unsigned char endpoint = setup->bytes[4];
            if ((endpoint & 0x80U) != 0 && (endpoint & 0x0fU) != 0)
                medius_report_set_endpoint_transition_pending(1);
        }
    }
    usbd_event_ep0_setup_complete_handler(bus_id, (const void *)setup);
}

/* Native entry: 0x403919a8. */
/* Original function-byte SHA-256:
 * 8c6685d624deea3a1adc74caafd28a1131c0f3a51febf059b91905054908ee52. */
/*
 * Set suppression output0 before reading attachment. Detached returns route0
 * without touching the caller's configuration index. Otherwise construct the
 * 44-byte policy context in native call order: policy pointer, three masks,
 * configured(bus0), configuration count, remote-wakeup, BOS presence and six
 * descriptor predicates. MEMW/read previous direction, then conditionally
 * MEMW/read prior stall; retain that raw byte in the context. These independent
 * reads/calls are not a coherent cross-core snapshot.
 *
 * Suppress OUT data only for standard OUT request types<0x20, odd requests<12,
 * nonzero wire length and requests other than5/7. Device-forced request9 bypasses
 * recipient validation; other recipients must resolve to0..2 under policy2/3.
 * Suppression is exactly (policy43==3). Publish it before reading/remapping the
 * caller's index: an index>=captured count becomes0 only when policy9==1.
 * Call the standard classifier with this setup and context; that callee remains
 * a separate native entry, rather than being duplicated into this wrapper.
 *
 * Only standard IN, zero length (LOW then HIGH byte tests), and routes0/3/7
 * enter the final global policy. Resolve recipient again from fresh request
 * bytes and the context's possibly changed policy pointer. A relevant request
 * override permits global fallback only for primary0, or primary3 with global3.
 * The global mode is read AGAIN after that test:2->route1,3->(old0?5:4), and
 * 4->route6 only for GET_DESCRIPTOR with old route0. Other modes retain route.
 * No output-pointer checks, lock, bus selection, setup mutation or rollback.
 */
unsigned int medius_ep0_resolve_setup_policy(const volatile MediusUsbSetupPacket *setup,
    unsigned char *suppress_out_payload, unsigned char *configuration_index)
{
    *suppress_out_payload = 0;
    if (medius_clone_get_attached() == 0) return 0;
    MediusEp0PolicyContext context;
    context.policy = medius_ep0_get_request_policy();
    context.missing_interface_default_mask = medius_ep0_get_missing_interface_default_mask();
    context.endpoint_status_stall_mask = medius_ep0_get_endpoint_status_stall_mask();
    context.set_interface_stall_mask = medius_ep0_get_set_interface_stall_mask();
    context.configured = usb_device_is_configured(0);
    context.configuration_count = medius_clone_get_configuration_count();
    context.remote_wakeup = medius_clone_configuration_has_remote_wakeup();
    context.bos_present = medius_clone_has_bos_descriptor();
    context.configuration_exists = medius_clone_configuration_value_exists;
    context.alternate_exists = medius_clone_interface_alternate_exists;
    context.interface_exists = medius_clone_interface_exists;
    context.endpoint_active = medius_clone_endpoint_is_in_active_alternate;
    context.report_descriptor_exists = medius_clone_has_report_descriptor;
    context.hid_descriptor_exists = medius_clone_has_hid_descriptor;
    memw();
    unsigned char previous_in = MEDIUS_EP0_REQUEST_STATE->previous_in;
    unsigned char previous_stall = 0;
    if (previous_in != 0) {
        memw();
        previous_stall = MEDIUS_EP0_REQUEST_STATE->stall;
    }
    unsigned char request_type = setup->request_type;
    context.previous_in_stall = previous_stall;
    unsigned char suppress = 0;
    const volatile MediusEp0RequestPolicy *policy = context.policy;
    if (request_type < 0x20U) {
        unsigned char request = setup->request;
        if (request < 12U && ((1U << request) & 0xaaaU) != 0) {
            unsigned int high = setup->bytes[7];
            unsigned int low = setup->bytes[6];
            if (((high << 8) | low) != 0 && (request & 0xfdU) != 5U) {
                bool admitted = request == 9 && policy->standard_device_recipient == 1;
                if (!admitted) {
                    unsigned char recipient = request_type;
                    if ((request_type & 0x1cU) != 0) {
                        if (policy->reserved_recipient_mode != 2 || policy->reserved_recipient_action != 1)
                            goto suppression_done;
                        recipient = request_type & 3U;
                    }
                    admitted = recipient <= 2U;
                }
                if (admitted) suppress = policy->out_data_suppression_mode == 3;
            }
        }
    }
suppression_done:
    *suppress_out_payload = suppress;
    unsigned char index = *configuration_index;
    if (index >= context.configuration_count && policy->configuration_index_fallback == 1) index = 0;
    *configuration_index = index;
    unsigned int route = medius_ep0_classify_standard_request(setup, &context);
    request_type = setup->request_type;
    if ((request_type & 0x60U) != 0 || (request_type & 0x80U) == 0) return route;
    if (setup->bytes[6] != 0 || setup->bytes[7] != 0) return route;
    if ((route & 0xfffffffbU) != 3U && route != 0) return route;
    unsigned char request = setup->request;
    unsigned char recipient = request_type & 0x1fU;
    policy = context.policy;
    bool forced_device = false;
    if ((unsigned char)(request - 8U) <= 1U || request == 5) {
        if (policy->standard_device_recipient == 1) {
            recipient = 0;
            forced_device = true;
        }
    }
    if (!forced_device && (request_type & 0x1cU) != 0 &&
        policy->reserved_recipient_mode == 2 && policy->reserved_recipient_action == 1)
        recipient = request_type & 3U;
    unsigned int policy_offset;
    if (!forced_device && request == 0)
        policy_offset = recipient == 0 ? 14U : recipient == 1 ? 20U : 24U;
    else if (request == 8 && recipient == 0) policy_offset = 17;
    else if (request == 10 && recipient == 1) policy_offset = 22;
    else goto global_policy;
    unsigned char primary = ((const volatile unsigned char *)policy)[policy_offset];
    if (primary != 0 && (primary != 3 || policy->zero_length_in_mode != 3)) return route;
global_policy:
    unsigned char mode = policy->zero_length_in_mode;
    if (mode == 2) return 1;
    if (mode == 3) return route == 0 ? 5U : 4U;
    if (mode == 4 && request == 6 && route == 0) return 6;
    return route;
}
