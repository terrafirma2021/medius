/* Medius v3.4.7 device — EP0 standard, class and vendor dispatch. */
#include "../include/types.h"

/* Request-dispatch reconstruction utilities; inline views, not native entries.
 * Keep the native full-WORD versus low16 bus address calculations explicit. */
static __inline__ __attribute__((always_inline)) volatile MediusUsbdWakeBusView *
setup_bus(unsigned int bus)
{
    return (volatile MediusUsbdWakeBusView *)(0x3fcbba9cU + bus * 0xaf4U);
}
static __inline__ __attribute__((always_inline)) const volatile MediusUsbdDescriptorTable *
setup_descriptors(volatile MediusUsbdWakeBusView *core)
{
    return (const volatile MediusUsbdDescriptorTable *)core->descriptors;
}
static __inline__ __attribute__((always_inline)) MediusUsbdRequestInterface *volatile *
setup_interfaces(unsigned int bus)
{
    return (MediusUsbdRequestInterface *volatile *)(0x3fcbc2c8U +
        (bus & 65535U) * 0xaf4U);
}
static __inline__ __attribute__((always_inline)) volatile unsigned char *
setup_alternates(unsigned int bus)
{
    return (volatile unsigned char *)(0x3fcbc308U + bus * 0xaf4U);
}
static __inline__ __attribute__((always_inline)) unsigned int
setup_configuration_length(const volatile unsigned char *descriptor)
{
    unsigned int high = descriptor[3];
    unsigned int low = descriptor[2];
    return low | (high << 8);
}


/* Native entry: 0x40382e28. */
/* Original function-byte SHA-256:
 * b742fc122b92a160b56d631d1befc5b65640b1e5605599777fa9ca4f8acffb2c. */
/*
 * Dispatch one modified-CherryUSB EP0 request. bus is a native WORD; state uses
 * its full32-bit stride product, interface-pointer walks and alternate-table
 * clearing use low16 bus, and driver/Medius BYTE boundaries narrow separately.
 * setup is live writable8-byte storage, data/length writable pointer/WORD slots.
 * Return1 for accepted,0 for rejected. Responses may replace *data with borrowed
 * descriptor storage. No universal wLength clamp, direction check or buffer
 * ownership transfer occurs here; standard policy performs its own checks first.
 *
 * Class interface requests choose the first matching numbered interface with a
 * callback; endpoint class requests choose the first endpoint callback without
 * matching an endpoint. Counts are cached for those scans. Class/fallback results
 * accept any nonnegative signed WORD. Vendor requests try OS1/OS2 and WebUSB
 * descriptors, then vendor callbacks until one returns EXACTLY0; that loop uses
 * a wrapping BYTE index and rereads the live count. A present OS1 table suppresses
 * the OS2 attempt even when its vendor code does not match. Reserved type rejects.
 *
 * Standard requests zero length, run local override, then use effective recipient.
 * Device requests manage address/status/wakeup/configuration/descriptors; interface
 * requests manage status, HID/report descriptors and alternates; endpoint requests
 * manage stall status/features through the Medius pre/post boundaries. Driver,
 * endpoint-open/close and notification results are ignored. Several callback/table
 * pointers are deliberately unchecked, as are descriptor record sizes and indices.
 *
 * Configuration/alternate walkers retain native total-1 unsigned termination:
 * total0 underflows; zero-length records stop. Only the later configuration-
 * attributes pass has an8191-byte traversal guard. SET_CONFIGURATION0 clears
 * alternates/configuration without closing endpoints or notifying; nonzero scans
 * may open endpoints before failure and have no rollback. SET_INTERFACE publishes
 * the alternate before its hook and may close every endpoint of that interface
 * when alternate0 is selected. No lock or stronger callback consistency is added.
 *
 * Generic string conversion uses low16 strlen and low16 doubled wire length,
 * checking only that wrapped length<=2048, then copies every low16 character.
 * This preserves the possible wrap/oversized-copy defect. Native BYTE/HALFWORD/
 * WORD accesses, fresh pointer loads, callback ordering and malformed-input edges
 * remain visible. Endpoint-halt acknowledgement and local recovery have separate native reviews;
 * their calls retain the original parameters and accepted/rejected result rules.
 */
unsigned int usbd_setup_request_handler(unsigned int bus, MediusUsbSetupPacket *setup,
    unsigned char **data, unsigned int *length)
{
    volatile MediusUsbSetupPacket *request = setup;
    unsigned char *volatile *data_slot = data;
    volatile unsigned int *length_slot = length;
    unsigned int request_type = request->request_type;
    unsigned int category = request_type & 0x60U;
    volatile MediusUsbdWakeBusView *core = setup_bus(bus);
    if (category == 0x20) {
        unsigned int recipient = request_type & 31U;
        if (recipient == 1 || recipient == 2) {
            unsigned int count = core->interface_count;
            MediusUsbdRequestInterface *volatile *entries = setup_interfaces(bus);
            for (unsigned int index = 0; index != count; ++index) {
                const volatile MediusUsbdRequestInterface *object = entries[index];
                if (object == NULL)
                    continue;
                MediusUsbdRequestCallback callback = recipient == 1 ?
                    object->interface_request : object->endpoint_request;
                if (callback == NULL)
                    continue;
                if (recipient == 1) {
                    unsigned int number = object->interface_number;
                    unsigned int requested = request->bytes[4];
                    if (number != requested)
                        continue;
                }
                return callback(bus, setup, data, length) >= 0;
            }
        }
        return medius_ep0_forward_unhandled_request(bus, setup, data, length) >= 0;
    }
    if (category == 0x40) {
        const volatile MediusUsbdDescriptorTable *descriptors = setup_descriptors(core);
        const volatile MediusUsbdOs10Descriptors *os10 = descriptors->os10;
        if (os10 != NULL) {
            unsigned int requested_code = request->request;
            unsigned int vendor_code = os10->vendor_code;
            if (requested_code == vendor_code) {
                unsigned int index = request->index;
                const volatile unsigned char *blob;
                if (index == 4)
                    blob = os10->compatible_id;
                else if (index == 5) {
                    const unsigned char *const volatile *properties = os10->properties;
                    unsigned int interface = request->value;
                    blob = properties[interface];
                } else
                    return 0;
                /* Native unaligned WORD assembly reads BYTE1,0,2,3. */
                unsigned int byte1 = blob[1];
                unsigned int byte0 = blob[0];
                unsigned int byte2 = blob[2];
                unsigned int byte3 = blob[3];
                *data_slot = (unsigned char *)blob;
                *length_slot = byte0 | (byte1 << 8) | (byte2 << 16) | (byte3 << 24);
                return 1;
            }
        } else {
            const volatile MediusUsbdOs20Descriptors *os20 = descriptors->os20;
            if (os20 != NULL) {
                unsigned int requested_code = request->request;
                unsigned int vendor_code = os20->vendor_code;
                if (requested_code == vendor_code) {
                    if (request->index != 7)
                        return 0;
                    unsigned char *response = (unsigned char *)os20->data;
                    unsigned int response_length = os20->length;
                    *data_slot = response;
                    *length_slot = response_length;
                    return 1;
                }
            }
        }
        const volatile MediusUsbdWebUsbDescriptor *web = descriptors->webusb;
        if (web != NULL) {
            unsigned int requested_code = request->request;
            unsigned int vendor_code = web->vendor_code;
            if (requested_code == vendor_code) {
                if (request->index != 2)
                    return 0;
                /* Interleaved native loads from the packed9-byte object. */
                unsigned int pointer1 = web->address_le[1];
                unsigned int length1 = web->length_le[1];
                unsigned int pointer0 = web->address_le[0];
                unsigned int pointer2 = web->address_le[2];
                unsigned int length0 = web->length_le[0];
                unsigned int length2 = web->length_le[2];
                unsigned int pointer3 = web->address_le[3];
                unsigned int length3 = web->length_le[3];
                *data_slot = (unsigned char *)(pointer0 | (pointer1 << 8) |
                    (pointer2 << 16) | (pointer3 << 24));
                *length_slot = length0 | (length1 << 8) | (length2 << 16) | (length3 << 24);
                return 1;
            }
        }
        if (core->interface_count != 0) {
            MediusUsbdRequestInterface *volatile *entry = setup_interfaces(bus);
            unsigned char index = 0;
            do {
                const volatile MediusUsbdRequestInterface *object = *entry;
                if (object != NULL) {
                    MediusUsbdRequestCallback callback = object->vendor_request;
                    if (callback != NULL && callback(bus, setup, data, length) == 0)
                        return 1;
                }
                index = (unsigned char)(index + 1U);
                unsigned int live_count = core->interface_count;
                ++entry;
                if (index >= live_count)
                    break;
            } while (1);
        }
        return medius_ep0_forward_unhandled_request(bus, setup, data, length) >= 0;
    }
    if (category != 0)
        return 0;
    *length_slot = 0;
    int overridden = medius_ep0_apply_request_override((unsigned char)bus, setup, data, length);
    if (overridden < 1)
        return overridden == 0;
    unsigned int recipient = medius_ep0_effective_recipient(bus, setup);
    if (recipient == 1) {
        const volatile MediusUsbdDescriptorTable *descriptors = setup_descriptors(core);
        unsigned int value = request->value;
        MediusUsbDescriptorCallback configuration = descriptors->configuration;
        unsigned int speed = core->state.speed;
        unsigned int requested_index = request->index;
        const volatile unsigned char *cursor = configuration(speed);
        if (core->state.configuration == 0)
            return 0;
        unsigned int code = request->request;
        unsigned int interface = requested_index & 255U;
        if (code == 10) {
            unsigned int alternate = setup_alternates(bus)[interface];
            **data_slot = (unsigned char)alternate;
            *length_slot = 1;
            return 1;
        }
        if (code == 0) {
            **data_slot = 0;
            (*data_slot)[1] = 0;
            *length_slot = 2;
            return 1;
        }
        if (code == 6) {
            unsigned int descriptor_type = value >> 8;
            if (descriptor_type == 0x21) {
                unsigned int consumed = 0, total = 0, active_interface = 255;
                for (;;) {
                    unsigned int record_length = cursor[0];
                    if (record_length == 0)
                        return 0;
                    unsigned int type = cursor[1];
                    if (type == 4)
                        active_interface = cursor[2];
                    else if (type == 0x21 && interface == active_interface) {
                        *data_slot = (unsigned char *)cursor;
                        *length_slot = cursor[0];
                        return 1;
                    } else if (type == 2) {
                        total = setup_configuration_length(cursor);
                        consumed = 0;
                    }
                    consumed += record_length;
                    cursor += record_length;
                    if (consumed > total - 1U)
                        return 0;
                }
            }
            if (descriptor_type == 0x22) {
                unsigned int count = core->interface_count;
                MediusUsbdRequestInterface *volatile *entries = setup_interfaces(bus);
                for (unsigned int index = 0; index != count; ++index) {
                    const volatile MediusUsbdRequestInterface *object = entries[index];
                    if (object != NULL && object->interface_number == interface) {
                        unsigned char *response = (unsigned char *)object->report_descriptor;
                        unsigned int response_length = object->report_length;
                        *data_slot = response;
                        *length_slot = response_length;
                        return 1;
                    }
                }
                return 0;
            }
            return medius_ep0_forward_unhandled_request(bus, setup, data, length) == 0;
        }
        if (code != 11)
            return 0;
        unsigned int alternate = request->bytes[2];
        setup_alternates(bus)[interface] = (unsigned char)alternate;
        unsigned int selected_interface = request->bytes[4];
        if (medius_clone_handle_set_interface((unsigned char)bus, selected_interface,
                (unsigned char)alternate) == 0) {
            descriptors = setup_descriptors(core);
            configuration = descriptors->configuration;
            cursor = configuration(core->state.speed);
            unsigned int consumed = 0, total = 0;
            unsigned int current_interface = 255, current_alternate = 255;
            unsigned char *selected_descriptor = NULL;
            for (;;) {
                unsigned int record_length = cursor[0];
                if (record_length == 0)
                    break;
                unsigned int type = cursor[1];
                if (type == 4) {
                    current_alternate = cursor[3];
                    current_interface = cursor[2];
                    if (current_interface == selected_interface && current_alternate == alternate)
                        selected_descriptor = (unsigned char *)cursor;
                } else if (type == 5 && current_interface == selected_interface) {
                    if (alternate == 0) {
                        medius_usbd_close_endpoint((unsigned char)bus, cursor[2]);
                        record_length = cursor[0];
                    } else if (current_alternate == alternate) {
                        medius_usbd_open_descriptor_endpoint(bus, (unsigned char *)cursor);
                        record_length = cursor[0];
                    }
                } else if (type == 2) {
                    total = setup_configuration_length(cursor);
                    consumed = 0;
                }
                consumed += record_length;
                cursor += record_length;
                if (consumed > total - 1U)
                    break;
            }
            medius_usbd_class_event_notify(bus, 8, selected_descriptor);
        }
        *length_slot = 0;
        return 1;
    }
    if (recipient == 2) {
        unsigned int endpoint = request->bytes[4];
        unsigned int configured = core->state.configuration;
        unsigned int code = request->request;
        if (configured == 0) {
            if (code == 0 && (endpoint & 127U) == 0) {
                **data_slot = 0;
                (*data_slot)[1] = 0;
                *length_slot = 2;
                return 1;
            }
            return 0;
        }
        if (code == 0) {
            unsigned char stalled;
            usbd_ep_is_stalled((unsigned char)bus, (unsigned char)endpoint, &stalled);
            **data_slot = stalled != 0;
            (*data_slot)[1] = 0;
            *length_slot = 2;
            return 1;
        }
        if (code != 1 && code != 3)
            return 0;
        if (request->value != 0) {
            *length_slot = 0;
            return 0;
        }
        unsigned int halted = code == 3;
        if (medius_clone_prepare_endpoint_halt((unsigned char)bus, endpoint,
                (unsigned char)halted) == 0)
            return 0;
        if (halted == 0) {
            usbd_ep_clear_stall((unsigned char)bus, (unsigned char)endpoint);
            medius_clone_endpoint_halt_changed(bus, endpoint, 0);
            return 1;
        }
        usb_device_set_stall((unsigned char)bus, (unsigned char)endpoint);
        medius_clone_endpoint_halt_changed(bus, endpoint, 1);
        *length_slot = 0;
        return 1;
    }
    if (recipient != 0)
        return 0;
    unsigned int code = request->request;
    unsigned int value = request->value;
    if (code == 5) {
        unsigned char address = (unsigned char)value;
        core->state.device_address = address;
        usbd_set_address((unsigned char)bus, address);
        *length_slot = 0;
        return 1;
    }
    if (code == 0) {
        unsigned int remote_wakeup = core->state.remote_wakeup_enabled;
        unsigned int self_powered = core->state.self_powered;
        unsigned int status = medius_ep0_filter_device_status(bus,
            (unsigned short)(self_powered | (remote_wakeup << 1)));
        **data_slot = (unsigned char)status;
        (*data_slot)[1] = (unsigned char)(status >> 8);
        *length_slot = 2;
        return 1;
    }
    if (code == 1 || code == 3) {
        if (value == 1) {
            MediusUsbdBusEventHandler notify = core->event_handler;
            core->state.remote_wakeup_enabled = code == 3 ? 1 : 0;
            notify(bus, code == 3 ? 9 : 10);
        }
        *length_slot = 0;
        return 1;
    }
    if (code == 8) {
        unsigned int configured = core->state.configuration;
        **data_slot = (unsigned char)configured;
        *length_slot = 1;
        return 1;
    }
    if (code == 9) {
        unsigned int selected_configuration = (unsigned char)value;
        if (selected_configuration == 0) {
            memset((void *)setup_alternates((unsigned short)bus), 0, 256);
            core->state.configuration = 0;
            *length_slot = 0;
            return 1;
        }
        const volatile MediusUsbdDescriptorTable *descriptors = setup_descriptors(core);
        MediusUsbDescriptorCallback configuration = descriptors->configuration;
        const volatile unsigned char *cursor = configuration(core->state.speed);
        unsigned int consumed = 0, total = 0, current_configuration = 255, alternate = 255;
        bool found = false;
        for (;;) {
            unsigned int record_length = cursor[0];
            if (record_length == 0)
                break;
            unsigned int type = cursor[1];
            if (type == 4)
                alternate = cursor[3];
            else if (type == 5 && current_configuration == selected_configuration && alternate == 0) {
                medius_usbd_open_descriptor_endpoint(bus, (unsigned char *)cursor);
                record_length = cursor[0];
            } else if (type == 2) {
                current_configuration = cursor[5];
                if (current_configuration == selected_configuration) {
                    total = setup_configuration_length(cursor);
                    consumed = 0;
                    found = true;
                }
            }
            consumed += record_length;
            cursor += record_length;
            if (consumed > total - 1U)
                break;
        }
        if (!found) {
            *length_slot = 0;
            return 0;
        }
        memset((void *)setup_alternates((unsigned short)bus), 0, 256);
        descriptors = setup_descriptors(core);
        configuration = descriptors->configuration;
        cursor = configuration(core->state.speed);
        if (cursor != NULL) {
            unsigned int traversed = 0;
            for (;;) {
                unsigned int record_length = cursor[0];
                if (record_length == 0 || traversed > 8191)
                    break;
                unsigned int type = cursor[1];
                traversed += record_length;
                if (type == 2 && cursor[5] == selected_configuration) {
                    core->state.self_powered = (cursor[7] >> 6) & 1U;
                    core->state.remote_wakeup_support = (cursor[7] >> 5) & 1U;
                    break;
                }
                cursor += record_length;
            }
        }
        core->state.configuration = (unsigned char)selected_configuration;
        core->state.is_suspend = 0;
        medius_usbd_class_event_notify(bus, 7, NULL);
        MediusUsbdBusEventHandler notify = core->event_handler;
        notify(bus, 7);
        *length_slot = 0;
        return 1;
    }
    if (code != 6)
        return 0;
    int special = medius_ep0_get_special_descriptor((unsigned char)bus, setup, data, length);
    if (special < 1)
        return special == 0;
    unsigned int descriptor_type = value >> 8;
    unsigned char *response;
    unsigned int response_length;
    if (descriptor_type == 1) {
        unsigned int speed = usbd_get_port_speed((unsigned char)bus);
        const volatile MediusUsbdDescriptorTable *descriptors = setup_descriptors(core);
        core->state.speed = (unsigned char)speed;
        MediusUsbDescriptorCallback callback = descriptors->device;
        if (callback == NULL)
            return 0;
        response = (unsigned char *)callback(speed);
        if (response == NULL)
            return 0;
        response_length = *(const volatile unsigned char *)response;
    } else if (descriptor_type == 2) {
        const volatile MediusUsbdDescriptorTable *descriptors = setup_descriptors(core);
        MediusUsbDescriptorCallback callback = descriptors->configuration;
        if (callback == NULL)
            return 0;
        response = (unsigned char *)callback(core->state.speed);
        if (response == NULL)
            return 0;
        response_length = setup_configuration_length(response);
        unsigned int configured = core->state.configuration;
        if (configured == 0 || ((const volatile unsigned char *)response)[5] == configured) {
            core->state.self_powered = (((const volatile unsigned char *)response)[7] >> 6) & 1U;
            core->state.remote_wakeup_support = (((const volatile unsigned char *)response)[7] >> 5) & 1U;
        }
    } else if (descriptor_type == 3) {
        unsigned int index = value & 255U;
        const volatile MediusUsbdDescriptorTable *descriptors = setup_descriptors(core);
        if (index == 0xee) {
            const volatile MediusUsbdOs10Descriptors *os10 = descriptors->os10;
            if (os10 == NULL)
                return 0;
            response = (unsigned char *)os10->string_descriptor;
            response_length = *(const volatile unsigned char *)response;
        } else {
            MediusUsbStringDescriptorCallback callback = descriptors->string;
            if (callback == NULL)
                return 0;
            const char *text = callback(core->state.speed, index);
            if (text == NULL)
                return 0;
            if (index == 0) {
                **data_slot = 4;
                (*data_slot)[1] = 3;
                unsigned char *output = *data_slot;
                unsigned int first = ((const volatile unsigned char *)text)[0];
                output[2] = (unsigned char)first;
                output = *data_slot;
                unsigned int second = ((const volatile unsigned char *)text)[1];
                output[3] = (unsigned char)second;
                response_length = 4;
            } else {
                unsigned int characters = (unsigned short)strlen(text);
                response_length = (unsigned short)((characters + 1U) * 2U);
                if (response_length > 2048)
                    return 0;
                **data_slot = (unsigned char)response_length;
                (*data_slot)[1] = 3;
                unsigned int offset = 2;
                for (unsigned int index = 0; (index & 65535U) < characters; ++index) {
                    unsigned char *output = *data_slot;
                    unsigned int character = ((const volatile unsigned char *)text)[index];
                    output[offset] = (unsigned char)character;
                    output = *data_slot;
                    output[offset + 1U] = 0;
                    offset += 2;
                }
            }
            *length_slot = response_length;
            return 1;
        }
    } else if (descriptor_type == 7) {
        const volatile MediusUsbdDescriptorTable *descriptors = setup_descriptors(core);
        MediusUsbDescriptorCallback callback = descriptors->other_speed;
        if (callback == NULL)
            return 0;
        response = (unsigned char *)callback(core->state.speed);
        if (response == NULL)
            return 0;
        response_length = setup_configuration_length(response);
    } else if (descriptor_type == 15) {
        const volatile MediusUsbdDescriptorTable *descriptors = setup_descriptors(core);
        const volatile MediusUsbDescriptorSpan *bos = descriptors->bos;
        if (bos == NULL)
            return 0;
        response = (unsigned char *)bos->data;
        response_length = bos->length;
    } else
        return 0;
    *data_slot = response;
    *length_slot = response_length;
    return 1;
}
