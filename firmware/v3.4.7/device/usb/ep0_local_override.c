/* Medius v3.4.7 device — local EP0 request overrides. */
#include "../include/types.h"

/* EP0 override reconstruction utilities: inlined native table walks, not
 * additional firmware entries. Header lengths/counts remain unchecked. */
static __attribute__((always_inline)) inline unsigned int override_find_alternate(
    unsigned char interface)
{
    memw();
    unsigned int count = MEDIUS_CLONE_CONFIGURATION_OVERRIDE_COUNT;
    if (count != 0) {
        unsigned int index = 0;
        const volatile MediusCloneAlternateOverride *record = MEDIUS_CLONE_ALTERNATE_OVERRIDES;
        do {
            unsigned char candidate = record->interface;
            ++record;
            if (candidate == interface)
                return index;
            memw();
            count = MEDIUS_CLONE_CONFIGURATION_OVERRIDE_COUNT;
            ++index;
        } while ((index & 255U) < count);
    }
    return 0xffffffffU;
}

static __attribute__((always_inline)) inline bool override_has_hid_patch(void)
{
    unsigned int count = DESCRIPTOR_PATCH_SERVED->count;
    if (count == 0)
        return false;
    unsigned char configuration = MEDIUS_CLONE_CONFIGURATION_INDEX;
    for (unsigned int index = 0; index < count; ++index) {
        const volatile DescriptorPatchRecord *patch = (const volatile void *)
            ((unsigned int)(uintptr_t)DESCRIPTOR_PATCH_SERVED + index * 10U);
        if (patch->kind == 1 && patch->configuration == configuration)
            return true;
    }
    return false;
}

static __attribute__((always_inline)) inline const volatile MediusEp0HidOverrideRecord *
override_find_hid_record(const unsigned char *table, unsigned int length,
    unsigned char configuration, unsigned int interface)
{
    unsigned short offset = 0;
    while ((unsigned int)offset + 3 < length) {
        const volatile MediusEp0HidOverrideRecord *record = (const volatile void *)(table + offset);
        if (record->configuration == configuration && record->interface == interface)
            return record;
        offset = (unsigned short)(offset + 4U + record->length);
    }
    return NULL;
}

/* Native entry: 0x40396168. */
/* Original function-byte SHA-256:
 * 6f852d63c637e4910d4b1956e90512b97cbb2cf111af446c34fe9e5c6d0ffb48. */
/* Apply the previously classified EP0 route; return -1 to reject, 0 when
 * handled locally, or 1 to continue core processing (route2 delegates its raw
 * relay result). Read route, cache interface BYTE, then read OUT suppression;
 * suppression marks setup consumed before route handling. Bus uses its low BYTE.
 *
 * Routes1/2/3 reject/relay/accept unchanged. Routes7/8 zero one BYTE for request10
 * or two otherwise; route8 also overrides length. Route6 marks length override
 * then continues. Route11 publishes a virtual configuration only when request
 * and current device generations match under the configuration lock. Route10
 * updates/appends an alternate override with a native HALFWORD pair store.
 *
 * Route12 clears min(wLength,2048), but still writes status/configuration bytes
 * even for a shorter/zero clear length. It preserves raw wake-byte arithmetic,
 * status policy and a second virtual-configuration read. Route9 serves report
 * descriptor buffers or HID override/real descriptor bytes; patch presence,
 * cached-versus-reloaded configuration views and malformed-chain exits matter.
 * General processing can serve a virtual GET_CONFIGURATION, read/remove an
 * alternate override, and serve/reject a HID override after recipient policy.
 * Preserve fresh policy/count/pointer reads, read-before-publish removal, BYTE
 * cursor comparisons, 16-bit descriptor offsets and unchecked payload copies.
 * No aggregate lock, capacity repair, timeout or controller stall is added.
 */
int medius_ep0_apply_request_override(unsigned char bus,
    const MediusUsbSetupPacket *setup, unsigned char **data, unsigned int *length)
{
    unsigned int route = medius_ep0_get_route();
    const volatile unsigned char *request = (const volatile unsigned char *)setup;
    unsigned char interface = request[4];
    if (medius_ep0_get_out_payload_suppressed() != 0)
        medius_ep0_mark_setup_consumed(bus);
    const volatile MediusEp0RequestPolicy *policy = MEDIUS_EP0_REQUEST_POLICY;
    switch (route) {
    case 1:
        return -1;
    case 2:
        return medius_ep0_relay_request_boundary(bus, setup, data, length);
    case 3:
        return 0;
    case 7:
    case 8: {
        unsigned int code = request[1];
        unsigned int cleared = code == 10 ? 1 : 2;
        void *destination = *(unsigned char *volatile *)data;
        *(volatile unsigned int *)length = cleared;
        memset(destination, 0, cleared);
        if (route == 8)
            medius_ep0_mark_length_override(bus);
        return 0;
    }
    case 6:
        medius_ep0_mark_length_override(bus);
        break;
    case 11: {
        (void)xPortEnterCriticalTimeout(MEDIUS_CLONE_CONFIGURATION_LOCK, -1);
        memw();
        unsigned int requested = MEDIUS_EP0_REPLY_LIFETIME->request_generation;
        memw();
        unsigned int current = DEVICE_OUT_GENERATION;
        if (requested == current) {
            unsigned char configuration = request[2];
            memw();
            MEDIUS_CLONE_VIRTUAL_CONFIGURATION = configuration;
        }
        vPortExitCritical(MEDIUS_CLONE_CONFIGURATION_LOCK);
        return 0;
    }
    case 10: {
        (void)xPortEnterCriticalTimeout(MEDIUS_CLONE_CONFIGURATION_LOCK, -1);
        unsigned int index = override_find_alternate(interface);
        if (index == 0xffffffffU) {
            memw();
            unsigned int guard_count = MEDIUS_CLONE_CONFIGURATION_OVERRIDE_COUNT;
            if (guard_count >= 8) {
                vPortExitCritical(MEDIUS_CLONE_CONFIGURATION_LOCK);
                return 0;
            }
            memw();
            index = MEDIUS_CLONE_CONFIGURATION_OVERRIDE_COUNT;
            unsigned char next_count = index + 1;
            memw();
            MEDIUS_CLONE_CONFIGURATION_OVERRIDE_COUNT = next_count;
        }
        unsigned char alternate = request[2];
        MEDIUS_CLONE_ALTERNATE_OVERRIDES[index].pair = interface | ((unsigned int)alternate << 8);
        vPortExitCritical(MEDIUS_CLONE_CONFIGURATION_LOCK);
        return 0;
    }
    case 12: {
        unsigned int requested = (unsigned int)request[7] << 8;
        requested |= request[6];
        unsigned int cleared = requested < 2048 ? requested : 2048;
        memset(*(unsigned char *volatile *)data, 0, cleared);
        if (request[1] == 0) {
            unsigned int status = 0;
            if (QUERY_CONFIGURATION_LENGTH >= 8) {
                const volatile unsigned char *configuration = QUERY_CONFIGURATION;
                status = (configuration[7] >> 6) & 1U;
            }
            memw();
            unsigned int wake = MEDIUS_USB_REMOTE_WAKE_ENABLED;
            unsigned int wake_policy = policy->remote_wakeup_status_mode;
            status = (status | (wake * 2U)) & 65535U;
            unsigned int wake_bit = wake_policy == 2 ? 0 : status & 2U;
            if (policy->device_status_override_mode == 1)
                status = MEDIUS_EP0_DEVICE_STATUS_OVERRIDE;
            unsigned int reply = (status & ~2U) | wake_bit;
            unsigned char *destination = *(unsigned char *volatile *)data;
            *(volatile unsigned char *)destination = reply;
            destination = *(unsigned char *volatile *)data;
            *(volatile unsigned char *)(destination + 1) = reply >> 8;
        } else {
            memw();
            unsigned char configuration = MEDIUS_CLONE_VIRTUAL_CONFIGURATION;
            if (configuration != 0) {
                memw();
                configuration = MEDIUS_CLONE_VIRTUAL_CONFIGURATION;
            } else if (usb_device_is_configured(0) && QUERY_CONFIGURATION_LENGTH >= 6) {
                const volatile unsigned char *descriptor = QUERY_CONFIGURATION;
                configuration = descriptor[5];
            }
            unsigned char *destination = *(unsigned char *volatile *)data;
            *(volatile unsigned char *)destination = configuration;
        }
        *(volatile unsigned int *)length = cleared;
        return 0;
    }
    case 9: {
        unsigned int descriptor_type = request[3];
        unsigned int requested_interface = request[4];
        if (descriptor_type == 0x22) {
            int count = USB_INTERFACE_COUNT;
            for (int index = 0; index < count; ++index) {
                if (REPORT_CAPTURE_INTERFACE_IDS[index] != requested_interface)
                    continue;
                unsigned int descriptor_length = USB_INTERFACE_REPORT_LENGTHS[index];
                if (descriptor_length == 0)
                    continue;
                *(unsigned char *volatile *)data = REPORT_BUFFER_STORAGE +
                    ((unsigned int)index & 65535U) * 2048U;
                *(volatile unsigned int *)length = descriptor_length;
                return 0;
            }
            return -1;
        }

        unsigned int configuration_length;
        const volatile unsigned char *configuration = NULL;
        bool pointer_cached = false;
        if (override_has_hid_patch()) {
            configuration_length = QUERY_CONFIGURATION_LENGTH;
        } else {
            configuration_length = QUERY_CONFIGURATION_LENGTH;
            unsigned char configuration_value = 0;
            const unsigned char *overrides;
            if (configuration_length >= 6) {
                configuration = QUERY_CONFIGURATION;
                pointer_cached = true;
                overrides = MEDIUS_EP0_HID_OVERRIDES->data;
                configuration_value = configuration[5];
            } else {
                overrides = MEDIUS_EP0_HID_OVERRIDES->data;
            }
            if (overrides != NULL) {
                unsigned int size = MEDIUS_EP0_HID_OVERRIDES->length;
                if (size >= 4) {
                    const volatile MediusEp0HidOverrideRecord *record =
                        override_find_hid_record(overrides, size, configuration_value, requested_interface);
                    if (record != NULL) {
                        unsigned int action = record->action;
                        unsigned int copied = record->length;
                        const unsigned char *payload = (const unsigned char *)record + 4;
                        if (action == 1)
                            return -1;
                        if (action == 2) {
                            medius_ep0_clear_stall_and_consume(bus);
                            return -1;
                        }
                        if (action == 0) {
                            memcpy(*(unsigned char *volatile *)data, payload, copied);
                            *(volatile unsigned int *)length = copied;
                            return 0;
                        }
                    }
                    pointer_cached = false;
                }
            }
        }
        if (!pointer_cached)
            configuration = QUERY_CONFIGURATION;
        if (configuration_length < 2)
            return -1;
        unsigned int active_interface = 0xffffffffU;
        unsigned short offset = 0;
        for (;;) {
            const volatile unsigned char *descriptor = configuration + offset;
            unsigned int size = descriptor[0];
            if (size < 2 || offset + size > configuration_length)
                return -1;
            unsigned int type = descriptor[1];
            if (type == 4) {
                if (size >= 9)
                    active_interface = descriptor[2];
            } else if (type == 0x21 && active_interface == requested_interface) {
                memcpy(*(unsigned char *volatile *)data, (const void *)descriptor, size);
                *(volatile unsigned int *)length = size;
                return 0;
            }
            offset = (unsigned short)(offset + size);
            if ((unsigned int)offset + 1 >= configuration_length)
                return -1;
        }
    }
    }

    unsigned int code = request[1];
    memw();
    unsigned int virtual_configuration = MEDIUS_CLONE_VIRTUAL_CONFIGURATION;
    int result = 1;
    unsigned int type, recipient;
    if (virtual_configuration != 0 && code == 8) {
        type = request[0];
        recipient = type & 31U;
        if (((type >> 5) & 3U) == 0) {
            if (policy->standard_device_recipient == 1)
                goto serve_virtual_configuration;
            if (((type >> 2) & 7U) == 0) {
                if (recipient == 0)
                    goto serve_virtual_configuration;
                goto after_interface_alternate;
            }
            if (policy->reserved_recipient_mode == 2 && policy->reserved_recipient_action == 1) {
                if ((type & 3U) == 0)
                    goto serve_virtual_configuration;
            } else if (recipient == 0) {
                goto serve_virtual_configuration;
            }
            goto standard_device_recipient_gate;
        }
        if (((type >> 2) & 7U) == 0) {
            if (recipient == 0)
                goto serve_virtual_configuration;
            goto after_interface_alternate;
        }
        if (policy->reserved_recipient_mode == 2 && policy->reserved_recipient_action == 1) {
            if ((type & 3U) == 0)
                goto serve_virtual_configuration;
        } else if (recipient == 0) {
            goto serve_virtual_configuration;
        }
        result = 1;
        if (policy->reserved_recipient_mode == 2)
            goto normalize_reserved_action;
        goto after_interface_alternate;

serve_virtual_configuration: {
            unsigned char *destination = *(unsigned char *volatile *)data;
            memw();
            unsigned char value = MEDIUS_CLONE_VIRTUAL_CONFIGURATION;
            *(volatile unsigned char *)destination = value;
            *(volatile unsigned int *)length = 1;
            code = request[1];
            result = 0;
        }
    }
    type = request[0];
    recipient = type & 31U;
    if (((type >> 5) & 3U) == 0 &&
        ((unsigned char)(code - 8) < 2 || code == 5)) {
standard_device_recipient_gate:
        if (policy->standard_device_recipient == 1 || ((type >> 2) & 7U) == 0)
            goto after_interface_alternate;
        if (policy->reserved_recipient_mode != 2)
            goto after_interface_alternate;
        goto normalize_reserved_action;
    }
    if ((type & 0x1cU) != 0 && policy->reserved_recipient_mode == 2) {
normalize_reserved_action:
        if (policy->reserved_recipient_action == 1)
            recipient = type & 3U;
    }
    if (recipient == 1 && (unsigned char)(code - 10) < 2) {
        (void)xPortEnterCriticalTimeout(MEDIUS_CLONE_CONFIGURATION_LOCK, -1);
        unsigned int index = override_find_alternate(interface);
        if (index != 0xffffffffU) {
            if (request[1] == 10) {
                unsigned char *destination = *(unsigned char *volatile *)data;
                unsigned char alternate = MEDIUS_CLONE_ALTERNATE_OVERRIDES[index].alternate;
                *(volatile unsigned char *)destination = alternate;
                *(volatile unsigned int *)length = 1;
                result = 0;
            } else {
                memw();
                unsigned char last = MEDIUS_CLONE_CONFIGURATION_OVERRIDE_COUNT - 1;
                unsigned short replacement = MEDIUS_CLONE_ALTERNATE_OVERRIDES[last].pair;
                memw();
                MEDIUS_CLONE_CONFIGURATION_OVERRIDE_COUNT = last;
                MEDIUS_CLONE_ALTERNATE_OVERRIDES[index].pair = replacement;
            }
        }
        vPortExitCritical(MEDIUS_CLONE_CONFIGURATION_LOCK);
        code = request[1];
        type = request[0];
    }

after_interface_alternate:
    recipient = type & 31U;
    if (((type >> 5) & 3U) == 0 &&
        ((unsigned char)(code - 8) < 2 || code == 5))
        goto finish;
    if (((type >> 2) & 7U) != 0 && policy->reserved_recipient_mode == 2 &&
        policy->reserved_recipient_action == 1)
        recipient = type & 3U;
    if (recipient == 1 && code == 6 && request[3] == 0x21) {
        if (override_has_hid_patch())
            goto finish;
        unsigned char configuration = 0;
        if (QUERY_CONFIGURATION_LENGTH >= 6) {
            const volatile unsigned char *descriptor = QUERY_CONFIGURATION;
            configuration = descriptor[5];
        }
        unsigned int requested_interface = request[4];
        const unsigned char *overrides = MEDIUS_EP0_HID_OVERRIDES->data;
        if (overrides != NULL) {
            unsigned int size = MEDIUS_EP0_HID_OVERRIDES->length;
            if (size >= 4) {
                const volatile MediusEp0HidOverrideRecord *record =
                    override_find_hid_record(overrides, size, configuration, requested_interface);
                if (record != NULL) {
                    unsigned int action = record->action;
                    if (action == 1)
                        return -1;
                    if (action == 2) {
                        medius_ep0_clear_stall_and_consume(bus);
                        return -1;
                    }
                    if (action == 0) {
                        unsigned int copied = record->length;
                        memcpy(*(unsigned char *volatile *)data, (const unsigned char *)record + 4, copied);
                        *(volatile unsigned int *)length = copied;
                        result = 0;
                    }
                }
            }
        }
    }
finish:
    if (route == 5)
        medius_ep0_mark_setup_consumed(bus);
    return result;
}
