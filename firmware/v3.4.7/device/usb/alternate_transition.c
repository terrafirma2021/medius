/* Medius v3.4.7 device — coordinated USB alternate-setting transitions. */
#include "../include/types.h"

/* Alternate-transition reconstruction utilities; inline expansions of repeated
 * native operations, not additional firmware entries. */
static __attribute__((always_inline)) inline bool alternate_interface_selected(
    const volatile UsbInterfaceSelection *selection, unsigned int interface)
{
    unsigned int word = selection->words[(interface >> 5) & 7U];
    return (word & (1U << (interface & 31U))) != 0;
}

static __attribute__((always_inline)) inline void alternate_clear_interface_gates(
    unsigned int interface)
{
    memw();
    REPORT_SUBMIT_BLOCKED_WRITABLE[interface] = 0;
    memw();
    REPORT_SERVICE_ACTIVE[interface] = 0;
    memw();
    REPORT_INTERFACE_BLOCKED[interface] = 0;
}

/* Native entry: 0x40391df4. */
/* Original function-byte SHA-256:
 * 0aacc986ab65fac1e621adb909c63a36ee6fbc3e7555828ae1554460b3d662a3. */
/* Apply selected interface alternate settings while recovering pending reports.
 * selection is eight live WORDs covering all 256 interface numbers;
 * alternates is a live 256-BYTE input. Both are reread through all passes.
 * Set the fast-path block, spin while fast worker active for at most a signed
 * modular elapsed 1000us, then proceed even if still active. Snapshot old
 * alternates and cache configuration pointer/length once for the initial scan.
 * Gather non-control, non-EP0 IN endpoints under selected old alternates;
 * malformed records end that interface scan but retain its collected bits.
 *
 * Under credit lock, block selected report interfaces/secondary endpoints and
 * cancel their active IN transfers; unlock before waiting for endpoint disable.
 * Recover completed reports under a second lock, optionally capture them, then
 * for all selected interfaces publish new alternate/close old, close new, open
 * new in three separate passes. Reparse/register, refresh input bindings or raw
 * poll timing, and clear stalls in a fourth pass. Retain native callback order.
 *
 * Under the final lock, clear gates and copy a pending endpoint bucket when an
 * interface moves between nonzero endpoint numbers; OR its new pending bit
 * without clearing the old bit. Discard removed interfaces or schedule queued
 * work with equal now/deadline snapshots. Clear all six secondary block BYTEs,
 * pump bindings, unlock, kick fast TX if a bucket moved, drain OUT work, and
 * clear the transition block. Counts/copy lengths are trusted; no capacity
 * clamp, rollback, lock-result handling or physical completion guarantee is
 * added. The native scratch initially clears only six endpoint BYTEs.
 */
void usb_clone_apply_alternate_changes(
    const volatile UsbInterfaceSelection *selection,
    const volatile unsigned char *alternates)
{
    memw();
    MEDIUS_CLONE_ALTERNATE_TRANSITION_BLOCK = 1;
    unsigned long long started = (unsigned long long)esp_timer_get_time();
    for (;;) {
        memw();
        if (REPORT_FAST_ACTIVE == 0)
            break;
        unsigned long long now = (unsigned long long)esp_timer_get_time();
        if ((long long)(now - started) > 999)
            break;
    }
    memcpy(MEDIUS_CLONE_ALTERNATE_SNAPSHOT, CLONE_ALTERNATE_SETTINGS, 256);
    unsigned int configuration_length = QUERY_CONFIGURATION_LENGTH;
    const volatile unsigned char *configuration = QUERY_CONFIGURATION;
    unsigned short affected_in = 0;
    for (unsigned int interface = 0; interface < 256; ++interface) {
        if (!alternate_interface_selected(selection, interface))
            continue;
        unsigned int old_alternate = ((const volatile unsigned char *)
            MEDIUS_CLONE_ALTERNATE_SNAPSHOT)[interface];
        if (configuration_length < 2)
            continue;
        unsigned int interface_in = 0;
        unsigned short offset = 0;
        bool matching = false;
        do {
            const volatile unsigned char *descriptor = configuration + offset;
            unsigned int length = descriptor[0];
            unsigned int type = descriptor[1];
            if (length < 2 || offset + length > configuration_length)
                break;
            if (type == 4 && length >= 9) {
                matching = false;
                if (descriptor[2] == interface)
                    matching = descriptor[3] == old_alternate;
            } else if (type == 5 && length >= 7 && matching) {
                unsigned int endpoint = descriptor[2];
                if ((endpoint & 0x80U) != 0) {
                    unsigned int attributes = descriptor[3];
                    if ((attributes & 3U) != 0 && (endpoint & 15U) != 0)
                        interface_in |= 1U << (endpoint & 15U);
                }
            }
            offset = (unsigned short)(offset + length);
        } while ((unsigned int)offset + 1 < configuration_length);
        affected_in |= interface_in;
    }

    volatile MediusAlternateEndpointScratch scratch;
    scratch.first_four = 0;
    scratch.last_two = 0;
    (void)xPortEnterCriticalTimeout(&CREDIT_LOCK, -1);
    unsigned short cancelled_in = 0;
    bool any_interface_selected = false;
    for (int interface = 0; interface < USB_INTERFACE_COUNT; ++interface) {
        unsigned int id = REPORT_CAPTURE_INTERFACE_IDS[interface];
        if (!alternate_interface_selected(selection, id))
            continue;
        unsigned char endpoint = USB_INTERFACE_ENDPOINTS[interface];
        memw();
        REPORT_INTERFACE_BLOCKED[interface] = 1;
        scratch.bytes[interface] = endpoint;
        memw();
        REPORT_SERVICE_ACTIVE[interface] = 0;
        any_interface_selected = true;
        unsigned int number = endpoint & 15U;
        if (number != 0) {
            const volatile CreditInterfaceQueue *queue = (const volatile void *)
                ((unsigned int)(uintptr_t)REPORT_HISTORY_QUEUES +
                 (unsigned int)interface * 960U);
            if (queue->extra_pending != 0) {
                medius_dwc2_cancel_in(0, number | 0x80U);
                cancelled_in |= 1U << number;
            }
        }
    }
    for (unsigned int number = 1; number < 16; ++number) {
        if ((affected_in & (1U << number)) == 0)
            continue;
        unsigned int endpoint = number | 0x80U;
        int count = CREDIT_BINDINGS.count;
        for (int index = 0; index < count; ++index) {
            if (CREDIT_BINDING_RECORDS[index].endpoint != endpoint)
                continue;
            unsigned int slot = CREDIT_BINDING_RECORDS[index].queue_slot;
            if (slot < 6) {
                memw();
                MEDIUS_REPORT_SECONDARY_BLOCKED_WRITABLE[slot] = 1;
                memw();
                if (REPORT_SECONDARY_IN_FLIGHT[slot] != 0) {
                    medius_dwc2_cancel_in(0, endpoint);
                    cancelled_in |= 1U << number;
                }
            }
            break;
        }
    }
    vPortExitCritical(&CREDIT_LOCK);
    medius_dwc2_wait_in_endpoints_disabled(cancelled_in);
    unsigned int recovery_stamp = (unsigned int)esp_timer_get_time();

    (void)xPortEnterCriticalTimeout(&CREDIT_LOCK, -1);
    int capture_count = 0;
    for (int interface = 0; interface < USB_INTERFACE_COUNT; ++interface) {
        memw();
        if (REPORT_INTERFACE_BLOCKED[interface] == 0)
            continue;
        if (!report_recover_interface_in(interface, (unsigned char *)&scratch.bytes[6]))
            continue;
        memw();
        unsigned char metadata = REPORT_SUBMIT_METADATA42[interface];
        unsigned int length = REPORT_SUBMIT_LENGTH[interface];
        unsigned char recovered_flags = scratch.bytes[6];
        unsigned char endpoint = USB_INTERFACE_ENDPOINTS[interface];
        volatile MediusAlternateCaptureRecord *record =
            &MEDIUS_CLONE_ALTERNATE_CAPTURE[capture_count];
        record->flags = metadata | recovered_flags;
        unsigned int copied = length < 64 ? length : 64;
        record->endpoint = endpoint;
        record->length = copied;
        memcpy((void *)record->payload, REPORT_SUBMIT_STORAGE +
               ((unsigned int)interface & 65535U) * 64U, copied);
        ++capture_count;
    }
    for (unsigned int number = 1; number < 16; ++number) {
        if ((affected_in & (1U << number)) == 0)
            continue;
        unsigned int endpoint = number | 0x80U;
        volatile MediusAlternateCaptureRecord *record =
            &MEDIUS_CLONE_ALTERNATE_CAPTURE[capture_count];
        if (medius_report_recover_secondary_in(endpoint, (void *)record->payload,
                (unsigned char *)&record->length) != 0) {
            record->endpoint = endpoint;
            record->flags = 0;
            ++capture_count;
        }
    }
    vPortExitCritical(&CREDIT_LOCK);
    memw();
    unsigned int capture_classes = CAPTURE_ENABLED_CLASSES;
    if ((capture_classes & 0x200U) != 0 && capture_count > 0) {
        for (int index = 0; index < capture_count; ++index) {
            const volatile MediusAlternateCaptureRecord *record = &MEDIUS_CLONE_ALTERNATE_CAPTURE[index];
            unsigned int length = record->length;
            unsigned int flags = record->flags;
            unsigned int endpoint = record->endpoint;
            medius_capture_record_transfer(9, endpoint & 15U, 1,
                flags | (length == 0 ? 2U : 0U), recovery_stamp, 1,
                (const unsigned char *)record->payload, length);
        }
    }

    for (unsigned int interface = 0; interface < 256; ++interface) {
        if (!alternate_interface_selected(selection, interface))
            continue;
        unsigned int next = alternates[interface];
        unsigned int previous = ((const volatile unsigned char *)MEDIUS_CLONE_ALTERNATE_SNAPSHOT)[interface];
        ((volatile unsigned char *)CLONE_ALTERNATE_SETTINGS)[interface] = next;
        medius_clone_apply_interface_alternate_endpoints(interface, previous, 0);
    }
    for (unsigned int interface = 0; interface < 256; ++interface) {
        if (alternate_interface_selected(selection, interface))
            medius_clone_apply_interface_alternate_endpoints(interface, alternates[interface], 0);
    }
    for (unsigned int interface = 0; interface < 256; ++interface) {
        if (alternate_interface_selected(selection, interface))
            medius_clone_apply_interface_alternate_endpoints(interface, alternates[interface], 1);
    }
    medius_clone_parse_configuration_reports(0);
    medius_usb_register_clone_endpoints();
    if (any_interface_selected) {
        int count = USB_INTERFACE_COUNT;
        if (count <= 0) {
            report_refresh_poll_timing(REPORT_BLOCK0_INTERFACE);
        } else {
            bool presence_changed = false, endpoint_changed = false;
            for (int interface = 0; interface < count; ++interface) {
                unsigned int id = REPORT_CAPTURE_INTERFACE_IDS[interface];
                if (!alternate_interface_selected(selection, id))
                    continue;
                unsigned int previous = scratch.bytes[interface];
                unsigned int next = USB_INTERFACE_ENDPOINTS[interface];
                presence_changed |= (previous == 0) != (next == 0);
                endpoint_changed |= previous != next;
            }
            if (presence_changed)
                clone_refresh_report_bindings(0, 1);
            else
                report_refresh_poll_timing(REPORT_BLOCK0_INTERFACE);
            if (endpoint_changed) {
                motion_configuration_changed();
                input_refresh_endpoint_priorities();
            }
        }
    }
    for (unsigned int interface = 0; interface < 256; ++interface) {
        if (alternate_interface_selected(selection, interface))
            medius_clone_apply_interface_alternate_endpoints(interface, alternates[interface], 2);
    }

    unsigned long long resume_time = (unsigned long long)esp_timer_get_time();
    (void)xPortEnterCriticalTimeout(&CREDIT_LOCK, -1);
    bool migrated_pending = false;
    for (int interface = 0; interface < USB_INTERFACE_COUNT; ++interface) {
        unsigned int id = REPORT_CAPTURE_INTERFACE_IDS[interface];
        if (!alternate_interface_selected(selection, id))
            continue;
        unsigned int previous = scratch.bytes[interface] & 15U;
        unsigned int endpoint = USB_INTERFACE_ENDPOINTS[interface];
        unsigned int next = endpoint & 15U;
        if (previous != 0 && next != 0) {
            if (previous == next) {
                alternate_clear_interface_gates(interface);
            } else {
                unsigned int pending = MEDIUS_REPORT_PENDING_ENDPOINTS;
                if ((pending & (1U << previous)) == 0) {
                    alternate_clear_interface_gates(interface);
                } else {
                    unsigned char bucket = MEDIUS_REPORT_PENDING_BUCKETS[previous];
                    memw();
                    REPORT_SUBMIT_BLOCKED_WRITABLE[interface] = 0;
                    MEDIUS_REPORT_PENDING_BUCKETS[next] = bucket;
                    memw();
                    REPORT_SERVICE_ACTIVE[interface] = 0;
                    MEDIUS_REPORT_PENDING_ENDPOINTS = pending | (1U << next);
                    memw();
                    REPORT_INTERFACE_BLOCKED[interface] = 0;
                    migrated_pending = true;
                }
            }
        } else {
            alternate_clear_interface_gates(interface);
            if (endpoint == 0) {
                report_discard_interface_pending(interface, 1);
                continue;
            }
        }
        memw();
        if (USB_SUSPENDED == 0) {
            volatile CreditInterfaceQueue *queue = (volatile void *)
                ((unsigned int)(uintptr_t)REPORT_HISTORY_QUEUES +
                 (unsigned int)interface * 960U);
            if (queue->extra_pending == 0 && queue->record_count != 0) {
                unsigned short period = REPORT_INTERFACE_PERIODS[interface];
                report_schedule_candidate((CreditInterfaceQueue *)queue,
                    resume_time, resume_time, period, interface, 0);
            }
        }
    }
    for (unsigned int slot = 0; slot < 5; ++slot) {
        memw();
        MEDIUS_REPORT_SECONDARY_BLOCKED_WRITABLE[slot] = 0;
    }
    int binding_count = CREDIT_BINDINGS.count;
    memw();
    MEDIUS_REPORT_SECONDARY_BLOCKED_WRITABLE[5] = 0;
    if (binding_count > 0) {
        int index = 0;
        do {
            if (CREDIT_BINDING_RECORDS[index].queue_slot < 6)
                report_pump_secondary(index);
            ++index;
        } while (index < CREDIT_BINDINGS.count);
    }
    vPortExitCritical(&CREDIT_LOCK);
    if (migrated_pending) {
        memw();
        *CREDIT_DIRTY = 1;
        link_kick_fast_tx();
    }
    out_drain_all_served_endpoints();
    memw();
    MEDIUS_CLONE_ALTERNATE_TRANSITION_BLOCK = 0;
}
