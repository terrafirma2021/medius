/* Medius v3.4.7 device — string and special descriptor responses. */
#include "../include/types.h"

/* Native entry: 0x40395694. */
/* Original function-byte SHA-256:
 * 146dc1719c3b9c8db784ed5832b608aabc86eaa5049314f6be8004e81885b3a7. */
/*
 * Handle string/type3, device-qualifier/type6 and other-speed/type7 descriptors.
 * bus contributes its low BYTE only to the type6/7 policy delegate; string
 * forwarding uses bus0. setup is borrowed, data/length are writable pointer/WORD
 * slots. Return1 for another descriptor type without touching those slots,
 * 0 for a local/forwarded answer, or -1 for a refused/failed request. Failure
 * generally leaves output length unchanged. Read descriptor type BYTE before
 * descriptor index BYTE; cache *data once for every string response below.
 *
 * Nonzero string indices first search served kind3 patches. Read payload offset
 * before configured length; convert at most126 nonzero ASCII BYTEs to UTF-16LE,
 * storing each zero HIGH BYTE before its character LOW BYTE. Local answers have
 * no wLength/capacity clamp or NULL-output guard. Empty patches produce02,03.
 * Otherwise scan raw records with a cached HALFWORD table length, unchecked
 * 16-bit wrapping record cursor and payload-length-before-bounds reads. Match
 * language HIGH then LOW unless index0/EE ignores language. Nonzero action
 * refuses. Index0 can synthesize04,03,09,04 when any served kind3 patch exists;
 * a raw action0 reply longer than2 takes precedence over that language list.
 *
 * Missing local answers forward an8-byte SETUP snapshot with wLength capped255.
 * Snapshot configured state, consult the unconfigured-refusal latch, check
 * quiescing, publish busy, THEN snapshot request generation. After idle wait and
 * generation gate, publish sequence/status/cancel/waiting, send opcode0x13 and
 * wait700 RTOS ticks. Keep both cancellation observations: a fresh cancel after
 * waiting is cleared forces status-1 even when the first cancel read was zero.
 *
 * Success copies min(received,255) into the cached output, or accepts length0
 * when it is NULL; capture uses the ORIGINAL SETUP, then publishes output length.
 * Failed completed waits capture flag1; stale/cancelled/early exits do not capture.
 * Failed unconfigured requests set the refusal latch unless latest status low8
 * equalsFD. No handler-consumed/stall helper, elapsed stats, retry, length-override
 * flag or rollback is supplied. Native access widths, fresh reads and fences are
 * retained; configuration/pointer lifetime and serialization remain external.
 */
int medius_ep0_get_special_descriptor(unsigned char bus,
    const MediusUsbSetupPacket *setup, unsigned char **data, unsigned int *length)
{
    const volatile unsigned char *setup_bytes = setup->bytes;
    unsigned int descriptor_type = setup_bytes[3];
    unsigned int descriptor_index = setup_bytes[2];
    if (descriptor_type == 6)
        return medius_ep0_apply_descriptor_policy(bus, setup, data, length, 0);
    if (descriptor_type == 7)
        return medius_ep0_apply_descriptor_policy(bus, setup, data, length, 1);
    if (descriptor_type != 3)
        return 1;
    unsigned char *payload = *(unsigned char *volatile *)data;
    volatile unsigned int *length_slot = length;
    const volatile DescriptorPatchTable *served = DESCRIPTOR_PATCH_SERVED;
    if (descriptor_index != 0) {
        unsigned int patch_count = served->count;
        for (unsigned int index = 0; index != patch_count; ++index) {
            const volatile DescriptorPatchRecord *patch = &served->records[index];
            if (patch->kind != 3 || patch->descriptor_index != descriptor_index)
                continue;
            unsigned int payload_offset = patch->payload_offset;
            unsigned int configured_length = patch->length;
            const volatile unsigned char *ascii = served->payload + payload_offset;
            volatile unsigned char *output = payload;
            if (configured_length == 0) {
                output[0] = 2;
                output[1] = 3;
                *length_slot = 2;
                return 0;
            }
            unsigned int characters = 0;
            unsigned int remaining = 126;
            for (;;) {
                unsigned int character = ascii[characters];
                if (character == 0)
                    break;
                characters = (unsigned short)(characters + 1U);
                if (characters == configured_length)
                    break;
                if (--remaining == 0)
                    break;
            }
            output[0] = (unsigned char)((characters + 1U) * 2U);
            output[1] = 3;
            for (unsigned int index = 0; index != characters; ++index) {
                unsigned int character = ascii[index];
                output[3 + index * 2U] = 0;
                output[2 + index * 2U] = (unsigned char)character;
            }
            unsigned int copied = characters == 0 ? 2 : output[0];
            *length_slot = copied;
            return 0;
        }
    }
    unsigned int language_high = setup_bytes[5];
    unsigned int language_low = setup_bytes[4];
    unsigned int language = language_low | (language_high << 8);
    unsigned int table_length = MEDIUS_STRING_OVERRIDE_TABLE->length;
    bool ignore_language = descriptor_index == 0 || descriptor_index == 0xee;
    bool found_raw = false;
    unsigned int raw_action = 0;
    unsigned int raw_length = 0;
    const unsigned char *raw_payload = NULL;
    if (table_length >= 5) {
        unsigned int offset = 0;
        do {
            const volatile MediusStringOverrideRecord *record =
                (const volatile MediusStringOverrideRecord *)(MEDIUS_STRING_OVERRIDE_TABLE->records + offset);
            unsigned int record_length = record->length;
            unsigned int end = offset + 5U + record_length;
            if (end > table_length)
                break;
            if (record->index == descriptor_index) {
                bool language_matches = true;
                if (!ignore_language) {
                    unsigned int high = record->language_high;
                    unsigned int low = record->language_low;
                    language_matches = (low | (high << 8)) == language;
                }
                if (language_matches) {
                    raw_payload = (const unsigned char *)record->payload;
                    raw_action = record->action;
                    raw_length = record_length;
                    found_raw = true;
                    break;
                }
            }
            offset = (unsigned short)end;
        } while (offset + 4U < table_length);
    }
    if (descriptor_index == 0) {
        if (found_raw && raw_action == 0 && raw_length > 2)
            goto serve_raw;
        unsigned int patch_count = served->count;
        for (unsigned int index = 0; index != patch_count; ++index) {
            if (served->records[index].kind == 3) {
                memcpy(payload, MEDIUS_CLONE_ENGLISH_LANGUAGE_DESCRIPTOR, 4);
                *length_slot = 4;
                return 0;
            }
        }
    }
    if (found_raw) {
serve_raw:
        if (raw_action != 0)
            return -1;
        memcpy(payload, raw_payload, raw_length);
        *length_slot = raw_length;
        return 0;
    }

    int configured = usb_device_is_configured(0);
    if (configured == 0) {
        memw();
        if (MEDIUS_EP0_UNCONFIGURED_DESCRIPTOR_REFUSED != 0)
            return -1;
    }
    MediusUsbSetupPacket original;
    memcpy(&original, setup, 8);
    MediusUsbSetupPacket request;
    request.words[1] = original.words[1];
    request.words[0] = original.words[0];
    if (request.length > 255)
        request.length = 255;
    memw();
    if (MEDIUS_EP0_REPLY_LIFETIME->quiescing != 0)
        goto refuse_unconfigured;
    memw();
    MEDIUS_EP0_REPLY_CHANNEL->ep0_worker_busy = 1;
    memw();
    unsigned int generation = MEDIUS_EP0_REPLY_LIFETIME->request_generation;
    control_wait_idle_50ms();
    memw();
    if (MEDIUS_EP0_REPLY_LIFETIME->quiescing != 0)
        goto clear_busy_and_refuse;
    if (control_forward_acquire_generation(generation) == 0)
        goto clear_busy_and_refuse;
    memw();
    unsigned char sequence = MEDIUS_EP0_REPLY_CHANNEL->sequence;
    sequence = (unsigned char)(sequence + 1U);
    memw();
    MEDIUS_EP0_REPLY_CHANNEL->sequence = sequence;
    memcpy(MEDIUS_EP0_REQUEST_BUFFER, &request, 8);
    RtosQueue *reply_signal = MEDIUS_EP0_REPLY_CHANNEL->signal;
    memw();
    MEDIUS_EP0_REPLY_STORAGE->status = -1;
    xQueueSemaphoreTake(reply_signal, 0);
    memw();
    MEDIUS_EP0_REPLY_LIFETIME->cancelled = 0;
    memw();
    MEDIUS_EP0_REPLY_CHANNEL->waiting = 1;
    memw();
    if (DEVICE_OUT_GENERATION != generation) {
        memw();
        MEDIUS_EP0_REPLY_CHANNEL->waiting = 0;
        RtosQueue *gate = CONTROL_FORWARD_GATE;
        if (gate != NULL)
            xQueueGenericSend(gate, NULL, 0, 0);
        goto clear_busy_and_refuse;
    }
    link_send_wait100(0x13, sequence, MEDIUS_EP0_REQUEST_BUFFER, 8);
    RtosQueue *gate = CONTROL_FORWARD_GATE;
    if (gate != NULL)
        xQueueGenericSend(gate, NULL, 0, 0);
    int wait_result = xQueueSemaphoreTake(MEDIUS_EP0_REPLY_CHANNEL->signal, 700);
    memw();
    if (DEVICE_OUT_GENERATION != generation)
        goto stale_or_cancelled;
    memw();
    unsigned int cancelled = MEDIUS_EP0_REPLY_LIFETIME->cancelled;
    if (cancelled != 0)
        goto stale_or_cancelled;
    memw();
    MEDIUS_EP0_REPLY_CHANNEL->waiting = (unsigned char)cancelled;
    memw();
    if (MEDIUS_EP0_REPLY_LIFETIME->cancelled != 0) {
        memw();
        MEDIUS_EP0_REPLY_LIFETIME->cancelled = (unsigned char)cancelled;
        memw();
        MEDIUS_EP0_REPLY_STORAGE->status = -1;
    }
    if (wait_result != 1)
        goto failed_completed_wait;
    memw();
    if (MEDIUS_EP0_REPLY_STORAGE->status != 0)
        goto failed_completed_wait;
    unsigned int copied = 0;
    if (payload != NULL) {
        memw();
        unsigned int received = MEDIUS_EP0_REPLY_STORAGE->length;
        copied = received < 255 ? received : 255;
        memcpy(payload, MEDIUS_EP0_REPLY_STORAGE->payload, copied);
    }
    memw();
    MEDIUS_EP0_REPLY_CHANNEL->ep0_worker_busy = 0;
    medius_capture_nonzero_control(0, original.bytes, 0, 0, payload, (unsigned short)copied);
    *length_slot = copied;
    return 0;

failed_completed_wait:
    memw();
    MEDIUS_EP0_REPLY_CHANNEL->ep0_worker_busy = 0;
    if (configured == 0) {
        memw();
        if (((unsigned int)MEDIUS_EP0_REPLY_STORAGE->status & 255U) != 253) {
            memw();
            MEDIUS_EP0_UNCONFIGURED_DESCRIPTOR_REFUSED = 1;
        }
    }
    medius_capture_nonzero_control(0, original.bytes, 0, 1, NULL, 0);
    return -1;

stale_or_cancelled:
    memw();
    MEDIUS_EP0_REPLY_CHANNEL->waiting = 0;
    memw();
    if (MEDIUS_EP0_REPLY_LIFETIME->cancelled != 0) {
        memw();
        MEDIUS_EP0_REPLY_LIFETIME->cancelled = 0;
        memw();
        MEDIUS_EP0_REPLY_STORAGE->status = -1;
    }
clear_busy_and_refuse:
    memw();
    MEDIUS_EP0_REPLY_CHANNEL->ep0_worker_busy = 0;
refuse_unconfigured:
    if (configured == 0) {
        memw();
        if (((unsigned int)MEDIUS_EP0_REPLY_STORAGE->status & 255U) != 253) {
            memw();
            MEDIUS_EP0_UNCONFIGURED_DESCRIPTOR_REFUSED = 1;
        }
    }
    return -1;
}
