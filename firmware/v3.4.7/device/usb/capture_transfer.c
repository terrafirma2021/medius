/* Medius v3.4.7 device — alternate-setting report/capture support. */
#include "../include/types.h"

/* Native entry: 0x403783a8. */
/* Original function-byte SHA-256:
 * 566c60b83346819e8102689c01eaa0bb6474d1ad51be213af9ce0dbd82c382f5. */
/* Select the first highest-scoring capture rule and queue a kind-0x16 transfer
 * record. Read active-bank BYTE then enabled-class HALFWORD with MEMWs even
 * for rejected classes; only full-word classes 0..11 are accepted here.
 * A zero rule kind matches any source_kind; other kinds require full-word
 * equality. Exact class/endpoint scores 4/5, class/FFFF scores 2/3, and class-FF
 * wildcard scores 0/1 while ignoring that rule's endpoint. Ties keep the first.
 * Trust the bank count; subscriber bit uses index modulo 32.
 *
 * Cache the selected payload limit before the room hint. Limit 0 is unlimited,
 * then cap at 64; advertise low8(original length) independently. A nonzero
 * effective length with NULL payload still submits uninitialized payload bytes.
 * Write original length BYTE, class/subtype HALFWORD, stamp WORD and remaining
 * header BYTEs in native order. Notify only if submit succeeds. No local lock,
 * payload clearing, subscription reservation or delivery guarantee is supplied.
 */
void medius_capture_record_transfer(unsigned int traffic_class,
    unsigned int endpoint, unsigned int source_kind, unsigned char flags,
    unsigned int source_stamp, unsigned int subtype,
    const unsigned char *payload, unsigned short length)
{
    memw();
    unsigned int bank_index = CAPTURE_ACTIVE_BANK;
    memw();
    unsigned int enabled = CAPTURE_ENABLED_CLASSES;
    if (traffic_class >= 12 || (enabled & (1U << traffic_class)) == 0)
        return;

    unsigned int bank_address = 0x3fcc7814U + bank_index * 260U;
    unsigned int count = *(const volatile unsigned char *)(bank_address + 258U);
    unsigned int selected = 0xffffffffU;
    int best_score = -1;
    for (unsigned int index = 0; index < count; ++index) {
        const volatile MediusCaptureRule *rule = (const volatile void *)
            (bank_address + index * 6U);
        unsigned int kind = rule->kind;
        if (kind != 0 && kind != source_kind)
            continue;
        unsigned int rule_class = rule->traffic_class;
        int specific_kind = kind != 0;
        int score;
        if (rule_class == traffic_class) {
            unsigned int rule_endpoint = rule->endpoint;
            if (rule_endpoint == endpoint)
                score = 4 + specific_kind;
            else if (rule_endpoint == 65535)
                score = 2 + specific_kind;
            else
                continue;
        } else if (rule_class == 255) {
            score = specific_kind;
        } else {
            continue;
        }
        if (score > best_score) {
            best_score = score;
            selected = index;
        }
    }
    unsigned short packed_type = (unsigned char)subtype | (traffic_class << 8);
    if (selected == 0xffffffffU)
        return;
    unsigned int subscribers = 1U << (selected & 31U);
    const volatile MediusCaptureRule *rule = (const volatile void *)
        (bank_address + selected * 6U);
    unsigned int limit = rule->payload_limit;
    if (medius_capture_ring_has_room(traffic_class, subscribers) == 0)
        return;

    MediusCaptureTransferWire wire;
    volatile MediusCaptureTransferWire *out = &wire;
    out->original_length = (unsigned char)length;
    unsigned int effective = length;
    if (limit != 0 && limit < effective)
        effective = limit;
    unsigned int copied = effective < 64 ? effective : 64;
    out->subtype_and_class = packed_type;
    out->source_stamp = source_stamp;
    out->endpoint = (unsigned char)endpoint;
    out->reserved7 = 0;
    out->source_kind = (unsigned char)source_kind;
    out->flags = flags;
    out->reserved11 = 0;
    if (effective != 0 && payload != NULL)
        memcpy(wire.payload, payload, copied);
    if (capture_submit_event(traffic_class, subscribers, 0x16, &wire, copied + 12) != 0)
        capture_notify_task();
}
