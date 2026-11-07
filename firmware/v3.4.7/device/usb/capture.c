/* Medius v3.4.7 device — usb/capture.c.
 * Recovered C and native assembly, grouped for source navigation.
 * Original entry addresses, firmware-byte hashes and function comments follow.
 */

#include "../include/types.h"

/* Native entry: 0x40392f38. */
/* Original function-byte SHA-256:
 * 0d6227c2b7f583b6b834af9ece3f2fe90edfcb3b8d0f1993998bf43ec9fecf60. */

/*
 * traffic_class: Full 32-bit class selecting the capture ring.
 * subscribers: 32-bit mask selecting per-subscriber drop counters.
 * Returns: 1 when admission is permitted; 0 after accounting a full-ring drop.
 *
 * Returns1 for classes<4 or10 without reading rings. Otherwise selects ring2
 * for8/11,ring3 for7,ring1 for all others, reads used THEN capacity without
 * fencing/locking, and returns1 only for used<capacity. No reservation/consume,
 * task-presence check, clock read, rate period or timed quota exists here.
 *
 * Rejection fences/read/increments/fences/writes the32-bit total-drop counter.
 * For each selected subscriber0..31: fence/read16-bit guard; if not65535,
 * fence/RE-READ current value, increment modulo16, fence/store. This saturates
 * only with stable state: a second read65535 after a nonsaturated guard wraps.
 * Counters are not locked here. Requires live initialized storage and external
 * serialization for coherent ring/counter observations; zero capacity rejects.
 */
int medius_capture_ring_has_room(unsigned int traffic_class,unsigned int subscribers)
{
    if (traffic_class < 4 || traffic_class == 10)
        return 1;
    unsigned int ring_index = traffic_class == 8 || traffic_class == 11 ? 2 :
                              traffic_class == 7 ? 3 : 1;
    unsigned int used = MEDIUS_CAPTURE_RINGS[ring_index].used;
    unsigned int capacity = MEDIUS_CAPTURE_RINGS[ring_index].capacity;
    if (used < capacity)
        return 1;
    memw();
    unsigned int total = CAPTURE_TOTAL_DROPS;
    memw();
    CAPTURE_TOTAL_DROPS = total + 1U;
    for (unsigned int subscriber = 0; subscriber < 32; ++subscriber) {
        if ((subscribers & (1U << subscriber)) == 0)
            continue;
        memw();
        unsigned int guard = CAPTURE_SUBSCRIBER_DROPS[subscriber];
        if (guard == 65535)
            continue;
        memw();
        unsigned short next = (unsigned short)(CAPTURE_SUBSCRIBER_DROPS[subscriber] + 1U);
        memw();
        CAPTURE_SUBSCRIBER_DROPS[subscriber] = next;
    }
    return 0;
}

/* Native entry: 0x40392fc4. */
/* Original function-byte SHA-256:
 * 0b548e1aaf25d9a1ea0bc69420b74eaa43f7e423d5a61d03b24e5b0bcb6f0660. */

/*
 * event: Borrowed writable output, aligned to 4 bytes; 88-byte view with 86 used bytes.
 * traffic_class: Full word for rule equality; the enabled-mask test uses its low 5 bits.
 * subtype: Low 16 bits ORed with (traffic_class << 8), without masking subtype to a byte.
 * endpoint: Full word for rule matching; the output records its low byte.
 * flags: Byte copied into the wire header.
 * source_stamp: Opaque 32-bit value emitted as low halfword, byte 2, then byte 3.
 * payload: Borrowed source; may be NULL, including when the effective length is nonzero.
 * length: Unsigned 16-bit source length; its low byte is recorded before truncation.
 * Returns: Nothing. event->ready distinguishes an admitted record from rejection.
 *
 * Fence/read bank index, fence/read16-bit enabled classes, THEN reset ready0.
 * Cache bank index/count; consider only rule kinds0/1. Scores: exact class plus
 * exact endpoint=4/5; exact class plus endpointFFFF=2/3; wildcard classFF=0/1,
 * IGNORING that rule's endpoint when class differs. Equal scores keep FIRST.
 * Query classFF is exact for anFF rule, so endpoint checks still apply then.
 * Rule count is unchecked; nominal bank stride260 holds43 six-byte rules.
 * Chosen index becomes bit(index&31), so indices>=32 alias subscribers.
 * Cache selected byte payload limit BEFORE room check; zero means unlimited.
 * Room check is a capacity hint with drop side effects, not a rate token.
 *
 * On admission: store packed class/subtype and low8 ORIGINAL length, apply
 * nonzero rule limit then64-byte cap, emit source stamp/subscriber mask/header,
 * optionally copy, publish wire_length=12+copied then ready1. Nonzero effective
 * length with NULL payload SKIPS copy but still advertises that length/ready1;
 * old payload bytes remain. No whole-event/padding clearing, quota consumption,
 * lock, notification, pointer/index repair or coherent configuration snapshot.
 * Caller supplies accessible bank/output/source storage and serialized config;
 * output must not overlap a non-NULL copied source.
 */
void capture_event_build(CaptureEvent *event,unsigned int traffic_class,
    unsigned short subtype,unsigned int endpoint,unsigned char flags,
    unsigned int source_stamp,const unsigned char *payload,unsigned short length)
{
    memw();
    unsigned int bank_index = CAPTURE_ACTIVE_BANK;
    memw();
    unsigned int enabled = CAPTURE_ENABLED_CLASSES;
    volatile CaptureEvent *out = event;
    out->ready = 0;
    if ((enabled & (1U << (traffic_class & 31U))) == 0)
        return;
    const volatile MediusCaptureSubscriptionBank *bank = &MEDIUS_CAPTURE_BANKS[bank_index];
    unsigned int count = bank->count;
    unsigned int selected = 0xffffffffU;
    int best_score = -1;
    for (unsigned int index = 0; index < count; ++index) {
        const volatile MediusCaptureRule *rule = &bank->rules[index];
        unsigned int kind = rule->kind;
        if (kind > 1)
            continue;
        unsigned int rule_class = rule->traffic_class;
        int score;
        if (rule_class == traffic_class) {
            unsigned int rule_endpoint = rule->endpoint;
            if (rule_endpoint == endpoint)
                score = 4 + kind;
            else if (rule_endpoint == 65535)
                score = 2 + kind;
            else
                continue;
        } else if (rule_class == 255) {
            score = kind;
        } else {
            continue;
        }
        if (score > best_score) {
            best_score = score;
            selected = index;
        }
    }
    unsigned short packed_type = (unsigned short)(subtype | (traffic_class << 8));
    if (selected == 0xffffffffU)
        return;
    unsigned int subscribers = 1U << (selected & 31U);
    unsigned int payload_limit = bank->rules[selected].payload_limit;
    if (medius_capture_ring_has_room(traffic_class,subscribers) == 0)
        return;
    out->wire.subtype_and_class = packed_type;
    out->wire.original_length = (unsigned char)length;
    unsigned int effective = length;
    if (payload_limit != 0 && payload_limit < effective)
        effective = payload_limit;
    unsigned int copied = effective < 64 ? effective : 64;
    out->wire.stamp_low = (unsigned short)source_stamp;
    out->subscriptions = subscribers;
    out->wire.stamp_byte2 = (unsigned char)(source_stamp >> 16);
    out->wire.stamp_byte3 = (unsigned char)(source_stamp >> 24);
    out->wire.endpoint = (unsigned char)endpoint;
    out->wire.reserved7 = 0;
    out->wire.version = 1;
    out->wire.flags = flags;
    out->wire.reserved11 = 0;
    if (effective != 0 && payload != NULL)
        memcpy((void *)out->wire.payload,payload,copied);
    out->wire_length = (unsigned short)(copied + 12U);
    out->ready = 1;
}

/* Native entry: 0x40392c98. */
/* Original function-byte SHA-256:
 * c7f218525c35b7a51bb746d860883c6e3d4098dc270a72c3a00d7f3e43f92351. */

/*
 * traffic_class: Full word selecting the ring and payload copy limit.
 * subscribers: Drop-accounting mask; omitted from the four-byte queue header.
 * record_kind: Byte stored at the start of the queued record.
 * wire: Borrowed memcpy source, including for a zero-length call; must meet memcpy's
 *   access and non-overlap requirements.
 * length: Unsigned 32-bit input length, capped according to the selected ring.
 * Returns: 1 on normal enqueue or ring 0 overwrite; 0 on missing task or another full ring.
 * Does not notify capture task; successful callers may call notify_task.
 *
 * Reads task handle once before class selection. Ring0(classes<4 or10) caps128;
 * ring2(8/11)caps192; ring3(7) andring1(other)caps76. Builds kind,zero,length16,
 * copied payload BEFORE context query/lock. Context-query results are ignored.
 * Under capture lock, tests used==capacity, not>=. Ring0 on equality stores
 * low16(capacity-1) as used and overwrites oldest; others reject after unlock.
 * Captures write index/item stride/storage before copy, then rereads capacity
 * andused after copy, retaining their native per-ring order. Publishes next
 * index=(cached_index+1)%current_capacity andlow16(current_used+1) in ONE32-bit
 * packed store. No read-index field is maintained by this routine.
 *
 * Missing task/full rejection counts a drop and returns0; overwrite counts a
 * drop AFTER unlock and returns1. Subscriber drops use THIS request's mask,
 * not the overwritten record's recipients. Fenced guard/fresh-read increments
 * skip first snapshot65535 but can wrap under mutation, as in room check.
 * Requires nonzero capacity,valid storage/index/item_size large enough for
 * header+copy,live kernel/task and serialized reconfiguration. Does not validate
 * stride,bounds,task lifetime or pointer,clear unused bytes,reserve quotas or
 * prove delivery. Used>capacity bypasses equality rejection; no repair added.
 */
unsigned int capture_submit_event(unsigned int traffic_class,
    unsigned int subscribers,unsigned char record_kind,const void *wire,unsigned int length)
{
    RtosTask *task = CAPTURE_TASK;
    unsigned int accepted = 0;
    if (task == NULL)
        goto account_drop;
    unsigned int ring_index;
    unsigned int limit;
    if (traffic_class < 4 || traffic_class == 10) {
        ring_index = 0; limit = 128;
    } else if (traffic_class == 8 || traffic_class == 11) {
        ring_index = 2; limit = 192;
    } else {
        ring_index = traffic_class == 7 ? 3 : 1;
        limit = 76;
    }
    unsigned int copied = length < limit ? length : limit;
    MediusCaptureQueuedRecord item __attribute__((aligned(4)));
    item.kind = record_kind;
    item.reserved = 0;
    item.length = (unsigned short)copied;
    memcpy(item.payload,wire,copied);
    xPortInIsrContext();
    xPortEnterCriticalTimeout(&MEDIUS_CAPTURE_LOCK,0xffffffffU);
    volatile MediusCaptureRing *ring = &MEDIUS_CAPTURE_RINGS[ring_index];
    unsigned int used_before = ring->used;
    unsigned int capacity_before = ring->capacity;
    int overwritten = 0;
    if (used_before == capacity_before) {
        if (ring_index != 0) {
            xPortInIsrContext();
            vPortExitCritical(&MEDIUS_CAPTURE_LOCK);
            goto account_drop;
        }
        ring->used = (unsigned short)(capacity_before - 1U);
        overwritten = 1;
    }
    unsigned int write_index = ring->write_index;
    unsigned int item_size = ring->item_size;
    unsigned char *storage = ring->storage;
    memcpy(storage + item_size * write_index,&item,copied + 4U);
    unsigned int used_after,capacity_after;
    if (ring_index == 1 || ring_index == 3) {
        capacity_after = ring->capacity;
        used_after = ring->used;
    } else {
        used_after = ring->used;
        capacity_after = ring->capacity;
    }
    unsigned int next = (write_index + 1U) % capacity_after;
    ring->write_and_used = next | ((used_after + 1U) << 16);
    xPortInIsrContext();
    vPortExitCritical(&MEDIUS_CAPTURE_LOCK);
    if (!overwritten)
        return 1;
    accepted = 1;
account_drop:
    memw();
    unsigned int total = CAPTURE_TOTAL_DROPS;
    memw();
    CAPTURE_TOTAL_DROPS = total + 1U;
    for (unsigned int subscriber = 0; subscriber < 32; ++subscriber) {
        if ((subscribers & (1U << subscriber)) == 0)
            continue;
        memw();
        unsigned int guard = CAPTURE_SUBSCRIBER_DROPS[subscriber];
        if (guard == 65535)
            continue;
        memw();
        unsigned short updated = (unsigned short)(CAPTURE_SUBSCRIBER_DROPS[subscriber] + 1U);
        memw();
        CAPTURE_SUBSCRIBER_DROPS[subscriber] = updated;
    }
    return accepted;
}
