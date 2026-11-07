/* Medius v3.4.7 device: recovered secondary USB report queue policy. */

#include "../include/types.h"

/* Local reconstruction utilities: native tables use unchecked wrapping32
 * binding/slot addresses; only the selected ring index is masked to three bits. */
static inline __attribute__((always_inline)) const volatile CreditBinding *
report_enqueue_binding(unsigned int binding_index)
{
    return (const volatile CreditBinding *)((unsigned int)CREDIT_BINDINGS.entry +
        binding_index * 8U);
}

static inline __attribute__((always_inline)) volatile CreditSecondaryRecord *
report_enqueue_record(unsigned int slot,unsigned int ring_index)
{
    return (volatile CreditSecondaryRecord *)((unsigned int)REPORT_SECONDARY_QUEUES +
        slot * 528U + ring_index * 66U);
}

/* Native entry: 0x4202e26c. */
/* Original function-byte SHA-256:
 * 521b9c83dfb05124acbd7aae699238e61caadee91ac8bb173bf28e0ed1739490. */

/*
 * endpoint: full binding comparison word; report/length: borrowed readable span.
 * kind: capture class is (6 + kind), also controls full-ring rejection.
 * source_stamp: capture stamp; synthetic: byte controlling length/credit policy;
 * flags: capture flags. Returns no value. Copies at most 64 report bytes.
 * Caller must serialize binding/ring configuration and provide valid indices,
 * counts and buffers. Credit-lock acquisition status is ignored; no allocation.
 *
 * Empty input adds flag bit 1. For kind 0/non-synthetic empty input, perform an
 * initial locked lookup: unequal/zero configured packet_length requires empty
 * queue and no in-flight report, otherwise return WITHOUT capture. A nonzero
 * packet_length equal to the saved expected byte permits replacement; it still
 * fences/reads count and, when empty, in-flight, discarding that latter value.
 * Missing/invalid bindings continue to capture and a second independent lookup.
 *
 * Emit capture before the final lock/lookup. Only the first matching IN binding
 * with slot < 6 is used. Full is EXACTLY count == 8: increment secondary drops,
 * then reject nonzero kind or an unapproved empty input. Otherwise discard one
 * head with separate fenced head/count read+stores and mark queues dirty.
 * Counts > 8 are not repaired or treated as full.
 *
 * Non-synthetic input updates expected length. Fence/read head and count, copy
 * into (head+count)&7, then REREAD binding slot. Fence/read that fresh slot's
 * count BEFORE publishing length and credit_marker at the original ring index.
 * Marker is (~synthetic)&1, not (synthetic == 0). Fence/publish fresh count+1
 * and pump the binding index. All fresh slot/count reads and byte wrap remain;
 * no queue acceptance, USB completion or physical timing result is returned.
 */
void report_enqueue_secondary(unsigned int endpoint,unsigned char *report,
    unsigned int length,unsigned int kind,unsigned int source_stamp,
    unsigned char synthetic,unsigned char flags)
{
    unsigned int copy_length = length < 64 ? length : 64;
    unsigned int empty_policy = 0;
    unsigned int replace_empty = 0;
    if (length == 0) {
        flags |= 2U;
        if (kind != 0) {
            empty_policy = kind;
        } else {
            empty_policy = 1;
            if (synthetic == 0) {
                xPortEnterCriticalTimeout(&CREDIT_LOCK,0xffffffffU);
                int binding_count = CREDIT_BINDINGS.count;
                for (int binding_index = 0; binding_index < binding_count; ++binding_index) {
                    const volatile CreditBinding *binding_entry =
                        report_enqueue_binding(binding_index);
                    if (binding_entry->endpoint != endpoint)
                        continue;
                    if ((endpoint & 128U) == 0)
                        break;
                    unsigned int slot = binding_entry->queue_slot;
                    if (slot >= 6)
                        break;
                    unsigned int configured_length = binding_entry->packet_length;
                    if (configured_length == 0 ||
                        REPORT_SECONDARY_EXPECTED_LENGTH[slot] != configured_length) {
                        memw();
                        if (REPORT_SECONDARY_COUNTS[slot] != 0) {
                            vPortExitCritical(&CREDIT_LOCK);
                            return;
                        }
                        memw();
                        if (REPORT_SECONDARY_IN_FLIGHT[slot] != 0) {
                            vPortExitCritical(&CREDIT_LOCK);
                            return;
                        }
                    } else {
                        memw();
                        if (REPORT_SECONDARY_COUNTS[slot] == 0) {
                            memw();
                            (void)REPORT_SECONDARY_IN_FLIGHT[slot];
                        }
                        replace_empty = 1;
                    }
                    break;
                }
                vPortExitCritical(&CREDIT_LOCK);
            }
        }
    }
    capture_emit_raw(6U + kind,endpoint & 15U,1,flags,
        source_stamp,synthetic,report,copy_length);
    xPortEnterCriticalTimeout(&CREDIT_LOCK,0xffffffffU);
    int binding_count = CREDIT_BINDINGS.count;
    for (int binding_index = 0; binding_index < binding_count; ++binding_index) {
        const volatile CreditBinding *binding_entry =
            report_enqueue_binding(binding_index);
        if (binding_entry->endpoint != endpoint)
            continue;
        if ((endpoint & 128U) == 0)
            break;
        unsigned int slot = binding_entry->queue_slot;
        if (slot >= 6)
            break;
        memw();
        if (REPORT_SECONDARY_COUNTS[slot] == 8) {
            memw();
            unsigned int drops = REPORT_SECONDARY_FALLBACK_DROPS;
            memw();
            REPORT_SECONDARY_FALLBACK_DROPS = drops + 1U;
            if (kind != 0 || (replace_empty != 1 && empty_policy != 0))
                break;
            memw();
            unsigned int old_head = REPORT_SECONDARY_HEADS[slot];
            memw();
            REPORT_SECONDARY_HEADS[slot] = (old_head + 1U) & 7U;
            memw();
            unsigned int old_count = REPORT_SECONDARY_COUNTS[slot];
            memw();
            REPORT_SECONDARY_COUNTS[slot] = old_count - 1U;
            memw();
            REPORT_QUEUES_DIRTY = 1;
        }
        if (synthetic == 0)
            REPORT_SECONDARY_EXPECTED_LENGTH[slot] = copy_length;
        memw();
        unsigned int ring_head = REPORT_SECONDARY_HEADS[slot];
        memw();
        unsigned int ring_count = REPORT_SECONDARY_COUNTS[slot];
        unsigned int ring_index = (ring_head + ring_count) & 7U;
        volatile CreditSecondaryRecord *copy_record = report_enqueue_record(slot,ring_index);
        memcpy((void *)copy_record->data,report,copy_length);
        unsigned int final_slot = binding_entry->queue_slot;
        memw();
        unsigned int final_count = REPORT_SECONDARY_COUNTS[final_slot];
        volatile CreditSecondaryRecord *published_record =
            report_enqueue_record(final_slot,ring_index);
        published_record->length = copy_length;
        published_record->credit_marker = (synthetic ^ 255U) & 1U;
        memw();
        REPORT_SECONDARY_COUNTS[final_slot] = final_count + 1U;
        report_pump_secondary(binding_index);
        break;
    }
    vPortExitCritical(&CREDIT_LOCK);
}
