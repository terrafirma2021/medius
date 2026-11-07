/* Medius v3.4.7 device — alternate endpoint transition/recovery. */
#include "../include/types.h"

/* Native entry: 0x40399f90. */
/* Original function-byte SHA-256:
 * 2fa2e168fc43ec32015b0f4410c3489e1647cdf94081ebba2669968db799759c. */
/* Recover the first served binding whose endpoint BYTE equals the full-width
 * input. Require an IN address, slot < 6 and a nonzero raw in-flight BYTE.
 * Mark queues dirty and clear in-flight, then read DIEPTSIZ before acknowledging
 * DIEPINT bits 0/1. A zero cached packet count copies the saved payload out,
 * marks completion seen, reloads its length after memcpy, and returns the
 * original in-flight BYTE unchanged. Outputs otherwise remain untouched.
 *
 * A nonzero packet count prepends the saved payload to the eight-record ring.
 * Only count == 8 is treated as full, incrementing the shared drop WORD; larger
 * counts are not rejected. Preserve fresh length/count/weight reads, BYTE wrap,
 * and unchecked copy lengths. No lock, controller abort or completion wait is
 * provided; interrupt acknowledgement alone does not establish completion.
 */
unsigned char medius_report_recover_secondary_in(
    unsigned int endpoint, void *output, unsigned char *length_output)
{
    int binding_count = CREDIT_BINDINGS.count;
    for (int index = 0; index < binding_count; ++index) {
        if (CREDIT_BINDING_RECORDS[index].endpoint != endpoint)
            continue;
        if ((endpoint & 0x80U) == 0)
            return 0;
        unsigned int slot = CREDIT_BINDING_RECORDS[index].queue_slot;
        if (slot >= 6)
            return 0;

        memw();
        unsigned char was_in_flight = REPORT_SECONDARY_IN_FLIGHT[slot];
        if (was_in_flight == 0)
            return 0;
        memw();
        REPORT_QUEUES_DIRTY = 1;
        memw();
        REPORT_SECONDARY_IN_FLIGHT[slot] = 0;

        volatile Dwc2InEndpointRegisters *registers =
            &DEVICE_DWC2_IN_REGISTERS[endpoint & 15U];
        memw();
        unsigned int transfer_size = registers->transfer_size;
        memw();
        registers->interrupt_status = 3;

        if (((transfer_size >> 19) & 127U) == 0) {
            unsigned int length = REPORT_SECONDARY_LENGTH[slot];
            memw();
            REPORT_SECONDARY_COMPLETION_SEEN[slot] = 1;
            memcpy(output, REPORT_SECONDARY_STORAGE + slot * 64, length);
            *length_output = REPORT_SECONDARY_LENGTH[slot];
            return was_in_flight;
        }

        memw();
        if (REPORT_SECONDARY_COUNTS[slot] == 8) {
            memw();
            unsigned int drops = REPORT_SECONDARY_FALLBACK_DROPS;
            memw();
            REPORT_SECONDARY_FALLBACK_DROPS = drops + 1;
            return 0;
        }
        memw();
        unsigned int head = REPORT_SECONDARY_HEADS[slot];
        unsigned int new_head = (head + 7) & 7U;
        volatile CreditSecondaryRecord *record =
            &REPORT_SECONDARY_QUEUES[slot].records[new_head];
        unsigned int length = REPORT_SECONDARY_LENGTH[slot];
        memcpy((void *)record->data,
               REPORT_SECONDARY_STORAGE + slot * 64, length);
        memw();
        REPORT_SECONDARY_HEADS[slot] = new_head;
        memw();
        unsigned char count = REPORT_SECONDARY_COUNTS[slot];
        unsigned char fresh_length = REPORT_SECONDARY_LENGTH[slot];
        unsigned char weight = REPORT_SECONDARY_WEIGHT[slot];
        record->length = fresh_length;
        record->credit_marker = weight;
        memw();
        REPORT_SECONDARY_COUNTS[slot] = count + 1;
        return 0;
    }
    return 0;
}
