/* Medius v3.4.7 device: recovered report sequence admission. */

#include "../include/types.h"

/* Native entry: 0x420299c0. */
/* Original function-byte SHA-256:
 * 52532f600e83e71b9e8a6eee2c99c65dda41859658efbe840bbe9d2a76c5b5b5. */

/*
 * endpoint: full comparison word; sequence: incoming byte sequence.
 * Returns 0 when a recent entry blocks this sequence, otherwise 1.
 * Samples LOW32(time) BEFORE taking the sequence lock with infinite timeout;
 * ignores lock status and unlocks every path. No sequence-table writes occur.
 * Cache (latest_sequence - sequence) modulo 256 once after locking. Scan all 16
 * entries until a match: time_low must be nonzero, unsigned LOW32 age < 5000000,
 * and (entry.sequence - sequence - 1) modulo 256 must be below the cached span.
 * Then endpoint 0 or exact full-word endpoint blocks. Timestamps/sequences and
 * endpoints are read conditionally in that order; a zero span still scans.
 * LOW32 time wrapping and byte sequence wrapping are retained; no bounds repair,
 * explicit MEMW, allocation or global scheduling guarantee is supplied here.
 */
int report_sequence_allowed(unsigned int endpoint,unsigned char sequence)
{
    unsigned int now_low = (unsigned int)esp_timer_get_time();
    xPortEnterCriticalTimeout(&REPORT_SEQUENCE_LOCK,0xffffffffU);
    unsigned int sequence_span = (REPORT_SEQUENCE_WINDOW.latest_sequence - sequence) & 255U;
    int admission_allowed = 1;
    for (unsigned int entry_index = 0; entry_index < 16; ++entry_index) {
        unsigned int entry_time_low = REPORT_SEQUENCE_WINDOW.entries[entry_index].time_low;
        if (entry_time_low == 0 || now_low - entry_time_low >= 5000000U)
            continue;
        unsigned int entry_sequence = REPORT_SEQUENCE_WINDOW.entries[entry_index].sequence;
        if (((entry_sequence - sequence - 1U) & 255U) >= sequence_span)
            continue;
        unsigned int entry_endpoint = REPORT_SEQUENCE_WINDOW.entries[entry_index].endpoint;
        if (entry_endpoint == 0 || endpoint == entry_endpoint) {
            admission_allowed = 0;
            break;
        }
    }
    vPortExitCritical(&REPORT_SEQUENCE_LOCK);
    return admission_allowed;
}
