/* Medius v3.4.7 host: recovered link credit accounting.
 * Native addresses and firmware-byte hashes are retained for each function.
 */

#include "../include/types.h"

/* Native entry: 0x40376e14. */
/* Original function-byte SHA-256:
 * 0fb4bbce59c88463b1c9969a47d0a6516788b9368f108860cc263c39dfcc5911. */

/*
 * unused_flags and unused_has_counted_pending: ignored direct-callback words.
 * payload: readable input, borrowed through memcpy; must not overlap destination.
 * length: only low16 is considered, then clamped to64 bytes.
 * Returns1 unconditionally, consuming this direct frame even for length0.
 *
 * Under the credit lock, if old length is1..64, saves bit0 from each complete
 * old record, ORed by endpoint low nibble; both old header count and byte length
 * limit traversal. Copies exactly min(low16(length),64), preserving the suffix.
 * Reads the resulting count byte even for zero copy. For each COMPLETE new
 * record, ORs the saved endpoint bit into its flags, retaining all incoming
 * flag bits. Publishes16-bit copied length and unlocks. Incomplete trailing
 * record bytes are neither interpreted nor cleared; no minimum header length,
 * endpoint-direction check, sequence validation or packet-count consistency.
 *
 * After unlock loads the credit task handle; if non-NULL gives notification
 * index0 with the ISR API and a zeroed wake output, yielding only when that
 * output becomes nonzero. No notification status gate or delivery guarantee.
 * Requires valid initialized storage/lock and a context compatible with those
 * APIs. The fourth incoming word is unused but is part of the registered ABI.
 * Zero-length input clears pending length while retaining old packet bytes.
 */
int medius_credit_receive(unsigned int unused_flags, const unsigned char *payload,
    unsigned int length, int unused_has_counted_pending)
{
    (void)unused_flags;
    (void)unused_has_counted_pending;
    unsigned int copied = length & 0xffffU;
    if (copied > 64)
        copied = 64;
    unsigned char saved_flags[16] = {0};
    xPortEnterCriticalTimeout(&CREDIT_LOCK, 0xffffffffU);
    volatile CreditPacket *pending = MEDIUS_CREDIT_PENDING_PACKET;
    unsigned int old_length = MEDIUS_CREDIT_PENDING_LENGTH;
    if (((old_length - 1U) & 0xffffU) < 64U) {
        unsigned int old_count = pending->record_count;
        unsigned int complete_records = (old_length - 1U) / 4U;
        for (unsigned int i = 0; i < old_count && i < complete_records; ++i) {
            unsigned int endpoint = pending->records[i].endpoint & 15U;
            unsigned int flags = pending->records[i].flags;
            saved_flags[endpoint] |= flags & 1U;
        }
    }
    memcpy((void *)pending, payload, copied);
    unsigned int new_count = pending->record_count;
    for (unsigned int i = 0; i < new_count && 4U + 4U * i < copied; ++i) {
        unsigned int endpoint = pending->records[i].endpoint & 15U;
        unsigned char flags = pending->records[i].flags;
        pending->records[i].flags = flags | saved_flags[endpoint];
    }
    MEDIUS_CREDIT_PENDING_LENGTH = (unsigned short)copied;
    vPortExitCritical(&CREDIT_LOCK);
    RtosTask *task = MEDIUS_CREDIT_TASK;
    if (task != NULL) {
        int higher_priority_woken = 0;
        vTaskGenericNotifyGiveFromISR(task, 0, &higher_priority_woken);
        if (higher_priority_woken != 0)
            _frxt_setup_switch();
    }
    return 1;
}
