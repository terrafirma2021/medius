/* Device input change sequence, commit epoch and timestamp. */

#include "../include/types.h"

/* Native entry: 0x420389c8. */
/* Original function-byte SHA-256:
 * 1ccd0de0a6ba5333d33b15456b7efc4b5aeab7dac037ea52f0aeb6c058bfe024. */
/* MEMW/read the primary emission-count WORD and return its raw 32-bit value.
 * No reset, atomic operation, mutex or cross-field snapshot is performed. */
unsigned int input_emission_count(void)
{
    memw();
    return PRIMARY_INPUT_EMISSIONS;
}

/* Native entry: 0x420389e8. */
/* Original function-byte SHA-256:
 * c5a55af4a6d55b42ec0af7b81a6f1b3130c890484a28c632ad8c68990413aeab. */
/* A nonzero increment_sequence BYTE calls the native atomic-add boundary
 * with sequence address,1 and memory-model5; ignore its previous-value result.
 * Take the initially sampled rewrite mutex indefinitely if present, ignoring
 * status. Read clock once; MEMW/store LOW then MEMW/store HIGH into change time.
 * Reload mutex BEFORE clearing committed BYTE, then give that saved nonnull
 * handle. Initial and release handles can differ. No result or epoch update.
 * Raw Ghidra duplicated timestamp writes after release; native has only these
 * two ordered stores and retains the saved timestamp solely in dead registers. */
void input_begin_change(unsigned char increment_sequence)
{
    if (increment_sequence != 0)
        atomic_fetch_add_u32(&INPUT_CHANGE_SEQUENCE,1,5);
    RtosQueue *mutex = REWRITE_MUTEX;
    if (mutex != NULL)
        xQueueSemaphoreTake(mutex,0xffffffffU);
    unsigned long long now = (unsigned long long)esp_timer_get_time();
    memw();
    INPUT_CHANGE_TIME.low = (unsigned int)now;
    memw();
    INPUT_CHANGE_TIME.high = (unsigned int)(now >> 32);
    mutex = REWRITE_MUTEX;
    INPUT_CHANGE_COMMITTED = 0;
    if (mutex != NULL)
        xQueueGenericSend(mutex,NULL,0,0);
}

/* Native entry: 0x42038a40. */
/* Original function-byte SHA-256:
 * f8cc174a776154c727dc569ad27eb2371e8440f2933b32a5f85b7469a9ae5c75. */
/* Call the native atomic-add boundary with sequence address,1,memory-model5.
 * Discard returned previous value. No clock, mutex, epoch or committed flag
 * is touched by this wrapper; the callee owns the atomic operation. */
void input_advance_change_sequence(void)
{
    atomic_fetch_add_u32(&INPUT_CHANGE_SEQUENCE,1,5);
}

/* Native entry: 0x42038a54. */
/* Original function-byte SHA-256:
 * 0b143bac23d4475c5bbc85fad78adcee973f5cb488816f38799e5797e1222e49. */
/* Take optional rewrite mutex indefinitely; ignore result. Two MEMWs precede
 * the sequence WORD snapshot; a third precedes committed BYTE read. If that
 * byte is 0, increment epoch HALFWORD modulo 65536. Snapshot release mutex BEFORE
 * storing committed=1 and acknowledging the SAVED sequence WORD, then give that
 * saved handle only if nonnull. Repeated commits leave epoch unchanged until
 * begin-change clears committed. No timestamp, sequence increment or status.
 * Handles may differ across take/give; no independent lifetime guard exists. */
void input_commit_change(void)
{
    RtosQueue *mutex = REWRITE_MUTEX;
    if (mutex != NULL)
        xQueueSemaphoreTake(mutex,0xffffffffU);
    memw();
    memw();
    unsigned int sequence = INPUT_CHANGE_SEQUENCE;
    memw();
    if (INPUT_CHANGE_COMMITTED == 0)
        INPUT_CHANGE_EPOCH = (unsigned short)(INPUT_CHANGE_EPOCH + 1U);
    mutex = REWRITE_MUTEX;
    INPUT_CHANGE_COMMITTED = 1;
    INPUT_CHANGE_ACKNOWLEDGED = sequence;
    if (mutex != NULL)
        xQueueGenericSend(mutex,NULL,0,0);
}

/* Native entry: 0x42038aa0. */
/* Original function-byte SHA-256:
 * bf4b54bfd7b0e4d90b9b66e5527c917fcd8e54a4c94c565ca27d9abeb83bff63. */
/* Return epoch HALFWORD, zero-extended. If initial rewrite mutex is absent,
 * read it directly. Otherwise take indefinitely ignoring result, RELOAD mutex
 * BEFORE reading epoch, then give that saved nonnull handle. Return the saved
 * value even if release changes epoch. No explicit MEMW or status; take/give
 * handles may differ and a newly null release handle is skipped. */
unsigned short input_change_epoch(void)
{
    RtosQueue *mutex = REWRITE_MUTEX;
    if (mutex == NULL)
        return INPUT_CHANGE_EPOCH;
    xQueueSemaphoreTake(mutex,0xffffffffU);
    mutex = REWRITE_MUTEX;
    unsigned short epoch = INPUT_CHANGE_EPOCH;
    if (mutex != NULL)
        xQueueGenericSend(mutex,NULL,0,0);
    return epoch;
}
