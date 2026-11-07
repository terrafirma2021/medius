/* Recovered byte/WORD atomics with the ESP32-S3 external-RAM workaround. */

#include "../include/types.h"

/* Native entry: 0x4038fadc. */
/* Original function-byte SHA-256:
 * 702c81255282a15e39d9dc034bc656fb25adb3c78689a243359ee1f0c5bd3ea0. */
/*
 * address/expected: valid writable 8-bit objects; desired uses its low 8-bit.
 * For address0x3c000000..0x3dffffff, emulates compare/exchange under the shared
 * atomic mux. Queries ISR context, enters with -1 timeout (results ignored),
 * then MEMW/reads address followed by expected. Equality MEMW/stores desired;
 * mismatch MEMW/REREADS address and publishes that second sample to expected.
 * Returns0/1 from the first comparison after context query/unlock. An uncooperating
 * writer may change the failure sample. Other addresses delegate to S32C1I.
 * weak is narrowed to a BYTE when forwarded; all weak/order inputs are ignored
 * by both implementations. No null/alignment check or selected ordering path.

 * Both borrowed objects stay live through the call. The source has no alias
 * rejection: on failure the destination is reread before writing expected.
 * The unsigned range subtraction wraps at 32 bits; its inclusive test selects
 * exactly 0x3c000000..0x3dffffff. weak occupies a BYTE; ordering arguments
 * occupy signed WORDs. The result is a full WORD containing only 0 or 1.
*/
unsigned int atomic_compare_exchange_byte(volatile unsigned char *address,unsigned char *expected,
    unsigned int desired,unsigned char ignored_weak,int ignored_success_order,int ignored_failure_order)
{
    desired &= 0xffU;
    if ((unsigned int)address - 0x3c000000U > 0x1ffffffU)
        return atomic_compare_exchange_u8_s32c1i(address,expected,desired,
            ignored_weak,ignored_success_order,ignored_failure_order);
    (void)xPortInIsrContext();
    (void)xPortEnterCriticalTimeout(ATOMIC_OPERATION_LOCK,-1);
    memw(); unsigned int observed = *address;
    unsigned int expected_value = *(volatile unsigned char *)expected;
    unsigned int equal = observed == expected_value;
    memw();
    if (equal) *address = desired;
    else *(volatile unsigned char *)expected = *address;
    (void)xPortInIsrContext();
    vPortExitCritical(ATOMIC_OPERATION_LOCK);
    return equal;
}

/* Native entry: 0x4038fb48. */
/* Original function-byte SHA-256:
 * 4b9e266bbd59528b4b74ef0e41fd09633bce8b65cba2697664eb4e550c044f08. */
/*
 * address/expected: valid writable 32-bit objects; desired uses its low 32-bit.
 * For address0x3c000000..0x3dffffff, emulates compare/exchange under the shared
 * atomic mux. Queries ISR context, enters with -1 timeout (results ignored),
 * then MEMW/reads address followed by expected. Equality MEMW/stores desired;
 * mismatch MEMW/REREADS address and publishes that second sample to expected.
 * Returns0/1 from the first comparison after context query/unlock. An uncooperating
 * writer may change the failure sample. Other addresses delegate to S32C1I.
 * weak is narrowed to a BYTE when forwarded; all weak/order inputs are ignored
 * by both implementations. No null/alignment check or selected ordering path.

 * Both borrowed objects stay live through the call. The source has no alias
 * rejection: on failure the destination is reread before writing expected.
 * The unsigned range subtraction wraps at 32 bits; its inclusive test selects
 * exactly 0x3c000000..0x3dffffff. weak occupies a BYTE; ordering arguments
 * occupy signed WORDs. The result is a full WORD containing only 0 or 1.
*/
unsigned int atomic_compare_exchange_u32(volatile unsigned int *address,unsigned int *expected,
    unsigned int desired,unsigned char ignored_weak,int ignored_success_order,int ignored_failure_order)
{
    if ((unsigned int)address - 0x3c000000U > 0x1ffffffU)
        return atomic_compare_exchange_u32_s32c1i(address,expected,desired,
            ignored_weak,ignored_success_order,ignored_failure_order);
    (void)xPortInIsrContext();
    (void)xPortEnterCriticalTimeout(ATOMIC_OPERATION_LOCK,-1);
    memw(); unsigned int observed = *address;
    unsigned int expected_value = *(volatile unsigned int *)expected;
    unsigned int equal = observed == expected_value;
    memw();
    if (equal) *address = desired;
    else *(volatile unsigned int *)expected = *address;
    (void)xPortInIsrContext();
    vPortExitCritical(ATOMIC_OPERATION_LOCK);
    return equal;
}

/* Native entry: 0x4038fbac. */
/* Original function-byte SHA-256:
 * 99cebf47ce7ba4b8defd5c3ae87ddf8c624a55c5f9a618909262e25d88c3c4c4. */
/*
 * For address0x3c000000..0x3dffffff takes the shared atomic mux, MEMW/reads
 * the old WORD, MEMW/stores old + value with32-bit wrap, unlocks and returns
 * the cached old WORD. Both ISR-context queries and the infinite lock entry's
 * result are discarded. Other addresses delegate to the S32C1I retry routine.
 * memory_order does not select instructions; no validation or finite wait.

 * address is borrowed word-aligned writable storage and must remain live;
 * value and result are unsigned WORDs. Input range arithmetic wraps at
 * 32 bits. memory_order is an unused signed WORD, not a timeout or flag.
*/
unsigned int atomic_fetch_add_u32(volatile unsigned int *address,unsigned int value,int ignored_memory_order)
{
    if ((unsigned int)address - 0x3c000000U > 0x1ffffffU)
        return atomic_fetch_add_u32_s32c1i(address,value,ignored_memory_order);
    (void)xPortInIsrContext();
    (void)xPortEnterCriticalTimeout(ATOMIC_OPERATION_LOCK,-1);
    memw(); unsigned int old_value = *address;
    memw(); *address = old_value + value;
    (void)xPortInIsrContext();
    vPortExitCritical(ATOMIC_OPERATION_LOCK);
    return old_value;
}

/* Native entry: 0x4038fbf0. */
/* Original function-byte SHA-256:
 * 0c65ffc7b77af103f84c6c1cc5a96327e60077e1f32d2e2746b94c26eee9f9dd. */
/*
 * For address0x3c000000..0x3dffffff takes the shared atomic mux, MEMW/reads
 * the old WORD, MEMW/stores old - value with32-bit wrap, unlocks and returns
 * the cached old WORD. Both ISR-context queries and the infinite lock entry's
 * result are discarded. Other addresses delegate to the S32C1I retry routine.
 * memory_order does not select instructions; no validation or finite wait.

 * address is borrowed word-aligned writable storage and must remain live;
 * value and result are unsigned WORDs. Input range arithmetic wraps at
 * 32 bits. memory_order is an unused signed WORD, not a timeout or flag.
*/
unsigned int atomic_fetch_sub_u32(volatile unsigned int *address,unsigned int value,int ignored_memory_order)
{
    if ((unsigned int)address - 0x3c000000U > 0x1ffffffU)
        return atomic_fetch_sub_u32_s32c1i(address,value,ignored_memory_order);
    (void)xPortInIsrContext();
    (void)xPortEnterCriticalTimeout(ATOMIC_OPERATION_LOCK,-1);
    memw(); unsigned int old_value = *address;
    memw(); *address = old_value - value;
    (void)xPortInIsrContext();
    vPortExitCritical(ATOMIC_OPERATION_LOCK);
    return old_value;
}

/* Native entry: 0x4038fd14. */
/* Original function-byte SHA-256:
 * 38b083bec4b104d4d8112b6689fbabaadbebc3a628b57c7de8809a19eeca74a4. */
/*
 * Requires the byte's entire aligned WORD to support read/write and S32C1I.
 * Reads expected BYTE before MEMW/full-WORD load; forms an8-bit lane mask,
 * preserving the initial neighbor bits. Each attempt combines the cached
 * expected byte with current neighbors for SCOMPARE1 and desired low8 bits
 * with those neighbors for the conditional store. On failure, retries ONLY
 * if neighboring bits changed, adopting them while retaining expected byte.
 * If neighbors are unchanged, stops even when the target byte differs.
 * Returns0/1 by comparing the returned lane with cached expected. On mismatch
 * stores that lane to expected BYTE. No outer retry, final MEMW, lock, timeout
 * or weak/order selection; repeated neighbor mutation may prevent completion.

 * address selects one little-endian BYTE lane, but the complete aligned
 * enclosing WORD must remain valid for every conditional-store attempt.
 * expected is a live writable BYTE object sampled once before the loop; no
 * alias rejection or pointer lifetime extension. desired uses its low BYTE.
 * weak and signed order WORDs are not read. Result is an unsigned 0/1 WORD.
*/
unsigned int atomic_compare_exchange_u8_s32c1i(volatile unsigned char *address,unsigned char *expected,
    unsigned int desired,unsigned char ignored_weak,int ignored_success_order,int ignored_failure_order)
{
    (void)ignored_weak; (void)ignored_success_order; (void)ignored_failure_order;
    unsigned int shift = ((unsigned int)address & 3U) * 8U;
    volatile unsigned int *word = (volatile unsigned int *)((unsigned int)address & 0xfffffffcU);
    unsigned int expected_byte = *(volatile unsigned char *)expected;
    unsigned int preserve_mask = ~(0xffU << shift);
    memw(); unsigned int neighbors = *word & preserve_mask;
    unsigned int observed;
    for (;;) {
        unsigned int expected_word = (expected_byte << shift) | neighbors;
        unsigned int desired_word = ((desired & 0xffU) << shift) | neighbors;
        observed = xtensa_compare_store_u32(word,expected_word,desired_word);
        unsigned int new_neighbors = observed & preserve_mask;
        if (observed == expected_word || new_neighbors == neighbors) break;
        neighbors = new_neighbors;
    }
    unsigned int observed_byte = (observed >> shift) & 0xffU;
    if (observed_byte != expected_byte) *(volatile unsigned char *)expected = observed_byte;
    return observed_byte == expected_byte;
}

/* Native entry: 0x4038fd80. */
/* Original function-byte SHA-256:
 * 68cefa24f6c412c09963ec1e1e5d8112d9c93cef7c3d843d786b9750733df375. */
/*
 * Loads expected WORD, writes SCOMPARE1, then performs ONE S32C1I attempt.
 * Success leaves expected unchanged; failure writes the returned observed
 * WORD there. Returns0/1 for equality. No explicit MEMW, retry, mux or ordinary
 * object read; memory clobber is only a compiler barrier. Requires aligned
 * supported memory. weak and both order arguments have no effect.

 * address/expected are live word-aligned WORD objects; no alias rejection.
 * Compare the one returned observed WORD with the cached expected sample,
 * without a second comparison or changed expected input. desired/result are
 * unsigned WORDs; result is 0/1. weak BYTE and order WORDs are not read.
*/
unsigned int atomic_compare_exchange_u32_s32c1i(volatile unsigned int *address,unsigned int *expected,
    unsigned int desired,unsigned char ignored_weak,int ignored_success_order,int ignored_failure_order)
{
    (void)ignored_weak; (void)ignored_success_order; (void)ignored_failure_order;
    unsigned int expected_value = *(volatile unsigned int *)expected;
    unsigned int observed = xtensa_compare_store_u32(address,expected_value,desired);
    if (observed != expected_value) *(volatile unsigned int *)expected = observed;
    return observed == expected_value;
}

/* Native entry: 0x4038fd9c. */
/* Original function-byte SHA-256:
 * 642c03e6c05bc388ccf40030fc24f76d06e0e85ec7185e618c902f82d8d02174. */
/*
 * Requires an aligned readable/writable WORD supporting S32C1I. MEMW/reads
 * initial observed value once. Each retry computes observed + value modulo
 *2^32, writes observed to SCOMPARE1, and conditionally stores the result.
 * S32C1I returns the prior memory WORD; a mismatch adopts it and retries,
 * without an ordinary reload or another explicit MEMW. Returns the old WORD
 * replaced on success. No retry bound, lock, final MEMW or memory-order branch.

 * address stays live and aligned for the entire unbounded retry sequence.
 * value, expected and observed are unsigned WORDs; arithmetic wraps modulo
 * 2^32. The signed ordering WORD is unused. No pointer lifetime extension.
*/
unsigned int atomic_fetch_add_u32_s32c1i(volatile unsigned int *address,unsigned int value,int ignored_memory_order)
{
    (void)ignored_memory_order;
    memw(); unsigned int observed = *address;
    unsigned int expected;
    do {
        expected = observed;
        observed = xtensa_compare_store_u32(address,expected,expected + value);
    } while (observed != expected);
    return expected;
}

/* Native entry: 0x4038fdb8. */
/* Original function-byte SHA-256:
 * ed84a1ee8565597c7efca1d23789172358a153246d221bd9b83e4314759c9163. */
/*
 * Requires an aligned readable/writable WORD supporting S32C1I. MEMW/reads
 * initial observed value once. Each retry computes observed - value modulo
 *2^32, writes observed to SCOMPARE1, and conditionally stores the result.
 * S32C1I returns the prior memory WORD; a mismatch adopts it and retries,
 * without an ordinary reload or another explicit MEMW. Returns the old WORD
 * replaced on success. No retry bound, lock, final MEMW or memory-order branch.

 * address stays live and aligned for the entire unbounded retry sequence.
 * value, expected and observed are unsigned WORDs; arithmetic wraps modulo
 * 2^32. The signed ordering WORD is unused. No pointer lifetime extension.
*/
unsigned int atomic_fetch_sub_u32_s32c1i(volatile unsigned int *address,unsigned int value,int ignored_memory_order)
{
    (void)ignored_memory_order;
    memw(); unsigned int observed = *address;
    unsigned int expected;
    do {
        expected = observed;
        observed = xtensa_compare_store_u32(address,expected,expected - value);
    } while (observed != expected);
    return expected;
}
