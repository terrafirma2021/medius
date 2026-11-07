/* Medius v3.4.7 device — platform/atomics.c.
 * Recovered C and native assembly, grouped for source navigation.
 * Original entry addresses, firmware-byte hashes and function comments follow.
 */

#include "../include/types.h"

/* Native entry: 0x40384154. */
/*
 * Medius v3.4.7 — device application; 0x40384154.
 *
 * ESP-IDF compare-and-set, with a guarded external-RAM workaround and native S32C1I elsewhere.
 *
 * Called by: esp_ipc_call_nonblocking, xPortEnterCriticalTimeout.
 *
 * Original function-byte SHA-256:
 * 82970b3d648dddacac31cc72eed7785742bd5328fd3f0bfbacc116960f4eb3a4.
 */

/*
 * Attempt a 32-bit compare-and-set without retrying.
 * address: valid writable aligned word; expected and desired are full words
 * passed by value. Returns exactly true when the observed word equals expected
 * and the conditional replacement succeeds. Does not update expected storage.
 *
 * Addresses 0x3c000000..0x3dffffff use the external-RAM workaround, selected by
 * unsigned address subtraction. RSIL saves PS and sets interrupt level 3.
 * A single S32C1I attempts to set the shared CAS guard from 0 to 1. A busy
 * guard returns false without reading address or clearing somebody else's guard.
 * On guard acquisition: MEMW, read address once, and on equality MEMW then
 * store desired. Release the guard with a zero store even on mismatch.
 * Finish either guard path with MEMW and WSR of the complete saved PS; no
 * RSYNC is present. SCOMPARE1 remains zero on this path.
 *
 * All other addresses use one WSR SCOMPARE1(expected)/S32C1I(desired) pair
 * directly on address, with no explicit MEMW or interrupt masking. SCOMPARE1
 * remains expected. This is an atomic conditional store, not a C load/store
 * pair. Failure makes no target write. There is no alignment, permission,
 * mapping or memory-capability validation; caller must satisfy hardware rules
 * and shared CAS-guard initialization. A successful result does not promise
 * that a later writer has left the value unchanged.
 *
 * Identity: ESP-IDF v5.4.4 esp_cpu_compare_and_set, including its configured
 * external-RAM branch. Both original callers pass expected by value.
 */
bool esp_cpu_compare_and_set(volatile unsigned int *address,
                              unsigned int expected, unsigned int desired)
{
    if ((unsigned int)address - 0x3c000000U <= 0x01ffffffU) {
        unsigned int previous_ps;
        __asm__ volatile ("rsil %0,3" : "=a"(previous_ps) : : "memory");
        unsigned int guard_observed = 1;
        __asm__ volatile (
            "wsr.scompare1 %2\n\ts32c1i %0,%3,0"
            : "+a"(guard_observed), "+m"(EXTERNAL_RAM_CAS_GUARD)
            : "a"(0U), "a"(&EXTERNAL_RAM_CAS_GUARD)
            : "memory");
        bool exchanged = false;
        if (guard_observed == 0) {
            __asm__ volatile ("memw" : : : "memory");
            unsigned int observed = *address;
            exchanged = observed == expected;
            if (exchanged) {
                __asm__ volatile ("memw" : : : "memory");
                *address = desired;
            }
            EXTERNAL_RAM_CAS_GUARD = 0;
        }
        __asm__ volatile ("memw\n\twsr %0,ps" : : "a"(previous_ps) : "memory");
        return exchanged;
    }

    unsigned int observed = desired;
    __asm__ volatile (
        "wsr.scompare1 %2\n\ts32c1i %0,%3,0"
        : "+a"(observed), "+m"(*address)
        : "a"(expected), "a"(address)
        : "memory");
    return observed == expected;
}

/* Native entry: 0x4038fa90. */
/*
 * Medius v3.4.7 — device application; 0x4038fa90.
 *
 * Selects a critical-section byte exchange for the external-memory interval and an S32C1I fallback
 * elsewhere.
 *
 * Calls: xPortInIsrContext, atomic_exchange_byte_s32c1i, vPortExitCritical,
 * xPortEnterCriticalTimeout.
 *
 * Called by: FUN_4037880c, FUN_42038780, app_main, device_link_message.
 *
 * Original function-byte SHA-256:
 * d0950202156f2b1d90ad6a3664c23e1a222667f488f231e4ea09e5373026482a.
 */



/*
 * address: Writable byte; outside the external-memory interval its whole containing aligned word
 *   must support conditional stores.
 * desired: Replacement narrowed to its low eight bits.
 * memory_order: Forwarded unchanged to the hardware helper outside the software interval;
 *   otherwise unused.
 * Returns: The old unsigned byte on the software path, or the unchanged return register from the
 *   fallback helper.
 * Requirements/effects: Uses a critical-section byte read/write for pointer bits in
 *   [0x3c000000,0x3e000000), otherwise delegates to the S32C1I helper. Software path queries ISR
 *   context, requests its fixed mux indefinitely and ignores entry status; MEMW precedes the read
 *   and the write. Caches the old byte before context-query/unlock calls. The address-range
 *   predicate uses unsigned 32-bit subtraction; it does not establish that RAM is physically
 *   present. Requires valid calling context and storage, with all relevant participants respecting
 *   the same lock.
 */

uint atomic_exchange_byte(uchar *address,uint desired,uint memory_order)

{
  uint old_value;

  if ((uint)address - 0x3c000000U < 0x02000000U) {
    xPortInIsrContext();
    xPortEnterCriticalTimeout(ATOMIC_BYTE_EXCHANGE_LOCK,0xffffffff);
    memw();
    old_value = (uint)*(const volatile uchar *)address;
    memw();
    *(volatile uchar *)address = (uchar)desired;
    xPortInIsrContext();
    vPortExitCritical(ATOMIC_BYTE_EXCHANGE_LOCK);
  }
  else {
    old_value = atomic_exchange_byte_s32c1i(address,desired & 0xff,memory_order);
  }
  return old_value;
}

/* Native entry: 0x4038fca8. */
/*
 * Medius v3.4.7 — device application; 0x4038fca8.
 *
 * Exchanges one byte using an aligned-word conditional-store retry loop while preserving adjacent
 * bytes.
 *
 * Called by: atomic_exchange_byte.
 *
 * Original function-byte SHA-256:
 * 170b0fa700994782221430cc7261afc4268f4c76f992426f8f09fbf2abf15621.
 */



/*
 * address: Byte address within a readable/writable aligned 32-bit word supporting S32C1I.
 * desired: Low eight bits replace the selected byte; higher bits are discarded.
 * ignored_memory_order: Unused by this body; no local instruction selection depends on it.
 * Returns: The unsigned byte replaced by the successful conditional store, 0..255.
 * Requirements/effects: Aligns the pointer down to four bytes and uses a byte-lane mask. MEMW
 *   precedes the initial byte load and each outer full-word read. Inner WSR/S32C1I retries adopt
 *   changed neighbor bytes while retaining the expected target byte; outer retries adopt a changed
 *   target byte and reread neighbors. Successful replacement preserves all other bytes. There is
 *   no retry bound, lock, sleep, final explicit MEMW or fairness guarantee. Full-word
 *   accessibility and actual architectural conditional-store support are required, beyond validity
 *   of the byte itself. The compiler memory clobber adds no hardware barrier instruction.
 */

unsigned int atomic_exchange_byte_s32c1i(unsigned char *address,
    unsigned int desired, unsigned int ignored_memory_order)
{
    unsigned int shift_bits = ((unsigned int)address & 3U) * 8U;
    unsigned int preserve_mask = ~(0xffU << shift_bits);
    volatile unsigned int *aligned_word = (unsigned int *)((unsigned int)address & 0xfffffffcU);
    unsigned int replacement_bits = (desired & 0xffU) << shift_bits;
    (void)ignored_memory_order;
    memw();
    unsigned int expected_byte = *(const volatile unsigned char *)address;
    for (;;) {
        memw();
        unsigned int neighbors = *aligned_word & preserve_mask;
        unsigned int observed_word;
        for (;;) {
            unsigned int expected_word = (expected_byte << shift_bits) | neighbors;
            observed_word = replacement_bits | neighbors;
            __asm__ volatile (
                "wsr.scompare1 %2\n\ts32c1i %0,%3,0"
                : "+a"(observed_word), "+m"(*aligned_word)
                : "a"(expected_word), "a"(aligned_word)
                : "memory");
            unsigned int observed_neighbors = observed_word & preserve_mask;
            if (observed_word == expected_word)
                break;
            bool neighbors_changed = neighbors != observed_neighbors;
            neighbors = observed_neighbors;
            if (!neighbors_changed)
                break;
            /* A neighboring byte changed: retry without adopting the target byte. */
        }
        unsigned int observed_byte = (observed_word >> shift_bits) & 0xffU;
        if (observed_byte == expected_byte)
            return expected_byte;
        /* The target byte changed: adopt it and reread the containing word. */
        expected_byte = observed_byte;
    }
}
