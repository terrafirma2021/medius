/* Recovered 64-bit atomic operations. */
#include "../include/types.h"

/* Native entry: 0x4038fc70. */
/* Original function-byte SHA-256:
 * 8c48a647eef380ed1e05ac4768424af526b2f2708fc9d6a5f70290d02195c385. */
/* Perform the software 64-bit OR under the shared atomic-operation
 * spinlock. Read LOW then HIGH; write LOW|mask then HIGH|mask, retaining four
 * MEMW sites. Return the old LOW/HIGH value. Retain ISR-context queries before
 * lock entry and exit; ignore their results and the critical-entry result.
 * memory_order is unused: every order takes this lock. Storage must support
 * both word accesses. No lock-free, hardware-atomic or fault-recovery claim.
 * The 64-bit mask occupies A4/A5: A3 is ABI alignment padding, not an API arg.
 * address is borrowed writable storage for two adjacent aligned 32-bit words;
 * its lifetime spans the call. No range/alignment/NULL validation. The lock
 * serializes cooperating operations, not arbitrary writers to either word.
 * mask is unsigned 64-bit; memory_order is a signed WORD without any test.
 * Windowed ABI uses address/A2, padding/A3, mask/A4-A5 and order/A6; the old
 * 64-bit result returns in A2-A3. The padding register is not a fourth argument.
*/
unsigned long long atomic_fetch_or_u64(volatile unsigned long long *address,
    unsigned long long mask,int memory_order)
{
    (void)memory_order;
    volatile unsigned int *words = (volatile unsigned int *)address;
    xPortInIsrContext();
    xPortEnterCriticalTimeout(ATOMIC_OPERATION_LOCK,-1);
    memw();
    unsigned int old_low = words[0];
    memw();
    unsigned int old_high = words[1];
    memw();
    words[0] = old_low | (unsigned int)mask;
    memw();
    words[1] = old_high | (unsigned int)(mask >> 32);
    xPortInIsrContext();
    vPortExitCritical(ATOMIC_OPERATION_LOCK);
    return ((unsigned long long)old_high << 32) | old_low;
}

/* Native entry: 0x4038fc38. */
/* Original function-byte SHA-256:
 * 2f31f3f48dce4d5ed593c94cd162d596fa5868056fbd9d65b5e99f19d78abc7b. */
/* Perform the software 64-bit AND under the shared atomic-operation
 * spinlock. Read LOW then HIGH; write LOW&mask then HIGH&mask, retaining four
 * MEMW sites. Return the old LOW/HIGH value. Retain ISR-context queries before
 * lock entry and exit; ignore their results and the critical-entry result.
 * memory_order is unused: every order takes this lock. Storage must support
 * both word accesses. No lock-free, hardware-atomic or fault-recovery claim.
 * The 64-bit mask occupies A4/A5: A3 is ABI alignment padding, not an API arg.
 * address is borrowed writable storage for two adjacent aligned 32-bit words;
 * its lifetime spans the call. No range/alignment/NULL validation. The lock
 * serializes cooperating operations, not arbitrary writers to either word.
 * mask is unsigned 64-bit; memory_order is a signed WORD without any test.
 * Windowed ABI uses address/A2, padding/A3, mask/A4-A5 and order/A6; the old
 * 64-bit result returns in A2-A3. The padding register is not a fourth argument.
*/
unsigned long long atomic_fetch_and_u64(volatile unsigned long long *address,
    unsigned long long mask,int memory_order)
{
    (void)memory_order;
    volatile unsigned int *words = (volatile unsigned int *)address;
    xPortInIsrContext();
    xPortEnterCriticalTimeout(ATOMIC_OPERATION_LOCK,-1);
    memw();
    unsigned int old_low = words[0];
    memw();
    unsigned int old_high = words[1];
    memw();
    words[0] = old_low & (unsigned int)mask;
    memw();
    words[1] = old_high & (unsigned int)(mask >> 32);
    xPortInIsrContext();
    vPortExitCritical(ATOMIC_OPERATION_LOCK);
    return ((unsigned long long)old_high << 32) | old_low;
}
