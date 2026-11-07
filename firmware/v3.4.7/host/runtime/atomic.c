/* Recovered GPIO atomic support. */
#include "../include/types.h"

/* Native entry: 0x4038b270. */
/* Original function-byte SHA-256:
 * fdba4fe9d02c1655e6df081bbbf99f0387b7c4dee1b602c69e7e0ce86c2925ba. */
/* Perform the software 64-bit OR under the shared atomic-operation
 * spinlock. Read LOW then HIGH; write LOW|mask then HIGH|mask, retaining four
 * MEMW sites. Return the old LOW/HIGH value. Retain ISR-context queries before
 * lock entry and exit; ignore their results and the critical-entry result.
 * memory_order is unused: every order takes this lock. Storage must support
 * both word accesses. No lock-free, hardware-atomic or fault-recovery claim.
 * The 64-bit mask occupies A4/A5: A3 is ABI alignment padding, not an API arg. */
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

/* Native entry: 0x4038b238. */
/* Original function-byte SHA-256:
 * db60304f6aa93ea645d8e4d41b012d2d8bb34fd4ed3dc4d72bf4dacb5b43e69a. */
/* Perform the software 64-bit AND under the shared atomic-operation
 * spinlock. Read LOW then HIGH; write LOW&mask then HIGH&mask, retaining four
 * MEMW sites. Return the old LOW/HIGH value. Retain ISR-context queries before
 * lock entry and exit; ignore their results and the critical-entry result.
 * memory_order is unused: every order takes this lock. Storage must support
 * both word accesses. No lock-free, hardware-atomic or fault-recovery claim.
 * The 64-bit mask occupies A4/A5: A3 is ABI alignment padding, not an API arg. */
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
