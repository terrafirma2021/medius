/* Medius v3.4.7 host — platform/atomics.c.
 * Recovered C and native assembly, grouped for source navigation.
 * Original entry addresses, firmware-byte hashes and function comments follow.
 */

#include "../include/types.h"

/* Native entry: 0x4037f960. */
/*
 * Medius v3.4.7 — host application; 0x4037f960.
 *
 * ESP-IDF esp_cpu_compare_and_set: one 32-bit conditional exchange, returning exact success 0/1.
 *
 * Called by: esp_ipc_call_nonblocking, xPortEnterCriticalTimeout.
 *
 * Original function-byte SHA-256:
 * 1af3706beffef34628bf5ae889c000c9ed43c34378c3a55c1f63770cec5b4319.
 */

/* Attempts one32-bit conditional exchange and returns exact success0/1. Writes expected to
   concreteSCOMPARE1, executes oneS32C1I at the unmodified address using desired, and receives the
   old word into a4. Subtracts that old word from cached expected modulo32bits, then NSAU and right
   shift5 produce1 exactly for equality and0 otherwise. Equal old word causes the conditional
   replacement; unequal old word leaves storage unchanged. No loop, helper call, explicitMEMW, lock,
   address alignment adjustment or pointer/range guard. Expected caller storage is not updated
   because expected is a value, not a pointer. A mutation immediately before CAS affects its
   observed word/result; a mutation after CAS can replace the stored result without changing the
   cached success result. SCOMPARE1 remains set to expected. Boundaries: Caller must provide a valid
   memory region/alignment supporting the instruction. No access fault, hardware bus, coherence,
   physical contention or memory-order semantics are modeled. Successful return identifies this
   conditional-store observation, not continued equality or ownership after a later writer. The recovered body now uses explicit WSR/S32C1I assembly, preserving the native conditional
   store rather than compiling a separate C load/store. */

/*
 * address: Writable 32-bit aligned word in memory supporting S32C1I.
 * expected: Full expected word passed by value; not an output parameter.
 * desired: Full replacement word.
 * Returns: Exactly 1 when S32C1I observed expected and performed the conditional store, otherwise
 *   0.
 * Requirements/effects: Writes expected to SCOMPARE1 and executes exactly one S32C1I. The
 *   instruction replaces the word only on equality and returns its observed prior word. There is
 *   no retry, explicit MEMW, lock or address validation. SCOMPARE1 remains changed. The inline-
 *   assembly memory clobber constrains the compiler; it does not add an architectural barrier
 *   instruction. A subsequent writer may replace the stored value after a successful result.
 */

bool esp_cpu_compare_and_set(volatile unsigned int *address,
                              unsigned int expected, unsigned int desired)

{
  uint observed;

  observed = desired;
  /* WSR sets the comparison word; S32C1I returns the observed old word. */
  __asm__ volatile (
      "wsr.scompare1 %2\n"
      "s32c1i %0, %3, 0\n"
      : "+a"(observed), "+m"(*address)
      : "a"(expected), "a"(address)
      : "memory");
  return (uint)(expected == observed);
}
