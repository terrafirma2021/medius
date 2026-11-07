/* Medius v3.4.7 device — panic diagnostic output. */
#include "../include/types.h"

/* Native entry: 0x42020c34. */
/* Original function-byte SHA-256:
 * a50f595a12cc6e7e90d28fa2424790fbfac53a684610d6fe5637b2112f16f23d. */
/* Console-disabled panic output stub: native ENTRY/RETW only. The caller
 * passes a string pointer, but no text byte is read and no output occurs.
 * The empty compiler barrier retains the native call boundary in aggregate
 * review compilation; it emits no instruction, MEMW or hardware operation. */
void panic_print_str(const char *text)
{
    __asm__ volatile("" ::: "memory");
}

/* Native entry: 0x42020c3c. */
/* Original function-byte SHA-256:
 * a50f595a12cc6e7e90d28fa2424790fbfac53a684610d6fe5637b2112f16f23d. */
/* Console-disabled panic output stub: native ENTRY/RETW only. The caller
 * passes a full WORD, but no digit is computed and no output occurs.
 * The empty compiler barrier retains the native call boundary in aggregate
 * review compilation; it emits no instruction, MEMW or hardware operation. */
void panic_print_hex(unsigned int value)
{
    __asm__ volatile("" ::: "memory");
}

/* Native entry: 0x42020c2c. */
/* Original function-byte SHA-256:
 * a50f595a12cc6e7e90d28fa2424790fbfac53a684610d6fe5637b2112f16f23d. */
/* Console-disabled abort-detail callback: ENTRY/RETW only. The frame
 * argument is ignored; no global details pointer or string byte is read.
 * Empty compiler barrier emits no instruction or hardware operation. */
void panic_print_abort_details(const void *unused_frame)
{
    __asm__ volatile("" ::: "memory");
}

/* Native entry: 0x42020c44. */
/* Original function-byte SHA-256:
 * a50f595a12cc6e7e90d28fa2424790fbfac53a684610d6fe5637b2112f16f23d. */
/* Console-disabled decimal-output stub: ENTRY/RETW only. The caller's
 * value is ignored; no division, UART read or output. Empty compiler barrier
 * retains the call boundary and emits no instruction or hardware operation. */
void panic_print_dec(int value)
{
    __asm__ volatile("" ::: "memory");
}
