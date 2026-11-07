/* Medius v3.4.7 device — linked PSRAM timing hook. */
#include "../include/types.h"

/* Native entry: 0x40384574. */
/* Original function-byte SHA-256:
 * a50f595a12cc6e7e90d28fa2424790fbfac53a684610d6fe5637b2112f16f23d. */
/* Linked timing-tuning hook consists only of ENTRY/RETW. It returns without
 * reading memory, configuring clocks, testing RAM or delaying. The compiler
 * barrier below keeps the call visible in reconstructed aggregate compilation;
 * it emits no native instruction and is not a hardware MEMW. */
void mspi_timing_psram_tuning(void)
{
    __asm__ volatile("" ::: "memory");
}
