/* Medius v3.4.7 device — linked flash-timing startup hook. */
#include "../include/types.h"

/* Native entry: 0x4038456c. */
/* Original function-byte SHA-256:
 * a50f595a12cc6e7e90d28fa2424790fbfac53a684610d6fe5637b2112f16f23d. */
/* This build's mspi_timing_flash_tuning hook consists only of ENTRY/RETW.
 * Return immediately, with no timing calibration, register/data access,
 * callbacks, allocation or status value. Keep its own native identity even
 * though this selected build links the empty implementation. */
void mspi_timing_flash_tuning(void)
{
    /* Compiler-only barrier retains the native call boundary when exported
     * modules are compiled together. It emits no hardware instruction. */
    __asm__ volatile("" ::: "memory");
}
