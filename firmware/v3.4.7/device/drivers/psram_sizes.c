/* Medius v3.4.7 device — PSRAM implementation size queries. */
#include "../include/types.h"

/* Native entry: 0x40385ce8. */
/* Original function-byte SHA-256:
 * f6bd37db7433ecb96c4fc430a0e8478b23efe9c90e7da0dc6b43c66a78c62947. */
/* NULL output returns0x102 before any shared-state read. Otherwise load the
 * cached physical-size WORD once and publish it even when0. Return0 for a
 * nonzero size, or0x103 for0. No initialized-BYTE check, device/MMU query,
 * reserved-space subtraction, MEMW or lock. This physical-size entry uses
 * the same cached WORD as the paired implementation query. */
int esp_psram_impl_get_physical_size(unsigned int *output)
{
    if (output==NULL) return 0x102;
    unsigned int size=PSRAM_PHYSICAL_SIZE;
    *output=size;
    return size!=0?0:0x103;
}

/* Native entry: 0x40385d08. */
/* Original function-byte SHA-256:
 * 7be62386f22f31f5a12af901c322e1f48243a08aaf03c6b4300625363ee0925a. */
/* NULL output returns0x102 before any shared-state read. Otherwise load the
 * cached physical-size WORD once and publish it even when0. Return0 for a
 * nonzero size, or0x103 for0. No initialized-BYTE check, device/MMU query,
 * reserved-space subtraction, MEMW or lock. This available-size entry uses
 * the same cached WORD as the paired implementation query. */
int esp_psram_impl_get_available_size(unsigned int *output)
{
    if (output==NULL) return 0x102;
    unsigned int size=PSRAM_PHYSICAL_SIZE;
    *output=size;
    return size!=0?0:0x103;
}
