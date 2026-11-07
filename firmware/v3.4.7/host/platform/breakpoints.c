/* Medius v3.4.7 host — CPU instruction breakpoint programming. */
#include "../include/types.h"

/* Native entry: 0x4202272c. */
/* Original function-byte SHA-256:
 * 7f4ac17a4b30d9abe936e916e95d2883e37ca72c651b448babb64169f43f7558. */
/* Write IBREAKA1 only for index1; all other index values write IBREAKA0.
 * Then read IBREAKENABLE, OR bit(index&31), write it and return0. No valid-index,
 * address/alignment check, disable step, ISYNC, MEMW, lock or status validation.
 * Invalid indices can therefore program address slot0 but enable another bit.
 * Only the executing CPU's special registers are touched. */
int esp_cpu_set_breakpoint(unsigned int index,const void *address)
{
    if (index==1U) __asm__ volatile("wsr.ibreaka1 %0" :: "a"(address));
    else __asm__ volatile("wsr.ibreaka0 %0" :: "a"(address));
    unsigned int enabled;
    __asm__ volatile("rsr.ibreakenable %0" : "=a"(enabled));
    enabled|=1U<<(index&31U);
    __asm__ volatile("wsr.ibreakenable %0" :: "a"(enabled));
    return 0;
}
