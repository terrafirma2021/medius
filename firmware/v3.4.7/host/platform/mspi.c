/* Medius v3.4.7 host: recovered MSPI clocks and pad drive. */

#include "../include/types.h"

/* Native entry: 0x4037fb40. */
/*
 * Medius v3.4.7 — host application; 0x4037fb40.
 * Instruction-checked recovered C.
 * Original function-byte SHA-256:
 * 8dd9c97cff7ac215c2b061731a1ccb4ebd0ff3baa4594e1d8a7ad5738da255c0.
 */

/* Program flash clock from the fixed 80 MHz MSPI core. speed_mode is unused
 * in this compiled specialization. First select core-clock code 0 by a fresh
 * RMW, then execute native unsigned QUOU(80,frequency_mhz). Keeping QUOU
 * explicit retains the instruction's zero-divisor behavior without C division
 * by zero or an invented software check. Frequencies above 80 assert only
 * AFTER the core-clock write and division; zero is not explicitly rejected.
 *
 * Divider 1 writes bit 31 alone. Otherwise form ((divider/2-1)<<8) OR
 * ((divider-1)*0x10001), with unsigned 32-bit wrapping and no field masking.
 * Requests not dividing 80 exactly use the truncated integer divider.
 * Write the WHOLE SPI0 clock register, and the identical word to SPI1 only
 * when the LOW BYTE of control_spi1 is nonzero. No cache freeze, lock, idle
 * wait, frequency measurement, divider rounding or status in this helper. */
void mspi_timing_config_set_flash_clock(unsigned int frequency_mhz,
    unsigned int speed_mode,unsigned char control_spi1)
{
    (void)speed_mode;
    memw();
    unsigned int core = MSPI0->core_clock;
    memw();
    MSPI0->core_clock = core & ~3U;
    unsigned int divider;
    __asm__ volatile ("quou %0,%1,%2" : "=a"(divider)
                      : "a"(80U),"a"(frequency_mhz) : "memory");
    if (frequency_mhz > 80U)
        __assert_func(0,0,0,0);
    unsigned int clock;
    if (divider == 1U)
        clock = 0x80000000U;
    else
        clock = (((divider >> 1) - 1U) << 8) | ((divider - 1U) * 0x10001U);
    memw();
    MSPI0->flash_clock = clock;
    if (control_spi1) {
        memw();
        MSPI1->flash_clock = clock;
    }
}

/* Native entry: 0x4037fbac. */
/*
 * Medius v3.4.7 — host application; 0x4037fbac.
 * Instruction-checked recovered C.
 * Original function-byte SHA-256:
 * 67acf9ba06a6ddecf84e87e87461b4bdd78f30d02dc60b396576be74f40e807b.
 */

/* Program SPI0 PSRAM clock from an 80 MHz core; both speed_mode and the
 * compatibility control_spi1 argument are unused. Fresh core-clock RMW to
 * code 0 precedes native QUOU(80,frequency_mhz), then the >80 fatal assertion.
 * Zero has no software guard; explicit QUOU retains native instruction behavior.
 * Divider 1 writes bit 31; other dividers use wrapped ((divider/2-1)<<8) OR
 * ((divider-1)*0x10001) without masking. Write the complete SRAM_CLK word.
 * No SPI1 write, cache freeze, lock, idle check, rounding or status. */
void mspi_timing_config_set_psram_clock(unsigned int frequency_mhz,
    unsigned int speed_mode,unsigned char control_spi1)
{
    (void)speed_mode;
    (void)control_spi1;
    memw();
    unsigned int core = MSPI0->core_clock;
    memw();
    MSPI0->core_clock = core & ~3U;
    unsigned int divider;
    __asm__ volatile ("quou %0,%1,%2" : "=a"(divider)
                      : "a"(80U),"a"(frequency_mhz) : "memory");
    if (frequency_mhz > 80U)
        __assert_func(0,0,0,0);
    unsigned int clock;
    if (divider == 1U)
        clock = 0x80000000U;
    else
        clock = (((divider >> 1) - 1U) << 8) | ((divider - 1U) * 0x10001U);
    memw();
    MSPI0->psram_clock = clock;
}

/* Native entry: 0x4037fc04. */
/*
 * Medius v3.4.7 — host application; 0x4037fc04.
 * Instruction-checked recovered C.
 * Original function-byte SHA-256:
 * 125cafc79da153c3f9c54a6d438f2183e25ea3b0394654840078d82faa1426f2.
 */

/* Freeze external-memory instruction/data caches, then use the LOW BYTE of
 * switch_down. Nonzero sets flash and PSRAM to 20 MHz using mode 0; zero sets
 * flash alone to 80 MHz using mode 1 and leaves PSRAM clock unchanged. Both
 * branches pass control_spi1=0. Finally unfreeze caches. There is no separate
 * other-core stall, spinlock, delay or status; a helper's fatal path cannot
 * reach unfreeze. This is the host specialization, not the device low-speed
 * helper, which has no cache freeze and interprets its byte as control_spi1. */
void mspi_timing_change_speed_mode_cache_safe(unsigned char switch_down)
{
    esp_cache_freeze_ext_mem_cache();
    if (switch_down) {
        mspi_timing_config_set_flash_clock(20,0,0);
        mspi_timing_config_set_psram_clock(20,0,0);
    } else {
        mspi_timing_config_set_flash_clock(80,1,0);
    }
    esp_cache_unfreeze_ext_mem_cache();
}

/* Native entry: 0x4037fc40. */
/*
 * Medius v3.4.7 — host application; 0x4037fc40.
 * Instruction-checked recovered C.
 * Original function-byte SHA-256:
 * 59d81de6d09859517aaac4028371042a5d34cac1388d714fdc74b6b1cdf57e92.
 */

/* Set SPI0 flash/PSRAM clock drive strength and nine MSPI pad strengths to 3.
 * Fresh DATE RMWs first set clock pad driver control bit 4, PSRAM drive bits
 * 0..1, then flash drive bits 2..3. Copy the original 36-byte address table to
 * stack BEFORE updating any pad: GPIO27,28,31,32,33,34,35,36,37 in that order.
 * Each pad uses its own fresh MEMW/read/MEMW/write setting drive bits 10..11.
 * The native hardware LOOP executes exactly nine iterations; the decompiler's
 * extra early-exit condition is absent. All unrelated register bits survive.
 * There are no arguments, pad remux, lock, delay, idle check or result. */
void mspi_set_all_pin_drive_3(void)
{
    memw();
    unsigned int date = MSPI0->date;
    memw();
    MSPI0->date = date | 0x10U;
    memw();
    date = MSPI0->date;
    memw();
    MSPI0->date = date | 3U;
    memw();
    date = MSPI0->date;
    memw();
    MSPI0->date = date | 0xcU;
    volatile unsigned int *pads[9];
    memcpy(pads,MSPI_DRIVE_PAD_TABLE,sizeof(pads));
    for (unsigned int index = 0; index < 9; ++index) {
        volatile unsigned int *pad = pads[index];
        memw();
        unsigned int configuration = *pad;
        memw();
        *pad = configuration | 0xc00U;
    }
}
