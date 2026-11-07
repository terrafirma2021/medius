/* Medius v3.4.7 device: recovered MSPI clocks and pad drive. */

#include "../include/types.h"

/* Native entry: 0x403843cc. */
/*
 * Medius v3.4.7 — device application; 0x403843cc.
 * Instruction-checked recovered C.
 * Original function-byte SHA-256:
 * b30950110ff68ac30ab623b730b23bd6ac1fe92b7cf80796a259388b8d1b70ba.
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

/* Native entry: 0x40384438. */
/*
 * Medius v3.4.7 — device application; 0x40384438.
 * Instruction-checked recovered C.
 * Original function-byte SHA-256:
 * d82007eeb836443c9ebd7951df9fc566d2c5237cf01a1a224eb64f0b7ad3bb75.
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

/* Native entry: 0x40384490. */
/*
 * Medius v3.4.7 — device application; 0x40384490.
 * Instruction-checked recovered C.
 * Original function-byte SHA-256:
 * eff84290702beaa89ff9ccea20c291f2655bb2263a6be6d7bec96b897a55f916.
 */

/* Device specialization: set flash then PSRAM clocks to 20 MHz/mode 0.
 * Forward the LOW BYTE of control_spi1 to both helpers; only flash uses it
 * to optionally update SPI1. No cache freeze, other-core stall, lock, delay,
 * tuning, status or high-speed branch. This is distinct from the host's
 * cache-safe speed-change wrapper. */
void mspi_timing_enter_low_speed_mode(unsigned char control_spi1)
{
    mspi_timing_config_set_flash_clock(20,0,control_spi1);
    mspi_timing_config_set_psram_clock(20,0,control_spi1);
}

/* Native entry: 0x4038450c. */
/*
 * Medius v3.4.7 — device application; 0x4038450c.
 * Instruction-checked recovered C.
 * Original function-byte SHA-256:
 * ab3dc7e3a23ef56478b04ec414c563c149ff611fdbe01cc5e1744ba5fd706441.
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

/* Native entry: 0x403844ac. */
/*
 * Medius v3.4.7 — device application; 0x403844ac.
 * Instruction-checked recovered C.
 * Original function-byte SHA-256:
 * dcb2452284d663336dfee3618e1544f16ff009af8d1bceac33bf9e3fe9fc2453.
 */

/* Device specialization: program flash to 80 MHz, then PSRAM to 40 MHz,
 * both with speed-mode argument 1. Forward LOW BYTE of control_spi1 to both
 * helpers; only flash can update SPI1. No cache freeze, tuning, lock, delay
 * or return status. Distinct from the host's flash-only high-speed path. */
void mspi_timing_enter_high_speed_mode(unsigned char control_spi1)
{
    mspi_timing_config_set_flash_clock(80,1,control_spi1);
    mspi_timing_config_set_psram_clock(40,1,control_spi1);
}

/* Native entry: 0x403844c8. */
/*
 * Medius v3.4.7 — device application; 0x403844c8.
 * Instruction-checked recovered C.
 * Original function-byte SHA-256:
 * f7ead2984bc7ae34290283db757744cdc0946879c0f7b508dd3903871741446f.
 */

/* Device specialization: freeze external-memory instruction/data caches,
 * then inspect LOW BYTE of switch_down. Nonzero sets flash and PSRAM to
 * 20 MHz/mode 0; zero sets flash to 80 and PSRAM to 40 MHz/mode 1. Always
 * pass control_spi1=0, then unfreeze caches. No separate other-core stall,
 * lock, delay or result. The host's high path leaves PSRAM untouched; this
 * device wrapper has an additional PSRAM write on that path. */
void mspi_timing_change_speed_mode_cache_safe(unsigned char switch_down)
{
    esp_cache_freeze_ext_mem_cache();
    if (switch_down) {
        mspi_timing_config_set_flash_clock(20,0,0);
        mspi_timing_config_set_psram_clock(20,0,0);
    } else {
        mspi_timing_config_set_flash_clock(80,1,0);
        mspi_timing_config_set_psram_clock(40,1,0);
    }
    esp_cache_unfreeze_ext_mem_cache();
}
