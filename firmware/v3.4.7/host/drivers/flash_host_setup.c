/* Medius v3.4.7 host: default flash host configuration and publication. */
#include "../include/types.h"

/* Inline reconstruction utilities preserve native ordering; no additional
 * firmware entry is represented by this barrier. */
static __inline__ __attribute__((always_inline)) void flash_host_setup_barrier(void)
{
    __asm__ volatile ("memw" ::: "memory");
}

/* Native entry: 0x42012ad8. */
/* Original function-byte SHA-256:
 * 8e6f3733c6a48f370c3b5adbfacae484c5e6139d4885e7f68d7060fc5f0d4f56. */
/* Initialize the fixed default host/chip, retaining partial state on errors.
 * Cache the ROM legacy pointer, zero all14 config WORDs (including padding),
 * set CS setup1/IOMUX1/frequency80, then replace IOMUX from ROM eFuse config.
 * Apply octal-mode correction. A true timing-tuned result sets its byte and
 * invokes the timing-parameter helper (this build's getter returnsfalse and
 * the parameter helper aborts). For host0, MEMW/read SPI0 DATE low2 source
 * bits:0=80,1=120,2=160,3=240MHz; other host IDs retain80. Publish config source
 * frequency only after selecting it. Initialize pointers, then probe/init chip;
 * propagate either error without rollback or default-pointer publication.
 * Detected size smaller than cached legacy chip's current image size gives104
 * with gated log. Larger size warns only at level>=2; log paths reread sizes
 * after timestamp. Above16MiB invoke feature check, propagate/log its error,
 * otherwise reread image size. Store chip.size BEFORE publishing default-chip
 * pointer; the old decompile reversed these stores. No lock, idempotence guard,
 * retained-config allocation or rollback is supplied. */
int esp_flash_init_default_chip(void)
{
    const volatile RomFlashLegacy *legacy = ROM_FLASH_LEGACY;
    volatile MemspiHostConfig config;
    volatile unsigned int *words = (volatile unsigned int *)&config;
    for (unsigned int index = 0; index < 14; ++index)
        words[index] = 0;
    config.timing.cs_setup = 1;
    config.iomux = 1;
    config.freq_mhz = 80;
    config.iomux = esp_rom_efuse_get_flash_gpio_info() == 0;
    flash_choose_default_io_mode((MemspiHostConfig *)&config);
    if (spi_flash_timing_is_tuned()) {
        config.using_timing_tuning = 1;
        spi_timing_get_flash_timing_param((FlashTimingConfig *)&config.timing);
    }
    unsigned int source_frequency = 80;
    if (config.host_id == 0) {
        flash_host_setup_barrier();
        unsigned int source = *(const volatile unsigned int *)0x600030ecU & 3U;
        if (source == 2)
            source_frequency = 160;
        else if (source == 3)
            source_frequency = 240;
        else if (source != 0)
            source_frequency = 120;
    }
    config.clock_src_freq = (int)source_frequency;
    int result = memspi_host_init_pointers(DEFAULT_FLASH_HOST,
        (const MemspiHostConfig *)&config);
    if (result != 0)
        return result;
    result = esp_flash_init_main((EspFlash *)DEFAULT_FLASH_OBJECT);
    if (result != 0)
        return result;
    unsigned int detected_size = DEFAULT_FLASH_OBJECT->size;
    unsigned int image_size = legacy->chip.chip_size;
    if (detected_size < image_size) {
        if (SYSTEM_EARLY_LOG_LEVEL != 0) {
            unsigned int timestamp = esp_log_timestamp();
            unsigned int expected = legacy->chip.chip_size;
            unsigned int detected = DEFAULT_FLASH_OBJECT->size;
            ets_printf("E (%lu) %s: Detected size(%dk) smaller than the size in the binary image header(%dk). Probe failed.\n",
                timestamp,"spi_flash",detected >> 10,expected >> 10);
        }
        return 0x104;
    }
    if (image_size < detected_size && SYSTEM_EARLY_LOG_LEVEL >= 2) {
        unsigned int timestamp = esp_log_timestamp();
        unsigned int expected = legacy->chip.chip_size;
        unsigned int detected = DEFAULT_FLASH_OBJECT->size;
        ets_printf("W (%lu) %s: Detected size(%dk) larger than the size in the binary image header(%dk). Using the size in the binary image header.\n",
            timestamp,"spi_flash",detected >> 10,expected >> 10);
        image_size = legacy->chip.chip_size;
    }
    if (image_size > 0x1000000U) {
        result = esp_mspi_32bit_address_flash_feature_check();
        if (result != 0) {
            if (SYSTEM_EARLY_LOG_LEVEL != 0) {
                unsigned int timestamp = esp_log_timestamp();
                ets_printf("E (%lu) %s: %s(%d): 32bit address feature check failed\n",
                    timestamp,"spi_flash","esp_flash_init_default_chip",0x1a3);
            }
            return result;
        }
        image_size = legacy->chip.chip_size;
    }
    DEFAULT_FLASH_OBJECT->size = image_size;
    DEFAULT_FLASH_CHIP = (EspFlash *)DEFAULT_FLASH_OBJECT;
    return 0;
}

/* Native entry: 0x42012a9c. */
/* Original function-byte SHA-256:
 * 7801572d47ac93b45eeb84921c8756ab51dde452b27370c8170bd20aa7a42d91. */
/* Read octal eFuse flag once. If clear, leave config and fixed chip unchanged.
 * If set, optionally warn at early-log level>=2 using linked mode string "dio",
 * then store config octal BYTE1,+40 I/O WORD16,chip read-mode WORD16, in that
 * order. No NULL/config validation, pin setup, clock change or returned status. */
void flash_choose_default_io_mode(MemspiHostConfig *config)
{
    if (!bootloader_flash_is_octal_mode_enabled())
        return;
    if (SYSTEM_EARLY_LOG_LEVEL >= 2) {
        unsigned int timestamp = esp_log_timestamp();
        ets_printf("W (%lu) %s: Octal flash chip is using but %s mode is selected, will automatically switch to Octal mode\n",
            timestamp,"spi_flash","dio");
    }
    volatile MemspiHostConfig *state = config;
    state->octal_mode_en = 1;
    state->default_io_mode = 16;
    DEFAULT_FLASH_OBJECT->read_mode = 16;
}

/* Native entry: 0x4037fc38. */
/* Original function-byte SHA-256:
 * 6e59ebde22093e8acd7f52b228576881671a199077ef5fc4137b5bc6987238cd. */
/* Timing-tuning-disabled specialization: ignore output and abort immediately.
 * No parameter write, hardware read or normal return exists in this build. */
void spi_timing_get_flash_timing_param(FlashTimingConfig *unused_output)
{
    (void)unused_output;
    abort();
}

/* Native entry: 0x4037fca8. */
/* Original function-byte SHA-256:
 * 92c9598ac7519d458b9e367d0d7b28064c9bff38bae50b088825d1dda27f16a4. */
/* Timing-tuning-disabled specialization: returnfalse; no reads or side effects. */
bool spi_flash_timing_is_tuned(void)
{
    return false;
}

/* Native entry: 0x4038bd38. */
/* Original function-byte SHA-256:
 * 64f6826c008f9133a8dee4648736f196520362efc8021b3c49889eaeb25f0b54. */
/* Select host driver then initialize HAL, returning its status. Classify only
 * the starting pointer using wrapping unsigned ranges[3fc88000,403e0000),
 * [50000000,50002000),[600fe000,60100000). Read config host_id even on an
 * outside pointer. Outside+host0 returns102 without writing host; other IDs
 * remain allowed here. Internal+host0 selects default MSPI table, all other
 * accepted cases select GPSPI. Publish driver before HAL call; retain it on
 * HAL failure. No NULL, alignment, entire-object range or host-ID validation. */
int memspi_host_init_pointers(FlashHostView *host,const MemspiHostConfig *config)
{
    unsigned int address = (uintptr_t)host;
    bool internal = address - 0x3fc88000U < 0x758000U ||
        address - 0x50000000U < 0x2000U ||
        address - 0x600fe000U < 0x2000U;
    int host_id = ((const volatile MemspiHostConfig *)config)->host_id;
    if (!internal && host_id == 0)
        return 0x102;
    ((volatile FlashHostView *)host)->driver = host_id == 0 ?
        DEFAULT_MEMSPI_DRIVER : GPSPI_FLASH_DRIVER;
    return spi_flash_hal_init(host,config);
}

/* Native entry: 0x4037d794. */
/* Original function-byte SHA-256:
 * 92c9598ac7519d458b9e367d0d7b28064c9bff38bae50b088825d1dda27f16a4. */
/* Compiled32-bit-address feature check returns ESP_OK0 unconditionally. It
 * neither probes capability nor changes hardware or address configuration. */
int esp_mspi_32bit_address_flash_feature_check(void)
{
    return 0;
}
