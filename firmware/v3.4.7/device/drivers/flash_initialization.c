/* Medius v3.4.7 device: main-flash chip detection and bus-mode initialization. */
#include "../include/types.h"

/* Native entry: 0x4037e114. */
/* Original function-byte SHA-256:
 * 8402a9acab148a407468654c7d92cd30660bcac51b1c7b09efaec7e816c3cccf. */
/* Initialize main flash. Require chip,host,host-driver and memspi SPI pointer,
 * returning0x102 if absent. Snapshot read_mode: values>=16 use ROM device_id
 * without issuing RDID; smaller modes retry sanity-checked RDID at most11 times,
 * retrying only0x6003. Store ID, probe a driver only if absent, then get physical
 * size. Errors retain earlier state and return immediately, with gated size log.
 * Optional get_chip_caps checks bit1 for >16MiB support. Missing callback warns;
 * absent support caps only the local physical-size WORD at16MiB and warns. This
 * path does not change chip.size to that cap. Diagnostics use cached/reloaded
 * early-log levels in native order; info indexes ten-byte mode labels using
 * the live read_mode after timestamp, without bounds validation.
 * Start bus, skip mode setup if original snapshot>=16, otherwise call the live
 * set_io_mode slot. Ignore0x108 unless the current mode is4 or5 (quad). Return
 * end(chip,status). No ROM/default-chip identity check, rollback, explicit bus
 * timeout, source-mode validation or hardware state verification is added. */
int esp_flash_init_main(void *opaque_chip)
{
    EspFlash *chip = opaque_chip;
    if (chip == NULL)
        return 0x102;
    volatile EspFlash *state = chip;
    FlashHostView *host = state->host;
    if (host == NULL)
        return 0x102;
    volatile FlashHostView *host_state = host;
    if (host_state->driver == NULL || host_state->spi == NULL)
        return 0x102;
    unsigned int original_mode = state->read_mode;
    volatile unsigned int flash_id = 0;
    unsigned int detected_id;
    int result;
    if (original_mode >= 16) {
        RomFlashLegacy *rom = ROM_FLASH_LEGACY;
        detected_id = ((volatile RomFlashLegacy *)rom)->chip.device_id;
        flash_id = detected_id;
    } else {
        unsigned int attempts = 11;
        do {
            result = esp_flash_read_chip_id(chip,(unsigned int *)&flash_id);
            --attempts;
        } while (result == 0x6003 && attempts != 0);
        if (result != 0)
            return result;
        detected_id = flash_id;
    }
    state->chip_id = detected_id;
    if (!esp_flash_chip_driver_initialized(chip)) {
        result = flash_detect_chip_driver(chip);
        if (result != 0)
            return result;
    }
    volatile unsigned int physical_size;
    result = esp_flash_get_physical_size(chip,(unsigned int *)&physical_size);
    if (result != 0) {
        if (SYSTEM_EARLY_LOG_LEVEL != 0) {
            unsigned int timestamp = esp_log_timestamp();
            ets_printf("E (%lu) %s: failed to get chip size\n",timestamp,"spi_flash");
        }
        return result;
    }
    unsigned int (*get_capabilities)(EspFlash *) = state->chip_driver->get_chip_caps;
    unsigned int log_level;
    if (get_capabilities == NULL) {
        log_level = SYSTEM_EARLY_LOG_LEVEL;
        if (log_level < 2)
            goto configure_bus;
        unsigned int timestamp = esp_log_timestamp();
        ets_printf("W (%lu) %s: get_chip_caps function pointer hasn't been initialized\n",timestamp,"spi_flash");
        log_level = SYSTEM_EARLY_LOG_LEVEL;
    } else {
        unsigned int capabilities = get_capabilities(chip);
        log_level = SYSTEM_EARLY_LOG_LEVEL;
        if ((capabilities & 2U) == 0 && physical_size > 0x1000000U) {
            if (log_level < 2) {
                physical_size = 0x1000000U;
                goto configure_bus;
            }
            unsigned int timestamp = esp_log_timestamp();
            ets_printf("W (%lu) %s: Detected flash size > 16 MB, but access beyond 16 MB is not supported for this flash model yet.\n",timestamp,"spi_flash");
            log_level = SYSTEM_EARLY_LOG_LEVEL;
            physical_size = 0x1000000U;
        }
    }
    if (log_level >= 3) {
        unsigned int timestamp = esp_log_timestamp();
        unsigned int mode = state->read_mode;
        const char *mode_label = (const char *)((uintptr_t)FLASH_IO_MODE_LABELS + mode * 10U);
        ets_printf("I (%lu) %s: flash io: %s\n",timestamp,"spi_flash",mode_label);
    }
configure_bus:
    result = FLASH_API->start(chip);
    if (result != 0)
        return result;
    if (original_mode < 16) {
        result = state->chip_driver->set_io_mode(chip);
        if (result == 0x108 && state->read_mode - 4U >= 2U)
            result = 0;
    }
    return FLASH_API->end(chip,result);
}

/* Native entry: 0x42010738. */
/* Original function-byte SHA-256:
 * 3ae648327672a19b2550780c382b34b89e69cc040602fe41e99a61830c55c9a6. */
/* Forward chip/output to the ID core with sanity_check1 and return its status.
 * Successful reads are compared twice by that core. No extra validation,
 * chip substitution, retry or locking is performed in this wrapper. */
int esp_flash_read_chip_id(EspFlash *chip,unsigned int *flash_id)
{
    return flash_read_id_core(chip,flash_id,1);
}
