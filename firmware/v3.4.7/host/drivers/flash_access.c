/* Medius v3.4.7 host: flash API transfers, region erasure and encryption. */
#include "../include/types.h"

/* Native entry: 0x4037c9e0. */
/* Original function-byte SHA-256:
 * c0ef982a7af6a0f466933e29672525102bd082ce78f0d8685047b31775e8ce4c. */
/* Erase a chip-relative range through the loaded flash API/driver callbacks.
 * chip_check may replace the chip pointer. Require sector/block erase slots
 * before OS protection;0x10d is returned, other protection failures abort.
 * After that callback reload driver: a now-NULL block slot selects block size0.
 * Reject sector size0 or block size not divisible by sector size with0x6003;
 * bounds/alignment failures return0x102, then a zero length returns0.
 * Optionally start/get protected-region mask/end, rejecting overlapping set
 * regions with0x6006. Native mask selection repeats bits modulo64 if a malformed
 * region count exceeds64; region-end and request-end additions wrap32 bits.
 * Yield/start each erase; use an aligned block when it fits, else one sector.
 * Advance/decrement even after erase failure and assert remaining<original.
 * Intermediate end failures and completed/error erases flush with acquired1;
 * start failure flushes with0; yield failures return directly. Return the final
 * flush result. No rollback, cancellation, local timeout or complete erase proof. */
int esp_flash_erase_region(void *opaque_chip,unsigned int address,unsigned int length)
{
    EspFlash *volatile current_chip = opaque_chip;
    int result = FLASH_API->chip_check((EspFlash **)&current_chip);
    if (result != 0)
        return result;
    volatile EspFlash *chip = current_chip;
    const volatile FlashChipDriverView *driver = chip->chip_driver;
    if (driver->erase_sector == NULL || driver->erase_block == NULL)
        return 0x6005;
    int (*protected_by_os)(FlashOsContext *,unsigned int,unsigned int) = chip->os_functions->region_protected;
    unsigned int sector_size,block_size;
    if (protected_by_os != NULL) {
        result = protected_by_os(chip->os_context,address,length);
        if (result == 0x10d)
            return result;
        if (result != 0)
            abort();
        chip = current_chip;
        driver = chip->chip_driver;
        if (driver->erase_block == NULL) {
            sector_size = driver->sector_size;
            block_size = 0;
            if (sector_size == 0)
                return 0x6003;
        } else {
            sector_size = driver->sector_size;
            if (sector_size == 0)
                return 0x6003;
            block_size = driver->block_erase_size;
            if (block_size % sector_size != 0)
                return 0x6003;
        }
    } else {
        sector_size = driver->sector_size;
        if (sector_size == 0)
            return 0x6003;
        block_size = driver->block_erase_size;
        if (block_size % sector_size != 0)
            return 0x6003;
    }
    unsigned int chip_size = chip->size;
    if (address > chip_size || length > chip_size - address ||
        address % sector_size != 0 || length % sector_size != 0)
        return 0x102;
    if (length == 0)
        return 0;

    if (driver->get_protected_regions != NULL && driver->num_protectable_regions != 0) {
        result = FLASH_API->start((EspFlash *)chip);
        if (result != 0)
            return result;
        chip = current_chip;
        unsigned long long protected_regions = 0;
        result = chip->chip_driver->get_protected_regions((EspFlash *)chip,&protected_regions);
        chip = current_chip;
        if (result == 0) {
            unsigned int low_mask = (unsigned int)protected_regions;
            unsigned int high_mask = (unsigned int)(protected_regions >> 32);
            if ((low_mask | high_mask) != 0) {
                driver = chip->chip_driver;
                unsigned int count = driver->num_protectable_regions;
                if (count != 0) {
                    const FlashProtectedRegion *regions = driver->protectable_regions;
                    unsigned int request_end = address + length;
                    for (unsigned int index = 0; index != count; ++index) {
                        unsigned int mask = (index & 32U) != 0 ? high_mask : low_mask;
                        if (((mask >> (index & 31U)) & 1U) != 0) {
                            const volatile FlashProtectedRegion *region = &regions[index];
                            unsigned int start = region->offset;
                            unsigned int size = region->size;
                            if (address < start + size && start < request_end) {
                                result = 0x6006;
                                break;
                            }
                        }
                    }
                }
            }
        }
        result = FLASH_API->end((EspFlash *)chip,result);
        if (result != 0)
            return result;
    }

    unsigned int erase_address = address;
    unsigned int remaining = length;
    unsigned int bus_acquired;
    while (true) {
        chip = current_chip;
        FlashYieldOperation yield = chip->chip_driver->yield;
        if (yield != NULL) {
            result = yield((EspFlash *)chip,0);
            if (result != 0)
                return result;
            chip = current_chip;
        }
        result = FLASH_API->start((EspFlash *)chip);
        chip = current_chip;
        if (result != 0) {
            bus_acquired = 0;
            break;
        }
        driver = chip->chip_driver;
        if (remaining > block_size - 1U && erase_address % block_size == 0) {
            result = driver->erase_block((EspFlash *)chip,erase_address);
            erase_address += block_size;
            remaining -= block_size;
        } else {
            result = driver->erase_sector((EspFlash *)chip,erase_address);
            erase_address += sector_size;
            remaining -= sector_size;
        }
        if (remaining >= length)
            __assert_func(NULL,0,NULL,NULL);
        bus_acquired = 1;
        if (result != 0 || remaining == 0)
            break;
        result = FLASH_API->end(current_chip,0);
        if (result != 0)
            break;
    }
    return FLASH_API->flash_end_flush_cache(current_chip,result,bus_acquired,address,length);
}

/* Native entry: 0x4037cbf8. */
/* Original function-byte SHA-256:
 * 67c2a599a78163658dda2c0da39081def978160ad3156cfe29586ebd48e1dcb8. */
/* Read chip-relative bytes. chip_check may substitute the chip; missing read
 * slot returns0x6005. NULL output, address>size or wrapping(address+length)>size
 * returns0x102. This is not the subtraction-based overflow check used by writes.
 * Zero length returns0 after those checks. Always query host direct support;
 * DRAM0x3fc88000..0x3fcfffff or supported output uses direct transfers, otherwise
 * request an OS temporary buffer. Missing/NULL buffer returns0x101. Initial
 * chunk cap is min(length,16KiB); accept the allocator's actual cap unchanged.
 * Start/read/end each chunk. Read failure ignores end's status and stops; an
 * end failure after successful read still copies temporary data back. Advance
 * pointers/counts before testing end status. Cleanup calls the current OS
 * release callback even on a direct path with bufferNULL, except allocation
 * failures return before cleanup. A zero actual chunk can stall indefinitely.
 * No rollback, total bytes-read result or additional output-span validation. */
int esp_flash_read(void *opaque_chip,void *output,unsigned int address,unsigned int length)
{
    EspFlash *volatile current_chip = opaque_chip;
    int result = FLASH_API->chip_check((EspFlash **)&current_chip);
    if (result != 0)
        return result;
    volatile EspFlash *chip = current_chip;
    if (chip->chip_driver->read == NULL)
        return 0x6005;
    if (output == NULL)
        return 0x102;
    unsigned int chip_size = chip->size;
    if (address > chip_size || address + length > chip_size)
        return 0x102;
    if (length == 0)
        return 0;
    FlashHostView *host = chip->host;
    bool supported = ((volatile FlashHostView *)host)->driver->supports_direct_read(host,output);
    unsigned int chunk_limit = length < 0x4000U ? length : 0x4000U;
    void *temporary = NULL;
    if ((uintptr_t)output - 0x3fc88000U >= 0x78000U && !supported) {
        chip = current_chip;
        void *(*allocate_buffer)(void *,unsigned int,unsigned int *) = chip->os_functions->get_temp_buffer;
        if (allocate_buffer == NULL)
            return 0x101;
        unsigned int actual_size = 0;
        temporary = allocate_buffer(chip->os_context,chunk_limit,&actual_size);
        chunk_limit = *(volatile unsigned int *)&actual_size;
        if (temporary == NULL)
            return 0x101;
    }
    while (true) {
        result = FLASH_API->start(current_chip);
        chip = current_chip;
        if (result != 0)
            break;
        unsigned int chunk = length < chunk_limit ? length : chunk_limit;
        result = chip->chip_driver->read((EspFlash *)chip,
            temporary == NULL ? output : temporary,address,chunk);
        if (result != 0) {
            (void)FLASH_API->end(current_chip,result);
            break;
        }
        result = FLASH_API->end(current_chip,0);
        if (temporary != NULL)
            memcpy(output,temporary,chunk);
        length -= chunk;
        address += chunk;
        output = (void *)((uintptr_t)output + chunk);
        if (result != 0 || length == 0)
            break;
    }
    chip = current_chip;
    void (*release_buffer)(void *,void *) = chip->os_functions->release_temp_buffer;
    if (release_buffer != NULL)
        release_buffer(chip->os_context,temporary);
    return result;
}

/* Native entry: 0x4037cd3c. */
/* Original function-byte SHA-256:
 * dbeb906d34f595ce8989fe16ed623e8002036695451ca43d8864aee8223c9237. */
/* Write chip-relative bytes. Check/substitute chip, require write slot0x6005,
 * then apply optional OS protection (0x10d returned; other errors abort).
 * Reject NULL source or subtraction-checked bounds0x102; zero length returns0.
 * Always query host direct support. Cache the BYTE of support OR DRAM-membership;
 * direct source writes at most8192 bytes per chunk, otherwise copy at most32
 * bytes into the stack buffer before each yield/start. Yield errors return
 * immediately. Start errors flush with acquired0; driver/end errors flush with1
 * but return the original error, logging only if cleanup itself fails. The last
 * successful write returns cleanup's status directly without that diagnostic.
 * Decrement remaining even after driver failure and assert it<original length.
 * Advance address/source only after successful intermediate end. No erase,
 * rollback, readback verification, cancellation or per-call timeout here. */
int esp_flash_write(void *opaque_chip,const void *data,unsigned int address,unsigned int length)
{
    EspFlash *volatile current_chip = opaque_chip;
    int result = FLASH_API->chip_check((EspFlash **)&current_chip);
    if (result != 0)
        return result;
    volatile EspFlash *chip = current_chip;
    if (chip->chip_driver->write == NULL)
        return 0x6005;
    int (*protected_by_os)(FlashOsContext *,unsigned int,unsigned int) = chip->os_functions->region_protected;
    if (protected_by_os != NULL) {
        int protection = protected_by_os(chip->os_context,address,length);
        if (protection == 0x10d)
            return protection;
        if (protection != 0)
            abort();
    }
    if (data == NULL)
        return 0x102;
    chip = current_chip;
    unsigned int chip_size = chip->size;
    if (address > chip_size || length > chip_size - address)
        return 0x102;
    if (length == 0)
        return 0;
    FlashHostView *host = chip->host;
    unsigned int supported = ((volatile FlashHostView *)host)->driver->supports_direct_write(host,data);
    unsigned char direct = supported | ((uintptr_t)data - 0x3fc88000U < 0x78000U);
    unsigned int remaining = length;
    unsigned int write_address = address;
    unsigned int bus_acquired;
    unsigned int temporary[8];
    while (true) {
        unsigned int limit = direct != 0 ? 0x2000U : 32U;
        unsigned int chunk = remaining < limit ? remaining : limit;
        const void *source = data;
        if (direct == 0) {
            memcpy(temporary,data,chunk);
            source = temporary;
        }
        chip = current_chip;
        FlashYieldOperation yield = chip->chip_driver->yield;
        if (yield != NULL) {
            result = yield((EspFlash *)chip,0);
            if (result != 0)
                return result;
            chip = current_chip;
        }
        result = FLASH_API->start((EspFlash *)chip);
        chip = current_chip;
        if (result != 0) {
            bus_acquired = 0;
            break;
        }
        result = chip->chip_driver->write((EspFlash *)chip,source,write_address,chunk);
        remaining -= chunk;
        if (remaining >= length)
            __assert_func(NULL,0,NULL,NULL);
        bus_acquired = 1;
        if (result != 0)
            break;
        if (remaining == 0)
            return FLASH_API->flash_end_flush_cache(current_chip,0,1,address,length);
        result = FLASH_API->end(current_chip,0);
        if (result != 0)
            break;
        write_address += chunk;
        data = (const void *)((uintptr_t)data + chunk);
    }
    int cleanup = FLASH_API->flash_end_flush_cache(current_chip,result,bus_acquired,address,length);
    if (cleanup != 0 && SYSTEM_EARLY_LOG_LEVEL != 0)
        ets_printf("E %s: restore cache fail\n\n","spi_flash");
    return result;
}

/* Native entry: 0x4037cf24. */
/* Original function-byte SHA-256:
 * ccb9026b631291b1de82f0e514aebbcd58a8ab924b6c06341fe9e5e281769475. */
/* Encrypted writes for the default flash chip only. Check/substitute chip,
 * require ordinary write slot0x6005 (not write_encrypted), reject other chip
 *0x106, then OS protection0x10d/abort. Validate non-NULL source/bounds0x102,
 * address16-byte alignment0x102, zero length0, length16-byte multiple0x104.
 * DRAM source locks once for the whole write; other source locks each row after
 * copying it to the aligned64-byte stack buffer. Choose64,32 or16 bytes by row
 * address alignment and remaining length. Invoke encrypted driver slot without
 * a separate NULL check. After non-DRAM rows end the bus before progressing;
 * after DRAM completion end once. Successful completion returns flush status
 * with acquired0. Any row/start/end failure calls end(chip,0) again and flushes
 * acquired0 with the original error; ignore cleanup status except diagnostic.
 * An initial DRAM start failure logs/returns directly. No yielding, rollback,
 * readback, recovery or written-byte result. Prior rows can already be changed. */
int esp_flash_write_encrypted(void *opaque_chip,unsigned int address,const void *data,unsigned int length)
{
    EspFlash *volatile current_chip = opaque_chip;
    int result = FLASH_API->chip_check((EspFlash **)&current_chip);
    if (result != 0)
        return result;
    volatile EspFlash *chip = current_chip;
    if (chip->chip_driver->write == NULL)
        return 0x6005;
    if ((void *)chip != DEFAULT_FLASH_CHIP)
        return 0x106;
    int (*protected_by_os)(FlashOsContext *,unsigned int,unsigned int) = chip->os_functions->region_protected;
    if (protected_by_os != NULL) {
        int protection = protected_by_os(chip->os_context,address,length);
        if (protection == 0x10d)
            return protection;
        if (protection != 0)
            abort();
    }
    if (data == NULL)
        return 0x102;
    chip = current_chip;
    unsigned int chip_size = chip->size;
    if (address > chip_size || length > chip_size - address)
        return 0x102;
    if ((address & 15U) != 0) {
        if (SYSTEM_EARLY_LOG_LEVEL != 0)
            ets_printf("E %s: flash encrypted write address must be 16 bytes aligned\n","spi_flash");
        return 0x102;
    }
    if (length == 0)
        return 0;
    if ((length & 15U) != 0) {
        if (SYSTEM_EARLY_LOG_LEVEL != 0)
            ets_printf("E %s: flash encrypted write length must be multiple of 16\n","spi_flash");
        return 0x104;
    }
    bool lock_once = (uintptr_t)data - 0x3fc88000U < 0x78000U;
    if (lock_once) {
        result = FLASH_API->start((EspFlash *)chip);
        if (result != 0) {
            if (SYSTEM_EARLY_LOG_LEVEL != 0)
                ets_printf("E %s: flash acquire lock failed\n","spi_flash");
            return result;
        }
    }
    unsigned int temporary[16];
    unsigned int offset = 0;
    do {
        unsigned int row_address = address + offset;
        unsigned int remaining = length - offset;
        unsigned int row_size;
        if ((row_address & 63U) == 0 && remaining >= 64U)
            row_size = 64;
        else if ((row_address & 31U) == 0 && remaining >= 32U)
            row_size = 32;
        else
            row_size = 16;
        memcpy(temporary,(const void *)((uintptr_t)data + offset),row_size);
        chip = current_chip;
        if (!lock_once) {
            result = FLASH_API->start((EspFlash *)chip);
            chip = current_chip;
            if (result != 0)
                goto restore_cache;
        }
        result = chip->chip_driver->write_encrypted((EspFlash *)chip,temporary,row_address,row_size);
        if (result != 0)
            goto restore_cache;
        if (!lock_once) {
            result = FLASH_API->end(current_chip,0);
            if (result != 0)
                goto restore_cache;
        }
        offset += row_size;
    } while (offset < length);
    if (lock_once) {
        result = FLASH_API->end(current_chip,0);
        if (result != 0)
            goto restore_cache;
    }
    return FLASH_API->flash_end_flush_cache(current_chip,0,0,address,length);

restore_cache:
    (void)FLASH_API->end(current_chip,0);
    int cleanup = FLASH_API->flash_end_flush_cache(current_chip,result,0,address,length);
    if (cleanup != 0 && SYSTEM_EARLY_LOG_LEVEL != 0)
        ets_printf("E %s: restore cache fail\n\n","spi_flash");
    return result;
}
