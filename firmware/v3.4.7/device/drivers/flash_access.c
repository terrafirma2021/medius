/* Medius v3.4.7 device: flash API transfers, region erasure and encryption. */
#include "../include/types.h"

/* Native entry: 0x4037e278. */
/* Original function-byte SHA-256:
 * c6aed003e1e94a284e7bb39b22174a1bfc54fd19b3add464fedeca8f4f4bd8b0. */
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
    const volatile FlashApiFunctions *api = FLASH_API;
    int (*check_chip)(EspFlash **) = api->chip_check;
    int result = check_chip((EspFlash **)&current_chip);
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
        api = FLASH_API;
        int (*start_query)(EspFlash *) = api->start;
        result = start_query((EspFlash *)chip);
        if (result != 0)
            return result;
        chip = current_chip;
        int (*get_protected_regions)(EspFlash *,unsigned long long *) =
            chip->chip_driver->get_protected_regions;
        unsigned long long protected_regions = 0;
        result = get_protected_regions((EspFlash *)chip,&protected_regions);
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
        api = FLASH_API;
        int (*end_query)(EspFlash *,int) = api->end;
        result = end_query((EspFlash *)chip,result);
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
        api = FLASH_API;
        int (*start_erase)(EspFlash *) = api->start;
        result = start_erase((EspFlash *)chip);
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
        /* These native reads also occur after a failed or final erase. */
        api = FLASH_API;
        chip = current_chip;
        if (result != 0 || remaining == 0)
            break;
        int (*end_erase)(EspFlash *,int) = api->end;
        result = end_erase((EspFlash *)chip,0);
        if (result != 0)
            break;
    }
    api = FLASH_API;
    chip = current_chip;
    int (*flush_erase)(EspFlash *,int,unsigned int,unsigned int,unsigned int) =
        api->flash_end_flush_cache;
    return flush_erase((EspFlash *)chip,result,bus_acquired,address,length);
}

/* Native entry: 0x4037e490. */
/* Original function-byte SHA-256:
 * 577c595aea187f02034df59985a9a8e429906d4462878d306e4333dcc66c2558. */
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
    const volatile FlashApiFunctions *api = FLASH_API;
    int (*check_chip)(EspFlash **) = api->chip_check;
    int result = check_chip((EspFlash **)&current_chip);
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
        unsigned int actual_size = 0;
        void *(*allocate_buffer)(void *,unsigned int,unsigned int *) = chip->os_functions->get_temp_buffer;
        if (allocate_buffer == NULL)
            return 0x101;
        temporary = allocate_buffer(chip->os_context,chunk_limit,&actual_size);
        chunk_limit = *(volatile unsigned int *)&actual_size;
        if (temporary == NULL)
            return 0x101;
    }
    while (true) {
        api = FLASH_API;
        chip = current_chip;
        int (*start_read)(EspFlash *) = api->start;
        result = start_read((EspFlash *)chip);
        chip = current_chip;
        if (result != 0)
            break;
        unsigned int chunk = length < chunk_limit ? length : chunk_limit;
        result = chip->chip_driver->read((EspFlash *)chip,
            temporary == NULL ? output : temporary,address,chunk);
        int (*end_read)(EspFlash *,int);
        if (temporary == NULL) {
            /* The direct path preloads END even if READ failed. A failed
             * read then reloads the table, chip and END for cleanup below. */
            api = FLASH_API;
            end_read = api->end;
            chip = current_chip;
            if (result != 0)
                goto failed_read;
        } else {
            if (result != 0)
                goto failed_read;
            api = FLASH_API;
            chip = current_chip;
            end_read = api->end;
        }
        result = end_read((EspFlash *)chip,0);
        if (temporary != NULL)
            memcpy(output,temporary,chunk);
        length -= chunk;
        address += chunk;
        output = (void *)((uintptr_t)output + chunk);
        if (result != 0 || length == 0) {
            chip = current_chip;
            break;
        }
    }
    goto release_read_buffer;

failed_read:
    api = FLASH_API;
    chip = current_chip;
    int (*end_failed_read)(EspFlash *,int) = api->end;
    (void)end_failed_read((EspFlash *)chip,result);
    chip = current_chip;

release_read_buffer:;
    void (*release_buffer)(void *,void *) = chip->os_functions->release_temp_buffer;
    if (release_buffer != NULL)
        release_buffer(chip->os_context,temporary);
    return result;
}

/* Native entry: 0x4037e5d4. */
/* Original function-byte SHA-256:
 * f2cd2aab14efe85253b8c5590d8caeba4a6326e164785af8e0eee9a640b9f38f. */
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
    const volatile FlashApiFunctions *api = FLASH_API;
    int (*check_chip)(EspFlash **) = api->chip_check;
    int result = check_chip((EspFlash **)&current_chip);
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
    unsigned int temporary[8] __attribute__((aligned(16)));
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
        api = FLASH_API;
        int (*start_write)(EspFlash *) = api->start;
        result = start_write((EspFlash *)chip);
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
        /* Preserve the table/chip snapshots before testing the write result. */
        api = FLASH_API;
        chip = current_chip;
        if (result != 0)
            break;
        if (remaining == 0) {
            int (*flush_successful_write)(EspFlash *,int,unsigned int,unsigned int,unsigned int) =
                api->flash_end_flush_cache;
            return flush_successful_write((EspFlash *)chip,0,1,address,length);
        }
        int (*end_write)(EspFlash *,int) = api->end;
        result = end_write((EspFlash *)chip,0);
        if (result != 0)
            break;
        write_address += chunk;
        data = (const void *)((uintptr_t)data + chunk);
    }
    api = FLASH_API;
    chip = current_chip;
    int (*flush_failed_write)(EspFlash *,int,unsigned int,unsigned int,unsigned int) =
        api->flash_end_flush_cache;
    int cleanup = flush_failed_write((EspFlash *)chip,result,bus_acquired,address,length);
    if (cleanup != 0 && SYSTEM_EARLY_LOG_LEVEL != 0)
        ets_printf("E %s: restore cache fail\n\n","spi_flash");
    return result;
}

/* Native entry: 0x4037e7bc. */
/* Original function-byte SHA-256:
 * 991772a88b00536bd68445194501c845174b55b2729b44f5dde7aeb7219000ff. */
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
    const volatile FlashApiFunctions *api = FLASH_API;
    int (*check_chip)(EspFlash **) = api->chip_check;
    int result = check_chip((EspFlash **)&current_chip);
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
        api = FLASH_API;
        int (*start_direct_write)(EspFlash *) = api->start;
        result = start_direct_write((EspFlash *)chip);
        if (result != 0) {
            if (SYSTEM_EARLY_LOG_LEVEL != 0)
                ets_printf("E %s: flash acquire lock failed\n","spi_flash");
            return result;
        }
    }
    unsigned int temporary[16] __attribute__((aligned(16)));
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
            api = FLASH_API;
            int (*start_row)(EspFlash *) = api->start;
            result = start_row((EspFlash *)chip);
            chip = current_chip;
            if (result != 0)
                goto restore_cache;
        }
        result = chip->chip_driver->write_encrypted((EspFlash *)chip,temporary,row_address,row_size);
        if (!lock_once) {
            /* Native non-DRAM rows prefetch END before testing WRITE. */
            api = FLASH_API;
            int (*end_row)(EspFlash *,int) = api->end;
            chip = current_chip;
            if (result != 0)
                goto restore_cache;
            result = end_row((EspFlash *)chip,0);
            if (result != 0)
                goto restore_cache;
        } else if (result != 0)
            goto restore_cache;
        offset += row_size;
    } while (offset < length);
    if (lock_once) {
        api = FLASH_API;
        chip = current_chip;
        int (*end_direct_write)(EspFlash *,int) = api->end;
        result = end_direct_write((EspFlash *)chip,0);
        if (result != 0)
            goto restore_cache;
    }
    api = FLASH_API;
    int (*flush_successful_encryption)(EspFlash *,int,unsigned int,unsigned int,unsigned int) =
        api->flash_end_flush_cache;
    chip = current_chip;
    return flush_successful_encryption((EspFlash *)chip,0,0,address,length);

restore_cache:
    api = FLASH_API;
    chip = current_chip;
    int (*end_failed_encryption)(EspFlash *,int) = api->end;
    (void)end_failed_encryption((EspFlash *)chip,0);
    api = FLASH_API;
    chip = current_chip;
    int (*flush_failed_encryption)(EspFlash *,int,unsigned int,unsigned int,unsigned int) =
        api->flash_end_flush_cache;
    int cleanup = flush_failed_encryption((EspFlash *)chip,result,0,address,length);
    if (cleanup != 0 && SYSTEM_EARLY_LOG_LEVEL != 0)
        ets_printf("E %s: restore cache fail\n\n","spi_flash");
    return result;
}
