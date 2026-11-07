/* Medius v3.4.7 host: flash API callbacks, probing and size/ID helpers. */
#include "../include/types.h"

/* Native entry: 0x4037c6ac. */
/* Original function-byte SHA-256:
 * c3ac57348983fa6702d76f5c2a7f3aa9dac4c0ee52f368ee936e1e6956825dd4. */
/* Flush host cache and end a flash operation, retaining an earlier error.
 * Only bus_acquired's low BYTE is tested. If zero, call the currently loaded
 * start callback; failure returns the original status if nonzero, otherwise
 * that start error, without flush/end. Once acquired, call optional host flush
 * even when status already failed; retain prior status over flush status.
 * Reload API table and return end(chip,status). No chip/host NULL validation,
 * direct cache instruction, rollback or local lock is supplied by this wrapper. */
int flash_flush_cache_and_end(EspFlash *chip,int status,unsigned int bus_acquired,
    unsigned int address,unsigned int length)
{
    if ((unsigned char)bus_acquired == 0) {
        int acquired = FLASH_API->start(chip);
        if (acquired != 0)
            return status != 0 ? status : acquired;
    }
    FlashHostView *host = ((volatile EspFlash *)chip)->host;
    int (*flush_cache)(FlashHostView *,unsigned int,unsigned int) =
        ((volatile FlashHostView *)host)->driver->flush_cache;
    int final_status = status;
    if (flush_cache != NULL) {
        int flushed = flush_cache(host,address,length);
        if (status == 0)
            final_status = flushed;
    }
    return FLASH_API->end(chip,final_status);
}

/* Native entry: 0x4037c6fc. */
/* Original function-byte SHA-256:
 * 029062938c5725d6d747cc2dbc48e3c91d5115af523cc45bc9d85796f085a391. */
/* Check/substitute an API chip pointer. Read *inout_chip; if NULL, load default
 * and write it back even when default is also NULL. A NULL default or absent
 * chip_driver returns0x6003; otherwise return0. The installed-driver predicate
 * only tests pointer presence. Does not validate the slot pointer, host, driver
 * callbacks, initialization state beyond that pointer, or acquire any lock. */
int flash_check_chip_pointer(EspFlash **inout_chip)
{
    EspFlash *chip = *(EspFlash *volatile *)inout_chip;
    if (chip == NULL) {
        chip = DEFAULT_FLASH_CHIP;
        *(EspFlash *volatile *)inout_chip = chip;
        if (chip == NULL)
            return 0x6003;
    }
    return esp_flash_chip_driver_initialized(chip) ? 0 : 0x6003;
}

/* Native entry: 0x4037c720. */
/* Original function-byte SHA-256:
 * 1929885881245b646c4001b05e420eb55c3c78bd1b35573e9f3a7a12c1f1a329. */
/* Probe registered flash drivers until the chip has one installed. Cache
 * chip_id and the registry base once. Each iteration reads the candidate then
 * tests driver presence, even for the terminating NULL candidate. An already
 * installed driver succeeds immediately. Otherwise publish the candidate before
 * start; start failure returns with that candidate still installed. Probe with
 * cached ID, clear chip_driver on probe failure, then call end(chip,0), ignoring
 * the probe status itself. End errors return; exhaustion without a driver gives
 *0x105. On success, log live driver's name only at early-log level>=3, return0.
 * No registry bounds, NULL chip/probe checks, locking around the list, or rollback. */
int flash_detect_chip_driver(EspFlash *chip)
{
    volatile EspFlash *state = chip;
    unsigned int flash_id = state->chip_id;
    const volatile FlashChipDriverView *const *registry = REGISTERED_FLASH_DRIVERS;
    while (true) {
        const volatile FlashChipDriverView *candidate =
            *(const volatile FlashChipDriverView *const volatile *)registry;
        bool installed = esp_flash_chip_driver_initialized(chip);
        if (installed)
            break;
        if (candidate == NULL)
            return 0x105;
        state->chip_driver = candidate;
        int result = FLASH_API->start(chip);
        if (result != 0)
            return result;
        const volatile FlashChipDriverView *driver = state->chip_driver;
        ++registry;
        int probed = driver->probe(chip,flash_id);
        if (probed != 0)
            state->chip_driver = NULL;
        result = FLASH_API->end(chip,0);
        if (result != 0)
            return result;
    }
    if (SYSTEM_EARLY_LOG_LEVEL >= 3) {
        unsigned int timestamp = esp_log_timestamp();
        const volatile FlashChipDriverView *driver = state->chip_driver;
        const char *name = driver->name;
        ets_printf("I (%lu) %s: detected chip: %s\n",timestamp,"spi_flash",name);
    }
    return 0;
}

/* Native entry: 0x4037c7b0. */
/* Original function-byte SHA-256:
 * a5ebb83890d82225fa4279136c9e389fea8c4d5c03c537e1b1e950bd579281d0. */
/* Read flash ID while holding the flash bus. Snapshot whether a driver was
 * installed before start(); start failure returns directly. If the snapshot
 * was true and the live driver's read_id slot is non-NULL, save that callback
 * with chip argument; otherwise save the host read_id callback/host argument.
 * On successful first read and nonzero full-word sanity_check, invoke the same
 * saved callback again into a local WORD, read second then first ID, and report
 *0x6003 on mismatch. Return current end(chip,status), preserving whatever first
 * read wrote even if sanity check/end fails. No output, chip or callback checks. */
int flash_read_id_core(EspFlash *chip,unsigned int *flash_id,unsigned int sanity_check)
{
    bool installed = esp_flash_chip_driver_initialized(chip);
    int result = FLASH_API->start(chip);
    if (result != 0)
        return result;
    volatile EspFlash *state = chip;
    FlashReadIdOperation read_id = NULL;
    void *argument = chip;
    if (installed)
        read_id = state->chip_driver->read_id;
    if (read_id == NULL) {
        FlashHostView *host = state->host;
        argument = host;
        read_id = ((volatile FlashHostView *)host)->driver->read_id;
    }
    result = read_id(argument,flash_id);
    if (result == 0 && sanity_check != 0) {
        unsigned int second_id;
        result = read_id(argument,&second_id);
        if (result == 0) {
            unsigned int second = *(volatile unsigned int *)&second_id;
            unsigned int first = *(volatile unsigned int *)flash_id;
            if (first != second)
                result = 0x6003;
        }
    }
    return FLASH_API->end(chip,result);
}

/* Native entry: 0x4037c814. */
/* Original function-byte SHA-256:
 * 2dec7dfae1635a74884a1822414c7f13ae2a428b660b491a1720406873548e92. */
/* Detect physical flash size. Check/substitute chip, require detect_size slot
 * before checking output (0x6005 then0x102), start and invoke the live slot into
 * a local WORD. On success, read cached chip size then detected WORD; initialize
 * chip.size only when it was0 and always publish detected size to output.
 * End(chip,status) determines the return value. Errors do not restore earlier
 * field/output writes. No local NULL chip/driver, detected-size or lock checks. */
int esp_flash_get_physical_size(void *opaque_chip,unsigned int *output)
{
    EspFlash *volatile current_chip = opaque_chip;
    int result = FLASH_API->chip_check((EspFlash **)&current_chip);
    if (result != 0)
        return result;
    volatile EspFlash *chip = current_chip;
    if (chip->chip_driver->detect_size == NULL)
        return 0x6005;
    if (output == NULL)
        return 0x102;
    result = FLASH_API->start((EspFlash *)chip);
    if (result != 0)
        return result;
    chip = current_chip;
    unsigned int physical_size;
    result = chip->chip_driver->detect_size((EspFlash *)chip,&physical_size);
    chip = current_chip;
    if (result == 0) {
        unsigned int cached_size = chip->size;
        unsigned int detected_size = *(volatile unsigned int *)&physical_size;
        if (cached_size == 0)
            chip->size = detected_size;
        *(volatile unsigned int *)output = detected_size;
    }
    return FLASH_API->end((EspFlash *)chip,result);
}

/* Native entry: 0x4037ceb8. */
/* Original function-byte SHA-256:
 * 5c19a4ef859cc903186da116db1c8bc9bd4a14a1b69460c08b6b9ee508f1009e. */
/* Read decrypted bytes through a temporary DATA cache mapping. Check/substitute
 * chip first, but bounds use the global ROM chip size rather than chip.size.
 * Wrapping(address+length)>ROM size gives0x104; zero length then returns0 even
 * with NULL output. A nonzero NULL output gives0x102. Align address to64KiB,
 * add within-page offset to mapping size with32-bit wrap, map/copy/unmap and
 * return map status0. Mapping failure leaves output untouched. No default-chip
 * restriction, source overflow check, transfer lock or cleanup result exists. */
int esp_flash_read_encrypted(void *opaque_chip,unsigned int address,void *output,unsigned int length)
{
    EspFlash *volatile current_chip = opaque_chip;
    int result = FLASH_API->chip_check((EspFlash **)&current_chip);
    if (result != 0)
        return result;
    RomFlashLegacy *rom = ROM_FLASH_LEGACY;
    unsigned int rom_size = ((volatile RomFlashLegacy *)rom)->chip.chip_size;
    if (address + length > rom_size)
        return 0x104;
    if (length == 0)
        return 0;
    if (output == NULL)
        return 0x102;
    unsigned int page_offset = address & 0xffffU;
    const void *mapped;
    unsigned int handle;
    result = spi_flash_mmap(address & 0xffff0000U,length + page_offset,0,&mapped,&handle);
    if (result == 0) {
        const void *source = *(const void *volatile *)&mapped;
        memcpy(output,(const void *)((uintptr_t)source + page_offset),length);
        spi_flash_munmap(*(volatile unsigned int *)&handle);
    }
    return result;
}

/* Native entry: 0x4037d79c. */
/* Original function-byte SHA-256:
 * 6db5833c47c4006224226dd6b95da5a686a04737648bafabe7e192cec1616de1. */
/* Default flash-operation start. If OS table/start exists, invoke it with the
 * current context and propagate failure without host configuration. Otherwise
 * reload host/table and call dev_config(host), discarding its result, return0.
 * No chip/host/dev_config NULL checks; locking is delegated to the OS hook. */
int flash_start_default(EspFlash *chip)
{
    volatile EspFlash *state = chip;
    const volatile MainFlashOsFunctions *os = state->os_functions;
    if (os != NULL) {
        int (*start)(FlashOsContext *) = os->start;
        if (start != NULL) {
            int result = start(state->os_context);
            if (result != 0)
                return result;
        }
    }
    FlashHostView *host = state->host;
    (void)((volatile FlashHostView *)host)->driver->dev_config(host);
    return 0;
}

/* Native entry: 0x4037d7c8. */
/* Original function-byte SHA-256:
 * e08e50d3b90fd1f666237431e09af6b35a87e421267c41ab1ca865ad623fc14a. */
/* Default flash-operation end. Invoke OS end when present, even after an
 * earlier nonzero status; preserve that status over the hook's result. With
 * status0 return the hook result, or0 if absent. No chip checks or cache work. */
int flash_end_default(EspFlash *chip,int status)
{
    volatile EspFlash *state = chip;
    const volatile MainFlashOsFunctions *os = state->os_functions;
    if (os != NULL) {
        int (*end)(FlashOsContext *) = os->end;
        if (end != NULL) {
            int ended = end(state->os_context);
            if (status == 0)
                return ended;
        }
    }
    return status;
}

/* Native entry: 0x4037d7e8. */
/* Original function-byte SHA-256:
 * fbda58cc3a92b354b12f1387a59c3d0cabe3104db9e0add7ba45ee26602fb324. */
/* Return whether chip_driver is non-NULL as canonical bool0/1. Dereference chip
 * without a NULL check; pointer presence does not establish working hardware. */
bool esp_flash_chip_driver_initialized(const EspFlash *chip)
{
    return ((const volatile EspFlash *)chip)->chip_driver != NULL;
}
