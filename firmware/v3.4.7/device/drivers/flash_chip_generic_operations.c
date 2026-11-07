/* Medius v3.4.7 device: generic flash-chip reset, transfers, erasure and polling. */
#include "../include/types.h"

/* Inline reconstruction utilities retain the native optional OS status hook.
 * The helper adds no firmware entry and reloads the table at each call site. */
static __inline__ __attribute__((always_inline)) void
flash_chip_erase_status(EspFlash *chip,unsigned int flags)
{
    const volatile EspFlash *context = chip;
    void (*set_status)(unsigned int) = context->os_functions->set_flash_op_status;
    if (set_status != 0)
        set_status(flags);
}

/* Native entry: 0x403906e8. */
/* Original function-byte SHA-256:
 * 9c1ac21fd1947da53f0312a8defe84a4def7171a0e7336db6db32a35c63a15b2. */
/* Send reset-enable 0x66 using a zeroed transaction. On success, zero the
 * transaction again, reload host/driver and send reset 0x99. A command failure
 * returns immediately. After both succeed, reload chip driver, timeout pointer
 * and wait_idle callback, then wait with its idle_timeout. Return that result.
 * No write-enable, pointer validation, recovery retry or separate reset delay. */
int spi_flash_chip_generic_reset(EspFlash *chip)
{
    const volatile EspFlash *context = chip;
    FlashTransaction transaction = {0};
    FlashHostView *host = context->host;
    int (*common)(FlashHostView *,FlashTransaction *) =
        ((const volatile FlashHostView *)host)->driver->common_command;
    transaction.command = 0x66;
    int result = common(host,&transaction);
    if (result != 0)
        return result;
    transaction = (FlashTransaction){0};
    host = context->host;
    common = ((const volatile FlashHostView *)host)->driver->common_command;
    transaction.command = 0x99;
    result = common(host,&transaction);
    if (result != 0)
        return result;
    const volatile FlashChipDriverView *driver = context->chip_driver;
    const volatile FlashTimeouts *timeouts = driver->timeout;
    int (*wait_idle)(EspFlash *,unsigned int) = driver->wait_idle;
    unsigned int timeout = timeouts->idle_timeout;
    return wait_idle(chip,timeout);
}

/* Native entry: 0x40390744. */
/* Original function-byte SHA-256:
 * ea296cfe3b9a132b39ab913233b50b89fe3aa21f2da6cfa15eac41ca8fdafad0. */
/* Request write-enable, then wait with idle_timeout only if that succeeded.
 * Both success and 0x106 permit erasure; other preparation errors return.
 * Call optional OS status hook with 1, reload host and invoke erase_chip, then
 * OR busy bit 0 into chip flags. Capture the chip driver before that flag store
 * and use its chip_erase_timeout/wait callback. Afterwards reload optional OS
 * hook and call it with 0. A final wait result 0x106 is replaced by the result
 * of a fresh set_write_protect(true) call; all other results pass through.
 * No local bounds/timeout/lock, command result or unconditional restoration. */
int spi_flash_chip_generic_erase_chip(EspFlash *chip)
{
    volatile EspFlash *context = chip;
    int result = context->chip_driver->set_chip_write_protect(chip,0);
    if (result == 0) {
        const volatile FlashChipDriverView *driver = context->chip_driver;
        const volatile FlashTimeouts *timeouts = driver->timeout;
        int (*wait_idle)(EspFlash *,unsigned int) = driver->wait_idle;
        result = wait_idle(chip,timeouts->idle_timeout);
    }
    if (result != 0 && result != 0x106)
        return result;
    flash_chip_erase_status(chip,1);
    FlashHostView *host = context->host;
    ((const volatile FlashHostView *)host)->driver->erase_chip(host);
    unsigned int flags = context->flags;
    const volatile FlashChipDriverView *driver = context->chip_driver;
    context->flags = flags | 1U;
    const volatile FlashTimeouts *timeouts = driver->timeout;
    int (*wait_idle)(EspFlash *,unsigned int) = driver->wait_idle;
    result = wait_idle(chip,timeouts->chip_erase_timeout);
    flash_chip_erase_status(chip,0);
    if (result == 0x106)
        result = context->chip_driver->set_chip_write_protect(chip,1);
    return result;
}

/* Native entry: 0x403907cc. */
/* Original function-byte SHA-256:
 * b674445c2131b4568f75260db320762bdfbbe1a8a55f9aeb0448f086c3fb591f. */
/* Same preparation/status/busy/cleanup flow as whole-chip erase, dispatching
 * the supplied address unchanged to host erase_sector and using the captured
 * driver's sector_erase_timeout. Preparation 0x106 still permits the operation;
 * final 0x106 is replaced by protection-restoration status. No address bounds,
 * alignment, capacity, local timeout or rollback is checked in this function. */
int spi_flash_chip_generic_erase_sector(EspFlash *chip,unsigned int address)
{
    volatile EspFlash *context = chip;
    int result = context->chip_driver->set_chip_write_protect(chip,0);
    if (result == 0) {
        const volatile FlashChipDriverView *driver = context->chip_driver;
        const volatile FlashTimeouts *timeouts = driver->timeout;
        int (*wait_idle)(EspFlash *,unsigned int) = driver->wait_idle;
        result = wait_idle(chip,timeouts->idle_timeout);
    }
    if (result != 0 && result != 0x106)
        return result;
    flash_chip_erase_status(chip,1);
    FlashHostView *host = context->host;
    ((const volatile FlashHostView *)host)->driver->erase_sector(host,address);
    unsigned int flags = context->flags;
    const volatile FlashChipDriverView *driver = context->chip_driver;
    context->flags = flags | 1U;
    const volatile FlashTimeouts *timeouts = driver->timeout;
    int (*wait_idle)(EspFlash *,unsigned int) = driver->wait_idle;
    result = wait_idle(chip,timeouts->sector_erase_timeout);
    flash_chip_erase_status(chip,0);
    if (result == 0x106)
        result = context->chip_driver->set_chip_write_protect(chip,1);
    return result;
}

/* Native entry: 0x40390860. */
/* Original function-byte SHA-256:
 * 570d4017eeb7826d4287b058084e087afa4c2443cb02e7884bfc86711b1131ba. */
/* Generic erase preparation and optional OS status hooks, using host erase_block
 * with the unchanged address and block_erase_timeout. Preserve busy flag updates,
 * live callback reloads and the special 0x106 preparation/cleanup behavior.
 * No block alignment, extent, chip-size, local timing or lock validation. */
int spi_flash_chip_generic_erase_block(EspFlash *chip,unsigned int address)
{
    volatile EspFlash *context = chip;
    int result = context->chip_driver->set_chip_write_protect(chip,0);
    if (result == 0) {
        const volatile FlashChipDriverView *driver = context->chip_driver;
        const volatile FlashTimeouts *timeouts = driver->timeout;
        int (*wait_idle)(EspFlash *,unsigned int) = driver->wait_idle;
        result = wait_idle(chip,timeouts->idle_timeout);
    }
    if (result != 0 && result != 0x106)
        return result;
    flash_chip_erase_status(chip,1);
    FlashHostView *host = context->host;
    ((const volatile FlashHostView *)host)->driver->erase_block(host,address);
    unsigned int flags = context->flags;
    const volatile FlashChipDriverView *driver = context->chip_driver;
    context->flags = flags | 1U;
    const volatile FlashTimeouts *timeouts = driver->timeout;
    int (*wait_idle)(EspFlash *,unsigned int) = driver->wait_idle;
    result = wait_idle(chip,timeouts->block_erase_timeout);
    flash_chip_erase_status(chip,0);
    if (result == 0x106)
        result = context->chip_driver->set_chip_write_protect(chip,1);
    return result;
}

/* Native entry: 0x40390694. */
/* Original function-byte SHA-256:
 * f8d131fbcd180af365c54fe59df8368d5d717e033ebe2d420b9e0ca0778a6c20. */
/* Assert that the output pointer is nonnull (four zero assertion arguments).
 * Call the current chip driver's read_reg with register ID 1. On success only,
 * store one Boolean byte: true when status WEL bit 1 is clear. Return callback
 * status, leaving output untouched on error. This is write-enable-latch state,
 * not block-protection bits; no independent wait or pointer/table validation. */
int spi_flash_chip_generic_get_write_protect(EspFlash *chip,bool *protected)
{
    if (protected == 0)
        __assert_func((const char *)0,0,(const char *)0,(const char *)0);
    unsigned int status;
    int result = ((const volatile EspFlash *)chip)->chip_driver->read_reg(chip,1,&status);
    if (result == 0)
        *protected = (status & 2U) == 0;
    return result;
}

/* Native entry: 0x403908f4. */
/* Original function-byte SHA-256:
 * d8c62513360b36ede08cabc3e681ee8d02e675997b7e5fe4a02725dc3fc9d3df. */
/* Retain the requested low BYTE, including noncanonical Boolean values. First
 * wait with the current idle timeout. Only wait result 0/0x106 dispatches host
 * set_write_protect, whose result is ignored. Regardless of every earlier
 * result, reload the chip driver and read back protection. Return that getter's
 * error, or 0x105 when its raw output byte differs from the requested byte,
 * else 0. Thus earlier wait/command errors can be hidden by successful readback.
 * No block-protection register update, rollback, local timeout or validation. */
int spi_flash_chip_generic_set_write_protect(EspFlash *chip,unsigned char protect)
{
    const volatile EspFlash *context = chip;
    const volatile FlashChipDriverView *driver = context->chip_driver;
    const volatile FlashTimeouts *timeouts = driver->timeout;
    int (*wait_idle)(EspFlash *,unsigned int) = driver->wait_idle;
    int result = wait_idle(chip,timeouts->idle_timeout);
    if (result == 0 || result == 0x106) {
        FlashHostView *host = context->host;
        ((const volatile FlashHostView *)host)->driver->set_write_protect(host,protect);
    }
    bool actual;
    result = context->chip_driver->get_chip_write_protect(chip,&actual);
    if (result != 0)
        return result;
    unsigned int actual_byte = *(volatile unsigned char *)&actual;
    return actual_byte == protect ? 0 : 0x105;
}

/* Native entry: 0x403903dc. */
/* Original function-byte SHA-256:
 * f1bd70ee2b3a3d3034eb3e6d6e586c8e12ae1320174280b0ec82b74f26131b12. */
/* Cache the driver's configure-host callback and page size, then configure with
 * flags 0 even for zero length. Result 0x106 logs the unsupported-mode message
 * and returns; other errors return through the loop guard. Each successful
 * iteration fills a 64-byte stack buffer with 0xff and calls the live host read
 * slicer. Compute unsigned/wrapping slice/request ends, offset and copy length.
 * Reload host/read callback and read the aligned slice. Always copy the selected
 * stack-buffer bytes to output and advance counters, including after read error;
 * then stop on that error. No slicer progress, 64-byte bound, wrap, pointer or
 * capacity checks. Zero-length slices can loop forever; malformed slices can
 * copy outside the stack buffer. No cache flush, rollback or own timeout/lock. */
int spi_flash_chip_generic_read(EspFlash *chip,void *buffer,unsigned int address,unsigned int length)
{
    const volatile EspFlash *context = chip;
    const volatile FlashChipDriverView *driver = context->chip_driver;
    int (*configure)(EspFlash *,unsigned int) = driver->config_host_io_mode;
    unsigned int page_size = driver->page_size;
    int result = configure(chip,0);
    if (result == 0x106) {
        unsigned int timestamp = esp_log_timestamp();
        esp_log_write(1,"chip_generic","E (%lu) %s: configure host io mode failed - unsupported\n",
            timestamp,"chip_generic");
        return result;
    }
    unsigned int destination = (unsigned int)buffer;
    unsigned char temporary[64] __attribute__((aligned(16)));
    while (result == 0 && length != 0) {
        memset(temporary,0xff,64);
        FlashHostView *host = context->host;
        unsigned int aligned_address;
        unsigned int slice_length = (unsigned int)((const volatile FlashHostView *)host)->driver->read_data_slicer(
            host,address,length,&aligned_address,page_size);
        host = context->host;
        int (*read)(FlashHostView *,void *,unsigned int,unsigned int) =
            ((const volatile FlashHostView *)host)->driver->read;
        unsigned int slice_end = aligned_address + slice_length;
        unsigned int request_end = address + length;
        unsigned int left_offset = address - aligned_address;
        unsigned int end = slice_end < request_end ? slice_end : request_end;
        result = read(host,temporary,aligned_address,slice_length);
        unsigned int copied = end - address;
        memcpy((void *)destination,(const void *)((unsigned int)temporary + left_offset),copied);
        length = request_end - end;
        destination += copied;
        address = end;
    }
    return result;
}

/* Native entry: 0x40390478. */
/* Original function-byte SHA-256:
 * 45d067932175fae5d85b5e75d6b077b48b40a1145baeb1da614089db9320935b. */
/* Cache page size, return 0 for zero length. Otherwise fill a 64-byte stack
 * buffer with 0xff, call the live host write slicer, compute wrapping unsigned
 * bounds and copy the user bytes into its aligned offset. Then request write
 * enable; any error, including 0x106, returns before page programming. On success
 * reload driver/program_page and pass the entire sliced buffer. Advance source,
 * address and remaining length even after page-program error, then stop on it.
 * No host configuration, cache flush, progress/buffer/range checks, independent
 * restoration or lock. Slicer zero progress and oversized offsets remain native. */
int spi_flash_chip_generic_write(EspFlash *chip,const void *buffer,unsigned int address,unsigned int length)
{
    const volatile EspFlash *context = chip;
    unsigned int page_size = context->chip_driver->page_size;
    unsigned int source = (unsigned int)buffer;
    unsigned char temporary[64] __attribute__((aligned(16)));
    int result = 0;
    while (result == 0 && length != 0) {
        memset(temporary,0xff,64);
        FlashHostView *host = context->host;
        unsigned int aligned_address;
        unsigned int slice_length = (unsigned int)((const volatile FlashHostView *)host)->driver->write_data_slicer(
            host,address,length,&aligned_address,page_size);
        unsigned int request_end = address + length;
        unsigned int slice_end = aligned_address + slice_length;
        unsigned int end = slice_end < request_end ? slice_end : request_end;
        unsigned int left_offset = address - aligned_address;
        unsigned int copied = end - address;
        memcpy((void *)((unsigned int)temporary + left_offset),(const void *)source,copied);
        result = context->chip_driver->set_chip_write_protect(chip,0);
        if (result != 0)
            return result;
        result = context->chip_driver->program_page(chip,temporary,aligned_address,slice_length);
        source += copied;
        length = request_end - end;
        address = end;
    }
    return result;
}

/* Native entry: 0x403909dc. */
/* Original function-byte SHA-256:
 * cc029196dfebea3288c168e2c7bb627e2eac2d352e78c96898f9c53986b4c155. */
/* Wait with idle_timeout; proceed on 0/0x106, return other errors. Dispatch the
 * unchanged buffer/address/length to live host program_page. Set chip busy bit 0,
 * using a chip driver captured before that flag store, then wait with its
 * page_program_timeout. Final 0x106 is replaced by a fresh protection-restoration
 * result; otherwise return wait status. No local write-enable, range/page/buffer
 * validation, OS erase-status hook, cache flush or independent timeout/lock. */
int spi_flash_chip_generic_page_program(EspFlash *chip,const void *buffer,
    unsigned int address,unsigned int length)
{
    volatile EspFlash *context = chip;
    const volatile FlashChipDriverView *driver = context->chip_driver;
    const volatile FlashTimeouts *timeouts = driver->timeout;
    int (*wait_idle)(EspFlash *,unsigned int) = driver->wait_idle;
    int result = wait_idle(chip,timeouts->idle_timeout);
    if (result != 0 && result != 0x106)
        return result;
    FlashHostView *host = context->host;
    ((const volatile FlashHostView *)host)->driver->program_page(host,buffer,address,length);
    unsigned int flags = context->flags;
    driver = context->chip_driver;
    context->flags = flags | 1U;
    timeouts = driver->timeout;
    wait_idle = driver->wait_idle;
    result = wait_idle(chip,timeouts->page_program_timeout);
    if (result == 0x106)
        result = context->chip_driver->set_chip_write_protect(chip,1);
    return result;
}

/* Native entry: 0x4039095c. */
/* Original function-byte SHA-256:
 * 86a7818496ed49ce9ae351f1de64b12041c055bcba6351935f7e1d62f28b465b. */
/* Initialize remaining=timeout_us+1 modulo 32 bits, replacing wrapped zero
 * with 1. Poll live host_status until nonzero. While it is zero, delay 1 us and
 * decrement only when remaining!=1; at 1 this spins indefinitely with no delay
 * or timeout progress. Any nonzero host status proceeds; no suspend/resume path.
 * Read chip register 1. On read error return it. If WIP bit 0 is clear, return
 * 0, except that a set chip busy flag is first cleared and WEL bit 1 then yields
 * 0x106. If WIP stays set, delay min(remaining,20), ignoring delay status; only
 * finite original timeouts subtract this budget, returning 0x107 at zero.
 * UINT_MAX uses unbounded WIP polling with one-us delays, but the inner host
 * loop still has its own decrement rule. Budgets count requested delays, not
 * measured elapsed time. No pointer checks, scheduling guarantee or own lock. */
int spi_flash_chip_generic_wait_idle(EspFlash *chip,unsigned int timeout_us)
{
    volatile EspFlash *context = chip;
    unsigned int remaining = timeout_us + 1U;
    if (remaining == 0)
        remaining = 1;
    for (;;) {
        for (;;) {
            FlashHostView *host = context->host;
            unsigned int host_status = ((const volatile FlashHostView *)host)->driver->host_status(host);
            if (host_status != 0)
                break;
            if (remaining != 1U) {
                const volatile MainFlashOsFunctions *os = context->os_functions;
                FlashOsContext *os_context = context->os_context;
                int (*delay)(void *,unsigned int) = os->delay_us;
                delay(os_context,1);
                --remaining;
            }
        }
        unsigned int status;
        int result = context->chip_driver->read_reg(chip,1,&status);
        unsigned int delay_us = remaining < 20U ? remaining : 20U;
        if (result != 0)
            return result;
        if ((status & 1U) == 0) {
            unsigned int flags = context->flags;
            if ((flags & 1U) == 0)
                return 0;
            context->flags = flags & ~1U;
            return (status & 2U) != 0 ? 0x106 : 0;
        }
        const volatile MainFlashOsFunctions *os = context->os_functions;
        FlashOsContext *os_context = context->os_context;
        int (*delay)(void *,unsigned int) = os->delay_us;
        delay(os_context,delay_us);
        if (timeout_us != 0xffffffffU) {
            remaining -= delay_us;
            if (remaining == 0)
                return 0x107;
        }
    }
}

/* Native entry: 0x4039054c. */
/* Original function-byte SHA-256:
 * 27f19d0d36b6198203744c14dd74f84f803108c9d9b62d594a6e11ac28118884. */
/* Issue RDUID 0x4b, eight RX bytes and 32 dummy cycles, into two zeroed words.
 * Cache command status, then sample high and low words. Exactly all-zero or
 * all-one 64-bit responses optionally emit the early error log and return 0x106,
 * overwriting command status. If logging runs, reload both words afterwards.
 * Other responses reverse all eight bytes, even when command status is nonzero,
 * and retain that status. Always store two output words in low/high order;
 * invalid sentinels are stored without conversion. No output pointer check,
 * callback validation, retry or independent timeout/lock. */
int spi_flash_chip_generic_read_unique_id(EspFlash *chip,unsigned long long *unique_id)
{
    unsigned int response[2] = {0,0};
    FlashTransaction transaction = {0};
    transaction.dummy_bitlen = 32;
    FlashHostView *host = ((const volatile EspFlash *)chip)->host;
    transaction.miso_len = 8;
    int (*common)(FlashHostView *,FlashTransaction *) =
        ((const volatile FlashHostView *)host)->driver->common_command;
    transaction.miso_data = (unsigned char *)response;
    transaction.command = 0x4b;
    int result = common(host,&transaction);
    unsigned int high = *(volatile unsigned int *)&response[1];
    unsigned int low = *(volatile unsigned int *)&response[0];
    if ((low == 0 && high == 0) || (low == 0xffffffffU && high == 0xffffffffU)) {
        if (SYSTEM_EARLY_LOG_LEVEL != 0) {
            unsigned int timestamp = esp_log_timestamp();
            ets_printf("E (%lu) %s: No response from device when trying to retrieve Unique ID\n\n",
                timestamp,"chip_generic");
            low = *(volatile unsigned int *)&response[0];
            high = *(volatile unsigned int *)&response[1];
        }
        result = 0x106;
    } else {
        unsigned int reversed_low = __builtin_bswap32(high);
        high = __builtin_bswap32(low);
        low = reversed_low;
    }
    volatile unsigned int *output = (volatile unsigned int *)unique_id;
    output[0] = low;
    output[1] = high;
    return result;
}
