/* Medius v3.4.7 host: Macronix octal flash transfers, protection and erasure. */
#include "../include/types.h"

/* Native entry: 0x4038cba4. */
/* Original function-byte SHA-256:
 * 5e899f6c57cf2697720ad7c27295cbd502ea4b3dad7d774369ab889603ac3a25. */
/* Request write-enable, then wait with idle_timeout only if that succeeded.
 * Preparation 0/0x106 permits a zeroed 28-byte transaction with command 0x9f60;
 * every other result returns. Ignore command status, OR busy bit 0 into chip
 * flags and wait with chip_erase_timeout. Capture the driver before storing
 * flags. If the final wait returns 0x106, reload set_write_protect and call it
 * with 1, but ignore its result and still return 0x106. Other final statuses
 * pass through. No address/data phase, program/erase transaction flag, OS status
 * hook, cache flush, pointer checks, local lock or independent timeout. */
int spi_flash_chip_mxic_opi_erase_chip(EspFlash *chip)
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
    FlashTransaction transaction = {0};
    FlashHostView *host = context->host;
    int (*common)(FlashHostView *,FlashTransaction *) =
        ((const volatile FlashHostView *)host)->driver->common_command;
    transaction.command = 0x9f60;
    common(host,&transaction);
    unsigned int flags = context->flags;
    const volatile FlashChipDriverView *driver = context->chip_driver;
    context->flags = flags | 1U;
    const volatile FlashTimeouts *timeouts = driver->timeout;
    int (*wait_idle)(EspFlash *,unsigned int) = driver->wait_idle;
    result = wait_idle(chip,timeouts->chip_erase_timeout);
    if (result == 0x106)
        context->chip_driver->set_chip_write_protect(chip,1);
    return result;
}

/* Native entry: 0x4038cc2c. */
/* Original function-byte SHA-256:
 * 0a435e2db8b9655ba2ab79b1a480681e3092c6df914edb359b8fffd310e8b45b. */
/* Request write-enable, then wait only on success; preparation 0/0x106 permits
 * erasure. Zero all 28 transaction bytes, set address width 32, full address and
 * command 0xde21. Flags/data/dummy/io mode remain zero. Ignore command status,
 * OR busy bit 0 into chip flags, then wait with the driver captured before that
 * flag store and its sector_erase_timeout. Final 0x106 is replaced by a fresh
 * set_write_protect(1) result. Other errors/statuses pass through. No alignment,
 * capacity, OS status hook, flush, rollback, local lock or separate timeout. */
int spi_flash_chip_mxic_opi_erase_sector(EspFlash *chip,unsigned int address)
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
    FlashTransaction transaction = {0};
    FlashHostView *host = context->host;
    transaction.address_bitlen = 32;
    int (*common)(FlashHostView *,FlashTransaction *) =
        ((const volatile FlashHostView *)host)->driver->common_command;
    transaction.address = address;
    transaction.command = 0xde21;
    common(host,&transaction);
    unsigned int flags = context->flags;
    const volatile FlashChipDriverView *driver = context->chip_driver;
    context->flags = flags | 1U;
    const volatile FlashTimeouts *timeouts = driver->timeout;
    int (*wait_idle)(EspFlash *,unsigned int) = driver->wait_idle;
    result = wait_idle(chip,timeouts->sector_erase_timeout);
    if (result == 0x106)
        result = context->chip_driver->set_chip_write_protect(chip,1);
    return result;
}

/* Native entry: 0x4038ccb8. */
/* Original function-byte SHA-256:
 * 1893d45364127eaa3e2c272d377fa5fddbf74e641b59c89866200a0abb3585ab. */
/* Use the sector-erase preparation and busy-state flow with command 0x23dc,
 * 32 address bits and block_erase_timeout. Ignore the command result; a final
 * wait 0x106 is replaced by the current protection-restoration callback result.
 * Retain full address, zero transaction flags and unchecked alignment/capacity.
 * No OS status hook, cache flush, local lock or independent deadline. */
int spi_flash_chip_mxic_opi_erase_block(EspFlash *chip,unsigned int address)
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
    FlashTransaction transaction = {0};
    FlashHostView *host = context->host;
    transaction.address_bitlen = 32;
    int (*common)(FlashHostView *,FlashTransaction *) =
        ((const volatile FlashHostView *)host)->driver->common_command;
    transaction.address = address;
    transaction.command = 0x23dc;
    common(host,&transaction);
    unsigned int flags = context->flags;
    const volatile FlashChipDriverView *driver = context->chip_driver;
    context->flags = flags | 1U;
    const volatile FlashTimeouts *timeouts = driver->timeout;
    int (*wait_idle)(EspFlash *,unsigned int) = driver->wait_idle;
    result = wait_idle(chip,timeouts->block_erase_timeout);
    if (result == 0x106)
        result = context->chip_driver->set_chip_write_protect(chip,1);
    return result;
}

/* Native entry: 0x4038cf64. */
/* Original function-byte SHA-256:
 * 67dc6eec90aa45c774b72f51c28b226293518f70b0501c7f7351edf47af81c61. */
/* Assert nonnull output with four zero assertion arguments. Call the live
 * read_reg callback for register ID 1. Success stores one Boolean byte, true
 * when status WEL bit 1 is clear; failure leaves output untouched. Return the
 * callback status. This queries write-enable state, without a separate wait. */
int spi_flash_chip_mxic_opi_get_write_protect(EspFlash *chip,bool *protected)
{
    if (protected == 0)
        __assert_func((const char *)0,0,(const char *)0,(const char *)0);
    unsigned int status;
    int result = ((const volatile EspFlash *)chip)->chip_driver->read_reg(chip,1,&status);
    if (result == 0)
        *protected = (status & 2U) == 0;
    return result;
}

/* Native entry: 0x4038cb38. */
/* Original function-byte SHA-256:
 * ab64590355c58bc7e20e26b63543659d3f12d4c9eb63022bb4bdaf0ce0ee11f8. */
/* Retain the requested low byte, including noncanonical Boolean values. Wait
 * with idle_timeout, then zero a 28-byte transaction. On 0/0x106 send 0xfb04
 * for any nonzero request or 0xf906 for zero; ignore command status. Regardless
 * of earlier errors, reload get_chip_write_protect and read back a raw byte.
 * Return its error, 0x105 on raw-byte mismatch, or 0. Successful readback can
 * hide wait/command errors; request 2 sends disable but mismatches normal 1.
 * No wait after the command, block-protection-bit update or rollback. */
int spi_flash_chip_mxic_opi_set_write_protect(EspFlash *chip,unsigned char protect)
{
    const volatile EspFlash *context = chip;
    const volatile FlashChipDriverView *driver = context->chip_driver;
    const volatile FlashTimeouts *timeouts = driver->timeout;
    int (*wait_idle)(EspFlash *,unsigned int) = driver->wait_idle;
    int result = wait_idle(chip,timeouts->idle_timeout);
    FlashTransaction transaction = {0};
    if (result == 0 || result == 0x106) {
        FlashHostView *host = context->host;
        int (*common)(FlashHostView *,FlashTransaction *) =
            ((const volatile FlashHostView *)host)->driver->common_command;
        transaction.command = protect != 0 ? 0xfb04 : 0xf906;
        common(host,&transaction);
    }
    bool actual;
    result = context->chip_driver->get_chip_write_protect(chip,&actual);
    if (result != 0)
        return result;
    unsigned int actual_byte = *(volatile unsigned char *)&actual;
    return actual_byte == protect ? 0 : 0x105;
}

/* Native entry: 0x4038cd78. */
/* Original function-byte SHA-256:
 * 3d867cf0d56a210faadb3e429b9dd9aa2f8aac82f0b8002e22eebb3e24a5e276. */
/* Cache page size; zero length returns 0. Fill a 64-byte stack buffer with
 * 0xff, call the current write slicer and copy user bytes into the aligned
 * offset using wrapping unsigned bounds. Request write-enable; every error,
 * including 0x106, stops before program_page. On success reload program_page
 * and dispatch the entire slice, then advance source/address/remaining even
 * after a program error. Stop on that error or exhaustion. No progress, stack
 * bounds, address-wrap, page/capacity checks, flush or own lock/deadline. */
int spi_flash_chip_mxic_opi_write(EspFlash *chip,const void *buffer,
    unsigned int address,unsigned int length)
{
    const volatile EspFlash *context = chip;
    unsigned int page_size = context->chip_driver->page_size;
    unsigned int source = (unsigned int)buffer;
    unsigned char temporary[64];
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

/* Native entry: 0x4038ce0c. */
/* Original function-byte SHA-256:
 * 06f4fae37ba93bfb94e2d561c01739470e2a86b34b6cad50e2666b7951e09363. */
/* Wait with idle_timeout, permitting 0/0x106. Zero a 28-byte transaction; send
 * 0xed12 with 32 address bits, original buffer/address and low byte of length.
 * Flags/dummy/io mode remain zero. Ignore command status, set busy bit 0 using
 * a driver captured before the flag store, then wait with page_program_timeout.
 * Replace final 0x106 with a fresh set_write_protect(1) result. Other statuses
 * pass through. No local write-enable, page/range validation, flush or timeout.
 * Length 256 becomes zero; larger lengths are reduced modulo 256. */
int spi_flash_chip_mxic_opi_page_program(EspFlash *chip,const void *buffer,
    unsigned int address,unsigned int length)
{
    volatile EspFlash *context = chip;
    const volatile FlashChipDriverView *driver = context->chip_driver;
    const volatile FlashTimeouts *timeouts = driver->timeout;
    int (*wait_idle)(EspFlash *,unsigned int) = driver->wait_idle;
    int result = wait_idle(chip,timeouts->idle_timeout);
    if (result != 0 && result != 0x106)
        return result;
    FlashTransaction transaction = {0};
    FlashHostView *host = context->host;
    transaction.mosi_len = (unsigned char)length;
    transaction.address_bitlen = 32;
    int (*common)(FlashHostView *,FlashTransaction *) =
        ((const volatile FlashHostView *)host)->driver->common_command;
    transaction.command = 0xed12;
    transaction.address = address;
    transaction.mosi_data = buffer;
    common(host,&transaction);
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

/* Native entry: 0x4038ce90. */
/* Original function-byte SHA-256:
 * 06aab6d983e148c4de39e9c361f3a1b4110e63b8448956b93e6ecbdd85095a3c. */
/* Cache read_mode, zero an aligned eight-byte response and assert mode 16/17
 * with four zero assertion arguments. Send a zeroed 28-byte transaction:
 * command 0x609f, 32 address bits, 3/6 receive bytes and 4/8 dummy bits for
 * STR/DTR. Ignore command status. Reload mode after the callback and sample
 * response low/high words. If the live mode is 17, collapse bytes 0,2,4 into
 * a 24-bit value and clear the response high word. Only raw 0 or 0xffffff00
 * is rejected: optionally print the early 'no response' error and return 0x108,
 * leaving output untouched. Otherwise store bswap32(raw)>>8 and return 0.
 * Consequently three 0xff bytes are accepted; no output-pointer check, wait,
 * capacity validation or propagation of common_command errors is supplied. */
int spi_flash_chip_mxic_opi_read_id(void *chip_pointer,unsigned int *chip_id)
{
    EspFlash *chip = chip_pointer;
    const volatile EspFlash *context = chip;
    unsigned int mode = context->read_mode;
    unsigned long long response = 0;
    if (mode - 16U > 1U)
        __assert_func((const char *)0,0,(const char *)0,(const char *)0);
    FlashTransaction transaction = {0};
    FlashHostView *host = context->host;
    transaction.dummy_bitlen = mode == 16 ? 4 : 8;
    transaction.miso_len = mode == 16 ? 3 : 6;
    transaction.address_bitlen = 32;
    int (*common)(FlashHostView *,FlashTransaction *) =
        ((const volatile FlashHostView *)host)->driver->common_command;
    transaction.miso_data = (unsigned char *)&response;
    transaction.command = 0x609f;
    common(host,&transaction);
    unsigned int live_mode = context->read_mode;
    volatile unsigned int *words = (volatile unsigned int *)&response;
    unsigned int raw = words[0];
    unsigned int high = words[1];
    if (live_mode == 17) {
        raw = (raw & 0xffU) | ((raw >> 8) & 0xff00U) | ((high & 0xffU) << 16);
        words[0] = raw;
        words[1] = 0;
    }
    unsigned int reversed = __builtin_bswap32(raw);
    if (raw == 0xffffff00U || raw == 0) {
        if (SYSTEM_EARLY_LOG_LEVEL != 0) {
            unsigned int timestamp = esp_log_timestamp();
            ets_printf("E (%lu) %s: no response\n\n",timestamp,"mxic (opi)");
        }
        return 0x108;
    }
    *chip_id = reversed >> 8;
    return 0;
}

/* Native entry: 0x4038cf98. */
/* Original function-byte SHA-256:
 * ecbda1c703159767e2517f451ff3918620b87f631a6accf3041c6108b1a34009. */
/* Cache mode, zero a four-byte response, assert mode 16/17 and ignore reg_id.
 * Zero a 28-byte transaction; send status command 0xfa05, 32 address bits and
 * 1/2 receive bytes with 4/8 dummy bits for STR/DTR. Return command errors
 * without modifying output. On success zero-extend response byte 0 into the
 * four-byte output and return 0. Other response bytes, including DTR duplicate,
 * are discarded. No output-pointer check, wait or register-ID validation. */
int spi_flash_chip_mxic_opi_read_reg(EspFlash *chip,unsigned int reg_id,
    unsigned int *status)
{
    (void)reg_id;
    const volatile EspFlash *context = chip;
    unsigned int mode = context->read_mode;
    unsigned int response = 0;
    if (mode - 16U > 1U)
        __assert_func((const char *)0,0,(const char *)0,(const char *)0);
    FlashTransaction transaction = {0};
    FlashHostView *host = context->host;
    transaction.dummy_bitlen = mode == 16 ? 4 : 8;
    transaction.miso_len = mode == 16 ? 1 : 2;
    transaction.address_bitlen = 32;
    int (*common)(FlashHostView *,FlashTransaction *) =
        ((const volatile FlashHostView *)host)->driver->common_command;
    transaction.miso_data = (unsigned char *)&response;
    transaction.command = 0xfa05;
    int result = common(host,&transaction);
    if (result == 0)
        *status = *(volatile unsigned char *)&response;
    return result;
}
