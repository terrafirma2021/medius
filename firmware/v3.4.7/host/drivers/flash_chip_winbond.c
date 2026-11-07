/* Medius v3.4.7 host: Winbond/GD 24/32-bit flash commands. */
#include "../include/types.h"

/* Native entry: 0x4038d0c8. */
/* Original function-byte SHA-256:
 * 75a8b9f76c80e716747947974b94acb82a3df11f0e8e83bcb4a146bcb1c7dcdb. */
/* Cache configure callback and page size; compute request_end with 32-bit
 * unsigned wrapping. Configure with flag 1 only when request_end > 0x01000000,
 * including a zero-length request. End exactly at 16 MiB uses 24-bit addressing;
 * overflow can select 24-bit addressing for a wrapping request. On 0x106 log the
 * unsupported-mode diagnostic and return; other configuration errors also stop.
 * Each iteration fills a 64-byte stack buffer with 0xff, invokes the live read
 * slicer, reloads host/read, then reads the entire aligned slice. Always copy the
 * selected bytes and advance output/address/remaining even after read failure.
 * Return that failure or 0 on completion. Slice arithmetic wraps; zero progress,
 * offsets/lengths outside the stack buffer and pointers remain unchecked.
 * No independent wait, cache flush, lock or bounds/capacity validation. */
int spi_flash_chip_winbond_read(EspFlash *chip,void *buffer,
    unsigned int address,unsigned int length)
{
    const volatile EspFlash *context = chip;
    const volatile FlashChipDriverView *driver = context->chip_driver;
    int (*configure)(EspFlash *,unsigned int) = driver->config_host_io_mode;
    unsigned int request_end = address + length;
    unsigned int page_size = driver->page_size;
    int result = configure(chip,request_end > 0x01000000U);
    if (result == 0x106) {
        unsigned int timestamp = esp_log_timestamp();
        esp_log_write(1,"chip_wb","E (%lu) %s: configure host io mode failed - unsupported\n",
            timestamp,"chip_wb");
        return result;
    }
    unsigned int destination = (unsigned int)buffer;
    unsigned char temporary[64];
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
        unsigned int end = slice_end < request_end ? slice_end : request_end;
        unsigned int left_offset = address - aligned_address;
        result = read(host,temporary,aligned_address,slice_length);
        unsigned int copied = end - address;
        memcpy((void *)destination,(const void *)((unsigned int)temporary + left_offset),copied);
        length = request_end - end;
        destination += copied;
        address = end;
    }
    return result;
}

/* Native entry: 0x4038d210. */
/* Original function-byte SHA-256:
 * 8c80714878f393bd310d90753fb1688e665ec9e8aa910562487e0acb2c21e6f9. */
/* Request write-enable and, only on success, wait with idle_timeout. Every
 * nonzero preparation result (including 0x106) returns without erasing. Reload
 * host, zero the complete 28-byte transaction and send 0x20/24 address bits
 * below 16 MiB or 0x21/32 bits at/above it. Pass the unchanged address,
 * flags 8 and no data. Command error returns. On success reload host and capture
 * its optional flush_cache callback; if present, flush address plus the current
 * chip driver's sector_size. Flush error returns before the final wait.
 * Finally reload driver/timeouts/wait and return sector_erase_timeout wait status.
 * No busy-flag update, OS erase-status hook, protection restoration, alignment,
 * capacity or wrap validation. The caller supplies locking and usable pointers. */
int spi_flash_chip_winbond_erase_sector(EspFlash *chip,unsigned int address)
{
    const volatile EspFlash *context = chip;
    int result = context->chip_driver->set_chip_write_protect(chip,0);
    if (result != 0)
        return result;
    const volatile FlashChipDriverView *driver = context->chip_driver;
    const volatile FlashTimeouts *timeouts = driver->timeout;
    int (*wait_idle)(EspFlash *,unsigned int) = driver->wait_idle;
    result = wait_idle(chip,timeouts->idle_timeout);
    if (result != 0)
        return result;
    FlashHostView *host = context->host;
    FlashTransaction transaction = {0};
    transaction.address_bitlen = address > 0x00ffffffU ? 32 : 24;
    int (*common)(FlashHostView *,FlashTransaction *) =
        ((const volatile FlashHostView *)host)->driver->common_command;
    transaction.address = address;
    transaction.flags = 8;
    transaction.command = address > 0x00ffffffU ? 0x21 : 0x20;
    result = common(host,&transaction);
    if (result != 0)
        return result;
    host = context->host;
    int (*flush)(FlashHostView *,unsigned int,unsigned int) =
        ((const volatile FlashHostView *)host)->driver->flush_cache;
    if (flush != 0) {
        unsigned int erase_size = context->chip_driver->sector_size;
        result = flush(host,address,erase_size);
        if (result != 0)
            return result;
    }
    driver = context->chip_driver;
    timeouts = driver->timeout;
    wait_idle = driver->wait_idle;
    return wait_idle(chip,timeouts->sector_erase_timeout);
}

/* Native entry: 0x4038d17c. */
/* Original function-byte SHA-256:
 * e25736bd7eac2cd0da3fd0455f7adca5f5c06d1fd2d5b493de698b2e28571995. */
/* Request write-enable and, only on success, wait with idle_timeout. Every
 * nonzero preparation result (including 0x106) returns without erasing. Reload
 * host, zero the complete 28-byte transaction and send 0xd8/24 address bits
 * below 16 MiB or 0xdc/32 bits at/above it. Pass the unchanged address,
 * flags 8 and no data. Command error returns. On success reload host and capture
 * its optional flush_cache callback; if present, flush address plus the current
 * chip driver's block_erase_size. Flush error returns before the final wait.
 * Finally reload driver/timeouts/wait and return block_erase_timeout wait status.
 * No busy-flag update, OS erase-status hook, protection restoration, alignment,
 * capacity or wrap validation. The caller supplies locking and usable pointers. */
int spi_flash_chip_winbond_erase_block(EspFlash *chip,unsigned int address)
{
    const volatile EspFlash *context = chip;
    int result = context->chip_driver->set_chip_write_protect(chip,0);
    if (result != 0)
        return result;
    const volatile FlashChipDriverView *driver = context->chip_driver;
    const volatile FlashTimeouts *timeouts = driver->timeout;
    int (*wait_idle)(EspFlash *,unsigned int) = driver->wait_idle;
    result = wait_idle(chip,timeouts->idle_timeout);
    if (result != 0)
        return result;
    FlashHostView *host = context->host;
    FlashTransaction transaction = {0};
    transaction.address_bitlen = address > 0x00ffffffU ? 32 : 24;
    int (*common)(FlashHostView *,FlashTransaction *) =
        ((const volatile FlashHostView *)host)->driver->common_command;
    transaction.address = address;
    transaction.flags = 8;
    transaction.command = address > 0x00ffffffU ? 0xdc : 0xd8;
    result = common(host,&transaction);
    if (result != 0)
        return result;
    host = context->host;
    int (*flush)(FlashHostView *,unsigned int,unsigned int) =
        ((const volatile FlashHostView *)host)->driver->flush_cache;
    if (flush != 0) {
        unsigned int erase_size = context->chip_driver->block_erase_size;
        result = flush(host,address,erase_size);
        if (result != 0)
            return result;
    }
    driver = context->chip_driver;
    timeouts = driver->timeout;
    wait_idle = driver->wait_idle;
    return wait_idle(chip,timeouts->block_erase_timeout);
}

/* Native entry: 0x4038d2a0. */
/* Original function-byte SHA-256:
 * 739e94ee8e80f77a6c5e9759e52db4924c8ea2aa63cbdc429a723e54427b6311. */
/* Wait with the current idle timeout; every nonzero result, including 0x106,
 * returns immediately. Reload host, zero a 28-byte transaction, retain only the
 * low length byte, and send program command 0x02/24 address bits below 16 MiB,
 * or 0x12/32 bits at/above it. Pass the full address and original buffer; set
 * transaction flags 8 (program/erase). Command failure returns immediately.
 * On success reload chip driver/timeout/wait and return its page-program wait.
 * No local write-enable, busy-flag update, flush, protection restoration, page
 * boundary, buffer, length or chip-size validation. Length 256 becomes 0. */
int spi_flash_chip_winbond_page_program(EspFlash *chip,const void *buffer,
    unsigned int address,unsigned int length)
{
    const volatile EspFlash *context = chip;
    const volatile FlashChipDriverView *driver = context->chip_driver;
    const volatile FlashTimeouts *timeouts = driver->timeout;
    int (*wait_idle)(EspFlash *,unsigned int) = driver->wait_idle;
    int result = wait_idle(chip,timeouts->idle_timeout);
    if (result != 0)
        return result;
    FlashHostView *host = context->host;
    FlashTransaction transaction = {0};
    transaction.mosi_len = (unsigned char)length;
    transaction.address_bitlen = address > 0x00ffffffU ? 32 : 24;
    int (*common)(FlashHostView *,FlashTransaction *) =
        ((const volatile FlashHostView *)host)->driver->common_command;
    transaction.address = address;
    transaction.mosi_data = buffer;
    transaction.flags = 8;
    transaction.command = address > 0x00ffffffU ? 0x12 : 0x02;
    result = common(host,&transaction);
    if (result != 0)
        return result;
    driver = context->chip_driver;
    timeouts = driver->timeout;
    wait_idle = driver->wait_idle;
    return wait_idle(chip,timeouts->page_program_timeout);
}
