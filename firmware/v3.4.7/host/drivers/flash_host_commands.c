/* Medius v3.4.7 host: flash host command wrappers and transfer slicing. */
#include "../include/types.h"

/* Inline reconstruction utilities retain native barriers and the unguarded
 * unsigned remainder instruction. Neither helper adds a firmware entry. */
static __inline__ __attribute__((always_inline)) void flash_command_barrier(void)
{
    __asm__ volatile ("memw" ::: "memory");
}
static __inline__ __attribute__((always_inline)) unsigned int
flash_slice_remainder(unsigned int address,unsigned int page_size)
{
    unsigned int remainder;
    __asm__ volatile ("remu %0,%1,%2" : "=a"(remainder)
        : "a"(address),"a"(page_size) : "memory");
    return remainder;
}

/* Native entry: 0x40385b5c. */
/* Original function-byte SHA-256:
 * b85b9fe285059a1661c11f33744b0cfa2fbe1e27758593723f8ebc10185461ba. */
/* Cache host->spi; MEMW/read the whole MSPI CMD word, then MEMW/read
 * SUS_STATUS at +0xa4. Return bit 0 iff CMD==0, plus bit 1 iff suspend-status
 * bit 0 is set. The samples are sequential, not atomic: 0..3 can be returned.
 * No USR-only test, waiting, clearing, pointer validation or lock occurs. */
unsigned int spi_flash_hal_check_status(FlashHostView *host)
{
    volatile MspiRegisters *regs =
        (volatile MspiRegisters *)((const volatile FlashHostView *)host)->spi;
    flash_command_barrier();
    unsigned int command = regs->cmd;
    flash_command_barrier();
    unsigned int suspended = regs->suspend_status;
    return (unsigned int)(command == 0) | ((suspended & 1U) << 1);
}

/* Native entry: 0x40385b4c. */
/* Original function-byte SHA-256:
 * 8ccacccbf4d679bc9dd40b79604a5764e2dbb1f64d913ed25631b6c8c2a71477. */
/* Cache the peripheral once and MEMW/read the entire CMD word until zero.
 * Other command bits also keep this loop busy. No timeout, yield or lock. */
void spi_flash_hal_poll_cmd_done(FlashHostView *host)
{
    volatile MspiRegisters *regs =
        (volatile MspiRegisters *)((const volatile FlashHostView *)host)->spi;
    unsigned int command;
    do {
        flash_command_barrier();
        command = regs->cmd;
    } while (command != 0);
}

/* Native entry: 0x40385b7c. */
/* Original function-byte SHA-256:
 * 384e8f93016f91a338af236cc4f4e37a105efdf50c5a4460456253f8d7999c6a. */
/* MEMW/read +0x9c and MEMW/write its old value OR bit 0 (MSPI FLASH_PER).
 * Then reload host->driver and call poll_cmd_done at +0x40 with this host.
 * This uses the MSPI offset unconditionally, even when reached through the
 * GPSPI driver table. No peripheral-type check, timeout, lock or status. */
void spi_flash_hal_resume(FlashHostView *host)
{
    const volatile FlashHostView *context = host;
    volatile MspiRegisters *regs = (volatile MspiRegisters *)context->spi;
    flash_command_barrier();
    unsigned int command = regs->flash_suspend_command;
    flash_command_barrier();
    regs->flash_suspend_command = command | 1U;
    context->driver->poll_cmd_done(host);
}

/* Native entry: 0x40385ba0. */
/* Original function-byte SHA-256:
 * 4e79b128494dd4905c3c8d9770be10af132392573ce094d19685983668532b8b. */
/* Set MSPI FLASH_PES bit 1 at +0x9c using separate MEMW/read and MEMW/write,
 * then reload driver->poll_cmd_done and call it. The peripheral and callback
 * are unchecked; no automatic-suspend setup, status result or timeout. */
void spi_flash_hal_suspend(FlashHostView *host)
{
    const volatile FlashHostView *context = host;
    volatile MspiRegisters *regs = (volatile MspiRegisters *)context->spi;
    flash_command_barrier();
    unsigned int command = regs->flash_suspend_command;
    flash_command_barrier();
    regs->flash_suspend_command = command | 2U;
    context->driver->poll_cmd_done(host);
}

/* Native entry: 0x4038bbd4. */
/* Original function-byte SHA-256:
 * 7b207da70fa7457fc0d3c47ae02d81daaa2c8fd7f89fce2da0353d9f1a9317f7. */
/* Zero a 28-byte transaction and a separate response word; issue RDID 0x9f
 * with three receive bytes through driver->common_command. Ignore its return.
 * An all-zero word or exactly 0x00ffffff logs "no response" when the live
 * early-log gate is nonzero and returns 0x108 without writing *id. Otherwise
 * return 0 and store (raw&255)<<16 | (raw&0xff00) | raw>>16. The last term
 * retains the response word's upper byte if a callback supplies one; do not
 * replace this with a masked 24-bit swap. Pointers/callback are unchecked. */
int memspi_host_read_id_hs(FlashHostView *host,unsigned int *id)
{
    unsigned int response = 0;
    FlashTransaction transaction = {0};
    transaction.miso_len = 3;
    transaction.miso_data = (unsigned char *)&response;
    transaction.command = 0x9f;
    ((const volatile FlashHostView *)host)->driver->common_command(host,&transaction);
    unsigned int raw = response;
    if (raw == 0 || raw == 0x00ffffffU) {
        if (SYSTEM_EARLY_LOG_LEVEL != 0) {
            unsigned int timestamp = esp_log_timestamp();
            ets_printf("E (%lu) %s: no response\n\n",timestamp,"memspi");
        }
        return 0x108;
    }
    *id = ((raw & 0xffU) << 16) | (raw & 0xff00U) | (raw >> 16);
    return 0;
}

/* Native entry: 0x4038bdd8. */
/* Original function-byte SHA-256:
 * 59b6dea7aa74f0947f9c7835b4a4fb135bc9036ff5176c93cb9841c050c09e28. */
/* Zero a complete transaction, issue chip-erase opcode 0xc7 and discard the
 * common-command result. No write-enable, chip-ready wait or protection check
 * is supplied here; peripheral command completion belongs to the callback. */
void memspi_host_erase_chip(FlashHostView *host)
{
    FlashTransaction transaction = {0};
    transaction.command = 0xc7;
    ((const volatile FlashHostView *)host)->driver->common_command(host,&transaction);
}

/* Native entry: 0x4038bcbc. */
/* Original function-byte SHA-256:
 * 54c302ea3d037450060cbf393c80dfdc16f2182b3c85dbe016b50c0df5868db1. */
/* Address >0x00ffffff invokes __assert_func with four null/zero arguments.
 * Otherwise issue sector erase 0x20 with 24 address bits; all other transaction
 * bytes start at zero. Ignore callback status. No alignment, chip-size,
 * write-enable, completion-of-flash-operation or protection check here. */
void memspi_host_erase_sector(FlashHostView *host,unsigned int address)
{
    if (address > 0x00ffffffU)
        __assert_func((const char *)0,0,(const char *)0,(const char *)0);
    FlashTransaction transaction = {0};
    transaction.address_bitlen = 24;
    transaction.address = address;
    transaction.command = 0x20;
    ((const volatile FlashHostView *)host)->driver->common_command(host,&transaction);
}

/* Native entry: 0x4038bcf8. */
/* Original function-byte SHA-256:
 * c70421870e49e63e6a81196eafb55c965fddd66b55aea55bfacff89cca9eaffc. */
/* Same 24-bit address assertion and unchecked dispatch as sector erase, using
 * block-erase opcode 0xd8. Callback status is discarded. No block alignment or
 * size validation, write-enable, ready polling or own lock is added. */
void memspi_host_erase_block(FlashHostView *host,unsigned int address)
{
    if (address > 0x00ffffffU)
        __assert_func((const char *)0,0,(const char *)0,(const char *)0);
    FlashTransaction transaction = {0};
    transaction.address_bitlen = 24;
    transaction.address = address;
    transaction.command = 0xd8;
    ((const volatile FlashHostView *)host)->driver->common_command(host,&transaction);
}

/* Native entry: 0x4038bda0. */
/* Original function-byte SHA-256:
 * 73776c6fca187c3fd86b6a21948c389be82bc63a576065d012ca95eb51b10fe2. */
/* Issue status-read 0x05 into a zeroed word with receive length 1. Propagate a
 * nonzero common-command result without touching *status. On success write
 * only the response's low byte and return 0. No chip-ready loop or validation. */
int memspi_host_read_status_hs(FlashHostView *host,unsigned char *status)
{
    unsigned int response = 0;
    FlashTransaction transaction = {0};
    transaction.miso_len = 1;
    transaction.miso_data = (unsigned char *)&response;
    transaction.command = 5;
    int result = ((const volatile FlashHostView *)host)->driver->common_command(host,&transaction);
    if (result != 0)
        return result;
    *status = (unsigned char)response;
    return 0;
}

/* Native entry: 0x4038bdfc. */
/* Original function-byte SHA-256:
 * 0eb55bc78dcf10e7ec8abdba6e57794aa665902b9e3200e26849435eb5d409b9. */
/* Truncate protect to its native argument byte. Nonzero issues WRDI 0x04;
 * zero issues WREN 0x06. Ignore callback status and always return 0. This
 * changes the write-enable latch; it does not program block-protection bits,
 * read back the latch, wait for flash-ready or validate the host. */
int memspi_host_set_write_protect(FlashHostView *host,unsigned char protect)
{
    FlashTransaction transaction = {0};
    transaction.command = protect != 0 ? 4 : 6;
    ((const volatile FlashHostView *)host)->driver->common_command(host,&transaction);
    return 0;
}

/* Native entry: 0x4038bc74. */
/* Original function-byte SHA-256:
 * 3550186e56a2cb6dcfc985e8cb53e994dd8f424eb31c3b79a1a04aef8268f571. */
/* Assert only that the wrapping 32-bit address+length is <=0x01000000. Issue
 * page-program 0x02 with address width 24, unchanged address and buffer, and
 * length truncated to one MOSI byte. This permits wrapped sums and length 256
 * becomes zero; no independent pointer, address, page boundary or length check.
 * Discard command status. No write-enable or flash-ready polling is supplied. */
void memspi_host_program_page(FlashHostView *host,const void *buffer,
    unsigned int address,unsigned int length)
{
    if (address + length > 0x01000000U)
        __assert_func((const char *)0,0,(const char *)0,(const char *)0);
    FlashTransaction transaction = {0};
    transaction.address_bitlen = 24;
    transaction.mosi_len = (unsigned char)length;
    transaction.address = address;
    transaction.mosi_data = buffer;
    transaction.command = 2;
    ((const volatile FlashHostView *)host)->driver->common_command(host,&transaction);
}

/* Native entry: 0x4038be2c. */
/* Original function-byte SHA-256:
 * 4f8ca069c0e5046d9ed20b5f6375ed1d056d86294360d4d4c0ba938a0b311b2f. */
/* If slicer_flags bit 0 (DTR) is set, align an odd address down by one and
 * increase length by 1 for odd lengths or 2 for even lengths. With an even
 * address, round odd length up by one. All additions wrap at 32 bits. Execute
 * native REMU(address,page_size) without guarding zero, then store the adjusted
 * address and return min(adjusted length,64,page_size-remainder). No pointer
 * validation, buffer padding, flash bounds, allocation or hardware access. */
int memspi_host_write_data_slicer(FlashHostView *host,unsigned int address,
    unsigned int length,unsigned int *aligned_address,unsigned int page_size)
{
    if ((((const volatile FlashHostView *)host)->slicer_flags & 1U) != 0) {
        if ((address & 1U) != 0) {
            address -= 1U;
            length += 1U + (unsigned int)((length & 1U) == 0);
        } else {
            length += length & 1U;
        }
    }
    unsigned int page_remaining = page_size - flash_slice_remainder(address,page_size);
    unsigned int limited = length < 64U ? length : 64U;
    *aligned_address = address;
    return (int)(page_remaining < limited ? page_remaining : limited);
}

/* Native entry: 0x4038be64. */
/* Original function-byte SHA-256:
 * e2ad10116b71d7e7a69c755e513d7504917570a3f3eceebb55ed593c673b3b38. */
/* Apply the same wrapping DTR alignment/length adjustment as write slicing,
 * store the adjusted address, and return min(adjusted length,64). The supplied
 * page_size is unused; this function neither divides by it nor clips to a page
 * boundary. No pointer/extent validation or transfer occurs. */
int memspi_host_read_data_slicer(FlashHostView *host,unsigned int address,
    unsigned int length,unsigned int *aligned_address,unsigned int unused_page_size)
{
    (void)unused_page_size;
    if ((((const volatile FlashHostView *)host)->slicer_flags & 1U) != 0) {
        if ((address & 1U) != 0) {
            address -= 1U;
            length += 1U + (unsigned int)((length & 1U) == 0);
        } else {
            length += length & 1U;
        }
    }
    *aligned_address = address;
    return (int)(length < 64U ? length : 64U);
}
