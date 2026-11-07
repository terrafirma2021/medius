/* Medius v3.4.7 host: native MSPI erase/read/program and cache-flush dispatch. */
#include "../include/types.h"

/* Inline reconstruction utilities retain explicit MEMW and wrapping native
 * register-address arithmetic. These helpers add no firmware entries. */
static __inline__ __attribute__((always_inline)) void mspi_command_barrier(void)
{
    __asm__ volatile ("memw" ::: "memory");
}
static __inline__ __attribute__((always_inline)) volatile unsigned int *
mspi_command_buffer_word(volatile MspiRegisters *regs,unsigned int index)
{
    return (volatile unsigned int *)((unsigned int)regs + 0x58U + (index << 2));
}

/* Native entry: 0x403855d4. */
/* Original function-byte SHA-256:
 * 65ae566bfeed756104f9eb8785fbd55b75128173df7a0997a967f81df3581065. */
/* MEMW/read CMD then MEMW/write old CMD OR chip-erase bit 22. Afterwards read
 * live host flags: bit 0 set skips polling; otherwise reload driver +0x40 and
 * call poll_cmd_done(host). No write-enable, ready-status or bounds checks.
 * Peripheral command completion is distinct from flash erase completion. */
void spi_flash_hal_erase_chip(FlashHostView *host)
{
    const volatile FlashHostView *context = host;
    volatile MspiRegisters *regs = (volatile MspiRegisters *)context->spi;
    mspi_command_barrier();
    unsigned int command = regs->cmd;
    mspi_command_barrier();
    regs->cmd = command | 0x00400000U;
    if ((context->flags & 1U) == 0)
        context->driver->poll_cmd_done(host);
}

/* Native entry: 0x403855fc. */
/* Original function-byte SHA-256:
 * eb7a4ea66b6dba2c081ea29377558bf147b3b683f361b20c5dc0a0b0a49d8e75. */
/* Set 24-bit addressing by clearing CACHE_FCTRL bit 1, replacing USER1's
 * high six bits with 23, and setting USER ADDR bit 30. Write address&0xffffff,
 * then clear the whole CTRL word. Set CMD sector-erase bit 24. All accesses
 * retain their separate MEMW; unrelated RMW bits remain unchanged. Read host
 * flags after starting: bit 0 skips polling, otherwise use the live callback.
 * No alignment, flash-size, pointer, write-enable or status validation. */
void spi_flash_hal_erase_sector(FlashHostView *host,unsigned int address)
{
    const volatile FlashHostView *context = host;
    volatile MspiRegisters *regs = (volatile MspiRegisters *)context->spi;
    mspi_command_barrier();
    unsigned int value = regs->cache_fctrl;
    mspi_command_barrier();
    regs->cache_fctrl = value & ~2U;
    mspi_command_barrier();
    value = regs->user1;
    mspi_command_barrier();
    regs->user1 = (value & 0x03ffffffU) | 0x5c000000U;
    mspi_command_barrier();
    value = regs->user;
    mspi_command_barrier();
    regs->user = value | 0x40000000U;
    mspi_command_barrier();
    regs->addr = address & 0x00ffffffU;
    mspi_command_barrier();
    regs->ctrl = 0;
    mspi_command_barrier();
    value = regs->cmd;
    mspi_command_barrier();
    regs->cmd = value | 0x01000000U;
    if ((context->flags & 1U) == 0)
        context->driver->poll_cmd_done(host);
}

/* Native entry: 0x4038566c. */
/* Original function-byte SHA-256:
 * e3be3ea8abce97d102ba1f13011bb7ed8f24d0fa6d3a15a248f1e49baff3d267. */
/* Same three ordered 24-bit-addressing RMWs as sector erase, then write the
 * masked address and set CMD block-erase bit 23. This path does not clear CTRL.
 * Live host flags bit 0 suppresses polling; otherwise reload the poll callback.
 * No block alignment, range, readiness, write-enable or pointer checks here. */
void spi_flash_hal_erase_block(FlashHostView *host,unsigned int address)
{
    const volatile FlashHostView *context = host;
    volatile MspiRegisters *regs = (volatile MspiRegisters *)context->spi;
    mspi_command_barrier();
    unsigned int value = regs->cache_fctrl;
    mspi_command_barrier();
    regs->cache_fctrl = value & ~2U;
    mspi_command_barrier();
    value = regs->user1;
    mspi_command_barrier();
    regs->user1 = (value & 0x03ffffffU) | 0x5c000000U;
    mspi_command_barrier();
    value = regs->user;
    mspi_command_barrier();
    regs->user = value | 0x40000000U;
    mspi_command_barrier();
    regs->addr = address & 0x00ffffffU;
    mspi_command_barrier();
    value = regs->cmd;
    mspi_command_barrier();
    regs->cmd = value | 0x00800000U;
    if ((context->flags & 1U) == 0)
        context->driver->poll_cmd_done(host);
}

/* Native entry: 0x40385784. */
/* Original function-byte SHA-256:
 * 082b4966943d96f0360f8aa15a7f9f1902a7c96981333dbdf81f0b8f390ad64d. */
/* Read CMD once with MEMW. The low argument byte selects WRDI bit 29 when
 * nonzero, WREN bit 30 when zero; MEMW/write old CMD OR that bit. Reload and
 * call poll_cmd_done after the write, then always return 0. No status/protection
 * verification, block-protect register programming or auto-suspend skip. */
int spi_flash_hal_set_write_protect(FlashHostView *host,unsigned char protect)
{
    const volatile FlashHostView *context = host;
    volatile MspiRegisters *regs = (volatile MspiRegisters *)context->spi;
    mspi_command_barrier();
    unsigned int command = regs->cmd;
    unsigned int latch_command = protect != 0 ? 0x20000000U : 0x40000000U;
    mspi_command_barrier();
    regs->cmd = command | latch_command;
    context->driver->poll_cmd_done(host);
    return 0;
}

/* Native entry: 0x403856d4. */
/* Original function-byte SHA-256:
 * 3e73b01df5389b0f96cb838f406fa29da477abc82ddc8e78f6a85745796b3bec. */
/* Configure 24 address bits, then write (address&0xffffff)|(length<<24) and
 * clear USER DUMMY bit 29. Copy (length+3 wrapping)>>2 source chunks through a
 * zeroed word into registers starting at +0x58, MEMW before every word write.
 * Final partial words have zero padding. Length is unchecked: >64 can write
 * past W15, the address length byte truncates, and near-UINT_MAX lengths can
 * wrap the word count to zero. After reading CMD, capture the live poll callback
 * before MEMW/writing CMD OR page-program bit 25, then invoke it unconditionally.
 * No source/range/page validation, write-enable or own timeout/lock is added. */
void spi_flash_hal_program_page(FlashHostView *host,const void *buffer,
    unsigned int address,unsigned int length)
{
    const volatile FlashHostView *context = host;
    volatile MspiRegisters *regs = (volatile MspiRegisters *)context->spi;
    mspi_command_barrier();
    unsigned int value = regs->cache_fctrl;
    mspi_command_barrier();
    regs->cache_fctrl = value & ~2U;
    mspi_command_barrier();
    value = regs->user1;
    mspi_command_barrier();
    regs->user1 = (value & 0x03ffffffU) | 0x5c000000U;
    mspi_command_barrier();
    value = regs->user;
    mspi_command_barrier();
    regs->user = value | 0x40000000U;
    mspi_command_barrier();
    regs->addr = (address & 0x00ffffffU) | (length << 24);
    mspi_command_barrier();
    value = regs->user;
    mspi_command_barrier();
    regs->user = value & ~0x20000000U;

    unsigned int words = (length + 3U) >> 2;
    unsigned int source = (unsigned int)buffer;
    for (unsigned int index = 0; index != words; ++index) {
        unsigned int chunk = length < 4U ? length : 4U;
        unsigned int word = 0;
        memcpy(&word,(const void *)source,chunk);
        mspi_command_barrier();
        *mspi_command_buffer_word(regs,index) = word;
        length -= chunk;
        source += chunk;
    }
    mspi_command_barrier();
    value = regs->cmd;
    void (*poll)(FlashHostView *) = context->driver->poll_cmd_done;
    mspi_command_barrier();
    regs->cmd = value | 0x02000000U;
    poll(host);
}

/* Native entry: 0x40385518. */
/* Original function-byte SHA-256:
 * 87a5a1e399f789f2b708307f9e327009146c76502e7a11748289ba90b132a56c. */
/* Read USER and, when ADDR bit 30 is set, also read USER1; retain that otherwise
 * unused MMIO read. Write the complete address word. Set USER MISO bit 28 iff
 * wrapping (length<<3) is nonzero; put (bits-1)&1023, or zero, in MISO_DLEN's
 * low ten bits. Read CMD, capture poll callback, then MEMW/write CMD OR USR
 * bit 18 and call it. Even length zero starts and polls a command.
 * Afterwards, aligned buffer+length use one ROM memcpy from +0x58 without an
 * explicit MEMW. Otherwise read (length+3 wrapping)>>2 words with MEMW and copy
 * min(remaining,4) bytes from each. No 64-byte bound, address, buffer or callback
 * validation; oversized reads can leave W0..W15 and word-count overflow skips
 * staged copying. Always return 0; no flash-ready check or own timeout/lock. */
int spi_flash_hal_read(FlashHostView *host,void *buffer,
    unsigned int address,unsigned int length)
{
    const volatile FlashHostView *context = host;
    volatile MspiRegisters *regs = (volatile MspiRegisters *)context->spi;
    mspi_command_barrier();
    unsigned int value = regs->user;
    if ((value & 0x40000000U) != 0) {
        mspi_command_barrier();
        (void)regs->user1;
    }
    mspi_command_barrier();
    regs->addr = address;
    mspi_command_barrier();
    value = regs->user;
    unsigned int bits = length << 3;
    mspi_command_barrier();
    regs->user = (value & ~0x10000000U) | ((unsigned int)(bits != 0) << 28);
    unsigned int bit_length_field = bits != 0 ? (bits - 1U) & 0x3ffU : 0;
    mspi_command_barrier();
    value = regs->miso_dlen;
    mspi_command_barrier();
    regs->miso_dlen = (value & ~0x3ffU) | bit_length_field;
    mspi_command_barrier();
    value = regs->cmd;
    void (*poll)(FlashHostView *) = context->driver->poll_cmd_done;
    mspi_command_barrier();
    regs->cmd = value | 0x00040000U;
    poll(host);

    if (length != 0) {
        if ((((unsigned int)buffer | length) & 3U) == 0) {
            memcpy(buffer,(const void *)mspi_command_buffer_word(regs,0),length);
        } else {
            unsigned int words = (length + 3U) >> 2;
            unsigned int destination = (unsigned int)buffer;
            for (unsigned int index = 0; index != words; ++index) {
                unsigned int chunk = length < 4U ? length : 4U;
                mspi_command_barrier();
                unsigned int word = *mspi_command_buffer_word(regs,index);
                memcpy((void *)destination,&word,chunk);
                destination += chunk;
                length -= chunk;
            }
        }
    }
    return 0;
}

/* Native entry: 0x4038bc58. */
/* Original function-byte SHA-256:
 * 8419c1323d9df1e9915dabac10932b85ca1e5f051770273e8769d862230a9f04. */
/* Compare host->spi with SPI1 0x60002000. Only that pointer calls the existing
 * cache check/flush routine with address and length. Discard its Boolean result
 * and always return 0. No address/size/pointer validation or direct MMIO here. */
int memspi_host_flush_cache(FlashHostView *host,unsigned int address,unsigned int length)
{
    if (((const volatile FlashHostView *)host)->spi == (volatile unsigned int *)0x60002000U)
        spi_flash_check_and_flush_cache(address,length);
    return 0;
}
