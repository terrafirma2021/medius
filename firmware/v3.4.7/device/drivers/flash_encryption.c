/* Medius v3.4.7 device: ESP32-S3 manual XTS-AES flash encryption. */
#include "../include/types.h"

/* Inline reconstruction utilities retain native MMIO barriers; no additional
 * firmware function entry is represented by this helper. */
static __inline__ __attribute__((always_inline)) void flash_encryption_barrier(void)
{
    __asm__ volatile ("memw" ::: "memory");
}

/* Native entry: 0x403898fc. */
/* Original function-byte SHA-256:
 * 0563c3c8c6c294b2dddac97d20a948e6b267c32387e2ace35e9038874061e176. */
/* Set SYSTEM manual encryption enable bits0(SPI) and3(download), then select
 * FLASH destination0 at XTS_AES+0x44. Preserve other SYSTEM bits. Three MEMWs;
 * no lock, key loading, current-state check or status result. */
void spi_flash_encryption_hal_enable(void)
{
    flash_encryption_barrier();
    unsigned int control = *SYSTEM_EXTERNAL_ENCRYPT_CONTROL;
    flash_encryption_barrier();
    *SYSTEM_EXTERNAL_ENCRYPT_CONTROL = control | 9U;
    flash_encryption_barrier();
    XTS_AES_REGISTERS->destination = 0;
}

/* Native entry: 0x40389920. */
/* Original function-byte SHA-256:
 * cfdc3b20a8cbe657550474116ac2cef8fe6b730e55b46c0a53216f0d2ad02fcd. */
/* Clear only SYSTEM SPI manual-encryption bit0, retaining download bit3 and
 * all other control bits. Two MEMWs. Does not destroy the ciphertext or wait. */
void spi_flash_encryption_hal_disable(void)
{
    flash_encryption_barrier();
    unsigned int control = *SYSTEM_EXTERNAL_ENCRYPT_CONTROL;
    flash_encryption_barrier();
    *SYSTEM_EXTERNAL_ENCRYPT_CONTROL = control & ~1U;
}

/* Native entry: 0x40389938. */
/* Original function-byte SHA-256:
 * 81bc2dd54e02388fd36a0fdc1979a00fddc63a97967e10e3efd661a3330ef83d. */
/* Write size>>5 to XTS size, then the physical address, each after MEMW.
 * Compute byte offset=address&63; abort if unsigned32(size+offset)>64, AFTER
 * those writes. Copy exactly size bytes via ROM memcpy into plaintext+offset,
 * then MEMW and trigger1. No buffer/NULL/alignment/key/state validation, no
 * unused-plaintext clearing and no wait. Keep 32-bit addition wrap, so extreme
 * sizes can pass the bound check. Size0 also copies0 and triggers. */
void spi_flash_encryption_hal_prepare(unsigned int address,const unsigned int *buffer,
    unsigned int size)
{
    flash_encryption_barrier();
    XTS_AES_REGISTERS->size = size >> 5;
    unsigned int offset = address & 63U;
    flash_encryption_barrier();
    XTS_AES_REGISTERS->physical_address = address;
    if (size + offset > 64U)
        abort();
    memcpy((void *)((uintptr_t)XTS_AES_REGISTERS->plaintext + offset),buffer,size);
    flash_encryption_barrier();
    XTS_AES_REGISTERS->trigger = 1;
}

/* Native entry: 0x40389978. */
/* Original function-byte SHA-256:
 * 64f06239288625820c1f393349119aa95f0c0fcf59af973a8682b2808e692532. */
/* MEMW/read state repeatedly while it equals1(calculating), then MEMW/write
 * release1 and MEMW/read repeatedly until state3(result accessible to SPI).
 * Exact WORD comparisons, no masks, timeout, yield, error/status or lock.
 * An initial state other than1 immediately proceeds to the release write. */
void spi_flash_encryption_hal_done(void)
{
    unsigned int state;
    do {
        flash_encryption_barrier();
        state = XTS_AES_REGISTERS->state;
    } while (state == 1);
    flash_encryption_barrier();
    XTS_AES_REGISTERS->release = 1;
    do {
        flash_encryption_barrier();
        state = XTS_AES_REGISTERS->state;
    } while (state != 3);
}

/* Native entry: 0x4038999c. */
/* Original function-byte SHA-256:
 * fe93830ed341748aa7f56c6f57b16675482903a61f136f9f8cad2a3a5469e899. */
/* MEMW/write XTS destroy1 to request ciphertext destruction. No polling,
 * plaintext overwrite, disable, locking or returned completion status. */
void spi_flash_encryption_hal_destroy(void)
{
    flash_encryption_barrier();
    XTS_AES_REGISTERS->destroy = 1;
}

/* Native entry: 0x403899ac. */
/* Original function-byte SHA-256:
 * 5634a1fe3d06d51cffe7b9826f08988578a1b22387e2bb96aa281c5466078dff. */
/* Return whether address is divisible by length using native unsigned REMU,
 * followed by NSAU/reduction to bool. No length0 check or software fallback
 * precedes the native REMU instruction. No
 * range, allowed block-size, buffer or hardware-encryption-state check. */
bool spi_flash_encryption_hal_check(unsigned int address,unsigned int length)
{
    return address % length == 0;
}

/* Native entry: 0x403905e0. */
/* Original function-byte SHA-256:
 * 9863e4967dfba39a9ae31fc14d7c715bdfb3678f5ce89254623109ba722294bf. */
/* Require chip to equal the current default-chip pointer and encryption-table
 * check(address,length) to return nonzero; otherwise0x106. Enable encryption,
 * then choose64 bytes if address64-aligned and remaining>=64, else32 if
 * address32-aligned and remaining>=32, else16. Prepare that many input bytes,
 * clear chip write protection, wait/release encryption, call chip write with
 * the WHOLE remaining length, then wait_idle using current driver's timeout
 * WORD+16. On success subtract block size, destroy result, advance buffer and
 * address with32-bit arithmetic, and repeat. Disable only on normal completion.
 * Each failed protect/write/wait returns its status immediately, leaving the
 * encryption state enabled and result undestroyed. No local buffer/bounds/lock
 * checks or protection restoration. Custom check callbacks can admit a length
 * below16, causing subtraction wrap and overread; default check uses REMU with
 * no zero-divisor guard. A custom check accepting0 allows enable/disable only.
 * Reload callback slots and chip driver at native boundaries; no cached policy. */
int spi_flash_chip_generic_write_encrypted(EspFlash *chip,const void *buffer,
    unsigned int address,unsigned int length)
{
    const volatile EspFlash *context = chip;
    if (chip != DEFAULT_FLASH_CHIP)
        return 0x106;
    if (!FLASH_ENCRYPTION_FUNCTIONS->check(address,length))
        return 0x106;
    FLASH_ENCRYPTION_FUNCTIONS->enable();
    const unsigned char *data = buffer;
    while (length != 0) {
        unsigned int block_size;
        if ((address & 63U) == 0 && length >= 64U)
            block_size = 64;
        else if ((address & 31U) == 0 && length >= 32U)
            block_size = 32;
        else
            block_size = 16;
        FLASH_ENCRYPTION_FUNCTIONS->prepare(address,(const unsigned int *)data,block_size);
        int status = context->chip_driver->set_chip_write_protect(chip,false);
        if (status != 0)
            return status;
        FLASH_ENCRYPTION_FUNCTIONS->done();
        status = context->chip_driver->write(chip,data,address,length);
        if (status != 0)
            return status;
        const volatile FlashChipDriverView *driver = context->chip_driver;
        const volatile FlashTimeouts *timeout = driver->timeout;
        int (*wait_idle)(EspFlash *,unsigned int) = driver->wait_idle;
        unsigned int timeout_us = timeout->page_program_timeout;
        status = wait_idle(chip,timeout_us);
        if (status != 0)
            return status;
        length -= block_size;
        FLASH_ENCRYPTION_FUNCTIONS->destroy();
        data = (const unsigned char *)((uintptr_t)data + block_size);
        address += block_size;
    }
    FLASH_ENCRYPTION_FUNCTIONS->disable();
    return 0;
}
