/* Medius v3.4.7 host: ESP32-S3 manual XTS-AES flash encryption. */
#include "../include/types.h"

/* Inline reconstruction utilities retain native MMIO barriers; no additional
 * firmware function entry is represented by this helper. */
static __inline__ __attribute__((always_inline)) void flash_encryption_barrier(void)
{
    __asm__ volatile ("memw" ::: "memory");
}

/* Native entry: 0x4038487c. */
/* Original function-byte SHA-256:
 * 9a79d68891859e5752ad384fd1fde1c626d3298d3ead4019e1e309889e425234. */
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

/* Native entry: 0x403848a0. */
/* Original function-byte SHA-256:
 * fe372edd236a1608c2ffda68bac69725e5d7831da0501733d2947e793468a83a. */
/* Clear only SYSTEM SPI manual-encryption bit0, retaining download bit3 and
 * all other control bits. Two MEMWs. Does not destroy the ciphertext or wait. */
void spi_flash_encryption_hal_disable(void)
{
    flash_encryption_barrier();
    unsigned int control = *SYSTEM_EXTERNAL_ENCRYPT_CONTROL;
    flash_encryption_barrier();
    *SYSTEM_EXTERNAL_ENCRYPT_CONTROL = control & ~1U;
}

/* Native entry: 0x403848b8. */
/* Original function-byte SHA-256:
 * 26047203fa5f75095493d4b2b6a542faed35918d99d7d36c3c8bf0f25d4db2ba. */
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

/* Native entry: 0x403848f8. */
/* Original function-byte SHA-256:
 * b3e10cb3b00920e4619c7c388a7a9ac96955d311ba0cc2da504bbcbc9827e64b. */
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

/* Native entry: 0x4038491c. */
/* Original function-byte SHA-256:
 * a2ce8c589418eebabc4fdb20a1e7e11461f9f7dec658fa290b4f064e6c4da4a5. */
/* MEMW/write XTS destroy1 to request ciphertext destruction. No polling,
 * plaintext overwrite, disable, locking or returned completion status. */
void spi_flash_encryption_hal_destroy(void)
{
    flash_encryption_barrier();
    XTS_AES_REGISTERS->destroy = 1;
}

/* Native entry: 0x4038492c. */
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

/* Native entry: 0x4038c3a8. */
/* Original function-byte SHA-256:
 * 9faecc8810d6c1e8c6a87a35d2f1be36a34052c4e8604c397b69156f2b6d9a56. */
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
        int status = chip->chip_driver->set_chip_write_protect(chip,false);
        if (status != 0)
            return status;
        FLASH_ENCRYPTION_FUNCTIONS->done();
        status = chip->chip_driver->write(chip,data,address,length);
        if (status != 0)
            return status;
        const volatile FlashChipDriverView *driver = chip->chip_driver;
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
