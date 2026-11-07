/* Medius v3.4.7 host: GPSPI flash setup/status and direct-buffer queries. */
#include "../include/types.h"

/* Inline reconstruction utilities preserve each native MEMW separately.
 * This helper does not represent an additional firmware entry. */
static __inline__ __attribute__((always_inline)) void gpspi_flash_barrier(void)
{
    __asm__ volatile ("memw" ::: "memory");
}

/* Native entry: 0x4038493c. */
/* Original function-byte SHA-256:
 * bb9861e9409a028fb4c3da87d1b7c9f6b98db5a0fe3965e55d67c3e6e6aaebde. */
/* Configure the cached GPSPI peripheral pointer from a HAL context. Zero USER
 * then CTRL; separately enable clock-gate/active/source bits 0/1/2. Reset
 * DMA_CONF then set TX/RX segment-clear bits 20/19 and clear segment mode bit 18,
 * keeping all three native RMWs. Select CS0/CS1 disable bits from one cached
 * signed CS value, leaving other CS bits untouched. MEMW/read context clock,
 * MEMW/write CLOCK. Read hold BYTE once: write (hold-1)&31 to USER1 bits 22..26,
 * and enable USER bit 6 iff nonzero. Read setup BYTE once: USER bit 7 iff nonzero,
 * USER1 bits 17..21=(setup-1)&31. Finally set CTRL HOLD_POL bit 20. Each MMIO
 * read/write retains its preceding MEMW, including the context-clock read.
 * Zero setup/hold programs 31 while disabling its phase. No validation, idle
 * wait, DMA transfer, timeout or lock. Return 0 (lost in old void decompile). */
int spi_flash_hal_gpspi_device_config(FlashHostView *host)
{
    const volatile FlashHostView *context = host;
    volatile GpspiFlashRegisters *regs = (volatile GpspiFlashRegisters *)context->spi;
    gpspi_flash_barrier();
    regs->user = 0;
    gpspi_flash_barrier();
    regs->ctrl = 0;
    gpspi_flash_barrier();
    unsigned int value = regs->clock_gate;
    gpspi_flash_barrier();
    regs->clock_gate = value | 1U;
    gpspi_flash_barrier();
    value = regs->clock_gate;
    gpspi_flash_barrier();
    regs->clock_gate = value | 2U;
    gpspi_flash_barrier();
    value = regs->clock_gate;
    gpspi_flash_barrier();
    regs->clock_gate = value | 4U;
    gpspi_flash_barrier();
    regs->dma_conf = 0;
    gpspi_flash_barrier();
    value = regs->dma_conf;
    gpspi_flash_barrier();
    regs->dma_conf = value | 0x100000U;
    gpspi_flash_barrier();
    value = regs->dma_conf;
    gpspi_flash_barrier();
    regs->dma_conf = value | 0x80000U;
    gpspi_flash_barrier();
    value = regs->dma_conf;
    gpspi_flash_barrier();
    regs->dma_conf = value & ~0x40000U;
    gpspi_flash_barrier();
    value = regs->misc;
    int cs = context->cs_num;
    gpspi_flash_barrier();
    regs->misc = (value & ~1U) | (unsigned int)(cs != 0);
    gpspi_flash_barrier();
    value = regs->misc;
    gpspi_flash_barrier();
    regs->misc = (value & ~2U) | ((unsigned int)(cs != 1) << 1);
    gpspi_flash_barrier();
    unsigned int clock = context->clock_conf;
    gpspi_flash_barrier();
    regs->clock = clock;
    unsigned int hold = context->cs_hold;
    gpspi_flash_barrier();
    value = regs->user1;
    gpspi_flash_barrier();
    regs->user1 = (value & 0xf83fffffU) | (((hold - 1U) & 31U) << 22);
    gpspi_flash_barrier();
    value = regs->user;
    gpspi_flash_barrier();
    regs->user = (value & ~0x40U) | ((unsigned int)(hold != 0) << 6);
    unsigned int setup = context->cs_setup;
    gpspi_flash_barrier();
    value = regs->user;
    gpspi_flash_barrier();
    regs->user = (value & ~0x80U) | ((unsigned int)(setup != 0) << 7);
    gpspi_flash_barrier();
    value = regs->user1;
    gpspi_flash_barrier();
    regs->user1 = (value & 0xffc1ffffU) | (((setup - 1U) & 31U) << 17);
    gpspi_flash_barrier();
    value = regs->ctrl;
    gpspi_flash_barrier();
    regs->ctrl = value | 0x100000U;
    return 0;
}

/* Native entry: 0x4038500c. */
/* Original function-byte SHA-256:
 * 93e8ed3c1512981fb448b3382b8582ce78752d5006aa89d4441e0c6cc75c4c7f. */
/* Return true without accessing host or buffer. This reports the GPSPI host's
 * direct-write capability only; it validates no pointer, length or lifetime. */
bool spi_flash_hal_gpspi_supports_direct_write(FlashHostView *unused_host,const void *unused_buffer)
{
    (void)unused_host;
    (void)unused_buffer;
    return true;
}

/* Native entry: 0x40385014. */
/* Original function-byte SHA-256:
 * 93e8ed3c1512981fb448b3382b8582ce78752d5006aa89d4441e0c6cc75c4c7f. */
/* Return true without accessing either argument. No alignment, buffer extent,
 * ownership or hardware-readiness validation is implied. */
bool spi_flash_hal_gpspi_supports_direct_read(FlashHostView *unused_host,const void *unused_buffer)
{
    (void)unused_host;
    (void)unused_buffer;
    return true;
}

/* Native entry: 0x4038501c. */
/* Original function-byte SHA-256:
 * 79038558161d336195f94eedc6350e3a20875263e0ba768306f43a23fae732d7. */
/* Cache host->spi, MEMW/read CMD and return 1 iff USR bit 24 is clear, else 0.
 * This specialization returns an idle predicate, not a complete status mask.
 * No other register, wait, error handling or lock; host pointer is unchecked. */
unsigned int spi_flash_hal_gpspi_check_status(FlashHostView *host)
{
    volatile GpspiFlashRegisters *regs =
        (volatile GpspiFlashRegisters *)((const volatile FlashHostView *)host)->spi;
    gpspi_flash_barrier();
    unsigned int command = regs->cmd;
    return ((command >> 24) & 1U) ^ 1U;
}

/* Native entry: 0x40384ffc. */
/* Original function-byte SHA-256:
 * e595bad14bb408da79037841b3323d2785eda654e9c07daf12c36f2e58e60ddf. */
/* Cache host->spi once, then MEMW/read CMD until USR bit 24 clears. Unlimited
 * busy wait without timeout, yield, error bits, own lock or returned status. */
void spi_flash_hal_gpspi_poll_cmd_done(FlashHostView *host)
{
    volatile GpspiFlashRegisters *regs =
        (volatile GpspiFlashRegisters *)((const volatile FlashHostView *)host)->spi;
    unsigned int command;
    do {
        gpspi_flash_barrier();
        command = regs->cmd;
    } while ((command & 0x1000000U) != 0);
}

/* Native entry: 0x4201370c. */
/* Original function-byte SHA-256:
 * abf7966a25b6873e347b28503b9edb36b8b327c43ab7fe9f6781d8580f95428b. */
/* Ignore buffer. Return whether the context's SPI pointer differs from SPI1
 * 0x60002000. A NULL/unknown SPI value also returns true; host itself is read
 * unchecked. No buffer classification, length, alignment or MMIO operation. */
bool spi_flash_hal_supports_direct_write(FlashHostView *host,const void *unused_buffer)
{
    (void)unused_buffer;
    return ((const volatile FlashHostView *)host)->spi != (volatile unsigned int *)0x60002000U;
}

/* Native entry: 0x42013720. */
/* Original function-byte SHA-256:
 * 3018990b89e96decb0404a8de45fa3f9d649b43b6332e6639f819ebc20892b8e. */
/* Same SPI1 exclusion predicate for direct reads. Buffer is unused; no buffer
 * or peripheral-state validation, dereference, cache work or lock occurs. */
bool spi_flash_hal_supports_direct_read(FlashHostView *host,const void *unused_buffer)
{
    (void)unused_buffer;
    return ((const volatile FlashHostView *)host)->spi != (volatile unsigned int *)0x60002000U;
}
