/* Medius v3.4.7 device: MSPI setup/suspend timing and GPSPI read transactions. */
#include "../include/types.h"

/* Inline reconstruction utilities preserve explicit barriers, ordered unsigned
 * division and wrapping buffer-register addresses. They add no native entries. */
static __inline__ __attribute__((always_inline)) void flash_setup_barrier(void)
{
    __asm__ volatile ("memw" ::: "memory");
}
static __inline__ __attribute__((always_inline)) unsigned int
flash_setup_remainder(unsigned int value,unsigned int unit)
{
    unsigned int result;
    __asm__ volatile ("remu %0,%1,%2" : "=a"(result) : "a"(value),"a"(unit) : "memory");
    return result;
}
static __inline__ __attribute__((always_inline)) unsigned int
flash_setup_quotient(unsigned int value,unsigned int unit)
{
    unsigned int result;
    __asm__ volatile ("quou %0,%1,%2" : "=a"(result) : "a"(value),"a"(unit) : "memory");
    return result;
}

/* Native entry: 0x4038aa44. */
/* Original function-byte SHA-256:
 * 967c0028559bfeec5d812df4aa80bf9629c7ae2ccd0a835b5a76bb92deacc47f. */
/* Reset selected MSPI USER/CTRL, update CS0/CS1 disable bits from one signed
 * cs_num load, and copy the context clock with MEMW before its RAM read and
 * MMIO write. Hold/setup are byte loads: program (value-1)&31 in CTRL2 while
 * enabling USER bits 6/7 only for nonzero values. Other CTRL2 bits survive.
 * Cache flags once. Bit 0 calls auto-suspend setup; otherwise disable its
 * WAITI/SUS bits at fixed SPI1, retaining volatile stack staging and each RMW.
 * Cached flag bit 1 sets/clears fixed SPI1 MISC bit 11. Finally clear selected
 * peripheral TIMING_CALI bits 2..4 and return 0. Fixed SPI1 accesses occur even
 * when the context names another peripheral. No validation, wait or own lock. */
int spi_flash_hal_device_config(FlashHostView *host)
{
    const volatile FlashHostView *context = host;
    volatile MspiRegisters *regs = (volatile MspiRegisters *)context->spi;
    flash_setup_barrier();
    regs->user = 0;
    flash_setup_barrier();
    regs->ctrl = 0;
    flash_setup_barrier();
    unsigned int value = regs->misc;
    int cs = context->cs_num;
    flash_setup_barrier();
    regs->misc = (value & ~1U) | (unsigned int)(cs != 0);
    flash_setup_barrier();
    value = regs->misc;
    flash_setup_barrier();
    regs->misc = (value & ~2U) | ((unsigned int)(cs != 1) << 1);
    flash_setup_barrier();
    unsigned int clock = context->clock_conf;
    flash_setup_barrier();
    regs->flash_clock = clock;
    unsigned int hold = context->cs_hold;
    flash_setup_barrier();
    value = regs->ctrl2;
    flash_setup_barrier();
    regs->ctrl2 = (value & ~0x3e0U) | (((hold - 1U) & 31U) << 5);
    flash_setup_barrier();
    value = regs->user;
    flash_setup_barrier();
    regs->user = (value & ~0x40U) | ((unsigned int)(hold != 0) << 6);
    unsigned int setup = context->cs_setup;
    flash_setup_barrier();
    value = regs->user;
    flash_setup_barrier();
    regs->user = (value & ~0x80U) | ((unsigned int)(setup != 0) << 7);
    flash_setup_barrier();
    value = regs->ctrl2;
    flash_setup_barrier();
    regs->ctrl2 = (value & ~31U) | ((setup - 1U) & 31U);

    unsigned int flags = context->flags;
    volatile MspiRegisters *spi1 = MSPI1;
    if ((flags & 1U) != 0) {
        spi_flash_hal_setup_auto_suspend_mode(host);
    } else {
        flash_setup_barrier();
        value = spi1->wait_idle_ctrl;
        flash_setup_barrier();
        volatile unsigned int staged_wait = value;
        flash_setup_barrier();
        value = staged_wait;
        value = (value & ~0x3fcU) | 0x14U;
        flash_setup_barrier();
        staged_wait = value;
        flash_setup_barrier();
        value = staged_wait;
        flash_setup_barrier();
        spi1->wait_idle_ctrl = value;
        flash_setup_barrier();
        value = spi1->wait_idle_ctrl;
        flash_setup_barrier();
        spi1->wait_idle_ctrl = value & ~1U;
        flash_setup_barrier();
        value = spi1->flash_suspend_command;
        flash_setup_barrier();
        spi1->flash_suspend_command = value & ~4U;
        flash_setup_barrier();
        value = spi1->flash_suspend_command;
        flash_setup_barrier();
        spi1->flash_suspend_command = value & ~8U;
        flash_setup_barrier();
        value = spi1->flash_suspend_control;
        flash_setup_barrier();
        spi1->flash_suspend_control = value & ~1U;
        flash_setup_barrier();
        value = spi1->flash_suspend_command;
        flash_setup_barrier();
        spi1->flash_suspend_command = value & ~16U;
    }
    flash_setup_barrier();
    value = spi1->misc;
    flash_setup_barrier();
    spi1->misc = (flags & 2U) != 0 ? value | 0x800U : value & ~0x800U;
    flash_setup_barrier();
    value = regs->timing_cali;
    flash_setup_barrier();
    regs->timing_cali = value & ~0x1cU;
    return 0;
}

/* Native entry: 0x4038a83c. */
/* Original function-byte SHA-256:
 * 178153f46ebc59440e4608560ef91c134742dad7978fd9b5d2f91d041c4ca731. */
/* ROM memcpy exactly eight config bytes into host->suspend, then reload command
 * bytes from the original input: suspend byte before the first RMW, resume
 * byte before its write. Two staged volatile RMWs on fixed SPI1 SUS_CTRL replace
 * bits 9..16 and 1..8 respectively, preserving other bits and all native MEMWs.
 * The mask/read-status bytes are copied but not programmed here. Return 0.
 * Neither host->spi nor pointer validity, overlap or command values is checked. */
int spi_flash_hal_setup_read_suspend(FlashHostView *host,
    const FlashSuspendCommands *commands)
{
    const volatile FlashSuspendCommands *input = commands;
    memcpy(&host->suspend,commands,8);
    volatile MspiRegisters *spi1 = MSPI1;
    unsigned int suspend_command = input->suspend_command;
    flash_setup_barrier();
    unsigned int value = spi1->flash_suspend_control;
    flash_setup_barrier();
    volatile unsigned int staged_suspend = value;
    flash_setup_barrier();
    value = staged_suspend;
    value = (value & ~0x1fe00U) | (suspend_command << 9);
    flash_setup_barrier();
    staged_suspend = value;
    flash_setup_barrier();
    value = staged_suspend;
    unsigned int resume_command = input->resume_command;
    flash_setup_barrier();
    spi1->flash_suspend_control = value;
    flash_setup_barrier();
    value = spi1->flash_suspend_control;
    flash_setup_barrier();
    volatile unsigned int staged_resume = value;
    flash_setup_barrier();
    value = staged_resume;
    value = (value & ~0x1feU) | (resume_command << 1);
    flash_setup_barrier();
    staged_resume = value;
    flash_setup_barrier();
    value = staged_resume;
    flash_setup_barrier();
    spi1->flash_suspend_control = value;
    return 0;
}

/* Native entry: 0x4038a8b0. */
/* Original function-byte SHA-256:
 * c2d0bd5a1e4166f2bee5d7ede37f06ba3fd3f83eda5de4cb2ea67482b70a1824. */
/* Operate on fixed SPI1/SPI0, independent of host->spi. Stage WAITI_CTRL's
 * bits 2..9 to 5, set WAITI bit 0 and SUS_CMD bit 2. SUS_CMD bit 3 receives
 * the complement of auto_waiti_pes's low bit, not a normalized byte Boolean.
 * Cache signed freq_mhz. Only at 120 MHz, configure WAITI dummy bits from the
 * extra_dummy byte: zero clears enable bit 1, nonzero sets it after writing
 * (dummy-1)&63. Set SUS_CTRL bit 0 and SUS_CMD bit 4.
 * Sample SPI1 SUS_STATUS twice around a tsus_val byte load. First bit 6 selects
 * quotient unit 4/256; second selects remainder unit 4/256. Multiply tsus*freq
 * modulo 32 bits, REMU using the second unit, then QUOU using the first. Write
 * (quotient+(remainder!=0))&1023 to CTRL1 bits 2..11. The two units can differ.
 * Then set SUS_STATUS bits 5 and 6 separately. Read SPI0 CORE_CLK low two bits
 * to choose CTRL2 bits 25..30 as 3/4/5/8; retain the second, discarded CORE_CLK
 * read before the CTRL2 RMW. No input bounds, stabilization loop or lock. */
void spi_flash_hal_setup_auto_suspend_mode(FlashHostView *host)
{
    const volatile FlashHostView *context = host;
    volatile MspiRegisters *spi1 = MSPI1;
    volatile MspiRegisters *spi0 = MSPI0;
    flash_setup_barrier();
    unsigned int value = spi1->wait_idle_ctrl;
    flash_setup_barrier();
    volatile unsigned int staged_wait = value;
    flash_setup_barrier();
    value = staged_wait;
    value = (value & ~0x3fcU) | 0x14U;
    flash_setup_barrier();
    staged_wait = value;
    flash_setup_barrier();
    value = staged_wait;
    unsigned int wait_after_suspend = context->auto_waiti_pes;
    flash_setup_barrier();
    spi1->wait_idle_ctrl = value;
    flash_setup_barrier();
    value = spi1->wait_idle_ctrl;
    flash_setup_barrier();
    spi1->wait_idle_ctrl = value | 1U;
    flash_setup_barrier();
    value = spi1->flash_suspend_command;
    flash_setup_barrier();
    spi1->flash_suspend_command = value | 4U;
    flash_setup_barrier();
    value = spi1->flash_suspend_command;
    flash_setup_barrier();
    spi1->flash_suspend_command = (value & ~8U) | (((wait_after_suspend ^ 1U) & 1U) << 3);

    int frequency = context->freq_mhz;
    if (frequency == 120) {
        unsigned int dummy = context->extra_dummy;
        if (dummy != 0) {
            flash_setup_barrier();
            value = spi1->wait_idle_ctrl;
            flash_setup_barrier();
            spi1->wait_idle_ctrl = (value & ~0xfc00U) | (((dummy - 1U) & 63U) << 10);
            flash_setup_barrier();
            value = spi1->wait_idle_ctrl;
            flash_setup_barrier();
            spi1->wait_idle_ctrl = value | 2U;
        } else {
            flash_setup_barrier();
            value = spi1->wait_idle_ctrl;
            flash_setup_barrier();
            spi1->wait_idle_ctrl = value & ~2U;
        }
    }
    flash_setup_barrier();
    value = spi1->flash_suspend_control;
    flash_setup_barrier();
    spi1->flash_suspend_control = value | 1U;
    flash_setup_barrier();
    value = spi1->flash_suspend_command;
    flash_setup_barrier();
    spi1->flash_suspend_command = value | 16U;
    flash_setup_barrier();
    unsigned int first_status = spi1->suspend_status;
    unsigned int tsus = context->tsus_val;
    flash_setup_barrier();
    unsigned int second_status = spi1->suspend_status;
    unsigned int product = tsus * (unsigned int)frequency;
    unsigned int remainder_unit = (second_status & 0x40U) != 0 ? 256U : 4U;
    unsigned int quotient_unit = (first_status & 0x40U) != 0 ? 256U : 4U;
    unsigned int remainder = flash_setup_remainder(product,remainder_unit);
    unsigned int quotient = flash_setup_quotient(product,quotient_unit);
    unsigned int delay = quotient + (unsigned int)(remainder != 0);
    flash_setup_barrier();
    value = spi1->ctrl1;
    flash_setup_barrier();
    spi1->ctrl1 = (value & ~0xffcU) | ((delay & 0x3ffU) << 2);
    flash_setup_barrier();
    value = spi1->suspend_status;
    flash_setup_barrier();
    spi1->suspend_status = value | 0x20U;
    flash_setup_barrier();
    value = spi1->suspend_status;
    flash_setup_barrier();
    spi1->suspend_status = value | 0x40U;
    flash_setup_barrier();
    unsigned int clock_source = spi0->core_clock & 3U;
    unsigned int hold_delay;
    if (clock_source == 2)
        hold_delay = 5;
    else if (clock_source == 3)
        hold_delay = 8;
    else
        hold_delay = clock_source != 0 ? 4 : 3;
    flash_setup_barrier();
    (void)spi0->core_clock;
    flash_setup_barrier();
    value = spi0->ctrl2;
    flash_setup_barrier();
    spi0->ctrl2 = (value & ~0x7e000000U) | (hold_delay << 25);
}

/* Native entry: 0x40389f84. */
/* Original function-byte SHA-256:
 * 2b9c0788ae7cc280bf488a4bd379d5b7c5f49686760989bc5ee2b4702994d4bf. */
/* Cache GPSPI registers. If USER ADDR is disabled, write address 0xffffffff;
 * otherwise round configured address bits down to 0/8/16/24/32 and pad its low
 * unsent portion with ones (32 leaves address unchanged; 0 yields all ones).
 * USER MISO bit 28 follows wrapping length*8. Only nonzero bit length updates
 * MS_DLEN low 18 bits to bits-1. Start UPDATE bit 23 and MEMW/poll it until
 * clear, then read CMD, capture driver->poll_cmd_done before writing USR bit 24,
 * and call it. Both waits have no timeout. Zero length still starts commands.
 * Aligned buffer+length use ROM memcpy from +0x98; other cases MEMW/read words
 * and copy partial chunks. Wrapping (length+3)>>2 and buffer arithmetic remain;
 * no 64-byte cap, pointer/range validation or own lock. Return 0. */
int spi_flash_hal_gpspi_read(FlashHostView *host,void *buffer,
    unsigned int address,unsigned int length)
{
    const volatile FlashHostView *context = host;
    volatile GpspiFlashRegisters *regs = (volatile GpspiFlashRegisters *)context->spi;
    flash_setup_barrier();
    unsigned int value = regs->user;
    if ((value & 0x40000000U) != 0) {
        flash_setup_barrier();
        unsigned int address_bits = ((regs->user1 >> 27) + 1U) & ~7U;
        if (address_bits == 0)
            address = 0xffffffffU;
        else if (address_bits != 32)
            address = (address << (32U - address_bits)) | (0xffffffffU >> address_bits);
    } else {
        address = 0xffffffffU;
    }
    flash_setup_barrier();
    regs->addr = address;
    flash_setup_barrier();
    value = regs->user;
    unsigned int bits = length << 3;
    flash_setup_barrier();
    regs->user = (value & ~0x10000000U) | ((unsigned int)(bits != 0) << 28);
    if (bits != 0) {
        flash_setup_barrier();
        value = regs->ms_dlen;
        flash_setup_barrier();
        regs->ms_dlen = (value & ~0x3ffffU) | ((bits - 1U) & 0x3ffffU);
    }
    flash_setup_barrier();
    value = regs->cmd;
    flash_setup_barrier();
    regs->cmd = value | 0x00800000U;
    do {
        flash_setup_barrier();
        value = regs->cmd;
    } while ((value & 0x00800000U) != 0);
    flash_setup_barrier();
    value = regs->cmd;
    void (*poll)(FlashHostView *) = context->driver->poll_cmd_done;
    flash_setup_barrier();
    regs->cmd = value | 0x01000000U;
    poll(host);
    if (length != 0) {
        unsigned int data_address = (unsigned int)regs + 0x98U;
        if ((((unsigned int)buffer | length) & 3U) == 0) {
            memcpy(buffer,(const void *)data_address,length);
        } else {
            unsigned int words = (length + 3U) >> 2;
            unsigned int destination = (unsigned int)buffer;
            for (unsigned int index = 0; index != words; ++index) {
                unsigned int chunk = length < 4U ? length : 4U;
                flash_setup_barrier();
                unsigned int word = *(volatile unsigned int *)(data_address + (index << 2));
                memcpy((void *)destination,&word,chunk);
                destination += chunk;
                length -= chunk;
            }
        }
    }
    return 0;
}
