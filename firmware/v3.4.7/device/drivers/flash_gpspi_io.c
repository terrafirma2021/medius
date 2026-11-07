/* Medius v3.4.7 device: GPSPI flash I/O modes and common transactions. */
#include "../include/types.h"

/* Inline reconstruction utilities preserve every explicit native MEMW.
 * The barrier helper does not add a firmware entry. */
static __inline__ __attribute__((always_inline)) void gpspi_io_barrier(void)
{
    __asm__ volatile ("memw" ::: "memory");
}

/* Native entry: 0x40389af8. */
/* Original function-byte SHA-256:
 * 88ae006a8d1603a1723ef715bd54aa61d1c844454a5bd68049dfa8a18ecf9e50. */
/* Configure the cached GPSPI registers, preserving ordered volatile RMWs and
 * volatile stack staging. io_mode bit 31 controls CTRL bit 3; set CTRL bits
 * 18/19 separately. Commands >255 select a 16-bit phase but retain only their
 * low byte; other commands select eight bits. This truncation is native.
 * Address length wraps into USER1's high five bits; zero disables USER ADDR.
 * Add the context extra_dummy byte to dummy_base modulo 32 bits. Nonzero
 * enables USER DUMMY; USER1 always receives (cycles-1)&255, including zero.
 * Disable both data phases, then stage CTRL/USER read-mode fields. Low mode
 * 0/1 selects single-line, 2 dual output, 3 dual I/O, 4 quad output, 5 quad I/O.
 * Other modes abort after earlier register changes, before the final staged
 * CTRL/USER commit. Mode bits 16..30 are unused. Return 0 on the normal path;
 * no argument, peripheral, command, idle-state, timeout or lock validation. */
int spi_flash_hal_gpspi_configure_host_io_mode(FlashHostView *host,
    unsigned int command,unsigned int address_bits,int dummy_base,unsigned int io_mode)
{
    const volatile FlashHostView *context = host;
    volatile GpspiFlashRegisters *regs = (volatile GpspiFlashRegisters *)context->spi;
    gpspi_io_barrier();
    unsigned int value = regs->ctrl;
    gpspi_io_barrier();
    regs->ctrl = (value & ~8U) | ((io_mode >> 31) << 3);
    gpspi_io_barrier();
    value = regs->ctrl;
    gpspi_io_barrier();
    regs->ctrl = value | 0x40000U;
    gpspi_io_barrier();
    value = regs->ctrl;
    gpspi_io_barrier();
    regs->ctrl = value | 0x80000U;

    unsigned int mode = io_mode & 0xffffU;
    bool long_command = command > 255U;
    gpspi_io_barrier();
    value = regs->user;
    gpspi_io_barrier();
    regs->user = value | 0x80000000U;
    gpspi_io_barrier();
    volatile unsigned int staged_command = 0;
    gpspi_io_barrier();
    value = staged_command;
    value = (value & 0xffff0000U) | (command & (long_command ? 0xffU : 0xffffU));
    gpspi_io_barrier();
    staged_command = value;
    gpspi_io_barrier();
    value = staged_command;
    value = long_command ? value | 0xf0000000U : (value & 0x0fffffffU) | 0x70000000U;
    gpspi_io_barrier();
    staged_command = value;
    gpspi_io_barrier();
    value = staged_command;
    gpspi_io_barrier();
    regs->user2 = value;

    gpspi_io_barrier();
    value = regs->user1;
    gpspi_io_barrier();
    regs->user1 = (value & 0x07ffffffU) | ((address_bits - 1U) << 27);
    gpspi_io_barrier();
    value = regs->user;
    gpspi_io_barrier();
    regs->user = (value & ~0x40000000U) | ((unsigned int)(address_bits != 0) << 30);
    unsigned int extra_dummy = context->extra_dummy;
    gpspi_io_barrier();
    value = regs->user;
    unsigned int dummy_cycles = (unsigned int)dummy_base + extra_dummy;
    gpspi_io_barrier();
    regs->user = (value & ~0x20000000U) | ((unsigned int)(dummy_cycles != 0) << 29);
    gpspi_io_barrier();
    value = regs->user1;
    gpspi_io_barrier();
    volatile unsigned int staged_dummy = value;
    gpspi_io_barrier();
    value = staged_dummy;
    value = (value & ~0xffU) | ((dummy_cycles - 1U) & 0xffU);
    gpspi_io_barrier();
    staged_dummy = value;
    gpspi_io_barrier();
    value = staged_dummy;
    gpspi_io_barrier();
    regs->user1 = value;
    gpspi_io_barrier();
    value = regs->user;
    gpspi_io_barrier();
    regs->user = value & ~0x10000000U;
    gpspi_io_barrier();
    value = regs->user;
    gpspi_io_barrier();
    regs->user = value & ~0x08000000U;

    gpspi_io_barrier();
    value = regs->ctrl;
    gpspi_io_barrier();
    volatile unsigned int staged_ctrl = value;
    gpspi_io_barrier();
    value = regs->user;
    gpspi_io_barrier();
    volatile unsigned int staged_user = value;
    gpspi_io_barrier();
    value = staged_ctrl;
    gpspi_io_barrier();
    staged_ctrl = value & 0xffff3c9fU;
    gpspi_io_barrier();
    value = staged_user;
    gpspi_io_barrier();
    staged_user = value & 0xffffcfffU;

    switch (mode) {
    case 0: /* slow single-line read */
    case 1: /* fast single-line read */
        break;
    case 2: /* dual output */
    case 3: /* dual I/O */
        if (mode == 3) {
            gpspi_io_barrier();
            value = staged_ctrl;
            gpspi_io_barrier();
            staged_ctrl = value | 0x4000U;
        }
        gpspi_io_barrier();
        value = staged_ctrl;
        gpspi_io_barrier();
        staged_ctrl = value | (mode == 3 ? 0x20U : 0x4000U);
        gpspi_io_barrier();
        value = staged_user;
        gpspi_io_barrier();
        staged_user = value | 0x1000U;
        break;
    case 4: /* quad output */
    case 5: /* quad I/O */
        if (mode == 5) {
            gpspi_io_barrier();
            value = staged_ctrl;
            gpspi_io_barrier();
            staged_ctrl = value | 0x8000U;
        }
        gpspi_io_barrier();
        value = staged_ctrl;
        gpspi_io_barrier();
        staged_ctrl = value | (mode == 5 ? 0x40U : 0x8000U);
        gpspi_io_barrier();
        value = staged_user;
        gpspi_io_barrier();
        staged_user = value | 0x2000U;
        break;
    default:
        abort();
    }
    gpspi_io_barrier();
    value = staged_ctrl;
    gpspi_io_barrier();
    regs->ctrl = value;
    gpspi_io_barrier();
    value = staged_user;
    gpspi_io_barrier();
    regs->user = value;
    return 0;
}

/* Native entry: 0x40389d5c. */
/* Original function-byte SHA-256:
 * a81127eb571cd3460c222ba0ae675ddfb405fe21beaf2f37e770c92a31efb656. */
/* Cache flags, peripheral, command and dummy byte. Flag bit 1 selects the
 * transaction mode instead of host base_io_mode. Call the live configure slot
 * at +0x3c and ignore its status. Reload address length/address afterwards;
 * pad address using native modulo-32 shifts, treating exactly 32 bits specially.
 * If the initial RX length is zero, override dummy timing without extra_dummy.
 * Set MOSI from its byte length and stage zero-padded TX words at +0x98. Length
 * can reach 255: no 64-byte hardware-buffer cap. After TX, reload RX length and
 * let its bit count replace the shared MS_DLEN field. Receive-only uses the
 * initial RX length; no-data leaves that field unchanged.
 * Set UPDATE and poll bit 23 without timeout, then capture the current polling
 * callback before setting USR bit 24 and calling it. Reload RX length/pointer
 * after polling. Aligned output uses one ROM memcpy; other output uses explicit
 * MEMW/word reads and partial copies. All live transaction reloads are retained.
 * Other transaction flags are unused. Return 0 regardless of configure status;
 * no pointer, capacity, mode, readiness or concurrency validation is provided. */
int spi_flash_hal_gpspi_common_command(FlashHostView *host,FlashTransaction *transaction)
{
    const volatile FlashHostView *context = host;
    const volatile FlashTransaction *input = transaction;
    unsigned int flags = input->flags;
    volatile GpspiFlashRegisters *regs = (volatile GpspiFlashRegisters *)context->spi;
    unsigned int command = input->command;
    unsigned int dummy = input->dummy_bitlen;
    unsigned int mode = (flags & 2U) != 0 ? input->io_mode : context->base_io_mode;
    unsigned int address_bits = input->address_bitlen;
    context->driver->configure_host_io_mode(host,command,address_bits,(int)dummy,mode);

    address_bits = input->address_bitlen;
    unsigned int address = input->address;
    unsigned int padding = address_bits == 32U ? 0 : 0xffffffffU >> (address_bits & 31U);
    unsigned int shifted_address = address << ((32U - address_bits) & 31U);
    gpspi_io_barrier();
    regs->addr = shifted_address | padding;
    unsigned int rx_length = input->miso_len;
    unsigned int value;
    if (rx_length == 0) {
        gpspi_io_barrier();
        value = regs->user;
        gpspi_io_barrier();
        regs->user = (value & ~0x20000000U) | ((unsigned int)(dummy != 0) << 29);
        gpspi_io_barrier();
        value = regs->user1;
        gpspi_io_barrier();
        volatile unsigned int staged_dummy = value;
        gpspi_io_barrier();
        value = staged_dummy;
        value = (value & ~0xffU) | ((dummy - 1U) & 0xffU);
        gpspi_io_barrier();
        staged_dummy = value;
        gpspi_io_barrier();
        value = staged_dummy;
        gpspi_io_barrier();
        regs->user1 = value;
    }
    unsigned int tx_length = input->mosi_len;
    gpspi_io_barrier();
    value = regs->user;
    gpspi_io_barrier();
    regs->user = (value & ~0x08000000U) | ((unsigned int)(tx_length != 0) << 27);
    if (tx_length != 0) {
        gpspi_io_barrier();
        value = regs->ms_dlen;
        gpspi_io_barrier();
        regs->ms_dlen = (value & ~0x3ffffU) | ((tx_length * 8U - 1U) & 0x3ffffU);
        unsigned int words = (tx_length + 3U) >> 2;
        unsigned int source = (unsigned int)input->mosi_data;
        for (unsigned int index = 0; index != words; ++index) {
            unsigned int chunk = tx_length < 4U ? tx_length : 4U;
            unsigned int word = 0;
            memcpy(&word,(const void *)source,chunk);
            unsigned int staged_word = *(volatile unsigned int *)&word;
            gpspi_io_barrier();
            *(volatile unsigned int *)((unsigned int)regs + 0x98U + (index << 2)) = staged_word;
            tx_length -= chunk;
            source += chunk;
        }
        rx_length = input->miso_len;
        gpspi_io_barrier();
        value = regs->user;
        gpspi_io_barrier();
        regs->user = (value & ~0x10000000U) | ((unsigned int)(rx_length != 0) << 28);
        if (rx_length != 0) {
            gpspi_io_barrier();
            value = regs->ms_dlen;
            gpspi_io_barrier();
            regs->ms_dlen = (value & ~0x3ffffU) | ((rx_length * 8U - 1U) & 0x3ffffU);
        }
    } else if (rx_length != 0) {
        gpspi_io_barrier();
        value = regs->user;
        gpspi_io_barrier();
        regs->user = value | 0x10000000U;
        gpspi_io_barrier();
        value = regs->ms_dlen;
        gpspi_io_barrier();
        regs->ms_dlen = (value & ~0x3ffffU) | ((rx_length * 8U - 1U) & 0x3ffffU);
    } else {
        gpspi_io_barrier();
        value = regs->user;
        gpspi_io_barrier();
        regs->user = value & ~0x10000000U;
    }

    gpspi_io_barrier();
    value = regs->cmd;
    gpspi_io_barrier();
    regs->cmd = value | 0x00800000U;
    do {
        gpspi_io_barrier();
        value = regs->cmd;
    } while ((value & 0x00800000U) != 0);
    gpspi_io_barrier();
    value = regs->cmd;
    void (*poll)(FlashHostView *) = context->driver->poll_cmd_done;
    gpspi_io_barrier();
    regs->cmd = value | 0x01000000U;
    poll(host);

    rx_length = input->miso_len;
    if (rx_length != 0) {
        unsigned int destination = (unsigned int)input->miso_data;
        unsigned int data = (unsigned int)regs + 0x98U;
        if (((destination | rx_length) & 3U) == 0) {
            memcpy((void *)destination,(const void *)data,rx_length);
        } else {
            unsigned int words = (rx_length + 3U) >> 2;
            for (unsigned int index = 0; index != words; ++index) {
                gpspi_io_barrier();
                unsigned int word = *(volatile unsigned int *)(data + (index << 2));
                unsigned int chunk = rx_length < 4U ? rx_length : 4U;
                memcpy((void *)destination,&word,chunk);
                destination += chunk;
                rx_length -= chunk;
            }
        }
    }
    return 0;
}
