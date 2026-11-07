/* Medius v3.4.7 host: MSPI I/O-mode configuration and common transactions. */
#include "../include/types.h"

/* Inline reconstruction utilities retain explicit native barriers.
 * The barrier helper adds no firmware entry. */
static __inline__ __attribute__((always_inline)) void mspi_io_barrier(void)
{
    __asm__ volatile ("memw" ::: "memory");
}

/* Native entry: 0x40385030. */
/* Original function-byte SHA-256:
 * 6474dcdbd967866b29b686f878e75fafbd8a628e577b9c0e6484f23491728a2e. */
/* Cache MSPI registers. Set CTRL dummy-output bit 3 from io_mode bit 31 and
 * set CTRL bits 18/19 through separate RMWs. Always enable the command phase;
 * write command's low 16 bits, then freshly reread USER2 and select 16 command
 * bits for command>255 or eight otherwise. Both updates retain volatile stack
 * staging. Unlike GPSPI, the 16-bit phase keeps the complete command halfword.
 * CACHE_FCTRL bit 1 is set only for address_bits==32; USER1 encodes length-1
 * modulo 64 and USER ADDR follows nonzero length. Add extra_dummy modulo 32
 * bits, enable DUMMY iff the sum is nonzero, and encode cycles-1 modulo 64.
 * Separately disable and zero both data phases/length fields. Stage CTRL read
 * mode, clear DDR bit 0, and set FASTRD before applying low mode 0/1/2/3/4/5
 * (slow/fast/dual-out/dual-I/O/quad-out/quad-I/O) or 16/17 (octal STR/DTR).
 * DTR re-enables DDR bit 0. Unsupported modes abort after earlier MMIO writes
 * but before committing staged CTRL. Preserve all native staged reads/writes
 * and barriers. Return 0 normally; no validation, readiness wait or own lock. */
int spi_flash_hal_configure_host_io_mode(FlashHostView *host,
    unsigned int command,unsigned int address_bits,int dummy_base,unsigned int io_mode)
{
    const volatile FlashHostView *context = host;
    volatile MspiRegisters *regs = (volatile MspiRegisters *)context->spi;
    mspi_io_barrier();
    unsigned int value = regs->ctrl;
    mspi_io_barrier();
    regs->ctrl = (value & ~8U) | ((io_mode >> 31) << 3);
    mspi_io_barrier();
    value = regs->ctrl;
    mspi_io_barrier();
    regs->ctrl = value | 0x40000U;
    mspi_io_barrier();
    value = regs->ctrl;
    mspi_io_barrier();
    regs->ctrl = value | 0x80000U;
    unsigned int mode = io_mode & 0xffffU;
    bool long_command = command > 255U;
    mspi_io_barrier();
    value = regs->user;
    mspi_io_barrier();
    regs->user = value | 0x80000000U;
    mspi_io_barrier();
    value = regs->user2;
    mspi_io_barrier();
    volatile unsigned int staged_command = value;
    mspi_io_barrier();
    value = staged_command;
    value = (value & 0xffff0000U) | (command & 0xffffU);
    mspi_io_barrier();
    staged_command = value;
    mspi_io_barrier();
    value = staged_command;
    mspi_io_barrier();
    regs->user2 = value;
    mspi_io_barrier();
    value = regs->user2;
    mspi_io_barrier();
    volatile unsigned int staged_command_length = value;
    mspi_io_barrier();
    value = staged_command_length;
    value = long_command ? value | 0xf0000000U : (value & 0x0fffffffU) | 0x70000000U;
    mspi_io_barrier();
    staged_command_length = value;
    mspi_io_barrier();
    value = staged_command_length;
    mspi_io_barrier();
    regs->user2 = value;

    mspi_io_barrier();
    value = regs->cache_fctrl;
    mspi_io_barrier();
    regs->cache_fctrl = (value & ~2U) | ((unsigned int)(address_bits == 32U) << 1);
    mspi_io_barrier();
    value = regs->user1;
    mspi_io_barrier();
    regs->user1 = (value & 0x03ffffffU) | ((address_bits - 1U) << 26);
    mspi_io_barrier();
    value = regs->user;
    mspi_io_barrier();
    regs->user = (value & ~0x40000000U) | ((unsigned int)(address_bits != 0) << 30);
    unsigned int extra_dummy = context->extra_dummy;
    mspi_io_barrier();
    value = regs->user;
    unsigned int dummy_cycles = (unsigned int)dummy_base + extra_dummy;
    mspi_io_barrier();
    regs->user = (value & ~0x20000000U) | ((unsigned int)(dummy_cycles != 0) << 29);
    mspi_io_barrier();
    value = regs->user1;
    mspi_io_barrier();
    regs->user1 = (value & ~63U) | ((dummy_cycles - 1U) & 63U);
    mspi_io_barrier();
    value = regs->user;
    mspi_io_barrier();
    regs->user = value & ~0x10000000U;
    mspi_io_barrier();
    value = regs->miso_dlen;
    mspi_io_barrier();
    regs->miso_dlen = value & ~0x3ffU;
    mspi_io_barrier();
    value = regs->user;
    mspi_io_barrier();
    regs->user = value & ~0x08000000U;
    mspi_io_barrier();
    value = regs->mosi_dlen;
    mspi_io_barrier();
    regs->mosi_dlen = value & ~0x3ffU;

    mspi_io_barrier();
    value = regs->ctrl;
    mspi_io_barrier();
    volatile unsigned int staged_ctrl = value;
    mspi_io_barrier();
    value = staged_ctrl;
    mspi_io_barrier();
    staged_ctrl = value & 0xfe6fbd8fU;
    mspi_io_barrier();
    value = regs->ddr;
    mspi_io_barrier();
    regs->ddr = value & ~1U;
    mspi_io_barrier();
    value = staged_ctrl;
    mspi_io_barrier();
    staged_ctrl = value | 0x2000U;
    switch (mode) {
    case 0: /* slow single-line */
        mspi_io_barrier();
        value = staged_ctrl;
        mspi_io_barrier();
        staged_ctrl = value & ~0x2000U;
        break;
    case 1: /* fast single-line */
        break;
    case 2: /* dual output */
        mspi_io_barrier();
        value = staged_ctrl;
        mspi_io_barrier();
        staged_ctrl = value | 0x4000U;
        break;
    case 3: /* dual I/O */
        mspi_io_barrier();
        value = staged_ctrl;
        mspi_io_barrier();
        staged_ctrl = value | 0x00800000U;
        break;
    case 4: /* quad output */
        mspi_io_barrier();
        value = staged_ctrl;
        mspi_io_barrier();
        staged_ctrl = value | 0x00100000U;
        break;
    case 5: /* quad I/O */
        mspi_io_barrier();
        value = staged_ctrl;
        mspi_io_barrier();
        staged_ctrl = value | 0x01000000U;
        break;
    case 16: /* octal STR */
    case 17: /* octal DTR */
        mspi_io_barrier();
        value = staged_ctrl;
        mspi_io_barrier();
        staged_ctrl = value | 0x40U;
        mspi_io_barrier();
        value = staged_ctrl;
        mspi_io_barrier();
        staged_ctrl = value | 0x200U;
        mspi_io_barrier();
        value = staged_ctrl;
        mspi_io_barrier();
        staged_ctrl = value | 0x20U;
        mspi_io_barrier();
        value = staged_ctrl;
        mspi_io_barrier();
        staged_ctrl = value | 0x10U;
        if (mode == 17) {
            mspi_io_barrier();
            value = regs->ddr;
            mspi_io_barrier();
            regs->ddr = value | 1U;
        }
        break;
    default:
        abort();
    }
    mspi_io_barrier();
    value = staged_ctrl;
    mspi_io_barrier();
    regs->ctrl = value;
    return 0;
}

/* Native entry: 0x40385368. */
/* Original function-byte SHA-256:
 * 3781bd232f98c3791c1592437961b67b026fe41bb01a780269a3e1117090a862. */
/* Snapshot command/dummy and flags bit 1 for selecting transaction/base I/O.
 * Cache host->spi, call the live mode-configure callback and ignore its status.
 * Afterwards load and write the complete address word without GPSPI padding.
 * Initial RX length zero overrides dummy timing with the captured dummy byte
 * only. Enable MOSI from its byte length and always update its low ten length
 * bits (zero writes zero). Nonzero TX copies padded words into +0x58; lengths
 * up to 255 are accepted despite the 64-byte hardware data buffer. After TX,
 * reload RX length; with no TX retain the initial sample. Set MISO and its own
 * ten-bit length field. Reload flags bit 3 for command PE bit 17, so flags can
 * differ from the initial snapshot. Read CMD, capture the live poll callback,
 * then set USR bit 18 (and PE when requested) and call it. No UPDATE phase.
 * Reload RX length/output pointer after polling and copy via aligned ROM memcpy
 * or MEMW/word reads with partial copies. Preserve unchecked pointers, wrapping
 * buffer addresses, truncated bit counts and ignored configure status. Return
 * 0; the callback supplies any wait, with no local timeout, capacity or lock. */
int spi_flash_hal_common_command(FlashHostView *host,FlashTransaction *transaction)
{
    const volatile FlashHostView *context = host;
    const volatile FlashTransaction *input = transaction;
    unsigned int flags = input->flags;
    volatile MspiRegisters *regs = (volatile MspiRegisters *)context->spi;
    unsigned int command = input->command;
    unsigned int dummy = input->dummy_bitlen;
    unsigned int mode = (flags & 2U) != 0 ? input->io_mode : context->base_io_mode;
    unsigned int address_bits = input->address_bitlen;
    context->driver->configure_host_io_mode(host,command,address_bits,(int)dummy,mode);
    unsigned int address = input->address;
    mspi_io_barrier();
    regs->addr = address;
    unsigned int rx_length = input->miso_len;
    unsigned int value;
    if (rx_length == 0) {
        mspi_io_barrier();
        value = regs->user;
        mspi_io_barrier();
        regs->user = (value & ~0x20000000U) | ((unsigned int)(dummy != 0) << 29);
        mspi_io_barrier();
        value = regs->user1;
        mspi_io_barrier();
        regs->user1 = (value & ~63U) | ((dummy - 1U) & 63U);
    }
    unsigned int tx_length = input->mosi_len;
    mspi_io_barrier();
    value = regs->user;
    mspi_io_barrier();
    regs->user = (value & ~0x08000000U) | ((unsigned int)(tx_length != 0) << 27);
    unsigned int tx_bits = tx_length != 0 ? (tx_length * 8U - 1U) & 0x3ffU : 0;
    mspi_io_barrier();
    value = regs->mosi_dlen;
    mspi_io_barrier();
    regs->mosi_dlen = (value & ~0x3ffU) | tx_bits;
    if (tx_length != 0) {
        unsigned int words = (tx_length + 3U) >> 2;
        unsigned int source = (unsigned int)input->mosi_data;
        for (unsigned int index = 0; index != words; ++index) {
            unsigned int chunk = tx_length < 4U ? tx_length : 4U;
            unsigned int word = 0;
            memcpy(&word,(const void *)source,chunk);
            mspi_io_barrier();
            *(volatile unsigned int *)((unsigned int)regs + 0x58U + (index << 2)) = word;
            tx_length -= chunk;
            source += chunk;
        }
        rx_length = input->miso_len;
    }
    mspi_io_barrier();
    value = regs->user;
    mspi_io_barrier();
    regs->user = (value & ~0x10000000U) | ((unsigned int)(rx_length != 0) << 28);
    unsigned int rx_bits = rx_length != 0 ? (rx_length * 8U - 1U) & 0x3ffU : 0;
    mspi_io_barrier();
    value = regs->miso_dlen;
    mspi_io_barrier();
    regs->miso_dlen = (value & ~0x3ffU) | rx_bits;
    flags = input->flags;
    mspi_io_barrier();
    value = regs->cmd;
    const volatile FlashHostDriverView *driver = context->driver;
    unsigned int user_command = (flags & 8U) != 0 ? 0x60000U : 0x40000U;
    void (*poll)(FlashHostView *) = driver->poll_cmd_done;
    mspi_io_barrier();
    regs->cmd = value | user_command;
    poll(host);

    rx_length = input->miso_len;
    if (rx_length != 0) {
        unsigned int destination = (unsigned int)input->miso_data;
        unsigned int data = (unsigned int)regs + 0x58U;
        if (((destination | rx_length) & 3U) == 0) {
            memcpy((void *)destination,(const void *)data,rx_length);
        } else {
            unsigned int words = (rx_length + 3U) >> 2;
            for (unsigned int index = 0; index != words; ++index) {
                mspi_io_barrier();
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
