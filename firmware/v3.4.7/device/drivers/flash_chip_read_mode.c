/* Medius v3.4.7 device: generic chip read-command and dummy-cycle selection. */
#include "../include/types.h"

/* Native entry: 0x40390214. */
/* Original function-byte SHA-256:
 * 6f0c01add6f45fb4b76fdb2299fc35fe48a64c79e581b7763bff7dbe7c555f46. */
/* Cache the full read_mode word; its low halfword must be 0..5, otherwise return
 * 0x6003 without reading flags/profiles/host or calling the HAL. Config flags bit
 * 0 selects 32 instead of 24 address bits and the corresponding opcode:
 * slow 03/13, fast 0b/0c, dual-out 3b/3c, dual-I/O bb/bc, quad-out 6b/6c,
 * quad-I/O eb/ec. Other config bits are unused. Read chip flags once; bit 1
 * selects the live high-performance dummy-profile pointer, otherwise normal.
 * Load exactly one profile byte for the selected mode. Set read_mode bit 31
 * for dual/quad I/O, retaining all other original high bits. Reload host and its
 * configure callback, pass command/address bits/dummy/full mode, and return its
 * status. No profile/pointer/range validation, hardware transaction or own wait. */
int spi_flash_chip_generic_config_host_io_mode(EspFlash *chip,unsigned int flags)
{
    const volatile EspFlash *context = chip;
    unsigned int read_mode = context->read_mode;
    unsigned int mode = read_mode & 0xffffU;
    unsigned int address32 = flags & 1U;
    unsigned int command;
    unsigned int dummy_offset;
    switch (mode) {
    case 0:
        command = address32 != 0 ? 0x13U : 0x03U;
        dummy_offset = __builtin_offsetof(FlashDummyCycles,slow_read);
        break;
    case 1:
        command = address32 != 0 ? 0x0cU : 0x0bU;
        dummy_offset = __builtin_offsetof(FlashDummyCycles,fast_read);
        break;
    case 2:
        command = address32 != 0 ? 0x3cU : 0x3bU;
        dummy_offset = __builtin_offsetof(FlashDummyCycles,dual_output);
        break;
    case 3:
        command = address32 != 0 ? 0xbcU : 0xbbU;
        dummy_offset = __builtin_offsetof(FlashDummyCycles,dual_io);
        break;
    case 4:
        command = address32 != 0 ? 0x6cU : 0x6bU;
        dummy_offset = __builtin_offsetof(FlashDummyCycles,quad_output);
        break;
    case 5:
        command = address32 != 0 ? 0xecU : 0xebU;
        dummy_offset = __builtin_offsetof(FlashDummyCycles,quad_io);
        break;
    default:
        return 0x6003;
    }
    unsigned int chip_flags = context->flags;
    const volatile FlashDummyCycles *profile = (chip_flags & 2U) != 0 ?
        FLASH_DUMMY_CYCLES_HIGH_PERFORMANCE : FLASH_DUMMY_CYCLES_NORMAL;
    unsigned int dummy = *((const volatile unsigned char *)profile + dummy_offset);
    if (mode == 3 || mode == 5)
        read_mode |= 0x80000000U;
    FlashHostView *host = context->host;
    return ((const volatile FlashHostView *)host)->driver->configure_host_io_mode(
        host,command,address32 != 0 ? 32U : 24U,(int)dummy,read_mode);
}

/* Native entry: 0x40390f7c. */
/* Original function-byte SHA-256:
 * ab48889f2821398cf98786f2ff5b84f4eb1fb12b3804752a1d529cadbe5f9506. */
/* Cache the full read-mode word; select by its low halfword. Mode 16 (STR)
 * passes command 0x13ec and dummy count 20; mode 17 (DTR) passes 0x11ee and
 * dummy count 40. Both use 32 address bits and preserve every original mode
 * high bit in the fifth callback argument. Any other low mode returns 0x6003
 * before reading host/driver. Ignore configuration flags. Reload host/driver,
 * invoke configure_host_io_mode and return its status. No dummy-profile read,
 * hardware transaction, mode writeback, pointer validation or separate wait. */
int spi_flash_chip_mxic_opi_config_host_io_mode(EspFlash *chip,unsigned int flags)
{
    (void)flags;
    const volatile EspFlash *context = chip;
    unsigned int read_mode = context->read_mode;
    unsigned int mode = read_mode & 0xffffU;
    unsigned int command;
    int dummy;
    if (mode == 16) {
        command = 0x13ec;
        dummy = 20;
    } else if (mode == 17) {
        command = 0x11ee;
        dummy = 40;
    } else {
        return 0x6003;
    }
    FlashHostView *host = context->host;
    return ((const volatile FlashHostView *)host)->driver->configure_host_io_mode(
        host,command,32,dummy,read_mode);
}
