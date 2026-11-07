/* Medius v3.4.7 device: chip status registers, quad/octal modes and suspend setup. */
#include "../include/types.h"

/* Inline reconstruction utilities recover the SDK's inlined transaction
 * builders. They add no native entries. A status read always stores the entire
 * zero-initialized response word, even when the command callback fails. */
static __inline__ __attribute__((always_inline)) int
flash_status_read(EspFlash *chip,unsigned short command,unsigned char bytes,unsigned int *status)
{
    FlashHostView *host = ((const volatile EspFlash *)chip)->host;
    unsigned int response = 0;
    FlashTransaction transaction = {0};
    transaction.miso_len = bytes;
    const volatile FlashHostDriverView *driver = ((const volatile FlashHostView *)host)->driver;
    int (*common)(FlashHostView *,FlashTransaction *) = driver->common_command;
    transaction.miso_data = (unsigned char *)&response;
    transaction.command = command;
    int result = common(host,&transaction);
    *status = *(volatile unsigned int *)&response;
    return result;
}
static __inline__ __attribute__((always_inline)) int
flash_status_write(EspFlash *chip,unsigned short command,unsigned char bytes,unsigned int status)
{
    FlashHostView *host = ((const volatile EspFlash *)chip)->host;
    unsigned int payload = status;
    FlashTransaction transaction = {0};
    transaction.mosi_len = bytes;
    const volatile FlashHostDriverView *driver = ((const volatile FlashHostView *)host)->driver;
    int (*common)(FlashHostView *,FlashTransaction *) = driver->common_command;
    transaction.mosi_data = &payload;
    transaction.command = command;
    return common(host,&transaction);
}

/* Native entry: 0x40390c9c. */
/* Original function-byte SHA-256:
 * b49f6a5050b42a2faf3dfab1febf486ca63ed71dcecacdd62ed0686215906e28. */
/* Delegate to the shared quad-mode updater using one-byte WRSR/RDSR and QE
 * bit 6. Return its status unchanged. The updater decides whether to write. */
int spi_flash_chip_issi_set_io_mode(EspFlash *chip)
{
    return spi_flash_common_set_io_mode(chip,spi_flash_common_write_status_8b_wrsr,
        spi_flash_common_read_status_8b_rdsr,0x40U);
}

/* Native entry: 0x40390cb0. */
/* Original function-byte SHA-256:
 * d3cc1d2630a956d438bc6de736b9c7c452785910744cd27cb19cdb1a36b67f6d. */
/* Read RDSR through the status helper. On success only, store 4 (quad output)
 * when bit 6 is set, otherwise 0. Propagate errors without touching *mode.
 * No mode write, pointer validation or retry occurs. */
int spi_flash_chip_issi_get_io_mode(EspFlash *chip,unsigned int *mode)
{
    unsigned int status;
    int result = spi_flash_common_read_status_8b_rdsr(chip,&status);
    if (result == 0)
        *mode = ((status >> 6) & 1U) << 2;
    return result;
}

/* Native entry: 0x403903bc. */
/* Original function-byte SHA-256:
 * 70d4804774e13921991d3a5bd9d74bacf674c2c1b9a0dd05f9813b6b5339ce87. */
/* Pass an eight-byte stack configuration to the live host driver sus_setup
 * slot: mask 0x80, status opcode 0x35, suspend 0x75, resume 0x7a, reserved 0.
 * Cache chip->host once and return callback status. No validation or I/O here
 * beyond the selected callback; no independent suspend/resume command is sent. */
int spi_flash_chip_generic_suspend_cmd_conf(EspFlash *chip)
{
    FlashSuspendCommands commands;
    commands.read_status_command = 0x35;
    commands.suspend_command = 0x75;
    commands.resume_command = 0x7a;
    commands.reserved = 0;
    FlashHostView *host = ((const volatile EspFlash *)chip)->host;
    int (*setup)(FlashHostView *,const FlashSuspendCommands *) =
        ((const volatile FlashHostView *)host)->driver->sus_setup;
    commands.mask = 0x80;
    return setup(host,&commands);
}

/* Native entry: 0x40390184. */
/* Original function-byte SHA-256:
 * 4bee8809f3465795780d468d84a7902e1823092f0afbb605421362073e7bb39b. */
/* One chip-ID load selects status-register conventions. Product byte 0x60 or
 * density<=0x15 uses two-byte WRSR, combined RDSR2/RDSR and QE bit 9. Otherwise
 * use one-byte WRSR2/RDSR2 and QE bit 1. Return the shared updater's status.
 * No manufacturer check or direct command dispatch occurs in this wrapper. */
int spi_flash_chip_gd_set_io_mode(EspFlash *chip)
{
    unsigned int id = ((const volatile EspFlash *)chip)->chip_id;
    if ((id & 0xff00U) == 0x6000U || (id & 0xffU) <= 0x15U)
        return spi_flash_common_set_io_mode(chip,spi_flash_common_write_status_16b_wrsr,
            spi_flash_common_read_status_16b_rdsr_rdsr2,0x200U);
    return spi_flash_common_set_io_mode(chip,spi_flash_common_write_status_8b_wrsr2,
        spi_flash_common_read_status_8b_rdsr2,2U);
}

/* Native entry: 0x40390148. */
/* Original function-byte SHA-256:
 * c2ad67281978cd0a11f050893c225efc87004776aaa07f532a4827b9023aee30. */
/* Read RDSR2, then on success only store 4 iff status bit 1 is set, else 0.
 * Propagate status-helper errors and leave output untouched on error. */
int spi_flash_chip_gd_get_io_mode(EspFlash *chip,unsigned int *mode)
{
    unsigned int status;
    int result = spi_flash_common_read_status_8b_rdsr2(chip,&status);
    if (result == 0)
        *mode = ((status >> 1) & 1U) << 2;
    return result;
}

/* Native entry: 0x40390128. */
/* Original function-byte SHA-256:
 * 3a829237c34f66ce606ea91d5ca800dbcc536f95f3dd10fcd7ea9ad3ef797bb0. */
/* Same command bytes as generic suspend setup, but mask 0x84. Pass the stack
 * object to the cached host's live sus_setup callback and return its status.
 * No pointer/callback validation, hardware wait or own lock is supplied. */
int spi_flash_chip_gd_suspend_cmd_conf(EspFlash *chip)
{
    FlashSuspendCommands commands;
    commands.read_status_command = 0x35;
    commands.suspend_command = 0x75;
    commands.resume_command = 0x7a;
    commands.reserved = 0;
    FlashHostView *host = ((const volatile EspFlash *)chip)->host;
    int (*setup)(FlashHostView *,const FlashSuspendCommands *) =
        ((const volatile FlashHostView *)host)->driver->sus_setup;
    commands.mask = 0x84;
    return setup(host,&commands);
}

/* Native entry: 0x403906c8. */
/* Original function-byte SHA-256:
 * 5cc52486c01a6f55688a63091bf1a54890d66548b32c6a79abff0c80761f4be8. */
/* Delegate to the common quad updater using two-byte WRSR, RDSR2/RDSR and QE
 * bit 9. Return its status; do not independently change the requested mode. */
int spi_flash_chip_generic_set_io_mode(EspFlash *chip)
{
    return spi_flash_common_set_io_mode(chip,spi_flash_common_write_status_16b_wrsr,
        spi_flash_common_read_status_16b_rdsr_rdsr2,0x200U);
}

/* Native entry: 0x40390a74. */
/* Original function-byte SHA-256:
 * 2e5ad1abeec0689465f7ce1677d71185dac2355a22a6192246529bf11f4310cb. */
/* Issue one-byte RDSR2 (0x35) into a zeroed response word. Read that word even
 * on callback error, but store *mode only on success: bit 1 maps to 4 or 0.
 * Return command status unchanged; no retry, pointer check or own locking. */
int spi_flash_chip_generic_get_io_mode(EspFlash *chip,unsigned int *mode)
{
    unsigned int status;
    int result = flash_status_read(chip,0x35,1,&status);
    if (result == 0)
        *mode = ((status >> 1) & 1U) << 2;
    return result;
}

/* Native entry: 0x403912d0. */
/* Original function-byte SHA-256:
 * 92c9598ac7519d458b9e367d0d7b28064c9bff38bae50b088825d1dda27f16a4. */
/* Return 0 without reading chip, configuring octal mode or issuing commands. */
int spi_flash_chip_mxic_opi_set_io_mode(EspFlash *unused_chip)
{
    (void)unused_chip;
    return 0;
}

/* Native entry: 0x40391230. */
/* Original function-byte SHA-256:
 * d050484846f125b22f2b1acf8d2cc6884312a5cd24cde98e1d5b45e71665bb2e. */
/* Cache read_mode and assert it is exactly 16 or 17; failure calls the native
 * assertion routine with four zero arguments. Read configuration via opcode
 * 0x8e71, 32 address bits/address 0: STR requests one RX byte/four dummy cycles,
 * DTR two RX bytes/eight dummy cycles. Command failure leaves output untouched.
 * On success decode the first byte: 1->16, 2->17, other->0. Store that result
 * first, then reload chip->read_mode and store 0 on mismatch, or the decoded
 * value on match. Retain both stores and their aliasing when mode points at
 * chip->read_mode. Mismatch is not an error; return 0. No validation or retry. */
int spi_flash_chip_mxic_opi_get_io_mode(EspFlash *chip,unsigned int *mode)
{
    const volatile EspFlash *context = chip;
    unsigned int initial_mode = context->read_mode;
    unsigned int response = 0;
    if (initial_mode - 16U >= 2U)
        __assert_func((const char *)0,0,(const char *)0,(const char *)0);
    unsigned int dummy = initial_mode == 16U ? 4U : 8U;
    unsigned int length = initial_mode == 16U ? 1U : 2U;
    FlashTransaction transaction = {0};
    FlashHostView *host = context->host;
    transaction.dummy_bitlen = (unsigned char)dummy;
    transaction.miso_len = (unsigned char)length;
    transaction.address_bitlen = 32;
    int (*common)(FlashHostView *,FlashTransaction *) =
        ((const volatile FlashHostView *)host)->driver->common_command;
    transaction.miso_data = (unsigned char *)&response;
    transaction.command = 0x8e71;
    int result = common(host,&transaction);
    if (result != 0)
        return result;
    unsigned int first_byte = *(volatile unsigned char *)&response;
    unsigned int decoded = first_byte == 1 ? 16U : first_byte == 2 ? 17U : 0U;
    volatile unsigned int *output = mode;
    *output = decoded;
    unsigned int current_mode = context->read_mode;
    *output = current_mode == decoded ? decoded : 0U;
    return 0;
}

/* Native entry: 0x40390b5c. */
/* Original function-byte SHA-256:
 * ba5f85d905702f643611b2bf3a6ba85e199a7a289d807d8d124f6c943daebad2. */
/* Send RDSR 0x05 with one RX byte into a zeroed word; always write the complete
 * response word to *status, including on error. Return callback status. No
 * busy-bit polling, output validation or write-enable operation is added. */
int spi_flash_common_read_status_8b_rdsr(EspFlash *chip,unsigned int *status)
{
    return flash_status_read(chip,5,1,status);
}

/* Native entry: 0x40390b90. */
/* Original function-byte SHA-256:
 * 1045c94a58195ed54ae0a7c0c274910419b3bb1ef3bc9a1cf8fd16cdcc5b5268. */
/* Send WRSR 0x01 with the low byte of a stack copy of status. Return command
 * status. No write-enable, idle wait, readback or protection restoration here. */
int spi_flash_common_write_status_8b_wrsr(EspFlash *chip,unsigned int status)
{
    return flash_status_write(chip,1,1,status);
}

/* Native entry: 0x40390ab0. */
/* Original function-byte SHA-256:
 * 4bc6a41514c6cac683570c8d4e275d25aaf7566afa7cbd2486e7412ae9f84d42. */
/* Read RDSR2 0x35 first, then RDSR 0x05 only if the first command succeeds.
 * Reload chip->host/driver for the second transaction. Each command uses a
 * zeroed response word; both are sampled before their error branches. Store
 * low RDSR byte | low RDSR2 byte<<8 only when both succeed. On either error
 * leave *status untouched and return it. No readiness polling or own lock. */
int spi_flash_common_read_status_16b_rdsr_rdsr2(EspFlash *chip,unsigned int *status)
{
    unsigned int status2;
    int result = flash_status_read(chip,0x35,1,&status2);
    if (result != 0)
        return result;
    unsigned int status1;
    result = flash_status_read(chip,5,1,&status1);
    if (result == 0)
        *status = (status1 & 0xffU) | ((status2 & 0xffU) << 8);
    return result;
}

/* Native entry: 0x40390a44. */
/* Original function-byte SHA-256:
 * 806082e9efaa1d40d31b0483c66e36922fb4a378e096f5366e8af6c9c6536b02. */
/* Send WRSR 0x01 with the low two bytes of a stack status word. Return callback
 * status directly; no write-enable, idle wait, byte swap or readback here. */
int spi_flash_common_write_status_16b_wrsr(EspFlash *chip,unsigned int status)
{
    return flash_status_write(chip,1,2,status);
}

/* Native entry: 0x40390b28. */
/* Original function-byte SHA-256:
 * 67288da0c7f0820c300bb71d7f971531f49059a850447b8658e58406bed7f3f7. */
/* Send RDSR2 0x35 with one RX byte. Always store the whole zero-initialized
 * response word even on command failure; propagate its status. */
int spi_flash_common_read_status_8b_rdsr2(EspFlash *chip,unsigned int *status)
{
    return flash_status_read(chip,0x35,1,status);
}

/* Native entry: 0x40390bc0. */
/* Original function-byte SHA-256:
 * fd8b4ab67714678a58f996a78aff90d4987db1b49676f789e0a9c7bde44f681f. */
/* Send WRSR2 0x31 with one byte from a stack status word. Propagate callback
 * status; no write-enable, wait, readback or status-bit mask is supplied here. */
int spi_flash_common_write_status_8b_wrsr2(EspFlash *chip,unsigned int status)
{
    return flash_status_write(chip,0x31,1,status);
}

/* Native entry: 0x40390bf0. */
/* Original function-byte SHA-256:
 * 2df00af86c12ed9e4d35eece0c4d8c8bc9512ace47ccf91d17bda03ee4c32df2. */
/* Read requested mode once. Modes other than 4/5 return 0 without calling the
 * supplied helpers. In a quad mode, read status; errors return immediately and
 * an already-set QE mask (including mask 0) returns 0. Otherwise request write
 * enable via the live chip driver, ignoring that result, then write status|mask.
 * A write error requests write protection via the driver captured after that
 * write, ignores restoration status and returns the original write error.
 * After a successful write use that captured driver's idle timeout/callback.
 * Wait result 0x106 restores protection through a freshly loaded driver and
 * still proceeds to readback; other nonzero wait errors return directly.
 * Read back through the original read helper. Require equality of the entire
 * status word, not only QE bits: mismatch returns 0x108. No rollback on read
 * failure/mismatch, routine success protection restore, pointer checks or lock. */
int spi_flash_common_set_io_mode(EspFlash *chip,FlashWriteStatusOperation write_status,
    FlashReadStatusOperation read_status,unsigned int qe_mask)
{
    const volatile EspFlash *context = chip;
    unsigned int mode = context->read_mode;
    if (mode - 4U >= 2U)
        return 0;
    unsigned int status;
    int result = read_status(chip,&status);
    if (result != 0)
        return result;
    unsigned int updated = status | qe_mask;
    if ((status & qe_mask) == qe_mask)
        return 0;
    context->chip_driver->set_chip_write_protect(chip,false);
    result = write_status(chip,updated);
    const volatile FlashChipDriverView *driver = context->chip_driver;
    if (result != 0) {
        driver->set_chip_write_protect(chip,true);
        return result;
    }
    const volatile FlashTimeouts *timeouts = driver->timeout;
    int (*wait_idle)(EspFlash *,unsigned int) = driver->wait_idle;
    unsigned int timeout = timeouts->idle_timeout;
    result = wait_idle(chip,timeout);
    if (result == 0x106)
        context->chip_driver->set_chip_write_protect(chip,true);
    else if (result != 0)
        return result;
    result = read_status(chip,&status);
    if (result != 0)
        return result;
    return status == updated ? 0 : 0x108;
}

/* Native entry: 0x40390948. */
/* Original function-byte SHA-256:
 * bd309e94530854c14a959e9bcd8359553e1dcc184aec0ea9aea7ae7192c9d524. */
/* Ignore reg_id and dispatch host->driver->read_status directly. The output is
 * passed as a BYTE pointer: only its low byte is supplied to that callback;
 * this wrapper does not clear the upper three bytes of *out_reg. Return callback
 * status without pointer/register validation, retry or independent I/O. */
int spi_flash_chip_generic_read_reg(EspFlash *chip,unsigned int unused_reg_id,unsigned int *out_reg)
{
    (void)unused_reg_id;
    FlashHostView *host = ((const volatile EspFlash *)chip)->host;
    return ((const volatile FlashHostView *)host)->driver->read_status(host,(unsigned char *)out_reg);
}

/* Native entry: 0x40390b20. */
/* Original function-byte SHA-256:
 * 47f4a5a620aba814440cfaf6a1ad1852ea9a3dc52d642e04d909ce5361a9ecef. */
/* Return 0x106 (unsupported), without reading chip or modifying unique_id. */
int spi_flash_chip_mxic_read_unique_id(EspFlash *unused_chip,unsigned long long *unused_unique_id)
{
    (void)unused_chip;
    (void)unused_unique_id;
    return 0x106;
}
