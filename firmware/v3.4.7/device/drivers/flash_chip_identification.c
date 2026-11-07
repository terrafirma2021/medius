/* Medius v3.4.7 device: registered flash-chip probes, density and capabilities. */
#include "../include/types.h"

/* Inline reconstruction utilities preserve native byte/halfword load widths
 * within the little-endian chip ID. They add no firmware entries. */
static __inline__ __attribute__((always_inline)) unsigned int
flash_chip_density_byte(const EspFlash *chip)
{
    return *(const volatile unsigned char *)&chip->chip_id;
}
static __inline__ __attribute__((always_inline)) unsigned int
flash_chip_manufacturer_id(const EspFlash *chip)
{
    return *(const volatile unsigned short *)((const unsigned char *)&chip->chip_id + 2);
}

/* Native entry: 0x40390c7c. */
/* Original function-byte SHA-256:
 * a0462430fe607c8eb625bcfe85f110cfc43207ab93178cebce930c6c6dee1200. */
/* Ignore chip. Accept only flash_id>>16==0x009d and masked product bits
 * (flash_id&0xcf00)==0x4000. Return 0 for a match, 0x105 otherwise. The complete
 * upper halfword is compared; density and product bits outside the mask are
 * ignored. No I/O or chip-pointer read occurs. */
int spi_flash_chip_issi_probe(EspFlash *unused_chip,unsigned int flash_id)
{
    (void)unused_chip;
    return (flash_id >> 16) == 0x9dU && (flash_id & 0xcf00U) == 0x4000U ? 0 : 0x105;
}

/* Native entry: 0x403901d4. */
/* Original function-byte SHA-256:
 * baff1c8880c4efac0bee9f7a7044f87cc683c092b976b120ebf15cb144f103a0. */
/* Read the chip ID once. Low product halfword 0/0xffff writes *size=0 and
 * returns 0x6005. Otherwise use the density byte, subtract 6 when >0x19, and
 * write 1<<(exponent&31), returning 0. The mask preserves native Xtensa shift
 * behavior for malformed/large densities. No manufacturer, size, pointer or
 * exponent validation; this reports an ID-derived size without querying flash. */
int spi_flash_chip_generic_detect_size(EspFlash *chip,unsigned int *size)
{
    unsigned int id = ((const volatile EspFlash *)chip)->chip_id;
    unsigned int product = id & 0xffffU;
    if (product == 0 || product == 0xffffU) {
        *size = 0;
        return 0x6005;
    }
    unsigned int exponent = id & 0xffU;
    if (exponent > 0x19U)
        exponent -= 6U;
    *size = 1U << (exponent & 31U);
    return 0;
}

/* Native entry: 0x40390ccc. */
/* Original function-byte SHA-256:
 * cebc5d75741ee728f371bf15e6f834d1cacd50ce35b264385313c30b542ee7b7. */
/* Return the fixed unique-ID capability bit. No chip or hardware access. */
unsigned int spi_flash_chip_issi_get_caps(EspFlash *unused_chip)
{
    (void)unused_chip;
    return FLASH_CAP_UNIQUE_ID;
}

/* Native entry: 0x40390164. */
/* Original function-byte SHA-256:
 * f427e19f727cf87f333bbdaf21dafb494001bf75952e3152e6bc00a6f535844b. */
/* Ignore chip. Match upper ID halfword 0x00c8 and (id&0xdf00)==0x4000,
 * accepting product bytes 0x40/0x60. Return 0 or 0x105; no I/O or density check. */
int spi_flash_chip_gd_probe(EspFlash *unused_chip,unsigned int flash_id)
{
    (void)unused_chip;
    return (flash_id >> 16) == 0xc8U && (flash_id & 0xdf00U) == 0x4000U ? 0 : 0x105;
}

/* Native entry: 0x403900f4. */
/* Original function-byte SHA-256:
 * 3c2ef6e1278d94bba3342817eabd2fccb702413fbbcc363a29b8aeade9d685ca. */
/* Reject product halfword 0/0xffff with size zero and 0x6005. Otherwise store
 * 1<<(chip_id&31) and return 0. This uses the unadjusted density's low five
 * bits; values >=32 wrap the shift. One chip-ID load, no flash or bounds check. */
int spi_flash_chip_gd_detect_size(EspFlash *chip,unsigned int *size)
{
    unsigned int id = ((const volatile EspFlash *)chip)->chip_id;
    unsigned int product = id & 0xffffU;
    if (product == 0 || product == 0xffffU) {
        *size = 0;
        return 0x6005;
    }
    *size = 1U << (id & 31U);
    return 0;
}

/* Native entry: 0x403901c0. */
/* Original function-byte SHA-256:
 * 9130864638c7389d11e9fc9898aec52a3d2b704358d6404f822ead60fe357266. */
/* Read only the ID density byte. Advertise unique ID, plus 32MB_SUPPORT when
 * density>0x18. No suspend bit or runtime capability query; chip is unchecked. */
unsigned int spi_flash_chip_gd_get_caps(EspFlash *chip)
{
    unsigned int density = flash_chip_density_byte(chip);
    return FLASH_CAP_UNIQUE_ID |
        (density > 0x18U ? FLASH_CAP_32MB_SUPPORT : 0U);
}

/* Native entry: 0x40390d14. */
/* Original function-byte SHA-256:
 * 494ef102cb8e0dd454f46f64073c8ade410a54100382c200e4a699955b1f2e4d. */
/* First require upper ID halfword 0x00c2; only then read chip->read_mode.
 * Accept unsigned modes <=15, reject others. Return 0/0x105 without I/O,
 * product/density checks or normalization of unsupported mode values 6..15. */
int spi_flash_chip_mxic_probe(EspFlash *chip,unsigned int flash_id)
{
    if ((flash_id >> 16) != 0xc2U)
        return 0x105;
    return ((const volatile EspFlash *)chip)->read_mode <= 15U ? 0 : 0x105;
}

/* Native entry: 0x40390cd4. */
/* Original function-byte SHA-256:
 * f2f39835c71dc6117f5a4c9d50980add3d8196f1d122ad21d25413492056ec1c. */
/* Reject low product halfword 0/0xffff with *size=0 and 0x6005. Otherwise take
 * the density byte, subtract 0x20 only when >0x30, and write 1<<(exponent&31).
 * Return 0. No bounds/manufacturer validation; native shift wrapping remains. */
int spi_flash_chip_mxic_detect_size(EspFlash *chip,unsigned int *size)
{
    unsigned int id = ((const volatile EspFlash *)chip)->chip_id;
    unsigned int product = id & 0xffffU;
    if (product == 0 || product == 0xffffU) {
        *size = 0;
        return 0x6005;
    }
    unsigned int exponent = id & 0xffU;
    if (exponent > 0x30U)
        exponent -= 0x20U;
    *size = 1U << (exponent & 31U);
    return 0;
}

/* Native entry: 0x40390d34. */
/* Original function-byte SHA-256:
 * 92c9598ac7519d458b9e367d0d7b28064c9bff38bae50b088825d1dda27f16a4. */
/* Return zero capability flags, ignoring the chip pointer. */
unsigned int spi_flash_chip_mxic_get_caps(EspFlash *unused_chip)
{
    (void)unused_chip;
    return 0;
}

/* Native entry: 0x40391548. */
/* Original function-byte SHA-256:
 * 824a4f36bfee72109ce19f494739bbc4d56f6fddb153953bc6ded9c02fab8518. */
/* Match only the complete upper ID halfword against 0x00ef. Ignore chip and
 * the lower halfword. Return 0/0x105 without any hardware access. */
int spi_flash_chip_winbond_probe(EspFlash *unused_chip,unsigned int flash_id)
{
    (void)unused_chip;
    return (flash_id >> 16) == 0xefU ? 0 : 0x105;
}

/* Native entry: 0x40391560. */
/* Original function-byte SHA-256:
 * 9130864638c7389d11e9fc9898aec52a3d2b704358d6404f822ead60fe357266. */
/* One density-byte load; return UNIQUE_ID plus 32MB_SUPPORT iff density>=0x19.
 * This build advertises no suspend bit and performs no hardware verification. */
unsigned int spi_flash_chip_winbond_get_caps(EspFlash *chip)
{
    unsigned int density = flash_chip_density_byte(chip);
    return FLASH_CAP_UNIQUE_ID |
        (density > 0x18U ? FLASH_CAP_32MB_SUPPORT : 0U);
}

/* Native entry: 0x403900cc. */
/* Original function-byte SHA-256:
 * 208309edacf5298113893fc51c12ae366032fc7f37e5bcec22544650ff29a46d. */
/* Ignore chip. Require upper ID halfword 0x0068 and product byte 0x40.
 * Density is ignored. Return 0 for a match, 0x105 otherwise; no I/O. */
int spi_flash_chip_boya_probe(EspFlash *unused_chip,unsigned int flash_id)
{
    (void)unused_chip;
    return (flash_id >> 16) == 0x68U && (flash_id & 0xff00U) == 0x4000U ? 0 : 0x105;
}

/* Native entry: 0x403900ec. */
/* Original function-byte SHA-256:
 * cebc5d75741ee728f371bf15e6f834d1cacd50ce35b264385313c30b542ee7b7. */
/* Return fixed UNIQUE_ID capability, without reading chip. */
unsigned int spi_flash_chip_boya_get_caps(EspFlash *unused_chip)
{
    (void)unused_chip;
    return FLASH_CAP_UNIQUE_ID;
}

/* Native entry: 0x403912d8. */
/* Original function-byte SHA-256:
 * 83c41dbdc353236a66672b2c52551baebe91834594250468f9c07a1986772b31. */
/* Ignore chip. Require upper ID halfword 0x00cd and product byte 0x60.
 * Return 0/0x105; density, pointer validity and hardware are not examined. */
int spi_flash_chip_th_probe(EspFlash *unused_chip,unsigned int flash_id)
{
    (void)unused_chip;
    return (flash_id >> 16) == 0xcdU && (flash_id & 0xff00U) == 0x6000U ? 0 : 0x105;
}

/* Native entry: 0x403912f8. */
/* Original function-byte SHA-256:
 * cebc5d75741ee728f371bf15e6f834d1cacd50ce35b264385313c30b542ee7b7. */
/* Return fixed UNIQUE_ID capability, without reading chip. */
unsigned int spi_flash_chip_th_get_caps(EspFlash *unused_chip)
{
    (void)unused_chip;
    return FLASH_CAP_UNIQUE_ID;
}

/* Native entry: 0x403912ac. */
/* Original function-byte SHA-256:
 * a325963414c31e71d977e49ecd32e4c289629fa31867c68e94bd81ad11abf3d0. */
/* Require upper ID halfword 0x00c2, then read unsigned read_mode and accept
 * any value >15. This does not restrict the mode to valid octal values 16/17.
 * Return 0/0x105; no chip access on manufacturer mismatch, no hardware I/O. */
int spi_flash_chip_mxic_opi_probe(EspFlash *chip,unsigned int flash_id)
{
    if ((flash_id >> 16) != 0xc2U)
        return 0x105;
    return ((const volatile EspFlash *)chip)->read_mode > 15U ? 0 : 0x105;
}

/* Native entry: 0x40390d3c. */
/* Original function-byte SHA-256:
 * 0c1a3d0fe5db86bbff315d4616c30ba4b2326b556a00c081d23e4e79a31bc794. */
/* Same unadjusted density calculation as GD: reject product 0/0xffff with
 * output zero/0x6005, otherwise store 1<<(chip_id&31) and return 0. No octal
 * mode, manufacturer, capacity-range or pointer validation is performed here. */
int spi_flash_chip_mxic_opi_detect_size(EspFlash *chip,unsigned int *size)
{
    unsigned int id = ((const volatile EspFlash *)chip)->chip_id;
    unsigned int product = id & 0xffffU;
    if (product == 0 || product == 0xffffU) {
        *size = 0;
        return 0x6005;
    }
    *size = 1U << (id & 31U);
    return 0;
}

/* Native entry: 0x403912c8. */
/* Original function-byte SHA-256:
 * a0a4dc14817060d93ac40e7f5fcb491e942f8c8e0d79f35313475348f6f37b9d. */
/* Return fixed 32MB_SUPPORT only; no chip read or hardware capability probe. */
unsigned int spi_flash_chip_mxic_opi_get_caps(EspFlash *unused_chip)
{
    (void)unused_chip;
    return FLASH_CAP_32MB_SUPPORT;
}

/* Native entry: 0x403906e0. */
/* Original function-byte SHA-256:
 * 92c9598ac7519d458b9e367d0d7b28064c9bff38bae50b088825d1dda27f16a4. */
/* Catch-all probe: return 0 without reading either argument or hardware. */
int spi_flash_chip_generic_probe(EspFlash *unused_chip,unsigned int unused_id)
{
    (void)unused_chip;
    (void)unused_id;
    return 0;
}

/* Native entry: 0x40390358. */
/* Original function-byte SHA-256:
 * 0a78b9e7acf1512adae0f73d988d0b29bdb9b7a11fbd3f5a413470b84865788c. */
/* Read the ID's upper halfword. Manufacturer 0x0046 advertises suspend directly.
 * For 0x0020 only, zero a 28-byte transaction and the first response byte, issue SFDP read
 * 0x5a at address 0x32 with 24 address bits, eight dummy cycles and one RX byte.
 * Use the live chip host/common-command slot; discard its result. Response
 * bit 3 supplies suspend, even on command failure, and the manufacturer is then
 * reloaded. A final manufacturer 0x00a1 also sets suspend. UNIQUE_ID is always
 * advertised; 32MB_SUPPORT is never set. The native response word's unused
 * upper bytes are uninitialized and do not contribute to bit 3. Sample the
 * response with the native WORD load before reloading the manufacturer.
 * No validation, retry, timeout or lock. */
unsigned int spi_flash_chip_generic_get_caps(EspFlash *chip)
{
    const volatile EspFlash *context = chip;
    unsigned int manufacturer = flash_chip_manufacturer_id(chip);
    unsigned int suspend = manufacturer == 0x46U ? FLASH_CAP_SUSPEND : 0U;
    if (manufacturer == 0x20U) {
        unsigned int response;
        *(volatile unsigned char *)&response = 0;
        FlashTransaction transaction = {0};
        transaction.dummy_bitlen = 8;
        FlashHostView *host = context->host;
        transaction.miso_len = 1;
        transaction.address_bitlen = 24;
        const volatile FlashHostDriverView *driver =
            ((const volatile FlashHostView *)host)->driver;
        int (*common_command)(FlashHostView *,FlashTransaction *) = driver->common_command;
        transaction.address = 0x32;
        transaction.miso_data = (unsigned char *)&response;
        transaction.command = 0x5a;
        common_command(host,&transaction);
        unsigned int response_word = *(volatile unsigned int *)&response;
        suspend = (response_word >> 3) & 1U;
        manufacturer = flash_chip_manufacturer_id(chip);
    }
    return FLASH_CAP_UNIQUE_ID | suspend |
        (manufacturer == 0xa1U ? FLASH_CAP_SUSPEND : 0U);
}
