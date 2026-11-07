/* Medius v3.4.7 host: recovered eFuse readback and chip/block revision. */

#include "../include/types.h"

/* Native entry: 0x4037603c. */
/* Original function-byte SHA-256:
 * 1e89d5ba2c1e740b5761eabe7b73e5843e9d8434fff889881dedfb776c2a74c0. */
/*
 * Calls major-chip reader, then minor-chip reader, returning major*100+minor.
 * These are separate readback sequences; no shared snapshot or lock joins
 * them. Does not read disable-version flags or validate revision support.
 */
unsigned int efuse_hal_chip_revision(void)
{
    unsigned int major = efuse_hal_get_major_chip_version();
    unsigned int minor = efuse_hal_get_minor_chip_version();
    return major * 100U + minor;
}

/* Native entry: 0x40376054. */
/* Original function-byte SHA-256:
 * 665278db496f7fa6b78abdc79bfd5a602d523943f252c50df775bccd27589d42. */
/*
 * MEMW/reads SYS_PART1_DATA4, then MEMW/reads MAC_SPI_SYS3, returning
 * (first WORD bits0..1)*100 + (second WORD bits24..26). No repeated snapshot,
 * disable-version flag test, hardware programming or validation is supplied.
 */
unsigned int efuse_hal_blk_version(void)
{
    memw();
    unsigned int major_word = EFUSE_READ_REGISTERS->sys_part1_data4;
    memw();
    unsigned int minor_word = EFUSE_READ_REGISTERS->mac_spi_sys3;
    return (major_word & 3U) * 100U + ((minor_word >> 24) & 7U);
}

/* Native entry: 0x40376078. */
/* Original function-byte SHA-256:
 * 327f290f3ba5af071250ce5e562f092178da2aad318f3cbf912ed5c07c4b6eef. */
/*
 * MEMW then samples REPEAT_DATA4 once and returns bit0 as bool. Reports the
 * major-wafer-version disable fuse; no inference about current secure-boot,
 * encryption, software policy or actual version-admission behavior.
 */
bool efuse_hal_get_disable_wafer_version_major(void)
{
    memw();
    return (EFUSE_READ_REGISTERS->repeat_data4 & 1U) != 0;
}

/* Native entry: 0x4037608c. */
/* Original function-byte SHA-256:
 * 9b5fd9ddb6135948ad085eef4ac626e09c7f4001ed3585fd5e7c2e702c347bf7. */
/*
 * MEMW then samples REPEAT_DATA4 once and returns bit1 as bool. Reports the
 * major-block-version disable fuse only; does not change eFuses or perform
 * a version check, policy transition or hardware-security verification.
 */
bool efuse_hal_get_disable_blk_version_major(void)
{
    memw();
    return ((EFUSE_READ_REGISTERS->repeat_data4 >> 1) & 1U) != 0;
}

/* Native entry: 0x403760a0. */
/* Original function-byte SHA-256:
 * 6a2ab2d03099743700271bcc7771bb648c93ced5e98aaeb904d5245dd75b80f6. */
/*
 * MEMW/reads REPEAT_DATA1 once, extracts SPI_BOOT_CRYPT_CNT bits18..20 and
 * XORs its individual low bits while shifting that cached value right.
 * Returns true for odd set-bit parity, false for even parity including zero.
 * No further MMIO reads, eFuse writes or image/flash integrity test occurs.
 */
bool efuse_hal_flash_encryption_enabled(void)
{
    memw();
    unsigned int count = (EFUSE_READ_REGISTERS->repeat_data1 >> 18) & 7U;
    unsigned int parity = 0;
    while (count != 0) {
        parity ^= count & 1U;
        count >>= 1;
    }
    return parity != 0;
}

/* Native entry: 0x403760c8. */
/* Original function-byte SHA-256:
 * 1e506164ac7f6e3abe19ebdc2b263c11fe16c877aa01bf96c7763e75a6570bfd. */
/*
 * Retains an initial MEMW/SYS5 WORD read even though that sample does not
 * affect the result. Then MEMW/reads SYS3 low-minor bits18..20. When zero,
 * tests fresh block-major low2 bits at+0x6c and block-minor bits24..26 at+0x50,
 * each after MEMW; block1.1 returns chip major0 (the early-chip workaround).
 * Other paths MEMW/REREAD SYS5 and return its major bits24..25. Short-circuit
 * read order is retained; no lock, disable-fuse test or coherent snapshot.
 */
unsigned int efuse_hal_get_major_chip_version(void)
{
    memw();
    unsigned int initial_wafer_word = EFUSE_READ_REGISTERS->mac_spi_sys5;
    (void)initial_wafer_word;
    memw();
    unsigned int low_minor = (EFUSE_READ_REGISTERS->mac_spi_sys3 >> 18) & 7U;
    if (low_minor == 0) {
        memw();
        unsigned int block_major = EFUSE_READ_REGISTERS->sys_part1_data4 & 3U;
        if (block_major == 1) {
            memw();
            unsigned int block_minor = (EFUSE_READ_REGISTERS->mac_spi_sys3 >> 24) & 7U;
            if (block_minor == 1) return 0;
        }
    }
    memw();
    return (EFUSE_READ_REGISTERS->mac_spi_sys5 >> 24) & 3U;
}

/* Native entry: 0x40376108. */
/* Original function-byte SHA-256:
 * e07b5f5941065633aef6fdeabed4e66aa6bde0863f201e8b342be38f246055b4. */
/*
 * MEMW/reads SYS5 then SYS3, combining first bit23 as minor bit3 and second
 * bits18..20 as minor bits0..2. Only low minor bits gate the early-chip
 * workaround: when zero, fresh MEMW/block-major and MEMW/block-minor reads
 * both equal to1 force result0, even if cached minor bit3 was set.
 * Otherwise returns the cached four-bit result. No snapshot/lock, disable-
 * fuse check, hardware write or unsupported-version error.
 */
unsigned int efuse_hal_get_minor_chip_version(void)
{
    memw();
    unsigned int high_word = EFUSE_READ_REGISTERS->mac_spi_sys5;
    memw();
    unsigned int low_word = EFUSE_READ_REGISTERS->mac_spi_sys3;
    unsigned int low_minor = (low_word >> 18) & 7U;
    unsigned int minor = (((high_word >> 23) & 1U) << 3) | low_minor;
    if (low_minor == 0) {
        memw();
        unsigned int block_major = EFUSE_READ_REGISTERS->sys_part1_data4 & 3U;
        if (block_major == 1) {
            memw();
            unsigned int block_minor = (EFUSE_READ_REGISTERS->mac_spi_sys3 >> 24) & 7U;
            if (block_minor == 1) return 0;
        }
    }
    return minor;
}
/* Native entry: 0x420021f4. */
/* Original function-byte SHA-256:
 * c691f32dd1c67a91db40b3aa3ae279512065af79f5f4d6776ab78403b89e5477. */
/* Public SDK eFuse error-check wrapper. Delegate once and return the complete
 * signed status WORD unchanged. No register access, lock, retry or translation
 * in this body. Its ESP32-S3 utility callee returns0 without checking hardware.
 */
int esp_efuse_check_errors(void)
{
    return esp_efuse_utility_check_errors();
}

/* Native entry: 0x4201e750. */
/* Original function-byte SHA-256:
 * 92c9598ac7519d458b9e367d0d7b28064c9bff38bae50b088825d1dda27f16a4. */
/* ESP32-S3 SDK eFuse coding-error utility: unconditional success stub.
 * Native body is ENTRY, set return WORD0, RETW. No inputs, register reads,
 * logging, eFuse correction, status validation or hardware writes occur here.
 * The SDK identity is established by the public check wrapper and the matching
 * ESP-IDF v5.4.4 esp32s3/esp_efuse_utility.c implementation.
 */
int esp_efuse_utility_check_errors(void)
{
    return 0;
}
