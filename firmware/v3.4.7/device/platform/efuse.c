/* Medius v3.4.7 device — eFuse field reads and factory MAC.
 * SDK identities checked against ESP-IDF v5.4.4 components/efuse/src and
 * components/esp_hw_support/mac_addr.c; the firmware instructions are authority.
 */
#include "../include/types.h"

/* eFuse reconstruction utilities: these sequences inline into the native
 * entries below and do not represent additional recovered functions.
 */
static __attribute__((always_inline)) inline unsigned int
efuse_read_checked(unsigned int block,unsigned int register_index)
{
    if (block > 10U)
        __assert_func(NULL,0,NULL,NULL);
    unsigned int start = EFUSE_REGISTER_RANGES[block].start;
    unsigned int end = EFUSE_REGISTER_RANGES[block].end;
    if (register_index > ((end - start) >> 2))
        __assert_func(NULL,0,NULL,NULL);
    memw();
    return *(volatile unsigned int *)(start + 4U * register_index);
}

static __attribute__((always_inline)) inline unsigned int
efuse_chunk_mask(int bit_count)
{
    return bit_count == 32 ? 0xffffffffU :
        (1U << ((unsigned int)bit_count & 31U)) - 1U;
}

/* Native entry: 0x40376440. */
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

/* Native entry: 0x40376458. */
/* Original function-byte SHA-256:
 * 26558ff60e9e917b19e5ef31601a1b7701375267c491396410727de885912ba6. */
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

/* Native entry: 0x4037647c. */
/* Original function-byte SHA-256:
 * 186b132f32f9d6eae3d0d902e6e87a62ea6cbd9b3a8c67398915dcb6012e9e0c. */
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

/* Native entry: 0x40376490. */
/* Original function-byte SHA-256:
 * 50e2e6d5f411e009675f16b88b67b99297bf89800abe64f6c38e26be59645c83. */
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

/* Native entry: 0x403764a4. */
/* Original function-byte SHA-256:
 * 0fc957003c98c9d9f173ed074c68a222477f83f299aaf4217424505b8c60ae5a. */
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

/* Native entry: 0x403764cc. */
/* Original function-byte SHA-256:
 * 655f166338111b37fa9c9178fd3c6da6e74058159a02c82ed4250122fdd2e8cc. */
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

/* Native entry: 0x4037650c. */
/* Original function-byte SHA-256:
 * f65c48880ca465805ddd3937d53c985307a56f429c0a118e64d6587f9cf199e3. */
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
/* Native entry: 0x420025c4. */
/* Original function-byte SHA-256:
 * 2845186441f05176f75db437dc2606dd3e560dd78f617fc5eb14c61b5a48fbeb. */
/* Internal retry body split from esp_efuse_read_field_blob by the compiler.
 * Requires the wrapper's non-NULL field/destination and nonzero bit length.
 * On EVERY attempt, clear ceil(destination_bits/8) bytes, then read at most
 * the smaller of the field length and requested bits. Excess destination bits
 * remain zero. A damaged-reading status delays one FreeRTOS tick and retries
 * without a timeout; every other status returns unchanged. No eFuse lock is
 * acquired, no partial read is retained across retries, and one tick is not
 * a promised wall-clock delay. The SDK signed item-count conversion is retained.
 */
int efuse_read_blob_retry(const EfuseDescriptor *const *field,
    void *destination,size_t destination_bits)
{
    for (;;) {
        int bytes = esp_efuse_utility_get_number_of_items((int)destination_bits,8);
        memset(destination,0,(size_t)bytes);
        int status = esp_efuse_utility_process(field,destination,destination_bits,
            esp_efuse_utility_fill_buff);
        if (status != ESP_ERR_DAMAGED_READING)
            return status;
        vTaskDelay(1);
    }
}

/* Native entry: 0x42002600. */
/* Original function-byte SHA-256:
 * dc432874dd4637121174be973944cbf3d81a815a665e20eac75cf9b7511a7707. */
/* Read a field into caller-owned storage, with size expressed in BITS.
 * Reject NULL field, NULL destination or zero size with 0x102 before any read
 * or write. Otherwise delegate to the clearing/retrying body and return its
 * status. Capacity, descriptor termination, valid register ranges and writable
 * destination lifetime are caller obligations; this wrapper adds no lock,
 * allocation, independent capacity check or retry limit.
 */
int esp_efuse_read_field_blob(const EfuseDescriptor *const *field,
    void *destination,size_t destination_bits)
{
    if (field == NULL || destination == NULL || destination_bits == 0)
        return ESP_ERR_INVALID_ARG;
    return efuse_read_blob_retry(field,destination,destination_bits);
}

/* Native entry: 0x42002640. */
/* Original function-byte SHA-256:
 * 393ea9b6d50bf8289c8e44cda6d0ec95e2bf442bee22a99640476915a523bb60. */
/* Read one checked eFuse WORD and count set bits in the selected chunk.
 * Callback argument order is register index, block, start, count, output,
 * processed counter. Block >10 or register index beyond its inclusive range
 * asserts. Fence immediately before the MMIO read. Count32 uses a full mask;
 * other counts and the start shift retain the native low-five-bit shifts.
 * Read the output WORD, then the processed WORD, before storing their wrapped
 * sums in that order. Thus aliased outputs retain the native last-store effect.
 * Requires valid writable outputs and a chunk selected by the field walker.
 * Returns zero; does not clear output, check the burn counter or take a lock.
 */
int esp_efuse_utility_count_once(unsigned int register_index,unsigned int block,
    int bit_start,int bit_count,void *output,int *processed_bits)
{
    unsigned int value = efuse_read_checked(block,register_index);
    unsigned int mask = efuse_chunk_mask(bit_count) << ((unsigned int)bit_start & 31U);
    unsigned int set_bits = (unsigned int)__popcountsi2(value & mask);
    volatile unsigned int *count = output;
    volatile int *processed = processed_bits;
    unsigned int old_count = *count;
    unsigned int old_processed = (unsigned int)*processed;
    *count = old_count + set_bits;
    *processed = (int)(old_processed + (unsigned int)bit_count);
    return 0;
}

/* Native entry: 0x420026a4. */
/* Original function-byte SHA-256:
 * c46e2603cf8f1c339ad4dcbe1bb2929108940e7adadb90205ef507972e4753c7. */
/* Walk a field in register-sized chunks through the six-argument callback.
 * The NULL-terminated POINTER LIST supplies the total bit count. A zero output
 * size requests that full total; otherwise take the unsigned minimum, then use
 * signed comparisons as native. Snapshot the burn counter after a MEMW.
 *
 * Important native behavior: processing starts at field[0], then advances by
 * one FOUR-BYTE DESCRIPTOR, rather than following later pointer-list entries.
 * The supplied descriptors must therefore also form a sufficiently long
 * contiguous sequence. A NULL first descriptor skips processing. No checks
 * repair sparse lists, missing termination, zero-length descriptors, NULL
 * callbacks/output, lack of callback progress or caller capacity.
 *
 * Reject descriptor start+count >256 with 0x1604, optionally logging the coding
 * error. Split accepted ranges at 32-bit register boundaries, cap each chunk
 * at remaining requested bits and pass the descriptor's raw block byte. The
 * callback advances the local processed counter; stop on its first nonzero
 * status or when the requested signed limit is reached. Zero-length fields
 * can still call a callback with count0, or advance without making progress.
 *
 * Every exit fences and reads the burn counter. Only successful fill_buff or
 * count_once callbacks turn a changed or odd counter into 0x1606; custom
 * callbacks and pre-existing errors retain their status. Sample the processed
 * WORD after every callback, including errors, before the final burn-counter
 * read. A range-error log also refreshes that sample after logging. Finally
 * assert the saved signed count did not exceed the signed request. No lock,
 * automatic retry, buffer clear, allocation or hardware write occurs here.
 */
int esp_efuse_utility_process(const EfuseDescriptor *const *field,
    void *output,size_t output_bits,EfuseChunkProcessor process)
{
    volatile int processed = 0;
    unsigned int requested = (unsigned int)esp_efuse_get_field_size(field);
    if (output_bits != 0 && output_bits < requested)
        requested = output_bits;
    int limit = (int)requested;
    int processed_count = processed;
    memw();
    unsigned int before = EFUSE_BURN_COUNTER;
    const volatile EfuseDescriptor *descriptor =
        *(const EfuseDescriptor *const volatile *)field;
    int status = 0;

    if (descriptor != NULL && processed_count < limit) {
        do {
            unsigned int start = descriptor->bit_start;
            unsigned int end = start + descriptor->bit_count;
            if (end > 256U) {
                if (SYSTEM_EARLY_LOG_LEVEL != 0) {
                    unsigned int timestamp = esp_log_timestamp();
                    ets_printf("E (%lu) %s: Range of data does not match the coding scheme\n",
                        timestamp,"efuse");
                    processed_count = processed;
                }
                status = ESP_ERR_CODING;
                goto failed_read;
            }
            int last_bit = (int)end - 1;
            unsigned int register_index = start >> 5;
            int last_register = last_bit / 32;
            int chunk_start = (int)(start & 31U);
            while ((int)register_index <= last_register) {
                int chunk_end = (int)register_index == last_register ? last_bit % 32 : 31;
                int chunk_bits = chunk_end - chunk_start + 1;
                if ((int)((unsigned int)processed_count + (unsigned int)chunk_bits) > limit)
                    chunk_bits = (int)(requested - (unsigned int)processed_count);
                status = process(register_index,descriptor->block,chunk_start,
                    chunk_bits,output,(int *)&processed);
                processed_count = processed;
                if (status != 0)
                    goto failed_read;
                if (processed_count >= limit)
                    goto check_consistency;
                ++register_index;
                chunk_start = 0;
            }
            ++descriptor;
        } while (processed_count < limit);
    }
check_consistency:
    memw();
    unsigned int after = EFUSE_BURN_COUNTER;
    if ((process == esp_efuse_utility_fill_buff || process == esp_efuse_utility_count_once)
        && (after != before || (after & 1U) != 0))
        status = ESP_ERR_DAMAGED_READING;
    goto check_count;
failed_read:
    memw();
    (void)EFUSE_BURN_COUNTER;
check_count:
    if (processed_count > limit)
        __assert_func(NULL,0,NULL,NULL);
    return status;
}

/* Native entry: 0x420027e0. */
/* Original function-byte SHA-256:
 * 37e01b26a5243651f3cf892baf577893a7340b509ade87e51da89a6456c4def7. */
/* Read one eFuse MMIO WORD. Block is an unsigned WORD, checked against10;
 * register index must fit the selected inclusive start/end range at3c045d7c.
 * Either violation asserts. Load both range addresses, fence, then read exactly
 * start+4*index and return the WORD unchanged. No lock, burn-counter consistency
 * check, field interpretation or retry; caller must ensure peripheral access.
 */
unsigned int esp_efuse_utility_read_reg(unsigned int block,unsigned int register_index)
{
    return efuse_read_checked(block,register_index);
}

/* Native entry: 0x42002818. */
/* Original function-byte SHA-256:
 * edad56ffc9aca08176d2a828015c30128d72d5414c825e7ebc2a0525090cd6b2. */
/* Read one register chunk and OR its bits into a caller-owned byte buffer.
 * The field walker supplies register index, block, bit start/count and a valid
 * processed-bit pointer. read_reg asserts bounds and fences the hardware read.
 * Read the initial processed WORD before alignment/masking. Count32 preserves
 * all shifted bits; other counts use the native low-five-bit mask operation.
 *
 * First OR into a partial output byte when the counter's low three bits are
 * nonzero. Consume min(8-signed_remainder,count) bits, then OR following bytes
 * while the signed remaining count is positive. Index division truncates
 * toward zero. Each BYTE is read before OR/write, then the processed WORD is
 * freshly loaded and updated with wrapping arithmetic. The shift accumulator
 * explicitly retains native bit5 zero selection (the zero-extended 64-bit
 * value in the SDK), including its low-five-bit shift for malformed inputs.
 * Returns zero. No buffer clearing, length/pointer validation, lock, burn
 * counter check or correction of overlapping buffer/counter storage is added.
 */
int esp_efuse_utility_fill_buff(unsigned int register_index,unsigned int block,
    int bit_start,int bit_count,void *output,int *processed_bits)
{
    unsigned int value = esp_efuse_utility_read_reg(block,register_index);
    volatile int *processed = processed_bits;
    int counter = *processed;
    int consumed = counter % 8;
    unsigned int aligned = (value >> ((unsigned int)bit_start & 31U)) & efuse_chunk_mask(bit_count);
    volatile unsigned char *blob = output;
    if (((unsigned int)counter & 7U) != 0) {
        volatile unsigned char *byte = blob + counter / 8;
        unsigned char old = *byte;
        *byte = (unsigned char)(old | (aligned << ((unsigned int)counter & 7U)));
        consumed = 8 - consumed < bit_count ? 8 - consumed : bit_count;
        counter = (int)((unsigned int)*processed + (unsigned int)consumed);
        *processed = counter;
        bit_count = (int)((unsigned int)bit_count - (unsigned int)consumed);
    }
    unsigned int shifted = 0;
    while (bit_count > 0) {
        volatile unsigned char *byte = blob + counter / 8;
        shifted += (unsigned int)consumed;
        unsigned char old = *byte;
        unsigned int next = (shifted & 32U) != 0 ? 0 : aligned >> (shifted & 31U);
        *byte = (unsigned char)(old | next);
        consumed = bit_count < 8 ? bit_count : 8;
        counter = (int)((unsigned int)*processed + (unsigned int)consumed);
        *processed = counter;
        bit_count = (int)((unsigned int)bit_count - (unsigned int)consumed);
    }
    return 0;
}

/* Native entry: 0x42020be4. */
/* Original function-byte SHA-256:
 * ca929043463e8bd1d779ec62a24752d04d3d48394f8c3e961612064a43c114ec. */
/* Sum descriptor bit_count HALFWORDS through a NULL-terminated POINTER LIST.
 * NULL field or a NULL first pointer returns0. Each descriptor must be readable
 * through byte3; list termination and lifetime are caller obligations. Load
 * each count and the next pointer before adding the count with WORD wrap.
 * Return the raw sum as a signed WORD. No 256-bit limit, block/range validation,
 * lock or independent maximum list length is imposed. Unlike process(), this
 * helper follows the pointer list rather than assuming contiguous descriptors.
 */
int esp_efuse_get_field_size(const EfuseDescriptor *const *field)
{
    unsigned int total = 0;
    if (field != NULL) {
        const EfuseDescriptor *const volatile *descriptors = field;
        const EfuseDescriptor *descriptor = *descriptors;
        while (descriptor != NULL) {
            unsigned int count = ((const volatile EfuseDescriptor *)descriptor)->bit_count;
            descriptor = *++descriptors;
            total += count;
        }
    }
    return (int)total;
}

/* Native entry: 0x42020c08. */
/* Original function-byte SHA-256:
 * 0176b30d2325054f2fb655484cf7ef2406f0fab3e69ba0c65386bd4fc29e9e0b. */
/* Compute signed bits/item_bits, adding1 only for a POSITIVE remainder.
 * For nonnegative bits and positive item_bits this is ceiling division; it
 * does not round negative values away from zero. Preserve native REMS before
 * QUOS so exceptional operands retain the processor's behavior instead of
 * C undefined division. Add with WORD wrap and return the resulting signed
 * WORD. No size validation or saturation; read_blob_retry supplies item_bits8.
 */
int esp_efuse_utility_get_number_of_items(int bits,int item_bits)
{
    int remainder;
    int quotient;
    __asm__ volatile ("rems %0, %1, %2" : "=a"(remainder)
        : "a"(bits),"a"(item_bits) : "memory");
    __asm__ volatile ("quos %0, %1, %2" : "=a"(quotient)
        : "a"(bits),"a"(item_bits) : "memory");
    return (int)((unsigned int)quotient + (remainder > 0 ? 1U : 0U));
}

/* Native entry: 0x420116d0. */
/* Original function-byte SHA-256:
 * 5c919ac6a0b6dac9d0d5f59846065fe657d94eb74427b25ed40cae606ea7bc59. */
/* Read the default six-byte factory MAC, with get_efuse_factory_mac inlined.
 * Sum the six field descriptors (48 bits) and assert byte alignment, then pass
 * that BIT LENGTH as the third read_field_blob argument omitted by Ghidra.
 * Descriptor bytes select block1 bits40..47,32..39,24..31,16..23,8..15,0..7,
 * placing the address in network byte order. Return the read status unchanged;
 * no CRC, override MAC, address derivation, allocation or output-size argument.
 * NULL mac is rejected by read_field_blob; a non-NULL pointer needs six writable
 * bytes. Consistency retries are delegated and may wait indefinitely.
 */
int esp_efuse_mac_get_default(unsigned char *mac)
{
    int bits = esp_efuse_get_field_size(EFUSE_MAC_FACTORY);
    if (((unsigned int)bits & 7U) != 0)
        __assert_func(NULL,0,NULL,NULL);
    return esp_efuse_read_field_blob(EFUSE_MAC_FACTORY,mac,(size_t)bits);
}

/* Native entry: 0x42002634. */
/* Original function-byte SHA-256:
 * 060b4de0bf39998b17dbde94868868fdeefa2e5cfc064a319673d1787ac4a97e. */
/* Public SDK eFuse error-check wrapper. Delegate once and return the complete
 * signed status WORD unchanged. No register access, lock, retry or translation
 * in this body. Its ESP32-S3 utility callee returns0 without checking hardware.
 */
int esp_efuse_check_errors(void)
{
    return esp_efuse_utility_check_errors();
}

/* Native entry: 0x42020c1c. */
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
