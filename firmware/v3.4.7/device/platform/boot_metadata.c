/* Medius v3.4.7 device — boot/OTA metadata admission and flash windows.
 * ESP-IDF v5.4.4 names; native instructions govern widths, gates and effects.
 */
#include "../include/types.h"

/* Boot metadata reconstruction utilities: native-inlined operations only. */
static __attribute__((always_inline)) inline bool boot_ota_entry_valid_inline(const OtaSelectEntry *entry)
{
    if (entry->sequence == 0xffffffffU)
        return false;
    if (entry->state - 3U < 2U)
        return false;
    unsigned int expected_crc = entry->crc;
    return expected_crc == esp_rom_crc32_le(0xffffffffU,entry,4U);
}
static __attribute__((always_inline)) inline unsigned int boot_revision_pair_inline(const RevisionPairBytes *pair)
{
    unsigned int high = pair->high;
    unsigned int low = pair->low;
    return (high << 8) | low;
}

/* Native entry: 0x4200f2a8. */
/* Original function-byte SHA-256:
 * 68492d8c814363f3784df0ee6806266b0a391f5090b40bcf0f974c9bc487b43c. */
/* Compute ROM CRC32-LE with initial value0xffffffff over exactly4 bytes
 * at entry.sequence. Label/state/stored CRC are excluded. Return ROM result
 * unchanged; no validity/NULL check or metadata modification. ROM0x40001c98
 * is crc32_le; Ghidra's overlapping Bluetooth-symbol alias was misleading.
 */
unsigned int bootloader_common_ota_select_crc(const OtaSelectEntry *entry)
{
    return esp_rom_crc32_le(0xffffffffU,entry,4U);
}

/* Native entry: 0x4200f2bc. */
/* Original function-byte SHA-256:
 * 7ae9edf727f3d77ab469ae6540587df845d4a3a046e1458dea246b0de1e97fd8. */
/* Check an OTA record: sequence0xffffffff is invalid; state3(INVALID) or
 *4(ABORTED) is invalid. ALL other raw states, including0xffffffff, pass this
 * state gate. Cache stored CRC before asking ROM to hash the4-byte sequence.
 * No label/hash/signature validation, sequence lower bound or NULL check.
 */
bool bootloader_common_ota_select_valid(const OtaSelectEntry *entry)
{
    return boot_ota_entry_valid_inline(entry);
}

/* Native entry: 0x4200f2e8. */
/* Original function-byte SHA-256:
 * cd1e936e531e68bf2482cec0b44b733c8596029283dcb361744d35d9e695ebb5. */
/* Compare one cached eFuse block revision (major*100+minor) with raw32-bit
 * image limits. Minimum0xffff disables the minimum check;0 passes naturally.
 * Maximum0 or0xffff disables the maximum check. Only an exceeded enabled max
 * reads the disable-block-major-version fuse; a set fuse bypasses that maximum
 * failure, never an earlier minimum failure. Both diagnostics may occur.
 * Return0 or-1. No resampling, fuse burn, image authentication or policy lock.
 */
int bootloader_common_check_efuse_blk_validity(unsigned int minimum_revision,unsigned int maximum_revision)
{
    unsigned int revision = efuse_hal_blk_version();
    unsigned int major = revision / 100U;
    unsigned int minor = revision % 100U;
    int result = 0;
    if (minimum_revision != 0xffffU && revision < minimum_revision) {
        unsigned int timestamp = esp_log_timestamp();
        esp_log_write(1,"boot_comm",
            "E (%lu) %s: Image requires efuse blk rev >= v%lu.%lu, but chip is v%lu.%lu\n",
            timestamp,"boot_comm",minimum_revision / 100U,minimum_revision % 100U,major,minor);
        result = -1;
    }
    if (maximum_revision != 0xffffU && maximum_revision != 0 && maximum_revision < revision &&
        !efuse_hal_get_disable_blk_version_major()) {
        unsigned int timestamp = esp_log_timestamp();
        esp_log_write(1,"boot_comm",
            "E (%lu) %s: Image requires efuse blk rev <= v%lu.%lu, but chip is v%lu.%lu\n",
            timestamp,"boot_comm",maximum_revision / 100U,maximum_revision % 100U,major,minor);
        result = -1;
    }
    return result;
}

/* Native entry: 0x4200f3a4. */
/* Original function-byte SHA-256:
 * 412a3bf97f4eae2368b877c0d77d4dc589574f6aa26d86884707499b9f089fb7. */
/* Check chip ID9 (ESP32-S3), reading each LE16 pair HIGH BYTE then LOW.
 * Mismatch logs a FRESH ID after timestamp and returns-1 without reading
 * chip revision. Otherwise sample eFuse revision even for raw image_type>=2;
 * those types return0 without reading revision limits. Types0(bootloader)
 * and1(application) enforce minimum;0xffff is NOT an unset minimum here.
 * Only type1 enforces maximum1..65534, and only an exceeded max queries the
 * disable-wafer-major-version fuse. That fuse bypasses max, not minimum.
 * Return0 or-1; both minimum/max diagnostics may occur. No header extent,
 * NULL, magic, image digest or authenticity check. Byte pairs can tear if
 * caller mutates the header; no coherent snapshot or lock is added.
 */
int bootloader_common_check_chip_validity(const ImageRevisionHeader *header,unsigned int image_type)
{
    unsigned int chip_id = boot_revision_pair_inline(&header->chip_id);
    if (chip_id != 9U) {
        unsigned int timestamp = esp_log_timestamp();
        unsigned int fresh_id = boot_revision_pair_inline(&header->chip_id);
        esp_log_write(1,"boot_comm","E (%lu) %s: mismatch chip ID, expected %d, found %d\n",
            timestamp,"boot_comm",9U,fresh_id);
        return -1;
    }
    unsigned int revision = efuse_hal_chip_revision();
    if (image_type >= 2U)
        return 0;
    unsigned int minimum = boot_revision_pair_inline(&header->minimum_revision);
    unsigned int major = revision / 100U;
    unsigned int minor = revision % 100U;
    int result = 0;
    if (revision < minimum) {
        unsigned int timestamp = esp_log_timestamp();
        esp_log_write(1,"boot_comm",
            "E (%lu) %s: Image requires chip rev >= v%d.%d, but chip is v%d.%d\n",
            timestamp,"boot_comm",minimum / 100U,minimum % 100U,major,minor);
        result = -1;
    }
    if (image_type != 1U)
        return result;
    unsigned int maximum = boot_revision_pair_inline(&header->maximum_revision);
    if (maximum != 0 && maximum != 0xffffU && maximum < revision &&
        !efuse_hal_get_disable_wafer_version_major()) {
        unsigned int timestamp = esp_log_timestamp();
        esp_log_write(1,"boot_comm","E (%lu) %s: Image requires chip rev <= v%d.%d, but chip is v%d.%d\n",
            timestamp,"boot_comm",maximum / 100U,maximum % 100U,major,minor);
        result = -1;
    }
    return result;
}

/* Native entry: 0x4200f4c4. */
/* Original function-byte SHA-256:
 * b10c4217a7357a1e0ae8317fc14cdd1df951878eaddbe18dc5fb4d72aa96a01b. */
/* Choose the active copy from two contiguous32-byte OTA records. NULL
 * returns-1. Validate copy0 then copy1 using the inlined native sequence/state
 * and ROM CRC gates, then call the selector with two BYTE flags and maximum
 * selection1. A tie chooses0; no sequence-wrap chronology or authenticity
 * inference is supplied. Each record is read separately, without a snapshot.
 */
int bootloader_common_get_active_otadata(const OtaSelectEntry entries[2])
{
    if (entries == 0)
        return -1;
    unsigned char validity[2];
    validity[0] = boot_ota_entry_valid_inline(&entries[0]);
    validity[1] = boot_ota_entry_valid_inline(&entries[1]);
    return bootloader_common_select_otadata(entries,validity,1);
}

/* Native entry: 0x4202115c. */
/* Original function-byte SHA-256:
 * d10740f09a6688e83eabe9b7e17dff1294bab01b59cdf003bb86438ee43997ba. */
/* Select OTA copy index using caller-supplied validity BYTES; no CRC or
 * state check here. Either NULL pointer returns-1 before reading flags. Cache
 * flags0 then1, treating every nonzero BYTE as true. Neither valid returns-1;
 * a single valid flag selects its index without reading sequences. Both valid
 * reads sequence0 then sequence1 and chooses unsigned min/max according to
 * the LOW BYTE select_maximum!=0. Equal sequences choose0. Numeric order has
 * no rollover handling; no record mutation, lock, log or signature check.
 */
int bootloader_common_select_otadata(const OtaSelectEntry entries[2],const unsigned char validity[2],unsigned char select_maximum)
{
    if (entries == 0 || validity == 0)
        return -1;
    unsigned char valid_first = *(const volatile unsigned char *)&validity[0];
    unsigned char valid_second = *(const volatile unsigned char *)&validity[1];
    if (valid_first == 0)
        return valid_second != 0 ? 1 : -1;
    if (valid_second == 0)
        return 0;
    unsigned int first = entries[0].sequence;
    unsigned int second = entries[1].sequence;
    unsigned int chosen = select_maximum != 0 ?
        (first > second ? first : second) : (first < second ? first : second);
    return chosen != first;
}

/* Native entry: 0x4200f53c. */
/* Original function-byte SHA-256:
 * b9e3ef7f27e4d1a3ecfd0eb4055a6ed7e1f87d4dc18f59bb5ffaaf0344c778af. */
/* Return spi_flash_mmap_get_free_pages(DATA=0), unchanged. Counts pages,
 * not a reserved/contiguous byte span. Does not allocate or lock a mapping.
 */
unsigned int bootloader_mmap_get_free_pages(void)
{
    return spi_flash_mmap_get_free_pages(0);
}

/* Native entry: 0x4200f548. */
/* Original function-byte SHA-256:
 * 6cfbf92b04aaf3bb83489f09c3c9f6b4f6ff16bf5072836ab58398ac78a54518. */
/* Map one bootloader DATA window. A nonzero shared handle rejects another
 * mapping and optionally prints an early diagnostic. Otherwise map64KiB-aligned
 * flash address with native32-bit length+(address&0xffff), returning mapped
 * base plus that offset with32-bit wrap. The FIFTH spi_flash_mmap argument is
 * the actual shared handle slot, omitted by the original decompiler output.
 * Return NULL on lower error; logging checks the current full WORD enable.
 * No local length/alignment/overflow/returned-base validation, handle rollback,
 * nested-map support or mutex. Lower API owns mapping limits and failure state.
 */
const void *bootloader_mmap(unsigned int flash_address,unsigned int length)
{
    if (BOOT_MMAP_HANDLE != 0)
        goto already_mapped;
    unsigned int offset = flash_address & 0xffffU;
    const void *base = 0;
    int status = spi_flash_mmap(flash_address & 0xffff0000U,length + offset,0,&base,
        (unsigned int *)&BOOT_MMAP_HANDLE);
    if (status == 0)
        return (const void *)((unsigned int)base + offset);
    if (BOOT_EARLY_LOG_ENABLED != 0) {
        unsigned int timestamp = esp_log_timestamp();
        ets_printf("E (%lu) %s: spi_flash_mmap failed: 0x%x\n",timestamp,"bootloader_mmap",status);
    }
    return 0;
already_mapped:
    if (BOOT_EARLY_LOG_ENABLED != 0) {
        unsigned int timestamp = esp_log_timestamp();
        ets_printf("E (%lu) %s: tried to bootloader_mmap twice\n",timestamp,"bootloader_mmap");
    }
    return 0;
}

/* Native entry: 0x4200f5b8. */
/* Original function-byte SHA-256:
 * 094bca5cdf47f9c4990086c8a72d8dfdfa73c080ad77bed50d4abc346637e677. */
/* If mapped_address is non-NULL, read the shared handle and unmap it only
 * when nonzero. The address is merely a gate; it is not compared with the
 * owned mapping. ALWAYS clear the handle afterward, including a NULL address
 * that skipped release (and can therefore lose the mapping handle). No lock,
 * status, ownership/range validation or cache operation is added here.
 */
void bootloader_munmap(const void *mapped_address)
{
    if (mapped_address != 0) {
        unsigned int handle = BOOT_MMAP_HANDLE;
        if (handle != 0)
            spi_flash_munmap(handle);
    }
    BOOT_MMAP_HANDLE = 0;
}
