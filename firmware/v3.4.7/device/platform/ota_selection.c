/* Medius v3.4.7 device — OTA boot selection, rollback and state lookup. */
#include "../include/types.h"

/* OTA selection reconstruction utilities: these are native-inlined helpers,
 * not extra function identities. Keep unsigned wrap and hardware REMU.
 */
static __attribute__((always_inline)) inline unsigned int ota_count_contiguous_inline(void)
{
    for (unsigned int subtype = ESP_PARTITION_SUBTYPE_APP_OTA_MIN; subtype <= ESP_PARTITION_SUBTYPE_APP_OTA_MAX; ++subtype) {
        if (esp_partition_find_first(ESP_PARTITION_TYPE_APP,subtype,NULL) == 0)
            return (subtype - ESP_PARTITION_SUBTYPE_APP_OTA_MIN) & 0xffffU;
        if (subtype == ESP_PARTITION_SUBTYPE_APP_OTA_MAX)
            __assert_func(0,0,0,0);
    }
    __builtin_unreachable();
}
static __attribute__((always_inline)) inline unsigned int ota_remainder_inline(unsigned int numerator,unsigned int denominator)
{
    unsigned int remainder;
    __asm__ volatile ("remu %0,%1,%2" : "=a"(remainder) : "a"(numerator),"a"(denominator) : "memory");
    return remainder;
}
static __attribute__((always_inline)) inline int ota_silent_verify_inline(const EspPartition *partition,ImagePosition *position,ImageMetadataScratch *metadata)
{
    unsigned int size = *(const volatile unsigned int *)&partition->size;
    unsigned int address = *(const volatile unsigned int *)&partition->address;
    position->offset = address;
    position->size = size;
    return esp_image_verify(ESP_IMAGE_VERIFY_SILENT,position,metadata);
}

/* Native entry: 0x4200e798. */
/* Original function-byte SHA-256:
 * fea1116561a92f9231d3bbe54f283afb1d766c674f59f9a21d6bc47478934e2f. */
/* Verify address/size in mode 0 before checking partition type; NULL returns
 * 0x102, any verifier error 0x1503, non-APP type 0x102. Factory subtype 0 finds
 * DATA/OTA and erases its entire size (missing 0x105), selecting factory by
 * clearing metadata; no restart. Other APP subtypes use their low 4 bits,
 * without requiring the usual 0x10..0x1f subtype range.
 *
 * Read two OTA records, count consecutive slots from subtype 0x10 until the
 * first hole (assert if 0x10..0x20 all exist), and require (subtype & 15) < count.
 * No active record: set record 0 state NEW (0) and rewrite sequence slot+1 there.
 * Active record: start sequence=(slot+1)%count and repeatedly add count with
 * 32-bit wrap until it is >= cached active sequence; equality is accepted.
 * There is no wrap detection/iteration bound, so this loop need not terminate
 * for hostile sequence values. Set the opposite record's state NEW (0) and rewrite
 * it. Return lower erase/write status unchanged. No partition canonicalization,
 * counter transaction, rollback on flash failure, lock or reboot.
 */
int esp_ota_set_boot_partition(const EspPartition *partition)
{
    if (partition == 0)
        return 0x102;
    unsigned int size = *(const volatile unsigned int *)&partition->size;
    unsigned int address = *(const volatile unsigned int *)&partition->address;
    if (ota_validate_image_region(address,size,ESP_IMAGE_VERIFY) != 0)
        return 0x1503;
    if (*(const volatile unsigned int *)&partition->type != ESP_PARTITION_TYPE_APP)
        return 0x102;
    unsigned int subtype = *(const volatile unsigned int *)&partition->subtype;
    if (subtype == ESP_PARTITION_SUBTYPE_APP_FACTORY) {
        const EspPartition *metadata_partition = esp_partition_find_first(ESP_PARTITION_TYPE_DATA,ESP_PARTITION_SUBTYPE_DATA_OTA,NULL);
        if (metadata_partition == 0)
            return 0x105;
        size = *(const volatile unsigned int *)&metadata_partition->size;
        return esp_partition_erase_range(metadata_partition,0,size);
    }
    OtaSelectEntry entries[2];
    const EspPartition *metadata_partition = ota_read_otadata(entries);
    if (metadata_partition == 0)
        return 0x105;
    unsigned int count = ota_count_contiguous_inline();
    unsigned int slot = subtype & 15U;
    if (slot >= count)
        return 0x102;
    int active = bootloader_common_get_active_otadata(entries);
    unsigned int sequence = slot + 1U;
    unsigned int target = 0;
    if (active != -1) {
        OtaSelectEntry *current = (OtaSelectEntry *)((uintptr_t)entries + ((unsigned int)active << 5));
        unsigned int active_sequence = current->sequence;
        sequence = ota_remainder_inline(sequence,count);
        while (sequence < active_sequence)
            sequence += count;
        target = ~(unsigned int)active & 1U;
    }
    entries[target].state = ESP_OTA_IMG_NEW;
    return ota_rewrite_sequence(entries,sequence,target,metadata_partition);
}

/* Native entry: 0x4200e880. */
/* Original function-byte SHA-256:
 * 027cf73b7ae1d4d2c0f4d7c49414a19da035cfe27446e2588a0067f12a86680e. */
/* Return the next available OTA partition in subtype order 0x10..0x1f.
 * NULL start uses the cached/initialized running partition. Non-NULL start is
 * canonicalized; failure asserts with four zeros. Scan all 16 subtypes, skipping
 * holes, retaining the first available as the wrap/default result. After the
 * exact start pointer is seen, return the next DIFFERENT pointer found; repeated
 * matches only keep the seen flag set. If start never appears or no later
 * pointer exists, return first (or NULL if none). No state/image validation,
 * erase, allocation, lock or suitability guarantee. Ghidra's extra five parameters
 * were register-inference artifacts; only the start pointer is an argument.
 */
const EspPartition *esp_ota_get_next_update_partition(const EspPartition *start)
{
    if (start == 0) {
        start = OTA_RUNNING_PARTITION;
        if (start == 0)
            start = ota_cache_running_partition();
    } else {
        start = esp_partition_verify(start);
        if (start == 0)
            __assert_func(0,0,0,0);
    }
    const EspPartition *first = 0;
    bool seen_start = false;
    for (unsigned int subtype = ESP_PARTITION_SUBTYPE_APP_OTA_MIN; subtype != ESP_PARTITION_SUBTYPE_APP_OTA_MAX; ++subtype) {
        const EspPartition *candidate = esp_partition_find_first(ESP_PARTITION_TYPE_APP,subtype,NULL);
        if (candidate == 0)
            continue;
        if (first == 0)
            first = candidate;
        if (candidate == start)
            seen_start = true;
        else if (seen_start)
            return candidate;
    }
    return first;
}

/* Native entry: 0x4200e8e4. */
/* Original function-byte SHA-256:
 * 4faece8024b70b81c1f4d8e2a203c80a8a2f87333dda1d161b96966777ee5d32. */
/* Probe rollback eligibility from a fresh two-record OTA snapshot. Missing
 * metadata, zero consecutive-slot count, or no valid active record returns
 * false. Validate both records, select unsigned maximum, and inspect the
 * opposite copy. An invalid opposite copy tries factory APP first and verifies
 * its full region in silent mode 1. A successful verification returns true.
 * After failure re-read its validity BYTE; still false returns false.
 *
 * A valid opposite copy maps wrapped(sequence-1)%count to subtype0x10+slot,
 * looks it up and verifies that partition in mode 1. Return status==0. Count
 * enumeration asserts if all 17 subtypes 0x10..0x20 exist. Does not compare with
 * the actual running partition, check secure-version fuses, change boot state,
 * reboot or lock the table. Verifier/body policy remains in esp_image_verify.
 */
bool esp_ota_check_rollback_is_possible(void)
{
    OtaSelectEntry entries[2];
    if (ota_read_otadata(entries) == 0)
        return false;
    unsigned int count = ota_count_contiguous_inline();
    if (count == 0)
        return false;
    volatile unsigned char validity[2];
    validity[0] = bootloader_common_ota_select_valid(&entries[0]);
    validity[1] = bootloader_common_ota_select_valid(&entries[1]);
    int active = bootloader_common_select_otadata(entries,(const unsigned char *)validity,1);
    if (active == -1)
        return false;
    unsigned int other = ~(unsigned int)active & 1U;
    ImagePosition position;
    ImageMetadataScratch metadata;
    if (validity[other] == 0) {
        const EspPartition *factory = esp_partition_find_first(ESP_PARTITION_TYPE_APP,ESP_PARTITION_SUBTYPE_APP_FACTORY,NULL);
        if (factory != 0 && ota_silent_verify_inline(factory,&position,&metadata) == 0)
            return true;
        if (validity[other] == 0)
            return false;
    }
    unsigned int slot = ota_remainder_inline(entries[other].sequence - 1U,count);
    const EspPartition *candidate = esp_partition_find_first(ESP_PARTITION_TYPE_APP,ESP_PARTITION_SUBTYPE_APP_OTA_MIN + slot,NULL);
    if (candidate == 0)
        return false;
    return ota_silent_verify_inline(candidate,&position,&metadata) == 0;
}

/* Native entry: 0x4200e9d4. */
/* Original function-byte SHA-256:
 * 2dc025bb4ce15d9181e0cce2314d1416cfb2c459eecff82cdddb26c65c0c27e4. */
/* Mark the currently selected OTA copy workable or request rollback.
 * Native valid tests the full 32-bit argument for zero; every nonzero value
 * means workable. Read metadata (missing 0x105), select active, then count
 * consecutive OTA subtypes. No active/zero count logs factory and returns -1.
 * Workable: state VALID (2) already returns zero without writing; otherwise set state VALID (2),
 * then check only the active index low byte < 2 and rewrite its existing sequence.
 * State mutation precedes that index check; no flash-error rollback.
 *
 * Rollback: first require esp_ota_check_rollback_is_possible, else log and return 0x1505.
 * Set current state INVALID (3), apply the same low-BYTE index check, and rewrite.
 * Return write error unchanged. On success log and restart (does not return).
 * The snapshot used for eligibility is separate from this function's snapshot;
 * no table/state transaction or concurrency guarantee connects them.
 */
int esp_ota_current_ota_is_workable(unsigned int valid)
{
    OtaSelectEntry entries[2];
    const EspPartition *metadata_partition = ota_read_otadata(entries);
    if (metadata_partition == 0)
        return 0x105;
    int active = bootloader_common_get_active_otadata(entries);
    if (active == -1)
        goto factory_image;
    if (ota_count_contiguous_inline() == 0)
        goto factory_image;
    OtaSelectEntry *current = (OtaSelectEntry *)((uintptr_t)entries + ((unsigned int)active << 5));
    if (valid != 0) {
        if (current->state == ESP_OTA_IMG_VALID)
            return 0;
        current->state = ESP_OTA_IMG_VALID;
        unsigned int index = (unsigned char)active;
        if (index >= 2U)
            return 0x102;
        return ota_rewrite_sequence(entries,current->sequence,index,metadata_partition);
    }
    if (!esp_ota_check_rollback_is_possible()) {
        unsigned int timestamp = esp_log_timestamp();
        esp_log_write(1,"esp_ota_ops",
            "E (%lu) %s: Rollback is not possible, do not have any suitable apps in slots\n",
            timestamp,"esp_ota_ops");
        return 0x1505;
    }
    current->state = ESP_OTA_IMG_INVALID;
    unsigned int index = (unsigned char)active;
    if (index >= 2U)
        return 0x102;
    int status = ota_rewrite_sequence(entries,current->sequence,index,metadata_partition);
    if (status != 0)
        return status;
    unsigned int timestamp = esp_log_timestamp();
    esp_log_write(3,"esp_ota_ops","I (%lu) %s: Rollback to previously worked partition. Restart.\n",
        timestamp,"esp_ota_ops");
    esp_restart();
factory_image:
    ;
    unsigned int factory_timestamp = esp_log_timestamp();
    esp_log_write(1,"esp_ota_ops","E (%lu) %s: Running firmware is factory\n",factory_timestamp,"esp_ota_ops");
    return -1;
}

/* Native entry: 0x4200eaf8. */
/* Original function-byte SHA-256:
 * 8d1c8de4f6a2c772f41366a6d51ee675c95cade18ce073f23ad9bfbcaa01f1e7. */
/* Read a partition's OTA state. NULL partition/output returns 0x102; type
 * other than APP (0) or subtype outside 0x10..0x1f returns 0x106. Count consecutive
 * slots BEFORE reading OTA metadata, including when that count will be zero.
 * Missing metadata or zero count returns 0x105; output stays untouched.
 *
 * Sample copy 0 sequence, then freshly re-read requested subtype and subtract
 * 0x10. Try copy 0 then copy 1: only a wrapped(sequence-1)%count slot match and
 * matching sequence CRC are required. Cache each CRC before calling ROM.
 * Do NOT use the validity predicate: sequence 0/0xffffffff and states INVALID,
 * ABORTED or undefined are not filtered here. First qualifying copy wins,
 * regardless of newer sequence in copy 1. Return its freshly read full state
 * WORD via output and zero; otherwise 0x105. No lock or authenticity claim.
 */
int esp_ota_get_state_partition(const EspPartition *partition,unsigned int *state)
{
    if (partition == 0 || state == 0)
        return 0x102;
    if (*(const volatile unsigned int *)&partition->type != ESP_PARTITION_TYPE_APP)
        return 0x106;
    if (*(const volatile unsigned int *)&partition->subtype - ESP_PARTITION_SUBTYPE_APP_OTA_MIN >= ESP_PARTITION_SUBTYPE_APP_OTA_MAX - ESP_PARTITION_SUBTYPE_APP_OTA_MIN)
        return 0x106;
    unsigned int count = ota_count_contiguous_inline();
    OtaSelectEntry entries[2];
    const EspPartition *metadata_partition = ota_read_otadata(entries);
    if (metadata_partition == 0 || count == 0)
        return 0x105;
    unsigned int first_sequence = entries[0].sequence;
    unsigned int slot = *(const volatile unsigned int *)&partition->subtype - ESP_PARTITION_SUBTYPE_APP_OTA_MIN;
    for (unsigned int index = 0; index < 2U; ++index) {
        unsigned int sequence = index == 0 ? first_sequence : entries[1].sequence;
        if (ota_remainder_inline(sequence - 1U,count) != slot)
            continue;
        unsigned int expected_crc = entries[index].crc;
        if (bootloader_common_ota_select_crc(&entries[index]) != expected_crc)
            continue;
        *(volatile unsigned int *)state = entries[index].state;
        return 0;
    }
    return 0x105;
}
