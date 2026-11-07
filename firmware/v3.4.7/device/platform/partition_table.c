/* Medius v3.4.7 device: lazy partition-table loading and ROM MD5 validation. */
#include "../include/types.h"

/* Native entry: 0x4200ec9c. */
/* Original function-byte SHA-256:
 * 3770babaf79a59e3321d4faccb3526b12b7f5af444f912a1cfcb2da2d4a0446f. */
/* Lock the partition list and load it only if still empty. Initialize ROM MD5,
 * map physical 0/4096 bytes as DATA and scan 32-byte records at mapped+0x8000 up
 * to mapped+0x9000. Each record is copied to RAM before inspecting its magic.
 * Normal 0x50aa records feed MD5 and become zeroed 52-byte list nodes; stop on
 * MD5 marker0xebeb. Missing marker, invalid magic, full table or node allocation
 * failure logs/returns 0x105; the allocation error is overwritten by this path.
 * Compare ROM digest with 16 mapped bytes at marker+16, returning 0x103 on mismatch.
 * On success publish the temporary list and unmap. Failures free accumulated
 * nodes/unmap, log the final status and leave global head empty. A map failure
 * logs its status without unmapping. Always unlock; an existing list returns 0.
 * Derive encryption from live flash-encryption state and cached type/subtype/
 * flags, force app/bootloader/table/OTA-data/NVS-keys encryption when enabled;
 * readonly uses freshly reloaded flag bit 1. Copy 16 label bytes; calloc supplies
 * byte 16 termination. A valid empty table leaves the head NULL and is loaded
 * again on the next call. No table geometry/range/overlap or authenticity checks. */
int ensure_partitions_loaded(void)
{
    _lock_acquire(PARTITION_LIST_LOCK);
    int result = 0;
    if (PARTITION_LIST != NULL)
        goto unlock;

    RomMd5Context md5;
    MD5Init(&md5);
    const void *mapped;
    unsigned int map_handle;
    result = spi_flash_mmap(0,PARTITION_TABLE_SCAN_SIZE,ESP_PARTITION_MMAP_DATA,&mapped,&map_handle);
    if (result != 0)
        goto report_failure;

    uintptr_t cursor = (uintptr_t)mapped + PARTITION_TABLE_FLASH_OFFSET;
    uintptr_t end = (uintptr_t)mapped + PARTITION_TABLE_FLASH_OFFSET + PARTITION_TABLE_SCAN_SIZE;
    PartitionListNode *first = NULL;
    PartitionListNode *last = NULL;
    union {
        PartitionTableEntry entry;
        unsigned char digest[16];
    } record;
    const volatile PartitionTableEntry *entry = &record.entry;
    do {
        memcpy(&record.entry,(const void *)cursor,sizeof(record.entry));
        unsigned int magic = entry->magic;
        if (magic == ESP_PARTITION_MAGIC_MD5) {
            if (cursor == 0)
                goto missing_md5;
            goto verify_md5;
        }
        if (magic != ESP_PARTITION_MAGIC)
            goto missing_md5;
        MD5Update(&md5,&record.entry,sizeof(record.entry));
        PartitionListNode *node = calloc(1,sizeof(PartitionListNode));
        if (node == NULL)
            goto missing_md5;
        volatile PartitionListNode *candidate = node;
        unsigned int type = entry->type;
        void *chip = DEFAULT_FLASH_CHIP;
        unsigned int subtype = entry->subtype;
        candidate->info.flash_chip = chip;
        unsigned int address = entry->address;
        candidate->info.type = type;
        candidate->info.address = address;
        unsigned int size = entry->size;
        candidate->info.subtype = subtype;
        candidate->info.size = size;
        unsigned int flags = entry->flags;
        candidate->info.erase_size = PARTITION_TABLE_SCAN_SIZE;
        unsigned int encrypted = esp_flash_encryption_enabled();
        if (encrypted != 0) {
            if (type == 0 || (unsigned char)(type - 2U) <= 1U)
                encrypted = 1;
            else
                encrypted = ((type == 1 && (subtype & 0xfbU) == 0) ? 1U : 0U) | (flags & 1U);
        }
        unsigned int current_flags = entry->flags;
        candidate->info.encrypted = encrypted;
        candidate->info.readonly = (current_flags >> 1) & 1U;
        candidate->user_registered = 0;
        strncpy(node->info.label,record.entry.label,16);
        if (last == NULL) {
            PartitionListNode *old_first = first;
            first = node;
            candidate->next = old_first;
        } else {
            PartitionListNode *next = ((volatile PartitionListNode *)last)->next;
            candidate->next = next;
            ((volatile PartitionListNode *)last)->next = node;
        }
        cursor += sizeof(record.entry);
        if (cursor == end)
            goto missing_md5;
        last = node;
    } while (true);

missing_md5:
    {
        unsigned int timestamp = esp_log_timestamp();
        esp_log_write(1,"partition","E (%lu) %s: No MD5 found in partition table\n",timestamp,"partition");
        result = 0x105;
    }
    goto discard;
verify_md5:
    MD5Final(record.digest,&md5);
    if (memcmp(record.digest,(const void *)(cursor + 16U),16) != 0) {
        unsigned int timestamp = esp_log_timestamp();
        esp_log_write(1,"partition","E (%lu) %s: Partition table MD5 mismatch\n",timestamp,"partition");
        result = 0x103;
        goto discard;
    }
    PARTITION_LIST = first;
    spi_flash_munmap(map_handle);
    result = 0;
    goto unlock;
discard:
    while (first != NULL) {
        PartitionListNode *node = first;
        first = ((volatile PartitionListNode *)node)->next;
        free(node);
    }
    spi_flash_munmap(map_handle);
report_failure:
    {
        unsigned int timestamp = esp_log_timestamp();
        esp_log_write(1,"partition","E (%lu) %s: load_partitions returned 0x%x\n",timestamp,"partition",result);
    }
unlock:
    _lock_release(PARTITION_LIST_LOCK);
    return result;
}
