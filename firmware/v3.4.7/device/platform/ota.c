/* Medius v3.4.7 device — OTA operation lifetime and metadata access.
 * ESP-IDF v5.4.4 identities; native widths/order/errors retained.
 */
#include "../include/types.h"

/* OTA reconstruction utilities: BSD list removal is native-inlined in both
 * end/abort entries. Keep the two previous_link reads distinct when next exists.
 */
static __attribute__((always_inline)) inline void ota_unlink_inline(OtaOperation *operation)
{
    OtaOperation *next = operation->next;
    if (next != 0)
        next->previous_link = operation->previous_link;
    *operation->previous_link = next;
}

/* Native entry: 0x4200e3c4. */
/* Original function-byte SHA-256:
 * 58b51730e0e7ca91304322b1e97c54a5912a9ca7f0c45e426598c25904522e31. */
/* Allocate one zero-filled 44-byte OTA operation and prepend it to the
 * shared BSD-style list. Allocation failure returns NULL without mutations.
 * Fix the old head's previous_link, publish the new head, then sample the
 * global handle counter, set the new back-link and partition, increment the
 * counter with 32-bit wrap and assign that value to the operation handle.
 * Return the new node: Ghidra incorrectly inferred void. Handle zero/collisions
 * after wrap are not excluded. No partition validation or list/counter lock.
 */
OtaOperation *esp_ota_init_entry(const EspPartition *partition)
{
    OtaOperation *operation = calloc(1,sizeof(OtaOperation));
    if (operation == 0)
        return 0;
    OtaOperation *old_head = OTA_OPERATIONS;
    operation->next = old_head;
    if (old_head != 0)
        old_head->previous_link = &operation->next;
    OTA_OPERATIONS = operation;
    unsigned int old_handle = OTA_LAST_HANDLE;
    operation->previous_link = &OTA_OPERATIONS;
    operation->partition = partition;
    OTA_LAST_HANDLE = old_handle + 1U;
    operation->handle = old_handle + 1U;
    return operation;
}

/* Native entry: 0x4200e3f8. */
/* Original function-byte SHA-256:
 * 834f7f06fdea579f6119364dde79d65a0e5396ddaa5a7117b518be7ea6ae68ef. */
/* Find the DATA/OTA partition (type 1, subtype 0, no label filter), map its full
 * current size as DATA, then copy 32 bytes at offset 0 and 32 at a freshly read erase_size
 * to the caller's two-record output. Read the second source from the freshly
 * loaded mapped-base slot after the first memcpy; finally unmap its handle.
 * Missing partition or mapping error logs and returns NULL. No output writes
 * on those failures. On success return the partition pointer, not a status.
 * No output-NULL, metadata CRC/state, minimum-size or sector-layout validation.
 */
const EspPartition *ota_read_otadata(OtaSelectEntry entries[2])
{
    const EspPartition *partition = esp_partition_find_first(
        ESP_PARTITION_TYPE_DATA,ESP_PARTITION_SUBTYPE_DATA_OTA,NULL);
    if (partition == 0) {
        unsigned int timestamp = esp_log_timestamp();
        esp_log_write(1,"esp_ota_ops","E (%lu) %s: not found otadata\n",timestamp,"esp_ota_ops");
        return 0;
    }
    const void *volatile mapped = 0;
    unsigned int map_handle;
    unsigned int size = *(const volatile unsigned int *)&partition->size;
    int status = esp_partition_mmap(partition,0,size,ESP_PARTITION_MMAP_DATA,
        (const void **)&mapped,&map_handle);
    if (status != 0) {
        unsigned int timestamp = esp_log_timestamp();
        esp_log_write(1,"esp_ota_ops","E (%lu) %s: mmap otadata filed. Err=0x%8x\n",timestamp,"esp_ota_ops",status);
        return 0;
    }
    memcpy(entries,mapped,sizeof(OtaSelectEntry));
    unsigned int erase_size = *(const volatile unsigned int *)&partition->erase_size;
    const void *second = (const void *)((uintptr_t)mapped + erase_size);
    memcpy((void *)((uintptr_t)entries + sizeof(OtaSelectEntry)),second,sizeof(OtaSelectEntry));
    esp_partition_munmap(map_handle);
    return partition;
}

/* Native entry: 0x4200e484. */
/* Original function-byte SHA-256:
 * c3e3c1144688d4cdbd5f5840b4dfc7c7999e59875b16d74517b909b2e6617ab9. */
/* Update the selected in-memory OTA record's sequence, compute its 4-byte
 * ROM CRC, sample erase_size, then store CRC before touching flash. Erase one
 * erase_size region at (0-sector_index)&erase_size. On success freshly read
 * erase_size again and write 32 bytes at that freshly derived offset. Return
 * the raw erase/write result. RAM changes remain even when flash fails.
 *
 * Native index is consumed at full 32-bit width, with wrapping index<<5 address
 * calculation and no 0/1 bounds check. The bitmask expression equals sector
 * multiplication only for intended indices 0/1. No state update, lock, rollback,
 * secondary-copy validation or power-loss transaction is supplied.
 */
int ota_rewrite_sequence(OtaSelectEntry *entries,unsigned int sequence,
    unsigned int sector_index,const EspPartition *partition)
{
    OtaSelectEntry *entry = (OtaSelectEntry *)((uintptr_t)entries + (sector_index << 5));
    entry->sequence = sequence;
    unsigned int crc = bootloader_common_ota_select_crc(entry);
    unsigned int erase_size = *(const volatile unsigned int *)&partition->erase_size;
    unsigned int sector_mask = 0U - sector_index;
    entry->crc = crc;
    int status = esp_partition_erase_range(partition,sector_mask & erase_size,erase_size);
    if (status != 0)
        return status;
    erase_size = *(const volatile unsigned int *)&partition->erase_size;
    return esp_partition_write(partition,sector_mask & erase_size,entry,sizeof(OtaSelectEntry));
}

/* Native entry: 0x4200e4bc. */
/* Original function-byte SHA-256:
 * 28f2d502df4929df1ed835009239562786c175df9c53f32fc7913ce6f0818ee3. */
/* Compiler-split running-partition cache initializer. Translate the address
 * of esp_ota_get_running_partition through spi_flash_cache2phys. Physical-1
 * or a missing initial APP iterator asserts with four zero arguments.
 * Search APP/any subtype records for start<=physical<start+size, retaining
 * native unsigned 32-bit end wrap. Size is read only after the start gate.
 * Exhaustion aborts. Release the matching iterator, cache its borrowed
 * partition pointer, then return that pointer. No cache recheck, pin/refcount,
 * table mutation lock, image validation or caller-provided address is used.
 */
const EspPartition *ota_cache_running_partition(void)
{
    unsigned int physical = spi_flash_cache2phys((const void *)esp_ota_get_running_partition);
    if (physical == 0xffffffffU)
        __assert_func(0,0,0,0);
    PartitionIterator *iterator = esp_partition_find(
        ESP_PARTITION_TYPE_APP,ESP_PARTITION_SUBTYPE_ANY,NULL);
    if (iterator == 0)
        __assert_func(0,0,0,0);
    const EspPartition *partition;
    for (;;) {
        partition = esp_partition_get(iterator);
        unsigned int start = *(const volatile unsigned int *)&partition->address;
        if (start <= physical) {
            unsigned int size = *(const volatile unsigned int *)&partition->size;
            if (physical < start + size)
                break;
        }
        iterator = esp_partition_next(iterator);
        if (iterator == 0)
            abort();
    }
    esp_partition_iterator_release(iterator);
    OTA_RUNNING_PARTITION = partition;
    return partition;
}

/* Native entry: 0x4200e51c. */
/* Original function-byte SHA-256:
 * 590b830611d62fba0a2899e80bd5c03599cd4bc4c08e553f333f12086626e4d4. */
/* Return one cached running-partition WORD. If NULL, call the initializer
 * and return its result without rereading the shared slot. Ghidra's void
 * inference for that helper obscured this return. No lock or validity refresh.
 */
const EspPartition *esp_ota_get_running_partition(void)
{
    const EspPartition *partition = OTA_RUNNING_PARTITION;
    if (partition == 0)
        partition = ota_cache_running_partition();
    return partition;
}

/* Native entry: 0x4200e530. */
/* Original function-byte SHA-256:
 * 86c09ea4307d1c6aa606f55033b1bc4e00866f1cb90108229ca60a3f642badfb. */
/* Compiler-specialized image_validate: receive address, size and mode
 * directly, construct the 8-byte position, and pass uninitialized 264-byte
 * metadata scratch to esp_image_verify. Return zero only on verifier success;
 * collapse every other result to OTA_VALIDATE_FAILED (0x1503). No local image
 * read, magic/hash policy or region validation beyond the called verifier.
 */
int ota_validate_image_region(unsigned int address,unsigned int size,unsigned int mode)
{
    ImageMetadataScratch metadata;
    ImagePosition position = {address,size};
    int status = esp_image_verify(mode,&position,&metadata);
    return status == 0 ? 0 : 0x1503;
}

/* Native entry: 0x4200e6d4. */
/* Original function-byte SHA-256:
 * 4be6ebc638d4d442e462b78f17d7ebf334bc9a58612aa38e3c11084e0e910f3c. */
/* Find the first shared-list operation matching the full 32-bit handle.
 * Missing handle returns NOT_FOUND (0x105). On match repair next.previous_link
 * when next is non-NULL, freshly load this node's previous_link, overwrite
 * that link with next, free the node, return zero. No flash erase, pending-buffer
 * flush, metadata change, handle-counter rollback, link validation or lock.
 */
int esp_ota_abort(unsigned int handle)
{
    OtaOperation *operation = OTA_OPERATIONS;
    while (operation != 0 && operation->handle != handle)
        operation = operation->next;
    if (operation == 0)
        return 0x105;
    ota_unlink_inline(operation);
    free(operation);
    return 0;
}

/* Native entry: 0x4200e710. */
/* Original function-byte SHA-256:
 * e7bae0cd1296b2172d0b4b25c43be86ab2095f59003476f121c697cf492c4c8e. */
/* Finish the first operation matching handle; absent returns 0x105 without
 * list mutation. Zero written_size returns 0x102 after unlink/free, even if a
 * partial encrypted block is buffered. Otherwise a nonzero partial BYTE
 * writes the full 16-byte buffer at the cached written offset. A write error
 * becomes 0x103; no verifier call follows. Success freshly reloads written_size,
 * clears partial_bytes, advances size by 16 with 32-bit wrap, then verifies.
 *
 * Verify the partition's full address/size region in mode 0 using 264-byte
 * scratch; load size before address, build address before size. Nonzero verify
 * status becomes 0x1503. Every matched path unlinks/frees the operation,
 * including write/verify/no-data failures. No retained retry handle, flash
 * rollback, boot selection, buffer padding, counter rollback or list lock.
 */
int esp_ota_end(unsigned int handle)
{
    OtaOperation *operation = OTA_OPERATIONS;
    while (operation != 0 && operation->handle != handle)
        operation = operation->next;
    if (operation == 0)
        return 0x105;
    int result = 0x102;
    unsigned int written = operation->written_size;
    if (written == 0)
        goto release_operation;
    if (operation->partial_bytes != 0) {
        int status = esp_partition_write(operation->partition,written,
            operation->partial_data,sizeof(operation->partial_data));
        if (status != 0) {
            result = 0x103;
            goto release_operation;
        }
        unsigned int current_written = operation->written_size;
        operation->partial_bytes = 0;
        operation->written_size = current_written + sizeof(operation->partial_data);
    }
    const EspPartition *partition = operation->partition;
    unsigned int size = *(const volatile unsigned int *)&partition->size;
    unsigned int address = *(const volatile unsigned int *)&partition->address;
    ImagePosition position = {address,size};
    ImageMetadataScratch metadata;
    int status = esp_image_verify(ESP_IMAGE_VERIFY,&position,&metadata);
    result = status == 0 ? 0 : 0x1503;
release_operation:
    ota_unlink_inline(operation);
    free(operation);
    return result;
}
