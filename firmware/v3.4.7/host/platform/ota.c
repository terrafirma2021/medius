/* Medius v3.4.7 host — OTA operation lifetime and metadata access.
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

/* Native entry: 0x420108c4. */
/* Original function-byte SHA-256:
 * 6dcb543b5b306937dee4d1373899301e21c7e8d37a47a03058c9e35377d39c58. */
/* Allocate one zero-filled44-byte OTA operation and prepend it to the
 * shared BSD-style list. Allocation failure returns NULL without mutations.
 * Fix the old head's previous_link, publish the new head, then sample the
 * global handle counter, set the new back-link and partition, increment the
 * counter with32-bit wrap and assign that value to the operation handle.
 * Return the new node: Ghidra incorrectly inferred void. Handle0/collisions
 * after wrap are not excluded. No partition validation or list/counter lock.
 */
OtaOperation *esp_ota_init_entry(const EspPartition *partition)
{
    OtaOperation *operation = calloc(1,44U);
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

/* Native entry: 0x420108f8. */
/* Original function-byte SHA-256:
 * a56e6b51cb58b84d37893e31070daada3ef8fdc9118b53cde591b2a43a76af04. */
/* Find DATA/OTA partition(type1,subtype0,labelNULL), map its full current
 * size as DATA, then copy32 bytes at offset0 and32 at a freshly read erase_size
 * to the caller's two-record output. Read the second source from the freshly
 * loaded mapped-base slot after the first memcpy; finally unmap its handle.
 * Missing partition or mapping error logs and returns NULL. No output writes
 * on those failures. On success return the partition pointer, not a status.
 * No output-NULL, metadata CRC/state, minimum-size or sector-layout validation.
 */
const EspPartition *ota_read_otadata(OtaSelectEntry entries[2])
{
    const EspPartition *partition = esp_partition_find_first(1,0,0);
    if (partition == 0) {
        unsigned int timestamp = esp_log_timestamp();
        esp_log_write(1,"esp_ota_ops","E (%lu) %s: not found otadata\n",timestamp,"esp_ota_ops");
        return 0;
    }
    const void *volatile mapped = 0;
    unsigned int map_handle;
    unsigned int size = *(const volatile unsigned int *)&partition->size;
    int status = esp_partition_mmap(partition,0,size,0,(const void **)&mapped,&map_handle);
    if (status != 0) {
        unsigned int timestamp = esp_log_timestamp();
        esp_log_write(1,"esp_ota_ops","E (%lu) %s: mmap otadata filed. Err=0x%8x\n",timestamp,"esp_ota_ops",status);
        return 0;
    }
    memcpy(entries,mapped,32U);
    unsigned int erase_size = *(const volatile unsigned int *)&partition->erase_size;
    const void *second = (const void *)((unsigned int)mapped + erase_size);
    memcpy((void *)((unsigned int)entries + 32U),second,32U);
    esp_partition_munmap(map_handle);
    return partition;
}

/* Native entry: 0x42010984. */
/* Original function-byte SHA-256:
 * 1c5a2823724da00f8a6be80c3ed35ef9d564a29aefce85423534de0937638047. */
/* Update the selected in-memory OTA record's sequence, compute its4-byte
 * ROM CRC, sample erase_size, then store CRC before touching flash. Erase one
 * erase_size region at (0-sector_index)&erase_size. On success freshly read
 * erase_size again and write32 bytes at that freshly derived offset. Return
 * the raw erase/write result. RAM changes remain even when flash fails.
 *
 * Native index is consumed at full32-bit width, with wrapping index<<5 address
 * calculation and no0/1 bounds check. The bitmask expression equals sector
 * multiplication only for intended indices0/1. No state update, lock, rollback,
 * secondary-copy validation or power-loss transaction is supplied.
 */
int ota_rewrite_sequence(OtaSelectEntry *entries,unsigned int sequence,
    unsigned int sector_index,const EspPartition *partition)
{
    OtaSelectEntry *entry = (OtaSelectEntry *)((unsigned int)entries + (sector_index << 5));
    entry->sequence = sequence;
    unsigned int crc = bootloader_common_ota_select_crc(entry);
    unsigned int erase_size = *(const volatile unsigned int *)&partition->erase_size;
    unsigned int sector_mask = 0U - sector_index;
    entry->crc = crc;
    int status = esp_partition_erase_range(partition,sector_mask & erase_size,erase_size);
    if (status != 0)
        return status;
    erase_size = *(const volatile unsigned int *)&partition->erase_size;
    return esp_partition_write(partition,sector_mask & erase_size,entry,32U);
}

/* Native entry: 0x420109bc. */
/* Original function-byte SHA-256:
 * e61aed1b5b6b8579549629e1f82742ebf05a6f2177880063aa713f88cf6156aa. */
/* Compiler-split running-partition cache initializer. Translate the address
 * of esp_ota_get_running_partition through spi_flash_cache2phys. Physical-1
 * or a missing initial APP iterator asserts with four zero arguments.
 * Search APP/any subtype records for start<=physical<start+size, retaining
 * native unsigned32-bit end wrap. Size is read only after the start gate.
 * Exhaustion aborts. Release the matching iterator, cache its borrowed
 * partition pointer, then return that pointer. No cache recheck, pin/refcount,
 * table mutation lock, image validation or caller-provided address is used.
 */
const EspPartition *ota_cache_running_partition(void)
{
    unsigned int physical = spi_flash_cache2phys((const void *)esp_ota_get_running_partition);
    if (physical == 0xffffffffU)
        __assert_func(0,0,0,0);
    PartitionIterator *iterator = esp_partition_find(0,0xffU,0);
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

/* Native entry: 0x42010a1c. */
/* Original function-byte SHA-256:
 * 0cfb2a0896bb27f6d265fd297ace39b9d2843a4cbd99d224492839ede7432062. */
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

/* Native entry: 0x42010a30. */
/* Original function-byte SHA-256:
 * 18599b27548bc0423ea64dcc6fa2d7b5ac42c4dfa374f4489ef112db8bf528de. */
/* Compiler-specialized image_validate: receive address, size and mode
 * directly, construct the8-byte position, and pass uninitialized264-byte
 * metadata scratch to esp_image_verify. Return0 only on verifier status0;
 * collapse EVERY other result to OTA_VALIDATE_FAILED0x1503. No local image
 * read, magic/hash policy or region validation beyond the called verifier.
 */
int ota_validate_image_region(unsigned int address,unsigned int size,unsigned int mode)
{
    ImageMetadataScratch metadata;
    ImagePosition position = {address,size};
    int status = esp_image_verify(mode,&position,&metadata);
    return status == 0 ? 0 : 0x1503;
}

/* Native entry: 0x42010bd4. */
/* Original function-byte SHA-256:
 * 2ee20a206cafc41c83d677a4265cf23304593ada33fe850e7ad525548a063723. */
/* Find the FIRST shared-list operation matching the full32-bit handle.
 * Missing handle returns NOT_FOUND0x105. On match repair next.previous_link
 * when next is non-NULL, freshly load this node's previous_link, overwrite
 * that link with next, free the node, return0. No flash erase, pending-buffer
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

/* Native entry: 0x42010c10. */
/* Original function-byte SHA-256:
 * b5ed3ef20a412f594fb3620c488354df009de546a11fcb0ef278e40d66ccbceb. */
/* Finish the first operation matching handle; absent returns0x105 without
 * list mutation. written_size0 returns0x102 after unlink/free, even if a
 * partial encrypted block is buffered. Otherwise a nonzero partial BYTE
 * writes the FULL16-byte buffer at the cached written offset. A write error
 * becomes0x103; no verifier call follows. Success freshly reloads written_size,
 * clears partial_bytes, advances size by16 with32-bit wrap, then verifies.
 *
 * Verify the partition's full address/size region in mode0 using264-byte
 * scratch; load size before address, build address before size. Nonzero verify
 * status becomes0x1503. EVERY matched path unlinks/frees the operation,
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
        int status = esp_partition_write(operation->partition,written,operation->partial_data,16U);
        if (status != 0) {
            result = 0x103;
            goto release_operation;
        }
        unsigned int current_written = operation->written_size;
        operation->partial_bytes = 0;
        operation->written_size = current_written + 16U;
    }
    const EspPartition *partition = operation->partition;
    unsigned int size = *(const volatile unsigned int *)&partition->size;
    unsigned int address = *(const volatile unsigned int *)&partition->address;
    ImagePosition position = {address,size};
    ImageMetadataScratch metadata;
    int status = esp_image_verify(0,&position,&metadata);
    result = status == 0 ? 0 : 0x1503;
release_operation:
    ota_unlink_inline(operation);
    free(operation);
    return result;
}
