/* Medius v3.4.7 host — OTA begin and encrypted sequential-write buffering. */
#include "../include/types.h"

/* Native entry: 0x42010a54. */
/* Original function-byte SHA-256:
 * baaff6b77859ae2f67f4912c855b78c153bb60022b2282e8e99d91943cbe937d. */
/* Append to the first operation matching handle. NULL payload logs0x102
 * even for length0; non-NULL length0 returns0 before reading the session list.
 * A missing nonempty handle logs0x102. Sequential erase uses cached partition,
 * offset and erase-size, with REMU then two QUOUs and32-bit wrapping arithmetic.
 * Erase-size0 retains the native divide exception. Starting at a sector boundary
 * erases through the last input byte; a partial starting sector only erases
 * following sectors. Staying inside it jumps directly to payload processing.
 * After an actual successful erase (or when erase is disabled), freshly check
 * written_size/partial_bytes; the first unbuffered byte must be0xE9. Failure
 * logs a FRESH byte after timestamp and returns0x1503. Erase effects remain.
 *
 * Query global flash encryption each call. If enabled, fill a pending16-byte
 * buffer, freshly sample its partial BYTE after memcpy, store the wrapped BYTE
 * sum and return0 if it is not exactly16. A completed buffer writes16 bytes;
 * failure retains that full buffer/count. Success clears count, fills all16
 * buffer bytes with0xff, advances written_size16 and consumes the copied input.
 * Cache the remaining tail BEFORE the aligned flash write; its state persists
 * even if that write fails. Always issue the final partition write, including
 * length0 after tail buffering, and advance the freshly read written_size only
 * on status0. Return lower erase/write errors unchanged.
 *
 * No NULL-partition, capacity, partial-count, overflow or list-ownership guard,
 * per-session lock, rollback, hash calculation or automatic handle cleanup.
 * Newly allocated buffer bytes start0; this entry only changes them to0xff
 * after a completed buffered write. Native integer address wrap is retained.
 */
int esp_ota_write(unsigned int handle,const void *payload,unsigned int length)
{
    if (payload == 0) {
        unsigned int timestamp = esp_log_timestamp();
        esp_log_write(1,"esp_ota_ops","E (%lu) %s: write data is invalid\n",timestamp,"esp_ota_ops");
        return 0x102;
    }
    if (length == 0)
        return 0;
    OtaOperation *operation = OTA_OPERATIONS;
    while (operation != 0 && operation->handle != handle)
        operation = operation->next;
    if (operation == 0)
        goto missing_handle;
    const unsigned char *bytes = payload;
    if (operation->need_erase != 0) {
        const EspPartition *partition = operation->partition;
        unsigned int offset = operation->written_size;
        unsigned int erase_size = *(const volatile unsigned int *)&partition->erase_size;
        unsigned int last_offset = offset + length - 1U;
        unsigned int remainder,first_sector,last_sector;
        /* Native divide/remainder ordering and zero-divisor trap, not C /0. */
        __asm__ volatile (
            "remu %0,%3,%5\n"
            "quou %1,%3,%5\n"
            "quou %2,%4,%5"
            : "=&a"(remainder),"=&a"(first_sector),"=&a"(last_sector)
            : "a"(offset),"a"(last_offset),"a"(erase_size) : "memory");
        int status;
        if (remainder == 0) {
            unsigned int erase_length = (last_sector + 1U - first_sector) * erase_size;
            status = esp_partition_erase_range(partition,offset,erase_length);
        } else {
            if (first_sector == last_sector)
                goto process_payload;
            unsigned int erase_start = (first_sector + 1U) * erase_size;
            unsigned int erase_length = (last_sector - first_sector) * erase_size;
            status = esp_partition_erase_range(partition,erase_start,erase_length);
        }
        if (status != 0)
            return status;
    }
    if (operation->written_size == 0 && operation->partial_bytes == 0 &&
        *(const volatile unsigned char *)bytes != 0xe9U) {
        unsigned int timestamp = esp_log_timestamp();
        unsigned int fresh_magic = *(const volatile unsigned char *)bytes;
        esp_log_write(1,"esp_ota_ops",
            "E (%lu) %s: OTA image has invalid magic byte (expected 0xE9, saw 0x%02x)\n",
            timestamp,"esp_ota_ops",fresh_magic);
        return 0x1503;
    }
process_payload:
    if (esp_flash_encryption_enabled()) {
        unsigned int buffered = operation->partial_bytes;
        if (buffered != 0) {
            unsigned int available = 16U - buffered;
            unsigned int copy_length = available < length ? available : length;
            memcpy((void *)((unsigned int)operation + 20U + buffered),bytes,copy_length);
            unsigned int fresh_buffered = operation->partial_bytes;
            unsigned char new_buffered = (unsigned char)(fresh_buffered + copy_length);
            operation->partial_bytes = new_buffered;
            if (new_buffered != 16U)
                return 0;
            unsigned int offset = operation->written_size;
            const EspPartition *partition = operation->partition;
            int status = esp_partition_write(partition,offset,operation->partial_data,16U);
            if (status != 0)
                return status;
            operation->partial_bytes = 0;
            memset(operation->partial_data,0xff,16U);
            unsigned int current_written = operation->written_size;
            bytes = (const unsigned char *)((unsigned int)bytes + copy_length);
            operation->written_size = current_written + 16U;
            length -= copy_length;
        }
        unsigned int tail_length = length & 15U;
        operation->partial_bytes = (unsigned char)tail_length;
        if (tail_length != 0) {
            length -= tail_length;
            memcpy(operation->partial_data,(const void *)((unsigned int)bytes + length),tail_length);
        }
    }
    unsigned int offset = operation->written_size;
    const EspPartition *partition = operation->partition;
    int status = esp_partition_write(partition,offset,bytes,length);
    if (status == 0)
        operation->written_size = operation->written_size + length;
    return status;
missing_handle:
    ;
    unsigned int timestamp = esp_log_timestamp();
    esp_log_write(1,"esp_ota_ops","E (%lu) %s: not found the handle\n",timestamp,"esp_ota_ops");
    return 0x102;
}

/* Native entry: 0x420110c8. */
/* Original function-byte SHA-256:
 * 5eba79f9d454dea025560c5fe1c24d2f487e46bb62aca84c1c37bb1378ead574. */
/* Begin an OTA session. Reject NULL partition/output with0x102; canonicalize
 * partition through esp_partition_verify, returning0x105 if absent. Require
 * APP type0/subtype0x10..0x1f or0x102. Compare its pointer with the cached or
 * initialized running partition (0x1501 on conflict). A successful state query
 * reporting PENDING_VERIFY1 logs and returns0x1506; other query errors are
 * ignored. Allocation failure returns0x101.
 *
 * After allocation, cache the new handle, store need_erase BYTE then publish
 * the handle to caller BEFORE any initial erase. Size0xfffffffe means
 * sequential writes: return0 without erasing. Size0 or0xffffffff erases full
 * partition size. Other sizes erase wrapped(size-1+erase_size)&(0-erase_size).
 * This mask assumes the intended erase geometry but is not validated here.
 * Return the erase status unchanged. On erase error the allocated list node
 * and published handle REMAIN live; caller must abort it. No initial buffer
 * fill, image-size/capacity guard, range rollback or session-list lock.
 */
int esp_ota_begin(const EspPartition *partition,unsigned int size,volatile unsigned int *handle)
{
    if (partition == 0 || handle == 0)
        return 0x102;
    partition = esp_partition_verify(partition);
    if (partition == 0)
        return 0x105;
    if (*(const volatile unsigned int *)&partition->type != 0)
        return 0x102;
    if (*(const volatile unsigned int *)&partition->subtype - 0x10U >= 0x10U)
        return 0x102;
    const EspPartition *running = OTA_RUNNING_PARTITION;
    if (running == 0)
        running = ota_cache_running_partition();
    if (partition == running)
        return 0x1501;
    unsigned int state;
    if (esp_ota_get_state_partition(running,&state) == 0 && state == 1U) {
        unsigned int timestamp = esp_log_timestamp();
        esp_log_write(1,"esp_ota_ops",
            "E (%lu) %s: Running app has not confirmed state (ESP_OTA_IMG_PENDING_VERIFY)\n",
            timestamp,"esp_ota_ops");
        return 0x1506;
    }
    OtaOperation *operation = esp_ota_init_entry(partition);
    if (operation == 0)
        return 0x101;
    unsigned int new_handle = operation->handle;
    operation->need_erase = size == 0xfffffffeU;
    *handle = new_handle;
    if (size == 0xfffffffeU)
        return 0;
    unsigned int erase_length;
    if (size == 0 || size == 0xffffffffU) {
        erase_length = *(const volatile unsigned int *)&partition->size;
    } else {
        unsigned int erase_size = *(const volatile unsigned int *)&partition->erase_size;
        erase_length = (size - 1U + erase_size) & (0U - erase_size);
    }
    return esp_partition_erase_range(partition,0,erase_length);
}
