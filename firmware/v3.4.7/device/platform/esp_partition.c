/* Medius v3.4.7 device: ESP-IDF partition lookup, protection and flash access. */
#include "../include/types.h"

/* Native entry: 0x4200ee8c. */
/* Original function-byte SHA-256:
 * ba90265c78252b65abfe19d9c9839779550c54e65be548f4c30ae85c601352c1. */
/* Advance a non-NULL heap iterator to its next matching partition. Assert on
 * NULL. An already-empty next pointer frees the iterator without taking the
 * global list lock. Otherwise lock, cache the type filter and scan nodes using
 * live subtype/label filters;0xff means any and NULL label means any name.
 * Release the lock, reload next_item, then publish info and advance next_item.
 * End of list frees the iterator and returns NULL. On success return the same
 * iterator; partition descriptors remain owned by the global list. */
PartitionIterator *esp_partition_next(PartitionIterator *iterator)
{
    if (iterator == NULL)
        __assert_func(NULL,0,NULL,NULL);
    volatile PartitionIterator *cursor = iterator;
    if (cursor->next_item != NULL) {
        _lock_acquire(PARTITION_LIST_LOCK);
        PartitionListNode *node = cursor->next_item;
        if (node != NULL) {
            unsigned int type = cursor->type;
            do {
                const volatile PartitionListNode *candidate = node;
                if (type != 0xff && type != candidate->info.type)
                    goto advance;
                unsigned int subtype = cursor->subtype;
                if (subtype != 0xff && subtype != candidate->info.subtype)
                    goto advance;
                const char *label = cursor->label;
                if (label == NULL || strcmp(label,node->info.label) == 0)
                    break;
advance:
                node = candidate->next;
                cursor->next_item = node;
            } while (node != NULL);
        }
        _lock_release(PARTITION_LIST_LOCK);
        node = cursor->next_item;
        if (node != NULL) {
            PartitionListNode *next = ((volatile PartitionListNode *)node)->next;
            cursor->info = &node->info;
            cursor->next_item = next;
            return iterator;
        }
    }
    free(iterator);
    return NULL;
}

/* Native entry: 0x4200ef10. */
/* Original function-byte SHA-256:
 * 1410374a724ef7f08961a7baea49a13b5adf6b28b04da4f4fb7ef9fae72b9aae. */
/* Find the first partition matching full32-bit type/subtype and borrowed label.
 * If global list is empty, attempt lazy loading first; any failure returns
 * NULL. Then reject typeANY0xff with a specific subtype. Allocate an iterator20,
 * reload the global head, store filters/infoNULL and call next(), which frees
 * it on exhaustion. NULL also means allocation failure or no matching node.
 * No error-code distinction, label copy, filter truncation or explicit lock. */
PartitionIterator *esp_partition_find(unsigned int type,unsigned int subtype,const char *label)
{
    if (PARTITION_LIST == NULL && ensure_partitions_loaded() != 0)
        return NULL;
    if (type == 0xff && subtype != 0xff)
        return NULL;
    PartitionIterator *iterator = malloc(sizeof(*iterator));
    if (iterator == NULL)
        return NULL;
    PartitionListNode *first = PARTITION_LIST;
    volatile PartitionIterator *cursor = iterator;
    cursor->type = type;
    cursor->next_item = first;
    cursor->subtype = subtype;
    cursor->label = label;
    cursor->info = NULL;
    return esp_partition_next(iterator);
}

/* Native entry: 0x4200ef60. */
/* Original function-byte SHA-256:
 * 7408a3ee1f908b6447c534b0b7db59992a5f392d402d89ea598b1c08aae53f1a. */
/* Find a partition, cache its descriptor and free only the iterator. Return
 * the list-owned descriptor or NULL. Does not copy or free the partition. */
const EspPartition *esp_partition_find_first(unsigned int type,unsigned int subtype,const char *label)
{
    PartitionIterator *iterator = esp_partition_find(type,subtype,label);
    if (iterator == NULL)
        return NULL;
    const EspPartition *partition = ((volatile PartitionIterator *)iterator)->info;
    free(iterator);
    return partition;
}

/* Native entry: 0x4200ef80. */
/* Original function-byte SHA-256:
 * 15a761f361bcd9554cd607d55b2cd73b0067bf58162811be88681797084c05c4. */
/* Free the heap iterator only. NULL is forwarded to free; descriptors and the
 * borrowed label remain owned by their respective callers/list. */
void esp_partition_iterator_release(PartitionIterator *iterator)
{
    free(iterator);
}

/* Native entry: 0x4200ef90. */
/* Original function-byte SHA-256:
 * 3575bc6c292a5625417f8c4b7ead06c2f9c32ed4413635cac1ef57149ffeb100. */
/* Assert iterator is non-NULL and return its current info pointer. No list
 * search, descriptor validation, reference increment or lock is performed. */
const EspPartition *esp_partition_get(PartitionIterator *iterator)
{
    if (iterator == NULL)
        __assert_func(NULL,0,NULL,NULL);
    return ((volatile PartitionIterator *)iterator)->info;
}

/* Native entry: 0x4200efa8. */
/* Original function-byte SHA-256:
 * 7bbc9705955cbe7529c5394ec37d08f887f1b461c13bd3dcee99b528c43c66f4. */
/* Resolve a supplied descriptor to a list-owned partition. Assert non-NULL;
 * use type/subtype and a nonempty label as find filters. Compare chip pointer,
 * address, size and encrypted BYTE in native order; no whole-struct memcmp.
 * Return the first match after freeing its iterator, otherwise NULL after
 * next() exhausts/frees it. Readonly, erase_size and padding are not compared.
 * Does not validate firmware content, cryptographic identity or ownership. */
const EspPartition *esp_partition_verify(const EspPartition *partition)
{
    if (partition == NULL)
        __assert_func(NULL,0,NULL,NULL);
    const volatile EspPartition *requested = partition;
    unsigned int first_character = (unsigned char)requested->label[0];
    unsigned int subtype = requested->subtype;
    unsigned int type = requested->type;
    PartitionIterator *iterator = esp_partition_find(type,subtype,
        first_character == 0 ? NULL : partition->label);
    while (iterator != NULL) {
        const EspPartition *partition_info = ((volatile PartitionIterator *)iterator)->info;
        const volatile EspPartition *candidate = partition_info;
        void *requested_chip = requested->flash_chip;
        void *candidate_chip = candidate->flash_chip;
        if (candidate_chip == requested_chip) {
            unsigned int candidate_address = candidate->address;
            unsigned int requested_address = requested->address;
            if (candidate_address == requested_address) {
                unsigned int requested_size = requested->size;
                unsigned int candidate_size = candidate->size;
                if (requested_size == candidate_size) {
                    unsigned int requested_encrypted = requested->encrypted;
                    unsigned int candidate_encrypted = candidate->encrypted;
                    if (requested_encrypted == candidate_encrypted) {
                        free(iterator);
                        return partition_info;
                    }
                }
            }
        }
        iterator = esp_partition_next(iterator);
    }
    return NULL;
}

/* Native entry: 0x4200f00c. */
/* Original function-byte SHA-256:
 * 260beeb1df4387a321f57a145809878e00d5cec860caefd2cb0fefa550763c68. */
/* Write partition-relative bytes, honoring encryption. Assert descriptor;
 * reject readonly0x10d, offset>size0x102, length>remaining0x104, in that order.
 * Add base with32-bit wrap. Unencrypted writes call esp_flash_write; encrypted
 * writes require the default chip or return0x106, then use the differently
 * ordered encrypted-write arguments. Return flash status. No local source,
 * alignment, zero-length or base-overflow validation, erase or synchronization. */
int esp_partition_write(const EspPartition *partition,size_t offset,const void *data,size_t size)
{
    if (partition == NULL)
        __assert_func(NULL,0,NULL,NULL);
    const volatile EspPartition *info = partition;
    if (info->readonly != 0)
        return 0x10d;
    unsigned int partition_size = info->size;
    if (offset > partition_size)
        return 0x102;
    if (size > partition_size - offset)
        return 0x104;
    unsigned int base = info->address;
    unsigned int encrypted = info->encrypted;
    unsigned int address = offset + base;
    void *chip = info->flash_chip;
    if (encrypted == 0)
        return esp_flash_write(chip,data,address,size);
    if (chip != DEFAULT_FLASH_CHIP)
        return 0x106;
    return esp_flash_write_encrypted(chip,address,data,size);
}

/* Native entry: 0x4200f074. */
/* Original function-byte SHA-256:
 * 41bd2813ab3b1e81cc45e63e73e5764f3ef3f61112a82ec74c21a25b734eddf1. */
/* Read raw flash bytes without decryption. Assert descriptor, reject offset
 * beyond partition with0x102 or length beyond remaining bytes with0x104.
 * Read base then chip and forward chip/output/base+offset/length to flash read.
 * Return its status. No output/alignment/zero-length or base-overflow checks. */
int esp_partition_read_raw(const EspPartition *partition,size_t offset,void *output,size_t size)
{
    if (partition == NULL)
        __assert_func(NULL,0,NULL,NULL);
    const volatile EspPartition *info = partition;
    unsigned int partition_size = info->size;
    if (offset > partition_size)
        return 0x102;
    if (size > partition_size - offset)
        return 0x104;
    unsigned int base = info->address;
    void *chip = info->flash_chip;
    return esp_flash_read(chip,output,offset + base,size);
}

/* Native entry: 0x4200f0b0. */
/* Original function-byte SHA-256:
 * 73c065764d0be5718741a186ad9730c7527cc8cc2e95e68082ab70e89900f3ee. */
/* Write raw bytes without encryption. Assert descriptor; check readonly0x10d,
 * offset0x102, length0x104, then forward chip/data/base+offset/length to flash.
 * Return flash status. No source/alignment/zero-length/base-overflow checks,
 * automatic erase, rollback or local synchronization. */
int esp_partition_write_raw(const EspPartition *partition,size_t offset,const void *data,size_t size)
{
    if (partition == NULL)
        __assert_func(NULL,0,NULL,NULL);
    const volatile EspPartition *info = partition;
    if (info->readonly != 0)
        return 0x10d;
    unsigned int partition_size = info->size;
    if (offset > partition_size)
        return 0x102;
    if (size > partition_size - offset)
        return 0x104;
    unsigned int base = info->address;
    void *chip = info->flash_chip;
    return esp_flash_write(chip,data,offset + base,size);
}

/* Native entry: 0x4200f0f4. */
/* Original function-byte SHA-256:
 * 52761daf35c8b721be50d4e72c88fc59e77c1feb2ac0734d87cec8ee58c225cd. */
/* Erase partition-relative bytes. Assert descriptor; reject readonly0x10d,
 * offset out of bounds0x102, length out of bounds or not a4096 multiple0x104,
 * then offset not a4096 multiple0x102. Read base then chip and return flash
 * erase status. The partition's erase_size field is not consulted; zero length
 * is forwarded. No overflow, rollback or local synchronization checks. */
int esp_partition_erase_range(const EspPartition *partition,size_t offset,size_t size)
{
    if (partition == NULL)
        __assert_func(NULL,0,NULL,NULL);
    const volatile EspPartition *info = partition;
    if (info->readonly != 0)
        return 0x10d;
    unsigned int partition_size = info->size;
    if (offset > partition_size)
        return 0x102;
    if (size > partition_size - offset || (size & 0xfffU) != 0)
        return 0x104;
    if ((offset & 0xfffU) != 0)
        return 0x102;
    unsigned int base = info->address;
    void *chip = info->flash_chip;
    return esp_flash_erase_region(chip,offset + base,size);
}

/* Native entry: 0x4200f140. */
/* Original function-byte SHA-256:
 * 9f7945c135ad41bc1360edf06c0ce174a959c8d62427dc8297180ab22c317952. */
/* Map a partition range through the cache. Assert descriptor; reject offset
 * beyond size0x102, oversized length0x104 or non-default flash chip0x106.
 * Add base, align physical address down to64KiB and extend mapping length by
 * the within-page offset. Pass memory/output pointer/handle to spi_flash_mmap.
 * On success adjust the returned pointer by that offset; otherwise leave it
 * as the mapper left it and propagate status. Additions wrap32 bits. No output,
 * mapping-kind, alignment, zero-length or addition-overflow validation here. */
int esp_partition_mmap(const EspPartition *partition,size_t offset,size_t size,
    unsigned int memory,const void **out_pointer,unsigned int *out_handle)
{
    if (partition == NULL)
        __assert_func(NULL,0,NULL,NULL);
    const volatile EspPartition *info = partition;
    unsigned int partition_size = info->size;
    if (offset > partition_size)
        return 0x102;
    if (size > partition_size - offset)
        return 0x104;
    void *chip = info->flash_chip;
    if (chip != DEFAULT_FLASH_CHIP)
        return 0x106;
    unsigned int address = offset + info->address;
    unsigned int page_offset = address & 0xffffU;
    int result = spi_flash_mmap(address & 0xffff0000U,size + page_offset,memory,out_pointer,out_handle);
    if (result == 0) {
        const void *mapped = *(const void *volatile *)out_pointer;
        *(const void *volatile *)out_pointer = (const void *)((uintptr_t)mapped + page_offset);
    }
    return result;
}

/* Native entry: 0x4200f198. */
/* Original function-byte SHA-256:
 * 8d68f0ce4ea6ee0aacd9348ffea7d8325b7f93c6114764f8514d4d206dd3eaf9. */
/* Read partition bytes, decrypting encrypted partitions through a temporary
 * DATA mapping. Assert descriptor; offset/length failures return0x102/0x104.
 * Unencrypted reads directly return flash-read status. Encrypted reads require
 * default flash chip0x106, map the range, memcpy it to output, unmap and return
 * the successful map status0. Mapping failure skips copy/unmap. No output or
 * zero-length checks, local lock or copy/unmap failure status is supplied. */
int esp_partition_read(const EspPartition *partition,size_t offset,void *output,size_t size)
{
    if (partition == NULL)
        __assert_func(NULL,0,NULL,NULL);
    const volatile EspPartition *info = partition;
    unsigned int partition_size = info->size;
    if (offset > partition_size)
        return 0x102;
    if (size > partition_size - offset)
        return 0x104;
    unsigned int encrypted = info->encrypted;
    void *chip = info->flash_chip;
    if (encrypted == 0) {
        unsigned int address = offset + info->address;
        return esp_flash_read(chip,output,address,size);
    }
    if (chip != DEFAULT_FLASH_CHIP)
        return 0x106;
    unsigned int handle;
    const void *mapped;
    int result = esp_partition_mmap(partition,offset,size,0,&mapped,&handle);
    if (result == 0) {
        memcpy(output,*(const void *volatile *)&mapped,size);
        spi_flash_munmap(*(volatile unsigned int *)&handle);
    }
    return result;
}

/* Native entry: 0x4200f20c. */
/* Original function-byte SHA-256:
 * ac9fd49f08704de5f57467d279d2b342691736833cc4c83f6173eb53f3a9ed76. */
/* Forward a32-bit mapping handle to spi_flash_munmap. No validation or result. */
void esp_partition_munmap(unsigned int handle)
{
    spi_flash_munmap(handle);
}

/* Native entry: 0x4200f218. */
/* Original function-byte SHA-256:
 * b6b7aedd2cac7f39afd16c338d6ea4414e28e83c873a551ff42bf30766a71306. */
/* Return false if address starts inside a readonly partition or a range starts
 * before one and ends strictly beyond its start. Range/end additions wrap32
 * bits, and zero length can still be rejected when its start lies inside.
 * Search all partition types/subtypes; missing list/allocation/load failure
 * therefore returns true. Early false retains/leaks the live iterator; normal
 * exhaustion frees it via next(). No running-app/table protection is added. */
bool esp_partition_is_flash_region_writable(size_t address,size_t size)
{
    PartitionIterator *iterator = esp_partition_find(0xff,0xff,NULL);
    if (iterator != NULL) {
        unsigned int end = address + size;
        do {
            const volatile EspPartition *partition = esp_partition_get(iterator);
            if (partition->readonly != 0) {
                unsigned int start = partition->address;
                if (address < start) {
                    if (start < end)
                        return false;
                } else {
                    unsigned int partition_size = partition->size;
                    if (address < start + partition_size)
                        return false;
                }
            }
            iterator = esp_partition_next(iterator);
        } while (iterator != NULL);
    }
    return true;
}

/* Native entry: 0x4200f268. */
/* Original function-byte SHA-256:
 * 66ecd08917a526967e9788dc1197d2d9e3ccd632a6167c668ab787b01e3bfab3. */
/* Return false for starts<=0x8c00, or ranges overlapping the running app by
 * the same start-inside/strict-crossing checks. Zero length may be rejected;
 * additions wrap32 bits. Above0x8c00, get the running partition and dereference
 * it without a NULL check. Does not inspect readonly partition attributes. */
bool esp_partition_main_flash_region_safe(size_t address,size_t size)
{
    if (address <= 0x8c00U)
        return false;
    const volatile EspPartition *partition = esp_ota_get_running_partition();
    unsigned int start = partition->address;
    if (address < start)
        return !(start < address + size);
    unsigned int partition_size = partition->size;
    return !(address < start + partition_size);
}

/* Native entry: 0x4200f2a0. */
/* Original function-byte SHA-256:
 * 47dd4e91a8b45cc83482690c7b7f609b469c59804cd71a88bb0e28b19cc8abd8. */
/* Return the compiled-in main-flash sector size4096; no chip/register query. */
unsigned int esp_partition_get_main_flash_sector_size(void)
{
    return 0x1000;
}
