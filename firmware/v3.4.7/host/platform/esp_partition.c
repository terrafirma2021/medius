/* Medius v3.4.7 host: ESP-IDF partition lookup, protection and flash access. */
#include "../include/types.h"

/* Native entry: 0x4201138c. */
/* Original function-byte SHA-256:
 * e05c5880641545966ac4f71f64b08698b015054aabbe1e222ac32b0147b6e5ca. */
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

/* Native entry: 0x42011410. */
/* Original function-byte SHA-256:
 * 7963ba61091be1f6ead041acb6258ea992f9d1f285380f6bf4460cc45e7ed757. */
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

/* Native entry: 0x42011460. */
/* Original function-byte SHA-256:
 * 3882a2ac3e07c023938fe693cde895ad662058ef35061fa48c0bfe28d7b7b96e. */
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

/* Native entry: 0x42011480. */
/* Original function-byte SHA-256:
 * dbc64ced780e8badd324faf52dc91f6bc92107ae3e6e2a313a3020afd2e45c32. */
/* Free the heap iterator only. NULL is forwarded to free; descriptors and the
 * borrowed label remain owned by their respective callers/list. */
void esp_partition_iterator_release(PartitionIterator *iterator)
{
    free(iterator);
}

/* Native entry: 0x42011490. */
/* Original function-byte SHA-256:
 * 73e82210e5162b76d05ac429724448a99f4efb3355623e52043f42be3f14cc1b. */
/* Assert iterator is non-NULL and return its current info pointer. No list
 * search, descriptor validation, reference increment or lock is performed. */
const EspPartition *esp_partition_get(PartitionIterator *iterator)
{
    if (iterator == NULL)
        __assert_func(NULL,0,NULL,NULL);
    return ((volatile PartitionIterator *)iterator)->info;
}

/* Native entry: 0x420114a8. */
/* Original function-byte SHA-256:
 * a2a4046d2952b71494659cc0c11d5e39ca4b2c155dabf8a51b5f46d9eed65fdf. */
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

/* Native entry: 0x4201150c. */
/* Original function-byte SHA-256:
 * acccb6db133efd271331517fe994d31f141861ced03c0d91b89c233abc8d05ff. */
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

/* Native entry: 0x42011574. */
/* Original function-byte SHA-256:
 * ab8a40b4b297bf9c88b4d72fe6cd020d4bff5c93412d64a4e977368a7c7f6151. */
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

/* Native entry: 0x420115c0. */
/* Original function-byte SHA-256:
 * 972bcd59a077bf92cfb9bed0d45365d1d03485b671dca123b85a34af4a4fb5a7. */
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

/* Native entry: 0x42011618. */
/* Original function-byte SHA-256:
 * f566a9e383fcd29aeb6754870b27cc86a291cb80f09ccc40c6d75e8be7105417. */
/* Forward a32-bit mapping handle to spi_flash_munmap. No validation or result. */
void esp_partition_munmap(unsigned int handle)
{
    spi_flash_munmap(handle);
}

/* Native entry: 0x42011624. */
/* Original function-byte SHA-256:
 * 314dd83052ba81553888fd5829254b106fe0636c81d74a40684e5ca96ff32ca9. */
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

/* Native entry: 0x42011674. */
/* Original function-byte SHA-256:
 * 2264a3e4ad89c28e0e498ad68fdffcdd7e106aa2b59b1d8ff28608964700390c. */
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

/* Native entry: 0x420116ac. */
/* Original function-byte SHA-256:
 * 7a1098169ed7e2768f31968ff6bbd9fd4efaff27c32a8aa481319680869782c6. */
/* Return the compiled-in main-flash sector size4096; no chip/register query. */
unsigned int esp_partition_get_main_flash_sector_size(void)
{
    return 0x1000;
}
