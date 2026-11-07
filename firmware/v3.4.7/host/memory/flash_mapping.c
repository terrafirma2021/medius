/* Medius v3.4.7 host: legacy flash mapping and cache queries. */
#include "../include/types.h"

/* Native entry: 0x42012834. */
/* Original function-byte SHA-256:
 * 02cb93afab0d4211b5a13126496287bb976ee4c9d2c5e77aab765c33e610be27. */
/* Map a flash range into the cache and return a heap-backed32-bit handle.
 * Reject address>=16MiB, size>16MiB or end>16MiB with a diagnostic/0x102;
 * address16MiB is invalid even for size0. Allocate internal-capability0x800
 * block8 then address-list4; failure frees earlier allocation/returns0x101.
 * Map targetFLASH0=1 with shared flag1; memoryINST=1 selects caps9, every other
 * value selects caps0x12. New mapping records address/count1. MMU status0x103
 * means already mapped: retain output pointer, count0 and return success.
 * Other errors free list/block, leave outputs untouched and propagate status.
 * Successful outputs are pointer then handle. No output-pointer, alignment or
 * zero-size validation, reference increment or local synchronization here. */
int spi_flash_mmap(size_t address,size_t size,unsigned int memory,
    const void **out_pointer,unsigned int *out_handle)
{
    if (address >= 0x1000000U || size > 0x1000000U || address > 0x1000000U - size) {
        unsigned int timestamp = esp_log_timestamp();
        esp_log_write(1,"flash_mmap",
            "E (%lu) %s: Address 0x%08zx is out of range for 24bit flash mapping, see CONFIG_BOOTLOADER_CACHE_32BIT_ADDR_QUAD_FLASH and CONFIG_BOOTLOADER_CACHE_32BIT_ADDR_OCTAL_FLASH for more details\n",
            timestamp,"flash_mmap",address);
        return 0x102;
    }
    void *mapped = NULL;
    FlashMappingHandle *block = heap_caps_calloc(1,8,0x800);
    if (block == NULL)
        return 0x101;
    unsigned int *addresses = heap_caps_calloc(1,4,0x800);
    if (addresses == NULL) {
        free(block);
        return 0x101;
    }
    volatile FlashMappingHandle *handle = block;
    handle->virtual_addresses = addresses;
    unsigned int capabilities = memory == 1 ? 9U : 0x12U;
    int result = esp_mmu_map(address,size,1,capabilities,1,&mapped);
    void *mapped_address;
    if (result == 0) {
        mapped_address = *(void *volatile *)&mapped;
        *(volatile unsigned int *)addresses = (uintptr_t)mapped_address;
        handle->count = 1;
    } else if (result == 0x103) {
        mapped_address = *(void *volatile *)&mapped;
        handle->count = 0;
    } else {
        free(addresses);
        free(block);
        return result;
    }
    *(const void *volatile *)out_pointer = mapped_address;
    *(volatile unsigned int *)out_handle = (uintptr_t)block;
    return 0;
}

/* Native entry: 0x42012900. */
/* Original function-byte SHA-256:
 * 802c90e59afd7e6a4d9c97b36070169045963a52bcfbc7ca533b3071249687e6. */
/* Release a heap mapping handle. If signed count>0, reload address-list and
 * unmap each entry; assert only on0x105 (not found), ignoring other statuses.
 * Reload signed count after each call; index arithmetic wraps32 bits. Then
 * reload/free the address-list and free the handle. Count<=0 skips MMU unmaps.
 * No NULL, bounds, provenance, double-free or ownership validation is present. */
void spi_flash_munmap(unsigned int handle)
{
    FlashMappingHandle *block = (FlashMappingHandle *)(uintptr_t)handle;
    volatile FlashMappingHandle *state = block;
    if (state->count > 0) {
        unsigned int index = 0;
        do {
            unsigned int *addresses = state->virtual_addresses;
            unsigned int address = *(volatile unsigned int *)((uintptr_t)addresses + index * 4U);
            int result = esp_mmu_unmap((void *)(uintptr_t)address);
            if (result == 0x105)
                __assert_func(NULL,0,NULL,NULL);
            int count = state->count;
            ++index;
            if ((int)index >= count)
                break;
        } while (true);
    }
    free(state->virtual_addresses);
    free(block);
}

/* Native entry: 0x42012944. */
/* Original function-byte SHA-256:
 * 89fecee7bc1f1b32adbc4c4165ac173b5506d0708fc6ee853f87473f2f6ebd0f. */
/* Query largest free FLASH virtual span for INST memory1 (caps9), otherwise
 * DATA caps0x12. Initialize a local WORD0, ignore query status and return its
 * upper HALFWORD, equivalent to count of64KiB pages. This reports the largest
 * consecutive slot, not total free pages, and performs no reservation. */
unsigned int spi_flash_mmap_get_free_pages(unsigned int memory)
{
    unsigned int caps = memory == 1 ? 9U : 0x12U;
    volatile size_t size = 0;
    (void)esp_mmu_map_get_max_consecutive_free_block_size(caps,1,(size_t *)&size);
    return *(const volatile unsigned short *)((uintptr_t)&size + 2U);
}

/* Native entry: 0x42012964. */
/* Original function-byte SHA-256:
 * 7005829bd00394663c5cea9c6127c1e7f4eafd8bb189e3040e2470e7477fef48. */
/* Convert a cached address to physical bytes. NULL immediately returns0xffffffff.
 * Initialize local physical/target WORDs0, call the MMU translation API, return
 * physical on success or0xffffffff on any error. Discard target, so a PSRAM
 * physical address can be returned too. No own table read or alignment check. */
size_t spi_flash_cache2phys(const void *cached)
{
    if (cached == NULL)
        return 0xffffffffU;
    volatile unsigned int physical = 0;
    volatile unsigned int target = 0;
    int result = esp_mmu_vaddr_to_paddr((void *)cached,(unsigned int *)&physical,(unsigned int *)&target);
    if (result != 0)
        return 0xffffffffU;
    return physical;
}

/* Native entry: 0x4037c5b0. */
/* Original function-byte SHA-256:
 * 5146355fac270622e8e49c59210b79ea55279057c1a4870721d02c0260646eca. */

/*
 * No parameters. Returns the cache HAL result for external-memory level1 and
 * ALL(2), requiring data and instruction cache enabled. No local read/write,
 * lock or validation. Native six-instruction wrapper matches ESP-IDF's
 * spi_flash_cache_enabled; actual fences and register reads belong to its HAL.
 */
bool spi_flash_cache_enabled(void)
{
    return cache_hal_is_cache_enabled(1, CACHE_TYPE_ALL);
}
