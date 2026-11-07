/* Medius v3.4.7 device: legacy flash-mapping handles over ESP-IDF MMU maps. */
#include "../include/types.h"

/* Native entry: 0x42010508. */
/* Original function-byte SHA-256:
 * 168c99bd13a8d834a9c50c5aa80c1716664a98ba1fa6da9851a2212fee194dae. */
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

/* Native entry: 0x420105d4. */
/* Original function-byte SHA-256:
 * 334d0dbef0716dc081f94cc2896ea79118ede370c3a838736626edee59b5a1bf. */
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
