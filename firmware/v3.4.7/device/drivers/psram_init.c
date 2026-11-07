/* Medius v3.4.7 device — external RAM initialization and mapping. */
#include "../include/types.h"

/* Native entry: 0x4200812c. */
/* Original function-byte SHA-256:
 * 6563c815cf88f75663d781ba7f106becc12efb5c8e3adc30aacf63a8a6632bd7. */
/*
 * Initialize the device's external PSRAM and reserve/map its primary region.
 * A nonzero initialized BYTE returns0x103 before probing hardware. Forward an
 * implementation-enable failure unchanged, optionally logging it; no state
 * rollback is attempted. After enable succeeds, set initialized=1 BEFORE
 * checking physical/available sizes, virtual reservation or hardware mapping.
 * Those later failures assert/abort and leave the BYTE set.
 *
 * Query physical size into an initially zero WORD and assert status0. Optional
 * level>=3 logs report MiB and fixed40MHz; recheck the gate between messages.
 * Query available size, find maximum caps0x1e/target2 span and reserve the
 * unsigned minimum, asserting on either API error. Cache the returned virtual
 * capacity before reservation/mapping. Zero all output locals
 * before their calls. Map MMU0/target2 at physical0 using requested length;
 * the HAL writes rounded mapped length, which controls cache-bus admission.
 *
 * Endpoint arithmetic wraps32 bits. CPU0 admits IROM start>=0x42000000 with
 * last<0x44000000, or DROM start>=0x3c000000 with last<=0x3dffffff, else aborts.
 * Clear the corresponding CPU0/CPU1 mask bits through independent I/D-cache
 * CTRL1 RMWs, retaining unchanged-value writes. Recompute last for CPU1; after
 * CPU0 admitted DROM, only the upper limit is retested on that fallback path.
 * Reload the rounded mapping length for CPU1. Publish mapped size between
 * CPU1's DCACHE read and write, then mapped
 * start/end, heap size/start/end in that order. These context sizes use the
 * requested length; cache admission used the rounded HAL result. Finally warn
 * at level>=2 if virtual capacity was smaller than available physical size.
 * No heap registration, memory test, cache flush, timeout or inter-core lock.
 */
int esp_psram_init(void)
{
    if (PSRAM_INITIALIZED != 0)
        return 0x103;
    int status = esp_psram_impl_enable();
    if (status != 0) {
        if (PSRAM_LOG_LEVEL != 0) {
            unsigned int timestamp = esp_log_timestamp();
            ets_printf("E (%lu) %s: PSRAM enabled but initialization failed. Bailing out.\n",
                       timestamp,PSRAM_LOG_TAG);
        }
        return status;
    }
    PSRAM_INITIALIZED = 1;
    unsigned int physical_size = 0;
    if (esp_psram_impl_get_physical_size(&physical_size) != 0)
        __assert_func(NULL,0,NULL,NULL);
    if (PSRAM_LOG_LEVEL >= 3U) {
        unsigned int timestamp = esp_log_timestamp();
        ets_printf("I (%lu) %s: Found %luMB PSRAM device\n",timestamp,
                   PSRAM_LOG_TAG,physical_size >> 20);
        if (PSRAM_LOG_LEVEL >= 3U) {
            timestamp = esp_log_timestamp();
            ets_printf("I (%lu) %s: Speed: %dMHz\n",timestamp,PSRAM_LOG_TAG,40);
        }
    }
    unsigned int available_output = 0;
    if (esp_psram_impl_get_available_size(&available_output) != 0)
        __assert_func(NULL,0,NULL,NULL);
    unsigned int available_size = available_output;
    size_t capacity_output = 0;
    if (esp_mmu_map_get_max_consecutive_free_block_size(0x1eU,2U,&capacity_output) != 0)
        __assert_func(NULL,0,NULL,NULL);
    unsigned int virtual_capacity = capacity_output;
    unsigned int requested_length = available_size < virtual_capacity
        ? available_size : virtual_capacity;
    const void *reserved_address = NULL;
    if (esp_mmu_map_reserve_block_with_caps(requested_length,0x1eU,2U,&reserved_address) != 0)
        __assert_func(NULL,0,NULL,NULL);
    unsigned int mapped_length = 0;
    mmu_hal_map_region(0,2,(unsigned int)(uintptr_t)reserved_address,0,
        requested_length,&mapped_length);
    /* Native reads the rounded length, then reloads the reserved address
     * after the HAL call. Neither output is frozen across that call. */
    unsigned int rounded_length = *(const volatile unsigned int *)&mapped_length;
    unsigned int virtual_address = (unsigned int)(uintptr_t)
        *(const void *volatile *)&reserved_address;
    unsigned int last_mapped_address = virtual_address + rounded_length - 1U;
    unsigned int data_mask,instruction_mask;
    bool instruction_bus = virtual_address >= 0x42000000U;
    if (last_mapped_address < 0x44000000U && instruction_bus) {
        data_mask = 0xffffffffU;
        instruction_mask = 0xfffffffeU;
    } else {
        if (virtual_address < 0x3c000000U || last_mapped_address > 0x3dffffffU)
            abort();
        data_mask = 0xfffffffdU;
        instruction_mask = 0xffffffffU;
    }
    memw();
    unsigned int cache_control = PSRAM_CACHE_BUSES->instruction_control1;
    memw();
    PSRAM_CACHE_BUSES->instruction_control1 = cache_control & instruction_mask;
    memw();
    cache_control = PSRAM_CACHE_BUSES->data_control1;
    memw();
    PSRAM_CACHE_BUSES->data_control1 = cache_control & data_mask;

    rounded_length = *(const volatile unsigned int *)&mapped_length;
    last_mapped_address = virtual_address + rounded_length - 1U;
    if (last_mapped_address < 0x44000000U && instruction_bus) {
        data_mask = 0xffffffffU;
        instruction_mask = 0xfffffffdU;
    } else {
        if (last_mapped_address > 0x3dffffffU)
            abort();
        data_mask = 0xfffffffeU;
        instruction_mask = 0xffffffffU;
    }
    memw();
    cache_control = PSRAM_CACHE_BUSES->instruction_control1;
    unsigned int virtual_end_address = virtual_address + requested_length;
    memw();
    PSRAM_CACHE_BUSES->instruction_control1 = cache_control & instruction_mask;
    memw();
    cache_control = PSRAM_CACHE_BUSES->data_control1;
    PSRAM_CONTEXT->mapped_regions[0].size = requested_length;
    memw();
    PSRAM_CACHE_BUSES->data_control1 = cache_control & data_mask;
    PSRAM_CONTEXT->mapped_regions[0].start = virtual_address;
    PSRAM_CONTEXT->mapped_regions[0].end = virtual_end_address;
    PSRAM_CONTEXT->heap_regions[0].size = requested_length;
    PSRAM_CONTEXT->heap_regions[0].start = virtual_address;
    PSRAM_CONTEXT->heap_regions[0].end = virtual_end_address;
    if (virtual_capacity < available_size && PSRAM_LOG_LEVEL >= 2U) {
        unsigned int timestamp = esp_log_timestamp();
        ets_printf("W (%lu) %s: Virtual address not enough for PSRAM, map as much as we can. %dMB is mapped\n",
                   timestamp,PSRAM_LOG_TAG,requested_length >> 20);
    }
    return 0;
}
