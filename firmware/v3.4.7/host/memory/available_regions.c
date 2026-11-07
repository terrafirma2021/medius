/* Medius v3.4.7 host — available SoC memory after reservations. */
#include "../include/types.h"

/* Native entry: 0x42003f44. */
/* Original function-byte SHA-256:
 * 67a94524b802dccaeafb093be294d53c24ed020d8438b9190f00d7ee9a3071cb. */
/*
 * Build available heap ranges from this image's immutable 20-byte SoC records.
 * Copy the complete records, including alias address, startup-stack BYTE and
 * padding. Add the live ROM DRAM reservation [layout->start, 0x3fcf0000) to
 * the linker reservations and sort the eight-byte ranges by signed start.
 * Round each current reservation out to four-byte boundaries; endpoint
 * addition wraps. Assert signed start <= end and strictly increasing starts.
 * The next start is checked BEFORE that next record is rounded. A signed
 * overlap logs when enabled, then aborts even when logging is disabled.
 *
 * Subtract reservations using signed address comparisons. A fully covered
 * input is dropped; an overlap trims the start/end; a hole emits the prefix
 * and updates the mutable input's size THEN start so the suffix is processed
 * again. Preserve the other 12 bytes without recomputing the IRAM alias.
 * Keep pieces larger than 16 bytes (unsigned test on ordinary exits, signed
 * test on the split-prefix exit). Output copies are exactly 20 bytes.
 * Return the number written. The caller supplies sufficient output capacity;
 * no NULL/capacity check, allocation, lock or hardware MEMW occurs here.
 */
size_t soc_get_available_memory_regions(SocMemoryRegion *output)
{
    unsigned int input_count = SOC_MEMORY_REGION_COUNT;
    SocMemoryRegion inputs[input_count];
    memcpy(inputs, SOC_MEMORY_REGIONS, input_count * 20U);
    enum { linked_count = (RESERVED_MEMORY_END - RESERVED_MEMORY_START) / 8U };
    ReservedMemoryRegion reserved[linked_count + 1U];
    reserved[0].start = HEAP_ROM_LAYOUT->dram0_rtos_reserved_start;
    reserved[0].end = 0x3fcf0000U;
    memcpy(reserved + 1, (const void *)RESERVED_MEMORY_START, linked_count * 8U);
    qsort(reserved, linked_count + 1U, 8, heap_compare_reserved_regions);
    for (unsigned int i = 0; i <= linked_count; ++i) {
        unsigned int start = reserved[i].start & 0xfffffffcU;
        unsigned int end = (reserved[i].end + 3U) & 0xfffffffcU;
        reserved[i].start = start;
        reserved[i].end = end;
        if ((int)start > (int)end) __assert_func(NULL, 0, NULL, NULL);
        if (i < linked_count) {
            unsigned int next_start = reserved[i + 1U].start;
            if ((int)next_start <= (int)start) __assert_func(NULL, 0, NULL, NULL);
            if ((int)next_start < (int)end) {
                if (HEAP_LOG_LEVEL != 0) {
                    unsigned int timestamp = esp_log_timestamp();
                    const volatile ReservedMemoryRegion *current = &reserved[i];
                    unsigned int next_end = current[1].end;
                    unsigned int next = current[1].start;
                    unsigned int current_end = current[0].end;
                    unsigned int current_start = current[0].start;
                    ets_printf("E (%lu) %s: SOC_RESERVE_MEMORY_REGION region range 0x%08x - 0x%08x overlaps with 0x%08x - 0x%08x\n",
                               timestamp, MEMORY_LAYOUT_LOG_TAG,
                               current_start, current_end, next, next_end);
                }
                abort();
            }
        }
    }
    SocMemoryRegion *out = output;
    unsigned int index = 0;
    while (index != input_count) {
        SocMemoryRegion current;
        memcpy(&current, &inputs[index], 20);
        unsigned int original_start = inputs[index].start;
        unsigned int original_size = inputs[index].size;
        unsigned int start = original_start;
        unsigned int size = original_size;
        unsigned int end = start + size;
        bool emit = true;
        bool advance = true;
        bool split_prefix = false;
        for (unsigned int i = 0; i <= linked_count; ++i) {
            unsigned int reserved_end = reserved[i].end;
            if ((int)reserved_end <= (int)start) continue;
            unsigned int reserved_start = reserved[i].start;
            if ((int)reserved_start >= (int)end) break;
            if ((int)reserved_start > (int)start) {
                size = reserved_start - start;
                if ((int)reserved_end < (int)end) {
                    inputs[index].size = original_size - (reserved_end - original_start);
                    inputs[index].start = reserved_end;
                    advance = false;
                    split_prefix = true;
                    break;
                }
                end = reserved_start;
            } else {
                if ((int)reserved_end >= (int)end) {
                    emit = false;
                    break;
                }
                start = reserved_end;
                size = end - start;
            }
        }
        if (emit && (split_prefix ? (int)size > 16 : size > 16U)) {
            current.start = start;
            current.size = size;
            memcpy(out, &current, 20);
            ++out;
        }
        if (advance) ++index;
    }
    return (size_t)(out - output);
}
