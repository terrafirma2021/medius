/* Medius v3.4.7 device: heap capability and reservation helpers. */
#include "../include/types.h"

/* Native entry: 0x42020c6c. */
/* Original function-byte SHA-256:
 * cd1bbf22749ead5eb698a845f52aea080a6519b1ac8b1968e2f3ee22cdcade46. */
/* Read the region's multi-heap pointer first; null returns false without
 * reading capability words. Otherwise read caps[0], caps[1], caps[2] once in
 * order and return whether their union contains every requested bit. An empty
 * mask matches a registered heap, but not an unregistered one. No allocation,
 * lock, priority preference, pointer validation or resampling of heap state. */
bool heap_caps_match(const HeapRegion *region,unsigned int required_caps)
{
    const volatile HeapRegion *heap = region;
    if (heap->heap == 0)
        return false;
    unsigned int priority_0_capabilities = heap->caps[0];
    unsigned int priority_1_capabilities = heap->caps[1];
    unsigned int priority_2_capabilities = heap->caps[2];
    unsigned int all_capabilities = priority_0_capabilities |
        priority_1_capabilities | priority_2_capabilities;
    return (all_capabilities & required_caps) == required_caps;
}

/* Native entry: 0x42020c94. */
/* Original function-byte SHA-256:
 * 9b6bcbe1c1e28bcc822545ffd10a2fe46cba3ad87bdba6530f4b48c586159727. */
/* qsort comparator for the eight-byte {start,end} reservation records.
 * Load the left start word, then the right start word and return their wrapping
 * 32-bit difference as signed int. Preserve subtraction overflow behavior;
 * this is not a normalized -1/0/1 ordering and can misorder distant addresses.
 * End fields are not read. No pointer validation or writes. */
int heap_compare_reserved_regions(const void *left,const void *right)
{
    unsigned int left_start = ((const volatile ReservedMemoryRegion *)left)->start;
    unsigned int right_start = ((const volatile ReservedMemoryRegion *)right)->start;
    return (int)(left_start - right_start);
}

/* Native entry: 0x42004320. */
/* Original function-byte SHA-256:
 * a667125c9e38a3e35683c7276c80b587143e6cca833cd08ae50cb27b60c22812. */
/* Read the native SoC memory-region count word. Add one ROM reservation plus
 * arithmetic-signed32(end-start)>>3 for the linker reservation records, then
 * return the wrapping 32-bit sum. This sizes the available-region builder's
 * output for the worst case of each reservation splitting a region. Retain
 * the native count load rather than Ghidra's folded constant. No allocation,
 * list scan, bounds/order/alignment checks or count clamping. */
unsigned int soc_get_available_memory_region_max_count(void)
{
    unsigned int regions = SOC_MEMORY_REGION_COUNT;
    unsigned int reserved_bytes = RESERVED_MEMORY_END - RESERVED_MEMORY_START;
    return regions + 1U + (unsigned int)((int)reserved_bytes >> 3);
}
