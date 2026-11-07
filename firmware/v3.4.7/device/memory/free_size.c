/* Medius v3.4.7 device — cached heap free-byte queries. */
#include "../include/types.h"

/* Native entry: 0x42003ed0. */
/* Original function-byte SHA-256:
 * 6741ea62839844329d107b5a0e4b023c61df2b17433bca1b2b8131b9bc629843. */
/* Sum the cached free-byte counters of registered heaps whose union of
 * three priority capability WORDs contains every requested bit. Load the
 * handle first; NULL handles skip all capability reads. Mask 0 includes every
 * non-NULL heap. Read caps in order 0, 1, 2, call the free-size accessor with
 * the captured handle, then freshly load next. Empty list returns 0.
 * The unsigned sum wraps at 32 bits. No list/allocator lock, hardware query,
 * allocator traversal, consistency retry, logging or MEMW: counters can change
 * independently, so the total is not a coherent multi-heap snapshot. */
size_t heap_caps_get_free_size(unsigned int caps)
{
    const volatile HeapRegion *region = HEAP_REGISTRATION_HEAD;
    unsigned int total_free_bytes = 0;
    while (region != NULL) {
        MultiHeap *heap = region->heap;
        if (heap != NULL) {
            unsigned int priority_0_capabilities = region->caps[0];
            unsigned int priority_1_capabilities = region->caps[1];
            unsigned int priority_2_capabilities = region->caps[2];
            unsigned int combined_capabilities = priority_0_capabilities |
                priority_1_capabilities | priority_2_capabilities;
            if ((combined_capabilities & caps) == caps)
                total_free_bytes += multi_heap_free_size(heap);
        }
        region = region->next;
    }
    return total_free_bytes;
}

/* Native entry: 0x42024998. */
/* Original function-byte SHA-256:
 * d4ec8696db008be11ed84331d696ba03ff8cd1c1ed47b2e582ed70c60c159205. */
/* NULL returns 0 without a dereference. Otherwise return the single cached
 * free-byte WORD at heap+4. No lock, MEMW, pool scan, metadata subtraction,
 * minimum-watermark read or accounting update. Caller owns handle validity. */
size_t multi_heap_free_size(const MultiHeap *heap)
{
    if (heap == NULL) return 0;
    return ((const volatile MultiHeap *)heap)->free_bytes;
}
