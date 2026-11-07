/* Medius v3.4.7 device — runtime capability-region registration. */
#include "../include/types.h"

/* Native entry: 0x42004228. */
/* Original function-byte SHA-256:
 * d5982cd1c9c9db43a89036448d2001f1cec4506141b456267e5c43712fbcefb8. */
/*
 * Register [start,end) with three priority capability WORDs. Reject NULL caps,
 * either zero endpoint, or signed end <= start with 0x102 before list access.
 * Scan without a reader lock; reject an existing endpoint strictly inside the
 * requested range, or an exact duplicate, with -1. A requested subrange of an
 * existing heap is allowed by this predicate; adjacency is also allowed.
 *
 * Allocate a 36-byte descriptor using caps 0x804. Allocation failure returns
 * 0x101 after free(NULL); failed multi_heap_register returns 0x104 after freeing
 * only the descriptor. Copy 12 capability bytes, initialize the embedded
 * portMUX and attach it to the new multi-heap on success. Call the ISR-context
 * helper before both critical-section entry and exit; ignore both results and
 * the infinite-timeout acquisition result. Under the writer portMUX, load the
 * old head, publish the NEW HEAD FIRST, then store new->next = old. This native
 * store order is retained; no reader synchronization or rollback is added.
 * Return 0 on success. No logging, MEMW, size upper bound or heap-content copy.
 */
int heap_caps_add_region_with_caps(const PsramHeapCapabilities *capabilities,
                                   int start, int end)
{
    if (capabilities == NULL || start == 0 || end == 0 || end <= start) return 0x102;
    for (const volatile HeapRegion *heap = HEAP_REGISTRATION_HEAD;
         heap != NULL; heap = heap->next) {
        int heap_start = heap->start;
        int heap_end = heap->end;
        if ((start < heap_start && heap_start < end) ||
            (start < heap_end && heap_end < end) ||
            (start == heap_start && end == heap_end)) return -1;
    }
    HeapRegion *created = heap_caps_malloc(36, 0x804U);
    if (created == NULL) {
        free(NULL);
        return 0x101;
    }
    memcpy(created->caps, capabilities, 12);
    volatile HeapRegion *descriptor = created;
    descriptor->start = start;
    descriptor->end = end;
    descriptor->lock_owner = 0xb33fffffU;
    descriptor->lock_count = 0;
    MultiHeap *handle = multi_heap_register((void *)(unsigned int)start,
                                          (unsigned int)end - (unsigned int)start);
    descriptor->heap = handle;
    descriptor->next = NULL;
    if (handle == NULL) {
        free(created);
        return 0x104;
    }
    multi_heap_set_lock(handle, (void *)((unsigned int)created + 20U));
    (void)xPortInIsrContext();
    (void)xPortEnterCriticalTimeout(HEAP_REGISTRATION_LOCK, -1);
    HeapRegion *old_head = HEAP_REGISTRATION_HEAD;
    HEAP_REGISTRATION_HEAD = created;
    ((volatile HeapRegion *)created)->next = old_head;
    (void)xPortInIsrContext();
    vPortExitCritical(HEAP_REGISTRATION_LOCK);
    return 0;
}
