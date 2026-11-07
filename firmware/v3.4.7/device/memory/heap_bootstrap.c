/* Medius v3.4.7 device — capability heap bootstrap. */
#include "../include/types.h"

/* Native entry: 0x42003fd0. */
/* Original function-byte SHA-256:
 * 2841b28b9ca098b3e8ae49b8e97200fad46a92ebd7e04346dbe84113485c1b5d. */
/*
 * Bootstrap capability heaps before scheduler startup. Obtain available ranges
 * in a stack array, then coalesce adjacent ranges when type and raw startup-
 * stack BYTE agree. Move the earlier start into the next record, mark the
 * earlier type -1 and add sizes with 32-bit wrapping arithmetic. IRAM aliases
 * are retained, not recomputed. Allocate a second stack array of 36-byte heap
 * descriptors, skipping merged records and initializing embedded portMUXes.
 * Startup-stack heaps remain unregistered; ordinary regions assert size <=
 * 32 MiB and call multi_heap_register. Registration may leave a NULL handle.
 *
 * Level >=3 logs the header and each range. Re-read the gate for every range;
 * per-range address/size/type-name loads follow the timestamp call. Assert
 * descriptor count agreement, an initially empty global list and a nonzero
 * heap count. Search internal/8-bit-capable heaps in order for a contiguous
 * descriptor allocation of exactly 36 * heap_count bytes: this image adds no
 * owner prefix. Failure to find space asserts. Copy the stack descriptors,
 * attach locks for non-NULL heaps, then link the permanent descriptors in
 * array order. No writer lock, rollback or reinitialization support here.
 * Dynamic stack space is 16-byte aligned by the native windowed ABI; these
 * typed arrays replace Ghidra's false WindowStart/pointer arithmetic.
 */
void heap_caps_init(void)
{
    unsigned int maximum = soc_get_available_memory_region_max_count();
    SocMemoryRegion regions[maximum];
    unsigned int region_count = soc_get_available_memory_regions(regions);
    unsigned int heap_count = region_count;
    for (unsigned int i = 1; i < region_count; ++i) {
        volatile SocMemoryRegion *previous = &regions[i - 1U];
        volatile SocMemoryRegion *next = &regions[i];
        unsigned int previous_start = previous->start;
        unsigned int previous_size = previous->size;
        unsigned int next_start = next->start;
        if (next_start != previous_start + previous_size)
            continue;
        int next_type = next->type;
        int previous_type = previous->type;
        if (next_type != previous_type)
            continue;
        unsigned char next_startup_stack = next->startup_stack;
        unsigned char previous_startup_stack = previous->startup_stack;
        if (next_startup_stack != previous_startup_stack)
            continue;
        unsigned int next_size = next->size;
        next->start = previous_start;
        previous->type = -1;
        next->size = next_size + previous_size;
        --heap_count;
    }
    unsigned int descriptor_bytes = heap_count * 36U;
    HeapRegion temporary[heap_count];
    /* The linked image has separate copies of this log on the two paths. */
    if (region_count < 2U) {
        if (HEAP_LOG_LEVEL >= 3U) {
            unsigned int timestamp = esp_log_timestamp();
            ets_printf("I (%lu) %s: Initializing. RAM available for dynamic allocation:\n",
                       timestamp, HEAP_INIT_LOG_TAG);
        }
    } else {
        if (HEAP_LOG_LEVEL >= 3U) {
            unsigned int timestamp = esp_log_timestamp();
            ets_printf("I (%lu) %s: Initializing. RAM available for dynamic allocation:\n",
                       timestamp, HEAP_INIT_LOG_TAG);
        }
    }
    if (region_count == 0) __assert_func(NULL, 0, NULL, NULL);
    unsigned int heap_index = 0;
    for (unsigned int i = 0; i < region_count; ++i) {
        volatile SocMemoryRegion *region = &regions[i];
        HeapRegion *heap = (HeapRegion *)((unsigned int)temporary + heap_index * 36U);
        int type_index = region->type;
        if (type_index == -1) {
            memset(heap, 0, 36);
            continue;
        }
        if (++heap_index > heap_count) __assert_func(NULL, 0, NULL, NULL);
        const SocMemoryType *type = (const SocMemoryType *)
            ((unsigned int)SOC_MEMORY_TYPES + ((unsigned int)type_index << 4));
        memcpy(heap->caps, type->caps, 12);
        unsigned int start = region->start;
        unsigned int size = region->size;
        volatile HeapRegion *descriptor = heap;
        descriptor->lock_owner = 0xb33fffffU;
        unsigned char startup_stack = region->startup_stack;
        descriptor->end = (int)(start + size);
        descriptor->start = (int)start;
        descriptor->lock_count = 0;
        MultiHeap *handle = NULL;
        if (startup_stack == 0) {
            if (size > 0x2000000U) __assert_func(NULL, 0, NULL, NULL);
            handle = multi_heap_register((void *)start, size);
        }
        descriptor->heap = handle;
        unsigned int log_level = HEAP_LOG_LEVEL;
        descriptor->next = NULL;
        if (log_level >= 3U) {
            unsigned int timestamp = esp_log_timestamp();
            const char *name = ((const volatile SocMemoryType *)type)->name;
            unsigned int logged_size = ((const volatile SocMemoryRegion *)region)->size;
            unsigned int logged_start = ((const volatile SocMemoryRegion *)region)->start;
            ets_printf("I (%lu) %s: At %08X len %08X (%d KiB): %s\n",
                       timestamp, HEAP_INIT_LOG_TAG,
                       logged_start, logged_size, logged_size >> 10, name);
        }
    }
    if (heap_index != heap_count) __assert_func(NULL, 0, NULL, NULL);
    if (HEAP_REGISTRATION_HEAD != NULL) __assert_func(NULL, 0, NULL, NULL);
    if (heap_count == 0) __assert_func(NULL, 0, NULL, NULL);
    HeapRegion *permanent = NULL;
    for (unsigned int i = 0; i < heap_count; ++i) {
        if (heap_caps_match(&temporary[i], 0x804U)) {
            MultiHeap *handle = ((const volatile HeapRegion *)&temporary[i])->heap;
            permanent = multi_heap_malloc(handle, descriptor_bytes);
            if (permanent != NULL) break;
        }
    }
    if (permanent == NULL) __assert_func(NULL, 0, NULL, NULL);
    memcpy(permanent, temporary, descriptor_bytes);
    for (unsigned int i = 0; i < heap_count; ++i) {
        HeapRegion *heap = (HeapRegion *)((unsigned int)permanent + i * 36U);
        MultiHeap *handle = ((const volatile HeapRegion *)heap)->heap;
        if (handle != NULL)
            multi_heap_set_lock(handle, (void *)((unsigned int)heap + 20U));
        if (i == 0) {
            HeapRegion *old_head = HEAP_REGISTRATION_HEAD;
            ((volatile HeapRegion *)heap)->next = old_head;
            HEAP_REGISTRATION_HEAD = heap;
        } else {
            volatile HeapRegion *previous = &permanent[i - 1U];
            HeapRegion *old_next = previous->next;
            previous->next = heap;
            ((volatile HeapRegion *)heap)->next = old_next;
        }
    }
}

/* Native entry: 0x4200421c. */
/* Original function-byte SHA-256:
 * 6c90666a2d4d126dca5b67e25edb30e34244c6f685524d2034890fc22c5f9ca9. */
/* Startup-table hook: initialize all capability heaps, then return 0.
 * No parameters, extra hardware work or error conversion; fatal assertions
 * in heap_caps_init prevent this return. */
int heap_startup_init(void)
{
    heap_caps_init();
    return 0;
}
