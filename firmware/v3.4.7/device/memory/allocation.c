/* Medius v3.4.7 device — memory/allocation.c.
 * Recovered C and native assembly, grouped for source navigation.
 * Original entry addresses, firmware-byte hashes and function comments follow.
 */

#include "../include/types.h"

/* Native entry: 0x4037ea44. */
/*
 * Medius v3.4.7 — device application; 0x4037ea44.
 *
 * Forwards the temporary buffer to free; ignores the OS context. Ownership must come from a
 * compatible allocator. It does not reset the caller pointer or report status.
 *
 * Calls: free.
 *
 * Original function-byte SHA-256:
 * 84a421986c73e49cb070b2ca8c996ec319506e402fd7441b6f36df1b76cb0b6a.
 */

/* Reference: ESP-IDF v5.4.4 components/spi_flash/spi_flash_os_func_app.c. */

/*
 * unused: Unused OS context; not dereferenced.
 * buffer: Buffer accepted by the compatible free implementation; NULL follows that allocator
 *   contract.
 * Returns: Nothing.
 * Requirements/effects: Forwards ownership release to free. Does not clear the caller pointer or
 *   report status.
 */

void release_buffer_malloc(void *unused, void *buffer)
{
    (void)unused;
    free(buffer);
}

/* Native entry: 0x4037ea50. */
/*
 * Medius v3.4.7 — device application; 0x4037ea50.
 *
 * Tries at most five internal byte-accessible allocations with capability 0x804. Each attempt
 * clamps to the largest-free-block query (the compiled <= path queries again), then rounds up to
 * four-byte alignment. Requires a valid actual_size pointer and stores the chosen size on success
 * or 0 after failure. Rounding up may itself make a tight-fit attempt fail; no lock covers the
 * size query and allocation together.
 *
 * Calls: heap_caps_malloc, heap_caps_get_largest_free_block.
 *
 * Original function-byte SHA-256:
 * 365d84a9e66486f63a8c485ff34676d4c2cafbab25a7cb78ed28899685699b42.
 */

/* Reference: ESP-IDF v5.4.4 components/spi_flash/spi_flash_os_func_app.c. */

/*
 * unused: Unused OS context; not dereferenced.
 * requested_size: Desired byte count, clamped to the largest internal byte-accessible block and
 *   rounded up to4 bytes on each attempt.
 * actual_size: Required writable uint32 output; chosen size on success,0 after all failures.
 * Returns: Allocated buffer, or NULL after at most5 attempts.
 * Requirements/effects: Uses capability mask0x804. The size query and allocation are not one
 *   locked transaction, and rounding can make a tight-fit attempt fail. Caller releases success
 *   with the paired release callback. Addition wraps32 before alignment; a size near UINT32_MAX
 *   can become zero. A successful zero-byte allocation still reports actual_size=0.
 */

void *get_buffer_malloc(void *unused, unsigned int requested_size,
    unsigned int *actual_size)
{
    (void)unused;
    void *buffer = NULL;
    for (unsigned int attempts_remaining = 5; attempts_remaining != 0;
         --attempts_remaining) {
        unsigned int largest_free = heap_caps_get_largest_free_block(0x804U);
        if (largest_free <= requested_size)
            requested_size = heap_caps_get_largest_free_block(0x804U);
        requested_size = (requested_size + 3U) & ~3U;
        buffer = heap_caps_malloc(requested_size, 0x804U);
        if (buffer != NULL)
            break;
    }
    *actual_size = buffer != NULL ? requested_size : 0;
    return buffer;
}

/* Native entry: 0x4038f9f8. */
/*
 * Medius v3.4.7 — device application; 0x4038f9f8.
 *
 * Allocates size bytes through the ESP default capability policy; returns the buffer or NULL.
 *
 * Calls: heap_caps_malloc_default.
 *
 * Called by: FUN_42007514, pthread_key_create, pthread_setspecific, FUN_4200ef10, FUN_4200fbd8, FUN_42012a0c,
 * FUN_4201320c, FUN_42013580, FUN_42013724, FUN_42013ec4, FUN_42014674, FUN_42014704,
 * FUN_42014918, FUN_42014b88, FUN_42015ecc, FUN_4201625c, FUN_42017e34, FUN_42017ee4,
 * _dtoa_r, _Balloc, _Bfree, __pow5mult.
 *
 * Original function-byte SHA-256:
 * cb1e92ffeb30398fe484c8c8437f591f26272fb16a9069e8ad4a336905bba89e.
 */

/* Allocates size bytes through the ESP default capability policy; returns the buffer or NULL.
   Reference: ESP-IDF v5.4.4 components/newlib/heap.c. */

/*
 * size: Requested payload bytes under the ESP default heap capability policy.
 * Returns: Allocation pointer or NULL.
 * Requirements/effects: Delegates to heap_caps_malloc_default. Does not zero memory or explicitly
 *   write errno in this wrapper.
 */

void *malloc(size_t size)
{
    return heap_caps_malloc_default(size);
}

/* Native entry: 0x4038fa04. */
/*
 * Medius v3.4.7 — device application; 0x4038fa04.
 *
 * Obtains the current Newlib context, rejects multiplication overflow and returns zeroed count-times-size bytes or NULL.
 *
 * Calls: heap_caps_malloc_default, __getreent, bzero.
 *
 * Called by: pthread_setspecific, FUN_4200e3c4, FUN_4200ec9c, FUN_42012f38, esp_task_wdt_init,
 * task_wdt_add_entry, usb_new_phy.
 *
 * Original function-byte SHA-256:
 * 520c3dcf7bf4578f6d8fee806ac072f27e29cd3257efe88dded038ce6d62b54b.
 */

/* Obtains the current Newlib context, rejects multiplication overflow and returns zeroed count-times-size bytes or NULL.
   Reference: ESP-IDF v5.4.4 components/newlib/heap.c. */

/*
 * count: Element count.
 * size: Element size in bytes.
 * Returns: Zero-filled allocation pointer or NULL.
 * Requirements/effects: Calls __getreent, rejects a count*size product with nonzero upper32 bits,
 *   allocates the low32-bit product under default capability policy and zeroes it through bzero.
 *   Does not explicitly set errno on the overflow path. A zero product still calls the allocator
 *   and, for a non-NULL result, bzero with length0.
 */

void *calloc(size_t count, size_t size)
{
    (void)__getreent();
    unsigned long long total_bytes = (unsigned long long)count * size;
    if ((total_bytes >> 32) != 0)
        return NULL;
    void *allocation = heap_caps_malloc_default((unsigned int)total_bytes);
    if (allocation != NULL)
        bzero(allocation, (unsigned int)total_bytes);
    return allocation;
}

/* Native entry: 0x4038fa2c. */
/*
 * Medius v3.4.7 — device application; 0x4038fa2c.
 *
 * Releases an ESP capability allocation; NULL is ignored by the underlying allocator.
 *
 * Calls: heap_caps_free.
 *
 * Called by: release_buffer_malloc, FUN_42004228, intr_free_for_current_cpu, pthread_cleanup_value_list, pthread_setspecific, FUN_4200e6d4,
 * FUN_4200e710, FUN_4200ec9c, FUN_4200ee8c, FUN_4200ef60, FUN_4200ef80, FUN_4200efa8,
 * FUN_4200fc24, FUN_42010508, FUN_420105d4, FUN_42011b00, FUN_420129fc, FUN_42012c0c,
 * FUN_42012f38, FUN_42012fb4, FUN_42013018, FUN_420131ac, FUN_420132b4, FUN_42013580; plus 26
 * other direct targets.
 *
 * Original function-byte SHA-256:
 * b236324a965800ced0b7a6c2d141620a17b7713ccaa150ae95361142e3469664.
 */

/* Releases an ESP capability allocation; NULL is ignored by the underlying allocator.
   Reference: ESP-IDF v5.4.4 components/newlib/heap.c. */

/*
 * buffer: Owned ESP capability allocation or NULL.
 * Returns: Nothing.
 * Requirements/effects: Delegates to heap_caps_free. Does not erase memory, clear the caller
 *   pointer or validate a stale/double-free pointer here.
 */

void free(void *buffer)
{
    heap_caps_free(buffer);
}

/* Native entry: 0x4038fa38. */
/*
 * Medius v3.4.7 — device application; 0x4038fa38.
 *
 * Newlib reentrant malloc wrapper. The context argument is unused because the ESP capability allocator owns allocation state.
 *
 * Calls: heap_caps_malloc_default.
 *
 * Called by: FUN_42018504, FUN_42018700, FUN_4201959c, FUN_4201c644, FUN_4201f404, FUN_42020ac8.
 *
 * Original function-byte SHA-256:
 * 2ea83dccd2769869736c8f4370c3b7161f607e7f1f654919b9010e97f50a5b5f.
 */

/* Newlib reentrant malloc wrapper. The context argument is unused because the ESP capability allocator owns allocation state.
   Reference: ESP-IDF v5.4.4 components/newlib/heap.c. */

/*
 * reent: Unused opaque SDK struct _reent pointer; no member is accessed.
 * size: Requested payload bytes.
 * Returns: Allocation pointer or NULL.
 * Requirements/effects: Uses the ESP default capability allocator; does not maintain separate
 *   context heap state or explicitly write context errno.
 */

void *_malloc_r(struct _reent *reent, size_t size)
{
    (void)reent;
    return heap_caps_malloc_default(size);
}

/* Native entry: 0x4038fa44. */
/*
 * Medius v3.4.7 — device application; 0x4038fa44.
 *
 * Newlib reentrant free wrapper. Ignores the context argument and releases the supplied capability allocation.
 *
 * Calls: heap_caps_free.
 *
 * Called by: FUN_420181a0, FUN_42018268, FUN_42018700, FUN_42018bbc, FUN_42018c60, newlib_reclaim_reent,
 * FUN_4201959c, FUN_4201c644, FUN_4201f4b0, FUN_42020ac8.
 *
 * Original function-byte SHA-256:
 * 8285a6138cabecd870b70f75a964999eb30215ca72103dcc9eb682d369475cb1.
 */

/* Newlib reentrant free wrapper. Ignores the context argument and releases the supplied capability allocation.
   Reference: ESP-IDF v5.4.4 components/newlib/heap.c. */

/*
 * reent: Unused opaque SDK struct _reent pointer; no member is accessed.
 * buffer: Owned capability allocation or NULL.
 * Returns: Nothing.
 * Requirements/effects: Forwards to heap_caps_free; no separate per-context allocation state or
 *   payload wipe.
 */

void _free_r(struct _reent *reent, void *buffer)
{
    (void)reent;
    heap_caps_free(buffer);
}

/* Native entry: 0x4038fa50. */
/*
 * Medius v3.4.7 — device application; 0x4038fa50.
 *
 * Newlib reentrant realloc wrapper. Uses the default ESP heap policy and does not use the context argument.
 *
 * Calls: heap_caps_realloc_default.
 *
 * Called by: FUN_42018700, FUN_42020ac8.
 *
 * Original function-byte SHA-256:
 * cf2c8989d24031f27353df20fad191d44f890f205c4952b9ee5bdf9697a22d86.
 */

/* Newlib reentrant realloc wrapper. Uses the default ESP heap policy and does not use the context argument.
   Reference: ESP-IDF v5.4.4 components/newlib/heap.c. */

/*
 * reent: Unused opaque SDK struct _reent pointer; no member is accessed.
 * buffer: Owned allocation or NULL.
 * size: New payload bytes; zero releases an existing allocation.
 * Returns: Replacement pointer or NULL.
 * Requirements/effects: Uses heap_caps_realloc_default. Nonzero-size allocation failure leaves the
 *   original allocation owned by the caller; no explicit errno write here.
 */

void *_realloc_r(struct _reent *reent, void *buffer, size_t size)
{
    (void)reent;
    return heap_caps_realloc_default(buffer, size);
}

/* Native entry: 0x4038fa64. */
/*
 * Medius v3.4.7 — device application; 0x4038fa64.
 *
 * Rejects count-times-size overflow, allocates through the default ESP policy and clears a successful buffer. The context argument is unused.
 *
 * Calls: heap_caps_malloc_default, bzero.
 *
 * Called by: _Balloc.
 *
 * Original function-byte SHA-256:
 * 1a5b2c84824b840173b53bd3736ae0d15fb6e5d5b89ca0f8afcf55d465fdb93b.
 */

/* Rejects count-times-size overflow, allocates through the default ESP policy and clears a successful buffer. The context argument is unused.
   Reference: ESP-IDF v5.4.4 components/newlib/heap.c. */

/*
 * reent: Unused opaque SDK struct _reent pointer; no member is accessed.
 * count: Element count.
 * size: Element size in bytes.
 * Returns: Zero-filled allocation pointer or NULL.
 * Requirements/effects: Rejects32-bit multiplication overflow before allocation, then zeroes a
 *   successful count*size allocation through bzero. No __getreent call or explicit context errno
 *   write occurs here. A zero product still allocates and conditionally calls bzero with length0.
 */

void *_calloc_r(struct _reent *reent, size_t count, size_t size)
{
    (void)reent;
    unsigned long long total_bytes = (unsigned long long)count * size;
    if ((total_bytes >> 32) != 0)
        return NULL;
    void *allocation = heap_caps_malloc_default((unsigned int)total_bytes);
    if (allocation != NULL)
        bzero(allocation, (unsigned int)total_bytes);
    return allocation;
}

