/* Medius v3.4.7 host — memory/allocation.c.
 * Recovered C and native assembly, grouped for source navigation.
 * Original entry addresses, firmware-byte hashes and function comments follow.
 */

#include "../include/types.h"

/* Native entry: 0x4037d1ac. */
/*
 * Medius v3.4.7 — host application; 0x4037d1ac.
 *
 * Forwards the temporary buffer to free; ignores the OS context. Ownership must come from a
 * compatible allocator. It does not reset the caller pointer or report status.
 *
 * Calls: free.
 *
 * Original function-byte SHA-256:
 * b6f179e3a5a7806fe8adab372a0dc2fdd56f543232975bc71d2050fabe772f73.
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

/* Native entry: 0x4037d1b8. */
/*
 * Medius v3.4.7 — host application; 0x4037d1b8.
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
 * e5edde917db40631ad32eef7bed252d032031c68b648f21e024ae7ed51721086.
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
 *   with the paired release callback.
 */

void *get_buffer_malloc(void *unused, unsigned int requested_size,
                        unsigned int *actual_size)
{
    (void)unused;
    for (unsigned int attempts_left = 5; attempts_left != 0; --attempts_left) {
        unsigned int largest_free = heap_caps_get_largest_free_block(0x804U);
        if (largest_free <= requested_size)
            requested_size = heap_caps_get_largest_free_block(0x804U);
        requested_size = (requested_size + 3U) & 0xfffffffcU;
        void *buffer = heap_caps_malloc(requested_size, 0x804U);
        if (buffer != NULL) {
            *actual_size = requested_size;
            return buffer;
        }
    }
    *actual_size = 0;
    return NULL;
}

/* Native entry: 0x4038b1a0. */
/*
 * Medius v3.4.7 — host application; 0x4038b1a0.
 *
 * Allocates size bytes through the ESP default capability policy; returns the buffer or NULL.
 *
 * Calls: heap_caps_malloc_default.
 *
 * Called by: FUN_420070e0, pthread_key_create, FUN_42011410, FUN_42011fe4, _dtoa_r, _Balloc,
 * _Bfree, __pow5mult, usb_osal_malloc.
 *
 * Original function-byte SHA-256:
 * 12337ff5c2b237f2cd6100b99843f359e158bb0bfdb946fcfb895ed5f3ce2f3e.
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

/* Native entry: 0x4038b1ac. */
/*
 * Medius v3.4.7 — host application; 0x4038b1ac.
 *
 * Obtains the current Newlib context, rejects multiplication overflow and returns zeroed count-times-size bytes or NULL.
 *
 * Calls: heap_caps_malloc_default, bzero, __getreent.
 *
 * Called by: FUN_420108c4, FUN_4201119c, esp_task_wdt_init, task_wdt_add_entry, usb_new_phy.
 *
 * Original function-byte SHA-256:
 * f5e534092cbc82fb1cb7021ce0bc14ca69fa413779d9053a8666b51d58731862.
 */

/* Obtains the current Newlib context, rejects multiplication overflow and returns zeroed count-times-size bytes or NULL.
   Reference: ESP-IDF v5.4.4 components/newlib/heap.c. */

/*
 * count: Element count.
 * size: Element size in bytes.
 * Returns: Zero-filled allocation pointer or NULL.
 * Requirements/effects: Calls __getreent, rejects a count*size product with nonzero upper32 bits,
 *   allocates the low32-bit product under default capability policy and zeroes it through bzero.
 *   Does not explicitly set errno on the overflow path.
 */

void *calloc(size_t count, size_t size)
{
    (void)__getreent();
    unsigned long long product = (unsigned long long)count * size;
    if ((product >> 32) != 0)
        return NULL;
    unsigned int allocation_bytes = (unsigned int)product;
    void *allocation = heap_caps_malloc_default(allocation_bytes);
    if (allocation != NULL)
        bzero(allocation, allocation_bytes);
    return allocation;
}

/* Native entry: 0x4038b1d4. */
/*
 * Medius v3.4.7 — host application; 0x4038b1d4.
 *
 * Releases an ESP capability allocation; NULL is ignored by the underlying allocator.
 *
 * Calls: heap_caps_free.
 *
 * Called by: release_buffer_malloc, intr_free_for_current_cpu, FUN_42010bd4, FUN_42010c10, FUN_4201119c, FUN_4201138c,
 * FUN_42011460, FUN_42011480, FUN_420114a8, FUN_42012030, FUN_42012834, FUN_42012900,
 * FUN_420151cc, FUN_42015740, FUN_42021b34, FUN_42021bf4, FUN_42022750, FUN_420227c8,
 * FUN_42022824, FUN_4202289c, FUN_4203274c, do_allocate_gdma_channel, esp_intr_alloc_intrstatus,
 * esp_mmu_map; plus 7 other direct targets.
 *
 * Original function-byte SHA-256:
 * aaae912e1bc95d2019f4b54229a7a6b45d495fc204e836545d0be61d014d632b.
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

/* Native entry: 0x4038b1e0. */
/*
 * Medius v3.4.7 — host application; 0x4038b1e0.
 *
 * Newlib reentrant malloc wrapper. The context argument is unused because the ESP capability allocator owns allocation state.
 *
 * Calls: heap_caps_malloc_default.
 *
 * Called by: FUN_42016070, FUN_4201626c, FUN_42017108, FUN_4201a1b0, FUN_4201cf70, FUN_4201e634.
 *
 * Original function-byte SHA-256:
 * 778633f11eb2a590f1e998007dce6632f13c4af78ca42b5baae2057dc6cbebef.
 */

/* Newlib reentrant malloc wrapper. The context argument is unused because the ESP capability allocator owns allocation state.
   Reference: ESP-IDF v5.4.4 components/newlib/heap.c. */

/*
 * reent: Unused reentrancy context in this ESP allocator wrapper.
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

/* Native entry: 0x4038b1ec. */
/*
 * Medius v3.4.7 — host application; 0x4038b1ec.
 *
 * Newlib reentrant free wrapper. Ignores the context argument and releases the supplied capability allocation.
 *
 * Calls: heap_caps_free.
 *
 * Called by: FUN_42015d0c, FUN_42015dd4, FUN_4201626c, FUN_42016728, FUN_420167cc, newlib_reclaim_reent,
 * FUN_42017108, FUN_4201a1b0, FUN_4201d01c, FUN_4201e634.
 *
 * Original function-byte SHA-256:
 * e70ad89684641df58e656dabced67f81779ce561db70302fdd3fc4980eeba389.
 */

/* Newlib reentrant free wrapper. Ignores the context argument and releases the supplied capability allocation.
   Reference: ESP-IDF v5.4.4 components/newlib/heap.c. */

/*
 * reent: Unused context in this wrapper.
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

/* Native entry: 0x4038b1f8. */
/*
 * Medius v3.4.7 — host application; 0x4038b1f8.
 *
 * Newlib reentrant realloc wrapper. Uses the default ESP heap policy and does not use the context argument.
 *
 * Calls: heap_caps_realloc_default.
 *
 * Called by: FUN_4201626c, FUN_4201e634.
 *
 * Original function-byte SHA-256:
 * 54def1b603cf26f709cc630b0f52297094de3f5ad15dfd186910f686a9caba4a.
 */

/* Newlib reentrant realloc wrapper. Uses the default ESP heap policy and does not use the context argument.
   Reference: ESP-IDF v5.4.4 components/newlib/heap.c. */

/*
 * reent: Unused context in this wrapper.
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

/* Native entry: 0x4038b20c. */
/*
 * Medius v3.4.7 — host application; 0x4038b20c.
 *
 * Rejects count-times-size overflow, allocates through the default ESP policy and clears a successful buffer. The context argument is unused.
 *
 * Calls: heap_caps_malloc_default, bzero.
 *
 * Called by: _Balloc.
 *
 * Original function-byte SHA-256:
 * 9d30e7743456a5e35fe57c2dd7dbfa5f326004c045a319671802f20623dabf3e.
 */

/* Rejects count-times-size overflow, allocates through the default ESP policy and clears a successful buffer. The context argument is unused.
   Reference: ESP-IDF v5.4.4 components/newlib/heap.c. */

/*
 * reent: Unused context in this ESP wrapper.
 * count: Element count.
 * size: Element size in bytes.
 * Returns: Zero-filled allocation pointer or NULL.
 * Requirements/effects: Rejects32-bit multiplication overflow before allocation, then zeroes a
 *   successful count*size allocation through bzero. No explicit context errno write.
 */

void *_calloc_r(struct _reent *reent, size_t count, size_t size)
{
    (void)reent;
    unsigned long long product = (unsigned long long)count * size;
    if ((product >> 32) != 0)
        return NULL;
    unsigned int allocation_bytes = (unsigned int)product;
    void *allocation = heap_caps_malloc_default(allocation_bytes);
    if (allocation != NULL)
        bzero(allocation, allocation_bytes);
    return allocation;
}

