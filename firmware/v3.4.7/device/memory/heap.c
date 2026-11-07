/* Medius v3.4.7 device — memory/heap.c.
 * Recovered C and native assembly, grouped for source navigation.
 * Original entry addresses, firmware-byte hashes and function comments follow.
 */

#include "../include/types.h"

/* Native entry: 0x40376548. */
/*
 * Medius v3.4.7 — device application; 0x40376548.
 *
 * Invokes the registered allocation-failure callback with the failed size, capability mask and allocator name. This build does not abort here.
 *
 * Called by: heap_caps_malloc, heap_caps_malloc_default, heap_caps_realloc_default, heap_caps_calloc.
 *
 * Indirect call: the registered allocation-failure callback.
 *
 * Original function-byte SHA-256:
 * eb353e80cc10d538fe609087046e8f3610cf7a09102d6e2bfcc5a3aa72860f57.
 */

/* Invokes the registered allocation-failure callback with the failed size, capability mask and allocator name. This build does not abort here.
   SDK match: ESP-IDF v5.4.4 components/heap/heap_caps.c. */

/*
 * size: Requested allocation bytes reported to the failure hook.
 * caps: Requested capability mask reported to the hook.
 * function_name: Allocator name pointer passed unchanged to the hook.
 * Returns: Nothing.
 * Requirements/effects: Snapshots the callback once, then calls it synchronously when present. This build does not
 *   abort here, validate the callback/name or provide recovery. Hook runs in the caller allocation
 *   context.
 */

void heap_caps_alloc_failed(unsigned int size, unsigned int caps, const char *function_name)
{
    HeapAllocationFailureCallback callback = HEAP_ALLOCATION_FAILURE_CALLBACK;
    if (callback != NULL)
        callback(size, caps, function_name);
}

/* Native entry: 0x40376560. */
/*
 * Medius v3.4.7 — device application; 0x40376560.
 *
 * Allocates from matching capability heaps; reports a nonzero-size allocation failure through the failure callback.
 *
 * Calls: heap_caps_alloc_failed, heap_caps_malloc_base.
 *
 * Called by: get_buffer_malloc, FUN_42004228, get_desc_for_int, rtc_isr_register, FUN_42008a44, FUN_42017464,
 * FUN_42039bd0, FUN_42039cdc, esp_intr_alloc_intrstatus, device_workers_init, pvPortMalloc.
 *
 * Original function-byte SHA-256:
 * 2ea7c171b80f22b3922ab8b2885e8575bbcd400093fcbe042bcd4efec43db2f2.
 */

/* Allocates from matching capability heaps; reports a nonzero-size allocation failure through the failure callback.
   SDK match: ESP-IDF v5.4.4 components/heap/heap_caps.c. */

/*
 * size: Requested payload bytes; zero-size failure does not notify.
 * caps: Required capability mask.
 * Returns: Allocated payload pointer or NULL.
 * Requirements/effects: Delegates to heap_caps_malloc_base and invokes the failure hook only for
 *   NULL with nonzero size. No zero-fill or capability relaxation.
 */

void *heap_caps_malloc(unsigned int size, unsigned int caps)
{
    void *allocation = heap_caps_malloc_base(size, caps);
    if (allocation == NULL && size != 0)
        heap_caps_alloc_failed(size, caps, "heap_caps_malloc");
    return allocation;
}

/* Native entry: 0x40376580. */
/*
 * Medius v3.4.7 — device application; 0x40376580.
 *
 * Uses the default internal/external-memory threshold policy, then retries with unrestricted default capabilities before reporting failure.
 *
 * Calls: heap_caps_alloc_failed, heap_caps_malloc_base.
 *
 * Called by: malloc, calloc, _malloc_r, _calloc_r.
 *
 * Original function-byte SHA-256:
 * b34a3e174bcdce46f3241f0458d75caa9b5d603653c68bbe3af8b7569bcd2ec5.
 */

/* Uses the default internal/external-memory threshold policy, then retries with unrestricted default capabilities before reporting failure.
   SDK match: ESP-IDF v5.4.4 components/heap/heap_caps.c. */

/*
 * size: Requested payload bytes.
 * Returns: Allocation pointer or NULL.
 * Requirements/effects: Snapshots the threshold once. UINT32_MAX selects DEFAULT|INTERNAL (0x1800) directly. Otherwise
 *   requests DEFAULT|SPIRAM (0x1400) above the threshold or0x1800 below/equal, then retries
 *   DEFAULT (0x1000) only after a nonzero-size failure. The failure hook reports the final policy
 *   mask. Does not zero-fill.
 */

void *heap_caps_malloc_default(unsigned int size)
{
    unsigned int threshold = HEAP_INTERNAL_ALLOCATION_THRESHOLD;
    if (threshold == 0xffffffffU) {
        void *allocation = heap_caps_malloc_base(size, 0x1800U);
        if (allocation == NULL && size != 0)
            heap_caps_alloc_failed(size, 0x1800U, "heap_caps_malloc");
        return allocation;
    }
    unsigned int capabilities = size > threshold ? 0x1400U : 0x1800U;
    void *allocation = heap_caps_malloc_base(size, capabilities);
    if (allocation == NULL && size != 0) {
        allocation = heap_caps_malloc_base(size, 0x1000U);
        if (allocation == NULL)
            heap_caps_alloc_failed(size, 0x1000U, "heap_caps_malloc_default");
    }
    return allocation;
}

/* Native entry: 0x403765f0. */
/*
 * Medius v3.4.7 — device application; 0x403765f0.
 *
 * Reallocates using the default internal/external-memory threshold policy; retries default capabilities on nonzero-size failure.
 *
 * Calls: heap_caps_alloc_failed, heap_caps_realloc_base.
 *
 * Called by: _realloc_r.
 *
 * Original function-byte SHA-256:
 * a0251a755b4bcbec25449699f8116252bbf75a84b929cba13ae54aeea3b8aa1d.
 */

/* Reallocates using the default internal/external-memory threshold policy; retries default capabilities on nonzero-size failure.
   SDK match: ESP-IDF v5.4.4 components/heap/heap_caps.c. */

/*
 * buffer: Owned allocation or NULL.
 * size: New payload bytes; zero frees an existing allocation through the base helper.
 * Returns: Replacement pointer, or NULL on failure/zero-size release.
 * Requirements/effects: Snapshots the threshold once, using the same policy and fallback masks as
 *   default malloc. A nonzero-size failure preserves the old allocation; reports only after the
 *   final failed attempt. Does not zero newly added bytes.
 */

void *heap_caps_realloc_default(void *buffer, unsigned int size)
{
    unsigned int threshold = HEAP_INTERNAL_ALLOCATION_THRESHOLD;
    if (threshold == 0xffffffffU) {
        void *replacement = heap_caps_realloc_base(buffer, size, 0x1800U);
        if (replacement == NULL && size != 0)
            heap_caps_alloc_failed(size, 0x1800U, "heap_caps_realloc");
        return replacement;
    }
    unsigned int capabilities = size > threshold ? 0x1400U : 0x1800U;
    void *replacement = heap_caps_realloc_base(buffer, size, capabilities);
    if (replacement == NULL && size != 0) {
        replacement = heap_caps_realloc_base(buffer, size, 0x1000U);
        if (replacement == NULL)
            heap_caps_alloc_failed(size, 0x1000U, "heap_caps_realloc_default");
    }
    return replacement;
}

/* Native entry: 0x40376664. */
/*
 * Medius v3.4.7 — device application; 0x40376664.
 *
 * Requests zeroed count-times-size bytes with the given capabilities and reports allocation failure through the registered callback.
 *
 * Calls: heap_caps_alloc_failed, heap_caps_calloc_base.
 *
 * Called by: FUN_42010508, esp_timer_create, FUN_42011a04, FUN_420162d4, gptimer_new_timer,
 * do_allocate_gdma_channel, esp_mmu_map.
 *
 * Original function-byte SHA-256:
 * 6a8af0a04bdf8ec1e6f1c5a3187feafc2d81b17f564c9a47d66b53ec1c2f2bf6.
 */

/* Requests zeroed count-times-size bytes with the given capabilities and reports allocation failure through the registered callback.
   SDK match: ESP-IDF v5.4.4 components/heap/heap_caps.c. */

/*
 * count: Number of elements.
 * size: Bytes per element.
 * caps: Required allocation capabilities.
 * Returns: Zero-filled allocation pointer or NULL.
 * Requirements/effects: Base helper rejects32-bit multiplication overflow. This wrapper reports
 *   failure when element size is nonzero, even if count is0; hook size is the low32-bit product on
 *   overflow.
 */

void *heap_caps_calloc(unsigned int count, unsigned int size, unsigned int caps)
{
    void *allocation = heap_caps_calloc_base(count, size, caps);
    if (allocation == NULL && size != 0)
        heap_caps_alloc_failed(count * size, caps, "heap_caps_calloc");
    return allocation;
}

/* Native entry: 0x40376688. */
/*
 * Medius v3.4.7 — device application; 0x40376688.
 *
 * Frees a capability allocation. NULL is ignored; executable IRAM aliases recover the DRAM pointer stored before the allocation. An invalid owning heap asserts.
 *
 * Calls: multi_heap_free, __assert_func.
 *
 * Called by: heap_caps_realloc_base, vPortFree, free, _free_r, FUN_42008a44.
 *
 * Original function-byte SHA-256:
 * a0ebf074294805a4d43a1d9c0eabe033e4f1d43e46f8b433925020558f633f4e.
 */

/* Frees a capability allocation. NULL is ignored; executable IRAM aliases recover the DRAM pointer stored before the allocation. An invalid owning heap asserts.
   SDK match: ESP-IDF v5.4.4 components/heap/heap_caps_base.c. */

/*
 * buffer: Live capability allocation payload, or NULL.
 * Returns: Nothing.
 * Requirements/effects: NULL is ignored. For executable aliases in the compiled IRAM range, reads
 *   the original DRAM allocation pointer from the preceding word. Finds a registered containing
 *   heap using signed start-inclusive/end-exclusive comparisons, asserts if absent, then frees
 *   through its cached heap handle. Alias-header address arithmetic wraps32; the recovered pointer
 *   is not checked for NULL again. No synchronization or MEMW is added. Does not wipe or clear the
 *   caller pointer.
 */

void heap_caps_free(void *buffer)
{
    if (buffer == NULL)
        return;
    unsigned int address = (unsigned int)buffer;
    if (address - 0x40378000U < 0x68000U)
        buffer = *(void *const volatile *)(address - 4U);
    const volatile HeapRegion *region = HEAP_REGISTRATION_HEAD;
    while (region != NULL) {
        MultiHeap *heap = region->heap;
        if (heap != NULL && region->start <= (int)(unsigned int)buffer &&
            (int)(unsigned int)buffer < region->end) {
            multi_heap_free(heap, buffer);
            return;
        }
        region = region->next;
    }
    __assert_func(NULL, 0, NULL, NULL);
}

/* Native entry: 0x403766d0. */
/*
 * Medius v3.4.7 — device application; 0x403766d0.
 *
 * Adjusts hardware alignment, rejects invalid/oversized requests and incompatible executable-memory capabilities, then searches three capability-priority levels. Executable aliases retain the DRAM allocation pointer.
 *
 * Calls: esp_heap_adjust_alignment_to_hw, multi_heap_aligned_alloc_offs, multi_heap_malloc, __assert_func.
 *
 * Called by: heap_caps_malloc_base, heap_caps_realloc_base.
 *
 * Original function-byte SHA-256:
 * 36d2ab400496ef728579de3bca665dbf95fc3b2b267b8ef98fea75764e34d2bf.
 */

/* Adjusts hardware alignment, rejects invalid/oversized requests and incompatible executable-memory capabilities, then searches three capability-priority levels. Executable aliases retain the DRAM allocation pointer.
   SDK match: ESP-IDF v5.4.4 components/heap/heap_caps_base.c. */

/*
 * alignment: Requested alignment, adjusted for hardware. Values at most4 use ordinary allocation;
 *   larger alignments are checked by the lower aligned allocator.
 * size: Requested bytes, adjusted before the zero/32MiB bound check.
 * caps: Required heap capabilities, adjusted by the hardware-policy helper.
 * Returns: Allocation pointer or NULL. Executable alias allocations return one word past a header
 *   holding the DRAM allocation address.
 * Requirements/effects: Searches registered heaps across three capability priorities, requiring
 *   one matching bit at that priority and all requested bits across the heap capability union.
 *   EXEC rejects8BIT/DMA and adds32BIT;32BIT rounds size to4. Alias conversion allocates an
 *   extra4-byte header and checks native address ranges/alignment. Larger requested alignment
 *   applies before this header adjustment; do not infer extra alignment of the returned alias.
 *   Priority traversal reloads the list head for each of three passes. Capability reads are the
 *   current-priority word, then priority1, priority0, priority2; mask0 finds no matching heap.
 *   Does not call failure hooks or zero-fill.
 */

void *heap_caps_aligned_alloc_base(unsigned int alignment, unsigned int size, unsigned int caps)
{
    unsigned int adjusted_alignment = alignment;
    unsigned int adjusted_size = size;
    unsigned int adjusted_caps = caps;
    esp_heap_adjust_alignment_to_hw(&adjusted_alignment, &adjusted_size, &adjusted_caps);
    if (adjusted_size - 1U > 0x01ffffffU)
        return NULL;
    if ((adjusted_caps & 1U) != 0) {
        if ((adjusted_caps & 0x0cU) != 0)
            return NULL;
        adjusted_caps |= 2U;
    }
    if ((adjusted_caps & 2U) != 0)
        adjusted_size = (adjusted_size + 3U) & ~3U;
    for (unsigned int priority = 0; priority < 3; ++priority) {
        const volatile HeapRegion *region = HEAP_REGISTRATION_HEAD;
        while (region != NULL) {
            MultiHeap *heap = region->heap;
            if (heap != NULL) {
                unsigned int priority_capabilities = region->caps[priority];
                if ((adjusted_caps & priority_capabilities) != 0) {
                    unsigned int priority_1_capabilities = region->caps[1];
                    unsigned int priority_0_capabilities = region->caps[0];
                    unsigned int priority_2_capabilities = region->caps[2];
                    unsigned int all_capabilities = priority_1_capabilities |
                        priority_0_capabilities | priority_2_capabilities;
                    if ((all_capabilities & adjusted_caps) == adjusted_caps) {
                        bool executable_alias = false;
                        if ((adjusted_caps & 1U) != 0)
                            executable_alias = (unsigned int)region->start - 0x3fc88000U < 0x68000U;
                        unsigned int allocation_size = adjusted_size + (executable_alias ? 4U : 0U);
                        void *allocation;
                        if (adjusted_alignment <= 4U)
                            allocation = multi_heap_malloc(heap, allocation_size);
                        else
                            allocation = multi_heap_aligned_alloc_offs(heap, allocation_size,
                                adjusted_alignment, 0);
                        if (allocation != NULL) {
                            if (!executable_alias)
                                return allocation;
                            unsigned int dram_address = (unsigned int)allocation;
                            unsigned int allocation_end = dram_address + adjusted_size + 4U;
                            bool start_in_dram = dram_address - 0x3fc88000U < 0x68000U;
                            bool start_in_rtc = dram_address - 0x600fe000U < 0x2000U;
                            bool last_word_in_dram = allocation_end - 0x3fc88004U < 0x68000U;
                            bool last_word_in_rtc = allocation_end - 0x600fe004U < 0x2000U;
                            if ((!start_in_dram && !start_in_rtc) ||
                                (!last_word_in_dram && !last_word_in_rtc) ||
                                ((dram_address | allocation_end) & 3U) != 0)
                                __assert_func(NULL, 0, NULL, NULL);
                            unsigned int header_address = dram_address;
                            if (!start_in_rtc)
                                header_address += 0x006f0000U;
                            *(volatile unsigned int *)header_address = dram_address;
                            return (void *)(header_address + 4U);
                        }
                    }
                }
            }
            region = region->next;
        }
    }
    return NULL;
}

/* Native entry: 0x403767ec. */
/*
 * Medius v3.4.7 — device application; 0x403767ec.
 *
 * Calls the capability aligned allocator with four-byte alignment; does not itself call the allocation-failure hook.
 *
 * Calls: heap_caps_aligned_alloc_base.
 *
 * Called by: heap_caps_malloc, heap_caps_malloc_default, heap_caps_calloc_base.
 *
 * Original function-byte SHA-256:
 * 75b683b35a7bf2d9d02fc09188ad9f9f638e949646421af40acba2d6b0fd60ea.
 */

/* Calls the capability aligned allocator with four-byte alignment; does not itself call the allocation-failure hook.
   SDK match: ESP-IDF v5.4.4 components/heap/heap_caps_base.c. */

/*
 * size: Requested payload bytes.
 * caps: Required capability mask.
 * Returns: Allocation pointer or NULL.
 * Requirements/effects: Forwards to the capability allocator with alignment4. Does not invoke the
 *   allocation-failure hook itself.
 */

void *heap_caps_malloc_base(unsigned int size, unsigned int caps)
{
    return heap_caps_aligned_alloc_base(4, size, caps);
}

/* Native entry: 0x403767fc. */
/*
 * Medius v3.4.7 — device application; 0x403767fc.
 *
 * Handles NULL as allocation and zero size as free. Tries in-place resizing on a compatible heap, otherwise allocates, copies the smaller byte count and frees the old block only after success.
 *
 * Calls: heap_caps_free, heap_caps_aligned_alloc_base, esp_heap_adjust_alignment_to_hw, multi_heap_get_allocated_size, multi_heap_realloc, __assert_func,
 * memcpy.
 *
 * Called by: heap_caps_realloc_default.
 *
 * Original function-byte SHA-256:
 * b3952aaa8a76979f9f71f9355c49cc1045c5dbfee7e0d66566cda5aeeff8f199.
 */

/* Handles NULL as allocation and zero size as free. Tries in-place resizing on a compatible heap, otherwise allocates, copies the smaller byte count and frees the old block only after success.
   SDK match: ESP-IDF v5.4.4 components/heap/heap_caps_base.c. */

/*
 * buffer: Owned capability allocation or NULL.
 * size: Requested bytes before hardware adjustment; adjusted zero frees an existing allocation.
 * caps: Required capabilities for the replacement.
 * Returns: Replacement pointer, or NULL for zero-size release, oversize rejection or allocation
 *   failure.
 * Requirements/effects: Finds and validates the original heap, recovering executable-alias header
 *   pointers. Direct realloc is attempted only for non-aliased memory with compatible capabilities
 *   and alignment at most4. Otherwise allocates, copies min(old usable size,new adjusted size),
 *   and frees the old block only after success. Invalid original metadata/owner or zero old usable
 *   size on a successful replacement asserts. For an executable alias, the old capacity comes
 *   from the DRAM allocation including its pointer-header space; native code does not subtract
 *   that header before selecting the copy length. Nonzero-size failure preserves the old block; no
 *   failure hook is called here. The capability union is read in priority1, priority0, priority2
 *   order even for an alias. After replacement allocation, ordinary incompatible owners have two
 *   fresh heap-handle reads; direct candidates and aliases have one.
 */

void *heap_caps_realloc_base(void *buffer, unsigned int size, unsigned int caps)
{
    unsigned int adjusted_alignment = 4;
    unsigned int adjusted_size = size;
    unsigned int adjusted_caps = caps;
    esp_heap_adjust_alignment_to_hw(&adjusted_alignment, &adjusted_size, &adjusted_caps);
    if (buffer == NULL)
        return heap_caps_aligned_alloc_base(adjusted_alignment, adjusted_size, adjusted_caps);
    if (adjusted_size == 0) {
        heap_caps_free(buffer);
        return NULL;
    }
    if (adjusted_size > 0x02000000U)
        return NULL;
    const volatile HeapRegion *owner = HEAP_REGISTRATION_HEAD;
    unsigned int buffer_address = (unsigned int)buffer;
    bool executable_alias = buffer_address - 0x40378000U < 0x68000U;
    void *dram_pointer = NULL;
    if (executable_alias)
        dram_pointer = *(void *const volatile *)(buffer_address - 4U);
    void *owner_pointer = executable_alias ? dram_pointer : buffer;
    MultiHeap *heap = NULL;
    while (owner != NULL) {
        heap = owner->heap;
        if (heap != NULL && owner->start <= (int)(unsigned int)owner_pointer &&
            (int)(unsigned int)owner_pointer < owner->end)
            break;
        owner = owner->next;
    }
    if (owner == NULL)
        __assert_func(NULL, 0, NULL, NULL);
    unsigned int priority_1_capabilities = owner->caps[1];
    unsigned int priority_0_capabilities = owner->caps[0];
    unsigned int priority_2_capabilities = owner->caps[2];
    unsigned int all_capabilities = priority_1_capabilities |
        priority_0_capabilities | priority_2_capabilities;
    bool direct_candidate = (all_capabilities & adjusted_caps) == adjusted_caps &&
        !executable_alias;
    if (direct_candidate && adjusted_alignment <= 4U) {
        void *resized = multi_heap_realloc(heap, buffer, adjusted_size);
        if (resized != NULL)
            return resized;
    }
    void *replacement = heap_caps_aligned_alloc_base(adjusted_alignment,
        adjusted_size, adjusted_caps);
    if (replacement == NULL)
        return NULL;
    MultiHeap *capacity_heap = owner->heap;
    if (!direct_candidate && !executable_alias)
        capacity_heap = owner->heap;
    unsigned int old_payload_size = multi_heap_get_allocated_size(capacity_heap,
        executable_alias ? dram_pointer : buffer);
    if (old_payload_size == 0)
        __assert_func(NULL, 0, NULL, NULL);
    unsigned int copy_size = old_payload_size < adjusted_size ? old_payload_size : adjusted_size;
    memcpy(replacement, buffer, copy_size);
    heap_caps_free(buffer);
    return replacement;
}

/* Native entry: 0x40376924. */
/*
 * Medius v3.4.7 — device application; 0x40376924.
 *
 * Rejects a 32-bit multiplication overflow, allocates count-times-size bytes and zeroes a successful allocation.
 *
 * Calls: heap_caps_malloc_base, memset.
 *
 * Called by: heap_caps_calloc.
 *
 * Original function-byte SHA-256:
 * 706717f96ee7b3d4f49481967c5321eaf6d628a284be67fc8f78dc47106de0b4.
 */

/* Rejects a 32-bit multiplication overflow, allocates count-times-size bytes and zeroes a successful allocation.
   SDK match: ESP-IDF v5.4.4 components/heap/heap_caps_base.c. */

/*
 * count: Element count used in a64-bit product.
 * size: Bytes per element.
 * caps: Required allocation capability mask.
 * Returns: Zero-filled allocation pointer or NULL.
 * Requirements/effects: Rejects any product with a nonzero upper32 bits before allocation. On
 *   success zeroes exactly count*size bytes. Does not invoke the failure hook.
 */

void *heap_caps_calloc_base(unsigned int count, unsigned int size, unsigned int caps)
{
    unsigned long long total_bytes = (unsigned long long)count * size;
    if ((total_bytes >> 32) != 0)
        return NULL;
    void *allocation = heap_caps_malloc_base((unsigned int)total_bytes, caps);
    if (allocation != NULL)
        memset(allocation, 0, (unsigned int)total_bytes);
    return allocation;
}

/* Native entry: 0x4037dc60. */
/*
 * Medius v3.4.7 — device application; 0x4037dc60.
 *
 * Applies cache, SIMD and encrypted-DMA alignment requirements, rounds size and normalizes descriptor/cache-only capability flags. Marks invalid capabilities when cache alignment cannot be obtained.
 *
 * Calls: efuse_hal_flash_encryption_enabled, esp_cache_get_alignment.
 *
 * Called by: heap_caps_aligned_alloc_base, heap_caps_realloc_base.
 *
 * Original function-byte SHA-256:
 * c4f01cd798fb8e619ea8293786d57c8100ed8087f91ed1259b679f062ad8dade.
 */

/* Applies cache, SIMD and encrypted-DMA alignment requirements, rounds size and normalizes descriptor/cache-only capability flags. Marks invalid capabilities when cache alignment cannot be obtained.
   SDK match: ESP-IDF v5.4.4 components/esp_mm/heap_align_hw.c. */

/*
 * alignment: Required writable in/out alignment word.
 * size: Required writable in/out byte size.
 * caps: Required writable in/out capability mask.
 * Returns: Nothing; modifies outputs only on relevant hardware capabilities, or marks invalid
 *   capabilities on cache-query failure.
 * Requirements/effects: For mask0x1e0008, obtains cache alignment, takes the larger
 *   requested/cache value and enforces16-byte alignment for SIMD or encrypted DMA. Normalizes
 *   descriptor capabilities to DMA, rounds size using power-of-two alignment arithmetic, clears
 *   cache-only flags and removes DMA when selecting SPIRAM. SPIRAM alone does not enter this
 *   adjustment path; descriptor-induced DMA is added after the encryption check. Aliased output
 *   words retain native size, alignment, capabilities store order. No general input power-of-two or
 *   overflow check is supplied; caller provides valid initial words. Cache failure sets INVALID
 *   bit31 and leaves size/alignment unchanged.
 */

void esp_heap_adjust_alignment_to_hw(unsigned int *alignment, unsigned int *size, unsigned int *caps)
{
    volatile unsigned int *alignment_word = alignment;
    volatile unsigned int *size_word = size;
    volatile unsigned int *caps_word = caps;
    unsigned int adjusted_caps = *caps_word;
    if ((adjusted_caps & 0x001e0008U) == 0)
        return;
    unsigned int requested_size = *size_word;
    unsigned int required_alignment = *alignment_word;
    unsigned int cache_alignment = 0;
    if (esp_cache_get_alignment(adjusted_caps, &cache_alignment) != 0) {
        unsigned int current_caps = *caps_word;
        *caps_word = current_caps | 0x80000000U;
        return;
    }
    if (required_alignment < cache_alignment)
        required_alignment = cache_alignment;
    if ((adjusted_caps & 0x00100000U) != 0 && required_alignment < 16U)
        required_alignment = 16U;
    if ((adjusted_caps & 8U) != 0 && efuse_hal_flash_encryption_enabled() &&
        required_alignment < 16U)
        required_alignment = 16U;
    if ((adjusted_caps & 0x00060000U) != 0)
        adjusted_caps = (adjusted_caps & 0xfff9ffffU) | 8U;
    *size_word = (0U - required_alignment) & (requested_size - 1U + required_alignment);
    if ((adjusted_caps & 0x400U) != 0)
        adjusted_caps &= ~8U;
    *alignment_word = required_alignment;
    *caps_word = adjusted_caps & 0xfff7ffffU;
}

/* Native entry: 0x4038af50. */
/*
 * Medius v3.4.7 — device application; 0x4038af50.
 *
 * Checks payload=block+8 using unsigned address comparisons against [tlsf_get_pool(heap_data),
 * pool+pool_size), aborting on failure. The upper bound uses the recorded region size, not the
 * block size. For heaps initialized by multi_heap_register, pool_size includes TLSF metadata
 * while pool_start has already skipped it; this upper bound therefore extends metadata_size bytes
 * beyond the registered region end. This is only coarse address admission: it does not prove
 * alignment, allocation ownership, live status, valid header contents or that an entire block
 * fits. Requires valid heap metadata; compiled assertions are silent.
 *
 * Calls: tlsf_get_pool, abort.
 *
 * Called by: multi_heap_free, multi_heap_realloc.
 *
 * Original function-byte SHA-256:
 * 6a035daac3c763c46c305ed3f12456ef7ae58f3e047914fe231d00b25da05ab7.
 */

/* Reference: ESP-IDF v5.4.4 components/heap/multi_heap.c assert_valid_block. */

/*
 * heap: Live heap descriptor and allocator metadata used to construct the coarse address interval.
 * block: Candidate header view; only payload address=block+8 is checked.
 * Returns: Nothing on admission; aborts outside the computed interval.
 * Requirements/effects: Upper bound uses pool_start+pool_size and can extend metadata_size beyond
 *   registered end. Does not establish allocation ownership, header integrity, alignment or whole-
 *   block bounds.
 */

void multi_heap_assert_valid_block(const MultiHeap *heap, const TlsfBlock *block)
{
    const volatile MultiHeap *state = heap;
    unsigned int pool_start = (unsigned int)tlsf_get_pool(state->heap_data);
    unsigned int payload = (unsigned int)block + 8U;
    if (payload < pool_start || payload >= pool_start + state->pool_size)
        abort();
}

/* Native entry: 0x4038af6c. */
/*
 * Medius v3.4.7 — device application; 0x4038af6c.
 *
 * Checks a nonzero power-of-two alignment, locks the owning heap and allocates through TLSF with an offset. Updates current and minimum free-byte counters on success.
 *
 * Calls: xPortInIsrContext, tlsf_alloc_overhead, tlsf_block_size, tlsf_memalign_offs, vPortExitCritical,
 * xPortEnterCriticalTimeout.
 *
 * Called by: heap_caps_aligned_alloc_base.
 *
 * Original function-byte SHA-256:
 * e946752bc03dbb03e616de578a3d16c976bb87085aef4afea8ab1f79bc62e843.
 */

/* Checks a nonzero power-of-two alignment, locks the owning heap and allocates through TLSF with an offset. Updates current and minimum free-byte counters on success.
   SDK match: ESP-IDF v5.4.4 components/heap/multi_heap.c. */

/*
 * heap: Heap context; NULL is rejected.
 * size: Nonzero requested payload bytes.
 * alignment: Nonzero power-of-two alignment; rejected otherwise.
 * offset: Offset passed to TLSF alignment placement.
 * Returns: Aligned payload pointer or NULL.
 * Requirements/effects: Uses heap lock when present. On success deducts TLSF block size plus
 *   allocation overhead and updates the minimum-free watermark. Does not report failure through
 *   the capability hook or zero-fill.
 */

void *multi_heap_aligned_alloc_offs(MultiHeap *heap, unsigned int size,
    unsigned int alignment, unsigned int offset)
{
    if (size == 0 || heap == NULL || (alignment & (alignment - 1U)) != 0 || alignment == 0)
        return NULL;
    volatile MultiHeap *state = heap;
    void *lock = state->lock;
    if (lock != NULL) {
        (void)xPortInIsrContext();
        (void)xPortEnterCriticalTimeout(lock, -1);
    }
    void *allocation = tlsf_memalign_offs(state->heap_data, alignment, size, offset);
    if (allocation != NULL) {
        unsigned int block_size = tlsf_block_size(allocation);
        unsigned int free_bytes = state->free_bytes;
        state->free_bytes = free_bytes - block_size;
        unsigned int overhead = tlsf_alloc_overhead();
        free_bytes = state->free_bytes;
        unsigned int minimum_free_bytes = state->minimum_free_bytes;
        free_bytes -= overhead;
        state->free_bytes = free_bytes;
        if (free_bytes < minimum_free_bytes)
            state->minimum_free_bytes = free_bytes;
    }
    lock = state->lock;
    if (lock != NULL) {
        (void)xPortInIsrContext();
        vPortExitCritical(lock);
    }
    return allocation;
}

/* Native entry: 0x4038afe4. */
/*
 * Medius v3.4.7 — device application; 0x4038afe4.
 *
 * Checks the payload against the allocator coarse address range, locks the heap, restores the block size and allocator overhead to free-byte accounting and releases the TLSF block.
 *
 * Calls: xPortInIsrContext, multi_heap_assert_valid_block, tlsf_alloc_overhead, tlsf_block_size, tlsf_free, vPortExitCritical,
 * xPortEnterCriticalTimeout.
 *
 * Called by: heap_caps_free.
 *
 * Original function-byte SHA-256:
 * 95041286d7395c347f49249c9de5c7215f43cb25a70643aec98ba434d9aa3217.
 */

/* Checks the payload against the allocator coarse address range, locks the heap, restores the block size and allocator overhead to free-byte accounting and releases the TLSF block.
   SDK match: ESP-IDF v5.4.4 components/heap/multi_heap.c. */

/*
 * heap: Owning heap context; NULL makes this wrapper a no-op.
 * buffer: Live payload from this heap, or NULL for a no-op.
 * Returns: Nothing.
 * Requirements/effects: Checks the allocator header address before acquiring the optional lock.
 *   Restores block size plus overhead to free-byte accounting, then calls TLSF free. Coarse
 *   address validation is not proof against double free or corrupted metadata.
 */

void multi_heap_free(MultiHeap *heap, void *buffer)
{
    if (heap == NULL || buffer == NULL)
        return;
    multi_heap_assert_valid_block(heap, (const TlsfBlock *)((unsigned int)buffer - 8U));
    volatile MultiHeap *state = heap;
    void *lock = state->lock;
    if (lock != NULL) {
        (void)xPortInIsrContext();
        (void)xPortEnterCriticalTimeout(lock, -1);
    }
    unsigned int block_size = tlsf_block_size(buffer);
    unsigned int free_bytes = state->free_bytes;
    state->free_bytes = free_bytes + block_size;
    unsigned int overhead = tlsf_alloc_overhead();
    free_bytes = state->free_bytes;
    TlsfControl *control = state->heap_data;
    state->free_bytes = free_bytes + overhead;
    tlsf_free(control, buffer);
    lock = state->lock;
    if (lock != NULL) {
        (void)xPortInIsrContext();
        vPortExitCritical(lock);
    }
}

/* Native entry: 0x4038b03c. */
/*
 * Medius v3.4.7 — device application; 0x4038b03c.
 *
 * Returns the TLSF block payload size; this build does not use the heap argument in this wrapper.
 *
 * Calls: tlsf_block_size.
 *
 * Called by: heap_caps_realloc_base.
 *
 * Original function-byte SHA-256:
 * 26e2bbfe92c8140036e467671a787a0f088d880cd83e22ba731bc6b22318ae70.
 */

/* Returns the TLSF block payload size; this build does not use the heap argument in this wrapper.
   SDK match: ESP-IDF v5.4.4 components/heap/multi_heap.c. */

/*
 * heap: Unused by this linked wrapper.
 * buffer: Valid TLSF allocation payload pointer; no NULL guard is supplied here.
 * Returns: TLSF usable payload block size.
 * Requirements/effects: Reads metadata through tlsf_block_size without locking or validating
 *   ownership. The actual allocation must remain live.
 */

unsigned int multi_heap_get_allocated_size(MultiHeap *heap, void *buffer)
{
    (void)heap;
    return tlsf_block_size(buffer);
}

/* Native entry: 0x4038b048. */
/*
 * Medius v3.4.7 — device application; 0x4038b048.
 *
 * Locks the heap around TLSF allocation and updates current/minimum free-byte counters by the block size plus allocator overhead.
 *
 * Calls: xPortInIsrContext, tlsf_alloc_overhead, tlsf_block_size, tlsf_malloc, vPortExitCritical,
 * xPortEnterCriticalTimeout.
 *
 * Called by: heap_caps_aligned_alloc_base, multi_heap_realloc, FUN_42003fd0.
 *
 * Original function-byte SHA-256:
 * b8eef8155d872fa7333868cea7c9fb985e5f307b4e0eb978d955c55acfacd826.
 */

/* Locks the heap around TLSF allocation and updates current/minimum free-byte counters by the block size plus allocator overhead.
   SDK match: ESP-IDF v5.4.4 components/heap/multi_heap.c. */

/*
 * heap: Heap context; NULL returns NULL.
 * size: Requested nonzero payload bytes; zero returns NULL.
 * Returns: TLSF allocation pointer or NULL.
 * Requirements/effects: Acquires optional heap lock, allocates, deducts actual block size and
 *   allocator overhead and lowers minimum-free watermark when needed. Does not zero-fill.
 */

void *multi_heap_malloc(MultiHeap *heap, unsigned int size)
{
    if (size == 0 || heap == NULL)
        return NULL;
    volatile MultiHeap *state = heap;
    void *lock = state->lock;
    if (lock != NULL) {
        (void)xPortInIsrContext();
        (void)xPortEnterCriticalTimeout(lock, -1);
    }
    void *allocation = tlsf_malloc(state->heap_data, size);
    if (allocation != NULL) {
        unsigned int block_size = tlsf_block_size(allocation);
        unsigned int free_bytes = state->free_bytes;
        state->free_bytes = free_bytes - block_size;
        unsigned int overhead = tlsf_alloc_overhead();
        free_bytes = state->free_bytes;
        unsigned int minimum_free_bytes = state->minimum_free_bytes;
        free_bytes -= overhead;
        state->free_bytes = free_bytes;
        if (free_bytes < minimum_free_bytes)
            state->minimum_free_bytes = free_bytes;
    }
    lock = state->lock;
    if (lock != NULL) {
        (void)xPortInIsrContext();
        vPortExitCritical(lock);
    }
    return allocation;
}

/* Native entry: 0x4038b0ac. */
/*
 * Medius v3.4.7 — device application; 0x4038b0ac.
 *
 * Resizes a TLSF block under the heap lock, handles NULL/zero-size cases and updates free-byte accounting; asserts for a NULL heap.
 *
 * Calls: xPortInIsrContext, multi_heap_assert_valid_block, multi_heap_malloc, tlsf_block_size, tlsf_realloc, __assert_func,
 * vPortExitCritical, xPortEnterCriticalTimeout.
 *
 * Called by: heap_caps_realloc_base.
 *
 * Original function-byte SHA-256:
 * 4d8b60a277695eb4f810b4b1a373961afd400497606e4a8a0ef1701b72ee5cf7.
 */

/* Resizes a TLSF block under the heap lock, handles NULL/zero-size cases and updates free-byte accounting; asserts for a NULL heap.
   SDK match: ESP-IDF v5.4.4 components/heap/multi_heap.c. */

/* For non-NULL buffer with size0, tlsf_realloc frees and returns NULL, so this
 * wrapper skips its success-only counter update. The outer heap_caps_realloc_base
 * handles zero sizes through heap_caps_free before reaching this internal path. */

/*
 * heap: Non-NULL owning heap; NULL asserts.
 * buffer: Live payload from this heap or NULL to allocate.
 * size: New payload size forwarded to TLSF; zero reaches its free-and-NULL behavior.
 * Returns: Replacement pointer or NULL.
 * Requirements/effects: For a non-NULL buffer validates its header and holds the optional heap
 *   lock around TLSF realloc. On non-NULL success adjusts free bytes by old minus new block size
 *   and updates the watermark; it does not add allocator overhead again. On a NULL TLSF result no
 *   accounting update occurs, including the zero-size release path in this linked implementation.
 */

void *multi_heap_realloc(MultiHeap *heap, void *buffer, unsigned int size)
{
    if (heap == NULL)
        __assert_func(NULL, 0, NULL, NULL);
    if (buffer == NULL)
        return multi_heap_malloc(heap, size);
    multi_heap_assert_valid_block(heap, (const TlsfBlock *)((unsigned int)buffer - 8U));
    volatile MultiHeap *state = heap;
    void *lock = state->lock;
    if (lock != NULL) {
        (void)xPortInIsrContext();
        (void)xPortEnterCriticalTimeout(lock, -1);
    }
    unsigned int old_block_size = tlsf_block_size(buffer);
    void *replacement = tlsf_realloc(state->heap_data, buffer, size);
    if (replacement != NULL) {
        unsigned int free_bytes = state->free_bytes;
        state->free_bytes = free_bytes + old_block_size;
        unsigned int new_block_size = tlsf_block_size(replacement);
        free_bytes = state->free_bytes;
        unsigned int minimum_free_bytes = state->minimum_free_bytes;
        free_bytes -= new_block_size;
        state->free_bytes = free_bytes;
        if (free_bytes < minimum_free_bytes)
            state->minimum_free_bytes = free_bytes;
    }
    lock = state->lock;
    if (lock != NULL) {
        (void)xPortInIsrContext();
        vPortExitCritical(lock);
    }
    return replacement;
}

/* Native entry: 0x4038b128. */
/*
 * Medius v3.4.7 — device application; 0x4038b128.
 *
 * Stores the supplied lock pointer in the heap descriptor. It neither creates nor initializes the
 * lock, takes it, validates either pointer, or frees a previous lock. The multi-heap callers use
 * this as an optional portMUX spinlock, not a recursive RTOS mutex.
 *
 * Called by: FUN_42003f8c, FUN_42003fd0, FUN_42004228.
 *
 * Original function-byte SHA-256:
 * 0e2fb49cf19e9d0c1c68073ed33e6f7fffd8a13b658d4f8f2365198da39991b3.
 */

/* Reference: ESP-IDF v5.4.4 components/heap/multi_heap.c. */

/*
 * heap: Writable initialized heap descriptor.
 * lock: Optional initialized portMUX spinlock pointer, or NULL to disable wrapper locking.
 * Returns: Nothing.
 * Requirements/effects: Stores the pointer only. Does not create, initialize, acquire or free a
 *   lock, validate either pointer or synchronize replacement with active heap operations.
 */

void multi_heap_set_lock(MultiHeap *heap, void *lock)
{
    ((volatile MultiHeap *)heap)->lock = lock;
}

/* Native entry: 0x42003f04. */
/*
 * Medius v3.4.7 — device application; 0x42003f04.
 *
 * Clears a 28-byte output and visits every registered heap with a live allocator and all
 * requested capabilities covered by its three capability words. Sums six statistics and takes the
 * maximum largest-free-block size. This build has no per-block-owner subtraction. Requires valid
 * output; individual heap snapshots do not form one globally atomic snapshot.
 *
 * Calls: multi_heap_get_info, memset.
 *
 * Called by: heap_caps_get_largest_free_block.
 *
 * Original function-byte SHA-256:
 * 189adbe35f04a51b7d3e05f2b070c937606ee228d335330ff3e4c9f0ef9f2a5f.
 */

/* Reference: ESP-IDF v5.4.4 components/heap/heap_caps.c. */

/*
 * information: Required writable28-byte MultiHeapInfo output, cleared before aggregation.
 * capabilities: Capability bits that each included registered region must collectively supply
 *   through its three capability words.
 * Returns: Nothing; outputs summed counters and the maximum largest-free-block value.
 * Requirements/effects: Registered region/heap objects must be live. Per-heap snapshots do not
 *   provide a single globally atomic snapshot; no per-owner adjustment is compiled here.
 */

void heap_caps_get_info(MultiHeapInfo *information, unsigned int capabilities)
{
    memset(information, 0, 28);
    const volatile HeapRegion *region = HEAP_REGISTRATION_HEAD;
    while (region != NULL) {
        MultiHeap *heap = region->heap;
        if (heap != NULL) {
            unsigned int priority_0_capabilities = region->caps[0];
            unsigned int priority_1_capabilities = region->caps[1];
            unsigned int priority_2_capabilities = region->caps[2];
            unsigned int all_capabilities = priority_0_capabilities |
                priority_1_capabilities | priority_2_capabilities;
            if ((all_capabilities & capabilities) == capabilities) {
                MultiHeapInfo snapshot;
                multi_heap_get_info(heap, &snapshot);
                volatile MultiHeapInfo *total = information;
                const volatile MultiHeapInfo *sample = &snapshot;
                unsigned int free_bytes = total->total_free_bytes;
                free_bytes += sample->total_free_bytes;
                unsigned int allocated_bytes = total->total_allocated_bytes;
                allocated_bytes += sample->total_allocated_bytes;
                unsigned int largest_free_block = total->largest_free_block;
                unsigned int sample_largest_free_block = sample->largest_free_block;
                if (largest_free_block < sample_largest_free_block)
                    largest_free_block = sample_largest_free_block;
                unsigned int minimum_free_bytes = total->minimum_free_bytes;
                minimum_free_bytes += sample->minimum_free_bytes;
                unsigned int allocated_blocks = total->allocated_blocks;
                allocated_blocks += sample->allocated_blocks;
                unsigned int free_blocks = total->free_blocks;
                free_blocks += sample->free_blocks;
                unsigned int total_blocks = total->total_blocks;
                total_blocks += sample->total_blocks;
                total->total_free_bytes = free_bytes;
                total->total_allocated_bytes = allocated_bytes;
                total->largest_free_block = largest_free_block;
                total->minimum_free_bytes = minimum_free_bytes;
                total->allocated_blocks = allocated_blocks;
                total->free_blocks = free_blocks;
                total->total_blocks = total_blocks;
            }
        }
        region = region->next;
    }
}

/* Native entry: 0x42003f78. */
/*
 * Medius v3.4.7 — device application; 0x42003f78.
 *
 * Collects the full 28-byte capability-filtered heap statistics into a local object and returns
 * its largest_free_block member at byte 8. It reports a snapshot, not a reservation; later
 * allocation may race other tasks.
 *
 * Calls: heap_caps_get_info.
 *
 * Called by: get_buffer_malloc, usb_clone_configure.
 *
 * Original function-byte SHA-256:
 * 2a962b8d6d77fadb6707710ad516aa6f294f023bc289b9523d82a83989e17e03.
 */

/* Reference: ESP-IDF v5.4.4 components/heap/heap_caps.c. */

/*
 * capabilities: Capability mask forwarded to the aggregate heap-statistics query.
 * Returns: Largest reported free payload block from the28-byte statistics snapshot.
 * Requirements/effects: Reports current availability, not a reservation; another task may allocate
 *   before a later allocation attempt.
 */

unsigned int heap_caps_get_largest_free_block(unsigned int capabilities)
{
    MultiHeapInfo snapshot;
    heap_caps_get_info(&snapshot, capabilities);
    return snapshot.largest_free_block;
}

/* Native entry: 0x42003f8c. */
/*
 * Medius v3.4.7 — device application; 0x42003f8c.
 *
 * Registers remaining capability regions as heaps and attaches each successful heap to its embedded lock.
 *
 * Calls: multi_heap_set_lock, __assert_func, multi_heap_register.
 *
 * Called by: main_task.
 *
 * Original function-byte SHA-256:
 * 8389d12314fcb6065297590f8548dc2cda8d064a2e33275289858847396eb514.
 */

/*
 * Returns: No value. An oversized missing region calls the nonreturning silent assertion helper.
 * Requirements/effects: Called during startup after the other core has left its startup stack.
 *   Reads the registered-region list head once, then walks the next links. A region with a non-
 *   NULL heap is skipped without checking its address range. For each NULL heap, snapshots start
 *   and end, subtracts them as unsigned 32-bit values, and asserts if the result exceeds
 *   0x02000000 bytes (32 MiB). Zero and the exact limit are passed through; there is no separate
 *   end-before-start check, so address wrap follows the native arithmetic. Calls
 *   multi_heap_register(start, bytes), restoring both arguments omitted from the raw decompile.
 *   Publishes the returned pointer into the region before calling multi_heap_set_lock with the
 *   embedded 8-byte portMUX at offset 0x14. A NULL result remains published as NULL and does not
 *   stop later regions; it can be retried on another invocation. The next link is loaded after the
 *   delegated calls, and partial registrations remain if a later region asserts. Does not
 *   initialize the mux, free prior registrations, lock the whole list, or detect cycles. The
 *   caller supplies live, writable, acyclic descriptors and safe ownership of the candidate
 *   memory. No concurrent lifetime guarantee is supplied here.
 */

void heap_caps_enable_nonos_stack_heaps(void)
{
    volatile HeapRegion *region = REGISTERED_HEAPS;
    while (region != NULL) {
        MultiHeap *heap = region->heap;
        if (heap == NULL) {
            unsigned int start = (unsigned int)region->start;
            unsigned int bytes = (unsigned int)region->end - start;
            if (bytes > 0x02000000U)
                __assert_func(NULL, 0, NULL, NULL);
            heap = multi_heap_register((void *)start, bytes);
            region->heap = heap;
            if (heap != NULL)
                multi_heap_set_lock(heap, (void *)((unsigned int)region + 20U));
        }
        region = region->next;
    }
}

/* Native entry: 0x420248a4. */
/*
 * Medius v3.4.7 — device application; 0x420248a4.
 *
 * Asserts a non-NULL region start and rejects fewer than 20 bytes. Reserves the 20-byte heap
 * descriptor, creates TLSF with max_bytes 0 at start+20, and stores its result even on failure.
 * On success clears the lock, records the remaining-region size, and initializes free/minimum-
 * free counters to that size minus TLSF metadata. This does not allocate its descriptor
 * separately, install a spinlock or validate that the supplied region is writable.
 *
 * Calls: tlsf_size, __assert_func, tlsf_create_with_pool.
 *
 * Called by: FUN_42003f8c, FUN_42003fd0, FUN_42004228.
 *
 * Original function-byte SHA-256:
 * 3781a63bb5e0b6af777e86b183ca71f0e452742993e878a7580684dd8f848384.
 */

/* Reference: ESP-IDF v5.4.4 components/heap/multi_heap.c multi_heap_register_impl. */

/*
 * start: Writable supplied region beginning with an in-place20-byte heap descriptor; NULL asserts.
 * bytes: Total supplied region bytes including descriptor; values below20 returnNULL.
 * Returns: Heap descriptor at start on successful TLSF creation; otherwiseNULL.
 * Requirements/effects: Caller owns live writable storage. Reserves descriptor and in-place TLSF;
 *   a failed attempt can still write heap_data/constructor metadata. Does not install a spinlock
 *   or allocate a separate descriptor.
 */

MultiHeap *multi_heap_register(void *start, unsigned int bytes)
{
    if (start == NULL)
        __assert_func(NULL, 0, NULL, NULL);
    if (bytes < 20U)
        return NULL;
    MultiHeap *heap = start;
    volatile MultiHeap *state = heap;
    unsigned int pool_bytes = bytes - 20U;
    TlsfControl *control = tlsf_create_with_pool((void *)((unsigned int)start + 20U), pool_bytes, 0);
    state->heap_data = control;
    if (control == NULL)
        return NULL;
    state->lock = NULL;
    unsigned int metadata_size = tlsf_size(control);
    unsigned int free_bytes = pool_bytes - metadata_size;
    state->free_bytes = free_bytes;
    state->pool_size = pool_bytes;
    state->minimum_free_bytes = free_bytes;
    return heap;
}

/* Native entry: 0x420248f0. */
/*
 * Medius v3.4.7 — device application; 0x420248f0.
 *
 * Clears all seven output words even for a NULL heap. With a heap, takes its optional spinlock,
 * walks TLSF blocks, subtracts metadata and four bytes per allocated block from occupied space,
 * copies free/minimum-free counters, then rounds the largest free payload to an allocable TLSF
 * size. Releases the optional lock. Requires a valid output; it is not a cross-heap atomic
 * snapshot.
 *
 * Calls: xPortInIsrContext, tlsf_alloc_overhead, tlsf_get_pool, tlsf_size, tlsf_walk_pool, tlsf_fit_size,
 * memset, vPortExitCritical, xPortEnterCriticalTimeout.
 *
 * Called by: heap_caps_get_info.
 *
 * Original function-byte SHA-256:
 * d75d5b1d552a97b22668bc95ac10444620e4baabf240de2ee1d9695a94f43f68.
 */

/* Reference: ESP-IDF v5.4.4 components/heap/multi_heap.c. */

/*
 * heap: Live20-byte heap descriptor or NULL; its optional lock and TLSF control are used when non-
 *   NULL.
 * information: Required writable28-byte statistics output, cleared even when heap is NULL.
 * Returns: Nothing.
 * Requirements/effects: Takes the optional heap spinlock, walks blocks, computes occupied
 *   bytes/accounting and rounds largest-free capacity through TLSF. Does not provide a cross-heap
 *   atomic snapshot.
 */

void multi_heap_get_info(MultiHeap *heap, MultiHeapInfo *information)
{
    memset(information, 0, 28);
    if (heap == NULL)
        return;
    volatile MultiHeap *state = heap;
    volatile MultiHeapInfo *output = information;
    void *lock = state->lock;
    if (lock != NULL) {
        (void)xPortInIsrContext();
        (void)xPortEnterCriticalTimeout(lock, -1);
    }
    void *pool = tlsf_get_pool(state->heap_data);
    tlsf_walk_pool(pool, multi_heap_get_info_tlsf, information);
    unsigned int allocated_blocks = output->allocated_blocks;
    unsigned int overhead = tlsf_alloc_overhead();
    TlsfControl *control = state->heap_data;
    unsigned int pool_size = state->pool_size;
    unsigned int metadata_size = tlsf_size(control);
    unsigned int free_bytes = state->free_bytes;
    unsigned int minimum_free_bytes = state->minimum_free_bytes;
    control = state->heap_data;
    unsigned int largest_free_block = output->largest_free_block;
    output->total_allocated_bytes = pool_size - free_bytes - metadata_size - allocated_blocks * overhead;
    output->minimum_free_bytes = minimum_free_bytes;
    output->total_free_bytes = free_bytes;
    unsigned int largest_allocable = tlsf_fit_size(control, largest_free_block);
    lock = state->lock;
    output->largest_free_block = largest_allocable;
    if (lock != NULL) {
        (void)xPortInIsrContext();
        vPortExitCritical(lock);
    }
}

/* Native entry: 0x42024970. */
/*
 * Medius v3.4.7 — device application; 0x42024970.
 *
 * TLSF statistics callback: treats user as the 28-byte output, increments either allocated_blocks
 * or free_blocks, updates the largest free payload only for a free block, and increments
 * total_blocks. Returns true to continue walking. Does not add free/allocated byte totals and
 * does not inspect payload bytes.
 *
 * Original function-byte SHA-256:
 * 453dedccc6f2f4f7d79840c4ad5b492da21abead5e45447e26f77d0ff319cf6d.
 */

/* Reference: ESP-IDF v5.4.4 components/heap/multi_heap.c. Body rendered from the original
   instructions with explicit recovered structure/ABI semantics. */

/*
 * unused_payload: Block payload address passed by the walker; this callback does not dereference
 *   it.
 * size: Block payload capacity in bytes after removing header flags.
 * used: 0 for free, any nonzero value for allocated.
 * user: Required writable28-byte MultiHeapInfo accumulator.
 * Returns: true to continue the walk.
 * Requirements/effects: Updates allocated/free/total block counts and largest free payload. Does
 *   not add byte totals or acquire a lock itself; caller owns synchronization.
 */

bool multi_heap_get_info_tlsf(void *unused_payload, unsigned int size, int used, void *user)
{
    (void)unused_payload;
    volatile MultiHeapInfo *information = user;
    if (used != 0) {
        unsigned int allocated_blocks = information->allocated_blocks;
        information->allocated_blocks = allocated_blocks + 1U;
    } else {
        unsigned int free_blocks = information->free_blocks;
        unsigned int largest_free_block = information->largest_free_block;
        information->free_blocks = free_blocks + 1U;
        if (largest_free_block < size)
            information->largest_free_block = size;
    }
    unsigned int total_blocks = information->total_blocks;
    information->total_blocks = total_blocks + 1U;
    return true;
}

