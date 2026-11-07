/* Medius v3.4.7 host — memory/heap.c.
 * Recovered C and native assembly, grouped for source navigation.
 * Original entry addresses, firmware-byte hashes and function comments follow.
 */

#include "../include/types.h"

/* Native entry: 0x40376144. */
/*
 * Medius v3.4.7 — host application; 0x40376144.
 *
 * Invokes the registered allocation-failure callback with the failed size, capability mask and allocator name. This build does not abort here.
 *
 * Called by: heap_caps_malloc, heap_caps_malloc_default, heap_caps_realloc_default, heap_caps_realloc, heap_caps_calloc.
 *
 * Indirect call: the registered allocation-failure callback.
 *
 * Original function-byte SHA-256:
 * 9aac8b5da850e7de20da396a310149053da639719257854e87f2d3aa2db3ae38.
 */

/* Invokes the registered allocation-failure callback with the failed size, capability mask and allocator name. This build does not abort here.
   SDK match: ESP-IDF v5.4.4 components/heap/heap_caps.c. */

/*
 * size: Requested allocation bytes reported to the failure hook.
 * caps: Requested capability mask reported to the hook.
 * function_name: Allocator name pointer passed unchanged to the hook.
 * Returns: Nothing.
 * Requirements/effects: Snapshots the hook once and calls it synchronously when present. This build does not
 *   abort here, validate the callback/name or provide recovery. Hook runs in the caller allocation
 *   context.
 */

void heap_caps_alloc_failed(unsigned int size, unsigned int caps, const char *function_name)

{
    HeapAllocationFailureCallback callback = HEAP_ALLOCATION_FAILURE_CALLBACK;
    if (callback != NULL)
        callback(size, caps, function_name);
}

/* Native entry: 0x4037615c. */
/*
 * Medius v3.4.7 — host application; 0x4037615c.
 *
 * Allocates from matching capability heaps; reports a nonzero-size allocation failure through the failure callback.
 *
 * Calls: heap_caps_alloc_failed, heap_caps_malloc_base.
 *
 * Called by: get_buffer_malloc, get_desc_for_int, rtc_isr_register, FUN_420151cc, FUN_42021bf4, FUN_42032640,
 * FUN_4203274c, esp_intr_alloc_intrstatus, pvPortMalloc.
 *
 * Original function-byte SHA-256:
 * a9d00edaaefa4a659bc5e7bdc88fe7b60d88a2e27f827191e23ca83a730c5804.
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

void * heap_caps_malloc(uint size,uint caps)

{
  void *allocation;

  allocation = heap_caps_malloc_base(size,caps);
  if ((allocation == (void *)0x0) && (size != 0)) {
    heap_caps_alloc_failed(size,caps,"heap_caps_malloc");
  }
  return allocation;
}

/* Native entry: 0x4037617c. */
/*
 * Medius v3.4.7 — host application; 0x4037617c.
 *
 * Uses the default internal/external-memory threshold policy, then retries with unrestricted default capabilities before reporting failure.
 *
 * Calls: heap_caps_alloc_failed, heap_caps_malloc_base.
 *
 * Called by: malloc, calloc, _malloc_r, _calloc_r.
 *
 * Original function-byte SHA-256:
 * 5d996c8341a215c1322c6e3c789c22e614065ab695592f6ffba3b0ea3c5513dd.
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

void * heap_caps_malloc_default(uint size)

{
  void *allocation;

  unsigned int internal_allocation_threshold = HEAP_INTERNAL_ALLOCATION_THRESHOLD;
  if (internal_allocation_threshold == 0xffffffffU) {
    allocation = heap_caps_malloc_base(size,0x1800);
    if ((allocation == (void *)0x0) && (size != 0)) {
      heap_caps_alloc_failed(size,0x1800,"heap_caps_malloc");
    }
  }
  else {
    if (internal_allocation_threshold < size) {
      allocation = heap_caps_malloc_base(size,0x1400);
    }
    else {
      allocation = heap_caps_malloc_base(size,0x1800);
    }
    if (((allocation == (void *)0x0) && (size != 0)) &&
       (allocation = heap_caps_malloc_base(size,0x1000), allocation == (void *)0x0)) {
      heap_caps_alloc_failed(size,0x1000,"heap_caps_malloc_default");
    }
  }
  return allocation;
}

/* Native entry: 0x403761ec. */
/*
 * Medius v3.4.7 — host application; 0x403761ec.
 *
 * Reallocates using the default internal/external-memory threshold policy; retries default capabilities on nonzero-size failure.
 *
 * Calls: heap_caps_alloc_failed, heap_caps_realloc_base.
 *
 * Called by: _realloc_r.
 *
 * Original function-byte SHA-256:
 * 64c93c994f6d87ea7adb84fe93819202963aff234531de0d7ae312575d756016.
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

void * heap_caps_realloc_default(void *buffer,uint size)

{
  void *replacement;

  unsigned int internal_allocation_threshold = HEAP_INTERNAL_ALLOCATION_THRESHOLD;
  if (internal_allocation_threshold == 0xffffffffU) {
    replacement = heap_caps_realloc_base(buffer,size,0x1800);
    if ((replacement == (void *)0x0) && (size != 0)) {
      heap_caps_alloc_failed(size,0x1800,"heap_caps_realloc");
    }
  }
  else {
    if (internal_allocation_threshold < size) {
      replacement = heap_caps_realloc_base(buffer,size,0x1400);
    }
    else {
      replacement = heap_caps_realloc_base(buffer,size,0x1800);
    }
    if (((replacement == (void *)0x0) && (size != 0)) &&
       (replacement = heap_caps_realloc_base(buffer,size,0x1000), replacement == (void *)0x0)) {
      heap_caps_alloc_failed(size,0x1000,"heap_caps_realloc_default");
    }
  }
  return replacement;
}

/* Native entry: 0x40376260. */
/*
 * Medius v3.4.7 — host application; 0x40376260.
 *
 * Reallocates with explicit capabilities and reports a nonzero-size failure; preserves the old allocation when allocation fails.
 *
 * Calls: heap_caps_alloc_failed, heap_caps_realloc_base.
 *
 * Called by: FUN_42021b34, FUN_42021bf4.
 *
 * Original function-byte SHA-256:
 * 23dc3b22bab843d4ccda3855ebc890d516c5f77c5d2c063bbb2ddd2e783cc8c2.
 */

/* Reallocates with explicit capabilities and reports a nonzero-size failure; preserves the old allocation when allocation fails.
   SDK match: ESP-IDF v5.4.4 components/heap/heap_caps.c. */

/*
 * buffer: Owned allocation or NULL.
 * size: New payload bytes; zero-size release returns NULL.
 * caps: Required capabilities for the replacement.
 * Returns: Replacement pointer or NULL.
 * Requirements/effects: Invokes the base realloc and reports NULL only when size is nonzero.
 *   Nonzero-size failure preserves the old allocation.
 */

void * heap_caps_realloc(void *buffer,uint size,uint caps)

{
  void *replacement;

  replacement = heap_caps_realloc_base(buffer,size,caps);
  if ((replacement == (void *)0x0) && (size != 0)) {
    heap_caps_alloc_failed(size,caps,"heap_caps_realloc");
  }
  return replacement;
}

/* Native entry: 0x40376280. */
/*
 * Medius v3.4.7 — host application; 0x40376280.
 *
 * Requests zeroed count-times-size bytes with the given capabilities and reports allocation failure through the registered callback.
 *
 * Calls: heap_caps_alloc_failed, heap_caps_calloc_base.
 *
 * Called by: FUN_42012834, FUN_4201403c, do_allocate_gdma_channel, esp_mmu_map, esp_timer_create.
 *
 * Original function-byte SHA-256:
 * d883350b82591bdc7f87f0e08f6a31602a9ed2a58274fe1a7aadc5d7f23b5133.
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

void * heap_caps_calloc(uint count,uint size,uint caps)

{
  void *allocation;

  allocation = heap_caps_calloc_base(count,size,caps);
  if ((allocation == (void *)0x0) && (size != 0)) {
    heap_caps_alloc_failed(count * size,caps,"heap_caps_calloc");
  }
  return allocation;
}

/* Native entry: 0x403762a4. */
/*
 * Medius v3.4.7 — host application; 0x403762a4.
 *
 * Frees a capability allocation. NULL is ignored; executable IRAM aliases recover the DRAM pointer stored before the allocation. An invalid owning heap asserts.
 *
 * Calls: multi_heap_free, __assert_func.
 *
 * Called by: heap_caps_realloc_base, vPortFree, free, _free_r.
 *
 * Original function-byte SHA-256:
 * 97a969d68224c4b21f4cba600a9c5696c2bee927ab0166d172db57267447c860.
 */

/* Frees a capability allocation. NULL is ignored; executable IRAM aliases recover the DRAM pointer stored before the allocation. An invalid owning heap asserts.
   SDK match: ESP-IDF v5.4.4 components/heap/heap_caps_base.c. */

/*
 * buffer: Live capability allocation payload, or NULL.
 * Returns: Nothing.
 * Requirements/effects: NULL is ignored. For executable aliases in the compiled IRAM range, reads
 *   the original DRAM allocation pointer from the preceding word. Finds a registered containing
 *   heap, asserts if absent, then frees through multi_heap_free. Does not wipe bytes or clear the
 *   caller pointer.
 */

void heap_caps_free(void *buffer)

{
  RegisteredHeapPointer registered_heap;

  if (buffer != (void *)0x0) {
    if ((int)buffer + 0xbfc88000U < 0x68000) {
      buffer = *(void **)((int)buffer + -4);
    }
    registered_heap = REGISTERED_HEAPS;
    while( true ) {
      if (registered_heap == (RegisteredHeapPointer)0x0) {
                    /* WARNING: Subroutine does not return */
        __assert_func((char *)0x0,0,(char *)0x0,(char *)0x0);
      }
      if (((registered_heap->heap != (MultiHeap *)0x0) && (registered_heap->start <= (int)buffer)) &&
         ((int)buffer < registered_heap->end)) break;
      registered_heap = registered_heap->next;
    }
    multi_heap_free(registered_heap->heap,buffer);
  }
  return;
}

/* Native entry: 0x403762ec. */
/*
 * Medius v3.4.7 — host application; 0x403762ec.
 *
 * Adjusts hardware alignment, rejects invalid/oversized requests and incompatible executable-memory capabilities, then searches three capability-priority levels. Executable aliases retain the DRAM allocation pointer.
 *
 * Calls: esp_heap_adjust_alignment_to_hw, multi_heap_aligned_alloc_offs, multi_heap_malloc, __assert_func.
 *
 * Called by: heap_caps_malloc_base, heap_caps_realloc_base.
 *
 * Original function-byte SHA-256:
 * 3328215e71b2ea3d0a183666a00848ccb84b5bccc8dee4237e2a664687ffd7a8.
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
 *   Does not call failure hooks or zero-fill.
 */

void * heap_caps_aligned_alloc_base(uint alignment,uint size,uint caps)

{
  RegisteredHeapPointer registered_heap;
  int capability_priority;
  uint *dram_allocation;
  void *allocation;
  uint allocation_end;
  MultiHeap *heap;
  uint *executable_header;
  uint adjusted_alignment;
  uint adjusted_size;
  uint adjusted_caps;

  adjusted_alignment = alignment;
  adjusted_size = size;
  adjusted_caps = caps;
  esp_heap_adjust_alignment_to_hw(&adjusted_alignment,&adjusted_size,&adjusted_caps);
  if (0x1ffffff < adjusted_size - 1) {
    return (void *)0x0;
  }
  if ((adjusted_caps & 1) == 0) {
    if ((adjusted_caps & 2) == 0) goto search_capability_heaps;
  }
  else {
    if ((adjusted_caps >> 2 & 3) != 0) {
      return (void *)0x0;
    }
    adjusted_caps = adjusted_caps | 2;
  }
  adjusted_size = adjusted_size + 3 & 0xfffffffc;
search_capability_heaps:
  capability_priority = 0;
  registered_heap = REGISTERED_HEAPS;
  do {
    while (registered_heap == (RegisteredHeapPointer)0x0) {
      capability_priority = capability_priority + 1;
      registered_heap = REGISTERED_HEAPS;
      if (capability_priority == 3) {
        return (void *)0x0;
      }
    }
    heap = registered_heap->heap;
    if (((heap != (MultiHeap *)0x0) && ((adjusted_caps & registered_heap->caps[capability_priority]) != 0)) &&
       ((~(registered_heap->caps[1] | registered_heap->caps[0] | registered_heap->caps[2]) & adjusted_caps) == 0)) {
      if (((adjusted_caps & 1) == 0) || (0x67fff < registered_heap->start + 0xc0378000U)) {
        if (adjusted_alignment < 5) {
          allocation = multi_heap_malloc(heap,adjusted_size);
        }
        else {
          allocation = multi_heap_aligned_alloc_offs(heap,adjusted_size,adjusted_alignment,0);
        }
        if (allocation != (void *)0x0) {
          return allocation;
        }
      }
      else {
        if (adjusted_alignment < 5) {
          dram_allocation = multi_heap_malloc(heap,adjusted_size + 4);
        }
        else {
          dram_allocation = multi_heap_aligned_alloc_offs(heap,adjusted_size + 4,adjusted_alignment,0);
        }
        if (dram_allocation != (uint *)0) {
          allocation_end = adjusted_size + 4 + (int)dram_allocation;
          if ((((0x67fffU < (uint)dram_allocation - 0x3fc88000U) &&
               (0x1fffU < (uint)dram_allocation - 0x600fe000U)) ||
              ((0x67fff < allocation_end + 0xc0377ffc && (0x1fff < allocation_end + 0x9ff01ffc)))) ||
             ((((uint)dram_allocation | allocation_end) & 3) != 0)) {
                    /* WARNING: Subroutine does not return */
            __assert_func((char *)0x0,0,(char *)0x0,(char *)0x0);
          }
          executable_header = dram_allocation;
          if (0x1fffU < (uint)dram_allocation - 0x600fe000U) {
            executable_header = (uint *)((uint)dram_allocation + 0x6f0000U);
          }
          *executable_header = (uint)dram_allocation;
          return executable_header + 1;
        }
      }
    }
    registered_heap = registered_heap->next;
  } while( true );
}

/* Native entry: 0x40376408. */
/*
 * Medius v3.4.7 — host application; 0x40376408.
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

void * heap_caps_malloc_base(uint size,uint caps)

{
  void *allocation;

  allocation = heap_caps_aligned_alloc_base(4,size,caps);
  return allocation;
}

/* Native entry: 0x40376418. */
/*
 * Medius v3.4.7 — host application; 0x40376418.
 *
 * Handles NULL as allocation and zero size as free. Tries in-place resizing on a compatible heap, otherwise allocates, copies the smaller byte count and frees the old block only after success.
 *
 * Calls: heap_caps_free, heap_caps_aligned_alloc_base, esp_heap_adjust_alignment_to_hw, multi_heap_get_allocated_size, multi_heap_realloc, __assert_func,
 * memcpy.
 *
 * Called by: heap_caps_realloc_default, heap_caps_realloc.
 *
 * Original function-byte SHA-256:
 * 9d04a3cae553a9d90591d779be7689bb27d9d4bbb158dbbfabb251c3df2ba88f.
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
 *   size on a successful replacement asserts. Nonzero-size failure preserves the old block; no
 *   failure hook is called here.
 */

void * heap_caps_realloc_base(void *buffer,uint size,uint caps)

{
  bool can_resize_directly;
  bool is_executable_alias;
  void *dram_pointer_or_replacement;
  uint old_payload_size;
  void *output;
  RegisteredHeapPointer owning_heap;
  MultiHeap *heap;
  uint adjusted_alignment;
  uint adjusted_size;
  uint adjusted_caps;

  adjusted_alignment = 4;
  adjusted_size = size;
  adjusted_caps = caps;
  esp_heap_adjust_alignment_to_hw(&adjusted_alignment,&adjusted_size,&adjusted_caps);
  if (buffer == (void *)0x0) {
    dram_pointer_or_replacement = heap_caps_aligned_alloc_base(adjusted_alignment,adjusted_size,adjusted_caps);
  }
  else {
    if (adjusted_size == 0) {
      heap_caps_free(buffer);
    }
    else if (adjusted_size < 0x2000001) {
      owning_heap = REGISTERED_HEAPS;
      if ((int)buffer + 0xbfc88000U < 0x68000) {
        dram_pointer_or_replacement = *(void **)((int)buffer + -4);
        if (owning_heap != (RegisteredHeapPointer)0x0) {
check_executable_owner:
          heap = owning_heap->heap;
          if (((heap == (MultiHeap *)0x0) || ((int)dram_pointer_or_replacement < owning_heap->start)) ||
             (owning_heap->end <= (int)dram_pointer_or_replacement)) goto next_executable_owner;
          can_resize_directly = false;
          is_executable_alias = true;
try_resize_or_replace:
          if (((~(owning_heap->caps[0] | owning_heap->caps[1] | owning_heap->caps[2]) & adjusted_caps) == 0) &&
             (can_resize_directly)) {
            if ((adjusted_alignment < 5) &&
               (dram_pointer_or_replacement = multi_heap_realloc(heap,buffer,adjusted_size), dram_pointer_or_replacement != (void *)0x0)) {
              return dram_pointer_or_replacement;
            }
            output = heap_caps_aligned_alloc_base(adjusted_alignment,adjusted_size,adjusted_caps);
            if (output != (void *)0x0) {
read_original_capacity:
              old_payload_size = multi_heap_get_allocated_size(owning_heap->heap,buffer);
copy_replacement_payload:
              if (old_payload_size != 0) {
                memcpy(output,buffer,old_payload_size < adjusted_size ? old_payload_size : adjusted_size)
                ;
                heap_caps_free(buffer);
                return output;
              }
              goto invalid_allocation;
            }
          }
          else {
            output = heap_caps_aligned_alloc_base(adjusted_alignment,adjusted_size,adjusted_caps);
            if (output != (void *)0x0) {
              if (!is_executable_alias) goto read_original_capacity;
              old_payload_size = multi_heap_get_allocated_size(owning_heap->heap,dram_pointer_or_replacement);
              goto copy_replacement_payload;
            }
          }
          goto return_null;
        }
      }
      else {
        for (; owning_heap != (RegisteredHeapPointer)0x0; owning_heap = owning_heap->next) {
          heap = owning_heap->heap;
          if (((heap != (MultiHeap *)0x0) && (owning_heap->start <= (int)buffer)) &&
             ((int)buffer < owning_heap->end)) {
            dram_pointer_or_replacement = (void *)0x0;
            can_resize_directly = true;
            is_executable_alias = false;
            goto try_resize_or_replace;
          }
        }
      }
invalid_allocation:
                    /* WARNING: Subroutine does not return */
      __assert_func((char *)0x0,0,(char *)0x0,(char *)0x0);
    }
return_null:
    dram_pointer_or_replacement = (void *)0x0;
  }
  return dram_pointer_or_replacement;
next_executable_owner:
  owning_heap = owning_heap->next;
  if (owning_heap == (HeapRegion *)0x0) goto invalid_allocation;
  goto check_executable_owner;
}

/* Native entry: 0x40376540. */
/*
 * Medius v3.4.7 — host application; 0x40376540.
 *
 * Rejects a 32-bit multiplication overflow, allocates count-times-size bytes and zeroes a successful allocation.
 *
 * Calls: heap_caps_malloc_base, memset.
 *
 * Called by: heap_caps_calloc.
 *
 * Original function-byte SHA-256:
 * ad03f3f72cd1e911baf1f2db1127ed593a2ccc9b5933d8f2c31ce432ac2f6e40.
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

void * heap_caps_calloc_base(uint count,uint size,uint caps)

{
  void *output;

  if ((int)((ulonglong)count * (ulonglong)size >> 0x20) == 0) {
    output = heap_caps_malloc_base(count * size,caps);
    if (output != (void *)0x0) {
      memset(output,0,count * size);
    }
  }
  else {
    output = (void *)0x0;
  }
  return output;
}

/* Native entry: 0x4037c3c8. */
/*
 * Medius v3.4.7 — host application; 0x4037c3c8.
 *
 * Applies cache, SIMD and encrypted-DMA alignment requirements, rounds size and normalizes descriptor/cache-only capability flags. Marks invalid capabilities when cache alignment cannot be obtained.
 *
 * Calls: efuse_hal_flash_encryption_enabled, esp_cache_get_alignment.
 *
 * Called by: heap_caps_aligned_alloc_base, heap_caps_realloc_base.
 *
 * Original function-byte SHA-256:
 * 872a112bea62dc291e63032bf6b4e585786f740cc6ef994648fb1db3fb71a7eb.
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
 *   cache-only flags and removes DMA when selecting SPIRAM. No general input power-of-two or
 *   overflow check is supplied; caller provides valid initial words. Cache failure sets INVALID
 *   bit31 and leaves size/alignment unchanged.
 */

void esp_heap_adjust_alignment_to_hw(uint *alignment,uint *size,uint *caps)

{
  int cache_alignment_status;
  uint flash_encryption_enabled;
  uint requested_size;
  uint required_alignment;
  uint adjusted_caps;
  uint cache_alignment;

  adjusted_caps = *caps;
  if ((adjusted_caps & 0x1e0008) != 0) {
    requested_size = *size;
    required_alignment = *alignment;
    cache_alignment = 0;
    cache_alignment_status = esp_cache_get_alignment(adjusted_caps,&cache_alignment);
    if (cache_alignment_status == 0) {
      required_alignment = required_alignment < cache_alignment ? cache_alignment : required_alignment;
      if ((adjusted_caps >> 0x14 & 1) != 0) {
        required_alignment = required_alignment < 16U ? 16U : required_alignment;
      }
      if ((adjusted_caps & 8) != 0) {
        flash_encryption_enabled = efuse_hal_flash_encryption_enabled();
        if (flash_encryption_enabled != 0) {
          required_alignment = required_alignment < 16U ? 16U : required_alignment;
        }
      }
      if ((adjusted_caps >> 0x11 & 3) != 0) {
        adjusted_caps = adjusted_caps & 0xfff9ffff | 8;
      }
      *size = -required_alignment & (requested_size - 1) + required_alignment;
      if ((adjusted_caps >> 10 & 1) != 0) {
        adjusted_caps = adjusted_caps & 0xfffffff7;
      }
      *alignment = required_alignment;
      *caps = adjusted_caps & 0xfff7ffff;
    }
    else {
      *caps = *caps | 0x80000000;
    }
  }
  return;
}

/* Native entry: 0x40385ed8. */
/*
 * Medius v3.4.7 — host application; 0x40385ed8.
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
 * aa40e8abd579f79ad52a128fa2755fd6ee2e6ee038b3bb187e5c63beac3085bc.
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

void multi_heap_assert_valid_block(const MultiHeap *heap,const TlsfBlock *block)

{
  uint pool_start;
  uint payload;

  pool_start = (uint)tlsf_get_pool(heap->heap_data);
  payload = (uint)block + 8U;
  /* pool_start skips metadata, but pool_size still includes those bytes. */
  if ((payload < pool_start) || (pool_start + heap->pool_size <= payload)) {
                    /* WARNING: Subroutine does not return */
    abort();
  }
  return;
}

/* Native entry: 0x40385ef4. */
/*
 * Medius v3.4.7 — host application; 0x40385ef4.
 *
 * Checks a nonzero power-of-two alignment, locks the owning heap and allocates through TLSF with an offset. Updates current and minimum free-byte counters on success.
 *
 * Calls: tlsf_alloc_overhead, tlsf_block_size, tlsf_memalign_offs, vPortExitCritical, xPortEnterCriticalTimeout,
 * xPortInIsrContext.
 *
 * Called by: heap_caps_aligned_alloc_base.
 *
 * Original function-byte SHA-256:
 * a334f8be712415718c9b83b907959b61adfc39bdfbc82fc01d018b9fa3c5ac43.
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

void * multi_heap_aligned_alloc_offs(MultiHeap *heap,uint size,uint alignment,uint offset)

{
  void *lock_or_allocation;
  uint block_size_or_free_bytes;
  int allocation_overhead;
  void *mux;

  if ((((size == 0) || (heap == (MultiHeap *)0x0 || size == 0)) ||
      ((alignment - 1 & alignment) != 0)) || (alignment == 0)) {
    lock_or_allocation = (void *)0x0;
  }
  else {
    lock_or_allocation = heap->lock;
    if (lock_or_allocation != (void *)0x0) {
      xPortInIsrContext();
      xPortEnterCriticalTimeout(lock_or_allocation,0xffffffff);
    }
    lock_or_allocation = (void *)tlsf_memalign_offs(heap->heap_data,alignment,size,offset);
    if (lock_or_allocation != (void *)0x0) {
      block_size_or_free_bytes = tlsf_block_size(lock_or_allocation);
      heap->free_bytes = heap->free_bytes - block_size_or_free_bytes;
      allocation_overhead = tlsf_alloc_overhead();
      block_size_or_free_bytes = heap->free_bytes - allocation_overhead;
      heap->free_bytes = block_size_or_free_bytes;
      if (block_size_or_free_bytes < heap->minimum_free_bytes) {
        heap->minimum_free_bytes = block_size_or_free_bytes;
      }
    }
    mux = heap->lock;
    if (mux != (void *)0x0) {
      xPortInIsrContext();
      vPortExitCritical(mux);
    }
  }
  return lock_or_allocation;
}

/* Native entry: 0x40385f6c. */
/*
 * Medius v3.4.7 — host application; 0x40385f6c.
 *
 * Checks the payload against the allocator coarse address range, locks the heap, restores the block size and allocator overhead to free-byte accounting and releases the TLSF block.
 *
 * Calls: multi_heap_assert_valid_block, tlsf_alloc_overhead, tlsf_block_size, tlsf_free, vPortExitCritical,
 * xPortEnterCriticalTimeout, xPortInIsrContext.
 *
 * Called by: heap_caps_free.
 *
 * Original function-byte SHA-256:
 * 7dfc0ad19e5a2bd77a52b999a6b3821fabdaad9727f742fd573f1af956b17b34.
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

void multi_heap_free(MultiHeap *heap,void *buffer)

{
  uint payload_size;
  int allocation_overhead;
  void *heap_lock;

  if ((heap != (MultiHeap *)0x0) && (buffer != (void *)0x0 && heap != (MultiHeap *)0x0))
  {
    multi_heap_assert_valid_block(heap,(const TlsfBlock *)((const unsigned char *)buffer - 8));
    heap_lock = heap->lock;
    if (heap_lock != (void *)0x0) {
      xPortInIsrContext();
      xPortEnterCriticalTimeout(heap_lock,0xffffffff);
    }
    payload_size = tlsf_block_size(buffer);
    heap->free_bytes = heap->free_bytes + payload_size;
    allocation_overhead = tlsf_alloc_overhead();
    heap->free_bytes = heap->free_bytes + allocation_overhead;
    tlsf_free(heap->heap_data,buffer);
    heap_lock = heap->lock;
    if (heap_lock != (void *)0x0) {
      xPortInIsrContext();
      vPortExitCritical(heap_lock);
    }
  }
  return;
}

/* Native entry: 0x40385fc4. */
/*
 * Medius v3.4.7 — host application; 0x40385fc4.
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

uint multi_heap_get_allocated_size(MultiHeap *heap,void *buffer)

{
  uint payload_size;

  payload_size = tlsf_block_size(buffer);
  return payload_size;
}

/* Native entry: 0x40385fd0. */
/*
 * Medius v3.4.7 — host application; 0x40385fd0.
 *
 * Locks the heap around TLSF allocation and updates current/minimum free-byte counters by the block size plus allocator overhead.
 *
 * Calls: tlsf_alloc_overhead, tlsf_block_size, tlsf_malloc, vPortExitCritical, xPortEnterCriticalTimeout,
 * xPortInIsrContext.
 *
 * Called by: heap_caps_aligned_alloc_base, multi_heap_realloc, FUN_42003cd0.
 *
 * Original function-byte SHA-256:
 * c9958766825b4926f917ab29000b5df5609ab51eaaf09709e0553ec49fb7222d.
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

void * multi_heap_malloc(MultiHeap *heap,uint size)

{
  void *lock_or_allocation;
  uint block_size_or_free_bytes;
  int allocation_overhead;
  void *mux;

  if ((size == 0) || (heap == (MultiHeap *)0x0 || size == 0)) {
    lock_or_allocation = (void *)0x0;
  }
  else {
    lock_or_allocation = heap->lock;
    if (lock_or_allocation != (void *)0x0) {
      xPortInIsrContext();
      xPortEnterCriticalTimeout(lock_or_allocation,0xffffffff);
    }
    lock_or_allocation = (void *)tlsf_malloc(heap->heap_data,size);
    if (lock_or_allocation != (void *)0x0) {
      block_size_or_free_bytes = tlsf_block_size(lock_or_allocation);
      heap->free_bytes = heap->free_bytes - block_size_or_free_bytes;
      allocation_overhead = tlsf_alloc_overhead();
      block_size_or_free_bytes = heap->free_bytes - allocation_overhead;
      heap->free_bytes = block_size_or_free_bytes;
      if (block_size_or_free_bytes < heap->minimum_free_bytes) {
        heap->minimum_free_bytes = block_size_or_free_bytes;
      }
    }
    mux = heap->lock;
    if (mux != (void *)0x0) {
      xPortInIsrContext();
      vPortExitCritical(mux);
    }
  }
  return lock_or_allocation;
}

/* Native entry: 0x40386034. */
/*
 * Medius v3.4.7 — host application; 0x40386034.
 *
 * Resizes a TLSF block under the heap lock, handles NULL/zero-size cases and updates free-byte accounting; asserts for a NULL heap.
 *
 * Calls: multi_heap_assert_valid_block, multi_heap_malloc, tlsf_block_size, tlsf_realloc, __assert_func, vPortExitCritical,
 * xPortEnterCriticalTimeout, xPortInIsrContext.
 *
 * Called by: heap_caps_realloc_base.
 *
 * Original function-byte SHA-256:
 * dff211df43b976dd4142cb00d177766371d232e5bafbd92516f201209ec4037c.
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

void * multi_heap_realloc(MultiHeap *heap,void *buffer,uint size)

{
  void *lock_or_replacement;
  uint block_size_or_free_bytes;
  void *mux;

  if (heap == (MultiHeap *)0x0) {
                    /* WARNING: Subroutine does not return */
    __assert_func((char *)0x0,0,(char *)0x0,(char *)0x0);
  }
  if (buffer == (void *)0x0) {
    lock_or_replacement = multi_heap_malloc(heap,size);
  }
  else {
    multi_heap_assert_valid_block(heap,(const TlsfBlock *)((const unsigned char *)buffer - 8));
    lock_or_replacement = heap->lock;
    if (lock_or_replacement != (void *)0x0) {
      xPortInIsrContext();
      xPortEnterCriticalTimeout(lock_or_replacement,0xffffffff);
    }
    block_size_or_free_bytes = tlsf_block_size(buffer);
    lock_or_replacement = tlsf_realloc(heap->heap_data,buffer,size);
    if (lock_or_replacement != (void *)0x0) {
      heap->free_bytes = heap->free_bytes + block_size_or_free_bytes;
      block_size_or_free_bytes = tlsf_block_size(lock_or_replacement);
      block_size_or_free_bytes = heap->free_bytes - block_size_or_free_bytes;
      heap->free_bytes = block_size_or_free_bytes;
      if (block_size_or_free_bytes < heap->minimum_free_bytes) {
        heap->minimum_free_bytes = block_size_or_free_bytes;
      }
    }
    mux = heap->lock;
    if (mux != (void *)0x0) {
      xPortInIsrContext();
      vPortExitCritical(mux);
    }
  }
  return lock_or_replacement;
}

/* Native entry: 0x403860b0. */
/*
 * Medius v3.4.7 — host application; 0x403860b0.
 *
 * Stores the supplied lock pointer in the heap descriptor. It neither creates nor initializes the
 * lock, takes it, validates either pointer, or frees a previous lock. The multi-heap callers use
 * this as an optional portMUX spinlock, not a recursive RTOS mutex.
 *
 * Called by: FUN_42003c8c, FUN_42003cd0.
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

void multi_heap_set_lock(MultiHeap *heap,void *lock)

{
  heap->lock = lock;
  return;
}

/* Native entry: 0x42003c04. */
/*
 * Medius v3.4.7 — host application; 0x42003c04.
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
 * fdc8789f9a43d554e7e39acb020f04a7856c7a73e755e3b8ae118396b454d469.
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

void heap_caps_get_info(MultiHeapInfo *information,uint capabilities)

{
  RegisteredHeapPointer region;
  uint previous_largest;
  MultiHeapInfo snapshot;

  memset(information,0,0x1c);
  for (region = REGISTERED_HEAPS; region != (RegisteredHeapPointer)0x0; region = region->next)
  {
    if ((region->heap != (MultiHeap *)0x0) &&
       ((~(region->caps[0] | region->caps[1] | region->caps[2]) & capabilities) == 0)) {
      multi_heap_get_info(region->heap,&snapshot);
      previous_largest = information->largest_free_block;
      information->total_free_bytes = information->total_free_bytes + snapshot.total_free_bytes
      ;
      information->total_allocated_bytes =
           information->total_allocated_bytes + snapshot.total_allocated_bytes;
      information->largest_free_block =
           previous_largest < snapshot.largest_free_block ? snapshot.largest_free_block : previous_largest;
      information->minimum_free_bytes =
           information->minimum_free_bytes + snapshot.minimum_free_bytes;
      information->allocated_blocks = information->allocated_blocks + snapshot.allocated_blocks
      ;
      information->free_blocks = information->free_blocks + snapshot.free_blocks;
      information->total_blocks = information->total_blocks + snapshot.total_blocks;
    }
  }
  return;
}

/* Native entry: 0x42003c78. */
/*
 * Medius v3.4.7 — host application; 0x42003c78.
 *
 * Collects the full 28-byte capability-filtered heap statistics into a local object and returns
 * its largest_free_block member at byte 8. It reports a snapshot, not a reservation; later
 * allocation may race other tasks.
 *
 * Calls: heap_caps_get_info.
 *
 * Called by: get_buffer_malloc.
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

uint heap_caps_get_largest_free_block(uint capabilities)

{
  MultiHeapInfo snapshot;

  heap_caps_get_info(&snapshot,capabilities);
  return snapshot.largest_free_block;
}

/* Native entry: 0x42003c8c. */
/*
 * Medius v3.4.7 — host application; 0x42003c8c.
 *
 * Registers remaining capability regions as heaps and attaches each successful heap to its embedded lock.
 *
 * Calls: multi_heap_set_lock, __assert_func, multi_heap_register.
 *
 * Called by: main_task.
 *
 * Original function-byte SHA-256:
 * e5256b39c0b629568c66602ab2a4fd25128fc5de1bc59e4dc608489bcb9f9050.
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
    for (HeapRegion *region = REGISTERED_HEAPS;
         region != 0; region = region->next) {
        if (region->heap != 0)
            continue;

        /* Match the native 32-bit subtraction without signed-overflow UB. */
        unsigned int start = (unsigned int)region->start;
        unsigned int bytes = (unsigned int)region->end - start;
        if (bytes > 0x02000000U)
            __assert_func(0, 0, 0, 0);

        MultiHeap *heap = multi_heap_register((void *)start, bytes);
        region->heap = heap;
        if (heap != 0)
            multi_heap_set_lock(heap, &region->lock_owner);
    }
}

/* Native entry: 0x42023ed0. */
/*
 * Medius v3.4.7 — host application; 0x42023ed0.
 *
 * Asserts a non-NULL region start and rejects fewer than 20 bytes. Reserves the 20-byte heap
 * descriptor, creates TLSF with max_bytes 0 at start+20, and stores its result even on failure.
 * On success clears the lock, records the remaining-region size, and initializes free/minimum-
 * free counters to that size minus TLSF metadata. This does not allocate its descriptor
 * separately, install a spinlock or validate that the supplied region is writable.
 *
 * Calls: tlsf_size, __assert_func, tlsf_create_with_pool.
 *
 * Called by: FUN_42003c8c, FUN_42003cd0.
 *
 * Original function-byte SHA-256:
 * c99ac31a703a17ab1a47c21d91aad7394395e76bd806748ada1b8606df694966.
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

MultiHeap * multi_heap_register(void *start,uint bytes)

{
  TlsfControl *control;
  uint metadata_size;
  MultiHeap *heap = (MultiHeap *)start;
  uint pool_bytes;

  if (start == (void *)0x0) {
                    /* WARNING: Subroutine does not return */
    __assert_func((char *)0x0,0,(char *)0x0,(char *)0x0);
  }
  if (0x13 < bytes) {
    pool_bytes = bytes - 0x14;
    control = tlsf_create_with_pool((void *)((unsigned char *)start + 20U),pool_bytes,0);
    heap->heap_data = control;
    if (control != (TlsfControl *)0x0) {
      heap->lock = (void *)0;
      metadata_size = tlsf_size(control);
      heap->free_bytes = pool_bytes - metadata_size;
      heap->pool_size = pool_bytes;
      heap->minimum_free_bytes = pool_bytes - metadata_size;
      return heap;
    }
  }
  return (MultiHeap *)0x0;
}

/* Native entry: 0x42023f1c. */
/*
 * Medius v3.4.7 — host application; 0x42023f1c.
 *
 * Clears all seven output words even for a NULL heap. With a heap, takes its optional spinlock,
 * walks TLSF blocks, subtracts metadata and four bytes per allocated block from occupied space,
 * copies free/minimum-free counters, then rounds the largest free payload to an allocable TLSF
 * size. Releases the optional lock. Requires a valid output; it is not a cross-heap atomic
 * snapshot.
 *
 * Calls: tlsf_alloc_overhead, tlsf_get_pool, tlsf_size, tlsf_walk_pool, tlsf_fit_size, memset,
 * vPortExitCritical, xPortEnterCriticalTimeout, xPortInIsrContext.
 *
 * Called by: heap_caps_get_info.
 *
 * Original function-byte SHA-256:
 * c9d059171639705853dc3af526e93e16167c9542ad66b4ef9ed3eefe8b13267d.
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

void multi_heap_get_info(MultiHeap *heap,MultiHeapInfo *information)

{
  uint allocation_overhead;
  uint largest_allocable;
  uint metadata_size;
  uint allocated_blocks;
  void *heap_lock;
  void *pool;
  uint pool_size;
  uint free_bytes;
  TlsfControl *control;
  uint minimum_free_bytes;

  memset(information,0,0x1c);
  if (heap != (MultiHeap *)0x0) {
    heap_lock = heap->lock;
    if (heap_lock != (void *)0x0) {
      xPortInIsrContext();
      xPortEnterCriticalTimeout(heap_lock,0xffffffff);
    }
    pool = tlsf_get_pool(heap->heap_data);
    tlsf_walk_pool(pool,multi_heap_get_info_tlsf,information);
    allocated_blocks = information->allocated_blocks;
    allocation_overhead = tlsf_alloc_overhead();
    pool_size = heap->pool_size;
    metadata_size = tlsf_size(heap->heap_data);
    free_bytes = heap->free_bytes;
    minimum_free_bytes = heap->minimum_free_bytes;
    control = heap->heap_data;
    information->total_allocated_bytes = ((pool_size - free_bytes) - metadata_size) - allocated_blocks * allocation_overhead;
    information->minimum_free_bytes = minimum_free_bytes;
    information->total_free_bytes = free_bytes;
    largest_allocable = tlsf_fit_size(control,information->largest_free_block);
    heap_lock = heap->lock;
    information->largest_free_block = largest_allocable;
    if (heap_lock != (void *)0x0) {
      xPortInIsrContext();
      vPortExitCritical(heap_lock);
    }
  }
  return;
}

/* Native entry: 0x42023f9c. */
/*
 * Medius v3.4.7 — host application; 0x42023f9c.
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

bool multi_heap_get_info_tlsf(void *unused_payload,uint size,int used,void *user)
{
  MultiHeapInfo *information = (MultiHeapInfo *)user;
  if (used == 0) {
    information->free_blocks += 1U;
    if (information->largest_free_block < size) {
      information->largest_free_block = size;
    }
  } else {
    information->allocated_blocks += 1U;
  }
  information->total_blocks += 1U;
  return true;
}

