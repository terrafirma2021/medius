/* Medius v3.4.7 host — memory/tlsf.c.
 * Recovered C and native assembly, grouped for source navigation.
 * Original entry addresses, firmware-byte hashes and function comments follow.
 */

#include "../include/types.h"

/* reconstruction utilities: NSAU also defines the zero-input result (32). */
static __inline__ __attribute__((always_inline)) int xtensa_count_leading_zeros(unsigned int value)
{
    int count;
    __asm__ ("nsau %0,%1" : "=a"(count) : "a"(value));
    return count;
}

/* Native entry: 0x403860b8. */
/*
 * Medius v3.4.7 — host application; 0x403860b8.
 *
 * Returns four bytes, the allocated-block size-word overhead on this 32-bit TLSF build. This
 * excludes free-list links and the previous-physical pointer, which overlap free payload or the
 * previous block.
 *
 * Called by: multi_heap_aligned_alloc_offs, multi_heap_free, multi_heap_malloc, multi_heap_get_info.
 *
 * Original function-byte SHA-256:
 * cebc5d75741ee728f371bf15e6f834d1cacd50ce35b264385313c30b542ee7b7.
 */

/* Reference: TLSF 2867f6883a12920b1969ff9624c0ab0e4185c2ce tlsf.c and tlsf_block_functions.h. */

/*
 * Returns: 4 bytes of allocated-block size-word overhead.
 * Requirements/effects: Constant query. Does not include free-list links or previous-physical
 *   storage that overlap free payload/neighbor space.
 */

uint tlsf_alloc_overhead(void)

{
  return 4;
}

/* Native entry: 0x403860c0. */
/*
 * Medius v3.4.7 — host application; 0x403860c0.
 *
 * Returns zero for NULL; otherwise reads the size word four bytes before payload and clears its
 * two low status bits. This is allocator payload capacity, not the original requested byte count.
 * It does not validate the address, block status or ownership.
 *
 * Called by: multi_heap_aligned_alloc_offs, multi_heap_free, multi_heap_get_allocated_size, multi_heap_malloc, multi_heap_realloc.
 *
 * Original function-byte SHA-256:
 * 65dcaad9a0940865489bf069c96bbe106909a3329c01f614dd09bcb9f89b0b55.
 */

/* Reference: TLSF 2867f6883a12920b1969ff9624c0ab0e4185c2ce tlsf.c. */

/*
 * payload: TLSF payload pointer or NULL.
 * Returns: 0 for NULL; otherwise the size word at payload-4 with low two status bits cleared.
 * Requirements/effects: Returns usable block capacity, not the original requested size. Performs
 *   no lock, ownership, bounds or allocation-state validation.
 */

uint tlsf_block_size(const void *payload)

{
  uint capacity;

  capacity = 0;
  if (payload != (void *)0x0) {
    capacity = *(uint *)((int)payload + -4) & 0xfffffffc;
  }
  return capacity;
}

/* Native entry: 0x403860d8. */
/*
 * Medius v3.4.7 — host application; 0x403860d8.
 *
 * Ignores NULL payload. Asserts the block is not already free, marks it and the successor
 * previous-free metadata, then coalesces eligible previous and next physical neighbors after
 * removing them from their size-class lists. Inserts the merged block and updates both bitmap
 * levels. No lock, ownership check, payload wipe or multi-heap free-byte accounting is supplied
 * here; those belong to callers. Both optional block_absorb_post_hook sites resolve to fixed
 * address 0 in this image and are skipped.
 *
 * Calls: __assert_func.
 *
 * Called by: multi_heap_free, tlsf_realloc.
 *
 * Optional coalescing-hook call sites: 2; linked address 0, skipped in this image.
 *
 * Original function-byte SHA-256:
 * 184ccbb3bad208557f7e232aa4e79065729a251c9ffbc570ea300dfa36987207.
 */

/* Reference: TLSF 2867f6883a12920b1969ff9624c0ab0e4185c2ce tlsf.c and tlsf_control_functions.h.
   The bit-count helper emits native NSAU (unsigned 32-bit leading zeros, including 32 for zero). The compiler reuses some address temporaries;
   &block->next_free denotes payload at block+8. */

/*
 * control: Initialized TLSF control/configuration/bitmap/list storage for this allocation;
 *   required when payload is non-NULL.
 * payload: Live used payload from this TLSF pool, or NULL for a no-op.
 * Returns: Nothing; inconsistent free status, neighbor/list pointers, sizes or alignment assert.
 * Requirements/effects: Marks the block and successor previous-free metadata, removes eligible
 *   free neighbors from their size classes, coalesces and reinserts the merged block with bitmap
 *   updates. Requires external synchronization and intact metadata. Does not wipe data or update
 *   multi-heap accounting. Both optional post-absorb hook targets are0 in this image.
 */

void tlsf_free(TlsfControl *control,void *payload)

{
  TlsfBlock *next_physical;
  TlsfBlock *previous_free_link;
  uint size_flags_config_or_bitmap;
  int most_significant_bit;
  TlsfBlock *merged_block;
  uint size_or_second_class;
  TlsfBlock *next_free_link;
  uint small_limit_or_first_class;
  TlsfBlock **free_lists;
  TlsfBlock *neighbor_or_head;
  int bit_length;
  uint *second_bitmaps;
  uint config_size_or_class_index;

  if (payload == (void *)0x0) {
    return;
  }
  merged_block = (TlsfBlock *)((int)payload + -8);
  size_flags_config_or_bitmap = *(uint *)((int)payload + -4);
  if (((size_flags_config_or_bitmap & 1) != 0) ||
     (next_physical = (TlsfBlock *)((int)payload + ((size_flags_config_or_bitmap & 0xfffffffc) - 4)), size_flags_config_or_bitmap < 4))
  goto invariant_failure;
  /* Mark this block free and publish its backlink/previous-free flag to the successor. */
  next_physical->size_flags = next_physical->size_flags | 2;
  size_flags_config_or_bitmap = *(uint *)((int)payload + -4);
  next_physical->previous_physical = merged_block;
  *(uint *)((int)payload + -4) = size_flags_config_or_bitmap | 1;
  /* block_merge_prev: remove and absorb the preceding free neighbor when flagged. */
  if ((size_flags_config_or_bitmap & 2) == 0) {
    neighbor_or_head = (TlsfBlock *)((int)payload + ((size_flags_config_or_bitmap & 0xfffffffc) - 4));
    if ((size_flags_config_or_bitmap | 1) < 4) goto invariant_failure;
  }
  else {
    merged_block = merged_block->previous_physical;
    if ((merged_block == (TlsfBlock *)0x0) || (size_flags_config_or_bitmap = merged_block->size_flags, (size_flags_config_or_bitmap & 1) == 0))
    goto invariant_failure;
    config_size_or_class_index = control->configuration;
    size_or_second_class = size_flags_config_or_bitmap & 0xfffffffc;
    small_limit_or_first_class = config_size_or_class_index >> 0x17 & 0xff;
    if (size_or_second_class < small_limit_or_first_class) {
      size_or_second_class = (int)size_or_second_class / (int)(small_limit_or_first_class / (config_size_or_class_index >> 0xe & 0x3f));
      config_size_or_class_index = 0;
    }
    else {
      if (size_or_second_class == 0) {
        most_significant_bit = -1;
        bit_length = 0;
      }
      else {
        bit_length = -(xtensa_count_leading_zeros(size_or_second_class) + -0x20);
        most_significant_bit = -(xtensa_count_leading_zeros(size_or_second_class) + -0x1f);
      }
      size_or_second_class = size_or_second_class >> (most_significant_bit - (config_size_or_class_index >> 0x14 & 7) & 0x1f) ^
              1U << (config_size_or_class_index >> 0x14 & 7);
      config_size_or_class_index = bit_length - (config_size_or_class_index >> 5 & 7);
    }
    neighbor_or_head = merged_block->previous_free;
    next_free_link = (TlsfBlock *)merged_block->next_free;
    if ((neighbor_or_head == (TlsfBlock *)0x0) || (next_free_link == (TlsfBlock *)0x0))
    goto invariant_failure;
    next_free_link->previous_free = neighbor_or_head;
    neighbor_or_head->next_free = (TlsfBlock *)next_free_link;
    if ((merged_block == control->free_lists[(control->configuration >> 0xe & 0x3f) * config_size_or_class_index + size_or_second_class]) &&
       (control->free_lists[(control->configuration >> 0xe & 0x3f) * config_size_or_class_index + size_or_second_class] =
             (TlsfBlock *)next_free_link, next_free_link == &control->null_block)) {
      size_flags_config_or_bitmap = control->second_level_bitmaps[config_size_or_class_index];
      size_flags_config_or_bitmap = 1U << (size_or_second_class & 0x1f) & size_flags_config_or_bitmap ^ size_flags_config_or_bitmap;
      control->second_level_bitmaps[config_size_or_class_index] = size_flags_config_or_bitmap;
      if (size_flags_config_or_bitmap == 0) {
        size_flags_config_or_bitmap = merged_block->size_flags;
        control->first_level_bitmap =
             1U << (config_size_or_class_index & 0x1f) & control->first_level_bitmap ^
             control->first_level_bitmap;
      }
      else {
        size_flags_config_or_bitmap = merged_block->size_flags;
      }
    }
    if (size_flags_config_or_bitmap < 4) goto invariant_failure;
    size_flags_config_or_bitmap = (*(uint *)((int)payload + -4) & 0xfffffffc) + 4 + size_flags_config_or_bitmap;
    merged_block->size_flags = size_flags_config_or_bitmap;
    payload = &merged_block->next_free;
    neighbor_or_head = (TlsfBlock *)((int)&merged_block->size_flags + (size_flags_config_or_bitmap & 0xfffffffc));
    if (size_flags_config_or_bitmap < 4) goto invariant_failure;
    neighbor_or_head->previous_physical = merged_block;
  }
  /* block_merge_next: inspect and, if free, unlink and absorb the successor. */
  if (neighbor_or_head == (TlsfBlock *)0x0) goto invariant_failure;
  if ((neighbor_or_head->size_flags & 1) == 0) {
    free_lists = control->free_lists;
    config_size_or_class_index = merged_block->size_flags & 0xfffffffc;
  }
  else {
    size_flags_config_or_bitmap = control->configuration;
    config_size_or_class_index = size_flags_config_or_bitmap >> 0x17 & 0xff;
    size_or_second_class = neighbor_or_head->size_flags & 0xfffffffc;
    if (size_or_second_class < config_size_or_class_index) {
      config_size_or_class_index = (int)size_or_second_class / (int)(config_size_or_class_index / (size_flags_config_or_bitmap >> 0xe & 0x3f));
      size_flags_config_or_bitmap = 0;
    }
    else {
      if (size_or_second_class == 0) {
        most_significant_bit = -1;
        bit_length = 0;
      }
      else {
        bit_length = -(xtensa_count_leading_zeros(size_or_second_class) + -0x20);
        most_significant_bit = -(xtensa_count_leading_zeros(size_or_second_class) + -0x1f);
      }
      config_size_or_class_index = size_or_second_class >> (most_significant_bit - (size_flags_config_or_bitmap >> 0x14 & 7) & 0x1f) ^
               1U << (size_flags_config_or_bitmap >> 0x14 & 7);
      size_flags_config_or_bitmap = bit_length - (size_flags_config_or_bitmap >> 5 & 7);
    }
    previous_free_link = neighbor_or_head->previous_free;
    next_free_link = (TlsfBlock *)neighbor_or_head->next_free;
    if ((previous_free_link == (TlsfBlock *)0x0) || (next_free_link == (TlsfBlock *)0x0))
    goto invariant_failure;
    next_free_link->previous_free = previous_free_link;
    previous_free_link->next_free = (TlsfBlock *)next_free_link;
    free_lists = control->free_lists;
    if ((free_lists[(control->configuration >> 0xe & 0x3f) * size_flags_config_or_bitmap + config_size_or_class_index] == neighbor_or_head) &&
       (free_lists[(control->configuration >> 0xe & 0x3f) * size_flags_config_or_bitmap + config_size_or_class_index] = (TlsfBlock *)next_free_link
       , next_free_link == &control->null_block)) {
      size_or_second_class = control->second_level_bitmaps[size_flags_config_or_bitmap];
      size_or_second_class = 1U << (config_size_or_class_index & 0x1f) & size_or_second_class ^ size_or_second_class;
      control->second_level_bitmaps[size_flags_config_or_bitmap] = size_or_second_class;
      if (size_or_second_class == 0) {
        control->first_level_bitmap =
             1U << (size_flags_config_or_bitmap & 0x1f) & control->first_level_bitmap ^
             control->first_level_bitmap;
      }
      size_flags_config_or_bitmap = merged_block->size_flags;
      if (size_flags_config_or_bitmap < 4) goto invariant_failure;
      size_or_second_class = neighbor_or_head->size_flags & 0xfffffffc;
    }
    else {
      size_flags_config_or_bitmap = merged_block->size_flags;
    }
    size_flags_config_or_bitmap = size_flags_config_or_bitmap + size_or_second_class + 4;
    config_size_or_class_index = size_flags_config_or_bitmap & 0xfffffffc;
    merged_block->size_flags = size_flags_config_or_bitmap;
    if (size_flags_config_or_bitmap < 4) goto invariant_failure;
    *(TlsfBlock **)((int)payload + (config_size_or_class_index - 4)) = merged_block;
  }
  /* block_insert: return the merged block to its size class and set both bitmap bits. */
  size_flags_config_or_bitmap = control->configuration;
  size_or_second_class = size_flags_config_or_bitmap >> 0x17 & 0xff;
  if (config_size_or_class_index < size_or_second_class) {
    config_size_or_class_index = (int)config_size_or_class_index / (int)(size_or_second_class / (size_flags_config_or_bitmap >> 0xe & 0x3f));
    small_limit_or_first_class = 0;
    size_or_second_class = config_size_or_class_index;
  }
  else {
    small_limit_or_first_class = -(size_flags_config_or_bitmap >> 5 & 7) - (xtensa_count_leading_zeros(config_size_or_class_index) + -0x20);
    size_or_second_class = config_size_or_class_index >> (-(size_flags_config_or_bitmap >> 0x14 & 7) - (xtensa_count_leading_zeros(config_size_or_class_index) + -0x1f) & 0x1f) ^
            1U << (size_flags_config_or_bitmap >> 0x14 & 7);
    config_size_or_class_index = (size_flags_config_or_bitmap >> 0xe & 0x3f) * small_limit_or_first_class + size_or_second_class;
  }
  neighbor_or_head = free_lists[config_size_or_class_index];
  if (neighbor_or_head != (TlsfBlock *)0x0) {
    merged_block->next_free = neighbor_or_head;
    merged_block->previous_free = &control->null_block;
    neighbor_or_head->previous_free = merged_block;
    if (payload == (unsigned char *)((uint)((int)payload + 3) & 0xfffffffc)) {
      size_flags_config_or_bitmap = control->first_level_bitmap;
      second_bitmaps = control->second_level_bitmaps;
      free_lists[(control->configuration >> 0xe & 0x3f) * small_limit_or_first_class + size_or_second_class] = merged_block;
      control->first_level_bitmap = size_flags_config_or_bitmap | 1U << (small_limit_or_first_class & 0x1f);
      second_bitmaps[small_limit_or_first_class] = second_bitmaps[small_limit_or_first_class] | 1U << (size_or_second_class & 0x1f);
      return;
    }
  }
invariant_failure:
                    /* WARNING: Subroutine does not return */
  __assert_func((char *)0x0,0,(char *)0x0,(char *)0x0);
}

/* Native entry: 0x403863c8. */
/*
 * Medius v3.4.7 — host application; 0x403863c8.
 *
 * Returns NULL for NULL control; otherwise adds metadata_size at control+20 to the control
 * address. This compiled specialization includes the inlined NULL-aware tlsf_size calculation. It
 * locates the original pool; it does not allocate, validate metadata or enumerate added pools.
 *
 * Called by: multi_heap_assert_valid_block, multi_heap_get_info.
 *
 * Original function-byte SHA-256:
 * ff615a5863296fda2a6714b2e6730d3bbaa4b31953681faf3faed96f05b83ba4.
 */

/* Reference: TLSF 2867f6883a12920b1969ff9624c0ab0e4185c2ce tlsf.c. */

/*
 * control: TLSF control whose metadata_size locates the initial pool; may be NULL.
 * Returns: NULL for NULL control; otherwise control address plus metadata_size.
 * Requirements/effects: Does not validate metadata, allocate memory or enumerate subsequently
 *   added pools. Non-NULL control must be readable.
 */

void * tlsf_get_pool(TlsfControl *control)

{
  void *pool;

  pool = (void *)0x0;
  if (control != (TlsfControl *)0x0) {
    pool = (void *)((unsigned char *)control + control->metadata_size);
  }
  return pool;
}

/* Native entry: 0x403863d4. */
/*
 * Medius v3.4.7 — host application; 0x403863d4.
 *
 * Aligns a nonzero request to four bytes and enforces the 12-byte minimum below the compiled FL
 * maximum. GoodFit mapping may round it further. Searches second/first-level bitmaps, unlinks a
 * suitable head, splits a tail only when at least 16 bytes remain, reinserts that free tail and
 * marks the returned block used. Returns NULL when adjustment or lookup cannot be satisfied. Does
 * not zero payload, acquire locks or update multi-heap counters. Request round-up uses native
 * 32-bit wrapping; this internal API has no independent size+3 overflow check.
 *
 * Calls: __assert_func.
 *
 * Called by: multi_heap_malloc, tlsf_realloc.
 *
 * Original function-byte SHA-256:
 * 190f6e9f4c17372a495864a11042c28e793df1d830ff13c4a7d9d9a23b0c8b1c.
 */

/* Reference: TLSF 2867f6883a12920b1969ff9624c0ab0e4185c2ce tlsf.c and tlsf_control_functions.h.
   The bit-count helper emits native NSAU (unsigned 32-bit leading zeros, including 32 for zero). The compiler reuses some address temporaries;
   &block->next_free denotes payload at block+8. */

/*
 * control: Initialized TLSF control with valid class configuration and sentinel/list state; NULL
 *   returns NULL.
 * size: Requested payload bytes;0 returns NULL. Caller bounds size before internal32-bit round-up.
 * Returns: Payload pointer or NULL when request adjustment or free-class search cannot be
 *   satisfied.
 * Requirements/effects: Rounds to4 bytes with minimum12, performs GoodFit mapping, scans bitmaps
 *   and removes a suitable head. Splits a free tail only when at least16 bytes remain, reinserts
 *   it and marks the allocated block used. Metadata inconsistencies assert. No zero-fill, lock or
 *   multi-heap counters. Native size+3 can wrap.
 */

void * tlsf_malloc(TlsfControl *control,uint size)

{
  void *allocated_payload;
  uint size_or_second_class_or_bitmap;
  TlsfBlock *next_free_link;
  int bit_length_or_most_significant_bit;
  uint config_size_or_bitmap;
  TlsfBlock *split_or_previous_link;
  uint *successor_size_word;
  TlsfBlock *previous_head;
  uint request_size_or_second_class;
  uint first_class_or_rounding_mask;
  int most_significant_bit_or_bit_length;
  uint *second_bitmaps;
  uint second_bitmap_or_class_parameter;
  TlsfBlock *selected_block;
  TlsfBlock **free_lists;

  /* adjust_request_size: align4, enforce minimum12, then map GoodFit size. */
  if (size == 0) {
    return (void *)0x0;
  }
  size_or_second_class_or_bitmap = size + 3 & 0xfffffffc;
  if (control == (TlsfControl *)0x0) {
    return (void *)0x0;
  }
  config_size_or_bitmap = control->configuration;
  if ((uint)(1U << (config_size_or_bitmap >> 8 & 0x1f)) <= size_or_second_class_or_bitmap) {
    return (void *)0x0;
  }
  request_size_or_second_class = (uint)(size_or_second_class_or_bitmap < 0xc) * 0xc + (size_or_second_class_or_bitmap >= 0xc) * size_or_second_class_or_bitmap;
  size_or_second_class_or_bitmap = config_size_or_bitmap >> 0x17 & 0xff;
  if (request_size_or_second_class < size_or_second_class_or_bitmap) {
map_small_request:
    size_or_second_class_or_bitmap = (int)request_size_or_second_class / (int)(size_or_second_class_or_bitmap / (config_size_or_bitmap >> 0xe & 0x3f));
    first_class_or_rounding_mask = 0;
  }
  else {
    second_bitmap_or_class_parameter = config_size_or_bitmap >> 0x14 & 7;
    first_class_or_rounding_mask = 1U << (-second_bitmap_or_class_parameter - (xtensa_count_leading_zeros(request_size_or_second_class) + -0x1f) & 0x1f);
    if ((first_class_or_rounding_mask - 1 & first_class_or_rounding_mask) != 0) goto invariant_failure;
    request_size_or_second_class = (request_size_or_second_class - 1) + first_class_or_rounding_mask & -first_class_or_rounding_mask;
    if (request_size_or_second_class < size_or_second_class_or_bitmap) goto map_small_request;
    if (request_size_or_second_class == 0) {
      most_significant_bit_or_bit_length = -1;
      bit_length_or_most_significant_bit = 0;
    }
    else {
      bit_length_or_most_significant_bit = -(xtensa_count_leading_zeros(request_size_or_second_class) + -0x20);
      most_significant_bit_or_bit_length = -(xtensa_count_leading_zeros(request_size_or_second_class) + -0x1f);
    }
    size_or_second_class_or_bitmap = request_size_or_second_class >> (most_significant_bit_or_bit_length - second_bitmap_or_class_parameter & 0x1f) ^ 1U << (config_size_or_bitmap >> 0x14 & 7);
    first_class_or_rounding_mask = bit_length_or_most_significant_bit - (config_size_or_bitmap >> 5 & 7);
  }
  if ((int)(config_size_or_bitmap & 0x1f) <= (int)first_class_or_rounding_mask) {
    return (void *)0x0;
  }
  /* search_suitable_block: scan SL bitmap, then the next nonempty FL bucket. */
  second_bitmaps = control->second_level_bitmaps;
  size_or_second_class_or_bitmap = 0xffffffffU << (size_or_second_class_or_bitmap & 0x1f);
  second_bitmap_or_class_parameter = size_or_second_class_or_bitmap & second_bitmaps[first_class_or_rounding_mask];
  if ((size_or_second_class_or_bitmap & second_bitmaps[first_class_or_rounding_mask]) == 0) {
    first_class_or_rounding_mask = 0xffffffffU << (first_class_or_rounding_mask + 1 & 0x1f);
    size_or_second_class_or_bitmap = first_class_or_rounding_mask & control->first_level_bitmap;
    if ((first_class_or_rounding_mask & control->first_level_bitmap) == 0) {
      return (void *)0x0;
    }
    first_class_or_rounding_mask = -(xtensa_count_leading_zeros(-size_or_second_class_or_bitmap & size_or_second_class_or_bitmap) + -0x1f);
    second_bitmap_or_class_parameter = second_bitmaps[first_class_or_rounding_mask & 0xffff];
    if (second_bitmap_or_class_parameter == 0) goto invariant_failure;
  }
  free_lists = control->free_lists;
  size_or_second_class_or_bitmap = -(xtensa_count_leading_zeros(-second_bitmap_or_class_parameter & second_bitmap_or_class_parameter) + -0x1f);
  selected_block = free_lists[(config_size_or_bitmap >> 0xe & 0x3f) * first_class_or_rounding_mask + size_or_second_class_or_bitmap];
  if (selected_block == (TlsfBlock *)0x0) {
    return (void *)0x0;
  }
  /* remove_free_block, block_trim_free, then block_mark_as_used. */
  if (request_size_or_second_class <= (selected_block->size_flags & 0xfffffffc)) {
    split_or_previous_link = selected_block->previous_free;
    next_free_link = (TlsfBlock *)selected_block->next_free;
    if ((split_or_previous_link != (TlsfBlock *)0x0) && (next_free_link != (TlsfBlock *)0x0)) {
      next_free_link->previous_free = split_or_previous_link;
      split_or_previous_link->next_free = (TlsfBlock *)next_free_link;
      if ((selected_block == free_lists[(control->configuration >> 0xe & 0x3f) * first_class_or_rounding_mask + size_or_second_class_or_bitmap]) &&
         ((free_lists[(control->configuration >> 0xe & 0x3f) * first_class_or_rounding_mask + size_or_second_class_or_bitmap] =
                (TlsfBlock *)next_free_link, next_free_link == &control->null_block &&
          (config_size_or_bitmap = second_bitmaps[first_class_or_rounding_mask], config_size_or_bitmap = 1U << (size_or_second_class_or_bitmap & 0x1f) & config_size_or_bitmap ^ config_size_or_bitmap,
          second_bitmaps[first_class_or_rounding_mask] = config_size_or_bitmap, config_size_or_bitmap == 0)))) {
        control->first_level_bitmap =
             1U << (first_class_or_rounding_mask & 0x1f) & control->first_level_bitmap ^
             control->first_level_bitmap;
      }
      if ((request_size_or_second_class != 0) && (size_or_second_class_or_bitmap = selected_block->size_flags, (size_or_second_class_or_bitmap & 1) != 0)) {
        config_size_or_bitmap = size_or_second_class_or_bitmap & 0xfffffffc;
        allocated_payload = (void *)((unsigned char *)selected_block + 8U);
        if (request_size_or_second_class + 0x10 <= config_size_or_bitmap) {
          split_or_previous_link = (TlsfBlock *)((request_size_or_second_class - 4) + (int)allocated_payload);
          size_or_second_class_or_bitmap = config_size_or_bitmap - (request_size_or_second_class + 4);
          if (((&split_or_previous_link->next_free !=
                (TlsfBlock **)((uint)((int)&split_or_previous_link->next_free + 3) & 0xfffffffc)) ||
              (config_size_or_bitmap != request_size_or_second_class + 4 + size_or_second_class_or_bitmap)) ||
             (split_or_previous_link->size_flags = split_or_previous_link->size_flags & 3 | size_or_second_class_or_bitmap, (size_or_second_class_or_bitmap & 0xfffffffc) < 0xc))
          goto invariant_failure;
          selected_block->size_flags = selected_block->size_flags & 3 | request_size_or_second_class;
          successor_size_word = (uint *)((split_or_previous_link->size_flags & 0xfffffffc) + (int)&split_or_previous_link->next_free);
          if (split_or_previous_link->size_flags < 4) goto invariant_failure;
          *successor_size_word = *successor_size_word | 2;
          size_or_second_class_or_bitmap = split_or_previous_link->size_flags;
          successor_size_word[-1] = (uint)split_or_previous_link;
          split_or_previous_link->size_flags = size_or_second_class_or_bitmap | 1;
          if (selected_block->size_flags < 4) goto invariant_failure;
          *(TlsfBlock **)((int)allocated_payload + ((selected_block->size_flags & 0xfffffffc) - 4)) = selected_block;
          split_or_previous_link->size_flags = size_or_second_class_or_bitmap | 3;
          request_size_or_second_class = control->configuration;
          size_or_second_class_or_bitmap = size_or_second_class_or_bitmap & 0xfffffffc;
          first_class_or_rounding_mask = request_size_or_second_class >> 0x17 & 0xff;
          config_size_or_bitmap = request_size_or_second_class >> 0xe & 0x3f;
          if (size_or_second_class_or_bitmap < first_class_or_rounding_mask) {
            size_or_second_class_or_bitmap = (int)size_or_second_class_or_bitmap / (int)(first_class_or_rounding_mask / config_size_or_bitmap);
            first_class_or_rounding_mask = 0;
            request_size_or_second_class = size_or_second_class_or_bitmap;
          }
          else {
            if (size_or_second_class_or_bitmap == 0) {
              bit_length_or_most_significant_bit = -1;
              most_significant_bit_or_bit_length = 0;
            }
            else {
              most_significant_bit_or_bit_length = -(xtensa_count_leading_zeros(size_or_second_class_or_bitmap) + -0x20);
              bit_length_or_most_significant_bit = -(xtensa_count_leading_zeros(size_or_second_class_or_bitmap) + -0x1f);
            }
            first_class_or_rounding_mask = most_significant_bit_or_bit_length - (request_size_or_second_class >> 5 & 7);
            request_size_or_second_class = size_or_second_class_or_bitmap >> (bit_length_or_most_significant_bit - (request_size_or_second_class >> 0x14 & 7) & 0x1f) ^
                    1U << (request_size_or_second_class >> 0x14 & 7);
            size_or_second_class_or_bitmap = first_class_or_rounding_mask * config_size_or_bitmap + request_size_or_second_class;
          }
          previous_head = free_lists[size_or_second_class_or_bitmap];
          if (previous_head == (TlsfBlock *)0x0) goto invariant_failure;
          split_or_previous_link->previous_free = &control->null_block;
          split_or_previous_link->next_free = previous_head;
          previous_head->previous_free = split_or_previous_link;
          size_or_second_class_or_bitmap = control->first_level_bitmap;
          free_lists[(control->configuration >> 0xe & 0x3f) * first_class_or_rounding_mask + request_size_or_second_class] = split_or_previous_link;
          control->first_level_bitmap = size_or_second_class_or_bitmap | 1U << (first_class_or_rounding_mask & 0x1f);
          second_bitmaps[first_class_or_rounding_mask] = second_bitmaps[first_class_or_rounding_mask] | 1U << (request_size_or_second_class & 0x1f);
          size_or_second_class_or_bitmap = selected_block->size_flags;
          config_size_or_bitmap = size_or_second_class_or_bitmap & 0xfffffffc;
        }
        if (3 < size_or_second_class_or_bitmap) {
          *(uint *)((int)&selected_block->next_free + config_size_or_bitmap) =
               *(uint *)((int)&selected_block->next_free + config_size_or_bitmap) & 0xfffffffd;
          selected_block->size_flags = selected_block->size_flags & 0xfffffffe;
          return allocated_payload;
        }
      }
    }
  }
invariant_failure:
                    /* WARNING: Subroutine does not return */
  __assert_func((char *)0x0,0,(char *)0x0,(char *)0x0);
}

/* Native entry: 0x403866a0. */
/*
 * Medius v3.4.7 — host application; 0x403866a0.
 *
 * Returns a pointer whose sum with data_offset rounded up to four bytes meets the requested
 * alignment, for valid caller arguments. Aligns size and data_offset to four bytes, reserves
 * extra alignment/split space when alignment exceeds 4, locates a free block, chooses an aligned
 * target and enforces a leading gap large enough for metadata and rounded offset.
 * Splits/reinserts the leading free block when needed, trims a trailing free block and marks the
 * result used. Align-up operations assert the power-of-two bit test when reached; zero alignment
 * is not separately rejected here, while the outer multi-heap API rejects it. It relies on valid
 * configuration and supplies no heap lock, zero fill or accounting update. All request/gap
 * arithmetic uses native 32-bit wrapping.
 *
 * Calls: __assert_func.
 *
 * Called by: multi_heap_aligned_alloc_offs.
 *
 * Original function-byte SHA-256:
 * e8281eda8c9d3382e94e68b26bf86e257683674c6b2db829833833dc345032cc.
 */

/* Reference: TLSF 2867f6883a12920b1969ff9624c0ab0e4185c2ce tlsf.c and tlsf_control_functions.h.
   The bit-count helper emits native NSAU (unsigned 32-bit leading zeros, including 32 for zero). The compiler reuses some address temporaries;
   &block->next_free denotes payload at block+8. */

/*
 * control: Initialized TLSF allocator with valid class configuration and metadata.
 * alignment: Caller-supplied nonzero power of two; outer multi-heap API validates it. Internal
 *   power-of-two assertions are reached conditionally.
 * size: Requested nonzero payload bytes; caller must prevent native32-bit request arithmetic from
 *   overflowing.
 * data_offset: Offset rounded up to4 bytes; returned payload plus this rounded offset meets
 *   alignment for valid inputs.
 * Returns: Payload pointer or NULL on unsatisfied size/class search; invalid reached
 *   alignment/metadata assertions abort.
 * Requirements/effects: Reserves extra gap/split space, locates and unlinks a free block, plans a
 *   leading gap large enough for metadata plus rounded offset, reinserts a leading free block when
 *   needed and trims/reinserts a trailing block. Does not lock, wipe or update multi-heap
 *   counters. Zero alignment has no independent rejection here; do not use it.
 */

void * tlsf_memalign_offs(TlsfControl *control,uint alignment,uint size,uint data_offset)

{
  int span_or_most_significant_bit;
  uint first_bitmap_candidates;
  uint size_flags_or_adjusted_request;
  uint minimum_payload_size;
  int most_significant_bit;
  uint second_class_or_alignment_value;
  TlsfBlock *split_or_previous_link;
  uint *successor_size_word;
  TlsfBlock *previous_head;
  uint rounding_mask_or_second_bitmap;
  TlsfBlock *selected_block;
  uint config_size_or_gap;
  unsigned char *aligned_target;
  TlsfBlock *next_free_link;
  uint second_level_index_bits;
  TlsfBlock **payload_or_free_lists;
  uint first_class_or_minimum_gap;
  uint *second_bitmaps;
  TlsfBlock **free_lists;

  if (((size == 0) || (size_flags_or_adjusted_request = size + 3 & 0xfffffffc, control == (TlsfControl *)0x0)) ||
     (config_size_or_gap = control->configuration, (uint)(1U << (config_size_or_gap >> 8 & 0x1f)) <= size_flags_or_adjusted_request))
  {
    if (alignment + 0x10 == 0) {
      return (void *)0x0;
    }
    if ((alignment - 1 & alignment) == 0) {
      return (void *)0x0;
    }
    goto invariant_failure;
  }
  minimum_payload_size = (uint)(size_flags_or_adjusted_request < 0xc) * 0xc + (size_flags_or_adjusted_request >= 0xc) * size_flags_or_adjusted_request;
  span_or_most_significant_bit = minimum_payload_size + alignment + 0x10;
  size_flags_or_adjusted_request = minimum_payload_size;
  if (span_or_most_significant_bit == 0) {
    if (4 < alignment) {
      return (void *)0x0;
    }
  }
  else {
    if ((alignment & alignment - 1) != 0) goto invariant_failure;
    second_class_or_alignment_value = -alignment & span_or_most_significant_bit + (alignment - 1);
    if (second_class_or_alignment_value < (uint)(1U << (config_size_or_gap >> 8 & 0x1f))) {
      if (4 < alignment) {
        size_flags_or_adjusted_request = (uint)(second_class_or_alignment_value < 0xc) * 0xc + (second_class_or_alignment_value >= 0xc) * second_class_or_alignment_value;
      }
    }
    else if (4 < alignment) {
      return (void *)0x0;
    }
  }
  /* block_locate_free: GoodFit search and unlink before alignment trimming. */
  second_class_or_alignment_value = config_size_or_gap >> 0x17 & 0xff;
  if (size_flags_or_adjusted_request < second_class_or_alignment_value) {
map_small_search_size:
    second_class_or_alignment_value = (int)size_flags_or_adjusted_request / (int)(second_class_or_alignment_value / (config_size_or_gap >> 0xe & 0x3f));
    first_class_or_minimum_gap = 0;
  }
  else {
    second_level_index_bits = config_size_or_gap >> 0x14 & 7;
    rounding_mask_or_second_bitmap = 1U << (-second_level_index_bits - (xtensa_count_leading_zeros(size_flags_or_adjusted_request) + -0x1f) & 0x1f);
    first_class_or_minimum_gap = rounding_mask_or_second_bitmap - 1 & rounding_mask_or_second_bitmap;
    if ((rounding_mask_or_second_bitmap - 1 & rounding_mask_or_second_bitmap) != 0) goto invariant_failure;
    size_flags_or_adjusted_request = (size_flags_or_adjusted_request - 1) + rounding_mask_or_second_bitmap & -rounding_mask_or_second_bitmap;
    if (size_flags_or_adjusted_request < second_class_or_alignment_value) goto map_small_search_size;
    span_or_most_significant_bit = -1;
    if (size_flags_or_adjusted_request != 0) {
      first_class_or_minimum_gap = -(xtensa_count_leading_zeros(size_flags_or_adjusted_request) + -0x20);
      span_or_most_significant_bit = -(xtensa_count_leading_zeros(size_flags_or_adjusted_request) + -0x1f);
    }
    second_class_or_alignment_value = size_flags_or_adjusted_request >> (span_or_most_significant_bit - second_level_index_bits & 0x1f) ^ 1U << (config_size_or_gap >> 0x14 & 7);
    first_class_or_minimum_gap = first_class_or_minimum_gap - (config_size_or_gap >> 5 & 7);
  }
  if ((int)(config_size_or_gap & 0x1f) <= (int)first_class_or_minimum_gap) {
    return (void *)0x0;
  }
  second_bitmaps = control->second_level_bitmaps;
  second_class_or_alignment_value = 0xffffffffU << (second_class_or_alignment_value & 0x1f);
  rounding_mask_or_second_bitmap = second_class_or_alignment_value & second_bitmaps[first_class_or_minimum_gap];
  if ((second_class_or_alignment_value & second_bitmaps[first_class_or_minimum_gap]) == 0) {
    second_class_or_alignment_value = 0xffffffffU << (first_class_or_minimum_gap + 1 & 0x1f);
    first_bitmap_candidates = second_class_or_alignment_value & control->first_level_bitmap;
    if ((second_class_or_alignment_value & control->first_level_bitmap) == 0) {
      return (void *)0;
    }
    first_class_or_minimum_gap = -(xtensa_count_leading_zeros((0U - first_bitmap_candidates) & first_bitmap_candidates) + -0x1f);
    rounding_mask_or_second_bitmap = second_bitmaps[first_class_or_minimum_gap & 0xffff];
    if (rounding_mask_or_second_bitmap == 0) goto invariant_failure;
  }
  free_lists = control->free_lists;
  second_class_or_alignment_value = -(xtensa_count_leading_zeros(-rounding_mask_or_second_bitmap & rounding_mask_or_second_bitmap) + -0x1f);
  selected_block = free_lists[(config_size_or_gap >> 0xe & 0x3f) * first_class_or_minimum_gap + second_class_or_alignment_value];
  if (selected_block == (TlsfBlock *)0x0) {
    return (void *)0x0;
  }
  if ((selected_block->size_flags & 0xfffffffc) < size_flags_or_adjusted_request) goto invariant_failure;
  split_or_previous_link = selected_block->previous_free;
  next_free_link = (TlsfBlock *)selected_block->next_free;
  if ((split_or_previous_link == (TlsfBlock *)0x0) || (next_free_link == (TlsfBlock *)0x0))
  goto invariant_failure;
  next_free_link->previous_free = split_or_previous_link;
  split_or_previous_link->next_free = (TlsfBlock *)next_free_link;
  if ((selected_block == free_lists[(control->configuration >> 0xe & 0x3f) * first_class_or_minimum_gap + second_class_or_alignment_value]) &&
     ((free_lists[(control->configuration >> 0xe & 0x3f) * first_class_or_minimum_gap + second_class_or_alignment_value] =
            (TlsfBlock *)next_free_link, next_free_link == &control->null_block &&
      (size_flags_or_adjusted_request = second_bitmaps[first_class_or_minimum_gap], size_flags_or_adjusted_request = 1U << (second_class_or_alignment_value & 0x1f) & size_flags_or_adjusted_request ^ size_flags_or_adjusted_request,
      second_bitmaps[first_class_or_minimum_gap] = size_flags_or_adjusted_request, size_flags_or_adjusted_request == 0)))) {
    control->first_level_bitmap =
         1U << (first_class_or_minimum_gap & 0x1f) & control->first_level_bitmap ^
         control->first_level_bitmap;
  }
  /* Leading-gap planning: return payload + align_up(data_offset,4) aligned. */
  payload_or_free_lists = &selected_block->next_free;
  size_flags_or_adjusted_request = alignment - 1;
  aligned_target = (unsigned char *)((int)payload_or_free_lists + size_flags_or_adjusted_request & -alignment);
  if ((alignment & size_flags_or_adjusted_request) != 0) goto invariant_failure;
  second_class_or_alignment_value = data_offset + 3 & 0xfffffffc;
  first_class_or_minimum_gap = second_class_or_alignment_value + 0x10;
  config_size_or_gap = (int)aligned_target - (int)payload_or_free_lists;
  if ((payload_or_free_lists == (TlsfBlock **)aligned_target) || (first_class_or_minimum_gap <= config_size_or_gap)) {
    if (config_size_or_gap != 0) goto split_leading_gap;
    if (second_class_or_alignment_value == 0) goto check_leading_gap;
    if (4 < alignment) goto expand_leading_gap;
keep_selected_block:
    size_flags_or_adjusted_request = selected_block->size_flags;
  }
  else {
expand_leading_gap:
    config_size_or_gap = first_class_or_minimum_gap - config_size_or_gap;
    config_size_or_gap = ((uint)(aligned_target +
                    (config_size_or_gap < alignment) * alignment + (config_size_or_gap >= alignment) * config_size_or_gap + size_flags_or_adjusted_request) &
             -alignment) - (int)payload_or_free_lists;
check_leading_gap:
    if (config_size_or_gap == 0) goto keep_selected_block;
split_leading_gap:
    if (config_size_or_gap < first_class_or_minimum_gap) goto invariant_failure;
    size_flags_or_adjusted_request = selected_block->size_flags;
    span_or_most_significant_bit = config_size_or_gap - second_class_or_alignment_value;
    if (span_or_most_significant_bit + 0x10U <= (size_flags_or_adjusted_request & 0xfffffffc)) {
      split_or_previous_link = (TlsfBlock *)((int)selected_block + span_or_most_significant_bit);
      config_size_or_gap = ((size_flags_or_adjusted_request & 0xfffffffc) + second_class_or_alignment_value) - config_size_or_gap;
      if ((&split_or_previous_link->next_free !=
           (TlsfBlock **)((uint)((int)&split_or_previous_link->next_free + 3) & 0xfffffffc)) ||
         (split_or_previous_link->size_flags = split_or_previous_link->size_flags & 3 | config_size_or_gap, (config_size_or_gap & 0xfffffffc) < 0xc))
      goto invariant_failure;
      selected_block->size_flags = selected_block->size_flags & 3 | span_or_most_significant_bit - 4U;
      successor_size_word = (uint *)((split_or_previous_link->size_flags & 0xfffffffc) + (int)&split_or_previous_link->next_free);
      if (split_or_previous_link->size_flags < 4) goto invariant_failure;
      *successor_size_word = *successor_size_word | 2;
      size_flags_or_adjusted_request = split_or_previous_link->size_flags;
      successor_size_word[-1] = (uint)split_or_previous_link;
      split_or_previous_link->size_flags = size_flags_or_adjusted_request | 3;
      size_flags_or_adjusted_request = selected_block->size_flags & 0xfffffffc;
      if (selected_block->size_flags < 4) goto invariant_failure;
      *(TlsfBlock **)((int)payload_or_free_lists + (size_flags_or_adjusted_request - 4)) = selected_block;
      config_size_or_gap = control->configuration;
      /* Map the leading free block for reinsertion after alignment splitting. */
      second_class_or_alignment_value = config_size_or_gap >> 0x17 & 0xff;
      first_class_or_minimum_gap = config_size_or_gap >> 0xe & 0x3f;
      if (size_flags_or_adjusted_request < second_class_or_alignment_value) {
        size_flags_or_adjusted_request = (int)size_flags_or_adjusted_request / (int)(second_class_or_alignment_value / first_class_or_minimum_gap);
        second_class_or_alignment_value = 0;
        config_size_or_gap = size_flags_or_adjusted_request;
      }
      else {
        second_class_or_alignment_value = -(config_size_or_gap >> 5 & 7) - (xtensa_count_leading_zeros(size_flags_or_adjusted_request) + -0x20);
        size_flags_or_adjusted_request = size_flags_or_adjusted_request >> (-(config_size_or_gap >> 0x14 & 7) - (xtensa_count_leading_zeros(size_flags_or_adjusted_request) + -0x1f) & 0x1f) ^
                1U << (config_size_or_gap >> 0x14 & 7);
        config_size_or_gap = second_class_or_alignment_value * first_class_or_minimum_gap + size_flags_or_adjusted_request;
      }
      previous_head = free_lists[config_size_or_gap];
      if (previous_head == (TlsfBlock *)0x0) goto invariant_failure;
      selected_block->next_free = previous_head;
      selected_block->previous_free = &control->null_block;
      previous_head->previous_free = selected_block;
      if (payload_or_free_lists != (TlsfBlock **)((uint)((int)&selected_block->next_free + 3) & 0xfffffffc))
      goto invariant_failure;
      config_size_or_gap = control->first_level_bitmap;
      free_lists[(control->configuration >> 0xe & 0x3f) * second_class_or_alignment_value + size_flags_or_adjusted_request] = selected_block;
      control->first_level_bitmap = config_size_or_gap | 1U << (second_class_or_alignment_value & 0x1f);
      second_bitmaps[second_class_or_alignment_value] = second_bitmaps[second_class_or_alignment_value] | 1U << (size_flags_or_adjusted_request & 0x1f);
      size_flags_or_adjusted_request = split_or_previous_link->size_flags;
      selected_block = split_or_previous_link;
    }
  }
  if ((size_flags_or_adjusted_request & 1) == 0) goto invariant_failure;
  config_size_or_gap = size_flags_or_adjusted_request & 0xfffffffc;
  payload_or_free_lists = &selected_block->next_free;
  /* block_prepare_used: optionally split/reinsert a tail, then clear free flags. */
  if (minimum_payload_size + 0x10 <= config_size_or_gap) {
    split_or_previous_link = (TlsfBlock *)((minimum_payload_size - 4) + (int)payload_or_free_lists);
    size_flags_or_adjusted_request = config_size_or_gap - (minimum_payload_size + 4);
    if (((&split_or_previous_link->next_free !=
          (TlsfBlock **)((uint)((int)&split_or_previous_link->next_free + 3) & 0xfffffffc)) ||
        (config_size_or_gap != minimum_payload_size + 4 + size_flags_or_adjusted_request)) ||
       (split_or_previous_link->size_flags = split_or_previous_link->size_flags & 3 | size_flags_or_adjusted_request, size_flags_or_adjusted_request < 0xc)) goto invariant_failure;
    selected_block->size_flags = selected_block->size_flags & 3 | minimum_payload_size;
    successor_size_word = (uint *)((split_or_previous_link->size_flags & 0xfffffffc) + (int)&split_or_previous_link->next_free);
    if (split_or_previous_link->size_flags < 4) goto invariant_failure;
    *successor_size_word = *successor_size_word | 2;
    size_flags_or_adjusted_request = split_or_previous_link->size_flags;
    successor_size_word[-1] = (uint)split_or_previous_link;
    split_or_previous_link->size_flags = size_flags_or_adjusted_request | 1;
    if (selected_block->size_flags < 4) goto invariant_failure;
    *(TlsfBlock **)((int)payload_or_free_lists + ((selected_block->size_flags & 0xfffffffc) - 4)) = selected_block;
    split_or_previous_link->size_flags = size_flags_or_adjusted_request | 3;
    minimum_payload_size = control->configuration;
    size_flags_or_adjusted_request = size_flags_or_adjusted_request & 0xfffffffc;
    config_size_or_gap = minimum_payload_size >> 0x17 & 0xff;
    second_class_or_alignment_value = minimum_payload_size >> 0xe & 0x3f;
    if (size_flags_or_adjusted_request < config_size_or_gap) {
      size_flags_or_adjusted_request = (int)size_flags_or_adjusted_request / (int)(config_size_or_gap / second_class_or_alignment_value);
      first_class_or_minimum_gap = 0;
      config_size_or_gap = size_flags_or_adjusted_request;
    }
    else {
      if (size_flags_or_adjusted_request == 0) {
        most_significant_bit = -1;
        span_or_most_significant_bit = 0;
      }
      else {
        span_or_most_significant_bit = -(xtensa_count_leading_zeros(size_flags_or_adjusted_request) + -0x20);
        most_significant_bit = -(xtensa_count_leading_zeros(size_flags_or_adjusted_request) + -0x1f);
      }
      first_class_or_minimum_gap = span_or_most_significant_bit - (minimum_payload_size >> 5 & 7);
      size_flags_or_adjusted_request = size_flags_or_adjusted_request >> (most_significant_bit - (minimum_payload_size >> 0x14 & 7) & 0x1f) ^
              1U << (minimum_payload_size >> 0x14 & 7);
      config_size_or_gap = first_class_or_minimum_gap * second_class_or_alignment_value + size_flags_or_adjusted_request;
    }
    previous_head = free_lists[config_size_or_gap];
    if (previous_head == (TlsfBlock *)0x0) goto invariant_failure;
    split_or_previous_link->next_free = previous_head;
    split_or_previous_link->previous_free = &control->null_block;
    previous_head->previous_free = split_or_previous_link;
    config_size_or_gap = control->first_level_bitmap;
    free_lists[(control->configuration >> 0xe & 0x3f) * first_class_or_minimum_gap + size_flags_or_adjusted_request] = split_or_previous_link;
    control->first_level_bitmap = config_size_or_gap | 1U << (first_class_or_minimum_gap & 0x1f);
    second_bitmaps[first_class_or_minimum_gap] = second_bitmaps[first_class_or_minimum_gap] | 1U << (size_flags_or_adjusted_request & 0x1f);
    size_flags_or_adjusted_request = selected_block->size_flags;
    config_size_or_gap = size_flags_or_adjusted_request & 0xfffffffc;
  }
  if (3 < size_flags_or_adjusted_request) {
    *(uint *)((int)&selected_block->next_free + config_size_or_gap) =
         *(uint *)((int)&selected_block->next_free + config_size_or_gap) & 0xfffffffd;
    selected_block->size_flags = selected_block->size_flags & 0xfffffffe;
    return payload_or_free_lists;
  }
invariant_failure:
                    /* WARNING: Subroutine does not return */
  __assert_func((char *)0x0,0,(char *)0x0,(char *)0x0);
}

/* Native entry: 0x40386b2c. */
/*
 * Medius v3.4.7 — host application; 0x40386b2c.
 *
 * Treats NULL as malloc and non-NULL plus zero size as free. Otherwise validates used status and
 * request adjustment; grows into the next free neighbor when sufficient, or allocates/copies
 * min(old_capacity, requested_size)/frees on successful movement. Failure preserves the old
 * allocation. Shrinking or successful in-place growth trims/reinserts trailing space and returns
 * the same payload. Both optional block_absorb_post_hook sites resolve to fixed address 0 and are
 * skipped; no heap lock, zero fill or multi-heap accounting is provided here. Request round-up
 * uses native 32-bit wrapping; this internal API has no independent size+3 overflow check.
 *
 * Calls: tlsf_free, tlsf_malloc, __assert_func, memcpy.
 *
 * Called by: multi_heap_realloc.
 *
 * Optional coalescing-hook call sites: 2; linked address 0, skipped in this image.
 *
 * Original function-byte SHA-256:
 * 0b0ea005b47b8df6e32163a847f75bd366b68588415833ba013b4adfc414098d.
 */

/* Reference: TLSF 2867f6883a12920b1969ff9624c0ab0e4185c2ce tlsf.c and tlsf_control_functions.h.
   The bit-count helper emits native NSAU (unsigned 32-bit leading zeros, including 32 for zero). The compiler reuses some address temporaries;
   &block->next_free denotes payload at block+8. */

/*
 * control: Owning initialized TLSF control; NULL only has the compiled rejection behavior on non-
 *   free allocation paths.
 * payload: Live used allocation or NULL to allocate.
 * size: New requested bytes;0 frees a non-NULL payload and returns NULL.
 * Returns: Same payload after in-place resize, moved allocation on successful replacement, or
 *   NULL. Nonzero-size allocation failure preserves the old block.
 * Requirements/effects: Checks request size and used status. Grows by absorbing a sufficient free
 *   successor, otherwise malloc/copy(min(old capacity,requested size))/free. Shrinks or trims
 *   successful growth by splitting a tail, optionally merging it with a free successor, then
 *   reinserting. Requires caller synchronization and intact metadata; no zero-fill or multi-heap
 *   accounting. Request+3 uses native32-bit wrapping.
 */

void * tlsf_realloc(TlsfControl *control,void *payload,uint size)

{
  void *replacement;
  TlsfBlock *neighbor_or_remainder;
  uint capacity_or_size_class;
  TlsfBlock *next_free_link;
  uint size_flags_or_bitmap;
  uint *successor_size_or_second_bitmaps;
  int bit_length_or_most_significant_bit;
  TlsfBlock *previous_free_link;
  uint request_size_or_class_index;
  int most_significant_bit_or_bit_length;
  uint successor_capacity;
  int *successor_header_words;
  uint configuration_or_first_class;
  TlsfBlock **remainder_payload_or_free_lists;

  /* API edge cases: NULL allocates; non-NULL plus zero frees. */
  if (payload == (void *)0x0) {
allocate_new_block:
    replacement = tlsf_malloc(control,size);
    return replacement;
  }
  if (size == 0) {
    tlsf_free(control,payload);
    return (void *)0x0;
  }
  if (payload == (void *)0x0) goto allocate_new_block;
  size_flags_or_bitmap = *(uint *)((int)payload + -4);
  if (size_flags_or_bitmap < 4) goto invariant_failure;
  if (size == 0) {
    return (void *)0x0;
  }
  request_size_or_class_index = size + 3 & 0xfffffffc;
  if (control == (TlsfControl *)0x0) {
    return (void *)0x0;
  }
  configuration_or_first_class = control->configuration;
  if ((uint)(1U << (configuration_or_first_class >> 8 & 0x1f)) <= request_size_or_class_index) {
    return (void *)0x0;
  }
  request_size_or_class_index = (uint)(request_size_or_class_index < 0xc) * 0xc + (request_size_or_class_index >= 0xc) * request_size_or_class_index;
  if ((size_flags_or_bitmap & 1) != 0) goto invariant_failure;
  capacity_or_size_class = size_flags_or_bitmap & 0xfffffffc;
  /* Growth: absorb a sufficient free successor, otherwise allocate/copy/free. */
  if (capacity_or_size_class < request_size_or_class_index) {
    neighbor_or_remainder = (TlsfBlock *)((int)payload + (capacity_or_size_class - 4));
    successor_capacity = neighbor_or_remainder->size_flags & 0xfffffffc;
    if ((capacity_or_size_class + 4 + successor_capacity < request_size_or_class_index) || ((neighbor_or_remainder->size_flags & 1) == 0)) {
      replacement = tlsf_malloc(control,size);
      if (replacement == (void *)0x0) {
        return (void *)0x0;
      }
      memcpy(replacement,payload,(size < capacity_or_size_class) * size + (size >= capacity_or_size_class) * capacity_or_size_class);
      tlsf_free(control,payload);
      return replacement;
    }
    capacity_or_size_class = configuration_or_first_class >> 0x17 & 0xff;
    if (successor_capacity < capacity_or_size_class) {
      capacity_or_size_class = (int)successor_capacity / (int)(capacity_or_size_class / (configuration_or_first_class >> 0xe & 0x3f));
      configuration_or_first_class = 0;
    }
    else {
      if (successor_capacity == 0) {
        most_significant_bit_or_bit_length = -1;
        bit_length_or_most_significant_bit = 0;
      }
      else {
        bit_length_or_most_significant_bit = -(xtensa_count_leading_zeros(successor_capacity) + -0x20);
        most_significant_bit_or_bit_length = -(xtensa_count_leading_zeros(successor_capacity) + -0x1f);
      }
      capacity_or_size_class = successor_capacity >> (most_significant_bit_or_bit_length - (configuration_or_first_class >> 0x14 & 7) & 0x1f) ^
              1U << (configuration_or_first_class >> 0x14 & 7);
      configuration_or_first_class = bit_length_or_most_significant_bit - (configuration_or_first_class >> 5 & 7);
    }
    previous_free_link = neighbor_or_remainder->previous_free;
    next_free_link = (TlsfBlock *)neighbor_or_remainder->next_free;
    if ((previous_free_link == (TlsfBlock *)0x0) || (next_free_link == (TlsfBlock *)0x0))
    goto invariant_failure;
    next_free_link->previous_free = previous_free_link;
    previous_free_link->next_free = (TlsfBlock *)next_free_link;
    if ((neighbor_or_remainder == control->free_lists[(control->configuration >> 0xe & 0x3f) * configuration_or_first_class + capacity_or_size_class]) &&
       (control->free_lists[(control->configuration >> 0xe & 0x3f) * configuration_or_first_class + capacity_or_size_class] =
             (TlsfBlock *)next_free_link, next_free_link == &control->null_block)) {
      size_flags_or_bitmap = control->second_level_bitmaps[configuration_or_first_class];
      size_flags_or_bitmap = 1U << (capacity_or_size_class & 0x1f) & size_flags_or_bitmap ^ size_flags_or_bitmap;
      control->second_level_bitmaps[configuration_or_first_class] = size_flags_or_bitmap;
      if (size_flags_or_bitmap == 0) {
        control->first_level_bitmap =
             1U << (configuration_or_first_class & 0x1f) & control->first_level_bitmap ^
             control->first_level_bitmap;
      }
      size_flags_or_bitmap = *(uint *)((int)payload + -4);
      if (size_flags_or_bitmap < 4) goto invariant_failure;
      successor_capacity = neighbor_or_remainder->size_flags & 0xfffffffc;
    }
    size_flags_or_bitmap = size_flags_or_bitmap + successor_capacity + 4;
    *(uint *)((int)payload + -4) = size_flags_or_bitmap;
    successor_header_words = (int *)((int)payload + ((size_flags_or_bitmap & 0xfffffffc) - 4));
    if (size_flags_or_bitmap < 4) goto invariant_failure;
    *successor_header_words = (int)payload + -8;
    successor_header_words[1] = successor_header_words[1] & 0xfffffffd;
    capacity_or_size_class = *(uint *)((int)payload + -4);
    *(uint *)((int)payload + -4) = capacity_or_size_class & 0xfffffffe;
    capacity_or_size_class = capacity_or_size_class & 0xfffffffc;
  }
  /* block_trim_used: keep a short tail, or split and merge/reinsert a free remainder. */
  if (capacity_or_size_class < request_size_or_class_index + 0x10) {
    return payload;
  }
  neighbor_or_remainder = (TlsfBlock *)((int)payload + (request_size_or_class_index - 4));
  remainder_payload_or_free_lists = &neighbor_or_remainder->next_free;
  size_flags_or_bitmap = capacity_or_size_class - (request_size_or_class_index + 4);
  if (((remainder_payload_or_free_lists != (TlsfBlock **)((uint)((int)&neighbor_or_remainder->next_free + 3) & 0xfffffffc)) ||
      (request_size_or_class_index + 4 + size_flags_or_bitmap != capacity_or_size_class)) ||
     (neighbor_or_remainder->size_flags = neighbor_or_remainder->size_flags & 3 | size_flags_or_bitmap, size_flags_or_bitmap < 0xc)) goto invariant_failure;
  *(uint *)((int)payload + -4) = *(uint *)((int)payload + -4) & 3 | request_size_or_class_index;
  successor_size_or_second_bitmaps = (uint *)((neighbor_or_remainder->size_flags & 0xfffffffc) + (int)remainder_payload_or_free_lists);
  if (neighbor_or_remainder->size_flags < 4) goto invariant_failure;
  *successor_size_or_second_bitmaps = *successor_size_or_second_bitmaps | 2;
  request_size_or_class_index = neighbor_or_remainder->size_flags;
  successor_size_or_second_bitmaps[-1] = (uint)neighbor_or_remainder;
  size_flags_or_bitmap = request_size_or_class_index & 0xfffffffd | 1;
  request_size_or_class_index = request_size_or_class_index & 0xfffffffc;
  successor_size_or_second_bitmaps = (uint *)((int)remainder_payload_or_free_lists + request_size_or_class_index);
  neighbor_or_remainder->size_flags = size_flags_or_bitmap;
  /* This pointer addresses the successor size word (+4); address4 means a NULL header. */
  if ((size_flags_or_bitmap < 4) || (successor_size_or_second_bitmaps == (uint *)4U)) goto invariant_failure;
  if ((*successor_size_or_second_bitmaps & 1) == 0) {
    configuration_or_first_class = control->configuration;
    remainder_payload_or_free_lists = control->free_lists;
    size_flags_or_bitmap = configuration_or_first_class >> 0x17 & 0xff;
    if (request_size_or_class_index < size_flags_or_bitmap) goto map_small_remainder;
    most_significant_bit_or_bit_length = -1;
    bit_length_or_most_significant_bit = 0;
    if (request_size_or_class_index != 0) {
map_large_remainder:
      bit_length_or_most_significant_bit = -(xtensa_count_leading_zeros(request_size_or_class_index) + -0x20);
      most_significant_bit_or_bit_length = -(xtensa_count_leading_zeros(request_size_or_class_index) + -0x1f);
    }
    capacity_or_size_class = bit_length_or_most_significant_bit - (configuration_or_first_class >> 5 & 7);
    size_flags_or_bitmap = request_size_or_class_index >> (most_significant_bit_or_bit_length - (configuration_or_first_class >> 0x14 & 7) & 0x1f) ^
            1U << (configuration_or_first_class >> 0x14 & 7);
    request_size_or_class_index = (configuration_or_first_class >> 0xe & 0x3f) * capacity_or_size_class + size_flags_or_bitmap;
  }
  else {
    configuration_or_first_class = control->configuration;
    capacity_or_size_class = *successor_size_or_second_bitmaps & 0xfffffffc;
    request_size_or_class_index = configuration_or_first_class >> 0x17 & 0xff;
    /* Map the free successor before merging it with the remainder. */
    if (capacity_or_size_class < request_size_or_class_index) {
      request_size_or_class_index = (int)capacity_or_size_class / (int)(request_size_or_class_index / (configuration_or_first_class >> 0xe & 0x3f));
      configuration_or_first_class = 0;
    }
    else {
      if (capacity_or_size_class == 0) {
        bit_length_or_most_significant_bit = -1;
        most_significant_bit_or_bit_length = 0;
      }
      else {
        most_significant_bit_or_bit_length = -(xtensa_count_leading_zeros(capacity_or_size_class) + -0x20);
        bit_length_or_most_significant_bit = -(xtensa_count_leading_zeros(capacity_or_size_class) + -0x1f);
      }
      request_size_or_class_index = capacity_or_size_class >> (bit_length_or_most_significant_bit - (configuration_or_first_class >> 0x14 & 7) & 0x1f) ^
              1U << (configuration_or_first_class >> 0x14 & 7);
      configuration_or_first_class = most_significant_bit_or_bit_length - (configuration_or_first_class >> 5 & 7);
    }
    previous_free_link = (TlsfBlock *)successor_size_or_second_bitmaps[2];
    next_free_link = (TlsfBlock *)successor_size_or_second_bitmaps[1];
    if ((previous_free_link == (TlsfBlock *)0x0) || (next_free_link == (TlsfBlock *)0x0))
    goto invariant_failure;
    next_free_link->previous_free = previous_free_link;
    previous_free_link->next_free = (TlsfBlock *)next_free_link;
    remainder_payload_or_free_lists = control->free_lists;
    if (((TlsfBlock *)(successor_size_or_second_bitmaps + -1) ==
         remainder_payload_or_free_lists[(control->configuration >> 0xe & 0x3f) * configuration_or_first_class + request_size_or_class_index]) &&
       (remainder_payload_or_free_lists[(control->configuration >> 0xe & 0x3f) * configuration_or_first_class + request_size_or_class_index] =
             (TlsfBlock *)next_free_link, next_free_link == &control->null_block)) {
      size_flags_or_bitmap = control->second_level_bitmaps[configuration_or_first_class];
      size_flags_or_bitmap = 1U << (request_size_or_class_index & 0x1f) & size_flags_or_bitmap ^ size_flags_or_bitmap;
      control->second_level_bitmaps[configuration_or_first_class] = size_flags_or_bitmap;
      if (size_flags_or_bitmap == 0) {
        control->first_level_bitmap =
             1U << (configuration_or_first_class & 0x1f) & control->first_level_bitmap ^
             control->first_level_bitmap;
      }
      size_flags_or_bitmap = neighbor_or_remainder->size_flags;
      if (size_flags_or_bitmap < 4) goto invariant_failure;
      capacity_or_size_class = *successor_size_or_second_bitmaps & 0xfffffffc;
    }
    size_flags_or_bitmap = size_flags_or_bitmap + capacity_or_size_class + 4;
    request_size_or_class_index = size_flags_or_bitmap & 0xfffffffc;
    neighbor_or_remainder->size_flags = size_flags_or_bitmap;
    if (size_flags_or_bitmap < 4) goto invariant_failure;
    *(TlsfBlock **)((int)&neighbor_or_remainder->size_flags + request_size_or_class_index) = neighbor_or_remainder;
    configuration_or_first_class = control->configuration;
    size_flags_or_bitmap = configuration_or_first_class >> 0x17 & 0xff;
    if (size_flags_or_bitmap <= request_size_or_class_index) goto map_large_remainder;
map_small_remainder:
    request_size_or_class_index = (int)request_size_or_class_index / (int)(size_flags_or_bitmap / (configuration_or_first_class >> 0xe & 0x3f));
    capacity_or_size_class = 0;
    size_flags_or_bitmap = request_size_or_class_index;
  }
  previous_free_link = remainder_payload_or_free_lists[request_size_or_class_index];
  if (previous_free_link != (TlsfBlock *)0x0) {
    neighbor_or_remainder->next_free = previous_free_link;
    neighbor_or_remainder->previous_free = &control->null_block;
    previous_free_link->previous_free = neighbor_or_remainder;
    request_size_or_class_index = control->first_level_bitmap;
    successor_size_or_second_bitmaps = control->second_level_bitmaps;
    remainder_payload_or_free_lists[(control->configuration >> 0xe & 0x3f) * capacity_or_size_class + size_flags_or_bitmap] = neighbor_or_remainder;
    control->first_level_bitmap = request_size_or_class_index | 1U << (capacity_or_size_class & 0x1f);
    successor_size_or_second_bitmaps[capacity_or_size_class] = successor_size_or_second_bitmaps[capacity_or_size_class] | 1U << (size_flags_or_bitmap & 0x1f);
    return payload;
  }
invariant_failure:
                    /* WARNING: Subroutine does not return */
  __assert_func((char *)0x0,0,(char *)0x0,(char *)0x0);
}

/* Native entry: 0x40386ed0. */
/*
 * Medius v3.4.7 — host application; 0x40386ed0.
 *
 * Returns zero for NULL control, otherwise the metadata_size word at offset 20. The value
 * includes fixed control, second-level bitmaps and free-list heads; it is not the total pool
 * capacity or current usage.
 *
 * Called by: multi_heap_register, multi_heap_get_info.
 *
 * Original function-byte SHA-256:
 * 9b31e209aedbc40f9974e01397ad9631dc00a58af91e1b786748f1767d645ee4.
 */

/* Reference: TLSF 2867f6883a12920b1969ff9624c0ab0e4185c2ce tlsf.c. */

/*
 * control: Readable TLSF control; may be NULL.
 * Returns: 0 for NULL; otherwise metadata_size at byte20.
 * Requirements/effects: Reports allocator metadata bytes, not total region capacity or current
 *   used bytes. Does not validate the stored value.
 */

uint tlsf_size(TlsfControl *control)

{
  uint metadata_size;

  metadata_size = 0;
  if (control != (TlsfControl *)0x0) {
    metadata_size = control->metadata_size;
  }
  return metadata_size;
}

/* Native entry: 0x42023fc4. */
/*
 * Medius v3.4.7 — host application; 0x42023fc4.
 *
 * Default TLSF walker prints payload address, used/free label, hexadecimal size and header
 * address payload-8, then returns true. The user argument is unused. Behavioral prefix
 * distinguishes the SDK static default_walker symbol; the printer calls the reviewed Newlib printf.
 *
 * Calls: newlib_printf.
 *
 * Original function-byte SHA-256:
 * d546347b5c15cfe7a09d2492e91161df9ea36ebd87b54c2ede1e5ae1ba4c3063.
 */

/* Reference: TLSF 2867f6883a12920b1969ff9624c0ab0e4185c2ce tlsf.c default_walker. */

/*
 * payload: Payload address displayed by the diagnostic printer; header is displayed as payload-8.
 * size: Payload capacity printed as hexadecimal.
 * used: 0 prints free, nonzero prints used.
 * unused_user: Unused callback context; not dereferenced.
 * Returns: true to continue the walk.
 * Requirements/effects: Prints through the linked printf-family dependency. Does not inspect
 *   payload bytes, lock the pool or reserve storage.
 */

bool tlsf_default_walker(void *payload,uint size,int used,void *unused_user)

{
  const char *allocation_state;

  allocation_state = "free";
  if (used != 0) {
    allocation_state = "used";
  }
  newlib_printf("\t%p %s size: %x (%p)\n",payload,allocation_state,size,(void *)((unsigned char *)payload - 8));
  return true;
}

/* Native entry: 0x42023fe4. */
/*
 * Medius v3.4.7 — host application; 0x42023fe4.
 *
 * Starts the block-header view four bytes before pool, chooses the supplied callback or default
 * printer, and visits non-sentinel blocks in physical order. Passes payload at header+8, size
 * without the two flag bits, inverted free bit as used, and user. Stops when the callback returns
 * false. On continuation reloads the size word before advancing and asserting that the old block
 * was not a sentinel. No lock, pool bounds or NULL-pool validation is supplied. Callbacks must
 * preserve block metadata unless the caller can guarantee the resulting traversal is valid.
 *
 * Calls: __assert_func.
 *
 * Called by: multi_heap_get_info.
 *
 * Indirect call: typed TLSF walker; statistics callback or fallback printer on this call chain.
 *
 * Original function-byte SHA-256:
 * 8dac8e39e3c99ef9797217feddcd428c8c6c1b2e95f37aa1385f0a7d268bd28e.
 */

/* Reference: TLSF 2867f6883a12920b1969ff9624c0ab0e4185c2ce tlsf.c and tlsf_block_functions.h.
   Body rendered from the original instructions with explicit recovered structure/ABI semantics. */

/*
 * pool: Pool address returned by TLSF; its first block-header view begins4 bytes earlier. NULL is
 *   not independently rejected.
 * walker: Callback receiving payload,size,used,user; NULL selects the diagnostic default walker.
 * user: Opaque value forwarded unchanged to each callback.
 * Returns: Nothing; stops at a zero-size sentinel, NULL block or false callback result.
 * Requirements/effects: Requires valid physical block metadata and caller synchronization. Reloads
 *   size after each callback; callbacks must preserve metadata or ensure that the resulting
 *   traversal remains valid.
 */

void tlsf_walk_pool(void *pool,TlsfWalker walker,void *user)
{
  TlsfBlock *block = (TlsfBlock *)((uint)pool - 4U);
  TlsfWalker visit = walker != (TlsfWalker)0 ? walker : tlsf_default_walker;
  while (block != (TlsfBlock *)0) {
    uint size_flags = block->size_flags;
    if (size_flags < 4U) {
      return;
    }
    void *payload = (void *)((uint)block + 8U);
    if (!visit(payload,size_flags & ~3U,(int)((~size_flags) & 1U),user)) {
      return;
    }
    /* The native code reloads this word after the callback. */
    size_flags = block->size_flags;
    block = (TlsfBlock *)((uint)payload + (size_flags & ~3U) - 4U);
    if (size_flags < 4U) {
      __assert_func((const char *)0,0,(const char *)0,(const char *)0);
    }
  }
}

/* Native entry: 0x42024034. */
/*
 * Medius v3.4.7 — host application; 0x42024034.
 *
 * Returns zero for NULL control or zero size. Below the packed small-block threshold, rounds to
 * four bytes, rejects values at or beyond the compiled maximum-block bound and enforces a 12-byte
 * minimum. Otherwise masks the size down to a second-level GoodFit interval. The native large-
 * size path uses signed QUOS; the rendering preserves it rather than substituting unsigned
 * division. Requires a valid initialized control with nonzero subdivision count; no configuration
 * validation or heap reservation occurs.
 *
 * Called by: multi_heap_get_info.
 *
 * Original function-byte SHA-256:
 * 182a11eee32ef2c5bc585b3fb52437f1c01f9cd04487a4cabc0e09f5844e2887.
 */

/* Reference: TLSF 2867f6883a12920b1969ff9624c0ab0e4185c2ce tlsf.c tlsf_fit_size and
   tlsf_control_functions.h. Body rendered from the original instructions with explicit recovered
   structure/ABI semantics. */

/*
 * control: Initialized TLSF control with a valid nonzero subdivision count; NULL returns0.
 * size: Requested candidate payload size in bytes;0 returns0.
 * Returns: Allocable size-class boundary, or0 on the documented NULL/zero/maximum rejection paths.
 * Requirements/effects: Small requests align to4 with minimum12. Large mapping preserves native
 *   signed QUOS and uint32 negation; this computes a fit without reserving a block or validating
 *   configuration.
 */

uint tlsf_fit_size(TlsfControl *control,uint size)
{
  if (size == 0U || control == (TlsfControl *)0) {
    return 0U;
  }
  uint configuration = control->configuration;
  uint small_block_size = (configuration >> 23) & 0xffU;
  if (size < small_block_size) {
    uint aligned_size = (size + 3U) & ~3U;
    /* SSL uses the low five bits of the extracted six-bit FL maximum. */
    uint maximum_shift = ((configuration >> 8) & 0x3fU) & 31U;
    uint maximum_block_size = 1U << maximum_shift;
    if (aligned_size >= maximum_block_size) {
      return 0U;
    }
    return aligned_size < 12U ? 12U : aligned_size;
  }
  uint second_level_count = (configuration >> 14) & 0x3fU;
  uint highest_size_bit = 0x80000000U >> __builtin_clz(size);
  /* QUOS is signed in the original binary; valid controls have nonzero count.
   * Unsigned negation preserves native wrap even for a signed INT_MIN quotient. */
  int signed_interval = (int)highest_size_bit / (int)second_level_count;
  return size & (0U - (uint)signed_interval);
}

/* Native entry: 0x4202408c. */
/*
 * Medius v3.4.7 — host application; 0x4202408c.
 *
 * Forms pool_bytes=(bytes-8)&~3. Rejects unaligned memory or payload outside 12..the compiled FL
 * maximum, printing the respective error; NULL control takes the size-error path. Requires a
 * valid writable pool/control and initialized non-NULL free-list heads. Creates the initial free
 * block at memory-4, maps its size to FL/SL indices, links it at the selected head, updates both
 * bitmaps and writes a zero-size used sentinel with previous-free flag 2. Returns memory on
 * success or NULL on admission failure. It supplies no lock, overlap detection or
 * configuration/index validation.
 *
 * Calls: __assert_func, newlib_printf.
 *
 * Called by: tlsf_create_with_pool.
 *
 * Original function-byte SHA-256:
 * eb43262cd1352d3fe430873356ff4c48074948625ca7ca387542abf4a8499bcd.
 */

/* Reference: TLSF 2867f6883a12920b1969ff9624c0ab0e4185c2ce tlsf.c and tlsf_control_functions.h.
   Typed rendering follows original native field stores, list/bitmap operations and assertion
   order. */

/*
 * control: Initialized writable TLSF control with valid bitmap/head tables; NULL fails size
 *   admission.
 * memory: Word-aligned writable pool memory; block view is memory-4 and the first written size
 *   word is at memory.
 * bytes: Pool-region extent; computes (bytes-8)&~3 using uint32 arithmetic.
 * Returns: memory on success, NULL on alignment/size rejection; invariant violations assert.
 * Requirements/effects: Requires initialized non-NULL list heads and consistent control
 *   configuration. Creates free block/sentinel and updates both bitmap levels; no overlap
 *   detection, lock or separate subtraction-underflow check.
 */

void *tlsf_add_pool(TlsfControl *control,void *memory,uint bytes)
{
  uint pool_bytes = (bytes - 8U) & ~3U;
  if (((uint)memory & 3U) != 0U) {
    newlib_printf("tlsf_add_pool: Memory must be aligned by %u bytes.\n",4U);
    return (void *)0;
  }
  uint maximum_block_size = control != (TlsfControl *)0 ?
      1U << ((control->configuration >> 8) & 31U) : 0U;
  if (control == (TlsfControl *)0 || pool_bytes < 12U || pool_bytes > maximum_block_size) {
    newlib_printf("tlsf_add_pool: Memory size must be between %u and %u bytes.\n",
                    20U,maximum_block_size + 8U);
    return (void *)0;
  }
  TlsfBlock *block = (TlsfBlock *)((uint)memory - 4U);
  block->size_flags = pool_bytes | 1U; /* free; previous block marked used */
  uint configuration = control->configuration;
  uint small_block_size = (configuration >> 23) & 0xffU;
  uint second_level_count = (configuration >> 14) & 0x3fU;
  uint first_level;
  uint second_level;
  if (pool_bytes < small_block_size) {
    first_level = 0U;
    int subdivision_size = (int)small_block_size / (int)second_level_count;
    second_level = (uint)((int)pool_bytes / subdivision_size);
  } else {
    uint highest_bit = 31U - __builtin_clz(pool_bytes);
    uint second_level_log2 = (configuration >> 20) & 7U;
    first_level = highest_bit + 1U - ((configuration >> 5) & 7U);
    second_level = (pool_bytes >> ((highest_bit - second_level_log2) & 31U)) ^
        (1U << second_level_log2);
  }
  TlsfBlock **heads = control->free_lists;
  TlsfBlock *previous_head = heads[first_level * second_level_count + second_level];
  if (previous_head == (TlsfBlock *)0) {
    __assert_func((const char *)0,0,(const char *)0,(const char *)0);
  }
  block->next_free = previous_head;
  block->previous_free = &control->null_block;
  previous_head->previous_free = block;
  uint payload = (uint)block + 8U;
  if (payload != (((uint)block + 11U) & ~3U)) {
    __assert_func((const char *)0,0,(const char *)0,(const char *)0);
  }
  uint current_columns = (control->configuration >> 14) & 0x3fU;
  uint old_first_bitmap = control->first_level_bitmap;
  uint *second_bitmaps = control->second_level_bitmaps;
  heads[first_level * current_columns + second_level] = block;
  control->first_level_bitmap = old_first_bitmap | (1U << (first_level & 31U));
  second_bitmaps[first_level] |= 1U << (second_level & 31U);
  uint size_flags = block->size_flags;
  TlsfBlock *sentinel = (TlsfBlock *)(payload + (size_flags & ~3U) - 4U);
  if (size_flags < 4U) {
    __assert_func((const char *)0,0,(const char *)0,(const char *)0);
  }
  sentinel->previous_physical = block;
  sentinel->size_flags = 2U; /* zero size, used, previous block free */
  return memory;
}

/* Native entry: 0x420241c4. */
/*
 * Medius v3.4.7 — host application; 0x420241c4.
 *
 * Rejects NULL or unaligned memory (printing the alignment error), and fewer than 36 bytes.
 * Inlined control construction chooses 8/16/32 subdivisions at 16KiB/256KiB thresholds, packs the
 * FL/SL configuration while preserving padding bit 31, and computes metadata space. Configuration
 * and size are written before the metadata-plus 12-byte capacity rejection. On success
 * initializes the null free-list links, bitmap pointers, zero bitmaps and every list head. It
 * leaves unused null-block fields untouched and returns the supplied memory. No external
 * allocation or lock occurs.
 *
 * Calls: __assert_func, newlib_printf.
 *
 * Called by: tlsf_create_with_pool.
 *
 * Original function-byte SHA-256:
 * 6adfbd10fa595156af4fee72136293066e405e81f8d6049a326a23f65be706f3.
 */

/* Reference: TLSF 2867f6883a12920b1969ff9624c0ab0e4185c2ce tlsf.c tlsf_create/control_construct.
   Typed rendering follows original native field stores, list/bitmap operations and assertion
   order. */

/*
 * memory: Word-aligned writable region holding control, bitmaps and list heads; NULL returnsNULL.
 * max_bytes: Region/capacity bound used to choose size classes and check metadata+minimum payload.
 * Returns: Control at memory on success, otherwiseNULL.
 * Requirements/effects: Rejects unaligned or fewer than36 bytes. Writes
 *   configuration/metadata_size before the later capacity failure; preserves padding bit31 and
 *   leaves unused null-block words untouched. No allocation or lock.
 */

TlsfControl *tlsf_create(void *memory,uint max_bytes)
{
  if (memory == (void *)0) {
    return (TlsfControl *)0;
  }
  if (((uint)memory & 3U) != 0U) {
    newlib_printf("tlsf_create: Memory must be aligned to %u bytes.\n",4U);
    return (TlsfControl *)0;
  }
  if (max_bytes < 36U) {
    return (TlsfControl *)0;
  }
  TlsfControl *control = (TlsfControl *)memory;
  uint first_level_max = 32U - __builtin_clz(max_bytes);
  uint second_level_log2 = max_bytes <= 16384U ? 3U : max_bytes <= 262144U ? 4U : 5U;
  uint first_level_shift = second_level_log2 + 2U;
  uint second_level_count = 1U << second_level_log2;
  uint small_block_size = 1U << first_level_shift;
  uint first_level_count = (first_level_max + 1U - first_level_shift) & 0xffU;
  uint metadata_size = 4U * (9U + first_level_count + first_level_count * second_level_count);
  uint padding_bit = control->configuration & 0x80000000U;
  /* These two fields are committed even when the following capacity test fails. */
  control->metadata_size = metadata_size;
  control->configuration = first_level_count | (first_level_shift << 5) |
      (first_level_max << 8) | (second_level_count << 14) |
      (second_level_log2 << 20) | (small_block_size << 23) | padding_bit;
  if (max_bytes < metadata_size + 12U) {
    return (TlsfControl *)0;
  }
  uint *bitmaps = (uint *)(((uint)memory + 39U) & ~3U);
  TlsfBlock **heads = (TlsfBlock **)(((uint)bitmaps + first_level_count * 4U + 3U) & ~3U);
  control->null_block.next_free = &control->null_block;
  control->null_block.previous_free = &control->null_block;
  control->first_level_bitmap = 0U;
  control->second_level_bitmaps = bitmaps;
  control->free_lists = heads;
  if ((int)small_block_size / (int)second_level_count != 4) {
    __assert_func((const char *)0,0,(const char *)0,(const char *)0);
  }
  uint row = 0U;
  if (first_level_count != 0U) {
    do {
      *bitmaps = 0U;
      uint configuration = control->configuration;
      uint column = 0U;
      uint columns = (configuration >> 14) & 0x3fU;
      while (column < columns) {
        heads[(row * columns + column) & 0xffffU] = &control->null_block;
        configuration = control->configuration;
        column += 1U;
        columns = (configuration >> 14) & 0x3fU;
      }
      row += 1U;
      bitmaps += 1;
      if (row >= (configuration & 0x1fU)) {
        break;
      }
    } while (true);
  }
  return control;
}

/* Native entry: 0x420242dc. */
/*
 * Medius v3.4.7 — host application; 0x420242dc.
 *
 * Creates control using max_bytes when nonzero or pool_bytes otherwise. If construction succeeds,
 * calls tlsf_add_pool at memory+metadata_size with pool_bytes-metadata_size. Returns the
 * constructed control and ignores add_pool failure; a non-NULL result alone does not prove pool
 * registration succeeded. Arithmetic is native 32-bit and has no independent subtraction-
 * underflow check.
 *
 * Calls: tlsf_add_pool, tlsf_create.
 *
 * Called by: multi_heap_register.
 *
 * Original function-byte SHA-256:
 * 631e865f23471f778ea3d1f25fefaee9cc043bef47f13b42f0d57f5207589093.
 */

/* Reference: TLSF 2867f6883a12920b1969ff9624c0ab0e4185c2ce tlsf.c. */

/*
 * memory: Writable storage for the control and initial pool.
 * pool_bytes: Total TLSF-region bytes, including metadata.
 * max_bytes: Constructor capacity bound;0 substitutes pool_bytes.
 * Returns: Constructed control, even if subsequent pool addition fails; NULL only when
 *   construction fails.
 * Requirements/effects: Calls add_pool at memory+metadata_size and ignores its return. Caller
 *   supplies consistent sizes; native32 subtraction has no independent underflow rejection.
 */

TlsfControl * tlsf_create_with_pool(void *memory,uint pool_bytes,uint max_bytes)

{
  TlsfControl *control;
  uint metadata_size;

  if (max_bytes == 0) {
    max_bytes = pool_bytes;
  }
  control = tlsf_create(memory,max_bytes);
  if (control != (TlsfControl *)0x0) {
    metadata_size = control->metadata_size;
    tlsf_add_pool(control,(void *)((unsigned char *)memory + metadata_size),
                  pool_bytes - metadata_size);
  }
  return control;
}

