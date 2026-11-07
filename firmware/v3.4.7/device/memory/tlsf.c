/* Medius v3.4.7 device — memory/tlsf.c.
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

/* Keep signed class division as QUOS, including processor exceptions for
 * malformed configuration words; a C divide would introduce undefined behavior. */
static __inline__ __attribute__((always_inline)) int
xtensa_signed_divide(int numerator, int denominator)
{
    int quotient;
    __asm__ volatile ("quos %0, %1, %2" : "=a"(quotient)
        : "a"(numerator), "a"(denominator) : "memory");
    return quotient;
}

/* Native inlined mapping_insert: classify a size using one configuration
 * snapshot. Indices wrap as WORDs and register shifts use the low five bits.
 * Both outputs are local class-index words at the recovered call sites. */
static __inline__ __attribute__((always_inline)) void
tlsf_classify_size(unsigned int configuration, unsigned int size,
    unsigned int *first_level, unsigned int *second_level)
{
    unsigned int small_block_limit = (configuration >> 23) & 0xffU;
    unsigned int first;
    unsigned int second;
    if (size < small_block_limit) {
        unsigned int second_level_count = (configuration >> 14) & 0x3fU;
        int bucket_width = xtensa_signed_divide((int)small_block_limit,
            (int)second_level_count);
        second = (unsigned int)xtensa_signed_divide((int)size, bucket_width);
        first = 0;
    } else {
        unsigned int bit_length = 0;
        if (size != 0)
            bit_length = 32U - (unsigned int)xtensa_count_leading_zeros(size);
        unsigned int most_significant_bit = bit_length - 1U;
        unsigned int second_level_log2 = (configuration >> 20) & 7U;
        unsigned int first_level_shift = (configuration >> 5) & 7U;
        second = (size >> ((most_significant_bit - second_level_log2) & 31U)) ^
            (1U << second_level_log2);
        first = bit_length - first_level_shift;
    }
    *first_level = first;
    *second_level = second;
}

/* Native entry: 0x4038b130. */
/*
 * Medius v3.4.7 — device application; 0x4038b130.
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

/* Native entry: 0x4038b138. */
/*
 * Medius v3.4.7 — device application; 0x4038b138.
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

unsigned int tlsf_block_size(const void *payload)
{
    if (payload == NULL)
        return 0;
    const volatile unsigned int *size_word =
        (const volatile unsigned int *)((unsigned int)payload - 4U);
    return *size_word & 0xfffffffcU;
}

/* Native entry: 0x4038b150. */
/*
 * Medius v3.4.7 — device application; 0x4038b150.
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
 * c21d8f06f7c8de0762fe12d9e3f5bd3d18429130aa8e1b6421ffdd22f19377a2.
 */

/* Reference: TLSF 2867f6883a12920b1969ff9624c0ab0e4185c2ce tlsf.c and tlsf_control_functions.h.
   The bit-count helper emits native NSAU (unsigned 32-bit leading zeros, including 32 for zero). Configuration snapshots, class indices, list links and size flags are kept separate.
   Native QUOS and low-five-bit shifts retain exceptional and wrapping arithmetic behavior. */

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

void tlsf_free(TlsfControl *control, void *payload)
{
    if (payload == NULL)
        return;
    volatile TlsfControl *state = control;
    unsigned int payload_address = (unsigned int)payload;
    volatile TlsfBlock *block = (TlsfBlock *)(payload_address - 8U);
    unsigned int flags = block->size_flags;
    if ((flags & 1U) != 0 || flags < 4U)
        goto invariant_failure;

    volatile TlsfBlock *successor = (TlsfBlock *)
        (payload_address - 4U + (flags & 0xfffffffcU));
    unsigned int successor_flags = successor->size_flags;
    successor->size_flags = successor_flags | 2U;
    flags = block->size_flags;
    successor->previous_physical = (TlsfBlock *)block;
    block->size_flags = flags | 1U;

    /* Remove and absorb the previous physical block when its flag is set. */
    if ((flags & 2U) != 0) {
        volatile TlsfBlock *previous = block->previous_physical;
        if (previous == NULL)
            goto invariant_failure;
        unsigned int previous_flags = previous->size_flags;
        if ((previous_flags & 1U) == 0)
            goto invariant_failure;
        unsigned int configuration = state->configuration;
        unsigned int first_level;
        unsigned int second_level;
        tlsf_classify_size(configuration, previous_flags & 0xfffffffcU,
            &first_level, &second_level);
        TlsfBlock *previous_free = previous->previous_free;
        TlsfBlock *next_free = previous->next_free;
        if (previous_free == NULL || next_free == NULL)
            goto invariant_failure;
        ((volatile TlsfBlock *)next_free)->previous_free = previous_free;
        ((volatile TlsfBlock *)previous_free)->next_free = next_free;
        configuration = state->configuration;
        TlsfBlock **lists = state->free_lists;
        unsigned int second_level_count = (configuration >> 14) & 0x3fU;
        unsigned int index = second_level_count * first_level + second_level;
        TlsfBlock *volatile *head = (TlsfBlock *volatile *)
            ((unsigned int)lists + index * 4U);
        TlsfBlock *current_head = *head;
        if ((TlsfBlock *)previous == current_head) {
            *head = next_free;
            if (next_free == (TlsfBlock *)control) {
                unsigned int *second_bitmaps = state->second_level_bitmaps;
                volatile unsigned int *bitmap = (volatile unsigned int *)
                    ((unsigned int)second_bitmaps + first_level * 4U);
                unsigned int remaining = *bitmap & ~(1U << (second_level & 31U));
                *bitmap = remaining;
                if (remaining == 0) {
                    unsigned int first_bitmap = state->first_level_bitmap;
                    previous_flags = previous->size_flags;
                    state->first_level_bitmap = first_bitmap & ~(1U << (first_level & 31U));
                } else {
                    previous_flags = previous->size_flags;
                }
            }
        }
        if (previous_flags < 4U)
            goto invariant_failure;
        unsigned int current_flags = block->size_flags;
        unsigned int merged_flags = (current_flags & 0xfffffffcU) + 4U + previous_flags;
        previous->size_flags = merged_flags;
        payload_address = (unsigned int)previous + 8U;
        successor = (TlsfBlock *)((unsigned int)previous + 4U +
            (merged_flags & 0xfffffffcU));
        if (merged_flags < 4U)
            goto invariant_failure;
        successor->previous_physical = (TlsfBlock *)previous;
        /* The first native post-absorb hook target is fixed at zero. */
        block = previous;
    } else {
        unsigned int marked_flags = flags | 1U;
        successor = (TlsfBlock *)(payload_address - 4U + (flags & 0xfffffffcU));
        if (marked_flags < 4U)
            goto invariant_failure;
    }

    /* Remove and absorb the following free block, retaining conditional reloads. */
    if (successor == NULL)
        goto invariant_failure;
    successor_flags = successor->size_flags;
    TlsfBlock **lists;
    unsigned int merged_size;
    if ((successor_flags & 1U) != 0) {
        unsigned int configuration = state->configuration;
        unsigned int successor_size = successor_flags & 0xfffffffcU;
        unsigned int first_level;
        unsigned int second_level;
        tlsf_classify_size(configuration, successor_size, &first_level, &second_level);
        TlsfBlock *previous_free = successor->previous_free;
        TlsfBlock *next_free = successor->next_free;
        if (previous_free == NULL || next_free == NULL)
            goto invariant_failure;
        ((volatile TlsfBlock *)next_free)->previous_free = previous_free;
        ((volatile TlsfBlock *)previous_free)->next_free = next_free;
        configuration = state->configuration;
        lists = state->free_lists;
        unsigned int second_level_count = (configuration >> 14) & 0x3fU;
        unsigned int index = second_level_count * first_level + second_level;
        TlsfBlock *volatile *head = (TlsfBlock *volatile *)
            ((unsigned int)lists + index * 4U);
        TlsfBlock *current_head = *head;
        unsigned int current_flags;
        if (current_head == (TlsfBlock *)successor) {
            *head = next_free;
            if (next_free == (TlsfBlock *)control) {
                unsigned int *second_bitmaps = state->second_level_bitmaps;
                volatile unsigned int *bitmap = (volatile unsigned int *)
                    ((unsigned int)second_bitmaps + first_level * 4U);
                unsigned int remaining = *bitmap & ~(1U << (second_level & 31U));
                *bitmap = remaining;
                if (remaining == 0) {
                    unsigned int first_bitmap = state->first_level_bitmap;
                    state->first_level_bitmap = first_bitmap & ~(1U << (first_level & 31U));
                }
                current_flags = block->size_flags;
                if (current_flags < 4U)
                    goto invariant_failure;
                successor_size = successor->size_flags & 0xfffffffcU;
            } else {
                current_flags = block->size_flags;
            }
        } else {
            current_flags = block->size_flags;
        }
        unsigned int merged_flags = current_flags + successor_size + 4U;
        merged_size = merged_flags & 0xfffffffcU;
        block->size_flags = merged_flags;
        if (merged_flags < 4U)
            goto invariant_failure;
        successor = (TlsfBlock *)(payload_address - 4U + merged_size);
        successor->previous_physical = (TlsfBlock *)block;
        /* The second native post-absorb hook target is fixed at zero. */
    } else {
        unsigned int current_flags = block->size_flags;
        lists = state->free_lists;
        merged_size = current_flags & 0xfffffffcU;
    }

    /* Insert the merged block. Re-read configuration after the link writes. */
    unsigned int configuration = state->configuration;
    unsigned int first_level;
    unsigned int second_level;
    tlsf_classify_size(configuration, merged_size, &first_level, &second_level);
    unsigned int second_level_count = (configuration >> 14) & 0x3fU;
    unsigned int index = second_level_count * first_level + second_level;
    TlsfBlock *volatile *head = (TlsfBlock *volatile *)((unsigned int)lists + index * 4U);
    TlsfBlock *previous_head = *head;
    if (previous_head == NULL)
        goto invariant_failure;
    block->next_free = previous_head;
    block->previous_free = (TlsfBlock *)control;
    ((volatile TlsfBlock *)previous_head)->previous_free = (TlsfBlock *)block;
    if ((payload_address & 3U) != 0)
        goto invariant_failure;
    configuration = state->configuration;
    unsigned int first_bitmap = state->first_level_bitmap;
    second_level_count = (configuration >> 14) & 0x3fU;
    unsigned int *second_bitmaps = state->second_level_bitmaps;
    index = second_level_count * first_level + second_level;
    head = (TlsfBlock *volatile *)((unsigned int)lists + index * 4U);
    *head = (TlsfBlock *)block;
    state->first_level_bitmap = first_bitmap | (1U << (first_level & 31U));
    volatile unsigned int *bitmap = (volatile unsigned int *)
        ((unsigned int)second_bitmaps + first_level * 4U);
    unsigned int second_bitmap = *bitmap;
    *bitmap = second_bitmap | (1U << (second_level & 31U));
    return;

invariant_failure:
    __assert_func(NULL, 0, NULL, NULL);
}

/* Native entry: 0x4038b440. */
/*
 * Medius v3.4.7 — device application; 0x4038b440.
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

void *tlsf_get_pool(TlsfControl *control)
{
    if (control == NULL)
        return NULL;
    unsigned int metadata_size = ((const volatile TlsfControl *)control)->metadata_size;
    return (void *)((unsigned int)control + metadata_size);
}

/* Native entry: 0x4038b44c. */
/*
 * Medius v3.4.7 — device application; 0x4038b44c.
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
 * 9caf6d63d4a71bdf90f4a8c504ff56f9d8f20349f3d4cea04f22577a8045e52a.
 */

/* Reference: TLSF 2867f6883a12920b1969ff9624c0ab0e4185c2ce tlsf.c and tlsf_control_functions.h.
   The bit-count helper emits native NSAU (unsigned 32-bit leading zeros, including 32 for zero). Configuration snapshots, request sizes, class indices and split metadata use separate
   names; native signed QUOS and low-five-bit shifts are retained. */

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

void *tlsf_malloc(TlsfControl *control, unsigned int size)
{
    if (size == 0)
        return NULL;
    unsigned int adjusted_size = (size + 3U) & 0xfffffffcU;
    if (control == NULL)
        return NULL;
    volatile TlsfControl *state = control;
    unsigned int configuration = state->configuration;
    unsigned int maximum_size = 1U << ((configuration >> 8) & 31U);
    if (adjusted_size >= maximum_size)
        return NULL;
    if (adjusted_size < 12U)
        adjusted_size = 12U;

    /* GoodFit rounds larger requests before assigning the two size classes. */
    unsigned int small_block_limit = (configuration >> 23) & 0xffU;
    if (adjusted_size >= small_block_limit) {
        unsigned int most_significant_bit = 31U -
            (unsigned int)xtensa_count_leading_zeros(adjusted_size);
        unsigned int second_level_log2 = (configuration >> 20) & 7U;
        unsigned int rounding = 1U << ((most_significant_bit - second_level_log2) & 31U);
        if (((rounding - 1U) & rounding) != 0)
            goto invariant_failure;
        adjusted_size = (adjusted_size - 1U + rounding) & (0U - rounding);
    }
    unsigned int first_level;
    unsigned int second_level;
    tlsf_classify_size(configuration, adjusted_size, &first_level, &second_level);
    if ((int)first_level >= (int)(configuration & 31U))
        return NULL;

    /* Retain the bitmap/list pointer snapshots used by the original search. */
    unsigned int *second_bitmaps = state->second_level_bitmaps;
    volatile unsigned int *bitmap = (volatile unsigned int *)
        ((unsigned int)second_bitmaps + first_level * 4U);
    unsigned int second_bitmap = *bitmap;
    second_bitmap &= 0xffffffffU << (second_level & 31U);
    if (second_bitmap == 0) {
        unsigned int first_bitmap = state->first_level_bitmap;
        first_bitmap &= 0xffffffffU << ((first_level + 1U) & 31U);
        if (first_bitmap == 0)
            return NULL;
        unsigned int first_bit = (0U - first_bitmap) & first_bitmap;
        first_level = 31U - (unsigned int)xtensa_count_leading_zeros(first_bit);
        bitmap = (volatile unsigned int *)
            ((unsigned int)second_bitmaps + (first_level & 0xffffU) * 4U);
        second_bitmap = *bitmap;
        if (second_bitmap == 0)
            goto invariant_failure;
    }
    unsigned int second_bit = (0U - second_bitmap) & second_bitmap;
    second_level = 31U - (unsigned int)xtensa_count_leading_zeros(second_bit);
    TlsfBlock **lists = state->free_lists;
    unsigned int second_level_count = (configuration >> 14) & 0x3fU;
    unsigned int index = second_level_count * first_level + second_level;
    TlsfBlock *volatile *head = (TlsfBlock *volatile *)((unsigned int)lists + index * 4U);
    volatile TlsfBlock *block = *head;
    if (block == NULL)
        return NULL;
    unsigned int flags = block->size_flags;
    if ((flags & 0xfffffffcU) < adjusted_size)
        goto invariant_failure;
    TlsfBlock *previous_free = block->previous_free;
    TlsfBlock *next_free = block->next_free;
    if (previous_free == NULL || next_free == NULL)
        goto invariant_failure;
    ((volatile TlsfBlock *)next_free)->previous_free = previous_free;
    ((volatile TlsfBlock *)previous_free)->next_free = next_free;
    configuration = state->configuration;
    second_level_count = (configuration >> 14) & 0x3fU;
    index = second_level_count * first_level + second_level;
    head = (TlsfBlock *volatile *)((unsigned int)lists + index * 4U);
    TlsfBlock *current_head = *head;
    if ((TlsfBlock *)block == current_head) {
        *head = next_free;
        if (next_free == (TlsfBlock *)control) {
            bitmap = (volatile unsigned int *)((unsigned int)second_bitmaps + first_level * 4U);
            unsigned int remaining = *bitmap & ~(1U << (second_level & 31U));
            *bitmap = remaining;
            if (remaining == 0) {
                unsigned int first_bitmap = state->first_level_bitmap;
                state->first_level_bitmap = first_bitmap & ~(1U << (first_level & 31U));
            }
        }
    }
    if (adjusted_size == 0)
        goto invariant_failure;
    flags = block->size_flags;
    if ((flags & 1U) == 0)
        goto invariant_failure;
    unsigned int capacity = flags & 0xfffffffcU;
    unsigned int payload_address = (unsigned int)block + 8U;

    /* A trailing fragment needs twelve payload bytes plus the size-word overhead. */
    if (capacity >= adjusted_size + 16U) {
        volatile TlsfBlock *split = (TlsfBlock *)(payload_address + adjusted_size - 4U);
        unsigned int split_payload = (unsigned int)split + 8U;
        unsigned int remainder_size = capacity - (adjusted_size + 4U);
        if ((split_payload & 3U) != 0 || capacity != adjusted_size + 4U + remainder_size)
            goto invariant_failure;
        unsigned int split_flags = split->size_flags;
        split_flags = (split_flags & 3U) | remainder_size;
        split->size_flags = split_flags;
        if ((split_flags & 0xfffffffcU) < 12U)
            goto invariant_failure;
        flags = block->size_flags;
        block->size_flags = (flags & 3U) | adjusted_size;
        split_flags = split->size_flags;
        volatile TlsfBlock *successor = (TlsfBlock *)
            ((unsigned int)split + 4U + (split_flags & 0xfffffffcU));
        if (split_flags < 4U)
            goto invariant_failure;
        unsigned int successor_flags = successor->size_flags;
        successor->size_flags = successor_flags | 2U;
        split_flags = split->size_flags;
        successor->previous_physical = (TlsfBlock *)split;
        split->size_flags = split_flags | 1U;
        flags = block->size_flags;
        if (flags < 4U)
            goto invariant_failure;
        successor = (TlsfBlock *)(payload_address - 4U + (flags & 0xfffffffcU));
        successor->previous_physical = (TlsfBlock *)block;
        split->size_flags = split_flags | 3U;

        configuration = state->configuration;
        tlsf_classify_size(configuration, split_flags & 0xfffffffcU, &first_level, &second_level);
        second_level_count = (configuration >> 14) & 0x3fU;
        index = second_level_count * first_level + second_level;
        head = (TlsfBlock *volatile *)((unsigned int)lists + index * 4U);
        TlsfBlock *previous_head = *head;
        if (previous_head == NULL)
            goto invariant_failure;
        split->previous_free = (TlsfBlock *)control;
        split->next_free = previous_head;
        ((volatile TlsfBlock *)previous_head)->previous_free = (TlsfBlock *)split;
        configuration = state->configuration;
        unsigned int first_bitmap = state->first_level_bitmap;
        second_level_count = (configuration >> 14) & 0x3fU;
        index = second_level_count * first_level + second_level;
        head = (TlsfBlock *volatile *)((unsigned int)lists + index * 4U);
        *head = (TlsfBlock *)split;
        state->first_level_bitmap = first_bitmap | (1U << (first_level & 31U));
        bitmap = (volatile unsigned int *)((unsigned int)second_bitmaps + first_level * 4U);
        second_bitmap = *bitmap;
        *bitmap = second_bitmap | (1U << (second_level & 31U));
        flags = block->size_flags;
        capacity = flags & 0xfffffffcU;
    }
    volatile TlsfBlock *successor = (TlsfBlock *)(payload_address - 4U + capacity);
    if (flags < 4U)
        goto invariant_failure;
    unsigned int successor_flags = successor->size_flags;
    successor->size_flags = successor_flags & ~2U;
    flags = block->size_flags;
    block->size_flags = flags & ~1U;
    return (void *)payload_address;

invariant_failure:
    __assert_func(NULL, 0, NULL, NULL);
}

/* Native entry: 0x4038b718. */
/*
 * Medius v3.4.7 — device application; 0x4038b718.
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
 * 2b1e62ea351746b54c9f5e7680e16d911392420b5de602b0a92038d9c91826d1.
 */

/* Reference: TLSF 2867f6883a12920b1969ff9624c0ab0e4185c2ce tlsf.c and tlsf_control_functions.h.
   The bit-count helper emits native NSAU (unsigned 32-bit leading zeros, including 32 for zero). Request size, alignment working space, offset, class indices and split metadata have
   separate names. Unsigned address arithmetic and native signed class division are retained. */

/*
 * control: Initialized TLSF allocator with valid class configuration and metadata.
 * alignment: Caller-supplied nonzero power of two; outer multi-heap API validates it. Internal
 *   power-of-two assertions are reached conditionally.
 * size: Requested nonzero total payload bytes, including offset storage; caller supplies valid
 *   sizes for the native 32-bit arithmetic.
 * data_offset: Offset rounded up to4 bytes; returned payload plus this rounded offset meets
 *   alignment for valid inputs.
 * Returns: Payload pointer or NULL on unsatisfied size/class search; invalid reached
 *   alignment/metadata assertions abort.
 * Requirements/effects: Reserves extra gap/split space, locates and unlinks a free block, plans a
 *   leading gap large enough for metadata plus rounded offset, reinserts a leading free block when
 *   needed and trims/reinserts a trailing block. Does not lock, wipe or update multi-heap
 *   counters. Zero alignment has no independent rejection here.
 */

void *tlsf_memalign_offs(TlsfControl *control, unsigned int alignment,
    unsigned int size, unsigned int data_offset)
{
    if (size == 0)
        goto invalid_request;
    unsigned int minimum_payload_size = (size + 3U) & 0xfffffffcU;
    if (control == NULL)
        goto invalid_request;
    volatile TlsfControl *state = control;
    unsigned int configuration = state->configuration;
    unsigned int maximum_size = 1U << ((configuration >> 8) & 31U);
    if (minimum_payload_size >= maximum_size)
        goto invalid_request;
    if (minimum_payload_size < 12U)
        minimum_payload_size = 12U;

    unsigned int search_size = minimum_payload_size;
    unsigned int span = minimum_payload_size + alignment + 16U;
    if (span == 0) {
        if (alignment > 4U)
            return NULL;
    } else {
        if ((alignment & (alignment - 1U)) != 0)
            goto invariant_failure;
        unsigned int aligned_span = (span + alignment - 1U) & (0U - alignment);
        if (aligned_span < maximum_size) {
            if (alignment > 4U)
                search_size = aligned_span < 12U ? 12U : aligned_span;
        } else if (alignment > 4U) {
            return NULL;
        }
    }

    /* Locate and unlink a block large enough for the alignment working space. */
    unsigned int small_block_limit = (configuration >> 23) & 0xffU;
    if (search_size >= small_block_limit) {
        unsigned int most_significant_bit = 31U -
            (unsigned int)xtensa_count_leading_zeros(search_size);
        unsigned int second_level_log2 = (configuration >> 20) & 7U;
        unsigned int rounding = 1U << ((most_significant_bit - second_level_log2) & 31U);
        if (((rounding - 1U) & rounding) != 0)
            goto invariant_failure;
        search_size = (search_size - 1U + rounding) & (0U - rounding);
    }
    unsigned int first_level;
    unsigned int second_level;
    tlsf_classify_size(configuration, search_size, &first_level, &second_level);
    if ((int)first_level >= (int)(configuration & 31U))
        return NULL;
    unsigned int *second_bitmaps = state->second_level_bitmaps;
    volatile unsigned int *bitmap = (volatile unsigned int *)
        ((unsigned int)second_bitmaps + first_level * 4U);
    unsigned int second_bitmap = *bitmap;
    second_bitmap &= 0xffffffffU << (second_level & 31U);
    if (second_bitmap == 0) {
        unsigned int first_bitmap = state->first_level_bitmap;
        first_bitmap &= 0xffffffffU << ((first_level + 1U) & 31U);
        if (first_bitmap == 0)
            return NULL;
        unsigned int first_bit = (0U - first_bitmap) & first_bitmap;
        first_level = 31U - (unsigned int)xtensa_count_leading_zeros(first_bit);
        bitmap = (volatile unsigned int *)
            ((unsigned int)second_bitmaps + (first_level & 0xffffU) * 4U);
        second_bitmap = *bitmap;
        if (second_bitmap == 0)
            goto invariant_failure;
    }
    unsigned int second_bit = (0U - second_bitmap) & second_bitmap;
    second_level = 31U - (unsigned int)xtensa_count_leading_zeros(second_bit);
    TlsfBlock **lists = state->free_lists;
    unsigned int second_level_count = (configuration >> 14) & 0x3fU;
    unsigned int index = second_level_count * first_level + second_level;
    TlsfBlock *volatile *head = (TlsfBlock *volatile *)((unsigned int)lists + index * 4U);
    volatile TlsfBlock *block = *head;
    if (block == NULL)
        return NULL;
    unsigned int flags = block->size_flags;
    if ((flags & 0xfffffffcU) < search_size)
        goto invariant_failure;
    TlsfBlock *previous_free = block->previous_free;
    TlsfBlock *next_free = block->next_free;
    if (previous_free == NULL || next_free == NULL)
        goto invariant_failure;
    ((volatile TlsfBlock *)next_free)->previous_free = previous_free;
    ((volatile TlsfBlock *)previous_free)->next_free = next_free;
    configuration = state->configuration;
    second_level_count = (configuration >> 14) & 0x3fU;
    index = second_level_count * first_level + second_level;
    head = (TlsfBlock *volatile *)((unsigned int)lists + index * 4U);
    TlsfBlock *current_head = *head;
    if ((TlsfBlock *)block == current_head) {
        *head = next_free;
        if (next_free == (TlsfBlock *)control) {
            bitmap = (volatile unsigned int *)((unsigned int)second_bitmaps + first_level * 4U);
            unsigned int remaining = *bitmap & ~(1U << (second_level & 31U));
            *bitmap = remaining;
            if (remaining == 0) {
                unsigned int first_bitmap = state->first_level_bitmap;
                state->first_level_bitmap = first_bitmap & ~(1U << (first_level & 31U));
            }
        }
    }

    /* Plan a leading free fragment so payload + rounded_offset meets alignment. */
    unsigned int payload_address = (unsigned int)block + 8U;
    unsigned int alignment_mask = alignment - 1U;
    unsigned int aligned_target = (payload_address + alignment_mask) & (0U - alignment);
    if ((alignment & alignment_mask) != 0)
        goto invariant_failure;
    unsigned int rounded_offset = (data_offset + 3U) & 0xfffffffcU;
    unsigned int minimum_gap = rounded_offset + 16U;
    unsigned int gap = aligned_target - payload_address;
    if ((gap != 0 && gap < minimum_gap) ||
        (gap == 0 && rounded_offset != 0 && alignment > 4U)) {
        unsigned int extra = minimum_gap - gap;
        if (extra < alignment)
            extra = alignment;
        aligned_target = (aligned_target + extra + alignment_mask) & (0U - alignment);
        gap = aligned_target - payload_address;
    }
    if (gap != 0 && gap < minimum_gap)
        goto invariant_failure;
    flags = block->size_flags;
    if (gap != 0) {
        unsigned int leading_span = gap - rounded_offset;
        unsigned int capacity = flags & 0xfffffffcU;
        if (capacity >= leading_span + 16U) {
            volatile TlsfBlock *aligned_block = (TlsfBlock *)
                ((unsigned int)block + leading_span);
            unsigned int aligned_payload = (unsigned int)aligned_block + 8U;
            unsigned int remaining_size = capacity + rounded_offset - gap;
            if ((aligned_payload & 3U) != 0)
                goto invariant_failure;
            unsigned int aligned_flags = aligned_block->size_flags;
            aligned_flags = (aligned_flags & 3U) | remaining_size;
            aligned_block->size_flags = aligned_flags;
            if ((aligned_flags & 0xfffffffcU) < 12U)
                goto invariant_failure;
            flags = block->size_flags;
            block->size_flags = (flags & 3U) | (leading_span - 4U);
            aligned_flags = aligned_block->size_flags;
            volatile TlsfBlock *successor = (TlsfBlock *)
                ((unsigned int)aligned_block + 4U + (aligned_flags & 0xfffffffcU));
            if (aligned_flags < 4U)
                goto invariant_failure;
            unsigned int successor_flags = successor->size_flags;
            successor->size_flags = successor_flags | 2U;
            aligned_flags = aligned_block->size_flags;
            successor->previous_physical = (TlsfBlock *)aligned_block;
            aligned_block->size_flags = aligned_flags | 3U;
            flags = block->size_flags;
            unsigned int leading_size = flags & 0xfffffffcU;
            if (flags < 4U)
                goto invariant_failure;
            successor = (TlsfBlock *)(payload_address - 4U + leading_size);
            successor->previous_physical = (TlsfBlock *)block;

            configuration = state->configuration;
            tlsf_classify_size(configuration, leading_size, &first_level, &second_level);
            second_level_count = (configuration >> 14) & 0x3fU;
            index = second_level_count * first_level + second_level;
            head = (TlsfBlock *volatile *)((unsigned int)lists + index * 4U);
            TlsfBlock *previous_head = *head;
            if (previous_head == NULL)
                goto invariant_failure;
            block->next_free = previous_head;
            block->previous_free = (TlsfBlock *)control;
            ((volatile TlsfBlock *)previous_head)->previous_free = (TlsfBlock *)block;
            if ((payload_address & 3U) != 0)
                goto invariant_failure;
            configuration = state->configuration;
            unsigned int first_bitmap = state->first_level_bitmap;
            second_level_count = (configuration >> 14) & 0x3fU;
            index = second_level_count * first_level + second_level;
            head = (TlsfBlock *volatile *)((unsigned int)lists + index * 4U);
            *head = (TlsfBlock *)block;
            state->first_level_bitmap = first_bitmap | (1U << (first_level & 31U));
            bitmap = (volatile unsigned int *)((unsigned int)second_bitmaps + first_level * 4U);
            second_bitmap = *bitmap;
            *bitmap = second_bitmap | (1U << (second_level & 31U));
            flags = aligned_block->size_flags;
            block = aligned_block;
        }
    }

    /* Trim the trailing free fragment using the original minimum payload size. */
    if ((flags & 1U) == 0)
        goto invariant_failure;
    unsigned int capacity = flags & 0xfffffffcU;
    payload_address = (unsigned int)block + 8U;
    if (capacity >= minimum_payload_size + 16U) {
        volatile TlsfBlock *split = (TlsfBlock *)(payload_address + minimum_payload_size - 4U);
        unsigned int split_payload = (unsigned int)split + 8U;
        unsigned int remainder_size = capacity - (minimum_payload_size + 4U);
        if ((split_payload & 3U) != 0 || capacity != minimum_payload_size + 4U + remainder_size)
            goto invariant_failure;
        unsigned int split_flags = split->size_flags;
        split_flags = (split_flags & 3U) | remainder_size;
        split->size_flags = split_flags;
        if ((split_flags & 0xfffffffcU) < 12U)
            goto invariant_failure;
        flags = block->size_flags;
        block->size_flags = (flags & 3U) | minimum_payload_size;
        split_flags = split->size_flags;
        volatile TlsfBlock *successor = (TlsfBlock *)
            ((unsigned int)split + 4U + (split_flags & 0xfffffffcU));
        if (split_flags < 4U)
            goto invariant_failure;
        unsigned int successor_flags = successor->size_flags;
        successor->size_flags = successor_flags | 2U;
        split_flags = split->size_flags;
        successor->previous_physical = (TlsfBlock *)split;
        split->size_flags = split_flags | 1U;
        flags = block->size_flags;
        if (flags < 4U)
            goto invariant_failure;
        successor = (TlsfBlock *)(payload_address - 4U + (flags & 0xfffffffcU));
        successor->previous_physical = (TlsfBlock *)block;
        split->size_flags = split_flags | 3U;
        configuration = state->configuration;
        tlsf_classify_size(configuration, split_flags & 0xfffffffcU, &first_level, &second_level);
        second_level_count = (configuration >> 14) & 0x3fU;
        index = second_level_count * first_level + second_level;
        head = (TlsfBlock *volatile *)((unsigned int)lists + index * 4U);
        TlsfBlock *previous_head = *head;
        if (previous_head == NULL)
            goto invariant_failure;
        split->next_free = previous_head;
        split->previous_free = (TlsfBlock *)control;
        ((volatile TlsfBlock *)previous_head)->previous_free = (TlsfBlock *)split;
        configuration = state->configuration;
        unsigned int first_bitmap = state->first_level_bitmap;
        second_level_count = (configuration >> 14) & 0x3fU;
        index = second_level_count * first_level + second_level;
        head = (TlsfBlock *volatile *)((unsigned int)lists + index * 4U);
        *head = (TlsfBlock *)split;
        state->first_level_bitmap = first_bitmap | (1U << (first_level & 31U));
        bitmap = (volatile unsigned int *)((unsigned int)second_bitmaps + first_level * 4U);
        second_bitmap = *bitmap;
        *bitmap = second_bitmap | (1U << (second_level & 31U));
        flags = block->size_flags;
        capacity = flags & 0xfffffffcU;
    }
    volatile TlsfBlock *successor = (TlsfBlock *)(payload_address - 4U + capacity);
    if (flags < 4U)
        goto invariant_failure;
    unsigned int successor_flags = successor->size_flags;
    successor->size_flags = successor_flags & ~2U;
    flags = block->size_flags;
    block->size_flags = flags & ~1U;
    return (void *)payload_address;

invalid_request:
    if (alignment + 16U == 0 || (alignment & (alignment - 1U)) == 0)
        return NULL;
invariant_failure:
    __assert_func(NULL, 0, NULL, NULL);
}

/* Native entry: 0x4038bba4. */
/*
 * Medius v3.4.7 — device application; 0x4038bba4.
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
 * 1c36dfadf859ad10d3945700e49d021e84d9e33e9b429a0e8ae94cfabddf8b63.
 */

/* Reference: TLSF 2867f6883a12920b1969ff9624c0ab0e4185c2ce tlsf.c and tlsf_control_functions.h.
   The bit-count helper emits native NSAU (unsigned 32-bit leading zeros, including 32 for zero). Growth, copying, tail splitting and remainder coalescing retain separate size/flag
   snapshots and the native conditional reloads. Class division remains signed QUOS. */

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

void *tlsf_realloc(TlsfControl *control, void *payload, unsigned int size)
{
    if (payload == NULL)
        return tlsf_malloc(control, size);
    if (size == 0) {
        tlsf_free(control, payload);
        return NULL;
    }
    unsigned int payload_address = (unsigned int)payload;
    volatile TlsfBlock *block = (TlsfBlock *)(payload_address - 8U);
    unsigned int flags = block->size_flags;
    if (flags < 4U)
        goto invariant_failure;
    unsigned int adjusted_size = (size + 3U) & 0xfffffffcU;
    if (control == NULL)
        return NULL;
    volatile TlsfControl *state = control;
    unsigned int configuration = state->configuration;
    unsigned int maximum_size = 1U << ((configuration >> 8) & 31U);
    if (adjusted_size >= maximum_size)
        return NULL;
    if (adjusted_size < 12U)
        adjusted_size = 12U;
    if ((flags & 1U) != 0)
        goto invariant_failure;
    unsigned int capacity = flags & 0xfffffffcU;

    /* Grow into a free successor, or move only after replacement allocation succeeds. */
    if (capacity < adjusted_size) {
        volatile TlsfBlock *successor = (TlsfBlock *)(payload_address - 4U + capacity);
        unsigned int successor_flags = successor->size_flags;
        unsigned int successor_size = successor_flags & 0xfffffffcU;
        if (capacity + 4U + successor_size < adjusted_size || (successor_flags & 1U) == 0) {
            void *replacement = tlsf_malloc(control, size);
            if (replacement == NULL)
                return NULL;
            unsigned int copy_size = size < capacity ? size : capacity;
            memcpy(replacement, payload, copy_size);
            tlsf_free(control, payload);
            return replacement;
        }
        unsigned int first_level;
        unsigned int second_level;
        tlsf_classify_size(configuration, successor_size, &first_level, &second_level);
        TlsfBlock *previous_free = successor->previous_free;
        TlsfBlock *next_free = successor->next_free;
        if (previous_free == NULL || next_free == NULL)
            goto invariant_failure;
        ((volatile TlsfBlock *)next_free)->previous_free = previous_free;
        ((volatile TlsfBlock *)previous_free)->next_free = next_free;
        configuration = state->configuration;
        TlsfBlock **lists = state->free_lists;
        unsigned int second_level_count = (configuration >> 14) & 0x3fU;
        unsigned int index = second_level_count * first_level + second_level;
        TlsfBlock *volatile *head = (TlsfBlock *volatile *)((unsigned int)lists + index * 4U);
        TlsfBlock *current_head = *head;
        if ((TlsfBlock *)successor == current_head) {
            *head = next_free;
            if (next_free == (TlsfBlock *)control) {
                unsigned int *second_bitmaps = state->second_level_bitmaps;
                volatile unsigned int *bitmap = (volatile unsigned int *)
                    ((unsigned int)second_bitmaps + first_level * 4U);
                unsigned int remaining = *bitmap & ~(1U << (second_level & 31U));
                *bitmap = remaining;
                if (remaining == 0) {
                    unsigned int first_bitmap = state->first_level_bitmap;
                    state->first_level_bitmap = first_bitmap & ~(1U << (first_level & 31U));
                }
                flags = block->size_flags;
                if (flags < 4U)
                    goto invariant_failure;
                successor_size = successor->size_flags & 0xfffffffcU;
            }
        }
        /* Other unlink paths retain the original flags and successor-size snapshots. */
        unsigned int merged_flags = flags + successor_size + 4U;
        block->size_flags = merged_flags;
        successor = (TlsfBlock *)(payload_address - 4U + (merged_flags & 0xfffffffcU));
        if (merged_flags < 4U)
            goto invariant_failure;
        successor->previous_physical = (TlsfBlock *)block;
        /* The first native post-absorb hook target is fixed at zero. */
        successor_flags = successor->size_flags;
        successor->size_flags = successor_flags & ~2U;
        flags = block->size_flags;
        block->size_flags = flags & ~1U;
        capacity = flags & 0xfffffffcU;
    }

    /* Keep a short tail; otherwise create a free remainder with a used predecessor. */
    if (capacity < adjusted_size + 16U)
        return payload;
    volatile TlsfBlock *remainder = (TlsfBlock *)(payload_address - 4U + adjusted_size);
    unsigned int remainder_payload = (unsigned int)remainder + 8U;
    unsigned int remainder_size = capacity - (adjusted_size + 4U);
    if ((remainder_payload & 3U) != 0 || adjusted_size + 4U + remainder_size != capacity)
        goto invariant_failure;
    unsigned int remainder_flags = remainder->size_flags;
    remainder_flags = (remainder_flags & 3U) | remainder_size;
    remainder->size_flags = remainder_flags;
    if ((remainder_flags & 0xfffffffcU) < 12U)
        goto invariant_failure;
    flags = block->size_flags;
    block->size_flags = (flags & 3U) | adjusted_size;
    remainder_flags = remainder->size_flags;
    volatile TlsfBlock *successor = (TlsfBlock *)
        ((unsigned int)remainder + 4U + (remainder_flags & 0xfffffffcU));
    if (remainder_flags < 4U)
        goto invariant_failure;
    unsigned int successor_flags = successor->size_flags;
    successor->size_flags = successor_flags | 2U;
    remainder_flags = remainder->size_flags;
    successor->previous_physical = (TlsfBlock *)remainder;
    remainder_size = remainder_flags & 0xfffffffcU;
    remainder_flags = (remainder_flags & ~2U) | 1U;
    remainder->size_flags = remainder_flags;
    successor = (TlsfBlock *)(remainder_payload - 4U + remainder_size);
    if (remainder_flags < 4U || successor == NULL)
        goto invariant_failure;
    successor_flags = successor->size_flags;

    /* Coalesce that remainder with the following free block before inserting it. */
    TlsfBlock **lists;
    if ((successor_flags & 1U) != 0) {
        configuration = state->configuration;
        unsigned int successor_size = successor_flags & 0xfffffffcU;
        unsigned int first_level;
        unsigned int second_level;
        tlsf_classify_size(configuration, successor_size, &first_level, &second_level);
        TlsfBlock *previous_free = successor->previous_free;
        TlsfBlock *next_free = successor->next_free;
        if (previous_free == NULL || next_free == NULL)
            goto invariant_failure;
        ((volatile TlsfBlock *)next_free)->previous_free = previous_free;
        ((volatile TlsfBlock *)previous_free)->next_free = next_free;
        configuration = state->configuration;
        lists = state->free_lists;
        unsigned int second_level_count = (configuration >> 14) & 0x3fU;
        unsigned int index = second_level_count * first_level + second_level;
        TlsfBlock *volatile *head = (TlsfBlock *volatile *)((unsigned int)lists + index * 4U);
        TlsfBlock *current_head = *head;
        if ((TlsfBlock *)successor == current_head) {
            *head = next_free;
            if (next_free == (TlsfBlock *)control) {
                unsigned int *second_bitmaps = state->second_level_bitmaps;
                volatile unsigned int *bitmap = (volatile unsigned int *)
                    ((unsigned int)second_bitmaps + first_level * 4U);
                unsigned int remaining = *bitmap & ~(1U << (second_level & 31U));
                *bitmap = remaining;
                if (remaining == 0) {
                    unsigned int first_bitmap = state->first_level_bitmap;
                    state->first_level_bitmap = first_bitmap & ~(1U << (first_level & 31U));
                }
                remainder_flags = remainder->size_flags;
                if (remainder_flags < 4U)
                    goto invariant_failure;
                successor_size = successor->size_flags & 0xfffffffcU;
            }
        }
        unsigned int merged_flags = remainder_flags + successor_size + 4U;
        remainder_size = merged_flags & 0xfffffffcU;
        remainder->size_flags = merged_flags;
        if (merged_flags < 4U)
            goto invariant_failure;
        successor = (TlsfBlock *)(remainder_payload - 4U + remainder_size);
        successor->previous_physical = (TlsfBlock *)remainder;
        /* The second native post-absorb hook target is fixed at zero. */
        configuration = state->configuration;
    } else {
        configuration = state->configuration;
        lists = state->free_lists;
    }

    unsigned int first_level;
    unsigned int second_level;
    tlsf_classify_size(configuration, remainder_size, &first_level, &second_level);
    unsigned int second_level_count = (configuration >> 14) & 0x3fU;
    unsigned int index = second_level_count * first_level + second_level;
    TlsfBlock *volatile *head = (TlsfBlock *volatile *)((unsigned int)lists + index * 4U);
    TlsfBlock *previous_head = *head;
    if (previous_head == NULL)
        goto invariant_failure;
    remainder->next_free = previous_head;
    remainder->previous_free = (TlsfBlock *)control;
    ((volatile TlsfBlock *)previous_head)->previous_free = (TlsfBlock *)remainder;
    configuration = state->configuration;
    unsigned int first_bitmap = state->first_level_bitmap;
    second_level_count = (configuration >> 14) & 0x3fU;
    unsigned int *second_bitmaps = state->second_level_bitmaps;
    index = second_level_count * first_level + second_level;
    head = (TlsfBlock *volatile *)((unsigned int)lists + index * 4U);
    *head = (TlsfBlock *)remainder;
    state->first_level_bitmap = first_bitmap | (1U << (first_level & 31U));
    volatile unsigned int *bitmap = (volatile unsigned int *)
        ((unsigned int)second_bitmaps + first_level * 4U);
    unsigned int second_bitmap = *bitmap;
    *bitmap = second_bitmap | (1U << (second_level & 31U));
    return payload;

invariant_failure:
    __assert_func(NULL, 0, NULL, NULL);
}

/* Native entry: 0x4038bf48. */
/*
 * Medius v3.4.7 — device application; 0x4038bf48.
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

/* Native entry: 0x420249a4. */
/*
 * Medius v3.4.7 — device application; 0x420249a4.
 *
 * Default TLSF walker prints payload address, used/free label, hexadecimal size and header
 * address payload-8, then returns true. The user argument is unused. Behavioral prefix
 * distinguishes the SDK static default_walker symbol; the printer calls the reviewed Newlib printf.
 *
 * Calls: newlib_printf.
 *
 * Original function-byte SHA-256:
 * bfc82f8bc97c09f29aa29d68ab8e8c761e91ee2f4d05894515df7dc5a749ad38.
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

bool tlsf_default_walker(void *payload, unsigned int size, int used, void *unused_user)
{
    const char *allocation_state = used != 0 ? "used" : "free";
    void *header = (void *)((unsigned int)payload - 8U);
    newlib_printf("\t%p %s size: %x (%p)\n", payload, allocation_state, size, header);
    return true;
}

/* Native entry: 0x420249c4. */
/*
 * Medius v3.4.7 — device application; 0x420249c4.
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
 * 8036cbef80e49168e246cfe70fd96ab2acbcd5d9961cbb3a104606ed5bd5addf.
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

void tlsf_walk_pool(void *pool, TlsfWalker walker, void *user)
{
    volatile TlsfBlock *block = (TlsfBlock *)((unsigned int)pool - 4U);
    TlsfWalker visit = walker != NULL ? walker : tlsf_default_walker;
    while (block != NULL) {
        unsigned int flags = block->size_flags;
        if (flags < 4U)
            return;
        unsigned int payload_address = (unsigned int)block + 8U;
        unsigned int capacity = flags & 0xfffffffcU;
        int used = (int)((~flags) & 1U);
        if (!visit((void *)payload_address, capacity, used, user))
            return;
        /* The callback may change metadata; advancement uses a fresh size word. */
        flags = block->size_flags;
        block = (TlsfBlock *)(payload_address + (flags & 0xfffffffcU) - 4U);
        if (flags < 4U)
            __assert_func(NULL, 0, NULL, NULL);
    }
}

/* Native entry: 0x42024a14. */
/*
 * Medius v3.4.7 — device application; 0x42024a14.
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
 * 8d18ed0ec783bda09b592dafc1f1292b8849b6313ca1977d30e8b197b0b23c55.
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

unsigned int tlsf_fit_size(TlsfControl *control, unsigned int size)
{
    if (size == 0 || control == NULL)
        return 0;
    volatile TlsfControl *state = control;
    unsigned int configuration = state->configuration;
    unsigned int small_block_size = (configuration >> 23) & 0xffU;
    if (size < small_block_size) {
        unsigned int aligned_size = (size + 3U) & 0xfffffffcU;
        unsigned int maximum_size = 1U << ((configuration >> 8) & 31U);
        if (aligned_size >= maximum_size)
            return 0;
        return aligned_size < 12U ? 12U : aligned_size;
    }
    unsigned int second_level_count = (configuration >> 14) & 0x3fU;
    unsigned int leading_zeros = (unsigned int)xtensa_count_leading_zeros(size);
    unsigned int highest_size_bit = 0x80000000U >> (leading_zeros & 31U);
    /* QUOS remains a native instruction, including its exceptional inputs. */
    int signed_interval = xtensa_signed_divide((int)highest_size_bit, (int)second_level_count);
    return size & (0U - (unsigned int)signed_interval);
}

/* Native entry: 0x42024a6c. */
/*
 * Medius v3.4.7 — device application; 0x42024a6c.
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
 * 91274ee54693616959009ab7794ed740a830dff6617a843498237d860dcd1ec3.
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

void *tlsf_add_pool(TlsfControl *control, void *memory, unsigned int bytes)
{
    unsigned int pool_size = (bytes - 8U) & 0xfffffffcU;
    unsigned int memory_address = (unsigned int)memory;
    if ((memory_address & 3U) != 0) {
        newlib_printf("tlsf_add_pool: Memory must be aligned by %u bytes.\n", 4U);
        return NULL;
    }
    volatile TlsfControl *state = control;
    unsigned int maximum_size = 0;
    if (control != NULL) {
        unsigned int configuration = state->configuration;
        maximum_size = 1U << ((configuration >> 8) & 31U);
    }
    if (control == NULL || pool_size < 12U || pool_size > maximum_size) {
        newlib_printf("tlsf_add_pool: Memory size must be between %u and %u bytes.\n",
                      20U, maximum_size + 8U);
        return NULL;
    }

    /* Retain the initial read even though forcing both flags replaces its low bits. */
    volatile TlsfBlock *block = (TlsfBlock *)(memory_address - 4U);
    unsigned int flags = block->size_flags;
    flags = (flags & 3U) | pool_size;
    block->size_flags = (flags & ~2U) | 1U;
    unsigned int capacity = flags & 0xfffffffcU;
    unsigned int configuration = state->configuration;
    unsigned int first_level;
    unsigned int second_level;
    tlsf_classify_size(configuration, capacity, &first_level, &second_level);
    unsigned int second_level_count = (configuration >> 14) & 0x3fU;
    TlsfBlock **lists = state->free_lists;
    unsigned int index = first_level * second_level_count + second_level;
    TlsfBlock *volatile *head = (TlsfBlock *volatile *)((unsigned int)lists + index * 4U);
    TlsfBlock *previous_head = *head;
    if (previous_head == NULL)
        goto invariant_failure;
    block->next_free = previous_head;
    block->previous_free = (TlsfBlock *)control;
    ((volatile TlsfBlock *)previous_head)->previous_free = (TlsfBlock *)block;
    unsigned int payload_address = (unsigned int)block + 8U;
    if (payload_address != (((unsigned int)block + 11U) & 0xfffffffcU))
        goto invariant_failure;

    /* Publish through the cached list base but freshly sampled configuration/bitmaps. */
    configuration = state->configuration;
    unsigned int first_bitmap = state->first_level_bitmap;
    second_level_count = (configuration >> 14) & 0x3fU;
    unsigned int *second_bitmaps = state->second_level_bitmaps;
    index = first_level * second_level_count + second_level;
    head = (TlsfBlock *volatile *)((unsigned int)lists + index * 4U);
    *head = (TlsfBlock *)block;
    state->first_level_bitmap = first_bitmap | (1U << (first_level & 31U));
    volatile unsigned int *bitmap = (volatile unsigned int *)
        ((unsigned int)second_bitmaps + first_level * 4U);
    unsigned int second_bitmap = *bitmap;
    *bitmap = second_bitmap | (1U << (second_level & 31U));
    flags = block->size_flags;
    volatile TlsfBlock *sentinel = (TlsfBlock *)
        (payload_address + (flags & 0xfffffffcU) - 4U);
    if (flags < 4U)
        goto invariant_failure;
    sentinel->previous_physical = (TlsfBlock *)block;
    sentinel->size_flags = 2U; /* zero size, used, previous block free */
    return memory;

invariant_failure:
    __assert_func(NULL, 0, NULL, NULL);
}

/* Native entry: 0x42024ba4. */
/*
 * Medius v3.4.7 — device application; 0x42024ba4.
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
 * 4951866a707f767d65c5dbd52e44a5abbe3fedf1eaec2a51c16f098761be5f13.
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

TlsfControl *tlsf_create(void *memory, unsigned int max_bytes)
{
    if (memory == NULL)
        return NULL;
    unsigned int memory_address = (unsigned int)memory;
    if ((memory_address & 3U) != 0) {
        newlib_printf("tlsf_create: Memory must be aligned to %u bytes.\n", 4U);
        return NULL;
    }
    if (max_bytes < 36U)
        return NULL;

    unsigned int first_level_max = 32U - (unsigned int)xtensa_count_leading_zeros(max_bytes);
    unsigned int second_level_log2 = max_bytes <= 16384U ? 3U : max_bytes <= 262144U ? 4U : 5U;
    unsigned int first_level_shift = second_level_log2 + 2U;
    unsigned int second_level_count = 1U << second_level_log2;
    unsigned int small_block_size = 1U << first_level_shift;
    unsigned int first_level_count = (first_level_max + 1U - first_level_shift) & 0xffU;
    unsigned int metadata_size = 4U * (9U + first_level_count + first_level_count * second_level_count);
    TlsfControl *control = memory;
    volatile TlsfControl *state = control;
    unsigned int padding_bit = state->configuration & 0x80000000U;
    unsigned int configuration = first_level_count | (first_level_shift << 5) |
        (first_level_max << 8) | (second_level_count << 14) |
        (second_level_log2 << 20) | (small_block_size << 23) | padding_bit;
    /* Both writes precede the final capacity check; failure leaves them committed. */
    state->metadata_size = metadata_size;
    state->configuration = configuration;
    if (max_bytes < metadata_size + 12U)
        return NULL;

    unsigned int bitmap_address = (memory_address + 39U) & 0xfffffffcU;
    unsigned int lists_address = (bitmap_address + first_level_count * 4U + 3U) & 0xfffffffcU;
    unsigned int *bitmaps = (unsigned int *)bitmap_address;
    TlsfBlock **lists = (TlsfBlock **)lists_address;
    int subdivision_size = xtensa_signed_divide((int)small_block_size, (int)second_level_count);
    state->null_block.next_free = (TlsfBlock *)control;
    state->null_block.previous_free = (TlsfBlock *)control;
    state->first_level_bitmap = 0;
    state->second_level_bitmaps = bitmaps;
    state->free_lists = lists;
    if (subdivision_size != 4)
        __assert_func(NULL, 0, NULL, NULL);

    /* The first row uses the calculated count; later rows use reloaded configuration. */
    unsigned int row = 0;
    if (first_level_count != 0) {
        do {
            *(volatile unsigned int *)bitmap_address = 0;
            configuration = state->configuration;
            unsigned int column = 0;
            unsigned int columns = (configuration >> 14) & 0x3fU;
            while (column < columns) {
                unsigned int index = (row * columns + column) & 0xffffU;
                *(TlsfBlock *volatile *)(lists_address + index * 4U) = (TlsfBlock *)control;
                configuration = state->configuration;
                ++column;
                columns = (configuration >> 14) & 0x3fU;
            }
            ++row;
            bitmap_address += 4U;
            if (row >= (configuration & 0x1fU))
                break;
        } while (true);
    }
    return control;
}

/* Native entry: 0x42024cbc. */
/*
 * Medius v3.4.7 — device application; 0x42024cbc.
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

TlsfControl *tlsf_create_with_pool(void *memory, unsigned int pool_bytes, unsigned int max_bytes)
{
    unsigned int capacity_bound = max_bytes != 0 ? max_bytes : pool_bytes;
    TlsfControl *control = tlsf_create(memory, capacity_bound);
    if (control != NULL) {
        unsigned int metadata_size = ((volatile TlsfControl *)control)->metadata_size;
        void *pool = (void *)((unsigned int)memory + metadata_size);
        /* Native subtraction wraps; the add-pool result does not replace control. */
        tlsf_add_pool(control, pool, pool_bytes - metadata_size);
    }
    return control;
}

