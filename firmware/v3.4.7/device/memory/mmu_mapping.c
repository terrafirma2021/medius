/* Medius v3.4.7 device: MMU virtual-range allocation and translation. */
#include "../include/types.h"

/* Inline reconstruction utilities for native list and region addressing.
 * They are not additional firmware entry points. */
static __inline__ __attribute__((always_inline)) volatile MmuRegion *
mmu_region_at(unsigned int index)
{
    return (volatile MmuRegion *)(0x3fcd862cU + index * 40U);
}
static __inline__ __attribute__((always_inline)) MmuBlock *
mmu_owner_of_next_link(MmuBlock **link)
{
    /* Native TAILQ_LAST/PREV reads the owner's previous_next at link+4,
     * then dereferences it. Preserve those reads, including malformed lists. */
    MmuBlock **previous = *(MmuBlock **volatile *)((uintptr_t)link + 4U);
    return *(MmuBlock *volatile *)previous;
}
static __inline__ __attribute__((always_inline)) unsigned int
mmu_reservation_bus(unsigned int start,unsigned int size)
{
    unsigned int last = start + size - 1U;
    if (start > 0x41ffffffU && last <= 0x43ffffffU)
        return 1;
    if (start > 0x3bffffffU && last <= 0x3dffffffU)
        return 8;
    abort();
}

/* Native entry: 0x4200fc58. */
/* Original function-byte SHA-256:
 * 1ad899fd0897df93aa2d7a0901710fa0a04e6c08f82432c0021091355c2d6920. */
/* Initialize the one-region MMU allocator from DROM descriptor0x3c0467e8.
 * Read size/start/end/bus/caps/targets; assert64KiB size alignment. Reserve the
 * linked IROM[0x42000020,0x4203a710) and DROM[0x3c040020,0x3c04826c) spans,
 * including first-page padding and upward64KiB rounding. Check virtual/linear
 * span agreement and abort on an unrecognized complete bus range.
 * Reservations test against the original region_size, including the second
 * reservation, then adjust free_head/max_slot_size with32-bit arithmetic.
 * Publish num_regions0 for caps0xffffffff, else1/copy40 bytes/reset TAILQ links.
 * For the actual descriptor this leaves free_head0x50000/max_slot0x1fb0000.
 * Leaves mutex untouched; repeated initialization loses prior block tracking
 * without freeing it or changing hardware mappings. No allocator or lock. */
void esp_mmu_map_init(void)
{
    const volatile MmuHardwareRegion *hardware = (const volatile MmuHardwareRegion *)0x3c0467e8U;
    unsigned int size = hardware->size;
    unsigned int start = hardware->start;
    unsigned int end = hardware->end;
    unsigned int bus = hardware->bus_id;
    unsigned int caps = hardware->caps;
    unsigned int targets = hardware->targets;
    MmuRegion region = {bus,start,end,size,start,size,caps,targets,NULL,NULL};
    if ((size & 0xffffU) != 0)
        __assert_func(NULL,0,NULL,NULL);

    unsigned int instruction_start = 0x42000020U;
    unsigned int instruction_end = 0x4203a710U;
    unsigned int instruction_size = instruction_end - instruction_start;
    if ((instruction_end & 0x1ffffffU) - (instruction_start & 0x1ffffffU) != instruction_size)
        __assert_func(NULL,0,NULL,NULL);
    unsigned int reserve = (instruction_size + (instruction_start & 0xffffU) + 0xffffU) & 0xffff0000U;
    unsigned int mask = mmu_reservation_bus(instruction_start,reserve);
    if ((bus & mask) != 0) {
        if (reserve >= size) {
            region.max_slot_size = 0;
            region.free_head = end;
        } else {
            region.free_head = start + reserve;
            region.max_slot_size = size - reserve;
        }
    }

    unsigned int data_start = 0x3c040020U;
    unsigned int data_end = 0x3c04826cU;
    unsigned int data_size = data_end - data_start;
    if ((data_end & 0x1ffffffU) - (data_start & 0x1ffffffU) != data_size)
        __assert_func(NULL,0,NULL,NULL);
    reserve = (data_size + (data_start & 0xffffU) + 0xffffU) & 0xffff0000U;
    mask = mmu_reservation_bus(data_start,reserve);
    if ((bus & mask) != 0) {
        if (reserve >= size) {
            region.max_slot_size = 0;
            region.free_head = end;
        } else {
            region.free_head += reserve;
            region.max_slot_size -= reserve;
        }
    }
    MMU_CONTEXT->num_regions = caps == 0xffffffffU ? 0 : 1;
    if (caps != 0xffffffffU) {
        memcpy((void *)&MMU_CONTEXT->regions[0],&region,40);
        MMU_CONTEXT->regions[0].blocks_first = NULL;
        MMU_CONTEXT->regions[0].blocks_last = (MmuBlock **)&MMU_CONTEXT->regions[0].blocks_first;
    }
    /* The final native region-count assertion is true by the branches above. */
}

/* Native entry: 0x4200fdc0. */
/* Original function-byte SHA-256:
 * 9f98f44a0aaa2058fd72ba1079103e22971283c8033b01749984728310aae83a. */
/* Return the compiled single region's maximum slot for matching caps/target.
 * NULL output or executable caps combined with0x14 logs/returns0x102 before
 * taking the lock. Otherwise write output0 before lock, then if num_regions is
 * nonzero and region0 masks contain every requested bit publish its max slot;
 * unmatched/empty context publishes0. Unlock and return0. No caps normalization,
 * region-array scan, target validation or hardware lookup occurs in this build. */
int esp_mmu_map_get_max_consecutive_free_block_size(unsigned int caps,unsigned int target,size_t *length)
{
    const char *format;
    unsigned int line;
    if (length == NULL) {
        format = "E (%lu) %s: %s(%d): null pointer\n";
        line = 0x116;
    } else if ((caps & 1U) != 0 && (caps & 0x14U) != 0) {
        format = "E (%lu) %s: %s(%d): invalid caps\n";
        line = 0x117;
    } else {
        *(volatile size_t *)length = 0;
        _lock_acquire(MMU_LOCK);
        unsigned int maximum = 0;
        if (MMU_CONTEXT->num_regions != 0) {
            unsigned int available_caps = MMU_CONTEXT->regions[0].caps;
            if ((available_caps & caps) == caps) {
                unsigned int available_targets = MMU_CONTEXT->regions[0].targets;
                if ((available_targets & target) == target)
                    maximum = MMU_CONTEXT->regions[0].max_slot_size;
            }
        }
        *(volatile size_t *)length = maximum;
        _lock_release(MMU_LOCK);
        return 0;
    }
    const char *tag = MMU_LOG_TAG;
    unsigned int timestamp = esp_log_timestamp();
    const char *format_tag = MMU_LOG_TAG;
    esp_log_write(1,tag,format,timestamp,format_tag,"esp_mmu_map_get_max_consecutive_free_block_size",line);
    return 0x102;
}

/* Native entry: 0x4200fe48. */
/* Original function-byte SHA-256:
 * 8a21e6053c4d675d3953f164b6f79da6f6b835d384df38d1e72a6f707a9fe9e4. */
/* Reserve a virtual span without creating a block or programming the MMU.
 * Reject NULL output or EXEC combined with0x14 caps using logged0x102. Round
 * size upward64KiB with32-bit wrap, scan cached num_regions at40-byte strides
 * for the first caps/target match with enough max_slot_size. Read free_head and
 * max_slot, advance/subtract rounded size, then publish free_head OR IROMbase
 *0x42000000 for EXEC, otherwise DROMbase0x3c000000. Failure logs only when the
 * early diagnostic gate is nonzero and returns0x105 without writing output.
 * No lock, target/size validity, rounding overflow, rollback or block tracking;
 * size0 or wrapped-to0 can reserve nothing and still report success. */
int esp_mmu_map_reserve_block_with_caps(size_t size,unsigned int caps,unsigned int target,const void **output)
{
    const char *format;
    unsigned int line;
    if (output == NULL) {
        format = "E (%lu) %s: %s(%d): null pointer\n";
        line = 0x13b;
    } else if ((caps & 1U) != 0 && (caps & 0x14U) != 0) {
        format = "E (%lu) %s: %s(%d): invalid caps\n";
        line = 0x13c;
    } else {
        unsigned int count = MMU_CONTEXT->num_regions;
        unsigned int aligned = (size + 0xffffU) & 0xffff0000U;
        for (unsigned int index = 0; index != count; ++index) {
            volatile MmuRegion *region = mmu_region_at(index);
            if ((region->caps & caps) == caps && (region->targets & target) == target &&
                region->max_slot_size >= aligned) {
                unsigned int start = region->free_head;
                unsigned int maximum = region->max_slot_size;
                region->free_head = start + aligned;
                region->max_slot_size = maximum - aligned;
                unsigned int base = (caps & 1U) != 0 ? 0x42000000U : 0x3c000000U;
                *(const void *volatile *)output = (const void *)(uintptr_t)(start | base);
                return 0;
            }
        }
        if (SYSTEM_EARLY_LOG_LEVEL != 0) {
            unsigned int timestamp = esp_log_timestamp();
            const char *tag = MMU_LOG_TAG;
            ets_printf("E (%lu) %s: no such vaddr range\n",timestamp,tag);
        }
        return 0x105;
    }
    const char *tag = MMU_LOG_TAG;
    unsigned int timestamp = esp_log_timestamp();
    const char *format_tag = MMU_LOG_TAG;
    esp_log_write(1,tag,format,timestamp,format_tag,"esp_mmu_map_reserve_block_with_caps",line);
    return 0x102;
}

/* Native entry: 0x4200ff28. */
/* Original function-byte SHA-256:
 * f1b6f74347e62bf1ca9499a6f3d21b99817b58d4d98d53a5ea7555778d8a32c0. */
/* Map an aligned physical range into the first eligible virtual region.
 * Reject NULL output, physical address not64KiB aligned, or EXEC with0x14 caps
 * using logged0x102. Lock, round size upward64KiB with32-bit wrap, and scan the
 * cached region count for caps/target subsets and enough maximum slot space.
 * No suitable region returns0x105. Empty lists receive calloc'd44-byte head/
 * tail sentinels. Check matching physical targets: enclosure publishes existing
 * virtual address plus offset and returns0x103 without new hardware mapping;
 * otherwise reject strict partial overlap unless flags bit0 allows sharing.
 * Allocate a block, choose the first sufficient gap, scan all remaining gaps
 * to recompute max_slot_size, insert before its following node, fill native
 * linear/physical/virtual fields and program hardware. EXEC selects IROM ORbase
 *0x42000000, otherwise DROM ORbase0x3c000000. Publish the live block virtual
 * address after the hardware helper and unlock, returning0.
 * Allocation failures return0x101. Cleanup frees newly allocated sentinels
 * without unlinking them, so failures after publication can leave dangling list
 * pointers. A missing gap despite cached capacity asserts while locked. Zero
 * or wrapped-to-zero size is accepted and can insert before the dummy head.
 * No target validation, physical-end overflow check, refcount, rollback or
 * hardware result check; outputs change on0 and0x103 only on normal paths. */
int esp_mmu_map(unsigned int address,size_t size,unsigned int target,unsigned int caps,
    int flags,void **output)
{
    const char *validation_format;
    unsigned int validation_line;
    if (output == NULL) {
        validation_format = "E (%lu) %s: %s(%d): null pointer\n";
        validation_line = 0x1d3;
    } else if ((address & 0xffffU) != 0) {
        validation_format = "E (%lu) %s: %s(%d): paddr must be rounded up to the nearest multiple of CONFIG_MMU_PAGE_SIZE\n";
        validation_line = 0x1d7;
    } else if ((caps & 1U) != 0 && (caps & 0x14U) != 0) {
        validation_format = "E (%lu) %s: %s(%d): invalid caps\n";
        validation_line = 0x1d8;
    } else {
        goto allocate;
    }
    {
        const char *tag = MMU_LOG_TAG;
        unsigned int timestamp = esp_log_timestamp();
        const char *format_tag = MMU_LOG_TAG;
        esp_log_write(1,tag,validation_format,timestamp,format_tag,"esp_mmu_map",validation_line);
    }
    return 0x102;

allocate:
    _lock_acquire(MMU_LOCK);
    unsigned int count = MMU_CONTEXT->num_regions;
    unsigned int aligned = (size + 0xffffU) & 0xffff0000U;
    unsigned int index;
    volatile MmuRegion *region = NULL;
    for (index = 0; index != count; ++index) {
        volatile MmuRegion *candidate = mmu_region_at(index);
        if ((candidate->caps & caps) == caps && (candidate->targets & target) == target &&
            candidate->max_slot_size >= aligned) {
            region = candidate;
            break;
        }
    }
    if (region == NULL) {
        const char *tag = MMU_LOG_TAG;
        unsigned int timestamp = esp_log_timestamp();
        const char *format_tag = MMU_LOG_TAG;
        esp_log_write(1,tag,"E (%lu) %s: %s(%d): no such vaddr range\n",timestamp,format_tag,"esp_mmu_map",0x1df);
        _lock_release(MMU_LOCK);
        return 0x105;
    }
    MmuBlock *block = region->blocks_first;
    MmuBlock *dummy_head = NULL;
    MmuBlock *dummy_tail = NULL;
    int result;
    if (block == NULL) {
        dummy_head = heap_caps_calloc(1,44,0x804);
        if (dummy_head == NULL) {
            const char *tag = MMU_LOG_TAG;
            unsigned int timestamp = esp_log_timestamp();
            const char *format_tag = MMU_LOG_TAG;
            esp_log_write(1,tag,"E (%lu) %s: %s(%d): no mem\n",timestamp,format_tag,"esp_mmu_map",0x1e7);
            _lock_release(MMU_LOCK);
            return 0x101;
        }
        volatile MmuBlock *head = dummy_head;
        unsigned int free_head = region->free_head;
        MmuBlock *first = region->blocks_first;
        head->linear_start = free_head;
        head->linear_end = free_head;
        head->size = 0;
        head->caps = caps;
        head->next = first;
        if (first != NULL)
            ((volatile MmuBlock *)first)->previous_next = &dummy_head->next;
        else
            region->blocks_last = &dummy_head->next;
        region = mmu_region_at(index);
        region->blocks_first = dummy_head;
        head->previous_next = (MmuBlock **)&region->blocks_first;

        dummy_tail = heap_caps_calloc(1,44,0x804);
        if (dummy_tail == NULL) {
            const char *tag = MMU_LOG_TAG;
            unsigned int timestamp = esp_log_timestamp();
            const char *format_tag = MMU_LOG_TAG;
            esp_log_write(1,tag,"E (%lu) %s: %s(%d): no mem\n",timestamp,format_tag,"esp_mmu_map",0x1f1);
            result = 0x101;
            goto discard_sentinels;
        }
        volatile MmuBlock *tail = dummy_tail;
        MmuBlock **previous_link = region->blocks_last;
        unsigned int end = region->end;
        tail->previous_next = previous_link;
        tail->linear_start = end;
        tail->linear_end = end;
        tail->size = 0;
        tail->caps = caps;
        tail->next = NULL;
        *(MmuBlock *volatile *)previous_link = dummy_tail;
        block = region->blocks_first;
        region->blocks_last = &dummy_tail->next;
    }
    unsigned int physical_end = address + aligned;
    while (block != NULL) {
        volatile MmuBlock *node = block;
        if (node->target == target) {
            unsigned int mapped_end = node->physical_end;
            unsigned int mapped_start = node->physical_start;
            if (mapped_end >= physical_end && mapped_start <= address) {
                unsigned int virtual_start = node->virtual_start;
                *(void *volatile *)output = (void *)(uintptr_t)(virtual_start - mapped_start + address);
                result = 0x103;
                goto discard_sentinels;
            }
            if (((unsigned int)flags & 1U) == 0 &&
                ((address < mapped_start && mapped_start < physical_end) ||
                 (address < mapped_end && mapped_end < physical_end))) {
                const char *tag = MMU_LOG_TAG;
                unsigned int timestamp = esp_log_timestamp();
                const char *format_tag = MMU_LOG_TAG;
                esp_log_write(1,tag,"E (%lu) %s: %s(%d): paddr block is overlapped with an already mapped paddr block\n",timestamp,format_tag,"esp_mmu_map",0x222);
                result = 0x102;
                goto discard_sentinels;
            }
        }
        block = node->next;
    }
    block = heap_caps_calloc(1,44,0x804);
    if (block == NULL) {
        const char *tag = MMU_LOG_TAG;
        unsigned int timestamp = esp_log_timestamp();
        const char *format_tag = MMU_LOG_TAG;
        esp_log_write(1,tag,"E (%lu) %s: %s(%d): no mem\n",timestamp,format_tag,"esp_mmu_map",0x227);
        result = 0x101;
        goto discard_sentinels;
    }
    region = mmu_region_at(index);
    MmuBlock *following = region->blocks_first;
    volatile MmuBlock *node = following;
    unsigned int previous_end = node->linear_end;
    unsigned int current_end = previous_end;
    unsigned int slot = node->linear_start - previous_end;
    unsigned int maximum = 0;
    volatile MmuBlock *allocated = block;
    while (true) {
        if (slot >= aligned) {
            MmuBlock *next = node->next;
            slot -= aligned;
            allocated->linear_start = previous_end;
            maximum = slot > maximum ? slot : maximum;
            while (next != NULL) {
                const volatile MmuBlock *remaining = next;
                unsigned int next_start = remaining->linear_start;
                unsigned int next_end = remaining->linear_end;
                unsigned int gap = next_start - current_end;
                next = remaining->next;
                maximum = gap > maximum ? gap : maximum;
                current_end = next_end;
            }
            break;
        }
        following = node->next;
        maximum = slot > maximum ? slot : maximum;
        if (following == NULL)
            __assert_func(NULL,0,NULL,NULL);
        node = following;
        unsigned int next_start = node->linear_start;
        previous_end = current_end;
        slot = next_start - current_end;
        current_end = node->linear_end;
    }
    MmuBlock **previous_link = node->previous_next;
    allocated->next = following;
    allocated->previous_next = previous_link;
    *(MmuBlock *volatile *)previous_link = block;
    unsigned int linear_start = allocated->linear_start;
    node->previous_next = &block->next;
    region->max_slot_size = maximum;
    unsigned int linear_end = linear_start + aligned;
    allocated->physical_end = address + aligned;
    allocated->linear_end = linear_end;
    allocated->size = aligned;
    allocated->caps = caps;
    allocated->physical_start = address;
    allocated->target = target;
    unsigned int base = (caps & 1U) != 0 ? 0x42000000U : 0x3c000000U;
    unsigned int virtual_address = linear_start | base;
    allocated->virtual_end = linear_end | base;
    allocated->virtual_start = virtual_address;
    mmu_map_region_with_cache(target,virtual_address,address,aligned);
    virtual_address = allocated->virtual_start;
    *(void *volatile *)output = (void *)(uintptr_t)virtual_address;
    _lock_release(MMU_LOCK);
    return 0;

discard_sentinels:
    if (dummy_tail != NULL)
        free(dummy_tail);
    if (dummy_head != NULL)
        free(dummy_head);
    _lock_release(MMU_LOCK);
    return result;
}

/* Native entry: 0x420102f8. */
/* Original function-byte SHA-256:
 * 16cd7f9ac9ee521a8a6f8198ba03a3101384409dd0fe34a144ec976a43915cd5. */
/* Remove a dynamically tracked mapping whose linear start matches address.
 * NULL logs/returns0x102. Otherwise lock and mask any address to25 linear bits;
 * only region0 is considered when num_regions is nonzero. Require free_head<=
 * linear<end, then traverse from head->next, excluding cached head and the tail
 * derived through native TAILQ link reads. Interior offsets do not match.
 * On match read previous/next boundaries, repair next.previous_next, update max
 * slot, reload current.previous_next, unlink, unmap hardware, free and unlock.
 * Outside/untracked ranges log/return0x105 after unlocking. Hardware unmapping
 * has no return status. No virtual-region/provenance validation, reference count,
 * empty-list sentinel cleanup or guard against corrupted neighbor links. */
int esp_mmu_unmap(void *address)
{
    if (address == NULL) {
        const char *tag = MMU_LOG_TAG;
        unsigned int timestamp = esp_log_timestamp();
        const char *format_tag = MMU_LOG_TAG;
        esp_log_write(1,tag,"E (%lu) %s: %s(%d): null pointer\n",timestamp,format_tag,"esp_mmu_unmap",0x28c);
        return 0x102;
    }
    _lock_acquire(MMU_LOCK);
    const char *format;
    unsigned int line;
    volatile MmuRegion *region = &MMU_CONTEXT->regions[0];
    if (MMU_CONTEXT->num_regions == 0)
        goto outside;
    unsigned int linear = (uintptr_t)address & 0x1ffffffU;
    if (linear < region->free_head || linear >= region->end)
        goto outside;
    MmuBlock *first = region->blocks_first;
    if (first != NULL) {
        MmuBlock **last_link = region->blocks_last;
        MmuBlock *block = first;
        while ((block = ((volatile MmuBlock *)block)->next) != NULL) {
            if (block == first || block == mmu_owner_of_next_link(last_link))
                continue;
            volatile MmuBlock *node = block;
            if (node->linear_start != linear)
                continue;
            MmuBlock **previous_link = node->previous_next;
            MmuBlock *next = node->next;
            MmuBlock **previous_previous_link =
                *(MmuBlock **volatile *)((uintptr_t)previous_link + 4U);
            unsigned int next_start = ((volatile MmuBlock *)next)->linear_start;
            MmuBlock *previous = *(MmuBlock *volatile *)previous_previous_link;
            unsigned int maximum = region->max_slot_size;
            unsigned int previous_end = ((volatile MmuBlock *)previous)->linear_end;
            ((volatile MmuBlock *)next)->previous_next = previous_link;
            unsigned int gap = next_start - previous_end;
            maximum = gap > maximum ? gap : maximum;
            previous_link = node->previous_next;
            unsigned int size = node->size;
            region->max_slot_size = maximum;
            unsigned int virtual_address = node->virtual_start;
            *(MmuBlock *volatile *)previous_link = next;
            mmu_unmap_region_with_cache(virtual_address,size);
            free(block);
            _lock_release(MMU_LOCK);
            return 0;
        }
    }
    format = "E (%lu) %s: %s(%d): munmap target pointer isn't mapped yet\n";
    line = 0x2b4;
    goto failure;
outside:
    format = "E (%lu) %s: %s(%d): munmap target pointer is outside external memory regions\n";
    line = 0x29c;
failure:
    {
        const char *tag = MMU_LOG_TAG;
        unsigned int timestamp = esp_log_timestamp();
        const char *format_tag = MMU_LOG_TAG;
        esp_log_write(1,tag,format,timestamp,format_tag,"esp_mmu_unmap",line);
    }
    _lock_release(MMU_LOCK);
    return 0x105;
}

/* Native entry: 0x420103f4. */
/* Original function-byte SHA-256:
 * d9be48899f4ad003bd8bf6d7c089d529e5258b2786f2dd6c74b9d9de74e96571. */
/* Translate one virtual address using MMU0. Require non-NULL address and
 * physical_address output; the target output is deliberately not checked.
 * Check a one-byte external DATA/INSTRUCTION region (type mask3); invalid inputs
 * log/return0x102. Initialize both local outputs0, lock, query HAL, unlock.
 * Unmapped HAL result logs/returns0x105. Otherwise publish physical address
 * first, then read/publish target and return0, so NULL target can fault after
 * physical output has changed. No requirement for dynamically tracked mappings,
 * buffer-size check, allocation or locking across final output stores. */
int esp_mmu_vaddr_to_paddr(void *address,unsigned int *physical_address,unsigned int *target)
{
    const char *format;
    unsigned int line;
    if (address == NULL || physical_address == NULL) {
        format = "E (%lu) %s: %s(%d): null pointer\n";
        line = 0x325;
        goto invalid;
    }
    if (!mmu_hal_check_valid_ext_vaddr_region(0,(uintptr_t)address,1,3)) {
        format = "E (%lu) %s: %s(%d): not a valid external virtual address\n";
        line = 0x326;
        goto invalid;
    }
    volatile unsigned int found_address = 0;
    volatile unsigned int found_target = 0;
    _lock_acquire(MMU_LOCK);
    bool mapped = mmu_hal_vaddr_to_paddr(0,(uintptr_t)address,
        (unsigned int *)&found_address,(unsigned int *)&found_target);
    _lock_release(MMU_LOCK);
    if (!mapped) {
        const char *tag = MMU_LOG_TAG;
        unsigned int timestamp = esp_log_timestamp();
        const char *format_tag = MMU_LOG_TAG;
        esp_log_write(1,tag,"E (%lu) %s: %s(%d): vaddr isn't mapped\n",timestamp,format_tag,"esp_mmu_vaddr_to_paddr",0x32c);
        return 0x105;
    }
    unsigned int physical = found_address;
    *(volatile unsigned int *)physical_address = physical;
    unsigned int memory_target = found_target;
    *(volatile unsigned int *)target = memory_target;
    return 0;
invalid:
    {
        const char *tag = MMU_LOG_TAG;
        unsigned int timestamp = esp_log_timestamp();
        const char *format_tag = MMU_LOG_TAG;
        esp_log_write(1,tag,format,timestamp,format_tag,"esp_mmu_vaddr_to_paddr",line);
    }
    return 0x102;
}
