/* Medius v3.4.7 host: ESP32-S3 MMU table access and cache coordination. */
#include "../include/types.h"

/* Inline reconstruction utilities for native inlined MMU operations.
 * No additional firmware entry points are represented here. */
static __inline__ __attribute__((always_inline)) bool
mmu_external_range(unsigned int address,unsigned int length,unsigned int type)
{
    unsigned int last = address + length - 1U;
    if ((type & 2U) != 0 && address - 0x42000000U < 0x2000000U)
        return last - 0x42000000U < 0x2000000U;
    if ((type & 1U) != 0 && address - 0x3c000000U < 0x2000000U)
        return last - 0x3c000000U < 0x2000000U;
    return false;
}
static __inline__ __attribute__((always_inline)) volatile unsigned int *
mmu_table_entry(unsigned int virtual_address)
{
    unsigned int index = (virtual_address >> 16) & 0x1ffU;
    return (volatile unsigned int *)(0x600c5000U + index * 4U);
}
static __inline__ __attribute__((always_inline)) void mmu_memory_barrier(void)
{
    __asm__ volatile ("memw" ::: "memory");
}

/* Native entry: 0x4037c290. */
/* Original function-byte SHA-256:
 * 2563b0d8cf03a7d1feda86b7860283d47e10c089e58987ee9e18773d74194d45. */
/* Forward to cache freeze/interrupt-disable coordination. No local state,
 * arguments, timeout or status handling is added; its callee owns restoration. */
void mmu_freeze_cache(void)
{
    esp_cache_freeze_caches_disable_interrupts();
}

/* Native entry: 0x4037c298. */
/* Original function-byte SHA-256:
 * cda73fc29beb985d4f3fe485c2454554a5b2fd40274b9e30019c2b4e57cc9c14. */
/* Enter the cache-sync critical section, invalidate the requested address/size,
 * discard the invalidate result, then exit. No extra range/NULL checks or status. */
void mmu_invalidate_cache_range(unsigned int virtual_address,unsigned int size)
{
    esp_cache_sync_ops_enter_critical_section();
    (void)cache_hal_invalidate_addr(virtual_address,size);
    esp_cache_sync_ops_exit_critical_section();
}

/* Native entry: 0x4037c2ac. */
/* Original function-byte SHA-256:
 * 67e9822d57a9c2a25f0a5ef5170b4f57e0feb7e04a43f5ed90fcd5f974a4dbbe. */
/* Forward to cache unfreeze/interrupt restoration; no local checks or result. */
void mmu_unfreeze_cache(void)
{
    esp_cache_unfreeze_caches_enable_interrupts();
}

/* Native entry: 0x4037c2b4. */
/* Original function-byte SHA-256:
 * 683d905441076588d45d124288756f523e7af2535999ba6a0812ccb81fcf49e6. */
/* Freeze caches/interrupts, initialize a local mapped length0 and map through
 * MMU0. Ignore the resulting mapped length. Then classify the requested full
 * virtual range; invalid range aborts without cache restoration. Enable IROM
 * instruction buses core0 then1, or DROM data buses core1 then0. Retain all four
 * read/modify/write operations, including no-op masks on the other cache, with
 * eight explicit MEMW barriers. Invalidate requested virtual range and unfreeze.
 * Uses requested size for range/cache operations, not the HAL-rounded size.
 * No returned hardware status, rollback, lock ownership check or cleanup on abort. */
void mmu_map_region_with_cache(unsigned int target,unsigned int virtual_address,
    unsigned int physical_address,unsigned int size)
{
    mmu_freeze_cache();
    volatile unsigned int mapped_length = 0;
    mmu_hal_map_region(0,target,virtual_address,physical_address,size,(unsigned int *)&mapped_length);
    unsigned int last = virtual_address + size - 1U;
    unsigned int first_instruction_mask,first_data_mask,second_instruction_mask,second_data_mask;
    if (virtual_address > 0x41ffffffU && last <= 0x43ffffffU) {
        first_instruction_mask = 0xfffffffeU;
        first_data_mask = 0xffffffffU;
        second_instruction_mask = 0xfffffffdU;
        second_data_mask = 0xffffffffU;
    } else if (virtual_address > 0x3bffffffU && last <= 0x3dffffffU) {
        first_instruction_mask = 0xffffffffU;
        first_data_mask = 0xfffffffdU;
        second_instruction_mask = 0xffffffffU;
        second_data_mask = 0xfffffffeU;
    } else {
        abort();
    }
    volatile unsigned int *instruction_control = (volatile unsigned int *)0x600c4064U;
    volatile unsigned int *data_control = (volatile unsigned int *)0x600c4004U;
    mmu_memory_barrier();
    unsigned int control = *instruction_control;
    mmu_memory_barrier();
    *instruction_control = control & first_instruction_mask;
    mmu_memory_barrier();
    control = *data_control;
    mmu_memory_barrier();
    *data_control = control & first_data_mask;
    mmu_memory_barrier();
    control = *instruction_control;
    mmu_memory_barrier();
    *instruction_control = control & second_instruction_mask;
    mmu_memory_barrier();
    control = *data_control;
    mmu_memory_barrier();
    *data_control = control & second_data_mask;
    mmu_invalidate_cache_range(virtual_address,size);
    mmu_unfreeze_cache();
}

/* Native entry: 0x4037c364. */
/* Original function-byte SHA-256:
 * 8919fa14ba9797569f3a7dd689ede7f1c97aa7e3a012d439354b6d6dadea6f0f. */
/* Freeze caches/interrupts, invalidate MMU0 entries for virtual address/size,
 * then unfreeze. No result, separate cache-range invalidate or rollback; an
 * abort in the HAL prevents the final unfreeze call. */
void mmu_unmap_region_with_cache(unsigned int virtual_address,unsigned int size)
{
    mmu_freeze_cache();
    mmu_hal_unmap_region(0,virtual_address,size);
    mmu_unfreeze_cache();
}

/* Native entry: 0x40384694. */
/* Original function-byte SHA-256:
 * 3b4e87ddb1ac2864be5eee3ee9cac869f968a9ffaaf7f9e654564559e269fa7c. */
/* Program64KiB MMU pages. Ignore mmu ID; assert virtual/physical alignment,
 * physical start/length/last below1GiB and requested virtual endpoints wholly
 * within IROM or DROM. All endpoint/rounding arithmetic wraps32 bits. Abort on
 * validation failure. Publish rounded mapped_length before table writes; NULL
 * output is not checked. Round page count from wrapping(length+0xffff)>>16.
 * Each write selects the low9 virtual-page bits at table0x600c5000 and stores
 * incrementing physical page OR target bit15 (clear only for FLASH0 target1).
 * Other target values all select PSRAM. No explicit MEMW, cache coordination,
 * existing-entry check, write verification or target validation here. */
void mmu_hal_map_region(unsigned int mmu,unsigned int target,unsigned int virtual_address,
    unsigned int physical_address,unsigned int length,unsigned int *mapped_length)
{
    (void)mmu;
    if (((virtual_address | physical_address) & 0xffffU) != 0)
        abort();
    unsigned int last_physical = physical_address + length - 1U;
    if ((last_physical | physical_address | length) > 0x3fffffffU)
        abort();
    if (!mmu_external_range(virtual_address,length,3))
        abort();
    unsigned int page = physical_address >> 16;
    unsigned int count = (length + 0xffffU) >> 16;
    *(volatile unsigned int *)mapped_length = count << 16;
    unsigned int target_bits = target == 1 ? 0 : 0x8000U;
    while (count != 0) {
        *mmu_table_entry(virtual_address) = page | target_bits;
        virtual_address += 0x10000U;
        ++page;
        --count;
    }
}

/* Native entry: 0x4038471c. */
/* Original function-byte SHA-256:
 * 67a0a2984f0464ba4da252df2caf48964641e8035574c1f5f2ca668adbb940cf. */
/* Invalidate64KiB MMU pages by storing0x4000 per table entry. Ignore mmu ID;
 * abort for unaligned virtual start or invalid requested IROM/DROM endpoints.
 * Round count using wrapping(length+0xffff)>>16; zero count performs no writes.
 * The table index uses only9 page bits. No explicit barriers, cache coordination,
 * previous target/value check, returned count or write verification is supplied. */
void mmu_hal_unmap_region(unsigned int mmu,unsigned int virtual_address,unsigned int length)
{
    (void)mmu;
    if ((virtual_address & 0xffffU) != 0)
        abort();
    if (!mmu_external_range(virtual_address,length,3))
        abort();
    unsigned int count = (length + 0xffffU) >> 16;
    while (count != 0) {
        *mmu_table_entry(virtual_address) = 0x4000;
        virtual_address += 0x10000U;
        --count;
    }
}

/* Native entry: 0x40384784. */
/* Original function-byte SHA-256:
 * 6912071311188137b707686767bc37e75f3e0610bba97f45000cceb1ed510e7c. */
/* Translate through one raw MMU table WORD. Ignore mmu ID and abort unless the
 * address lies in IROM[0x42000000,0x44000000) or DROM[0x3c000000,0x3e000000).
 * Bit14 set returns false with outputs untouched. Otherwise target bit15 selects
 * PSRAM2 or FLASH1; store target first, then physical=(entry.low14<<16)|offset16,
 * return true. Aliased outputs therefore finish with the physical value. No
 * output NULL checks, lock, cache work, MEMW or second table read. */
bool mmu_hal_vaddr_to_paddr(unsigned int mmu,unsigned int address,
    unsigned int *physical_address,unsigned int *target)
{
    (void)mmu;
    if (address - 0x42000000U >= 0x2000000U && address - 0x3c000000U >= 0x2000000U)
        abort();
    unsigned int entry = *mmu_table_entry(address);
    if ((entry & 0x4000U) != 0)
        return false;
    unsigned int memory_target = (entry & 0x8000U) != 0 ? 2U : 1U;
    *(volatile unsigned int *)target = memory_target;
    unsigned int physical = ((entry & 0x3fffU) << 16) | (address & 0xffffU);
    *(volatile unsigned int *)physical_address = physical;
    return true;
}

/* Native entry: 0x40384834. */
/* Original function-byte SHA-256:
 * f88c548cde2540986b4d47eb4e75ca322a92d7f7fdc86cc54e9acf40a2fcc6c3. */
/* Test requested virtual endpoints only; ignore mmu ID. Type bit1 enables
 * IROM and bit0 DROM, with32MiB windows. Compute last=address+length-1 modulo32;
 * no length0/overflow rejection. An instruction-window start returns its end
 * test directly; otherwise try data. No table lookup, output, mapping ownership,
 * permission check, synchronization or hardware state read is performed. */
bool mmu_hal_check_valid_ext_vaddr_region(unsigned int mmu,unsigned int address,
    unsigned int length,unsigned int type_mask)
{
    (void)mmu;
    return mmu_external_range(address,length,type_mask);
}

/* Native entry: 0x403847d4. */
/* Original function-byte SHA-256:
 * 58bb298762258ee51b0e59c9c0ca277b154448d023cd73e1b0484692c4c2eaed. */
/* Ignore mmu selector. Abort if physical_address exceeds0x3fffffff, then scan
 * all512 table WORDs in ascending index at0x600c5000. Skip bit14-invalid slots,
 * require target1 for bit15 clear or target2 for set, and compare14-bit page.
 * On the first match OR index<<16, physical low16 and DATA base0x3c000000 when
 * type==1, otherwise INST base0x42000000. Store output and returntrue; a miss
 * returnsfalse without touching output. NULL output is unchecked and faults
 * only on a match. No lock, explicit MEMW, bus-enable or region-range check;
 * the selected virtual alias is returned even when its cache bus is disabled. */
bool mmu_hal_paddr_to_vaddr(unsigned int mmu,unsigned int physical_address,
    unsigned int target,unsigned int type,unsigned int *virtual_address)
{
    (void)mmu;
    if (physical_address > 0x3fffffffU)
        abort();
    const volatile unsigned int *table = (const volatile unsigned int *)0x600c5000U;
    unsigned int page = physical_address >> 16;
    for (unsigned int index = 0; index < 512; ++index) {
        unsigned int entry = table[index];
        if ((entry & 0x4000U) != 0)
            continue;
        unsigned int entry_target = (entry & 0x8000U) == 0 ? 1U : 2U;
        if (target != entry_target || page != (entry & 0x3fffU))
            continue;
        unsigned int base = type == 1 ? 0x3c000000U : 0x42000000U;
        *virtual_address = (physical_address & 0xffffU) | (index << 16) | base;
        return true;
    }
    return false;
}

/* Native entry: 0x4037c37c. */
/* Original function-byte SHA-256:
 * 0874124999613a780e0b82180f4c770e11ad91a4b4ba2f2afaf0183f1e7281e2. */
/* Find capabilities of a tracked block containing physical_address, without a
 * lock or target filter. NULL output returns0x102. Uninitialized/empty context
 * or no match returns0x105 without changing output. Only region0 is inspected,
 * even if num_regions is larger. Cache its first node and tail-next-link once;
 * advance before testing, skip both dummy nodes and compare [start,end).
 * Native TAILQ_LAST dereferences tail_link+4 and then that pointer on each
 * candidate. Corrupt lists can fault or cycle. Return0 and store caps on match. */
int esp_mmu_paddr_find_caps(unsigned int physical_address,unsigned int *caps)
{
    if (caps == NULL)
        return 0x102;
    if (MMU_CONTEXT->num_regions == 0)
        return 0x105;
    MmuBlock *first = MMU_CONTEXT->regions[0].blocks_first;
    if (first == NULL)
        return 0x105;
    MmuBlock **tail_link = MMU_CONTEXT->regions[0].blocks_last;
    volatile MmuBlock *block = first;
    for (;;) {
        block = block->next;
        if (block == NULL)
            return 0x105;
        if (block == first)
            continue;
        MmuBlock **previous_link =
            *(MmuBlock **volatile *)((uintptr_t)tail_link + 4U);
        if (block == *(MmuBlock *volatile *)previous_link)
            continue;
        if (physical_address < block->physical_start || physical_address >= block->physical_end)
            continue;
        *caps = block->caps;
        return 0;
    }
}
