/* Medius v3.4.7 device: ESP32-S3 MMU table access and cache coordination. */
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

/* Native entry: 0x4037db28. */
/* Original function-byte SHA-256:
 * ea2874c60161e8cb12cdd0b222bf3cf3bb11c9de5ba6a8a5d7e0a37d8c307432. */
/* Forward to cache freeze/interrupt-disable coordination. No local state,
 * arguments, timeout or status handling is added; its callee owns restoration. */
void mmu_freeze_cache(void)
{
    esp_cache_freeze_caches_disable_interrupts();
}

/* Native entry: 0x4037db30. */
/* Original function-byte SHA-256:
 * 41572758ca392b5cf33ee5565d9c09df11853bafe94f8ebc047a41ef5c6c4744. */
/* Enter the cache-sync critical section, invalidate the requested address/size,
 * discard the invalidate result, then exit. No extra range/NULL checks or status. */
void mmu_invalidate_cache_range(unsigned int virtual_address,unsigned int size)
{
    esp_cache_sync_ops_enter_critical_section();
    (void)cache_hal_invalidate_addr(virtual_address,size);
    esp_cache_sync_ops_exit_critical_section();
}

/* Native entry: 0x4037db44. */
/* Original function-byte SHA-256:
 * f7c97efd7410a4808ab76f4dec19fb17114cdc5361d3786568ae0c893f89d7b0. */
/* Forward to cache unfreeze/interrupt restoration; no local checks or result. */
void mmu_unfreeze_cache(void)
{
    esp_cache_unfreeze_caches_enable_interrupts();
}

/* Native entry: 0x4037db4c. */
/* Original function-byte SHA-256:
 * 950ae23f74d2dd670e939f934fa84ef41cf983044fad38628a2372fff762172d. */
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

/* Native entry: 0x4037dbfc. */
/* Original function-byte SHA-256:
 * 771a51ef3b5ba24dbd1385775d75563e22eee90bec2c1c570d1cc595dd0098d2. */
/* Freeze caches/interrupts, invalidate MMU0 entries for virtual address/size,
 * then unfreeze. No result, separate cache-range invalidate or rollback; an
 * abort in the HAL prevents the final unfreeze call. */
void mmu_unmap_region_with_cache(unsigned int virtual_address,unsigned int size)
{
    mmu_freeze_cache();
    mmu_hal_unmap_region(0,virtual_address,size);
    mmu_unfreeze_cache();
}

/* Native entry: 0x40389714. */
/* Original function-byte SHA-256:
 * 1dcbae1302a7d1c77ef377c2af3da52ec4fbdf2f2b9e46b897e41284309e70c1. */
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

/* Native entry: 0x4038979c. */
/* Original function-byte SHA-256:
 * f0c6fc2b45061d46675c34eb78b8d8355f58a26250daa3d474796e33e373b6d0. */
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

/* Native entry: 0x40389804. */
/* Original function-byte SHA-256:
 * 7d4d4c99f2223eb61a1a632882366b9ae89f25c3b9eee6e1fcb107b17c13e3f6. */
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

/* Native entry: 0x403898b4. */
/* Original function-byte SHA-256:
 * 30ccad5c8573d4eb059eedcb057e8016aea07f73ef56f0218e9b5d9beba0e2fd. */
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

/* Native entry: 0x42010618. */
/* Original function-byte SHA-256:
 * 7940ba3f351c8299bd5b243b4dd20a6490ccdae93e89c95f04086661ef797c74. */
/* Query largest free FLASH virtual span for INST memory1 (caps9), otherwise
 * DATA caps0x12. Initialize a local WORD0, ignore query status and return its
 * upper HALFWORD, equivalent to count of64KiB pages. This reports the largest
 * consecutive slot, not total free pages, and performs no reservation. */
unsigned int spi_flash_mmap_get_free_pages(unsigned int memory)
{
    unsigned int caps = memory == 1 ? 9U : 0x12U;
    volatile size_t size = 0;
    (void)esp_mmu_map_get_max_consecutive_free_block_size(caps,1,(size_t *)&size);
    return *(const volatile unsigned short *)((uintptr_t)&size + 2U);
}

/* Native entry: 0x42010638. */
/* Original function-byte SHA-256:
 * 7005829bd00394663c5cea9c6127c1e7f4eafd8bb189e3040e2470e7477fef48. */
/* Convert a cached address to physical bytes. NULL immediately returns0xffffffff.
 * Initialize local physical/target WORDs0, call the MMU translation API, return
 * physical on success or0xffffffff on any error. Discard target, so a PSRAM
 * physical address can be returned too. No own table read or alignment check. */
size_t spi_flash_cache2phys(const void *cached)
{
    if (cached == NULL)
        return 0xffffffffU;
    volatile unsigned int physical = 0;
    volatile unsigned int target = 0;
    int result = esp_mmu_vaddr_to_paddr((void *)cached,(unsigned int *)&physical,(unsigned int *)&target);
    if (result != 0)
        return 0xffffffffU;
    return physical;
}
