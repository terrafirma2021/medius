/* Medius v3.4.7 device: physical MMU lookups and cache forwarding. */
#include "../include/types.h"

/* Native entry: 0x4037dc14. */
/* Original function-byte SHA-256:
 * 006bb576f15ba05c13b352192ec49ef7c443b52db3520e575fea1eb484a07bd9. */
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

/* Native entry: 0x4037dcec. */
/* Original function-byte SHA-256:
 * 9fc9d251ef501afbed9c9178162528a5360b4cb650ddbed708f7dea849f414dc. */
/* Forward directly to external-memory cache suspension. No used parameters,
 * local status, lock, interrupt masking or saved-state output in this body. */
void flash_suspend_cache(void)
{
    esp_cache_suspend_ext_mem_cache();
}

/* Native entry: 0x4037dcfc. */
/* Original function-byte SHA-256:
 * 9fc9d251ef501afbed9c9178162528a5360b4cb650ddbed708f7dea849f414dc. */
/* Forward directly to external-memory cache resumption. The callee uses saved
 * HAL autoload state; this wrapper restores no interrupts or scheduler state. */
void flash_resume_cache(void)
{
    esp_cache_resume_ext_mem_cache();
}

/* Native entry: 0x40389854. */
/* Original function-byte SHA-256:
 * 9eeae9ea2203ab90db1950715b15d366eb36e2db1ac849a8083309ea61cff21d. */
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
