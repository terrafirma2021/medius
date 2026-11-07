/* Medius v3.4.7 device — ESP-IDF cache HAL startup and saved autoload state. */
#include "../include/types.h"

/* Native entry: 0x403890d4. */
/* Original function-byte SHA-256:
 * cda9257e1eb92229038b6c452ea99b9681d4fce281b883ca0d042484528fc9e5. */
/* Snapshot autoload-enable bit2 from DCACHE, then ICACHE control, storing
 * BYTE booleans to the L1 data/instruction state slots. Read both hardware
 * controls again and populate L2 data/instruction context slots in the same
 * order. These SDK L2 slots reuse the same physical S3 controls; they are not
 * evidence of another cache controller. Each read retains its preceding
 * MEMW. Four independent reads may observe different values; do not replace
 * them with one cached pair or promise an atomic snapshot. No lock, register
 * write, allocation, cache enable or return value is supplied here. */
void s_cache_hal_init_ctx(void)
{
    memw();
    unsigned int control=CACHE_DATA_AUTOLOAD_CONTROL;
    CACHE_HAL_CONTEXT.l1.data_autoload_enabled=((control>>2)&1U)!=0U;
    memw();
    control=CACHE_INSTRUCTION_AUTOLOAD_CONTROL;
    CACHE_HAL_CONTEXT.l1.instruction_autoload_enabled=((control>>2)&1U)!=0U;
    memw();
    control=CACHE_DATA_AUTOLOAD_CONTROL;
    CACHE_HAL_CONTEXT.l2.data_autoload_enabled=((control>>2)&1U)!=0U;
    memw();
    control=CACHE_INSTRUCTION_AUTOLOAD_CONTROL;
    CACHE_HAL_CONTEXT.l2.instruction_autoload_enabled=((control>>2)&1U)!=0U;
}

/* Native entry: 0x40389110. */
/* Original function-byte SHA-256:
 * ce77cf22b0fe649b85df951daf4bdd8adb68e0454c708ea42e76c8198a2f73c2. */
/* Capture autoload state, read its L1 instruction BYTE then data BYTE before
 * either enable call, and pass each raw BYTE<<2 to ROM: enable ICACHE first,
 * DCACHE second. Raw-byte reads preserve the native shift even if state is
 * corrupted; a C bool read must not silently normalize it.
 *
 * Perform eight separate CTRL1 read/modify/write pairs, each with MEMW before
 * its read and write: I unchanged, D clear bit1, I clear bit0, D unchanged,
 * I unchanged, D clear bit0, I clear bit1, D unchanged. These are the compiled
 * per-core data/instruction bus-enabling operations, including zero-mask
 * operations. Do not remove unchanged writes or merge the sequence into one
 * mask per register. Final low2 shut-bus bits are clear in both controls.
 * No local lock, interrupt masking, cache invalidate, timeout or status return;
 * startup callers supply the required execution context. */
void cache_hal_init(void)
{
    s_cache_hal_init_ctx();
    unsigned int instruction_autoload=CACHE_AUTOLOAD_STATE.instruction_autoload_enabled;
    unsigned int data_autoload=CACHE_AUTOLOAD_STATE.data_autoload_enabled;
    Cache_Enable_ICache(instruction_autoload<<2);
    Cache_Enable_DCache(data_autoload<<2);
    volatile CacheBusControlRegisters *buses=(volatile CacheBusControlRegisters *)0x600c4000U;
    memw();
    unsigned int control=buses->icache_bus_control;
    memw();
    buses->icache_bus_control=control;
    memw();
    control=buses->dcache_bus_control;
    memw();
    buses->dcache_bus_control=control&0xfffffffdU;
    memw();
    control=buses->icache_bus_control;
    memw();
    buses->icache_bus_control=control&0xfffffffeU;
    memw();
    control=buses->dcache_bus_control;
    memw();
    buses->dcache_bus_control=control;
    memw();
    control=buses->icache_bus_control;
    memw();
    buses->icache_bus_control=control;
    memw();
    control=buses->dcache_bus_control;
    memw();
    buses->dcache_bus_control=control&0xfffffffeU;
    memw();
    control=buses->icache_bus_control;
    memw();
    buses->icache_bus_control=control&0xfffffffdU;
    memw();
    control=buses->dcache_bus_control;
    memw();
    buses->dcache_bus_control=control;
}
