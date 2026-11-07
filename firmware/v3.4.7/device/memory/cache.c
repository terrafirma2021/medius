/* Medius v3.4.7 device — memory/cache.c.
 * Recovered C and native assembly, grouped for source navigation.
 * Original entry addresses, firmware-byte hashes and function comments follow.
 */

#include "../include/types.h"

/* reconstruction utilities: retain Xtensa REMU for a possible zero divisor. */
static __inline__ __attribute__((always_inline)) unsigned int
cache_native_unsigned_remainder(unsigned int dividend,unsigned int divisor)
{
    unsigned int remainder;
    __asm__ volatile ("remu %0,%1,%2" : "=a"(remainder) : "a"(dividend),"a"(divisor) : "memory");
    return remainder;
}

/* Native entry: 0x40375740. */
/*
 * Medius v3.4.7 — device application; 0x40375740.
 *
 * Updates the asymmetric instruction/data cache bus shut bits while preserving other live register bits.
 *
 * Calls: cache_hal_disable, cache_hal_enable.
 *
 * Called by: firmware_entry.
 *
 * Original function-byte SHA-256:
 * 59145116f129ccbaee7244db8a3bcc9ab38d2910f83e041a29ad7564f1833e06.
 */

/*
 * Returns: No value.
 * Requirements/effects: Reads I-cache CTRL1 before D-cache CTRL1, then disables both level-one
 *   caches. A saved zero I-cache bit 0 selects clearing live I-cache bit 1; a saved zero D-cache
 *   bit 1 selects clearing live D-cache bit 0. Preserves this asymmetric native mapping and every
 *   other live register bit. Reloads each control word before writing it, then enables both caches
 *   with the saved autoload state. Calls must execute from accessible internal memory; no lock or
 *   all-core handshake is implemented here.
 */

void do_multicore_settings(void)
{
    volatile CacheBusControlRegisters *registers =
        (volatile CacheBusControlRegisters *)0x600c4000U;

    memw();
    unsigned int saved_instruction = registers->icache_bus_control;
    memw();
    unsigned int saved_data = registers->dcache_bus_control;
    cache_hal_disable(1, CACHE_TYPE_ALL);

    /* Keep the native asymmetric mapping: I-cache bit 0 selects bit 1;
       D-cache bit 1 selects bit 0. This only enables the selected bus and
       never shuts a bus that was already enabled. */
    memw();
    unsigned int live_instruction = registers->icache_bus_control;
    unsigned int instruction_enable_mask = ((~saved_instruction) & 1U) << 1;
    memw();
    registers->icache_bus_control = live_instruction & ~instruction_enable_mask;

    memw();
    unsigned int live_data = registers->dcache_bus_control;
    unsigned int data_enable_mask = ((saved_data >> 1) & 1U) ^ 1U;
    memw();
    registers->dcache_bus_control = live_data & ~data_enable_mask;
    cache_hal_enable(1, CACHE_TYPE_ALL);
}

/* Native entry: 0x40385710. */
/*
 * Medius v3.4.7 — device application; 0x40385710.
 *
 * Suspends the external-memory cache by requesting level 1 and ALL (2), which visits the
 * instruction cache before the data cache. This S3 body performs no extra internal-cache
 * writeback and does not acquire a flash mutex or mask interrupts itself.
 *
 * Calls: cache_hal_suspend.
 *
 * Called by: spi_flash_disable_cache, FUN_4037dcec.
 *
 * Original function-byte SHA-256:
 * 5864bdd33f97434834c5f455594e09c58b32e36fd2eb0cd56880b931204f3bd4.
 */

/* Reference: ESP-IDF v5.4.4 components/esp_mm/esp_cache_utils.c. */

/*
 * Returns: Nothing; requests the level-1 instruction/data cache suspend sequence.
 * Requirements/effects: The caller must already arrange flash-operation exclusion and
 *   interrupt/scheduler safety. This wrapper takes no lock.
 */

void esp_cache_suspend_ext_mem_cache(void)
{
    cache_hal_suspend(1,CACHE_TYPE_ALL);
}

/* Native entry: 0x40385720. */
/*
 * Medius v3.4.7 — device application; 0x40385720.
 *
 * Resumes level-1 instruction and data caches through cache_hal_resume(1, ALL). The HAL uses
 * previously initialized autoload bytes; this wrapper does not restore interrupt masks, release
 * a mutex or resume scheduling.
 *
 * Calls: cache_hal_resume.
 *
 * Called by: spi_flash_restore_cache, FUN_4037dcfc.
 *
 * Original function-byte SHA-256:
 * 9faf6d73c21fefb7394d1a4de83a180c62a913ee149457d68618ba5e1d8933cf.
 */

/* Reference: ESP-IDF v5.4.4 components/esp_mm/esp_cache_utils.c. */

/*
 * Returns: Nothing; resumes both level-1 caches using the HAL autoload bytes.
 * Requirements/effects: Requires initialized HAL autoload state. The suspend wrapper does not
 *   update that state. Does not restore interrupt masks or scheduling.
 */

void esp_cache_resume_ext_mem_cache(void)
{
    cache_hal_resume(1,CACHE_TYPE_ALL);
}

/* Native entry: 0x40385d28. */
/*
 * Medius v3.4.7 — device application; 0x40385d28.
 *
 * Calls the original ROM instruction-cache suspend at 0x4000189c, preserves its 32-bit return,
 * then polls volatile EXTMEM_CACHE_STATE bits 11:0 until they equal 1. This is the SDK workaround
 * for the ROM cache-suspend WAITI bug. The busy wait has no timeout and does not yield.
 *
 * Calls: rom_Cache_Suspend_ICache.
 *
 * Called by: cache_hal_suspend.
 *
 * Original function-byte SHA-256:
 * f348b79137ca6e1063737aa51ff0b3655358f70af60ebf2c400d361e752b4b2a.
 */

/* Reference: ESP-IDF v5.4.4 components/esp_rom/patches/esp_rom_cache_esp32s2_esp32s3.c. ROM
   symbol/address verified against esp32s3.rom.ld; ROM body is external to this application image. */

/*
 * Returns: The unchanged 32-bit state value returned by the ROM instruction-cache suspend routine.
 * Requirements/effects: Busy-polls EXTMEM bits 11:0 for idle state 1 after the ROM call; no
 *   timeout or yield. Caller supplies exclusion.
 */

unsigned int Cache_Suspend_ICache(void)
{
    unsigned int rom_result = rom_Cache_Suspend_ICache();
    unsigned int cache_state;
    do {
        memw();
        cache_state = EXTMEM_CACHE_STATE;
    } while ((cache_state & 0xfffU) != 1U);
    return rom_result;
}

/* Native entry: 0x40385d44. */
/*
 * Medius v3.4.7 — device application; 0x40385d44.
 *
 * Calls the original ROM data-cache suspend at 0x400018b4, preserves its 32-bit return, then
 * polls volatile EXTMEM_CACHE_STATE bits 23:12 until they equal 1. This is the SDK workaround for
 * the ROM cache-suspend WAITI bug. The busy wait has no timeout and does not yield.
 *
 * Calls: rom_Cache_Suspend_DCache.
 *
 * Called by: cache_hal_suspend, firmware_entry.
 *
 * Original function-byte SHA-256:
 * 71448a1486c9cfdf63cda1be1ee7d63d726bc310b8012b5e067fc812d13238ba.
 */

/* Reference: ESP-IDF v5.4.4 components/esp_rom/patches/esp_rom_cache_esp32s2_esp32s3.c. ROM
   symbol/address verified against esp32s3.rom.ld; ROM body is external to this application image. */

/*
 * Returns: The unchanged 32-bit state value returned by the ROM data-cache suspend routine.
 * Requirements/effects: Busy-polls EXTMEM bits 23:12 for idle state 1 after the ROM call; no
 *   timeout or yield. Caller supplies exclusion.
 */

unsigned int Cache_Suspend_DCache(void)
{
    unsigned int rom_result = rom_Cache_Suspend_DCache();
    unsigned int cache_state;
    do {
        memw();
        cache_state = EXTMEM_CACHE_STATE;
    } while ((cache_state & 0x00fff000U) != 0x1000U);
    return rom_result;
}

/* Native entry: 0x4038919c. */
/*
 * Medius v3.4.7 — device application; 0x4038919c.
 *
 * Disables the selected level-one caches through ROM, aborting for any other cache level.
 *
 * Calls: Cache_Disable_ICache, Cache_Disable_DCache, abort.
 *
 * Called by: do_multicore_settings.
 *
 * Original function-byte SHA-256:
 * 5819b572c4dd123bbe4a3ca731ed7ce79ef6140e695698094066e53d2fd176be.
 */

/*
 * cache_level: Must equal 1; any other raw value calls abort before cache operations.
 * cache_type: DATA (0) disables D-cache; INSTRUCTION (1) disables I-cache; every other raw value
 *   disables I-cache then D-cache.
 * Returns: No value; invalid cache levels abort.
 * Requirements/effects: Calls the ESP32-S3 ROM disable entry points and ignores their returned
 *   autoload state. Supplies no lock, writeback, register restoration or timeout. Keep executing
 *   code and data accessible while the selected caches are disabled.
 */

void cache_hal_disable(unsigned int cache_level, CacheType cache_type)
{
    if (cache_level != 1)
        abort();

    /* Native default includes every raw value except DATA and INSTRUCTION. */
    if (cache_type != CACHE_TYPE_DATA) {
        Cache_Disable_ICache();
        if (cache_type == CACHE_TYPE_INSTRUCTION)
            return;
    }
    Cache_Disable_DCache();
}

/* Native entry: 0x403891c4. */
/*
 * Medius v3.4.7 — device application; 0x403891c4.
 *
 * Enables selected level-one caches using raw saved autoload bytes, with DATA snapshotted before INSTRUCTION.
 *
 * Calls: Cache_Enable_ICache, Cache_Enable_DCache, abort.
 *
 * Called by: do_multicore_settings.
 *
 * Original function-byte SHA-256:
 * a62603a4d17c6dd5c430f81181454c1af70539f6f708c56e2ae8a04f0a82ee90.
 */

/*
 * cache_level: Must equal 1; any other raw value calls abort before reading saved state.
 * cache_type: DATA (0), INSTRUCTION (1), or both caches for every other raw value.
 * Returns: No value; invalid cache levels abort.
 * Requirements/effects: Reads the saved DATA autoload byte first, including the instruction-only
 *   path. If requested, reads INSTRUCTION next and calls its ROM enable routine. DATA uses the
 *   original snapshot after that call. Each raw byte is shifted left by two without boolean
 *   normalization. No local lock or saved-state update is supplied.
 */

void cache_hal_enable(unsigned int cache_level, CacheType cache_type)
{
    if (cache_level != 1)
        abort();

    volatile CacheHalRawAutoloadState *state =
        &CACHE_AUTOLOAD_STATE;
    /* DATA is read first even for an instruction-only request. Its snapshot
       survives the instruction-cache ROM call. Preserve raw bytes, not bool
       normalization: the native operations shift each loaded byte by two. */
    unsigned int data_autoload = state->data_autoload_enabled;
    if (cache_type != CACHE_TYPE_DATA) {
        unsigned int instruction_autoload = state->instruction_autoload_enabled;
        Cache_Enable_ICache(instruction_autoload << 2);
        if (cache_type == CACHE_TYPE_INSTRUCTION)
            return;
    }
    Cache_Enable_DCache(data_autoload << 2);
}

/* Native entry: 0x403891fc. */
/*
 * Medius v3.4.7 — device application; 0x403891fc.
 *
 * Aborts unless cache_level is exactly 1. DATA (0) suspends only data cache, INSTRUCTION (1) only
 * instruction cache, and every other type follows the compiled default: instruction then data.
 * Each patched suspend helper waits for the corresponding idle state. No timeout or cache-type
 * range assertion is present.
 *
 * Calls: Cache_Suspend_ICache, Cache_Suspend_DCache, abort.
 *
 * Called by: FUN_4037eb34, esp_cache_suspend_ext_mem_cache.
 *
 * Original function-byte SHA-256:
 * da3c2a0479982c9fed626d7c2c9afde5a0339a6a5f80c5a4ba3e81bf5cd93309.
 */

/* Reference: ESP-IDF v5.4.4 components/hal/cache_hal.c and
   components/hal/esp32s3/include/hal/cache_ll.h. */

/*
 * cache_level: Hardware cache level; this ESP32-S3 build requires exactly 1 and aborts otherwise.
 * type: DATA selects data only, INSTRUCTION selects instruction only; every other value selects
 *   instruction then data.
 * Returns: Nothing. Invalid cache_level aborts without returning.
 * Requirements/effects: Stores no autoload state in this body; dispatches the patched suspend
 *   helpers and inherits their unbounded idle polling. Caller supplies synchronization.
 */

void cache_hal_suspend(unsigned int cache_level, CacheType type)
{
    if (cache_level != 1)
        abort();
    if (type != CACHE_TYPE_DATA) {
        (void)Cache_Suspend_ICache();
        if (type == CACHE_TYPE_INSTRUCTION)
            return;
    }
    (void)Cache_Suspend_DCache();
}

/* Native entry: 0x4038921c. */
/*
 * Medius v3.4.7 — device application; 0x4038921c.
 *
 * Aborts unless cache_level is 1, snapshots the saved data-autoload byte, and dispatches DATA
 * (0), INSTRUCTION (1), or the default instruction-then-data path. Passes each raw autoload byte
 * shifted by 2 to its ROM resume API. Does not sample hardware autoload afresh or use the return from a
 * suspend call as its saved state.
 *
 * Calls: Cache_Resume_ICache, Cache_Resume_DCache, abort.
 *
 * Called by: FUN_4037eb20, esp_cache_resume_ext_mem_cache.
 *
 * Original function-byte SHA-256:
 * 90f2e7b26028a14c798f9917ded85917b98b128a578d49196d07def1e4c8ef51.
 */

/* Reference: ESP-IDF v5.4.4 components/hal/cache_hal.c and
   components/hal/esp32s3/include/hal/cache_ll.h. */

/*
 * cache_level: Hardware cache level; this ESP32-S3 build requires exactly 1 and aborts otherwise.
 * type: DATA selects data only, INSTRUCTION selects instruction only; every other value selects
 *   instruction then data.
 * Returns: Nothing. Invalid cache_level aborts without returning.
 * Requirements/effects: Reads the saved DATA byte first, even for an instruction-only request.
 *   Reads INSTRUCTION next if requested; DATA retains the earlier snapshot across that ROM call.
 *   Shifts raw bytes by two without boolean normalization. The suspend body does not update these
 *   bytes. Caller supplies synchronization and initialized HAL state.
 */

void cache_hal_resume(unsigned int cache_level, CacheType type)
{
    if (cache_level != 1)
        abort();
    volatile CacheHalRawAutoloadState *state = &CACHE_AUTOLOAD_STATE;
    unsigned int data_autoload_enabled = state->data_autoload_enabled;
    if (type != CACHE_TYPE_DATA) {
        unsigned int instruction_autoload_enabled = state->instruction_autoload_enabled;
        Cache_Resume_ICache(instruction_autoload_enabled << 2);
        if (type == CACHE_TYPE_INSTRUCTION)
            return;
    }
    Cache_Resume_DCache(data_autoload_enabled << 2);
}

/* Native entry: 0x42002e98. */
/*
 * Medius v3.4.7 — device application; 0x42002e98.
 *
 * Routes and enables cache-illegal/access events on CPU interrupt 25 for the current core.
 *
 * Calls: esp_intr_enable_source, esp_intr_disable_source, intr_matrix_set.
 *
 * Called by: call_start_cpu1, firmware_entry.
 *
 * Original function-byte SHA-256:
 * 1702ca6ea42072f1b3796a796785dde7b603a9931c757ce14444762a8135c9bd.
 */

/*
 * Returns: No value.
 * Requirements/effects: Snapshots PRID bit 13, disables CPU interrupt 25, and routes shared
 *   illegal-cache source 56 to it. Reads/ORs/writes the illegal CLEAR word before ENABLE, using
 *   mask 0x3f. Routes core-0 source 94 or core-1 source 95 to interrupt 25, then reads/ORs/writes
 *   that core's CLEAR and ENABLE words with mask 0x1f. Re-enables interrupt 25. All other register
 *   bits and the other core's words are retained. CLEAR is a hardware event register: the
 *   recovered read/OR/write is preserved; ordinary-RAM tests do not simulate its physical write-
 *   one-to-clear effect. No C interrupt handler is registered here.
 */

void esp_cache_err_int_init(void)
{
    unsigned int core = (xtensa_read_prid() >> 13) & 1U;
    volatile CacheErrorRegisters *registers =
        (volatile CacheErrorRegisters *)0x600c40dcU;

    esp_intr_disable_source(25);
    intr_matrix_set(core, 56, 25);
    memw();
    unsigned int illegal_clear = registers->illegal.clear;
    memw();
    registers->illegal.clear = illegal_clear | 0x3fU;
    memw();
    unsigned int illegal_enable = registers->illegal.enable;
    memw();
    registers->illegal.enable = illegal_enable | 0x3fU;

    intr_matrix_set(core, 94U + core, 25);
    volatile CacheErrorEventRegisters *access = &registers->core[core];
    memw();
    unsigned int access_clear = access->clear;
    memw();
    access->clear = access_clear | 0x1fU;
    memw();
    unsigned int access_enable = access->enable;
    memw();
    access->enable = access_enable | 0x1fU;
    esp_intr_enable_source(25);
}

/* Native entry: 0x403854d8. */
/*
 * Medius v3.4.7 — device application; 0x403854d8.
 * Instruction-checked recovered C.
 * Original function-byte SHA-256:
 * 25e4c4833c3849a4fe02d5f2bbb5bd99a6ca1af54e4ba54e39afc5ffdb68d90f.
 */

/* Enter the cache-sync operations mux indefinitely after the ISR-context probe.
 * Both probe and lock status are discarded as native. Caller must pair exit;
 * this entry performs no cache operation, allocation or other-core handshake. */
void esp_cache_sync_ops_enter_critical_section(void)
{
    (void)xPortInIsrContext();
    (void)xPortEnterCriticalTimeout(CACHE_SYNC_LOCK,-1);
}

/* Native entry: 0x403854ec. */
/*
 * Medius v3.4.7 — device application; 0x403854ec.
 * Instruction-checked recovered C.
 * Original function-byte SHA-256:
 * 30dc053c0f813270742d661e94e983058c7fec4884786bf5e070db575cb658f4.
 */

/* Probe ISR context (discard result), then release the cache-sync mux. Requires
 * matching ownership/entry. No cache flush, status or interrupt enable here. */
void esp_cache_sync_ops_exit_critical_section(void)
{
    (void)xPortInIsrContext();
    vPortExitCritical(CACHE_SYNC_LOCK);
}

/* Native entry: 0x403856d4. */
/*
 * Medius v3.4.7 — device application; 0x403856d4.
 * Instruction-checked recovered C.
 * Original function-byte SHA-256:
 * b46973d34e993fd37e40fd4be47d09e975316508b8a0b8e2decbdd17d99627bb.
 */

/* Return required DATA cache-line alignment for heap capabilities. Only SPIRAM
 * bit10 selects external level1; otherwise request internal level0, whose S3
 * HAL returns0. Store unchecked writable output and return0. NULL output logs
 * the native cache/line281 diagnostic and returns ESP_ERR_INVALID_ARG0x102.
 * No validation of other capability bits, allocation or alignment rounding. */
int esp_cache_get_alignment(unsigned int heap_capabilities,size_t *alignment)
{
    if (!alignment) {
        unsigned int timestamp = esp_log_timestamp();
        esp_log_write(1,CACHE_LOG_TAG,"E (%lu) %s: %s(%d): null pointer\n",
                      timestamp,CACHE_LOG_TAG,"esp_cache_get_alignment",0x119);
        return 0x102;
    }
    *alignment = cache_hal_get_cache_line_size((heap_capabilities >> 10) & 1U,
                                              CACHE_TYPE_DATA);
    return 0;
}

/* Native entry: 0x40385730. */
/*
 * Medius v3.4.7 — device application; 0x40385730.
 * Instruction-checked recovered C.
 * Original function-byte SHA-256:
 * 01d27c7251dbe88697b6594bea8e306525f12fc645bc005cad2fd176e8d7548e.
 */

/* Freeze both level1 external-memory caches, instruction before data, with
 * native busy-ack mode0 and idle polling supplied by patched ROM wrappers.
 * No mux, interrupt masking, writeback or explicit other-core stall here. */
void esp_cache_freeze_ext_mem_cache(void)
{
    cache_hal_freeze(1,CACHE_TYPE_ALL);
}

/* Native entry: 0x40385740. */
/*
 * Medius v3.4.7 — device application; 0x40385740.
 * Instruction-checked recovered C.
 * Original function-byte SHA-256:
 * af35bce751b852630e85f8ce7cf8e4441131218255b5a5b9924dbb83ef8af7a6.
 */

/* Unfreeze level1 instruction then data cache. No mux, interrupt re-enable or
 * status; caller supplies pairing with freeze and accessible code/storage. */
void esp_cache_unfreeze_ext_mem_cache(void)
{
    cache_hal_unfreeze(1,CACHE_TYPE_ALL);
}

/* Native entry: 0x40385750. */
/*
 * Medius v3.4.7 — device application; 0x40385750.
 * Instruction-checked recovered C.
 * Original function-byte SHA-256:
 * 886e5db168884fb4b308f3a9f29dbc9b2d160d3ad3445e79f65787db04bb0d0b.
 */

/* Require current post-prologue SP in internal DRAM [3fc88000,3fcfffff] or RTC
 * fast DRAM [600fe000,600fffff], using unsigned32 range subtraction; else fatal
 * assert. These are address tests, not enormous decompiler stack allocations.
 * Probe ISR context, acquire freeze mux indefinitely, disable non-IRAM IRQs
 * on this CPU, then freeze instruction/data level1 caches in that order.
 * Retain mux until matching unfreeze/enable call. Lock/probe results ignored;
 * no timeout, writeback, rollback or explicit other-CPU stall in this body. */
void esp_cache_freeze_caches_disable_interrupts(void)
{
    unsigned int stack_address;
    __asm__ volatile ("mov %0,a1" : "=a"(stack_address));
    if (stack_address - 0x3fc88000U > 0x77fffU &&
        stack_address - 0x600fe000U > 0x1fffU)
        __assert_func(0,0,0,0);
    (void)xPortInIsrContext();
    (void)xPortEnterCriticalTimeout(CACHE_FREEZE_LOCK,-1);
    esp_intr_noniram_disable();
    cache_hal_freeze(1,CACHE_TYPE_ALL);
}

/* Native entry: 0x40385790. */
/*
 * Medius v3.4.7 — device application; 0x40385790.
 * Instruction-checked recovered C.
 * Original function-byte SHA-256:
 * 1bee588d3c209f2f546ed4150016181679a9aa7166e3e0260551c891c9f5a0f2.
 */

/* Unfreeze level1 instruction then data cache, restore non-IRAM IRQs through
 * the interrupt helper, probe ISR context, then release freeze mux. Requires
 * paired freeze/disable ownership. Ordering permits enabled IRQs before mux
 * release, as native; no independent pairing check or output status. */
void esp_cache_unfreeze_caches_enable_interrupts(void)
{
    cache_hal_unfreeze(1,CACHE_TYPE_ALL);
    esp_intr_noniram_enable();
    (void)xPortInIsrContext();
    vPortExitCritical(CACHE_FREEZE_LOCK);
}

/* Native entry: 0x40389358. */
/*
 * Medius v3.4.7 — device application; 0x40389358.
 * Instruction-checked recovered C.
 * Original function-byte SHA-256:
 * 31d66e25201bc842ae7e7959c2840a53efe9df613f57552a82283751b16f827c.
 */

/* Require level1 or abort. DATA0 freezes only D; INSTRUCTION1 only I; EVERY
 * other type value freezes I then D (native accepts noncanonical values).
 * Pass busy-ack mode0 to patched freeze wrappers, which poll hardware idle
 * indefinitely. No mux, state bookkeeping, callback or IRQ masking here. */
void cache_hal_freeze(unsigned int level,CacheType type)
{
    if (level != 1U)
        abort();
    if (type != CACHE_TYPE_DATA)
        Cache_Freeze_ICache_Enable(0);
    if (type != CACHE_TYPE_INSTRUCTION)
        Cache_Freeze_DCache_Enable(0);
}

/* Native entry: 0x4038937c. */
/*
 * Medius v3.4.7 — device application; 0x4038937c.
 * Instruction-checked recovered C.
 * Original function-byte SHA-256:
 * e6eb9e0f2e33320a3be4f327b2b644c5a99c41ec75e775db73b83a14ce21a1cd.
 */

/* Require level1 or abort. DATA0 unfreezes D only; INSTRUCTION1 I only; all
 * other values unfreeze I then D. Delegate to fixed ROM disable-freeze entries.
 * No idle polling, mux, prior-state restoration or status is supplied here. */
void cache_hal_unfreeze(unsigned int level,CacheType type)
{
    if (level != 1U)
        abort();
    if (type != CACHE_TYPE_DATA)
        Cache_Freeze_ICache_Disable();
    if (type != CACHE_TYPE_INSTRUCTION)
        Cache_Freeze_DCache_Disable();
}

/* Native entry: 0x403893a4. */
/*
 * Medius v3.4.7 — device application; 0x403893a4.
 * Instruction-checked recovered C.
 * Original function-byte SHA-256:
 * 5497f3af8d32f6b9ad082fc1e00c84e6b371de7c45df9b68e1d1c91a89a601fc.
 */

/* Unsigned level>1 aborts; internal level0 returns0 WITHOUT checking type.
 * External level1 queries ROM DATA0 or INSTRUCTION1 line size and forwards it;
 * other type (including ALL2) aborts. No lock, conversion or cached result. */
unsigned int cache_hal_get_cache_line_size(unsigned int level,CacheType type)
{
    if (level > 1U)
        abort();
    if (level == 0)
        return 0;
    if (type == CACHE_TYPE_DATA)
        return Cache_Get_DCache_Line_Size();
    if (type == CACHE_TYPE_INSTRUCTION)
        return Cache_Get_ICache_Line_Size();
    abort();
}

/* Native entry: 0x40385d68. */
/*
 * Medius v3.4.7 — device application; 0x40385d68.
 * Instruction-checked recovered C.
 * Original function-byte SHA-256:
 * 488993e5aecd414fa4beeba05cefa6421a67946c6850cde6b01c245c6e17f606.
 */

/* Forward mode unchanged to ROM I-cache freeze, then repeatedly MEMW/read
 * EXTMEM CACHE_STATE bits0..11 until exactly1 (idle). ESP-IDF ROM wait-idle
 * workaround. No timeout, scheduler delay, argument validation or mux here. */
void Cache_Freeze_ICache_Enable(unsigned int mode)
{
    rom_Cache_Freeze_ICache_Enable(mode);
    unsigned int state;
    do {
        memw();
        state = EXTMEM_CACHE_STATE;
    } while ((state & 0xfffU) != 1U);
}

/* Native entry: 0x40385d84. */
/*
 * Medius v3.4.7 — device application; 0x40385d84.
 * Instruction-checked recovered C.
 * Original function-byte SHA-256:
 * 11eff202781d07e8a6f131bf1db2c30ddbac8fab3b5ca9709f54cbd1db72cd9f.
 */

/* Forward mode unchanged to ROM D-cache freeze, then repeatedly MEMW/read
 * EXTMEM CACHE_STATE bits12..23 until field==1 (masked word==0x1000).
 * ESP-IDF ROM wait-idle workaround; no timeout, yield, validation or mux. */
void Cache_Freeze_DCache_Enable(unsigned int mode)
{
    rom_Cache_Freeze_DCache_Enable(mode);
    unsigned int state;
    do {
        memw();
        state = EXTMEM_CACHE_STATE;
    } while ((state & 0x00fff000U) != 0x1000U);
}

/* Native entry: 0x403854fc. */
/*
 * Medius v3.4.7 — device application; 0x403854fc.
 * Instruction-checked recovered C.
 * Original function-byte SHA-256:
 * 6955b03a34b67e2c611095735fae4c1edb005a33b209dde65e7631a10f530f80.
 */

/* Synchronize an external-memory range. Reject NULL address, unsigned32 end
 * overflow, both direction bits, both type bits or HAL-invalid range with
 * ESP_ERR_INVALID_ARG0x102. Early diagnostics are conditional on live log level.
 * Default flags select data C2M (writeback); M2C selects invalidate only.
 * Query line size even for UNALIGNED mode. Without UNALIGNED, native REMU tests
 * address then length (short circuit); zero divisor retains CPU behavior, not
 * invented C modulo semantics. M2C forbids UNALIGNED; C2M forbids instruction.
 * Hold cache-sync mux around each HAL operation with discarded ISR probes and
 * lock statuses. C2M may additionally invalidate with flag1, using a SEPARATE
 * critical section after writeback. Failed HAL operations assert AFTER unlock;
 * normal completion returns0. Unknown flag bits are ignored. No copy, address
 * rounding, per-task mutex, rollback, timeout or runtime coherence proof here.
 * Range/invalidate/writeback helpers have their own reviewed native entries. */
int esp_cache_msync(void *address,size_t length,unsigned int flags)
{
    unsigned int start = (unsigned int)address;
    if (!address) {
        if (SYSTEM_EARLY_LOG_LEVEL != 0) {
            unsigned int timestamp = esp_log_timestamp();
            ets_printf("E (%lu) %s: %s(%d): null pointer\n",timestamp,
                       CACHE_LOG_TAG,"esp_cache_msync",0x61);
        }
        return 0x102;
    }
    if (start + length < start) {
        if (SYSTEM_EARLY_LOG_LEVEL != 0) {
            unsigned int timestamp = esp_log_timestamp();
            ets_printf("E (%lu) %s: %s(%d): wrong size, total size overflow\n",timestamp,
                       CACHE_LOG_TAG,"esp_cache_msync",0x66);
        }
        return 0x102;
    }
    if ((flags & 0x0cU) == 0x0cU || (flags & 0x30U) == 0x30U) {
        if (SYSTEM_EARLY_LOG_LEVEL != 0) {
            unsigned int timestamp = esp_log_timestamp();
            ets_printf("E (%lu) %s: %s(%d): both C2M and M2C directions, or both data and instruction type are selected, you should only select one direction or one type\n",
                       timestamp,CACHE_LOG_TAG,"esp_cache_msync",0x6a);
        }
        return 0x102;
    }
    unsigned int cache_level = 0;
    unsigned int cache_id = 0;
    if (!cache_hal_vaddr_to_cache_level_id(start,length,&cache_level,&cache_id)) {
        if (SYSTEM_EARLY_LOG_LEVEL != 0) {
            unsigned int timestamp = esp_log_timestamp();
            ets_printf("E (%lu) %s: %s(%d): invalid addr or null pointer\n",timestamp,
                       CACHE_LOG_TAG,"esp_cache_msync",0x71);
        }
        return 0x102;
    }
    unsigned int instruction = flags & 0x20U;
    unsigned int line_size = cache_hal_get_cache_line_size(cache_level,
        instruction ? CACHE_TYPE_INSTRUCTION : CACHE_TYPE_DATA);
    if ((flags & 2U) == 0) {
        if (cache_native_unsigned_remainder(start,line_size) != 0 ||
            cache_native_unsigned_remainder(length,line_size) != 0) {
            if (SYSTEM_EARLY_LOG_LEVEL != 0) {
                unsigned int timestamp = esp_log_timestamp();
                ets_printf("E (%lu) %s: %s(%d): start address: 0x%lx, or the size: 0x%lx is(are) not aligned with cache line size (0x%lx)B\n",
                           timestamp,CACHE_LOG_TAG,"esp_cache_msync",0x7a,
                           start,length,line_size);
            }
            return 0x102;
        }
    } else if (flags & 8U) {
        if (SYSTEM_EARLY_LOG_LEVEL != 0) {
            unsigned int timestamp = esp_log_timestamp();
            ets_printf("E (%lu) %s: %s(%d): M2C direction doesn't allow ESP_CACHE_MSYNC_FLAG_UNALIGNED\n",
                       timestamp,CACHE_LOG_TAG,"esp_cache_msync",0x82);
        }
        return 0x102;
    }
    if ((flags & 8U) == 0) {
        if (instruction) {
            if (SYSTEM_EARLY_LOG_LEVEL != 0) {
                unsigned int timestamp = esp_log_timestamp();
                ets_printf("E (%lu) %s: %s(%d): C2M direction doesn't support instruction type\n",
                           timestamp,CACHE_LOG_TAG,"esp_cache_msync",0x8d);
            }
            return 0x102;
        }
        (void)xPortInIsrContext();
        (void)xPortEnterCriticalTimeout(CACHE_SYNC_LOCK,-1);
        bool valid = cache_hal_writeback_addr(start,length);
        (void)xPortInIsrContext();
        vPortExitCritical(CACHE_SYNC_LOCK);
        if (!valid)
            __assert_func(0,0,0,0);
        if ((flags & 1U) == 0)
            return 0;
    }
    (void)xPortInIsrContext();
    (void)xPortEnterCriticalTimeout(CACHE_SYNC_LOCK,-1);
    bool valid = cache_hal_invalidate_addr(start,length);
    (void)xPortInIsrContext();
    vPortExitCritical(CACHE_SYNC_LOCK);
    if (!valid)
        __assert_func(0,0,0,0);
    return 0;
}

/* Native entry: 0x4038928c. */
/*
 * Medius v3.4.7 — device application; 0x4038928c.
 * Instruction-checked recovered C.
 * Original function-byte SHA-256:
 * 203d7bf697a255ba6e92a5620eff4dbb6f30677c3962d1834b183e281811dde1.
 */

/* Validate start and inclusive last byte against one 32MiB S3 cache window:
 * instruction [42000000,43ffffff] first, else data [3c000000,3dffffff]. All
 * additions/subtractions wrap unsigned32, including start+length-base-1;
 * there is NO independent overflow or length>0 rejection. Zero length at the
 * window base fails; elsewhere it can pass. Large wrapping lengths can also
 * pass these endpoint tests. On success store level1 THEN cache_id0 and return
 * true; output pointers may alias (final word then0). NULL output or invalid
 * range returns false without stores. No MMIO, mapping lookup or cache op. */
bool cache_hal_vaddr_to_cache_level_id(unsigned int start,unsigned int length,
                                      unsigned int *level,unsigned int *cache_id)
{
    if (!level || !cache_id)
        return false;
    unsigned int last;
    if (start - 0x42000000U < 0x02000000U) {
        last = start + length - 0x42000000U - 1U;
    } else {
        if (start - 0x3c000000U >= 0x02000000U)
            return false;
        last = start + length - 0x3c000000U - 1U;
    }
    if (last >= 0x02000000U)
        return false;
    *(volatile unsigned int *)level = 1;
    *(volatile unsigned int *)cache_id = 0;
    return true;
}

/* Native entry: 0x403892dc. */
/*
 * Medius v3.4.7 — device application; 0x403892dc.
 * Instruction-checked recovered C.
 * Original function-byte SHA-256:
 * 0b32218607f7895b0526253686298325a72434a9abbf514aa658903e912c1714.
 */

/* S3 range admission uses start and start+length-1 in the SAME 32MiB IROM or
 * DROM window, with native unsigned32 wrap and no separate overflow/zero-size
 * test. For an admitted range call ROM Cache_Invalidate_Addr(start,length),
 * discard its status and return true. Otherwise return false with no call.
 * No rounding, mux, IRQ masking, cache mapping validation or writeback here. */
bool cache_hal_invalidate_addr(unsigned int start,unsigned int length)
{
    unsigned int last;
    if (start - 0x42000000U < 0x02000000U) {
        last = start + length - 0x42000000U - 1U;
    } else {
        if (start - 0x3c000000U >= 0x02000000U)
            return false;
        last = start + length - 0x3c000000U - 1U;
    }
    if (last >= 0x02000000U)
        return false;
    (void)Cache_Invalidate_Addr(start,length);
    return true;
}

/* Native entry: 0x4038931c. */
/*
 * Medius v3.4.7 — device application; 0x4038931c.
 * Instruction-checked recovered C.
 * Original function-byte SHA-256:
 * 4b470ec28af14baf9a359362c7853a173ab8561506ea7cbfc3b50c3052cfb3b3.
 */

/* Admit start and inclusive last byte in the same S3 IROM/DROM 32MiB window,
 * using modulo32 endpoint tests, no independent overflow/zero-size rejection.
 * Call the patched Cache_WriteBack_Addr with ORIGINAL start/length and ignore
 * its result, returning true on admission or false without a call on rejection.
 * This wrapper adds no lock, IRQ mask, alignment rounding or mapping lookup. */
bool cache_hal_writeback_addr(unsigned int start,unsigned int length)
{
    unsigned int last;
    if (start - 0x42000000U < 0x02000000U) {
        last = start + length - 0x42000000U - 1U;
    } else {
        if (start - 0x3c000000U >= 0x02000000U)
            return false;
        last = start + length - 0x3c000000U - 1U;
    }
    if (last >= 0x02000000U)
        return false;
    (void)Cache_WriteBack_Addr(start,length);
    return true;
}

/* Native entry: 0x40385da8. */
/*
 * Medius v3.4.7 — device application; 0x40385da8.
 * Instruction-checked recovered C.
 * Original function-byte SHA-256:
 * 611580e63dfcfd7f06d62dfe997f3f02bf41856ca8e882f598316bb973273f3f.
 */

/* S3 ROM writeback workaround. Query D-cache line size even when length0,
 * then return0 for empty work. For an unaligned start, round up using native
 * (start-1+line)&(-line), reduce remaining length with unsigned comparison,
 * mask IRQs via RSIL7, freeze/write back ONE line at ORIGINAL start, restore
 * the complete saved PS with WSR/RSYNC, then return0 if nothing remains.
 * Handle unaligned end similarly at end&(-line), retaining modulo32 address/
 * length arithmetic. For aligned middle, suspend D-cache autoload, call ROM
 * writeback, restore the saved autoload word and return ROM status unchanged.
 * Partial-line-only completion returns0. No line-size/range/overflow check,
 * per-call mux or timeout; input/ROM state must satisfy the hardware contract. */
int Cache_WriteBack_Addr(unsigned int start,unsigned int length)
{
    unsigned int line_size = Cache_Get_DCache_Line_Size();
    if (length == 0)
        return 0;
    unsigned int mask = line_size - 1U;
    unsigned int end = start + length;
    if ((start & mask) != 0) {
        unsigned int aligned_start = (start - 1U + line_size) & (0U - line_size);
        unsigned int prefix = aligned_start - start;
        length = length < prefix ? 0 : end - aligned_start;
        unsigned int previous_ps;
        __asm__ volatile ("rsil %0,7" : "=a"(previous_ps) : : "memory");
        cache_writeback_items_freeze(start,1);
        __asm__ volatile ("wsr %0,PS\nrsync" : : "a"(previous_ps) : "memory");
        if (length == 0)
            return 0;
        start = aligned_start;
    }
    if ((end & mask) != 0) {
        unsigned int aligned_end = end & (0U - line_size);
        length = aligned_end - start;
        unsigned int previous_ps;
        __asm__ volatile ("rsil %0,7" : "=a"(previous_ps) : : "memory");
        cache_writeback_items_freeze(aligned_end,1);
        __asm__ volatile ("wsr %0,PS\nrsync" : : "a"(previous_ps) : "memory");
        if (length == 0)
            return 0;
    }
    unsigned int autoload = Cache_Suspend_DCache_Autoload();
    int result = rom_Cache_WriteBack_Addr(start,length);
    Cache_Resume_DCache_Autoload(autoload);
    return result;
}

/* Native entry: 0x40385e30. */
/*
 * Medius v3.4.7 — device application; 0x40385e30.
 * Instruction-checked recovered C.
 * Original function-byte SHA-256:
 * 1f34ca49808fa6b5038cc5d812080a2484c720d7d10263a3cbc0d25b6d465441.
 */

/* Register-only S3 erratum workaround; caller has masked IRQs and supplies a
 * cache-line start and line count (not byte length). Program SYNC_ADDR/SIZE,
 * MEMW, clear freeze MODE1 and set ENA0, then poll DONE2. Set writeback ENA1
 * in SYNC_CTRL and poll DONE3; clear freeze ENA0 and wait for DONE2 to clear.
 * Poll barriers occur AFTER each read; no timeout, status, size/range validation
 * or interrupt restoration. The freeze mode is left0, not restored.
 * Preserve the SDK leaf assembly: no stack/literal access after freezing, only
 * A2..A5. Compiler supplies the windowed ENTRY32/RETW; actual output is checked
 * instruction-for-instruction against the native leaf, including loop order.
 * MMIO offsets correspond to CacheWritebackRegisters below the base+0x28
 * window. Ordinary compiler-generated C loads/spills are unsafe while frozen. */
void cache_writeback_items_freeze(unsigned int address,unsigned int items)
{
    register unsigned int address_or_freeze __asm__("a2") = address;
    register unsigned int items_or_sync __asm__("a3") = items;
    __asm__ volatile (
        /* Stage the address and item count before the cache freeze. */
        "movi a4,0x600c402c\n"
        "s32i %0,a4,0\n"
        "movi a4,0x600c4030\n"
        "s32i %1,a4,0\n"
        "memw\n"
        "movi %0,0x600c4150\n"
        "movi %1,0x600c4028\n"
        /* Freeze in busy mode; await freeze acknowledgement. */
        "l32i a4,%0,0\n"
        "movi a5,-3\n"
        "and a4,a4,a5\n"
        "movi a5,1\n"
        "or a4,a4,a5\n"
        "s32i a4,%0,0\n"
        "movi a5,4\n"
        "1: l32i a4,%0,0\n"
        "memw\n"
        "bnone a4,a5,1b\n"
        /* Request writeback; await sync completion. */
        "l32i a4,%1,0\n"
        "movi a5,2\n"
        "or a4,a4,a5\n"
        "s32i a4,%1,0\n"
        "movi a5,8\n"
        "2: l32i a4,%1,0\n"
        "memw\n"
        "bnone a4,a5,2b\n"
        /* Unfreeze; await acknowledgement falling. */
        "l32i a4,%0,0\n"
        "movi a5,-2\n"
        "and a4,a4,a5\n"
        "s32i a4,%0,0\n"
        "movi a5,4\n"
        "3: l32i a4,%0,0\n"
        "memw\n"
        "bany a4,a5,3b\n"
        : "+a"(address_or_freeze),"+a"(items_or_sync) : : "a4","a5","memory");
}
