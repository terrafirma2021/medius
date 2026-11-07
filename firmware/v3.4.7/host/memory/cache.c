/* Medius v3.4.7 host — memory/cache.c.
 * Recovered C and native assembly, grouped for source navigation.
 * Original entry addresses, firmware-byte hashes and function comments follow.
 */

#include "../include/types.h"

/* Native entry: 0x4037534c. */
/*
 * Medius v3.4.7 — host application; 0x4037534c.
 *
 * Enables selected second-core cache buses from saved startup masks while preserving live register bits.
 *
 * Calls: cache_hal_disable, cache_hal_enable.
 *
 * Called by: firmware_entry.
 *
 * Original function-byte SHA-256:
 * 80a22daedca6345e20aff2e8d0b43e55d30b2656a78c75db8cc7114f0b34dc00.
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
    uint saved_instruction = registers->icache_bus_control;
    memw();
    uint saved_data = registers->dcache_bus_control;
    cache_hal_disable(1, CACHE_TYPE_ALL);

    /* Keep the native asymmetric mapping: I-cache bit 0 selects bit 1;
       D-cache bit 1 selects bit 0. This only enables the selected bus and
       never shuts a bus that was already enabled. */
    memw();
    uint live_instruction = registers->icache_bus_control;
    uint instruction_enable_mask = ((~saved_instruction) & 1U) << 1;
    memw();
    registers->icache_bus_control = live_instruction & ~instruction_enable_mask;

    memw();
    uint live_data = registers->dcache_bus_control;
    uint data_enable_mask = ((saved_data >> 1) & 1U) ^ 1U;
    memw();
    registers->dcache_bus_control = live_data & ~data_enable_mask;
    cache_hal_enable(1, CACHE_TYPE_ALL);
}

/* Native entry: 0x40380c64. */
/*
 * Medius v3.4.7 — host application; 0x40380c64.
 *
 * Suspends the external-memory cache by requesting level 1 and ALL (2), which visits the
 * instruction cache before the data cache. This S3 body performs no extra internal-cache
 * writeback and does not acquire a flash mutex or mask interrupts itself.
 *
 * Calls: cache_hal_suspend.
 *
 * Called by: spi_flash_disable_cache, FUN_4037c454.
 *
 * Original function-byte SHA-256:
 * cbc45c8c3a404da5139eb590d8895eab78ecf4615b5b33ccff312b97b456d3a1.
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
  return;
}

/* Native entry: 0x40380c74. */
/*
 * Medius v3.4.7 — host application; 0x40380c74.
 *
 * Resumes level-1 instruction and data caches through cache_hal_resume(1, ALL). The HAL uses
 * autoload bytes initialized in its context; this wrapper does not restore interrupt masks, release
 * a mutex or resume scheduling.
 *
 * Calls: cache_hal_resume.
 *
 * Called by: spi_flash_restore_cache, FUN_4037c464.
 *
 * Original function-byte SHA-256:
 * 7c0fac901ad761b71de592e5cac56bdca182635e54d92e09064635fe4cee37c7.
 */

/* Reference: ESP-IDF v5.4.4 components/esp_mm/esp_cache_utils.c. */

/*
 * Returns: Nothing; resumes both level-1 caches using initialized raw autoload bytes.
 * Requirements/effects: Requires the initialized HAL context; suspend does not save these bytes. Does
 *   not restore interrupt masks or scheduling.
 */

void esp_cache_resume_ext_mem_cache(void)

{
  cache_hal_resume(1,CACHE_TYPE_ALL);
  return;
}

/* Native entry: 0x40381064. */
/*
 * Medius v3.4.7 — host application; 0x40381064.
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
 * 1464ae79fadf9cabc803ad1d5a5f56c3dcc42c9df1c474bb4854102e5305462d.
 */

/* Reference: ESP-IDF v5.4.4 components/esp_rom/patches/esp_rom_cache_esp32s2_esp32s3.c. ROM
   symbol/address verified against esp32s3.rom.ld; ROM body is external to this application image. */

/*
 * Returns: The unchanged 32-bit state value returned by the ROM instruction-cache suspend routine.
 * Requirements/effects: Busy-polls EXTMEM bits 11:0 for idle state 1 after the ROM call; no
 *   timeout or yield. Caller supplies exclusion.
 */

uint Cache_Suspend_ICache(void)

{
  CacheStateRegister cache_state;
  uint rom_result;

  rom_result = rom_Cache_Suspend_ICache();
  do {
    memw();
    cache_state = EXTMEM_CACHE_STATE;
  } while ((cache_state & 0xfff) != 1);
  return rom_result;
}

/* Native entry: 0x40381080. */
/*
 * Medius v3.4.7 — host application; 0x40381080.
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
 * ebeea70b35277a4f9ea562c0b023a270dd6b650e674f8aea88ee3992705055f8.
 */

/* Reference: ESP-IDF v5.4.4 components/esp_rom/patches/esp_rom_cache_esp32s2_esp32s3.c. ROM
   symbol/address verified against esp32s3.rom.ld; ROM body is external to this application image. */

/*
 * Returns: The unchanged 32-bit state value returned by the ROM data-cache suspend routine.
 * Requirements/effects: Busy-polls EXTMEM bits 23:12 for idle state 1 after the ROM call; no
 *   timeout or yield. Caller supplies exclusion.
 */

uint Cache_Suspend_DCache(void)

{
  CacheStateRegister cache_state;
  uint rom_result;

  rom_result = rom_Cache_Suspend_DCache();
  do {
    memw();
    cache_state = EXTMEM_CACHE_STATE;
  } while ((cache_state >> 0xc & 0xfff) != 1);
  return rom_result;
}

/* Native entry: 0x403841a8. */
/*
 * Medius v3.4.7 — host application; 0x403841a8.
 *
 * Disables the selected level-one caches through ROM, aborting for any other cache level.
 *
 * Calls: Cache_Disable_ICache, Cache_Disable_DCache, abort.
 *
 * Called by: do_multicore_settings.
 *
 * Original function-byte SHA-256:
 * 72c597f4ff40cc22edf7d5f36ee3f8c1242bed40462cc2b4fda5ef221efbd26a.
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

void cache_hal_disable(uint cache_level, CacheType cache_type)
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

/* Native entry: 0x403841d0. */
/*
 * Medius v3.4.7 — host application; 0x403841d0.
 *
 * Enables selected level-one caches using raw saved autoload bytes, with DATA snapshotted before INSTRUCTION.
 *
 * Calls: Cache_Enable_ICache, Cache_Enable_DCache, abort.
 *
 * Called by: do_multicore_settings.
 *
 * Original function-byte SHA-256:
 * d18860352277fa7229fe22e76bf2fd2f519c56060b600a1e22f6cd4757e07f7d.
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

void cache_hal_enable(uint cache_level, CacheType cache_type)
{
    if (cache_level != 1)
        abort();

    volatile CacheHalRawAutoloadState *state =
        &CACHE_AUTOLOAD_STATE;
    /* DATA is read first even for an instruction-only request. Its snapshot
       survives the instruction-cache ROM call. Preserve raw bytes, not bool
       normalization: the native operations shift each loaded byte by two. */
    uint data_autoload = state->data_autoload_enabled;
    if (cache_type != CACHE_TYPE_DATA) {
        uint instruction_autoload = state->instruction_autoload_enabled;
        Cache_Enable_ICache(instruction_autoload << 2);
        if (cache_type == CACHE_TYPE_INSTRUCTION)
            return;
    }
    Cache_Enable_DCache(data_autoload << 2);
}

/* Native entry: 0x40384208. */
/*
 * Medius v3.4.7 — host application; 0x40384208.
 *
 * Aborts unless cache_level is exactly 1. DATA (0) suspends only data cache, INSTRUCTION (1) only
 * instruction cache, and every other type follows the compiled default: instruction then data.
 * Each patched suspend helper waits for the corresponding idle state. No timeout or cache-type
 * range assertion is present.
 *
 * Calls: Cache_Suspend_ICache, Cache_Suspend_DCache, abort.
 *
 * Called by: FUN_4037d29c, esp_cache_suspend_ext_mem_cache.
 *
 * Original function-byte SHA-256:
 * f3b00ca4cbf5715a183d8e7ac1f6984a6d5433546152c069844112ce8c7e58f4.
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

void cache_hal_suspend(uint cache_level,CacheType type)

{
  if (cache_level != 1) {
                    /* WARNING: Subroutine does not return */
    abort();
  }
  if (type != CACHE_TYPE_DATA) {
    if (type == CACHE_TYPE_INSTRUCTION) {
      Cache_Suspend_ICache();
      return;
    }
    Cache_Suspend_ICache();
  }
  Cache_Suspend_DCache();
  return;
}

/* Native entry: 0x40384228. */
/*
 * Medius v3.4.7 — host application; 0x40384228.
 *
 * Aborts unless cache_level is 1, snapshots the saved data-autoload byte, and dispatches DATA
 * (0), INSTRUCTION (1), or the default instruction-then-data path. Passes each raw autoload byte
 * shifted by 2 to each ROM resume API. Does not sample autoload afresh or use the return from a
 * suspend call as its saved state.
 *
 * Calls: Cache_Resume_ICache, Cache_Resume_DCache, abort.
 *
 * Called by: FUN_4037d288, esp_cache_resume_ext_mem_cache.
 *
 * Original function-byte SHA-256:
 * 47d85d8d5a0f6b43d69ac475764eb16190d096b2555a33d815d59ef9fb918726.
 */

/* Reference: ESP-IDF v5.4.4 components/hal/cache_hal.c and
   components/hal/esp32s3/include/hal/cache_ll.h. */

/*
 * cache_level: Hardware cache level; this ESP32-S3 build requires exactly 1 and aborts otherwise.
 * type: DATA selects data only, INSTRUCTION selects instruction only; every other value selects
 *   instruction then data.
 * Returns: Nothing. Invalid cache_level aborts without returning.
 * Requirements/effects: Reads the initialized DATA byte first, even for an instruction-only
 *   request. Reads INSTRUCTION next only when requested; DATA retains its original snapshot
 *   across the ROM instruction-cache call. Passes raw bytes shifted left by two, without Boolean
 *   normalization. Suspend does not save these bytes. Caller supplies synchronization.
 */

void cache_hal_resume(unsigned int cache_level, CacheType type)
{
    if (cache_level != 1U)
        abort();
    volatile CacheHalRawAutoloadState *state = &CACHE_AUTOLOAD_STATE;
    unsigned int data_autoload = state->data_autoload_enabled;
    if (type != CACHE_TYPE_DATA) {
        unsigned int instruction_autoload = state->instruction_autoload_enabled;
        Cache_Resume_ICache(instruction_autoload << 2);
        if (type == CACHE_TYPE_INSTRUCTION)
            return;
    }
    Cache_Resume_DCache(data_autoload << 2);
}

/* Native entry: 0x420027d8. */
/*
 * Medius v3.4.7 — host application; 0x420027d8.
 *
 * Routes and enables cache-illegal/access events on CPU interrupt 25 for the current core.
 *
 * Calls: esp_intr_enable_source, esp_intr_disable_source, intr_matrix_set.
 *
 * Called by: call_start_cpu1, firmware_entry.
 *
 * Original function-byte SHA-256:
 * 961c5e134a7543a71dc25cdcf470de746aa1e48dce97202e318419f6956c577f.
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
    uint core = (xtensa_read_prid() >> 13) & 1U;
    volatile CacheErrorRegisters *registers =
        (volatile CacheErrorRegisters *)0x600c40dcU;

    esp_intr_disable_source(25);
    intr_matrix_set(core, 56, 25);
    memw();
    uint illegal_clear = registers->illegal.clear;
    memw();
    registers->illegal.clear = illegal_clear | 0x3fU;
    memw();
    uint illegal_enable = registers->illegal.enable;
    memw();
    registers->illegal.enable = illegal_enable | 0x3fU;

    intr_matrix_set(core, 94U + core, 25);
    volatile CacheErrorEventRegisters *access = &registers->core[core];
    memw();
    uint access_clear = access->clear;
    memw();
    access->clear = access_clear | 0x1fU;
    memw();
    uint access_enable = access->enable;
    memw();
    access->enable = access_enable | 0x1fU;
    esp_intr_enable_source(25);
}

/* Native entry: 0x40380c04. */
/*
 * Medius v3.4.7 — host application; 0x40380c04.
 * Instruction-checked recovered C.
 * Original function-byte SHA-256:
 * d2842302a896b31caa3f6120411375a4c07637ba62d3f843d9050978949a305b.
 */

/* Enter the cache-sync operations mux indefinitely after the ISR-context probe.
 * Both probe and lock status are discarded as native. Caller must pair exit;
 * this entry performs no cache operation, allocation or other-core handshake. */
void esp_cache_sync_ops_enter_critical_section(void)
{
    (void)xPortInIsrContext();
    (void)xPortEnterCriticalTimeout(CACHE_SYNC_LOCK,-1);
}

/* Native entry: 0x40380c18. */
/*
 * Medius v3.4.7 — host application; 0x40380c18.
 * Instruction-checked recovered C.
 * Original function-byte SHA-256:
 * 5b7c869e725107e245e210bec89bf6ab7fd9984cbdf03408c8923c3e4a8844ba.
 */

/* Probe ISR context (discard result), then release the cache-sync mux. Requires
 * matching ownership/entry. No cache flush, status or interrupt enable here. */
void esp_cache_sync_ops_exit_critical_section(void)
{
    (void)xPortInIsrContext();
    vPortExitCritical(CACHE_SYNC_LOCK);
}

/* Native entry: 0x40380c28. */
/*
 * Medius v3.4.7 — host application; 0x40380c28.
 * Instruction-checked recovered C.
 * Original function-byte SHA-256:
 * f81873d550365c0017e3e0fbe5ec7ad1fd3c304b5352036d0f478dd1443052e9.
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

/* Native entry: 0x40380c84. */
/*
 * Medius v3.4.7 — host application; 0x40380c84.
 * Instruction-checked recovered C.
 * Original function-byte SHA-256:
 * 84c658b13ca66af01e2af16b72f64c1e333a0659a5bf24a1e95ace1eaf2afe81.
 */

/* Freeze both level1 external-memory caches, instruction before data, with
 * native busy-ack mode0 and idle polling supplied by patched ROM wrappers.
 * No mux, interrupt masking, writeback or explicit other-core stall here. */
void esp_cache_freeze_ext_mem_cache(void)
{
    cache_hal_freeze(1,CACHE_TYPE_ALL);
}

/* Native entry: 0x40380c94. */
/*
 * Medius v3.4.7 — host application; 0x40380c94.
 * Instruction-checked recovered C.
 * Original function-byte SHA-256:
 * 265972ff05f29e86c4d36ca24411795e22bff4c1e30fce57e5bb584c49b99aaf.
 */

/* Unfreeze level1 instruction then data cache. No mux, interrupt re-enable or
 * status; caller supplies pairing with freeze and accessible code/storage. */
void esp_cache_unfreeze_ext_mem_cache(void)
{
    cache_hal_unfreeze(1,CACHE_TYPE_ALL);
}

/* Native entry: 0x40380ca4. */
/*
 * Medius v3.4.7 — host application; 0x40380ca4.
 * Instruction-checked recovered C.
 * Original function-byte SHA-256:
 * 53a5bc3b6c46684c640123f63191130518a358fa4e4719e1eeb38d4cbedd4b03.
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

/* Native entry: 0x40380ce4. */
/*
 * Medius v3.4.7 — host application; 0x40380ce4.
 * Instruction-checked recovered C.
 * Original function-byte SHA-256:
 * d246e3d39d33612087108a6c3d377bfc67c637e8c1e1196a221cc93f630e57e3.
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

/* Native entry: 0x403842d8. */
/*
 * Medius v3.4.7 — host application; 0x403842d8.
 * Instruction-checked recovered C.
 * Original function-byte SHA-256:
 * 45b41bde1dbf65153e67360c6a83238c3eacdef0002f50a20b5d715245765ed0.
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

/* Native entry: 0x403842fc. */
/*
 * Medius v3.4.7 — host application; 0x403842fc.
 * Instruction-checked recovered C.
 * Original function-byte SHA-256:
 * c9d6d4884cfc3134b8b81d8f913323e5299319d4d4eefecf96c66263ff02a0e9.
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

/* Native entry: 0x40384324. */
/*
 * Medius v3.4.7 — host application; 0x40384324.
 * Instruction-checked recovered C.
 * Original function-byte SHA-256:
 * 49c9e45691e06029d88777b6f8f3731ace56ce7791a6337c1494c9e5bda27991.
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

/* Native entry: 0x403810a4. */
/*
 * Medius v3.4.7 — host application; 0x403810a4.
 * Instruction-checked recovered C.
 * Original function-byte SHA-256:
 * 3c27fda371ff4175323029dd9c5045944ef00d5b0e5c025e39fec615c21708ac.
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

/* Native entry: 0x403810c0. */
/*
 * Medius v3.4.7 — host application; 0x403810c0.
 * Instruction-checked recovered C.
 * Original function-byte SHA-256:
 * 930dca4a08b767a6b2802d5690106d195cbf2bb08affa447be1335f2a5ee0cd5.
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

/* Native entry: 0x40384260. */
/*
 * Medius v3.4.7 — host application; 0x40384260.
 * Instruction-checked recovered C.
 * Original function-byte SHA-256:
 * 933765109677497e42de6e3f1eb505427fb3d5df1b1dde01509a9e8b01f38d51.
 */

/* S3 ignores level. DATA0 reads DCACHE enable bit0; INSTRUCTION1 reads ICACHE
 * enable bit0. Every other type requires both, short-circuiting on disabled D.
 * MEMW before each actual MMIO read; return normalized bool. No lock, writes,
 * address validation or proof that earlier cache maintenance has completed. */
bool cache_hal_is_cache_enabled(unsigned int level,CacheType type)
{
    (void)level;
    if (type == CACHE_TYPE_DATA) {
        memw();
        return (EXTMEM_CACHE->dcache_ctrl & 1U) != 0;
    }
    if (type != CACHE_TYPE_INSTRUCTION) {
        memw();
        if ((EXTMEM_CACHE->dcache_ctrl & 1U) == 0)
            return false;
    }
    memw();
    return (EXTMEM_CACHE->icache_ctrl & 1U) != 0;
}

/* Native entry: 0x40384298. */
/*
 * Medius v3.4.7 — host application; 0x40384298.
 * Instruction-checked recovered C.
 * Original function-byte SHA-256:
 * 0d765cd105770d3eab23b6ea7ef0d9ad6eb2f0447826dfbad7be57f6f5425123.
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
