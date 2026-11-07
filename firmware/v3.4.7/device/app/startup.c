/* Medius v3.4.7 device — app/startup.c.
 * Recovered C and native assembly, grouped for source navigation.
 * Original entry addresses, firmware-byte hashes and function comments follow.
 */

#include "../include/types.h"

/* Native entry: 0x40375694. */
/* Original function-byte SHA-256:
 * 4cc672fc4b3b08d248f0123e52b1f085d87095250d7fcd46bec3317bfd326192.
 */

/*
 * Returns: No value.
 * Requirements/effects: Writes VECBASE = 0x40374000 and clears the app-CPU boot address. Applies
 *   memory protection and clears ROM console channels 1/2. Enables core-1 debug recording, publishes up[1],
 *   and snapshots PRID bit 13 to route sources 0 through 98 to invalid CPU interrupt 6. Configures
 *   cache-error interrupts, publishes initialized[1], then requests repeated 100-microsecond
 *   delays while the shared resume byte is zero. This wait has no timeout. A fresh PRID read
 *   selects one of two typed system-startup functions. The native routine can return if that
 *   callback returns. Caller supplies accessible internal execution/data memory and coordinated
 *   primary-core initialization; no scheduler, physical delay or cross-core lifetime guarantee is
 *   introduced.
 */

void call_start_cpu1(void)
{
    __asm__ volatile ("wsr.vecbase %0" :: "a"(0x40374000U) : "memory");
    ets_set_appcpu_boot_addr(0);
    bootloader_init_mem();
    esp_rom_install_channel_putc(1, 0);
    esp_rom_install_channel_putc(2, 0);

    memw();
    *(volatile uint *)0x600ce0d8U = 1; /* Core 1 debug recording enable. */
    memw();
    *(volatile uint *)0x600ce0dcU = 1; /* Core 1 recording trigger. */
    memw();
    CPU_STARTUP_FLAGS.up[1] = 1;

    uint core = (xtensa_read_prid() >> 13) & 1U;
    for (uint source = 0; source < 99; source++)
        intr_matrix_set(core, source, 6);
    esp_cache_err_int_init();
    memw();
    CPU_STARTUP_FLAGS.initialized[1] = 1;
    memw();
    while (CPU_STARTUP_FLAGS.resume_cores == 0) {
        esp_rom_delay_us(100);
        memw();
    }

    /* The dispatch uses a fresh PRID read, not the earlier routing snapshot. */
    core = (xtensa_read_prid() >> 13) & 1U;
    SYSTEM_STARTUP_FUNCTIONS[core]();
}

/* Native entry: 0x403757a4. */
/* Original function-byte SHA-256:
 * 5f22dcf416a22fe6a5bfc1fa2069ac8c78f1566059f790c518e95cc3cd223f29. */
/* Primary boot entry; no C arguments. Install VECBASE0x40374000, read both
 * reset reasons, clear this image's0x1b0a0 BSS bytes, and call the zero-length
 * RTC-BSS clear unless CPU0 reset reason is deep-sleep5. Configure multicore
 * cache access,16KiB instruction/32KiB data caches with8 ways/32-byte lines,
 * MMU split16/1008 bytes, MSPI/flash/RTC state and optional PSRAM in order.
 * Nonzero PSRAM init status only emits the gated information message; pin
 * reservation and multicore startup continue. Dependency implementations
 * retain their separate native review status.
 *
 * Publish CPU0 up, obtain chip information and abort for cores<2 after the
 * gated diagnostics. Unstall CPU1. If its clock-gate bit1 was clear, perform
 * separate RMWs to set bit1, clear runstall bit0 and assert/release reset bit2;
 * otherwise retain debugger-established state. Set CPU1 entry and poll raw
 * up[0]&up[1], delaying100us even on success. No timeout is supplied. Only
 * when the raw initialized PSRAM BYTE is nonzero, call its memory test and
 * abort on a zero WORD result. No console UART baud setup is linked here.
 *
 * Set MMU info for4 instruction/1 data entries with zero PSRAM offsets,
 * initialize clocks, store one RTC timestamp LOW then HIGH, snapshot PRID
 * bit13 once and route all99 interrupt sources to interrupt6. Reset wakeup
 * I/O for deep-sleep, then initialize cache-error IRQs. Locked/error memory-
 * protection state restarts; applying the copied24-byte default config also
 * restarts on error, logging timestamp before error-name lookup. Config has
 * panic/lock1, null split, memory mask0x7fffffff and target CPUs0/1.
 *
 * Zero six header WORDs, copy24 mapped header bytes and check only magic0xe9;
 * invalid magic aborts. Publish CPU0 initialized, then poll with a volatile
 * BYTE seeded1 and bitwise-ANDed with both raw initialized bytes, preserving
 * all MEMWs and the100us delay on a successful pass. Fresh PRID selects the
 * typed system-startup callback, and this routine returns if it returns.
 * No rollback, complete image-integrity check or physical timing/concurrency
 * guarantee is introduced by this static reconstruction. */
void firmware_entry(void)
{
    __asm__ volatile("wsr.vecbase %0" :: "a"(0x40374000U) : "memory");
    int reset_reason=rtc_get_reset_reason(0);
    rtc_get_reset_reason(1);
    memset(BOOT_BSS_START,0,BOOT_BSS_LENGTH);
    if (reset_reason!=5) memset((void *)0x50000000U,0,0);
    do_multicore_settings();
    cache_hal_init();
    rom_config_instruction_cache_mode(16384,8,32);
    Cache_Suspend_DCache();
    rom_config_data_cache_mode(32768,8,32);
    Cache_Resume_DCache(0);
    Cache_Set_IDROM_MMU_Size(16,1008);
    esp_mspi_pin_init();
    flash_update_rom_chip_id();
    esp_rtc_init();
    spi_flash_init_chip_state();
    mspi_timing_flash_tuning();
    esp_mmu_map_init();
    int psram_error=esp_psram_init();
    if (psram_error!=0 && SYSTEM_EARLY_LOG_LEVEL>2U) {
        unsigned int timestamp=esp_log_timestamp();
        ets_printf("I (%lu) %s: Failed to init external RAM; continuing without it.\n",
            timestamp,"cpu_start");
    }
    esp_mspi_pin_reserve();
    if (SYSTEM_EARLY_LOG_LEVEL>2U) {
        unsigned int timestamp=esp_log_timestamp();
        ets_printf("I (%lu) %s: Multicore app\n",timestamp,"cpu_start");
    }
    bootloader_init_mem();
    memw();CPU_STARTUP_FLAGS.up[0]=1;
    BootChipInfo chip;
    esp_chip_info(&chip);
    if (chip.cores<2U) {
        if (SYSTEM_EARLY_LOG_LEVEL!=0U) {
            unsigned int timestamp=esp_log_timestamp();
            ets_printf("E (%lu) %s: Running on single core variant of a chip, but app is built with multi-core support.\n",
                timestamp,"cpu_start");
            if (SYSTEM_EARLY_LOG_LEVEL!=0U) {
                timestamp=esp_log_timestamp();
                ets_printf("E (%lu) %s: Check that CONFIG_FREERTOS_UNICORE is enabled in menuconfig\n",
                    timestamp,"cpu_start");
            }
        }
        abort();
    }
    esp_cpu_unstall(1);
    memw();unsigned int control=BOOT_CORE1_CONTROL;
    if ((control&2U)==0U) {
        memw();control=BOOT_CORE1_CONTROL;
        memw();BOOT_CORE1_CONTROL=control|2U;
        memw();control=BOOT_CORE1_CONTROL;
        memw();BOOT_CORE1_CONTROL=control&0xfffffffeU;
        memw();control=BOOT_CORE1_CONTROL;
        memw();BOOT_CORE1_CONTROL=control|4U;
        memw();control=BOOT_CORE1_CONTROL;
        memw();BOOT_CORE1_CONTROL=control&0xfffffffbU;
    }
    ets_set_appcpu_boot_addr((unsigned int)call_start_cpu1);
    unsigned char up_mask;
    do {
        memw();unsigned char core0=CPU_STARTUP_FLAGS.up[0];
        memw();unsigned char core1=CPU_STARTUP_FLAGS.up[1];
        up_mask=core0&core1;
        esp_rom_delay_us(100);
    } while (up_mask==0U);
    if (esp_psram_is_initialized()!=0U && esp_psram_extram_test()==0) {
        if (SYSTEM_EARLY_LOG_LEVEL!=0U) {
            unsigned int timestamp=esp_log_timestamp();
            ets_printf("E (%lu) %s: External RAM failed memory test!\n",timestamp,"cpu_start");
        }
        abort();
    }
    Cache_Set_IDROM_MMU_Info(4,1,0x3c040020U,0x3c04826cU,0,0);
    esp_clk_init();
    esp_perip_clk_init();
    unsigned long long startup_time=esp_rtc_get_time_us();
    BOOT_TIMESTAMP.low=(unsigned int)startup_time;
    BOOT_TIMESTAMP.high=(unsigned int)(startup_time>>32);
    unsigned int core=(xtensa_read_prid()>>13)&1U;
    for (unsigned int source=0;source<99U;++source) intr_matrix_set(core,source,6);
    if (reset_reason==5) esp_deep_sleep_wakeup_io_reset();
    esp_cache_err_int_init();
    unsigned char locked=0;
    if (esp_mprot_is_conf_locked_any(&locked)!=0 || locked!=0U) {
        if (SYSTEM_EARLY_LOG_LEVEL!=0U) {
            unsigned int timestamp=esp_log_timestamp();
            ets_printf("E (%lu) %s: Memprot feature locked after the system reset! Potential safety corruption, rebooting.\n",
                timestamp,"cpu_start");
        }
        esp_restart_noos();
    }
    BootMemoryProtectionConfiguration protection;
    memcpy(&protection,BOOT_PROTECTION_DEFAULTS,sizeof(protection));
    int protection_error=esp_mprot_set_prot(&protection);
    if (protection_error!=0) {
        if (SYSTEM_EARLY_LOG_LEVEL!=0U) {
            unsigned int timestamp=esp_log_timestamp();
            const char *error_name=esp_err_to_name(protection_error);
            ets_printf("E (%lu) %s: Failed to set Memprot feature (0x%08X: %s), rebooting.\n",
                timestamp,"cpu_start",protection_error,error_name);
        }
        esp_restart_noos();
    }
    volatile BootImageHeader header;
    for (unsigned int word=0;word<6U;++word) header.words[word]=0;
    memcpy((void *)&header,(const void *)0x3c040000U,sizeof(header));
    if (header.magic!=0xe9U) {
        if (SYSTEM_EARLY_LOG_LEVEL!=0U) {
            unsigned int timestamp=esp_log_timestamp();
            ets_printf("E (%lu) %s: Invalid app image header\n",timestamp,"cpu_start");
        }
        abort();
    }
    memw();CPU_STARTUP_FLAGS.initialized[0]=1;
    volatile unsigned char initialized;
    memw();initialized=0;
    memw();
    while (initialized==0U) {
        memw();initialized=1;
        memw();unsigned char core0=CPU_STARTUP_FLAGS.initialized[0];
        memw();unsigned char accumulated=initialized;
        memw();initialized=accumulated&core0;
        memw();unsigned char core1=CPU_STARTUP_FLAGS.initialized[1];
        memw();accumulated=initialized;
        memw();initialized=accumulated&core1;
        esp_rom_delay_us(100);
        memw();
    }
    core=(xtensa_read_prid()>>13)&1U;
    SYSTEM_STARTUP_FUNCTIONS[core]();
}

/* Native entry: 0x40375fbc. */
/* Original function-byte SHA-256:
 * f1c7c5f8676e13a146149be943f152716bf358c2783c702c16c99b8dfd12f59e.
 */

/*
 * Returns: Does not return normally. A returned app-start handoff raises one native ILL trap.
 * Requirements/effects: The SDK weak start_cpu_other_cores alias resolves to this default
 *   implementation. Calls do_system_init_fn(1), then reads the raw shared full-initialized byte.
 *   While zero, repeatedly requests a 100-microsecond ROM delay with no timeout. Any nonzero
 *   release value proceeds to esp_startup_start_app_other_cores. If that handoff unexpectedly
 *   returns, emits ILL directly; a generic compiler trap would emit a different breakpoint
 *   instruction on this toolchain. The fallback contains exactly one ILL instruction.
 *   Scheduler startup and physical delay/exception behavior belong to separate dependencies.
 */

void start_cpu_other_cores_default(void)
{
    do_system_init_fn(1); /* ESP_SYSTEM_INIT_STAGE_SECONDARY */
    memw();
    while (SYSTEM_FULL_INITIALIZED == 0) {
        esp_rom_delay_us(100);
        memw();
    }
    esp_startup_start_app_other_cores();
    /* The native fallback is a single ILL, not a loop of trap instructions. */
    __asm__ volatile ("ill" ::: "memory");
    __builtin_unreachable();
}

/* Native entry: 0x420029dc. */
/* Original function-byte SHA-256:
 * a871365598613317b5c4f4212d8b9c8bc0dfdf66f97b1c4fe34ebb2e3fe89a5d.
 */

/*
 * Returns: No value.
 * Requirements/effects: Stores exactly byte1 to CpuStartupFlags.resume_cores after MEMW.
 *   Does not modify the initialized/up bytes or neighboring padding, wake a task directly, or wait
 *   for an acknowledgement. The static flags object must remain available; other cores observe
 *   this through their separate polling code.
 */

void startup_resume_other_cores(void)
{
    memw();
    CPU_STARTUP_FLAGS.resume_cores = 1;
}

/* Native entry: 0x420032a4. */
/* Original function-byte SHA-256:
 * 5233f8a3b10d9a7514869129ed45b11d60ff3c878cd909ff8911043101dc25ef.
 */

/*
 * stage: Full 32-bit stage selector, normally CORE (0) or SECONDARY (1). Compared with each stored
 *   16-bit stage without truncating this argument.
 * Returns: No value on success. The first nonzero callback result calls abort.
 * Requirements/effects: Snapshots PRID bit 13 once. Walks this build's twenty fixed 8-byte entries
 *   in order, checking stage before core-mask membership and invoking each matching int(void)
 *   callback. All native masks in this image are 1: core 1 makes no component callbacks. Stops at
 *   the first full-width nonzero error. If the fresh 32-bit early-log level is nonzero, obtains a
 *   timestamp and logs the callback pointer/error before aborting. The log gate is not rechecked
 *   after the timestamp call. Only complete traversal sets the current core's initialized byte to
 *   1; an unmatched stage also completes, while failure preserves its previous byte. Callback side
 *   effects are not rolled back and there is no callback timeout or local synchronization.
 */

void do_system_init_fn(uint stage)
{
    uint core = (xtensa_read_prid() >> 13) & 1U;
    const volatile SystemInitEntry *entries = SYSTEM_INIT_ENTRIES;
    for (uint index = 0; index < 20; index++) {
        const volatile SystemInitEntry *entry = &entries[index];
        if (entry->stage != stage || (entry->core_mask & (1U << core)) == 0)
            continue;

        int error = entry->function();
        if (error != 0) {
            if (SYSTEM_EARLY_LOG_LEVEL != 0) {
                uint timestamp = esp_log_timestamp();
                ets_printf("E (%lu) %s: init function %p has failed (0x%x), aborting\n",
                    timestamp, "cpu_start", (void *)entry->function, (uint)error);
            }
            abort();
        }
    }
    memw();
    SYSTEM_CORE_INITIALIZED[core] = 1;
}

/* Native entry: 0x42003310. */
/* Original function-byte SHA-256:
 * ce5aa121bb7a35a8a1819df219f29db2b3c78e72e3844fb905246c9db4c22a16.
 */

/*
 * Returns: Does not return. If application startup unexpectedly returns, executes an unconditional
 *   jump-to-self fallback.
 * Requirements/effects: CPU0 entry is the weak start_cpu0 default implementation. Calls
 *   do_system_init_fn(0), then all five pinned void(void) constructor pointers from index4 down
 *   to0, without NULL checks. Calls startup_resume_other_cores and do_system_init_fn(1).
 *   Initializes a volatile byte accumulator to0; each polling iteration sets it to1, reads core0
 *   and core1 initialization bytes in that order without short circuit, and bitwise-ANDs each into
 *   the accumulator. Thus only bit0 of each raw flag contributes; other nonzero values such as2 do
 *   not signal success. Requests esp_rom_delay_us(100) even on the successful iteration, then
 *   checks the saved accumulator rather than re-reading flags. No timeout is supplied. Finally
 *   stores full-initialization byte1 and calls esp_startup_start_app. Failures or nonreturning
 *   constructors/dependencies leave prior side effects intact. Delays are requests; this body
 *   supplies no physical scheduling or concurrency guarantee.
 */

void start_cpu0_default(void)
{
    do_system_init_fn(0);

    /* Five pinned constructor pointers, visited from the last entry to first. */
    for (unsigned int remaining = 5; remaining != 0; --remaining)
        GLOBAL_CONSTRUCTORS[remaining - 1]();

    startup_resume_other_cores();
    do_system_init_fn(1);

    /* Preserve the native byte accumulator and its full bitwise ANDs.
     * Using bool here would normalize noncanonical input flag bytes. */
    volatile unsigned char all_cores_initialized;
    memw();
    all_cores_initialized = 0;
    memw();
    while (all_cores_initialized == 0) {
        memw();
        all_cores_initialized = 1;
        memw();
        unsigned char core0_initialized = SYSTEM_CORE_INITIALIZED[0];
        memw();
        unsigned char accumulated = all_cores_initialized;
        memw();
        all_cores_initialized = accumulated & core0_initialized;
        memw();
        unsigned char core1_initialized = SYSTEM_CORE_INITIALIZED[1];
        memw();
        accumulated = all_cores_initialized;
        memw();
        all_cores_initialized = accumulated & core1_initialized;

        /* A delay request is made even on the successful polling iteration. */
        esp_rom_delay_us(100);
        memw();
    }

    memw();
    SYSTEM_FULL_INITIALIZED = 1;
    esp_startup_start_app();
    for (;;) {
        /* Native jump-to-self fallback if application startup returns. */
        __asm__ volatile ("" ::: "memory");
    }
}

/* Native entry: 0x4200f534. */
/* Original function-byte SHA-256:
 * 3a22d0c7288ea9151142b4b27ce78b6748875b67e5b8b91b3939617ff826e35d.
 */

/*
 * Returns: No value.
 * Requirements/effects: This build delegates only to esp_cpu_configure_region_protection. No
 *   parameters, allocation, clearing, status propagation or local synchronization are added; the
 *   protection implementation is a separate dependency.
 */

void bootloader_init_mem(void)
{
    /* This build enables only the Xtensa memory-region protection step. */
    esp_cpu_configure_region_protection();
}

/* Native entry: 0x420242a4. */
/* Original function-byte SHA-256:
 * 83a9a2aa627bb53af3ebb2b9525cdbdb4c6a52744775c5f3c5a0ee13a588475e.
 */

/*
 * Returns: true (native return word1).
 * Requirements/effects: Stores exactly byte1 to the shared other-CPU-startup-done flag after MEMW.
 *   Does not inspect the prior value, read PRID, deregister itself, wait, or reset the flag.
 *   Returning true permits the idle-hook dispatcher to proceed toward its idle decision; actual
 *   idle entry also depends on its other callbacks and dispatcher behavior. Intended registration
 *   targets the other core during main_task startup.
 */

bool other_cpu_startup_idle_hook_cb(void)
{
    memw();
    OTHER_CPU_STARTUP_DONE = 1;
    return true;
}

/* Native entry: 0x42024370. */
/* Original function-byte SHA-256:
 * f32dfe0975a0b4c43b94a1fffdd907c405c5ce94a1fa07ba9562044d0eb2475d.
 */

/*
 * Returns: No value. May return if vTaskStartScheduler returns; the caller supplies any fallback.
 * Requirements/effects: Calls esp_int_wdt_init, esp_int_wdt_cpu_init and esp_crosscore_int_init in
 *   that order. Then creates main_task with name main,4096 stack bytes,NULL
 *   argument,priority1,NULL handle output and core0; the seventh core argument is written on the
 *   Xtensa caller stack. Tests the full32-bit creation status against1. Any other value calls the
 *   nonreturning silent __assert_func with NULL file/function/expression and line0; prior
 *   initialization is retained. The optional weak port_start_app_hook literal is exactlyNULL in
 *   both linked binaries, so its conditional indirect call cannot run. Finally calls
 *   vTaskStartScheduler. Task allocation/scheduling and interrupt initialization are separate
 *   dependencies; no task handle or rollback is supplied here.
 */

void esp_startup_start_app(void)
{
    esp_int_wdt_init();
    esp_int_wdt_cpu_init();
    esp_crosscore_int_init();

    int creation_status = xTaskCreatePinnedToCore(main_task, "main", 4096U,
        0, 1U, 0, 0);
    if (creation_status != 1)
        __assert_func(0, 0, 0, 0);

    /* The optional weak port_start_app_hook is NULL in this linked image. */
    vTaskStartScheduler();
}

/* Native entry: 0x420243bc. */
/* Original function-byte SHA-256:
 * 5ce072dc440b075bd445d968f642e76e79ce41bde2fadf095c4e18d3f17f564a.
 */

/*
 * Returns: Does not return normally. A returned scheduler entry falls back to abort.
 * Requirements/effects: Reads PRID and derives its one-bit core ID. The retained native <2 guard
 *   cannot fail for that extraction; no synthetic invalid core is introduced. Busy-polls the full
 *   32-bit CPU0 scheduler-running word, with a fresh read each iteration and no delay or timeout.
 *   Then calls esp_int_wdt_cpu_init, esp_crosscore_int_init and xPortStartScheduler in that order.
 *   Cross-core allocation failure aborts before scheduler entry. The linked scheduler normally
 *   transfers control without returning; any returned value is ignored before abort. Scheduler,
 *   watchdog and ROM operations have separate implementations.
 */

void esp_startup_start_app_other_cores(void)
{
    uint core = (xtensa_read_prid() >> 13) & 1U;
    /* The native assertion retains this guard, but a one-bit core ID is
       necessarily below two in this linked ESP32-S3 build. */
    if (core >= 2)
        abort();

    /* Busy-poll a full 32-bit shared word. There is no delay or timeout. */
    do {
        memw();
    } while (SCHEDULER_RUNNING[0] == 0);
    esp_int_wdt_cpu_init();
    esp_crosscore_int_init();
    /* Use a return-capable callable view to retain the native abort fallback,
     * even though the linked scheduler normally transfers control permanently. */
    int (*volatile scheduler_entry)(void) = xPortStartScheduler;
    (void)scheduler_entry();
    abort(); /* Fallback if the scheduler entry unexpectedly returns. */
}
