/* Medius v3.4.7 host — app/startup.c.
 * Recovered C and native assembly, grouped for source navigation.
 * Original entry addresses, firmware-byte hashes and function comments follow.
 */

#include "../include/types.h"

/* Native entry: 0x403752a4. */
/*
 * Medius v3.4.7 — host application; 0x403752a4.
 *
 * Installs the secondary-core vector base, console and cache-error setup, waits for release, then dispatches to its system-startup entry.
 *
 * Calls: esp_rom_delay_us, esp_rom_install_uart_printf, esp_cache_err_int_init, bootloader_init_mem, ets_set_appcpu_boot_addr,
 * intr_matrix_set, uart_tx_switch.
 *
 * Indirect dispatch: the PRID-selected void(void) system-startup table entry.
 *
 * Original function-byte SHA-256:
 * b7ac32ce9f0484b84a14e53a6b394dbd59934ca89e6f0b5d8a5b36e73c672721.
 */

/*
 * Returns: No value.
 * Requirements/effects: Writes VECBASE = 0x40374000 and clears the app-CPU boot address. Applies
 *   memory protection, then uses this image's console policy: device clears ROM channels 1/2; host
 *   installs UART printing and selects UART 0. Enables core-1 debug recording, publishes up[1],
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
    esp_rom_install_uart_printf();
    uart_tx_switch(0);

    memw();
    *(volatile unsigned int *)0x600ce0d8U = 1; /* Core 1 debug recording enable. */
    memw();
    *(volatile unsigned int *)0x600ce0dcU = 1; /* Core 1 recording trigger. */
    memw();
    CPU_STARTUP_FLAGS.up[1] = 1;

    unsigned int core = (xtensa_read_prid() >> 13) & 1U;
    for (unsigned int source = 0; source < 99; source++)
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

/* Native entry: 0x403753b0. */
/* Original function-byte SHA-256:
 * 5455c3e9aae3946a8b5a20b1df361f13f0895165c2910c27a3fb845dc85a25c4. */
/* Primary boot entry; no C arguments. Install VECBASE0x40374000, read both
 * reset reasons, clear this image's0x24bc0 BSS bytes, and call the zero-length
 * RTC-BSS clear unless CPU0 reset reason is deep-sleep5. Configure multicore
 * cache access,16KiB instruction/32KiB data caches with8 ways/32-byte lines,
 * MMU split16/1008 bytes, MSPI/flash/RTC state and pin reservations in order.
 * Dependency bodies retain their separate native review status.
 *
 * Publish CPU0 up, obtain chip information and abort for cores<2 after the
 * gated diagnostics. Unstall CPU1. If its clock-gate bit1 was clear, perform
 * four separate control RMWs: set bit1, clear runstall bit0, assert/release
 * reset bit2. Otherwise preserve debugger-established control state. Set CPU1
 * entry and poll raw up[0]&up[1], delaying100us even on the successful pass.
 * There is no timeout. Set MMU info for4 instruction/2 data entries and no
 * PSRAM offsets, initialize clocks, store one RTC timestamp LOW then HIGH,
 * snapshot PRID bit13 once and route all99 interrupt sources to interrupt6.
 *
 * Host console uses XTAL frequency after the APB query and waits for UART0
 * TX idle. Compute source divider=ceil(unsigned frequency/471744000) through
 * native64-bit division. Only low-WORD dividers1..256 program the12.4 baud
 * divider for115200 and source-divider-minus-one field. Preserve wrapping
 * frequency<<4 and the native volatile staged CLK_CONF WORD/MEMW sequence.
 * No local UART lock or timeout is introduced.
 *
 * Reset deep-sleep wakeup I/O when applicable, initialize cache-error IRQs,
 * reject locked/error memory-protection state by restarting, and apply the
 * copied24-byte config (panic/lock1, null split, all memory types, CPUs0/1).
 * Failure logs timestamp before error-name lookup, then restarts. Zero six
 * header WORDs, copy24 mapped image-header bytes and check only magic0xe9;
 * invalid magic aborts. This is not a complete image-integrity check.
 *
 * Publish CPU0 initialized and poll using a volatile BYTE accumulator seeded1
 * then bitwise-ANDed with both raw initialized bytes. Only bit0 contributes;
 * retain separate MEMWs and the delay on a successful iteration. Fresh PRID
 * selects the typed system-startup callback; this entry returns if it returns.
 * Prior boot effects survive failures. Static review establishes neither
 * physical delays, hardware state transitions nor cross-core correctness. */
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
    esp_mspi_pin_reserve();
    if (SYSTEM_EARLY_LOG_LEVEL>2U) {
        unsigned int timestamp=esp_log_timestamp();
        ets_printf("I (%lu) %s: Multicore app\n",timestamp,"cpu_start");
    }
    bootloader_init_mem();
    memw();
    CPU_STARTUP_FLAGS.up[0]=1;
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
    memw();
    unsigned int control=BOOT_CORE1_CONTROL;
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
    Cache_Set_IDROM_MMU_Info(4,2,0x3c040020U,0x3c052794U,0,0);
    esp_clk_init();
    esp_perip_clk_init();
    unsigned long long startup_time=esp_rtc_get_time_us();
    BOOT_TIMESTAMP.low=(unsigned int)startup_time;
    BOOT_TIMESTAMP.high=(unsigned int)(startup_time>>32);
    unsigned int core=(xtensa_read_prid()>>13)&1U;
    for (unsigned int source=0;source<99U;++source) intr_matrix_set(core,source,6);

    esp_clk_apb_freq();
    unsigned int frequency=(unsigned int)esp_clk_xtal_freq();
    uart_tx_wait_idle(0);
    unsigned int source_divider=(unsigned int)medius_boot_unsigned_divide(
        (unsigned long long)frequency+471743999U,471744000U);
    if (source_divider-1U<256U) {
        UartRegisterView *uart=(UartRegisterView *)0x60000000U;
        memw();unsigned int divider=uart->clkdiv;
        unsigned int fixed_divider=(frequency<<4)/(source_divider*115200U);
        memw();uart->clkdiv=(divider&0xfffff000U)|((fixed_divider>>4)&4095U);
        memw();divider=uart->clkdiv;
        memw();uart->clkdiv=(divider&0xff0fffffU)|((fixed_divider&15U)<<20);
        memw();unsigned int clock_configuration=uart->clk_conf;
        volatile unsigned int staged_configuration;
        memw();staged_configuration=clock_configuration;
        memw();unsigned int staged=staged_configuration;
        staged=(staged&0xfff00fffU)|(((source_divider-1U)&255U)<<12);
        memw();staged_configuration=staged;
        memw();staged=staged_configuration;
        memw();uart->clk_conf=staged;
    }
    if (SYSTEM_EARLY_LOG_LEVEL>2U) {
        unsigned int timestamp=esp_log_timestamp();
        ets_printf("I (%lu) %s: GPIO %d and %d are used as console UART I/O pins\n",
            timestamp,"cpu_start",44,43);
    }
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

/* Native entry: 0x40375bec. */
/*
 * Medius v3.4.7 — host application; 0x40375bec.
 *
 * Initializes the secondary stage, waits for system-wide completion, and transfers to the other-core app startup.
 *
 * Calls: esp_rom_delay_us, do_system_init_fn, esp_startup_start_app_other_cores.
 *
 * Original function-byte SHA-256:
 * a9f0b3ab517c7318a83c1faf73c1490e9828b64e90df492fda691cc3accff71c.
 */

/*
 * Returns: Does not return normally. A returned app-start handoff raises one native ILL trap.
 * Requirements/effects: The SDK weak start_cpu_other_cores alias resolves to this default
 *   implementation. Calls do_system_init_fn(1), then reads the raw shared full-initialized byte.
 *   While zero, repeatedly requests a 100-microsecond ROM delay with no timeout. Any nonzero
 *   release value proceeds to esp_startup_start_app_other_cores. If that handoff unexpectedly
 *   returns, emits ILL directly; a generic compiler trap would emit a different breakpoint
 *   instruction on this toolchain. The raw decompiler's repeated-ILL loop is not retained.
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

/* Native entry: 0x42002314. */
/*
 * Medius v3.4.7 — host application; 0x42002314.
 *
 * Publishes the shared resume byte that releases other cores from their startup wait.
 *
 * Called by: start_cpu0_default.
 *
 * Original function-byte SHA-256:
 * fadb2717170b8b8421d4f1f36a302a4a050c18aa319be0e6ad69aab0ca77fb61.
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

/* Native entry: 0x42002fd8. */
/*
 * Medius v3.4.7 — host application; 0x42002fd8.
 *
 * Runs matching typed component-init callbacks, aborts on first error, then publishes per-core initialization.
 *
 * Calls: typed component-init callbacks, esp_log_timestamp, ets_printf, abort.
 *
 * Called by: start_cpu_other_cores_default, FUN_42003044.
 *
 * Original function-byte SHA-256:
 * 606cc5bdbc34f39d53d994ff94b5d91b1fbeb6f9a1d7709a7e8f5bb10ecddcca.
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

void do_system_init_fn(unsigned int stage)
{
    unsigned int core = (xtensa_read_prid() >> 13) & 1U;
    const volatile SystemInitEntry *entries = SYSTEM_INIT_ENTRIES;
    for (unsigned int index = 0; index < 20; index++) {
        const volatile SystemInitEntry *entry = &entries[index];
        if (entry->stage != stage || (entry->core_mask & (1U << core)) == 0)
            continue;

        int error = entry->function();
        if (error != 0) {
            if (SYSTEM_EARLY_LOG_LEVEL != 0) {
                unsigned int timestamp = esp_log_timestamp();
                ets_printf("E (%lu) %s: init function %p has failed (0x%x), aborting\n",
                    timestamp, "cpu_start", (void *)entry->function, (unsigned int)error);
            }
            abort();
        }
    }
    memw();
    SYSTEM_CORE_INITIALIZED[core] = 1;
}

/* Native entry: 0x42003044. */
/*
 * Medius v3.4.7 — host application; 0x42003044.
 *
 * Runs CPU0 component initialization and constructors, resumes other cores, waits for their initialization, and starts the application scheduler.
 *
 * Calls: esp_rom_delay_us, startup_resume_other_cores, do_system_init_fn, FUN_42013ff8, FUN_42015764, esp_startup_start_app.
 *
 * Original function-byte SHA-256:
 * 954431b36d6db4ac9cb364467e307bc7f3790b79612268bbb4de2cd3dca9cafa.
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

/* Native entry: 0x42011940. */
/*
 * Medius v3.4.7 — host application; 0x42011940.
 *
 * Applies this build's configured Xtensa memory-region protection during early startup.
 *
 * Calls: esp_cpu_configure_region_protection.
 *
 * Called by: call_start_cpu1, firmware_entry.
 *
 * Original function-byte SHA-256:
 * f55b5dbd202427035dce52353388e94bb5e56ec65712d8f9e5ec7dc931130a7b.
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

/* Native entry: 0x42023974. */
/*
 * Medius v3.4.7 — host application; 0x42023974.
 *
 * Publishes that the other CPU has reached its idle hook and returns true.
 *
 * Original function-byte SHA-256:
 * 12f47c59c46669e874ad7018bf940d0bb3c5a30c3de774aa9733bd41dcc4375c.
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

/* Native entry: 0x42023a40. */
/*
 * Medius v3.4.7 — host application; 0x42023a40.
 *
 * Initializes CPU0 interrupt services, creates the main task pinned to CPU0, and starts FreeRTOS scheduling.
 *
 * Calls: vTaskStartScheduler, __assert_func, esp_int_wdt_init, esp_int_wdt_cpu_init, esp_crosscore_int_init,
 * xTaskCreatePinnedToCore.
 *
 * Called by: FUN_42003044.
 *
 * Optional weak port_start_app_hook is NULL in this linked image.
 *
 * Original function-byte SHA-256:
 * 086473906a98e7a6fe212558dd2f2fe918067938a7a28313badd6b82001143e7.
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

/* Native entry: 0x42023a8c. */
/*
 * Medius v3.4.7 — host application; 0x42023a8c.
 *
 * Waits for CPU0 scheduler publication, initializes per-core interrupt services, and enters the FreeRTOS scheduler.
 *
 * Calls: xPortStartScheduler, esp_int_wdt_cpu_init, esp_crosscore_int_init, abort.
 *
 * Called by: FUN_40375bec.
 *
 * Original function-byte SHA-256:
 * 7e0350b6956e6eac5006a230beadb58c0964467367d8cd272b40c43342e930db.
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
    unsigned int core = (xtensa_read_prid() >> 13) & 1U;
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
    (void)xPortStartScheduler();
    abort(); /* Fallback if the scheduler entry unexpectedly returns. */
}
