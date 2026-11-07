/* Medius v3.4.7 host — RTC, CPU and peripheral clock startup.
 * SDK names checked against ESP-IDF v5.4.4 esp32s3/clk.c; native bytes are authority.
 */
#include "../include/types.h"

/* Native entry: 0x42002370. */
/* Original function-byte SHA-256:
 * 50d8a5d877646331260e05e2fc7a357001b89d046a83dad4d30f4439bca3da43. */
/* Select/calibrate this build's RTC slow clock and publish its Q19 period.
 * Snapshot the old source once. Only requested_source==1 takes the crystal
 * path; every other WORD selects internal RC0, including SDK sources that this
 * specialized body does not implement. Crystal attempts enable32k, calibrate
 * XTAL source2 over1024 cycles, then select source1 and calibrate the RTC mux0
 * over1024 cycles. A failed initial crystal probe consumes ONE shared retry;
 * successful probes followed by failed mux calibration retry without resetting
 * that allowance. Once consumed, a failed probe optionally logs at level>=2
 * and falls back to RC0. No fixed limit bounds successful-probe/mux retries.
 *
 * RC attempts select0, disable the32k crystal and external pad on fallback or
 * when the ORIGINAL source was1, then calibrate mux0/1024. Subsequent failures
 * reselect0; repeat the disable sequence only when the original source was1.
 * Continue until calibration is nonzero, then pass that exact WORD to
 * esp_clk_slowclk_cal_set. No sleep, whole-operation lock or total timeout;
 * per-attempt hardware timeouts are supplied by the calibration callee.
 */
void select_rtc_slow_clk(unsigned int requested_source)
{
    unsigned int old_source = rtc_clk_slow_src_get();
    unsigned int calibration;
    bool revoke_crystal = false;
    if (requested_source == 1U) {
        bool retry_available = true;
        for (;;) {
            rtc_clk_32k_enable(1);
            calibration = rtc_clk_cal(RTC_CAL_32K_XTAL,1024);
            if (calibration != 0) {
                rtc_clk_slow_src_set(1);
                calibration = rtc_clk_cal(RTC_CAL_RTC_MUX,1024);
                if (calibration != 0)
                    goto publish_period;
                continue;
            }
            if (retry_available) {
                retry_available = false;
                continue;
            }
            if (SYSTEM_EARLY_LOG_LEVEL >= 2U) {
                unsigned int timestamp = esp_log_timestamp();
                ets_printf("W (%lu) %s: 32 kHz XTAL not found, switching to internal 150 kHz oscillator\n",
                    timestamp,"clk");
            }
            revoke_crystal = true;
            break;
        }
    }
    do {
        rtc_clk_slow_src_set(0);
        if (revoke_crystal || old_source == 1U) {
            rtc_clk_32k_enable(0);
            rtc_clk_32k_disable_external();
        }
        revoke_crystal = false;
        calibration = rtc_clk_cal(RTC_CAL_RTC_MUX,1024);
    } while (calibration == 0);
publish_period:
    esp_clk_slowclk_cal_set(calibration);
}

/* Native entry: 0x42002438. */
/* Original function-byte SHA-256:
 * 5f4406344bfe9e01f915359bf1133176445117467a26708717f9281e7fdc7297. */
/* Initialize RTC power/clock control after the reviewed PLL workaround.
 * Read the packed default configuration WORD from DROM BEFORE querying CPU0's
 * ROM reset reason; it is0x27146414 in this image. Replace only OCode-calibration
 * bit30: set it for power-on reason1, clear it otherwise. Pass the full resulting
 * WORD to rtc_init and return after it completes. No local voltage calibration,
 * sleep, lock, status check or constant-folded substitute for the DROM read.
 */
void esp_rtc_init(void)
{
    rtc_reconfigure_active_pll();
    unsigned int configuration = RTC_DEFAULT_CONFIGURATION;
    int reason = rtc_get_reset_reason(0);
    configuration &= ~RTC_INIT_CALIBRATE_OCODE;
    if (reason == 1)
        configuration |= RTC_INIT_CALIBRATE_OCODE;
    rtc_init(configuration);
}

/* Native entry: 0x4200246c. */
/* Original function-byte SHA-256:
 * ea231718cebbdb395d6b67c61fa8645bb87fb244945517024ba6c9e5bdcebd92. */
/* Initialize RTC fast/slow clocks and switch this CPU to240MHz.
 * Require a40MHz XTAL or assert. Preserve the existing RC_FAST/256 enable flag,
 * enable RC_FAST and select it as fast source1. Construct an8-byte RWDT context
 * (register pointer first, then instance0). Snapshot slow-Hz, disable protection,
 * feed, compute low32(floor(1600ULL*Hz/1000)) through ROM unsigned64 division,
 * set stage0/reset-RTC action4 and restore protection. Select/calibrate slow
 * source0, then repeat the watchdog sequence with WRAPPING32-bit Hz*9 ticks.
 * These are programmed nominal thresholds, not measured deadlines.
 *
 * Query the old four-WORD CPU configuration and explicitly load cpu_mhz+12.
 * Unsupported readback may leave stack scratch unwritten; no fallback is added.
 * Build the240MHz configuration or assert. Drain ROM UART0 TX before changing clocks.
 * Apply the new configuration, read CCOUNT once, divide unsigned64(CCOUNT*240)
 * by the saved unsigned MHz, then write only the low result WORD to CCOUNT.
 * The native ROM division, including a possible zero denominator from failed
 * readback, is retained. No ISYNC, rollback, lock, status return or independent
 * oscillator-ready guarantee. Calibration and ROM calls can fail to return.
 */
void esp_clk_init(void)
{
    if (rtc_clk_xtal_freq_get() != 40U)
        __assert_func(NULL,0,NULL,NULL);
    bool divided_enabled = rtc_clk_8md256_enabled();
    rtc_clk_8m_enable(1,divided_enabled);
    rtc_clk_fast_src_set(1);

    WatchdogHalContext rtc;
    volatile WatchdogHalContext *initial = &rtc;
    initial->rwdt_registers = (RtcWatchdogRegisters *)0x60008000U;
    initial->instance = WDT_RWDT;
    unsigned int slow_hz = rtc_clk_slow_freq_get_hz();
    wdt_hal_write_protect_disable(&rtc);
    wdt_hal_feed(&rtc);
    unsigned int timeout = (unsigned int)rom_unsigned_divide_u64(1600ULL * slow_hz,1000ULL);
    wdt_hal_config_stage(&rtc,WDT_STAGE0,timeout,WDT_STAGE_ACTION_RESET_RTC);
    wdt_hal_write_protect_enable(&rtc);

    select_rtc_slow_clk(0);
    slow_hz = rtc_clk_slow_freq_get_hz();
    wdt_hal_write_protect_disable(&rtc);
    wdt_hal_feed(&rtc);
    wdt_hal_config_stage(&rtc,WDT_STAGE0,slow_hz * 9U,WDT_STAGE_ACTION_RESET_RTC);
    wdt_hal_write_protect_enable(&rtc);

    RtcCpuFrequencyConfig old_configuration,new_configuration;
    rtc_clk_cpu_freq_get_config(&old_configuration);
    unsigned int old_mhz;
    __asm__ volatile ("l32i %0,%1,12" : "=a"(old_mhz)
        : "a"(&old_configuration) : "memory");
    if (!rtc_clk_cpu_freq_mhz_to_config(240,&new_configuration))
        __assert_func(NULL,0,NULL,NULL);
    uart_tx_wait_idle(0);
    rtc_clk_cpu_freq_set_config(&new_configuration);
    unsigned int cycles = esp_cpu_get_cycle_count();
    unsigned long long scaled = rom_unsigned_divide_u64((unsigned long long)cycles * 240U,
        (unsigned long long)old_mhz);
    esp_cpu_set_cycle_count((unsigned int)scaled);
}

/* Native entry: 0x42002570. */
/* Original function-byte SHA-256:
 * 90b04c9debcf9a2be39c44ebd231aef97afb4403f54a0355eb4ddf90ac395d88. */
/* Configure peripheral startup clocks from both CPUs' reset reasons.
 * CPU-local reset reasons11..13 or17 on EITHER core use four fenced snapshots:
 * clock0, clock1 for common peripherals, a FRESH clock1 for crypto, then WiFi.
 * Other resets use fixed masks. Host/device clock0 masks differ at UART0 bit2:
 * the host preserves its console clock; the device disables/resets it here.
 * USB-Serial-JTAG bit10 is excluded from the common clock1 reset mask.
 *
 * Perform fresh MEMW/read, MEMW/write pairs in native order: clock0/reset0,
 * common clock1/reset1, crypto clock1/reset1, then clear backup-DMA reset bit0
 * through a NEW reset1 RMW. Update WiFi clocks in TWO distinct RMWs: retain the
 * selected mask, then OR0x00fb9fcf. Clear BT low-power divider bits0..11; clear
 * source bits24..27, then select RTC_SLOW bit24 with a separate fresh RMW.
 * Finally enable RNG module25 through the separate reference-counted API.
 * No encompassing lock, readback verification, peripheral driver initialization
 * or rollback. Separate snapshots/RMWs may observe independently changing state.
 */
void esp_perip_clk_init(void)
{
    int reset0 = rtc_get_reset_reason(0);
    int reset1 = rtc_get_reset_reason(1);
    bool cpu_only_reset = ((unsigned int)reset0 - 11U < 3U) || reset0 == 17 ||
        ((unsigned int)reset1 - 11U < 3U) || reset1 == 17;
    SystemPeripheralRegistersPrefix *system = SYSTEM_PERIPHERAL_REGISTERS;
    unsigned int common_reset0,common_reset1,crypto_reset,wifi_keep;
    if (cpu_only_reset) {
        memw();
        unsigned int clock0 = system->clock_enable0;
        memw();
        unsigned int common_clock1 = system->clock_enable1;
        memw();
        unsigned int crypto_clock1 = system->clock_enable1;
        common_reset0 = ~clock0 | 0x88e513f0U;
        common_reset1 = (~(common_clock1 | 0x3eU) & ~0x400U) | 0x200U;
        crypto_reset = (~crypto_clock1) & 0x3eU;
        memw();
        wifi_keep = PERIPHERAL_WIFI_CLOCK;
    } else {
        common_reset0 = 0x8eff9ff8U;
        common_reset1 = 0x200U;
        crypto_reset = 0x0eU;
        wifi_keep = 0xffffcfdfU;
    }
    memw();
    unsigned int value = system->clock_enable0;
    memw();
    system->clock_enable0 = value & ~common_reset0;
    memw();
    value = system->reset_enable0;
    memw();
    system->reset_enable0 = value | common_reset0;
    memw();
    value = system->clock_enable1;
    memw();
    system->clock_enable1 = value & ~common_reset1;
    memw();
    value = system->reset_enable1;
    memw();
    system->reset_enable1 = value | common_reset1;
    memw();
    value = system->clock_enable1;
    memw();
    system->clock_enable1 = value & ~crypto_reset;
    memw();
    value = system->reset_enable1;
    memw();
    system->reset_enable1 = value | crypto_reset;
    memw();
    value = system->reset_enable1;
    memw();
    system->reset_enable1 = value & ~1U;
    memw();
    value = PERIPHERAL_WIFI_CLOCK;
    memw();
    PERIPHERAL_WIFI_CLOCK = value & wifi_keep;
    memw();
    value = PERIPHERAL_WIFI_CLOCK;
    memw();
    PERIPHERAL_WIFI_CLOCK = value | 0x00fb9fcfU;
    memw();
    value = system->bluetooth_clock_integer;
    memw();
    system->bluetooth_clock_integer = value & ~0xfffU;
    memw();
    value = system->bluetooth_clock_fractional;
    memw();
    system->bluetooth_clock_fractional = value & ~0x0f000000U;
    memw();
    value = system->bluetooth_clock_fractional;
    memw();
    system->bluetooth_clock_fractional = value | 0x01000000U;
    periph_module_enable(25);
}
