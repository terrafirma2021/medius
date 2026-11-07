/* Medius v3.4.7 host — panic watchdog and re-entry control. */
#include "../include/types.h"

/* Native entry: 0x42002980. */
/* Original function-byte SHA-256:
 * e86e423cde0861fc83be184b05bc6f9e57237508c5803734e3cfdd9ed8176d48. */
/*
 * Feed enabled watchdogs in order: timer-group0, timer-group1, then the shared
 * RTC watchdog. Copy each8-byte group context from its image template only
 * when that group's turn is reached. Query each enabled state once; any
 * nonzero full-WORD response causes unlock/feed/relock through the ROM HAL.
 * RTC uses the shared context directly, not a copy. No panic-count guard,
 * independent lock, timeout, status return or watchdog enable operation here.
 */
void panic_feed_enabled_wdts(void)
{
    WatchdogHalContext timer0;
    WatchdogInstance instance=PANIC_WDT0_TEMPLATE->instance;
    TimerGroupRegisters *registers=PANIC_WDT0_TEMPLATE->mwdt_registers;
    timer0.instance=instance;
    timer0.mwdt_registers=registers;
    if (panic_wdt_is_enabled(&timer0)!=0) {
        wdt_hal_write_protect_disable(&timer0);
        wdt_hal_feed(&timer0);
        wdt_hal_write_protect_enable(&timer0);
    }

    WatchdogHalContext timer1;
    instance=PANIC_WDT1_TEMPLATE->instance;
    registers=PANIC_WDT1_TEMPLATE->mwdt_registers;
    timer1.instance=instance;
    timer1.mwdt_registers=registers;
    if (panic_wdt_is_enabled(&timer1)!=0) {
        wdt_hal_write_protect_disable(&timer1);
        wdt_hal_feed(&timer1);
        wdt_hal_write_protect_enable(&timer1);
    }
    if (panic_wdt_is_enabled(PANIC_RTC_WDT)!=0) {
        wdt_hal_write_protect_disable(PANIC_RTC_WDT);
        wdt_hal_feed(PANIC_RTC_WDT);
        wdt_hal_write_protect_enable(PANIC_RTC_WDT);
    }
}

/* Native entry: 0x42002b70. */
/* Original function-byte SHA-256:
 * 993eefeead6d7dd7c3f53bbb399945b0b12682db1ea8454a44412deef5cf8497. */

/*
 * Disable both timer-group watchdogs, group0 before group1. Copy the exact
 * instance/register WORD pair from each image template immediately before its
 * unlock/disable/relock sequence. No enabled query, RTC-watchdog operation,
 * register restoration, independent lock or status is provided.
 */
void esp_panic_handler_disable_timg_wdts(void)
{
    WatchdogHalContext timer0;
    WatchdogInstance instance=PANIC_WDT0_TEMPLATE->instance;
    TimerGroupRegisters *registers=PANIC_WDT0_TEMPLATE->mwdt_registers;
    timer0.instance=instance;
    timer0.mwdt_registers=registers;
    wdt_hal_write_protect_disable(&timer0);
    wdt_hal_disable(&timer0);
    wdt_hal_write_protect_enable(&timer0);

    WatchdogHalContext timer1;
    instance=PANIC_WDT1_TEMPLATE->instance;
    registers=PANIC_WDT1_TEMPLATE->mwdt_registers;
    timer1.instance=instance;
    timer1.mwdt_registers=registers;
    wdt_hal_write_protect_disable(&timer1);
    wdt_hal_disable(&timer1);
    wdt_hal_write_protect_enable(&timer1);
}

/* Native entry: 0x42002bbc. */
/* Original function-byte SHA-256:
 * 37230ecb9fb216fff8302507ec75a508b23f4b94a2c09cd3dda44ac988c580e9. */

/*
 * Build a local RTC watchdog context (instance0, registers0x60008000), initialize
 * it with instance/prescaler/interrupt all0, then sample RTC slow-clock Hz once.
 * Unlock, configure stage0 to reset RTC after ticks=(Hz*timeout_ms mod2^32)/1000,
 * enable, and relock. The multiply truncates BEFORE division: a large timeout
 * wraps and can arm a shorter interval. No range check, rounding-up, 64-bit
 * correction, feed, inter-core lock, actual-time guarantee or status return.
 */
void esp_panic_handler_enable_rtc_wdt(unsigned int timeout_ms)
{
    WatchdogHalContext rtc;
    rtc.rwdt_registers=(RtcWatchdogRegisters *)0x60008000U;
    rtc.instance=WDT_RWDT;
    wdt_hal_init(&rtc,WDT_RWDT,0,false);
    unsigned int frequency_hz=rtc_clk_slow_freq_get_hz();
    wdt_hal_write_protect_disable(&rtc);
    unsigned int ticks=(frequency_hz*timeout_ms)/1000U;
    wdt_hal_config_stage(&rtc,WDT_STAGE0,ticks,WDT_STAGE_ACTION_RESET_RTC);
    wdt_hal_enable(&rtc);
    wdt_hal_write_protect_enable(&rtc);
}

/* Native entry: 0x42002c14. */
/* Original function-byte SHA-256:
 * 549b0836700814e5f689616cf6bdb984a08ea9fb18c2740d659675fdd77dfb51. */

/*
 * Read PRID bit13 once, then the selected core's panic-entry count once. Feed
 * enabled watchdogs only while the unsigned count is below3. Do not increment
 * or clear it. No lock or cross-core snapshot; the feed helper performs the
 * individual ROM queries and unlock/feed/relock operations.
 */
void esp_panic_handler_feed_wdts(void)
{
    unsigned int core=(xtensa_read_prid()>>13)&1U;
    if (PANIC_ENTRY_COUNTS[core]<3U) panic_feed_enabled_wdts();
}

/* Native entry: 0x42002c30. */
/* Original function-byte SHA-256:
 * 8d4d5d20f2edc61fa9facace39756e573ce2fb15e17d87f0e51af1102e463837. */
/*
 * Select this core using PRID bit13, load its panic count, add1 modulo32 and
 * store it before testing the new value. Counts>=3 trigger a panic restart;
 * wrapped0 does not. This is a plain load/store increment with no lock, CAS,
 * MEMW or saturation, and does not alter the other core's count.
 * The host prints the fixed recursive-panic diagnostic before restarting.
 */
void esp_panic_handler_increment_entry_count(void)
{
    unsigned int core=(xtensa_read_prid()>>13)&1U;
    unsigned int count=PANIC_ENTRY_COUNTS[core]+1U;
    PANIC_ENTRY_COUNTS[core]=count;
    if (count>=3U) {
        panic_print_str("Panic handler entered multiple times. Abort panic handling. Rebooting ...\r\n");
        panic_restart();
    }
}

/* Native entry: 0x42003288. */
/* Original function-byte SHA-256:
 * bbfc92c82f6b09380c53ba3d2230feba1efdaf294c46ab04e4927952788dae85. */
/* Call the no-OS restart routine with no arguments. If it returns, execute
 * the native illegal instruction. No normal return, watchdog setup, delay,
 * output or recovery is supplied by this wrapper. */
void panic_restart(void)
{
    panic_restart_boundary();
    __asm__ volatile("ill");
    __builtin_unreachable();
}
