/* Medius v3.4.7 device — panic watchdog and re-entry control. */
#include "../include/types.h"

/* Native entry: 0x42003040. */
/* Original function-byte SHA-256:
 * 662e314eb7a32fb61aea3ec1044554858fc8342291e079e008eceb2849401142. */
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

/* Native entry: 0x420030c8. */
/* Original function-byte SHA-256:
 * 19ebf2c95b885940971f702e16e0d9d3992ddb0f8971789a45d081c647d19e5a. */

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

/* Native entry: 0x42003114. */
/* Original function-byte SHA-256:
 * d17269e4a8c1b9ab8f3ba7b9388ab44975424476026d4cfa5290633a911c7f73. */

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

/* Native entry: 0x4200316c. */
/* Original function-byte SHA-256:
 * 39c84fd0ce712f97ac97cefb33d2af98d2b42e43fad068d57fe840f0286ec84b. */

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

/* Native entry: 0x42003188. */
/* Original function-byte SHA-256:
 * d5c9d79819774ffcabc68bdd68b52dd84210c90337d5a90f1055d5bd4fd3177f. */
/*
 * Select this core using PRID bit13, load its panic count, add1 modulo32 and
 * store it before testing the new value. Counts>=3 trigger a panic restart;
 * wrapped0 does not. This is a plain load/store increment with no lock, CAS,
 * MEMW or saturation, and does not alter the other core's count.
 * This image performs no diagnostic-output call on the recursive-panic path.
 */
void esp_panic_handler_increment_entry_count(void)
{
    unsigned int core=(xtensa_read_prid()>>13)&1U;
    unsigned int count=PANIC_ENTRY_COUNTS[core]+1U;
    PANIC_ENTRY_COUNTS[core]=count;
    if (count>=3U) {
        panic_restart();
    }
}

/* Native entry: 0x42003554. */
/* Original function-byte SHA-256:
 * 9570629b6528cd26323214df191fff9b0f02dfc7163e3e6e7d6b20027d7b0903. */
/* Call the no-OS restart routine with no arguments. If it returns, execute
 * the native illegal instruction. No normal return, watchdog setup, delay,
 * output or recovery is supplied by this wrapper. */
void panic_restart(void)
{
    panic_restart_boundary();
    __asm__ volatile("ill");
    __builtin_unreachable();
}
