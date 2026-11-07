/* Medius v3.4.7 host: recovered timekeeping and native clock boundaries. */

#include "../include/types.h"

/* Native entry: 0x40376d80. */
/* Original function-byte SHA-256:
 * 9637d72a8507bef894079608f419370856532f6b1ce7fa31d5b5b609153e4735. */
/* Cache the SYSTIMER register base, then MEMW/read INT_CLR (+0x6c), OR alarm2
 * mask 0x4, and MEMW/write it back. Only after that store, load the current upper
 * alarm-handler pointer and call it with the original argument. No NULL check,
 * local lock, pending-loop or status result. This is a hardware-alarm ISR entry;
 * upper-layer dispatch policy is outside this wrapper. */
void timer_alarm_isr(void *argument)
{
    volatile unsigned int *regs = ((const volatile SystimerHal *)CLOCK_HAL)->dev;
    memw();
    unsigned int clear = regs[27];
    memw();
    regs[27] = clear | 4U;
    ClockAlarmHandler handler = *CLOCK_ALARM_HANDLER;
    handler(argument);
}

/* Native entry: 0x40376da8. */
/* Original function-byte SHA-256:
 * 6c367eac918f3a060dc8071c7d03476cb7b30336662d09c6564ae2fd07d4e7c4. */
/* Cache the configured ticks_to_us callback BEFORE reading hardware counter0
 * through systimer_hal_get_counter_value. Pass its unsigned64 ticks to that
 * cached callback and return both result words as signed64 microseconds. No
 * callback/context validation, local lock or extra MEMW is added. The counter
 * reader supplies its native snapshot polling; conversion can change elsewhere
 * without changing this call's cached function pointer. */
long long esp_timer_get_time(void)
{
    SystimerHal *hal = CLOCK_HAL;
    SystimerConvert convert = ((const volatile SystimerHal *)hal)->ticks_to_us;
    unsigned long long ticks = systimer_hal_get_counter_value(hal,0);
    return (long long)convert(ticks);
}

/* Native entry: 0x40376d64. */
/* Original function-byte SHA-256:
 * 89c7208ce080c8ed8f89adce3dae1c3c3e0e8d822279d61212988af3ad911406. */
/* Sample esp_timer_get_time, then read the system correction LOW before HIGH.
 * Add the two native words modulo64 and return their signed64 interpretation.
 * No lock, retry, overflow trap or extra hardware fence is supplied. A correction
 * change between its two reads can produce a mixed pair; preserve those reads. */
long long esp_system_get_time(void)
{
    unsigned long long timer = (unsigned long long)esp_timer_get_time();
    unsigned int low = CLOCK_SYSTEM_CORRECTION->low;
    unsigned int high = CLOCK_SYSTEM_CORRECTION->high;
    return (long long)(timer + (((unsigned long long)high << 32) | low));
}

/* Native entry: 0x40380ac4. */
/*
 * Medius v3.4.7 — host application; 0x40380ac4.
 * Instruction-checked recovered C.
 * Original function-byte SHA-256:
 * 8d36073922439aadc9f1ceafb0b26c6c1e07749a8bf1752224701aed05f818f1.
 */

/* Convert unsigned64 microseconds to RTC slow-clock ticks using a nonzero
 * calibration period in Q19 microseconds/tick. Zero period asserts. For inputs
 * whose left shift fits64, return (time<<19)/period. Larger inputs calculate
 * remainder's fractional ticks first, then add (whole quotient<<19), avoiding
 * overflow of the initial time shift. Native unsigned64 shift/add wrap and
 * integer truncation remain; an oversized final tick result is not saturated.
 * No timer read, scheduling delay, calibration refresh or rounding-to-nearest. */
unsigned long long rtc_time_us_to_slowclk(unsigned long long time_in_us,
                                         unsigned int period_q19)
{
    if (period_q19 == 0)
        __assert_func(0,0,0,0);
    if (time_in_us <= (0xffffffffffffffffULL >> 19))
        return (time_in_us << 19) / period_q19;
    unsigned long long remainder = time_in_us % period_q19;
    unsigned long long fractional_ticks = (remainder << 19) / period_q19;
    unsigned long long whole = time_in_us / period_q19;
    return fractional_ticks + (whole << 19);
}

/* Native entry: 0x40380b40. */
/*
 * Medius v3.4.7 — host application; 0x40380b40.
 * Instruction-checked recovered C.
 * Original function-byte SHA-256:
 * 971fcfc2b9d4de84d69f706be24e2b8e457c35e72edb47aa1794d5e1ef5aa14b.
 */

/* Request RTC counter snapshot by MEMW/read TIME_UPDATE then MEMW/write with
 * UPDATE bit31 set. MEMW/read LOW then MEMW/read HIGH and concatenate all32
 * bits of each register. Hardware exposes a48-bit timer, but this entry does
 * not mask high reserved bits, poll a completion flag, lock or retry. Returns
 * raw RTC ticks, without microsecond conversion or task scheduling. */
unsigned long long rtc_time_get(void)
{
    RtcTimeSnapshotRegisters *registers = RTC_TIME_SNAPSHOT_REGISTERS;
    memw();
    unsigned int update = registers->update;
    memw();
    registers->update = update | 0x80000000U;
    memw();
    unsigned int low = registers->low;
    memw();
    unsigned int high = registers->high;
    return ((unsigned long long)high << 32) | low;
}

/* Native entry: 0x40380b68. */
/*
 * Medius v3.4.7 — host application; 0x40380b68.
 * Instruction-checked recovered C.
 * Original function-byte SHA-256:
 * 7b497cf15a92323967a0a9a9d30d9a4673b94320200b6d76c29b1f539dc5949a.
 */

/* Return floor((1000000<<19)/calibration) truncated to unsigned32, or0 when
 * calibration is0. Normally calibration is Q19 microseconds/tick and result
 * is Hz; the SDK frequency-to-period alias uses the same reciprocal formula.
 * Division uses a64-bit numerator; no clock read, validation or saturation. */
unsigned int rtc_clk_freq_cal(unsigned int calibration)
{
    if (calibration == 0)
        return 0;
    return (unsigned int)((1000000ULL << 19) / calibration);
}

/* Native entry: 0x40380b84. */
/*
 * Medius v3.4.7 — host application; 0x40380b84.
 * Instruction-checked recovered C.
 * Original function-byte SHA-256:
 * e68e4f23b7d6c1124dac8fcb66c4d8a78128f8b4c646735be6e20eca40c5aaae.
 */

/* Startup constructor acquires the RCC ownership/refcount guard for TIMG0
 * (module10). Only when the returned previous byte count is0, enable bus clock
 * bit13, assert then clear reset bit13 using fresh RMWs, and clear watchdog
 * flash-boot-protection bit14. All four RMWs retain native MEMW read/write
 * order. Always release RCC guard with the saved reference count, including
 * already-owned case. Leaves clock enabled; no calibration measurement, delay,
 * interrupt setup or write-protection unlock is performed by this body. */
void enable_timer_group0_for_calibration(void)
{
    unsigned char references = periph_rcc_acquire_enter(10);
    if (references == 0) {
        memw();
        unsigned int clocks = WATCHDOG_SYSTEM_CLOCK_REGISTERS->peripheral_clock_enable0;
        memw();
        WATCHDOG_SYSTEM_CLOCK_REGISTERS->peripheral_clock_enable0 = clocks | 0x2000U;
        memw();
        unsigned int reset = WATCHDOG_SYSTEM_CLOCK_REGISTERS->peripheral_reset_enable0;
        memw();
        WATCHDOG_SYSTEM_CLOCK_REGISTERS->peripheral_reset_enable0 = reset | 0x2000U;
        memw();
        reset = WATCHDOG_SYSTEM_CLOCK_REGISTERS->peripheral_reset_enable0;
        memw();
        WATCHDOG_SYSTEM_CLOCK_REGISTERS->peripheral_reset_enable0 = reset & ~0x2000U;
        memw();
        unsigned int watchdog = CALIBRATION_TIMER_GROUP0_REGISTERS->watchdog_config0;
        memw();
        CALIBRATION_TIMER_GROUP0_REGISTERS->watchdog_config0 = watchdog & ~0x4000U;
    }
    periph_rcc_acquire_exit(10,references);
}

/* Native entry: 0x42013bc0. */
/* Original function-byte SHA-256:
 * 18cb8ae55cfee48d9a0d74b9223d1dfeca31d0b2e15d9e2c2166e939cec41f6b. */
/* Read the peripheral's cached RC_FAST frequency once. Zero is returned
 * unchanged when no frequency has been recorded. No calibration, enabling,
 * reference-count change, lock, MEMW or live frequency measurement occurs. */
unsigned int periph_rtc_dig_clk8m_get_freq(void)
{
    return RTC_DIGITAL_RC_FAST_FREQUENCY_HZ;
}

/* Native entry: 0x420074cc. */
/* Original function-byte SHA-256:
 * 698b2499d7547d3e72af820dea1aa349438dc176ba099abd784c02106cf07c45. */
/*
 * Samples RTC time, startup timestamp LOW/HIGH, then esp_timer_get_time.
 * Stores correction = RTC - startup - timer modulo64, HIGH WORD before LOW.
 * Registers esp_sync_timekeeping_timers as a shutdown handler after publication;
 * on any nonzero registration status logs one warning and returns normally.
 * No lock, retry, boot-offset update, hardware counter write or task creation.
 */
void esp_timer_impl_init_system_time(void)
{
    unsigned long long rtc_us = esp_rtc_get_time_us();
    unsigned int startup_low = TIME_STARTUP_WORDS->low;
    unsigned int startup_high = TIME_STARTUP_WORDS->high;
    unsigned long long startup_us = ((unsigned long long)startup_high << 32) | startup_low;
    unsigned long long elapsed_rtc = rtc_us - startup_us;
    unsigned long long timer_us = (unsigned long long)esp_timer_get_time();
    unsigned long long correction = elapsed_rtc - timer_us;
    CLOCK_SYSTEM_CORRECTION->high = (unsigned int)(correction >> 32);
    CLOCK_SYSTEM_CORRECTION->low = (unsigned int)correction;
    int status = esp_register_shutdown_handler(esp_sync_timekeeping_timers);
    if (status != 0) {
        unsigned int timestamp = esp_log_timestamp();
        esp_log_write(2,"system_time","W (%lu) %s: Register shutdown handler failed, err = 0x%x\n",
            timestamp,"system_time",status);
    }
}
