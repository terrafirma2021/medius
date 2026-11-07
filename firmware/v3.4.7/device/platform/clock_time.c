/* Medius v3.4.7 device: recovered timekeeping and native clock boundaries. */

#include "../include/types.h"

/* Native entry: 0x403770f8. */
/* Original function-byte SHA-256:
 * fe5602a4c79ff0f39dfbe45462c770be41de62a8107e6a3fa28fef65ad9fcfa9. */
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

/* Native entry: 0x40377120. */
/* Original function-byte SHA-256:
 * 7be785bc340f5618905dcfdc25af7cc5224bc3e342253899b491f9e3ca28131a. */
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

/* Native entry: 0x403770dc. */
/* Original function-byte SHA-256:
 * 4fce75c1b88aa11a2d33ac7c865bca8a6e1593d0a5d4054bc8d9b8fb6b01a68a. */
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

/* Native entry: 0x40385398. */
/*
 * Medius v3.4.7 — device application; 0x40385398.
 * Instruction-checked recovered C.
 * Original function-byte SHA-256:
 * 6a25314d1ca0dbba8447702c9be60c10ac67a183db348e964de045ac164ac292.
 */

/* Convert unsigned64 microseconds to RTC slow-clock ticks using a nonzero
 * calibration period in Q19 microseconds/tick. Zero period asserts. For inputs
 * whose left shift fits64, return (time<<19)/period. Larger inputs calculate
 * remainder's fractional ticks first, then add (whole quotient<<19), avoiding
 * overflow of the initial time shift. Native unsigned64 shift/add wrap and
 * integer truncation remain; an oversized final tick result is not saturated.
 * ROM remainder and division calls remain explicit in their native order.
 * No timer read, scheduling delay, calibration refresh or rounding-to-nearest. */
unsigned long long rtc_time_us_to_slowclk(unsigned long long time_in_us,
                                         unsigned int period_q19)
{
    if (period_q19 == 0)
        __assert_func(0,0,0,0);
    if (time_in_us <= (0xffffffffffffffffULL >> 19))
        return rom_unsigned_divide_u64(time_in_us << 19,period_q19);
    unsigned long long remainder = rom_unsigned_remainder_u64(time_in_us,period_q19);
    unsigned long long fractional_ticks = rom_unsigned_divide_u64(remainder << 19,period_q19);
    unsigned long long whole = rom_unsigned_divide_u64(time_in_us,period_q19);
    return fractional_ticks + (whole << 19);
}

/* Native entry: 0x40385414. */
/*
 * Medius v3.4.7 — device application; 0x40385414.
 * Instruction-checked recovered C.
 * Original function-byte SHA-256:
 * 36c19304de5f80e4ef7a8c2736fb082698c130b0a9c4ce28a345bce4b8ff8486.
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

/* Native entry: 0x4038543c. */
/*
 * Medius v3.4.7 — device application; 0x4038543c.
 * Instruction-checked recovered C.
 * Original function-byte SHA-256:
 * 9743ef19aec6e0069b9646e24a573ee0c303e3fb646011dcd4ef6c1a61058676.
 */

/* Return floor((1000000<<19)/calibration) truncated to unsigned32, or0 when
 * calibration is0. Normally calibration is Q19 microseconds/tick and result
 * is Hz; the SDK frequency-to-period alias uses the same reciprocal formula.
 * Division uses a64-bit numerator; no clock read, validation or saturation. */
unsigned int rtc_clk_freq_cal(unsigned int calibration)
{
    if (calibration == 0)
        return 0;
    return (unsigned int)rom_unsigned_divide_u64(1000000ULL << 19,calibration);
}

/* Native entry: 0x40385458. */
/*
 * Medius v3.4.7 — device application; 0x40385458.
 * Instruction-checked recovered C.
 * Original function-byte SHA-256:
 * b1b6cae8450e570a2450410c925fb8247b9384fa929ca6aa94bdfbb0213dc66a.
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

/* Native entry: 0x42017bb4. */
/* Original function-byte SHA-256:
 * 775a1a9902b4acc9b4d914127123e13e7b8c8b0690cb4b0e74fadcd41f04acca. */
/* Read the peripheral's cached RC_FAST frequency once. Zero is returned
 * unchanged when no frequency has been recorded. No calibration, enabling,
 * reference-count change, lock, MEMW or live frequency measurement occurs. */
unsigned int periph_rtc_dig_clk8m_get_freq(void)
{
    return RTC_DIGITAL_RC_FAST_FREQUENCY_HZ;
}

/* Native entry: 0x42007a98. */
/* Original function-byte SHA-256:
 * 9aef6e90793a4b429ad1e03c295fd043a147dbf9688c3e4614bd97c3781cd5c1. */
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
