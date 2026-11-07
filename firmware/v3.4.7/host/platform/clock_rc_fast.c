/* Medius v3.4.7 host — platform/clock_rc_fast.c.
 */

#include "../include/types.h"

/* Digital RC_FAST calibration uses the shared clock-tree API. */

/* Native entry: 0x42013b64. */
/*
 * Medius v3.4.7 — host application; 0x42013b64.
 * Instruction-checked recovered C.
 * Original function-byte SHA-256:
 * 4f6958036e06632a56753527874d7e2e79630afb43a36579959049e85967cdea.
 */

/* Under peripheral RTC mux, sample the8-bit reference count. On zero, enable
 * digital RC_FAST and calibrate at exact precision2; publish resulting frequency.
 * Zero frequency disables digital clock, unlocks and returns false without
 * incrementing. Success RELOADS count after calibration; an initially nonzero
 * count reuses its first snapshot. Increment modulo256, unlock, return true.
 * No overflow guard or recalibration when initially referenced. Caller owns
 * matching release and handling failure; this can wrap255 references to0. */
bool periph_rtc_dig_clk8m_enable(void)
{
    (void)xPortEnterCriticalTimeout(RTC_DIGITAL_RC_FAST_LOCK,-1);
    unsigned int references=RTC_DIGITAL_RC_FAST_REFERENCE_COUNT;
    if (references==0) {
        rtc_dig_clk8m_enable();
        unsigned int frequency=esp_clk_tree_rc_fast_get_freq_hz(2);
        RTC_DIGITAL_RC_FAST_FREQUENCY_HZ=frequency;
        if (frequency==0) {
            rtc_dig_clk8m_disable();
            vPortExitCritical(RTC_DIGITAL_RC_FAST_LOCK);
            return false;
        }
        references=RTC_DIGITAL_RC_FAST_REFERENCE_COUNT;
    }
    RTC_DIGITAL_RC_FAST_REFERENCE_COUNT=(unsigned char)(references+1U);
    vPortExitCritical(RTC_DIGITAL_RC_FAST_LOCK);
    return true;
}

/* Native entry: 0x4201ebd8. */
/*
 * Medius v3.4.7 — host application; 0x4201ebd8.
 * Instruction-checked recovered C.
 * Original function-byte SHA-256:
 * 92c9598ac7519d458b9e367d0d7b28064c9bff38bae50b088825d1dda27f16a4.
 */

/* This ESP32-S3 image's generic clock-source enable hook is a no-op: ignore
 * source/enable arguments and return ESP_OK(0). No validation, register access,
 * lock, refcount, delay or source-frequency calibration occurs here. */
int esp_clk_tree_enable_src(unsigned int source_clock,bool enable)
{
    (void)source_clock;
    (void)enable;
    return 0;
}

/* Native entry: 0x403805b4. */
/*
 * Medius v3.4.7 — host application; 0x403805b4.
 * Instruction-checked recovered C.
 * Original function-byte SHA-256:
 * db58f51705fca9e596781821b171071a9dd02fc2d58efd5814b6c19580400776.
 */

/* Read/OR RTC digital-clock bit10 at0x60008074, with MEMW before read/write,
 * then call the ROM delay for5us. Repeats even when already enabled. No reference
 * count, calibration, lock or status polling; delay timing is not verified here. */
void rtc_dig_clk8m_enable(void)
{
    memw(); unsigned int setting=RTC_DIGITAL_CLOCK_REGISTER;
    memw(); RTC_DIGITAL_CLOCK_REGISTER=setting|0x400U;
    esp_rom_delay_us(5);
}

/* Native entry: 0x403805d4. */
/*
 * Medius v3.4.7 — host application; 0x403805d4.
 * Instruction-checked recovered C.
 * Original function-byte SHA-256:
 * 28f272dcf51983d061e951c1eac7ef907c2452118c1d51dab70d072d989c3c99.
 */

/* Read/clear RTC digital-clock bit10 at0x60008074, with MEMW before read/write,
 * then invoke ROM delay5us even if already disabled. No refcount, calibration,
 * status polling or lock. This documents the call, not measured physical time. */
void rtc_dig_clk8m_disable(void)
{
    memw(); unsigned int setting=RTC_DIGITAL_CLOCK_REGISTER;
    memw(); RTC_DIGITAL_CLOCK_REGISTER=setting&0xfffffbffU;
    esp_rom_delay_us(5);
}
