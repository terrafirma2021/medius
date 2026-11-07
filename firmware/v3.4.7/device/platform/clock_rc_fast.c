/* Medius v3.4.7 device — platform/clock_rc_fast.c.
 */

#include "../include/types.h"

/* Digital RC_FAST calibration uses the shared clock-tree API. */

/* Native entry: 0x42017b58. */
/*
 * Medius v3.4.7 — device application; 0x42017b58.
 * Instruction-checked recovered C.
 * Original function-byte SHA-256:
 * 09beed1f7a476cf0a45973589af51935bc78a957e52f3177cf6eb6d40ff196ba.
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
    (void)xPortEnterCriticalTimeout(RTC_DIGITAL_RC_FAST_LOCK, -1);
    unsigned int reference_count = RTC_DIGITAL_RC_FAST_REFERENCE_COUNT;
    if (reference_count == 0) {
        rtc_dig_clk8m_enable();
        unsigned int frequency_hz = esp_clk_tree_rc_fast_get_freq_hz(
            ESP_CLK_TREE_SRC_FREQ_PRECISION_EXACT);
        RTC_DIGITAL_RC_FAST_FREQUENCY_HZ = frequency_hz;
        if (frequency_hz == 0) {
            rtc_dig_clk8m_disable();
            vPortExitCritical(RTC_DIGITAL_RC_FAST_LOCK);
            return false;
        }
        /* The native success path reloads the count after calibration. */
        reference_count = RTC_DIGITAL_RC_FAST_REFERENCE_COUNT;
    }
    RTC_DIGITAL_RC_FAST_REFERENCE_COUNT = (unsigned char)(reference_count + 1U);
    vPortExitCritical(RTC_DIGITAL_RC_FAST_LOCK);
    return true;
}

/* Native entry: 0x42021444. */
/*
 * Medius v3.4.7 — device application; 0x42021444.
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

/* Native entry: 0x40384e88. */
/*
 * Medius v3.4.7 — device application; 0x40384e88.
 * Instruction-checked recovered C.
 * Original function-byte SHA-256:
 * 77bd31fcf3b072e81eedc1f6294bb85baece27466f64e61d0955fb846261974a.
 */

/* Read/OR RTC digital-clock bit10 at0x60008074, with MEMW before read/write,
 * then call the ROM delay for5us. Repeats even when already enabled. No reference
 * count, calibration, lock or status polling; delay timing is not verified here. */
void rtc_dig_clk8m_enable(void)
{
    memw();
    unsigned int clock_configuration = RTC_DIGITAL_CLOCK_REGISTER;
    memw();
    RTC_DIGITAL_CLOCK_REGISTER = clock_configuration | 0x400U;
    esp_rom_delay_us(5U);
}

/* Native entry: 0x40384ea8. */
/*
 * Medius v3.4.7 — device application; 0x40384ea8.
 * Instruction-checked recovered C.
 * Original function-byte SHA-256:
 * 1887dc85a812a89c29af2bdbd1fe4158fa3effd5de0acfddd92f4e8d26dff2bb.
 */

/* Read/clear RTC digital-clock bit10 at0x60008074, with MEMW before read/write,
 * then invoke ROM delay5us even if already disabled. No refcount, calibration,
 * status polling or lock. This documents the call, not measured physical time. */
void rtc_dig_clk8m_disable(void)
{
    memw();
    unsigned int clock_configuration = RTC_DIGITAL_CLOCK_REGISTER;
    memw();
    RTC_DIGITAL_CLOCK_REGISTER = clock_configuration & 0xfffffbffU;
    esp_rom_delay_us(5U);
}
