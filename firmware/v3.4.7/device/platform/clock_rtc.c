/* Medius v3.4.7 device: recovered RTC clocks and calibration. */

#include "../include/types.h"

/* Native entry: 0x403846a0. */
/*
 * Medius v3.4.7 — device application; 0x403846a0.
 * Instruction-checked recovered C.
 * Original function-byte SHA-256:
 * f47555735a07fd20b59058317bc776fcd95e674856acd890a4de3bc5f4a4292d.
 */

/* Treat the LOW BYTE of each argument as truth. Enable RC_FAST by clearing
 * disable bit6 and selecting TIMER1 wait5; request a50us ROM delay only on this
 * path. Disable instead sets bit6 and wait20. Independently configure divide-
 * by256 enable via inverse bit7 afterward, using a FRESH clock-conf read even
 * after delay. Native separate MEMW/RMWs preserve unrelated bits. No lock,
 * digital-gate bit9 update, reference counting or measured-delay guarantee. */
void rtc_clk_8m_enable(unsigned char fast_enabled,unsigned char divided_enabled)
{
    RtcCalibrationClockRegisters *clocks = RTC_CALIBRATION_CLOCK_REGISTERS;
    memw();
    unsigned int clock_conf = clocks->clock_conf;
    if (fast_enabled) {
        memw();
        clocks->clock_conf = clock_conf & ~0x40U;
        memw();
        unsigned int wait = clocks->timer1;
        memw();
        clocks->timer1 = (wait & 0xffffc03fU) | 0x140U;
        esp_rom_delay_us(50);
    } else {
        memw();
        clocks->clock_conf = clock_conf | 0x40U;
        memw();
        unsigned int wait = clocks->timer1;
        memw();
        clocks->timer1 = (wait & 0xffffc03fU) | 0x500U;
    }
    memw();
    clock_conf = clocks->clock_conf;
    if (divided_enabled) {
        memw();
        clocks->clock_conf = clock_conf & ~0x80U;
    } else {
        memw();
        clocks->clock_conf = clock_conf | 0x80U;
    }
}

/* Native entry: 0x403847f4. */
/*
 * Medius v3.4.7 — device application; 0x403847f4.
 * Instruction-checked recovered C.
 * Original function-byte SHA-256:
 * 28aefe9ec92715b30e41753a237536d676c470d22184445f3a33474d5257e21a.
 */

/* MEMW/read RTC clock-conf bits30..31: return RC_SLOW0, XTAL32K1 or RC_FAST_D2562.
 * Reserved code3 aborts. The original void declaration lost this return value.
 * No write, lock, calibration, frequency conversion or fresh wait is supplied. */
unsigned int rtc_clk_slow_src_get(void)
{
    memw();
    unsigned int source = RTC_CALIBRATION_CLOCK_REGISTERS->clock_conf >> 30;
    if (source == 3U)
        abort();
    return source;
}

/* Native entry: 0x40384880. */
/*
 * Medius v3.4.7 — device application; 0x40384880.
 * Instruction-checked recovered C.
 * Original function-byte SHA-256:
 * c904ced354aa04357f62b8696334b7883c6985e92c7eef60b6d8970aea44b9f1.
 */

/* MEMW/read stored XTAL frequency word. Require identical16-bit copies and
 * exclude all-zero/all-one words; clear low bit0 before interpreting MHz.
 * A resulting zero is also invalid. Invalid storage optionally logs a warning
 * when live early-log level>=2, then returns40MHz. Valid nonzero EVEN values
 * are returned without a whitelist; no physical frequency measurement/refresh,
 * register repair or lock. The bit0 storage flag is not a fractional MHz bit. */
unsigned int rtc_clk_xtal_freq_get(void)
{
    memw();
    unsigned int stored = RTC_CALIBRATION_CLOCK_REGISTERS->xtal_store;
    if ((stored & 0xffffU) == (stored >> 16) && stored != 0 && stored != 0xffffffffU) {
        unsigned int mhz = stored & 0xfffeU;
        if (mhz != 0)
            return mhz;
    }
    if (SYSTEM_EARLY_LOG_LEVEL >= 2U) {
        unsigned int timestamp = esp_log_timestamp();
        ets_printf("W (%lu) %s: invalid RTC_XTAL_FREQ_REG value, assume 40MHz\n",
                   timestamp,RTC_CLOCK_LOG_TAG);
    }
    return 40;
}

/* Native entry: 0x40385048. */
/*
 * Medius v3.4.7 — device application; 0x40385048.
 * Instruction-checked recovered C.
 * Original function-byte SHA-256:
 * 5b933833537e93c3608d3f9cee52271c40f8d3107351967f75956f4c9b5ad09f.
 */

/* Count XTAL cycles over requested slow-clock cycles using TIMG0 calibration.
 * Selection MUX0 follows current RTC slow source (0slow,1XTAL32K,2fast/256);
 * INTERNAL3 explicitly chooses slow0. Other selection values are accepted:
 * hardware CLK_SEL receives low2 bits, but timeout/cleanup use the full value.
 * Sample digital32k gate, RC_FAST disable, then /256 disable in separate fresh
 * reads. Temporarily enable missing32k gate, or force RC_FAST+/256 and digital
 * gate9 for selection1. If cycling is active, install threshold1 and wait for
 * READY or hardware timeout; no software deadline. Program selection, disable
 * cycling, MAX=cycles low15. Timeout threshold uses FULL cycles<<19 for32k/
 * fast256, else<<17, with unsigned32 truncation. Toggle START clear then set;
 * ROM divide computes low32 floor(cycles*1000000/expected_hz), then ROM delay.
 * Poll READY before timeout. READY returns config1>>7, timeout returns0. Clear
 * START, remove only the32k gate added here, or clear digital/256 gate9 and
 * restore saved RC_FAST+/256 enables. Native read/write/barrier and cleanup
 * order retained; common setup reads are factored across equivalent branches.
 * No caller serialization, cycle-count/selection validation or guaranteed
 * wall-clock timeout: a stuck peripheral can leave either polling loop stuck. */
unsigned int rtc_clk_cal_internal(unsigned int selection,unsigned int cycles)
{
    RtcCalibrationClockRegisters *clocks = RTC_CALIBRATION_CLOCK_REGISTERS;
    RtcCalibrationTimerRegisters *timer = RTC_CALIBRATION_TIMER_REGISTERS;
    if (selection == RTC_CAL_RTC_MUX) {
        unsigned int slow_source = rtc_clk_slow_src_get();
        if (slow_source == 1U)
            selection = RTC_CAL_32K_XTAL;
        else if (slow_source == 2U)
            selection = RTC_CAL_8MD256;
    } else if (selection == RTC_CAL_INTERNAL_OSC) {
        selection = RTC_CAL_RTC_MUX;
    }
    memw();
    unsigned int gate_snapshot = clocks->clock_conf;
    bool added_32k_gate = selection == RTC_CAL_32K_XTAL &&
                           (gate_snapshot & 0x100U) == 0;
    if (added_32k_gate) {
        memw();
        unsigned int live = clocks->clock_conf;
        memw();
        clocks->clock_conf = live | 0x100U;
    }
    memw();
    unsigned char saved_fast = ((clocks->clock_conf >> 6) & 1U) ^ 1U;
    memw();
    unsigned char saved_divided = ((clocks->clock_conf >> 7) & 1U) ^ 1U;
    if (selection == RTC_CAL_8MD256) {
        rtc_clk_8m_enable(1,1);
        memw();
        unsigned int live = clocks->clock_conf;
        memw();
        clocks->clock_conf = live | 0x200U;
    }
    memw();
    unsigned int configuration = timer->configuration;
    if (configuration & 0x1000U) {
        memw();
        unsigned int timeout = timer->timeout;
        memw();
        timer->timeout = (timeout & 0xffU) | 0x80U;
        for (;;) {
            memw();
            if (timer->configuration & 0x8000U)
                break;
            memw();
            if (timer->timeout & 1U)
                break;
        }
    }
    memw();
    configuration = timer->configuration;
    memw();
    timer->configuration = (configuration & 0xffff9fffU) | ((selection & 3U) << 13);
    memw();
    configuration = timer->configuration;
    memw();
    timer->configuration = configuration & ~0x1000U;
    memw();
    configuration = timer->configuration;
    memw();
    timer->configuration = (configuration & 0x8000ffffU) | ((cycles & 0x7fffU) << 16);
    memw();
    unsigned int timeout = timer->timeout;
    unsigned int expected_hz;
    unsigned int threshold;
    if (selection == RTC_CAL_32K_XTAL) {
        threshold = cycles << 19;
        expected_hz = 32768;
    } else if (selection == RTC_CAL_8MD256) {
        threshold = cycles << 19;
        expected_hz = 68359;
    } else {
        threshold = cycles << 17;
        expected_hz = 136000;
    }
    memw();
    timer->timeout = (timeout & 0x7fU) | threshold;
    memw();
    configuration = timer->configuration;
    memw();
    timer->configuration = configuration & ~0x80000000U;
    memw();
    configuration = timer->configuration;
    memw();
    timer->configuration = configuration | 0x80000000U;
    unsigned int estimated_us = (unsigned int)rom_unsigned_divide_u64(
        (unsigned long long)cycles * 1000000ULL,expected_hz);
    esp_rom_delay_us(estimated_us);
    unsigned int measured;
    for (;;) {
        memw();
        if (timer->configuration & 0x8000U) {
            memw();
            measured = timer->value >> 7;
            break;
        }
        memw();
        if (timer->timeout & 1U) {
            measured = 0;
            break;
        }
    }
    memw();
    configuration = timer->configuration;
    memw();
    timer->configuration = configuration & ~0x80000000U;
    if (added_32k_gate) {
        memw();
        unsigned int live = clocks->clock_conf;
        memw();
        clocks->clock_conf = live & ~0x100U;
    } else if (selection == RTC_CAL_8MD256) {
        memw();
        unsigned int live = clocks->clock_conf;
        memw();
        clocks->clock_conf = live & ~0x200U;
        rtc_clk_8m_enable(saved_fast,saved_divided);
    }
    return measured;
}

/* Native entry: 0x403852f8. */
/*
 * Medius v3.4.7 — device application; 0x403852f8.
 * Instruction-checked recovered C.
 * Original function-byte SHA-256:
 * d596b70d215f3fc022ce4c25bbc88472b9259149b87977758b0c30d5d4d6cca2.
 */

/* Return Q19 microseconds per calibrated slow-clock tick, or0 on rejected32k
 * crystal measurement. cycles must be nonzero or assert. Read stored XTAL MHz
 * (with getter fallback), then perform hardware calibration. ONLY original
 * selection2 applies nominal32768Hz +/- floor(expected/2000) XTAL-cycle bounds;
 * MUX0 remapped to32k internally does not enable this check. Inclusive bounds.
 * Use uint64 modulo arithmetic for expected=(MHz*cycles*1000000)>>15 and final
 * ((measured<<19)+(MHz*cycles)/2-1)/(MHz*cycles); return LOW32 of quotient.
 * Native ROM divisions remain explicit and ordered. No cached calibration
 * publication, saturation, physical timing verification or per-call lock. */
unsigned int rtc_clk_cal(unsigned int selection,unsigned int cycles)
{
    if (cycles == 0)
        __assert_func(0,0,0,0);
    unsigned int xtal_mhz = rtc_clk_xtal_freq_get();
    unsigned int measured = rtc_clk_cal_internal(selection,cycles);
    unsigned long long divider = (unsigned long long)xtal_mhz * cycles;
    if (selection == RTC_CAL_32K_XTAL) {
        unsigned long long expected = (divider * 1000000ULL) >> 15;
        unsigned long long tolerance = rom_unsigned_divide_u64(expected,2000);
        if ((unsigned long long)measured < expected - tolerance ||
            (unsigned long long)measured > expected + tolerance)
            return 0;
    }
    unsigned long long numerator = ((unsigned long long)measured << 19) +
                                    (divider >> 1) - 1U;
    return (unsigned int)rom_unsigned_divide_u64(numerator,divider);
}

/* Native entry: 0x40384650. */
/*
 * Medius v3.4.7 — device application; 0x40384650.
 * Instruction-checked recovered C.
 * Original function-byte SHA-256:
 * d7f320ba8c7a010f87a734efb3793d68ebf5f6693878c80b1e9b028b529579cd.
 */

/* Disable-only entry: clear GPIO15 IO_MUX input-enable bit9, release its RTC
 * pad-hold bit15, force32k crystal power control to software (EXT_XTL_CONF7),
 * then clear crystal power bit16 via a FRESH read of the same register. Four
 * separate MEMW/RMWs preserve unrelated bits and native order. No argument
 * read, delay, clock-source switch, lock, status or restoration of pad input.
 * Matches rtc_clk_32k_disable_external in ESP-IDF ESP32-S3 rtc_clk.c,
 * including GPIO15/pad-hold cleanup before its inline crystal-disable step. */
void rtc_clk_32k_disable_external(void)
{
    memw();
    unsigned int pad = RTC_XTAL32K_INPUT_PAD;
    memw();
    RTC_XTAL32K_INPUT_PAD = pad & ~0x200U;
    memw();
    unsigned int held = RTC_CALIBRATION_CLOCK_REGISTERS->pad_hold;
    memw();
    RTC_CALIBRATION_CLOCK_REGISTERS->pad_hold = held & ~0x8000U;
    memw();
    unsigned int power = RTC_CALIBRATION_CLOCK_REGISTERS->xtal_control;
    memw();
    RTC_CALIBRATION_CLOCK_REGISTERS->xtal_control = power | 0x80U;
    memw();
    power = RTC_CALIBRATION_CLOCK_REGISTERS->xtal_control;
    memw();
    RTC_CALIBRATION_CLOCK_REGISTERS->xtal_control = power & ~0x10000U;
}

/* Native entry: 0x40384728. */
/*
 * Medius v3.4.7 — device application; 0x40384728.
 * Instruction-checked recovered C.
 * Original function-byte SHA-256:
 * fa5225e49dc1dfc594b7103efaaf7ac842c7f846aec3df27c504327a2b13c29c.
 */

/* MEMW/read inverse disable bit7 in RTC clock-conf and return normalized bool.
 * Reflects oscillator /256 enable, not digital gate9, selected RTC source or
 * measured clock activity. No lock, write, delay or reference-count query. */
bool rtc_clk_8md256_enabled(void)
{
    memw();
    return ((RTC_CALIBRATION_CLOCK_REGISTERS->clock_conf >> 7) & 1U) == 0;
}

/* Native entry: 0x40384814. */
/*
 * Medius v3.4.7 — device application; 0x40384814.
 * Instruction-checked recovered C.
 * Original function-byte SHA-256:
 * 521e296248be7c4f1503354d2610068433043be8ef38e218e6c197a22ea5193a.
 */

/* MEMW/read current slow source bits30..31. Return nominal Hz: RC_SLOW0=136000,
 * XTAL32K1=32768, RC_FAST_D2562=68359; reserved3 aborts. These are fixed nominal
 * constants, not a calibrated frequency or timer measurement. No lock/write. */
unsigned int rtc_clk_slow_freq_get_hz(void)
{
    memw();
    unsigned int source = RTC_CALIBRATION_CLOCK_REGISTERS->clock_conf >> 30;
    if (source == 1U)
        return 32768;
    if (source == 2U)
        return 68359;
    if (source == 0)
        return 136000;
    abort();
}

/* Native entry: 0x4038483c. */
/*
 * Medius v3.4.7 — device application; 0x4038483c.
 * Instruction-checked recovered C.
 * Original function-byte SHA-256:
 * 4cdf456e3241de0bdd049c68f904850fe5c42e894ef4c1428fcbf868896a4d2b.
 */

/* Select RTC fast clock: XTAL_D2 source0 clears clock-conf bit29; RC_FAST1
 * sets it. Other values abort BEFORE any MMIO or delay. Each admitted path
 * uses a fresh MEMW/read/MEMW/write and requests a3us ROM delay afterward.
 * Does not enable/check the oscillator, lock, restore old source or verify
 * stabilization; the delay request is not a measured hardware timing result. */
void rtc_clk_fast_src_set(unsigned int source)
{
    if (source == 0) {
        memw();
        unsigned int config = RTC_CALIBRATION_CLOCK_REGISTERS->clock_conf;
        memw();
        RTC_CALIBRATION_CLOCK_REGISTERS->clock_conf = config & ~0x20000000U;
    } else if (source == 1U) {
        memw();
        unsigned int config = RTC_CALIBRATION_CLOCK_REGISTERS->clock_conf;
        memw();
        RTC_CALIBRATION_CLOCK_REGISTERS->clock_conf = config | 0x20000000U;
    } else {
        abort();
    }
    esp_rom_delay_us(3);
}

/* Native entry: 0x403848c0. */
/*
 * Medius v3.4.7 — device application; 0x403848c0.
 * Instruction-checked recovered C.
 * Original function-byte SHA-256:
 * d86771a7091db9b4515d1cd6f918d301e74af00f9b5637cf448ded077a76961a.
 */

/* Derive a CPU clock description without applying it. Always read stored XTAL
 * MHz first (including getter warning/fallback). Requests1..XTAL use XTAL0:
 * divider=floor(XTAL/request), then require rounded(XTAL/divider)==request.
 * Only requests beyond this XTAL branch may use PLL1 at480MHz for80/160/240,
 * with dividers6/3/2. Other requests return false and leave output untouched.
 * Thus an unusually high stored XTAL value takes precedence over PLL choices.
 * On success write source,source-MHz,divider,CPU-MHz in that exact word order,
 * then return true. Output must be writable16-byte config; no NULL check,
 * allocation, clock/PLL switch, register write, lock or timer adjustment. */
bool rtc_clk_cpu_freq_mhz_to_config(unsigned int requested_mhz,RtcCpuFrequencyConfig *configuration)
{
    unsigned int xtal_mhz = rtc_clk_xtal_freq_get();
    unsigned int source;
    unsigned int source_mhz;
    unsigned int divider;
    if (requested_mhz - 1U < xtal_mhz) {
        divider = xtal_mhz / requested_mhz;
        if ((xtal_mhz + (divider >> 1)) / divider != requested_mhz)
            return false;
        source = 0;
        source_mhz = xtal_mhz;
    } else {
        if (requested_mhz == 80U)
            divider = 6;
        else if (requested_mhz == 160U)
            divider = 3;
        else if (requested_mhz == 240U)
            divider = 2;
        else
            return false;
        source = 1;
        source_mhz = 480;
    }
    volatile RtcCpuFrequencyConfig *output = configuration;
    output->source = source;
    output->source_mhz = source_mhz;
    output->divider = divider;
    output->cpu_mhz = requested_mhz;
    return true;
}

/* Native entry: 0x40384740. */
/*
 * Medius v3.4.7 — device application; 0x40384740.
 * Instruction-checked recovered C.
 * Original function-byte SHA-256:
 * c22d874ca0cb5cbed4c98079382e5e637ba150fbcce81a01a78a044f9aec44fb.
 */

/* Select RTC slow source0=RC_SLOW,1=XTAL32K,2=RC_FAST_D256. For source2 borrow
 * the unlocked submode counter array; if mode0 count is exactly0, activate it
 * once (ignore API status). Other sources FORCE-CLEAR mode0 BEFORE validating
 * source, so an invalid source still clears that sleep reference then aborts.
 * Update clock-conf source bits30..31, then fresh RMW digital32k gate8 (set
 * only for source1). Request ROM delay300us after admitted updates. No whole-
 * operation lock, oscillator start, reference rollback or measured stability;
 * PM counter locking does not serialize the subsequent hardware RMWs. */
void rtc_clk_slow_src_set(unsigned int source)
{
    if (source == 2U) {
        int *counts = esp_sleep_sub_mode_dump_config(NULL);
        if (*(volatile int *)&counts[ESP_SLEEP_RTC_USE_RC_FAST_MODE] == 0)
            (void)esp_sleep_sub_mode_config(ESP_SLEEP_RTC_USE_RC_FAST_MODE,1);
        memw();
        unsigned int config = RTC_CALIBRATION_CLOCK_REGISTERS->clock_conf;
        memw();
        RTC_CALIBRATION_CLOCK_REGISTERS->clock_conf = (config & 0x3fffffffU) | 0x80000000U;
    } else {
        (void)esp_sleep_sub_mode_force_disable(ESP_SLEEP_RTC_USE_RC_FAST_MODE);
        if (source == 0) {
            memw();
            unsigned int config = RTC_CALIBRATION_CLOCK_REGISTERS->clock_conf;
            memw();
            RTC_CALIBRATION_CLOCK_REGISTERS->clock_conf = config & 0x3fffffffU;
        } else if (source == 1U) {
            memw();
            unsigned int config = RTC_CALIBRATION_CLOCK_REGISTERS->clock_conf;
            memw();
            RTC_CALIBRATION_CLOCK_REGISTERS->clock_conf = (config & 0x3fffffffU) | 0x40000000U;
            memw();
            config = RTC_CALIBRATION_CLOCK_REGISTERS->clock_conf;
            memw();
            RTC_CALIBRATION_CLOCK_REGISTERS->clock_conf = config | 0x100U;
            esp_rom_delay_us(300);
            return;
        } else {
            abort();
        }
    }
    memw();
    unsigned int config = RTC_CALIBRATION_CLOCK_REGISTERS->clock_conf;
    memw();
    RTC_CALIBRATION_CLOCK_REGISTERS->clock_conf = config & ~0x100U;
    esp_rom_delay_us(300);
}

/* Native entry: 0x40384920. */
/*
 * Medius v3.4.7 — device application; 0x40384920.
 * Instruction-checked recovered C.
 * Original function-byte SHA-256:
 * cc741599a5ba98094e4167bd3c8e02c23bc326f4f50032ded831b3b7139ea5d6.
 */

/* Read CPU source bits10..11 from SYSCLK_CONF. XTAL0 takes a SECOND fresh
 * SYSCLK word before the XTAL-MHz getter, then divides by low10+1. PLL1 reads
 * CPU_PER_CONF TWICE: first low2 period bits, then PLL320/480 bit2. Report80MHz
 * at div4/6,160MHz at div2/3,or240MHz only for PLL480 at div2. RC_FAST2 reports
 * nominal20MHz/div1 without measuring it. Reserved source3,period3 or240/320
 * logs conditionally and returns WITHOUT touching output or giving status.
 * Success writes four words source/sourceMHz/divider/CPU-MHz in native order.
 * Output must cover16 writable bytes. No lock, coherent multi-register snapshot,
 * calibration or hardware change; mixed live PLL reads are intentionally kept. */
void rtc_clk_cpu_freq_get_config(RtcCpuFrequencyConfig *configuration)
{
    memw();
    unsigned int source = (RTC_CPU_SYSTEM_REGISTERS->system_clock >> 10) & 3U;
    unsigned int source_mhz;
    unsigned int divider;
    unsigned int cpu_mhz;
    if (source == 0) {
        memw();
        unsigned int divided_clock = RTC_CPU_SYSTEM_REGISTERS->system_clock;
        source_mhz = rtc_clk_xtal_freq_get();
        divider = (divided_clock & 0x3ffU) + 1U;
        cpu_mhz = source_mhz / divider;
    } else if (source == 1U) {
        memw();
        unsigned int period = RTC_CPU_SYSTEM_REGISTERS->cpu_period & 3U;
        memw();
        unsigned int pll_word = RTC_CPU_SYSTEM_REGISTERS->cpu_period;
        bool pll480 = (pll_word & 4U) != 0;
        if (period == 0) {
            cpu_mhz = 80;
            divider = pll480 ? 6 : 4;
            source_mhz = pll480 ? 480 : 320;
        } else if (period == 1U) {
            cpu_mhz = 160;
            divider = pll480 ? 3 : 2;
            source_mhz = pll480 ? 480 : 320;
        } else if (period == 2U && pll480) {
            cpu_mhz = 240;
            divider = 2;
            source_mhz = 480;
        } else {
            goto unsupported_configuration;
        }
    } else if (source == 2U) {
        cpu_mhz = 20;
        divider = 1;
        source_mhz = 20;
    } else {
        goto unsupported_configuration;
    }
    volatile RtcCpuFrequencyConfig *output = configuration;
    output->source = source;
    output->source_mhz = source_mhz;
    output->divider = divider;
    output->cpu_mhz = cpu_mhz;
    return;
unsupported_configuration:
    if (SYSTEM_EARLY_LOG_LEVEL != 0) {
        unsigned int timestamp = esp_log_timestamp();
        ets_printf("E (%lu) %s: unsupported frequency configuration\n",
                   timestamp,RTC_CLOCK_LOG_TAG);
    }
}

/* Native entry: 0x40384bb0. */
/*
 * Medius v3.4.7 — device application; 0x40384bb0.
 * Instruction-checked recovered C.
 * Original function-byte SHA-256:
 * 5635f9e4e4a41db02d5b13b4f89abc2205670242edcea967294f31e1115d9a45.
 */

/* Switch CPU to XTAL using unchecked target MHz and divider. Read prior CPU
 * config into UNINITIALIZED scratch, then update ROM CPU ticks/us BEFORE
 * clearing divider. Divider0 aborts only AFTER that ROM update and first
 * SYSCLK RMW. Otherwise set low10=(divider-1)&0x3ff, then clear source bits10..11.
 * Read saved prior-MHz scratch word and publish targetMHz*1000000 modulo32 to
 * APB-frequency cache. Unsupported readback leaves scratch unwritten: the
 * explicit instruction load preserves that unchecked native stack read instead
 * of inventing a default or permitting C undefined-value propagation.
 * Prior240MHz lowers RTC then digital bias through FRESH byte trim reads/I2C
 * writes, then requests40us ROM delay. Finally set DATE slave-power bits13..18
 * to7 via fresh RMW. No per-call lock, PLL disable, target validation, scheduler
 * timer correction or measured settling guarantee. No error status is returned. */
void rtc_clk_cpu_freq_to_xtal(unsigned int target_mhz,unsigned int divider)
{
    RtcCpuFrequencyConfig previous;
    rtc_clk_cpu_freq_get_config(&previous);
    esp_rom_set_cpu_ticks_per_us(target_mhz);
    memw();
    unsigned int system_clock = RTC_CPU_SYSTEM_REGISTERS->system_clock;
    memw();
    RTC_CPU_SYSTEM_REGISTERS->system_clock = system_clock & ~0x3ffU;
    if (divider == 0)
        abort();
    memw();
    system_clock = RTC_CPU_SYSTEM_REGISTERS->system_clock;
    memw();
    RTC_CPU_SYSTEM_REGISTERS->system_clock = (system_clock & ~0x3ffU) | ((divider - 1U) & 0x3ffU);
    memw();
    system_clock = RTC_CPU_SYSTEM_REGISTERS->system_clock;
    memw();
    RTC_CPU_SYSTEM_REGISTERS->system_clock = system_clock & ~0xc00U;
    unsigned int previous_mhz;
    __asm__ volatile ("l32i %0,%1,12" : "=a"(previous_mhz) : "a"(&previous) : "memory");
    RTC_CACHED_APB_HZ = target_mhz * 1000000U;
    if (previous_mhz == 240U) {
        regi2c_ctrl_write_reg_mask(0x6d,1,4,4,0,RTC_CPU_BIAS_CALIBRATION->rtc_non240);
        regi2c_ctrl_write_reg_mask(0x6d,1,6,4,0,RTC_CPU_BIAS_CALIBRATION->digital_non240);
        esp_rom_delay_us(40);
    }
    memw();
    unsigned int date = RTC_CPU_DATE_REGISTER;
    memw();
    RTC_CPU_DATE_REGISTER = (date & 0xfff81fffU) | 0xe000U;
}

/* Native entry: 0x40384e4c. */
/*
 * Medius v3.4.7 — device application; 0x40384e4c.
 * Instruction-checked recovered C.
 * Original function-byte SHA-256:
 * 5c0b920f2652801c46cb84a79a37243b8d9895a606a40ddd7ea7f9bf83943912.
 */

/* Query stored XTAL MHz (including getter fallback) and switch CPU to it with
 * divider1 through the XTAL-switch helper. No additional register operation,
 * PLL disable, status, lock or validation is supplied by this wrapper. */
void rtc_clk_cpu_set_to_default_config(void)
{
    unsigned int xtal_mhz = rtc_clk_xtal_freq_get();
    rtc_clk_cpu_freq_to_xtal(xtal_mhz,1);
}

/* Native entry: 0x40384e5c. */
/*
 * Medius v3.4.7 — device application; 0x40384e5c.
 * Instruction-checked recovered C.
 * Original function-byte SHA-256:
 * 6eeaef368a0e523cebc1fc39bf43785a40b12e4f67dc73f3717ddbad6e38f29f.
 */

/* Switch CPU to stored XTAL MHz/div1, then MEMW/read OPTIONS0 and MEMW/write
 * OR0x540 to force BB I2C,BBPLL andBBPLL I2C power-down. Only afterward publish
 * cached PLL frequency0. Does not check shared PLL consumer references, wait
 * for a power-down acknowledgement, lock or restore the old configuration. */
void rtc_clk_cpu_freq_set_xtal(void)
{
    unsigned int xtal_mhz = rtc_clk_xtal_freq_get();
    rtc_clk_cpu_freq_to_xtal(xtal_mhz,1);
    memw();
    unsigned int options = RTC_OPTIONS0_REGISTER;
    memw();
    RTC_OPTIONS0_REGISTER = options | 0x540U;
    RTC_CACHED_PLL_MHZ = 0;
}

/* Native entry: 0x403849d4. */
/*
 * Medius v3.4.7 — device application; 0x403849d4.
 * Instruction-checked recovered C.
 * Original function-byte SHA-256:
 * dfe11fbbffa58ccf539a07cc79c51a68eb9ca49593fd606f109d15d5f2d71f72.
 */

/* Switch the CPU to an already enabled PLL at 80, 160 or 240 MHz.
 * Save the previous CPU frequency, initializing ONLY that scratch word to zero
 * before readback. The signed target/80 quotient selects the LDO slave mask;
 * native SSR uses its low five bits, including for invalid negative bit patterns.
 * On an increase, apply the slave mask before changing clocks. Entering 240 MHz
 * first writes the two high-voltage trim BYTES and requests a 40 us ROM delay.
 * An invalid increasing target can therefore change DATE before aborting.
 *
 * Set CPU period, clear the divider, select PLL, cache APB at 80 MHz, then update
 * ROM CPU ticks/us. On a decrease from 240 MHz, write the two non-240 trim bytes
 * and request 40 us before updating the slave mask. Each MMIO RMW uses a fresh
 * read; the trim reads also remain separated by their analog-register calls.
 * No PLL enable/calibration, whole-operation lock, timer adjustment or status.
 * Delay arguments describe requests, not measured voltage-settling times. */
void rtc_clk_cpu_freq_to_pll_mhz(unsigned int target_mhz)
{
    int slave_shift = (int)target_mhz / 80;
    unsigned int power_down_slaves = 7U >> ((unsigned int)slave_shift & 31U);
    RtcCpuFrequencyConfig previous;
    previous.cpu_mhz = 0;
    rtc_clk_cpu_freq_get_config(&previous);
    unsigned int previous_mhz = previous.cpu_mhz;

    if (previous_mhz < target_mhz) {
        if (target_mhz == 240U) {
            regi2c_ctrl_write_reg_mask(0x6d,1,4,4,0,RTC_CPU_BIAS_CALIBRATION->rtc_240);
            regi2c_ctrl_write_reg_mask(0x6d,1,6,4,0,RTC_CPU_BIAS_CALIBRATION->digital_240);
            esp_rom_delay_us(40);
        }
        memw();
        unsigned int date = RTC_CPU_DATE_REGISTER;
        memw();
        RTC_CPU_DATE_REGISTER = (date & 0xfff81fffU) | (power_down_slaves << 13);
    }

    unsigned int period;
    if (target_mhz == 80U)
        period = 0;
    else if (target_mhz == 160U)
        period = 1;
    else if (target_mhz == 240U)
        period = 2;
    else
        abort();

    memw();
    unsigned int cpu_period = RTC_CPU_SYSTEM_REGISTERS->cpu_period;
    memw();
    RTC_CPU_SYSTEM_REGISTERS->cpu_period = (cpu_period & ~3U) | period;
    memw();
    unsigned int system_clock = RTC_CPU_SYSTEM_REGISTERS->system_clock;
    memw();
    RTC_CPU_SYSTEM_REGISTERS->system_clock = system_clock & ~0x3ffU;
    memw();
    system_clock = RTC_CPU_SYSTEM_REGISTERS->system_clock;
    memw();
    RTC_CPU_SYSTEM_REGISTERS->system_clock = (system_clock & ~0xc00U) | 0x400U;
    RTC_CACHED_APB_HZ = 80000000;
    esp_rom_set_cpu_ticks_per_us(target_mhz);

    if (previous_mhz > target_mhz) {
        if (previous_mhz == 240U) {
            regi2c_ctrl_write_reg_mask(0x6d,1,4,4,0,RTC_CPU_BIAS_CALIBRATION->rtc_non240);
            regi2c_ctrl_write_reg_mask(0x6d,1,6,4,0,RTC_CPU_BIAS_CALIBRATION->digital_non240);
            esp_rom_delay_us(40);
        }
        memw();
        unsigned int date = RTC_CPU_DATE_REGISTER;
        memw();
        RTC_CPU_DATE_REGISTER = (date & 0xfff81fffU) | (power_down_slaves << 13);
    }
}

/* Native entry: 0x40384c60. */
/*
 * Medius v3.4.7 — device application; 0x40384c60.
 * Instruction-checked recovered C.
 * Original function-byte SHA-256:
 * 3e9c7ba65c0297b9d92987f647b49aa65a9f1ea9bd3ec26603597d069b7c5cc3.
 */

/* Apply a readable 16-byte CPU clock configuration. Read source once, then
 * read the live hardware source. XTAL source 0 reads divider before CPU MHz and
 * delegates switching; only a prior PLL source permits conditional power-down.
 * A single consumer-count read decides that shutdown, and its saved zero is
 * copied to the PLL cache AFTER the OPTIONS0 RMW; there is no second count read.
 *
 * PLL source 1 skips PLL setup entirely when hardware already selects PLL,
 * even if requested source_mhz differs. Otherwise power up PLL before reading
 * XTAL and requested source MHz. Accept 320/480, select the digital PLL bit,
 * start analog calibration and write the native coefficient table. XTAL 32 MHz
 * has special coefficients; every other stored XTAL value uses the 40 MHz case.
 * Poll CAL_DONE with a fresh MEMW/read on EVERY iteration, without a timeout.
 * Request 10 us, stop calibration using two separate RMWs, cache PLL MHz, then
 * freshly read CPU MHz and switch CPU frequency. Divider is ignored on PLL.
 *
 * Invalid PLL MHz aborts AFTER power-up and the XTAL getter. RC_FAST source 2
 * takes the native fatal assertion; other source codes return without changes.
 * Input must stay readable through the calls; there is no NULL check, input
 * snapshot, whole-operation lock, rollback or success/error return. Individual
 * analog writes lock internally; they do not serialize this complete sequence. */
void rtc_clk_cpu_freq_set_config(const RtcCpuFrequencyConfig *configuration)
{
    const volatile RtcCpuFrequencyConfig *input = configuration;
    unsigned int source = input->source;
    memw();
    unsigned int previous_source = (RTC_CPU_SYSTEM_REGISTERS->system_clock >> 10) & 3U;
    if (source == 0) {
        unsigned int divider = input->divider;
        unsigned int target_mhz = input->cpu_mhz;
        rtc_clk_cpu_freq_to_xtal(target_mhz,divider);
        if (previous_source == 1U) {
            unsigned int consumers = RTC_PLL_CONSUMER_COUNT;
            if (consumers == 0) {
                memw();
                unsigned int options = RTC_OPTIONS0_REGISTER;
                memw();
                RTC_OPTIONS0_REGISTER = options | 0x540U;
                RTC_CACHED_PLL_MHZ = consumers;
            }
        }
        return;
    }
    if (source != 1U) {
        if (source == 2U)
            __assert_func(0,0,0,0);
        return;
    }

    if (previous_source != 1U) {
        memw();
        unsigned int options = RTC_OPTIONS0_REGISTER;
        memw();
        RTC_OPTIONS0_REGISTER = options & ~0x540U;
        unsigned int xtal_mhz = rtc_clk_xtal_freq_get();
        unsigned int pll_mhz = input->source_mhz;
        unsigned char reference_and_charge_pump;
        unsigned char feedback_divider;
        unsigned char drive_strength;
        unsigned char reference_current;
        unsigned char mode;

        if (pll_mhz == 320U) {
            memw();
            unsigned int period = RTC_CPU_SYSTEM_REGISTERS->cpu_period;
            memw();
            RTC_CPU_SYSTEM_REGISTERS->cpu_period = period & ~4U;
            mode = 0x69;
        } else if (pll_mhz == 480U) {
            memw();
            unsigned int period = RTC_CPU_SYSTEM_REGISTERS->cpu_period;
            memw();
            RTC_CPU_SYSTEM_REGISTERS->cpu_period = period | 4U;
            mode = 0x6b;
        } else {
            abort();
        }
        memw();
        unsigned int analog = RTC_PLL_ANALOG_CONFIGURATION;
        memw();
        RTC_PLL_ANALOG_CONFIGURATION = analog & ~4U;
        memw();
        analog = RTC_PLL_ANALOG_CONFIGURATION;
        memw();
        RTC_PLL_ANALOG_CONFIGURATION = analog | 8U;

        if (pll_mhz == 320U) {
            reference_and_charge_pump = xtal_mhz == 32U ? 0x51 : 0x50;
            feedback_divider = xtal_mhz == 32U ? 6 : 4;
            drive_strength = 0;
            reference_current = 0x73;
        } else if (xtal_mhz == 32U) {
            reference_and_charge_pump = 0x41;
            feedback_divider = 26;
            drive_strength = 1;
            reference_current = 0x70;
        } else {
            reference_and_charge_pump = 0x50;
            feedback_divider = 8;
            drive_strength = 0;
            reference_current = 0x73;
        }
        regi2c_ctrl_write_reg(0x66,1,4,mode);
        regi2c_ctrl_write_reg(0x66,1,2,reference_and_charge_pump);
        regi2c_ctrl_write_reg(0x66,1,3,feedback_divider);
        regi2c_ctrl_write_reg_mask(0x66,1,5,2,0,drive_strength);
        regi2c_ctrl_write_reg_mask(0x66,1,5,6,4,drive_strength);
        regi2c_ctrl_write_reg(0x66,1,6,reference_current);
        regi2c_ctrl_write_reg_mask(0x66,1,9,1,0,3);
        do {
            memw();
            analog = RTC_PLL_ANALOG_CONFIGURATION;
        } while ((analog & 0x1000000U) == 0);
        esp_rom_delay_us(10);
        memw();
        analog = RTC_PLL_ANALOG_CONFIGURATION;
        memw();
        RTC_PLL_ANALOG_CONFIGURATION = analog & ~8U;
        memw();
        analog = RTC_PLL_ANALOG_CONFIGURATION;
        memw();
        RTC_PLL_ANALOG_CONFIGURATION = analog | 4U;
        RTC_CACHED_PLL_MHZ = pll_mhz;
    }
    unsigned int target_mhz = input->cpu_mhz;
    rtc_clk_cpu_freq_to_pll_mhz(target_mhz);
}

/* Native entry: 0x40375c60. */
/*
 * Medius v3.4.7 — device application; 0x40375c60.
 * Instruction-checked recovered C.
 * Original function-byte SHA-256:
 * 18b7f18e6055de58c3800f386c30f6a0ce35c22a698e69a8439e75c78088b616.
 */

/* Save the current clock configuration in uninitialized stack scratch. Only
 * a saved PLL source (1) causes XTAL switching with unconditional PLL power-down,
 * followed by applying the saved configuration to recalibrate/restart the PLL.
 * Other saved source words return. Unsupported readback can leave scratch
 * unwritten: the explicit native load retains that unchecked read instead of
 * inventing an initial source or allowing C indeterminate-value optimization.
 * No added lock, validation, status, PLL consumer check or restoration guarantee.
 * The C compiler chooses scratch placement; unknown stack contents are not
 * claimed to match a particular hardware execution. */
void rtc_reconfigure_active_pll(void)
{
    RtcCpuFrequencyConfig saved;
    rtc_clk_cpu_freq_get_config(&saved);
    unsigned int saved_source;
    __asm__ volatile ("l32i %0,%1,0" : "=a"(saved_source) : "a"(&saved) : "memory");
    if (saved_source == 1U) {
        rtc_clk_cpu_freq_set_xtal();
        rtc_clk_cpu_freq_set_config(&saved);
    }
}

/* Native entry: 0x40384584. */
/*
 * Medius v3.4.7 — device application; 0x40384584.
 * Instruction-checked recovered C.
 * Original function-byte SHA-256:
 * b1841705384f7f7d3769f6b2f013b01c49620ad32e0706fd2ae79f73077dbb5f.
 */

/* Treat the LOW BYTE as truth when enabling/disabling the 32 kHz crystal.
 * Enable selects RTC mux bit 19 on GPIO15/16, clears external-clock select,
 * sets DAC/DRES/DGM to 3 and DBUF to 1, then sets crystal power bit 16.
 * Disable first forces software power control (bit 7), then clears power.
 * Every update is a separate fresh MEMW/read/MEMW/write. Enable preserves the
 * software-force bit and disable leaves RTC mux/tuning settings in place.
 * This is oscillator configuration, not RTC slow-source selection. No startup
 * wait, ready poll, clock calibration, pad restoration, lock or status. */
void rtc_clk_32k_enable(unsigned char enabled)
{
    if (enabled) {
        memw();
        unsigned int pad = RTC_XTAL32K_PAD_REGISTERS->positive;
        memw();
        RTC_XTAL32K_PAD_REGISTERS->positive = pad | 0x80000U;
        memw();
        pad = RTC_XTAL32K_PAD_REGISTERS->negative;
        memw();
        RTC_XTAL32K_PAD_REGISTERS->negative = pad | 0x80000U;
        memw();
        unsigned int crystal = RTC_CALIBRATION_CLOCK_REGISTERS->xtal_control;
        memw();
        RTC_CALIBRATION_CLOCK_REGISTERS->xtal_control = crystal & ~0x800000U;
        memw();
        crystal = RTC_CALIBRATION_CLOCK_REGISTERS->xtal_control;
        memw();
        RTC_CALIBRATION_CLOCK_REGISTERS->xtal_control = (crystal & ~0xe0000U) | 0x60000U;
        memw();
        crystal = RTC_CALIBRATION_CLOCK_REGISTERS->xtal_control;
        memw();
        RTC_CALIBRATION_CLOCK_REGISTERS->xtal_control = (crystal & ~0xe000U) | 0x6000U;
        memw();
        crystal = RTC_CALIBRATION_CLOCK_REGISTERS->xtal_control;
        memw();
        RTC_CALIBRATION_CLOCK_REGISTERS->xtal_control = (crystal & ~0x1c00U) | 0xc00U;
        memw();
        crystal = RTC_CALIBRATION_CLOCK_REGISTERS->xtal_control;
        memw();
        RTC_CALIBRATION_CLOCK_REGISTERS->xtal_control = crystal | 0x200U;
        memw();
        crystal = RTC_CALIBRATION_CLOCK_REGISTERS->xtal_control;
        memw();
        RTC_CALIBRATION_CLOCK_REGISTERS->xtal_control = crystal | 0x10000U;
    } else {
        memw();
        unsigned int crystal = RTC_CALIBRATION_CLOCK_REGISTERS->xtal_control;
        memw();
        RTC_CALIBRATION_CLOCK_REGISTERS->xtal_control = crystal | 0x80U;
        memw();
        crystal = RTC_CALIBRATION_CLOCK_REGISTERS->xtal_control;
        memw();
        RTC_CALIBRATION_CLOCK_REGISTERS->xtal_control = crystal & ~0x10000U;
    }
}
