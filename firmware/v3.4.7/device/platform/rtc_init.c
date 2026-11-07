/* Medius v3.4.7 device: recovered RTC initialization and voltage trims. */

#include "../include/types.h"

/* reconstruction utilities: expand each native MEMW/read/MEMW/write pair.
 * Always inline so the notation introduces no extra firmware calls. Each
 * invocation performs a fresh read even when adjacent fields share a register. */
static __inline__ __attribute__((always_inline)) void rtc_init_replace_bits(
    volatile unsigned int *register_address,unsigned int clear_mask,unsigned int set_bits)
{
    memw();
    unsigned int previous = *register_address;
    memw();
    *register_address = (previous & ~clear_mask) | set_bits;
}

/* Native entry: 0x42023ac0. */
/*
 * Medius v3.4.7 — device application; 0x42023ac0.
 * Instruction-checked recovered C.
 * Original function-byte SHA-256:
 * ac9a46fca1dd8bd2f2641e65a301d8e976881906318c2f77f7842457d65c85f9.
 */

/* Derive RTC bias code 15..31 for the supplied digital bias word. Read five
 * eFuse words separately, in native order: 0x54,0x54,0x58,0x54,0x58. The RTC
 * voltage correction crosses the 0x54/0x58 boundary, with HIGH read before LOW.
 * Decode slopes as 7-bit sign/magnitude and voltage corrections as 8-bit
 * sign/magnitude; these fields are not two's-complement signed integers.
 *
 * Slopes are 198+RTC and 211+digital; voltage bases are 10181/10841 in units
 * of 1/10000 V, with each stored voltage correction multiplied by 20. Starting
 * at RTC code 15, choose the first code whose estimated RTC voltage reaches
 * digital voltage minus 250 (0.025 V). Compare codes 15..30; if none reaches
 * the threshold, return 31 without another comparison. All final voltage and
 * input-dependent arithmetic wraps as unsigned 32-bit native operations.
 * No eFuse-version validation, saturation of input, write, lock or measurement. */
unsigned int rtc_bias_from_efuse(unsigned int digital_bias)
{
    memw();
    unsigned int rtc_slope_word = RTC_EFUSE_REGISTERS->ldo_low;
    memw();
    unsigned int digital_slope_word = RTC_EFUSE_REGISTERS->ldo_low;
    memw();
    unsigned int rtc_voltage_high = RTC_EFUSE_REGISTERS->ldo_high;
    memw();
    unsigned int rtc_voltage_low = RTC_EFUSE_REGISTERS->ldo_low;
    memw();
    unsigned int digital_voltage_word = RTC_EFUSE_REGISTERS->ldo_high;

    int rtc_slope = (rtc_slope_word >> 13) & 0x7fU;
    int digital_slope = (digital_slope_word >> 20) & 0x7fU;
    int rtc_correction = ((rtc_voltage_high & 7U) << 5) | (rtc_voltage_low >> 27);
    int digital_correction = (digital_voltage_word >> 3) & 0xffU;
    if (rtc_slope & 0x40)
        rtc_slope = -(rtc_slope & 0x3f);
    if (digital_slope & 0x40)
        digital_slope = -(digital_slope & 0x3f);
    if (rtc_correction & 0x80)
        rtc_correction = -(rtc_correction & 0x7f);
    if (digital_correction & 0x80)
        digital_correction = -(digital_correction & 0x7f);
    unsigned int rtc_step = (unsigned int)(rtc_slope + K_RTC_MID_MUL10000);
    unsigned int digital_step = (unsigned int)(digital_slope + K_DIG_MID_MUL10000);
    unsigned int target_voltage = (digital_bias - 20U) * digital_step +
                                  (unsigned int)digital_correction * 20U + (V_DIG_MID_MUL10000 - 250U);
    unsigned int rtc_voltage = (unsigned int)rtc_correction * 20U -
                               5U * rtc_step + V_RTC_MID_MUL10000;
    unsigned int rtc_bias;
    for (rtc_bias = 15; rtc_bias < 31; ++rtc_bias) {
        if (rtc_voltage >= target_voltage)
            break;
        rtc_voltage += rtc_step;
    }
    return rtc_bias;
}

/* Native entry: 0x42023b70. */
/*
 * Medius v3.4.7 — device application; 0x42023b70.
 * Instruction-checked recovered C.
 * Original function-byte SHA-256:
 * 9668c0c7e471e1863db5eb300c66ca08fc0ed9e4fab959805d6ce83aca825134.
 */

/* Initialize RTC power/clock control from the packed 32-bit rtc_config_t ABI.
 * Low byte is RC_FAST wait, byte 2 is PLL wait; XTAL-wait byte 1 and bit 31
 * are unused here. Bits 24..30 select the named options in the public header.
 * Each rtc_init_replace_bits call expands to one fresh native MMIO RMW.
 *
 * Release modem power/isolation first so later WiFi-memory register accesses
 * are possible. Program waits and power-up timers, reset RTC bias to 23, and
 * optionally calibrate bandgap OCode. eFuse major version 1 supplies OCode
 * directly; other versions temporarily lower MSPI clocks, measure a nominal
 * 10 ms slow-clock deadline, save CPU config, switch to XTAL and disable PLL,
 * reset/start analog calibration, then poll BOTH done bits and read RTC time
 * even on success. Timeout only logs at warning level and still restores CPU
 * and MSPI configuration. Deadline addition/comparison is ordinary unsigned
 * 64-bit arithmetic, not a wrap-safe timeout. Readback scratch is uninitialized
 * if CPU-config readback fails; no fabricated fallback is added.
 *
 * When supported eFuses contain a nonzero HVT bias code, derive the 1.3 V
 * digital limit by checking codes 16..30 (31 is the cap), publish digital
 * high/normal words, then derive/publish RTC high/normal words. Otherwise keep
 * the existing trim globals. Apply RTC trim then a FRESH digital trim byte.
 * Optional clock setup releases force-on gates; optional power setup applies
 * XTAL/PLL/boost choices and releases memory/domain overrides. Finally force
 * WiFi modem isolation/power-down, disable/clear RTC interrupts, then initialize
 * SAR FSM control. No whole-operation lock, rollback, status, oscillator-ready
 * guarantee, measured voltage or measured 10 ms bound is supplied. */
void rtc_init(unsigned int configuration_word)
{
    RtcInitRegisters *rtc_registers = RTC_INIT_REGISTERS;
    rtc_init_replace_bits(&rtc_registers->digital_power,0x20000U,0); /* WiFi force PD */
    rtc_init_replace_bits(&rtc_registers->digital_isolation,0x10000000U,0);
    regi2c_ctrl_write_reg_mask(0x6d,1,13,2,2,0);
    regi2c_ctrl_write_reg_mask(0x6d,1,13,3,3,0);
    rtc_init_replace_bits(&rtc_registers->analog,0x4000000U,0); /* PVT monitor */
    rtc_init_replace_bits(&rtc_registers->timer1,0xff000000U,(configuration_word & 0xff0000U) << 8);
    rtc_init_replace_bits(&rtc_registers->timer1,0x3fc0U,(configuration_word & 0xffU) << 6);
    rtc_init_replace_bits(&rtc_registers->timer5,0xff00U,0x200U); /* minimum sleep */
    rtc_init_replace_bits(&rtc_registers->timer3,0xfe00U,0x200U); /* WiFi power-up */
    rtc_init_replace_bits(&rtc_registers->timer3,0x1ffU,1); /* WiFi wait */
    rtc_init_replace_bits(&rtc_registers->timer3,0xfe000000U,0x2000000U); /* BT power-up */
    rtc_init_replace_bits(&rtc_registers->timer3,0x1ff0000U,0x10000U); /* BT wait */
    rtc_init_replace_bits(&rtc_registers->timer6,0xfe00U,0x200U); /* CPU top power-up */
    rtc_init_replace_bits(&rtc_registers->timer6,0x1ffU,1); /* CPU top wait */
    rtc_init_replace_bits(&rtc_registers->timer4,0xfe00U,0x200U); /* RTC power-up */
    rtc_init_replace_bits(&rtc_registers->timer4,0x1ffU,1); /* RTC wait */
    rtc_init_replace_bits(&rtc_registers->timer4,0xfe000000U,0x2000000U); /* digital wrap */
    rtc_init_replace_bits(&rtc_registers->timer4,0x1ff0000U,0x10000U);
    rtc_init_replace_bits(&rtc_registers->timer6,0xfe000000U,0x2000000U); /* digital peri */
    rtc_init_replace_bits(&rtc_registers->timer6,0x1ff0000U,0x10000U);
    regi2c_ctrl_write_reg_mask(0x6d,1,5,4,0,23); /* RTC sleep bias */
    regi2c_ctrl_write_reg_mask(0x6d,1,4,4,0,23); /* RTC active bias */
    rtc_init_replace_bits(&rtc_registers->timer2,0xff8000U,0x80000U); /* ULP/touch wait */

    if (configuration_word & RTC_INIT_CALIBRATE_OCODE) {
        memw();
        unsigned int efuse_major = RTC_EFUSE_REGISTERS->version_major & 3U;
        if (efuse_major == 1U) {
            memw();
            unsigned int ocode = (RTC_EFUSE_REGISTERS->version_major >> 13) & 0xffU;
            regi2c_ctrl_write_reg_mask(0x61,1,6,7,0,ocode);
            regi2c_ctrl_write_reg_mask(0x61,1,5,6,6,1);
        } else {
            mspi_timing_change_speed_mode_cache_safe(1);
            unsigned int slow_source = rtc_clk_slow_src_get();
            unsigned int calibration_clock = slow_source == 1U ? 2 : slow_source == 2U ? 1 : 0;
            unsigned int period_q19 = rtc_clk_cal(calibration_clock,100);
            unsigned long long timeout_ticks = rtc_time_us_to_slowclk(10000,period_q19);
            unsigned long long deadline = timeout_ticks + rtc_time_get();
            RtcCpuFrequencyConfig saved_cpu_configuration;
            rtc_clk_cpu_freq_get_config(&saved_cpu_configuration);
            rtc_clk_cpu_freq_set_xtal();
            regi2c_ctrl_write_reg_mask(0x61,1,0,0,0,0);
            regi2c_ctrl_write_reg_mask(0x61,1,0,0,0,1);
            for (;;) {
                unsigned char ocode_done = regi2c_ctrl_read_reg_mask(0x61,1,3,0,0);
                unsigned char bandgap_done = regi2c_ctrl_read_reg_mask(0x61,1,3,3,3);
                unsigned long long now = rtc_time_get();
                if (ocode_done != 0 && bandgap_done != 0)
                    break;
                if (now >= deadline) {
                    if (SYSTEM_EARLY_LOG_LEVEL >= 2U) {
                        unsigned int timestamp = esp_log_timestamp();
                        ets_printf("W (%lu) %s: o_code calibration fail\n\n",timestamp,"rtcinit");
                    }
                    break;
                }
            }
            rtc_clk_cpu_freq_set_config(&saved_cpu_configuration);
            mspi_timing_change_speed_mode_cache_safe(0);
        }
    }

    memw();
    unsigned int efuse_minor = (RTC_EFUSE_REGISTERS->version_minor >> 24) & 7U;
    memw();
    unsigned int efuse_major = RTC_EFUSE_REGISTERS->version_major & 3U;
    unsigned int rtc_trim_code;
    bool trim_updated = false;
    if (efuse_minor == 1U || efuse_major > 1U || (efuse_minor > 1U && (efuse_major & 1U))) {
        memw();
        unsigned int slope_word = RTC_EFUSE_REGISTERS->ldo_low;
        memw();
        unsigned int voltage_word = RTC_EFUSE_REGISTERS->ldo_high;
        int digital_slope = (slope_word >> 20) & 0x7fU;
        int digital_correction = (voltage_word >> 3) & 0xffU;
        if (digital_slope & 0x40)
            digital_slope = -(digital_slope & 0x3f);
        if (digital_correction & 0x80)
            digital_correction = -(digital_correction & 0x7f);
        unsigned int digital_step = (unsigned int)(digital_slope + K_DIG_MID_MUL10000);
        unsigned int estimated_digital_voltage = (unsigned int)digital_correction * 20U - 5U * digital_step + V_DIG_MID_MUL10000;
        unsigned int digital_limit = 15;
        do {
            ++digital_limit;
            estimated_digital_voltage += digital_step;
            if (digital_limit == 31U)
                break;
        } while (estimated_digital_voltage < 13000U);
        memw();
        unsigned int hvt_bias = (RTC_EFUSE_REGISTERS->ldo_high >> 11) & 0x1fU;
        if (hvt_bias != 0) {
            unsigned int high_bias = hvt_bias + 3U;
            unsigned int normal_bias = hvt_bias + 2U;
            if (high_bias > digital_limit)
                high_bias = digital_limit;
            if (normal_bias > digital_limit)
                normal_bias = digital_limit;
            RTC_CPU_BIAS_WORDS->digital_240 = high_bias;
            RTC_CPU_BIAS_WORDS->digital_non240 = normal_bias;
            unsigned int high_rtc_bias = rtc_bias_from_efuse(high_bias);
            RTC_CPU_BIAS_WORDS->rtc_240 = high_rtc_bias;
            rtc_trim_code = rtc_bias_from_efuse(normal_bias);
            RTC_CPU_BIAS_WORDS->rtc_non240 = rtc_trim_code;
            trim_updated = true;
        }
    }
    if (!trim_updated)
        rtc_trim_code = RTC_CPU_BIAS_CALIBRATION->rtc_non240;
    regi2c_ctrl_write_reg_mask(0x6d,1,4,4,0,(unsigned char)rtc_trim_code);
    regi2c_ctrl_write_reg_mask(0x6d,1,6,4,0,RTC_CPU_BIAS_CALIBRATION->digital_non240);

    if (configuration_word & RTC_INIT_CLOCK_CONTROL) {
        rtc_init_replace_bits(&RTC_CACHE_POWER_REGISTERS->mmu_power,1,0);
        memw();
        SLEEP_SYSCON_REGISTERS->clock_gate_force_on = 0;
        rtc_init_replace_bits(&RTC_CACHE_POWER_REGISTERS->data_tag_power,1,0);
        rtc_init_replace_bits(&RTC_CACHE_POWER_REGISTERS->instruction_tag_power,1,0);
        rtc_init_replace_bits(&MSPI0->clock_gate,1,0);
        rtc_init_replace_bits(&MSPI1->clock_gate,1,0);
    }
    if (configuration_word & RTC_INIT_POWER_CONTROL) {
        rtc_init_replace_bits(&rtc_registers->clock_config,0x4000000U,0); /* RC_FAST force PU */
        unsigned int xtal_force = (configuration_word & (RTC_INIT_XTAL_FORCE_ON |
                                   RTC_INIT_PLL_FORCE_ON)) != 0 ? 0x2000U : 0;
        rtc_init_replace_bits(&rtc_registers->options0,0x2000U,xtal_force);
        rtc_init_replace_bits(&rtc_registers->analog,0x40000U,0); /* SAR I2C POR protection */
        if (configuration_word & RTC_INIT_PLL_FORCE_ON) {
            rtc_init_replace_bits(&rtc_registers->options0,0,0x800U);
            rtc_init_replace_bits(&rtc_registers->options0,0,0x200U);
            rtc_init_replace_bits(&rtc_registers->options0,0,0x80U);
        } else {
            rtc_init_replace_bits(&rtc_registers->options0,0x800U,0);
            rtc_init_replace_bits(&rtc_registers->options0,0x200U,0);
            rtc_init_replace_bits(&rtc_registers->options0,0x80U,0);
        }
        rtc_init_replace_bits(&rtc_registers->rtc_power,0x80000U,0);
        rtc_init_replace_bits(&rtc_registers->regulator,0x80000000U,0);
        rtc_init_replace_bits(&rtc_registers->regulator,0x20000000U,0);
        rtc_init_replace_bits(&rtc_registers->rtc_power,5,0); /* fast/slow memory no-isolation */
        unsigned int boost_down = configuration_word & RTC_INIT_BOOST_FORCE_OFF ? 0x10000000U : 0;
        rtc_init_replace_bits(&rtc_registers->regulator,0x10000000U,boost_down);
        rtc_init_replace_bits(&rtc_registers->analog,0x40000U,0);
        rtc_init_replace_bits(&RTC_CPU_SYSTEM_REGISTERS->memory_power_mask,1,0);
        rtc_sleep_pu(0);
        rtc_init_replace_bits(&rtc_registers->digital_power,0x100000U,0); /* digital wrap */
        rtc_init_replace_bits(&rtc_registers->digital_isolation,0xc0000000U,0);
        rtc_init_replace_bits(&rtc_registers->digital_isolation,0x30000000U,0); /* WiFi */
        rtc_init_replace_bits(&rtc_registers->digital_power,0x40000U,0);
        rtc_init_replace_bits(&rtc_registers->digital_isolation,0xc00000U,0); /* Bluetooth */
        rtc_init_replace_bits(&rtc_registers->digital_power,0x1000U,0);
        rtc_init_replace_bits(&rtc_registers->digital_isolation,0xc000000U,0); /* CPU top */
        rtc_init_replace_bits(&rtc_registers->digital_power,0x400000U,0);
        rtc_init_replace_bits(&rtc_registers->digital_isolation,0x3000000U,0); /* digital peri */
        rtc_init_replace_bits(&rtc_registers->digital_power,0x4000U,0);
        rtc_init_replace_bits(&rtc_registers->rtc_power,0x20U,0);
        rtc_init_replace_bits(&rtc_registers->rtc_power,0x10U,0);
        rtc_init_replace_bits(&rtc_registers->rtc_power,0x80000U,0);
        unsigned int wait_force = configuration_word & RTC_INIT_CPU_WAIT_GATE ? 0 : 8;
        rtc_init_replace_bits(&RTC_CPU_SYSTEM_REGISTERS->cpu_period,8,wait_force);
        rtc_init_replace_bits(&rtc_registers->digital_isolation,0x4000U,0); /* pad unhold */
        rtc_init_replace_bits(&rtc_registers->digital_isolation,0x1000U,0); /* pad no-isolation */
    }
    rtc_init_replace_bits(&rtc_registers->digital_isolation,0,0x10000000U);
    rtc_init_replace_bits(&rtc_registers->digital_power,0,0x20000U);
    memw();
    rtc_registers->interrupt_enable = 0;
    memw();
    rtc_registers->interrupt_clear = 0xffffffffU;
    sar_periph_ctrl_init();
}

/* Native entry: 0x42024278. */
/*
 * Medius v3.4.7 — device application; 0x42024278.
 * Instruction-checked recovered C.
 * Original function-byte SHA-256:
 * d638203b279ad581a4115e1e430da8fc4408b411ec4a833e4084ba27ea6d1de4.
 */

/* Enable the SAR ADC peripheral clock (bit 30), then release the two-bit
 * force-power override (bits 29..30) to the SAR hardware FSM. Separate fresh
 * MEMW/read/MEMW/write pairs preserve all unrelated SENS bits. No conversion
 * start, SAR reference count, peripheral lock, ready wait or return status.
 * The original decompiler misidentified the 0x40000000 mask as a ROM symbol. */
void sar_periph_ctrl_init(void)
{
    rtc_init_replace_bits(&RTC_SAR_REGISTERS->peripheral_clock,0,0x40000000U);
    rtc_init_replace_bits(&RTC_SAR_REGISTERS->power,0x60000000U,0);
}
