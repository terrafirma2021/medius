/* Medius v3.4.7 device — platform/clock.c.
 * Recovered C and native assembly, grouped for source navigation.
 * Original entry addresses, firmware-byte hashes and function comments follow.
 */

#include "../include/types.h"

/* Native entry: 0x40376b88. */
/* Original function-byte SHA-256:
 * 85f03b1aeca27b8e9c3c18432503b7ea58a10469562a7352594b953fb3fa0d0a. */
/*
 * Queries ISR context, discards that result, then calls the common port
 * critical-section entry with the peripheral clock/reset mux and -1 timeout.
 * The acquisition result is discarded and the lock is left held on return.
 * No local ISR branch, clock write or reset is performed; pair with exit.
 */
void periph_rcc_enter(void)
{
    (void)xPortInIsrContext();
    (void)xPortEnterCriticalTimeout(PERIPHERAL_RCC_LOCK, -1);
}

/* Native entry: 0x40376b9c. */
/* Original function-byte SHA-256:
 * 3b2f949e017dc927f26d07a5d52e603d40ea21dc6f6dd44d0648c10c9a437902. */
/*
 * Queries ISR context and discards its result, then calls the common port
 * critical-section exit for the peripheral clock/reset mux. The caller must
 * hold this mux on the current CPU. No local ISR dispatch or register write.
 */
void periph_rcc_exit(void)
{
    (void)xPortInIsrContext();
    vPortExitCritical(PERIPHERAL_RCC_LOCK);
}

/* Native entry: 0x40376c60. */
/*
 * Medius v3.4.7 — device application; 0x40376c60.
 *
 * Serializes a ROM internal analog-register masked read using the REGI2C spinlock. Forwards five
 * byte-sized block/host/register/bit-range arguments, preserves the low-byte result across
 * unlock, and returns it. This wrapper supplies no argument validation or error/timeout result.
 *
 * Calls: xPortInIsrContext, rom_i2c_readReg_Mask, vPortExitCritical, xPortEnterCriticalTimeout.
 *
 * Called by: FUN_42023b70.
 *
 * Original function-byte SHA-256:
 * 346cbfd48e406149da471555cfc452a0fc612bffecf0a8bd26a219b96b0cda2f.
 */

/* Reference: ESP-IDF v5.4.4 components/esp_hw_support/regi2c_ctrl.c. */

/*
 * block: Eight-bit internal analog/I2C block identifier passed to ROM.
 * host_id: Eight-bit internal analog/I2C host selector passed to ROM.
 * reg_address: Eight-bit register index within the selected block.
 * msb: Inclusive upper bit index for the ROM masked read.
 * lsb: Inclusive lower bit index for the ROM masked read.
 * Returns: The low byte returned by rom_i2c_readReg_Mask.
 * Requirements/effects: Serializes the ROM operation with the shared analog-register mux; caller supplies a valid
 *   block/register/bit range. No range validation, timeout or separate error result is provided.
 */

uchar regi2c_ctrl_read_reg_mask(uchar block,uchar host_id,uchar reg_address,uchar msb,uchar lsb)

{
  uchar value;

  xPortInIsrContext();
  xPortEnterCriticalTimeout(REGI2C_LOCK,-1);
  value = rom_i2c_readReg_Mask(block,host_id,reg_address,msb,lsb);
  xPortInIsrContext();
  vPortExitCritical(REGI2C_LOCK);
  return value;
}

/* Native entry: 0x40376c9c. */
/*
 * Medius v3.4.7 — device application; 0x40376c9c.
 *
 * Locks REGI2C, truncates block/host/register/value to eight bits, forwards one whole internal
 * analog-register write to ROM, then unlocks. It returns no status and provides no address
 * validation or retry logic.
 *
 * Calls: xPortInIsrContext, rom_i2c_writeReg, vPortExitCritical, xPortEnterCriticalTimeout.
 *
 * Called by: FUN_40384c60.
 *
 * Original function-byte SHA-256:
 * 00f2811e0c43f2953e1835320f9c55055ee3272e05b035bbe50f9f011a42ecbf.
 */

/* Reference: ESP-IDF v5.4.4 components/esp_hw_support/regi2c_ctrl.c. */

/*
 * block: Eight-bit internal analog/I2C block identifier passed to ROM.
 * host_id: Eight-bit internal analog/I2C host selector passed to ROM.
 * reg_address: Eight-bit register index within the selected block.
 * value: Eight-bit replacement register value passed to ROM.
 * Returns: Nothing; ROM write status is not exposed.
 * Requirements/effects: Serializes one complete analog-register write with the shared analog-register mux. Caller
 *   supplies valid ROM addressing; no range validation or retry is added.
 */

void regi2c_ctrl_write_reg(uchar block,uchar host_id,uchar reg_address,uchar value)

{
  xPortInIsrContext();
  xPortEnterCriticalTimeout(REGI2C_LOCK,-1);
  rom_i2c_writeReg(block,host_id,reg_address,value);
  xPortInIsrContext();
  vPortExitCritical(REGI2C_LOCK);
  return;
}

/* Native entry: 0x40376cd4. */
/*
 * Medius v3.4.7 — device application; 0x40376cd4.
 *
 * Locks REGI2C around the ROM masked internal analog-register write, forwarding six byte-sized
 * arguments in A2 through A7. ROM performs the masked register update; this wrapper adds
 * serialization but no separate mask-range validation or status return.
 *
 * Calls: xPortInIsrContext, rom_i2c_writeReg_Mask, vPortExitCritical, xPortEnterCriticalTimeout.
 *
 * Called by: FUN_403849d4, FUN_40384bb0, FUN_40384c60, brownout_hal_config, FUN_42023b70.
 *
 * Original function-byte SHA-256:
 * a60bfebe93372c18dfa37560b24110b06647b4b1c54fa3e8744f1edefbc64ff4.
 */

/* Reference: ESP-IDF v5.4.4 components/esp_hw_support/regi2c_ctrl.c. */

/*
 * block: Eight-bit internal analog/I2C block identifier passed to ROM.
 * host_id: Eight-bit internal analog/I2C host selector passed to ROM.
 * reg_address: Eight-bit register index within the selected block.
 * msb: Inclusive upper bit index for the ROM update.
 * lsb: Inclusive lower bit index for the ROM update.
 * value: Eight-bit field value passed to the ROM masked update.
 * Returns: Nothing; ROM update status is not exposed.
 * Requirements/effects: Serializes the masked analog-register write with the shared analog-register mux. Caller
 *   supplies a valid bit range; masking is performed by ROM.
 */

void regi2c_ctrl_write_reg_mask
               (uchar block,uchar host_id,uchar reg_address,uchar msb,uchar lsb,uchar value)

{
  xPortInIsrContext();
  xPortEnterCriticalTimeout(REGI2C_LOCK,-1);
  rom_i2c_writeReg_Mask(block,host_id,reg_address,msb,lsb,value);
  xPortInIsrContext();
  vPortExitCritical(REGI2C_LOCK);
  return;
}

/* Native entry: 0x420050a8. */
/*
 * Medius v3.4.7 — device application; 0x420050a8.
 *
 * Enters the shared peripheral clock/reset critical section and returns the existing uint8
 * reference count. Leaves the critical section HELD for the caller hardware update and matching
 * acquire_exit. Does not increment the count or check the peripheral index.
 *
 * Calls: xPortInIsrContext, xPortEnterCriticalTimeout.
 *
 * Called by: FUN_40385458, vSystimerSetup, FUN_42002f68, FUN_42011078, FUN_42011a04,
 * esp_timer_impl_early_init.
 *
 * Original function-byte SHA-256:
 * f78030e6530c204329379e83f147377c19959c1d07d9e2659cd167c365ab5b4b.
 */

/* Enters the shared peripheral clock/reset critical section and returns the existing uint8
   reference count. Leaves the critical section HELD for the caller hardware update and matching
   acquire_exit. Does not increment the count or check the peripheral index. Reference: ESP-IDF
   v5.4.4 components/esp_hw_support/periph_ctrl.c and esp_private/periph_ctrl.h. */

/*
 * peripheral: Unchecked SDK peripheral-enum index into the shared uint8 reference table.
 * Returns: Existing uint8 count, with the peripheral critical section still held.
 * Requirements/effects: Caller performs clock/reset changes before matching acquire_exit. Does not
 *   increment the count or enable hardware itself.
 */

uchar periph_rcc_acquire_enter(int peripheral)

{
  xPortInIsrContext();
  xPortEnterCriticalTimeout(PERIPHERAL_RCC_LOCK,-1);
  return PERIPHERAL_RCC_REFERENCE_COUNTS[peripheral];
}

/* Native entry: 0x420050c8. */
/*
 * Medius v3.4.7 — device application; 0x420050c8.
 *
 * Stores previous_count+1 modulo 256 in the peripheral reference table, then releases the shared
 * clock/reset critical section held by acquire_enter. The caller must pass the count obtained
 * under that same lock; the helper does not enable the clock itself.
 *
 * Calls: xPortInIsrContext, vPortExitCritical.
 *
 * Called by: FUN_40385458, vSystimerSetup, FUN_42002f68, FUN_42011078, FUN_42011a04,
 * esp_timer_impl_early_init.
 *
 * Original function-byte SHA-256:
 * 70c5795587cf2f19e9ecd559ebd4a8a00628fde8934f45ce4033b7e9e3c6d0c0.
 */

/* Stores previous_count+1 modulo 256 in the peripheral reference table, then releases the shared
   clock/reset critical section held by acquire_enter. The caller must pass the count obtained
   under that same lock; the helper does not enable the clock itself. Reference: ESP-IDF v5.4.4
   components/esp_hw_support/periph_ctrl.c and esp_private/periph_ctrl.h. */

/*
 * peripheral: Same index as the matching acquire_enter.
 * previous_count: Count obtained under that same peripheral lock.
 * Returns: Nothing.
 * Requirements/effects: Stores previous_count+1 modulo256, then unlocks. Caller supplies correct
 *   pairing and the intervening hardware update.
 */

void periph_rcc_acquire_exit(int peripheral,uchar previous_count)

{
  PERIPHERAL_RCC_REFERENCE_COUNTS[peripheral] = (unsigned char)(previous_count + 1U);
  xPortInIsrContext();
  vPortExitCritical(PERIPHERAL_RCC_LOCK);
  return;
}

/* Native entry: 0x420050e8. */
/*
 * Medius v3.4.7 — device application; 0x420050e8.
 *
 * Enters the shared peripheral clock/reset critical section and returns the uint8 reference count
 * minus one, modulo 256, without storing it yet. Leaves the section HELD for the caller hardware
 * update and release_exit. A zero count wraps to 255; no underflow/index check is added.
 *
 * Calls: xPortInIsrContext, xPortEnterCriticalTimeout.
 *
 * Called by: FUN_42011b00.
 *
 * Original function-byte SHA-256:
 * b3140ccc68b812bba9599090089785b3b804d615afe68bcf3f4dcf2ea77a82b9.
 */

/* Enters the shared peripheral clock/reset critical section and returns the uint8 reference count
   minus one, modulo 256, without storing it yet. Leaves the section HELD for the caller hardware
   update and release_exit. A zero count wraps to 255; no underflow/index check is added.
   Reference: ESP-IDF v5.4.4 components/esp_hw_support/periph_ctrl.c and
   esp_private/periph_ctrl.h. */

/*
 * peripheral: Unchecked SDK peripheral-enum index into the shared uint8 reference table.
 * Returns: Count minus one modulo256, with the peripheral critical section held.
 * Requirements/effects: Does not store the decrement or disable hardware. Zero wraps to255; caller
 *   updates hardware before matching release_exit.
 */

uchar periph_rcc_release_enter(int peripheral)

{
  xPortInIsrContext();
  xPortEnterCriticalTimeout(PERIPHERAL_RCC_LOCK,-1);
  return (unsigned char)(PERIPHERAL_RCC_REFERENCE_COUNTS[peripheral] - 1U);
}

/* Native entry: 0x4200510c. */
/*
 * Medius v3.4.7 — device application; 0x4200510c.
 *
 * Stores the caller supplied remaining uint8 reference count, then releases the shared
 * clock/reset critical section held by release_enter. Does not decrement again, check the
 * peripheral index, or disable/reset the hardware itself.
 *
 * Calls: xPortInIsrContext, vPortExitCritical.
 *
 * Called by: FUN_42011b00.
 *
 * Original function-byte SHA-256:
 * f0a7f61cbaf16708b7f53c17f761483c6297482b94148ea997532093da6b494c.
 */

/* Stores the caller supplied remaining uint8 reference count, then releases the shared
   clock/reset critical section held by release_enter. Does not decrement again, check the
   peripheral index, or disable/reset the hardware itself. Reference: ESP-IDF v5.4.4
   components/esp_hw_support/periph_ctrl.c and esp_private/periph_ctrl.h. */

/*
 * peripheral: Same index as the matching release_enter.
 * remaining_count: Remaining count returned by release_enter, stored without another decrement.
 * Returns: Nothing.
 * Requirements/effects: Stores the supplied count then unlocks. Caller supplies valid pairing and
 *   intervening clock/reset changes.
 */

void periph_rcc_release_exit(int peripheral,uchar remaining_count)

{
  PERIPHERAL_RCC_REFERENCE_COUNTS[peripheral] = remaining_count;
  xPortInIsrContext();
  vPortExitCritical(PERIPHERAL_RCC_LOCK);
  return;
}

/* Native entry: 0x42017bc0. */
/* Original function-byte SHA-256:
 * b80d02d259b8e97b15e032449e3314b68664b3732ad947f9ea57fa58f8bed944. */
/*
 * source: module-clock IDs1..12; precision:0 cached,1 approximate,2 recalibrate;
 * frequency_hz: writable output WORD. Validates in that order, logging first
 * error and returning0x102 without changing output. Fixed PLL80/160 and PLL/2
 * bypass the zero-result check; PLL/2 MEMW/reads CPU_PER bit2 for160/240MHz.
 * Other sources delegate to HAL/RTC readers, with XTAL MHz converted using
 * WORD multiplication. A zero dynamic result logs failure, returns-1 and
 * leaves output unchanged. Success stores Hz once and returns0. Precision
 * 'exact' requests calibration where supported; no accuracy/timing guarantee,
 * lock, oscillator enable or coherent snapshot across registers is supplied.
 */
int esp_clk_tree_src_get_freq_hz(unsigned int source, unsigned int precision,
    unsigned int *frequency_hz)
{
    const char *error_format;
    unsigned int error_line;
    if (source - 1U > 11U) {
        error_format = "E (%lu) %s: %s(%d): unknown clk src\n";
        error_line = 21U;
    } else if (precision > ESP_CLK_TREE_SRC_FREQ_PRECISION_EXACT) {
        error_format = "E (%lu) %s: %s(%d): unknown precision\n";
        error_line = 22U;
    } else if (frequency_hz == 0) {
        error_format = "E (%lu) %s: %s(%d): null pointer\n";
        error_line = 23U;
    } else goto valid_arguments;
    unsigned int timestamp = esp_log_timestamp();
    esp_log_write(1, "esp_clk_tree", error_format, timestamp, "esp_clk_tree",
        "esp_clk_tree_src_get_freq_hz", error_line);
    return 0x102;

valid_arguments:
    ;
    unsigned int result_hz;
    switch (source) {
    case SOC_MOD_CLK_CPU: result_hz = clk_hal_cpu_get_freq_hz(); break;
    case SOC_MOD_CLK_RTC_FAST: result_hz = esp_clk_tree_lp_fast_get_freq_hz(precision); break;
    case SOC_MOD_CLK_RTC_SLOW: result_hz = esp_clk_tree_lp_slow_get_freq_hz(precision); break;
    case SOC_MOD_CLK_APB: result_hz = clk_hal_apb_get_freq_hz(); break;
    case SOC_MOD_CLK_PLL_F80M: result_hz = 80000000U; goto publish;
    case SOC_MOD_CLK_PLL_F160M: result_hz = 160000000U; goto publish;
    case SOC_MOD_CLK_PLL_D2:
        memw();
        result_hz = (CLOCK_SYSTEM_REGISTERS->cpu_per_conf & 4U) ? 240000000U : 160000000U;
        goto publish;
    case SOC_MOD_CLK_XTAL32K: result_hz = esp_clk_tree_xtal32k_get_freq_hz(precision); break;
    case SOC_MOD_CLK_RC_FAST_D256: result_hz = esp_clk_tree_rc_fast_d256_get_freq_hz(precision); break;
    case SOC_MOD_CLK_XTAL: result_hz = clk_hal_xtal_get_freq_mhz() * 1000000U; break;
    default: result_hz = esp_clk_tree_rc_fast_get_freq_hz(precision); break;
    }
    if (result_hz == 0) {
        timestamp = esp_log_timestamp();
        esp_log_write(1, "esp_clk_tree", "E (%lu) %s: %s(%d): freq shouldn't be 0, calibration failed\n",
            timestamp, "esp_clk_tree", "esp_clk_tree_src_get_freq_hz", 65U);
        return -1;
    }
publish:
    *frequency_hz = result_hz;
    return 0;
}

/* Native entry: 0x40384268. */
/*
 * Medius v3.4.7 — device application; 0x40384268.
 * Instruction-checked recovered C.
 * Original function-byte SHA-256:
 * 941e31b0bfef32e9af6d9c97253a23b87b5f9f95c282fe4ee47fcd169075b8ff.
 */

/* Execute native WAITI0, enabling level0 interrupt wakeup and waiting until an
 * eligible interrupt resumes this CPU. Return afterward. No kernel lock, task
 * delay, deadline, timeout or explicit PS restoration is present in this entry. */
void esp_cpu_wait_for_intr(void)
{
    __asm__ volatile ("waiti 0" : : : "memory");
}

/* Native entry: 0x4200730c. */
/* Original function-byte SHA-256:
 * 4a24e5110295b487e743a8a382a5c14031d5608222a242954f6614e4f24caa8a. */
/*
 * precision 1 returns nominal 68359Hz without reading the shared cache.
 * precision 0 returns a nonzero cached WORD, or calibrates when it is zero;
 * precision 2 always calibrates. Calibration uses source1,100 cycles then
 * rtc_clk_freq_cal, stores even zero, and returns that same converted value.
 * Other precision values return zero. Cache accesses are ordinary RAM WORDs;
 * no lock, retry-on-failure, oscillator enable or timeout is added here.
 */
unsigned int esp_clk_tree_rc_fast_d256_get_freq_hz(unsigned int precision)
{
    if (precision == ESP_CLK_TREE_SRC_FREQ_PRECISION_APPROX) return 68359U;
    if (precision != ESP_CLK_TREE_SRC_FREQ_PRECISION_CACHED && precision != ESP_CLK_TREE_SRC_FREQ_PRECISION_EXACT) return 0;
    if (precision == ESP_CLK_TREE_SRC_FREQ_PRECISION_CACHED) {
        unsigned int cached_hz = CLOCK_FREQUENCY_CACHE->rc_fast_d256_hz;
        if (cached_hz != 0) return cached_hz;
    }
    unsigned int period_q19 = rtc_clk_cal(RTC_CAL_8MD256, 100U);
    unsigned int frequency_hz = rtc_clk_freq_cal(period_q19);
    CLOCK_FREQUENCY_CACHE->rc_fast_d256_hz = frequency_hz;
    return frequency_hz;
}

/* Native entry: 0x42007358. */
/* Original function-byte SHA-256:
 * 433ae17b47baa21033c2a5f0c1e404e0821e824d85849cda7505da819a8eae16. */
/*
 * precision 1 returns nominal 32768Hz; 0 uses a nonzero cached XTAL32K WORD
 * or calibrates when zero; 2 recalibrates regardless of the previous cache.
 * Calibration passes source2,100 cycles to rtc_clk_cal, converts its Q19
 * period through rtc_clk_freq_cal, and stores/returns the result including0.
 * Invalid precision returns0. No lock, oscillator enable, retry or timeout.
 */
unsigned int esp_clk_tree_xtal32k_get_freq_hz(unsigned int precision)
{
    if (precision == ESP_CLK_TREE_SRC_FREQ_PRECISION_APPROX) return 32768U;
    if (precision != ESP_CLK_TREE_SRC_FREQ_PRECISION_CACHED && precision != ESP_CLK_TREE_SRC_FREQ_PRECISION_EXACT) return 0;
    if (precision == ESP_CLK_TREE_SRC_FREQ_PRECISION_CACHED) {
        unsigned int cached_hz = CLOCK_FREQUENCY_CACHE->xtal32k_hz;
        if (cached_hz != 0) return cached_hz;
    }
    unsigned int period_q19 = rtc_clk_cal(RTC_CAL_32K_XTAL, 100U);
    unsigned int frequency_hz = rtc_clk_freq_cal(period_q19);
    CLOCK_FREQUENCY_CACHE->xtal32k_hz = frequency_hz;
    return frequency_hz;
}

/* Native entry: 0x420073a4. */
/* Original function-byte SHA-256:
 * 46b90e80f2fabdb19dbcd06cf112e8a1b7313b83df038c496ad23eb61255f018. */
/*
 * precision 0 MEMW/reads RTC slow-period storage once and converts Q19 toHz;
 * 1 returns the selected slow clock's nominal frequency from the HAL reader.
 * 2 calibrates the current RTC mux for1024 cycles, publishes a nonzero period
 * via esp_clk_slowclk_cal_set, then converts the originally returned period.
 * Zero calibration is converted but not published; invalid precision returns0.
 * No wrapper lock, oscillator enable or repeated calibration is supplied.
 */
unsigned int esp_clk_tree_lp_slow_get_freq_hz(unsigned int precision)
{
    if (precision == ESP_CLK_TREE_SRC_FREQ_PRECISION_APPROX) return clk_hal_lp_slow_get_freq_hz();
    if (precision == ESP_CLK_TREE_SRC_FREQ_PRECISION_CACHED) {
        memw();
        unsigned int period_q19 = RTC_SLOW_PERIOD_Q19;
        return rtc_clk_freq_cal(period_q19);
    }
    if (precision == ESP_CLK_TREE_SRC_FREQ_PRECISION_EXACT) {
        unsigned int period_q19 = rtc_clk_cal(RTC_CAL_RTC_MUX, 1024U);
        if (period_q19 != 0) esp_clk_slowclk_cal_set(period_q19);
        return rtc_clk_freq_cal(period_q19);
    }
    return 0;
}

/* Native entry: 0x420073f4. */
/* Original function-byte SHA-256:
 * de9547d0618507f25e3c8f1d5c18a94d14091febdd1a8c017f60e1f13084a53f. */
/*
 * precision 1 returns nominal17500000Hz. Precision0 uses the shared divided
 * RC-fast cache, calibrating source1 for100 cycles only if that WORD is zero;
 * precision2 always calibrates. The converted divided frequency is stored
 * including zero and then shifted left8 with WORD wrap to produce full Hz.
 * The native return uses the cached/converted register value, without a new
 * cache read after storing. Invalid precision returns0. No lock or retry.
 */
unsigned int esp_clk_tree_rc_fast_get_freq_hz(unsigned int precision)
{
    if (precision == ESP_CLK_TREE_SRC_FREQ_PRECISION_APPROX) return 17500000U;
    if (precision != ESP_CLK_TREE_SRC_FREQ_PRECISION_CACHED && precision != ESP_CLK_TREE_SRC_FREQ_PRECISION_EXACT) return 0;
    unsigned int divided_hz;
    if (precision == ESP_CLK_TREE_SRC_FREQ_PRECISION_CACHED) {
        divided_hz = CLOCK_FREQUENCY_CACHE->rc_fast_d256_hz;
        if (divided_hz != 0) return divided_hz << 8;
    }
    divided_hz = rtc_clk_freq_cal(rtc_clk_cal(RTC_CAL_8MD256, 100U));
    CLOCK_FREQUENCY_CACHE->rc_fast_d256_hz = divided_hz;
    return divided_hz << 8;
}

/* Native entry: 0x42007448. */
/* Original function-byte SHA-256:
 * a6ec991d09876bade9255811fac8672323064a19b5d61a436555b7f806200e4e. */
/*
 * MEMW/samples RTC CLK_CONF bit29. If clear, ignores precision and returns
 * (XTAL_MHz*1000000 modulo2^32)>>1, without consulting the RC divider.
 * If set, precision1 uses nominal17500000Hz; other precisions obtain the
 * divided RC-fast frequency and shift left8 with WORD wrap. Only then does
 * it MEMW/REREAD CLK_CONF, dividing Hz by1+bits12..14 (range1..8).
 * Source and divider samples can differ; no snapshot lock or enable occurs.
 */
unsigned int esp_clk_tree_lp_fast_get_freq_hz(unsigned int precision)
{
    memw();
    unsigned int source_word = RTC_CALIBRATION_CLOCK_REGISTERS->clock_conf;
    if ((source_word & (1U << 29)) == 0)
        return (clk_hal_xtal_get_freq_mhz() * 1000000U) >> 1;
    unsigned int source_hz = precision == ESP_CLK_TREE_SRC_FREQ_PRECISION_APPROX ? 17500000U :
        esp_clk_tree_rc_fast_d256_get_freq_hz(precision) << 8;
    memw();
    unsigned int divider_word = RTC_CALIBRATION_CLOCK_REGISTERS->clock_conf;
    return source_hz / (((divider_word >> 12) & 7U) + 1U);
}

/* Native entry: 0x42011410. */
/* Original function-byte SHA-256:
 * a19cbdeae98a78267d8ae27af264d2c2ccb66240400d9997d00b7c864f4e4a0f. */
/*
 * MEMW/reads RTC XTAL storage once. Accepts matching16-bit halves except
 * all-zero/all-one WORDs; strips low flag bit0 to obtain an even MHz value.
 * A resulting zero is also invalid. On invalid storage, logs one warning
 * through the normal logger and returns40MHz. Does not measure the crystal,
 * update the storage, validate a supported range or acquire a lock.
 */
unsigned int clk_hal_xtal_get_freq_mhz(void)
{
    memw();
    unsigned int stored = RTC_CALIBRATION_CLOCK_REGISTERS->xtal_store;
    if ((stored & 0xffffU) == (stored >> 16) && stored != 0 && stored != 0xffffffffU) {
        unsigned int frequency_mhz = stored & 0xfffeU;
        if (frequency_mhz != 0) return frequency_mhz;
    }
    unsigned int timestamp = esp_log_timestamp();
    esp_log_write(2, "clk_hal", "W (%lu) %s: invalid RTC_XTAL_FREQ_REG value, assume 40MHz\n",
        timestamp, "clk_hal");
    return 40U;
}

/* Native entry: 0x42011450. */
/* Original function-byte SHA-256:
 * f74c3f79a0e63d10943f4c902b2e8928aa8e54565e30dbcce86d34d786da6bdb. */
/*
 * MEMW/reads SYSTEM SYSCLK source bits10..11. PLL source1 MEMW/reads CPU_PER
 * twice: first bit2 identifies the PLL variant, second bits0..1 the CPU rate.
 * Rate0/1 gives80/160MHz; rate2 gives240MHz only with first bit2 set, otherwise
 * logs Invalid cpu config and returns0. Rate3 returns0 silently. The PLL
 * branch does not apply the SYSCLK divider. XTAL source0 uses MHz*1000000
 * with WORD wrap; RC source2 uses17000000Hz, distinct from the RTC nominal
 * 17500000Hz. Both then MEMW/REREAD SYSCLK and divide by1+bits0..9 (1..1024).
 * Source3 aborts. Separate MMIO samples, ordinary logging and no lock remain.
 */
unsigned int clk_hal_cpu_get_freq_hz(void)
{
    memw();
    unsigned int source = (CLOCK_SYSTEM_REGISTERS->sysclk_conf >> 10) & 3U;
    if (source == 1) {
        memw();
        unsigned int pll_word = CLOCK_SYSTEM_REGISTERS->cpu_per_conf;
        memw();
        unsigned int rate_word = CLOCK_SYSTEM_REGISTERS->cpu_per_conf;
        unsigned int rate = rate_word & 3U;
        if (rate == 0) return 80000000U;
        if (rate == 1) return 160000000U;
        if (rate == 3) return 0;
        if ((pll_word & 4U) != 0) return 240000000U;
        unsigned int timestamp = esp_log_timestamp();
        esp_log_write(1, "clk_hal", "E (%lu) %s: Invalid cpu config\n", timestamp, "clk_hal");
        return 0;
    }
    unsigned int root_hz;
    if (source == 0) root_hz = clk_hal_xtal_get_freq_mhz() * 1000000U;
    else if (source == 2) root_hz = 17000000U;
    else abort();
    memw();
    unsigned int divider_word = CLOCK_SYSTEM_REGISTERS->sysclk_conf;
    return root_hz / ((divider_word & 0x3ffU) + 1U);
}

/* Native entry: 0x420114fc. */
/* Original function-byte SHA-256:
 * 48d570fe191fddb01e4410282ced2b3c10591b5a67e7b22c830c23e1e6652b50. */
/*
 * MEMW/samples SYSTEM SYSCLK source bits10..11 once. PLL source1 returns a
 * fixed80000000Hz; other sources delegate to the CPU frequency reader,
 * which makes its own fresh source/register samples. No extra APB divider,
 * maximum cap, calibration, register write or snapshot lock is applied.
 */
unsigned int clk_hal_apb_get_freq_hz(void)
{
    memw();
    unsigned int source = (CLOCK_SYSTEM_REGISTERS->sysclk_conf >> 10) & 3U;
    return source == 1 ? 80000000U : clk_hal_cpu_get_freq_hz();
}

/* Native entry: 0x420113e4. */
/* Original function-byte SHA-256:
 * d07ca61c264b2bd6d46fe5c365e0b705c54216efeac98c15cbf69a23473455a4. */
/*
 * MEMW/reads RTC CLK_CONF once and selects bits30..31: source0 gives136000Hz
 * RC_SLOW, source1 gives32768Hz XTAL32K, source2 gives68359Hz RC_FAST/256.
 * Source3 calls abort and does not return normally. These are nominal values;
 * no calibration, cache, enable, lock or actual frequency measurement occurs.
 */
unsigned int clk_hal_lp_slow_get_freq_hz(void)
{
    memw();
    unsigned int source = RTC_CALIBRATION_CLOCK_REGISTERS->clock_conf >> 30;
    if (source == 0) return 136000U;
    if (source == 1) return 32768U;
    if (source == 2) return 68359U;
    abort();
}

/* Native entry: 0x4200460c. */
/* Original function-byte SHA-256:
 * 0b2152d78229b59511ed9eb6404b9627251042f3756b5858d090fba0e09153c3. */
/*
 * new_period_q19: RTC slow-clock microseconds per tick in Q13.19 form.
 * Calls the RTC time-accounting boundary first (its result is ignored),
 * then MEMW/stores the supplied WORD to RTC slow-period storage at +0x54.
 * Zero is accepted. This wrapper adds no lock/validation and does not
 * calibrate hardware; the accounting callee's internal work is separate.
 */
void esp_clk_slowclk_cal_set(unsigned int new_period_q19)
{
    esp_rtc_get_time_us();
    memw();
    RTC_SLOW_PERIOD_Q19 = new_period_q19;
}

/* Native entry: 0x42004524. */
/* Original function-byte SHA-256:
 * a2914e0d66a6f857403ff47d5274047ecbc70ef88088be2d972598f9cdab0d20. */
/*
 * Returns the retained RTC time in microseconds, updated under its port mux.
 * Queries ISR context (ignored), enters with unlimited timeout (result ignored),
 * and MEMW/samples the Q13.19 microseconds-per-tick calibration once. Zero
 * calibration clears all24 retained bytes without reading the first-call flag.
 * With nonzero calibration, only the first call validates the stored checksum:
 * read checksum first, then fold the preceding5 WORDs using (hash*31)^word,
 * with WORD wrap. A mismatch clears the24-byte block; later calls skip validation.
 * Clears the BYTE first-call flag before taking a coherent rtc_time_get sample.
 *
 * Tick subtraction wraps at64 bits. Conversion splits the tick delta into two
 *32-bit halves: (low*period>>19)+(high*period<<13), with64-bit wrap. Adds this
 * to the retained microseconds. Native store order is last_ticks_low, time_low,
 * time_high, last_ticks_high, then the new checksum over the5 preceding WORDs.
 * Queries ISR context again (ignored), unlocks, and returns the cached new time
 * in a2/a3; it does not reread time after unlocking. Zero period still advances
 * the retained tick sample. No calibration refresh, overflow check, monotonicity
 * guarantee, wall-clock synchronization or independent hardware timer is added.
 * Identity: ESP-IDF esp_clk.c esp_rtc_get_time_us with RTC retained memory.
 */
unsigned long long esp_rtc_get_time_us(void)
{
    (void)xPortInIsrContext();
    (void)xPortEnterCriticalTimeout(RTC_TIME_LOCK, -1);
    memw();
    unsigned int period_q19 = RTC_SLOW_PERIOD_Q19;
    volatile RtcRetainedTime *retained = RTC_RETAINED_TIME;
    bool clear_retained;
    if (period_q19 == 0) clear_retained = true;
    else if (RTC_TIME_FIRST_CALL == 0) clear_retained = false;
    else {
        unsigned int expected_checksum = retained->checksum;
        unsigned int checksum = 0;
        const volatile unsigned int *words = (const volatile unsigned int *)retained;
        for (unsigned int index = 0; index < 5; ++index)
            checksum = (checksum * 31U) ^ words[index];
        clear_retained = expected_checksum != checksum;
    }
    if (clear_retained) memset((void *)retained, 0, 24);
    RTC_TIME_FIRST_CALL = 0;
    unsigned long long current_ticks = rtc_time_get();
    unsigned int previous_low = retained->last_ticks_low;
    unsigned int previous_high = retained->last_ticks_high;
    unsigned long long previous_ticks = ((unsigned long long)previous_high << 32) | previous_low;
    unsigned long long delta_ticks = current_ticks - previous_ticks;
    unsigned long long low_product = (unsigned long long)(unsigned int)delta_ticks * period_q19;
    unsigned long long high_product = (delta_ticks >> 32) * period_q19;
    unsigned long long delta_us = (low_product >> 19) + (high_product << 13);
    unsigned int old_time_low = retained->time_us_low;
    unsigned int old_time_high = retained->time_us_high;
    unsigned long long updated_us = (((unsigned long long)old_time_high << 32) | old_time_low) + delta_us;
    retained->last_ticks_low = (unsigned int)current_ticks;
    retained->time_us_low = (unsigned int)updated_us;
    retained->time_us_high = (unsigned int)(updated_us >> 32);
    retained->last_ticks_high = (unsigned int)(current_ticks >> 32);
    unsigned int checksum = 0;
    const volatile unsigned int *words = (const volatile unsigned int *)retained;
    for (unsigned int index = 0; index < 5; ++index)
        checksum = (checksum * 31U) ^ words[index];
    retained->checksum = checksum;
    (void)xPortInIsrContext();
    vPortExitCritical(RTC_TIME_LOCK);
    return updated_us;
}

/* Native entry: 0x4037694c. */
/* Original function-byte SHA-256:
 * 84d49f9e84984d488fcc7cf6896471e66c87607de0dcf4b9a9729d76f6554eab. */
/* Query ROM CPU MHz once and multiply by1,000,000 modulo32, returning
 * that WORD as signed Hz. No validation, lock, measurement or clock change. */
int esp_clk_cpu_freq(void)
{
    return (int)(ets_get_cpu_frequency()*1000000U);
}
