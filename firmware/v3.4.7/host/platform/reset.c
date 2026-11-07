/* Medius v3.4.7 host — platform/reset.c.
 * Recovered C and native assembly, grouped for source navigation.
 * Original entry addresses, firmware-byte hashes and function comments follow.
 */

#include "../include/types.h"

/* Native entry: 0x40375794. */
/*
 * Medius v3.4.7 — host application; 0x40375794.
 *
 * Brownout interrupt callback: acknowledges, records the cause, drains UARTs and resets; never
 * returns.
 *
 * Calls: esp_reset_reason_set_hint, bootloader_flash_reset_chip, esp_cpu_stall, spi_flash_brownout_need_reset, ets_printf, software_reset,
 * uart_tx_wait_idle.
 *
 * Original function-byte SHA-256:
 * 2306ae64cee329e3ee093e44d4f2fbebce3a8ff2a9710957d50a767c863a630f.
 */

__attribute__((noreturn))

/*
 * unused_argument: Unused RTC dispatcher context; not dereferenced.
 * Returns: Never returns: requests software reset and spins if ROM returns.
 * Requirements/effects: Brownout ISR context. Acknowledges bit0x200, stalls the other CPU, records
 *   hint9, conditionally resets flash or prints, and drains unreset/clocked UARTs. UART/SPI/ROM
 *   waits can be unbounded.
 */

void rtc_brownout_isr_handler(void *unused_argument)

{
  uint register_value;
  uint clock_enables;
  bool flash_reset_required;
  memw();
  register_value = RTC_INT_CLR;
  memw();
  RTC_INT_CLR = register_value | 0x200;
  register_value = xtensa_read_prid();
  esp_cpu_stall((uint)((register_value >> 0xd & 1) == 0));
  esp_reset_reason_set_hint(9);
  flash_reset_required = spi_flash_brownout_need_reset();
  if (flash_reset_required) {
    bootloader_flash_reset_chip();
  }
  else if (SYSTEM_EARLY_LOG_LEVEL != 0) {
    ets_printf("E %s: Brownout detector was triggered\r\n\r\n\n","BOD");
  }
  memw();
  register_value = SYSTEM_RESET_ENABLE0;
  if ((register_value & 4) == 0) {
    memw();
    clock_enables = SYSTEM_CLOCK_ENABLE0;
    if ((clock_enables & 4) != 0) {
      uart_tx_wait_idle(0);
    }
  }
  memw();
  register_value = SYSTEM_RESET_ENABLE0;
  if ((register_value & 0x20) == 0) {
    memw();
    register_value = SYSTEM_CLOCK_ENABLE0;
    if ((register_value & 0x20) != 0) {
      uart_tx_wait_idle(1);
    }
  }
  memw();
  register_value = SYSTEM_RESET_ENABLE0;
  if ((register_value & 0x200) == 0) {
    memw();
    register_value = SYSTEM_CLOCK_ENABLE0;
    if ((register_value & 0x200) != 0) {
      uart_tx_wait_idle(2);
    }
  }
  software_reset();
  for (;;) __asm__ volatile ("" ::: "memory");
}

/* Acknowledges RTC brownout bit0x200, stalls the other CPU and records reset hint9. Resets the
   flash only when both the XMC-reset and flash-erasing flags are set; otherwise prints the DRAM
   error message when the default log level is nonzero. Drains each unreset, clocked UART0/1/2,
   requests a system software reset and spins if ROM returns. Original format/tag are in DRAM at
   0x3fc9e47c, 0x3fc9e4a8; literals below represent their bytes. Reference: ESP-IDF v5.4.4
   components/esp_system/port/brownout.c. */

/* Native entry: 0x40375900. */
/*
 * Medius v3.4.7 — host application; 0x40375900.
 *
 * Asserts hint fits15 bits, duplicates it into bits0..14 and16..30 of RTC STORE6/RESET_CAUSE, and
 * sets bit31. This encodes a retained software hint for the next boot; it neither resets a CPU
 * nor changes the cached reset-reason result.
 *
 * Calls: __assert_func.
 *
 * Called by: rtc_brownout_isr_handler, FUN_42002c58, FUN_42012e48.
 *
 * Original function-byte SHA-256:
 * cbe86b3b3aa81db97ade83b86f34cb1a294d6351ec446995880850d3b7572b15.
 */

/* Reference: ESP-IDF v5.4.4 components/esp_system/port/soc/esp32s3/reset_reason.c. */

/*
 * hint: Retained software reset hint, required to fit15 bits; larger values assert.
 * Returns: Nothing.
 * Requirements/effects: Encodes the hint twice in RTC STORE6 and sets bit31. Does not reset the
 *   CPU or update the cached public reset reason.
 */

void esp_reset_reason_set_hint(uint hint)

{
  if (0x7fff < hint) {
                    /* WARNING: Subroutine does not return */
    __assert_func((char *)0x0,0,(char *)0x0,(char *)0x0);
  }
  memw();
  RTC_RESET_HINT = hint << 0x10 | hint | 0x80000000;
  return;
}

/* Native entry: 0x4037592c. */
/*
 * Medius v3.4.7 — host application; 0x4037592c.
 *
 * Drains each UART0/1/2 whose reset bit is clear and clock bit set. Pulses core-reset mask0x3faf,
 * peripheral reset masks0x20120007/0xfe, then EDMA reset bit1. The first three reset banks are
 * written back to zero after assertion, not restored to their previous state. No global CPU reset
 * occurs in this helper.
 *
 * Calls: uart_tx_wait_idle.
 *
 * Called by: esp_restart_noos.
 *
 * Original function-byte SHA-256:
 * 8c103ca0559731db81ee8584fc4b71a7061d963ab4b23dd780f84184b2c33828.
 */

/* Reference: ESP-IDF v5.4.4 components/esp_system/port/soc/esp32s3/system_internal.c. */

/*
 * Returns: Nothing.
 * Requirements/effects: Drains active UART0/1/2, pulses core/peripheral reset masks and EDMA
 *   reset. Writes the first reset banks back to0, rather than restoring their prior contents;
 *   caller owns shutdown ordering.
 */

void esp_system_reset_modules_on_exit(void)

{
  uint reset_or_control_value;
  uint uart_clock_enables;

  memw();
  reset_or_control_value = SYSTEM_RESET_ENABLE0;
  if ((reset_or_control_value & 4) == 0) {
    memw();
    uart_clock_enables = SYSTEM_CLOCK_ENABLE0;
    if ((uart_clock_enables & 4) != 0) {
      uart_tx_wait_idle(0);
    }
  }
  memw();
  reset_or_control_value = SYSTEM_RESET_ENABLE0;
  if ((reset_or_control_value & 0x20) == 0) {
    memw();
    reset_or_control_value = SYSTEM_CLOCK_ENABLE0;
    if ((reset_or_control_value & 0x20) != 0) {
      uart_tx_wait_idle(1);
    }
  }
  memw();
  reset_or_control_value = SYSTEM_RESET_ENABLE0;
  if ((reset_or_control_value & 0x200) == 0) {
    memw();
    reset_or_control_value = SYSTEM_CLOCK_ENABLE0;
    if ((reset_or_control_value & 0x200) != 0) {
      uart_tx_wait_idle(2);
    }
  }
  memw();
  reset_or_control_value = SYSTEM_CORE_RESET_ENABLE;
  memw();
  SYSTEM_CORE_RESET_ENABLE = reset_or_control_value | 0x3faf;
  memw();
  SYSTEM_CORE_RESET_ENABLE = 0;
  memw();
  reset_or_control_value = SYSTEM_RESET_ENABLE0;
  memw();
  SYSTEM_RESET_ENABLE0 = reset_or_control_value | 0x20120007;
  memw();
  SYSTEM_RESET_ENABLE0 = 0;
  memw();
  reset_or_control_value = SYSTEM_RESET_ENABLE1;
  memw();
  SYSTEM_RESET_ENABLE1 = reset_or_control_value | 0xfe;
  memw();
  SYSTEM_RESET_ENABLE1 = 0;
  memw();
  reset_or_control_value = SYSTEM_EDMA_CONTROL;
  memw();
  SYSTEM_EDMA_CONTROL = reset_or_control_value | 2;
  memw();
  reset_or_control_value = SYSTEM_EDMA_CONTROL;
  memw();
  SYSTEM_EDMA_CONTROL = reset_or_control_value & 0xfffffffd;
  return;
}

/* Native entry: 0x40375a14. */
/* Original function-byte SHA-256:
 * 7e19a876143684f48810896d4fb5fd18deee5ba6e8de9bc52884f89489e411c1. */
/*
 * Terminal restart path. Disables all interrupt-enable bits, ignoring the old
 * mask. Initializes ROM RTC WDT context(instance0,prescaler0,interrupt=false),
 * samples slow-clock Hz, unlocks it, sets stages0/1 to that same tick count with
 * actions3(system reset)/4(RTC reset), enables flashboot mode and relocks.
 * Copies each pinned8-byte TIMER0/TIMER1 WDT context, unlocks/disables/relocks
 * each through ROM. The returned frequency supplies intended one-second stage
 * counts; this routine does not measure the resulting reset timeout.
 *
 * The device-only external-stack recovery is absent in this host image. Then samples PRID bit13, resets the OTHER CPU before stalling it,
 * disables I-cache then D-cache, and MEMW/writes0x30 to GPIO input selectors0..5
 * in order. Resets the reviewed peripheral module set, restores XTAL CPU clock
 * configuration and MEMW/clears the other-core entry WORD at SYSTEM+4.
 * CPU0 resets CPU1 then CPU0; CPU1 resets CPU0, unstalls it, then resets CPU1.
 * Spins forever if execution survives those reset requests. No RTOS cleanup,
 * UART draining, flash flush, watchdog feed loop, local timeout or error return.
 */
void esp_restart_noos(void)
{
    RestartWatchdogFrame frame;
    (void)xt_ints_off(0xffffffffU);
    wdt_hal_init(&frame.rtc,WDT_RWDT,0,false);
    unsigned int stage_ticks = rtc_clk_slow_freq_get_hz();
    wdt_hal_write_protect_disable(&frame.rtc);
    wdt_hal_config_stage(&frame.rtc,WDT_STAGE0,stage_ticks,WDT_STAGE_ACTION_RESET_SYSTEM);
    wdt_hal_config_stage(&frame.rtc,WDT_STAGE1,stage_ticks,WDT_STAGE_ACTION_RESET_RTC);
    wdt_hal_set_flashboot_en(&frame.rtc,true);
    wdt_hal_write_protect_enable(&frame.rtc);
    WatchdogInstance instance0 = RESTART_WATCHDOG0_TEMPLATE->instance;
    TimerGroupRegisters *registers0 = RESTART_WATCHDOG0_TEMPLATE->mwdt_registers;
    frame.timer0.instance = instance0;
    frame.timer0.mwdt_registers = registers0;
    wdt_hal_write_protect_disable(&frame.timer0);
    wdt_hal_disable(&frame.timer0);
    wdt_hal_write_protect_enable(&frame.timer0);
    WatchdogInstance instance1 = RESTART_WATCHDOG1_TEMPLATE->instance;
    TimerGroupRegisters *registers1 = RESTART_WATCHDOG1_TEMPLATE->mwdt_registers;
    frame.timer1.instance = instance1;
    frame.timer1.mwdt_registers = registers1;
    wdt_hal_write_protect_disable(&frame.timer1);
    wdt_hal_disable(&frame.timer1);
    wdt_hal_write_protect_enable(&frame.timer1);

    unsigned int core = (xtensa_read_prid() >> 13) & 1U;
    unsigned int other_core = core == 0 ? 1U : 0U;
    software_reset_cpu(other_core);
    esp_cpu_stall(other_core);
    Cache_Disable_ICache();
    Cache_Disable_DCache();
    for (unsigned int index = 0; index < 6; ++index) {
        memw();
        RESTART_GPIO_DEFAULTS->select[index] = 0x30;
    }
    esp_system_reset_modules_on_exit();
    rtc_clk_cpu_set_to_default_config();
    memw(); RESTART_SYSTEM_REGISTERS->core1_entry = 0;
    if (core == 0) {
        software_reset_cpu(1);
        software_reset_cpu(0);
    } else {
        software_reset_cpu(0);
        esp_cpu_unstall(0);
        software_reset_cpu(1);
    }
    for (;;) __asm__ volatile ("" : : : "memory");
}

/* Native entry: 0x42002234. */
/* Original function-byte SHA-256:
 * c5c08a590ee7e2cd84158582c9f428a7b802717732afc2fce8f06745cf2e6904. */
/*
 * Visits shutdown slots4,3,2,1,0, reading each current callback only after the
 * previous one returns and skippingNULL. Callbacks may mutate later slots;
 * no callback snapshot, timeout, lock or recursion guard is supplied. After
 * all five visits calls vTaskSuspendAll, then the terminal esp_restart_noos.
 * No normal return. This wrapper itself does not disable interrupts, drain
 * peripherals or force progress past a callback that never returns.
 */
void esp_restart(void)
{
    for (int index = 4; index >= 0; --index) {
        ShutdownHandler handler = SHUTDOWN_HANDLERS[index];
        if (handler != 0) handler();
    }
    vTaskSuspendAll();
    esp_restart_noos();
}

/* Native entry: 0x42002324. */
/*
 * Medius v3.4.7 — host application; 0x42002324.
 *
 * Passes the five-byte configuration {7,1,0,1,1} to the HAL: threshold7, detector enabled,
 * hardware reset disabled, flash/RF power-down enabled. Clears brownout status, registers the
 * IRAM RTC callback with mask0x200, then enables that interrupt. The compiled caller ignores
 * registration failure.
 *
 * Calls: brownout_hal_config, rtc_isr_register.
 *
 * Called by: FUN_420022a0.
 *
 * Original function-byte SHA-256:
 * 8b6d65fe34c1dd1e60aade4b91ac864ab9556125cc713cff7ff5633dc1c8ff66.
 */

/* Reference: ESP-IDF v5.4.4 components/esp_system/port/brownout.c. */

/*
 * Returns: Nothing; the compiled caller ignores RTC callback-registration failure.
 * Requirements/effects: Initializes threshold7, detection enabled, hardware reset disabled and
 *   flash/RF power-down enabled. Clears status, requests the cache-safe RTC callback and enables
 *   bit0x200.
 */

void esp_brownout_init(void)
{
  BrownoutConfig configuration = {7, 1, 0, 1, 1};
  uint value;

  brownout_hal_config(&configuration);
  memw();
  value = RTC_INT_CLR;
  memw();
  RTC_INT_CLR = value | 0x200U;
  rtc_isr_register(rtc_brownout_isr_handler, (void *)0, 0x200U, 1U);
  memw();
  value = RTC_INT_ENA;
  memw();
  RTC_INT_ENA = value | 0x200U;
}

/* Native entry: 0x420026f0. */
/*
 * Medius v3.4.7 — host application; 0x420026f0.
 *
 * Returns the cached public reset reason populated by the startup constructor. It does not sample
 * the hardware reset register again or consume a retained hint.
 *
 * Called by: app_main.
 *
 * Original function-byte SHA-256:
 * 6d3f89f767bc1c8898b7494f516b4b037169f1c41b3d01b31c0ba4d560d3f01e.
 */

/* Reference: ESP-IDF v5.4.4 components/esp_system/port/soc/esp32s3/reset_reason.c. */

/*
 * Returns: Cached public reset-reason value set during startup.
 * Requirements/effects: Does not reread hardware reset cause or consume a retained hint.
 */

uint esp_reset_reason(void)

{
  return CACHED_RESET_REASON;
}

/* Native entry: 0x420026fc. */
/*
 * Medius v3.4.7 — host application; 0x420026fc.
 *
 * Reads RTC STORE6 once. Returns its low15-bit hint only when bit31 is set and both
 * duplicated15-bit halves match; returns UNKNOWN0 otherwise. It does not clear the retained hint
 * or read hardware reset cause.
 *
 * Called by: esp_reset_reason_init, FUN_42002c58.
 *
 * Original function-byte SHA-256:
 * 9b5af65ce2063a65494dbee6db1b90c3526cee595eec6b291af2f0124f212448.
 */

/* Reference: ESP-IDF v5.4.4 components/esp_system/port/soc/esp32s3/reset_reason.c. */

/*
 * Returns: The low15-bit hint only when bit31 is set and both copies match; otherwise0.
 * Requirements/effects: Reads RTC STORE6 once without clearing it or sampling hardware reset
 *   cause.
 */

uint esp_reset_reason_get_hint(void)

{
  uint encoded_hint;
  uint hint;

  memw();
  encoded_hint = RTC_RESET_HINT;
  hint = encoded_hint & 0x7fff;
  if (((encoded_hint >> 0x10 & 0x7fff) != hint) || (-1 < (int)encoded_hint)) {
    hint = 0;
  }
  return hint;
}

/* Native entry: 0x42002718. */
/*
 * Medius v3.4.7 — host application; 0x42002718.
 *
 * Startup constructor combines CPU0 ROM reset cause with the retained software hint and caches
 * the public reason. Software/core resets accept only PANIC4, INT_WDT5, TASK_WDT6 or BROWNOUT9
 * hints. Maps power-on, sleep, watchdog, brownout and USB causes; unknown codes map0. Clears
 * STORE6 when the decoded hint is nonzero.
 *
 * Calls: esp_reset_reason_get_hint, rtc_get_reset_reason.
 *
 * Original function-byte SHA-256:
 * ec1eb31ea37325ba8d3cf6157d421f14b83b49cd88ca246f5f416e8baa267370.
 */

/* Reference: ESP-IDF v5.4.4 components/esp_system/port/soc/esp32s3/reset_reason.c. */

/*
 * Returns: Nothing; writes the cached public reason once and conditionally clears the retained hint.
 * Requirements/effects: Startup constructor maps CPU0 ROM cause plus a valid software hint. Only
 *   hints4/5/6/9 override software/core resets; unknown causes map0. A nonzero decoded hint is
 *   consumed.
 */

void esp_reset_reason_init(void)

{
  uint hint = esp_reset_reason_get_hint();
  uint hardware_cause = (uint)rtc_get_reset_reason(0);
  uint public_reason;

  switch (hardware_cause) {
    case 1: public_reason = 1; break;  /* Power-on. */
    case 3:
    case 12:                         /* Software system/core reset. */
      public_reason = ((hint >= 4 && hint <= 6) || hint == 9) ? hint : 3;
      break;
    case 5: public_reason = 8; break;  /* Deep sleep. */
    case 7: public_reason = 6; break;  /* Task watchdog. */
    case 8: public_reason = 5; break;  /* Interrupt watchdog. */
    case 9:
    case 11:
    case 13:
    case 16:
    case 17:
    case 18: public_reason = 7; break; /* Other watchdog causes. */
    case 15: public_reason = 9; break; /* Brownout. */
    case 21:
    case 22: public_reason = 11; break; /* USB reset causes. */
    default: public_reason = 0; break;
  }
  CACHED_RESET_REASON = public_reason;
  if (hint != 0) {
    memw();
    RTC_RESET_HINT = 0;
  }
}

/* Native entry: 0x42003938. */
/*
 * Medius v3.4.7 — host application; 0x42003938.
 *
 * Disables analog hardware reset through FIB_SEL and BROWN_OUT, sets interrupt wait2, applies
 * flash/RF shutdown flags, pulses counter-clear, sets reset wait0x3ff/system level and reset-
 * enable flag, writes threshold through REGI2C block0x61/host1/register5 bits2..0, then applies
 * detector enable. Preserves separate volatile reads/writes and barriers; pointer/fields are not
 * validated.
 *
 * Calls: regi2c_ctrl_write_reg_mask.
 *
 * Called by: esp_brownout_init.
 *
 * Original function-byte SHA-256:
 * f999c7901bef9a15d87f51ebaac9422cd7873035c6a3aa458edeec30e4f352df.
 */

/* Reference: ESP-IDF v5.4.4 components/hal/brownout_hal.c and
   components/hal/esp32s3/include/hal/brownout_ll.h. */

/*
 * configuration: Readable5-byte threshold/enabled/reset-enabled/flash-power-down/RF-power-down
 *   configuration.
 * Returns: Nothing.
 * Requirements/effects: Raw flag bytes contribute bit0 only. Programs
 *   FIB_SEL/BROWN_OUT and analog REGI2C threshold in the documented order, preserving RMW
 *   barriers; takes no lock or pointer validation.
 *   Reads flash/RF bytes before their register reads, reset-enabled during the reset-wait
 *   RMW and detector-enabled after the threshold call; does not snapshot the configuration.
 */

void brownout_hal_config(const BrownoutConfig *configuration)

{
  uint register_value;
  const volatile BrownoutConfig *fields = configuration;
  unsigned char flag;
  unsigned char reset_enabled;

  memw();
  register_value = RTC_FIB_SELECT_REGISTER;
  memw();
  RTC_FIB_SELECT_REGISTER = register_value & 0xfffffffd;
  memw();
  register_value = RTC_BROWNOUT_REGISTER;
  memw();
  RTC_BROWNOUT_REGISTER = register_value & 0xefffffff;
  memw();
  register_value = RTC_BROWNOUT_REGISTER;
  memw();
  RTC_BROWNOUT_REGISTER = register_value & 0xffffc00f | 0x20;
  flag = fields->flash_power_down;
  memw();
  register_value = RTC_BROWNOUT_REGISTER;
  memw();
  RTC_BROWNOUT_REGISTER = (register_value & 0xffffbfffU) | ((uint)(flag & 1U) << 14);
  flag = fields->rf_power_down;
  memw();
  register_value = RTC_BROWNOUT_REGISTER;
  memw();
  RTC_BROWNOUT_REGISTER = (register_value & 0xffff7fffU) | ((uint)(flag & 1U) << 15);
  memw();
  register_value = RTC_BROWNOUT_REGISTER;
  memw();
  RTC_BROWNOUT_REGISTER = register_value | 0x20000000;
  memw();
  register_value = RTC_BROWNOUT_REGISTER;
  memw();
  RTC_BROWNOUT_REGISTER = register_value & 0xdfffffff;
  memw();
  register_value = RTC_BROWNOUT_REGISTER;
  reset_enabled = fields->reset_enabled;
  memw();
  RTC_BROWNOUT_REGISTER = register_value | 0x3ff0000;
  memw();
  register_value = RTC_BROWNOUT_REGISTER;
  memw();
  RTC_BROWNOUT_REGISTER = (register_value & 0xfbffffffU) | ((uint)(reset_enabled & 1U) << 26);
  memw();
  register_value = RTC_BROWNOUT_REGISTER;
  memw();
  RTC_BROWNOUT_REGISTER = register_value | 0x8000000;
  regi2c_ctrl_write_reg_mask(0x61, 1, 5, 2, 0, fields->threshold);
  flag = fields->enabled;
  memw();
  register_value = RTC_BROWNOUT_REGISTER;
  memw();
  RTC_BROWNOUT_REGISTER = (register_value & 0xbfffffffU) | ((uint)(flag & 1U) << 30);
  return;
}

/* Native entry: 0x42002200. */
/* Original function-byte SHA-256:
 * 3dc14626b785803ff3d1d4601aad9dece154d85cfba27d3123251fdd4f557f20. */
/*
 * Scans the five callback slots in order. At each slot checks equality first:
 * a match returns0x103, including a null handler meeting an empty slot. The
 * first empty slot otherwise receives handler and returns0, without examining
 * later slots, so a duplicate beyond a hole is accepted. Five occupied unequal
 * slots return0x101. No lock, compaction, full-array duplicate scan, callback
 * invocation or argument validation. This registers work; it does not run it.
 */
int esp_register_shutdown_handler(ShutdownHandler handler)
{
    for (unsigned int index = 0; index < 5; ++index) {
        ShutdownHandler current = SHUTDOWN_HANDLERS[index];
        if (current == handler) return 0x103;
        if (current == 0) {
            SHUTDOWN_HANDLERS[index] = handler;
            return 0;
        }
    }
    return 0x101;
}
