/* Medius v3.4.7 device — platform/reset.c.
 * Recovered C and native assembly, grouped for source navigation.
 * Original entry addresses, firmware-byte hashes and function comments follow.
 */

#include "../include/types.h"

/* Native entry: 0x40375b10. */
/*
 * Medius v3.4.7 — device application; 0x40375b10.
 *
 * Brownout interrupt callback: acknowledges, records the cause, drains UARTs and resets; never
 * returns.
 *
 * Calls: esp_reset_reason_set_hint, bootloader_flash_reset_chip, esp_cpu_stall, spi_flash_brownout_need_reset, ets_printf, software_reset,
 * uart_tx_wait_idle.
 *
 * Original function-byte SHA-256:
 * ea3dc23cea39becfef20f3bd52ef7d7e252a871ccb36a819fa0557794595bd93.
 */

__attribute__((noreturn))

/*
 * unused_argument: Unused RTC dispatcher context; not dereferenced.
 * Returns: Never returns: requests software reset and spins if ROM returns.
 * Requirements/effects: Brownout ISR context. Acknowledges bit0x200, stalls the other CPU, records
 *   hint9, conditionally resets flash or prints, and drains unreset/clocked UARTs. UART/SPI/ROM
 *   waits can be unbounded. All three native UART checks use system bank 0;
 *   UART2 is tested with bit 9 of that bank, without selecting bank 1.
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
   0x3fcabc50, 0x3fcabc7c; literals below represent their bytes. Reference: ESP-IDF v5.4.4
   components/esp_system/port/brownout.c. */

/* Native entry: 0x40375c7c. */
/*
 * Medius v3.4.7 — device application; 0x40375c7c.
 *
 * Asserts hint fits15 bits, duplicates it into bits0..14 and16..30 of RTC STORE6/RESET_CAUSE, and
 * sets bit31. This encodes a retained software hint for the next boot; it neither resets a CPU
 * nor changes the cached reset-reason result.
 *
 * Calls: __assert_func.
 *
 * Called by: rtc_brownout_isr_handler, FUN_420031a8, FUN_42010af8.
 *
 * Original function-byte SHA-256:
 * 27fdcbaf253449dc5bfb956de57a07ed85d3beb0dff56e2a5399568ad1141e9a.
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
  if (hint > 0x7fffU) {
    __assert_func(NULL, 0, NULL, NULL);
  }
  memw();
  RTC_RESET_HINT = (hint << 16) | hint | 0x80000000U;
  return;
}

/* Native entry: 0x40375ca8. */
/*
 * Medius v3.4.7 — device application; 0x40375ca8.
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
 * 0594ff96446a3777c3a7b5253020b7ca22bf4985e3248395bedbe10871ec02d5.
 */

/* Reference: ESP-IDF v5.4.4 components/esp_system/port/soc/esp32s3/system_internal.c. */

/*
 * Returns: Nothing.
 * Requirements/effects: Drains active UART0/1/2, pulses core/peripheral reset masks and EDMA
 *   reset. Writes the first reset banks back to0, rather than restoring their prior contents;
 *   caller owns shutdown ordering. The native UART2 check uses bank 0 bit 9,
 *   as do the two preceding UART checks; it does not select UART2's bank 1.
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

/* Native entry: 0x40375d90. */
/* Original function-byte SHA-256:
 * dd3261ebbb01d05ff170145e9f09fe729bc436903ade28896836e015369e7351. */
/*
 * Terminal restart path. Disables all interrupt-enable bits, ignoring the old
 * mask. Initializes ROM RTC WDT context(instance0,prescaler0,interrupt=false),
 * samples slow-clock Hz, unlocks it, sets stages0/1 to that same tick count with
 * actions3(system reset)/4(RTC reset), enables flashboot mode and relocks.
 * Copies each pinned8-byte TIMER0/TIMER1 WDT context, unlocks/disables/relocks
 * each through ROM. The returned frequency supplies intended one-second stage
 * counts; this routine does not measure the resulting reset timeout.
 *
 * If the current stack is external RAM, performs native window/stack recovery.
 * Then samples PRID bit 13, resets the other CPU before stalling it,
 * disables I-cache then D-cache, and MEMW/writes0x30 to GPIO input selectors0..5
 * in order. Calls the module-reset helper, which first drains UARTs using its
 * native bank-0 checks. Restores XTAL CPU clock
 * configuration and MEMW/clears the other-core entry WORD at SYSTEM+4.
 * CPU0 resets CPU1 then CPU0; CPU1 resets CPU0, unstalls it, then resets CPU1.
 * Spins forever if execution survives those reset requests. No RTOS cleanup,
 * flash flush, watchdog feed loop, local timeout or error return.
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

    /* Only the device build supports restart from an external-RAM task stack.
     * Native checks the stack-resident TIMER1 context, then switches to the
     * 16-byte-aligned internal stack-top WORD minus 48 bytes. The frame link at
     * top - 60 holds top. Reset PS window-overflow/call-increment state, retain
     * only the current register window, clear a0, move a1 and reenable WOE.
     * This terminal restart path never accesses the old local frame again.
     * Keep these architectural operations as assembly, as in IDF SET_STACK.
     */
    if (esp_ptr_external_ram(&frame.timer1)) {
        unsigned int top = *RESTART_INTERNAL_STACK_TOP & 0xfffffff0U;
        *(volatile unsigned int *)(top - 60U) = top;
        unsigned int new_stack = top - 48U;
        unsigned int scratch = 0,window_enable = 0;
        __asm__ volatile (
            "rsr.ps %[scratch]\n"
            "and %[scratch], %[scratch], %[mask]\n"
            "wsr.ps %[scratch]\n"
            "rsync\n"
            "rsr.windowbase %[scratch]\n"
            "ssl %[scratch]\n"
            "movi %[scratch], 1\n"
            "sll %[scratch], %[scratch]\n"
            "wsr.windowstart %[scratch]\n"
            "rsync\n"
            "movi a0, 0\n"
            "mov a1, %[stack]\n"
            "rsr.ps %[scratch]\n"
            "movi %[enable], 0x40000\n"
            "or %[scratch], %[scratch], %[enable]\n"
            "wsr.ps %[scratch]\n"
            "rsync\n"
            : [stack] "+a"(new_stack),[scratch] "+&a"(scratch),[enable] "+&a"(window_enable)
            : [mask] "a"(0xfff8f0ffU)
            : "memory");
    }

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

/* Native entry: 0x420028fc. */
/* Original function-byte SHA-256:
 * 47ec73230e42dd21cceae534f649db195ab295369b0cf78f36a728ea4719069c. */
/*
 * Visits shutdown slots 4, 3, 2, 1, 0, reading each current callback only after
 * the previous one returns and skipping NULL. Callbacks may mutate later slots;
 * no callback snapshot, timeout, lock or recursion guard is supplied. After
 * all five visits, calls vTaskSuspendAll, then the terminal esp_restart_noos.
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

/* Native entry: 0x420029ec. */
/*
 * Medius v3.4.7 — device application; 0x420029ec.
 *
 * Passes the five-byte configuration {7,1,0,1,1} to the HAL: threshold7, detector enabled,
 * hardware reset disabled, flash/RF power-down enabled. Clears brownout status, registers the
 * IRAM RTC callback with mask0x200, then enables that interrupt. The compiled caller ignores
 * registration failure.
 *
 * Calls: brownout_hal_config, rtc_isr_register.
 *
 * Called by: FUN_42002968.
 *
 * Original function-byte SHA-256:
 * 149b5912cbc85a40822aac5e1c5acbcc871eb595df183cc84eb4e9f17163adb2.
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

/* Native entry: 0x42002db0. */
/*
 * Medius v3.4.7 — device application; 0x42002db0.
 *
 * Returns the cached public reset reason populated by the startup constructor. It does not sample
 * the hardware reset register again or consume a retained hint.
 *
 * Called by: app_main.
 *
 * Original function-byte SHA-256:
 * e30b8593ea347f58f3f08f511458631897c48a89affb65d6f3ab89b56913e94c.
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

/* Native entry: 0x42002dbc. */
/*
 * Medius v3.4.7 — device application; 0x42002dbc.
 *
 * Reads RTC STORE6 once. Returns its low15-bit hint only when bit31 is set and both
 * duplicated15-bit halves match; returns UNKNOWN0 otherwise. It does not clear the retained hint
 * or read hardware reset cause.
 *
 * Called by: esp_reset_reason_init, FUN_420031a8.
 *
 * Original function-byte SHA-256:
 * 5ca4e99008ced56617c0aad7450cf76f89344df8108a733d8a9628a0bd0773dd.
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
  hint = encoded_hint & 0x7fffU;
  if (((encoded_hint >> 16) & 0x7fffU) != hint ||
      (encoded_hint & 0x80000000U) == 0) {
    hint = 0;
  }
  return hint;
}

/* Native entry: 0x42002dd8. */
/*
 * Medius v3.4.7 — device application; 0x42002dd8.
 *
 * Startup constructor combines CPU0 ROM reset cause with the retained software hint and caches
 * the public reason. Software/core resets accept only PANIC4, INT_WDT5, TASK_WDT6 or BROWNOUT9
 * hints. Maps power-on, sleep, watchdog, brownout and USB causes; unknown codes map0. Clears
 * STORE6 when the decoded hint is nonzero.
 *
 * Calls: esp_reset_reason_get_hint, rtc_get_reset_reason.
 *
 * Original function-byte SHA-256:
 * 52b716af614888c93e05048b4b4c48adddff5bfae454a7deeb3abd9b846299ca.
 */

/* Reference: ESP-IDF v5.4.4 components/esp_system/port/soc/esp32s3/reset_reason.c. */

/*
 * Returns: Nothing; writes the cached public reason once and conditionally clears the hint.
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

/* Native entry: 0x42003c04. */
/*
 * Medius v3.4.7 — device application; 0x42003c04.
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
 * ee93a00afa76caa641590eed6419f30ee186cac5b9c12131fb08247f3b057d89.
 */

/* Reference: ESP-IDF v5.4.4 components/hal/brownout_hal.c and
   components/hal/esp32s3/include/hal/brownout_ll.h. */

/*
 * configuration: Readable5-byte threshold/enabled/reset-enabled/flash-power-down/RF-power-down
 *   configuration.
 * Returns: Nothing.
 * Requirements/effects: Flag bytes contribute bit0 only, including noncanonical values. Programs
 *   FIB_SEL/BROWN_OUT and analog REGI2C threshold in the documented order, preserving RMW
 *   barriers; takes no lock or pointer validation.
 *   Reads flash/RF flags before their register reads, caches reset-enabled during the reset-wait
 *   RMW, and reads detector-enabled after programming the threshold. These are separate byte
 *   observations, not a configuration snapshot.
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

/* Native entry: 0x420028c8. */
/* Original function-byte SHA-256:
 * 1066009cdeac7ce68ff1e925f19973c9bb5af1dea8a9b6beee825895671c2386. */
/*
 * Scans the five callback slots in order. At each slot checks equality first:
 * a match returns 0x103, including a null handler meeting an empty slot. The
 * first empty slot otherwise receives handler and returns 0, without examining
 * later slots, so a duplicate beyond a hole is accepted. Five occupied unequal
 * slots return 0x101. No lock, compaction, full-array duplicate scan, callback
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
