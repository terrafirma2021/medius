/* Medius v3.4.7 device — SYSTIMER hardware ticks, alarms and conversions. */
#include "../include/types.h"

/* Native entry: 0x40386e44. */
/* Original function-byte SHA-256:
 * 3a696b99a5902047716cb3c8c296bc18784c72af5b32094412a709887eb35f9a. */
/* Service the current core's periodic hardware tick alarm on shared counter 1.
 * Clear the captured core's pending bit, sample the 52-bit counter, read that
 * alarm's 26-bit period, and take the low 32 bits of the unsigned quotient.
 * Subtract the handled count modulo 2^32. Publish a changed count before hooks;
 * when the previous count was zero, process one tick rather than replaying all.
 * Re-read PRID for every kernel tick, call the matching core's scheduler tick,
 * and request a switch for any nonzero result. Recheck pending and repeat.
 *
 * argument is an initialized SystimerHal; a nonzero period is required. The
 * native code supplies no zero-divisor guard, timeout, lock or catch-up bound.
 * The counter, alarm channels and handled counts retain their native wrapping. */
void SysTickIsrHandler(void *argument)
{
  SystimerHal *hal = argument;
  unsigned int core = (xtensa_read_prid() >> 13) & 1U;
  unsigned int alarm_bit = 1U << core;
  volatile unsigned int *handled_ticks = SYSTEM_HANDLED_TICKS;
  volatile unsigned int *registers = hal->dev;
  do {
    memw();
    unsigned int clear = registers[SYSTIMER_WORD_INTERRUPT_CLEAR]; /* INT_CLR */
    memw();
    registers[SYSTIMER_WORD_INTERRUPT_CLEAR] = clear | alarm_bit;
    unsigned long long counter = systimer_hal_get_counter_value(hal,1);
    registers = hal->dev;
    memw();
    unsigned int period_ticks = registers[SYSTIMER_WORD_ALARM_CONFIGURATION + core] & SYSTIMER_ALARM_PERIOD_MASK;
    unsigned int elapsed_ticks = (unsigned int)rom_unsigned_divide_u64(counter,(unsigned long long)period_ticks);
    unsigned int previous_ticks = handled_ticks[core];
    unsigned int pending_tick_count = elapsed_ticks - previous_ticks; /* Deliberate uint32 wraparound. */
    if (pending_tick_count != 0) {
      handled_ticks[core] = elapsed_ticks;
      if (previous_ticks == 0) {
        pending_tick_count = 1; /* First positive observation; do not replay pre-start ticks. */
      }
      do {
        esp_vApplicationTickHook();
        unsigned int tick_core = (xtensa_read_prid() >> 13) & 1U;
        int switch_required = tick_core == 0 ? xTaskIncrementTick() : xTaskIncrementTickOtherCores();
        if (switch_required != 0) {
          _frxt_setup_switch();
        }
      } while (--pending_tick_count != 0);
      registers = hal->dev;
    }
    memw();
  } while ((registers[SYSTIMER_WORD_INTERRUPT_STATUS] & alarm_bit) != 0); /* INT_ST */
}

/* Native entry: 0x40386ed4. */
/* Original function-byte SHA-256:
 * 683ab88e563eea240c05b2b3a605c52535fda179fc75bb3f4b351f216367a5b9. */
/* Install source 57 + core with flags 0x402 (IRAM and interrupt level 1).
 * Allocation failure aborts. Core 1 only enables its alarm interrupt and relies
 * on core 0 having initialized the shared HAL and counter 1.
 *
 * Core 0 acquires the peripheral reference guard. Only a zero previous byte
 * enables the bus clock and pulses reset; acquire-exit receives that original
 * byte. Initialize the HAL, copy the pinned conversion pair through a local
 * eight-byte object, then clear counter 1 HIGH/LOW and apply its load.
 * Reset both stall permissions and modes. For alarm 0, then 1, connect counter
 * 1, set a 1000-us period, select periodic mode and permit its CPU to stall it.
 * After configuring alarm 0, enable it and counter 1, then advance by 500 us.
 * Alarm 1 is configured here but its interrupt is enabled by core 1's call.
 *
 * Alarms 0/1 are dedicated hardware tick channels; the SYSTIMER peripheral is
 * shared with esp_timer's counter 0/alarm 2. No software timer is created. The
 * reference guard covers clock/reset changes, not the later HAL register work. */
void vSystimerSetup(void)
{
  unsigned int core = (xtensa_read_prid() >> 13) & 1U;
  SystimerHal *hal = SYSTEM_TICK_HAL;
  int allocation_status = esp_intr_alloc(core + SYSTIMER_TICK_INTERRUPT_SOURCE,SYSTIMER_TICK_INTERRUPT_FLAGS,
      SysTickIsrHandler,hal,(InterruptHandle **)0);
  if (allocation_status != 0) {
    abort();
  }
  if (core != 0) {
    systimer_hal_enable_alarm_int(hal,core);
    return;
  }

  unsigned char previous_count = periph_rcc_acquire_enter(PERIPH_SYSTIMER_MODULE);
  if (previous_count == 0) {
    SystemPeripheralRegistersPrefix *system_registers = SYSTEM_PERIPHERAL_REGISTERS;
    memw();
    unsigned int clock_config = system_registers->clock_enable0;
    memw();
    system_registers->clock_enable0 = clock_config | SYSTIMER_BUS_CLOCK_RESET_MASK;
    memw();
    unsigned int reset_config = system_registers->reset_enable0;
    memw();
    system_registers->reset_enable0 = reset_config | SYSTIMER_BUS_CLOCK_RESET_MASK;
    memw();
    reset_config = system_registers->reset_enable0;
    memw();
    system_registers->reset_enable0 = reset_config & ~SYSTIMER_BUS_CLOCK_RESET_MASK;
  }
  periph_rcc_acquire_exit(PERIPH_SYSTIMER_MODULE,previous_count);
  systimer_hal_init(hal);
  SystimerTickOps conversion_ops;
  SystimerConvert ticks_to_us = SYSTEM_TICK_CONVERSION_OPS->ticks_to_us;
  SystimerConvert us_to_ticks = SYSTEM_TICK_CONVERSION_OPS->us_to_ticks;
  conversion_ops.ticks_to_us = ticks_to_us;
  conversion_ops.us_to_ticks = us_to_ticks;
  systimer_hal_set_tick_rate_ops(hal,&conversion_ops);

  /* Original code loads dev once, then performs HIGH RMW, LOW write and LOAD. */
  volatile unsigned int *registers = hal->dev;
  memw();
  unsigned int counter_high = registers[SYSTIMER_WORD_COUNTER_LOAD_HIGH + 2U];
  memw();
  registers[SYSTIMER_WORD_COUNTER_LOAD_HIGH + 2U] = counter_high & ~SYSTIMER_HIGH_VALUE_MASK;
  memw();
  registers[SYSTIMER_WORD_COUNTER_LOAD_LOW + 2U] = 0;
  memw();
  registers[SYSTIMER_WORD_COUNTER_LOAD + 1U] = 1;
  systimer_hal_counter_can_stall_by_cpu(hal,1,0,0);
  systimer_hal_select_alarm_mode(hal,0,0);
  systimer_hal_counter_can_stall_by_cpu(hal,1,1,0);
  systimer_hal_select_alarm_mode(hal,1,0);

  unsigned int alarm_id = 0;
  while (true) {
    systimer_hal_connect_alarm_counter(hal,alarm_id,1);
    systimer_hal_set_alarm_period(hal,alarm_id,SYSTIMER_TICK_PERIOD_US);
    systimer_hal_select_alarm_mode(hal,alarm_id,1);
    systimer_hal_counter_can_stall_by_cpu(hal,1,alarm_id,1);
    if (alarm_id != 0) {
      break;
    }
    systimer_hal_enable_alarm_int(hal,0);
    systimer_hal_enable_counter(hal,1);
    systimer_hal_counter_value_advance(hal,1,SYSTIMER_TICK_PHASE_US);
    alarm_id = 1;
  }
}

/* Native entry: 0x40387004. */
/* Original function-byte SHA-256:
 * cb6a4b5b7f7db0f6d235e6a65676615939b89b4b5e071fb23271c9a4219c2f49. */
/* Per-core scheduler-startup wrapper for vSystimerSetup in this build.
 * No CCOUNT/CCOMPARE setup or software timer/service task is created here. */
void vPortSetupTimer(void)

{
  vSystimerSetup();
  return;
}

/* Native entry: 0x4038ac44. */
/* Original function-byte SHA-256:
 * 76d3d854c971434533b81379036758e5f08b194603f290115752497a507be5ad. */
/* Read SYSTIMER CONF, publish the fixed device pointer into hal->dev,
 * then write CONF with CLK_EN set. hal must address the 12-byte context.
 * Conversion pointers, counter values, alarms and interrupt state are untouched.
 * The device-pointer store remains between the native MMIO read and write. */
void systimer_hal_init(SystimerHal *hal)
{
  volatile unsigned int *registers = (volatile unsigned int *)SYSTIMER_REGISTER_BASE;
  memw();
  unsigned int configuration = registers[SYSTIMER_WORD_CONFIGURATION];
  hal->dev = registers;
  memw();
  registers[SYSTIMER_WORD_CONFIGURATION] = configuration | SYSTIMER_CLOCK_ENABLE; /* CONF.CLK_EN */
}

/* Native entry: 0x4038ac60. */
/* Original function-byte SHA-256:
 * 5702c3bca3aa6961362e1db1cc84d8aa5a5dbfa77830d676c8e2c0b0ecdf0b0b. */
/* Request a hardware snapshot and wait for VALUE_VALID with repeated reads.
 * Read LOW, then repeatedly read HIGH and LOW until consecutive LOW values
 * agree. HIGH is inside the retry loop. Return the coherent unsigned 52-bit
 * tick count, without calling either conversion callback.
 *
 * hal must supply a device pointer. counter_id normally selects 0 or 1; no
 * bounds check, per-call lock or timeout is supplied. The device pointer is
 * loaded once and retained across every snapshot and retry access. */
unsigned long long systimer_hal_get_counter_value(SystimerHal *hal,unsigned int counter_id)
{
  volatile unsigned int *registers = hal->dev;
  memw();
  unsigned int operation = registers[SYSTIMER_WORD_COUNTER_OPERATION + counter_id];
  memw();
  registers[SYSTIMER_WORD_COUNTER_OPERATION + counter_id] = operation | SYSTIMER_COUNTER_SNAPSHOT_UPDATE; /* UNITn_OP.UPDATE */
  do {
    memw();
  } while ((registers[SYSTIMER_WORD_COUNTER_OPERATION + counter_id] & SYSTIMER_COUNTER_VALUE_VALID) == 0); /* VALUE_VALID */
  memw();
  unsigned int low = registers[SYSTIMER_WORD_COUNTER_VALUE_LOW + 2U * counter_id];
  unsigned int high;
  unsigned int previous_low;
  do {
    memw();
    high = registers[SYSTIMER_WORD_COUNTER_VALUE_HIGH + 2U * counter_id];
    previous_low = low;
    memw();
    low = registers[SYSTIMER_WORD_COUNTER_VALUE_LOW + 2U * counter_id];
  } while (low != previous_low);
  /* HIGH is sampled on every retry, before its corresponding LOW read. */
  return ((unsigned long long)(high & SYSTIMER_HIGH_VALUE_MASK) << 32) | low;
}

/* Native entry: 0x4038aca8. */
/* Original function-byte SHA-256:
 * da4392ecf2b26fde477799ef73ab71e25f41e9b81056546d2180556cf510173c. */
/* Disable the alarm, then call hal->us_to_ticks with zero-extended period_us.
 * Check only the low 32 conversion bits against the 26-bit period limit;
 * abort on overflow. A nonzero returned high word is otherwise ignored.
 * Read and update period through the device pointer cached before the call.
 * Reload hal->dev before the period store, then use that new pointer to apply
 * the value and re-enable the alarm. This distinction survives callback changes
 * to hal->dev. Counter selection and periodic/one-shot mode are unchanged.
 *
 * hal and converter must be valid; alarm_id is unchecked. No lock or rollback
 * restores the disabled alarm when conversion or the overflow check fails. */
void systimer_hal_set_alarm_period(SystimerHal *hal,unsigned int alarm_id,unsigned int period_us)
{
  volatile unsigned int *period_registers = hal->dev;
  memw();
  unsigned int configuration = period_registers[SYSTIMER_WORD_CONFIGURATION];
  unsigned int enable_bit = 1U << ((24U - alarm_id) & 31U);
  SystimerConvert convert = hal->us_to_ticks;
  memw();
  period_registers[SYSTIMER_WORD_CONFIGURATION] = configuration & ~enable_bit;
  unsigned long long converted = convert((unsigned long long)period_us);
  unsigned int ticks = (unsigned int)converted; /* Only the low word is checked/stored. */
  if (ticks > SYSTIMER_ALARM_PERIOD_MASK) {
    abort();
  }
  memw();
  unsigned int target_config = period_registers[SYSTIMER_WORD_ALARM_CONFIGURATION + alarm_id];
  volatile unsigned int *apply_registers = hal->dev;
  memw();
  period_registers[SYSTIMER_WORD_ALARM_CONFIGURATION + alarm_id] = (target_config & ~SYSTIMER_ALARM_PERIOD_MASK) | ticks;
  memw();
  apply_registers[SYSTIMER_WORD_ALARM_LOAD + alarm_id] = 1; /* COMPn_LOAD */
  memw();
  configuration = apply_registers[SYSTIMER_WORD_CONFIGURATION];
  memw();
  apply_registers[SYSTIMER_WORD_CONFIGURATION] = configuration | enable_bit;
}

/* Native entry: 0x4038ad18. */
/* Original function-byte SHA-256:
 * 20012c857c5704b8bcd30816840995bfbc1960c43f9e13c48f3d6fa61d3c51fa. */
/* Sample the selected counter, then call us_to_ticks with delta_us's 64-bit
 * two's-complement bit pattern. Add the returned delta modulo 2^64. Reload
 * hal->dev after both calls, update HIGH's low 20 bits, write LOW, then LOAD.
 * The reserved HIGH bits are preserved and excess sum bits are discarded.
 *
 * counter_id is unchecked; hal and its callback must be valid. Conversion
 * determines delta semantics. The supplied left-shift converter makes negative
 * deltas subtract modulo the hardware width. No writer lock is acquired. */
void systimer_hal_counter_value_advance(SystimerHal *hal,unsigned int counter_id,long long delta_us)
{
  unsigned long long previous_ticks = systimer_hal_get_counter_value(hal,counter_id);
  unsigned long long delta_ticks = hal->us_to_ticks((unsigned long long)delta_us);
  volatile unsigned int *registers = hal->dev;
  unsigned long long updated_ticks = previous_ticks + delta_ticks;
  memw();
  unsigned int old_high = registers[SYSTIMER_WORD_COUNTER_LOAD_HIGH + 2U * counter_id];
  memw();
  registers[SYSTIMER_WORD_COUNTER_LOAD_HIGH + 2U * counter_id] = (old_high & ~SYSTIMER_HIGH_VALUE_MASK) | ((unsigned int)(updated_ticks >> 32) & SYSTIMER_HIGH_VALUE_MASK);
  memw();
  registers[SYSTIMER_WORD_COUNTER_LOAD_LOW + 2U * counter_id] = (unsigned int)updated_ticks;
  memw();
  registers[SYSTIMER_WORD_COUNTER_LOAD + counter_id] = 1; /* UNITn_LOAD */
}

/* Native entry: 0x4038ad6c. */
/* Original function-byte SHA-256:
 * 6f6946d4d582b567e74b7d33c7caa266e6c1c1cba8002585a9e565d00ef2335c. */
/* For mode 0, clear TARGET_CONF.PERIOD_MODE; for mode 1, set it.
 * Every other signed mode returns without dereferencing hal. Recognized modes
 * require initialized hal and a valid, unchecked alarm_id. Other fields are
 * preserved. This does not enable the alarm or change its period/counter. */
void systimer_hal_select_alarm_mode(SystimerHal *hal,unsigned int alarm_id,int mode)
{
  if (mode != 0 && mode != 1) {
    return; /* No HAL/device dereference on this path. */
  }
  volatile unsigned int *registers = hal->dev;
  memw();
  unsigned int configuration = registers[SYSTIMER_WORD_ALARM_CONFIGURATION + alarm_id];
  memw();
  if (mode == 0) {
    registers[SYSTIMER_WORD_ALARM_CONFIGURATION + alarm_id] = configuration & ~SYSTIMER_ALARM_PERIODIC_MODE;
  } else {
    registers[SYSTIMER_WORD_ALARM_CONFIGURATION + alarm_id] = configuration | SYSTIMER_ALARM_PERIODIC_MODE; /* PERIOD_MODE */
  }
}

/* Native entry: 0x4038adac. */
/* Original function-byte SHA-256:
 * 1d6f9f180d933d4c35ba01ca54da8de538e7ff8c76f69622f983fcf109788dca. */
/* Load both callback words from ops before writing either destination word
 * at hal offsets 4 and 8, preserving the native behavior for overlapping views.
 * No callback is invoked or validated. The device pointer is not accessed.
 * ops must expose eight readable bytes and hal twelve writable bytes; callers
 * serialize publication if other code can read the conversion pointers. */
void systimer_hal_set_tick_rate_ops(SystimerHal *hal,const SystimerTickOps *ops)
{
  const volatile SystimerTickOps *source = ops;
  volatile SystimerHal *destination = hal;
  SystimerConvert ticks_to_us = source->ticks_to_us;
  SystimerConvert us_to_ticks = source->us_to_ticks;
  destination->ticks_to_us = ticks_to_us;
  destination->us_to_ticks = us_to_ticks;
}

/* Native entry: 0x4038adbc. */
/* Original function-byte SHA-256:
 * 4f669eb70966b331cd8ebddb9f0e4037e61796d4af7a4db7389db82c8230db1a. */
/* Call us_to_ticks before loading hal->dev or disabling the alarm. Update
 * HIGH's low 20 bits, write LOW, apply COMP_LOAD, then re-enable the alarm.
 * Preserve reserved HIGH/configuration bits. The converted high bits above
 * the 52-bit hardware target are discarded.
 *
 * target_us is unsigned 64-bit microseconds; hal/converter must be valid and
 * alarm_id is unchecked. This S3 path has no software deadline-retry loop,
 * period change, counter change, writer lock or failure rollback. */
void systimer_hal_set_alarm_target(SystimerHal *hal,unsigned int alarm_id,unsigned long long target_us)
{
  unsigned long long target_ticks = hal->us_to_ticks(target_us);
  volatile unsigned int *registers = hal->dev;
  memw();
  unsigned int configuration = registers[SYSTIMER_WORD_CONFIGURATION];
  unsigned int enable_bit = 1U << ((24U - alarm_id) & 31U);
  memw();
  registers[SYSTIMER_WORD_CONFIGURATION] = configuration & ~enable_bit;
  memw();
  unsigned int old_high = registers[SYSTIMER_WORD_ALARM_TARGET_HIGH + 2U * alarm_id];
  memw();
  registers[SYSTIMER_WORD_ALARM_TARGET_HIGH + 2U * alarm_id] = (old_high & ~SYSTIMER_HIGH_VALUE_MASK) | ((unsigned int)(target_ticks >> 32) & SYSTIMER_HIGH_VALUE_MASK);
  memw();
  registers[SYSTIMER_WORD_ALARM_TARGET_LOW + 2U * alarm_id] = (unsigned int)target_ticks;
  memw();
  registers[SYSTIMER_WORD_ALARM_LOAD + alarm_id] = 1; /* COMPn_LOAD */
  memw();
  configuration = registers[SYSTIMER_WORD_CONFIGURATION];
  memw();
  registers[SYSTIMER_WORD_CONFIGURATION] = configuration | enable_bit;
}

/* Native entry: 0x4038ae20. */
/* Original function-byte SHA-256:
 * 97dbe3523ebae612aed27f917fc403f4da9d2777a2627987325e006c136f6441. */
/* Set the masked alarm bit in INT_ENA with a fresh MMIO read/modify/write.
 * hal must be initialized; alarm_id is unchecked and the native shift uses
 * its low five bits. Pending status, comparator enable and ISR registration
 * are untouched. Caller supplies synchronization with competing writers. */
void systimer_hal_enable_alarm_int(SystimerHal *hal,unsigned int alarm_id)
{
  volatile unsigned int *registers = hal->dev;
  memw();
  unsigned int enabled = registers[SYSTIMER_WORD_INTERRUPT_ENABLE]; /* INT_ENA, byte offset 0x64 */
  memw();
  registers[SYSTIMER_WORD_INTERRUPT_ENABLE] = enabled | (1U << (alarm_id & 31U));
}

/* Native entry: 0x4038ae40. */
/* Original function-byte SHA-256:
 * f0fda0df3473ca989a88551a7ec03c88a60f48ea78a3661257b079d76ed24621. */
/* Set CONF bit (30 - counter_id) modulo 32 to run the selected counter.
 * IDs 0/1 are expected but unchecked. Requires initialized hal; no counter
 * reset, stall-permission change, interrupt setup or writer lock is provided. */
void systimer_hal_enable_counter(SystimerHal *hal,unsigned int counter_id)
{
  volatile unsigned int *registers = hal->dev;
  memw();
  unsigned int configuration = registers[SYSTIMER_WORD_CONFIGURATION];
  memw();
  registers[SYSTIMER_WORD_CONFIGURATION] = configuration | (1U << ((30U - counter_id) & 31U));
}

/* Native entry: 0x4038ae64. */
/* Original function-byte SHA-256:
 * 73715616f0383c93aef1bccb3f76a591f4fc1449cd3d9857ca18d8fb2fe009eb. */
/* Replace TARGET_CONF bit 31 with counter_id bit 0 and preserve all other
 * fields. Both IDs are unchecked; normal hardware IDs are alarms 0..2 and
 * counters 0/1. Requires initialized hal. No counter reset or alarm enable. */
void systimer_hal_connect_alarm_counter(SystimerHal *hal,unsigned int alarm_id,unsigned int counter_id)
{
  volatile unsigned int *registers = hal->dev;
  memw();
  unsigned int configuration = registers[SYSTIMER_WORD_ALARM_CONFIGURATION + alarm_id];
  memw();
  registers[SYSTIMER_WORD_ALARM_CONFIGURATION + alarm_id] = (configuration & 0x7fffffffU) | (counter_id << 31);
}

/* Native entry: 0x4038ae88. */
/* Original function-byte SHA-256:
 * f36c88ce72885df3c75383e7db4e0951f9669ede66395ee1ca5e2e4042fe1657. */
/* Set or clear CONF bit (28 - 2*counter_id - cpu_id) modulo 32 from the
 * low BYTE can_stall: zero clears, any nonzero byte sets. IDs are unchecked.
 * This permits hardware counter stalling when a CPU stalls; it does not
 * immediately stop a timer/task. Requires initialized hal and caller locking. */
void systimer_hal_counter_can_stall_by_cpu(SystimerHal *hal,unsigned int counter_id,unsigned int cpu_id,unsigned char can_stall)
{
  volatile unsigned int *registers = hal->dev;
  memw();
  unsigned int configuration = registers[SYSTIMER_WORD_CONFIGURATION];
  unsigned int bit = 1U << ((28U - 2U * counter_id - cpu_id) & 31U);
  memw();
  registers[SYSTIMER_WORD_CONFIGURATION] = can_stall ? configuration | bit : configuration & ~bit;
}

/* Native entry: 0x403854b8. */
/* Original function-byte SHA-256:
 * 94f52d30c5f235b4135c3e40306d8d63999337e7d2f196dcc4b32d6ad83ed827. */
/* Convert unsigned 64-bit hardware ticks to whole microseconds: shift
 * right by four for 16 ticks/us. Fractional ticks are truncated; no effects. */
unsigned long long systimer_ticks_to_us(unsigned long long ticks)
{
    return ticks >> 4;
}

/* Native entry: 0x403854c8. */
/* Original function-byte SHA-256:
 * 6e399c2ef5b291d0752dde0d8fcb83850f8141d6860df9aaebe8fd0a60df63a1. */
/* Convert unsigned 64-bit microseconds to ticks: shift left by four,
 * modulo 2^64. No saturation, range check, context access or other effects. */
unsigned long long systimer_us_to_ticks(unsigned long long microseconds)
{
    return microseconds << 4;
}
