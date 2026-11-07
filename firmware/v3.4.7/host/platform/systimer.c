/* Medius v3.4.7 host — platform/systimer.c.
 * Recovered C and native assembly, grouped for source navigation.
 * Original entry addresses, firmware-byte hashes and function comments follow.
 */

#include "../include/types.h"

/* Native entry: 0x40382124. */
/*
 * Medius v3.4.7 — host application; 0x40382124.
 *
 * Clears the current core alarm interrupt, samples shared OS counter 1 and divides by that alarm
 * period to count elapsed ticks. Keeps the low 32-bit quotient and per-core handled count; first
 * observation processes only one tick. Invokes tick hooks and core-specific scheduler tick work
 * for each elapsed tick, requests a switch when needed, and repeats while pending. Counter
 * sampling is 52-bit; this accounting wraps modulo 32 bits.
 *
 * Calls: esp_vApplicationTickHook, _frxt_setup_switch, xTaskIncrementTick, xTaskIncrementTickOtherCores, __udivdi3,
 * systimer_hal_get_counter_value.
 *
 * Original function-byte SHA-256:
 * b71e67f30c003134a441e738e5865e0d772ed1e97a45279850cf742e680c30f6.
 */

/* Clears the current core alarm interrupt, samples shared OS counter 1 and divides by that alarm
   period to count elapsed ticks. Keeps the low 32-bit quotient and per-core handled count; first
   observation processes only one tick. Invokes tick hooks and core-specific scheduler tick work
   for each elapsed tick, requests a switch when needed, and repeats while pending. Counter
   sampling is 52-bit; this accounting wraps modulo 32 bits. Reference: ESP-IDF v5.4.4
   components/freertos/port_systick.c. */

/*
 * argument: Writable 12-byte SystimerHal context installed as the interrupt argument.
 * Returns: Nothing; advances kernel ticks and requests switches.
 * Requirements/effects: ISR context requires initialized counter1, a nonzero comparator period and
 *   live per-core tick counters. Clears/rechecks pending status and accounts elapsed ticks
 *   modulo32 bits.
 */

void SysTickIsrHandler(void *argument)
{
  SystimerHal *hal = argument;
  uint core = (xtensa_read_prid() >> 13) & 1U;
  uint alarm_bit = 1U << core;
  volatile uint *handled_ticks = SYSTEM_HANDLED_TICKS;
  volatile uint *regs = hal->dev;
  do {
    memw();
    uint clear = regs[27]; /* INT_CLR */
    memw();
    regs[27] = clear | alarm_bit;
    ulonglong counter = systimer_hal_get_counter_value(hal,1);
    regs = hal->dev;
    memw();
    uint period_ticks = regs[core + 13] & 0x03ffffffU;
    uint elapsed = (uint)rom_unsigned_divide_u64(counter,(ulonglong)period_ticks);
    uint previous = handled_ticks[core];
    uint diff = elapsed - previous; /* Deliberate uint32 wraparound. */
    if (diff != 0) {
      handled_ticks[core] = elapsed;
      if (previous == 0) {
        diff = 1; /* First positive observation; do not replay pre-start ticks. */
      }
      do {
        esp_vApplicationTickHook();
        uint tick_core = (xtensa_read_prid() >> 13) & 1U;
        int switch_required = tick_core == 0 ? xTaskIncrementTick() : xTaskIncrementTickOtherCores();
        if (switch_required != 0) {
          _frxt_setup_switch();
        }
      } while (--diff != 0);
      regs = hal->dev;
    }
    memw();
  } while ((regs[28] & alarm_bit) != 0); /* INT_ST */
}

/* Native entry: 0x403821b4. */
/*
 * Medius v3.4.7 — host application; 0x403821b4.
 *
 * Installs the per-core hardware tick ISR at source 57+core with IRAM/level-1 flags 0x402. Core 0
 * acquires the peripheral clock/reset guard, initializes shared SYSTIMER counter 1 and periodic
 * alarms 0/1 for 1000 us, sets CPU stall permissions, starts counter/alarm 0 and adds a 500-us
 * phase offset. Core 1 enables alarm 1. Hardware peripheral is shared with esp_timer alarm 2;
 * these are dedicated tick alarm channels in ISR context, not software timers.
 *
 * Calls: systimer_hal_set_alarm_period, systimer_hal_counter_value_advance, systimer_hal_select_alarm_mode, systimer_hal_enable_alarm_int, systimer_hal_enable_counter, systimer_hal_connect_alarm_counter,
 * systimer_hal_counter_can_stall_by_cpu, periph_rcc_acquire_enter, periph_rcc_acquire_exit, abort, esp_intr_alloc, systimer_hal_init,
 * systimer_hal_set_tick_rate_ops.
 *
 * Called by: vPortSetupTimer.
 *
 * Original function-byte SHA-256:
 * 6e525d23e2b174c90d0d232d2d7ce244cb8edb81459bedb56309159ea13efd56.
 */

/* Installs the per-core hardware tick ISR at source 57+core with IRAM/level-1 flags 0x402. Core 0
   acquires the peripheral clock/reset guard, initializes shared SYSTIMER counter 1 and periodic
   alarms 0/1 for 1000 us, sets CPU stall permissions, starts counter/alarm 0 and adds a 500-us
   phase offset. Core 1 enables alarm 1. Hardware peripheral is shared with esp_timer alarm 2;
   these are dedicated tick alarm channels in ISR context, not software timers. Reference: ESP-IDF
   v5.4.4 components/freertos/port_systick.c. */

/*
 * Returns: Nothing on success; interrupt-allocation failure aborts.
 * Requirements/effects: Startup-only per-CPU setup. CPU1 requires the shared HAL to be
 *   initialized. CPU0 initializes counter1 and both tick comparators; only its comparator0 is
 *   enabled here. The shared reference guard covers clock/reset changes, not all later register
 *   writes.
 */

void vSystimerSetup(void)
{
  uint core = (xtensa_read_prid() >> 13) & 1U;
  SystimerHal *hal = SYSTEM_TICK_HAL;
  int allocation_status = esp_intr_alloc(core + 57U,0x402,
      SysTickIsrHandler,hal,(InterruptHandle **)0);
  if (allocation_status != 0) {
    abort();
  }
  if (core != 0) {
    systimer_hal_enable_alarm_int(hal,core);
    return;
  }

  uchar previous_count = periph_rcc_acquire_enter(36);
  if (previous_count == 0) {
    volatile uint *system_regs = (volatile uint *)0x600c0000U;
    memw();
    uint clock_config = system_regs[6];
    memw();
    system_regs[6] = clock_config | 0x20000000U;
    memw();
    uint reset_config = system_regs[8];
    memw();
    system_regs[8] = reset_config | 0x20000000U;
    memw();
    reset_config = system_regs[8];
    memw();
    system_regs[8] = reset_config & 0xdfffffffU;
  }
  periph_rcc_acquire_exit(36,previous_count);
  systimer_hal_init(hal);
  SystimerTickOps conversion_ops;
  SystimerConvert ticks_to_us = SYSTEM_TICK_CONVERSION_OPS->ticks_to_us;
  SystimerConvert us_to_ticks = SYSTEM_TICK_CONVERSION_OPS->us_to_ticks;
  conversion_ops.ticks_to_us = ticks_to_us;
  conversion_ops.us_to_ticks = us_to_ticks;
  systimer_hal_set_tick_rate_ops(hal,&conversion_ops);

  /* Original code loads dev once, then performs HIGH RMW, LOW write and LOAD. */
  volatile uint *regs = hal->dev;
  memw();
  uint counter_high = regs[5];
  memw();
  regs[5] = counter_high & 0xfff00000U;
  memw();
  regs[6] = 0;
  memw();
  regs[24] = 1;
  systimer_hal_counter_can_stall_by_cpu(hal,1,0,0);
  systimer_hal_select_alarm_mode(hal,0,0);
  systimer_hal_counter_can_stall_by_cpu(hal,1,1,0);
  systimer_hal_select_alarm_mode(hal,1,0);

  uint alarm_id = 0;
  while (true) {
    systimer_hal_connect_alarm_counter(hal,alarm_id,1);
    systimer_hal_set_alarm_period(hal,alarm_id,1000);
    systimer_hal_select_alarm_mode(hal,alarm_id,1);
    systimer_hal_counter_can_stall_by_cpu(hal,1,alarm_id,1);
    if (alarm_id != 0) {
      break;
    }
    systimer_hal_enable_alarm_int(hal,0);
    systimer_hal_enable_counter(hal,1);
    systimer_hal_counter_value_advance(hal,1,500);
    alarm_id = 1;
  }
}

/* Native entry: 0x403822e4. */
/*
 * Medius v3.4.7 — host application; 0x403822e4.
 *
 * For this SYSTIMER build, calls vSystimerSetup. Does not use the Xtensa CCOUNT/CCOMPARE tick
 * implementation or create a software timer/service task.
 *
 * Calls: vSystimerSetup.
 *
 * Called by: xPortStartScheduler.
 *
 * Original function-byte SHA-256:
 * cb6a4b5b7f7db0f6d235e6a65676615939b89b4b5e071fb23271c9a4219c2f49.
 */

/* For this SYSTIMER build, calls vSystimerSetup. Does not use the Xtensa CCOUNT/CCOMPARE tick
   implementation or create a software timer/service task. Reference: ESP-IDF v5.4.4
   components/freertos/port_systick.c. */

/*
 * Returns: Nothing; delegates to vSystimerSetup.
 * Requirements/effects: Per-CPU scheduler startup. Creates no software timer or service task.
 */

void vPortSetupTimer(void)

{
  vSystimerSetup();
  return;
}

/* Native entry: 0x40385bc4. */
/*
 * Medius v3.4.7 — host application; 0x40385bc4.
 *
 * Stores SYSTIMER base 0x60023000 in hal->dev and sets CONF clock-enable bit 31. Does not reset
 * counters or alarms, install conversion callbacks, enable alarm interrupts, or provide
 * synchronization.
 *
 * Called by: vSystimerSetup, esp_timer_impl_early_init.
 *
 * Original function-byte SHA-256:
 * 140921d4db8576003dcaffb6e901fb99462d9743cc8b7dd205694001a284e48d.
 */

/* Stores SYSTIMER base 0x60023000 in hal->dev and sets CONF clock-enable bit 31. Does not reset
   counters or alarms, install conversion callbacks, enable alarm interrupts, or provide
   synchronization. MMIO accesses retain their instruction order and MEMW barriers. Volatile
   locals prevent decompiler read-hoisting artifacts. Reference: ESP-IDF v5.4.4
   components/hal/systimer_hal.c and hal/esp32s3/include/hal/systimer_ll.h. */

/*
 * hal: Writable 12-byte HAL context; only its dev pointer is initialized here.
 * Returns: Nothing.
 * Requirements/effects: Assigns SYSTIMER base and enables its clock. Does not initialize
 *   conversion callbacks, counter values or alarms.
 */

void systimer_hal_init(SystimerHal *hal)
{
  volatile uint *regs = (volatile uint *)0x60023000;
  memw();
  uint config = regs[0];
  hal->dev = regs;
  memw();
  regs[0] = config | 0x80000000U; /* CONF.CLK_EN */
}

/* Native entry: 0x40385be0. */
/*
 * Medius v3.4.7 — host application; 0x40385be0.
 *
 * Requests a counter snapshot, busy-waits for its value-valid bit, then reads low/high/low until
 * the low words agree. Returns the 52-bit hardware count as uint64; no timeout or counter-ID
 * bounds check. This is a coherent sample, not a microsecond conversion.
 *
 * Called by: SysTickIsrHandler, systimer_hal_counter_value_advance, esp_timer_get_time.
 *
 * Original function-byte SHA-256:
 * 2fc48034965739ebd825cb0e80cc2ac2b03dbd175bd1eaa046888955d6efb4d3.
 */

/* Requests a counter snapshot, busy-waits for its value-valid bit, then reads low/high/low until
   the low words agree. Returns the 52-bit hardware count as uint64; no timeout or counter-ID
   bounds check. This is a coherent sample, not a microsecond conversion. MMIO accesses
   retain their instruction order and MEMW barriers. The volatile register pointer preserves these accesses
   in this rendering. The local MEMW-aware decompiler now also retains HIGH inside the retry loop.
   Native instructions read HIGH at +0x33, then LOW at +0x3a and branch back to HIGH on mismatch. Reference:
   ESP-IDF v5.4.4 components/hal/systimer_hal.c and hal/esp32s3/include/hal/systimer_ll.h. */

/*
 * hal: Writable 12-byte SystimerHal context whose dev pointer addresses SYSTIMER registers.
 * counter_id: Hardware counter 0 or 1; unchecked here.
 * Returns: Coherent unsigned 52-bit hardware count, in ticks.
 * Requirements/effects: Requires initialized dev and valid counter ID. Busy-waits without timeout
 *   and repeats HIGH/LOW reads until consecutive LOW values agree; no lock.
 */

ulonglong systimer_hal_get_counter_value(SystimerHal *hal,uint counter_id)
{
  volatile uint *regs = hal->dev;
  memw();
  uint operation = regs[counter_id + 1];
  memw();
  regs[counter_id + 1] = operation | 0x40000000U; /* UNITn_OP.UPDATE */
  do {
    memw();
  } while ((regs[counter_id + 1] & 0x20000000U) == 0); /* VALUE_VALID */
  memw();
  uint low = regs[2 * counter_id + 17];
  uint high;
  uint previous_low;
  do {
    memw();
    high = regs[2 * counter_id + 16];
    previous_low = low;
    memw();
    low = regs[2 * counter_id + 17];
  } while (low != previous_low);
  /* HIGH is sampled on every retry, before its corresponding LOW read. */
  return ((ulonglong)(high & 0x000fffffU) << 32) | low;
}

/* Native entry: 0x40385c28. */
/*
 * Medius v3.4.7 — host application; 0x40385c28.
 *
 * Disables the selected alarm in CONF, converts period_us through us_to_ticks, checks the low
 * 32-bit tick result is below 2^26, writes TARGETn_CONF period bits 0..25, applies the value, and
 * re-enables the alarm. Does not choose periodic mode or its source counter; those are separate
 * calls.
 *
 * Calls: abort.
 *
 * Called by: vSystimerSetup.
 *
 * Indirect call: hal->us_to_ticks converts the supplied microseconds to hardware ticks.
 *
 * Original function-byte SHA-256:
 * aa8c45d24172be8cc9d2d4697f446c145bbf247f49bb012f0a829dcda7574a0f.
 */

/* Disables the selected alarm in CONF, converts period_us through us_to_ticks, checks the low
   32-bit tick result is below 2^26, writes TARGETn_CONF period bits 0..25, applies the value, and
   re-enables the alarm. Does not choose periodic mode or its source counter; those are separate
   calls. MMIO accesses retain their instruction order and MEMW barriers. Volatile locals
   prevent decompiler read-hoisting artifacts. Reference: ESP-IDF v5.4.4
   components/hal/systimer_hal.c and hal/esp32s3/include/hal/systimer_ll.h. */

/*
 * hal: Writable 12-byte SystimerHal context whose dev pointer addresses SYSTIMER registers.
 * alarm_id: Hardware comparator 0, 1 or 2; unchecked here.
 * period_us: Unsigned 32-bit microsecond period passed through us_to_ticks.
 * Returns: Nothing; aborts if the low32 converted bits exceed 0x03ffffff.
 * Requirements/effects: Requires a valid converter. Disables/programs/applies/re-enables the
 *   comparator period; caller excludes competing register writers.
 */

void systimer_hal_set_alarm_period(SystimerHal *hal,uint alarm_id,uint period_us)
{
  volatile uint *period_regs = hal->dev;
  memw();
  uint config = period_regs[0];
  uint enable_bit = 1U << ((24U - alarm_id) & 31U);
  SystimerConvert convert = hal->us_to_ticks;
  memw();
  period_regs[0] = config & ~enable_bit;
  ulonglong converted = convert((ulonglong)period_us);
  uint ticks = (uint)converted; /* Only the low word is checked/stored. */
  if (ticks > 0x03ffffffU) {
    abort();
  }
  memw();
  uint target_config = period_regs[alarm_id + 13];
  volatile uint *apply_regs = hal->dev;
  memw();
  period_regs[alarm_id + 13] = (target_config & 0xfc000000U) | ticks;
  memw();
  apply_regs[alarm_id + 20] = 1; /* COMPn_LOAD */
  memw();
  config = apply_regs[0];
  memw();
  apply_regs[0] = config | enable_bit;
}

/* Native entry: 0x40385c98. */
/*
 * Medius v3.4.7 — host application; 0x40385c98.
 *
 * Reads the selected 52-bit counter, converts the signed microsecond delta through the uint64
 * us_to_ticks callback, adds modulo 64 bits, writes the low 32/high 20 counter-load fields, and
 * applies the new count. Positive deltas advance and two-complement negative deltas subtract
 * modulo hardware width. Hardware update is not atomic with other writers.
 *
 * Calls: systimer_hal_get_counter_value.
 *
 * Called by: vSystimerSetup.
 *
 * Indirect call: hal->us_to_ticks converts the supplied microseconds to hardware ticks.
 *
 * Original function-byte SHA-256:
 * 20012c857c5704b8bcd30816840995bfbc1960c43f9e13c48f3d6fa61d3c51fa.
 */

/* Reads the selected 52-bit counter, converts the signed microsecond delta through the uint64
   us_to_ticks callback, adds modulo 64 bits, writes the low 32/high 20 counter-load fields, and
   applies the new count. Positive deltas advance and two-complement negative deltas subtract
   modulo hardware width. Hardware update is not atomic with other writers. MMIO accesses
   retain their instruction order and MEMW barriers. Volatile locals prevent decompiler read-
   hoisting artifacts. Reference: ESP-IDF v5.4.4 components/hal/systimer_hal.c and
   hal/esp32s3/include/hal/systimer_ll.h. */

/*
 * hal: Writable 12-byte SystimerHal context whose dev pointer addresses SYSTIMER registers.
 * counter_id: Hardware counter 0 or 1; unchecked here.
 * delta_us: Signed 64-bit microsecond adjustment forwarded to the uint64 converter by its two-
 *   complement bit pattern.
 * Returns: Nothing.
 * Requirements/effects: Requires a converter. Adds modulo64 and applies the low32/high20 counter-
 *   load fields; caller excludes competing counter writers.
 */

void systimer_hal_counter_value_advance(SystimerHal *hal,uint counter_id,longlong delta_us)
{
  ulonglong previous = systimer_hal_get_counter_value(hal,counter_id);
  ulonglong delta_ticks = hal->us_to_ticks((ulonglong)delta_us);
  volatile uint *regs = hal->dev;
  ulonglong next = previous + delta_ticks;
  memw();
  uint old_high = regs[2 * counter_id + 3];
  memw();
  regs[2 * counter_id + 3] = (old_high & 0xfff00000U) | ((uint)(next >> 32) & 0x000fffffU);
  memw();
  regs[2 * counter_id + 4] = (uint)next;
  memw();
  regs[counter_id + 23] = 1; /* UNITn_LOAD */
}

/* Native entry: 0x40385cec. */
/*
 * Medius v3.4.7 — host application; 0x40385cec.
 *
 * Mode 0 clears TARGETn_CONF bit 30 for one-shot; mode 1 sets it for periodic. Other modes leave
 * the register unchanged. The value 0x40000000 is a register bit mask, not a Bluetooth ROM
 * function pointer. Does not enable the alarm or change its period/counter.
 *
 * Called by: vSystimerSetup, esp_timer_impl_early_init.
 *
 * Original function-byte SHA-256:
 * 33fb038c070e2758e525fe4e849d1d6d40c30bee8301626346893bda9b12d2b6.
 */

/* Mode 0 clears TARGETn_CONF bit 30 for one-shot; mode 1 sets it for periodic. Other modes leave
   the register unchanged. The value 0x40000000 is a register bit mask, not a Bluetooth ROM
   function pointer. Does not enable the alarm or change its period/counter. MMIO accesses
   retain their instruction order and MEMW barriers. Volatile locals prevent decompiler read-
   hoisting artifacts. Reference: ESP-IDF v5.4.4 components/hal/systimer_hal.c and
   hal/esp32s3/include/hal/systimer_ll.h. */

/*
 * hal: HAL context, dereferenced only for mode0 or mode1.
 * alarm_id: Hardware comparator 0, 1 or 2; unchecked here.
 * mode: 0 selects one-shot, 1 periodic; other values return without dereferencing hal.
 * Returns: Nothing.
 * Requirements/effects: Recognized modes require valid HAL/ID and caller serialization of
 *   TARGETn_CONF updates. Does not enable the comparator.
 */

void systimer_hal_select_alarm_mode(SystimerHal *hal,uint alarm_id,int mode)
{
  if (mode != 0 && mode != 1) {
    return; /* No HAL/device dereference on this path. */
  }
  volatile uint *regs = hal->dev;
  memw();
  uint config = regs[alarm_id + 13];
  memw();
  if (mode == 0) {
    regs[alarm_id + 13] = config & ~0x40000000U;
  } else {
    regs[alarm_id + 13] = config | 0x40000000U; /* PERIOD_MODE */
  }
}

/* Native entry: 0x40385d2c. */
/*
 * Medius v3.4.7 — host application; 0x40385d2c.
 *
 * Copies the two uint64 conversion callback pointers into the 12-byte HAL context at offsets 4
 * and 8. Does not call the callbacks, validate pointers, change a clock rate, or serialize
 * concurrent access.
 *
 * Called by: vSystimerSetup, esp_timer_impl_early_init.
 *
 * Original function-byte SHA-256:
 * 1d6f9f180d933d4c35ba01ca54da8de538e7ff8c76f69622f983fcf109788dca.
 */

/* Copies the two uint64 conversion callback pointers into the 12-byte HAL context at offsets 4
   and 8. Does not call the callbacks, validate pointers, change a clock rate, or serialize
   concurrent access. Reference: ESP-IDF v5.4.4
   components/hal/systimer_hal.c and hal/esp32s3/include/hal/systimer_ll.h. */

/*
 * hal: Writable 12-byte HAL context receiving callback pointers.
 * ops: Readable 8-byte pair; both callback pointers are read before either destination store.
 * Returns: Nothing.
 * Requirements/effects: Copies pointers without invoking/validating them. No initialized dev
 *   pointer or MMIO is needed; caller serializes concurrent updates.
 */

void systimer_hal_set_tick_rate_ops(SystimerHal *hal,const SystimerTickOps *ops)
{
  const volatile SystimerTickOps *source = ops;
  volatile SystimerHal *destination = hal;
  SystimerConvert ticks_to_us = source->ticks_to_us;
  SystimerConvert us_to_ticks = source->us_to_ticks;
  destination->ticks_to_us = ticks_to_us;
  destination->us_to_ticks = us_to_ticks;
}

/* Native entry: 0x40385d3c. */
/*
 * Medius v3.4.7 — host application; 0x40385d3c.
 *
 * Converts the absolute microsecond target to ticks, disables the alarm, writes its low 32/high
 * 20 target bits, applies the target and re-enables it. S3 hardware supports alarm-miss
 * compensation; this compiled path has no software deadline-retry loop. Counter choice and alarm
 * mode are unchanged.
 *
 * Called by: esp_timer_impl_set_alarm_id.
 *
 * Indirect call: hal->us_to_ticks converts the supplied microseconds to hardware ticks.
 *
 * Original function-byte SHA-256:
 * 4f669eb70966b331cd8ebddb9f0e4037e61796d4af7a4db7389db82c8230db1a.
 */

/* Converts the absolute microsecond target to ticks, disables the alarm, writes its low 32/high
   20 target bits, applies the target and re-enables it. S3 hardware supports alarm-miss
   compensation; this compiled path has no software deadline-retry loop. Counter choice and alarm
   mode are unchanged. MMIO accesses retain their instruction order and MEMW barriers. Volatile
   locals prevent decompiler read-hoisting artifacts. Reference: ESP-IDF v5.4.4
   components/hal/systimer_hal.c and hal/esp32s3/include/hal/systimer_ll.h. */

/*
 * hal: Writable 12-byte SystimerHal context whose dev pointer addresses SYSTIMER registers.
 * alarm_id: Hardware comparator 0, 1 or 2; unchecked here.
 * target_us: Absolute unsigned 64-bit microsecond target converted through us_to_ticks.
 * Returns: Nothing.
 * Requirements/effects: Requires a converter. Writes/applies low32/high20 target bits and re-
 *   enables the alarm, without a software deadline retry or register lock.
 */

void systimer_hal_set_alarm_target(SystimerHal *hal,uint alarm_id,ulonglong target_us)
{
  ulonglong target = hal->us_to_ticks(target_us);
  volatile uint *regs = hal->dev;
  memw();
  uint config = regs[0];
  uint enable_bit = 1U << ((24U - alarm_id) & 31U);
  memw();
  regs[0] = config & ~enable_bit;
  memw();
  uint old_high = regs[2 * alarm_id + 7];
  memw();
  regs[2 * alarm_id + 7] = (old_high & 0xfff00000U) | ((uint)(target >> 32) & 0x000fffffU);
  memw();
  regs[2 * alarm_id + 8] = (uint)target;
  memw();
  regs[alarm_id + 20] = 1; /* COMPn_LOAD */
  memw();
  config = regs[0];
  memw();
  regs[0] = config | enable_bit;
}

/* Native entry: 0x40385da0. */
/*
 * Medius v3.4.7 — host application; 0x40385da0.
 *
 * Sets the alarm bit in INT_ENA at SYSTIMER+0x64 using a read-modify-write. Does not clear
 * pending status, register a CPU ISR, enable the alarm itself or mask concurrent register
 * writers.
 *
 * Called by: vSystimerSetup, FUN_420075d0.
 *
 * Original function-byte SHA-256:
 * 97dbe3523ebae612aed27f917fc403f4da9d2777a2627987325e006c136f6441.
 */

/* Sets the alarm bit in INT_ENA at SYSTIMER+0x64 using a read-modify-write. Does not clear
   pending status, register a CPU ISR, enable the alarm itself or mask concurrent register
   writers. MMIO accesses retain their instruction order and MEMW barriers. Volatile locals
   prevent decompiler read-hoisting artifacts. Reference: ESP-IDF v5.4.4
   components/hal/systimer_hal.c and hal/esp32s3/include/hal/systimer_ll.h. */

/*
 * hal: Writable 12-byte SystimerHal context whose dev pointer addresses SYSTIMER registers.
 * alarm_id: Hardware comparator 0, 1 or 2; unchecked here.
 * Returns: Nothing.
 * Requirements/effects: Updates INT_ENA only. Caller supplies valid ID and synchronization;
 *   pending status, comparator run state and CPU ISR registration are unchanged.
 */

void systimer_hal_enable_alarm_int(SystimerHal *hal,uint alarm_id)
{
  volatile uint *regs = hal->dev;
  memw();
  uint enabled = regs[25]; /* INT_ENA, byte offset 0x64 */
  memw();
  regs[25] = enabled | (1U << (alarm_id & 31U));
}

/* Native entry: 0x40385dc0. */
/*
 * Medius v3.4.7 — host application; 0x40385dc0.
 *
 * Sets CONF bit 30-counter_id to run that counter. Does not reset the counter value, set stall
 * permissions or enable a CPU interrupt. Valid counter IDs are 0 and 1; this helper does not
 * check them.
 *
 * Called by: vSystimerSetup, esp_timer_impl_early_init.
 *
 * Original function-byte SHA-256:
 * f0fda0df3473ca989a88551a7ec03c88a60f48ea78a3661257b079d76ed24621.
 */

/* Sets CONF bit 30-counter_id to run that counter. Does not reset the counter value, set stall
   permissions or enable a CPU interrupt. Valid counter IDs are 0 and 1; this helper does not
   check them. MMIO accesses retain their instruction order and MEMW barriers. Volatile locals
   prevent decompiler read-hoisting artifacts. Reference: ESP-IDF v5.4.4
   components/hal/systimer_hal.c and hal/esp32s3/include/hal/systimer_ll.h. */

/*
 * hal: Writable 12-byte SystimerHal context whose dev pointer addresses SYSTIMER registers.
 * counter_id: Hardware counter 0 or 1; unchecked here.
 * Returns: Nothing.
 * Requirements/effects: Sets the counter run bit without resetting its value or CPU stall
 *   permissions. Caller serializes register updates.
 */

void systimer_hal_enable_counter(SystimerHal *hal,uint counter_id)
{
  volatile uint *regs = hal->dev;
  memw();
  uint config = regs[0];
  memw();
  regs[0] = config | (1U << ((30U - counter_id) & 31U));
}

/* Native entry: 0x40385de4. */
/*
 * Medius v3.4.7 — host application; 0x40385de4.
 *
 * Writes the one-bit counter select in TARGETn_CONF bit 31 while preserving all other fields.
 * Does not reset either counter or change the selected alarm target, mode or enable bit.
 *
 * Called by: vSystimerSetup, esp_timer_impl_early_init.
 *
 * Original function-byte SHA-256:
 * 73715616f0383c93aef1bccb3f76a591f4fc1449cd3d9857ca18d8fb2fe009eb.
 */

/* Writes the one-bit counter select in TARGETn_CONF bit 31 while preserving all other fields.
   Does not reset either counter or change the selected alarm target, mode or enable bit. MMIO
   accesses retain their instruction order and MEMW barriers. Volatile locals prevent decompiler
   read-hoisting artifacts. Reference: ESP-IDF v5.4.4 components/hal/systimer_hal.c and
   hal/esp32s3/include/hal/systimer_ll.h. */

/*
 * hal: Writable 12-byte SystimerHal context whose dev pointer addresses SYSTIMER registers.
 * alarm_id: Hardware comparator 0, 1 or 2; unchecked here.
 * counter_id: Hardware counter 0 or 1; unchecked here.
 * Returns: Nothing.
 * Requirements/effects: Stores counter_id bit0 in TARGETn_CONF bit31 and preserves other fields.
 *   IDs are unchecked; caller excludes competing writers.
 */

void systimer_hal_connect_alarm_counter(SystimerHal *hal,uint alarm_id,uint counter_id)
{
  volatile uint *regs = hal->dev;
  memw();
  uint config = regs[alarm_id + 13];
  memw();
  regs[alarm_id + 13] = (config & 0x7fffffffU) | (counter_id << 31);
}

/* Native entry: 0x40385e08. */
/*
 * Medius v3.4.7 — host application; 0x40385e08.
 *
 * Sets or clears CONF bit 28-2*counter_id-cpu_id according to can_stall. This permits hardware to
 * stall a counter when that CPU stalls; it is not a general timer stop, task suspension or
 * software deadline guarantee. IDs are trusted and register updates are not locked.
 *
 * Called by: vSystimerSetup, esp_timer_impl_early_init.
 *
 * Original function-byte SHA-256:
 * f36c88ce72885df3c75383e7db4e0951f9669ede66395ee1ca5e2e4042fe1657.
 */

/* Sets or clears CONF bit 28-2*counter_id-cpu_id according to can_stall. This permits hardware to
   stall a counter when that CPU stalls; it is not a general timer stop, task suspension or
   software deadline guarantee. IDs are trusted and register updates are not locked. MMIO accesses
   retain their instruction order and MEMW barriers. Volatile locals prevent decompiler read-
   hoisting artifacts. Reference: ESP-IDF v5.4.4 components/hal/systimer_hal.c and
   hal/esp32s3/include/hal/systimer_ll.h. */

/*
 * hal: Writable 12-byte SystimerHal context whose dev pointer addresses SYSTIMER registers.
 * counter_id: Hardware counter 0 or 1; unchecked here.
 * cpu_id: CPU0 or CPU1 selector used to choose a stall-permission bit.
 * can_stall: Zero clears the permission; any nonzero byte sets it.
 * Returns: Nothing.
 * Requirements/effects: Updates CONF bit28-2*counter_id-cpu_id. Caller provides valid IDs and
 *   serialization; this permits hardware stall without immediately stopping a timer or task.
 */

void systimer_hal_counter_can_stall_by_cpu(SystimerHal *hal,uint counter_id,uint cpu_id,uchar can_stall)
{
  volatile uint *regs = hal->dev;
  memw();
  uint config = regs[0];
  uint bit = 1U << ((28U - 2U * counter_id - cpu_id) & 31U);
  memw();
  regs[0] = can_stall ? config | bit : config & ~bit;
}

/* Native entry: 0x40380be4. */
/* Original function-byte SHA-256:
 * 94f52d30c5f235b4135c3e40306d8d63999337e7d2f196dcc4b32d6ad83ed827. */
/* Convert unsigned64 hardware ticks to whole microseconds by shifting right4
 * (16 ticks/us). Fractional ticks are truncated. No context access or effects. */
unsigned long long systimer_ticks_to_us(unsigned long long ticks)
{
    return ticks >> 4;
}

/* Native entry: 0x40380bf4. */
/* Original function-byte SHA-256:
 * 6e399c2ef5b291d0752dde0d8fcb83850f8141d6860df9aaebe8fd0a60df63a1. */
/* Convert unsigned64 microseconds to ticks by shifting left4, modulo2^64.
 * No saturation, range check, context access or side effects. */
unsigned long long systimer_us_to_ticks(unsigned long long microseconds)
{
    return microseconds << 4;
}
