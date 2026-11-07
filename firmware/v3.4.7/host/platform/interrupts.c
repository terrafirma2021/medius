/* Medius v3.4.7 host — platform/interrupts.c.
 * Recovered C and native assembly, grouped for source navigation.
 * Original entry addresses, firmware-byte hashes and function comments follow.
 */

#include "../include/types.h"

/* Native entry: 0x403765b0. */
/*
 * Medius v3.4.7 — host application; 0x403765b0.
 *
 * Snapshots the shared-node head, acquires the interrupt allocator spinlock, and walks every
 * node. Calls a handler only when its disabled bit is clear and its optional volatile status
 * register intersects the mask. The lock remains held across callbacks. It neither acknowledges
 * peripheral flags nor schedules tasks itself.
 *
 * Calls: vPortExitCritical, xPortEnterCriticalTimeout.
 *
 * Indirect call: each enabled shared node supplies isr(argument).
 *
 * Original function-byte SHA-256:
 * b83175b56787ac6b543f2df00ccd9ee2129f7ab97816ee85f41f9600289a33f6.
 */

/* Reference: ESP-IDF v5.4.4 components/esp_hw_support/intr_alloc.c. */

/*
 * argument: Live shared vector descriptor passed through the void-pointer ISR ABI. Its head is
 *   snapshotted before taking the allocator lock; the status pointer is cached per node.
 * Returns: Nothing.
 * Requirements/effects: Walks all shared nodes under the allocator lock, including during
 *   callbacks. Skips disabled nodes and status filters that do not intersect; NULL status register
 *   is unfiltered. Does not clear peripheral status. Handlers must obey ISR restrictions and
 *   preserve node/list lifetime during traversal.
 */

void shared_intr_isr(void *argument)

{
  InterruptVector *vector = argument;
  SharedInterrupt *shared_node;

  shared_node = vector->shared_vec_info;
  xPortEnterCriticalTimeout(INTERRUPT_ALLOCATOR_LOCK,0xffffffff);
  for (; shared_node != (SharedInterrupt *)0x0; shared_node = shared_node->next) {
    if ((shared_node->disabled_source & 1) == 0) {
      volatile unsigned int *status_register = shared_node->statusreg;
      if (status_register == 0 || (memw(), (*status_register & shared_node->statusmask) != 0))
        shared_node->isr(shared_node->argument);
    }
  }
  vPortExitCritical(INTERRUPT_ALLOCATOR_LOCK);
  return;
}

/* Native entry: 0x403765ec. */
/*
 * Medius v3.4.7 — host application; 0x403765ec.
 *
 * Rejects NULL with 0x102, clears the shared node disabled bit when present, and enables its
 * source under the allocator lock. External sources reconnect through the interrupt matrix;
 * negative internal sources require the owning CPU and enable its CPU interrupt bit. Returns zero
 * or invalid-argument after unlocking.
 *
 * Calls: xt_ints_on, intr_matrix_set, vPortExitCritical, xPortEnterCriticalTimeout,
 * xPortInIsrContext.
 *
 * Called by: FUN_420075d0.
 *
 * Original function-byte SHA-256:
 * 4f02b655a2f6533e53af17bc1fd935aa95c9ce2e195919e8845c9f81ee7898cc.
 */

/* Reference: ESP-IDF v5.4.4 components/esp_hw_support/intr_alloc.c. The handle and its
   vector/shared nodes must be valid. Source enable/disable does not acknowledge peripheral
   interrupt status. */

/*
 * handle: Live interrupt handle; NULL is rejected.
 * Returns: 0 on success or0x102 for NULL/wrong CPU on an internal source.
 * Requirements/effects: Under the allocator lock clears a shared-node disabled bit, then
 *   reconnects external sources through the matrix or enables the owning CPU internal interrupt
 *   bit. Does not acknowledge peripheral status. Internal-source calls must run on the owner CPU;
 *   an error need not undo prior shared-node state changes.
 */

int esp_intr_enable(InterruptHandle *handle)

{
  uint processor_id;
  uint shared_source_word_or_owner_cpu;
  SharedInterrupt *shared_node;
  InterruptVector *vector;
  int source_or_status;
  uint vector_flags;

  if (handle == (InterruptHandle *)0x0) {
invalid_argument:
    source_or_status = 0x102;
  }
  else {
    xPortInIsrContext();
    xPortEnterCriticalTimeout(INTERRUPT_ALLOCATOR_LOCK,0xffffffff);
    shared_node = handle->shared_vector_desc;
    vector = handle->vector_desc;
    if (shared_node == (SharedInterrupt *)0x0) {
      source_or_status = (int)vector->source;
    }
    else {
      shared_source_word_or_owner_cpu = shared_node->disabled_source & 0xfffffffe;
      shared_node->disabled_source = shared_source_word_or_owner_cpu;
      source_or_status = (int)(shared_source_word_or_owner_cpu << 0xf) >> 0x10;
    }
    vector_flags = vector->flags_cpu_intno;
    shared_source_word_or_owner_cpu = vector_flags >> 0x10 & 1;
    if (source_or_status < 0) {
      processor_id = xtensa_read_prid();
      if ((processor_id >> 0xd & 1) != shared_source_word_or_owner_cpu) {
        xPortInIsrContext();
        vPortExitCritical(INTERRUPT_ALLOCATOR_LOCK);
        goto invalid_argument;
      }
      xt_ints_on(1U << (vector_flags >> 0x11 & 0x1f));
    }
    else {
      intr_matrix_set(shared_source_word_or_owner_cpu,source_or_status,vector_flags >> 0x11 & 0x1f);
    }
    xPortInIsrContext();
    vPortExitCritical(INTERRUPT_ALLOCATOR_LOCK);
    source_or_status = 0;
  }
  return source_or_status;
}

/* Native entry: 0x40376668. */
/*
 * Medius v3.4.7 — host application; 0x40376668.
 *
 * Rejects NULL, marks a shared node disabled, and scans same-source nodes so an external source
 * is disconnected only when no enabled sibling needs it. External sources route to disabled
 * input6; internal sources clear the CPU interrupt bit only on the owning CPU. Uses the recursive
 * allocator critical section; returns zero or 0x102.
 *
 * Calls: __assert_func, xt_ints_off, intr_matrix_set, vPortExitCritical,
 * xPortEnterCriticalTimeout, xPortInIsrContext.
 *
 * Called by: intr_free_for_current_cpu, esp_intr_alloc_intrstatus.
 *
 * Original function-byte SHA-256:
 * 03be268197bcd2b7d0e7c8eca030095771cef0fe71627c0af6e49fca986dd7d5.
 */

/* Reference: ESP-IDF v5.4.4 components/esp_hw_support/intr_alloc.c. The handle and its
   vector/shared nodes must be valid. Source enable/disable does not acknowledge peripheral
   interrupt status. */

/*
 * handle: Live interrupt handle; NULL is rejected.
 * Returns: 0 on success or0x102 for NULL/wrong CPU on an internal source.
 * Requirements/effects: Under the allocator lock marks a shared node disabled and scans same-
 *   source siblings. Disconnects an external source to matrix input6 only if no enabled sibling
 *   needs it. Internal sources clear their CPU bit on the owner. Does not free the handle or
 *   acknowledge peripheral flags.
 */

int esp_intr_disable(InterruptHandle *handle)

{
  SharedInterrupt *shared_node;
  uint source_word_or_processor_id;
  int source_or_status;
  InterruptVector *vector;

  if (handle == (InterruptHandle *)0x0) {
invalid_argument:
    source_or_status = 0x102;
  }
  else {
    xPortInIsrContext();
    xPortEnterCriticalTimeout(INTERRUPT_ALLOCATOR_LOCK,0xffffffff);
    shared_node = handle->shared_vector_desc;
    vector = handle->vector_desc;
    if (shared_node == (SharedInterrupt *)0x0) {
      source_or_status = (int)vector->source;
      if (-1 < source_or_status) goto disconnect_external_source;
disable_internal_source:
      source_word_or_processor_id = xtensa_read_prid();
      if ((vector->flags_cpu_intno >> 0x10 & 1) != (source_word_or_processor_id >> 0xd & 1)) {
        xPortInIsrContext();
        vPortExitCritical(INTERRUPT_ALLOCATOR_LOCK);
        goto invalid_argument;
      }
      xt_ints_off(1U << (vector->flags_cpu_intno >> 0x11 & 0x1f));
    }
    else {
      source_word_or_processor_id = shared_node->disabled_source | 1;
      shared_node->disabled_source = source_word_or_processor_id;
      shared_node = vector->shared_vec_info;
      source_or_status = (int)(source_word_or_processor_id << 0xf) >> 0x10;
      if (shared_node == (SharedInterrupt *)0x0) {
                    /* WARNING: Subroutine does not return */
        __assert_func((char *)0x0,0,(char *)0x0,(char *)0x0);
      }
      do {
        if ((source_or_status == (int)(shared_node->disabled_source << 0xf) >> 0x10) &&
           ((shared_node->disabled_source & 1) == 0)) {
          if (source_or_status < 0) goto disable_internal_source;
          goto unlock_success;
        }
        shared_node = shared_node->next;
      } while (shared_node != (SharedInterrupt *)0x0);
      if (source_or_status < 0) goto disable_internal_source;
disconnect_external_source:
      intr_matrix_set(vector->flags_cpu_intno >> 0x10 & 1,source_or_status,6);
    }
unlock_success:
    xPortInIsrContext();
    vPortExitCritical(INTERRUPT_ALLOCATOR_LOCK);
    source_or_status = 0;
  }
  return source_or_status;
}

/* Native entry: 0x40376720. */
/*
 * Medius v3.4.7 — host application; 0x40376720.
 *
 * Under the allocator lock, rejects nested disable with abort, marks this CPU cache-disabled
 * state, masks its registered non-IRAM interrupt bits, invokes RTC non-IRAM masking, and saves
 * only bits that were previously enabled. It preserves IRAM-designated CPU interrupts; that
 * designation is not a transitive audit of handler data/callees.
 *
 * Calls: rtc_isr_noniram_disable, xt_ints_off, abort, vPortExitCritical, xPortEnterCriticalTimeout,
 * xPortInIsrContext.
 *
 * Called by: spi_flash_op_block_func, spi_flash_disable_interrupts_caches_and_other_cpu, FUN_40380ca4.
 *
 * Original function-byte SHA-256:
 * 4feff97f24bea92b4d4a333638c880e074228204e7e8834d827a036937321be7.
 */

/* Reference: ESP-IDF v5.4.4 components/esp_hw_support/intr_alloc.c. */

/*
 * Returns: Nothing; nested disable aborts.
 * Requirements/effects: For this PRID-selected CPU, holds the allocator lock, marks non-IRAM
 *   interrupts disabled, snapshots INTENABLE, masks registered non-IRAM CPU bits, invokes RTC
 *   masking and saves only formerly enabled bits. Must be paired with enable on the same CPU. IRAM
 *   designation does not verify every handler callee or data address.
 */

void esp_intr_noniram_disable(void)

{
  uint previous_intenable;
  uint current_core;
  uint mask;

  xPortInIsrContext();
  xPortEnterCriticalTimeout(INTERRUPT_ALLOCATOR_LOCK,0xffffffff);
  current_core = xtensa_read_prid();
  current_core = current_core >> 0xd & 1;
  unsigned char already_disabled = INTERRUPT_ALLOCATOR_STATE->non_iram_disabled[current_core];
  mask = INTERRUPT_ALLOCATOR_STATE->non_iram_mask[current_core];
  if (already_disabled != 0) {
                    /* WARNING: Subroutine does not return */
    abort();
  }
  INTERRUPT_ALLOCATOR_STATE->non_iram_disabled[current_core] = '\x01';
  previous_intenable = xtensa_read_intenable();
  xt_ints_off(mask);
  rtc_isr_noniram_disable(current_core);
  INTERRUPT_ALLOCATOR_STATE->saved_non_iram_enabled[current_core] = mask & previous_intenable;
  xPortInIsrContext();
  vPortExitCritical(INTERRUPT_ALLOCATOR_LOCK);
  return;
}

/* Native entry: 0x40376774. */
/*
 * Medius v3.4.7 — host application; 0x40376774.
 *
 * Under the allocator lock, aborts without a matching disable, clears the per-CPU disabled flag,
 * restores the saved non-IRAM CPU interrupt bits and invokes RTC non-IRAM restoration. This is a
 * paired mask restoration, not an unconditional enable of all interrupts.
 *
 * Calls: rtc_isr_noniram_enable, xt_ints_on, abort, vPortExitCritical, xPortEnterCriticalTimeout,
 * xPortInIsrContext.
 *
 * Called by: spi_flash_op_block_func, spi_flash_enable_interrupts_caches_and_other_cpu, FUN_40380ce4.
 *
 * Original function-byte SHA-256:
 * 74bae91e85aad6e9e0eeda37d2797bad04455bf9e719992898d54cfb0c7b4bda.
 */

/* Reference: ESP-IDF v5.4.4 components/esp_hw_support/intr_alloc.c. */

/*
 * Returns: Nothing; missing matching disable aborts.
 * Requirements/effects: Under the allocator lock clears this CPU disabled flag, restores its saved
 *   non-IRAM interrupt mask and invokes RTC restoration. Does not enable arbitrary interrupts that
 *   were disabled before the paired mask operation.
 */

void esp_intr_noniram_enable(void)

{
  uint current_core;
  uint mask;

  xPortInIsrContext();
  xPortEnterCriticalTimeout(INTERRUPT_ALLOCATOR_LOCK,0xffffffff);
  current_core = xtensa_read_prid();
  current_core = current_core >> 0xd & 1;
  unsigned char already_disabled = INTERRUPT_ALLOCATOR_STATE->non_iram_disabled[current_core];
  mask = INTERRUPT_ALLOCATOR_STATE->saved_non_iram_enabled[current_core];
  if (already_disabled == 0) {
                    /* WARNING: Subroutine does not return */
    abort();
  }
  INTERRUPT_ALLOCATOR_STATE->non_iram_disabled[current_core] = '\0';
  xt_ints_on(mask);
  rtc_isr_noniram_enable(current_core);
  xPortInIsrContext();
  vPortExitCritical(INTERRUPT_ALLOCATOR_LOCK);
  return;
}

/* Native entry: 0x403767b8. */
/*
 * Medius v3.4.7 — host application; 0x403767b8.
 *
 * Enables the current CPU interrupt bit through xt_ints_on(1U << (number &31)). The API argument
 * is a CPU interrupt number, not an external peripheral matrix source; no range check is
 * performed.
 *
 * Calls: xt_ints_on.
 *
 * Called by: FUN_420027d8, FUN_4200294c, FUN_420032b4, FUN_42006244.
 *
 * Original function-byte SHA-256:
 * 184584daf88a21f8603a5a3748143e21e6190f2002fe74eb66df8da0ba436caf.
 */

/* Reference: ESP-IDF v5.4.4 components/esp_hw_support/intr_alloc.c. */

/*
 * interrupt_number: CPU interrupt number, not a peripheral matrix source; low5 bits are used.
 * Returns: Nothing; old INTENABLE returned by the lower helper is discarded.
 * Requirements/effects: Enables that bit on the current CPU. No number validation, matrix routing,
 *   descriptor update or peripheral acknowledgement.
 */

void esp_intr_enable_source(uint interrupt_number)

{
  xt_ints_on(1U << (interrupt_number & 0x1f));
  return;
}

/* Native entry: 0x403767c8. */
/*
 * Medius v3.4.7 — host application; 0x403767c8.
 *
 * Disables the current CPU interrupt bit through xt_ints_off(1U << (number &31)). Does not edit
 * the matrix, shared descriptors or peripheral flags, and does not validate the number.
 *
 * Calls: xt_ints_off.
 *
 * Called by: FUN_420027d8, FUN_4200294c, FUN_420032b4, FUN_42006244.
 *
 * Original function-byte SHA-256:
 * 5ce8c8eeed790cfdbbc004908a28badd87f4b419977b817ee3d9d0fad25a0a41.
 */

/* Reference: ESP-IDF v5.4.4 components/esp_hw_support/intr_alloc.c. */

/*
 * interrupt_number: CPU interrupt number; low5 bits are used without validation.
 * Returns: Nothing.
 * Requirements/effects: Disables that bit on the current CPU through xt_ints_off. Does not alter
 *   routing, descriptors or peripheral status.
 */

void esp_intr_disable_source(uint interrupt_number)

{
  xt_ints_off(1U << (interrupt_number & 0x1f));
  return;
}

/* Native entry: 0x403767fc. */
/*
 * Medius v3.4.7 — host application; 0x403767fc.
 *
 * Snapshots masked RTC status once, walks the 20-byte callback list under its spinlock, and
 * releases/reacquires that lock around each matching callback. Writes the original snapshot to
 * RTC INT_CLR after the walk, including unclaimed bits. This dispatcher does not reread status
 * between callbacks.
 *
 * Calls: vPortExitCritical, xPortEnterCriticalTimeout.
 *
 * Callback: each matching node supplies handler(handler_arg).
 *
 * Original function-byte SHA-256:
 * 0f4f016309cfde4ec51caaf45eb23866dd4da4b316a4687f6182beddb30b694f.
 */

/* Reference: ESP-IDF v5.4.4 components/esp_hw_support/rtc_module.c. */

/*
 * unused_argument: Unused interrupt-registration context; this dispatcher reads the global
 *   callback list.
 * Returns: Nothing; acknowledges the original status snapshot after dispatch.
 * Requirements/effects: Runs in interrupt context. The list and callbacks must remain valid while
 *   the lock is released around each callback; no timeout or status resampling is added.
 */

void rtc_isr(void *unused_argument)

{
  uint status;
  RtcIsrListHead node;

  memw();
  status = RTC_INT_ST;
  xPortEnterCriticalTimeout(&RTC_INTERRUPT_STATE->lock,0xffffffff);
  for (node = RTC_INTERRUPT_STATE->handlers; node != (RtcIsrListHead)0x0; node = node->next)
  {
    if ((status & node->mask) != 0) {
      vPortExitCritical(&RTC_INTERRUPT_STATE->lock);
      (*node->handler)(node->handler_arg);
      xPortEnterCriticalTimeout(&RTC_INTERRUPT_STATE->lock,0xffffffff);
    }
  }
  vPortExitCritical(&RTC_INTERRUPT_STATE->lock);
  memw();
  RTC_INT_CLR = status;
  return;
}

/* Native entry: 0x4037684c. */
/*
 * Medius v3.4.7 — host application; 0x4037684c.
 *
 * Acts only when cpu matches the CPU owning the RTC interrupt. Under the RTC peripheral atomic
 * guard, ORs the first INT_ENA read into the saved enable mask and writes a second INT_ENA read
 * AND the cache-safe mask. Repeated calls accumulate saved bits; this helper has no nesting check
 * or peripheral acknowledgement.
 *
 * Calls: periph_rcc_enter, periph_rcc_exit.
 *
 * Called by: esp_intr_noniram_disable.
 *
 * Original function-byte SHA-256:
 * 33b2926871bd4c7d233a7a1dc079cb00f6ee47dcb62b6f2983fbd74870cbaa43.
 */

/* Reference: ESP-IDF v5.4.4 components/esp_hw_support/rtc_module.c. */

/* Instruction-order recovery preserves the native register/memory accesses. */

/*
 * cpu: CPU being suspended; only the CPU owning rtc_isr_handle changes the RTC enable register.
 * Returns: Nothing; a non-owning CPU returns immediately.
 * Requirements/effects: ORs current enables into the saved mask, then applies the cache-safe mask
 *   under the peripheral guard. Repeated calls accumulate state without a nesting check.
 */

void rtc_isr_noniram_disable(uint cpu)
{
  uint initial_enables;
  uint current_enables;
  uint saved_enables;
  uint cache_safe_mask;

  if ((uint)RTC_INTERRUPT_STATE->owner_cpu != cpu) {
    return;
  }
  periph_rcc_enter();
  memw();
  initial_enables = RTC_INT_ENA;
  saved_enables = RTC_INTERRUPT_STATE->saved_enables;
  memw();
  current_enables = RTC_INT_ENA;
  cache_safe_mask = RTC_INTERRUPT_STATE->cache_safe_mask;
  RTC_INTERRUPT_STATE->saved_enables = saved_enables | initial_enables;
  memw();
  RTC_INT_ENA = current_enables & cache_safe_mask;
  periph_rcc_exit();
}

/* Native entry: 0x40376888. */
/*
 * Medius v3.4.7 — host application; 0x40376888.
 *
 * On the owning CPU only, enters the peripheral atomic guard, overwrites RTC INT_ENA with the
 * saved mask and then clears that saved mask. It restores the saved full enable state rather than
 * ORing current enables, and neither validates pairing nor acknowledges pending status.
 *
 * Calls: periph_rcc_enter, periph_rcc_exit.
 *
 * Called by: esp_intr_noniram_enable.
 *
 * Original function-byte SHA-256:
 * b1c93caa1061d4e92fff2afe31d299ffe3b898a29e81eb0b3ef39bd94825639a.
 */

/* Reference: ESP-IDF v5.4.4 components/esp_hw_support/rtc_module.c. */

/* Instruction-order recovery preserves the native register/memory accesses. */

/*
 * cpu: CPU being resumed; only the RTC interrupt owner restores its enable register.
 * Returns: Nothing; a non-owning CPU returns immediately.
 * Requirements/effects: Overwrites enables with the saved mask and clears that saved mask under
 *   the peripheral guard. The caller must pair suspension/resumption; current enables are not ORed
 *   into the restore.
 */

void rtc_isr_noniram_enable(uint cpu)
{
  uint saved_enables;

  if ((uint)RTC_INTERRUPT_STATE->owner_cpu != cpu) {
    return;
  }
  periph_rcc_enter();
  saved_enables = RTC_INTERRUPT_STATE->saved_enables;
  memw();
  RTC_INT_ENA = saved_enables;
  RTC_INTERRUPT_STATE->saved_enables = 0;
  periph_rcc_exit();
}

/* Native entry: 0x4037b930. */
/*
 * Medius v3.4.7 — host application; 0x4037b930.
 *
 * Prints the supplied diagnostic argument as an integer and the current CPU from PRID bit13, then
 * returns. The default ISR table supplies an interleaved index (IRQ*2+CPU), which is not divided
 * back into a plain IRQ number here. No interrupt masking, acknowledgement or panic is performed
 * in this body.
 *
 * Calls: ets_printf.
 *
 * Original function-byte SHA-256:
 * 6dd1ae6a84667961c07fd3c6950cf76d6d55da8dd26cf1bc56a0056351465a45.
 */

/* Reference: ESP-IDF v5.4.4 components/xtensa/xtensa_intr.c. */

/*
 * diagnostic_argument: 32-bit diagnostic value formatted as an integer; the default ISR table
 *   supplies IRQ*2+CPU, not a plain IRQ number.
 * Returns: Nothing; returns after ets_printf.
 * Requirements/effects: Reads PRID for CPU reporting. Does not dereference diagnostic_argument,
 *   acknowledge/mask the interrupt or panic; ROM printing is an external dependency.
 */

void xt_unhandled_interrupt(void *diagnostic_argument)
{
  uint prid = xtensa_read_prid();

  ets_printf("Unhandled interrupt %d on cpu %d!\n", (int)diagnostic_argument, (prid >> 13) & 1U);
  return;
}

/* Native entry: 0x4037d2b0. */
/*
 * Medius v3.4.7 — host application; 0x4037d2b0.
 *
 * Acknowledges a cross-core interrupt, consumes its saved reason mask, and dispatches enabled actions.
 *
 * Calls: esp_backtrace_print, _frxt_setup_switch, task_wdt_timeout_abort, vPortExitCritical, xPortEnterCriticalTimeout.
 *
 * Original function-byte SHA-256:
 * 17cad56c6c30a13ddba7092a071bd54dd3c0ed4b808bcefb095862d3e67e1f6a.
 */

/*
 * reason_word: Borrowed writable, aligned 32-bit reason-mask address passed by interrupt
 *   allocation. No NULL or association check is performed.
 * Returns: No value. A delegated timeout-abort helper may transfer control without returning.
 * Requirements/effects: Snapshots PRID bit 13 and clears that core's interrupt register at
 *   0x600c0030+4*core before entering the shared reason mux with timeout 0xffffffff cycles; the
 *   entry result is ignored. Reads the caller-supplied reason word once, clears it, then exits the
 *   same mux. Dispatches the saved value in order: bit0 requests the FreeRTOS switch, bit2 calls
 *   esp_backtrace_print(100) and ignores its status, bit4 calls task_wdt_timeout_abort(false).
 *   Frequency-switch bit1, GDB bit3 and other bits cause no C action in this build, but are
 *   consumed by the clear. Later changes to the reason word do not alter this dispatch. PRID
 *   selects the interrupt acknowledgement independently of the passed pointer. This body does not
 *   supply its own bounds, lifetime or concurrency guarantee.
 */

void esp_crosscore_isr(void *reason_word)
{
    PortMuxWords *reason_lock = CROSSCORE_REASON_LOCK;
    volatile CrosscoreReasonMask *reason = reason_word;
    uint core = (xtensa_read_prid() >> 13) & 1U;
    /* Acknowledge this CPU's interrupt before taking the shared reason mux. */
    memw();
    CPU_INTERRUPT_FROM_CPU[core] = 0;

    (void)xPortEnterCriticalTimeout(reason_lock, -1);
    memw();
    CrosscoreReasonMask pending = *reason;
    memw();
    *reason = 0;
    vPortExitCritical(reason_lock);

    /* Dispatch the saved snapshot; later writers cannot change this dispatch. */
    if ((pending & 1U) != 0)
        _frxt_setup_switch();
    if ((pending & 4U) != 0)
        (void)esp_backtrace_print(100);
    if ((pending & 16U) != 0)
        task_wdt_timeout_abort(false);
}

/* Native entry: 0x4037d30c. */
/*
 * Medius v3.4.7 — host application; 0x4037d30c.
 *
 * ORs a reason mask under the cross-core spinlock and triggers the selected CPU interrupt.
 *
 * Calls: __assert_func, vPortExitCritical, xPortEnterCriticalTimeout.
 *
 * Called by: esp_crosscore_int_send_yield, esp_crosscore_int_send_print_backtrace, esp_crosscore_int_send_twdt_abort.
 *
 * Original function-byte SHA-256:
 * 63842ccc2a590f5f8511fa715be452af6f8952787988d418c1f37ab5f8518e64.
 */

/* ORs a reason mask under the cross-core spinlock and triggers the selected CPU interrupt.
   SDK match: ESP-IDF v5.4.4 components/esp_system/crosscore_int.c.
   Recovered types/control flow retain the original function bytes and non-returning assertion paths. */

/*
 * core_id: Target CPU0 or CPU1. The compiled signed check rejects values greater than1 but does
 *   not separately reject negatives.
 * reason_mask: Reason bits ORed into the target CPU pending-reason word under the shared spinlock.
 * Returns: Nothing; triggers the selected CPU software-interrupt register after releasing the
 *   lock.
 * Requirements/effects: Caller supplies a valid nonnegative CPU ID and initialized shared
 *   reason/lock state. Does not wait for acknowledgement or clear existing reason bits.
 */

void esp_crosscore_int_send(int core_id,uint reason_mask)

{
  if (1 < core_id) {
                    /* WARNING: Subroutine does not return */
    __assert_func((char *)0x0,0,(char *)0x0,(char *)0x0);
  }
  xPortEnterCriticalTimeout(CROSSCORE_REASON_LOCK,0xffffffff);
  memw();
  unsigned int pending_reasons = CROSSCORE_REASONS[core_id];
  pending_reasons |= reason_mask;
  memw();
  CROSSCORE_REASONS[core_id] = pending_reasons;
  vPortExitCritical(CROSSCORE_REASON_LOCK);
  if (core_id == 0) {
    memw();
    CPU_INTERRUPT_FROM_CPU[0] = 1;
  }
  else {
    memw();
    CPU_INTERRUPT_FROM_CPU[1] = 1;
  }
  return;
}

/* Native entry: 0x4037d35c. */
/*
 * Medius v3.4.7 — host application; 0x4037d35c.
 *
 * Requests a scheduler yield using cross-core interrupt reason bit 0.
 *
 * Calls: esp_crosscore_int_send.
 *
 * Called by: prvSendAcquireGeneric, prvReceiveGeneric, vRingbufferReturnItem, FUN_403812e0, FUN_40381d8c, prvAddNewTaskToReadyList,
 * vTaskDelete, vTaskDelay, vTaskPrioritySet, xTaskResumeAll, ulTaskGenericNotifyTake, xTaskGenericNotify,
 * xQueueGenericSend, xQueuePeek, xQueueReceive, xQueueSemaphoreTake.
 *
 * Original function-byte SHA-256:
 * 7c521c839fafe9bfdc0e286d4a31a680a03e68cc0ed16261443e4e0fecabf709.
 */

/* Requests a scheduler yield using cross-core interrupt reason bit 0.
   SDK match: ESP-IDF v5.4.4 components/esp_system/crosscore_int.c.
   Recovered types/control flow retain the original function bytes and non-returning assertion paths. */

/*
 * core_id: Target CPU0 or CPU1 forwarded to the shared cross-core send helper.
 * Returns: Nothing.
 * Requirements/effects: Requests scheduler yield bit0 through the same locked reason-
 *   word/interrupt-trigger path. Caller supplies a valid CPU; completion is asynchronous.
 */

void esp_crosscore_int_send_yield(int core_id)

{
  esp_crosscore_int_send(core_id,1);
  return;
}

/* Native entry: 0x4037d36c. */
/*
 * Medius v3.4.7 — host application; 0x4037d36c.
 *
 * Requests a backtrace on the selected CPU using reason bit 2.
 *
 * Calls: esp_crosscore_int_send.
 *
 * Called by: FUN_42013260.
 *
 * Original function-byte SHA-256:
 * 914cbf3d231b8ac8b46c9c59bd0967e10c8e2c7683b660ca96e597c17f245018.
 */

/* Requests a backtrace on the selected CPU using reason bit 2.
   SDK match: ESP-IDF v5.4.4 components/esp_system/crosscore_int.c.
   Recovered types/control flow retain the original function bytes and non-returning assertion paths. */

/*
 * core_id: Target CPU0 or CPU1 forwarded to the shared cross-core send helper.
 * Returns: Nothing.
 * Requirements/effects: Requests backtrace bit2 through the same locked reason-word/interrupt-
 *   trigger path. Caller supplies a valid CPU; completion is asynchronous.
 */

void esp_crosscore_int_send_print_backtrace(int core_id)

{
  esp_crosscore_int_send(core_id,4);
  return;
}

/* Native entry: 0x4037d37c. */
/*
 * Medius v3.4.7 — host application; 0x4037d37c.
 *
 * Requests a task-watchdog abort on the selected CPU using reason bit 4.
 *
 * Calls: esp_crosscore_int_send.
 *
 * Called by: FUN_42013260.
 *
 * Original function-byte SHA-256:
 * c57c1dbfd8fa83c54b23616a08c26105df95b965672d47e415e00a72e13def90.
 */

/* Requests a task-watchdog abort on the selected CPU using reason bit 4.
   SDK match: ESP-IDF v5.4.4 components/esp_system/crosscore_int.c.
   Recovered types/control flow retain the original function bytes and non-returning assertion paths. */

/*
 * core_id: Target CPU0 or CPU1 forwarded to the shared cross-core send helper.
 * Returns: Nothing.
 * Requirements/effects: Requests task-watchdog abort bit4 through the same locked reason-
 *   word/interrupt-trigger path. Caller supplies a valid CPU; completion is asynchronous.
 */

void esp_crosscore_int_send_twdt_abort(int core_id)

{
  esp_crosscore_int_send(core_id,0x10);
  return;
}

/* Native entry: 0x4038d8c0. */
/*
 * Medius v3.4.7 — host application; 0x4038d8c0.
 *
 * Exchanges INTENABLE with zero, synchronizes, writes old_mask|mask, synchronizes and returns the
 * old 32-bit mask. Local CPU operation; no software virtual-priority mask is compiled into this
 * build.
 *
 * Called by: esp_intr_enable, esp_intr_noniram_enable, esp_intr_enable_source, esp_intr_alloc_intrstatus.
 *
 * Original function-byte SHA-256:
 * bcccc147325dd13e6344c73af64329090a11c380a898efef542cb4d7f1d6a8f4.
 */

/* Reference: ESP-IDF v5.4.4 components/xtensa/xtensa_intr_asm.S. */

/*
 * mask: 32-bit CPU interrupt bits to enable.
 * Returns: Previous INTENABLE mask, before the exchange.
 * Requirements/effects: Local CPU register operation. Atomically exchanges INTENABLE with0 using
 *   XSR, executes RSYNC, writes the mask formed by ORing mask into the saved value, then executes
 *   RSYNC again. No peripheral acknowledgement, matrix routing or software virtual-priority mask
 *   is involved.
 */

uint xt_ints_on(uint mask)
{
  uint previous_mask = 0;
  /* XSR exchanges zero with INTENABLE in a single native operation. */
  __asm__ volatile ("xsr.intenable %0\n\trsync" : "+a"(previous_mask) : : "memory");
  uint new_mask = previous_mask | mask;
  __asm__ volatile ("wsr.intenable %0\n\trsync" : : "a"(new_mask) : "memory");
  return previous_mask;
}

/* Native entry: 0x4038d8d8. */
/*
 * Medius v3.4.7 — host application; 0x4038d8d8.
 *
 * Exchanges INTENABLE with zero, synchronizes, writes old_mask&~mask, synchronizes and returns
 * the old 32-bit mask. Its previous inferred 64-bit return/extra source argument were decompiler
 * register artifacts.
 *
 * Called by: esp_intr_disable, esp_intr_noniram_disable, esp_intr_disable_source, esp_restart_noos.
 *
 * Original function-byte SHA-256:
 * b5287bc6ea6fbef10d28fc3f13b4db268833c4786075db9deeeb074f012e6298.
 */

/* Reference: ESP-IDF v5.4.4 components/xtensa/xtensa_intr_asm.S. */

/*
 * mask: 32-bit CPU interrupt bits to disable.
 * Returns: Previous INTENABLE mask, before the exchange.
 * Requirements/effects: Local CPU register operation. Atomically exchanges INTENABLE with0 using
 *   XSR, executes RSYNC, writes the mask formed by clearing mask bits from the saved value, then
 *   executes RSYNC again. No peripheral acknowledgement, matrix routing or software virtual-
 *   priority mask is involved.
 */

uint xt_ints_off(uint mask)
{
  uint previous_mask = 0;
  /* XSR exchanges zero with INTENABLE in a single native operation. */
  __asm__ volatile ("xsr.intenable %0\n\trsync" : "+a"(previous_mask) : : "memory");
  uint new_mask = previous_mask & ~mask;
  __asm__ volatile ("wsr.intenable %0\n\trsync" : : "a"(new_mask) : "memory");
  return previous_mask;
}

/* Native entry: 0x42004224. */
/*
 * Medius v3.4.7 — host application; 0x42004224.
 *
 * Returns 0/1 after checking fixed CPU interrupt properties, requested level/edge mode, runtime
 * reservation/nonshared use, shared IRAM compatibility, and any preinstalled low-level handler.
 * Asserts shared/nonshared flags are not both set. A forced interrupt may use a special-purpose
 * slot; reserved slots still fail.
 *
 * Calls: __assert_func, esp_cpu_intr_get_desc, xt_int_has_handler.
 *
 * Called by: esp_intr_alloc_intrstatus.
 *
 * Original function-byte SHA-256:
 * ed7c923f56bf8dd2cd8a0db82124256976173f6642be168f500c22ad4040f988.
 */

/* Reference: ESP-IDF v5.4.4 components/esp_hw_support/intr_alloc.c. */

/*
 * vector: Candidate descriptor or initialized temporary with an encoded interrupt number.
 * flags: Requested allocator flags, including accepted levels, edge/shared/IRAM policy.
 * cpu: CPU used for the fixed hardware descriptor lookup.
 * forced_number: -1 for general selection; a forced slot can admit a special-purpose interrupt.
 * Returns: 1 if usable,0 if rejected; mutually set shared/nonshared runtime flags assert.
 * Requirements/effects: Checks hardware reservation/level/trigger, descriptor use state, shared
 *   IRAM compatibility and preinstalled low-level handler. Does not reserve or modify the
 *   descriptor and takes no lock; caller serializes selection. The handler-table probe uses the
 *   current PRID CPU, so allocator callers pass their current CPU.
 */

int is_vect_desc_usable(InterruptVector *vector,int flags,int cpu,int forced_number)
{
  unsigned int interrupt_number = (vector->flags_cpu_intno >> 17) & 31U;
  CpuInterruptDescription hardware;
  esp_cpu_intr_get_desc(cpu,(int)interrupt_number,&hardware);
  if ((hardware.flags & 2U) != 0)
    return 0; /* Reserved slots are never candidates. */
  if (forced_number == -1 && (hardware.flags & 1U) != 0)
    return 0; /* Special-purpose slots require an explicitly forced number. */
  if (((unsigned int)flags & (1U << ((unsigned int)hardware.priority & 31U))) == 0)
    return 0;
  if ((flags & 0x200U) == 0) {
    if (hardware.type == 1)
      return 0;
  } else if (hardware.type == 0) {
    return 0;
  }

  unsigned int runtime_flags = vector->flags_low16;
  if ((runtime_flags & 1U) != 0)
    return 0;
  if ((runtime_flags & 0x0cU) == 0x0cU)
    __assert_func(0,0,0,0); /* Shared and nonshared ownership cannot coexist. */
  if ((runtime_flags & 8U) != 0)
    return 0;
  if ((runtime_flags & 4U) != 0) {
    if ((flags & 0x100U) == 0)
      return 0;
    return (((unsigned int)flags >> 10) & 1U) == ((runtime_flags >> 1) & 1U);
  }

  unsigned int current_cpu = (xtensa_read_prid() >> 13) & 1U;
  return (xt_int_has_handler((int)interrupt_number,(int)current_cpu) ^ 1) & 0xff;
}

/* Native entry: 0x420042c0. */
/*
 * Medius v3.4.7 — host application; 0x420042c0.
 *
 * Finds an existing descriptor for CPU/number or allocates and zeroes 16 internal byte-accessible
 * bytes, packs the one-bit CPU/five-bit number, and inserts it into the global list sorted by CPU
 * then interrupt number. Returns NULL on allocation failure. Caller holds allocator lock;
 * existing descriptors persist after free.
 *
 * Calls: heap_caps_malloc, memset.
 *
 * Called by: esp_intr_alloc_intrstatus.
 *
 * Original function-byte SHA-256:
 * 3fa5707db3b2c4802846d8b54be92930f717b327aa06c8dab5c32aa76e8314bb.
 */

/* Reference: ESP-IDF v5.4.4 components/esp_hw_support/intr_alloc.c. */

/*
 * interrupt_number: Validated CPU interrupt0..31; not range-checked here.
 * cpu: Validated CPU0 orCPU1; not independently range-checked here.
 * Returns: Existing descriptor, newly allocated descriptor, or NULL on allocation failure.
 * Requirements/effects: Caller holds the allocator lock. Allocates/zeroes16 internal byte-
 *   accessible bytes if absent, encodes one CPU bit and five interrupt bits, and inserts sorted by
 *   CPU then number. Descriptors remain allocated for reuse after handle cleanup.
 */

InterruptVector * get_desc_for_int(int interrupt_number,int cpu)

{
  InterruptVector *output;
  InterruptVectorHead cursor;
  uint cursor_flags;
  InterruptVectorHead next_cursor;
  InterruptVectorHead previous_cursor;

  for (cursor = INTERRUPT_ALLOCATOR_STATE->vector_head; cursor != (InterruptVectorHead)0x0; cursor = cursor->next) {
    if ((cpu == (cursor->flags_cpu_intno >> 0x10 & 1)) &&
       (interrupt_number == (cursor->flags_cpu_intno >> 0x11 & 0x1f))) {
      return cursor;
    }
  }
  output = heap_caps_malloc(0x10,0x804);
  if (output != (InterruptVector *)0x0) {
    memset(output,0,0x10);
    output->flags_cpu_intno =
         output->flags_cpu_intno & 0xffc0ffff | (interrupt_number & 0x1fU) << 0x11 |
         (cpu & 1U) << 0x10;
    cursor = INTERRUPT_ALLOCATOR_STATE->vector_head;
    if (cursor != (InterruptVectorHead)0x0) {
      next_cursor = cursor;
      previous_cursor = (InterruptVectorHead)0x0;
      while( true ) {
        cursor = next_cursor;
        cursor_flags = cursor->flags_cpu_intno;
        if (((cpu & 1U) < (cursor_flags >> 0x10 & 1)) ||
           ((((cursor_flags ^ output->flags_cpu_intno) & 0x10000) == 0 &&
            ((interrupt_number & 0x1fU) <= (cursor_flags >> 0x11 & 0x1f))))) break;
        next_cursor = cursor->next;
        if (next_cursor == (InterruptVector *)0x0) goto insert_after_cursor;
        previous_cursor = cursor;
      }
      if (previous_cursor != (InterruptVectorHead)0x0) {
        next_cursor = cursor;
        cursor = previous_cursor;
insert_after_cursor:
        cursor->next = output;
        output->next = next_cursor;
        return output;
      }
    }
    output->next = cursor;
    INTERRUPT_ALLOCATOR_STATE->vector_head = output;
  }
  return output;
}

/* Native entry: 0x42004368. */
/*
 * Medius v3.4.7 — host application; 0x42004368.
 *
 * Validates sharing, trigger mode, C-handler level, status mask and IRAM address; chooses a
 * compatible CPU interrupt on the current core, creates a descriptor/optional shared node,
 * installs the handler, routes the matrix, updates cache-disable masks and starts enabled unless
 * requested disabled. Returns 0, NO_MEM0x101, INVALID_ARG0x102 or NOT_FOUND0x105; optional result
 * receives an 8-byte handle. Status filtering is implemented by the shared ISR path.
 *
 * Calls: heap_caps_malloc, esp_intr_disable, esp_log_timestamp, esp_log_write, __assert_func, free,
 * xt_ints_on, is_vect_desc_usable, get_desc_for_int, esp_cpu_intr_get_desc, xt_set_interrupt_handler, intr_matrix_set, memset,
 * vPortExitCritical, xPortEnterCriticalTimeout, xthal_set_intclear.
 *
 * Called by: esp_intr_alloc.
 *
 * Original function-byte SHA-256:
 * 584bdf083855b2ec3c44e12da9c3bd0c75c1936df21f0765027f06d1c18a9f5a.
 */

/* Reference: ESP-IDF v5.4.4 components/esp_hw_support/intr_alloc.c. The seventh allocator
   parameter is the caller-owned handle-output slot on the stack. The no-free-input log also has a
   seventh stack argument: the effective flags. A NULL output slot frees only the temporary
   handle, leaving the interrupt registered. */

/*
 * source: Peripheral interrupt source or supported negative internal-source identifier.
 * flags: Requested level, sharing, edge, IRAM and initially-disabled flags.
 * status_reg: Optional32-bit MMIO address for a shared-handler status filter.
 * status_mask: Filter bits; must be nonzero when status_reg is nonzero.
 * handler: C callback when permitted by level/sharing flags; IRAM requests validate its code
 *   address.
 * argument: Opaque context for handler; must remain valid while installed.
 * result: Optional writable output for the allocated8-byte handle. NULL frees only this handle
 *   wrapper after successful installation.
 * Returns: 0 on success;0x101 for allocation failure,0x102 for rejected arguments/flag
 *   combinations,0x105 if no compatible CPU interrupt is available.
 * Requirements/effects: Task-context allocator on the current CPU, using its allocator spinlock.
 *   Selects/reuses a compatible vector, allocates a shared node when requested, installs
 *   callbacks, routes nonnegative sources and records non-IRAM mask policy. Internal sources map
 *   to fixed CPU slots; shared internal and shared edge requests are rejected. Normal allocation
 *   enables the CPU bit, then applies initial-disable if requested. Shared status filters are
 *   checked during dispatch, not acknowledged here. Failure does not publish result. IRAM address
 *   admission does not audit callback data or callees.
 */

int esp_intr_alloc_intrstatus
              (int source,int flags,uint status_reg,uint status_mask,InterruptHandler handler,
              void *argument,InterruptHandle **result)

{
  InterruptVector **next_vector_slot;
  int best_priority_or_usable;
  int candidate_usable;
  InterruptVector *selected_vector;
  uint shared_requested_or_current_cpu;
  InterruptVectorHead descriptor_cursor;
  uint interrupt_number;
  SharedInterrupt *shared_node;
  uint flags_or_shared_count_or_number;
  uint candidate_flags_or_source;
  uint forced_number_or_interrupt_mask;
  ushort vector_flags_low;
  uint vector_flags_or_noniram_mask;
  SharedInterrupt *previous_shared_head;
  InterruptVector temporary_vector;
  CpuInterruptDescription hardware_descriptor;
  uint source_or_search_flags;
  uint flags_or_selected_number;
  uint status_address_or_saved_flags;
  uint saved_status_mask;
  void *saved_argument;
  InterruptHandle *allocated_handle;
  uint handler_present_or_saved_flags;
  uint best_shared_count_or_flags;
  uint saved_source;
  uint saved_request_flags;
  InterruptHandler saved_handler;

  if ((~flags & 0x300U) == 0) {
    return 0x102;
  }
  forced_number_or_interrupt_mask = flags & 0xf0;
  if ((flags & 0xf0U) == 0) {
    shared_requested_or_current_cpu = flags & 0x100;
    if ((flags & 0x100U) != 0) {
      if (handler == (InterruptHandler)0x0) {
        forced_number_or_interrupt_mask = 1;
      }
      if (forced_number_or_interrupt_mask != 0) {
        return 0x102;
      }
      if (source < 0) {
        return 0x102;
      }
      shared_requested_or_current_cpu = 0x100;
    }
    if ((status_reg != 0) && (status_mask == 0)) {
      return 0x102;
    }
    handler_present_or_saved_flags = (uint)(uint)(handler != (InterruptHandler)0x0);
    forced_number_or_interrupt_mask = (uint)flags >> 10 & 1;
    if (((uint)handler_present_or_saved_flags & forced_number_or_interrupt_mask) != 0) {
      if ((((uint)handler - 0x40370000U > 0x6ffffU) && ((uint)handler - 0x600fe000U > 0x1fffU)) &&
         ((uint)handler - 0x40000000U > 0x5ffffU)) {
        return 0x102;
      }
      handler_present_or_saved_flags = (uint)((uint)handler_present_or_saved_flags & forced_number_or_interrupt_mask);
    }
    if (((uint)flags >> 1 & 0x7f) == 0) {
      if (shared_requested_or_current_cpu == 0) goto select_default_levels;
      flags = flags | 2;
    }
  }
  else {
    if (handler != (InterruptHandler)0x0) {
      return 0x102;
    }
    if ((flags & 0x100U) != 0) {
      return 0x102;
    }
    if (status_reg != 0 && status_mask == 0) {
      return 0x102;
    }
    handler_present_or_saved_flags = (uint)0x0;
    if (((uint)flags >> 1 & 0x7f) == 0) {
select_default_levels:
      flags = flags | 0xe;
    }
  }
  forced_number_or_interrupt_mask = 6;
  if ((((source != -1) && (forced_number_or_interrupt_mask = 0xf, source != -2)) &&
      ((forced_number_or_interrupt_mask = 0x10, source != -3 && ((forced_number_or_interrupt_mask = 7, source != -4 && (forced_number_or_interrupt_mask = 0x1d, source != -5)))
       ))) && (forced_number_or_interrupt_mask = 0xb, source != -6)) {
    forced_number_or_interrupt_mask = 0xffffffff;
  }
  source_or_search_flags = (uint)source;
  flags_or_selected_number = (uint)flags;
  status_address_or_saved_flags = (uint)status_reg;
  saved_status_mask = status_mask;
  saved_argument = argument;
  allocated_handle = heap_caps_malloc(8,0x804);
  if (allocated_handle == (InterruptHandle *)0x0) {
    return 0x101;
  }
  xPortEnterCriticalTimeout(INTERRUPT_ALLOCATOR_LOCK,0xffffffff);
  shared_requested_or_current_cpu = xtensa_read_prid();
  shared_requested_or_current_cpu = shared_requested_or_current_cpu >> 0xd & 1;
  memset(&temporary_vector,0,0x10);
  flags_or_shared_count_or_number = flags_or_selected_number;
  candidate_flags_or_source = (uint)((uint)flags_or_selected_number | 0xe);
  if (((uint)flags_or_selected_number & 0xfe) != 0) {
    candidate_flags_or_source = flags_or_selected_number;
  }
  InterruptVector *vector_list = INTERRUPT_ALLOCATOR_STATE->vector_head;
  if (vector_list == (InterruptVectorHead)0x0) {
    if (forced_number_or_interrupt_mask == 0xffffffff) goto search_all_interrupts;
prepare_forced_vector:
    temporary_vector.flags_cpu_intno = temporary_vector.flags_cpu_intno & 0xffc1ffff | (forced_number_or_interrupt_mask & 0x1f) << 0x11;
    selected_vector = &temporary_vector;
check_forced_vector:
    best_priority_or_usable = is_vect_desc_usable(selected_vector,(int)candidate_flags_or_source,shared_requested_or_current_cpu,forced_number_or_interrupt_mask);
    flags_or_shared_count_or_number = flags_or_selected_number;
    if (best_priority_or_usable == 0) {
no_usable_interrupt:
      flags_or_selected_number = flags_or_shared_count_or_number;
      vPortExitCritical(INTERRUPT_ALLOCATOR_LOCK);
      free(allocated_handle);
      forced_number_or_interrupt_mask = esp_log_timestamp();

















      esp_log_write(1,"intr_alloc",INTERRUPT_ALLOCATION_FAILURE_FORMAT,forced_number_or_interrupt_mask,"intr_alloc",
                    INTERRUPT_SOURCE_NAMES[(int)source_or_search_flags],(uint)flags_or_selected_number);
      return 0x105;
    }
    flags_or_selected_number = (uint)(selected_vector->flags_cpu_intno >> 0x11 & 0x1f);
  }
  else {
    descriptor_cursor = vector_list;
    do {
      if ((descriptor_cursor->flags_cpu_intno & 4) == 0) {
        if ((source_or_search_flags == (uint)(int)descriptor_cursor->source) &&
           (vector_flags_or_noniram_mask = descriptor_cursor->flags_cpu_intno, shared_requested_or_current_cpu == (vector_flags_or_noniram_mask >> 0x10 & 1))) {
reuse_source_vector:
          if (((forced_number_or_interrupt_mask != 0xffffffff) && (forced_number_or_interrupt_mask != (vector_flags_or_noniram_mask >> 0x11 & 0x1f))) ||
             (best_priority_or_usable = is_vect_desc_usable(descriptor_cursor,(int)candidate_flags_or_source,shared_requested_or_current_cpu,forced_number_or_interrupt_mask), flags_or_shared_count_or_number = flags_or_selected_number,
             best_priority_or_usable == 0)) goto no_usable_interrupt;
          flags_or_selected_number = (uint)(descriptor_cursor->flags_cpu_intno >> 0x11 & 0x1f);
          goto create_selected_descriptor;
        }
      }
      else {
        vector_flags_or_noniram_mask = descriptor_cursor->flags_cpu_intno;
        if (shared_requested_or_current_cpu == (vector_flags_or_noniram_mask >> 0x10 & 1)) {
          shared_node = descriptor_cursor->shared_vec_info;
          if (shared_node == (SharedInterrupt *)0x0) goto invalid_descriptor;
          do {
            if (source_or_search_flags == (uint)((int)(shared_node->disabled_source << 0xf) >> 0x10))
            goto reuse_source_vector;
            shared_node = shared_node->next;
          } while (shared_node != (SharedInterrupt *)0x0);
        }
      }
      descriptor_cursor = descriptor_cursor->next;
    } while (descriptor_cursor != (InterruptVector *)0x0);
    selected_vector = vector_list;
    if (forced_number_or_interrupt_mask != 0xffffffff) {
      do {
        if ((shared_requested_or_current_cpu == (selected_vector->flags_cpu_intno >> 0x10 & 1)) &&
           (forced_number_or_interrupt_mask == (selected_vector->flags_cpu_intno >> 0x11 & 0x1f))) goto check_forced_vector;
        next_vector_slot = &selected_vector->next;
        selected_vector = *next_vector_slot;
      } while (*next_vector_slot != (InterruptVector *)0x0);
      goto prepare_forced_vector;
    }
search_all_interrupts:
    best_shared_count_or_flags = (uint)0x7fffffff;
    flags_or_selected_number = (uint)0xffffffff;
    best_priority_or_usable = 9;
    interrupt_number = (uint)0x0;
    saved_source = (uint)source_or_search_flags;
    saved_request_flags = flags_or_shared_count_or_number;
    descriptor_cursor = vector_list;
    source_or_search_flags = candidate_flags_or_source;
    saved_handler = handler;
find_candidate_descriptor:
    for (; descriptor_cursor != (InterruptVectorHead)0x0; descriptor_cursor = descriptor_cursor->next) {
      if ((shared_requested_or_current_cpu == (descriptor_cursor->flags_cpu_intno >> 0x10 & 1)) &&
         ((uint)(descriptor_cursor->flags_cpu_intno >> 0x11 & 0x1f) == interrupt_number)) goto check_candidate;
    }
    temporary_vector.flags_cpu_intno =
         temporary_vector.flags_cpu_intno & 0xffc1ffff | ((uint)interrupt_number & 0x1f) << 0x11;
    descriptor_cursor = &temporary_vector;
check_candidate:
    esp_cpu_intr_get_desc(shared_requested_or_current_cpu,(int)interrupt_number,&hardware_descriptor);
    candidate_usable = is_vect_desc_usable(descriptor_cursor,(int)source_or_search_flags,shared_requested_or_current_cpu,-1);
    if (candidate_usable != 0) {
      if (((uint)candidate_flags_or_source & 0x100) == 0) {
choose_lower_priority:
        if (hardware_descriptor.priority < best_priority_or_usable) {
          best_priority_or_usable = hardware_descriptor.priority;
          flags_or_selected_number = interrupt_number;
        }
      }
      else if ((descriptor_cursor->flags_cpu_intno & 4) == 0) {
        if (flags_or_selected_number == (uint)0xffffffff) goto choose_lower_priority;
      }
      else {
        shared_node = descriptor_cursor->shared_vec_info;
        if (shared_node == (SharedInterrupt *)0x0) {
          flags_or_shared_count_or_number = (uint)0x0;
        }
        else {
          flags_or_shared_count_or_number = (uint)0x0;
          do {
            shared_node = shared_node->next;
            flags_or_shared_count_or_number = (uint)((int)flags_or_shared_count_or_number + 1);
          } while (shared_node != (SharedInterrupt *)0x0);
        }
        if (((int)flags_or_shared_count_or_number < (int)best_shared_count_or_flags) || (hardware_descriptor.priority < best_priority_or_usable)) {
          best_priority_or_usable = hardware_descriptor.priority;
          flags_or_selected_number = interrupt_number;
          best_shared_count_or_flags = flags_or_shared_count_or_number;
        }
      }
    }
    interrupt_number = (uint)((int)interrupt_number + 1);
    if (interrupt_number != 32U) {
      descriptor_cursor = INTERRUPT_ALLOCATOR_STATE->vector_head;
      goto find_candidate_descriptor;
    }
    handler = saved_handler;
    flags_or_shared_count_or_number = saved_request_flags;
    source_or_search_flags = (uint)saved_source;
    if (flags_or_selected_number == (uint)0xffffffff) goto no_usable_interrupt;
  }
create_selected_descriptor:
  best_shared_count_or_flags = flags_or_shared_count_or_number;
  selected_vector = get_desc_for_int((int)flags_or_selected_number,shared_requested_or_current_cpu);
  flags_or_shared_count_or_number = flags_or_selected_number;
  if (selected_vector == (InterruptVector *)0x0) {
allocation_failed:
    vPortExitCritical(INTERRUPT_ALLOCATOR_LOCK);
    free(allocated_handle);
    return 0x101;
  }
  if (((uint)best_shared_count_or_flags & 0x100) != 0) {
    handler_present_or_saved_flags = best_shared_count_or_flags;
    shared_node = heap_caps_malloc(0x18,0x804);
    if (shared_node == (SharedInterrupt *)0x0) goto allocation_failed;
    memset(shared_node,0,0x18);
    flags_or_shared_count_or_number = flags_or_selected_number;
    forced_number_or_interrupt_mask = selected_vector->flags_cpu_intno;
    previous_shared_head = selected_vector->shared_vec_info;
    shared_node->statusreg = (volatile uint *)status_address_or_saved_flags;
    shared_node->statusmask = saved_status_mask;
    shared_node->disabled_source = ((uint)source_or_search_flags & 0xffff) * 2 | shared_node->disabled_source & 0xfffe0000
    ;
    shared_node->isr = handler;
    shared_node->argument = saved_argument;
    shared_node->next = previous_shared_head;
    selected_vector->shared_vec_info = shared_node;
    selected_vector->flags_low16 = (ushort)forced_number_or_interrupt_mask | 4;
    if (31U < flags_or_selected_number) goto invalid_descriptor;
    xt_set_interrupt_handler((uint)flags_or_selected_number,shared_intr_isr,selected_vector);
    vector_flags_low = (ushort)selected_vector->flags_cpu_intno;
    forced_number_or_interrupt_mask = 1U << ((uint)flags_or_shared_count_or_number & 0x1f);
    flags_or_shared_count_or_number = handler_present_or_saved_flags;
    candidate_flags_or_source = source_or_search_flags;
    goto publish_cache_policy;
  }
  selected_vector->flags_low16 = 8;
  if (handler_present_or_saved_flags == (uint)0x0) {
    if (((uint)best_shared_count_or_flags & 0x200) == 0) {
      forced_number_or_interrupt_mask = 1U << ((uint)flags_or_selected_number & 0x1f);
      vector_flags_low = 8;
      flags_or_shared_count_or_number = best_shared_count_or_flags;
    }
    else {
      candidate_flags_or_source = best_shared_count_or_flags;
      if (31U < flags_or_selected_number) goto invalid_descriptor;
clear_pending_edge:
      forced_number_or_interrupt_mask = 1U << ((uint)flags_or_selected_number & 0x1f);
      status_address_or_saved_flags = candidate_flags_or_source;
      xthal_set_intclear(forced_number_or_interrupt_mask);
      vector_flags_low = (ushort)selected_vector->flags_cpu_intno;
      flags_or_shared_count_or_number = status_address_or_saved_flags;
    }
  }
  else {
    status_address_or_saved_flags = best_shared_count_or_flags;
    if (31U < flags_or_selected_number) {
invalid_descriptor:
                    /* WARNING: Subroutine does not return */
      __assert_func((char *)0x0,0,(char *)0x0,(char *)0x0);
    }
    xt_set_interrupt_handler((uint)flags_or_selected_number,handler,saved_argument);
    candidate_flags_or_source = status_address_or_saved_flags;
    if (((uint)status_address_or_saved_flags & 0x200) != 0) goto clear_pending_edge;
    vector_flags_low = (ushort)selected_vector->flags_cpu_intno;
    forced_number_or_interrupt_mask = 1U << ((uint)flags_or_shared_count_or_number & 0x1f);
    flags_or_shared_count_or_number = status_address_or_saved_flags;
  }
  selected_vector->source = (short)source_or_search_flags;
  candidate_flags_or_source = source_or_search_flags;
publish_cache_policy:
  vector_flags_or_noniram_mask = INTERRUPT_ALLOCATOR_STATE->non_iram_mask[shared_requested_or_current_cpu];
  if (((uint)flags_or_shared_count_or_number & 0x400) == 0) {
    vector_flags_low = vector_flags_low & 0xfffd;
    vector_flags_or_noniram_mask = forced_number_or_interrupt_mask | vector_flags_or_noniram_mask;
  }
  else {
    vector_flags_low = vector_flags_low | 2;
    vector_flags_or_noniram_mask = forced_number_or_interrupt_mask & vector_flags_or_noniram_mask ^ vector_flags_or_noniram_mask;
  }
  INTERRUPT_ALLOCATOR_STATE->non_iram_mask[shared_requested_or_current_cpu] = vector_flags_or_noniram_mask;
  selected_vector->flags_low16 = vector_flags_low;
  source_or_search_flags = flags_or_shared_count_or_number;
  if (-1 < (int)candidate_flags_or_source) {
    intr_matrix_set(shared_requested_or_current_cpu,(int)candidate_flags_or_source,(int)flags_or_selected_number);
  }
  shared_node = selected_vector->shared_vec_info;
  allocated_handle->vector_desc = selected_vector;
  allocated_handle->shared_vector_desc = shared_node;
  xt_ints_on(forced_number_or_interrupt_mask);
  if (((uint)source_or_search_flags & 0x800) != 0) {
    esp_intr_disable(allocated_handle);
  }
  vPortExitCritical(INTERRUPT_ALLOCATOR_LOCK);
  if (result == (InterruptHandle **)0x0) {
    free(allocated_handle);
  }
  else {
    *result = allocated_handle;
  }
  return 0;
}

/* Native entry: 0x4200485c. */
/*
 * Medius v3.4.7 — host application; 0x4200485c.
 *
 * Five-argument wrapper around esp_intr_alloc_intrstatus with status register/mask both zero.
 * Returns the allocator status. A NULL result suppresses handle ownership for the caller but the
 * handler allocation remains connected.
 *
 * Calls: esp_intr_alloc_intrstatus.
 *
 * Called by: vSystimerSetup, rtc_isr_register, FUN_420075d0, FUN_42012c50, FUN_420133c8,
 * link_init, usb_hc_low_level_init.
 *
 * Original function-byte SHA-256:
 * 6de9412066768ab89275324af40277a0522457fdda8c5ca1ccda071a7b4da70b.
 */

/* Reference: ESP-IDF v5.4.4 components/esp_hw_support/intr_alloc.c. */

/*
 * source: SDK source identifier, forwarded to the full allocator.
 * flags: Allocator level/sharing/IRAM/initial-disable flags.
 * handler: Optional C handler when permitted by the selected level/flags.
 * argument: Opaque handler context.
 * result: Optional writable handle output. NULL leaves the installed connection without a returned
 *   handle.
 * Returns: Status from esp_intr_alloc_intrstatus.
 * Requirements/effects: Forwards status-register and mask as0; no filtering or additional
 *   validation is supplied by this wrapper.
 */

int esp_intr_alloc(int source,int flags,InterruptHandler handler,void *argument,
                  InterruptHandle **result)

{
  int status;

  status = esp_intr_alloc_intrstatus(source,flags,0,0,handler,argument,result);
  return status;
}

/* Native entry: 0x42004874. */
/*
 * Medius v3.4.7 — host application; 0x42004874.
 *
 * Compiled void specialization of the SDK internal free routine. Disables the source under the
 * allocator lock, unlinks/frees its shared node, and resets the handler/flags/source when the
 * last user leaves. Clears the non-IRAM mask bit, retains the 16-byte vector descriptor for
 * reuse, unlocks, then frees the 8-byte handle. Callers synthesize the SDK always-success result;
 * no C return is recovered here.
 *
 * Calls: esp_intr_disable, __assert_func, free, xt_set_interrupt_handler, vPortExitCritical,
 * xPortEnterCriticalTimeout.
 *
 * Called by: intr_free_for_other_cpu, esp_intr_free.
 *
 * Original function-byte SHA-256:
 * 177476acbde5d53325f8e603ed310eb479cc3af386d71e460993b41eaac96c09.
 */

/* Reference: ESP-IDF v5.4.4 components/esp_hw_support/intr_alloc.c. The handle and its
   vector/shared nodes must be valid. Source enable/disable does not acknowledge peripheral
   interrupt status. */

/*
 * handle: Live handle being destroyed on its owner CPU; NULL/stale values are invalid.
 * Returns: Nothing; compiled specialization has no C status result.
 * Requirements/effects: Under the allocator lock disables the source and unlinks/frees a shared
 *   node. For the last user resets the low-level handler, clears flags and non-IRAM mask bit and
 *   marks source-99. Retains the vector descriptor. Unlocks then frees the8-byte handle. Does not
 *   wipe callback data or synchronize arbitrary concurrent users.
 */

void intr_free_for_current_cpu(InterruptHandle *handle)

{
  ushort vector_flags;
  SharedInterrupt *next_node;
  SharedInterrupt *previous_node;
  SharedInterrupt *buffer;
  uint interrupt_number_or_noniram_mask;
  InterruptVector *vector;

  xPortEnterCriticalTimeout(INTERRUPT_ALLOCATOR_LOCK,0xffffffff);
  esp_intr_disable(handle);
  vector = handle->vector_desc;
  vector_flags = (ushort)vector->flags_cpu_intno;
  if ((vector_flags & 4) == 0) {
check_nonshared_owner:
    if ((vector_flags & 8) == 0) goto unlock_and_free_handle;
  }
  else {
    if (vector->shared_vec_info == (SharedInterrupt *)0x0) {
                    /* WARNING: Subroutine does not return */
      __assert_func((char *)0x0,0,(char *)0x0,(char *)0x0);
    }
    previous_node = (SharedInterrupt *)0x0;
    buffer = vector->shared_vec_info;
    while (next_node = buffer->next, handle->shared_vector_desc != buffer) {
      if (next_node == (SharedInterrupt *)0x0) goto reload_remaining_vector_flags;
      previous_node = buffer;
      buffer = next_node;
    }
    if (previous_node == (SharedInterrupt *)0x0) {
      vector->shared_vec_info = next_node;
    }
    else {
      previous_node->next = next_node;
    }
    free(buffer);
    vector = handle->vector_desc;
    if (vector->shared_vec_info != (SharedInterrupt *)0x0) {
reload_remaining_vector_flags:
      vector_flags = (ushort)vector->flags_cpu_intno;
      goto check_nonshared_owner;
    }
  }
  interrupt_number_or_noniram_mask = vector->flags_cpu_intno >> 0x11 & 0x1f;
  xt_set_interrupt_handler(interrupt_number_or_noniram_mask,(InterruptHandler)0x0,(void *)interrupt_number_or_noniram_mask);
  vector = handle->vector_desc;
  vector->flags_low16 = (ushort)vector->flags_cpu_intno & 0xfff2;
  interrupt_number_or_noniram_mask = INTERRUPT_ALLOCATOR_STATE->non_iram_mask[vector->flags_cpu_intno >> 0x10 & 1];
  vector->source = -99;
  INTERRUPT_ALLOCATOR_STATE->non_iram_mask[vector->flags_cpu_intno >> 0x10 & 1] =
       ~(1U << (vector->flags_cpu_intno >> 0x11 & 0x1f)) & interrupt_number_or_noniram_mask;
unlock_and_free_handle:
  vPortExitCritical(INTERRUPT_ALLOCATOR_LOCK);
  free(handle);
  return;
}

/* Native entry: 0x42004934. */
/*
 * Medius v3.4.7 — host application; 0x42004934.
 *
 * IPC callback that invokes intr_free_for_current_cpu on the owning CPU. The argument is the
 * interrupt handle; the wrapper returns no value and adds no lock or allocation.
 *
 * Calls: intr_free_for_current_cpu.
 *
 * Original function-byte SHA-256:
 * e2a108084ad8477f25c0db3d5dca1547a9ebbc094f6f83014d3b52ca118789e1.
 */

/* Reference: ESP-IDF v5.4.4 components/esp_hw_support/intr_alloc.c. */

/*
 * argument: Live interrupt handle supplied as the IPC callback context.
 * Returns: Nothing.
 * Requirements/effects: Delegates to intr_free_for_current_cpu on the IPC target CPU. Does not add
 *   another lock or allocate memory.
 */

void intr_free_for_other_cpu(void *argument)

{
  intr_free_for_current_cpu(argument);
  return;
}

/* Native entry: 0x42004940. */
/*
 * Medius v3.4.7 — host application; 0x42004940.
 *
 * Rejects NULL. For unpinned tasks or another owning CPU, uses blocking IPC to free on the owner
 * and maps IPC failure to -1. Otherwise performs local cleanup and returns zero. Successful free
 * invalidates the handle; vector descriptors remain allocated for reuse.
 *
 * Calls: xTaskGetCoreID, esp_ipc_call_blocking, intr_free_for_current_cpu.
 *
 * Called by: FUN_4201eea8, FUN_42022824, FUN_4202289c.
 *
 * Original function-byte SHA-256:
 * a6397c891037e35acc027fbff0d06cd5fcd17404dfad0cf4541658e0606f1ab8.
 */

/* Reference: ESP-IDF v5.4.4 components/esp_hw_support/intr_alloc.c. */

/*
 * handle: Live interrupt handle to destroy; NULL is rejected.
 * Returns: 0 on success,0x102 for NULL, or-1 if owner-CPU blocking IPC fails.
 * Requirements/effects: Unpinned tasks always use owner-CPU IPC; pinned tasks on another CPU also
 *   use IPC. Same-owner pinned tasks free locally. On success the handle is invalid and vector
 *   descriptor storage persists. Task-context API; blocking IPC and handle lifetime must be valid.
 */

int esp_intr_free(InterruptHandle *handle)

{
  uint processor_id;
  int task_affinity_or_status;
  uint cpu_id;

  if (handle == (InterruptHandle *)0x0) {
    task_affinity_or_status = 0x102;
  }
  else {
    task_affinity_or_status = xTaskGetCoreID((RtosTask *)0x0);
    cpu_id = handle->vector_desc->flags_cpu_intno >> 0x10 & 1;
    if ((task_affinity_or_status == 0x7fffffff) || (processor_id = xtensa_read_prid(), cpu_id != (processor_id >> 0xd & 1))) {
      task_affinity_or_status = esp_ipc_call_blocking(cpu_id,intr_free_for_other_cpu,handle);
      task_affinity_or_status = -(uint)(task_affinity_or_status != 0);
    }
    else {
      intr_free_for_current_cpu(handle);
      task_affinity_or_status = 0;
    }
  }
  return task_affinity_or_status;
}

/* Native entry: 0x42004e48. */
/*
 * Medius v3.4.7 — host application; 0x42004e48.
 *
 * Lazily installs the IRAM RTC dispatcher on matrix source39, initially disabling all RTC enables
 * and clearing pending bits. Allocates a 20-byte internal callback node, records
 * mask/handler/argument/flags, updates the cache-safe mask using flags bit0, and prepends the
 * node under the list lock. Returns allocator failure, NO_MEM0x101 or zero. A node allocation
 * failure leaves an already installed dispatcher in place. No callback or mask validation is
 * supplied.
 *
 * Calls: heap_caps_malloc, esp_intr_get_cpu, esp_intr_alloc, vPortExitCritical, xPortEnterCriticalTimeout.
 *
 * Called by: esp_brownout_init.
 *
 * Original function-byte SHA-256:
 * e83a37499f3c8ff3919417b5350390b21a1323edd7b98583c6c7626875515dc7.
 */

/* Reference: ESP-IDF v5.4.4 components/esp_hw_support/rtc_module.c. */

/* Instruction-order recovery preserves the native register/memory accesses. */

/*
 * handler: Callback invoked as handler(handler_arg) when a captured RTC status bit intersects its
 *   mask.
 * handler_arg: Opaque callback context stored unchanged in the allocated node.
 * rtc_intr_mask: RTC status/enable bits assigned to this callback.
 * flags: Node flags; bit0 includes its mask in the cache-safe interrupt set, while a clear bit
 *   removes those bits.
 * Returns: 0 on success; the first interrupt-allocation error, or 0x101 when the 20-byte callback-
 *   node allocation fails.
 * Requirements/effects: Lazily installs the dispatcher and prepends a node under rtc_handler_lock.
 *   Caller supplies a valid callback and suitable mask; an already installed dispatcher remains
 *   after node-allocation failure.
 */

int rtc_isr_register(InterruptHandler handler, void *handler_arg,
                     uint rtc_intr_mask, uint flags)
{
  int status;
  RtcIsrHandler *node;
  uint old_cache_mask;
  uint new_cache_mask;

  xPortEnterCriticalTimeout(&RTC_INTERRUPT_STATE->lock, 0xffffffffU);
  if (RTC_ISR_HANDLE == (InterruptHandle *)0) {
    memw();
    RTC_INT_ENA = 0;
    memw();
    RTC_INT_CLR = 0xffffffffU;
    status = esp_intr_alloc(39, 0x400, rtc_isr, (void *)0, (InterruptHandle **)&RTC_ISR_HANDLE);
    if (status != 0) {
      vPortExitCritical(&RTC_INTERRUPT_STATE->lock);
      return status;
    }
    RTC_INTERRUPT_STATE->owner_cpu = esp_intr_get_cpu(RTC_ISR_HANDLE);
  }
  vPortExitCritical(&RTC_INTERRUPT_STATE->lock);

  node = heap_caps_malloc(20, 0x800);
  if (node == (RtcIsrHandler *)0) {
    return 0x101;
  }
  node->mask = rtc_intr_mask;
  node->flags = flags;
  node->handler = handler;
  node->handler_arg = handler_arg;
  xPortEnterCriticalTimeout(&RTC_INTERRUPT_STATE->lock, 0xffffffffU);
  old_cache_mask = RTC_INTERRUPT_STATE->cache_safe_mask;
  new_cache_mask = old_cache_mask & ~rtc_intr_mask;
  if ((flags & 1U) != 0) {
    new_cache_mask = old_cache_mask | rtc_intr_mask;
  }
  node->next = RTC_INTERRUPT_STATE->handlers;
  RTC_INTERRUPT_STATE->handlers = node;
  RTC_INTERRUPT_STATE->cache_safe_mask = new_cache_mask;
  vPortExitCritical(&RTC_INTERRUPT_STATE->lock);
  return 0;
}

/* Native entry: 0x42006d9c. */
/*
 * Medius v3.4.7 — host application; 0x42006d9c.
 *
 * Asserts CPU is 0/1 and output is non-NULL, then reads fixed S3 interrupt priority/type/flags
 * from the per-core table into a 12-byte descriptor. The interrupt number is trusted; this body
 * supplies no separate 0..31 bounds check. No interrupt is installed or enabled.
 *
 * Calls: __assert_func.
 *
 * Called by: is_vect_desc_usable, esp_intr_alloc_intrstatus.
 *
 * Original function-byte SHA-256:
 * 6ff00171eeb2243c3205d796cff8a8fe0492e110885a9c88b955f7fcfcf9ae1a.
 */

/* Reference: ESP-IDF v5.4.4 components/esp_hw_support/port/esp32s3/esp_cpu_intr.c. */

/*
 * cpu: CPU0 orCPU1; invalid values assert.
 * interrupt_number: Caller-validated table index0..31; no check is compiled here.
 * description: Required writable12-byte result record; NULL asserts.
 * Returns: Nothing.
 * Requirements/effects: Reads the fixed16-byte table row and selects the CPU flag word. Copies
 *   priority/type/flags only; does not install or enable an interrupt.
 */

void esp_cpu_intr_get_desc(int cpu,int interrupt_number,CpuInterruptDescription *description)

{
  const CpuInterruptTableEntry *table = CPU_INTERRUPT_DESCRIPTIONS;
  int hardware_flags;
  int hardware_type;

  if ((1 < (uint)cpu) || (description == (CpuInterruptDescription *)0x0)) {
                    /* WARNING: Subroutine does not return */
    __assert_func((char *)0x0,0,(char *)0x0,(char *)0x0);
  }
  hardware_type = table[interrupt_number].type;
  hardware_flags = table[interrupt_number].flags[cpu];
  description->priority = table[interrupt_number].priority;
  description->type = hardware_type;
  description->flags = hardware_flags;
  return;
}

/* Native entry: 0x42012c50. */
/*
 * Medius v3.4.7 — host application; 0x42012c50.
 *
 * Clears a per-core cross-core reason word and allocates its IRAM interrupt handler.
 *
 * Calls: abort, esp_intr_alloc, vPortExitCritical, xPortEnterCriticalTimeout.
 *
 * Called by: FUN_42023a40, esp_startup_start_app_other_cores.
 *
 * Original function-byte SHA-256:
 * b95cecc843073adba926f98f52ad43e8bb925e7d7facc114f3efb590a4e46882.
 */

/*
 * Returns: No value on successful allocation; a full-width nonzero allocator result calls abort.
 * Requirements/effects: Calls the shared reason portMUX entry with timeout 0xffffffff cycles,
 *   ignoring its status. Reads PRID inside that section, clears the selected 32-bit reason word,
 *   and exits the same mux. Reads PRID again after exit, then calls esp_intr_alloc with source
 *   79/80, IRAM flag 0x400, esp_crosscore_isr and the corresponding static reason-word address.
 *   The handle-output pointer is NULL. No earlier state is restored on failure: the clear and
 *   critical-exit side effects precede allocation. Call once on each active core; no extra
 *   lifetime, scheduling or contention guarantee is supplied.
 */

void esp_crosscore_int_init(void)
{
    PortMuxWords *reason_lock = CROSSCORE_REASON_LOCK;
    (void)xPortEnterCriticalTimeout(reason_lock, -1);
    uint cleared_core = (xtensa_read_prid() >> 13) & 1U;
    memw();
    CROSSCORE_REASONS[cleared_core] = 0;
    vPortExitCritical(reason_lock);

    /* The allocation uses a fresh core snapshot after the critical section. */
    uint allocation_core = (xtensa_read_prid() >> 13) & 1U;
    int status = esp_intr_alloc(79U + allocation_core, 0x400, /* IRAM handler */
        esp_crosscore_isr, (void *)&CROSSCORE_REASONS[allocation_core], 0);
    if (status != 0)
        abort();
}

/* Native entry: 0x4201e7c4. */
/*
 * Medius v3.4.7 — host application; 0x4201e7c4.
 *
 * Returns -1 for a NULL handle or NULL vector pointer; otherwise extracts the one-bit owner CPU
 * from the vector descriptor. It does not validate that a non-NULL handle is live, acquire a
 * lock, or change interrupt state.
 *
 * Called by: rtc_isr_register.
 *
 * Original function-byte SHA-256:
 * 9aa780d3c051c507265d7e7c060c3c12cff4ba24c29eb4351d555d48a25449c5.
 */

/* Reference: ESP-IDF v5.4.4 components/esp_hw_support/intr_alloc.c. */

/* Instruction-order recovery preserves the native register/memory accesses. */

/*
 * handle: Interrupt handle whose vector descriptor stores owner CPU in packed bit16; may be NULL.
 * Returns: -1 for NULL handle/vector; otherwise owner CPU 0 or 1.
 * Requirements/effects: Does not lock, validate lifetime or change interrupt state. A non-NULL
 *   handle and vector descriptor must remain live during the read.
 */

int esp_intr_get_cpu(InterruptHandle *handle)
{
  if (handle == (InterruptHandle *)0 || handle->vector_desc == (InterruptVector *)0) {
    return -1;
  }
  return (int)((handle->vector_desc->flags_cpu_intno >> 16) & 1U);
}

/* Native entry: 0x42033164. */
/*
 * Medius v3.4.7 — host application; 0x42033164.
 *
 * Compares the selected (interrupt_number*2+cpu) handler-table entry with xt_unhandled_interrupt.
 * Returns 0/1, without bounds checks, locking or changing the entry.
 *
 * Called by: is_vect_desc_usable.
 *
 * Original function-byte SHA-256:
 * 87f2794f6e45d35532d145f01d659a3db8cc3f247d1c9dd3adf780c6fadaeb1f.
 */

/* Reference: ESP-IDF v5.4.4 components/xtensa/xtensa_intr.c. */

/*
 * interrupt_number: Validated interrupt-table index0..31.
 * cpu: Validated CPU0 orCPU1.
 * Returns: 1 when the stored handler differs from xt_unhandled_interrupt, otherwise0.
 * Requirements/effects: No bounds checks, locks or lifetime protection. Compares only the handler
 *   pointer, without checking its argument or allocator descriptors.
 */

int xt_int_has_handler(int interrupt_number,int cpu)

{
  return (uint)(CPU_ISR_TABLE[interrupt_number][cpu].handler != xt_unhandled_interrupt);
}

/* Native entry: 0x42033180. */
/*
 * Medius v3.4.7 — host application; 0x42033180.
 *
 * Rejects numbers outside 0..31 and levels above3. Updates the current CPU table argument then
 * handler, returning the previous handler or NULL for the default. NULL handler installs
 * xt_unhandled_interrupt and uses the interleaved table index as its diagnostic argument.
 * Supplies no lock; allocator callers hold their critical section.
 *
 * Called by: intr_free_for_current_cpu, esp_intr_alloc_intrstatus.
 *
 * Original function-byte SHA-256:
 * 7ab8673d183d70bf7fa71dbbf15acad1a49a1875fd129ddfadd7250f5f4f7ac7.
 */

/* Reference: ESP-IDF v5.4.4 components/xtensa/xtensa_intr.c. */

/*
 * interrupt_number: CPU interrupt index; values outside0..31 are rejected.
 * handler: Replacement C handler or NULL to install the default unhandled entry.
 * argument: Opaque handler argument; NULL-handler installation replaces it with the interleaved
 *   table index.
 * Returns: Previous handler, or NULL when it was the default or the requested slot/level is
 *   rejected.
 * Requirements/effects: Accepts only fixed levels at most3. Reads current CPU from PRID, stores
 *   argument before handler, and takes no lock. Caller must provide suitable critical context and
 *   callback/context lifetime.
 */

InterruptHandler xt_set_interrupt_handler(uint interrupt_number,InterruptHandler handler,void *argument)

{
  InterruptHandler previous_handler;
  uint current_core;

  if ((interrupt_number < 0x20) && (CPU_INTERRUPT_LEVELS[interrupt_number] < 4)) {
    current_core = xtensa_read_prid();
    current_core = current_core >> 0xd & 1;
    if (handler == (InterruptHandler)0x0) {
      argument = (void *)(current_core + interrupt_number * 2);
    }
    previous_handler = CPU_ISR_TABLE[interrupt_number][current_core].handler;
    if (handler == (InterruptHandler)0x0) {
      handler = xt_unhandled_interrupt;
    }
    CPU_ISR_TABLE[interrupt_number][current_core].argument = argument;
    CPU_ISR_TABLE[interrupt_number][current_core].handler = handler;
    if (previous_handler != xt_unhandled_interrupt) {
      return previous_handler;
    }
  }
  return (InterruptHandler)0x0;
}

