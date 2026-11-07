/* Medius v3.4.7 device — platform/interrupts.c.
 * Recovered C and native assembly, grouped for source navigation.
 * Original entry addresses, firmware-byte hashes and function comments follow.
 */

#include "../include/types.h"

/* Native entry: 0x40376960. */
/*
 * Medius v3.4.7 — device application; 0x40376960.
 *
 * Snapshots the shared-node head, acquires the interrupt allocator spinlock, and walks every
 * node. Calls a handler only when its disabled bit is clear and its optional volatile status
 * register intersects the mask. The lock remains held across callbacks. It neither acknowledges
 * peripheral flags nor schedules tasks itself.
 *
 * Calls: vPortExitCritical, xPortEnterCriticalTimeout.
 *
 * Indirect call: the shared node's typed ISR callback.
 *
 * Original function-byte SHA-256:
 * 6d3de66d3a52c8ef617c27e2cfc19d6fb5ee76fed28af2a461d4626e38d1a8d3.
 */

/* Reference: ESP-IDF v5.4.4 components/esp_hw_support/intr_alloc.c. */

/*
 * argument: Live shared vector descriptor passed through the ISR callback ABI. Its list head is
 *   snapshotted before taking the allocator lock; its optional status pointer is cached per node.
 * Returns: Nothing.
 * Requirements/effects: Walks all shared nodes under the allocator lock, including during
 *   callbacks. Skips disabled nodes and status filters that do not intersect; NULL status register
 *   is unfiltered. Does not clear peripheral status. Handlers must obey ISR restrictions and
 *   preserve node/list lifetime during traversal.
 */

void shared_intr_isr(void *argument)
{
    const volatile InterruptVector *vector = argument;
    volatile SharedInterrupt *node = vector->shared_vec_info;
    xPortEnterCriticalTimeout(INTERRUPT_ALLOCATOR_LOCK,0xffffffffU);
    while (node != NULL) {
        unsigned int state = node->disabled_source;
        if ((state & 1U) == 0) {
            volatile unsigned int *status_register = node->statusreg;
            bool pending = true;
            if (status_register != NULL) {
                memw();
                unsigned int status = *status_register;
                unsigned int mask = node->statusmask;
                pending = (status & mask) != 0;
            }
            if (pending) {
                InterruptHandler handler = node->isr;
                void *handler_argument = node->argument;
                handler(handler_argument);
            }
        }
        node = node->next;
    }
    vPortExitCritical(INTERRUPT_ALLOCATOR_LOCK);
}

/* Native entry: 0x4037699c. */
/*
 * Medius v3.4.7 — device application; 0x4037699c.
 *
 * Rejects NULL with 0x102, clears the shared node disabled bit when present, and enables its
 * source under the allocator lock. External sources reconnect through the interrupt matrix;
 * negative internal sources require the owning CPU and enable its CPU interrupt bit. Returns zero
 * or invalid-argument after unlocking.
 *
 * Calls: xPortInIsrContext, xt_ints_on, intr_matrix_set, vPortExitCritical,
 * xPortEnterCriticalTimeout.
 *
 * Called by: FUN_42007b9c, gptimer_enable.
 *
 * Original function-byte SHA-256:
 * 65086e38cab7e5957c7b7cd4184107e5c56f53980fb5f10c0bce52148d0cc854.
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
    if (handle == NULL)
        return 0x102;

    xPortInIsrContext();
    xPortEnterCriticalTimeout(INTERRUPT_ALLOCATOR_LOCK,0xffffffffU);
    const volatile InterruptHandle *handle_view = handle;
    volatile SharedInterrupt *shared = handle_view->shared_vector_desc;
    const volatile InterruptVector *vector = handle_view->vector_desc;
    int source;
    if (shared != NULL) {
        unsigned int state = shared->disabled_source & ~1U;
        shared->disabled_source = state;
        source = (int)(state << 15) >> 16;
    } else {
        source = vector->source;
    }

    unsigned int vector_word = vector->flags_cpu_intno;
    unsigned int owner_cpu = (vector_word >> 16) & 1U;
    unsigned int interrupt_number = (vector_word >> 17) & 31U;
    if (source < 0) {
        unsigned int current_cpu = (xtensa_read_prid() >> 13) & 1U;
        if (current_cpu != owner_cpu) {
            xPortInIsrContext();
            vPortExitCritical(INTERRUPT_ALLOCATOR_LOCK);
            return 0x102;
        }
        xt_ints_on(1U << interrupt_number);
    } else {
        intr_matrix_set(owner_cpu,source,interrupt_number);
    }
    xPortInIsrContext();
    vPortExitCritical(INTERRUPT_ALLOCATOR_LOCK);
    return 0;
}

/* Native entry: 0x40376a18. */
/*
 * Medius v3.4.7 — device application; 0x40376a18.
 *
 * Rejects NULL, marks a shared node disabled, and scans same-source nodes so an external source
 * is disconnected only when no enabled sibling needs it. External sources route to disabled
 * input6; internal sources clear the CPU interrupt bit only on the owning CPU. Uses the recursive
 * allocator critical section; returns zero or 0x102.
 *
 * Calls: xPortInIsrContext, __assert_func, xt_ints_off, intr_matrix_set, vPortExitCritical,
 * xPortEnterCriticalTimeout.
 *
 * Called by: intr_free_for_current_cpu, esp_intr_alloc_intrstatus.
 *
 * Original function-byte SHA-256:
 * d589dd13d628ca1171a15bc72ab1dd3b5be2e0f5a054fbc64944f550ae11c848.
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
    if (handle == NULL)
        return 0x102;

    xPortInIsrContext();
    xPortEnterCriticalTimeout(INTERRUPT_ALLOCATOR_LOCK,0xffffffffU);
    const volatile InterruptHandle *handle_view = handle;
    volatile SharedInterrupt *shared = handle_view->shared_vector_desc;
    const volatile InterruptVector *vector = handle_view->vector_desc;
    bool enabled_sibling = false;
    int source;
    if (shared != NULL) {
        unsigned int state = shared->disabled_source | 1U;
        shared->disabled_source = state;
        volatile SharedInterrupt *node = vector->shared_vec_info;
        source = (int)(state << 15) >> 16;
        if (node == NULL)
            __assert_func(NULL,0,NULL,NULL);
        do {
            unsigned int sibling_state = node->disabled_source;
            int sibling_source = (int)(sibling_state << 15) >> 16;
            if (sibling_source == source && (sibling_state & 1U) == 0) {
                enabled_sibling = true;
                break;
            }
            node = node->next;
        } while (node != NULL);
    } else {
        source = vector->source;
    }

    if (source < 0) {
        unsigned int current_cpu = (xtensa_read_prid() >> 13) & 1U;
        unsigned int vector_word = vector->flags_cpu_intno;
        if (((vector_word >> 16) & 1U) != current_cpu) {
            xPortInIsrContext();
            vPortExitCritical(INTERRUPT_ALLOCATOR_LOCK);
            return 0x102;
        }
        xt_ints_off(1U << ((vector_word >> 17) & 31U));
    } else if (!enabled_sibling) {
        unsigned int vector_word = vector->flags_cpu_intno;
        intr_matrix_set((vector_word >> 16) & 1U,source,6);
    }
    xPortInIsrContext();
    vPortExitCritical(INTERRUPT_ALLOCATOR_LOCK);
    return 0;
}

/* Native entry: 0x40376ad0. */
/*
 * Medius v3.4.7 — device application; 0x40376ad0.
 *
 * Under the allocator lock, rejects nested disable with abort, marks this CPU cache-disabled
 * state, masks its registered non-IRAM interrupt bits, invokes RTC non-IRAM masking, and saves
 * only bits that were previously enabled. It preserves IRAM-designated CPU interrupts; that
 * designation is not a transitive audit of handler data/callees.
 *
 * Calls: rtc_isr_noniram_disable, xPortInIsrContext, xt_ints_off, abort, vPortExitCritical,
 * xPortEnterCriticalTimeout.
 *
 * Called by: spi_flash_op_block_func, spi_flash_disable_interrupts_caches_and_other_cpu, FUN_40385750.
 *
 * Original function-byte SHA-256:
 * 2ebad60d0c0e2ffd9dbfea443ef04c2d9910d53b0a15b3bbc666ff9197c76745.
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

/* Native entry: 0x40376b24. */
/*
 * Medius v3.4.7 — device application; 0x40376b24.
 *
 * Under the allocator lock, aborts without a matching disable, clears the per-CPU disabled flag,
 * restores the saved non-IRAM CPU interrupt bits and invokes RTC non-IRAM restoration. This is a
 * paired mask restoration, not an unconditional enable of all interrupts.
 *
 * Calls: rtc_isr_noniram_enable, xPortInIsrContext, xt_ints_on, abort, vPortExitCritical,
 * xPortEnterCriticalTimeout.
 *
 * Called by: spi_flash_op_block_func, spi_flash_enable_interrupts_caches_and_other_cpu, FUN_40385790.
 *
 * Original function-byte SHA-256:
 * 7603946013aa9cd96577051c24ccec6d8009f2bbab1c4e1652ac72cfdc6ff8ef.
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

/* Native entry: 0x40376b68. */
/*
 * Medius v3.4.7 — device application; 0x40376b68.
 *
 * Enables the current CPU interrupt bit through xt_ints_on(1U << (number &31)). The API argument
 * is a CPU interrupt number, not an external peripheral matrix source; no range check is
 * performed.
 *
 * Calls: xt_ints_on.
 *
 * Called by: FUN_42002e98, FUN_4200300c, FUN_42003580, FUN_42006678.
 *
 * Original function-byte SHA-256:
 * a8fe3583b3cec5776b340ef7528d40dd2b36967fa0164325988a7f41391a8c18.
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

/* Native entry: 0x40376b78. */
/*
 * Medius v3.4.7 — device application; 0x40376b78.
 *
 * Disables the current CPU interrupt bit through xt_ints_off(1U << (number &31)). Does not edit
 * the matrix, shared descriptors or peripheral flags, and does not validate the number.
 *
 * Calls: xt_ints_off.
 *
 * Called by: FUN_42002e98, FUN_4200300c, FUN_42003580, FUN_42006678.
 *
 * Original function-byte SHA-256:
 * e16f2e66b7157bb30fb9a8e94b5a8ebbddea118d3484cfc48d84ad7e96c30251.
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

/* Native entry: 0x40376bac. */
/*
 * Medius v3.4.7 — device application; 0x40376bac.
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
 * a48e88dc5210e1d4a2b5d697019235b8f1f3fb1cfbe8f18620db4576238c6c05.
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
    (void)unused_argument;
    memw();
    unsigned int status = RTC_INT_ST;
    xPortEnterCriticalTimeout(&RTC_INTERRUPT_STATE->lock,0xffffffffU);
    volatile RtcIsrHandler *node = RTC_INTERRUPT_STATE->handlers;
    while (node != NULL) {
        unsigned int mask = node->mask;
        if ((status & mask) != 0) {
            vPortExitCritical(&RTC_INTERRUPT_STATE->lock);
            void *handler_argument = node->handler_arg;
            InterruptHandler handler = node->handler;
            handler(handler_argument);
            xPortEnterCriticalTimeout(&RTC_INTERRUPT_STATE->lock,0xffffffffU);
        }
        node = node->next;
    }
    vPortExitCritical(&RTC_INTERRUPT_STATE->lock);
    memw();
    RTC_INT_CLR = status;
}

/* Native entry: 0x40376bfc. */
/*
 * Medius v3.4.7 — device application; 0x40376bfc.
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
 * 898840124fa544d4acc9f2c2e75a541808d09cd73c58d5a2954f2b4c6b58928e.
 */

/* Reference: ESP-IDF v5.4.4 components/esp_hw_support/rtc_module.c. */

/* Instruction-order recovery preserves the native register/memory accesses. */

/*
 * cpu: CPU being suspended; only the CPU owning RTC_ISR_HANDLE changes the RTC enable register.
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

/* Native entry: 0x40376c38. */
/*
 * Medius v3.4.7 — device application; 0x40376c38.
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
 * 18c7ef37ce6f1971c046b0735b70704b9f459d284b3e4958c2f6d574bf982c56.
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

/* Native entry: 0x4037d1c8. */
/*
 * Medius v3.4.7 — device application; 0x4037d1c8.
 *
 * Prints the supplied diagnostic argument as an integer and the current CPU from PRID bit13, then
 * returns. The default ISR table supplies an interleaved index (IRQ*2+CPU), which is not divided
 * back into a plain IRQ number here. No interrupt masking, acknowledgement or panic is performed
 * in this body.
 *
 * Calls: ets_printf.
 *
 * Original function-byte SHA-256:
 * 93a03002e49fa8b874507cab9c6e9897189efa6a4dcbdcbaf83ee6393854e9dd.
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

/* Native entry: 0x4037eb48. */
/*
 * Medius v3.4.7 — device application; 0x4037eb48.
 *
 * Acknowledges a cross-core interrupt, consumes its saved reason mask, and dispatches enabled actions.
 *
 * Calls: esp_backtrace_print, _frxt_setup_switch, task_wdt_timeout_abort, vPortExitCritical, xPortEnterCriticalTimeout.
 *
 * Original function-byte SHA-256:
 * e0b4a99ab4b89e30171f384e516d6f5828ce60e7ef2ae23c537b2f302173608d.
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

/* Native entry: 0x4037eba4. */
/*
 * Medius v3.4.7 — device application; 0x4037eba4.
 *
 * ORs a reason mask under the cross-core spinlock and triggers the selected CPU interrupt.
 *
 * Calls: __assert_func, vPortExitCritical, xPortEnterCriticalTimeout.
 *
 * Called by: esp_crosscore_int_send_yield, esp_crosscore_int_send_print_backtrace, esp_crosscore_int_send_twdt_abort.
 *
 * Original function-byte SHA-256:
 * a8c046f8c51723b82cf6b916c559875740afac5be6f63aaa19e26cc0c71ff8ec.
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
 *   MEMW precedes the pending-word read, then another MEMW precedes its OR-result write.
 */

void esp_crosscore_int_send(int core_id,uint reason_mask)

{
  if (1 < core_id) {
                    /* WARNING: Subroutine does not return */
    __assert_func((char *)0x0,0,(char *)0x0,(char *)0x0);
  }
  xPortEnterCriticalTimeout(CROSSCORE_REASON_LOCK,0xffffffff);
  /* Native ADDX4 wraps the signed CPU word; the assertion has no lower bound. */
  volatile CrosscoreReasonMask *reason = (volatile CrosscoreReasonMask *)(
      (uintptr_t)CROSSCORE_REASONS + (unsigned int)core_id * sizeof(CrosscoreReasonMask));
  memw();
  unsigned int pending_reasons = *reason;
  pending_reasons |= reason_mask;
  memw();
  *reason = pending_reasons;
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

/* Native entry: 0x4037ebf4. */
/*
 * Medius v3.4.7 — device application; 0x4037ebf4.
 *
 * Requests a scheduler yield using cross-core interrupt reason bit 0.
 *
 * Calls: esp_crosscore_int_send.
 *
 * Called by: FUN_4038608c, FUN_40386ae4, prvAddNewTaskToReadyList, vTaskDelete, vTaskDelay, vTaskPrioritySet,
 * xTaskResumeAll, ulTaskGenericNotifyTake, xTaskGenericNotifyWait, xTaskGenericNotify, xQueueGenericSend, xQueuePeek,
 * xQueueReceive, xQueueSemaphoreTake.
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

/* Native entry: 0x4037ec04. */
/*
 * Medius v3.4.7 — device application; 0x4037ec04.
 *
 * Requests a backtrace on the selected CPU using reason bit 2.
 *
 * Calls: esp_crosscore_int_send.
 *
 * Called by: FUN_42010f10.
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

/* Native entry: 0x4037ec14. */
/*
 * Medius v3.4.7 — device application; 0x4037ec14.
 *
 * Requests a task-watchdog abort on the selected CPU using reason bit 4.
 *
 * Calls: esp_crosscore_int_send.
 *
 * Called by: FUN_42010f10.
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

/* Native entry: 0x4039a46c. */
/*
 * Medius v3.4.7 — device application; 0x4039a46c.
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

/* Native entry: 0x4039a484. */
/*
 * Medius v3.4.7 — device application; 0x4039a484.
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

/* Native entry: 0x4200461c. */
/* Original function-byte SHA-256:
 * db81cd1d81012f1e19121d84ca77797ff4f2336fa8b50dd614c1509b702875b9. */
/* Test a candidate vector without reserving or changing it.
 * Read its IRQ, query the fixed CPU descriptor, reject reserved slots and reject
 * special slots unless forced_number differs from -1. Apply the requested level
 * and trigger policy; type 2 is neither level nor edge. Read runtime flags as a
 * halfword. A vector marked both shared and nonshared asserts; reserved or
 * nonshared vectors fail. Shared candidates require matching IRAM policy.
 * An unused vector probes the handler table using a fresh PRID CPU, separately
 * from the cpu argument used for hardware properties. Return 0/1. No local lock
 * or pointer validation; caller supplies a live descriptor and serialization.
 */
int is_vect_desc_usable(InterruptVector *vector,int flags,int cpu,int forced_number)
{
    const volatile InterruptVector *view = vector;
    unsigned int interrupt_number = (view->flags_cpu_intno >> 17) & 31U;
    CpuInterruptDescription hardware;
    esp_cpu_intr_get_desc(cpu,(int)interrupt_number,&hardware);
    const volatile CpuInterruptDescription *fixed = &hardware;
    unsigned int hardware_flags = fixed->flags;
    if ((hardware_flags & 2U) != 0)
        return 0;
    if (forced_number == -1 && (hardware_flags & 1U) != 0)
        return 0;
    int priority = fixed->priority;
    if (((unsigned int)flags & (1U << ((unsigned int)priority & 31U))) == 0)
        return 0;
    int trigger_type = fixed->type;
    if ((flags & 0x200U) != 0 ? trigger_type == 0 : trigger_type == 1)
        return 0;

    unsigned int runtime_flags = (unsigned int)(short)view->flags_low16;
    if ((runtime_flags & 1U) != 0)
        return 0;
    if ((runtime_flags & 0xcU) == 0xcU)
        __assert_func(NULL,0,NULL,NULL);
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

/* Native entry: 0x420046b8. */
/* Original function-byte SHA-256:
 * 386ac01100c10600c62a12570fe06e382eec56fde7323278639f37c27e6c9e24. */
/* Find or create a persistent vector descriptor under the caller's lock.
 * First search for the full supplied CPU/IRQ values. On a miss, allocate and
 * clear 16 internal byte-accessible bytes, then pack only one CPU bit and five
 * IRQ bits. Insert before the first equal-or-greater CPU/IRQ entry, preserving
 * native list publication order. Out-of-range arguments are not rejected and
 * can create truncated duplicate keys. Return the descriptor or NULL on failure.
 * Descriptors persist after interrupt-handle cleanup; this routine takes no lock.
 */
InterruptVector *get_desc_for_int(int interrupt_number,int cpu)
{
    InterruptVector *cursor = INTERRUPT_ALLOCATOR_STATE->vector_head;
    while (cursor != NULL) {
        const volatile InterruptVector *view = cursor;
        unsigned int word = view->flags_cpu_intno;
        if (((word >> 16) & 1U) == (unsigned int)cpu &&
            ((word >> 17) & 31U) == (unsigned int)interrupt_number)
            return cursor;
        cursor = view->next;
    }
    InterruptVector *output = heap_caps_malloc(16,0x804);
    if (output == NULL)
        return NULL;
    memset(output,0,16);
    volatile InterruptVector *initial = output;
    unsigned int word = initial->flags_cpu_intno;
    unsigned int number_bits = (unsigned int)interrupt_number & 31U;
    unsigned int cpu_bit = (unsigned int)cpu & 1U;
    initial->flags_cpu_intno = (word & 0xffc0ffffU) | (number_bits << 17) | (cpu_bit << 16);

    cursor = INTERRUPT_ALLOCATOR_STATE->vector_head;
    InterruptVector *previous = NULL;
    while (cursor != NULL) {
        const volatile InterruptVector *view = cursor;
        unsigned int cursor_word = view->flags_cpu_intno;
        if (cpu_bit < ((cursor_word >> 16) & 1U))
            break;
        unsigned int output_word = initial->flags_cpu_intno;
        if (((cursor_word ^ output_word) & 0x10000U) == 0 &&
            number_bits <= ((cursor_word >> 17) & 31U))
            break;
        previous = cursor;
        cursor = view->next;
    }
    if (previous == NULL) {
        initial->next = cursor;
        INTERRUPT_ALLOCATOR_STATE->vector_head = output;
    } else {
        ((volatile InterruptVector *)previous)->next = output;
        initial->next = cursor;
    }
    return output;
}

/* Native entry: 0x42004760. */
/* Original function-byte SHA-256:
 * 07944ce01c040d34caa4b91db952bd12f5c11343b57fa48ad337ee42fa8a60f5. */
/* Allocate and connect an interrupt on the current CPU.
 * Validate shared/edge/high-level combinations, callback requirements, status
 * mask and requested IRAM code ranges. A nonshared status filter is not used
 * for dispatch. Default shared requests to level 1, others to levels 1..3.
 * Sources -1..-6 force IRQs 6,15,16,7,29,11; other values use general selection.
 * Existing source ownership is considered first and an incompatible match
 * fails immediately. Otherwise inspect the forced slot or all 32 IRQs. Shared
 * selection can replace a candidate for either fewer handlers OR lower priority;
 * after any choice, later unused slots do not compete. Ties retain earlier IRQs.
 * Allocate an 8-byte handle, retain/create a 16-byte vector and optionally prepend
 * a 24-byte shared node. Install callbacks, clear a pending nonshared edge when
 * requested, update cache policy, route nonnegative sources and enable the CPU
 * bit before applying initial-disable. Calls and node/mask stores retain native
 * order under the recursive allocator lock. IRAM code admission does not inspect
 * callback data or callees. No callback ownership or peripheral acknowledgement.
 * Return 0, 0x101 for allocation failure, 0x102 for rejected arguments or 0x105
 * when no vector qualifies. The 0x105 path unlocks/frees before logging and uses
 * the raw source as an unchecked name-table index, including negative values.
 * Failures do not publish result. A failed shared-node allocation retains its
 * vector descriptor. NULL result frees only the handle after installation.
 */
int esp_intr_alloc_intrstatus(int source,int flags,uint status_reg,uint status_mask,
    InterruptHandler handler,void *argument,InterruptHandle **result)
{
    if ((flags & 0x300U) == 0x300U)
        return 0x102;
    bool has_handler = handler != NULL;
    bool shared_request = (flags & 0x100U) != 0;
    if ((flags & 0xf0U) != 0 && (has_handler || shared_request))
        return 0x102;
    if (shared_request && (!has_handler || source < 0))
        return 0x102;
    if (status_reg != 0 && status_mask == 0)
        return 0x102;
    if (has_handler && (flags & 0x400U) != 0) {
        unsigned int address = (unsigned int)(uintptr_t)handler;
        if (address - 0x40370000U > 0x6ffffU &&
            address - 0x600fe000U > 0x1fffU &&
            address - 0x40000000U > 0x5ffffU)
            return 0x102;
    }
    if (((unsigned int)flags & 0xfeU) == 0)
        flags |= shared_request ? 2U : 0xeU;

    int forced_number;
    switch (source) {
    case -1: forced_number = 6; break;
    case -2: forced_number = 15; break;
    case -3: forced_number = 16; break;
    case -4: forced_number = 7; break;
    case -5: forced_number = 29; break;
    case -6: forced_number = 11; break;
    default: forced_number = -1; break;
    }
    InterruptHandle *handle = heap_caps_malloc(8,0x804);
    if (handle == NULL)
        return 0x101;
    xPortEnterCriticalTimeout(INTERRUPT_ALLOCATOR_LOCK,-1);
    unsigned int cpu = (xtensa_read_prid() >> 13) & 1U;
    InterruptVector empty_vector;
    memset(&empty_vector,0,16);
    volatile InterruptVector *empty = &empty_vector;
    unsigned int search_flags = (unsigned int)flags;
    if ((search_flags & 0xfeU) == 0)
        search_flags |= 0xeU;
    InterruptVector *list_head = INTERRUPT_ALLOCATOR_STATE->vector_head;
    InterruptVector *candidate = list_head;
    unsigned int candidate_word;
    unsigned int selected_number = 0xffffffffU;

    /* Reusing this source takes precedence over every alternative vector. */
    while (candidate != NULL) {
        volatile InterruptVector *view = candidate;
        unsigned int runtime_flags = view->flags_low16;
        if ((runtime_flags & 4U) == 0) {
            int registered_source = view->source;
            if (registered_source == source) {
                candidate_word = view->flags_cpu_intno;
                if (((candidate_word >> 16) & 1U) == cpu)
                    goto reuse_source;
            }
        } else {
            candidate_word = view->flags_cpu_intno;
            if (((candidate_word >> 16) & 1U) == cpu) {
                volatile SharedInterrupt *node = view->shared_vec_info;
                if (node == NULL)
                    __assert_func(NULL,0,NULL,NULL);
                do {
                    unsigned int state = node->disabled_source;
                    if (((int)(state << 15) >> 16) == source)
                        goto reuse_source;
                    node = node->next;
                } while (node != NULL);
            }
        }
        candidate = view->next;
    }

    if (forced_number != -1) {
        candidate = list_head;
        while (candidate != NULL) {
            volatile InterruptVector *view = candidate;
            unsigned int word = view->flags_cpu_intno;
            if (((word >> 16) & 1U) == cpu &&
                ((word >> 17) & 31U) == (unsigned int)forced_number)
                break;
            candidate = view->next;
        }
        if (candidate == NULL) {
            unsigned int word = empty->flags_cpu_intno;
            empty->flags_cpu_intno = (word & 0xffc1ffffU) |
                (((unsigned int)forced_number & 31U) << 17);
            candidate = &empty_vector;
        }
        if (!is_vect_desc_usable(candidate,(int)search_flags,(int)cpu,forced_number))
            goto no_usable_interrupt;
        selected_number = (((volatile InterruptVector *)candidate)->flags_cpu_intno >> 17) & 31U;
        goto allocate_descriptor;
    }

    int best_priority = 9;
    int best_shared_count = 0x7fffffff;
    for (unsigned int number = 0; number != 32; ++number) {
        candidate = number == 0 ? list_head : INTERRUPT_ALLOCATOR_STATE->vector_head;
        while (candidate != NULL) {
            volatile InterruptVector *view = candidate;
            unsigned int word = view->flags_cpu_intno;
            if (((word >> 16) & 1U) == cpu && ((word >> 17) & 31U) == number)
                break;
            candidate = view->next;
        }
        if (candidate == NULL) {
            unsigned int word = empty->flags_cpu_intno;
            empty->flags_cpu_intno = (word & 0xffc1ffffU) | (number << 17);
            candidate = &empty_vector;
        }
        CpuInterruptDescription hardware;
        esp_cpu_intr_get_desc((int)cpu,(int)number,&hardware);
        if (!is_vect_desc_usable(candidate,(int)search_flags,(int)cpu,-1))
            continue;

        if (shared_request) {
            unsigned int runtime_flags = ((volatile InterruptVector *)candidate)->flags_low16;
            if ((runtime_flags & 4U) != 0) {
                volatile SharedInterrupt *node = ((volatile InterruptVector *)candidate)->shared_vec_info;
                unsigned int count = 0;
                while (node != NULL) {
                    node = node->next;
                    ++count;
                }
                int priority = ((volatile CpuInterruptDescription *)&hardware)->priority;
                if ((int)count < best_shared_count || priority < best_priority) {
                    best_shared_count = (int)count;
                    best_priority = priority;
                    selected_number = number;
                }
                continue;
            }
            /* After choosing any candidate, later unused slots do not compete. */
            if (selected_number != 0xffffffffU)
                continue;
        }
        int priority = ((volatile CpuInterruptDescription *)&hardware)->priority;
        if (priority < best_priority) {
            best_priority = priority;
            selected_number = number;
        }
    }
    if (selected_number == 0xffffffffU)
        goto no_usable_interrupt;
    goto allocate_descriptor;

reuse_source:
    if (forced_number != -1 &&
        ((candidate_word >> 17) & 31U) != (unsigned int)forced_number)
        goto no_usable_interrupt;
    if (!is_vect_desc_usable(candidate,(int)search_flags,(int)cpu,forced_number))
        goto no_usable_interrupt;
    selected_number = (((volatile InterruptVector *)candidate)->flags_cpu_intno >> 17) & 31U;

allocate_descriptor:;
    InterruptVector *vector = get_desc_for_int((int)selected_number,(int)cpu);
    if (vector == NULL)
        goto allocation_failed;
    volatile InterruptVector *view = vector;
    unsigned int interrupt_mask;
    unsigned int vector_flags;
    if (shared_request) {
        SharedInterrupt *node = heap_caps_malloc(24,0x804);
        if (node == NULL)
            goto allocation_failed;
        memset(node,0,24);
        volatile SharedInterrupt *initial = node;
        unsigned int old_state = initial->disabled_source;
        unsigned int previous_flags = view->flags_low16;
        SharedInterrupt *previous_head = view->shared_vec_info;
        initial->statusreg = (volatile unsigned int *)(uintptr_t)status_reg;
        initial->statusmask = status_mask;
        initial->disabled_source = (old_state & 0xfffe0000U) |
            (((unsigned int)source & 0xffffU) << 1);
        initial->isr = handler;
        initial->argument = argument;
        initial->next = previous_head;
        view->shared_vec_info = node;
        view->flags_low16 = (unsigned short)(previous_flags | 4U);
        if (selected_number > 31)
            __assert_func(NULL,0,NULL,NULL);
        xt_set_interrupt_handler(selected_number,shared_intr_isr,vector);
        vector_flags = view->flags_low16;
        interrupt_mask = 1U << (selected_number & 31U);
    } else {
        view->flags_low16 = 8;
        if (has_handler) {
            if (selected_number > 31)
                __assert_func(NULL,0,NULL,NULL);
            xt_set_interrupt_handler(selected_number,handler,argument);
        }
        interrupt_mask = 1U << (selected_number & 31U);
        if ((flags & 0x200U) != 0) {
            if (selected_number > 31)
                __assert_func(NULL,0,NULL,NULL);
            xthal_set_intclear(interrupt_mask);
            vector_flags = view->flags_low16;
        } else {
            vector_flags = has_handler ? view->flags_low16 : 8U;
        }
        view->source = (short)source;
    }
    unsigned int non_iram_mask = INTERRUPT_ALLOCATOR_STATE->non_iram_mask[cpu];
    if ((flags & 0x400U) != 0) {
        vector_flags |= 2U;
        non_iram_mask &= ~interrupt_mask;
    } else {
        vector_flags &= ~2U;
        non_iram_mask |= interrupt_mask;
    }
    INTERRUPT_ALLOCATOR_STATE->non_iram_mask[cpu] = non_iram_mask;
    view->flags_low16 = (unsigned short)vector_flags;
    if (source >= 0)
        intr_matrix_set((int)cpu,source,(int)selected_number);
    SharedInterrupt *handle_shared = view->shared_vec_info;
    volatile InterruptHandle *initial_handle = handle;
    initial_handle->vector_desc = vector;
    initial_handle->shared_vector_desc = handle_shared;
    xt_ints_on(interrupt_mask);
    if ((flags & 0x800U) != 0)
        esp_intr_disable(handle);
    vPortExitCritical(INTERRUPT_ALLOCATOR_LOCK);
    if (result == NULL)
        free(handle);
    else
        *(InterruptHandle *volatile *)result = handle;
    return 0;

allocation_failed:
    vPortExitCritical(INTERRUPT_ALLOCATOR_LOCK);
    free(handle);
    return 0x101;

no_usable_interrupt:
    vPortExitCritical(INTERRUPT_ALLOCATOR_LOCK);
    free(handle);
    unsigned int timestamp = esp_log_timestamp();
    const char *const volatile *name_slot = (const char *const volatile *)(
        (uintptr_t)INTERRUPT_SOURCE_NAMES + (unsigned int)source * sizeof(const char *));
    const char *source_name = *name_slot;
    esp_log_write(1,"intr_alloc",INTERRUPT_ALLOCATION_FAILURE_FORMAT,
        timestamp,"intr_alloc",source_name,(unsigned int)flags);
    return 0x105;
}

/* Native entry: 0x42004c54. */
/* Original function-byte SHA-256:
 * 6de9412066768ab89275324af40277a0522457fdda8c5ca1ccda071a7b4da70b. */
/* Forward source, flags, handler, argument and result to the full allocator.
 * Supply zero status-register and status-mask arguments, including the seventh
 * handle-output argument on the native stack. Return the allocator status.
 * NULL result leaves the installed interrupt without a returned handle.
 */
int esp_intr_alloc(int source,int flags,InterruptHandler handler,void *argument,
                  InterruptHandle **result)

{
  int status;

  status = esp_intr_alloc_intrstatus(source,flags,0,0,handler,argument,result);
  return status;
}

/* Native entry: 0x42004c6c. */
/* Original function-byte SHA-256:
 * 8dee7e23edbd01fe94be3b2c46cbed327bb4868473969130969ab67ade8010cf. */
/* Destroy a live handle on its owning CPU; there is no C status result.
 * Under the allocator lock, call esp_intr_disable and ignore its result. For a
 * shared vector, assert a nonempty list, cache the target node, walk next links
 * and unlink/free a match. A missing target still reaches handle cleanup.
 * Reset the low-level handler for the last shared user or a nonshared vector:
 * clear low-halfword flags, mark source -99 and clear the owner's non-IRAM bit.
 * Retain the vector allocation. Unlock before freeing the 8-byte handle.
 * No NULL/stale-handle validation, callback-data wipe or rollback is supplied.
 */
void intr_free_for_current_cpu(InterruptHandle *handle)
{
    xPortEnterCriticalTimeout(INTERRUPT_ALLOCATOR_LOCK,-1);
    esp_intr_disable(handle);
    const volatile InterruptHandle *handle_view = handle;
    volatile InterruptVector *vector = handle_view->vector_desc;
    unsigned int flags = vector->flags_low16;
    if ((flags & 4U) != 0) {
        SharedInterrupt *node = vector->shared_vec_info;
        if (node == NULL)
            __assert_func(NULL,0,NULL,NULL);
        SharedInterrupt *target = handle_view->shared_vector_desc;
        SharedInterrupt *previous = NULL;
        while (true) {
            SharedInterrupt *next = ((volatile SharedInterrupt *)node)->next;
            if (node == target) {
                if (previous == NULL)
                    vector->shared_vec_info = next;
                else
                    ((volatile SharedInterrupt *)previous)->next = next;
                free(node);
                vector = handle_view->vector_desc;
                if (vector->shared_vec_info == NULL)
                    goto reset_vector;
                break;
            }
            if (next == NULL)
                break;
            previous = node;
            node = next;
        }
        /* A missing shared target still reaches native handle cleanup. */
        flags = vector->flags_low16;
    }
    if ((flags & 8U) == 0)
        goto unlock_and_free_handle;

reset_vector:;
    unsigned int word = vector->flags_cpu_intno;
    unsigned int number = (word >> 17) & 31U;
    xt_set_interrupt_handler(number,NULL,(void *)(uintptr_t)number);
    vector = handle_view->vector_desc;
    unsigned int old_flags = vector->flags_low16;
    vector->flags_low16 = (unsigned short)(old_flags & 0xfff2U);
    unsigned int current_word = vector->flags_cpu_intno;
    unsigned int owner_cpu = (current_word >> 16) & 1U;
    unsigned int interrupt_mask = 1U << ((current_word >> 17) & 31U);
    unsigned int non_iram_mask = INTERRUPT_ALLOCATOR_STATE->non_iram_mask[owner_cpu];
    vector->source = -99;
    INTERRUPT_ALLOCATOR_STATE->non_iram_mask[owner_cpu] = non_iram_mask & ~interrupt_mask;

unlock_and_free_handle:
    vPortExitCritical(INTERRUPT_ALLOCATOR_LOCK);
    free(handle);
}

/* Native entry: 0x42004d2c. */
/* Original function-byte SHA-256:
 * e2a108084ad8477f25c0db3d5dca1547a9ebbc094f6f83014d3b52ca118789e1. */
/* IPC callback: forward the borrowed context as an interrupt handle to
 * intr_free_for_current_cpu. Add no validation, allocation, lock or return value.
 */
void intr_free_for_other_cpu(void *argument)

{
  intr_free_for_current_cpu(argument);
  return;
}

/* Native entry: 0x42004d38. */
/* Original function-byte SHA-256:
 * 12cc9343409a9111d3412522bcc761553c2b83f4c07a857c79c3938bf719b304. */
/* Free an interrupt on its owner CPU, using blocking IPC when needed.
 * NULL handle returns 0x102. Query the current task affinity, then read owner CPU
 * from the handle's vector. Unpinned tasks always use IPC without reading PRID;
 * pinned tasks compare a fresh PRID CPU and free locally only on the owner.
 * Return 0 for success or -1 for any nonzero IPC status. Successful cleanup
 * invalidates the handle and retains the vector; an IPC failure is not retried.
 */
int esp_intr_free(InterruptHandle *handle)
{
    if (handle == NULL)
        return 0x102;
    int task_affinity = xTaskGetCoreID(NULL);
    const volatile InterruptHandle *handle_view = handle;
    const volatile InterruptVector *vector = handle_view->vector_desc;
    unsigned int owner_cpu = (vector->flags_cpu_intno >> 16) & 1U;
    if (task_affinity == 0x7fffffff || owner_cpu != ((xtensa_read_prid() >> 13) & 1U)) {
        int ipc_status = esp_ipc_call_blocking(owner_cpu,intr_free_for_other_cpu,handle);
        return ipc_status == 0 ? 0 : -1;
    }
    intr_free_for_current_cpu(handle);
    return 0;
}

/* Native entry: 0x42005280. */
/* Original function-byte SHA-256:
 * 873f943e090a359ae2f2ee5a9516bff873f230e4386be642a776c51bdb9d153c. */
/* Register a callback for a captured RTC interrupt-mask intersection.
 * Under the RTC list lock, lazily disable RTC enables, clear all pending status
 * and install the IRAM dispatcher on matrix source 39. Publish its owner CPU
 * only after successful allocation. Unlock before allocating the 20-byte node;
 * a later node-allocation failure leaves that dispatcher installed.
 * Initialize mask, flags, callback and argument in that order. Reacquire the list
 * lock, read cache mask then list head, prepend the node and publish cache policy.
 * Flag bit 0 adds its mask to the cache-safe set; clear bit 0 removes those bits,
 * including bits another callback might use. No callback/mask validation or
 * aggregate recalculation. Return allocation status, 0x101 for no node, or 0.
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
  volatile RtcIsrHandler *initial = node;
  initial->mask = rtc_intr_mask;
  initial->flags = flags;
  initial->handler = handler;
  initial->handler_arg = handler_arg;
  xPortEnterCriticalTimeout(&RTC_INTERRUPT_STATE->lock, 0xffffffffU);
  old_cache_mask = RTC_INTERRUPT_STATE->cache_safe_mask;
  RtcIsrHandler *previous_head = RTC_INTERRUPT_STATE->handlers;
  new_cache_mask = old_cache_mask & ~rtc_intr_mask;
  if ((flags & 1U) != 0) {
    new_cache_mask = old_cache_mask | rtc_intr_mask;
  }
  initial->next = previous_head;
  RTC_INTERRUPT_STATE->handlers = node;
  RTC_INTERRUPT_STATE->cache_safe_mask = new_cache_mask;
  vPortExitCritical(&RTC_INTERRUPT_STATE->lock);
  return 0;
}

/* Native entry: 0x420071d0. */
/* Original function-byte SHA-256:
 * 3129369b68a35535096d488a61a4ae72f2dec1c6eb454cb938f56e9ffc7e86cc. */
/* Copy fixed CPU interrupt properties into a 12-byte result.
 * Require CPU 0/1 and non-NULL description; otherwise assert. The interrupt
 * number has no bounds check. Compute its native wrapped 16-byte row address,
 * read priority, trigger type and selected CPU flags in that order, then write
 * the three output words in the same order. Type values are level 0, edge 1,
 * not-applicable 2; flags are unsigned. No interrupt state is changed.
 */
void esp_cpu_intr_get_desc(int cpu,int interrupt_number,CpuInterruptDescription *description)
{
    if ((unsigned int)cpu > 1U || description == NULL)
        __assert_func(NULL,0,NULL,NULL);
    const volatile CpuInterruptTableEntry *row = (const volatile CpuInterruptTableEntry *)(
        (uintptr_t)CPU_INTERRUPT_DESCRIPTIONS + (unsigned int)interrupt_number * sizeof(CpuInterruptTableEntry));
    int priority = row->priority;
    int trigger_type = row->type;
    unsigned int flags = row->flags[cpu];
    volatile CpuInterruptDescription *output = description;
    output->priority = priority;
    output->type = trigger_type;
    output->flags = flags;
}

/* Native entry: 0x42010900. */
/* Original function-byte SHA-256:
 * 9124c71db551d71d58d9226912951cb27f1e1e117f2cf9cad0b23792624eb681. */
/* Clear this CPU's pending reasons and install its IRAM cross-core ISR.
 * Lock the reason mux, read PRID, MEMW/clear that CPU's word, then unlock.
 * Read PRID again after unlock to choose source 79/80 and the corresponding
 * reason pointer. Allocate with IRAM flag 0x400 and NULL handle output.
 * Abort on any nonzero allocation status. No rollback or duplicate-install
 * guard; call once per active core. The two CPU samples remain independent.
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

/* Native entry: 0x42020cb0. */
/* Original function-byte SHA-256:
 * 9aa780d3c051c507265d7e7c060c3c12cff4ba24c29eb4351d555d48a25449c5. */
/* Return the vector's owner CPU bit, or -1 for NULL handle/vector.
 * Cache the vector pointer once, then read its packed word. No lock, lifetime
 * validation, allocation or interrupt-state change is supplied.
 */
int esp_intr_get_cpu(InterruptHandle *handle)
{
    if (handle == NULL)
        return -1;
    const volatile InterruptHandle *handle_view = handle;
    const volatile InterruptVector *vector = handle_view->vector_desc;
    if (vector == NULL)
        return -1;
    return (int)((vector->flags_cpu_intno >> 16) & 1U);
}

/* Native entry: 0x4203a6a8. */
/* Original function-byte SHA-256:
 * 3bc927924499703b327e91b4721347e9f222753c446e29f33b375ac20aa44f1b. */
/* Compare one handler-table entry with xt_unhandled_interrupt.
 * Use the native wrapped index interrupt_number * 2 + cpu and 8-byte stride.
 * Read only its handler pointer and return 0/1. No bounds checks, lock, argument
 * validation or descriptor lookup; caller supplies a suitable live table index.
 */
int xt_int_has_handler(int interrupt_number,int cpu)
{
    unsigned int index = (unsigned int)interrupt_number * 2U + (unsigned int)cpu;
    const volatile CpuIsrEntry *entry = (const volatile CpuIsrEntry *)(
        (uintptr_t)CPU_ISR_TABLE + index * sizeof(CpuIsrEntry));
    InterruptHandler handler = entry->handler;
    return handler != xt_unhandled_interrupt;
}

/* Native entry: 0x4203a6c4. */
/* Original function-byte SHA-256:
 * 614c5166f0394b16b6d8f29015ec04343053f35012c5d9bdcc72a48916f5d0fe. */
/* Replace a handler on the current CPU and return the previous handler.
 * Reject IRQs outside 0..31 or fixed levels above 3 with NULL. Read PRID, then
 * cache the old pointer. Store argument before handler without taking a lock.
 * NULL handler installs xt_unhandled_interrupt with IRQ * 2 + CPU as its raw
 * diagnostic argument. Return NULL if the old handler was the default.
 * Caller supplies serialization and callback/context lifetime.
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

