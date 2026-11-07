/* Medius v3.4.7 host — rtos/port.c.
 * Recovered C and native assembly, grouped for source navigation.
 * Original entry addresses, firmware-byte hashes and function comments follow.
 */

#include "../include/types.h"

/* Native entry: 0x40376964. */
/*
 * Medius v3.4.7 — host application; 0x40376964.
 *
 * Reads CPU ID from PRID bit13 and returns whether that CPU interrupt-nesting counter is nonzero.
 * Unlike xPortInIsrContext, this short helper does not mask and restore interrupts around the
 * read; it does not inspect task priority or scheduler state.
 *
 * Called by: FUN_42003458.
 *
 * Original function-byte SHA-256:
 * b4e81cbc812c0a42df57b404efa18aabd5cbd838e114bb3453ad03bc72c347f7.
 */

/* Reference: ESP-IDF v5.4.4 components/freertos/FreeRTOS-Kernel/portable/xtensa/port.c. */

/*
 * Returns: 1 when the current CPU interrupt-nesting counter is nonzero; otherwise 0.
 * Requirements/effects: Reads CPU selection from PRID bit13. Takes no lock and does not mask
 *   interrupts; it is an instantaneous nesting-state observation.
 */

int xPortInterruptedFromISRContext(void)

{
  uint core = (xtensa_read_prid() >> 13) & 1U;
  return PORT_INTERRUPT_NESTING[core] != 0;
}

/* Native entry: 0x40381b4c. */
/*
 * Medius v3.4.7 — host application; 0x40381b4c.
 *
 * Masks interrupts to level 3, clears the coprocessor owner table, sets up the SYSTIMER tick,
 * marks this core scheduler running, and spills startup-stack register windows before CALL0 to
 * _frxt_dispatch. The SDK declares a BaseType_t result, but this compiled path never returns to
 * its startup caller.
 *
 * Calls: _frxt_dispatch, vPortSetupTimer, xthal_window_spill, _xt_coproc_init.
 *
 * Called by: vTaskStartScheduler, FUN_42023a8c.
 *
 * Original function-byte SHA-256:
 * 1d9b46bdcf74aa228f71ccad4703e6b9bbbf9e137864110fadd120205b34ea6c.
 */

/* Masks interrupts to level 3, clears the coprocessor owner table, sets up the SYSTIMER tick,
   marks this core scheduler running, and spills startup-stack register windows before CALL0 to
   _frxt_dispatch. The SDK declares a BaseType_t result, but this compiled path never returns to
   its startup caller. Reference: ESP-IDF v5.4.4 components/freertos/FreeRTOS-
   Kernel/portable/xtensa/port.c. */

__attribute__((noreturn))

/*
 * Returns: Does not return in this linked build, despite the SDK int declaration.
 * Requirements/effects: Startup path raises interrupt level, initializes coprocessor/tick state,
 *   marks this CPU running, spills windows and CALL0-transfers to the dispatcher.
 */

int xPortStartScheduler(void)
{
  uint previous_ps;
  __asm__ volatile ("rsil %0,3" : "=a"(previous_ps) : : "memory");
  _xt_coproc_init();
  vPortSetupTimer();
  uint core = (xtensa_read_prid() >> 13) & 1U;
  memw();
  SCHEDULER_RUNNING[core] = 1;
  xthal_window_spill();
  /* CALL0 transfers into an assembly dispatcher using the selected task's
     stack. A normal windowed C call would model the wrong entry contract. */
  __asm__ volatile ("call0 _frxt_dispatch" : : : "memory");
  __builtin_unreachable();
}

/* Native entry: 0x40381b74. */
/*
 * Medius v3.4.7 — host application; 0x40381b74.
 *
 * Requires 16-byte-aligned stack top. Initializes the coprocessor header, performs the compiled zero-byte GCC TLS copy, zeroes a 192-byte exception frame and sets exit dispatcher, task PC, PS=0x50030, A1, A6 and THREADPTR. Returns the frame address, 512 bytes below the incoming top in these images.
 *
 * Calls: __assert_func, memcpy, memset.
 *
 * Called by: prvInitialiseNewTask.
 *
 * Original function-byte SHA-256:
 * 5410a6e4018d85bcee68962f5a77d29cc948d7aa1042e300952cf192ca67c1d8.
 */

/* Requires 16-byte-aligned stack top. Initializes the coprocessor header, performs the compiled zero-byte GCC TLS copy, zeroes a 192-byte exception frame and sets exit dispatcher, task PC, PS=0x50030, A1, A6 and THREADPTR. Returns the frame address, 512 bytes below the incoming top in these images.
   Reference: ESP-IDF v5.4.4 components/freertos/FreeRTOS-Kernel/portable/xtensa/port.c. */

/*
 * top: 16-byte-aligned writable top-of-stack; backing storage must extend at least 512 bytes below
 *   it.
 * entry: Task entry address placed in the initial frame.
 * argument: Opaque task argument placed in frame register A6.
 * Returns: Initial frame pointer, 512 bytes below the aligned incoming top.
 * Requirements/effects: Asserts on misalignment. Clears coprocessor header and 192-byte exception
 *   frame; installs PS 0x50030, exit dispatcher and per-image thread-pointer bias. Linked GCC TLS
 *   copy length is zero. Does not allocate or validate total stack size, and does not clear the
 *   entire coprocessor payload.
 */

uint *pxPortInitialiseStack(uint *top,TaskEntry entry,void *argument)
{
  if (((uint)top & 15) != 0) {
    __assert_func(0,0,0,0);
  }
  uint coprocessor_base = ((uint)top - 0x13c) & 0xfffffff0;
  volatile XtensaCoprocessorHeader *coprocessors = (XtensaCoprocessorHeader *)coprocessor_base;
  coprocessors->enabled_stored = 0;
  coprocessors->saved_reserved = 0;
  coprocessors->aligned_save_area = (void *)(coprocessor_base + 16);
  /* The linked GCC TLS image is empty. The firmware still calls ROM memcpy
     with length zero before constructing the initial interrupt frame. */
  memcpy((void *)coprocessor_base,(const void *)0x3c052794,0);
  volatile XtensaExceptionFrame *frame = (XtensaExceptionFrame *)(coprocessor_base - 192);
  memset((void *)frame,0,192);
  frame->exit_dispatch = _xt_user_exit;
  frame->a[1] = coprocessor_base;
  frame->a[0] = 0;
  frame->pc = entry;
  frame->a[6] = (uint)argument;
  frame->ps = 0x50030; /* UM | EXCM | WOE | CALLINC(1); RFE clears EXCM. */
  frame->thread_pointer = coprocessor_base - 0x12684;
  return (uint *)frame;
}

/* Native entry: 0x40381bf8. */
/*
 * Medius v3.4.7 — host application; 0x40381bf8.
 *
 * Checks whether the current core has a nonzero interrupt nesting count.
 *
 * Calls: _xtos_set_intlevel.
 *
 * Called by: FUN_40375b48, FUN_40375b58, esp_intr_enable, esp_intr_disable, esp_intr_noniram_disable, esp_intr_noniram_enable,
 * periph_rcc_enter, periph_rcc_exit, regi2c_ctrl_read_reg_mask, regi2c_ctrl_write_reg, regi2c_ctrl_write_reg_mask, esp_timer_impl_set_alarm_id,
 * timer_remove, FUN_40380c04, FUN_40380c18, FUN_40380ca4, FUN_40380ce4, FUN_4038127c,
 * xTaskIncrementTick, vTaskSwitchContext, xTaskRemoveFromEventList, multi_heap_aligned_alloc_offs, multi_heap_free, multi_heap_malloc; plus 37
 * other direct targets.
 *
 * Original function-byte SHA-256:
 * 4bf054c97e57d1977a846e3ec2454e12551761615f301abb38dd6b6c3fd43fcb.
 */

/*
 * Snapshot this CPU's interrupt-nesting count with interrupt level set to 3.
 * Takes no arguments and returns exactly 0 or 1 as a FreeRTOS BaseType_t.
 * PRID bit 13 selects one of the two per-CPU counters; the full PRID is not
 * an array index. No spinlock is acquired and no counter is changed.
 *
 * RSIL saves the complete previous PS. The ROM _xtos_set_intlevel call
 * restores only its INTLEVEL field, not the entire PS. Requires initialized
 * port counters and normal Xtensa privileged execution; the observation can
 * become stale after the interrupt level is restored.
 */
int xPortInIsrContext(void)
{
    unsigned int previous_ps;
    __asm__ volatile ("rsil %0,3" : "=a"(previous_ps) : : "memory");
    unsigned int core_id = (xtensa_read_prid() >> 13) & 1U;
    unsigned int interrupt_nesting = PORT_INTERRUPT_NESTING[core_id];
    (void)_xtos_set_intlevel((int)previous_ps);
    return interrupt_nesting != 0;
}

/* Native entry: 0x40381c1c. */
/*
 * Medius v3.4.7 — host application; 0x40381c1c.
 *
 * Masks interrupts and acquires a recursive per-core spinlock with a timeout.
 *
 * Calls: __assert_func, _xtos_set_intlevel, esp_cpu_compare_and_set.
 *
 * Called by: FUN_40375b58, shared_intr_isr, esp_intr_enable, esp_intr_disable, esp_intr_noniram_disable, esp_intr_noniram_enable,
 * periph_rcc_enter, rtc_isr, regi2c_ctrl_read_reg_mask, regi2c_ctrl_write_reg, regi2c_ctrl_write_reg_mask, lock_acquire_generic,
 * FUN_40376a70, FUN_40376b30, FUN_40376b58, esp_timer_impl_set_alarm_id, FUN_4037d2b0, esp_crosscore_int_send,
 * timer_remove, FUN_4037f8b4, FUN_40380c04, FUN_40380ca4, prvSendAcquireGeneric, prvReceiveGeneric; plus 173
 * other direct targets.
 *
 * Original function-byte SHA-256:
 * 8f99177e87d5b163f90ce719415c8a36dc4031188d3487510413cd85559c2d9e.
 */

/*
 * Raise this CPU's interrupt level to 3 and acquire a recursive portMUX.
 * lock: initialized, aligned, shared 8-byte owner/count object; must be non-NULL.
 * timeout_cycles: 0 makes one CAS attempt; -1 retries indefinitely. All other
 * values use an unsigned, wrapping CCOUNT delta and retry while delta <= timeout.
 * A failed first attempt samples CCOUNT even for -1; a successful first attempt
 * or timeout 0 does not sample it. Failed attempts never sleep or yield.
 * Returns 1 on acquisition, leaving the outer interrupt mask in force, or 0 on
 * timeout after restoring the caller's interrupt level. This host image's
 * compare-and-set helper uses S32C1I directly, without the device's RAM guard.
 *
 * Ownership uses the full PRID, not core index 0/1. Recursive ownership requires
 * count 1..254 and increments it; first acquisition requires count 0 and sets 1.
 * Failed acquisition permits only the other CPU's owner (PRID XOR 0x6666) or
 * FREE, with count < 255. Invalid state is fatal through __assert_func.
 *
 * The inner spinlock scope restores its complete saved PS with WSR/RSYNC.
 * Successful entry then increments the separate per-CPU critical nesting;
 * only transition 0->1 saves the caller's outer PS. Timeout restores INTLEVEL
 * through ROM and leaves those per-CPU arrays unchanged. Requires valid port
 * state, suitable memory for the helper, and caller-controlled lock lifetime.
 * This entry allows ISR use; it does not perform the compliance wrapper's
 * ISR rejection. Interrupt delivery, scheduling and physical contention are
 * hardware/runtime requirements, not established by this static reconstruction.
 */
int xPortEnterCriticalTimeout(PortMux *lock, int timeout_cycles)
{
    unsigned int outer_ps;
    __asm__ volatile ("rsil %0,3" : "=a"(outer_ps) : : "memory");
    if (lock == 0)
        __assert_func(0, 0, 0, 0);

    unsigned int spinlock_ps;
    __asm__ volatile ("rsil %0,3" : "=a"(spinlock_ps) : : "memory");
    unsigned int owner_id = xtensa_read_prid();
    int acquired = 1;
    if (lock->owner == owner_id) {
        unsigned int count = lock->count;
        if (count == 0 || count >= 255U)
            __assert_func(0, 0, 0, 0);
        lock->count = count + 1U;
    } else {
        acquired = esp_cpu_compare_and_set(&lock->owner,
                                           PORTMUX_FREE_OWNER, owner_id);
        if (!acquired && timeout_cycles != 0) {
            unsigned int start_cycles;
            __asm__ volatile ("rsr.ccount %0" : "=a"(start_cycles));
            for (;;) {
                acquired = esp_cpu_compare_and_set(&lock->owner,
                                                   PORTMUX_FREE_OWNER, owner_id);
                if (acquired)
                    break;
                if (timeout_cycles != -1) {
                    unsigned int now_cycles;
                    __asm__ volatile ("rsr.ccount %0" : "=a"(now_cycles));
                    if ((now_cycles - start_cycles) > (unsigned int)timeout_cycles)
                        break;
                }
            }
        }
        if (acquired) {
            if (lock->owner != owner_id || lock->count != 0)
                __assert_func(0, 0, 0, 0);
            lock->count = 1;
        } else {
            unsigned int observed_owner = lock->owner;
            if ((observed_owner != (owner_id ^ 0x6666U) &&
                 observed_owner != PORTMUX_FREE_OWNER) || lock->count >= 255U)
                __assert_func(0, 0, 0, 0);
        }
    }
    __asm__ volatile ("wsr %0,ps\n\trsync" : : "a"(spinlock_ps) : "memory");
    if (!acquired) {
        (void)_xtos_set_intlevel((int)outer_ps);
        return 0;
    }

    unsigned int core_id = (xtensa_read_prid() >> 13) & 1U;
    unsigned int nesting = PORT_CRITICAL_NESTING[core_id] + 1U;
    PORT_CRITICAL_NESTING[core_id] = nesting;
    if (nesting == 1)
        PORT_SAVED_PS[core_id] = outer_ps;
    return 1;
}

/* Native entry: 0x40381d24. */
/*
 * Medius v3.4.7 — host application; 0x40381d24.
 *
 * Releases a recursive spinlock and restores interrupt state when nesting permits.
 *
 * Calls: __assert_func, _xtos_set_intlevel.
 *
 * Called by: FUN_40375b48, shared_intr_isr, esp_intr_enable, esp_intr_disable, esp_intr_noniram_disable, esp_intr_noniram_enable,
 * periph_rcc_exit, rtc_isr, regi2c_ctrl_read_reg_mask, regi2c_ctrl_write_reg, regi2c_ctrl_write_reg_mask, lock_acquire_generic,
 * FUN_40376a70, FUN_40376b30, FUN_40376b58, esp_timer_impl_set_alarm_id, FUN_4037d2b0, esp_crosscore_int_send,
 * timer_remove, FUN_4037f8b4, FUN_40380c18, FUN_40380ce4, prvSendAcquireGeneric, prvReceiveGeneric; plus 173
 * other direct targets.
 *
 * Original function-byte SHA-256:
 * 674dbfc45ed34b221495fd5388ba9a7aae163b18d2ed60d090167d93e3205bdc.
 */

/*
 * Release one recursion level of lock and one critical nesting level on this CPU.
 * lock: the same live, initialized portMUX successfully entered by this CPU;
 * calls must balance successful entries. No value is returned.
 *
 * Asserts on NULL before changing PS. With interrupt level 3, verifies full
 * PRID ownership, decrements and stores count, then marks owner FREE if count
 * became zero. A nonzero remaining count > 255 is fatal. In particular, an
 * invalid original count of zero is stored as 0xffffffff before that assertion;
 * this routine does not undo a corrupt release.
 *
 * Restores the inner complete PS with WSR/RSYNC before inspecting per-CPU
 * critical nesting. Nonpositive signed nesting is fatal after the lock release.
 * Otherwise decrements that separate counter and, only on transition 1->0,
 * restores the saved outer INTLEVEL through ROM _xtos_set_intlevel. It does
 * not restore the entire saved outer PS, clear the saved slot, yield, free
 * the lock, or verify balanced use of different lock objects. Requires
 * valid per-CPU state and appropriate shared-memory ordering/lifetime.
 */
void vPortExitCritical(PortMux *lock)
{
    if (lock == 0)
        __assert_func(0, 0, 0, 0);
    unsigned int previous_ps;
    __asm__ volatile ("rsil %0,3" : "=a"(previous_ps) : : "memory");
    unsigned int owner_id = xtensa_read_prid();
    if (lock->owner != owner_id)
        __assert_func(0, 0, 0, 0);

    unsigned int remaining = lock->count - 1U;
    lock->count = remaining;
    if (remaining == 0)
        lock->owner = PORTMUX_FREE_OWNER;
    else if (remaining > 255U)
        __assert_func(0, 0, 0, 0);
    __asm__ volatile ("wsr %0,ps\n\trsync" : : "a"(previous_ps) : "memory");

    unsigned int core_id = (xtensa_read_prid() >> 13) & 1U;
    unsigned int nesting = PORT_CRITICAL_NESTING[core_id];
    if ((int)nesting <= 0)
        __assert_func(0, 0, 0, 0);
    nesting -= 1U;
    PORT_CRITICAL_NESTING[core_id] = nesting;
    if (nesting == 0)
        (void)_xtos_set_intlevel((int)PORT_SAVED_PS[core_id]);
}

/* Native entry: 0x40381dd8. */
/*
 * Medius v3.4.7 — host application; 0x40381dd8.
 *
 * Runs thread-local-storage deletion callbacks and coprocessor cleanup before task deletion.
 *
 * Calls: esp_ptr_executable, esp_log_timestamp, _xt_coproc_release, abort, ets_printf.
 *
 * Called by: prvDeleteTCB.
 *
 * Indirect call: invokes the stored TLS deletion callback with index0 and its TLS value.
 *
 * Original function-byte SHA-256:
 * a0894aa2094be75efe61ed3600b5afd0eb1f20f61f8a8fe59d40705b518fb740.
 */

/*
 * Run the single configured TLS deletion callback, then release this task's
 * coprocessor-owner slots. task must be a live, exclusively reclaimed TCB;
 * NULL, core ID, stack bounds and callback lifetime are not validated here.
 * Returns no value. It neither frees the task/stack nor reclaims its Newlib
 * context; prvDeleteTCB performs those operations after this hook returns.
 *
 * Read callback at TCB+0x58 once for the initial non-NULL/address check.
 * A rejected address optionally prints the fatal diagnostic when the shared
 * word gate is nonzero, then calls abort regardless of that gate. Timestamp
 * precedes a fresh callback read for the diagnostic; the TLS index printed is
 * zero. Region membership alone does not establish valid executable code.
 *
 * On acceptance, reload callback and TLS value (+0x54), then call (0,value).
 * The reload is not revalidated; concurrent/reentrant mutation of the slot
 * can therefore replace a checked callback. No slot is cleared, no local
 * lock is acquired, and callback nonreturn/exception prevents later cleanup.
 *
 * After callback return (or absent callback), read stack_end (+0x48) and core
 * (+0x44) afresh. Release owner-table matches for the 16-byte-aligned header
 * at (stack_end - 316) modulo 32 bits. _xt_coproc_release owns its internal
 * interrupt mask/lock; it does not free the payload or save CP registers.
 * Valid stack storage and a valid owner-table CPU row are caller obligations.
 * The volatile TCB view retains the observed native read/reload ordering;
 * it does not provide synchronization or pin the callback's code lifetime.
 */
void vPortTCBPreDeleteHook(RtosTask *task)
{
    volatile RtosTask *state = task;
    TlsDeleteCallback callback = state->tls_delete_callback;
    if (callback != 0) {
        if (!esp_ptr_executable((const void *)callback)) {
            if (PORT_TLS_DIAGNOSTIC_GATE != 0) {
                unsigned int timestamp = esp_log_timestamp();
                TlsDeleteCallback reported_callback = state->tls_delete_callback;
                ets_printf("E (%lu) %s: Fatal error: TLSP deletion callback at index %d overwritten with non-excutable pointer %p\n",
                           (unsigned long)timestamp, "FreeRTOS", 0, (void *)reported_callback);
            }
            abort();
        }
        callback = state->tls_delete_callback;
        void *value = state->thread_local_storage;
        callback(0, value);
    }
    unsigned int stack_end = (unsigned int)state->stack_end;
    int target_core = state->core_id;
    XtensaCoprocessorHeader *header = (XtensaCoprocessorHeader *)
        ((stack_end - 0x13cU) & ~15U);
    _xt_coproc_release(header, target_core);
}

/* Native entry: 0x40381f40. */
/*
 * Medius v3.4.7 — host application; 0x40381f40.
 * Instruction-reviewed Xtensa assembly; C braces display the native entry.
 *
 * Windowed-ABI task yield. Creates a 32-byte solicited frame containing
 * return PC, original PS and THREADPTR, spills register windows, records the
 * frame in the TCB with exit=0, clears hardware/saved CPENABLE, and tail-dispatches.
 * The task later resumes through the dispatcher's solicited RETW path, so this
 * remains a returning C-facing void API despite its nonreturning tail transfer.
 *
 * Calls: _frxt_dispatch, xthal_window_spill_nw, _xt_coproc_savecs.
 *
 * Called by: usb_osal_thread_schedule_other.
 *
 * Original function-byte SHA-256:
 * d9f86f0b4b09325882fb92ffe3e2194bf3126db05cad023af9d61bd9c1e0fe01.
 */

/* Preserve the actual instruction operands: after saving PS, this build
   overwrites A2 with THREADPTR, then derives temporary PS from
       (THREADPTR & 0xfffbfff0) + 3
   before calling xthal_window_spill_nw. It does NOT reload saved PS before that
   mask. The original PS is reloaded from frame+8 after the spill. This unusual
   sequence exists in both binaries; the reconstruction does not silently
   replace THREADPTR with PS. It has been traced statically, not exercised by
   the successful initial-dispatch runtime check.
   After spilling, RSIL masks interrupts at level 3. The zero marker is written
   to frame+0, the TCB saves A1, and both hardware/header CPENABLE are cleared.
   There is no local RETW: _frxt_dispatch eventually returns for the resumed
   task using this saved frame. Do not mark the public vPortYield API noreturn.
   Reference: ESP-IDF v5.4.4 components/freertos/FreeRTOS-Kernel/portable/xtensa/portasm.S.
   Corrected assembly span: 0x40381f40..0x40381fa3; SHA-256:
   d9f86f0b4b09325882fb92ffe3e2194bf3126db05cad023af9d61bd9c1e0fe01. */

/* These braces display the original assembly body, not a C wrapper
   to compile with an additional compiler-generated prologue. */

/*
 * Returns: Eventually returns to the yielded task through the dispatcher solicited-frame RETW
 *   path.
 * Requirements/effects: Windowed task context with valid current TCB and spill/save areas. Builds
 *   the32-byte frame, saves PS/TLS, spills windows and dispatches; preserves the compiled
 *   THREADPTR-derived temporary-PS sequence described above.
 */

void vPortYield(void)
{
  __asm__ volatile (
      /* Allocate the 32-byte solicited frame and save return PC/PS/TLS. */
      "entry\ta1, 32\n"
      "rsr.ps\ta2\n"
      "s32i.n\ta0, a1, 4\n"
      "s32i.n\ta2, a1, 8\n"
      "rur.threadptr\ta2\n"
      "s32i.n\ta2, a1, 12\n"
      /* Actual binary operand is THREADPTR still in A2, not saved PS. */
      "l32r\ta6, 0x40374d3c\n" /* literal: 0xfffbfff0 */
      "and\ta2, a2, a6\n"
      "addi\ta2, a2, 3\n"
      "wsr.ps\ta2\n"
      "rsync\n"
      "call0\txthal_window_spill_nw\n"
      /* Restore the original PS after the manual spill. */
      "l32i.n\ta2, a1, 8\n"
      "wsr.ps\ta2\n"
      /* Mask interrupts and save callee-saved coprocessor bookkeeping. */
      "rsil\ta2, 3\n"
      "call0\t_xt_coproc_savecs\n"
      "l32r\ta2, 0x40374d2c\n" /* literal: 0x3fca76c8 */
      "rsr.prid\ta3\n"
      "extui\ta3, a3, 13, 1\n"
      "addx4\ta2, a3, a2\n"
      "l32i.n\ta2, a2, 0\n"
      "movi.n\ta3, 0\n"
      /* Publish exit=0 and this task's frame pointer. */
      "s32i.n\ta3, a1, 0\n"
      "s32i.n\ta1, a2, 0\n"
      "l32r\ta3, 0x40374d34\n" /* literal: 0x3fc9f238 */
      "l32i.n\ta3, a3, 0\n"
      "add.n\ta2, a2, a3\n"
      "l32i.n\ta2, a2, 0\n"
      "l32r\ta3, 0x40374d38\n" /* literal: 0x3fc9f234 */
      "l32i.n\ta3, a3, 0\n"
      "sub\ta2, a2, a3\n"
      "movi.n\ta3, -16\n"
      "and\ta2, a2, a3\n"
      /* Clear hardware and saved CPENABLE; dispatch rather than locally return. */
      "movi.n\ta3, 0\n"
      "wsr.cpenable\ta3\n"
      "beqz\ta2, .Lyield_40381fa1\n"
      "s16i\ta3, a2, 0\n"
      ".Lyield_40381fa1:\n"
      "call0\t_frxt_dispatch\n"
  );
}

/* Native entry: 0x40381fa4. */
/*
 * Medius v3.4.7 — host application; 0x40381fa4.
 * Instruction-reviewed Xtensa assembly; C braces display the native entry.
 *
 * Windowed-ABI helper called by outermost interrupt exit before dispatch.
 * Finds the current task's aligned coprocessor header, stores hardware CPENABLE
 * in header.enabled, clears CPENABLE, and RETW returns to _frxt_int_exit.
 * It does not choose the next task itself in this windowed build. The caller
 * supplies a valid current TCB and coprocessor header; no NULL check is added.
 *
 * Called by: _frxt_int_exit.
 *
 * Original function-byte SHA-256:
 * eef61095ddf8b44afe277bec354d3e6bf8c340d8683198a86425d9139df3dc77.
 */

/* Computes the header as align_down(task->stack_end - 316,16). Saves
   the low 16 CPENABLE bits at header+0 before clearing the hardware register.
   Unlike task yield, this path leaves an interrupt-frame exit pointer nonzero.
   RETW returns to the assembly caller, which then tail-calls _frxt_dispatch.
   Reference: ESP-IDF v5.4.4 components/freertos/FreeRTOS-Kernel/portable/xtensa/portasm.S.
   Corrected assembly span: 0x40381fa4..0x40381fd7; SHA-256:
   eef61095ddf8b44afe277bec354d3e6bf8c340d8683198a86425d9139df3dc77. */

/* These braces display the original assembly body, not a C wrapper
   to compile with an additional compiler-generated prologue. */

/*
 * Returns: RETW returns to its assembly interrupt-exit caller.
 * Requirements/effects: Outermost interrupt-switch path requires a live current TCB and aligned
 *   coprocessor header. Saves low16 CPENABLE to header.enabled, clears hardware CPENABLE and
 *   leaves the full-frame exit pointer unchanged.
 */

void vPortYieldFromInt(void)
{
  __asm__ volatile (
      "entry\ta1, 16\n"
      "l32r\ta2, 0x40374d2c\n" /* literal: 0x3fca76c8 */
      "rsr.prid\ta3\n"
      "extui\ta3, a3, 13, 1\n"
      "addx4\ta2, a3, a2\n"
      "l32i.n\ta2, a2, 0\n"
      "l32r\ta3, 0x40374d34\n" /* literal: 0x3fc9f238 */
      "l32i.n\ta3, a3, 0\n"
      "add.n\ta2, a2, a3\n"
      "l32i.n\ta2, a2, 0\n"
      "l32r\ta3, 0x40374d38\n" /* literal: 0x3fc9f234 */
      "l32i.n\ta3, a3, 0\n"
      "sub\ta2, a2, a3\n"
      "movi.n\ta3, -16\n"
      "and\ta2, a2, a3\n"
      "rsr.cpenable\ta3\n"
      "s16i\ta3, a2, 0\n"
      "movi.n\ta3, 0\n"
      "wsr.cpenable\ta3\n"
      "retw.n\n"
  );
}

/* Native entry: 0x40382048. */
/*
 * Medius v3.4.7 — host application; 0x40382048.
 *
 * Allocates FreeRTOS memory from internal byte-addressable RAM.
 *
 * Calls: heap_caps_malloc.
 *
 * Called by: vApplicationGetIdleTaskMemory, usb_osal_timer_create, xQueueCreateMutex, xQueueGenericCreate,
 * xTaskCreatePinnedToCore.
 *
 * Original function-byte SHA-256:
 * 11908a26bd27541788ea3a157a5cbcd757e33dea2a48ba44d833d872ff9c9bc7.
 */

/*
 * Allocates size bytes through heap_caps_malloc with INTERNAL|8BIT (0x804).
 * size is passed unchanged as an unsigned 32-bit byte count. Returns the
 * delegate's pointer unchanged. Zero-size and allocation-failure handling are
 * delegated; no local fallback, assertion, clearing or alignment adjustment.
 * Requires the initialized capability heap; ownership passes to the caller
 * according to that allocator's contract. This wrapper itself acquires no lock.
 */
void *pvPortMalloc(unsigned int size)
{
    return heap_caps_malloc(size, MALLOC_CAP_INTERNAL | MALLOC_CAP_8BIT);
}

/* Native entry: 0x4038205c. */
/*
 * Medius v3.4.7 — host application; 0x4038205c.
 *
 * Releases a FreeRTOS allocation through heap_caps_free; NULL is ignored by the underlying allocator. Does not clear the caller pointer.
 *
 * Calls: heap_caps_free.
 *
 * Called by: FUN_40381b30, prvDeleteTCB, usb_osal_timer_create, usb_osal_timer_delete,
 * xTaskCreatePinnedToCore.
 *
 * Original function-byte SHA-256:
 * 939a7b6e7fe0b9a91328022e74eea18c818179661ceab0b9d4f9eeb2b0084bea.
 */

/* Releases a FreeRTOS allocation through heap_caps_free; NULL is ignored by the underlying allocator. Does not clear the caller pointer.
   Reference: ESP-IDF v5.4.4 components/freertos/heap_idf.c. */

/*
 * buffer: Owned allocation accepted by heap_caps_free, or NULL.
 * Returns: Nothing.
 * Requirements/effects: Releases through the heap capability allocator. Does not clear the caller
 *   pointer or wipe the allocation; invalid or double-free pointers are not admitted here.
 */

void vPortFree(void *buffer)

{
  heap_caps_free(buffer);
  return;
}

/* Native entry: 0x40382068. */
/*
 * Medius v3.4.7 — host application; 0x40382068.
 *
 * Tests internal-region membership and byte accessibility for TCB/list storage. It checks the address, not allocation size, ownership or object lifetime.
 *
 * Calls: esp_ptr_byte_accessible.
 *
 * Called by: xTaskCreateStaticPinnedToCore, FUN_40384044.
 *
 * Original function-byte SHA-256:
 * 0c035abdee0a717abc6ead36ef2553dccb771e75db0585358cc64e6f7a02feb4.
 */

/* Tests internal-region membership and byte accessibility for TCB/list storage. It checks the address, not allocation size, ownership or object lifetime.
   Reference: ESP-IDF v5.4.4 components/freertos/heap_idf.c. */

/*
 * pointer: TCB/list starting address to admit.
 * Returns: True only when both internal-region and byte-accessibility predicates pass.
 * Requirements/effects: Checks address membership without validating allocation size, alignment,
 *   ownership or lifetime.
 */

bool xPortCheckValidTCBMem(void *pointer)
{
  uint address = (uint)pointer;
  bool internal = address + 0x9ff02000U < 0x2000U ||
                  address + 0xc0378000U < 0x758000U ||
                  address + 0xb0000000U < 0x2000U;
  if (!internal) return false;
  return esp_ptr_byte_accessible(pointer);
}

/* Native entry: 0x403820ac. */
/*
 * Medius v3.4.7 — host application; 0x403820ac.
 *
 * Host static stacks require both internal-region membership and byte accessibility. This is address admission, not a bounds check.
 *
 * Calls: esp_ptr_byte_accessible.
 *
 * Called by: xTaskCreateStaticPinnedToCore.
 *
 * Original function-byte SHA-256:
 * 781d483237becda5a6072a4358e5920da7a22a7054ff0a7f5754a86b21a4e8bd.
 */

/* Host static stacks require both internal-region membership and byte accessibility. This is address admission, not a bounds check.
   Reference: ESP-IDF v5.4.4 components/freertos/heap_idf.c. */

/*
 * pointer: Starting stack address to admit.
 * Returns: True only for an internal, byte-accessible address.
 * Requirements/effects: Host build requires internal memory. This address predicate does not
 *   validate full stack length, alignment or lifetime.
 */

bool xPortcheckValidStackMem(void *pointer)
{
  uint address = (uint)pointer;
  bool internal = address + 0x9ff02000U < 0x2000U ||
                  address + 0xc0378000U < 0x758000U ||
                  address + 0xb0000000U < 0x2000U;
  if (!internal) return false;
  return esp_ptr_byte_accessible(pointer);
}

