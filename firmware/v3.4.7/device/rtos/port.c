/* Medius v3.4.7 device — port.c. */
#include "../include/types.h"

/* Native entry: 0x40376d14. */
/* Original function-byte SHA-256:
 * 32517ad71af4bfd38c1bd71a20fe17f530ec5a9b71844bd0b5c820022372b218. */
/*
 * Returns: 1 when the current CPU interrupt-nesting counter is nonzero; otherwise 0.
 * Requirements/effects: Reads CPU selection from PRID bit13. Takes no lock and does not mask
 *   interrupts; it is an instantaneous nesting-state observation.
 */
int xPortInterruptedFromISRContext(void)

{
  unsigned int core = (xtensa_read_prid() >> 13) & 1U;
  return PORT_INTERRUPT_NESTING[core] != 0;
}

/* Native entry: 0x403868a4. */
/* Original function-byte SHA-256:
 * e955864dd9327d69896bbb42c5911e70714eceb6b24aaee3d559964374ea85f2. */
/*
 * Returns: Does not return in this linked build, despite the SDK int declaration.
 * Requirements/effects: Startup path raises interrupt level, initializes coprocessor/tick state,
 *   marks this CPU running, spills windows and CALL0-transfers to the dispatcher.
 */
int xPortStartScheduler(void)
{
  unsigned int previous_ps;
  __asm__ volatile ("rsil %0,3" : "=a"(previous_ps) : : "memory");
  _xt_coproc_init();
  vPortSetupTimer();
  unsigned int core = (xtensa_read_prid() >> 13) & 1U;
  memw();
  SCHEDULER_RUNNING[core] = 1;
  xthal_window_spill();
  /* CALL0 transfers into an assembly dispatcher using the selected task's
     stack. A normal windowed C call would model the wrong entry contract. */
  __asm__ volatile ("call0 _frxt_dispatch" : : : "memory");
  __builtin_unreachable();
}

/* Native entry: 0x403868cc. */
/* Original function-byte SHA-256:
 * a0a4e1dee303ea89a614ab9933b57214195ff1af662d4c3cba1855a4f9e5fe3f. */
/*
 * top: SDK byte-stack pointer, 16-byte-aligned writable top-of-stack; backing storage must extend at least 512 bytes below
 *   it.
 * entry: Task entry address placed in the initial frame.
 * argument: Opaque task argument placed in frame register A6.
 * Returns: Initial frame pointer, 512 bytes below the aligned incoming top.
 * Requirements/effects: Asserts on misalignment. Clears coprocessor header and 192-byte exception
 *   frame; installs PS 0x50030, exit dispatcher and per-image thread-pointer bias. Linked GCC TLS
 *   copy length is zero. Does not allocate or validate total stack size, and does not clear the
 *   entire coprocessor payload.
 */
unsigned char *pxPortInitialiseStack(unsigned char *top,TaskEntry entry,void *argument)
{
  if (((unsigned int)top & 15) != 0) {
    __assert_func(0,0,0,0);
  }
  unsigned int coprocessor_base = ((unsigned int)top - 0x13c) & 0xfffffff0;
  volatile XtensaCoprocessorHeader *coprocessors = (XtensaCoprocessorHeader *)coprocessor_base;
  coprocessors->enabled_stored = 0;
  coprocessors->saved_reserved = 0;
  coprocessors->aligned_save_area = (void *)(coprocessor_base + 16);
  /* The linked GCC TLS image is empty. The firmware still calls ROM memcpy
     with length zero before constructing the initial interrupt frame. */
  memcpy((void *)coprocessor_base,(const void *)0x3c04826c,0);
  volatile XtensaExceptionFrame *frame = (XtensaExceptionFrame *)(coprocessor_base - 192);
  memset((void *)frame,0,192);
  frame->exit_dispatch = (unsigned int)(uintptr_t)_xt_user_exit;
  frame->a[1] = coprocessor_base;
  frame->a[0] = 0;
  frame->pc = (unsigned int)(uintptr_t)entry;
  frame->a[6] = (unsigned int)argument;
  frame->ps = 0x50030; /* UM | EXCM | WOE | CALLINC(1); RFE clears EXCM. */
  frame->thread_pointer = coprocessor_base - 0x815c;
  return (unsigned char *)frame;
}

/* Native entry: 0x40386950. */
/* Original function-byte SHA-256:
 * bbd76539fc99c9e2e6e301e83a4f62bd4ccb650a1e4c8abd2dcbbde6ef9175b7. */
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

/* Native entry: 0x40386974. */
/* Original function-byte SHA-256:
 * 13925ffa0cf37812ccbf08beb48544bf387b916fdd81797acef2dddec389f666. */
/*
 * Raise this CPU's interrupt level to 3 and acquire a recursive portMUX.
 * lock: initialized, aligned, shared 8-byte owner/count object; must be non-NULL.
 * timeout_cycles: 0 makes one CAS attempt; -1 retries indefinitely. All other
 * values use an unsigned, wrapping CCOUNT delta and retry while delta <= timeout.
 * A failed first attempt samples CCOUNT even for -1; a successful first attempt
 * or timeout 0 does not sample it. Failed attempts never sleep or yield.
 * Returns 1 on acquisition, leaving the outer interrupt mask in force, or 0 on
 * timeout after restoring the caller's interrupt level. The device image's
 * compare-and-set helper can also report a busy external-RAM CAS guard.
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

/* Native entry: 0x40386a7c. */
/* Original function-byte SHA-256:
 * cbca0d41ecdb8d3f6f354d3c057201344ca6c4d8784841d11ebf5a4db154fc58. */
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

/* Native entry: 0x40386b30. */
/* Original function-byte SHA-256:
 * f5fa307307266d3cfd8ece88c8b1e57b977358a30732d727b12e6d30dcff0763. */
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

/* Native entry: 0x40386c98. */
/* Original function-byte SHA-256:
 * 313adffc32f457e093eb6b93a66a07b80f920176c6da53766f591883ea048131. */
/*
 * Returns: Eventually returns to the yielded task through the dispatcher solicited-frame RETW
 *   path.
 * Requirements/effects: Windowed task context with valid current TCB and spill/save areas. Builds
 *   the32-byte frame, saves PS/TLS, spills windows and dispatches. The native temporary PS
 *   is (THREADPTR & 0xfffbfff0) + 3, not a masked saved PS. Restores saved PS after
 *   window spilling, then RSIL3. Saves exit=0/current TCB frame, clears hardware and
 *   saved CPENABLE, and CALL0-transfers to the dispatcher with no local RETW. No
 *   callback/table validation or independent execution-deadline guarantee is added.
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
      "l32r\ta6, 0x40374fe8\n" /* literal: 0xfffbfff0 */
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
      "l32r\ta2, 0x40374fd8\n" /* literal: 0x3fcbdd1c */
      "rsr.prid\ta3\n"
      "extui\ta3, a3, 13, 1\n"
      "addx4\ta2, a3, a2\n"
      "l32i.n\ta2, a2, 0\n"
      "movi.n\ta3, 0\n"
      /* Publish exit=0 and this task's frame pointer. */
      "s32i.n\ta3, a1, 0\n"
      "s32i.n\ta1, a2, 0\n"
      "l32r\ta3, 0x40374fe0\n" /* literal: 0x3fcace18 */
      "l32i.n\ta3, a3, 0\n"
      "add.n\ta2, a2, a3\n"
      "l32i.n\ta2, a2, 0\n"
      "l32r\ta3, 0x40374fe4\n" /* literal: 0x3fcace14 */
      "l32i.n\ta3, a3, 0\n"
      "sub\ta2, a2, a3\n"
      "movi.n\ta3, -16\n"
      "and\ta2, a2, a3\n"
      /* Clear hardware and saved CPENABLE; dispatch rather than locally return. */
      "movi.n\ta3, 0\n"
      "wsr.cpenable\ta3\n"
      "beqz\ta2, .Lyield_40386cf9\n"
      "s16i\ta3, a2, 0\n"
      ".Lyield_40386cf9:\n"
      "call0\t_frxt_dispatch\n"
  );
}

/* Native entry: 0x40386cfc. */
/* Original function-byte SHA-256:
 * cf911e3620097adc38f5137288d2193a326d3c77dd558bac2e92d2842c682112. */
/*
 * Returns: RETW returns to its assembly interrupt-exit caller.
 * Requirements/effects: Outermost interrupt-switch path requires a live current TCB and aligned
 *   coprocessor header. Saves low16 CPENABLE to header.enabled, clears hardware CPENABLE and
 *   leaves the full-frame exit pointer unchanged. Computes the header using the native
 *   runtime-loaded stack-end and CPSA offsets; no local NULL check or task selection.
 */
void vPortYieldFromInt(void)
{
  __asm__ volatile (
      "entry\ta1, 16\n"
      "l32r\ta2, 0x40374fd8\n" /* literal: 0x3fcbdd1c */
      "rsr.prid\ta3\n"
      "extui\ta3, a3, 13, 1\n"
      "addx4\ta2, a3, a2\n"
      "l32i.n\ta2, a2, 0\n"
      "l32r\ta3, 0x40374fe0\n" /* literal: 0x3fcace18 */
      "l32i.n\ta3, a3, 0\n"
      "add.n\ta2, a2, a3\n"
      "l32i.n\ta2, a2, 0\n"
      "l32r\ta3, 0x40374fe4\n" /* literal: 0x3fcace14 */
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

/* Native entry: 0x40386da0. */
/* Original function-byte SHA-256:
 * 6439f2ce62556328ae08707154e91e8488df61e70709a32193d8e00363a2f030. */
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

/* Native entry: 0x40386db4. */
/* Original function-byte SHA-256:
 * 3f33f5f7961bdf6ddca9f4256d6ac1cc24ca5bdf74fcd5057cc49087cc3deebd. */
/*
 * buffer: Allocation accepted by heap_caps_free, or NULL, under its contract.
 * Returns no value. Always calls heap_caps_free with the unchanged pointer,
 * including NULL. No local admission check, wipe, caller-pointer clear, lock,
 * retry or double-free protection is added; allocator behavior is delegated.
 */
void vPortFree(void *buffer)

{
  heap_caps_free(buffer);
  return;
}

/* Native entry: 0x40386dc0. */
/* Original function-byte SHA-256:
 * dc5e3e33c8bcdaa24f759d0b731b6a49ece6716423cf2505ff17410e56eaf749. */
/*
 * pointer: TCB/list starting address to admit.
 * Returns: Raw byte-accessibility result for an internal-region address; zero otherwise.
 * Requirements/effects: Checks address membership without validating allocation size, alignment,
 *   ownership or lifetime.
 */
unsigned char xPortCheckValidTCBMem(void *pointer)

{
  unsigned int address = (unsigned int)pointer;
  if (address + 0x9ff02000U < 0x2000U ||
      address + 0xc0378000U < 0x758000U ||
      address + 0xb0000000U < 0x2000U) {
    return esp_ptr_byte_accessible(pointer);
  }
  return 0;
}

/* Native entry: 0x40386e04. */
/* Original function-byte SHA-256:
 * 6ba06d0f62de1bb079b5262c62381523ffc878221945170f8ca96e04a958710d. */
/*
 * pointer: Starting stack address to admit.
 * Returns: Result of byte-accessibility classification.
 * Requirements/effects: Device build permits mapped PSRAM stacks. No total-size or alignment
 *   validation is performed by this predicate.
 */
unsigned char xPortcheckValidStackMem(void *pointer)

{
  return esp_ptr_byte_accessible(pointer);
}
