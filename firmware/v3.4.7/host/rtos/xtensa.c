/* Medius v3.4.7 host — rtos/xtensa.c.
 * Recovered C and native assembly, grouped for source navigation.
 * Original entry addresses, firmware-byte hashes and function comments follow.
 */

#include "../include/types.h"

/* Native entry: 0x4037b980. */
/*
 * Medius v3.4.7 — host application; 0x4037b980.
 * Instruction-reviewed Xtensa assembly; C braces display the native entry.
 *
 * User-mode exception entry, entered with interrupted A0 in EXCSAVE1.
 * Routes level-1 interrupts to _xt_lowint1, causes >=32 to the coprocessor path,
 * cause 5 to the alloca path and cause 1 to the syscall path. Other causes build
 * a 192-byte frame on the interrupted stack, save context/cause/fault address,
 * and call the per-core exception handler with that frame. Restores the saved
 * state and RFE resumes the interrupted PC; there is no ordinary C return.
 *
 * Calls: _xt_syscall_exc, _xt_coproc_exc, _xt_context_save, _xt_alloca_exc, _xt_context_restore.
 *
 * Called by: _UserExceptionVector.
 *
 * Indirect call: registered exception handler selected by cause and CPU.
 *
 * Original function-byte SHA-256:
 * 8f49fb5efc2779f66602847511b1e2dce0db456ed146f724a8e9b31fe01694ce.
 */

/* The exception table contains one 4-byte handler pointer per cause/core:
   entry = table[(EXCCAUSE * 2) + core_id]. CALLX4 passes frame pointer in A6,
   corresponding to the C handler's A2 after register-window entry. The stack
   stays on the interrupted task, unlike the level-1 RTOS interrupt entry.
   Backtrace spill words copy interrupted A0/A1 and synthesize CALL4 link bits.
   No exception pre-hook branch is compiled into this body. The original Ghidra
   range hash includes mismerged adjacent paths; the corrected 154-byte body
   has its own span hash below. Branches before this entry are SDK jump veneers,
   not overlapping instructions to execute as ordinary C function calls.
   Reference: ESP-IDF v5.4.4 components/xtensa/xtensa_vectors.S.
   Corrected assembly span: 0x4037b980..0x4037ba19; SHA-256:
   aadb3a56a25d2a7f112f6cdc7e0343f9ab8d13290ce916bfb5ab0887c56fe865. */

/* These braces display the original assembly body, not a C wrapper
   to compile with an additional compiler-generated prologue. */
__attribute__((noreturn))

/*
 * Returns: Architectural RFE resumes interrupted execution; there is no C return.
 * Requirements/effects: Exception-vector entry has interrupted A0 in EXCSAVE1 and a valid
 *   interrupted stack. Builds a192-byte frame, routes special causes or calls the per-core
 *   exception-table entry; hardware privilege/exception state must match the entry contract.
 */

void _xt_user_exc(void)
{
  __asm__ volatile (
      /* Separate interrupt, coprocessor, alloca and syscall paths. */
      "rsr.exccause\ta0\n"
      "bnei\ta0, 4, .Luser_exc_4037b989\n"
      "j\t_xt_lowint1\n"
      ".Luser_exc_4037b989:\n"
      "bgeui\ta0, 32, 0x4037b97c\n"
      "beqi\ta0, 5, 0x4037b970\n"
      "beqi\ta0, 1, 0x4037b978\n"
      /* Build the generic exception frame on the interrupted stack. */
      "or\ta0, a1, a1\n"
      "addmi\ta1, a1, 0xffffff00\n"
      "addi\ta1, a1, 64\n"
      "s32i\ta0, a1, 16\n"
      "s32e\ta0, a1, -12\n"
      "rsr.ps\ta0\n"
      "s32i.n\ta0, a1, 8\n"
      "rsr.epc1\ta0\n"
      "s32i.n\ta0, a1, 4\n"
      "rsr.excsave1\ta0\n"
      "s32i.n\ta0, a1, 12\n"
      "s32e\ta0, a1, -16\n"
      "s32i\ta12, a1, 60\n"
      "s32i\ta13, a1, 64\n"
      "call0\t_xt_context_save\n"
      "rsr.exccause\ta0\n"
      "s32i\ta0, a1, 80\n"
      "rsr.excvaddr\ta0\n"
      "s32i\ta0, a1, 84\n"
      "l32r\ta0, 0x4037496c\n" /* literal: 0x00040024 */
      "wsr.ps\ta0\n"
      "l32i.n\ta3, a1, 12\n"
      "s32e\ta3, a1, -16\n"
      "l32i.n\ta3, a1, 16\n"
      "s32e\ta3, a1, -12\n"
      "rsr.epc1\ta0\n"
      "l32r\ta5, 0x40374970\n" /* literal: 0xc0000000 */
      "rsync\n"
      "or\ta0, a0, a5\n"
      "addx2\ta0, a5, a0\n"
      "rsr.exccause\ta2\n"
      "rsr.exccause\ta2\n"
      "l32r\ta3, 0x40374974\n" /* literal: 0x3fc9e060 */
      "rsr.prid\ta4\n"
      "extui\ta4, a4, 13, 1\n"
      "addx2\ta2, a2, a4\n"
      "addx4\ta4, a2, a3\n"
      "l32i.n\ta4, a4, 0\n"
      "mov.n\ta6, a1\n"
      "callx4\ta4\n"
      /* Restore context and return directly with RFE. */
      "call0\t_xt_context_restore\n"
      "l32i.n\ta0, a1, 8\n"
      "wsr.ps\ta0\n"
      "l32i.n\ta0, a1, 4\n"
      "wsr.epc1\ta0\n"
      "l32i.n\ta0, a1, 12\n"
      "l32i.n\ta1, a1, 16\n"
      "rsync\n"
      "rfe\n"
  );
  __builtin_unreachable();
}

/* Native entry: 0x4037ba1c. */
/*
 * Medius v3.4.7 — host application; 0x4037ba1c.
 * Instruction-reviewed Xtensa assembly; C braces display the native entry.
 *
 * Assembly exception-return entry using the existing frame at A1. Restores PS, EPC1, A0 and A1, synchronizes, then executes RFE to resume the saved PC with exception mode cleared. This is not an ordinary C call/return.
 *
 * Called by: _xt_coproc_exc.
 *
 * Original function-byte SHA-256:
 * fb89301adde7c58df10a079ddd2b4d28cfd650f96fc30439fbc49090ac79184e.
 */

/* Assembly exception-return entry using the existing frame at A1. Restores PS, EPC1, A0 and A1, synchronizes, then executes RFE to resume the saved PC with exception mode cleared. This is not an ordinary C call/return.
   Reference: ESP-IDF v5.4.4 components/xtensa/xtensa_vectors.S _xt_user_exit. */

__attribute__((noreturn))

/*
 * Returns: Resumes the saved EPC1 through RFE; no C return.
 * Requirements/effects: Native assembly entry with A1 already pointing to the exception frame: PC
 *   at +4, PS +8, A0 +12, A1 +16. Restores status/PC/registers, synchronizes and clears exception
 *   mode via RFE. Not callable with an ordinary C stack.
 */

void _xt_user_exit(void)
{
  /* Assembly entry: A1 already points to the interrupt frame. No C call or
     ENTRY prologue exists in the firmware; these braces document its body. */
  __asm__ volatile (
      "l32i.n a0,a1,8\n"
      "wsr a0,PS\n"
      "l32i.n a0,a1,4\n"
      "wsr a0,EPC1\n"
      "l32i.n a0,a1,12\n"
      "l32i.n a1,a1,16\n"
      "rsync\n"
      "rfe\n");
  __builtin_unreachable();
}

/* Native entry: 0x4037ba30. */
/*
 * Medius v3.4.7 — host application; 0x4037ba30.
 * Instruction-reviewed Xtensa assembly; C braces display the native entry.
 *
 * Assembly syscall exception entry. Allocates a full 192-byte scratch frame
 * and saves context to spill windows. Advances EPC1 by the three-byte SYSCALL;
 * its loop-end branch can select LBEG. Restores context, removes the frame,
 * returns A2 unchanged for syscall 0 or sets A2=-1 for any other number, then RFE.
 * This is an exception entry, not a C function returning an undefined value.
 *
 * Calls: _xt_context_save, _xt_context_restore.
 *
 * Called by: _xt_user_exc.
 *
 * Original function-byte SHA-256:
 * ba4044b42056f5627627a2a3494e7c4e11f38449289f72d2115418a3ef50fabc.
 */

/* For a syscall whose next PC equals LEND and whose LCOUNT is nonzero,
   the code writes LCOUNT-1 and selects LBEG before calling _xt_context_restore.
   That restore then reloads LCOUNT from the earlier saved frame+0x60; the
   decremented count is not written into that frame. Preserve this ordering;
   do not rewrite the dump as though a saved counter update occurred.
   The syscall number is the interrupted A2 reloaded by context restoration.
   MOVNEZ changes nonzero numbers to -1; syscall 0 retains zero. EXCSAVE1
   restores interrupted A0, and RFE clears exception mode.
   Reference: ESP-IDF v5.4.4 components/xtensa/xtensa_vectors.S.
   Corrected assembly span: 0x4037ba30..0x4037ba6f; SHA-256:
   ba4044b42056f5627627a2a3494e7c4e11f38449289f72d2115418a3ef50fabc. */

/* These braces display the original assembly body, not a C wrapper
   to compile with an additional compiler-generated prologue. */
__attribute__((noreturn))

/*
 * Returns: RFE resumes at updated EPC1; interrupted A2 remains0 for syscall0 or becomes -1
 *   otherwise.
 * Requirements/effects: Architectural syscall entry requires valid interrupted stack/state. Uses
 *   a192-byte scratch frame; loop-count decrement precedes restoration from the saved frame and is
 *   not written back into that frame.
 */

void _xt_syscall_exc(void)
{
  __asm__ volatile (
      /* Allocate a full scratch exception frame and spill interrupted context. */
      "addmi\ta1, a1, 0xffffff00\n"
      "addi\ta1, a1, 64\n"
      "s32i\ta12, a1, 60\n"
      "s32i\ta13, a1, 64\n"
      "call0\t_xt_context_save\n"
      /* Skip SYSCALL, with the compiled zero-overhead-loop branch. */
      "rsr.epc1\ta2\n"
      "addi\ta3, a2, 3\n"
      "rsr.lend\ta0\n"
      "bne\ta3, a0, .Lsyscall_4037ba59\n"
      "rsr.lcount\ta0\n"
      "beqz\ta0, .Lsyscall_4037ba59\n"
      "addi.n\ta0, a0, -1\n"
      "rsr.lbeg\ta3\n"
      "wsr.lcount\ta0\n"
      ".Lsyscall_4037ba59:\n"
      "wsr.epc1\ta3\n"
      /* Restore context, then translate a nonzero syscall number to -1. */
      "call0\t_xt_context_restore\n"
      "addmi\ta1, a1, 0x100\n"
      "addi\ta1, a1, -64\n"
      "movi.n\ta0, -1\n"
      "movnez\ta2, a0, a2\n"
      "rsr.excsave1\ta0\n"
      "rfe\n"
  );
  __builtin_unreachable();
}

/* Native entry: 0x4037ba74. */
/*
 * Medius v3.4.7 — host application; 0x4037ba74.
 * Instruction-reviewed Xtensa assembly; C braces display the native entry.
 *
 * Three-byte jump veneer for the coprocessor handler's completion path.
 * This is SDK local label .L_goto_done, not a C-callable function. A1 must still
 * point to the handler's existing exception frame. The destination restores
 * A2-A7/A15 and transfers to _xt_user_exit; it does not return to a C caller.
 *
 * Called by: _xt_coproc_exc.
 *
 * Original function-byte SHA-256:
 * 0f4dd4d10d9a59cbdd6bf5067013d39e8a31e4b74a5d27c41d3ef6e74d3e9a52.
 */

/* Analyst name for a local SDK jump label. The previous decompiler output
   followed adjacent routines and invented loops that do not belong to these
   three bytes. The absolute jump below is the complete original body.
   Reference: ESP-IDF v5.4.4 components/xtensa/xtensa_vectors.S.
   Corrected assembly span: 0x4037ba74..0x4037ba76; SHA-256:
   0f4dd4d10d9a59cbdd6bf5067013d39e8a31e4b74a5d27c41d3ef6e74d3e9a52. */

/* The braces display the original assembly body; this recovered export
   is not a C wrapper to compile with an additional compiler prologue. */
__attribute__((noreturn))

/*
 * Returns: Tail jump to the coprocessor completion path and then architectural user exit; no C
 *   return.
 * Requirements/effects: A1 must still address the existing exception frame. Preserves the minimal
 *   frame used by the lazy coprocessor handler; the destination restores interrupted registers.
 */

void xtensa_coprocessor_return_trampoline(void)
{
  __asm__ volatile (
      "j\t0x4037bce0\n"
  );
  __builtin_unreachable();
}

/* Native entry: 0x4037ba78. */
/*
 * Medius v3.4.7 — host application; 0x4037ba78.
 * Instruction-reviewed Xtensa assembly; C braces display the native entry.
 *
 * Lazy coprocessor exception handling for CP0 (FPU) and CP3 (vector/AI).
 * Saves a minimal 192-byte exception frame, pins the running task to this core,
 * enables the faulting CP, and switches its per-core owner under a spinlock.
 * Saves the old owner's active registers, then restores the new owner's saved
 * registers when present. Resumes the faulting instruction through _xt_user_exit.
 * A missing task save area takes the coprocessor panic path; ISR use is rejected.
 *
 * Calls: _xt_user_exit, xtensa_coprocessor_return_trampoline, xtensa_coprocessor_panic, _frxt_task_coproc_state, _frxt_coproc_exc_hook, _xt_coproc_restorecs.
 *
 * Called by: _xt_user_exc.
 *
 * Original function-byte SHA-256:
 * 1cf943d819905f986e95a97b0ea7917dac4d586fe1ae22f987019802139ddb2a.
 */

/* Assembly exception entry, not a six-parameter C function. The faulting
   thread's A0 is already in EXCSAVE1. EXCCAUSE-32 selects the CP index.
   CPENABLE is enabled before touching CP registers. The owner table contains
   four pointers per core and its lock uses SCOMPARE1/S32C1I with raw PRID.
   Equal owners skip the save/restore. No old owner or an inactive old CP skips
   saving. Saving clears old.enabled, sets old.stored, and uses aligned_save_area
   plus offsets {0,72,72,80}. Restoring clears new.stored. A fresh, unsaved CP
   is left as-is unless a callee-saved flag requests the separate restore helper.
   CP0 stores F0-F15 at 0..60, FCR at 64, FSR at 68 (72 bytes).
   CP3 stores scalar ACCX/QACC/SAR_BYTE/FFT/UA state at 0..68 and eight
   128-bit Q registers at 80..192 (208 bytes, 16-byte aligned).
   Frame A13/A14 are additionally preserved around the callee-saved helper.
   Instruction comparison against the original image establishes this sequence;
   no physical vector/FPU interrupt behavior has been measured.
   The original header hash covers Ghidra's incomplete/discontiguous ranges;
   the corrected contiguous handler span has its own hash below.
   Reference: ESP-IDF v5.4.4 components/xtensa/xtensa_vectors.S.
   Corrected assembly span: 0x4037ba78..0x4037bd11; SHA-256:
   300384e1ac1740330c8845f23a2c44b60dcb5109c40a62f71bae12eff601f62b. */

/* The braces display the original assembly body; this recovered export
   is not a C wrapper to compile with an additional compiler prologue. */
__attribute__((noreturn))

/*
 * Returns: Resumes the faulting instruction through _xt_user_exit, or transfers to coprocessor
 *   panic.
 * Requirements/effects: Architectural disabled-CP exception with EXCCAUSE-32 selecting CP0/CP3.
 *   Requires a task save area and valid exception/window state; rejects ISR use. Pins the task,
 *   switches per-core ownership under a spinlock and saves/restores complete selected payloads.
 */

void _xt_coproc_exc(void)
{
  __asm__ volatile (
      /* Allocate and populate the minimal exception frame. */
      "or\ta0, a1, a1\n"
      "addmi\ta1, a1, 0xffffff00\n"
      "addi\ta1, a1, 64\n"
      "s32i\ta0, a1, 16\n"
      "s32e\ta0, a1, -12\n"
      "rsr.ps\ta0\n"
      "s32i.n\ta0, a1, 8\n"
      "rsr.epc1\ta0\n"
      "s32i.n\ta0, a1, 4\n"
      "rsr.excsave1\ta0\n"
      "s32i.n\ta0, a1, 12\n"
      "s32e\ta0, a1, -16\n"
      "l32r\ta0, 0x40374978\n" /* literal: 0x4037ba1c */
      "s32i.n\ta0, a1, 0\n"
      /* EXCCAUSE-32 is the disabled coprocessor index. */
      "rsr.exccause\ta0\n"
      "s32i.n\ta5, a1, 32\n"
      "addi\ta5, a0, -32\n"
      "s32i.n\ta2, a1, 20\n"
      "s32i.n\ta3, a1, 24\n"
      "s32i.n\ta4, a1, 28\n"
      "s32i\ta6, a1, 36\n"
      "s32i.n\ta7, a1, 40\n"
      "s32i\ta15, a1, 72\n"
      /* Pin the task, then obtain its save header through A15. */
      "call0\t_frxt_coproc_exc_hook\n"
      "call0\t_frxt_task_coproc_state\n"
      "beqz\ta15, 0x4037ba70\n"
      /* Enable the selected coprocessor and select this core's owner array. */
      "l32r\ta0, 0x4037497c\n" /* literal: 0x3c050d00 */
      "rsr.cpenable\ta4\n"
      "addx4\ta0, a5, a0\n"
      "l32i.n\ta0, a0, 0\n"
      "extui\ta2, a0, 0, 16\n"
      "or\ta4, a4, a2\n"
      "wsr.cpenable\ta4\n"
      "rsr.prid\ta3\n"
      "extui\ta3, a3, 13, 1\n"
      "movi.n\ta2, 16\n"
      "mull\ta2, a2, a3\n"
      "l32r\ta3, 0x40374980\n" /* literal: 0x3fc9e260 */
      "add.n\ta3, a3, a2\n"
      /* Take the global owner-table spinlock with compare-and-swap. */
      "l32r\ta6, 0x40374984\n" /* literal: 0x3fc9e280 */
      ".Lhandler_4037bae4:\n"
      "movi.n\ta7, 0\n"
      "wsr.scompare1\ta7\n"
      "rsync\n"
      "rsr.prid\ta7\n"
      "s32c1i\ta7, a6, 0\n"
      "bnez\ta7, .Lhandler_4037bae4\n"
      /* Publish the new owner and synchronize CPENABLE before unlocking. */
      "addx4\ta3, a5, a3\n"
      "l32i.n\ta2, a3, 0\n"
      "s32i.n\ta15, a3, 0\n"
      "rsync\n"
      "l32r\ta6, 0x40374984\n" /* literal: 0x3fc9e280 */
      "movi.n\ta7, 0\n"
      "s32i.n\ta7, a6, 0\n"
      /* The existing owner can keep the live registers. */
      "bne\ta15, a2, .Lcp_switch_owner_4037ba78\n"
      "j\txtensa_coprocessor_return_trampoline\n"
      ".Lcp_switch_owner_4037ba78:\n"
      "beqz\ta2, .Lcp_check_new_4037ba78\n"
      "l16ui\ta4, a2, 0\n"
      "bany\ta4, a0, .Lcp_save_old_4037ba78\n"
      "j\t.Lcp_check_new_4037ba78\n"
      /* Move the active old owner to stored state and find its payload. */
      ".Lcp_save_old_4037ba78:\n"
      "l32r\ta5, 0x40374988\n" /* literal: 0x3c050ce0 */
      "xor\ta4, a4, a0\n"
      "s16i\ta4, a2, 0\n"
      "extui\ta4, a0, 16, 5\n"
      "addx4\ta5, a4, a5\n"
      "l16ui\ta4, a2, 2\n"
      "l32i.n\ta5, a5, 0\n"
      "or\ta4, a4, a0\n"
      "s16i\ta4, a2, 2\n"
      "l32i.n\ta2, a2, 8\n"
      "extui\ta3, a0, 16, 5\n"
      "add.n\ta2, a2, a5\n"
      /* Save CP0 FPU state, or branch to the CP3 vector state. */
      "bnez.n\ta3, .Lcp_save_vector_4037ba78\n"
      "ssi\tf0, a2, 0\n"
      "ssi\tf1, a2, 4\n"
      "ssi\tf2, a2, 8\n"
      "ssi\tf3, a2, 12\n"
      "ssi\tf4, a2, 16\n"
      "ssi\tf5, a2, 20\n"
      "ssi\tf6, a2, 24\n"
      "ssi\tf7, a2, 28\n"
      "ssi\tf8, a2, 32\n"
      "ssi\tf9, a2, 36\n"
      "ssi\tf10, a2, 40\n"
      "ssi\tf11, a2, 44\n"
      "ssi\tf12, a2, 48\n"
      "ssi\tf13, a2, 52\n"
      "ssi\tf14, a2, 56\n"
      "ssi\tf15, a2, 60\n"
      "rur.fcr\ta3\n"
      "s32i\ta3, a2, 64\n"
      "rur.fsr\ta3\n"
      "s32i\ta3, a2, 68\n"
      "j\t.Lcp_check_new_4037ba78\n"
      /* Unexecuted linker fill/relaxation bytes between labeled blocks. */
      ".byte 0x00,0x00\n"
      /* CP3 scalar user registers; these are not LBEG/LEND/LCOUNT. */
      ".Lcp_save_vector_4037ba78:\n"
      "bnei\ta3, 3, .Lcp_check_new_4037ba78\n"
      "rur.accx_0\ta3\n"
      "s32i.n\ta3, a2, 0\n"
      "rur.accx_1\ta3\n"
      "s32i.n\ta3, a2, 4\n"
      "rur.qacc_h_0\ta3\n"
      "s32i.n\ta3, a2, 8\n"
      "rur.qacc_h_1\ta3\n"
      "s32i.n\ta3, a2, 12\n"
      "rur.qacc_h_2\ta3\n"
      "s32i.n\ta3, a2, 16\n"
      "rur.qacc_h_3\ta3\n"
      "s32i.n\ta3, a2, 20\n"
      "rur.qacc_h_4\ta3\n"
      "s32i.n\ta3, a2, 24\n"
      "rur.qacc_l_0\ta3\n"
      "s32i.n\ta3, a2, 28\n"
      "rur.qacc_l_1\ta3\n"
      "s32i.n\ta3, a2, 32\n"
      "rur.qacc_l_2\ta3\n"
      "s32i.n\ta3, a2, 36\n"
      "rur.qacc_l_3\ta3\n"
      "s32i.n\ta3, a2, 40\n"
      "rur.qacc_l_4\ta3\n"
      "s32i.n\ta3, a2, 44\n"
      "rur.sar_byte\ta3\n"
      "s32i.n\ta3, a2, 48\n"
      "rur.fft_bit_width\ta3\n"
      "s32i.n\ta3, a2, 52\n"
      "rur.ua_state_0\ta3\n"
      "s32i.n\ta3, a2, 56\n"
      "rur.ua_state_1\ta3\n"
      "s32i.n\ta3, a2, 60\n"
      "rur.ua_state_2\ta3\n"
      "s32i\ta3, a2, 64\n"
      "rur.ua_state_3\ta3\n"
      "s32i\ta3, a2, 68\n"
      /* CP3 Q0..Q7, with padding between scalar and vector registers. */
      "st.qr\tq0, a2, 80\n"
      "st.qr\tq1, a2, 96\n"
      "st.qr\tq2, a2, 112\n"
      "addmi\ta2, a2, 0x100\n"
      "addi\ta2, a2, -128\n"
      "st.qr\tq3, a2, 0\n"
      "st.qr\tq4, a2, 16\n"
      "st.qr\tq5, a2, 32\n"
      "st.qr\tq6, a2, 48\n"
      "st.qr\tq7, a2, 64\n"
      "j\t.Lcp_check_new_4037ba78\n"
      /* Check whether the new owner has full saved state. */
      ".Lcp_check_new_4037ba78:\n"
      "beqz\ta15, .Lcp_done_4037ba78\n"
      "l16ui\ta3, a15, 2\n"
      "l32r\ta4, 0x40374988\n" /* literal: 0x3c050ce0 */
      "bany\ta3, a0, .Lcp_restore_full_4037ba78\n"
      "j\t.Lcp_check_callee_saved_4037ba78\n"
      ".Lcp_restore_full_4037ba78:\n"
      "xor\ta3, a3, a0\n"
      "s16i\ta3, a15, 2\n"
      "extui\ta3, a0, 16, 5\n"
      "addx4\ta4, a3, a4\n"
      "l32i.n\ta4, a4, 0\n"
      "l32i.n\ta5, a15, 8\n"
      "add.n\ta2, a4, a5\n"
      /* Restore CP0 FPU state, or branch to the CP3 vector state. */
      "bnez.n\ta3, .Lcp_restore_vector_4037ba78\n"
      "lsi\tf0, a2, 0\n"
      "lsi\tf1, a2, 4\n"
      "lsi\tf2, a2, 8\n"
      "lsi\tf3, a2, 12\n"
      "lsi\tf4, a2, 16\n"
      "lsi\tf5, a2, 20\n"
      "lsi\tf6, a2, 24\n"
      "lsi\tf7, a2, 28\n"
      "lsi\tf8, a2, 32\n"
      "lsi\tf9, a2, 36\n"
      "lsi\tf10, a2, 40\n"
      "lsi\tf11, a2, 44\n"
      "lsi\tf12, a2, 48\n"
      "lsi\tf13, a2, 52\n"
      "lsi\tf14, a2, 56\n"
      "lsi\tf15, a2, 60\n"
      "l32i\ta3, a2, 64\n"
      "wur.fcr\ta3\n"
      "l32i\ta3, a2, 68\n"
      "wur.fsr\ta3\n"
      "j\t.Lcp_done_4037ba78\n"
      /* Unexecuted linker fill/relaxation bytes between labeled blocks. */
      ".byte 0x00,0x00\n"
      /* Restore CP3 scalar and 128-bit vector registers. */
      ".Lcp_restore_vector_4037ba78:\n"
      "bnei\ta3, 3, .Lcp_done_4037ba78\n"
      "l32i.n\ta3, a2, 0\n"
      "wur.accx_0\ta3\n"
      "l32i.n\ta3, a2, 4\n"
      "wur.accx_1\ta3\n"
      "l32i.n\ta3, a2, 8\n"
      "wur.qacc_h_0\ta3\n"
      "l32i.n\ta3, a2, 12\n"
      "wur.qacc_h_1\ta3\n"
      "l32i.n\ta3, a2, 16\n"
      "wur.qacc_h_2\ta3\n"
      "l32i.n\ta3, a2, 20\n"
      "wur.qacc_h_3\ta3\n"
      "l32i.n\ta3, a2, 24\n"
      "wur.qacc_h_4\ta3\n"
      "l32i.n\ta3, a2, 28\n"
      "wur.qacc_l_0\ta3\n"
      "l32i.n\ta3, a2, 32\n"
      "wur.qacc_l_1\ta3\n"
      "l32i.n\ta3, a2, 36\n"
      "wur.qacc_l_2\ta3\n"
      "l32i.n\ta3, a2, 40\n"
      "wur.qacc_l_3\ta3\n"
      "l32i.n\ta3, a2, 44\n"
      "wur.qacc_l_4\ta3\n"
      "l32i.n\ta3, a2, 48\n"
      "wur.sar_byte\ta3\n"
      "l32i.n\ta3, a2, 52\n"
      "wur.fft_bit_width\ta3\n"
      "l32i.n\ta3, a2, 56\n"
      "wur.ua_state_0\ta3\n"
      "l32i.n\ta3, a2, 60\n"
      "wur.ua_state_1\ta3\n"
      "l32i\ta3, a2, 64\n"
      "wur.ua_state_2\ta3\n"
      "l32i\ta3, a2, 68\n"
      "wur.ua_state_3\ta3\n"
      "ld.qr\tq0, a2, 80\n"
      "ld.qr\tq1, a2, 96\n"
      "ld.qr\tq2, a2, 112\n"
      "addmi\ta2, a2, 0x100\n"
      "addi\ta2, a2, -128\n"
      "ld.qr\tq3, a2, 0\n"
      "ld.qr\tq4, a2, 16\n"
      "ld.qr\tq5, a2, 32\n"
      "ld.qr\tq6, a2, 48\n"
      "ld.qr\tq7, a2, 64\n"
      "j\t.Lcp_done_4037ba78\n"
      /* Restore interrupted integer registers and resume through RFE. */
      ".Lcp_done_4037ba78:\n"
      "l32i\ta15, a1, 72\n"
      "l32i.n\ta6, a1, 36\n"
      "l32i.n\ta7, a1, 40\n"
      "l32i.n\ta5, a1, 32\n"
      "l32i.n\ta4, a1, 28\n"
      "l32i\ta3, a1, 24\n"
      "l32i\ta2, a1, 20\n"
      "call0\t_xt_user_exit\n"
      /* Only the requested callee-saved mask is handed to the helper. */
      ".Lcp_check_callee_saved_4037ba78:\n"
      "l16ui\ta2, a15, 4\n"
      "bnone\ta2, a0, .Lcp_done_4037ba78\n"
      "and\ta2, a2, a0\n"
      "extui\ta2, a2, 0, 8\n"
      "s32i\ta13, a1, 64\n"
      "s32i\ta14, a1, 68\n"
      "call0\t_xt_coproc_restorecs\n"
      "l32i\ta13, a1, 64\n"
      "l32i\ta14, a1, 68\n"
      "j\t.Lcp_done_4037ba78\n"
  );
  __builtin_unreachable();
}

/* Native entry: 0x4037bd15. */
/*
 * Medius v3.4.7 — host application; 0x4037bd15.
 * Instruction-reviewed Xtensa assembly; C braces display the native entry.
 *
 * Coprocessor exception failure entry (SDK local .L_xt_coproc_invalid).
 * Sets EXCCAUSE to 4, the software panic reason PANIC_RSN_COPROCEXCEPTION,
 * then transfers to _xt_panic with CALL0. Never returns or falls through into
 * the following _xt_lowint1 interrupt entry.
 *
 * Calls: _xt_panic. The separate level-1 entry calls
 * _frxt_int_enter and _frxt_int_exit.
 *
 * Called by: _xt_coproc_exc.
 *
 * Indirect call in the separate level-1 entry: registered interrupt handler.
 *
 * Original function-byte SHA-256:
 * 3e8f202f6c520ec0a34d9c3867334afc034b4b4383373ba713e834ffd46e5ba7.
 */

/* Analyst name for the SDK local failure label. The prior Ghidra body
   incorrectly merged this 11-byte nonreturning entry with the following level-1
   dispatcher and then followed its RTOS exit into unrelated level-2 code.
   The original header hash still describes the original Ghidra ranges, not
   either corrected entry alone. Both corrected spans are identified below.
   Reference: ESP-IDF v5.4.4 components/xtensa/xtensa_vectors.S.
   Corrected assembly span: 0x4037bd15..0x4037bd1f; SHA-256:
   3845f680298608912a27f26c95be9e0fb3c4a34b7e99955288f494b08690c1fb. */

/* The braces display the original assembly body; this recovered export
   is not a C wrapper to compile with an additional compiler prologue. */
__attribute__((noreturn))

/*
 * Returns: Never returns: sets software coprocessor panic reason and CALL0-transfers to the panic
 *   entry.
 * Requirements/effects: Architectural exception failure path. EXCCAUSE is set to4; the neighboring
 *   level1 interrupt entry below is a separate routine, not fall-through code.
 */

void xtensa_coprocessor_panic(void)
{
  __asm__ volatile (
      "movi.n\ta0, 4\n"
      "wsr.exccause\ta0\n"
      "or\ta1, a1, a1\n"
      "call0\tFUN_4037d38c\n" /* SDK _xt_panic; never returns */
  );
  __builtin_unreachable();
}

/* Level-1 CPU interrupt entry using the interrupted stack and saved A0.
   Allocates a 192-byte frame, saves PS/EPC1/A0/A1, records _xt_user_exit,
   enters the RTOS interrupt stack, and sets PS=0x40021. Repeatedly dispatches
   enabled pending interrupts masked by 0x637ff, highest interrupt number first.
   Clears each selected software/edge interrupt and calls its registered ISR
   with the table's argument. Transfers to RTOS interrupt exit when none remain.
   The dispatch table is indexed by (interrupt_number * 2 + core_id), 8 bytes
   per entry. A level-triggered source must be cleared by its peripheral ISR. */

/* Assembly-only entry, not a normal C function. EXCSAVE1 first holds
   interrupted A0 and is then reused to point to this exception frame. CALL0 to
   the RTOS interrupt entry saves the remaining registers and manages nesting.
   This body copies A0/A1 into the interrupt-stack spill area for backtraces,
   encodes a CALL4 return-address size, and uses CALLX4 for the registered ISR.
   The INTENABLE/pending intersection is reread after every ISR, not cached.
   CALL0 to RTOS interrupt exit is a nonreturning transfer, so this routine does
   not execute the neighboring level-2 interrupt code printed by old Ghidra.
   Reference: ESP-IDF v5.4.4 components/xtensa/xtensa_vectors.S.
   Corrected assembly span: 0x4037bd20..0x4037bdb9; SHA-256:
   5c64a654bb15bcafbf64ccc52080d23170a8f0b7ed69cf4800064566054c1886. */

/* The braces display the original assembly body; this recovered export
   is not a C wrapper to compile with an additional compiler prologue. */
__attribute__((noreturn))
/*
 * Returns: Transfers to RTOS interrupt exit; the saved exit routine later performs architectural
 *   return.
 * Requirements/effects: Level1 vector preserves interrupted A0 in EXCSAVE1 and supplies valid
 *   interrupted stack/state. Builds a192-byte frame, dispatches highest enabled pending source in
 *   mask0x637ff and rereads pending/enables after every ISR. Peripheral-level flags remain the ISR
 *   responsibility.
 */

void _xt_lowint1(void)
{
  __asm__ volatile (
      /* Build the exception frame before entering the RTOS interrupt stack. */
      "or\ta0, a1, a1\n"
      "addmi\ta1, a1, 0xffffff00\n"
      "addi\ta1, a1, 64\n"
      "s32i\ta0, a1, 16\n"
      "rsr.ps\ta0\n"
      "s32i\ta0, a1, 8\n"
      "rsr.epc1\ta0\n"
      "s32i.n\ta0, a1, 4\n"
      "rsr.excsave1\ta0\n"
      "s32i.n\ta0, a1, 12\n"
      "l32r\ta0, 0x40374978\n" /* literal: 0x4037ba1c */
      "s32i.n\ta0, a1, 0\n"
      "mov.n\ta0, a1\n"
      "wsr.excsave1\ta0\n"
      "call0\t_frxt_int_enter\n" /* SDK _frxt_int_enter */
      "l32r\ta0, 0x4037498c\n" /* literal: 0x00040021 */
      "wsr.ps\ta0\n"
      "rsync\n"
      /* Reread enabled/pending level-1 sources for every dispatch. */
      ".Llowint1_4037bd52:\n"
      "rsr.intenable\ta2\n"
      "rsr.interrupt\ta3\n"
      "l32r\ta4, 0x40374990\n" /* literal: 0x000637ff */
      "and\ta2, a2, a3\n"
      "and\ta2, a2, a4\n"
      "beqz\ta2, .Llowint1_4037bdb4\n"
      "rsr.excsave1\ta0\n"
      "l32i.n\ta3, a0, 12\n"
      "s32e\ta3, a1, -16\n"
      "l32i.n\ta3, a0, 16\n"
      "s32e\ta3, a1, -12\n"
      "rsr.epc1\ta0\n"
      "l32r\ta4, 0x40374970\n" /* literal: 0xc0000000 */
      "or\ta0, a0, a4\n"
      "addx2\ta0, a4, a0\n"
      /* Find the highest numbered pending interrupt, then acknowledge it. */
      ".Llowint1_4037bd7d:\n"
      "addi.n\ta4, a2, -1\n"
      "and\ta2, a2, a4\n"
      "bnez\ta2, .Llowint1_4037bd7d\n"
      "addi.n\ta4, a4, 1\n"
      "wsr.intclear\ta4\n"
      "movi.n\ta3, 31\n"
      "nsau\ta4, a4\n"
      "sub\ta3, a3, a4\n"
      /* Select the registered ISR and argument for this CPU. */
      "rsr.prid\ta12\n"
      "extui\ta12, a12, 13, 1\n"
      "addx2\ta3, a3, a12\n"
      "l32r\ta4, 0x40374994\n" /* literal: 0x3fc9de60 */
      "addx8\ta3, a3, a4\n"
      "l32i.n\ta4, a3, 0\n"
      "or\ta2, a6, a6\n"
      "l32i\ta6, a3, 4\n"
      "callx4\ta4\n"
      "j\t.Llowint1_4037bd52\n"
      /* Unexecuted linker fill/relaxation bytes between labeled blocks. */
      ".byte 0x00,0x00,0x46,0xe7,0xff\n"
      /* No source remains: transfer to RTOS interrupt exit. */
      ".Llowint1_4037bdb4:\n"
      "or\ta1, a1, a1\n"
      "call0\t_frxt_int_exit\n" /* SDK _frxt_int_exit; never returns */
  );
  __builtin_unreachable();
}

/* Native entry: 0x4037bdbc. */
/*
 * Medius v3.4.7 — host application; 0x4037bdbc.
 * Instruction-reviewed Xtensa assembly; C braces display the native entry.
 *
 * Level-2 CPU interrupt assembly entry. Creates a 192-byte frame,
 * saves interrupted A0/A1, EPS2 and EPC2, and records its level-2 exit label.
 * Enters the shared RTOS interrupt stack, enables interrupts above level 2,
 * dispatches the highest numbered enabled pending source in this level's mask,
 * and transfers to RTOS interrupt exit. The saved exit label restores the
 * selected frame's EPS2/EPC2/A0/A1 and executes RFI 2.
 *
 * Calls: _frxt_int_enter, _frxt_int_exit.
 *
 * Called by: _Level2Vector.
 *
 * Indirect call: registered interrupt handler with its stored argument.
 *
 * Original function-byte SHA-256:
 * 55c15e2522916cac766e5ca0c6d462076550818a0ba94f36c4ee056086b36dd7.
 */

/* The entry begins with interrupted A0 already preserved in EXCSAVE2.
   EXCSAVE2 is then reused as the frame pointer for backtrace spill copies.
   The dispatch mask is the immutable literal loaded before the pending-mask
   intersection below. Hardware INTENABLE and pending bits are reread after
   every ISR. The selected source is acknowledged in INTCLEAR, and its table
   entry is indexed by interrupt_number*2+core_id, with function/argument words.
   CALLX4 passes the registered argument through A6 into the ISR's C A2.
   RTOS interrupt exit does not return to the next instruction. Later task/ISR
   restoration jumps to the level-2 exit address recorded at frame+0, which
   restores EPS2/EPC2 and returns with RFI 2. It does not fall through into
   the next interrupt level. Peripheral level-triggered flags remain the ISR's
   responsibility. This reconstruction is static; physical interrupt nesting
   and peripheral behavior have not been measured.
   Reference: ESP-IDF v5.4.4 components/xtensa/xtensa_vectors.S.
   Corrected assembly span: 0x4037bdbc..0x4037be6b; SHA-256:
   979920d6bbef296b79b860a53b677303de40985d4aec6828e607d38d58563cba. */

/* These braces display the original assembly body, not a C wrapper
   to compile with an additional compiler-generated prologue. */
__attribute__((noreturn))

/*
 * Returns: Transfers through RTOS interrupt exit; its saved exit label later restores CPU state
 *   and executes RFI 2.
 * Requirements/effects: Level2 vector must preserve interrupted A0 in EXCSAVE2. Creates a192-byte
 *   frame, dispatches the highest enabled pending source in its immutable mask and acknowledges
 *   CPU pending bits. Peripheral-level acknowledgement remains the handler responsibility.
 */

void _xt_medint2(void)
{
  __asm__ volatile (
      "or\ta0, a1, a1\n"
      "addmi\ta1, a1, 0xffffff00\n"
      "addi\ta1, a1, 64\n"
      "s32i\ta0, a1, 16\n"
      "rsr.eps2\ta0\n"
      "s32i\ta0, a1, 8\n"
      "rsr.epc2\ta0\n"
      "s32i.n\ta0, a1, 4\n"
      "rsr.excsave2\ta0\n"
      "s32i.n\ta0, a1, 12\n"
      "l32r\ta0, 0x40374998\n" /* literal: 0x4037be58 */
      "s32i.n\ta0, a1, 0\n"
      "mov.n\ta0, a1\n"
      "wsr.excsave2\ta0\n"
      "call0\t_frxt_int_enter\n"
      "l32r\ta0, 0x4037499c\n" /* literal: 0x00040022 */
      "wsr.ps\ta0\n"
      "rsync\n"
      ".Lmedint2_4037bdee:\n"
      "rsr.intenable\ta2\n"
      "rsr.interrupt\ta3\n"
      "l32r\ta4, 0x403749a0\n" /* literal: 0x00380000 */
      "and\ta2, a2, a3\n"
      "and\ta2, a2, a4\n"
      "beqz\ta2, .Lmedint2_4037be50\n"
      "rsr.excsave2\ta0\n"
      "l32i.n\ta3, a0, 12\n"
      "s32e\ta3, a1, -16\n"
      "l32i.n\ta3, a0, 16\n"
      "s32e\ta3, a1, -12\n"
      "rsr.epc2\ta0\n"
      "l32r\ta4, 0x40374970\n" /* literal: 0xc0000000 */
      "or\ta0, a0, a4\n"
      "addx2\ta0, a4, a0\n"
      ".Lmedint2_4037be19:\n"
      "addi.n\ta4, a2, -1\n"
      "and\ta2, a2, a4\n"
      "bnez\ta2, .Lmedint2_4037be19\n"
      "addi.n\ta4, a4, 1\n"
      "wsr.intclear\ta4\n"
      "movi.n\ta3, 31\n"
      "nsau\ta4, a4\n"
      "sub\ta3, a3, a4\n"
      "rsr.prid\ta12\n"
      "extui\ta12, a12, 13, 1\n"
      "addx2\ta3, a3, a12\n"
      "l32r\ta4, 0x40374994\n" /* literal: 0x3fc9de60 */
      "addx8\ta3, a3, a4\n"
      "l32i.n\ta4, a3, 0\n"
      "or\ta2, a6, a6\n"
      "l32i\ta6, a3, 4\n"
      "callx4\ta4\n"
      "j\t.Lmedint2_4037bdee\n"
      /* Unexecuted alignment bytes between labeled paths. */
      ".byte 0x0,0x0,0x46,0xe7,0xff\n"
      ".Lmedint2_4037be50:\n"
      "or\ta1, a1, a1\n"
      "call0\t_frxt_int_exit\n"
      /* Unexecuted alignment bytes between labeled paths. */
      ".byte 0x0,0x0\n"
      ".L_xt_medint2_exit_4037bdbc:\n"
      "l32i.n\ta0, a1, 8\n"
      "wsr.eps2\ta0\n"
      "l32i.n\ta0, a1, 4\n"
      "wsr.epc2\ta0\n"
      "l32i.n\ta0, a1, 12\n"
      "l32i.n\ta1, a1, 16\n"
      "rsync\n"
      "rfi\t2\n"
  );
  __builtin_unreachable();
}

/* Native entry: 0x4037be6c. */
/*
 * Medius v3.4.7 — host application; 0x4037be6c.
 * Instruction-reviewed Xtensa assembly; C braces display the native entry.
 *
 * Level-3 CPU interrupt assembly entry. Creates a 192-byte frame,
 * saves interrupted A0/A1, EPS3 and EPC3, and records its level-3 exit label.
 * Enters the shared RTOS interrupt stack, enables interrupts above level 3,
 * dispatches the highest numbered enabled pending source in this level's mask,
 * and transfers to RTOS interrupt exit. The saved exit label restores the
 * selected frame's EPS3/EPC3/A0/A1 and executes RFI 3.
 *
 * Calls: _frxt_int_enter, _frxt_int_exit.
 *
 * Called by: _Level3Vector.
 *
 * Indirect call: registered interrupt handler with its stored argument.
 *
 * Original function-byte SHA-256:
 * afdf5ec1daa8a1be3b295b97648439638c559d36bcd3c16a4115d3252d11dd9f.
 */

/* The entry begins with interrupted A0 already preserved in EXCSAVE3.
   EXCSAVE3 is then reused as the frame pointer for backtrace spill copies.
   The dispatch mask is the immutable literal loaded before the pending-mask
   intersection below. Hardware INTENABLE and pending bits are reread after
   every ISR. The selected source is acknowledged in INTCLEAR, and its table
   entry is indexed by interrupt_number*2+core_id, with function/argument words.
   CALLX4 passes the registered argument through A6 into the ISR's C A2.
   RTOS interrupt exit does not return to the next instruction. Later task/ISR
   restoration jumps to the level-3 exit address recorded at frame+0, which
   restores EPS3/EPC3 and returns with RFI 3. It does not fall through into
   the next interrupt level. Peripheral level-triggered flags remain the ISR's
   responsibility. This reconstruction is static; physical interrupt nesting
   and peripheral behavior have not been measured.
   Reference: ESP-IDF v5.4.4 components/xtensa/xtensa_vectors.S.
   Corrected assembly span: 0x4037be6c..0x4037bf1b; SHA-256:
   e574809d3cfb64e9075494f263bcb70528f607ab44113e661915dd3affe578bb. */

/* These braces display the original assembly body, not a C wrapper
   to compile with an additional compiler-generated prologue. */
__attribute__((noreturn))

/*
 * Returns: Transfers through RTOS interrupt exit; its saved exit label later restores CPU state
 *   and executes RFI 3.
 * Requirements/effects: Level3 vector must preserve interrupted A0 in EXCSAVE3. Creates a192-byte
 *   frame, dispatches the highest enabled pending source in its immutable mask and acknowledges
 *   CPU pending bits. Peripheral-level acknowledgement remains the handler responsibility.
 */

void _xt_medint3(void)
{
  __asm__ volatile (
      "or\ta0, a1, a1\n"
      "addmi\ta1, a1, 0xffffff00\n"
      "addi\ta1, a1, 64\n"
      "s32i\ta0, a1, 16\n"
      "rsr.eps3\ta0\n"
      "s32i\ta0, a1, 8\n"
      "rsr.epc3\ta0\n"
      "s32i.n\ta0, a1, 4\n"
      "rsr.excsave3\ta0\n"
      "s32i.n\ta0, a1, 12\n"
      "l32r\ta0, 0x403749a4\n" /* literal: 0x4037bf08 */
      "s32i.n\ta0, a1, 0\n"
      "mov.n\ta0, a1\n"
      "wsr.excsave3\ta0\n"
      "call0\t_frxt_int_enter\n"
      "l32r\ta0, 0x403749a8\n" /* literal: 0x00040023 */
      "wsr.ps\ta0\n"
      "rsync\n"
      ".Lmedint3_4037be9e:\n"
      "rsr.intenable\ta2\n"
      "rsr.interrupt\ta3\n"
      "l32r\ta4, 0x403749ac\n" /* literal: 0x28c08800 */
      "and\ta2, a2, a3\n"
      "and\ta2, a2, a4\n"
      "beqz\ta2, .Lmedint3_4037bf00\n"
      "rsr.excsave3\ta0\n"
      "l32i.n\ta3, a0, 12\n"
      "s32e\ta3, a1, -16\n"
      "l32i.n\ta3, a0, 16\n"
      "s32e\ta3, a1, -12\n"
      "rsr.epc3\ta0\n"
      "l32r\ta4, 0x40374970\n" /* literal: 0xc0000000 */
      "or\ta0, a0, a4\n"
      "addx2\ta0, a4, a0\n"
      ".Lmedint3_4037bec9:\n"
      "addi.n\ta4, a2, -1\n"
      "and\ta2, a2, a4\n"
      "bnez\ta2, .Lmedint3_4037bec9\n"
      "addi.n\ta4, a4, 1\n"
      "wsr.intclear\ta4\n"
      "movi.n\ta3, 31\n"
      "nsau\ta4, a4\n"
      "sub\ta3, a3, a4\n"
      "rsr.prid\ta12\n"
      "extui\ta12, a12, 13, 1\n"
      "addx2\ta3, a3, a12\n"
      "l32r\ta4, 0x40374994\n" /* literal: 0x3fc9de60 */
      "addx8\ta3, a3, a4\n"
      "l32i.n\ta4, a3, 0\n"
      "or\ta2, a6, a6\n"
      "l32i\ta6, a3, 4\n"
      "callx4\ta4\n"
      "j\t.Lmedint3_4037be9e\n"
      /* Unexecuted alignment bytes between labeled paths. */
      ".byte 0xc6,0xe7,0xff,0x0,0x0\n"
      ".Lmedint3_4037bf00:\n"
      "or\ta1, a1, a1\n"
      "call0\t_frxt_int_exit\n"
      /* Unexecuted alignment bytes between labeled paths. */
      ".byte 0x0,0x0\n"
      ".L_xt_medint3_exit_4037be6c:\n"
      "l32i.n\ta0, a1, 8\n"
      "wsr.eps3\ta0\n"
      "l32i.n\ta0, a1, 4\n"
      "wsr.epc3\ta0\n"
      "l32i.n\ta0, a1, 12\n"
      "l32i.n\ta1, a1, 16\n"
      "rsync\n"
      "rfi\t3\n"
  );
  __builtin_unreachable();
}

/* Native entry: 0x40381e30. */
/*
 * Medius v3.4.7 — host application; 0x40381e30.
 *
 * Sets this core port-switch flag so interrupt exit performs a task switch.
 *
 * Called by: lock_acquire_generic, FUN_40376a1c, _lock_release, FUN_4037d2b0, FUN_4037d3cc, SysTickIsrHandler,
 * medius_credit_receive, medius_hid_report_enqueue, medius_hid_special_enqueue,
 * medius_host_publish_resume_event, link_receive_publish, link_uart_interrupt_handler,
 * medius_out_complete, medius_usbh_queue_send_value, medius_vendor_complete, usb_osal_mq_recv,
 * usb_osal_sem_give.
 *
 * Original function-byte SHA-256:
 * 9212770ba18f213cf7231f3fcc77dd8bf00918fbf3e9a0916edca1cf51bc16ec.
 */

/* Sets this core port-switch flag so interrupt exit performs a task switch.
   SDK match: ESP-IDF v5.4.4 components/freertos/FreeRTOS-Kernel/portable/xtensa/portasm.S.
   Recovered types/control flow retain the original function bytes and non-returning assertion paths. */

/*
 * Returns: Nothing; stores 1 in the current CPU switch-request word.
 * Requirements/effects: Reads hardware PRID bit 13 to select CPU0 or CPU1. Marks a pending switch
 *   for interrupt exit; does not itself invoke the scheduler, wait for a switch or send an inter-
 *   core interrupt.
 */

void _frxt_setup_switch(void)
{
  uint processor_id;
  __asm__ volatile ("rsr.prid %0" : "=a"(processor_id));
  volatile uint *switch_requests = (volatile uint *)0x3fca76d0U;
  switch_requests[(processor_id >> 13) & 1U] = 1U;
}

/* Native entry: 0x40381e48. */
/*
 * Medius v3.4.7 — host application; 0x40381e48.
 * Instruction-reviewed Xtensa assembly; C braces display the native entry.
 *
 * Assembly CALL0 interrupt entry using an already allocated exception frame.
 * Saves A12/A13 and the remaining interrupted context. If the scheduler runs,
 * increments this core's nesting count. On the outermost interrupt with a current
 * task, stores A1 in TCB.top_of_stack and moves to this core's 1536-byte ISR stack.
 * Nested interrupts keep their current stack. Returns through the saved A0.
 *
 * Calls: _xt_context_save.
 *
 * Called by: _xt_lowint1, _xt_medint2, _xt_medint3.
 *
 * Original function-byte SHA-256:
 * 2ed5d568124e2d55859dda036d00f339977cd2a53e848b6d2880020c290524a4.
 */

/* A1 changes only for the first interrupt of a running task. When the
   scheduler has not started, nesting and the stack stay unchanged after the
   processor save. When nesting was already nonzero, the existing ISR stack is
   retained. This image has FPU-in-ISR support disabled: no CPENABLE save/clear
   sequence appears in this entry. A12 holds the CALL0 return address.
   Reference: ESP-IDF v5.4.4 components/freertos/FreeRTOS-Kernel/portable/xtensa/portasm.S.
   Corrected assembly span: 0x40381e48..0x40381e8b; SHA-256:
   2ed5d568124e2d55859dda036d00f339977cd2a53e848b6d2880020c290524a4. */

/* These braces display the original assembly body, not a C wrapper
   to compile with an additional compiler-generated prologue. */

/*
 * Returns: CALL0 RET resumes the assembly caller; A1 may now address the per-core ISR stack.
 * Requirements/effects: A1 must address an allocated192-byte exception frame. Saves remaining
 *   context and, for the outermost running-task interrupt, stores task SP and selects the1536-byte
 *   ISR stack. FPU-in-ISR support is not enabled in this image.
 */

void _frxt_int_enter(void)
{
  __asm__ volatile (
      /* Save A12/A13 before the shared context-save helper. */
      "s32i.n\ta12, a1, 60\n"
      "s32i\ta13, a1, 64\n"
      "mov.n\ta12, a0\n"
      "call0\t_xt_context_save\n"
      /* Choose this core's nesting and scheduler words. */
      "rsr.prid\ta4\n"
      "extui\ta4, a4, 13, 1\n"
      "l32r\ta2, 0x40374cec\n" /* literal: 0x3fca76f0 */
      "addx4\ta2, a4, a2\n"
      "l32r\ta3, 0x403746e4\n" /* literal: 0x3fca76e8 */
      "addx4\ta3, a4, a3\n"
      "l32i.n\ta2, a2, 0\n"
      "beqz.n\ta2, .Lenter_40381e88\n"
      /* Increment nesting only while the scheduler is running. */
      "l32i.n\ta2, a3, 0\n"
      "addi.n\ta2, a2, 1\n"
      "s32i.n\ta2, a3, 0\n"
      "bnei\ta2, 1, .Lenter_40381e88\n"
      "l32r\ta2, 0x40374d2c\n" /* literal: 0x3fca76c8 */
      "addx4\ta2, a4, a2\n"
      "l32i.n\ta2, a2, 0\n"
      "beqz.n\ta2, .Lenter_40381e88\n"
      /* Outermost task interrupt: save task SP and select the core ISR stack. */
      "s32i.n\ta1, a2, 0\n"
      "l32r\ta1, 0x40374d30\n" /* literal: 0x3fc9ec30 */
      "movi\ta2, 0x600\n"
      "mull\ta2, a4, a2\n"
      "add.n\ta1, a1, a2\n"
      ".Lenter_40381e88:\n"
      "mov.n\ta0, a12\n"
      "ret.n\n"
  );
}

/* Native entry: 0x40381e8c. */
/*
 * Medius v3.4.7 — host application; 0x40381e8c.
 * Instruction-reviewed Xtensa assembly; C braces display the native entry.
 *
 * Assembly interrupt exit with no ordinary C return. Masks interrupts to
 * level 3 and decrements this core's nesting count when the scheduler runs.
 * An outermost exit reloads the task stack and consumes the core's switch flag;
 * a requested switch saves CPENABLE and dispatches a ready task. Otherwise it
 * restores the interrupted context and jumps through the frame's exit pointer.
 *
 * Calls: _frxt_dispatch, vPortYieldFromInt, _xt_context_restore.
 *
 * Called by: _xt_lowint1, _xt_medint2, _xt_medint3.
 *
 * Original function-byte SHA-256:
 * 74a3f83e3f79e50bd048cfbdcd84d3f2c7e6bc672ea6c4672b833f4eccb6f00d.
 */

/* The no-switch/nested path calls _xt_context_restore, loads frame.exit
   into A0, and RET transfers there rather than to this routine's caller.
   With a current task, outermost exit first reloads TCB.top_of_stack even if
   the switch flag is clear. The flag is cleared before vPortYieldFromInt.
   With no current task, the SDK code falls through the switching sequence;
   it does not add validation absent from the image.
   Reference: ESP-IDF v5.4.4 components/freertos/FreeRTOS-Kernel/portable/xtensa/portasm.S.
   Corrected assembly span: 0x40381e8c..0x40381edb; SHA-256:
   74a3f83e3f79e50bd048cfbdcd84d3f2c7e6bc672ea6c4672b833f4eccb6f00d. */

/* These braces display the original assembly body, not a C wrapper
   to compile with an additional compiler-generated prologue. */
__attribute__((noreturn))

/*
 * Returns: Transfers to a selected task or frame exit pointer; never returns as an ordinary C
 *   call.
 * Requirements/effects: Requires the interrupt frame and nesting/scheduler state established by
 *   interrupt entry. Masks low/medium interrupts, handles outermost switch requests and restores
 *   the selected context; the current task/frame must be valid where dereferenced.
 */

void _frxt_int_exit(void)
{
  __asm__ volatile (
      "rsr.prid\ta4\n"
      "extui\ta4, a4, 13, 1\n"
      "l32r\ta2, 0x40374cec\n" /* literal: 0x3fca76f0 */
      "addx4\ta2, a4, a2\n"
      "l32r\ta3, 0x403746e4\n" /* literal: 0x3fca76e8 */
      "addx4\ta3, a4, a3\n"
      /* Mask low/medium interrupts before testing nesting. */
      "rsil\ta0, 3\n"
      "l32i.n\ta2, a2, 0\n"
      "beqz.n\ta2, .Lexit_40381ed5\n"
      /* Decrement the current core's nesting count. */
      "l32i.n\ta2, a3, 0\n"
      "addi.n\ta2, a2, -1\n"
      "s32i.n\ta2, a3, 0\n"
      "bnez.n\ta2, .Lexit_40381ed5\n"
      "l32r\ta2, 0x40374d2c\n" /* literal: 0x3fca76c8 */
      "addx4\ta2, a4, a2\n"
      "l32i.n\ta2, a2, 0\n"
      "beqz.n\ta2, .Lexit_40381ec9\n"
      "l32i.n\ta1, a2, 0\n"
      "l32r\ta2, 0x40374d28\n" /* literal: 0x3fca76d0 */
      "addx4\ta2, a4, a2\n"
      "l32i.n\ta3, a2, 0\n"
      "beqz.n\ta3, .Lexit_40381ed5\n"
      "movi\ta3, 0\n"
      "s32i\ta3, a2, 0\n"
      /* Save CPENABLE, then tail-dispatch. */
      ".Lexit_40381ec9:\n"
      "or\ta1, a1, a1\n"
      "call4\tvPortYieldFromInt\n"
      "or\ta1, a1, a1\n"
      "call0\t_frxt_dispatch\n"
      /* Restore the unchanged task or nested ISR and transfer to frame.exit. */
      ".Lexit_40381ed5:\n"
      "call0\t_xt_context_restore\n"
      "l32i.n\ta0, a1, 0\n"
      "ret.n\n"
  );
  __builtin_unreachable();
}

/* Native entry: 0x40381edc. */
/*
 * Medius v3.4.7 — host application; 0x40381edc.
 * Instruction-reviewed Xtensa assembly; C braces display the native entry.
 *
 * Assembly scheduler dispatcher. Calls vTaskSwitchContext, selects this
 * core's current TCB, and loads its saved stack pointer into A1. A zero frame
 * exit field selects a solicited yield frame: restore THREADPTR/PS/PC and RETW.
 * A nonzero exit field selects a full interrupt frame: restore CPENABLE and full
 * processor state, then transfer to the saved exception-exit dispatcher.
 * The old 64-bit C return was an artifact of resumed register contents.
 *
 * Calls: vTaskSwitchContext, _xt_context_restore.
 *
 * Called by: xPortStartScheduler, _frxt_int_exit, vPortYield.
 *
 * Original function-byte SHA-256:
 * d50a91f389ccfc339085a4c781bc39c20f89a582a5a70f07d417648e7c23c988.
 */

/* Two different suspension layouts share frame[0]: zero is the solicited
   marker, otherwise it is an exit code pointer. The solicited frame is 32 bytes;
   the full frame is 192 bytes. The context restore operates on the SELECTED
   task's stack, not the dispatcher's original stack. CPENABLE stays cleared for
   a solicited resume; a full resume loads header.enabled before restoring.
   The native full-frame path loads A1 from TCB.top_of_stack and restores
   all 14 A2-A15 registers from that selected frame's fields.
   Reference: ESP-IDF v5.4.4 components/freertos/FreeRTOS-Kernel/portable/xtensa/portasm.S.
   Corrected assembly span: 0x40381edc..0x40381f3f; SHA-256:
   d50a91f389ccfc339085a4c781bc39c20f89a582a5a70f07d417648e7c23c988. */

/* These braces display the original assembly body, not a C wrapper
   to compile with an additional compiler-generated prologue. */
__attribute__((noreturn))

/*
 * Returns: Resumes a task via RETW or its exception-exit pointer; no C return value.
 * Requirements/effects: Assembly scheduler entry requires valid ready/current TCB and saved stack.
 *   Distinguishes a32-byte solicited frame by exit_marker0 from a192-byte full frame; updates
 *   SP/TLS/PS and appropriate coprocessor state.
 */

void _frxt_dispatch(void)
{
  __asm__ volatile (
      /* Let the kernel choose the next ready task. */
      "call4\tvTaskSwitchContext\n"
      "l32r\ta2, 0x40374d2c\n" /* literal: 0x3fca76c8 */
      "rsr.prid\ta3\n"
      "extui\ta3, a3, 13, 1\n"
      "addx4\ta2, a3, a2\n"
      "l32i\ta3, a2, 0\n"
      "l32i\ta1, a3, 0\n"
      "s32i\ta3, a2, 0\n"
      /* Read the frame tag at the selected task's saved SP. */
      "l32i.n\ta2, a1, 0\n"
      "bnez.n\ta2, .Ldispatch_40381f09\n"
      /* Solicited frame: restore TLS, PS and return link, then RETW. */
      "l32i.n\ta2, a1, 12\n"
      "wur.threadptr\ta2\n"
      "l32i.n\ta3, a1, 8\n"
      "l32i.n\ta0, a1, 4\n"
      "rsync\n"
      "wsr.ps\ta3\n"
      "retw.n\n"
      /* Full frame: restore the task's CPENABLE before processor context. */
      ".Ldispatch_40381f09:\n"
      "l32r\ta2, 0x40374d2c\n" /* literal: 0x3fca76c8 */
      "rsr.prid\ta3\n"
      "extui\ta3, a3, 13, 1\n"
      "addx4\ta2, a3, a2\n"
      "l32i\ta2, a2, 0\n"
      "l32r\ta3, 0x40374d34\n" /* literal: 0x3fc9f238 */
      "l32i\ta3, a3, 0\n"
      "add\ta2, a2, a3\n"
      "l32i.n\ta2, a2, 0\n"
      "l32r\ta3, 0x40374d38\n" /* literal: 0x3fc9f234 */
      "l32i.n\ta3, a3, 0\n"
      "sub\ta2, a2, a3\n"
      "movi.n\ta3, -16\n"
      "and\ta2, a2, a3\n"
      "l16ui\ta3, a2, 0\n"
      "wsr.cpenable\ta3\n"
      "call0\t_xt_context_restore\n"
      "rsync\n"
      "l32i.n\ta0, a1, 0\n"
      "ret.n\n"
  );
  __builtin_unreachable();
}

/* Native entry: 0x40381fd8. */
/*
 * Medius v3.4.7 — host application; 0x40381fd8.
 * Instruction-reviewed Xtensa assembly; C braces display the native entry.
 *
 * Assembly CALL0 helper returning the running task's coprocessor header in
 * A15, not the C return register A2. Returns A15=0 before scheduler start, inside
 * an ISR, or without a current TCB. Otherwise returns
 * align_down(task->stack_end - 316, 16). Clobbers A3 and A15 only.
 *
 * Called by: _xt_coproc_exc, _xt_coproc_savecs, _xt_coproc_restorecs.
 *
 * Original function-byte SHA-256:
 * 458b7e9bf963008c9c45e93c93f0232eeeef69a587b257bf99a2f7df38b6c82a.
 */

/* The original C export discarded this routine's useful result because it
   is returned in A15. Do not replace this with a normal C pointer return.
   Both images load offset_pxEndOfStack=0x48 and offset_cpsa=0x13c from the
   SDK's exported offset globals before the 16-byte alignment operation.
   Reference: ESP-IDF v5.4.4 components/freertos/FreeRTOS-Kernel/portable/xtensa/portasm.S.
   Corrected assembly span: 0x40381fd8..0x40382017; SHA-256:
   458b7e9bf963008c9c45e93c93f0232eeeef69a587b257bf99a2f7df38b6c82a. */

/* The braces display the original assembly body; this recovered export
   is not a C wrapper to compile with an additional compiler prologue. */

/*
 * Returns: Header pointer in A15, or0 before scheduler start, inside ISR or without a current
 *   task; no C A2 result.
 * Requirements/effects: CALL0 assembly contract. Uses CPU-selected scheduler/nesting/current-TCB
 *   state; clobbers A3/A15 and computes align_down(task.stack_end-316,16) for a live task.
 */

void _frxt_task_coproc_state(void)
{
  __asm__ volatile (
      "rsr.prid\ta3\n"
      "extui\ta3, a3, 13, 1\n"
      "l32r\ta15, 0x40374cec\n" /* literal: 0x3fca76f0 */
      "addx4\ta15, a3, a15\n"
      "l32i.n\ta15, a15, 0\n"
      "beqz.n\ta15, .Lstate_40382014\n"
      "l32r\ta15, 0x403746e4\n" /* literal: 0x3fca76e8 */
      "addx4\ta15, a3, a15\n"
      "l32i.n\ta15, a15, 0\n"
      "bnez.n\ta15, .Lstate_40382014\n"
      "l32r\ta15, 0x40374d2c\n" /* literal: 0x3fca76c8 */
      "addx4\ta15, a3, a15\n"
      "l32i.n\ta15, a15, 0\n"
      "beqz.n\ta15, .Lstate_40382016\n"
      "l32r\ta3, 0x40374d34\n" /* literal: 0x3fc9f238 */
      "l32i.n\ta3, a3, 0\n"
      "add.n\ta15, a15, a3\n"
      "l32i.n\ta15, a15, 0\n"
      "l32r\ta3, 0x40374d38\n" /* literal: 0x3fc9f234 */
      "l32i.n\ta3, a3, 0\n"
      "sub\ta15, a15, a3\n"
      "movi.n\ta3, -16\n"
      "and\ta15, a15, a3\n"
      "ret.n\n"
      ".Lstate_40382014:\n"
      "movi.n\ta15, 0\n"
      ".Lstate_40382016:\n"
      "ret.n\n"
  );
}

/* Native entry: 0x40382018. */
/*
 * Medius v3.4.7 — host application; 0x40382018.
 * Instruction-reviewed Xtensa assembly; C braces display the native entry.
 *
 * Assembly CALL0 hook for lazy FPU/vector use. Before scheduler start or
 * inside an ISR it does nothing. In task context it writes the current CPU
 * number to TCB.core_id (offset 0x44), pinning that task to this CPU for scheduling.
 * Uses A2-A4 as scratch; there is no ordinary C argument or return value.
 *
 * Called by: _xt_coproc_exc.
 *
 * Original function-byte SHA-256:
 * c1cb648e8f64f6f17d2a87dec2185cab87f44c5eef21b63ccdfcd0413cd1be5e.
 */

/* The two guards test the current core's scheduler-running and interrupt
   nesting words. Once both permit task context, the code assumes pxCurrentTCBs
   is valid; it does not add a third NULL check. The coprocessor owner state is
   per-core, which explains the core-pinning store before ownership changes.
   Reference: ESP-IDF v5.4.4 components/freertos/FreeRTOS-Kernel/portable/xtensa/portasm.S.
   Corrected assembly span: 0x40382018..0x40382045; SHA-256:
   c1cb648e8f64f6f17d2a87dec2185cab87f44c5eef21b63ccdfcd0413cd1be5e. */

/* The braces display the original assembly body; this recovered export
   is not a C wrapper to compile with an additional compiler prologue. */

/*
 * Returns: CALL0 RET; no C result.
 * Requirements/effects: Before scheduler start or in ISR does nothing. In task context requires a
 *   live TCB and writes the current CPU to core_id, pinning scheduling; uses A2-A4 as scratch.
 */

void _frxt_coproc_exc_hook(void)
{
  __asm__ volatile (
      "rsr.prid\ta2\n"
      "extui\ta2, a2, 13, 1\n"
      "l32r\ta3, 0x40374cec\n" /* literal: 0x3fca76f0 */
      "addx4\ta3, a2, a3\n"
      "l32i.n\ta3, a3, 0\n"
      "beqz.n\ta3, .Lhook_40382044\n"
      "l32r\ta3, 0x403746e4\n" /* literal: 0x3fca76e8 */
      "addx4\ta3, a2, a3\n"
      "l32i.n\ta3, a3, 0\n"
      "bnez.n\ta3, .Lhook_40382044\n"
      "l32r\ta3, 0x40374d2c\n" /* literal: 0x3fca76c8 */
      "addx4\ta3, a2, a3\n"
      "l32i.n\ta3, a3, 0\n"
      "l32r\ta4, 0x40374d40\n" /* literal: 0x3fc9f230 */
      "l32i.n\ta4, a4, 0\n"
      "add.n\ta3, a3, a4\n"
      "s32i\ta2, a3, 0\n"
      ".Lhook_40382044:\n"
      "ret.n\n"
  );
}

/* Native entry: 0x4038d594. */
/*
 * Medius v3.4.7 — host application; 0x4038d594.
 * Instruction-reviewed Xtensa assembly; C braces display the native entry.
 *
 * HAL CALL0 routine for manually spilling live register windows into their
 * ABI stack areas. Rotates WINDOWSTART relative to WINDOWBASE, selects CALL4/8/12
 * spill layouts from successive mask bits, writes 4/8/12 registers, and rotates
 * the window/mask until finished. Requires valid caller spill regions and the
 * interrupt/window-overflow state prepared by its assembly caller.
 * Returns a diagnostic in A2; it does not have six ordinary C arguments.
 *
 * Called by: vPortYield, xthal_window_spill.
 *
 * Original function-byte SHA-256:
 * 45bd997eff19331c3981ea45063a2b23854c7dddb0ff282707a4d4cc7cbf084a.
 */

/* Alias in the SDK HAL object: xthal_spill_registers_into_stack_nw.
   The entire 273-byte span matches windowspill_asm.o, including linker fill.
   It returns A2=1 when the WINDOWSTART bit for the current WINDOWBASE is clear.
   Its normal completion leaves WINDOWSTART with only the current-window bit
   set and returns A2=0. With a nonzero scan mask whose low three bits are clear,
   it rebuilds WINDOWSTART/WINDOWBASE from the remaining mask and returns A2=2.
   These are the observed branch results; callers here discard the diagnostic.
   The 4-register path spills A4-A7 at A9-16 and advances one window. The
   8-register path also spills A8-A11 through the caller stack pointer chain,
   then advances two windows. The 12-register path temporarily rotates once,
   writes the base-save words, follows the saved stack chain, writes the other
   eight words, and advances three windows in total. No pointer bounds checks
   are performed. Preserve assembly rotation semantics instead of treating the
   different windows' same-named registers as ordinary C variables.
   Reference: ESP-IDF v5.4.4 components/xtensa/esp32s3/libxt_hal.a.
   Corrected assembly span: 0x4038d594..0x4038d6a4; SHA-256:
   cd0fd9e403bc238bd495de1def1033b78203d34fce47ba3519fa7fb5da3f2374. */

/* These braces display the original assembly body, not a C wrapper
   to compile with an additional compiler-generated prologue. */

/*
 * Returns: CALL0 diagnostic in A2:0 for normal completion,1 for an unmarked current window,2 for
 *   the documented invalid low-mask layout.
 * Requirements/effects: Non-windowed assembly calling convention. Requires prepared processor
 *   window/interrupt state and valid ABI spill areas throughout the saved stack chain. Rotates
 *   live windows and writes their4/8/12-register layouts; no capacity checks.
 */

unsigned int xthal_window_spill_nw(void)
{
  __asm__ volatile (
      /* Rotate the live-window mask around WINDOWBASE. */
      "rsr.windowbase\ta2\n"
      "addi.n\ta2, a2, 1\n"
      "ssr\ta2\n"
      "rsr.windowstart\ta3\n"
      "srl\ta2, a3\n"
      "sll\ta3, a3\n"
      "bgez\ta3, .Lspill_4038d668\n"
      "extui\ta3, a3, 16, 16\n"
      "or\ta2, a2, a3\n"
      "neg\ta3, a2\n"
      "and\ta3, a3, a2\n"
      "nsau\ta3, a3\n"
      "ssl\ta3\n"
      "srl\ta2, a2\n"
      "wsr.windowstart\ta2\n"
      "rsr.windowbase\ta2\n"
      "addi\ta2, a2, 31\n"
      "sub\ta3, a2, a3\n"
      "wsr.windowbase\ta3\n"
      "rsync\n"
      "rsr.windowstart\ta2\n"
      /* Select the next 4-, 8- or 12-register spill layout. */
      ".Lspill_4038d5d2:\n"
      "beqz\ta2, .Lspill_4038d650\n"
      "bbsi\ta2, 0, .Lspill_4038d5e1\n"
      "bbsi\ta2, 1, .Lspill_4038d5f5\n"
      "bbsi\ta2, 2, .Lspill_4038d619\n"
      "j\t.Lspill_4038d66e\n"
      /* CALL4-shaped spill. */
      ".Lspill_4038d5e1:\n"
      "addi\ta3, a9, -16\n"
      "s32i.n\ta4, a3, 0\n"
      "s32i.n\ta5, a3, 4\n"
      "s32i.n\ta6, a3, 8\n"
      "s32i.n\ta7, a3, 12\n"
      "srli\ta6, a2, 1\n"
      "rotw\t1\n"
      "j\t.Lspill_4038d5d2\n"
      /* CALL8-shaped spill. */
      ".Lspill_4038d5f5:\n"
      "addi\ta3, a13, -16\n"
      "s32i.n\ta4, a3, 0\n"
      "s32i.n\ta5, a3, 4\n"
      "s32i.n\ta6, a3, 8\n"
      "s32i.n\ta7, a3, 12\n"
      "addi\ta3, a5, -12\n"
      "l32i.n\ta3, a3, 0\n"
      "addi\ta3, a3, -32\n"
      "s32i.n\ta8, a3, 0\n"
      "s32i.n\ta9, a3, 4\n"
      "s32i.n\ta10, a3, 8\n"
      "s32i.n\ta11, a3, 12\n"
      "srli\ta10, a2, 2\n"
      "rotw\t2\n"
      "j\t.Lspill_4038d5d2\n"
      /* CALL12-shaped spill. */
      ".Lspill_4038d619:\n"
      "rotw\t1\n"
      "addi\ta13, a13, -16\n"
      "s32i.n\ta0, a13, 0\n"
      "s32i.n\ta1, a13, 4\n"
      "s32i.n\ta2, a13, 8\n"
      "s32i.n\ta3, a13, 12\n"
      "addi\ta3, a1, -12\n"
      "l32i.n\ta3, a3, 0\n"
      "addi\ta13, a13, 16\n"
      "addi\ta3, a3, -48\n"
      "s32i.n\ta4, a3, 0\n"
      "s32i.n\ta5, a3, 4\n"
      "s32i.n\ta6, a3, 8\n"
      "s32i.n\ta7, a3, 12\n"
      "s32i.n\ta8, a3, 16\n"
      "s32i.n\ta9, a3, 20\n"
      "s32i.n\ta10, a3, 24\n"
      "s32i.n\ta11, a3, 28\n"
      "rotw\t-1\n"
      "srli\ta14, a2, 3\n"
      "rotw\t3\n"
      "j\t.Lspill_4038d5d2\n"
      /* Unexecuted alignment bytes between labeled paths. */
      ".byte 0x0,0x0\n"
      /* Normal completion: retain the current window bit. */
      ".Lspill_4038d650:\n"
      "rotw\t1\n"
      "rsr.windowbase\ta2\n"
      "ssl\ta2\n"
      "movi.n\ta2, 1\n"
      "sll\ta2, a2\n"
      "wsr.windowstart\ta2\n"
      "rsync\n"
      "movi.n\ta2, 0\n"
      "ret.n\n"
      /* Current window was not marked live: diagnostic 1. */
      ".Lspill_4038d668:\n"
      "movi.n\ta2, 1\n"
      "ret.n\n"
      /* Unexecuted alignment bytes between labeled paths. */
      ".byte 0x0,0x0\n"
      /* No valid low-three-bit layout: reconstruct window state and return 2. */
      ".Lspill_4038d66e:\n"
      "slli\ta2, a2, 1\n"
      "addi.n\ta2, a2, 1\n"
      "rsr.windowbase\ta3\n"
      "bbsi\ta2, 15, .Lspill_4038d684\n"
      ".Lspill_4038d679:\n"
      "addi.n\ta3, a3, -1\n"
      "slli\ta2, a2, 1\n"
      "bbci\ta2, 15, .Lspill_4038d679\n"
      "extui\ta3, a3, 0, 4\n"
      ".Lspill_4038d684:\n"
      "ssl\ta3\n"
      "slli\ta3, a2, 16\n"
      "src\ta2, a2, a3\n"
      "extui\ta2, a2, 0, 16\n"
      "wsr.windowstart\ta2\n"
      "rsr.sar\ta3\n"
      "movi.n\ta2, 32\n"
      "sub\ta3, a2, a3\n"
      "wsr.windowbase\ta3\n"
      "rsync\n"
      "movi.n\ta2, 2\n"
      "ret.n\n"
  );
}

/* Native entry: 0x4038d6a8. */
/*
 * Medius v3.4.7 — host application; 0x4038d6a8.
 * Instruction-reviewed Xtensa assembly; C braces display the native entry.
 *
 * C-callable windowed wrapper around xthal_window_spill_nw. Preserves
 * return address and PS in A4/A5, clears WOE and INTLEVEL in a temporary PS,
 * selects interrupt level 3, synchronizes, spills windows manually, then restores
 * PS and returns with RETW. Ignores the non-windowed helper's A2 diagnostic.
 *
 * Calls: xthal_window_spill_nw.
 *
 * Called by: FUN_40375f1c, xPortStartScheduler.
 *
 * Original function-byte SHA-256:
 * d306c4becdda95ba9d2c9d8c87e641b76fa7d4d6af41b057463f9adc9a7b6a5b.
 */

/* ENTRY allocates 16 bytes. Its PS operand is the actual saved PS in A5,
   unlike the separate vPortYield sequence. The mask literal is 0xfffbfff0.
   No window overflow trap is needed inside the manual HAL routine because this
   wrapper clears WOE; it synchronizes before and after restoring processor state.
   Reference: ESP-IDF v5.4.4 components/xtensa/esp32s3/libxt_hal.a.
   Corrected assembly span: 0x4038d6a8..0x4038d6ca; SHA-256:
   d306c4becdda95ba9d2c9d8c87e641b76fa7d4d6af41b057463f9adc9a7b6a5b. */

/* These braces display the original assembly body, not a C wrapper
   to compile with an additional compiler-generated prologue. */

/*
 * Returns: Windowed RETW returns after restoring the original PS; the CALL0 helper diagnostic is
 *   discarded.
 * Requirements/effects: Valid windowed task stack/spill chain. Saves return link/PS, disables WOE
 *   in a temporary interrupt-level3 state, manually spills and restores the saved PS.
 */

void xthal_window_spill(void)
{
  __asm__ volatile (
      "entry\ta1, 16\n"
      "l32r\ta6, 0x40374d3c\n" /* literal: 0xfffbfff0 */
      "rsr.ps\ta5\n"
      "mov.n\ta4, a0\n"
      "and\ta2, a5, a6\n"
      "addi.n\ta2, a2, 3\n"
      "wsr.ps\ta2\n"
      "rsync\n"
      "call0\txthal_window_spill_nw\n"
      "mov.n\ta0, a4\n"
      "wsr.ps\ta5\n"
      "rsync\n"
      "retw.n\n"
  );
}

/* Native entry: 0x4038d6cc. */
/*
 * Medius v3.4.7 — host application; 0x4038d6cc.
 * Instruction-reviewed Xtensa assembly; C braces display the native entry.
 *
 * CALL0 non-windowed helper; A2 points to a readable 36-byte state area.
 * Loads THREADPTR, ACCLO, ACCHI, BR, SCOMPARE1 and M0-M3 from offsets 0..32.
 * Uses A3 as scratch, preserves A2, and RET returns through A0. This is the
 * inverse of xthal_save_extra_nw, separate from FPU/vector context restoration.
 *
 * Called by: _xt_context_restore.
 *
 * Original function-byte SHA-256:
 * a46f489283cc93bf7b7deaa7cbad5acda15c46be66ee9f030803fa3ddd4fcc82.
 */

/* Register/field order: THREADPTR +0, ACCLO +4, ACCHI +8, BR +12,
   SCOMPARE1 +16, M0 +20, M1 +24, M2 +28, M3 +32. This 47-byte routine matches
   the ESP32-S3 SDK libxt_hal.a state_asm--restore_extra_nw.o reference object.
   Reference: ESP-IDF v5.4.4 components/xtensa/esp32s3/libxt_hal.a.
   Corrected assembly span: 0x4038d6cc..0x4038d6fa; SHA-256:
   a46f489283cc93bf7b7deaa7cbad5acda15c46be66ee9f030803fa3ddd4fcc82. */

/* These braces display the original assembly body, not a C wrapper
   to compile with an additional compiler-generated prologue. */

/*
 * state: Readable, word-aligned36-byte non-coprocessor register state supplied in A2 under the
 *   CALL0 convention.
 * Returns: CALL0 RET through A0; A2 is preserved and A3 is scratch.
 * Requirements/effects: Restores THREADPTR, ACCLO/ACCHI, BR, SCOMPARE1 and M0-M3 in the documented
 *   field order. Does not restore FPU/vector payloads; caller provides appropriate privileged
 *   context.
 */

void xthal_restore_extra_nw(const XtensaExtraState *state)
{
  __asm__ volatile (
      "l32i.n\ta3, a2, 0\n"
      "wur.threadptr\ta3\n"
      "l32i.n\ta3, a2, 4\n"
      "wsr.acclo\ta3\n"
      "l32i.n\ta3, a2, 8\n"
      "wsr.acchi\ta3\n"
      "l32i.n\ta3, a2, 12\n"
      "wsr.br\ta3\n"
      "l32i.n\ta3, a2, 16\n"
      "wsr.scompare1\ta3\n"
      "l32i.n\ta3, a2, 20\n"
      "wsr.m0\ta3\n"
      "l32i.n\ta3, a2, 24\n"
      "wsr.m1\ta3\n"
      "l32i.n\ta3, a2, 28\n"
      "wsr.m2\ta3\n"
      "l32i.n\ta3, a2, 32\n"
      "wsr.m3\ta3\n"
      "ret.n\n"
  );
}

/* Native entry: 0x4038d6fc. */
/*
 * Medius v3.4.7 — host application; 0x4038d6fc.
 * Instruction-reviewed Xtensa assembly; C braces display the native entry.
 *
 * CALL0 non-windowed helper; A2 points to a writable 36-byte state area.
 * Stores THREADPTR, ACCLO, ACCHI, BR, SCOMPARE1 and M0-M3 at offsets 0..32.
 * Uses A3 as scratch, preserves A2, and RET returns through A0. No FPU/vector
 * state is stored here; that state belongs to the separate coprocessor payload.
 *
 * Called by: _xt_context_save.
 *
 * Original function-byte SHA-256:
 * b8545114bdbd12d28b9d4295ec8caf578ab239c4322e3c87b933075424d91cc0.
 */

/* Register/field order: THREADPTR +0, ACCLO +4, ACCHI +8, BR +12,
   SCOMPARE1 +16, M0 +20, M1 +24, M2 +28, M3 +32. This 47-byte routine matches
   the ESP32-S3 SDK libxt_hal.a state_asm--save_extra_nw.o reference object.
   Reference: ESP-IDF v5.4.4 components/xtensa/esp32s3/libxt_hal.a.
   Corrected assembly span: 0x4038d6fc..0x4038d72a; SHA-256:
   b8545114bdbd12d28b9d4295ec8caf578ab239c4322e3c87b933075424d91cc0. */

/* These braces display the original assembly body, not a C wrapper
   to compile with an additional compiler-generated prologue. */

/*
 * state: Writable, word-aligned36-byte non-coprocessor register state supplied in A2 under the
 *   CALL0 convention.
 * Returns: CALL0 RET through A0; A2 is preserved and A3 is scratch.
 * Requirements/effects: Stores THREADPTR, ACCLO/ACCHI, BR, SCOMPARE1 and M0-M3 at offsets0..32. No
 *   FPU/vector payload is included; caller owns the buffer and processor context.
 */

void xthal_save_extra_nw(XtensaExtraState *state)
{
  __asm__ volatile (
      "rur.threadptr\ta3\n"
      "s32i.n\ta3, a2, 0\n"
      "rsr.acclo\ta3\n"
      "s32i.n\ta3, a2, 4\n"
      "rsr.acchi\ta3\n"
      "s32i.n\ta3, a2, 8\n"
      "rsr.br\ta3\n"
      "s32i.n\ta3, a2, 12\n"
      "rsr.scompare1\ta3\n"
      "s32i.n\ta3, a2, 16\n"
      "rsr.m0\ta3\n"
      "s32i.n\ta3, a2, 20\n"
      "rsr.m1\ta3\n"
      "s32i.n\ta3, a2, 24\n"
      "rsr.m2\ta3\n"
      "s32i.n\ta3, a2, 28\n"
      "rsr.m3\ta3\n"
      "s32i.n\ta3, a2, 32\n"
      "ret.n\n"
  );
}

/* Native entry: 0x4038d72c. */
/*
 * Medius v3.4.7 — host application; 0x4038d72c.
 * Instruction-reviewed Xtensa assembly; C braces display the native entry.
 *
 * Assembly CALL0 context save with A1 pointing to the existing 192-byte
 * exception frame. Saves A2-A11/A14-A15, SAR, loop registers and 36 bytes of
 * non-coprocessor state. Uses frame scratch slots while preserving live windows,
 * spills all windows with controlled PS/EPC1, and restores its scratch/return
 * registers. Caller already saved A12/A13, A0/A1, PC and PS. No six C arguments.
 *
 * Calls: xthal_save_extra_nw.
 *
 * Called by: FUN_40375854, _xt_user_exc, _xt_syscall_exc, FUN_4037d38c, _frxt_int_enter.
 *
 * Original function-byte SHA-256:
 * fab82f980fbb47025f55f4462ae3f7511ee0650fb87edd60e8a0eb1333032b14.
 */

/* Saved A12/A13 at frame+0x3c/+0x40 must already be valid. The scratch
   words at +0x64/+0x68/+0x6c preserve this helper's A12/A13 and return address.
   Before saving extra state, original A9/A12/A13 are reloaded so register-window
   spills do not capture temporary values. Extra state starts at frame+0x70.
   The spill sequence temporarily clears EXCM, enables WOE, sets INTLEVEL to
   max(old INTLEVEL,3), and saves EPC1. It moves A1 up by 192 into the spill
   region, performs AND/ROTW overflow-triggering steps across all 64 registers,
   then returns A1 down by 192 and restores PS/EPC1 and scratch registers.
   The AND instructions deliberately touch high registers to trigger hardware
   overflow saves; they are not meaningless expressions to delete.
   Reference: ESP-IDF v5.4.4 components/xtensa/xtensa_context.S.
   Corrected assembly span: 0x4038d72c..0x4038d7cf; SHA-256:
   fab82f980fbb47025f55f4462ae3f7511ee0650fb87edd60e8a0eb1333032b14. */

/* These braces display the original assembly body, not a C wrapper
   to compile with an additional compiler-generated prologue. */

/*
 * Returns: CALL0 RET returns to the assembly caller with A1 still addressing its exception frame.
 * Requirements/effects: A1 must address a192-byte frame with A0/A1/PC/PS/A12/A13 already saved.
 *   Saves other GPRs, SAR/loop state and ExtraState36, then spills windows while preserving
 *   scratch/link state.
 */

void _xt_context_save(void)
{
  __asm__ volatile (
      /* Save interrupted register values before using any as scratch. */
      "s32i.n\ta2, a1, 20\n"
      "s32i.n\ta3, a1, 24\n"
      "s32i.n\ta4, a1, 28\n"
      "s32i.n\ta5, a1, 32\n"
      "s32i.n\ta6, a1, 36\n"
      "s32i.n\ta7, a1, 40\n"
      "s32i.n\ta8, a1, 44\n"
      "s32i.n\ta9, a1, 48\n"
      "s32i.n\ta10, a1, 52\n"
      "s32i.n\ta11, a1, 56\n"
      "s32i\ta14, a1, 68\n"
      "s32i\ta15, a1, 72\n"
      "rsr.sar\ta3\n"
      "s32i\ta3, a1, 76\n"
      "rsr.lbeg\ta3\n"
      "s32i\ta3, a1, 88\n"
      "rsr.lend\ta3\n"
      "s32i\ta3, a1, 92\n"
      "rsr.lcount\ta3\n"
      "s32i\ta3, a1, 96\n"
      "mov.n\ta9, a0\n"
      "s32i\ta12, a1, 100\n"
      "s32i\ta13, a1, 104\n"
      "s32i\ta9, a1, 108\n"
      "l32i.n\ta12, a1, 60\n"
      "l32i\ta13, a1, 64\n"
      "l32i.n\ta9, a1, 48\n"
      /* Store the 36-byte extra state at frame+0x70. */
      "addi\ta2, a1, 112\n"
      "call0\txthal_save_extra_nw\n"
      /* Set the temporary processor state for hardware window spilling. */
      "rsr.ps\ta2\n"
      "movi.n\ta0, 15\n"
      "and\ta3, a2, a0\n"
      "bgeui\ta3, 3, .Lsave_4038d784\n"
      "movi\ta3, 3\n"
      ".Lsave_4038d784:\n"
      "l32r\ta0, 0x403752a0\n" /* literal: 0x00040020 */
      "or\ta3, a3, a0\n"
      "wsr.ps\ta3\n"
      "rsr.epc1\ta0\n"
      /* Move up into the spill area and touch/rotate all register windows. */
      "addmi\ta1, a1, 0x100\n"
      "addi\ta1, a1, -64\n"
      "and\ta12, a12, a12\n"
      "rotw\t3\n"
      "and\ta12, a12, a12\n"
      "rotw\t3\n"
      "and\ta12, a12, a12\n"
      "rotw\t3\n"
      "and\ta12, a12, a12\n"
      "rotw\t3\n"
      "and\ta12, a12, a12\n"
      "rotw\t4\n"
      /* Move back to the frame and restore original PS/EPC1 and scratch state. */
      "addmi\ta1, a1, 0xffffff00\n"
      "addi\ta1, a1, 64\n"
      "wsr.ps\ta2\n"
      "rsync\n"
      "wsr.epc1\ta0\n"
      "l32i\ta12, a1, 100\n"
      "l32i\ta13, a1, 104\n"
      "l32i\ta9, a1, 108\n"
      "mov.n\ta0, a9\n"
      "ret.n\n"
  );
}

/* Native entry: 0x4038d7d0. */
/*
 * Medius v3.4.7 — host application; 0x4038d7d0.
 * Instruction-reviewed Xtensa assembly; C braces display the native entry.
 *
 * Assembly CALL0 context restore from the existing frame at A1. Restores
 * THREADPTR, MAC/boolean/compare state, LBEG/LEND/LCOUNT, SAR and A2-A15.
 * Preserves its own return address through A13 while restoring the extra state.
 * Does not restore the interrupted PC, PS, A0 or A1; the exception-exit routine
 * owns those. Restored A2-A5 are not a 16-byte C return value.
 *
 * Calls: xthal_restore_extra_nw.
 *
 * Called by: FUN_40375854, _xt_user_exc, _xt_syscall_exc, _frxt_int_exit, _frxt_dispatch.
 *
 * Original function-byte SHA-256:
 * 7d73629bb02547ce73d52d3b1822eedb69755887872433ca4ab7e7d3e95173cb.
 */

/* Restoration reloads loop state from frame+0x58/+0x5c/+0x60 and SAR
   from +0x4c. Extra state restores THREADPTR and all nine words at +0x70.
   The returning A0 is this helper's CALL0 link, not interrupted A0. A1 remains
   the same frame pointer. Its caller performs the final RFE/RFI or RETW path.
   Reference: ESP-IDF v5.4.4 components/xtensa/xtensa_context.S.
   Corrected assembly span: 0x4038d7d0..0x4038d812; SHA-256:
   7d73629bb02547ce73d52d3b1822eedb69755887872433ca4ab7e7d3e95173cb. */

/* These braces display the original assembly body, not a C wrapper
   to compile with an additional compiler-generated prologue. */

/*
 * Returns: CALL0 RET through this helper link; restored register values are not a C aggregate
 *   result.
 * Requirements/effects: A1 must address a readable192-byte saved frame. Restores A2-A15, SAR/loop
 *   and non-coprocessor state; caller remains responsible for interrupted PC, PS, A0, A1 and the
 *   final architectural return.
 */

void _xt_context_restore(void)
{
  __asm__ volatile (
      /* Preserve CALL0 return link while restoring non-coprocessor extra state. */
      "mov.n\ta13, a0\n"
      "addi\ta2, a1, 112\n"
      "call0\txthal_restore_extra_nw\n"
      "mov.n\ta0, a13\n"
      /* Restore saved hardware loop state. */
      "l32i\ta2, a1, 88\n"
      "l32i\ta3, a1, 92\n"
      "wsr.lbeg\ta2\n"
      "l32i\ta2, a1, 96\n"
      "wsr.lend\ta3\n"
      "wsr.lcount\ta2\n"
      /* Restore SAR and all A2-A15; PC/PS/A0/A1 remain caller-owned. */
      "l32i\ta3, a1, 76\n"
      "l32i.n\ta2, a1, 20\n"
      "wsr.sar\ta3\n"
      "l32i.n\ta3, a1, 24\n"
      "l32i.n\ta4, a1, 28\n"
      "l32i.n\ta5, a1, 32\n"
      "l32i.n\ta6, a1, 36\n"
      "l32i.n\ta7, a1, 40\n"
      "l32i.n\ta8, a1, 44\n"
      "l32i.n\ta9, a1, 48\n"
      "l32i.n\ta10, a1, 52\n"
      "l32i.n\ta11, a1, 56\n"
      "l32i.n\ta12, a1, 60\n"
      "l32i\ta13, a1, 64\n"
      "l32i\ta14, a1, 68\n"
      "l32i\ta15, a1, 72\n"
      "ret.n\n"
  );
}

/* Native entry: 0x4038d814. */
/*
 * Medius v3.4.7 — host application; 0x4038d814.
 *
 * Clears all eight coprocessor owner pointers: four slots for each CPU. Leaves CPENABLE, the
 * owner-table spinlock and task save payloads unchanged. Startup-only initialization with no
 * locking; not a task-state save or memory free.
 *
 * Called by: xPortStartScheduler.
 *
 * Original function-byte SHA-256:
 * 3e670ae41ae9c70a77ffe6a1050592355fa8b96456769b4465b4503a06a68dfc.
 */

/* Clears all eight coprocessor owner pointers: four slots for each CPU. Leaves CPENABLE, the
   owner-table spinlock and task save payloads unchanged. Startup-only initialization with no
   locking; not a task-state save or memory free. Reference: ESP-IDF v5.4.4
   components/xtensa/xtensa_context.S. */

/*
 * Returns: Nothing.
 * Requirements/effects: Startup-only: clears the2x4 coprocessor-owner pointers without their lock.
 *   Does not free payloads or alter CPENABLE.
 */

void _xt_coproc_init(void)
{
    /* Four owner slots per CPU, eight consecutive native pointer stores. */
    for (unsigned int slot = 0; slot < 8U; ++slot)
        XTENSA_COPROCESSOR_OWNER_SLOTS[slot] = 0;
}

/* Native entry: 0x4038d82c. */
/*
 * Medius v3.4.7 — host application; 0x4038d82c.
 * Instruction-reviewed Xtensa assembly; C braces display the native entry.
 *
 * Windowed-ABI cleanup called before deleting a task's coprocessor area.
 * With interrupts masked to level 3 and the shared owner-table spinlock held,
 * clears every matching pointer among the target core's four CP owner slots.
 * Releases the lock and restores PS. Does not free memory, save registers,
 * modify CPENABLE, or validate target_core; the RTOS supplies a valid core.
 *
 * Called by: vPortTCBPreDeleteHook.
 *
 * Original function-byte SHA-256:
 * e0d2f90dfc5d56aa080d5178514d0441f316aa7b35e2c34a8cb676bcb31441fc.
 */

/* The firmware ENTRY a1,16 prologue and RETW are retained below. A2 is
   coproc_header and A3 is target_core after window entry. The spinlock compare
   expects zero and stores raw PRID; a failed S32C1I retries. Pointer matching is
   performed across the entire selected core's four-slot array under that lock.
   Reference: ESP-IDF v5.4.4 components/xtensa/xtensa_context.S.
   Corrected assembly span: 0x4038d82c..0x4038d86c; SHA-256:
   e0d2f90dfc5d56aa080d5178514d0441f316aa7b35e2c34a8cb676bcb31441fc. */

/* The braces display the original assembly body; this recovered export
   is not a C wrapper to compile with an additional compiler prologue. */

/*
 * coproc_header: Header pointer whose matching owner-table slots are cleared; memory is not freed
 *   here.
 * target_core: Target CPU owner-table row0 or1, trusted without a range check.
 * Returns: Windowed RETW after restoring PS.
 * Requirements/effects: Masks interrupts and takes the shared owner-table spinlock, clearing
 *   matches among four slots. Does not save CP registers, alter CPENABLE or free the task payload.
 */

void _xt_coproc_release(XtensaCoprocessorHeader *coproc_header,int target_core)
{
  __asm__ volatile (
      "entry\ta1, 16\n"
      "movi.n\ta4, 16\n"
      "mull\ta4, a3, a4\n"
      "l32r\ta3, 0x40374980\n" /* literal: 0x3fc9e260 */
      "add.n\ta3, a3, a4\n"
      "addi\ta4, a3, 16\n"
      "movi.n\ta5, 0\n"
      "rsil\ta6, 3\n"
      "l32r\ta7, 0x40374984\n" /* literal: 0x3fc9e280 */
      ".Lrelease_4038d844:\n"
      "movi.n\ta8, 0\n"
      "wsr.scompare1\ta8\n"
      "rsync\n"
      "rsr.prid\ta8\n"
      "s32c1i\ta8, a7, 0\n"
      "bnez\ta8, .Lrelease_4038d844\n"
      ".Lrelease_4038d855:\n"
      "l32i.n\ta7, a3, 0\n"
      "bne\ta2, a7, .Lrelease_4038d85c\n"
      "s32i.n\ta5, a3, 0\n"
      ".Lrelease_4038d85c:\n"
      "addi.n\ta3, a3, 4\n"
      "bltu\ta3, a4, .Lrelease_4038d855\n"
      "l32r\ta7, 0x40374984\n" /* literal: 0x3fc9e280 */
      "movi.n\ta8, 0\n"
      "s32i.n\ta8, a7, 0\n"
      "wsr.ps\ta6\n"
      "retw.n\n"
  );
}

/* Native entry: 0x4038d870. */
/*
 * Medius v3.4.7 — host application; 0x4038d870.
 * Instruction-reviewed Xtensa assembly; C braces display the native entry.
 *
 * Assembly CALL0 helper for a solicited context switch. Reads CPENABLE,
 * gets the current task header through A15, and records the enabled mask in
 * header.callee_saved. These S3 macros select no callee-saved CP0/CP3 registers:
 * this compiled routine computes save pointers but writes no register payload.
 * Clobbers A2/A3/A13-A15; preserves A0 across the nested CALL0.
 *
 * Calls: _frxt_task_coproc_state.
 *
 * Called by: vPortYield.
 *
 * Original function-byte SHA-256:
 * cb23977be5cf2cc70e20b0c15ddd6df5394d331a3109fa04bfe8caf7bbea3b01.
 */

/* No ordinary C parameters. CALL0 preserves the assembly return address
   through A14 while _frxt_task_coproc_state returns its result in A15.
   A CPENABLE=0 or A15=0 early exit leaves the saved header unchanged.
   Reference: ESP-IDF v5.4.4 components/xtensa/xtensa_context.S.
   Corrected assembly span: 0x4038d870..0x4038d895; SHA-256:
   cb23977be5cf2cc70e20b0c15ddd6df5394d331a3109fa04bfe8caf7bbea3b01. */

/* The braces display the original assembly body; this recovered export
   is not a C wrapper to compile with an additional compiler prologue. */

/*
 * Returns: CALL0 RET with A0 preserved across the nested helper; no C result.
 * Requirements/effects: Reads CPENABLE and obtains the current header through A15. Records
 *   header.callee_saved. S3 macros select no callee-saved CP0/CP3 payload registers here; pointer
 *   calculation does not imply payload stores.
 */

void _xt_coproc_savecs(void)
{
  __asm__ volatile (
      "rsr.cpenable\ta2\n"
      "beqz.n\ta2, .Lsavecs_4038d894\n"
      "mov.n\ta14, a0\n"
      "call0\t_frxt_task_coproc_state\n"
      "mov.n\ta0, a14\n"
      "beqz.n\ta15, .Lsavecs_4038d894\n"
      "s16i\ta2, a15, 4\n"
      "l32r\ta13, 0x40374988\n" /* literal: 0x3c050ce0 */
      "l32i.n\ta15, a15, 8\n"
      "bbci\ta2, 0, .Lsavecs_4038d88d\n"
      "l32i.n\ta14, a13, 0\n"
      "add.n\ta3, a14, a15\n"
      ".Lsavecs_4038d88d:\n"
      "bbci\ta2, 3, .Lsavecs_4038d894\n"
      "l32i.n\ta14, a13, 12\n"
      "add.n\ta3, a14, a15\n"
      ".Lsavecs_4038d894:\n"
      "ret.n\n"
  );
}

/* Native entry: 0x4038d898. */
/*
 * Medius v3.4.7 — host application; 0x4038d898.
 * Instruction-reviewed Xtensa assembly; C braces display the native entry.
 *
 * Assembly CALL0 helper with the requested coprocessor mask in A2.
 * Gets the current task header in A15 and XOR-clears those previously saved
 * bits. The 32-bit store at header+4 also zeroes header.reserved at +6.
 * These S3 callee-saved macros contain no register loads: full register restore
 * occurs in _xt_coproc_exc. Clobbers A3/A13-A15; preserves A0 and A2.
 *
 * Calls: _frxt_task_coproc_state.
 *
 * Called by: _xt_coproc_exc.
 *
 * Original function-byte SHA-256:
 * 12bddc8a1de93fe7810a2e5df826b2b4cda29bd7826d7b483d549916cc2743c4.
 */

/* A2 must be a subset of header.callee_saved, as ensured by the exception
   caller's intersection. XOR is the instruction in the image, not an arbitrary
   mask removal for unchecked input. With A15=0 it returns without a store.
   Reference: ESP-IDF v5.4.4 components/xtensa/xtensa_context.S.
   Corrected assembly span: 0x4038d898..0x4038d8bd; SHA-256:
   12bddc8a1de93fe7810a2e5df826b2b4cda29bd7826d7b483d549916cc2743c4. */

/* The braces display the original assembly body; this recovered export
   is not a C wrapper to compile with an additional compiler prologue. */

/*
 * Returns: CALL0 RET preserving A0/A2; no C result.
 * Requirements/effects: Requested coprocessor mask arrives in native A2. XOR-updates callee_saved
 *   through a32-bit store that also clears reserved+6. These S3 macros perform no payload loads;
 *   full restore occurs in _xt_coproc_exc.
 */

void _xt_coproc_restorecs(void)
{
  __asm__ volatile (
      "mov.n\ta14, a0\n"
      "call0\t_frxt_task_coproc_state\n"
      "mov.n\ta0, a14\n"
      "beqz.n\ta15, .Lrestorecs_4038d8bc\n"
      "l16ui\ta3, a15, 4\n"
      "xor\ta3, a3, a2\n"
      "s32i.n\ta3, a15, 4\n"
      "l32r\ta13, 0x40374988\n" /* literal: 0x3c050ce0 */
      "l32i.n\ta15, a15, 8\n"
      "bbci\ta2, 0, .Lrestorecs_4038d8b5\n"
      "l32i.n\ta14, a13, 0\n"
      "add.n\ta3, a14, a15\n"
      ".Lrestorecs_4038d8b5:\n"
      "bbci\ta2, 3, .Lrestorecs_4038d8bc\n"
      "l32i.n\ta14, a13, 12\n"
      "add.n\ta3, a14, a15\n"
      ".Lrestorecs_4038d8bc:\n"
      "ret.n\n"
  );
}

