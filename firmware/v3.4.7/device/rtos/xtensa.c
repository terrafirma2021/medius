/* Medius v3.4.7 device — rtos/xtensa.c.
 * Recovered C and native assembly, grouped for source navigation.
 * Original entry addresses, firmware-byte hashes and function comments follow.
 */

#include "../include/types.h"

/* Native entry: 0x4037d218. */
/* User/level-1 exception entry; EXCSAVE1 holds interrupted A0, EPC1 the
 * interrupted PC, and A1 a valid interrupted stack. This is a processor entry,
 * with no ordinary C arguments or result. EXCCAUSE 4 jumps to _xt_lowint1;
 * causes >=32, 5 and 1 use the coprocessor, alloca and syscall veneers at
 * 0x4037d214, 0x4037d208 and 0x4037d210. Those CALL0 veneers do not return.
 *
 * Other causes allocate a 192-byte XtensaExceptionFrame on the interrupted
 * stack. Save A1/+16, PS/+8, EPC1/+4, EXCSAVE1/+12, A12/+60 and A13/+64,
 * then CALL0 _xt_context_save saves the remaining context and spills windows.
 * Save EXCCAUSE/+80 and EXCVADDR/+84. Backtrace words below A1 hold the
 * interrupted A0/A1; the synthesized link has CALL4 size bits.
 *
 * WSR PS writes 0x00040024: window exceptions enabled, user stack selected,
 * interrupt level 4, EXCM cleared. RSYNC follows the backtrace preparation.
 * Read EXCCAUSE twice as compiled; core is PRID bit 13. Load the handler
 * from 0x3fcab798 + 4 * (2 * cause + core), without a NULL/bounds check.
 * CALLX4 passes the frame in A6 (the handler's A2 after window entry).
 * No exception pre-hook or switch to the RTOS interrupt stack occurs here.
 *
 * After the handler, _xt_context_restore reloads the saved registers. Restore
 * the full PS and EPC1, then A0/A1; RSYNC and RFE resume the saved execution
 * with EXCM cleared. The handler can modify the saved frame before return.
 * Hardware state, stack capacity and handler/frame lifetimes are required;
 * this display must not acquire a compiler-generated C prologue.
 *
 * Primary reference: ESP-IDF components/xtensa/xtensa_vectors.S.
 * Original entry/hash identity includes three separate preceding veneers.
 * Corrected body: 0x4037d218..0x4037d2b1, 154 bytes; SHA-256:
 * 0ae52939812433fa138786c4cbf718b49fe150ff612f1a289c1b5dbeaca1b638.
 * Original function-byte SHA-256:
 * f0bac9b5cd554ecc869038a6969414b7a3273044b7418610a3779eebc8f800a0.
 */

__attribute__((noreturn))
void _xt_user_exc(void)
{
  __asm__ volatile (
      /* Separate interrupt, coprocessor, alloca and syscall paths. */
      "rsr.exccause\ta0\n"
      "bnei\ta0, 4, .Luser_exc_4037d221\n"
      "j\t_xt_lowint1\n"
      ".Luser_exc_4037d221:\n"
      "bgeui\ta0, 32, 0x4037d214\n"
      "beqi\ta0, 5, 0x4037d208\n"
      "beqi\ta0, 1, 0x4037d210\n"
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
      "l32r\ta0, 0x40374a00\n" /* literal: 0x00040024 */
      "wsr.ps\ta0\n"
      "l32i.n\ta3, a1, 12\n"
      "s32e\ta3, a1, -16\n"
      "l32i.n\ta3, a1, 16\n"
      "s32e\ta3, a1, -12\n"
      "rsr.epc1\ta0\n"
      "l32r\ta5, 0x40374804\n" /* literal: 0xc0000000 */
      "rsync\n"
      "or\ta0, a0, a5\n"
      "addx2\ta0, a5, a0\n"
      "rsr.exccause\ta2\n"
      "rsr.exccause\ta2\n"
      "l32r\ta3, 0x40374a04\n" /* literal: 0x3fcab798 */
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

/* Native entry: 0x4037d2b4. */
/* Architectural exception-return tail. A1 already points to a saved
 * XtensaExceptionFrame: PC/+4, PS/+8, A0/+12 and original A1/+16. Load and
 * write the full PS, then EPC1, then restore A0 and A1 in that order.
 * RSYNC completes those special-register writes; RFE resumes EPC1 and clears
 * EXCM. No context helper, register-window rotation or ordinary C epilogue
 * appears here. Other context must already have been restored by the caller.
 * Requires a valid existing frame and matching processor exception state;
 * void(void) displays an assembly entry, with no C arguments/result/prologue.
 * Primary reference: ESP-IDF components/xtensa/xtensa_vectors.S _xt_user_exit.
 * Original function-byte SHA-256:
 * fb89301adde7c58df10a079ddd2b4d28cfd650f96fc30439fbc49090ac79184e.
 */

__attribute__((noreturn))
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

/* Native entry: 0x4037d2c8. */
/* SYSCALL exception entry, reached through the CALL0 veneer at 0x4037d210.
 * EXCSAVE1 holds interrupted A0; EPC1 points to the three-byte SYSCALL;
 * interrupted A2 holds its number. Requires a valid interrupted stack and
 * exception state. No C argument list, prologue or return value is supplied.
 *
 * Allocate a 192-byte scratch XtensaExceptionFrame, save A12/+60 and A13/+64,
 * then CALL0 _xt_context_save to preserve context and spill register windows.
 * Advance EPC1 by 3. If that next PC equals LEND and LCOUNT is nonzero, select
 * LBEG and write LCOUNT-1 before the context-restore call. Crucially, that
 * call reloads LCOUNT from the earlier frame/+0x60: the decrement was never
 * written to the frame. Preserve this native ordering and its consequences.
 *
 * Restore context, remove the 192-byte frame, then MOVNEZ changes restored
 * nonzero A2 to -1; syscall 0 retains zero. Reload A0 from EXCSAVE1 and RFE
 * to updated EPC1, clearing EXCM. There is no ordinary C return or firmware
 * syscall service dispatch beyond these zero/nonzero results.
 * Primary reference: ESP-IDF components/xtensa/xtensa_vectors.S and
 * xtensa_context.S; the original firmware determines the compiled behavior.
 * Body: 0x4037d2c8..0x4037d307, 64 bytes. Original function-byte SHA-256:
 * 5b4fcbd9e379c0c0e9919c6cf6285b3741bd9bab56323dd5ddcfd532c2467ab8.
 */

__attribute__((noreturn))
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
      "bne\ta3, a0, .Lsyscall_4037d2f1\n"
      "rsr.lcount\ta0\n"
      "beqz\ta0, .Lsyscall_4037d2f1\n"
      "addi.n\ta0, a0, -1\n"
      "rsr.lbeg\ta3\n"
      "wsr.lcount\ta0\n"
      ".Lsyscall_4037d2f1:\n"
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

/* Native entry: 0x4037d30c. */
/* SDK local .L_goto_done: one three-byte jump to 0x4037d578, inside
 * _xt_coproc_exc. A1 must still point to that handler's minimal 192-byte
 * exception frame. Preserve registers and transfer without making a new link;
 * the destination restores A2-A7/A15, then _xt_user_exit restores PS/PC/A0/A1
 * and executes RFE. No C arguments, result or independent frame/prologue.
 * Corrected/original span: 0x4037d30c..0x4037d30e. Original byte SHA-256:
 * 0f4dd4d10d9a59cbdd6bf5067013d39e8a31e4b74a5d27c41d3ef6e74d3e9a52.
 */

__attribute__((noreturn))
void xtensa_coprocessor_return_trampoline(void)
{
  __asm__ volatile (
      "j\t0x4037d578\n"
  );
  __builtin_unreachable();
}

/* Native entry: 0x4037d310. */
/* Lazy disabled-coprocessor exception entry for configured CP0 (FPU) and
 * CP3 (vector/AI). Architectural inputs: interrupted A0 in EXCSAVE1, faulting
 * instruction in EPC1, and valid interrupted A1/PS. void(void) is a display
 * convention, not a C argument/result ABI; do not add a compiled prologue.
 *
 * Allocate a 192-byte frame; save A0/A1/PS/PC, exit address _xt_user_exit,
 * A2-A7 and A15, plus A0/A1 backtrace words below the frame. EXCCAUSE-32 is
 * the CP index. CALL0 _frxt_coproc_exc_hook pins task context before CALL0
 * _frxt_task_coproc_state returns its header in A15. Missing header branches
 * through 0x4037d308 to xtensa_coprocessor_panic; ISR use is not supported.
 * These helper results are architectural register contracts, not C returns.
 *
 * Load (index << 16) | (1 << index), OR its low mask into CPENABLE, then
 * select one of two four-pointer owner rows using PRID bit 13. Spin on the
 * shared lock at 0x3fcab9c0: SCOMPARE1=0, RSYNC, S32C1I with raw PRID until
 * the returned old lock word is zero. No timeout or recursive acquisition.
 * Load old owner, publish A15 in the selected 0x3fcab9a0 slot, RSYNC, then
 * unlock with a zero WORD. Payload save/restore occurs AFTER that unlock.
 * Equal owner pointers take the return trampoline without payload accesses.
 *
 * For a nonnull active old owner, clear its enabled HALFWORD bit, set its
 * stored HALFWORD bit, and save to aligned_save_area + CP offset. Offsets for
 * indices 0..3 are {0,72,72,80}; only CP0/CP3 have register payload code.
 * CP0 stores F0-F15, FCR, FSR at 0..68: 72 bytes, alignment 4.
 * CP3 stores ACCX[2], QACC high/low[5], SAR_BYTE, FFT_BIT_WIDTH, UA_STATE[4]
 * at 0..68 and eight 128-bit Q registers at 80..192: 208 bytes, alignment 16.
 * The two WORDs at CP3+72 are untouched. Header and payload are separate;
 * XtensaCoprocessorPayload includes CP0+72, eight alignment bytes, then CP3.
 *
 * If the new stored bit is set, clear it before loading that full payload.
 * Otherwise inspect the callee-saved HALFWORD, pass its matching low-byte
 * mask in A2 to _xt_coproc_restorecs, preserving A13/A14 around that CALL0.
 * If neither stored flag requests restoration, leave CP registers as-is;
 * no fresh-state zeroing or new enabled-HALFWORD store occurs here.
 * Restore A15/A6/A7/A5/A4/A3/A2, then transfer to _xt_user_exit. It restores
 * full PS/EPC1/A0/A1 and RFE retries the faulting instruction. Assume valid
 * configured cause, task/header/payload/table lifetimes and required alignment;
 * no added range checks, ownership pinning or payload validation.
 *
 * Primary: ESP-IDF xtensa_vectors.S and ESP32-S3 config/tie{,-asm}.h.
 * Corrected body: 0x4037d310..0x4037d5a9; SHA-256:
 * fff7b42a2ce0461873f76cfac0a87c7ee5a1348b726b5f13bd2709fd3f629dd8.
 * Original identity retains incomplete/discontiguous Ghidra ranges; SHA-256:
 * 49140f366fcf07815a21f984f762d1af82c11a1b6625053ddf96124bdd05610c.
 */

__attribute__((noreturn))
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
      "l32r\ta0, 0x40374a08\n" /* literal: 0x4037d2b4 */
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
      "beqz\ta15, 0x4037d308\n"
      /* Enable the selected coprocessor and select this core's owner array. */
      "l32r\ta0, 0x40374a0c\n" /* literal: 0x3c0465c0 */
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
      "l32r\ta3, 0x40374a10\n" /* literal: 0x3fcab9a0 */
      "add.n\ta3, a3, a2\n"
      /* Take the global owner-table spinlock with compare-and-swap. */
      "l32r\ta6, 0x40374a14\n" /* literal: 0x3fcab9c0 */
      ".Lhandler_4037d37c:\n"
      "movi.n\ta7, 0\n"
      "wsr.scompare1\ta7\n"
      "rsync\n"
      "rsr.prid\ta7\n"
      "s32c1i\ta7, a6, 0\n"
      "bnez\ta7, .Lhandler_4037d37c\n"
      /* Publish the new owner and synchronize CPENABLE before unlocking. */
      "addx4\ta3, a5, a3\n"
      "l32i.n\ta2, a3, 0\n"
      "s32i.n\ta15, a3, 0\n"
      "rsync\n"
      "l32r\ta6, 0x40374a14\n" /* literal: 0x3fcab9c0 */
      "movi.n\ta7, 0\n"
      "s32i.n\ta7, a6, 0\n"
      /* The existing owner can keep the live registers. */
      "bne\ta15, a2, .Lcp_switch_owner_4037d310\n"
      "j\txtensa_coprocessor_return_trampoline\n"
      ".Lcp_switch_owner_4037d310:\n"
      "beqz\ta2, .Lcp_check_new_4037d310\n"
      "l16ui\ta4, a2, 0\n"
      "bany\ta4, a0, .Lcp_save_old_4037d310\n"
      "j\t.Lcp_check_new_4037d310\n"
      /* Move the active old owner to stored state and find its payload. */
      ".Lcp_save_old_4037d310:\n"
      "l32r\ta5, 0x40374a18\n" /* literal: 0x3c0465a0 */
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
      "bnez.n\ta3, .Lcp_save_vector_4037d310\n"
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
      "j\t.Lcp_check_new_4037d310\n"
      /* Unexecuted linker fill/relaxation bytes between labeled blocks. */
      ".byte 0x00,0x00\n"
      /* CP3 scalar user registers; these are not LBEG/LEND/LCOUNT. */
      ".Lcp_save_vector_4037d310:\n"
      "bnei\ta3, 3, .Lcp_check_new_4037d310\n"
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
      "j\t.Lcp_check_new_4037d310\n"
      /* Check whether the new owner has full saved state. */
      ".Lcp_check_new_4037d310:\n"
      "beqz\ta15, .Lcp_done_4037d310\n"
      "l16ui\ta3, a15, 2\n"
      "l32r\ta4, 0x40374a18\n" /* literal: 0x3c0465a0 */
      "bany\ta3, a0, .Lcp_restore_full_4037d310\n"
      "j\t.Lcp_check_callee_saved_4037d310\n"
      ".Lcp_restore_full_4037d310:\n"
      "xor\ta3, a3, a0\n"
      "s16i\ta3, a15, 2\n"
      "extui\ta3, a0, 16, 5\n"
      "addx4\ta4, a3, a4\n"
      "l32i.n\ta4, a4, 0\n"
      "l32i.n\ta5, a15, 8\n"
      "add.n\ta2, a4, a5\n"
      /* Restore CP0 FPU state, or branch to the CP3 vector state. */
      "bnez.n\ta3, .Lcp_restore_vector_4037d310\n"
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
      "j\t.Lcp_done_4037d310\n"
      /* Unexecuted linker fill/relaxation bytes between labeled blocks. */
      ".byte 0x00,0x00\n"
      /* Restore CP3 scalar and 128-bit vector registers. */
      ".Lcp_restore_vector_4037d310:\n"
      "bnei\ta3, 3, .Lcp_done_4037d310\n"
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
      "j\t.Lcp_done_4037d310\n"
      /* Restore interrupted integer registers and resume through RFE. */
      ".Lcp_done_4037d310:\n"
      "l32i\ta15, a1, 72\n"
      "l32i.n\ta6, a1, 36\n"
      "l32i.n\ta7, a1, 40\n"
      "l32i.n\ta5, a1, 32\n"
      "l32i.n\ta4, a1, 28\n"
      "l32i\ta3, a1, 24\n"
      "l32i\ta2, a1, 20\n"
      "call0\t_xt_user_exit\n"
      /* Only the requested callee-saved mask is handed to the helper. */
      ".Lcp_check_callee_saved_4037d310:\n"
      "l16ui\ta2, a15, 4\n"
      "bnone\ta2, a0, .Lcp_done_4037d310\n"
      "and\ta2, a2, a0\n"
      "extui\ta2, a2, 0, 8\n"
      "s32i\ta13, a1, 64\n"
      "s32i\ta14, a1, 68\n"
      "call0\t_xt_coproc_restorecs\n"
      "l32i\ta13, a1, 64\n"
      "l32i\ta14, a1, 68\n"
      "j\t.Lcp_done_4037d310\n"
  );
  __builtin_unreachable();
}

/* Native entry: 0x4037d5ad. */
/* SDK local .L_xt_coproc_invalid, reached when no task coprocessor header
 * is available. Write EXCCAUSE=4 (software PANIC_RSN_COPROCEXCEPTION), keep
 * A1 unchanged, and CALL0-transfer to native _xt_panic at 0x4037ec24.
 * The panic entry's preserved assembler binding is FUN_4037ec24. No C formal
 * parameters, result, frame allocation, cleanup, unlock or return is supplied.
 * Never falls through into the separate _xt_lowint1 entry below.
 * Corrected 11-byte span: 0x4037d5ad..0x4037d5b7; SHA-256:
 * 3845f680298608912a27f26c95be9e0fb3c4a34b7e99955288f494b08690c1fb.
 * Original identity also includes separate level-1 dispatch ranges; SHA-256:
 * a1a43359dd3b817f0a900bae856096ef90e48110c72e1996f461140a5181ec0b.
 */

__attribute__((noreturn))
void xtensa_coprocessor_panic(void)
{
  __asm__ volatile (
      "movi.n\ta0, 4\n"
      "wsr.exccause\ta0\n"
      "or\ta1, a1, a1\n"
      "call0\tFUN_4037ec24\n" /* SDK _xt_panic; never returns */
  );
  __builtin_unreachable();
}

/* Level-1 interrupt entry; interrupted A0 is in EXCSAVE1, PC in EPC1 and
 * A1 is the interrupted stack. Allocate a 192-byte XtensaExceptionFrame,
 * save A0/A1/PS/PC and _xt_user_exit at +0, then repurpose EXCSAVE1 to hold
 * the frame address. CALL0 _frxt_int_enter saves remaining context, tracks
 * nesting and enters the RTOS interrupt stack. Set full PS=0x00040021 and
 * RSYNC: window exceptions enabled, user stack, level 1, EXCM cleared.
 *
 * Each dispatch rereads INTENABLE and INTERRUPT, intersects both with
 * 0x637ff, and exits if empty. Copy interrupted A0/A1 into the current stack's
 * backtrace spill words and synthesize CALL4 link bits. Repeatedly clear the
 * lowest set bit in a scratch copy to isolate the highest-numbered source;
 * write that source's mask to INTCLEAR before selecting its registered ISR.
 * Level-triggered peripheral flags must be cleared by the ISR itself.
 *
 * Table at 0x3fcab598 contains CpuIsrEntry {handler, argument}, eight bytes
 * each, indexed by interrupt_number*2 + PRID bit 13. Load the handler, retain
 * the compiled A2=A6 scratch move, then load argument into A6. CALLX4 maps it
 * to the C handler's A2. No NULL-handler guard; registration/lifetimes are
 * required. After every ISR return, reread enable/pending state from hardware.
 * No-source path CALL0-transfers to _frxt_int_exit, without returning here;
 * later dispatch uses the frame's saved exit address for architectural return.
 * No C formal arguments/result or compiler-generated wrapper is appropriate.
 *
 * Primary: ESP-IDF xtensa_vectors.S level-1 dispatch. Separate reconstructed
 * entry within the preceding original Ghidra identity; no second native count.
 * Complete span 0x4037d5b8..0x4037d651 includes five unreachable fill bytes.
 * SHA-256: c7213421f4ba63b72ffd667cf77a284835ae89d47018db3a8fdf44d246004619.
 */

__attribute__((noreturn))
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
      "l32r\ta0, 0x40374a08\n" /* literal: 0x4037d2b4 */
      "s32i.n\ta0, a1, 0\n"
      "mov.n\ta0, a1\n"
      "wsr.excsave1\ta0\n"
      "call0\t_frxt_int_enter\n" /* SDK _frxt_int_enter */
      "l32r\ta0, 0x40374a1c\n" /* literal: 0x00040021 */
      "wsr.ps\ta0\n"
      "rsync\n"
      /* Reread enabled/pending level-1 sources for every dispatch. */
      ".Llowint1_4037d5ea:\n"
      "rsr.intenable\ta2\n"
      "rsr.interrupt\ta3\n"
      "l32r\ta4, 0x40374a20\n" /* literal: 0x000637ff */
      "and\ta2, a2, a3\n"
      "and\ta2, a2, a4\n"
      "beqz\ta2, .Llowint1_4037d64c\n"
      "rsr.excsave1\ta0\n"
      "l32i.n\ta3, a0, 12\n"
      "s32e\ta3, a1, -16\n"
      "l32i.n\ta3, a0, 16\n"
      "s32e\ta3, a1, -12\n"
      "rsr.epc1\ta0\n"
      "l32r\ta4, 0x40374804\n" /* literal: 0xc0000000 */
      "or\ta0, a0, a4\n"
      "addx2\ta0, a4, a0\n"
      /* Find the highest numbered pending interrupt, then acknowledge it. */
      ".Llowint1_4037d615:\n"
      "addi.n\ta4, a2, -1\n"
      "and\ta2, a2, a4\n"
      "bnez\ta2, .Llowint1_4037d615\n"
      "addi.n\ta4, a4, 1\n"
      "wsr.intclear\ta4\n"
      "movi.n\ta3, 31\n"
      "nsau\ta4, a4\n"
      "sub\ta3, a3, a4\n"
      /* Select the registered ISR and argument for this CPU. */
      "rsr.prid\ta12\n"
      "extui\ta12, a12, 13, 1\n"
      "addx2\ta3, a3, a12\n"
      "l32r\ta4, 0x40374a24\n" /* literal: 0x3fcab598 */
      "addx8\ta3, a3, a4\n"
      "l32i.n\ta4, a3, 0\n"
      "or\ta2, a6, a6\n"
      "l32i\ta6, a3, 4\n"
      "callx4\ta4\n"
      "j\t.Llowint1_4037d5ea\n"
      /* Unexecuted linker fill/relaxation bytes between labeled blocks. */
      ".byte 0x00,0x00,0x46,0xe7,0xff\n"
      /* No source remains: transfer to RTOS interrupt exit. */
      ".Llowint1_4037d64c:\n"
      "or\ta1, a1, a1\n"
      "call0\t_frxt_int_exit\n" /* SDK _frxt_int_exit; never returns */
  );
  __builtin_unreachable();
}

/* Native entry: 0x4037d654. */
/* Level-2 architectural interrupt entry. EXCSAVE2 holds interrupted A0;
 * EPS2/EPC2 hold saved PS/PC and A1 supplies a valid interrupted stack.
 * Allocate a 192-byte XtensaExceptionFrame and store A1/+16, EPS2/+8,
 * EPC2/+4, A0/+12 and exit dispatcher 0x4037d6f0/+0. Repurpose EXCSAVE2
 * to hold this frame; CALL0 _frxt_int_enter saves the remaining context and
 * manages RTOS nesting/stack selection. Write full PS=0x00040022, then RSYNC.
 *
 * Reread INTENABLE and INTERRUPT on every pass; intersect mask 0x00380000.
 * If nonempty, copy interrupted A0/A1 to the active stack's backtrace spill
 * words and synthesize a CALL4 link. Isolate the highest-numbered pending
 * source by repeatedly clearing its lowest set bit, then write its one-bit
 * mask to INTCLEAR. Peripheral level-triggered flags remain the ISR's job.
 * Select the eight-byte CpuIsrEntry at 0x3fcab598 using interrupt_number*2
 * plus PRID bit 13. Load handler, retain A2=A6 scratch move, load argument
 * into A6 and CALLX4 (callee sees argument in A2). No NULL-handler check,
 * pre-hook, timer-specific dispatch or virtual-priority branch is compiled.
 * Registered handlers/table/arguments and frame/stack lifetimes must be valid.
 *
 * With no source remaining, CALL0-transfer to _frxt_int_exit; it does not
 * return here. Later selected-frame restoration jumps to 0x4037d6f0, which
 * restores EPS2, EPC2, A0 and A1, synchronizes and executes RFI 2.
 * The exit label is independently reachable through frame/+0, not fall-through
 * after interrupt exit. All seven unreachable fill bytes are retained.
 * No ordinary C arguments/result or compiler-generated entry/exit wrapper.
 * Primary: ESP-IDF xtensa_vectors.S and portable/xtensa/portasm.S.
 * Corrected complete span: 0x4037d654..0x4037d703; SHA-256: e5add190806c9b0a00208d0f7d088e3490b3a2826ada7a200c26280f86094489.
 * Original function-byte SHA-256:
 * 707b31af6312987f4e8b1c83f4380f99e7f7059cb05812dea2cc5955dd0ad4bf.
 */

__attribute__((noreturn))
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
      "l32r\ta0, 0x40374a28\n" /* literal: 0x4037d6f0 */
      "s32i.n\ta0, a1, 0\n"
      "mov.n\ta0, a1\n"
      "wsr.excsave2\ta0\n"
      "call0\t_frxt_int_enter\n"
      "l32r\ta0, 0x40374a2c\n" /* literal: 0x00040022 */
      "wsr.ps\ta0\n"
      "rsync\n"
      ".Lmedint2_4037d686:\n"
      "rsr.intenable\ta2\n"
      "rsr.interrupt\ta3\n"
      "l32r\ta4, 0x40374a30\n" /* literal: 0x00380000 */
      "and\ta2, a2, a3\n"
      "and\ta2, a2, a4\n"
      "beqz\ta2, .Lmedint2_4037d6e8\n"
      "rsr.excsave2\ta0\n"
      "l32i.n\ta3, a0, 12\n"
      "s32e\ta3, a1, -16\n"
      "l32i.n\ta3, a0, 16\n"
      "s32e\ta3, a1, -12\n"
      "rsr.epc2\ta0\n"
      "l32r\ta4, 0x40374804\n" /* literal: 0xc0000000 */
      "or\ta0, a0, a4\n"
      "addx2\ta0, a4, a0\n"
      ".Lmedint2_4037d6b1:\n"
      "addi.n\ta4, a2, -1\n"
      "and\ta2, a2, a4\n"
      "bnez\ta2, .Lmedint2_4037d6b1\n"
      "addi.n\ta4, a4, 1\n"
      "wsr.intclear\ta4\n"
      "movi.n\ta3, 31\n"
      "nsau\ta4, a4\n"
      "sub\ta3, a3, a4\n"
      "rsr.prid\ta12\n"
      "extui\ta12, a12, 13, 1\n"
      "addx2\ta3, a3, a12\n"
      "l32r\ta4, 0x40374a24\n" /* literal: 0x3fcab598 */
      "addx8\ta3, a3, a4\n"
      "l32i.n\ta4, a3, 0\n"
      "or\ta2, a6, a6\n"
      "l32i\ta6, a3, 4\n"
      "callx4\ta4\n"
      "j\t.Lmedint2_4037d686\n"
      /* Unexecuted alignment bytes between labeled paths. */
      ".byte 0x0,0x0,0x46,0xe7,0xff\n"
      ".Lmedint2_4037d6e8:\n"
      "or\ta1, a1, a1\n"
      "call0\t_frxt_int_exit\n"
      /* Unexecuted alignment bytes between labeled paths. */
      ".byte 0x0,0x0\n"
      ".L_xt_medint2_exit_4037d654:\n"
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

/* Native entry: 0x4037d704. */
/* Level-3 architectural interrupt entry. EXCSAVE3 holds interrupted A0;
 * EPS3/EPC3 hold saved PS/PC and A1 supplies a valid interrupted stack.
 * Allocate a 192-byte XtensaExceptionFrame and store A1/+16, EPS3/+8,
 * EPC3/+4, A0/+12 and exit dispatcher 0x4037d7a0/+0. Repurpose EXCSAVE3
 * to hold this frame; CALL0 _frxt_int_enter saves the remaining context and
 * manages RTOS nesting/stack selection. Write full PS=0x00040023, then RSYNC.
 *
 * Reread INTENABLE and INTERRUPT on every pass; intersect mask 0x28c08800.
 * If nonempty, copy interrupted A0/A1 to the active stack's backtrace spill
 * words and synthesize a CALL4 link. Isolate the highest-numbered pending
 * source by repeatedly clearing its lowest set bit, then write its one-bit
 * mask to INTCLEAR. Peripheral level-triggered flags remain the ISR's job.
 * Select the eight-byte CpuIsrEntry at 0x3fcab598 using interrupt_number*2
 * plus PRID bit 13. Load handler, retain A2=A6 scratch move, load argument
 * into A6 and CALLX4 (callee sees argument in A2). No NULL-handler check,
 * pre-hook, timer-specific dispatch or virtual-priority branch is compiled.
 * Registered handlers/table/arguments and frame/stack lifetimes must be valid.
 *
 * With no source remaining, CALL0-transfer to _frxt_int_exit; it does not
 * return here. Later selected-frame restoration jumps to 0x4037d7a0, which
 * restores EPS3, EPC3, A0 and A1, synchronizes and executes RFI 3.
 * The exit label is independently reachable through frame/+0, not fall-through
 * after interrupt exit. All seven unreachable fill bytes are retained.
 * No ordinary C arguments/result or compiler-generated entry/exit wrapper.
 * Primary: ESP-IDF xtensa_vectors.S and portable/xtensa/portasm.S.
 * Corrected complete span: 0x4037d704..0x4037d7b3; SHA-256: 1c6946b6f5c61114eddf908f4763d5424db2934554af9d1828aa0417a58bc236.
 * Original function-byte SHA-256:
 * 7628710fac8b7ba7461ea8266114ab59689bad8b045017d0468a883d651a5dde.
 */

__attribute__((noreturn))
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
      "l32r\ta0, 0x40374a34\n" /* literal: 0x4037d7a0 */
      "s32i.n\ta0, a1, 0\n"
      "mov.n\ta0, a1\n"
      "wsr.excsave3\ta0\n"
      "call0\t_frxt_int_enter\n"
      "l32r\ta0, 0x40374a38\n" /* literal: 0x00040023 */
      "wsr.ps\ta0\n"
      "rsync\n"
      ".Lmedint3_4037d736:\n"
      "rsr.intenable\ta2\n"
      "rsr.interrupt\ta3\n"
      "l32r\ta4, 0x40374a3c\n" /* literal: 0x28c08800 */
      "and\ta2, a2, a3\n"
      "and\ta2, a2, a4\n"
      "beqz\ta2, .Lmedint3_4037d798\n"
      "rsr.excsave3\ta0\n"
      "l32i.n\ta3, a0, 12\n"
      "s32e\ta3, a1, -16\n"
      "l32i.n\ta3, a0, 16\n"
      "s32e\ta3, a1, -12\n"
      "rsr.epc3\ta0\n"
      "l32r\ta4, 0x40374804\n" /* literal: 0xc0000000 */
      "or\ta0, a0, a4\n"
      "addx2\ta0, a4, a0\n"
      ".Lmedint3_4037d761:\n"
      "addi.n\ta4, a2, -1\n"
      "and\ta2, a2, a4\n"
      "bnez\ta2, .Lmedint3_4037d761\n"
      "addi.n\ta4, a4, 1\n"
      "wsr.intclear\ta4\n"
      "movi.n\ta3, 31\n"
      "nsau\ta4, a4\n"
      "sub\ta3, a3, a4\n"
      "rsr.prid\ta12\n"
      "extui\ta12, a12, 13, 1\n"
      "addx2\ta3, a3, a12\n"
      "l32r\ta4, 0x40374a24\n" /* literal: 0x3fcab598 */
      "addx8\ta3, a3, a4\n"
      "l32i.n\ta4, a3, 0\n"
      "or\ta2, a6, a6\n"
      "l32i\ta6, a3, 4\n"
      "callx4\ta4\n"
      "j\t.Lmedint3_4037d736\n"
      /* Unexecuted alignment bytes between labeled paths. */
      ".byte 0xc6,0xe7,0xff,0x0,0x0\n"
      ".Lmedint3_4037d798:\n"
      "or\ta1, a1, a1\n"
      "call0\t_frxt_int_exit\n"
      /* Unexecuted alignment bytes between labeled paths. */
      ".byte 0x0,0x0\n"
      ".L_xt_medint3_exit_4037d704:\n"
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

/* Native entry: 0x40386b88. */
/* Set this CPU's pending port-switch WORD to 1. Read PRID, select bit 13,
 * then perform one volatile store at 0x3fcbdd24 + 4*core. Ordinary windowed
 * void(void) API, with no C arguments/result. Repeated requests coalesce.
 * Does not invoke the scheduler, wait for completion, clear the request,
 * send a cross-core interrupt or supply a lock/atomic read-modify-write.
 * Interrupt-exit code consumes the flag; initialized per-CPU state is required.
 * Original function-byte SHA-256:
 * de3032d4115e82ec0c728b7286c5bc8a479459450f6f9fb3c355681d5638ac34.
 */

void _frxt_setup_switch(void)
{
  uint processor_id;
  __asm__ volatile ("rsr.prid %0" : "=a"(processor_id));
  volatile uint *switch_requests = (volatile uint *)0x3fcbdd24U;
  switch_requests[(processor_id >> 13) & 1U] = 1U;
}

/* Native entry: 0x40386ba0. */
/* CALL0-only RTOS interrupt entry; A0 is the helper return link and A1
 * points to an already allocated 192-byte frame. Save A12/+60 and A13/+64,
 * preserve the link in A12, then _xt_context_save saves the remaining context.
 * No ordinary C argument/result ABI or extra compiler prologue is valid.
 *
 * Select CPU via PRID bit 13. If its scheduler WORD at 0x3fcbdd44 is zero,
 * leave nesting and SP unchanged after saving context. Otherwise increment
 * nesting at 0x3fcbdd3c modulo 2^32, store it, and switch stacks only if the
 * new value is exactly 1 and current TCB at 0x3fcbdd1c is nonnull.
 * Store A1 into TCB.top_of_stack/+0 before setting A1 to 0x3fcac610 +
 * 2048*core. That literal is the CPU0 ISR stack TOP, not its lower bound.
 * Nested entries or a missing current TCB retain their existing stack.
 *
 * Restore the CALL0 link from A12 and RET; A1 can now be the ISR stack.
 * No nesting overflow, stack-bound or allocation check; no CPENABLE save/
 * clear sequence is compiled (FPU-in-ISR support is disabled). Valid frame,
 * task and ISR stack capacity are external requirements.
 * Original function-byte SHA-256:
 * 6e9d477107dbdb5a8f29fa717e371533b7e6d016078c0b53278503533d4b76bc.
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
      "l32r\ta2, 0x40374f98\n" /* literal: 0x3fcbdd44 */
      "addx4\ta2, a4, a2\n"
      "l32r\ta3, 0x403746d4\n" /* literal: 0x3fcbdd3c */
      "addx4\ta3, a4, a3\n"
      "l32i.n\ta2, a2, 0\n"
      "beqz.n\ta2, .Lenter_40386be0\n"
      /* Increment nesting only while the scheduler is running. */
      "l32i.n\ta2, a3, 0\n"
      "addi.n\ta2, a2, 1\n"
      "s32i.n\ta2, a3, 0\n"
      "bnei\ta2, 1, .Lenter_40386be0\n"
      "l32r\ta2, 0x40374fd8\n" /* literal: 0x3fcbdd1c */
      "addx4\ta2, a4, a2\n"
      "l32i.n\ta2, a2, 0\n"
      "beqz.n\ta2, .Lenter_40386be0\n"
      /* Outermost task interrupt: save task SP and select the core ISR stack. */
      "s32i.n\ta1, a2, 0\n"
      "l32r\ta1, 0x40374fdc\n" /* literal: 0x3fcac610 */
      "l32r\ta2, 0x403748dc\n" /* literal: 0x00000800 */
      "mull\ta2, a4, a2\n"
      "add.n\ta1, a1, a2\n"
      ".Lenter_40386be0:\n"
      "mov.n\ta0, a12\n"
      "ret.n\n"
  );
}

/* Native entry: 0x40386be4. */
/* CALL0-only nonreturning interrupt exit. Select CPU by PRID bit 13,
 * then RSIL 3 masks low/medium interrupts; its saved full PS in A0 is not
 * restored locally. If scheduler is stopped, restore the existing frame.
 * Otherwise decrement nesting modulo 2^32 without an underflow guard; a
 * nonzero result also restores the existing frame and skips switch handling.
 *
 * On outermost exit with a current TCB, load A1=TCB.top_of_stack/+0 BEFORE
 * reading the core's switch flag. A zero flag restores this task frame;
 * a nonzero flag is cleared before CALL4 vPortYieldFromInt, which saves the
 * task's low-16 CPENABLE and clears hardware CPENABLE. Then CALL0-transfer
 * to _frxt_dispatch. The missing-current-TCB branch also enters that sequence
 * without reloading A1 or reading/clearing the flag; its callee has no NULL
 * guard. Preserve this unchecked path, rather than adding recovery.
 *
 * Restore path calls _xt_context_restore, loads frame.exit_dispatch/+0 into
 * A0 and RET-transfers there; the exit dispatcher restores PS/PC/A0/A1 and
 * performs architectural return. Requires matching live frame/nesting/task
 * state. No ordinary C return, allocation or interrupt acknowledgement.
 * Original function-byte SHA-256:
 * 4ea32392675260c47ffaa78ffe07730d8699d7b03bac2256cc0fd31ec1ab89bc.
 */

__attribute__((noreturn))
void _frxt_int_exit(void)
{
  __asm__ volatile (
      "rsr.prid\ta4\n"
      "extui\ta4, a4, 13, 1\n"
      "l32r\ta2, 0x40374f98\n" /* literal: 0x3fcbdd44 */
      "addx4\ta2, a4, a2\n"
      "l32r\ta3, 0x403746d4\n" /* literal: 0x3fcbdd3c */
      "addx4\ta3, a4, a3\n"
      /* Mask low/medium interrupts before testing nesting. */
      "rsil\ta0, 3\n"
      "l32i.n\ta2, a2, 0\n"
      "beqz.n\ta2, .Lexit_40386c2d\n"
      /* Decrement the current core's nesting count. */
      "l32i.n\ta2, a3, 0\n"
      "addi.n\ta2, a2, -1\n"
      "s32i.n\ta2, a3, 0\n"
      "bnez.n\ta2, .Lexit_40386c2d\n"
      "l32r\ta2, 0x40374fd8\n" /* literal: 0x3fcbdd1c */
      "addx4\ta2, a4, a2\n"
      "l32i.n\ta2, a2, 0\n"
      "beqz.n\ta2, .Lexit_40386c21\n"
      "l32i.n\ta1, a2, 0\n"
      "l32r\ta2, 0x40374fd4\n" /* literal: 0x3fcbdd24 */
      "addx4\ta2, a4, a2\n"
      "l32i.n\ta3, a2, 0\n"
      "beqz.n\ta3, .Lexit_40386c2d\n"
      "movi\ta3, 0\n"
      "s32i\ta3, a2, 0\n"
      /* Save CPENABLE, then tail-dispatch. */
      ".Lexit_40386c21:\n"
      "or\ta1, a1, a1\n"
      "call4\tvPortYieldFromInt\n"
      "or\ta1, a1, a1\n"
      "call0\t_frxt_dispatch\n"
      /* Restore the unchanged task or nested ISR and transfer to frame.exit. */
      ".Lexit_40386c2d:\n"
      "call0\t_xt_context_restore\n"
      "l32i.n\ta0, a1, 0\n"
      "ret.n\n"
  );
  __builtin_unreachable();
}

/* Native entry: 0x40386c34. */
/* Assembly task dispatcher, tail-entered without a C prologue. CALL4
 * vTaskSwitchContext chooses a task. Select current TCB using PRID bit 13,
 * load A1 from its top_of_stack/+0, then write that same TCB back to its
 * current slot as compiled. All subsequent restoration uses the selected
 * task's stack. No NULL-TCB, stack-bound, frame-tag or code-pointer validation.
 *
 * A zero frame/+0 denotes XtensaSolicitedFrame32: load THREADPTR/+12,
 * saved PS/+8 and encoded return link/+4; RSYNC, write full PS, then RETW.
 * This path DOES NOT write CPENABLE. The normal yield caller clears it;
 * the dispatcher itself supplies no independent cleared-state guarantee.
 * Keep RSYNC before WSR PS and the native RETW sequence unchanged.
 *
 * A nonzero tag denotes XtensaExceptionFrame192. Reread current TCB and
 * runtime offsets, derive align_down(task.stack_end-316,16), load the
 * header.enabled HALFWORD and write CPENABLE. _xt_context_restore reloads
 * A2-A15, loop/SAR/non-CP state from selected A1. RSYNC, load exit pointer
 * from frame/+0 into A0, and RET there for final PS/PC/A0/A1 restoration.
 * Architectural resume supplies no C return or invented aggregate result.
 * Original function-byte SHA-256:
 * 7a805f1e5a1f74273b6167cb527408fcf73c7fbd333394834774332a0e2dfe3c.
 */

__attribute__((noreturn))
void _frxt_dispatch(void)
{
  __asm__ volatile (
      /* Let the kernel choose the next ready task. */
      "call4\tvTaskSwitchContext\n"
      "l32r\ta2, 0x40374fd8\n" /* literal: 0x3fcbdd1c */
      "rsr.prid\ta3\n"
      "extui\ta3, a3, 13, 1\n"
      "addx4\ta2, a3, a2\n"
      "l32i\ta3, a2, 0\n"
      "l32i\ta1, a3, 0\n"
      "s32i\ta3, a2, 0\n"
      /* Read the frame tag at the selected task's saved SP. */
      "l32i.n\ta2, a1, 0\n"
      "bnez.n\ta2, .Ldispatch_40386c61\n"
      /* Solicited frame: restore TLS, PS and return link, then RETW. */
      "l32i.n\ta2, a1, 12\n"
      "wur.threadptr\ta2\n"
      "l32i.n\ta3, a1, 8\n"
      "l32i.n\ta0, a1, 4\n"
      "rsync\n"
      "wsr.ps\ta3\n"
      "retw.n\n"
      /* Full frame: restore the task's CPENABLE before processor context. */
      ".Ldispatch_40386c61:\n"
      "l32r\ta2, 0x40374fd8\n" /* literal: 0x3fcbdd1c */
      "rsr.prid\ta3\n"
      "extui\ta3, a3, 13, 1\n"
      "addx4\ta2, a3, a2\n"
      "l32i\ta2, a2, 0\n"
      "l32r\ta3, 0x40374fe0\n" /* literal: 0x3fcace18 */
      "l32i\ta3, a3, 0\n"
      "add\ta2, a2, a3\n"
      "l32i.n\ta2, a2, 0\n"
      "l32r\ta3, 0x40374fe4\n" /* literal: 0x3fcace14 */
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

/* Native entry: 0x40386d30. */
/* CALL0-only coprocessor-header lookup. PRID bit 13 selects this CPU.
 * Return A15=0 if scheduler is stopped, nesting is nonzero or current TCB
 * is NULL. Otherwise load the runtime stack-end field offset from
 * 0x3fcace18 (72), dereference that TCB field, subtract the runtime CPSA
 * offset from 0x3fcace14 (316), and align down to 16 bytes.
 *
 * Return the header pointer in A15, NOT the C result register A2. Only A3
 * and A15 are scratch; A0 is the CALL0 link and A1 is unchanged. No allocation,
 * bounds/lifetime/alignment-input validation or pinning occurs here. Requires
 * valid per-CPU state and a live TCB/stack allocation on the successful path.
 * Original function-byte SHA-256:
 * c3980656bde0c0512edbba55fdb60a1037c1cd40d7d4a2e0228d990b0562a607.
 */

void _frxt_task_coproc_state(void)
{
  __asm__ volatile (
      "rsr.prid\ta3\n"
      "extui\ta3, a3, 13, 1\n"
      "l32r\ta15, 0x40374f98\n" /* literal: 0x3fcbdd44 */
      "addx4\ta15, a3, a15\n"
      "l32i.n\ta15, a15, 0\n"
      "beqz.n\ta15, .Lstate_40386d6c\n"
      "l32r\ta15, 0x403746d4\n" /* literal: 0x3fcbdd3c */
      "addx4\ta15, a3, a15\n"
      "l32i.n\ta15, a15, 0\n"
      "bnez.n\ta15, .Lstate_40386d6c\n"
      "l32r\ta15, 0x40374fd8\n" /* literal: 0x3fcbdd1c */
      "addx4\ta15, a3, a15\n"
      "l32i.n\ta15, a15, 0\n"
      "beqz.n\ta15, .Lstate_40386d6e\n"
      "l32r\ta3, 0x40374fe0\n" /* literal: 0x3fcace18 */
      "l32i.n\ta3, a3, 0\n"
      "add.n\ta15, a15, a3\n"
      "l32i.n\ta15, a15, 0\n"
      "l32r\ta3, 0x40374fe4\n" /* literal: 0x3fcace14 */
      "l32i.n\ta3, a3, 0\n"
      "sub\ta15, a15, a3\n"
      "movi.n\ta3, -16\n"
      "and\ta15, a15, a3\n"
      "ret.n\n"
      ".Lstate_40386d6c:\n"
      "movi.n\ta15, 0\n"
      ".Lstate_40386d6e:\n"
      "ret.n\n"
  );
}

/* Native entry: 0x40386d70. */
/* CALL0-only lazy-coprocessor hook, with no ordinary C arguments/result.
 * PRID bit 13 selects this CPU. If scheduler is stopped or interrupt nesting
 * is nonzero, return without pinning. Otherwise load current TCB, then the
 * runtime core_id offset at 0x3fcace10 (68), and store this CPU into that
 * TCB WORD. This pins subsequent task scheduling before owner-table handling.
 *
 * Uses A2-A4 as scratch, leaves A15 unchanged and RETs through A0. Unlike
 * the header-lookup helper, this path has NO current-TCB NULL check. No task
 * lock, migration handshake, allocation or payload validation is supplied;
 * live TCB and matching exception/kernel state are required.
 * Original function-byte SHA-256:
 * e287f6bdbcdde12c13fdfa6ccfd5c40617bbcaaf819961ca9b7d21d70aa6aae3.
 */

void _frxt_coproc_exc_hook(void)
{
  __asm__ volatile (
      "rsr.prid\ta2\n"
      "extui\ta2, a2, 13, 1\n"
      "l32r\ta3, 0x40374f98\n" /* literal: 0x3fcbdd44 */
      "addx4\ta3, a2, a3\n"
      "l32i.n\ta3, a3, 0\n"
      "beqz.n\ta3, .Lhook_40386d9c\n"
      "l32r\ta3, 0x403746d4\n" /* literal: 0x3fcbdd3c */
      "addx4\ta3, a2, a3\n"
      "l32i.n\ta3, a3, 0\n"
      "bnez.n\ta3, .Lhook_40386d9c\n"
      "l32r\ta3, 0x40374fd8\n" /* literal: 0x3fcbdd1c */
      "addx4\ta3, a2, a3\n"
      "l32i.n\ta3, a3, 0\n"
      "l32r\ta4, 0x40374fec\n" /* literal: 0x3fcace10 */
      "l32i.n\ta4, a4, 0\n"
      "add.n\ta3, a3, a4\n"
      "s32i\ta2, a3, 0\n"
      ".Lhook_40386d9c:\n"
      "ret.n\n"
  );
}

/* Native entry: 0x4039a140. */
/* CALL0 manual register-window spill; SDK alias
 * xthal_spill_registers_into_stack_nw. No ordinary C arguments; diagnostic is
 * returned in A2. Requires prepared window/interrupt state and valid ABI spill
 * areas throughout the saved stack chain. No bounds or capacity checks.
 *
 * Rotate WINDOWSTART around WINDOWBASE+1 using SAR shifts. If the current
 * window bit is unmarked, return 1 before changing WINDOWSTART/WINDOWBASE.
 * Otherwise find the first marked window, update the mask/base, synchronize,
 * and scan the remaining mask. Low set bit 0/1/2 selects CALL4/8/12 layout.
 * CALL4 stores A4-A7 at A9-16..-4, shifts the mask into A6 and ROTW 1.
 * CALL8 stores A4-A7 at A13-16..-4, follows [A5-12], stores A8-A11 at
 * that linked frame's -32..-20, shifts into A10 and ROTW 2.
 * CALL12 ROTW 1 temporarily, stores A0-A3 at A13-16..-4, follows [A1-12],
 * and stores A4-A11 at linked -48..-20. Undo that temporary rotation, shift
 * the mask into A14, then ROTW 3. These are different physical register
 * windows; identically spelled A registers must not become ordinary C locals.
 *
 * Empty mask: ROTW 1, retain only the current WINDOWSTART bit, synchronize,
 * return A2=0. Nonzero mask with no low-three-bit shape reconstructs the
 * remaining WINDOWSTART/WINDOWBASE and returns 2; it does not roll back any
 * earlier spill stores. SAR/window state and scratch registers are affected.
 * Preserve every rotation, native shift and four unreachable fill bytes.
 * Corrected span 0x4039a140..0x4039a250, 273 bytes; SHA-256:
 * cd0fd9e403bc238bd495de1def1033b78203d34fce47ba3519fa7fb5da3f2374.
 * Exact bytes match the primary ESP32-S3 libxt_hal.a windowspill_asm.o symbol;
 * original Ghidra identity omits the four fill bytes and is retained below.
 * Original function-byte SHA-256:
 * 45bd997eff19331c3981ea45063a2b23854c7dddb0ff282707a4d4cc7cbf084a.
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
      "bgez\ta3, .Lspill_4039a214\n"
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
      ".Lspill_4039a17e:\n"
      "beqz\ta2, .Lspill_4039a1fc\n"
      "bbsi\ta2, 0, .Lspill_4039a18d\n"
      "bbsi\ta2, 1, .Lspill_4039a1a1\n"
      "bbsi\ta2, 2, .Lspill_4039a1c5\n"
      "j\t.Lspill_4039a21a\n"
      /* CALL4-shaped spill. */
      ".Lspill_4039a18d:\n"
      "addi\ta3, a9, -16\n"
      "s32i.n\ta4, a3, 0\n"
      "s32i.n\ta5, a3, 4\n"
      "s32i.n\ta6, a3, 8\n"
      "s32i.n\ta7, a3, 12\n"
      "srli\ta6, a2, 1\n"
      "rotw\t1\n"
      "j\t.Lspill_4039a17e\n"
      /* CALL8-shaped spill. */
      ".Lspill_4039a1a1:\n"
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
      "j\t.Lspill_4039a17e\n"
      /* CALL12-shaped spill. */
      ".Lspill_4039a1c5:\n"
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
      "j\t.Lspill_4039a17e\n"
      /* Unexecuted alignment bytes between labeled paths. */
      ".byte 0x0,0x0\n"
      /* Normal completion: retain the current window bit. */
      ".Lspill_4039a1fc:\n"
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
      ".Lspill_4039a214:\n"
      "movi.n\ta2, 1\n"
      "ret.n\n"
      /* Unexecuted alignment bytes between labeled paths. */
      ".byte 0x0,0x0\n"
      /* No valid low-three-bit layout: reconstruct window state and return 2. */
      ".Lspill_4039a21a:\n"
      "slli\ta2, a2, 1\n"
      "addi.n\ta2, a2, 1\n"
      "rsr.windowbase\ta3\n"
      "bbsi\ta2, 15, .Lspill_4039a230\n"
      ".Lspill_4039a225:\n"
      "addi.n\ta3, a3, -1\n"
      "slli\ta2, a2, 1\n"
      "bbci\ta2, 15, .Lspill_4039a225\n"
      "extui\ta3, a3, 0, 4\n"
      ".Lspill_4039a230:\n"
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

/* Native entry: 0x4039a254. */
/* Ordinary windowed void(void) wrapper around CALL0 xthal_window_spill_nw.
 * The native ENTRY allocates 16 bytes. Save full PS in A5 and return link in
 * A4, compute (saved_PS & 0xfffbfff0) + 3, then write PS and RSYNC. This
 * clears WOE and INTLEVEL and selects level 3 while retaining other PS bits.
 * Run the manual spill helper, restore A0 and the full saved PS, RSYNC, RETW.
 * No C arguments or result; discard the helper's A2 diagnostic. Requires a
 * valid windowed stack/spill chain and appropriate processor context. Preserve
 * native assembly; adding a second C prologue would change the contract.
 * Original function-byte SHA-256:
 * 5e86438f5b5672fcfdaf0d0a153940282d395a0cc7eb021f2f0119309e922c72.
 */

void xthal_window_spill(void)
{
  __asm__ volatile (
      "entry\ta1, 16\n"
      "l32r\ta6, 0x40374fe8\n" /* literal: 0xfffbfff0 */
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

/* Native entry: 0x4039a278. */
/* CALL0 extra-state restore. state is the required word-aligned readable
 * XtensaExtraState36 pointer in A2. In order, load WORDs and write THREADPTR,
 * ACCLO, ACCHI, BR, SCOMPARE1 and M0-M3 from +0,+4,+8,+12,+16,+20..+32.
 * A3 is scratch; A2 is preserved and RET uses the CALL0 link in A0. No NULL,
 * length, ownership or privilege check; caller keeps the area live and supplies
 * suitable processor state. No FPU/vector, loop, SAR or PC/PS restoration.
 * const describes readable memory, not a regular windowed-call wrapper.
 * All 47 bytes match primary libxt_hal.a state_asm--restore_extra_nw.o.
 * Original function-byte SHA-256:
 * a46f489283cc93bf7b7deaa7cbad5acda15c46be66ee9f030803fa3ddd4fcc82.
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

/* Native entry: 0x4039a2a8. */
/* CALL0 extra-state save. state is the required word-aligned writable
 * XtensaExtraState36 pointer in A2. In order, read THREADPTR, ACCLO, ACCHI,
 * BR, SCOMPARE1 and M0-M3, storing WORDs at +0,+4,+8,+12,+16,+20..+32.
 * A3 is scratch; preserve A2 and RET through A0. No NULL, length, lock,
 * ownership or privilege validation. Caller owns the live output area and
 * processor context. This excludes FPU/vector, loop/SAR and PC/PS state.
 * The typed parameter documents A2 under CALL0, without a new C wrapper.
 * All 47 bytes match primary libxt_hal.a state_asm--save_extra_nw.o.
 * Original function-byte SHA-256:
 * b8545114bdbd12d28b9d4295ec8caf578ab239c4322e3c87b933075424d91cc0.
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

/* Native entry: 0x4039a2d8. */
/* CALL0 context save. A1 points to an allocated XtensaExceptionFrame192;
 * caller already saved interrupted PC/PS/A0/A1/A12/A13. A0 is this helper's
 * return link. No ordinary C arguments/result or extra entry prologue.
 * Save A2-A11/+20..+56, A14/+68, A15/+72, SAR/+76 and loop state/+88..+96.
 * Temporarily save this helper's A12/A13/link at +100/+104/+108, then reload
 * interrupted A12/A13/A9 before spilling, so temporary values do not leak
 * into ancestor register windows. Save ExtraState36 at frame/+112.
 *
 * Read current PS; temporary PS is 0x40020 | max(old_INTLEVEL,3), clearing
 * EXCM and enabling WOE. Save EPC1, move A1 up 192 bytes into the spill region,
 * then touch A12 and rotate 3,3,3,3,4 windows. The AND A12,A12,A12 operations
 * deliberately trigger overflow saves; do not delete them as algebraic no-ops.
 * Return A1 down 192, restore full PS, RSYNC, then restore EPC1.
 *
 * Reload helper A12/A13 and its link from scratch slots, set A0, RET. A1 and
 * incoming helper A12/A13 are preserved. A9 holds the helper link on return;
 * interrupted A9 remains in frame/+48. Other scratch/SAR values need not be
 * restored here. Requires valid ABI spill chains and exception/window state;
 * no capacity checks, allocation or coprocessor payload save.
 * Original function-byte SHA-256:
 * b253c3d5a81dfd96440fa63afca1ea6acc878146d2e7874fe33eb4e21cdd2a30.
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
      "bgeui\ta3, 3, .Lsave_4039a330\n"
      "movi\ta3, 3\n"
      ".Lsave_4039a330:\n"
      "l32r\ta0, 0x40375690\n" /* literal: 0x00040020 */
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

/* Native entry: 0x4039a37c. */
/* CALL0 context restore from readable XtensaExceptionFrame192 at A1;
 * A0 is this helper's return link. Preserve that link in A13 while restoring
 * ExtraState36 from frame/+112, then recover it. Reload LBEG/+88, LEND/+92,
 * LCOUNT/+96 in native load/write order, SAR/+76 and all A2-A15/+20..+72.
 * Restoring loop_count always uses the saved frame value; an earlier live
 * LCOUNT change is overwritten unless the frame itself was updated.
 *
 * RET uses the helper link; A1 remains the same frame pointer. Caller still
 * owns interrupted PC/PS/A0/A1 and final RFE/RFI. No C aggregate result,
 * frame validation, stack switch or FPU/vector restore. Privileged state and
 * frame lifetime/alignment are external requirements.
 * Original function-byte SHA-256:
 * 7d73629bb02547ce73d52d3b1822eedb69755887872433ca4ab7e7d3e95173cb.
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

/* Native entry: 0x4039a3c0. */
/* Initialize all eight coprocessor-owner pointers at 0x3fcab9a0 through
 * 0x3fcab9bc to NULL, in ascending WORD order: two CPU rows of four slots.
 * Ordinary windowed void(void), no arguments/result. Startup-only without
 * locking; concurrent live ownership is not supported. Does not free any
 * header/payload, clear the shared lock or modify hardware CPENABLE.
 * Original function-byte SHA-256:
 * 973f45811f3812ae8c8b2124f55e13be1e318c3856431f98913d3b74b4162961.
 */

void _xt_coproc_init(void)
{
    /* Four owner slots per CPU, eight consecutive native pointer stores. */
    for (unsigned int slot = 0; slot < 8U; ++slot)
        XTENSA_COPROCESSOR_OWNER_SLOTS[slot] = 0;
}

/* Native entry: 0x4039a3d8. */
/* Windowed cleanup before a task's coprocessor area is deleted. Native
 * ENTRY16 receives coproc_header in A2 and signed target_core in A3. The
 * pointer is compared by identity and never dereferenced; NULL also matches
 * empty slots. Caller keeps referenced areas/state live through this cleanup.
 * target_core must select row 0 or 1: native 16*core address arithmetic is
 * unchecked, with no signed/range/overflow guard for arbitrary inputs.
 *
 * RSIL 3 saves full PS in A6. Take shared owner lock 0x3fcab9c0 using
 * SCOMPARE1=0, RSYNC, raw PRID and retrying S32C1I until old lock value is 0.
 * No timeout or recursive-lock support. Under that lock, scan the selected
 * four-pointer row and zero every matching slot, without stopping at a match.
 * Store zero to unlock, write the full saved PS, then RETW. Preserve the
 * absence of an additional RSYNC between the final WSR PS and RETW.
 * SCOMPARE1 is scratch; it is not restored here. No payload/register save,
 * CPENABLE update, memory free or validation is performed.
 * Original function-byte SHA-256:
 * 022c0ae6e1793c3fe8c5958838726b3448e501e58ad7806dec9135c0a6e98b10.
 */

void _xt_coproc_release(XtensaCoprocessorHeader *coproc_header,int target_core)
{
  __asm__ volatile (
      "entry\ta1, 16\n"
      "movi.n\ta4, 16\n"
      "mull\ta4, a3, a4\n"
      "l32r\ta3, 0x40374a10\n" /* literal: 0x3fcab9a0 */
      "add.n\ta3, a3, a4\n"
      "addi\ta4, a3, 16\n"
      "movi.n\ta5, 0\n"
      "rsil\ta6, 3\n"
      "l32r\ta7, 0x40374a14\n" /* literal: 0x3fcab9c0 */
      ".Lrelease_4039a3f0:\n"
      "movi.n\ta8, 0\n"
      "wsr.scompare1\ta8\n"
      "rsync\n"
      "rsr.prid\ta8\n"
      "s32c1i\ta8, a7, 0\n"
      "bnez\ta8, .Lrelease_4039a3f0\n"
      ".Lrelease_4039a401:\n"
      "l32i.n\ta7, a3, 0\n"
      "bne\ta2, a7, .Lrelease_4039a408\n"
      "s32i.n\ta5, a3, 0\n"
      ".Lrelease_4039a408:\n"
      "addi.n\ta3, a3, 4\n"
      "bltu\ta3, a4, .Lrelease_4039a401\n"
      "l32r\ta7, 0x40374a14\n" /* literal: 0x3fcab9c0 */
      "movi.n\ta8, 0\n"
      "s32i.n\ta8, a7, 0\n"
      "wsr.ps\ta6\n"
      "retw.n\n"
  );
}

/* Native entry: 0x4039a41c. */
/* CALL0 callee-saved coprocessor bookkeeping for a solicited switch.
 * Read CPENABLE into A2; zero returns immediately without looking up a task.
 * Preserve A0 in A14 across _frxt_task_coproc_state, which returns the header
 * in A15. A missing header returns without stores. Otherwise store the low
 * 16 enabled bits in header.callee_saved/+4; reserved/+6 is untouched.
 *
 * Read aligned_save_area/+8 and offset-table entries 0 and 3 when their mask
 * bits are set, calculating CP0/CP3 pointers in A3. This build's callee-saved
 * HAL macros emit NO payload stores; pointer arithmetic does not imply a
 * FPU/vector save. CPENABLE is unchanged. A2 holds the mask, A3/A13-A15 are
 * scratch and RET uses preserved A0; no C arguments/result or new prologue.
 * Original function-byte SHA-256:
 * 86610e253d3e8a4f5ee42fae0c4791ba7f777cc5a28657949d60a038a6df9cf3.
 */

void _xt_coproc_savecs(void)
{
  __asm__ volatile (
      "rsr.cpenable\ta2\n"
      "beqz.n\ta2, .Lsavecs_4039a440\n"
      "mov.n\ta14, a0\n"
      "call0\t_frxt_task_coproc_state\n"
      "mov.n\ta0, a14\n"
      "beqz.n\ta15, .Lsavecs_4039a440\n"
      "s16i\ta2, a15, 4\n"
      "l32r\ta13, 0x40374a18\n" /* literal: 0x3c0465a0 */
      "l32i.n\ta15, a15, 8\n"
      "bbci\ta2, 0, .Lsavecs_4039a439\n"
      "l32i.n\ta14, a13, 0\n"
      "add.n\ta3, a14, a15\n"
      ".Lsavecs_4039a439:\n"
      "bbci\ta2, 3, .Lsavecs_4039a440\n"
      "l32i.n\ta14, a13, 12\n"
      "add.n\ta3, a14, a15\n"
      ".Lsavecs_4039a440:\n"
      "ret.n\n"
  );
}

/* Native entry: 0x4039a444. */
/* CALL0 callee-saved bookkeeping; requested mask arrives in native A2.
 * Preserve A0 in A14 across the header lookup (result A15); missing header
 * returns without a store. Otherwise load the callee_saved HALFWORD at +4,
 * XOR with the full A2 word and store a WORD at +4. This also overwrites
 * reserved/+6. For the actual caller's low-byte subset mask it becomes zero;
 * arbitrary high input bits would be stored, not masked or independently
 * cleared. Missing low bits would be toggled on: preserve XOR semantics.
 *
 * Caller supplies a subset of saved CP bits and valid enabled/task state.
 * Read aligned_save_area/+8 and selected CP0/CP3 offsets to compute A3;
 * these callee-saved HAL macros emit NO payload loads. Full FPU/vector
 * restoration belongs to _xt_coproc_exc. CPENABLE and A2 remain unchanged;
 * A3/A13-A15 are scratch. RET uses preserved A0; no ordinary C formal list.
 * Original function-byte SHA-256:
 * 4b9060c2347cdb6305897d639c0f0f1f6622064f22becf5a14076024da5ea7cd.
 */

void _xt_coproc_restorecs(void)
{
  __asm__ volatile (
      "mov.n\ta14, a0\n"
      "call0\t_frxt_task_coproc_state\n"
      "mov.n\ta0, a14\n"
      "beqz.n\ta15, .Lrestorecs_4039a468\n"
      "l16ui\ta3, a15, 4\n"
      "xor\ta3, a3, a2\n"
      "s32i.n\ta3, a15, 4\n"
      "l32r\ta13, 0x40374a18\n" /* literal: 0x3c0465a0 */
      "l32i.n\ta15, a15, 8\n"
      "bbci\ta2, 0, .Lrestorecs_4039a461\n"
      "l32i.n\ta14, a13, 0\n"
      "add.n\ta3, a14, a15\n"
      ".Lrestorecs_4039a461:\n"
      "bbci\ta2, 3, .Lrestorecs_4039a468\n"
      "l32i.n\ta14, a13, 12\n"
      "add.n\ta3, a14, a15\n"
      ".Lrestorecs_4039a468:\n"
      "ret.n\n"
  );
}

