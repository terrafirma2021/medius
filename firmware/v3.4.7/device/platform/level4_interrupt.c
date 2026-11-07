/* Medius v3.4.7 device: platform/level4_interrupt.c. */
#include "../include/types.h"

/* Native entry: 0x40375bd0. */
/* Original function-byte SHA-256:
 * 28fcf95ade2d77c4af5b7a343aa27f1d32681097b9729da0413585c814efcb7e. */
/* Level-4 architectural interrupt entry (Espressif xt_highint4).
 * No ordinary C parameters or return: _Level4Vector has saved interrupted A0
 * in EXCSAVE4. Read INTERRUPT bit 28 first; when set, tail-jump to the native
 * IPC ISR at 0x4037604c without a frame, acknowledgement or panic processing.
 * This branch wins even when other level-4 sources are pending.
 *
 * Otherwise allocate 192 bytes below A1. Save old A1 at frame+16 and spill-12,
 * PS/EPC4/interrupted A0 at +8/+4/+12, A0 also at spill-16, A12/A13 at +60/+64.
 * CALL0 context-save handles remaining registers/windows and extra state.
 * Store EXCVADDR at +84, then freshly sample INTERRUPT bit 25. If set, mask
 * INTENABLE bit 25 (no peripheral acknowledgement) and select cache reason 7.
 * Otherwise read a FULL WORD at 0x3fcbd7ec: zero selects CPU1 watchdog reason 6,
 * any nonzero WORD selects CPU0 watchdog reason 5. This is not a BYTE read.
 * Store that pseudo-cause at frame+80; frame+0 remains uninitialized here.
 *
 * Write PS=0x40025 (WOE, user mode, interrupt level 5, EXCM clear), with no
 * following RSYNC, and CALL4 panic with the borrowed frame pointer in A6.
 * If it returns, CALL0 context-restore, reload PS and EPC4, read frame A0,
 * restore A1, RSYNC, then replace A0 with EXCSAVE4 and RFI 4. Thus an edit of
 * frame A0 does not determine final A0. No lock, MEMW, timeout or validation.
 *
 * Native assembly is emitted directly, without a compiler C prologue. Stack,
 * saved registers and exception return cannot use the ordinary C call ABI.
 * Named frame fields/offsets are in XtensaExceptionFrame. */
void xt_highint4(void);
__asm__(
    ".section .text.FUN_40375bd0,\"ax\",@progbits\n"
    ".p2align 2\n"
    ".literal_position\n"
    ".literal .Llevel4_mask,0xfdffffff\n"
    ".literal .Llevel4_tick,0x3fcbd7ec\n"
    ".literal .Llevel4_ps,0x00040025\n"
    ".literal .Llevel4_ipc,0x4037604c\n"
    ".global FUN_40375bd0\n"
    ".type FUN_40375bd0,@function\n"
    ".begin no-transform\n"
    "FUN_40375bd0:\n"
    "rsr a0,interrupt\n"
    "extui a0,a0,28,1\n"
    "bnez a0,.Llevel4_ipc_dispatch\n"
    "mov.n a0,a1\n"
    "addmi a1,a1,-256\n"
    "addi a1,a1,64\n"
    "s32i.n a0,a1,16\n"
    "s32e a0,a1,-12\n"
    "rsr a0,ps\n"
    "s32i.n a0,a1,8\n"
    "rsr a0,epc4\n"
    "s32i.n a0,a1,4\n"
    "rsr a0,excsave4\n"
    "s32i.n a0,a1,12\n"
    "s32e a0,a1,-16\n"
    "s32i.n a12,a1,60\n"
    "s32i a13,a1,64\n"
    "call0 _xt_context_save\n"
    "rsr a0,excvaddr\n"
    "s32i a0,a1,84\n"
    "rsr a0,interrupt\n"
    "extui a0,a0,25,1\n"
    "beqz.n a0,.Llevel4_watchdog\n"
    "rsr a0,intenable\n"
    "l32r a4,.Llevel4_mask\n"
    "and a0,a4,a0\n"
    "wsr a0,intenable\n"
    "movi.n a0,7\n"
    "j .Llevel4_panic\n"
    ".byte 0\n"
    ".Llevel4_watchdog:\n"
    "l32r a0,.Llevel4_tick\n"
    "l32i.n a0,a0,0\n"
    "bnez.n a0,.Llevel4_watchdog_cpu0\n"
    "movi.n a0,6\n"
    "j .Llevel4_panic\n"
    ".byte 0\n"
    ".Llevel4_watchdog_cpu0:\n"
    "movi a0,5\n"
    ".Llevel4_panic:\n"
    "s32i a0,a1,80\n"
    "l32r a0,.Llevel4_ps\n"
    "wsr a0,ps\n"
    "or a6,a1,a1\n"
    "call4 FUN_40375ff4\n"
    "call0 _xt_context_restore\n"
    "l32i.n a0,a1,8\n"
    "wsr a0,ps\n"
    "l32i.n a0,a1,4\n"
    "wsr a0,epc4\n"
    "l32i.n a0,a1,12\n"
    "l32i.n a1,a1,16\n"
    "rsync\n"
    "rsr a0,excsave4\n"
    "rfi 4\n"
    ".Llevel4_ipc_dispatch:\n"
    "l32r a0,.Llevel4_ipc\n"
    "jx a0\n"
    ".end no-transform\n"
    ".size FUN_40375bd0,.-FUN_40375bd0\n"
    ".previous\n"
);
