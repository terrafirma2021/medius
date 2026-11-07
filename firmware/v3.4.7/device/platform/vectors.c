/* Medius v3.4.7 device — native Xtensa register-window and exception vectors. */
#include "../include/types.h"

/* Native entry: 0x40374000. */
/* Original function-byte SHA-256:
 * 53d68da35c568259ca6a855e79f467c1f9b962694ddc9e10682c6889926e0750. */
/* CALL4 window-overflow entry: hardware has rotated to the ancestor window.
 * Spill A0..A3, in order, to A5-16,-12,-8,-4. A5 is the next frame's stack
 * pointer. Preserve A4..A15. RFWO completes the architectural window/exception
 * return through EPC1. Requires valid saved-window stack space; no bounds check,
 * allocation or ordinary C parameters/result. This is register spilling. */
__asm__(
    ".section .text._WindowOverflow4,\"ax\",@progbits\n"
    ".global _WindowOverflow4\n"
    ".type _WindowOverflow4,@function\n"
    "_WindowOverflow4:\n"
    "s32e a0,a5,-0x10\n"
    "s32e a1,a5,-0xc\n"
    "s32e a2,a5,-0x8\n"
    "s32e a3,a5,-0x4\n"
    "rfwo\n"
    ".size _WindowOverflow4,.-_WindowOverflow4\n"
);

/* Native entry: 0x40374040. */
/* Original function-byte SHA-256:
 * 100b10498fd552079b7cb30544a6848a585637835cbe7cf0cd92b21dc8d95195. */
/* CALL4 window-underflow entry: reload A0..A3 from A5-16,-12,-8,-4, in order.
 * A5 is the returning callee's stack pointer. Preserve A4..A15 and finish with
 * RFWU so the interrupted return can resume with the restored caller window.
 * Requires a valid spill area; no extra stack-link read for this four-word case.
 * No ordinary C arguments/result. Underflow means registers need reloading. */
__asm__(
    ".section .text._WindowUnderflow4,\"ax\",@progbits\n"
    ".global _WindowUnderflow4\n"
    ".type _WindowUnderflow4,@function\n"
    "_WindowUnderflow4:\n"
    "l32e a0,a5,-0x10\n"
    "l32e a1,a5,-0xc\n"
    "l32e a2,a5,-0x8\n"
    "l32e a3,a5,-0x4\n"
    "rfwu\n"
    ".size _WindowUnderflow4,.-_WindowUnderflow4\n"
);

/* Native entry: 0x40374050. */
/* Original function-byte SHA-256:
 * 19aef14362bbe59351cfd39070702a3206ca8b3afe84080cf339f68560426237. */
/* MOVSP/alloca exception path. Save WINDOWBASE in A0, rotate back one window
 * so that value is visible as A4, and replace PS.OWB bits 8..11 with that saved
 * base using XOR of old/new bits. EXCSAVE1 restores the interrupted A0 into A4.
 * WSR PS is followed by RSYNC. If saved link bit 31 is clear, branch to
 * _WindowUnderflow4. Otherwise rotate once more; if bit 30 in A8 is clear,
 * branch to _WindowUnderflow8. Otherwise rotate again and jump to
 * _WindowUnderflow12. RFWU in the selected vector supplies exception return.
 * Requires valid saved link/window/spill state; no C argument or result ABI. */
__asm__(
    ".section .text._xt_alloca_exc,\"ax\",@progbits\n"
    ".global _xt_alloca_exc\n"
    ".type _xt_alloca_exc,@function\n"
    "_xt_alloca_exc:\n"
    "rsr a0,WindowBase\n"
    "rotw -0x1\n"
    "rsr a2,PS\n"
    "extui a3,a2,0x8,0x4\n"
    "xor a3,a3,a4\n"
    "rsr a4,EXCSAVE1\n"
    "slli a3,a3,0x8\n"
    "xor a2,a2,a3\n"
    "wsr a2,PS\n"
    "rsync\n"
    "bbci a4,0x1f,_WindowUnderflow4\n"
    "rotw -0x1\n"
    "bbci a8,0x1e,_WindowUnderflow8\n"
    "rotw -0x1\n"
    "j _WindowUnderflow12\n"
    ".size _xt_alloca_exc,.-_xt_alloca_exc\n"
);

/* Native entry: 0x40374080. */
/* Original function-byte SHA-256:
 * 6e84a7c3dbdf1bb497f2d01659863009e770720decc9bd73d66fa01576a424e3. */
/* CALL8 overflow: preserve A8..A15. Store A0 at A9-16 before using A0 for
 * the linked stack pointer read from A1-12. Store A1..A3 at A9-12,-8,-4,
 * then A4..A7 at linked-frame offsets -32,-28,-24,-20. Eight register stores
 * and one stack-link load, then RFWO. Requires both ABI spill areas valid.
 * A0 is scratch after its spill; RFWO rotates back without a C epilogue. */
__asm__(
    ".section .text._WindowOverflow8,\"ax\",@progbits\n"
    ".global _WindowOverflow8\n"
    ".type _WindowOverflow8,@function\n"
    "_WindowOverflow8:\n"
    "s32e a0,a9,-0x10\n"
    "l32e a0,a1,-0xc\n"
    "s32e a1,a9,-0xc\n"
    "s32e a2,a9,-0x8\n"
    "s32e a3,a9,-0x4\n"
    "s32e a4,a0,-0x20\n"
    "s32e a5,a0,-0x1c\n"
    "s32e a6,a0,-0x18\n"
    "s32e a7,a0,-0x14\n"
    "rfwo\n"
    ".size _WindowOverflow8,.-_WindowOverflow8\n"
);

/* Native entry: 0x403740c0. */
/* Original function-byte SHA-256:
 * 53270d96e97fe2723bc9d237a5b2489d236a75d30b63a4d69f2e5ea234bd8de6. */
/* CALL8 underflow: preserve A8..A15. Load A0,A1,A2 from A9-16,-12,-8;
 * use restored A1-12 to load the linked-frame pointer into scratch A7.
 * Load A3 at A9-4, then A4..A7 at linked offsets -32,-28,-24,-20.
 * Reload A7 last so its temporary address remains available. Eight register
 * loads plus one link load, then RFWU; no C parameters/result or validation. */
__asm__(
    ".section .text._WindowUnderflow8,\"ax\",@progbits\n"
    ".global _WindowUnderflow8\n"
    ".type _WindowUnderflow8,@function\n"
    "_WindowUnderflow8:\n"
    "l32e a0,a9,-0x10\n"
    "l32e a1,a9,-0xc\n"
    "l32e a2,a9,-0x8\n"
    "l32e a7,a1,-0xc\n"
    "l32e a3,a9,-0x4\n"
    "l32e a4,a7,-0x20\n"
    "l32e a5,a7,-0x1c\n"
    "l32e a6,a7,-0x18\n"
    "l32e a7,a7,-0x14\n"
    "rfwu\n"
    ".size _WindowUnderflow8,.-_WindowUnderflow8\n"
);

/* Native entry: 0x40374100. */
/* Original function-byte SHA-256:
 * 344f6e3567b5cbe32a7b0d9dae7f8c61fd14b2709485748f86f23cc4fef9f864. */
/* CALL12 overflow: preserve A12..A15. Store A0 at A13-16, then load the
 * linked-frame pointer from A1-12 into A0. Store A1..A3 at A13-12,-8,-4;
 * store A4..A11 at linked offsets -48,-44,-40,-36,-32,-28,-24,-20.
 * Twelve register stores plus one link load, then RFWO. Valid ABI stack
 * chains/spill capacity are required; no C prologue, argument or result. */
__asm__(
    ".section .text._WindowOverflow12,\"ax\",@progbits\n"
    ".global _WindowOverflow12\n"
    ".type _WindowOverflow12,@function\n"
    "_WindowOverflow12:\n"
    "s32e a0,a13,-0x10\n"
    "l32e a0,a1,-0xc\n"
    "s32e a1,a13,-0xc\n"
    "s32e a2,a13,-0x8\n"
    "s32e a3,a13,-0x4\n"
    "s32e a4,a0,-0x30\n"
    "s32e a5,a0,-0x2c\n"
    "s32e a6,a0,-0x28\n"
    "s32e a7,a0,-0x24\n"
    "s32e a8,a0,-0x20\n"
    "s32e a9,a0,-0x1c\n"
    "s32e a10,a0,-0x18\n"
    "s32e a11,a0,-0x14\n"
    "rfwo\n"
    ".size _WindowOverflow12,.-_WindowOverflow12\n"
);

/* Native entry: 0x40374140. */
/* Original function-byte SHA-256:
 * 4dfb444134c75d4e86c4926b681db3bedf8ce35a96cf058a6fdb4fc721864dcc. */
/* CALL12 underflow: preserve A12..A15. Load A0,A1,A2 from A13-16,-12,-8,
 * then load the linked-frame pointer from restored A1-12 into scratch A11.
 * Load A3 at A13-4; load A4..A11 at linked offsets -48 through -20 in
 * four-byte steps. A11 is loaded last, after all other uses of the temporary.
 * Twelve register loads plus one link load, then RFWU; no ordinary C ABI. */
__asm__(
    ".section .text._WindowUnderflow12,\"ax\",@progbits\n"
    ".global _WindowUnderflow12\n"
    ".type _WindowUnderflow12,@function\n"
    "_WindowUnderflow12:\n"
    "l32e a0,a13,-0x10\n"
    "l32e a1,a13,-0xc\n"
    "l32e a2,a13,-0x8\n"
    "l32e a11,a1,-0xc\n"
    "l32e a3,a13,-0x4\n"
    "l32e a4,a11,-0x30\n"
    "l32e a5,a11,-0x2c\n"
    "l32e a6,a11,-0x28\n"
    "l32e a7,a11,-0x24\n"
    "l32e a8,a11,-0x20\n"
    "l32e a9,a11,-0x1c\n"
    "l32e a10,a11,-0x18\n"
    "l32e a11,a11,-0x14\n"
    "rfwu\n"
    ".size _WindowUnderflow12,.-_WindowUnderflow12\n"
);

/* Native entry: 0x40374180. */
/* Original function-byte SHA-256:
 * 9f6fd5a30d4c54912719ab3eb315465a5da5405e15a46f7bce75e34a6e26a618. */
/* Level-2 architectural interrupt stub: save incoming A0 in EXCSAVE2, then
 * CALL0 to _xt_medint2 at 0x4037d654. CALL0 writes A0=0x40374186 without
 * rotating a register window. No stack frame or peripheral acknowledgement
 * here; context save, scheduling and exception return belong to the handler. */
__asm__(
    ".section .text._Level2Vector,\"ax\",@progbits\n"
    ".global _Level2Vector\n"
    ".type _Level2Vector,@function\n"
    "_Level2Vector:\n"
    "wsr a0,excsave2\n"
    "call0 _xt_medint2\n"
    ".size _Level2Vector,.-_Level2Vector\n"
);

/* Native entry: 0x403741c0. */
/* Original function-byte SHA-256:
 * 9d7676eb30ae4b396de088b8ddd2c9cec0747d6e055f414a42a025492a6ccc8c. */
/* Level-3 architectural interrupt stub: save incoming A0 in EXCSAVE3, then
 * CALL0 to _xt_medint3 at 0x4037d704, writing A0=0x403741c6 without window
 * rotation. No C parameter/result, stack allocation or peripheral clear here;
 * the downstream handler owns context save and architectural return. */
__asm__(
    ".section .text._Level3Vector,\"ax\",@progbits\n"
    ".global _Level3Vector\n"
    ".type _Level3Vector,@function\n"
    "_Level3Vector:\n"
    "wsr a0,excsave3\n"
    "call0 _xt_medint3\n"
    ".size _Level3Vector,.-_Level3Vector\n"
);

/* Native entry: 0x40374200. */
/* Original function-byte SHA-256:
 * bc2ca7c0a3c8c386db7aad20604d494746ba0f34d6184a6c665a046c6ce6b009. */
/* Level-4 architectural interrupt stub: save A0 in EXCSAVE4; CALL0 to
 * xt_highint4 at 0x40375bd0, writing A0=0x40374206 without window rotation.
 * FUN_40375bd0 below is its preserved native assembler binding, with recovered
 * xt_highint4 defined in level4_interrupt.c. No frame allocation or IRQ clear. */
__asm__(
    ".section .text._Level4Vector,\"ax\",@progbits\n"
    ".global _Level4Vector\n"
    ".type _Level4Vector,@function\n"
    "_Level4Vector:\n"
    "wsr a0,excsave4\n"
    "call0 FUN_40375bd0\n"
    ".size _Level4Vector,.-_Level4Vector\n"
);

/* Native entry: 0x40374240. */
/* Original function-byte SHA-256:
 * 86a1384076257b67f19764ce0355151a71cdd15306d0cdb18d729bf73d52a5ed. */
/* Level-5 architectural interrupt stub: save A0 in EXCSAVE5; CALL0 to
 * _xt_highint5 at 0x4037d7bc, writing A0=0x40374246 without window rotation.
 * FUN_4037d7bc below binds that recovered handler in exception_entries.c.
 * No ordinary C arguments/result, stack frame or peripheral acknowledgement. */
__asm__(
    ".section .text._Level5Vector,\"ax\",@progbits\n"
    ".global _Level5Vector\n"
    ".type _Level5Vector,@function\n"
    "_Level5Vector:\n"
    "wsr a0,excsave5\n"
    "call0 FUN_4037d7bc\n"
    ".size _Level5Vector,.-_Level5Vector\n"
);

/* Native entry: 0x40374280. */
/* Original function-byte SHA-256:
 * 9134ecb0a46e19fbd43715b861c545fb596cdd508175770b63b9db2a5ed4254f. */
/* Debug exception stub for configured level 6: save A0 in EXCSAVE6, then
 * J to _xt_debugexception at 0x4037d1e0. J leaves A0 unchanged; it supplies
 * no return link or window rotation. FUN_4037d1e0 is the handler's native
 * assembler binding in exception_entries.c. No stack frame or peripheral clear. */
__asm__(
    ".section .text._DebugExceptionVector,\"ax\",@progbits\n"
    ".global _DebugExceptionVector\n"
    ".type _DebugExceptionVector,@function\n"
    "_DebugExceptionVector:\n"
    "wsr a0,excsave6\n"
    "j FUN_4037d1e0\n"
    ".size _DebugExceptionVector,.-_DebugExceptionVector\n"
);

/* Native entry: 0x403742c0. */
/* Original function-byte SHA-256:
 * bb30bcb94bca2735f9fc386e247e007a1fbb28a2d6470ad31bc5aecce3c189e9. */
/* NMI stub for configured level 7: save A0 in EXCSAVE7; CALL0 to _xt_nmi
 * at 0x4037d7c4, writing A0=0x403742c6 without window rotation. The preserved
 * FUN_4037d7c4 assembler binding resolves to _xt_nmi in exception_entries.c.
 * No ordinary C argument/result, frame allocation or peripheral clear here. */
__asm__(
    ".section .text._NMIExceptionVector,\"ax\",@progbits\n"
    ".global _NMIExceptionVector\n"
    ".type _NMIExceptionVector,@function\n"
    "_NMIExceptionVector:\n"
    "wsr a0,excsave7\n"
    "call0 FUN_4037d7c4\n"
    ".size _NMIExceptionVector,.-_NMIExceptionVector\n"
);

/* Native entry: 0x40374300. */
/* Original function-byte SHA-256:
 * 72a2fc3dd7078178007b565904d855d79190d9272c9e1837dd72302c1ba33c57. */
/* Kernel/level-1 exception stub: save A0 in EXCSAVE1; CALL0 to
 * _xt_kernel_exc at 0x4037d1f8, writing A0=0x40374306 without window rotation.
 * FUN_4037d1f8 is the recovered handler's binding in exception_entries.c.
 * No local frame or ordinary C return; downstream code owns panic/return. */
__asm__(
    ".section .text._KernelExceptionVector,\"ax\",@progbits\n"
    ".global _KernelExceptionVector\n"
    ".type _KernelExceptionVector,@function\n"
    "_KernelExceptionVector:\n"
    "wsr a0,excsave1\n"
    "call0 FUN_4037d1f8\n"
    ".size _KernelExceptionVector,.-_KernelExceptionVector\n"
);

/* Native entry: 0x40374340. */
/* Original function-byte SHA-256:
 * 1ede05460fb7f277a4751342bc719a4744b5f2806a1f3f7cc664b4ed17629ae4. */
/* User/level-1 exception stub: save A0 in EXCSAVE1; CALL0 to _xt_user_exc
 * at 0x4037d218, writing A0=0x40374346 without rotating a register window.
 * This includes the path that can route MOVSP to _xt_alloca_exc. No C argument
 * list, local frame, peripheral acknowledgement or exception return here. */
__asm__(
    ".section .text._UserExceptionVector,\"ax\",@progbits\n"
    ".global _UserExceptionVector\n"
    ".type _UserExceptionVector,@function\n"
    "_UserExceptionVector:\n"
    "wsr a0,excsave1\n"
    "call0 _xt_user_exc\n"
    ".size _UserExceptionVector,.-_UserExceptionVector\n"
);

/* Native entry: 0x403743c0. */
/* Original function-byte SHA-256:
 * 7f2c611ec4318993d245e2cf2ebaee40f5b0847ee92e8230be322b9c1df170fe. */
/* Double-exception path: BREAK 1,4 first. If execution continues, set A0=2,
 * write EXCCAUSE=2, then CALL0 to _xt_panic at 0x4037ec24. CALL0 replaces
 * A0 with 0x403743cb. FUN_4037ec24 is its preserved native assembler binding
 * in exception_entries.c. No frame or ordinary C return is supplied here.
 * The four-instruction native range ends at CALL0; no SDK RFDE is invented. */
__asm__(
    ".section .text._DoubleExceptionVector,\"ax\",@progbits\n"
    ".global _DoubleExceptionVector\n"
    ".type _DoubleExceptionVector,@function\n"
    "_DoubleExceptionVector:\n"
    "break 0x1,0x4\n"
    "movi.n a0,0x2\n"
    "wsr a0,exccause\n"
    "call0 FUN_4037ec24\n"
    ".size _DoubleExceptionVector,.-_DoubleExceptionVector\n"
);
