/* Medius v3.4.7 host — platform/vectors.c.
 * Recovered C and native assembly, grouped for source navigation.
 * Original entry addresses, firmware-byte hashes and function comments follow.
 */

#include "../include/types.h"

/* Native entry: 0x40374000. */
/*
 * Medius v3.4.7 — host application; 0x40374000.
 * Native Xtensa assembly; recovered directly from the application image.
 *
 * Spills 4 windowed registers on a CALL4 overflow.
 *
 * Original function-byte SHA-256:
 * 53d68da35c568259ca6a855e79f467c1f9b962694ddc9e10682c6889926e0750.
 */

/* Spills 4 windowed registers on a CALL4 overflow. Stores a0..a3 at [a5-16,-12,-8,-4] in order.
   Ends with RFWO, returning through EPC1 with the architecture-defined
   register-window/exception-state transition. Accesses exactly 4 words (plus one frame-pointer load
   when count>4); caller windows a4..a15 are preserved. No address/capacity checks; valid windowed
   ABI stack frames are required. Hardware side effects are not emulated by this review. */

/* Native Xtensa window entry: register/stack state, not an ordinary C call ABI. */

/*
 * Returns: Architectural RFWO through EPC1; no ordinary C return or scalar/aggregate result.
 * Requirements/effects: Architectural window-overflow vector, with valid PS/window exception
 *   state. A5 addresses the end of the16-byte base-save area; for4 registers no further stack link
 *   is read. Writes interrupted register words before RFWO.
 */

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
/*
 * Medius v3.4.7 — host application; 0x40374040.
 * Native Xtensa assembly; recovered directly from the application image.
 *
 * Restores 4 windowed registers on a CALL4 underflow.
 *
 * Original function-byte SHA-256:
 * 100b10498fd552079b7cb30544a6848a585637835cbe7cf0cd92b21dc8d95195.
 */

/* Restores 4 windowed registers on a CALL4 underflow. Loads a0..a3 at [a5-16,-12,-8,-4] in order.
   Ends with RFWU, returning through EPC1 with the architecture-defined
   register-window/exception-state transition. Accesses exactly 4 words (plus one frame-pointer load
   when count>4); caller windows a4..a15 are preserved. No address/capacity checks; valid windowed
   ABI stack frames are required. Hardware side effects are not emulated by this review. */

/* Native Xtensa window entry: register/stack state, not an ordinary C call ABI. */

/*
 * Returns: Architectural RFWU through EPC1; no ordinary C return or scalar/aggregate result.
 * Requirements/effects: Architectural window-underflow vector, with valid PS/window exception
 *   state. A5 addresses the end of the16-byte base-save area; for4 registers no further stack link
 *   is read. Reads saved register words before RFWU; restored A1 must identify a valid previous
 *   frame when an extended restore is needed.
 */

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
/*
 * Medius v3.4.7 — host application; 0x40374050.
 * Native Xtensa assembly; recovered directly from the application image.
 *
 * Handles MOVSP alloca exception by selecting a window-underflow path.
 *
 * Tail transfers: _WindowUnderflow4, _WindowUnderflow8, _WindowUnderflow12.
 *
 * Called by: _xt_user_exc.
 *
 * Original function-byte SHA-256:
 * 19aef14362bbe59351cfd39070702a3206ca8b3afe84080cf339f68560426237.
 */

/* Handles MOVSP alloca exception by selecting a window-underflow path. Reads WINDOWBASE, rotates
   window back, updates PS.OWB, retrieves EXCSAVE1; tests saved return-address call-size bits and
   rotates again as needed before branching to the CALL4/8/12 underflow vector. The native listing below preserves all three tail transfers and the exact
   privileged/window instructions; RFWU completes the architectural return through EPC1. */

/* Native Xtensa window entry: register/stack state, not an ordinary C call ABI. */

/*
 * Returns: Tail-transfers to the CALL4/8/12 underflow vector; RFWU completes the architectural
 *   return.
 * Requirements/effects: MOVSP alloca-exception entry requires valid saved return-link bits in
 *   EXCSAVE1 and valid window/spill chains. Reads WINDOWBASE, rotates windows, updates PS.OWB and
 *   selects the appropriate restore path; no ordinary C argument list.
 */

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
/*
 * Medius v3.4.7 — host application; 0x40374080.
 * Native Xtensa assembly; recovered directly from the application image.
 *
 * Spills 8 windowed registers on a CALL8 overflow.
 *
 * Original function-byte SHA-256:
 * 6e84a7c3dbdf1bb497f2d01659863009e770720decc9bd73d66fa01576a424e3.
 */

/* Spills 8 windowed registers on a CALL8 overflow. Stores a0 at a9-16, loads previous frame pointer
   from a1-12 into a0, stores a1..a3 at a9-12,-8,-4, then a4..a7 at previous-frame offsets -32
   through -20. Ends with RFWO, returning through EPC1 with the architecture-defined
   register-window/exception-state transition. Accesses exactly 8 words (plus one frame-pointer load
   when count>4); caller windows a8..a15 are preserved. No address/capacity checks; valid windowed
   ABI stack frames are required. Hardware side effects are not emulated by this review. */

/* Native Xtensa window entry: register/stack state, not an ordinary C call ABI. */

/*
 * Returns: Architectural RFWO through EPC1; no ordinary C return or scalar/aggregate result.
 * Requirements/effects: Architectural window-overflow vector, with valid PS/window exception
 *   state. A9 addresses the end of the16-byte base-save area; the linked previous-frame stack area
 *   must also be valid for the extended register words. Writes interrupted register words before
 *   RFWO.
 */

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
/*
 * Medius v3.4.7 — host application; 0x403740c0.
 * Native Xtensa assembly; recovered directly from the application image.
 *
 * Restores 8 windowed registers on a CALL8 underflow.
 *
 * Original function-byte SHA-256:
 * 53270d96e97fe2723bc9d237a5b2489d236a75d30b63a4d69f2e5ea234bd8de6.
 */

/* Restores 8 windowed registers on a CALL8 underflow. Loads a0,a1,a2 from [a9-16,-12,-8], then
   loads previous frame pointer from restored a1-12 into a7. Loads a3 from a9-4 and a4..a7 from the
   previous-frame tail at offsets -32 through -20. The temporary frame pointer is overwritten last.
   Ends with RFWU, returning through EPC1 with the architecture-defined
   register-window/exception-state transition. Accesses exactly 8 words (plus one frame-pointer load
   when count>4); caller windows a8..a15 are preserved. No address/capacity checks; valid windowed
   ABI stack frames are required. Hardware side effects are not emulated by this review. */

/* Native Xtensa window entry: register/stack state, not an ordinary C call ABI. */

/*
 * Returns: Architectural RFWU through EPC1; no ordinary C return or scalar/aggregate result.
 * Requirements/effects: Architectural window-underflow vector, with valid PS/window exception
 *   state. A9 addresses the end of the16-byte base-save area; the linked previous-frame stack area
 *   must also be valid for the extended register words. Reads saved register words before RFWU;
 *   restored A1 must identify a valid previous frame when an extended restore is needed.
 */

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
/*
 * Medius v3.4.7 — host application; 0x40374100.
 * Native Xtensa assembly; recovered directly from the application image.
 *
 * Spills 12 windowed registers on a CALL12 overflow.
 *
 * Original function-byte SHA-256:
 * 344f6e3567b5cbe32a7b0d9dae7f8c61fd14b2709485748f86f23cc4fef9f864.
 */

/* Spills 12 windowed registers on a CALL12 overflow. Stores a0 at a13-16, loads previous frame
   pointer from a1-12 into a0, stores a1..a3 at a13-12,-8,-4, then a4..a11 at previous-frame offsets
   -48 through -20. Ends with RFWO, returning through EPC1 with the architecture-defined
   register-window/exception-state transition. Accesses exactly 12 words (plus one frame-pointer
   load when count>4); caller windows a12..a15 are preserved. No address/capacity checks; valid
   windowed ABI stack frames are required. Hardware side effects are not emulated by this review. */

/* Native Xtensa window entry: register/stack state, not an ordinary C call ABI. */

/*
 * Returns: Architectural RFWO through EPC1; no ordinary C return or scalar/aggregate result.
 * Requirements/effects: Architectural window-overflow vector, with valid PS/window exception
 *   state. A13 addresses the end of the16-byte base-save area; the linked previous-frame stack
 *   area must also be valid for the extended register words. Writes interrupted register words
 *   before RFWO.
 */

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
/*
 * Medius v3.4.7 — host application; 0x40374140.
 * Native Xtensa assembly; recovered directly from the application image.
 *
 * Restores 12 windowed registers on a CALL12 underflow.
 *
 * Called by: _xt_alloca_exc.
 *
 * Original function-byte SHA-256:
 * 4dfb444134c75d4e86c4926b681db3bedf8ce35a96cf058a6fdb4fc721864dcc.
 */

/* Restores 12 windowed registers on a CALL12 underflow. Loads a0,a1,a2 from [a13-16,-12,-8], then
   loads previous frame pointer from restored a1-12 into a11. Loads a3 from a13-4 and a4..a11 from
   the previous-frame tail at offsets -48 through -20. The temporary frame pointer is overwritten
   last. Ends with RFWU, returning through EPC1 with the architecture-defined
   register-window/exception-state transition. Accesses exactly 12 words (plus one frame-pointer
   load when count>4); caller windows a12..a15 are preserved. No address/capacity checks; valid
   windowed ABI stack frames are required. Hardware side effects are not emulated by this review. */

/* Native Xtensa window entry: register/stack state, not an ordinary C call ABI. */

/*
 * Returns: Architectural RFWU through EPC1; no ordinary C return or scalar/aggregate result.
 * Requirements/effects: Architectural window-underflow vector, with valid PS/window exception
 *   state. A13 addresses the end of the16-byte base-save area; the linked previous-frame stack
 *   area must also be valid for the extended register words. Reads saved register words before
 *   RFWU; restored A1 must identify a valid previous frame when an extended restore is needed.
 */

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
/*
 * Medius v3.4.7 — host application; 0x40374180.
 * Instruction-reviewed Xtensa assembly; architectural vector entry.
 *
 * Exception vector for Level2Vector.
 *
 * Calls: _xt_medint2.
 *
 * Original function-byte SHA-256:
 * e60ca6b3574e53e50e486a05eaef7735efb0c8c700b575566ba97ee399992fe7.
 */

/*
 * Returns: Architectural transfer to the handler; no ordinary C return or C result.
 * Requirements/effects: Entered by the processor with the appropriate exception/interrupt state.
 *   Saves the incoming A0 bits in EXCSAVE2, then CALL0-transfers, setting A0 to 0x40374186 to
 *   _xt_medint2 at 0x4037bdbc. These instructions allocate no stack frame and do not acknowledge a
 *   peripheral. The downstream handler supplies context saving and exception return or panic; its
 *   full behavior is a separate entry contract.
 */

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
/*
 * Medius v3.4.7 — host application; 0x403741c0.
 * Instruction-reviewed Xtensa assembly; architectural vector entry.
 *
 * Exception vector for Level3Vector.
 *
 * Calls: _xt_medint3.
 *
 * Original function-byte SHA-256:
 * 464c0b4b97152ad41a61882fa529ab727d8b6481a61d72d202ce3fc11baf1ad6.
 */

/*
 * Returns: Architectural transfer to the handler; no ordinary C return or C result.
 * Requirements/effects: Entered by the processor with the appropriate exception/interrupt state.
 *   Saves the incoming A0 bits in EXCSAVE3, then CALL0-transfers, setting A0 to 0x403741c6 to
 *   _xt_medint3 at 0x4037be6c. These instructions allocate no stack frame and do not acknowledge a
 *   peripheral. The downstream handler supplies context saving and exception return or panic; its
 *   full behavior is a separate entry contract.
 */

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
/*
 * Medius v3.4.7 — host application; 0x40374200.
 * Instruction-reviewed Xtensa assembly; architectural vector entry.
 *
 * Exception vector for Level4Vector.
 *
 * Calls: FUN_40375854.
 *
 * Original function-byte SHA-256:
 * 2b73f7b4efdb6ae38c85481cfb4d4d19b0b105f5a52b377e650e32a424d7a93c.
 */

/*
 * Returns: Architectural transfer to the handler; no ordinary C return or C result.
 * Requirements/effects: Entered by the processor with the appropriate exception/interrupt state.
 *   Saves the incoming A0 bits in EXCSAVE4, then CALL0-transfers, setting A0 to 0x40374206 to
 *   FUN_40375854 at 0x40375854. These instructions allocate no stack frame and do not acknowledge
 *   a peripheral. The downstream handler supplies context saving and exception return or panic;
 *   its full behavior is a separate entry contract.
 */

__asm__(
    ".section .text._Level4Vector,\"ax\",@progbits\n"
    ".global _Level4Vector\n"
    ".type _Level4Vector,@function\n"
    "_Level4Vector:\n"
    "wsr a0,excsave4\n"
    "call0 FUN_40375854\n"
    ".size _Level4Vector,.-_Level4Vector\n"
);

/* Native entry: 0x40374240. */
/*
 * Medius v3.4.7 — host application; 0x40374240.
 * Instruction-reviewed Xtensa assembly; architectural vector entry.
 *
 * Exception vector for Level5Vector.
 *
 * Calls: FUN_4037bf24.
 *
 * Original function-byte SHA-256:
 * ff272b8d78e9151a1b98ca0febdb07ca28f6448be8e3e9a4621b43c3d07cbbb3.
 */

/*
 * Returns: Architectural transfer to the handler; no ordinary C return or C result.
 * Requirements/effects: Entered by the processor with the appropriate exception/interrupt state.
 *   Saves the incoming A0 bits in EXCSAVE5, then CALL0-transfers, setting A0 to 0x40374246 to
 *   FUN_4037bf24 at 0x4037bf24. These instructions allocate no stack frame and do not acknowledge
 *   a peripheral. The downstream handler supplies context saving and exception return or panic;
 *   its full behavior is a separate entry contract.
 */

__asm__(
    ".section .text._Level5Vector,\"ax\",@progbits\n"
    ".global _Level5Vector\n"
    ".type _Level5Vector,@function\n"
    "_Level5Vector:\n"
    "wsr a0,excsave5\n"
    "call0 FUN_4037bf24\n"
    ".size _Level5Vector,.-_Level5Vector\n"
);

/* Native entry: 0x40374280. */
/*
 * Medius v3.4.7 — host application; 0x40374280.
 * Instruction-reviewed Xtensa assembly; architectural vector entry.
 *
 * Exception vector for DebugExceptionVector.
 *
 * Calls: FUN_4037b948.
 *
 * Original function-byte SHA-256:
 * 229497464c3622d04b92e6921b7e8711a14788148bd8f28926fd043935cacc7b.
 */

/*
 * Returns: Architectural transfer to the handler; no ordinary C return or C result.
 * Requirements/effects: Entered by the processor with the appropriate exception/interrupt state.
 *   Saves the incoming A0 bits in EXCSAVE6, then J-transfers without changing A0 to FUN_4037b948
 *   at 0x4037b948. These instructions allocate no stack frame and do not acknowledge a peripheral.
 *   The downstream handler supplies context saving and exception return or panic; its full
 *   behavior is a separate entry contract.
 */

__asm__(
    ".section .text._DebugExceptionVector,\"ax\",@progbits\n"
    ".global _DebugExceptionVector\n"
    ".type _DebugExceptionVector,@function\n"
    "_DebugExceptionVector:\n"
    "wsr a0,excsave6\n"
    "j FUN_4037b948\n"
    ".size _DebugExceptionVector,.-_DebugExceptionVector\n"
);

/* Native entry: 0x403742c0. */
/*
 * Medius v3.4.7 — host application; 0x403742c0.
 * Instruction-reviewed Xtensa assembly; architectural vector entry.
 *
 * Exception vector for NMIExceptionVector.
 *
 * Calls: FUN_4037bf2c.
 *
 * Original function-byte SHA-256:
 * 4f1c737c48dbdd2c5270c820d400b67a63d6ee1928c46f01bae527436d731277.
 */

/*
 * Returns: Architectural transfer to the handler; no ordinary C return or C result.
 * Requirements/effects: Entered by the processor with the appropriate exception/interrupt state.
 *   Saves the incoming A0 bits in EXCSAVE7, then CALL0-transfers, setting A0 to 0x403742c6 to
 *   FUN_4037bf2c at 0x4037bf2c. These instructions allocate no stack frame and do not acknowledge
 *   a peripheral. The downstream handler supplies context saving and exception return or panic;
 *   its full behavior is a separate entry contract.
 */

__asm__(
    ".section .text._NMIExceptionVector,\"ax\",@progbits\n"
    ".global _NMIExceptionVector\n"
    ".type _NMIExceptionVector,@function\n"
    "_NMIExceptionVector:\n"
    "wsr a0,excsave7\n"
    "call0 FUN_4037bf2c\n"
    ".size _NMIExceptionVector,.-_NMIExceptionVector\n"
);

/* Native entry: 0x40374300. */
/*
 * Medius v3.4.7 — host application; 0x40374300.
 * Instruction-reviewed Xtensa assembly; architectural vector entry.
 *
 * Exception vector for KernelExceptionVector.
 *
 * Calls: FUN_4037b960.
 *
 * Original function-byte SHA-256:
 * 7b633105586bfe1f65feecb2eff5cad5d8e7dea69fabfc495416f48b5006d569.
 */

/*
 * Returns: Architectural transfer to the handler; no ordinary C return or C result.
 * Requirements/effects: Entered by the processor with the appropriate exception/interrupt state.
 *   Saves the incoming A0 bits in EXCSAVE1, then CALL0-transfers, setting A0 to 0x40374306 to
 *   FUN_4037b960 at 0x4037b960. These instructions allocate no stack frame and do not acknowledge
 *   a peripheral. The downstream handler supplies context saving and exception return or panic;
 *   its full behavior is a separate entry contract.
 */

__asm__(
    ".section .text._KernelExceptionVector,\"ax\",@progbits\n"
    ".global _KernelExceptionVector\n"
    ".type _KernelExceptionVector,@function\n"
    "_KernelExceptionVector:\n"
    "wsr a0,excsave1\n"
    "call0 FUN_4037b960\n"
    ".size _KernelExceptionVector,.-_KernelExceptionVector\n"
);

/* Native entry: 0x40374340. */
/*
 * Medius v3.4.7 — host application; 0x40374340.
 * Instruction-reviewed Xtensa assembly; architectural vector entry.
 *
 * Exception vector for UserExceptionVector.
 *
 * Calls: _xt_user_exc.
 *
 * Original function-byte SHA-256:
 * 317d17643e2a05fb12d323f49b2d937f05225d729dfffd0935dc23b3bcfed7c0.
 */

/*
 * Returns: Architectural transfer to the handler; no ordinary C return or C result.
 * Requirements/effects: Entered by the processor with the appropriate exception/interrupt state.
 *   Saves the incoming A0 bits in EXCSAVE1, then CALL0-transfers, setting A0 to 0x40374346 to
 *   _xt_user_exc at 0x4037b980. These instructions allocate no stack frame and do not acknowledge
 *   a peripheral. The downstream handler supplies context saving and exception return or panic;
 *   its full behavior is a separate entry contract.
 */

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
/*
 * Medius v3.4.7 — host application; 0x403743c0.
 * Instruction-reviewed Xtensa assembly; architectural vector entry.
 *
 * Routes a double exception into the panic handler.
 *
 * Calls: FUN_4037d38c.
 *
 * Original function-byte SHA-256:
 * 78417574c5d3336c66e25b9f2ee0ddb206c5ba69302a6f50aab6c857f65124ac.
 */

/*
 * Returns: Architectural transfer to the handler; no ordinary C return or C result.
 * Requirements/effects: Entered by the processor with the appropriate exception/interrupt state.
 *   Executes BREAK 1,4. If execution continues, sets A0=2, writes EXCCAUSE=2 and CALL0-transfers
 *   to FUN_4037d38c at 0x4037d38c; that transfer sets A0 to 0x403743cb. These instructions
 *   allocate no stack frame and do not acknowledge a peripheral. The downstream handler supplies
 *   context saving and exception return or panic; its full behavior is a separate entry contract.
 */

__asm__(
    ".section .text._DoubleExceptionVector,\"ax\",@progbits\n"
    ".global _DoubleExceptionVector\n"
    ".type _DoubleExceptionVector,@function\n"
    "_DoubleExceptionVector:\n"
    "break 0x1,0x4\n"
    "movi.n a0,0x2\n"
    "wsr a0,exccause\n"
    "call0 FUN_4037d38c\n"
    ".size _DoubleExceptionVector,.-_DoubleExceptionVector\n"
);

