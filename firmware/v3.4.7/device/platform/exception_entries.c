/* Medius v3.4.7 device — platform/exception_entries.c.
 * Instruction-checked recovered exception entries and flash-security wrapper.
 */

#include "../include/types.h"

/* Native entry: 0x4037d1e0. */
/* Original function-byte SHA-256:
 * 1ba3a1bea90a440425674cb3c96858d2dd1c2341e242461a55ab130f1968473a. */
/* Architectural assembly below is displayed inside C braces for source
 * navigation. It is not an ordinary C ABI wrapper: do not insert a compiler
 * prologue/epilogue when reconstructing the native entry. */
/*
 * Debug-exception entry with interrupted A0 already saved in EXCSAVE6.
 * Writes software panic cause 1, copies EPC6 to EPC1 and EXCSAVE6 to EXCSAVE1,
 * then CALL0-transfers to the common panic-frame entry. The following RFI 6
 * remains present if that transfer returns. No C arguments or stack frame,
 * peripheral acknowledgement, EXCVADDR repair or debug-reason decoding here.
 */
void _xt_debugexception(void)
{
    __asm__ volatile (
        "movi.n a0,1\n"
        "wsr.exccause a0\n"
        "rsr.epc6 a0\n"
        "wsr.epc1 a0\n"
        "rsr.excsave6 a0\n"
        "wsr.excsave1 a0\n"
        "call0 FUN_4037ec24\n" /* Common panic-frame entry */
        "rfi 6\n"
    );
}

/* Native entry: 0x4037d1f8. */
/* Original function-byte SHA-256:
 * 47c28f6dd4f6facbba7ed07f16c6e4bc07f1fd72a87c3f0f563a10faebb9e553. */
/* Architectural assembly below is displayed inside C braces for source
 * navigation. It is not an ordinary C ABI wrapper: do not insert a compiler
 * prologue/epilogue when reconstructing the native entry. */
/*
 * Kernel-exception failure entry, with interrupted A0 in EXCSAVE1.
 * Executes BREAK 1,0; if execution continues, writes software panic cause 3
 * and CALL0-transfers to the common panic-frame entry. RFE is the remaining
 * architectural return if that transfer returns. No C arguments, stack frame,
 * device interrupt acknowledgement or cause-dependent dispatch is supplied.
 */
void _xt_kernel_exc(void)
{
    __asm__ volatile (
        "break 1,0\n"
        "movi.n a0,3\n"
        "wsr.exccause a0\n"
        "call0 FUN_4037ec24\n"
        "rfe\n"
    );
}

/* Native entry: 0x4037d7bc. */
/* Original function-byte SHA-256:
 * 710c6a5501090e9ca5bb290950417433af9f7903145e77db42cd61fc5e0e6fc8. */
/* Architectural assembly below is displayed inside C braces for source
 * navigation. It is not an ordinary C ABI wrapper: do not insert a compiler
 * prologue/epilogue when reconstructing the native entry. */
/*
 * Default level-5 interrupt return entry. Restores A0 from EXCSAVE5,
 * then RFI 5 restores processor exception state. No C arguments/result, stack
 * allocation or peripheral acknowledgement. The caller/vector must already
 * have saved A0 and supplied valid level-5 exception state; a still-asserted
 * interrupt source is not cleared by these instructions.
 */
void _xt_highint5(void)
{
    __asm__ volatile (
        "rsr.excsave5 a0\n"
        "rfi 5\n"
    );
}

/* Native entry: 0x4037d7c4. */
/* Original function-byte SHA-256:
 * 2066e94d0ffb39f989aceb9f1deb4284a7a73e509945ccca3826d95593a7240f. */
/* Architectural assembly below is displayed inside C braces for source
 * navigation. It is not an ordinary C ABI wrapper: do not insert a compiler
 * prologue/epilogue when reconstructing the native entry. */
/*
 * Default level-7/NMI return entry. Restores A0 from EXCSAVE7, then
 * RFI 7 restores processor exception state. No C arguments/result, stack
 * allocation, NMI-source service or acknowledgement. Entry requires A0 already
 * saved in EXCSAVE7 and valid level-7 exception state.
 */
void _xt_nmi(void)
{
    __asm__ volatile (
        "rsr.excsave7 a0\n"
        "rfi 7\n"
    );
}

/* Native entry: 0x4037d7cc. */
/* Original function-byte SHA-256:
 * 98349ec0f6c8d394439a04272efdb440477159e0659141348feafd9791faa437. */
/*
 * Return the eFuse HAL's flash-encryption enable result unchanged.
 * No arguments; the result is Boolean parity of SPI_BOOT_CRYPT_CNT. The
 * callee performs the single fenced eFuse WORD read and extracts bits18..20.
 * This wrapper adds no caching, fuse write or image-integrity verification.
 */
bool esp_flash_encryption_enabled(void)
{
    return efuse_hal_flash_encryption_enabled();
}

/* Native entry: 0x4037ec24. */
/* Original function-byte SHA-256:
 * 7fbc071f47aa82e18fd39f43dbeda55dca66c006d3b5e3f9e84df23139ba879a. */
/* Architectural assembly below is displayed inside C braces for source
 * navigation. It is not an ordinary C ABI wrapper: do not insert a compiler
 * prologue/epilogue when reconstructing the native entry. */
/*
 * Common panic entry: build a 192-byte exception frame below A1.
 * Saves old A1 at frame+0x10 and spill-12; PS/PC/A0 at +8/+4/+12, copies
 * interrupted A0 to spill-16, and saves A12/A13 at +0x3c/+0x40 before CALL0
 * context saving. That helper saves remaining registers, loop/extra state and
 * register windows. Frame+0 (normal exit_dispatch) is not initialized here.
 *
 * Copies EXCCAUSE/EXCVADDR to frame+0x50/+0x54, writes PS=0x40024 directly
 * (WOE, user mode, interrupt level4, EXCM clear), and CALL4-passes the frame
 * pointer in A6 to the panic handler. There is no RSYNC after this PS write.
 * The terminal path is expected downstream; the native trailing RET.N is
 * retained with current A0/A1 if the handler returns. It does not restore the
 * frame or execute an exception return. No validation, allocation or locks.
 * Requires valid interrupted stack, EPC1 and interrupted A0 in EXCSAVE1.
 * EXCCAUSE may already contain a software panic reason from a wrapper.
 */
void _xt_panic(void)
{
    __asm__ volatile (
        "mov.n a0,a1\n"
        "addmi a1,a1,-256\n"
        "addi a1,a1,64\n"
        "s32i.n a0,a1,16\n" /* Saved interrupted A1 */
        "s32e a0,a1,-12\n"
        "rsr.ps a0\n"
        "s32i.n a0,a1,8\n"
        "rsr.epc1 a0\n"
        "s32i.n a0,a1,4\n"
        "rsr.excsave1 a0\n"
        "s32i.n a0,a1,12\n"
        "s32e a0,a1,-16\n"
        "s32i.n a12,a1,60\n"
        "s32i a13,a1,64\n"
        "call0 _xt_context_save\n"
        "rsr.exccause a0\n"
        "s32i a0,a1,80\n"
        "rsr.excvaddr a0\n"
        "s32i a0,a1,84\n"
        "l32r a0,0x40374a00\n" /* Original literal WORD: PS=0x00040024 */
        "wsr.ps a0\n"
        "mov.n a6,a1\n" /* CALL4 first argument: frame pointer */
        "call4 FUN_40375ff4\n"
        "ret.n\n"
    );
}
