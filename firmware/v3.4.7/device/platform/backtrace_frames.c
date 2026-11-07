/* Medius v3.4.7 device — platform/backtrace_frames.c.
 * Instruction-checked recovered C and register-window capture assembly.
 */

#include "../include/types.h"

/* Native entry: 0x403760b0. */
/* Original function-byte SHA-256:
 * 993f4274bff1b24d5f341e9280e09396d1777d7791221d682f77ae0258bc89af. */
/*
 * Advance the mutable backtrace cursor by one spilled register-window frame.
 * Cache old SP/next_pc, publish pc=next_pc, read WORD[old_SP-16] into next_pc,
 * then WORD[old_SP-12] into SP. All mutations precede validation. The current
 * stack is dereferenced without first checking its range, alignment or extent;
 * false does not roll back any cursor field. No NULL check or fault handling.
 *
 * New SP may be 16-byte aligned in [0x3fc88010,0x3fcffff0], or anywhere in
 * [0x600fe000,0x600fffff] (no RTC alignment test). Device additionally asks the
 * PSRAM stack predicate whenever the internal aligned test fails. After that
 * call, an admitted PSRAM/RTC path rereads cursor.pc; the fast internal path
 * keeps the cached old next_pc. Preserve that difference if a callee changes
 * cursor storage. Normalize an encoded negative PC to (PC&0x3fffffff)|0x40000000
 * only in a local value, subtract three with WORD wrap, then return the
 * executable-address predicate. No target instruction bytes are decoded.
 * The descriptor's optional exception_frame tail is untouched.
 */
bool esp_backtrace_get_next_frame(volatile BacktraceFrame *cursor)
{
    unsigned int old_sp=cursor->sp;
    unsigned int pc=cursor->next_pc;
    cursor->pc=pc;
    cursor->next_pc=*(const volatile unsigned int *)(old_sp-16U);
    unsigned int next_sp=*(const volatile unsigned int *)(old_sp-12U);
    cursor->sp=next_sp;
    bool aligned_internal=next_sp-0x3fc88010U<=0x77fe0U && (next_sp&15U)==0;
    if (!aligned_internal) {
        if (!esp_stack_ptr_in_extram(next_sp) && next_sp-0x600fe000U>0x1fffU)
            return false;
        pc=cursor->pc;
    }
    if ((pc&0x80000000U)!=0) pc=(pc&0x3fffffffU)|0x40000000U;
    return esp_ptr_executable((const void *)(pc-3U));
}

/* Native entry: 0x40376320. */
/* Original function-byte SHA-256:
 * 974a7227a7f8708ec1e9164df19957f37e0ff9361237c9abdaa1eb5ff06d8c65. */
/*
 * Capture the caller's spilled window into three output WORDs. The native
 * ENTRY allocates32 bytes; xthal_window_spill first materializes the chain.
 * Load saved A0 from this frame's spill-16, store *pc, then load its spill-12
 * link and follow it: store that frame's spill-12 to *sp and spill-16 to
 * *next_pc, in this exact order. Output aliasing can affect later loads.
 * No pointer, stack-range or alignment validation; all outputs must be writable
 * and the windowed ABI spill chain valid. No status or independent lock.
 *
 * These C braces display the complete architectural body, including ENTRY
 * and RETW. Do not add another compiler prologue/epilogue when using it.
 */
void esp_backtrace_get_start(unsigned int *pc,unsigned int *sp,unsigned int *next_pc)
{
    __asm__ volatile (
        "entry a1,32\n"
        "call8 xthal_window_spill\n"
        "l32e a5,a1,-16\n"
        "s32i a5,a2,0\n"
        "l32e a6,a1,-12\n"
        "l32e a5,a6,-12\n"
        "s32i a5,a3,0\n"
        "l32e a5,a6,-16\n"
        "s32i a5,a4,0\n"
        "retw.n\n"
    );
}
