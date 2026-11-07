/* Medius v3.4.7 host — windowed backtrace printing. */
#include "../include/types.h"

/* Native entry: 0x40375d38. */
/* Original function-byte SHA-256:
 * 1b733611d57762621735ff7609fa3aec22dc00369f6b077700b9cd95fddb53a6. */
/*
 * Print a copied 16-byte register-window cursor, then at most depth additional
 * frames. depth<=0 returns 0x102 before reading frame or producing output.
 * The initial entry is always printed before validation. Encoded negative PCs
 * are normalized to (pc&0x3fffffff)|0x40000000, then reduced by three with
 * unsigned wrap. The caller's cursor is never modified.
 *
 * An initial non-executable PC is accepted only with exception_cause==20
 * (instruction-fetch prohibited) in the optional exception frame. This exception
 * does not waive the stack check and is not used for later frames. The walker
 * mutates its local cursor before reporting failure; even a failed step is
 * printed. Emit CORRUPTED/-1 on invalidity, CONTINUES/0 on depth exhaustion
 * with another PC, otherwise return0, followed by two CRLFs in either mode.
 *
 * panic is a raw low byte: any nonzero value selects the panic output API.
 * No NULL checks, stack pinning, fault recovery, locks or cycle detection.
 * Native stack-range and output configuration differences are retained below.
 */
int esp_backtrace_print_from_frame(int depth,const BacktraceFrame *frame,
                                   unsigned char panic)
{
    if (depth<=0) return 0x102;

    BacktraceFrame cursor;
    memcpy(&cursor,frame,sizeof(cursor));
    if (panic!=0) {
        panic_print_str("\r\n\r\nBacktrace:");
        unsigned int pc=cursor.pc;
        unsigned int sp=cursor.sp;
        if ((pc&0x80000000U)!=0) pc=(pc&0x3fffffffU)|0x40000000U;
        panic_print_str(" 0x");
        panic_print_hex(pc-3U);
        panic_print_str(":0x");
        panic_print_hex(sp);
    } else {
        ets_printf("\r\n\r\nBacktrace:");
        unsigned int pc=cursor.pc;
        unsigned int sp=cursor.sp;
        if ((pc&0x80000000U)!=0) pc=(pc&0x3fffffffU)|0x40000000U;
        ets_printf(" 0x%08lX:0x%08lX",pc-3U,sp);
    }

    bool stack_valid;
    unsigned int sp=cursor.sp;
    /* Internal DRAM requires16-byte alignment; RTC RAM accepts any alignment. */
    if (sp-0x3fc88010U<=0x77fe0U) stack_valid=(sp&15U)==0;
    else stack_valid=sp-0x600fe000U<=0x1fffU;
    bool corrupted=true;
    if (stack_valid) {
        unsigned int pc=cursor.pc;
        if ((pc&0x80000000U)!=0) pc=(pc&0x3fffffffU)|0x40000000U;
        if (esp_ptr_executable((const void *)(pc-3U))) {
            corrupted=false;
        } else if (cursor.exception_frame!=NULL &&
                   cursor.exception_frame->exception_cause==20U) {
            corrupted=false;
        }
    }

    while (cursor.next_pc!=0 && !corrupted) {
        corrupted=!esp_backtrace_get_next_frame(&cursor);
        unsigned int pc=cursor.pc;
        unsigned int next_sp=cursor.sp;
        if ((pc&0x80000000U)!=0) pc=(pc&0x3fffffffU)|0x40000000U;
        unsigned int call_pc=pc-3U;
        if (panic!=0) {
            panic_print_str(" 0x");
            panic_print_hex(call_pc);
            panic_print_str(":0x");
            panic_print_hex(next_sp);
        } else {
            ets_printf(" 0x%08lX:0x%08lX",call_pc,next_sp);
        }
        if (--depth==0) break;
    }

    int status=0;
    if (corrupted) {
        if (panic!=0) panic_print_str(" |<-CORRUPTED");
        else ets_printf(" |<-CORRUPTED");
        status=-1;
    } else if (cursor.next_pc!=0) {
        if (panic!=0) panic_print_str(" |<-CONTINUES");
        else ets_printf(" |<-CONTINUES");
    }
    if (panic!=0) panic_print_str("\r\n\r\n");
    else ets_printf("\r\n\r\n");
    return status;
}

/* Native entry: 0x40375ef4. */
/* Original function-byte SHA-256:
 * 4adba71b459579433ee33ba9efafea359875794a9d01839bd884788c1a2a46d6. */
/*
 * Zero all four cursor WORDs, capture the caller's spilled PC/SP/next-PC via
 * the architectural window-spill helper, then print with panic mode0. Capture
 * occurs even for depth<=0; return the printer's0/-1/0x102 status unchanged.
 * No pointer arguments, independent validation, locks or exception recovery.
 */
int esp_backtrace_print(int depth)
{
    BacktraceFrame start={0};
    esp_backtrace_get_start(&start.pc,&start.sp,&start.next_pc);
    return esp_backtrace_print_from_frame(depth,&start,0);
}
