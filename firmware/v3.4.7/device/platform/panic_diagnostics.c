/* Medius v3.4.7 device — panic diagnostics and exception classification. */
#include "../include/types.h"

/* Native entry: 0x42002f2c. */
/* Original function-byte SHA-256:
 * 6724180f2a83aa0e0aa54fad613e22565b257e8e10b72615c6d7e0dbe375e4bd. */
/*
 * MEMW/read core0's cache-access fault status low 5 bits. If any is set return 0
 * without reading core1. Otherwise MEMW/read core1 low 5 bits; return 1 if set,
 * or -1 if neither reports a fault. Core0 wins when both are set. No status
 * clearing, latch, retry, lock, or guarantee that the two reads are simultaneous.
 */
int esp_cache_err_get_cpuid(void)
{
    memw();
    if ((PANIC_CACHE->core0_access_fault & PANIC_CACHE_ACCESS_FAULT_MASK) != 0)
        return 0;
    memw();
    return (PANIC_CACHE->core1_access_fault & PANIC_CACHE_ACCESS_FAULT_MASK) != 0 ? 1 : -1;
}

/* Native entry: 0x420034e8. */
/* Original function-byte SHA-256:
 * 3efcb0f48f32a1ebd413543034a5f1fa1398803a196cd80e1588ff7a0627ad8f. */
/*
 * Snapshot core0's saved-frame pointer once. Treat current_frame as core0 only
 * if it equals that snapshot, otherwise as core1, even if neither slot matches.
 * Unless the raw abort flag is nonzero, dump current registers and CRLF; always
 * print its backtrace and CRLF. Then load the opposite core's saved frame once
 * and, if non-NULL, repeat using a fresh abort-byte read. The current frame is
 * neither checked for NULL nor required to belong to either saved slot.
 * No frame lifetime protection, coherent cross-core snapshot or lock; device
 * output APIs are empty stubs but the frame reads/backtrace work still occur.
 */
void panic_dump_frames(const void *current_frame)
{
    const XtensaExceptionFrame *core0_frame=PANIC_FRAMES[0];
    int core=core0_frame!=current_frame;
    if (PANIC_ABORT_IN_PROGRESS==0) {
        panic_print_registers(current_frame,core);
        panic_print_str("\r\n");
    }
    panic_print_frame_backtrace(current_frame,core);
    panic_print_str("\r\n");

    int other_core=core^1;
    const XtensaExceptionFrame *other=PANIC_FRAMES[other_core];
    if (other!=NULL) {
        if (PANIC_ABORT_IN_PROGRESS==0) {
            panic_print_registers(other,other_core);
            panic_print_str("\r\n");
        }
        panic_print_frame_backtrace(other,other_core);
        panic_print_str("\r\n");
    }
}

/* Native entry: 0x420035a4. */
/* Original function-byte SHA-256:
 * d453ecce26843b0c108de2cebe007e729bf2403821b7fd0b9c9a809f570dc559. */
/*
 * Snapshot DEBUGCAUSE once and report each of bits0..5 in order: single-step,
 * instruction breakpoint, data watchpoint, BREAK, BREAKN, debug interrupt.
 * When bit2 is set, bit8 selects watchpoint1 rather than0. Other bits are
 * ignored. The callback frame argument is unused; no task-name lookup, status
 * clearing, newline, lock or state change beyond the output calls. On the
 * device these output calls do nothing, but the special-register read remains.
 */
void panic_debug_details(const void *unused_frame)
{
    unsigned int cause;
    __asm__ volatile("rsr.debugcause %0" : "=a"(cause));
    panic_print_str("Debug exception reason: ");
    if ((cause&1U)!=0) panic_print_str("SingleStep ");
    if ((cause&2U)!=0) panic_print_str("HwBreakpoint ");
    if ((cause&4U)!=0) {
        if ((cause&0x100U)!=0) panic_print_str("Watchpoint 1 triggered ");
        else panic_print_str("Watchpoint 0 triggered ");
    }
    if ((cause&8U)!=0) panic_print_str("BREAK instr ");
    if ((cause&16U)!=0) panic_print_str("BREAKN instr ");
    if ((cause&32U)!=0) panic_print_str("DebugIntr ");
}

/* Native entry: 0x420035f4. */
/* Original function-byte SHA-256:
 * 3bc96a65f6660f2c91cf95f739e649e029bdbffe11f2461c0e709110f0cf8a7d. */
/*
 * Read the frame PC, align down to 4 bytes, then subtract 4 with WORD wrap.
 * Admit start addresses 0x40000000..0x43ffffff and print three WORDs beginning
 * there, each preceded by MEMW. The final two reads are not independently
 * range-checked; start 0x43fffffc crosses the upper boundary. No byte-access
 * fallback, mapping validation, NULL check, fault recovery or trailing newline.
 * Device panic output is disabled, but all three native memory reads still run.
 */
void panic_illegal_instruction_details(const void *saved_frame)
{
    const volatile XtensaExceptionFrame *frame=saved_frame;
    unsigned int address=((unsigned int)frame->pc&~3U)-4U;
    if (address-0x40000000U>0x03ffffffU) return;
    const volatile unsigned int *instructions=(const volatile unsigned int *)address;
    panic_print_str("Memory dump at 0x");
    panic_print_hex(address);
    panic_print_str(": ");
    memw();
    unsigned int word=instructions[0];
    panic_print_hex(word);
    panic_print_str(" ");
    memw();
    word=instructions[1];
    panic_print_hex(word);
    panic_print_str(" ");
    memw();
    word=instructions[2];
    panic_print_hex(word);
}

/* Native entry: 0x42003648. */
/* Original function-byte SHA-256:
 * 6fa28f0f1e3569bac21c19a614430d975a88134a2929a0b5a36135113c89fb84. */
/*
 * Snapshot cache debug status once (MEMW), then scan all 32 bits low to high.
 * Bits0/2 report I/D sync-size faults without reading address/size registers:
 * they reuse the carried address/size, initially0. Bits1/3 refresh that pair
 * from I/D preload registers before reporting it. Thus a D-sync fault can show
 * an earlier I-preload pair. Bit4 emits writeback/backtrace warnings. Bit5
 * reads the MMU fault address, prints it, then separately MEMW/reads content
 * bit14 for the invalid-entry suffix. This also updates the carried address.
 * Other bits are ignored; always append CRLF. No status clear, polling, lock
 * or simultaneous-register snapshot. The frame callback argument is unused.
 * Device output is disabled; register reads, scan and barriers still occur.
 */
void panic_cache_details(const void *unused_frame)
{
    memw();
    unsigned int status=PANIC_CACHE->debug_status;
    unsigned int address=0,size=0;
    for (unsigned int bit=0;bit<32U;++bit) {
        const char *description;
        switch (status&(1U<<bit)) {
        case 1U:
            description="Icache sync parameter configuration error, the error address and size is 0x";
            break;
        case 2U:
            memw();
            address=PANIC_CACHE->icache_preload_address;
            memw();
            size=PANIC_CACHE->icache_preload_size;
            description="Icache preload parameter configuration error, the error address and size is 0x";
            break;
        case 4U:
            description="Dcache sync parameter configuration error, the error address and size is 0x";
            break;
        case 8U:
            memw();
            address=PANIC_CACHE->dcache_preload_address;
            memw();
            size=PANIC_CACHE->dcache_preload_size;
            description="Dcache preload parameter configuration error, the error address and size is 0x";
            break;
        case 16U:
            panic_print_str("Write back error occurred while dcache tries to write back to flash\r\n");
            panic_print_str("The following backtrace may not indicate the code that caused Cache invalid access\r\n");
            continue;
        case 32U:
            memw();
            address=PANIC_CACHE->mmu_fault_address;
            panic_print_str("MMU entry fault error occurred while accessing the address 0x");
            panic_print_hex(address);
            memw();
            if ((PANIC_CACHE->mmu_fault_content&0x4000U)!=0)
                panic_print_str(" (invalid mmu entry)");
            panic_print_str("\r\n");
            continue;
        default:
            continue;
        }
        panic_print_str(description);
        panic_print_hex(address);
        panic_print_str("(0x");
        panic_print_hex(size);
        panic_print_str(")\r\n");
    }
    panic_print_str("\r\n");
}

/* Native entry: 0x42003724. */
/* Original function-byte SHA-256:
 * 5154d2aa1f3505e3bc2b920afe0afe7cc6dd5eac61a5ad861b1d8078b10b2324. */
/*
 * Copy 24 label pointers (96 bytes) from the image table onto the stack. Print
 * six rows of four frame WORDs at offsets 4..96, skipping a label whose first
 * byte is NUL. These cover PC, PS, A0..A15, SAR, EXCCAUSE, EXCVADDR, LBEG,
 * LEND and LCOUNT. Each label byte and frame WORD is read at its turn, after
 * preceding output calls; this is not an atomic frame snapshot.
 *
 * Query xPortInterruptedFromISRContext after the rows. If nonzero and core0
 * has cause5, or core1 has cause6, also read current CPU EPC1..4 separately.
 * EPC1 is sampled before the ISR-heading calls; each later EPC precedes its
 * own label/output calls. The supplied core is a label/guard, not a remote
 * special-register selector. Other core values suppress this extra block.
 * No frame/label NULL check, lock, cache recovery or final newline. Device
 * console stubs suppress output but not native reads and special-registers.
 */
void panic_print_registers(const void *saved_frame,int core)
{
    const char *labels[PANIC_REGISTER_LABEL_COUNT];
    memcpy(labels,PANIC_REGISTER_LABELS,sizeof(labels));
    const volatile unsigned int *words=saved_frame;
    panic_print_str("Core ");
    panic_print_dec(core);
    panic_print_str(" register dump:");
    for (unsigned int row=0;row<PANIC_REGISTER_LABEL_COUNT;row+=4U) {
        panic_print_str("\r\n");
        for (unsigned int column=0;column<4U;++column) {
            unsigned int index=row+column;
            const char *label=labels[index];
            if (*(const volatile unsigned char *)label!=0) {
                panic_print_str(label);
                panic_print_str(": 0x");
                unsigned int value=words[index+1U];
                panic_print_hex(value);
                panic_print_str("  ");
            }
        }
    }
    if (xPortInterruptedFromISRContext()==0) return;
    const volatile XtensaExceptionFrame *frame=saved_frame;
    if (core==0) {
        if (frame->exception_cause!=5U) return;
    } else {
        if (core!=1 || frame->exception_cause!=6U) return;
    }
    unsigned int epc;
    __asm__ volatile("rsr.epc1 %0" : "=a"(epc));
    panic_print_str("\r\n");
    panic_print_str("Core ");
    panic_print_dec(core);
    panic_print_str(" was running in ISR context:\r\n");
    panic_print_str("EPC1    : 0x");
    panic_print_hex(epc);
    __asm__ volatile("rsr.epc2 %0" : "=a"(epc));
    panic_print_str("  EPC2    : 0x");
    panic_print_hex(epc);
    __asm__ volatile("rsr.epc3 %0" : "=a"(epc));
    panic_print_str("  EPC3    : 0x");
    panic_print_hex(epc);
    __asm__ volatile("rsr.epc4 %0" : "=a"(epc));
    panic_print_str("  EPC4    : 0x");
    panic_print_hex(epc);
}

/* Native entry: 0x42003814. */
/* Original function-byte SHA-256:
 * 9621cb1310cb9a8707890aa1820b27d49268cb016fa00adfd24abff4836deb5c. */
/*
 * Classify architectural exception causes 0..39 through the image string table.
 * In-range: load reason, store fixed description then reason; install the
 * illegal-instruction details callback only for cause 0. Out-of-range: store
 * "Unknown" reason then the same description. Finally read frame PC and store
 * info->address. Other fields, including an existing details callback for a
 * nonzero cause, are untouched. No clearing, validation, allocation or lock;
 * volatile views preserve native read/write ordering even for overlapping data.
 */
void panic_arch_fill_info(const XtensaExceptionFrame *saved_frame,PanicInfo *result)
{
    const volatile XtensaExceptionFrame *frame=saved_frame;
    volatile PanicInfo *info=result;
    unsigned int cause=frame->exception_cause;
    if (cause<PANIC_ARCH_REASON_COUNT) {
        const char *reason=PANIC_ARCH_REASONS[cause];
        info->description="Exception was unhandled.";
        info->reason=reason;
        if (cause==0) info->details=panic_illegal_instruction_details;
    } else {
        info->reason="Unknown";
        info->description="Exception was unhandled.";
    }
    info->address=(const void *)frame->pc;
}

/* Native entry: 0x4200384c. */
/* Original function-byte SHA-256:
 * a6f9389e41a294b83c2005368c8cd769cf8a0e75301264c8ed4ef30c90c73cf9. */
/*
 * Fill SoC pseudo-cause information. Causes5/6 store core0/1, load that reason,
 * set type=interrupt-watchdog, clear description, then store reason. Cause7
 * queries the cache-fault CPU, reloads cause BEFORE writing info->core, and
 * continues with the reloaded value. Other causes keep the existing core.
 * Default reason is "Unknown reason" and description=NULL. A SIGNED cause<8
 * selects the table: there is no lower-bound check, so a negative cause reads
 * before it. Cause1 sets debug type and callback; cause7 installs cache details.
 * Other type/details/address/frame fields remain unchanged. No zero-fill,
 * NULL guard, fault recovery or lock; preserve native overlapping-field order.
 */
void panic_soc_fill_info(const XtensaExceptionFrame *saved_frame,PanicInfo *result)
{
    const volatile XtensaExceptionFrame *frame=saved_frame;
    volatile PanicInfo *info=result;
    int cause=(int)frame->exception_cause;
    if (cause==5 || cause==6) {
        info->core=cause==5?0:1;
        const char *reason=*(const char *const volatile *)
            ((uintptr_t)PANIC_PSEUDO_REASONS + ((unsigned int)cause << 2));
        info->exception=PANIC_EXCEPTION_INTERRUPT_WATCHDOG;
        info->description=NULL;
        info->reason=reason;
        return;
    }
    if (cause==7) {
        int core=esp_cache_err_get_cpuid();
        cause=(int)frame->exception_cause;
        info->core=core;
    }
    info->reason="Unknown reason";
    info->description=NULL;
    if (cause >= (int)PANIC_PSEUDO_REASON_COUNT) return;
    /* Signed negative causes retain the native wrapping table-address read. */
    info->reason=*(const char *const volatile *)
        ((uintptr_t)PANIC_PSEUDO_REASONS + ((unsigned int)cause << 2));
    if (cause==1) {
        info->exception=PANIC_EXCEPTION_DEBUG;
        info->details=panic_debug_details;
    } else if (cause==7) {
        info->details=panic_cache_details;
    }
}

/* Native entry: 0x420038b4. */
/* Original function-byte SHA-256:
 * 6109ddfffcf63f9979810def1b69606e44d272220eb9f3245dbaf5ba813e4354. */
/*
 * Read PC, saved A1 and saved A0 in that order before storing a 16-byte local
 * backtrace cursor with the original exception-frame pointer. Ask the reviewed
 * printer for depth 100 in panic mode 1, ignoring its status. The core argument
 * is unused: no CPU selection or frame validation. Device output is disabled,
 * but stack walking and its possible faults remain. No independent lock.
 */
void panic_print_frame_backtrace(const void *saved_frame,int unused_core)
{
    const volatile XtensaExceptionFrame *frame=saved_frame;
    unsigned int pc=(unsigned int)frame->pc;
    unsigned int sp=frame->a[1];
    unsigned int next_pc=frame->a[0];
    BacktraceFrame cursor={pc,sp,next_pc,(XtensaExceptionFrame *)saved_frame};
    (void)esp_backtrace_print_from_frame(100,&cursor,1);
}
