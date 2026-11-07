/* Medius v3.4.7 host — common panic arbitration entry. */
#include "../include/types.h"

/* Native entry: 0x420030e0. */
/* Original function-byte SHA-256:
 * cef6d7c15d7573156bf1c44ae7429463907a985f4e09eff502b0530e6b0d44d5. */
/*
 * Common panic arbitration and abstract-info construction. Increment this
 * core's panic count first, clear all nine local info WORDs, then publish the
 * supplied frame in the PRID-bit13 slot without MEMW/lock. exception_context
 * is a full WORD for arbitration; only its low byte contributes to the final
 * pseudo-cause flag. Thus0x100 takes the arbitration path but can later select
 * architectural classification.
 *
 * On nonzero context, read cause separately for each test. Cause5 parks core1;
 * cause6 parks core0. Cause7 queries cache-fault CPU: unknown/-1 parks core1;
 * a known result triggers a SECOND query and parks a mismatching core after
 * clearing only its own saved-frame slot. The two queries need not agree.
 * Parking is an endless instruction loop, without wait/yield, feed or timeout.
 *
 * The surviving core arms RTC WDT for10000ms using the reviewed wrapping
 * conversion, disables timer-group WDTs, delays1us, stalls the other CPU, then
 * clears shared IPC stall state. Read external debugger status0x10200c once.
 * If bit0 is set, normalize one saved PC for the executable predicate. Only
 * when executable, read PC again to require its high2 bits nonzero; otherwise
 * overwrite saved PC with0x40374000. No second debugger query or revalidation.
 *
 * Read PRID afresh for info.core; initialize fault type, NULL details and
 * "Unknown" reason. Call the no-op SoC check hook with frame/info, store raw
 * lowBYTE(hook_result|exception_context), classify, set state callback/frame,
 * and hand the info to the retained-record/system-handler boundary. That
 * downstream body is reviewed separately. Return only if it returns. No NULL
 * frame validation, synchronization, runtime timing or complete-reset guarantee.
 */
void panic_dispatch_frame(XtensaExceptionFrame *frame,unsigned int exception_context)
{
    esp_panic_handler_increment_entry_count();
    PanicInfoStorage storage;
    for (unsigned int index=0;index<9U;++index)
        ((volatile unsigned int *)storage.words)[index]=0;
    volatile PanicInfo *info=&storage.info;
    unsigned int core=(xtensa_read_prid()>>13)&1U;
    PANIC_FRAMES[core]=frame;

    if (exception_context!=0) {
        unsigned int cause=panic_get_cause(frame);
        if (core==1U && cause==5U) {
            for (;;) __asm__ volatile("");
        }
        cause=panic_get_cause(frame);
        if (cause==6U && core==0) {
            for (;;) __asm__ volatile("");
        }
        cause=panic_get_cause(frame);
        if (cause==7U) {
            int cache_core=esp_cache_err_get_cpuid();
            if (cache_core==-1) {
                if (core!=0) {
                    for (;;) __asm__ volatile("");
                }
            } else if ((unsigned int)esp_cache_err_get_cpuid()!=core) {
                PANIC_FRAMES[core]=NULL;
                for (;;) __asm__ volatile("");
            }
        }
    }

    esp_panic_handler_enable_rtc_wdt(10000U);
    esp_panic_handler_disable_timg_wdts();
    esp_rom_delay_us(1U);
    esp_cpu_stall((int)(core^1U));
    panic_clear_ipc_stall();

    unsigned int debugger_status;
    unsigned int debugger_register=0x10200cU;
    __asm__ volatile("rer %0,%1" : "=a"(debugger_status) : "a"(debugger_register));
    if ((debugger_status&1U)!=0) {
        unsigned int address=panic_get_address(frame);
        const void *code=(const void *)((address&0x3fffffffU)|0x40000000U);
        if (!esp_ptr_executable(code) || panic_get_address(frame)<0x40000000U)
            panic_set_address(frame,0x40374000U);
    }

    info->core=(int)((xtensa_read_prid()>>13)&1U);
    info->exception=PANIC_EXCEPTION_FAULT;
    info->details=NULL;
    info->reason="Unknown";
    unsigned int supplied=panic_soc_check_pseudo_cause(frame,(PanicInfo *)info);
    unsigned char pseudo=(unsigned char)(supplied|exception_context);
    info->pseudo_exception=pseudo;
    if (pseudo!=0) panic_soc_fill_info(frame,(PanicInfo *)info);
    else panic_arch_fill_info(frame,(PanicInfo *)info);
    info->state=panic_dump_frames;
    info->frame=frame;
    panic_record_and_handle((PanicInfo *)info);
}

/* Native entry: 0x4201e760. */
/* Original function-byte SHA-256:
 * 92c9598ac7519d458b9e367d0d7b28064c9bff38bae50b088825d1dda27f16a4. */
/* Xtensa SoC pseudo-cause check hook: return full-WORD0 without reading
 * either argument or writing any panic-info field. No override, hardware read,
 * output, lock or status clearing. Empty compiler barrier retains the native
 * call boundary in aggregate review; it emits no machine instruction. */
unsigned int panic_soc_check_pseudo_cause(const void *unused_frame,PanicInfo *unused_info)
{
    __asm__ volatile("" ::: "memory");
    return 0;
}
