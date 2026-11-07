/* Medius v3.4.7 device — system panic handler. */
#include "../include/types.h"

/* Native entry: 0x420031a8. */
/* Original function-byte SHA-256:
 * 3fd49c65b931dd9c3b8003529cf5cbc70dcd434f4a7fd98b36a155c87c464232. */
/*
 * System panic handling; info must point to the36-byte native structure.
 * Read PRID/current-core entry count once and feed enabled watchdogs only if
 * count<3. An abort overrides description/reason/details and sets type=abort;
 * the exact image-specific store/callback order is retained below.
 * The device emits no headings, register text or ELF-hash output here.
 * Call a non-NULL details callback with the then-current frame, and only then
 * RER/read debugger status0x10200c bit0. Callbacks may change info or globals;
 * subsequent fields are read afresh. No callback validation or fault recovery.
 *
 * Attached debugger: select info.reason when pseudo_exception lowBYTE!=0,
 * otherwise select global abort details only if a fresh abort byte is nonzero.
 * For a non-NULL selected pointer, store pointer, call strlen, store length,
 * and BREAK1,14 with A2=0x116 and A3=&{pointer,length}. Return status is ignored.
 * The device emits no breakpoint/returning diagnostic.
 * Disable both timer-group watchdogs, then unlock/disable/relock the shared RTC
 * watchdog. Read info.address afterwards, set instruction breakpoint0 and
 * ignore its status. Return normally; no state callback, reset hint or restart
 * occurs on this debugger path. No timeout, USB output, debugger wait or lock.
 *
 * No debugger: feed through the per-core count guard, invoke non-NULL state
 * callback, clear the global abort BYTE, and feed again. No output occurs between the two guarded feeds in this image.
 * Query reset hint once; preserve nonzero hints. Otherwise map interrupt WDT
 * type1 to hint5, task WDT type2 to hint6, all other types to panic hint4.
 * Call the reviewed nonreturning panic restart wrapper.
 * Native status/field reads and branch order are retained; no NULL-info guard,
 * callback ownership guarantee, atomic snapshot or runtime timing claim.
 */
void esp_panic_handler(PanicInfo *result)
{
    volatile PanicInfo *info=result;
    unsigned int core=(xtensa_read_prid()>>13)&1U;
    if (PANIC_ENTRY_COUNTS[core]<3U) panic_feed_enabled_wdts();

    PanicDumpCallback details;
    if (PANIC_ABORT_IN_PROGRESS==0) {
        details=info->details;
    } else {
        const char *details_text=PANIC_ABORT_DETAILS;
        info->description=NULL;
        if (details_text!=NULL) {
            details=panic_print_abort_details;
            info->reason=NULL;
            info->details=details;
            info->exception=PANIC_EXCEPTION_ABORT;
        } else {
            details=NULL;
            info->details=NULL;
            info->reason=NULL;
            info->exception=PANIC_EXCEPTION_ABORT;
        }
    }
    if (details!=NULL) details(info->frame);

    unsigned int debugger_status;
    unsigned int debugger_register=0x10200cU;
    __asm__ volatile("rer %0,%1" : "=a"(debugger_status) : "a"(debugger_register));
    if ((debugger_status&1U)!=0) {
        const char *reason=NULL;
        if (info->pseudo_exception!=0) reason=info->reason;
        else if (PANIC_ABORT_IN_PROGRESS!=0) reason=PANIC_ABORT_DETAILS;
        if (reason!=NULL) {
            volatile PanicSemihostArguments arguments;
            arguments.text=reason;
            arguments.length=strlen(reason);
            register unsigned int operation __asm__("a2")=0x116U;
            register const volatile void *argument_pointer __asm__("a3")=&arguments;
            __asm__ volatile("break 1,14" : "+r"(operation)
                             : "r"(argument_pointer) : "memory");
        }

        esp_panic_handler_disable_timg_wdts();
        wdt_hal_write_protect_disable(PANIC_RTC_WDT);
        wdt_hal_disable(PANIC_RTC_WDT);
        wdt_hal_write_protect_enable(PANIC_RTC_WDT);
        (void)esp_cpu_set_breakpoint(0U,info->address);
        return;
    }

    esp_panic_handler_feed_wdts();
    PanicDumpCallback state=info->state;
    if (state!=NULL) state(info->frame);

    PANIC_ABORT_IN_PROGRESS=0;

    esp_panic_handler_feed_wdts();
    if (esp_reset_reason_get_hint()==0) {
        PanicException exception=info->exception;
        if (exception==PANIC_EXCEPTION_INTERRUPT_WATCHDOG)
            esp_reset_reason_set_hint(5);
        else if (exception==PANIC_EXCEPTION_TASK_WATCHDOG)
            esp_reset_reason_set_hint(6);
        else esp_reset_reason_set_hint(4);
    }
    panic_restart();
}
