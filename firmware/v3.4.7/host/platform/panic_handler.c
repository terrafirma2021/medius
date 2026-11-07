/* Medius v3.4.7 host — system panic handler. */
#include "../include/types.h"

/* Inline source reconstruction utilities for native inlined UART sequences;
 * these helpers are not additional firmware functions or API calls. */
static __inline__ __attribute__((always_inline))
void medius_panic_handler_emit_byte(unsigned char character)
{
    UartRegisterView *uart=MEDIUS_PANIC_UART_HAL->dev;
    volatile unsigned int written=0;
    do {
        memw();
    } while (((uart->status>>16)&0x3ffU)==128U);
    uart_hal_write_txfifo(MEDIUS_PANIC_UART_HAL,&character,1U,
                         (unsigned int *)&written);
}

static __inline__ __attribute__((always_inline))
void medius_panic_handler_emit_text(const char *text)
{
    unsigned char character=(unsigned char)*text;
    while (character!=0) {
        medius_panic_handler_emit_byte(character);
        character=(unsigned char)*++text;
    }
}

/* Native entry: 0x42002c58. */
/* Original function-byte SHA-256:
 * f2bd01a5aec39935d24fac2a813fbaef04c9abb3d0eab77453ddd7a63453b590. */
/*
 * System panic handling; info must point to the36-byte native structure.
 * Read PRID/current-core entry count once and feed enabled watchdogs only if
 * count<3. An abort overrides description/reason/details and sets type=abort;
 * the exact image-specific store/callback order is retained below.
 * The host prints its heading, optional description and CRLFs directly to UART.
 * Call a non-NULL details callback with the then-current frame, and only then
 * RER/read debugger status0x10200c bit0. Callbacks may change info or globals;
 * subsequent fields are read afresh. No callback validation or fault recovery.
 *
 * Attached debugger: select info.reason when pseudo_exception lowBYTE!=0,
 * otherwise select global abort details only if a fresh abort byte is nonzero.
 * For a non-NULL selected pointer, store pointer, call strlen, store length,
 * and BREAK1,14 with A2=0x116 and A3=&{pointer,length}. Return status is ignored.
 * The host then prints the breakpoint address and returning message.
 * Disable both timer-group watchdogs, then unlock/disable/relock the shared RTC
 * watchdog. Read info.address afterwards, set instruction breakpoint0 and
 * ignore its status. Return normally; no state callback, reset hint or restart
 * occurs on this debugger path. No timeout, USB output, debugger wait or lock.
 *
 * No debugger: feed through the per-core count guard, invoke non-NULL state
 * callback, clear the global abort BYTE, and feed again. The host prints cached ELF-hash text between these feeds; no hash is computed.
 * Query reset hint once; preserve nonzero hints. Otherwise map interrupt WDT
 * type1 to hint5, task WDT type2 to hint6, all other types to panic hint4.
 * Host prints rebooting, calls restart, then executes ILL if that call returns.
 * Native status/field reads and branch order are retained; no NULL-info guard,
 * callback ownership guarantee, atomic snapshot or runtime timing claim.
 */
void esp_panic_handler(PanicInfo *result)
{
    volatile PanicInfo *info=result;
    unsigned int core=(xtensa_read_prid()>>13)&1U;
    if (PANIC_ENTRY_COUNTS[core]<3U) panic_feed_enabled_wdts();

    if (PANIC_ABORT_IN_PROGRESS!=0) {
        const char *details_text=PANIC_ABORT_DETAILS;
        PanicDumpCallback details=details_text?panic_print_abort_details:NULL;
        info->description=NULL;
        info->reason=NULL;
        info->details=details;
        info->exception=PANIC_EXCEPTION_ABORT;
    } else {
        if (info->reason!=NULL) {
            medius_panic_handler_emit_text("Guru Meditation Error: Core ");
            int value=info->core;
            int tens=value/10;
            int ones=value-tens*10;
            medius_panic_handler_emit_byte(tens==0?' ':(unsigned char)((unsigned int)tens+'0'));
            medius_panic_handler_emit_byte((unsigned char)(ones+'0'));
            medius_panic_handler_emit_text(" panic'ed (");
            medius_panic_handler_emit_text(info->reason);
            medius_panic_handler_emit_text("). ");
        }
        const char *description=info->description;
        if (description!=NULL) medius_panic_handler_emit_text(description);
    }
    medius_panic_handler_emit_text("\r\n");
    PanicDumpCallback details=info->details;
    if (details!=NULL) details(info->frame);
    medius_panic_handler_emit_text("\r\n");

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
        medius_panic_handler_emit_text("Setting breakpoint at 0x");
        panic_print_hex((unsigned int)info->address);
        medius_panic_handler_emit_text(" and returning...\r\n");
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
    panic_print_str("\r\n");
    PANIC_ABORT_IN_PROGRESS=0;
    panic_print_str("\r\nELF file SHA256: ");
    panic_print_str(MEDIUS_PANIC_ELF_SHA256);
    panic_print_str("\r\n");
    panic_print_str("\r\n");
    esp_panic_handler_feed_wdts();
    if (esp_reset_reason_get_hint()==0) {
        PanicException exception=info->exception;
        if (exception==PANIC_EXCEPTION_INTERRUPT_WATCHDOG)
            esp_reset_reason_set_hint(5);
        else if (exception==PANIC_EXCEPTION_TASK_WATCHDOG)
            esp_reset_reason_set_hint(6);
        else esp_reset_reason_set_hint(4);
    }
    panic_print_str("Rebooting...\r\n");
    medius_panic_restart_returnable();
    __asm__ volatile("ill");
    __builtin_unreachable();
}
