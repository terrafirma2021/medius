/* Medius v3.4.7 host — app/logging.c.
 * Recovered C and native assembly, grouped for source navigation.
 * Original entry addresses, firmware-byte hashes and function comments follow.
 */

#include "../include/types.h"

/* Native entry: 0x420166a4. */
/*
 * Medius v3.4.7 — host application; 0x420166a4.
 *
 * Builds a bounded string-stream prefix for the formatter, applies capacity/error handling and
 * terminates at the formatter-updated cursor.
 *
 * Calls: FUN_42017108.
 *
 * Called by: medius_format_bounded_current_context.
 *
 * Original function-byte SHA-256:
 * 9c1991dd0b193888a957765115062f3f2f3e27004868c7fe8ec873aa2a887864.
 */

/*
 * error_context: Writable Newlib context; errno is its first32-bit field.
 * output: Borrowed destination; capacity0 permits NULL if the engine honors its zero-capacity
 *   contract.
 * capacity: Unsigned size; bit31 set rejects before engine/output access. Other values reserve one
 *   byte for NUL.
 * format: Borrowed format string interpreted by the separate engine.
 * args: Exact12-byte Xtensa va_list descriptor, passed wholly on the stack in this five-argument
 *   ABI.
 * Returns: Raw signed formatter result; -1 with errno139 for a rejected size.
 * Requirements/effects: Builds a104-byte Newlib string FILE with only flags, cursor/base,
 *   remaining/capacity and descriptor initialized. The read count and80-byte tail remain
 *   uninitialized, as in native code. Flags0x208 select writable string storage; descriptor=-1.
 *   Calls the engine with unchanged three va_list words. A result below-1 sets errno139; -1 and
 *   nonnegative results retain engine errno. Every accepted nonzero capacity writes NUL at the
 *   freshly engine-updated cursor, even after failure. Zero capacity still formats but supplies no
 *   local terminator write. No cursor bounds validation, rollback, output preclear or locking;
 *   engine owns formatting, cursor advancement and any allocation policy.
 */

int medius_format_bounded_context(NewlibReent *error_context,char *output,
                                  unsigned int capacity,const char *format,MediusXtensaVaList argument_list)
{
    if (capacity & 0x80000000U) {
        error_context->error_number = 139; /* EOVERFLOW in this Newlib ABI. */
        return -1;
    }
    MediusNewlibStringStream stream;
    stream.flags = 0x0208; /* __SWR | __SSTR */
    stream.cursor = output;
    stream.buffer_base = output;
    int remaining = capacity == 0 ? 0 : (int)(capacity - 1U);
    stream.write_remaining = remaining;
    stream.buffer_capacity = remaining;
    stream.file_descriptor = -1;
    union {
        MediusXtensaVaList descriptor;
        va_list native;
    } arguments = {.descriptor = argument_list};
    int result = medius_newlib_vformat_string(error_context,&stream,format,arguments.native);
    if (result < -1)
        error_context->error_number = 139;
    if (capacity != 0)
        *stream.cursor = '\0';
    return result;
}

/* Native entry: 0x420166fc. */
/*
 * Medius v3.4.7 — host application; 0x420166fc.
 *
 * Obtains the current library context and forwards bounded-format arguments with the Xtensa
 * three-word va_list ABI.
 *
 * Calls: __getreent, medius_format_bounded_context.
 *
 * Called by: medius_host_log_formatted, medius_host_log_hook.
 *
 * Original function-byte SHA-256:
 * 6192a5f22b9a41dc671c4f340489ff8a52a8904c65c6a4881f173cacc3789706.
 */

/*
 * output: Borrowed destination passed unchanged.
 * capacity: Full32-bit capacity passed unchanged, including negative-size bit patterns.
 * format: Borrowed format string passed unchanged.
 * args: Three opaque Xtensa va_list words arriving in a5/a6/a7.
 * Returns: Bounded formatter result unchanged.
 * Requirements/effects: Obtains the current task/startup Newlib context through __getreent, then
 *   passes context/output/size/format and the entire12-byte argument descriptor on the outgoing
 *   stack. No local size, pointer, result or payload checks, errno changes, allocation or va_arg
 *   iteration.
 */

int medius_format_bounded_current_context(char *output,unsigned int capacity,const char *format,
                                          MediusXtensaVaList argument_list)
{
    NewlibReent *error_context = (NewlibReent *)__getreent();
    return medius_format_bounded_context(error_context,output,capacity,format,argument_list);
}

/* Native entry: 0x420263ac. */
/*
 * Medius v3.4.7 — host application; 0x420263ac.
 *
 * Uses a recursion guard to format a log message, trim trailing CR/LF and send a nonempty payload
 * without waiting.
 *
 * Calls: medius_format_bounded_current_context, medius_link_send_nowait.
 *
 * Original function-byte SHA-256:
 * f540ecbeee75c13757d5e6bb038ebfcbac4ece6282e8a0faac2d385e696a54b3.
 */

/* Logging route: installed by medius_host_log_init through esp_log_set_vprintf. Runs in the
   SDK logging caller context after tag-level filtering. Its type-3 UART1 text is received by
   device_link_message and wrapped as an INFO/hostlog statement, then emitted through
   the device UART0 LOG opcode 0x08. Queue admission here is nonblocking; successful formatting
   does not establish delivery. The device can truncate the text again after adding its prefix. */

/*
 * format: Borrowed SDK log format after tag-level filtering.
 * args: Complete Xtensa12-byte va_list descriptor; referenced arguments must remain live through
 *   formatting.
 * Returns: 0 for an already busy guard; otherwise a nonpositive formatter result or the clamped
 *   CR/LF-trimmed send length.
 * Requirements/effects: MEMW then reads one recursion-guard byte. Busy returns without clearing it
 *   or calling dependencies. Active processing MEMW-publishes1, formats into176 stack bytes, caps
 *   positive results at175 and removes only trailing LF/CR bytes. Embedded NUL, space and other
 *   bytes stop trimming; bytes themselves are retained. Nonempty payload sends type3/flags0
 *   without waiting; all-CR/LF or nonpositive results skip send. Ignores send result and MEMW-
 *   clears guard unconditionally after active processing, even if callbacks changed it. Separate
 *   load/store plus MEMW provides no atomic cross-core exclusion. Stack payload is borrowed during
 *   the send; queue copying, delivery and physical UART timing belong to dependencies.
 */

int medius_host_log_hook(const char *format,MediusXtensaVaList argument_list)
{
    memw();
    if (HOST_LOG_RECURSION_GUARD != 0)
        return 0;
    memw();
    HOST_LOG_RECURSION_GUARD = 1;
    char payload[176];
    int result = medius_format_bounded_current_context(payload,176,format,argument_list);
    if (result > 0) {
        unsigned int length = result < 175 ? (unsigned int)result : 175U;
        while (length != 0) {
            unsigned char tail = (unsigned char)payload[length - 1U];
            if (tail != '\n' && tail != '\r')
                break;
            --length;
        }
        if (length != 0)
            medius_link_send_nowait(3,0,payload,length);
        result = (int)length;
    }
    memw();
    HOST_LOG_RECURSION_GUARD = 0;
    return result;
}

/* Native entry: 0x42027cb0. */
/* Original function-byte SHA-256:
 * eb36b2923927a10c1f43b7fd3190b7f226b29f12d70b900510abb4c208435b9c. */
/*
 * Installs the reviewed host log hook through esp_log_set_vprintf and ignores
 * the previous callback. The alias supplies the same native12-byte va_list
 * register ABI as the hook's explicit raw-descriptor view. No extra reset,
 * transport setup, allocation, flush or success check is performed here.
 */
void medius_host_log_init(void)
{
    esp_log_set_vprintf(medius_host_log_vprintf);
}

/* Native entry: 0x42027cbc. */
/*
 * Medius v3.4.7 — host application; 0x42027cbc.
 *
 * Formats into a176-byte stack buffer and sends up to175 bytes as a type3, flags0 link message
 * when formatting returns nonnegative.
 *
 * Calls: medius_format_bounded_current_context, link_send_wait100.
 *
 * Called by: FUN_4200c3e8, medius_host_update_link_dispatch, FUN_4200c68c, ota_grace_timer_cb, FUN_4202e07c, FUN_4202e370,
 * FUN_42030438, app_main, medius_clone_publish, medius_halt_timer_cb, medius_hid_attach_interface,
 * medius_hid_initialize_endpoint, medius_host_apply_generation,
 * medius_host_capture_descriptors_and_probe_controls, medius_host_fetch_configuration_descriptor,
 * medius_host_prepare_configuration_capture, medius_host_request_recovery,
 * medius_host_teardown_interfaces, medius_out_register, medius_snapshot_timer_cb,
 * medius_task_cfgswitch, medius_task_ctrlwk, medius_vendor_initialize_interface,
 * medius_vendor_restore_alternate.
 *
 * Original function-byte SHA-256:
 * c3f07a63242503dcc5fe6da467a3ebc0c7d0658a547f51f4ae1706a80f2c98c2.
 */

/* Logging route: direct application helper, bypassing SDK tag-level filtering and the host SDK
   print-hook recursion guard. Uses a 100-tick queue-admission budget. Device receipt wraps the
   bytes in an INFO/hostlog statement and sends an external UART0 LOG frame. Unlike the SDK
   host hook, this helper does not strip trailing CR/LF. */

/*
 * format: Borrowed printf-style format string.
 * ...: Xtensa variadic arguments: first five32-bit slots in saved a3..a7, then caller stack;
 *   compiler va_start retains ABI alignment rules.
 * Returns: No value; formatter/send results are not returned.
 * Requirements/effects: Uses the compiler Xtensa va_start/va_end representation to recover the
 *   native12-byte va_list and formats into176 stack bytes. Negative result suppresses send.
 *   Otherwise sends type3/flags0 with min(result,175), including a zero-length send for0, through
 *   the100-tick queue-admission helper. Does not trim CR/LF or use the SDK hook guard/tag filter.
 *   No buffer preclear, retry or delivery guarantee. Payload is borrowed during send; formatter
 *   and link helpers define argument consumption, content initialization, copying and scheduling.
 */

void medius_host_log_formatted(const char *format,...)
{
    /* The compiler supplies the Xtensa register-save and caller-stack areas.
     * Copy their three-word descriptor, not a pointer-only va_list guess. */
    __builtin_va_list native_args;
    __builtin_va_start(native_args,format);
    MediusXtensaVaList argument_list;
    __builtin_memcpy(&argument_list,&native_args,sizeof(argument_list));
    char payload[176];
    int result = medius_format_bounded_current_context(payload,176,format,argument_list);
    __builtin_va_end(native_args);
    if (result >= 0) {
        unsigned int length = result < 175 ? (unsigned int)result : 175U;
        link_send_wait100(3,0,payload,length);
    }
}
