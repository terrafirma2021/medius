/* Medius v3.4.7 host — runtime/format.c.
 * Recovered C and native assembly, grouped for source navigation.
 * Original entry addresses, firmware-byte hashes and function comments follow.
 */

#include "../include/types.h"

/* Native entry: 0x42016680. */
/* Original function-byte SHA-256:
 * 8f0cad3b1f145c4de5a4411b81eacd7cb67b15f272ad4f5d10659ff4d6122414. */
/* Snapshot the incoming three-word Xtensa va_list by value, obtain the current
 * Newlib reentrancy context and load its stdout pointer at +8. Pass context,
 * stdout, format and that va_list to the native stream formatter; return its
 * full signed status. No pointer checks, own locking, buffering or alternate
 * output route. This is the initial ESP logger callback; replacing the logger
 * callback does not intercept independent direct stdout/ROM output calls.
 * The delegated formatter is a separate native entry, not reviewed here. */
int vprintf(const char *format,va_list arguments)
{
    NewlibReent *reent = medius_current_newlib_reent();
    NewlibFile *output = ((const volatile NewlibReent *)reent)->standard_output;
    return medius_newlib_vformat_stream(reent,output,format,arguments);
}

/* Native entry: 0x42016220. */
/* Original function-byte SHA-256:
 * 948a6fc2d3f8e3b6e567a963886746338826cd87d9ffa85898fd22804f266dda. */
/* * fprintf-style wrapper: capture the full Xtensa va_list (stack pointer,
 * register-save pointer, byte offset8 for two fixed WORD arguments), obtain
 * current reent, and forward stream/format/arguments to the stream formatter.
 * Return its signed status. No pointer validation, local locking, descriptor
 * routing, retry or errno handling; downstream formatter owns those effects.
 */
int newlib_fprintf(NewlibFile *stream,const char *format,...)
{
    va_list arguments;
    va_start(arguments,format);
    NewlibReent *reent = medius_current_newlib_reent();
    int result = medius_newlib_vformat_stream(reent,stream,format,arguments);
    va_end(arguments);
    return result;
}

/* Native entry: 0x42016518. */
/* Original function-byte SHA-256:
 * 61c56d7a8834c788e74b76f07d744f5b0d7d39cbfbdc624c126cc9593536bd20. */
/* * printf-style wrapper: save variable arguments (Xtensa initial byte offset4),
 * get current reent, freshly load its stdout WORD at+8, and call stream formatter
 * with the complete12-byte va_list. Return status unchanged. No independent
 * logging-hook call, pointer check, error translation or buffer allocation.
 */
int newlib_printf(const char *format,...)
{
    va_list arguments;
    va_start(arguments,format);
    NewlibReent *reent = medius_current_newlib_reent();
    NewlibFile *stream = ((const volatile NewlibReent *)reent)->standard_output;
    int result = medius_newlib_vformat_stream(reent,stream,format,arguments);
    va_end(arguments);
    return result;
}

/* Native entry: 0x4201654c. */
/* Original function-byte SHA-256:
 * 999aed0e4b109cd06ae9db647fc88232c51fcec3253c95e2064b99aa8b74b70b. */
/* * snprintf-style wrapper: obtain current reent and reject capacity bit31 with
 * errno139/EOVERFLOW and return-1, without touching output. Otherwise initialize
 * ONLY the string FILE fields observed natively: flags208, cursor/base=output,
 * write_remaining/capacity=max(capacity-1,0), descriptor-1. Other FILE fields
 * remain uninitialized. Format with the captured Xtensa va_list (initial byte
 * offset12 for three fixed WORD arguments). A result<-1 sets errno139 but is
 * returned unchanged; exact-1 does not set it here. For nonzero capacity always
 * write a NUL through the formatter's final cursor, even after failure. Zero
 * capacity still calls formatter and performs no final output store. No local
 * pointer/format/argument checks, explicit lock or output-allocation ownership.
 */
int newlib_snprintf(char *output,size_t capacity,const char *format,...)
{
    va_list arguments;
    va_start(arguments,format);
    NewlibReent *reent = medius_current_newlib_reent();
    if ((capacity & 0x80000000U) != 0) {
        reent->error_number = 139;
        va_end(arguments);
        return -1;
    }
    NewlibFile stream;
    stream.flags = 0x208;
    stream.cursor = output;
    stream.buffer_base = output;
    unsigned int remaining = capacity == 0 ? 0 : capacity - 1U;
    stream.write_remaining = (int)remaining;
    stream.buffer_capacity = (int)remaining;
    stream.file_descriptor = -1;
    int result = medius_newlib_vformat_string(reent,&stream,format,arguments);
    if (result < -1)
        reent->error_number = 139;
    if (capacity != 0)
        *((volatile NewlibFile *)&stream)->cursor = 0;
    va_end(arguments);
    return result;
}
