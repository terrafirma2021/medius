/* Medius v3.4.7 device — runtime/format.c.
 * Recovered C and native assembly, grouped for source navigation.
 * Original entry addresses, firmware-byte hashes and function comments follow.
 */

#include "../include/types.h"

/* Native entry: 0x42018b14. */
/* Original function-byte SHA-256:
 * df333c3eb91bfe4bb33a854135fb057b9e81486e6395290f7c29302b1af458cd. */
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


/* Native entry: 0x420186b4. */
/* Original function-byte SHA-256:
 * 21929c21bfb56873fbdf91f1c0fcfb3cdf35b5dbd037866519a74cdb99ed7bc4. */
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

/* Native entry: 0x420189ac. */
/* Original function-byte SHA-256:
 * f4da9dc6b483bfccc6278fd730b628c1a85017b8f6531b0580696df0ba55999e. */
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

/* Native entry: 0x420189e0. */
/* Original function-byte SHA-256:
 * 3b64d2b108de7401cce4648e00a283ac34ae018600440a38db5838ce1dde6d35. */
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

/* Native entry: 0x42018b38. */
/* Original function-byte SHA-256:
 * 9c1991dd0b193888a957765115062f3f2f3e27004868c7fe8ec873aa2a887864. */
/* * Reentrant bounded formatter (_vsnprintf_r): same partial FILE initialization,
 * capacity-bit31 rejection, result<-1 errno139 translation and conditional final
 * NUL as snprintf wrapper, using the supplied reent and va_list. The whole
 *12-byte va_list arrives on the native stack because it cannot fit in the two
 * remaining argument registers; forward all three WORDs. No va_arg iteration,
 * context lookup, untouched-FILE-field initialization, locking or pointer checks.
 */
int medius_newlib_vsnprintf_r(NewlibReent *reent,char *output,size_t capacity,
    const char *format,va_list arguments)
{
    if ((capacity & 0x80000000U) != 0) {
        reent->error_number = 139;
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
    return result;
}

/* Native entry: 0x42018b90. */
/* Original function-byte SHA-256:
 * f1f08d21f8a6e9170c2fb420c9ba17cd03562962e26d6a083e75ce435da84695. */
/* * Snapshot the complete incoming12-byte Xtensa va_list, obtain current reent,
 * then pass reent/output/capacity/format and those three words to _vsnprintf_r.
 * Native forwarding moves the aggregate from argument registers to the outgoing
 * stack without inspecting or advancing it. Return full status unchanged; no
 * local size, output, format or context checks and no direct output mutation.
 */
int vsnprintf(char *output,size_t capacity,const char *format,va_list arguments)
{
    NewlibReent *reent = medius_current_newlib_reent();
    return medius_newlib_vsnprintf_r(reent,output,capacity,format,arguments);
}
