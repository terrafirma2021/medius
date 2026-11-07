/* Medius v3.4.7 device: temporary formatting streams, locale and binary64 decomposition. */
#include "../include/types.h"

/* Native entry: 0x4201f2dc. */
/* Original function-byte SHA-256:
 * 5ea44ad92a9f8b394f7a2558cb9139357d7d15d4f93038d54be617e8fcf012ac. */
/* * Newlib __sbprintf: format through a temporary128-byte stack buffer, with
 * original flags minus unbuffered2, secondary flags, descriptor, cookie and
 * write callback copied in native read order. Initialize ONLY those fields,
 * buffer/cursor, write_remaining128, capacity128, line_write_remaining0 and
 * the recursive lock; leave other FILE fields uninitialized. Pass the complete
 * incoming12-byte va_list to the same stream formatter. Nonnegative formatter
 * result is followed by a flush; nonzero flush status changes result to-1.
 * Negative formatter result skips flushing. Propagate temporary error40 into
 * freshly read original flags, then always close the temporary recursive lock.
 * Return result. No callback/pointer checks, heap buffer or restoration of
 * original FILE fields beyond conditional error propagation.
 */
int medius_newlib_format_temporary_stream(NewlibReent *reent,NewlibFile *stream,
    const char *format,va_list arguments)
{
    unsigned char buffer[128];
    NewlibFile temporary;
    volatile NewlibFile *temp = &temporary;
    const volatile NewlibFile *original = stream;
    temp->flags = original->flags & ~2U;
    temp->secondary_flags = original->secondary_flags;
    temp->file_descriptor = original->file_descriptor;
    void *cookie = original->cookie;
    temp->write_remaining = 128;
    temp->cookie = cookie;
    int (*writer)(NewlibReent *,void *,const char *,int) = original->write_callback;
    temp->buffer_capacity = 128;
    temp->write_callback = writer;
    temp->line_write_remaining = 0;
    temp->cursor = (char *)buffer;
    temp->buffer_base = (char *)buffer;
    __retarget_lock_init_recursive((NewlibLock *)&temporary.lock);
    int result = medius_newlib_vformat_stream(reent,&temporary,format,arguments);
    if (result >= 0 && medius_newlib_flush_file(reent,&temporary) != 0)
        result = -1;
    if ((temp->flags & 0x40U) != 0)
        ((volatile NewlibFile *)stream)->flags = original->flags | 0x40U;
    __retarget_lock_close_recursive(temp->lock);
    return result;
}

/* Native entry: 0x4201f5a4. */
/* Original function-byte SHA-256:
 * b07db093d5d9544f332484b99a3352ff1094bcb7bb06598db273abcae13ca778. */
/* * Newlib localeconv-compatible accessor: load the global-locale pointer once
 * and return its lconv member at+240, with32-bit address wrap. Identical native
 * bodies serve localeconv/_localeconv_r in the pinned library; no per-thread
 * context, input argument, NULL check, allocation, field copy or lock is used.
 * Return borrowed global storage. The SDK lconv layout is retained explicitly.
 */
MediusNewlibLocaleConversion *medius_newlib_localeconv(void)
{
    const void *locale = MEDIUS_NEWLIB_GLOBAL_LOCALE;
    return (MediusNewlibLocaleConversion *)((uintptr_t)locale + 240U);
}

/* Native entry: 0x4201f5b4. */
/* Original function-byte SHA-256:
 * 7ac38b50b5d0e80f1fe6337f4872eb649e0e8f87d343fd9b2c778c0003d8d3b2. */
/* * Newlib binary64 frexp. Store exponent0 first. Signed zero, infinity and NaN
 * return their original bits unchanged. For a finite nonzero value, scale a
 * subnormal by2^54 through the native soft-double multiply and set exponent-54.
 * Then add exponent-field-1022 to a freshly read exponent WORD and replace the
 * returned value's exponent with1022, preserving sign/fraction. Thus ordinary
 * results have absolute mantissa in[0.5,1). Arithmetic works from bit fields;
 * no comparison/arithmetic is performed on NaN inputs. No exponent-pointer
 * validation, errno mutation, allocation or hardware-double instruction here.
 */
double medius_newlib_frexp(double value,int *exponent)
{
    MediusBinary64Words bits = {.value=value};
    volatile int *output = exponent;
    *output = 0;
    unsigned int absolute_high = bits.high & 0x7fffffffU;
    if (absolute_high <= 0x7fefffffU && (absolute_high | bits.low) != 0) {
        if (((bits.high >> 20) & 0x7ffU) == 0) {
            bits.value = bits.value * 0x1p54;
            absolute_high = bits.high & 0x7fffffffU;
            *output = -54;
        }
        int adjustment = (int)(absolute_high >> 20) - 1022;
        int previous = *output;
        *output = (int)((unsigned int)previous + (unsigned int)adjustment);
        bits.high = (bits.high & 0x800fffffU) | 0x3fe00000U;
    }
    return bits.value;
}
