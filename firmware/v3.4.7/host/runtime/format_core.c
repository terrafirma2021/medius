/*
 * Copyright (c) 1990 The Regents of the University of California.
 * All rights reserved.
 *
 * This code is derived from software contributed to Berkeley by
 * Chris Torek.
 *
 * Redistribution and use in source and binary forms, with or without
 * modification, are permitted provided that the following conditions
 * are met:
 * 1. Redistributions of source code must retain the above copyright
 *    notice, this list of conditions and the following disclaimer.
 * 2. Redistributions in binary form must reproduce the above copyright
 *    notice, this list of conditions and the following disclaimer in the
 *    documentation and/or other materials provided with the distribution.
 * 3. Neither the name of the University nor the names of its contributors
 *    may be used to endorse or promote products derived from this software
 *    without specific prior written permission.
 *
 * THIS SOFTWARE IS PROVIDED BY THE REGENTS AND CONTRIBUTORS ``AS IS'' AND
 * ANY EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT LIMITED TO, THE
 * IMPLIED WARRANTIES OF MERCHANTABILITY AND FITNESS FOR A PARTICULAR PURPOSE
 * ARE DISCLAIMED.  IN NO EVENT SHALL THE REGENTS OR CONTRIBUTORS BE LIABLE
 * FOR ANY DIRECT, INDIRECT, INCIDENTAL, SPECIAL, EXEMPLARY, OR CONSEQUENTIAL
 * DAMAGES (INCLUDING, BUT NOT LIMITED TO, PROCUREMENT OF SUBSTITUTE GOODS
 * OR SERVICES; LOSS OF USE, DATA, OR PROFITS; OR BUSINESS INTERRUPTION)
 * HOWEVER CAUSED AND ON ANY THEORY OF LIABILITY, WHETHER IN CONTRACT, STRICT
 * LIABILITY, OR TORT (INCLUDING NEGLIGENCE OR OTHERWISE) ARISING IN ANY WAY
 * OUT OF THE USE OF THIS SOFTWARE, EVEN IF ADVISED OF THE POSSIBILITY OF
 * SUCH DAMAGE.
 */
#include "../include/types.h"
#include <limits.h>

/* Readable reconstruction utilities for operations inlined into both native
 * formatter cores. They do not represent additional native entry points.
 * Newlib 9a0d3915 source is adapted to the native-bound recovered layouts.
 * Native 32-bit signed arithmetic wraps; no validation has been added.
 */
enum MediusPrintfFlags {
    PRINTF_ALTERNATE = 0x001,
    PRINTF_HEX_PREFIX = 0x002,
    PRINTF_LEFT_ADJUST = 0x004,
    PRINTF_LONG_DOUBLE = 0x008,
    PRINTF_LONG = 0x010,
    PRINTF_QUAD = 0x020,
    PRINTF_SHORT = 0x040,
    PRINTF_ZERO_PAD = 0x080,
    PRINTF_FLOAT = 0x100,
    PRINTF_CHAR = 0x200,
    PRINTF_GROUP = 0x400
};

extern char *medius_newlib_dtoa_r(NewlibReent *, double, int, int, int *, int *,
                                  char **) __asm__("_dtoa_r");
char *strncpy(char *, const char *, size_t);

static int format_decimal_digit(int character) {
    return character - '0';
}
static int format_is_decimal_digit(int character) {
    return (unsigned int)(character - '0') <= 9U;
}
static int format_digit_character(int digit) {
    return digit + '0';
}
static int format_sign_bit(double value) {
    MediusBinary64Words bits = {.value = value};
    return (int)(bits.high >> 31);
}
static int format_is_nan(double value) {
    MediusBinary64Words bits = {.value = value};
    return (bits.high & 0x7fffffffU) > 0x7ff00000U ||
           ((bits.high & 0x7fffffffU) == 0x7ff00000U && bits.low != 0);
}
static int format_is_infinite(double value) {
    MediusBinary64Words bits = {.value = value};
    return (bits.high & 0x7fffffffU) == 0x7ff00000U && bits.low == 0;
}
static int format_wrap_add(int left, int right) {
    return (int)((unsigned int)left + (unsigned int)right);
}

/* Finite binary64 conversion: hexadecimal digits use the caller's scratch
 * buffer, round ties to even and include any requested trailing zeros.
 * Decimal digits use _dtoa_r's reentrant storage, which is extended in place.
 * Preserve the sign of negative zero. No allocation-failure recovery or
 * digit-buffer bounds check is added to the native conversion path. */
static char *format_float_digits(NewlibReent *reent, double value, int precision, int flags,
                                 char *sign, int *conversion_exponent, int conversion,
                                 int *digit_count, char *scratch) {
    int mode, ignored_dtoa_sign;
    char *digits, *write_cursor, *digit_end;

    MediusBinary64Words value_bits;

    value_bits.value = value;
    if (value_bits.high & 0x80000000U) {
        value = -value;
        *sign = '-';
    } else
        *sign = '\000';

    if (conversion == 'a' || conversion == 'A') {

        value = medius_newlib_frexp(value, conversion_exponent) / 8;
        if (!value)
            *conversion_exponent = 1;
        digits = conversion == 'a' ? "0123456789abcdef" : "0123456789ABCDEF";
        write_cursor = scratch;
        do {
            value *= 16;
            mode = (int)value;
            value -= mode;
            *write_cursor++ = digits[mode];
        } while (precision-- && value);
        if (value > 0.5 || (value == 0.5 && mode & 1)) {

            digit_end = write_cursor;
            while (*--digit_end == digits[0xf]) {
                *digit_end = '0';
            }
            *digit_end = *digit_end == '9' ? digits[0xa] : *digit_end + 1;
        } else {
            while (precision-- >= 0) {
                *write_cursor++ = '0';
            }
        }
        *digit_count = write_cursor - scratch;
        return scratch;
    }

    if (conversion == 'f' || conversion == 'F') {
        mode = 3;
    } else {

        if (conversion == 'e' || conversion == 'E') {
            precision++;
        }
        mode = 2;
    }

    digits = medius_newlib_dtoa_r(reent, value, mode, precision, conversion_exponent,
                                  &ignored_dtoa_sign, &digit_end);

    if ((conversion != 'g' && conversion != 'G') || flags & PRINTF_ALTERNATE) {
        write_cursor = digits + precision;
        if (conversion == 'f' || conversion == 'F') {
            if (*digits == '0' && value)
                *conversion_exponent = -precision + 1;
            write_cursor += *conversion_exponent;
        }
        if (value == 0)
            digit_end = write_cursor;
        while (digit_end < write_cursor)
            *digit_end++ = '0';
    }
    *digit_count = digit_end - digits;
    return (digits);
}

/* Emit e/E with at least two exponent digits, or p/P with at least one.
 * Returns the number of bytes written; no NUL terminator is appended. */
static int format_exponent(char *destination, int binary_or_decimal_exponent, int conversion) {
    char *write_cursor, *read_cursor;
    char reversed_digits[7];

    int hexadecimal = conversion == 'a' || conversion == 'A';

    write_cursor = destination;
    *write_cursor++ = hexadecimal ? 'p' - 'a' + conversion : conversion;
    if (binary_or_decimal_exponent < 0) {
        binary_or_decimal_exponent = -binary_or_decimal_exponent;
        *write_cursor++ = '-';
    } else
        *write_cursor++ = '+';
    read_cursor = reversed_digits + 7;
    if (binary_or_decimal_exponent > 9) {
        do {
            *--read_cursor = format_digit_character(binary_or_decimal_exponent % 10);
        } while ((binary_or_decimal_exponent /= 10) > 9);
        *--read_cursor = format_digit_character(binary_or_decimal_exponent);
        for (; read_cursor < reversed_digits + 7; *write_cursor++ = *read_cursor++)
            ;
    } else {
        if (!hexadecimal)
            *write_cursor++ = '0';
        *write_cursor++ = format_digit_character(binary_or_decimal_exponent);
    }
    return (write_cursor - destination);
}

/* Native entry: 0x42017108. */
/* Medius v3.4.7 host; native function-byte SHA-256:
 * afb595fbc75676203da3bea9d5f6a991a921fbd2f5e3a2f30866a9ae7a0f9477.
 */

/* Format a 12-byte Xtensa va_list into the caller's string FILE.
 * Supports byte strings/chars, integer widths, %n, decimal/hexadecimal binary64,
 * positional arguments, field padding and locale numeric grouping. Eight
 * borrowed vectors are flushed together; every completed conversion flushes.
 * A growable stream with no buffer first receives 64 bytes. This core does not
 * append a NUL, initialize stdio, lock the stream or validate its arguments.
 * Returns the wrapping 32-bit formatted count, or -1 when the FILE error bit is
 * set. A malformed positional index can leave without setting that error bit;
 * zero/negative indices, oversized fields and NULL strings are not repaired.
 * %C/%S and l-prefixed characters/strings stay byte-based in this native build.
 * Decimal float storage belongs to reent; only temporary hex-float storage is
 * allocated/freed here. No bounds hardening or runtime equivalence is claimed.
 */
int medius_newlib_vformat_string(NewlibReent *reent, NewlibFile *stream,
                                 const char *format, va_list arguments) {
    char *format_cursor;
    int conversion;
    int temporary, literal_length;
    char *fragment;
    int flags;
    char *conversion_start;

    int conversion_index;
    int next_argument;
    int cached_count;
    const unsigned char *resume_format;
    MediusNewlibArgumentValue argument_cache[32];
    int argument_types[32];
    int positional;
    int saved_positional;

    int output_count;
    int width;
    int precision;
    char sign;

    char *thousands_sep = NULL;
    size_t separator_length = 0;
    const char *grouping = NULL;

    char *decimal_point = medius_newlib_localeconv()->decimal_point;
    size_t decimal_point_length = strlen(decimal_point);
    char floating_sign;
    double floating_value = 0;
    int conversion_exponent;
    int exponent_length = 0;
    char exponent_buffer[7];
    int leading_digits;

    int digit_count = 0;

    int distinct_separators;
    int repeated_separators;

    unsigned long long integer_magnitude;
    enum { PRINTF_OCTAL, PRINTF_DECIMAL, PRINTF_HEXADECIMAL } integer_base;
    int integer_precision;
    int field_length;
    int fragment_length;
    char *hex_digits = NULL;

    MediusNewlibStringWriteRequest output;
    MediusNewlibInputVector vectors[8];
    MediusNewlibInputVector *next_vector;

    char scratch[100];
    char hex_prefix[2];

    char *allocated_fragment = NULL;

    static const char space_padding[16] = {' ', ' ', ' ', ' ', ' ', ' ', ' ', ' ',
                                           ' ', ' ', ' ', ' ', ' ', ' ', ' ', ' '};
    static const char zero_padding[16] = {'0', '0', '0', '0', '0', '0', '0', '0',
                                          '0', '0', '0', '0', '0', '0', '0', '0'};

/* Fragments are borrowed until the next flush. Each conversion flushes before
 * releasing its temporary allocation. PAD_FIELD deliberately uses temporary. */
#define PRINT_FRAGMENT(pointer, fragment_bytes)                                                    \
    {                                                                                              \
        next_vector->base = (pointer);                                                             \
        next_vector->length = (fragment_bytes);                                                    \
        output.residual += (fragment_bytes);                                                       \
        ++next_vector;                                                                             \
        if (++output.count >= 8) {                                                                 \
            if (medius_newlib_write_string_vectors(reent, stream, &output))                        \
                goto finish;                                                                       \
            next_vector = vectors;                                                                 \
        }                                                                                          \
    }
#define PAD_FIELD(count, padding)                                                                  \
    {                                                                                              \
        if ((temporary = (count)) > 0) {                                                           \
            while (temporary > 16) {                                                               \
                PRINT_FRAGMENT(padding, 16);                                                       \
                temporary -= 16;                                                                   \
            }                                                                                      \
            PRINT_FRAGMENT(padding, temporary);                                                    \
        }                                                                                          \
    }
#define PRINT_AND_PAD(pointer, end, count, padding)                                                \
    {                                                                                              \
        int temporary = (end) - (pointer);                                                         \
        if (temporary > (count))                                                                   \
            temporary = (count);                                                                   \
        if (temporary > 0)                                                                         \
            PRINT_FRAGMENT(pointer, temporary);                                                    \
        PAD_FIELD((count) - (temporary > 0 ? temporary : 0), padding);                             \
    }
#define FLUSH_FRAGMENTS()                                                                          \
    {                                                                                              \
        if (output.residual && medius_newlib_write_string_vectors(reent, stream, &output))         \
            goto finish;                                                                           \
        output.count = 0;                                                                          \
        next_vector = vectors;                                                                     \
    }
/* Preserve unchecked zero/negative positional indices and the native
 * sequential-cache selection. The scanner resumes lazily from its last '%'. */
#define READ_ARGUMENT(index, type, member)                                                         \
    (positional ? ((index) < cached_count ? argument_cache[index].member                           \
                                          : medius_newlib_get_string_argument(                     \
                                                index, (const unsigned char *)conversion_start,    \
                                                (MediusXtensaVaListCursor *)(void *)&arguments,    \
                                                (unsigned int *)(void *)&cached_count,             \
                                                argument_cache, argument_types, &resume_format)    \
                                                ->member)                                          \
                : (next_argument++ < cached_count                                                  \
                       ? argument_cache[index].member                                              \
                       : (cached_count < 32                                                        \
                              ? (argument_cache[cached_count++].member = va_arg(arguments, type))  \
                              : va_arg(arguments, type))))
#define SIGNED_ARGUMENT()                                                                          \
    (flags & PRINTF_QUAD    ? READ_ARGUMENT(conversion_index, long long, quad_integer)             \
     : flags & PRINTF_LONG  ? READ_ARGUMENT(conversion_index, long, long_integer)                  \
     : flags & PRINTF_SHORT ? (long)(short)READ_ARGUMENT(conversion_index, int, integer)           \
     : flags & PRINTF_CHAR  ? (long)(signed char)READ_ARGUMENT(conversion_index, int, integer)     \
                            : (long)READ_ARGUMENT(conversion_index, int, integer))
#define UNSIGNED_ARGUMENT()                                                                        \
    (flags & PRINTF_QUAD                                                                           \
         ? READ_ARGUMENT(conversion_index, unsigned long long, unsigned_quad_integer)              \
     : flags & PRINTF_LONG ? READ_ARGUMENT(conversion_index, unsigned long, unsigned_long_integer) \
     : flags & PRINTF_SHORT                                                                        \
         ? (unsigned long)(unsigned short)READ_ARGUMENT(conversion_index, int, integer)            \
     : flags & PRINTF_CHAR                                                                         \
         ? (unsigned long)(unsigned char)READ_ARGUMENT(conversion_index, int, integer)             \
         : (unsigned long)READ_ARGUMENT(conversion_index, unsigned int, unsigned_integer))

    if (stream->flags & 0x80U && !stream->buffer_base) {
        stream->buffer_base = stream->cursor = medius_newlib_malloc_r(reent, 64);
        if (!stream->cursor) {
            reent->error_number = 12;
            return -1;
        }
        stream->buffer_capacity = 64;
    }

    format_cursor = (char *)format;

    output.vectors = next_vector = vectors;
    output.residual = 0;
    output.count = 0;

    output_count = 0;

    next_argument = 0;
    resume_format = NULL;
    argument_types[0] = -1;
    cached_count = 0;
    positional = 0;

    for (;;) {
        fragment = format_cursor;
        while (*format_cursor != '\0' && *format_cursor != '%')
            format_cursor += 1;

        if ((literal_length = format_cursor - fragment) != 0) {
            PRINT_FRAGMENT(fragment, literal_length);
            output_count = format_wrap_add(output_count, literal_length);
        }

        if (*format_cursor == '\0')
            goto flush_trailing_literal;

        conversion_start = format_cursor;
        format_cursor++;

        flags = 0;
        integer_precision = 0;
        width = 0;
        precision = -1;
        sign = '\0';

        leading_digits = 0;

        distinct_separators = repeated_separators = 0;

        conversion_index = next_argument;
        positional = 0;

    parse_flags:
        conversion = *format_cursor++;
    dispatch_conversion:
        switch (conversion) {

            case '\'':
                thousands_sep = medius_newlib_localeconv()->thousands_sep;
                separator_length = strlen(thousands_sep);
                grouping = medius_newlib_localeconv()->grouping;
                if (separator_length > 0 && grouping && *grouping)
                    flags |= PRINTF_GROUP;
                goto parse_flags;

            case ' ':

                if (!sign)
                    sign = ' ';
                goto parse_flags;
            case '#':
                flags |= PRINTF_ALTERNATE;
                goto parse_flags;
            case '*':

                temporary = conversion_index;
                saved_positional = positional;
                positional = 0;
                if (format_is_decimal_digit(*format_cursor)) {
                    char *saved_cursor = format_cursor;

                    temporary = 0;
                    conversion = *format_cursor++;
                    do {
                        temporary = (int)(10U * (unsigned int)temporary +
                                          (unsigned int)format_decimal_digit(conversion));
                        conversion = *format_cursor++;
                    } while (format_is_decimal_digit(conversion));

                    if (conversion == '$') {
                        if (temporary <= 32) {
                            temporary -= 1;
                            positional = 1;
                        } else
                            goto finish;
                    } else {
                        format_cursor = saved_cursor;
                        goto parse_flags;
                    }
                }

                width = READ_ARGUMENT(temporary, int, integer);

                positional = saved_positional;

                if (width >= 0)
                    goto parse_flags;
                width = (int)(0U - (unsigned int)width);

            case '-':
                flags |= PRINTF_LEFT_ADJUST;
                goto parse_flags;
            case '+':
                sign = '+';
                goto parse_flags;
            case '.':
                if ((conversion = *format_cursor++) == '*') {

                    temporary = conversion_index;
                    saved_positional = positional;
                    positional = 0;
                    if (format_is_decimal_digit(*format_cursor)) {
                        char *saved_cursor = format_cursor;

                        temporary = 0;
                        conversion = *format_cursor++;
                        do {
                            temporary = (int)(10U * (unsigned int)temporary +
                                              (unsigned int)format_decimal_digit(conversion));
                            conversion = *format_cursor++;
                        } while (format_is_decimal_digit(conversion));

                        if (conversion == '$') {
                            if (temporary <= 32) {
                                temporary -= 1;
                                positional = 1;
                            } else
                                goto finish;
                        } else {
                            format_cursor = saved_cursor;
                            goto parse_flags;
                        }
                    }

                    precision = READ_ARGUMENT(temporary, int, integer);

                    positional = saved_positional;

                    if (precision < 0)
                        precision = -1;
                    goto parse_flags;
                }
                temporary = 0;
                while (format_is_decimal_digit(conversion)) {
                    temporary = (int)(10U * (unsigned int)temporary +
                                      (unsigned int)format_decimal_digit(conversion));
                    conversion = *format_cursor++;
                }
                precision = temporary < 0 ? -1 : temporary;
                goto dispatch_conversion;
            case '0':

                flags |= PRINTF_ZERO_PAD;
                goto parse_flags;
            case '1':
            case '2':
            case '3':
            case '4':
            case '5':
            case '6':
            case '7':
            case '8':
            case '9':
                temporary = 0;
                do {
                    temporary = (int)(10U * (unsigned int)temporary +
                                      (unsigned int)format_decimal_digit(conversion));
                    conversion = *format_cursor++;
                } while (format_is_decimal_digit(conversion));

                if (conversion == '$') {
                    if (temporary <= 32) {
                        conversion_index = temporary - 1;
                        positional = 1;
                        goto parse_flags;
                    } else
                        goto finish;
                }

                width = temporary;
                goto dispatch_conversion;

            case 'L':
                flags |= PRINTF_LONG_DOUBLE;
                goto parse_flags;

            case 'h':

                if (*format_cursor == 'h') {
                    format_cursor++;
                    flags |= PRINTF_CHAR;
                } else

                    flags |= PRINTF_SHORT;
                goto parse_flags;
            case 'l':

                if (*format_cursor == 'l') {
                    format_cursor++;
                    flags |= PRINTF_QUAD;
                } else

                    flags |= PRINTF_LONG;
                goto parse_flags;
            case 'q':
                flags |= PRINTF_QUAD;
                goto parse_flags;

            case 'j':
                flags |= PRINTF_QUAD;
                goto parse_flags;
            case 'z':
            case 't':
                goto parse_flags;
            case 'C':

            case 'c':
                fragment = scratch;
                {
                    *fragment = READ_ARGUMENT(conversion_index, int, integer);
                    fragment_length = 1;
                }
                sign = '\0';
                break;
            case 'D':
                flags |= PRINTF_LONG;

            case 'd':
            case 'i':
                integer_magnitude = SIGNED_ARGUMENT();

                if ((long long)integer_magnitude < 0)

                {

                    integer_magnitude = -integer_magnitude;
                    sign = '-';
                }
                integer_base = PRINTF_DECIMAL;
                goto format_integer;

            case 'a':
            case 'A':
            case 'F':

            case 'e':
            case 'E':
            case 'f':
            case 'g':
            case 'G':

                if (flags & PRINTF_LONG_DOUBLE) {
                    floating_value =
                        (double)READ_ARGUMENT(conversion_index, long double, extended_floating);
                } else {
                    floating_value = READ_ARGUMENT(conversion_index, double, floating);
                }

                if (format_is_infinite(floating_value)) {
                    if (floating_value < 0)
                        sign = '-';
                    if (conversion <= 'G')
                        fragment = "INF";
                    else
                        fragment = "inf";
                    fragment_length = 3;
                    flags &= ~PRINTF_ZERO_PAD;
                    break;
                }
                if (format_is_nan(floating_value)) {
                    if (format_sign_bit(floating_value))
                        sign = '-';
                    if (conversion <= 'G')
                        fragment = "NAN";
                    else
                        fragment = "nan";
                    fragment_length = 3;
                    flags &= ~PRINTF_ZERO_PAD;
                    break;
                }

                if (conversion == 'a' || conversion == 'A') {
                    hex_prefix[0] = '0';
                    hex_prefix[1] = conversion == 'a' ? 'x' : 'X';
                    flags |= PRINTF_HEX_PREFIX;
                    if (precision >= 100) {
                        if ((allocated_fragment =
                                 (char *)medius_newlib_malloc_r(reent, precision + 1)) == NULL) {
                            stream->flags |= 0x40U;
                            goto finish;
                        }
                        fragment = allocated_fragment;
                    } else
                        fragment = scratch;
                } else

                    if (precision == -1) {
                    precision = 6;
                } else if ((conversion == 'g' || conversion == 'G') && precision == 0) {
                    precision = 1;
                }

                flags |= PRINTF_FLOAT;

                fragment =
                    format_float_digits(reent, floating_value, precision, flags, &floating_sign,
                                        &conversion_exponent, conversion, &digit_count, fragment);

                if (conversion == 'g' || conversion == 'G') {
                    if (conversion_exponent <= -4 || conversion_exponent > precision)
                        conversion -= 2;
                    else
                        conversion = 'g';
                }

                else if (conversion == 'F')
                    conversion = 'f';

                if (conversion <= 'e') {
                    --conversion_exponent;
                    exponent_length =
                        format_exponent(exponent_buffer, conversion_exponent, conversion);
                    fragment_length = exponent_length + digit_count;
                    if (digit_count > 1 || flags & PRINTF_ALTERNATE)
                        fragment_length += decimal_point_length;

                    flags &= ~PRINTF_GROUP;

                } else {
                    if (conversion == 'f') {
                        if (conversion_exponent > 0) {
                            fragment_length = conversion_exponent;
                            if (precision || flags & PRINTF_ALTERNATE)
                                fragment_length += precision + decimal_point_length;
                        } else
                            fragment_length = (precision || flags & PRINTF_ALTERNATE)
                                                  ? precision + 1 + decimal_point_length
                                                  : 1;
                    } else if (conversion_exponent >= digit_count) {
                        fragment_length = conversion_exponent;
                        if (flags & PRINTF_ALTERNATE)
                            fragment_length += decimal_point_length;
                    } else {
                        fragment_length = digit_count + decimal_point_length;
                        if (conversion_exponent <= 0)
                            fragment_length += 1 - conversion_exponent;
                    }

                    if ((flags & PRINTF_GROUP) && conversion_exponent > 0) {

                        distinct_separators = repeated_separators = 0;
                        leading_digits = conversion_exponent;
                        while (*grouping != CHAR_MAX) {
                            if (leading_digits <= *grouping)
                                break;
                            leading_digits -= *grouping;
                            if (grouping[1]) {
                                distinct_separators++;
                                grouping++;
                            } else
                                repeated_separators++;
                        }
                        fragment_length +=
                            (distinct_separators + repeated_separators) * separator_length;
                    } else

                        leading_digits = conversion_exponent;
                }

                if (floating_sign)
                    sign = '-';
                break;

            /* Count stores have no output and do not flush the pending vectors. */
            case 'n':

                if (flags & PRINTF_QUAD)
                    *READ_ARGUMENT(conversion_index, long long *, quad_pointer) = output_count;
                else

                    if (flags & PRINTF_LONG)
                    *READ_ARGUMENT(conversion_index, long *, long_pointer) = output_count;
                else if (flags & PRINTF_SHORT)
                    *READ_ARGUMENT(conversion_index, short *, short_pointer) = output_count;

                else if (flags & PRINTF_CHAR)
                    *READ_ARGUMENT(conversion_index, char *, string) = output_count;

                else
                    *READ_ARGUMENT(conversion_index, int *, integer_pointer) = output_count;
                continue;
            case 'O':
                flags |= PRINTF_LONG;

            case 'o':
                integer_magnitude = UNSIGNED_ARGUMENT();
                integer_base = PRINTF_OCTAL;

                flags &= ~PRINTF_GROUP;

                goto format_unsigned_integer;
            case 'p':

                integer_magnitude = (uintptr_t)READ_ARGUMENT(conversion_index, void *, pointer);
                integer_base = PRINTF_HEXADECIMAL;
                hex_digits = "0123456789abcdef";
                flags |= PRINTF_HEX_PREFIX;
                hex_prefix[0] = '0';
                hex_prefix[1] = conversion = 'x';
                goto format_unsigned_integer;
            case 's':

            case 'S':

                fragment = READ_ARGUMENT(conversion_index, char *, string);

                sign = '\0';
                if (precision >= 0) {

                    char *nul = memchr(fragment, 0, precision);

                    if (nul != NULL)
                        fragment_length = nul - fragment;
                    else
                        fragment_length = precision;
                } else
                    fragment_length = strlen(fragment);

                break;
            case 'U':
                flags |= PRINTF_LONG;

            case 'u':
                integer_magnitude = UNSIGNED_ARGUMENT();
                integer_base = PRINTF_DECIMAL;
                goto format_unsigned_integer;
            case 'X':
                hex_digits = "0123456789ABCDEF";
                goto format_hex_integer;
            case 'x':
                hex_digits = "0123456789abcdef";
            format_hex_integer:
                integer_magnitude = UNSIGNED_ARGUMENT();
                integer_base = PRINTF_HEXADECIMAL;

                if (flags & PRINTF_ALTERNATE && integer_magnitude != 0) {
                    hex_prefix[0] = '0';
                    hex_prefix[1] = conversion;
                    flags |= PRINTF_HEX_PREFIX;
                }

                flags &= ~PRINTF_GROUP;

            format_unsigned_integer:
                sign = '\0';

            format_integer:
                if ((integer_precision = precision) >= 0)
                    flags &= ~PRINTF_ZERO_PAD;

                fragment = scratch + 100;
                if (integer_magnitude != 0 || precision != 0) {

                    switch (integer_base) {
                        case PRINTF_OCTAL:
                            do {
                                *--fragment = format_digit_character(integer_magnitude & 7);
                                integer_magnitude >>= 3;
                            } while (integer_magnitude);

                            if (flags & PRINTF_ALTERNATE && *fragment != '0')
                                *--fragment = '0';
                            break;

                        case PRINTF_DECIMAL:

                            if (integer_magnitude < 10) {
                                *--fragment = format_digit_character(integer_magnitude);
                                break;
                            }

                            digit_count = 0;

                            do {
                                *--fragment = format_digit_character(integer_magnitude % 10);

                                digit_count++;

                                if ((flags & PRINTF_GROUP) && digit_count == *grouping &&
                                    *grouping != CHAR_MAX && integer_magnitude > 9) {
                                    fragment -= separator_length;
                                    strncpy(fragment, thousands_sep, separator_length);
                                    digit_count = 0;

                                    if (grouping[1] != '\0')
                                        grouping++;
                                }

                                integer_magnitude /= 10;
                            } while (integer_magnitude != 0);
                            break;

                        case PRINTF_HEXADECIMAL:
                            do {
                                *--fragment = hex_digits[integer_magnitude & 15];
                                integer_magnitude >>= 4;
                            } while (integer_magnitude);
                            break;

                        default:
                            fragment = "bug in vfprintf: bad base";
                            fragment_length = strlen(fragment);
                            goto integer_ready;
                    }
                }

                else if (integer_base == PRINTF_OCTAL && (flags & PRINTF_ALTERNATE))
                    *--fragment = '0';

                fragment_length = scratch + 100 - fragment;
            integer_ready:
                break;
            default:
                if (conversion == '\0')
                    goto flush_trailing_literal;

                fragment = scratch;
                *fragment = conversion;
                fragment_length = 1;
                sign = '\0';
                break;
        }

        /* Emit blank padding, sign/0x, zero padding, then the body. */
        field_length = integer_precision > fragment_length ? integer_precision : fragment_length;
        if (sign)
            field_length++;
        if (flags & PRINTF_HEX_PREFIX)
            field_length += 2;

        if ((flags & (PRINTF_LEFT_ADJUST | PRINTF_ZERO_PAD)) == 0)
            PAD_FIELD(width - field_length, space_padding);

        if (sign)
            PRINT_FRAGMENT(&sign, 1);
        if (flags & PRINTF_HEX_PREFIX)
            PRINT_FRAGMENT(hex_prefix, 2);

        if ((flags & (PRINTF_LEFT_ADJUST | PRINTF_ZERO_PAD)) == PRINTF_ZERO_PAD)
            PAD_FIELD(width - field_length, zero_padding);

        PAD_FIELD(integer_precision - fragment_length, zero_padding);

        if ((flags & PRINTF_FLOAT) == 0) {
            PRINT_FRAGMENT(fragment, fragment_length);
        } else {
            if (conversion >= 'f') {
                if (floating_value == 0) {

                    PRINT_FRAGMENT("0", 1);
                    if (conversion_exponent < digit_count || flags & PRINTF_ALTERNATE) {
                        PRINT_FRAGMENT(decimal_point, decimal_point_length);
                        PAD_FIELD(digit_count - 1, zero_padding);
                    }
                } else if (conversion_exponent <= 0) {
                    PRINT_FRAGMENT("0", 1);
                    if (conversion_exponent || digit_count || flags & PRINTF_ALTERNATE) {
                        PRINT_FRAGMENT(decimal_point, decimal_point_length);
                        PAD_FIELD(-conversion_exponent, zero_padding);
                        PRINT_FRAGMENT(fragment, digit_count);
                    }
                } else {
                    char *digit_start = fragment;
                    PRINT_AND_PAD(fragment, digit_start + digit_count, leading_digits,
                                  zero_padding);
                    fragment += leading_digits;

                    if (flags & PRINTF_GROUP) {
                        while (distinct_separators > 0 || repeated_separators > 0) {
                            if (repeated_separators > 0)
                                repeated_separators--;
                            else {
                                grouping--;
                                distinct_separators--;
                            }
                            PRINT_FRAGMENT(thousands_sep, separator_length);
                            PRINT_AND_PAD(fragment, digit_start + digit_count, *grouping,
                                          zero_padding);
                            fragment += *grouping;
                        }
                        if (fragment > digit_start + digit_count)
                            fragment = digit_start + digit_count;
                    }

                    if (conversion_exponent < digit_count || flags & PRINTF_ALTERNATE)
                        PRINT_FRAGMENT(decimal_point, decimal_point_length);
                    PRINT_AND_PAD(fragment, digit_start + digit_count,
                                  digit_count - conversion_exponent, zero_padding);
                }
            } else {
                if (digit_count > 1 || flags & PRINTF_ALTERNATE) {
                    PRINT_FRAGMENT(fragment, 1);
                    fragment++;
                    PRINT_FRAGMENT(decimal_point, decimal_point_length);
                    if (floating_value) {
                        PRINT_FRAGMENT(fragment, digit_count - 1);
                    } else

                        PAD_FIELD(digit_count - 1, zero_padding);
                } else
                    PRINT_FRAGMENT(fragment, 1);
                PRINT_FRAGMENT(exponent_buffer, exponent_length);
            }
        }

        if (flags & PRINTF_LEFT_ADJUST)
            PAD_FIELD(width - field_length, space_padding);

        output_count = format_wrap_add(output_count, width > field_length ? width : field_length);

        FLUSH_FRAGMENTS();

        if (allocated_fragment != NULL) {
            medius_newlib_free_r(reent, allocated_fragment);
            allocated_fragment = NULL;
        }
    }
flush_trailing_literal:
    FLUSH_FRAGMENTS();
finish:
    if (allocated_fragment != NULL)
        medius_newlib_free_r(reent, allocated_fragment);

    return ((stream->flags & 0x40U) ? -1 : output_count);

#undef PRINT_FRAGMENT
#undef PAD_FIELD
#undef PRINT_AND_PAD
#undef FLUSH_FRAGMENTS
#undef READ_ARGUMENT
#undef SIGNED_ARGUMENT
#undef UNSIGNED_ARGUMENT
}

/* Native entry: 0x4201a1b0. */
/* Medius v3.4.7 host; native function-byte SHA-256:
 * 367cc3264945b78ec4191d1c01fe27e55451a04fd12180f4e1a84f0f12fdc8a3.
 */

/* Format a 12-byte Xtensa va_list into a writable Newlib FILE.
 * Initialize stdio if reent exists and cleanup is NULL. Take/release the FILE's
 * recursive lock unless secondary bit 0 or primary flag 0x200 suppresses it.
 * Prepare the write buffer when necessary. For a write-only unbuffered stream
 * with a nonnegative descriptor, unlock and delegate to the 128-byte temporary
 * stream helper. Locale decimal-point lookup precedes stdio initialization.
 * Conversion, positional-cache, grouping and eight-vector behavior matches the
 * string core; this build treats %C/%S and l-strings as bytes and long double
 * as binary64. %n writes through the caller's pointer at the requested width.
 * Flush each completed conversion and free its temporary hex-float allocation.
 * Return the wrapping 32-bit formatted count, or -1 for a FILE error. Invalid
 * positional indices may leave without setting that bit. No input/field bounds,
 * pointer safety, timeout or runtime/timing guarantee is supplied.
 */
int medius_newlib_vformat_stream(NewlibReent *reent, NewlibFile *stream,
                                 const char *format, va_list arguments) {
    char *format_cursor;
    int conversion;
    int temporary, literal_length;
    char *fragment;
    int flags;
    char *conversion_start;

    int conversion_index;
    int next_argument;
    int cached_count;
    const unsigned char *resume_format;
    MediusNewlibArgumentValue argument_cache[32];
    int argument_types[32];
    int positional;
    int saved_positional;

    int output_count;
    int width;
    int precision;
    char sign;

    char *thousands_sep = NULL;
    size_t separator_length = 0;
    const char *grouping = NULL;

    char *decimal_point = medius_newlib_localeconv()->decimal_point;
    size_t decimal_point_length = strlen(decimal_point);
    char floating_sign;
    double floating_value = 0;
    int conversion_exponent;
    int exponent_length = 0;
    char exponent_buffer[7];
    int leading_digits;

    int digit_count = 0;

    int distinct_separators;
    int repeated_separators;

    unsigned long long integer_magnitude;
    enum { PRINTF_OCTAL, PRINTF_DECIMAL, PRINTF_HEXADECIMAL } integer_base;
    int integer_precision;
    int field_length;
    int fragment_length;
    char *hex_digits = NULL;

    MediusNewlibStringWriteRequest output;
    MediusNewlibInputVector vectors[8];
    MediusNewlibInputVector *next_vector;

    char scratch[100];
    char hex_prefix[2];

    char *allocated_fragment = NULL;

    static const char space_padding[16] = {' ', ' ', ' ', ' ', ' ', ' ', ' ', ' ',
                                           ' ', ' ', ' ', ' ', ' ', ' ', ' ', ' '};
    static const char zero_padding[16] = {'0', '0', '0', '0', '0', '0', '0', '0',
                                          '0', '0', '0', '0', '0', '0', '0', '0'};

/* Fragments are borrowed until the next flush. Each conversion flushes before
 * releasing its temporary allocation. PAD_FIELD deliberately uses temporary. */
#define PRINT_FRAGMENT(pointer, fragment_bytes)                                                    \
    {                                                                                              \
        next_vector->base = (pointer);                                                             \
        next_vector->length = (fragment_bytes);                                                    \
        output.residual += (fragment_bytes);                                                       \
        ++next_vector;                                                                             \
        if (++output.count >= 8) {                                                                 \
            if (medius_newlib_flush_vectors(reent, stream, &output))                               \
                goto finish;                                                                       \
            next_vector = vectors;                                                                 \
        }                                                                                          \
    }
#define PAD_FIELD(count, padding)                                                                  \
    {                                                                                              \
        if ((temporary = (count)) > 0) {                                                           \
            while (temporary > 16) {                                                               \
                PRINT_FRAGMENT(padding, 16);                                                       \
                temporary -= 16;                                                                   \
            }                                                                                      \
            PRINT_FRAGMENT(padding, temporary);                                                    \
        }                                                                                          \
    }
#define PRINT_AND_PAD(pointer, end, count, padding)                                                \
    {                                                                                              \
        int temporary = (end) - (pointer);                                                         \
        if (temporary > (count))                                                                   \
            temporary = (count);                                                                   \
        if (temporary > 0)                                                                         \
            PRINT_FRAGMENT(pointer, temporary);                                                    \
        PAD_FIELD((count) - (temporary > 0 ? temporary : 0), padding);                             \
    }
#define FLUSH_FRAGMENTS()                                                                          \
    {                                                                                              \
        if (output.residual && medius_newlib_flush_vectors(reent, stream, &output))                \
            goto finish;                                                                           \
        output.count = 0;                                                                          \
        next_vector = vectors;                                                                     \
    }
/* Preserve unchecked zero/negative positional indices and the native
 * sequential-cache selection. The scanner resumes lazily from its last '%'. */
#define READ_ARGUMENT(index, type, member)                                                         \
    (positional ? ((index) < cached_count ? argument_cache[index].member                           \
                                          : medius_newlib_get_stream_argument(                     \
                                                index, (const unsigned char *)conversion_start,    \
                                                (MediusXtensaVaListCursor *)(void *)&arguments,    \
                                                (unsigned int *)(void *)&cached_count,             \
                                                argument_cache, argument_types, &resume_format)    \
                                                ->member)                                          \
                : (next_argument++ < cached_count                                                  \
                       ? argument_cache[index].member                                              \
                       : (cached_count < 32                                                        \
                              ? (argument_cache[cached_count++].member = va_arg(arguments, type))  \
                              : va_arg(arguments, type))))
#define SIGNED_ARGUMENT()                                                                          \
    (flags & PRINTF_QUAD    ? READ_ARGUMENT(conversion_index, long long, quad_integer)             \
     : flags & PRINTF_LONG  ? READ_ARGUMENT(conversion_index, long, long_integer)                  \
     : flags & PRINTF_SHORT ? (long)(short)READ_ARGUMENT(conversion_index, int, integer)           \
     : flags & PRINTF_CHAR  ? (long)(signed char)READ_ARGUMENT(conversion_index, int, integer)     \
                            : (long)READ_ARGUMENT(conversion_index, int, integer))
#define UNSIGNED_ARGUMENT()                                                                        \
    (flags & PRINTF_QUAD                                                                           \
         ? READ_ARGUMENT(conversion_index, unsigned long long, unsigned_quad_integer)              \
     : flags & PRINTF_LONG ? READ_ARGUMENT(conversion_index, unsigned long, unsigned_long_integer) \
     : flags & PRINTF_SHORT                                                                        \
         ? (unsigned long)(unsigned short)READ_ARGUMENT(conversion_index, int, integer)            \
     : flags & PRINTF_CHAR                                                                         \
         ? (unsigned long)(unsigned char)READ_ARGUMENT(conversion_index, int, integer)             \
         : (unsigned long)READ_ARGUMENT(conversion_index, unsigned int, unsigned_integer))

    if (reent != NULL && reent->cleanup == NULL)
        medius_newlib_initialize_stdio_context(reent);
    if (!(stream->secondary_flags & 1) && !(stream->flags & 0x200U))
        __retarget_lock_acquire_recursive(stream->lock);

    if (((!(stream->flags & 0x8U) || stream->buffer_base == NULL) &&
         medius_newlib_prepare_write(reent, stream))) {
        if (!(stream->secondary_flags & 1) && !(stream->flags & 0x200U))
            __retarget_lock_release_recursive(stream->lock);
        return (-1);
    }

    if ((stream->flags & (0x2U | 0x8U | 0x10U)) == (0x2U | 0x8U) && stream->file_descriptor >= 0) {
        if (!(stream->secondary_flags & 1) && !(stream->flags & 0x200U))
            __retarget_lock_release_recursive(stream->lock);
        return (medius_newlib_format_temporary_stream(reent, stream, format, arguments));
    }

    format_cursor = (char *)format;

    output.vectors = next_vector = vectors;
    output.residual = 0;
    output.count = 0;

    output_count = 0;

    next_argument = 0;
    resume_format = NULL;
    argument_types[0] = -1;
    cached_count = 0;
    positional = 0;

    for (;;) {
        fragment = format_cursor;
        while (*format_cursor != '\0' && *format_cursor != '%')
            format_cursor += 1;

        if ((literal_length = format_cursor - fragment) != 0) {
            PRINT_FRAGMENT(fragment, literal_length);
            output_count = format_wrap_add(output_count, literal_length);
        }

        if (*format_cursor == '\0')
            goto flush_trailing_literal;

        conversion_start = format_cursor;
        format_cursor++;

        flags = 0;
        integer_precision = 0;
        width = 0;
        precision = -1;
        sign = '\0';

        leading_digits = 0;

        distinct_separators = repeated_separators = 0;

        conversion_index = next_argument;
        positional = 0;

    parse_flags:
        conversion = *format_cursor++;
    dispatch_conversion:
        switch (conversion) {

            case '\'':
                thousands_sep = medius_newlib_localeconv()->thousands_sep;
                separator_length = strlen(thousands_sep);
                grouping = medius_newlib_localeconv()->grouping;
                if (separator_length > 0 && grouping && *grouping)
                    flags |= PRINTF_GROUP;
                goto parse_flags;

            case ' ':

                if (!sign)
                    sign = ' ';
                goto parse_flags;
            case '#':
                flags |= PRINTF_ALTERNATE;
                goto parse_flags;
            case '*':

                temporary = conversion_index;
                saved_positional = positional;
                positional = 0;
                if (format_is_decimal_digit(*format_cursor)) {
                    char *saved_cursor = format_cursor;

                    temporary = 0;
                    conversion = *format_cursor++;
                    do {
                        temporary = (int)(10U * (unsigned int)temporary +
                                          (unsigned int)format_decimal_digit(conversion));
                        conversion = *format_cursor++;
                    } while (format_is_decimal_digit(conversion));

                    if (conversion == '$') {
                        if (temporary <= 32) {
                            temporary -= 1;
                            positional = 1;
                        } else
                            goto finish;
                    } else {
                        format_cursor = saved_cursor;
                        goto parse_flags;
                    }
                }

                width = READ_ARGUMENT(temporary, int, integer);

                positional = saved_positional;

                if (width >= 0)
                    goto parse_flags;
                width = (int)(0U - (unsigned int)width);

            case '-':
                flags |= PRINTF_LEFT_ADJUST;
                goto parse_flags;
            case '+':
                sign = '+';
                goto parse_flags;
            case '.':
                if ((conversion = *format_cursor++) == '*') {

                    temporary = conversion_index;
                    saved_positional = positional;
                    positional = 0;
                    if (format_is_decimal_digit(*format_cursor)) {
                        char *saved_cursor = format_cursor;

                        temporary = 0;
                        conversion = *format_cursor++;
                        do {
                            temporary = (int)(10U * (unsigned int)temporary +
                                              (unsigned int)format_decimal_digit(conversion));
                            conversion = *format_cursor++;
                        } while (format_is_decimal_digit(conversion));

                        if (conversion == '$') {
                            if (temporary <= 32) {
                                temporary -= 1;
                                positional = 1;
                            } else
                                goto finish;
                        } else {
                            format_cursor = saved_cursor;
                            goto parse_flags;
                        }
                    }

                    precision = READ_ARGUMENT(temporary, int, integer);

                    positional = saved_positional;

                    if (precision < 0)
                        precision = -1;
                    goto parse_flags;
                }
                temporary = 0;
                while (format_is_decimal_digit(conversion)) {
                    temporary = (int)(10U * (unsigned int)temporary +
                                      (unsigned int)format_decimal_digit(conversion));
                    conversion = *format_cursor++;
                }
                precision = temporary < 0 ? -1 : temporary;
                goto dispatch_conversion;
            case '0':

                flags |= PRINTF_ZERO_PAD;
                goto parse_flags;
            case '1':
            case '2':
            case '3':
            case '4':
            case '5':
            case '6':
            case '7':
            case '8':
            case '9':
                temporary = 0;
                do {
                    temporary = (int)(10U * (unsigned int)temporary +
                                      (unsigned int)format_decimal_digit(conversion));
                    conversion = *format_cursor++;
                } while (format_is_decimal_digit(conversion));

                if (conversion == '$') {
                    if (temporary <= 32) {
                        conversion_index = temporary - 1;
                        positional = 1;
                        goto parse_flags;
                    } else
                        goto finish;
                }

                width = temporary;
                goto dispatch_conversion;

            case 'L':
                flags |= PRINTF_LONG_DOUBLE;
                goto parse_flags;

            case 'h':

                if (*format_cursor == 'h') {
                    format_cursor++;
                    flags |= PRINTF_CHAR;
                } else

                    flags |= PRINTF_SHORT;
                goto parse_flags;
            case 'l':

                if (*format_cursor == 'l') {
                    format_cursor++;
                    flags |= PRINTF_QUAD;
                } else

                    flags |= PRINTF_LONG;
                goto parse_flags;
            case 'q':
                flags |= PRINTF_QUAD;
                goto parse_flags;

            case 'j':
                flags |= PRINTF_QUAD;
                goto parse_flags;
            case 'z':
            case 't':
                goto parse_flags;
            case 'C':

            case 'c':
                fragment = scratch;
                {
                    *fragment = READ_ARGUMENT(conversion_index, int, integer);
                    fragment_length = 1;
                }
                sign = '\0';
                break;
            case 'D':
                flags |= PRINTF_LONG;

            case 'd':
            case 'i':
                integer_magnitude = SIGNED_ARGUMENT();

                if ((long long)integer_magnitude < 0)

                {

                    integer_magnitude = -integer_magnitude;
                    sign = '-';
                }
                integer_base = PRINTF_DECIMAL;
                goto format_integer;

            case 'a':
            case 'A':
            case 'F':

            case 'e':
            case 'E':
            case 'f':
            case 'g':
            case 'G':

                if (flags & PRINTF_LONG_DOUBLE) {
                    floating_value =
                        (double)READ_ARGUMENT(conversion_index, long double, extended_floating);
                } else {
                    floating_value = READ_ARGUMENT(conversion_index, double, floating);
                }

                if (format_is_infinite(floating_value)) {
                    if (floating_value < 0)
                        sign = '-';
                    if (conversion <= 'G')
                        fragment = "INF";
                    else
                        fragment = "inf";
                    fragment_length = 3;
                    flags &= ~PRINTF_ZERO_PAD;
                    break;
                }
                if (format_is_nan(floating_value)) {
                    if (format_sign_bit(floating_value))
                        sign = '-';
                    if (conversion <= 'G')
                        fragment = "NAN";
                    else
                        fragment = "nan";
                    fragment_length = 3;
                    flags &= ~PRINTF_ZERO_PAD;
                    break;
                }

                if (conversion == 'a' || conversion == 'A') {
                    hex_prefix[0] = '0';
                    hex_prefix[1] = conversion == 'a' ? 'x' : 'X';
                    flags |= PRINTF_HEX_PREFIX;
                    if (precision >= 100) {
                        if ((allocated_fragment =
                                 (char *)medius_newlib_malloc_r(reent, precision + 1)) == NULL) {
                            stream->flags |= 0x40U;
                            goto finish;
                        }
                        fragment = allocated_fragment;
                    } else
                        fragment = scratch;
                } else

                    if (precision == -1) {
                    precision = 6;
                } else if ((conversion == 'g' || conversion == 'G') && precision == 0) {
                    precision = 1;
                }

                flags |= PRINTF_FLOAT;

                fragment =
                    format_float_digits(reent, floating_value, precision, flags, &floating_sign,
                                        &conversion_exponent, conversion, &digit_count, fragment);

                if (conversion == 'g' || conversion == 'G') {
                    if (conversion_exponent <= -4 || conversion_exponent > precision)
                        conversion -= 2;
                    else
                        conversion = 'g';
                }

                else if (conversion == 'F')
                    conversion = 'f';

                if (conversion <= 'e') {
                    --conversion_exponent;
                    exponent_length =
                        format_exponent(exponent_buffer, conversion_exponent, conversion);
                    fragment_length = exponent_length + digit_count;
                    if (digit_count > 1 || flags & PRINTF_ALTERNATE)
                        fragment_length += decimal_point_length;

                    flags &= ~PRINTF_GROUP;

                } else {
                    if (conversion == 'f') {
                        if (conversion_exponent > 0) {
                            fragment_length = conversion_exponent;
                            if (precision || flags & PRINTF_ALTERNATE)
                                fragment_length += precision + decimal_point_length;
                        } else
                            fragment_length = (precision || flags & PRINTF_ALTERNATE)
                                                  ? precision + 1 + decimal_point_length
                                                  : 1;
                    } else if (conversion_exponent >= digit_count) {
                        fragment_length = conversion_exponent;
                        if (flags & PRINTF_ALTERNATE)
                            fragment_length += decimal_point_length;
                    } else {
                        fragment_length = digit_count + decimal_point_length;
                        if (conversion_exponent <= 0)
                            fragment_length += 1 - conversion_exponent;
                    }

                    if ((flags & PRINTF_GROUP) && conversion_exponent > 0) {

                        distinct_separators = repeated_separators = 0;
                        leading_digits = conversion_exponent;
                        while (*grouping != CHAR_MAX) {
                            if (leading_digits <= *grouping)
                                break;
                            leading_digits -= *grouping;
                            if (grouping[1]) {
                                distinct_separators++;
                                grouping++;
                            } else
                                repeated_separators++;
                        }
                        fragment_length +=
                            (distinct_separators + repeated_separators) * separator_length;
                    } else

                        leading_digits = conversion_exponent;
                }

                if (floating_sign)
                    sign = '-';
                break;

            /* Count stores have no output and do not flush the pending vectors. */
            case 'n':

                if (flags & PRINTF_QUAD)
                    *READ_ARGUMENT(conversion_index, long long *, quad_pointer) = output_count;
                else

                    if (flags & PRINTF_LONG)
                    *READ_ARGUMENT(conversion_index, long *, long_pointer) = output_count;
                else if (flags & PRINTF_SHORT)
                    *READ_ARGUMENT(conversion_index, short *, short_pointer) = output_count;

                else if (flags & PRINTF_CHAR)
                    *READ_ARGUMENT(conversion_index, char *, string) = output_count;

                else
                    *READ_ARGUMENT(conversion_index, int *, integer_pointer) = output_count;
                continue;
            case 'O':
                flags |= PRINTF_LONG;

            case 'o':
                integer_magnitude = UNSIGNED_ARGUMENT();
                integer_base = PRINTF_OCTAL;

                flags &= ~PRINTF_GROUP;

                goto format_unsigned_integer;
            case 'p':

                integer_magnitude = (uintptr_t)READ_ARGUMENT(conversion_index, void *, pointer);
                integer_base = PRINTF_HEXADECIMAL;
                hex_digits = "0123456789abcdef";
                flags |= PRINTF_HEX_PREFIX;
                hex_prefix[0] = '0';
                hex_prefix[1] = conversion = 'x';
                goto format_unsigned_integer;
            case 's':

            case 'S':

                fragment = READ_ARGUMENT(conversion_index, char *, string);

                sign = '\0';
                if (precision >= 0) {

                    char *nul = memchr(fragment, 0, precision);

                    if (nul != NULL)
                        fragment_length = nul - fragment;
                    else
                        fragment_length = precision;
                } else
                    fragment_length = strlen(fragment);

                break;
            case 'U':
                flags |= PRINTF_LONG;

            case 'u':
                integer_magnitude = UNSIGNED_ARGUMENT();
                integer_base = PRINTF_DECIMAL;
                goto format_unsigned_integer;
            case 'X':
                hex_digits = "0123456789ABCDEF";
                goto format_hex_integer;
            case 'x':
                hex_digits = "0123456789abcdef";
            format_hex_integer:
                integer_magnitude = UNSIGNED_ARGUMENT();
                integer_base = PRINTF_HEXADECIMAL;

                if (flags & PRINTF_ALTERNATE && integer_magnitude != 0) {
                    hex_prefix[0] = '0';
                    hex_prefix[1] = conversion;
                    flags |= PRINTF_HEX_PREFIX;
                }

                flags &= ~PRINTF_GROUP;

            format_unsigned_integer:
                sign = '\0';

            format_integer:
                if ((integer_precision = precision) >= 0)
                    flags &= ~PRINTF_ZERO_PAD;

                fragment = scratch + 100;
                if (integer_magnitude != 0 || precision != 0) {

                    switch (integer_base) {
                        case PRINTF_OCTAL:
                            do {
                                *--fragment = format_digit_character(integer_magnitude & 7);
                                integer_magnitude >>= 3;
                            } while (integer_magnitude);

                            if (flags & PRINTF_ALTERNATE && *fragment != '0')
                                *--fragment = '0';
                            break;

                        case PRINTF_DECIMAL:

                            if (integer_magnitude < 10) {
                                *--fragment = format_digit_character(integer_magnitude);
                                break;
                            }

                            digit_count = 0;

                            do {
                                *--fragment = format_digit_character(integer_magnitude % 10);

                                digit_count++;

                                if ((flags & PRINTF_GROUP) && digit_count == *grouping &&
                                    *grouping != CHAR_MAX && integer_magnitude > 9) {
                                    fragment -= separator_length;
                                    strncpy(fragment, thousands_sep, separator_length);
                                    digit_count = 0;

                                    if (grouping[1] != '\0')
                                        grouping++;
                                }

                                integer_magnitude /= 10;
                            } while (integer_magnitude != 0);
                            break;

                        case PRINTF_HEXADECIMAL:
                            do {
                                *--fragment = hex_digits[integer_magnitude & 15];
                                integer_magnitude >>= 4;
                            } while (integer_magnitude);
                            break;

                        default:
                            fragment = "bug in vfprintf: bad base";
                            fragment_length = strlen(fragment);
                            goto integer_ready;
                    }
                }

                else if (integer_base == PRINTF_OCTAL && (flags & PRINTF_ALTERNATE))
                    *--fragment = '0';

                fragment_length = scratch + 100 - fragment;
            integer_ready:
                break;
            default:
                if (conversion == '\0')
                    goto flush_trailing_literal;

                fragment = scratch;
                *fragment = conversion;
                fragment_length = 1;
                sign = '\0';
                break;
        }

        /* Emit blank padding, sign/0x, zero padding, then the body. */
        field_length = integer_precision > fragment_length ? integer_precision : fragment_length;
        if (sign)
            field_length++;
        if (flags & PRINTF_HEX_PREFIX)
            field_length += 2;

        if ((flags & (PRINTF_LEFT_ADJUST | PRINTF_ZERO_PAD)) == 0)
            PAD_FIELD(width - field_length, space_padding);

        if (sign)
            PRINT_FRAGMENT(&sign, 1);
        if (flags & PRINTF_HEX_PREFIX)
            PRINT_FRAGMENT(hex_prefix, 2);

        if ((flags & (PRINTF_LEFT_ADJUST | PRINTF_ZERO_PAD)) == PRINTF_ZERO_PAD)
            PAD_FIELD(width - field_length, zero_padding);

        PAD_FIELD(integer_precision - fragment_length, zero_padding);

        if ((flags & PRINTF_FLOAT) == 0) {
            PRINT_FRAGMENT(fragment, fragment_length);
        } else {
            if (conversion >= 'f') {
                if (floating_value == 0) {

                    PRINT_FRAGMENT("0", 1);
                    if (conversion_exponent < digit_count || flags & PRINTF_ALTERNATE) {
                        PRINT_FRAGMENT(decimal_point, decimal_point_length);
                        PAD_FIELD(digit_count - 1, zero_padding);
                    }
                } else if (conversion_exponent <= 0) {
                    PRINT_FRAGMENT("0", 1);
                    if (conversion_exponent || digit_count || flags & PRINTF_ALTERNATE) {
                        PRINT_FRAGMENT(decimal_point, decimal_point_length);
                        PAD_FIELD(-conversion_exponent, zero_padding);
                        PRINT_FRAGMENT(fragment, digit_count);
                    }
                } else {
                    char *digit_start = fragment;
                    PRINT_AND_PAD(fragment, digit_start + digit_count, leading_digits,
                                  zero_padding);
                    fragment += leading_digits;

                    if (flags & PRINTF_GROUP) {
                        while (distinct_separators > 0 || repeated_separators > 0) {
                            if (repeated_separators > 0)
                                repeated_separators--;
                            else {
                                grouping--;
                                distinct_separators--;
                            }
                            PRINT_FRAGMENT(thousands_sep, separator_length);
                            PRINT_AND_PAD(fragment, digit_start + digit_count, *grouping,
                                          zero_padding);
                            fragment += *grouping;
                        }
                        if (fragment > digit_start + digit_count)
                            fragment = digit_start + digit_count;
                    }

                    if (conversion_exponent < digit_count || flags & PRINTF_ALTERNATE)
                        PRINT_FRAGMENT(decimal_point, decimal_point_length);
                    PRINT_AND_PAD(fragment, digit_start + digit_count,
                                  digit_count - conversion_exponent, zero_padding);
                }
            } else {
                if (digit_count > 1 || flags & PRINTF_ALTERNATE) {
                    PRINT_FRAGMENT(fragment, 1);
                    fragment++;
                    PRINT_FRAGMENT(decimal_point, decimal_point_length);
                    if (floating_value) {
                        PRINT_FRAGMENT(fragment, digit_count - 1);
                    } else

                        PAD_FIELD(digit_count - 1, zero_padding);
                } else
                    PRINT_FRAGMENT(fragment, 1);
                PRINT_FRAGMENT(exponent_buffer, exponent_length);
            }
        }

        if (flags & PRINTF_LEFT_ADJUST)
            PAD_FIELD(width - field_length, space_padding);

        output_count = format_wrap_add(output_count, width > field_length ? width : field_length);

        FLUSH_FRAGMENTS();

        if (allocated_fragment != NULL) {
            medius_newlib_free_r(reent, allocated_fragment);
            allocated_fragment = NULL;
        }
    }
flush_trailing_literal:
    FLUSH_FRAGMENTS();
finish:
    if (allocated_fragment != NULL)
        medius_newlib_free_r(reent, allocated_fragment);

    if (!(stream->secondary_flags & 1) && !(stream->flags & 0x200U))
        __retarget_lock_release_recursive(stream->lock);

    return ((stream->flags & 0x40U) ? -1 : output_count);

#undef PRINT_FRAGMENT
#undef PAD_FIELD
#undef PRINT_AND_PAD
#undef FLUSH_FRAGMENTS
#undef READ_ARGUMENT
#undef SIGNED_ARGUMENT
#undef UNSIGNED_ARGUMENT
}
