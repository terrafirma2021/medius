/* Medius v3.4.7 device — runtime/number_conversion.c.
 * Recovered C and native assembly, grouped for source navigation.
 * Original entry addresses, firmware-byte hashes and function comments follow.
 */

#include "../include/types.h"

/* Native entry: 0x4201f614. */
/*
 * Medius v3.4.7 — device application; 0x4201f614.
 *
 * Extracts a decimal quotient digit from normalized Bigints, subtracting an estimated denominator multiple in place from the numerator, correcting the estimate by magnitude comparison and trimming high zero words.
 *
 * Calls: __mcmp.
 *
 * Called by: _dtoa_r.
 *
 * Original function-byte SHA-256:
 * 0f5b8619a6ef98751bd04cdc26d34efb976c30050706eeb31b063ed0f747f406.
 */

/****************************************************************
 *
 * The author of this software is David M. Gay.
 *
 * Copyright (c) 1991 by AT&T.
 *
 * Permission to use, copy, modify, and distribute this software for any
 * purpose without fee is hereby granted, provided that this entire notice
 * is included in all copies of any software which is or includes a copy
 * or modification of this software and in all copies of the supporting
 * documentation for such software.
 *
 * THIS SOFTWARE IS BEING PROVIDED "AS IS", WITHOUT ANY EXPRESS OR IMPLIED
 * WARRANTY.  IN PARTICULAR, NEITHER THE AUTHOR NOR AT&T MAKES ANY
 * REPRESENTATION OR WARRANTY OF ANY KIND CONCERNING THE MERCHANTABILITY
 * OF THIS SOFTWARE OR ITS FITNESS FOR ANY PARTICULAR PURPOSE.
 *
 ***************************************************************/

/* Reconstructed from the instruction-matched Newlib implementation by David M. Gay.
 * Primary reference: espressif/newlib-esp32, commit
 * d16a927c7334602a563893fa53b3746afdd31c0d, newlib/libc/stdlib/.
 * Typed layouts and binary64 word views retain the ESP32-S3 ABI. Control flow,
 * allocation ownership, halfword arithmetic and rounding branches were reviewed
 * against the original firmware instructions. Borrow propagation uses signed
 * arithmetic right shifts; packing a result word uses an unsigned left shift.
 */

/*
 * numerator: Writable normalized magnitude; overwritten with the remainder.
 * denominator: Readable nonoverlapping normalized divisor; high word plus one must not wrap.
 * Returns: The estimated quotient with at most one correction; under the formatter's scaling
 *   invariant this is one decimal digit.
 * Requirements/effects: No allocation or locking. Caller supplies the formatter's relative word-
 *   count and normalized-divisor bounds; this is not general arbitrary-size division. A shorter
 *   numerator returns zero unchanged. Subtracts the estimated product, corrects once if needed and
 *   trims high zero words. Denominator is unchanged. Signed arithmetic right shifts propagate
 *   the borrow; an unsigned left shift packs the upper half of each stored result word.
 */

static int quorem(MediusBigInt *numerator, MediusBigInt *denominator) {
    int last_word_index;
    long borrow, low_difference;
    unsigned int carry, quotient, low_product;
    unsigned int *numerator_cursor, *numerator_high, *denominator_cursor, *denominator_high;
    long high_difference;
    unsigned int denominator_word, high_product;
    last_word_index = denominator->used_words;
    if (numerator->used_words < last_word_index)
        return 0;
    denominator_cursor = denominator->words;
    denominator_high = denominator_cursor + --last_word_index;
    numerator_cursor = numerator->words;
    numerator_high = numerator_cursor + last_word_index;
    quotient = *numerator_high / (*denominator_high + 1);
    if (quotient) {
        borrow = 0;
        carry = 0;
        do {
            denominator_word = *denominator_cursor++;
            low_product = (denominator_word & 0xffff) * quotient + carry;
            high_product = (denominator_word >> 16) * quotient + (low_product >> 16);
            carry = high_product >> 16;
            low_difference = (*numerator_cursor & 0xffff) - (low_product & 0xffff) + borrow;
            borrow = low_difference >> 16;
            high_difference = (*numerator_cursor >> 16) - (high_product & 0xffff) + borrow;
            borrow = high_difference >> 16;
            (*(numerator_cursor)++ =
                 ((unsigned long)(high_difference) << 16) | ((low_difference) & 0xffff));
        } while (denominator_cursor <= denominator_high);
        if (!*numerator_high) {
            numerator_cursor = numerator->words;
            while (--numerator_high > numerator_cursor && !*numerator_high)
                --last_word_index;
            numerator->used_words = last_word_index;
        }
    }
    if (__mcmp(numerator, denominator) >= 0) {
        quotient++;
        borrow = 0;
        carry = 0;
        numerator_cursor = numerator->words;
        denominator_cursor = denominator->words;
        do {
            denominator_word = *denominator_cursor++;
            low_product = (denominator_word & 0xffff) + carry;
            high_product = (denominator_word >> 16) + (low_product >> 16);
            carry = high_product >> 16;
            low_difference = (*numerator_cursor & 0xffff) - (low_product & 0xffff) + borrow;
            borrow = low_difference >> 16;
            high_difference = (*numerator_cursor >> 16) - (high_product & 0xffff) + borrow;
            borrow = high_difference >> 16;
            (*(numerator_cursor)++ =
                 ((unsigned long)(high_difference) << 16) | ((low_difference) & 0xffff));
        } while (denominator_cursor <= denominator_high);
        numerator_cursor = numerator->words;
        numerator_high = numerator_cursor + last_word_index;
        if (!*numerator_high) {
            while (--numerator_high > numerator_cursor && !*numerator_high)
                --last_word_index;
            numerator->used_words = last_word_index;
        }
    }
    return quotient;
}

/* Native entry: 0x4201f74c. */
/*
 * Medius v3.4.7 — device application; 0x4201f74c.
 *
 * Formats a binary64 value as decimal digits using the selected mode and precision. Reports decimal-point position, sign and optional end pointer; handles zero, Infinity and NaN. Reuses per-context result storage and uses multi-precision powers of five for rounding-sensitive paths.
 *
 * Calls: __assert_func, malloc, quorem, _Balloc, _Bfree, __multadd,
 * __i2b, __multiply, __pow5mult, __lshift, __mdiff, __d2b,
 * __hi0bits, __mcmp, __adddf3, __divdf3, __eqdf2, __fixdfsi, __floatsidf, __floatunsidf,
 * __gtdf2, __ledf2, __ltdf2, __muldf3; plus 3 other direct targets.
 *
 * Called by: FUN_4201959c, FUN_4201c644.
 *
 * Original function-byte SHA-256:
 * 2c43c478f5e63b86703ca967c519f6c2e974cb31418209978aae7fe21382c16c.
 */

/****************************************************************
 *
 * The author of this software is David M. Gay.
 *
 * Copyright (c) 1991 by AT&T.
 *
 * Permission to use, copy, modify, and distribute this software for any
 * purpose without fee is hereby granted, provided that this entire notice
 * is included in all copies of any software which is or includes a copy
 * or modification of this software and in all copies of the supporting
 * documentation for such software.
 *
 * THIS SOFTWARE IS BEING PROVIDED "AS IS", WITHOUT ANY EXPRESS OR IMPLIED
 * WARRANTY.  IN PARTICULAR, NEITHER THE AUTHOR NOR AT&T MAKES ANY
 * REPRESENTATION OR WARRANTY OF ANY KIND CONCERNING THE MERCHANTABILITY
 * OF THIS SOFTWARE OR ITS FITNESS FOR ANY PARTICULAR PURPOSE.
 *
 ***************************************************************/

/* Reconstructed from the instruction-matched Newlib implementation by David M. Gay.
 * Primary reference: espressif/newlib-esp32, commit
 * d16a927c7334602a563893fa53b3746afdd31c0d, newlib/libc/stdlib/.
 * Typed layouts and binary64 word views retain the ESP32-S3 ABI. Control flow,
 * allocation ownership, halfword arithmetic and rounding branches were reviewed
 * against the original firmware instructions. Borrow propagation uses signed
 * arithmetic right shifts; packing a result word uses an unsigned left shift.
 */

/*
 * reent: Live private conversion context; a subsequent conversion invalidates its previous
 *   allocated digit buffer.
 * value: Binary64 input, including signed zero, infinity and NaN.
 * mode: 0: shortest round-trip; 1: Steele/White stopping; 2/3: significant/fractional digits; 4/5:
 *   corresponding margin-aware forms. Modes 6..9 map to 2..5 with the quick path disabled; other
 *   values map to 0.
 * digits: Requested precision for modes 2..9; modes 2/4 use at least one significant digit.
 *   Fractional precision may be negative; intermediate size arithmetic must stay supported.
 * decimal_point: Required writable output: decimal-point position; 9999 for NaN/infinity, 1 for
 *   zero.
 * sign: Required writable output: original sign bit, including negative zero or NaN.
 * end: Optional output pointing just after the returned characters, at the terminating NUL.
 * Returns: NUL-terminated unsigned decimal digits with trailing zeros suppressed, or static
 *   strings "0", "Infinity" or "NaN". Decimal position and sign are returned separately.
 * Requirements/effects: Uses the supplied Newlib context without locking; concurrent users require
 *   caller exclusion. Bigint metadata, capacities and allocation arithmetic must be valid.
 *   Recycles the previous dynamic result, estimates the decimal exponent, tries bounded floating-
 *   point/integer paths and falls back to scaled Bigint division with rounding margins and ties-
 *   to-even. The result uses the context-owned allocation itself as character storage. Required
 *   allocation failures assert; there is no general precision upper-bound check or allocation-free
 *   guarantee.
 */

char *_dtoa_r(struct NewlibReent *reent, double value, int mode, int digits,
              int *decimal_point, int *sign, char **end) {
    int significand_bits, numerator_twos, numerator_fives, binary_exponent, digit, working_int,
        rounding_error_units, digit_limit, initial_digit_limit, alternate_digit_limit,
        working_shift, secondary_shift, decimal_exponent, initial_decimal_exponent,
        check_decimal_exponent, track_rounding_margins, margin_twos, margin_fives, denominator_twos,
        denominator_fives, power_of_two_boundary, try_fast_path;
    MediusBinary64 input_bits, saved_or_normalized, error_bound;
    long integer_digit;
    int is_subnormal;
    unsigned int subnormal_significand;
    MediusBigInt *numerator, *temporary_bigint, *remainder_margin, *lower_margin = ((void *)0),
                                                                   *upper_margin, *denominator;
    double scaled_value;
    char *write_cursor, *digits_buffer;
    /* Recycle the previous digit buffer before inspecting this input. */
    input_bits.value = value;
    if (reent->mprec == ((void *)0)) {
        reent->mprec = malloc(sizeof *reent->mprec);
        if (reent->mprec == ((void *)0))
            __assert_func(
                "/builds/idf/crosstool-NG/.build/xtensa-esp-elf/src/newlib/newlib/libc/stdlib/dtoa.c",
                239, (char *)0, "REENT malloc succeeded");
        reent->mprec->result_bucket = 0;
        reent->mprec->result = reent->mprec->powers_of_five = 0;
        reent->mprec->freelist = 0;
    }
    if (reent->mprec->result) {
        reent->mprec->result->bucket = reent->mprec->result_bucket;
        reent->mprec->result->capacity_words = 1 << reent->mprec->result_bucket;
        _Bfree(reent, reent->mprec->result);
        reent->mprec->result = 0;
    }
    if ((input_bits.word[1]) & ((unsigned int)0x80000000L)) {
        *sign = 1;
        (input_bits.word[1]) &= ~((unsigned int)0x80000000L);
    } else
        *sign = 0;
    if (((input_bits.word[1]) & ((unsigned int)0x7ff00000L)) == ((unsigned int)0x7ff00000L)) {
        *decimal_point = 9999;
        write_cursor =
            !(input_bits.word[0]) && !((input_bits.word[1]) & 0xfffff) ? "Infinity" : "NaN";
        if (end)
            *end = write_cursor[3] ? write_cursor + 8 : write_cursor + 3;
        return write_cursor;
    }
    if (!input_bits.value) {
        *decimal_point = 1;
        write_cursor = "0";
        if (end)
            *end = write_cursor + 1;
        return write_cursor;
    }
    /* Extract the odd significand and estimate floor(log10(value)). */
    numerator = __d2b(reent, input_bits.value, &binary_exponent, &significand_bits);
    if ((working_int = (int)((input_bits.word[1]) >> 20 & (((unsigned int)0x7ff00000L) >> 20))) !=
        0) {
        saved_or_normalized.value = input_bits.value;
        (saved_or_normalized.word[1]) &= ((unsigned int)0xfffffL);
        (saved_or_normalized.word[1]) |= ((unsigned int)0x3ff00000L);
        working_int -= 1023;
        is_subnormal = 0;
    } else {
        working_int = significand_bits + binary_exponent + (1023 + (53 - 1) - 1);
        subnormal_significand = (working_int > 32)
                                    ? ((input_bits.word[1]) << (64 - working_int)) |
                                          ((input_bits.word[0]) >> (working_int - 32))
                                    : ((input_bits.word[0]) << (32 - working_int));
        saved_or_normalized.value = subnormal_significand;
        (saved_or_normalized.word[1]) -= 31 * ((unsigned int)0x100000L);
        working_int -= (1023 + (53 - 1) - 1) + 1;
        is_subnormal = 1;
    }
    scaled_value = (saved_or_normalized.value - 1.5) * 0.289529654602168 + 0.1760912590558 +
                   working_int * 0.301029995663981;
    decimal_exponent = (int)scaled_value;
    if (scaled_value < 0. && scaled_value != decimal_exponent)
        decimal_exponent--;
    check_decimal_exponent = 1;
    if (decimal_exponent >= 0 && decimal_exponent <= 22) {
        if (input_bits.value < __mprec_tens[decimal_exponent])
            decimal_exponent--;
        check_decimal_exponent = 0;
    }
    working_shift = significand_bits - working_int - 1;
    if (working_shift >= 0) {
        numerator_twos = 0;
        denominator_twos = working_shift;
    } else {
        numerator_twos = -working_shift;
        denominator_twos = 0;
    }
    if (decimal_exponent >= 0) {
        numerator_fives = 0;
        denominator_fives = decimal_exponent;
        denominator_twos += decimal_exponent;
    } else {
        numerator_twos -= decimal_exponent;
        numerator_fives = -decimal_exponent;
        denominator_fives = 0;
    }
    /* Translate formatting mode into digit limits and rounding-margin policy. */
    if (mode < 0 || mode > 9)
        mode = 0;
    try_fast_path = 1;
    if (mode > 5) {
        mode -= 4;
        try_fast_path = 0;
    }
    track_rounding_margins = 1;
    digit_limit = alternate_digit_limit = -1;
    switch (mode) {
    case 0:
    case 1:
        working_int = 18;
        digits = 0;
        break;
    case 2:
        track_rounding_margins = 0;
    case 4:
        if (digits <= 0)
            digits = 1;
        digit_limit = alternate_digit_limit = working_int = digits;
        break;
    case 3:
        track_rounding_margins = 0;
    case 5:
        working_int = digits + decimal_exponent + 1;
        digit_limit = working_int;
        alternate_digit_limit = working_int - 1;
        if (working_int <= 0)
            working_int = 1;
    }
    working_shift = sizeof(unsigned int);
    for (reent->mprec->result_bucket = 0;
         sizeof(MediusBigInt) - sizeof(unsigned int) + working_shift <= working_int;
         working_shift <<= 1)
        reent->mprec->result_bucket++;
    reent->mprec->result = ({
        void *allocation = _Balloc(reent, reent->mprec->result_bucket);
        if (allocation == ((void *)0))
            __assert_func(
                "/builds/idf/crosstool-NG/.build/xtensa-esp-elf/src/newlib/newlib/libc/stdlib/dtoa.c",
                431, (char *)0, "Balloc succeeded");
        allocation;
    });
    /* Characters overwrite the Bigint header; the next call restores its metadata. */
    write_cursor = digits_buffer = (char *)reent->mprec->result;
    /* Accept floating-point digits only when the accumulated error bounds decide rounding. */
    if (digit_limit >= 0 && digit_limit <= 14 && try_fast_path) {
        working_int = 0;
        saved_or_normalized.value = input_bits.value;
        initial_decimal_exponent = decimal_exponent;
        initial_digit_limit = digit_limit;
        rounding_error_units = 2;
        if (decimal_exponent > 0) {
            scaled_value = __mprec_tens[decimal_exponent & 0xf];
            working_shift = decimal_exponent >> 4;
            if (working_shift & 0x10) {
                working_shift &= 0x10 - 1;
                input_bits.value /= __mprec_bigtens[5 - 1];
                rounding_error_units++;
            }
            for (; working_shift; working_shift >>= 1, working_int++)
                if (working_shift & 1) {
                    rounding_error_units++;
                    scaled_value *= __mprec_bigtens[working_int];
                }
            input_bits.value /= scaled_value;
        } else if ((secondary_shift = -decimal_exponent) != 0) {
            input_bits.value *= __mprec_tens[secondary_shift & 0xf];
            for (working_shift = secondary_shift >> 4; working_shift;
                 working_shift >>= 1, working_int++)
                if (working_shift & 1) {
                    rounding_error_units++;
                    input_bits.value *= __mprec_bigtens[working_int];
                }
        }
        if (check_decimal_exponent && input_bits.value < 1. && digit_limit > 0) {
            if (alternate_digit_limit <= 0)
                goto fast_failed;
            digit_limit = alternate_digit_limit;
            decimal_exponent--;
            input_bits.value *= 10.;
            rounding_error_units++;
        }
        error_bound.value = rounding_error_units * input_bits.value + 7.;
        (error_bound.word[1]) -= (53 - 1) * ((unsigned int)0x100000L);
        if (digit_limit == 0) {
            denominator = upper_margin = 0;
            input_bits.value -= 5.;
            if (input_bits.value > error_bound.value)
                goto one_digit;
            if (input_bits.value < -error_bound.value)
                goto no_digits;
            goto fast_failed;
        }
        if (track_rounding_margins) {
            error_bound.value = 0.5 / __mprec_tens[digit_limit - 1] - error_bound.value;
            for (working_int = 0;;) {
                integer_digit = input_bits.value;
                input_bits.value -= integer_digit;
                *write_cursor++ = '0' + (int)integer_digit;
                if (input_bits.value < error_bound.value)
                    goto ret1;
                if (1. - input_bits.value < error_bound.value)
                    goto bump_up;
                if (++working_int >= digit_limit)
                    break;
                error_bound.value *= 10.;
                input_bits.value *= 10.;
            }
        } else {
            error_bound.value *= __mprec_tens[digit_limit - 1];
            for (working_int = 1;; working_int++, input_bits.value *= 10.) {
                integer_digit = input_bits.value;
                input_bits.value -= integer_digit;
                *write_cursor++ = '0' + (int)integer_digit;
                if (working_int == digit_limit) {
                    if (input_bits.value > 0.5 + error_bound.value)
                        goto bump_up;
                    else if (input_bits.value < 0.5 - error_bound.value) {
                        while (*--write_cursor == '0')
                            ;
                        write_cursor++;
                        goto ret1;
                    }
                    break;
                }
            }
        }
    fast_failed:
        /* An ambiguous fast path must restore all state before exact conversion. */
        write_cursor = digits_buffer;
        input_bits.value = saved_or_normalized.value;
        decimal_exponent = initial_decimal_exponent;
        digit_limit = initial_digit_limit;
    }
    /* Small integral inputs have an exact, bounded digit-extraction path. */
    if (binary_exponent >= 0 && decimal_exponent <= 14) {
        scaled_value = __mprec_tens[decimal_exponent];
        if (digits < 0 && digit_limit <= 0) {
            denominator = upper_margin = 0;
            if (digit_limit < 0 || input_bits.value <= 5 * scaled_value)
                goto no_digits;
            goto one_digit;
        }
        for (working_int = 1;; working_int++) {
            integer_digit = input_bits.value / scaled_value;
            input_bits.value -= integer_digit * scaled_value;
            *write_cursor++ = '0' + (int)integer_digit;
            if (working_int == digit_limit) {
                input_bits.value += input_bits.value;
                if ((input_bits.value > scaled_value) ||
                    ((input_bits.value == scaled_value) && (integer_digit & 1))) {
                bump_up:
                    while (*--write_cursor == '9')
                        if (write_cursor == digits_buffer) {
                            decimal_exponent++;
                            *write_cursor = '0';
                            break;
                        }
                    ++*write_cursor++;
                }
                break;
            }
            if (!(input_bits.value *= 10.))
                break;
        }
        goto ret1;
    }
    /* Build an exact numerator/denominator and, when requested, rounding margins. */
    margin_twos = numerator_twos;
    margin_fives = numerator_fives;
    upper_margin = lower_margin = 0;
    if (track_rounding_margins) {
        if (mode < 2) {
            working_int = is_subnormal ? binary_exponent + (1023 + (53 - 1) - 1 + 1)
                                       : 1 + 53 - significand_bits;
        } else {
            working_shift = digit_limit - 1;
            if (margin_fives >= working_shift)
                margin_fives -= working_shift;
            else {
                denominator_fives += working_shift -= margin_fives;
                numerator_fives += working_shift;
                margin_fives = 0;
            }
            if ((working_int = digit_limit) < 0) {
                margin_twos -= working_int;
                working_int = 0;
            }
        }
        numerator_twos += working_int;
        denominator_twos += working_int;
        upper_margin = __i2b(reent, 1);
    }
    if (margin_twos > 0 && denominator_twos > 0) {
        working_int = margin_twos < denominator_twos ? margin_twos : denominator_twos;
        numerator_twos -= working_int;
        margin_twos -= working_int;
        denominator_twos -= working_int;
    }
    if (numerator_fives > 0) {
        if (track_rounding_margins) {
            if (margin_fives > 0) {
                upper_margin = __pow5mult(reent, upper_margin, margin_fives);
                temporary_bigint = __multiply(reent, upper_margin, numerator);
                _Bfree(reent, numerator);
                numerator = temporary_bigint;
            }
            if ((working_shift = numerator_fives - margin_fives) != 0)
                numerator = __pow5mult(reent, numerator, working_shift);
        } else
            numerator = __pow5mult(reent, numerator, numerator_fives);
    }
    denominator = __i2b(reent, 1);
    if (denominator_fives > 0)
        denominator = __pow5mult(reent, denominator, denominator_fives);
    power_of_two_boundary = 0;
    if (mode < 2) {
        if (!(input_bits.word[0]) && !((input_bits.word[1]) & ((unsigned int)0xfffffL)) &&
            (input_bits.word[1]) & ((unsigned int)0x7ff00000L)) {
            numerator_twos += 1;
            denominator_twos += 1;
            power_of_two_boundary = 1;
        }
    }
    if ((working_int =
             ((denominator_fives ? 32 - __hi0bits(denominator->words[denominator->used_words - 1])
                                 : 1) +
              denominator_twos) &
             0x1f) != 0)
        working_int = 32 - working_int;
    if (working_int > 4) {
        working_int -= 4;
        numerator_twos += working_int;
        margin_twos += working_int;
        denominator_twos += working_int;
    } else if (working_int < 4) {
        working_int += 28;
        numerator_twos += working_int;
        margin_twos += working_int;
        denominator_twos += working_int;
    }
    if (numerator_twos > 0)
        numerator = __lshift(reent, numerator, numerator_twos);
    if (denominator_twos > 0)
        denominator = __lshift(reent, denominator, denominator_twos);
    if (check_decimal_exponent) {
        if (__mcmp(numerator, denominator) < 0) {
            decimal_exponent--;
            numerator = __multadd(reent, numerator, 10, 0);
            if (track_rounding_margins)
                upper_margin = __multadd(reent, upper_margin, 10, 0);
            digit_limit = alternate_digit_limit;
        }
    }
    if (digit_limit <= 0 && mode > 2) {
        if (digit_limit < 0 ||
            __mcmp(numerator, denominator = __multadd(reent, denominator, 5, 0)) <= 0) {
        no_digits:
            decimal_exponent = -1 - digits;
            goto ret;
        }
    one_digit:
        *write_cursor++ = '1';
        decimal_exponent++;
        goto ret;
    }
    if (track_rounding_margins) {
        if (margin_twos > 0)
            upper_margin = __lshift(reent, upper_margin, margin_twos);
        lower_margin = upper_margin;
        if (power_of_two_boundary) {
            upper_margin = ({
                void *allocation = _Balloc(reent, upper_margin->bucket);
                if (allocation == ((void *)0))
                    __assert_func(
                        "/builds/idf/crosstool-NG/.build/xtensa-esp-elf/src/newlib/newlib/libc/stdlib/dtoa.c",
                        751, (char *)0, "Balloc succeeded");
                allocation;
            });
            memcpy((char *)&upper_margin->sign, (char *)&lower_margin->sign,
                   lower_margin->used_words * sizeof(long) + 2 * sizeof(int));
            upper_margin = __lshift(reent, upper_margin, 1);
        }
        /* Emit digits until the exact remainder enters a permitted rounding margin. */
        for (working_int = 1;; working_int++) {
            digit = quorem(numerator, denominator) + '0';
            working_shift = __mcmp(numerator, lower_margin);
            remainder_margin = __mdiff(reent, denominator, upper_margin);
            secondary_shift = remainder_margin->sign ? 1 : __mcmp(numerator, remainder_margin);
            _Bfree(reent, remainder_margin);
            if (secondary_shift == 0 && !mode && !((input_bits.word[0]) & 1)) {
                if (digit == '9')
                    goto round_9_up;
                if (working_shift > 0)
                    digit++;
                *write_cursor++ = digit;
                goto ret;
            }
            if ((working_shift < 0) ||
                ((working_shift == 0) && !mode && !((input_bits.word[0]) & 1))) {
                if (secondary_shift > 0) {
                    numerator = __lshift(reent, numerator, 1);
                    secondary_shift = __mcmp(numerator, denominator);
                    if (((secondary_shift > 0) || ((secondary_shift == 0) && (digit & 1))) &&
                        digit++ == '9')
                        goto round_9_up;
                }
                *write_cursor++ = digit;
                goto ret;
            }
            if (secondary_shift > 0) {
                if (digit == '9') {
                round_9_up:
                    *write_cursor++ = '9';
                    goto roundoff;
                }
                *write_cursor++ = digit + 1;
                goto ret;
            }
            *write_cursor++ = digit;
            if (working_int == digit_limit)
                break;
            numerator = __multadd(reent, numerator, 10, 0);
            if (lower_margin == upper_margin)
                lower_margin = upper_margin = __multadd(reent, upper_margin, 10, 0);
            else {
                lower_margin = __multadd(reent, lower_margin, 10, 0);
                upper_margin = __multadd(reent, upper_margin, 10, 0);
            }
        }
    } else
        for (working_int = 1;; working_int++) {
            *write_cursor++ = digit = quorem(numerator, denominator) + '0';
            if (working_int >= digit_limit)
                break;
            numerator = __multadd(reent, numerator, 10, 0);
        }
    /* At the precision limit, compare twice the remainder; exact halves round to even. */
    numerator = __lshift(reent, numerator, 1);
    working_shift = __mcmp(numerator, denominator);
    if ((working_shift > 0) || ((working_shift == 0) && (digit & 1))) {
    roundoff:
        while (*--write_cursor == '9')
            if (write_cursor == digits_buffer) {
                decimal_exponent++;
                *write_cursor++ = '1';
                goto ret;
            }
        ++*write_cursor++;
    } else {
        while (*--write_cursor == '0')
            ;
        write_cursor++;
    }
ret:
    /* Distinct margins own separate allocations; the result buffer stays in reent. */
    _Bfree(reent, denominator);
    if (upper_margin) {
        if (lower_margin && lower_margin != upper_margin)
            _Bfree(reent, lower_margin);
        _Bfree(reent, upper_margin);
    }
ret1:
    _Bfree(reent, numerator);
    *write_cursor = 0;
    *decimal_point = decimal_exponent + 1;
    if (end)
        *end = write_cursor;
    return digits_buffer;
}

/* Native entry: 0x420203e4. */
/*
 * Medius v3.4.7 — device application; 0x420203e4.
 *
 * Allocates or reuses a Bigint with capacity 2^bucket 32-bit words from the context freelist; clears sign and used-word count. Lazily creates the context conversion state and freelist.
 *
 * Calls: __assert_func, malloc, _calloc_r.
 *
 * Called by: _dtoa_r, __multadd, __i2b, __multiply, __lshift, __mdiff,
 * __d2b.
 *
 * Original function-byte SHA-256:
 * 8960cd89402ce20e743b6bb0ef39104e7ccbbd8f7073908cf27e5a2ef6e1934b.
 */

/****************************************************************
 *
 * The author of this software is David M. Gay.
 *
 * Copyright (c) 1991 by AT&T.
 *
 * Permission to use, copy, modify, and distribute this software for any
 * purpose without fee is hereby granted, provided that this entire notice
 * is included in all copies of any software which is or includes a copy
 * or modification of this software and in all copies of the supporting
 * documentation for such software.
 *
 * THIS SOFTWARE IS BEING PROVIDED "AS IS", WITHOUT ANY EXPRESS OR IMPLIED
 * WARRANTY.  IN PARTICULAR, NEITHER THE AUTHOR NOR AT&T MAKES ANY
 * REPRESENTATION OR WARRANTY OF ANY KIND CONCERNING THE MERCHANTABILITY
 * OF THIS SOFTWARE OR ITS FITNESS FOR ANY PARTICULAR PURPOSE.
 *
 ***************************************************************/

/* Reconstructed from the instruction-matched Newlib implementation by David M. Gay.
 * Primary reference: espressif/newlib-esp32, commit
 * d16a927c7334602a563893fa53b3746afdd31c0d, newlib/libc/stdlib/.
 * Typed layouts and binary64 word views retain the ESP32-S3 ABI. Control flow,
 * allocation ownership, halfword arithmetic and rounding branches were reviewed
 * against the original firmware instructions. Borrow propagation uses signed
 * arithmetic right shifts; packing a result word uses an unsigned left shift.
 */

/*
 * reent: Live writable 240-byte Newlib context.
 * bucket: Supported freelist index; requested capacity is 2^bucket 32-bit words, without a range
 *   check here.
 * Returns: A cached or newly allocated Bigint with sign and used_words reset to zero; NULL if
 *   freelist or block allocation fails.
 * Requirements/effects: Uses the supplied Newlib context without locking; concurrent users require
 *   caller exclusion. Bigint metadata, capacities and allocation arithmetic must be valid. Lazily
 *   allocates the 16-byte conversion state and 33-pointer freelist. Conversion-state allocation
 *   failure asserts. Cached payload and next link are not cleared.
 */

MediusBigInt *_Balloc(struct NewlibReent *reent, int bucket) {
    int capacity_words;
    MediusBigInt *result;
    if (reent->mprec == ((void *)0)) {
        reent->mprec = malloc(sizeof *reent->mprec);
        if (reent->mprec == ((void *)0))
            __assert_func(
                "/builds/idf/crosstool-NG/.build/xtensa-esp-elf/src/newlib/newlib/libc/stdlib/mprec.c",
                107, (char *)0, "REENT malloc succeeded");
        reent->mprec->result_bucket = 0;
        reent->mprec->result = reent->mprec->powers_of_five = 0;
        reent->mprec->freelist = 0;
    }
    if (reent->mprec->freelist == ((void *)0)) {
        reent->mprec->freelist = (struct MediusBigInt **)_calloc_r(
            reent, sizeof(struct MediusBigInt *), (sizeof(size_t) << 3) + 1);
        if (reent->mprec->freelist == ((void *)0)) {
            return ((void *)0);
        }
    }
    if ((result = reent->mprec->freelist[bucket]) != 0) {
        reent->mprec->freelist[bucket] = result->next;
    } else {
        capacity_words = 1 << bucket;
        result = (MediusBigInt *)_calloc_r(
            reent, 1, sizeof(MediusBigInt) + (capacity_words - 1) * sizeof(result->words));
        if (result == ((void *)0))
            return ((void *)0);
        result->bucket = bucket;
        result->capacity_words = capacity_words;
    }
    result->sign = result->used_words = 0;
    return result;
}

/* Native entry: 0x4202046c. */
/*
 * Medius v3.4.7 — device application; 0x4202046c.
 *
 * Returns a non-NULL Bigint to its capacity bucket in the context freelist, retaining the allocation for reuse. Lazily creates conversion state if absent.
 *
 * Calls: __assert_func, malloc.
 *
 * Called by: _dtoa_r, __multadd, __pow5mult, __lshift.
 *
 * Original function-byte SHA-256:
 * b4d3c8c11ec481bde2dc044fb453b9ecd42d3bbc5f30e63293c62158951fb55d.
 */

/****************************************************************
 *
 * The author of this software is David M. Gay.
 *
 * Copyright (c) 1991 by AT&T.
 *
 * Permission to use, copy, modify, and distribute this software for any
 * purpose without fee is hereby granted, provided that this entire notice
 * is included in all copies of any software which is or includes a copy
 * or modification of this software and in all copies of the supporting
 * documentation for such software.
 *
 * THIS SOFTWARE IS BEING PROVIDED "AS IS", WITHOUT ANY EXPRESS OR IMPLIED
 * WARRANTY.  IN PARTICULAR, NEITHER THE AUTHOR NOR AT&T MAKES ANY
 * REPRESENTATION OR WARRANTY OF ANY KIND CONCERNING THE MERCHANTABILITY
 * OF THIS SOFTWARE OR ITS FITNESS FOR ANY PARTICULAR PURPOSE.
 *
 ***************************************************************/

/* Reconstructed from the instruction-matched Newlib implementation by David M. Gay.
 * Primary reference: espressif/newlib-esp32, commit
 * d16a927c7334602a563893fa53b3746afdd31c0d, newlib/libc/stdlib/.
 * Typed layouts and binary64 word views retain the ESP32-S3 ABI. Control flow,
 * allocation ownership, halfword arithmetic and rounding branches were reviewed
 * against the original firmware instructions. Borrow propagation uses signed
 * arithmetic right shifts; packing a result word uses an unsigned left shift.
 */

/*
 * reent: Live context; a non-NULL value requires its freelist to exist.
 * value: NULL, or an exclusively owned valid Bigint allocated for this context.
 * Returns: Nothing.
 * Requirements/effects: Uses the supplied Newlib context without locking; concurrent users require
 *   caller exclusion. Bigint metadata, capacities and allocation arithmetic must be valid. Pushes
 *   value onto its bucket freelist without freeing or wiping it. Even a NULL value can cause lazy
 *   conversion-state allocation; failure of that allocation asserts.
 */

void _Bfree(struct NewlibReent *reent, MediusBigInt *value) {
    if (reent->mprec == ((void *)0)) {
        reent->mprec = malloc(sizeof *reent->mprec);
        if (reent->mprec == ((void *)0))
            __assert_func(
                "/builds/idf/crosstool-NG/.build/xtensa-esp-elf/src/newlib/newlib/libc/stdlib/mprec.c",
                143, (char *)0, "REENT malloc succeeded");
        reent->mprec->result_bucket = 0;
        reent->mprec->result = reent->mprec->powers_of_five = 0;
        reent->mprec->freelist = 0;
    }
    if (value) {
        value->next = reent->mprec->freelist[value->bucket];
        reent->mprec->freelist[value->bucket] = value;
    }
}

/* Native entry: 0x420204ac. */
/*
 * Medius v3.4.7 — device application; 0x420204ac.
 *
 * Updates a Bigint to value*multiplier+addend using 16-bit partial products. Grows the allocation when a carry exceeds capacity, returns the resulting pointer and recycles the old allocation.
 *
 * Calls: __assert_func, _Balloc, _Bfree, memcpy.
 *
 * Called by: _dtoa_r, __pow5mult.
 *
 * Original function-byte SHA-256:
 * 452a191351746749e06ec40e62010991346ee46331ea0407c5cd26b7052e4628.
 */

/****************************************************************
 *
 * The author of this software is David M. Gay.
 *
 * Copyright (c) 1991 by AT&T.
 *
 * Permission to use, copy, modify, and distribute this software for any
 * purpose without fee is hereby granted, provided that this entire notice
 * is included in all copies of any software which is or includes a copy
 * or modification of this software and in all copies of the supporting
 * documentation for such software.
 *
 * THIS SOFTWARE IS BEING PROVIDED "AS IS", WITHOUT ANY EXPRESS OR IMPLIED
 * WARRANTY.  IN PARTICULAR, NEITHER THE AUTHOR NOR AT&T MAKES ANY
 * REPRESENTATION OR WARRANTY OF ANY KIND CONCERNING THE MERCHANTABILITY
 * OF THIS SOFTWARE OR ITS FITNESS FOR ANY PARTICULAR PURPOSE.
 *
 ***************************************************************/

/* Reconstructed from the instruction-matched Newlib implementation by David M. Gay.
 * Primary reference: espressif/newlib-esp32, commit
 * d16a927c7334602a563893fa53b3746afdd31c0d, newlib/libc/stdlib/.
 * Typed layouts and binary64 word views retain the ESP32-S3 ABI. Control flow,
 * allocation ownership, halfword arithmetic and rounding branches were reviewed
 * against the original firmware instructions. Borrow propagation uses signed
 * arithmetic right shifts; packing a result word uses an unsigned left shift.
 */

/*
 * reent: Live conversion context.
 * value: Owned Bigint with at least one used word.
 * multiplier: Nonnegative small multiplier satisfying the caller's halfword-product bounds.
 * addend: Nonnegative small initial carry satisfying those bounds.
 * Returns: The possibly replaced Bigint representing value * multiplier + addend.
 * Requirements/effects: Uses the supplied Newlib context without locking; concurrent users require
 *   caller exclusion. Bigint metadata, capacities and allocation arithmetic must be valid. Updates
 *   words in place and appends a final carry. If capacity is exhausted, allocates a larger block,
 *   copies sign/count/payload and recycles the old block. Allocation failure asserts. Caller must
 *   use the returned pointer.
 */

MediusBigInt *__multadd(struct NewlibReent *reent, MediusBigInt *value, int multiplier,
                        int addend) {
    int word_index, used_words;
    unsigned int *word_cursor, low_product;
    unsigned int input_word, high_product;
    MediusBigInt *grown;
    used_words = value->used_words;
    word_cursor = value->words;
    word_index = 0;
    do {
        input_word = *word_cursor;
        low_product = (input_word & 0xffff) * multiplier + addend;
        high_product = (input_word >> 16) * multiplier + (low_product >> 16);
        addend = (int)(high_product >> 16);
        *word_cursor++ = (high_product << 16) + (low_product & 0xffff);
    } while (++word_index < used_words);
    if (addend) {
        if (used_words >= value->capacity_words) {
            grown = ({
                void *allocation = _Balloc(reent, value->bucket + 1);
                if (allocation == ((void *)0))
                    __assert_func(
                        "/builds/idf/crosstool-NG/.build/xtensa-esp-elf/src/newlib/newlib/libc/stdlib/mprec.c",
                        186, (char *)0, "Balloc succeeded");
                allocation;
            });
            memcpy((char *)&grown->sign, (char *)&value->sign,
                   value->used_words * sizeof(long) + 2 * sizeof(int));
            _Bfree(reent, value);
            value = grown;
        }
        value->words[used_words++] = addend;
        value->used_words = used_words;
    }
    return value;
}

/* Native entry: 0x42020538. */
/*
 * Medius v3.4.7 — device application; 0x42020538.
 *
 * Allocates a bucket-1 Bigint, stores the input word and sets the used-word count to one. Asserts if allocation fails.
 *
 * Calls: __assert_func, _Balloc.
 *
 * Called by: _dtoa_r, __pow5mult.
 *
 * Original function-byte SHA-256:
 * 7350326f64fef8234a3dcd7652224b533be4305a93b92749427afba38649efff.
 */

/****************************************************************
 *
 * The author of this software is David M. Gay.
 *
 * Copyright (c) 1991 by AT&T.
 *
 * Permission to use, copy, modify, and distribute this software for any
 * purpose without fee is hereby granted, provided that this entire notice
 * is included in all copies of any software which is or includes a copy
 * or modification of this software and in all copies of the supporting
 * documentation for such software.
 *
 * THIS SOFTWARE IS BEING PROVIDED "AS IS", WITHOUT ANY EXPRESS OR IMPLIED
 * WARRANTY.  IN PARTICULAR, NEITHER THE AUTHOR NOR AT&T MAKES ANY
 * REPRESENTATION OR WARRANTY OF ANY KIND CONCERNING THE MERCHANTABILITY
 * OF THIS SOFTWARE OR ITS FITNESS FOR ANY PARTICULAR PURPOSE.
 *
 ***************************************************************/

/* Reconstructed from the instruction-matched Newlib implementation by David M. Gay.
 * Primary reference: espressif/newlib-esp32, commit
 * d16a927c7334602a563893fa53b3746afdd31c0d, newlib/libc/stdlib/.
 * Typed layouts and binary64 word views retain the ESP32-S3 ABI. Control flow,
 * allocation ownership, halfword arithmetic and rounding branches were reviewed
 * against the original firmware instructions. Borrow propagation uses signed
 * arithmetic right shifts; packing a result word uses an unsigned left shift.
 */

/*
 * reent: Live conversion context.
 * value: Integer stored as one 32-bit payload word; numeric callers use a nonnegative value.
 * Returns: A bucket-1 Bigint with used_words=1, sign=0 and words[0] set to value's bits.
 * Requirements/effects: Uses the supplied Newlib context without locking; concurrent users require
 *   caller exclusion. Bigint metadata, capacities and allocation arithmetic must be valid.
 *   Allocates from the context freelist; allocation failure asserts. No normalization, range
 *   validation or sign extraction is performed.
 */

MediusBigInt *__i2b(struct NewlibReent *reent, int value) {
    MediusBigInt *result;
    result = ({
        void *allocation = _Balloc(reent, 1);
        if (allocation == ((void *)0))
            __assert_func(
                "/builds/idf/crosstool-NG/.build/xtensa-esp-elf/src/newlib/newlib/libc/stdlib/mprec.c",
                325, (char *)0, "Balloc succeeded");
        allocation;
    });
    result->words[0] = value;
    result->used_words = 1;
    return result;
}

/* Native entry: 0x42020564. */
/*
 * Medius v3.4.7 — device application; 0x42020564.
 *
 * Allocates a Bigint product, multiplies the operand word arrays using 16-bit partial products and trims leading zero words. Leaves both input allocations owned by the caller.
 *
 * Calls: __assert_func, _Balloc.
 *
 * Called by: _dtoa_r, __pow5mult.
 *
 * Original function-byte SHA-256:
 * c59413a10b1661f657d3c8dd457ac9fce17599ffbac30fde049464b05df9e183.
 */

/****************************************************************
 *
 * The author of this software is David M. Gay.
 *
 * Copyright (c) 1991 by AT&T.
 *
 * Permission to use, copy, modify, and distribute this software for any
 * purpose without fee is hereby granted, provided that this entire notice
 * is included in all copies of any software which is or includes a copy
 * or modification of this software and in all copies of the supporting
 * documentation for such software.
 *
 * THIS SOFTWARE IS BEING PROVIDED "AS IS", WITHOUT ANY EXPRESS OR IMPLIED
 * WARRANTY.  IN PARTICULAR, NEITHER THE AUTHOR NOR AT&T MAKES ANY
 * REPRESENTATION OR WARRANTY OF ANY KIND CONCERNING THE MERCHANTABILITY
 * OF THIS SOFTWARE OR ITS FITNESS FOR ANY PARTICULAR PURPOSE.
 *
 ***************************************************************/

/* Reconstructed from the instruction-matched Newlib implementation by David M. Gay.
 * Primary reference: espressif/newlib-esp32, commit
 * d16a927c7334602a563893fa53b3746afdd31c0d, newlib/libc/stdlib/.
 * Typed layouts and binary64 word views retain the ESP32-S3 ABI. Control flow,
 * allocation ownership, halfword arithmetic and rounding branches were reviewed
 * against the original firmware instructions. Borrow propagation uses signed
 * arithmetic right shifts; packing a result word uses an unsigned left shift.
 */

/*
 * reent: Live conversion context.
 * left: Readable magnitude Bigint with at least one used word.
 * right: Readable magnitude Bigint with at least one used word; may alias left.
 * Returns: A separately allocated unsigned magnitude product; an all-zero product can have
 *   used_words=0.
 * Requirements/effects: Uses the supplied Newlib context without locking; concurrent users require
 *   caller exclusion. Bigint metadata, capacities and allocation arithmetic must be valid. Uses
 *   16-bit partial products and carry propagation. Inputs are retained and unchanged. Chooses the
 *   larger operand first and normalizes leading zero product words. Allocation failure asserts;
 *   operand sign fields are not multiplied.
 */

MediusBigInt *__multiply(struct NewlibReent *reent, MediusBigInt *left, MediusBigInt *right) {
    MediusBigInt *result;
    int bucket, left_count, right_count, product_count;
    unsigned int carry, halfword, low_product;
    unsigned int *left_cursor, *left_start, *left_end, *right_cursor, *right_end, *output_cursor,
        *row_start;
    unsigned int high_product;
    if (left->used_words < right->used_words) {
        result = left;
        left = right;
        right = result;
    }
    bucket = left->bucket;
    left_count = left->used_words;
    right_count = right->used_words;
    product_count = left_count + right_count;
    if (product_count > left->capacity_words)
        bucket++;
    result = ({
        void *allocation = _Balloc(reent, bucket);
        if (allocation == ((void *)0))
            __assert_func(
                "/builds/idf/crosstool-NG/.build/xtensa-esp-elf/src/newlib/newlib/libc/stdlib/mprec.c",
                354, (char *)0, "Balloc succeeded");
        allocation;
    });
    for (left_cursor = result->words, left_start = left_cursor + product_count;
         left_cursor < left_start; left_cursor++)
        *left_cursor = 0;
    left_start = left->words;
    left_end = left_start + left_count;
    right_cursor = right->words;
    right_end = right_cursor + right_count;
    row_start = result->words;
    for (; right_cursor < right_end; right_cursor++, row_start++) {
        if ((halfword = *right_cursor & 0xffff) != 0) {
            left_cursor = left_start;
            output_cursor = row_start;
            carry = 0;
            do {
                low_product =
                    (*left_cursor & 0xffff) * halfword + (*output_cursor & 0xffff) + carry;
                carry = low_product >> 16;
                high_product = (*left_cursor++ >> 16) * halfword + (*output_cursor >> 16) + carry;
                carry = high_product >> 16;
                (*(output_cursor)++ = ((high_product) << 16) | ((low_product) & 0xffff));
            } while (left_cursor < left_end);
            *output_cursor = carry;
        }
        if ((halfword = *right_cursor >> 16) != 0) {
            left_cursor = left_start;
            output_cursor = row_start;
            carry = 0;
            high_product = *output_cursor;
            do {
                low_product = (*left_cursor & 0xffff) * halfword + (*output_cursor >> 16) + carry;
                carry = low_product >> 16;
                (*(output_cursor)++ = ((low_product) << 16) | ((high_product) & 0xffff));
                high_product =
                    (*left_cursor++ >> 16) * halfword + (*output_cursor & 0xffff) + carry;
                carry = high_product >> 16;
            } while (left_cursor < left_end);
            *output_cursor = high_product;
        }
    }
    for (row_start = result->words, output_cursor = row_start + product_count;
         product_count > 0 && !*--output_cursor; --product_count)
        ;
    result->used_words = product_count;
    return result;
}

/* Native entry: 0x420206e4. */
/*
 * Medius v3.4.7 — device application; 0x420206e4.
 *
 * Multiplies by 5^exponent using a small remainder multiplier and cached powers generated by repeated squaring. Recycles replaced value allocations and returns the surviving Bigint pointer.
 *
 * Calls: __assert_func, malloc, _Bfree, __multadd, __i2b, __multiply.
 *
 * Called by: _dtoa_r.
 *
 * Original function-byte SHA-256:
 * 090f755f611109e1eca6ceb081e8471ab2e5e2f6a8b70d0f39d821217c99780b.
 */

/****************************************************************
 *
 * The author of this software is David M. Gay.
 *
 * Copyright (c) 1991 by AT&T.
 *
 * Permission to use, copy, modify, and distribute this software for any
 * purpose without fee is hereby granted, provided that this entire notice
 * is included in all copies of any software which is or includes a copy
 * or modification of this software and in all copies of the supporting
 * documentation for such software.
 *
 * THIS SOFTWARE IS BEING PROVIDED "AS IS", WITHOUT ANY EXPRESS OR IMPLIED
 * WARRANTY.  IN PARTICULAR, NEITHER THE AUTHOR NOR AT&T MAKES ANY
 * REPRESENTATION OR WARRANTY OF ANY KIND CONCERNING THE MERCHANTABILITY
 * OF THIS SOFTWARE OR ITS FITNESS FOR ANY PARTICULAR PURPOSE.
 *
 ***************************************************************/

/* Reconstructed from the instruction-matched Newlib implementation by David M. Gay.
 * Primary reference: espressif/newlib-esp32, commit
 * d16a927c7334602a563893fa53b3746afdd31c0d, newlib/libc/stdlib/.
 * Typed layouts and binary64 word views retain the ESP32-S3 ABI. Control flow,
 * allocation ownership, halfword arithmetic and rounding branches were reviewed
 * against the original firmware instructions. Borrow propagation uses signed
 * arithmetic right shifts; packing a result word uses an unsigned left shift.
 */

/*
 * reent: Live conversion context with exclusive access to its power cache.
 * value: Owned valid magnitude Bigint; caller must replace its pointer with the return value.
 * exponent: Nonnegative supported exponent; no validation here.
 * Returns: The possibly replaced value multiplied by 5^exponent.
 * Requirements/effects: Uses the supplied Newlib context without locking; concurrent users require
 *   caller exclusion. Bigint metadata, capacities and allocation arithmetic must be valid. Handles
 *   exponent modulo four with 5/25/125, then squares cached powers starting at 625. Recycles
 *   intermediate input blocks, retains cache nodes in powers_of_five, and asserts on required
 *   allocation failure. Exponent zero returns the input unchanged.
 */

MediusBigInt *__pow5mult(struct NewlibReent *reent, MediusBigInt *value, int exponent) {
    MediusBigInt *product, *power, *next_power;
    int low_exponent_bits;
    static const int small_powers[3] = {5, 25, 125};
    if ((low_exponent_bits = exponent & 3) != 0)
        value = __multadd(reent, value, small_powers[low_exponent_bits - 1], 0);
    if (!(exponent >>= 2))
        return value;
    if (reent->mprec == ((void *)0)) {
        reent->mprec = malloc(sizeof *reent->mprec);
        if (reent->mprec == ((void *)0))
            __assert_func(
                "/builds/idf/crosstool-NG/.build/xtensa-esp-elf/src/newlib/newlib/libc/stdlib/mprec.c",
                435, (char *)0, "REENT malloc succeeded");
        reent->mprec->result_bucket = 0;
        reent->mprec->result = reent->mprec->powers_of_five = 0;
        reent->mprec->freelist = 0;
    }
    if (!(power = reent->mprec->powers_of_five)) {
        power = reent->mprec->powers_of_five = __i2b(reent, 625);
        power->next = 0;
    }
    for (;;) {
        if (exponent & 1) {
            product = __multiply(reent, value, power);
            _Bfree(reent, value);
            value = product;
        }
        if (!(exponent >>= 1))
            break;
        if (!(next_power = power->next)) {
            next_power = power->next = __multiply(reent, power, power);
            next_power->next = 0;
        }
        power = next_power;
    }
    return value;
}

/* Native entry: 0x420207a0. */
/*
 * Medius v3.4.7 — device application; 0x420207a0.
 *
 * Allocates space for a left shift by whole words and remaining bits, copies/shifts the data, updates the used-word count, recycles the input allocation and returns the new pointer.
 *
 * Calls: __assert_func, _Balloc, _Bfree.
 *
 * Called by: _dtoa_r.
 *
 * Original function-byte SHA-256:
 * 5fb92c991480dcd0f3dcc19d36e5478c5767c5c06cf664e64d053f84b0e3afef.
 */

/****************************************************************
 *
 * The author of this software is David M. Gay.
 *
 * Copyright (c) 1991 by AT&T.
 *
 * Permission to use, copy, modify, and distribute this software for any
 * purpose without fee is hereby granted, provided that this entire notice
 * is included in all copies of any software which is or includes a copy
 * or modification of this software and in all copies of the supporting
 * documentation for such software.
 *
 * THIS SOFTWARE IS BEING PROVIDED "AS IS", WITHOUT ANY EXPRESS OR IMPLIED
 * WARRANTY.  IN PARTICULAR, NEITHER THE AUTHOR NOR AT&T MAKES ANY
 * REPRESENTATION OR WARRANTY OF ANY KIND CONCERNING THE MERCHANTABILITY
 * OF THIS SOFTWARE OR ITS FITNESS FOR ANY PARTICULAR PURPOSE.
 *
 ***************************************************************/

/* Reconstructed from the instruction-matched Newlib implementation by David M. Gay.
 * Primary reference: espressif/newlib-esp32, commit
 * d16a927c7334602a563893fa53b3746afdd31c0d, newlib/libc/stdlib/.
 * Typed layouts and binary64 word views retain the ESP32-S3 ABI. Control flow,
 * allocation ownership, halfword arithmetic and rounding branches were reviewed
 * against the original firmware instructions. Borrow propagation uses signed
 * arithmetic right shifts; packing a result word uses an unsigned left shift.
 */

/*
 * reent: Live conversion context.
 * value: Owned magnitude Bigint with at least one used word.
 * shift_bits: Nonnegative supported bit shift; capacity and size calculations must not overflow.
 * Returns: A new Bigint containing value shifted left by shift_bits; the input is recycled.
 * Requirements/effects: Uses the supplied Newlib context without locking; concurrent users require
 *   caller exclusion. Bigint metadata, capacities and allocation arithmetic must be valid. Inserts
 *   whole zero words, shifts remaining bits with carry and sets the output count. Allocates even
 *   for a zero shift, resets output sign through _Balloc and asserts on allocation failure. Caller
 *   must use the returned pointer.
 */

MediusBigInt *__lshift(struct NewlibReent *reent, MediusBigInt *value, int shift_bits) {
    int capacity_words, allocation_bucket, zero_word_index, carry_shift, whole_words, result_word_limit;
    MediusBigInt *result;
    unsigned int *input_cursor, *output_cursor, *input_end, carry;
    whole_words = shift_bits >> 5;
    allocation_bucket = value->bucket;
    result_word_limit = whole_words + value->used_words + 1;
    for (capacity_words = value->capacity_words; result_word_limit > capacity_words;
         capacity_words <<= 1)
        allocation_bucket++;
    result = ({
        void *allocation = _Balloc(reent, allocation_bucket);
        if (allocation == ((void *)0))
            __assert_func(
                "/builds/idf/crosstool-NG/.build/xtensa-esp-elf/src/newlib/newlib/libc/stdlib/mprec.c",
                478, (char *)0, "Balloc succeeded");
        allocation;
    });
    output_cursor = result->words;
    for (zero_word_index = 0; zero_word_index < whole_words; zero_word_index++)
        *output_cursor++ = 0;
    input_cursor = value->words;
    input_end = input_cursor + value->used_words;
    if (shift_bits &= 0x1f) {
        carry_shift = 32 - shift_bits;
        carry = 0;
        do {
            *output_cursor++ = *input_cursor << shift_bits | carry;
            carry = *input_cursor++ >> carry_shift;
        } while (input_cursor < input_end);
        if ((*output_cursor = carry) != 0)
            ++result_word_limit;
    } else
        do
            *output_cursor++ = *input_cursor++;
        while (input_cursor < input_end);
    result->used_words = result_word_limit - 1;
    _Bfree(reent, value);
    return result;
}

/* Native entry: 0x420208b0. */
/*
 * Medius v3.4.7 — device application; 0x420208b0.
 *
 * Compares magnitudes and allocates their absolute difference. Sets the sign field when left is smaller, propagates borrows and trims high zero words; equal inputs produce a one-word zero.
 *
 * Calls: __assert_func, _Balloc, __mcmp.
 *
 * Called by: _dtoa_r.
 *
 * Original function-byte SHA-256:
 * 09b0adfb948fe37b737d9906833fdf4d39e463e6411e62cbac35f517bb52e3c4.
 */

/****************************************************************
 *
 * The author of this software is David M. Gay.
 *
 * Copyright (c) 1991 by AT&T.
 *
 * Permission to use, copy, modify, and distribute this software for any
 * purpose without fee is hereby granted, provided that this entire notice
 * is included in all copies of any software which is or includes a copy
 * or modification of this software and in all copies of the supporting
 * documentation for such software.
 *
 * THIS SOFTWARE IS BEING PROVIDED "AS IS", WITHOUT ANY EXPRESS OR IMPLIED
 * WARRANTY.  IN PARTICULAR, NEITHER THE AUTHOR NOR AT&T MAKES ANY
 * REPRESENTATION OR WARRANTY OF ANY KIND CONCERNING THE MERCHANTABILITY
 * OF THIS SOFTWARE OR ITS FITNESS FOR ANY PARTICULAR PURPOSE.
 *
 ***************************************************************/

/* Reconstructed from the instruction-matched Newlib implementation by David M. Gay.
 * Primary reference: espressif/newlib-esp32, commit
 * d16a927c7334602a563893fa53b3746afdd31c0d, newlib/libc/stdlib/.
 * Typed layouts and binary64 word views retain the ESP32-S3 ABI. Control flow,
 * allocation ownership, halfword arithmetic and rounding branches were reviewed
 * against the original firmware instructions. Borrow propagation uses signed
 * arithmetic right shifts; packing a result word uses an unsigned left shift.
 */

/*
 * reent: Live conversion context.
 * left: Readable normalized magnitude with at least one used word.
 * right: Readable normalized magnitude with at least one used word; may alias left.
 * Returns: A newly allocated absolute difference; sign=1 precisely when left is less than right.
 *   Equality returns a one-word zero.
 * Requirements/effects: Uses the supplied Newlib context without locking; concurrent users require
 *   caller exclusion. Bigint metadata, capacities and allocation arithmetic must be valid. Inputs
 *   are retained. Compares magnitudes, subtracts smaller from larger with halfword borrow and
 *   removes high zero words. Allocation failure asserts. Signed borrow is arithmetically shifted;
 *   stored upper halves use unsigned shifts to retain native bit behavior.
 */

MediusBigInt *__mdiff(struct NewlibReent *reent, MediusBigInt *left, MediusBigInt *right) {
    MediusBigInt *result;
    int comparison, larger_count, smaller_count;
    long borrow, low_difference;
    unsigned int *larger_cursor, *larger_end, *smaller_cursor, *smaller_end, *output_cursor;
    long high_difference;
    comparison = __mcmp(left, right);
    if (!comparison) {
        result = ({
            void *allocation = _Balloc(reent, 0);
            if (allocation == ((void *)0))
                __assert_func(
                    "/builds/idf/crosstool-NG/.build/xtensa-esp-elf/src/newlib/newlib/libc/stdlib/mprec.c",
                    567, (char *)0, "Balloc succeeded");
            allocation;
        });
        result->used_words = 1;
        result->words[0] = 0;
        return result;
    }
    if (comparison < 0) {
        result = left;
        left = right;
        right = result;
        comparison = 1;
    } else
        comparison = 0;
    result = ({
        void *allocation = _Balloc(reent, left->bucket);
        if (allocation == ((void *)0))
            __assert_func(
                "/builds/idf/crosstool-NG/.build/xtensa-esp-elf/src/newlib/newlib/libc/stdlib/mprec.c",
                581, (char *)0, "Balloc succeeded");
        allocation;
    });
    result->sign = comparison;
    larger_count = left->used_words;
    larger_cursor = left->words;
    larger_end = larger_cursor + larger_count;
    smaller_count = right->used_words;
    smaller_cursor = right->words;
    smaller_end = smaller_cursor + smaller_count;
    output_cursor = result->words;
    borrow = 0;
    do {
        low_difference = (*larger_cursor & 0xffff) - (*smaller_cursor & 0xffff) + borrow;
        borrow = low_difference >> 16;
        high_difference = (*larger_cursor++ >> 16) - (*smaller_cursor++ >> 16) + borrow;
        borrow = high_difference >> 16;
        (*(output_cursor)++ =
             ((unsigned long)(high_difference) << 16) | ((low_difference) & 0xffff));
    } while (smaller_cursor < smaller_end);
    while (larger_cursor < larger_end) {
        low_difference = (*larger_cursor & 0xffff) + borrow;
        borrow = low_difference >> 16;
        high_difference = (*larger_cursor++ >> 16) + borrow;
        borrow = high_difference >> 16;
        (*(output_cursor)++ =
             ((unsigned long)(high_difference) << 16) | ((low_difference) & 0xffff));
    }
    while (!*--output_cursor)
        larger_count--;
    result->used_words = larger_count;
    return result;
}

/* Native entry: 0x42020a08. */
/*
 * Medius v3.4.7 — device application; 0x42020a08.
 *
 * Converts the binary64 magnitude into a Bigint significand plus a base-2 exponent and significant-bit count. Removes trailing zero bits and handles normal/subnormal exponent layouts; used by decimal formatting.
 *
 * Calls: __assert_func, _Balloc, __hi0bits, __lo0bits.
 *
 * Called by: _dtoa_r.
 *
 * Original function-byte SHA-256:
 * 0062067d99ec659b3c39e5870a1df0ef5fe6690d25e1cc1e1a7274762f5c1e91.
 */

/****************************************************************
 *
 * The author of this software is David M. Gay.
 *
 * Copyright (c) 1991 by AT&T.
 *
 * Permission to use, copy, modify, and distribute this software for any
 * purpose without fee is hereby granted, provided that this entire notice
 * is included in all copies of any software which is or includes a copy
 * or modification of this software and in all copies of the supporting
 * documentation for such software.
 *
 * THIS SOFTWARE IS BEING PROVIDED "AS IS", WITHOUT ANY EXPRESS OR IMPLIED
 * WARRANTY.  IN PARTICULAR, NEITHER THE AUTHOR NOR AT&T MAKES ANY
 * REPRESENTATION OR WARRANTY OF ANY KIND CONCERNING THE MERCHANTABILITY
 * OF THIS SOFTWARE OR ITS FITNESS FOR ANY PARTICULAR PURPOSE.
 *
 ***************************************************************/

/* Reconstructed from the instruction-matched Newlib implementation by David M. Gay.
 * Primary reference: espressif/newlib-esp32, commit
 * d16a927c7334602a563893fa53b3746afdd31c0d, newlib/libc/stdlib/.
 * Typed layouts and binary64 word views retain the ESP32-S3 ABI. Control flow,
 * allocation ownership, halfword arithmetic and rounding branches were reviewed
 * against the original firmware instructions. Borrow propagation uses signed
 * arithmetic right shifts; packing a result word uses an unsigned left shift.
 */

/*
 * reent: Live conversion context.
 * value: Binary64 value; formatter callers exclude zero, NaN and infinity before this conversion.
 * exponent: Writable int output receiving the power-of-two exponent.
 * significant_bits: Writable int output receiving the remaining significand bit count.
 * Returns: A newly allocated unsigned Bigint magnitude with trailing binary zeros removed; for
 *   finite nonzero value, magnitude * 2^exponent equals abs(value).
 * Requirements/effects: Uses the supplied Newlib context without locking; concurrent users require
 *   caller exclusion. Bigint metadata, capacities and allocation arithmetic must be valid. Reads
 *   the binary64 representation through an explicit little-endian word union, discards sign and
 *   handles normal/subnormal exponents. Does not itself reject special values or zero. Allocation
 *   failure asserts; input is passed by value.
 */

MediusBigInt *__d2b(struct NewlibReent *reent, double value, int *exponent,
                    int *significant_bits) {
    MediusBinary64 input_bits;
    MediusBigInt *result;
    int biased_exponent, used_words, trailing_zeros;
    unsigned int *output_words, low_significand, high_significand;
    input_bits.value = value;
    result = ({
        void *allocation = _Balloc(reent, 1);
        if (allocation == ((void *)0))
            __assert_func(
                "/builds/idf/crosstool-NG/.build/xtensa-esp-elf/src/newlib/newlib/libc/stdlib/mprec.c",
                783, (char *)0, "Balloc succeeded");
        allocation;
    });
    output_words = result->words;
    high_significand = (input_bits.word[1]) & ((unsigned int)0xfffffL);
    (input_bits.word[1]) &= 0x7fffffff;
    if ((biased_exponent = (int)((input_bits.word[1]) >> 20)) != 0)
        high_significand |= ((unsigned int)0x100000L);
    if ((input_bits.word[0])) {
        low_significand = (input_bits.word[0]);
        trailing_zeros = __lo0bits(&low_significand);
        if (trailing_zeros) {
            output_words[0] = low_significand | high_significand << (32 - trailing_zeros);
            high_significand >>= trailing_zeros;
        } else
            output_words[0] = low_significand;
        used_words = result->used_words = (output_words[1] = high_significand) ? 2 : 1;
    } else {
        trailing_zeros = __lo0bits(&high_significand);
        output_words[0] = high_significand;
        used_words = result->used_words = 1;
        trailing_zeros += 32;
    }
    if (biased_exponent) {
        *exponent = biased_exponent - 1023 - (53 - 1) + trailing_zeros;
        *significant_bits = 53 - trailing_zeros;
    } else {
        *exponent = biased_exponent - 1023 - (53 - 1) + 1 + trailing_zeros;
        *significant_bits = 32 * used_words - __hi0bits(output_words[used_words - 1]);
    }
    return result;
}

/* Native entry: 0x4202155c. */
/*
 * Medius v3.4.7 — device application; 0x4202155c.
 *
 * Counts leading zero bits of a 32-bit word, returning 32 for zero.
 *
 * Called by: _dtoa_r, __d2b.
 *
 * Original function-byte SHA-256:
 * bb29053a08d125ce214252a14890d7343d575ebf501497f303691282886a51ac.
 */

/* Counts leading zero bits of a 32-bit word, returning 32 for zero.
   Reference: installed ESP32-S3 newlib 4.3.0 libc_a-mprec.o symbols, DWARF types and relocation-aware instruction comparison. */

/*
 * value: 32-bit unsigned word.
 * Returns: Leading-zero count0..32, with32 for zero.
 * Requirements/effects: Pure integer helper; no memory access or mutation outside locals.
 */

int __hi0bits(uint value)

{
  int leading_zeros;

  leading_zeros = 0;
  if (value < 0x10000) {
    value = value << 0x10;
    leading_zeros = 0x10;
  }
  if (value < 0x1000000) {
    leading_zeros = leading_zeros + 8;
    value = value << 8;
  }
  if (value < 0x10000000) {
    leading_zeros = leading_zeros + 4;
    value = value << 4;
  }
  if (value < 0x40000000) {
    leading_zeros = leading_zeros + 2;
    value = value << 2;
  }
  if ((-1 < (int)value) && (leading_zeros = leading_zeros + 1, (value >> 0x1e & 1) == 0)) {
    leading_zeros = 0x20;
  }
  return leading_zeros;
}

/* Native entry: 0x420215ac. */
/*
 * Medius v3.4.7 — device application; 0x420215ac.
 *
 * Counts trailing zero bits, shifts a nonzero input right by that count and returns it; zero returns 32.
 *
 * Called by: __d2b.
 *
 * Original function-byte SHA-256:
 * fe8b121773c5027b6b64f810da73203b5b54125d38987f805ab65c539a4c0ef3.
 */

/* Counts trailing zero bits, shifts a nonzero input right by that count and returns it; zero returns 32.
   Reference: installed ESP32-S3 newlib 4.3.0 libc_a-mprec.o symbols, DWARF types and relocation-aware instruction comparison. */

/*
 * value: Required writable uint32 word.
 * Returns: Trailing-zero count0..32, with32 for an input of zero.
 * Requirements/effects: For a nonzero input shifts it right by the returned count, leaving an odd
 *   word. Zero is left unchanged. No pointer validation, allocation or locking.
 */

int __lo0bits(uint *value)

{
  int trailing_zeros;
  uint shifted_value;

  shifted_value = *value;
  if ((shifted_value & 7) == 0) {
    trailing_zeros = 0;
    if ((shifted_value & 0xffff) == 0) {
      shifted_value = shifted_value >> 0x10;
      trailing_zeros = 0x10;
    }
    if ((shifted_value & 0xff) == 0) {
      trailing_zeros = trailing_zeros + 8;
      shifted_value = shifted_value >> 8;
    }
    if ((shifted_value & 0xf) == 0) {
      trailing_zeros = trailing_zeros + 4;
      shifted_value = shifted_value >> 4;
    }
    if ((shifted_value & 3) == 0) {
      trailing_zeros = trailing_zeros + 2;
      shifted_value = shifted_value >> 2;
    }
    if ((shifted_value & 1) == 0) {
      shifted_value = shifted_value >> 1;
      trailing_zeros = trailing_zeros + 1;
      if (shifted_value == 0) {
        return 0x20;
      }
    }
    *value = shifted_value;
  }
  else {
    trailing_zeros = 0;
    if ((shifted_value & 1) == 0) {
      if ((shifted_value & 2) == 0) {
        *value = shifted_value >> 2;
        trailing_zeros = 2;
      }
      else {
        *value = shifted_value >> 1;
        trailing_zeros = 1;
      }
    }
  }
  return trailing_zeros;
}

/* Native entry: 0x42021618. */
/*
 * Medius v3.4.7 — device application; 0x42021618.
 *
 * Compares Bigint magnitudes by used-word count then high-to-low words. Returns a negative, zero or positive result; the count difference need not be exactly -1 or 1.
 *
 * Called by: quorem, _dtoa_r, __mdiff.
 *
 * Original function-byte SHA-256:
 * f04b6030bb9bd6c19042dca4b587aefaae2f23961d0463f0e81583f922c1481f.
 */

/* Compares Bigint magnitudes by used-word count then high-to-low words. Returns a negative, zero or positive result; the count difference need not be exactly -1 or 1.
   Reference: installed ESP32-S3 newlib 4.3.0 libc_a-mprec.o symbols, DWARF types and relocation-aware instruction comparison. */

/*
 * left: Valid normalized nonnegative Bigint magnitude with used_words at least1.
 * right: Valid normalized magnitude with used_words at least1.
 * Returns: Negative, zero or positive magnitude comparison; unequal word-count results are not
 *   restricted to-1/+1.
 * Requirements/effects: Compares used-word counts, then scans equal-length word arrays from high
 *   to low. Does not allocate, modify operands or compare their sign fields.
 */

int __mcmp(MediusBigInt *left,MediusBigInt *right)

{
  int comparison;
  uint *right_cursor;
  int right_words;
  uint *left_cursor;

  right_words = right->used_words;
  comparison = left->used_words - right_words;
  if (comparison == 0) {
    left_cursor = left->words + right_words;
    right_cursor = right->words + right_words;
    do {
      left_cursor = left_cursor + -1;
      right_cursor = right_cursor + -1;
      if (*left_cursor != *right_cursor) {
        if (*left_cursor < *right_cursor) {
          return -1;
        }
        return 1;
      }
    } while (left->words < left_cursor);
  }
  return comparison;
}

