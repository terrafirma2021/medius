/* Medius v3.4.7 host — runtime/math_errors.c.
 */

#include "../include/types.h"

/* Source reconstruction utilities; not additional native firmware entries. */
extern int *math_errors_errno_location(void) __asm__("__errno");
extern float math_errors_divide(float numerator, float denominator) __asm__("__divsf3");

static bool math_errors_is_nan(float value)
{
    unsigned int unordered;
    __asm__ volatile(
        "movi %0, 0\n\t"
        "un.s b0, %1, %1\n\t"
        "bf b0, 1f\n\t"
        "movi %0, 1\n"
        "1:"
        : "=&a"(unordered) : "f"(value) : "b0");
    return unordered != 0;
}

static float math_errors_float(unsigned int bits)
{
    union {unsigned int bits; float value;} representation = {.bits = bits};
    return representation.value;
}

/* Native entry: 0x42015ba4. */
/*
 * Medius v3.4.7 — host application; 0x42015ba4.
 * Instruction-checked recovered C.
 * Original function-byte SHA-256:
 * f854df4c72f461dae400fe65fc797232ae4b99174d0d29584ea91ebfe3cc9df2.
 */

/*
 * Get the current errno slot, store the full 32-bit error argument, and return
 * result unchanged. The original a2 result survives the windowed call: this
 * function returns a float, despite the raw decompiler's void signature. No
 * floating arithmetic, error filtering, NULL-slot check or mode change occurs.
 */
float medius_math_with_errno(float result, int error)
{
    *math_errors_errno_location() = error;
    return result;
}

/* Native entry: 0x42015bb4. */
/*
 * Medius v3.4.7 — host application; 0x42015bb4.
 * Instruction-checked recovered C.
 * Original function-byte SHA-256:
 * 7a559569b86a4f657ea315ec70d5f672174d57cfe8cadbf8d914778d35173c43.
 */

/*
 * Multiply value by itself, negating the first multiplicand when negative is
 * nonzero, then set ERANGE (34) and return the product. Negation precedes the
 * single binary32 multiply. No overflow/underflow test gates the errno write;
 * even zero, finite and NaN results take the same errno-setting call. Arithmetic
 * rounding and exception effects remain those of the native floating operations.
 */
float medius_math_range_product(unsigned int negative, float value)
{
    float first = negative ? -value : value;
    return medius_math_with_errno(first * value, 34);
}

/* Native entry: 0x42015bd4. */
/*
 * Medius v3.4.7 — host application; 0x42015bd4.
 * Instruction-checked recovered C.
 * Original function-byte SHA-256:
 * 4131923c0467ba8219c2ae38e9bd37d88a4c221e6b30cacb3a250d4d075cfb2e.
 */

/*
 * Generate a signed overflow through range_product(negative, 2^97), forwarding
 * the entire sign-selector word. The native literal is float bits 0x70000000,
 * not the integer value converted to float. Product rounding is mode-dependent;
 * do not replace this with a fixed infinity constant. ERANGE is always written.
 */
float medius_math_overflow(unsigned int negative)
{
    return medius_math_range_product(negative, math_errors_float(0x70000000U));
}

/* Native entry: 0x42015be8. */
/*
 * Medius v3.4.7 — host application; 0x42015be8.
 * Instruction-checked recovered C.
 * Original function-byte SHA-256:
 * 7ce3c13c565319476af62f95f6f5da98f91266b2161fe35d5e46bf40aae78c7c.
 */

/*
 * Divide +1.0f by +0.0f, or -1.0f by +0.0f when negative is nonzero, using
 * the ROM binary32 division helper. Then write ERANGE (34) and return that
 * helper's result. Preserve the division call and both arguments; no finite
 * replacement, sign normalization, pointer check or errno rollback is added.
 */
float medius_math_divide_by_zero(unsigned int negative)
{
    float numerator = negative ? -1.0f : 1.0f;
    float result = math_errors_divide(numerator, 0.0f);
    return medius_math_with_errno(result, 34);
}

/* Native entry: 0x42015c10. */
/*
 * Medius v3.4.7 — host application; 0x42015c10.
 * Instruction-checked recovered C.
 * Original function-byte SHA-256:
 * 229a540ae45072fe1913674cf60288e5c7fe08c28633bace75615e09551a1bf8.
 */

/*
 * Subtract the input from itself once, then pass that same binary32 difference
 * as both arguments to the ROM divide helper. After division, classify the
 * original input with UN.S. A NaN input returns the division result without
 * touching errno; every other input writes EDOM (33) and returns that result.
 * Infinity therefore still reaches the errno write even though its difference
 * is NaN. No arithmetic operation is replaced with a fixed NaN or integer cast.
 */
float medius_math_invalid(float value)
{
    float difference = value - value;
    float result = math_errors_divide(difference, difference);
    if (math_errors_is_nan(value)) return result;
    return medius_math_with_errno(result, 33);
}
