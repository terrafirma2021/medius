/* Medius v3.4.7 host — runtime/square_root.c.
 */

#include "../include/types.h"

/* Source reconstruction utilities; not additional native firmware entries. */
extern int *sqrt_errno_location(void) __asm__("__errno");
extern float sqrt_invalid_result(float numerator, float denominator) __asm__("__divsf3");

static bool sqrt_is_ordered_negative(float value)
{
    unsigned int negative;
    /* Preserve UN.S before OLT.S: a NaN bypasses the ordered comparison. */
    __asm__ volatile(
        "movi %0, 0\n\t"
        "un.s b0, %1, %1\n\t"
        "bt b0, 1f\n\t"
        "olt.s b0, %1, %2\n\t"
        "bf b0, 1f\n\t"
        "movi %0, 1\n"
        "1:"
        : "=&a"(negative) : "f"(value), "f"(0.0f) : "b0");
    return negative != 0;
}

/* Native entry: 0x403872ac. */
/*
 * Medius v3.4.7 — host application; 0x403872ac.
 * Instruction-checked recovered C.
 * Original function-byte SHA-256:
 * 18dc55e0dab78895e97bb81667a17db57772b5071c6dc99d55ad6bb5ba78c960.
 */

/*
 * Always evaluate the hardware square-root core first, including negative and
 * NaN inputs. Test the original input for unordered/NaN, then ordered less than
 * zero. NaNs, signed zero and nonnegative inputs return the core's float bits
 * unchanged. An ordered negative input, including negative infinity, gets the
 * current errno slot, writes EDOM (33), then returns the ROM binary32 divide
 * helper's result for 0.0f/0.0f. Both zero arguments are explicit; the missing
 * denominator in the raw decompilation was a calling-signature artifact.
 * No errno reset on success, rounding-mode change or error-pointer check occurs.
 */
float medius_math_sqrtf(float value)
{
    float result = medius_math_sqrtf_core(value);
    if (sqrt_is_ordered_negative(value)) {
        *sqrt_errno_location() = 33;
        return sqrt_invalid_result(0.0f, 0.0f);
    }
    return result;
}

/* Native entry: 0x4038407c. */
/*
 * Medius v3.4.7 — host application; 0x4038407c.
 * Instruction-checked recovered C and native floating-point operations.
 * Original function-byte SHA-256:
 * 607214b2e43d651bd3054c5eda7720e39a277b563fe44cd5d609027893ce7c1e.
 * That original identity covered only the first six bytes: decoding stopped
 * at SQRT0.S. The complete 98-byte body is 0x4038407c..0x403840dd, SHA-256:
 * a68bf1d15f2aaa3fdaa38225289728b593f82e51b39587f82829c16530b43dd0.
 */

/*
 * Execute the native binary32 square-root refinement sequence. SQRT0 supplies
 * the reciprocal-root estimate; normalized argument/error terms refine that
 * estimate and a reduced-range root. MKSADJ carries the original argument's
 * exponent and special-case adjustment into ADDEXPM/ADDEXP; DIVN performs the
 * final correction. Preserve all 29 native floating-point instructions and
 * their operand data flow, including NaN/zero/infinity/negative handling by
 * these CPU operations. Their intermediate encodings are not ordinary floats
 * that can safely be replaced with C multiplication or a guessed sqrt call.
 * CONST selector 0 supplies zero; selector 3 supplies one half. No memory,
 * allocation, errno handling or rounding-mode write occurs inside this core.
 */
float medius_math_sqrtf_core(float value)
{
    float root, inverse, temporary, negative_half_argument;
    float positive_argument, correction, half_inverse;
    __asm__ volatile(
        /* Initial reciprocal-root estimate and its first error correction. */
        "sqrt0.s %[inverse], %[argument]\n\t"
        "const.s %[temporary], 0\n\t"
        "maddn.s %[temporary], %[inverse], %[inverse]\n\t"
        "nexp01.s %[negative_half], %[argument]\n\t"
        "const.s %[root], 3\n\t"
        "addexp.s %[negative_half], %[root]\n\t"
        "maddn.s %[root], %[temporary], %[negative_half]\n\t"
        "nexp01.s %[temporary], %[argument]\n\t"
        "neg.s %[positive], %[temporary]\n\t"
        "maddn.s %[inverse], %[root], %[inverse]\n\t"
        /* Form and refine the reduced-range root and half reciprocal root. */
        "const.s %[root], 0\n\t"
        "const.s %[correction], 0\n\t"
        "const.s %[half_inverse], 0\n\t"
        "maddn.s %[root], %[positive], %[inverse]\n\t"
        "maddn.s %[correction], %[inverse], %[negative_half]\n\t"
        "const.s %[negative_half], 3\n\t"
        "maddn.s %[half_inverse], %[negative_half], %[inverse]\n\t"
        "maddn.s %[temporary], %[root], %[root]\n\t"
        "maddn.s %[negative_half], %[correction], %[inverse]\n\t"
        "neg.s %[inverse], %[half_inverse]\n\t"
        "maddn.s %[root], %[temporary], %[inverse]\n\t"
        "maddn.s %[half_inverse], %[negative_half], %[half_inverse]\n\t"
        /* Reapply original argument adjustments and finish the correction. */
        "mksadj.s %[inverse], %[argument]\n\t"
        "nexp01.s %[argument], %[argument]\n\t"
        "maddn.s %[argument], %[root], %[root]\n\t"
        "neg.s %[temporary], %[half_inverse]\n\t"
        "addexpm.s %[root], %[inverse]\n\t"
        "addexp.s %[temporary], %[inverse]\n\t"
        "divn.s %[root], %[argument], %[temporary]"
        : [argument] "+f"(value), [root] "=&f"(root),
          [inverse] "=&f"(inverse), [temporary] "=&f"(temporary),
          [negative_half] "=&f"(negative_half_argument),
          [positive] "=&f"(positive_argument), [correction] "=&f"(correction),
          [half_inverse] "=&f"(half_inverse));
    return root;
}
