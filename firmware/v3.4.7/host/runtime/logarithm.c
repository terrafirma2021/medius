/* Medius v3.4.7 host — runtime/logarithm.c.
 */

#include "../include/types.h"

/* Source reconstruction utilities; not additional native firmware entries.
 * MADD.S/MSUB.S must stay combined native instructions. Expanding them into C
 * multiply/add expressions can change the target's intermediate rounding. */
extern float log1p_divide(float numerator,float denominator) __asm__("__divsf3");
static __inline__ __attribute__((always_inline)) float log1p_add(float left,float right)
{float result;__asm__ volatile("add.s %0, %1, %2":"=f"(result):"f"(left),"f"(right));return result;}
static __inline__ __attribute__((always_inline)) float log1p_subtract(float left,float right)
{float result;__asm__ volatile("sub.s %0, %1, %2":"=f"(result):"f"(left),"f"(right));return result;}
static __inline__ __attribute__((always_inline)) float log1p_multiply(float left,float right)
{float result;__asm__ volatile("mul.s %0, %1, %2":"=f"(result):"f"(left),"f"(right));return result;}
static __inline__ __attribute__((always_inline)) float log1p_negate(float value)
{float result;__asm__ volatile("neg.s %0, %1":"=f"(result):"f"(value));return result;}
static __inline__ __attribute__((always_inline)) float log1p_madd(float accumulator,float left,float right)
{__asm__ volatile("madd.s %0, %1, %2":"+f"(accumulator):"f"(left),"f"(right));return accumulator;}
static __inline__ __attribute__((always_inline)) float log1p_msub(float accumulator,float left,float right)
{__asm__ volatile("msub.s %0, %1, %2":"+f"(accumulator):"f"(left),"f"(right));return accumulator;}
static __inline__ __attribute__((always_inline)) float log1p_float_signed(int value)
{float result;__asm__ volatile("float.s %0, %1, 0":"=f"(result):"a"(value));return result;}
static __inline__ __attribute__((always_inline)) float log1p_from_bits(unsigned int bits)
{union {unsigned int bits;float value;} view={.bits=bits};return view.value;}
static __inline__ __attribute__((always_inline)) unsigned int log1p_to_bits(float value)
{union {unsigned int bits;float value;} view={.value=value};return view.bits;}

/* Native entry: 0x4038703c. */
/* Original function-byte SHA-256:
 * 8f5bb07f5d6c6205cc50a26cf0cef23c568f59b0a3f44585ce9b62b1eea90cba. */
/* Binary32 log(1+x), with native bit classification and range reduction.
 * Positive infinity/NaNs take x+x. In the signed-small branch, |x|>=1 sends
 * exactly-1 to the negative divide-by-zero service and all other such inputs
 * to invalid(value), preserving their separately reviewed errno/FPU behavior.
 * Consequently negative infinities/NaNs use that error path. Tiny |x|<2^-29
 * first performs 33554432+x; |x|<2^-54 can then return the original bits,
 * including negative zero. Other tiny inputs use x-(x*x)*0.5 via native MSUB.S.
 *
 * Moderate near-zero values use x directly. Otherwise form rounded u=1+x and
 * its cancellation correction, divide that correction by u, and normalize
 * u's mantissa about1. For x>=2^53 use x without adding1, correction+0. Adjust
 * the signed binary exponent when the mantissa crosses the native0x3504f6
 * boundary. Evaluate the reduced logarithm using half-square and a seven-term
 * polynomial in (f/(2+f))^2, or its zero-fraction shortcut. Recombine exponent
 * with split ln(2) high/low constants and the saved cancellation correction.
 *
 * All binary32 constants, operation/operand order, MADD.S/MSUB.S, signed bit
 * tests and exceptional-value routes are retained explicitly. The routine
 * borrows ROM float division and the existing error services; it does not
 * allocate, log or synchronize. This review does not establish a measured
 * approximation-error bound or runtime/timing equivalence.
 */
float medius_math_log1pf(float value)
{
    unsigned int bits = log1p_to_bits(value);
    int signed_bits = (int)bits;
    if (signed_bits > 0x7f7fffff) return log1p_add(value,value);
    int exponent = 0;
    float correction = 0.0f;
    float reduced = value;
    unsigned int fraction = 1;
    int reduce = 1;
    if (signed_bits <= 0x3ed413d6) {
        unsigned int absolute = bits & 0x7fffffffU;
        if (absolute > 0x3f7fffffU) {
            if (value == -1.0f) return medius_math_divide_by_zero(1);
            return medius_math_invalid(value);
        }
        if (absolute <= 0x30ffffffU) {
            float forced_rounding = log1p_add(value,33554432.0f);
            if (0.0f < forced_rounding && absolute <= 0x247fffffU) return value;
            float squared = log1p_multiply(value,value);
            return log1p_msub(value,squared,0.5f);
        }
        if (bits+0x416a09e0U > 0x416a09e0U) reduce = 0;
    }
    if (reduce) {
        unsigned int normalization_bits;
        if (signed_bits <= 0x59ffffff) {
            float rounded_one_plus_x = log1p_add(value,1.0f);
            normalization_bits = log1p_to_bits(rounded_one_plus_x);
            exponent = ((int)normalization_bits >> 23)-127;
            if (exponent >= 1) correction = log1p_subtract(1.0f,
                log1p_subtract(rounded_one_plus_x,value));
            else correction = log1p_subtract(value,log1p_subtract(rounded_one_plus_x,1.0f));
            correction = log1p_divide(correction,rounded_one_plus_x);
        } else {
            normalization_bits = bits;
            exponent = (signed_bits >> 23)-127;
            correction = 0.0f;
        }
        fraction = normalization_bits & 0x7fffffU;
        unsigned int normalized;
        if (fraction <= 0x3504f6U) normalized = fraction|0x3f800000U;
        else {
            normalized = fraction|0x3f000000U;
            ++exponent;
            fraction = (0x800000U-fraction)>>2;
        }
        reduced = log1p_subtract(log1p_from_bits(normalized),1.0f);
    }
    float half_square = log1p_multiply(log1p_multiply(reduced,0.5f),reduced);
    const float ln2_low = log1p_from_bits(0x3717f7d1U);
    const float ln2_high = log1p_from_bits(0x3f317180U);
    if (fraction == 0) {
        if (reduced == 0.0f) {
            if (exponent == 0) return 0.0f;
            float power = log1p_float_signed(exponent);
            float low = log1p_madd(correction,power,ln2_low);
            return log1p_madd(low,power,ln2_high);
        }
        float factor = log1p_msub(1.0f,reduced,log1p_from_bits(0x3f2aaaabU));
        half_square = log1p_multiply(factor,half_square);
        if (exponent == 0) return log1p_subtract(reduced,half_square);
        float power = log1p_float_signed(exponent);
        float low = log1p_madd(correction,power,ln2_low);
        float residual = log1p_subtract(half_square,low);
        residual = log1p_subtract(residual,reduced);
        residual = log1p_negate(residual);
        return log1p_madd(residual,power,ln2_high);
    }
    float ratio = log1p_divide(reduced,log1p_add(reduced,2.0f));
    float square = log1p_multiply(ratio,ratio);
    float polynomial = log1p_madd(log1p_from_bits(0x3e1cd04fU),square,log1p_from_bits(0x3e178897U));
    polynomial = log1p_madd(log1p_from_bits(0x3e3a3325U),polynomial,square);
    polynomial = log1p_madd(log1p_from_bits(0x3e638e29U),polynomial,square);
    polynomial = log1p_madd(log1p_from_bits(0x3e924925U),polynomial,square);
    polynomial = log1p_madd(log1p_from_bits(0x3ecccccdU),polynomial,square);
    polynomial = log1p_madd(log1p_from_bits(0x3f2aaaabU),polynomial,square);
    float term = log1p_madd(half_square,polynomial,square);
    term = log1p_multiply(ratio,term);
    if (exponent == 0) return log1p_subtract(reduced,log1p_subtract(half_square,term));
    float power = log1p_float_signed(exponent);
    float low = log1p_madd(correction,power,ln2_low);
    low = log1p_add(low,term);
    float residual = log1p_subtract(half_square,low);
    residual = log1p_subtract(residual,reduced);
    residual = log1p_negate(residual);
    return log1p_madd(residual,power,ln2_high);
}
