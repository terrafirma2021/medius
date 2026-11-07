/* Medius v3.4.7 host — runtime/exponential.c.
 * Instruction-checked recovered binary32 exponential-minus-one.
 */

#include "../include/types.h"

/* Source reconstruction utilities; not additional native firmware entries.
 * Inline native instructions retain each rounding boundary and exceptional
 * conversion. Constant hex floats encode the literal-pool WORDs exactly. */
typedef union {unsigned int bits;float value;} ExponentialFloatWord;
_Static_assert(sizeof(ExponentialFloatWord)==4,"binary32 WORD");
extern float exponential_divide(float numerator,float denominator) __asm__("__divsf3");
static __inline__ __attribute__((always_inline)) float exponential_add(float a,float b)
{float r;__asm__ volatile("add.s %0,%1,%2":"=f"(r):"f"(a),"f"(b));return r;}
static __inline__ __attribute__((always_inline)) float exponential_subtract(float a,float b)
{float r;__asm__ volatile("sub.s %0,%1,%2":"=f"(r):"f"(a),"f"(b));return r;}
static __inline__ __attribute__((always_inline)) float exponential_multiply(float a,float b)
{float r;__asm__ volatile("mul.s %0,%1,%2":"=f"(r):"f"(a),"f"(b));return r;}
static __inline__ __attribute__((always_inline)) float exponential_madd(float sum,float a,float b)
{__asm__ volatile("madd.s %0,%1,%2":"+f"(sum):"f"(a),"f"(b));return sum;}
static __inline__ __attribute__((always_inline)) float exponential_msub(float sum,float a,float b)
{__asm__ volatile("msub.s %0,%1,%2":"+f"(sum):"f"(a),"f"(b));return sum;}
static __inline__ __attribute__((always_inline)) float exponential_negate(float value)
{float r;__asm__ volatile("neg.s %0,%1":"=f"(r):"f"(value));return r;}
static __inline__ __attribute__((always_inline)) float exponential_from_int(int value)
{float r;__asm__ volatile("float.s %0,%1,0":"=f"(r):"a"(value));return r;}
static __inline__ __attribute__((always_inline)) int exponential_truncate(float value)
{int r;__asm__ volatile("trunc.s %0,%1,0":"=a"(r):"f"(value));return r;}

/* Native entry: 0x420158dc. */
/* Original function-byte SHA-256:
 * f7967f95511fa91de474a2a6bff4db2c2788416becae55012c80d46f4856aac3. */
/*
 * Return exp(value)-1 in binary32 without losing the small-input difference.
 * Input classification uses magnitude/sign bits, not floating comparisons.
 * NaN returns value+value; +infinity returns unchanged; -infinity returns-1.
 * Positive magnitude above0x42b17217 delegates to the positive-overflow helper.
 * Large negative finite values execute value+1e-30 before returning-1 when
 * the ordered sum is negative. Tiny |value|<2^-25 executes
 * value-((value+1e30)-(value+1e30)), preserving native arithmetic effects.
 *
 * For other finite inputs, reduce by k*ln(2) using split constants and native
 * TRUNC.S, retaining the reduction error. Evaluate the reduced polynomial with
 * the exact MADD.S/MSUB.S grouping, then reconstruct with separate k=0,-1,1,
 * 2..22,23..56 and outside-range forms. Final exponent adjustments operate on
 * raw WORDs with unsigned wrap; they are not C numeric float/integer casts.
 *
 * No allocation, memory mutation, explicit errno write or independent lock.
 * Overflow/division helpers and native FP instructions supply their own flags
 * and errors. This is a static reconstruction, not a claim of accuracy across
 * untested hardware rounding/exception modes.
 */
float medius_math_expm1f(float value)
{
    ExponentialFloatWord input={.value=value};
    unsigned int magnitude=input.bits&0x7fffffffU;
    bool negative=(input.bits&0x80000000U)!=0;
    if (magnitude>0x4195b843U) {
        if (magnitude>0x7f800000U) return exponential_add(value,value);
        if (magnitude==0x7f800000U) return negative ? -1.0f : value;
        if (!negative && magnitude>0x42b17217U) return medius_math_overflow(0);
        if (negative) {
            float sum=exponential_add(value,0x1.4484c0p-100f); /* 1e-30 */
            if (sum<0.0f) return -1.0f;
        }
    }

    int exponent=0;
    float reduced=value,reduction_error=0.0f;
    if (magnitude>0x3eb17218U) {
        float high,low;
        if (magnitude<=0x3f851591U) {
            if (negative) {
                high=exponential_add(value,0x1.62e300p-1f);
                low=-0x1.2fefa2p-17f;
                exponent=-1;
            } else {
                high=exponential_subtract(value,0x1.62e300p-1f);
                low=0x1.2fefa2p-17f;
                exponent=1;
            }
        } else {
            float quotient=exponential_multiply(value,0x1.715476p+0f);
            float rounded=exponential_add(negative ? -0.5f : 0.5f,quotient);
            exponent=exponential_truncate(rounded);
            float k=exponential_from_int(exponent);
            high=exponential_msub(value,k,0x1.62e300p-1f);
            low=exponential_multiply(k,0x1.2fefa2p-17f);
        }
        reduced=exponential_subtract(high,low);
        reduction_error=exponential_subtract(exponential_subtract(high,reduced),low);
    } else if (magnitude<0x33000000U) {
        float large_sum=exponential_add(value,0x1.93e594p+99f); /* 1e30 */
        return exponential_subtract(value,exponential_subtract(large_sum,large_sum));
    }

    float half_reduced=exponential_multiply(reduced,0.5f);
    float half_square=exponential_multiply(reduced,half_reduced);
    float polynomial=exponential_madd(0x1.0cfca8p-18f,half_square,-0x1.afdb76p-23f);
    polynomial=exponential_madd(-0x1.4ce19ap-14f,polynomial,half_square);
    polynomial=exponential_madd(0x1.a01a02p-10f,polynomial,half_square);
    polynomial=exponential_madd(-0x1.111112p-5f,polynomial,half_square);
    polynomial=exponential_madd(1.0f,polynomial,half_square);
    float t=exponential_msub(3.0f,half_reduced,polynomial);
    float denominator=exponential_msub(6.0f,reduced,t);
    float numerator=exponential_subtract(polynomial,t);
    float fraction=exponential_divide(numerator,denominator);
    float error=exponential_multiply(fraction,half_square);
    if (exponent==0) {
        float correction=exponential_madd(exponential_negate(half_square),reduced,error);
        return exponential_subtract(reduced,correction);
    }
    float corrected=exponential_subtract(error,reduction_error);
    error=exponential_madd(exponential_negate(reduction_error),corrected,reduced);
    error=exponential_subtract(error,half_square);
    if (exponent==-1)
        return exponential_madd(-0.5f,exponential_subtract(reduced,error),0.5f);
    if (exponent==1) {
        if (reduced < -0.25f)
            return exponential_multiply(exponential_subtract(error,exponential_add(reduced,0.5f)),-2.0f);
        return exponential_madd(1.0f,exponential_subtract(reduced,error),2.0f);
    }

    unsigned int exponent_word=(unsigned int)exponent<<23;
    ExponentialFloatWord result;
    if ((unsigned int)(exponent+1)>57U) {
        result.value=exponential_subtract(1.0f,exponential_subtract(error,reduced));
        result.bits+=exponent_word;
        return exponential_subtract(result.value,1.0f);
    }
    if (exponent<23) {
        ExponentialFloatWord one_minus_scale={.bits=0x3f800000U-(0x01000000U>>((unsigned int)exponent&31U))};
        result.value=exponential_subtract(one_minus_scale.value,exponential_subtract(error,reduced));
    } else {
        ExponentialFloatWord reciprocal_scale={.bits=(127U-(unsigned int)exponent)<<23};
        result.value=exponential_add(exponential_subtract(reduced,
            exponential_add(error,reciprocal_scale.value)),1.0f);
    }
    result.bits+=exponent_word;
    return result.value;
}
