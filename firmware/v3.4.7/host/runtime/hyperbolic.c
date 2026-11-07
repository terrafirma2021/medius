/* Medius v3.4.7 host — runtime/hyperbolic.c.
 * Instruction-checked recovered binary32 activation and sign-bit operation.
 */

#include "../include/types.h"

/* Source reconstruction utilities; not additional native firmware entries.
 * ROM constants are read at the original widths/order with explicit barriers.
 * C literals would discard these repeated reads and their call boundaries.
 */
typedef union {unsigned int bits;float value;} HyperbolicFloatWord;
_Static_assert(sizeof(HyperbolicFloatWord)==4,"binary32 WORD");
#define TANH_ONE ((const volatile HyperbolicFloatWord *)0x3c0519e8U)
#define TANH_TWO ((const volatile HyperbolicFloatWord *)0x3c0519e4U)
#define TANH_TINY ((const volatile HyperbolicFloatWord *)0x3c0519e0U)
extern float hyperbolic_divide(float numerator,float denominator) __asm__("__divsf3");
static __inline__ __attribute__((always_inline)) float hyperbolic_add(float a,float b)
{float r;__asm__ volatile("add.s %0,%1,%2":"=f"(r):"f"(a),"f"(b));return r;}
static __inline__ __attribute__((always_inline)) float hyperbolic_subtract(float a,float b)
{float r;__asm__ volatile("sub.s %0,%1,%2":"=f"(r):"f"(a),"f"(b));return r;}
static __inline__ __attribute__((always_inline)) float hyperbolic_multiply(float a,float b)
{float r;__asm__ volatile("mul.s %0,%1,%2":"=f"(r):"f"(a),"f"(b));return r;}
static __inline__ __attribute__((always_inline)) float hyperbolic_negate(float a)
{float r;__asm__ volatile("neg.s %0,%1":"=f"(r):"f"(a));return r;}

/* Native entry: 0x4201579c. */
/* Original function-byte SHA-256:
 * 5c9135691130f70fe89cfbbffcf094704a9e46ece3c836a69497e38c9694b7a0. */
/*
 * Binary32 tanh using expm1 and sign restoration. Input bits select every
 * range; no floating comparison is used for classification or the sign test.
 *
 * NaN/infinity: divide the ROM ONE by the original input, then add/subtract
 * a separately read ONE according to the original sign bit. Finite |x|>=22
 * uses ONE-TINY. |x|<2^-55 uses (ONE+x)*x, retaining signed zero and native
 * arithmetic flags. Between those limits, |x|>=1 uses 1-2/(expm1(2|x|)+2),
 * and |x|<1 uses -expm1(-2|x|)/(2+expm1(-2|x|)).
 *
 * Cached versus reread constants, operand order and MEMW boundaries follow
 * the instructions. The linked ROM WORDs are ONE=1, TWO=2 and TINY~=1e-30;
 * non-default rounding therefore remains native arithmetic, not forced +/-1.
 * No explicit errno write, argument validation, allocation or synchronization
 * beyond the shown barriers. Expm1/division retain their own behavior.
 */
float medius_math_tanhf(float value)
{
    HyperbolicFloatWord input={.value=value};
    unsigned int magnitude=input.bits&0x7fffffffU;
    bool negative=(input.bits&0x80000000U)!=0;
    if (magnitude>0x7f7fffffU) {
        memw();
        HyperbolicFloatWord numerator={.bits=TANH_ONE->bits};
        memw();
        float one=TANH_ONE->value;
        float quotient=hyperbolic_divide(numerator.value,value);
        return negative ? hyperbolic_subtract(quotient,one) : hyperbolic_add(quotient,one);
    }
    if (magnitude<0x24000000U) {
        memw();
        float one=TANH_ONE->value;
        return hyperbolic_multiply(hyperbolic_add(one,value),value);
    }
    float result;
    if (magnitude>=0x41b00000U) {
        memw();
        float one=TANH_ONE->value;
        memw();
        float tiny=TANH_TINY->value;
        result=hyperbolic_subtract(one,tiny);
    } else if (magnitude>=0x3f800000U) {
        float absolute=medius_math_fabsf(value);
        memw();
        float two=TANH_TWO->value;
        float exponential=medius_math_expm1f(hyperbolic_multiply(absolute,two));
        memw();
        float one=TANH_ONE->value;
        memw();
        HyperbolicFloatWord numerator={.bits=TANH_TWO->bits};
        memw();
        float denominator_two=TANH_TWO->value;
        float denominator=hyperbolic_add(denominator_two,exponential);
        float quotient=hyperbolic_divide(numerator.value,denominator);
        result=hyperbolic_subtract(one,quotient);
    } else {
        memw();
        float two=TANH_TWO->value;
        float absolute=medius_math_fabsf(value);
        float negative_two=hyperbolic_negate(two);
        float exponential=medius_math_expm1f(hyperbolic_multiply(negative_two,absolute));
        memw();
        float denominator_two=TANH_TWO->value;
        float denominator=hyperbolic_add(denominator_two,exponential);
        float numerator=hyperbolic_negate(exponential);
        result=hyperbolic_divide(numerator,denominator);
    }
    return negative ? hyperbolic_negate(result) : result;
}

/* Native entry: 0x4201ec70. */
/* Original function-byte SHA-256:
 * 89ace34c1571a3c1c404c9a9ece80fc1a653ca958199f40a80098b450076d03b. */
/* Clear only the binary32 sign bit and return the remaining bits unchanged.
 * This is an integer operation: negative zero becomes positive zero; exponent,
 * significand, NaN payload and signaling/quiet bit survive unchanged. No floating
 * arithmetic, classification, memory access, errno change or flags operation. */
float medius_math_fabsf(float value)
{
    HyperbolicFloatWord word={.value=value};
    word.bits&=0x7fffffffU;
    return word.value;
}
