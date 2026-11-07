/* Medius v3.4.7 host — runtime/rounding.c.
 */

#include "../include/types.h"

/* Source reconstruction utilities; not additional native firmware entries. */
static unsigned int math_rounding_bits(float value)
{
    union { float value; unsigned int bits; } representation = { .value = value };
    return representation.bits;
}

static float math_rounding_float(unsigned int bits)
{
    union { unsigned int bits; float value; } representation = { .bits = bits };
    return representation.value;
}

/* Native entry: 0x42015b94. */
/*
 * Medius v3.4.7 — host application; 0x42015b94.
 * Instruction-checked recovered C.
 * Original function-byte SHA-256:
 * 5930da1b6fca8e8bd0ec08c4e0a561b3b9d76a88246970447d714ddda3d672ec.
 */

/*
 * Forward the binary32 argument unchanged to the rounding core and return its
 * binary32 result. The windowed ABI transfers float bits in integer argument
 * and return registers; this is not an integer-to-float conversion. No extra
 * rounding-mode change, validation, errno write or memory access is added.
 */
float medius_math_rintf(float value)
{
    return medius_math_rintf_core(value);
}

/* Native entry: 0x42015c40. */
/*
 * Medius v3.4.7 — host application; 0x42015c40.
 * Instruction-checked recovered C.
 * Original function-byte SHA-256:
 * bd4d37e97deb5d59433105af80a33639ff0385946cd5909458d954bf812bb600.
 */

/*
 * Round a binary32 value to an integral binary32 value using the current
 * floating-point arithmetic rounding mode. Preserve both signed zeros and
 * already-integral finite values without arithmetic. For fractional finite
 * values, retain the relevant rounding/sticky bits and add/subtract signed
 * 2^23. Store the intermediate sum as volatile binary32 between the two native
 * MEMW barriers: evaluation at wider precision changes this algorithm.
 * Values below one receive an explicit restoration of the original sign bit,
 * including a zero result. Infinity/NaN takes value+value, preserving the native
 * arithmetic path for NaN quieting/exception behavior rather than returning
 * their bits directly. This does not change the floating-point mode, write
 * errno or force ties-away rounding; under nearest-even, half ties go even.
 */
float medius_math_rintf_core(float value)
{
    unsigned int bits = math_rounding_bits(value);
    unsigned int magnitude = bits & 0x7fffffffU;
    int exponent = (int)((bits >> 23) & 255U) - 127;
    if (exponent > 22) {
        if (magnitude <= 0x7f7fffffU) return value;
        return value + value;
    }
    if (magnitude == 0) return value;
    unsigned int sign = bits >> 31;
    float bias = sign ? -8388608.0f : 8388608.0f;
    if (exponent < 0) {
        unsigned int fraction = bits & 0x007fffffU;
        unsigned int sticky = ((0U - fraction) >> 31) << 22;
        unsigned int reduced_bits = (bits & 0xfff00000U) | sticky;
        float sum = bias + math_rounding_float(reduced_bits);
        memw();
        volatile float rounded = sum;
        memw();
        float result = rounded - bias;
        unsigned int result_bits = math_rounding_bits(result);
        return math_rounding_float((result_bits & 0x7fffffffU) | (sign << 31));
    }
    unsigned int fractional_mask = 0x007fffffU >> (unsigned int)exponent;
    if ((bits & fractional_mask) == 0) return value;
    unsigned int lower_mask = fractional_mask >> 1;
    if (bits & lower_mask)
        bits = (bits ^ (bits & lower_mask)) | (0x00200000U >> (unsigned int)exponent);
    float sum = bias + math_rounding_float(bits);
    memw();
    volatile float rounded = sum;
    memw();
    return rounded - bias;
}
