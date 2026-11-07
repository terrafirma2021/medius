/* Medius v3.4.7 host — app/motion_features.c.
 */

#include "../include/types.h"

/* Source reconstruction utilities; not extra native firmware entries. Retain
 * separate ROM unsigned64 divide/remainder boundaries and tie-to-even rules. */
extern unsigned long long motion_feature_udiv64(unsigned long long value,
    unsigned long long divisor) __asm__("__udivdi3");
extern unsigned long long motion_feature_umod64(unsigned long long value,
    unsigned long long divisor) __asm__("__umoddi3");

static long long motion_feature_round_ratio(long long numerator,unsigned int denominator)
{
    int negative = numerator < 0;
    unsigned long long absolute = negative ? 0ULL - (unsigned long long)numerator : (unsigned long long)numerator;
    unsigned long long quotient = motion_feature_udiv64(absolute,denominator);
    unsigned long long remainder = motion_feature_umod64(absolute,denominator);
    unsigned long long twice = remainder + remainder;
    if (twice > denominator || (twice == denominator && (quotient & 1ULL))) ++quotient;
    return negative ? -(long long)quotient : (long long)quotient;
}

static short motion_feature_clamp_q15(long long value)
{
    if (value < -32767) return -32767;
    if (value > 32767) return 32767;
    return (short)value;
}

static int motion_feature_round_q16(long long product)
{
    int negative = product < 0;
    unsigned long long absolute = negative ? 0ULL - (unsigned long long)product : (unsigned long long)product;
    unsigned int whole = (unsigned int)(absolute >> 16);
    unsigned int fraction = (unsigned int)absolute & 0xffffU;
    if (fraction > 0x8000U || (fraction == 0x8000U && (whole & 1U))) ++whole;
    return negative ? -(int)whole : (int)whole;
}

/* Native entry: 0x40377fd4. */
/* Original function-byte SHA-256:
 * 7d7a43c045eaa9189c5462d28cbcb6fcd0e832de0d32e1fe228472d098dc5d2a. */
/* Compute floor(sqrt(x*x+y*y)) using the native unsigned64 restoring square
 * root algorithm, then write its unsigned32 magnitude FIRST. Signed32 input
 * squares are widened before addition, so the largest sum is exactly2^63.
 * The native high-root guard saturates a result aboveUINT32_MAX; valid signed32
 * inputs cannot reach it. Zero magnitude writes direction X0 thenY0 and stops.
 *
 * For nonzero magnitude, divide each signed64 component*32767 by the cached
 * integer magnitude, round nearest with ties to even and clamp to[-32767,32767].
 * Finish both component calculations before storing signed16 X thenY. This is
 * normalization by the FLOOR magnitude, not a floating Euclidean unit vector;
 * e.g.(1,1) yields magnitude1 and direction(32767,32767). No NULL checks, lock,
 * rounding-mode dependence or error return. Magnitude/output overlap retains
 * the initial WORD write and subsequent two HALFWORD stores in native order.
 */
void medius_motion_normalize_vector_q15(int x,int y,volatile MediusMotionDirectionQ15 *direction,
    volatile unsigned int *magnitude)
{
    unsigned long long squared = (unsigned long long)((long long)x*x) +
        (unsigned long long)((long long)y*y);
    unsigned long long bit = 1ULL << 62;
    while (bit > squared) bit >>= 2;
    unsigned long long root = 0;
    while (bit != 0) {
        unsigned long long trial = root + bit;
        root >>= 1;
        if (trial <= squared) {
            squared -= trial;
            root += bit;
        }
        bit >>= 2;
    }
    unsigned int length = root > 0xffffffffULL ? 0xffffffffU : (unsigned int)root;
    *magnitude = length;
    if (length == 0) {
        direction->x = 0;
        direction->y = 0;
        return;
    }
    long long normalized_x = motion_feature_round_ratio((long long)x*32767,length);
    long long normalized_y = motion_feature_round_ratio((long long)y*32767,length);
    short output_x = motion_feature_clamp_q15(normalized_x);
    short output_y = motion_feature_clamp_q15(normalized_y);
    direction->x = output_x;
    direction->y = output_y;
}

/* Native entry: 0x403782f8. */
/* Original function-byte SHA-256:
 * 3cf7448b2e6b5f8ad5542a925ce4cbe205fb89d35a1456de7d3b4dbaa9848afa. */
/* Approximate ln(unsigned64 magnitude/2^20) in signedQ14. Magnitude arrives as
 * explicit LOW/HIGH WORDs after an ignored ABI word. Zero returns-262144
 * (-16 inQ14) without reading configuration. Otherwise normalize its leading
 * bit to bit24, discard lower bits, subtract2^24 and use an8-bit interval plus
 *16-bit fraction. Read the cached signed16 table's upper entry before lower;
 * interpolate their difference with signed nearest/ties-even Q16 rounding.
 * The native fallback reads entry256 if interval>255. Add (floor_log2-20)*11357
 * using the firmware's rounded Q14 ln(2), not a floating logarithm.
 *
 * The embedded configuration table contains round(ln(1+i/256)*16384),0..256.
 * It remains a borrowed caller-selected table: no table identity, pointer,
 * length, monotonicity or lock checks are added. No configuration dereference
 * occurs on the zero path. This is a fixed-point approximation, not libm log.
 */
int medius_motion_lookup_log_magnitude(const volatile MediusMotionDecodedConfiguration *configuration,
    unsigned int unused_word,unsigned int magnitude_low,unsigned int magnitude_high)
{
    (void)unused_word;
    unsigned long long magnitude = ((unsigned long long)magnitude_high << 32) | magnitude_low;
    if (magnitude == 0) return -262144;
    unsigned int exponent = magnitude_high != 0 ? 63U-__builtin_clz(magnitude_high) : 31U-__builtin_clz(magnitude_low);
    unsigned int normalized = exponent < 24U ? magnitude_low << (24U-exponent) :
        (unsigned int)(magnitude >> (exponent-24U));
    unsigned int remainder = normalized - 0x01000000U;
    unsigned int interval = remainder >> 16;
    const volatile short *table = configuration->log_mantissa_q14;
    int value;
    if (interval > 255U) value = table[256];
    else {
        int upper = table[interval+1U];
        int lower = table[interval];
        long long difference = (long long)(upper-lower)*(remainder & 0xffffU);
        value = lower + motion_feature_round_q16(difference);
    }
    return ((int)exponent-20)*11357 + value;
}

/* Native entry: 0x403790dc. */
/* Original function-byte SHA-256:
 * f37dcb89a1acd5a15af787ea8b3ecdf73578a4a7a7598368ee7e867a62092ee4. */
/* Validate core, its configuration pointer, input and phase in that order.
 * NULL core/configuration/input returns-1; phase other than1 returns-5, with
 * no copy/update. Otherwise memcpy exactly40 input bytes into the embedded
 * latest_features cache at+0x7d4, call core_update_features(core,&cache), then
 * return0 regardless of the callee's return register. This wrapper supplies
 * no inference algorithm, count advancement, overlap repair, lock or rollback.
 * Input must expose all20 halfwords, including any caller-reserved values.
 */
int medius_motion_core_submit_features(MediusMotionCoreState *core,const MediusMotionFeatureFrame *features)
{
    if (core == NULL) return -1;
    volatile MediusMotionCoreState *state = core;
    if (state->configuration == NULL) return -1;
    if (features == NULL) return -1;
    if (state->phase != 1U) return -5;
    memcpy(&core->latest_features,features,40);
    medius_motion_core_update_features(core,&core->latest_features);
    return 0;
}

/* Native entry: 0x4037b0ac. */
/* Original function-byte SHA-256:
 * 3521f4b2a18542aa43033cac651e7cb8c95ad8c1be87790976c5b9f44de9ae83. */
/* Zero clear_length bytes at high_bytes, then at biased_low_bytes, even when
 * count<=0. For positive signed count, write that many bytes to each output:
 * high is the signed16 sample's high byte; low is (raw low byte-128) modulo256.
 * Read input twice per sample, with the high-byte store BETWEEN the reads;
 * overlapping input/output therefore retains this native access dependence.
 * Output overlap also preserves high-then-low stores and both initial memsets.
 * count is NOT capped by clear_length. Caller supplies valid aligned input,
 * count readable halfwords and adequate output buffers; no validation, lock,
 * sign extension into larger output elements or allocation occurs here.
 */
void medius_motion_split_feature_bytes(const volatile unsigned short *input,int count,
    unsigned int clear_length,volatile unsigned char *high_bytes,volatile unsigned char *biased_low_bytes)
{
    memset((void *)high_bytes,0,clear_length);
    memset((void *)biased_low_bytes,0,clear_length);
    if (count <= 0) return;
    for (unsigned int i = 0;i < (unsigned int)count;++i) {
        unsigned int first = input[i];
        high_bytes[i] = (unsigned char)(first >> 8);
        unsigned int second = input[i];
        biased_low_bytes[i] = (unsigned char)(second - 128U);
    }
}

/* Native entry: 0x4200c6fc. */
/* Original function-byte SHA-256:
 * fc7a65a403c0a3f1b8d0210afbcfc1fe49077acbdda44800ba06e90095c8bb8b. */
/* Read a little-endian IEEE binary16 from two bytes, HIGH byte before LOW,
 * and return the corresponding binary32 bit pattern in the normal float ABI.
 * No pointer check or alignment requirement beyond readable bytes. Preserve
 * sign, signed zero, infinity and every NaN payload/signaling bit; no floating
 * arithmetic or forced quieting. Normalize subnormal mantissas by shifting
 * until bit10 is set and decrementing the exponent. All binary16 finite values
 * are exactly representable in binary32. The native final4-byte stack memcpy
 * is represented by a union bit view, not an arithmetic float conversion.
 */
float medius_motion_half_to_float(const void *little_endian_half)
{
    const volatile unsigned char *bytes = little_endian_half;
    unsigned int high = bytes[1];
    unsigned int low = bytes[0];
    unsigned int half = (high << 8) | low;
    unsigned int sign = (half & 0x8000U) << 16;
    unsigned int exponent = (half >> 10) & 31U;
    unsigned int fraction = half & 0x3ffU;
    unsigned int bits = sign;
    if (exponent == 0) {
        if (fraction != 0) {
            int power = -14;
            do {fraction <<= 1;--power;} while ((fraction & 0x400U) == 0);
            bits |= ((unsigned int)(power + 127) << 23) | ((fraction & 0x3ffU) << 13);
        }
    } else {
        bits |= fraction << 13;
        bits |= exponent == 31U ? 0x7f800000U : (exponent + 112U) << 23;
    }
    union {unsigned int bits;float value;} representation = {.bits = bits};
    return representation.value;
}

/* Native entry: 0x4200e2e0. */
/* Original function-byte SHA-256:
 * 5817c36d9cc14b2a3c2681c010ac69d9ed863b44f7428a198f9b46f47400a9e9. */
/* Install a completed256-sample summary into a phase1 core. NULL core,
 * configuration or summary returns-1. Wrong phase/sample count, activity_count
 *>60 or activity_cursor>59 returns-5 before mutation (checks occur in that
 * order, count before cursor). Caller supplies a readable97-byte prefix with
 * aligned native halfwords; bytes22/23 are ignored. No length field exists.
 *
 * Copy10 statistics bytes, three4-byte parameter blocks and the8-byte Q16
 * vector in order; copy activity weight as16 bits, mode as8 bits, then60 flag
 * bytes. Reload count then cursor and publish their packed little-endian16
 * indices. Read vector Y before X, normalize into direction/magnitude and set
 * direction X=32767 only if both resulting components are0. Finally memset
 * the two residual WORDs to0 and return0. Other state is retained. Copies use
 * memcpy, with no overlap repair, second validation, rollback or serialization;
 * an aliased summary can be changed by earlier writes before its later reads.
 */
int medius_motion_core_apply_summary(MediusMotionCoreState *core,const MediusMotionCoreSummary *summary)
{
    if (core == NULL) return -1;
    volatile MediusMotionCoreState *state = core;
    if (state->configuration == NULL) return -1;
    if (summary == NULL) return -1;
    if (state->phase != 1U) return -5;
    if (state->samples != 256U) return -5;
    const volatile MediusMotionCoreSummary *input = summary;
    if (input->activity_count > 60U) return -5;
    if (input->activity_cursor > 59U) return -5;
    memcpy(core->summary_statistics,summary->statistics,10);
    memcpy(&core->summary_parameters[0],summary->parameters_le[0],4);
    memcpy(&core->summary_parameters[1],summary->parameters_le[1],4);
    memcpy(&core->summary_parameters[2],summary->parameters_le[2],4);
    memcpy(core->summary_vector_q16,summary->vector_q16_le,8);
    state->summary_activity_weight = input->activity_weight;
    state->summary_activity_mode = input->activity_mode;
    memcpy(core->summary_activity_flags,summary->activity_flags,60);
    unsigned int count = input->activity_count;
    unsigned int cursor = input->activity_cursor;
    state->summary_activity_indices = (unsigned short)((count << 8) | cursor);
    int vector_y = state->summary_vector_q16[1];
    int vector_x = state->summary_vector_q16[0];
    medius_motion_normalize_vector_q15(vector_x,vector_y,&state->direction,&state->summary_vector_magnitude);
    if (state->direction.x == 0 && state->direction.y == 0) state->initial_halfword = 32767;
    memset(core->residual,0,8);
    return 0;
}
