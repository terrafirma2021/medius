/* Medius v3.4.7 host — app/motion_decoder.c.
 */

#include "../include/types.h"

/* Source reconstruction utilities; not additional native firmware entries. */
static int motion_decoder_round(float value, unsigned int fractional_bits)
{
    int result;
    if (fractional_bits == 8)
        __asm__ volatile("round.s %0, %1, 8" : "=a"(result) : "f"(value));
    else
        __asm__ volatile("round.s %0, %1, 0" : "=a"(result) : "f"(value));
    return result;
}

static int motion_decoder_trunc(float value)
{
    int result;
    __asm__ volatile("trunc.s %0, %1, 0" : "=a"(result) : "f"(value));
    return result;
}

static float motion_decoder_float(unsigned int bits)
{
    union { unsigned int bits; float value; } representation = { .bits = bits };
    return representation.value;
}

static unsigned int motion_decoder_u16(const unsigned char *bytes)
{
    const volatile unsigned char *p = bytes;
    unsigned int high = p[1], low = p[0];
    return low | (high << 8);
}

static unsigned int motion_decoder_u32(const unsigned char *bytes)
{
    const volatile unsigned char *p = bytes;
    unsigned int second = p[1], first = p[0], third = p[2], fourth = p[3];
    return first | (second << 8) | (third << 16) | (fourth << 24);
}

/* Native entry: 0x4200d570. */
/*
 * Medius v3.4.7 — host application; 0x4200d570.
 * Instruction-checked recovered C.
 * Original function-byte SHA-256:
 * 8e9882b9a686c6cd10f5b5a4e6e8b078fbafeea224fa01701abb644e01f21c4f.
 */

/*
 * Validate and decode the fixed 39,512-byte ABCFIX1-NUL base motion image.
 * First check hardware ROUND.S against fixed scaled results and the software
 * rounding routine; this runs even for NULL arguments. A rounding mismatch
 * returns -2 without clearing output. Next NULL output/image returns -1;
 * otherwise clear all 108 output bytes before checking length or contents.
 * Header/layout/reserved-byte failures return -2, either fixed identity block
 * mismatch returns -4, and the stored/payload CRC mismatch returns -3. The
 * payload is image[256..39511], reflected CRC32 0x6be2896c. Failure after the
 * clear leaves the output zero and does not copy tables into global caches.
 *
 * On success publish borrowed image/table pointers and reread the eleven
 * header parameters, then populate six shared caches. The native aligned
 * path copies 128 groups and separate final elements; the fallback copies
 * 257 groups using byte reads. Preserve its exact 32-bit overlap predicate,
 * high-before-low word accesses and interleaved final-element reads. Publish
 * the six cache pointers last, then return 0. No allocation, ownership
 * transfer, input/output overlap rejection, lock or MEMW occurs. Later calls
 * overwrite the same caches; the borrowed image must remain readable.
 * Parameter names identify serialized offsets where downstream meaning has
 * not yet been established; this function only validates and transfers them.
 */
int medius_motion_decode_base(MediusMotionDecodedConfiguration *decoded,
    const unsigned char *image, unsigned int length)
{
    const unsigned int half_values[6] = {
        0x3f000000U, 0x3fc00000U, 0x40200000U,
        0xbf000000U, 0xbfc00000U, 0xc0200000U
    };
    const int scaled_results[6] = {128, 384, 640, -128, -384, -640};
    int first_rounded = 0;
    volatile float rounding_result;
    for (unsigned int i = 0; i < 6; ++i) {
        float value = motion_decoder_float(half_values[i]);
        if (motion_decoder_round(value, 8) != scaled_results[i]) return -2;
        int hardware = motion_decoder_round(value, 0);
        float software = medius_math_rintf(value);
        int converted = motion_decoder_trunc(software);
        rounding_result = software;
        if (converted != hardware) return -2;
        if (i == 0) first_rounded = converted;
    }
    float small = motion_decoder_float(0x3b000000U);
    if (motion_decoder_round(small, 8) != first_rounded) return -2;
    int hardware = motion_decoder_round(small, 0);
    float software = medius_math_rintf(small);
    int converted = motion_decoder_trunc(software);
    rounding_result = software;
    if (converted != hardware) return -2;
    const unsigned int other_values[2][2] = {
        {0x406ccccdU, 0x446ccccdU}, {0xc06ccccdU, 0xc46ccccdU}
    };
    for (unsigned int i = 0; i < 2; ++i) {
        float value = motion_decoder_float(other_values[i][0]);
        hardware = motion_decoder_round(value, 8);
        software = medius_math_rintf(motion_decoder_float(other_values[i][1]));
        converted = motion_decoder_trunc(software);
        rounding_result = software;
        if (converted != hardware) return -2;
        hardware = motion_decoder_round(value, 0);
        software = medius_math_rintf(value);
        converted = motion_decoder_trunc(software);
        rounding_result = software;
        if (converted != hardware) return -2;
    }
    (void)sizeof(rounding_result);
    if (!decoded || !image) return -1;
    memset(decoded, 0, 108);
    if (length != 39512) return -2;
    if (memcmp(image, "ABCFIX1", 8)) return -2;

    if (motion_decoder_u16(image + 0x08) != 1) return -2;
    if (motion_decoder_u16(image + 0x0a) != 256) return -2;
    if (motion_decoder_u16(image + 0x0c) != 80) return -2;
    if (motion_decoder_u16(image + 0x0e) != 20) return -2;
    if (motion_decoder_u16(image + 0x10) != 5) return -2;
    if (motion_decoder_u16(image + 0x12) != 2) return -2;
    if (motion_decoder_u32(image + 0x14) != 15) return -2;
    if (motion_decoder_u32(image + 0x18) != 39512) return -2;
    if (motion_decoder_u32(image + 0x20) != 33760) return -2;
    if (motion_decoder_u32(image + 0x1c) != 256) return -2;
    if (motion_decoder_u32(image + 0x28) != 2408) return -2;
    if (motion_decoder_u32(image + 0x24) != 34016) return -2;
    if (motion_decoder_u32(image + 0x30) != 512) return -2;
    if (motion_decoder_u32(image + 0x2c) != 36424) return -2;
    if (motion_decoder_u32(image + 0x38) != 514) return -2;
    if (motion_decoder_u32(image + 0x34) != 36936) return -2;
    if (motion_decoder_u32(image + 0x40) != 514) return -2;
    if (motion_decoder_u32(image + 0x3c) != 37452) return -2;
    if (motion_decoder_u32(image + 0x48) != 1028) return -2;
    if (motion_decoder_u32(image + 0x44) != 37968) return -2;
    if (motion_decoder_u32(image + 0x4c) != 38996) return -2;
    if (motion_decoder_u32(image + 0x50) != 514) return -2;
    static const unsigned char format_tag[8] = {8,15,14,16,15,20,14,15};
    if (memcmp(image + 0x58, format_tag, 8)) return -2;
    if (motion_decoder_u32(image + 0x60) != 4800) return -2;
    unsigned int shared_count = motion_decoder_u32(image + 0x70);
    if (shared_count != 240) return -2;
    if (motion_decoder_u16(image + 0x80) != 3) return -2;
    if (motion_decoder_u32(image + 0x64) != 19200) return -2;
    if (motion_decoder_u32(image + 0x74) != shared_count) return -2;
    if (motion_decoder_u16(image + 0x82) != 3) return -2;
    if (motion_decoder_u32(image + 0x68) != 80) return -2;
    if (motion_decoder_u32(image + 0x78) != 1) return -2;
    if (motion_decoder_u16(image + 0x84) != 1) return -2;
    if (motion_decoder_u32(image + 0x6c) != 9680) return -2;
    unsigned int final_count = motion_decoder_u32(image + 0x7c);
    if (final_count != 121) return -2;
    if (motion_decoder_u16(image + 0x86) != final_count) return -2;
    if (motion_decoder_u32(image + 0x88) != 24576) return -2;
    if (motion_decoder_u32(image + 0x8c) != 50412) return -2;
    if (motion_decoder_u32(image + 0x90) != 87381) return -2;
    if (motion_decoder_u32(image + 0x94) != 436907) return -2;
    unsigned int shared_parameter = motion_decoder_u32(image + 0x98);
    if (shared_parameter != 32768) return -2;
    if (motion_decoder_u32(image + 0x9c) != 2097152) return -2;
    if (motion_decoder_u32(image + 0xa0) != 32767) return -2;
    if (motion_decoder_u32(image + 0xa4) != 0) return -2;
    unsigned int repeated_parameter = motion_decoder_u32(image + 0xa8);
    if (repeated_parameter != shared_parameter) return -2;
    if (motion_decoder_u32(image + 0xac) != 98304) return -2;
    if (motion_decoder_u32(image + 0xb0) != repeated_parameter) return -2;
    static const unsigned char identity_a[32] = {
        0xe9,0x95,0x1a,0x9b,0xc2,0x5b,0x69,0xbf,0x65,0x2c,0xeb,0xbc,0xa8,0x74,0x9b,0xad,
        0xd0,0x2b,0x8c,0x06,0x75,0xa5,0xf1,0xad,0x4c,0xde,0x7f,0x1a,0x86,0x24,0x13,0x2a
    };
    static const unsigned char identity_b[16] = {
        0x34,0x85,0xfc,0x08,0xbf,0xb9,0xfb,0xc7,0xee,0x7f,0x30,0x73,0x4e,0x9f,0xd0,0xa4
    };
    if (memcmp(image + 0xb4, identity_a, 32)) return -4;
    if (memcmp(image + 0xd4, identity_b, 16)) return -4;
    const volatile unsigned char *bytes = image;
    for (unsigned int i = 0xe4; i < 256; ++i)
        if (bytes[i]) return -2;
    if (motion_decoder_u32(image + 0x54) != 1810008428U) return -3;
    unsigned int crc = 0xffffffffU;
    for (unsigned int i = 256; i < 39512; ++i) {
        crc ^= bytes[i];
        for (unsigned int bit = 0; bit < 8; ++bit)
            crc = (crc >> 1) ^ ((0U - (crc & 1U)) & 0xedb88320U);
    }
    if (crc != 2484958867U) return -3;

    const unsigned char *table_a = image + 36936, *table_b = image + 37452;
    const unsigned char *table_c = image + 37968, *table_d = image + 38996;
    volatile MediusMotionDecodedConfiguration *out = decoded;
    out->image = image;
    out->length = 39512;
    out->payload = image + 256;
    out->serialized_words_602 = image + 34016;
    out->serialized_words_128 = image + 36424;
    out->serialized_halfwords_a = table_a;
    out->serialized_halfwords_b = table_b;
    out->serialized_words_257 = table_c;
    out->serialized_halfwords_d = table_d;
    for (unsigned int i = 0; i < 6; ++i)
        out->parameters_88_to_9c[i] = motion_decoder_u32(image + 0x88 + 4 * i);
    out->maximum_step = motion_decoder_u32(image + 0xa0);
    for (unsigned int i = 0; i < 4; ++i)
        out->parameters_a4_to_b0[i] = motion_decoder_u32(image + 0xa4 + 4 * i);
    out->payload_crc32 = 1810008428U;

    volatile unsigned int *cache_602 = (volatile unsigned int *)0x3fcc0360U;
    volatile unsigned int *cache_128 = (volatile unsigned int *)0x3fcc0160U;
    volatile unsigned short *cache_a = (volatile unsigned short *)0x3fcbff5cU;
    volatile unsigned short *cache_b = (volatile unsigned short *)0x3fcbfd58U;
    volatile unsigned int *cache_c = (volatile unsigned int *)0x3fcbf954U;
    volatile unsigned short *cache_d = (volatile unsigned short *)0x3fcbf750U;
    for (unsigned int i = 0; i < 602; ++i)
        cache_602[i] = motion_decoder_u32(image + 34016 + 4 * i);
    for (unsigned int i = 0; i < 128; ++i)
        cache_128[i] = motion_decoder_u32(image + 36424 + 4 * i);

    unsigned int base = (unsigned int)image;
    unsigned int a = (unsigned int)table_a, b = (unsigned int)table_b;
    unsigned int c = (unsigned int)table_c, d = (unsigned int)table_d;
    unsigned int ca = (unsigned int)cache_a, cb = (unsigned int)cache_b;
    unsigned int cc = (unsigned int)cache_c, cd = (unsigned int)cache_d;
    bool aligned_copy =
        (unsigned int)(cd - (base + 36938U) + 1U) > 2062U &&
        (unsigned int)(cc - (base + 37972U) + 3U) > 6U &&
        (ca + 4U <= a || base + 39000U <= ca) &&
        (d <= ca || ca + 514U <= c) &&
        (cb + 4U <= a || base + 39000U <= cb) &&
        (cb + 514U <= c || d <= cb) &&
        (base + 39510U <= cc || cc + 1028U <= a) &&
        (d <= cd || cd + 514U <= c) && ((a | b | c | d) & 3U) == 0;
    if (aligned_copy) {
        volatile unsigned int *word_a = (volatile unsigned int *)cache_a;
        volatile unsigned int *word_b = (volatile unsigned int *)cache_b;
        volatile unsigned int *word_d = (volatile unsigned int *)cache_d;
        const volatile unsigned int *source_a = (const volatile unsigned int *)table_a;
        const volatile unsigned int *source_c = (const volatile unsigned int *)table_c;
        const volatile unsigned int *source_d = (const volatile unsigned int *)table_d;
        for (unsigned int i = 0; i < 128; ++i) {
            word_a[i] = source_a[i];
            word_b[i] = source_a[i + 129];
            unsigned int high = source_c[2 * i + 1], low = source_c[2 * i];
            cache_c[2 * i + 1] = high;
            cache_c[2 * i] = low;
            word_d[i] = source_d[i];
        }
        unsigned int c_second = bytes[38993], c_first = bytes[38992];
        unsigned int c_third = bytes[38994], a_high = bytes[37449];
        unsigned int c_fourth = bytes[38995], a_low = bytes[37448];
        unsigned int b_high = bytes[37965], d_high = bytes[39509];
        unsigned int b_low = bytes[37964], d_low = bytes[39508];
        cache_a[256] = a_low | (a_high << 8);
        cache_b[256] = b_low | (b_high << 8);
        cache_c[256] = c_first | (c_second << 8) | (c_third << 16) | (c_fourth << 24);
        cache_d[256] = d_low | (d_high << 8);
    } else {
        for (unsigned int i = 0; i < 257; ++i) {
            cache_a[i] = motion_decoder_u16(table_a + 2 * i);
            cache_b[i] = motion_decoder_u16(table_b + 2 * i);
            cache_c[i] = motion_decoder_u32(table_c + 4 * i);
            cache_d[i] = motion_decoder_u16(table_d + 2 * i);
        }
    }
    out->cached_words_602 = cache_602;
    out->cached_words_128 = cache_128;
    out->cached_halfwords_a = cache_a;
    out->cached_halfwords_b = cache_b;
    out->cached_words_257 = cache_c;
    out->cached_halfwords_d = cache_d;
    return 0;
}
