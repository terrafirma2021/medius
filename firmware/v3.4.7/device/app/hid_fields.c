/* Device signed packed-field motion application. */

#include "../include/types.h"

/* Native entry: 0x4038c298. */
/* Original function-byte SHA-256:
 * a84746c1271326f8d9fa32e4f4bb6eb972bc7d42a0888cf3e812b8017442556c. */
/* Apply a requested signed delta to one packed report field and subtract the
 * amount applied from *remaining modulo 32 bits. A zero residual returns
 * immediately; a disabled field clears it; delta 0 leaves it alone. Requested
 * delta is independent of residual magnitude and is not capped to that magnitude.
 *
 * field is the native12-byte BY-VALUE descriptor (A4/A5/A6),remaining is A7,
 * delta is stack word0. Read bits with16-bit address wrap andmodulo32 shifts,
 * stopping on a missing byte; sign-extend widths1..31. Use valid configured
 * min/max,otherwise intrinsic signed width bounds orfull signed32 for width0
 * and widths>=32. Positive deltas consume at most positive room to maximum;
 * negative deltas consume at most negative room to minimum. An already
 * out-of-range value is not pulled back when the request points farther out.
 *
 * Store residual BEFORE repainting report bits. A no-room path writes the old
 * residual andstill repaints. On that path,width0 UNDERFLOWS the write count:
 * continue until a byte-bound failure or2^32 bit iterations. Favorable-room
 * width0 instead updates residual andreturns without repainting. This native
 * distinction is retained. Writes reread each affected byte,preserving otherbits;
 * aliased residual/report storage can therefore affect those fresh byte reads.
 * No local lock, fence or allocation; returns no value.
 *
 * report: writable length-byte span, sampled and repainted one bit at a time.
 * length: full unsigned 32-bit byte availability, without entry truncation.
 * field: descriptor copied by value; packed offset/width/enabled and signed bounds.
 * remaining: writable signed 32-bit accumulator; native subtraction wraps.
 * delta: signed 32-bit requested change, passed as the first stack argument.
 */
void hid_apply_numeric_delta(unsigned char *report,unsigned int length,
    ReportNumericField field,int *remaining,int delta)
{
    volatile int *residual = remaining;
    unsigned int old_remaining = (unsigned int)*residual;
    if (old_remaining == 0)
        return;
    if (field.enabled == 0) {
        *residual = 0;
        return;
    }
    if (delta == 0)
        return;
    unsigned int width = field.width,bit_offset = field.bit_offset;
    unsigned int raw_value_bits = hid_read_bits(report,length,bit_offset,width);
    int current_value = hid_sign_extend(raw_value_bits,width);
    int minimum = field.minimum,maximum = field.maximum;
    if (minimum >= maximum) {
        if (width < 32) {
            unsigned int sign = 1U << ((width - 1U) & 31U);
            minimum = (int)(0U - sign);
            maximum = (int)(sign - 1U);
        } else {
            minimum = (int)0x80000000U;
            maximum = 0x7fffffff;
        }
    }
    long long room = (long long)(delta > 0 ? maximum : minimum) - current_value;
    unsigned int no_room = delta > 0 ? room <= 0 : room >= 0;
    long long applied_delta = 0;
    if (no_room == 0) {
        applied_delta = delta;
        if (delta > 0 && room < applied_delta)
            applied_delta = room;
        if (delta < 0 && room > applied_delta)
            applied_delta = room;
    }
    *residual = (int)(old_remaining - (unsigned int)applied_delta);
    unsigned int updated_value = (unsigned int)current_value + (unsigned int)applied_delta;
    if (no_room == 0 && width == 0)
        return;
    volatile unsigned char *bytes = report;
    unsigned int bits_left = width,bit_index = 0;
    do {
        unsigned int bit = (bit_offset + bit_index) & 65535U;
        unsigned int byte = bit >> 3;
        if (byte >= length)
            return;
        unsigned int mask = 1U << (bit & 7U);
        unsigned int original = bytes[byte];
        bytes[byte] = (unsigned char)((updated_value & (1U << (bit_index & 31U))) != 0 ?
            original | mask : original ^ (original & mask));
        ++bit_index;
    } while (--bits_left != 0);
}
