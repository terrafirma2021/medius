/* Device input-report boundary helpers and transition state. */

#include <stddef.h>
#include "../include/types.h"

/* Native entry: 0x4038cd8c. */
/* Original function-byte SHA-256:
 * 97c47e29d9d0466d8647e0eef9b5131c1209b266b082d540c64819cb2f89697e. */
/* Read pending motion for low-byte axis 0..3; invalid axes return 0 without
 * state access. Start with signed32 secondary motion. If LOW8(include_primary)
 * is nonzero, add primary motion; for X/Y also add the selected timed-history
 * sum. History count is sampled once and unchecked. Each declared 16-byte
 * sample reads signed16 X then Y, even when only one sum is selected.
 * Return the signed64 total clamped to [-2147483647,2147483647], deliberately
 * excluding INT_MIN. No state mutation, local lock or memory fence. */
int input_read_pending_axis(const InputStateView *state,
    unsigned int axis,unsigned int include_primary)
{
    axis &= 255U;
    if (axis >= 4)
        return 0;
    const volatile InputStateView *input_state = state;
    long long total = (int)input_state->secondary_words[axis];
    if ((include_primary & 255U) != 0) {
        total += (int)input_state->primary_words[axis];
        if (axis < 2) {
            unsigned int count = input_state->motion_history_count;
            int sum_x = 0,sum_y = 0;
            for (unsigned int index = 0; index < count; ++index) {
                const volatile InputMotionSample *sample = (const volatile void *)
                    ((const unsigned char *)state + 0x38U + index * 16U);
                int x = sample->x;
                int y = sample->y;
                sum_x += x;
                sum_y += y;
            }
            total += axis == 0 ? sum_x : sum_y;
        }
    }
    if (total < -2147483647LL)
        total = -2147483647LL;
    if (total > 2147483647LL)
        total = 2147483647LL;
    return (int)total;
}

/* Native entry: 0x4038f37c. */
/* Original function-byte SHA-256:
 * 6956ede94557cf54f20d005d98c646f49af41cc83733556c138629521320ddf0. */
/* Transform a key transition and publish its resulting state bit. Sample the
 * old state byte first, then rising-suppression bitmap. An unset bit falls back to global flag
 * bit0 via a BYTE read. Next read falling-retention bitmap; an unset bit falls back to global
 * flag bit1 via a HALFWORD read at +0x29e, including its padding byte.
 *
 * For boolean pressed, suppression blocks rising edges and retention holds falling edges.
 * The full pressed word is not normalized first: with old state 0, an odd word
 * takes the rising-edge rule; other nonzero words normally yield 1. With old
 * state 1, the release-retention test uses (pressed^1)&old&retain_falling, then pressed!=0.
 * Always write the cached state byte with the selected bit replaced, and return
 * that bit (0/1), even when unchanged. Other bits use the original byte snapshot.
 * Usage is NOT narrowed or bounds-checked: callers supply valid bitmap spans
 * for usage>>3 (normally usage 0..255). No local lock, dirty update or MEMW. */
unsigned int input_filter_key_transition(InputStateView *state,
    unsigned int usage,unsigned int pressed)
{
    volatile unsigned char *state_bytes = (volatile unsigned char *)state;
    unsigned int byte_index = usage >> 3,bit_index = usage & 7U,mask = 1U << bit_index;
    volatile unsigned char *state_byte = state_bytes + offsetof(InputStateView,key_transition_state) + byte_index;
    unsigned int previous_state_byte = *state_byte;
    unsigned int suppress_rising = state_bytes[offsetof(InputStateView,key_rising_suppression) + byte_index];
    unsigned int previous_pressed = (previous_state_byte >> bit_index) & 1U;
    suppress_rising = (suppress_rising >> bit_index) & 1U;
    if (suppress_rising == 0)
        suppress_rising = state_bytes[offsetof(InputStateView,keyboard_transform_flags)] & 1U;
    unsigned int retain_falling = (state_bytes[offsetof(InputStateView,key_falling_retention) + byte_index] >> bit_index) & 1U;
    if (retain_falling == 0)
        retain_falling = (*(volatile unsigned short *)(state_bytes + offsetof(InputStateView,keyboard_transform_flags)) >> 1) & 1U;
    unsigned int filtered_pressed;
    if (((previous_pressed ^ 1U) & pressed) != 0) {
        filtered_pressed = suppress_rising == 0;
    } else {
        unsigned int retained = (pressed ^ 1U) & previous_pressed & retain_falling;
        filtered_pressed = retained != 0 || pressed != 0;
    }
    *state_byte = (unsigned char)(filtered_pressed != 0 ? previous_state_byte | mask : previous_state_byte & ~mask);
    return filtered_pressed;
}

/* Native entry: 0x42026a1c. */
/* Original function-byte SHA-256:
 * cf59dbbead23f81a149448a403f685e125344d65add4ae31418c024da4e853b0. */
/* Forward state, input, output, LOW16(length), LOW8(flags), and the supplied
 * 64-bit timestamp to the report rewrite entry, with a NULL axis override.
 * Native A7 is alignment padding, not a logical argument; timestamp LOW/HIGH
 * enter on stack words 0/1 and the NULL override is outgoing stack word 2.
 * No additional validation, lock, allocation, clock read or returned value. */
void input_rewrite_report_timed(InputStateView *state,
    const unsigned char *input,unsigned int length,unsigned char *output,
    unsigned int flags,unsigned long long now_us)
{
    input_rewrite_report_native(state,input,length & 65535U,output,
        flags & 255U,now_us,0);
}

/* Native entry: 0x42026a40. */
/* Original function-byte SHA-256:
 * ccec5651a67a5e3770e5c0734a157a33e5157a46d415e9f249f5c54479a11f20. */
/* Forward state, input, LOW16(length), and output to the report rewrite entry
 * with flags 3, timestamp 0, and no axis override. The three outgoing stack
 * words are all zero. No local state change, validation, clock read or result. */
void input_rewrite_report_defaults(InputStateView *state,
    const unsigned char *input,unsigned int length,unsigned char *output)
{
    input_rewrite_report_native(state,input,length & 65535U,output,3,0,0);
}
