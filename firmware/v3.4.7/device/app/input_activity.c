/* Device input activity, dirty state and report-bit clearing. */

#include "../include/types.h"

/* Native entry: 0x4038c838. */
/* Original function-byte SHA-256:
 * bb992f98ff67e9014045f693a1b9d1fa3d849776f68f613cc54283674cf0c120. */

/*
 * state: writable input-state view through byte +0x2f4; not NULL-checked.
 * Fences and writes dirty=1. Returns no value. No allocation, ownership change,
 * free, notification or local lock occurs; caller supplies synchronization.
 */
void input_mark_dirty(InputStateView *state)
{
    memw();
    ((volatile InputStateView *)state)->dirty = 1;
}

/* Native entry: 0x4038caa0. */
/* Original function-byte SHA-256:
 * 8bb59dea636e137a84654f70c13e7848372169bfcc578942343754b97b2cdbec. */

/*
 * state: readable view through byte +0xb8; not NULL-checked.
 * Returns 1 at the first nonzero word at +4,+8,+12,+16; otherwise returns
 * primary_active != 0. Ordered, independent reads; no fences, writes or lock.
 * The word names describe this primary activity test, not decoded HID usages.
 */
int input_has_primary_activity(const InputStateView *state)
{
    const volatile InputStateView *input_state = state;
    for (unsigned int word = 0; word < 4; ++word)
        if (input_state->primary_words[word] != 0)
            return 1;
    return input_state->primary_active != 0;
}

/* Native entry: 0x4038cac0. */
/* Original function-byte SHA-256:
 * 9114898a4f262b14c71de6a8d41e63076e51d781c7f29a56eade3718459118c5. */

/*
 * state: readable view through word +0x20; not NULL-checked.
 * Returns 1 at the first nonzero word at +0x14,+0x18,+0x1c,+0x20, else 0.
 * Reads in that order without fences, mutation or a local lock.
 */
int input_has_secondary_activity(const InputStateView *state)
{
    const volatile InputStateView *input_state = state;
    for (unsigned int word = 0; word < 4; ++word)
        if (input_state->secondary_words[word] != 0)
            return 1;
    return 0;
}

/* Native entry: 0x4039a0e4. */
/* Original function-byte SHA-256:
 * 562c3450db49d3e18d6f0779db1dc933153e863a3a9edc76bfc0805b7d5f561c. */

/*
 * layout: readable bit-clear layout and all described 12-byte field records.
 * report: writable byte span; length: byte bound used before every byte access.
 * Returns no value. Clears each field's bits, preserving all other report bits.
 * Reads width before bit_offset. Bit positions and end wrap at 16 bits; the
 * field index wraps at 8 bits. On a byte index >= length, stop that field.
 * Reload count after every nonempty field, including a bound break; retain
 * the previous count after a zero-width field. No fences/lock or count repair.
 */
void report_clear_layout_bits(const BitClearLayout *layout,
    unsigned char *report,unsigned int length)
{
    const volatile BitClearLayout *clear_layout = layout;
    unsigned int count = clear_layout->count;
    if (count == 0)
        return;
    unsigned int index = 0;
    do {
        unsigned int width = clear_layout->fields[index].width;
        unsigned int bit = clear_layout->fields[index].bit_offset;
        if (width != 0) {
            unsigned int end = (bit + width) & 65535U;
            do {
                unsigned int byte = bit >> 3;
                unsigned int mask = 1U << (bit & 7U);
                bit = (bit + 1U) & 65535U;
                if (byte >= length)
                    break;
                unsigned int original = ((volatile unsigned char *)report)[byte];
                ((volatile unsigned char *)report)[byte] = original ^ (original & mask);
            } while (bit != end);
            count = clear_layout->count;
        }
        index = (index + 1U) & 255U;
    } while (index < count);
}

/* Native entry: 0x4202a770. */
/* Original function-byte SHA-256:
 * db3cf232112d138912362ab746bc985921234b22f2568c4e8b19f1f414948f81. */
/*
 * Update primary input activity anchors using supplied64-bit time (a2/a3).
 * MEMW/read riding window: if zero, or primary activity reader returns0, clear
 * idle anchor LOW/HIGH with separate fences. Otherwise MEMW/read both anchor
 * WORDs and set them, with separate fences, only when BOTH were zero.
 * Always query secondary activity. If nonzero, or a newly sampled zero window
 * plus primary activity, stamp extension-event LOW/HIGH and return1. Otherwise
 * sample window AGAIN: zero still stamps extension-event, nonzero retains it;
 * return the RAW primary-state changed BYTE. Independent samples can differ.
 * No clock read, locking, expiry calculation, atomic64-bit access or monotonic
 * guarantee; timestamp0 is accepted. Input state and anchors are global.
 */
unsigned char primary_input_refresh_activity_time(unsigned long long now_us)
{
    InputStateView *state = (InputStateView *)&FIXED_INPUTS[0].state;
    unsigned int low = (unsigned int)now_us,high = (unsigned int)(now_us >> 32);
    memw();
    if (MOVEMENT_RIDING_US == 0 || input_has_primary_activity(state) == 0) {
        memw(); FIXED_INPUTS[0].idle_motion_anchor.low = 0;
        memw(); FIXED_INPUTS[0].idle_motion_anchor.high = 0;
    } else {
        memw(); unsigned int anchor_low = FIXED_INPUTS[0].idle_motion_anchor.low;
        memw(); unsigned int anchor_high = FIXED_INPUTS[0].idle_motion_anchor.high;
        if ((anchor_low | anchor_high) == 0) {
            memw(); FIXED_INPUTS[0].idle_motion_anchor.low = low;
            memw(); FIXED_INPUTS[0].idle_motion_anchor.high = high;
        }
    }
    if (input_has_secondary_activity(state) != 0) goto active;
    memw();
    if (MOVEMENT_RIDING_US == 0 && input_has_primary_activity(state) != 0)
        goto active;
    memw();
    if (MOVEMENT_RIDING_US == 0) {
        memw(); FIXED_INPUTS[0].extension_event_time.low = low;
        memw(); FIXED_INPUTS[0].extension_event_time.high = high;
    }
    return FIXED_INPUTS[0].state.changed;
active:
    memw(); FIXED_INPUTS[0].extension_event_time.low = low;
    memw(); FIXED_INPUTS[0].extension_event_time.high = high;
    return 1;
}
