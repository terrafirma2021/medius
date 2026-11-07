/* Device input transforms: motion/button scales, key filters and control queries. */

#include "../include/types.h"

/* Native entry: 0x42026ca4. */
/* Original function-byte SHA-256:
 * 403306b2dc4c66733815fba4974586acceccc5aacdfc8f95189417347906c633. */
/* Set selected scale columns for one channel. Channel/selector use their low
 * bytes; value is signed16. Channels 0..3 are motion axes, 4..19 mouse buttons.
 * Reject values outside -255..255, negative button values, invalid channels or
 * selectors >4. Selector 0 selects all columns; 1..4 select columns 0..3.
 *
 * Motion columns 0/1 receive value. Columns 2/3 receive 100 for selector 0,
 * otherwise value. Each changed motion column clears its negative scale
 * remainder, then its positive remainder. Axes 0/1 also clear bearing Y before
 * X. Button columns 0/1 become 0 below value 100, otherwise 100. Columns 2/3 are only handled
 * by selector 0 and receive 100; selecting either alone does nothing.
 * Return the handled-column mask, including unchanged columns, not a change
 * mask. No local lock, memory fence or dirty/publication update. */
unsigned int input_set_scale_group(InputStateView *state,
    unsigned int channel,unsigned int selector,short value)
{
    channel &= 255U;
    selector &= 255U;
    if (channel >= 20 || value < -255 || value > 255 ||
        (channel >= 4 && value < 0) || selector > 4)
        return 0;
    volatile InputStateView *input = state;
    unsigned int selected = selector == 0 ? 15U : 1U << (selector - 1U);
    unsigned int handled = 0;
    for (unsigned int column = 0; column < 4; ++column) {
        unsigned int bit = 1U << column;
        if ((selected & bit) == 0)
            continue;
        if (channel < 4) {
            short target = column >= 2 && selector == 0 ? 100 : value;
            handled |= bit;
            if ((short)input->primary_scales[channel][column] != target) {
                input->primary_scales[channel][column] = (unsigned short)target;
                input->axis_scale_remainders[channel][1] = 0;
                input->axis_scale_remainders[channel][0] = 0;
                if (channel < 2) {
                    input->bearing_remainder_y = 0;
                    input->bearing_remainder_x = 0;
                }
            }
        } else {
            if (column >= 2 && selector != 0)
                continue;
            short target = column >= 2 || value >= 100 ? 100 : 0;
            handled |= bit;
            if ((short)input->button_scales[channel - 4][column] != target)
                input->button_scales[channel - 4][column] = (unsigned short)target;
        }
    }
    return handled;
}

/* Native entry: 0x42026e1c. */
/* Original function-byte SHA-256:
 * d24d8bcb433ff4fe626f406d18594d4101530ce9624604de1c516088da7b78b5. */
/* Update key-transform bitmaps for low-byte usage 4..255. Accept only modes
 * 0 (both), 1 (rising suppression) and 2 (falling retention), and nonnegative signed16 value. Set the selected
 * bit below value 100; clear it at or above 100. Return whether a selected bit
 * differed. Even an unchanged selected bitmap byte is written.
 * For mode 0, when rising suppression already agrees, sample falling retention
 * before writing rising suppression to determine
 * the result; reread falling retention after that store to update it. Preserve this access
 * order. No runtime-state reset, local lock, fence or publication update. */
unsigned int input_set_key_transform(InputStateView *state,
    unsigned int usage,unsigned int mode,short value)
{
    usage &= 255U;
    mode &= 255U;
    if (usage < 4 || value < 0 || mode > 2)
        return 0;
    volatile InputStateView *input = state;
    unsigned int bitmap_index = usage >> 3,usage_mask = 1U << (usage & 7U);
    unsigned int transform_enabled = value < 100;
    if (mode == 2) {
        unsigned int previous_bits = input->key_falling_retention[bitmap_index];
        unsigned int changed = ((previous_bits & usage_mask) != 0) != transform_enabled;
        input->key_falling_retention[bitmap_index] = (unsigned char)(transform_enabled ? previous_bits | usage_mask : previous_bits & ~usage_mask);
        return changed;
    }
    unsigned int previous_rising_bits = input->key_rising_suppression[bitmap_index];
    unsigned int changed = ((previous_rising_bits & usage_mask) != 0) != transform_enabled;
    if (mode == 0 && changed == 0) {
        unsigned int previous_falling_bits = input->key_falling_retention[bitmap_index];
        changed = ((previous_falling_bits & usage_mask) != 0) != transform_enabled;
    }
    input->key_rising_suppression[bitmap_index] = (unsigned char)(transform_enabled ? previous_rising_bits | usage_mask : previous_rising_bits & ~usage_mask);
    if (mode == 0) {
        unsigned int previous_falling_bits = input->key_falling_retention[bitmap_index];
        input->key_falling_retention[bitmap_index] = (unsigned char)(transform_enabled ? previous_falling_bits | usage_mask : previous_falling_bits & ~usage_mask);
    }
    return changed;
}

/* Native entry: 0x42027004. */
/* Original function-byte SHA-256:
 * ba253868d952fad7df12b6c826115afff09d8f8bab4172d0c4036b4ee82c273c. */
/* Read one signed16 scale, sign-extended to int. Use low-byte channel/column;
 * invalid channel >=20 or column >=4 returns 100 without dereferencing state.
 * Channels 0..3 use motion scales, 4..19 button scales. No lock or fence. */
int input_get_scale(const InputStateView *state,
    unsigned int channel,unsigned int column)
{
    channel &= 255U;
    column &= 255U;
    if (channel >= 20 || column >= 4)
        return 100;
    const volatile InputStateView *input = state;
    return channel < 4 ? (short)input->primary_scales[channel][column] :
        (short)input->button_scales[channel - 4][column];
}

/* Native entry: 0x4202704c. */
/* Original function-byte SHA-256:
 * 529318cda0303587526a3ddaf38d272fb613e4ed6181dd96f7e11f50c729b268. */
/* Set one raw signed16 scale without the group setter's value restrictions,
 * threshold conversion or selector defaults. Low-byte channel/column must be
 * <20/<4. An unchanged value does nothing. Changed motion scales clear their
 * negative then positive remainder; axes 0/1 also clear bearing Y before X.
 * Button changes only write the selected halfword. No lock, fence, dirty flag
 * or result. */
void input_set_scale(InputStateView *state,
    unsigned int channel,unsigned int column,short value)
{
    channel &= 255U;
    column &= 255U;
    if (channel >= 20 || column >= 4)
        return;
    volatile InputStateView *input = state;
    if (channel < 4) {
        if ((short)input->primary_scales[channel][column] == value)
            return;
        input->primary_scales[channel][column] = (unsigned short)value;
        input->axis_scale_remainders[channel][1] = 0;
        input->axis_scale_remainders[channel][0] = 0;
        if (channel < 2) {
            input->bearing_remainder_y = 0;
            input->bearing_remainder_x = 0;
        }
    } else if ((short)input->button_scales[channel - 4][column] != value) {
        input->button_scales[channel - 4][column] = (unsigned short)value;
    }
}

/* Native entry: 0x420270b0. */
/* Original function-byte SHA-256:
 * ba54f312341597281e4218d3689d14e25b35d5be06e58ec22abdb7906025d27d. */
/* Return the raw keyboard-transform flag byte at +0x29e, zero-extended.
 * No boolean normalization, validation, lock or fence. */
unsigned char input_get_keyboard_transform_flags(const InputStateView *state)
{
    return ((const volatile InputStateView *)state)->keyboard_transform_flags;
}

/* Native entry: 0x420270bc. */
/* Original function-byte SHA-256:
 * dbf27edf34fb01728c973fcbd8bc3db926acdb5e8a58015048606795c0fbe5fb. */
/* Return the raw transform-mode byte at +0x2b0, zero-extended. No boolean
 * normalization, validation, lock or fence. */
unsigned char input_get_transform_mode(const InputStateView *state)
{
    return ((const volatile InputStateView *)state)->transform_mode;
}

/* Native entry: 0x420270c8. */
/* Original function-byte SHA-256:
 * 4dce5b52ee43190e71a74b1526373deea877b2ad0ee36377f7cd81de3cb6bf77. */
/* Return 1 if global keyboard-transform flags are nonzero, otherwise if the
 * low-byte usage has rising suppression, otherwise return its falling-retention bit. Short-circuit
 * reads follow that order; usages 0..255 are accepted. No lock or fence. */
unsigned int input_key_is_transformed(const InputStateView *state,
    unsigned int usage)
{
    const volatile InputStateView *input = state;
    if (input->keyboard_transform_flags != 0)
        return 1;
    usage &= 255U;
    unsigned int bitmap_index = usage >> 3,usage_mask = 1U << (usage & 7U);
    if ((input->key_rising_suppression[bitmap_index] & usage_mask) != 0)
        return 1;
    return (input->key_falling_retention[bitmap_index] & usage_mask) != 0;
}

/* Native entry: 0x42027100. */
/* Original function-byte SHA-256:
 * 02d55953e3d74c87073e9a27c7c6574497efcdec06207203ff00322250109035. */
/* Return the raw nonzero transform-mode byte immediately. When mode is zero,
 * search all eight consumer-transform halfwords for low16 usage and return
 * 1 on a match, 0 otherwise. Zero usage can match an empty slot. No lock/fence. */
unsigned char input_consumer_is_transformed(const InputStateView *state,
    unsigned int usage)
{
    const volatile InputStateView *input = state;
    unsigned char mode = input->transform_mode;
    if (mode != 0)
        return mode;
    for (unsigned int slot = 0; slot < 8; ++slot)
        if (input->consumer_transforms[slot] == (unsigned short)usage)
            return 1;
    return 0;
}

/* Native entry: 0x4202712c. */
/* Original function-byte SHA-256:
 * ae40fd70b8e250796adc1d3c1aca79c0266a450693f9bd6685d056884d8b070f. */
/* Enumerate usages 0..255 in ascending order: rising suppression yields kind 1,
 * then falling retention yields
 * kind 2, so one usage can produce two rows. Capacity uses its low byte; zero
 * returns before reading state or outputs. Each row writes usage halfword,
 * then kind byte. Stop immediately if a rising-suppression row fills capacity;
 * otherwise read falling retention after those output writes. Global flags are ignored. Outputs need room for
 * capacity rows; native alias-sensitive read/store order is retained. Return
 * row count <=capacity. No clearing of unused output, local lock or fence. */
unsigned int input_list_key_transforms(const InputStateView *state,
    unsigned short *usages,unsigned char *kinds,unsigned int capacity)
{
    capacity &= 255U;
    if (capacity == 0)
        return 0;
    const volatile InputStateView *input = state;
    volatile unsigned short *usage_out = usages;
    volatile unsigned char *kind_out = kinds;
    unsigned int count = 0;
    for (unsigned int usage = 0; usage < 256; ++usage) {
        unsigned int bitmap_index = usage >> 3,usage_mask = 1U << (usage & 7U);
        if ((input->key_rising_suppression[bitmap_index] & usage_mask) != 0) {
            usage_out[count] = (unsigned short)usage;
            kind_out[count] = 1;
            if (++count >= capacity)
                return count;
        }
        if ((input->key_falling_retention[bitmap_index] & usage_mask) != 0) {
            usage_out[count] = (unsigned short)usage;
            kind_out[count] = 2;
            ++count;
        }
        if (count >= capacity)
            break;
    }
    return count;
}

/* Native entry: 0x42027190. */
/* Original function-byte SHA-256:
 * 5d8f7f02106336fcc2c97fae8207d9da7a9d0f55678270a5c545c2a6b2f64660. */
/* Copy nonzero consumer-transform usages from eight slots in storage order,
 * preserving duplicates. Low-byte capacity zero avoids all pointer accesses.
 * Read each halfword once before its output store, stop at capacity, and return
 * count <=8. Ignore global mode; unused output remains. No lock or fence. */
unsigned int input_list_consumer_transforms(const InputStateView *state,
    unsigned short *usages,unsigned int capacity)
{
    capacity &= 255U;
    if (capacity == 0)
        return 0;
    const volatile InputStateView *input = state;
    volatile unsigned short *usage_out = usages;
    unsigned int count = 0;
    for (unsigned int slot = 0; slot < 8 && count < capacity; ++slot) {
        unsigned short usage = input->consumer_transforms[slot];
        if (usage != 0)
            usage_out[count++] = usage;
    }
    return count;
}

/* Native entry: 0x420271c4. */
/* Original function-byte SHA-256:
 * 24738fbfa519e7da5b889a0f018da0ee28aaae288b54ab00a7a7ed25eb85d9a2. */
/* List set forced-key bits as ascending usage halfwords 0..255. Capacity uses
 * its low byte; zero avoids state/output reads. Read the bitmap byte anew for
 * every usage, then store a matching usage. Stop at capacity and return count;
 * unused output remains. No local lock, fence or publication side effect. */
unsigned int input_list_forced_keys(const InputStateView *state,
    unsigned short *usages,unsigned int capacity)
{
    capacity &= 255U;
    if (capacity == 0)
        return 0;
    const volatile InputStateView *input = state;
    volatile unsigned short *usage_out = usages;
    unsigned int count = 0;
    for (unsigned int usage = 0; usage < 256 && count < capacity; ++usage)
        if ((input->forced_keys[usage >> 3] & (1U << (usage & 7U))) != 0)
            usage_out[count++] = (unsigned short)usage;
    return count;
}

/* Native entry: 0x420271fc. */
/* Original function-byte SHA-256:
 * 4a1cdd332e34fd5c65aa482e8590a574a2f64cac791e27cf9199c80cbf7749b2. */
/* Copy nonzero forced-consumer usages from eight slots in storage order,
 * retaining duplicates. Low-byte capacity zero avoids all pointer accesses.
 * Read each slot once, write its usage if nonzero, stop at capacity and return
 * count <=8. Unused output remains. No local lock or memory fence. */
unsigned int input_list_forced_consumers(const InputStateView *state,
    unsigned short *usages,unsigned int capacity)
{
    capacity &= 255U;
    if (capacity == 0)
        return 0;
    const volatile InputStateView *input = state;
    volatile unsigned short *usage_out = usages;
    unsigned int count = 0;
    for (unsigned int slot = 0; slot < 8 && count < capacity; ++slot) {
        unsigned short usage = input->forced_consumers[slot];
        if (usage != 0)
            usage_out[count++] = usage;
    }
    return count;
}
