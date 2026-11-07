/* Medius v3.4.7 device: mouse, keyboard and consumer report transformations.
 * Helpers below factor repeated native inline code for readability. They are
 * reconstruction utilities, not additional recovered native entry points. */

#include "../include/types.h"

/* Use the firmware's signed division boundary, including wrapped operands. */
extern long long report_divide_signed64(long long numerator,long long denominator)
    __asm__("__divdi3");
extern long long report_remainder_signed64(long long numerator,long long denominator)
    __asm__("__moddi3");

/* Add modulo 2^64, then interpret the resulting native bit pattern as signed. */
static long long report_add_wrapped_signed64(long long left,long long right)
{
    return (long long)((unsigned long long)left + (unsigned long long)right);
}

/* Retain the low 64 product bits, including native signed-overflow cases. */
static long long report_multiply_wrapped_signed64(long long left,long long right)
{
    return (long long)((unsigned long long)left * (unsigned long long)right);
}

/* Read LOW then HIGH without a retry, memory fence or atomic snapshot. */
static unsigned long long report_read_timestamp(const volatile TimestampWords *time)
{
    unsigned int low = time->low;
    unsigned int high = time->high;
    return ((unsigned long long)high << 32) | low;
}

/* Publish LOW then HIGH; concurrent readers can observe a partial update. */
static void report_write_timestamp(volatile TimestampWords *time,
    unsigned long long value)
{
    time->low = (unsigned int)value;
    time->high = (unsigned int)(value >> 32);
}

/* Copy the packed header, minimum and maximum as three ordered word reads. */
static ReportNumericField report_snapshot_numeric_field(
    const volatile ReportNumericField *source)
{
    ReportNumericField field;
    field.packed = source->packed;
    field.minimum = source->minimum;
    field.maximum = source->maximum;
    return field;
}

/* Snapshot one of four axes; an invalid rule selector produces a zero field. */
static ReportNumericField report_snapshot_axis(
    const volatile HidReportLayout *layout,unsigned int axis)
{
    ReportNumericField field = {0};
    if (axis < 4)
        field = report_snapshot_numeric_field(&layout->axes[axis]);
    return field;
}

/* Extract the configured bits and sign-extend widths 1..31. A missing suffix
 * leaves the accumulated prefix; bit addresses and shifts retain native wraps. */
static int report_read_numeric_value(const unsigned char *report,unsigned int length,
    ReportNumericField field)
{
    return hid_sign_extend(hid_read_bits(report,length,
        field.bit_offset,field.width),field.width);
}

/* The width-zero default is the full signed word: the native shift count
 * (width-1) is masked to five bits. Widths >=32 also use full signed32 bounds. */
static int report_clamp_numeric_value(long long value,ReportNumericField field)
{
    int minimum = field.minimum,maximum = field.maximum;
    if (minimum >= maximum) {
        unsigned int sign = 1U << ((field.width - 1U) & 31U);
        if (field.width >= 32)
            sign = 0x80000000U;
        minimum = (int)(0U - sign);
        maximum = (int)(sign - 1U);
    }
    if (value < minimum)
        value = minimum;
    if (value > maximum)
        value = maximum;
    return (int)value;
}

/* Packed fields wrap their bit address at16 bits and value positions at32.
 * A byte beyond the configured report span stops painting that field. */
static void report_write_bits(unsigned char *report,unsigned int length,
    unsigned int bit_offset,unsigned int width,unsigned int value)
{
    volatile unsigned char *bytes = report;
    for (unsigned int index = 0; index < width; ++index) {
        unsigned int bit = (bit_offset + index) & 65535U;
        unsigned int byte = bit >> 3,mask = 1U << (bit & 7U);
        if (byte >= length)
            break;
        unsigned int old = bytes[byte];
        bytes[byte] = (unsigned char)((value & (1U << (index & 31U))) != 0
            ? old | mask : old & ~mask);
    }
}

/* Test a key in a caller-supplied 256-bit mask; callers supply an 8-bit usage. */
static unsigned int report_key_mask_contains(const volatile unsigned char *map,
    unsigned int usage)
{
    return (map[usage >> 3] >> (usage & 7U)) & 1U;
}

/* Decode four axes, apply optional coupled X/Y projection and directional
 * scaling with signed residuals, then repaint changed enabled fields. Limits
 * and scales remain live reads; this routine adds no locking or validation. */
static void report_scale_axes(volatile InputStateView *state,unsigned char *output,
    unsigned int length)
{
    /* Scaling reloads the layout after the initial report copy. */
    const volatile HidReportLayout *layout = state->hid_layout;
    ReportNumericField fields[4];
    int values[4],original[4];
    for (unsigned int axis = 0; axis < 4; ++axis)
        fields[axis] = report_snapshot_numeric_field(&layout->axes[axis]);
    for (unsigned int axis = 0; axis < 4; ++axis) {
        original[axis] = fields[axis].enabled != 0
            ? report_read_numeric_value(output,length,fields[axis]) : 0;
        values[axis] = original[axis];
    }
    int reference[4];
    unsigned int coupled = state->filter_active == 1;
    reference[0] = (int)state->filter_runtime[0];
    reference[1] = (int)state->filter_runtime[1];
    if (coupled) {
        long long norm = report_add_wrapped_signed64(report_multiply_wrapped_signed64(reference[0],reference[0]),
            report_multiply_wrapped_signed64(reference[1],reference[1]));
        long long dot = report_add_wrapped_signed64(report_multiply_wrapped_signed64(reference[0],values[0]),
            report_multiply_wrapped_signed64(reference[1],values[1]));
        if (norm != 0 && dot != 0) {
            unsigned int column = dot > 0 ? 2 : 3;
            int coefficient = (short)state->primary_scales[0][column];
            int y_coefficient = (short)state->primary_scales[1][column];
            if (coefficient > y_coefficient)
                coefficient = y_coefficient;
            if (coefficient != 100) {
                long long numerator = report_multiply_wrapped_signed64(
                    report_multiply_wrapped_signed64(coefficient - 100,dot),100);
                for (unsigned int axis = 0; axis < 2; ++axis) {
                    if (state->axis_limits[axis].enabled == 0)
                        continue;
                    long long projection = report_add_wrapped_signed64(report_divide_signed64(
                        report_multiply_wrapped_signed64(report_remainder_signed64(numerator,norm),reference[axis]),norm),
                        report_multiply_wrapped_signed64(report_divide_signed64(numerator,norm),reference[axis]));
                    volatile int *remainder = axis == 0
                        ? &state->bearing_remainder_x : &state->bearing_remainder_y;
                    projection = report_add_wrapped_signed64(projection,*remainder);
                    long long correction = report_divide_signed64(projection,10000);
                    *remainder = (int)((unsigned int)projection -
                        10000U * (unsigned int)correction);
                    if (correction != 0) {
                        long long adjusted = report_add_wrapped_signed64(values[axis],correction);
                        long long limited = adjusted;
                        int maximum = state->axis_limits[axis].maximum;
                        int minimum = state->axis_limits[axis].minimum;
                        if (limited > maximum)
                            limited = maximum;
                        if (limited < minimum)
                            limited = minimum;
                        if (limited != adjusted)
                            *remainder = 0;
                        values[axis] = (int)limited;
                    }
                }
            }
        }
    }
    for (unsigned int axis = 0; axis < 4; ++axis) {
        int value = values[axis];
        if (value == 0)
            continue;
        unsigned int negative = value < 0;
        if (axis >= 2)
            reference[axis] = (int)state->filter_runtime[axis];
        int scale = (short)state->primary_scales[axis][negative];
        int direction_scale = 100;
        if ((axis >= 2 || !coupled) && reference[axis] != 0) {
            unsigned int column = (reference[axis] < 0) == negative ? 2 : 3;
            direction_scale = (short)state->primary_scales[axis][column];
        }
        if (scale == 100 && direction_scale == 100)
            continue;
        int scaled = 0;
        volatile int *remainder = &state->axis_scale_remainders[axis][negative];
        if (scale != 0 && direction_scale != 0) {
            long long product = report_multiply_wrapped_signed64(
                report_multiply_wrapped_signed64(scale,value),direction_scale);
            int saved_remainder = *remainder;
            unsigned int numerator_low = (unsigned int)product + (unsigned int)saved_remainder;
            unsigned int numerator_high = (unsigned int)((unsigned long long)product >> 32) +
                (saved_remainder < 0 ? 0xffffffffU : 0U);
            /* The uncoupled X path rereads the carry operand independently. */
            unsigned int carry_operand = axis == 0 && !coupled
                ? (unsigned int)*remainder : (unsigned int)saved_remainder;
            numerator_high += numerator_low < carry_operand;
            long long numerator = (long long)(((unsigned long long)numerator_high << 32) | numerator_low);
            long long quotient = report_divide_signed64(numerator,10000);
            *remainder = (int)((unsigned int)numerator - 10000U*(unsigned int)quotient);
            if (quotient < -2147483647LL)
                quotient = -2147483647LL;
            if (quotient > 2147483647LL)
                quotient = 2147483647LL;
            scaled = (int)quotient;
        }
        if (scaled != value) {
            int limited = scaled;
            int maximum = state->axis_limits[axis].maximum;
            int minimum = state->axis_limits[axis].minimum;
            if (limited > maximum)
                limited = maximum;
            if (limited < minimum)
                limited = minimum;
            if (limited != scaled)
                *remainder = 0;
            values[axis] = limited;
        }
    }
    for (unsigned int axis = 0; axis < 4; ++axis) {
        if (fields[axis].enabled != 0 && values[axis] != original[axis])
            report_write_bits(output,length,fields[axis].bit_offset,fields[axis].width,
                (unsigned int)values[axis]);
    }
}

/* Filter at most 16 button edges against the cached latch. Scales <=99 suppress
 * new presses or retain releases; every processed button republishes the latch. */
static void report_filter_button_edges(volatile InputStateView *state,
    const volatile HidReportLayout *layout,unsigned char *output,
    unsigned int length,unsigned int count)
{
    if (count == 0)
        return;
    unsigned int latch = state->button_scale_state;
    volatile unsigned char *bytes = output;
    for (unsigned int button = 0; button < count; ++button) {
        int release = (short)state->button_scales[button][1];
        unsigned int bit = (layout->button_bit_offset + button) & 65535U;
        unsigned int byte = bit >> 3,mask = 1U << (bit & 7U),latch_mask = 1U << button;
        unsigned int old = (latch >> button) & 1U;
        unsigned int pressed = byte < length ? (bytes[byte] >> (bit & 7U)) & 1U : 0;
        if (byte >= length) {
            pressed = old != 0 && release <= 99;
        } else if (pressed != 0 && old == 0) {
            if ((short)state->button_scales[button][0] <= 99) {
                bytes[byte] &= (unsigned char)~mask;
                latch = state->button_scale_state;
                pressed = 0;
            }
        } else if (pressed == 0 && old != 0 && release <= 99) {
            bytes[byte] |= (unsigned char)mask;
            latch = state->button_scale_state;
            pressed = 1;
        }
        latch = pressed != 0 ? latch | latch_mask : latch & ~latch_mask;
        state->button_scale_state = (unsigned short)latch;
    }
}

/* Walk the live-count mapping table in order. Numeric rules swap or add/clear;
 * button rules move or conditionally clear bits. Counts are not capped at 32,
 * and an overlapping destination can change what a later source read sees. */
static void report_apply_mappings(volatile InputStateView *state,
    const volatile HidReportLayout *layout,unsigned char *output,
    unsigned int length)
{
    const volatile InputMapTable *table = state->mapping_table;
    if (table == 0 || table->count == 0)
        return;
    unsigned int conditions = state->mapping_conditions;
    volatile unsigned char *bytes = output;
    unsigned int index = 0;
    do {
        const volatile InputMapRule *rule = (const volatile void *)
            ((const unsigned char *)table + index * 8U);
        unsigned int operation = rule->operation;
        if (operation == 1 || (operation == 0 && rule->subtype == 3)) {
            ReportNumericField source = report_snapshot_axis(layout,rule->source);
            ReportNumericField destination = report_snapshot_axis(layout,rule->destination);
            if (source.enabled != 0 && destination.enabled != 0) {
                int source_value = report_read_numeric_value(output,length,source);
                int destination_value = report_read_numeric_value(output,length,destination);
                if (operation == 1) {
                    int source_replacement = report_clamp_numeric_value(destination_value,source);
                    report_write_bits(output,length,source.bit_offset,source.width,(unsigned int)source_replacement);
                    report_write_bits(output,length,destination.bit_offset,destination.width,
                        (unsigned int)report_clamp_numeric_value(source_value,destination));
                } else {
                    int sum = report_clamp_numeric_value((long long)source_value+destination_value,destination);
                    report_write_bits(output,length,destination.bit_offset,destination.width,
                        (unsigned int)sum);
                    /* Source is cleared AFTER destination, including overlap. */
                    report_write_bits(output,length,source.bit_offset,source.width,0);
                }
            }
        } else if (operation == 0) {
            unsigned int source = rule->source;
            unsigned int buttons = layout->button_count;
            if (source < buttons && source < 16) {
                unsigned int mode = rule->button_mode;
                if (mode == 0) {
                    unsigned int destination = rule->destination;
                    if (destination < buttons && destination < 16) {
                        unsigned int button_offset = layout->button_bit_offset;
                        unsigned int bit = (button_offset+source) & 65535U;
                        unsigned int byte = bit >> 3,mask = 1U << (bit & 7U);
                        if (byte < length) {
                            unsigned int old_byte = bytes[byte];
                            if ((old_byte & mask) != 0) {
                                unsigned int to_bit = (button_offset+destination) & 65535U;
                                if ((to_bit >> 3) < length) {
                                    bytes[to_bit >> 3] |= (unsigned char)(1U << (to_bit & 7U));
                                    unsigned int refreshed_source = rule->source;
                                    bit = (layout->button_bit_offset+refreshed_source) & 65535U;
                                    byte = bit >> 3;
                                    mask = 1U << (bit & 7U);
                                    if (byte < length)
                                        bytes[byte] &= (unsigned char)~mask;
                                } else {
                                    bytes[byte] = (unsigned char)(old_byte & ~mask);
                                }
                            } else {
                                bytes[byte] = (unsigned char)(old_byte & ~mask);
                            }
                        }
                    }
                } else if ((mode == 1 && (conditions & 1U) != 0) ||
                           (mode == 2 && (conditions & 2U) != 0)) {
                    unsigned int bit = (layout->button_bit_offset+source) & 65535U;
                    unsigned int byte = bit >> 3,mask = 1U << (bit & 7U);
                    if (byte < length)
                        bytes[byte] &= (unsigned char)~mask;
                }
            }
        }
        ++index;
    } while (index < table->count);
}

/* Interpolate a signed axis with wrapped multiplication and signed division.
 * Round positive products up by half and negative products down by ceil-half;
 * cap only toward the original axis value. Nonpositive intervals return zero. */
static int report_interpolate_motion(int primary,long long elapsed,long long duration)
{
    if (primary == 0)
        return 0;
    if (elapsed <= 0 || duration <= 0)
        return 0;
    long long product = report_multiply_wrapped_signed64(elapsed,primary);
    long long half = duration >> 1;
    long long rounded = product >= 0 ? report_add_wrapped_signed64(product,half)
        : report_add_wrapped_signed64(product,-half-(duration & 1));
    long long amount = report_divide_signed64(rounded,duration);
    if (primary > 0 && amount > primary)
        amount = primary;
    if (primary < 0 && amount < primary)
        amount = primary;
    return (int)amount;
}

/* Apply timed primary motion and retire a paced/due prefix of 16-byte history
 * records. History counts are not capped at eight. Update residual accumulators
 * through hid_apply_numeric_delta, then clear or advance the timing anchors. */
static void report_apply_primary_motion(volatile InputStateView *state,
    const volatile HidReportLayout *layout,unsigned char *output,
    unsigned int length,unsigned long long now)
{
    unsigned long long deadline = report_read_timestamp(&state->motion_deadline);
    int primary_x = (int)state->primary_words[0];
    int primary_y = (int)state->primary_words[1];
    int requested_x = primary_x,requested_y = primary_y;
    unsigned int count;
    if ((long long)now > 0 && deadline != 0 && (long long)now < (long long)deadline &&
        (primary_x != 0 || primary_y != 0)) {
        /* X and Y share one origin snapshot. The history count is sampled
         * after X interpolation and before Y interpolation. */
        unsigned long long origin = report_read_timestamp(&state->motion_origin);
        long long elapsed = (long long)(now-origin);
        long long duration = (long long)(deadline-origin);
        requested_x = report_interpolate_motion(primary_x,elapsed,duration);
        count = state->motion_history_count;
        requested_y = report_interpolate_motion(primary_y,elapsed,duration);
    } else {
        count = state->motion_history_count;
    }
    if (count != 0) {
        unsigned int selected = count,forced_pace = 0;
        if ((long long)now > 0) {
            unsigned long long pace = report_read_timestamp(&state->motion_history_pace_time);
            unsigned int half_elapsed = state->motion_last_elapsed >> 1;
            forced_pace = (long long)(now-pace) >= (long long)half_elapsed;
            unsigned int multiple = state->motion_window_multiple;
            selected = forced_pace ? (count < multiple ? count : multiple) : 0;
            if (!forced_pace || multiple < count) {
                while (selected < count) {
                    const volatile InputMotionSample *sample = (const volatile void *)
                        ((const unsigned char *)state+0x38U+16U*selected);
                    /* Due is sampled HIGH before LOW, unlike pacing anchors. */
                    unsigned int high = sample->due.high;
                    int now_high = (int)(now >> 32);
                    if ((int)high > now_high)
                        break;
                    if ((int)high == now_high && sample->due.low > (unsigned int)now)
                        break;
                    ++selected;
                }
                if (count-selected > multiple)
                    selected = count-multiple;
            }
        }
        if (selected != 0) {
            if (forced_pace)
                report_write_timestamp(&state->motion_history_pace_time,now);
            int sum_x = 0,sum_y = 0;
            for (unsigned int index = 0; index < selected; ++index) {
                const volatile InputMotionSample *sample = (const volatile void *)
                    ((const unsigned char *)state+0x38U+16U*index);
                sum_x += sample->x;
                sum_y += sample->y;
            }
            unsigned char *history = (unsigned char *)state+0x38U;
            memmove(history,history+selected*16U,(count-selected)*16U);
            state->motion_history_count = (unsigned char)(state->motion_history_count-selected);
            state->primary_words[0] = (unsigned int)input_clamp_motion_sum((long long)primary_x+sum_x);
            state->primary_words[1] = (unsigned int)input_clamp_motion_sum((long long)primary_y+sum_y);
            requested_x = (int)((unsigned int)requested_x+(unsigned int)sum_x);
            requested_y = (int)((unsigned int)requested_y+(unsigned int)sum_y);
        }
    }
    for (unsigned int axis = 0; axis < 4; ++axis) {
        int delta = axis == 0 ? requested_x : axis == 1 ? requested_y : (int)state->primary_words[axis];
        ReportNumericField field = report_snapshot_numeric_field(&layout->axes[axis]);
        hid_apply_numeric_delta(output,length,field,(int *)&state->primary_words[axis],delta);
    }
    if (state->primary_words[0] == 0 && state->primary_words[1] == 0) {
        report_write_timestamp(&state->motion_deadline,0);
        report_write_timestamp(&state->motion_origin,0);
    } else {
        unsigned long long remaining_deadline = report_read_timestamp(&state->motion_deadline);
        if (remaining_deadline != 0) {
            int high = (int)state->motion_origin.high;
            int now_high = (int)(now >> 32);
            if (high < now_high || (high == now_high && state->motion_origin.low < (unsigned int)now))
                report_write_timestamp(&state->motion_origin,now);
        }
    }
}

/* For up to two selected axes changed from input, clamp the decoded value and
 * store its low byte at the configured offset. The final store is unchecked. */
static void report_apply_byte_clamps(volatile InputStateView *state,
    const unsigned char *input,unsigned char *output)
{
    const volatile HidReportLayout *layout = state->hid_layout;
    unsigned int count = layout->output_count;
    if (count == 0)
        return;
    unsigned int length = layout->expected_length;
    for (unsigned int index = 0; index < 2 && index < count; ++index) {
        int selector = (signed char)((volatile unsigned char *)state)[0xc8U+index];
        if (selector < 0)
            continue;
        const volatile ReportNumericField *field = &layout->axes[selector == 0 ? 0 : 1];
        if (field->enabled == 0)
            continue;
        unsigned int width = field->width;
        unsigned int bit_offset = field->bit_offset;
        if (width == 0)
            continue;
        int value = hid_sign_extend(hid_read_bits(output,length,bit_offset,width),width);
        int original = hid_sign_extend(hid_read_bits(input,length,bit_offset,width),width);
        if (value != original) {
            int minimum = layout->byte_clamps[index].minimum;
            unsigned int byte = layout->byte_clamps[index].byte_offset;
            int maximum = layout->byte_clamps[index].maximum;
            if (value < minimum)
                value = minimum;
            if (value > maximum)
                value = maximum;
            /* Deliberately NO report-length check on this native store. */
            ((volatile unsigned char *)output)[byte] = (unsigned char)value;
            count = layout->output_count;
        }
    }
}

/* Detect keyboard work: forced/cleared masks first, the complete flags/edge-mask
 * scan next, then saved keys. Return a normalized boolean without mutating state. */
static unsigned int report_keyboard_has_transforms(volatile InputStateView *state)
{
    for (unsigned int index = 0; index < 32; ++index)
        if (state->forced_keys[index] != 0 || state->cleared_keys[index] != 0)
            return 1;
    unsigned int transforms = state->keyboard_transform_flags;
    for (unsigned int index = 0; index < 32; ++index) {
        unsigned int rising = state->key_rising_suppression[index];
        unsigned int falling = state->key_falling_retention[index];
        transforms |= rising | falling;
    }
    if (transforms != 0)
        return 1;
    for (unsigned int index = 0; index < 32; ++index)
        if (state->saved_keys[index] != 0)
            return 1;
    return 0;
}

/* Filter original bitmap transitions, then apply overrides in ascending usage
 * order. Skip modifier usages in the second pass; its first matching range wins.
 * The live range count is not capped at the declared eight descriptor slots. */
static void report_rewrite_keyboard_bitmap(volatile InputStateView *state,
    const volatile HidKeyboardLayout *keyboard,const unsigned char *input,
    unsigned char *output,unsigned int length)
{
    for (unsigned int range_index = 0; range_index < keyboard->range_count; ++range_index) {
        const volatile HidBitmapRange *range = (const volatile void *)
            ((const unsigned char *)keyboard+16U+range_index*6U);
        for (unsigned int index = 0; index < range->count; ++index) {
            unsigned int bit = (range->bit_offset+index) & 65535U;
            unsigned int usage = (range->usage_base+index) & 255U;
            unsigned int pressed = hid_read_bits(input,length,bit,1);
            unsigned int retained = input_filter_key_transition((InputStateView *)state,usage,pressed);
            /* Overrides are a separate ascending-usage pass below. Applying
             * them here would change overlapping-range behavior. */
            report_write_bits(output,length,bit,1,retained);
        }
    }
    for (unsigned int usage = 0; usage < 256; ++usage) {
        if (usage >= 0xe0 && usage <= 0xe7)
            continue;
        unsigned int set = report_key_mask_contains(state->forced_keys,usage) || report_key_mask_contains(state->saved_keys,usage);
        if (!set && !report_key_mask_contains(state->cleared_keys,usage))
            continue;
        unsigned int range_count = keyboard->range_count;
        for (unsigned int index = 0; index < range_count; ++index) {
            const volatile HidBitmapRange *range = (const volatile void *)
                ((const unsigned char *)keyboard+16U+index*6U);
            unsigned int base = range->usage_base;
            if (usage < base)
                continue;
            unsigned int end = (base+range->count) & 65535U;
            if (usage < end) {
                report_write_bits(output,length,(range->bit_offset+usage-base) & 65535U,1,set);
                break;
            }
        }
    }
}

/* Test membership in the local gathered byte-key prefix; preserve duplicates. */
static unsigned int report_key_list_contains(const unsigned char *list,
    unsigned int count,unsigned int usage)
{
    for (unsigned int index = 0; index < count; ++index)
        if (list[index] == usage)
            return 1;
    return 0;
}

/* Fill in-span array slots with gathered keys and zeros, or rollover usage 1. */
static void report_write_key_array(unsigned char *output,unsigned int length,
    unsigned int byte,unsigned int capacity,const unsigned char *keys,
    unsigned int count,unsigned int rollover)
{
    volatile unsigned char *bytes = output;
    for (unsigned int index = 0; index < capacity; ++index) {
        if (byte+index >= length)
            break;
        bytes[byte+index] = (unsigned char)(rollover ? 1 : index < count ? keys[index] : 0);
    }
}

/* Rebuild an aligned 8-bit key array from current, retained and forced/saved
 * keys. Preserve current duplicates and existing leading rollover 1; gather at
 * most 64 keys and emit rollover if descriptor capacity is exceeded. */
static void report_rewrite_keyboard_array(volatile InputStateView *state,
    const volatile HidKeyboardLayout *keyboard,const unsigned char *input,
    unsigned char *output,unsigned int length)
{
    if (keyboard->key_width != 8)
        return;
    unsigned int key_bit_offset = keyboard->key_bit_offset;
    if ((key_bit_offset & 7U) != 0)
        return;
    unsigned int byte = key_bit_offset >> 3;
    unsigned int capacity = keyboard->key_count;
    const volatile unsigned char *bytes = input;
    if (byte < length && bytes[byte] == 1)
        return;
    unsigned char seen[32],keys[64];
    memset(seen,0,sizeof(seen));
    unsigned int count = 0,overflow = 0;
    for (unsigned int index = 0; index < capacity && byte+index < length; ++index) {
        unsigned int usage = bytes[byte+index];
        if (usage < 2)
            continue;
        seen[usage >> 3] |= (unsigned char)(1U << (usage & 7U));
        if (input_filter_key_transition((InputStateView *)state,usage,1) != 0 &&
            !report_key_mask_contains(state->cleared_keys,usage) && count < 64)
            keys[count++] = (unsigned char)usage;
    }
    for (unsigned int usage = 0; usage < 256; ++usage) {
        if ((usage >= 0xe0 && usage <= 0xe7) || report_key_mask_contains(seen,usage))
            continue;
        if (input_filter_key_transition((InputStateView *)state,usage,0) != 0 &&
            !report_key_mask_contains(state->cleared_keys,usage) && !report_key_list_contains(keys,count,usage)) {
            if (count >= capacity) {
                overflow = 1;
                break;
            }
            if (count < 64)
                keys[count++] = (unsigned char)usage;
        }
    }
    for (unsigned int usage = 0; usage < 256; ++usage) {
        if (usage >= 0xe0 && usage <= 0xe7)
            continue;
        if ((report_key_mask_contains(state->forced_keys,usage) || report_key_mask_contains(state->saved_keys,usage)) &&
            !report_key_list_contains(keys,count,usage)) {
            if (count >= capacity) {
                report_write_key_array(output,length,byte,capacity,keys,count,1);
                return;
            }
            if (count < 64)
                keys[count++] = (unsigned char)usage;
        }
    }
    report_write_key_array(output,length,byte,capacity,keys,count,overflow || count > capacity);
}

/* Copy the descriptor-sized keyboard report, filter up to eight modifiers,
 * then rewrite bitmap or array keys when transform state requires work. */
static void report_rewrite_keyboard(volatile InputStateView *state,
    const volatile HidReportLayout *layout,const unsigned char *input,
    unsigned char *output)
{
    const volatile HidKeyboardLayout *keyboard = &layout->keyboard;
    unsigned int length = keyboard->expected_length;
    memcpy(output,input,length);
    if (!report_keyboard_has_transforms(state))
        return;
    unsigned int modifier_width = keyboard->modifier_width;
    for (unsigned int index = 0; index < 8 && index < modifier_width; ++index) {
        unsigned int usage = 0xe0U+index;
        unsigned int bit = (keyboard->modifier_bit_offset+index) & 65535U;
        unsigned int pressed = hid_read_bits(input,length,bit,1);
        unsigned int retained = input_filter_key_transition((InputStateView *)state,usage,pressed);
        unsigned int output_bit = (keyboard->modifier_bit_offset+index) & 65535U;
        unsigned int value = report_key_mask_contains(state->forced_keys,usage) ||
            report_key_mask_contains(state->saved_keys,usage) ||
            (!report_key_mask_contains(state->cleared_keys,usage) && retained);
        report_write_bits(output,length,output_bit,1,value);
        modifier_width = keyboard->modifier_width;
    }
    if (keyboard->bitmap_mode != 0)
        report_rewrite_keyboard_bitmap(state,keyboard,input,output,length);
    else
        report_rewrite_keyboard_array(state,keyboard,input,output,length);
}

/* Test a usage against all eight halfword slots, stopping at the first match. */
static unsigned int report_consumer_list_contains(const volatile unsigned short *list,
    unsigned int value)
{
    for (unsigned int index = 0; index < 8; ++index)
        if (list[index] == value)
            return 1;
    return 0;
}

/* Decode one little-endian usage with the native HIGH-byte-first read order. */
static unsigned int report_read_consumer_usage(const volatile unsigned char *bytes,
    unsigned int byte)
{
    unsigned int high = bytes[byte+1];
    return (high << 8) | bytes[byte];
}

/* Copy the descriptor-sized consumer report. For aligned 16-bit usages, remove
 * suppressed entries, then inject forced and saved usages into the first empty
 * or unprotected slot. Existing forced/saved usages are protected from eviction. */
static void report_rewrite_consumer(volatile InputStateView *state,
    const volatile HidReportLayout *layout,const unsigned char *input,
    unsigned char *output)
{
    const volatile HidConsumerLayout *consumer = &layout->consumer;
    unsigned int length = consumer->expected_length;
    memcpy(output,input,length);
    unsigned int enabled = 0;
    for (unsigned int index = 0; index < 8 && !enabled; ++index)
        enabled = state->forced_consumers[index] != 0 || state->cleared_consumers[index] != 0;
    if (!enabled)
        enabled = state->transform_mode != 0;
    for (unsigned int index = 0; index < 8 && !enabled; ++index)
        enabled = state->consumer_transforms[index] != 0;
    for (unsigned int index = 0; index < 8 && !enabled; ++index)
        enabled = state->saved_consumers[index] != 0;
    if (!enabled || consumer->width != 16)
        return;
    unsigned int bit_offset = consumer->bit_offset;
    if ((bit_offset & 7U) != 0)
        return;
    unsigned int byte = bit_offset >> 3;
    if (length <= byte+1)
        return;
    unsigned int count = (length-byte) >> 1;
    unsigned int capacity = consumer->count;
    if (count > capacity)
        count = capacity;
    volatile unsigned char *bytes = output;
    for (unsigned int index = 0; index < count; ++index) {
        unsigned int position = byte+2U*index;
        unsigned int value = report_read_consumer_usage(bytes,position);
        if (value != 0 && (state->transform_mode != 0 ||
            report_consumer_list_contains(state->consumer_transforms,value) ||
            report_consumer_list_contains(state->cleared_consumers,value))) {
            bytes[position] = 0;
            bytes[position+1] = 0;
        }
    }
    for (unsigned int list = 0; list < 2; ++list) {
        const volatile unsigned short *values = list == 0 ? state->forced_consumers : state->saved_consumers;
        for (unsigned int index = 0; index < 8; ++index) {
            unsigned int value = values[index];
            if (value == 0 || count == 0)
                continue;
            unsigned int empty = count,replace = count,found = 0;
            for (unsigned int slot = 0; slot < count; ++slot) {
                unsigned int old = report_read_consumer_usage(bytes,byte+2U*slot);
                if (old == value) {
                    found = 1;
                    break;
                }
                if (old == 0) {
                    if (empty == count)
                        empty = slot;
                } else if (replace == count && !report_consumer_list_contains(state->forced_consumers,old) &&
                    !report_consumer_list_contains(state->saved_consumers,old)) {
                    replace = slot;
                }
            }
            if (!found) {
                unsigned int slot = empty != count ? empty : replace;
                if (slot != count) {
                    unsigned int position = (byte+2U*slot) & 65535U;
                    bytes[position] = (unsigned char)value;
                    bytes[position+1] = (unsigned char)(value >> 8);
                }
            }
        }
    }
}

/* Native entry: 0x4038ce28. */
/* Original function-byte SHA-256:
 * 8b3b43e94a4f23ce46bd27aa2e99e6a6113f7230507bc9b2a7e0202809205a04. */
/* Rewrite a matching mouse, keyboard or consumer report; otherwise copy
 * LOW16(length). Matching uses cached layout/report IDs and reads input[0]
 * without a caller-length check. Matched copies use the descriptor's length,
 * NOT the caller length. Pending dirty events are drained before dispatch.
 *
 * Mouse order: axis override/scaling, button edge filtering, sequential maps,
 * secondary then timed primary/history motion, forced/cleared buttons, byte
 * clamps. flags LOW8 bit0 consumes secondary, bit1 primary/history, bit2 skips
 * scaling and optionally paints the four signed32 axis_override values. A NULL
 * override still skips scaling. now_us is interpreted as signed64; nonpositive
 * time consumes available primary/history without interpolation. No clock read.
 *
 * Keyboard supports modifier bits, bitmap ranges and byte key arrays, including
 * retained releases and forced/saved keys. Input duplicates are preserved;
 * capacity failure writes rollover1. The 64-byte gather limit silently drops
 * additional keys. Consumer reports remove configured usages, then insert
 * forced/saved usages into empty or unprotected slots, preserving protected keys.
 *
 * Bounds/quirks are native: mapping/range/history counts are not array-capped;
 * bit addresses wrap16 and shifts wrap32; byte-clamp stores lack a length check;
 * overlapping add mappings clear source AFTER destination. Accumulator
 * subtraction/zero-width painting remain
 * in hid_apply_numeric_delta. No local lock or output status is supplied.
 * This reconstruction describes the static instruction paths, not a hardware
 * timing or concurrency validation. A7 is unused ABI alignment padding before
 * now_us stack words0/1 and axis_override stack word2. */
void input_rewrite_report_native(InputStateView *state,
    const unsigned char *input,unsigned int length,unsigned char *output,
    unsigned int flags,unsigned long long now_us,const int *axis_override)
{
    volatile InputStateView *state_fields = state;
    unsigned int queued_event_count = state_fields->queued_event_count;
    const volatile HidReportLayout *layout = state_fields->hid_layout;
    length &= 65535U;
    flags &= 255U;
    if (queued_event_count != 0) {
        memw();
        if (state_fields->dirty != 0)
            input_drain_queued_events(state);
    }
    const volatile unsigned char *input_bytes = input;
    unsigned int mouse_match = layout->axes[0].enabled != 0;
    if (mouse_match) {
        unsigned int id = layout->report_id;
        mouse_match = id == 0 || input_bytes[0] == id;
    }
    if (mouse_match) {
        layout = state_fields->hid_layout;
        unsigned int report_length = layout->expected_length;
        memcpy(output,input,report_length);
        if ((flags & 4U) != 0) {
            if (axis_override != 0) {
                ReportNumericField fields[4];
                for (unsigned int axis = 0; axis < 4; ++axis)
                    fields[axis] = report_snapshot_numeric_field(&layout->axes[axis]);
                for (unsigned int axis = 0; axis < 4; ++axis) {
                    ReportNumericField field = fields[axis];
                    if (field.enabled != 0) {
                        int value = ((const volatile int *)axis_override)[axis];
                        value = report_clamp_numeric_value(value,field);
                        report_write_bits(output,report_length,field.bit_offset,field.width,(unsigned int)value);
                    }
                }
            }
        } else {
            report_scale_axes(state_fields,output,report_length);
        }
        unsigned int buttons = layout->button_count;
        if (buttons > 16)
            buttons = 16;
        report_filter_button_edges(state_fields,layout,output,report_length,buttons);
        report_apply_mappings(state_fields,layout,output,report_length);
        if ((flags & 1U) != 0) {
            for (unsigned int axis = 0; axis < 4; ++axis) {
                ReportNumericField field = report_snapshot_numeric_field(&layout->axes[axis]);
                int delta = (int)state_fields->secondary_words[axis];
                hid_apply_numeric_delta(output,report_length,field,
                    (int *)&state_fields->secondary_words[axis],delta);
            }
        }
        if ((flags & 2U) != 0)
            report_apply_primary_motion(state_fields,layout,output,report_length,now_us);
        for (unsigned int button = 0; button < buttons; ++button) {
            unsigned int mask = 1U << button;
            if ((state_fields->forced_buttons & mask) != 0) {
                unsigned int bit = (layout->button_bit_offset+button) & 65535U;
                report_write_bits(output,report_length,bit,1,1);
            } else if ((state_fields->cleared_buttons & mask) != 0) {
                unsigned int bit = (layout->button_bit_offset+button) & 65535U;
                report_write_bits(output,report_length,bit,1,0);
            }
        }
        report_apply_byte_clamps(state_fields,input,output);
    } else {
        unsigned int keyboard_match = layout->keyboard.enabled != 0;
        if (keyboard_match) {
            unsigned int id = layout->keyboard.report_id;
            keyboard_match = id == 0 || input_bytes[0] == id;
        }
        if (keyboard_match) {
            report_rewrite_keyboard(state_fields,state_fields->hid_layout,input,output);
        } else {
            unsigned int consumer_match = layout->consumer.enabled != 0;
            if (consumer_match) {
                unsigned int id = layout->consumer.report_id;
                consumer_match = id == 0 || input_bytes[0] == id;
            }
            if (consumer_match)
                report_rewrite_consumer(state_fields,state_fields->hid_layout,input,output);
            else
                memcpy(output,input,length);
        }
    }
}
