/* Medius v3.4.7 device — HID report descriptor metadata decoding. */
#include "../include/types.h"

/* HID decoder reconstruction utilities: inline portions of0x42024ce0, not
 * additional native entries. State grouping names the original scalar roles;
 * it does not claim original source boundaries or an original stack layout. */
typedef struct HidDecoderState {
    unsigned int usages[16];
    unsigned short cached_offsets[16];
    unsigned char cached_ids[16],generic_ids[12],vendor_ids[16];
    unsigned int usage_count,wide_usage,range_present,usage_minimum,usage_maximum;
    unsigned int usage_page,report_size,report_count,report_count_full;
    unsigned int logical_minimum,logical_maximum,report_id,offset,has_ids,cache_count;
    unsigned int axis_ids[4],button_id,primary_bits;
    unsigned int keyboard_selected,keyboard_id,keyboard_bits,keyboard_total,keyboard_invalid;
    unsigned int consumer_selected,consumer_id,consumer_bits;
    unsigned int part_count,parts_changed;
    MediusHidUnsupportedParts parts;
} HidDecoderState;

static __attribute__((always_inline)) inline unsigned int hid_signed_item(
    unsigned int value,unsigned int width)
{
    if (width == 1)
        return (unsigned int)(int)(signed char)value;
    if (width == 2)
        return (unsigned int)(int)(short)value;
    return value;
}

static __attribute__((always_inline)) inline void hid_select_report_id(
    HidDecoderState *state,unsigned int next_id)
{
    unsigned int slot = 0;
    while (slot != state->cache_count && state->cached_ids[slot] != state->report_id)
        ++slot;
    if (slot != state->cache_count) {
        state->cached_offsets[slot] = (unsigned short)state->offset;
    } else if (state->cache_count != 16) {
        state->cached_ids[slot] = (unsigned char)state->report_id;
        state->cached_offsets[slot] = (unsigned short)state->offset;
        state->cache_count = (unsigned char)(state->cache_count + 1U);
    }
    next_id = (unsigned char)next_id;
    slot = 0;
    while (slot != state->cache_count && state->cached_ids[slot] != next_id)
        ++slot;
    state->offset = slot == state->cache_count ? 8 : state->cached_offsets[slot];
    state->report_id = next_id;
    state->has_ids = 1;
}

static __attribute__((always_inline)) inline void hid_account_unsupported(
    HidDecoderState *state,unsigned int flags)
{
    bool constant = (flags & 1U) != 0;
    bool variable = (flags & 2U) != 0;
    bool relative = (flags & 4U) != 0;
    bool supported = !constant && !state->wide_usage &&
        ((variable && relative) ||
         (variable && state->usage_page == 9 && state->report_size == 1) ||
         (!variable && (state->usage_page == 7 || state->usage_page == 12)));
    unsigned int contribution = supported ? 0 : state->report_size * state->report_count_full;
    unsigned int slot = 0;
    while (slot != state->part_count && state->parts.report_ids[slot] != state->report_id)
        ++slot;
    if (slot == state->part_count) {
        if (slot == 16) {
            state->parts.overflow = 1;
            return;
        }
        state->part_count = (unsigned char)(state->part_count + 1U);
        state->parts.report_ids[slot] = (unsigned char)state->report_id;
        state->parts.bits[slot] = 0;
        state->parts.first_offset[slot] = 65535;
        state->parts_changed = 1;
    }
    if (contribution != 0) {
        if (state->parts.first_offset[slot] == 65535)
            state->parts.first_offset[slot] = (unsigned short)state->offset;
        unsigned int sum = state->parts.bits[slot] + contribution; /* wraps32 before clamp */
        state->parts.bits[slot] = (unsigned short)(sum < 65535U ? sum : 65535U);
    }
}

static __attribute__((always_inline)) inline void hid_store_axis(
    volatile ReportNumericField *axis,HidDecoderState *state,
    unsigned int index,unsigned int offset,unsigned int *x_present,bool consumer_page)
{
    unsigned int present = index == 0 ? *x_present : axis->enabled;
    if (present != 0)
        return;
    axis->bit_offset = (unsigned short)offset;
    if (consumer_page) {
        axis->width = (unsigned char)state->report_size;
        axis->enabled = 1;
        state->axis_ids[index] = state->report_id;
        axis->minimum = (int)state->logical_minimum;
        axis->maximum = (int)state->logical_maximum;
    } else {
        axis->minimum = (int)state->logical_minimum;
        axis->width = (unsigned char)state->report_size;
        axis->enabled = 1;
        axis->maximum = (int)state->logical_maximum;
        state->axis_ids[index] = state->report_id;
    }
    if (index == 0)
        *x_present = 1;
}

static __attribute__((always_inline)) inline void hid_classify_variable(
    HidDecoderState *state,volatile HidReportLayout *layout,
    unsigned int flags,unsigned int *x_present)
{
    unsigned int size = state->report_size, count = state->report_count;
    unsigned int page = state->usage_page;
    if (page == 9 && size == 1) {
        if (layout->button_count == 0) {
            state->button_id = state->report_id;
            layout->button_bit_offset = (unsigned short)state->offset;
            layout->button_count = (unsigned char)count;
        }
        return;
    }
    if (page == 7 && size == 1) {
        unsigned int usage = state->range_present ? (unsigned short)state->usage_minimum :
            state->usage_count != 0 ? (unsigned short)state->usages[0] : 0;
        bool modifier = (unsigned short)(usage - 224U) < 8;
        if (!modifier)
            state->keyboard_total += count;
        if (state->keyboard_selected != 0 && state->keyboard_id != state->report_id)
            return;
        if (modifier) {
            if (layout->keyboard.modifier_width == 0) {
                layout->keyboard.modifier_bit_offset = (unsigned short)state->offset;
                layout->keyboard.modifier_width = (unsigned char)count;
            }
        } else {
            unsigned int group = layout->keyboard.range_count;
            if (group >= 8) {
                state->keyboard_invalid = 1;
            } else {
                layout->keyboard.ranges[group].bit_offset = (unsigned short)state->offset;
                layout->keyboard.ranges[group].count = (unsigned short)count;
                layout->keyboard.ranges[group].usage_base = (unsigned short)usage;
                layout->keyboard.range_count = (unsigned char)(group + 1U);
                layout->keyboard.bitmap_mode = 1;
            }
        }
        state->keyboard_selected = 1;
        state->keyboard_id = state->report_id;
        return;
    }
    if ((flags & 4U) != 0 && (page == 1 || page == 12)) {
        unsigned int offset = state->offset;
        if (state->usage_count != 0) {
            for (unsigned int field = 0; field != count; ++field) {
                unsigned int usage = state->usages[field < state->usage_count ? field : state->usage_count - 1U];
                if (page == 1) {
                    if (usage == 0x30)
                        hid_store_axis(&layout->axes[0], state, 0, offset, x_present, false);
                    else if (usage == 0x31)
                        hid_store_axis(&layout->axes[1], state, 1, offset, x_present, false);
                    else if (usage == 0x38)
                        hid_store_axis(&layout->axes[2], state, 2, offset, x_present, false);
                    else if (usage == 0x000c0238U)
                        hid_store_axis(&layout->axes[3], state, 3, offset, x_present, false);
                } else if (usage == 0x238 || usage == 0x000c0238U) {
                    hid_store_axis(&layout->axes[3], state, 3, offset, x_present, true);
                }
                offset = (unsigned short)(offset + size);
            }
        }
        return;
    }
    if (size == 8 && (int)state->logical_minimum < 0 && page >= 0xff00U) {
        unsigned int offset = state->offset;
        for (unsigned int field = 0; field != count; ++field) {
            unsigned int index = layout->output_count;
            if (index >= 2)
                break;
            if ((offset & 7U) == 0) {
                layout->byte_clamps[index].byte_offset = (unsigned short)(offset >> 3);
                layout->byte_clamps[index].minimum = (short)state->logical_minimum;
                state->vendor_ids[index] = (unsigned char)state->report_id;
                layout->byte_clamps[index].maximum = (short)state->logical_maximum;
                layout->output_count = (unsigned char)(index + 1U);
            }
            offset = (unsigned short)(offset + 8U);
        }
    }
}

static __attribute__((always_inline)) inline void hid_classify_array(
    HidDecoderState *state,volatile HidReportLayout *layout)
{
    if (state->usage_page == 7) {
        if (layout->keyboard.key_count != 0 ||
            (state->keyboard_selected && state->keyboard_id != state->report_id))
            return;
        layout->keyboard.key_bit_offset = (unsigned short)state->offset;
        layout->keyboard.key_count = (unsigned char)state->report_count;
        layout->keyboard.key_width = (unsigned char)state->report_size;
        unsigned short minimum = state->range_present ? (unsigned short)state->usage_minimum : 0;
        unsigned short maximum = state->range_present ? (unsigned short)state->usage_maximum : 0;
        state->keyboard_id = state->report_id;
        state->keyboard_selected = 1;
        layout->keyboard.usage_minimum = minimum;
        layout->keyboard.usage_maximum = maximum;
    } else if (state->usage_page == 12) {
        if (layout->consumer.count != 0 ||
            (state->consumer_selected && state->consumer_id != state->report_id))
            return;
        layout->consumer.bit_offset = (unsigned short)state->offset;
        layout->consumer.count = (unsigned char)state->report_count;
        layout->consumer.width = (unsigned char)state->report_size;
        unsigned short minimum = state->range_present ? (unsigned short)state->usage_minimum : 0;
        unsigned short maximum = state->range_present ? (unsigned short)state->usage_maximum : 0;
        state->consumer_id = state->report_id;
        layout->consumer_usage_minimum = minimum;
        layout->consumer_usage_maximum = maximum;
        state->consumer_selected = 1;
    }
}

static __attribute__((always_inline)) inline bool hid_process_input(
    HidDecoderState *state,volatile HidReportLayout *layout,unsigned int flags)
{
    if (state->report_size == 0)
        return false;
    hid_account_unsupported(state, flags);
    unsigned int x_present = layout->axes[0].enabled;
    bool constant = (flags & 1U) != 0;
    bool variable = (flags & 2U) != 0;
    bool relative = (flags & 4U) != 0;
    if (!constant) {
        if (variable)
            hid_classify_variable(state, layout, flags, &x_present);
        else
            hid_classify_array(state, layout);
    }
    bool rejected = false;
    for (unsigned int field = 0; field != state->report_count; ++field) {
        if (!constant && variable && relative) {
            unsigned int index = layout->field_count;
            if (state->report_size > 32 || index > 11) {
                rejected = true;
                break; /* Specialized writes survive; this field does not advance. */
            }
            layout->fields[index].bit_offset = (unsigned short)state->offset;
            layout->fields[index].width = (unsigned char)state->report_size;
            layout->fields[index].minimum = (int)state->logical_minimum;
            state->generic_ids[index] = (unsigned char)state->report_id;
            layout->fields[index].maximum = (int)state->logical_maximum;
            layout->field_count = (unsigned char)(index + 1U);
        }
        state->offset = (unsigned short)(state->offset + state->report_size);
        if (state->offset > 512) {
            rejected = true;
            break;
        }
    }
    if (x_present != 0 && state->report_id == state->axis_ids[0])
        state->primary_bits = state->offset;
    if (state->keyboard_selected && state->report_id == state->keyboard_id)
        state->keyboard_bits = state->offset;
    if (state->consumer_selected && state->report_id == state->consumer_id)
        state->consumer_bits = state->offset;
    return !rejected;
}

static __attribute__((always_inline)) inline unsigned int hid_finish_metadata(
    HidDecoderState *state,volatile HidReportLayout *layout)
{
    if (state->parts_changed)
        state->parts.count = (unsigned char)state->part_count;
    unsigned int keys = layout->keyboard.key_count;
    layout->keyboard.bitmap_key_count = (unsigned short)
        (state->keyboard_total < 65535U ? state->keyboard_total : 65535U);
    if (state->keyboard_invalid) {
        layout->keyboard.enabled = 0;
    } else {
        if (keys == 0)
            keys = layout->keyboard.range_count;
        layout->keyboard.enabled = keys != 0;
        if (keys != 0) {
            layout->keyboard.report_id = state->has_ids ? (unsigned char)state->keyboard_id : 0;
            unsigned int bits = state->keyboard_bits;
            if ((unsigned short)(bits - 1U) > 511 || (bits & 7U) != 0)
                layout->keyboard.enabled = 0;
            else
                layout->keyboard.expected_length = (unsigned short)(bits >> 3);
        }
    }
    unsigned int consumers = layout->consumer.count;
    layout->consumer.enabled = consumers != 0;
    if (consumers != 0) {
        layout->consumer.report_id = state->has_ids ? (unsigned char)state->consumer_id : 0;
        unsigned int bits = state->consumer_bits;
        if (bits == 0 || (bits & 7U) != 0 || bits > 512)
            layout->consumer.enabled = 0;
        else
            layout->consumer.expected_length = (unsigned short)(bits >> 3);
    }
    unsigned int primary_bits;
    bool invalid;
    if (state->has_ids) {
        if (layout->axes[0].enabled == 0)
            goto invalid_primary;
        layout->report_id = (unsigned char)state->axis_ids[0];
        for (unsigned int axis = 1; axis != 4; ++axis) {
            if (layout->axes[axis].enabled != 0 && state->axis_ids[axis] != state->axis_ids[0])
                layout->axes[axis].enabled = 0;
        }
        if (layout->button_count != 0 && state->button_id != state->axis_ids[0])
            layout->button_count = 0;
        primary_bits = state->primary_bits;
        invalid = primary_bits == 0;
        unsigned int count = layout->field_count;
        unsigned int vendor_count;
        if (count != 0) {
            unsigned int retained = 0;
            for (unsigned int index = 0; index != count; ++index) {
                if (state->generic_ids[index] != state->axis_ids[0])
                    continue;
                unsigned int header = layout->fields[index].packed;
                unsigned int minimum = (unsigned int)layout->fields[index].minimum;
                layout->fields[retained].packed = header;
                unsigned int maximum = (unsigned int)layout->fields[index].maximum;
                layout->fields[retained].minimum = (int)minimum;
                layout->fields[retained].maximum = (int)maximum;
                retained = (unsigned char)(retained + 1U);
            }
            vendor_count = layout->output_count;
            layout->field_count = (unsigned char)retained;
            invalid |= retained == 0;
        } else {
            vendor_count = layout->output_count;
            if (vendor_count == 0)
                goto invalid_primary;
            invalid = true;
        }
        unsigned int retained = 0;
        for (unsigned int index = 0; index != vendor_count; ++index) {
            if (state->vendor_ids[index] != state->axis_ids[0])
                continue;
            unsigned short offset = layout->byte_clamps[index].byte_offset;
            short minimum = layout->byte_clamps[index].minimum;
            layout->byte_clamps[retained].byte_offset = offset;
            short maximum = layout->byte_clamps[index].maximum;
            layout->byte_clamps[retained].minimum = minimum;
            layout->byte_clamps[retained].maximum = maximum;
            state->vendor_ids[retained] = (unsigned char)state->axis_ids[0];
            retained = (unsigned char)(retained + 1U);
        }
        layout->output_count = (unsigned char)retained;
    } else {
        unsigned int count = layout->field_count;
        primary_bits = state->offset;
        invalid = count == 0 || primary_bits == 0;
        layout->report_id = 0;
    }
    if (invalid || (primary_bits & 7U) != 0)
        goto invalid_primary;
    layout->first_unsupported_bit = 65535;
    unsigned int safe = 0;
    bool matched = false;
    unsigned int part_count = state->parts.count;
    if (part_count != 0) {
        unsigned int id = layout->report_id;
        for (unsigned int slot = 0; slot != part_count; ++slot) {
            if (state->parts.report_ids[slot] != id)
                continue;
            unsigned int first = state->parts.first_offset[slot];
            unsigned int bits = state->parts.bits[slot];
            *(volatile unsigned int *)&layout->unsupported_bits = bits | (first << 16);
            safe = bits == 0;
            matched = true;
            break;
        }
    }
    if (!matched && layout->unsupported_bits == 0)
        safe = (unsigned char)(state->parts.overflow ^ 1U);
    unsigned int bytes = (primary_bits >> 3) & 65535U;
    layout->raw_capture_safe = (unsigned char)safe;
    layout->expected_length = (unsigned short)bytes;
    if ((unsigned short)(bytes - 1U) <= 63) {
        layout->enabled = 1;
        return 1;
    }
invalid_primary:
    layout->enabled = 0;
    return 0;
}

/* Native entry: 0x42024ce0. */
/* Original function-byte SHA-256:
 * f20224855823f2f72694535a6e01c406a91a32b47cf8b48d2ba2b3c7eceb6172. */
/* Decode HID short items into the304-byte report layout. Return primary-report
 * validity0/1, independently of keyboard/consumer validity. Clear304 output bytes
 * before checking descriptorNULL, preserving overlap effects; no output NULL or
 * span check is supplied. length is low16. Clear exactly82 bytes of the separate
 * unsupported-part table. Long itemFE, truncated value and Global Push/Pop reject
 * immediately, clearing only primary enabled again; prior field writes survive.
 *
 * Values are unsigned little endian0/1/2/4 bytes. Logical min/max independently
 * sign-extend one/two-byte values. Page narrows16, Size and iteration Count8;
 * retain the full Count WORD for wrapping unsupported-bit multiplication. Local
 * Usage retains first16 values and repeats its last value for extra fields;
 * every four-byte Usage marks wide even after capacity. Either range bound marks
 * range-present; clearing local state retains the two range words. Output,
 * Collection/Feature variants, EndCollection and completed Inputs clear local
 * usage count/wide/range state. Unknown items otherwise leave state unchanged.
 *
 * Report ID saves current offset in an independent16-ID cache, updating existing
 * IDs even at capacity, then restores the new low8 ID offset or defaults to8.
 * Initial implicit ID0 starts at0; explicit ID0 can restore it. Every Input needs
 * nonzero size and finds/adds one of16 unsupported-part IDs, even with Count0.
 * A17th ID latches overflow. Supported relative variable, one-bit Button and
 * Keyboard/Consumer array Inputs contribute zero only when nonconstant and not
 * wide-Usage. Otherwise Size8*Count32 wraps32; add old bits16 with wrap32, then
 * saturate65535. First nonzero contribution records current offset. A later wrap
 * can reduce a saturated count. Unsupported accounting does not block decoding.
 *
 * Nonconstant variables classify the first Button span, keyboard modifiers or up
 * to eight bitmap ranges, first X/Y/wheel/pan occurrences, and up to two aligned
 * signed vendor bytes. Keyboard ID locks on eligible fields including Count0;
 * foreign bitmap fields still add to its wrapping aggregate count. Usage ranges
 * do not synthesize axes. Arrays retain first nonzero-count Keyboard/Consumer
 * span for an eligible ID; zero-count spans can still select the ID. Bounds use
 * range words only when range-present. Each relative variable field additionally
 * appends a generic12-byte entry; Size>32 or entry13 rejects before that field's
 * advance, after specialized writes. All other fields advance too. Offset wraps16
 * per Size8/Count8 iteration; >512 rejects after the advance. Update lengths for
 * matching X/keyboard/consumer IDs before rejecting an aborted Input.
 *
 * Normal finalization publishes saturated bitmap count and independent keyboard /
 * consumer flags/IDs/byte lengths, requiring presence, no keyboard overflow and
 * aligned1..512 bits. Modifier-only data does not enable keyboard. With ID items,
 * X must exist; choose its ID, disable foreign axes/buttons and compact matching
 * generic/vendor entries without clearing their old tails. Without IDs choose0
 * and the current offset, with no X requirement or compaction. A retained generic
 * field and nonzero aligned primary bits are required. Then initialize unsupported
 * offsetFFFF, publish a matched bits/offset pair as one WORD, derive raw-safe from
 * matched bits0 or no-match/no-overflow, and publish length. Only1..64 bytes sets
 * primary enabled and returns1. Error does not roll back independent metadata.
 * No allocation, RTOS, UART, MMIO, notification, report I/O or lifetime guarantee.
 */
unsigned int medius_hid_decode_report_metadata(const unsigned char *descriptor,
    unsigned short length,HidReportLayout *storage)
{
    memset(storage, 0, 304);
    if (descriptor == NULL)
        return 0;
    volatile HidReportLayout *layout = storage;
    const volatile unsigned char *bytes = descriptor;
    HidDecoderState state;
    memset(&state.parts, 0, 82);
    state.usage_count = state.wide_usage = state.range_present = 0;
    state.usage_minimum = state.usage_maximum = state.usage_page = 0;
    state.report_size = state.report_count = state.report_count_full = 0;
    state.logical_minimum = state.logical_maximum = state.report_id = state.offset = 0;
    state.has_ids = state.cache_count = state.button_id = state.primary_bits = 0;
    state.axis_ids[0] = state.axis_ids[1] = state.axis_ids[2] = state.axis_ids[3] = 0;
    state.keyboard_selected = state.keyboard_id = state.keyboard_bits = 0;
    state.keyboard_total = state.keyboard_invalid = 0;
    state.consumer_selected = state.consumer_id = state.consumer_bits = 0;
    state.part_count = state.parts_changed = 0;
    unsigned int cursor = 0;
    while (cursor < length) {
        unsigned int prefix = bytes[cursor];
        if (prefix == 0xfe)
            goto reject;
        unsigned int width = prefix & 3U;
        if (width == 3)
            width = 4;
        unsigned int data_cursor = (unsigned short)(cursor + 1U);
        if (data_cursor + width > length)
            goto reject;
        unsigned int value = 0;
        for (unsigned int index = 0; index != width; ++index)
            value |= (unsigned int)bytes[cursor + 1U + index] << (index * 8U);
        unsigned int item = prefix & 0xfcU;
        if (item == 0x74) {
            state.report_size = (unsigned char)value;
        } else if (item == 0x94) {
            state.report_count = (unsigned char)value;
            state.report_count_full = value;
        } else if (item == 0x14) {
            state.logical_minimum = hid_signed_item(value, width);
        } else if (item == 0x24) {
            state.logical_maximum = hid_signed_item(value, width);
        } else if (item == 0x04) {
            state.usage_page = (unsigned short)value;
        } else if (item == 0x08) {
            if (state.usage_count <= 15)
                state.usages[state.usage_count++] = value;
            state.wide_usage |= width == 4;
        } else if (item == 0x18) {
            state.usage_minimum = value;
            state.range_present = 1;
        } else if (item == 0x28) {
            state.usage_maximum = value;
            state.range_present = 1;
        } else if (item == 0x84) {
            hid_select_report_id(&state, value);
        } else if (item == 0x80) {
            if (state.report_size == 0)
                goto reject; /* Native rejects before rereading Input flag bytes. */
            unsigned int flags = width == 0 ? 0 : bytes[cursor + 1U];
            if (!hid_process_input(&state, layout, flags))
                goto reject;
            state.usage_count = state.wide_usage = state.range_present = 0;
        } else if (item == 0x90 || (item > 0x94 &&
                ((prefix & 0xecU) == 0xa0 || item == 0xc0))) {
            state.usage_count = state.wide_usage = state.range_present = 0;
        } else if (item > 0x94 && (prefix & 0xecU) == 0xa4) {
            goto reject;
        }
        cursor = (unsigned short)(data_cursor + width);
    }
    return hid_finish_metadata(&state, layout);
reject:
    layout->enabled = 0;
    return 0;
}
