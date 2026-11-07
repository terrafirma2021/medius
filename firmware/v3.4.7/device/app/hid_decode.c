/* Device keyboard/consumer decoding and report-change policy. */

#include <stddef.h>
#include "../include/types.h"

/* Native entry: 0x42026a60. */
/* Original function-byte SHA-256:
 * d12b26c207c040bf47d124c43bbd0d7f652650c6d797a40fc4d7767c888d36a2. */
/* Decode an ordered unique key list through a256-bit temporary bitmap.
 * LOW16(length) bounds report reads; LOW8(capacity) bounds output keys. The
 * required modifier output is written first,with at most8 described bits.
 * Bitmap mode visits every declared range bit,wrapping report addresses16
 * bits and mapped usages8 bits; missing bytes are skipped. Range count and
 * counts are not repaired: caller supplies all declared range records.
 * Array mode requires byte-aligned8-bit slots and records values2..255,
 * ignoring0 and1. Output usage order is ascending and duplicates collapse.
 * No enabled/report-ID/expected-length check,lock or barrier occurs here.
 * Return copied key count; capacity0 still computes modifiers andbitmap. */
unsigned int hid_decode_keyboard(const HidKeyboardLayout *layout,
    const unsigned char *report,unsigned int length,unsigned char *modifiers,
    unsigned char *keys,unsigned int capacity)
{
    const volatile HidKeyboardLayout *keyboard_layout = layout;
    const volatile unsigned char *bytes = report;
    unsigned int bound = (unsigned short)length;
    unsigned int limit = (unsigned char)capacity;
    unsigned int modifier_width = keyboard_layout->modifier_width;
    unsigned int modifier_bits = 0;
    if (modifier_width != 0) {
        unsigned int start = keyboard_layout->modifier_bit_offset;
        if (modifier_width > 8)
            modifier_width = 8;
        for (unsigned int index = 0; index < modifier_width; ++index) {
            unsigned int bit = (start + index) & 65535U;
            if ((bit >> 3) < bound && (bytes[bit >> 3] & (1U << (bit & 7U))) != 0)
                modifier_bits |= 1U << index;
        }
    }
    *modifiers = (unsigned char)modifier_bits;
    unsigned char bitmap[32];
    memset(bitmap,0,32);
    if (keyboard_layout->bitmap_mode != 0) {
        unsigned int ranges = keyboard_layout->range_count;
        for (unsigned int range_index = 0; range_index < ranges; ++range_index) {
            const volatile HidBitmapRange *range = (const volatile void *)
                ((const unsigned char *)layout + offsetof(HidKeyboardLayout,ranges) +
                    range_index * sizeof(HidBitmapRange));
            unsigned int count = range->count;
            if (count == 0)
                continue;
            unsigned int start = range->bit_offset;
            for (unsigned int index = 0; index < count; ++index) {
                unsigned int bit = (start + index) & 65535U;
                if ((bit >> 3) >= bound || (bytes[bit >> 3] & (1U << (bit & 7U))) == 0)
                    continue;
                unsigned int usage = (index + range->usage_base) & 255U;
                bitmap[usage >> 3] |= (unsigned char)(1U << (usage & 7U));
            }
        }
    } else if (keyboard_layout->key_width == 8) {
        unsigned int start = keyboard_layout->key_bit_offset;
        if ((start & 7U) == 0) {
            unsigned int slots = keyboard_layout->key_count;
            unsigned int offset = start >> 3;
            unsigned int end = offset + slots;
            while (offset < end && offset < bound) {
                unsigned int usage = bytes[offset++];
                if (usage > 1)
                    bitmap[usage >> 3] |= (unsigned char)(1U << (usage & 7U));
            }
        }
    }
    unsigned int copied = 0;
    if (limit != 0) {
        for (unsigned int usage = 0; usage < 256; ++usage) {
            if ((bitmap[usage >> 3] & (1U << (usage & 7U))) != 0)
                keys[copied++] = (unsigned char)usage;
            if (copied >= limit)
                break;
        }
    }
    return copied;
}

/* Native entry: 0x42026bc0. */
/* Original function-byte SHA-256:
 * 9e51462817f1b230bd44bb20f7c0c3218a7c3fc199e1df4cf211c24d98a017f5. */
/* Return1 for byte value1 in a nonempty,byte-aligned8-bit key array,else0.
 * Uses signed full-word length,not LOW16; a missing byte stops with0. It does
 * not test bitmap mode,enabled/report ID or other HID error values. No writes,
 * fences or locks; layout/report must cover bytes actually inspected. */
unsigned char hid_keyboard_has_rollover(const HidKeyboardLayout *layout,
    const unsigned char *report,int length)
{
    const volatile HidKeyboardLayout *keyboard_layout = layout;
    unsigned int count = keyboard_layout->key_count;
    if (count == 0 || keyboard_layout->key_width != 8)
        return 0;
    unsigned int offset = keyboard_layout->key_bit_offset;
    if ((offset & 7U) != 0)
        return 0;
    offset >>= 3;
    unsigned int end = offset + count;
    do {
        if ((int)offset >= length)
            return 0;
        if (((const volatile unsigned char *)report)[offset++] == 1)
            return 1;
    } while (offset != end);
    return 0;
}

/* Native entry: 0x42027230. */
/* Original function-byte SHA-256:
 * 527637271c2c74b76bad1c62ae2a9a05813d3d986e4bc132da5417669f03e294. */
/* Decode byte-aligned16-bit little-endian consumer usages. LOW16(length) must
 * cover both bytes; LOW8(capacity) bounds writes. Read HIGH byte before LOW,
 * omit zero usages,retain duplicates,then selection-sort in ascending order.
 * Each sorting comparison reads right before left and swaps immediately.
 * Return count0..255. Reject other widths,unaligned offset or count0 with0;
 * enabled/report-ID/expected-length are not checked. No fence or lock. */
unsigned int hid_decode_consumer(const HidConsumerLayout *layout,
    const unsigned char *report,unsigned int length,unsigned short *usages,unsigned int capacity)
{
    const volatile HidConsumerLayout *consumer_layout = layout;
    if (consumer_layout->width != 16)
        return 0;
    unsigned int start = consumer_layout->bit_offset;
    if ((start & 7U) != 0)
        return 0;
    unsigned int slots = consumer_layout->count;
    if (slots == 0)
        return 0;
    unsigned int bound = (unsigned short)length,limit = (unsigned char)capacity;
    unsigned int offset = start >> 3,copied = 0;
    unsigned int end = offset + slots * 2U;
    const volatile unsigned char *bytes = report;
    volatile unsigned short *output = usages;
    while (offset != end && offset + 1U < bound && copied < limit) {
        unsigned int high = bytes[offset + 1];
        unsigned int low = bytes[offset];
        unsigned int usage = low | (high << 8);
        offset += 2;
        if (usage != 0)
            output[copied++] = (unsigned short)usage;
    }
    for (unsigned int left = 0; left + 1 < copied; ++left) {
        for (unsigned int right = left + 1; right < copied; ++right) {
            unsigned short candidate = output[right];
            unsigned short selected = output[left];
            if (candidate < selected) {
                output[left] = candidate;
                output[right] = selected;
            }
        }
    }
    return copied;
}

/* Native entry: 0x4038c5dc. */
/* Original function-byte SHA-256:
 * 40326346f023a6ced48228c0da0cbeea780e18e02d643f1929a212751a0d29bb. */
/* Decide whether the incoming report needs emission/update,not generic equality.
 * Only LOW16(length) is used. Primary mouse mode requires axis0 enabled and
 * incoming ID match (or ID0): any nonzero described relative field requires
 * update regardless of previous contents; otherwise compare only button bits.
 * Field enabled flags are ignored. Field count is cached,unchecked; caller
 * supplies every described12-byte record. Buttons wrap16 and skip missingbytes.
 *
 * Otherwise matching keyboard mode accepts bitmaps or aligned8-bit arrays.
 * Reject either report containing array rollover value1; then decode modifiers
 * and up to64 unique keys and compare those lists. Matching aligned16-bit
 * consumer mode compares up to32 sorted nonzero usages,retaining duplicates.
 * Other layouts fall back to memcmp over the supplied bound. Only INCOMING ID
 * is gated; the previous ID is not independently checked. Selected IDs can read
 * byte0 even for length0,so caller must supply it. No lock or state writes.
 * Return exactly0/1. Keyboard/consumer temporary capacities are fixed,native. */
int hid_report_needs_update(const HidReportLayout *layout,
    const unsigned char *incoming,const unsigned char *previous,unsigned int length)
{
    const volatile HidReportLayout *report_layout = layout;
    unsigned int bound = (unsigned short)length;
    const volatile unsigned char *incoming_bytes = incoming,*previous_bytes = previous;
    if (report_layout->axes[0].enabled != 0) {
        unsigned int report_id = report_layout->report_id;
        if (report_id == 0 || incoming_bytes[0] == report_id) {
            unsigned int count = report_layout->field_count;
            for (unsigned int index = 0; index < count; ++index) {
                const volatile ReportNumericField *field = (const volatile void *)
                    ((const unsigned char *)layout + offsetof(HidReportLayout,fields) +
                        index * sizeof(ReportNumericField));
                unsigned int width = field->width;
                unsigned int offset = field->bit_offset;
                if (width != 0 && hid_read_bits(incoming,bound,offset,width) != 0)
                    return 1;
            }
            unsigned int width = report_layout->button_count;
            unsigned int bit = report_layout->button_bit_offset;
            unsigned int end = (bit + width) & 65535U;
            if (width != 0) {
                do {
                    unsigned int byte = bit >> 3;
                    unsigned int mask = 1U << (bit & 7U);
                    bit = (bit + 1) & 65535U;
                    if (byte < bound) {
                        unsigned int incoming_byte = incoming_bytes[byte];
                        unsigned int previous_byte = previous_bytes[byte];
                        if (((incoming_byte ^ previous_byte) & mask) != 0)
                            return 1;
                    }
                } while (bit != end);
            }
            return 0;
        }
    }
    const volatile HidKeyboardLayout *keyboard = &report_layout->keyboard;
    if (keyboard->enabled != 0) {
        unsigned int id = keyboard->report_id;
        if (id == 0 || incoming_bytes[0] == id) {
            unsigned int bitmap = keyboard->bitmap_mode;
            unsigned int supported = bitmap != 0;
            if (bitmap == 0 && keyboard->key_width == 8)
                supported = (keyboard->key_bit_offset & 7U) == 0;
            if (supported != 0) {
                const HidKeyboardLayout *keyboard_layout = &layout->keyboard;
                if (hid_keyboard_has_rollover(keyboard_layout,incoming,(int)bound) != 0 ||
                    hid_keyboard_has_rollover(keyboard_layout,previous,(int)bound) != 0)
                    return 1;
                unsigned char first_keys[64],second_keys[64],first_modifiers,second_modifiers;
                unsigned int first_count = hid_decode_keyboard(keyboard_layout,incoming,bound,
                    &first_modifiers,first_keys,64);
                unsigned int second_count = hid_decode_keyboard(keyboard_layout,previous,bound,
                    &second_modifiers,second_keys,64);
                return first_modifiers != second_modifiers || first_count != second_count ||
                    memcmp(first_keys,second_keys,first_count) != 0;
            }
        }
    }
    const volatile HidConsumerLayout *consumer = &report_layout->consumer;
    if (consumer->enabled != 0) {
        unsigned int id = consumer->report_id;
        if ((id == 0 || incoming_bytes[0] == id) && consumer->width == 16 &&
            (consumer->bit_offset & 7U) == 0) {
            unsigned short first_usages[32],second_usages[32];
            const HidConsumerLayout *consumer_layout = &layout->consumer;
            unsigned int first_count = hid_decode_consumer(consumer_layout,incoming,bound,first_usages,32);
            unsigned int second_count = hid_decode_consumer(consumer_layout,previous,bound,second_usages,32);
            return first_count != second_count ||
                memcmp(first_usages,second_usages,(first_count & 65535U) * 2U) != 0;
        }
    }
    return memcmp(incoming,previous,bound) != 0;
}
