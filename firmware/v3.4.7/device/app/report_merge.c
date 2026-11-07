/* Device packed HID report merging and residual-motion accumulation. */

#include "../include/types.h"

/* Native entry: 0x4202a1e4. */
/* Original function-byte SHA-256:
 * c0679046b791fd8351cb43204c34d7849fd485e7ba0fec1b10beb3e8cb62e572. */
/* Under the credit spinlock, copy four signed32 accumulated axes to local
 * storage, zero their shared16-byte region, fence/clear the merge-pending
 * byte, then unlock. The infinite-wait lock result is ignored. Clamp each
 * LOCAL axis to [-32768,32767] and admit those signed16 values to the fixed
 * primary input state after unlocking. Excess motion is discarded; even an
 * all-zero snapshot calls the accumulator. Later producer writes survive.
 * No allocation, timestamp read, report emission or pending-byte recheck. */
void report_merge_drain_motion(void)
{
    int motion[4];
    (void)xPortEnterCriticalTimeout(&CREDIT_LOCK,0xffffffffU);
    memcpy(motion,(const void *)REPORT_MERGE_ACCUMULATORS,16);
    memset((void *)REPORT_MERGE_ACCUMULATORS,0,16);
    memw();
    REPORT_MERGE_PENDING = 0;
    vPortExitCritical(&CREDIT_LOCK);
    for (unsigned int axis = 0; axis < 4; ++axis) {
        if (motion[axis] < -32768)
            motion[axis] = -32768;
        if (motion[axis] > 32767)
            motion[axis] = 32767;
    }
    input_accumulate_motion(INPUT0_STATE,(short)motion[0],
        (short)motion[1],(short)motion[2],(short)motion[3]);
}

/* Native entry: 0x4038c254. */
/* Original function-byte SHA-256:
 * a60e904672fe3e1ac9aa01ddd4101205595a9374c6a20be9573fa6275f37ff3a. */

/*
 * layout: readable merge context; stored/incoming: readable length-byte spans.
 * Returns 1 if every selected in-range bit agrees, otherwise 0 at first mismatch.
 * Cache the button count, then the button bit offset. The interval end and cursor wrap
 * at 16 bits. Out-of-range byte positions are skipped, not an early stop; input
 * is read before stored at each in-range bit. Zero width returns 1 without a
 * buffer access. No mutation, lock, fence or NULL check is supplied.
 */
int report_buttons_equal(const HidReportLayout *layout,
    const unsigned char *stored,const unsigned char *incoming,unsigned short length)
{
    const volatile HidReportLayout *layout_fields = layout;
    unsigned int width = layout_fields->button_count;
    if (width == 0)
        return 1;
    unsigned int bit = layout_fields->button_bit_offset;
    unsigned int end = (bit + width) & 65535U;
    do {
        unsigned int byte = bit >> 3;
        unsigned int position = bit & 7U;
        bit = (bit + 1U) & 65535U;
        if (byte < length) {
            unsigned int input = ((const volatile unsigned char *)incoming)[byte];
            unsigned int previous = ((const volatile unsigned char *)stored)[byte];
            if (((input ^ previous) & (1U << position)) != 0)
                return 0;
        }
    } while (bit != end);
    return 1;
}

/* Native entry: 0x4038bf54. */
/* Original function-byte SHA-256:
 * dd3c972eac637087f240909605b6da88375a88bdd42eb426ba81feb8d745b93c. */

/*
 * layout: readable 304-byte context, stable valid field table (count <= 12).
 * selectors: optional two bytes; stored: writable length-byte report;
 * incoming: readable length-byte report; length: 16-bit byte bound.
 * overflow: optional writable 12-word array, always zeroed FIRST when supplied.
 * Returns no value. Caller supplies synchronization and valid borrowed storage.
 * No locks, explicit fences, allocation or local count/width repair occurs.
 *
 * A disabled/mismatched length/report ID copies incoming without field merging.
 * Otherwise cache field_count for the compute pass. Extract stored then input
 * bits, wrapping bit addresses at 16 bits and value-bit shifts modulo 32.
 * Widths 1..31 sign-extend; >=32 retain the assembled word. Add modulo 32 BEFORE
 * signed clamping: use configured [minimum,maximum] if min < max, otherwise the
 * width's signed range for 1..31, no clamp for >=32, and value 0 for width 0.
 * Save clamped words locally and optional modulo32(sum-clamped) overflow.
 *
 * Copy incoming, then reread count/field width/offset and rewrite merged bits.
 * Nonzero-width fields reload count after writing or a byte-bound break; zero
 * width keeps the cached count. Bit writes reread the destination byte each time.
 * Finally optional selectors process at most two byte clamps: bit7 skips, zero
 * selects channel0, other bytes select channel1. Extract that signed channel,
 * apply signed16 min THEN max, and store LOW8 at the configured byte offset.
 * Reload output_count only after an actual byte store. No bounds repair beyond
 * per-byte length tests; table/count mutation is not an atomic snapshot.
 */
void report_merge_fields(const HidReportLayout *layout,
    const unsigned char *selectors,unsigned char *stored,const unsigned char *incoming,
    unsigned short length,int *overflow)
{
    const volatile HidReportLayout *layout_fields = layout;
    if (overflow != NULL)
        memset(overflow,0,48);
    if (layout_fields->enabled == 0 || layout_fields->expected_length != length)
        goto copy_only;
    unsigned int report_id = layout_fields->report_id;
    if (report_id != 0 && (length == 0 || ((const volatile unsigned char *)incoming)[0] != report_id))
        goto copy_only;
    unsigned int values[12];
    unsigned int count = layout_fields->field_count;
    for (unsigned int index = 0; index < count; ++index) {
        const volatile ReportNumericField *field = &layout_fields->fields[index];
        unsigned int width = field->width;
        unsigned int start = field->bit_offset;
        unsigned int previous = 0,input = 0;
        for (unsigned int bit = 0; bit < width; ++bit) {
            unsigned int position = (start + bit) & 65535U;
            unsigned int byte = position >> 3;
            if (byte >= length)
                break;
            unsigned int data = ((const volatile unsigned char *)stored)[byte];
            if (((data >> (position & 7U)) & 1U) != 0)
                previous |= 1U << (bit & 31U);
        }
        if (width != 0 && width < 32 && (previous & (1U << (width - 1U))) != 0)
            previous |= 0U - (1U << width);
        for (unsigned int bit = 0; bit < width; ++bit) {
            unsigned int position = (start + bit) & 65535U;
            unsigned int byte = position >> 3;
            if (byte >= length)
                break;
            unsigned int data = ((const volatile unsigned char *)incoming)[byte];
            if (((data >> (position & 7U)) & 1U) != 0)
                input |= 1U << (bit & 31U);
        }
        int minimum = field->minimum;
        int maximum = field->maximum;
        if (width != 0 && width < 32 && (input & (1U << (width - 1U))) != 0)
            input |= 0U - (1U << width);
        unsigned int sum = previous + input;
        int merged = (int)sum;
        if (minimum < maximum) {
            if (merged > maximum)
                merged = maximum;
            else if (merged < minimum)
                merged = minimum;
        } else if (width < 32) {
            if (width == 0) {
                merged = 0;
            } else {
                int positive = (int)((1U << (width - 1U)) - 1U);
                int negative = (int)(0U - (1U << (width - 1U)));
                if (merged > positive)
                    merged = positive;
                else if (merged < negative)
                    merged = negative;
            }
        }
        values[index] = (unsigned int)merged;
        if (overflow != NULL)
            ((volatile int *)overflow)[index] = (int)(sum - (unsigned int)merged);
    }
    memcpy(stored,incoming,length);
    count = layout_fields->field_count;
    unsigned int index = 0;
    while (index < count) {
        unsigned int width = layout_fields->fields[index].width;
        unsigned int start = layout_fields->fields[index].bit_offset;
        unsigned int value = values[index];
        if (width != 0) {
            for (unsigned int bit = 0; bit < width; ++bit) {
                unsigned int position = (start + bit) & 65535U;
                unsigned int byte = position >> 3;
                if (byte >= length)
                    break;
                unsigned int original = ((volatile unsigned char *)stored)[byte];
                unsigned int mask = 1U << (position & 7U);
                unsigned int replacement = (value & (1U << (bit & 31U))) != 0 ?
                    original | mask : original ^ (original & mask);
                ((volatile unsigned char *)stored)[byte] = replacement;
            }
            count = layout_fields->field_count;
        }
        index = (index + 1U) & 255U;
    }
    if (selectors != NULL) {
        unsigned int outputs = layout_fields->output_count;
        if (outputs != 0) {
            for (unsigned int output = 0; output < 2; ++output) {
                unsigned int selector = ((const volatile unsigned char *)selectors)[output];
                if ((selector & 128U) == 0) {
                    const volatile ReportNumericField *channel = &layout_fields->axes[selector != 0];
                    if (channel->enabled != 0) {
                        unsigned int byte_offset = layout_fields->byte_clamps[output].byte_offset;
                        if (byte_offset < length) {
                            unsigned int width = channel->width;
                            unsigned int start = channel->bit_offset;
                            unsigned int value = 0;
                            for (unsigned int bit = 0; bit < width; ++bit) {
                                unsigned int position = (start + bit) & 65535U;
                                unsigned int byte = position >> 3;
                                if (byte >= length)
                                    break;
                                unsigned int data = ((volatile unsigned char *)stored)[byte];
                                if (((data >> (position & 7U)) & 1U) != 0)
                                    value |= 1U << (bit & 31U);
                            }
                            if (width != 0 && width < 32 && (value & (1U << (width - 1U))) != 0)
                                value |= 0U - (1U << width);
                            int minimum = layout_fields->byte_clamps[output].minimum;
                            int maximum = layout_fields->byte_clamps[output].maximum;
                            int clamped = (int)value;
                            if (clamped < minimum)
                                clamped = minimum;
                            if (clamped > maximum)
                                clamped = maximum;
                            ((volatile unsigned char *)stored)[byte_offset] = clamped;
                            outputs = layout_fields->output_count;
                        }
                    }
                }
                if (output + 1U >= outputs)
                    break;
            }
        }
    }
    return;
copy_only:
    memcpy(stored,incoming,length);
}

/* Native entry: 0x40377ae0. */
/* Original function-byte SHA-256:
 * 03f278c846ca53569d0b3a9c834870d219eb5223d56a9d5eb9a5d6c62ec68b17. */

/*
 * interface: configured 304-byte merge context index. stored/incoming: writable
 * destination/readable input of length bytes. length: LOW16 native byte bound.
 * stored_kind/incoming_kind: raw queue-record kind bytes; either nonzero
 * bypasses button equality guards. These are passed from the two record kinds.
 * Returns 0 for a rejected guard/keyboard-layout comparison, otherwise 1.
 * No local lock, allocation or clock call. Caller serializes report/layout and
 * accumulator state and supplies a valid field_count <= 12 and borrowed spans.
 *
 * Primary enabled/length/report ID selects numeric merging. With both controls
 * zero, selected guard bits must agree first. Otherwise a primary mismatch copies
 * input directly when either control is nonzero. With neither control, mismatch
 * instead requires enabled/matching keyboard length/report ID AND memcmp equality.
 *
 * Primary merge optionally uses input-0 selectors when that interface is active
 * and matches. Its 12-word overflow array is then matched against four enabled
 * axis bit offsets, using a FRESH field count and per-match min/max/width.
 * Symmetric accumulator limit is min(8*(max-min),INT_MAX) for min < max; otherwise
 * min(8*(2^width-1),INT_MAX) for widths 1..31, or INT_MAX. Add in signed64 and clamp
 * to [-limit,+limit]. Store each matching accumulator then fence/set pending=1.
 *
 * Successful processing increments the fenced global merge counter only when
 * both controls are zero OR both are nonzero. One nonzero control skips it.
 * Native low-width wrapping, repeated reads and lack of state/bounds repair remain.
 */
int report_merge_interface(unsigned int interface_index,unsigned char *stored,
    const unsigned char *incoming,unsigned short length,unsigned char stored_kind,
    unsigned char incoming_kind)
{
    const volatile HidReportLayout *layout = &HID_REPORT_LAYOUTS[interface_index];
    unsigned int overrides = stored_kind | incoming_kind;
    if (layout->enabled == 0 || layout->expected_length != length)
        goto primary_mismatch;
    unsigned int report_id = layout->report_id;
    if (report_id != 0 && (length == 0 || ((const volatile unsigned char *)incoming)[0] != report_id))
        goto primary_mismatch;
    if (overrides == 0 && report_buttons_equal(
            (const HidReportLayout *)layout,stored,incoming,length) == 0)
        return 0;
    int overflow[12];
    if (REPORT_BLOCK0_ACTIVE != 0 && REPORT_BLOCK0_INTERFACE == (int)interface_index) {
        report_merge_fields((const HidReportLayout *)layout,
            &INPUT0_STATE->primary_normalization_flags,stored,incoming,length,overflow);
        unsigned int count = layout->field_count;
        for (unsigned int field_index = 0; field_index < count; ++field_index) {
            int residual = overflow[field_index];
            if (residual == 0)
                continue;
            for (unsigned int channel = 0; channel < 4; ++channel) {
                if (layout->axes[channel].enabled == 0)
                    continue;
                unsigned int channel_bit = layout->axes[channel].bit_offset;
                unsigned int field_bit = layout->fields[field_index].bit_offset;
                if (channel_bit != field_bit)
                    continue;
                int minimum = layout->fields[field_index].minimum;
                int maximum = layout->fields[field_index].maximum;
                unsigned long long limit;
                if (minimum < maximum) {
                    limit = (unsigned long long)((long long)maximum - minimum) * 8U;
                } else {
                    unsigned int width = layout->fields[field_index].width;
                    limit = width >= 1 && width <= 31 ?
                        (unsigned long long)((1U << width) - 1U) * 8U : 0x7fffffffU;
                }
                if (limit > 0x7fffffffU)
                    limit = 0x7fffffffU;
                int previous = REPORT_MERGE_ACCUMULATORS[channel];
                long long sum = (long long)previous + residual;
                long long bound = (long long)limit;
                if (sum > bound)
                    sum = bound;
                else if (sum < -bound)
                    sum = -bound;
                REPORT_MERGE_ACCUMULATORS[channel] = (int)sum;
                memw();
                REPORT_MERGE_PENDING = 1;
            }
        }
    } else {
        report_merge_fields((const HidReportLayout *)layout,
            NULL,stored,incoming,length,overflow);
    }
    goto accepted;
primary_mismatch:
    if (overrides == 0) {
        if (layout->keyboard.enabled == 0 || layout->keyboard.expected_length != length)
            return 0;
        unsigned int secondary_id = layout->keyboard.report_id;
        if (secondary_id != 0 && (length == 0 ||
                ((const volatile unsigned char *)incoming)[0] != secondary_id))
            return 0;
        if (memcmp(stored,incoming,length) != 0)
            return 0;
    } else {
        memcpy(stored,incoming,length);
    }
accepted:
    if ((stored_kind == 0) == (incoming_kind == 0)) {
        memw();
        unsigned int count = REPORT_MERGE_COUNT;
        memw();
        REPORT_MERGE_COUNT = count + 1U;
    }
    return 1;
}
