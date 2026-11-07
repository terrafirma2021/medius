/* Device input-state predicates, publication and mouse decoding. */

#include "../include/types.h"

/* Native entry: 0x4038c508. */
/* Original function-byte SHA-256:
 * dc250697919bd3493e3d4bf2acec09f91a5c1595a9f995ecb594be2159d9e0fb. */
/* Return 1 for any forced/cleared button,key or consumer control,else 0.
 * Read buttons first,then each forced/cleared key-byte pair,then each consumer
 * halfword pair. state must cover these arrays; no null check,fence or lock. */
int input_has_forced_controls(const InputStateView *state)
{
    const volatile InputStateView *input_state = state;
    if (input_state->forced_buttons != 0 || input_state->cleared_buttons != 0)
        return 1;
    for (unsigned int index = 0; index < 32; ++index)
        if (input_state->forced_keys[index] != 0 || input_state->cleared_keys[index] != 0)
            return 1;
    for (unsigned int index = 0; index < 8; ++index)
        if (input_state->forced_consumers[index] != 0 || input_state->cleared_consumers[index] != 0)
            return 1;
    return 0;
}

/* Native entry: 0x4038c55c. */
/* Original function-byte SHA-256:
 * 6c215682b05e6251bc1460c61534954d37a3f74fbe51c449a848b77e88b13905. */
/* Test 8 primary and 32 button scale-pair words against 0x00640064,then the
 * keyboard transform byte/two 32-byte flag maps,transform mode and 8 consumer
 * halfwords. Return 1 for a mismatch/nonzero field,except a nonzero transform
 * mode returns that RAW byte. Scan each complete scale/map block before its
 * decision. No mutation,fence or lock; caller supplies readable state. */
unsigned char input_has_transforms(const InputStateView *state)
{
    const volatile InputStateView *input_state = state;
    unsigned int different = 0;
    for (unsigned int index = 0; index < 8; ++index)
        different |= input_state->primary_scale_pairs[index] ^ 0x00640064U;
    if (different != 0)
        return 1;
    for (unsigned int index = 0; index < 32; ++index)
        different |= input_state->button_scale_pairs[index] ^ 0x00640064U;
    if (different != 0)
        return 1;
    unsigned int flags = input_state->keyboard_transform_flags;
    for (unsigned int index = 0; index < 32; ++index) {
        unsigned int rising_flags = input_state->key_rising_suppression[index];
        unsigned int falling_flags = input_state->key_falling_retention[index];
        flags = (flags | rising_flags | falling_flags) & 255U;
    }
    if (flags != 0)
        return 1;
    unsigned char mode = input_state->transform_mode;
    if (mode != 0)
        return mode;
    for (unsigned int index = 0; index < 8; ++index)
        if (input_state->consumer_transforms[index] != 0)
            return 1;
    return 0;
}

/* Native entry: 0x4038c7f4. */
/* Original function-byte SHA-256:
 * 1a8d5e7653af1ed1b2ea1146b11b8beb64cc29c1b572d00a4b2f0dd3be66ec19. */
/* Fence/cache dirty BEFORE reading and clearing changed. If dirty was nonzero
 * or the published halfword is zero,and the sampled active halfword is nonzero,
 * reread active,then fence/clear dirty and active and latch that halfword.
 * Set events_published to exactly 0/1,drain queued events,and return the OLD
 * changed byte. Empty active state leaves dirty/published untouched. No local
 * lock; the drain's state changes occur after publication and can set changed. */
unsigned char input_publish_events(InputStateView *state)
{
    volatile InputStateView *input_state = state;
    memw();
    unsigned int dirty = input_state->dirty;
    unsigned char changed = input_state->changed;
    input_state->changed = 0;
    unsigned int pair = input_state->publication_pair;
    unsigned char published = 0;
    if ((dirty != 0 || pair <= 65535U) && (pair & 65535U) != 0) {
        unsigned short active = input_state->active_count_and_flags;
        memw();
        input_state->dirty = 0;
        input_state->active_count_and_flags = 0;
        input_state->published_count_and_flags = active;
        published = 1;
    }
    input_state->events_published = published;
    input_drain_queued_events(state);
    return changed;
}

/* Native entry: 0x4038c848. */
/* Original function-byte SHA-256:
 * 50f42259153ed93b254e28bf0625aad79142652ef1a561e9e8048609a44cae96. */
/* Return the raw publication-result byte. No fence,null check,write or lock. */
unsigned char input_events_were_published(const InputStateView *state)
{
    return ((const volatile InputStateView *)state)->events_published;
}

/* Native entry: 0x4038c854. */
/* Original function-byte SHA-256:
 * 172866f37f096007a8cc78f0e2c6a5a7163648297273ed973ea4a45b07f20300. */
/* Decode buttons then X,Y,wheel,pan using the state's cached layout pointer
 * and its expected length,not a caller-provided report length. All outputs
 * are required. Buttons use at most 16 bits; out-of-bound bits are skipped.
 * Each enabled axis uses its cached width/offset,16-bit bit-address wrap and
 * modulo32 value shifts; stop at the first missing byte,sign-extend widths 1..31,
 * then clamp to signed16. Disabled/zero-width axes yield 0. Layout min/max are
 * ignored here. Caller supplies expected-length storage; no lock or fences. */
void hid_decode_mouse(const InputStateView *state,const unsigned char *report,
    unsigned short *buttons,short *x,short *y,short *wheel,short *pan)
{
    const volatile HidReportLayout *layout = state->hid_layout;
    unsigned int count = layout->button_count;
    unsigned int length = layout->expected_length;
    unsigned int mask = 0;
    if (count != 0) {
        unsigned int start = layout->button_bit_offset;
        if (count > 16)
            count = 16;
        for (unsigned int index = 0; index < count; ++index) {
            unsigned int bit = (start + index) & 65535U;
            if ((bit >> 3) < length &&
                (((const volatile unsigned char *)report)[bit >> 3] & (1U << (bit & 7U))) != 0)
                mask |= 1U << index;
        }
    }
    *buttons = (unsigned short)mask;
    short *outputs[4] = {x,y,wheel,pan};
    for (unsigned int axis = 0; axis < 4; ++axis) {
        int value = 0;
        if (layout->axes[axis].enabled != 0) {
            unsigned int width = layout->axes[axis].width;
            unsigned int offset = layout->axes[axis].bit_offset;
            value = hid_sign_extend(hid_read_bits(report,length,offset,width),width);
            if (value > 32767)
                value = 32767;
            if (value < -32768)
                value = -32768;
        }
        *outputs[axis] = (short)value;
    }
}

/* Native entry: 0x4038cadc. */
/* Original function-byte SHA-256:
 * e7a564d2a57da338960e53313bc3e58d9b2ac8a9c11b9b242678e806a97cdace. */
/* Add four signed16 deltas to secondary motion words,clamping each signed64
 * sum to [-0x40000000,+0x40000000]. Preserve native pipelining: read the NEXT
 * old word before storing the preceding result. No local lock,fence or result;
 * state must cover all four words. The decompiled code-pointer constants were
 * numeric saturation limits,not function addresses. */
void input_accumulate_motion(InputStateView *state,short x,short y,short wheel,short pan)
{
    volatile InputStateView *input_state = state;
    short deltas[4] = {x,y,wheel,pan};
    int previous = (int)input_state->secondary_words[0];
    for (unsigned int axis = 0; axis < 4; ++axis) {
        long long sum = (long long)previous + deltas[axis];
        if (sum < -0x40000000LL)
            sum = -0x40000000LL;
        if (sum > 0x40000000LL)
            sum = 0x40000000LL;
        int next = 0;
        if (axis != 3)
            next = (int)input_state->secondary_words[axis + 1];
        input_state->secondary_words[axis] = (unsigned int)(int)sum;
        previous = next;
    }
}

/* Native entry: 0x4038cbcc. */
/* Original function-byte SHA-256:
 * c02b87a90b4fad8d1e33b17d6824d5b2bbc1841ee11054d5d8ba4571eeb72e1f. */
/* With nonzero output_count and both X/Y enabled,decode signed X/Y from the
 * expected-length report. For at most two clamp-byte mappings,skip selectors
 * whose high bit is set. Clamp X/Y using signed16 min THEN max,narrow to bytes,
 * and compare the mapped report byte only if those bytes differ: select 0 for
 * X,1 for Y,ff for neither. Equal candidate bytes leave the selector unchanged.
 * Mapped byte offsets have NO bounds check. No fences,locks or output report
 * writes. Field count/widths are cached at their native decision boundaries. */
void input_select_normalization_channels(InputStateView *state,const unsigned char *report)
{
    volatile InputStateView *input_state = state;
    const volatile HidReportLayout *layout = input_state->hid_layout;
    unsigned int count = layout->output_count;
    if (count == 0 || layout->axes[0].enabled == 0 || layout->axes[1].enabled == 0)
        return;
    int values[2];
    unsigned int width = layout->axes[0].width;
    unsigned int length = layout->expected_length;
    unsigned int offset = layout->axes[0].bit_offset;
    values[0] = hid_sign_extend(hid_read_bits(report,length,offset,width),width);
    width = layout->axes[1].width;
    offset = layout->axes[1].bit_offset;
    values[1] = hid_sign_extend(hid_read_bits(report,length,offset,width),width);
    for (unsigned int index = 0; index < count && index < 2; ++index) {
        unsigned char selector = index == 0 ? input_state->primary_normalization_flags :
            input_state->secondary_normalization_flags;
        if ((selector & 0x80U) != 0)
            continue;
        int minimum = layout->byte_clamps[index].minimum;
        int maximum = layout->byte_clamps[index].maximum;
        int clamped_x = values[0] < minimum ? minimum : values[0];
        int clamped_y = values[1] < minimum ? minimum : values[1];
        if (clamped_x > maximum)
            clamped_x = maximum;
        if (clamped_y > maximum)
            clamped_y = maximum;
        unsigned char x_byte = (unsigned char)clamped_x,y_byte = (unsigned char)clamped_y;
        if (x_byte == y_byte)
            continue;
        unsigned int offset = layout->byte_clamps[index].byte_offset;
        unsigned char actual = ((const volatile unsigned char *)report)[offset];
        unsigned char selected = actual == x_byte ? 0 : actual == y_byte ? 1 : 255;
        if (index == 0)
            input_state->primary_normalization_flags = selected;
        else
            input_state->secondary_normalization_flags = selected;
    }
}

/* Native entry: 0x4038cd28. */
/* Original function-byte SHA-256:
 * c17d7159bafeca8692a82c8c8e410a413f5930783582474d9c968adc757c1e30. */
/* Return 64-bit sum of unsigned magnitudes of four secondary/primary word
 * pairs,then X/Y from each 16-byte history sample. Secondary is read BEFORE
 * primary for each pair. Native ABS(INT_MIN) contributes 0x80000000,not signed
 * overflow. History count is an unchecked byte; caller supplies its readable
 * sample span at +0x38. No writes,fences or locks. Ghidra's void/empty-loop body
 * discarded the A2/A3 result and is incorrect for this native entry. */
unsigned long long input_motion_magnitude(const InputStateView *state)
{
    const volatile InputStateView *input_state = state;
    unsigned long long total = 0;
    for (unsigned int axis = 0; axis < 4; ++axis) {
        unsigned int secondary = input_state->secondary_words[axis];
        unsigned int primary = input_state->primary_words[axis];
        total += (int)secondary < 0 ? 0U - secondary : secondary;
        total += (int)primary < 0 ? 0U - primary : primary;
    }
    unsigned int count = input_state->motion_history_count;
    for (unsigned int index = 0; index < count; ++index) {
        const volatile InputMotionSample *sample = (const volatile void *)
            ((const unsigned char *)state + 0x38U + index * 16U);
        int x = sample->x,y = sample->y;
        unsigned int magnitude_x = x < 0 ? (unsigned int)-x : (unsigned int)x;
        unsigned int magnitude_y = y < 0 ? (unsigned int)-y : (unsigned int)y;
        total += magnitude_x + magnitude_y;
    }
    return total;
}

/* Native entry: 0x4038f298. */
/* Original function-byte SHA-256:
 * f0dc34e72ff897b053c725ff7b4beed23cc96fbf85e31557e60c9e57d71f21d5. */
/* Return 1 at the first nonzero saved key-byte,then consumer-halfword;otherwise 0.
 * Does not test button/motion state. No null check,barrier,mutation or lock. */
int input_has_saved_controls(const InputStateView *state)
{
    const volatile InputStateView *input_state = state;
    for (unsigned int index = 0; index < 32; ++index)
        if (input_state->saved_keys[index] != 0)
            return 1;
    for (unsigned int index = 0; index < 8; ++index)
        if (input_state->saved_consumers[index] != 0)
            return 1;
    return 0;
}

/* Native entry: 0x42025d00. */
/* Original function-byte SHA-256:
 * 90c36698f75774a170dbb6b48868bbbae233f6e822aacd92919f22ddbfa547b1. */
/* Return RAW active blocked byte when nonzero,else 1 for active count>=16 or
 * any active event matching full-word kind/value (action ignored). Otherwise
 * fence/read dirty: nonzero permits the event with 0; zero returns whether the
 * published halfword is nonzero. Storage is sampled even for active count 0,
 * but records are dereferenced only for count 1..15. No writes or local lock. */
unsigned char input_event_would_block(const InputStateView *state,
    unsigned int kind,unsigned int value)
{
    const volatile InputStateView *input_state = state;
    unsigned char blocked = input_state->active_event_blocked;
    if (blocked != 0)
        return blocked;
    unsigned int count = input_state->active_event_count;
    if (count >= 16)
        return 1;
    const volatile InputEventStorage *storage = input_state->event_storage;
    for (unsigned int index = 0; index < count; ++index)
        if (storage->active[index].kind == kind && storage->active[index].value == value)
            return 1;
    memw();
    if (input_state->dirty != 0)
        return 0;
    return input_state->publication_pair > 65535U;
}

/* Native entry: 0x4038f2d4. */
/* Original function-byte SHA-256:
 * 50e9236dc51a28d25e9884231ba07395b6c5584a158c4f42ff3f2a18f9aa6ace. */
/* Drain queued events until the admission gate blocks or a freshly sampled
 * queued count is exhausted. Snapshot kind/value BEFORE the gate and read
 * action AFTER it. Gate arguments kind/value were omitted by Ghidra. Apply
 * may change counts/state; resample count after each apply. Index/head wrap
 * subtracts capacity ONCE,not a general modulo; caller ensures valid storage.
 * A block before any event leaves cursors untouched. Otherwise resample storage,
 * capacity and head,then publish remaining count/head with ONE halfword store.
 * No allocation,local lock or fence; gate/apply supply their own behavior. */
void input_drain_queued_events(InputStateView *state)
{
    volatile InputStateView *input_state = state;
    unsigned int count = input_state->queued_event_count;
    if (count == 0)
        return;
    unsigned int walked = 0,processed;
    do {
        const volatile InputEventStorage *storage = input_state->event_storage;
        unsigned int head = input_state->queued_event_head;
        unsigned int capacity = storage->capacity;
        const volatile InputEvent *queued = storage->queued;
        unsigned int slot = head + walked;
        slot = slot < capacity ? (unsigned short)slot : slot - capacity;
        const volatile InputEvent *event = &queued[slot];
        unsigned int kind = event->kind;
        unsigned int value = event->value;
        if (input_event_would_block(state,kind,value) != 0) {
            processed = walked & 255U;
            if (processed == 0)
                return;
            break;
        }
        unsigned int action = event->action;
        ++walked;
        input_apply_event(state,kind,value,(int)action);
        count = input_state->queued_event_count;
        processed = walked & 255U;
    } while (processed < count);
    const volatile InputEventStorage *storage = input_state->event_storage;
    unsigned int head = input_state->queued_event_head;
    unsigned int capacity = storage->capacity;
    unsigned int next = head + processed;
    if (next >= capacity)
        next = processed + head - capacity;
    input_state->queued_cursor = (unsigned short)(((count - processed) & 255U) | ((next & 255U) << 8));
}
