/* Device input reset policy and transform configuration. */

#include "../include/types.h"

/* Native entry: 0x42025bdc. */
/* Original function-byte SHA-256:
 * ad98ae913156f4689ae0e870f1fd5871b3f41b8e1f41ed0ecbfd2a0eeb2f2376. */
/* Store 100 into all 4x4 primary and 16x4 button halfword scales, then rewrite
 * the primary block as eight 0x00640064 words. Clear axis-scale remainder words+150..16f,
 * then bearing Y remainder+174,then X remainder+170. Return state+100,not a status. The native
 * wrapping index expression is two discontiguous scale blocks,not a large
 * contiguous array. No fences,local locks or null check; requires writable state. */
unsigned char *input_reset_scales(InputStateView *state)
{
    volatile InputStateView *input_state = state;
    for (unsigned int row = 0; row < 4; ++row)
        for (unsigned int column = 0; column < 4; ++column)
            input_state->primary_scales[row][column] = 100;
    for (unsigned int row = 0; row < 16; ++row)
        for (unsigned int column = 0; column < 4; ++column)
            input_state->button_scales[row][column] = 100;
    for (unsigned int row = 0; row < 4; ++row) {
        input_state->primary_scale_pairs[row * 2] = 0x00640064U;
        input_state->primary_scale_pairs[row * 2 + 1] = 0x00640064U;
    }
    for (unsigned int row = 0; row < 4; ++row) {
        input_state->axis_scale_remainders[row][0] = 0;
        input_state->axis_scale_remainders[row][1] = 0;
    }
    input_state->bearing_remainder_y = 0;
    input_state->bearing_remainder_x = 0;
    return (unsigned char *)state + 0x100;
}

/* Native entry: 0x420266ac. */
/* Original function-byte SHA-256:
 * 20348ac1b21455a863a4959ff17d1cfdf5832622b6f32cc7c3b271f6839ddbde. */
/* Reset motion,control overrides,scales and transform runtime in native order.
 * First snapshot whether buttons,button scales,forced/cleared keys/consumers,
 * transform maps/flags/mode or consumer transforms are nondefault. PRIMARY
 * scales and motion words do not participate in this snapshot. A sole nonzero
 * transform mode supplies its RAW byte to active_event_blocked; other detected
 * causes supply 1. If no cause exists,that byte is 0 and changed is retained.
 *
 * Clear motion words/times/history,forced masks and lists,restore scales,then
 * clear filter/key/consumer transform runtime. Clear queued/active COUNT bytes
 * only; preserve queue head,published word,dirty/publication flags,saved controls,
 * layout/storage pointers and other fields not explicitly addressed. Set changed=1
 * only for the initial snapshot. No local lock,fence,allocation or return value. */
void input_reset_runtime(InputStateView *state)
{
    volatile InputStateView *input_state = state;
    unsigned int forced = input_state->forced_buttons;
    unsigned int cleared = input_state->cleared_buttons;
    unsigned char blocked = 0;
    unsigned int notify_change = 1;
    if ((forced | cleared) != 0)
        goto nondefault;
    unsigned int different = 0;
    for (unsigned int index = 0; index < 32; ++index)
        different |= input_state->button_scale_pairs[index] ^ 0x00640064U;
    if (different != 0)
        goto nondefault;
    for (unsigned int index = 0; index < 32; ++index)
        if (input_state->forced_keys[index] != 0 || input_state->cleared_keys[index] != 0)
            goto nondefault;
    for (unsigned int index = 0; index < 8; ++index)
        if (input_state->forced_consumers[index] != 0 || input_state->cleared_consumers[index] != 0)
            goto nondefault;
    unsigned int flags = input_state->keyboard_transform_flags;
    for (unsigned int index = 0; index < 32; ++index) {
        unsigned int first = input_state->key_rising_suppression[index];
        unsigned int second = input_state->key_falling_retention[index];
        flags = (flags | first | second) & 255U;
    }
    if (flags != 0)
        goto nondefault;
    blocked = input_state->transform_mode;
    if (blocked != 0)
        goto reset;
    for (unsigned int index = 0; index < 8; ++index)
        if (input_state->consumer_transforms[index] != 0)
            goto nondefault;
    notify_change = 0;
    goto reset;
nondefault:
    blocked = 1;
reset:
    memset(state->primary_words,0,16);
    memset(state->secondary_words,0,16);
    volatile MotionResetView *motion = (volatile void *)state;
    motion->riding_words[0] = 0;
    motion->riding_words[1] = 0;
    motion->riding_words[2] = 0;
    motion->riding_words[3] = 0;
    memset(((MotionResetView *)state)->riding_history,0,144);
    input_state->cleared_buttons = 0;
    input_state->forced_buttons = 0;
    memset(state->forced_keys,0,32);
    memset(state->cleared_keys,0,32);
    memset(state->forced_consumers,0,16);
    memset(state->cleared_consumers,0,16);
    (void)input_reset_scales(state);
    input_state->button_scale_state = 0;
    input_state->filter_runtime[0] = 0;
    input_state->filter_runtime[1] = 0;
    input_state->filter_runtime[2] = 0;
    input_state->filter_runtime[3] = 0;
    input_state->filter_active = 0;
    memset(state->key_rising_suppression,0,32);
    memset(state->key_falling_retention,0,32);
    memset(state->key_transition_state,0,32);
    input_state->keyboard_transform_flags = 0;
    memset(state->consumer_transforms,0,16);
    input_state->transform_mode = 0;
    input_state->queued_event_count = 0;
    input_state->active_event_count = 0;
    input_state->active_event_blocked = blocked;
    if (notify_change != 0)
        input_state->changed = 1;
}

/* Native entry: 0x42026854. */
/* Original function-byte SHA-256:
 * af0c690b52086e15a8ba60021f5857527a0546f58620748586e5bc0058172b5a. */
/* Snapshot forced/cleared buttons,keys and consumers. Always clear queued-count,
 * forced masks and lists; publish active count/blocked halfword as 0x0100 if any
 * override existed,else 0x0000. Set changed=1 only when an override existed; otherwise
 * preserve it. Queue head,published word,dirty,scales,saved controls and motion are
 * untouched. No fences or lock; requires serialized writable state. */
void input_clear_forced_controls(InputStateView *state)
{
    volatile InputStateView *input_state = state;
    unsigned int forced = input_state->forced_buttons;
    unsigned int cleared = input_state->cleared_buttons;
    unsigned int had_controls = 1;
    if ((forced | cleared) != 0)
        goto clear;
    for (unsigned int index = 0; index < 32; ++index)
        if (input_state->forced_keys[index] != 0 || input_state->cleared_keys[index] != 0)
            goto clear;
    for (unsigned int index = 0; index < 8; ++index)
        if (input_state->forced_consumers[index] != 0 || input_state->cleared_consumers[index] != 0)
            goto clear;
    had_controls = 0;
clear:
    input_state->queued_event_count = 0;
    input_state->active_count_and_flags = had_controls != 0 ? 0x0100U : 0;
    input_state->cleared_buttons = 0;
    input_state->forced_buttons = 0;
    memset(state->forced_keys,0,32);
    memset(state->cleared_keys,0,32);
    memset(state->forced_consumers,0,16);
    memset(state->cleared_consumers,0,16);
    if (had_controls != 0)
        input_state->changed = 1;
}

/* Native entry: 0x420269a8. */
/* Original function-byte SHA-256:
 * e6f3529dd9ce32962edb5a9ae400457dc554eca9fb18e02b9c1256c5535b95a1. */
/* For nonzero LOW16(value),update the 8-slot consumer-transform set using the
 * byte enabled argument. Negative signed16 values become their unsigned16
 * usage. Value 0 does nothing. No status,changed flag,fence or local lock. */
void input_set_consumer_transform(InputStateView *state,
    short value,unsigned char enabled)
{
    if ((unsigned short)value != 0)
        input_usage_set_update(state->consumer_transforms,(unsigned short)value,enabled);
}

/* Native entry: 0x420269c0. */
/* Original function-byte SHA-256:
 * e7f9b65276cbc04385c40379c89685a46501d14cbf30db1005c7118a8f4a703b. */
/* Copy 32 primary scale bytes, then 128 button scale bytes into the 160-byte
 * snapshot. memcpy requires valid nonoverlapping spans. No lock,fence or result;
 * runtime words between the scale blocks are not included. */
void input_copy_scales(const InputStateView *state,InputScaleSnapshot *output)
{
    memcpy(output->primary,state->primary_scale_pairs,32);
    memcpy(output->buttons,state->button_scale_pairs,128);
}

/* Native entry: 0x420269e8. */
/* Original function-byte SHA-256:
 * 946eb87ac9e2a605ff2a331ac6f457aac4822717a87f9eceefb76cd0c8127464. */
/* Restore 32 primary then 128 button scale bytes from a 160-byte snapshot.
 * Does not clear runtime or mark changed. Valid nonoverlapping spans are
 * required by memcpy; no local lock,fence or return status. */
void input_restore_scales(InputStateView *state,const InputScaleSnapshot *input)
{
    memcpy(state->primary_scale_pairs,input->primary,32);
    memcpy(state->button_scale_pairs,input->buttons,128);
}

/* Native entry: 0x42026f58. */
/* Original function-byte SHA-256:
 * 4437307cd406783288eae20f1590eabfedbe67e3c01c574e2a88aea5a319493a. */
/* Selection 1/2 chooses that keyboard-transform flag bit; 0 chooses both (mask 3).
 * Other byte values return 0 without access. Nonzero enabled sets bits,zero
 * clears them; always store the resulting byte on a valid selection. Return
 * whether the byte changed. No changed flag,notification,fence or lock. */
unsigned int input_set_keyboard_transform_flags(InputStateView *state,
    unsigned char selection,unsigned char enabled)
{
    unsigned int mask = selection;
    if (selection != 1 && selection != 2) {
        if (selection != 0)
            return 0;
        mask = 3;
    }
    volatile InputStateView *input_state = state;
    unsigned char old = input_state->keyboard_transform_flags;
    unsigned char updated = (unsigned char)(enabled != 0 ? old | mask : old & ~mask);
    input_state->keyboard_transform_flags = updated;
    return old != updated;
}

/* Native entry: 0x42026f90. */
/* Original function-byte SHA-256:
 * 47086ed10e909c5b183e59daed898aeef4f4b2bf348f0bcee6abc9ed8997cb58. */
/* Store enabled!=0 as a byte transform mode. No read-before-write,changed flag,
 * validation,notification,fence or local lock. */
void input_set_transform_mode(InputStateView *state,unsigned char enabled)
{
    ((volatile InputStateView *)state)->transform_mode = enabled != 0;
}

/* Native entry: 0x42026fa4. */
/* Original function-byte SHA-256:
 * 11fdfc25feec7508c0b9d5aa6afb8faa270d69adf4aefe30c9bf00bc56117d55. */
/* Write 100 into all 80 snapshot halfwords: 4 primary rows, then 16 button rows,
 * four stores per row. Requires 160 writable bytes. Does not access live state,
 * clear runtime,return a result,lock or issue barriers. */
void input_scale_snapshot_defaults(InputScaleSnapshot *snapshot)
{
    volatile InputScaleSnapshot *snapshot_view = snapshot;
    for (unsigned int row = 0; row < 4; ++row)
        for (unsigned int column = 0; column < 4; ++column)
            snapshot_view->primary[row][column] = 100;
    for (unsigned int row = 0; row < 16; ++row)
        for (unsigned int column = 0; column < 4; ++column)
            snapshot_view->buttons[row][column] = 100;
}
