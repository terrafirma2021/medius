/* Device playback control and temporary input transformations. */

#include "../include/types.h"

/* Native entry: 0x4202a368. */
/* Original function-byte SHA-256:
 * 7fa0a3a1ab5df4b315fd9a371311be55bc4c5e2947e316554a9fdcf5cf1cb54c. */
/* Stop playback unless mode3 locks it out. A nonzero discard_pending_controls clears the pending
 * count and advances the control queue read cursor to its saved write cursor. Clear mode/progress, cache retain,
 * fence/clear active then status; rewind retained input or clear streaming
 * input. Restore applied transforms before clearing their applied flag, then
 * release playback controls. No local locking, allocation or timer arming. */
void playback_stop(int discard_pending_controls)
{
    if (PLAYBACK_MODE == 3)
        return;
    if (discard_pending_controls != 0) {
        unsigned int write_cursor = IMPERFECT_CLIP_QUEUE->write_cursor;
        IMPERFECT_CLIP_QUEUE->pending_count = 0;
        IMPERFECT_CLIP_QUEUE->read_cursor = write_cursor;
    }
    PLAYBACK_MODE = 0;
    PLAYBACK_PROGRESS = 0;
    unsigned int retain = PLAYBACK_TRANSFORMS.retain;
    memw();
    PLAYBACK_ACTIVE = 0;
    PLAYBACK_STATUS = 0;
    if (retain != 0)
        clip_ring_rewind(PLAYBACK_RING);
    else
        clip_ring_clear(PLAYBACK_RING);
    if (PLAYBACK_TRANSFORMS.applied != 0) {
        playback_restore_transforms();
        PLAYBACK_TRANSFORMS.applied = 0;
    }
    playback_release_controls();
}

/* Native entry: 0x4202a3cc. */
/* Original function-byte SHA-256:
 * ada07795ead778218067ebdc7db2087e2b5c1660eeeee59ca265f557f7e9ab23. */
/* Start/resume retained playback. Mode3 or an empty retained span returns
 * without timestamp writes (Ghidra incorrectly invented common-exit stores).
 * Mode2+restart0 resumes with active1/mode1 and a fresh timestamp, without
 * rewind or transform changes. Other active/restarted modes release controls
 * and discard queued controls before rewinding. A fresh mode0 start retains them.
 *
 * On first selected transform override, clear20 restoration masks, then zero
 * only primary scales currently EXACTLY100 and mirror those writes to dynamic
 * states. Selection bits0/1 choose axes0..1/2..3; bit2 chooses button channels
 * up to the cached, capped16 button count (buttons use only columns0/1).
 * Dynamic count is refreshed after every callback, not capped. Record changed
 * columns per channel. Bits3/4 enable missing keyboard flag bits/consumer mode
 * and remember only what this start enabled for later restoration. Preserve
 * flag/sample/store ordering; caller owns serialization and valid descriptors. */
void playback_start(int restart)
{
    if (PLAYBACK_MODE == 3 || clip_ring_retained_bytes(PLAYBACK_RING) == 0)
        return;
    unsigned int mode = PLAYBACK_MODE;
    if (mode == 2 && restart == 0) {
        memw();
        PLAYBACK_ACTIVE = 1;
        PLAYBACK_MODE = 1;
        unsigned long long now = (unsigned long long)esp_timer_get_time();
        PLAYBACK_TIME.low = (unsigned int)now;
        PLAYBACK_TIME.high = (unsigned int)(now >> 32);
        return;
    }
    memw();
    unsigned int active = PLAYBACK_ACTIVE;
    if (mode != 2 && active == 1 && restart == 0)
        return;
    if (mode != 0) {
        playback_release_controls();
        unsigned int write_cursor = IMPERFECT_CLIP_QUEUE->write_cursor;
        IMPERFECT_CLIP_QUEUE->pending_count = 0;
        IMPERFECT_CLIP_QUEUE->read_cursor = write_cursor;
    }
    clip_ring_rewind(PLAYBACK_RING);
    PLAYBACK_PROGRESS = 0;
    PLAYBACK_MODE = 1;
    memw();
    PLAYBACK_ACTIVE = 1;
    PLAYBACK_STATUS = 0;
    unsigned long long now = (unsigned long long)esp_timer_get_time();
    unsigned int applied = PLAYBACK_TRANSFORMS.applied;
    PLAYBACK_TIME.low = (unsigned int)now;
    PLAYBACK_TIME.high = (unsigned int)(now >> 32);
    if (applied != 0)
        return;
    unsigned int selection = PLAYBACK_TRANSFORMS.selection;
    if (selection == 0)
        return;
    motion_configuration_changed();
    memset((void *)PLAYBACK_TRANSFORMS.scale_columns,0,20);
    if (FIXED_INPUTS[0].enabled != 0 && (selection & 7U) != 0) {
        unsigned int buttons = 0;
        const HidReportLayout *layout = FIXED_INPUTS[0].state.hid_layout;
        if (layout != 0) {
            buttons = ((const volatile HidReportLayout *)layout)->button_count;
            if (buttons > 15)
                buttons = 16;
        }
        for (unsigned int channel = 0; channel < 20; ++channel) {
            unsigned int selected = channel < 2 ? selection & 1U :
                channel < 4 ? selection & 2U :
                channel-3U <= buttons ? selection & 4U : 0;
            if (selected == 0)
                continue;
            unsigned int columns = channel < 4 ? 4 : 2;
            for (unsigned int column = 0; column < columns; ++column) {
                if (input_get_scale(INPUT0_STATE,channel,column) != 100)
                    continue;
                input_set_scale(INPUT0_STATE,channel,column,0);
                int count = REPORT_BINDING_COUNT;
                for (int index = 0; index < count; ++index) {
                    InputStateView *state = (InputStateView *)(uintptr_t)
                        ((unsigned int)(uintptr_t)REPORT_BINDINGS+8U+(unsigned int)index*904U);
                    input_set_scale(state,channel,column,0);
                    count = REPORT_BINDING_COUNT;
                }
                PLAYBACK_TRANSFORMS.scale_columns[channel] |= (unsigned char)(1U << column);
            }
        }
    }
    if ((selection & 8U) != 0 && FIXED_INPUTS[1].enabled != 0) {
        unsigned int missing = (unsigned char)~input_get_keyboard_transform_flags(INPUT1_STATE);
        unsigned int enabled = missing & 1U;
        if (enabled != 0)
            (void)input_set_keyboard_transform_flags(INPUT1_STATE,1,1);
        if ((missing & 2U) != 0) {
            enabled = missing & 3U;
            (void)input_set_keyboard_transform_flags(INPUT1_STATE,2,1);
        }
        PLAYBACK_TRANSFORMS.keyboard = (unsigned char)enabled;
        if ((missing & 3U) != 0)
            FIXED_INPUTS[1].state.changed = 1;
    }
    if ((selection & 16U) != 0 && FIXED_INPUTS[2].enabled != 0 &&
        input_get_transform_mode(INPUT2_STATE) == 0) {
        input_set_transform_mode(INPUT2_STATE,1);
        FIXED_INPUTS[2].state.changed = 1;
        PLAYBACK_TRANSFORMS.consumer = 1;
    }
    PLAYBACK_TRANSFORMS.applied = 1;
}

/* Native entry: 0x4202a2e8. */
/* Original function-byte SHA-256:
 * 0e2588afba6d52805b8d6540b1c72a96107bdaa0782f5e03bdbc7c81fc1f3780. */
/* Release forced playback controls: enabled primary, every dynamic state, then
 * enabled keyboard and consumer. Dynamic count is refreshed after each clear.
 * After those calls, cache the output mask ONCE. For its low three bits, mark
 * each corresponding currently enabled fixed output cache valid, then clear
 * the whole mask. This forces later control comparison against cached output.
 * No fences, local locking or fixed input-valid changes. */
void playback_release_controls(void)
{
    if (FIXED_INPUTS[0].enabled != 0)
        input_clear_forced_controls(INPUT0_STATE);
    int count = REPORT_BINDING_COUNT;
    for (int index = 0; index < count; ++index) {
        InputStateView *state = (InputStateView *)(uintptr_t)
            ((unsigned int)(uintptr_t)REPORT_BINDINGS+8U+(unsigned int)index*904U);
        input_clear_forced_controls(state);
        count = REPORT_BINDING_COUNT;
    }
    if (FIXED_INPUTS[1].enabled != 0)
        input_clear_forced_controls(INPUT1_STATE);
    if (FIXED_INPUTS[2].enabled != 0)
        input_clear_forced_controls(INPUT2_STATE);
    unsigned int mask = FIXED_OUTPUT_MASK;
    for (unsigned int index = 0; index < 3; ++index)
        if ((mask & (1U << index)) != 0 && FIXED_INPUTS[index].enabled != 0)
            FIXED_INPUTS[index].output_valid = 1;
    FIXED_OUTPUT_MASK = 0;
}

/* Native entry: 0x420293f4. */
/* Original function-byte SHA-256:
 * 5fdf708fc75b58e90dec444f95438011a4deffebe5d9b6936de5de5a1bfe0697. */
/* Notify motion configuration, then restore scale100 for each selected bit of
 *20 channel masks. Read the mask freshly for EVERY column, including after
 * callbacks; mirror each write to dynamic states using a live count. No enabled
 * gate or current-value check is applied here. Any scale restoration marks the
 * primary changed. Clear all20 masks before processing keyboard/consumer.
 * A nonzero keyboard mask marks changed even if neither low bit was set. Read
 * bit1 freshly after a bit0 callback, disable selected flags, then clear mask.
 * Disable a selected consumer mode and mark changed before clearing its mask.
 * The outer applied flag is owned by the caller; it is not cleared here.
 * No local lock, bounds cap or timing operation. */
void playback_restore_transforms(void)
{
    motion_configuration_changed();
    unsigned int restored = 0;
    for (unsigned int channel = 0; channel < 20; ++channel) {
        for (unsigned int column = 0; column < 4; ++column) {
            unsigned int mask = PLAYBACK_TRANSFORMS.scale_columns[channel];
            if ((mask & (1U << column)) == 0)
                continue;
            input_set_scale(INPUT0_STATE,channel,column,100);
            int count = REPORT_BINDING_COUNT;
            for (int index = 0; index < count; ++index) {
                InputStateView *state = (InputStateView *)(uintptr_t)
                    ((unsigned int)(uintptr_t)REPORT_BINDINGS+8U+(unsigned int)index*904U);
                input_set_scale(state,channel,column,100);
                count = REPORT_BINDING_COUNT;
            }
            restored = 1;
        }
    }
    if (restored != 0)
        FIXED_INPUTS[0].state.changed = 1;
    memset((void *)PLAYBACK_TRANSFORMS.scale_columns,0,20);
    unsigned int keyboard = PLAYBACK_TRANSFORMS.keyboard;
    if (keyboard != 0) {
        if ((keyboard & 1U) != 0) {
            (void)input_set_keyboard_transform_flags(INPUT1_STATE,1,0);
            keyboard = PLAYBACK_TRANSFORMS.keyboard;
        }
        if ((keyboard & 2U) != 0)
            (void)input_set_keyboard_transform_flags(INPUT1_STATE,2,0);
        FIXED_INPUTS[1].state.changed = 1;
        PLAYBACK_TRANSFORMS.keyboard = 0;
    }
    if (PLAYBACK_TRANSFORMS.consumer != 0) {
        input_set_transform_mode(INPUT2_STATE,0);
        FIXED_INPUTS[2].state.changed = 1;
        PLAYBACK_TRANSFORMS.consumer = 0;
    }
}

/* Native entry: 0x42028614. */
/* Original function-byte SHA-256:
 * 3523ee707e8c85353f102fd3a6f1568b22159c7cf6e32235a915a49a74e9a7da. */
/* Reset playback/capture trigger runtime without a local lock. MEMW/clear
 * active BYTE, then mode, progress WORD, status and clip sequence-valid BYTE. Clear only
 * the20 scale bytes and seven transform BYTEs in reverse field order; leave
 * transform byte7 unchanged. Clear input-trigger count and388 bytes spanning
 * eight packet-trigger records plus their trailing bookkeeping, then button,
 * key and consumer suppression state. Invalidate consumer/keyboard/button
 * trigger baselines by clearing their valid BYTEs only, and clear clip ring.
 * Read the control queue write cursor WORD BEFORE clearing pending HALFWORD,
 * then copy the saved cursor to its read cursor. Snapshot fixed-output mask
 * BYTE ONCE before clearing the playback action count BYTE. For each of the three1000-byte fixed
 * bindings, a saved mask bit plus current enabled BYTE sets output-valid1;
 * other output-valid bytes remain unchanged. Clear mask only after this loop.
 * No retained payloads, timestamps, saved transforms or whole binding blocks
 * are erased beyond these explicit spans. No task, timer or USB call. */
void playback_reset_runtime(void)
{
    memw();
    PLAYBACK_ACTIVE = 0;
    PLAYBACK_MODE = 0;
    PLAYBACK_PROGRESS = 0;
    PLAYBACK_STATUS = 0;
    CLIP_APPEND_SEQUENCE_VALID = 0;
    memset((void *)PLAYBACK_TRANSFORMS.scale_columns,0,20);
    PLAYBACK_TRANSFORMS.keyboard = 0;
    PLAYBACK_TRANSFORMS.consumer = 0;
    PLAYBACK_TRANSFORMS.applied = 0;
    PLAYBACK_TRANSFORMS.selection = 0;
    PLAYBACK_TRANSFORMS.repeat = 0;
    PLAYBACK_TRANSFORMS.retain = 0;
    PLAYBACK_TRANSFORMS.timed_motion = 0;
    INPUT_TRIGGER_COUNT = 0;
    memset(PACKET_TRIGGER_RESET_STORAGE,0,388);
    INPUT_SUPPRESSED_BUTTONS = 0;
    INPUT_SUPPRESSION_COUNT = 0;
    memset((void *)INPUT_SUPPRESSED_KEYS,0,32);
    memset((void *)INPUT_SUPPRESSED_CONSUMERS,0,16);
    REPORT_CONSUMER_TRIGGERS.valid = 0;
    REPORT_KEYBOARD_TRIGGERS.valid = 0;
    REPORT_TRIGGER_BUTTONS_VALID = 0;
    clip_ring_clear(PLAYBACK_RING);
    unsigned int write_cursor = IMPERFECT_CLIP_QUEUE->write_cursor;
    IMPERFECT_CLIP_QUEUE->pending_count = 0;
    IMPERFECT_CLIP_QUEUE->read_cursor = write_cursor;
    unsigned char mask = FIXED_OUTPUT_MASK;
    PLAYBACK_ACTION_COUNT = 0;
    for (unsigned int index = 0; index < 3; ++index)
        if ((mask & (1U << index)) != 0 && FIXED_INPUTS[index].enabled != 0)
            FIXED_INPUTS[index].output_valid = 1;
    FIXED_OUTPUT_MASK = 0;
}
