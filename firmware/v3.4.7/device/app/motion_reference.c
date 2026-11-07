/* Device motion reference: retained axes and primary idle anchoring. */

#include "../include/types.h"

/* Native entry: 0x4038f280. */
/* Original function-byte SHA-256:
 * d747df406f079c27aa2b7341ebfc834e5735b566123a04ecfc006e5a99094f3d. */
/* Store four full32-bit motion-reference words and LOW8(mode). The destination
 * must be valid. Preserve four WORD stores in axis order, then the mode BYTE.
 * No validation, dirty publication, lock or memory fence. */
void input_set_motion_reference(InputStateView *state,
    int x,int y,int wheel,int pan,unsigned int mode)
{
    volatile InputStateView *view = state;
    view->filter_runtime[0] = (unsigned int)x;
    view->filter_runtime[1] = (unsigned int)y;
    view->filter_runtime[2] = (unsigned int)wheel;
    view->filter_runtime[3] = (unsigned int)pan;
    view->filter_active = (unsigned char)mode;
}

/* Native entry: 0x403925ac. */
/* Original function-byte SHA-256:
 * b5fa912e8c1e0c4c51732ca4d76c69bfff0022ff3fc19173ecf8720f0db8e121. */
/* Refresh destination's reference using pending motion from the FIXED PRIMARY
 * state, even when destination is another state. Timestamp is supplied by the
 * caller (A4/A5; A3 is alignment padding), never read from the clock here.
 * Include primary words when its window is zero, its anchor is zero, or the
 * SIGNED64 elapsed time is <= a fresh window read; negative ages qualify.
 * For each axis, retain a nonzero pending value with now_us. With a nonzero
 * hold window, publish it only if its timestamp is nonzero and its UNSIGNED64
 * age is within that window. Expiry does not erase the retained value/time.
 * Windows and split timestamp words are sampled separately, with native
 * fences; there is no lock or atomic64 snapshot.
 * Scale X/Y together by ceil(max(abs(X),abs(Y))/32767) if necessary, using
 * signed64 division toward zero and retaining at least +/-1 for nonzero axes.
 * INT_MIN magnitude is handled as unsigned0x80000000. Clamp wheel/pan to
 * [-32767,32767], then copy a freshly sampled mode byte to destination. */
void input_refresh_motion_reference(InputStateView *destination,
    unsigned long long now_us)
{
    volatile FixedInputBinding *primary = FIXED_INPUTS;
    unsigned int include_primary = 1;
    memw();
    unsigned int primary_window = MOVEMENT_RIDING_US;
    if (primary_window != 0) {
        memw();
        unsigned int low = primary->idle_motion_anchor.low;
        memw();
        unsigned int high = primary->idle_motion_anchor.high;
        if ((low | high) != 0) {
            memw();
            low = primary->idle_motion_anchor.low;
            memw();
            high = primary->idle_motion_anchor.high;
            unsigned long long anchor = ((unsigned long long)high << 32) | low;
            memw();
            primary_window = MOVEMENT_RIDING_US;
            include_primary = (long long)(now_us-anchor) <= (long long)primary_window;
        }
    }
    int reference[4];
    for (unsigned int axis = 0; axis < 4; ++axis) {
        memw();
        int retained = primary->retained_motion[axis];
        memw();
        unsigned int low = primary->retained_motion_time[axis].low;
        memw();
        unsigned int high = primary->retained_motion_time[axis].high;
        int pending = input_read_pending_axis(INPUT0_STATE,axis,include_primary);
        memw();
        unsigned int hold_window = MOTION_HOLD_WINDOW;
        int output = 0;
        if (pending != 0) {
            retained = pending;
            low = (unsigned int)now_us;
            high = (unsigned int)(now_us >> 32);
            if (hold_window != 0 && now_us != 0)
                output = pending;
        } else if (hold_window != 0 && (low | high) != 0) {
            unsigned long long stamp = ((unsigned long long)high << 32) | low;
            if (now_us-stamp <= hold_window)
                output = retained;
        }
        memw();
        primary->retained_motion[axis] = retained;
        memw();
        primary->retained_motion_time[axis].low = low;
        reference[axis] = output;
        memw();
        primary->retained_motion_time[axis].high = high;
    }
    unsigned int magnitude_x = reference[0] < 0 ? 0U-(unsigned int)reference[0] : (unsigned int)reference[0];
    unsigned int magnitude_y = reference[1] < 0 ? 0U-(unsigned int)reference[1] : (unsigned int)reference[1];
    unsigned int peak = magnitude_x > magnitude_y ? magnitude_x : magnitude_y;
    if (peak > 32767U) {
        unsigned long long divisor = ((unsigned long long)peak+32766U)/32767U;
        for (unsigned int axis = 0; axis < 2; ++axis) {
            int original = reference[axis];
            int scaled = (int)((long long)original/(long long)divisor);
            if (scaled == 0 && original != 0)
                scaled = original < 0 ? -1 : 1;
            reference[axis] = scaled;
        }
    }
    for (unsigned int axis = 2; axis < 4; ++axis) {
        if (reference[axis] < -32767)
            reference[axis] = -32767;
        if (reference[axis] > 32767)
            reference[axis] = 32767;
    }
    memw();
    unsigned int mode = MOTION_REFERENCE_MODE;
    input_set_motion_reference(destination,reference[0],reference[1],
        reference[2],reference[3],mode);
}

/* Native entry: 0x420290d0. */
/* Original function-byte SHA-256:
 * 0e90a1f1030336d72cd23a3e011977aa6881ee0e61efd758f7372a9d433f00c7. */
/* Clear the primary idle anchor when the primary window is zero or the primary
 * state has no primary activity. Otherwise set now_us only if both sampled
 * words were zero; retain an existing anchor. LOW/HIGH accesses each have a
 * native fence and are not atomic. No clock read, timeout, lock or return. */
void input_update_idle_motion_anchor(unsigned long long now_us)
{
    volatile TimestampWords *anchor = &FIXED_INPUTS[0].idle_motion_anchor;
    memw();
    if (MOVEMENT_RIDING_US == 0 ||
        input_has_primary_activity(INPUT0_STATE) == 0) {
        memw();
        anchor->low = 0;
        memw();
        anchor->high = 0;
        return;
    }
    memw();
    unsigned int low = anchor->low;
    memw();
    unsigned int high = anchor->high;
    if ((low | high) == 0) {
        memw();
        anchor->low = (unsigned int)now_us;
        memw();
        anchor->high = (unsigned int)(now_us >> 32);
    }
}
