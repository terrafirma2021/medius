/* Device local motion: MOVE command processing and command-gap learning. */
#include "../include/types.h"

/* Local reconstruction utilities: inlined command-gap phase of native
 * 0x4202df60. No additional firmware entry is implied. */
/* Return a live histogram halfword at the raw unsigned index.
 * index is deliberately unchecked: callers preserve native retired-byte and
 * mode-halfword addressing, including values outside the nominal 128 buckets. */
static __inline__ __attribute__((always_inline))
volatile unsigned short *injection_interval_bucket(unsigned int index)
{
    return (volatile unsigned short *)
        ((unsigned int)&INJECTION_INTERVAL_HISTORY + index * 2U);
}

/* Record the positive signed gap from the previous timestamp to now_us.
 * Quantize by 250 us, clamp only the quotient's low word and update the live
 * 128-slot ring/histogram with native saturation and write order. No result.
 * A full count of exactly 128 retires a sample; other counts increment with
 * halfword wrap. A mode rescan chooses the earliest tied maximum. This helper
 * neither publishes the new timestamp nor locks the state itself. */
static __inline__ __attribute__((always_inline))
void injection_record_interval(unsigned long long now_us)
{
    unsigned int previous_low = INJECTION_LAST_TIME.low;
    unsigned int previous_high = INJECTION_LAST_TIME.high;
    if ((previous_low | previous_high) == 0) return;
    long long elapsed = (long long)(now_us -
        (((unsigned long long)previous_high << 32) | previous_low));
    if (elapsed <= 0) return;
    /* Native clamps only the LOW32 of signed division, not the full quotient. */
    unsigned int quotient_low = (unsigned int)(elapsed / 250LL);
    unsigned int bucket = quotient_low <= 127U ? quotient_low : 127U;
    volatile InjectionIntervalHistory *history = &INJECTION_INTERVAL_HISTORY;
    unsigned short count = history->sample_count;
    unsigned short cursor = history->cursor;
    volatile unsigned char *ring_slot = (volatile unsigned char *)
        ((unsigned int)history + 256U + cursor);
    if (count == 128) {
        unsigned char retired = *ring_slot;
        volatile unsigned short *old_bucket = injection_interval_bucket(retired);
        unsigned short old_count = *old_bucket;
        if (old_count != 0) *old_bucket = (unsigned short)(old_count - 1U);
    } else {
        history->sample_count = (unsigned short)(count + 1U);
    }
    history->cursor = (unsigned short)((cursor + 1U) & 127U);
    volatile unsigned short *selected = injection_interval_bucket(bucket);
    unsigned short selected_count = *selected;
    *ring_slot = (unsigned char)bucket;
    if (selected_count != 65535)
        *selected = (unsigned short)(selected_count + 1U);
    unsigned int observations = history->observations;
    if (observations != 0xffffffffU) history->observations = observations + 1U;
    unsigned short old_mode = history->mode;
    unsigned short mode_count = *injection_interval_bucket(old_mode);
    unsigned short new_count = *selected;
    if (mode_count < new_count) {
        history->mode = (unsigned short)bucket;
    } else if (bucket != old_mode && mode_count == 0) {
        unsigned short best_count = 0;
        unsigned short best_bucket = 0;
        for (unsigned int index = 0; index < 128; ++index) {
            unsigned short current = *injection_interval_bucket(index);
            if (current > best_count) {
                best_count = current;
                best_bucket = (unsigned short)index;
            }
        }
        /* One final HALFWORD write; Ghidra rendered writes inside the scan. */
        history->mode = best_bucket;
    }
}

/* Native entry: 0x4202df60. */
/* Original function-byte SHA-256:
 * f6b43c1f070455a9a936cc742bfe16a9a0db5b4d07280eb07a5475badc517d83. */
/*
 * Process local MOVE axes as five full native WORD arguments. x/y/wheel/pan
 * retain their full32 values for activity records; motion helpers consume their
 * signed LOW16. flags is not narrowed: bit2 resets riding plus retained motion
 * and times, otherwise bit1 flushes motion history; either path then fences and
 * clears idle-anchor LOW/HIGH. Bit0 selects direct accumulation over timed work.
 *
 * Sample one clock before optionally taking the rewrite mutex forever; ignore
 * take result. Learn only a positive signed wrapping gap after a nonzero last
 * timestamp. Divide by250us, use quotient LOW32 and clamp to127. A ring retires
 * only at count exactly128; count otherwise wraps16. Cursor's old value is used
 * unchecked, then new cursor is masked127. Histogram HALFWORDs and observation
 * WORD saturate; choose a more frequent bucket or rescan all128 when the old
 * mode emptied, ties keeping the earliest. Native out-of-range cursor/mode and
 * retired BYTE addresses are preserved through explicit address arithmetic.
 * Publish last-time LOW, sample primary-active BYTE, then publish last-time HIGH.
 *
 * Inactive input skips motion but still unlocks and calls change-service(0).
 * Active input uses ordinary timed accumulation unless at least16 observations,
 * mode<=126, nonzero spread, nonzero mode*250 and bit0 clear allow spreading.
 * delay=floor(mode*250*spread/100); the native multiply/inverse sequence reduces
 * to unsigned division100 under these HALFWORD/mode bounds. Zero delay or zero
 * x/y falls back to timed accumulation. Otherwise admit timed x/y with the full
 * clock, computed delay/interval and emission period; separately accumulate any
 * wheel/pan with window0. Period is fenced configured WORD, otherwise default
 *1000 for profile/render bit1 or a separately fenced/reloaded learned WORD.
 *
 * For each originally nonzero axis, fence/store retained WORD then fence/store
 * time LOW then fence/store HIGH. Refresh primary activity with the same clock.
 * Reload mutex once for optional give, then call change-service after unlock.
 * No owned allocation, error rollback, index repair or coherent concurrency
 * guarantee. Requested timing is not verified USB timing or callback latency.
 */
void input_process_local_motion(int x,int y,int wheel,int pan,unsigned int flags)
{
    unsigned long long now_us = (unsigned long long)esp_timer_get_time();
    RtosQueue *mutex = REWRITE_MUTEX;
    if (mutex != 0) (void)xQueueSemaphoreTake(mutex,0xffffffffU);
    injection_record_interval(now_us);
    INJECTION_LAST_TIME.low = (unsigned int)now_us;
    unsigned char active = REPORT_BLOCK0_ACTIVE;
    INJECTION_LAST_TIME.high = (unsigned int)(now_us >> 32);
    unsigned char changed = 0;
    if (active == 0) goto unlock;

    InputStateView *state = INPUT0_STATE;
    if ((flags & 4U) != 0) {
        motion_reset_riding((MotionResetView *)state);
        memset((void *)FIXED_INPUTS[0].retained_motion,0,16);
        memset((void *)FIXED_INPUTS[0].retained_motion_time,0,32);
    } else if ((flags & 2U) != 0) {
        input_flush_motion_history(state);
    } else {
        goto select_motion;
    }
    memw();
    FIXED_INPUTS[0].idle_motion_anchor.low = 0;
    memw();
    FIXED_INPUTS[0].idle_motion_anchor.high = 0;
select_motion:
    {
        unsigned int observations = INJECTION_INTERVAL_HISTORY.observations;
        unsigned int interval_us;
        unsigned int delay_us;
        if (observations <= 15) goto ordinary_motion;
        unsigned short mode = INJECTION_INTERVAL_HISTORY.mode;
        if (mode > 126) goto ordinary_motion;
        unsigned short spread = MOTION_OPTIONS.spread;
        interval_us = (unsigned int)mode * 250U;
        if (spread == 0 || interval_us == 0) goto ordinary_motion;
        if ((flags & 1U) != 0) goto direct_motion;
        delay_us = (unsigned int)(((unsigned long long)interval_us * spread) / 100ULL);
        if (delay_us == 0 || (x == 0 && y == 0)) goto timed_motion;
        memw();
        unsigned int period_us = EMISSION_OPTIONS.period_us;
        if (period_us == 0) {
            memw();
            unsigned char profile = MOTION_OPTIONS.profile;
            if (profile != 0) {
                memw();
                if ((MOTION_RENDER_STATE & 2U) != 0) {
                    period_us = 1000;
                    goto admit_motion;
                }
            }
            period_us = 1000;
            memw();
            unsigned int learned = REPORT_LEARNED_PERIOD;
            if (learned != 0) {
                memw();
                period_us = REPORT_LEARNED_PERIOD;
            }
        }
admit_motion:
        input_admit_timed_motion(state,(short)x,(short)y,now_us,
            delay_us,interval_us,period_us);
        if (wheel != 0 || pan != 0)
            input_accumulate_timed_motion(state,0,0,(short)wheel,(short)pan,now_us,0);
        goto record_activity;
    }
ordinary_motion:
    if ((flags & 1U) != 0) {
direct_motion:
        input_accumulate_motion(state,(short)x,(short)y,(short)wheel,(short)pan);
    } else {
timed_motion:
        input_accumulate_timed_motion(state,(short)x,(short)y,(short)wheel,(short)pan,now_us,0);
    }
record_activity:
    {
        int axes[4] = {x,y,wheel,pan};
        for (unsigned int axis = 0; axis < 4; ++axis) {
            int delta = axes[axis];
            if (delta == 0) continue;
            memw();
            FIXED_INPUTS[0].retained_motion[axis] = delta;
            memw();
            FIXED_INPUTS[0].retained_motion_time[axis].low = (unsigned int)now_us;
            memw();
            FIXED_INPUTS[0].retained_motion_time[axis].high = (unsigned int)(now_us >> 32);
        }
    }
    changed = primary_input_refresh_activity_time(now_us);
unlock:
    mutex = REWRITE_MUTEX;
    if (mutex != 0) (void)xQueueGenericSend(mutex,0,0,0);
    input_service_after_change(changed);
}
