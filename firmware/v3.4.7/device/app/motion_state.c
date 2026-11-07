/* Device motion state: timed history, layout binding and axis limits. */

#include "../include/types.h"

/* Native entry: 0x420260c4. */
/* Original function-byte SHA-256:
 * e610e733b38b1e8cb2ab45e92c657308ea89c34fe56c7bd83e6bbd709ccdc78d. */
/* Add signed16 X/Y/wheel/pan to primary words,clamping signed64 sums to
 * +/-0x40000000. Read the next old word before storing the previous result.
 * If window_us!=0 and X/Y is nonzero,set deadline=now+window modulo64; set
 * origin=now first only when the sampled deadline LOW/HIGH pair iszero.
 * Pure wheel/pan does not extend the window. No local lock,fence,clock read
 * or return. The native A7 argument word is unused64-bit alignment padding. */
void input_accumulate_timed_motion(InputStateView *state,
    short x,short y,short wheel,short pan,unsigned long long now_us,unsigned int window_us)
{
    volatile InputStateView *input = state;
    short deltas[4] = {x,y,wheel,pan};
    int previous = (int)input->primary_words[0];
    for (unsigned int axis = 0; axis < 4; ++axis) {
        int value = input_clamp_motion_sum((long long)previous + deltas[axis]);
        int next = 0;
        if (axis != 3)
            next = (int)input->primary_words[axis + 1];
        input->primary_words[axis] = (unsigned int)value;
        previous = next;
    }
    if (window_us == 0 || (x == 0 && y == 0))
        return;
    unsigned int low = input->motion_deadline.low;
    unsigned int high = input->motion_deadline.high;
    if ((low | high) == 0) {
        input->motion_origin.low = (unsigned int)now_us;
        input->motion_origin.high = (unsigned int)(now_us >> 32);
    }
    unsigned long long deadline = now_us + window_us;
    input->motion_deadline.low = (unsigned int)deadline;
    input->motion_deadline.high = (unsigned int)(deadline >> 32);
}

/* Native entry: 0x420261d8. */
/* Original function-byte SHA-256:
 * 2657e3141398b1d4045b12a9d0119da2ca73e614174c5968d5da82afcf6de694. */
/* Consider a timed X/Y sample. Nonzero delay,interval,elapsed and interval>=delay
 * admit an interval search: k=1..4, inclusive[k*interval,k*(interval+281)].
 * Products/comparisons are64-bit,so interval+281 does not wrap32.
 * Exactly one match,nonzero X/Y and history count<8 append a16-byte sample:
 * packed X/Y,untouched word+4,due=now+delay. Publish count+1/matching k in ONE
 * halfword,then save elapsed. No direct motion accumulation occurs on that path.
 *
 * Otherwise accumulate X/Y immediately,with wheel/pan0. A unique match that
 * cannot queue (zero motion or full history) uses window0; no/ambiguous matches
 * and invalid search inputs use the original delay. Native performs a second
 * argument-only search on fallback; the unique/ambiguous result is equivalent
 * to the single search below. No clock read,local lock,fence or allocation. */
void input_admit_timed_motion(InputStateView *state,short x,short y,
    unsigned long long now_us,unsigned int delay_us,unsigned int interval_us,unsigned int elapsed_us)
{
    unsigned int matching_multiple = 0,match_count = 0;
    if (delay_us != 0 && interval_us != 0 && elapsed_us != 0 && interval_us >= delay_us) {
        unsigned long long upper_step = (unsigned long long)interval_us + 281U;
        for (unsigned int candidate_multiple = 1; candidate_multiple <= 4; ++candidate_multiple) {
            unsigned long long lower = (unsigned long long)candidate_multiple * interval_us;
            unsigned long long upper = (unsigned long long)candidate_multiple * upper_step;
            if (lower <= elapsed_us && elapsed_us <= upper) {
                matching_multiple = candidate_multiple;
                ++match_count;
                if (match_count == 2)
                    break;
            }
        }
        if (match_count == 1) {
            volatile InputStateView *input = state;
            if (x != 0 || y != 0) {
                unsigned int count = input->motion_history_count;
                if (count < 8) {
                    unsigned long long due = now_us + delay_us;
                    input->motion_history[count].packed_xy = (unsigned short)x | ((unsigned int)(unsigned short)y << 16);
                    input->motion_history[count].due.low = (unsigned int)due;
                    input->motion_history[count].due.high = (unsigned int)(due >> 32);
                    input->motion_history_state = (unsigned short)(((count + 1) & 255U) | (matching_multiple << 8));
                    input->motion_last_elapsed = elapsed_us;
                    return;
                }
            }
            delay_us = 0;
        }
    }
    input_accumulate_timed_motion(state,x,y,0,0,now_us,delay_us);
}

/* Native entry: 0x42026384. */
/* Original function-byte SHA-256:
 * 580aaf6753eed62b31943b53dd15f16e03ed54dda61b1e72d6e1042b370193c3. */
/* Sum cached-count history X/Y,clear only the count BYTE,then saturating-add
 * those sums to primary X/Y. Next,for each axis,read primary BEFORE secondary,
 * saturating-add into secondary,clear primary,then store secondary. Finally
 * clear deadline/origin LOW/HIGH words. History bytes,multiple tag andlast elapsed
 * remain. Count is unchecked; caller supplies all declared16-byte samples.
 * No local lock,fence,clock sample or return; saturation uses signed64 sums. */
void input_flush_motion_history(InputStateView *state)
{
    volatile InputStateView *input = state;
    unsigned int count = input->motion_history_count;
    int sum_x = 0,sum_y = 0;
    for (unsigned int index = 0; index < count; ++index) {
        const volatile InputMotionSample *sample = (const volatile void *)
            ((const unsigned char *)state + 0x38U + index * 16U);
        int x = sample->x;
        int y = sample->y;
        sum_x += x;
        sum_y += y;
    }
    int old_x = (int)input->primary_words[0];
    input->motion_history_count = 0;
    int new_x = input_clamp_motion_sum((long long)old_x + sum_x);
    int old_y = (int)input->primary_words[1];
    input->primary_words[0] = (unsigned int)new_x;
    input->primary_words[1] = (unsigned int)input_clamp_motion_sum((long long)old_y + sum_y);
    for (unsigned int axis = 0; axis < 4; ++axis) {
        int primary = (int)input->primary_words[axis];
        int secondary = (int)input->secondary_words[axis];
        int combined = input_clamp_motion_sum((long long)primary + secondary);
        input->primary_words[axis] = 0;
        input->secondary_words[axis] = (unsigned int)combined;
    }
    input->motion_deadline.low = 0;
    input->motion_deadline.high = 0;
    input->motion_origin.low = 0;
    input->motion_origin.high = 0;
}

/* Native entry: 0x42025c58. */
/* Original function-byte SHA-256:
 * be50640c60cca8c27dfc1b11f1781603e2ee2a1d91571bae789996bb41e4e4a8. */
/* Snapshot all four12-byte axis descriptors before publishing limits. Native
 * read order is axis0,axis2,axis3(minimum BEFORE packed metadata),axis1.
 * For each output,write enabled!=0 BYTE first,then maximum,then minimum.
 * Valid configured minimum<maximum is retained. Otherwise widths0..31 use
 * mask-shifted signed width bounds (width0 yields INT_MIN/INT_MAX); widths>=32
 * use full signed32 limits. Disabled axes still get limits. Preserve output
 * padding. state/layout must be valid; no local lock,fence or returned value. */
void input_refresh_axis_limits(InputStateView *state)
{
    volatile InputStateView *input = state;
    const volatile HidReportLayout *layout = input->hid_layout;
    ReportNumericField axis_fields[4];
    axis_fields[0].packed = layout->axes[0].packed;
    axis_fields[0].minimum = layout->axes[0].minimum;
    axis_fields[0].maximum = layout->axes[0].maximum;
    axis_fields[2].packed = layout->axes[2].packed;
    axis_fields[2].minimum = layout->axes[2].minimum;
    axis_fields[2].maximum = layout->axes[2].maximum;
    axis_fields[3].minimum = layout->axes[3].minimum;
    axis_fields[3].packed = layout->axes[3].packed;
    axis_fields[3].maximum = layout->axes[3].maximum;
    axis_fields[1].packed = layout->axes[1].packed;
    axis_fields[1].minimum = layout->axes[1].minimum;
    axis_fields[1].maximum = layout->axes[1].maximum;
    for (unsigned int axis = 0; axis < 4; ++axis) {
        int minimum = axis_fields[axis].minimum,maximum = axis_fields[axis].maximum;
        input->axis_limits[axis].enabled = axis_fields[axis].enabled != 0;
        if (maximum <= minimum) {
            unsigned int width = axis_fields[axis].width;
            if (width < 32) {
                unsigned int sign = 1U << ((width - 1U) & 31U);
                maximum = (int)(sign - 1U);
                minimum = (int)(0U - sign);
            } else {
                maximum = 0x7fffffff;
                minimum = (int)0x80000000U;
            }
        }
        input->axis_limits[axis].maximum = maximum;
        input->axis_limits[axis].minimum = minimum;
    }
}

/* Native entry: 0x42025fac. */
/* Original function-byte SHA-256:
 * ddb2e445d594cc987b45b499421628e2e43686cf1eb329e7e8e1d74dc8893e74. */
/* Bind layout andrefresh all axis limits. Cache history count BEFORE clearing
 * deadline/origin words; sum that many X/Y samples,clear count BYTE andsaturate
 * the sums into primary X/Y. This does not transfer motion into secondary.
 * Initialize normalization selectors from fresh layout output_count:0=>ff/ff,
 * 1=>0/ff,otherwise0/1. Clear button scale state and32-byte key transform state.
 * Other motion axes,history bytes/tag,pointers andcontrol state remain. Caller
 * supplies nonNULL layout andreadable unchecked-count history; no lock/fence. */
void input_bind_layout(InputStateView *state,HidReportLayout *layout)
{
    volatile InputStateView *input = state;
    input->hid_layout = layout;
    input_refresh_axis_limits(state);
    unsigned int count = input->motion_history_count;
    input->motion_deadline.low = 0;
    input->motion_deadline.high = 0;
    input->motion_origin.low = 0;
    input->motion_origin.high = 0;
    int sum_x = 0,sum_y = 0;
    for (unsigned int index = 0; index < count; ++index) {
        const volatile InputMotionSample *sample = (const volatile void *)
            ((const unsigned char *)state + 0x38U + index * 16U);
        int x = sample->x;
        int y = sample->y;
        sum_x += x;
        sum_y += y;
    }
    int old_x = (int)input->primary_words[0];
    input->motion_history_count = 0;
    int new_x = input_clamp_motion_sum((long long)old_x + sum_x);
    int old_y = (int)input->primary_words[1];
    input->primary_words[0] = (unsigned int)new_x;
    input->primary_words[1] = (unsigned int)input_clamp_motion_sum((long long)old_y + sum_y);
    unsigned int outputs = ((const volatile HidReportLayout *)layout)->output_count;
    input->primary_normalization_flags = outputs == 0 ? 255 : 0;
    input->secondary_normalization_flags = outputs < 2 ? 255 : 1;
    input->button_scale_state = 0;
    memset(state->key_transition_state,0,32);
}

/* Native entry: 0x420260a4. */
/* Original function-byte SHA-256:
 * 68ddfcedf4e81e9f15573c6eb035635e28472079d2ef83a8fe534e9e6110ca66. */
/* Zero EXACTLY760 bytes,restore default scales/runtime,then bind the supplied
 * nonNULL layout. Does not initialize extra auxiliary-context storage beyond
 * the760-byte core. No allocation,local lock,fence or status result. */
void input_initialize(InputStateView *state,HidReportLayout *layout)
{
    memset(state,0,760);
    (void)input_reset_scales(state);
    input_bind_layout(state,layout);
}

/* Native entry: 0x42026a10. */
/* Original function-byte SHA-256:
 * 48bcad8d9d4fd6eb12d8dfb5886b5ca0c0ba25a37e6587df10936c8a0548e113. */
/* Forward state unchanged to the axis-limit refresh entry. No additional
 * validation,mutation,lock,fence or returned value. */
void input_update_axis_limits(InputStateView *state)
{
    input_refresh_axis_limits(state);
}
