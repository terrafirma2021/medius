/* Medius v3.4.7 device: report rewriting, timing, capture and dispatch.
 * Reconstruction utilities name operations inlined in the native processor.
 * The native entry address and original function-byte hash are retained. */

#include "../include/types.h"

/* Source reconstruction utility result, not a native on-wire/RAM layout. */
typedef struct InputRewriteResult {
    const unsigned char *report;
    unsigned int length,capture_id,change_flags;
} InputRewriteResult;

/* Source reconstruction utility for the class4 rule scan/application in
 * native40396f75..403971b0 and its cold continuations. Caller has already
 * capped input length at64 and handled the class4 catch rule. Match the
 * cached capture ID directly, with no endpoint nibble mask. Cache rule count,
 * choose the first strict best score, then saturating-increment ONE sampled
 * hit value. Action0 returns unchanged. Other actions first copy the original
 * input, then reload payload offset/action/length; action1 drops after that
 * copy. Patch2/7 requires full fit; replace3/4/8 takes min(payload length,64),
 * including zero length. Unknown actions retain the copy. The capture ID is
 * freshly sampled after memcmp; replacement also samples before its length
 * comparison. No-action paths retain the caller's cached ID. Return1 on drop,
 * else0; changed reports publish scratch/length and flag0x80. No local lock,
 * fence, capture submission or allocation. Counts/prefixes remain unchecked. */
static unsigned int report_apply_input_rules(unsigned int interface_index,
    unsigned int capture_id,const unsigned char *input,unsigned int length,
    unsigned char *scratch,InputRewriteResult *result)
{
    result->report = input;
    result->length = length;
    result->capture_id = capture_id;
    result->change_flags = 0;
    unsigned int rule_count = REWRITE_COUNT;
    int best_score = -1;
    unsigned int selected_index = 0xffffffffU;
    for (unsigned int index = 0; index < rule_count; ++index) {
        const volatile RewriteRule *rule = REWRITE_RULES+index;
        unsigned int traffic_class = rule->traffic_class;
        unsigned int endpoint = rule->endpoint;
        unsigned int direction = rule->direction;
        unsigned int prefix_length = rule->prefix_length;
        int rank;
        if (traffic_class == 4 && endpoint == capture_id)
            rank = 2;
        else if (traffic_class == 4 && endpoint == 65535U)
            rank = 1;
        else if (traffic_class == 255)
            rank = 0;
        else
            continue;
        if (direction > 1)
            continue;
        int mask_bits = 0;
        if (prefix_length != 0) {
            if (length < prefix_length || input == 0)
                continue;
            const volatile unsigned char *rule_bytes = (const volatile void *)rule;
            unsigned int matched = 0;
            for (; matched < prefix_length; ++matched) {
                unsigned int mask = rule_bytes[21U+matched];
                unsigned int value = ((const volatile unsigned char *)input)[matched];
                unsigned int prefix = rule_bytes[5U+matched];
                if (prefix != (value & mask))
                    break;
            }
            if (matched != prefix_length)
                continue;
            for (unsigned int byte = 0; byte < prefix_length; ++byte)
                mask_bits += __popcountsi2(rule_bytes[21U+byte]);
        }
        int score = rank*100000+mask_bits*10+(int)direction;
        if (score > best_score) {
            best_score = score;
            selected_index = index;
        }
    }
    if (selected_index == 0xffffffffU)
        return 0;
    volatile RewriteRule *chosen = REWRITE_RULES+selected_index;
    unsigned int hits = chosen->hits;
    if (hits != 0xffffffffU)
        chosen->hits = hits+1U;
    if (chosen->action == 0)
        return 0;
    chosen = REWRITE_RULES+(selected_index & 65535U);
    memcpy(scratch,input,length);
    unsigned int payload_offset = chosen->payload_offset;
    unsigned int action = chosen->action;
    unsigned int payload_length = chosen->payload_length;
    const unsigned char *payload = REWRITE_PAYLOAD_POOL+payload_offset;
    if (action == 1) {
        result->capture_id = REPORT_CAPTURE_INTERFACE_IDS[interface_index];
        return 1;
    }
    unsigned int size = length;
    if (action == 2 || action == 7) {
        unsigned int offset = chosen->patch_offset;
        if (offset+payload_length <= length)
            memcpy(scratch+offset,payload,payload_length);
    } else if (action == 3 || action == 4 || action == 8) {
        size = payload_length < 64 ? payload_length : 64;
        if (size != 0)
            memcpy(scratch,payload,size);
        result->capture_id = REPORT_CAPTURE_INTERFACE_IDS[interface_index];
        if (size != length) {
            result->report = scratch;
            result->length = size;
            result->change_flags = 128;
            return 0;
        }
    }
    int changed = memcmp(scratch,input,length);
    result->capture_id = REPORT_CAPTURE_INTERFACE_IDS[interface_index];
    if (changed != 0) {
        result->report = scratch;
        result->length = size;
        result->change_flags = 128;
    }
    return 0;
}

/* Source reconstruction utilities for native403972d3..40397af6 inside the
 * report processor. These give names to inlined operations; they are not
 * additional native functions. The surrounding processor is still under
 * review. In particular, these routines do not validate physical USB timing. */
static unsigned int report_interval_window_end(unsigned int bucket)
{
    unsigned int end = (bucket+(bucket*3U)/10U) & 65535U;
    return end < 127 ? end : 127;
}

/* Weighted bucket centroid, in microseconds, including half a250-us bin.
 * An empty/reversed window uses its starting bucket rather than dividing0.
 * The final addition retains native32-bit wrapping. */
static unsigned int report_interval_centroid(
    volatile ReportIntervalHistory *history,unsigned int first)
{
    unsigned int end = report_interval_window_end(first);
    unsigned long long weighted = 0,count = 0;
    for (unsigned int bucket = first; bucket <= end; ++bucket) {
        unsigned int hits = history->histogram[bucket];
        weighted += (unsigned long long)bucket*hits;
        count += hits;
    }
    if (count == 0)
        return first*250U+125U;
    return (unsigned int)((weighted*250U)/count)+125U;
}

/* Re-evaluate harmonic classification at a ratio change or after the wrapped
 * same-ratio byte reaches8. A gap clears accumulated deficit. Each record
 * adds ratio-minus-multiplier, clamped below at0. Deficit>ratio, or a second
 * touch of ratio, rejects; the first touch replaces deficit with ratio-1.
 * A complete walk publishes the cached prior-seen byte as success. */
static void report_interval_classify(volatile ReportIntervalHistory *history,
    unsigned int ratio,unsigned int next_cursor,unsigned int count,unsigned int prior_seen)
{
    if (ratio == history->last_ratio) {
        unsigned int repeated = (unsigned char)(history->same_ratio_count+1U);
        history->same_ratio_count = (unsigned char)repeated;
        if (repeated < 8)
            return;
    }
    /* Native signed remainder is preserved before LOW16 conversion. Corrupt
     * sample_count can therefore make the first ring index exceed255. */
    unsigned int cursor = (unsigned short)(((int)next_cursor+256-(int)count)%256);
    const volatile unsigned char *multipliers =
        (const volatile unsigned char *)history+0x200;
    int deficit = 0;
    unsigned int touched = 0;
    unsigned int accepted = 1;
    unsigned int processed = 0;
    while (processed != count) {
        unsigned int sample = multipliers[cursor];
        processed = (processed+1U) & 65535U;
        if ((sample & 128U) != 0)
            deficit = 0;
        deficit += (int)ratio-(int)(sample & 127U);
        if (deficit < 0)
            deficit = 0;
        if (deficit > (int)ratio) {
            accepted = 0;
            break;
        }
        if (deficit == (int)ratio) {
            if (touched != 0) {
                accepted = 0;
                break;
            }
            deficit = (int)ratio-1;
            touched = prior_seen;
        }
        cursor = (cursor+1U) & 255U;
    }
    history->last_ratio = (unsigned char)ratio;
    history->classified = (unsigned char)(accepted != 0 ? prior_seen : 0);
    history->same_ratio_count = 0;
}

/* Insert one accepted interval and update the histogram's harmonic choice.
 * Returns1 when the native path has already established total_count>=16;
 * otherwise its caller must freshly read total_count before publication. */
static unsigned int report_interval_insert(volatile ReportIntervalHistory *history,
    unsigned long long interval,
    unsigned int divisor,unsigned int base_bucket,unsigned int prior_seen)
{
    unsigned int bucket = (unsigned int)interval/250U;
    unsigned int count = history->sample_count;
    unsigned int cursor = history->cursor;
    volatile unsigned char *raw = (volatile unsigned char *)history+0x100;
    volatile unsigned char *multipliers = (volatile unsigned char *)history+0x200;
    if (count == 256) {
        unsigned int old_bucket = raw[cursor];
        unsigned int old_hits = history->histogram[old_bucket];
        if (old_hits != 0)
            history->histogram[old_bucket] = (unsigned short)(old_hits-1U);
    } else {
        history->sample_count = (unsigned short)(count+1U);
    }
    raw[cursor] = (unsigned char)bucket;
    unsigned int multiple = (unsigned int)((long long)(interval+(divisor>>1))/(long long)divisor);
    if (multiple > 127)
        multiple = 127;
    else if (multiple == 0)
        multiple = 1;
    unsigned int gap = history->gap;
    unsigned int next_cursor = (cursor+1U) & 255U;
    multipliers[cursor] = (unsigned char)(multiple | (gap << 7));
    unsigned int hits = history->histogram[bucket];
    history->gap = 0;
    history->cursor = (unsigned short)next_cursor;
    if (hits != 65535U)
        history->histogram[bucket] = (unsigned short)(hits+1U);
    unsigned int total = history->total_count;
    if (total != 0xffffffffU) {
        ++total;
        history->total_count = total;
    }
    unsigned int first = history->first_frequent;
    if (bucket >= base_bucket && bucket < first && history->histogram[bucket] >= 8) {
        first = (unsigned short)bucket;
        history->first_frequent = (unsigned short)first;
    } else if (first >= 128 || history->histogram[first] < 8) {
        first = base_bucket;
        while (first < 128 && history->histogram[first] < 8)
            first = (first+1U) & 65535U;
        if (first >= 128) {
            history->first_frequent = 128;
            history->harmonic_bucket = 0;
            return 0;
        }
        history->first_frequent = (unsigned short)first;
    }
    if (total < 16) {
        history->harmonic_bucket = 0;
        return 0;
    }
    unsigned int second = 0;
    unsigned int search = (report_interval_window_end(first)+1U) & 65535U;
    for (; search < 128; ++search) {
        if (history->histogram[search] >= 8) {
            second = search;
            break;
        }
    }
    unsigned int selected = second;
    unsigned int same_harmonic = 0,ratio = 0,lower_support = 0;
    if (second != 0) {
        unsigned int end = report_interval_window_end(second);
        for (unsigned int candidate = second; candidate <= end; ++candidate) {
            unsigned int candidate_hits = history->histogram[candidate];
            unsigned int selected_hits = history->histogram[selected];
            if (candidate_hits > selected_hits)
                selected = candidate;
        }
        same_harmonic = history->harmonic_bucket == selected;
        unsigned int center = report_interval_centroid(history,selected);
        unsigned int rounded = center+(divisor>>1);
        if (rounded >= divisor) {
            ratio = rounded/divisor;
            unsigned int twice_time = ratio*divisor*2U;
            if (twice_time < 32000)
                lower_support = history->histogram[twice_time/250U];
        }
    }
    unsigned int lower_time = (ratio-1U)*divisor;
    unsigned int upper_time = lower_time+divisor*2U;
    unsigned int upper_support = 0;
    for (unsigned int multiple_index = 1; multiple_index < ratio; ++multiple_index) {
        unsigned int upper_hits = 0;
        if (upper_time < 32000)
            upper_hits = history->histogram[upper_time/250U];
        upper_support += upper_hits;
        unsigned int lower_hits = 0;
        if (lower_time < 32000)
            lower_hits = history->histogram[lower_time/250U];
        lower_support += lower_hits;
        lower_time -= divisor;
        upper_time += divisor;
    }
    if (ratio-2U > 61U) {
        selected = 0;
    } else {
        unsigned int first_hits = history->histogram[first];
        unsigned int selected_hits = history->histogram[selected];
        if (selected_hits < (3U-same_harmonic)*first_hits) {
            selected = 0;
        } else {
            unsigned int factor = same_harmonic != 0 ? 8U : 6U;
            count = history->sample_count;
            if (selected_hits*factor < count || lower_support*32U+count < upper_support*32U) {
                selected = 0;
            } else {
                report_interval_classify(history,ratio,next_cursor,count,prior_seen);
                if (history->classified == 0)
                    selected = 0;
            }
        }
    }
    history->harmonic_bucket = (unsigned short)selected;
    return 1;
}

/* Observe one report containing nonzero X/Y bits. Timestamp deltas wrap32.
 * A base hint snaps a nonzero delta to a nearest multiple only within +/-25%.
 * Intervals>=32000 mark a gap; short/zero intervals can skip insertion while
 * still publishing an existing histogram. Keep separate hinted minimum and
 * fallback divisor: no base hint means minimum200 us, divisor1000 us.
 * Period publication rounds to milliseconds with minimum1 ms. With256 or
 * more retained samples, debounce the period-minus500 threshold for64 repeats.
 * Native fences and repeated reads are explicit; there is no local lock. */
static void report_interval_observe(unsigned int source_stamp)
{
    volatile ReportIntervalHistory *history = &REPORT_INTERVAL_HISTORY;
    memw();
    unsigned int prior_seen = REPORT_INTERVAL_SEEN;
    if (prior_seen != 0) {
        unsigned int base_bucket = history->base_bucket;
        unsigned int base_interval = base_bucket*250U;
        memw();
        unsigned int delta = source_stamp-REPORT_INTERVAL_STAMP;
        unsigned long long interval = delta;
        unsigned int divisor = base_bucket != 0 ? base_interval : 1000;
        unsigned int publication_checked = 0;
        if (base_bucket != 0 && delta == 0)
            goto publish_existing;
        if (base_bucket != 0) {
            unsigned long long nearest = (unsigned long long)delta+(base_interval>>1);
            long long multiple = (long long)nearest/(long long)base_interval;
            if (multiple != 0) {
                long long snapped = (long long)(int)base_interval*(long long)(int)multiple;
                long long residual = (long long)(unsigned long long)delta-snapped;
                unsigned int tolerance = base_interval>>2;
                if (residual >= -(long long)tolerance && residual <= (long long)tolerance)
                    interval = (unsigned long long)snapped;
            }
        }
        if ((long long)interval >= 32000) {
            history->gap = 1;
        } else if ((long long)interval >= 0 && interval >= (base_interval < 200 ? 200U : base_interval)) {
            publication_checked = report_interval_insert(history,interval,divisor,base_bucket,prior_seen);
        }
publish_existing:
        if (publication_checked == 0 && history->total_count < 16)
            goto observation_complete;
        unsigned int first = history->first_frequent;
        if (first < 128) {
            unsigned int harmonic = history->harmonic_bucket;
            if (harmonic != 0)
                first = harmonic;
            unsigned int center = report_interval_centroid(history,first);
            if (center != 0) {
                unsigned int rounded = center+500U;
                unsigned int period = (rounded > 999 ? rounded/1000U : 1U)*1000U;
                memw();
                if (REPORT_LEARNED_PERIOD != period) {
                    memw();
                    REPORT_LEARNED_PERIOD = period;
                    motion_configuration_changed();
                }
                if (history->sample_count > 255) {
                    rounded = period+500U;
                    unsigned int threshold = (rounded > 999 ? rounded/1000U : 1U)*1000U-500U;
                    memw();
                    if (REPORT_ACTIVE_THRESHOLD == threshold) {
                        memw();
                        REPORT_PERIOD_DEBOUNCE = 0;
                    } else {
                        memw();
                        if (REPORT_PENDING_THRESHOLD == threshold) {
                            memw();
                            if (REPORT_PERIOD_DEBOUNCE != 65535U) {
                                memw();
                                unsigned int repeated = REPORT_PERIOD_DEBOUNCE;
                                memw();
                                REPORT_PERIOD_DEBOUNCE = (unsigned short)(repeated+1U);
                            }
                            memw();
                            if (REPORT_PERIOD_DEBOUNCE > 63) {
                                memw();
                                PROFILE_PERIOD_PENDING = 1;
                            }
                        } else {
                            memw();
                            REPORT_PENDING_THRESHOLD = threshold;
                            memw();
                            REPORT_PERIOD_DEBOUNCE = 1;
                        }
                    }
                }
            }
        }
    }
observation_complete:
    memw();
    REPORT_INTERVAL_STAMP = source_stamp;
    memw();
    REPORT_INTERVAL_SEEN = 1;
}

/* Update primary short-gap count and split input timestamp, then inspect X/Y
 * bitfields. A fresh zero period disables short-gap accumulation. Non-motion
 * reports return0 even when motion_seen was previously set; the native read
 * of that byte is retained. Motion updates the learner and publishes the
 * first-motion dirty flag. Caller supplies the current microsecond timestamp. */
static unsigned int report_primary_observe_timing(const unsigned char *report,
    unsigned int length,unsigned int source_stamp,unsigned long long now_us)
{
    volatile FixedInputBinding *binding = FIXED_INPUTS;
    memw();
    unsigned int run = binding->short_gap_run;
    memw();
    unsigned int low = binding->last_input_time.low;
    memw();
    unsigned int high = binding->last_input_time.high;
    unsigned long long previous = ((unsigned long long)high << 32) | low;
    memw();
    unsigned int period = REPORT_LEARNED_PERIOD;
    if (period == 0) {
        period = 1000;
    } else {
        memw();
        period = REPORT_LEARNED_PERIOD;
    }
    unsigned int threshold_low = period+(period>>2);
    unsigned long long threshold = ((unsigned long long)(threshold_low < period) << 32) | threshold_low;
    if (period == 0 || previous == 0 || (long long)now_us < (long long)previous ||
        (long long)(now_us-previous) >= (long long)threshold)
        run = 0;
    else if (run != 65535U)
        ++run;
    memw();
    binding->short_gap_run = (unsigned short)run;
    const volatile HidReportLayout *layout = binding->state.hid_layout;
    memw();
    binding->last_input_time.low = (unsigned int)now_us;
    memw();
    binding->last_input_time.high = (unsigned int)(now_us>>32);
    unsigned int motion = 0;
    if (layout != 0) {
        for (unsigned int axis = 0; axis < 2; ++axis) {
            if (layout->axes[axis].enabled != 0) {
                unsigned int width = layout->axes[axis].width;
                unsigned int offset = layout->axes[axis].bit_offset;
                if (width != 0 && hid_read_bits(report,length,offset,width) != 0) {
                    motion = 1;
                    break;
                }
            }
        }
    }
    if (motion == 0) {
        memw();
        (void)binding->motion_seen;
        return 0;
    }
    report_interval_observe(source_stamp);
    memw();
    if (binding->motion_seen == 0) {
        memw();
        binding->motion_seen = 1;
        memw();
        PROFILE_BASELINE_PENDING = 1;
    }
    return 1;
}

/* Source reconstruction utilities for native40397afb..40398038. The two
 * control baselines are independent: capture sees original bytes; mappings
 * and triggers see current bytes after the class4 rewrite. */
typedef struct DecodedMouseInput {
    unsigned short buttons;
    short x,y,wheel,pan;
} DecodedMouseInput;

/* Source utility for native40397262..403972cc. Compare against the previous
 * input only when valid. Count identical reports up to8, setting the latch
 * only on the transition7->8. A changed/invalid report clears the count but
 * DOES NOT clear the latch. Cache the caller's already selected layout; do
 * not reselect it here. Copy length bytes, then separately fence/store valid
 * and updated. Caller supplies a length fitting the64-byte fixed input cache. */
static void report_primary_cache_input(const HidReportLayout *layout,
    const unsigned char *input,unsigned int length)
{
    volatile FixedInputBinding *binding = FIXED_INPUTS;
    memw();
    if (binding->last_input_valid == 0 ||
        hid_report_needs_update(layout,input,(const unsigned char *)binding->last_input,length) != 0) {
        binding->unchanged_count = 0;
    } else {
        unsigned int count = binding->unchanged_count;
        if (count < 8) {
            ++count;
            binding->unchanged_count = (unsigned char)count;
            if (count == 8)
                binding->suppress_until_change = 1;
        }
    }
    memcpy((void *)binding->last_input,input,length);
    memw();
    binding->last_input_valid = 1;
    memw();
    binding->updated = 1;
}

/* Normalize current input, then build original-input captures and run current
 * button mappings/triggers. A first nonzero capture baseline emits a button
 * capture, while a first trigger baseline only initializes state. Motion
 * capture overwrites record0 and sets count1; its header word is written last.
 * Button records can then append through the reviewed builder. Preserve both
 * separately fenced capture-valid samples and fresh baseline comparison.
 * Trigger button count is cached/capped16. Every matched rule requests work,
 * regardless of playback's return; rising rules sample suppress AFTER the
 * action callback. Finally release each tracked absent button using a fresh
 * tracking mask per bit, then write trigger buttons/valid without fences.
 * Return1 for any matched trigger, else0. Caller serializes the whole path. */
static unsigned int report_primary_controls(const unsigned char *original,
    const unsigned char *current,unsigned int source_stamp,
    BufferedInputCapture *records,int *record_count)
{
    volatile InputStateView *state = INPUT0_STATE;
    unsigned int old_primary = state->primary_normalization_flags;
    unsigned int old_secondary = state->secondary_normalization_flags;
    input_select_normalization_channels(INPUT0_STATE,current);
    if (state->primary_normalization_flags != old_primary ||
        state->secondary_normalization_flags != old_secondary) {
        memw();
        PROFILE_NORMALIZATION_PENDING = 1;
    }
    memw();
    unsigned int capture_mask = CAPTURE_CLASS_MASK;
    if ((capture_mask & 9U) != 0) {
        DecodedMouseInput mouse;
        hid_decode_mouse(INPUT0_STATE,original,&mouse.buttons,
            &mouse.x,&mouse.y,&mouse.wheel,&mouse.pan);
        unsigned int old_buttons = 0;
        memw();
        if (REPORT_CAPTURE_BUTTONS_VALID != 0) {
            memw();
            old_buttons = REPORT_CAPTURE_BUTTONS;
        }
        memw();
        unsigned int valid = REPORT_CAPTURE_BUTTONS_VALID;
        unsigned int changed = mouse.buttons != 0;
        if (valid != 0) {
            memw();
            changed = REPORT_CAPTURE_BUTTONS != mouse.buttons;
        }
        memw();
        REPORT_CAPTURE_BUTTONS = mouse.buttons;
        memw();
        REPORT_CAPTURE_BUTTONS_VALID = 1;
        int selected = capture_find_motion_rule(mouse.x,mouse.y,mouse.wheel,mouse.pan);
        if (selected != -1) {
            volatile BufferedInputCapture *record = records;
            record->motion_class = 0;
            record->motion_axes[0][0] = (unsigned char)mouse.x;
            record->motion_axes[3][0] = (unsigned char)mouse.pan;
            *(volatile int *)record_count = 1;
            record->rule_mask = 1U << ((unsigned int)selected & 31U);
            record->source_stamp = source_stamp;
            record->motion_axes[0][1] = (unsigned char)((unsigned short)mouse.x >> 8);
            record->motion_axes[1][0] = (unsigned char)mouse.y;
            record->motion_axes[1][1] = (unsigned char)((unsigned short)mouse.y >> 8);
            record->motion_axes[2][0] = (unsigned char)mouse.wheel;
            record->motion_axes[2][1] = (unsigned char)((unsigned short)mouse.wheel >> 8);
            record->motion_axes[3][1] = (unsigned char)((unsigned short)mouse.pan >> 8);
            record->header = 0x000d0c03U;
        }
        if (changed != 0) {
            const volatile HidReportLayout *layout = FIXED_INPUTS[0].state.hid_layout;
            unsigned int button_count = layout != 0 ? layout->button_count : 0;
            if (button_count > 15)
                button_count = 16;
            unsigned int edge = ((old_buttons & mouse.buttons) != mouse.buttons) ? 1U : 2U;
            capture_append_buttons(records,record_count,source_stamp,mouse.buttons,edge,button_count);
        }
    }
    if (OBSERVED_BUTTON_RULE_COUNT != 0) {
        DecodedMouseInput mouse;
        hid_decode_mouse(INPUT0_STATE,current,&mouse.buttons,
            &mouse.x,&mouse.y,&mouse.wheel,&mouse.pan);
        FIXED_INPUTS[0].last_buttons = mouse.buttons;
        input_update_button_mappings();
    }
    unsigned int trigger_count = INPUT_TRIGGER_COUNT;
    unsigned int suppression_count = INPUT_SUPPRESSION_COUNT;
    unsigned int matched = 0;
    if ((trigger_count | suppression_count) != 0) {
        DecodedMouseInput mouse;
        hid_decode_mouse(INPUT0_STATE,current,&mouse.buttons,
            &mouse.x,&mouse.y,&mouse.wheel,&mouse.pan);
        const volatile HidReportLayout *layout = FIXED_INPUTS[0].state.hid_layout;
        unsigned int button_count = layout != 0 ? layout->button_count : 0;
        if (button_count > 15)
            button_count = 16;
        if (REPORT_TRIGGER_BUTTONS_VALID != 0) {
            unsigned int previous = REPORT_TRIGGER_BUTTONS;
            unsigned int common = previous & mouse.buttons;
            unsigned int rising = common ^ mouse.buttons;
            unsigned int falling = common ^ previous;
            for (unsigned int button = 0; button < button_count; ++button) {
                unsigned int bit = 1U << button;
                if ((rising & bit) != 0) {
                    const volatile InputTriggerRule *rule = input_find_trigger(0,button,1);
                    if (rule != 0) {
                        (void)playback_apply_action(rule->action);
                        if (rule->suppress != 0)
                            input_suppress_button(button,1);
                        matched = 1;
                    }
                }
                if ((falling & bit) != 0) {
                    const volatile InputTriggerRule *rule = input_find_trigger(0,button,2);
                    if (rule != 0) {
                        (void)playback_apply_action(rule->action);
                        matched = 1;
                    }
                }
            }
        }
        for (unsigned int button = 0; button < 16; ++button) {
            unsigned int tracked = INPUT_SUPPRESSED_BUTTONS;
            if ((tracked & (1U << button)) != 0 && (mouse.buttons & (1U << button)) == 0)
                input_suppress_button(button,0);
        }
        REPORT_TRIGGER_BUTTONS = mouse.buttons;
        REPORT_TRIGGER_BUTTONS_VALID = 1;
    }
    return matched;
}

/* Source utility: each use samples LOW then HIGH with separate native fences. */
static unsigned long long report_primary_input_time(void)
{
    memw();
    unsigned int low = FIXED_INPUTS[0].last_input_time.low;
    memw();
    unsigned int high = FIXED_INPUTS[0].last_input_time.high;
    return ((unsigned long long)high << 32) | low;
}

/* Source utility result, not a native RAM or return-register layout. */
typedef struct PrimaryTransformResult {
    unsigned int motion_consumed,pending_controls;
    InputStateView *published_state;
    const HidReportLayout *layout;
} PrimaryTransformResult;

/* Refresh primary references, drain merged motion and rewrite current input.
 * Cache the initial primary-window word for flags and the later anchor update.
 * With a nonzero window and X/Y motion, sample the anchor HIGH/LOW for presence,
 * then separately sample input time, anchor LOW/HIGH and a fresh window. A
 * SIGNED64 age greater than that window resets riding state and retained axes.
 * Always clear the anchor on this path, including a non-expired anchor.
 * Rewrite flags are1 only for a nonzero initial window without X/Y motion;
 * otherwise3, OR override_enabled<<2. Timestamp and optional copied axes pass
 * through the reviewed native rewrite boundary. Compare before/after motion
 * magnitudes as signed64 to determine consumption. Extension flag stamps its
 * own clock time; a nonzero INITIAL window updates the idle anchor afterward.
 * Publish input events, cache the layout before last_processed LOW/HIGH writes,
 * then query transforms, forced controls and observed mappings in that order
 * unless extension flag already keeps pending_controls true. No output rules,
 * report transmission, local lock, allocation or error/status propagation. */
static void report_primary_transform(const unsigned char *input,unsigned int length,
    unsigned char *output,unsigned int xy_motion,unsigned int override_enabled,
    const int *axis_override,unsigned int extension_flag,PrimaryTransformResult *result)
{
    volatile FixedInputBinding *binding = FIXED_INPUTS;
    memw();
    unsigned int window = MOVEMENT_RIDING_US;
    if (window != 0 && xy_motion != 0) {
        memw();
        unsigned int high = binding->idle_motion_anchor.high;
        memw();
        unsigned int low = binding->idle_motion_anchor.low;
        if ((low | high) != 0) {
            unsigned long long now = report_primary_input_time();
            memw();
            low = binding->idle_motion_anchor.low;
            memw();
            high = binding->idle_motion_anchor.high;
            unsigned long long anchor = ((unsigned long long)high << 32) | low;
            memw();
            unsigned int fresh_window = MOVEMENT_RIDING_US;
            if ((long long)(now-anchor) > (long long)fresh_window) {
                motion_reset_riding(MOTION_PRIMARY_STATE);
                memset((void *)binding->retained_motion,0,16);
                memset((void *)binding->retained_motion_time,0,32);
            }
        }
        memw();
        binding->idle_motion_anchor.low = 0;
        memw();
        binding->idle_motion_anchor.high = 0;
    }
    unsigned long long input_time = report_primary_input_time();
    input_refresh_motion_reference(INPUT0_STATE,input_time);
    memw();
    if (REPORT_MERGE_PENDING != 0)
        report_merge_drain_motion();
    unsigned long long before = input_motion_magnitude(INPUT0_STATE);
    unsigned int flags = window != 0 && xy_motion == 0 ? 1U : 3U;
    flags |= override_enabled << 2;
    input_time = report_primary_input_time();
    input_rewrite_report_native(INPUT0_STATE,input,length,output,flags,input_time,axis_override);
    unsigned long long after = input_motion_magnitude(INPUT0_STATE);
    result->motion_consumed = (long long)after < (long long)before;
    if (extension_flag != 0) {
        unsigned long long now = (unsigned long long)esp_timer_get_time();
        memw();
        binding->extension_event_time.low = (unsigned int)now;
        memw();
        binding->extension_event_time.high = (unsigned int)(now >> 32);
    }
    if (window != 0) {
        input_time = report_primary_input_time();
        input_update_idle_motion_anchor(input_time);
    }
    (void)input_publish_events(INPUT0_STATE);
    result->published_state = input_events_were_published(INPUT0_STATE) != 0 ? INPUT0_STATE : 0;
    unsigned long long now = (unsigned long long)esp_timer_get_time();
    result->layout = binding->state.hid_layout;
    memw();
    binding->last_processed.low = (unsigned int)now;
    memw();
    binding->last_processed.high = (unsigned int)(now >> 32);
    result->pending_controls = 1;
    if (extension_flag == 0 && input_has_transforms(INPUT0_STATE) == 0 &&
        input_has_forced_controls(INPUT0_STATE) == 0)
        result->pending_controls = OBSERVED_BUTTON_RULE_COUNT != 0;
}

/* Source utility result, not a native RAM/return-register layout. */
typedef struct DynamicReportResult {
    const unsigned char *report;
    const HidReportLayout *layout;
    unsigned int pending_controls;
} DynamicReportResult;

/* Source reconstruction utility for native40398097..403982f5. The binding is
 * a904-byte dynamic record already selected by the caller. Compare with its
 * cached input using a freshly read expected_length/layout. Identical reports
 * saturate at8 and latch only on7->8; a changed/invalid report clears just the
 * count. Copy CURRENT length bytes, fence/sample capture mask, then set valid.
 * Capture uses ORIGINAL input and the binding's independent observed baseline.
 * Its old button word is read even when invalid and still determines edge1/2:
 * a first nonzero report can therefore be labeled edge2 by stale storage.
 * Motion capture sets count1 before class/payload stores; header publishes last.
 * Mapping observes CURRENT buttons. Rewrite only when transforms or observed
 * mapping count is nonzero: refresh this binding's reference at clock time,
 * then rewrite with a FRESH expected_length, flags0,time0. Output rules later
 * still receive the caller's current length. Cache layout before the SECOND
 * transform query; pending_controls retains its RAW nonzero byte or uses a
 * fresh boolean mapping count. No trigger/suppression pass, normalization,
 * input-event publication, local lock or bounds repair is supplied here. */
static void report_dynamic_input(ReportLayoutBinding *binding,
    const unsigned char *original,const unsigned char *current,unsigned int length,
    unsigned int source_stamp,unsigned char *rewritten,BufferedInputCapture *records,
    int *record_count,DynamicReportResult *result)
{
    volatile ReportLayoutBinding *shared = binding;
    unsigned int changed = 1;
    if (shared->last_input_valid != 0) {
        unsigned int expected_length = shared->expected_length;
        const HidReportLayout *layout = shared->state.hid_layout;
        changed = hid_report_needs_update(layout,current,binding->last_input,expected_length) != 0;
    }
    if (changed != 0) {
        shared->unchanged_count = 0;
    } else {
        unsigned int count = shared->unchanged_count;
        if (count < 8) {
            ++count;
            shared->unchanged_count = (unsigned char)count;
            if (count == 8)
                shared->suppress_until_change = 1;
        }
    }
    memcpy(binding->last_input,current,length);
    memw();
    unsigned int mask = CAPTURE_CLASS_MASK;
    shared->last_input_valid = 1;
    InputStateView *state = &binding->state;
    if ((mask & 9U) != 0) {
        DecodedMouseInput mouse;
        hid_decode_mouse(state,original,&mouse.buttons,&mouse.x,&mouse.y,&mouse.wheel,&mouse.pan);
        unsigned int valid = shared->observed_buttons_valid;
        unsigned int old_buttons = shared->observed_buttons;
        unsigned int buttons_changed = valid != 0 ? old_buttons != mouse.buttons : mouse.buttons != 0;
        shared->observed_buttons = mouse.buttons;
        shared->observed_buttons_valid = 1;
        int selected = capture_find_motion_rule(mouse.x,mouse.y,mouse.wheel,mouse.pan);
        if (selected != -1) {
            volatile BufferedInputCapture *record = records;
            *(volatile int *)record_count = 1;
            record->motion_class = 0;
            record->motion_axes[0][0] = (unsigned char)mouse.x;
            record->rule_mask = 1U << ((unsigned int)selected & 31U);
            record->source_stamp = source_stamp;
            record->motion_axes[0][1] = (unsigned char)((unsigned short)mouse.x >> 8);
            record->motion_axes[1][0] = (unsigned char)mouse.y;
            record->motion_axes[1][1] = (unsigned char)((unsigned short)mouse.y >> 8);
            record->motion_axes[2][0] = (unsigned char)mouse.wheel;
            record->motion_axes[2][1] = (unsigned char)((unsigned short)mouse.wheel >> 8);
            record->motion_axes[3][0] = (unsigned char)mouse.pan;
            record->motion_axes[3][1] = (unsigned char)((unsigned short)mouse.pan >> 8);
            record->header = 0x000d0c03U;
        }
        if (buttons_changed != 0) {
            const volatile HidReportLayout *layout = shared->state.hid_layout;
            unsigned int button_count = layout != 0 ? layout->button_count : 0;
            if (button_count > 15)
                button_count = 16;
            unsigned int edge = (old_buttons & mouse.buttons) == mouse.buttons ? 2U : 1U;
            capture_append_buttons(records,record_count,source_stamp,mouse.buttons,edge,button_count);
        }
    }
    if (OBSERVED_BUTTON_RULE_COUNT != 0) {
        DecodedMouseInput mouse;
        hid_decode_mouse(state,current,&mouse.buttons,&mouse.x,&mouse.y,&mouse.wheel,&mouse.pan);
        shared->last_buttons = mouse.buttons;
        input_update_button_mappings();
    }
    result->report = current;
    if (input_has_transforms(state) != 0 || OBSERVED_BUTTON_RULE_COUNT != 0) {
        unsigned long long now = (unsigned long long)esp_timer_get_time();
        input_refresh_motion_reference(state,now);
        unsigned int expected_length = shared->expected_length;
        input_rewrite_report_timed(state,current,expected_length,rewritten,0,0);
        result->report = rewritten;
    }
    result->layout = shared->state.hid_layout;
    unsigned int transforms = input_has_transforms(state);
    result->pending_controls = transforms != 0 ? transforms : OBSERVED_BUTTON_RULE_COUNT != 0;
}

/* Source reconstruction utilities for keyboard rebinding and capture, and the
 * shared fixed-control tail. These remain portions of native40396d08. */

/* Native40398398..40398497. Caller has established a changed keyboard
 * interface. Publish that full32-bit interface BEFORE refreshing endpoint
 * priorities. Expected length/report ID come from its FULL interface layout;
 * the state layout pointer instead uses LOW16(interface), preserving native
 * address arithmetic. Reset64-byte input/output baselines, optionally seed
 * report ID, clear output-mask bit1, repeat/latch HALFWORD and output-valid.
 * Input-valid/updated are retained until the later cache update. Enable the
 * keyboard binding, and publish mapping_conditions=LOW8(consumer_enabled*2|1)
 * to primary and every dynamic state using the cached native loop bound.
 * Clear capture-valid with a fence, then trigger-valid without another fence.
 * No input dirty flag, runtime reset or event notification is added. */
static void report_rebind_keyboard(unsigned int interface)
{
    volatile FixedInputBinding *keyboard = FIXED_INPUTS+1;
    keyboard->interface = (int)interface;
    input_refresh_endpoint_priorities();
    const volatile HidReportLayout *full = (const volatile void *)
        ((unsigned int)(uintptr_t)HID_REPORT_LAYOUTS+interface*304U);
    keyboard->expected_length = full->keyboard.expected_length;
    keyboard->state.hid_layout = HID_REPORT_LAYOUTS+(interface & 65535U);
    memset((void *)keyboard->last_input,0,64);
    unsigned int report_id = full->keyboard.report_id;
    if (report_id != 0)
        keyboard->last_input[0] = (unsigned char)report_id;
    memcpy((void *)keyboard->previous_output,(const void *)keyboard->last_input,64);
    unsigned int consumer_enabled = FIXED_INPUTS[2].enabled;
    unsigned int output_mask = FIXED_OUTPUT_MASK;
    unsigned int conditions = (unsigned char)((consumer_enabled*2U) | 1U);
    FIXED_OUTPUT_MASK = (unsigned char)(output_mask & 0xfdU);
    keyboard->suppression_pair = 0;
    int count = REPORT_BINDING_COUNT;
    keyboard->output_valid = 0;
    keyboard->enabled = 1;
    ((volatile InputStateView *)INPUT0_STATE)->mapping_conditions = (unsigned char)conditions;
    if (count > 0) {
        unsigned int iterations = (((unsigned int)count-1U) & 0x1fffffffU)+1U;
        for (unsigned int index = 0; index < iterations; ++index)
            ((volatile ReportLayoutBinding *)REPORT_BINDINGS)[index].state.mapping_conditions = (unsigned char)conditions;
    }
    memw();
    REPORT_KEYBOARD_CAPTURE.valid = 0;
    REPORT_KEYBOARD_TRIGGERS.valid = 0;
}

/* Repeated native inlined six-byte rule scan. Count is cached, not capped43;
 * exact class/usage scores4, wildcard usage2, wildcard class0xff scores0 and
 * ignores usage. Edge0 is wildcard; otherwise require matching edge and add1.
 * First strict highest score wins. Sampling of profile/mask belongs to caller. */
static int report_capture_find_rule(unsigned int profile,unsigned int traffic_class,
    unsigned int usage,unsigned int edge)
{
    const volatile unsigned char *base = (const volatile unsigned char *)CAPTURE_PROFILES+profile*260U;
    unsigned int count = base[258];
    int selected = -1,best = -1;
    for (unsigned int index = 0; index < count; ++index) {
        const volatile CaptureProfileRule *rule = (const volatile void *)(base+index*6U);
        unsigned int rule_edge = rule->edge;
        if (rule_edge != 0 && rule_edge != edge)
            continue;
        unsigned int kind = rule->traffic_class;
        int score;
        if (kind == traffic_class) {
            unsigned int rule_usage = rule->usage;
            if (rule_usage == usage)
                score = 4;
            else if (rule_usage == 65535U)
                score = 2;
            else
                continue;
        } else if (kind == 255) {
            score = 0;
        } else {
            continue;
        }
        if (rule_edge != 0)
            ++score;
        if (score > best) {
            best = score;
            selected = (int)index;
        }
    }
    return selected;
}

/* Native40398498..403988d8. Decode ORIGINAL keyboard input to modifiers and
 * up to32 unique keys. Compare capture baseline with separately fenced valid,
 * modifier and count reads, then optionally memcmp. Independently sample
 * validity again for old count/modifiers, publish new modifier/count/key bytes
 * and fence/store valid1 even when unchanged. On change choose aggregate edge1
 * when count grows or new modifiers include an old-absent bit; otherwise edge2.
 * A same-count key replacement can thus be labeled edge2.
 * Seed subscribers with the first class1/0xff rule, ignoring usage/edge, using
 * a MOD32 shift. Scan all8 modifier usages and every CURRENT decoded key with
 * fresh profile-then-mask samples. Specific rule indices>31 add no mask bit,
 * but still count as selected. Append only current set modifiers/current keys,
 * at most40 triples, preserving byte stores and unused payload. A seed alone
 * can emit an empty record. Store payload length, mask, kind0x0f01, then count1.
 * Caller owns record0 and the count; no append-capacity or lock is checked. */
static void report_capture_keyboard(const HidKeyboardLayout *layout,
    const unsigned char *input,unsigned int length,unsigned int source_stamp,
    BufferedInputCapture *records,int *record_count)
{
    memw();
    if ((CAPTURE_CLASS_MASK & 2U) == 0)
        return;
    unsigned char modifiers,keys[32];
    unsigned int count = hid_decode_keyboard(layout,input,length,&modifiers,keys,32);
    volatile ReportKeyboardBaseline *baseline = &REPORT_KEYBOARD_CAPTURE;
    memw();
    unsigned int valid = baseline->valid;
    unsigned int changed = ((unsigned char)count | modifiers) != 0;
    if (valid != 0) {
        memw();
        unsigned int old_modifiers = baseline->modifiers;
        if (old_modifiers != modifiers) {
            changed = 1;
        } else {
            memw();
            unsigned int old_count = baseline->count;
            changed = old_count != count || memcmp(keys,(const void *)baseline->keys,count) != 0;
        }
    }
    unsigned int old_count = 0,old_modifiers = 0;
    memw();
    if (baseline->valid != 0) {
        memw();
        old_count = baseline->count;
    }
    memw();
    if (baseline->valid != 0) {
        memw();
        old_modifiers = baseline->modifiers;
    }
    memw();
    baseline->modifiers = modifiers;
    memw();
    baseline->count = (unsigned char)count;
    memcpy((void *)baseline->keys,keys,count);
    memw();
    baseline->valid = 1;
    if (changed == 0)
        return;
    unsigned int edge = count > old_count || (old_modifiers & modifiers) != modifiers ? 1U : 2U;
    int selected = -1;
    unsigned int rule_mask = 0;
    memw();
    if ((CAPTURE_CLASS_MASK & 2U) != 0) {
        memw();
        unsigned int profile = CAPTURE_PROFILE_INDEX;
        const volatile unsigned char *base = (const volatile unsigned char *)CAPTURE_PROFILES+profile*260U;
        unsigned int rules = base[258];
        for (unsigned int index = 0; index < rules; ++index) {
            unsigned int kind = base[index*6U+2];
            if (kind == 1 || kind == 255) {
                selected = (int)index;
                rule_mask = 1U << (index & 31U);
                break;
            }
        }
    }
    volatile BufferedInputCapture *record = records;
    record->class_and_reserved = 0x0100;
    record->source_stamp = source_stamp;
    record->usage_count = 0;
    record->edge = (unsigned char)edge;
    unsigned int payload_length = 8;
    for (unsigned int modifier = 0; modifier < 8; ++modifier) {
        memw();
        unsigned int profile = CAPTURE_PROFILE_INDEX;
        memw();
        if ((CAPTURE_CLASS_MASK & 2U) == 0)
            continue;
        int match = report_capture_find_rule(profile,1,224U+modifier,edge);
        if (match == -1)
            continue;
        if (selected < 0)
            selected = match;
        if ((unsigned int)match <= 31)
            rule_mask |= 1U << (unsigned int)match;
        if ((modifiers & (1U << modifier)) == 0 || record->usage_count >= 40)
            continue;
        volatile unsigned char *payload = (volatile unsigned char *)record+8;
        payload[payload_length] = 1;
        payload[payload_length+1] = (unsigned char)(224U+modifier);
        payload[payload_length+2] = 0;
        unsigned int usages = record->usage_count;
        record->usage_count = (unsigned char)(usages+1U);
        payload_length = (payload_length+3U) & 65535U;
    }
    for (unsigned int index = 0; index < count; ++index) {
        memw();
        unsigned int profile = CAPTURE_PROFILE_INDEX;
        memw();
        if ((CAPTURE_CLASS_MASK & 2U) == 0)
            continue;
        unsigned int usage = keys[index];
        int match = report_capture_find_rule(profile,1,usage,edge);
        if (match == -1)
            continue;
        if (selected < 0)
            selected = match;
        if ((unsigned int)match <= 31)
            rule_mask |= 1U << (unsigned int)match;
        if (record->usage_count >= 40)
            continue;
        volatile unsigned char *payload = (volatile unsigned char *)record+8;
        payload[payload_length] = 1;
        payload[payload_length+1] = (unsigned char)usage;
        payload[payload_length+2] = 0;
        unsigned int usages = record->usage_count;
        record->usage_count = (unsigned char)(usages+1U);
        payload_length = (payload_length+3U) & 65535U;
    }
    if (selected >= 0) {
        record->payload_length = (unsigned short)payload_length;
        record->rule_mask = rule_mask;
        record->kind = 0x0f01;
        *(volatile int *)record_count = 1;
    }
}

typedef struct FixedControlResult {
    const unsigned char *report;
    const HidReportLayout *layout;
    InputStateView *published_state;
    unsigned int pending_controls;
} FixedControlResult;

/* Source utility for repeated inlined keyboard membership tests. Modifier
 * usagesE0..E7 use the modifier byte, even if also present in a key list.
 * Other usages scan count bytes; old-baseline counts are not capped32. */
static unsigned int report_keyboard_contains(unsigned int usage,unsigned int modifiers,
    const volatile unsigned char *keys,unsigned int count)
{
    if (((usage+32U) & 255U) < 8)
        return (modifiers >> (usage & 31U)) & 1U;
    for (unsigned int index = 0; index < count; ++index)
        if (keys[index] == usage)
            return 1;
    return 0;
}

/* Native403988d9..40398bdc plus its cold current-key continuation. Decode
 * CURRENT input to a separate live baseline. A missing baseline suppresses
 * transition actions but still permits tracked-key cleanup and publication.
 * With a baseline, modifiers sample OLD modifiers separately per bit. Current
 * keys use a cached old count, refreshed only after a matched rising callback;
 * released-old-key iteration instead reloads its count after every element.
 * Call actions on matching rises/falls; only rises may suppress, sampling that
 * byte AFTER the action. Preserve native RAW work-request values: modifier and
 * release matches use cached validity; a new-key match uses its nonzero suppress
 * byte, or cached validity when suppress is zero. Cleanup itself requests no
 * work. Gate cleanup by one fresh shared suppression count, walk32 bitmap bytes,
 * skip zero bytes, and refresh nonzero-byte masks per bit so callbacks can alter
 * later releases. Publish modifiers/count/keys then valid1, without fences.
 * Return the raw request value, not a normalized action-success boolean. */
static unsigned int report_keyboard_triggers(const HidKeyboardLayout *layout,
    const unsigned char *input,unsigned int length)
{
    unsigned int triggers = INPUT_TRIGGER_COUNT;
    unsigned int suppressed = INPUT_SUPPRESSION_COUNT;
    if ((triggers | suppressed) == 0)
        return 0;
    unsigned char modifiers,keys[32];
    unsigned int count = hid_decode_keyboard(layout,input,length,&modifiers,keys,32);
    volatile ReportKeyboardBaseline *baseline = &REPORT_KEYBOARD_TRIGGERS;
    unsigned int valid = baseline->valid;
    unsigned int work = 0;
    if (valid != 0) {
        for (unsigned int bit = 0; bit < 8; ++bit) {
            unsigned int old = (baseline->modifiers >> bit) & 1U;
            unsigned int current = (modifiers >> bit) & 1U;
            if (old == current)
                continue;
            unsigned int edge = current != 0 ? 1U : 2U;
            const volatile InputTriggerRule *rule = input_find_trigger(1,224U+bit,edge);
            if (rule == 0)
                continue;
            (void)playback_apply_action(rule->action);
            if (current != 0 && rule->suppress != 0)
                input_suppress_key(224U+bit,1);
            work = valid;
        }
        unsigned int previous_count = baseline->count;
        for (unsigned int index = 0; index < count; ++index) {
            unsigned int usage = keys[index];
            unsigned int present;
            if (((usage+32U) & 255U) < 8)
                present = (baseline->modifiers >> (usage & 31U)) & 1U;
            else
                present = report_keyboard_contains(usage,0,baseline->keys,previous_count);
            if (present != 0)
                continue;
            const volatile InputTriggerRule *rule = input_find_trigger(1,usage,1);
            if (rule == 0)
                continue;
            (void)playback_apply_action(rule->action);
            unsigned int suppress = rule->suppress;
            work = suppress;
            if (suppress != 0)
                input_suppress_key(usage,1);
            else
                work = valid;
            previous_count = baseline->count;
        }
        unsigned int index = 0;
        if (baseline->count != 0) {
            do {
                unsigned int usage = baseline->keys[index];
                if (report_keyboard_contains(usage,modifiers,keys,count) == 0) {
                    const volatile InputTriggerRule *rule = input_find_trigger(1,usage,2);
                    if (rule != 0) {
                        (void)playback_apply_action(rule->action);
                        work = valid;
                    }
                }
                ++index;
            } while ((unsigned char)index < baseline->count);
        }
    }
    if (INPUT_SUPPRESSION_COUNT != 0) {
        for (unsigned int byte = 0; byte < 32; ++byte) {
            unsigned int mask = INPUT_SUPPRESSED_KEYS[byte];
            if (mask == 0)
                continue;
            for (unsigned int bit = 0; bit < 8; ++bit) {
                if (bit != 0)
                    mask = INPUT_SUPPRESSED_KEYS[byte];
                unsigned int usage = byte*8U+bit;
                if ((mask & (1U << bit)) != 0 &&
                    report_keyboard_contains(usage,modifiers,keys,count) == 0)
                    input_suppress_key(usage,0);
            }
        }
    }
    baseline->modifiers = modifiers;
    baseline->count = (unsigned char)count;
    memcpy((void *)baseline->keys,keys,count);
    baseline->valid = 1;
    return work;
}

/* Native keyboard tail40398bdd..40398ccc; consumer has the same operations.
 * Compare/cache current input with its fresh layout, saturate repeat count8
 * and latch7->8; changed/invalid clears only count. Fence/store valid/updated.
 * Rewrite defaults only for forced controls or transforms, in that order;
 * only that path stamps last_processed LOW/HIGH. Publish events, cache layout,
 * and preserve the supplied initial pending byte unless fresh forced/transform
 * queries both return0, in which case use has_saved_controls. No bounds check,
 * local lock, output rules or timestamp read on the passthrough path. */
static void report_finish_fixed_control(unsigned int index,const unsigned char *input,
    unsigned int length,unsigned char *rewritten,unsigned int initial_pending,
    FixedControlResult *result)
{
    volatile FixedInputBinding *binding = FIXED_INPUTS+index;
    InputStateView *state = index == 1 ? INPUT1_STATE : INPUT2_STATE;
    unsigned int changed = 1;
    memw();
    if (binding->last_input_valid != 0) {
        const HidReportLayout *layout = binding->state.hid_layout;
        changed = hid_report_needs_update(layout,input,(const unsigned char *)binding->last_input,length) != 0;
    }
    if (changed != 0) {
        binding->unchanged_count = 0;
    } else {
        unsigned int count = binding->unchanged_count;
        if (count < 8) {
            binding->unchanged_count = (unsigned char)(count+1U);
            if (count+1U == 8)
                binding->suppress_until_change = 1;
        }
    }
    memcpy((void *)binding->last_input,input,length);
    memw();
    binding->last_input_valid = 1;
    memw();
    binding->updated = 1;
    result->report = input;
    if (input_has_forced_controls(state) != 0 || input_has_transforms(state) != 0) {
        input_rewrite_report_defaults(state,input,length,rewritten);
        unsigned long long now = (unsigned long long)esp_timer_get_time();
        memw();
        binding->last_processed.low = (unsigned int)now;
        memw();
        binding->last_processed.high = (unsigned int)(now >> 32);
        result->report = rewritten;
    }
    (void)input_publish_events(state);
    result->published_state = input_events_were_published(state) != 0 ? state : 0;
    result->layout = binding->state.hid_layout;
    result->pending_controls = initial_pending;
    if (input_has_forced_controls(state) == 0 && input_has_transforms(state) == 0)
        result->pending_controls = (unsigned int)input_has_saved_controls(state);
}

/* Source reconstruction utility for native40398d55..40398e55. Caller selected
 * a changed consumer interface. Full32 interface/length/report ID and LOW16
 * state-layout addressing follow the keyboard rebind pattern. Clear output
 * mask bit2 and repeat/latch HALFWORD, enable consumer, retain input-valid and
 * updated, and publish LOW8(keyboard_enabled|2) mapping conditions to primary
 * and the cached native number of dynamic bindings. Only capture-valid has a
 * native fence before reset; live-trigger validity is cleared immediately
 * afterward. No state dirty flag, runtime reset or event publication. */
static void report_rebind_consumer(unsigned int interface)
{
    volatile FixedInputBinding *consumer = FIXED_INPUTS+2;
    consumer->interface = (int)interface;
    input_refresh_endpoint_priorities();
    const volatile HidReportLayout *full = (const volatile void *)
        ((unsigned int)(uintptr_t)HID_REPORT_LAYOUTS+interface*304U);
    consumer->expected_length = full->consumer.expected_length;
    consumer->state.hid_layout = HID_REPORT_LAYOUTS+(interface & 65535U);
    memset((void *)consumer->last_input,0,64);
    unsigned int report_id = full->consumer.report_id;
    if (report_id != 0)
        consumer->last_input[0] = (unsigned char)report_id;
    memcpy((void *)consumer->previous_output,(const void *)consumer->last_input,64);
    unsigned int keyboard_enabled = FIXED_INPUTS[1].enabled;
    unsigned int conditions = (unsigned char)(keyboard_enabled | 2U);
    unsigned int output_mask = FIXED_OUTPUT_MASK;
    FIXED_OUTPUT_MASK = (unsigned char)(output_mask & 0xfbU);
    consumer->suppression_pair = 0;
    int count = REPORT_BINDING_COUNT;
    consumer->output_valid = 0;
    consumer->enabled = 1;
    ((volatile InputStateView *)INPUT0_STATE)->mapping_conditions = (unsigned char)conditions;
    if (count > 0) {
        unsigned int iterations = (((unsigned int)count-1U) & 0x1fffffffU)+1U;
        for (unsigned int index = 0; index < iterations; ++index)
            ((volatile ReportLayoutBinding *)REPORT_BINDINGS)[index].state.mapping_conditions = (unsigned char)conditions;
    }
    memw();
    REPORT_CONSUMER_CAPTURE.valid = 0;
    REPORT_CONSUMER_TRIGGERS.valid = 0;
}

/* Native40398e56..40399107. Capture ORIGINAL consumer input, up to8 sorted
 * nonzero usages, retaining duplicates. Compare independent capture baseline,
 * separately fence/sample validity again for old count, then store count/list
 * and valid1 even when unchanged. On change, edge1 means count grew; all other
 * changes use edge2, including same-count replacement. Seed the mask with the
 * first class2/0xff rule ignoring usage/edge. Native seed index EXACTLY32 adds
 * no bit; other indices shift MOD32. Specific matches contribute only<=31.
 * Fresh profile-then-mask sampling precedes each CURRENT usage's ranked scan.
 * Append class2/little-endian16-bit usage triples, at most40, without clearing
 * unused bytes. A generic seed can publish an empty record. Write mask, length,
 * kind0x0f02 and count1. Caller owns record0; no capacity check or local lock. */
static void report_capture_consumer(const HidConsumerLayout *layout,
    const unsigned char *input,unsigned int length,unsigned int source_stamp,
    BufferedInputCapture *records,int *record_count)
{
    memw();
    if ((CAPTURE_CLASS_MASK & 4U) == 0)
        return;
    unsigned short usages[8];
    unsigned int count = hid_decode_consumer(layout,input,length,usages,8);
    unsigned int bytes = (unsigned short)count*2U;
    volatile ReportConsumerCapture *baseline = &REPORT_CONSUMER_CAPTURE;
    memw();
    unsigned int valid = baseline->valid;
    unsigned int changed = count != 0;
    if (valid != 0) {
        memw();
        unsigned int previous = baseline->count;
        changed = previous != count || memcmp(usages,(const void *)baseline->usages,bytes) != 0;
    }
    unsigned int old_count = 0;
    memw();
    if (baseline->valid != 0) {
        memw();
        old_count = baseline->count;
    }
    memw();
    baseline->count = (unsigned char)count;
    memcpy((void *)baseline->usages,usages,bytes);
    memw();
    baseline->valid = 1;
    if (changed == 0)
        return;
    unsigned int edge = count > old_count ? 1U : 2U;
    int selected = -1;
    unsigned int rule_mask = 0;
    memw();
    if ((CAPTURE_CLASS_MASK & 4U) != 0) {
        memw();
        unsigned int profile = CAPTURE_PROFILE_INDEX;
        const volatile unsigned char *base = (const volatile unsigned char *)CAPTURE_PROFILES+profile*260U;
        unsigned int rules = base[258];
        for (unsigned int index = 0; index < rules; ++index) {
            unsigned int kind = base[index*6U+2];
            if (kind == 2 || kind == 255) {
                selected = (int)index;
                if (index != 32)
                    rule_mask = 1U << (index & 31U);
                break;
            }
        }
    }
    volatile BufferedInputCapture *record = records;
    record->class_and_reserved = 0x0200;
    record->source_stamp = source_stamp;
    record->edge = (unsigned char)edge;
    record->usage_count = 0;
    unsigned int payload_length = 8;
    for (unsigned int index = 0; index < count; ++index) {
        memw();
        unsigned int profile = CAPTURE_PROFILE_INDEX;
        memw();
        if ((CAPTURE_CLASS_MASK & 4U) == 0)
            continue;
        unsigned int usage = usages[index];
        int match = report_capture_find_rule(profile,2,usage,edge);
        if (match == -1)
            continue;
        if (selected < 0)
            selected = match;
        if ((unsigned int)match <= 31)
            rule_mask |= 1U << (unsigned int)match;
        if (record->usage_count >= 40)
            continue;
        volatile unsigned char *payload = (volatile unsigned char *)record+8;
        payload[payload_length] = 2;
        payload[payload_length+1] = (unsigned char)usage;
        payload[payload_length+2] = (unsigned char)(usage >> 8);
        unsigned int copied = record->usage_count;
        record->usage_count = (unsigned char)(copied+1U);
        payload_length = (payload_length+3U) & 65535U;
    }
    if (selected >= 0) {
        record->rule_mask = rule_mask;
        record->payload_length = (unsigned short)payload_length;
        record->kind = 0x0f02;
        *(volatile int *)record_count = 1;
    }
}

/* Source utility for repeated native16-bit list scans; old counts are not
 * repaired to8. Current decoder output may contain duplicate usages. */
static unsigned int report_consumer_contains(unsigned int usage,
    const volatile unsigned short *usages,unsigned int count)
{
    for (unsigned int index = 0; index < count; ++index)
        if (usages[index] == usage)
            return 1;
    return 0;
}

/* Native40399108..403992f8 and cold membership continuations. Decode CURRENT
 * input to a live baseline separate from capture. Missing baseline suppresses
 * transitions but not tracked-consumer cleanup/publication. New usages compare
 * with a cached old count, refreshed only after matched rising callbacks; old
 * releases reload count after every element. Duplicates remain separate visits.
 * Actions sample suppress afterward; a matched rise's nonzero suppress byte is
 * the RAW work value, otherwise use cached validity. Release matches also use
 * cached validity. Gate cleanup once on a fresh suppression count, then read
 * each of8 tracking slots freshly and release nonzero usages absent from current
 * input. Cleanup does not request work. Store count, copy LOW16(count)*2 bytes,
 * then valid1 without fences. No input validation, local lock or deduplication. */
static unsigned int report_consumer_triggers(const HidConsumerLayout *layout,
    const unsigned char *input,unsigned int length)
{
    unsigned int triggers = INPUT_TRIGGER_COUNT;
    unsigned int suppressed = INPUT_SUPPRESSION_COUNT;
    if ((triggers | suppressed) == 0)
        return 0;
    unsigned short usages[8];
    unsigned int count = hid_decode_consumer(layout,input,length,usages,8);
    volatile ReportConsumerBaseline *baseline = &REPORT_CONSUMER_TRIGGERS;
    unsigned int valid = baseline->valid;
    unsigned int work = 0;
    if (valid != 0) {
        unsigned int previous_count = baseline->count;
        for (unsigned int index = 0; index < count; ++index) {
            unsigned int usage = usages[index];
            if (report_consumer_contains(usage,baseline->usages,previous_count) != 0)
                continue;
            const volatile InputTriggerRule *rule = input_find_trigger(2,usage,1);
            if (rule == 0)
                continue;
            (void)playback_apply_action(rule->action);
            unsigned int suppress = rule->suppress;
            work = suppress;
            if (suppress != 0)
                input_suppress_consumer(usage,1);
            else
                work = valid;
            previous_count = baseline->count;
        }
        unsigned int index = 0;
        if (baseline->count != 0) {
            do {
                unsigned int usage = baseline->usages[index];
                if (report_consumer_contains(usage,usages,count) == 0) {
                    const volatile InputTriggerRule *rule = input_find_trigger(2,usage,2);
                    if (rule != 0) {
                        (void)playback_apply_action(rule->action);
                        work = valid;
                    }
                }
                ++index;
            } while ((unsigned char)index < baseline->count);
        }
    }
    if (INPUT_SUPPRESSION_COUNT != 0) {
        for (unsigned int slot = 0; slot < 8; ++slot) {
            unsigned int usage = INPUT_SUPPRESSED_CONSUMERS[slot];
            if (usage != 0 && report_consumer_contains(usage,usages,count) == 0)
                input_suppress_consumer(usage,0);
        }
    }
    baseline->count = (unsigned char)count;
    memcpy((void *)baseline->usages,usages,(unsigned short)count*2U);
    baseline->valid = 1;
    return work;
}

/* Reconstructed inlined entry/exit bookkeeping, not additional native entries.
 * The first queue selection uses FULL32 index; the exit queue wraps LOW16.
 * Cache the interface count per scan, keep timestamp word sampling explicit,
 * and ignore critical-section acquisition status as the firmware does. */
static void report_begin_endpoint(unsigned int endpoint)
{
    unsigned int canonical = endpoint_canonicalize(endpoint);
    int count = CREDIT_INTERFACES.count;
    for (int index = 0; index < count; ++index) {
        if (USB_INTERFACE_ENDPOINTS[index] != canonical)
            continue;
        (void)xPortEnterCriticalTimeout(&CREDIT_LOCK,0xffffffffU);
        unsigned long long now = (unsigned long long)esp_timer_get_time();
        volatile CreditInterfaceQueue *queue = (volatile void *)
            ((unsigned int)(uintptr_t)CREDIT_INTERFACE_QUEUES+(unsigned int)index*960U);
        memw();
        unsigned int written = queue->history_write_count;
        memw();
        unsigned int read = queue->history_read_count;
        if (written != read) {
            unsigned int low = queue->pending_start.low;
            unsigned int high = queue->pending_start.high;
            if ((low | high) == 0) {
                queue->pending_start.low = (unsigned int)now;
                queue->pending_start.high = (unsigned int)(now >> 32);
            }
        }
        vPortExitCritical(&CREDIT_LOCK);
        break;
    }
}

static void report_service_endpoint(unsigned int endpoint)
{
    unsigned long long now = (unsigned long long)esp_timer_get_time();
    (void)xPortEnterCriticalTimeout(&CREDIT_LOCK,0xffffffffU);
    int count = CREDIT_INTERFACES.count;
    for (int index = 0; index < count; ++index) {
        if (USB_INTERFACE_ENDPOINTS[index] != endpoint)
            continue;
        CreditInterfaceQueue *queue = (CreditInterfaceQueue *)(uintptr_t)
            ((unsigned int)(uintptr_t)CREDIT_INTERFACE_QUEUES+((unsigned int)index & 65535U)*960U);
        report_history_retire(queue,now,0);
        report_service_interface((unsigned int)index,0);
        int allow_gating = 0;
        memw();
        unsigned int low = REPORT_RECOVERY_EPOCH.low;
        memw();
        unsigned int high = REPORT_RECOVERY_EPOCH.high;
        if ((low | high) != 0) {
            memw();
            low = REPORT_RECOVERY_EPOCH.low;
            memw();
            high = REPORT_RECOVERY_EPOCH.high;
            unsigned long long elapsed = now-(((unsigned long long)high << 32) | low);
            if ((long long)elapsed < 3000)
                allow_gating = REPORT_RECOVERY_MODE <= 1;
        }
        report_try_schedule(queue,allow_gating,now,
            REPORT_INTERFACE_PERIODS[index],(unsigned int)index);
        break;
    }
    vPortExitCritical(&CREDIT_LOCK);
}

/* Native4039940a..40399656 and cold fixed-buffer continuations. Apply class9
 * output rules first, then decide emission. The pending/changed gate tests
 * BIT0, not generic nonzero. A repeat latch bypasses semantic comparison.
 * Valid fixed baselines add a second comparison (masked primary controls;
 * bytewise keyboard/consumer) that can force emission. A drop never emits.
 * Return the native skip byte, including a raw nonzero keyboard validity on
 * that drop path. Cache output even if the downstream submit rejects it;
 * invalidate the selected fixed output cache only after submission/copy.
 * Caller supplies writable64-byte scratch, readable prior output and a held
 * rewrite mutex. No length, pointer or interface bounds checks are added. */
static unsigned int report_emit_output(unsigned int interface,
    const unsigned char *input,unsigned int length,unsigned int original_length,
    unsigned int flags,unsigned char *scratch,const HidReportLayout *layout,
    unsigned char *previous,unsigned int repeat_latch,unsigned int pending,
    InputStateView *published_state,unsigned int motion_consumed,
    CaptureEvent *capture,unsigned short *selected_length)
{
    const unsigned char *selected;
    unsigned int drop = report_apply_output_rules(interface,input,length,
        scratch,&selected,selected_length) == 1;
    unsigned int pointer_changed = selected != input;
    unsigned int skip = drop;
    unsigned int compare_fixed = 0;
    if (drop == 0 && layout != 0 && ((pending | pointer_changed) & 1U) != 0 && repeat_latch == 0) {
        compare_fixed = 1;
        skip = hid_report_needs_update(layout,selected,previous,*selected_length) == 0;
    }
    int fixed_index = -1;
    for (unsigned int index = 0; index < 3; ++index) {
        if (previous != (unsigned char *)FIXED_INPUTS[index].previous_output)
            continue;
        unsigned int valid = FIXED_INPUTS[index].output_valid;
        if (drop != 0 && index == 1 && valid != 0)
            return valid;
        if (valid != 0) {
            fixed_index = (int)index;
            if (compare_fixed != 0) {
                unsigned int differs = index == 0 ?
                    report_controls_differ(INPUT0_STATE,selected,previous,*selected_length) :
                    memcmp(selected,previous,*selected_length) != 0;
                if (differs != 0)
                    skip = 0;
            }
        }
        break;
    }
    if (skip != 0)
        return skip;
    unsigned int short_multiple = flags;
    if (*selected_length != original_length) {
        unsigned int period = REPORT_INTERFACE_PERIODS[interface];
        unsigned int limit = REPORT_COMPARISON_LIMITS[interface];
        unsigned int maximum = period > limit ? period : limit;
        short_multiple = *selected_length != 0 && *selected_length < maximum &&
            period != 0 && *selected_length % period == 0;
    }
    unsigned int emitted_length = *selected_length;
    (void)report_process_interface(interface,selected,emitted_length,0,0,
        pointer_changed << 7,capture,(unsigned int)(uintptr_t)published_state,
        (unsigned char)motion_consumed,(unsigned char)short_multiple,
        &REPORT_PROCESS_STATUS,0,0xffffffffU);
    if (previous != 0)
        memcpy(previous,selected,emitted_length);
    if (fixed_index != -1)
        FIXED_INPUTS[fixed_index].output_valid = 0;
    return 0;
}

/* Native4039965b..4039979d, plus empty-report capture continuation. Request a
 * wake only while USB is suspended and no request is already pending.
 * Preserve repeated activity queries, fresh render-bit reads, changed flags
 * and raw returned bytes. With no activity, no skipped output and length0,
 * capture readiness itself is returned as work, without setting request.
 * Submit the raw capture before marking a skipped published state dirty.
 * Buffered captures are submitted by the caller AFTER releasing the mutex. */
static unsigned int report_finish_output(unsigned int skipped,unsigned int length,
    CaptureEvent *capture,InputStateView *published_state)
{
    memw();
    unsigned int work = USB_SUSPENDED;
    if (work == 0)
        goto no_work;
    memw();
    if (REPORT_WAKE_REQUEST != 0)
        goto no_work;
    memw();
    if ((MOTION_RENDER_STATE & 1U) != 0) {
        memw();
        if ((MOTION_RENDER_STATE & 8U) != 0)
            goto active;
    } else {
        if (input_has_primary_activity(INPUT0_STATE) != 0 ||
            input_has_secondary_activity(INPUT0_STATE) != 0)
            goto active;
    }
    if (input_has_primary_activity(INPUT0_STATE) != 0 ||
        input_has_secondary_activity(INPUT0_STATE) != 0 ||
        FIXED_INPUTS[0].state.changed != 0 ||
        (FIXED_INPUTS[1].enabled != 0 && FIXED_INPUTS[1].state.changed != 0) ||
        (FIXED_INPUTS[2].enabled != 0 && FIXED_INPUTS[2].state.changed != 0))
        goto active;
    if (skipped != 0)
        goto no_work;
    if (length == 0) {
        work = capture->ready;
        if (work == 0)
            return 0;
        goto submit;
    }
    goto request_for_report;
active:
    if (skipped != 0) {
        memw();
        REPORT_WAKE_REQUEST = 1;
        work = skipped;
        goto submit_if_ready;
    }
    if (length == 0) {
        unsigned int ready = capture->ready;
        memw();
        REPORT_WAKE_REQUEST = 1;
        if (ready != 0)
            goto submit;
        capture->ready = 0;
        return work;
    }
request_for_report:
    {
        unsigned int ready = capture->ready;
        memw();
        REPORT_WAKE_REQUEST = 1;
        if (ready == 0)
            return work;
        goto submit;
    }
no_work:
    work = 0;
submit_if_ready:
    if (capture->ready != 0) {
submit:
        if (capture_submit_event(4,capture->subscriptions,0x16,
            &capture->wire,capture->wire_length) != 0)
            capture_notify_task();
    }
    capture->ready = 0;
    if (published_state != 0 && skipped != 0)
        input_mark_dirty(published_state);
    return work;
}

/* Native40399950..403999d3. Called only for nonzero work after the report
 * mutex has been released. Fast-task context clears the request then notifies
 * TXWD with notification mask0x08, using task/ISR APIs and yielding only for
 * an awakened task.
 * Other contexts try bus0 remote wake; on a ZERO return increment a fenced wrapping
 * resume counter and invoke resume handling, leaving the request set. */
static void report_perform_wakeup(void)
{
    if (xTaskGetCurrentTaskHandle() == REPORT_FAST_TASK) {
        RtosTask *task = MOTION_TXWD_TASK;
        memw();
        REPORT_WAKE_REQUEST = 0;
        if (task != 0) {
            int in_isr = xPortInIsrContext();
            task = MOTION_TXWD_TASK;
            if (in_isr == 0)
                (void)xTaskGenericNotify(task,0,8,1,0);
            else {
                int awakened = 0;
                (void)xTaskGenericNotifyFromISR(task,0,8,1,0,&awakened);
                if (awakened != 0)
                    _frxt_setup_switch();
            }
        }
    } else if (usbd_send_remote_wakeup(0) == 0) {
        memw();
        unsigned int resumes = REPORT_WAKE_RESUMES;
        memw();
        REPORT_WAKE_RESUMES = resumes+1U;
        usbd_event_resume_handler(0);
    } else {
        memw();
        REPORT_WAKE_REQUEST = 0;
    }
}

/* Native extension motion bytes are loaded individually, including when the
 * caller supplies an unaligned26-byte link payload. The four override words
 * are copied separately into aligned scratch before their later use. */
static void report_admit_extension(const unsigned char *extension)
{
    const volatile unsigned char *raw = extension;
    unsigned int pan_high = raw[23],wheel_high = raw[21];
    unsigned int y_high = raw[19],x_high = raw[17];
    unsigned int wheel_low = raw[20],pan_low = raw[22];
    unsigned int y_low = raw[18],x_low = raw[16];
    input_accumulate_motion(INPUT0_STATE,
        (short)((x_high << 8) | x_low),(short)((y_high << 8) | y_low),
        (short)((wheel_high << 8) | wheel_low),(short)((pan_high << 8) | pan_low));
}

/* Native entry: 0x40396d08. */
/* Original function-byte SHA-256:
 * 4dbf1052ac97abda73a41df8b581ffac9685921386a3c0b5cdaa9b212cbc64b5. */
/* Process a device-side report and optional26-byte inter-chip extension.
 * Start outstanding-history timing before taking the report mutex; canonicalize
 * the endpoint again afterward. The fast/configured path selects the first
 * matching interface, caps original input to64 bytes and serializes transforms
 * with the rewrite mutex. Matching extension tags supply an aligned four-word
 * override and an optional extension timestamp; primary motion admission is
 * deferred until a matching interface or final cleanup, and occurs once.
 *
 * Class4 catch/drop paths capture ORIGINAL bytes and skip normal transforms.
 * Otherwise preserve original input for capture while rewriting current input,
 * then dispatch primary, dynamic, keyboard, consumer or passthrough. Class9
 * output rules, native repeat suppression, report submission and output-cache
 * updates follow. Raw capture is submitted inside the rewrite lock; up to two
 * buffered captures are submitted after release. Arm input work when required,
 * service endpoint history under the credit lock when status permits, release
 * the report mutex, and perform any deferred wake/notification.
 *
 * Caller supplies valid report/extension storage and valid global descriptors.
 * Selected keyboard/consumer IDs read byte0 even for length0. Shared fields,
 * raw work bytes, unchecked indices and ignored lock/submission results retain
 * native behavior. No local timeout or transport/hardware equivalence claim.
 */
void report_process(unsigned char endpoint,unsigned int source_stamp,
    unsigned char *report,unsigned short length,const unsigned char *extension,
    unsigned char flags)
{
    RtosQueue *report_mutex;
    RtosQueue *rewrite_mutex;
    report_begin_endpoint(endpoint);
    report_mutex = REPORT_MUTEX;
    if (report_mutex != 0)
        (void)xQueueSemaphoreTake(report_mutex,0xffffffffU);
    REPORT_PROCESS_STATUS = 0;
    unsigned int canonical = endpoint_canonicalize(endpoint);
    unsigned int extension_matches_primary = 0;
    if (extension != 0 && FIXED_INPUTS[0].enabled != 0) {
        int primary_interface = FIXED_INPUTS[0].interface;
        if (primary_interface >= 0)
            extension_matches_primary = USB_INTERFACE_ENDPOINTS[primary_interface] == canonical;
    }
    unsigned int deferred_extension = 0;
    unsigned int work = 0;
    memw();
    if (REPORT_FAST_ENABLED == 0) {
        if (extension_matches_primary != 0)
            goto admit_deferred_extension;
        goto service_endpoint;
    }
    int configured = usb_device_is_configured(0);
    if (extension_matches_primary != 0) {
        if (configured == 0)
            goto admit_deferred_extension;
        deferred_extension = (unsigned int)configured;
    } else if (configured == 0) {
        goto check_service_status;
    }
    int interface_count = CREDIT_INTERFACES.count;
    if (interface_count > 0) {
        for (int candidate = 0; candidate < interface_count; ++candidate) {
            if (USB_INTERFACE_ENDPOINTS[candidate] != canonical)
                continue;
            unsigned int interface = (unsigned int)candidate;
            unsigned int original_length = length < 64 ? length : 64;
            BufferedInputCapture buffered[2];
            int buffered_count = 0;
            CaptureEvent capture;
            unsigned char input_scratch[64],output_scratch[64],final_report[64];
            int override_words[4];
            const int *override = 0;
            unsigned int override_enabled,extension_timestamp = 0;
            if (extension != 0 && ((const volatile unsigned char *)extension)[24] == MOTION_RENDER_TOKEN) {
                extension_timestamp = ((const volatile unsigned char *)extension)[25] & 1U;
                memcpy(override_words,extension,16);
                override = override_words;
                override_enabled = 1;
            } else {
                memw();
                override_enabled = MOTION_RENDER_STATE & 1U;
                if (override_enabled != 0) {
                    memw();
                    unsigned int session = REPORTED_HOST_SESSION;
                    override_enabled = MOTION_RENDER_TOKEN == session;
                }
            }
            rewrite_mutex = REWRITE_MUTEX;
            if (rewrite_mutex != 0)
                (void)xQueueSemaphoreTake(rewrite_mutex,0xffffffffU);
            if (extension_matches_primary != 0 &&
                (unsigned int)FIXED_INPUTS[0].interface == interface) {
                report_admit_extension(extension);
                deferred_extension = 0;
            }
            memw();
            if (OUTPUT_RESET_PENDING != 0)
                input_reset_output_reports();
            unsigned int capture_id = REPORT_CAPTURE_INTERFACE_IDS[interface];
            unsigned int capture_flags = (unsigned char)(flags*2U);
            if (PACKET_TRIGGER_COUNT != 0) {
                unsigned int caught = clip_packet_rules_evaluate(4,capture_id,1,report,original_length);
                capture_id = REPORT_CAPTURE_INTERFACE_IDS[interface];
                if (caught != 0)
                    goto capture_dropped_input;
            }
            InputRewriteResult rewritten;
            if (report_apply_input_rules(interface,capture_id,report,original_length,input_scratch,&rewritten) != 0) {
                capture_id = rewritten.capture_id;
                capture_flags |= 0x80U;
capture_dropped_input:
                capture_event_build(&capture,4,0,capture_id,(unsigned char)capture_flags,
                    source_stamp,report,(unsigned short)original_length);
                if (capture.ready != 0 && capture_submit_event(4,capture.subscriptions,
                    0x16,&capture.wire,capture.wire_length) != 0)
                    capture_notify_task();
                capture.ready = 0;
                rewrite_mutex = REWRITE_MUTEX;
                if (rewrite_mutex != 0)
                    (void)xQueueGenericSend(rewrite_mutex,0,0,0);
                goto after_interface;
            }
            const unsigned char *current = rewritten.report;
            unsigned int current_length = rewritten.length;
            capture_event_build(&capture,4,0,rewritten.capture_id,
                (unsigned char)(rewritten.change_flags | (unsigned int)flags*2U),
                source_stamp,report,(unsigned short)original_length);
            const HidReportLayout *layout = FIXED_INPUTS[0].state.hid_layout;
            unsigned int primary_id_matches = 0;
            if (layout != 0) {
                unsigned int id = ((const volatile HidReportLayout *)layout)->report_id;
                primary_id_matches = id == 0 || (current_length != 0 && current[0] == id);
            }
            unsigned char *previous = 0;
            unsigned int pending = 0,repeat_latch = 0,motion_consumed = 0,trigger_work = 0;
            InputStateView *published_state = 0;
            if ((unsigned int)FIXED_INPUTS[0].interface == interface &&
                FIXED_INPUTS[0].enabled != 0 &&
                FIXED_INPUTS[0].expected_length == current_length && primary_id_matches != 0) {
                report_primary_cache_input(layout,current,current_length);
                unsigned long long now = (unsigned long long)esp_timer_get_time();
                unsigned int motion_seen = report_primary_observe_timing(current,current_length,source_stamp,now);
                trigger_work = report_primary_controls(report,current,source_stamp,buffered,&buffered_count);
                PrimaryTransformResult transformed;
                report_primary_transform(current,current_length,final_report,motion_seen,
                    override_enabled,override,extension_timestamp,&transformed);
                current = final_report;
                layout = transformed.layout;
                published_state = transformed.published_state;
                motion_consumed = transformed.motion_consumed;
                pending = transformed.pending_controls;
                repeat_latch = FIXED_INPUTS[0].suppress_until_change;
                previous = (unsigned char *)FIXED_INPUTS[0].previous_output;
            } else {
                ReportLayoutBinding *binding = report_layout_find((int)interface,current,current_length);
                if (binding != 0) {
                    DynamicReportResult transformed;
                    report_dynamic_input(binding,report,current,current_length,source_stamp,
                        final_report,buffered,&buffered_count,&transformed);
                    current = transformed.report;
                    layout = transformed.layout;
                    pending = transformed.pending_controls;
                    repeat_latch = ((const volatile ReportLayoutBinding *)binding)->suppress_until_change;
                    previous = binding->previous_output;
                } else {
                    const volatile HidKeyboardLayout *keyboard = (const volatile void *)
                        ((unsigned int)(uintptr_t)HID_REPORT_LAYOUTS+interface*304U+0xdaU);
                    unsigned int enabled = keyboard->enabled;
                    unsigned int matches = 0;
                    if (enabled != 0 && keyboard->expected_length == current_length) {
                        unsigned int id = keyboard->report_id;
                        matches = id == 0 || current[0] == id;
                    }
                    if (matches != 0) {
                        const HidKeyboardLayout *selected = &HID_REPORT_LAYOUTS[interface & 65535U].keyboard;
                        if ((unsigned int)FIXED_INPUTS[1].interface != interface)
                            report_rebind_keyboard(interface);
                        report_capture_keyboard(selected,report,original_length,source_stamp,buffered,&buffered_count);
                        trigger_work = report_keyboard_triggers(selected,current,current_length);
                        FixedControlResult transformed;
                        report_finish_fixed_control(1,current,current_length,final_report,enabled,&transformed);
                        current = transformed.report;
                        layout = transformed.layout;
                        published_state = transformed.published_state;
                        pending = transformed.pending_controls;
                        repeat_latch = FIXED_INPUTS[1].suppress_until_change;
                        previous = (unsigned char *)FIXED_INPUTS[1].previous_output;
                    } else {
                        const volatile HidConsumerLayout *consumer = (const volatile void *)
                            ((unsigned int)(uintptr_t)HID_REPORT_LAYOUTS+interface*304U+0x11eU);
                        enabled = consumer->enabled;
                        matches = 0;
                        if (enabled != 0 && consumer->expected_length == current_length) {
                            unsigned int id = consumer->report_id;
                            matches = id == 0 || current[0] == id;
                        }
                        if (matches != 0) {
                            const HidConsumerLayout *selected = &HID_REPORT_LAYOUTS[interface & 65535U].consumer;
                            if ((unsigned int)FIXED_INPUTS[2].interface != interface)
                                report_rebind_consumer(interface);
                            report_capture_consumer(selected,report,original_length,source_stamp,buffered,&buffered_count);
                            trigger_work = report_consumer_triggers(selected,current,current_length);
                            FixedControlResult transformed;
                            report_finish_fixed_control(2,current,current_length,final_report,enabled,&transformed);
                            current = transformed.report;
                            layout = transformed.layout;
                            published_state = transformed.published_state;
                            pending = transformed.pending_controls;
                            repeat_latch = FIXED_INPUTS[2].suppress_until_change;
                            previous = (unsigned char *)FIXED_INPUTS[2].previous_output;
                        } else {
                            layout = 0;
                        }
                    }
                }
            }
            unsigned short selected_length;
            unsigned int skipped = report_emit_output(interface,current,current_length,original_length,
                flags,output_scratch,layout,previous,repeat_latch,pending,published_state,
                motion_consumed,&capture,&selected_length);
            work = report_finish_output(skipped,selected_length,&capture,published_state);
            rewrite_mutex = REWRITE_MUTEX;
            if (rewrite_mutex != 0)
                (void)xQueueGenericSend(rewrite_mutex,0,0,0);
            int count = buffered_count;
            for (int index = 0; index < count; ++index) {
                const BufferedInputCapture *record = buffered+index;
                if (capture_submit_event(record->kind & 255U,record->rule_mask,
                    (unsigned char)(record->kind >> 8),(const unsigned char *)record+8,
                    record->payload_length) != 0)
                    capture_notify_task();
            }
            if (trigger_work != 0)
                input_ensure_timer_armed();
            else {
                memw();
                if (REPORT_MERGE_PENDING != 0)
                    input_ensure_timer_armed();
            }
            goto after_interface;
        }
    }
after_interface:
    if (deferred_extension != 0) {
admit_deferred_extension:
        rewrite_mutex = REWRITE_MUTEX;
        if (rewrite_mutex != 0)
            (void)xQueueSemaphoreTake(rewrite_mutex,0xffffffffU);
        report_admit_extension(extension);
        rewrite_mutex = REWRITE_MUTEX;
        if (rewrite_mutex != 0)
            (void)xQueueGenericSend(rewrite_mutex,0,0,0);
    }
check_service_status:
    if (REPORT_PROCESS_STATUS == 0) {
service_endpoint:
        report_service_endpoint(canonical);
    }
    report_mutex = REPORT_MUTEX;
    if (report_mutex != 0)
        (void)xQueueGenericSend(report_mutex,0,0,0);
    if (work != 0)
        report_perform_wakeup();
}
