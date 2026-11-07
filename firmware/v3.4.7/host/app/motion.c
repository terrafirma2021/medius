/* Medius v3.4.7 host — app/motion.c.
 */

#include "../include/types.h"

/* Source reconstruction utilities; not additional native firmware entries. */
static unsigned int motion_pending_clamp(long long value)
{
    if(value < -0x40000000LL)return 0xc0000000U;
    if(value > 0x40000000LL)return 0x40000000U;
    return (unsigned int)value;
}

/* Source reconstruction utilities for the configuration reset and axis-limit
 * blocks, not additional native entries. Preserve all visible reset stores. */
static void motion_configuration_clear_fractions(volatile MediusMotionTransformState *state)
{
    for (unsigned int axis = 0; axis != 4; ++axis) {
        state->fractions[axis][0] = 0;
        state->fractions[axis][1] = 0;
    }
    state->coupled_fractions[1] = 0;
    state->coupled_fractions[0] = 0;
}

static void motion_configuration_clear_recent(volatile MediusMotionTransformState *state)
{
    memset(MEDIUS_MOTION_RECENT_AXIS_STATE,0,16);
    memset((void *)MEDIUS_MOTION_AXIS_LAST_INPUT_TIMES,0,32);
    memset((void *)state->recent_state,0,16);
}

static int motion_configuration_axis_limit(int positive,int negative)
{
    long long limit = positive;
    long long other = -(long long)negative;
    if (other < limit) limit = other;
    if (limit < 127) return 127;
    if (limit > 32767) return 32767;
    return (int)limit;
}

/* Source reconstruction utilities for native42024a44, not extra native
 * entries. Interval bins use250us quanta and saturating counters; all shared
 * loads/stores remain explicit. Caller holds the pending-motion lock. */
static void motion_samples_track_interval(unsigned int source_us)
{
    unsigned int previous = MEDIUS_MOTION_LAST_SOURCE_US->low;
    unsigned int previous_high = MEDIUS_MOTION_LAST_SOURCE_US->high;
    unsigned int delta = source_us - previous;
    if ((previous | previous_high) != 0 && delta != 0 && delta < 1000000U) {
        unsigned int quotient = (unsigned int)medius_motion_signed_divide(delta,250);
        unsigned int bin = quotient <= 127 ? quotient : 127;
        volatile MediusMotionIntervalHistory *history = MEDIUS_MOTION_INTERVAL_HISTORY;
        unsigned short count = history->count;
        unsigned short head = history->head;
        if (count == 128) {
            unsigned int old_bin = history->recent_bins[head];
            unsigned short old_count = history->bins[old_bin];
            if (old_count != 0) history->bins[old_bin] = old_count - 1U;
        } else history->count = (unsigned short)(count + 1U);
        history->recent_bins[head] = (unsigned char)bin;
        unsigned short bin_count = history->bins[bin];
        history->head = (head + 1U) & 127U;
        if (bin_count != 65535U) history->bins[bin] = bin_count + 1U;
        unsigned int total = history->total_samples;
        if (total != 0xffffffffU) history->total_samples = total + 1U;
        unsigned short mode = history->modal_bin;
        unsigned short mode_count = history->bins[mode];
        unsigned short fresh_count = history->bins[bin];
        if (mode_count < fresh_count) history->modal_bin = (unsigned short)bin;
        else if (mode != bin && mode_count == 0) {
            unsigned short largest = 0,selected = 0;
            for (unsigned int index = 0; index != 128; ++index) {
                unsigned short frequency = history->bins[index];
                if (frequency > largest) { largest = frequency; selected = index; }
            }
            history->modal_bin = selected;
        }
    }
    MEDIUS_MOTION_LAST_SOURCE_US->low = source_us;
    MEDIUS_MOTION_LAST_SOURCE_US->high = 0;
}

static unsigned int motion_samples_unique_multiple(unsigned int period,unsigned int requested)
{
    unsigned int selected = 0;
    for (unsigned int multiple = 1; multiple != 5; ++multiple) {
        unsigned long long lower = (unsigned long long)period * multiple;
        unsigned long long upper = ((unsigned long long)period + 281ULL) * multiple;
        if (lower <= requested && requested <= upper) {
            if (selected != 0) return 0;
            selected = multiple;
        }
    }
    return selected;
}

static unsigned int motion_samples_modal_period(void)
{
    if (MEDIUS_MOTION_INTERVAL_HISTORY->total_samples <= 15) return 0;
    unsigned short mode = MEDIUS_MOTION_INTERVAL_HISTORY->modal_bin;
    return mode <= 126 ? (unsigned int)mode * 250U : 0;
}

/* Source reconstruction utilities for native403878e4, not extra native
 * entries. Preserve modulo64 multiply/rounding and signed division. The
 * denominator and elapsed interval have already passed signed-positive tests. */
static unsigned int motion_report_interpolate(unsigned int value,
    unsigned long long elapsed,unsigned long long duration)
{
    unsigned long long numerator = elapsed * (unsigned long long)(long long)(int)value;
    unsigned long long half = duration >> 1;
    if ((long long)numerator < 0) numerator -= half;
    else numerator += half;
    long long quotient = medius_motion_signed_divide((long long)numerator,(long long)duration);
    long long bound = (int)value;
    if (bound > 0 ? quotient < bound : quotient > bound) return (unsigned int)quotient;
    return value;
}

/* Consume an already sampled, nonzero queue count. Caller holds the motion
 * lock. The native queue trusts count/multiple; no extra eight-slot guard is
 * inserted. The nonpositive-clock path consumes every entry without pacing. */
static void motion_report_consume_segments(unsigned int now_low,unsigned int now_high,
    unsigned int count,unsigned int original[2],unsigned int emitted[2],
    unsigned int remaining[2])
{
    volatile MediusMotionSegmentQueue *queue = MEDIUS_MOTION_SEGMENTS;
    unsigned long long now = ((unsigned long long)now_high << 32) | now_low;
    unsigned int consume = count;
    unsigned int retained = 0;
    if ((long long)now > 0) {
        unsigned int last_low = queue->last_consume_us.low;
        unsigned int last_high = queue->last_consume_us.high;
        unsigned int half_duration = queue->selected_duration_us >> 1;
        long long elapsed = (long long)(now - (((unsigned long long)last_high << 32) | last_low));
        int paced = elapsed >= 0 && (unsigned long long)elapsed >= half_duration;
        unsigned int multiple = queue->multiple;
        consume = paced ? (count < multiple ? count : multiple) : 0;
        if (!paced || multiple < count) {
            while (consume < count) {
                unsigned int high = queue->entries[consume].until_us.high;
                if ((int)now_high < (int)high) break;
                if (high == now_high && now_low < queue->entries[consume].until_us.low) break;
                consume = (unsigned char)(consume + 1U);
            }
            if (count - consume > multiple) consume = (unsigned char)(count - multiple);
        }
        retained = count - consume;
        if (consume == 0) {
            remaining[0] = original[0] - emitted[0];
            remaining[1] = original[1] - emitted[1];
            return;
        }
        if (paced) {
            queue->last_consume_us.high = now_high;
            queue->last_consume_us.low = now_low;
        }
    }
    unsigned int sum_x = 0,sum_y = 0;
    for (unsigned int index = 0; index != consume; ++index) {
        short x = queue->entries[index].x;
        short y = queue->entries[index].y;
        sum_x += (unsigned int)(int)x;
        sum_y += (unsigned int)(int)y;
    }
    /* ROM memmove returns the destination. Read count again after the copy. */
    volatile MediusMotionSegmentQueue *moved = memmove((void *)queue,
        (const void *)&queue->entries[consume],retained * 16U);
    unsigned char fresh_count = moved->count;
    moved->count = (unsigned char)(fresh_count - consume);
    emitted[0] += sum_x;
    emitted[1] += sum_y;
    unsigned int augmented_y = motion_pending_clamp((long long)(int)original[1] + (int)sum_y);
    unsigned int augmented_x = motion_pending_clamp((long long)(int)original[0] + (int)sum_x);
    remaining[0] = augmented_x - emitted[0];
    remaining[1] = augmented_y - emitted[1];
}

/* Source reconstruction utility for native403875bc, not another native
 * function. Caller already observed a non-NULL timer. Sample the clock once,
 * reload timer for stop, then reload it again for start; do not add NULL tests.
 * The timer calls' results are ignored and only the requested delay is clamped. */
static void motion_grid_rearm_at(unsigned long long target_us)
{
    unsigned long long current_us = (unsigned long long)esp_timer_get_time();
    long long delay_us = (long long)(target_us - current_us);
    EspTimer *timer = MEDIUS_MOTION_GRID_TIMER;
    (void)esp_timer_stop(timer);
    if (delay_us < 20) delay_us = 20;
    (void)esp_timer_start_once(MEDIUS_MOTION_GRID_TIMER,(unsigned long long)delay_us);
}

/* Source reconstruction utilities for native40387f0c, not additional
 * native entries. Context axes and coefficient fractions belong to the shared
 * motion lock. All modulo arithmetic below represents native register widths. */
static int motion_hid_symmetric_clamp(long long value)
{
    if (value < -2147483647LL) return -2147483647;
    if (value > 2147483647LL) return 2147483647;
    return (int)value;
}

static short motion_hid_short_clamp(int value)
{
    if (value < -32768) return -32768;
    if (value > 32767) return 32767;
    return (short)value;
}

static int motion_hid_bound_axis(long long value,unsigned int axis)
{
    int upper = MEDIUS_MOTION_TRANSFORM->bounds[axis].positive;
    if (value > upper) value = upper;
    int lower = MEDIUS_MOTION_TRANSFORM->bounds[axis].negative;
    if (value < lower) value = lower;
    return (int)value;
}

static void motion_hid_expire_interpolation(unsigned short policy,int raw_xy,
    unsigned long long now)
{
    if (policy == 0 || !raw_xy) return;
    unsigned int low = MEDIUS_MOTION_INTERPOLATION_REFERENCE_US->low;
    unsigned int high = MEDIUS_MOTION_INTERPOLATION_REFERENCE_US->high;
    unsigned long long reference = ((unsigned long long)high << 32) | low;
    if (reference != 0 && (long long)(now - reference) > (long long)policy * 1000LL) {
        memset((void *)MEDIUS_MOTION_INTERPOLATED_AXES,0,16);
        for (unsigned int index = 0; index != 4; ++index)
            MEDIUS_MOTION_INTERPOLATION_CLOCK_WORDS[index] = 0;
        memset(MEDIUS_MOTION_SEGMENT_STORAGE,0,144);
        motion_configuration_clear_recent(MEDIUS_MOTION_TRANSFORM);
    }
    /* An admitted raw XY report clears this reference even when not expired. */
    MEDIUS_MOTION_INTERPOLATION_REFERENCE_US->low = 0;
    MEDIUS_MOTION_INTERPOLATION_REFERENCE_US->high = 0;
}

static void motion_hid_collect_context(unsigned long long now,int context[4])
{
    unsigned short policy = MEDIUS_MOTION_INTERPOLATION_POLICY;
    int stale = 0;
    if (policy != 0) {
        unsigned int low = MEDIUS_MOTION_INTERPOLATION_REFERENCE_US->low;
        unsigned int high = MEDIUS_MOTION_INTERPOLATION_REFERENCE_US->high;
        unsigned long long reference = ((unsigned long long)high << 32) | low;
        stale = reference != 0 && (long long)(now - reference) > (long long)policy * 1000LL;
    }
    unsigned int window_us = (unsigned int)MEDIUS_MOTION_FILTER_PARAMETER * 1000U;
    for (unsigned int axis = 0; axis != 4; ++axis) {
        long long balance = (int)MEDIUS_MOTION_PENDING_AXES[axis];
        if (!stale) {
            balance += (int)MEDIUS_MOTION_INTERPOLATED_AXES[axis];
            if (axis < 2) {
                unsigned char count = MEDIUS_MOTION_SEGMENTS->count;
                unsigned int sum_x = 0,sum_y = 0;
                for (unsigned int index = 0; index != count; ++index) {
                    short x = MEDIUS_MOTION_SEGMENTS->entries[index].x;
                    short y = MEDIUS_MOTION_SEGMENTS->entries[index].y;
                    sum_x += (unsigned int)(int)x;
                    sum_y += (unsigned int)(int)y;
                }
                balance += (int)(axis == 0 ? sum_x : sum_y);
            }
        }
        int current = motion_hid_symmetric_clamp(balance);
        int recent;
        unsigned int low,high;
        int selected = 0;
        if (current != 0) {
            recent = current;
            low = (unsigned int)now;
            high = (unsigned int)(now >> 32);
            if (window_us != 0 && now != 0) selected = current;
        } else {
            recent = ((volatile int *)MEDIUS_MOTION_RECENT_AXIS_STATE)[axis];
            low = MEDIUS_MOTION_AXIS_LAST_INPUT_TIMES[axis].low;
            high = MEDIUS_MOTION_AXIS_LAST_INPUT_TIMES[axis].high;
            unsigned long long reference = ((unsigned long long)high << 32) | low;
            unsigned long long elapsed = now - reference;
            if (window_us != 0 && reference != 0 && (elapsed >> 32) == 0 &&
                (unsigned int)elapsed <= window_us) selected = recent;
        }
        context[axis] = selected;
        ((volatile int *)MEDIUS_MOTION_RECENT_AXIS_STATE)[axis] = recent;
        MEDIUS_MOTION_AXIS_LAST_INPUT_TIMES[axis].low = low;
        MEDIUS_MOTION_AXIS_LAST_INPUT_TIMES[axis].high = high;
    }
    unsigned int abs_x = context[0] < 0 ? 0U - (unsigned int)context[0] : (unsigned int)context[0];
    unsigned int abs_y = context[1] < 0 ? 0U - (unsigned int)context[1] : (unsigned int)context[1];
    unsigned int maximum = abs_x > abs_y ? abs_x : abs_y;
    if (maximum > 32767U) {
        /* Native reciprocal arithmetic equals ceil(maximum/32767). Even a
         * cached INT_MIN has magnitude0x80000000, so this addition fits32 bits. */
        unsigned int scale = (maximum + 32766U) / 32767U;
        for (unsigned int axis = 0; axis != 2; ++axis) {
            int original = context[axis];
            int scaled = (int)medius_motion_signed_divide(original,scale);
            if (scaled == 0 && original != 0) scaled = original > 0 ? 1 : -1;
            context[axis] = scaled;
        }
    }
}

/* Each axis row is [positive,negative,same-direction,opposite-direction]
 * percentages. Fractions are signed WORD remainders in units of1/10000. */
static int motion_hid_scale_axis(int value,int context,unsigned int axis,int coupled_mode)
{
    if (value == 0) return 0;
    unsigned int sign = value < 0;
    int primary = MEDIUS_MOTION_TRANSFORM->coefficients[axis][sign];
    int secondary = 100;
    if (!coupled_mode && context != 0) {
        unsigned int column = (value > 0) == (context > 0) ? 2U : 3U;
        secondary = MEDIUS_MOTION_TRANSFORM->coefficients[axis][column];
    }
    int candidate = 0;
    if (primary != 0 && secondary != 0) {
        if (primary == 100 && secondary == 100) return value;
        unsigned int fraction = MEDIUS_MOTION_TRANSFORM->fractions[axis][sign];
        unsigned long long numerator = (unsigned long long)(long long)value *
            (unsigned long long)(long long)primary * (unsigned long long)(long long)secondary;
        numerator += (unsigned long long)(long long)(int)fraction;
        long long quotient = medius_motion_signed_divide((long long)numerator,10000);
        MEDIUS_MOTION_TRANSFORM->fractions[axis][sign] =
            (unsigned int)numerator - (unsigned int)quotient * 10000U;
        candidate = motion_hid_symmetric_clamp(quotient);
    }
    /* Identity-result paths do not read bounds, even if bounds are exceeded. */
    if (candidate == value) return value;
    int bounded = motion_hid_bound_axis(candidate,axis);
    if (bounded != candidate) MEDIUS_MOTION_TRANSFORM->fractions[axis][sign] = 0;
    return bounded;
}

static void motion_hid_project_xy(int axes[4],const int context[4])
{
    unsigned long long norm = (unsigned long long)((long long)context[0] * context[0]) +
        (unsigned long long)((long long)context[1] * context[1]);
    unsigned long long dot = (unsigned long long)((long long)context[0] * axes[0]) +
        (unsigned long long)((long long)context[1] * axes[1]);
    if (norm == 0 || dot == 0) return;
    unsigned int column = (long long)dot > 0 ? 2U : 3U;
    int y_percent = MEDIUS_MOTION_TRANSFORM->coefficients[1][column];
    int x_percent = MEDIUS_MOTION_TRANSFORM->coefficients[0][column];
    int percent = x_percent < y_percent ? x_percent : y_percent;
    if (percent == 100) return;
    unsigned long long scaled_dot = dot * (unsigned long long)(long long)(percent - 100) * 100ULL;
    for (unsigned int axis = 0; axis != 2; ++axis) {
        if (MEDIUS_MOTION_TRANSFORM->bounds[axis].enabled == 0) continue;
        long long remainder = medius_motion_signed_remainder((long long)scaled_dot,(long long)norm);
        long long partial = medius_motion_signed_divide((long long)((unsigned long long)remainder *
            (unsigned long long)(long long)context[axis]),(long long)norm);
        long long whole = medius_motion_signed_divide((long long)scaled_dot,(long long)norm);
        unsigned long long numerator = (unsigned long long)whole *
            (unsigned long long)(long long)context[axis] + (unsigned long long)partial;
        unsigned int old_fraction = MEDIUS_MOTION_TRANSFORM->coupled_fractions[axis];
        numerator += (unsigned long long)(long long)(int)old_fraction;
        long long adjustment = medius_motion_signed_divide((long long)numerator,10000);
        unsigned int fraction = (unsigned int)numerator - (unsigned int)adjustment * 10000U;
        MEDIUS_MOTION_TRANSFORM->coupled_fractions[axis] = fraction;
        if (adjustment != 0) {
            long long unbounded = (long long)((unsigned long long)(long long)axes[axis] +
                (unsigned long long)adjustment);
            int bounded = motion_hid_bound_axis(unbounded,axis);
            if ((long long)bounded != unbounded) fraction = 0;
            MEDIUS_MOTION_TRANSFORM->coupled_fractions[axis] = fraction;
            axes[axis] = bounded;
        }
    }
}

static void motion_hid_requeue_excess(int axes[4],short submitted_x,short submitted_y)
{
    (void)xPortEnterCriticalTimeout(&MEDIUS_MOTION_PENDING_LOCK,-1);
    unsigned int pending_x = MEDIUS_MOTION_PENDING_AXES[0];
    unsigned int excess_x = (unsigned int)axes[0] - (unsigned int)(int)submitted_x;
    unsigned int next_x = motion_pending_clamp((long long)(int)pending_x + (int)excess_x);
    unsigned int pending_y = MEDIUS_MOTION_PENDING_AXES[1];
    unsigned int excess_y = (unsigned int)axes[1] - (unsigned int)(int)submitted_y;
    MEDIUS_MOTION_PENDING_AXES[0] = next_x;
    MEDIUS_MOTION_PENDING_AXES[1] = motion_pending_clamp((long long)(int)pending_y + (int)excess_y);
    vPortExitCritical(&MEDIUS_MOTION_PENDING_LOCK);
    axes[1] = 0;
    axes[0] = 0;
}

static void motion_hid_update_grid(unsigned int source_us_low)
{
    unsigned long long now = (unsigned long long)esp_timer_get_time();
    unsigned int source_high = (unsigned int)(now >> 32) - ((unsigned int)now < source_us_low);
    unsigned long long source = ((unsigned long long)source_high << 32) | source_us_low;
    long long base_ns,period_ns;
    int valid = medius_host_get_frame_timing(&base_ns,&period_ns,NULL);
    long long phase = -1;
    if (valid != 0) {
        phase = medius_motion_signed_remainder((long long)(source * 1000ULL -
            (unsigned long long)base_ns),period_ns);
        if (phase < 0) phase = (long long)((unsigned long long)phase + (unsigned long long)period_ns);
    }
    (void)xPortEnterCriticalTimeout(&MEDIUS_MOTION_PENDING_LOCK,-1);
    unsigned int next_low = MEDIUS_MOTION_GRID_NEXT_US->low;
    unsigned int next_high = MEDIUS_MOTION_GRID_NEXT_US->high;
    unsigned long long next = ((unsigned long long)next_high << 32) | next_low;
    int initialize = next == 0;
    int rebase = initialize || (long long)source >= (long long)(next - 999ULL);
    if (phase >= 0 && rebase) {
        MEDIUS_MOTION_GRID_PHASE_NS->low = (unsigned int)phase;
        MEDIUS_MOTION_GRID_PHASE_NS->high = (unsigned int)((unsigned long long)phase >> 32);
    }
    int drain = initialize || (long long)source >= (long long)(next - 500ULL);
    if (rebase) {
        unsigned long long target = source + 1000ULL;
        MEDIUS_MOTION_GRID_NEXT_US->low = (unsigned int)target;
        MEDIUS_MOTION_GRID_NEXT_US->high = (unsigned int)(target >> 32);
    }
    vPortExitCritical(&MEDIUS_MOTION_PENDING_LOCK);
    if (drain) {
        medius_motion_drain_output_guarded();
        medius_motion_wake_worker();
    }
}

/* Native entry: 0x42025450. */
/*
 * Medius v3.4.7 — host application; 0x42025450.
 * Instruction-checked recovered C.
 * Original function-byte SHA-256:
 * 9a7fe8b3e7f4c9f14885d29757ff2589dbbd79462bf67671e13ea03715d5d10d.
 */

/*
 * Cancel the motion engine and requeue its unconsumed input deltas. length is
 * narrowed to16 bits; values below2 do nothing. payload must provide2 readable
 * bytes. Both bytes are copied before cancellation; only byte0 is used.
 * A nonzero byte0 also requeues the command deltas, adding each pair modulo32
 * before interpreting it as signed. The second byte and trailing bytes are
 * ignored. Each signed pending axis plus its signed delta is saturated to
 * [-0x40000000,0x40000000]. Y is sampled before X is stored.
 * Engine cancellation and pending publication use separate critical sections;
 * acquisition results are ignored. After unlocking, force a status publication.
 * No result, rollback or acknowledgement of the subsequent UART send is given.
 */
void medius_motion_cancel_requeue(const unsigned char *payload,unsigned short length)
{
    if(length<2)return;
    unsigned char request[2];
    memcpy(request,payload,2);
    unsigned int command_x=0,command_y=0,input_x=0,input_y=0;
    medius_motion_cancel_read(&command_x,&command_y,&input_x,&input_y);
    xPortEnterCriticalTimeout(&MEDIUS_MOTION_PENDING_LOCK,-1);
    if(request[0]){input_x+=command_x;input_y+=command_y;}
    unsigned int old_x=MEDIUS_MOTION_PENDING_AXES[0];
    long long sum_x=(long long)(int)old_x+(int)input_x;
    unsigned int next_x=motion_pending_clamp(sum_x);
    unsigned int old_y=MEDIUS_MOTION_PENDING_AXES[1];
    long long sum_y=(long long)(int)old_y+(int)input_y;
    MEDIUS_MOTION_PENDING_AXES[0]=next_x;
    MEDIUS_MOTION_PENDING_AXES[1]=motion_pending_clamp(sum_y);
    vPortExitCritical(&MEDIUS_MOTION_PENDING_LOCK);
    medius_motion_publish_status(1);
}

/* Native entry: 0x42032384. */
/*
 * Medius v3.4.7 — host application; 0x42032384.
 * Instruction-checked recovered C.
 * Original function-byte SHA-256:
 * 7008af43af138ea86567f580e43193d6da5e1decd76e2ab80568e3b4296809c2.
 */

/*
 * Return optional command X/Y and input X/Y balances, then cancel the engine.
 * Each output is a modulo32 sum of active and staged contributions. Outputs
 * are written in parameter order before subsequent state reads: aliasing an
 * output with another output or the engine therefore affects later reads.
 * All four accumulator words and all eight balance words are sampled when
 * deciding whether to wake the worker. Cancellation sums that wrap to zero
 * count as zero. Only an all-zero aggregate falls back to the raw busy byte.
 * Clear staged balances, accumulators, split timestamps and active balances,
 * then publish the previously sampled generation+1 modulo32 after MEMW.
 * A nonzero wake decision sets cancel_requested after MEMW. It does not clear
 * busy or cancel_requested on the idle path. Unlock before sampling the worker
 * once and optionally notify index0/value0/eSetValueWithOverwrite(2).
 * The critical-section and notification results are ignored; no value returns.
 */
void medius_motion_cancel_read(unsigned int *command_x,unsigned int *command_y,
    unsigned int *input_x,unsigned int *input_y)
{
    volatile MediusMotionEngineState *engine=MEDIUS_MOTION_ENGINE;
    xPortEnterCriticalTimeout(&MEDIUS_MOTION_ENGINE_LOCK,-1);
    if(command_x){
        unsigned int active=engine->active.command_x;
        unsigned int staged=engine->staged.command_x;
        *command_x=active+staged;
    }
    if(command_y){
        unsigned int active=engine->active.command_y;
        unsigned int staged=engine->staged.command_y;
        *command_y=active+staged;
    }
    if(input_x){
        unsigned int active=engine->active.input_x;
        unsigned int staged=engine->staged.input_x;
        *input_x=active+staged;
    }
    if(input_y){
        unsigned int active=engine->active.input_y;
        unsigned int staged=engine->staged.input_y;
        *input_y=staged+active;
    }
    unsigned int immediate_y=engine->immediate_y;
    unsigned int immediate_x=engine->immediate_x;
    unsigned int timed_x=engine->timed_x;
    unsigned int timed_y=engine->timed_y;
    unsigned int active_command_x=engine->active.command_x;
    unsigned int active_input_x=engine->active.input_x;
    unsigned int active_command_y=engine->active.command_y;
    unsigned int active_input_y=engine->active.input_y;
    unsigned int staged_input_x=engine->staged.input_x;
    unsigned int staged_command_x=engine->staged.command_x;
    unsigned int staged_input_y=engine->staged.input_y;
    unsigned int staged_command_y=engine->staged.command_y;
    unsigned int pending=immediate_x|immediate_y|timed_y|timed_x|
        (active_command_x+active_input_x)|(active_input_y+active_command_y)|
        (staged_input_x+staged_command_x)|(staged_input_y+staged_command_y);
    unsigned char wake=1;
    if(!pending){memw();wake=engine->busy;}
    memw();
    unsigned int next_generation=engine->generation+1U;
    engine->staged.input_x=0;engine->staged.command_x=0;
    engine->staged.input_y=0;engine->staged.command_y=0;
    engine->immediate_x=0;engine->immediate_y=0;
    engine->timed_x=0;engine->timed_y=0;
    engine->timed_until_us.low=0;engine->timed_until_us.high=0;
    engine->timed_started_us.low=0;engine->timed_started_us.high=0;
    engine->active.input_x=0;engine->active.command_x=0;
    engine->active.input_y=0;engine->active.command_y=0;
    memw();engine->generation=next_generation;
    if(wake){memw();engine->cancel_requested=1;}
    vPortExitCritical(&MEDIUS_MOTION_ENGINE_LOCK);
    if(wake){
        RtosTask *worker=engine->worker;
        if(worker)xTaskGenericNotify(worker,0,0,2,NULL);
    }
}

/* Native entry: 0x403890c0. */
/*
 * Medius v3.4.7 — host application; 0x403890c0.
 * Instruction-checked recovered C.
 * Original function-byte SHA-256:
 * 115f98e5d943e73fc8d1a41a9e3703eea4fef4bb8228ab9544caa9373023d088.
 */

/*
 * Publish a14-byte motion/status record on link opcode0x37,flags0. force is
 * a full-width integer; any nonzero value bypasses unchanged-status suppression.
 * Bit0 is always set; bit1 reflects the sampled raw program-ready byte. Sample
 * time once, then command-pending. Under the pending lock, command work, a
 * nonzero segment count, or any of four paired interpolated/pending axes extends
 * the activity deadline to now+20000us modulo64. An existing signed future
 * deadline also sets bit3. These active/holdover paths call motion_pending but
 * ignore its result and always set bit2. Outside holdover, bit2 uses that result.
 *
 * The interval metric is zero until sample_count>15 and modal_bin<=126;
 * otherwise it is floor((250*modal_bin)*scale/100), with scale read once as16
 * bits. These histogram/config reads occur outside the lock and are not one
 * coherent snapshot. The payload holds flags8, tag8, metric32, counted RX
 * drops32 and other-type RX drops32, all multibyte fields little-endian.
 *
 * With force0, unchanged flags/metric/counted drops suppress transmission while
 * signed wrapped(now-last_sent)<=999999us, including negative elapsed values.
 * Tag and other-type drops are excluded from that comparison. On transmission,
 * sample tag, then commit flags, metric, counted drops and last_sent LOW/HIGH
 * before sampling other-type drops and calling the nonwaiting send wrapper.
 * A failed send still leaves this cache updated. No send result is returned.
 * Lock acquisition status is ignored; cache/histogram accesses are not locked.
 */
void medius_motion_publish_status(int force)
{
    unsigned short flags=medius_motion_program_ready()?3:1;
    unsigned long long now=(unsigned long long)esp_timer_get_time();
    unsigned char command_pending=medius_motion_command_pending();
    xPortEnterCriticalTimeout(&MEDIUS_MOTION_PENDING_LOCK,-1);
    unsigned char active=command_pending!=0;
    if(!active)active=MEDIUS_MOTION_SEGMENT_COUNT!=0;
    if(!active){
        for(unsigned int axis=0;axis<4;++axis){
            unsigned int interpolated=MEDIUS_MOTION_INTERPOLATED_AXES[axis];
            if(interpolated){active=1;break;}
            unsigned int pending=MEDIUS_MOTION_PENDING_AXES[axis];
            if(pending){active=1;break;}
        }
    }
    unsigned char holdover;
    if(active){
        unsigned long long until=now+20000ULL;
        MEDIUS_MOTION_STATUS_CACHE->active_until_us.low=(unsigned int)until;
        MEDIUS_MOTION_STATUS_CACHE->active_until_us.high=(unsigned int)(until>>32);
        vPortExitCritical(&MEDIUS_MOTION_PENDING_LOCK);
        holdover=1;
    }else{
        unsigned int high=MEDIUS_MOTION_STATUS_CACHE->active_until_us.high;
        unsigned int low=MEDIUS_MOTION_STATUS_CACHE->active_until_us.low;
        vPortExitCritical(&MEDIUS_MOTION_PENDING_LOCK);
        holdover=(long long)now<(long long)(((unsigned long long)high<<32)|low);
    }
    if(holdover){flags|=8;medius_motion_pending();flags|=4;}
    else if(medius_motion_pending())flags|=4;
    unsigned int metric=0;
    unsigned int samples=MEDIUS_MOTION_INTERVAL_SAMPLE_COUNT;
    if(samples>15){
        unsigned short modal_bin=MEDIUS_MOTION_INTERVAL_MODAL_BIN;
        if(modal_bin<=126){
            unsigned short scale=MEDIUS_MOTION_INTERVAL_SCALE;
            unsigned int interval=250U*modal_bin;
            if(interval&&scale)metric=(unsigned int)((unsigned long long)interval*scale/100U);
        }
    }
    unsigned int drops=medius_link_counted_rx_drop_count();
    volatile MediusMotionStatusCache *cache=MEDIUS_MOTION_STATUS_CACHE;
    if(!force&&cache->flags==flags&&cache->interval_metric==metric&&cache->counted_rx_drops==drops){
        unsigned int low=cache->last_sent_us.low;
        unsigned int high=cache->last_sent_us.high;
        unsigned long long last=((unsigned long long)high<<32)|low;
        if((long long)(now-last)<=999999LL)return;
    }
    unsigned char tag=MEDIUS_MOTION_STATUS_TAG;
    cache->flags=(unsigned char)flags;
    cache->interval_metric=metric;
    cache->counted_rx_drops=drops;
    cache->last_sent_us.low=(unsigned int)now;
    cache->last_sent_us.high=(unsigned int)(now>>32);
    MediusMotionStatusPacket packet;
    packet.flags_and_tag=(unsigned short)(flags|((unsigned short)tag<<8));
    packet.metric_low=(unsigned short)metric;
    packet.metric_high=(unsigned short)(metric>>16);
    packet.counted_drops_low=(unsigned short)drops;
    packet.counted_drops_high=(unsigned short)(drops>>16);
    unsigned int other=medius_link_other_rx_drop_count();
    packet.other_drops_low=(unsigned short)other;
    packet.other_drops_high=(unsigned short)(other>>16);
    medius_link_send_borrowed_nowait(0x37,0,&packet,14);
}

/* Native entry: 0x4038b540. */
/*
 * Medius v3.4.7 — host application; 0x4038b540.
 * Instruction-checked recovered C.
 * Original function-byte SHA-256:
 * b43b39c924b85ff52087d7b7f78f803aa27376076e8391f7688633920ffc9e60.
 */

/*
 * Query motion work under the engine critical section. After MEMW, sample busy
 * once and return its raw nonzero byte unchanged. Otherwise compare the two
 * separately fenced output-ring cursors; unequal cursors return1. If equal,
 * read all four staged contributions, sum each axis modulo32 and return0/1.
 * Active balances and the timed/immediate accumulators are not inspected.
 * Unlock on every path. Acquisition status is ignored; no state is cleared.
 */
unsigned char medius_motion_pending(void)
{
    volatile MediusMotionEngineState *engine=MEDIUS_MOTION_ENGINE;
    xPortEnterCriticalTimeout(&MEDIUS_MOTION_ENGINE_LOCK,-1);
    memw();unsigned char pending=engine->busy;
    if(!pending){
        memw();unsigned int read_index=MEDIUS_MOTION_OUTPUT_READ;
        memw();unsigned int write_index=MEDIUS_MOTION_OUTPUT_WRITE;
        if(read_index!=write_index)pending=1;
        else{
            unsigned int command_x=engine->staged.command_x;
            unsigned int input_x=engine->staged.input_x;
            unsigned int input_y=engine->staged.input_y;
            unsigned int command_y=engine->staged.command_y;
            pending=((command_x+input_x)|(input_y+command_y))!=0;
        }
    }
    vPortExitCritical(&MEDIUS_MOTION_ENGINE_LOCK);
    return pending;
}

/* Native entry: 0x4038ba4c. */
/*
 * Medius v3.4.7 — host application; 0x4038ba4c.
 * Instruction-checked recovered C.
 * Original function-byte SHA-256:
 * 2938221c4682e90895912ce30651103692c0706a8f41147bc962ad835022b299.
 */

/*
 * Return0/1 for command motion still represented in staged/active X/Y balances
 * or timed X/Y accumulators. Read all six native32 words in their native order
 * under the engine lock, even after a nonzero word. No axis cancellation is
 * applied to this test. Input balances, immediate accumulators, busy and the
 * output ring are excluded. Ignore acquisition status and unlock before return.
 */
unsigned char medius_motion_command_pending(void)
{
    volatile MediusMotionEngineState *engine=MEDIUS_MOTION_ENGINE;
    xPortEnterCriticalTimeout(&MEDIUS_MOTION_ENGINE_LOCK,-1);
    unsigned int staged_x=engine->staged.command_x;
    unsigned int staged_y=engine->staged.command_y;
    unsigned int active_x=engine->active.command_x;
    unsigned int active_y=engine->active.command_y;
    unsigned int timed_x=engine->timed_x;
    unsigned int timed_y=engine->timed_y;
    unsigned char pending=(staged_x|staged_y|active_x|active_y|timed_x|timed_y)!=0;
    vPortExitCritical(&MEDIUS_MOTION_ENGINE_LOCK);
    return pending;
}

/* Native entry: 0x4038bb70. */
/*
 * Medius v3.4.7 — host application; 0x4038bb70.
 * Instruction-checked recovered C.
 * Original function-byte SHA-256:
 * 8f9c8a8bb806ae08e8359f161184665790c1304fe1528348dafa88aee3cdaa32.
 */

/*
 * Return the raw motion-program-ready byte after MEMW. The worker sets this
 * after copying a prepared program and clears it on its reset path. This is
 * one byte read, not a lock, boolean normalization or a program-data snapshot.
 */
unsigned char medius_motion_program_ready(void)
{
    memw();return MEDIUS_MOTION_PROGRAM_READY;
}

/* Native entry: 0x42032488. */
/*
 * Medius v3.4.7 — host application; 0x42032488.
 * Instruction-checked recovered C.
 * Original function-byte SHA-256:
 * b515531b968385014c9a8431357eeac99cbcc1df06b80a420d7e4cae75ab6b6a.
 */

/*
 * Update the engine's raw byte policy under its critical section. Arguments
 * are narrowed to8 bits, without boolean normalization or mode validation.
 * MEMW precedes each access: sample old enabled, sample old input_enabled,
 * store enabled, store program_mode, then store input_enabled. Ignore lock
 * acquisition status and unlock before evaluating the cached transition result.
 * Return old_enabled & (enabled^1) if nonzero, otherwise return
 * old_input_enabled & (input_enabled^1). This is a raw bitwise result, not a
 * boolean for arbitrary byte inputs. No reset, cancellation or wake occurs.
 */
unsigned char medius_motion_set_policy(unsigned char enabled,unsigned char program_mode,
    unsigned char input_enabled)
{
    volatile MediusMotionEngineState *engine=MEDIUS_MOTION_ENGINE;
    xPortEnterCriticalTimeout(&MEDIUS_MOTION_ENGINE_LOCK,-1);
    memw();unsigned char old_enabled=engine->enabled;
    memw();unsigned char old_input_enabled=engine->input_enabled;
    memw();engine->enabled=enabled;
    memw();engine->program_mode=program_mode;
    memw();engine->input_enabled=input_enabled;
    vPortExitCritical(&MEDIUS_MOTION_ENGINE_LOCK);
    unsigned char changed=old_enabled&(enabled^1U);
    if(!changed)changed=old_input_enabled&(input_enabled^1U);
    return changed;
}

/* Native entry: 0x420324e8. */
/*
 * Medius v3.4.7 — host application; 0x420324e8.
 * Instruction-checked recovered C.
 * Original function-byte SHA-256:
 * bf7d294bb7eb20fbd5672adb5c359d0ecacbdcda54e12e0c3d7d4fa1c040ea29.
 */

/*
 * Clear motion accounting and request a full worker reset. Under the engine
 * lock, clear immediate X/Y, MEMW and sample generation, then clear timed X,
 * active balances, staged balances, timed Y and both split timestamps in that
 * order. Publish the sampled generation+1 modulo32 after MEMW, then unlock.
 * Sample worker once after unlocking, before MEMW/store reset_requested=1.
 * Notify that cached nonNULL worker at index0/value0/action2, ignoring status.
 * A NULL worker still leaves reset_requested set. Lock status is ignored.
 * busy, cancel_requested, policy and program-ready are not cleared here;
 * the separate worker handles the reset request asynchronously. No completion
 * wait, acknowledgement, notification retry or return value is provided.
 */
void medius_motion_request_reset(void)
{
    volatile MediusMotionEngineState *engine=MEDIUS_MOTION_ENGINE;
    xPortEnterCriticalTimeout(&MEDIUS_MOTION_ENGINE_LOCK,-1);
    engine->immediate_x=0;engine->immediate_y=0;
    memw();unsigned int next_generation=engine->generation+1U;
    engine->timed_x=0;
    engine->active.input_x=0;engine->active.command_x=0;
    engine->active.input_y=0;engine->active.command_y=0;
    engine->staged.input_x=0;engine->staged.command_x=0;
    engine->staged.input_y=0;engine->staged.command_y=0;
    engine->timed_y=0;
    engine->timed_until_us.low=0;engine->timed_until_us.high=0;
    engine->timed_started_us.low=0;engine->timed_started_us.high=0;
    memw();engine->generation=next_generation;
    vPortExitCritical(&MEDIUS_MOTION_ENGINE_LOCK);
    RtosTask *worker=engine->worker;
    memw();engine->reset_requested=1;
    if(worker)xTaskGenericNotify(worker,0,0,2,NULL);
}

/* Native entry: 0x42032568. */
/*
 * Medius v3.4.7 — host application; 0x42032568.
 * Instruction-checked recovered C.
 * Original function-byte SHA-256:
 * 6d37db3f52b281b1ec52c8a71561afa05a2ccd97bb7e73ba6b41ad19c34f6de5.
 */

/*
 * Clamp full-width signed X/Y motion limits independently to[1,32767] and
 * publish one16-bit X store followed by one16-bit Y store under the engine
 * lock. Each axis has only its final clamped store; the raw export's transient
 * stores of1/32767 are absent from native code. Lock acquisition status is
 * ignored. No MEMW, worker notification, cancellation or value return occurs.
 */
void medius_motion_set_axis_limits(int x_limit,int y_limit)
{
    xPortEnterCriticalTimeout(&MEDIUS_MOTION_ENGINE_LOCK,-1);
    int x=x_limit<1?1:x_limit>32767?32767:x_limit;
    MEDIUS_MOTION_AXIS_LIMITS->x=(unsigned short)x;
    int y=y_limit<1?1:y_limit>32767?32767:y_limit;
    MEDIUS_MOTION_AXIS_LIMITS->y=(unsigned short)y;
    vPortExitCritical(&MEDIUS_MOTION_ENGINE_LOCK);
}

/* Native entry: 0x4038ba1c. */
/*
 * Medius v3.4.7 — host application; 0x4038ba1c.
 * Instruction-checked recovered C.
 * Original function-byte SHA-256:
 * 5866eea733a53b816e4e42d97b38a6a5f17cda572d4749e121ec98ff1241cdb7.
 */

/*
 * Return0 unless the separately fenced enabled and input_enabled bytes are
 * both nonzero. If both pass, return the raw program-ready byte after another
 * MEMW. Reads short-circuit in that order; the result is not normalized to1.
 * No lock, reset-request check or coherent policy/program snapshot is supplied.
 */
unsigned char medius_motion_input_program_ready(void)
{
    memw();unsigned char enabled=MEDIUS_MOTION_ENGINE->enabled;
    if(!enabled)return 0;
    memw();unsigned char input_enabled=MEDIUS_MOTION_ENGINE->input_enabled;
    if(!input_enabled)return 0;
    memw();return MEDIUS_MOTION_PROGRAM_READY;
}

/* Native entry: 0x4038bb18. */
/*
 * Medius v3.4.7 — host application; 0x4038bb18.
 * Instruction-checked recovered C.
 * Original function-byte SHA-256:
 * 2375753b093c3af553215178c9fd2fdeccdc562696b6e5745c6b5b2eac92a78d.
 */

/*
 * Enqueue an input record: caller-supplied32-bit stamp, then signed X/Y packed
 * into low/high16 bits of the second word. Sample write_index after MEMW, then
 * read_index after MEMW. next=(cached_write+1)&255; if next==read, silently drop
 * the record with no stores or notification. Otherwise use cached_write*8 for
 * both record stores, preserving native32 address wrap and no index repair.
 * Two MEMWs precede publishing next; sample worker once afterward and notify
 * index0/value0/action2 when nonNULL, ignoring the notification result.
 * No lock, space wait, overflow counter or result is supplied. Requires an
 * externally serialized producer and valid ring storage/cursors for safe use.
 * Cursor reads and the later worker sample are not a coherent snapshot.
 */
void medius_motion_enqueue_input(unsigned int stamp,short x,short y)
{
    memw();unsigned int write_index=MEDIUS_MOTION_INPUT_WRITE;
    memw();unsigned int read_index=MEDIUS_MOTION_INPUT_READ;
    unsigned int next=(write_index+1U)&255U;
    if(next==read_index)return;
    unsigned int address=0x3fcb9928U+write_index*8U;
    volatile MediusMotionInputRecord *record=(volatile MediusMotionInputRecord *)address;
    record->stamp=stamp;
    record->xy=(unsigned int)(unsigned short)x|((unsigned int)(unsigned short)y<<16);
    memw();memw();MEDIUS_MOTION_INPUT_WRITE=next;
    RtosTask *worker=MEDIUS_MOTION_ENGINE->worker;
    if(worker)xTaskGenericNotify(worker,0,0,2,NULL);
}

/* Native entry: 0x4038bb84. */
/*
 * Medius v3.4.7 — host application; 0x4038bb84.
 * Instruction-checked recovered C.
 * Original function-byte SHA-256:
 * 387d5919c57cf58ecbae0e9f1de297e15844bc7d6a5dca20dff2ca5b1d6f3c77.
 */

/*
 * Sample the motion worker's wake semaphore once. If nonNULL, give it using
 * xQueueGenericSend(handle,NULL,0,queueSEND_TO_BACK=0), with no wait. Ignore
 * the result, including a full semaphore. A NULL handle is a no-op. No MEMW,
 * lock, retry, task notification or motion-state update occurs in this helper.
 */
void medius_motion_wake_worker(void)
{
    RtosQueue *semaphore=MEDIUS_MOTION_ENGINE->wake_semaphore;
    if(semaphore)xQueueGenericSend(semaphore,NULL,0,0);
}

/* Native entry: 0x42024544. */
/* Original function-byte SHA-256:
 * a154063a4920f3c753cde99a21c6302222af38346b738c6cd925cab0295d7ef6. */
/*
 * Apply a101-byte motion configuration (low16 length<101: no action). Copy the
 * incoming wire record BEFORE taking the pending-motion lock forever. Under
 * lock copy old101 bytes, sample old filter HALF, ready BYTE, mode BYTE, policy
 * HALF. Full reset iff not ready, tag differs, or endpoint differs; tag/endpoint
 * comparisons reread shared configuration rather than the saved copy.
 * Publish new101 bytes, copy32 coefficient bytes into transform state, decode
 * four unaligned signed32 positive/negative bounds and enable bits, set mode,
 * ready1, then publish endpoint/report-id activity selector while still locked.
 *
 * Full reset clears interpolated/pending16 bytes each, four interpolation-clock WORDs,
 * segment144, recent-axis16/per-axis clocks32/transform16, interval396 and both split
 * reference clocks. Write four rows of100 coefficients, clear all fractions
 * (coupled HIGH before LOW), then overwrite coefficients from the new record.
 * Unlock, request renderer reset. Otherwise a changed mode clears all fractions
 * and the three recent spans. With unchanged mode compare four HALF fields in
 * each saved/new coefficient row; first difference clears that row HIGH then
 * LOW, and rows0/1 also clear coupled HIGH/LOW. Changed filter parameter clears
 * recent spans. Changed interpolation policy additionally clears interpolation,
 * interpolation-clock WORDs, segment/recent spans and reference clock0, retaining pending
 * axes, interval histogram and reference clock1. Unlock on every admitted path.
 *
 * Outside the lock set X/Y limits: unbounded axis32767; otherwise clamp
 * min(signed positive_bound,-signed negative_bound) to[127,32767], with64-bit
 * negation including INT_MIN. Set renderer policy(enabled=selector!=0, mode=
 * selector?low8(selector-1):0, input_enabled=byte82!=0). If it changes, cancel/read
 * command/input X/Y, sum each pair modulo32, add signed to pending X/Y in64 bits
 * and clamp to+/-0x40000000. Read pendingY BEFORE publishing pendingX; use a
 * separate lock interval. Finally force status publication. No input NULL guard,
 * atomic wire/renderer transaction, delivery result or rollback is introduced.
 */
void medius_motion_configuration_receive(const unsigned char *payload,unsigned short length)
{
    if (length < 101) return;
    MediusMotionWireConfiguration incoming,previous;
    memcpy(&incoming,payload,101);
    (void)xPortEnterCriticalTimeout(&MEDIUS_MOTION_PENDING_LOCK,-1);
    memcpy(&previous,(const void *)MEDIUS_MOTION_WIRE_CONFIGURATION,101);
    unsigned short old_filter = MEDIUS_MOTION_FILTER_PARAMETER;
    unsigned char was_ready = MEDIUS_MOTION_CONFIGURATION_READY;
    unsigned char old_mode = MEDIUS_MOTION_MAPPING_MODE;
    unsigned short old_policy = MEDIUS_MOTION_INTERPOLATION_POLICY;
    int full_reset = was_ready == 0 || incoming.tag != MEDIUS_MOTION_STATUS_TAG ||
        incoming.endpoint != MEDIUS_MOTION_WIRE_CONFIGURATION->endpoint;
    memcpy((void *)MEDIUS_MOTION_WIRE_CONFIGURATION,&incoming,101);
    volatile MediusMotionTransformState *state = MEDIUS_MOTION_TRANSFORM;
    memcpy((void *)state->coefficients,incoming.coefficients,32);
    for (unsigned int axis = 0; axis != 4; ++axis) {
        state->bounds[axis].positive = incoming.positive_bounds[axis];
        state->bounds[axis].negative = incoming.negative_bounds[axis];
        state->bounds[axis].enabled = (incoming.bounded_axes >> axis) & 1U;
    }
    state->mapping_mode = incoming.mapping_mode;
    MEDIUS_MOTION_CONFIGURATION_READY = 1;
    medius_hid_set_activity_selector(incoming.endpoint,incoming.report_id);
    if (full_reset) {
        memset((void *)MEDIUS_MOTION_INTERPOLATED_AXES,0,16);
        memset((void *)MEDIUS_MOTION_PENDING_AXES,0,16);
        for (unsigned int axis = 0; axis != 4; ++axis) MEDIUS_MOTION_INTERPOLATION_CLOCK_WORDS[axis] = 0;
        memset(MEDIUS_MOTION_SEGMENT_STORAGE,0,144);
        motion_configuration_clear_recent(state);
        memset(MEDIUS_MOTION_INTERVAL_STORAGE,0,396);
        MEDIUS_MOTION_REFERENCE_CLOCKS[0].low = 0;
        MEDIUS_MOTION_REFERENCE_CLOCKS[0].high = 0;
        MEDIUS_MOTION_REFERENCE_CLOCKS[1].low = 0;
        MEDIUS_MOTION_REFERENCE_CLOCKS[1].high = 0;
        for (unsigned int axis = 0; axis != 4; ++axis) {
            ((volatile unsigned int *)state->coefficients)[2 * axis] = 0x00640064U;
            ((volatile unsigned int *)state->coefficients)[2 * axis + 1] = 0x00640064U;
        }
        motion_configuration_clear_fractions(state);
        memcpy((void *)state->coefficients,incoming.coefficients,32);
        vPortExitCritical(&MEDIUS_MOTION_PENDING_LOCK);
        medius_motion_request_reset();
    } else {
        int clear_recent = incoming.mapping_mode != old_mode;
        if (clear_recent) motion_configuration_clear_fractions(state);
        else {
            for (unsigned int axis = 0; axis != 4; ++axis) {
                for (unsigned int coefficient = 0; coefficient != 4; ++coefficient) {
                    if (incoming.coefficients[axis][coefficient] ==
                        previous.coefficients[axis][coefficient]) continue;
                    state->fractions[axis][1] = 0;
                    state->fractions[axis][0] = 0;
                    if (axis < 2) {
                        state->coupled_fractions[1] = 0;
                        state->coupled_fractions[0] = 0;
                    }
                    break;
                }
            }
            clear_recent = incoming.filter_parameter != old_filter;
        }
        if (clear_recent) motion_configuration_clear_recent(state);
        if (incoming.interpolation_policy != old_policy) {
            memset((void *)MEDIUS_MOTION_INTERPOLATED_AXES,0,16);
            for (unsigned int axis = 0; axis != 4; ++axis) MEDIUS_MOTION_INTERPOLATION_CLOCK_WORDS[axis] = 0;
            memset(MEDIUS_MOTION_SEGMENT_STORAGE,0,144);
            motion_configuration_clear_recent(state);
            MEDIUS_MOTION_REFERENCE_CLOCKS[0].low = 0;
            MEDIUS_MOTION_REFERENCE_CLOCKS[0].high = 0;
        }
        vPortExitCritical(&MEDIUS_MOTION_PENDING_LOCK);
    }
    int x_limit = 32767,y_limit = 32767;
    if ((incoming.bounded_axes & 1U) != 0)
        x_limit = motion_configuration_axis_limit(incoming.positive_bounds[0],incoming.negative_bounds[0]);
    if ((incoming.bounded_axes & 2U) != 0)
        y_limit = motion_configuration_axis_limit(incoming.positive_bounds[1],incoming.negative_bounds[1]);
    medius_motion_set_axis_limits(x_limit,y_limit);
    unsigned char selector = incoming.program_selector;
    unsigned char mode = selector == 0 ? 0 : (unsigned char)(selector - 1U);
    if (medius_motion_set_policy(selector != 0,mode,incoming.input_enabled != 0) != 0) {
        unsigned int command_x = 0,command_y = 0,input_x = 0,input_y = 0;
        medius_motion_cancel_read(&command_x,&command_y,&input_x,&input_y);
        (void)xPortEnterCriticalTimeout(&MEDIUS_MOTION_PENDING_LOCK,-1);
        unsigned int combined_x = command_x + input_x;
        unsigned int old_x = MEDIUS_MOTION_PENDING_AXES[0];
        unsigned int next_x = motion_pending_clamp((long long)(int)combined_x + (int)old_x);
        unsigned int combined_y = command_y + input_y;
        unsigned int old_y = MEDIUS_MOTION_PENDING_AXES[1];
        unsigned int next_y = motion_pending_clamp((long long)(int)combined_y + (int)old_y);
        MEDIUS_MOTION_PENDING_AXES[0] = next_x;
        MEDIUS_MOTION_PENDING_AXES[1] = next_y;
        vPortExitCritical(&MEDIUS_MOTION_PENDING_LOCK);
    }
    medius_motion_publish_status(1);
}

/* Native entry: 0x42024a44. */
/* Original function-byte SHA-256:
 * 3f6a646b5a071fde53a2d0d91811871682e42ee80b6fcf7de8f4445d39d9954b. */
/*
 * Consume complete13-byte motion samples from low16 payload length. Initial
 * length<13 or configuration-ready0 returns; readiness is not rechecked per
 * sample. Each record has four signed16 axes, flags BYTE, unaligned source-us
 * LOW32. Copy BEFORE sampling local64 clock and locking pending motion.
 *
 * With flag7 clear, track source intervals1..999,999us in128 bins of250us,
 * clamp bin127, maintain128-entry history with HALFWORD head/count, saturate
 * bin counts65535 and totalWORD UINT_MAX. Prefer a strictly larger modal bin
 * count; if the old mode empties, rescan and choose first maximum. Always store
 * this source timestamp LOW/HIGH0. Flag7 skips interval tracking entirely.
 *
 * Flag bit2 clears interpolation, both interpolation times, segment144/recent axis16/
 * per-axis clocks32/transform16 and interpolation-reference clock; pending axes
 * and interval history remain. Else bit1 flushes all queued XY segment deltas,
 * clears segment count BYTE only, folds interpolation into pending four axes,
 * zeros interpolation and interpolation times. Release lock. Flag bits1/2 then
 * cancel/read renderer balances and, under a new lock, requeue command XY only
 * without flag2, always requeue input XY. All signed additions saturate at
 * +/-0x40000000; segment summation itself wraps32. Lock statuses are ignored.
 *
 * Modal timing needs total>15 and modal<=126. Estimated duration is floor(
 * modal*250*unsigned scale_percent/100), zero for missing period/scale. No lock
 * spans this sample. Nonzero XY can enter renderer when flag7 OR low3 flags0,
 * program-selector!=0 and program-ready. Submit with cached local time and
 * duration0 for flag7, estimated duration otherwise. Regardless of success,
 * reacquire pending lock; successful renderer admission skips manual XY only.
 *
 * Manual XY uses preferred duration (HIGH HALF then LOW); zero chooses1000 if
 * an enabled program is ready, otherwise fallback duration (HIGH then LOW),
 * finally1000. Flag0 selects direct pending XY. Other XY can queue a segment
 * when modal period>=nonzero estimated duration and exactly ONE k=1..4 contains
 * requested duration in[k*period,k*(period+281)] and queue count<8. Store XY WORD,
 * due-time HIGH then LOW, then count/k HALF and selected-duration WORD. Missing
 * eligibility, ambiguous k or full queue adds XY to interpolation. For manual
 * non-direct fallback with nonzero estimate, update interpolation until/start
 * only if the same interval test does NOT select a unique k; full queue with
 * valid k retains previous interpolation times. Due-time publication is HIGH/
 * LOW; an initial start is LOW/HIGH. These asymmetries are native behavior.
 *
 * Wheel/pan always accumulate into pending when flag0, interpolation otherwise,
 * even after renderer XY admission. For each nonzero RAW axis retain its signed
 * value and cached local64 sample time LOW/HIGH. Non-direct input initializes
 * interpolation-reference if absent, retaining its split stores. Then clear
 * that reference when policy0 or interpolation/segments empty; otherwise ensure
 * initialized. Unlock, separately relock/sample segment-count/unlock. Count0
 * calls report flush with a FRESH local clock; always publish status(force0).
 * Trailing bytes ignored. No NULL/corrupt-count validation, transaction across
 * locks/renderer/flush, transport result, timer allocation or timing guarantee.
 */
void medius_motion_samples_receive(const unsigned char *payload,unsigned short length)
{
    if (length < 13 || MEDIUS_MOTION_CONFIGURATION_READY == 0) return;
    for (unsigned int offset = 0; offset + 13U <= length; offset += 13) {
        MediusMotionWireSample sample;
        memcpy(&sample,payload + offset,13);
        unsigned long long now = (unsigned long long)esp_timer_get_time();
        (void)xPortEnterCriticalTimeout(&MEDIUS_MOTION_PENDING_LOCK,-1);
        if ((sample.flags & 0x80U) == 0) motion_samples_track_interval(sample.source_us_low);
        if ((sample.flags & 4U) != 0) {
            memset((void *)MEDIUS_MOTION_INTERPOLATED_AXES,0,16);
            for (unsigned int word = 0; word != 4; ++word) MEDIUS_MOTION_INTERPOLATION_CLOCK_WORDS[word] = 0;
            memset(MEDIUS_MOTION_SEGMENT_STORAGE,0,144);
            motion_configuration_clear_recent(MEDIUS_MOTION_TRANSFORM);
            MEDIUS_MOTION_INTERPOLATION_REFERENCE_US->low = 0;
            MEDIUS_MOTION_INTERPOLATION_REFERENCE_US->high = 0;
        } else if ((sample.flags & 2U) != 0) {
            unsigned int count = MEDIUS_MOTION_SEGMENTS->count;
            MEDIUS_MOTION_INTERPOLATION_REFERENCE_US->low = 0;
            MEDIUS_MOTION_INTERPOLATION_REFERENCE_US->high = 0;
            unsigned int sum_x = 0,sum_y = 0;
            const volatile MediusMotionSegment *segment = (const volatile void *)MEDIUS_MOTION_SEGMENTS;
            for (unsigned int remaining = count; remaining != 0; --remaining,++segment) {
                sum_x += (unsigned int)(int)segment->x;
                sum_y += (unsigned int)(int)segment->y;
            }
            unsigned int old_x = MEDIUS_MOTION_INTERPOLATED_AXES[0];
            MEDIUS_MOTION_SEGMENTS->count = 0;
            unsigned int next_x = motion_pending_clamp((long long)(int)old_x + (int)sum_x);
            unsigned int old_y = MEDIUS_MOTION_INTERPOLATED_AXES[1];
            MEDIUS_MOTION_INTERPOLATED_AXES[0] = next_x;
            MEDIUS_MOTION_INTERPOLATED_AXES[1] = motion_pending_clamp((long long)(int)old_y + (int)sum_y);
            for (unsigned int axis = 0; axis != 4; ++axis) {
                unsigned int interpolated = MEDIUS_MOTION_INTERPOLATED_AXES[axis];
                unsigned int pending = MEDIUS_MOTION_PENDING_AXES[axis];
                unsigned int combined = motion_pending_clamp((long long)(int)interpolated + (int)pending);
                MEDIUS_MOTION_INTERPOLATED_AXES[axis] = 0;
                MEDIUS_MOTION_PENDING_AXES[axis] = combined;
            }
            for (unsigned int word = 0; word != 4; ++word) MEDIUS_MOTION_INTERPOLATION_CLOCK_WORDS[word] = 0;
        }
        vPortExitCritical(&MEDIUS_MOTION_PENDING_LOCK);
        if ((sample.flags & 6U) != 0) {
            unsigned int command_x = 0,command_y = 0,input_x = 0,input_y = 0;
            medius_motion_cancel_read(&command_x,&command_y,&input_x,&input_y);
            (void)xPortEnterCriticalTimeout(&MEDIUS_MOTION_PENDING_LOCK,-1);
            unsigned int x = MEDIUS_MOTION_PENDING_AXES[0];
            unsigned int y = MEDIUS_MOTION_PENDING_AXES[1];
            if ((sample.flags & 4U) == 0) {
                x = motion_pending_clamp((long long)(int)x + (int)command_x);
                y = motion_pending_clamp((long long)(int)y + (int)command_y);
            }
            unsigned int next_x = motion_pending_clamp((long long)(int)x + (int)input_x);
            MEDIUS_MOTION_PENDING_AXES[0] = next_x;
            MEDIUS_MOTION_PENDING_AXES[1] = motion_pending_clamp((long long)(int)y + (int)input_y);
            vPortExitCritical(&MEDIUS_MOTION_PENDING_LOCK);
        }
        unsigned int estimated_duration = 0;
        if (MEDIUS_MOTION_INTERVAL_HISTORY->total_samples > 15) {
            unsigned short mode = MEDIUS_MOTION_INTERVAL_HISTORY->modal_bin;
            if (mode <= 126) {
                unsigned int scale = MEDIUS_MOTION_INTERVAL_SCALE;
                unsigned int period = (unsigned int)mode * 250U;
                if (scale != 0 && period != 0) estimated_duration =
                    (unsigned int)((unsigned long long)period * scale / 100U);
            }
        }
        int renderer_accepted = 0;
        if ((sample.x | sample.y) != 0 &&
            ((sample.flags & 0x80U) != 0 || (sample.flags & 7U) == 0) &&
            MEDIUS_MOTION_WIRE_CONFIGURATION->program_selector != 0 && medius_motion_program_ready() != 0)
            renderer_accepted = medius_motion_submit_command(sample.x,sample.y,
                (unsigned int)now,(unsigned int)(now >> 32),
                (sample.flags & 0x80U) != 0 ? 0U : estimated_duration);
        (void)xPortEnterCriticalTimeout(&MEDIUS_MOTION_PENDING_LOCK,-1);
        unsigned int direct = sample.flags & 1U;
        if (!renderer_accepted && (sample.x | sample.y) != 0) {
            unsigned int modal_period = motion_samples_modal_period();
            unsigned int high = MEDIUS_MOTION_PREFERRED_DURATION_HALVES[1];
            unsigned int low = MEDIUS_MOTION_PREFERRED_DURATION_HALVES[0];
            unsigned int requested = low | (high << 16);
            if (requested == 0) {
                if (MEDIUS_MOTION_WIRE_CONFIGURATION->program_selector != 0 && medius_motion_program_ready() != 0)
                    requested = 1000;
                else {
                    high = MEDIUS_MOTION_FALLBACK_DURATION_HALVES[1];
                    low = MEDIUS_MOTION_FALLBACK_DURATION_HALVES[0];
                    requested = low | (high << 16);
                    if (requested == 0) requested = 1000;
                }
            }
            int eligible = modal_period != 0 && modal_period >= estimated_duration && estimated_duration != 0;
            unsigned int multiple = !direct && eligible ? motion_samples_unique_multiple(modal_period,requested) : 0;
            unsigned int count = 0;
            int queued = 0;
            if (!direct && multiple != 0 && (count = MEDIUS_MOTION_SEGMENTS->count) < 8) {
                unsigned long long until = now + estimated_duration;
                MEDIUS_MOTION_SEGMENTS->entries[count].xy = (unsigned short)sample.x |
                    ((unsigned int)(unsigned short)sample.y << 16);
                MEDIUS_MOTION_SEGMENTS->entries[count].until_us.high = (unsigned int)(until >> 32);
                MEDIUS_MOTION_SEGMENTS->entries[count].until_us.low = (unsigned int)until;
                MEDIUS_MOTION_SEGMENTS->count_and_multiple =
                    (unsigned char)(count + 1U) | (unsigned short)(multiple << 8);
                MEDIUS_MOTION_SEGMENTS->selected_duration_us = requested;
                queued = 1;
            }
            if (!queued) {
                volatile unsigned int *destination = direct ? MEDIUS_MOTION_PENDING_AXES : MEDIUS_MOTION_INTERPOLATED_AXES;
                unsigned int x = destination[0];
                unsigned int next_x = motion_pending_clamp((long long)(int)x + sample.x);
                unsigned int y = destination[1];
                destination[0] = next_x;
                destination[1] = motion_pending_clamp((long long)(int)y + sample.y);
                if (!direct && estimated_duration != 0 &&
                    (!eligible || motion_samples_unique_multiple(modal_period,requested) == 0)) {
                    unsigned int until_low = MEDIUS_MOTION_INTERPOLATION_TIMES->until_us.low;
                    unsigned int until_high = MEDIUS_MOTION_INTERPOLATION_TIMES->until_us.high;
                    if ((until_low | until_high) == 0) {
                        MEDIUS_MOTION_INTERPOLATION_TIMES->started_us.low = (unsigned int)now;
                        MEDIUS_MOTION_INTERPOLATION_TIMES->started_us.high = (unsigned int)(now >> 32);
                    }
                    unsigned long long until = now + estimated_duration;
                    MEDIUS_MOTION_INTERPOLATION_TIMES->until_us.high = (unsigned int)(until >> 32);
                    MEDIUS_MOTION_INTERPOLATION_TIMES->until_us.low = (unsigned int)until;
                }
            }
        }
        if ((sample.wheel | sample.pan) != 0) {
            volatile unsigned int *destination = direct ? MEDIUS_MOTION_PENDING_AXES : MEDIUS_MOTION_INTERPOLATED_AXES;
            unsigned int wheel = destination[2];
            unsigned int next_wheel = motion_pending_clamp((long long)(int)wheel + sample.wheel);
            unsigned int pan = destination[3];
            destination[2] = next_wheel;
            destination[3] = motion_pending_clamp((long long)(int)pan + sample.pan);
        }
        if (!direct) {
            unsigned int low = MEDIUS_MOTION_INTERPOLATION_REFERENCE_US->low;
            unsigned int high = MEDIUS_MOTION_INTERPOLATION_REFERENCE_US->high;
            if ((low | high) == 0) { low = (unsigned int)now; high = (unsigned int)(now >> 32); }
            MEDIUS_MOTION_INTERPOLATION_REFERENCE_US->low = low;
            MEDIUS_MOTION_INTERPOLATION_REFERENCE_US->high = high;
        }
        int raw_axes[4] = {sample.x,sample.y,sample.wheel,sample.pan};
        for (unsigned int axis = 0; axis != 4; ++axis) {
            if (raw_axes[axis] == 0) continue;
            ((volatile int *)MEDIUS_MOTION_RECENT_AXIS_STATE)[axis] = raw_axes[axis];
            MEDIUS_MOTION_AXIS_LAST_INPUT_TIMES[axis].low = (unsigned int)now;
            MEDIUS_MOTION_AXIS_LAST_INPUT_TIMES[axis].high = (unsigned int)(now >> 32);
        }
        int need_reference = MEDIUS_MOTION_INTERPOLATION_POLICY != 0;
        if (need_reference) {
            unsigned int x = MEDIUS_MOTION_INTERPOLATED_AXES[0];
            unsigned int y = MEDIUS_MOTION_INTERPOLATED_AXES[1];
            unsigned int wheel = MEDIUS_MOTION_INTERPOLATED_AXES[2];
            unsigned int pan = MEDIUS_MOTION_INTERPOLATED_AXES[3];
            need_reference = (x | y | wheel | pan) != 0 || MEDIUS_MOTION_SEGMENTS->count != 0;
        }
        if (!need_reference) {
            MEDIUS_MOTION_INTERPOLATION_REFERENCE_US->low = 0;
            MEDIUS_MOTION_INTERPOLATION_REFERENCE_US->high = 0;
        } else {
            unsigned int low = MEDIUS_MOTION_INTERPOLATION_REFERENCE_US->low;
            unsigned int high = MEDIUS_MOTION_INTERPOLATION_REFERENCE_US->high;
            if ((low | high) == 0) {
                MEDIUS_MOTION_INTERPOLATION_REFERENCE_US->low = (unsigned int)now;
                MEDIUS_MOTION_INTERPOLATION_REFERENCE_US->high = (unsigned int)(now >> 32);
            }
        }
        vPortExitCritical(&MEDIUS_MOTION_PENDING_LOCK);
        (void)xPortEnterCriticalTimeout(&MEDIUS_MOTION_PENDING_LOCK,-1);
        unsigned char queued = MEDIUS_MOTION_SEGMENTS->count;
        vPortExitCritical(&MEDIUS_MOTION_PENDING_LOCK);
        if (queued == 0) {
            unsigned long long flush_time = (unsigned long long)esp_timer_get_time();
            medius_motion_flush_report((unsigned int)flush_time,(unsigned int)(flush_time >> 32));
        }
        medius_motion_publish_status(0);
    }
}

/* Native entry: 0x403878e4. */
/* Original function-byte SHA-256:
 * 6cc85e37bed287c4ea789c3578b86e90c517ff94d8f150cd034c658cdf9caab9. */
/* Build four signed16 output axes at packet bytes16..23; return1 iff any
 * emitted axis is nonzero, otherwise0. Prefix16/tag/trailing byte are untouched.
 * output must be writable. now is supplied as two WORDs; no clock call here.
 *
 * Hold the pending-motion lock forever, ignoring enter status, and drain four
 * pending32 axes. When advance_interpolation==0 and configured policy!=0,
 * leave interpolation/segments unchanged; initialize a zero reference clock
 * only if interpolated X or Y is nonzero (wheel/pan alone do not initialize it).
 * Otherwise advance X/Y by signed elapsed/duration with nearest rounding away
 * from zero at halves, modulo64 products and a one-sided clamp to the original
 * axis. Nonpositive elapsed/duration emits no timed X/Y. An unset deadline or
 * nonpositive now emits all interpolated X/Y. Consume due queued segments;
 * once half selected_duration has elapsed, consume at least min(count,multiple),
 * and always retain at most multiple. Nonpositive now consumes the entire queue
 * without updating its pacing clock. Count/multiple and pointers are trusted.
 *
 * Add segment sums to emitted axes modulo32, saturate original+sum to
 * +/-0x40000000, and retain the difference. Consume wheel/pan immediately and
 * clear them. Clear both interpolation clocks when remaining X/Y are zero;
 * otherwise an existing deadline permits started_us to advance to newer now.
 * Clear the interpolation reference after advancement. Native split-word store
 * orders are retained, including HIGH-before-LOW clock updates in this builder.
 *
 * Quantize each drained/advanced axis to[-32768,32767]. Return overflow to the
 * CURRENT pending32 value with signed64 +/-0x40000000 saturation; an in-range
 * axis still clamps current pending. Write each output low BYTE then high BYTE,
 * then the pending WORD. No packet clear, external acknowledgement, rollback,
 * timeout, bounds validation or delivery guarantee is added.
 */
unsigned char medius_motion_build_report(unsigned int now_low,unsigned int now_high,
    int advance_interpolation,MediusMotionReport *output)
{
    (void)xPortEnterCriticalTimeout(&MEDIUS_MOTION_PENDING_LOCK,-1);
    unsigned int axes[4];
    for (unsigned int axis = 0; axis != 4; ++axis) {
        unsigned int pending = MEDIUS_MOTION_PENDING_AXES[axis];
        MEDIUS_MOTION_PENDING_AXES[axis] = 0;
        axes[axis] = pending;
    }
    if (advance_interpolation == 0 && MEDIUS_MOTION_INTERPOLATION_POLICY != 0) {
        unsigned int reference_low = MEDIUS_MOTION_INTERPOLATION_REFERENCE_US->low;
        unsigned int reference_high = MEDIUS_MOTION_INTERPOLATION_REFERENCE_US->high;
        if ((reference_low | reference_high) == 0) {
            unsigned int x = MEDIUS_MOTION_INTERPOLATED_AXES[0];
            unsigned int y = MEDIUS_MOTION_INTERPOLATED_AXES[1];
            if ((x | y) != 0) {
                MEDIUS_MOTION_INTERPOLATION_REFERENCE_US->high = now_high;
                MEDIUS_MOTION_INTERPOLATION_REFERENCE_US->low = now_low;
            }
        }
    } else {
        unsigned int until_high = MEDIUS_MOTION_INTERPOLATION_TIMES->until_us.high;
        unsigned int until_low = MEDIUS_MOTION_INTERPOLATION_TIMES->until_us.low;
        unsigned int original[2];
        original[0] = MEDIUS_MOTION_INTERPOLATED_AXES[0];
        original[1] = MEDIUS_MOTION_INTERPOLATED_AXES[1];
        unsigned int emitted[2] = {original[0],original[1]};
        unsigned int remaining[2];
        unsigned int queued;
        unsigned long long now = ((unsigned long long)now_high << 32) | now_low;
        unsigned long long until = ((unsigned long long)until_high << 32) | until_low;
        if (until != 0 && (long long)now > 0 && (original[0] | original[1]) != 0 &&
            (long long)now < (long long)until) {
            unsigned int started_low = MEDIUS_MOTION_INTERPOLATION_TIMES->started_us.low;
            unsigned int started_high = MEDIUS_MOTION_INTERPOLATION_TIMES->started_us.high;
            unsigned long long started = ((unsigned long long)started_high << 32) | started_low;
            unsigned long long elapsed = now - started;
            unsigned long long duration = until - started;
            int valid = (long long)elapsed > 0 && (long long)duration > 0;
            emitted[0] = valid && original[0] != 0 ?
                motion_report_interpolate(original[0],elapsed,duration) : 0;
            /* Native samples queue count after X division, before Y division. */
            queued = MEDIUS_MOTION_SEGMENTS->count;
            emitted[1] = valid && original[1] != 0 ?
                motion_report_interpolate(original[1],elapsed,duration) : 0;
        } else queued = MEDIUS_MOTION_SEGMENTS->count;
        remaining[0] = original[0] - emitted[0];
        remaining[1] = original[1] - emitted[1];
        if (queued != 0) motion_report_consume_segments(now_low,now_high,queued,original,emitted,remaining);
        axes[0] += emitted[0];
        axes[1] += emitted[1];
        unsigned int wheel = MEDIUS_MOTION_INTERPOLATED_AXES[2];
        unsigned int pan = MEDIUS_MOTION_INTERPOLATED_AXES[3];
        axes[2] += wheel;
        axes[3] += pan;
        MEDIUS_MOTION_INTERPOLATED_AXES[0] = remaining[0];
        MEDIUS_MOTION_INTERPOLATED_AXES[1] = remaining[1];
        MEDIUS_MOTION_INTERPOLATED_AXES[3] = 0;
        MEDIUS_MOTION_INTERPOLATED_AXES[2] = 0;
        if ((remaining[0] | remaining[1]) == 0) {
            MEDIUS_MOTION_INTERPOLATION_TIMES->until_us.low = 0;
            MEDIUS_MOTION_INTERPOLATION_TIMES->until_us.high = 0;
            MEDIUS_MOTION_INTERPOLATION_TIMES->started_us.low = 0;
            MEDIUS_MOTION_INTERPOLATION_TIMES->started_us.high = 0;
        } else if (until != 0) {
            unsigned int high = MEDIUS_MOTION_INTERPOLATION_TIMES->started_us.high;
            if ((int)high < (int)now_high ||
                (high == now_high && MEDIUS_MOTION_INTERPOLATION_TIMES->started_us.low < now_low)) {
                MEDIUS_MOTION_INTERPOLATION_TIMES->started_us.high = now_high;
                MEDIUS_MOTION_INTERPOLATION_TIMES->started_us.low = now_low;
            }
        }
        MEDIUS_MOTION_INTERPOLATION_REFERENCE_US->low = 0;
        MEDIUS_MOTION_INTERPOLATION_REFERENCE_US->high = 0;
    }
    unsigned char any_motion = 0;
    unsigned char *wire_axes = (unsigned char *)output->axes;
    for (unsigned int axis = 0; axis != 4; ++axis) {
        unsigned int pending = MEDIUS_MOTION_PENDING_AXES[axis];
        int value = (int)axes[axis];
        int quantized = value;
        long long excess = 0;
        if (value > 32767) { quantized = 32767; excess = value - 32767; }
        else if (value < -32768) { quantized = -32768; excess = value + 32768; }
        unsigned int next_pending = motion_pending_clamp((long long)(int)pending + excess);
        if (quantized != 0) any_motion = 1;
        wire_axes[2U * axis] = (unsigned char)quantized;
        wire_axes[2U * axis + 1U] = (unsigned char)((unsigned short)quantized >> 8);
        MEDIUS_MOTION_PENDING_AXES[axis] = next_pending;
    }
    vPortExitCritical(&MEDIUS_MOTION_PENDING_LOCK);
    return any_motion;
}

/* Native entry: 0x40388f68. */
/* Original function-byte SHA-256:
 * 326d50e5499453eaa939acbfba2b2be7b0e195a72c04d36bdb35feb107afb563. */
/* Attempt an opcode0x36 motion report only when signed modulo64
 * (now-last_emitted)>499us. now_low/high are the caller's timestamp, not a
 * fresh clock sample. Zero all26 packet bytes and snapshot configuration tag
 * into byte24, then build axes with advance_interpolation0. An all-zero report
 * returns without taking the TX mutex or advancing last_emitted.
 *
 * A NULL initial mutex, take result other than1, or UART-queue rejection rolls
 * back ONLY the four emitted signed16 axes into current pending axes, under
 * the motion lock with signed64 +/-0x40000000 saturation. Builder interpolation
 * state/segments are not rolled back. Take waits forever. After the send,
 * reload the current mutex and give it without a new NULL check; ignore status.
 * Accepted queueing stores now LOW then HIGH, with no delivery acknowledgement.
 * The HID metadata formatter also advances this shared clock before its outer
 * UART enqueue. The unlocked rate check is admission control, not a guaranteed
 * 500us deadline.
 */
void medius_motion_flush_report(unsigned int now_low,unsigned int now_high)
{
    unsigned int previous_low = MEDIUS_MOTION_REPORT_LAST_EMITTED_US->low;
    unsigned int previous_high = MEDIUS_MOTION_REPORT_LAST_EMITTED_US->high;
    unsigned long long now = ((unsigned long long)now_high << 32) | now_low;
    unsigned long long previous = ((unsigned long long)previous_high << 32) | previous_low;
    if ((long long)(now - previous) <= 499) return;
    MediusMotionReport packet;
    memset(&packet,0,26);
    packet.tag = MEDIUS_MOTION_WIRE_CONFIGURATION->tag;
    if (!medius_motion_build_report(now_low,now_high,0,&packet)) return;
    RtosQueue *mutex = MEDIUS_MOTION_REPORT_TX_MUTEX;
    if (mutex != NULL && xQueueSemaphoreTake(mutex,0xffffffffU) == 1) {
        int accepted = medius_link_send_with_scratch(MEDIUS_MOTION_REPORT_TX_SCRATCH,
            0x36,0,&packet,26);
        RtosQueue *current_mutex = MEDIUS_MOTION_REPORT_TX_MUTEX;
        (void)xQueueGenericSend(current_mutex,NULL,0,0);
        if (accepted != 0) {
            MEDIUS_MOTION_REPORT_LAST_EMITTED_US->low = now_low;
            MEDIUS_MOTION_REPORT_LAST_EMITTED_US->high = now_high;
            return;
        }
    }
    (void)xPortEnterCriticalTimeout(&MEDIUS_MOTION_PENDING_LOCK,-1);
    for (unsigned int axis = 0; axis != 4; ++axis) {
        short emitted = packet.axes[axis];
        unsigned int pending = MEDIUS_MOTION_PENDING_AXES[axis];
        MEDIUS_MOTION_PENDING_AXES[axis] = motion_pending_clamp((long long)(int)pending + emitted);
    }
    vPortExitCritical(&MEDIUS_MOTION_PENDING_LOCK);
}

/* Native entry: 0x40387580. */
/* Original function-byte SHA-256:
 * 3f967e99a1d4346c63f5ffc5ccb199533d5d7284d0ef9473074b5029617b858b. */
/* Guard one motion-output drain against reentrant/concurrent drains.
 * Enter the pending-motion lock forever, ignoring enter status, and sample
 * the active BYTE once. A nonzero sample only releases the lock and returns;
 * it performs NO flag store. Otherwise set active1, release the lock, call
 * medius_motion_drain_output outside the lock, reacquire forever, restore the
 * cached zero and release. There is no queue, wait-for-active-clear, retry,
 * status, cancellation or exception cleanup; actual draining is the callee.
 */
void medius_motion_drain_output_guarded(void)
{
    (void)xPortEnterCriticalTimeout(&MEDIUS_MOTION_PENDING_LOCK,-1);
    unsigned char active = MEDIUS_MOTION_DRAIN_ACTIVE;
    if (active == 0) {
        MEDIUS_MOTION_DRAIN_ACTIVE = 1;
        vPortExitCritical(&MEDIUS_MOTION_PENDING_LOCK);
        medius_motion_drain_output();
        (void)xPortEnterCriticalTimeout(&MEDIUS_MOTION_PENDING_LOCK,-1);
        MEDIUS_MOTION_DRAIN_ACTIVE = active;
    }
    vPortExitCritical(&MEDIUS_MOTION_PENDING_LOCK);
}

/* Native entry: 0x403875bc. */
/* Original function-byte SHA-256:
 * de210a098dea43cec3efc8b5f10dc37de93e201e0a170b68a79396fe30d4b08e. */
/* Advance the host's nominal1000us motion grid and rearm its one-shot
 * esp_timer. This is shared software-timer task work; requested deadlines do
 * not guarantee execution time and depend on dispatch and other callback work.
 * Sample now once for grid decisions/output timestamps. Under the motion lock,
 * configuration-ready AND endpoint!=0 admit the HID-activity deferral path.
 * Reconstruct the activity low32 timestamp in the current/previous clock epoch.
 * If it reaches grid_next-500us and differs from last handled activity, store
 * its LOW word, sample timer handle, then store HIGH. A NULL handle returns;
 * otherwise stop/rearm for original_now+500us with minimum requested20us and
 * return without advancing/draining/waking/flushing the grid.
 *
 * Otherwise snapshot USB frame base/period, lock and read current grid time.
 * An unset grid schedules now+1000us and one step. An overdue grid computes
 * signed(now-grid)/1000+1, caps signed-positive counts above4, and advances by
 * signed-low32(count)*1000; if still overdue, reset next to now+1000. Preserve
 * modulo64 arithmetic and the native low-WORD step count on extreme inputs.
 * Future grids perform no steps. A valid frame snapshot phase-corrects next:
 * signed remainder(next*1000-base_ns-phase_ns,period_ns), wrapped about signed
 * period/2, then correction=-phase/1000us limited to+/-20. No zero-period or
 * arithmetic-overflow guard is inserted. Store changed grid LOW then HIGH.
 *
 * Release the lock before timer/worker calls. For nonzero low-WORD step count,
 * rearm at next+50us, drain/wake once per step, flush using the ORIGINAL now,
 * and publish status0. The native do-loop runs once for a negative step count.
 * With no steps rearm at next+150us only. Timer handles are sampled afresh for
 * admission, stop and start; a later NULL is not checked. Rearm samples a fresh
 * clock and clamps the signed target-current delay to20us. All lock/timer
 * results are ignored; no busy wait, hardware timer or delivery guarantee.
 */
void medius_motion_grid_timer_cb(void)
{
    unsigned long long now = (unsigned long long)esp_timer_get_time();
    unsigned int now_low = (unsigned int)now;
    unsigned int now_high = (unsigned int)(now >> 32);
    (void)xPortEnterCriticalTimeout(&MEDIUS_MOTION_PENDING_LOCK,-1);
    int activity_enabled = MEDIUS_MOTION_CONFIGURATION_READY != 0 &&
        MEDIUS_MOTION_WIRE_CONFIGURATION->endpoint != 0;
    unsigned int sampled_next_low = 0,sampled_next_high = 0;
    if (activity_enabled) {
        sampled_next_low = MEDIUS_MOTION_GRID_NEXT_US->low;
        sampled_next_high = MEDIUS_MOTION_GRID_NEXT_US->high;
    }
    vPortExitCritical(&MEDIUS_MOTION_PENDING_LOCK);
    if (activity_enabled) {
        unsigned int activity_low = medius_hid_get_activity_time();
        if (activity_low != 0) {
            unsigned int activity_high = now_high - (now_low < activity_low);
            unsigned int handled_low = MEDIUS_MOTION_GRID_LAST_ACTIVITY_US->low;
            unsigned int handled_high = MEDIUS_MOTION_GRID_LAST_ACTIVITY_US->high;
            unsigned long long next = ((unsigned long long)sampled_next_high << 32) | sampled_next_low;
            unsigned long long activity = ((unsigned long long)activity_high << 32) | activity_low;
            if (next != 0 && (long long)activity >= (long long)(next - 500ULL) &&
                (handled_low != activity_low || handled_high != activity_high)) {
                MEDIUS_MOTION_GRID_LAST_ACTIVITY_US->low = activity_low;
                EspTimer *timer = MEDIUS_MOTION_GRID_TIMER;
                MEDIUS_MOTION_GRID_LAST_ACTIVITY_US->high = activity_high;
                if (timer != NULL) motion_grid_rearm_at(now + 500ULL);
                return;
            }
        }
    }
    long long frame_base_ns,frame_period_ns;
    int frame_valid = medius_host_get_frame_timing(&frame_base_ns,&frame_period_ns,NULL);
    (void)xPortEnterCriticalTimeout(&MEDIUS_MOTION_PENDING_LOCK,-1);
    unsigned int next_low = MEDIUS_MOTION_GRID_NEXT_US->low;
    unsigned int next_high = MEDIUS_MOTION_GRID_NEXT_US->high;
    unsigned long long next = ((unsigned long long)next_high << 32) | next_low;
    unsigned int steps = 0;
    if (next == 0) {
        next = now + 1000ULL;
        MEDIUS_MOTION_GRID_NEXT_US->low = (unsigned int)next;
        MEDIUS_MOTION_GRID_NEXT_US->high = (unsigned int)(next >> 32);
        steps = 1;
    } else if ((long long)next <= (long long)now) {
        long long quotient = medius_motion_signed_divide((long long)(now - next),1000);
        unsigned long long count = (unsigned long long)quotient + 1ULL;
        steps = (long long)count > 4 ? 4U : (unsigned int)count;
        next += (unsigned long long)((long long)(int)steps * 1000LL);
        if ((long long)next <= (long long)now) next = now + 1000ULL;
        MEDIUS_MOTION_GRID_NEXT_US->low = (unsigned int)next;
        MEDIUS_MOTION_GRID_NEXT_US->high = (unsigned int)(next >> 32);
    }
    if (frame_valid != 0) {
        unsigned int phase_low = MEDIUS_MOTION_GRID_PHASE_NS->low;
        unsigned int phase_high = MEDIUS_MOTION_GRID_PHASE_NS->high;
        unsigned long long phase_offset = ((unsigned long long)phase_high << 32) | phase_low;
        long long phase = medius_motion_signed_remainder(
            (long long)(next * 1000ULL - (unsigned long long)frame_base_ns - phase_offset),frame_period_ns);
        long long half = frame_period_ns / 2;
        if (phase < -half) phase = (long long)((unsigned long long)phase + (unsigned long long)frame_period_ns);
        else if (phase >= half) phase = (long long)((unsigned long long)phase - (unsigned long long)frame_period_ns);
        long long correction;
        if (phase < -20999) correction = 20;
        else if (phase > 20999) correction = -20;
        else correction = medius_motion_signed_divide(phase,-1000);
        next += (unsigned long long)correction;
        MEDIUS_MOTION_GRID_NEXT_US->low = (unsigned int)next;
        MEDIUS_MOTION_GRID_NEXT_US->high = (unsigned int)(next >> 32);
    }
    vPortExitCritical(&MEDIUS_MOTION_PENDING_LOCK);
    if (steps == 0) {
        if (MEDIUS_MOTION_GRID_TIMER != NULL) motion_grid_rearm_at(next + 150ULL);
        return;
    }
    if (MEDIUS_MOTION_GRID_TIMER != NULL) motion_grid_rearm_at(next + 50ULL);
    unsigned int completed = 0;
    do {
        ++completed;
        medius_motion_drain_output_guarded();
        medius_motion_wake_worker();
    } while ((int)completed < (int)steps);
    medius_motion_flush_report(now_low,now_high);
    medius_motion_publish_status(0);
}

/* Native entry: 0x40387f0c. */
/* Original function-byte SHA-256:
 * 882a074fbb29454064278270b97a21bae4a0fe324fa29a6c232ca973e263dcd1. */
/* Format26 bytes of host motion metadata for an admitted HID report.
 * endpoint narrows8, length16; source_us_low is the original report timestamp.
 * Under the motion lock snapshot readiness BYTE and all101 configuration bytes.
 * Readiness0, disabled/mismatched endpoint, nonmatching nonzero report ID, or
 * nonmatching nonzero configured report length returns0 without writing output.
 * Otherwise read four LSB-first signed fields using configured bit offsets,
 * widths and signed-axis bits. Invalid/unsigned/missing fields yield0 through
 * the extractor; their failures do not reject this report. report is borrowed,
 * metadata must provide26 writable bytes; no pointer/overlap checks are added.
 *
 * Sample time and lock again. A snapshot policy plus raw XY input clears the
 * interpolation reference; if its signed age exceeds policy*1000us, first reset
 * interpolation/time/segment/recent/context spans, retaining pending axes and
 * coefficient fractions. Independently sample live policy to exclude stale
 * interpolation/segments from context. Sum pending+interpolated and queued XY,
 * clamp to+/-INT_MAX, and cache nonzero axes/timestamps. A zero balance can use
 * its recent value only within the live filter window. Window0 supplies zero
 * context even for nonzero balance. Stores of cached recent/time values remain.
 * Normalize XY context to32767 scale with ceil(max_abs/32767), preserving a
 * nonzero component as+/-1; publish four context WORDs and live mapping mode.
 *
 * Mode1 projects XY along this context using dot/norm and the smaller signed
 * direction percentage. Only enabled bounds admit coupled adjustments; preserve
 * split quotient/remainder arithmetic and signed1/10000 fractions. Then scale
 * each nonzero XY by its sign percentage. Other modes and wheel/pan multiply
 * sign and same/opposite-context percentages. Zero factors produce a zero
 * candidate, identity factors/results skip bounds; changed candidates clamp
 * upper THEN lower and clear their sign fraction only if bounds alter them.
 * All products/fraction arithmetic retain native64/32 wrap and signed division.
 * Unlock before renderer calls. Bypass byte98 or low2 flags99, or unavailable
 * input program, select raw XY history; otherwise use transformed XY and submit
 * nonzero RAW XY to the input renderer. History is gated by snapshot selector81.
 * Accepted signed16 input requeues only transformed excess and zeros base XY;
 * wheel/pan remain. Acceptance sets metadata byte25 bit0.
 *
 * Reconstruct the report timestamp epoch from a fresh clock. Optionally update
 * USB frame phase, rebase grid at source+1000us when source>=next-999us, and
 * drain/wake when source>=next-500us; a zero grid initializes and drains.
 * All grid/phase stores are LOW then HIGH, and draining occurs outside the lock.
 * No frame-period-zero guard or atomic64 access is invented.
 *
 * Sample emission time, zero26 output bytes, copy snapshot tag to24 and four
 * signed32 transformed base axes to0..15. Builder supplies additional signed16
 * axes at16..23 and advances interpolation only for original nonzero raw XY.
 * Publish status0. Return the INITIAL readiness BYTE (not necessarily1) iff
 * input was accepted, any base axis changed, or any additional axis is nonzero;
 * also store emission time LOW/HIGH in that case. Otherwise return0 with no
 * emission-clock store, although metadata/state/status have been processed.
 * This clock advances before the caller's UART enqueue and is not a delivery
 * acknowledgement. No report-byte rewrite, local transport call or rollback.
 */
unsigned int medius_motion_prepare_hid_metadata(unsigned int endpoint,unsigned int source_us_low,
    const unsigned char *report,unsigned int length,unsigned char *metadata)
{
    MediusMotionWireConfiguration configuration;
    (void)xPortEnterCriticalTimeout(&MEDIUS_MOTION_PENDING_LOCK,-1);
    unsigned char ready = MEDIUS_MOTION_CONFIGURATION_READY;
    memcpy(&configuration,(const void *)MEDIUS_MOTION_WIRE_CONFIGURATION,101);
    vPortExitCritical(&MEDIUS_MOTION_PENDING_LOCK);
    endpoint &= 255U;
    length &= 65535U;
    if (ready == 0 || configuration.endpoint == 0 || configuration.endpoint != endpoint) return 0;
    if (configuration.report_id != 0 &&
        (length == 0 || report[0] != configuration.report_id)) return 0;
    if (configuration.report_length != 0 && configuration.report_length != length) return 0;
    int axes[4],original[4];
    for (unsigned int axis = 0; axis != 4; ++axis)
        axes[axis] = medius_hid_extract_signed_field(report,length,configuration.bit_offsets[axis],
            configuration.bit_widths[axis],(configuration.signed_axes >> axis) & 1U);
    memcpy(original,axes,16);
    int raw_xy = (original[0] | original[1]) != 0;
    unsigned long long now = (unsigned long long)esp_timer_get_time();
    (void)xPortEnterCriticalTimeout(&MEDIUS_MOTION_PENDING_LOCK,-1);
    motion_hid_expire_interpolation(configuration.interpolation_policy,raw_xy,now);
    int context[4];
    motion_hid_collect_context(now,context);
    unsigned char mode = MEDIUS_MOTION_MAPPING_MODE;
    MEDIUS_MOTION_TRANSFORM->context_axes[0] = context[0];
    MEDIUS_MOTION_TRANSFORM->context_axes[1] = context[1];
    int wheel_context = context[2] < -32767 ? -32767 : context[2] > 32767 ? 32767 : context[2];
    int pan_context = context[3] < -32767 ? -32767 : context[3] > 32767 ? 32767 : context[3];
    MEDIUS_MOTION_TRANSFORM->context_axes[2] = wheel_context;
    MEDIUS_MOTION_TRANSFORM->context_axes[3] = pan_context;
    MEDIUS_MOTION_TRANSFORM->mapping_mode = mode;
    if (mode == 1) motion_hid_project_xy(axes,context);
    axes[0] = motion_hid_scale_axis(axes[0],context[0],0,mode == 1);
    axes[1] = motion_hid_scale_axis(axes[1],context[1],1,mode == 1);
    axes[2] = motion_hid_scale_axis(axes[2],context[2],2,0);
    axes[3] = motion_hid_scale_axis(axes[3],context[3],3,0);
    vPortExitCritical(&MEDIUS_MOTION_PENDING_LOCK);
    unsigned int consumed = 0;
    int input_ready = medius_motion_input_program_ready();
    if (!input_ready || configuration.input_bypass != 0 ||
        (configuration.input_bypass_flags & 3U) != 0) {
        if (configuration.program_selector != 0)
            medius_motion_enqueue_input(source_us_low,motion_hid_short_clamp(original[0]),
                motion_hid_short_clamp(original[1]));
    } else {
        if (configuration.program_selector != 0)
            medius_motion_enqueue_input(source_us_low,motion_hid_short_clamp(axes[0]),
                motion_hid_short_clamp(axes[1]));
        if (raw_xy) {
            short x = motion_hid_short_clamp(axes[0]);
            short y = motion_hid_short_clamp(axes[1]);
            consumed = medius_motion_submit_input(x,y);
            if (consumed != 0) motion_hid_requeue_excess(axes,x,y);
        }
    }
    motion_hid_update_grid(source_us_low);
    unsigned long long emitted_us = (unsigned long long)esp_timer_get_time();
    MediusMotionReport *packet = (void *)metadata;
    memset(metadata,0,26);
    volatile unsigned char *wire_metadata = metadata;
    wire_metadata[24] = configuration.tag;
    if (consumed != 0) {
        unsigned char flags = wire_metadata[25];
        wire_metadata[25] = flags | 1U;
    }
    memcpy(packet->prefix,axes,16);
    (void)medius_motion_build_report((unsigned int)emitted_us,
        (unsigned int)(emitted_us >> 32),raw_xy,packet);
    int changed = consumed != 0;
    if (!changed) {
        const volatile unsigned char *bytes = metadata;
        for (unsigned int axis = 0; axis != 4; ++axis) {
            unsigned int byte1 = bytes[4U * axis + 1U];
            unsigned int byte0 = bytes[4U * axis];
            unsigned int byte2 = bytes[4U * axis + 2U];
            unsigned int byte3 = bytes[4U * axis + 3U];
            unsigned int base = byte0 | (byte1 << 8) | (byte2 << 16) | (byte3 << 24);
            if (base != (unsigned int)original[axis]) { changed = 1; break; }
            unsigned int high = bytes[17U + 2U * axis];
            unsigned int low = bytes[16U + 2U * axis];
            if ((short)(low | (high << 8)) != 0) { changed = 1; break; }
        }
    }
    medius_motion_publish_status(0);
    if (!changed) return 0;
    MEDIUS_MOTION_REPORT_LAST_EMITTED_US->low = (unsigned int)emitted_us;
    MEDIUS_MOTION_REPORT_LAST_EMITTED_US->high = (unsigned int)(emitted_us >> 32);
    return ready;
}
