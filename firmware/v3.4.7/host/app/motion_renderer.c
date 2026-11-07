/* Medius v3.4.7 host — app/motion_renderer.c.
 */

#include "../include/types.h"

/* Source reconstruction utilities for native42031130/403771bc. These block
 * helpers and task-local structures are not extra native firmware entries. */
typedef struct RenderPrivateState {
    unsigned long long q16_x,q16_y;
    unsigned int pending_x,pending_y;
    unsigned int emitted_x,emitted_y;
    unsigned int held_seen,burst;
} RenderPrivateState;

typedef struct RenderAxisSplit {
    unsigned int retained,accepted,overflow_adjustment;
} RenderAxisSplit;

static unsigned int render_balance_clamp(long long value)
{
    if (value < -0x20000000LL) return 0xe0000000U;
    if (value > 0x20000000LL) return 0x20000000U;
    return (unsigned int)value;
}

static short render_sample_clamp(int value)
{
    if (value < -32768) return -32768;
    if (value > 32767) return 32767;
    return (short)value;
}

/* Hardware conversions retain Xtensa FPU exceptional-value/status behavior;
 * substituting C casts for NaN/out-of-range floats would introduce undefined
 * behavior. Multiplication by65536 remains a separate binary32 operation. */
static int render_trunc_q16(float value)
{
    int result;
    float scaled = value * 65536.0f;
    __asm__ volatile("trunc.s %0, %1, 0" : "=a"(result) : "f"(scaled));
    return result;
}

static int render_round_q16(float value)
{
    int result;
    float scaled = value * 65536.0f;
    __asm__ volatile("round.s %0, %1, 0" : "=a"(result) : "f"(scaled));
    return result;
}

static long long render_round_q16_total(unsigned long long value)
{
    if ((long long)value < 0) {
        unsigned long long magnitude = 0ULL - value + 32768ULL;
        return (long long)(0ULL - (unsigned long long)((long long)magnitude >> 16));
    }
    return (long long)(value + 32768ULL) >> 16;
}

static unsigned int render_timed_amount(unsigned int value,unsigned long long elapsed,
    unsigned long long duration)
{
    unsigned long long product = elapsed * (unsigned long long)(long long)(int)value;
    unsigned long long half = duration >> 1;
    if ((long long)product < 0) product -= half;
    else product += half;
    long long quotient = medius_motion_signed_divide((long long)product,(long long)duration);
    long long bound = (int)value;
    if (bound > 0 ? quotient < bound : quotient > bound) return (unsigned int)quotient;
    return value;
}

/* Retain at most4096 units to bridge the difference from active balances.
 * Saturated-away accepted units become a command-balance correction. */
static RenderAxisSplit render_split_axis(unsigned int requested,long long residual)
{
    RenderAxisSplit split = {0,0,0};
    int value = (int)requested;
    if (value == 0) return split;
    long long retained;
    if (value > 0) {
        if (residual < 0) residual = 0;
        retained = 4096LL - residual;
        if (retained < 0) retained = 0;
        if ((long long)value < retained) { split.retained = requested; return split; }
    } else {
        if (residual > 0) residual = 0;
        retained = -4096LL - residual;
        if (retained > 0) retained = 0;
        if ((long long)value > retained) { split.retained = requested; return split; }
    }
    long long accepted = (long long)value - retained;
    split.retained = (unsigned int)retained;
    split.accepted = render_balance_clamp(accepted);
    split.overflow_adjustment = split.accepted - (unsigned int)accepted;
    return split;
}

static int render_cancel_opposed(unsigned int *input,unsigned int *command)
{
    int amount;
    if ((int)*input > 0 && (int)*command < 0) {
        int magnitude = (int)(0U - *command);
        amount = magnitude < (int)*input ? magnitude : (int)*input;
        *input -= (unsigned int)amount;
        *command += (unsigned int)amount;
        return 1;
    }
    if ((int)*input < 0 && (int)*command > 0) {
        int magnitude = (int)(0U - *input);
        amount = magnitude < (int)*command ? magnitude : (int)*command;
        *input += (unsigned int)amount;
        *command -= (unsigned int)amount;
        return 1;
    }
    return 0;
}

static unsigned int render_apply_axis(unsigned int input,unsigned int command,
    unsigned int overflow,volatile unsigned int *active_input,volatile unsigned int *active_command,
    volatile unsigned int *staged_input,volatile unsigned int *staged_command)
{
    command = render_balance_clamp((long long)(int)command + (int)overflow);
    (void)render_cancel_opposed(&input,&command);
    unsigned int new_input = *staged_input;
    input = render_balance_clamp((long long)(int)input + (int)new_input);
    *active_input = input;
    int canceled = render_cancel_opposed(&input,&command);
    unsigned int new_command = *staged_command;
    command = render_balance_clamp((long long)(int)command + (int)new_command);
    if (canceled) *active_input = input;
    *active_command = command;
    if (render_cancel_opposed(&input,&command)) {
        *active_input = input;
        *active_command = command;
    }
    return new_input + new_command;
}

static void render_clear_batcher_tail(void)
{
    MEDIUS_MOTION_BATCHER->sum_x = 0;
    MEDIUS_MOTION_BATCHER->sum_y = 0;
    MEDIUS_MOTION_BATCHER->started = 0;
    MEDIUS_MOTION_BATCHER->gap_samples = 0;
    MEDIUS_MOTION_BATCHER->pending.word = 0;
    MEDIUS_MOTION_BATCHER->pending_y = 0;
    MEDIUS_MOTION_BATCHER->pending_stamp_us = 0;
}

static void render_reset_batcher(void)
{
    MEDIUS_MOTION_BATCHER->callback = medius_motion_collect_sample;
    MEDIUS_MOTION_BATCHER->context = 0;
    MEDIUS_MOTION_BATCHER->deadline_us = 0;
    render_clear_batcher_tail();
}

static void render_reset_window(void)
{
    MEDIUS_MOTION_WINDOW->samples = 0;
    MEDIUS_MOTION_WINDOW->late_nonzero = 0;
}

static void render_discard_input_ring(void)
{
    memw(); unsigned int write = MEDIUS_MOTION_INPUT_WRITE;
    memw(); MEDIUS_MOTION_INPUT_READ = write;
}

static void render_publish_deferred(void)
{
    if (MEDIUS_MOTION_DEFERRED_READY == 0) return;
    memw(); unsigned char reset = MEDIUS_MOTION_ENGINE->reset_requested;
    if (reset != 0) return;
    short y = MEDIUS_MOTION_DEFERRED_Y;
    short x = MEDIUS_MOTION_DEFERRED_X;
    MEDIUS_MOTION_DEFERRED_READY = reset;
    if (medius_motion_process_sample(MEDIUS_MOTION_DEFERRED_STATE,x,y) == 0) {
        memcpy(MEDIUS_MOTION_PUBLISHED_STATE,MEDIUS_MOTION_DEFERRED_STATE,4672);
        memw(); MEDIUS_MOTION_PROGRAM_READY = 1;
    }
}

static void render_idle_wait(void)
{
    memw(); unsigned int read = MEDIUS_MOTION_INPUT_READ;
    memw(); unsigned int write = MEDIUS_MOTION_INPUT_WRITE;
    if (read != write || MEDIUS_MOTION_BATCHER->gap_samples != 0) vTaskDelay(1);
    else (void)ulTaskGenericNotifyTake(0,1,50);
}

static int render_start_processing(RenderPrivateState *run)
{
    memw(); if (MEDIUS_MOTION_ENGINE->reset_requested != 0) return 0;
    memw(); if (MEDIUS_MOTION_PROGRAM_READY == 0) return 0;
    memcpy(MOTION_RENDER_STATE,MEDIUS_MOTION_PUBLISHED_STATE,4672);
    medius_motion_filter_reset(MEDIUS_MOTION_RENDER_FILTER);
    memw(); unsigned char mode = MEDIUS_MOTION_ENGINE->program_mode;
    MEDIUS_MOTION_ENGINE->active_program_mode = mode;
    MEDIUS_MOTION_RENDER_FILTER_MODE_ONE = mode == 1;
    unsigned long long seed = (unsigned long long)esp_timer_get_time();
    memw(); unsigned int write = MEDIUS_MOTION_INPUT_WRITE;
    if (medius_motion_seed_processing(MOTION_RENDER_STATE,(unsigned int)(seed >> 32),
        (unsigned int)seed,write ^ (unsigned int)(seed >> 32)) != 0) return 0;
    (void)xPortEnterCriticalTimeout(&MEDIUS_MOTION_ENGINE_LOCK,-1);
    short y_limit = (short)MEDIUS_MOTION_AXIS_LIMITS->y;
    short x_limit = (short)MEDIUS_MOTION_AXIS_LIMITS->x;
    vPortExitCritical(&MEDIUS_MOTION_ENGINE_LOCK);
    if (medius_motion_processing_set_limits(MOTION_RENDER_STATE,x_limit,y_limit) != 0) return 0;
    memw(); MEDIUS_MOTION_ENGINE->busy = 1;
    unsigned long long started = (unsigned long long)esp_timer_get_time();
    MEDIUS_MOTION_ENGINE->last_work_us.low = (unsigned int)started;
    MEDIUS_MOTION_ENGINE->last_work_us.high = (unsigned int)(started >> 32);
    *run = (RenderPrivateState){0};
    return 1;
}

static void render_take_motion(unsigned long long now,unsigned int delivered[2],RenderPrivateState *run)
{
    volatile MediusMotionEngineState *engine = MEDIUS_MOTION_ENGINE;
    (void)xPortEnterCriticalTimeout(&MEDIUS_MOTION_ENGINE_LOCK,-1);
    unsigned int timed_x = engine->timed_x;
    unsigned int timed_y = engine->timed_y;
    unsigned int until_low = engine->timed_until_us.low;
    unsigned int until_high = engine->timed_until_us.high;
    unsigned int start_high = engine->timed_started_us.high;
    unsigned int start_low = engine->timed_started_us.low;
    memw(); unsigned int generation = engine->generation;
    vPortExitCritical(&MEDIUS_MOTION_ENGINE_LOCK);
    unsigned long long until = ((unsigned long long)until_high << 32) | until_low;
    if (until != 0 && (long long)now > 0 && (long long)now < (long long)until) {
        unsigned long long started = ((unsigned long long)start_high << 32) | start_low;
        unsigned long long elapsed = now - started;
        unsigned long long duration = until - started;
        if ((long long)elapsed <= 0 || (long long)duration <= 0) timed_x = timed_y = 0;
        else {
            if (timed_x != 0) timed_x = render_timed_amount(timed_x,elapsed,duration);
            if (timed_y != 0) timed_y = render_timed_amount(timed_y,elapsed,duration);
        }
    }
    (void)xPortEnterCriticalTimeout(&MEDIUS_MOTION_ENGINE_LOCK,-1);
    memw(); if (engine->generation != generation) timed_x = timed_y = 0;
    unsigned int remaining_x = engine->timed_x;
    unsigned int remaining_y = engine->timed_y;
    remaining_x -= timed_x;
    remaining_y -= timed_y;
    engine->timed_x = remaining_x;
    engine->timed_y = remaining_y;
    if ((remaining_x | remaining_y) == 0) {
        engine->timed_until_us.low = 0;
        engine->timed_until_us.high = 0;
        engine->timed_started_us.low = 0;
        engine->timed_started_us.high = 0;
    } else {
        unsigned int low = engine->timed_until_us.low;
        unsigned int high = engine->timed_until_us.high;
        if ((low | high) != 0) {
            unsigned int start = engine->timed_started_us.high;
            if ((int)start < (int)(now >> 32) ||
                (start == (unsigned int)(now >> 32) && engine->timed_started_us.low < (unsigned int)now)) {
                engine->timed_started_us.low = (unsigned int)now;
                engine->timed_started_us.high = (unsigned int)(now >> 32);
            }
        }
    }
    unsigned int input_x = engine->active.input_x;
    unsigned int requested_x = timed_x + engine->immediate_x;
    unsigned int command_x = engine->active.command_x;
    unsigned int requested_y = timed_y + engine->immediate_y;
    long long residual_x = (int)(input_x + command_x);
    residual_x -= (long long)(int)requested_x + (long long)(int)remaining_x;
    RenderAxisSplit x = render_split_axis(requested_x,residual_x);
    unsigned int input_y = engine->active.input_y;
    unsigned int command_y = engine->active.command_y;
    long long residual_y = (int)(input_y + command_y);
    residual_y -= (long long)(int)requested_y + (long long)(int)remaining_y;
    RenderAxisSplit y = render_split_axis(requested_y,residual_y);
    engine->immediate_x = x.accepted;
    engine->immediate_y = y.accepted;
    run->held_seen |= (x.retained | y.retained) != 0;
    unsigned int staged_x = render_apply_axis(input_x,command_x,x.overflow_adjustment,
        &engine->active.input_x,&engine->active.command_x,&engine->staged.input_x,&engine->staged.command_x);
    unsigned int staged_y = render_apply_axis(input_y,command_y,y.overflow_adjustment,
        &engine->active.input_y,&engine->active.command_y,&engine->staged.input_y,&engine->staged.command_y);
    delivered[0] = staged_x + x.retained;
    delivered[1] = staged_y + y.retained;
    engine->staged.input_x = 0;
    engine->staged.command_x = 0;
    engine->staged.input_y = 0;
    engine->staged.command_y = 0;
    vPortExitCritical(&MEDIUS_MOTION_ENGINE_LOCK);
    if ((delivered[0] | delivered[1]) != 0) {
        engine->last_work_us.low = (unsigned int)now;
        engine->last_work_us.high = (unsigned int)(now >> 32);
    }
}

static void render_publish_output(MediusMotionDelta output)
{
    (void)xPortEnterCriticalTimeout(&MEDIUS_MOTION_ENGINE_LOCK,-1);
    memw(); unsigned char cancel = MEDIUS_MOTION_ENGINE->cancel_requested;
    if (cancel != 0) { vPortExitCritical(&MEDIUS_MOTION_ENGINE_LOCK); return; }
    memw(); unsigned char reset = MEDIUS_MOTION_ENGINE->reset_requested;
    if (reset != 0) { vPortExitCritical(&MEDIUS_MOTION_ENGINE_LOCK); return; }
    memw(); unsigned int generation = MEDIUS_MOTION_ENGINE->generation;
    vPortExitCritical(&MEDIUS_MOTION_ENGINE_LOCK);
    if (MEDIUS_MOTION_OUTPUT_HANDLER == NULL) return;
    memw(); unsigned int write = MEDIUS_MOTION_OUTPUT_WRITE;
    MEDIUS_MOTION_OUTPUT_RECORDS[write].xy = output.xy;
    MEDIUS_MOTION_OUTPUT_RECORDS[write].generation = generation;
    memw();
    unsigned int next = (write + 1U) & 7U;
    memw(); MEDIUS_MOTION_OUTPUT_WRITE = next;
}

static void render_end_if_idle(unsigned long long now,const RenderPrivateState *run,
    unsigned int delivered_x,unsigned int delivered_y)
{
    memw(); unsigned int read = MEDIUS_MOTION_OUTPUT_READ;
    memw(); unsigned int write = MEDIUS_MOTION_OUTPUT_WRITE;
    if ((delivered_x | delivered_y) != 0) return;
    unsigned int last_high = MEDIUS_MOTION_ENGINE->last_work_us.high;
    unsigned int last_low = MEDIUS_MOTION_ENGINE->last_work_us.low;
    unsigned long long last = ((unsigned long long)last_high << 32) | last_low;
    long long elapsed = (long long)(now - last);
    if (read != write || elapsed <= 40000) return;
    volatile MediusMotionEngineState *engine = MEDIUS_MOTION_ENGINE;
    (void)xPortEnterCriticalTimeout(&MEDIUS_MOTION_ENGINE_LOCK,-1);
    unsigned int command_x = engine->active.command_x;
    unsigned int input_x = engine->active.input_x;
    unsigned int command_y = engine->active.command_y;
    unsigned int input_y = engine->active.input_y;
    unsigned int reason = 0;
    if (((input_x + command_x) | (input_y + command_y)) == 0) reason = 1;
    else if (elapsed > 200000) reason = run->held_seen + 1U;
    if (engine->immediate_x != 0 || engine->immediate_y != 0 ||
        engine->timed_x != 0 || engine->timed_y != 0 || reason == 0) {
        vPortExitCritical(&MEDIUS_MOTION_ENGINE_LOCK); return;
    }
    if (reason == 2) {
        unsigned int fresh_command_x = engine->active.command_x;
        unsigned int fresh_input_x = engine->active.input_x;
        engine->staged.command_x = fresh_command_x;
        unsigned int fresh_input_y = engine->active.input_y;
        unsigned int fresh_command_y = engine->active.command_y;
        engine->staged.input_x = fresh_input_x;
        engine->staged.input_y = fresh_input_y;
        engine->staged.command_y = fresh_command_y;
    }
    memw(); unsigned int generation = engine->generation;
    memw(); engine->generation = generation + 1U;
    engine->active.input_x = 0;
    engine->active.command_x = 0;
    engine->active.input_y = 0;
    engine->active.command_y = 0;
    memw(); engine->busy = 0;
    vPortExitCritical(&MEDIUS_MOTION_ENGINE_LOCK);
    (void)medius_motion_processing_reset(MEDIUS_MOTION_BUILD_STATE,MEDIUS_MOTION_CONFIG);
    MEDIUS_MOTION_BATCHER->context = 0;
    render_reset_window();
    MEDIUS_MOTION_BATCHER->deadline_us = 0;
    MEDIUS_MOTION_BATCHER->callback = medius_motion_collect_sample;
    render_clear_batcher_tail();
}

/* Native entry: 0x403771bc. */
/* Original function-byte SHA-256:
 * f0728844be37eefc34ad87591877f470026a4b3f8deb1a9daf0dd7887628c9d5. */
/* Process the input ring/batcher with caller-supplied callback and record
 * budgets. Full32-bit budgets wrap; callback_limit0 still permits one outer
 * iteration. Reset callback_count WORD before reading any work. Pending gaps
 * invoke callback(context,0,0) at least once, with modulo32 budget minus the
 * previous count snapshot; callback_limit is checked only after that pass.
 * Fresh gap count is decremented modulo16, deadline advances1000us, and a
 * completed gap restores pending sample/deadline, clearing only flags HALF.
 *
 * With no gaps, record_limit0 or equal fenced input cursors returns. Snapshot
 * record index and a separate fresh read cursor, read X/Y HALFWORDs, resample
 * gaps, fence/store NEXT cursor&255, then read record timestamp. Gaps that
 * appeared during those reads merge signed16 pending XY with saturation.
 * Otherwise first/early samples seed or add to the1ms bucket; expired buckets
 * call the current callback/context with saturated old sums. Reread deadline
 * after callback. Delta<=999 signed seeds the next sample immediately; larger
 * gaps schedule up to64 zeros and defer XY/stamp, marking count64 as capped.
 * Decrement record budget only for actual ring records, then sample callback
 * count and return if count>=callback_limit. No lock, callback NULL guard,
 * whole-ring snapshot, timer, physical1ms deadline or status result is added.
 */
void medius_motion_process_input_limited(unsigned int callback_limit,unsigned int record_limit)
{
    volatile MediusMotionInputBatcher *batcher = MEDIUS_MOTION_BATCHER;
    MEDIUS_MOTION_CALLBACK_COUNT = 0;
    unsigned int callbacks = 0;
    for (;;) {
        unsigned short gaps = batcher->gap_samples;
        if (gaps != 0) {
            unsigned int budget = callback_limit - callbacks;
            unsigned int emitted = 0;
            do {
                MediusMotionSampleHandler callback = batcher->callback;
                unsigned int context = batcher->context;
                callback(context,0,0);
                unsigned short remaining = (unsigned short)(batcher->gap_samples - 1U);
                unsigned int deadline = batcher->deadline_us;
                batcher->deadline_us = deadline + 1000U;
                batcher->gap_samples = remaining;
                ++emitted;
                if (remaining == 0) {
                    if (batcher->pending.present != 0) {
                        unsigned char capped = batcher->pending.capped;
                        unsigned int next = deadline + 2000U;
                        if (capped != 0) next = batcher->pending_stamp_us + 1000U;
                        short y = batcher->pending_y;
                        short x = batcher->pending.x;
                        batcher->sum_y = (unsigned int)(int)y;
                        batcher->deadline_us = next;
                        batcher->sum_x = (unsigned int)(int)x;
                        batcher->pending.flags = 0;
                    }
                    break;
                }
            } while (emitted != budget);
        } else {
            if (record_limit == 0) return;
            memw(); unsigned int read = MEDIUS_MOTION_INPUT_READ;
            memw(); unsigned int write = MEDIUS_MOTION_INPUT_WRITE;
            if (read == write) return;
            memw(); memw();
            unsigned int index = MEDIUS_MOTION_INPUT_READ;
            memw(); unsigned int fresh_read = MEDIUS_MOTION_INPUT_READ;
            volatile MediusMotionInputSample *sample = (volatile void *)(0x3fcb9928U + index * 8U);
            unsigned short raw_x = (unsigned short)sample->x;
            unsigned short raw_y = (unsigned short)sample->y;
            unsigned short observed_gaps = batcher->gap_samples;
            memw(); MEDIUS_MOTION_INPUT_READ = (fresh_read + 1U) & 255U;
            unsigned int stamp = sample->stamp;
            int x = (short)raw_x,y = (short)raw_y;
            if (observed_gaps != 0) {
                short pending_x = batcher->pending.x;
                short next_x = render_sample_clamp((int)pending_x + x);
                short pending_y = batcher->pending_y;
                batcher->pending.x = next_x;
                batcher->pending_y = render_sample_clamp((int)pending_y + y);
            } else if (batcher->started == 0) {
                batcher->started = 1;
                batcher->deadline_us = stamp + 1000U;
                batcher->sum_x = (unsigned int)x;
                batcher->sum_y = (unsigned int)y;
            } else {
                unsigned int deadline = batcher->deadline_us;
                unsigned int sum_x = batcher->sum_x;
                unsigned int sum_y = batcher->sum_y;
                if ((int)(stamp - deadline) < 0) {
                    batcher->sum_x = sum_x + (unsigned int)x;
                    batcher->sum_y = sum_y + (unsigned int)y;
                } else {
                    MediusMotionSampleHandler callback = batcher->callback;
                    unsigned int context = batcher->context;
                    callback(context,render_sample_clamp((int)sum_x),render_sample_clamp((int)sum_y));
                    unsigned int fresh_deadline = batcher->deadline_us;
                    unsigned int delta = stamp - fresh_deadline;
                    if ((int)delta <= 999) {
                        batcher->pending.x = (short)raw_x;
                        batcher->pending_y = (short)raw_y;
                        batcher->pending_stamp_us = stamp;
                        batcher->gap_samples = observed_gaps;
                        batcher->deadline_us = fresh_deadline + 1000U;
                        batcher->sum_x = (unsigned int)x;
                        batcher->sum_y = (unsigned int)y;
                        batcher->pending.flags = observed_gaps;
                    } else {
                        unsigned int count = observed_gaps;
                        unsigned int remainder = delta - 1000U;
                        do {
                            ++count;
                            if (remainder <= 999U) break;
                            remainder -= 1000U;
                        } while (count != 64U);
                        batcher->pending.x = (short)raw_x;
                        batcher->pending_y = (short)raw_y;
                        batcher->pending_stamp_us = stamp;
                        batcher->pending.present = 1;
                        batcher->pending.capped = count == 64U;
                        batcher->gap_samples = (unsigned short)count;
                    }
                }
            }
            --record_limit;
        }
        callbacks = MEDIUS_MOTION_CALLBACK_COUNT;
        if (callbacks >= callback_limit) return;
    }
}

/* Native entry: 0x4037ab90. */
/* Original function-byte SHA-256:
 * c9e3122a28208f9f139d41d4cb07d9aed7051f867254e9266c758d6bdf3548a1. */
/* Six-WORD forwarding boundary to native40379124. Pass the core pointer,
 * two signed INTEGER Q16 increments, borrowed lower/upper signed-WORD XY
 * bounds and output signed16 XY pair without inspection. Return the entire
 * status unchanged; no NULL guard, conversion, initialization, lock, extra
 * call or local success guarantee. The rendering algorithm is the callee.
 */
int medius_motion_core_render_step(MediusMotionCoreState *core,
    int x_q16,int y_q16,const int lower[2],const int upper[2],MediusMotionDelta *output)
{
    return medius_motion_core_render_impl(core,x_q16,y_q16,lower,upper,output);
}

/* Native entry: 0x40377fb4. */
/* Original function-byte SHA-256:
 * 29a739eabcd3ea5953f91400a07553634f34f6b67426574bffe880a2e158085d. */
/* Validate only the processing-state pointer. NULL returns full native-1
 * without dereferencing or calling the core. Otherwise pass state+8 (embedded
 * core), the two INTEGER Q16 increments, lower/upper signed-WORD XY bounds
 * and signed16 output pair unchanged to the core wrapper. Return its complete
 * status. No other validation, copying, mutation, float conversion or lock.
 * Bounds/output lifetimes and successful writes are delegated to that callee.
 */
int medius_motion_processing_render_step(MediusMotionProcessingState *state,
    int x_q16,int y_q16,const int lower[2],const int upper[2],MediusMotionDelta *output)
{
    if (state == NULL) return -1;
    return medius_motion_core_render_step(&state->core,x_q16,y_q16,lower,upper,output);
}

/* Native entry: 0x42031130. */
/* Original function-byte SHA-256:
 * 69fb9464408c0a4c9a9096791bd0ad74b3255fcb76ffcf7efdd0ef383e0d3835. */
/* Motion renderer task: ignored startup argument, no normal return. Creator
 * requests stack8192,priority6,core1. Register with the shared watchdog once,
 * then feed at every outer iteration. This task is separate from mgrid's
 * shared esp_timer callback. Tick waits and queue pressure affect cadence.
 *
 * Full reset clears busy/window, immediate/timed/active/staged balances and
 * timed clocks, clears program-ready, increments generation and discards input
 * ring data; then resets builder, batcher and filter. Cancel clears its request
 * and busy, discards input ring and resets builder/window/batcher, retaining
 * the balances, generation, program-ready and filter. These branches do not
 * themselves clear task-local Q16/pending totals. Starting a new run does.
 * Deferred samples publish a4672-byte state only on sample-processing status0.
 *
 * Disabled/idle paths process input and wait one tick when input/gaps remain,
 * otherwise notification index0/clear1/up to50 ticks. Idle-enabled admission
 * requires balances/staged work, a ready program and no reset. Drain semaphore
 * without waiting when no run can start. Active admission takes semaphore at
 * wait0; every32 successes yields one tick. Other statuses try a10-tick take
 * and reset burst count. Take results after that wait are ignored. Start copies
 * published state, resets filter, snapshots program mode, seeds with clock and
 * input-write index, applies signed16 limits and sets busy only on status0.
 *
 * An output ring whose NEXT write meets read skips work entirely. Otherwise
 * process input with callback budget1/record budget4, sample time, snapshot
 * timed motion/generation and interpolate signed-positive intervals. Preserve
 * nearest-away-at-half division, modulo64 products and one-sided axis clamp.
 * A changed generation discards only that sampled timed contribution. Commit
 * timed subtraction, clear/advance its clocks, split current immediate/timed
 * work around a4096-unit retained window, and cap accepted balances at+/-2^29.
 * Saturation corrections and staged input/command balances cancel only when
 * opposed; native intermediate WORD stores are retained. Deliver staged sums
 * plus retained work modulo32 and clear the four staged WORDs under the lock.
 *
 * Convert signed delivered XY to binary32. Mode2 bypasses the filter and uses
 * TRUNC.S(value*65536); other modes use filter output only on nonzero status,
 * then ROUND.S. Accumulate signed Q16 increments modulo64. Native Q16-total
 * rounding, signed emitted totals and pending totals determine lower/upper
 * bounds; direction of the CURRENT Q16 increment controls bound extension.
 * The processing-step API receives INTEGER Q16 increments/bounds, not floats.
 * On step status0 remove signed16 output from local pending totals and update
 * emitted totals before checking cancel/reset/handler. No local rollback.
 * Nonzero output is queued with generation if those flags permit and callback
 * exists; queue ownership is single producer and no fresh full check is added.
 *
 * With no delivered input, empty output ring and signed inactivity>40000us,
 * inspect balances. Zero summed active axes may end the run; nonzero sums need
 * >200000us. If retained work was seen, carry active balances into staged on
 * that longer timeout. Immediate/timed work prevents ending. Bump generation,
 * clear active/busy, reset builder/window/batcher outside lock. All timestamps
 * are separate native WORD accesses; lock/semaphore/filter/reset statuses are
 * ignored where native code ignores them. No physical timing, atomic64 state,
 * output acknowledgement, hardware timer or original-build equivalence claim.
 */
void medius_task_render(void *unused_argument)
{
    (void)unused_argument;
    medius_worker_watchdog_add();
    RenderPrivateState run = {0};
    volatile MediusMotionEngineState *engine = MEDIUS_MOTION_ENGINE;
    for (;;) {
        medius_worker_watchdog_feed();
        memw();
        if (engine->reset_requested != 0) {
            memw(); engine->busy = 0;
            render_reset_window();
            (void)xPortEnterCriticalTimeout(&MEDIUS_MOTION_ENGINE_LOCK,-1);
            engine->immediate_x = 0;
            engine->immediate_y = 0;
            memw(); engine->reset_requested = 0;
            engine->timed_x = 0;
            memw(); MEDIUS_MOTION_PROGRAM_READY = 0;
            engine->timed_y = 0;
            memw(); unsigned int generation = engine->generation;
            engine->active.input_x = 0;
            engine->active.command_x = 0;
            engine->active.input_y = 0;
            engine->active.command_y = 0;
            memw(); engine->generation = generation + 1U;
            engine->timed_until_us.low = 0;
            engine->timed_until_us.high = 0;
            engine->timed_started_us.low = 0;
            engine->timed_started_us.high = 0;
            engine->staged.input_x = 0;
            engine->staged.command_x = 0;
            engine->staged.input_y = 0;
            engine->staged.command_y = 0;
            vPortExitCritical(&MEDIUS_MOTION_ENGINE_LOCK);
            MEDIUS_MOTION_DEFERRED_READY = 0;
            render_discard_input_ring();
            (void)medius_motion_processing_reset(MEDIUS_MOTION_BUILD_STATE,MEDIUS_MOTION_CONFIG);
            render_reset_batcher();
            medius_motion_filter_reset(MEDIUS_MOTION_RENDER_FILTER);
        }
        memw();
        if (engine->cancel_requested != 0) {
            memw(); engine->cancel_requested = 0;
            memw(); engine->busy = 0;
            render_discard_input_ring();
            (void)medius_motion_processing_reset(MEDIUS_MOTION_BUILD_STATE,MEDIUS_MOTION_CONFIG);
            render_reset_window();
            render_reset_batcher();
        }
        memw();
        if (engine->enabled == 0) {
            render_publish_deferred();
            medius_motion_process_input();
            render_idle_wait();
            continue;
        }
        memw();
        if (engine->busy == 0) {
            medius_motion_process_input();
            render_publish_deferred();
            (void)xPortEnterCriticalTimeout(&MEDIUS_MOTION_ENGINE_LOCK,-1);
            unsigned int immediate_x = engine->immediate_x;
            unsigned int timed_x = engine->timed_x;
            unsigned int immediate_y = engine->immediate_y;
            unsigned int timed_y = engine->timed_y;
            unsigned int input_x = engine->staged.input_x;
            unsigned int command_x = engine->staged.command_x;
            unsigned int input_y = engine->staged.input_y;
            unsigned int command_y = engine->staged.command_y;
            unsigned int work = immediate_x | timed_x | immediate_y | timed_y |
                (input_x + command_x) | (input_y + command_y);
            vPortExitCritical(&MEDIUS_MOTION_ENGINE_LOCK);
            int blocked = work == 0;
            if (!blocked) { memw(); blocked = MEDIUS_MOTION_PROGRAM_READY == 0; }
            if (!blocked) { memw(); blocked = engine->reset_requested != 0; }
            if (blocked) {
                while (xQueueSemaphoreTake(engine->wake_semaphore,0) == 1) { }
                render_idle_wait();
                continue;
            }
        }
        if (xQueueSemaphoreTake(engine->wake_semaphore,0) == 1) {
            ++run.burst;
            if (run.burst > 31U) { vTaskDelay(1); run.burst = 0; }
        } else {
            (void)xQueueSemaphoreTake(engine->wake_semaphore,10);
            run.burst = 0;
        }
        memw();
        if (engine->busy == 0 && !render_start_processing(&run)) {
            medius_motion_process_input();
            continue;
        }
        memw(); unsigned int write = MEDIUS_MOTION_OUTPUT_WRITE;
        memw(); unsigned int read = MEDIUS_MOTION_OUTPUT_READ;
        if (((write + 1U) & 7U) == read) continue;
        medius_motion_process_input_limited(1,4);
        unsigned long long now = (unsigned long long)esp_timer_get_time();
        unsigned int delivered[2];
        render_take_motion(now,delivered,&run);
        run.pending_x += delivered[0];
        run.pending_y += delivered[1];
        float input_x = (float)(int)delivered[0];
        float input_y = (float)(int)delivered[1];
        int increment_x = 0,increment_y = 0;
        if (engine->active_program_mode == 2) {
            increment_y = render_trunc_q16(input_y);
            increment_x = render_trunc_q16(input_x);
        } else {
            float filtered[2];
            if (medius_motion_filter_step(MEDIUS_MOTION_RENDER_FILTER,input_x,input_y,filtered) != 0) {
                increment_x = render_round_q16(filtered[0]);
                increment_y = render_round_q16(filtered[1]);
            }
        }
        run.q16_x += (unsigned long long)(long long)increment_x;
        run.q16_y += (unsigned long long)(long long)increment_y;
        int lower[2] = {(int)run.pending_x < 0 ? (int)run.pending_x : 0,
                        (int)run.pending_y < 0 ? (int)run.pending_y : 0};
        int upper[2] = {(int)run.pending_x > 0 ? (int)run.pending_x : 0,
                        (int)run.pending_y > 0 ? (int)run.pending_y : 0};
        long long wanted_x = (long long)((unsigned long long)render_round_q16_total(run.q16_x) -
            (unsigned long long)(long long)(int)run.emitted_x);
        long long wanted_y = (long long)((unsigned long long)render_round_q16_total(run.q16_y) -
            (unsigned long long)(long long)(int)run.emitted_y);
        if (increment_x > 0 && wanted_x > upper[0]) upper[0] = (int)wanted_x;
        else if (increment_x < 0 && wanted_x < lower[0]) lower[0] = (int)wanted_x;
        if (increment_y > 0 && wanted_y > upper[1]) upper[1] = (int)wanted_y;
        else if (increment_y < 0 && wanted_y < lower[1]) lower[1] = (int)wanted_y;
        MediusMotionDelta output;
        if (medius_motion_processing_render_step(MOTION_RENDER_STATE,increment_x,increment_y,
            lower,upper,&output) == 0) {
            run.pending_x -= (unsigned int)(int)output.x;
            run.emitted_x += (unsigned int)(int)output.x;
            run.pending_y -= (unsigned int)(int)output.y;
            run.emitted_y += (unsigned int)(int)output.y;
            if ((output.x | output.y) != 0) render_publish_output(output);
        }
        render_end_if_idle(now,&run,delivered[0],delivered[1]);
    }
}
