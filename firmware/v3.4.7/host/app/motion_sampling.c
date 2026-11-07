/* Medius v3.4.7 host — app/motion_sampling.c.
 */

#include "../include/types.h"

/* Source reconstruction utilities; not additional native firmware entries.
 * Explicit binary32 operations/conversions retain native rounding, NaN and
 * signed-zero behavior rather than Ghidra's invalid C float/integer casts. */
extern float sample_divide(float numerator,float denominator) __asm__("__divsf3");

static __inline__ __attribute__((always_inline)) float sample_add(float left,float right)
{float result;__asm__ volatile("add.s %0, %1, %2":"=f"(result):"f"(left),"f"(right));return result;}
static __inline__ __attribute__((always_inline)) float sample_subtract(float left,float right)
{float result;__asm__ volatile("sub.s %0, %1, %2":"=f"(result):"f"(left),"f"(right));return result;}
static __inline__ __attribute__((always_inline)) float sample_multiply(float left,float right)
{float result;__asm__ volatile("mul.s %0, %1, %2":"=f"(result):"f"(left),"f"(right));return result;}
static __inline__ __attribute__((always_inline)) float sample_negate(float value)
{float result;__asm__ volatile("neg.s %0, %1":"=f"(result):"f"(value));return result;}
static __inline__ __attribute__((always_inline)) float sample_float_signed(int value)
{float result;__asm__ volatile("float.s %0, %1, 0":"=f"(result):"a"(value));return result;}
static __inline__ __attribute__((always_inline)) float sample_float_unsigned(unsigned int value)
{float result;__asm__ volatile("ufloat.s %0, %1, 0":"=f"(result):"a"(value));return result;}

static __inline__ __attribute__((always_inline)) short sample_quantize_q8(float value)
{
    int rounded;
    __asm__ volatile("round.s %0, %1, 8":"=a"(rounded):"f"(value));
    float converted = sample_float_signed(rounded);
    if (converted < -32768.0f) return -32768;
    if (32767.0f < converted) return 32767;
    int narrowed;
    __asm__ volatile("trunc.s %0, %1, 0":"=a"(narrowed):"f"(converted));
    return (short)narrowed;
}

static float sample_clamp(float value,float lower,float upper)
{
    if (value < lower) return lower;
    if (upper < value) return upper;
    return value; /* Ordered comparisons leave NaN for native ROUND.S. */
}

/* Seven independent complex oscillators. Grouping each bin makes the recovered
 * DFT recurrence readable; each multiply/add operand order is native, including
 * the distinct bin0/1 forms. Caller owns serialized ordinary RAM state. */
static void sample_accumulate_spectrum(volatile MediusMotionProcessingState *state,float magnitude)
{
    for (unsigned int bin = 0;bin < 7U;++bin) {
        float phase_real = state->spectral_phase_real[bin];
        float rotation_real = state->rotation_real[bin];
        float phase_imaginary = state->spectral_phase_imaginary[bin];
        float rotation_imaginary = state->rotation_imaginary[bin];
        float next_real,next_imaginary,real_term,imaginary_term;
        if (bin < 2U) {
            next_real = sample_subtract(sample_multiply(rotation_real,phase_real),
                sample_multiply(rotation_imaginary,phase_imaginary));
            if (bin == 0) next_imaginary = sample_add(sample_multiply(rotation_real,phase_imaginary),
                sample_multiply(rotation_imaginary,phase_real));
            else next_imaginary = sample_add(sample_multiply(rotation_imaginary,phase_real),
                sample_multiply(rotation_real,phase_imaginary));
        } else {
            next_real = sample_subtract(sample_multiply(phase_real,rotation_real),
                sample_multiply(phase_imaginary,rotation_imaginary));
            next_imaginary = sample_add(sample_multiply(phase_real,rotation_imaginary),
                sample_multiply(phase_imaginary,rotation_real));
        }
        if (bin == 1) {
            real_term = sample_multiply(phase_real,magnitude);
            imaginary_term = sample_multiply(phase_imaginary,magnitude);
        } else {
            real_term = sample_multiply(magnitude,phase_real);
            imaginary_term = sample_multiply(magnitude,phase_imaginary);
        }
        float old_real = state->statistics.spectrum_real[bin];
        float old_imaginary = state->statistics.spectrum_imaginary[bin];
        if (bin < 2U) {
            state->statistics.spectrum_real[bin] = sample_add(real_term,old_real);
            state->statistics.spectrum_imaginary[bin] = sample_add(imaginary_term,old_imaginary);
        } else {
            state->statistics.spectrum_real[bin] = sample_add(old_real,real_term);
            state->statistics.spectrum_imaginary[bin] = sample_add(old_imaginary,imaginary_term);
        }
        state->spectral_phase_real[bin] = next_real;
        state->spectral_phase_imaginary[bin] = next_imaginary;
    }
}

/* Native entry: 0x4037d638. */
/* Original function-byte SHA-256:
 * cfbfd5ce5a56c9c2416c7b7da7fc868332a9ea617ba2cb1c76df02904b05055b. */
/* Append signed16 XY to a phase1 core's256-sample ring. NULL core or missing
 * configuration returns-1; any phase other than1 returns-5 without writes.
 * Read cursor16 then sample-count16. Use the FULL old cursor for X/Y HALFWORD
 * stores at core+0x102+4*cursor, and only afterward publish (cursor+1)&255.
 * Thus corrupt cursors are not made safe before writing. Increment sample
 * count only while <=255; larger values remain unchanged. Then read total
 * count LOW/HIGH, increment modulo64 and store LOW then HIGH. Return0.
 * No capacity failure, configuration dereference, overwrite prevention,
 * allocation, lock, MEMW or atomic64 update is supplied. Input narrowing occurs
 * before validation, as in the native sign-extension instructions.
 */
int medius_motion_core_append_sample(MediusMotionCoreState *core,short x,short y)
{
    if (core == NULL) return -1;
    volatile MediusMotionCoreState *state = core;
    if (state->configuration == NULL) return -1;
    if (state->phase != 1U) return -5;
    unsigned int cursor = state->sample_cursor;
    unsigned int samples = state->samples;
    volatile MediusMotionRawSample *slot = (volatile MediusMotionRawSample *)
        ((volatile unsigned char *)core + 0x102U + 4U*cursor);
    slot->x = x;
    slot->y = y;
    state->sample_cursor = (unsigned short)((cursor+1U)&255U);
    if (samples <= 255U) state->samples = (unsigned short)(samples+1U);
    unsigned int low = state->total_samples.low;
    unsigned int high = state->total_samples.high;
    ++low;
    high += low == 0;
    state->total_samples.low = low;
    state->total_samples.high = high;
    return 0;
}

/* Native entry: 0x4037737c. */
/* Original function-byte SHA-256:
 * 0eb9ef23c03341f00e10466cc423ed35839d96a65f5deeb998b3d2ced091f297. */
/* Extract15 signedQ8 local features (30 bytes) from one filtered XY and its
 * delayed raw sample. Caller supplies valid serialized window/input/output;
 * there are no NULL, sample-index, alias or finite-value checks. Euclidean
 * speed uses the existing sqrtf service. With nonzero sample_index, speed
 * change uses previous_speed and turn is 1-clamp(cosine,-1,1) when both speeds
 * exceed1e-9. An unusable current direction falls back to last_direction_vector;
 * that cache stores the unnormalized input, while local direction is normalized
 * via a second sqrt and two divisions. Ordered native comparisons/NaNs remain.
 *
 * Accumulate filtered positions, advance baseline by previous raw XY except
 * at index0, and project deviation, previous raw XY and previous nonzero XY
 * onto forward/lateral axes. Emit quarter-speed, speed-change clamped[-3,3],
 * turn, direction, deviations clamped[-4,4], quarter raw projections clamped
 *[-4,4], old activity BYTE shifted8, capped run/64, fraction of zero history,
 * log1p(speed), and quarter nonzero projections clamped[-4,4]. Quantization is
 * native ROUND.S scale8, FLOAT.S, saturation to signed16, then TRUNC.S; C casts
 * of exceptional floats would be incorrect. The log1pf implementation remains
 * a separate review. An empty activity history emits inactive fraction1.
 *
 * Tail reads cursor and run length before the last output store. Continue a
 * nonzero run only when the cached previous activity BYTE equals new0/1, then
 * increment modulo16. Store new activity, history[cursor], cursor modulo60,
 * and cached history_count+1 unless it was EXACTLY60. Corrupt counts/cursors
 * are not clamped before access. Store raw XY, nonzero/axis caches, then reload
 * filtered X/Y words and publish previous_speed between those final stores.
 * Output/state/input overlap retains the explicit read/write dependencies.
 */
void medius_motion_extract_sample_features(volatile MediusMotionFeatureWindow *window,
    unsigned int sample_index,int raw_x,int raw_y,const volatile MediusMotionFilterVector *filtered,
    volatile MediusMotionLocalFeatures *output)
{
    float x = filtered->x;
    float y = filtered->y;
    float x_squared = sample_multiply(x,x);
    float y_squared = sample_multiply(y,y);
    float speed = medius_math_sqrtf(sample_add(y_squared,x_squared));
    unsigned char active = (raw_x|raw_y) != 0;
    float speed_change = 0.0f;
    float turn = 0.0f;
    int use_previous_direction = 0;
    if (sample_index != 0) {
        float previous_speed = window->previous_speed;
        speed_change = sample_subtract(speed,previous_speed);
        if (1e-9f < previous_speed && 1e-9f < speed) {
            float previous_x = window->previous_filtered.x;
            float dot_x = sample_multiply(x,previous_x);
            float previous_y = window->previous_filtered.y;
            float dot_y = sample_multiply(y,previous_y);
            float denominator = sample_multiply(previous_speed,speed);
            float cosine = sample_divide(sample_add(dot_x,dot_y),denominator);
            if (cosine < -1.0f) turn = 2.0f;
            else {
                if (1.0f < cosine) cosine = 1.0f;
                turn = sample_subtract(1.0f,cosine);
            }
        } else if (!(1e-9f < speed)) use_previous_direction = 1;
    } else if (!(1e-9f < speed)) use_previous_direction = 1;
    if (use_previous_direction) {
        x = window->last_direction_vector.x;
        x_squared = sample_multiply(x,x);
        y = window->last_direction_vector.y;
    } else {
        window->last_direction_vector.x = x;
        y = filtered->y;
        window->last_direction_vector.y = y;
    }
    float direction_length = medius_math_sqrtf(sample_add(sample_multiply(y,y),x_squared));
    if (!(direction_length <= 1e-9f)) {
        x = sample_divide(x,direction_length);
        y = sample_divide(y,direction_length);
    }
    float input_x = filtered->x;
    float old_sum_x = window->sum.x;
    float baseline_x = window->baseline.x;
    float sum_x = sample_add(old_sum_x,input_x);
    float old_sum_y = window->sum.y;
    float previous_raw_x = window->previous_raw.x;
    float baseline_y = window->baseline.y;
    window->sum.x = sum_x;
    float input_y = filtered->y;
    float previous_raw_y = window->previous_raw.y;
    float sum_y = sample_add(old_sum_y,input_y);
    float negative_y = sample_negate(y);
    window->sum.y = sum_y;
    if (sample_index != 0) {
        baseline_x = sample_add(baseline_x,previous_raw_x);
        baseline_y = sample_add(baseline_y,previous_raw_y);
        window->baseline.x = baseline_x;
        window->baseline.y = baseline_y;
    }
    float deviation_x = sample_subtract(sum_x,baseline_x);
    float deviation_y = sample_subtract(sum_y,baseline_y);
    float previous_nonzero_x = window->previous_nonzero_raw.x;
    float previous_nonzero_y = window->previous_nonzero_raw.y;
    float raw_lateral_x = sample_multiply(negative_y,previous_raw_x);
    float forward_x = sample_multiply(deviation_x,x);
    float forward_y = sample_multiply(deviation_y,y);
    float raw_forward_x = sample_multiply(x,previous_raw_x);
    float lateral_y = sample_multiply(deviation_y,x);
    float nonzero_forward_x = sample_multiply(previous_nonzero_x,x);
    float nonzero_forward_y = sample_multiply(previous_nonzero_y,y);
    float lateral_x = sample_multiply(negative_y,deviation_x);
    float nonzero_lateral_x = sample_multiply(previous_nonzero_x,negative_y);
    float nonzero_lateral_y = sample_multiply(previous_nonzero_y,x);
    float raw_forward_y = sample_multiply(y,previous_raw_y);
    float lateral = sample_add(lateral_x,lateral_y);
    float nonzero_forward = sample_add(nonzero_forward_x,nonzero_forward_y);
    float raw_lateral_y = sample_multiply(x,previous_raw_y);
    unsigned int history_count = window->activity_count;
    float forward = sample_add(forward_x,forward_y);
    float nonzero_lateral = sample_add(nonzero_lateral_x,nonzero_lateral_y);
    float raw_forward = sample_add(raw_forward_x,raw_forward_y);
    float raw_lateral = sample_add(raw_lateral_x,raw_lateral_y);
    float inactive_fraction = 1.0f;
    if (history_count != 0) {
        unsigned int inactive = 0;
        const volatile unsigned char *history = (const volatile unsigned char *)window+0x3b;
        for (unsigned int i = 0;i < history_count;++i) inactive += history[i] == 0;
        inactive_fraction = sample_divide(sample_float_unsigned(inactive),sample_float_signed((int)history_count));
    }
    output->quarter_speed_q8 = sample_quantize_q8(sample_multiply(speed,0.25f));
    output->speed_change_q8 = sample_quantize_q8(sample_clamp(speed_change,-3.0f,3.0f));
    output->turn_q8 = sample_quantize_q8(turn);
    output->direction_x_q8 = sample_quantize_q8(x);
    output->direction_y_q8 = sample_quantize_q8(y);
    output->forward_deviation_q8 = sample_quantize_q8(sample_clamp(forward,-4.0f,4.0f));
    output->lateral_deviation_q8 = sample_quantize_q8(sample_clamp(lateral,-4.0f,4.0f));
    output->quarter_previous_forward_q8 = sample_quantize_q8(sample_clamp(sample_multiply(raw_forward,0.25f),-4.0f,4.0f));
    short previous_lateral = sample_quantize_q8(sample_clamp(sample_multiply(raw_lateral,0.25f),-4.0f,4.0f));
    unsigned char previous_activity = window->previous_activity;
    unsigned int run_length = window->activity_run_length;
    output->quarter_previous_lateral_q8 = previous_lateral;
    output->previous_activity_q8 = (short)((unsigned int)previous_activity<<8);
    float run = run_length <= 64U ? sample_multiply(sample_float_unsigned(run_length),0.015625f) : 1.0f;
    output->activity_run_q8 = sample_quantize_q8(run);
    output->inactive_fraction_q8 = sample_quantize_q8(inactive_fraction);
    output->log_speed_q8 = sample_quantize_q8(medius_math_log1pf(speed));
    output->quarter_nonzero_forward_q8 = sample_quantize_q8(sample_clamp(sample_multiply(nonzero_forward,0.25f),-4.0f,4.0f));
    short nonzero_lateral_q8 = sample_quantize_q8(sample_clamp(sample_multiply(nonzero_lateral,0.25f),-4.0f,4.0f));
    unsigned int cursor = window->activity_cursor;
    unsigned int current_run = window->activity_run_length;
    output->quarter_nonzero_lateral_q8 = nonzero_lateral_q8;
    unsigned int next_run = current_run != 0 && previous_activity == active ? current_run : 0;
    window->activity_run_length = (unsigned short)(next_run+1U);
    window->previous_activity = active;
    volatile unsigned char *history = (volatile unsigned char *)window+0x3b;
    history[cursor] = active;
    window->activity_cursor = (unsigned char)((cursor+1U)%60U);
    if (history_count != 60U) window->activity_count = (unsigned char)(history_count+1U);
    float raw_float_x = sample_float_signed(raw_x);
    float raw_float_y = sample_float_signed(raw_y);
    window->previous_raw.x = raw_float_x;
    window->previous_raw.y = raw_float_y;
    if (active) {
        window->previous_nonzero_raw.x = raw_float_x;
        window->previous_nonzero_raw.y = raw_float_y;
        if (raw_x != 0) window->last_nonzero_axis.x = (short)raw_x;
        if (raw_y != 0) window->last_nonzero_axis.y = (short)raw_y;
    }
    window->previous_filtered.x_bits = filtered->x_bits;
    unsigned int latest_y = filtered->y_bits;
    window->previous_speed = speed;
    window->previous_filtered.y_bits = latest_y;
}

/* Native entry: 0x403779a4. */
/* Original function-byte SHA-256:
 * aa4f4c9df7db3f7f37eb2dcd162d0bd14eadb3e2bd21b303f818cafc69eadb59. */
/* Admit one signed16 XY into the host's256-sample processing run. NULL outer
 * state/configuration returns-1; cached collected_samples>255 returns-5.
 * Append into the embedded core first and forward any failure unchanged.
 * All later failures retain that append and every statistics/filter/window
 * update. Outer collected_samples increments only after successful feature
 * submission and, on original index255, successful finalization. The final
 * increment reloads the current HALFWORD; there is no rollback on failure.
 *
 * Statistics use max(abs(X),abs(Y)), not Euclidean distance. Insert nonzero
 * magnitudes stably into the ascending list, update nonzero count/sum/squares/
 * peak, sign-change counts across nonzero values on both axes, squared speed
 * differences, seven complex DFT recurrences and an alternating magnitude sum.
 * Zero samples leave the sorted list and previous nonzero signs intact.
 * Recovered spectrum code groups independent bins; binary32 operand ordering
 * and per-operation rounding are explicit, with no FMA/reassociation.
 *
 * Cache five signedQ8 global features: nonzero fraction, log1p(mean magnitude),
 * log1p(peak), sign-change fraction and log1p(speed-delta-squares) times the
 * native binary32 0x3f31f145. Native ROUND.S/FLOAT.S/saturation/TRUNC.S are
 * retained. Log1pf and finalization bodies are separate native reviews.
 *
 * Feed filter0, clear only the30 local-feature bytes and extract local features
 * if it emits, using the raw sample at uint16(original_index-4). From index128
 * also feed filter1 and its second window with uint16(index-132); those local
 * outputs are discarded, while window state advances. From index196 publish
 * raw activity into the60-byte late window. Store cached global features in
 * native branch-specific order, submit the40-byte frame, and finalize only on
 * original index255. There is no clipping of corrupted history/list counts,
 * delay-index repair, pointer lifetime validation, lock or completion wait.
 */
int medius_motion_process_sample(MediusMotionProcessingState *state,short x,short y)
{
    if (state == NULL) return -1;
    volatile MediusMotionProcessingState *current = state;
    if (current->configuration == NULL) return -1;
    unsigned int sample_index = current->collected_samples;
    if (sample_index > 255U) return -5;
    int status = medius_motion_core_append_sample(&state->core,x,y);
    if (status != 0) return status;
    unsigned int absolute_x = x < 0 ? (unsigned int)(-(int)x) : (unsigned int)x;
    unsigned int absolute_y = y < 0 ? (unsigned int)(-(int)y) : (unsigned int)y;
    unsigned int maximum = absolute_x > absolute_y ? absolute_x : absolute_y;
    float unsigned_magnitude = sample_float_unsigned(maximum);
    unsigned int previous_samples = current->collected_samples;
    volatile MediusMotionSampleStatistics *statistics = &current->statistics;
    unsigned int nonzero_count = statistics->nonzero_count;
    float magnitude = sample_float_signed((int)maximum);
    if (maximum != 0) {
        volatile unsigned short *sorted = (volatile unsigned short *)
            ((volatile unsigned char *)state+0xb5cU);
        unsigned int insertion = nonzero_count;
        while (insertion != 0) {
            unsigned int preceding = sorted[insertion-1U];
            if (preceding <= maximum) break;
            sorted[insertion] = (unsigned short)preceding;
            --insertion;
        }
        float old_sum = statistics->magnitude_sum;
        float square = sample_multiply(magnitude,unsigned_magnitude);
        float old_squares = statistics->magnitude_squares;
        float sum = sample_add(old_sum,magnitude);
        float squares = sample_add(old_squares,square);
        sorted[insertion] = (unsigned short)maximum;
        ++nonzero_count;
        unsigned int peak = statistics->peak_magnitude;
        statistics->nonzero_count = nonzero_count;
        statistics->magnitude_sum = sum;
        statistics->magnitude_squares = squares;
        if (peak < maximum) statistics->peak_magnitude = (unsigned short)maximum;
    }
    unsigned char sign_x = (unsigned char)((x > 0)-(x < 0));
    if (sign_x != 0) {
        unsigned char previous_sign = statistics->previous_x_sign;
        if (previous_sign != 0) {
            unsigned int comparisons = statistics->sign_comparisons;
            statistics->sign_comparisons = comparisons+1U;
            if (previous_sign != sign_x) {
                unsigned int changes = statistics->sign_changes;
                statistics->sign_changes = changes+1U;
            }
        }
        statistics->previous_x_sign = sign_x;
    }
    unsigned char sign_y = (unsigned char)((y > 0)-(y < 0));
    if (sign_y != 0) {
        unsigned char previous_sign = statistics->previous_y_sign;
        if (previous_sign != 0) {
            unsigned int comparisons = statistics->sign_comparisons;
            statistics->sign_comparisons = comparisons+1U;
            if (previous_sign != sign_y) {
                unsigned int changes = statistics->sign_changes;
                statistics->sign_changes = changes+1U;
            }
        }
        statistics->previous_y_sign = sign_y;
    }
    if (previous_samples != 0) {
        unsigned int previous = statistics->previous_magnitude;
        float difference = sample_subtract(unsigned_magnitude,sample_float_signed((int)previous));
        float old_squares = statistics->speed_delta_squares;
        float square = sample_multiply(difference,difference);
        statistics->speed_delta_squares = sample_add(old_squares,square);
    }
    statistics->previous_magnitude = (unsigned short)maximum;
    sample_accumulate_spectrum(current,magnitude);
    float negative_magnitude = sample_negate(unsigned_magnitude);
    float alternating = current->alternating_magnitude_sum;
    current->alternating_magnitude_sum = sample_add(alternating,
        (previous_samples&1U) ? negative_magnitude : unsigned_magnitude);

    float nonzero_float = sample_float_unsigned(nonzero_count);
    float count_float = sample_float_signed((int)(previous_samples+1U));
    short nonzero_fraction = sample_quantize_q8(sample_divide(nonzero_float,count_float));
    float mean = 0.0f;
    if (nonzero_count != 0) mean = sample_divide(statistics->magnitude_sum,nonzero_float);
    short log_mean = sample_quantize_q8(medius_math_log1pf(mean));
    unsigned int peak = statistics->peak_magnitude;
    short log_peak = sample_quantize_q8(medius_math_log1pf(sample_float_unsigned(peak)));
    unsigned int comparisons = statistics->sign_comparisons;
    float sign_fraction = 0.0f;
    if (comparisons != 0) {
        unsigned int changes = statistics->sign_changes;
        float denominator = sample_float_unsigned(comparisons);
        float numerator = sample_float_unsigned(changes);
        sign_fraction = sample_divide(numerator,denominator);
    }
    short sign_changes = sample_quantize_q8(sign_fraction);
    float log_variation = medius_math_log1pf(statistics->speed_delta_squares);
    short variation = sample_quantize_q8(sample_multiply(log_variation,0x1.63e28ap-1f));
    float raw_float_x = sample_float_signed(x);
    float raw_float_y = sample_float_signed(y);
    MediusMotionFilterVector filtered;
    int emitted = medius_motion_filter_step(&current->filters[0],raw_float_x,raw_float_y,&filtered.x);
    memset(&state->features.local,0,30);
    if (emitted != 0) {
        unsigned int index = (unsigned short)(sample_index-4U);
        const volatile MediusMotionRawSample *past = (const volatile MediusMotionRawSample *)
            ((const volatile unsigned char *)state+0x10aU+4U*index);
        int delayed_y = past->y;
        int delayed_x = past->x;
        medius_motion_extract_sample_features(&current->feature_windows[0],index,
            delayed_x,delayed_y,&filtered,&current->features.local);
    }
    if (sample_index > 127U) {
        if (medius_motion_filter_step(&current->filters[1],raw_float_x,raw_float_y,&filtered.x) != 0) {
            unsigned int raw_index = (unsigned short)(sample_index-4U);
            const volatile MediusMotionRawSample *past = (const volatile MediusMotionRawSample *)
                ((const volatile unsigned char *)state+0x10aU+4U*raw_index);
            int delayed_y = past->y;
            int delayed_x = past->x;
            MediusMotionLocalFeatures discarded;
            medius_motion_extract_sample_features(&current->feature_windows[1],
                (unsigned short)(sample_index-132U),delayed_x,delayed_y,&filtered,&discarded);
        }
        if (sample_index > 195U) {
            current->late_activity[sample_index-196U] = (x|y) != 0;
            current->features.nonzero_fraction_q8 = nonzero_fraction;
            current->features.log_mean_speed_q8 = log_mean;
            current->features.log_peak_speed_q8 = log_peak;
            current->features.log_speed_variation_q8 = variation;
            current->features.sign_change_fraction_q8 = sign_changes;
            status = medius_motion_core_submit_features(&state->core,&state->features);
            if (status != 0) return status;
            if (sample_index == 255U) status = medius_motion_finalize_processing(state);
            if (status != 0) return status;
            unsigned int samples = current->collected_samples;
            current->collected_samples = (unsigned short)(samples+1U);
            return status;
        }
    }
    current->features.nonzero_fraction_q8 = nonzero_fraction;
    current->features.log_mean_speed_q8 = log_mean;
    current->features.log_speed_variation_q8 = variation;
    current->features.log_peak_speed_q8 = log_peak;
    current->features.sign_change_fraction_q8 = sign_changes;
    status = medius_motion_core_submit_features(&state->core,&state->features);
    if (status == 0) {
        unsigned int samples = current->collected_samples;
        current->collected_samples = (unsigned short)(samples+1U);
    }
    return status;
}
