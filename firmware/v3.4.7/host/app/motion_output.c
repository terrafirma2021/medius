/* Medius v3.4.7 host — app/motion_output.c.
 * Instruction-checked fixed-point recurrent motion rendering.
 */

#include "../include/types.h"

/* Source reconstruction utilities; not additional native firmware entries.
 * WORD arithmetic wraps explicitly. Signed fixed-point reductions round to
 * nearest, ties to even, before retaining the native low WORD.
 * Borrowed model tables and shared workspaces require serialized callers. */
extern unsigned long long motion_output_divide(unsigned long long numerator,
    unsigned long long denominator) __asm__("__udivdi3");
extern unsigned long long motion_output_remainder(unsigned long long numerator,
    unsigned long long denominator) __asm__("__umoddi3");

static unsigned long long motion_output_abs(long long value)
{
    return value < 0 ? 0ULL-(unsigned long long)value : (unsigned long long)value;
}

static unsigned int motion_output_round(long long value,unsigned int shift)
{
    unsigned long long magnitude=motion_output_abs(value);
    unsigned long long whole=magnitude>>shift;
    unsigned long long fraction=magnitude&((1ULL<<shift)-1ULL);
    unsigned long long half=1ULL<<(shift-1U);
    if (fraction>half || (fraction==half && (whole&1ULL))) ++whole;
    unsigned int word=(unsigned int)whole;
    return value<0 ? 0U-word : word;
}

static int motion_output_clamp(int value,int lower,int upper)
{
    if (value<lower) return lower;
    if (value>upper) return upper;
    return value;
}

static int motion_output_feature(long long projection,unsigned int shift)
{
    return motion_output_clamp((int)motion_output_round(projection,shift),-1024,1024);
}

static int motion_output_cosine(int x,int y,int previous_x,int previous_y,
    unsigned int magnitude,unsigned int previous_magnitude)
{
    long long first=(long long)x*previous_x;
    long long second=(long long)y*previous_y;
    unsigned long long sum=(unsigned long long)first+(unsigned long long)second;
    /* Two signed32 products cannot overflow negatively. Saturate the one
     * positive-overflow case rather than overflowing a C signed addition. */
    if (first>0 && second>0 && sum>0x7fffffffffffffffULL)
        sum=0x7fffffffffffffffULL;
    long long dot=(long long)sum;
    unsigned long long absolute_dot=motion_output_abs(dot);
    unsigned long long denominator=(unsigned long long)magnitude*previous_magnitude;
    unsigned int quotient=(unsigned int)motion_output_divide(absolute_dot,denominator);
    unsigned long long remainder=motion_output_remainder(absolute_dot,denominator);
    for (unsigned int bit=0;bit<15U;++bit) {
        quotient<<=1;
        unsigned long long complement=denominator-remainder;
        if (remainder>=complement) {
            remainder-=complement;
            quotient|=1U;
        } else remainder+=remainder;
    }
    unsigned long long complement=denominator-remainder;
    if (remainder>complement || (remainder==complement && (quotient&1U))) ++quotient;
    if (dot<0) quotient=0U-quotient;
    return motion_output_clamp((int)quotient,-32768,32768);
}

static unsigned int motion_output_sigmoid(const volatile unsigned short *table,int value)
{
    value=motion_output_clamp(value,-131072,131072);
    unsigned int interval=(unsigned int)(value+131072)>>10;
    if (interval==256U) return table[256];
    int lower=table[interval];
    int upper=table[interval+1U];
    int product=(upper-lower)*(int)((unsigned int)value&1023U);
    return (unsigned int)lower+motion_output_round(product,10);
}

static unsigned int motion_output_exp(const volatile unsigned int *table,int delta)
{
    if (delta>0) return table[0];
    if (delta < -262144) return table[256];
    unsigned int magnitude=0U-(unsigned int)delta;
    unsigned int interval=magnitude>>10;
    if (interval==256U) return table[256];
    unsigned int lower=table[interval];
    unsigned int upper=table[interval+1U];
    /* The native interpolation multiply retains only its signed low WORD. */
    int product=(int)((upper-lower)*(magnitude&1023U));
    return lower+motion_output_round(product,10);
}

static unsigned int motion_output_random(unsigned long long value)
{
    value^=value>>30;
    value*=0xbf58476d1ce4e5b9ULL;
    value^=value>>27;
    value*=0x94d049bb133111ebULL;
    unsigned int high=(unsigned int)(value>>32);
    high^=high>>31;
    return high>>9;
}

static int motion_output_dot(const volatile signed char weights[80],
    const volatile short hidden[80])
{
    int sum=0;
    for (unsigned int unit=0;unit<80U;++unit) {
        int weight=weights[unit];
        short input=hidden[unit];
        sum+=weight*(int)input;
    }
    return sum; /* Eighty signed8*16 products fit signed32. */
}

/* Native entry: 0x40379124. */
/* Original function-byte SHA-256:
 * d202e74450e9e75ce941a134c2e8ab8455b219d189ac4cfe99f1fcdab0d50b9c. */
/* Render one signed Q16 input vector through the 80-unit recurrent model.
 * core/output/configuration must be nonnull (-1), and core phase must be2
 * (-5). The configured model, LUTs and shared accelerator cache are borrowed;
 * no allocation, lock, timeout or table-length validation is supplied here.
 * lower/upper are optional signed32 X/Y limits, applied only when both exist.
 *
 * Add input to signed residuals in64 bits, normalize the input direction and
 * build20 signed16 features: speed/change/turn, directional projections,
 * activity history, log speed and five cached summary statistics. Update the
 * recurrent hidden state, evaluate a Q15 sigmoid gate, and derive a23-bit
 * random sample from the seed and render counter. Force sampling for large
 * residuals, suppress sufficiently small stationary input, otherwise compare
 * midpoint random probability against the gate using integer arithmetic.
 *
 * Sampling projects hidden state to121 logits on an11x11 grid. Normalize and
 * rescale six Chebyshev rings from the original ROM index tables, penalize
 * perpendicular displacement, convert relative logits to Q20 weights and
 * choose the first CDF crossing using a second deterministic random sample.
 * Scalar and accelerated paths are both retained. The acceleration WORD is
 * read twice; the projection path reuses the earlier split hidden buffers.
 * A flag change from scalar gate to accelerated projection uses stale buffers,
 * just as the native code does. There is no local synchronization repair.
 *
 * Round residual+input to integer output, suppress small per-axis reversals
 * BEFORE adding the sampled grid offset, then clamp to signed16 core limits
 * and optional signed32 bounds. Negative/reversed limits are not sanitized.
 * When sampling is skipped, force output zero and retain the entire residual.
 * Return-7 if Y, then X residual cannot fit signed32. Earlier direction,
 * feature/input, recurrent, logit/weight and random writes survive that error;
 * output/residual/history/counter and last gate/index are success-only writes.
 *
 * Success stores low16 output components, residuals computed with the full
 * signed32 candidates, activity/run/history and per-axis last nonzero output.
 * A corrupt history cursor is used before modulo60; counts are not validated.
 * Increment a freshly reloaded64-bit counter after output Y then X stores.
 * Index120 is recorded even when no grid was sampled. Static instruction and
 * ABI/layout review does not establish runtime model accuracy or concurrency.
 */
int medius_motion_core_render_impl(MediusMotionCoreState *core,
    int x_q16,int y_q16,const int lower[2],const int upper[2],MediusMotionDelta *output)
{
    if (!core || !output) return -1;
    volatile MediusMotionCoreState *state=core;
    const volatile MediusMotionDecodedConfiguration *configuration=state->configuration;
    if (!configuration) return -1;
    if (state->phase!=2U) return -5;

    int residual_x=(int)state->residual[0];
    int residual_y=(int)state->residual[1];
    long long total_x=(long long)residual_x+x_q16;
    long long total_y=(long long)residual_y+y_q16;
    volatile MediusMotionDirectionQ15 normalized;
    volatile unsigned int magnitude;
    medius_motion_normalize_vector_q15(x_q16,y_q16,&normalized,&magnitude);
    unsigned int current_magnitude=magnitude;
    unsigned int previous_magnitude=state->summary_vector_magnitude;
    long long speed_change=(long long)current_magnitude-previous_magnitude;
    if (speed_change>196608) speed_change=196608;
    else if (speed_change < -196608) speed_change=-196608;

    int direction_x,direction_y,turn=0;
    if (current_magnitude==0U) {
        direction_y=state->direction.y;
        direction_x=state->direction.x;
    } else {
        direction_y=normalized.y;
        direction_x=normalized.x;
        state->direction.x=(short)direction_x;
        state->direction.y=(short)direction_y;
        if (previous_magnitude!=0U) {
            int previous_x=state->summary_vector_q16[0];
            int previous_y=state->summary_vector_q16[1];
            int cosine=motion_output_cosine(x_q16,y_q16,previous_x,previous_y,
                current_magnitude,previous_magnitude);
            turn=(int)motion_output_round((long long)(32768-cosine)*256,15);
        }
    }
    int perpendicular_x=(short)(0U-(unsigned int)direction_y);
    int nonzero_y=state->previous_nonzero_output.y;
    int previous_x=state->previous_output.x;
    int previous_y=state->previous_output.y;
    int nonzero_x=state->previous_nonzero_output.x;
    long long forward=total_x*direction_x+total_y*direction_y;
    long long lateral=total_x*perpendicular_x+total_y*direction_x;
    long long previous_forward=(long long)previous_x*direction_x+(long long)previous_y*direction_y;
    long long previous_lateral=(long long)previous_x*perpendicular_x+(long long)previous_y*direction_x;
    long long nonzero_forward=(long long)nonzero_x*direction_x+(long long)nonzero_y*direction_y;
    long long nonzero_lateral=(long long)nonzero_x*perpendicular_x+(long long)nonzero_y*direction_x;
    unsigned int activity_count=state->summary_activity_count;
    unsigned int inactive_count=0;
    const volatile unsigned char *activity=(const volatile unsigned char *)state+0xc4U;
    for (unsigned int i=0;i<activity_count;++i)
        if (activity[i]==0U) ++inactive_count;

    volatile MediusMotionFeatureFrame *features=&state->latest_features;
    unsigned int quarter_speed=motion_output_round(current_magnitude,10);
    if (quarter_speed>32767U) quarter_speed=32767U;
    features->local.quarter_speed_q8=(short)quarter_speed;
    features->local.speed_change_q8=(short)motion_output_round(speed_change,8);
    features->local.turn_q8=(short)turn;
    features->local.direction_x_q8=(short)motion_output_round(direction_x,7);
    features->local.direction_y_q8=(short)motion_output_round(direction_y,7);
    features->local.forward_deviation_q8=(short)motion_output_feature(forward,23);
    features->local.lateral_deviation_q8=(short)motion_output_feature(lateral,23);
    features->local.quarter_previous_forward_q8=(short)motion_output_feature(previous_forward,9);
    unsigned int previous_lateral_half=(unsigned short)motion_output_feature(previous_lateral,9);
    unsigned int old_activity=state->previous_output_active;
    features->words[4]=previous_lateral_half|(old_activity<<24);
    unsigned int activity_run=state->output_activity_run;
    if (activity_run>64U) activity_run=64U;
    features->local.activity_run_q8=(short)(activity_run*4U);
    unsigned int inactive_fraction=256U;
    if (activity_count!=0U) {
        unsigned long long numerator=(unsigned long long)inactive_count<<8;
        inactive_fraction=(unsigned int)motion_output_divide(numerator,activity_count);
        unsigned long long remainder=motion_output_remainder(numerator,activity_count);
        unsigned long long complement=activity_count-remainder;
        if (remainder>complement || (remainder==complement && (inactive_fraction&1U)))
            ++inactive_fraction;
    }
    features->local.inactive_fraction_q8=(short)inactive_fraction;
    unsigned int biased_magnitude=current_magnitude+65536U;
    unsigned long long log_argument=((unsigned long long)(biased_magnitude<4096U)<<32)|biased_magnitude;
    log_argument<<=4;
    int log_speed=medius_motion_lookup_log_magnitude(configuration,0,
        (unsigned int)log_argument,(unsigned int)(log_argument>>32));
    features->local.log_speed_q8=(short)motion_output_round(log_speed,6);
    features->local.quarter_nonzero_forward_q8=(short)motion_output_feature(nonzero_forward,9);
    unsigned int nonzero_lateral_half=(unsigned short)motion_output_feature(nonzero_lateral,9);
    unsigned int statistic=(unsigned short)state->summary_statistics[0];
    features->words[7]=nonzero_lateral_half|(statistic<<16);
    unsigned int high_half=(unsigned short)state->summary_statistics[2];
    unsigned int low_half=(unsigned short)state->summary_statistics[1];
    features->words[8]=low_half|(high_half<<16);
    high_half=(unsigned short)state->summary_statistics[4];
    low_half=(unsigned short)state->summary_statistics[3];
    features->words[9]=low_half|(high_half<<16);
    state->summary_vector_q16[0]=x_q16;
    state->summary_vector_q16[1]=y_q16;
    state->summary_vector_magnitude=current_magnitude;
    medius_motion_core_update_features(core,(const MediusMotionFeatureFrame *)features);

    const volatile MediusMotionModelWeights *weights=configuration->model_weights;
    const volatile MediusMotionModelScales *scales;
    volatile MediusMotionRenderWorkspace *workspace=MEDIUS_MOTION_RENDER_WORKSPACE;
    volatile MediusMotionModelCache *cache=MEDIUS_MOTION_MODEL_CACHE;
    int gate_dot,gate_scale;
    if (MEDIUS_MOTION_GRU_ACCELERATED==0U) {
        scales=configuration->model_scales;
        gate_scale=scales->gate;
        gate_dot=motion_output_dot(weights->single_output,state->hidden_state);
    } else {
        medius_motion_split_feature_bytes((const volatile unsigned short *)state->hidden_state,
            80,80,(volatile unsigned char *)&workspace->hidden_high,
            (volatile unsigned char *)&workspace->hidden_low);
        volatile unsigned int accelerated_dot;
        medius_motion_dot_s8_80(&cache->single_output,&workspace->hidden_high,&accelerated_dot,1);
        medius_motion_accumulate_s8_80(&cache->single_output,&workspace->hidden_low,
            &accelerated_dot,1,&cache->single_correction);
        scales=configuration->model_scales;
        gate_scale=scales->gate;
        gate_dot=(int)accelerated_dot;
    }
    unsigned int gate_score=motion_output_round((long long)gate_dot*gate_scale,31);
    const volatile MediusMotionModelBiases *biases=configuration->model_biases;
    gate_score+=(unsigned int)biases->gate;
    gate_score+=(unsigned int)configuration->gate_offset_q14;
    unsigned int activation=motion_output_round((long long)(int)gate_score*configuration->gate_gain_q16,16);
    unsigned int gate=motion_output_sigmoid(configuration->sigmoid_q15,(int)activation);
    unsigned int steps_low=state->render_steps.low;
    unsigned int steps_high=state->render_steps.high;
    unsigned int seed_low=state->render_seed.low;
    unsigned int seed_high=state->render_seed.high;
    unsigned long long steps=((unsigned long long)steps_high<<32)|steps_low;
    unsigned long long seed=((unsigned long long)seed_high<<32)|seed_low;
    unsigned int gate_random=motion_output_random(seed+steps*0x3c6ef372fe94f82aULL+0x9e3779b97f4a7c15ULL);
    state->gate_random_u23=gate_random;

    unsigned long long absolute_x=motion_output_abs(total_x);
    unsigned long long absolute_y=motion_output_abs(total_y);
    unsigned int force_threshold=configuration->grid_force_threshold_q16;
    bool sample=absolute_x>=force_threshold || absolute_y>=force_threshold;
    if (!sample) {
        bool small_input=motion_output_abs(x_q16)<=configuration->small_input_threshold_q16;
        if (small_input)
            small_input=motion_output_abs(y_q16)<=configuration->small_input_threshold_q16;
        unsigned long long maximum=absolute_x>absolute_y ? absolute_x : absolute_y;
        if (!(small_input && maximum<configuration->minimum_residual_threshold_q16)) {
            unsigned long long midpoint=(unsigned long long)(2U*gate_random+1U)*32768U;
            unsigned long long gate_threshold=(unsigned long long)(long long)(int)gate<<24;
            sample=midpoint<gate_threshold;
        }
    }

    unsigned int selected=120U;
    if (sample) {
        if (MEDIUS_MOTION_GRU_ACCELERATED==0U) {
            for (unsigned int row=0;row<121U;++row) {
                int dot=motion_output_dot(weights->projection[row],state->hidden_state);
                int scale=scales->grid[row];
                unsigned int score=motion_output_round((long long)dot*scale,31);
                state->grid_logits_q14[row]=(int)(score+(unsigned int)biases->grid[row]);
            }
        } else {
            medius_motion_dot_s8_80(cache->projection,&workspace->hidden_high,workspace->projection_dot,121);
            medius_motion_accumulate_s8_80(cache->projection,&workspace->hidden_low,
                workspace->projection_dot,121,cache->projection_corrections);
            scales=configuration->model_scales;
            biases=configuration->model_biases;
            for (unsigned int row=0;row<121U;++row) {
                int scale=scales->grid[row];
                int dot=(int)workspace->projection_dot[row];
                unsigned int score=motion_output_round((long long)dot*scale,31);
                state->grid_logits_q14[row]=(int)(score+(unsigned int)biases->grid[row]);
            }
            /* Only this branch refreshes the second random sample's inputs. */
            seed_low=state->render_seed.low;
            seed_high=state->render_seed.high;
            steps_low=state->render_steps.low;
            steps_high=state->render_steps.high;
            seed=((unsigned long long)seed_high<<32)|seed_low;
            steps=((unsigned long long)steps_high<<32)|steps_low;
        }

        const volatile unsigned int *exp_table=configuration->cached_words_257;
        int center_gain=configuration->ring_center_gain_q16;
        const volatile unsigned char *ring_boundaries=(const volatile unsigned char *)0x3c045d90U;
        const volatile unsigned char *ring_indices=(const volatile unsigned char *)0x3c045d98U;
        for (unsigned int ring=0;ring<6U;++ring) {
            unsigned int first=ring_boundaries[ring];
            unsigned int end=ring_boundaries[ring+1U];
            int maximum=(int)0x80000000U;
            for (unsigned int member=first;member<end;++member) {
                unsigned int index=ring_indices[member];
                int score=state->grid_logits_q14[index];
                if (score>maximum) maximum=score;
            }
            unsigned long long sum=0;
            for (unsigned int member=first;member<end;++member) {
                unsigned int index=ring_indices[member];
                unsigned int delta=(unsigned int)state->grid_logits_q14[index]-(unsigned int)maximum;
                sum+=motion_output_exp(exp_table,(int)delta);
            }
            int log_sum=medius_motion_lookup_log_magnitude(configuration,0,
                (unsigned int)sum,(unsigned int)(sum>>32));
            unsigned int normalizer=(unsigned int)log_sum+(unsigned int)maximum;
            unsigned int center=motion_output_round((long long)(int)normalizer*center_gain,16);
            if (first<end) {
                int contrast=configuration->ring_contrast_q16;
                for (unsigned int member=first;member<end;++member) {
                    unsigned int index=ring_indices[member];
                    unsigned int difference=(unsigned int)state->grid_logits_q14[index]-normalizer;
                    unsigned int rescaled=motion_output_round((long long)(int)difference*contrast,16);
                    state->grid_logits_q14[index]=(int)(center+rescaled);
                }
            }
        }
        int perpendicular_dead_zone=configuration->perpendicular_dead_zone_q15;
        for (unsigned int index=0;index<121U;++index) {
            int grid_x=(int)(index/11U)-5;
            int grid_y=(int)(index%11U)-5;
            unsigned long long perpendicular=motion_output_abs((long long)grid_x*perpendicular_x+
                (long long)grid_y*direction_x);
            int excess=(int)((unsigned int)perpendicular-(unsigned int)perpendicular_dead_zone);
            if (excess>0) {
                int coefficient=configuration->perpendicular_penalty_q17;
                unsigned int penalty=motion_output_round((long long)coefficient*excess,17);
                state->grid_logits_q14[index]=(int)((unsigned int)state->grid_logits_q14[index]-penalty);
            }
        }
        int maximum=(int)0x80000000U;
        for (unsigned int index=0;index<121U;++index) {
            int score=state->grid_logits_q14[index];
            if (score>maximum) maximum=score;
        }
        unsigned long long weight_sum=0;
        for (unsigned int index=0;index<121U;++index) {
            unsigned int delta=(unsigned int)state->grid_logits_q14[index]-(unsigned int)maximum;
            unsigned int weight=motion_output_exp(exp_table,(int)delta);
            state->grid_weights_q20[index]=weight;
            weight_sum+=weight;
        }
        unsigned int grid_random=motion_output_random(seed+(steps+1ULL)*0x3c6ef372fe94f82aULL);
        state->grid_random_u23=grid_random;
        unsigned long long threshold=weight_sum*(2U*grid_random+1U);
        unsigned long long cumulative=0;
        for (unsigned int index=0;index<121U;++index) {
            cumulative+=state->grid_weights_q20[index];
            if ((cumulative<<24)>=threshold) {
                selected=index;
                break;
            }
        }
    }

    int candidate_x=(int)motion_output_round(total_x,16);
    int candidate_y=(int)motion_output_round(total_y,16);
    int last_x=state->previous_nonzero_axis.x;
    if (last_x!=0 && candidate_x!=0 && ((last_x<0)!=(candidate_x<0)) &&
        absolute_x<configuration->reversal_dead_zone_q16) candidate_x=0;
    int last_y=state->previous_nonzero_axis.y;
    if (last_y!=0 && candidate_y!=0 && ((last_y<0)!=(candidate_y<0)) &&
        absolute_y<configuration->reversal_dead_zone_q16) candidate_y=0;
    if (sample) {
        candidate_x=(int)((unsigned int)candidate_x+selected/11U-5U);
        candidate_y=(int)((unsigned int)candidate_y+selected%11U-5U);
    }
    int x_limit=(short)state->x_limit;
    candidate_x=motion_output_clamp(candidate_x,-x_limit,x_limit);
    int y_limit=(short)state->y_limit;
    candidate_y=motion_output_clamp(candidate_y,-y_limit,y_limit);
    if (lower && upper) {
        const volatile int *lower_bounds=lower,*upper_bounds=upper;
        int bound=lower_bounds[0];
        if (candidate_x<bound) candidate_x=bound;
        else {
            bound=upper_bounds[0];
            if (candidate_x>bound) candidate_x=bound;
        }
        bound=lower_bounds[1];
        if (candidate_y<bound) candidate_y=bound;
        else {
            bound=upper_bounds[1];
            if (candidate_y>bound) candidate_y=bound;
        }
    }
    long long next_residual_x=total_x,next_residual_y=total_y;
    if (sample) {
        next_residual_x-=(long long)candidate_x*65536;
        next_residual_y-=(long long)candidate_y*65536;
    } else candidate_x=candidate_y=0;
    if (next_residual_y < -2147483648LL || next_residual_y>2147483647LL) return -7;
    if (next_residual_x < -2147483648LL || next_residual_x>2147483647LL) return -7;

    short output_x=(short)candidate_x,output_y=(short)candidate_y;
    bool active=output_x!=0 || output_y!=0;
    unsigned int run=state->output_activity_run;
    state->residual[1]=(unsigned int)next_residual_y;
    state->residual[0]=(unsigned int)next_residual_x;
    if (run==0U || state->previous_output_active!=(unsigned int)active)
        state->output_activity_run=1;
    else if (run!=65535U) state->output_activity_run=(unsigned short)(run+1U);
    state->previous_output_active=(unsigned char)active;
    unsigned int packed=(unsigned short)output_x|((unsigned int)(unsigned short)output_y<<16);
    state->summary_parameters[0]=packed;
    if (active) {
        state->summary_parameters[1]=packed;
        if (output_x!=0) state->previous_nonzero_axis.x=output_x;
        if (output_y!=0) state->previous_nonzero_axis.y=output_y;
    }
    unsigned int cursor=state->summary_activity_cursor;
    volatile unsigned char *history=(volatile unsigned char *)state+0xc4U;
    history[cursor]=(unsigned char)active;
    state->summary_activity_cursor=(unsigned char)((cursor+1U)%60U);
    unsigned int count=state->summary_activity_count;
    if (count<60U) state->summary_activity_count=(unsigned char)(count+1U);
    steps_low=state->render_steps.low;
    steps_high=state->render_steps.high;
    unsigned int next_low=steps_low+1U;
    unsigned int next_high=steps_high+(next_low==0U);
    volatile MediusMotionDelta *destination=output;
    destination->y=output_y;
    destination->x=output_x;
    state->last_gate_q15=gate;
    state->last_grid_index=(unsigned short)selected;
    state->render_steps.low=next_low;
    state->render_steps.high=next_high;
    return 0;
}
