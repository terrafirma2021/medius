/* Medius v3.4.7 host — app/motion_inference.c.
 */

#include "../include/types.h"

/* Source reconstruction utilities; not additional native firmware entries.
 * Fixed-point helpers preserve ties-to-even and low-WORD wrapping explicitly.
 * All tables/weights/workspaces are ordinary serialized RAM, not MMIO. */
typedef struct GruGateTerms {
    unsigned int input[3],recurrent[3];
} GruGateTerms;

static unsigned int gru_round_shift(long long value,unsigned int shift)
{
    int negative = value < 0;
    unsigned long long magnitude = negative ? 0ULL-(unsigned long long)value : (unsigned long long)value;
    unsigned long long whole = magnitude>>shift;
    unsigned long long fraction = magnitude&((1ULL<<shift)-1ULL);
    unsigned long long half = 1ULL<<(shift-1U);
    if (fraction > half || (fraction == half && (whole&1ULL))) ++whole;
    unsigned int word = (unsigned int)whole;
    return negative ? 0U-word : word;
}

static unsigned int gru_scale_dot(int dot,int scale)
{
    return gru_round_shift((long long)dot*scale,31);
}

static int gru_clamp_activation(unsigned int word)
{
    int value = (int)word;
    if (value > 131072) value = 131072;
    if (value < -131072) value = -131072;
    return value;
}

static unsigned int gru_sigmoid(const volatile unsigned short *table,unsigned int word)
{
    int value = gru_clamp_activation(word);
    unsigned int interval = (unsigned int)(value+131072)>>10;
    if (interval == 256U) return table[256];
    int lower = table[interval];
    int upper = table[interval+1U];
    int product = (upper-lower)*(int)((unsigned int)value&1023U);
    return (unsigned int)lower+gru_round_shift(product,10);
}

static int gru_tanh(const volatile short *table,unsigned int word)
{
    int value = gru_clamp_activation(word);
    unsigned int interval = (unsigned int)(value+131072)>>10;
    if (interval == 256U) return table[256];
    int lower = table[interval];
    int upper = table[interval+1U];
    int product = (upper-lower)*(int)((unsigned int)value&1023U);
    return (int)((unsigned int)lower+gru_round_shift(product,10));
}

static void gru_write_hidden_unit(volatile MediusMotionCoreState *core,unsigned int unit,
    const GruGateTerms *terms,const volatile unsigned short *sigmoid,const volatile short *tanh_table)
{
    unsigned int reset = gru_sigmoid(sigmoid,terms->input[0]+terms->recurrent[0]);
    unsigned int update = gru_sigmoid(sigmoid,terms->input[1]+terms->recurrent[1]);
    unsigned int gated_recurrent = gru_round_shift((long long)(int)reset*(int)terms->recurrent[2],15);
    int candidate = gru_tanh(tanh_table,terms->input[2]+gated_recurrent);
    short old_hidden = core->hidden_state[unit];
    /* The complement is a zero-extended unsigned WORD in the original
     * multiply. Preserve its wrap if caller-selected tables return >32768. */
    unsigned int complement = 32768U-update;
    long long blended = (long long)complement*candidate+(long long)old_hidden*(int)update;
    int next = (int)gru_round_shift(blended,15);
    if (next < -32767) next = -32767;
    else if (next > 32767) next = 32767;
    core->next_hidden_state[unit] = (short)next;
}

static int gru_input_dot(const volatile signed char weights[20],
    const volatile MediusMotionFeatureFrame *features)
{
    int sum = 0;
    for (unsigned int i = 0;i < 20U;++i) {
        int weight = weights[i];
        short input = features->values[i];
        sum += weight*(int)input;
    }
    return sum; /* 20 signed8*16 products fit signed32. */
}

static int gru_recurrent_dot(const volatile signed char weights[80],
    const volatile short hidden[80])
{
    int sum = 0;
    for (unsigned int i = 0;i < 80U;++i) {
        int weight = weights[i];
        short input = hidden[i];
        sum += weight*(int)input;
    }
    return sum; /* 80 signed8*16 products also fit signed32. */
}

/* Native entry: 0x4037840c. */
/* Original function-byte SHA-256:
 * 0f31a3a4d092fe2d5ffd294eb0b13060d9bb051e1d8133433c993164eb7b800b. */
/* Run one80-unit fixed-point GRU update from20 signed16 feature values and
 * the previous80 signedQ15 hidden values. No pointer/configuration/phase/
 * sample-count check occurs here. Caller supplies live decoded scales, biases,
 * weights and257-entry sigmoid/tanh tables, with serialized access to the
 * shared accelerated workspace. Load configuration/scales pointer, snapshot
 * the FULL acceleration WORD, then cache all6 signedQ31 scales before choosing
 * the path. Any nonzero flag selects acceleration; no MEMW or mutex is added.
 *
 * Accelerated path splits features20/hidden80 into high and biased-low bytes,
 * zeroing32/80-byte output blocks. Run32-lane input dots and80-lane recurrent
 * dots for240 rows each; second dot passes reconstruct full signed16 products
 * with old<<8 and per-row bias corrections. Fetch table/bias pointers after
 * those calls, scale all6 dot terms for each unit and add the6 model biases
 * modulo32. Scalar path reads serialized20-wide/80-wide weight rows directly,
 * rereading features/hidden per unit without an upfront input snapshot; it
 * preserves the per-gate input/recurrent dot sequence and uses the same scales.
 *
 * Signed64 products are rounded nearest/ties-even after31 fractional bits;
 * narrowing keeps the low32 bits before later signed clamps. Reset/update
 * preactivations are wrapping WORD sums clamped to[-131072,131072] (Q14+/-8).
 * Interpolate unsignedQ15 sigmoid entries using10 fractional bits; clamp the
 * candidate preactivation identically and interpolate signedQ15 tanh entries.
 * Tables are read lower then upper, with entry256 used directly at the top
 * endpoint. Interpolation and reset*candidate-recurrent use ties-even shifts.
 *
 * candidate=tanh(input_candidate + reset*recurrent_candidate/32768).
 * next=round_even(((32768-update)*candidate + update*old_hidden)/32768),
 * then clamp to[-32767,32767]. The native complement is UNSIGNED32; retain its
 * wrap/zero extension for abnormal table values, and low32 wrap after rounding.
 * Write80 next_hidden values separately, then memcpy exactly160 bytes over
 * hidden_state. Intermediate writes/scratch remain if a callee does not return;
 * no reset, allocation, status, rollback or original-build/timing guarantee.
 */
void medius_motion_core_update_features(MediusMotionCoreState *core,const MediusMotionFeatureFrame *features)
{
    volatile MediusMotionCoreState *state = core;
    const volatile MediusMotionDecodedConfiguration *configuration = state->configuration;
    const volatile MediusMotionGruScales *source_scales = configuration->gru_scales;
    unsigned int accelerated = MEDIUS_MOTION_GRU_ACCELERATED;
    MediusMotionGruScales scales;
    scales.input[0] = source_scales->input[0];
    scales.input[1] = source_scales->input[1];
    scales.input[2] = source_scales->input[2];
    scales.recurrent[0] = source_scales->recurrent[0];
    scales.recurrent[1] = source_scales->recurrent[1];
    scales.recurrent[2] = source_scales->recurrent[2];
    if (accelerated != 0) {
        volatile MediusMotionGruWorkspace *work = MEDIUS_MOTION_GRU_WORKSPACE;
        medius_motion_split_feature_bytes((const volatile unsigned short *)features,20,32,
            (volatile unsigned char *)&work->input_high,(volatile unsigned char *)&work->input_low);
        medius_motion_split_feature_bytes((const volatile unsigned short *)core->hidden_state,80,80,
            (volatile unsigned char *)&work->hidden_high,(volatile unsigned char *)&work->hidden_low);
        medius_motion_dot_s8_32(MEDIUS_MOTION_GRU_INPUT_WEIGHTS,&work->input_high,work->input_dot,240);
        medius_motion_accumulate_s8_32(MEDIUS_MOTION_GRU_INPUT_WEIGHTS,&work->input_low,
            work->input_dot,240,MEDIUS_MOTION_GRU_INPUT_CORRECTIONS);
        medius_motion_dot_s8_80(MEDIUS_MOTION_GRU_RECURRENT_WEIGHTS,&work->hidden_high,work->recurrent_dot,240);
        medius_motion_accumulate_s8_80(MEDIUS_MOTION_GRU_RECURRENT_WEIGHTS,&work->hidden_low,
            work->recurrent_dot,240,MEDIUS_MOTION_GRU_RECURRENT_CORRECTIONS);
        const volatile short *tanh_table = configuration->tanh_q15;
        const volatile unsigned short *sigmoid = configuration->sigmoid_q15;
        const volatile int *bias = configuration->gru_bias_words;
        for (unsigned int unit = 0;unit < 80U;++unit) {
            GruGateTerms terms;
            for (unsigned int gate = 0;gate < 3U;++gate) {
                unsigned int row = gate*80U+unit;
                int input_dot = (int)work->input_dot[row];
                unsigned int input_term = gru_scale_dot(input_dot,scales.input[gate]);
                int recurrent_dot = (int)work->recurrent_dot[row];
                unsigned int input_bias = (unsigned int)bias[row];
                terms.input[gate] = input_term+input_bias;
                unsigned int recurrent_term = gru_scale_dot(recurrent_dot,scales.recurrent[gate]);
                unsigned int recurrent_bias = (unsigned int)bias[240U+row];
                terms.recurrent[gate] = recurrent_term+recurrent_bias;
            }
            gru_write_hidden_unit(state,unit,&terms,sigmoid,tanh_table);
        }
    } else {
        const volatile short *tanh_table = configuration->tanh_q15;
        const volatile MediusMotionGruWeights *weights = configuration->gru_weights;
        const volatile unsigned short *sigmoid = configuration->sigmoid_q15;
        const volatile int *bias = configuration->gru_bias_words;
        const volatile MediusMotionFeatureFrame *input = features;
        for (unsigned int unit = 0;unit < 80U;++unit) {
            GruGateTerms terms;
            for (unsigned int gate = 0;gate < 3U;++gate) {
                unsigned int row = gate*80U+unit;
                int input_dot = gru_input_dot(weights->input[gate][unit],input);
                unsigned int input_term = gru_scale_dot(input_dot,scales.input[gate]);
                unsigned int input_bias = (unsigned int)bias[row];
                terms.input[gate] = input_term+input_bias;
                int recurrent_dot = gru_recurrent_dot(weights->recurrent[gate][unit],state->hidden_state);
                unsigned int recurrent_term = gru_scale_dot(recurrent_dot,scales.recurrent[gate]);
                unsigned int recurrent_bias = (unsigned int)bias[240U+row];
                terms.recurrent[gate] = recurrent_term+recurrent_bias;
            }
            gru_write_hidden_unit(state,unit,&terms,sigmoid,tanh_table);
        }
    }
    memcpy(core->hidden_state,core->next_hidden_state,160);
}
