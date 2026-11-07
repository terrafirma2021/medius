/* Medius v3.4.7 host — app/motion_finalize.c.
 */

#include "../include/types.h"

/* Source reconstruction utilities; not additional native firmware entries.
 * Keep binary32 instruction rounding and multiply-add reduction grouping.
 * Native conversions also define exceptional/overflow cases that C casts do not.
 */
extern float finalizer_divide(float numerator,float denominator) __asm__("__divsf3");
extern long long finalizer_float_to_i64(float value) __asm__("__fixsfdi");

static __inline__ __attribute__((always_inline)) float finalizer_add(float a,float b)
{float r;__asm__ volatile("add.s %0,%1,%2":"=f"(r):"f"(a),"f"(b));return r;}
static __inline__ __attribute__((always_inline)) float finalizer_subtract(float a,float b)
{float r;__asm__ volatile("sub.s %0,%1,%2":"=f"(r):"f"(a),"f"(b));return r;}
static __inline__ __attribute__((always_inline)) float finalizer_multiply(float a,float b)
{float r;__asm__ volatile("mul.s %0,%1,%2":"=f"(r):"f"(a),"f"(b));return r;}
static __inline__ __attribute__((always_inline)) float finalizer_madd(float sum,float a,float b)
{__asm__ volatile("madd.s %0,%1,%2":"+f"(sum):"f"(a),"f"(b));return sum;}
static __inline__ __attribute__((always_inline)) float finalizer_signed_float(int value)
{float r;__asm__ volatile("float.s %0,%1,0":"=f"(r):"a"(value));return r;}
static __inline__ __attribute__((always_inline)) float finalizer_unsigned_float(unsigned int value)
{float r;__asm__ volatile("ufloat.s %0,%1,0":"=f"(r):"a"(value));return r;}
static __inline__ __attribute__((always_inline)) int finalizer_truncate(float value)
{int r;__asm__ volatile("trunc.s %0,%1,0":"=a"(r):"f"(value));return r;}
static __inline__ __attribute__((always_inline)) unsigned int finalizer_unsigned_truncate(float value)
{unsigned int r;__asm__ volatile("utrunc.s %0,%1,0":"=a"(r):"f"(value));return r;}
static __inline__ __attribute__((always_inline)) int finalizer_round(float value)
{int r;__asm__ volatile("round.s %0,%1,0":"=a"(r):"f"(value));return r;}

static short finalizer_quantize_q8(float value)
{
    int rounded;
    __asm__ volatile("round.s %0,%1,8":"=a"(rounded):"f"(value));
    float converted=finalizer_signed_float(rounded);
    if (converted < -32768.0f) return -32768;
    if (32767.0f < converted) return 32767;
    return (short)finalizer_truncate(converted);
}

static int finalizer_quantize_q16(float value)
{
    int rounded=finalizer_round(finalizer_multiply(value,65536.0f));
    long long wide=finalizer_float_to_i64(finalizer_signed_float(rounded));
    if (wide < -2147483648LL) return (-2147483647-1);
    if (2147483647LL < wide) return 2147483647;
    return (int)wide;
}

/* Tables are serialized little-endian bytes, not guaranteed aligned float
 * arrays. Native reads byte1,byte0,byte2,byte3 and copies the assembled WORD. */
static unsigned int finalizer_read_word(const volatile unsigned char *bytes)
{
    unsigned int byte1=bytes[1],byte0=bytes[0],byte2=bytes[2],byte3=bytes[3];
    return byte0|(byte1<<8)|(byte2<<16)|(byte3<<24);
}
static float finalizer_word_as_float(unsigned int bits)
{
    float value;
    memcpy(&value,&bits,4);
    return value;
}

static short finalizer_quantize_hidden(float value)
{
    if (value < -1.0f) return -32767;
    if (1.0f < value) value=1.0f;
    float rounded=medius_math_rintf(finalizer_multiply(value,32768.0f));
    if (rounded < -32767.0f) return -32767;
    if (32767.0f < rounded) rounded=32767.0f;
    return (short)finalizer_truncate(rounded);
}

/* Eight accumulators span interleaved columns. Preserve the native balanced
 * sums; a single linear dot product changes binary32 rounding. */
static float finalizer_hidden_unit(const volatile MediusMotionConfiguration *model,
    const float normalized[145],unsigned int unit)
{
    float scale=finalizer_word_as_float(finalizer_read_word(model->dense_hidden_scales+4*unit));
    const volatile signed char *weights=model->dense_hidden_weights+145*unit;
    float partial[8]={0.0f,0.0f,0.0f,0.0f,0.0f,0.0f,0.0f,0.0f};
    static const unsigned char lane_order[8]={0,4,1,5,2,6,3,7};
    for (unsigned int block=0;block<18;++block) {
        for (unsigned int position=0;position<8;++position) {
            unsigned int lane=lane_order[position],column=8*block+lane;
            float weight=finalizer_multiply(finalizer_signed_float(weights[column]),scale);
            partial[lane]=finalizer_madd(partial[lane],weight,normalized[column]);
        }
    }
    float pair04=finalizer_add(partial[0],partial[4]);
    float pair15=finalizer_add(partial[1],partial[5]);
    float pair26=finalizer_add(partial[2],partial[6]);
    float pair37=finalizer_add(partial[3],partial[7]);
    float sum=finalizer_add(finalizer_add(pair04,pair15),finalizer_add(pair26,pair37));
    float tail_weight=finalizer_multiply(finalizer_signed_float(weights[144]),scale);
    unsigned int bias_bits=finalizer_read_word(model->dense_hidden_biases+4*unit);
    sum=finalizer_madd(sum,tail_weight,normalized[144]);
    float bias=finalizer_word_as_float(bias_bits);
    return medius_math_tanhf(finalizer_add(bias,sum));
}

static float finalizer_output_unit(const volatile MediusMotionConfiguration *model,
    const float hidden[16],unsigned int unit,const volatile float *recurrent_input)
{
    float scale=finalizer_word_as_float(finalizer_read_word(model->dense_output_scales+4*unit));
    const volatile signed char *weights=model->dense_output_weights+16*unit;
    float partial[8];
    for (unsigned int lane=0;lane<8;++lane) {
        float weight=finalizer_multiply(finalizer_signed_float(weights[lane]),scale);
        partial[lane]=lane==7 ? finalizer_madd(0.0f,weight,hidden[lane]) :
            finalizer_madd(0.0f,hidden[lane],weight);
    }
    for (unsigned int lane=0;lane<8;++lane) {
        float weight=finalizer_multiply(finalizer_signed_float(weights[lane+8]),scale);
        partial[lane]=finalizer_madd(partial[lane],weight,hidden[lane+8]);
    }
    float pair04=finalizer_add(partial[0],partial[4]);
    float pair15=finalizer_add(partial[1],partial[5]);
    float pair26=finalizer_add(partial[2],partial[6]);
    float pair37=finalizer_add(partial[3],partial[7]);
    unsigned int bias_bits=finalizer_read_word(model->dense_output_biases+4*unit);
    float sum=finalizer_add(finalizer_add(pair15,pair04),finalizer_add(pair26,pair37));
    sum=finalizer_add(sum,*recurrent_input);
    float bias=finalizer_word_as_float(bias_bits);
    return finalizer_add(sum,bias);
}

/* Native entry: 0x4200c774. */
/* Original function-byte SHA-256:
 * 582f4279906efc7ad4cb847ebe456d3c77c14ee6bff3be96dcfc1e2bb7722885. */
/*
 * Finalize a 256-sample motion window and correct its 80-value recurrent state.
 *
 * state: initialized, serialized processing RAM with valid configuration/tables
 * and sampler counts. No NULL or local sample-count validation is performed.
 * Compute five global Q8 statistics, finish the second filter's four pending
 * vectors and emit four15-value local records from raw slots252..255 using
 * feature indices124..127. Build/install the summary through the core API.
 *
 * On success, compose 145 float inputs (80 Q15 recurrent,60 Q8 tail features,
 * five Q8 statistics), normalize with serialized half-float tables, and apply
 * a 145->16 tanh->80 residual correction with signed-byte weights and float
 * scales/biases. Retain eight-lane multiply-add grouping and native conversion
 * instructions. Finally overwrite80 core hidden HALFWORDs, bounded to +/-32767.
 *
 * Returns-5 if filter_finish does not return exactly4; otherwise forwards a
 * nonzero core-summary result. A NULL tail-header marker returns-1 only after
 * summary installation/input-buffer writes. Success returns0. Earlier writes,
 * filter/window mutations and core-summary changes persist on any error.
 * No allocation, rollback, locks, timeout or runtime timing claim.
 */
int medius_motion_finalize_processing(MediusMotionProcessingState *processing)
{
    volatile MediusMotionProcessingState *state=processing;
    unsigned int nonzero_count=state->statistics.nonzero_count;
    float magnitude_sum=state->statistics.magnitude_sum;
    float count_float=finalizer_unsigned_float(nonzero_count);
    float mean=0.0f,percentile95=0.0f;
    if (nonzero_count!=0) {
        mean=finalizer_divide(magnitude_sum,count_float);
        if (nonzero_count==1) {
            percentile95=finalizer_unsigned_float(state->statistics.sorted_magnitudes[0]);
        } else {
            float position=finalizer_multiply(finalizer_unsigned_float(nonzero_count-1U),0.95f);
            unsigned int index=finalizer_unsigned_truncate(position);
            unsigned int low=state->statistics.sorted_magnitudes[index];
            unsigned int high=state->statistics.sorted_magnitudes[index+1U];
            float fraction=finalizer_subtract(position,finalizer_unsigned_float(index));
            percentile95=finalizer_add(finalizer_multiply(finalizer_signed_float((int)high-(int)low),fraction),
                finalizer_signed_float((int)low));
        }
    }

    float imaginary=state->statistics.spectrum_imaginary[0];
    float real=state->statistics.spectrum_real[0];
    float pair=finalizer_add(finalizer_multiply(imaginary,imaginary),finalizer_multiply(real,real));
    float spectral_energy=finalizer_add(pair,0.0f);
    for (unsigned int bin=1;bin<7;++bin) {
        imaginary=state->statistics.spectrum_imaginary[bin];
        real=state->statistics.spectrum_real[bin];
        pair=finalizer_add(finalizer_multiply(imaginary,imaginary),finalizer_multiply(real,real));
        spectral_energy=finalizer_add(pair,spectral_energy);
    }
    float mean_square=finalizer_multiply(finalizer_multiply(magnitude_sum,magnitude_sum),1.0f/256.0f);
    float centered=finalizer_subtract(state->statistics.magnitude_squares,mean_square);
    float alternating=state->alternating_magnitude_sum;
    float noise=finalizer_subtract(finalizer_multiply(finalizer_subtract(finalizer_multiply(centered,256.0f),
        finalizer_multiply(alternating,alternating)),0.5f),spectral_energy);
    noise=0.0f<noise ? finalizer_multiply(noise,1.0f/256.0f) : 0.0f;

    state->final_statistics[0]=finalizer_quantize_q8(finalizer_multiply(count_float,1.0f/256.0f));
    state->final_statistics[1]=finalizer_quantize_q8(medius_math_log1pf(mean));
    state->final_statistics[2]=finalizer_quantize_q8(medius_math_log1pf(percentile95));
    float sign_fraction=0.0f;
    unsigned int sign_comparisons=state->statistics.sign_comparisons;
    if (sign_comparisons!=0)
        sign_fraction=finalizer_divide(finalizer_unsigned_float(state->statistics.sign_changes),
            finalizer_unsigned_float(sign_comparisons));
    state->final_statistics[3]=finalizer_quantize_q8(sign_fraction);
    state->final_statistics[4]=finalizer_quantize_q8(medius_math_log1pf(noise));

    MediusMotionFilterVector tail_filtered[4];
    if (medius_motion_filter_finish(&processing->filters[1],(float *)tail_filtered)!=4) return -5;
    for (unsigned int tail=0;tail<4;++tail) {
        int raw_y=state->core.raw_samples[252+tail].y;
        int raw_x=state->core.raw_samples[252+tail].x;
        medius_motion_extract_sample_features(&state->feature_windows[1],124+tail,raw_x,raw_y,
            &tail_filtered[tail],&state->tail_features[tail]);
    }

    union {MediusMotionCoreSummary summary;unsigned int words[25];} completed;
    memset(&completed,0,100);
    memcpy(completed.summary.statistics,(const void *)state->final_statistics,10);
    volatile MediusMotionFeatureWindow *window=&state->feature_windows[1];
    completed.summary.last_nonzero_axis.x=window->last_nonzero_axis.x;
    completed.summary.previous_raw.x=(short)finalizer_truncate(window->previous_raw.x);
    completed.summary.previous_nonzero_raw.x=(short)finalizer_truncate(window->previous_nonzero_raw.x);
    int vector_x=finalizer_quantize_q16(window->previous_filtered.x);
    completed.words[6]=(unsigned int)vector_x;
    completed.summary.previous_raw.y=(short)finalizer_truncate(window->previous_raw.y);
    completed.summary.previous_nonzero_raw.y=(short)finalizer_truncate(window->previous_nonzero_raw.y);
    completed.summary.last_nonzero_axis.y=window->last_nonzero_axis.y;
    int vector_y=finalizer_quantize_q16(window->previous_filtered.y);
    unsigned short activity_weight=window->activity_run_length;
    unsigned char activity_mode=window->previous_activity;
    completed.words[7]=(unsigned int)vector_y;
    completed.summary.activity_weight=activity_weight;
    completed.summary.activity_mode=activity_mode;
    memcpy(completed.summary.activity_flags,(const void *)state->late_activity,60);
    completed.summary.activity_count=60;
    completed.summary.activity_cursor=0;
    int status=medius_motion_core_apply_summary(&processing->core,&completed.summary);
    if (status!=0) return status;

    for (unsigned int unit=0;unit<80;++unit)
        state->network_inputs[unit]=finalizer_multiply(finalizer_signed_float(state->core.hidden_state[unit]),1.0f/32768.0f);
    const volatile short *tail_values=(const volatile short *)state->tail_features;
    for (unsigned int value=0;value<60;++value)
        state->network_inputs[80+value]=finalizer_multiply(finalizer_signed_float(tail_values[value]),1.0f/256.0f);
    for (unsigned int value=0;value<5;++value)
        state->network_inputs[140+value]=finalizer_multiply(finalizer_signed_float(state->final_statistics[value]),1.0f/256.0f);

    const volatile MediusMotionConfiguration *model=state->configuration;
    if (model->tail_header==NULL) return -1;
    float normalized[145],hidden[16];
    for (unsigned int column=0;column<145;++column) {
        float input=state->network_inputs[column];
        float center=medius_motion_half_to_float((const void *)(model->dense_input_centers+2*column));
        float centered_input=finalizer_subtract(input,center);
        float scale=medius_motion_half_to_float((const void *)(model->dense_input_scales+2*column));
        normalized[column]=finalizer_multiply(centered_input,scale);
    }
    for (unsigned int unit=0;unit<16;++unit)
        hidden[unit]=finalizer_hidden_unit(model,normalized,unit);
    for (unsigned int unit=0;unit<80;++unit)
        state->corrected_hidden[unit]=finalizer_output_unit(model,hidden,unit,&state->network_inputs[unit]);
    for (unsigned int unit=0;unit<80;++unit)
        state->core.hidden_state[unit]=finalizer_quantize_hidden(state->corrected_hidden[unit]);
    return status;
}
