/* Medius v3.4.7 host — app/motion_filter.c.
 */

#include "../include/types.h"

/* Source reconstruction utilities; not extra native firmware entries. Explicit
 * binary32 operations preserve the native evaluation order, signed zeros and
 * FPU handling of exceptional inputs. No algebraic reassociation or FMA. */
static __inline__ __attribute__((always_inline)) float filter_add(float left,float right)
{
    float result;
    __asm__ volatile("add.s %0, %1, %2" : "=f"(result) : "f"(left),"f"(right));
    return result;
}

static __inline__ __attribute__((always_inline)) float filter_subtract(float left,float right)
{
    float result;
    __asm__ volatile("sub.s %0, %1, %2" : "=f"(result) : "f"(left),"f"(right));
    return result;
}

static __inline__ __attribute__((always_inline)) float filter_multiply(float left,float right)
{
    float result;
    __asm__ volatile("mul.s %0, %1, %2" : "=f"(result) : "f"(left),"f"(right));
    return result;
}

static float filter_float_bits(unsigned int bits)
{
    union {unsigned int bits;float value;} representation = {.bits = bits};
    return representation.value;
}

static unsigned int filter_result_bits(float value)
{
    union {unsigned int bits;float value;} representation = {.value = value};
    return representation.bits;
}

/* Finish's dummy first-stage updates repeat the latest cumulative position,
 * not an additional motion input. Preserve count/history fields and narrow
 * native writes; caller publishes the exact cached sample-count increment. */
static void filter_finish_extend_first(volatile MediusMotionFilterState *filter,
    unsigned int x,unsigned int y,unsigned int count)
{
    filter->cumulative_latest.x_bits = x;
    filter->cumulative_latest.y_bits = y;
    if (count < 5U) {
        filter->cumulative_history[count].x_bits = x;
        unsigned int fresh_y = filter->cumulative_latest.y_bits;
        filter->cumulative_history[count].y_bits = fresh_y;
        filter->cumulative_history_count = count + 1U;
    } else {
        unsigned int x1 = filter->cumulative_history[1].x_bits;
        unsigned int y1 = filter->cumulative_history[1].y_bits;
        unsigned int x2 = filter->cumulative_history[2].x_bits;
        unsigned int y2 = filter->cumulative_history[2].y_bits;
        unsigned int x3 = filter->cumulative_history[3].x_bits;
        unsigned int y3 = filter->cumulative_history[3].y_bits;
        unsigned int x4 = filter->cumulative_history[4].x_bits;
        unsigned int y4 = filter->cumulative_history[4].y_bits;
        filter->cumulative_history[0].x_bits = x1;
        filter->cumulative_history[0].y_bits = y1;
        filter->cumulative_history[1].x_bits = x2;
        filter->cumulative_history[1].y_bits = y2;
        filter->cumulative_history[2].x_bits = x3;
        filter->cumulative_history[2].y_bits = y3;
        filter->cumulative_history[3].x_bits = x4;
        filter->cumulative_history[3].y_bits = y4;
        filter->cumulative_history[4].x_bits = x;
        filter->cumulative_history[4].y_bits = y;
    }
}

extern float medius_motion_filter_divide(float numerator,float denominator) __asm__("__divsf3");

/* Native entry: 0x4037abac. */
/* Original function-byte SHA-256:
 * bbb6798c77adec05f0377f1431009bdb8d6c433e6f1c91d2ffaefcb78a8bf9d5. */
/* Average five interleaved binary32 XY positions. unused_word is ignored;
 * count_low/high are two WORDs, not an aligned64 argument. Exactly count3/high0
 * repeats the first position three times; count4/high0 repeats it twice. Every
 * other count, including0/1/2 or nonzero high, reads all five positions. No
 * pointer/count validation or internal history mutation. output receives X
 * before Y is read; input/output overlap therefore retains native effects.
 * Each multiply uses the exact binary32 0.2f. The explicit ADD.S ordering,
 * including initial+0 and operand order, preserves native rounding behavior.
 */
void medius_motion_filter_average_five(const volatile MediusMotionFilterVector history[5],
    unsigned int unused_word,unsigned int count_low,unsigned int count_high,
    volatile MediusMotionFilterVector *output)
{
    (void)unused_word;
    float x0 = filter_multiply(history[0].x,0.2f);
    float x1 = filter_multiply(history[1].x,0.2f);
    float x2 = filter_multiply(history[2].x,0.2f);
    float sum = filter_add(x0,0.0f);
    if (count_low == 3U && count_high == 0) {
        sum = filter_add(sum,x0);
        sum = filter_add(x0,sum);
        sum = filter_add(x1,sum);
        output->x = filter_add(x2,sum);
        float y0 = filter_multiply(history[0].y,0.2f);
        float y1 = filter_multiply(history[1].y,0.2f);
        float ysum = filter_add(y0,0.0f);
        float y2 = filter_multiply(history[2].y,0.2f);
        ysum = filter_add(ysum,y0);
        ysum = filter_add(y0,ysum);
        ysum = filter_add(y1,ysum);
        output->y = filter_add(y2,ysum);
        return;
    }
    float x3 = filter_multiply(history[3].x,0.2f);
    if (count_low == 4U && count_high == 0) {
        sum = filter_add(sum,x0);
        sum = filter_add(sum,x1);
        sum = filter_add(sum,x2);
        output->x = filter_add(sum,x3);
    } else {
        sum = filter_add(sum,x1);
        float x4 = filter_multiply(history[4].x,0.2f);
        sum = filter_add(sum,x2);
        sum = filter_add(sum,x3);
        output->x = filter_add(x4,sum);
    }
    float y0 = filter_multiply(history[0].y,0.2f);
    float raw_y2 = history[2].y;
    float raw_y3 = history[3].y;
    float raw_y1 = history[1].y;
    float y2 = filter_multiply(raw_y2,0.2f);
    float y1 = filter_multiply(raw_y1,0.2f);
    float ysum = filter_add(y0,0.0f);
    float y3 = filter_multiply(raw_y3,0.2f);
    if (count_low == 4U && count_high == 0) {
        ysum = filter_add(ysum,y0);
        ysum = filter_add(y1,ysum);
        ysum = filter_add(y2,ysum);
        output->y = filter_add(ysum,y3);
    } else {
        ysum = filter_add(y1,ysum);
        float y4 = filter_multiply(history[4].y,0.2f);
        ysum = filter_add(y2,ysum);
        ysum = filter_add(ysum,y3);
        output->y = filter_add(y4,ysum);
    }
}

/* Native entry: 0x4037ac88. */
/* Original function-byte SHA-256:
 * 95e0b061b830698d467bdb39c7cc8ebb6b22522ef8c4e3b15957cb7dceb371df. */
/* Feed the second five-position average and emit its difference from the
 * previous result. No pointer/sealed/mode checks: callers own valid serialized
 * state/input/output. Read averaged sample count LOW then HIGH; an initially
 * zero pair copies input into averaged_initial. Copy latest and append/shift
 * its five-position history using raw32 views, preserving sample bit patterns.
 * Increment/publish count LOW/HIGH modulo64. Counts1/2 with HIGH0 return0 with
 * output untouched; all other counts run average_five. First result emits that
 * position, later ones emit signed binary32 differences, X before Y.
 *
 * Read output-count LOW/HIGH before writing output Y; then store previous Y,
 * previous-valid BYTE1, output-count LOW/HIGH. Return1 for emitted output,0
 * for warm-up only. Mode changes, time, locks, atomic64 accesses, zero filling,
 * rejection of NaN/infinity and transport are not supplied here. State/input/
 * output aliases retain explicit native reads/writes rather than a no-alias
 * assumption. Counters wrap; a full wrap can re-enter initialization/warm-up.
 */
int medius_motion_filter_difference(volatile MediusMotionFilterState *filter,
    const volatile MediusMotionFilterVector *input,volatile MediusMotionFilterVector *output)
{
    unsigned int low = filter->averaged_samples.low;
    unsigned int high = filter->averaged_samples.high;
    if ((low | high) == 0) {
        filter->averaged_initial.x_bits = input->x_bits;
        filter->averaged_initial.y_bits = input->y_bits;
    }
    unsigned int x = input->x_bits;
    unsigned int count = filter->averaged_history_count;
    filter->averaged_latest.x_bits = x;
    filter->averaged_latest.y_bits = input->y_bits;
    if (count < 5U) {
        filter->averaged_history[count].x_bits = input->x_bits;
        filter->averaged_history[count].y_bits = input->y_bits;
        filter->averaged_history_count = count + 1U;
    } else {
        unsigned int x1 = filter->averaged_history[1].x_bits;
        unsigned int y4 = filter->averaged_history[4].y_bits;
        filter->averaged_history[0].x_bits = x1;
        unsigned int x2 = filter->averaged_history[2].x_bits;
        unsigned int y2 = filter->averaged_history[2].y_bits;
        unsigned int x3 = filter->averaged_history[3].x_bits;
        unsigned int y3 = filter->averaged_history[3].y_bits;
        unsigned int x4 = filter->averaged_history[4].x_bits;
        unsigned int y1 = filter->averaged_history[1].y_bits;
        filter->averaged_history[1].x_bits = x2;
        filter->averaged_history[0].y_bits = y1;
        filter->averaged_history[1].y_bits = y2;
        filter->averaged_history[2].x_bits = x3;
        filter->averaged_history[2].y_bits = y3;
        filter->averaged_history[3].x_bits = x4;
        filter->averaged_history[3].y_bits = y4;
        filter->averaged_history[4].x_bits = input->x_bits;
        filter->averaged_history[4].y_bits = input->y_bits;
    }
    ++low;
    high += low == 0;
    filter->averaged_samples.low = low;
    filter->averaged_samples.high = high;
    if (high == 0 && low < 3U) return 0;
    MediusMotionFilterVector average;
    medius_motion_filter_average_five(filter->averaged_history,0,low,high,&average);
    unsigned char valid = filter->has_previous;
    float y = average.y;
    float mean_x = average.x;
    float delta_y;
    if (valid == 0) {
        output->x = mean_x;
        filter->previous.x = mean_x;
        delta_y = y;
    } else {
        float old_x = filter->previous.x;
        output->x = filter_subtract(mean_x,old_x);
        filter->previous.x = mean_x;
        float old_y = filter->previous.y;
        delta_y = filter_subtract(y,old_y);
    }
    unsigned int outputs_low = filter->output_samples.low;
    unsigned int outputs_high = filter->output_samples.high;
    ++outputs_low;
    outputs_high += outputs_low == 0;
    output->y = delta_y;
    filter->previous.y = y;
    filter->has_previous = 1;
    filter->output_samples.low = outputs_low;
    filter->output_samples.high = outputs_high;
    return 1;
}

/* Native entry: 0x4037ad70. */
/* Original function-byte SHA-256:
 * ecdb61f9ced14e4516e76752b7d3265f3debca8449ee319d87b4b9194ab945af. */
/* Feed one binary32 XY motion sample. NULL state/output or an already sealed
 * state returns0 without mutation. Otherwise increment the two-WORD input
 * counter modulo64. A nonzero weighted_mode selects newest-first weights
 *9,8,7,6,5,4,3,2,1 divided by45, even during history warm-up: it emits1 on
 * every input and increments output count before computing/writing outputs.
 * weighted_count advances only while <=8; arbitrary larger values use all9.
 * X uses cached old history; Y is read afresh after output X, retaining alias
 * effects. Division is the original ROM binary32 helper, not reciprocal/FMA.
 * ADD.S operand order, including +0 and the doubled weight2 term, is explicit.
 *
 * Mode0 integrates input into a cumulative position, feeds a five-position
 * average, then another five-position average and differences its outputs.
 * Counts1/2 in either stage warm up without writing output; normal zero-reset
 * mode0 emits first on input5. First emitted difference is the position itself.
 * Both stages repeat their first sample during averaging at counts3/4. State
 * and history persist across mode changes. Counters can wrap back through
 * initialization/warm-up. No bounds validation, NaN rejection, normalization
 * of partial weighted history, lock or mode-switch reset is supplied here.
 */
int medius_motion_filter_step(volatile MediusMotionFilterState *filter,
    float x,float y,float output_xy[2])
{
    if (filter == NULL || output_xy == NULL) return 0;
    if (filter->sealed != 0) return 0;
    volatile MediusMotionFilterVector *output = (volatile MediusMotionFilterVector *)output_xy;
    unsigned int inputs_low = filter->input_samples.low;
    unsigned int inputs_high = filter->input_samples.high;
    ++inputs_low;
    unsigned char weighted = filter->weighted_mode;
    inputs_high += inputs_low == 0;
    if (weighted != 0) {
        unsigned int outputs_low = filter->output_samples.low;
        unsigned int outputs_high = filter->output_samples.high;
        ++outputs_low;
        outputs_high += outputs_low == 0;
        unsigned int old_y5 = filter->weighted_history[5].y_bits;
        unsigned int old_x7_bits = filter->weighted_history[7].x_bits;
        unsigned int old_y7 = filter->weighted_history[7].y_bits;
        float old_x6 = filter->weighted_history[6].x;
        unsigned int old_y6 = filter->weighted_history[6].y_bits;
        float old_x5 = filter->weighted_history[5].x;
        float old_x4 = filter->weighted_history[4].x;
        unsigned int old_y4 = filter->weighted_history[4].y_bits;
        float old_x3 = filter->weighted_history[3].x;
        unsigned int old_y3 = filter->weighted_history[3].y_bits;
        float old_x2 = filter->weighted_history[2].x;
        unsigned int old_y2 = filter->weighted_history[2].y_bits;
        float old_x1 = filter->weighted_history[1].x;
        filter->input_samples.low = inputs_low;
        filter->weighted_history[6].y_bits = old_y5;
        filter->input_samples.high = inputs_high;
        filter->output_samples.low = outputs_low;
        filter->output_samples.high = outputs_high;
        filter->weighted_history[8].x_bits = old_x7_bits;
        filter->weighted_history[8].y_bits = old_y7;
        filter->weighted_history[7].x = old_x6;
        filter->weighted_history[7].y_bits = old_y6;
        filter->weighted_history[6].x = old_x5;
        filter->weighted_history[5].x = old_x4;
        filter->weighted_history[5].y_bits = old_y4;
        filter->weighted_history[4].x = old_x3;
        filter->weighted_history[4].y_bits = old_y3;
        filter->weighted_history[3].x = old_x2;
        filter->weighted_history[3].y_bits = old_y2;
        filter->weighted_history[2].x = old_x1;
        unsigned int old_y1 = filter->weighted_history[1].y_bits;
        unsigned int old_y0 = filter->weighted_history[0].y_bits;
        float old_x0 = filter->weighted_history[0].x;
        unsigned int count = filter->weighted_count;
        filter->weighted_history[1].y_bits = old_y0;
        filter->weighted_history[2].y_bits = old_y1;
        filter->weighted_history[1].x = old_x0;
        filter->weighted_history[0].x = x;
        filter->weighted_history[0].y = y;
        if (count <= 8U) filter->weighted_count = ++count;

        float sum_x = filter_add(filter_multiply(x,9.0f),0.0f);
        if (count != 1U) {
            sum_x = filter_add(filter_multiply(old_x0,8.0f),sum_x);
            if (count != 2U) {
                sum_x = filter_add(sum_x,filter_multiply(old_x1,7.0f));
                if (count != 3U) {
                    sum_x = filter_add(sum_x,filter_multiply(old_x2,6.0f));
                    if (count != 4U) {
                        sum_x = filter_add(sum_x,filter_multiply(old_x3,5.0f));
                        if (count != 5U) {
                            sum_x = filter_add(sum_x,filter_multiply(old_x4,4.0f));
                            if (count != 6U) {
                                sum_x = filter_add(sum_x,filter_multiply(old_x5,3.0f));
                                if (count != 7U) {
                                    sum_x = filter_add(sum_x,filter_add(old_x6,old_x6));
                                    if (count != 8U) sum_x = filter_add(sum_x,filter_float_bits(old_x7_bits));
                                }
                            }
                        }
                    }
                }
            }
        }
        output->x_bits = filter_result_bits(medius_motion_filter_divide(sum_x,45.0f));

        float sum_y = filter_add(filter_multiply(filter->weighted_history[0].y,9.0f),0.0f);
        if (count != 1U) {
            sum_y = filter_add(filter_multiply(filter->weighted_history[1].y,8.0f),sum_y);
            if (count != 2U) {
                float term = filter_multiply(filter->weighted_history[2].y,7.0f);
                sum_y = count > 8U ? filter_add(term,sum_y) : filter_add(sum_y,term);
                if (count != 3U) {
                    sum_y = filter_add(sum_y,filter_multiply(filter->weighted_history[3].y,6.0f));
                    if (count != 4U) {
                        sum_y = filter_add(sum_y,filter_multiply(filter->weighted_history[4].y,5.0f));
                        if (count != 5U) {
                            sum_y = filter_add(sum_y,filter_multiply(filter->weighted_history[5].y,4.0f));
                            if (count != 6U) {
                                sum_y = filter_add(sum_y,filter_multiply(filter->weighted_history[6].y,3.0f));
                                if (count != 7U) {
                                    float twice = filter->weighted_history[7].y;
                                    sum_y = filter_add(sum_y,filter_add(twice,twice));
                                    if (count != 8U) sum_y = filter_add(sum_y,filter->weighted_history[8].y);
                                }
                            }
                        }
                    }
                }
            }
        }
        output->y_bits = filter_result_bits(medius_motion_filter_divide(sum_y,45.0f));
        return 1;
    }

    float previous_x = filter->cumulative.x;
    unsigned int samples_low = filter->cumulative_samples.low;
    float cumulative_x = filter_add(x,previous_x);
    float previous_y = filter->cumulative.y;
    unsigned int samples_high = filter->cumulative_samples.high;
    float cumulative_y = filter_add(y,previous_y);
    filter->input_samples.low = inputs_low;
    filter->cumulative.x = cumulative_x;
    filter->input_samples.high = inputs_high;
    filter->cumulative.y = cumulative_y;
    if ((samples_low | samples_high) == 0) {
        filter->cumulative_initial.x = cumulative_x;
        filter->cumulative_initial.y = cumulative_y;
    }
    unsigned int count = filter->cumulative_history_count;
    filter->cumulative_latest.x = cumulative_x;
    filter->cumulative_latest.y = cumulative_y;
    if (count < 5U) {
        filter->cumulative_history[count].x = cumulative_x;
        filter->cumulative_history[count].y = cumulative_y;
        filter->cumulative_history_count = count + 1U;
    } else {
        unsigned int x1 = filter->cumulative_history[1].x_bits;
        unsigned int y1 = filter->cumulative_history[1].y_bits;
        unsigned int x2 = filter->cumulative_history[2].x_bits;
        unsigned int y2 = filter->cumulative_history[2].y_bits;
        unsigned int x3 = filter->cumulative_history[3].x_bits;
        unsigned int y3 = filter->cumulative_history[3].y_bits;
        unsigned int x4 = filter->cumulative_history[4].x_bits;
        unsigned int y4 = filter->cumulative_history[4].y_bits;
        filter->cumulative_history[0].x_bits = x1;
        filter->cumulative_history[0].y_bits = y1;
        filter->cumulative_history[1].x_bits = x2;
        filter->cumulative_history[1].y_bits = y2;
        filter->cumulative_history[2].x_bits = x3;
        filter->cumulative_history[2].y_bits = y3;
        filter->cumulative_history[3].x_bits = x4;
        filter->cumulative_history[3].y_bits = y4;
        filter->cumulative_history[4].x = cumulative_x;
        filter->cumulative_history[4].y = cumulative_y;
    }
    ++samples_low;
    samples_high += samples_low == 0;
    filter->cumulative_samples.low = samples_low;
    filter->cumulative_samples.high = samples_high;
    if (samples_high == 0 && samples_low < 3U) return 0;
    MediusMotionFilterVector average;
    medius_motion_filter_average_five(filter->cumulative_history,0,samples_low,samples_high,&average);
    return medius_motion_filter_difference(filter,&average,output);
}

/* Native entry: 0x4200e3f8. */
/* Original function-byte SHA-256:
 * 4dfb16ce35192b4f6252346103179d53c9cc43a71813187ccd645dccb53a32ec. */
/* Seal and drain the motion filter into up to four XY output pairs (eight
 * float WORDs). NULL state/output or an already sealed state returns-1 before
 * mutation. Cache input count LOW/HIGH and set sealed BYTE1 even for empty
 * input or a later error. Empty input returns0. Weighted mode produces no
 * delayed samples: return0 only when output count equals the saved input
 * count, otherwise-1. No unseal, rollback, clearing or retry is performed.
 *
 * Mode0 repeats the latest cumulative position twice through stage1, then
 * repeats averaged_latest twice through stage2. Each emitted pair is copied
 * to output in X/Y raw32 order; return the number copied only when final
 * output count matches saved input count. Otherwise return-1 with all earlier
 * writes/state advances retained. Stage1 counts are original_count+1/+2,
 * modulo64, not fresh counter reads after an output alias. If the original
 * first-stage history was full, the second update remains a shift even if
 * an intervening output changed its count. Latest positions are reloaded
 * after those writes. Stage2 receives a pointer into the state itself.
 *
 * Final stage2 drains check the four-pair capacity AFTER advancing stage2;
 * an overflow error retains that advance and previous outputs. The original
 * output index is narrowed to16 bits. Output capacity is a caller contract,
 * not a length parameter. Concurrent use is not serialized here. Counters,
 * NaN/infinite samples and caller state/output overlap are not sanitized.
 */
int medius_motion_filter_finish(volatile MediusMotionFilterState *filter,float output_xy[8])
{
    if (filter == NULL || output_xy == NULL) return -1;
    if (filter->sealed != 0) return -1;
    volatile MediusMotionFilterVector *output = (volatile MediusMotionFilterVector *)output_xy;
    unsigned int input_low = filter->input_samples.low;
    unsigned int input_high = filter->input_samples.high;
    filter->sealed = 1;
    if ((input_low | input_high) == 0) return 0;
    if (filter->weighted_mode != 0) {
        unsigned int output_low = filter->output_samples.low;
        unsigned int output_high = filter->output_samples.high;
        return output_low == input_low && output_high == input_high ? 0 : -1;
    }

    unsigned int original_low = filter->cumulative_samples.low;
    unsigned int original_high = filter->cumulative_samples.high;
    unsigned int x = filter->cumulative_latest.x_bits;
    unsigned int y = filter->cumulative_latest.y_bits;
    if ((original_low | original_high) == 0) {
        filter->cumulative_initial.x_bits = x;
        filter->cumulative_initial.y_bits = y;
    }
    unsigned int initial_history_count = filter->cumulative_history_count;
    unsigned int written = 0;
    MediusMotionFilterVector scratch = {.x_bits = 0,.y_bits = 0};
    for (unsigned int repeat = 1;repeat <= 2U;++repeat) {
        unsigned int count = initial_history_count;
        if (repeat == 2U) {
            x = filter->cumulative_latest.x_bits;
            y = filter->cumulative_latest.y_bits;
            /* A full64-bit wrap on the first dummy re-enters the native
             * first-position initialization before the second dummy. */
            if (original_low == 0xffffffffU && original_high == 0xffffffffU) {
                filter->cumulative_initial.x_bits = x;
                filter->cumulative_initial.y_bits = y;
            }
            if (initial_history_count < 5U) count = filter->cumulative_history_count;
        }
        filter_finish_extend_first(filter,x,y,count);
        unsigned int low = original_low + repeat;
        unsigned int high = original_high + (low < repeat);
        filter->cumulative_samples.low = low;
        filter->cumulative_samples.high = high;
        if (high != 0 || low >= 3U) {
            MediusMotionFilterVector average;
            medius_motion_filter_average_five(filter->cumulative_history,0,low,high,&average);
            if (medius_motion_filter_difference(filter,&average,&scratch) != 0) {
                output[(unsigned short)written].x_bits = scratch.x_bits;
                output[(unsigned short)written].y_bits = scratch.y_bits;
                ++written;
            }
        }
    }
    for (unsigned int repeat = 0;repeat < 2U;++repeat) {
        if (medius_motion_filter_difference(filter,&filter->averaged_latest,&scratch) != 0) {
            if (written >= 4U) return -1;
            output[(unsigned short)written].x_bits = scratch.x_bits;
            output[(unsigned short)written].y_bits = scratch.y_bits;
            ++written;
        }
    }
    if (filter->output_samples.low != input_low) return -1;
    if (filter->output_samples.high != input_high) return -1;
    return (int)written;
}
