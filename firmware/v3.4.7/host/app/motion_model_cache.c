/* Medius v3.4.7 host — app/motion_model_cache.c.
 */

#include "../include/types.h"

/* Source reconstruction utilities; not additional native firmware entries.
 * These scalar comparisons are the original firmware's startup self-tests.
 * They describe valid serialized RAM; they add no synchronization or recovery.
 */
static unsigned int model_row_correction(const volatile signed char *source,
    unsigned int columns)
{
    int sum=0;
    for (unsigned int column=0;column<columns;++column) sum+=source[column];
    return (unsigned int)sum<<7; /* Native WORD shift, including negative sums. */
}

static bool model_test_s8_rows(const volatile signed char *weights,
    unsigned int stride,const volatile signed char *input,unsigned int columns,
    const volatile unsigned int *results,unsigned int rows)
{
    for (unsigned int row=0;row<rows;++row) {
        int expected=0;
        for (unsigned int column=0;column<columns;++column) {
            int weight=weights[row*stride+column];
            int sample=input[column];
            expected+=weight*sample;
        }
        if ((unsigned int)expected!=results[row]) return false;
    }
    return true;
}

static bool model_test_s16_rows(const volatile signed char *weights,
    unsigned int stride,const volatile short *input,unsigned int columns,
    const volatile unsigned int *results,unsigned int rows)
{
    for (unsigned int row=0;row<rows;++row) {
        int expected=0;
        for (unsigned int column=0;column<columns;++column) {
            int weight=weights[row*stride+column];
            int sample=input[column];
            expected+=weight*sample;
        }
        if ((unsigned int)expected!=results[row]) return false;
    }
    return true;
}

static void model_test_split(volatile MediusMotionMatrixTestState *test,
    unsigned int count,unsigned int clear_length)
{
    memset((void *)&test->high,0,clear_length);
    memset((void *)&test->low,0,clear_length);
    for (unsigned int column=0;column<count;++column) {
        short sample=test->input[column]; /* One HALF read, unlike the public split helper. */
        test->high.lanes[column]=(signed char)((unsigned short)sample>>8);
        test->low.lanes[column]=(signed char)(unsigned char)((int)sample-128);
    }
}

/* Native entry: 0x4200e6c8. */
/* Original function-byte SHA-256:
 * 47f350920ed2019de8cd5780625d8248aa9a4e389995fa28d5636635ecc64d8a. */
/*
 * Build aligned signed-byte model caches and select accelerated GRU execution.
 *
 * configuration: borrowed decoded model; payload must cover all 33,760 matrix
 * bytes. Input rows are padded from 20 to 32 bytes. For each matrix, all copies
 * finish before the source bytes are summed to build correction WORDs. The
 * seemingly redundant memset/memcpy pairs retain the native call boundaries.
 *
 * The firmware then runs nine scalar-versus-vector comparison groups: two
 * signed-byte patterns and signed-16 edge/pseudorandom inputs. A mismatch
 * immediately stores zero to the shared 32-bit acceleration flag. Only the
 * final comparison publishes success. The old flag is not cleared on entry;
 * caches and test buffers already written remain changed after a failure.
 *
 * No argument/length validation, allocation, logging, timeout or locking is
 * supplied. The shared scratch state and cache require serialized callers.
 */
void medius_motion_config_prepare(const MediusMotionDecodedConfiguration *configuration)
{
    const volatile MediusMotionModelWeights *model=configuration->model_weights;
    const volatile signed char *input_source=(const volatile signed char *)model->gru.input;
    const volatile signed char *recurrent_source=(const volatile signed char *)model->gru.recurrent;
    const volatile signed char *projection_source=(const volatile signed char *)model->projection;
    volatile MediusMotionModelCache *cache=MEDIUS_MOTION_MODEL_CACHE;
    volatile MediusMotionMatrixTestState *test=MEDIUS_MOTION_MATRIX_TEST;
    union {
        MediusMotionS8Vector80 vector;
        unsigned short first_half;
    } pattern;

    for (unsigned int row=0;row<240;++row) {
        memset((void *)&cache->input[row],0,32);
        memcpy((void *)&cache->input[row],(const void *)(input_source+20*row),20);
    }
    for (unsigned int row=0;row<240;++row)
        cache->input_corrections[row]=model_row_correction(input_source+20*row,20);

    for (unsigned int row=0;row<240;++row) {
        memset((void *)&cache->recurrent[row],0,80);
        memcpy((void *)&cache->recurrent[row],(const void *)(recurrent_source+80*row),80);
    }
    for (unsigned int row=0;row<240;++row)
        cache->recurrent_corrections[row]=model_row_correction(recurrent_source+80*row,80);

    for (unsigned int row=0;row<121;++row) {
        memset((void *)&cache->projection[row],0,80);
        memcpy((void *)&cache->projection[row],(const void *)(projection_source+80*row),80);
    }
    for (unsigned int row=0;row<121;++row)
        cache->projection_corrections[row]=model_row_correction(projection_source+80*row,80);

    memset((void *)&cache->single_output,0,80);
    memcpy((void *)&cache->single_output,(const void *)model->single_output,80);
    cache->single_correction=model_row_correction(model->single_output,80);

    unsigned int value=17;
    for (unsigned int column=0;column<80;++column) {
        pattern.vector.lanes[column]=(signed char)(unsigned char)value;
        value=(value+53)&255U;
    }
    pattern.first_half=0x807fU; /* Original little-endian HALF store: +127, -128. */
    pattern.vector.lanes[40]=-128;
    pattern.vector.lanes[79]=127;

    medius_motion_dot_s8_32(cache->input,(const volatile MediusMotionS8Vector32 *)&pattern,
        test->results,240);
    if (!model_test_s8_rows((const volatile signed char *)cache->input,32,
        pattern.vector.lanes,32,test->results,240)) goto mismatch;

    medius_motion_dot_s8_80(&cache->single_output,&pattern.vector,test->results,1);
    if (!model_test_s8_rows(cache->single_output.lanes,80,
        pattern.vector.lanes,80,test->results,1)) goto mismatch;

    medius_motion_dot_s8_80(cache->projection,&pattern.vector,test->results,121);
    if (!model_test_s8_rows((const volatile signed char *)cache->projection,80,
        pattern.vector.lanes,80,test->results,121)) goto mismatch;

    for (unsigned int column=0;column<80;++column)
        pattern.vector.lanes[column]=(signed char)((int)column-128);

    medius_motion_dot_s8_32(cache->input,(const volatile MediusMotionS8Vector32 *)&pattern,
        test->results,240);
    if (!model_test_s8_rows((const volatile signed char *)cache->input,32,
        pattern.vector.lanes,32,test->results,240)) goto mismatch;

    medius_motion_dot_s8_80(cache->recurrent,&pattern.vector,test->results,240);
    if (!model_test_s8_rows((const volatile signed char *)cache->recurrent,80,
        pattern.vector.lanes,80,test->results,240)) goto mismatch;

    /* Original five immutable seed WORDs at 0x3c045e14. Preserve store order:
     * (32767,-32768), (0,1), (-1,255), (256,-256), (-257,128). */
    test->input_words[1]=0x00010000U;
    test->input_words[0]=0x80007fffU;
    test->input_words[2]=0x00ffffffU;
    test->input_words[3]=0xff000100U;
    test->input_words[4]=0x0080feffU;
    unsigned short sample=0x44d6U;
    for (unsigned int column=10;column<80;++column) {
        test->input[column]=(short)sample;
        sample=(unsigned short)(sample+0x13afU);
    }

    model_test_split(test,20,32);
    medius_motion_dot_s8_32(cache->input,(const volatile MediusMotionS8Vector32 *)&test->high,
        test->results,240);
    medius_motion_accumulate_s8_32(cache->input,(const volatile MediusMotionS8Vector32 *)&test->low,
        test->results,240,cache->input_corrections);
    if (!model_test_s16_rows((const volatile signed char *)cache->input,32,
        test->input,20,test->results,240)) goto mismatch;

    model_test_split(test,80,80);
    medius_motion_dot_s8_80(cache->recurrent,&test->high,test->results,240);
    medius_motion_accumulate_s8_80(cache->recurrent,&test->low,
        test->results,240,cache->recurrent_corrections);
    if (!model_test_s16_rows((const volatile signed char *)cache->recurrent,80,
        test->input,80,test->results,240)) goto mismatch;

    model_test_split(test,80,80);
    medius_motion_dot_s8_80(cache->projection,&test->high,test->results,121);
    medius_motion_accumulate_s8_80(cache->projection,&test->low,
        test->results,121,cache->projection_corrections);
    if (!model_test_s16_rows((const volatile signed char *)cache->projection,80,
        test->input,80,test->results,121)) goto mismatch;

    model_test_split(test,80,80);
    medius_motion_dot_s8_80(&cache->single_output,&test->high,test->results,1);
    medius_motion_accumulate_s8_80(&cache->single_output,&test->low,
        test->results,1,&cache->single_correction);
    MEDIUS_MOTION_GRU_ACCELERATED=(unsigned int)model_test_s16_rows(cache->single_output.lanes,
        80,test->input,80,test->results,1);
    return;

mismatch:
    MEDIUS_MOTION_GRU_ACCELERATED=0;
}
