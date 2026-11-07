/* Medius v3.4.7 host — app/motion_reset.c.
 */

#include "../include/types.h"

/* Native entry: 0x4200d330. */
/*
 * Medius v3.4.7 — host application; 0x4200d330.
 * Instruction-checked recovered C.
 * Original function-byte SHA-256:
 * 7034513e42661d97bee031730a482636225f897728d421b776110c17ffd05655.
 */

/*
 * Reset all 4,672 processing bytes. NULL state/configuration, or a NULL image
 * in the configuration, returns -1 before any write. Otherwise clear the state,
 * publish its configuration pointer and two unit parameters, then perform six
 * half-angle steps through twelve sqrtf calls. Starting from cosine zero gives
 * a rotation approximately exp(-i*pi/128). Store its first seven powers in the
 * real/imaginary arrays and set the seven adjacent unit parameters to 1.0.
 * Keep the native single-precision products/additions separate when compiling;
 * replacing them with trigonometric calls, fused arithmetic or double precision
 * changes the recovered initialization values.
 *
 * Clear the first 256-byte filter block, then the second; finally initialize
 * the embedded core using configuration->decoded and return its status unchanged.
 * The image pointer is sampled only before the large clear; overlapping storage
 * is accepted and can invalidate the configuration seen by the final initializer.
 * No rollback follows a final error. No sqrtf error check, lock, MEMW, allocation
 * or callback suppression is supplied by this routine.
 */
int medius_motion_processing_reset(MediusMotionProcessingState *state,
    MediusMotionConfiguration *configuration)
{
    if (!state || !configuration) return -1;
    const volatile MediusMotionConfiguration *source = configuration;
    if (!source->image) return -1;
    memset(state, 0, 4672);
    volatile MediusMotionProcessingState *out = state;
    out->configuration = configuration;
    out->unit_parameter_a30 = 1.0f;
    out->unit_parameter_aac = 1.0f;

    float cosine = 0.0f, positive_sine = 0.0f;
    for (unsigned int step = 0; step < 6; ++step) {
        positive_sine = medius_math_sqrtf((1.0f - cosine) * 0.5f);
        cosine = medius_math_sqrtf((cosine + 1.0f) * 0.5f);
    }
    float sine = -positive_sine;
    float cosine_squared = cosine * cosine;
    float sine_cosine = sine * cosine;
    float sine_squared = positive_sine * positive_sine;
    out->rotation_imaginary[0] = sine;
    float real2 = cosine_squared - sine_squared;
    float imaginary2 = sine_cosine + sine_cosine;
    out->rotation_real[0] = cosine;

    float real3 = cosine * real2 - sine * imaginary2;
    float imaginary3 = sine * real2 + cosine * imaginary2;
    out->rotation_real[1] = real2;
    out->rotation_imaginary[1] = imaginary2;
    out->rotation_unit_parameters[0] = 1.0f;

    float real4 = cosine * real3 - sine * imaginary3;
    float imaginary4 = sine * real3 + cosine * imaginary3;
    out->rotation_real[2] = real3;
    out->rotation_imaginary[2] = imaginary3;
    out->rotation_unit_parameters[1] = 1.0f;
    out->rotation_unit_parameters[2] = 1.0f;

    float real5 = cosine * real4 - sine * imaginary4;
    float imaginary5 = sine * real4 + cosine * imaginary4;
    out->rotation_real[3] = real4;
    out->rotation_imaginary[3] = imaginary4;
    out->rotation_unit_parameters[3] = 1.0f;

    float real6 = cosine * real5 - sine * imaginary5;
    float imaginary6 = sine * real5 + cosine * imaginary5;
    out->rotation_real[4] = real5;
    out->rotation_imaginary[4] = imaginary5;
    out->rotation_unit_parameters[4] = 1.0f;
    out->rotation_unit_parameters[5] = 1.0f;

    float real7 = cosine * real6 - sine * imaginary6;
    float imaginary7 = sine * real6 + cosine * imaginary6;
    out->rotation_real[5] = real6;
    out->rotation_imaginary[5] = imaginary6;
    out->rotation_unit_parameters[6] = 1.0f;
    out->rotation_real[6] = real7;
    out->rotation_imaginary[6] = imaginary7;

    medius_motion_filter_reset(state->filter_history[0]);
    medius_motion_filter_reset(state->filter_history[1]);
    return medius_motion_core_initialize(&state->core, &configuration->decoded);
}
