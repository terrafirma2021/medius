/* Medius v3.4.7 host — app/motion_matrix.c.
 * Historical importer identities cover only ENTRY for these four functions.
 * Complete native extents and byte hashes are supplied below as well.
 * EE.VMULAS.S8.ACCX: ESP32-S3 TRM, Processor Instruction Extensions:
 * https://documentation.espressif.com/esp32-s3_technical_reference_manual_en.pdf
 */

#include "../include/types.h"

/* Native entry: 0x4037d694. */
/* Original function-byte SHA-256:
 * ca53509c6d2afe1b402636b228256af96119e21327e3fd66055207a66ccdaf63.
 * Historical identity covers ENTRY only. Complete procedure 0x4037d694..0x4037d6d1:
 * SHA-256 feae6caf76492e02f6f04372f120830d980f364621ea0b2b2dff07c5ca8bce40. */
/* Scalar recovery of the native signed8 dot-product kernel, 80 lanes per
 * weight row. Snapshot the entire input vector BEFORE checking rows, matching
 * the unconditional native5 vector loads; rows0 still reads input but
 * does not read weights/output. Each row starts a fresh ACCX=0, sums
 * signed8 products and exposes the low32-bit result. Even the80-lane bound
 * is only1,310,720 in magnitude, so native40-bit ACCX saturation is unreachable.
 * Input is reused from its snapshot; weights are consumed freshly per row,
 * preserving earlier-output/later-weight alias effects. No row-count cap,
 * allocation, NULL check, rescaling, activation, lock or status is supplied.
 *
 * Write each row's signed dot result as one raw output WORD.
 * The native implementation uses16-byte vector loads and requires aligned
 * readable vectors/weights and aligned WORD outputs. This readable
 * scalar reconstruction assumes ordinary serialized RAM and represents the
 * numerical/memory algorithm; it does not emulate vector-register clobbers,
 * invalid-address faults,128-bit bus transactions or execution timing.
 */
void medius_motion_dot_s8_80(const volatile MediusMotionS8Vector80 *weights,
    const volatile MediusMotionS8Vector80 *input,volatile unsigned int *output,unsigned int rows)
{
    signed char snapshot[80];
    for (unsigned int lane = 0;lane < 80U;++lane) snapshot[lane] = input->lanes[lane];
    for (unsigned int row = 0;row < rows;++row) {
        int dot = 0;
        for (unsigned int lane = 0;lane < 80U;++lane)
            dot += (int)weights[row].lanes[lane]*(int)snapshot[lane];
        output[row] = (unsigned int)dot;
    }
}

/* Native entry: 0x4037d6d4. */
/* Original function-byte SHA-256:
 * ca53509c6d2afe1b402636b228256af96119e21327e3fd66055207a66ccdaf63.
 * Historical identity covers ENTRY only. Complete procedure 0x4037d6d4..0x4037d6fd:
 * SHA-256 f5ef1a695827198df3c3b39a0b389f6d91c469fc7d70dae442c084e73289ed56. */
/* Scalar recovery of the native signed8 dot-product kernel, 32 lanes per
 * weight row. Snapshot the entire input vector BEFORE checking rows, matching
 * the unconditional native2 vector loads; rows0 still reads input but
 * does not read weights/output. Each row starts a fresh ACCX=0, sums
 * signed8 products and exposes the low32-bit result. Even the80-lane bound
 * is only1,310,720 in magnitude, so native40-bit ACCX saturation is unreachable.
 * Input is reused from its snapshot; weights are consumed freshly per row,
 * preserving earlier-output/later-weight alias effects. No row-count cap,
 * allocation, NULL check, rescaling, activation, lock or status is supplied.
 *
 * Write each row's signed dot result as one raw output WORD.
 * The native implementation uses16-byte vector loads and requires aligned
 * readable vectors/weights and aligned WORD outputs. This readable
 * scalar reconstruction assumes ordinary serialized RAM and represents the
 * numerical/memory algorithm; it does not emulate vector-register clobbers,
 * invalid-address faults,128-bit bus transactions or execution timing.
 */
void medius_motion_dot_s8_32(const volatile MediusMotionS8Vector32 *weights,
    const volatile MediusMotionS8Vector32 *input,volatile unsigned int *output,unsigned int rows)
{
    signed char snapshot[32];
    for (unsigned int lane = 0;lane < 32U;++lane) snapshot[lane] = input->lanes[lane];
    for (unsigned int row = 0;row < rows;++row) {
        int dot = 0;
        for (unsigned int lane = 0;lane < 32U;++lane)
            dot += (int)weights[row].lanes[lane]*(int)snapshot[lane];
        output[row] = (unsigned int)dot;
    }
}

/* Native entry: 0x4037d700. */
/* Original function-byte SHA-256:
 * ca53509c6d2afe1b402636b228256af96119e21327e3fd66055207a66ccdaf63.
 * Historical identity covers ENTRY only. Complete procedure 0x4037d700..0x4037d749:
 * SHA-256 6d7ccbac448d57a83a787ab4e770bb1ae52f1aed24951c9a8a607d7751727052. */
/* Scalar recovery of the native signed8 dot-product kernel, 80 lanes per
 * weight row. Snapshot the entire input vector BEFORE checking rows, matching
 * the unconditional native5 vector loads; rows0 still reads input but
 * does not read weights/output/bias. Each row starts a fresh ACCX=0, sums
 * signed8 products and exposes the low32-bit result. Even the80-lane bound
 * is only1,310,720 in magnitude, so native40-bit ACCX saturation is unreachable.
 * Input is reused from its snapshot; weights are consumed freshly per row,
 * preserving earlier-output/later-weight alias effects. No row-count cap,
 * allocation, NULL check, rescaling, activation, lock or status is supplied.
 *
 * For each row read old output WORD then bias WORD, and publish
 * (old_output<<8)+bias+dot modulo32. This is not a saturated32-bit add.
 * Bias/output may alias; both reads precede that row's output store.
 * The native implementation uses16-byte vector loads and requires aligned
 * readable vectors/weights and aligned WORD outputs/bias. This readable
 * scalar reconstruction assumes ordinary serialized RAM and represents the
 * numerical/memory algorithm; it does not emulate vector-register clobbers,
 * invalid-address faults,128-bit bus transactions or execution timing.
 */
void medius_motion_accumulate_s8_80(const volatile MediusMotionS8Vector80 *weights,
    const volatile MediusMotionS8Vector80 *input,volatile unsigned int *output,unsigned int rows,
    const volatile unsigned int *bias)
{
    signed char snapshot[80];
    for (unsigned int lane = 0;lane < 80U;++lane) snapshot[lane] = input->lanes[lane];
    for (unsigned int row = 0;row < rows;++row) {
        int dot = 0;
        for (unsigned int lane = 0;lane < 80U;++lane)
            dot += (int)weights[row].lanes[lane]*(int)snapshot[lane];
        unsigned int previous = output[row];
        unsigned int correction = bias[row];
        output[row] = (previous<<8)+correction+(unsigned int)dot;
    }
}

/* Native entry: 0x4037d74c. */
/* Original function-byte SHA-256:
 * ca53509c6d2afe1b402636b228256af96119e21327e3fd66055207a66ccdaf63.
 * Historical identity covers ENTRY only. Complete procedure 0x4037d74c..0x4037d781:
 * SHA-256 f435bf446ef4898b053bdbfb88682439dfdc9a18a75d4b1abb2059eed5cf7989. */
/* Scalar recovery of the native signed8 dot-product kernel, 32 lanes per
 * weight row. Snapshot the entire input vector BEFORE checking rows, matching
 * the unconditional native2 vector loads; rows0 still reads input but
 * does not read weights/output/bias. Each row starts a fresh ACCX=0, sums
 * signed8 products and exposes the low32-bit result. Even the80-lane bound
 * is only1,310,720 in magnitude, so native40-bit ACCX saturation is unreachable.
 * Input is reused from its snapshot; weights are consumed freshly per row,
 * preserving earlier-output/later-weight alias effects. No row-count cap,
 * allocation, NULL check, rescaling, activation, lock or status is supplied.
 *
 * For each row read old output WORD then bias WORD, and publish
 * (old_output<<8)+bias+dot modulo32. This is not a saturated32-bit add.
 * Bias/output may alias; both reads precede that row's output store.
 * The native implementation uses16-byte vector loads and requires aligned
 * readable vectors/weights and aligned WORD outputs/bias. This readable
 * scalar reconstruction assumes ordinary serialized RAM and represents the
 * numerical/memory algorithm; it does not emulate vector-register clobbers,
 * invalid-address faults,128-bit bus transactions or execution timing.
 */
void medius_motion_accumulate_s8_32(const volatile MediusMotionS8Vector32 *weights,
    const volatile MediusMotionS8Vector32 *input,volatile unsigned int *output,unsigned int rows,
    const volatile unsigned int *bias)
{
    signed char snapshot[32];
    for (unsigned int lane = 0;lane < 32U;++lane) snapshot[lane] = input->lanes[lane];
    for (unsigned int row = 0;row < rows;++row) {
        int dot = 0;
        for (unsigned int lane = 0;lane < 32U;++lane)
            dot += (int)weights[row].lanes[lane]*(int)snapshot[lane];
        unsigned int previous = output[row];
        unsigned int correction = bias[row];
        output[row] = (previous<<8)+correction+(unsigned int)dot;
    }
}
