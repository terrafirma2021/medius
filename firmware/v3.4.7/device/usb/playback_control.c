/* Medius v3.4.7 device — playback_control_complete. */
#include "../include/types.h"

/* Native entry: 0x4202c080. */
/* Original function-byte SHA-256:
 * 62fe6063210e85dc0cca6079bf564c8c31d90f55137c2252a9eb9be2809db5ff. */
/*
 * Complete a playback control attempt. Clear waiting BYTE, then sample SETUP
 * request-type BYTE and endpoint BYTE before branching on the full status WORD.
 * Successful OUT requests suppress payload/length; successful IN requests pass
 * the borrowed buffer and low16 length. Increment the success HALFWORD modulo
 * 65536 and submit class11 control capture, with direction_out1 for OUT/0 for IN.
 *
 * Nonzero status increments error HALFWORD, emits no payload with low8 status
 * flags, and only exactly0xfe checks elapsed time. Sample time, then saved start
 * low WORD/high WORD; signed interpretation of wrapping64 elapsed must exceed
 * 249999us. On expiry reload errors, read pending HALFWORD and write cursor WORD,
 * publish read cursor=write cursor WORD, pending0 HALFWORD, then errors+=pending HALFWORD.
 * No time update, MEMW, lock, retry or bounds repair is added. Always invoke the
 * playback queue-start function afterward to try the next queued request.
 * Return no value. Capture storage is shared; execution/timing are not verified.
 */
void playback_control_complete(int status,unsigned char *payload,unsigned int length)
{
    volatile PlaybackControlRequest *request = PLAYBACK_CONTROL_REQUEST;
    request->waiting = 0;
    unsigned char request_type = request->setup[0];
    unsigned int endpoint = request->endpoint;
    unsigned char direction_out = (request_type & 0x80U) == 0;
    if (status == 0) {
        unsigned int successes = PLAYBACK_CONTROL_SUCCESSES;
        if (direction_out != 0) {
            payload = NULL;
            length = 0;
        }
        PLAYBACK_CONTROL_SUCCESSES = (unsigned short)(successes + 1U);
        medius_capture_control_build(11,endpoint,(unsigned char *)request->setup,
            direction_out,0,payload,(unsigned short)length,
            PLAYBACK_CONTROL_CAPTURE_SCRATCH,MEDIUS_PLAYBACK_CONTROL_CAPTURE_OUTPUT);
    } else {
        unsigned int errors = PLAYBACK_CONTROL_ERRORS;
        PLAYBACK_CONTROL_ERRORS = (unsigned short)(errors + 1U);
        medius_capture_control_build(11,endpoint,(unsigned char *)request->setup,
            direction_out,(unsigned char)status,NULL,0,
            PLAYBACK_CONTROL_CAPTURE_SCRATCH,MEDIUS_PLAYBACK_CONTROL_CAPTURE_OUTPUT);
        if (status == 0xfe) {
            unsigned long long now = (unsigned long long)esp_timer_get_time();
            unsigned int start_low = request->started.low;
            unsigned int start_high = request->started.high;
            unsigned long long start = ((unsigned long long)start_high << 32) | start_low;
            unsigned long long elapsed = now - start;
            if (elapsed < 0x8000000000000000ULL && elapsed > 249999ULL) {
                unsigned int current_errors = PLAYBACK_CONTROL_ERRORS;
                unsigned int pending = IMPERFECT_CLIP_QUEUE->pending_count;
                unsigned int write_cursor = IMPERFECT_CLIP_QUEUE->write_cursor;
                IMPERFECT_CLIP_QUEUE->read_cursor = write_cursor;
                IMPERFECT_CLIP_QUEUE->pending_count = 0;
                PLAYBACK_CONTROL_ERRORS = (unsigned short)(current_errors + pending);
            }
        }
    }
    playback_control_try_start();
}
