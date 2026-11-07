/* Device MOVE commands: cursor, vertical wheel and horizontal pan. */
#include "../include/types.h"

/* Native entry: 0x4203606c. */
/* Original function-byte SHA-256:
 * aed8147865183933070f37a0cb400e82e913a1dcc7238011993da9f5d4429dbc. */
/*
 * MOVE selector0. Sign-extend dx/dy from16 bits; retain flags LOW8. Fence/set
 * injection-pending BYTE even for zero movement. If either axis is nonzero,
 * obtain clock LOW32, then fence/store the recent-mouse timestamp WORD.
 * Fence/read render-state BYTE exactly once. Bit0 clear calls local processing
 * with signed x/y, wheel0,pan0 and flags, without reading the clock callback.
 * Bit0 set samples the registered clock pointer once; call it if non-NULL,
 * otherwise use a NEW esp_timer clock LOW32. Queue signed x/y, wheel0,pan0,
 * flags and that stamp as six native WORDs. This clock read still happens for
 * zero movement. No lock, mode/pointer stability check, flag interpretation,
 * return status or delivery guarantee is supplied by this wrapper.
 */
void move_cursor(short dx,short dy,unsigned char flags)
{
    memw();
    MOTION_INJECTION_PENDING = 1;
    if (dx != 0 || dy != 0) {
        unsigned int stamp = (unsigned int)esp_timer_get_time();
        memw();
        QUERY_MOTION_RECENT_TIME = stamp;
    }
    memw();
    unsigned char render = MOTION_RENDER_STATE;
    if ((render & 1U) == 0) {
        input_process_local_motion(dx,dy,0,0,flags);
    } else {
        ReceiveTimestampReader clock = INPUT_RECEIVE_TIMESTAMP_READER;
        unsigned int stamp = clock != 0 ? clock() : (unsigned int)esp_timer_get_time();
        input_queue_motion(dx,dy,0,0,flags,stamp);
    }
}

/* Native entry: 0x420360e4. */
/* Original function-byte SHA-256:
 * 2f8f0e5d36c9a7fff71b6ce158b49e297da5d4d7d5421d21562b8aeb6b676927. */
/*
 * MOVE selector1: signed16 vertical wheel delta, flags LOW8. Fence/set pending
 * even for delta0. A nonzero delta gets clock LOW32 then fence/publishes recent
 * mouse WORD. Fence/read render BYTE once. Bit0 clear calls local processing
 * with x0,y0,wheel=delta,pan0,flags. Bit0 set samples one callback pointer,
 * obtains its WORD stamp or a fresh esp_timer LOW32, and queues those four axes,
 * flags and stamp. Zero delta still follows the render branch and its clock.
 * No lock, flag filtering, result or guaranteed USB delivery here.
 */
void move_wheel(short delta,unsigned char flags)
{
    memw();
    MOTION_INJECTION_PENDING = 1;
    if (delta != 0) {
        unsigned int stamp = (unsigned int)esp_timer_get_time();
        memw();
        QUERY_MOTION_RECENT_TIME = stamp;
    }
    memw();
    unsigned char render = MOTION_RENDER_STATE;
    if ((render & 1U) == 0) {
        input_process_local_motion(0,0,delta,0,flags);
    } else {
        ReceiveTimestampReader clock = INPUT_RECEIVE_TIMESTAMP_READER;
        unsigned int stamp = clock != 0 ? clock() : (unsigned int)esp_timer_get_time();
        input_queue_motion(0,0,delta,0,flags,stamp);
    }
}

/* Native entry: 0x42036154. */
/* Original function-byte SHA-256:
 * becbfa4015b55ab9f7b8450e8dedbe938cb9a8767abc2b310afc202d85554b76. */
/*
 * MOVE selector2: signed16 horizontal pan delta, flags LOW8. Fence/set pending
 * for every call; nonzero delta samples clock LOW32 then fence/stores recent
 * mouse WORD. Fence/read render BYTE once. Bit0 clear calls local processing
 * with x0,y0,wheel0,pan=delta,flags. Bit0 set caches the clock pointer and uses
 * its WORD return or fresh esp_timer LOW32, then queues the axes/flags/stamp as
 * six WORDs. A zero delta skips only the recent-time update, not the routing
 * or rendered clock. No lock, validation, status or delivery guarantee here.
 */
void move_pan(short delta,unsigned char flags)
{
    memw();
    MOTION_INJECTION_PENDING = 1;
    if (delta != 0) {
        unsigned int stamp = (unsigned int)esp_timer_get_time();
        memw();
        QUERY_MOTION_RECENT_TIME = stamp;
    }
    memw();
    unsigned char render = MOTION_RENDER_STATE;
    if ((render & 1U) == 0) {
        input_process_local_motion(0,0,0,delta,flags);
    } else {
        ReceiveTimestampReader clock = INPUT_RECEIVE_TIMESTAMP_READER;
        unsigned int stamp = clock != 0 ? clock() : (unsigned int)esp_timer_get_time();
        input_queue_motion(0,0,0,delta,flags,stamp);
    }
}
