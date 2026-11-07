/* Medius v3.4.7 host — app/motion_program.c.
 */

#include "../include/types.h"

/* Source reconstruction utilities; not additional native firmware entries. */
static short motion_sample_clamp(int value)
{
    if(value < -32768)return -32768;
    if(value > 32767)return 32767;
    return (short)value;
}

/* Native entry: 0x420325a8. */
/*
 * Medius v3.4.7 — host application; 0x420325a8.
 * Instruction-checked recovered C.
 * Original function-byte SHA-256:
 * 0e2e10851477db204262df8095aacc6dc5b8c3f3869c3afe3613db2ca5e18ec5.
 */

/*
 * Publish the output callback before loading the embedded44,484-byte ABCFIX1
 * configuration at3c045e28. A nonzero loader status returns false immediately;
 * the callback publication is retained. On success, prepare decoded config
 * tables, reset the4672-byte processing state (ignoring reset status), clear
 * the window count/tail flag, and initialize the input batcher callback/state
 * with the native8/16/32-bit stores. Padding bytes are not blanket-cleared.
 * Clear the256-byte render filter through filter_reset, then create a counting
 * semaphore with capacity4,count0 and publish its handle, including NULL.
 * A NULL handle returns false without creating a task. Otherwise request
 * render:8192-byte stack, NULL argument, priority6, CPU1, publishing the task
 * handle through the native output slot. Return true only for status1.
 * No repeat guard, rollback, resource cleanup, lock or MEMW is supplied here.
 * Worker/filter/config lifetimes and task execution belong to their callees.
 */
bool medius_motion_start_renderer(MediusMotionOutputHandler output)
{
    MEDIUS_MOTION_OUTPUT_HANDLER=output;
    int status=medius_motion_config_load(MEDIUS_MOTION_CONFIG,
        MEDIUS_MOTION_EMBEDDED_CONFIG,44484);
    if(status)return false;
    medius_motion_config_prepare(&MEDIUS_MOTION_CONFIG->decoded);
    medius_motion_processing_reset(MEDIUS_MOTION_BUILD_STATE,MEDIUS_MOTION_CONFIG);
    MEDIUS_MOTION_WINDOW->samples=0;
    MEDIUS_MOTION_WINDOW->late_nonzero=0;
    volatile MediusMotionInputBatcher *batcher=MEDIUS_MOTION_BATCHER;
    batcher->callback=medius_motion_collect_sample;
    batcher->context=0;
    batcher->deadline_us=0;
    batcher->sum_x=0;batcher->sum_y=0;
    batcher->started=0;
    batcher->gap_samples=0;
    batcher->pending.word=0;
    batcher->pending_y=0;
    batcher->pending_stamp_us=0;
    medius_motion_filter_reset(MEDIUS_MOTION_RENDER_FILTER);
    RtosQueue *semaphore=medius_motion_create_counting_semaphore(4,0);
    MEDIUS_MOTION_ENGINE->wake_semaphore=semaphore;
    if(!semaphore)return false;
    status=xTaskCreatePinnedToCore(medius_motion_render_worker,"render",8192,
        NULL,6,(RtosTask **)&MEDIUS_MOTION_ENGINE->worker,1);
    return status==1;
}

/* Native entry: 0x40376f10. */
/*
 * Medius v3.4.7 — host application; 0x40376f10.
 * Instruction-checked recovered C.
 * Original function-byte SHA-256:
 * 69da10013d69cf746bc3582fec7de5c0756a3ea82645b27b0382259c0b1e538a.
 */

/*
 * Collect one signed16 X/Y sample; unused_context is the batcher's native
 * callback context and is not read. Increment the shared callback counter
 * modulo32 before any processing. Sample the16-bit window count once for
 * admission. Counts0..254 process a sample; on status0, resample the count,
 * mark late_nonzero when X/Y is nonzero and that fresh count>195, then store
 * fresh_count+1 modulo16. A processing failure leaves those fields untouched.
 *
 * Counts>=255 close the window. A nonzero X/Y or sampled late_nonzero admits
 * closing only if low16(old_count+1)>255; count65535 therefore skips it. Busy
 * is sampled after MEMW. If busy, copy4672 bytes to deferred state, store X,
 * then Y, then MEMW/publish deferred_ready=1. If idle, process the closing
 * sample; only status0 clears deferred_ready, copies4672 bytes to published
 * state and MEMW/sets program-ready. Every closing-window path then resets
 * the builder (ignoring status), count and late_nonzero, even if skipped or
 * failed. No lock, allocation, notification, retry or return value occurs.
 */
void medius_motion_collect_sample(unsigned int unused_context,short x,short y)
{
    (void)unused_context;
    unsigned int callbacks=MEDIUS_MOTION_CALLBACK_COUNT;
    unsigned short samples=MEDIUS_MOTION_WINDOW->samples;
    MEDIUS_MOTION_CALLBACK_COUNT=callbacks+1U;
    unsigned int next=(unsigned int)samples+1U;
    if(next<=255){
        if(medius_motion_process_sample(MEDIUS_MOTION_BUILD_STATE,x,y)==0){
            unsigned short current=MEDIUS_MOTION_WINDOW->samples;
            if((x||y)&&current>195)MEDIUS_MOTION_WINDOW->late_nonzero=1;
            MEDIUS_MOTION_WINDOW->samples=(unsigned short)(current+1U);
        }
        return;
    }
    unsigned char close=(x||y)!=0;
    if(!close)close=MEDIUS_MOTION_WINDOW->late_nonzero!=0;
    if(close&&(unsigned short)next>255){
        memw();unsigned char busy=MEDIUS_MOTION_ENGINE->busy;
        if(busy){
            memcpy(MEDIUS_MOTION_DEFERRED_STATE,MEDIUS_MOTION_BUILD_STATE,4672);
            MEDIUS_MOTION_DEFERRED_X=x;
            MEDIUS_MOTION_DEFERRED_Y=y;
            memw();MEDIUS_MOTION_DEFERRED_READY=1;
        }else if(medius_motion_process_sample(MEDIUS_MOTION_BUILD_STATE,x,y)==0){
            MEDIUS_MOTION_DEFERRED_READY=0;
            memcpy(MEDIUS_MOTION_PUBLISHED_STATE,MEDIUS_MOTION_BUILD_STATE,4672);
            memw();MEDIUS_MOTION_PROGRAM_READY=1;
        }
    }
    medius_motion_processing_reset(MEDIUS_MOTION_BUILD_STATE,MEDIUS_MOTION_CONFIG);
    MEDIUS_MOTION_WINDOW->samples=0;
    MEDIUS_MOTION_WINDOW->late_nonzero=0;
}

/* Native entry: 0x40376ff4. */
/*
 * Medius v3.4.7 — host application; 0x40376ff4.
 * Instruction-checked recovered C.
 * Original function-byte SHA-256:
 * 411d29f9f38a8786281f432805d4cb90d976f120d77b47d867db61cb39fc3dc4.
 */

/*
 * Process timestamped input records into nominal1ms samples. Reset the callback
 * counter on entry; at most256 records are popped. Gap callbacks are limited
 * per pass by256 minus the callback-count snapshot from the previous loop tail
 * (zero initially), then the shared counter is resampled; >255 returns. A
 * callback that does not advance that counter can cause additional gap passes.
 * No task delay, wall-clock wait, lock or callback-NULL guard is supplied.
 *
 * Gap work calls the current callback/context with X=Y=0, then rereads and
 * decrements gap_samples modulo16 and advances the fresh deadline by1000.
 * When gaps finish, pending input becomes the new sums; uncapped gaps advance
 * from the sampled deadline by2000, capped gaps use pending_stamp+1000.
 *
 * Input-ring comparison and two distinct read-index samples are MEMW ordered.
 * Read X/Y16 and gap_samples before publishing the incremented current cursor;
 * read the record stamp afterward. Addressing trusts the original raw index
 * and wraps to32 bits. If gaps appeared during those reads, saturating16 adds
 * merge X/Y into the pending record; this native path was lost by Ghidra.
 *
 * First input seeds deadline=stamp+1000 and sums. Earlier signed-wrapped stamps
 * add to sums modulo32. Otherwise emit the old sums saturated to signed16,
 * then reread deadline after the callback. A wrapped signed delta<1000 seeds
 * the next sample immediately. Larger gaps schedule up to64 zero samples and
 * defer X/Y/stamp; count64 is marked capped, even if exactly64 were needed.
 * Callback, context, counters and timestamps are independent native snapshots.
 * No physical1ms execution guarantee, time validation or completion result.
 */
void medius_motion_process_input(void)
{
    volatile MediusMotionInputBatcher *batcher=MEDIUS_MOTION_BATCHER;
    MEDIUS_MOTION_CALLBACK_COUNT=0;
    unsigned int records_left=256,callbacks_snapshot=0;
    for(;;){
        unsigned short gaps=batcher->gap_samples;
        if(gaps){
            unsigned int budget=256U-callbacks_snapshot,emitted=0;
            do{
                MediusMotionSampleHandler callback=batcher->callback;
                unsigned int context=batcher->context;
                callback(context,0,0);
                unsigned short remaining=(unsigned short)(batcher->gap_samples-1U);
                unsigned int deadline=batcher->deadline_us;
                batcher->deadline_us=deadline+1000U;
                batcher->gap_samples=remaining;
                ++emitted;
                if(!remaining){
                    unsigned char pending=batcher->pending.present;
                    if(pending){
                        unsigned char capped=batcher->pending.capped;
                        unsigned int next=capped?batcher->pending_stamp_us+1000U:deadline+2000U;
                        short pending_y=batcher->pending_y;
                        short pending_x=batcher->pending.x;
                        batcher->sum_y=(unsigned int)(int)pending_y;
                        batcher->deadline_us=next;
                        batcher->sum_x=(unsigned int)(int)pending_x;
                        batcher->pending.flags=0;
                    }
                    break;
                }
            }while(emitted!=budget);
        }else{
            if(!records_left)return;
            memw();unsigned int read_index=MEDIUS_MOTION_INPUT_READ;
            memw();unsigned int write_index=MEDIUS_MOTION_INPUT_WRITE;
            if(read_index==write_index)return;
            memw();memw();
            unsigned int record_index=MEDIUS_MOTION_INPUT_READ;
            memw();unsigned int current_read=MEDIUS_MOTION_INPUT_READ;
            unsigned int address=0x3fcb9928U+record_index*8U;
            volatile MediusMotionInputSample *record=(volatile MediusMotionInputSample *)address;
            unsigned short raw_x=(unsigned short)record->x;
            unsigned short raw_y=(unsigned short)record->y;
            unsigned int next=(current_read+1U)&255U;
            unsigned short observed_gaps=batcher->gap_samples;
            memw();MEDIUS_MOTION_INPUT_READ=next;
            unsigned int stamp=record->stamp;
            int x=(short)raw_x,y=(short)raw_y;
            if(observed_gaps){
                short old_x=batcher->pending.x;
                batcher->pending.x=motion_sample_clamp((int)old_x+x);
                short old_y=batcher->pending_y;
                batcher->pending_y=motion_sample_clamp((int)old_y+y);
            }else{
                unsigned char started=batcher->started;
                if(!started){
                    batcher->started=1;
                    batcher->deadline_us=stamp+1000U;
                    batcher->sum_x=(unsigned int)x;batcher->sum_y=(unsigned int)y;
                }else{
                    unsigned int deadline=batcher->deadline_us;
                    unsigned int sum_x=batcher->sum_x;
                    unsigned int sum_y=batcher->sum_y;
                    if((int)(stamp-deadline)<0){
                        batcher->sum_x=sum_x+(unsigned int)x;
                        batcher->sum_y=sum_y+(unsigned int)y;
                    }else{
                        MediusMotionSampleHandler callback=batcher->callback;
                        unsigned int context=batcher->context;
                        callback(context,motion_sample_clamp((int)sum_x),motion_sample_clamp((int)sum_y));
                        unsigned int fresh_deadline=batcher->deadline_us;
                        unsigned int delta=stamp-fresh_deadline;
                        if((int)delta<=999){
                            batcher->pending.x=(short)raw_x;batcher->pending_y=(short)raw_y;
                            batcher->pending_stamp_us=stamp;
                            batcher->gap_samples=observed_gaps;
                            batcher->deadline_us=fresh_deadline+1000U;
                            batcher->sum_x=(unsigned int)x;batcher->sum_y=(unsigned int)y;
                            batcher->pending.flags=observed_gaps;
                        }else{
                            unsigned int count=observed_gaps;
                            unsigned int remainder=delta-1000U;
                            do{
                                ++count;
                                if(remainder<=999U)break;
                                remainder-=1000U;
                            }while(count!=64);
                            batcher->pending.x=(short)raw_x;batcher->pending_y=(short)raw_y;
                            batcher->pending_stamp_us=stamp;
                            batcher->pending.present=1;
                            batcher->pending.capped=count==64;
                            batcher->gap_samples=(unsigned short)count;
                        }
                    }
                }
            }
            --records_left;
        }
        callbacks_snapshot=MEDIUS_MOTION_CALLBACK_COUNT;
        if(callbacks_snapshot>255)return;
    }
}

/* Native entry: 0x4200e3e4. */
/*
 * Medius v3.4.7 — host application; 0x4200e3e4.
 * Instruction-checked recovered C.
 * Original function-byte SHA-256:
 * 5f37857fa52725d7b77b3bf744f4178a78dd5f488471e1b65894982cac67a633.
 */

/*
 * Clear exactly256 bytes at state when nonNULL. NULL is a no-op. No alignment
 * requirement, lock, status return, allocation or adjacent-state reset is added;
 * a nonNULL pointer must name256 writable bytes suitable for memset.
 */
void medius_motion_filter_reset(void *state)
{
    if(state)memset(state,0,256);
}
