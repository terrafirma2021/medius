/* Medius v3.4.7 host — app/motion_admission.c.
 */

#include "../include/types.h"

/* Source reconstruction utilities; not additional native firmware entries. */
static unsigned int motion_accumulator_clamp(long long value)
{
    if(value < -0x20000000LL)return 0xe0000000U;
    if(value > 0x20000000LL)return 0x20000000U;
    return (unsigned int)value;
}
static unsigned int motion_signed_min(unsigned int first,unsigned int second)
{
    return (int)first<(int)second?first:second;
}

/* Native entry: 0x4038b2a8. */
/*
 * Medius v3.4.7 — host application; 0x4038b2a8.
 * Instruction-checked recovered C.
 * Original function-byte SHA-256:
 * d5995fa0aff8d2a60fcc52596cfe2b2f328bd61a4be815f1db3d5c8aeeeab640.
 */

/*
 * Add signed32 X/Y motion to the engine's accounting. Caller must serialize
 * access (the reviewed command/input wrappers hold the engine lock). There is
 * no local lock, MEMW, task wake or return value. source_class0 selects command
 * balances; every nonzero class selects input balances. unused_slot is never
 * read; it occupies the fourth native ABI slot before the split64 timestamp.
 *
 * Command class with nonzero duration_us selects timed accumulators X/Y at
 * 3fcba164/160. All other inputs select immediate X/Y at3fcba16c/168. Only a
 * nonzero X/Y request on the timed path touches timestamps: read deadline LOW
 * then HIGH, seed start LOW/HIGH if that pair is zero, and publish
 * (now_high:now_low)+duration_us modulo64, LOW then HIGH. A deadline is extended
 * even if the corresponding accumulator is saturated and admits no new motion.
 *
 * Clamp signed accumulator sums to[-0x20000000,0x20000000]. Sample both old
 * axes before storing X then Y. The actual admitted increments are new-old
 * modulo32, interpreted signed before adding them to the selected active
 * input/command balances and applying the same clamp. Opposite-signed active
 * contributions cancel by a signed minimum of magnitudes. All negation and
 * balance updates preserve native32 wrap, including corrupted INT_MIN storage.
 *
 * Native access order matters: input X is sampled before the class branch.
 * Input-class updates read the opposing command axis only when their new
 * input balance is nonzero. Command-class updates always use the cached input
 * X and sample input Y before storing command Y. Each selected balance is
 * stored before cancellation; cancellation stores input before command.
 * Staged balances, generation, busy and policy fields are left unchanged.
 */
void medius_motion_accumulate(int x,int y,unsigned int source_class,
    unsigned int unused_slot,unsigned int now_low,unsigned int now_high,
    unsigned int duration_us)
{
    (void)unused_slot;
    volatile MediusMotionEngineState *engine=MEDIUS_MOTION_ENGINE;
    volatile unsigned int *accumulator_x,*accumulator_y;
    if(duration_us&&source_class==0){
        if((unsigned int)x|(unsigned int)y){
            unsigned int deadline_low=engine->timed_until_us.low;
            unsigned int deadline_high=engine->timed_until_us.high;
            if(!(deadline_low|deadline_high)){
                engine->timed_started_us.low=now_low;
                engine->timed_started_us.high=now_high;
            }
            unsigned int until_low=now_low+duration_us;
            unsigned int until_high=now_high+(until_low<duration_us);
            engine->timed_until_us.low=until_low;
            engine->timed_until_us.high=until_high;
        }
        accumulator_x=&engine->timed_x;accumulator_y=&engine->timed_y;
    }else{
        accumulator_x=&engine->immediate_x;accumulator_y=&engine->immediate_y;
    }
    unsigned int old_x=*accumulator_x;
    unsigned int next_x=motion_accumulator_clamp((long long)(int)old_x+x);
    unsigned int old_y=*accumulator_y;
    long long sum_y=(long long)(int)old_y+y;
    *accumulator_x=next_x;
    unsigned int next_y=motion_accumulator_clamp(sum_y);
    unsigned int admitted_x=next_x-old_x;
    *accumulator_y=next_y;
    unsigned int input_x=engine->active.input_x;
    if(source_class){
        input_x=motion_accumulator_clamp((long long)(int)input_x+(int)admitted_x);
        engine->active.input_x=input_x;
        if((int)input_x>0){
            unsigned int command_x=engine->active.command_x;
            if((int)command_x<0){
                unsigned int amount=motion_signed_min(0U-command_x,input_x);
                engine->active.input_x=input_x-amount;
                engine->active.command_x=command_x+amount;
            }
        }else if((int)input_x<0){
            unsigned int command_x=engine->active.command_x;
            if((int)command_x>0){
                unsigned int amount=motion_signed_min(0U-input_x,command_x);
                engine->active.input_x=input_x+amount;
                engine->active.command_x=command_x-amount;
            }
        }
        unsigned int input_y=engine->active.input_y;
        unsigned int admitted_y=next_y-old_y;
        input_y=motion_accumulator_clamp((long long)(int)input_y+(int)admitted_y);
        engine->active.input_y=input_y;
        if((int)input_y>0){
            unsigned int command_y=engine->active.command_y;
            if((int)command_y<0){
                unsigned int amount=motion_signed_min(0U-command_y,input_y);
                engine->active.input_y=input_y-amount;
                engine->active.command_y=command_y+amount;
            }
        }else if((int)input_y<0){
            unsigned int command_y=engine->active.command_y;
            if((int)command_y>0){
                unsigned int amount=motion_signed_min(0U-input_y,command_y);
                engine->active.input_y=input_y+amount;
                engine->active.command_y=command_y-amount;
            }
        }
    }else{
        unsigned int command_x=engine->active.command_x;
        command_x=motion_accumulator_clamp((long long)(int)command_x+(int)admitted_x);
        engine->active.command_x=command_x;
        if((int)input_x>0&&(int)command_x<0){
            unsigned int amount=motion_signed_min(0U-command_x,input_x);
            engine->active.input_x=input_x-amount;
            engine->active.command_x=command_x+amount;
        }else if((int)input_x<0&&(int)command_x>0){
            unsigned int amount=motion_signed_min(0U-input_x,command_x);
            engine->active.input_x=input_x+amount;
            engine->active.command_x=command_x-amount;
        }
        unsigned int command_y=engine->active.command_y;
        unsigned int admitted_y=next_y-old_y;
        command_y=motion_accumulator_clamp((long long)(int)command_y+(int)admitted_y);
        unsigned int input_y=engine->active.input_y;
        engine->active.command_y=command_y;
        if((int)input_y>0&&(int)command_y<0){
            unsigned int amount=motion_signed_min(0U-command_y,input_y);
            engine->active.input_y=input_y-amount;
            engine->active.command_y=command_y+amount;
        }else if((int)input_y<0&&(int)command_y>0){
            unsigned int amount=motion_signed_min(0U-input_y,command_y);
            engine->active.input_y=input_y+amount;
            engine->active.command_y=command_y-amount;
        }
    }
}

/* Native entry: 0x4038ba90. */
/*
 * Medius v3.4.7 — host application; 0x4038ba90.
 * Instruction-checked recovered C.
 * Original function-byte SHA-256:
 * 075dd3bfc006e83fc769541452b7f184fafa41511b54ed0e65743e61113636ea.
 */

/*
 * Submit signed16 input X/Y to immediate motion accounting when enabled,
 * input_enabled, program-ready and !reset_requested pass in that order.
 * Each gate is a fresh MEMW-ordered raw byte read under the engine lock.
 * A failed gate unlocks and returns0. On success, accumulate input class1
 * with zero timestamp/duration, unlock, then sample worker once and notify
 * index0/value0/action2 if nonNULL. Return the sampled raw program-ready byte,
 * even if policy/readiness changes during accumulation or notification.
 * Lock/notification statuses are ignored. No wait for motion output is given.
 */
unsigned char medius_motion_submit_input(short x,short y)
{
    volatile MediusMotionEngineState *engine=MEDIUS_MOTION_ENGINE;
    xPortEnterCriticalTimeout(&MEDIUS_MOTION_ENGINE_LOCK,-1);
    memw();unsigned char enabled=engine->enabled;
    if(!enabled){vPortExitCritical(&MEDIUS_MOTION_ENGINE_LOCK);return 0;}
    memw();unsigned char input_enabled=engine->input_enabled;
    if(!input_enabled){vPortExitCritical(&MEDIUS_MOTION_ENGINE_LOCK);return 0;}
    memw();unsigned char ready=MEDIUS_MOTION_PROGRAM_READY;
    if(!ready){vPortExitCritical(&MEDIUS_MOTION_ENGINE_LOCK);return 0;}
    memw();unsigned char resetting=engine->reset_requested;
    if(resetting){vPortExitCritical(&MEDIUS_MOTION_ENGINE_LOCK);return 0;}
    medius_motion_accumulate(x,y,1,0,0,0,0);
    vPortExitCritical(&MEDIUS_MOTION_ENGINE_LOCK);
    RtosTask *worker=engine->worker;
    if(worker)xTaskGenericNotify(worker,0,0,2,NULL);
    return ready;
}

/* Native entry: 0x42032300. */
/*
 * Medius v3.4.7 — host application; 0x42032300.
 * Instruction-checked recovered C.
 * Original function-byte SHA-256:
 * 68511181cafa52c142033df77659c2a06d02241c2b25526686c676361262d262.
 */

/*
 * Submit signed16 command X/Y with a split64 timestamp and unsigned32 duration
 * in microseconds. All five native arguments are significant: the raw export
 * omitted the final three from this signature. Under the engine lock, test
 * enabled, program-ready, then !reset_requested with fresh MEMW-ordered byte
 * reads, short-circuiting to unlock/return0 at the first failed gate.
 * input_enabled is not tested. On success, accumulate command class0 using
 * now_low,now_high,duration_us, unlock, sample worker once and optionally notify
 * index0/value0/action2. Return the cached raw program-ready byte. Lock and
 * notification results are ignored; no output completion or time validation.
 */
unsigned char medius_motion_submit_command(short x,short y,unsigned int now_low,
    unsigned int now_high,unsigned int duration_us)
{
    volatile MediusMotionEngineState *engine=MEDIUS_MOTION_ENGINE;
    xPortEnterCriticalTimeout(&MEDIUS_MOTION_ENGINE_LOCK,-1);
    memw();unsigned char enabled=engine->enabled;
    if(!enabled){vPortExitCritical(&MEDIUS_MOTION_ENGINE_LOCK);return 0;}
    memw();unsigned char ready=MEDIUS_MOTION_PROGRAM_READY;
    if(!ready){vPortExitCritical(&MEDIUS_MOTION_ENGINE_LOCK);return 0;}
    memw();unsigned char resetting=engine->reset_requested;
    if(resetting){vPortExitCritical(&MEDIUS_MOTION_ENGINE_LOCK);return 0;}
    medius_motion_accumulate(x,y,0,0,now_low,now_high,duration_us);
    vPortExitCritical(&MEDIUS_MOTION_ENGINE_LOCK);
    RtosTask *worker=engine->worker;
    if(worker)xTaskGenericNotify(worker,0,0,2,NULL);
    return ready;
}
