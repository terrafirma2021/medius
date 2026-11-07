/* Medius v3.4.7 host — app/motion_completion.c.
 */

#include "../include/types.h"

/* Source reconstruction utilities; not additional native firmware entries. */
static unsigned int motion_completion_clamp(long long value)
{
    if(value < -0x20000000LL)return 0xe0000000U;
    if(value > 0x20000000LL)return 0x20000000U;
    return (unsigned int)value;
}
static unsigned int motion_output_clamp(long long value)
{
    if(value < -0x40000000LL)return 0xc0000000U;
    if(value > 0x40000000LL)return 0x40000000U;
    return (unsigned int)value;
}
/* step is a sign-extended native16 value. Each balance is read only once. */
static void motion_consume_axis(volatile unsigned int *input_balance,
    volatile unsigned int *command_balance,int step)
{
    unsigned int command=*command_balance;
    unsigned int input=*input_balance;
    unsigned int remaining=(unsigned int)step;
    if((int)remaining>0&&(int)input>0){
        unsigned int take=(int)remaining<(int)input?remaining:input;
        input-=take;remaining-=take;
    }else if((int)remaining<0&&(int)input<0){
        unsigned int take=(int)remaining>(int)input?remaining:input;
        input-=take;remaining-=take;
    }
    if(!remaining){
        *command_balance=command;
    }else if((int)remaining>0&&(int)command>0){
        unsigned int take=(int)remaining<(int)command?remaining:command;
        command-=take;remaining-=take;
        *command_balance=command;
    }else if((int)remaining<0&&(int)command<0){
        unsigned int take=(int)remaining>(int)command?remaining:command;
        command-=take;remaining-=take;
        *command_balance=command;
    }
    input=motion_completion_clamp((long long)(int)input-(int)remaining);
    *input_balance=input;
    if((int)input>0&&(int)command<0){
        unsigned int magnitude=0U-command;
        unsigned int amount=(int)magnitude<(int)input?magnitude:input;
        *input_balance=input-amount;
        *command_balance=command+amount;
    }else if((int)input<0&&(int)command>0){
        unsigned int magnitude=0U-input;
        unsigned int amount=(int)magnitude<(int)command?magnitude:command;
        *input_balance=input+amount;
        *command_balance=command-amount;
    }
}

/* Native entry: 0x4038b594. */
/*
 * Medius v3.4.7 — host application; 0x4038b594.
 * Instruction-checked recovered C.
 * Original function-byte SHA-256:
 * a8429645b7975670625ab350509c95063d1dbb8671e3ff95bf60cdda37e9c1bd.
 */

/*
 * Consume a rendered signed16 X/Y step only when expected_generation matches
 * the single MEMW-ordered engine generation sample. Hold the engine lock for
 * the comparison and both axis updates. A mismatch unlocks and returns false
 * without reading or writing balances. Acquisition status is ignored.
 *
 * For each axis (X before Y), read command then input balance once. Consume
 * same-signed input first, then same-signed command; subtract any residual
 * step from input with signed64 saturation to[-0x20000000,0x20000000]. Publish
 * command before input when command was consumed or the residual entering
 * command consumption was zero (including a zero step). Then cancel opposite
 * signs, storing adjusted input before adjusted command. Magnitude negation
 * and updates wrap to32 bits, including corrupted INT_MIN balance storage.
 * Even a zero step can clamp input and cancel opposing balances. Command is
 * not independently clamped. Staged balances, accumulators, generation and
 * task state remain unchanged. Unlock and return the cached comparison result;
 * no notification or output routing is performed here.
 */
bool medius_motion_consume_output(unsigned int expected_generation,short x,short y)
{
    xPortEnterCriticalTimeout(&MEDIUS_MOTION_ENGINE_LOCK,-1);
    memw();unsigned int generation=MEDIUS_MOTION_ENGINE->generation;
    bool current=generation==expected_generation;
    if(current){
        motion_consume_axis(&MEDIUS_MOTION_ENGINE->active.input_x,
            &MEDIUS_MOTION_ENGINE->active.command_x,x);
        motion_consume_axis(&MEDIUS_MOTION_ENGINE->active.input_y,
            &MEDIUS_MOTION_ENGINE->active.command_y,y);
    }
    vPortExitCritical(&MEDIUS_MOTION_ENGINE_LOCK);
    return current;
}

/* Native entry: 0x4038927c. */
/*
 * Medius v3.4.7 — host application; 0x4038927c.
 * Instruction-checked recovered C.
 * Original function-byte SHA-256:
 * 0738f80e4c0963f955d932ae66c6431a82638941177823f1f9617de51ccb2dad.
 */

/*
 * Complete a rendered signed16 X/Y step under the pending lock. Nest the engine
 * lock through consume_output; a generation mismatch skips routing. A match
 * consumes balances first, then samples the16-bit interpolation policy. Zero
 * policy selects pending axes without querying program readiness. Otherwise,
 * input_program_ready's raw nonzero result selects pending axes; zero selects
 * interpolated axes. The policy and readiness are sampled after consumption.
 *
 * Add the original step to the chosen signed32 X/Y totals, saturating each
 * signed64 sum to[-0x40000000,0x40000000]. Read Y before publishing X, then
 * publish Y. Unlock on every path. Critical acquisition statuses are ignored.
 * No retry, completion notification, UART send or value return is provided;
 * the generation can change again after the successful inner comparison.
 */
void medius_motion_complete_output(short x,short y,unsigned int generation)
{
    xPortEnterCriticalTimeout(&MEDIUS_MOTION_PENDING_LOCK,-1);
    if(medius_motion_consume_output(generation,x,y)){
        unsigned short interpolation=MEDIUS_MOTION_INTERPOLATION_POLICY;
        volatile unsigned int *axes=MEDIUS_MOTION_PENDING_AXES;
        if(interpolation&&!medius_motion_input_program_ready())
            axes=MEDIUS_MOTION_INTERPOLATED_AXES;
        unsigned int old_x=axes[0];
        unsigned int next_x=motion_output_clamp((long long)(int)old_x+x);
        unsigned int old_y=axes[1];
        long long sum_y=(long long)(int)old_y+y;
        axes[0]=next_x;
        axes[1]=motion_output_clamp(sum_y);
    }
    vPortExitCritical(&MEDIUS_MOTION_PENDING_LOCK);
}

/* Native entry: 0x4038b9c0. */
/*
 * Medius v3.4.7 — host application; 0x4038b9c0.
 * Instruction-checked recovered C.
 * Original function-byte SHA-256:
 * f1139532f534da2d55c23124feccd63d5df089527a29d01e1cd596905be81d4c.
 */

/*
 * Drain the rendered-output ring until separately fenced read/write cursor
 * samples agree. Initial reads are read_index then write_index. For each item,
 * MEMW/sample the current callback, then MEMW/sample the current read index,
 * even if the callback is NULL. A nonNULL callback receives generation32,
 * signed Y16 and signed X16 sampled in that order, passed as (X,Y,generation).
 * Slot addressing uses index*8 plus3fcb98e0 modulo32 with no bounds repair.
 * A NULL callback discards the item without reading its record.
 *
 * After the callback, two MEMWs precede a fresh read_index sample. Compute
 * (sample+1)&7, then MEMW/publish it. Recompare fresh read and write samples,
 * each preceded by MEMW, and repeat if unequal. Callback changes to the cursor
 * therefore affect advancement; the record index is not reused for it.
 * No lock, reentrancy guard, item limit, yield or timeout is supplied. Requires
 * an externally serialized consumer and valid ring/callback lifetime. Producer
 * activity can keep the loop running indefinitely. No value is returned.
 */
void medius_motion_drain_output(void)
{
    memw();unsigned int read_index=MEDIUS_MOTION_OUTPUT_READ;
    memw();unsigned int write_index=MEDIUS_MOTION_OUTPUT_WRITE;
    if(read_index==write_index)return;
    do{
        memw();MediusMotionOutputHandler handler=MEDIUS_MOTION_OUTPUT_HANDLER;
        memw();unsigned int record_index=MEDIUS_MOTION_OUTPUT_READ;
        if(handler){
            unsigned int address=0x3fcb98e0U+record_index*8U;
            volatile MediusMotionOutputRecord *record=(volatile MediusMotionOutputRecord *)address;
            unsigned int generation=record->generation;
            short y=record->y;
            short x=record->x;
            handler(x,y,generation);
        }
        memw();memw();
        unsigned int current_read=MEDIUS_MOTION_OUTPUT_READ;
        unsigned int next=(current_read+1U)&7U;
        memw();MEDIUS_MOTION_OUTPUT_READ=next;
        memw();read_index=MEDIUS_MOTION_OUTPUT_READ;
        memw();write_index=MEDIUS_MOTION_OUTPUT_WRITE;
    }while(read_index!=write_index);
}

/* Native entry: 0x4038904c. */
/*
 * Medius v3.4.7 — host application; 0x4038904c.
 * Instruction-checked recovered C.
 * Original function-byte SHA-256:
 * a450c5e952b77dfaf74cdab8c6bd275571468a4418b34cef370eb19942c47b93.
 */

/*
 * Restore four signed16 little-endian deltas at metadata offsets16,18,20,22
 * to the four pending motion axes under the pending lock. metadata must provide
 * 24 readable bytes; alignment is unrestricted. Each delta reads its high byte
 * before its low byte, then samples the corresponding signed32 accumulator.
 * Add in signed64 arithmetic and saturate to[-0x40000000,0x40000000], storing
 * each result before reading the next metadata pair. An input alias into the
 * pending storage can therefore observe earlier stores; no entry copy is made.
 * The first16 bytes are not read. Lock acquisition status is ignored. No MEMW,
 * zeroing, interpolation update, notification, retry or value return occurs.
 */
void medius_motion_delta_restore(const unsigned char *metadata)
{
    const volatile unsigned char *bytes=metadata;
    xPortEnterCriticalTimeout(&MEDIUS_MOTION_PENDING_LOCK,-1);
    for(unsigned int axis=0;axis<4;++axis){
        unsigned int high=bytes[17+2*axis];
        unsigned int low=bytes[16+2*axis];
        short delta=(short)((high<<8)|low);
        unsigned int pending=MEDIUS_MOTION_PENDING_AXES[axis];
        MEDIUS_MOTION_PENDING_AXES[axis]=motion_output_clamp((long long)(int)pending+delta);
    }
    vPortExitCritical(&MEDIUS_MOTION_PENDING_LOCK);
}
