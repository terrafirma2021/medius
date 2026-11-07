/* Device input-lock status serialization. */
#include "../include/types.h"

/* reconstruction utilities: ordered wire BYTE stores, not native entries.
 * Sample count before each admitted record and reload it after all six stores.
 * Individual keyboard records write usage HIGH before LOW; other records LOW
 * before HIGH. Scratch is sampled only while a wire slot remains available.
 */
static __inline__ __attribute__((always_inline)) unsigned int
input_lock_status_append(volatile unsigned char *output,unsigned int offset,
    unsigned int input_class,unsigned int usage,unsigned int direction,int scale)
{
    if (output[1] >= 85) return offset;
    volatile InputLockWireRecord *record = (volatile void *)(output + offset);
    record->input_class = (unsigned char)input_class;
    record->usage_le[0] = (unsigned char)usage;
    record->usage_le[1] = (unsigned char)(usage >> 8);
    record->direction = (unsigned char)direction;
    record->scale_le[0] = (unsigned char)scale;
    record->scale_le[1] = (unsigned char)((unsigned int)scale >> 8);
    output[1] += 1;
    return (unsigned short)(offset+6U);
}

static __inline__ __attribute__((always_inline)) unsigned int
input_lock_status_append_usage(volatile unsigned char *output,unsigned int offset,
    unsigned char input_class,const unsigned short *usage,
    const unsigned char *direction)
{
    if (output[1] >= 85)
        return offset;
    unsigned int selected_usage = *(const volatile unsigned short *)usage;
    volatile InputLockWireRecord *record = (volatile void *)(output + offset);
    record->input_class = input_class;
    if (direction != NULL) {
        unsigned int selected_direction = *(const volatile unsigned char *)direction;
        record->usage_le[1] = (unsigned char)(selected_usage >> 8);
        record->usage_le[0] = (unsigned char)selected_usage;
        record->direction = (unsigned char)selected_direction;
    } else {
        record->usage_le[0] = (unsigned char)selected_usage;
        record->usage_le[1] = (unsigned char)(selected_usage >> 8);
        record->direction = 0;
    }
    record->scale_le[0] = 0;
    record->scale_le[1] = 0;
    output[1] += 1;
    return (unsigned short)(offset + 6U);
}

/* Native entry: 0x420374c8. */
/* Original function-byte SHA-256:
 * 1d17e4490f2c2aea321730a871fd2e366030dc013c9adab0782d82456baa41a9. */
/*
 * output: private writable 512-byte buffer, disjoint from input state/scratch.
 * Returns 2+6*count bytes, count<=85. No output-capacity argument is provided.
 * Writes selector 6/count 0 BEFORE taking the optional config mutex indefinitely;
 * take status is ignored and release reloads the handle. A missing mutex needs
 * external exclusion. No allocation, input mutation or independent timing.
 *
 * Emit nondefault scales for 20 primary channels/four directions;100 is default.
 * Channels 0..3 use class 3/axisID,4..19 class 0/buttonID(channel-4), direction 1..4.
 * Each scale query is followed by MEMW and a fresh reference-mode BYTE read.
 * Only mode==1,channel 0/1,direction 2/3 queries the paired channel, takes signed
 * minimum, then narrows to signed 16 before comparing against 100. No percentage
 * normalization/clamp is added. Primary output is at most 80 records.
 *
 * Next emit keyboard wildcard flags(bit 0->direction 1,bit 1->direction 2), consumer
 * wildcard(mode nonzero) and at most 8 individual consumer transforms. Finally
 * reread keyboard enable and enumerate its individual transforms with capacity
 * LOW 8(85-count). Usage results use the native nonzeroWORD/LOW 16 LOOP conversion.
 * Every emission checks count<85, but helper calls still run when wire space is
 * exhausted. Individual usage/kind scratch is caller-owned on this stack.
 * All records are[class,idLE 16,direction,scaleLE 16]. Wildcards use idffff and 0
 * scale; individual keyboard/consumer records also use 0 scale. Cursor wraps 16
 * bits. Individual keyboard records sample usage, store class, sample direction,
 * then store usage HIGH before LOW. Other records store usage LOW before HIGH.
 * Under the updater/callee bounds the result fits 512 bytes; no new bounds
 * checks, alternate lock order, aggregate snapshot or hardware guarantee.
 */
unsigned int locks_encode(unsigned char *output)
{
    unsigned short usages[85];
    unsigned char directions[86];
    volatile unsigned char *wire = output;
    RtosQueue *configuration_mutex = REWRITE_MUTEX;
    wire[0] = 6;
    wire[1] = 0;
    if (configuration_mutex != NULL) xQueueSemaphoreTake(configuration_mutex,0xffffffffU);
    unsigned int offset = 2;
    const InputStateView *primary = (const InputStateView *)&FIXED_INPUTS[0].state;
    const InputStateView *keyboard = (const InputStateView *)&FIXED_INPUTS[1].state;
    const InputStateView *consumer = (const InputStateView *)&FIXED_INPUTS[2].state;
    if (FIXED_INPUTS[0].enabled != 0) {
        for (unsigned int channel = 0; channel < 20; ++channel) {
            for (unsigned int direction = 0; direction < 4; ++direction) {
                int scale = input_get_scale(primary,channel,direction);
                memw();
                if (MOTION_REFERENCE_MODE == 1 &&
                    ((direction-2U)&255U) < 2 && channel < 2) {
                    int paired_scale = input_get_scale(primary,(channel&255U)^1U,direction);
                    scale = (short)(scale < paired_scale ? scale : paired_scale);
                }
                if (scale != 100)
                    offset = input_lock_status_append(wire,offset,channel < 4 ? 3 : 0,
                        channel < 4 ? channel : (channel&255U)-4U,direction+1U,scale);
            }
        }
    }
    if (FIXED_INPUTS[1].enabled != 0) {
        unsigned int flags = input_get_keyboard_transform_flags(keyboard);
        if (flags&1U) offset = input_lock_status_append(wire,offset,1,0xffff,1,0);
        if (flags&2U) offset = input_lock_status_append(wire,offset,1,0xffff,2,0);
        if (FIXED_INPUTS[2].enabled == 0) goto individual_keyboard;
    } else if (FIXED_INPUTS[2].enabled == 0) goto release_configuration;

    if (input_get_transform_mode(consumer) != 0)
        offset = input_lock_status_append(wire,offset,2,0xffff,0,0);
    unsigned int consumer_count = input_list_consumer_transforms(consumer,usages,8);
    if (consumer_count != 0) {
        unsigned int loop_count = ((((consumer_count&0xffffU)*2U)-2U)>>1)+1U;
        for (unsigned int index = 0; index < loop_count; ++index)
            offset = input_lock_status_append_usage(wire,offset,2,usages + index,NULL);
    }
individual_keyboard:
    if (FIXED_INPUTS[1].enabled != 0) {
        unsigned int capacity = (85U-wire[1])&255U;
        unsigned int keyboard_count = input_list_key_transforms(keyboard,usages,directions,capacity);
        if (keyboard_count != 0) {
            unsigned int loop_count = ((((keyboard_count&0xffffU)*2U)-2U)>>1)+1U;
            for (unsigned int index = 0; index < loop_count; ++index)
                offset = input_lock_status_append_usage(wire,offset,1,
                    usages + index,directions + index);
        }
    }
release_configuration:
    configuration_mutex = REWRITE_MUTEX;
    if (configuration_mutex != NULL) xQueueGenericSend(configuration_mutex,NULL,0,0);
    return offset;
}
