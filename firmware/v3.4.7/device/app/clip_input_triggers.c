/* Device clip input-edge binding updates. */
#include "../include/types.h"

/* Native entry: 0x42036ee0. */
/* Original function-byte SHA-256:
 * bd40215393328ebe7ecf30fdc6366d423e2d1aa9ce2f59ebcaa2a157ad06aa67. */
/*
 * Add or replace an input-edge binding when flags bit 0 is set; otherwise
 * remove the first exact class/usage/edge match. Arguments narrow to
 * 8/16/8/8/8 bits at entry. Returns no status.
 *
 * input_class: 0 buttons, 1 keys, 2 consumer usages, 0xff any class.
 * usage: buttons 0..15 or keys 0..255, with 0xffff as wildcard; consumer
 *        usages accept all 16 bits. Any-class bindings normalize to 0xffff.
 * edge: 0 any edge, 1 or 2 the selected edge; other values are rejected.
 * action: playback verb 0..5 for add/replace; ignored for removal.
 * flags: bit 0 selects add/replace; bit 1 becomes consume. Others ignored.
 *
 * Special class 0xff/usage 0xffff/edge 0/removal clears the input count then
 * 388 bytes of packet-rule storage, including its accounting, but leaves the
 * input slots and baseline-valid bytes untouched. Its optional mutex wait
 * is indefinite and its give reloads the mutex after memset. Other admitted
 * operations also wait UINT32_MAX ticks if a mutex exists, then immediately
 * reload/cache that pointer for eventual give. An initially NULL mutex is
 * never reloaded on these ordinary paths. Acquisition failures do not stop
 * the update.
 *
 * Upsert searches the cached count, replacing in place or appending unless
 * count is EXACTLY 8; no >=8 repair for corrupt state. Publish incremented
 * count before the new record fields. Clear consumer then keyboard baselines,
 * store class BYTE, usage HALFWORD, combined edge/action HALFWORD and consume
 * BYTE, then clear button baseline. Preserve padding and old trailing slots.
 * Removal shifts later records with memmove and decrements the count; it does
 * not clear the vacated tail or baseline state. No timer work or new fence.
 */
void clip_input_trigger_update(unsigned char input_class,unsigned short usage,
    unsigned char edge,unsigned char action,unsigned char flags)
{
    if (input_class == 0xffU && usage == 0xffffU && edge == 0 &&
        (flags & 1U) == 0) {
        RtosQueue *mutex = REWRITE_MUTEX;
        if (mutex != NULL)
            (void)xQueueSemaphoreTake(mutex,0xffffffffU);
        INPUT_TRIGGER_COUNT = 0;
        memset(PACKET_TRIGGER_RESET_STORAGE,0,sizeof(ClipPacketTriggerTable));
        mutex = REWRITE_MUTEX;
        if (mutex != NULL)
            (void)xQueueGenericSend(mutex,NULL,0,0);
        return;
    }
    if (edge > 2U)
        return;
    switch (input_class) {
    case 0:
        if ((unsigned short)(usage - 16U) <= 0xffeeU)
            return;
        break;
    case 1:
        if ((unsigned short)(usage - 256U) <= 0xfefeU)
            return;
        break;
    case 2:
        break;
    case 0xff:
        usage = 0xffffU;
        break;
    default:
        return;
    }
    RtosQueue *mutex = REWRITE_MUTEX;
    if (mutex != NULL) {
        (void)xQueueSemaphoreTake(mutex,0xffffffffU);
        mutex = REWRITE_MUTEX;
    }
    if ((flags & 1U) != 0) {
        if (action > 5U)
            goto unlock;
        unsigned int count = INPUT_TRIGGER_COUNT;
        unsigned int index = 0;
        while (index < count) {
            volatile ClipInputTrigger *rule = CLIP_INPUT_TRIGGERS + index;
            if (rule->input_class == input_class && rule->usage == usage &&
                rule->edge == edge)
                break;
            ++index;
        }
        if (index == count) {
            if (count == 8U)
                goto unlock;
            INPUT_TRIGGER_COUNT = (unsigned char)(count + 1U);
        }
        volatile ClipInputTrigger *rule = CLIP_INPUT_TRIGGERS + index;
        REPORT_CONSUMER_TRIGGERS.valid = 0;
        REPORT_KEYBOARD_TRIGGERS.valid = 0;
        rule->input_class = input_class;
        rule->usage = usage;
        rule->edge_action = (unsigned short)(edge | ((unsigned int)action << 8));
        rule->consume = (flags >> 1) & 1U;
        REPORT_TRIGGER_BUTTONS_VALID = 0;
    } else {
        unsigned int count = INPUT_TRIGGER_COUNT;
        for (unsigned int index = 0; index != count;
             index = (unsigned char)(index + 1U)) {
            volatile ClipInputTrigger *rule = CLIP_INPUT_TRIGGERS + index;
            if (rule->input_class != input_class || rule->usage != usage ||
                rule->edge != edge)
                continue;
            unsigned int next = (unsigned char)(index + 1U);
            if (next < count) {
                unsigned int records = (unsigned char)(count - 2U - index) + 1U;
                memmove((void *)(CLIP_INPUT_TRIGGERS + (unsigned short)(next - 1U)),
                    (const void *)(CLIP_INPUT_TRIGGERS + next),records * 8U);
            }
            INPUT_TRIGGER_COUNT = (unsigned char)(count - 1U);
            break;
        }
    }
unlock:
    if (mutex != NULL)
        (void)xQueueGenericSend(mutex,NULL,0,0);
}
