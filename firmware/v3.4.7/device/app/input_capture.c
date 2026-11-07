/* Device motion-rule selection and button capture records. */

#include "../include/types.h"

/* Source reconstruction utilities for repeated inlined six-byte rule scans.
 * Raw addressing preserves the unchecked native count, including values that
 * walk beyond the 43 declared records. These are not additional native entries. */
/* Read a profile's count once, then rank each record's edge/class/usage.
 * Ties retain the first record. A class wildcard ignores usage. No count cap,
 * synchronization, writes or allocation is added to the inlined native scan.
 * profile: BYTE-selected table index; traffic_class/usage/edge: full WORDs.
 * Returns the first highest-scoring record index, or -1 when none matches.
 */
static int capture_profile_find_rule(unsigned int profile,unsigned int traffic_class,
    unsigned int usage,unsigned int edge)
{
    const volatile unsigned char *base = (const volatile unsigned char *)CAPTURE_PROFILES + profile*260U;
    unsigned int count = base[258];
    int best_score = -1;
    int selected = -1;
    for (unsigned int index = 0; index < count; ++index) {
        const volatile CaptureProfileRule *rule = (const volatile void *)(base+index*6U);
        unsigned int rule_edge = rule->edge;
        if (rule_edge != 0 && rule_edge != edge)
            continue;
        unsigned int rule_class = rule->traffic_class;
        int score;
        if (rule_class == traffic_class) {
            unsigned int rule_usage = rule->usage;
            if (rule_usage == usage)
                score = 4;
            else if (rule_usage == 65535U)
                score = 2;
            else
                continue;
        } else if (rule_class == 255) {
            score = 0;
        } else {
            continue;
        }
        if (rule_edge != 0)
            ++score;
        if (score > best_score) {
            best_score = score;
            selected = (int)index;
        }
    }
    return selected;
}

/* Native entry: 0x403927a4. */
/* Original function-byte SHA-256:
 * 49d1482e4baccd43e1008c8aa87a9229a754e40294a5e63ca6d2fabe54fc8ddd. */
/* Return a capture-profile rule index for motion, or -1. Try nonzero axes in
 * X,Y,wheel,pan order and return the FIRST axis with any matching rule, even
 * if a later axis could score higher. Independently fence/sample profile and
 * capture mask for each axis; mask bit 3 enables motion. Positive edge=1,
 * negative edge=2. Within an axis choose the first highest score: class 3 with
 * exact usage (axis 0..3)=4, wildcard usage0xffff=2, class0xff=0; add 1 for an
 * explicit matching edge, while edge 0 is wildcard. Counts are not capped and
 * class0xff ignores usage. No state mutation, clock read or lock. */
int capture_find_motion_rule(int motion_x,int motion_y,int wheel_delta,int pan_delta)
{
    const int motion[4] = {motion_x,motion_y,wheel_delta,pan_delta};
    for (unsigned int axis = 0; axis < 4; ++axis) {
        if (motion[axis] == 0)
            continue;
        unsigned int edge = motion[axis] > 0 ? 1U : 2U;
        memw();
        unsigned int profile = CAPTURE_PROFILE_INDEX;
        memw();
        unsigned int mask = CAPTURE_CLASS_MASK;
        if ((mask & 8U) == 0)
            continue;
        int selected = capture_profile_find_rule(profile,3,axis,edge);
        if (selected != -1)
            return selected;
    }
    return -1;
}

/* Native entry: 0x4202aef0. */
/* Original function-byte SHA-256:
 * 90d8f5375376262c4ab2e575ba3110ed01b028025700cd9d967ee9ec042f6a75. */
/* Append at most one 136-byte button capture record when signed *record_count
 * is < 2. Negative counts are NOT rejected. Caller provides the array/count
 * and serialization. Seed the rule mask with the first class 0/0xff rule in
 * the current profile when capture mask bit 0 is set, ignoring usage/edge for
 * this seed. Initialize class/reserved/count/stamp/LOW8(edge), even if no rule
 * is ultimately selected and the count remains unchanged.
 * Scan LOW8(button_count) usages. Freshly sample profile/mask per button and
 * rank rules as in motion lookup, with class 0; match explicit edge against
 * FULL32(edge). OR every selected rule into a 32-bit mask (indices wrap mod32).
 * Append a class 0/little-endian usage triple only for a set bit of buttons,
 * also testing button indices mod32, up to 40 triples. The passed edge does
 * not invert or synthesize a release mask. A seed alone can emit an empty
 * record. On success publish kind 0x0f00, mask and payload length(8+3*usages),
 * then increment a fresh count read. Unused payload bytes remain untouched. */
void capture_append_buttons(BufferedInputCapture *records,
    int *record_count,unsigned int source_stamp,unsigned int buttons,
    unsigned int edge,unsigned int button_count)
{
    int count = *(volatile int *)record_count;
    if (count >= 2)
        return;
    volatile BufferedInputCapture *record = records+count;
    unsigned int rule_mask = 0;
    int first_selected = -1;
    memw();
    unsigned int mask = CAPTURE_CLASS_MASK;
    if ((mask & 1U) != 0) {
        memw();
        unsigned int profile = CAPTURE_PROFILE_INDEX;
        const volatile unsigned char *base = (const volatile unsigned char *)CAPTURE_PROFILES + profile*260U;
        unsigned int rule_count = base[258];
        for (unsigned int index = 0; index < rule_count; ++index) {
            unsigned int traffic_class = base[index*6U+2];
            if (traffic_class == 0 || traffic_class == 255) {
                first_selected = (int)index;
                rule_mask = 1U << (index & 31U);
                break;
            }
        }
    }
    record->class_and_reserved = 0;
    record->usage_count = 0;
    record->source_stamp = source_stamp;
    record->edge = (unsigned char)edge;
    unsigned int payload_length = 8;
    unsigned int limit = (unsigned char)button_count;
    for (unsigned int button = 0; button < limit; ++button) {
        memw();
        unsigned int profile = CAPTURE_PROFILE_INDEX;
        memw();
        mask = CAPTURE_CLASS_MASK;
        if ((mask & 1U) == 0)
            continue;
        int selected = capture_profile_find_rule(profile,0,button,edge);
        if (selected == -1)
            continue;
        rule_mask |= 1U << ((unsigned int)selected & 31U);
        if (first_selected < 0)
            first_selected = selected;
        if ((buttons & (1U << (button & 31U))) == 0 || record->usage_count >= 40)
            continue;
        volatile unsigned char *payload = (volatile unsigned char *)record+8;
        payload[payload_length] = 0;
        payload[payload_length+2] = 0;
        payload[payload_length+1] = (unsigned char)button;
        unsigned int usages = record->usage_count;
        record->usage_count = (unsigned char)(usages+1U);
        payload_length = (payload_length+3U) & 65535U;
    }
    if (first_selected >= 0) {
        record->kind = 0x0f00;
        count = *(volatile int *)record_count;
        record->rule_mask = rule_mask;
        record->payload_length = (unsigned short)payload_length;
        *(volatile int *)record_count = (int)((unsigned int)count+1U);
    }
}
