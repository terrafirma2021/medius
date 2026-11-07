/* Device trigger selection and temporary physical-input suppression. */

#include "../include/types.h"

/* Native entry: 0x42028388. */
/* Original function-byte SHA-256:
 * 13a98b012cd7658e4e8c6a7263025198f63b5db01008bcdacae0f17365a05b5c. */
/* Find the FIRST highest-scoring matching 8-byte trigger rule. Cache byte count
 * once and walk that many records without a table-size cap. Class must equal
 * the FULL32 argument or 0xff; usage must equal the FULL32 argument or 0xffff;
 * edge 0 is wildcard, otherwise its byte must equal FULL32 edge.
 * Score 4 for class equality, 2 more for BOTH class and usage equality, 1 for
 * nonzero matching edge. Consequently usage specificity does NOT improve a
 * wildcard-class rule when the caller class is not 0xff. Caller arguments are
 * not narrowed: requesting class 0xff/usage0xffff can equal the wildcard itself.
 * Return live rule pointer or NULL. No mutation, fence, lock or action dispatch. */
InputTriggerRule *input_find_trigger(unsigned int traffic_class,
    unsigned int usage,unsigned int edge)
{
    unsigned int count = INPUT_TRIGGER_COUNT;
    InputTriggerRule *selected = 0;
    int best_score = -1;
    for (unsigned int index = 0; index < count; ++index) {
        InputTriggerRule *rule = INPUT_TRIGGERS+index;
        const volatile InputTriggerRule *rule_view = rule;
        unsigned int rule_class = rule_view->traffic_class;
        if (rule_class != traffic_class && rule_class != 255)
            continue;
        unsigned int rule_usage = rule_view->usage;
        if (rule_usage != usage && rule_usage != 65535)
            continue;
        unsigned int rule_edge = rule_view->edge;
        if (rule_edge != 0 && rule_edge != edge)
            continue;
        unsigned int same_class = rule_class == traffic_class;
        int score = 4*same_class + 2*(same_class && rule_usage == usage) + (rule_edge != 0);
        if (score > best_score) {
            best_score = score;
            selected = rule;
        }
    }
    return selected;
}

/* Native entry: 0x42028e1c. */
/* Original function-byte SHA-256:
 * 647fca1261e67ccf8d3620b65ab9100d29ef6eeba95433906ff6dec4d2c57a70. */
/* Set/clear temporary suppression for a mouse-button scale channel. Shift the
 * FULL32 button modulo32 and retain the low16 mask; channel is LOW8(button+4).
 * Enable only when not tracked and all 4 PRIMARY channel scales currently 100;
 * write scale group 0 value 0 to primary then every dynamic binding state. Only
 * primary values are checked; existing binding scales are overwritten. Publish
 * tracking mask, then increment shared BYTE count (wrap permitted).
 * Release only if tracked: write group 0 value 100 to primary/all bindings,
 * force primary.changed=1, clear tracking bit and decrement BYTE count. This
 * restores 100, not saved scale values. Sample binding count after each setter;
 * table count is signed/unchecked. Setter statuses are ignored. No lock/fence,
 * no enabled gate, and no independent button bound check. A zero low16 mask
 * can therefore increment the count repeatedly without tracking a button. */
void input_suppress_button(unsigned int button,int suppress)
{
    unsigned int mask = (1U << (button & 31U)) & 65535U;
    unsigned int tracked = INPUT_SUPPRESSED_BUTTONS & mask;
    unsigned int channel = (button+4U) & 255U;
    if (suppress != 0) {
        if (tracked != 0)
            return;
        for (unsigned int column = 0; column < 4; ++column)
            if (input_get_scale(INPUT0_STATE,channel,column) != 100)
                return;
        input_set_scale_group(INPUT0_STATE,channel,0,0);
        for (int index = 0; index < REPORT_BINDING_COUNT; ++index)
            input_set_scale_group(&REPORT_BINDINGS[index].state,channel,0,0);
        unsigned int buttons = INPUT_SUPPRESSED_BUTTONS;
        unsigned int count = INPUT_SUPPRESSION_COUNT;
        INPUT_SUPPRESSED_BUTTONS = (unsigned short)(buttons | mask);
        INPUT_SUPPRESSION_COUNT = (unsigned char)(count+1U);
    } else if (tracked != 0) {
        input_set_scale_group(INPUT0_STATE,channel,0,100);
        for (int index = 0; index < REPORT_BINDING_COUNT; ++index)
            input_set_scale_group(&REPORT_BINDINGS[index].state,channel,0,100);
        unsigned int buttons = INPUT_SUPPRESSED_BUTTONS;
        unsigned int count = INPUT_SUPPRESSION_COUNT;
        ((volatile InputStateView *)INPUT0_STATE)->changed = 1;
        INPUT_SUPPRESSED_BUTTONS = (unsigned short)(buttons & ~mask);
        INPUT_SUPPRESSION_COUNT = (unsigned char)(count-1U);
    }
}

/* Native entry: 0x42028f2c. */
/* Original function-byte SHA-256:
 * cc35cbd81eb4ca79949b158a7a9444309ee39e227cd9b636bb469ec1244a34f7. */
/* Track temporary keyboard suppression in an unchecked usage>>3 bitmap; usage
 * is FULL32 and only its bit position is narrowed to low3. Enable if untracked,
 * keyboard block enabled, and key_is_transformed returns 0; call mode 0/value 0
 * setter, reread bitmap, set bit then increment shared BYTE count.
 * On release of a tracked key, an enabled block calls mode 0/value 100 setter,
 * rereads bitmap and forces keyboard.changed=1. A disabled block still clears
 * the bit/count, using the ORIGINAL bitmap byte. Publish cleared bitmap before
 * decremented count. No saved transform restoration, setter-status handling,
 * lock/fence, dirty-task notification or usage bound check. */
void input_suppress_key(unsigned int usage,int suppress)
{
    volatile unsigned char *tracking_byte = INPUT_SUPPRESSED_KEYS+(usage >> 3);
    unsigned int tracked_bits = *tracking_byte,mask = 1U << (usage & 7U);
    if (suppress != 0) {
        if ((tracked_bits & mask) != 0 || INPUT1_ENABLED == 0 ||
            input_key_is_transformed(INPUT1_STATE,usage) != 0)
            return;
        input_set_key_transform(INPUT1_STATE,usage,0,0);
        tracked_bits = *tracking_byte;
        unsigned int count = INPUT_SUPPRESSION_COUNT;
        *tracking_byte = (unsigned char)(tracked_bits | mask);
        INPUT_SUPPRESSION_COUNT = (unsigned char)(count+1U);
    } else if ((tracked_bits & mask) != 0) {
        if (INPUT1_ENABLED != 0) {
            input_set_key_transform(INPUT1_STATE,usage,0,100);
            tracked_bits = *tracking_byte;
            ((volatile InputStateView *)INPUT1_STATE)->changed = 1;
        }
        unsigned int count = INPUT_SUPPRESSION_COUNT;
        *tracking_byte = (unsigned char)(tracked_bits & ~mask);
        INPUT_SUPPRESSION_COUNT = (unsigned char)(count-1U);
    }
}

/* Native entry: 0x42028fcc. */
/* Original function-byte SHA-256:
 * a9f0c4a5cbbd86882a07a1def461f5277b13a9533e0c26c2c6e7e028cbe9dad9. */
/* Scan 8 tracked consumer HALFWORD slots completely: choose LAST FULL32 usage
 * match and FIRST empty slot; matching takes precedence over recognizing empty.
 * Enable when absent, room exists, consumer block enabled and helper says not
 * transformed. Set transform 1, store LOW16 usage, increment shared BYTE count.
 * Release the last match; if block enabled, clear transform and mark changed.
 * Then decrement BYTE count and zero that slot (slot store precedes count store).
 * A zero usage matches empty slots: release can decrement an empty tracker to 255;
 * duplicate usages release only the last one. Arguments are not normalized or
 * bounds-repaired and no previous transform is saved. No local lock/fence. */
void input_suppress_consumer(unsigned int usage,int suppress)
{
    int matching_slot = -1,empty_slot = -1;
    for (unsigned int index = 0; index < 8; ++index) {
        unsigned int value = INPUT_SUPPRESSED_CONSUMERS[index];
        if (usage == value)
            matching_slot = (int)index;
        else if (value == 0 && empty_slot < 0)
            empty_slot = (int)index;
    }
    if (suppress != 0) {
        if (matching_slot >= 0 || empty_slot < 0 || INPUT2_ENABLED == 0 ||
            input_consumer_is_transformed(INPUT2_STATE,usage) != 0)
            return;
        input_set_consumer_transform(INPUT2_STATE,(short)usage,1);
        unsigned int count = INPUT_SUPPRESSION_COUNT;
        INPUT_SUPPRESSED_CONSUMERS[empty_slot] = (unsigned short)usage;
        INPUT_SUPPRESSION_COUNT = (unsigned char)(count+1U);
    } else if (matching_slot >= 0) {
        if (INPUT2_ENABLED != 0) {
            input_set_consumer_transform(INPUT2_STATE,(short)usage,0);
            ((volatile InputStateView *)INPUT2_STATE)->changed = 1;
        }
        unsigned int count = INPUT_SUPPRESSION_COUNT;
        INPUT_SUPPRESSED_CONSUMERS[matching_slot] = 0;
        INPUT_SUPPRESSION_COUNT = (unsigned char)(count-1U);
    }
}
