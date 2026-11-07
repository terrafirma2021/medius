/* Medius v3.4.7 device — transform rule configuration and queries. */
#include "../include/types.h"

/* Transform reconstruction utilities: inline native walks, not more native
 * entries. The packed mode/source HALFWORD must be0 for a button target.
 * Cache count separately for each held usage; do not add a32-slot cap.
 */
static __attribute__((always_inline)) inline unsigned int transform_has_button_target(
    unsigned int destination_class,unsigned int usage)
{
    unsigned int count = TRANSFORM_COUNT;
    for (unsigned int index = 0; index < count; ++index) {
        volatile TransformRule *rule = TRANSFORM_RULES + index;
        if (rule->mode_source == 0 && rule->destination_class == destination_class &&
            rule->destination_usage == usage)
            return 1;
    }
    return 0;
}

/* Release saved keyboard/consumer usages with no remaining button target,
 * service changed enabled outputs, then clear the seven native button latches. */
static __attribute__((always_inline)) inline void transform_release_orphans(void)
{
    const volatile InputStateView *keyboard = INPUT1_STATE;
    unsigned char changed = 0;
    for (unsigned int usage = 0; usage < 256U; ++usage) {
        unsigned int held = keyboard->saved_keys[usage >> 3];
        if ((held & (1U << (usage & 7U))) != 0 &&
            transform_has_button_target(1,usage) == 0)
            changed = (unsigned char)(changed |
                input_update_saved_control(INPUT1_STATE,1,usage,0));
    }
    if (changed != 0 && FIXED_INPUTS[1].enabled != 0 &&
        input_needs_service(INPUT1_STATE) != 0)
        fixed_input_service(1,0xffffffffU);
    const volatile InputStateView *consumer = INPUT2_STATE;
    changed = 0;
    for (unsigned int index = 0; index < 8U; ++index) {
        unsigned int usage = consumer->saved_consumers[index];
        if (usage != 0 && transform_has_button_target(2,usage) == 0)
            changed = (unsigned char)(changed |
                input_update_saved_control(INPUT2_STATE,2,usage,0));
    }
    if (changed != 0 && FIXED_INPUTS[2].enabled != 0 &&
        input_needs_service(INPUT2_STATE) != 0)
        fixed_input_service(2,0xffffffffU);
    FIXED_INPUTS[0].last_buttons = 0;
    for (unsigned int index = 0; index < 6U; ++index)
        ((volatile ReportLayoutBinding *)REPORT_BINDINGS)[index].last_buttons = 0;
}

/* Native entry: 0x42038040. */
/* Original function-byte SHA-256:
 * c25f5ff3b6a499457e34167ebafc694552e1c54254a0653aa1c46cdc04b83c91. */
/*
 * Add/update or remove a transform keyed by both class/usage endpoints; mode
 * is not part of the key. Narrow to BYTE/HALFWORD fields at entry. Take the
 * optional rewrite mutex with an infinite tick wait, ignoring status. Snapshot enabled and
 * descriptor WORD for primary, then keyboard, then consumer BEFORE count.
 * Absent ff/ffff -> ff/ffff clears exactly258 bytes (32 rows,count,full),
 * not rounded struct padding; it ignores mode. Notify configuration change
 * then perform orphan release. Other removals search cached count, shift each
 * row with two source WORD loads BEFORE two destination WORD stores, publish
 * count-1 BYTE, zero tail8 and clear full. Missing removal still notifies and
 * releases orphans, but retains full. Search compares source class BYTE, source
 * usage HALFWORD, destination class BYTE, destination usage HALFWORD.
 *
 * Present any nonzero accepts mode0/1 and rejects identical endpoints. Mode1
 * permits axis3->axis3 only. Mode0 permits3->3, button0->button0 and button0->
 * keyboard1/consumer2. Call source usage validator, then destination validator,
 * with the same cached descriptor pointers. Invalid upserts still notify.
 * Append requires cached count<32; rejection sets sticky full1. Append writes
 * destination BYTE, packed mode/source HALFWORD and usages WORD, preserving
 * reserved byte3; count BYTE is published last from cached count+1. Existing
 * key writes only mode BYTE, even if unchanged. Upserts notify exactly once,
 * then reread count and update button mappings only if nonzero; they do not
 * perform the removal cleanup. Successful upserts do not clear sticky full.
 *
 * Removal cleanup visits all256 saved keyboard bits, releasing each without
 * a remaining mode0/source0 rule targeting that usage. It similarly visits
 * eight fresh unsigned consumer HALFWORD slots; per-usage table count is
 * sampled afresh. Accumulate only LOW8 of updater results. Service each changed
 * target only when enabled and needs_service, epoch UINT_MAX, keyboard before
 * consumer. Clear primary and six fixed dynamic last-buttons HALFWORDs after
 * release, regardless of actual binding count. Finally give a fresh optional
 * mutex pointer. No new fence, rollback, allocation or bounds repair.
 */
void transform_update(unsigned char mode,unsigned char source_class,
    unsigned short source_usage,unsigned char destination_class,
    unsigned short destination_usage,unsigned char present)
{
    RtosQueue *mutex = REWRITE_MUTEX;
    if (mutex != NULL)
        (void)xQueueSemaphoreTake(mutex,0xffffffffU);
    const HidReportLayout *primary = NULL;
    if (FIXED_INPUTS[0].enabled != 0)
        primary = FIXED_INPUTS[0].state.hid_layout;
    const HidReportLayout *keyboard = NULL;
    if (FIXED_INPUTS[1].enabled != 0)
        keyboard = FIXED_INPUTS[1].state.hid_layout;
    const HidReportLayout *consumer = NULL;
    if (FIXED_INPUTS[2].enabled != 0)
        consumer = FIXED_INPUTS[2].state.hid_layout;
    if (present == 0 && source_class == 0xffU && source_usage == 0xffffU &&
        destination_class == 0xffU && destination_usage == 0xffffU) {
        memset((void *)TRANSFORM_RULES,0,258U);
        motion_configuration_changed();
        transform_release_orphans();
        goto unlock;
    }
    unsigned int count = TRANSFORM_COUNT;
    unsigned int selected = 0xffffffffU;
    for (unsigned int index = 0; (unsigned char)index < count; ++index) {
        volatile TransformRule *rule = TRANSFORM_RULES + index;
        if (rule->source_class == source_class && rule->source_usage == source_usage &&
            rule->destination_class == destination_class &&
            rule->destination_usage == destination_usage) {
            selected = index;
            break;
        }
    }
    if (present == 0) {
        if (selected != 0xffffffffU) {
            for (unsigned int next = selected + 1U; next < count; ++next) {
                unsigned int header = TRANSFORM_RULES[next].header;
                unsigned int usages = TRANSFORM_RULES[next].usages;
                TRANSFORM_RULES[next - 1U].header = header;
                TRANSFORM_RULES[next - 1U].usages = usages;
            }
            unsigned char remaining = (unsigned char)(count - 1U);
            TRANSFORM_COUNT = remaining;
            memset((void *)(TRANSFORM_RULES + remaining),0,8U);
            TRANSFORM_FULL = 0;
        }
        motion_configuration_changed();
        transform_release_orphans();
        goto unlock;
    }
    unsigned int axis_pair = source_class == 3 && destination_class == 3;
    unsigned int allowed = mode < 2 &&
        (source_class != destination_class || source_usage != destination_usage);
    if (allowed != 0) {
        if (mode == 1)
            allowed = axis_pair;
        else
            allowed = axis_pair || (source_class == 0 && destination_class == 0) ||
                (source_class == 0 && (unsigned char)(destination_class - 1U) < 2U);
    }
    if (allowed != 0 &&
        transform_usage_supported(source_class,source_usage,primary,keyboard,consumer) != 0 &&
        transform_usage_supported(destination_class,destination_usage,primary,keyboard,consumer) != 0) {
        if (selected == 0xffffffffU) {
            if (count >= 32U) {
                TRANSFORM_FULL = 1;
            } else {
                volatile TransformRule *rule = TRANSFORM_RULES + count;
                rule->destination_class = destination_class;
                rule->mode_source = (unsigned short)(mode | ((unsigned int)source_class << 8));
                rule->usages = source_usage | ((unsigned int)destination_usage << 16);
                TRANSFORM_COUNT = (unsigned char)(count + 1U);
            }
        } else {
            TRANSFORM_RULES[selected].mode = mode;
        }
    }
    motion_configuration_changed();
    if (TRANSFORM_COUNT != 0)
        input_update_button_mappings();
unlock:
    mutex = REWRITE_MUTEX;
    if (mutex != NULL)
        (void)xQueueGenericSend(mutex,NULL,0,0);
}

/* Native entry: 0x420383d8. */
/* Original function-byte SHA-256:
 * 8eb39541bbebcc86936215c6a50f544b6e6a7dc8e6706d5e1f42e02d1626393a. */
/*
 * Serialize selector0x10/full/count0, then at most32 seven-byte transforms
 * when output is exclusively caller-owned. Requires up to227 writable bytes;
 * no capacity argument. Take optional mutex with an infinite tick wait, ignoring status.
 * Read full BYTE after the optional take; write header before reading count.
 * Initially NULL paths keep NULL for give. A locked path caches a FRESH mutex
 * pointer after the count read and gives that pointer later, even if no rows.
 *
 * Cache emitted count0; increment walk BYTE before checking emitted<32. Read
 * source usage HALFWORD, mode BYTE, source class BYTE, destination usage
 * HALFWORD and destination class BYTE, then write wire mode/class/sourceLE/
 * destination class/destinationLE. Increment fresh output[2], and wrap used16
 * on+7. Advance full8-byte cursor and read live count every iteration, including
 * skipped rows; stop when walk BYTE>=count. Only continuing iterations reload
 * output[2] for the next emission test. Return3 for empty table. No snapshot
 * generation, prezero of remaining output, fence or final mutex reload.
 */
unsigned int transforms_encode(unsigned char *output)
{
    volatile unsigned char *out = output;
    RtosQueue *mutex = REWRITE_MUTEX;
    unsigned int count;
    if (mutex == NULL) {
        unsigned int full = TRANSFORM_FULL;
        out[0] = 0x10;
        out[1] = full;
        out[2] = 0;
        count = TRANSFORM_COUNT;
    } else {
        (void)xQueueSemaphoreTake(mutex,0xffffffffU);
        unsigned int full = TRANSFORM_FULL;
        out[0] = 0x10;
        out[1] = full;
        out[2] = 0;
        count = TRANSFORM_COUNT;
        mutex = REWRITE_MUTEX;
    }
    unsigned int used = 3;
    if (count != 0) {
        volatile TransformRule *rule = TRANSFORM_RULES;
        unsigned char walked = 0;
        unsigned int emitted = 0;
        for (;;) {
            walked = (unsigned char)(walked + 1U);
            if (emitted < 32U) {
                unsigned int source_usage = rule->source_usage;
                unsigned int mode = rule->mode;
                unsigned int source_class = rule->source_class;
                unsigned int destination_usage = rule->destination_usage;
                unsigned int destination_class = rule->destination_class;
                out[used] = mode;
                out[used + 1U] = source_class;
                out[used + 2U] = source_usage;
                out[used + 3U] = source_usage >> 8;
                out[used + 4U] = destination_class;
                out[used + 5U] = destination_usage;
                out[used + 6U] = destination_usage >> 8;
                out[2] = (unsigned char)(out[2] + 1U);
                used = (unsigned short)(used + 7U);
            }
            ++rule;
            count = TRANSFORM_COUNT;
            if (walked >= count)
                break;
            emitted = out[2];
        }
    }
    if (mutex != NULL)
        (void)xQueueGenericSend(mutex,NULL,0,0);
    return used;
}

/* Native entry: 0x42039a44. */
/* Original function-byte SHA-256:
 * d6a7d354299bc3976742b3077c8da87eebad381a0adef052a5ba255ace2c9095. */
/*
 * Test one transform endpoint against cached descriptor pointers. Class and
 * usage retain full32-bit inputs; no narrowing or layout-enabled top-level
 * check. Class0 requires primary pointer, reads button count BYTE, then tests
 * full usage<count and<=15. Class1 requires keyboard pointer and nonzero
 * keyboard.enabled BYTE, then accepts low16(usage-4)<=251. Class2 requires
 * consumer pointer and returns (full usage!=0) AND consumer.enabled bit0:
 * an even nonzero enable BYTE returns0. Class3 requires primary and full
 * usage<=3, reads the selected numeric-axis packed WORD at0x98+12*usage and
 * tests its high BYTE, rather than reading the enabled byte directly. Other
 * classes return0. All results are0/1; no mutation, lock, fence or null layout
 * dereference is introduced. Pointer lifetime belongs to the caller.
 */
unsigned char transform_usage_supported(unsigned int input_class,unsigned int usage,
    const HidReportLayout *primary,const HidReportLayout *keyboard,
    const HidReportLayout *consumer)
{
    switch (input_class) {
    case 0: {
        if (primary == NULL)
            return 0;
        unsigned int buttons = ((const volatile HidReportLayout *)primary)->button_count;
        return usage < buttons && usage <= 15U;
    }
    case 1:
        if (keyboard == NULL ||
            ((const volatile HidReportLayout *)keyboard)->keyboard.enabled == 0)
            return 0;
        return (unsigned short)(usage - 4U) <= 251U;
    case 2: {
        if (consumer == NULL)
            return 0;
        unsigned int enabled = ((const volatile HidReportLayout *)consumer)->consumer.enabled;
        return enabled & (usage != 0);
    }
    case 3: {
        if (primary == NULL || usage > 3U)
            return 0;
        unsigned int axis = ((const volatile HidReportLayout *)primary)->axes[usage].packed;
        return (axis >> 24) != 0;
    }
    default:
        return 0;
    }
}
