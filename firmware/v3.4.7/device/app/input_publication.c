/* Device input revision and pending-record publication. */

#include "../include/types.h"

/* Native entry: 0x420295c8. */
/* Original function-byte SHA-256:
 * fcd12164f36a393013b4d159a43f24a949c36bf11303931085ebc8af3abe16cd. */
/* Publish pending input records and changed motion/report metadata.
 * Optionally take the saved publication mutex indefinitely, ignoring result.
 * Under pending-list spinlock, snapshot count BYTE and copy exactly count*13
 * bytes to shared scratch; no count/capacity clamp. Unlock, then MEMW/read
 * revision WORD and MEMW/read last-published WORD, each ONCE. If different and
 * may_read_report_state==0, release a freshly reloaded mutex and return 0,
 * WITHOUT posting even the saved pending records. Other exits return 1, including
 * encoding/queue failures; this result is not transport success.
 * For a changed revision with permission, zero exactly 101 metadata bytes.
 * Snapshot profile, scope, bearing, time windows, output periods, render token,
 * spread and USB-suspended flag with native read/store ordering. Window division is
 * unsigned/1000, narrowed to 16 bits. Period halves come from one saved WORD each.
 * Derive observed-axis mask from an unchecked BYTE count of eight-byte rules: source-kind
 * high byte 3 uses button index, target kind 3 uses target index; admit indices < 4.
 * A valid active primary layout contributes endpoint/report ID/expected length,
 * four 12-byte axis descriptions, bounds and first 32 scale bytes. Axis WORDs
 * are read in native interleaved order, not a fresh per-axis loop snapshot.
 * Width < 32 uses sign bit1<<((width-1)&31); width 0 therefore yields full32-bit
 * limits, as does width>=32. Intersect with descriptor min/max only when its
 * minimum<maximum, without repairing an inverted intersection. Preserve native
 * BYTE store order for unaligned LE32 bounds. Publish enabled mask before three
 * axis WORDs; copy 160 scale bytes locally but send only their first 32 here.
 * Queue opcode 0x38, metadata 0, length 101. Failure skips pending-record send and
 * retains published revision. Success acknowledges the SAVED revision, then
 * attempts saved count*13 records as 0x39. A failed record enqueue retains list.
 * On success lock list, compare current count to saved count; move only its
 * remaining tail when current>saved, otherwise clear count. Reload/release
 * optional mutex on every normal exit. No hardware/drain/ACK wait, new bounds,
 * coherent cross-field snapshot or atomic publication is added. */
int input_publish_pending(int may_read_report_state)
{
    RtosQueue *mutex = INPUT_PUBLICATION_MUTEX;
    if (mutex != NULL)
        xQueueSemaphoreTake(mutex,0xffffffffU);
    xPortEnterCriticalTimeout(INPUT_PENDING_LOCK,-1);
    unsigned int saved_count = INPUT_PENDING_COUNT;
    if (saved_count != 0)
        memcpy(INPUT_PENDING_SNAPSHOT,INPUT_PENDING_RECORDS,saved_count * 13U);
    vPortExitCritical(INPUT_PENDING_LOCK);
    memw();
    unsigned int revision = *MOTION_REVISION;
    memw();
    unsigned int published_revision = INPUT_PUBLISHED_REVISION;
    if (revision != published_revision) {
        if (may_read_report_state == 0) {
            mutex = INPUT_PUBLICATION_MUTEX;
            if (mutex != NULL)
                xQueueGenericSend(mutex,NULL,0,0);
            return 0;
        }
        volatile InputPublicationWire *wire = INPUT_PUBLICATION_WIRE;
        memset((void *)wire,0,101);
        memw();
        unsigned char profile = MOTION_OPTIONS.profile;
        memw();
        wire->scope = EMISSION_OPTIONS.scope;
        memw();
        wire->bearing_coupled = BEARING_COUPLED;
        memw();
        unsigned int bearing_window_us = MOTION_OPTIONS.bearing_window_us;
        memw();
        unsigned int riding_window_us = MOVEMENT_RIDING_US;
        memw();
        unsigned int period_us = EMISSION_OPTIONS.period_us;
        wire->render_token = MOTION_RENDER_TOKEN;
        unsigned short spread = MOTION_OPTIONS.spread;
        memw();
        unsigned int learned_period = REPORT_LEARNED_PERIOD;
        wire->bearing_window_ms = (unsigned short)(bearing_window_us / 1000U);
        wire->riding_window_ms = (unsigned short)(riding_window_us / 1000U);
        wire->profile = profile;
        wire->spread = spread;
        wire->period_low = (unsigned short)period_us;
        wire->period_high = (unsigned short)(period_us >> 16);
        memw();
        unsigned char usb_suspended = USB_SUSPENDED;
        wire->learned_period_low = (unsigned short)learned_period;
        unsigned char rule_count = OBSERVED_BUTTON_RULE_COUNT;
        wire->learned_period_high = (unsigned short)(learned_period >> 16);
        wire->usb_suspended = usb_suspended;
        if (rule_count != 0) {
            unsigned char mask = wire->observed_axes;
            int mask_changed = 0;
            for (unsigned int index = 0; index < rule_count; ++index) {
                const volatile ObservedButtonRule *rule = &OBSERVED_BUTTON_RULES[index];
                if (((const volatile unsigned char *)rule)[1] == 3) {
                    unsigned int button = rule->button;
                    unsigned int bit = 1U << (button & 31U);
                    if (button < 4) {
                        mask = (unsigned char)(mask | bit);
                        mask_changed = may_read_report_state;
                    }
                }
                if (rule->target_kind == 3) {
                    unsigned int target = rule->target_usage;
                    unsigned int bit = 1U << (target & 31U);
                    if (target < 4) {
                        mask = (unsigned char)(mask | bit);
                        mask_changed = may_read_report_state;
                    }
                }
            }
            if (mask_changed != 0)
                wire->observed_axes = mask;
        }
        unsigned char primary_active = REPORT_BLOCK0_ACTIVE;
        if (primary_active != 0) {
            const volatile InputStateView *state = INPUT0_STATE;
            const volatile HidReportLayout *layout = state->hid_layout;
            if (layout != NULL) {
                int interface = REPORT_BLOCK0_INTERFACE;
                if (interface >= 0) {
                    ReportNumericField axes[4];
                    axes[0].minimum = layout->axes[0].minimum;
                    axes[1].minimum = layout->axes[1].minimum;
                    axes[1].maximum = layout->axes[1].maximum;
                    axes[1].packed = layout->axes[1].packed;
                    axes[2].packed = layout->axes[2].packed;
                    unsigned char report_id = layout->report_id;
                    unsigned char endpoint = USB_INTERFACE_ENDPOINTS[interface];
                    axes[2].minimum = layout->axes[2].minimum;
                    axes[2].maximum = layout->axes[2].maximum;
                    unsigned short expected_length = layout->expected_length;
                    axes[3].packed = layout->axes[3].packed;
                    wire->endpoint_report_id = (unsigned short)(endpoint | ((unsigned int)report_id << 8));
                    axes[3].minimum = layout->axes[3].minimum;
                    axes[0].packed = layout->axes[0].packed;
                    axes[3].maximum = layout->axes[3].maximum;
                    unsigned char enabled_mask = wire->enabled_axes;
                    axes[0].maximum = layout->axes[0].maximum;
                    wire->expected_length = expected_length;
                    InputPublishedAxisFields fields;
                    unsigned char any_enabled = 0;
                    for (unsigned int axis = 0; axis < 4; ++axis) {
                        fields.offset[axis] = axes[axis].bit_offset;
                        unsigned int width = axes[axis].width;
                        unsigned char enabled = axes[axis].enabled;
                        fields.width[axis] = (unsigned char)width;
                        if (enabled != 0) {
                            enabled_mask = (unsigned char)(enabled_mask | (1U << axis));
                            any_enabled = primary_active;
                        }
                        unsigned int sign_bit = 1U << ((width - 1U) & 31U);
                        int minimum = (int)(0U - sign_bit);
                        int maximum = (int)(sign_bit - 1U);
                        if (width >= 32) {
                            minimum = (-2147483647 - 1);
                            maximum = 2147483647;
                        }
                        if (axes[axis].minimum < axes[axis].maximum) {
                            if (minimum < axes[axis].minimum)
                                minimum = axes[axis].minimum;
                            if (maximum > axes[axis].maximum)
                                maximum = axes[axis].maximum;
                        }
                        unsigned int low_bits = (unsigned int)minimum;
                        unsigned int high_bits = (unsigned int)maximum;
                        wire->minimum_le[axis][0] = (unsigned char)low_bits;
                        wire->maximum_le[axis][0] = (unsigned char)high_bits;
                        wire->minimum_le[axis][2] = (unsigned char)(low_bits >> 16);
                        wire->minimum_le[axis][3] = (unsigned char)(low_bits >> 24);
                        wire->minimum_le[axis][1] = (unsigned char)(low_bits >> 8);
                        wire->maximum_le[axis][1] = (unsigned char)(high_bits >> 8);
                        wire->maximum_le[axis][2] = (unsigned char)(high_bits >> 16);
                        wire->maximum_le[axis][3] = (unsigned char)(high_bits >> 24);
                    }
                    if (any_enabled != 0)
                        wire->enabled_axes = enabled_mask;
                    wire->axis_fields.words[0] = fields.words[0];
                    wire->axis_fields.words[1] = fields.words[1];
                    wire->axis_fields.words[2] = fields.words[2];
                    InputScaleSnapshot scales;
                    input_copy_scales(INPUT0_STATE,&scales);
                    memcpy((void *)wire->primary_scales,&scales,32);
                }
            }
        }
        if (link_queue_encoded_frame(INPUT_METADATA_ITEM,0x38,0,
                (const void *)wire,101) == 0)
            goto release_mutex;
        INPUT_PUBLISHED_REVISION = revision;
    }
    if (saved_count != 0 &&
        link_queue_encoded_frame(INPUT_PENDING_ITEM,0x39,0,
            INPUT_PENDING_SNAPSHOT,saved_count * 13U) != 0) {
        xPortEnterCriticalTimeout(INPUT_PENDING_LOCK,-1);
        unsigned char remaining = 0;
        unsigned int current_count = INPUT_PENDING_COUNT;
        if (saved_count < current_count) {
            unsigned int tail_count = current_count - saved_count;
            memmove(INPUT_PENDING_RECORDS,
                INPUT_PENDING_RECORDS + saved_count,tail_count * 13U);
            remaining = (unsigned char)tail_count;
        }
        INPUT_PENDING_COUNT = remaining;
        vPortExitCritical(INPUT_PENDING_LOCK);
    }
release_mutex:
    mutex = INPUT_PUBLICATION_MUTEX;
    if (mutex != NULL)
        xQueueGenericSend(mutex,NULL,0,0);
    return 1;
}

/* Native entry: 0x4202b150. */
/* Original function-byte SHA-256:
 * 67f3bbef267dc356595c22695be80a6cabb9f909f44be6f28bab8080d1b1c26c. */
/*
 * Queue four axes/flags/time into 13-byte pending records under input spinlock
 * (UINT_MAX cycles; entry status ignored). Snapshot count once. Count<=38:
 * encode low16 axes/low8 flags/time32 with BYTE stores in native order, publish
 * count+1 from cached count, unlock. Only filling slot 38 immediately flushes;
 * lower slots return. Queue capacity is 39, not 40.
 *
 * Count>38: if FULL-WORD flags==0 and last record 38 flags BYTE==0, merge into
 * that SAME final queued record. Read pan,X,Y,wheel as signed HALFWORDs; add
 * full32 inputs modulo32, signed-clamp each result to[-32768,32767], store X,
 * Y,wheel,pan HALFWORDs and replace time BYTEs. No new slot/count is published.
 * Otherwise MEMW/read drops; unless 65535, fence/REREAD and increment modulo16
 * with another fence before store. Thus a changed second sample can wrap.
 * Unlock and flush on every full path, even a rejected record. No capacity
 * repair, flag normalization, local time read, error result or delivery proof.
 */
void input_queue_motion(int x,int y,int wheel,int pan,int flags,unsigned int stamp)
{
    (void)xPortEnterCriticalTimeout(INPUT_PENDING_LOCK,-1);
    unsigned int count = INPUT_PENDING_COUNT;
    if (count <= 38) {
        volatile unsigned char *record = INPUT_PENDING_RECORDS[count].bytes;
        record[2] = (unsigned char)y;
        record[3] = (unsigned char)((unsigned int)y >> 8);
        record[9] = (unsigned char)stamp;
        record[0] = (unsigned char)x;
        record[5] = (unsigned char)((unsigned int)wheel >> 8);
        record[1] = (unsigned char)((unsigned int)x >> 8);
        record[4] = (unsigned char)wheel;
        record[6] = (unsigned char)pan;
        record[7] = (unsigned char)((unsigned int)pan >> 8);
        record[8] = (unsigned char)flags;
        record[10] = (unsigned char)(stamp >> 8);
        record[11] = (unsigned char)(stamp >> 16);
        record[12] = (unsigned char)(stamp >> 24);
        INPUT_PENDING_COUNT = (unsigned char)(count + 1U);
        vPortExitCritical(INPUT_PENDING_LOCK);
        if (count != 38) return;
    } else {
        volatile PendingMotionMergeView *tail = PENDING_MOTION_TAIL;
        unsigned char tail_flags = tail->flags; /* Read even when incoming flags!=0. */
        if ((unsigned int)flags == 0 && tail_flags == 0) {
            int old_pan = tail->pan;
            int old_x = tail->x;
            int old_y = tail->y;
            int old_wheel = tail->wheel;
            int sum_x = (int)((unsigned int)old_x + (unsigned int)x);
            int sum_y = (int)((unsigned int)old_y + (unsigned int)y);
            int sum_wheel = (int)((unsigned int)old_wheel + (unsigned int)wheel);
            int sum_pan = (int)((unsigned int)old_pan + (unsigned int)pan);
            tail->x = sum_x < -32768 ? -32768 : sum_x > 32767 ? 32767 : sum_x;
            tail->y = sum_y < -32768 ? -32768 : sum_y > 32767 ? 32767 : sum_y;
            tail->wheel = sum_wheel < -32768 ? -32768 : sum_wheel > 32767 ? 32767 : sum_wheel;
            tail->pan = sum_pan < -32768 ? -32768 : sum_pan > 32767 ? 32767 : sum_pan;
            tail->stamp_le[0] = (unsigned char)stamp;
            tail->stamp_le[1] = (unsigned char)(stamp >> 8);
            tail->stamp_le[2] = (unsigned char)(stamp >> 16);
            tail->stamp_le[3] = (unsigned char)(stamp >> 24);
        } else {
            memw(); unsigned int initial_drop_count = PENDING_INPUT_DROPS;
            if (initial_drop_count != 65535U) {
                memw(); unsigned int drop_count = PENDING_INPUT_DROPS;
                memw(); PENDING_INPUT_DROPS = (unsigned short)(drop_count + 1U);
            }
        }
        vPortExitCritical(INPUT_PENDING_LOCK);
    }
    input_flush_pending();
}
