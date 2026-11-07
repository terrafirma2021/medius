/* Device profile persistence service and reconstruction utilities.
 * The inline utilities below represent repeated inlined native operations;
 * they are not additional firmware function entries. */

#include "../include/types.h"

static __inline__ __attribute__((always_inline)) unsigned int
profile_render_blocks_store(void)
{
    memw();
    unsigned int state = MOTION_RENDER_STATE;
    if ((state & 1U) == 0)
        return 0;
    memw();
    return (MOTION_RENDER_STATE >> 2) & 1U;
}

static __inline__ __attribute__((always_inline)) long long
profile_sample_idle_age(void)
{
    unsigned long long now = (unsigned long long)esp_timer_get_time();
    memw();
    unsigned int low = FIXED_INPUTS[0].last_input_time.low;
    memw();
    unsigned int high = FIXED_INPUTS[0].last_input_time.high;
    return (long long)(now - (((unsigned long long)high << 32) | low));
}

static __inline__ __attribute__((always_inline)) void
profile_clear_button_bits(const volatile HidReportLayout *layout,
    unsigned char *report,unsigned int length)
{
    unsigned int count = layout->button_count;
    if (count == 0)
        return;
    unsigned int index = 0;
    do {
        unsigned int bit = (layout->button_bit_offset + index) & 65535U;
        unsigned int byte = bit >> 3;
        ++index;
        if (byte < length) {
            unsigned char original = ((volatile unsigned char *)report)[byte];
            ((volatile unsigned char *)report)[byte] =
                (unsigned char)(original ^ (original & (1U << (bit & 7U))));
            count = layout->button_count;
        }
    } while ((index & 255U) < count);
}

/* Native entry: 0x42038d30. */
/* Original function-byte SHA-256:
 * dd8d733caa309ac90d69b465ece0d0f6f4e68b0d958438f690cdc29c638b27f7. */
/* Service capture flags, stamp queue, baseline, normalization and learned period,
 * in that priority order. Successful store attempts and actual stamp service
 * return immediately; rejected gates may advance to a later class. Store
 * admission requires no primary/secondary activity, no simultaneous render
 * bits0/2 (read separately), no button overrides, and signed wrapped idle age
 * >=200000us. Clock and last-input snapshots are fresh at each stage.
 *
 * Pending capture flag is tested BEFORE its two fenced identity HALFWORDs.
 * A zero identity pair is cleared even when activity/idle gates reject it.
 * Nonzero pair stays pending through rejection. Store failure increments its
 * retry BYTE modulo256; below8 retain pending and return. At8..255 reset count,
 * warn, clear pending and return. Success resets count then clears pending.
 * Queued stamps use short-circuit activity/render/override checks and return
 * immediately after the stamp service, even if that service did no NVS work.
 *
 * Other stages have separate lock/gate paths. Initial dirty-flag pruning
 * short-circuits three fenced BYTE reads. Baseline takes optional rewrite
 * mutex before rechecking its dirty flag. Even activity-rejected baseline and
 * normalization paths still call override helper and clock, then fence/read
 * last-input LOW/HIGH. Period's activity-rejected path reads HIGH/LOW instead.
 * Later age/render rejection reloads the release mutex; eligible normalization
 * and period paths instead keep the handle sampled after the idle-time
 * reads and BEFORE the final age/render rejection checks. An absent
 * release handle after certain baseline rejections enters normalization work
 * without another take; the dedicated label retains that native distinction.
 * No take/give result is checked; handles may differ between acquire/release.
 *
 * Eligible baseline requires live enabled/updated, cached layout and expected
 * length1..64; copy report locally, clear numeric fields then buttons. Snapshot
 * release handle BEFORE fenced active identities, clear dirty BEFORE release
 * and store. Normalization rechecks dirty/enabled/layout, clears dirty even
 * when output_count0, otherwise saves one/two current normalization BYTEs.
 * Period rechecks pending then tests learned WORD, reads it AGAIN, reads both
 * identities and clears pending before releasing and saving LOW16(period).
 *
 * Baseline/normalization failures increment/store separate retry BYTEs; below8
 * rearm their flag under a newly sampled optional mutex, with release handle
 * read BEFORE the fenced flag1 store. At8..255 clear count and warn without
 * rearming. Period uses the same policy; success or exhausted retries also
 * publishes one fenced active-threshold WORD:500 below the nearest1000us
 * boundary of LOW16(period)+500, minimum500. Pending flag remains cleared.
 * There is no false temporary threshold500 store, duplicated rearm store,
 * early identity snapshot or discarded busy-path sampling as in raw Ghidra.
 * Static behavior reconstruction; no hardware, timing, durability or mutex
 * lifetime/concurrency equivalence is claimed. */
void profile_persistence_service(void)
{
    memw();
    if (INPUT_IDENTITY_PENDING != 0) {
        memw();
        unsigned short identity_first = INPUT_PENDING_IDENTITY[1];
        memw();
        unsigned short identity_second = INPUT_PENDING_IDENTITY[0];
        if (input_has_primary_activity(INPUT0_STATE) != 0 ||
            input_has_secondary_activity(INPUT0_STATE) != 0)
            goto capture_not_ready;
        if (profile_render_blocks_store() != 0 ||
            input_has_button_overrides(INPUT0_STATE) != 0)
            goto capture_not_ready;
        if (profile_sample_idle_age() < 200000)
            goto capture_not_ready;
        if ((identity_first | identity_second) == 0)
            goto capture_not_ready;
        if (profile_store_capture_flag(identity_first,identity_second) != 0) {
            PROFILE_RETRIES.capture_flag = 0;
        } else {
            unsigned char failures = (unsigned char)(PROFILE_RETRIES.capture_flag + 1U);
            if (failures < 8) {
                PROFILE_RETRIES.capture_flag = failures;
                return;
            }
            PROFILE_RETRIES.capture_flag = 0;
            unsigned int timestamp = esp_log_timestamp();
            esp_log_write(2,"usbdev","W (%lu) %s: persist dropped: NVS refused it %u times running\n",
                timestamp,"usbdev",8);
        }
        memw();
        INPUT_IDENTITY_PENDING = 0;
        return;
capture_not_ready:
        if ((identity_first | identity_second) == 0) {
            memw();
            INPUT_IDENTITY_PENDING = 0;
        }
    }
    if (profile_stamp_pending() != 0 &&
        input_has_primary_activity(INPUT0_STATE) == 0 &&
        input_has_secondary_activity(INPUT0_STATE) == 0 &&
        profile_render_blocks_store() == 0 &&
        input_has_button_overrides(INPUT0_STATE) == 0 &&
        profile_sample_idle_age() >= 200000) {
        profile_process_pending_stamp();
        return;
    }
    memw();
    if (PROFILE_BASELINE_PENDING == 0) {
        memw();
        if (PROFILE_NORMALIZATION_PENDING == 0) {
            memw();
            if (PROFILE_PERIOD_PENDING == 0)
                return;
        }
    }
    volatile FixedInputBinding *primary = FIXED_INPUTS;
    RtosQueue *mutex = REWRITE_MUTEX;
    if (mutex != NULL)
        xQueueSemaphoreTake(mutex,0xffffffffU);
    memw();
    if (PROFILE_BASELINE_PENDING == 0) {
        mutex = REWRITE_MUTEX;
        if (mutex != NULL)
            xQueueGenericSend(mutex,NULL,0,0);
        goto normalization_gate;
    }
    if (input_has_primary_activity(INPUT0_STATE) != 0 ||
        input_has_secondary_activity(INPUT0_STATE) != 0) {
        input_has_button_overrides(INPUT0_STATE);
        (void)profile_sample_idle_age();
        goto baseline_release_or_bypass;
    }
    unsigned int store_blocked = profile_render_blocks_store();
    store_blocked = (store_blocked | input_has_button_overrides(INPUT0_STATE)) & 255U;
    long long idle_age_us = profile_sample_idle_age();
    if (idle_age_us < 200000 || store_blocked != 0)
        goto baseline_release_or_bypass;
    if (primary->enabled == 0)
        goto baseline_release;
    memw();
    if (primary->updated == 0)
        goto baseline_release;
    const volatile HidReportLayout *layout = primary->state.hid_layout;
    unsigned int length = primary->expected_length;
    if (layout == NULL || length == 0)
        goto baseline_release;
    if (length > 64)
        goto baseline_release_or_bypass;
    unsigned char scratch[64];
    memcpy(scratch,(const void *)primary->last_input,length);
    report_clear_layout_bits((const BitClearLayout *)layout,scratch,length);
    profile_clear_button_bits(layout,scratch,length);
    mutex = REWRITE_MUTEX;
    memw();
    unsigned short identity_first = INPUT_ACTIVE_IDENTITY[1];
    memw();
    unsigned short identity_second = INPUT_ACTIVE_IDENTITY[0];
    memw();
    PROFILE_BASELINE_PENDING = 0;
    if (mutex != NULL)
        xQueueGenericSend(mutex,NULL,0,0);
    volatile unsigned char *retry_counter;
    volatile unsigned char *pending_flag;
    if (profile_store_baseline(identity_first,identity_second,scratch,(unsigned short)length) != 0) {
        PROFILE_RETRIES.baseline = 0;
        return;
    }
    retry_counter = &PROFILE_RETRIES.baseline;
    pending_flag = &PROFILE_BASELINE_PENDING;
    goto data_store_failed;

baseline_release_or_bypass:
    mutex = REWRITE_MUTEX;
    if (mutex == NULL)
        goto normalization_without_take;
    xQueueGenericSend(mutex,NULL,0,0);
    goto normalization_gate;
baseline_release:
    mutex = REWRITE_MUTEX;
    if (mutex != NULL)
        xQueueGenericSend(mutex,NULL,0,0);
normalization_gate:
    memw();
    if (PROFILE_NORMALIZATION_PENDING == 0)
        goto period_gate;
    mutex = REWRITE_MUTEX;
    if (mutex != NULL)
        xQueueSemaphoreTake(mutex,0xffffffffU);
    goto normalization_work;
normalization_without_take:
    memw();
    if (PROFILE_NORMALIZATION_PENDING == 0)
        goto period_gate;
normalization_work:
    if (input_has_primary_activity(INPUT0_STATE) != 0 ||
        input_has_secondary_activity(INPUT0_STATE) != 0) {
        input_has_button_overrides(INPUT0_STATE);
        (void)profile_sample_idle_age();
        goto normalization_release_reload;
    }
    store_blocked = profile_render_blocks_store();
    store_blocked = (store_blocked | input_has_button_overrides(INPUT0_STATE)) & 255U;
    idle_age_us = profile_sample_idle_age();
    mutex = REWRITE_MUTEX;
    if (idle_age_us < 200000 || store_blocked != 0)
        goto normalization_release_reload;
    memw();
    if (PROFILE_NORMALIZATION_PENDING == 0 || primary->enabled == 0)
        goto normalization_release_saved;
    layout = primary->state.hid_layout;
    if (layout == NULL)
        goto normalization_release_saved;
    unsigned int output_count = layout->output_count;
    memw();
    PROFILE_NORMALIZATION_PENDING = 0;
    if (output_count == 0)
        goto normalization_release_saved;
    scratch[0] = primary->state.primary_normalization_flags;
    if (output_count != 1)
        scratch[1] = primary->state.secondary_normalization_flags;
    memw();
    identity_first = INPUT_ACTIVE_IDENTITY[1];
    memw();
    identity_second = INPUT_ACTIVE_IDENTITY[0];
    if (mutex != NULL)
        xQueueGenericSend(mutex,NULL,0,0);
    if (profile_store_normalization(identity_first,identity_second,scratch,
            (unsigned short)(output_count < 2 ? output_count : 2)) != 0) {
        PROFILE_RETRIES.normalization = 0;
        return;
    }
    retry_counter = &PROFILE_RETRIES.normalization;
    pending_flag = &PROFILE_NORMALIZATION_PENDING;
    goto data_store_failed;
normalization_release_reload:
    mutex = REWRITE_MUTEX;
normalization_release_saved:
    if (mutex != NULL)
        xQueueGenericSend(mutex,NULL,0,0);

period_gate:
    memw();
    if (PROFILE_PERIOD_PENDING == 0)
        return;
    mutex = REWRITE_MUTEX;
    if (mutex != NULL)
        xQueueSemaphoreTake(mutex,0xffffffffU);
    if (input_has_primary_activity(INPUT0_STATE) != 0 ||
        input_has_secondary_activity(INPUT0_STATE) != 0) {
        input_has_button_overrides(INPUT0_STATE);
        esp_timer_get_time();
        memw();
        (void)primary->last_input_time.high;
        memw();
        (void)primary->last_input_time.low;
        goto period_release_reload;
    }
    store_blocked = profile_render_blocks_store();
    store_blocked = (store_blocked | input_has_button_overrides(INPUT0_STATE)) & 255U;
    idle_age_us = profile_sample_idle_age();
    mutex = REWRITE_MUTEX;
    if (idle_age_us < 200000 || store_blocked != 0)
        goto period_release_reload;
    memw();
    if (PROFILE_PERIOD_PENDING == 0)
        goto period_release_saved;
    memw();
    if (REPORT_LEARNED_PERIOD == 0)
        goto period_release_saved;
    memw();
    unsigned int saved_period = REPORT_LEARNED_PERIOD;
    memw();
    identity_first = INPUT_ACTIVE_IDENTITY[1];
    memw();
    identity_second = INPUT_ACTIVE_IDENTITY[0];
    memw();
    PROFILE_PERIOD_PENDING = 0;
    if (mutex != NULL)
        xQueueGenericSend(mutex,NULL,0,0);
    unsigned short stored_period = (unsigned short)saved_period;
    if (profile_store_period(identity_first,identity_second,stored_period) != 0) {
        PROFILE_RETRIES.period = 0;
    } else {
        unsigned char failures = (unsigned char)(PROFILE_RETRIES.period + 1U);
        PROFILE_RETRIES.period = failures;
        if (failures < 8) {
            mutex = REWRITE_MUTEX;
            if (mutex != NULL) {
                xQueueSemaphoreTake(mutex,0xffffffffU);
                mutex = REWRITE_MUTEX;
            }
            memw();
            PROFILE_PERIOD_PENDING = 1;
            if (mutex != NULL)
                xQueueGenericSend(mutex,NULL,0,0);
            return;
        }
        PROFILE_RETRIES.period = 0;
        unsigned int timestamp = esp_log_timestamp();
        esp_log_write(2,"usbdev","W (%lu) %s: persist dropped: NVS refused it %u times running\n",
            timestamp,"usbdev",8);
    }
    unsigned int rounded = (unsigned int)stored_period + 500U;
    unsigned int threshold = rounded < 1000 ? 500 : (rounded / 1000U) * 1000U - 500U;
    memw();
    REPORT_ACTIVE_THRESHOLD = threshold;
    return;
period_release_reload:
    mutex = REWRITE_MUTEX;
period_release_saved:
    if (mutex != NULL)
        xQueueGenericSend(mutex,NULL,0,0);
    return;

data_store_failed:
    unsigned char failures = (unsigned char)(*retry_counter + 1U);
    *retry_counter = failures;
    if (failures >= 8) {
        *retry_counter = 0;
        unsigned int timestamp = esp_log_timestamp();
        esp_log_write(2,"usbdev","W (%lu) %s: persist dropped: NVS refused it %u times running\n",
            timestamp,"usbdev",8);
        return;
    }
    mutex = REWRITE_MUTEX;
    if (mutex != NULL) {
        xQueueSemaphoreTake(mutex,0xffffffffU);
        mutex = REWRITE_MUTEX;
    }
    memw();
    *pending_flag = 1;
    if (mutex != NULL)
        xQueueGenericSend(mutex,NULL,0,0);
}
