/* Device INJECT/LOCK command routing and scale propagation. */
#include "../include/types.h"

/* Local reconstruction utilities: repeated inline LOCK emission branch,
 * not an additional firmware function or a synchronization guarantee. */
/* index: fixed keyboard/consumer slot selected by the LOCK caller.
 * Handle reset before testing the signed interface and separately fenced
 * input-valid/USB-suspend bytes; emit with the full UINT_MAX epoch when ready.
 * No allocation, returned status, lock admission or readiness snapshot.
 */
static __inline__ __attribute__((always_inline))
void lock_emit_fixed_if_ready(unsigned int index)
{
    volatile FixedInputBinding *binding = &FIXED_INPUTS[index];
    memw();
    if (OUTPUT_RESET_PENDING != 0) input_reset_output_reports();
    if (binding->interface < 0) return;
    memw();
    if (binding->last_input_valid == 0) return;
    memw();
    if (USB_SUSPENDED == 0) fixed_input_emit(index,0xffffffffU);
}

/* Native entry: 0x42028dc8. */
/* Original function-byte SHA-256:
 * 886896fedb7f04b99b6e5bf4bdb8fc2233ae6d6ccb1dd7525219cdff08f566c2. */
/*
 * Apply channel/selector/value to primary input scales, save its FULL WORD
 * handled-column mask, then apply the same request to each auxiliary state at
 * 904-byte stride. Cache the initial signed auxiliary count only for entry;
 * reload count after every auxiliary call BEFORE advancing index/pointer.
 * No count cap or low-byte narrowing of channel/selector is done here; the
 * underlying scale setter validates their LOW8 and signed16 value.
 *
 * Finally read playback scale-columns BYTE at the unchecked FULL channel index,
 * clear the primary handled bits, store LOW8 and return the full primary mask.
 * Auxiliary results are ignored. This is a handled mask, including unchanged
 * columns, rather than a claim that a value changed. No lock, fence, dirty mark
 * or task notification is local; caller serializes the state and valid storage.
 */
unsigned int input_set_motion_scale_group(unsigned int channel,
    unsigned int selector,short value)
{
    unsigned int handled = input_set_scale_group(INPUT0_STATE,channel,selector,value);
    int count = MOTION_AUX_COUNT;
    if (count > 0) {
        unsigned int index = 0;
        unsigned int address = (unsigned int)MOTION_AUX_STATES;
        for (;;) {
            (void)input_set_scale_group((InputStateView *)address,channel,selector,value);
            count = MOTION_AUX_COUNT;
            ++index;
            address += 904U;
            if ((int)index >= count) break;
        }
    }
    volatile unsigned char *retained_columns = (volatile unsigned char *)
        ((unsigned int)&PLAYBACK_TRANSFORMS.scale_columns[0] + channel);
    unsigned char previous = *retained_columns;
    *retained_columns = (unsigned char)(previous & ~handled);
    return handled;
}

/* Native entry: 0x420361c4. */
/* Original function-byte SHA-256:
 * 83f94332aaf02f9ac1b4736935168798f279cad128cb8c57988187e24e0de3be. */
/*
 * INJECT: input_class LOW8, usage LOW16, action LOW8. Class 1 selects keyboard,
 * class 2 consumer, every other class primary; pass the ORIGINAL class to event
 * admission, including unrecognized classes. Optionally take the initially
 * sampled rewrite mutex forever, ignoring status. An inactive selected binding
 * skips event/time updates. Only the initially non-NULL-mutex inactive path
 * reloads/gives a mutex; inactive primary still calls change-service(0).
 *
 * Active binding calls event admission with all four arguments, obtains a fresh
 * clock, then separately fences/stores its extension-event LOW/HIGH. Primary
 * computes changed from secondary activity, then fenced riding-window/primary
 * activity tests, falling back to pending work. Give a freshly sampled mutex
 * once if non-NULL, then run change-service after unlocking.
 *
 * Keyboard/consumer first service when needs_service and publication is not
 * blocked, with index and epoch UINT_MAX. Sample pending work, reload/give mutex,
 * and only if pending fence/read the coalesced-rearm BYTE. Clear means fence/
 * publish 1 BEFORE ensuring t0 is armed. No own action validation, event-result
 * handling, retry, armed rollback or guaranteed callback/USB delivery time.
 */
void inject_usage(unsigned char input_class,unsigned short usage,unsigned char action)
{
    unsigned int index = input_class == 1 ? 1U : input_class == 2 ? 2U : 0U;
    RtosQueue *mutex = REWRITE_MUTEX;
    int took_mutex_path = mutex != 0;
    if (mutex != 0) (void)xQueueSemaphoreTake(mutex,0xffffffffU);
    volatile FixedInputBinding *binding = &FIXED_INPUTS[index];
    unsigned char enabled = binding->enabled;
    if (enabled == 0) {
        if (took_mutex_path) {
            mutex = REWRITE_MUTEX;
            if (mutex != 0) (void)xQueueGenericSend(mutex,0,0,0);
        }
        if (index == 0) input_service_after_change(0);
        return;
    }
    InputStateView *state = (InputStateView *)&binding->state;
    input_enqueue_event(state,input_class,usage,action);
    unsigned long long now_us = (unsigned long long)esp_timer_get_time();
    memw();
    binding->extension_event_time.low = (unsigned int)now_us;
    memw();
    binding->extension_event_time.high = (unsigned int)(now_us >> 32);
    if (index == 0) {
        unsigned int changed;
        if (input_has_secondary_activity(state)) {
            changed = 1;
        } else {
            memw();
            unsigned int riding_window = MOVEMENT_RIDING_US;
            if (riding_window == 0 && input_has_primary_activity(state))
                changed = 1;
            else
                changed = input_has_pending_work(state);
        }
        mutex = REWRITE_MUTEX;
        if (mutex != 0) (void)xQueueGenericSend(mutex,0,0,0);
        input_service_after_change(changed);
        return;
    }
    if (input_needs_service(state) && !input_publication_is_blocked(state))
        fixed_input_service(index,0xffffffffU);
    unsigned char pending = input_has_pending_work(state);
    mutex = REWRITE_MUTEX;
    if (mutex != 0) (void)xQueueGenericSend(mutex,0,0,0);
    if (pending == 0) return;
    memw();
    if (INPUT_REARM_COALESCED == 0) {
        memw();
        INPUT_REARM_COALESCED = 1;
        input_ensure_timer_armed();
    }
}

/* Native entry: 0x420365b4. */
/* Original function-byte SHA-256:
 * d325e309f31d08a166c1e8a35fd056e2521d12e7a39a86e92a81de798d17d2b3. */
/*
 * LOCK physical input: class/direction LOW8, usage LOW16, percent signed16.
 * Negative percent returns BEFORE taking a mutex except for axis class 3.
 * Cache below-100 enable flag and optionally take rewrite mutex forever,
 * ignoring status. For valid nonnegative input, percent >= 100 restores controls;
 * the delegated scale helpers retain their own value/selector restrictions.
 *
 * Class 0 mouse buttons: require primary enabled. Below 100 needs a descriptor
 * and caps its BYTE button count to 16; restoration permits 16 with no descriptor.
 * Usage 0xffff applies all, otherwise one zero-based button; channels are button+4.
 * Each request includes the previously omitted percent argument. Whole-class
 * handled masks accumulate as BYTE; a single request retains its full return.
 * Only restoration with a nonzero handled mask marks primary changed and later
 * calls change-service(1), including requests whose values were already set.
 *
 * Class 3 axes: enabled primary and usage 0xffff selects 0..3, or usage < 4 selects one;
 * ignore returned masks. Class 1 keyboard: whole-class sets transform flags and
 * clears retained playback bits for direction 0/1/2, otherwise leaves the BYTE;
 * one key uses usage LOW8 and signed percent. A nonzero helper return marks
 * changed and may emit. Class 2 consumer: whole-class sets mode and clears its
 * retained playback BYTE; one usage sets its boolean transform. Always mark
 * changed after an active consumer request and conditionally emit.
 *
 * Keyboard/consumer emit only after needs_service, fenced output-reset handling,
 * signed interface>=0, fenced input-valid and fenced USB-not-suspended gate.
 * Every path after mutex admission, even invalid class/usage or disabled input,
 * calls motion-configuration-changed before a freshly sampled optional give,
 * then change-service(primary_restore_only). No local clock, timer, allocation,
 * rollback or synchronization/timing guarantee is invented.
 */
void lock_input(unsigned char input_class,unsigned short usage,
    unsigned char direction,short percent)
{
    if (percent < 0 && input_class != 3) return;
    unsigned char enable = percent < 100;
    RtosQueue *mutex = REWRITE_MUTEX;
    if (mutex != 0) (void)xQueueSemaphoreTake(mutex,0xffffffffU);
    unsigned int primary_restore = 0;
    if (input_class == 0) {
        if (FIXED_INPUTS[0].enabled == 0) goto finish;
        const volatile HidReportLayout *layout = FIXED_INPUTS[0].state.hid_layout;
        unsigned int limit;
        unsigned int handled = 0;
        if (percent < 100) {
            if (layout == 0) goto finish;
            unsigned char count = layout->button_count;
            limit = count < 16 ? count : 16;
            if (usage == 0xffffU && count == 0) goto finish;
        } else {
            limit = 16;
        }
        if (usage == 0xffffU) {
            for (unsigned int button = 0; button < limit; ++button) {
                unsigned int mask = input_set_motion_scale_group(button + 4U,direction,percent);
                handled = (unsigned char)(handled | mask);
            }
        } else {
            if (usage >= limit) goto finish;
            handled = input_set_motion_scale_group((usage + 4U) & 255U,direction,percent);
        }
        if (percent >= 100 && handled != 0) {
            FIXED_INPUTS[0].state.changed = 1;
            primary_restore = 1;
        }
    } else if (input_class == 3) {
        if (FIXED_INPUTS[0].enabled == 0) goto finish;
        if (usage == 0xffffU) {
            for (unsigned int axis = 0; axis < 4; ++axis)
                (void)input_set_motion_scale_group(axis,direction,percent);
        } else if (usage < 4) {
            (void)input_set_motion_scale_group(usage,direction,percent);
        }
    } else if (input_class == 1) {
        if (FIXED_INPUTS[1].enabled == 0) goto finish;
        InputStateView *state = (InputStateView *)&FIXED_INPUTS[1].state;
        unsigned int handled;
        if (usage == 0xffffU) {
            handled = input_set_keyboard_transform_flags(state,direction,enable);
            unsigned char mask = direction == 1 ? 0xfe : direction == 2 ? 0xfd :
                direction == 0 ? 0xfc : 0xff;
            unsigned char retained = PLAYBACK_TRANSFORMS.keyboard;
            PLAYBACK_TRANSFORMS.keyboard = retained & mask;
        } else {
            handled = input_set_key_transform(state,usage & 255U,direction,percent);
        }
        if (handled != 0) {
            FIXED_INPUTS[1].state.changed = 1;
            if (input_needs_service(state)) lock_emit_fixed_if_ready(1);
        }
    } else if (input_class == 2) {
        if (FIXED_INPUTS[2].enabled == 0) goto finish;
        InputStateView *state = (InputStateView *)&FIXED_INPUTS[2].state;
        if (usage == 0xffffU) {
            input_set_transform_mode(state,enable);
            PLAYBACK_TRANSFORMS.consumer = 0;
        } else {
            input_set_consumer_transform(state,(short)usage,enable);
        }
        FIXED_INPUTS[2].state.changed = 1;
        if (input_needs_service(state)) lock_emit_fixed_if_ready(2);
    }
finish:
    motion_configuration_changed();
    mutex = REWRITE_MUTEX;
    if (mutex != 0) (void)xQueueGenericSend(mutex,0,0,0);
    input_service_after_change(primary_restore);
}
