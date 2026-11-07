/* Device input timer: queued actions, playback, report emission and idle checks. */
#include "../include/types.h"

/* Local reconstruction utilities: inline phases of native 0x42031518.
 * They do not add native entries or supply a hardware timing guarantee. */
/* Join the low and high 32-bit words of one sampled timestamp.
 * Returns the unsigned 64-bit value; this does not sample or synchronize memory. */
static __inline__ __attribute__((always_inline))
unsigned long long input_timer_time(unsigned int low,unsigned int high)
{
    return ((unsigned long long)high << 32) | low;
}

/* Drain the live byte-counted action queue. No arguments or result.
 * Reload the count after each action; disabled iterations retain the last
 * eligible result. Clear playback time only for that result, then timestamp
 * this nonempty drain. Empty queues do not update the action timestamp. */
static __inline__ __attribute__((always_inline))
void input_timer_drain_actions(void)
{
    if (PLAYBACK_ACTION_COUNT == 0) return;
    const volatile unsigned char *cursor = PLAYBACK_ACTIONS;
    unsigned int last_result = 0;
    do {
        memw();
        if (REPORT_FAST_ENABLED != 0) {
            unsigned char action = *cursor;
            unsigned int result = playback_apply_action(action);
            memw();
            last_result = PLAYBACK_ACTIVE;
            if (last_result != 0) {
                last_result = result;
                if (result == 0) {
                    action = *cursor;
                    last_result = (unsigned char)(action - 3U) <= 1;
                }
            }
        }
        ++cursor;
        unsigned char count = PLAYBACK_ACTION_COUNT;
        if ((unsigned char)((unsigned int)cursor - (unsigned int)PLAYBACK_ACTIONS) >= count)
            break;
    } while (1);
    PLAYBACK_ACTION_COUNT = 0;
    /* This is the last eligible action's result, not an OR across the queue. */
    if (last_result != 0) {
        PLAYBACK_TIME.low = 0;
        PLAYBACK_TIME.high = 0;
    }
    unsigned long long now_us = (unsigned long long)esp_timer_get_time();
    PLAYBACK_ACTION_TIME.low = (unsigned int)now_us;
    PLAYBACK_ACTION_TIME.high = (unsigned int)(now_us >> 32);
}

/* Choose the playback interval in microseconds from live enabled/period state.
 * Returns 900 on the native fallback paths, otherwise rounds the wrapped
 * 32-bit period-plus-500 to a millisecond boundary minus 500 (minimum 500).
 * Preserve the separate configured-period and learned-period reads. */
static __inline__ __attribute__((always_inline))
unsigned int input_timer_playback_period(void)
{
    unsigned char primary_enabled = FIXED_INPUTS[0].enabled;
    if (primary_enabled == 0) {
        memw();
        if (EMISSION_OPTIONS.period_us == 0) return 900;
    }
    memw();
    unsigned int period = EMISSION_OPTIONS.period_us;
    if (period == 0) {
        memw();
        if (REPORT_LEARNED_PERIOD == 0) return 900;
        memw();
        period = REPORT_LEARNED_PERIOD;
    }
    unsigned int rounded = period + 500U;
    return rounded < 1000U ? 500U : (rounded / 1000U) * 1000U - 500U;
}

/* Return the next 11-bit USB frame epoch, or UINT_MAX when phase is unusable.
 * Hold CREDIT_LOCK across phase snapshots and signed ROM division by 1000.
 * Recovery age is a signed difference: negative ages pass the 3000-us gate.
 * Round a positive target offset upward to milliseconds after unlocking. */
static __inline__ __attribute__((always_inline))
unsigned int input_timer_frame_epoch(void)
{
    unsigned int epoch = 0xffffffffU;
    (void)xPortEnterCriticalTimeout(&CREDIT_LOCK,-1);
    if (USB_FRAME_PHASE.valid == 0) goto unlock;
    unsigned long long now_us = (unsigned long long)esp_timer_get_time();
    memw();
    unsigned int low = REPORT_RECOVERY_EPOCH.low;
    memw();
    unsigned int high = REPORT_RECOVERY_EPOCH.high;
    if ((low | high) == 0) goto unlock;
    /* Second native snapshot is HIGH/LOW, unlike the first LOW/HIGH pair. */
    memw();
    high = REPORT_RECOVERY_EPOCH.high;
    memw();
    low = REPORT_RECOVERY_EPOCH.low;
    if ((long long)(now_us - input_timer_time(low,high)) >= 3000LL) goto unlock;
    if (USB_FRAME_PHASE.recovery_mode >= 2) goto unlock;
    low = USB_FRAME_PHASE.reference_ns.low;
    high = USB_FRAME_PHASE.reference_ns.high;
    /* Keep this native ROM call inside the critical section. Expressing it
     * solely as C division lets GCC defer its pure libcall until after unlock. */
    long long (*volatile divide_signed)(long long,long long) =
        (long long (*)(long long,long long))0x4000225cU;
    unsigned long long reference_us = (unsigned long long)
        divide_signed((long long)input_timer_time(low,high),1000LL);
    unsigned int frame = USB_FRAME_PHASE.frame;
    vPortExitCritical(&CREDIT_LOCK);
    low = INPUT_TIMER_TARGET.low;
    high = INPUT_TIMER_TARGET.high;
    unsigned long long difference = input_timer_time(low,high) - reference_us;
    if ((long long)difference > 0) {
        long long rounded = (long long)(difference + 999ULL);
        unsigned int steps = (unsigned int)(rounded / 1000LL);
        frame = (unsigned short)(frame + steps);
    }
    return (frame + 1U) & 0x7ffU;
unlock:
    vPortExitCritical(&CREDIT_LOCK);
    return epoch;
}

/* Apply signed playback axes from the borrowed decoded entry at now_us.
 * Retain nonzero axes with their timestamps before selecting rendered, timed
 * or direct accumulation. Return touched bit 3 for direct/timed accumulation;
 * rendered queueing and disabled/absent motion return zero. The presence
 * test covers only the low three bytes of motion_presence. */
static __inline__ __attribute__((always_inline))
unsigned char input_timer_play_motion(volatile ClipDecodedEntry *entry,
    unsigned long long now_us)
{
    if (FIXED_INPUTS[0].enabled == 0) return 0;
    if ((entry->motion_presence & 0xffffffU) == 0) return 0;
    int axes[4];
    axes[0] = entry->x;
    axes[1] = entry->y;
    axes[2] = entry->wheel;
    axes[3] = entry->pan;
    for (unsigned int axis = 0; axis < 4; ++axis) {
        if (axes[axis] == 0) continue;
        memw(); FIXED_INPUTS[0].retained_motion[axis] = axes[axis];
        memw(); FIXED_INPUTS[0].retained_motion_time[axis].low = (unsigned int)now_us;
        memw(); FIXED_INPUTS[0].retained_motion_time[axis].high = (unsigned int)(now_us >> 32);
    }
    memw();
    QUERY_MOTION_RECENT_TIME = (unsigned int)now_us;
    memw();
    unsigned char render = MOTION_RENDER_STATE;
    unsigned char timed = PLAYBACK_TRANSFORMS.timed_motion;
    if ((render & 1U) != 0) {
        unsigned char flags = (unsigned char)((timed ^ 1U) | 0x80U);
        input_queue_motion(axes[0],axes[1],axes[2],axes[3],flags,(unsigned int)now_us);
        memw(); FIXED_INPUTS[0].extension_event_time.low = (unsigned int)now_us;
        memw(); FIXED_INPUTS[0].extension_event_time.high = (unsigned int)(now_us >> 32);
        memw(); MOTION_INJECTION_PENDING = 1;
        return 0;
    }
    if (timed != 0) {
        input_accumulate_timed_motion(INPUT0_STATE,(short)axes[0],(short)axes[1],
            (short)axes[2],(short)axes[3],now_us,0);
        input_update_idle_motion_anchor(now_us);
    } else {
        input_accumulate_motion(INPUT0_STATE,(short)axes[0],(short)axes[1],
            (short)axes[2],(short)axes[3]);
    }
    return 8;
}

/* Queue the entry's six-byte usage events into enabled fixed input states.
 * mask is the incoming touched-bit set; return it with admitted binding bits.
 * Reload the volatile count only after enqueueing. Unknown/disabled targets
 * retain the sampled count; native byte index wrap and unchecked bounds remain. */
static __inline__ __attribute__((always_inline))
unsigned char input_timer_play_usages(volatile ClipDecodedEntry *entry,unsigned char mask)
{
    unsigned char count = entry->usage_count;
    unsigned char index = 0;
    while (index < count) {
        const volatile ClipUsageChange *change =
            (const volatile ClipUsageChange *)
            ((unsigned int)entry + 18U + (unsigned int)index * 6U);
        unsigned char kind = change->target_kind;
        unsigned char action = change->value;
        unsigned short usage = change->usage;
        unsigned int binding;
        if (kind == 0) binding = 0;
        else if ((unsigned char)(kind - 1U) < 2) binding = kind == 1 ? 1U : 2U;
        else goto next;
        if (FIXED_INPUTS[binding].enabled != 0) {
            InputStateView *state = (InputStateView *)&FIXED_INPUTS[binding].state;
            input_enqueue_event(state,kind,usage,action);
            mask = (unsigned char)(mask | (1U << binding));
            count = entry->usage_count;
        }
next:
        index = (unsigned char)(index + 1U);
    }
    return mask;
}

/* Route the entry's variable-length raw packet records using epoch.
 * Advance over the full record before admission; count rejected imperfect
 * traffic and reload the entry count at the native query/router boundaries.
 * No result, allocation or additional bounds validation is supplied. */
static __inline__ __attribute__((always_inline))
void input_timer_play_packets(volatile ClipDecodedEntry *entry,unsigned int epoch)
{
    unsigned char count = entry->packet_count;
    const volatile unsigned char *cursor = entry->packet_records;
    unsigned char index = 0;
    while (index < count) {
        unsigned int high = cursor[3];
        unsigned int low = cursor[2];
        unsigned int length = (high << 8) | low;
        const unsigned char *payload = (const unsigned char *)cursor + 4;
        const volatile unsigned char *record = cursor;
        cursor = (const volatile unsigned char *)((unsigned int)payload + length);
        if (IMPERFECT_FORWARDING_ALLOWED == 0) {
            unsigned short dropped = IMPERFECT_CLIP_DROPPED;
            IMPERFECT_CLIP_DROPPED = (unsigned short)(dropped + 1U);
        } else {
            memw();
            if (REPORT_FAST_ENABLED != 0) {
                unsigned char direction = record[1];
                unsigned char endpoint = record[0];
                bool configured = usb_device_is_configured(0);
                count = entry->packet_count;
                if (configured && (unsigned char)(direction - 1U) < 2) {
                    raw_endpoint_route(endpoint,direction,payload,length,
                        (unsigned char *)&FIXED_OUTPUT_MASK,epoch);
                    count = entry->packet_count;
                }
            }
        }
        index = (unsigned char)(index + 1U);
    }
}

/* Append one control record to the imperfect-playback byte ring.
 * record supplies full_length encoded bytes; payload_length forms its prefix.
 * Narrow the copy length to 16 bits and preserve unsigned space arithmetic,
 * both wrap copies and the early prefix-cursor publication. On success reload
 * entry->control_count into *count before publishing the body cursor/count;
 * on rejection increment the error halfword and leave *count unchanged.
 * No result, lock, capacity repair or record validation is supplied here. */
static __inline__ __attribute__((always_inline))
void input_timer_queue_control(const unsigned char *record,unsigned int full_length,
    unsigned int payload_length,unsigned char *count,volatile ClipDecodedEntry *entry)
{
    volatile ImperfectClipQueue *queue = IMPERFECT_CLIP_QUEUE;
    unsigned int capacity = queue->capacity;
    unsigned int read_cursor = queue->read_cursor;
    unsigned int write_cursor = queue->write_cursor;
    unsigned int length = (unsigned short)full_length;
    if (capacity + read_cursor - write_cursor < length + 2U) goto rejected;
    unsigned int offset = (capacity - 1U) & write_cursor;
    unsigned int available = capacity - offset;
    unsigned char *base = queue->storage;
    unsigned int first = available < 2U ? available : 2U;
    unsigned short prefix = (unsigned short)((full_length & 255U) |
        (((payload_length + 9U) >> 8 & 255U) << 8));
    memcpy(base + offset,&prefix,first);
    if (available < 2U)
        memcpy(queue->storage,(unsigned char *)&prefix + first,2U - first);
    write_cursor = queue->write_cursor;
    capacity = queue->capacity;
    write_cursor += 2U;
    offset = (capacity - 1U) & write_cursor;
    available = capacity - offset;
    base = queue->storage;
    first = available < length ? available : length;
    queue->write_cursor = write_cursor;
    memcpy(base + offset,record,first);
    if (available < length)
        memcpy(queue->storage,record + first,length - first);
    write_cursor = queue->write_cursor;
    unsigned short pending = queue->pending_count;
    *count = entry->control_count;
    queue->write_cursor = write_cursor + length;
    queue->pending_count = (unsigned short)(pending + 1U);
    return;
rejected:
    {
        unsigned short errors = PLAYBACK_CONTROL_ERRORS;
        PLAYBACK_CONTROL_ERRORS = (unsigned short)(errors + 1U);
    }
}

/* Walk entry's control records and queue admitted records. No result.
 * Flag bit 7 uses a nine-byte record without reading payload-length bytes.
 * Advance by the full 32-bit length, but preserve the native 16-bit admission
 * test and queue-copy length, including their wrap cases. Counts refresh only
 * after successful queue publication; byte index wrap remains unchecked. */
static __inline__ __attribute__((always_inline))
void input_timer_play_controls(volatile ClipDecodedEntry *entry)
{
    unsigned char count = entry->control_count;
    const volatile unsigned char *cursor = entry->control_records;
    unsigned char index = 0;
    while (index < count) {
        unsigned int length,full_length;
        unsigned char flags = cursor[1];
        if ((flags & 0x80U) != 0) {
            length = 0;
            full_length = 9;
        } else {
            unsigned int high = cursor[8];
            unsigned int low = cursor[7];
            length = (high << 8) | low;
            full_length = length + 9U;
        }
        const unsigned char *record = (const unsigned char *)cursor;
        cursor = (const volatile unsigned char *)((unsigned int)cursor + full_length);
        if (IMPERFECT_FORWARDING_ALLOWED == 0) {
            unsigned short dropped = IMPERFECT_CLIP_DROPPED;
            IMPERFECT_CLIP_DROPPED = (unsigned short)(dropped + 1U);
        } else if ((flags & 0x80U) == 0 && (unsigned short)(length + 8U) > 509U) {
            unsigned short errors = PLAYBACK_CONTROL_ERRORS;
            PLAYBACK_CONTROL_ERRORS = (unsigned short)(errors + 1U);
        } else {
            input_timer_queue_control(record,full_length,length,&count,entry);
        }
        index = (unsigned char)(index + 1U);
    }
}

/* Process at most one normal entry at now_us using the supplied frame epoch.
 * Return touched bits 0..3; delay, starvation, stop/error and budget exhaustion
 * return zero. Delay-zero entries and retained rewinds share a 64-iteration
 * budget. Preserve decoder errors, underflow accounting and transform/control
 * release order; the decoded entry borrows the ring scratch storage. */
static __inline__ __attribute__((always_inline))
unsigned char input_timer_playback_step(unsigned long long now_us,unsigned int epoch)
{
    unsigned int remaining = PLAYBACK_PROGRESS;
    if (remaining != 0) {
        PLAYBACK_PROGRESS = remaining - 1U;
        return 0;
    }
    unsigned int budget = 64;
    do {
        ClipDecodedEntry entry;
        int decoded = clip_ring_decode_next(PLAYBACK_RING,&entry);
        if (decoded < 0) {
            unsigned int write_cursor = IMPERFECT_CLIP_QUEUE->write_cursor;
            PLAYBACK_MODE = 3;
            unsigned char applied = PLAYBACK_TRANSFORMS.applied;
            memw(); PLAYBACK_ACTIVE = 0;
            IMPERFECT_CLIP_QUEUE->read_cursor = write_cursor;
            IMPERFECT_CLIP_QUEUE->pending_count = 0;
            if (applied != 0) {
                playback_restore_transforms();
                PLAYBACK_TRANSFORMS.applied = 0;
            }
            playback_release_controls();
            return 0;
        }
        if (decoded == 0) {
            if (clip_ring_is_finalized(PLAYBACK_RING) &&
                clip_ring_at_end(PLAYBACK_RING)) {
                if (PLAYBACK_TRANSFORMS.repeat != 0) {
                    playback_release_controls();
                    clip_ring_rewind(PLAYBACK_RING);
                    PLAYBACK_PROGRESS = 0;
                    PLAYBACK_STATUS = 0;
                    continue;
                }
                playback_stop(0);
            } else if (PLAYBACK_STATUS == 0) {
                unsigned short underflows = PLAYBACK_UNDERFLOWS;
                PLAYBACK_STATUS = 1;
                PLAYBACK_UNDERFLOWS = (unsigned short)(underflows + 1U);
            }
            return 0;
        }
        if (PLAYBACK_TRANSFORMS.retain == 0)
            clip_ring_release_consumed(PLAYBACK_RING);
        PLAYBACK_STATUS = 0;
        volatile ClipDecodedEntry *view = &entry;
        if (view->is_delay != 0) {
            unsigned short ticks = view->delay_ticks;
            if (ticks == 0) continue;
            PLAYBACK_PROGRESS = ticks - 1U;
            return 0;
        }
        unsigned char mask = input_timer_play_motion(view,now_us);
        mask = input_timer_play_usages(view,mask);
        input_timer_play_packets(view,epoch);
        input_timer_play_controls(view);
        unsigned int steps = PLAYBACK_STEPS;
        PLAYBACK_STEPS = steps + 1U;
        return mask;
    } while (--budget != 0);
    return 0;
}

/* Return nonzero when the primary input has work that keeps the timer armed.
 * Test secondary activity, gated primary activity, pending output, rendered
 * motion and merge state in native order; preserve short-circuit reads. */
static __inline__ __attribute__((always_inline))
int input_timer_primary_work(void)
{
    if (input_has_secondary_activity(INPUT0_STATE)) return 1;
    memw();
    unsigned int riding = MOVEMENT_RIDING_US;
    if (riding == 0 && input_has_primary_activity(INPUT0_STATE)) return 1;
    if (FIXED_INPUTS[0].output_valid != 0) return 1;
    memw();
    if ((MOTION_RENDER_STATE & 4U) != 0) return 1;
    memw();
    return REPORT_MERGE_PENDING != 0;
}

/* Return nonzero for the first enabled fixed input with pending work.
 * Scan the three bindings in order and stop at the first match. */
static __inline__ __attribute__((always_inline))
int input_timer_any_fixed_pending(void)
{
    for (unsigned int index = 0; index < 3; ++index) {
        if (FIXED_INPUTS[index].enabled != 0 &&
            input_has_pending_work((const InputStateView *)&FIXED_INPUTS[index].state))
            return 1;
    }
    return 0;
}

/* Return nonzero only when both activity ages are signed-greater than 8000 us.
 * now_us is the caller's clock snapshot. Read extension LOW/HIGH with barriers
 * first; skip the action timestamp when that first age is still recent.
 * Signed subtraction preserves native wrap and future-timestamp behavior. */
static __inline__ __attribute__((always_inline))
int input_timer_idle_ages(unsigned long long now_us)
{
    memw(); unsigned int low = FIXED_INPUTS[0].extension_event_time.low;
    memw(); unsigned int high = FIXED_INPUTS[0].extension_event_time.high;
    if ((long long)(now_us - input_timer_time(low,high)) <= 8000LL) return 0;
    low = PLAYBACK_ACTION_TIME.low;
    high = PLAYBACK_ACTION_TIME.high;
    return (long long)(now_us - input_timer_time(low,high)) > 8000LL;
}

/* Recheck whether the armed timer can stop after its caller takes timer mutex.
 * Sample a fresh clock, optionally take rewrite mutex and resample work, USB
 * readiness, playback and ages. Keep the native mutex-pointer snapshots and
 * release order; clear armed only after releasing rewrite mutex. No result. */
static __inline__ __attribute__((always_inline))
void input_timer_recheck_idle(void)
{
    memw();
    if (INPUT_TIMER_ARMED == 0) return;
    unsigned long long now_us = (unsigned long long)esp_timer_get_time();
    RtosQueue *mutex = REWRITE_MUTEX;
    if (mutex != 0) (void)xQueueSemaphoreTake(mutex,0xffffffffU);
    int pending = 0;
    if (FIXED_INPUTS[0].interface >= 0 && FIXED_INPUTS[0].enabled != 0) {
        memw();
        if (FIXED_INPUTS[0].last_input_valid != 0) {
            memw();
            if (USB_SUSPENDED == 0 && input_timer_primary_work()) {
                pending = 1;
                goto decide;
            }
        }
    }
    memw();
    if (USB_SUSPENDED == 0) pending = input_timer_any_fixed_pending();
decide:
    memw();
    if (REPORT_FAST_ENABLED != 0 && usb_device_is_configured(0)) {
        /* This pointer snapshot precedes the ACTIVE read, not the final give. */
        mutex = REWRITE_MUTEX;
        memw();
        if (PLAYBACK_ACTIVE != 0 || PLAYBACK_ACTION_COUNT != 0 ||
            pending || !input_timer_idle_ages(now_us)) {
            if (mutex != 0) (void)xQueueGenericSend(mutex,0,0,0);
            return;
        }
    }
    mutex = REWRITE_MUTEX;
    if (mutex != 0) (void)xQueueGenericSend(mutex,0,0,0);
    memw(); INPUT_TIMER_ARMED = 0;
}

/* Native entry: 0x42031518. */
/* Original function-byte SHA-256:
 * 52c9bde4ccd04ad40e271d1a0376cea2e9f0fc593114c8719841413af01d64d1. */
/*
 * t0 software-timer callback; argument is unused. Sample fast-enabled and bus0
 * configuration before an optional rewrite-mutex take; honor output reset,
 * then drain the live action queue. Actions update their timestamp only when
 * at least one was queued. Cache primary availability from signed interface
 * and enabled BYTE. Native phantom timestamp writes in Ghidra are omitted.
 *
 * A configured bus may process one due playback step with a phase-derived
 * frame epoch, ordinary input emission, and keyboard/consumer service. Decoder
 * delay0 and retained rewind paths share a budget64; a normal entry ends the
 * pass. Preserve delay countdown, status/error paths, timed/direct/rendered
 * axes, six-byte usage events, variable packet records and the control ring's
 * length/space/wrap rules. Each phase above names its native reads and stores.
 * Packet/control record counts are resampled at native call/publication points;
 * no nominal array bound is added. Control size arithmetic intentionally narrows
 * to16 bits before the native bounds/space checks, retaining oversized wrap cases.
 *
 * Primary force/epoch derives from touched bits0/3; keyboard/consumer epochs
 * derive from bits1/2. USB suspend skips playback/emission. Pending work,
 * active playback/actions or signed activity age<=8000us keeps the timer alive.
 * Otherwise perform a second idle check after dropping the rewrite mutex,
 * flushing pending output and taking the timer mutex (without a NULL guard).
 * This recheck samples fresh state/time, retakes rewrite mutex, and clears armed
 * only after releasing it when the device is unavailable or both ages are old.
 *
 * Finally fence/read armed, rearm t0 if nonzero, and give a freshly read timer
 * mutex. Ignore semaphore/timer results; preserve native lock order and lack
 * of rollback. No allocation or runtime timing/concurrency verification here.
 * This callback shares the configured ESP timer task; deadlines do not guarantee
 * execution time when that dispatcher or other required resources are busy.
 */
void input_timer_cb(void *unused_argument)
{
    (void)unused_argument;
    bool configured = false;
    memw();
    if (REPORT_FAST_ENABLED != 0) configured = usb_device_is_configured(0);
    RtosQueue *mutex = REWRITE_MUTEX;
    if (mutex != 0) (void)xQueueSemaphoreTake(mutex,0xffffffffU);
    memw();
    if (OUTPUT_RESET_PENDING != 0) input_reset_output_reports();
    input_timer_drain_actions();
    unsigned char primary_available = 0;
    if (FIXED_INPUTS[0].interface >= 0)
        primary_available = FIXED_INPUTS[0].enabled;
    int recheck_idle = 1;
    if (!configured) goto finish_processing;
    unsigned long long now_us = (unsigned long long)esp_timer_get_time();
    unsigned char touched = 0;
    unsigned int epoch = 0xffffffffU;
    memw();
    if (USB_SUSPENDED != 0) goto assess_primary;
    if (primary_available != 0) {
        memw();
        if (FIXED_INPUTS[0].last_input_valid == 0) goto assess_primary;
        memw();
        if (PLAYBACK_ACTIVE == 0) goto emit_primary;
    } else {
        memw();
        if (PLAYBACK_ACTIVE == 0) goto emit_other;
    }
    {
        unsigned int low = PLAYBACK_TIME.low;
        unsigned int high = PLAYBACK_TIME.high;
        long long age = (long long)(now_us - input_timer_time(low,high));
        unsigned int period_us = input_timer_playback_period();
        if (age >= (long long)period_us) {
            PLAYBACK_TIME.low = (unsigned int)now_us;
            PLAYBACK_TIME.high = (unsigned int)(now_us >> 32);
            epoch = input_timer_frame_epoch();
            touched = input_timer_playback_step(now_us,epoch);
        }
    }
    if (primary_available == 0) goto emit_other;
emit_primary:
    primary_input_emit(now_us,touched & 1U,(touched & 9U) != 0 ? epoch : 0xffffffffU);
emit_other:
    if (FIXED_INPUTS[1].enabled != 0 &&
        (input_needs_service((const InputStateView *)&FIXED_INPUTS[1].state) ||
         FIXED_INPUTS[1].output_valid != 0))
        fixed_input_service(1,(touched & 2U) != 0 ? epoch : 0xffffffffU);
    if (FIXED_INPUTS[2].enabled != 0 &&
        (input_needs_service((const InputStateView *)&FIXED_INPUTS[2].state) ||
         FIXED_INPUTS[2].output_valid != 0))
        fixed_input_service(2,(touched & 4U) != 0 ? epoch : 0xffffffffU);
assess_primary:
    if (primary_available != 0) {
        memw();
        if (FIXED_INPUTS[0].last_input_valid != 0) {
            memw();
            if (USB_SUSPENDED == 0 && input_timer_primary_work()) goto pending_work;
        }
    }
    memw();
    if (USB_SUSPENDED == 0 && input_timer_any_fixed_pending()) goto pending_work;
    memw();
    if (PLAYBACK_ACTIVE != 0 || PLAYBACK_ACTION_COUNT != 0) goto keep_armed;
    recheck_idle = input_timer_idle_ages(now_us);
    goto finish_processing;
pending_work:
    memw(); (void)PLAYBACK_ACTIVE;
keep_armed:
    recheck_idle = 0;
finish_processing:
    playback_control_try_start();
    mutex = REWRITE_MUTEX;
    if (mutex != 0) (void)xQueueGenericSend(mutex,0,0,0);
    input_flush_pending();
    (void)xQueueSemaphoreTake(INPUT_TIMER_MUTEX,0xffffffffU);
    if (recheck_idle) input_timer_recheck_idle();
    memw();
    if (INPUT_TIMER_ARMED != 0) input_timer_rearm();
    (void)xQueueGenericSend(INPUT_TIMER_MUTEX,0,0,0);
}
