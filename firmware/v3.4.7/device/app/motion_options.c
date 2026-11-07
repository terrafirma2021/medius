/* Device motion options: emission settings, runtime resets and persistence. */

#include "../include/types.h"

/* Native entry: 0x4203581c. */
/* Original function-byte SHA-256:
 * 6a383355125c22c5061ef3a1d87dc149c6d31f87a32aeae567c407ff8299187d. */
/* Writes optional opt-in, capacity/problem and imperfect-clone bytes, in that
 * order. A nonzero capacity flag yields exactly1; otherwise write the raw
 * secondary problem byte. No lock, barrier or coherent multi-field snapshot. */
void option_get_imperfect(unsigned char *allow,unsigned char *over_capacity,
    unsigned char *imperfect_clone)
{
    if (allow != NULL)
        *allow = IMPERFECT_FORWARDING_ALLOWED;
    if (over_capacity != NULL) {
        unsigned char problem = 1;
        if (CLONE_CAPACITY_EXCEEDED == 0)
            problem = CLONE_OTHER_PROBLEM;
        *over_capacity = problem;
    }
    if (imperfect_clone != NULL)
        *imperfect_clone = CLONE_IMPERFECT;
}

/* Native entry: 0x42035850. */
/* Original function-byte SHA-256:
 * 4c640319cf56f09217e0ee56934859cc203d64feb135e220a195993a5d8befa2. */
/* On a changed16-bit millisecond setting, optionally take the configuration
 * mutex forever, publish microseconds, clear LOW then HIGH riding time, reset
 * primary riding state and both shared histories, then notify the worker.
 * Reread/release the optional mutex before persisting key "o7". Take/send and
 * persistence results are ignored; an unchanged setting does nothing. */
void option_set_movement_riding(unsigned short window_ms)
{
    unsigned int window_us = (unsigned int)window_ms * 1000U;
    memw();
    if (MOVEMENT_RIDING_US == window_us)
        return;
    RtosQueue *mutex = REWRITE_MUTEX;
    if (mutex != NULL)
        xQueueSemaphoreTake(mutex,0xffffffffU);
    memw();
    MOVEMENT_RIDING_US = window_us;
    memw();
    MOTION_HISTORY.last_riding.low = 0;
    memw();
    MOTION_HISTORY.last_riding.high = 0;
    motion_reset_riding(MOTION_PRIMARY_STATE);
    memset((void *)MOTION_HISTORY.history16,0,16);
    memset((void *)MOTION_HISTORY.history32,0,32);
    motion_configuration_changed();
    mutex = REWRITE_MUTEX;
    if (mutex != NULL)
        xQueueGenericSend(mutex,NULL,0,0);
    (void)settings_store_u16("o7",window_ms);
}

/* Native entry: 0x420358f4. */
/* Original function-byte SHA-256:
 * b14a18c42b9d44cfafa1b916c75baa4ab2028ab8df34a43ab588da16e8c677f8. */
/* Accept coupled0/1 and LOW16(window_ms). On change, optionally lock forever,
 * publish window microseconds then coupling with separate preceding barriers,
 * clear shared histories and reset primary plus all auxiliary bearing states.
 * Auxiliary count is signed and reread after each904-byte-stride iteration.
 * Notify, reread/release the optional mutex, then persist "ob" and "oc".
 * All helper results are ignored; invalid coupling/unchanged settings return. */
void option_set_bearing(unsigned int window_ms,unsigned char coupled)
{
    if (coupled >= 2)
        return;
    unsigned short milliseconds = (unsigned short)window_ms;
    unsigned int window_us = (unsigned int)milliseconds * 1000U;
    memw();
    if (MOTION_OPTIONS.bearing_window_us == window_us) {
        memw();
        if (BEARING_COUPLED == coupled)
            return;
    }
    RtosQueue *mutex = REWRITE_MUTEX;
    if (mutex != NULL)
        xQueueSemaphoreTake(mutex,0xffffffffU);
    memw();
    MOTION_OPTIONS.bearing_window_us = window_us;
    memw();
    BEARING_COUPLED = coupled;
    memset((void *)MOTION_HISTORY.history16,0,16);
    memset((void *)MOTION_HISTORY.history32,0,32);
    (void)motion_reset_bearing(MOTION_PRIMARY_STATE);
    for (int index = 0; index < MOTION_AUX_COUNT; ++index)
        (void)motion_reset_bearing(&MOTION_AUX_STATES[index]);
    motion_configuration_changed();
    mutex = REWRITE_MUTEX;
    if (mutex != NULL)
        xQueueGenericSend(mutex,NULL,0,0);
    (void)settings_store_u16("ob",milliseconds);
    (void)settings_store_u16("oc",coupled);
}

/* Native entry: 0x420359e4. */
/* Original function-byte SHA-256:
 * f08deaf17a9352a7b9a6f57198ecef7cf0812a9b05a7a7a6836f65c84dd62ef0. */
/* Reject pace>2 with0. Publish pace FIRST; pace2 stores rate_hz capped1000,
 * with zero selecting1000. Narrow force_hz to16 bits and cap1000; a changed
 * forced setting is persisted as "od". Return1 only if an active clone's
 * newly derived served interval differs from its cached interval; otherwise0.
 * Recompute period from a fresh pace:1=learned microseconds,2=1e6/min(rate,1000)
 * (1000 when the first rate sample iszero),otherwise0. Native rate resampling
 * and barriers are retained, including the unchecked second division sample.
 * Notify then persist fresh pace/rate as "o8"/"o9". No local mutex or rollback;
 * persistence failures do not change the returned restart indication. */
unsigned int option_set_emit(unsigned char pace,unsigned short rate_hz,unsigned int force_hz)
{
    if (pace >= 3)
        return 0;
    memw();
    EMISSION_OPTIONS.pace = pace;
    if (pace == 2) {
        unsigned short rate = rate_hz == 0 ? 1000 : rate_hz < 1000 ? rate_hz : 1000;
        memw();
        EMISSION_OPTIONS.configured_hz = rate;
    }
    unsigned int forced = (unsigned short)force_hz;
    if (forced > 1000)
        forced = 1000;
    unsigned int restart = 0;
    memw();
    if (EMISSION_OPTIONS.forced_hz != forced) {
        memw();
        EMISSION_OPTIONS.forced_hz = (unsigned short)forced;
        (void)settings_store_u16("od",(unsigned short)forced);
        memw();
        if (CLONE_ACTIVE != 0) {
            unsigned int interval = clone_forced_interval();
            memw();
            restart = interval != EMISSION_OPTIONS.served_interval;
        }
    }
    memw();
    unsigned int current_pace = EMISSION_OPTIONS.pace;
    unsigned int period = 0;
    if (current_pace == 1) {
        memw();
        period = EMISSION_OPTIONS.learned_period_us;
    } else if (current_pace == 2) {
        memw();
        unsigned int first_rate = EMISSION_OPTIONS.configured_hz;
        period = 1000;
        if (first_rate != 0) {
            memw();
            unsigned int rate = EMISSION_OPTIONS.configured_hz;
            period = 1000000U / (rate < 1000U ? rate : 1000U);
        }
    }
    memw();
    EMISSION_OPTIONS.period_us = period;
    motion_configuration_changed();
    memw();
    unsigned short stored_pace = EMISSION_OPTIONS.pace;
    (void)settings_store_u16("o8",stored_pace);
    memw();
    unsigned short stored_rate = EMISSION_OPTIONS.configured_hz;
    (void)settings_store_u16("o9",stored_rate);
    return restart;
}

/* Native entry: 0x42035ad0. */
/* Original function-byte SHA-256:
 * d2295b3b5ba5976ab37c22161bf9fe4e3b5d1cdc60165d041275d3daee5212d4. */
/* Accept profile0..3/scope0..1 and return1 even when unchanged; invalid=>0.
 * On change publish profile then scope, notify, recompute emission period using
 * fresh pace/rate samples, notify AGAIN, send render-state1, then persist fresh
 * profile/scope as "or"/"os". Native read/barrier ordering matches set_emit's
 * calculation; no mutex, persistence rollback or delivery guarantee. */
unsigned int option_set_render(unsigned char profile,unsigned char scope)
{
    if (profile >= 4 || scope >= 2)
        return 0;
    memw();
    if (MOTION_OPTIONS.profile == profile) {
        memw();
        if (EMISSION_OPTIONS.scope == scope)
            return 1;
    }
    memw();
    MOTION_OPTIONS.profile = profile;
    memw();
    EMISSION_OPTIONS.scope = scope;
    motion_configuration_changed();
    memw();
    unsigned int pace = EMISSION_OPTIONS.pace;
    unsigned int period = 0;
    if (pace == 1) {
        memw();
        period = EMISSION_OPTIONS.learned_period_us;
    } else if (pace == 2) {
        period = 1000;
        memw();
        unsigned int first_rate = EMISSION_OPTIONS.configured_hz;
        if (first_rate != 0) {
            memw();
            unsigned int rate = EMISSION_OPTIONS.configured_hz;
            period = 1000000U / (rate < 1000U ? rate : 1000U);
        }
    }
    memw();
    EMISSION_OPTIONS.period_us = period;
    motion_configuration_changed();
    motion_send_render_state(1);
    memw();
    unsigned short stored_profile = MOTION_OPTIONS.profile;
    (void)settings_store_u16("or",stored_profile);
    memw();
    unsigned short stored_scope = EMISSION_OPTIONS.scope;
    (void)settings_store_u16("os",stored_scope);
    return 1;
}

/* Native entry: 0x42035ba0. */
/* Original function-byte SHA-256:
 * 480322d8d839c65f7fae33e090ec7ef153520dec9e69beefef3da0b4ec92fe45. */
/* Store any16-bit spread value, notify and persist "ot", even if unchanged.
 * Return1 regardless of persistence outcome. No local lock or barrier. */
unsigned int option_set_spread(unsigned short spread)
{
    MOTION_OPTIONS.spread = spread;
    motion_configuration_changed();
    (void)settings_store_u16("ot",spread);
    return 1;
}

/* Native entry: 0x42035bc4. */
/* Original function-byte SHA-256:
 * d0c67c30c1e5f1afdcd2369e2b138ad8e521eb3a3d8db7c13a8513446ea7bcc2. */
/* Optional byte outputs: profile,scope,then rendering-state bit1. Each requested
 * value has its own preceding MEMW; no whole-state atomic snapshot or lock. */
void option_get_render(unsigned char *profile,unsigned char *scope,unsigned char *armed)
{
    if (profile != NULL) {
        memw();
        *profile = MOTION_OPTIONS.profile;
    }
    if (scope != NULL) {
        memw();
        *scope = EMISSION_OPTIONS.scope;
    }
    if (armed != NULL) {
        memw();
        *armed = (MOTION_RENDER_STATE >> 1) & 1U;
    }
}

/* Native entry: 0x42035bf8. */
/* Original function-byte SHA-256:
 * a0ba5cc03260ec3a8ced2f62e1ab30b2ad60cb1b661d33259cf682e2cf39c784. */
/* Write optional outputs in native order: pace,configured rate,effective rate,
 * forced rate,forced-active BYTE,learned period. Effective rate uses one cached
 * period sample: round to milliseconds, then divide1000, capped by the native
 * sub-millisecond branch. The +500 addition wraps32 bits. A zero period yields
 * 1000 only if profile!=0 and render-state bit1; otherwise0. Separate barriers
 * and volatile reads supply individual samples, not an atomic snapshot. */
void option_get_emit(unsigned char *pace,unsigned short *rate_hz,
    unsigned short *effective_hz,unsigned short *force_hz,unsigned short *learned_period,
    unsigned char *forced_active)
{
    if (pace != NULL) {
        memw();
        *pace = EMISSION_OPTIONS.pace;
    }
    if (rate_hz != NULL) {
        memw();
        *rate_hz = EMISSION_OPTIONS.configured_hz;
    }
    if (effective_hz != NULL) {
        memw();
        unsigned int period = EMISSION_OPTIONS.period_us;
        unsigned int rate = 0;
        if (period == 0) {
            memw();
            if (MOTION_OPTIONS.profile != 0) {
                memw();
                if (((MOTION_RENDER_STATE >> 1) & 1U) != 0)
                    rate = 1000;
            }
        } else {
            unsigned int rounded = period + 500U;
            rate = rounded <= 999U ? 1000U : 1000U / (rounded / 1000U);
        }
        *effective_hz = (unsigned short)rate;
    }
    if (force_hz != NULL) {
        memw();
        *force_hz = EMISSION_OPTIONS.forced_hz;
    }
    if (forced_active != NULL) {
        memw();
        *forced_active = EMISSION_OPTIONS.served_interval != 0;
    }
    if (learned_period != NULL) {
        memw();
        *learned_period = EMISSION_OPTIONS.learned_period;
    }
}

/* Native entry: 0x42035ce4. */
/* Original function-byte SHA-256:
 * 0ca4b0ae51f21d66f9d68d59bdcae0d433033f2ffc220afefabe2e3cbbfd43b4. */
/* Read at most min(LOW16(length),32) printable ASCII bytes, stopping before
 * the first byte outside0x20..0x7e. Append NUL. Compare with RAM name BEFORE
 * taking the name spinlock; if different, copy the string under that lock,
 * unlock, then persist current RAM name as "oa". Empty input clears the name.
 * name may beNULL only when LOW16(length)==0; no local allocation/failure result.
 * Concurrent writers can race the comparison and unlocked persistence. */
void option_set_name(const unsigned char *name,unsigned int length)
{
    char cleaned[33];
    unsigned int copied = 0;
    unsigned int limit = (unsigned short)length;
    while (copied < limit && copied < 32) {
        unsigned int character = name[copied];
        if ((unsigned char)(character - 0x20U) > 0x5eU)
            break;
        cleaned[copied++] = (char)character;
    }
    cleaned[copied] = '\0';
    if (strcmp(cleaned,BOX_NAME) == 0)
        return;
    xPortEnterCriticalTimeout(BOX_NAME_LOCK,-1);
    memcpy(BOX_NAME,cleaned,(unsigned short)(copied + 1));
    vPortExitCritical(BOX_NAME_LOCK);
    (void)settings_store_string("oa",BOX_NAME);
}

/* Native entry: 0x42035d64. */
/* Original function-byte SHA-256:
 * 638180304e7c9cb80181d3711a455630d64f724654aa0bfed83764004a65e9a2. */
/* Under the name spinlock choose nonempty explicit name,else default. Copy up
 * to LOW16(capacity), return the count, and DO NOT appendNUL. Native reads the
 * next source byte before testing the capacity after each store. output must
 * cover the copied span; it may beNULL for capacity0. Lock result is ignored. */
unsigned int option_copy_name(char *output,unsigned int capacity)
{
    xPortEnterCriticalTimeout(BOX_NAME_LOCK,-1);
    const volatile char *source = BOX_NAME;
    char character = source[0];
    if (character == '\0') {
        source = BOX_DEFAULT_NAME;
        character = source[0];
    }
    unsigned int copied = 0,limit = (unsigned short)capacity;
    if (limit != 0 && character != '\0') {
        do {
            output[copied] = character;
            copied = (unsigned short)(copied + 1);
            character = source[copied];
            if (copied >= limit)
                break;
        } while (character != '\0');
    }
    vPortExitCritical(BOX_NAME_LOCK);
    return copied;
}

/* Native entry: 0x42035fa0. */
/* Original function-byte SHA-256:
 * 319a6277f46621fb688dad3e9910dcae24125a2ca7c15c7b65d3e8092893a715. */
/* Optional configured spread output is unfenced. With an effective output,
 * fence/read render-state bit0: active=>fenced cached duration; inactive=>0
 * unless observations>15 and interval<=126. Then use floor(interval*250*spread
 * /100), or0 if either factor iszero. The original64-bit reciprocal sequence
 * is exact unsigned division by100 in this bounded domain (product<2^31).
 * No lock, state update or timing guarantee; each requested field is sampled. */
void option_get_spread(unsigned short *configured,unsigned int *effective_duration)
{
    if (configured != NULL)
        *configured = MOTION_OPTIONS.spread;
    if (effective_duration == NULL)
        return;
    memw();
    unsigned int active = MOTION_RENDER_STATE & 1U;
    unsigned int duration = 0;
    if (active != 0) {
        memw();
        duration = MOTION_EFFECTIVE_SPREAD;
    } else if (SPREAD_OBSERVATIONS.observations > 15) {
        unsigned int interval = SPREAD_OBSERVATIONS.mode_bucket;
        if (interval <= 126) {
            unsigned int spread = MOTION_OPTIONS.spread;
            duration = interval * 250U * spread / 100U;
        }
    }
    *effective_duration = duration;
}

/* Native entry: 0x42026480. */
/* Original function-byte SHA-256:
 * d990d338f99b4f3cf3484849ab7c9c9fe6d47912c61d5ff50d0f9b5e6c8f01c3. */
/* Clear primary words+4..13, four riding words+28..37, then144 history bytes
 * +38..c7. Preserve every other byte. Requires writable motion state; no lock,
 * barrier, null check or return value. Byte ranges are views,not original types. */
void motion_reset_riding(MotionResetView *state)
{
    memset(state->primary_words,0,16);
    volatile MotionResetView *view = state;
    view->riding_words[0] = 0;
    view->riding_words[1] = 0;
    view->riding_words[2] = 0;
    view->riding_words[3] = 0;
    memset(state->riding_history,0,144);
}

/* Native entry: 0x42026fdc. */
/* Original function-byte SHA-256:
 * 0a03f7b55c724fba017f2c34ff9485651a5fba13a0299406625bb12e8012f89f. */
/* Clear eight signed axis-scale remainder words+150..16f, then bearing Y+174,
 * then X+170. Return the
 * interior address state+100; this is not a success code. Requires writable
 * state. No lock/barrier/null check; surrounding state bytes are preserved. */
unsigned char *motion_reset_bearing(MotionResetView *state)
{
    volatile MotionResetView *view = state;
    for (unsigned int index = 0; index < 8; ++index)
        view->axis_scale_remainders[index] = 0;
    view->bearing_remainder_y = 0;
    view->bearing_remainder_x = 0;
    return (unsigned char *)state + 0x100;
}

/* Native entry: 0x42029070. */
/* Original function-byte SHA-256:
 * 44acdd7c127ee5874ee9dac498e54d211af648209168cc9c730286ba431f18f0. */
/* Derive forced USB polling interval,not Hz:0 if imperfect opt-in isdisabled
 * or either of two independently fenced forced-Hz samples iszero. Otherwise
 * round1000/rate,cap128,choose a power of two by the native doubling loop and
 * enforce minimum16 only for low-speed byte==1,else1. For rates>2000 the loop
 * still yields1. No lock or writes; return fits a byte. */
unsigned int clone_forced_interval(void)
{
    if (IMPERFECT_FORWARDING_ALLOWED == 0)
        return 0;
    memw();
    if (EMISSION_OPTIONS.forced_hz == 0)
        return 0;
    memw();
    unsigned int rate = EMISSION_OPTIONS.forced_hz;
    if (rate == 0)
        return 0;
    unsigned int rounded = (1000U + (rate >> 1)) / rate;
    if (rounded > 128)
        rounded = 128;
    unsigned int interval = 1,next;
    do {
        next = (unsigned short)interval * 2U;
        if (next > rounded)
            break;
        interval = next;
    } while (1);
    unsigned int minimum = CLONE_LOW_SPEED == 1 ? 16U : 1U;
    return interval < minimum ? minimum : (unsigned char)interval;
}

/* Native entry: 0x40394a9c. */
/* Original function-byte SHA-256:
 * 30774afafe191334b8a0d95bc989e6857f4fc07267de72211c9f68f990ade55d. */
/* Always delegate atomic revision increment(+1,memory-model3),ignoring its old
 * value. If txwd task exists, detect ISR context, reread its handle, then OR
 * notification bit2 at index0. ISR path starts woken=0 and requests a switch
 * only if it becomes nonzero. Task path ignores notify result. No local lock,
 * allocation or barrier; atomic/notification ordering belongs to callees. */
void motion_configuration_changed(void)
{
    (void)atomic_fetch_add_u32(MOTION_REVISION,1,3);
    if (MOTION_TXWD_TASK == NULL)
        return;
    int in_isr = xPortInIsrContext();
    RtosTask *task = MOTION_TXWD_TASK;
    if (in_isr != 0) {
        int woken = 0;
        xTaskGenericNotifyFromISR(task,0,2,1,NULL,&woken);
        if (woken != 0)
            _frxt_setup_switch();
    } else {
        xTaskGenericNotify(task,0,2,1,NULL);
    }
}

/* Native entry: 0x42029bd0. */
/* Original function-byte SHA-256:
 * 49f5dfc4983c6018e767c4caf221d171f9687dfb34fa06f66ce60d12ceea92c0. */
/* Fence/test render-state bit0. When active,send opcode3a,sequence0,payload2:
 * little-endian LOW16(state | (token<<8)). Successful send (return0) publishes
 * LOW8(2-state),with a preceding MEMW; failure/inactive leaves ACK unchanged.
 * state is a full unsigned WORD, not clamped to0/1 or masked before
 * OR,although only the low halfword is sent. No retry,lock or delivery proof. */
void motion_send_render_state(unsigned int state)
{
    memw();
    if ((MOTION_RENDER_STATE & 1U) == 0)
        return;
    unsigned short payload = (unsigned short)(state | ((unsigned int)MOTION_RENDER_TOKEN << 8));
    if (motion_link_send(0x3a,0,&payload,2) != 0)
        return;
    unsigned char acknowledged = (unsigned char)(2U - state);
    memw();
    MOTION_RENDER_ACK = acknowledged;
}

/* Native entry: 0x420355e8. */
/* Original function-byte SHA-256:
 * 3f9d000cc6ea7bd8e9f57034560154e0455d0af171eb6ef7b8c1d2cf071def6b. */
/*
 * Set raw low8 imperfect option. Equal current BYTE returns0 without work;
 * otherwise publish it before persisting key"imperf", ignoring store result.
 * Disabling optionally takes rewrite mutex forever (result ignored), snapshots
 * rewrite count and clears the complete0xe08-byte rules/pool/count block.
 * Remove each packet trigger with consume bit1, shifting following48-byte
 * records left, lowering count and zeroing the vacated slot. For remaining
 * entries recompute run-edge(bit2) count and sum match_length BYTEs modulo65536.
 * Reconsider the same index after deletion; skipped indices/removal count wrap8.
 * No local table-count validation; stored admission invariants are required.
 * Drop all queued clip records: read pending count and prior drop counter,
 * snapshot write cursor, cache release mutex, then copy cursor to read cursor,
 * zero pending and add drops modulo65536. Clearing rules/removing triggers or
 * dropping records marks input changed. Release cached mutex if present.
 *
 * Then, with a newly sampled optional mutex, test patch refresh; fence/set
 * refresh-pending1 if needed. A missing mutex skips both take and, when no
 * refresh is needed, release reload. Other paths release a current handle.
 * Return1 for any degradation or active clone with forced interval different
 * from served interval; this happens BEFORE incrementing change epoch. Otherwise
 * changed input increments the HALFWORD epoch under another optional take,
 * caching its release handle BEFORE epoch read/increment/store, then returns0.
 * No re-clone/reboot is done here, no mutex/store errors are surfaced, and none
 * of the phases form a coherent whole-operation transaction or guarantee progress.
 */
unsigned int option_set_imperfect(unsigned char allow)
{
    if (IMPERFECT_FORWARDING_ALLOWED == allow) return 0;
    REWRITE_ALLOWED = allow;
    (void)settings_store_flag("imperf",allow);
    bool changed = false;
    RtosQueue *mutex;
    if (allow == 0) {
        mutex = REWRITE_MUTEX;
        if (mutex != 0) (void)xQueueSemaphoreTake(mutex,0xffffffffU);
        unsigned char previous_rewrites = REWRITE_COUNT;
        memset(IMPERFECT_REWRITE_STORAGE,0,0xe08);
        volatile ClipPacketTriggerTable *triggers = CLIP_PACKET_TRIGGER_TABLE;
        unsigned int count = triggers->count;
        unsigned char removed = 0,index = 0;
        if (count != 0) {
            do {
                if ((triggers->records[index].flags & 2U) == 0) {
                    index = (unsigned char)(index + 1U);
                    count = triggers->count;
                } else {
                    for (unsigned int next = (unsigned int)index + 1U; next < count; ++next)
                        memcpy((ClipPacketTrigger *)&triggers->records[next - 1U],
                            (const ClipPacketTrigger *)&triggers->records[next],48);
                    unsigned char last = (unsigned char)(count - 1U);
                    triggers->count = last;
                    memset((ClipPacketTrigger *)&triggers->records[last],0,48);
                    triggers->run_edge_count = 0;
                    count = triggers->count;
                    triggers->total_match_length = 0;
                    if (count == 0) {
                        removed = (unsigned char)(removed + 1U);
                        break;
                    }
                    unsigned char edge_count = 0;
                    unsigned short total = 0;
                    bool has_edges = false;
                    for (unsigned int remaining = 0; remaining < count; ++remaining) {
                        unsigned char flags = triggers->records[remaining].flags;
                        if ((flags & 4U) != 0) {
                            edge_count = (unsigned char)(edge_count + 1U);
                            has_edges = true;
                        }
                        total = (unsigned short)(total + triggers->records[remaining].match_length);
                    }
                    triggers->total_match_length = total;
                    if (has_edges) triggers->run_edge_count = edge_count;
                    removed = (unsigned char)(removed + 1U);
                }
            } while (index < count);
        }
        unsigned char cleared = previous_rewrites | removed;
        volatile ImperfectClipQueue *queue = IMPERFECT_CLIP_QUEUE;
        unsigned short pending = queue->pending_count;
        unsigned short dropped = IMPERFECT_CLIP_DROPPED;
        unsigned int write_cursor = queue->write_cursor;
        mutex = REWRITE_MUTEX;
        queue->read_cursor = write_cursor;
        queue->pending_count = 0;
        IMPERFECT_CLIP_DROPPED = (unsigned short)(dropped + pending);
        changed = cleared != 0 || pending != 0;
        if (mutex == 0) goto refresh_without_mutex;
        (void)xQueueGenericSend(mutex,0,0,0);
    }
    mutex = REWRITE_MUTEX;
    if (mutex == 0) goto refresh_without_mutex;
    (void)xQueueSemaphoreTake(mutex,0xffffffffU);
    if (descriptor_patches_need_refresh() != 0) {
        memw(); IMPERFECT_PATCH_REFRESH = 1;
    }
    goto release_refresh;
refresh_without_mutex:
    if (descriptor_patches_need_refresh() == 0) goto check_clone;
    memw(); IMPERFECT_PATCH_REFRESH = 1;
release_refresh:
    mutex = REWRITE_MUTEX;
    if (mutex != 0) (void)xQueueGenericSend(mutex,0,0,0);
check_clone:
    if (clone_degradation_status() != 0) return 1;
    memw();
    if (CLONE_ACTIVE != 0) {
        unsigned int desired_interval = clone_forced_interval();
        memw();
        if (desired_interval != IMPERFECT_SERVED_INTERVAL) return 1;
    }
    if (changed) {
        mutex = REWRITE_MUTEX;
        if (mutex == 0) {
            unsigned short epoch = INPUT_CHANGE_EPOCH;
            INPUT_CHANGE_EPOCH = (unsigned short)(epoch + 1U);
        } else {
            (void)xQueueSemaphoreTake(mutex,0xffffffffU);
            mutex = REWRITE_MUTEX;
            unsigned short epoch = INPUT_CHANGE_EPOCH;
            INPUT_CHANGE_EPOCH = (unsigned short)(epoch + 1U);
            if (mutex != 0) (void)xQueueGenericSend(mutex,0,0,0);
        }
    }
    return 0;
}
