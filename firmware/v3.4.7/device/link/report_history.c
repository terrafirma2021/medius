/* Medius v3.4.7 device: recovered report history consumption and scheduling gates. */

#include "../include/types.h"

/* Native entry: 0x40377d1c. */
/* Original function-byte SHA-256:
 * d303d94949453c717b00315453b1da4a0947be32b241caedf282c77b0420bf5f. */

/*
 * Consumes one report-history entry and optionally updates delay statistics.
 *
 * queue: live, writable 960-byte interface view.
 * now_us: caller's 64-bit time sample.
 * update_statistics: only a low byte of 1 permits statistics; other values
 * still consume history. Returns no value. Caller supplies serialization.
 * The former apparent endpoint argument was unused Xtensa alignment padding.
 *
 * Fence/read write, fence/read read; equal returns. Repeat both snapshots and
 * cache sample_mode before checking their difference. Difference>4 reads the
 * read counter twice more with fences, discards the first, clears pending_start
 * LOW/HIGH and fences/publishes second+1, then returns. No statistics update.
 * A difference of 1..4 fences/reloads the index and loads the timestamp HIGH,
 * then LOW. HIGH=0xc0000000 with LOW=0 suppresses statistics. If the second pair
 * became equal, uses LOW=0 and no sentinel instead of returning early.
 *
 * Another fenced read chooses sample byte when cached sample_mode!=0; that
 * counter read occurs even when sampling disabled. Another fenced read supplies
 * the increment, pending_start LOW/HIGH are cached and cleared, then a fence
 * precedes read-counter publication. Only afterward is the statistics gate used.
 *
 * For nonzero pending_start <= now (signed 64-bit), delay is LOW32(now-start).
 * First matching
 * nonempty ID bucket wins. Otherwise prefer the LAST empty bucket, or the oldest
 * signed-HIGH/unsigned-LOW timestamp among filled buckets. Minimum delay is at
 * least 1; hits grow only below 32. A lower matching minimum reloads hit count;
 * other matching paths use its cached count. A new delay of 0xffffffff keeps
 * that minimum and initializes hits to 1. Updates chosen last-seen LOW/HIGH.
 * Always on the statistics path: cache old running minimum before last-history
 * LOW/HIGH stores, reduce by LOW32(now-history), and publish effective minimum.
 * A hit count below 32 increments; effective delay is capped at 25 until the
 * new count reaches 32.
 * No clock call, allocation, wake, bounds repair or atomic multi-read snapshot.
 * Counter arithmetic wraps at 32 bits; configured storage and external locking
 * are required. Native stale/sentinel/overflow paths are retained.
 */
void report_history_retire(CreditInterfaceQueue *queue,
    unsigned long long now_us,unsigned int update_statistics)
{
    volatile CreditInterfaceQueue *queue_state = queue;
    memw();
    unsigned int first_write = queue_state->history_write_count;
    memw();
    unsigned int first_read = queue_state->history_read_count;
    if (first_write == first_read)
        return;
    memw();
    unsigned int write_snapshot = queue_state->history_write_count;
    memw();
    unsigned int read_snapshot = queue_state->history_read_count;
    unsigned char sample_mode = queue_state->sample_mode;
    unsigned int available = write_snapshot - read_snapshot;
    unsigned int history_low;
    unsigned int invalid_timestamp;
    if (write_snapshot == read_snapshot) {
        history_low = available;
        invalid_timestamp = available;
    } else {
        if (available > 4) {
            memw();
            (void)queue_state->history_read_count;
            memw();
            unsigned int skipped_read = queue_state->history_read_count;
            queue_state->pending_start.low = 0;
            queue_state->pending_start.high = 0;
            memw();
            queue_state->history_read_count = skipped_read + 1U;
            return;
        }
        memw();
        unsigned int timestamp_index = queue_state->history_read_count & 3U;
        unsigned int history_high = queue_state->history_time[timestamp_index].high;
        history_low = queue_state->history_time[timestamp_index].low;
        invalid_timestamp = history_high == 0xc0000000U && history_low == 0;
    }
    unsigned int skip_statistics = (invalid_timestamp | (update_statistics ^ 1U)) & 255U;
    memw();
    unsigned int sample_index = queue_state->history_read_count;
    unsigned char sample = sample_mode != 0 ? queue_state->history_sample[sample_index & 3U] : 0;
    memw();
    unsigned int next_read = queue_state->history_read_count + 1U;
    unsigned int pending_low = queue_state->pending_start.low;
    unsigned int pending_high = queue_state->pending_start.high;
    queue_state->pending_start.low = 0;
    queue_state->pending_start.high = 0;
    memw();
    queue_state->history_read_count = next_read;
    if (skip_statistics != 0)
        return;
    unsigned int now_low = (unsigned int)now_us;
    unsigned int now_high = (unsigned int)(now_us >> 32);
    if ((pending_low | pending_high) != 0 &&
        ((int)pending_high < (int)now_high ||
         (pending_high == now_high && pending_low <= now_low))) {
        unsigned int delay = now_low - pending_low;
        unsigned int selected = 0;
        for (unsigned int index = 0; index < 4; ++index) {
            unsigned char hits = queue_state->minimum_hits[index];
            if (hits == 0) {
                selected = index;
                continue;
            }
            if (queue_state->minimum_ids[index] == sample) {
                if (delay < queue_state->minimum_delay_by_id[index]) {
                    queue_state->minimum_delay_by_id[index] = delay != 0 ? delay : 1;
                    hits = queue_state->minimum_hits[index];
                }
                if (hits < 32)
                    queue_state->minimum_hits[index] = hits + 1U;
                queue_state->minimum_last_seen[index].low = now_low;
                queue_state->minimum_last_seen[index].high = now_high;
                goto running_minimum;
            }
            if (queue_state->minimum_hits[selected] != 0) {
                unsigned int current_high = queue_state->minimum_last_seen[index].high;
                unsigned int selected_high = queue_state->minimum_last_seen[selected].high;
                if ((int)current_high < (int)selected_high) {
                    selected = index;
                } else if (current_high == selected_high) {
                    unsigned int current_low = queue_state->minimum_last_seen[index].low;
                    unsigned int selected_low = queue_state->minimum_last_seen[selected].low;
                    if (current_low < selected_low)
                        selected = index;
                }
            }
        }
        queue_state->minimum_ids[selected] = sample;
        queue_state->minimum_hits[selected] = 0;
        queue_state->minimum_delay_by_id[selected] = 0xffffffffU;
        unsigned char hits;
        if (delay == 0xffffffffU) {
            hits = 1;
        } else {
            queue_state->minimum_delay_by_id[selected] = delay != 0 ? delay : 1;
            hits = queue_state->minimum_hits[selected];
            if (hits >= 32)
                goto bucket_timestamp;
            ++hits;
        }
        queue_state->minimum_hits[selected] = hits;
bucket_timestamp:
        queue_state->minimum_last_seen[selected].low = now_low;
        queue_state->minimum_last_seen[selected].high = now_high;
    }
running_minimum:
    unsigned int running_minimum = queue_state->minimum_delay;
    queue_state->last_history_time.low = now_low;
    queue_state->last_history_time.high = now_high;
    unsigned int elapsed = now_low - history_low;
    if (elapsed < running_minimum) {
        queue_state->minimum_delay = elapsed;
        running_minimum = elapsed;
    }
    unsigned char hits = queue_state->history_hits;
    if (hits < 32) {
        ++hits;
        queue_state->history_hits = hits;
        if (hits != 32 && running_minimum > 25)
            running_minimum = 25;
    }
    queue_state->effective_delay = running_minimum;
}

/* Native entry: 0x40378ee0. */
/* Original function-byte SHA-256:
 * f2484ea3a7fb9904e8211c5139ef8d8d5d8003f2e7eadf0ecc6957ca32f1fb05. */

/*
 * Applies report score/history gates, then delegates eligible scheduling.
 *
 * queue: live interface view; selector must return a valid record or UINT_MAX.
 * allow_gating: zero bypasses preselection gates.
 * now_us: caller's 64-bit clock sample.
 * period: full word for length comparisons; low 16 bits reach the scheduler.
 * interface: forwarded unchanged. Returns no value.
 *
 * Does nothing when extra_pending != 0 or record_count == 0. No direct writes,
 * locks, clock calls or fences; caller must serialize, delegated scheduler owns
 * mutation. The typed timestamp interface leaves unused A3 alignment padding.
 *
 * With gating, the selector returns one index word. UINT_MAX enters the window
 * path; kind 0 schedules immediately. Cache score before length. A nonzero
 * period smaller than length, or special with nonzero length, requires score 12.
 * Otherwise kind 1 finds the first nonzero matching recent-ID time (ID 0 unless
 * sample_mode and length are nonzero). Age < interval_scale * 2500 and a recent
 * minimum below that threshold require score 255. Negative modular ages pass.
 * Normal gating requires score 2, except mode_count >= 8 with last-history age
 * < scale * 1500 and empty_run >= 2 bypasses score and schedules immediately.
 * No later matching recent bucket is examined after the first matching ID.
 *
 * Insufficient score/window-only selection requires window_active and signed
 * time in [start, end). Read HIGH first and only read LOW on equality. Cache
 * deadline LOW/HIGH before the final strict-point LOW comparison. Schedule at
 * cached deadline,strict=(now>=strict point); immediate path uses deadline=now,
 * strict=0. All times use signed HIGH/unsigned LOW comparisons; intervals use
 * an unsigned 16-bit scale. This does not provide a timer or wall-clock guarantee.
 * The selector and scheduler are recovered in report_selection.c and
 * report_scheduling.c. These local checks do not prove physical delivery.
 */
void report_try_schedule(CreditInterfaceQueue *queue,int allow_gating,
    unsigned long long now_us,unsigned int period,unsigned int interface)
{
    volatile CreditInterfaceQueue *queue_state = queue;
    if (queue_state->extra_pending != 0)
        return;
    if (queue_state->record_count == 0)
        return;
    unsigned int now_low = (unsigned int)now_us;
    unsigned int now_high = (unsigned int)(now_us >> 32);
    if (allow_gating == 0)
        goto immediate;
    unsigned int index = report_select_candidate(queue,period,now_us);
    if (index == 0xffffffffU)
        goto window;
    const volatile CreditInterfaceRecord *record =
        (const volatile CreditInterfaceRecord *)((unsigned int)queue + index * 84U);
    unsigned int kind = record->kind;
    if (kind == 0)
        goto immediate;
    unsigned int score = record->score;
    unsigned int length = record->length;
    unsigned int required_score;
    if (period != 0 && length > period) {
        required_score = 12;
        goto threshold;
    }
    if (record->special != 0 && length != 0) {
        required_score = 12;
        goto threshold;
    }
    if (kind == 1) {
        unsigned int sample = 0;
        if (queue_state->sample_mode != 0 && length != 0)
            sample = *(const volatile unsigned char *)
                ((unsigned int)queue + (unsigned int)(unsigned short)index * 84U);
        for (unsigned int bucket = 0; bucket < 4; ++bucket) {
            unsigned int low = queue_state->recent_time[bucket].low;
            unsigned int high = queue_state->recent_time[bucket].high;
            if ((low | high) == 0 || queue_state->recent_ids[bucket] != sample)
                continue;
            unsigned int scale = queue_state->interval_scale;
            unsigned long long limit = (unsigned long long)scale * 2500U;
            unsigned long long previous = ((unsigned long long)high << 32) | low;
            if ((long long)(now_us - previous) < (long long)limit &&
                (unsigned long long)queue_state->recent_minimum[bucket] < limit) {
                required_score = 255;
                goto threshold;
            }
            break;
        }
    }
    if (queue_state->mode_count >= 8) {
        unsigned int low = queue_state->last_history_time.low;
        unsigned int high = queue_state->last_history_time.high;
        unsigned int scale = queue_state->interval_scale;
        unsigned long long previous = ((unsigned long long)high << 32) | low;
        if ((long long)(now_us - previous) < (long long)((unsigned long long)scale * 1500U) &&
            queue_state->empty_run >= 2)
            goto immediate;
    }
    required_score = 2;
threshold:
    if (score < required_score)
        goto window;
immediate:
    report_schedule_candidate(queue,now_us,now_us,period,interface,0);
    return;
window:
    if (queue_state->window_active == 0)
        return;
    unsigned int start_high = queue_state->window_start.high;
    if ((int)now_high < (int)start_high ||
        (now_high == start_high && now_low < queue_state->window_start.low))
        return;
    unsigned int end_high = queue_state->window_end.high;
    if ((int)now_high > (int)end_high ||
        (now_high == end_high && now_low >= queue_state->window_end.low))
        return;
    unsigned int strict_high = queue_state->window_strict.high;
    unsigned int deadline_low = queue_state->window_deadline.low;
    unsigned int deadline_high = queue_state->window_deadline.high;
    unsigned int strict = 1;
    if ((int)now_high < (int)strict_high ||
        (now_high == strict_high && now_low < queue_state->window_strict.low))
        strict = 0;
    unsigned long long deadline = ((unsigned long long)deadline_high << 32) | deadline_low;
    report_schedule_candidate(queue,now_us,deadline,period,interface,strict);
}
