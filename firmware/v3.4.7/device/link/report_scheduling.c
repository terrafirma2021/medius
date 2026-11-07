/* Medius v3.4.7 device: recovered report history/deadline scheduling. */

#include "../include/types.h"

/* Local reconstruction utilities: keep full32 metadata indexing separate
 * from the selected payload's native LOW16 index. No record-capacity guard. */
static inline __attribute__((always_inline)) volatile CreditInterfaceRecord *
report_scheduler_record_state(volatile CreditInterfaceQueue *queue,unsigned int index)
{
    return (volatile CreditInterfaceRecord *)((unsigned int)queue + index * 84U);
}

/* Native entry: 0x403788d4. */
/* Original function-byte SHA-256:
 * f29ea58ccbed4b50ec2f47152f532190d16c490db26057807f05fd89da1de839. */

/*
 * Selects, defers or submits one queued report and updates interface state.
 *
 * queue: live, writable interface view with valid records/history storage.
 * now_us: caller's clock sample; deadline_us: caller's comparison deadline.
 * period: 16-bit comparison/division period; zero disables period-specific work.
 * interface: configured USB interface forwarded to the submit helper.
 * strict: nonzero enables learned-delay deferral and suppresses reservation.
 * Returns no value. Caller supplies serialization; no local lock, allocation,
 * clock sample or timer start occurs. USB acceptance is delegated to submission.
 *
 * Empty/extra-pending queues and selector UINT_MAX return. A kind-0 selection
 * goes straight to submission. Otherwise cache score, effective delay, oldest
 * history timestamp and multiple independently fenced counter snapshots.
 * Occupancy is initially saturated to 255, but the <=255 path resamples and
 * narrows its NEW difference to a byte. Oldest time is 0 for empty, a fresh
 * indexed LOW/HIGH for 1..4, or sentinel 0xc000000000000000 for larger history.
 *
 * Score requirements are 12 for oversized/special records, 255 for a recent
 * kind-1 sample with a small minimum, normally 2, or 0 after recent history and
 * two kind-0 submissions. Signed modular age comparisons admit negative ages.
 * For 1..4 outstanding samples, a learned delay requires a first matching ID
 * bucket with >=32 hits and nonzero minimum for EVERY sample; use their minimum.
 * A kind-1 sample already outstanding (or history >4) is a conflict. A sufficiently
 * scored conflict can submit record 0 instead when its kind is 0; otherwise defer.
 * The cached score, not a fresh record read, controls these decisions.
 *
 * Low-score deferral uses the cached oldest time plus effective delay, compared
 * strictly with deadline. Strict mode also uses pending_start (or now) plus the
 * learned delay. Non-strict deferral can set reservation while window_active,
 * before window_strict and before deadline. Existing reservation/deferred flags
 * are retained on return paths unless an explicit store changes them.
 *
 * Before submission clear reservation. Failure leaves local queue metadata
 * unchanged otherwise. Success publishes pending kind/sample/split flags,
 * updates the kind-0 run and clears scores of other matching kind-1 records,
 * shifts later 84-byte records with memcpy, sets extra_pending, decrements the
 * sampled byte count and clears window_active. A zero post-submit count wraps
 * to 255 natively. Sample-mode low-bit versus nonzero tests and fresh reads,
 * including repeated candidate data reads, are retained. No bounds repair or
 * physical completion, timing or concurrency guarantee is supplied.
 */
void report_schedule_candidate(CreditInterfaceQueue *queue,
    unsigned long long now_us,unsigned long long deadline_us,
    unsigned short period,unsigned int interface,unsigned char strict)
{
    volatile CreditInterfaceQueue *queue_state = queue;
    if (queue_state->extra_pending != 0 || queue_state->record_count == 0)
        return;
    unsigned int record_index = report_select_candidate(queue,period,now_us);
    if (record_index == 0xffffffffU)
        return;
    unsigned int kind = report_scheduler_record_state(queue_state,record_index)->kind;
    CreditInterfaceRecord *selected_record = (CreditInterfaceRecord *)report_scheduler_record_state(queue,(unsigned short)record_index);

    if (kind != 0) {
        memw();
        unsigned int history_write_count = queue_state->history_write_count;
        memw();
        unsigned int history_read_count = queue_state->history_read_count;
        unsigned int occupancy = 255;
        if (history_write_count - history_read_count <= 255U) {
            memw();
            history_write_count = queue_state->history_write_count;
            memw();
            history_read_count = queue_state->history_read_count;
            occupancy = (history_write_count - history_read_count) & 255U;
        }
        memw();
        history_write_count = queue_state->history_write_count;
        memw();
        history_read_count = queue_state->history_read_count;
        unsigned int outstanding = history_write_count - history_read_count;
        unsigned int oldest_low,oldest_high;
        if (history_write_count == history_read_count) {
            oldest_low = outstanding;
            oldest_high = outstanding;
        } else if (outstanding < 5) {
            memw();
            unsigned int oldest_index = queue_state->history_read_count & 3U;
            oldest_low = queue_state->history_time[oldest_index].low;
            oldest_high = queue_state->history_time[oldest_index].high;
        } else {
            oldest_low = 0;
            oldest_high = 0xc0000000U;
        }
        unsigned int length = report_scheduler_record_state(queue_state,record_index)->length;
        unsigned int oversized = period != 0 && period < length;
        unsigned int special = report_scheduler_record_state(queue_state,record_index)->special;
        unsigned int last_low = queue_state->last_history_time.low;
        unsigned int last_high = queue_state->last_history_time.high;
        unsigned int effective_delay = queue_state->effective_delay;
        unsigned int split = oversized != 0 ? 1U : special & (length != 0);
        unsigned long long last = ((unsigned long long)last_high << 32) | last_low;
        unsigned int stale_and_empty = 0;
        if ((last_low | last_high) == 0 || (long long)(now_us - last) > 12000) {
            memw();
            history_write_count = queue_state->history_write_count;
            memw();
            history_read_count = queue_state->history_read_count;
            stale_and_empty = history_write_count == history_read_count;
        }
        unsigned int score = report_scheduler_record_state(queue_state,record_index)->score;
        unsigned int required_score;
        if (oversized != 0 || (length != 0 && special != 0)) {
            required_score = 12;
        } else {
            if (kind == 1) {
                unsigned int mode = queue_state->sample_mode;
                unsigned int sample = mode != 0 && length != 0 ?
                    ((const volatile CreditInterfaceRecord *)selected_record)->data[0] : 0;
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
                        goto recent_pending_snapshot;
                    }
                    break;
                }
            }
            required_score = 2;
            if (queue_state->mode_count >= 8) {
                unsigned int scale = queue_state->interval_scale;
                if ((long long)(now_us - last) < (long long)((unsigned long long)scale * 1500U) &&
                    queue_state->empty_run >= 2)
                    required_score = 0;
            }
        }

        unsigned int pending_low,pending_high;
        memw();
        history_write_count = queue_state->history_write_count;
        memw();
        history_read_count = queue_state->history_read_count;
        pending_low = queue_state->pending_start.low;
        outstanding = history_write_count - history_read_count;
        pending_high = queue_state->pending_start.high;
        goto learn_delay;

recent_pending_snapshot:
        /* The score-255 path samples pending LOW between the fenced counters. */
        memw();
        history_write_count = queue_state->history_write_count;
        pending_low = queue_state->pending_start.low;
        memw();
        history_read_count = queue_state->history_read_count;
        outstanding = history_write_count - history_read_count;
        pending_high = queue_state->pending_start.high;
learn_delay:
        ;
        unsigned int learned_delay = 0;
        if (outstanding - 1U < 4U) {
            unsigned int mode = queue_state->sample_mode;
            learned_delay = 0xffffffffU;
            for (unsigned int sample_number = 0; sample_number < outstanding; ++sample_number) {
                memw();
                unsigned int sample_index = queue_state->history_read_count;
                unsigned int sample = mode != 0 ? queue_state->history_sample[(sample_index + sample_number) & 3U] : 0;
                unsigned int bucket;
                for (bucket = 0; bucket < 4; ++bucket) {
                    unsigned int hits = queue_state->minimum_hits[bucket];
                    if (hits == 0 || queue_state->minimum_ids[bucket] != sample)
                        continue;
                    if (hits < 32)
                        goto no_learned_delay;
                    unsigned int minimum = queue_state->minimum_delay_by_id[bucket];
                    if (minimum == 0)
                        goto no_learned_delay;
                    if (minimum < learned_delay)
                        learned_delay = minimum;
                    break;
                }
                if (bucket == 4)
                    goto no_learned_delay;
            }
        }
        goto check_conflict;
no_learned_delay:
        learned_delay = 0;
check_conflict:
        if (kind == 1) {
            unsigned int mode = queue_state->sample_mode;
            unsigned int sample = length != 0 && mode != 0 ?
                ((const volatile CreditInterfaceRecord *)selected_record)->data[0] : 0;
            memw();
            history_write_count = queue_state->history_write_count;
            memw();
            history_read_count = queue_state->history_read_count;
            unsigned int outstanding_count = history_write_count - history_read_count;
            if (outstanding_count > 4)
                goto conflict;
            for (unsigned int sample_number = 0; sample_number < outstanding_count; ++sample_number) {
                memw();
                unsigned int sample_index = queue_state->history_read_count;
                unsigned int historical_sample = mode != 0 ?
                    queue_state->history_sample[(sample_index + sample_number) & 3U] : 0;
                if (sample == historical_sample)
                    goto conflict;
            }
        }
        if (score >= required_score)
            goto submit;
        goto low_score;
conflict:
        if (score >= required_score) {
            if (record_index != 0 && report_scheduler_record_state(queue_state,0)->kind == 0) {
                record_index = 0;
                selected_record = (CreditInterfaceRecord *)report_scheduler_record_state(queue,0);
                goto submit;
            }
            goto defer;
        }
low_score:
        if (split != 0) {
            if (stale_and_empty == 0 || occupancy != 0)
                goto defer;
            goto submit;
        }
        if (occupancy != 0) {
            unsigned long long oldest = ((unsigned long long)oldest_high << 32) | oldest_low;
            unsigned long long predicted = oldest + effective_delay;
            if ((long long)predicted < (long long)deadline_us) {
                if (strict == 0)
                    goto defer;
                if (learned_delay == 0) {
                    queue_state->deferred = 1;
                    return;
                }
                unsigned long long base = (pending_low | pending_high) != 0 ?
                    ((unsigned long long)pending_high << 32) | pending_low : now_us;
                if ((long long)(base + learned_delay) < (long long)deadline_us) {
                    queue_state->deferred = 1;
                    return;
                }
            }
        }
        goto submit;
defer:
        queue_state->deferred = 1;
        if (strict != 0 || queue_state->window_active == 0)
            return;
        unsigned int strict_high = queue_state->window_strict.high;
        unsigned int now_high = (unsigned int)(now_us >> 32);
        if ((int)now_high > (int)strict_high ||
            (now_high == strict_high && (unsigned int)now_us >= queue_state->window_strict.low))
            return;
        if (occupancy == 0)
            return;
        unsigned long long oldest = ((unsigned long long)oldest_high << 32) | oldest_low;
        if ((long long)(oldest + effective_delay) < (long long)deadline_us)
            queue_state->reservation = 1;
        return;
    }

submit:
    queue_state->reservation = 0;
    if (report_submit_record(interface,selected_record) == 0)
        return;
    const volatile CreditInterfaceRecord *selected_state = selected_record;
    kind = selected_state->kind;
    queue_state->pending_kind = kind != 0;
    unsigned int length = selected_state->length;
    unsigned int mode = queue_state->sample_mode;
    unsigned int nonempty = length != 0;
    unsigned int sample_enabled = mode & nonempty;
    unsigned int pending_sample = sample_enabled != 0 ? selected_state->data[0] : 0;
    queue_state->pending_sample = pending_sample;
    unsigned int special = selected_state->special;
    unsigned int short_multiple = 0;
    if (length > period && period != 0) {
        queue_state->pending_split = 1;
        if (special == 0)
            goto test_multiple;
    } else if (special != 0 && nonempty != 0) {
        queue_state->pending_split = 1;
    } else {
        queue_state->pending_split = 0;
        if ((period != 0) && ((special ^ 1U) & 1U) != 0 && nonempty != 0)
            goto test_multiple;
    }
    goto publish_multiple;
test_multiple:
    ;
    unsigned int limit = queue_state->comparison_limit;
    if (limit < period)
        limit = period;
    unsigned int remainder = length % period;
    short_multiple = remainder == 0 && length < limit;
publish_multiple:
    queue_state->pending_short_multiple = short_multiple;
    unsigned int record_count;
    if (kind == 0) {
        unsigned int run = queue_state->empty_run;
        if (run != 255)
            queue_state->empty_run = run + 1U;
    } else {
        record_count = queue_state->record_count;
        queue_state->empty_run = 0;
        if (record_count == 0)
            goto finish;
        for (unsigned int other = 0; other < record_count; ++other) {
            volatile CreditInterfaceRecord *prior = report_scheduler_record_state(queue_state,other);
            if ((unsigned char)record_index == other || prior->kind != 1 || prior->length != length)
                continue;
            unsigned int other_sample = nonempty != 0 && mode != 0 ? prior->data[0] : 0;
            unsigned int selected_sample = sample_enabled != 0 ? selected_state->data[0] : 0;
            if (selected_sample == other_sample)
                prior->score = 0;
        }
    }
    record_count = queue_state->record_count;
    unsigned int next = record_index + 1U;
    if ((int)next < (int)record_count) {
        unsigned int next_index = (unsigned char)((unsigned char)record_index + 1U);
        do {
            memcpy((CreditInterfaceRecord *)report_scheduler_record_state(queue,record_index),(CreditInterfaceRecord *)report_scheduler_record_state(queue,next),84);
            record_index = next_index;
            ++next_index;
            next = next_index;
        } while ((int)next_index < (int)record_count);
    }
finish:
    queue_state->extra_pending = 1;
    queue_state->record_count = record_count - 1U;
    queue_state->window_active = 0;
}
