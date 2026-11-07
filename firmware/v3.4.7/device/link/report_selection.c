/* Medius v3.4.7 device: recovered report candidate selection. */

#include "../include/types.h"

/* Local reconstruction utilities: native record-count bytes are trusted,
 * so record addresses use wrapping32 arithmetic without an eight-slot cap. */
static inline __attribute__((always_inline)) const volatile CreditInterfaceRecord *
report_selection_record(const volatile CreditInterfaceQueue *queue,unsigned int index)
{
    return (const volatile CreditInterfaceRecord *)((unsigned int)queue + index * 84U);
}

/* Native entry: 0x40378060. */
/* Original function-byte SHA-256:
 * 22504a0927c35c9c85d8a1d77d7c896bf705e48a967d5e36ccde3d9fa1cc5b8d. */

/*
 * Selects a queued report without changing queue state.
 *
 * queue: readable interface view with a valid record count/storage.
 * period: full word used for length comparisons; zero disables that check.
 * now_us: caller's 64-bit clock sample. Caller supplies serialization.
 * Returns UINT_MAX for an empty queue or a prefix boundary at index 0; otherwise
 * returns the first admitted index, falling back to 0 if the prefix has none.
 * No locks, fences, allocations, clock calls or direct state writes occur.
 *
 * Cache record_count once. A first record with length_and_kind == 0 and nonzero
 * special returns 0 immediately. Otherwise stop the prefix before the first
 * record whose epoch tag is not 0xffff and whose epoch gate is off or whose
 * (queue epoch - record tag) has bit 10 set. Only earlier records are scanned.
 *
 * Skip kind 0. Other records normally require score >= 2; a nonzero period
 * smaller than length, or special with nonzero length, raises that to 12.
 * Kind 1 uses the first nonzero matching recent-ID timestamp: signed modular
 * age < scale * 2500 and recent minimum below that limit require score 255.
 * Otherwise mode_count >= 8, age < scale * 1500 and empty_run >= 2 bypass score.
 * Negative modular ages pass. The kind-1 path caches scale before the ID scan.
 *
 * An admitted kind-1 record cannot overtake an earlier kind-0 record with the
 * same length and sample. Candidate sampling uses sample_mode's LOW BIT and
 * nonzero length; earlier-record sampling uses sample_mode != 0. The native
 * asymmetry for even nonzero modes is retained. Candidate data is reread at
 * this check, and mode is refreshed only on the paths that refresh it natively.
 * No count, index or epoch repair is supplied; the fallback is also retained.
 */
unsigned int report_select_candidate(CreditInterfaceQueue *queue,
    unsigned int period,unsigned long long now_us)
{
    const volatile CreditInterfaceQueue *queue_state = queue;
    unsigned int record_count = queue_state->record_count;
    if (record_count == 0)
        return 0xffffffffU;
    if (report_selection_record(queue_state,0)->length_and_kind == 0 && report_selection_record(queue_state,0)->special != 0)
        return 0;

    unsigned int prefix_end = 0;
    do {
        unsigned int tag = report_selection_record(queue_state,prefix_end)->epoch_tag;
        if (tag != 0xffffU) {
            unsigned int gate = queue_state->epoch_gate;
            if (gate == 0 || ((queue_state->epoch_tag - tag) & 0x400U) != 0)
                break;
        }
        prefix_end = (prefix_end + 1U) & 255U;
    } while (prefix_end != record_count);
    if (prefix_end == 0)
        return 0xffffffffU;

    for (unsigned int record_index = 0; record_index < prefix_end; ++record_index) {
        const volatile CreditInterfaceRecord *record = report_selection_record(queue_state,record_index);
        unsigned int kind = record->kind;
        if (kind == 0)
            continue;
        unsigned int length = record->length;
        unsigned int score = record->score;
        unsigned int sample_mode,nonempty,sample_enabled;
        unsigned int interval_scale;
        if (length > period && period != 0) {
            if (score < 12)
                continue;
            goto admitted_refresh;
        }
        if (record->special != 0 && length != 0) {
            if (score < 12)
                continue;
            goto admitted_refresh;
        }

        if (kind == 1) {
            sample_mode = queue_state->sample_mode;
            nonempty = length != 0;
            sample_enabled = sample_mode & nonempty;
            unsigned int sample = sample_enabled != 0 ? record->data[0] : 0;
            interval_scale = queue_state->interval_scale;
            for (unsigned int bucket = 0; bucket < 4; ++bucket) {
                unsigned int low = queue_state->recent_time[bucket].low;
                unsigned int high = queue_state->recent_time[bucket].high;
                if ((low | high) == 0 || queue_state->recent_ids[bucket] != sample)
                    continue;
                unsigned long long previous = ((unsigned long long)high << 32) | low;
                unsigned long long limit = (unsigned long long)interval_scale * 2500U;
                if ((long long)(now_us - previous) < (long long)limit &&
                    (unsigned long long)queue_state->recent_minimum[bucket] < limit) {
                    if (score != 255)
                        goto next_candidate;
                    goto admitted_cached;
                }
                break;
            }
            if (queue_state->mode_count < 8) {
                if (score < 2)
                    continue;
                goto admitted_cached;
            }
        } else {
            if (queue_state->mode_count < 8) {
                if (score >= 2)
                    return record_index;
                continue;
            }
            interval_scale = queue_state->interval_scale;
        }

        {
            unsigned int low = queue_state->last_history_time.low;
            unsigned int high = queue_state->last_history_time.high;
            unsigned long long previous = ((unsigned long long)high << 32) | low;
            if ((long long)(now_us - previous) < (long long)((unsigned long long)interval_scale * 1500U) &&
                queue_state->empty_run >= 2)
                goto admitted_refresh;
        }
        if (score < 2)
            continue;
admitted_refresh:
        if (kind != 1)
            return record_index;
        sample_mode = queue_state->sample_mode;
        nonempty = length != 0;
        sample_enabled = sample_mode & nonempty;
admitted_cached:
        {
            unsigned int selected_sample = sample_enabled != 0 ? record->data[0] : 0;
            if (record_index == 0)
                return 0;
            for (unsigned int earlier_index = 0; earlier_index < record_index; ++earlier_index) {
                const volatile CreditInterfaceRecord *earlier_record = report_selection_record(queue_state,earlier_index);
                if (earlier_record->kind == 0 && earlier_record->length == length) {
                    unsigned int prior_sample = 0;
                    if (nonempty != 0 && sample_mode != 0)
                        prior_sample = earlier_record->data[0];
                    if (selected_sample == prior_sample)
                        goto next_candidate;
                }
            }
            return record_index;
        }
next_candidate:
        ;
    }
    return 0;
}

/* Native entry: 0x403771c0. */
/* Original function-byte SHA-256:
 * 04af7497a7b8fb9315f09f11dde8d54f120bdaa2173148cf031881ad0a7198d5. */

/*
 * queue: readable interface view with valid record_count/storage.
 * Returns 1 for the first nonzero kind before the epoch prefix boundary, else 0.
 * Cache count once. Before testing each kind, a tag other than 0xffff ends the
 * scan with 0 if epoch_gate == 0 or (queue epoch - tag) has bit 10 set. Other
 * tags permit the kind test. No mutation, fences, calls, bounds check or lock.
 */
int report_prefix_has_pending_kind(const CreditInterfaceQueue *queue)
{
    const volatile CreditInterfaceQueue *queue_state = queue;
    unsigned int record_count = queue_state->record_count;
    for (unsigned int record_index = 0; record_index < record_count; ++record_index) {
        unsigned int tag = report_selection_record(queue_state,record_index)->epoch_tag;
        if (tag != 0xffffU) {
            unsigned int gate = queue_state->epoch_gate;
            if (gate == 0 || ((queue_state->epoch_tag - tag) & 0x400U) != 0)
                return 0;
        }
        if (report_selection_record(queue_state,record_index)->kind != 0)
            return 1;
    }
    return 0;
}
