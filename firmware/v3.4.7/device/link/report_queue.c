/* Medius v3.4.7 device: report admission, merging and queue pressure policy. */

#include "../include/types.h"

/* Local reconstruction utilities: preserve unchecked wrapping32 record
 * addressing without giving the compiler an eight-element array bound. */
static inline __attribute__((always_inline)) CreditInterfaceRecord *
report_queue_record(CreditInterfaceQueue *queue,unsigned int index)
{
    return (CreditInterfaceRecord *)((unsigned int)queue + index * 84U);
}

static inline __attribute__((always_inline)) volatile CreditInterfaceRecord *
report_queue_record_state(volatile CreditInterfaceQueue *queue,unsigned int index)
{
    return (volatile CreditInterfaceRecord *)((unsigned int)queue + index * 84U);
}

/* Native entry: 0x40379280. */
/* Original function-byte SHA-256:
 * 0f7c1c19440a102c9d602a0a8b04c6c94732bba02a80df5a37179c1ad926ea7e. */

/*
 * Admits a report into an interface's eight-record queue, then tries scheduling.
 *
 * queue: writable queue, serialized by the caller. Counts/indices are trusted;
 * the native policy normally uses eight slots but does not cap every walk.
 * report/length: readable input; at most 64 bytes are copied here. The ORIGINAL
 * length still controls empty-report classification and the oversized gate.
 * kind: 0 ordinary, 1 combinable, 2 separate; other values follow native tests.
 * record_flags: low byte becomes record.metadata42.
 * dirty_state_word: full word becomes record.metadata50, a deferred dirty-state pointer.
 * mode: LOW BIT enables the incoming report ID; queued ID tests use NONZERO.
 * options: byte participates in combining; normalized_hash identifies content.
 * short_multiple: byte stored as record.special, subject to admission overrides.
 * source_interface: merge-layout index; allow_recovery: enables score gating and
 * epoch retention; now_us: supplied clock sample; period: comparison period;
 * interface: submission interface; epoch: signed-negative means no epoch tag.
 * Flags are used as native byte/bit expressions, not normalized indiscriminately.
 *
 * Returns status0=1 when an existing record was consumed/updated; dropped=1
 * when queue pressure discarded a queued or incoming item; secondary=1 for an
 * empty-slot discard or the full-queue conversion failure. dirty_state identifies
 * displaced metadata50, including the incoming pointer if admission failed.
 * Ordinary paths clear auxiliary/status3; the duplicate-empty early return sets
 * auxiliary's LOW byte to 1 and leaves its upper bytes and status3 unspecified.
 * zero is always 0. This is admission state, not a USB completion result.
 *
 * Empty ordinary input can be suppressed, converted into a special marker, or
 * replace the first kind-1 record. Matching reports use length, ID, kind class
 * and special state. Existing kind-1 duplicates can be merged and removed
 * before the new report is considered; that merge's result is ignored natively.
 * Full queues evict first an empty ordinary/non-special slot, then a nonempty
 * kind-0 slot, then a kind-2 slot; otherwise the incoming report is discarded.
 * A failed merge inserts after its candidate and trailing empty slots. Preserve
 * the native post-removal candidate equality test, including adjacent indices.
 *
 * Tracks burst count and four recent-ID buckets for ordinary nonempty input.
 * Scheduling requires scores 12, 255 or normally 2, with a burst/history bypass;
 * a blocked candidate can instead use an active start/end/strict window.
 * Signed modular ages admit negative deltas. Some bucket deltas preserve their
 * LOW word even with a negative HIGH word; this is not repaired into a clamp.
 * No allocation, local lock, clock read or MEMW occurs in this entry. Helper
 * calls may change queue state; byte counts are resampled where used below.
 * Timestamp reads retain each native path's order: window tests read HIGH
 * before conditional LOW; bucket scans read HIGH/LOW, then the selected
 * bucket's HIGH and conditional LOW. Scale reads stay between the two history
 * timestamp words where the native code samples them that way.
 */
ReportQueueResult report_queue_update(CreditInterfaceQueue *queue,
    const unsigned char *report,unsigned int length,unsigned int kind,
    unsigned int record_flags,unsigned int dirty_state_word,unsigned char mode,
    unsigned char options,unsigned int normalized_hash,unsigned char short_multiple,
    unsigned int source_interface,unsigned char allow_recovery,
    unsigned long long now_us,unsigned short period,unsigned int interface,
    unsigned int epoch)
{
    volatile CreditInterfaceQueue *queue_state = queue;
    unsigned int now_low = (unsigned int)now_us;
    unsigned int now_high = (unsigned int)(now_us >> 32);
    ReportQueueResult result = {0};
    unsigned int nonempty = length != 0;
    unsigned int ordinary_class = kind == 0;
    unsigned int special = nonempty & mode;
    unsigned int sample_id = special != 0 ? report[0] : 0;
    unsigned int copy_length = length < 64U ? length : 64U;
    unsigned int period_gate = period != 0;
    unsigned int combine_allowed = 0;
    unsigned int scan_enabled,merge_barrier;
    unsigned int count,index,insert_index;
    unsigned int discarded_empty = 0,discarded = 0;
    unsigned int merge_kind = 0,merge_kind_cached = 0;
    unsigned int inserting_after_target = 0;
    unsigned int dirty_pointer = 0;
    int first_kind1 = -1,last_match = -1,last_ordinary = -1,target = -1;
    unsigned int kind1_count = 0,has_target = 0,suppress_target = 0;

    /* 403792ed..4037942d: empty ordinary reports have a separate policy. */
    if (nonempty == 0 && ordinary_class != 0) {
        unsigned int short_empty = 0;
        count = queue_state->record_count;
        index = count;
        while (index != 0) {
            --index;
            if (report_queue_record_state(queue_state,index)->kind != 0)
                continue;
            unsigned int old_special = report_queue_record_state(queue_state,index)->special;
            unsigned int old_length = report_queue_record_state(queue_state,index)->length;
            period_gate = (old_length != 0) & (period != 0) & (old_special ^ 1U);
            if (period_gate == 0 || old_length % period != 0)
                goto inspect_empty_records;
            unsigned int limit = queue_state->comparison_limit;
            if (limit < period)
                limit = period;
            if (old_length >= limit)
                goto inspect_empty_records;
            short_empty = 1;
            goto classify_empty_report;
        }
        if (queue_state->pending_short_multiple != 0) {
            short_empty = 1;
            period_gate = period != 0;
            goto classify_empty_report;
        }
inspect_empty_records:
        /* The native second scan reloads kind bytes before suppression. */
        for (index = 0; index < count; ++index)
            if (report_queue_record_state(queue_state,index)->kind == 0)
                goto suppress_empty;
        if (queue_state->extra_pending != 0 && queue_state->pending_split == 0)
            goto suppress_empty;
        period_gate = period != 0;
classify_empty_report:
        copy_length = 0;
        special = short_empty;
        unsigned int enabled = queue_state->combine_window_enabled;
        if (enabled != 0) {
            unsigned int deferred = queue_state->deferred;
            ordinary_class = deferred != 0 ? deferred : enabled;
            special = short_empty != 0 ? ordinary_class : 0;
            if (deferred != 0 && queue_state->combine_deadline_inhibited == 0) {
                unsigned int deadline_high = queue_state->window_deadline.high;
                combine_allowed = (int)now_high > (int)deadline_high ||
                    (now_high == deadline_high && now_low >= queue_state->window_deadline.low);
            }
            scan_enabled = (special | (deferred ^ 1U)) & 255U;
        } else {
            scan_enabled = special;
        }
    } else {
        /* 40379433..403794f8: nonempty classification precedes age tests. */
        special = short_multiple;
        if (queue_state->combine_window_enabled != 0 && queue_state->deferred != 0 &&
            queue_state->combine_deadline_inhibited == 0) {
            unsigned int deadline_high = queue_state->window_deadline.high;
            combine_allowed = (int)now_high > (int)deadline_high ||
                (now_high == deadline_high && now_low >= queue_state->window_deadline.low);
        }
        period_gate = (period != 0) && period < length;
        scan_enabled = (special | 1U) & 255U;
        if (period_gate != 0) {
            combine_allowed = 0;
            goto classified;
        }
        if ((nonempty & special) != 0) {
            combine_allowed = 0;
            if (allow_recovery == 0) {
                special &= nonempty;
                epoch = 0xffffffffU;
                goto classified;
            }
            special = allow_recovery;
            merge_barrier = allow_recovery;
            goto scan_or_insert;
        }
    }

    /* 40379519..4037969e: recent IDs and queued normalized-content conflicts. */
    for (index = 0; index < 4; ++index) {
        unsigned long long previous = report_read_time(&queue_state->recent_time[index]);
        if (previous == 0 || queue_state->recent_ids[index] != sample_id)
            continue;
        unsigned int recent_limit = queue_state->interval_scale * 2500U;
        if ((long long)(now_us - previous) < recent_limit &&
            queue_state->recent_minimum[index] < recent_limit)
            goto forbid_combining;
        break;
    }
    for (index = 0; index < 4; ++index) {
        unsigned long long previous = report_read_time(&queue_state->recent_time[index]);
        if (previous != 0 && queue_state->recent_ids[index] != sample_id &&
            (long long)(now_us - previous) < 12000)
            goto forbid_combining;
    }
    if (combine_allowed != 0)
        goto forbid_combining;
    count = queue_state->record_count;
    unsigned int matching_kind1 = 0;
    for (index = 0; index < count; ++index) {
        if (report_queue_record_state(queue_state,index)->kind != 1 || report_queue_record_state(queue_state,index)->length != copy_length)
            continue;
        unsigned int old_id = copy_length != 0 && mode != 0 ? report_queue_record_state(queue_state,index)->data[0] : 0;
        if (old_id == sample_id)
            ++matching_kind1;
    }
    if (matching_kind1 >= 2)
        goto classified;
    if (kind == 0) {
        for (index = 0; index < count; ++index) {
            if (report_queue_record_state(queue_state,index)->kind != 1 || report_queue_record_state(queue_state,index)->length != copy_length)
                continue;
            unsigned int old_id = copy_length != 0 && mode != 0 ? report_queue_record_state(queue_state,index)->data[0] : 0;
            if (old_id == sample_id && report_queue_record_state(queue_state,index)->metadata48 != normalized_hash)
                goto classified;
        }
    }
    combine_allowed = 1;
    goto classified;

forbid_combining:
    combine_allowed = 0;
classified:
    if (allow_recovery == 0)
        epoch = 0xffffffffU;
    if (scan_enabled == 0) {
        count = queue_state->record_count;
        for (index = 0; index < count; ++index) {
            if (report_queue_record_state(queue_state,index)->kind != 1)
                continue;
            report_queue_record_state(queue_state,index)->kind = 0;
            report_queue_record_state(queue_state,index)->score = 0;
            report_queue_record_state(queue_state,index)->metadata44 = 1;
            report_queue_record_state(queue_state,index)->epoch_tag = 0xffffU;
            target = (int)index;
            goto move_to_ordinary_prefix;
        }
        if (count == 8) {
            result.dropped = result.secondary = 1;
            goto update_history;
        }
    }
    merge_barrier = ((kind != 0) | (options ^ 1U) | ((combine_allowed ^ 1U) & 1U)) & 255U;

scan_or_insert:
    if (kind == 2 || nonempty == 0 || queue_state->record_count == 0)
        goto no_match;
    /* 40379839..40379997: keep indices as indices, not Ghidra byte pointers. */
    index = 0;
    do {
        CreditInterfaceRecord *record = report_queue_record(queue,index);
        volatile CreditInterfaceRecord *record_state = record;
        unsigned int old_kind = report_queue_record_state(queue_state,index)->kind;
        if (old_kind == 2 || report_queue_record_state(queue_state,index)->length != copy_length)
            goto next_match;
        unsigned int old_id = copy_length != 0 && mode != 0 ? report_queue_record_state(queue_state,index)->data[0] : 0;
        if (old_id != sample_id || ((old_kind != 0) != ordinary_class &&
            report_queue_record_state(queue_state,index)->special != special))
            goto next_match;
        if (old_kind != 1) {
            last_ordinary = last_match = (int)index;
            goto next_match;
        }
        if (ordinary_class == 0 || merge_barrier == 0 || first_kind1 < 0) {
            if (first_kind1 < 0)
                first_kind1 = (int)index;
            ++kind1_count;
            last_match = (int)index;
            goto next_match;
        }
        CreditInterfaceRecord *first = report_queue_record(queue,first_kind1);
        volatile CreditInterfaceRecord *first_state = first;
        /* Native ignores rejection and still removes the later kind-1 record. */
        (void)report_merge_interface(source_interface,first->data,record->data,
            (unsigned short)copy_length,1,1);
        unsigned int removed_flags = record_state->metadata42;
        unsigned int retained_flags = first_state->metadata42;
        first_state->metadata42 = retained_flags | removed_flags;
        unsigned int removed_metadata = record_state->metadata50;
        if (removed_metadata != 0)
            first_state->metadata50 = removed_metadata;
        count = queue_state->record_count;
        for (unsigned int shift = (index & 255U) + 1; shift < count; ++shift)
            memcpy(report_queue_record(queue,shift - 1),report_queue_record(queue,shift),84);
        count = (count - 1) & 255U;
        queue_state->record_count = (unsigned char)count;
        continue;
next_match:
        count = queue_state->record_count;
        ++index;
    } while ((int)index < (int)count);

    if ((ordinary_class & (first_kind1 >= 0)) != 0) {
        target = first_kind1;
        if (merge_barrier == 0) {
            if (last_ordinary < 0) {
                ordinary_class = 1;
                goto insert_default;
            }
            target = last_ordinary;
            if (report_queue_record_state(queue_state,target)->kind != 0) {
                ordinary_class = 1;
                goto merge_incoming;
            }
        }
        goto reconsider_target;
    }
    target = last_match;
    has_target = target >= 0;
    if (target >= 0 && ordinary_class != 0)
        goto reconsider_target;
    goto select_action;

reconsider_target:
    if (report_queue_record_state(queue_state,target)->kind == 0) {
        for (index = (unsigned int)target + 1; index < count; ++index) {
            if (report_queue_record_state(queue_state,index)->kind == 0 && report_queue_record_state(queue_state,index)->length != 0) {
                target = -1;
                has_target = 0;
                goto select_action;
            }
        }
    }
    if (kind != 1) {
        ordinary_class = 1;
        goto merge_incoming;
    }
    has_target = 1;

select_action:
    if (kind == 1 && has_target != 0) {
        unsigned int old_kind = report_queue_record_state(queue_state,target)->kind;
        if (old_kind == 1) {
            if (kind1_count >= 2) {
                merge_kind = old_kind;
                merge_kind_cached = 1;
                goto merge_incoming;
            }
            has_target = suppress_target = 1;
        } else if (old_kind == 0) {
            combine_allowed &= 1U;
            has_target = suppress_target = combine_allowed & report_queue_record_state(queue_state,target)->metadata44;
            if (has_target == 0)
                goto merge_incoming;
        } else {
            merge_kind = old_kind;
            merge_kind_cached = 1;
            goto merge_incoming;
        }
        goto replace_empty_with_cached_count;
    }
    if (kind == 1 && target < 0) {
        suppress_target = 0;
        goto replace_empty;
    }
    if (has_target != 0)
        goto merge_incoming;
    goto insert_default;

no_match:
    if (kind != 1)
        goto insert_default;
    has_target = suppress_target = 0;

replace_empty:
    /* 40379aca: an empty marker after the last ordinary record can be reused
     * only when the entire sampled queue contains no kind-1 record. */
    count = queue_state->record_count;
replace_empty_with_cached_count:
    int empty = -1;
    unsigned int any_kind1 = 0;
    for (index = 0; index < count; ++index) {
        unsigned int old_header = report_queue_record_state(queue_state,index)->length_and_kind;
        unsigned int old_kind = report_queue_record_state(queue_state,index)->kind;
        if (old_header == 0 && report_queue_record_state(queue_state,index)->special == 0) {
            if (empty == -1)
                empty = (int)index;
        } else if (old_kind == 0) {
            empty = -1;
        }
        any_kind1 |= old_kind == 1;
    }
    if (empty >= 0 && any_kind1 == 0) {
        CreditInterfaceRecord *record = report_queue_record(queue,(unsigned short)empty);
        volatile CreditInterfaceRecord *record_state = record;
        memcpy(record->data,report,copy_length);
        record_state->metadata42 = (unsigned char)record_flags;
        record_state->metadata44 = 1;
        record_state->metadata48 = normalized_hash;
        record_state->length = (unsigned char)copy_length;
        record_state->special = (unsigned char)special;
        record_state->score = 0;
        record_state->metadata50 = dirty_state_word;
        result.status0 = 1;
        goto update_history;
    }
    has_target &= suppress_target ^ 1U;
    if (has_target != 0)
        goto merge_incoming;
    goto insert_default;

merge_incoming:
    {
        CreditInterfaceRecord *record = report_queue_record(queue,target);
        volatile CreditInterfaceRecord *record_state = record;
        unsigned int old_kind = merge_kind_cached != 0 ? merge_kind :
            report_queue_record_state(queue_state,target)->kind;
        if (report_merge_interface(source_interface,record->data,report,
            (unsigned short)copy_length,(unsigned char)old_kind,(unsigned char)kind) == 0)
            goto insert_after_target;
        record_state->metadata42 |= (unsigned char)record_flags;
        if (dirty_state_word != 0)
            record_state->metadata50 = dirty_state_word;
        unsigned int merge_markers = record_state->metadata44 | options;
        if (kind == 1) {
            if (report_queue_record_state(queue_state,target)->kind == 1) {
                if ((int)epoch >= 0) {
                    unsigned int old_epoch = report_queue_record_state(queue_state,target)->epoch_tag;
                    unsigned short chosen_epoch = (unsigned short)epoch;
                    if (old_epoch != 0xffffU && (((epoch & 65535U) - old_epoch) & 0x400U) != 0)
                        chosen_epoch = (unsigned short)old_epoch;
                    record_state->epoch_tag = chosen_epoch;
                }
                record_state->metadata44 = 1;
                record_state->metadata48 = normalized_hash;
            } else {
                record_state->metadata44 = 1;
            }
        } else {
            if (merge_markers != 0) {
                record_state->metadata44 = 1;
            } else if (report_queue_record_state(queue_state,target)->kind == 1) {
                record_state->metadata44 = 1;
                if (kind == 0)
                    goto convert_to_ordinary;
                goto merged_report;
            }
            if (kind == 0 && report_queue_record_state(queue_state,target)->kind != 0) {
convert_to_ordinary:
                record_state->kind = 0;
                record_state->score = 0;
                record_state->special = (unsigned char)special;
                record_state->epoch_tag = 0xffffU;
                goto move_to_ordinary_prefix;
            }
        }
merged_report:
        result.status0 = 1;
        goto update_history;
    }

move_to_ordinary_prefix:
    for (index = 0; (index & 255U) < ((unsigned int)target & 255U); ++index) {
        if (report_queue_record_state(queue_state,index)->kind == 0)
            continue;
        CreditInterfaceRecord saved;
        memcpy(&saved,report_queue_record(queue,(unsigned char)target),84);
        unsigned int moved = ((unsigned int)target - (index & 255U)) & 255U;
        memmove(report_queue_record(queue,index + 1),report_queue_record(queue,index),moved * 84U);
        memcpy(report_queue_record(queue,index),&saved,84);
        break;
    }
    result.status0 = 1;
    goto update_history;

insert_after_target:
    inserting_after_target = 1;
    count = queue_state->record_count;
    if (count >= 8)
        goto evict_record;
    goto choose_after_target;

insert_default:
    inserting_after_target = 0;
    target = -1;
    count = queue_state->record_count;
    if (count >= 8)
        goto evict_record;
    goto choose_insertion;

evict_record:
    {
        int victim = -1;
        for (index = 0; index < count; ++index) {
            if (report_queue_record_state(queue_state,index)->length_and_kind == 0 && report_queue_record_state(queue_state,index)->special == 0) {
                victim = (int)index;
                discarded_empty = 1;
                break;
            }
        }
        if (victim < 0) {
            for (index = 0; index < 8; ++index) {
                if (report_queue_record_state(queue_state,index)->kind == 0 && report_queue_record_state(queue_state,index)->length_and_kind != 0) {
                    victim = (int)index;
                    break;
                }
            }
        }
        if (victim < 0) {
            for (index = 0; index < 8; ++index) {
                if (report_queue_record_state(queue_state,index)->kind == 2 && report_queue_record_state(queue_state,index)->length_and_kind != 0) {
                    victim = (int)index;
                    break;
                }
            }
        }
        if (victim < 0) {
            result.dropped = 1;
            result.dirty_state = (InputStateView *)dirty_state_word;
            goto update_history;
        }
        if (discarded_empty == 0)
            dirty_pointer = report_queue_record_state(queue_state,victim)->metadata50;
        unsigned int stop = discarded_empty != 0 ? count : 8;
        for (index = (unsigned char)(victim + 1); index < stop; ++index)
            memcpy(report_queue_record(queue,index - 1),report_queue_record(queue,index),84);
        /* Default insertion's last-slot empty eviction stores seven even
         * for a corrupt count above eight. Keep that native asymmetry. */
        count = discarded_empty != 0 &&
            (inserting_after_target != 0 || (unsigned int)victim + 1U < count) ?
            (count - 1U) & 255U : 7U;
        queue_state->record_count = (unsigned char)count;
        discarded = 1;
        if (target >= 0) {
            target -= victim < target;
            if (target != victim)
                goto choose_after_target;
        }
    }
choose_insertion:
    insert_index = count;
    if (kind == 0) {
        epoch = 0xffffffffU;
        for (index = 0; index < count; ++index) {
            if (report_queue_record_state(queue_state,index)->kind != 0) {
                insert_index = index;
                break;
            }
        }
    }
    goto insert_record;

choose_after_target:
    insert_index = ((unsigned int)target + 1) & 255U;
    while (insert_index < count && report_queue_record_state(queue_state,insert_index)->length_and_kind == 0)
        insert_index = (insert_index + 1) & 255U;
    if (kind == 0)
        epoch = 0xffffffffU;
insert_record:
    report_insert_record(queue,insert_index,report,copy_length,kind,
        (unsigned char)record_flags,options,normalized_hash,(unsigned char)special,
        dirty_state_word,(int)epoch);
    result.dropped = (unsigned char)discarded;
    result.secondary = (unsigned char)discarded_empty;
    result.dirty_state = (InputStateView *)dirty_pointer;

update_history:
    queue_state->sample_mode = mode;
    if (kind == 0) {
        if (nonempty != 0 && ordinary_class != 0) {
            unsigned int burst = queue_state->mode_count;
            if (burst == 0) {
                burst = 1;
            } else {
                unsigned int last_low = queue_state->last_mode_time.low;
                unsigned int scale = queue_state->interval_scale;
                unsigned int last_high = queue_state->last_mode_time.high;
                unsigned long long last = ((unsigned long long)last_high << 32) | last_low;
                if ((long long)(now_us - last) >= scale * 1500U)
                    burst = 1;
                else if (burst != 255)
                    ++burst;
            }
            queue_state->mode_count = (unsigned char)burst;
            queue_state->last_mode_time.low = (unsigned int)now_us;
            queue_state->last_mode_time.high = (unsigned int)(now_us >> 32);
            unsigned int bucket = 0;
            unsigned long long previous = 0;
            for (index = 0; index < 4; ++index) {
                unsigned int previous_high = queue_state->recent_time[index].high;
                unsigned int previous_low = queue_state->recent_time[index].low;
                previous = ((unsigned long long)previous_high << 32) | previous_low;
                if (previous != 0 && queue_state->recent_ids[index] == sample_id) {
                    bucket = index;
                    goto record_recent;
                }
                unsigned int selected_high = queue_state->recent_time[bucket].high;
                if ((int)previous_high < (int)selected_high ||
                    (previous_high == selected_high && previous_low < queue_state->recent_time[bucket].low))
                    bucket = index;
            }
            previous = report_read_time(&queue_state->recent_time[bucket]);
record_recent:
            unsigned int delta = 0xffffffffU;
            if (previous != 0 && queue_state->recent_ids[bucket] == sample_id) {
                unsigned long long elapsed = now_us - previous;
                unsigned int low = (unsigned int)elapsed;
                int high = (int)(elapsed >> 32);
                if (high < 0 || (high == 0 && low <= 0x7ffffffeU))
                    delta = low;
            }
            queue_state->recent_minimum[bucket] = delta;
            queue_state->recent_ids[bucket] = (unsigned char)sample_id;
            queue_state->recent_time[bucket].low = (unsigned int)now_us;
            queue_state->recent_time[bucket].high = (unsigned int)(now_us >> 32);
        }
    } else {
        if (queue_state->window_active == 0) {
            queue_state->expiry_defer_enabled = 1;
        } else {
            unsigned int end_high = queue_state->window_end.high;
            if ((int)now_high < (int)end_high ||
                (now_high == end_high && now_low < queue_state->window_end.low))
                queue_state->expiry_defer_enabled = 1;
        }
    }
    if (queue_state->extra_pending != 0 || queue_state->record_count == 0)
        return result;
    if (allow_recovery == 0)
        goto schedule_now;
    index = report_select_candidate(queue,period,now_us);
    if (index == 0xffffffffU)
        goto schedule_window;
    unsigned int selected_kind = report_queue_record_state(queue_state,index)->kind;
    if (selected_kind == 0)
        goto schedule_now;
    unsigned int selected_length = report_queue_record_state(queue_state,index)->length;
    unsigned int score = report_queue_record_state(queue_state,index)->score;
    unsigned int required_score = 2;
    if ((selected_length > period && period_gate != 0) ||
        (report_queue_record_state(queue_state,index)->special != 0 && selected_length != 0)) {
        required_score = 12;
    } else {
        if (selected_kind == 1) {
            unsigned int selected_id = selected_length != 0 && mode != 0 ?
                report_queue_record_state(queue_state,(unsigned short)index)->data[0] : 0;
            for (unsigned int bucket = 0; bucket < 4; ++bucket) {
                unsigned long long previous = report_read_time(&queue_state->recent_time[bucket]);
                if (previous == 0 || queue_state->recent_ids[bucket] != selected_id)
                    continue;
                unsigned int recent_limit = queue_state->interval_scale * 2500U;
                if ((long long)(now_us - previous) < recent_limit &&
                    queue_state->recent_minimum[bucket] < recent_limit) {
                    required_score = 255;
                    goto check_score;
                }
                break;
            }
        }
        if (queue_state->mode_count > 7) {
            unsigned int history_low = queue_state->last_history_time.low;
            unsigned int scale = queue_state->interval_scale;
            unsigned int history_high = queue_state->last_history_time.high;
            unsigned long long last_history = ((unsigned long long)history_high << 32) | history_low;
            if ((long long)(now_us - last_history) < scale * 1500U && queue_state->empty_run > 1)
                goto schedule_now;
        }
    }
check_score:
    if (score < required_score)
        goto schedule_window;
schedule_now:
    report_schedule_candidate(queue,now_us,now_us,period,interface,0);
    return result;
schedule_window:
    if (queue_state->window_active == 0)
        return result;
    unsigned int start_high = queue_state->window_start.high;
    if ((int)now_high < (int)start_high ||
        (now_high == start_high && now_low < queue_state->window_start.low))
        return result;
    unsigned int end_high = queue_state->window_end.high;
    if ((int)now_high > (int)end_high ||
        (now_high == end_high && now_low >= queue_state->window_end.low))
        return result;
    unsigned int strict_high = queue_state->window_strict.high;
    unsigned int deadline_low = queue_state->window_deadline.low;
    unsigned int deadline_high = queue_state->window_deadline.high;
    unsigned int strict = 1;
    if ((int)now_high < (int)strict_high ||
        (now_high == strict_high && now_low < queue_state->window_strict.low))
        strict = 0;
    unsigned long long deadline = ((unsigned long long)deadline_high << 32) | deadline_low;
    report_schedule_candidate(queue,now_us,deadline,period,interface,strict);
    return result;

suppress_empty:
    /* Native stack bytes +77 and +7d..7f have no producer on this path. Use
     * an unconstrained register value to describe unspecified bits without
     * invoking C's undefined behavior for an uninitialized automatic object. */
    {
        unsigned int unspecified_status,unspecified_auxiliary;
        __asm__ volatile ("" : "=r"(unspecified_status),"=r"(unspecified_auxiliary));
        result.status3 = (unsigned char)unspecified_status;
        result.auxiliary = (unspecified_auxiliary & 0xffffff00U) | 1U;
        return result;
    }
}
