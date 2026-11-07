/* Medius v3.4.7 device — link clock estimator. */
#include "../include/types.h"

/* Native byte counts are trusted, including counts beyond the declared
 * backing capacities. These reconstruction utilities retain wrapping 32-bit
 * addresses without introducing bounds checks or C array-bound assumptions. */
static inline __attribute__((always_inline)) volatile unsigned int *
link_sync_word_at(volatile unsigned int *words,unsigned int index)
{
    return (volatile unsigned int *)((unsigned int)words + index * 4U);
}

static inline __attribute__((always_inline)) const LinkSyncWindowSample *
link_sync_sample_at(const LinkSyncWindowSample *samples,unsigned int index)
{
    return (const LinkSyncWindowSample *)((unsigned int)samples + index * 12U);
}

/* Source reconstruction utilities for the two fitting blocks in the native
 * sync estimator, not additional native entries. Sums/products are raw64 bits
 * so signed native arithmetic wraps explicitly. Samples use physical storage
 * order; latest-time selection uses signed32 differences, not ring head order. */
static int link_sync_fit_drift(const LinkSyncWindowSample *samples,
    unsigned int count,unsigned int maximum_round_trip_us,int require_minimum_span,int *drift_out)
{
    unsigned int reference_index = 0xffffffffU;
    for (unsigned int index = 0; index < count; ++index) {
        if (link_sync_sample_at(samples,index)->round_trip_us > maximum_round_trip_us) continue;
        if (reference_index == 0xffffffffU ||
            (int)(link_sync_sample_at(samples,index)->time_us_low - link_sync_sample_at(samples,reference_index)->time_us_low) > 0)
            reference_index = index;
    }
    unsigned long long sum_time_delta = 0,sum_offset_delta = 0,sum_time_squared = 0,sum_time_offset = 0;
    unsigned int accepted_count = 0;
    int earliest_delta_us = 0;
    for (unsigned int index = 0; index < count; ++index) {
        if (link_sync_sample_at(samples,index)->round_trip_us > maximum_round_trip_us) continue;
        int delta_us = (int)(link_sync_sample_at(samples,index)->time_us_low - link_sync_sample_at(samples,reference_index)->time_us_low);
        int time_delta_ms = delta_us / 1000;
        int offset_delta_us = (int)(link_sync_sample_at(samples,index)->offset_us - link_sync_sample_at(samples,reference_index)->offset_us);
        sum_time_delta += (unsigned long long)(long long)time_delta_ms;
        sum_offset_delta += (unsigned long long)(long long)offset_delta_us;
        sum_time_squared += (unsigned long long)((long long)time_delta_ms * time_delta_ms);
        sum_time_offset += (unsigned long long)((long long)time_delta_ms * offset_delta_us);
        if (delta_us < earliest_delta_us) earliest_delta_us = delta_us;
        ++accepted_count;
    }
    if (accepted_count < 4 || (require_minimum_span && 0U - (unsigned int)earliest_delta_us < 3000000U))
        return 0;
    unsigned long long covariance = accepted_count * sum_time_offset - sum_time_delta * sum_offset_delta;
    unsigned long long variance = accepted_count * sum_time_squared - sum_time_delta * sum_time_delta;
    /* Native unsigned-range test conservatively bounds the scaled numerator. */
    const unsigned long long covariance_limit = 9223372036853ULL;
    if (covariance + covariance_limit > 2ULL * covariance_limit || (long long)variance <= 0) return 0;
    long long drift_ppb = link_sync_signed_divide(
        (long long)(covariance * 1000000ULL),(long long)variance);
    if (drift_ppb < -1000000LL) drift_ppb = -1000000LL;
    else if (drift_ppb > 1000000LL) drift_ppb = 1000000LL;
    *drift_out = (int)drift_ppb;
    return 1;
}

/* Native entry: 0x42021c30. */
/* Original function-byte SHA-256:
 * a132ea0a7b2d97d4f39e6d85f1a730e57c0f3eb973175864de169ca5b9cc0a57. */
/*
 * Recompute the worker-private link-clock estimate. Snapshot recent BYTE count,
 * read RTT slot0 even when count0, and scan remaining physical slots for the
 * smallest unsigned RTT; ties select the LAST index. Read its timestamp and
 * history count, then store reference-time and minimum RTT before reading
 * window-valid. No ring-head chronological ordering or ready check here.
 *
 * First try physical history[0..count), appending the current window if valid
 * (count+1 narrows8). With no history but a valid window use that one sample.
 * Filter to RTT<=min+8 (wrapped32); choose newest qualifying signed32 timestamp
 * as regression origin. x=trunc(signed32(time-origin)/1000) in milliseconds,
 * y=signed32(offset-base) in microseconds.
 * Fit needs>=4 points and unsigned(-minimum signed time delta)>=3,000,000us.
 * Failure falls back to all recent physical samples, RTT<=fresh_min+4, same
 * regression with>=4 points but no minimum span. Zero recent count skips it.
 *
 * Regression sums/products wrap64. Covariance=n*sum(x*y)-sum(x)*sum(y),
 * variance=n*sum(x*x)-sum(x)^2. Require positive signed variance and covariance
 * in[-9223372036853,9223372036853] using the native unsigned shifted-range test.
 * Drift=trunc(covariance*1,000,000/variance), clamped to+/-1,000,000ppb.
 * If both fits fail, copy freshest-read offset at the original best-RTT index,
 * store drift0, drift-valid0, then estimated offset. Ready is left unchanged.
 *
 * A valid fit caches that best-index offset and sets drift-valid1. Average only
 * recent samples with RTT<=the INITIAL minimum+4: signed32(offset-base) plus
 * trunc(signed32(time-reference)*drift/-1e9). Time is read before the explicit
 * ROM divide, offset afterward. Sum wraps64; add/subtract floor(count/2) by
 * sign, then signed-divide by count and add LOW32 to base offset. This rounds
 * halfway cases away from zero. No zero-denominator guard is added: corrupt
 * counts/RTT wrap or a long fit with no recent samples can call ROM divide0.
 *
 * Counts/indices are trusted native BYTEs. The local33-record workspace can
 * overflow if corrupted history count exceeds its native capacity; no cap or
 * sanitization is introduced. No lock/fence, coherent shared estimate, sample
 * authentication, physical clock accuracy or timing guarantee. Caller publishes
 * the worker estimate separately under its clock mux.
 */
void link_sync_recompute_estimate(void)
{
    volatile LinkSyncFilterState *filter_state = LINK_SYNC_FILTER;
    unsigned int recent_count = filter_state->recent_count;
    unsigned int initial_minimum_trip_us = *link_sync_word_at(filter_state->round_trips_us,0);
    unsigned int best_trip_index = 0;
    for (unsigned int index = 1; index < recent_count; ++index) {
        unsigned int round_trip_us = *link_sync_word_at(filter_state->round_trips_us,index);
        if (round_trip_us <= initial_minimum_trip_us) {
            best_trip_index = index;
            initial_minimum_trip_us = round_trip_us;
        }
    }
    unsigned int reference_time_us_low = *link_sync_word_at(filter_state->times_us_low,best_trip_index);
    unsigned int history_count = filter_state->history_count;
    filter_state->reference_us_low = reference_time_us_low;
    filter_state->estimated_round_trip_us = initial_minimum_trip_us;
    unsigned char window_valid = filter_state->window_valid;
    LinkSyncWindowSample samples[33];
    unsigned int sample_count = history_count;
    if (history_count != 0) {
        memcpy(samples,(const void *)filter_state->history,history_count * 12U);
        if (window_valid != 0) {
            unsigned int sample_time_us_low = filter_state->window_time_us_low;
            unsigned int round_trip_us = filter_state->window_round_trip_us;
            unsigned int sample_offset_us = filter_state->window_offset_us;
            /* The workspace is mutable; the helper supplies its raw address. */
            volatile LinkSyncWindowSample *appended_sample =
                (volatile LinkSyncWindowSample *)link_sync_sample_at(samples,history_count);
            appended_sample->offset_us = sample_offset_us;
            appended_sample->time_us_low = sample_time_us_low;
            appended_sample->round_trip_us = round_trip_us;
            sample_count = (unsigned char)(history_count + 1U);
        }
    } else if (window_valid != 0) {
        unsigned int round_trip_us = filter_state->window_round_trip_us;
        unsigned int sample_time_us_low = filter_state->window_time_us_low;
        unsigned int sample_offset_us = filter_state->window_offset_us;
        volatile LinkSyncWindowSample *only_sample = samples;
        only_sample->time_us_low = sample_time_us_low;
        only_sample->round_trip_us = round_trip_us;
        only_sample->offset_us = sample_offset_us;
        sample_count = 1;
    }
    int drift_ppb = 0;
    unsigned int base_offset;
    if (sample_count != 0) {
        unsigned int minimum = link_sync_sample_at(samples,0)->round_trip_us;
        for (unsigned int index = 1; index < sample_count; ++index)
            if (link_sync_sample_at(samples,index)->round_trip_us < minimum) minimum = link_sync_sample_at(samples,index)->round_trip_us;
        if (link_sync_fit_drift(samples,sample_count,minimum + 8U,1,&drift_ppb)) {
            /* Long-fit native order: offset read precedes drift publication. */
            base_offset = *link_sync_word_at(filter_state->offsets_us,best_trip_index);
            filter_state->estimated_drift_ppb = drift_ppb;
            goto fit_ready;
        }
    }
    if (recent_count != 0) {
        for (unsigned int index = 0; index < recent_count; ++index) {
            unsigned int sample_time_us_low = *link_sync_word_at(filter_state->times_us_low,index);
            unsigned int round_trip_us = *link_sync_word_at(filter_state->round_trips_us,index);
            unsigned int sample_offset_us = *link_sync_word_at(filter_state->offsets_us,index);
            volatile LinkSyncWindowSample *recent_sample =
                (volatile LinkSyncWindowSample *)link_sync_sample_at(samples,index);
            recent_sample->time_us_low = sample_time_us_low;
            recent_sample->round_trip_us = round_trip_us;
            recent_sample->offset_us = sample_offset_us;
        }
        unsigned int minimum = link_sync_sample_at(samples,0)->round_trip_us;
        for (unsigned int index = 1; index < recent_count; ++index)
            if (link_sync_sample_at(samples,index)->round_trip_us < minimum) minimum = link_sync_sample_at(samples,index)->round_trip_us;
        if (link_sync_fit_drift(samples,recent_count,minimum + 4U,0,&drift_ppb)) {
            /* Recent-fit native order: drift store precedes offset read. */
            filter_state->estimated_drift_ppb = drift_ppb;
            base_offset = *link_sync_word_at(filter_state->offsets_us,best_trip_index);
            goto fit_ready;
        }
    }
    base_offset = *link_sync_word_at(filter_state->offsets_us,best_trip_index);
    filter_state->estimated_drift_ppb = 0;
    filter_state->drift_valid = 0;
    filter_state->estimated_offset_us = base_offset;
    return;

fit_ready:
    filter_state->drift_valid = 1;
    unsigned int maximum_round_trip_us = initial_minimum_trip_us + 4U;
    unsigned long long sum = 0;
    unsigned int accepted_count = 0;
    for (unsigned int index = 0; index < recent_count; ++index) {
        if (*link_sync_word_at(filter_state->round_trips_us,index) > maximum_round_trip_us) continue;
        unsigned int sample_time_us_low = *link_sync_word_at(filter_state->times_us_low,index);
        ++accepted_count;
        long long correction = link_sync_signed_divide(
            (long long)(int)(sample_time_us_low - reference_time_us_low) * drift_ppb,-1000000000LL);
        unsigned int offset_delta = *link_sync_word_at(filter_state->offsets_us,index) - base_offset;
        sum += (unsigned long long)correction + (unsigned long long)(long long)(int)offset_delta;
    }
    unsigned int half_count = accepted_count >> 1;
    if ((long long)sum < 0) sum -= half_count;
    else sum += half_count;
    long long mean = link_sync_signed_divide((long long)sum,(long long)(int)accepted_count);
    filter_state->estimated_offset_us = base_offset + (unsigned int)mean;
}
