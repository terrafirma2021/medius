/* Medius v3.4.7 host — link clock estimator. */
#include "../include/types.h"

/* Source reconstruction utilities for the two fitting blocks in the native
 * sync estimator, not additional native entries. Sums/products are raw64 bits
 * so signed native arithmetic wraps explicitly. Samples use physical storage
 * order; latest-time selection uses signed32 differences, not ring head order. */
static int link_sync_fit_drift(const LinkSyncWindowSample *samples,
    unsigned int count,unsigned int maximum_trip,int require_three_seconds,int *drift_out)
{
    unsigned int reference = 0xffffffffU;
    for (unsigned int index = 0; index < count; ++index) {
        if (samples[index].round_trip_us > maximum_trip) continue;
        if (reference == 0xffffffffU ||
            (int)(samples[index].time_us_low - samples[reference].time_us_low) > 0)
            reference = index;
    }
    unsigned long long sum_x = 0,sum_y = 0,sum_xx = 0,sum_xy = 0;
    unsigned int used = 0;
    int earliest_delta_us = 0;
    for (unsigned int index = 0; index < count; ++index) {
        if (samples[index].round_trip_us > maximum_trip) continue;
        int delta_us = (int)(samples[index].time_us_low - samples[reference].time_us_low);
        int x = delta_us / 1000;
        int y = (int)(samples[index].offset_us - samples[reference].offset_us);
        sum_x += (unsigned long long)(long long)x;
        sum_y += (unsigned long long)(long long)y;
        sum_xx += (unsigned long long)((long long)x * x);
        sum_xy += (unsigned long long)((long long)x * y);
        if (delta_us < earliest_delta_us) earliest_delta_us = delta_us;
        ++used;
    }
    if (used < 4 || (require_three_seconds && 0U - (unsigned int)earliest_delta_us < 3000000U))
        return 0;
    unsigned long long covariance = used * sum_xy - sum_x * sum_y;
    unsigned long long variance = used * sum_xx - sum_x * sum_x;
    /* Native unsigned-range test conservatively bounds the scaled numerator. */
    const unsigned long long limit = 9223372036853ULL;
    if (covariance + limit > 2ULL * limit || (long long)variance <= 0) return 0;
    long long drift = link_sync_signed_divide(
        (long long)(covariance * 1000000ULL),(long long)variance);
    if (drift < -1000000LL) drift = -1000000LL;
    else if (drift > 1000000LL) drift = 1000000LL;
    *drift_out = (int)drift;
    return 1;
}

/* Native entry: 0x42020c60. */
/* Original function-byte SHA-256:
 * d06481c02497df5037b4807d237bd6848b2f1f5c11f3390e6035f9dcb34d1ed6. */
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
 * as regression origin. x=signed32(time-origin)/1000ms, y=signed32(offset-base).
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
    volatile LinkSyncFilterState *filter = LINK_SYNC_FILTER;
    unsigned int recent_count = filter->recent_count;
    unsigned int initial_minimum = filter->round_trips_us[0];
    unsigned int best = 0;
    for (unsigned int index = 1; index < recent_count; ++index) {
        unsigned int trip = filter->round_trips_us[index];
        if (trip <= initial_minimum) {
            best = index;
            initial_minimum = trip;
        }
    }
    unsigned int reference = filter->times_us_low[best];
    unsigned int history_count = filter->history_count;
    filter->reference_us_low = reference;
    filter->estimated_round_trip_us = initial_minimum;
    unsigned char window_valid = filter->window_valid;
    LinkSyncWindowSample samples[33];
    unsigned int sample_count = history_count;
    if (history_count != 0) {
        memcpy(samples,(const void *)filter->history,history_count * 12U);
        if (window_valid != 0) {
            unsigned int time = filter->window_time_us_low;
            unsigned int trip = filter->window_round_trip_us;
            unsigned int offset = filter->window_offset_us;
            samples[history_count].offset_us = offset;
            samples[history_count].time_us_low = time;
            samples[history_count].round_trip_us = trip;
            sample_count = (unsigned char)(history_count + 1U);
        }
    } else if (window_valid != 0) {
        unsigned int trip = filter->window_round_trip_us;
        unsigned int time = filter->window_time_us_low;
        unsigned int offset = filter->window_offset_us;
        samples[0] = (LinkSyncWindowSample){time,trip,offset};
        sample_count = 1;
    }
    int drift = 0;
    unsigned int base_offset;
    if (sample_count != 0) {
        unsigned int minimum = samples[0].round_trip_us;
        for (unsigned int index = 1; index < sample_count; ++index)
            if (samples[index].round_trip_us < minimum) minimum = samples[index].round_trip_us;
        if (link_sync_fit_drift(samples,sample_count,minimum + 8U,1,&drift)) {
            /* Long-fit native order: offset read precedes drift publication. */
            base_offset = filter->offsets_us[best];
            filter->estimated_drift_ppb = drift;
            goto fit_ready;
        }
    }
    if (recent_count != 0) {
        for (unsigned int index = 0; index < recent_count; ++index) {
            unsigned int time = filter->times_us_low[index];
            unsigned int trip = filter->round_trips_us[index];
            unsigned int offset = filter->offsets_us[index];
            samples[index] = (LinkSyncWindowSample){time,trip,offset};
        }
        unsigned int minimum = samples[0].round_trip_us;
        for (unsigned int index = 1; index < recent_count; ++index)
            if (samples[index].round_trip_us < minimum) minimum = samples[index].round_trip_us;
        if (link_sync_fit_drift(samples,recent_count,minimum + 4U,0,&drift)) {
            /* Recent-fit native order: drift store precedes offset read. */
            filter->estimated_drift_ppb = drift;
            base_offset = filter->offsets_us[best];
            goto fit_ready;
        }
    }
    base_offset = filter->offsets_us[best];
    filter->estimated_drift_ppb = 0;
    filter->drift_valid = 0;
    filter->estimated_offset_us = base_offset;
    return;

fit_ready:
    filter->drift_valid = 1;
    unsigned int maximum_trip = initial_minimum + 4U;
    unsigned long long sum = 0;
    unsigned int used = 0;
    for (unsigned int index = 0; index < recent_count; ++index) {
        if (filter->round_trips_us[index] > maximum_trip) continue;
        unsigned int time = filter->times_us_low[index];
        ++used;
        long long correction = link_sync_signed_divide(
            (long long)(int)(time - reference) * drift,-1000000000LL);
        unsigned int offset_delta = filter->offsets_us[index] - base_offset;
        sum += (unsigned long long)correction + (unsigned long long)(long long)(int)offset_delta;
    }
    unsigned int half_count = used >> 1;
    if ((long long)sum < 0) sum -= half_count;
    else sum += half_count;
    long long mean = link_sync_signed_divide((long long)sum,(long long)(int)used);
    filter->estimated_offset_us = base_offset + (unsigned int)mean;
}
