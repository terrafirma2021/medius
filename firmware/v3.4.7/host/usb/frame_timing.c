/* Medius v3.4.7 host — usb/frame_timing.c.
 * Recovered C and native assembly, grouped for source navigation.
 * Original entry addresses, firmware-byte hashes and function comments follow.
 */

#include "../include/types.h"

/* Native entry: 0x40389438. */
/*
 * Medius v3.4.7 — host application; 0x40389438.
 *
 * Copies a successful frame-clock snapshot into caller timing outputs.
 *
 * Calls: medius_dwc2_host_frame_clock_snapshot.
 *
 * Called by: medius_motion_grid_timer_cb, FUN_40387f0c, FUN_4202d86c, medius_host_phase_gate_open.
 *
 * Original function-byte SHA-256:
 * 71fb2a17bf280bc26bfbc407356b1f0af79021e04e1ee54a622b572c4dfa26ff.
 */

/*
 * base_ns: Required writable signed64 output on snapshot success.
 * period_ns: Required writable signed64 output on snapshot success; use distinct storage when
 *   independent values are required.
 * frame: Optional writable 16-bit output.
 * Returns: The snapshot helper result, 1 or 0.
 * Requirements/effects: Uses one local 32-byte snapshot. On success writes base first, period
 *   second and optional frame last; outputs are separate native word stores, not one atomic
 *   publication. On failure does not access caller outputs. There are no success-path
 *   NULL/capacity checks and no allocation.
 */

int medius_host_get_frame_timing(longlong *base_ns, longlong *period_ns, ushort *frame)
{
    MediusHostFrameClockSnapshot snapshot;
    int result = medius_dwc2_host_frame_clock_snapshot(&snapshot);
    if (result != 0) {
        *(volatile longlong *)base_ns = snapshot.base_ns;
        *(volatile longlong *)period_ns = snapshot.period_ns;
        if (frame != (ushort *)0)
            *(volatile ushort *)frame = snapshot.frame;
    }
    return result;
}

/* Native entry: 0x40389460. */
/*
 * Medius v3.4.7 — host application; 0x40389460.
 *
 * Returns the phase threshold selected by the last successful frame-clock sample.
 *
 * Called by: FUN_4202d86c, medius_host_phase_gate_open.
 *
 * Original function-byte SHA-256:
 * 5c0011fb268350ff44404362de78fc6a770a5987a71c65d48a9dc9c74a77c161.
 */

/*
 * Returns: Signed64 value 500000 ns for any nonzero cached low-rate byte, otherwise 400000 ns;
 *   high return word is zero.
 * Requirements/effects: MEMW then samples the byte at 0x3fcb974d once. Does not resample USB
 *   hardware, take a lock or validate cache age. A failed frame sample leaves the prior cached
 *   rate in use.
 */

longlong medius_host_frame_phase_threshold_ns(void)
{
    memw();
    uchar low_rate = MEDIUS_HOST_FRAME_LOW_RATE;
    return low_rate != 0 ? 500000LL : 400000LL;
}

/* Native entry: 0x4038947c. */
/*
 * Medius v3.4.7 — host application; 0x4038947c.
 *
 * Checks the age and magnitude of a cached frame-phase sample.
 *
 * Calls: esp_timer_get_time, vPortExitCritical, xPortEnterCriticalTimeout, xPortInIsrContext.
 *
 * Called by: medius_host_phase_gate_open.
 *
 * Original function-byte SHA-256:
 * 365535cfab051e7a0894b4a2b3996f4e0fa3806d53d92c30c59c99636c7b9aa7.
 */

/*
 * Returns: 1 precisely when the cached timestamp is nonzero, signed wrapped age is less than
 *   200000 us and phase error is within inclusive [-49999,49999] ns; otherwise 0.
 * Requirements/effects: Queries ISR context, requests mux 0x3fc9de00 indefinitely and ignores
 *   entry status. Reads error-low, timestamp-low, timestamp-high, error-high in that native order,
 *   then queries context and unlocks. No extra MEMW is inserted in these four reads. Zero
 *   timestamp returns without a timer call; otherwise samples current time after unlock. Age
 *   subtraction wraps to 64 bits before signed comparison. Negative ages are admitted because
 *   there is no lower-bound test. This is a software validity heuristic, not a physical
 *   synchronization or freshness guarantee.
 */

int medius_host_recent_phase_within_tolerance(void)
{
    xPortInIsrContext();
    xPortEnterCriticalTimeout(&MEDIUS_HOST_PHASE_LOCK,-1);
    /* These four native word reads have this order, without extra MEMWs. */
    uint error_low = MEDIUS_HOST_PHASE_ERROR_NS->low;
    uint sample_low = MEDIUS_HOST_PHASE_SAMPLE_US->low;
    uint sample_high = MEDIUS_HOST_PHASE_SAMPLE_US->high;
    uint error_high = MEDIUS_HOST_PHASE_ERROR_NS->high;
    xPortInIsrContext();
    vPortExitCritical(&MEDIUS_HOST_PHASE_LOCK);

    ulonglong sample_bits = ((ulonglong)sample_high << 32) | sample_low;
    if (sample_bits == 0)
        return 0;
    longlong now_us = esp_timer_get_time();
    longlong age_us = (longlong)((ulonglong)now_us - sample_bits);
    longlong error_ns = (longlong)(((ulonglong)error_high << 32) | error_low);
    /* Native code admits a negative age; there is no lower-bound test. */
    return age_us < 200000LL && error_ns >= -49999LL && error_ns <= 49999LL;
}

/* Native entry: 0x40389eb4. */
/*
 * Medius v3.4.7 — host application; 0x40389eb4.
 *
 * Opens outside a selected middle portion of the sampled USB frame, or when timing is unavailable.
 *
 * Calls: esp_timer_get_time, medius_host_frame_phase_threshold_ns, medius_host_get_frame_timing,
 * medius_host_recent_phase_within_tolerance.
 *
 * Called by: medius_hid_apply_credit_records, medius_vendor_apply_credit_records.
 *
 * Original function-byte SHA-256:
 * 40ee05ac2a6ba1cbf760401c6e2d25e925b2b5cb7d0d0d3c77ed9b4b5ac06a2c.
 */

/*
 * Returns: 0 inside the middle exclusion interval; 1 outside it or when recent-phase/frame timing
 *   is unavailable.
 * Requirements/effects: Short-circuits open when recent-phase validity or frame timing fails.
 *   Otherwise samples timer, computes signed wrapped delta=now_us*1000-base_ns, obtains the cached
 *   threshold and closes only when delta >= threshold-30000 and delta < period-59999. Lower bound
 *   is inclusive; upper is exclusive. All arithmetic follows native modulo-64 bit behavior before
 *   signed comparisons. There is no modulo-by-period, positive-period check or coherent combined
 *   snapshot across the three helper calls. Scheduling meaning and physical timing remain with
 *   callers/hardware.
 */

int medius_host_phase_gate_open(void)
{
    longlong base_ns;
    longlong period_ns;
    if (medius_host_recent_phase_within_tolerance() == 0 ||
        medius_host_get_frame_timing(&base_ns, &period_ns, (ushort *)0) == 0)
        return 1;

    longlong now_us = esp_timer_get_time();
    longlong delta_ns = (longlong)((ulonglong)now_us * 1000ULL - (ulonglong)base_ns);
    longlong threshold_ns = medius_host_frame_phase_threshold_ns();
    longlong lower_ns = (longlong)((ulonglong)threshold_ns - 30000ULL);
    longlong upper_ns = (longlong)((ulonglong)period_ns - 59999ULL);
    return !(delta_ns >= lower_ns && delta_ns < upper_ns);
}

/* Native entry: 0x40389f30. */
/* Original function-byte SHA-256:
 * c63bb35b73e14374c53dda1cd6d653daab8f9fb85ba2db9140d6cd550423e760. */
/* Fence and sample HFNUM once at the fixed USB controller. Return its low16
 * bits as an unsigned word, without applying the USB frame's 11-bit mask. */
unsigned int medius_host_get_frame(void)
{
    memw();
    unsigned int frame = MEDIUS_HOST_USB_REGISTERS->frame_number;
    return frame & 65535U;
}

/* Native entry: 0x40389f40. */
/* Original function-byte SHA-256:
 * 7cd634f6759cea0b8750bc51ef3bd60e6a24c085678eee51ff50a1e1817c3bbb. */
/* Sample HFNUM once after a fence. Return1 exactly when its unsigned32
 * difference from previous_frame, modulo2048, is1; otherwise0. Upper input
 * and hardware bits therefore do not affect the result. No state is changed. */
int medius_host_frame_is_next(unsigned int previous_frame)
{
    memw();
    unsigned int frame = MEDIUS_HOST_USB_REGISTERS->frame_number;
    return ((frame-previous_frame) & 2047U) == 1U;
}

/* Native entry: 0x42026368. */
/* Original function-byte SHA-256:
 * e99e827be360522c97a2b8cd860af1d92ee1cdc13ddeb1592300d01845b91e4e. */
/* Enter the SOF-mask lock indefinitely, ignoring the entry result. Sample
 * the shared WORD gate after entry; nonzero skips MMIO. Otherwise sample
 * GINTMSK once after a fence. Compare bit3 with low8(enabled), and if unequal
 * replace bit3 with low1(enabled), preserving every other sampled bit. Thus
 * nonboolean low bytes can cause a redundant write. Always exit the lock.
 * No other USB controller, acknowledgement, interrupt-delivery check or
 * recovery action is involved. The gate is a software condition. */
void medius_host_set_sof_interrupt(unsigned int enabled)
{
    xPortEnterCriticalTimeout(&MEDIUS_HOST_SOF_MASK_LOCK,-1);
    unsigned int requested = enabled & 255U;
    if (MEDIUS_HOST_SOF_MASK_GATE == 0) {
        memw();
        unsigned int mask = MEDIUS_HOST_USB_REGISTERS->interrupt_mask;
        if (((mask >> 3) & 1U) != requested) {
            memw();
            MEDIUS_HOST_USB_REGISTERS->interrupt_mask =
                (mask & 0xfffffff7U) | ((requested & 1U) << 3);
        }
    }
    vPortExitCritical(&MEDIUS_HOST_SOF_MASK_LOCK);
}

