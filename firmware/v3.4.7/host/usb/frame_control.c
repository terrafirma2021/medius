/* Medius v3.4.7 host — usb/frame_control.c.
 * Recovered frame-interval controller; native identity follows the utilities.
 */

#include "../include/types.h"

/* Source reconstruction utilities for native4202563c, not additional native
 * entries. Unsigned64 arithmetic expresses native wrapped products/additions;
 * signed casts select its signed comparisons/divisions. Word access helpers
 * preserve separately visible LOW/HIGH or HIGH/LOW reads and publications. */
static unsigned long long frame_control_read(const volatile ClockWords *words)
{
    unsigned int low = words->low;
    unsigned int high = words->high;
    return ((unsigned long long)high << 32) | low;
}

static unsigned long long frame_control_read_high_first(const volatile ClockWords *words)
{
    unsigned int high = words->high;
    unsigned int low = words->low;
    return ((unsigned long long)high << 32) | low;
}

static void frame_control_write(volatile ClockWords *words,unsigned long long value)
{
    words->low = (unsigned int)value;
    words->high = (unsigned int)(value >> 32);
}

static void frame_control_write_high_first(volatile ClockWords *words,unsigned long long value)
{
    words->high = (unsigned int)(value >> 32);
    words->low = (unsigned int)value;
}

static void frame_control_clear(volatile MediusHostFrameController *control)
{
    volatile unsigned int *words = (volatile void *)control;
    for (unsigned int index = 0; index < 84; ++index) words[index] = 0;
}

/* The native byte count is trusted, including values outside the8-slot array.
 * Integer address arithmetic retains its32-bit stride/address wrap. */
static volatile MediusFrameDriftBucket *frame_control_bucket(
    volatile MediusHostFrameController *control,unsigned int index)
{
    return (volatile void *)((unsigned int)control + 80U + index * 32U);
}

static long long frame_control_clamp(long long value,long long low,long long high)
{
    if (value < low) return low;
    if (value > high) return high;
    return value;
}

/* Both native control paths floor the signed fractional tick request, cap its
 * absolute magnitude, then limit its step from the CURRENT hardware setting.
 * A clipped request drops the fraction; comparison uses quotient LOW32. */
static int frame_control_choose_ticks(volatile MediusHostFrameController *control,
    unsigned long long numerator,unsigned int nominal,int current_ticks)
{
    long long quotient = (long long)numerator / 1000000000LL;
    if ((long long)numerator < 0 && numerator != (unsigned long long)quotient * 1000000000ULL)
        --quotient;
    long long limit = (long long)(nominal / 2500U);
    int chosen = (int)frame_control_clamp(quotient,-limit,limit);
    unsigned int step = nominal > 12000U ? 5U : 1U;
    int ceiling = (int)((unsigned int)current_ticks + step);
    if (ceiling < chosen) chosen = ceiling;
    else {
        int floor = (int)((unsigned int)current_ticks - step);
        if (floor > chosen) chosen = floor;
    }
    unsigned long long remainder = 0;
    if ((unsigned int)chosen == (unsigned int)quotient)
        remainder = numerator - (unsigned long long)quotient * 1000000000ULL;
    frame_control_write(&control->tick_remainder,remainder);
    control->adjustment_ticks = (unsigned int)chosen;
    return chosen;
}

static void frame_control_accumulate_bucket(volatile MediusHostFrameController *control,
    unsigned long long base_ns,unsigned long long phase,unsigned int nominal)
{
    unsigned int count = control->bucket_count;
    unsigned int index = count - 1U, write_index = count;
    unsigned long long elapsed = 0;
    int create = count == 0;
    if (!create) {
        elapsed = base_ns - frame_control_read(&frame_control_bucket(control,index)->started_ns);
        create = (long long)elapsed > 1999999999LL;
    }
    if (create) {
        if (count == 8) {
            memmove((void *)&control->buckets[0],(const void *)&control->buckets[1],224);
            write_index = index = 7;
        } else {
            write_index = count;
            count = (count + 1U) & 255U;
            index = count - 1U;
        }
        volatile MediusFrameDriftBucket *fresh = frame_control_bucket(control,write_index);
        frame_control_write_high_first(&fresh->started_ns,base_ns);
        elapsed = base_ns - frame_control_read(&frame_control_bucket(control,index)->started_ns);
        control->bucket_count = (unsigned char)count;
        frame_control_write(&fresh->elapsed_sum_ns,0);
        frame_control_write(&fresh->phase_sum_ns,0);
        fresh->samples = 0;
    }
    volatile MediusFrameDriftBucket *bucket = frame_control_bucket(control,index);
    unsigned long long elapsed_sum = frame_control_read(&bucket->elapsed_sum_ns) + elapsed;
    bucket->elapsed_sum_ns.low = (unsigned int)elapsed_sum;
    unsigned long long integrated = frame_control_read_high_first(&control->integrated_tick_ns);
    bucket->elapsed_sum_ns.high = (unsigned int)(elapsed_sum >> 32);
    long long correction = (long long)integrated / (long long)nominal;
    unsigned long long old_sum = frame_control_read(&bucket->phase_sum_ns);
    unsigned int samples = bucket->samples;
    frame_control_write(&bucket->phase_sum_ns,phase - (unsigned long long)correction + old_sum);
    bucket->samples = samples + 1U;
}

typedef struct {
    unsigned long long origin,phase,drift;
} MediusFramePrediction;

/* Fit the first/last buckets with at least four signed-count samples. Mean
 * times/phase use separate signed divisions; no floating-point regression.
 * Publish drift and fitted phase HIGH before LOW, then the valid byte. */
static int frame_control_fit(volatile MediusHostFrameController *control,
    unsigned int nominal,MediusFramePrediction *prediction)
{
    unsigned int count = control->bucket_count;
    if (count == 0) return 0;
    unsigned int first = 0,last = count - 1U;
    while (first < count && (int)frame_control_bucket(control,first)->samples < 4) ++first;
    if (first >= last) return 0;
    while (first < last && (int)frame_control_bucket(control,last)->samples < 4) --last;
    if (first >= last) return 0;
    volatile MediusFrameDriftBucket *latest = frame_control_bucket(control,last);
    volatile MediusFrameDriftBucket *earliest = frame_control_bucket(control,first);
    int last_count = (int)latest->samples;
    int first_count = (int)earliest->samples;
    unsigned long long last_elapsed = frame_control_read_high_first(&latest->elapsed_sum_ns);
    unsigned long long last_mean = (unsigned long long)((long long)last_elapsed / last_count);
    last_mean += frame_control_read(&latest->started_ns);
    unsigned long long first_elapsed = frame_control_read_high_first(&earliest->elapsed_sum_ns);
    unsigned long long first_mean = (unsigned long long)((long long)first_elapsed / first_count);
    first_mean += frame_control_read(&earliest->started_ns);
    unsigned long long span = last_mean - first_mean;
    if ((long long)span <= 1999999999LL) return 0;
    long long last_phase = (long long)frame_control_read(&latest->phase_sum_ns) / last_count;
    long long first_phase = (long long)frame_control_read_high_first(&earliest->phase_sum_ns) / first_count;
    unsigned long long difference = (unsigned long long)last_phase - (unsigned long long)first_phase;
    if (difference + 1000000000ULL > 2000000000ULL) return 0;
    unsigned long long drift = (unsigned long long)((long long)(difference * 1000000000ULL) / (long long)span);
    unsigned long long origin = frame_control_read(&control->model_origin_ns);
    frame_control_write_high_first(&control->drift_ppb,drift);
    long long interpolated = (long long)((origin - last_mean) * difference) / (long long)span;
    long long integrated = (long long)frame_control_read(&control->integrated_tick_ns) / (long long)nominal;
    unsigned long long phase = (unsigned long long)last_phase + (unsigned long long)interpolated + (unsigned long long)integrated;
    frame_control_write_high_first(&control->modeled_phase_ns,phase);
    control->model_valid = 1;
    prediction->origin = origin;
    prediction->phase = phase;
    prediction->drift = drift;
    return 1;
}

static int frame_control_predict(volatile MediusHostFrameController *control,
    unsigned long long base_ns,unsigned int nominal,int current_ticks,MediusFramePrediction prediction)
{
    unsigned long long elapsed = base_ns - prediction.origin;
    unsigned long long ticks = (unsigned long long)(long long)current_ticks;
    if ((long long)elapsed > 0) {
        long long hardware_phase = (long long)(ticks * elapsed) / (long long)nominal;
        long long drift_phase = (long long)(prediction.drift * elapsed) / 1000000000LL;
        prediction.phase += (unsigned long long)hardware_phase + (unsigned long long)drift_phase;
        frame_control_write(&control->modeled_phase_ns,prediction.phase);
    }
    if (prediction.origin != 0 && (long long)base_ns > (long long)prediction.origin) {
        unsigned long long integrated = frame_control_read(&control->integrated_tick_ns);
        frame_control_write(&control->integrated_tick_ns,integrated + ticks * elapsed);
    }
    frame_control_write(&control->model_origin_ns,base_ns);
    long long proportional = (long long)(prediction.phase * 17ULL) / 5LL;
    long long frequency = frame_control_clamp((long long)(prediction.drift + (unsigned long long)proportional),-400000,400000);
    unsigned long long remainder = frame_control_read(&control->tick_remainder);
    unsigned long long numerator = (0ULL - (unsigned long long)frequency) * nominal + remainder;
    return frame_control_choose_ticks(control,numerator,nominal,current_ticks);
}

/* Native entry: 0x4202563c. */
/* Original function-byte SHA-256:
 * 0ff1f401cf18da0870e162f051174ec9295c2e80777637bbec747fdc9beb978f. */
/* Update USB frame-interval correction from one7-byte timing message.
 * payload: flag byte, unaligned LE remote_us32, fine_ns16; length is low16.
 * Short input or NULL initial frame mutex returns without touching state.
 * Copy timestamp fields BEFORE flag-bit0 admission; optional clock conversion
 * uses an initialized-zero output. Cache converted ns, then take CURRENT mutex
 * indefinitely, ignoring result. Fence blocked flag; blocked only gives CURRENT
 * mutex. No handle-lifetime or NULL-give guard is added.
 *
 * Sample time/publish reference LOW/HIGH before frame-clock snapshot. Snapshot
 * failure clears84 words of controller state, last-valid then last-update.
 * Processing otherwise needs signed elapsed>=20000us; a first valid remote
 * sample bypasses this when last-update0. A missing remote estimate requires
 * an earlier valid sample. Nominal clock changes clear the336-byte controller.
 *
 * Valid measurement: normalize phase into[-500000,499999]ns using fixed1ms
 * signed remainder and cached low-rate threshold400000/500000ns. Cache old PI
 * integral/fraction; update frame-base timing, drift-integral and regression
 * buckets. PI proportional gain17/5 uses OLD integral for this sample. Conditional
 * integration uses phase*(dt/1000)*36/1e7, clamped+/-350000; anti-windup suppresses
 * integration when saturated at+/-400000 and error pushes further outward.
 * Fractional ticks floor signed division, magnitude cap nominal/2500 and step
 * cap1 or5 (nominal>12000). Clipping discards the fraction. Twenty good samples
 * within10us set lock;>50us clears it, with hysteresis between thresholds.
 *
 * Without a new measurement, use an existing drift model or fit first/last
 * qualified buckets separated by>=2s; prediction combines separate truncated
 * hardware/drift contributions. Failed fit reapplies the current interval.
 * The source utilities retain the native bucket/fit/control arithmetic and
 * split publications. Bucket counts, nonzero nominal divisors and addresses
 * remain trusted. No added bounds cap or recovery for corrupt state.
 *
 * Apply hardware with BOTH nominal and adjustment arguments; publish last-update
 * after the call. A valid measurement additionally publishes last-valid and,
 * under phase mux, phase LOW/HIGH then sample-time LOW/HIGH. Always give freshly
 * sampled frame mutex. No atomic multi-field snapshot, rollback, physical clock
 * accuracy, interrupt timing or concurrency/lifetime guarantee is established. */
void medius_host_update_frame_controller(const unsigned char *payload,unsigned short length)
{
    if (length < 7 || MEDIUS_HOST_FRAME_CLOCK_MUTEX == NULL) return;
    unsigned int remote_us;
    unsigned short fine_ns;
    memcpy(&remote_us,payload + 1,4);
    memcpy(&fine_ns,payload + 5,2);
    long long converted_us = 0;
    unsigned int remote_valid = 0;
    if ((payload[0] & 1U) != 0)
        remote_valid = medius_link_remote_to_local_us(remote_us,&converted_us);
    unsigned long long target_ns = (unsigned long long)converted_us * 1000ULL;
    xQueueSemaphoreTake(MEDIUS_HOST_FRAME_CLOCK_MUTEX,0xffffffffU);
    memw(); if (MEDIUS_HOST_FRAME_CLOCK_BLOCKED != 0) goto release_mutex;
    unsigned long long now_us = (unsigned long long)esp_timer_get_time();
    frame_control_write(MEDIUS_HOST_FRAME_CLOCK_REFERENCE_US,now_us);
    MediusHostFrameClockSnapshot snapshot;
    snapshot.base_ns = 0;
    snapshot.nominal_ticks_per_ms = 0;
    snapshot.interval_ticks_minus_one = 0;
    volatile MediusHostFrameController *control = MEDIUS_HOST_FRAME_CONTROLLER;
    if (medius_dwc2_host_frame_clock_snapshot(&snapshot) == 0) {
        frame_control_clear(control);
        frame_control_write(MEDIUS_HOST_FRAME_LAST_VALID_US,0);
        frame_control_write(MEDIUS_HOST_FRAME_LAST_UPDATE_US,0);
        goto release_mutex;
    }
    unsigned int nominal = snapshot.nominal_ticks_per_ms;
    unsigned long long base_ns = (unsigned long long)snapshot.base_ns;
    if (remote_valid != 0) {
        unsigned long long last_update = frame_control_read(MEDIUS_HOST_FRAME_LAST_UPDATE_US);
        if (last_update != 0 && (long long)(now_us - last_update) <= 19999LL) goto release_mutex;
        unsigned long long old_sample = 0,old_origin = 0,old_integral = 0,old_fraction = 0;
        if (MEDIUS_HOST_FRAME_CACHED_NOMINAL == nominal) {
            old_sample = frame_control_read_high_first(&control->last_sample_ns);
            old_origin = frame_control_read(&control->model_origin_ns);
            old_integral = frame_control_read(&control->integral_ppb);
            old_fraction = frame_control_read(&control->tick_remainder);
        } else {
            frame_control_clear(control);
            MEDIUS_HOST_FRAME_CACHED_NOMINAL = nominal;
        }
        target_ns += fine_ns;
        memw(); unsigned int threshold = MEDIUS_HOST_FRAME_LOW_RATE != 0 ? 500000U : 400000U;
        int current_ticks = (int)(snapshot.interval_ticks_minus_one + 1U - nominal);
        control->adjustment_ticks = (unsigned int)current_ticks;
        unsigned long long phase = (unsigned long long)((long long)(base_ns - target_ns + threshold) % 1000000LL);
        if ((long long)phase < -500000LL) phase += 1000000ULL;
        else if ((long long)phase > 499999LL) phase -= 1000000ULL;
        unsigned long long dt = base_ns - old_sample;
        if (old_sample == 0 || dt - 1ULL > 199999999ULL) dt = 50000000ULL;
        frame_control_write(&control->last_sample_ns,base_ns);
        if (old_origin != 0) {
            unsigned long long elapsed = base_ns - old_origin;
            if ((long long)elapsed > 1000000000LL) control->bucket_count = 0;
            if ((long long)base_ns > (long long)old_origin) {
                unsigned long long integrated = frame_control_read(&control->integrated_tick_ns);
                frame_control_write(&control->integrated_tick_ns,
                    integrated + (unsigned long long)(long long)current_ticks * elapsed);
            }
        }
        frame_control_write(&control->model_origin_ns,base_ns);
        frame_control_write(&control->modeled_phase_ns,phase);
        control->model_valid = 0;
        if (phase + 50000ULL <= 100000ULL)
            frame_control_accumulate_bucket(control,base_ns,phase,nominal);
        else control->bucket_count = 0;
        long long proportional = (long long)(phase * 17ULL) / 5LL;
        long long frequency = (long long)(old_integral + (unsigned long long)proportional);
        if (!((frequency >= 400000LL && (long long)phase > 0) ||
              (frequency <= -400000LL && (long long)phase < 0))) {
            unsigned long long product = phase * (unsigned long long)((long long)dt / 1000LL) * 36ULL;
            long long increment = (long long)product / 10000000LL;
            long long integral = frame_control_clamp((long long)(old_integral + (unsigned long long)increment),-350000,350000);
            frame_control_write(&control->integral_ppb,(unsigned long long)integral);
        }
        frequency = frame_control_clamp(frequency,-400000,400000);
        unsigned long long numerator = (0ULL - (unsigned long long)frequency) * nominal + old_fraction;
        int chosen = frame_control_choose_ticks(control,numerator,nominal,current_ticks);
        unsigned long long absolute_phase = (long long)phase < 0 ? 0ULL - phase : phase;
        if (absolute_phase <= 10000ULL) {
            unsigned int stable = control->stable_samples;
            if (stable == 0xffff) control->locked = 1;
            else {
                stable = (stable + 1U) & 65535U;
                control->stable_samples = (unsigned short)stable;
                if (stable > 19) control->locked = 1;
            }
        } else {
            control->stable_samples = 0;
            if (absolute_phase > 50000ULL) control->locked = 0;
        }
        medius_host_apply_frame_interval_adjustment(nominal,chosen);
        frame_control_write(MEDIUS_HOST_FRAME_LAST_UPDATE_US,now_us);
        frame_control_write(MEDIUS_HOST_FRAME_LAST_VALID_US,now_us);
        xPortEnterCriticalTimeout(&MEDIUS_HOST_PHASE_LOCK,-1);
        /* Native phase at0x3fcb9760 precedes timestamp at0x3fcb9758. */
        frame_control_write(MEDIUS_HOST_PHASE_ERROR_NS,phase);
        frame_control_write(MEDIUS_HOST_PHASE_SAMPLE_US,now_us);
        vPortExitCritical(&MEDIUS_HOST_PHASE_LOCK);
    } else {
        if (frame_control_read(MEDIUS_HOST_FRAME_LAST_VALID_US) == 0) goto release_mutex;
        unsigned long long last_update = frame_control_read(MEDIUS_HOST_FRAME_LAST_UPDATE_US);
        if ((long long)(now_us - last_update) <= 19999LL) goto release_mutex;
        int current_ticks = (int)(snapshot.interval_ticks_minus_one + 1U - nominal);
        if (MEDIUS_HOST_FRAME_CACHED_NOMINAL != nominal) {
            frame_control_clear(control);
            MEDIUS_HOST_FRAME_CACHED_NOMINAL = nominal;
        }
        control->adjustment_ticks = (unsigned int)current_ticks;
        MediusFramePrediction prediction;
        int modeled = control->model_valid != 0;
        if (modeled) {
            unsigned int origin_low = control->model_origin_ns.low;
            unsigned int phase_low = control->modeled_phase_ns.low;
            unsigned int origin_high = control->model_origin_ns.high;
            unsigned int phase_high = control->modeled_phase_ns.high;
            prediction.origin = ((unsigned long long)origin_high << 32) | origin_low;
            prediction.phase = ((unsigned long long)phase_high << 32) | phase_low;
            prediction.drift = frame_control_read(&control->drift_ppb);
        } else modeled = frame_control_fit(control,nominal,&prediction);
        int chosen = modeled ? frame_control_predict(control,base_ns,nominal,current_ticks,prediction) : current_ticks;
        medius_host_apply_frame_interval_adjustment(nominal,chosen);
        frame_control_write(MEDIUS_HOST_FRAME_LAST_UPDATE_US,now_us);
    }
release_mutex:
    xQueueGenericSend(MEDIUS_HOST_FRAME_CLOCK_MUTEX,NULL,0,0);
}

/* Native entry: 0x42026220. */
/* Original function-byte SHA-256:
 * 4a2a1adcd9524c4b9d13a08c176a5fe7485a0f92f9f2ee8d965274d77a5dfff4. */
/*
 * Heartbeat-driven frame-clock recovery. Snapshot initial frame mutex; NULL
 * returns. Take that handle indefinitely, ignoring status, then fence/sample
 * blocked BYTE. Blocked gives a FRESH mutex handle with no controller/time
 * accesses. Otherwise obtain a hardware frame snapshot. Failure clears84
 * controller WORDs, last-valid LOW/HIGH, then last-update LOW/HIGH, and gives.
 *
 * Successful snapshot needs a nonzero last-valid time. If reference time is
 * nonzero, sample now then REREAD reference LOW/HIGH; only signed64 elapsed
 * >5,000,000us triggers recovery. Missing reference triggers it immediately.
 * Cache nominal ticks when changed. Current adjustment is interval+1-nominal
 * modulo32; step=nominal>12000?5:1. If signed(current+step)<0 choose current+
 * step, else choose max(signed(current-step),0), retaining wrapped32 sums.
 *
 * Clear all84 controller WORDs BEFORE storing the chosen adjustment at+16.
 * Call hardware apply with BOTH nominal and signed adjustment arguments;
 * Ghidra omitted these arguments and moved the adjustment store before clear.
 * Sample time again; read CURRENT controller adjustment, publish last-update
 * LOW/HIGH, then clear last-valid LOW/HIGH only if that sampled adjustment0.
 * Native hardware apply may decline a write; no result or rollback is checked.
 * Every acquired path gives a freshly sampled mutex, without NULL/ownership
 * validation. No dedicated timer, atomic timestamp snapshot or physical timing
 * guarantee; execution depends on the heartbeat task and mutex availability.
 */
void medius_host_frame_clock_maintenance(void)
{
    RtosQueue *mutex = MEDIUS_HOST_FRAME_CLOCK_MUTEX;
    if (mutex == 0) return;
    (void)xQueueSemaphoreTake(mutex,0xffffffffU);
    memw(); if (MEDIUS_HOST_FRAME_CLOCK_BLOCKED != 0) goto release_mutex;
    MediusHostFrameClockSnapshot snapshot;
    volatile MediusHostFrameController *control = MEDIUS_HOST_FRAME_CONTROLLER;
    if (medius_dwc2_host_frame_clock_snapshot(&snapshot) == 0) {
        frame_control_clear(control);
        frame_control_write(MEDIUS_HOST_FRAME_LAST_VALID_US,0);
        frame_control_write(MEDIUS_HOST_FRAME_LAST_UPDATE_US,0);
        goto release_mutex;
    }
    if (frame_control_read(MEDIUS_HOST_FRAME_LAST_VALID_US) == 0) goto release_mutex;
    if (frame_control_read(MEDIUS_HOST_FRAME_CLOCK_REFERENCE_US) != 0) {
        unsigned long long now = (unsigned long long)esp_timer_get_time();
        unsigned long long reference = frame_control_read(MEDIUS_HOST_FRAME_CLOCK_REFERENCE_US);
        if ((long long)(now - reference) <= 5000000LL) goto release_mutex;
    }
    unsigned int nominal = snapshot.nominal_ticks_per_ms;
    if (MEDIUS_HOST_FRAME_CACHED_NOMINAL != nominal) MEDIUS_HOST_FRAME_CACHED_NOMINAL = nominal;
    unsigned int current = snapshot.interval_ticks_minus_one + 1U - nominal;
    unsigned int step = nominal > 12000U ? 5U : 1U;
    int next = (int)(current + step);
    if (next >= 0) {
        next = (int)(current - step);
        if (next < 0) next = 0;
    }
    frame_control_clear(control);
    control->adjustment_ticks = (unsigned int)next;
    medius_host_apply_frame_interval_adjustment(nominal,next);
    unsigned long long now = (unsigned long long)esp_timer_get_time();
    unsigned int applied = control->adjustment_ticks;
    frame_control_write(MEDIUS_HOST_FRAME_LAST_UPDATE_US,now);
    if (applied == 0) frame_control_write(MEDIUS_HOST_FRAME_LAST_VALID_US,0);
release_mutex:
    (void)xQueueGenericSend(MEDIUS_HOST_FRAME_CLOCK_MUTEX,0,0,0);
}
