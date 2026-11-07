/* Device input scheduling: USB phase deadlines and one-shot timer arming. */
#include "../include/types.h"

/* Native entry: 0x4202aa4c. */
/* Original function-byte SHA-256:
 * f9ba8da9274e5783330111d0be17df1f27e914a46eaa877ab23db7c861efa787. */
/*
 * Select a phase-relative input deadline in NANOSECONDS. now_us is one aligned
 * 64-bit argument in A2/A3; deadline_ns is the output pointer in A4. Return the
 * cached nonzero phase-valid BYTE on success, otherwise0 with output untouched.
 *
 * Under credit lock (entry result ignored), require valid!=0, samples>=16,
 * nonzero recovery epoch, signed wrapping epoch age<3000us, recovery mode<2,
 * and a fenced clear USB suspend flag. Negative ages pass. Both epoch snapshots
 * read LOW then HIGH with separate MEMW; no unrecorded fresh reads are added.
 *
 * Read input0 active BYTE, then snapshot signed interface count once. An active
 * input0 with an in-range signed interface chooses its nonzero learned minimum;
 * otherwise scan the initial count of 12-byte learners for the first nonzero
 * minimum. No nominal six-interface cap. At the common selection exit, sample
 * reference LOW/HIGH even if no nonzero minimum was found, then unlock. Only a
 * nonzero minimum writes output LOW/HIGH = reference_ns + minimum_us*1000.
 * No output NULL check, own allocation or runtime timing guarantee.
 */
unsigned char input_get_timing_deadline(unsigned long long now_us,
    TimestampWords *deadline_ns)
{
    (void)xPortEnterCriticalTimeout(&CREDIT_LOCK,-1);
    unsigned char valid = USB_FRAME_PHASE.valid;
    if (valid == 0) goto unavailable;
    unsigned char samples = USB_FRAME_PHASE.samples;
    if (samples < 16) goto unavailable;
    memw();
    unsigned int epoch_low = REPORT_RECOVERY_EPOCH.low;
    memw();
    unsigned int epoch_high = REPORT_RECOVERY_EPOCH.high;
    if ((epoch_low | epoch_high) == 0) goto unavailable;
    memw();
    epoch_low = REPORT_RECOVERY_EPOCH.low;
    memw();
    epoch_high = REPORT_RECOVERY_EPOCH.high;
    unsigned long long epoch = ((unsigned long long)epoch_high << 32) | epoch_low;
    if ((long long)(now_us - epoch) >= 3000LL) goto unavailable;
    if (USB_FRAME_PHASE.recovery_mode >= 2) goto unavailable;
    memw();
    if (USB_SUSPENDED != 0) goto unavailable;

    unsigned char input_active = REPORT_BLOCK0_ACTIVE;
    int count = USB_INTERFACE_COUNT;
    unsigned int minimum_us = 0;
    if (input_active != 0) {
        int preferred = REPORT_BLOCK0_INTERFACE;
        if (preferred >= 0 && preferred < count) {
            const volatile ReportIntervalLearner *learner =
                (const volatile ReportIntervalLearner *)
                ((unsigned int)REPORT_INTERVAL_LEARNERS + (unsigned int)preferred * 12U);
            minimum_us = learner->minimum_us;
            if (minimum_us != 0) goto selected;
        }
    }
    if (count < 1) goto unavailable;
    for (unsigned int index = 0; index < (unsigned int)count; ++index) {
        const volatile ReportIntervalLearner *learner =
            (const volatile ReportIntervalLearner *)
            ((unsigned int)REPORT_INTERVAL_LEARNERS + index * 12U);
        minimum_us = learner->minimum_us;
        if (minimum_us != 0) break;
    }
selected:
    {
        unsigned int reference_low = USB_FRAME_PHASE.reference_ns.low;
        unsigned int reference_high = USB_FRAME_PHASE.reference_ns.high;
        vPortExitCritical(&CREDIT_LOCK);
        if (minimum_us == 0) return 0;
        unsigned long long deadline =
            (((unsigned long long)reference_high << 32) | reference_low) + minimum_us * 1000ULL;
        volatile TimestampWords *output = deadline_ns;
        output->low = (unsigned int)deadline;
        output->high = (unsigned int)(deadline >> 32);
        return valid;
    }
unavailable:
    vPortExitCritical(&CREDIT_LOCK);
    return 0;
}

/* Native entry: 0x4202ab40. */
/* Original function-byte SHA-256:
 * c58ab484e4ae2e3f89a56737dee92ca196f2b06ccb2ebc2973b937eb8f5e3a19. */
/*
 * Compute the next t0 one-shot expiration. Sample time once, then ask the timing
 * helper for a nanosecond deadline. Without a usable phase, try saved target
 * LOW/HIGH +1000us; if it is not later than now by signed absolute timestamp
 * ordering, choose now+1000us and delay1000 instead.
 *
 * With phase, signed-divide deadline_ns by1000 and subtract150us. If target is
 * not later than now+50us, add (signed((now+50)-target)/1000 +1)*1000 using
 * modulo64 arithmetic. Only this catch-up branch clamps a nonpositive signed
 * delay to1us, retaining the computed absolute target even when clamped.
 *
 * Publish target LOW, read t0 handle WORD, publish target HIGH, then call
 * esp_timer_start_once(handle,delay). Ignore its result; do not stop an existing
 * timer, clear armed state or retry failures. No mutex is taken locally.
 * This is software-timer scheduling: callback delivery depends on the shared
 * ESP timer dispatcher and competing work, so the requested time is not a
 * guarantee that processing runs exactly then.
 */
void input_timer_rearm(void)
{
    unsigned long long now_us = (unsigned long long)esp_timer_get_time();
    TimestampWords phase_deadline;
    unsigned long long target;
    unsigned long long delay;
    if (input_get_timing_deadline(now_us,&phase_deadline) == 0) {
        unsigned int low = INPUT_TIMER_TARGET.low;
        unsigned int high = INPUT_TIMER_TARGET.high;
        target = (((unsigned long long)high << 32) | low) + 1000ULL;
        if ((long long)now_us < (long long)target) {
            delay = target - now_us;
        } else {
            target = now_us + 1000ULL;
            delay = 1000ULL;
        }
    } else {
        unsigned long long deadline_ns =
            ((unsigned long long)phase_deadline.high << 32) | phase_deadline.low;
        target = (unsigned long long)((long long)deadline_ns / 1000LL) - 150ULL;
        unsigned long long guard = now_us + 50ULL;
        if ((long long)guard < (long long)target) {
            delay = target - now_us;
        } else {
            long long missed_us = (long long)(guard - target);
            unsigned long long periods = (unsigned long long)(missed_us / 1000LL) + 1ULL;
            target += periods * 1000ULL;
            delay = target - now_us;
            if ((long long)delay <= 0) delay = 1;
        }
    }
    INPUT_TIMER_TARGET.low = (unsigned int)target;
    EspTimer *timer = INPUT_TIMER_HANDLE;
    INPUT_TIMER_TARGET.high = (unsigned int)(target >> 32);
    (void)esp_timer_start_once(timer,delay);
}

/* Native entry: 0x4202b0bc. */
/* Original function-byte SHA-256:
 * 3afcdf5056fd46061aa2c8d8d55c889d10a2634fdf1f344cf7a01afc618991b7. */
/*
 * t1 catch-action timer callback; argument is ignored. Require a non-NULL t0
 * handle, then a non-NULL input-timer mutex. Take forever, ignoring status.
 * Fence/read armed BYTE; if clear, fence/store1 BEFORE rearming t0. Give a
 * freshly reloaded mutex with queue-send(NULL,wait0,back), ignoring status.
 * No own action dequeue, clock read, armed rollback or task is created here.
 * t1 and t0 use the shared ESP timer dispatcher configured by worker startup.
 */
void catch_action_timer_cb(void *unused_argument)
{
    (void)unused_argument;
    if (INPUT_TIMER_HANDLE == 0) return;
    RtosQueue *mutex = INPUT_TIMER_MUTEX;
    if (mutex == 0) return;
    (void)xQueueSemaphoreTake(mutex,0xffffffffU);
    memw();
    if (INPUT_TIMER_ARMED == 0) {
        memw();
        INPUT_TIMER_ARMED = 1;
        input_timer_rearm();
    }
    (void)xQueueGenericSend(INPUT_TIMER_MUTEX,0,0,0);
}
