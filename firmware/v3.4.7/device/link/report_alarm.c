/* Medius v3.4.7 device: dedicated GPTimer report-decision alarm. */

#include "../include/types.h"

/* Native entry: 0x40377a2c. */
/* Original function-byte SHA-256:
 * c7e66e9a4ed75e6f0edfd086f07047b30bc3c9ea804333a0e0dd2930644be507. */
/* Arm the dedicated decision GPTimer for an absolute signed64 deadline,
 * supplied as LOW32/HIGH32 words. A missing timer returns immediately.
 * Under the credit lock, replace the saved deadline only when absent, later
 * than the request, or already due. Sample now once. Program a one-shot alarm
 * at current hardware count + max(signed64(deadline-now-5),2) ticks, using
 * native modulo64 subtraction/addition. This timer is configured at1 MHz.
 * Save the requested deadline BEFORE reading the count/programming the alarm.
 * Both driver statuses are ignored; a failed count read leaves initialized0.
 * Reload count, flags and config padding are all0. ISR-context queries before
 * lock entry and exit have ignored return values; lock timeout is UINT_MAX.
 * No conversion, timer creation/start or returned status occurs here. */
void decision_timer_arm(unsigned int deadline_low,int deadline_high)
{
    if (DECISION_TIMER_HANDLE == 0)
        return;
    xPortInIsrContext();
    xPortEnterCriticalTimeout(&CREDIT_LOCK,0xffffffffU);
    unsigned long long now_us = (unsigned long long)esp_timer_get_time();
    unsigned int saved_low = DECISION_TIMER_DEADLINE.low;
    unsigned int saved_high = DECISION_TIMER_DEADLINE.high;
    unsigned long long saved_deadline = ((unsigned long long)saved_high << 32) | saved_low;
    unsigned long long requested_deadline = ((unsigned long long)(unsigned int)deadline_high << 32) | deadline_low;
    if (saved_deadline == 0 || (long long)requested_deadline < (long long)saved_deadline || (long long)saved_deadline <= (long long)now_us) {
        Gptimer *timer = DECISION_TIMER_HANDLE;
        DECISION_TIMER_DEADLINE.low = deadline_low;
        DECISION_TIMER_DEADLINE.high = (unsigned int)deadline_high;
        unsigned long long hardware_count = 0;
        gptimer_get_raw_count(timer,&hardware_count);
        GptimerAlarmConfig alarm;
        alarm.reload_count = 0;
        alarm.flags = 0;
        alarm.padding20 = 0;
        long long delay_ticks = (long long)(requested_deadline - 5ULL - now_us);
        if (delay_ticks < 2)
            delay_ticks = 2;
        alarm.alarm_count = hardware_count + (unsigned long long)delay_ticks;
        gptimer_set_alarm_action(DECISION_TIMER_HANDLE,&alarm);
    }
    xPortInIsrContext();
    vPortExitCritical(&CREDIT_LOCK);
}

/* Native entry: 0x4037908c. */
/* Original function-byte SHA-256:
 * 3c405da7bce5ae69ece6359a7c7308a4927e00358dfc225f6a3e8538502c1949. */
/* Dedicated GPTimer interrupt callback; native code reads no callback arguments
 * and always returns0 (no direct task-woken indication). This is hardware-timer
 * ISR work, not a FreeRTOS software-timer or shared esp_timer task callback.
 *
 * Snapshot the saved absolute deadline under the credit lock. Before each pass,
 * spin on clock reads while the target is future and its signed modular delay
 * is <=10 us; a target farther away does NOT skip the following queue scan.
 * Under the lock, fence/read fast-enabled, clear the saved LOW/HIGH deadline,
 * and return if disabled. Scan interface queues, stopping on deduct-one, current
 * interface-count bound, or a fenced disabled flag after an interface.
 *
 * Active windows compare now with window_start/window_end. Inside that span,
 * clear reservation when window_strict is due and schedule using window_deadline
 * and the cached strict-due bit. Expired windows can set deferred if the queue
 * prefix has pending kind and expiry deferral is enabled; then clear active and
 * reservation. Future active windows with no extra_pending select window_start,
 * or a future reserved window_strict, as the next wake. The signed64 MAX sentinel
 * means no candidate; zero candidates are ignored. No queue-index cap is added.
 *
 * Unlock and resample time. Revisit a <=10-us/due target for at most4 total
 * passes; otherwise rearm through decision_timer_arm. The near-deadline
 * spin itself has no retry/time limit. Individual timestamp HIGH/LOW reads and
 * shared-state fences are explicit; no hardware timing guarantee is implied. */
unsigned int decision_timer_alarm_callback(Gptimer *timer,
    const GptimerAlarmEvent *event,void *context)
{
    (void)timer;
    (void)event;
    (void)context;
    xPortEnterCriticalTimeout(&CREDIT_LOCK,0xffffffffU);
    unsigned int target_low = DECISION_TIMER_DEADLINE.low;
    unsigned int target_high = DECISION_TIMER_DEADLINE.high;
    vPortExitCritical(&CREDIT_LOCK);
    unsigned long long target = ((unsigned long long)target_high << 32) | target_low;
    unsigned int passes = 4;
    for (;;) {
        unsigned long long now_us = (unsigned long long)esp_timer_get_time();
        while (target != 0 && (long long)now_us < (long long)target) {
            if ((long long)(target-now_us) > 10)
                break;
            now_us = (unsigned long long)esp_timer_get_time();
        }
        xPortEnterCriticalTimeout(&CREDIT_LOCK,0xffffffffU);
        memw();
        unsigned int enabled = REPORT_FAST_ENABLED;
        DECISION_TIMER_DEADLINE.low = 0;
        DECISION_TIMER_DEADLINE.high = 0;
        if (enabled == 0) {
            vPortExitCritical(&CREDIT_LOCK);
            return 0;
        }
        unsigned long long next_deadline = 0x7fffffffffffffffULL;
        for (unsigned int interface = 0;; ++interface) {
            memw();
            if (USB_SUSPENDED != 0 || (int)interface >= CREDIT_INTERFACES.count)
                break;
            CreditInterfaceQueue *queue = (CreditInterfaceQueue *)
                ((unsigned int)CREDIT_INTERFACE_QUEUES + interface*0x3c0U);
            volatile CreditInterfaceQueue *queue_state = queue;
            now_us = (unsigned long long)esp_timer_get_time();
            if (queue_state->window_active != 0) {
                int now_high = (int)(now_us >> 32);
                unsigned int now_low = (unsigned int)now_us;
                int start_high = (int)queue_state->window_start.high;
                unsigned int before_start = now_high < start_high ||
                    (now_high == start_high && now_low < queue_state->window_start.low);
                unsigned int choose_candidate = before_start;
                if (!before_start) {
                    int strict_high = (int)queue_state->window_strict.high;
                    unsigned int strict_low = queue_state->window_strict.low;
                    unsigned int strict_due = now_high > strict_high ||
                        (now_high == strict_high && now_low >= strict_low);
                    int end_high = (int)queue_state->window_end.high;
                    unsigned int before_end = now_high < end_high ||
                        (now_high == end_high && now_low < queue_state->window_end.low);
                    if (before_end) {
                        unsigned short period = REPORT_INTERFACE_PERIODS[interface];
                        if (strict_due)
                            queue_state->reservation = 0;
                        unsigned int deadline_low = queue_state->window_deadline.low;
                        unsigned int deadline_high = queue_state->window_deadline.high;
                        unsigned long long requested_deadline = ((unsigned long long)deadline_high << 32) | deadline_low;
                        report_schedule_candidate(queue,now_us,requested_deadline,period,interface,(unsigned char)strict_due);
                        choose_candidate = queue_state->window_active != 0;
                    } else {
                        if (queue_state->extra_pending == 0 && report_prefix_has_pending_kind(queue) != 0 &&
                            queue_state->expiry_defer_enabled != 0)
                            queue_state->deferred = 1;
                        queue_state->window_active = 0;
                        queue_state->reservation = 0;
                    }
                }
                if (choose_candidate && queue_state->extra_pending == 0 && report_prefix_has_pending_kind(queue) != 0) {
                    unsigned int high = queue_state->window_start.high;
                    unsigned int low = queue_state->window_start.low;
                    unsigned long long candidate = ((unsigned long long)high << 32) | low;
                    unsigned int select = (long long)now_us < (long long)candidate;
                    if (!select && queue_state->reservation != 0) {
                        high = queue_state->window_strict.high;
                        low = queue_state->window_strict.low;
                        candidate = ((unsigned long long)high << 32) | low;
                        select = (long long)now_us < (long long)candidate;
                    }
                    if (select && candidate != 0 && (long long)candidate < (long long)next_deadline)
                        next_deadline = candidate;
                }
            }
            memw();
            if (REPORT_FAST_ENABLED == 0)
                break;
        }
        vPortExitCritical(&CREDIT_LOCK);
        if (next_deadline == 0x7fffffffffffffffULL)
            return 0;
        now_us = (unsigned long long)esp_timer_get_time();
        if ((long long)(next_deadline-now_us) > 10 || --passes == 0) {
            decision_timer_arm((unsigned int)next_deadline,(int)(next_deadline >> 32));
            return 0;
        }
        target = next_deadline;
    }
}
