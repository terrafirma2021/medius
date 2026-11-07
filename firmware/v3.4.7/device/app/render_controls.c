/* Device host-motion feedback, session state and worker requests. */
#include "../include/types.h"

/* Render-control reconstruction utilities: the two native notification
 * sequences inline here; no extra native function. Gate the initial handle,
 * query ISR context, then read the handle again before choosing the API.
 */
static __attribute__((always_inline)) inline void render_notify_worker(unsigned int bits)
{
    if (MOTION_TXWD_TASK == NULL)
        return;
    int in_isr = xPortInIsrContext();
    RtosTask *task = MOTION_TXWD_TASK;
    if (in_isr != 0) {
        int woken = 0;
        (void)xTaskGenericNotifyFromISR(task,0,bits,1,NULL,&woken);
        if (woken != 0)
            _frxt_setup_switch();
    } else {
        (void)xTaskGenericNotify(task,0,bits,1,NULL);
    }
}

/* Native entry: 0x420354ec. */
/* Original function-byte SHA-256:
 * d906dadcafe087d735f9ce0c4657b7342b56f3e2c85ace15ce0dd9274f02710d. */
/* Fence/read the RAW served poll-interval BYTE, then pass its one-byte stack
 * snapshot to link opcode0x30,flags0,length1 through send_wait100. The host
 * routes it to its poll-override handler. Ignore admission status; this wrapper
 * adds no retry, interval normalization, clock read or persistent state change.
 */
void link_publish_poll_interval(void)
{
    memw();
    unsigned char interval = IMPERFECT_SERVED_INTERVAL;
    (void)link_send_wait100(0x30,0,&interval,1);
}

/* Native entry: 0x420355c8. */
/* Original function-byte SHA-256:
 * 132980e2ffe7ee30bb8a6df2a1cf9e3e379aa4c6fbcafc883cd680d76e0a31ed. */
/* Fence/read clone-active BYTE. Zero returns false without a USB query;
 * any nonzero value delegates bus0 to the reviewed bool configuration helper
 * and returns its result. No mutex, generation check or active recheck.
 */
bool clone_is_configured(void)
{
    memw();
    if (CLONE_ACTIVE == 0)
        return false;
    return usb_device_is_configured(0);
}

/* Native entry: 0x420358dc. */
/* Original function-byte SHA-256:
 * 0340e4cfa7aa07e388d66fcbab9e7bda6c93a59636c980b05e3277fc073481f2. */
/* Fence/read movement-riding duration WORD in microseconds, divide unsigned
 * by1000, and return LOW16 milliseconds as a WORD. Truncates fractional ms
 * and wraps the quotient at65536; does not clamp, lock or change the option.
 */
unsigned int option_get_movement_riding_ms(void)
{
    memw();
    unsigned int duration = MOVEMENT_RIDING_US;
    return (duration / 1000U) & 0xffffU;
}

/* Native entry: 0x420359b8. */
/* Original function-byte SHA-256:
 * 2388af122d29d59a2995c050d071b3ef25b69b37fbf228ddc1c102c2bc067062. */
/* Fence/read bearing-window duration WORD in microseconds, divide unsigned
 * by1000 and return LOW16 milliseconds as a WORD. Native reciprocal multiply
 * implements this division; no rounding up, clamping, lock or state change.
 */
unsigned int option_get_bearing_window_ms(void)
{
    memw();
    unsigned int duration = MOTION_OPTIONS.bearing_window_us;
    return (duration / 1000U) & 0xffffU;
}

/* Native entry: 0x420359d0. */
/* Original function-byte SHA-256:
 * 2c328b49e538925ffebc57ba346ca047d58f12b07af3198c1b5112da9fb3ae30. */
/* Fence/read the complete coupled-bearing BYTE unchanged. Values beyond0/1
 * remain visible; no normalization, lock or state mutation.
 */
unsigned char option_get_bearing_coupled(void)
{
    memw();
    return BEARING_COUPLED;
}

/* Native entry: 0x42035db0. */
/* Original function-byte SHA-256:
 * 492c5a77a468bc355436ce0945e79028fe5dbd53c3bd111c43cab23f00585205. */
/* Fence/test clone-active BYTE; any nonzero value permits txwd notification
 * mask 0x04 (bit 2) at index0 with eSetBits1. Require initial task handle, query ISR context,
 * then reload handle without rechecking it. ISR path sets woken0 and requests
 * a switch only when the notification changes it to nonzero. Task path ignores
 * status. Worker mask 0x04 publishes ordered power state while clone remains active;
 * no state snapshot, blocking wait, direct link send or delivery guarantee here.
 */
void request_power_state_publish(void)
{
    memw();
    if (CLONE_ACTIVE != 0)
        render_notify_worker(4);
}

/* Native entry: 0x42035e04. */
/* Original function-byte SHA-256:
 * 63bcb5636daa9da234b9b065c990dbde67485f00cdaee8b7b250c936a241f4a3. */
/* Request txwd remote-wakeup processing with index0/mask 0x08 (bit 3)/eSetBits1. Require
 * initial task handle, query ISR context, reload handle, then use task/ISR API.
 * ISR path starts woken0 and requests a switch only if it becomes nonzero.
 * No clone-active test or MEMW occurs here. Called for host opcode0x43; worker
 * later checks suspend/wakeup conditions. Ignore status; no immediate USB action.
 */
void request_remote_wakeup(void)
{
    render_notify_worker(8);
}

/* Native entry: 0x42035e4c. */
/* Original function-byte SHA-256:
 * 56905e283de3c2c9b8996d7325ef59747d25a5f070dab7ab230bfef7610e37a7. */
/*
 * Apply four signed16 host feedback deltas from bytes16..23; NULL does nothing.
 * No length argument: caller must provide those bytes (link dispatcher admits
 * opcode0x36 only after copying>=26 bytes). Take optional rewrite mutex indefinitely
 * (0xffffffff ticks), ignoring status. If primary binding is disabled, skip payload/clock
 * access but still give a fresh mutex and service_after_change(0).
 *
 * Enabled path reads pan HIGH, wheel HIGH, Y HIGH, X HIGH, pan LOW, Y LOW,
 * X LOW, wheel LOW as separate BYTE accesses in that native order. Assemble
 * signed16 values and accumulate into primary state. Read clock once, then
 * MEMW/store extension-event LOW WORD, MEMW/store HIGH WORD, MEMW/reload LOW,
 * MEMW/reload HIGH and pass the RELOADED pair to refresh_activity_time. Cache
 * its byte result, give a freshly sampled mutex, then service_after_change.
 * No trailing timestamp writes, payload prefix interpretation, bounds repair,
 * timed-motion admission or physical report-send guarantee is supplied.
 */
void input_apply_host_motion_feedback(const HostMotionFeedback *feedback)
{
    if (feedback == NULL)
        return;
    RtosQueue *mutex = REWRITE_MUTEX;
    if (mutex != NULL)
        (void)xQueueSemaphoreTake(mutex,0xffffffffU);
    unsigned int changed = 0;
    if (FIXED_INPUTS[0].enabled != 0) {
        const volatile HostMotionFeedback *input = feedback;
        unsigned int pan_high = input->pan_le[1];
        unsigned int wheel_high = input->wheel_le[1];
        unsigned int y_high = input->y_le[1];
        unsigned int x_high = input->x_le[1];
        unsigned int pan_low = input->pan_le[0];
        unsigned int y_low = input->y_le[0];
        unsigned int x_low = input->x_le[0];
        unsigned int wheel_low = input->wheel_le[0];
        short x = (short)(x_low | (x_high << 8));
        short y = (short)(y_low | (y_high << 8));
        short wheel = (short)(wheel_low | (wheel_high << 8));
        short pan = (short)(pan_low | (pan_high << 8));
        input_accumulate_motion((InputStateView *)&FIXED_INPUTS[0].state,
            x,y,wheel,pan);
        unsigned long long now = (unsigned long long)esp_timer_get_time();
        memw();
        FIXED_INPUTS[0].extension_event_time.low = (unsigned int)now;
        memw();
        FIXED_INPUTS[0].extension_event_time.high = (unsigned int)(now >> 32);
        memw();
        unsigned int low = FIXED_INPUTS[0].extension_event_time.low;
        memw();
        unsigned int high = FIXED_INPUTS[0].extension_event_time.high;
        changed = primary_input_refresh_activity_time(((unsigned long long)high << 32) | low);
    }
    mutex = REWRITE_MUTEX;
    if (mutex != NULL)
        (void)xQueueGenericSend(mutex,NULL,0,0);
    input_service_after_change(changed);
}

/* Native entry: 0x42035ef4. */
/* Original function-byte SHA-256:
 * a0ca65b0795ad0e2f03afeb95f6557f9f0789ae8e9d278ffc34e6423c98a817d. */
/* Advance raw render-token BYTE modulo256, replacing wrapped0 with1. Read
 * old token BEFORE MEMW/clearing render-state BYTE; publish the new nonzero
 * token, then MEMW/clear last host-session BYTE and notify configuration change.
 * This is the link-loss/session safety reset; it leaves reported metrics/drop
 * counters and acknowledgement BYTE intact. No lock, timestamp or direct send.
 */
void motion_reset_host_session(void)
{
    unsigned char next = (unsigned char)(MOTION_RENDER_TOKEN + 1U);
    memw();
    MOTION_RENDER_STATE = 0;
    MOTION_RENDER_TOKEN = next != 0 ? next : 1;
    memw();
    REPORTED_HOST_SESSION = 0;
    motion_configuration_changed();
}
