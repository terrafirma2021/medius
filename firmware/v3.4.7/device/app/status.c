/* Medius v3.4.7 device — status getters and host motion telemetry. */
#include "../include/types.h"

/* Native entry: 0x420394b0. */
/* Original function-byte SHA-256:
 * 6da32ee80ed357eb46d843da1d45cc8d5885e5eea7de480b7d60a61b9f086283. */
/* Return the RAW32 accepted-merge counter after MEMW. Its writer increments
 * when report merge accepts and stored_kind/incoming_kind have equal boolean state.
 * This is an event counter; no saturation, reset, lock or interface enumeration.
 */
unsigned int report_merge_accept_count(void)
{
    memw();
    return REPORT_MERGE_COUNT;
}

/* Native entry: 0x420394c0. */
/* Original function-byte SHA-256:
 * b338a612ffdbf025974dcc05fe8e81cb33329a380e0911ae492324c79a8240c8. */
/* Return RAW32 primary fallback/report-queue drops after MEMW. Includes
 * writer-side queue-admission losses counted at this address; no sum, reset,
 * saturation, lock or hardware-delivery check. The query encoder may clamp it.
 */
unsigned int report_primary_fallback_drop_count(void)
{
    memw();
    return REPORT_PRIMARY_FALLBACK_DROPS;
}

/* Native entry: 0x420394d0. */
/* Original function-byte SHA-256:
 * 64991524f8ce982911180c3c052ea9168d5c326dd9c48fc97946804788677be0. */
/* Return a modulo32 forwarding-drop sum: fenced local OUT/secondary fallback
 * WORD, then fenced host-reported OTHER-opcode UART RX-drop WORD, then fenced
 * pending-input drop HALFWORD. Zero-extend the last value. Reads are separate
 * snapshots; the host value remains stale until its next opcode0x37 update.
 * Counted-opcode host RX drops and primary fallback drops are not in this sum.
 * No counter clearing, saturation or all-firmware loss accounting is implied.
 */
unsigned int forwarding_drop_count(void)
{
    memw();
    unsigned int local = DEVICE_OUT_DROPS;
    memw();
    unsigned int host = REPORTED_HOST_OTHER_RX_DROPS;
    unsigned int total = local + host;
    memw();
    unsigned int pending = PENDING_INPUT_DROPS;
    return total + pending;
}

/* Native entry: 0x420394f8. */
/* Original function-byte SHA-256:
 * 73a0a5f46e006aad9f92e292712608c9e5e3ca624f9bc14ef21f6a8d0ed81ed7. */
/* Return RAW32 report-queue depth high-water after MEMW. The producer raises
 * it when accepted queue depth exceeds the saved maximum. This getter neither
 * samples current queue depth nor resets/clamps the recorded maximum.
 */
unsigned int report_queue_depth_high_water(void)
{
    memw();
    return REPORT_DEPTH_HIGH_WATER;
}

/* Native entry: 0x42039508. */
/* Original function-byte SHA-256:
 * 9d1ea50d43504e602377045fc14123fd2895476f835b4bb7491e1d0fc6626bd7. */
/* Return RAW32 busy-endpoint watchdog observations after MEMW. The txwd
 * writer increments in overdue IN-work paths when its busy probe and endpoint
 * enable test remain set, subject to each path's markers. Observations can
 * repeat for an endpoint; no distinct-packet count, physical stall proof,
 * reset, saturation or lock is supplied by this getter.
 */
unsigned int report_busy_watchdog_count(void)
{
    memw();
    return REPORT_BUSY_WATCHDOG_OBSERVATIONS;
}

/* Native entry: 0x42039518. */
/* Original function-byte SHA-256:
 * a99acbd6d5fcc040b6d5ec217af8868655b0476c64c3be76e65a615e39a0cd8c. */
/* Return RAW32 remote-wakeup/resume success-path count after MEMW. Writers
 * increment after the wakeup helper returns0 before invoking resume handling.
 * This getter provides no physical-bus acknowledgement, reset, saturation
 * or lock; it returns the complete WORD unchanged.
 */
unsigned int report_wakeup_resume_count(void)
{
    memw();
    return REPORT_WAKE_RESUMES;
}

/* Native entry: 0x42039690. */
/* Original function-byte SHA-256:
 * dfcd850911f42e83b59f96efc668a8114a7b203496c6313279298d5704870532. */
/* Return1 when the signed primary interface index is nonnegative, otherwise0.
 * Native SRAI31 followed by+1 tests its sign, including any negative index.
 * Read one WORD without MEMW; do not test enabled, descriptor, clone state,
 * USB configuration or interface range. No lock or state change.
 */
int primary_input_interface_is_selected(void)
{
    int interface = FIXED_INPUTS[0].interface;
    return (interface >> 31) + 1;
}

/* Native entry: 0x42035f28. */
/* Original function-byte SHA-256:
 * a645c0f35ee7bce38cea8010be18ea59248d8d811edcdb957976a458530595d0. */
/*
 * Receive host opcode0x37 motion/status telemetry. Length narrows16; short
 * input<14 is ignored. Copy exactly14 bytes into the local packet, ignoring
 * excess input; payload must be readable and is not retained or NULL-checked.
 * Wire fields are raw flags BYTE, session BYTE, little-endian interval metric
 * WORD, counted-opcode UART RX-drop WORD and other-opcode RX-drop WORD.
 *
 * Publication order is MEMW/flags BYTE, MEMW/metric WORD, MEMW/counted WORD,
 * MEMW/other WORD. Then read the current local render token BYTE BEFORE
 * MEMW/publishing received session BYTE. A mismatch notifies configuration
 * change, even for a repeated received session; equality does not notify.
 * Fields are separate snapshots, with no aggregate lock, normalization,
 * session rejection, retry, lifetime extension or status response.
 */
void motion_receive_host_status(const void *payload,unsigned short length)
{
    if (length < 14U)
        return;
    HostMotionStatusPacket packet;
    memcpy(&packet,payload,14U);
    unsigned int metric = packet.metric_low | ((unsigned int)packet.metric_high << 16);
    unsigned int counted = packet.counted_drops_low | ((unsigned int)packet.counted_drops_high << 16);
    unsigned int other = packet.other_drops_low | ((unsigned int)packet.other_drops_high << 16);
    memw();
    MOTION_RENDER_STATE = packet.flags;
    memw();
    REPORTED_HOST_INTERVAL_METRIC = metric;
    memw();
    REPORTED_HOST_COUNTED_RX_DROPS = counted;
    memw();
    REPORTED_HOST_OTHER_RX_DROPS = other;
    unsigned int expected_session = MOTION_RENDER_TOKEN;
    memw();
    REPORTED_HOST_SESSION = packet.session;
    if (expected_session != packet.session)
        motion_configuration_changed();
}

/* Native entry: 0x420389d8. */
/* Original function-byte SHA-256:
 * 8f3230e9575bdd605b4b34b5b6d054d7666cc82fc199c4d6a82b5ec87498c4bc. */
/*
 * MEMW then read the last reported host counted-RX-drop WORD once. Status
 * packets update this cached remote value; this does not query the host or
 * inspect local RX queues. Return it unchanged, without clearing, freshness
 * validation, lock or a coherent snapshot with other control-response fields.
 */
unsigned int status_get_host_counted_rx_drops(void)
{
    memw();
    return REPORTED_HOST_COUNTED_RX_DROPS;
}
