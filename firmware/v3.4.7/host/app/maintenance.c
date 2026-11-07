/* Medius v3.4.7 host — app/maintenance.c.
 * Recovered maintenance policy; native identities follow each function.
 */

#include "../include/types.h"

/* Native entry: 0x4202e370. */
/* Original function-byte SHA-256:
 * 444aef2a0a00971ed5fb767d903b3842d56f4501b792af94a1e4f007751459e9. */
/* One host maintenance pass, called after app_main's1000-tick delay.
 * No argument/result; independent paths run in native order, so earlier callees
 * may affect later admission. No coherent shared-state snapshot or mutex.
 * Fenced deferred recovery plus nonNULL configuration queue and fenced zero
 * forwarding/restart/switch/precapture gates logs then schedules force0, without
 * rechecking after the log. Clone-active with fenced capture-running0 and the
 * same queue/gates clears clone-active BEFORE logging. After the log, fenced
 * capture-pending0 and unfenced capture-ready!=0 schedules force1; otherwise
 * fence/set capture-pending,restart,recovery-active1, cache current selector and
 * CURRENT queue BEFORE fenced requested-selector publication, then give it.
 * A later fenced restart0 invokes idle vendor-stream service.
 *
 * Switch-active: sample time BEFORE fenced timestamp read; signed microseconds
 * /1000 supplies now_ms. Unsigned32 elapsed>6000 clears fenced switch,requested
 * selector and precapture-complete, sends12hex with empty payload, then logs.
 * Precapture-active similarly samples time before timestamp; elapsed>3000
 * fences/reloads phase then fences/reads requested capture index. Cached phase1
 * logs fallback, fences phase2/selector0, samples NEW time, caches queue BEFORE
 * fenced timestamp publication and gives if nonNULL. Any other cached phase
 * logs abandonment, fences phase0/selector0/complete0, then sends empty12hex.
 * Log callbacks do not cause a phase-decision recheck.
 *
 * Fence/sample enumeration-start32; nonzero samples signed milliseconds.
 * Unsigned elapsed>7999 and cached SIGNED restart-count<3 then fence/recheck
 * start nonzero and restart/switch/precapture zero. Store cached count+1 modulo32,
 * fence/store earlier now_ms BEFORE log. Block frame updates,deinitialize bus0,
 * delay50 scheduler ticks,initialize bus0 at60080000/same event callback,resume
 * frame updates; statuses ignored. Negative corrupted restart counts pass.
 * No restart gate publication, rollback, physical deadline or object-lifetime
 * guarantee is supplied by this pass. Timeout sends report fallback policy. */
void medius_host_recovery_service(void)
{
    memw();
    if (MEDIUS_HOST_RECOVERY_DEFERRED != 0 && MEDIUS_HOST_CONFIGURATION_QUEUE != NULL) {
        memw(); if (MEDIUS_HOST_FORWARDING_INHIBIT != 0) goto capture_recovery;
        memw(); if (MEDIUS_HOST_RESTART_GATE != 0) goto capture_recovery;
        memw(); if (MEDIUS_HOST_CONFIGURATION_SWITCH_GATE != 0) goto capture_recovery;
        memw(); if (MEDIUS_HOST_PRECAPTURE_STATE != 0) goto capture_recovery;
        medius_host_log_formatted("enumerating the device again, as a bus reset left it unconfigured");
        medius_host_schedule_reenumeration(0);
    }
capture_recovery:
    memw(); if (MEDIUS_HOST_CLONE_ACTIVE == 0) goto vendor_service;
    memw(); if (MEDIUS_HOST_CAPTURE_RUNNING != 0) goto vendor_service;
    if (MEDIUS_HOST_CONFIGURATION_QUEUE == NULL) goto vendor_service;
    memw(); if (MEDIUS_HOST_FORWARDING_INHIBIT != 0) goto vendor_service;
    memw(); if (MEDIUS_HOST_RESTART_GATE != 0) goto vendor_service;
    memw(); if (MEDIUS_HOST_CONFIGURATION_SWITCH_GATE != 0) goto vendor_service;
    memw(); if (MEDIUS_HOST_PRECAPTURE_STATE != 0) goto vendor_service;
    memw(); MEDIUS_HOST_CLONE_ACTIVE = 0;
    medius_host_log_formatted("the device did not come back from a capture probe; enumerating it again");
    memw();
    if (MEDIUS_HOST_CAPTURE_PENDING == 0 && MEDIUS_HOST_CAPTURE_READY != 0) {
        medius_host_schedule_reenumeration(1);
    } else {
        memw(); MEDIUS_HOST_CAPTURE_PENDING = 1;
        memw(); MEDIUS_HOST_RESTART_GATE = 1;
        memw(); MEDIUS_HOST_RECOVERY_ACTIVE = 1;
        unsigned char selector = MEDIUS_HOST_CURRENT_CONFIGURATION;
        RtosQueue *queue = MEDIUS_HOST_CONFIGURATION_QUEUE;
        memw(); MEDIUS_HOST_REQUESTED_CONFIGURATION = selector;
        xQueueGenericSend(queue,NULL,0,0);
    }
vendor_service:
    memw(); if (MEDIUS_HOST_RESTART_GATE == 0) medius_vendor_service_idle_streams();
    memw();
    if (MEDIUS_HOST_CONFIGURATION_SWITCH_GATE != 0) {
        long long now_us = esp_timer_get_time();
        memw(); unsigned int started_ms = MEDIUS_HOST_RESTART_REQUESTED_MS;
        unsigned int now_ms = (unsigned int)(now_us / 1000LL);
        if (now_ms - started_ms > 6000U) {
            memw(); MEDIUS_HOST_CONFIGURATION_SWITCH_GATE = 0;
            memw(); MEDIUS_HOST_REQUESTED_CONFIGURATION = 0;
            memw(); MEDIUS_HOST_PRECAPTURE_COMPLETE = 0;
            link_send_wait100(0x12,0,NULL,0);
            medius_host_log_formatted("configuration switch did not land in %ums; back to the first configuration",6000);
        }
    }
    memw();
    if (MEDIUS_HOST_PRECAPTURE_STATE != 0) {
        long long now_us = esp_timer_get_time();
        memw(); unsigned int started_ms = MEDIUS_HOST_PRECAPTURE->timestamp_ms;
        unsigned int now_ms = (unsigned int)(now_us / 1000LL);
        if (now_ms - started_ms > 3000U) {
            memw(); unsigned char phase = MEDIUS_HOST_PRECAPTURE_STATE;
            memw(); unsigned char index = MEDIUS_HOST_PRECAPTURE->requested;
            if (phase == 1) {
                medius_host_log_formatted("pre-capture of configuration %u did not land in %ums; %s",index,3000,"back to the first");
                memw(); MEDIUS_HOST_PRECAPTURE_STATE = 2;
                memw(); MEDIUS_HOST_REQUESTED_CONFIGURATION = 0;
                unsigned int restarted_ms = (unsigned int)(esp_timer_get_time() / 1000LL);
                RtosQueue *queue = MEDIUS_HOST_CONFIGURATION_QUEUE;
                memw(); MEDIUS_HOST_PRECAPTURE->timestamp_ms = restarted_ms;
                if (queue != NULL) xQueueGenericSend(queue,NULL,0,0);
            } else {
                medius_host_log_formatted("pre-capture of configuration %u did not land in %ums; %s",index,3000,"abandoned");
                memw(); MEDIUS_HOST_PRECAPTURE_STATE = 0;
                memw(); MEDIUS_HOST_REQUESTED_CONFIGURATION = 0;
                memw(); MEDIUS_HOST_PRECAPTURE_COMPLETE = 0;
                link_send_wait100(0x12,0,NULL,0);
            }
        }
    }
    memw(); unsigned int started_ms = MEDIUS_HOST_ENUMERATION_STARTED_MS;
    if (started_ms == 0) return;
    unsigned int now_ms = (unsigned int)(esp_timer_get_time() / 1000LL);
    if (now_ms - started_ms <= 7999U) return;
    unsigned int attempts = MEDIUS_HOST_ENUMERATION_RESTART_COUNT;
    if ((int)attempts >= 3) return;
    memw(); if (MEDIUS_HOST_ENUMERATION_STARTED_MS == 0) return;
    memw(); if (MEDIUS_HOST_RESTART_GATE != 0) return;
    memw(); if (MEDIUS_HOST_CONFIGURATION_SWITCH_GATE != 0) return;
    memw(); if (MEDIUS_HOST_PRECAPTURE_STATE != 0) return;
    unsigned int next_attempt = attempts + 1U;
    MEDIUS_HOST_ENUMERATION_RESTART_COUNT = next_attempt;
    memw(); MEDIUS_HOST_ENUMERATION_STARTED_MS = now_ms;
    medius_host_log_formatted("enumerate stuck >%dms -> host-stack restart %d/%d",8000,next_attempt,3);
    medius_host_block_frame_interval_updates();
    usbh_deinitialize(0);
    vTaskDelay(50);
    usbh_initialize(0,0x60080000U,medius_usb_host_event_callback);
    medius_host_resume_frame_interval_updates();
}
