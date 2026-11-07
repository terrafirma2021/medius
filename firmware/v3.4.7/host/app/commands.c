/* Medius v3.4.7 host — app/commands.c.
 * Recovered C and native assembly, grouped for source navigation.
 * Original entry addresses, firmware-byte hashes and function comments follow.
 */

#include "../include/types.h"

/* Native entry: 0x4202858c. */
/* Original function-byte SHA-256:
 * c40c0f69ae147b7a819a6b1e59b7c5275c0f2f9b48411351a1e7ea68cb1d7916. */
/* Run the halt_tick software-timer retry scan over all six fixed HID slots.
 * No argument/result. Publish callback-busy=1, then fence/test restart,
 * configuration-switch, precapture, forwarding-inhibit and global HID-pause
 * gates in that short-circuit order. A blocked scan only clears busy on exit.
 * Otherwise sample time once. Each active slot caches ordered ACK BEFORE
 * testing halted/special-valid/retry. A halted valid special report enqueues
 * on nonzero retry or modulo32 age>=100000 us, using that cached ACK.
 *
 * Reread halted/paused after the special callback. A nonzero needs_rearm on
 * a live class/connected port is eligible when its signed64 retry deadline
 * is zero or <=now. Read deadline LOW then HIGH. Fence/sample period BEFORE
 * writing now+250000 HIGH then LOW. Period<2 calls rearm; every negative result,
 * including -6, clears armed and leaves needs_rearm. Period>=2 clears armed;
 * that path and successful rearm clear needs_rearm. Missing/disconnected or
 * not-yet-due states retain their flags and deadline. No local lock is taken.
 *
 * Native aggregation retains raw bytes: remember the LAST nonzero retry
 * sample and the last eligible slot's retry-or-active sample. Only when the
 * former !=1, latter !=0 and global retry is nonzero, clear global retry and
 * log. Successful local rearm still contributes its cached retry byte, so a
 * normal byte1 delays the all-polling log until a later scan. Do not normalize
 * arbitrary byte values or reinterpret this as a live post-scan flag search.
 * Clear callback-busy on every local return. The 20 ms timer shares esp_timer
 * dispatch; scheduling, other callbacks and interrupts can delay it. Backoff
 * values do not guarantee a physical USB or scheduler deadline. */
void medius_halt_timer_cb(void)
{
    memw(); MEDIUS_HID_SHARED_BUSY_FLAGS[0] = 1;
    memw(); if (MEDIUS_HOST_RESTART_GATE != 0) goto done;
    memw(); if (MEDIUS_HOST_CONFIGURATION_SWITCH_GATE != 0) goto done;
    memw(); if (MEDIUS_HOST_PRECAPTURE_STATE != 0) goto done;
    memw(); if (MEDIUS_HOST_FORWARDING_INHIBIT != 0) goto done;
    memw(); if (MEDIUS_HOST_HID_PAUSED != 0) goto done;

    unsigned long long now = (unsigned long long)esp_timer_get_time();
    unsigned int now_low = (unsigned int)now;
    unsigned int now_high = (unsigned int)(now >> 32);
    unsigned char last_retry_sample = 0, last_poll_sample = 0;
    for (unsigned int slot = 0; slot < 6; ++slot) {
        volatile MediusHidEndpointState *state = &MEDIUS_HOST_HID_ENDPOINTS[slot];
        memw(); unsigned char active = state->active;
        if (active == 0) continue;
        memw(); unsigned char acknowledgement = MEDIUS_HOST_ORDERED_LAST_ACK;
        memw(); unsigned char halted = state->halted;
        if (halted != 0) {
            memw(); unsigned char valid = state->special_valid;
            if (valid != 0) {
                memw(); unsigned char retry = state->special_retry;
                if (retry != 0 || now_low - state->last_special_us > 99999U)
                    medius_hid_special_enqueue((MediusHidEndpointState *)state,0,acknowledgement);
            }
        }
        memw(); if (state->halted != 0) continue;
        memw(); if (state->paused != 0) continue;
        memw(); unsigned char retry = state->needs_rearm;
        last_poll_sample = retry;
        if (retry == 0) { last_poll_sample = active; continue; }
        last_retry_sample = retry;
        MediusHostHidClass *hid = state->interface_handle;
        if (hid == NULL) continue;
        MediusHostHubPortPrefix *port = ((volatile MediusHostHidClass *)hid)->port;
        if (port == NULL || ((volatile MediusHostHubPortPrefix *)port)->connected == 0) continue;
        unsigned int deadline_low = state->rearm_after_us_low;
        unsigned int deadline_high = state->rearm_after_us_high;
        if ((deadline_low | deadline_high) != 0 &&
            ((int)now_high < (int)deadline_high ||
             (now_high == deadline_high && now_low < deadline_low))) continue;
        memw(); unsigned int period = state->poll_period;
        unsigned int next_low = now_low + 250000U;
        state->rearm_after_us_high = now_high + (next_low < 250000U);
        state->rearm_after_us_low = next_low;
        if (period < 2) {
            if (medius_hid_rearm_with_credit_gate((MediusHidEndpointState *)state) < 0) {
                memw(); state->armed = 0;
                continue;
            }
        } else { memw(); state->armed = 0; }
        memw(); state->needs_rearm = 0;
    }
    if (last_retry_sample != 1 && last_poll_sample != 0) {
        memw();
        if (MEDIUS_HID_RETRY_PENDING != 0) {
            memw(); MEDIUS_HID_RETRY_PENDING = 0;
            medius_host_log_formatted("every stream is polling again");
        }
    }
done:
    memw(); MEDIUS_HID_SHARED_BUSY_FLAGS[0] = 0;
}

