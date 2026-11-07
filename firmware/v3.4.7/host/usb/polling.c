/* Medius v3.4.7 host — usb/polling.c.
 * Recovered HID interval/phase policy; native identities follow each function.
 */

#include "../include/types.h"

/* Source reconstruction utilities: both native4202e07c credit calculations
 * share this body. No additional native entry. Preserve max-packet/length
 * snapshots and the second period read only on the slow-period branch. */
static void medius_hid_update_poll_credit(volatile MediusHidEndpointState *state)
{
    unsigned int max_packet = state->max_packet;
    unsigned int packets = 1;
    if (max_packet == 0) {
        memw(); unsigned int period = state->poll_period;
        if (period < 2) { state->credit_limit = 1; return; }
    } else {
        unsigned int length = state->transfer_length;
        memw(); unsigned int period = state->poll_period;
        packets = ((length + max_packet - 1U) / max_packet) & 65535U;
        if (period < 2) {
            state->credit_limit = (unsigned char)((packets > 1U) + 1U);
            return;
        }
    }
    memw(); unsigned int period = state->poll_period;
    state->credit_limit = (unsigned char)((packets >= period) + 1U);
}

/* Native entry: 0x4202e07c. */
/* Original function-byte SHA-256:
 * 9a4564d5a176f797ed915425a4cb1702af58f6eabcbf480505fbc681e6053e77. */
/* Set low8 poll override and update exactly six HID endpoints.
 * Fence/sample old override, fence/store new override, THEN fence/set policy-
 * updating1. Each active slot fences/tests current override; nonzero fences/
 * rereads it, otherwise uses descriptor interval. These are separate samples.
 * Round byte interval down to a power of two; zero/one choose1. Fence/recheck
 * active, needs-rearm0 and period inequality. Unchanged/ineligible entries keep
 * their phase, credits and arm state. Changed entries fence/set phaseFFFF.
 * New period>=2 first enables SOF interrupts, then fence/stores period; period1
 * only fences/stores1. Both paths recalculate credit using the source utility.
 * It caches max-packet, optional length and fenced period. A slow first period
 * reads period AGAIN; credit=1+(packet_count>=fresh_period). Fast/nonzero packet
 * uses1+(packet_count>1); max-packet0/fast gives1. No lock or coherent snapshot.
 *
 * Only the chosen period1 path then fences/tests active,needs-rearm0,armed0,
 * global-pause0 and rearms. Negative results except-6 fence/set needs-rearm1
 * and global retry1. No handle/descriptor/halt admission is added here.
 * After six slots fence/clear policy-updating, log the ORIGINAL low8 input iff
 * it differs from the initial override, regardless of later global mutations.
 * No SOF disable, cancellation, timeout, rollback or atomic update guarantee. */
void medius_hid_set_poll_override(unsigned char override_ms)
{
    memw(); unsigned char previous = MEDIUS_HID_POLL_OVERRIDE;
    memw(); MEDIUS_HID_POLL_OVERRIDE = override_ms;
    memw(); MEDIUS_HID_POLL_POLICY_UPDATING = 1;
    for (unsigned int slot = 0; slot < 6; ++slot) {
        volatile MediusHidEndpointState *state = &MEDIUS_HOST_HID_ENDPOINTS[slot];
        memw(); if (state->active == 0) continue;
        unsigned int interval;
        memw();
        if (MEDIUS_HID_POLL_OVERRIDE == 0) interval = state->descriptor_interval;
        else { memw(); interval = MEDIUS_HID_POLL_OVERRIDE; }
        unsigned int period = 1;
        while (period * 2U <= interval) period *= 2U;
        memw(); if (state->active == 0) continue;
        memw(); if (state->needs_rearm != 0) continue;
        memw(); if (state->poll_period == period) continue;
        memw(); state->poll_phase = 0xffff;
        if (period >= 2) {
            medius_host_set_sof_interrupt(1);
            memw(); state->poll_period = (unsigned short)period;
            medius_hid_update_poll_credit(state);
        } else {
            memw(); state->poll_period = 1;
            medius_hid_update_poll_credit(state);
            memw(); if (state->active == 0) continue;
            memw(); if (state->needs_rearm != 0) continue;
            memw(); if (state->armed != 0) continue;
            memw(); if (MEDIUS_HOST_HID_PAUSED != 0) continue;
            int result = medius_hid_rearm_with_credit_gate((MediusHidEndpointState *)state);
            if (result < 0 && result != -6) {
                memw(); state->needs_rearm = 1;
                memw(); MEDIUS_HID_RETRY_PENDING = 1;
            }
        }
    }
    memw(); MEDIUS_HID_POLL_POLICY_UPDATING = 0;
    if (previous != override_ms) medius_host_log_formatted("poll force=%ums",(unsigned int)override_ms);
}

/* Native entry: 0x4202d86c. */
/* Original function-byte SHA-256:
 * 44449ecc3aca9556171c92ff4efd256c3a0b7dcbd3360381d27b74869272b369. */
/* Apply poll phases from low16 payload length: ignore first7 bytes, then
 * process complete8-byte records. Each record caches endpoint BEFORE the six-
 * slot fenced active scan. The FIRST active endpoint match consumes the record,
 * even if its fenced period is<2; later duplicate endpoints are not considered.
 * For period>=2, copy unaligned LE remote microseconds32 and sub-us ns16 from
 * record+2/+6, convert remote time, then obtain frame base/period/frame. Either
 * zero status skips only this record. There is no sequence/header validation.
 *
 * Read phase threshold, subtract100000ns modulo64, then cache max-packet and
 * optional transfer length. Extra packets = ceil(length/max_packet)-1 after
 * native16 quotient truncation; zero max-packet chooses0, zero length with
 * nonzero packet chooses-1. Add extra_packets*frame_period to that lead.
 * delta = local_us*1000 + raw sub-us ns - lead - frame_base, all modulo64.
 * Nonnegative delta uses signed division by frame period. Negative delta uses
 * -((period-1-delta)/period) with native modulo64 numerator; for positive periods
 * this is floor division. Divisor validity is delegated, not checked locally.
 * Fence/store low16((frame+advance)&(CACHED poll_period-1)). No active/period
 * recheck after callees, no phase normalization of sub-us input, and no lock,
 * rearm, cancellation or physical timestamp/scheduling guarantee. */
void medius_hid_apply_poll_phases(const unsigned char *payload,unsigned int payload_length)
{
    unsigned int length = (unsigned short)payload_length;
    for (unsigned int offset = 7; offset + 7U < length; offset += 8) {
        const MediusHidPollPhaseRecord *record = (const void *)(payload + offset);
        unsigned char endpoint = record->endpoint;
        for (unsigned int slot = 0; slot < 6; ++slot) {
            volatile MediusHidEndpointState *state = &MEDIUS_HOST_HID_ENDPOINTS[slot];
            memw(); if (state->active == 0 || state->endpoint != endpoint) continue;
            memw(); unsigned int poll_period = state->poll_period;
            if (poll_period < 2) break;
            unsigned int remote_us;
            unsigned short sub_us_ns;
            memcpy(&remote_us,record->remote_us_le,4);
            memcpy(&sub_us_ns,record->sub_us_ns_le,2);
            long long local_us,frame_base_ns,frame_period_ns;
            unsigned short frame;
            if (medius_link_remote_to_local_us(remote_us,&local_us) == 0) break;
            if (medius_host_get_frame_timing(&frame_base_ns,&frame_period_ns,&frame) == 0) break;
            unsigned long long lead = (unsigned long long)medius_host_frame_phase_threshold_ns() - 100000ULL;
            unsigned int max_packet = state->max_packet;
            int extra_packets = 0;
            if (max_packet != 0) {
                unsigned int packets = ((state->transfer_length + max_packet - 1U) / max_packet) & 65535U;
                extra_packets = (int)(packets - 1U);
            }
            lead += (unsigned long long)frame_period_ns * (unsigned long long)(long long)extra_packets;
            unsigned long long delta = (unsigned long long)local_us * 1000ULL + sub_us_ns - lead - (unsigned long long)frame_base_ns;
            unsigned int advance;
            if ((long long)delta < 0) {
                unsigned long long numerator = (unsigned long long)frame_period_ns - 1ULL - delta;
                advance = 0U - (unsigned int)((long long)numerator / frame_period_ns);
            } else advance = (unsigned int)((long long)delta / frame_period_ns);
            memw(); state->poll_phase = (unsigned short)((frame + advance) & (poll_period - 1U));
            break;
        }
    }
}
