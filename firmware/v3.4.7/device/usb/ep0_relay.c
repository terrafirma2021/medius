/* Medius v3.4.7 device — EP0 request relay, rules and HID cache. */
#include "../include/types.h"

/* Readability reconstruction utilities; these are not additional native entries.
 * Keep volatile table reads separate: callbacks can replace configuration and
 * the native matcher rereads masks for scoring after comparing the prefix. */
static __inline__ __attribute__((always_inline)) unsigned int
ep0_select_rewrite(const unsigned char *sample, unsigned int sample_length,
    unsigned int direction, unsigned int count)
{
    int best_score = -1;
    unsigned int selected = 0xffffffffU;
    for (unsigned int index = 0; index != count; ++index) {
        volatile RewriteRule *rule = &REWRITE_RULES[index];
        unsigned int traffic_class = rule->traffic_class;
        unsigned int endpoint = rule->endpoint;
        unsigned int rule_direction = rule->direction;
        unsigned int prefix_length = rule->prefix_length;
        unsigned int specificity;
        if (traffic_class == 8 && endpoint == 0)
            specificity = 2;
        else if (traffic_class == 8 && endpoint == 65535)
            specificity = 1;
        else if (traffic_class == 255)
            specificity = 0; /* Wildcard class ignores the endpoint. */
        else
            continue;
        if (rule_direction != 0 && rule_direction != direction)
            continue;
        if (prefix_length > sample_length)
            continue;
        unsigned int offset;
        for (offset = 0; offset != prefix_length; ++offset) {
            unsigned int mask = rule->mask[offset];
            unsigned int observed = sample[offset];
            unsigned int expected = rule->prefix[offset];
            if (expected != (observed & mask))
                break;
        }
        if (offset != prefix_length)
            continue;
        unsigned int mask_bits = 0;
        for (offset = 0; offset != prefix_length; ++offset)
            mask_bits += __popcountsi2(rule->mask[offset]);
        int score = (int)(specificity * 100000U + mask_bits * 10U +
                          (rule_direction != 0));
        if (score > best_score) {
            selected = index;
            best_score = score; /* Equal scores retain the first rule. */
        }
    }
    return selected;
}

static __inline__ __attribute__((always_inline)) void ep0_release_rewrite_mutex(void)
{
    RtosQueue *mutex = REWRITE_MUTEX;
    if (mutex != NULL)
        xQueueGenericSend(mutex, NULL, 0, 0);
}

static __inline__ __attribute__((always_inline)) void
ep0_record_elapsed(unsigned long long elapsed)
{
    memw();
    MEDIUS_EP0_RELAY_STATS->elapsed_low = (unsigned int)elapsed;
    memw();
    MEDIUS_EP0_RELAY_STATS->elapsed_high = (unsigned int)(elapsed >> 32);
}

static __inline__ __attribute__((always_inline)) void ep0_count_completed(void)
{
    memw();
    unsigned int completed = MEDIUS_EP0_RELAY_STATS->completed;
    memw();
    MEDIUS_EP0_RELAY_STATS->completed = completed + 1U;
}

/* Native entry: 0x40393504. */
/* Original function-byte SHA-256:
 * 3470bdb26cdc13541dd3cb8a6a34d76e8b2eb2a821171f3934b77d5d8b2e817b. */
/*
 * Relay one EP0 SETUP transaction to the other chip, or answer a local rule or
 * cached HID GET_PROTOCOL/GET_IDLE request. bus is a native WORD; flag helpers
 * consume its low BYTE. setup_in is borrowed for an immediate 8-byte snapshot.
 * data and length are caller-owned writable pointer/WORD slots; *data must have
 * enough capacity for the received length, which this function does not clamp.
 * Returns 0 for an accepted/local answer, -1 for rejection, cancellation or a
 * failed forwarding transaction. Output length is not cleared on every failure.
 *
 * Pre-request rules see SETUP plus at most 8 OUT bytes. Their best match bypasses
 * the HID cache even when its action does nothing. Actions 2/3 patch OUT data,
 * 4 answers locally, 5 rejects, and 6 clears/consumes the stall. After a forwarded
 * IN answer, matched-request mode searches again using SETUP alone: action 7
 * patches the answer; 8 replaces it within min(wLength,2048,payload_length).
 * Counts/offsets/pool bounds are trusted; rule-hit saturation is not atomic.
 * Only a 172-byte OUT preimage is retained for capture; original wLength remains
 * the advertised capture length, leaving clipping to the capture builder.
 *
 * Unmatched class requests scan the published interface IDs without a recipient
 * check or six-entry bound. A session generation change invalidates all six
 * cached protocol/idle pairs. Cached values are signed HALFWORDs (-1 invalid).
 * Forwarded OUT requests above 2048 bytes reject. wLength<=504 selects link
 * opcode 0x13 and a 700-tick wait; larger requests use 506-byte fragments and
 * 1500 ticks, including IN requests whose outgoing message is just SETUP.
 * Send results are ignored. These waits are RTOS ticks, not measured timings.
 *
 * Generation changes can suppress capture after an otherwise successful reply.
 * Cancellation clears waiting/busy and marks the handler consumed, without
 * publishing elapsed/completed stats. Other completed waits store elapsed LOW
 * then HIGH, then increment completed; early/local/cache paths do not. Received
 * lengths are copied as published, including oversized IN/OUT answers. Keep the
 * native semaphore/generation read order and per-access fences: no whole-request
 * lock, capacity validation or stronger concurrent-state guarantee is added.
 */
int medius_ep0_relay_request(unsigned int bus, const MediusUsbSetupPacket *setup_in,
    unsigned char **data, unsigned int *length)
{
    unsigned char *volatile *data_slot = data;
    volatile unsigned int *length_slot = length;
    memw();
    if (MEDIUS_EP0_REPLY_LIFETIME->quiescing != 0)
        return -1;
    memw();
    unsigned int generation = MEDIUS_EP0_REPLY_LIFETIME->request_generation;
    MediusUsbSetupPacket setup;
    memcpy(&setup, setup_in, 8);
    unsigned int request_type = setup.request_type;
    unsigned int requested_length = setup.length;
    unsigned int direction_out = ((~request_type) >> 7) & 1U;
    unsigned int initial_rule_count = REWRITE_COUNT;
    unsigned char *capture_payload;
    unsigned int capture_length;
    if (direction_out != 0) {
        capture_payload = *data_slot;
        capture_length = requested_length;
    } else {
        capture_payload = NULL;
        capture_length = 0;
    }
    unsigned char capture_flags = 0;
    unsigned int matched_request = 0;
    unsigned int interface_index = 0xffffffffU;

    if (initial_rule_count != 0 || PACKET_TRIGGER_COUNT != 0) {
        unsigned char sample[16];
        memcpy(sample, &setup, 8);
        unsigned int sample_length = 8;
        unsigned int rule_direction = direction_out != 0 ? 2 : 1;
        if (direction_out != 0 && requested_length != 0) {
            unsigned int copied = requested_length < 8 ? requested_length : 8;
            memcpy(sample + 8, *data_slot, copied);
            sample_length += copied;
        }
        RtosQueue *mutex = REWRITE_MUTEX;
        if (mutex != NULL)
            xQueueSemaphoreTake(mutex, 0xffffffffU);
        if (PACKET_TRIGGER_COUNT != 0)
            clip_packet_rules_evaluate(8, 0, rule_direction, sample, sample_length);
        unsigned int count = REWRITE_COUNT;
        unsigned int selected = ep0_select_rewrite(sample, sample_length, rule_direction, count);
        if (selected == 0xffffffffU) {
            ep0_release_rewrite_mutex();
        } else {
            volatile RewriteRule *rule = &REWRITE_RULES[selected];
            unsigned int hits = rule->hits;
            if (hits != 0xffffffffU)
                rule->hits = hits + 1U;
            unsigned int action = rule->action;
            if (action == 4 && direction_out != 0) {
                mutex = REWRITE_MUTEX;
                *length_slot = 0;
                if (mutex != NULL)
                    xQueueGenericSend(mutex, NULL, 0, 0);
                medius_capture_nonzero_control(0, setup.bytes, 1, 0x80,
                    capture_payload, (unsigned short)capture_length);
                return 0;
            }
            unsigned int payload_offset = rule->payload_offset;
            unsigned int payload_length = rule->payload_length;
            const unsigned char *payload = REWRITE_PAYLOAD_POOL + payload_offset;
            if (action == 4) {
                unsigned int copied = requested_length < 2048 ? requested_length : 2048;
                if (payload_length < copied)
                    copied = payload_length;
                memcpy(*data_slot, payload, copied);
                mutex = REWRITE_MUTEX;
                *length_slot = copied;
                if (mutex != NULL)
                    xQueueGenericSend(mutex, NULL, 0, 0);
                capture_payload = *data_slot;
                medius_capture_nonzero_control(0, setup.bytes, 0, 0x80,
                    capture_payload, (unsigned short)copied);
                return 0;
            }
            unsigned int patch_offset = 0;
            unsigned int patch_length = 0;
            if (action == 2 && direction_out != 0) {
                patch_offset = rule->patch_offset;
                if (patch_offset + payload_length <= requested_length)
                    patch_length = payload_length;
            } else if (action == 3 && direction_out != 0) {
                patch_length = requested_length < payload_length ? requested_length : payload_length;
            }
            if (patch_length != 0) {
                unsigned char *original = *data_slot;
                if (memcmp(original + patch_offset, payload, patch_length) != 0) {
                    unsigned int saved = requested_length < 172 ? requested_length : 172;
                    memcpy(MEDIUS_EP0_CAPTURE_PREIMAGE, original, saved);
                    memcpy(*data_slot + patch_offset, payload, patch_length);
                    capture_flags = 0x80;
                    capture_payload = MEDIUS_EP0_CAPTURE_PREIMAGE;
                }
            }
            ep0_release_rewrite_mutex();
            if (action == 5) {
                medius_capture_nonzero_control(0, setup.bytes, (unsigned char)direction_out,
                    0x81, capture_payload, (unsigned short)capture_length);
                return -1;
            }
            if (action == 6) {
                medius_ep0_clear_stall_and_consume((unsigned char)bus);
                medius_capture_nonzero_control(0, setup.bytes, (unsigned char)direction_out,
                    0x82, capture_payload, (unsigned short)capture_length);
                return -1;
            }
            matched_request = 1;
        }
    }

    if (generation != MEDIUS_EP0_CACHE_GENERATION) {
        for (unsigned int index = 0; index != 6; ++index)
            MEDIUS_EP0_HID_CACHE[index].pair = 0xffffffffU;
        MEDIUS_EP0_CACHE_GENERATION = generation;
    }
    if (matched_request == 0 && ((request_type >> 5) & 3U) == 1) {
        unsigned int interface_id = setup.bytes[4];
        int count = USB_INTERFACE_COUNT;
        if (count > 0) {
            for (unsigned int index = 0; index != (unsigned int)count; ++index) {
                if (REPORT_CAPTURE_INTERFACE_IDS[index] != interface_id)
                    continue;
                interface_index = index;
                break;
            }
        }
        if (interface_index != 0xffffffffU && direction_out == 0 && requested_length != 0) {
            short cached;
            if (setup.request == 3)
                cached = MEDIUS_EP0_HID_CACHE[interface_index].protocol;
            else if (setup.request == 2 && setup.bytes[2] == 0)
                cached = MEDIUS_EP0_HID_CACHE[interface_index].idle;
            else
                goto forward_request;
            if (cached >= 0) {
                memw();
                if (DEVICE_OUT_GENERATION == generation) {
                    **data_slot = (unsigned char)cached;
                    memw();
                    unsigned int hits = MEDIUS_EP0_CACHE_HITS;
                    unsigned char *reply = *data_slot;
                    *length_slot = 1;
                    memw();
                    MEDIUS_EP0_CACHE_HITS = hits + 1U;
                    medius_capture_nonzero_control(0, setup.bytes, 0, 0, reply, 1);
                    return 0;
                }
            }
        }
    }

forward_request:
    if (requested_length > 2048 && direction_out != 0)
        return -1;
    memw();
    MEDIUS_EP0_REPLY_CHANNEL->ep0_worker_busy = 1;
    control_wait_idle_50ms();
    memw();
    if (MEDIUS_EP0_REPLY_LIFETIME->quiescing != 0)
        goto early_forward_failure;
    int gate_acquired = control_forward_acquire_generation(generation);
    if (gate_acquired == 0)
        goto early_forward_failure;
    memw();
    unsigned char sequence = MEDIUS_EP0_REPLY_CHANNEL->sequence;
    sequence = (unsigned char)(sequence + 1U);
    memw();
    MEDIUS_EP0_REPLY_CHANNEL->sequence = sequence;
    memcpy(MEDIUS_EP0_REQUEST_BUFFER, &setup, 8);
    unsigned short wire_length = 8;
    if (requested_length != 0 && direction_out != 0) {
        memcpy(MEDIUS_EP0_REQUEST_BUFFER + 8, *data_slot, requested_length);
        wire_length = (unsigned short)(requested_length + 8U);
    }
    memw();
    MEDIUS_EP0_REPLY_STORAGE->status = -1;
    RtosQueue *reply_signal = MEDIUS_EP0_REPLY_CHANNEL->signal;
    if (requested_length > 504) {
        MEDIUS_EP0_REPLY_ASSEMBLY->length = 0;
        MEDIUS_EP0_REPLY_ASSEMBLY->state = 0;
    }
    xQueueSemaphoreTake(reply_signal, 0); /* Drain a stale completion. */
    memw();
    MEDIUS_EP0_REPLY_LIFETIME->cancelled = 0;
    memw();
    MEDIUS_EP0_REPLY_CHANNEL->waiting = 1;
    memw();
    if (DEVICE_OUT_GENERATION != generation) {
        RtosQueue *gate = CONTROL_FORWARD_GATE;
        memw();
        MEDIUS_EP0_REPLY_CHANNEL->waiting = 0;
        if (gate != NULL)
            xQueueGenericSend(gate, NULL, 0, 0);
        goto early_forward_failure;
    }
    unsigned long long started = (unsigned long long)esp_timer_get_time();
    if (requested_length <= 504)
        link_send_wait100(0x13, sequence, MEDIUS_EP0_REQUEST_BUFFER, wire_length);
    else
        control_fragment_emit(MEDIUS_EP0_REQUEST_BUFFER, wire_length, 506,
            medius_ep0_send_request_fragment_boundary, &sequence);
    RtosQueue *gate = CONTROL_FORWARD_GATE;
    if (gate != NULL)
        xQueueGenericSend(gate, NULL, 0, 0);
    unsigned int wait_ticks = requested_length <= 504 ? 700 : 1500;
    int wait_result = xQueueSemaphoreTake(MEDIUS_EP0_REPLY_CHANNEL->signal, wait_ticks);
    unsigned long long finished = (unsigned long long)esp_timer_get_time();
    memw();
    MEDIUS_EP0_REPLY_CHANNEL->waiting = 0;
    memw();
    unsigned int cancelled = MEDIUS_EP0_REPLY_LIFETIME->cancelled;
    unsigned long long elapsed = finished - started;
    if (cancelled != 0) {
        memw();
        MEDIUS_EP0_REPLY_LIFETIME->cancelled = 0;
        medius_ep0_mark_handler_consumed((unsigned char)bus);
        goto early_forward_failure;
    }
    memw();
    unsigned int observed_generation = DEVICE_OUT_GENERATION;
    if (observed_generation != generation) {
        memw();
        MEDIUS_EP0_REPLY_STORAGE->status = -1;
    }
    /* Timeout/FE status use flag 2 after acquiring the gate. Other error statuses
     * use flag 1: native a14 still holds the zero cancellation observation. */
    int failure_marker = 0;
    if (wait_result != 1) {
        medius_ep0_clear_stall_and_consume((unsigned char)bus);
        failure_marker = gate_acquired;
        goto failed_wait;
    }
    memw();
    int status = MEDIUS_EP0_REPLY_STORAGE->status;
    if (status != 0) {
        memw();
        if (((unsigned int)MEDIUS_EP0_REPLY_STORAGE->status & 255U) == 254) {
            medius_ep0_clear_stall_and_consume((unsigned char)bus);
            failure_marker = gate_acquired;
        }
        goto failed_wait;
    }

    if (direction_out != 0) {
        memw();
        unsigned int received = MEDIUS_EP0_REPLY_STORAGE->length;
        if (received == 0) {
            *length_slot = 0;
        } else {
            unsigned char *destination = *data_slot;
            if (destination == capture_payload) {
                unsigned int saved = requested_length < 172 ? requested_length : 172;
                memcpy(MEDIUS_EP0_CAPTURE_PREIMAGE, capture_payload, saved);
                destination = *data_slot;
                capture_payload = MEDIUS_EP0_CAPTURE_PREIMAGE;
            }
            memw();
            unsigned int copied = MEDIUS_EP0_REPLY_STORAGE->length;
            memcpy(destination, MEDIUS_EP0_REPLY_STORAGE->payload, copied);
            memw();
            *length_slot = MEDIUS_EP0_REPLY_STORAGE->length;
            medius_ep0_mark_length_override((unsigned char)bus);
        }
    } else {
        memw();
        unsigned int received = MEDIUS_EP0_REPLY_STORAGE->length;
        if (requested_length < received)
            medius_ep0_mark_length_override((unsigned char)bus);
        memcpy(*data_slot, MEDIUS_EP0_REPLY_STORAGE->payload, received);
        *length_slot = received;
        if (matched_request != 0) {
            RtosQueue *mutex = REWRITE_MUTEX;
            if (mutex != NULL)
                xQueueSemaphoreTake(mutex, 0xffffffffU);
            unsigned int count = REWRITE_COUNT;
            unsigned int selected = ep0_select_rewrite(setup.bytes, 8, 1, count);
            if (selected != 0xffffffffU) {
                volatile RewriteRule *rule = &REWRITE_RULES[selected];
                unsigned int payload_offset = rule->payload_offset;
                const unsigned char *payload = REWRITE_PAYLOAD_POOL + payload_offset;
                unsigned int action = rule->action;
                if (action == 7) {
                    unsigned int patch_offset = rule->patch_offset;
                    unsigned int payload_length = rule->payload_length;
                    unsigned int current_length = *length_slot;
                    if (patch_offset + payload_length <= current_length) {
                        unsigned char *destination = *data_slot + patch_offset;
                        if (memcmp(destination, payload, payload_length) != 0)
                            capture_flags = 0x80;
                        memcpy(destination, payload, payload_length);
                    }
                } else if (action == 8) {
                    unsigned int payload_length = rule->payload_length;
                    unsigned int copied = requested_length < 2048 ? requested_length : 2048;
                    if (payload_length < copied)
                        copied = payload_length;
                    unsigned int current_length = *length_slot;
                    unsigned char *destination = *data_slot;
                    if (copied != current_length || memcmp(destination, payload, copied) != 0)
                        capture_flags = 0x80;
                    memcpy(destination, payload, copied);
                    *length_slot = copied;
                }
            }
            ep0_release_rewrite_mutex();
        }
    }
    memw();
    MEDIUS_EP0_REPLY_CHANNEL->ep0_worker_busy = 0;
    if (interface_index != 0xffffffffU && direction_out == 0) {
        memw();
        unsigned int cache_length = MEDIUS_EP0_REPLY_STORAGE->length;
        if (cache_length == 1) {
            memw();
            if (DEVICE_OUT_GENERATION == generation) {
                if (setup.request == 3 || (setup.request == 2 && setup.bytes[2] == 0)) {
                    ep0_record_elapsed(elapsed);
                    memw();
                    unsigned int completed = MEDIUS_EP0_RELAY_STATS->completed;
                    unsigned int reply_byte = *(const volatile unsigned char *)MEDIUS_EP0_REPLY_STORAGE->payload;
                    memw();
                    MEDIUS_EP0_RELAY_STATS->completed = completed + 1U;
                    if (setup.request == 3)
                        MEDIUS_EP0_HID_CACHE[interface_index].protocol = (short)reply_byte;
                    else
                        MEDIUS_EP0_HID_CACHE[interface_index].idle = (short)reply_byte;
                    if (observed_generation != generation)
                        return 0;
                    goto capture_in_reply;
                }
                if (setup.request == 2 && setup.bytes[2] != 0)
                    goto completed_success;
            }
        }
    }
    if (interface_index != 0xffffffffU) {
        if (setup.request == 11)
            MEDIUS_EP0_HID_CACHE[interface_index].protocol = -1;
        else if (setup.request == 10)
            MEDIUS_EP0_HID_CACHE[interface_index].idle = -1;
    }
completed_success:
    ep0_record_elapsed(elapsed);
    ep0_count_completed();
    if (observed_generation != generation)
        return 0;
    if (direction_out != 0) {
        medius_capture_nonzero_control(0, setup.bytes, 1, capture_flags,
            capture_payload, (unsigned short)capture_length);
        return 0;
    }
capture_in_reply:
    capture_payload = *data_slot;
    capture_length = *(const volatile unsigned short *)length;
    medius_capture_nonzero_control(0, setup.bytes, 0, capture_flags,
        capture_payload, (unsigned short)capture_length);
    return 0;

failed_wait:
    memw();
    MEDIUS_EP0_REPLY_CHANNEL->ep0_worker_busy = 0;
    if (interface_index != 0xffffffffU) {
        if (setup.request == 11)
            MEDIUS_EP0_HID_CACHE[interface_index].protocol = -1;
        else if (setup.request == 10)
            MEDIUS_EP0_HID_CACHE[interface_index].idle = -1;
    }
    ep0_record_elapsed(elapsed);
    ep0_count_completed();
    if (observed_generation != generation)
        return -1;
    capture_flags |= failure_marker != 0 ? 2 : 1;
    medius_capture_nonzero_control(0, setup.bytes, (unsigned char)direction_out,
        capture_flags, capture_payload, (unsigned short)capture_length);
    return -1;

early_forward_failure:
    memw();
    MEDIUS_EP0_REPLY_CHANNEL->ep0_worker_busy = 0;
    return -1;
}

/* Native entry: 0x403960f0. */
/* Original function-byte SHA-256:
 * 1c78f5cbb0e214f75bc062104a0b8b14dd4136ae6c2d98619bec953fd01b47bd. */
/*
 * Forward an otherwise unhandled EP0 request. bus is a native WORD narrowed to
 * its low BYTE at this boundary; setup/data/length are passed through unchanged.
 * Returns the relay's complete signed WORD result (0 or -1), with all cache,
 * rewrite, forwarding and capture side effects owned by that relay.
 */
int medius_ep0_forward_unhandled_request(unsigned int bus,
    const MediusUsbSetupPacket *setup, unsigned char **data, unsigned int *length)
{
    return medius_ep0_relay_request((unsigned char)bus, setup, data, length);
}
