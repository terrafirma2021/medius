/* Medius v3.4.7 device — Nonzero-control request worker. */
#include "../include/types.h"

/* ctrln reconstruction utilities: inline native rule scans, not extra entries.
 * Both scans cache the BYTE count and keep the first strictly highest score.
 * Request matching uses SETUP plus up to eight original OUT bytes and a
 * direction code of2-USB_IN; response matching uses SETUP alone, directions0/1.
 * Counts/payload offsets rely on the native admission invariants, without clamps.
 */
static __attribute__((always_inline)) inline int ctrln_select_request_rule(
    unsigned int endpoint,unsigned int direction,unsigned char *query,
    unsigned int query_length,unsigned int count)
{
    int selected = -1,best_score = -1;
    for (unsigned int index = 0; index < count; ++index) {
        volatile RewriteRule *rule = &REWRITE_RULES[index];
        unsigned int traffic_class = rule->traffic_class;
        unsigned int rule_endpoint = rule->endpoint;
        unsigned int rule_direction = rule->direction;
        unsigned int prefix_length = rule->prefix_length;
        unsigned int specificity;
        if (traffic_class == 8 && rule_endpoint == endpoint)
            specificity = 2;
        else if (traffic_class == 8 && rule_endpoint == 0xffffU)
            specificity = 1;
        else if (traffic_class == 0xffU)
            specificity = 0;
        else
            continue;
        if (rule_direction != 0 && rule_direction != direction)
            continue;
        if (prefix_length > query_length)
            continue;
        unsigned int byte;
        for (byte = 0; byte < prefix_length; ++byte) {
            unsigned char mask = rule->mask[byte];
            unsigned char value = *(volatile unsigned char *)(query + byte);
            unsigned char expected = rule->prefix[byte];
            if (expected != (value & mask))
                break;
        }
        if (byte != prefix_length)
            continue;
        int bits = 0;
        for (byte = 0; byte < prefix_length; ++byte)
            bits += __popcountsi2(rule->mask[byte]);
        int score = (int)(specificity * 100000U) + bits * 10 + (rule_direction != 0);
        if (score > best_score) {
            selected = (int)index;
            best_score = score;
        }
    }
    return selected;
}

static __attribute__((always_inline)) inline int ctrln_select_response_rule(
    unsigned int endpoint,unsigned char *setup,unsigned int count)
{
    int selected = -1,best_score = -1;
    for (unsigned int index = 0; (unsigned char)index < count; ++index) {
        volatile RewriteRule *rule = &REWRITE_RULES[index];
        unsigned int traffic_class = rule->traffic_class;
        unsigned int rule_endpoint = rule->endpoint;
        unsigned int direction = rule->direction;
        unsigned int prefix_length = rule->prefix_length;
        unsigned int specificity;
        if (traffic_class == 8 && rule_endpoint == endpoint)
            specificity = 2;
        else if (traffic_class == 8 && rule_endpoint == 0xffffU)
            specificity = 1;
        else if (traffic_class == 0xffU)
            specificity = 0;
        else
            continue;
        if (direction > 1 || prefix_length > 8)
            continue;
        unsigned int byte;
        for (byte = 0; (unsigned char)byte < prefix_length; ++byte) {
            unsigned char value = *(volatile unsigned char *)(setup + byte);
            unsigned char mask = rule->mask[byte];
            unsigned char expected = rule->prefix[byte];
            if (expected != (value & mask))
                break;
        }
        if ((unsigned char)byte != prefix_length)
            continue;
        int bits = 0;
        for (byte = 0; (unsigned char)byte < prefix_length; ++byte)
            bits += __popcountsi2(rule->mask[byte]);
        int score = (int)(specificity * 100000U) + bits * 10 + (int)direction;
        if (score > best_score) {
            selected = (int)index;
            best_score = score;
        }
    }
    return selected;
}

/* Native entry: 0x4202b4d8. */
/* Original function-byte SHA-256:
 * c087cb21c950fbdd989b1e40821a3d95f9353cde047e36ac6e13e6773c2feb8e. */
/*
 * ctrln task: receive one-BYTE slot indexes indefinitely; ignore receive!=1 and
 * slot>1. Publish busy, snapshot record generation/current WORD generation, and
 * require record state2, clone active and no quiesce. Stage endpoint+SETUP and
 * OUT actual bytes, then recheck record generation. Save at most172 original
 * OUT bytes for capture while retaining the original actual count.
 *
 * When rewrite/catch rules exist, snapshot SETUP plus up to eight original OUT
 * bytes, lock rewrite storage, evaluate enabled class8 catch rules, then scan
 * cached rewrite count. Rank class8 exact endpoint above class8 wildcard above
 * wildcard class; score100000*specificity+10*mask-popcount+direction-specific.
 * Equal scores keep the first rule; selected request hits saturate at UINT_MAX.
 * Action4 intercepts, actions2/3 modify an OUT prefix only if different, and
 * actions5/6 capture0x81 then stall. Other actions remain eligible for IN reply
 * rewriting. Native direction bytes/counts/pool offsets are trusted, not clamped.
 *
 * Forward after idle-wait and generation-gate acquisition, rechecking record
 * generation. Publish correlated reply state, drain signal and reset assembly.
 * Request<=512 uses opcode0x20; larger requests use506-byte fragments/opcode0x22.
 * Sequence wraps at256. Release gate, then wait700 ticks, or1400 for fragmented
 * requests/requested>=504. Transport results are ignored. Invalidate active slot
 * before checking reply. Disconnect clears state even before the generation
 * test; superseded records keep their new state. Timeout/error captures then
 * stalls. Successful IN replies with a selected request rule rescan class8
 * against SETUP alone, direction0/1, applying actions7/8 without incrementing hits.
 *
 * Capture original OUT data or successful IN reply with changed/error flags.
 * OUT/empty-request success publishes state4 and writes response actual bytes,
 * even when larger than requested. IN success publishes state3 and sets ZLP
 * for nonempty short exact-MPS multiples. Local interception uses its distinct
 * repeated actual reads and ZLP-before-state ordering. Failed submission clears
 * state/stalls. Every exit from an admitted slot clears busy after MEMW.
 *
 * Slot buffers persist for USB completion. No additional pointer/actual bounds,
 * local-intercept generation recheck, transport retry or atomic ownership is
 * added. Finite BYTE generations/sequences can wrap. Static recovery establishes
 * these operations, not runtime timing, reset interleavings or hardware success.
 */
void nonzero_control_task(void)
{
    for (;;) {
        unsigned char queued_slot;
        if (xQueueReceive(NONZERO_CONTROL_QUEUE,&queued_slot,0xffffffffU) != 1)
            continue;
        unsigned int slot = queued_slot;
        if (slot > 1)
            continue;
        memw();
        NONZERO_CONTROL_WORKER_BUSY = 1;
        volatile MediusNonzeroControlState *state = &MEDIUS_NONZERO_CONTROL_STATES[slot];
        memw();
        unsigned char record_generation = state->generation;
        memw();
        unsigned int generation = DEVICE_OUT_GENERATION;
        memw();
        unsigned char initial_state = state->state;
        if (initial_state != 2)
            goto idle;
        memw();
        unsigned char connected = CLONE_ACTIVE;
        if (connected == 0)
            goto idle;
        memw();
        unsigned char quiescing = MEDIUS_EP0_REPLY_LIFETIME->quiescing;
        if (quiescing != 0)
            goto idle;
        unsigned int requested = state->requested;
        unsigned char endpoint = state->endpoint;
        unsigned int direction_in = state->direction_in;
        unsigned int out_actual = state->actual;
        MediusNonzeroControlRequest *request = MEDIUS_NONZERO_REQUEST;
        *(volatile unsigned char *)&request->endpoint = endpoint;
        memcpy(request->setup,(const void *)state->setup,8);
        unsigned int direction_out = (unsigned char)(direction_in ^ 1U);
        unsigned char *buffer = MEDIUS_NONZERO_CONTROL_BUFFERS + slot * 2048U;
        unsigned int packet_length = 9;
        if ((direction_out & (out_actual != 0)) != 0) {
            memcpy(request->out_payload,buffer,out_actual);
            packet_length = (unsigned short)(out_actual + 9U);
        }
        memw();
        if (state->generation != record_generation)
            goto idle;
        unsigned int capture_out_length = 0;
        int out_payload_present = (direction_out & (out_actual != 0)) != 0 ||
            (direction_in == 0 && out_actual != 0);
        if (out_payload_present) {
            unsigned int saved = out_actual < 172U ? out_actual : 172U;
            memcpy(MEDIUS_NONZERO_CAPTURE_PREIMAGE,request->out_payload,saved);
            capture_out_length = out_actual;
        }
        unsigned char capture_flags = 0;
        int response_rule_eligible = 0;
        if (REWRITE_COUNT != 0 || PACKET_TRIGGER_COUNT != 0) {
            unsigned char query[16];
            memcpy(query,request->setup,8);
            unsigned int query_length = 8;
            if (out_payload_present) {
                unsigned int prefix = out_actual < 8U ? out_actual : 8U;
                memcpy(query + 8,request->out_payload,prefix);
                query_length = (unsigned short)(prefix + 8U);
            }
            unsigned int rule_direction = (unsigned char)(2U - direction_in);
            if (out_payload_present)
                rule_direction = initial_state;
            rewrite_lock();
            unsigned int rule_endpoint = state->endpoint;
            if (PACKET_TRIGGER_COUNT != 0) {
                clip_packet_rules_evaluate(8,rule_endpoint,rule_direction,query,query_length);
                rule_endpoint = state->endpoint;
            }
            unsigned int rule_count = REWRITE_COUNT;
            int selected = -1;
            if (rule_count != 0)
                selected = ctrln_select_request_rule(rule_endpoint,rule_direction,
                    query,query_length,rule_count);
            if (selected < 0) {
                rewrite_unlock();
            } else {
                response_rule_eligible = connected != 0;
                volatile RewriteRule *rule = &REWRITE_RULES[selected];
                unsigned int hits = rule->hits;
                if (hits != 0xffffffffU)
                    rule->hits = hits + 1U;
                unsigned int payload_offset = rule->payload_offset;
                unsigned int action = rule->action;
                const unsigned char *replacement = REWRITE_PAYLOAD_POOL + payload_offset;
                if (action == 4) {
                    MediusNonzeroControlReply *reply = MEDIUS_NONZERO_REPLY;
                    if (direction_in == 0) {
                        memw();
                        reply->actual = 0;
                        rewrite_unlock();
                        unsigned int capture_endpoint = state->endpoint;
                        medius_capture_nonzero_control(capture_endpoint,request->setup,1,0x80,
                            MEDIUS_NONZERO_CAPTURE_PREIMAGE,(unsigned short)capture_out_length);
                        unsigned char target = state->endpoint;
                        state->needs_zlp = 0;
                        memw();
                        state->state = 4;
                        if (usb_device_write_aligned(0,target | 0x80U,NULL,0) < 0)
                            goto stall;
                        goto idle;
                    }
                    unsigned int length = rule->payload_length;
                    unsigned int limit = requested < 2048U ? requested : 2048U;
                    if (length > limit)
                        length = limit;
                    memcpy(buffer,replacement,length);
                    memw();
                    reply->actual = (unsigned short)length;
                    rewrite_unlock();
                    memw();
                    unsigned short capture_length = reply->actual;
                    unsigned int capture_endpoint = state->endpoint;
                    medius_capture_nonzero_control(capture_endpoint,request->setup,0,0x80,
                        buffer,capture_length);
                    if (requested == 0) {
                        unsigned char target = state->endpoint;
                        state->needs_zlp = 0;
                        memw();
                        state->state = 4;
                        if (usb_device_write_aligned(0,target | 0x80U,NULL,0) < 0)
                            goto stall;
                        goto idle;
                    }
                    memw();
                    unsigned int first_actual = reply->actual;
                    unsigned int submitted_length;
                    unsigned char needs_zlp = quiescing;
                    if (first_actual > requested) {
                        submitted_length = requested;
                        needs_zlp = 0;
                    } else {
                        memw();
                        submitted_length = reply->actual;
                        if (submitted_length >= requested)
                            needs_zlp = 0;
                        else if (submitted_length != 0) {
                            unsigned int max_packet = state->max_packet;
                            if (max_packet != 0)
                                needs_zlp = submitted_length % max_packet == 0;
                        }
                    }
                    unsigned char target = state->endpoint;
                    state->needs_zlp = needs_zlp;
                    memw();
                    state->state = 3;
                    if (usb_device_write_aligned(0,target | 0x80U,buffer,submitted_length) < 0)
                        goto stall;
                    goto idle;
                }
                unsigned int patch_offset = 0,patch_length = 0;
                if (action == 2 && direction_out != 0) {
                    patch_offset = rule->patch_offset;
                    patch_length = rule->payload_length;
                    if (patch_offset + patch_length > out_actual)
                        patch_length = 0;
                } else if (action == 3 && direction_out != 0) {
                    patch_length = rule->payload_length;
                    if (patch_length > out_actual)
                        patch_length = out_actual;
                }
                if (patch_length != 0 && memcmp(request->out_payload + patch_offset,
                        replacement,patch_length) != 0) {
                    memcpy(request->out_payload + patch_offset,replacement,patch_length);
                    rewrite_unlock();
                    capture_flags = 0x80;
                } else {
                    rewrite_unlock();
                    if (action == 5 || action == 6) {
                        unsigned int capture_endpoint = state->endpoint;
                        medius_capture_nonzero_control(capture_endpoint,request->setup,
                            (unsigned char)direction_out,0x81,MEDIUS_NONZERO_CAPTURE_PREIMAGE,
                            (unsigned short)capture_out_length);
                        goto stall;
                    }
                }
            }
        }
        control_wait_idle_50ms();
        if (control_forward_acquire_generation(generation) == 0)
            goto idle;
        memw();
        if (state->generation != record_generation) {
            medius_control_forward_release();
            goto idle;
        }
        MediusNonzeroControlReply *reply = MEDIUS_NONZERO_REPLY;
        unsigned char expected_sequence = MEDIUS_NONZERO_NEXT_SEQUENCE;
        memw();
        reply->status = 0xfe;
        memw();
        reply->actual = 0;
        memw();
        reply->completed_sequence = (unsigned char)(expected_sequence - 1U);
        RtosQueue *signal = reply->signal;
        memw();
        reply->expected_sequence = expected_sequence;
        memw();
        reply->expected_generation = record_generation;
        memw();
        MEDIUS_NONZERO_ACTIVE_SLOT = queued_slot;
        xQueueSemaphoreTake(signal,0);
        unsigned char sent_sequence = MEDIUS_NONZERO_NEXT_SEQUENCE;
        *(volatile unsigned short *)&MEDIUS_NONZERO_RESPONSE_ASSEMBLY->total = 0;
        MEDIUS_NONZERO_ASSEMBLY_PROGRESS = 0;
        MEDIUS_NONZERO_NEXT_SEQUENCE = (unsigned char)(sent_sequence + 1U);
        unsigned int wait_ticks;
        if (packet_length > 512U) {
            unsigned char fragment_sequence = sent_sequence;
            control_fragment_emit((const unsigned char *)request,
                (unsigned short)packet_length,506,medius_nonzero_send_request_fragment,
                &fragment_sequence);
            medius_control_forward_release();
            signal = reply->signal;
            wait_ticks = 1400;
        } else {
            link_send_wait100(0x20,sent_sequence,request,(unsigned short)packet_length);
            medius_control_forward_release();
            signal = reply->signal;
            wait_ticks = requested >= 504U ? 1400 : 700;
        }
        int received = xQueueSemaphoreTake(signal,wait_ticks);
        memw();
        MEDIUS_NONZERO_ACTIVE_SLOT = 0xff;
        int matched = 0;
        if (received == 1) {
            memw();
            matched = reply->completed_sequence == expected_sequence;
        }
        memw();
        if (CLONE_ACTIVE == 0)
            goto disconnected;
        memw();
        if (MEDIUS_EP0_REPLY_LIFETIME->quiescing != 0)
            goto disconnected;
        memw();
        if (state->generation != record_generation)
            goto idle;
        if (response_rule_eligible && matched) {
            memw();
            unsigned int status = reply->status;
            if (status == 0 && direction_in != 0) {
                rewrite_lock();
                unsigned int rule_endpoint = state->endpoint;
                unsigned int rule_count = REWRITE_COUNT;
                int selected = ctrln_select_response_rule(rule_endpoint,request->setup,rule_count);
                if (selected >= 0) {
                    volatile RewriteRule *rule = &REWRITE_RULES[selected];
                    unsigned int payload_offset = rule->payload_offset;
                    unsigned int action = rule->action;
                    const unsigned char *replacement = REWRITE_PAYLOAD_POOL + payload_offset;
                    if (action == 7) {
                        unsigned int offset = rule->patch_offset;
                        unsigned int length = rule->payload_length;
                        memw();
                        unsigned int actual = reply->actual;
                        if (offset + length <= actual) {
                            if (memcmp(buffer + offset,replacement,length) != 0)
                                capture_flags = 0x80;
                            memcpy(buffer + offset,replacement,length);
                        }
                    } else if (action == 8) {
                        unsigned int length = rule->payload_length;
                        unsigned int limit = requested < 2048U ? requested : 2048U;
                        memw();
                        unsigned int actual = reply->actual;
                        if (length > limit)
                            length = limit;
                        if (length != actual || memcmp(buffer,replacement,length) != 0)
                            capture_flags = 0x80;
                        memcpy(buffer,replacement,length);
                        memw();
                        reply->actual = (unsigned short)length;
                    }
                }
                rewrite_unlock();
            }
        }
        unsigned int capture_endpoint = state->endpoint;
        if (!matched) {
            capture_flags |= 1;
            if (direction_in == 0)
                medius_capture_nonzero_control(capture_endpoint,request->setup,
                    (unsigned char)direction_out,capture_flags,MEDIUS_NONZERO_CAPTURE_PREIMAGE,
                    (unsigned short)capture_out_length);
            else
                medius_capture_nonzero_control(capture_endpoint,request->setup,0,
                    capture_flags,NULL,0);
            goto stall;
        }
        memw();
        unsigned int capture_status = reply->status;
        capture_flags |= capture_status != 0;
        if (direction_in == 0) {
            medius_capture_nonzero_control(capture_endpoint,request->setup,1,capture_flags,
                MEDIUS_NONZERO_CAPTURE_PREIMAGE,(unsigned short)capture_out_length);
        } else {
            unsigned char *capture_payload = NULL;
            unsigned short capture_length = 0;
            if (capture_status == 0) {
                memw();
                capture_length = reply->actual;
                capture_payload = buffer;
            }
            medius_capture_nonzero_control(capture_endpoint,request->setup,0,
                capture_flags,capture_payload,capture_length);
        }
        memw();
        if (reply->status != 0)
            goto stall;
        if (requested == 0 || direction_in == 0) {
            memw();
            state->state = 4;
            unsigned char target = state->endpoint;
            memw();
            unsigned char *submitted = reply->actual != 0 ? buffer : NULL;
            memw();
            unsigned int length = reply->actual;
            if (usb_device_write_aligned(0,target | 0x80U,submitted,length) < 0)
                goto stall;
        } else {
            memw();
            unsigned int length = reply->actual;
            unsigned char needs_zlp = 0;
            if (length < requested && length != 0) {
                unsigned int max_packet = state->max_packet;
                if (max_packet != 0)
                    needs_zlp = length % max_packet == 0;
            }
            unsigned char target = state->endpoint;
            memw();
            state->state = 3;
            state->needs_zlp = needs_zlp;
            if (usb_device_write_aligned(0,target | 0x80U,buffer,length) < 0)
                goto stall;
        }
        goto idle;
disconnected:
        memw();
        state->state = 0;
        goto idle;
stall:
        memw();
        state->state = 0;
        medius_nonzero_control_stall((const MediusNonzeroControlState *)state);
idle:
        memw();
        NONZERO_CONTROL_WORKER_BUSY = 0;
    }
}
