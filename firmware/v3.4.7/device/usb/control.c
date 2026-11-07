/* Medius v3.4.7 device — usb/control.c.
 * Recovered C and native assembly, grouped for source navigation.
 * Original entry addresses, firmware-byte hashes and function comments follow.
 */

#include "../include/types.h"

/* Native entry: 0x40377630. */
/* Original function-byte SHA-256:
 * 707db46da207746cc734685894804d9bc102d7e357747ad30249854f1b08edb1. */
/*
 * Publish empty type0x35 generation markers up to target_generation. No gate:
 * return. Otherwise snapshot published generation and use candidate=sent+1.
 * Each changed candidate gets a50,000us absolute deadline. Candidate0 following
 * an initial UINT_MAX starts with deadline0. Take the forwarding gate; failure
 * returns. Unless skip_out_wait!=0, a peeked OUT head or active OUT worker with
 * generation<candidate blocks readiness. Only if these checks pass, require
 * low-priority TX queue empty. Peek copies a complete80-byte message, wait0.
 *
 * While the published generation equals the cached snapshot, publish when
 * ready OR the signed64 clock reaches the deadline. Send(type0x35,0,NULL,0),
 * ignore admission result, fence and store candidate even on failure. Give a
 * freshly sampled gate on every acquired path. If a fresh sent sample remains
 * below candidate, delay1tick; fence and take another sent sample for the next
 * candidate. Separate samples and gate ownership order are retained.
 *
 * The50ms deadline allows markers past backlog; it is not a whole-call bound.
 * Gate take can wait indefinitely, queue-empty is not physical TX-idle, and
 * published generation does not prove delivery. Unsigned comparisons/addition
 * are not wrap-aware; targetUINT_MAX can continue through generation0.
 */
void control_forward_generations(unsigned int target_generation,int skip_out_wait)
{
    if (CONTROL_FORWARD_GATE == 0) return;
    memw();
    unsigned int sent_snapshot = CONTROL_FORWARDED_GENERATION;
    unsigned int candidate = sent_snapshot + 1U;
    unsigned int previous_candidate = 0;
    long long deadline = 0;
    while (candidate <= target_generation) {
        if (candidate != previous_candidate)
            deadline = (long long)((unsigned long long)esp_timer_get_time() + 50000ULL);
        if (medius_control_forward_take() == 0) return;
        int ready = 1;
        if (skip_out_wait == 0) {
            RtosQueue *queue = DEVICE_OUT_FORWARD_QUEUE;
            MediusDeviceOutMessage head;
            if (queue != 0 && xQueuePeek(queue,&head,0) == 1 && head.generation < candidate)
                ready = 0;
            else {
                memw();
                if (MEDIUS_OUT_ACTIVE_GENERATION < candidate) ready = 0;
            }
        }
        if (ready && link_low_priority_queue_empty() == 0) ready = 0;
        memw();
        if (CONTROL_FORWARDED_GENERATION == sent_snapshot &&
            (ready || esp_timer_get_time() >= deadline)) {
            (void)link_send_wait100(0x35,0,0,0);
            memw(); CONTROL_FORWARDED_GENERATION = candidate;
        }
        (void)xQueueGenericSend(CONTROL_FORWARD_GATE,0,0,0);
        memw();
        if (CONTROL_FORWARDED_GENERATION < candidate) vTaskDelay(1);
        memw(); sent_snapshot = CONTROL_FORWARDED_GENERATION;
        previous_candidate = candidate;
        candidate = sent_snapshot + 1U;
    }
}

/* Native entry: 0x403942a8. */
/* Original function-byte SHA-256:
 * 9d33158a88fbc6c97408cfead7f008bd3dd894e09eb940a49cd39f3b87ca5abb. */
/*
 * If the published marker generation is unsigned-less than generation, first
 * request markers with OUT-drain waiting enabled. Then, with no gate, return
 * current session generation==generation. Otherwise take the gate, fence and
 * compare CURRENT session generation; return1 holding the gate on equality.
 * Failed take returns0; mismatch gives a freshly sampled gate, then returns0.
 * Comparisons are not wrap-aware; equality is a snapshot, not reset exclusion.
 * A missing gate provides no mutual exclusion. Marker advancement can occur
 * despite transport failure, and take can wait indefinitely while connected.
 */
int control_forward_acquire_generation(unsigned int generation)
{
    memw();
    if (CONTROL_FORWARDED_GENERATION < generation)
        control_forward_generations(generation,0);
    RtosQueue *gate = CONTROL_FORWARD_GATE;
    if (gate == 0) {
        memw();
        return DEVICE_OUT_GENERATION == generation;
    }
    int acquired = medius_control_forward_take();
    if (acquired == 0) return 0;
    memw();
    if (DEVICE_OUT_GENERATION == generation) return acquired;
    (void)xQueueGenericSend(CONTROL_FORWARD_GATE,0,0,0);
    return 0;
}

/* Native entry: 0x40395088. */
/* Original function-byte SHA-256:
 * 87c4b8982e7b3b81379e157625b4852948ed038c77745ce715d0a3c724b4cf2c. */
/*
 * Repeatedly take the freshly sampled forwarding gate with10-tick waits. After
 * EACH attempt, fence and sample quiescing once. Exact status1 with quiescing0
 * returns1 with the gate held; status1 during quiescing gives the freshly
 * sampled gate back, then returns0. Other statuses retry until quiescing!=0.
 * Always attempts once, even if already quiescing. No NULL guard, total timeout
 * or guarantee that a concurrently replaced handle is the acquired handle.
 */
int medius_control_forward_take(void)
{
    for (;;) {
        int status = xQueueSemaphoreTake(CONTROL_FORWARD_GATE,10);
        memw();
        unsigned char quiescing = CLONE_QUIESCING;
        if (status == 1) {
            if (quiescing == 0) return 1;
            (void)xQueueGenericSend(CONTROL_FORWARD_GATE,0,0,0);
            return 0;
        }
        if (quiescing != 0) return 0;
    }
}

/* Native entry: 0x4202845c. */
/* Original function-byte SHA-256:
 * 31ee48678e22810f667c0b29eb6367f5db71e68e85c00bb85f665661ad26a6f4. */
/*
 * Snapshot the current forwarding gate; if nonnull, give it with zero wait and
 * discard the result. Does not track ownership, change generations or cancel
 * queued work. The handle is sampled once for this give operation.
 */
void medius_control_forward_release(void)
{
    RtosQueue *gate = CONTROL_FORWARD_GATE;
    if (gate != 0) (void)xQueueGenericSend(gate,0,0,0);
}

/* Native entry: 0x42028568. */
/* Original function-byte SHA-256:
 * c2c4d54ed2bc51a016ad0bb7a43f671d0d89aec838e9a3b81cc58a1203e184ae. */
/* Read endpoint BYTE and stall bus0/LOW8(endpoint|0x80). RELOAD the state
 * endpoint BYTE after that driver call, then stall bus0/raw endpoint. Ignore
 * both results. No bounds/direction normalization, state-byte change or lock;
 * an endpoint already carrying bit7 can target IN twice. Driver may mutate
 * shared state between calls, so the second endpoint is deliberately reread. */
void medius_nonzero_control_stall(const MediusNonzeroControlState *state)
{
    const volatile MediusNonzeroControlState *view = state;
    unsigned char endpoint = view->endpoint;
    usb_device_set_stall(0,(unsigned char)(endpoint | 0x80U));
    endpoint = view->endpoint;
    usb_device_set_stall(0,endpoint);
}

/* Native entry: 0x4203943c. */
/* Original function-byte SHA-256:
 * db3c248d6368ad470bf9048dd9eb27517ee4f691ba693807ab72f03685d3468c. */
/*
 * RAW wrapper: low8 endpoint/direction and low16 length. If a configuration
 * mutex exists, take it with UINT_MAX ticks, ignoring result; then MEMW/test
 * active clone. Without mutex, MEMW/test clone and return immediately if zero
 * (no release-handle reload). For an active clone require configured bus0 and
 * direction1 or2, then call the raw endpoint router with NULL update mask
 * and UINT_MAX report epoch. No endpoint/length/payload validation here; the
 * external dispatcher separately gates imperfect mode. Reload current mutex
 * and send(NULL,0,back) on the common exit; no error result or send retry.
 */
void raw_endpoint_send(unsigned char endpoint,unsigned char direction,
    const unsigned char *bytes,unsigned short length)
{
    RtosQueue *mutex = REWRITE_MUTEX;
    if (mutex == 0) {
        memw();
        if (CLONE_ACTIVE == 0) return;
    } else {
        (void)xQueueSemaphoreTake(mutex,0xffffffffU);
        memw();
        if (CLONE_ACTIVE == 0) goto release;
    }
    if (usb_device_is_configured(0) && (unsigned char)(direction - 1U) < 2)
        FUN_4203118c(endpoint,direction,bytes,length,0,0xffffffffU);
release:
    mutex = REWRITE_MUTEX;
    if (mutex != 0) (void)xQueueGenericSend(mutex,0,0,0);
}

/* Native entry: 0x4203118c. */
/* Original function-byte SHA-256:
 * 54de1c6945be985c9181d830dde79017ecb564a03ecffcb8d3cf265d38352ab2. */
/*
 * Sample clock LOW, canonicalize endpoint to its low4 number. Direction EXACTLY1
 * uses IN; every other full-WORD direction uses OUT. No configuration/clone
 * gate, local lock, pointer validation or status result is supplied here.
 *
 * IN: first matching HID interface wins. Its cached HALFWORD length limit is
 * capped64 (zero means64); oversized input returns, without auxiliary fallback.
 * Submit kind2 through report processing with all optional fields zero, shared
 * status pointer and caller epoch; ignore submission result. Then cache prior
 * output for matching primary mouse, else dynamic layout, else keyboard, else
 * consumer, checking current binding/length/report-ID metadata. Fixed caches
 * clear output-valid and OR class bit0/1/2 into optional update mask; dynamic
 * cache returns without those operations. Cache updates still occur on submit
 * failure. Primary report-ID is read once; zero-ID accepts an empty report.
 *
 * No HID endpoint match: first auxiliary IN record with queue_slot<6 is used.
 * Packet size zero means64; NONZERO is not capped here. Nonbulk fits one packet
 * (kind0,synthetic1,flags0). Bulk(kind1) splits with16-bit remaining/offset,
 * flags1 on final short fragment, and adds ZLP/flags1 on an exact multiple;
 * empty input emits one ZLP. The secondary helper itself copies at most64 per
 * fragment, so this router does not make large auxiliary packets lossless.
 *
 * OUT: require forward queue and nonzero number. First auxiliary match supplies
 * type/MPS; scan cached control count too, letting each matching nonzero MPS
 * replace that limit (last nonzero duplicate wins). At least one source must
 * match. Cap effective packet size64; auxiliary bulk splits/terminates as above
 * into type2 pending packets; other paths require one fitting type3 packet.
 * Drain after appending, without knowing admission success. Bulk offset wraps16;
 * a full32 length above65535 can prevent progress. No timeout or added repair.
 */
void raw_endpoint_route(unsigned int endpoint,int direction,const unsigned char *bytes,
    unsigned int length,unsigned char *updated_mask,unsigned int epoch)
{
    unsigned int stamp = (unsigned int)esp_timer_get_time();
    endpoint &= 15U;
    if (direction == 1) {
        endpoint |= 128U;
        int interface_count = USB_INTERFACE_COUNT;
        for (int interface = 0; interface < interface_count; ++interface) {
            if (USB_INTERFACE_ENDPOINTS[interface] != endpoint) continue;
            unsigned int limit = MEDIUS_RAW_INTERFACE_LENGTH_LIMITS[interface];
            if (limit == 0 || limit > 64) limit = 64;
            if (length > limit) return;
            (void)report_process_interface(interface,bytes,length,1,0,0,0,0,0,0,
                &REPORT_PROCESS_STATUS,0,epoch);
            unsigned int fixed = 0;
            if (FIXED_INPUTS[0].enabled != 0 &&
                FIXED_INPUTS[0].interface == interface &&
                FIXED_INPUTS[0].expected_length == length) {
                const volatile HidReportLayout *layout = FIXED_INPUTS[0].state.hid_layout;
                if (layout != 0) {
                    unsigned char id = layout->report_id;
                    if (id == 0 || (length != 0 && *(const volatile unsigned char *)bytes == id))
                        goto cache_fixed;
                }
            }
            ReportLayoutBinding *dynamic = report_layout_find(interface,bytes,length);
            if (dynamic != 0) {
                memcpy(dynamic->previous_output,bytes,length);
                return;
            }
            if (FIXED_INPUTS[1].enabled != 0 && FIXED_INPUTS[1].interface == interface) {
                const volatile HidKeyboardLayout *keyboard = &HID_REPORT_LAYOUTS[interface].keyboard;
                if (keyboard->enabled != 0 && keyboard->expected_length == length) {
                    unsigned char id = keyboard->report_id;
                    if (id == 0 || (length != 0 && *(const volatile unsigned char *)bytes == id)) {
                        fixed = 1; goto cache_fixed;
                    }
                }
            }
            if (FIXED_INPUTS[2].enabled == 0 || FIXED_INPUTS[2].interface != interface)
                return;
            const volatile HidConsumerLayout *consumer = &HID_REPORT_LAYOUTS[interface].consumer;
            if (consumer->enabled == 0 || consumer->expected_length != length) return;
            unsigned char id = consumer->report_id;
            if (id != 0 && (length == 0 || *(const volatile unsigned char *)bytes != id)) return;
            fixed = 2;
cache_fixed:
            memcpy((unsigned char *)FIXED_INPUTS[fixed].previous_output,bytes,length);
            FIXED_INPUTS[fixed].output_valid = 0;
            if (updated_mask != 0) {
                volatile unsigned char *mask = updated_mask;
                unsigned char old = *mask;
                *mask = old | (unsigned char)(1U << fixed);
            }
            return;
        }
        int count = CREDIT_BINDINGS.count;
        for (int index = 0; index < count; ++index) {
            const volatile CreditBinding *binding = &CREDIT_BINDINGS.entry[index];
            if (binding->endpoint != endpoint) continue;
            if (binding->queue_slot >= 6) return;
            unsigned int packet = binding->packet_length;
            unsigned char kind = binding->kind;
            if (packet == 0) packet = 64;
            if (kind != 2) {
                if (length > packet) return;
                report_enqueue_secondary(endpoint,(unsigned char *)bytes,length,0,stamp,1,0);
            } else if (length == 0) {
                report_enqueue_secondary(endpoint,(unsigned char *)bytes,0,1,stamp,1,1);
            } else {
                unsigned short offset = 0;
                do {
                    unsigned int remaining = (unsigned short)(length - offset);
                    unsigned int chunk = remaining < packet ? remaining : packet;
                    unsigned short next = (unsigned short)(offset + chunk);
                    unsigned char final_short = next >= length && remaining < packet;
                    report_enqueue_secondary(endpoint,(unsigned char *)bytes + offset,chunk,1,stamp,1,final_short);
                    offset = next;
                } while (offset < length);
                if (length % packet == 0)
                    report_enqueue_secondary(endpoint,(unsigned char *)bytes,0,1,stamp,1,1);
            }
            return;
        }
        return;
    }
    RtosQueue *queue = DEVICE_OUT_FORWARD_QUEUE;
    if (queue == 0 || endpoint == 0) return;
    int count = CREDIT_BINDINGS.count;
    int auxiliary = -1;
    unsigned int packet = 64;
    for (int index = 0; index < count; ++index) {
        if (CREDIT_BINDINGS.entry[index].endpoint != endpoint) continue;
        auxiliary = index;
        packet = CREDIT_BINDINGS.entry[index].packet_length;
        if (packet == 0) packet = 64;
        break;
    }
    bool matched = auxiliary != -1;
    int control_count = MEDIUS_RAW_CONTROL_ENDPOINT_COUNT;
    for (int index = 0; index < control_count; ++index) {
        if (MEDIUS_RAW_CONTROL_ENDPOINT_ADDRESSES[index] != endpoint) continue;
        unsigned int control_packet = MEDIUS_RAW_CONTROL_ENDPOINT_LIMITS[index];
        matched = true;
        if (control_packet != 0) packet = control_packet;
    }
    if (!matched) return;
    if (packet > 64) packet = 64;
    if (auxiliary != -1 && CREDIT_BINDINGS.entry[auxiliary].kind == 2) {
        if (length == 0) {
            medius_out_append_pending(endpoint,2,bytes,0,stamp);
        } else {
            unsigned short offset = 0;
            do {
                unsigned int remaining = (unsigned short)(length - offset);
                unsigned int chunk = remaining < packet ? remaining : packet;
                medius_out_append_pending(endpoint,2,bytes + offset,chunk,stamp);
                offset = (unsigned short)(offset + chunk);
            } while (offset < length);
            if (length % packet == 0) medius_out_append_pending(endpoint,2,bytes,0,stamp);
        }
    } else {
        if (length > packet) return;
        medius_out_append_pending(endpoint,3,bytes,length,stamp);
    }
    out_drain_pending(endpoint);
}
