/* Medius v3.4.7 device — usb/outbound.c.
 * Recovered C and native assembly, grouped for source navigation.
 * Original entry addresses, firmware-byte hashes and function comments follow.
 */

#include "../include/types.h"

/* Native entry: 0x4202e4d4. */
/* Original function-byte SHA-256:
 * 290b2089f962ed16a1522ec4e4613e9ab24cc1883f45ad62f3386b6e4f68ded6. */
/*
 * Device OUT forwarding task; unused task argument. Peek an80-byte message with
 * UINT_MAX ticks until status1; snapshot the queue again, fence/publish the
 * PEEKED generation as active, then receive with zero wait and ignore status.
 * A competing consumer or queue replacement can leave active generation and
 * received record different; no local NULL/receive-success guard.
 *
 * Ordinary records have state_action==control_type==0. Unless already accounted,
 * apply report rewrite then capture the ORIGINAL payload (class=event_kind,
 * direction2, subtype1, zero-length flag2 plus rewrite flags). A rewrite drop
 * releases endpoint accounting and drains pending data only when configured.
 * A different output pointer is copied back and length narrowed to BYTE; same
 * pointer retains original length. Neither selected length nor64-byte scratch
 * is locally bounded. Markers catch up with OUT waiting skipped. Type2 or no
 * gate bypasses take; failed take still permits a nonstale generation. Stale
 * reports increment drops, release accounting and optionally drain pending.
 *
 * Before sending, under OUT lock, find first exact nonzero OUT endpoint among
 * ten24-byte slots. Advance its BYTE sent sequence, reduce nonzero completion
 * debt via ONE HALFWORD store at+10 and store a fresh clock LOW then HIGH at
 * +16/+20. Type2 reads MPS under credit lock and sends type0x1d with8-byte header:
 * endpoint, stamp little-endian4, sequence, zero, short-packet flag. Flag is1
 * when MPS0 or length!=MPS. Others send type0x18 with endpoint/sequence2-byte
 * header. Shared wire storage is borrowed; no local lock covers its lifetime.
 *
 * Metadata records catch up markers, discard stale generations, then either
 * send type0x3f {endpoint,state_action==1,state_sequence}, or acquire the CURRENT
 * session generation and send control_type/payload. Control work already
 * quiescing is skipped. Every send path attempts at least once, then retries
 * failed transport admission only while quiescing0 and clone active!=0. Release
 * a freshly sampled gate when held. Accepted ordinary forwarding does not free
 * endpoint accounting here. Control records decrement active-control even
 * when stale/rejected. Finally fence/store active-generation UINT_MAX.
 *
 * Comparisons are unsigned, not wrap-aware. No whole-call retry deadline,
 * physical-send acknowledgement or execution/timing/concurrency guarantee.
 * Task registration uses label outfwd; scheduling is separate from this body.
 */
void outbound_forward_task(void *unused_argument)
{
    (void)unused_argument;
    for (;;) {
        MediusDeviceOutMessage message;
        unsigned char completion_control_type;
        do {
        } while (xQueuePeek(DEVICE_OUT_FORWARD_QUEUE,&message,0xffffffffU) != 1);
        unsigned int peeked_generation = message.generation;
        RtosQueue *receive_queue = DEVICE_OUT_FORWARD_QUEUE;
        memw(); MEDIUS_OUT_ACTIVE_GENERATION = peeked_generation;
        (void)xQueueReceive(receive_queue,&message,0);

        if (((message.route >> 8) & 0xffffU) != 0) {
            memw();
            if (CONTROL_FORWARDED_GENERATION < message.generation)
                control_forward_generations(message.generation,1);
            completion_control_type = message.control_type;
            memw();
            if (message.generation < CONTROL_FORWARDED_GENERATION)
                goto finish_with_cached_control_type;
            if (completion_control_type == 0) {
                unsigned char state[3] = {message.endpoint,
                    message.state_action == 1,message.state_sequence};
                for (;;) {
                    if (link_send_wait100(0x3f,0,state,3) != 0) break;
                    memw(); if (CLONE_QUIESCING != 0) break;
                    memw(); if (CLONE_ACTIVE == 0) break;
                }
                goto finish_record;
            }
            memw();
            if (CLONE_QUIESCING != 0) goto finish_with_cached_control_type;
            int acquired = control_forward_acquire_generation(message.generation);
            completion_control_type = message.control_type;
            if (acquired == 0) goto finish_with_cached_control_type;
            unsigned char control_type = completion_control_type;
            unsigned int length = message.length;
            for (;;) {
                if (link_send_wait100(control_type,0,message.payload,length) != 0) break;
                memw(); if (CLONE_QUIESCING != 0) break;
                memw(); if (CLONE_ACTIVE == 0) break;
            }
            RtosQueue *gate = CONTROL_FORWARD_GATE;
            if (gate != 0) (void)xQueueGenericSend(gate,0,0,0);
            goto finish_record;
        }

        if (message.accounted == 0) {
            unsigned char scratch[64],rewrite_flags;
            unsigned char *selected;
            unsigned short selected_length;
            unsigned int dropped = report_apply_rewrite(message.event_kind,
                message.endpoint,2,message.payload,message.length,scratch,
                &selected,&selected_length,&rewrite_flags);
            capture_emit_raw(message.event_kind,message.endpoint & 15U,2,
                (message.length == 0 ? 2U : 0U) | rewrite_flags,
                message.stamp,1,message.payload,message.length);
            if (dropped != 0) {
                unsigned int endpoint = message.endpoint;
                medius_out_release_accounting(endpoint);
                if (usb_device_is_configured(0) != 0) out_drain_pending(endpoint);
                goto finish_record;
            }
            if (selected != message.payload) {
                unsigned short length = selected_length;
                memcpy(message.payload,selected,length);
                message.length = (unsigned char)length;
            }
        }
        memw();
        if (CONTROL_FORWARDED_GENERATION < message.generation)
            control_forward_generations(message.generation,1);
        int gate_held = 0;
        if (message.transfer_type == 2 || CONTROL_FORWARD_GATE == 0) {
            memw();
            if (message.generation < CONTROL_FORWARDED_GENERATION) goto drop_report;
        } else {
            int acquired = medius_control_forward_take();
            memw(); unsigned int forwarded = CONTROL_FORWARDED_GENERATION;
            if (message.generation < forwarded) {
                if (acquired != 0) {
                    RtosQueue *gate = CONTROL_FORWARD_GATE;
                    if (gate != 0) (void)xQueueGenericSend(gate,0,0,0);
                }
                goto drop_report;
            }
            gate_held = acquired != 0;
        }
        unsigned int endpoint = message.endpoint;
        unsigned char sent_sequence = 0;
        (void)xPortEnterCriticalTimeout(DEVICE_OUT_LOCK,-1);
        if ((endpoint & 0x7fU) != 0 && (endpoint & 0x80U) == 0) {
            for (unsigned int index = 0; index != 10; ++index) {
                volatile DeviceOutEndpoint *slot = &DEVICE_OUT_ENDPOINTS[index];
                if (slot->endpoint != endpoint) continue;
                unsigned char previous_sequence = slot->sent_sequence;
                unsigned char debt = slot->completion_debt;
                sent_sequence = (unsigned char)(previous_sequence + 1U);
                slot->sent_sequence = sent_sequence;
                if (debt != 0) slot->sequence_and_debt =
                    sent_sequence | ((unsigned short)(unsigned char)(debt - 1U) << 8);
                unsigned long long now = (unsigned long long)esp_timer_get_time();
                slot->last_forward_us_low = (unsigned int)now;
                slot->last_forward_us_high = (unsigned int)(now >> 32);
                break;
            }
        }
        vPortExitCritical(DEVICE_OUT_LOCK);
        unsigned int wire_length;
        unsigned char wire_type;
        if (message.transfer_type == 2) {
            unsigned int maximum_packet = 0;
            (void)xPortEnterCriticalTimeout(&CREDIT_LOCK,-1);
            int count = CREDIT_BINDINGS.count;
            const volatile CreditBinding *binding =
                (const volatile CreditBinding *)0x3fccbe20U;
            for (int remaining = count; remaining > 0; --remaining,++binding) {
                if (binding->endpoint != message.endpoint) continue;
                maximum_packet = binding->packet_length;
                break;
            }
            vPortExitCritical(&CREDIT_LOCK);
            unsigned int stamp = message.stamp;
            unsigned int length = message.length;
            unsigned char short_packet = maximum_packet == 0 || length != maximum_packet;
            MEDIUS_OUT_FORWARD_WIRE.halfwords[2] =
                (unsigned short)((stamp >> 24) | ((unsigned int)sent_sequence << 8));
            MEDIUS_OUT_FORWARD_WIRE.words[0] = message.endpoint | (stamp << 8);
            MEDIUS_OUT_FORWARD_WIRE.bytes[6] = 0;
            MEDIUS_OUT_FORWARD_WIRE.bytes[7] = short_packet;
            if (length != 0) {
                memcpy((void *)&MEDIUS_OUT_FORWARD_WIRE.bytes[8],message.payload,length);
                length = message.length;
            }
            wire_length = length + 8U;
            wire_type = 0x1d;
        } else {
            unsigned int length = message.length;
            MEDIUS_OUT_FORWARD_WIRE.halfwords[0] =
                message.endpoint | ((unsigned short)sent_sequence << 8);
            if (length != 0) {
                memcpy((void *)&MEDIUS_OUT_FORWARD_WIRE.bytes[2],message.payload,length);
                length = message.length;
            }
            wire_length = length + 2U;
            wire_type = 0x18;
        }
        for (;;) {
            if (link_send_wait100(wire_type,0,
                    (const void *)&MEDIUS_OUT_FORWARD_WIRE,wire_length) != 0) break;
            memw(); if (CLONE_QUIESCING != 0) break;
            memw(); if (CLONE_ACTIVE == 0) break;
        }
        if (gate_held != 0) {
            RtosQueue *gate = CONTROL_FORWARD_GATE;
            if (gate != 0) (void)xQueueGenericSend(gate,0,0,0);
        }
        goto finish_record;

drop_report:
        endpoint = message.endpoint;
        memw(); unsigned int drops = DEVICE_OUT_DROPS + 1U;
        memw(); DEVICE_OUT_DROPS = drops;
        medius_out_release_accounting(endpoint);
        if (usb_device_is_configured(0) != 0) out_drain_pending(endpoint);
finish_record:
        completion_control_type = message.control_type;
finish_with_cached_control_type:
        if (completion_control_type != 0)
            (void)atomic_fetch_sub_u32(&CONTROL_OPERATION_ACTIVE,1,3);
        memw(); MEDIUS_OUT_ACTIVE_GENERATION = 0xffffffffU;
    }
}

/* Native entry: 0x4202ae48. */
/* Original function-byte SHA-256:
 * c40d7a740a5e0656e1832068d8d0ca8e1fa67ee40bb4fc97cafee60a367a749c. */
/*
 * Enter OUT spinlock(UINT_MAX cycles,ignored result), scan ten24-byte records
 * for first address BYTE equal to FULL-WORD endpoint. No zero/IN admission gate.
 * Missing slot/count>=16: unlock then fenced WORD drop read/increment/store.
 * Otherwise use cached pending count for76-byte destination: MEMW/load current
 * generation and store+4, timestamp+0, HALF(endpoint | type<<8)+8, publish
 * count+1 BYTE, length low8+10, then memcpy payload+11 for FULL32 nonzero length.
 * Freshly increment matched-slot pending BYTE, unlock; no drain/rearm/status.
 * Payload capacity64 is unchecked; bytes after copied span/padding are retained.
 * Count precedes payload publication, with no rollback on copy fault. Invalid
 * length can overflow record/array; caller admission and locking are required.
 */
void medius_out_append_pending(unsigned int endpoint,unsigned int transfer_type,
    const unsigned char *payload,unsigned int length,unsigned int stamp)
{
    (void)xPortEnterCriticalTimeout(DEVICE_OUT_LOCK,-1);
    for (unsigned int slot = 0; slot < 10; ++slot) {
        if (DEVICE_OUT_ENDPOINTS[slot].endpoint != endpoint) continue;
        unsigned int count = MEDIUS_DEVICE_OUT_PENDING_COUNT;
        if (count >= 16) break;
        volatile MediusDeviceOutPending *record = &MEDIUS_DEVICE_OUT_PENDING[count];
        memw(); unsigned int generation = DEVICE_OUT_GENERATION;
        record->generation = generation;
        record->stamp = stamp;
        record->endpoint_type = (unsigned short)(endpoint | transfer_type << 8);
        MEDIUS_DEVICE_OUT_PENDING_COUNT = (unsigned char)(count + 1U);
        record->length = (unsigned char)length;
        if (length != 0) memcpy((unsigned char *)record->payload,payload,length);
        unsigned char pending = DEVICE_OUT_ENDPOINTS[slot].pending;
        DEVICE_OUT_ENDPOINTS[slot].pending = (unsigned char)(pending + 1U);
        vPortExitCritical(DEVICE_OUT_LOCK);
        return;
    }
    vPortExitCritical(DEVICE_OUT_LOCK);
    memw(); unsigned int drops = DEVICE_OUT_DROPS;
    memw(); DEVICE_OUT_DROPS = drops + 1U;
}

/* Native entry: 0x40394c8c. */
/* Original function-byte SHA-256:
 * 2f2f70bc48f63b0e26ca113c6974f00ab241ee7c34f88420e3228bbfa663ca07. */
/*
 * Optionally take outer mutex forever(ignored result), then OUT spinlock.
 * Low7 endpoint0/low8 IN skips work. Each iteration scans ten address records
 * for full endpoint equality. Require pending!=0, then read blocked BYTE and
 * snapshot pending queue count BEFORE testing blocked. Scan that cached count
 * for first endpoint; missing match exits without repairing accounting.
 * Zero80-byte stack message, read pending type BYTE,timestamp WORD,length BYTE,
 * then generation WORD, and fill header endpoint/type HALF, length/accounted1;
 * bytes12..15 remain zero. Always memcpy stored length BYTE to payload+16,
 * including length0, without64-byte guard. Freshly read pending count AFTER
 * copy; memmove following records left by76 using wrapped32(fresh-index-1)*76.
 * Reload/decrement cached slot pending, read produced/ack, publish produced+1
 * modulo8, blocked=(low8(new-produced-ack)>1), then fresh-count-1 low8. Obsolete
 * queue tail bytes remain. Cached slot survives copies without validation.
 *
 * Unlock, sample forward queue and send stack message with wait0/back. Missing
 * queue or return!=1: fenced WORD drop increment and release accounting.
 * Relock and repeat fresh lookup; no global iteration/time bound. On exit
 * unlock, release freshly sampled outer mutex, then ALWAYS try USB rearm.
 * No copy bound, queue-count<=16, generation validation or rollback. Shrinking
 * count during copy can underflow move length; >64 stored length overflows the
 * message payload. Native faults/partial publication are not repaired here.
 */
void out_drain_pending(unsigned int endpoint)
{
    RtosQueue *mutex = DEVICE_OUT_OUTER_MUTEX;
    if (mutex != 0) (void)xQueueSemaphoreTake(mutex,0xffffffffU);
    (void)xPortEnterCriticalTimeout(DEVICE_OUT_LOCK,-1);
    if ((endpoint & 127U) != 0 && (endpoint & 128U) == 0) {
        for (;;) {
            unsigned int slot = 0;
            for (; slot < 10; ++slot)
                if (DEVICE_OUT_ENDPOINTS[slot].endpoint == endpoint) break;
            if (slot == 10) break;
            volatile DeviceOutEndpoint *state = &DEVICE_OUT_ENDPOINTS[slot];
            if (state->pending == 0) break;
            unsigned char blocked = state->blocked;
            unsigned int search_count = MEDIUS_DEVICE_OUT_PENDING_COUNT;
            if (blocked != 0) break;
            unsigned int index = 0;
            for (; index != search_count; ++index)
                if (MEDIUS_DEVICE_OUT_PENDING[index].endpoint == endpoint) break;
            if (index == search_count) break;
            MediusDeviceOutMessage message;
            memset(&message,0,80);
            volatile MediusDeviceOutPending *record = &MEDIUS_DEVICE_OUT_PENDING[index];
            unsigned char type = record->transfer_type;
            unsigned int stamp = record->stamp;
            unsigned char length = record->length;
            message.stamp = stamp;
            unsigned int generation = record->generation;
            message.endpoint_type = (unsigned short)(endpoint | (unsigned int)type << 8);
            message.generation = generation;
            message.length = length;
            message.accounted = 1;
            memcpy(message.payload,(const unsigned char *)record->payload,length);
            unsigned int fresh_count = MEDIUS_DEVICE_OUT_PENDING_COUNT;
            memmove((MediusDeviceOutPending *)record,
                (const MediusDeviceOutPending *)(record + 1),(fresh_count - index - 1U) * 76U);
            unsigned char pending = state->pending;
            state->pending = (unsigned char)(pending - 1U);
            unsigned char produced = state->produced;
            unsigned char acknowledged = state->acknowledged;
            unsigned char next = (unsigned char)(produced + 1U);
            state->produced = next;
            state->blocked = (unsigned char)(next - acknowledged) > 1;
            MEDIUS_DEVICE_OUT_PENDING_COUNT = (unsigned char)(fresh_count - 1U);
            vPortExitCritical(DEVICE_OUT_LOCK);
            RtosQueue *queue = DEVICE_OUT_FORWARD_QUEUE;
            if (queue == 0 || xQueueGenericSend(queue,&message,0,0) != 1) {
                memw(); unsigned int drops = DEVICE_OUT_DROPS;
                memw(); DEVICE_OUT_DROPS = drops + 1U;
                medius_out_release_accounting(endpoint);
            }
            (void)xPortEnterCriticalTimeout(DEVICE_OUT_LOCK,-1);
        }
    }
    vPortExitCritical(DEVICE_OUT_LOCK);
    mutex = DEVICE_OUT_OUTER_MUTEX;
    if (mutex != 0) (void)xQueueGenericSend(mutex,0,0,0);
    medius_out_try_rearm(endpoint);
}

/* Native entry: 0x40394ae4. */
/* Original function-byte SHA-256:
 * ba637846db33783ffe70ca035a5dfbee20bab9f9fc4581127e207b5e0c4a5090. */
/*
 * Ignore ISR-context query, enter OUT spinlock forever, reject low7 endpoint0
 * or low8 IN bit. First of ten24-byte records with FULL-WORD address equality
 * wins. Decrement completion_debt if nonzero. Cache acknowledged and blocked
 * BYTEs, publish ack+1 modulo256, and only for cached blocked!=0 read produced;
 * clear blocked when low8(produced-new_ack)<2. Query ISR context again before
 * unlocking. No queue pop, USB rearm, generation check or status result.
 */
void medius_out_release_accounting(unsigned int endpoint)
{
    (void)xPortInIsrContext();
    (void)xPortEnterCriticalTimeout(DEVICE_OUT_LOCK,-1);
    if ((endpoint & 127U) != 0 && (endpoint & 128U) == 0) {
        for (unsigned int slot = 0; slot < 10; ++slot) {
            volatile DeviceOutEndpoint *state = &DEVICE_OUT_ENDPOINTS[slot];
            if (state->endpoint != endpoint) continue;
            unsigned char debt = state->completion_debt;
            if (debt != 0) state->completion_debt = (unsigned char)(debt - 1U);
            unsigned char acknowledged = state->acknowledged;
            unsigned char blocked = state->blocked;
            unsigned char next_ack = (unsigned char)(acknowledged + 1U);
            state->acknowledged = next_ack;
            if (blocked != 0 && (unsigned char)(state->produced - next_ack) < 2)
                state->blocked = 0;
            break;
        }
    }
    (void)xPortInIsrContext();
    vPortExitCritical(DEVICE_OUT_LOCK);
}

/* Native entry: 0x40394bc4. */
/* Original function-byte SHA-256:
 * 1269559cee6ee93b6a4cb9b7d8c550e9a24b3c4770a314ec35b65d8ae6974231. */
/*
 * Ignore ISR-context query, enter OUT spinlock forever and require low7!=0/
 * low8 IN-clear. Find first exact FULL-WORD endpoint among ten records. Read
 * armed,blocked,pending BYTEs in that order and require each zero; set armed1
 * then cache MPS HALF. Query ISR context/unlock BEFORE bus0 read into endpoint
 * low4*64 buffer. Length is zero-MPS?64:min(MPS,64). Nonnegative driver result
 * returns directly. Negative result queries ISR context/relocks and scans a
 * fresh address table, clearing armed on the first match (no generation test).
 * Other exits query ISR context/unlock. No retry, extra queue reset or status.
 */
void medius_out_try_rearm(unsigned int endpoint)
{
    (void)xPortInIsrContext();
    (void)xPortEnterCriticalTimeout(DEVICE_OUT_LOCK,-1);
    if ((endpoint & 127U) == 0 || (endpoint & 128U) != 0) goto unlock;
    for (unsigned int slot = 0; slot < 10; ++slot) {
        volatile DeviceOutEndpoint *state = &DEVICE_OUT_ENDPOINTS[slot];
        if (state->endpoint != endpoint) continue;
        if (state->armed != 0 || state->blocked != 0 || state->pending != 0) goto unlock;
        state->armed = 1;
        unsigned int packet = state->max_packet;
        (void)xPortInIsrContext();
        vPortExitCritical(DEVICE_OUT_LOCK);
        unsigned int length = packet == 0 || packet > 64 ? 64 : packet;
        int result = usbd_ep_start_read(0,(unsigned char)endpoint,
            MEDIUS_DEVICE_OUT_READ_BUFFERS + (endpoint & 15U) * 64U,length);
        if (result >= 0) return;
        (void)xPortInIsrContext();
        (void)xPortEnterCriticalTimeout(DEVICE_OUT_LOCK,-1);
        for (unsigned int current = 0; current < 10; ++current) {
            if (DEVICE_OUT_ENDPOINTS[current].endpoint != endpoint) continue;
            DEVICE_OUT_ENDPOINTS[current].armed = 0;
            break;
        }
        goto unlock;
    }
unlock:
    (void)xPortInIsrContext();
    vPortExitCritical(DEVICE_OUT_LOCK);
}

/* Native entry: 0x40394e28. */
/* Original function-byte SHA-256:
 * abf8d6c56a36fd5f62ddebe376d4bcf9d55d206fb3df9c029b8acd5711bf0e82. */
/*
 * Clear pending BYTE in ALL ten endpoint slots, then snapshot pending count.
 * Nonzero full-WORD discard_all drops that many records without reading them,
 * incrementing WORD drops with fresh fenced read/store per record. Zero mode
 * scans cached count in order: read endpoint BYTE, reject low7==0/IN-bit, then
 * find first matching address among ten current slots. Missing/invalid drops.
 * Accept: increment current pending BYTE modulo256; if retained!=source index,
 * memcpy exactly76 bytes down into retained position; increment retained count.
 * Source/retained counters wrap8; final count overwrites global pending count.
 * No internal lock, count<=16 check, payload validation, tail clearing or USB
 * rearm. Callers must hold the OUT lock; source count remains cached through
 * copies while endpoint slots are freshly scanned. Copy mutations can affect
 * later records/slots, but do not change the number of source records visited.
 */
void medius_out_filter_pending(unsigned int discard_all)
{
    for (unsigned int slot = 0; slot < 10; ++slot)
        DEVICE_OUT_ENDPOINTS[slot].pending = 0;
    unsigned int count = MEDIUS_DEVICE_OUT_PENDING_COUNT;
    unsigned char retained = 0,source = 0;
    if (count != 0) {
        do {
            if (discard_all == 0) {
                volatile MediusDeviceOutPending *record = &MEDIUS_DEVICE_OUT_PENDING[source];
                unsigned char endpoint = record->endpoint;
                if ((endpoint & 127U) != 0 && (endpoint & 128U) == 0) {
                    unsigned int slot = 0;
                    for (; slot < 10; ++slot)
                        if (DEVICE_OUT_ENDPOINTS[slot].endpoint == endpoint) break;
                    if (slot != 10) {
                        unsigned char pending = DEVICE_OUT_ENDPOINTS[slot].pending;
                        DEVICE_OUT_ENDPOINTS[slot].pending = (unsigned char)(pending + 1U);
                        if (retained != source)
                            memcpy((MediusDeviceOutPending *)&MEDIUS_DEVICE_OUT_PENDING[retained],
                                (const MediusDeviceOutPending *)record,76);
                        retained = (unsigned char)(retained + 1U);
                        goto next_record;
                    }
                }
            }
            memw(); unsigned int drops = DEVICE_OUT_DROPS;
            memw(); DEVICE_OUT_DROPS = drops + 1U;
next_record:
            source = (unsigned char)(source + 1U);
        } while (source != count);
    }
    MEDIUS_DEVICE_OUT_PENDING_COUNT = retained;
}

/* Native entry: 0x4202a8ac. */
/* Original function-byte SHA-256:
 * 3d356468010cceaeae04efec4ed97fda82b070fc2bd500bf5e76e3daacc0c99f. */
/*
 * Query ISR context/enter OUT lock, ignoring results. Visit ALL ten slots:
 * sample address BYTE, scan positive signed input count for first equality,
 * even for address0; memset24 only for nonzero address absent from input.
 * Count<=0 thus removes nonzero slots without reading either input array.
 * For each positive-count input, addresses1..127 first search existing slots;
 * address0/IN skip that search. Otherwise allocate first zero-address slot:
 * memset24, REREAD current input endpoint BYTE and publish it, then read input
 * MPS HALF and store raw at+2. Existing slots update only MPS. Full allocation
 * silently skips input WITHOUT MPS read. Duplicate valid addresses reuse first
 * match; invalid/IN duplicates can allocate multiple slots; zero stays free.
 * Finally filter_pending(0) WHILE locked, query context/unlock. No count<=10,
 * MPS cap, pointer/alias checks, generation tag, rearm/wake or return status.
 */
void medius_out_reconcile_endpoints(const unsigned char *endpoints,
    const unsigned short *maximum_packet_sizes,int count)
{
    const volatile unsigned char *addresses = endpoints;
    const volatile unsigned short *packets = maximum_packet_sizes;
    (void)xPortInIsrContext();
    (void)xPortEnterCriticalTimeout(DEVICE_OUT_LOCK,-1);
    for (unsigned int slot = 0; slot < 10; ++slot) {
        volatile DeviceOutEndpoint *state = &DEVICE_OUT_ENDPOINTS[slot];
        unsigned char endpoint = state->endpoint;
        bool retained = false;
        for (int input = 0; input < count; ++input) {
            if (addresses[input] != endpoint) continue;
            retained = true;
            break;
        }
        if (endpoint != 0 && !retained) memset((DeviceOutEndpoint *)state,0,24);
    }
    for (int input = 0; input < count; ++input) {
        unsigned char endpoint = addresses[input];
        unsigned int selected = 10;
        if ((endpoint & 127U) != 0 && (endpoint & 128U) == 0) {
            for (unsigned int slot = 0; slot < 10; ++slot) {
                if (DEVICE_OUT_ENDPOINTS[slot].endpoint != endpoint) continue;
                selected = slot;
                break;
            }
        }
        if (selected == 10) {
            for (unsigned int slot = 0; slot < 10; ++slot) {
                if (DEVICE_OUT_ENDPOINTS[slot].endpoint != 0) continue;
                selected = slot;
                memset((DeviceOutEndpoint *)&DEVICE_OUT_ENDPOINTS[slot],0,24);
                DEVICE_OUT_ENDPOINTS[slot].endpoint = addresses[input];
                break;
            }
        }
        if (selected != 10) DEVICE_OUT_ENDPOINTS[selected].max_packet = packets[input];
    }
    medius_out_filter_pending(0);
    (void)xPortInIsrContext();
    vPortExitCritical(DEVICE_OUT_LOCK);
}

/* Native entry: 0x4202c2d4. */
/* Original function-byte SHA-256:
 * d083491cb0e32da50165cd37db44a23eafe40e515471bd1b96bf5f0c5fa29975. */
/*
 * Completed OUT packet: sample forwarding queue first; absent or actual>64
 * queries context/locks, clears armed for first matching valid nonzero OUT
 * address, queries context/unlocks and tries rearm. No clock/copy/drop count.
 *
 * Otherwise zero80-byte message, sample clock LOW, MEMW/load generation WORD,
 * store low16(endpoint | transfer_type<<8), length BYTE and event-kind low8 at
 * message+12. accounted(+11) stays0. Always copy actual bytes from low4 endpoint
 *64 receive buffer, even length0. Context/lock, clear matching valid slot armed,
 * sample produced/ack, publish produced+1 modulo256 and blocked=(delta>1), then
 * context/unlock. Invalid/unknown endpoint still goes to queue, without slot
 * accounting. Send from ISR to a FRESH queue handle, back, with local woken0.
 * Return!=1 increments fenced WORD drops, captures raw event using FULL32
 * event-kind/low4 endpoint/direction2/empty-flag2/timeLOW/synthetic1, then releases
 * accounting. Nonzero woken yields even on failure. Every path tries rearm.
 * No NULL recheck before ISR send, allocation, retry, status return or generation
 * validation; stack80 must match configured queue item size. Capture/drop does
 * not prove physical forwarding. Actual is bounded64 before any payload copy.
 */
void medius_out_complete_enqueue(unsigned int endpoint,unsigned int actual,
    unsigned short transfer_type,unsigned int event_kind)
{
    RtosQueue *queue = DEVICE_OUT_FORWARD_QUEUE;
    if (queue == 0 || actual > 64) {
        (void)xPortInIsrContext();
        (void)xPortEnterCriticalTimeout(DEVICE_OUT_LOCK,-1);
        if ((endpoint & 127U) != 0 && (endpoint & 128U) == 0) {
            for (unsigned int slot = 0; slot < 10; ++slot) {
                if (DEVICE_OUT_ENDPOINTS[slot].endpoint != endpoint) continue;
                DEVICE_OUT_ENDPOINTS[slot].armed = 0;
                break;
            }
        }
        (void)xPortInIsrContext();
        vPortExitCritical(DEVICE_OUT_LOCK);
        medius_out_try_rearm(endpoint);
        return;
    }
    MediusDeviceOutMessage message;
    memset(&message,0,80);
    unsigned int stamp = (unsigned int)esp_timer_get_time();
    memw(); unsigned int generation = DEVICE_OUT_GENERATION;
    message.stamp = stamp;
    message.generation = generation;
    message.endpoint_type = (unsigned short)(endpoint | (unsigned int)transfer_type << 8);
    message.length = (unsigned char)actual;
    message.event_kind = (unsigned char)event_kind;
    unsigned char *buffer = MEDIUS_DEVICE_OUT_READ_BUFFERS + (endpoint & 15U) * 64U;
    memcpy(message.payload,buffer,actual);
    (void)xPortInIsrContext();
    (void)xPortEnterCriticalTimeout(DEVICE_OUT_LOCK,-1);
    if ((endpoint & 127U) != 0 && (endpoint & 128U) == 0) {
        for (unsigned int slot = 0; slot < 10; ++slot) {
            volatile DeviceOutEndpoint *state = &DEVICE_OUT_ENDPOINTS[slot];
            if (state->endpoint != endpoint) continue;
            state->armed = 0;
            unsigned char produced = state->produced;
            unsigned char acknowledged = state->acknowledged;
            unsigned char next = (unsigned char)(produced + 1U);
            state->produced = next;
            state->blocked = (unsigned char)(next - acknowledged) > 1;
            break;
        }
    }
    (void)xPortInIsrContext();
    vPortExitCritical(DEVICE_OUT_LOCK);
    int woken = 0;
    queue = DEVICE_OUT_FORWARD_QUEUE;
    if (xQueueGenericSendFromISR(queue,&message,&woken,0) != 1) {
        memw(); unsigned int drops = DEVICE_OUT_DROPS;
        memw(); DEVICE_OUT_DROPS = drops + 1U;
        capture_emit_raw(event_kind,endpoint & 15U,2,actual == 0 ? 2 : 0,
            message.stamp,1,buffer,actual);
        medius_out_release_accounting(endpoint);
    }
    if (woken != 0) _frxt_setup_switch();
    medius_out_try_rearm(endpoint);
}

/* Native entry: 0x40394b60. */
/* Original function-byte SHA-256:
 * dd899b5e26c7ca4f50fed6e6089ba463be7faaed1a1fb044ac87e364b71ccee1. */
/*
 * Rebase OUT sequence accounting under its spinlock, ignoring ISR-context and
 * entry statuses. For each of ten NONZERO-address slots, read sent_sequence8,
 * acknowledged7,rebase_sequence9,produced6 BYTEs in that order. Compute sum=
 * low8(sent+ack), publish ack=low8(sum-old_rebase), rebase=sampled sent and
 * blocked=(low8(old_rebase+produced-sum)>1). Then clear reset flags13/14,
 * completion debt11 and armed4, in that order. Zero-address slots are untouched.
 * Query context/unlock. Retains pending count, MPS, payloads and other bytes;
 * no queue filtering, rearm, generation test, status result or delivery claim.
 */
void medius_out_rebase_accounting(void)
{
    (void)xPortInIsrContext();
    (void)xPortEnterCriticalTimeout(DEVICE_OUT_LOCK,-1);
    for (unsigned int slot = 0; slot < 10; ++slot) {
        volatile DeviceOutEndpoint *state = &DEVICE_OUT_ENDPOINTS[slot];
        if (state->endpoint == 0) continue;
        unsigned char sent = state->sent_sequence;
        unsigned char acknowledged = state->acknowledged;
        unsigned char previous = state->rebase_sequence;
        unsigned char produced = state->produced;
        unsigned char sum = (unsigned char)(sent + acknowledged);
        state->acknowledged = (unsigned char)(sum - previous);
        state->rebase_sequence = sent;
        state->blocked = (unsigned char)(previous + produced - sum) > 1;
        state->reset_flag13 = 0;
        state->reset_flag14 = 0;
        state->completion_debt = 0;
        state->armed = 0;
    }
    (void)xPortInIsrContext();
    vPortExitCritical(DEVICE_OUT_LOCK);
}

/* Native entry: 0x40394ef8. */
/* Original function-byte SHA-256:
 * ba6a58e6d83aab301fc1edb5138c2c61a20d6597d021e8fe3d3fd1b01e49b7d9. */
/*
 * Admit an ordered control record to the device OUT-forward queue. Set busy1,
 * fence/sample quiescing, require quiescing0 and a nonnull initial queue. Zero
 * the80-byte record; store clock LOW, supplied generation and control_type at
 * byte14. Copy FULL length bytes into its64-byte payload, including length0.
 * With sequence!=UINT_MAX, append low8 sequence at payload[length], then store
 * low8(length+1); otherwise store low8 length. No payload/length validation:
 * oversized inputs overwrite the native stack record and length can wrap.
 *
 * Increment the active-control WORD atomically, then send to a freshly sampled
 * queue with20 ticks/back. Exact status1 returns1, leaving decrement to worker.
 * Failure decrements active-control and increments the non-atomic drop WORD;
 * rejection before admission changes neither. On any unsuccessful result with
 * a sequence, enter sequence lock forever, inspect entry[sequence&15].sequence
 * BYTE and clear its time LOW WORD only if it equals low8 sequence. Unlock.
 * Every exit fences and clears busy0. Does not wait for transport delivery or
 * undo a successful enqueue; busy is a shared BYTE, not an ownership count.
 */
unsigned int medius_out_enqueue_control_message(unsigned char control_type,
    const void *payload,unsigned int length,unsigned int generation,unsigned int sequence)
{
    unsigned int admitted = 0;
    memw(); MEDIUS_CONTROL_ENQUEUE_BUSY = 1;
    memw();
    if (CLONE_QUIESCING == 0 && DEVICE_OUT_FORWARD_QUEUE != 0) {
        MediusDeviceOutMessage message;
        memset(&message,0,sizeof(message));
        message.stamp = (unsigned int)esp_timer_get_time();
        message.generation = generation;
        message.control_type = control_type;
        memcpy(message.payload,payload,length);
        if (sequence != 0xffffffffU) {
            message.payload[length] = (unsigned char)sequence;
            message.length = (unsigned char)(length + 1U);
        } else message.length = (unsigned char)length;
        (void)atomic_fetch_add_u32(&CONTROL_OPERATION_ACTIVE,1,3);
        if (xQueueGenericSend(DEVICE_OUT_FORWARD_QUEUE,&message,20,0) == 1)
            admitted = 1;
        else {
            (void)atomic_fetch_sub_u32(&CONTROL_OPERATION_ACTIVE,1,3);
            memw(); unsigned int drops = DEVICE_OUT_DROPS + 1U;
            memw(); DEVICE_OUT_DROPS = drops;
        }
    }
    if (admitted == 0 && sequence != 0xffffffffU) {
        (void)xPortEnterCriticalTimeout(&REPORT_SEQUENCE_LOCK,-1);
        volatile ReportSequenceEntry *entry =
            &REPORT_SEQUENCE_WINDOW.entries[sequence & 15U];
        if (entry->sequence == (unsigned char)sequence) entry->time_low = 0;
        vPortExitCritical(&REPORT_SEQUENCE_LOCK);
    }
    memw(); MEDIUS_CONTROL_ENQUEUE_BUSY = 0;
    return admitted;
}
