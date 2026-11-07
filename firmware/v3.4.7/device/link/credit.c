/* Medius v3.4.7 device: recovered link credit accounting.
 * Native addresses and firmware-byte hashes are retained for each function.
 */

#include "../include/types.h"

/* Native entry: 0x40377364. */
/* Original function-byte SHA-256:
 * 518fb1acc3c10623ebb0676cef3ef9f5e64c3d4753a0962750d8fa7d7cf6e429. */

/*
 * endpoint: full32-bit endpoint value. Returns an unchanged input when either
 * registered list contains an exact match, otherwise possibly a mapped IN byte.
 * Caches the signed primary count once, scans its whole byte list, then scans
 * the secondary eight-byte bindings if their signed count is positive.
 * Only an unmatched input with bit7 set reads the signed low-nibble map, after
 * MEMW. A nonnegative mapped index below the CACHED primary count selects a
 * primary endpoint; zero mapped endpoint preserves the original input.
 * No endpoint narrowing, allocation, lock, table-length or pointer validation.
 * Requires valid configured table lengths and serialized updates. Searches do
 * not reread the primary count for the final mapping bound.
 */
unsigned int endpoint_canonicalize(unsigned int endpoint)
{
    int primary_count = CREDIT_INTERFACES.count;
    for (int interface_index = 0; interface_index < primary_count; ++interface_index) {
        const volatile unsigned char *configured_endpoint =
            (const volatile unsigned char *)((unsigned int)&CREDIT_INTERFACES +
                                            (unsigned int)interface_index);
        if (*configured_endpoint == endpoint)
            return endpoint;
    }
    int secondary_count = CREDIT_BINDINGS.count;
    for (int binding_index = 0; binding_index < secondary_count; ++binding_index) {
        const volatile CreditBinding *binding =
            (const volatile CreditBinding *)((unsigned int)&CREDIT_BINDINGS +
                                              (unsigned int)binding_index * 8U);
        if (binding->endpoint == endpoint)
            return endpoint;
    }
    if ((endpoint & 0x80U) != 0) {
        memw();
        int mapped = CREDIT_ENDPOINT_INTERFACE[endpoint & 15U];
        if (mapped >= 0 && mapped < primary_count) {
            unsigned int canonical = *(const volatile unsigned char *)
                ((unsigned int)&CREDIT_INTERFACES + (unsigned int)mapped);
            if (canonical != 0)
                endpoint = canonical;
        }
    }
    return endpoint;
}

/* Native entry: 0x40378528. */
/* Original function-byte SHA-256:
 * 325299c13b83c47ab1268d2adb68db511a8e9cdb0cffe58fb6edf858d241dcde. */

/*
 * endpoint: full32-bit endpoint address; state is indexed by its low nibble.
 * now_us: caller's64-bit timestamp. Native alignment leaves A3 unused; LOW/HIGH
 * arrive in A4/A5, not in a fabricated second pointer argument.
 * Returns the calculated unsigned load, saturated at255.
 *
 * Caches this endpoint's LOW then HIGH timestamp BEFORE canonicalization.
 * Recent means signed64-bit wrapping age<20000us; negative ages also pass.
 * First matching primary interface takes precedence. Sum its own recent byte
 * observation and recent nonzero observations of other endpoints1..15 whose
 * signed mapping equals that interface. Each other mapping read is fenced.
 * Add one per zero-marker84-byte interface record, using its initial count;
 * record-base indexing narrows the interface to16 bits, unlike the count read.
 * extra_pending adds one only when that interface's extra-held byte is zero.
 *
 * Otherwise, first exact ORIGINAL endpoint match in the secondary bindings
 * selects a slot only if slot<6. Kind2 ignores observation age and counts every
 * queued record. Other kinds use recent observations and count only nonzero
 * markers in66-byte records. Non-kind2 head is freshly fenced/read on EVERY
 * iteration; physical index=(head+byte ordinal)&7. Both paths re-read queue
 * count after every iteration, with a fenced byte read; this is not a snapshot.
 * In-flight work adds one for kind2 or its byte weight for other kinds.
 * Kind2 plus in-flight takes a special exit: it still fences/reads the global
 * deduction byte, but ignores its value. Common exit deducts one only when
 * deduction is enabled, load!=0 and the binding was not kind2.
 *
 * Missing/invalid secondary binding falls back to this endpoint's recent
 * observation, then common deduction. No local lock, software timer, counter
 * reset, array-bound repair or stable concurrent snapshot. Caller must provide
 * initialized, accessible configured tables/queues and coordinate mutation;
 * unchecked counts can walk beyond nominal arrays. Byte ordinal wraps if
 * concurrent count changes prevent termination. MEMW is retained at native
 * reads, without a hardware timing/coherence claim.
 */
unsigned int credit_endpoint_load(unsigned int endpoint,
                                          unsigned long long now_us)
{
    unsigned int number = endpoint & 15U;
    unsigned int now_low = (unsigned int)now_us;
    unsigned int now_high = (unsigned int)(now_us >> 32);
    unsigned int previous_low = CREDIT_STATE.last_rx[number].low;
    unsigned int previous_high = CREDIT_STATE.last_rx[number].high;
    int age_high = (int)(now_high - previous_high - (now_low < previous_low));
    unsigned int canonical = endpoint_canonicalize(endpoint);
    unsigned int age_low = now_low - previous_low;
    int recent = age_high < 0 || (age_high == 0 && age_low < 20000U);
    unsigned int load;
    int count_all_records = 0;

    int interface_count = CREDIT_INTERFACES.count;
    for (int interface = 0; interface < interface_count; ++interface) {
        const volatile unsigned char *configured_endpoint =
            (const volatile unsigned char *)((unsigned int)&CREDIT_INTERFACES +
                                            (unsigned int)interface);
        if (*configured_endpoint != canonical)
            continue;
        load = recent ? CREDIT_STATE.load_observations[number] : 0;
        for (unsigned int other = 1; other < 16; ++other) {
            if (other == number)
                continue;
            memw();
            if (CREDIT_ENDPOINT_INTERFACE[other] != interface)
                continue;
            unsigned int observed = CREDIT_STATE.load_observations[other];
            if (observed == 0)
                continue;
            unsigned int low = CREDIT_STATE.last_rx[other].low;
            unsigned int high = CREDIT_STATE.last_rx[other].high;
            int high_difference = (int)(now_high - high - (now_low < low));
            unsigned int low_difference = now_low - low;
            if (high_difference < 0 ||
                (high_difference == 0 && low_difference < 20000U))
                load += observed;
        }
        const volatile CreditInterfaceQueue *queue =
            (const volatile CreditInterfaceQueue *)
                ((unsigned int)CREDIT_INTERFACE_QUEUES + (unsigned int)interface * 960U);
        unsigned int record_count = queue->record_count;
        const volatile CreditInterfaceQueue *record_base =
            (const volatile CreditInterfaceQueue *)
                ((unsigned int)CREDIT_INTERFACE_QUEUES +
                 (unsigned int)(unsigned short)interface * 960U);
        for (unsigned int record = 0; record < record_count; ++record) {
            const volatile CreditInterfaceRecord *entry =
                (const volatile CreditInterfaceRecord *)
                ((unsigned int)record_base + record * 84U);
            load += entry->credit_marker == 0;
        }
        if (queue->extra_pending != 0)
            load += CREDIT_INTERFACE_EXTRA_HELD[interface] == 0;
        goto common_deduction;
    }

    int binding_count = CREDIT_BINDINGS.count;
    for (int binding = 0; binding < binding_count; ++binding) {
        const volatile CreditBinding *entry =
            (const volatile CreditBinding *)((unsigned int)&CREDIT_BINDINGS +
                                              (unsigned int)binding * 8U);
        if (entry->endpoint != endpoint)
            continue;
        unsigned int slot = entry->queue_slot;
        if (slot >= 6)
            break;
        count_all_records = entry->kind == 2;
        memw();
        unsigned int initially_queued = CREDIT_SECONDARY_COUNTS[slot];
        load = (count_all_records || recent) ?
            CREDIT_STATE.load_observations[number] : 0;
        if (initially_queued != 0) {
            unsigned char ordinal = 0;
            for (;;) {
                unsigned char next = (unsigned char)(ordinal + 1U);
                unsigned int include;
                if (count_all_records) {
                    include = 1;
                } else {
                    memw();
                    unsigned int head = CREDIT_SECONDARY_HEADS[slot];
                    unsigned int physical = (head + ordinal) & 7U;
                    include = CREDIT_SECONDARY_QUEUES[slot]
                                  .records[physical].credit_marker != 0;
                }
                memw();
                unsigned int current_count = CREDIT_SECONDARY_COUNTS[slot];
                ordinal = next;
                load += include;
                if (ordinal >= current_count)
                    break;
            }
        }
        memw();
        if (CREDIT_SECONDARY_IN_FLIGHT[slot] != 0) {
            if (count_all_records) {
                ++load;
                memw();
                (void)USB_SUSPENDED;
                goto saturated_result;
            }
            load += CREDIT_SECONDARY_IN_FLIGHT_WEIGHT[slot];
        }
        goto common_deduction;
    }
    load = recent ? CREDIT_STATE.load_observations[number] : 0;
common_deduction:
    memw();
    if (USB_SUSPENDED != 0 && load != 0 && !count_all_records)
        --load;
saturated_result:
    return load < 255 ? load : 255;
}

/* Native entry: 0x4037880c. */
/* Original function-byte SHA-256:
 * 1fa8e469745f2e568ca72114ed5e4bd3e40daa6daf5243961e839dfb4c8d63e6. */

/*
 * type_out: writable byte, always set to0x40 before any locking or capacity test.
 * payload_out: writable packet storage; at least its header byte is required
 * even when low16(capacity)==0. capacity: only low16 is used; TX supplies64.
 * Returns packet length1..61 if dirty state, a changed sequence-minus-load, or
 * emitted nonzero flags demand transmission; otherwise returns0. Writes the
 * packet/header and updates state even when returning0.
 *
 * Exchanges the dirty byte to0 with order4 before entering the credit lock;
 * cached nonzero result initializes changed=true. Samples one64-bit timestamp
 * under lock for all load calculations. For endpoints1..15, first checks room
 * for an entire four-byte record, then freshly tests the tracked mask. Each
 * tracked endpoint emits endpoint|0x80, freshly reloaded sequence, low8 load,
 * flags. Sequence-minus-load uses a sequence read before the cache comparison;
 * the sequence stored into the packet is read again afterward. A changed cache
 * is updated; nonzero emitted flags are cleared and force a nonzero result.
 * Unlocks BEFORE writing record_count and deciding the returned length.
 *
 * Does not clear unused output bytes, validate pointers, hold the dirty exchange
 * inside the credit lock, requeue cleared dirty/flags on TX failure, or guarantee
 * delivery. Partial-capacity output visits endpoints in numeric order and can
 * leave later flags unconsumed. Callbacks/lock/load helper must return; shared
 * state must be initialized and output must not overlap it. No physical timing
 * or concurrent snapshot guarantee follows from this source.
 */
unsigned int credit_build_packet(unsigned char *type_out,
    unsigned char *payload_out, unsigned int capacity)
{
    *type_out = 0x40;
    unsigned int changed = atomic_exchange_byte(CREDIT_DIRTY, 0, 4) != 0;
    xPortEnterCriticalTimeout(&CREDIT_LOCK, 0xffffffffU);
    unsigned long long now_us = (unsigned long long)esp_timer_get_time();
    unsigned int used = 1;
    capacity &= 0xffffU;
    volatile CreditPacket *packet = (volatile CreditPacket *)payload_out;
    for (unsigned int number = 1; number < 16; ++number) {
        if (used + 3U >= capacity)
            break;
        if ((CREDIT_STATE.tracked_endpoints & (1U << number)) == 0)
            continue;
        unsigned char endpoint = (unsigned char)(number | 0x80U);
        unsigned char load = (unsigned char)credit_endpoint_load(endpoint, now_us);
        unsigned char sequence_minus_load = (unsigned char)
            (CREDIT_STATE.sequence[number] - load);
        if (CREDIT_STATE.last_sequence_minus_load[number] != sequence_minus_load) {
            CREDIT_STATE.last_sequence_minus_load[number] = sequence_minus_load;
            changed = 1;
        }
        volatile CreditRecord *record = &packet->records[(used - 1U) / 4U];
        record->endpoint = endpoint;
        unsigned char sequence = CREDIT_STATE.sequence[number];
        record->load = load;
        record->sequence = sequence;
        unsigned char flags = CREDIT_STATE.pending_flags[number];
        used = (used + 4U) & 0xffffU;
        record->flags = flags;
        if (flags != 0) {
            CREDIT_STATE.pending_flags[number] = 0;
            changed = flags;
        }
    }
    vPortExitCritical(&CREDIT_LOCK);
    packet->record_count = (unsigned char)((used - 1U) / 4U);
    return changed != 0 ? used : 0;
}

/* Native entry: 0x4202c88c. */
/* Original function-byte SHA-256:
 * d73d7fe439421d8bac28442ad7b5767f2a5d1602d1960f5a2adf468c083aa8e2. */

/*
 * now_us: caller's64-bit clock sample, incoming A2/A3. Returns1 if any tracked
 * endpoint1..15 has cached sequence-minus-load different from its current value,
 * otherwise0. Snapshots the tracked mask ONCE, then reads sequence before each
 * load-helper call and reads the comparison cache AFTER that call. The cached
 * pre-call sequence is used even if shared state changes inside the helper.
 * No clock read, lock, dirty/flag test, cache write, notification or allocation.
 * Requires initialized shared state and external serialization for a coherent
 * observation; zero does not prove no dirty packet/flags need transmission.
 */
int credit_state_changed(unsigned long long now_us)
{
    unsigned int tracked = CREDIT_STATE.tracked_endpoints;
    for (unsigned int number = 1; number < 16; ++number) {
        if ((tracked & (1U << number)) == 0)
            continue;
        unsigned char sequence = CREDIT_STATE.sequence[number];
        unsigned char load = (unsigned char)
            credit_endpoint_load(number | 0x80U, now_us);
        unsigned char previous = CREDIT_STATE.last_sequence_minus_load[number];
        if (previous != (unsigned char)(sequence - load))
            return 1;
    }
    return 0;
}
