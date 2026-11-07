/* Medius v3.4.7 device: recovered link/report_rx.c.
 * Native entry addresses and firmware-byte hashes are retained.
 */

#include "../include/types.h"

/* Native entry: 0x403773bc. */
/* Original function-byte SHA-256:
 * 104d52e6501e460b58a8c7f8b17b883a36c1617a51914cd77425ecdabf4806a4. */

/*
 * endpoint: full32-bit address, canonicalized before the primary search.
 * Returns first matching interface index, or -1 when absent/blocked.
 * Tests, in order: fenced per-interface block byte; active blocking selector0;
 * the interface's +0xda and +0x11e bytes; blocking selectors1 and2; then every
 * configured 0x388-byte block-list entry. Only the first byte check is fenced.
 * Signed nonpositive list counts skip searches. No locks, mutations, wakes or
 * count/pointer validation; caller supplies accessible, stable configured lists.
 */
int report_find_fast_interface(unsigned int endpoint)
{
    unsigned int canonical = endpoint_canonicalize(endpoint);
    int interface_count = CREDIT_INTERFACES.count;
    for (int interface_index = 0; interface_index < interface_count; ++interface_index) {
        unsigned int endpoint_address = (unsigned int)CREDIT_INTERFACES.endpoint +
            (unsigned int)interface_index;
        if (*(const volatile unsigned char *)endpoint_address != canonical)
            continue;
        memw();
        if (REPORT_INTERFACE_BLOCKED[interface_index] != 0)
            return -1;
        if (REPORT_BLOCK0_ACTIVE != 0 &&
            REPORT_BLOCK0_INTERFACE == interface_index)
            return -1;
        const volatile ReportInterfaceMode *interface_mode =
            (const volatile ReportInterfaceMode *)((unsigned int)REPORT_INTERFACE_MODES +
                (unsigned int)interface_index * 304U);
        if (interface_mode->block_da != 0)
            return -1;
        if (interface_mode->block_11e != 0)
            return -1;
        if (REPORT_BLOCK1_INTERFACE == interface_index ||
            REPORT_BLOCK2_INTERFACE == interface_index)
            return -1;
        int blocked_count = REPORT_BLOCK_LIST_COUNT;
        for (int blocked_index = 0; blocked_index < blocked_count; ++blocked_index) {
            const volatile ReportBlockListEntry *blocked_entry =
                (const volatile ReportBlockListEntry *)((unsigned int)REPORT_BLOCK_LIST +
                    (unsigned int)blocked_index * 904U);
            if (blocked_entry->interface == interface_index)
                return -1;
        }
        return interface_index;
    }
    return -1;
}

/* Native entry: 0x4037744c. */
/* Original function-byte SHA-256:
 * c19c6fdde6183571b150bd20f2feda647829188a07a262d5df1d65870bd8b4c6. */

/*
 * payload: readable report header; length: full word, must be>=6 to read byte5.
 * Returns0 on rejection, otherwise raw final gate byte XOR1, not a normalized
 * Boolean. Values2..255 in that byte therefore return nonzero. No mutations.
 * Rejects header bit2, then performs six ordered, short-circuit fenced reads:
 * global block, enabled byte, deduction byte, block97, block98, final gate96.
 * No USB-configuration, endpoint-routing or other strong-path checks here.
 * Pointer/table state must be valid; no lock or coherent gate snapshot.
 */
unsigned int report_fast_fallback_allowed(const unsigned char *payload,
                                                 unsigned int length)
{
    if (length < 6 || (payload[5] & 4U) != 0)
        return 0;
    memw();
    if (REPORT_FAST_GLOBAL_BLOCK != 0)
        return 0;
    memw();
    if (REPORT_FAST_ENABLED == 0)
        return 0;
    memw();
    if (USB_SUSPENDED != 0)
        return 0;
    memw();
    if (REPORT_FAST_BLOCK97 != 0)
        return 0;
    memw();
    if (REPORT_FAST_BLOCK98 != 0)
        return 0;
    memw();
    return REPORT_FAST_GATE96 ^ 1U;
}

/* Native entry: 0x403774bc. */
/* Original function-byte SHA-256:
 * b280de951b4df5b125fc8bab411e8e45d8e87876f2bf1f841e71f4e5c9f1872c. */

/*
 * sequence: low byte stored as received sequence. payload: borrowed header;
 * reads byte5 unconditionally, so six accessible bytes are required regardless
 * of length. length: full word. count_pending: nonzero increments pending count.
 * Returns no value; caller supplies the shared credit lock/serialization.
 *
 * Samples byte32 only when initial header bit0 is set AND length>=32; otherwise
 * samples byte6. The selected byte is read only when offset<length, else sample0.
 * Canonicalizes the initial endpoint, samples one64-bit clock, then REREADS the
 * raw endpoint. Writes raw sequence before publishing its tracked-mask bit;
 * a distinct nonzero first-canonical nibble gets sequence then mask as well.
 * Canonicalizes the cached raw endpoint AGAIN. First matching primary interface
 * propagates sequence to all signed-mapped endpoints1..15, each mapping fenced.
 * Those propagated endpoints do not gain tracked bits here.
 *
 * Saturates the raw endpoint's load byte at255, stores clock LOW then HIGH, and
 * optionally saturates its pending byte. Rereads header byte5 after these stores.
 * If bit2 is clear, searches using FIRST canonical value and CACHED primary count.
 * History uses THREE separately fenced reads of history_write_count: first&3
 * chooses timestamp slot, second&3 sample slot, third+1 is the published counter.
 * Stores selected LOW/HIGH, sample byte, latest LOW/HIGH, fences and publishes
 * the cached third counter+1 modulo32. No attempt makes these three reads atomic.
 * Selected sample bytes must be accessible when their offset is below length.
 * No allocation, notification, report copy, bounds validation or timeout. Tables,
 * payload and shared structures must be live; callbacks/time reads may expose
 * changes between the explicitly cached and fresh observations.
 */
void report_track_rx(unsigned int sequence, const unsigned char *payload,
                            unsigned int length, int count_pending)
{
    const volatile unsigned char *frame = payload;
    unsigned int sample_offset = (frame[5] & 1U) != 0 && length >= 32 ? 32 : 6;
    unsigned char sample = sample_offset < length ? frame[sample_offset] : 0;
    unsigned int first_canonical = endpoint_canonicalize(frame[0]);
    unsigned long long now = (unsigned long long)esp_timer_get_time();
    unsigned int endpoint = frame[0];
    unsigned int endpoint_number = endpoint & 15U;
    unsigned int tracked = CREDIT_STATE.tracked_endpoints;
    unsigned int alias_endpoint_number = first_canonical & 15U;
    CREDIT_STATE.sequence[endpoint_number] = (unsigned char)sequence;
    tracked |= 1U << endpoint_number;
    CREDIT_STATE.tracked_endpoints = (unsigned short)tracked;
    if (alias_endpoint_number != 0 && alias_endpoint_number != endpoint_number) {
        CREDIT_STATE.sequence[alias_endpoint_number] = (unsigned char)sequence;
        tracked |= 1U << alias_endpoint_number;
        CREDIT_STATE.tracked_endpoints = (unsigned short)tracked;
    }
    unsigned int second_canonical = endpoint_canonicalize(endpoint);
    int interface_count = CREDIT_INTERFACES.count;
    for (int interface_index = 0; interface_index < interface_count; ++interface_index) {
        unsigned int endpoint_address = (unsigned int)CREDIT_INTERFACES.endpoint +
            (unsigned int)interface_index;
        if (*(const volatile unsigned char *)endpoint_address != second_canonical)
            continue;
        for (unsigned int other_endpoint = 1; other_endpoint < 16; ++other_endpoint) {
            memw();
            if (CREDIT_ENDPOINT_INTERFACE[other_endpoint] == interface_index)
                CREDIT_STATE.sequence[other_endpoint] = (unsigned char)sequence;
        }
        break;
    }
    unsigned char observed = CREDIT_STATE.load_observations[endpoint_number];
    if (observed != 255)
        CREDIT_STATE.load_observations[endpoint_number] = observed + 1U;
    CREDIT_STATE.last_rx[endpoint_number].low = (unsigned int)now;
    CREDIT_STATE.last_rx[endpoint_number].high = (unsigned int)(now >> 32);
    if (count_pending != 0) {
        unsigned char pending = REPORT_PENDING[endpoint_number];
        if (pending != 255)
            REPORT_PENDING[endpoint_number] = pending + 1U;
    }
    if ((frame[5] & 4U) != 0)
        return;
    for (int interface_index = 0; interface_index < interface_count; ++interface_index) {
        unsigned int endpoint_address = (unsigned int)CREDIT_INTERFACES.endpoint +
            (unsigned int)interface_index;
        if (*(const volatile unsigned char *)endpoint_address != first_canonical)
            continue;
        volatile CreditInterfaceQueue *queue = (volatile CreditInterfaceQueue *)(
            (unsigned int)REPORT_HISTORY_QUEUES + (unsigned int)interface_index * 960U);
        memw();
        unsigned int timestamp_selector = queue->history_write_count;
        memw();
        unsigned int sample_selector = queue->history_write_count;
        memw();
        unsigned int increment_snapshot = queue->history_write_count;
        queue->history_time[timestamp_selector & 3U].low = (unsigned int)now;
        queue->history_time[timestamp_selector & 3U].high = (unsigned int)(now >> 32);
        queue->history_sample[sample_selector & 3U] = sample;
        queue->latest_time.low = (unsigned int)now;
        queue->latest_time.high = (unsigned int)(now >> 32);
        memw();
        queue->history_write_count = increment_snapshot + 1U;
        return;
    }
}

/* Native entry: 0x40377718. */
/* Original function-byte SHA-256:
 * 5a72d8ffac3ec64abbad515db15b2400ba7d64fc93a9e4d4612db0e1a7f4eeba. */

/*
 * type,flags: low bytes used; length narrows to16 bits; payload borrowed.
 * Returns no value. Enters credit lock before routing. Type0x10 calls track_rx
 * with count_pending=1. EVERY other type follows the alternate format, locally
 * without a length/type check: reads endpoint byte0 and sequence byte5, then
 * publishes tracked bit, sequence, saturating load increment and current clock
 * LOW/HIGH before unlock. The load byte is cached before tracked/sequence stores.
 * Normal publisher calls only for type0x10 length>=6 or0x1c length>=8; standalone
 * callers must satisfy payload access themselves. Does not enqueue, notify or
 * reset flags. Lock result ignored; no physical concurrency/timing guarantee.
 */
void report_receive_observer(unsigned int type, unsigned int flags,
    const unsigned char *payload, unsigned int length)
{
    type &= 255U; flags &= 255U; length &= 65535U;
    xPortEnterCriticalTimeout(&CREDIT_LOCK, 0xffffffffU);
    if (type == 0x10) {
        report_track_rx(flags, payload, length, 1);
    } else {
        const volatile unsigned char *frame = payload;
        unsigned int endpoint_number = frame[0] & 15U;
        unsigned int tracked = CREDIT_STATE.tracked_endpoints;
        unsigned char sequence = frame[5];
        unsigned char observed_load = CREDIT_STATE.load_observations[endpoint_number];
        CREDIT_STATE.tracked_endpoints = (unsigned short)(tracked | (1U << endpoint_number));
        CREDIT_STATE.sequence[endpoint_number] = sequence;
        if (observed_load != 255)
            CREDIT_STATE.load_observations[endpoint_number] = observed_load + 1U;
        unsigned long long now = (unsigned long long)esp_timer_get_time();
        CREDIT_STATE.last_rx[endpoint_number].low = (unsigned int)now;
        CREDIT_STATE.last_rx[endpoint_number].high = (unsigned int)(now >> 32);
    }
    vPortExitCritical(&CREDIT_LOCK);
}

/* Native entry: 0x40377854. */
/* Original function-byte SHA-256:
 * 31deed2826a77d7bd0b0c5e3817bad8b73bd499f8c17834cb935853ccbaaf8ae. */

/*
 * payload: borrowed header, length>=6 required; reads endpoint after USB check.
 * Returns0 when blocked. A configured IN secondary binding with slot<6 returns
 * the USB configured check's original nonzero result; otherwise returns1 iff
 * find_fast_interface(cached endpoint) is not -1. No state writes or lock.
 *
 * Rejects header bits0/2, then fenced global-block/enabled/deduction/block97/
 * block98/gate96/extra-block bytes in that order. Reads ALL three unfenced
 * mode bytes (7d18,9d8a,8f84), even when the first is nonzero, before testing
 * their OR. Only then queries USB bus0. Scans the complete secondary binding
 * list for the first exact endpoint. A matching OUT endpoint or invalid slot
 * falls through to primary routing; it does not examine later duplicates.
 * No pointer/count validation, permission check or race-free mode snapshot.
 */
int report_fast_route_allowed(const unsigned char *payload,
                                     unsigned int length)
{
    if (length < 6 || (payload[5] & 5U) != 0)
        return 0;
    memw();
    if (REPORT_FAST_GLOBAL_BLOCK != 0) return 0;
    memw();
    if (REPORT_FAST_ENABLED == 0) return 0;
    memw();
    if (USB_SUSPENDED != 0) return 0;
    memw();
    if (REPORT_FAST_BLOCK97 != 0) return 0;
    memw();
    if (REPORT_FAST_BLOCK98 != 0) return 0;
    memw();
    if (REPORT_FAST_GATE96 != 0) return 0;
    memw();
    if (REPORT_FAST_EXTRA_BLOCK != 0) return 0;
    unsigned int mode_block0 = REPORT_MODE_BLOCK_7D18;
    unsigned int mode_block1 = REPORT_MODE_BLOCK_9D8A;
    unsigned int mode_block2 = REPORT_MODE_BLOCK_8F84;
    if ((mode_block0 | mode_block1 | mode_block2) != 0)
        return 0;
    int usb_configured = usb_device_is_configured(0);
    if (usb_configured == 0)
        return 0;
    unsigned int endpoint = ((const volatile unsigned char *)payload)[0];
    int binding_count = CREDIT_BINDINGS.count;
    for (int binding_index = 0; binding_index < binding_count; ++binding_index) {
        const volatile CreditBinding *binding = (const volatile CreditBinding *)(
            (unsigned int)CREDIT_BINDINGS.entry + (unsigned int)binding_index * 8U);
        if (binding->endpoint != endpoint)
            continue;
        if ((endpoint & 0x80U) != 0 && binding->queue_slot < 6)
            return usb_configured;
        break;
    }
    return report_find_fast_interface(endpoint) != -1;
}

/* Native entry: 0x40377ef4. */
/* Original function-byte SHA-256:
 * c61513428a0ab836da8e2bdeecbc637e78089a1cee47f3edc57dcb7190b2b55f. */

/*
 * endpoint: full address, low nibble selects its pending-report byte.
 * Returns1 immediately for a nonzero own count. Otherwise canonicalizes, finds
 * the first primary interface, then scans endpoints1..15: fence/read signed
 * mapping, and read pending byte only on a mapping match. Any nonzero returns1;
 * absent interface or no matching pending count returns0. The original endpoint
 * may be revisited in that scan. No lock, mutations, allocation or count checks;
 * initialized storage and external serialization are needed for a stable answer.
 */
int report_pending_for_endpoint(unsigned int endpoint)
{
    if (REPORT_PENDING[endpoint & 15U] != 0)
        return 1;
    unsigned int canonical = endpoint_canonicalize(endpoint);
    int interface_count = CREDIT_INTERFACES.count;
    for (int interface_index = 0; interface_index < interface_count; ++interface_index) {
        unsigned int endpoint_address = (unsigned int)CREDIT_INTERFACES.endpoint +
            (unsigned int)interface_index;
        if (*(const volatile unsigned char *)endpoint_address != canonical)
            continue;
        for (unsigned int other_endpoint = 1; other_endpoint < 16; ++other_endpoint) {
            memw();
            if (CREDIT_ENDPOINT_INTERFACE[other_endpoint] == interface_index &&
                REPORT_PENDING[other_endpoint] != 0)
                return 1;
        }
        return 0;
    }
    return 0;
}

/* Native entry: 0x40377f60. */
/* Original function-byte SHA-256:
 * 18b096b8b20be5632629be6b0100b102a4bf6f8f457be1b2b9e5c5dac991eaa3. */

/*
 * flags: low byte saved as sequence. payload: borrowed6..96-byte report.
 * length: low16; has_counted_pending: ONLY low byte gates rejection.
 * Returns1 after successful insertion (cache check's true result), otherwise0
 * so normal RX handling can proceed. No producer-side pending-count increment.
 *
 * Rejects nonzero pending byte, initial NULL rptfast handle, length outside6..96,
 * or disabled instruction/data cache. Saves low8(strong_route_result XOR1).
 * Only saved0 bypasses weak fallback check; nonzero requires nonzero weak result.
 * Enters credit lock, rejects pending endpoint/interface work, fences/reads ring
 * count and rejects>=16. Calls track_rx(flags,payload,length,0) before slot choice.
 * Fences/reads head, fences/reads count AGAIN; slot=(count+head)&15, stride99.
 * Writes sequence,length,classification, copies exactly length bytes (suffix
 * untouched), then fences/reads current count, fences/stores low8(count+1).
 * Unlocks, RELOADS rptfast handle without a NULL recheck, gives ISR notification
 * index0 with zeroed wake output, yielding iff nonzero. Notification status does
 * not change success. Requires live ring/callback/task/kernel and initialized
 * shared state; caller/context must support the chosen lock/ISR APIs. No stable
 * admission snapshot, reconfiguration protection or successful USB delivery claim.
 * Input must not overlap the selected ring payload passed to memcpy.
 */
int report_receive_direct(unsigned int flags, const unsigned char *payload,
    unsigned int length, int has_counted_pending)
{
    flags &= 255U; length &= 65535U;
    if ((unsigned char)has_counted_pending != 0 || REPORT_FAST_TASK == NULL ||
        (unsigned short)(length - 6U) > 90U)
        return 0;
    int cache_ready = spi_flash_cache_enabled();
    if (cache_ready == 0)
        return 0;
    unsigned char classification = (unsigned char)
        (report_fast_route_allowed(payload, length) ^ 1U);
    if (classification != 0 && report_fast_fallback_allowed(payload, length) == 0)
        return 0;
    xPortEnterCriticalTimeout(&CREDIT_LOCK, 0xffffffffU);
    if (report_pending_for_endpoint(((const volatile unsigned char *)payload)[0]) != 0) {
        vPortExitCritical(&CREDIT_LOCK);
        return 0;
    }
    memw();
    if (REPORT_FAST_RING_COUNT >= 16) {
        vPortExitCritical(&CREDIT_LOCK);
        return 0;
    }
    report_track_rx(flags, payload, length, 0);
    memw();
    unsigned int ring_head = REPORT_FAST_RING_HEAD;
    memw();
    unsigned int ring_count = REPORT_FAST_RING_COUNT;
    volatile FastReportRingItem *ring_item =
        &REPORT_FAST_RING[(ring_head + ring_count) & 15U];
    ring_item->sequence = (unsigned char)flags;
    ring_item->length = (unsigned char)length;
    ring_item->classification = classification;
    memcpy((void *)ring_item->payload, payload, length);
    memw();
    unsigned char next_count = (unsigned char)(REPORT_FAST_RING_COUNT + 1U);
    memw();
    REPORT_FAST_RING_COUNT = next_count;
    vPortExitCritical(&CREDIT_LOCK);
    int higher_priority_woken = 0;
    vTaskGenericNotifyGiveFromISR(REPORT_FAST_TASK, 0, &higher_priority_woken);
    if (higher_priority_woken != 0)
        _frxt_setup_switch();
    return cache_ready;
}

/* Native entry: 0x40383e74. */
/* Original function-byte SHA-256:
 * 67099fceddee861891d30cbaf071b275d48c73a2a44312b8b946a076bdacc0e0. */

/*
 * No parameters/value. Caches TX task handle BEFORE MEMW/pending-byte store1.
 * Cached non-NULL handle receives task notification(index0,value0,eIncrement2,
 * previous=NULL); status ignored. Always sets pending even for NULL handle.
 * No allocation, timer or lifetime protection; a replaced old task can still
 * be notified. Requires live initialized task/kernel and coordinated teardown.
 */
void link_kick_fast_tx(void)
{
    RtosTask *tx_task = LINK_TX_TASK_HANDLE;
    memw();
    LINK_TX_FAST_PENDING = 1;
    if (tx_task != NULL)
        xTaskGenericNotify(tx_task, 0, 0, 2, NULL);
}

/* Native entry: 0x420336f8. */
/* Original function-byte SHA-256:
 * 604fef7511ef90949284eb43d34fcdf72fd2b7ad05b64d7e75941dd20e70a81d. */

/*
 * endpoint: low byte then low nibble select counters. Returns no value.
 * Under credit lock decrements load-observation and pending bytes independently
 * when nonzero, without underflow. Reads one64-bit clock and passes it to the
 * changed-check. Unlocks before calling kick_fast_tx iff cached result nonzero.
 * Does not itself change tracked mask, sequence cache, timestamps or dirty byte.
 * Lock result ignored; initialized storage/callees required. This accounts one
 * local processing event, without proving UART/USB delivery or timer precision.
 */
void report_complete(unsigned int endpoint)
{
    xPortEnterCriticalTimeout(&CREDIT_LOCK, 0xffffffffU);
    unsigned int endpoint_number = (unsigned char)endpoint & 15U;
    unsigned char observed_load = CREDIT_STATE.load_observations[endpoint_number];
    if (observed_load != 0)
        CREDIT_STATE.load_observations[endpoint_number] = observed_load - 1U;
    unsigned char pending_reports = REPORT_PENDING[endpoint_number];
    if (pending_reports != 0)
        REPORT_PENDING[endpoint_number] = pending_reports - 1U;
    unsigned long long now = (unsigned long long)esp_timer_get_time();
    int credit_changed = credit_state_changed(now);
    vPortExitCritical(&CREDIT_LOCK);
    if (credit_changed != 0)
        link_kick_fast_tx();
}
