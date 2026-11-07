/* Medius v3.4.7 device — link/workers.c.
 * Recovered C and native assembly, grouped for source navigation.
 * Original entry addresses, firmware-byte hashes and function comments follow.
 */

#include "../include/types.h"

/* reconstruction utilities: inlined expressions, not extra native entries.
 * Timestamp reads remain explicit LOW then HIGH at every call site. */
/* Native table indices are not C array bounds. Keep the 32-bit address wrap
 * even for a corrupt ring head or a live count beyond the nominal table. */
static __inline__ __attribute__((always_inline)) unsigned int
worker_table_address(const volatile void *base,unsigned int index,unsigned int stride)
{
    return (unsigned int)base + index*stride;
}

static __inline__ __attribute__((always_inline)) unsigned long long
tx_maintenance_timestamp(unsigned int low,unsigned int high)
{
    return ((unsigned long long)high << 32) | low;
}

static __inline__ __attribute__((always_inline)) long long
tx_maintenance_elapsed(unsigned long long now,unsigned long long before)
{
    return (long long)(now-before);
}

static __inline__ __attribute__((always_inline)) InputStateView *
tx_maintenance_fixed_state(unsigned int index)
{
    return (InputStateView *)worker_table_address(&FIXED_INPUTS[0].state,
        index,sizeof(FIXED_INPUTS[0]));
}

/* Native service order: predicate/output byte, optional reset, interface,
 * fenced input-valid byte, fenced suspend byte, then synchronous emitter. */
static __inline__ __attribute__((always_inline)) void
tx_maintenance_service_fixed(unsigned int index)
{
    if (input_needs_service(tx_maintenance_fixed_state(index)) == 0 &&
        FIXED_INPUTS[index].output_valid == 0)
        return;
    memw();
    if (OUTPUT_RESET_PENDING != 0) input_reset_output_reports();
    if (FIXED_INPUTS[index].interface < 0) return;
    memw();
    if (FIXED_INPUTS[index].last_input_valid == 0) return;
    memw();
    if (USB_SUSPENDED == 0) fixed_input_emit(index,0xffffffffU);
}

/* Whole microseconds and fractional nanoseconds are truncated from signed
 * ROM division. A negative remainder retains its low16 bits on the wire. */
static __inline__ __attribute__((always_inline)) unsigned short
tx_maintenance_append_timing(unsigned char *packet,unsigned short offset,
    unsigned char endpoint,unsigned int interval,unsigned int whole_us,
    unsigned short fractional_ns)
{
    unsigned int address = worker_table_address(packet,offset,1);
    *(volatile unsigned char *)address = endpoint;
    *(volatile unsigned char *)(address+1U) = interval < 255 ? interval : 255;
    memcpy((void *)(address+2U),&whole_us,4);
    memcpy((void *)(address+6U),&fractional_ns,2);
    return (unsigned short)(offset+8U);
}

/* Native entry: 0x4037d074. */
/*
 * Medius v3.4.7 — device application; 0x4037d074.
 *
 * Drains link transmit queues and the fast callback path.
 *
 * Calls: ulTaskGenericNotifyTake, link_frame_encode, link_uart_transmit_wait, xQueuePeek,
 * xQueueReceive.
 *
 * Indirect calls: fast payload builder and two TX admission sites.
 *
 * Original function-byte SHA-256:
 * 6843f6060c100f1bf8d9a98c12c177cb1622ec66a18f2daf10f90431bf2d9b01.
 */

/*
 * Drains fast work, queue 0, queue 1, then queue 2 in that order. After
 * each transmission or wait, selection starts again at the fast-work flag.
 * unused_argument: ignored task context. Returns: never normally returns.
 * Created at priority 13 with a 3072-byte stack and no core affinity.
 *
 * The fast handler is cached BEFORE clearing its pending byte. The byte is
 * cleared even for a NULL handler; only type is initialized before the call.
 * The third handler argument is the 64-byte payload capacity.
 * A nonzero handler length is narrowed to 16 bits by the encoder interface.
 * Type comes from the handler, flags is zero, and encoded capacity is 72.
 * Only a strictly positive signed encoder result publishes the saved length
 * and enters the UART completion wait. No handler-length bound is checked here.
 *
 * Queue 0 bypasses admission. Queue 1 calls admission only for encoded lengths
 * over 200; queue 2 calls it for every peeked item when a handler exists. The
 * callback receives length and the freshly loaded context word. A zero result
 * leaves the item queued and waits one RTOS tick on notification index 0,
 * clearing the count on exit. A blocked queue 1 prevents checking queue 2.
 * If neither lower queue has an item, that wait uses UINT32_MAX instead.
 * Neither wait is a software timer or a guaranteed wall-clock deadline.
 *
 * The selected lower queue handle is reloaded after admission. Its receive
 * result is ignored: the shared scratch length/frame is transmitted even if
 * receive fails. Peek does not reserve an item. Caller/configuration must
 * supply valid 522-byte queues and serialize consumption/reconfiguration;
 * this function adds no queue lock, length validation or retry on TX failure.
 * Fast callbacks must synchronously write at most one type byte and 64 payload
 * bytes and return a suitable length; the payload is otherwise uninitialized.
 * Both scratch buffers are borrowed by transmit_wait. Callback reentry,
 * starvation, peer delivery and physical scheduling are not established here.
 */
void link_transmit_task(void *unused_argument)
{
    (void)unused_argument;
    unsigned char fast_payload[64];
    unsigned char fast_type;
    LinkTxQueueItem *scratch = LINK_TX_QUEUE_SCRATCH;
    LinkFastTxFrame *fast_frame = LINK_TX_FAST_FRAME;

    for (;;) {
        for (;;) {
            memw();
            if (LINK_TX_FAST_PENDING == 0)
                break;
            LinkFastTxHandler handler = LINK_TX_FAST_HANDLER;
            memw();
            LINK_TX_FAST_PENDING = 0;
            fast_type = 0;
            if (handler == NULL)
                continue;
            unsigned int payload_length = handler(&fast_type, fast_payload,
                                                   sizeof(fast_payload));
            if (payload_length == 0)
                continue;
            int encoded_length = link_frame_encode(
                fast_frame->encoded_frame, 72, fast_type, 0, fast_payload,
                (unsigned short)payload_length);
            if (encoded_length <= 0)
                continue;
            fast_frame->encoded_length = (unsigned short)encoded_length;
            link_uart_transmit_wait(fast_frame->encoded_frame,
                                           (unsigned short)encoded_length);
        }

        if (xQueueReceive(LINK_TX_QUEUE_HANDLES.slot[0], scratch, 0) == 1) {
            link_uart_transmit_wait(scratch->encoded_frame,
                                           scratch->encoded_length);
            continue;
        }

        RtosQueue *selected_queue;
        if (xQueuePeek(LINK_TX_QUEUE_HANDLES.slot[1], scratch, 0) == 1) {
            unsigned int length = scratch->encoded_length;
            if (length > 200) {
                LinkTxAdmissionHandler admission = LINK_TX_ADMISSION;
                if (admission != NULL &&
                    admission(length, LINK_TX_ADMISSION_CONTEXT) == 0) {
                    ulTaskGenericNotifyTake(0, 1, 1);
                    continue;
                }
            }
            selected_queue = LINK_TX_QUEUE_HANDLES.slot[1];
        } else if (xQueuePeek(LINK_TX_QUEUE_HANDLES.slot[2], scratch, 0) == 1) {
            LinkTxAdmissionHandler admission = LINK_TX_ADMISSION;
            if (admission != NULL &&
                admission(scratch->encoded_length,
                          LINK_TX_ADMISSION_CONTEXT) == 0) {
                ulTaskGenericNotifyTake(0, 1, 1);
                continue;
            }
            selected_queue = LINK_TX_QUEUE_HANDLES.slot[2];
        } else {
            ulTaskGenericNotifyTake(0, 1, 0xffffffffU);
            continue;
        }
        xQueueReceive(selected_queue, scratch, 0);
        link_uart_transmit_wait(scratch->encoded_frame,
                                       scratch->encoded_length);
    }
}

/* Native entry: 0x40383e98. */
/*
 * Medius v3.4.7 — device application; 0x40383e98.
 *
 * Drains received UART link frames and invokes the registered frame dispatcher.
 *
 * Calls: ulTaskGenericNotifyTake, link_frame_dispatch, vPortExitCritical, xPortEnterCriticalTimeout,
 * xQueueReceive.
 *
 * Original function-byte SHA-256:
 * 91a047e2b32d9be858670b384ddd6a038c80cd03a594a6982fd496fd02c525c1.
 */

/*
 * UART1 receive worker: priority12/core0 with an8192-byte stack in this build.
 * unused_argument is the unused task context. Never returns normally.
 * Requires initialized kernel state, sole-consumer ownership and valid live
 * queue/ring/handler storage. No CRC, payload-length, cursor-range or lifetime
 * validation is performed here. No independent software timer is created.
 *
 * Wait on notification index0, clearing its count, for up to100 kernel ticks.
 * Scheduling and preemption can delay execution after that timeout. Repeatedly
 * drain the optional100-byte-copy queue with zero wait before each descriptor.
 * Dispatch its type/flags, payload at+4 and unchecked16-bit length with time0.
 * This static scratch is reused by the next queue receive. Continuous queue
 * arrivals can postpone ring service; fallback items do not change accounting.
 *
 * Ring poll reads descriptor_read after MEMW, then descriptor_write after MEMW.
 * On nonempty, MEMW and re-read descriptor_read as the cached slot to dequeue.
 * Load offset,time,length,flags,type in native order, then dispatch the borrowed
 * ring payload. The dispatcher must not retain that pointer after returning.
 * Re-read the descriptor's marker after dispatch: if nonzero, acquire the count
 * portMUX and MEMW/read/MEMW/write counted_pending-1 modulo32bits, then unlock.
 * There is no underflow guard and the producer increment takes no such lock.
 *
 * Re-read length and offset after dispatch/accounting, rather than freeing the
 * earlier snapshot. MEMW then advance payload_read to(offset+length)&8191;
 * MEMW then publish(cached_slot+1)%96 to descriptor_read. No trailing MEMW is
 * supplied. Callback edits to these descriptor fields affect the release;
 * callback edits to global descriptor_read do not replace the cached slot.
 * Queue and callback lifetime/synchronization remain caller responsibilities.
 */
void link_receive_task(void *unused_argument)
{
    (void)unused_argument;
    for (;;) {
        (void)ulTaskGenericNotifyTake(0, 1, 100);
        for (;;) {
            for (;;) {
                RtosQueue *queue = LINK_RX_OPTIONAL_QUEUE;
                if (queue == 0 || xQueueReceive(queue, LINK_RX_QUEUE_SCRATCH, 0) != 1)
                    break;
                unsigned short length = LINK_RX_QUEUE_SCRATCH->length;
                unsigned char flags = LINK_RX_QUEUE_SCRATCH->flags;
                unsigned char type = LINK_RX_QUEUE_SCRATCH->type;
                link_frame_dispatch(type, flags,
                    LINK_RX_QUEUE_SCRATCH->payload, length, 0);
            }
            memw();
            unsigned int observed_consumer = LINK_RX_CURSOR_STATE.descriptor_read;
            memw();
            unsigned int producer = LINK_RX_CURSOR_STATE.descriptor_write;
            if (observed_consumer == producer)
                break;
            memw();
            unsigned int slot = LINK_RX_CURSOR_STATE.descriptor_read;
            volatile LinkRxDescriptor *descriptor = (volatile LinkRxDescriptor *)
                worker_table_address(LINK_RX_DESCRIPTORS,slot,sizeof(LinkRxDescriptor));
            unsigned short payload_offset = descriptor->payload_offset;
            unsigned int timestamp = descriptor->received_at_us_low;
            unsigned short length = descriptor->length;
            unsigned char flags = descriptor->flags;
            unsigned char type = descriptor->type;
            link_frame_dispatch(type, flags,
                (unsigned char *)worker_table_address(LINK_RX_PAYLOAD,payload_offset,1),
                length, timestamp);
            if (descriptor->counted != 0) {
                (void)xPortEnterCriticalTimeout(&LINK_RX_COUNT_LOCK, -1);
                memw();
                unsigned int pending = LINK_RX_COUNTED_PENDING;
                memw();
                LINK_RX_COUNTED_PENDING = pending - 1U;
                vPortExitCritical(&LINK_RX_COUNT_LOCK);
            }
            unsigned int released_length = descriptor->length;
            unsigned int released_offset = descriptor->payload_offset;
            unsigned int next_read_offset = (released_offset + released_length)
                & LINK_RX_PAYLOAD_MASK;
            memw();
            LINK_RX_CURSOR_STATE.payload_read = next_read_offset;
            memw();
            LINK_RX_CURSOR_STATE.descriptor_read = (slot + 1U) % LINK_RX_DESCRIPTOR_SLOTS;
        }
    }
}

/* Native entry: 0x42021a80. */
/*
 * Medius v3.4.7 — device application; 0x42021a80.
 *
 * Probes silent links and cycles the inter-chip UART baud rate.
 *
 * Calls: vTaskDelay, esp_log_timestamp, esp_log_write, esp_timer_get_time, link_frame_enqueue,
 * link_parser_reset, uart_set_baudrate.
 *
 * Original function-byte SHA-256:
 * 03f19018f44fdf6b070c5bf7c219ba6df501d43368a9ecae3822ab88fbd27a4f.
 */

/*
 * Probes an uninhibited silent link and cycles its three native baud entries.
 * unused_argument: ignored task context. Returns: never normally returns.
 * Created only for link role 1: priority 2, stack 3072 bytes, no core affinity.
 * Normal device startup uses role 0, so this entry is normally not created.
 *
 * Sleeps 400 RTOS ticks before every attempt, including while inhibited.
 * A zero inhibit byte and signed 32-bit wrapping clock difference >1500000
 * enqueue type 0x25 with flags 0 and sixteen zero bytes, zero queue wait and
 * drop diagnostics enabled. Enqueue inserts at the back. Its result is ignored.
 * After 300 ticks, rechecks inhibit
 * before sampling the clock and current last-direct-RX timestamp again.
 * Difference >300000 advances index, initially 1, modulo 3. The constant
 * table is [5000000,12000000,20000000], so attempts start at 20000000, then
 * 5000000, then 12000000. Link activity does not reset this task's index.
 *
 * Ignores uart_set_baudrate status, then sets and clears UART1 RXFIFO_RST
 * with separately fenced read/modify/write operations, resets the parser and
 * logs a warning. The second register read is fresh. This is RX FIFO reset,
 * not TX reset, UART reinitialization, or evidence that the peer changed baud.
 * Clock differences deliberately use low32 modular subtraction followed by
 * signed comparison: ages at or above 2^31 are not ordinary positive ages.
 * No lock spans the inhibit/timestamp checks, enqueue, delays or register
 * writes; link activity can change between them. The sixteen-byte probe is
 * borrowed only during synchronous enqueue. Configuration must initialize
 * the parser/UART and serialize competing reconfiguration. These are task
 * delays, not software timers; wake times depend on tick conversion, scheduler
 * load, higher-priority work and interrupts. No physical baud/timing claim.
 */
void link_baud_task(void *unused_argument)
{
    (void)unused_argument;
    unsigned int baud_index = 1;
    for (;;) {
        vTaskDelay(400);
        memw();
        if (LINK_BAUD_PROBE_INHIBIT != 0)
            continue;

        unsigned int now_us_low = (unsigned int)esp_timer_get_time();
        memw();
        unsigned int age = now_us_low - LINK_LAST_DIRECT_RX_US;
        if ((int)age <= 1500000)
            continue;
        unsigned int probe[4];
        volatile unsigned int *probe_words = probe;
        probe_words[0] = 0;
        probe_words[1] = 0;
        probe_words[2] = 0;
        probe_words[3] = 0;
        link_frame_enqueue(0x25, 0, probe, sizeof(probe), 0, 0);
        vTaskDelay(300);
        memw();
        if (LINK_BAUD_PROBE_INHIBIT != 0)
            continue;
        now_us_low = (unsigned int)esp_timer_get_time();
        memw();
        age = now_us_low - LINK_LAST_DIRECT_RX_US;
        if ((int)age <= 300000)
            continue;

        baud_index = (baud_index + 1U) % 3U;
        unsigned int baud = LINK_BAUD_TABLE[baud_index];
        uart_set_baudrate(LINK_UART_NUMBER, baud);
        memw();
        unsigned int conf0 = LINK_UART1->conf0;
        memw();
        LINK_UART1->conf0 = conf0 | UART_RX_FIFO_RESET;
        memw();
        conf0 = LINK_UART1->conf0;
        memw();
        LINK_UART1->conf0 = conf0 & ~UART_RX_FIFO_RESET;
        link_parser_reset(LINK_RX_PARSER);
        unsigned int log_timestamp = esp_log_timestamp();
        esp_log_write(2, LINK_LOG_TAG,
                      "W (%lu) %s: link silent; trying %u baud\n",
                      log_timestamp, LINK_LOG_TAG, baud);
    }
}

/* Native entry: 0x420222c8. */
/* Original function-byte SHA-256:
 * 27c72cd26457f4ccc4833d66011457e8879d14f526be2abdba7d6aa52dde948b. */
/*
 * Link-sync task. startup_role is interpreted as a full native WORD boolean
 * (normal creator passes only low8). Nonzero uses20 ticks for probe_count0..15;
 * otherwise configured period*1000 is wrapped32 then divided by1000. The local
 * probe count wraps32, so startup intervals recur after a full wrap. Deadline
 * advances by that period; if signed(now-deadline)>period, resample now and
 * rebase to now+period. Queue wait=max(signed(deadline-now),0) ticks. Exact
 * receive1 processes another16-byte exchange; any other status emits a probe.
 * Continuous queued samples can postpone probes past the deadline indefinitely.
 *
 * Exchange timestamps t0..t3 are local_start,remote_start,remote_end,local_end.
 * All differences wrap32. Accept remote turnaround<=10,000us unsigned, local
 * elapsed nonnegative signed, and corrected RTT=local_elapsed-turnaround also
 * nonnegative signed. Offset=(t1-t0)-RTT/2 modulo32. When ready, predict drift
 * from signed(t0-reference)*signed(ppb)/1e9 (truncate toward zero). Residual is
 * the signed32 offset-prediction-old_offset. Reset all624 filter/history bytes
 * if outside +/-((old_RTT+RTT)/2+50+zero_extended_abs32(t0-reference)/5000).
 * INT_MIN absolute value retains raw80000000; no signed-overflow UB is added.
 *
 * Append offset/RTT/t0 to the16-sample ring, update head&15, saturate count16.
 * Read window-valid BEFORE ready=1. Missing window starts one; signed elapsed
 * >999,999us archives its best sample in32-window history, head&31/count<=32,
 * then starts a new window. Otherwise RTT<=current best replaces time/RTT/
 * offset, retaining the window start. Raw BYTE heads are trusted on indexing;
 * only their NEXT values are masked. Recompute estimator after any accepted
 * sample. Its fitting algorithm remains a separately reviewed callee boundary.
 *
 * After EVERY received exchange, even rejected ones, enter clock mux forever,
 * read flags HALF then offset/drift/reference/RTT WORDs, and publish flags HALF
 * followed by offset/drift/RTT/reference WORDs. Unlock. Queue errors/timeouts
 * increment the shared probe sequence, zero16 bytes, memcpy sequence into first
 * WORD and enqueue type25/flags0/length16/wait0/suppress0; ignore result.
 * No sample authentication, probe-sequence matching, NULL queue guard, hardware
 * timer or physical timing guarantee. Tick/clock wraps use native signed
 * comparisons; delays, queue traffic and task scheduling affect cadence.
 */
void link_sync_task(void *startup_role)
{
    unsigned int startup = startup_role != 0;
    unsigned int deadline = xTaskGetTickCount();
    unsigned int probe_count = 0;
    volatile LinkSyncFilterState *filter = LINK_SYNC_FILTER;
    for (;;) {
        unsigned int period = 20;
        if (probe_count > 15 || startup == 0) {
            memw();
            unsigned int microseconds = LINK_SYNC_PERIOD * 1000U;
            period = microseconds / 1000U;
        }
        deadline += period;
        unsigned int now = xTaskGetTickCount();
        if ((int)(now - deadline) > (int)period) deadline = xTaskGetTickCount() + period;
        for (;;) {
            now = xTaskGetTickCount();
            unsigned int wait = deadline - now;
            if ((int)wait < 0) wait = 0;
            LinkSyncExchange exchange;
            if (xQueueReceive(LINK_SYNC_QUEUE,&exchange,wait) != 1) break;
            unsigned int local_elapsed = exchange.local_end_us - exchange.local_start_us;
            unsigned int remote_elapsed = exchange.remote_end_us - exchange.remote_start_us;
            unsigned int round_trip = local_elapsed - remote_elapsed;
            if (remote_elapsed <= 10000U && (int)local_elapsed >= 0 && (int)round_trip >= 0) {
                unsigned int offset = (exchange.remote_start_us - exchange.local_start_us) -
                    (round_trip >> 1);
                if (filter->ready != 0) {
                    unsigned int elapsed = exchange.local_start_us - filter->reference_us_low;
                    int drift = filter->estimated_drift_ppb;
                    long long predicted = link_sync_signed_divide(
                        (long long)(int)elapsed * drift,1000000000LL);
                    unsigned int previous_round_trip = filter->estimated_round_trip_us;
                    unsigned long long paired_trip = (unsigned long long)previous_round_trip + round_trip;
                    unsigned int previous_offset = filter->estimated_offset_us;
                    int residual = (int)(offset - (unsigned int)predicted - previous_offset);
                    unsigned int magnitude = (int)elapsed < 0 ? 0U - elapsed : elapsed;
                    unsigned long long tolerance = (paired_trip >> 1) + 50ULL +
                        (unsigned long long)link_sync_signed_divide((long long)magnitude,5000);
                    if ((long long)residual > (long long)tolerance ||
                        (long long)residual < (long long)(0ULL - tolerance))
                        memset((void *)filter,0,624);
                }
                unsigned int recent_head = filter->recent_head;
                unsigned char recent_count = filter->recent_count;
                *(volatile unsigned int *)worker_table_address(filter->offsets_us,recent_head,4) = offset;
                *(volatile unsigned int *)worker_table_address(filter->round_trips_us,recent_head,4) = round_trip;
                *(volatile unsigned int *)worker_table_address(filter->times_us_low,recent_head,4) = exchange.local_start_us;
                filter->recent_head = (unsigned char)((recent_head + 1U) & 15U);
                if (recent_count < 16) filter->recent_count = recent_count + 1U;
                unsigned char window_valid = filter->window_valid;
                filter->ready = 1;
                if (window_valid == 0) goto start_window;
                if ((int)(exchange.local_start_us - filter->window_started_us_low) > 999999) {
                    unsigned int head = filter->history_head;
                    unsigned int time = filter->window_time_us_low;
                    volatile LinkSyncWindowSample *window = (volatile LinkSyncWindowSample *)
                        worker_table_address(filter->history,head,sizeof(LinkSyncWindowSample));
                    window->time_us_low = time;
                    unsigned int previous_trip = filter->window_round_trip_us;
                    unsigned int previous_offset = filter->window_offset_us;
                    window->round_trip_us = previous_trip;
                    window->offset_us = previous_offset;
                    unsigned char count = filter->history_count;
                    filter->history_head = (unsigned char)((head + 1U) & 31U);
                    if (count < 32) filter->history_count = count + 1U;
start_window:
                    filter->window_offset_us = offset;
                    filter->window_time_us_low = exchange.local_start_us;
                    filter->window_round_trip_us = round_trip;
                    filter->window_started_us_low = exchange.local_start_us;
                    filter->window_valid = 1;
                } else if (round_trip <= filter->window_round_trip_us) {
                    filter->window_time_us_low = exchange.local_start_us;
                    filter->window_round_trip_us = round_trip;
                    filter->window_offset_us = offset;
                }
                link_sync_recompute_estimate();
            }
            (void)xPortEnterCriticalTimeout(&LINK_CLOCK_LOCK,-1);
            unsigned short flags = filter->flags;
            unsigned int offset = filter->estimated_offset_us;
            int drift = filter->estimated_drift_ppb;
            unsigned int reference = filter->reference_us_low;
            unsigned int trip = filter->estimated_round_trip_us;
            LINK_CLOCK_ESTIMATE->flags = flags;
            LINK_CLOCK_ESTIMATE->offset_us = offset;
            LINK_CLOCK_ESTIMATE->drift_ppb = drift;
            LINK_CLOCK_ESTIMATE->round_trip_us = trip;
            LINK_CLOCK_ESTIMATE->reference_us_low = reference;
            vPortExitCritical(&LINK_CLOCK_LOCK);
        }
        unsigned int sequence = LINK_SYNC_PROBE_SEQUENCE;
        LINK_SYNC_PROBE_SEQUENCE = sequence + 1U;
        unsigned int probe[4];
        volatile unsigned int *probe_words = probe;
        probe_words[0] = 0;
        probe_words[1] = 0;
        probe_words[2] = 0;
        probe_words[3] = 0;
        memcpy(probe,&sequence,4);
        (void)link_frame_enqueue(0x25,0,probe,16,0,0);
        ++probe_count;
    }
}

/* Native entry: 0x420321c4. */
/* Original function-byte SHA-256:
 * c573bbcb1adfeaf8619630331278cd367b7c0391f529ff70059df172f2e908bb. */
/*
 * TX maintenance task: priority 11,3072-byte stack,CPU 0; task argument unused.
 * Notification index 0 waits forever, clears all exit bits and coalesces work.
 * Value 1 performs maintenance; value 2 ONLY flushes pending input when value 1
 * is absent. Values 4/8 are processed afterward for power publication/wake.
 * A 50,000us ESP software timer posts value 1; its callback/scheduler/interrupt
 * delays mean neither this worker nor its retry intervals are deadlines.
 * Returns: never normally returns. Requires initialized live USB/link/input
 * storage, valid queue/mutex handles and external configuration serialization.
 *
 * Maintenance sends render acknowledgements with compare/exchange, checks the
 * four second playback-control timeout, and sends opcode 3b phase estimates
 * only when configured and awake. Low-speed fallback uses observed activity
 * and a wire-duration estimate, not a measured future USB transaction time.
 * A 56-byte local packet starts at 7 and appends 8 bytes per admitted interface;
 * live signed interface counts and LOW16 lengths are trusted without a bound.
 * Signed 64 time comparisons use wrapping subtraction; LOW/HIGH loads are not
 * atomic snapshots. Native MEMWs and rereads are retained explicitly.
 *
 * Low-speed token-empty masking clears DIEPINT0..6 only if DIEPMSK bit 13 was
 * absent, then enables it under the report spinlock. Alternate 0 reselection
 * takes report/config mutexes opportunistically and rechecks USB state.
 * Twelve secondary bindings get 100,000us busy checks; ten OUT records retry
 * opcode 3e after 50,000us, outside their spinlock. Per-interface recovery marks
 * admitted epochs ffff after 3,000us or recovery_mode>=2, then retires stale
 * history after 50,000us. Counts/slots are not sanitized beyond native gates.
 *
 * The config mutex then protects idle cleanup after strictly 1,000,000us since
 * the saved change time: primary/keyboard/consumer/dynamic state, captures,
 * rewrite rules, playback and transforms. Raw predicate bytes, fresh enable
 * samples, keyboard-service-before-consumer-reset order and the transform
 * clear's direct commit branch matter. Clearing 258 transform bytes commits
 * without recomputing the timer eligibility mask. Releases reload the current
 * mutex handle; failed indefinite takes are ignored as in the firmware.
 * Finally publishes credit-dirty/kicks TX, optionally queues render motion
 * and arms the input software timer. Native retry/cleanup paths are preserved;
 * no new bounds checks, lock, wake retry or timeout recovery is supplied.
 *
 * Remote wake requires suspended and no outstanding request. Success of
 * usbd_set_remote_wakeup increments the wrapping counter and calls resume;
 * error clears the request and publishes power state only if clone-active.
 * This static reconstruction establishes no physical wake/timing/concurrency
 * guarantee. Helper contracts remain separate reviewed native boundaries.
 */
void transmit_watchdog_task(void)
{
    for (;;) {
        unsigned int notifications = 0;
        xTaskGenericNotifyWait(0,0,0xffffffffU,&notifications,0xffffffffU);
        if ((notifications & 1U) == 0) {
            if (notifications & 2U) input_flush_pending();
            goto power_notifications;
        }

        memw();
        unsigned char expected_render_ack = MOTION_RENDER_ACK;
        if (expected_render_ack != 0) {
            unsigned char token = MOTION_RENDER_TOKEN;
            unsigned short acknowledgement = (unsigned short)(expected_render_ack == 1) |
                ((unsigned short)token << 8);
            if (link_enqueue_nowait_silent(0x3a,0,&acknowledgement,2) != 0)
                atomic_compare_exchange_byte_task(&MOTION_RENDER_ACK,
                    &expected_render_ack,0,4,2);
        }
        input_flush_pending();
        unsigned char control_waiting = PLAYBACK_CONTROL_REQUEST->waiting;
        if (control_waiting != 0 || IMPERFECT_CLIP_QUEUE->pending_count != 0) {
            RtosQueue *configuration_mutex = REWRITE_MUTEX;
            if (configuration_mutex != NULL) {
                xQueueSemaphoreTake(configuration_mutex,0xffffffffU);
                control_waiting = PLAYBACK_CONTROL_REQUEST->waiting;
            }
            if (control_waiting != 0) {
                unsigned long long control_now = esp_timer_get_time();
                unsigned int started_low = PLAYBACK_CONTROL_REQUEST->started.low;
                unsigned int started_high = PLAYBACK_CONTROL_REQUEST->started.high;
                if (tx_maintenance_elapsed(control_now,
                    tx_maintenance_timestamp(started_low,started_high)) >= 4000000)
                    playback_control_complete(0xfe,NULL,0);
                else playback_control_try_start();
            } else playback_control_try_start();
            configuration_mutex = REWRITE_MUTEX;
            if (configuration_mutex != NULL)
                xQueueGenericSend(configuration_mutex,NULL,0,0);
        }

        memw();
        unsigned char active_sample = CLONE_ACTIVE;
        unsigned int endpoint_maintenance = 0;
        if (active_sample != 0 && usb_device_is_configured(0) != 0) {
            endpoint_maintenance = 1;
            memw();
            if (USB_SUSPENDED == 0) {
                unsigned long long timing_now = esp_timer_get_time();
                TimestampWords deadline = {0,0};
                unsigned char deadline_valid = input_get_timing_deadline(timing_now,&deadline);
                unsigned char low_speed = CLONE_LOW_SPEED;
                unsigned int preferred_interface = 0xffffffffU;
                if (FIXED_INPUTS[0].enabled != 0) {
                    int selected_interface = FIXED_INPUTS[0].interface;
                    preferred_interface = (unsigned int)selected_interface;
                    if (selected_interface < 0 || selected_interface >= USB_INTERFACE_COUNT)
                        preferred_interface = 0xffffffffU;
                }
                unsigned char timing_packet[56];
                unsigned short timing_length = 7;
                unsigned long long fallback_deadline_ns = 0;
                xPortEnterCriticalTimeout(&CREDIT_LOCK,-1);
                for (unsigned int interface = 0;
                     (int)interface < USB_INTERFACE_COUNT; ++interface) {
                    volatile CreditInterfaceQueue *queue =
                        (volatile CreditInterfaceQueue *)worker_table_address(
                            REPORT_INTERFACE_QUEUES_WRITABLE,interface,sizeof(CreditInterfaceQueue));
                    if (deadline_valid != 0) {
                        unsigned int interval = queue->interval_scale;
                        if (interval >= 2 && queue->frame_number_valid != 0) {
                            unsigned int minimum_us = ((const volatile ReportIntervalLearner *)
                                worker_table_address(REPORT_INTERVAL_LEARNERS,interface,
                                    sizeof(ReportIntervalLearner)))->minimum_us;
                            if (minimum_us == 0 && preferred_interface != 0xffffffffU)
                                minimum_us = ((const volatile ReportIntervalLearner *)
                                    worker_table_address(REPORT_INTERVAL_LEARNERS,preferred_interface,
                                        sizeof(ReportIntervalLearner)))->minimum_us;
                            if (minimum_us == 0) continue;
                            unsigned int last_frame = queue->last_frame_number;
                            unsigned int current_frame = USB_FRAME_PHASE.frame;
                            unsigned int frame_delta = (interval-
                                ((current_frame+1U-last_frame)&0x7ffU)%interval)%interval;
                            unsigned int reference_low = USB_FRAME_PHASE.reference_ns.low;
                            unsigned int reference_high = USB_FRAME_PHASE.reference_ns.high;
                            unsigned long long target_ns =
                                tx_maintenance_timestamp(reference_low,reference_high) +
                                (unsigned long long)(unsigned short)frame_delta*1000000U +
                                (unsigned long long)minimum_us*1000U;
                            if (target_ns == 0) continue;
                            unsigned int whole_us = (unsigned int)link_sync_signed_divide(
                                (long long)target_ns,1000);
                            unsigned short fractional_ns = (unsigned short)signed_remainder_i64(
                                (long long)target_ns,1000);
                            unsigned char endpoint = USB_INTERFACE_ENDPOINTS[interface];
                            timing_length = tx_maintenance_append_timing(timing_packet,timing_length,
                                endpoint,interval,whole_us,fractional_ns);
                            continue;
                        }
                    }
                    if (low_speed != 1) continue;
                    unsigned char endpoint = USB_INTERFACE_ENDPOINTS[interface];
                    if (endpoint == 0) continue;
                    unsigned int period = REPORT_INTERFACE_PERIODS[interface];
                    unsigned int length = REPORT_LAST_IN_LENGTH[interface];
                    if (period == 0) period = 8;
                    unsigned int packet_bytes = length == 0 ? 0 : ((length-1U)%period)+1U;
                    unsigned int completion_low = REPORT_LAST_IN_COMPLETION[interface].low;
                    unsigned int completion_high = REPORT_LAST_IN_COMPLETION[interface].high;
                    unsigned int activity_low = REPORT_LAST_IN_ACTIVITY[interface].low;
                    unsigned int activity_high = REPORT_LAST_IN_ACTIVITY[interface].high;
                    unsigned long long completion = tx_maintenance_timestamp(completion_low,completion_high);
                    unsigned long long activity = tx_maintenance_timestamp(activity_low,activity_high);
                    if (completion == 0 && activity == 0) continue;
                    if (completion != 0) {
                        unsigned int wire_us = ((((packet_bytes&0xffffU)*88U+385U)/10U+60U)*2U)/3U;
                        completion = completion-wire_us+15U;
                    }
                    if (activity != 0) activity -= 10U;
                    unsigned long long observed_time =
                        (long long)activity < (long long)completion ? completion : activity;
                    if (observed_time == 0) continue;
                    unsigned long long horizon =
                        (unsigned long long)REPORT_CONFIGURED_PERIOD_US[interface]+99999U;
                    if (tx_maintenance_elapsed(timing_now,observed_time) > (long long)horizon) continue;
                    unsigned int interval = queue->interval_scale;
                    if (fallback_deadline_ns == 0 || interface == preferred_interface)
                        fallback_deadline_ns = observed_time*1000U;
                    timing_length = tx_maintenance_append_timing(timing_packet,timing_length,
                        endpoint,interval,(unsigned int)observed_time,0);
                }
                vPortExitCritical(&CREDIT_LOCK);
                unsigned char timing_valid;
                unsigned long long common_deadline;
                if (deadline_valid == 1 || fallback_deadline_ns == 0) {
                    timing_valid = deadline_valid;
                    common_deadline = tx_maintenance_timestamp(deadline.low,deadline.high);
                } else {
                    timing_valid = 1;
                    common_deadline = fallback_deadline_ns;
                }
                unsigned int whole_us = (unsigned int)link_sync_signed_divide(
                    (long long)common_deadline,1000);
                unsigned short fractional_ns = (unsigned short)signed_remainder_i64(
                    (long long)common_deadline,1000);
                timing_packet[0] = timing_valid;
                memcpy(timing_packet+1,&whole_us,4);
                memcpy(timing_packet+5,&fractional_ns,2);
                link_enqueue_nowait_silent(0x3b,0,timing_packet,timing_length);
            }
        }

        if (CLONE_LOW_SPEED == 1) {
            memw(); REPORT_MAINTENANCE_BUSY = 1;
            memw();
            if (REPORT_FAST_GLOBAL_BLOCK == 0) {
                memw(); active_sample = CLONE_ACTIVE;
                if (active_sample != 0) {
                    xPortEnterCriticalTimeout(&CREDIT_LOCK,-1);
                    memw(); unsigned int interrupt_mask = DWC2_IN_ENDPOINT_INTERRUPT_MASK;
                    if ((interrupt_mask & 0x2000U) == 0) {
                        for (unsigned int endpoint = 0; endpoint < 7; ++endpoint) {
                            memw(); DWC2_IN_ENDPOINT_INTERRUPT(endpoint) = 0x2000U;
                        }
                        memw(); interrupt_mask = DWC2_IN_ENDPOINT_INTERRUPT_MASK;
                        memw(); DWC2_IN_ENDPOINT_INTERRUPT_MASK = interrupt_mask | 0x2000U;
                    }
                    vPortExitCritical(&CREDIT_LOCK);
                }
            }
            memw(); REPORT_MAINTENANCE_BUSY = 0;
        }

        unsigned long long now_us;
        unsigned int service_available = 0;
        if (endpoint_maintenance == 0) {
            now_us = esp_timer_get_time();
            goto input_cleanup;
        }
        memw();
        if (CLONE_ALTERNATE_PENDING != 0) {
            memw();
            if (NONZERO_CONTROL_WORKER_BUSY == 0) {
                RtosQueue *report_mutex = REPORT_MUTEX;
                if (report_mutex != NULL && xQueueSemaphoreTake(report_mutex,0) == 1) {
                    unsigned int did_reselect = 0;
                    RtosQueue *configuration_mutex = REWRITE_MUTEX;
                    if (configuration_mutex != NULL) {
                        if (xQueueSemaphoreTake(configuration_mutex,0) != 1)
                            goto release_report_mutex;
                        memw();
                        if (CLONE_ALTERNATE_PENDING == 0) goto release_configuration_mutex;
                        memw();
                        if (CLONE_ACTIVE == 0) goto release_configuration_mutex;
                    } else {
                        memw();
                        if (CLONE_ALTERNATE_PENDING == 0) goto release_report_mutex;
                        memw();
                        if (CLONE_ACTIVE == 0) goto release_report_mutex;
                    }
                    if (usb_device_is_configured(0) != 0) {
                        memw(); CLONE_ALTERNATE_PENDING = 0;
                        UsbInterfaceSelection selection = {{0}};
                        for (unsigned int interface = 0; interface < 256; ++interface)
                            if (((const volatile unsigned char *)CLONE_ALTERNATE_SETTINGS)[interface] != 0)
                                selection.words[(interface>>5)&7U] |= 1U << (interface&31U);
                        usb_clone_reset_transfer_accounting();
                        unsigned int any_alternate = 0;
                        for (unsigned int word = 0; word < 8; ++word)
                            if (selection.words[word] != 0) { any_alternate = 1; break; }
                        if (any_alternate != 0)
                            usb_clone_apply_alternate_changes(&selection,CLONE_ZERO_ALTERNATES);
                        else out_drain_all_served_endpoints();
                        did_reselect = 1;
                    }
release_configuration_mutex:
                    configuration_mutex = REWRITE_MUTEX;
                    if (configuration_mutex != NULL) xQueueGenericSend(configuration_mutex,NULL,0,0);
release_report_mutex:
                    report_mutex = REPORT_MUTEX;
                    if (report_mutex != NULL) xQueueGenericSend(report_mutex,NULL,0,0);
                    if (did_reselect != 0) {
                        unsigned int log_timestamp = esp_log_timestamp();
                        esp_log_write(2,"usbdev",
                            "W (%lu) %s: SET_CONFIGURATION reselected alt 0 on every interface\n",
                            log_timestamp,"usbdev");
                    }
                }
            }
        }

        now_us = esp_timer_get_time();
        for (unsigned int binding_index = 0; binding_index < 12; ++binding_index) {
            xPortEnterCriticalTimeout(&CREDIT_LOCK,-1);
            const volatile CreditBinding *binding = &CREDIT_BINDINGS.entry[binding_index];
            if ((int)binding_index < CREDIT_BINDINGS.count) {
                unsigned int slot = binding->queue_slot;
                if (slot < 6 && binding->kind != 2) {
                    memw();
                    if (REPORT_SECONDARY_BLOCKED[slot] != 0) goto secondary_done;
                    memw();
                    if (USB_SUSPENDED != 0) goto secondary_done;
                    memw();
                    if (REPORT_SECONDARY_STALLED[slot] != 0) goto secondary_done;
                    memw();
                    if (REPORT_SECONDARY_IN_FLIGHT[slot] == 0) goto secondary_done;
                    memw(); unsigned int sent_low = REPORT_SECONDARY_TIME[slot].low;
                    memw(); unsigned int sent_high = REPORT_SECONDARY_TIME[slot].high;
                    if (tx_maintenance_elapsed(now_us,tx_maintenance_timestamp(sent_low,sent_high)) > 100000) {
                        int busy = dwc2_in_endpoint_is_busy(0,binding->endpoint);
                        slot = binding->queue_slot;
                        if (busy == 0) {
                            memw(); REPORT_SECONDARY_IN_FLIGHT[slot] = 0;
                            report_pump_secondary(binding_index);
                        } else {
                            memw();
                            if (REPORT_SECONDARY_COMPLETION_SEEN[slot] != 0) {
                                unsigned int endpoint = binding->endpoint & 15U;
                                memw();
                                if ((int)DWC2_IN_CONTROL(endpoint) < 0) {
                                    memw(); unsigned int count = REPORT_BUSY_WATCHDOG_OBSERVATIONS;
                                    memw(); REPORT_BUSY_WATCHDOG_OBSERVATIONS = count+1U;
                                }
                            }
                        }
                    }
                }
            }
secondary_done:
            vPortExitCritical(&CREDIT_LOCK);
        }
        now_us = esp_timer_get_time();
        unsigned int now_low = (unsigned int)now_us;
        unsigned int now_high = (unsigned int)(now_us>>32);
        for (unsigned int index = 0; index < 10; ++index) {
            xPortEnterCriticalTimeout(DEVICE_OUT_LOCK,-1);
            volatile DeviceOutEndpoint *out = &DEVICE_OUT_ENDPOINTS[index];
            unsigned char endpoint = out->endpoint;
            if (endpoint == 0) goto out_retry_done;
            unsigned char sent_sequence = out->sent_sequence;
            if (out->rebase_sequence == sent_sequence) goto out_retry_done;
            unsigned int sent_low = out->last_forward_us_low;
            unsigned int sent_high = out->last_forward_us_high;
            if (tx_maintenance_elapsed(now_us,tx_maintenance_timestamp(sent_low,sent_high)) <= 50000)
                goto out_retry_done;
            out->last_forward_us_low = now_low;
            out->last_forward_us_high = now_high;
            unsigned short retry = (unsigned short)endpoint | ((unsigned short)sent_sequence << 8);
            vPortExitCritical(DEVICE_OUT_LOCK);
            link_send_wait100(0x3e,0,&retry,2);
            continue;
out_retry_done:
            vPortExitCritical(DEVICE_OUT_LOCK);
        }

        for (unsigned int interface = 0;
             (int)interface < USB_INTERFACE_COUNT; ++interface) {
            xPortEnterCriticalTimeout(&CREDIT_LOCK,-1);
            volatile CreditInterfaceQueue *queue =
                (volatile CreditInterfaceQueue *)worker_table_address(
                    REPORT_INTERFACE_QUEUES_WRITABLE,interface,sizeof(CreditInterfaceQueue));
            memw();
            if (USB_SUSPENDED != 0) goto interface_service;
            memw();
            if (REPORT_SUBMIT_BLOCKED[interface] != 0) goto interface_service;
            memw();
            if (REPORT_INTERFACE_BLOCKED[interface] != 0 || queue->extra_pending == 0)
                goto interface_service;
            memw(); unsigned int submitted_low = REPORT_SUBMIT_TIME[interface].low;
            memw(); unsigned int submitted_high = REPORT_SUBMIT_TIME[interface].high;
            if (tx_maintenance_elapsed(now_us,tx_maintenance_timestamp(submitted_low,submitted_high)) > 100000) {
                if (dwc2_in_endpoint_is_busy(0,USB_INTERFACE_ENDPOINTS[interface]) == 0) {
                    InputStateView *state = REPORT_SUBMIT_INPUT_STATES[interface];
                    if (state != NULL) {
                        input_mark_dirty(state);
                        REPORT_SUBMIT_INPUT_STATES[interface] = NULL;
                    }
                    REPORT_SUBMIT_SPLIT[interface] = 0;
                    queue->extra_pending = 0;
                    queue->pending_short_multiple = 0;
                } else {
                    unsigned int endpoint = USB_INTERFACE_ENDPOINTS[interface]&15U;
                    memw();
                    if ((int)DWC2_IN_CONTROL(endpoint) < 0) {
                        memw();
                        if (REPORT_INTERFACE_COMPLETING[interface] != 0 &&
                            REPORT_SUBMIT_CLEAR[interface] == 0) {
                            memw(); unsigned int count = REPORT_BUSY_WATCHDOG_OBSERVATIONS;
                            memw(); REPORT_BUSY_WATCHDOG_OBSERVATIONS = count+1U;
                        }
                        REPORT_SUBMIT_CLEAR[interface] = 1;
                    }
                }
            }
interface_service:
            report_service_interface(interface,0);
            memw();
            if (USB_SUSPENDED == 0 && queue->extra_pending == 0) {
                unsigned int record_count = queue->record_count;
                if (record_count != 0) {
                    memw(); unsigned int recovery_low = REPORT_RECOVERY_EPOCH.low;
                    memw(); unsigned int recovery_high = REPORT_RECOVERY_EPOCH.high;
                    unsigned int force_recovery = 1;
                    if ((recovery_low | recovery_high) != 0) {
                        memw(); recovery_low = REPORT_RECOVERY_EPOCH.low;
                        memw(); recovery_high = REPORT_RECOVERY_EPOCH.high;
                        if (tx_maintenance_elapsed(now_us,tx_maintenance_timestamp(recovery_low,recovery_high)) < 3000 &&
                            REPORT_RECOVERY_MODE < 2) force_recovery = 0;
                    }
                    if (force_recovery != 0) {
                        /* Retain native address arithmetic and LOOP count even
                         * for corrupt counts or an interface beyond LOW16. */
                        unsigned int end = 0x3fcc1150U+(interface&0xffffU)*0x3c0U+record_count*0x54U;
                        unsigned int difference = end-(unsigned int)queue-0x54U;
                        unsigned int loop_count = (((difference>>2)*0x3cf3cf3dU)&0x3fffffffU)+1U;
                        unsigned int record_address = (unsigned int)queue;
                        for (unsigned int remaining = loop_count; remaining != 0; --remaining) {
                            *(volatile unsigned short *)(record_address+0x4eU) = 0xffffU;
                            record_address += 0x54U;
                        }
                        report_schedule_candidate((CreditInterfaceQueue *)queue,
                            now_us,now_us,REPORT_INTERFACE_PERIODS[interface&0xffffU],interface,0);
                    }
                }
            }
            memw(); unsigned int write_count = queue->history_write_count;
            memw(); unsigned int read_count = queue->history_read_count;
            if (write_count != read_count) {
                unsigned int latest_low = queue->latest_time.low;
                unsigned int latest_high = queue->latest_time.high;
                if (tx_maintenance_elapsed(now_us,tx_maintenance_timestamp(latest_low,latest_high)) > 50000) {
                    memw(); write_count = queue->history_write_count;
                    memw(); queue->history_read_count = write_count;
                    queue->pending_start.low = 0;
                    queue->pending_start.high = 0;
                }
            }
            vPortExitCritical(&CREDIT_LOCK);
        }
        service_available = 1;

input_cleanup:
        now_low = (unsigned int)now_us;
        RtosQueue *configuration_mutex = REWRITE_MUTEX;
        if (configuration_mutex != NULL) xQueueSemaphoreTake(configuration_mutex,0xffffffffU);
        memw(); unsigned int changed_low = INPUT_CHANGE_TIME.low;
        memw(); unsigned int changed_high = INPUT_CHANGE_TIME.high;
        unsigned int primary_reset_requested = FIXED_INPUTS[0].enabled;
        unsigned int idle_expired = tx_maintenance_elapsed(now_us,
            tx_maintenance_timestamp(changed_low,changed_high)) > 1000000;
        unsigned int changed = 0;
        unsigned int service_state = 0;
        if (primary_reset_requested != 0) {
            unsigned int primary_work = 0;
            memw(); unsigned int render_state = MOTION_RENDER_STATE;
            if ((render_state&1U) == 0) {
                if (input_has_primary_activity(tx_maintenance_fixed_state(0)) != 0 ||
                    input_has_secondary_activity(tx_maintenance_fixed_state(0)) != 0)
                    primary_work = 1;
            } else {
                memw();
                if (MOTION_RENDER_STATE&8U) primary_work = 1;
            }
            if (primary_work == 0 && input_has_transforms(tx_maintenance_fixed_state(0)) != 0)
                primary_work = 1;
            unsigned int button_override = input_has_button_overrides(tx_maintenance_fixed_state(0));
            if (primary_work != 0 || button_override != 0) {
                if (idle_expired != 0) {
                    input_reset_runtime(tx_maintenance_fixed_state(0));
                    memw(); MOTION_HISTORY.last_riding.low = 0;
                    memw(); MOTION_HISTORY.last_riding.high = 0;
                    memset((void *)MOTION_HISTORY.history16,0,16);
                    memset((void *)MOTION_HISTORY.history32,0,32);
                    motion_configuration_changed();
                }
            } else primary_reset_requested = 0;
        }
        if (idle_expired == 0) {
            primary_reset_requested = 0;
            if (service_available != 0) {
                if (FIXED_INPUTS[1].enabled != 0) tx_maintenance_service_fixed(1);
                if (FIXED_INPUTS[2].enabled != 0) tx_maintenance_service_fixed(2);
            }
        } else {
            memw(); unsigned int pending_injection = MOTION_INJECTION_PENDING;
            unsigned int keyboard_enabled;
            if (pending_injection != 0) {
                memw(); MOTION_INJECTION_PENDING = 0;
                motion_send_render_state(0);
                keyboard_enabled = FIXED_INPUTS[1].enabled;
                service_state = keyboard_enabled;
                changed = pending_injection;
            } else {
                keyboard_enabled = FIXED_INPUTS[1].enabled;
                service_state = primary_reset_requested;
                changed = primary_reset_requested;
            }
            if (keyboard_enabled != 0) {
                if (input_has_forced_controls(tx_maintenance_fixed_state(1)) != 0 ||
                    input_has_transforms(tx_maintenance_fixed_state(1)) != 0) {
                    input_reset_runtime(tx_maintenance_fixed_state(1));
                    changed = 1;
                } else changed = service_state;
                if (service_available != 0 && FIXED_INPUTS[1].enabled != 0)
                    tx_maintenance_service_fixed(1);
            } else service_state = changed;
            if (FIXED_INPUTS[2].enabled != 0) {
                unsigned int forced_controls = input_has_forced_controls(tx_maintenance_fixed_state(2));
                if (forced_controls != 0) {
                    input_reset_runtime(tx_maintenance_fixed_state(2));
                    changed = service_available != 0 ? 1 : forced_controls;
                } else if (input_has_transforms(tx_maintenance_fixed_state(2)) != 0) {
                    input_reset_runtime(tx_maintenance_fixed_state(2));
                    changed = 1;
                }
                if (service_available != 0 && FIXED_INPUTS[2].enabled != 0)
                    tx_maintenance_service_fixed(2);
            }
        }

        for (unsigned int index = 0; (int)index < MOTION_AUX_COUNT; ++index) {
            if (idle_expired != 0) {
                InputStateView *state = (InputStateView *)worker_table_address(
                    AUXILIARY_INPUTS,index,sizeof(AuxiliaryInputBinding));
                unsigned int transforms = input_has_transforms(state);
                if (transforms != 0) {
                    input_reset_runtime(state);
                    changed = transforms;
                }
            }
        }
        unsigned int capture_active = CAPTURE_SESSION_ACTIVE;
        if (idle_expired != 0) {
            if (capture_active != 0) {
                capture_clear_subscriptions();
                memw(); REPORT_CAPTURE_BUTTONS_VALID = 0;
                memw(); REPORT_KEYBOARD_CAPTURE.valid = 0;
                int auxiliary_count = MOTION_AUX_COUNT;
                memw(); REPORT_CONSUMER_CAPTURE.valid = 0;
                if (auxiliary_count > 0) {
                    unsigned int span = (unsigned int)auxiliary_count*0x388U-0x388U;
                    unsigned int loop_count = (((span>>3)*0x0fdbc091U)&0x1fffffffU)+1U;
                    unsigned int valid_address = 0x3fcca0daU;
                    for (unsigned int remaining = loop_count; remaining != 0; --remaining) {
                        *(volatile unsigned char *)valid_address = 0;
                        valid_address += 0x388U;
                    }
                }
                changed = 1;
            }
            if (REWRITE_COUNT != 0) {
                rewrite_update_rule(0xff,0xffff,0,0,0,0,0,NULL,NULL,NULL,0);
                changed = 1;
            }
            memw();
            if (PLAYBACK_ACTIVE != 0 || PLAYBACK_MODE != 0 ||
                clip_ring_retained_bytes(PLAYBACK_RING) != 0 ||
                PLAYBACK_TRANSFORMS.repeat != 0 ||
                PLAYBACK_TRANSFORMS.retain != 0 ||
                PLAYBACK_TRANSFORMS.timed_motion != 0) changed = 1;
            else {
                unsigned int catch_enabled = PACKET_TRIGGER_COUNT;
                unsigned int trigger_count = INPUT_TRIGGER_COUNT;
                unsigned int selection = PLAYBACK_TRANSFORMS.selection;
                if ((catch_enabled | trigger_count | selection) != 0) changed = 1;
                else changed = (unsigned char)changed | (IMPERFECT_CLIP_QUEUE->pending_count != 0);
            }
            playback_reset_runtime();
            if (TRANSFORM_COUNT != 0) {
                memset((void *)TRANSFORM_RULES,0,0x102);
                if (service_available != 0) input_clear_last_controls();
                motion_configuration_changed();
                memw(); (void)PLAYBACK_ACTIVE;
                goto commit_change;
            }
        }

        if ((unsigned char)service_state != 1 && service_available != 0) {
            if (FIXED_INPUTS[0].enabled != 0) {
                memw(); service_state = FIXED_INPUTS[0].last_input_valid;
                if (service_state != 0) {
                    memw();
                    if (USB_SUSPENDED == 0) {
                        if (input_has_secondary_activity(tx_maintenance_fixed_state(0)) != 0)
                            goto eligibility_ready;
                        memw();
                        if (MOVEMENT_RIDING_US == 0 &&
                            input_has_primary_activity(tx_maintenance_fixed_state(0)) != 0)
                            goto eligibility_ready;
                        if (FIXED_INPUTS[0].output_valid != 0) goto eligibility_ready;
                        memw();
                        if (MOTION_RENDER_STATE&4U) goto eligibility_ready;
                    }
                }
            }
            memw(); unsigned int suspended = USB_SUSPENDED;
            service_state = 0;
            if (suspended == 0)
                for (unsigned int index = 0; index < 3; ++index)
                    if (FIXED_INPUTS[index].enabled != 0) {
                        unsigned int work = input_has_pending_work(tx_maintenance_fixed_state(index));
                        if (work != 0) { service_state = work; break; }
                    }
        }
eligibility_ready:
        memw();
        if (PLAYBACK_ACTIVE == 0)
            service_available &= service_state | (PLAYBACK_ACTION_COUNT != 0);
        if (changed != 0) {
commit_change:
            memw();
            memw(); unsigned int sequence = INPUT_CHANGE_SEQUENCE;
            memw(); unsigned int committed = INPUT_CHANGE_COMMITTED;
            if (committed == 0) INPUT_CHANGE_EPOCH = INPUT_CHANGE_EPOCH+1U;
            INPUT_CHANGE_COMMITTED = 1;
            INPUT_CHANGE_ACKNOWLEDGED = sequence;
        }
        configuration_mutex = REWRITE_MUTEX;
        if (configuration_mutex != NULL) xQueueGenericSend(configuration_mutex,NULL,0,0);
        if (primary_reset_requested != 0) {
            memw();
            if (MOTION_RENDER_STATE&1U) input_queue_motion(0,0,0,0,4,now_low);
        }
        if (service_available != 0) input_ensure_timer_armed();
        memw(); USB_FRAME_CREDIT_DIRTY = 1;
        link_kick_fast_tx();

power_notifications:
        if (notifications&4U) {
            memw();
            if (CLONE_ACTIVE != 0) out_publish_power_state();
        }
        if ((notifications&8U) == 0) continue;
        memw();
        if (USB_SUSPENDED == 0) continue;
        memw(); unsigned char previous_wake_request = REPORT_WAKE_REQUEST;
        if (previous_wake_request != 0) continue;
        memw(); REPORT_WAKE_REQUEST = 1;
        if (usbd_set_remote_wakeup(0) == 0) {
            memw(); unsigned int resumes = REPORT_WAKE_RESUMES;
            memw(); REPORT_WAKE_RESUMES = resumes+1U;
            usbd_event_resume_handler(0);
        } else {
            memw(); REPORT_WAKE_REQUEST = previous_wake_request;
            memw();
            if (CLONE_ACTIVE != 0) out_publish_power_state();
        }
    }
}
