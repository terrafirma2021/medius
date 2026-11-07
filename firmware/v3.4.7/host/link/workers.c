/* Medius v3.4.7 host — link/workers.c.
 * Recovered C and native assembly, grouped for source navigation.
 * Original entry addresses, firmware-byte hashes and function comments follow.
 */

#include "../include/types.h"

/* Native entry: 0x4037b590. */
/*
 * Medius v3.4.7 — host application; 0x4037b590.
 *
 * Drains link transmit queues and the fast callback path.
 *
 * Calls: ulTaskGenericNotifyTake, link_frame_encode, link_uart_transmit_wait, xQueuePeek,
 * xQueueReceive.
 *
 * Indirect calls: fast payload builder and two TX admission sites.
 *
 * Original function-byte SHA-256:
 * ef9554e41f00a869f94a304f049614e6cecada69a8312a6c50ebf338806be788.
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

/* Native entry: 0x4037f7ec. */
/*
 * Medius v3.4.7 — host application; 0x4037f7ec.
 *
 * Drains received UART link frames and invokes the registered frame dispatcher.
 *
 * Calls: link_frame_dispatch, ulTaskGenericNotifyTake, vPortExitCritical, xPortEnterCriticalTimeout, xQueueReceive.
 *
 * Original function-byte SHA-256:
 * f66479ea30fde0a9e1507ad1674f12225f71ea0be44aea1162bf847093fe5509.
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
            volatile LinkRxDescriptor *descriptor = &LINK_RX_DESCRIPTORS[slot];
            unsigned short payload_offset = descriptor->payload_offset;
            unsigned int timestamp = descriptor->received_at_us_low;
            unsigned short length = descriptor->length;
            unsigned char flags = descriptor->flags;
            unsigned char type = descriptor->type;
            link_frame_dispatch(type, flags,
                LINK_RX_PAYLOAD + payload_offset, length, timestamp);
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

/* Native entry: 0x403894e8. */
/* Original function-byte SHA-256:
 * 442fe3046393c812a2d9f77366ace898169a0b5882e497d95625a716281cfa13. */
/* Consume the latest device-to-host credit packet in task context.
 * unused is ignored. Never normally returns. Wait on notification index0 with
 * clear-on-exit1 and infinite ticks; ignore its count. Under the credit lock,
 * read pending length as one unsigned HALFWORD, copy exactly that many bytes
 * into a private64-byte packet, clear pending length with one HALFWORD store,
 * and unlock. Even length0 invokes memcpy before clearing/unlocking; it then
 * waits again without applying records. A nonzero length applies the private
 * snapshot outside the lock and immediately returns to notification waiting.
 *
 * Receiver0x40376e14 clamps published lengths to64; this worker adds no bounds
 * check and trusts that invariant. It does not clear the packet or global byte
 * suffix, queue every intermediate update, validate records, or retry an apply.
 * The local packet is borrowed only during the synchronous apply call. The
 * native96-byte stack frame includes the windowed ABI area, not96 payload bytes.
 * Task creation sets stack3072,priority16,core0; no independent credit timer.
 */
void medius_task_credit(void *unused)
{
    (void)unused;
    CreditPacket packet;
    for (;;) {
        (void)ulTaskGenericNotifyTake(0,1,0xffffffffU);
        (void)xPortEnterCriticalTimeout(&CREDIT_LOCK,-1);
        unsigned short length = MEDIUS_CREDIT_PENDING_LENGTH;
        memcpy(&packet,(const void *)MEDIUS_CREDIT_PENDING_PACKET,length);
        MEDIUS_CREDIT_PENDING_LENGTH = 0;
        vPortExitCritical(&CREDIT_LOCK);
        if (length != 0) medius_hid_apply_credit_records((unsigned char *)&packet,length);
    }
}

/* Native entry: 0x42020b78. */
/*
 * Medius v3.4.7 — host application; 0x42020b78.
 *
 * Probes silent links and cycles the inter-chip UART baud rate.
 *
 * Calls: vTaskDelay, esp_log_timestamp, esp_log_write, esp_timer_get_time, link_frame_enqueue,
 * link_parser_reset, uart_set_baudrate.
 *
 * Original function-byte SHA-256:
 * f73c95284646bf6fc3873fed99cdeaa65d1ee2365f45c365b235d9c6573c22d7.
 */

/*
 * Probes an uninhibited silent link and cycles its three native baud entries.
 * unused_argument: ignored task context. Returns: never normally returns.
 * Created only for link role 1: priority 2, stack 3072 bytes, no core affinity.
 * Normal host startup uses role 1, so this entry is normally created.
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
        unsigned int probe[4] = {0, 0, 0, 0};
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

/* Native entry: 0x420212f8. */
/* Original function-byte SHA-256:
 * fd529a9b1e62c98cd04d1259d20883a593a5797ed4a8edb412cd361483b0b989. */
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
                    unsigned long long tolerance = (paired_trip >> 1) + 50ULL + magnitude / 5000U;
                    if ((long long)residual > (long long)tolerance ||
                        (long long)residual < (long long)(0ULL - tolerance))
                        memset((void *)filter,0,624);
                }
                unsigned int recent_head = filter->recent_head;
                unsigned char recent_count = filter->recent_count;
                filter->offsets_us[recent_head] = offset;
                filter->round_trips_us[recent_head] = round_trip;
                filter->times_us_low[recent_head] = exchange.local_start_us;
                filter->recent_head = (unsigned char)((recent_head + 1U) & 15U);
                if (recent_count < 16) filter->recent_count = recent_count + 1U;
                unsigned char window_valid = filter->window_valid;
                filter->ready = 1;
                if (window_valid == 0) goto start_window;
                if ((int)(exchange.local_start_us - filter->window_started_us_low) > 999999) {
                    unsigned int head = filter->history_head;
                    unsigned int time = filter->window_time_us_low;
                    filter->history[head].time_us_low = time;
                    unsigned int previous_trip = filter->window_round_trip_us;
                    unsigned int previous_offset = filter->window_offset_us;
                    filter->history[head].round_trip_us = previous_trip;
                    filter->history[head].offset_us = previous_offset;
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
        unsigned int probe[4] = {0,0,0,0};
        memcpy(probe,&sequence,4);
        (void)link_frame_enqueue(0x25,0,probe,16,0,0);
        ++probe_count;
    }
}

/* Native entry: 0x4202431c. */
/* Original function-byte SHA-256:
 * d2401c728b3cbc4c787f0181af0ba1e8276ec8eda6bf37e9cff89af55a3f083c. */
/*
 * Host heartbeat task; unused task argument. Repeatedly delay100 RTOS ticks,
 * sample microsecond clock LOW and send link type1/flags0 with two WORDs:
 * wrapping counter (initial0), timestamp. Nonblocking link admission result is
 * discarded by send-nowait. Run frame-clock maintenance, then sample the first
 * slow HID-active predicate, increment counter modulo32, and enable SOF IRQs
 * only for a nonzero predicate. No SOF disable or termination path.
 * This is relative task-delay scheduling, not a dedicated/software timer:
 * delay plus execution/queue/mutex time determines the interval. Maintenance
 * can wait indefinitely on its mutex;100 ticks is not a heartbeat deadline.
 */
void medius_task_link_hb(void *unused_argument)
{
    (void)unused_argument;
    unsigned int counter = 0;
    for (;;) {
        vTaskDelay(100);
        unsigned int heartbeat[2];
        heartbeat[1] = (unsigned int)esp_timer_get_time();
        heartbeat[0] = counter;
        medius_link_send_nowait(1,0,heartbeat,8);
        medius_host_frame_clock_maintenance();
        unsigned char slow_hid_active = medius_host_first_slow_hid_active();
        ++counter;
        if (slow_hid_active != 0) medius_host_set_sof_interrupt(1);
    }
}
