/* Medius v3.4.7 device — link/control.c.
 * Recovered C and native assembly, grouped for source navigation.
 * Original entry addresses, firmware-byte hashes and function comments follow.
 */

#include "../include/types.h"

/* Native entry: 0x4037c8ec. */
/*
 * Medius v3.4.7 — device application; 0x4037c8ec.
 *
 * Publishes a decoded external control frame to the UART0 receive ring.
 *
 * Calls: _frxt_setup_switch, vTaskGenericNotifyGiveFromISR, esp_timer_get_time, memcpy.
 *
 * Original function-byte SHA-256:
 * 5788f09fc62b6bd99a83e823278c189fab6e27096dd30b883b6182d8f7837cb4.
 */

/*
 * Publishes one decoded UART0 frame into the 16 KiB control receive ring.
 *
 * opcode, sequence: the two decoded frame bytes.
 * payload: readable input for length bytes; unused when length is zero.
 * length: payload bytes; the stored payload area is rounded up to four bytes.
 * context: unused parser-callback argument, omitted by the raw decompile.
 *
 * Takes MEMW-ordered write/read cursor snapshots. Reserves an eight-byte
 * header plus aligned payload, keeping one ring byte unavailable so equal
 * cursors mean empty. A wrapped record also consumes the unused tail.
 * Insufficient space increments the overflow counter and returns.
 *
 * Writes a 0xffff length marker when wrapping leaves room for a header;
 * shorter tails are skipped by the consumer. Stores the low 32 bits of
 * esp_timer_get_time(), copies the exact payload, and leaves padding alone.
 * Both native publication barriers precede the write-cursor store.
 *
 * If the saved cursors were equal, notifies ctrl_rx at index zero and
 * requests an ISR-exit switch when a higher-priority task was awakened.
 * No local lock or producer serialization is supplied. Requires one
 * serialized producer, valid aligned cursors, and a live input buffer.
 */
void control_receive_publish(unsigned char opcode, unsigned char sequence,
                               const unsigned char *payload, unsigned short length,
                               void *context)
{
    (void)context;

    memw();
    unsigned int write_offset = CONTROL_RX_WRITE_OFFSET;
    memw();
    unsigned int read_offset = CONTROL_RX_READ_OFFSET;

    unsigned int payload_bytes = length;
    unsigned int aligned_payload_bytes = (payload_bytes + 3U) & ~3U;
    unsigned int record_bytes = sizeof(ControlRxRecordHeader) + aligned_payload_bytes;
    unsigned int used_bytes =
        (write_offset - read_offset) & CONTROL_RX_CURSOR_MASK;
    unsigned int next_write_offset = write_offset + record_bytes;
    unsigned int tail_bytes = next_write_offset > CONTROL_RX_RING_BYTES
        ? CONTROL_RX_RING_BYTES - write_offset : 0U;

    if (used_bytes + tail_bytes + record_bytes > CONTROL_RX_CURSOR_MASK) {
        memw();
        unsigned int dropped_frames = CONTROL_RX_OVERFLOW_COUNT;
        memw();
        CONTROL_RX_OVERFLOW_COUNT = dropped_frames + 1U;
        return;
    }

    unsigned int record_offset = write_offset;
    if (next_write_offset > CONTROL_RX_RING_BYTES) {
        if (tail_bytes >= sizeof(ControlRxRecordHeader)) {
            volatile ControlRxRecordHeader *wrap_marker =
                (volatile ControlRxRecordHeader *)(CONTROL_RX_RING + write_offset);
            wrap_marker->payload_length = 0xffffU;
        }
        record_offset = 0;
        next_write_offset = record_bytes;
    }

    volatile ControlRxRecordHeader *record =
        (volatile ControlRxRecordHeader *)(CONTROL_RX_RING + record_offset);
    record->payload_length = length;
    record->opcode_sequence = (unsigned short)(opcode | ((unsigned int)sequence << 8));
    record->timestamp_us_low = (unsigned int)esp_timer_get_time();
    if (payload_bytes != 0) {
        memcpy(CONTROL_RX_RING + record_offset + sizeof(*record),
               payload, payload_bytes);
    }

    memw();
    next_write_offset &= CONTROL_RX_CURSOR_MASK;
    memw();
    CONTROL_RX_WRITE_OFFSET = next_write_offset;

    if (write_offset == read_offset) {
        RtosTask *receive_task = CONTROL_RX_TASK;
        if (receive_task != NULL) {
            int higher_priority_task_woken = 0;
            vTaskGenericNotifyGiveFromISR(receive_task, 0, &higher_priority_task_woken);
            if (higher_priority_task_woken != 0) {
                _frxt_setup_switch();
            }
        }
    }
}

/* Native entry: 0x40383c38. */
/* Original function-byte SHA-256:
 * a821a4eab76468e7c64fb269d3d7b16c0b9c6a902d8b8dad761659ef6f58960b. */
/* Synchronously fragment total LOW16 bytes using chunk_limit LOW16 clamped
 * to1..506. A512-byte stack frame contains total/offset as one LE32 store,
 * count as LE16, then exact payload bytes. Invoke callback(frame,count+6,
 * context) even for total0/count0. Callback has no result; storage is borrowed
 * only until return and must be copied if retained. Offset advances modulo16
 * until reaching total. No callback/source NULL check, allocation or lock.
 * Unused stack bytes remain untouched; no encoding/CRC or transport send here. */
void control_fragment_emit(const unsigned char *data,unsigned short total,
    unsigned short chunk_limit,FragmentCallback callback,void *context)
{
    unsigned int chunk_size = chunk_limit;
    if (chunk_size > 506) chunk_size = 506;
    if (chunk_size == 0) chunk_size = 1;
    unsigned int offset = 0;
    ControlFragmentFrame frame;
    do {
        unsigned int count = ((unsigned int)total - offset) & 65535U;
        if (count > chunk_size) count = chunk_size;
        frame.total_and_offset = (unsigned int)total | (offset << 16);
        frame.count = (unsigned short)count;
        if (count != 0) memcpy(frame.data,data + offset,count);
        callback((const unsigned char *)&frame,(unsigned short)(count + 6U),context);
        offset = (offset + count) & 65535U;
    } while (offset < total);
}

/* Native entry: 0x40383ca4. */
/* Original function-byte SHA-256:
 * 3d3a301a99c0b22fa51003e63dfc0ae2e393e1cd33c42d55e656776b363677d2. */
/* Consume one total/offset/count LE16 header plus bytes. Require length>=6
 * and LOW16(count+6)==length; read count5,4, then offset3,total1,offset2,total0.
 * Offset0 requires total<=2057 and stores total, used0, flagsHALFWORD1
 * (active1,error0). A continuation requires active BYTE!=0 and matching total;
 * inactive continuation returns0 unchanged. Require used==offset and
 * offset+count<=total. Nonzero count copies, then RELOADS used and total.
 * Store LOW16(used+count); equality with total clears only active BYTE and
 * returns1. Incomplete returns0. Invalid input stores flagsHALFWORD0x100
 * (active0,error1), retaining lengths/payload. Capacity is2058 but accepted
 * total max2057. Total0 completes. Zero-byte continuation can make no progress.
 * No NULL, alias, source-lifetime or coherent-state lock checks; require valid
 * assembly invariants. Native count+6 wrap check is deliberately retained. */
int control_fragment_accept(ControlAssembly *assembly,
    const unsigned char *fragment,unsigned short length)
{
    volatile ControlAssembly *state = assembly;
    const volatile unsigned char *input = fragment;
    if (length < 6) goto invalid;
    unsigned int count_high = input[5];
    unsigned int count_low = input[4];
    unsigned int count = (count_high << 8) | count_low;
    if (((count + 6U) & 65535U) != length) goto invalid;
    unsigned int offset_high = input[3];
    unsigned int total_high = input[1];
    unsigned int offset_low = input[2];
    unsigned int total_low = input[0];
    unsigned int offset = (offset_high << 8) | offset_low;
    unsigned int total = (total_high << 8) | total_low;
    if (offset == 0) {
        if (total > 2057) goto invalid;
        state->total = (unsigned short)total;
        state->used = 0;
        state->flags = 1;
    } else {
        if (state->active == 0) return 0;
        if (total != state->total) goto invalid;
    }
    unsigned int used = state->used;
    if (used != offset || offset + count > total) goto invalid;
    if (count != 0) {
        memcpy(assembly->payload + offset,fragment + 6,count);
        used = state->used;
        total = state->total;
    }
    unsigned short next_used = (unsigned short)(used + count);
    state->used = next_used;
    if (next_used == total) {
        state->active = 0;
        return 1;
    }
    return 0;
invalid:
    state->flags = 0x100;
    return 0;
}

/* Native entry: 0x40395040. */
/* Original function-byte SHA-256:
 * 7d5863fb693136aaec03a63ce9a3f58421f4d71b91fd34fa0e9a358ca0442af1. */
/* Snapshot signed64 clock and add50,000us modulo64. Loop: MEMW, read full
 * operation word, MEMW; zero returns. Otherwise MEMW, read block BYTE; nonzero
 * returns. Read current signed64 clock; at/after deadline returns, otherwise
 * delay ONE scheduler tick and repeat. Signed high-word/unsigned low-word
 * comparison is retained; the raw decompiler wrongly called its low comparison
 * unreachable. No result, lock, hardware busy clear or delivery guarantee.
 * Requested50ms budget can be exceeded by scheduling or the tick delay. */
void control_wait_idle_50ms(void)
{
    long long started_us = esp_timer_get_time();
    long long deadline_us = (long long)((unsigned long long)started_us + 50000U);
    for (;;) {
        memw();
        unsigned int operation = CONTROL_OPERATION_ACTIVE;
        memw();
        if (operation == 0)
            return;
        memw();
        if (REPORT_FAST_GLOBAL_BLOCK != 0)
            return;
        if (esp_timer_get_time() >= deadline_us)
            return;
        vTaskDelay(1);
    }
}

/* Native entry: 0x4200a07c. */
/*
 * Medius v3.4.7 — device application; 0x4200a07c.
 *
 * Writes UART0 bytes immediately when possible and queues the remainder.
 *
 * Calls: memcpy, vPortExitCritical, xPortEnterCriticalTimeout.
 *
 * Called by: control_send_frame, control_try_send_encoded.
 *
 * Original function-byte SHA-256:
 * 6c77d30c4f296f4e81c4938d92718ff0c14f7bb8a50fc9b8a9b05821a5315aa1.
 */

/*
 * Admits length bytes to the control UART0 transmitter under its TX spinlock.
 * bytes must cover length readable bytes; length is an unsigned 32-bit input.
 * Returns 1 after admission or 0 when queued_bytes + length exceeds 4095.
 * This addition is native 32-bit arithmetic: callers must supply bounded
 * lengths so it cannot wrap. No new overflow or NULL checks are inserted.
 *
 * If the software ring starts empty, sends as many bytes as fit directly to
 * the 128-byte hardware FIFO. In that path only, the remaining length is
 * narrowed to 16 bits before further processing. A completely direct send
 * returns without publishing a ring cursor or enabling TX-empty interrupts.
 *
 * Remaining bytes are copied into the 4 KiB ring, splitting at its end if
 * necessary. MEMW precedes publication of the updated write cursor; TX-empty
 * interrupts are then enabled. Even a zero-length call takes the lock; with
 * an already nonempty ring it still follows the zero-byte copy/publication
 * path and enables that interrupt. Other interrupt-enable bits are retained.
 *
 * Requires initialized UART/ring/mux, valid offsets and FIFO count <=128,
 * readable source, and serialization through the same TX lock. Critical
 * entry waits indefinitely and its result is ignored. No allocation, task
 * delay, wait for wire completion or delivery acknowledgement is supplied.
 */
int control_tx_enqueue(const unsigned char *bytes, unsigned int length)
{
    (void)xPortEnterCriticalTimeout(&CONTROL_TX_LOCK, -1);
    memw();
    unsigned int admission_write = CONTROL_TX_WRITE_OFFSET;
    memw();
    unsigned int admission_read = CONTROL_TX_READ_OFFSET;
    unsigned int queued_bytes =
        (admission_write - admission_read) & CONTROL_TX_CURSOR_MASK;
    if (queued_bytes + length > CONTROL_TX_CURSOR_MASK) {
        vPortExitCritical(&CONTROL_TX_LOCK);
        return 0;
    }

    UartRegisterView *uart = CONTROL_UART0;
    unsigned int remaining_bytes = length;
    if (queued_bytes == 0) {
        memw();
        unsigned int fifo_status = uart->status;
        unsigned int fifo_count = (fifo_status >> 16) & UART_FIFO_COUNT_MASK;
        unsigned int fifo_space = UART_FIFO_CAPACITY - fifo_count;
        unsigned int direct_bytes = fifo_space < length ? fifo_space : length;
        for (unsigned int index = 0; index < direct_bytes; ++index) {
            unsigned int byte_to_send = bytes[index];
            memw();
            uart->fifo = byte_to_send;
        }
        bytes += direct_bytes;
        remaining_bytes = (length - direct_bytes) & 0xffffU;
        if (remaining_bytes == 0) {
            vPortExitCritical(&CONTROL_TX_LOCK);
            return 1;
        }
    }

    memw();
    unsigned int write_offset = CONTROL_TX_WRITE_OFFSET;
    unsigned int tail_bytes = CONTROL_TX_RING_BYTES - write_offset;
    unsigned int first_copy_bytes = tail_bytes < remaining_bytes
        ? tail_bytes : remaining_bytes;
    memcpy(CONTROL_TX_RING + write_offset, bytes, first_copy_bytes);
    if (tail_bytes < remaining_bytes)
        memcpy(CONTROL_TX_RING, bytes + first_copy_bytes,
                 remaining_bytes - first_copy_bytes);

    unsigned int next_write =
        (write_offset + remaining_bytes) & CONTROL_TX_CURSOR_MASK;
    memw();
    CONTROL_TX_WRITE_OFFSET = next_write;
    memw();
    unsigned int enabled_irqs = uart->interrupt_enable;
    memw();
    uart->interrupt_enable = enabled_irqs | UART_TX_EMPTY_IRQ;
    vPortExitCritical(&CONTROL_TX_LOCK);
    return 1;
}

/* Native entry: 0x4200a158. */
/*
 * Medius v3.4.7 — device application; 0x4200a158.
 *
 * Consumes UART0 control frames and dispatches application API commands.
 *
 * Calls: ulTaskGenericNotifyTake.
 *
 * Typed first-frame, application-frame and empty-ring callback sites.
 *
 * Original function-byte SHA-256:
 * 3d1234f330ec7594e979ed152b25fad21de422a85d2d939e5530d4daa5d639a3.
 */


/*
 * ctrl_rx task entry: notification index 0, clear-on-exit, wait 100 ticks.
 * Created by control_uart_init with a 6,144-byte stack, priority 12
 * and CPU 0 affinity. The native creator entry is 0x4200a25c.
 * argument is unused. The task drains the ring after a notification or
 * timeout, calls the optional empty-ring hook, then waits again forever.
 * The wait is a scheduler timeout, not a guaranteed service interval.
 *
 * Uses ordered cursor snapshots and a fresh read offset for each record.
 * Skips short tails and 0xffff length markers by publishing read offset 0.
 * Latches has-received-frame and the record's low timestamp before callbacks;
 * this task never clears that latch. The first-frame hook runs only when
 * the prior latch byte was zero.
 *
 * Opcode, sequence and callback length are saved before that hook. The
 * application callback and context are loaded afterward, so the hook can
 * install a new handler. Payload bytes remain owned by this record until
 * dispatch returns; callers must finish reading them before returning.
 *
 * Rereads the header length after callbacks to advance the read cursor,
 * retaining the native behavior if a callback changes it. The MEMW precedes
 * cursor publication. Requires valid producer-created records and one
 * consumer; supplies no extra header-length check, lock or callback timeout.
 */
void control_receive_task(void *argument)
{
    (void)argument;
    for (;;) {
        (void)ulTaskGenericNotifyTake(0, 1, 100);
        for (;;) {
            memw();
            unsigned int empty_check_read = CONTROL_RX_READ_OFFSET;
            memw();
            unsigned int published_write = CONTROL_RX_WRITE_OFFSET;
            if (empty_check_read == published_write) {
                break;
            }

            memw();
            memw();
            unsigned int read_offset = CONTROL_RX_READ_OFFSET;
            unsigned int tail_bytes = CONTROL_RX_RING_BYTES - read_offset;
            if (tail_bytes < sizeof(ControlRxRecordHeader)) {
                memw();
                CONTROL_RX_READ_OFFSET = 0;
                continue;
            }

            volatile ControlRxRecordHeader *record =
                (volatile ControlRxRecordHeader *)(CONTROL_RX_RING + read_offset);
            unsigned short payload_length = record->payload_length;
            unsigned int payload_offset = read_offset + sizeof(*record);
            if (payload_length == 0xffffU) {
                memw();
                CONTROL_RX_READ_OFFSET = 0;
                continue;
            }

            memw();
            unsigned char had_received_frame = CONTROL_RX_HAS_RECEIVED_FRAME;
            unsigned int timestamp_us_low = record->timestamp_us_low;
            memw();
            CONTROL_RX_HAS_RECEIVED_FRAME = 1;
            CONTROL_RX_LAST_TIMESTAMP_US_LOW = timestamp_us_low;
            unsigned char sequence = record->sequence;
            unsigned char opcode = record->opcode;

            if (had_received_frame == 0) {
                ControlRxHook first_frame_hook = CONTROL_RX_FIRST_FRAME_HOOK;
                if (first_frame_hook != NULL) {
                    first_frame_hook();
                }
            }

            FrameCallback handler = CONTROL_RX_FRAME_HANDLER;
            if (handler != NULL) {
                void *context = CONTROL_RX_FRAME_CONTEXT;
                handler(opcode, sequence, CONTROL_RX_RING + payload_offset,
                        payload_length, context);
            }

            unsigned int current_payload_length = record->payload_length;
            unsigned int aligned_payload_bytes = (current_payload_length + 3U) & ~3U;
            unsigned int next_read_offset =
                (payload_offset + aligned_payload_bytes) & CONTROL_RX_CURSOR_MASK;
            memw();
            CONTROL_RX_READ_OFFSET = next_read_offset;
        }

        ControlRxHook empty_ring_hook = CONTROL_RX_EMPTY_RING_HOOK;
        if (empty_ring_hook != NULL) {
            empty_ring_hook();
        }
    }
}

/* Native entry: 0x4200a228. */
/*
 * Medius v3.4.7 — device application; 0x4200a228.
 *
 * Reads the sum of external UART receive-drop counters.
 *
 * Called by: control_command_dispatch.
 *
 * Original function-byte SHA-256:
 * 18d4487ba77d93db5d294adfc1a9a1e4464b5f2abb68358665e424f0fae5d4ce.
 */


/*
 * Returns the modulo-2^32 sum of ring-admission failures and serviced UART0
 * RX-FIFO-overflow events. These are event counters, not lost-byte counts.
 * Reads the ring counter first, then the FIFO counter, with one MEMW before
 * each load. The two samples are not an atomic snapshot and are not cleared.
 */
unsigned int control_rx_drop_count(void)
{
    memw();
    unsigned int ring_overflows = CONTROL_RX_OVERFLOW_COUNT;
    memw();
    unsigned int fifo_overflows = CONTROL_UART_RX_FIFO_OVERFLOW_COUNT;
    return ring_overflows + fifo_overflows;
}

/* Native entry: 0x4200a24c. */
/*
 * Medius v3.4.7 — device application; 0x4200a24c.
 *
 * Installs the UART0 control-frame callback and context.
 *
 * Called by: control_protocol_init.
 *
 * Original function-byte SHA-256:
 * 8415d957d094993b9c4b89471686118013cedb085380f7d3e3349648ad5af078.
 */


/*
 * Installs the optional application frame handler and its borrowed context.
 * Stores the callback first and context second, without a lock or barrier.
 * NULL disables dispatch. The pair is not published atomically; the caller
 * must serialize updates with any consumer that could run concurrently.
 */
void control_set_frame_handler(FrameCallback callback, void *context)
{
    CONTROL_RX_FRAME_HANDLER = callback;
    CONTROL_RX_FRAME_CONTEXT = context;
}

/* Native entry: 0x4200a3b8. */
/* Original function-byte SHA-256:
 * 96330f92b18b6dcfb9ec94a7a34ef34d56bc3922c02298f86502f107b5d7d356. */
/* Synchronously encode and admit a control reply in the caller's context.
 * Opcode/sequence narrow8, length narrows16. Snapshot TX mutex; absent returns.
 * Take that handle with infinite tick wait, ignoring success. Encode into the
 * shared520-byte scratch buffer with capacity520. Negative encoder result skips
 * admission; otherwise use LOW16 encoded length. Attempt byte admission up to
 * 200 times, delay ONE scheduler tick after EVERY failure, including the last.
 * Any nonzero enqueue result stops retrying. Release the CURRENT reloaded mutex
 * with queue-send(NULL,0,back), ignoring its result; it can differ from the
 * initially acquired handle if concurrently replaced. No success/error return,
 * extra payload check, UART drain or wire-delivery acknowledgement. The separately
 * reviewed encoder rejects payload>512 and writes length+7 bytes on success. */
void control_send_frame(unsigned char opcode,unsigned char sequence,
    const void *payload,unsigned int length)
{
    RtosQueue *mutex = CONTROL_TX_MUTEX;
    unsigned short payload_length = (unsigned short)length;
    if (mutex == NULL)
        return;
    xQueueSemaphoreTake(mutex,0xffffffffU);
    int encoded_length = link_frame_encode(CONTROL_TX_SCRATCH,520,
        opcode,sequence,payload,payload_length);
    if (encoded_length >= 0) {
        unsigned short bytes = (unsigned short)encoded_length;
        unsigned int attempts_left = 200;
        do {
            if (control_tx_enqueue(CONTROL_TX_SCRATCH,bytes) != 0)
                break;
            --attempts_left;
            vTaskDelay(1);
        } while (attempts_left != 0);
    }
    xQueueGenericSend(CONTROL_TX_MUTEX,NULL,0,0);
}

/* Native entry: 0x4200a488. */
/* Original function-byte SHA-256:
 * ef5027918079d45c249290bb73038fb8a43e19048eab31453110b43082a8b0ce. */
/* Attempt admission of an already encoded frame, length LOW16. Snapshot
 * mutex; absent or zero length returns0 without locking or touching bytes.
 * Take saved mutex indefinitely (result ignored); under TX spinlock sample
 * write cursor, read cursor, UART0 status with three distinct native MEMWs.
 * Unlock, then require ((write-read)&4095)+FIFO_count+length<=2048; no byte
 * currently in the serializer is counted. If within budget, call TX enqueue
 * once and retain its raw32-bit result; otherwise result0. Release the CURRENT
 * reloaded mutex via queue-send(NULL,0,back), ignore that result and return
 * admission result. Snapshot does not reserve space and may become stale.
 * No input/CRC validation, retry, task delay, drain or delivery guarantee. */
int control_try_send_encoded(const unsigned char *bytes,unsigned int length)
{
    RtosQueue *mutex = CONTROL_TX_MUTEX;
    unsigned short byte_count = (unsigned short)length;
    if (mutex == NULL || byte_count == 0)
        return 0;
    xQueueSemaphoreTake(mutex,0xffffffffU);
    xPortEnterCriticalTimeout(&CONTROL_TX_LOCK,-1);
    memw();
    unsigned int write_offset = CONTROL_TX_WRITE_OFFSET;
    memw();
    unsigned int read_offset = CONTROL_TX_READ_OFFSET;
    memw();
    unsigned int fifo_status = CONTROL_UART0->status;
    unsigned int fifo_count = (fifo_status >> 16) & UART_FIFO_COUNT_MASK;
    vPortExitCritical(&CONTROL_TX_LOCK);
    unsigned int outstanding = ((write_offset - read_offset) & CONTROL_TX_CURSOR_MASK)
                               + fifo_count + byte_count;
    int admitted = 0;
    if (outstanding <= 2048)
        admitted = control_tx_enqueue(bytes,byte_count);
    xQueueGenericSend(CONTROL_TX_MUTEX,NULL,0,0);
    return admitted;
}

/* Native entry: 0x4200a514. */
/*
 * Medius v3.4.7 — device application; 0x4200a514.
 *
 * Reads whether the external control receive task has dispatched a frame.
 *
 * Called by: device_log_hook, app_main, device_link_message.
 *
 * Original function-byte SHA-256:
 * b75f4c70db4775138d93af03cf1b43df20f8f36809960694f55d69f8028c532c.
 */


/*
 * Returns the raw has-received-frame latch byte after MEMW.
 * ctrl_rx sets it before its first-frame/application callbacks and never
 * clears it here. This reports received control traffic; it does not test
 * USB cable presence or prove that a subsequent log was delivered.
 */
unsigned char control_pc_has_sent_frame(void)
{
    memw();
    return CONTROL_RX_HAS_RECEIVED_FRAME;
}

/* Native entry: 0x4200a534. */
/* Original function-byte SHA-256:
 * f5aa1babe751457c5c72fc9717d9b2611da83e01ceda6f0e51d183cd121d2e2c. */
/* Dedicated ctrlevt task: argument unused. Publish CURRENT task handle,
 * subscribe it to watchdog, snapshot generation. Each iteration feeds watchdog,
 * reads generation, then samples TX budget BEFORE outstanding byte count.
 * A generation change bypasses old batch retry/held-event reuse: it starts a
 * fresh selection and discards the old encoded batch and retained event.
 * Otherwise a refused batch is retried whole; each further failure delays1
 * scheduler tick. A retained event waits1 tick while LOW16(length+8)>budget.
 * New selection requires budget>20. Under pending>1024, skip the last event
 * ring; no event then delays1 tick. Without pressure, no event waits on task
 * notification index0/clear1/up to1000 ticks. No event is selected at low budget.
 * Build into the shared buffer with capacity=min(budget,1024). Encode opcode,
 * sequence, payload and LOW16 length; successful lengths accumulate modulo16.
 * Stop when bytes+199>=capacity or selection finds no next event. Encoding
 * failure retains the current event. Submit a nonempty batch once immediately;
 * first refusal keeps it WITHOUT an immediate delay, for next-iteration retry.
 * Empty batches loop without a delay. A malformed held length can consequently
 * fail encoding repeatedly without yielding; no new bound check is inserted.
 * No exit, private timer, copied ownership, delivery acknowledgement or measured
 * scheduling guarantee. Ring selection/encoding/admission are separately named. */
void control_event_task(void *argument)
{
    (void)argument;
    control_event_set_task(xTaskGetCurrentTaskHandle());
    watch_current_task();
    unsigned int previous_generation = control_event_generation();
    unsigned short encoded_bytes = 0;
    int retained_event = 0;
    ControlEventWork event;
    for (;;) {
        feed_current_task_watchdog();
        unsigned int generation = control_event_generation();
        unsigned int budget = control_tx_budget_bytes();
        unsigned int pending = control_tx_pending_bytes();
        unsigned int pressure = pending > 1024;
        unsigned short capacity;
        if (previous_generation != generation)
            goto select_new_event;
        if (encoded_bytes != 0) {
            if (control_try_send_encoded(CONTROL_EVENT_TX_BUFFER,encoded_bytes) != 0)
                encoded_bytes = 0;
            else
                vTaskDelay(1);
            previous_generation = generation;
            continue;
        }
        if (retained_event != 0) {
            if ((unsigned short)(event.length + 8U) > budget) {
                vTaskDelay(1);
                previous_generation = generation;
                continue;
            }
            capacity = (unsigned short)(budget < 1024 ? budget : 1024);
            goto encode_events;
        }
    select_new_event:
        if (budget <= 20) {
            retained_event = 0;
            vTaskDelay(1);
            encoded_bytes = 0;
            previous_generation = generation;
            continue;
        }
        retained_event = control_event_take(&event.opcode,&event.sequence,
            event.payload,&event.length,pressure);
        if (retained_event == 0) {
            if (pending > 1024)
                vTaskDelay(1);
            else
                ulTaskGenericNotifyTake(0,1,1000);
            encoded_bytes = 0;
            previous_generation = generation;
            continue;
        }
        capacity = (unsigned short)(budget < 1024 ? budget : 1024);
    encode_events:
        encoded_bytes = 0;
        for (;;) {
            unsigned char sequence = event.sequence;
            unsigned char opcode = event.opcode;
            int count = link_frame_encode(CONTROL_EVENT_TX_BUFFER + encoded_bytes,
                (unsigned int)capacity - encoded_bytes,opcode,sequence,event.payload,event.length);
            if (count < 0) {
                retained_event = 1;
                break;
            }
            encoded_bytes = (unsigned short)(encoded_bytes + (unsigned int)count);
            if ((unsigned int)encoded_bytes + 199U >= capacity ||
                control_event_take(&event.opcode,&event.sequence,event.payload,
                    &event.length,pressure) == 0) {
                retained_event = 0;
                break;
            }
        }
        if (encoded_bytes != 0 &&
            control_try_send_encoded(CONTROL_EVENT_TX_BUFFER,encoded_bytes) == 0) {
            previous_generation = generation;
            continue;
        }
        encoded_bytes = 0;
        previous_generation = generation;
    }
}

/* Native entry: 0x4200b558. */
/* Original function-byte SHA-256:
 * b0946287b7c986eba57929430b2be11270e7633db1c22b9322fd11e8edb1c32a. */
/* Register external command callback with NULL context, install RX idle
 * service, then install the stored-receive-timestamp reader, in that order.
 * Create ctrlevt with3072-byte stack, NULL argument, priority6, no returned
 * handle and core1 affinity. Ignore creation result. No initialization guard,
 * rollback or allocation-failure report; repeated calls can create duplicates.
 * The command handler is reviewed separately in app/commands.c. */
void control_protocol_init(void)
{
    control_set_frame_handler(control_command_dispatch,NULL);
    control_set_rx_empty_hook(control_rx_idle_service);
    input_set_receive_timestamp_reader(control_rx_last_timestamp_us_low);
    xTaskCreatePinnedToCore(control_event_task,"ctrlevt",3072,NULL,6,NULL,1);
}

/* Native entry: 0x4200a21c. */
/*
 * Medius v3.4.7 — device application; 0x4200a21c.
 *
 * Reads the last dispatched control record timestamp in low microsecond bits.
 *
 * Original function-byte SHA-256:
 * b1a64aecf2e4142ab4fa708814e305815f5f890e3b570512a90302c31bde2660.
 */


/*
 * Returns the low 32-bit timestamp saved when ctrl_rx starts dispatching a
 * record. This is stored receive history, not a fresh hardware-clock read.
 * Performs one native RAM load; does not add a barrier, clear or conversion.
 */
unsigned int control_rx_last_timestamp_us_low(void)
{
    return CONTROL_RX_LAST_TIMESTAMP_US_LOW;
}

/* Native entry: 0x4200a240. */
/*
 * Medius v3.4.7 — device application; 0x4200a240.
 *
 * Installs the optional control receive-ring empty hook.
 *
 * Called by: control_protocol_init.
 *
 * Original function-byte SHA-256:
 * 7e12673ce2de7a303e6f0cd4e2f6e8931670deb4c747238579be19dc7f498e47.
 */


/*
 * Stores the optional no-argument empty-ring hook. NULL disables it.
 * The task can call it after a notification timeout with no received data;
 * it is not restricted to a nonempty-to-empty transition.
 * Supplies no lock, barrier, callback ownership or lifetime pin.
 */
void control_set_rx_empty_hook(ControlRxHook callback)
{
    CONTROL_RX_EMPTY_RING_HOOK = callback;
}

/* Native entry: 0x4200a528. */
/*
 * Medius v3.4.7 — device application; 0x4200a528.
 *
 * Installs the optional first-frame hook without resetting the receive latch.
 *
 * Called by: app_main.
 *
 * Original function-byte SHA-256:
 * 6dee7b8ea392e90e1a660bb2b99075845f58fb8ed3b7d03b36c9a243179f17b4.
 */


/*
 * Stores the optional no-argument first-frame hook. NULL disables it.
 * Does not clear the has-received-frame latch or invoke the hook now.
 * Installation after the latch is set does not retroactively notify it.
 * Supplies no lock, barrier, callback ownership or lifetime pin.
 */
void control_set_first_frame_hook(ControlRxHook callback)
{
    CONTROL_RX_FIRST_FRAME_HOOK = callback;
}

/* Native entry: 0x4200b4c0. */
/*
 * Medius v3.4.7 — device application; 0x4200b4c0.
 *
 * Sends the initial version reply with sequence zero from the first-frame hook.
 *
 * Calls: query_version_send.
 *
 * Registered by: app_main; invoked through ctrl_rx.
 *
 * Original function-byte SHA-256:
 * 92d377ceeee681efa289419140c9b84524696fdcf06c07bedb1b2fd0b89a62a0.
 */


/*
 * No-argument first-frame hook used by app_main.
 * Calls query_version_send with sequence 0, then returns.
 * Does not use the incoming frame's sequence, return a send status,
 * retry a failure, or retain any callback context.
 */
void control_send_initial_version(void)
{
    query_version_send(0);
}

/* Native entry: 0x4200a37c. */
/*
 * Medius v3.4.7 — device application; 0x4200a37c.
 *
 * Samples outstanding control UART0 TX bytes.
 *
 * Calls: vPortExitCritical, xPortEnterCriticalTimeout.
 *
 * Called by: control_event_task.
 *
 * Original function-byte SHA-256:
 * a79004c31fa6a333b6b45f4f23a0c0c5877aa214dfbafdd915591c74065cf620.
 */

/*
 * Returns bytes queued in the 4 KiB software TX ring plus the sampled UART0
 * TX FIFO occupancy. The snapshot excludes any byte already in the hardware
 * serializer; it is not a wire-completion test or a delivery acknowledgement.
 * No parameters. Takes the TX spinlock with an infinite wait, reads write
 * cursor, read cursor and FIFO status with native MEMW ordering, then unlocks.
 * Requires initialized mux and valid UART/ring state; no mutex-ready check,
 * allocation, delay or state mutation beyond critical-section bookkeeping.
 */
unsigned int control_tx_pending_bytes(void)
{
    (void)xPortEnterCriticalTimeout(&CONTROL_TX_LOCK, -1);
    memw();
    unsigned int write_offset = CONTROL_TX_WRITE_OFFSET;
    memw();
    unsigned int read_offset = CONTROL_TX_READ_OFFSET;
    unsigned int queued_bytes =
        (write_offset - read_offset) & CONTROL_TX_CURSOR_MASK;
    memw();
    unsigned int fifo_status = CONTROL_UART0->status;
    unsigned int fifo_count = (fifo_status >> 16) & UART_FIFO_COUNT_MASK;
    vPortExitCritical(&CONTROL_TX_LOCK);
    return queued_bytes + fifo_count;
}

/* Native entry: 0x4200a42c. */
/*
 * Medius v3.4.7 — device application; 0x4200a42c.
 *
 * Computes the remaining control UART0 TX backpressure budget.
 *
 * Calls: vPortExitCritical, xPortEnterCriticalTimeout.
 *
 * Called by: control_event_task.
 *
 * Original function-byte SHA-256:
 * a8606987d24fb3a5099aaff575be5ab5c6487cbc198c92be55b37cf8d28789ba.
 */

/*
 * Returns the remaining byte allowance below a 2048-byte outstanding-TX
 * budget, or zero if that threshold is reached or the TX mutex is absent.
 * No parameters. This is a producer backpressure policy, not the free space
 * of the larger 4 KiB ring. It does not reserve the returned allowance.
 *
 * Samples the mutex handle once without a barrier or taking that mutex. If
 * present, holds the TX spinlock while sampling write/read cursors and UART0
 * FIFO occupancy with native MEMW ordering, then releases it before computing
 * the allowance. The native result is masked to 16 bits and returned in the
 * integer result register. Requires valid mux/ring/UART state once initialized;
 * no task delay, allocation or wait for bytes to leave the wire is supplied.
 */
unsigned int control_tx_budget_bytes(void)
{
    if (CONTROL_TX_MUTEX == 0)
        return 0;

    (void)xPortEnterCriticalTimeout(&CONTROL_TX_LOCK, -1);
    memw();
    unsigned int write_offset = CONTROL_TX_WRITE_OFFSET;
    memw();
    unsigned int read_offset = CONTROL_TX_READ_OFFSET;
    unsigned int queued_bytes =
        (write_offset - read_offset) & CONTROL_TX_CURSOR_MASK;
    memw();
    unsigned int fifo_status = CONTROL_UART0->status;
    unsigned int fifo_count = (fifo_status >> 16) & UART_FIFO_COUNT_MASK;
    vPortExitCritical(&CONTROL_TX_LOCK);

    unsigned int outstanding_bytes = queued_bytes + fifo_count;
    if (outstanding_bytes >= 0x800U)
        return 0;
    return (0x800U - outstanding_bytes) & 0xffffU;
}
