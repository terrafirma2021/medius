/* Medius v3.4.7 host — link/transport.c.
 * Recovered C and native assembly, grouped for source navigation.
 * Original entry addresses, firmware-byte hashes and function comments follow.
 */

#include "../include/types.h"

/* Native entry: 0x4037b0f4. */
/*
 * Medius v3.4.7 — host application; 0x4037b0f4.
 *
 * Copies validated frames into the RX payload/descriptor rings and wakes the receive task.
 *
 * Calls: _frxt_setup_switch, vTaskGenericNotifyGiveFromISR, esp_timer_get_time, memcpy.
 *
 * Indirect calls: policy direct_handler and observer, described below.
 *
 * Original function-byte SHA-256:
 * 8d99d2305be0f94a091003d8ea5adfdbf719a1e60ee88f52aa9b9942fbb2cf27.
 */

/*
 * Publish one parsed UART1 frame, or let its configured direct handler consume it.
 * type/flags are byte values; length is a 16-bit byte count, not implicitly
 * capped at 512 here. payload must remain readable and disjoint from the copy
 * destination for length bytes when copied; callbacks borrow the original
 * pointer synchronously. unused_context is the parser's unused fifth argument.
 * Returns no value. No allocation, retry, local lock or cursor-range repair.
 * Requires one serialized, nonreentrant producer, valid ring state and a context
 * suitable for the ISR notification API. Policy/handler lifetime is external.
 *
 * Snapshot direct_handler, then test its current opcode. Its nonzero result
 * consumes the frame: store low32 esp_timer_get_time after MEMW and return.
 * A zero result falls through. Its fourth argument reports whether the shared
 * counted-pending word was nonzero; it is not a new task-woken output.
 *
 * Cache descriptor_write once. A 96-slot descriptor ring keeps one slot empty;
 * full drops do not even read payload cursors. The 8192-byte payload ring keeps
 * one byte free. Reserve a contiguous payload, consuming unused tail padding
 * when wrapping to zero; length zero still reserves a descriptor. Commit the
 * byte reservation before memcpy. Ordinary failed bounds checks do not write
 * it. The corrupt negative-old-write path commits the wrapped cursor before
 * dropping, exactly as native code does. All arithmetic is unsigned32/modulo.
 * Drops increment only the selected-opcode counter for 0x10/0x36/0x39/0x3a,
 * otherwise the other counter, with MEMW/read/MEMW/write ordering.
 *
 * Copy payload, store the type/flags halfword, length and 16-bit payload offset.
 * Timestamp only types 2 and 0x25; all other descriptor timestamps are zero.
 * Read the raw accounting marker before storing timestamp. If enabled, exempt
 * the current direct opcode (even with no handler) and bitmap-listed types;
 * otherwise increment counted_pending modulo32bits and retain the raw marker byte.
 * Padding bytes at +6..7/+13..15 are untouched.
 *
 * Load observer, MEMW, snapshot descriptor_read, then store the marker byte.
 * Observer runs only for type0x10 length>=6 or type0x1c length>=8, before
 * publication, with the original payload. A nonreturning callback leaves the
 * byte reservation/descriptor work unpublished. Finally MEMW then store the
 * cached next descriptor index. Notify index0 only when the earlier consumer
 * snapshot equaled the original producer index and the now-read RX task exists;
 * a nonzero woken output requests an ISR-exit reschedule. No post-callback
 * cursor refresh, notification retry or callback/policy revalidation is added.
 */
void link_receive_publish(unsigned char type, unsigned char flags,
    const unsigned char *payload, unsigned short length, void *unused_context)
{
    LinkRxDirectHandler direct = LINK_RX_POLICY.direct_handler;
    if (direct != 0 && LINK_RX_POLICY.direct_type == type) {
        memw();
        int has_pending = LINK_RX_COUNTED_PENDING != 0;
        if (direct(flags, payload, length, has_pending) != 0) {
            unsigned int now_us_low = (unsigned int)esp_timer_get_time();
            memw();
            LINK_LAST_DIRECT_RX_US = now_us_low;
            return;
        }
    }

    memw();
    unsigned int producer = LINK_RX_CURSOR_STATE.descriptor_write;
    unsigned int next_producer = (producer + 1U) % LINK_RX_DESCRIPTOR_SLOTS;
    memw();
    unsigned int consumer = LINK_RX_CURSOR_STATE.descriptor_read;
    if (consumer == next_producer)
        goto drop_frame;
    memw();
    unsigned int write_offset = LINK_RX_CURSOR_STATE.payload_write;
    memw();
    unsigned int read_offset = LINK_RX_CURSOR_STATE.payload_read;
    unsigned int used = (write_offset - read_offset) & LINK_RX_PAYLOAD_MASK;
    unsigned int end_offset = write_offset + (unsigned int)length;
    unsigned int copy_offset;
    unsigned short descriptor_offset;
    if (end_offset <= LINK_RX_PAYLOAD_BYTES) {
        if (used + (unsigned int)length > LINK_RX_PAYLOAD_MASK)
            goto drop_frame;
        memw();
        LINK_RX_CURSOR_STATE.payload_write = end_offset & LINK_RX_PAYLOAD_MASK;
        if ((int)write_offset < 0)
            goto drop_frame;
        copy_offset = write_offset;
        descriptor_offset = (unsigned short)write_offset;
    } else {
        unsigned int reservation = used + (LINK_RX_PAYLOAD_BYTES - write_offset)
            + (unsigned int)length;
        if (reservation > LINK_RX_PAYLOAD_MASK)
            goto drop_frame;
        memw();
        LINK_RX_CURSOR_STATE.payload_write = length & LINK_RX_PAYLOAD_MASK;
        copy_offset = 0;
        descriptor_offset = 0;
    }
    if (length != 0)
        memcpy(LINK_RX_PAYLOAD + copy_offset, payload, length);

    volatile LinkRxDescriptor *descriptor = &LINK_RX_DESCRIPTORS[producer];
    descriptor->type_and_flags = (unsigned short)((unsigned int)type | ((unsigned int)flags << 8));
    descriptor->length = length;
    descriptor->payload_offset = descriptor_offset;
    unsigned int timestamp = 0;
    if (type == 2 || type == 0x25)
        timestamp = (unsigned int)esp_timer_get_time();
    unsigned char counted = LINK_RX_POLICY.accounting_enabled;
    descriptor->received_at_us_low = timestamp;
    if (counted != 0) {
        if (LINK_RX_POLICY.direct_type == type ||
            (LINK_RX_POLICY.uncounted_types[type >> 5] & (1U << (type & 31))) != 0) {
            counted = 0;
        } else {
            memw();
            unsigned int pending = LINK_RX_COUNTED_PENDING;
            memw();
            LINK_RX_COUNTED_PENDING = pending + 1U;
        }
    }
    LinkRxObserver observer = LINK_RX_POLICY.observer;
    memw();
    unsigned int consumer_snapshot = LINK_RX_CURSOR_STATE.descriptor_read;
    descriptor->counted = counted;
    if (observer != 0 && ((type == 0x10 && length >= 6) || (type == 0x1c && length >= 8)))
        observer(type, flags, payload, length);
    memw();
    LINK_RX_CURSOR_STATE.descriptor_write = next_producer;
    if (consumer_snapshot != producer)
        return;
    RtosTask *rx_task = LINK_RX_TASK_HANDLE;
    if (rx_task == 0)
        return;
    int higher_priority_task_woken = 0;
    vTaskGenericNotifyGiveFromISR(rx_task, 0, &higher_priority_task_woken);
    if (higher_priority_task_woken != 0)
        _frxt_setup_switch();
    return;

drop_frame: {
    volatile unsigned int *drops =
        (type == 0x10 || type == 0x36 || type == 0x39 || type == 0x3a)
        ? &LINK_RX_SELECTED_TYPE_DROPS : &LINK_RX_OTHER_TYPE_DROPS;
    memw();
    unsigned int previous_drops = *drops;
    memw();
    *drops = previous_drops + 1U;
    return;
}
}

/* Native entry: 0x4037f5e0. */
/* Original function-byte SHA-256:
 * c2360bf4bc1b7bc42892fd9407d4942be46ffed90375a7e80f73bc7b5fc96028. */
/*
 * Route FULL-WORD type exactly0x10->channel0, exactly0x1c->channel2, else1.
 * Take that channel's mutex with0 ticks for wait_ticks0, else UINT_MAX; only
 * return1 admits encoding. Encode into shared522-byte item(frame capacity520),
 * narrowing type/flags8 and payload length16 at encoder boundary. Negative
 * encoder result releases current mutex without queueing. Otherwise snapshot
 * TX queue, store encoded length HALF, send full item with supplied wait ticks,
 * release freshly sampled channel mutex, and require send result EXACTLY1.
 * Success notifies sampled TX task if nonnull(index0,value0,action2,outNULL),
 * ignoring notify result, then returns1. Other paths return0; unless low8
 * suppress flag!=0, emit original link-busy or queue-full warning with full type.
 * Scratch tail is retained; no queue/mutexNULL guard, payload validation,
 * timeout rollback, ISR adaptation, UART completion or physical delivery proof.
 */
unsigned int link_frame_enqueue(int type,unsigned char flags,void *payload,
    unsigned int length,unsigned int wait_ticks,char suppress_drop_log)
{
    unsigned int channel = type == 0x10 ? 0U : type == 0x1c ? 2U : 1U;
    unsigned int timestamp;
    const char *error_format;
    RtosQueue *mutex = LINK_TX_MUTEX_HANDLES.slot[channel];
    if (xQueueSemaphoreTake(mutex,wait_ticks == 0 ? 0U : 0xffffffffU) != 1) {
        if ((unsigned char)suppress_drop_log != 0) return 0;
        timestamp = esp_log_timestamp();
        error_format = "W (%lu) %s: tx drop type=0x%02x (link busy)\n";
        goto report_drop;
    }
    volatile LinkTxQueueItem *item = &LINK_TX_CHANNEL_ITEMS[channel];
    int encoded_length = link_frame_encode((unsigned char *)item->encoded_frame,
        520,(unsigned char)type,flags,payload,(unsigned short)length);
    if (encoded_length < 0) {
        mutex = LINK_TX_MUTEX_HANDLES.slot[channel];
        (void)xQueueGenericSend(mutex,0,0,0);
    } else {
        RtosQueue *queue = LINK_TX_QUEUE_HANDLES.slot[channel];
        item->encoded_length = (unsigned short)encoded_length;
        int accepted = xQueueGenericSend(queue,(const LinkTxQueueItem *)item,wait_ticks,0);
        mutex = LINK_TX_MUTEX_HANDLES.slot[channel];
        (void)xQueueGenericSend(mutex,0,0,0);
        if (accepted == 1) {
            RtosTask *task = LINK_TX_TASK_HANDLE;
            if (task != 0) (void)xTaskGenericNotify(task,0,0,2,0);
            return 1;
        }
    }
    if ((unsigned char)suppress_drop_log != 0) return 0;
    timestamp = esp_log_timestamp();
    error_format = "W (%lu) %s: tx drop type=0x%02x (queue full)\n";
report_drop:
    esp_log_write(2,"link",error_format,timestamp,"link",type);
    return 0;
}

/* Native entry: 0x4037f6f4. */
/* Original function-byte SHA-256:
 * 98e85af79117be66e62bf616ab76ae6f9741b574f3df0c00c7fd79ce9f987041. */
/*
 * Low8 type/flags and low16 length; borrow payload and call frame enqueue with
 * queue wait100 ticks/suppress0, returning its0/1 result unchanged. Mutex wait
 * can still be UINT_MAX;100 ticks is not a whole-call or physical-send bound.
 */
int link_send_wait100(unsigned char type,unsigned char flags,
    const void *payload,unsigned short length)
{
    return link_frame_enqueue(type,flags,(void *)payload,length,100,0);
}

/* Native entry: 0x4037f730. */
/* Original function-byte SHA-256:
 * bb2bb9cd1e5d20267dd1b6ae3f476d8fa3615f81e4368b2e4d56cafc34215ef7. */
/*
 * Always sample clock LOW, MEMW/store last-direct-RX time before dispatch.
 * Full type0x25/length>=16: zero16-byte reply, memcpy first8 payload bytes,
 * then received_at_low into reply+8; tail+12 stays0. Enqueue type2 with low8
 * flags,length16,wait0 AND explicit suppress0; ignore result. Full type2/
 * length>=16: form16-byte sample with finalWORD received_at_low, copying three
 * separate4-byte words from payload+4,+8,+12. If sampled sync queue nonnull,
 * send sample wait0/back, ignoring result. These branches consume the frame.
 * Other types, including short sync frames, snapshot callback then context and
 * call(type,flags,payload,length,context) if nonnull. Full argument WORDs pass
 * through; installed callbacks may narrow them. Payload is borrowed. No null
 * validation for admitted sync payload, callback lock, atomic pair snapshot,
 * per-frame allocation, replay/authentication check or success return here.
 */
void link_frame_dispatch(int type,unsigned int flags,void *payload,
    unsigned int length,unsigned int received_at_low)
{
    unsigned int now_low = (unsigned int)esp_timer_get_time();
    memw(); LINK_LAST_DIRECT_RX_US = now_low;
    if (type == 0x25 && length >= 16) {
        LinkSyncReply reply = {{0,0},0,0};
        memcpy(reply.request_words,payload,8);
        memcpy(&reply.received_at_low,&received_at_low,4);
        (void)link_frame_enqueue(2,(unsigned char)flags,&reply,16,0,0);
        return;
    }
    if (type == 2 && length >= 16) {
        LinkSyncSample sample = {{0,0,0},received_at_low};
        const unsigned char *bytes = payload;
        memcpy(&sample.payload_words[0],bytes + 4,4);
        memcpy(&sample.payload_words[1],bytes + 8,4);
        memcpy(&sample.payload_words[2],bytes + 12,4);
        RtosQueue *queue = LINK_SYNC_QUEUE;
        if (queue != 0) (void)xQueueGenericSend(queue,&sample,0,0);
        return;
    }
    LinkApplicationFrameHandler callback = LINK_APPLICATION_HANDLER;
    if (callback != 0) {
        void *context = LINK_APPLICATION_CONTEXT;
        callback(type,flags,payload,length,context);
    }
}

/* Native entry: 0x403872e8. */
/* Original function-byte SHA-256:
 * 941cffb0e7a9fb40e37cf4e313592c4da236a183712356efbd6f5d90961abf95. */
/*
 * Device-to-host application frame callback: low8 opcode/flags, low16 length,
 * borrowed payload; ignores the dispatcher's fifth context WORD. Routes:
 * 04 reboot (byte0==1 with nonzero length: run; otherwise download), with the
 * exact warning first;13 EP0 setup,19 EP0 fragment,18 short OUT,1d timed OUT,
 * 3e OUT status query,3f endpoint halt,1f interface,20 nonzero setup,24 config,
 * 35 generation marker,41 power,42 remote wake,22 nonzero fragment,31/33 direct
 * USB transfer requests (responses32/34),15 clone publication,30 poll override
 * when length>=1,16 HID GET_REPORT when length>=4,38 motion config,39 motion
 * samples,3a cancel/requeue,3b frame correction THEN HID poll phases,1b LED
 * override when length>=2,27..2f firmware update. Others do nothing.
 *
 * All payload handlers receive the length, including38/39/3a/3b where Ghidra
 * omitted the retained argument. GET_REPORT reads bytes3,2,1,0, assembles LE16
 * count and forwards flags as sequence. LED reads byte1 before byte0. No
 * general NULL/length validation;38/39/3a/3b delegate admission to callees.
 * No local authentication, copy, acknowledgement or status result. Native
 * callees return to this callback if they return at all, including reboot.
 */
void medius_host_link_message(unsigned char opcode,unsigned char flags,
    unsigned char *payload,unsigned short length)
{
    const volatile unsigned char *bytes = payload;
    switch (opcode) {
    case 0x04:
        if (length == 0 || bytes[0] != 1) {
            unsigned int timestamp = esp_log_timestamp();
            esp_log_write(2,"host","W (%lu) %s: link REBOOT_DL -> host reboot to download\n",
                timestamp,"host");
            medius_host_reboot_to_download();
        } else {
            unsigned int timestamp = esp_log_timestamp();
            esp_log_write(2,"host","W (%lu) %s: link REBOOT -> host reboot to run\n",
                timestamp,"host");
            medius_host_reboot_to_run();
        }
        return;
    case 0x13: medius_usb_control_request_enqueue(flags,payload,length); return;
    case 0x19: medius_ep0_request_fragment(flags,payload,length); return;
    case 0x18: medius_out_handle_short(payload,length); return;
    case 0x1d: medius_out_handle_timed(payload,length); return;
    case 0x3e: medius_out_handle_status_query(payload,length); return;
    case 0x3f: medius_ordered_endpoint_halt_request(payload,length); return;
    case 0x1f: medius_ordered_interface_request(payload,length); return;
    case 0x20: medius_nonzero_request_enqueue(flags,payload,length); return;
    case 0x24: medius_ordered_configuration_request(payload,length); return;
    case 0x35: medius_ordered_generation_marker(); return;
    case 0x41: medius_ordered_power_request(payload,length); return;
    case 0x42: medius_ordered_remote_wakeup_request(payload,length); return;
    case 0x22: medius_nonzero_request_fragment(flags,payload,length); return;
    case 0x31: medius_host_transfer_ep0_enqueue(flags,payload,length); return;
    case 0x33: medius_host_transfer_nonzero_enqueue(flags,payload,length); return;
    case 0x15: medius_clone_publish_request(); return;
    case 0x30:
        if (length != 0) medius_hid_set_poll_override(bytes[0]);
        return;
    case 0x16:
        if (length >= 4) {
            unsigned int high = bytes[3];
            unsigned int low = bytes[2];
            unsigned char report_id = bytes[1];
            unsigned char interface_number = bytes[0];
            medius_hid_get_report_enqueue(flags,interface_number,report_id,
                (unsigned short)(low | (high << 8)));
        }
        return;
    case 0x38: medius_motion_configuration_receive(payload,length); return;
    case 0x39: medius_motion_samples_receive(payload,length); return;
    case 0x3a: medius_motion_cancel_requeue(payload,length); return;
    case 0x3b:
        medius_host_update_frame_controller(payload,length);
        medius_hid_apply_poll_phases(payload,length);
        return;
    case 0x1b:
        if (length >= 2) {
            unsigned char brightness = bytes[1];
            unsigned char mode = bytes[0];
            medius_host_led_override_set(mode,brightness);
        }
        return;
    default:
        if ((unsigned char)(opcode - 0x27U) < 9)
            medius_host_update_link_dispatch(opcode,payload,length);
        return;
    }
}

/* Native entry: 0x420217cc. */
/* Original function-byte SHA-256:
 * f086e68343911f918ef3bbefd5aac08f8dabe683ae09b755c47bc13fb14ac092. */
/*
 * Publish application callback pointer WORD first, context WORD second. NULL
 * callback disables application dispatch; no callback invocation or context
 * ownership transfer. No fence, lock or atomic pair publication; a concurrent
 * dispatcher may observe a callback/context from different registrations.
 */
void link_set_frame_handler(LinkApplicationFrameHandler callback,void *context)
{
    LINK_APPLICATION_HANDLER = callback;
    LINK_APPLICATION_CONTEXT = context;
}

/* Native entry: 0x420217dc. */
/*
 * Medius v3.4.7 — host application; 0x420217dc.
 *
 * Initializes the inter-chip UART1 link, TX queues, IRQ and link tasks.
 *
 * Calls: esp_log_timestamp, esp_log_write, abort, esp_intr_alloc, link_parser_init,
 * uart_param_config, uart_set_pin, vPortExitCritical, xPortEnterCriticalTimeout,
 * xQueueCreateMutex, xQueueGenericCreate, xTaskCreatePinnedToCore.
 *
 * Called by: app_main.
 *
 * Original function-byte SHA-256:
 * 5920a1c4a4059b0fb1cda0d24e68ac6c35e3860bc2bd833439de18311c4014bb.
 */

/*
 * Initialize the fixed UART1 inter-chip link from normal startup task context.
 * role: 0 selects device pins TX2/RX1 and sets the initial TX FIFO fill limit
 * to 32. Role 1 selects host pins TX1/RX2 and creates the baud worker. Other
 * values are accepted: TX2/RX1, DEVICE label, no baud worker, and the current
 * initial-fill limit is retained. Nonzero roles never reset that limit; its
 * original image value is 128. There is no role-range or repeat-init guard.
 * Returns no value. Repeated calls replace retained handles without releasing
 * old objects or stopping tasks; initialization requires exclusive startup use.
 *
 * In order: create three mutexes, one empty capacity-1/zero-item completion
 * semaphore, and three capacity-8 queues copying 522-byte items. Channels are
 * opcode 0x10, other opcodes, and opcode 0x1c. Store every returned handle
 * immediately, without NULL checks. Initialize the parser with the RX callback
 * and NULL context. These allocation failures do not stop later setup.
 *
 * Configure UART1 for requested 20,000,000 baud, 8 data bits, no parity, one
 * stop bit, no flow control, APB source and zero flags. UART configuration or
 * pin errors abort. Normal task/PS.EXCM-clear context is required by the native
 * six-word hardware-loop initialization of the local configuration tail.
 *
 * With each observed MEMW/read/MEMW/write retained: set RX-full threshold 32,
 * RX-timeout threshold 20, enable RX timeout, then set TX-empty threshold 16.
 * Other register bits are preserved. Create link_rx (8192-byte stack, priority
 * 12, core 0) before the native unused INT_ENA read, INT_ENA=0 and all-bit
 * interrupt clear. Task-creation results are ignored; setup may still log up.
 *
 * Read UART1's interrupt source from the constant peripheral table (28 in
 * these images). Allocate its ISR on the calling CPU: IRAM|level2 for role 0,
 * IRAM|level3 otherwise. Failure aborts, with no cleanup of prior resources.
 * Under the existing TX portMUX, OR 0x11d RX/error/timeout sources into INT_ENA.
 * No TX-empty/TX-done bit is added here. Create link_tx (3072 bytes, priority
 * 13, no affinity); role 1 also creates link_baud (3072 bytes, priority 2, no
 * affinity) with no retained handle. All task arguments and ISR context are NULL.
 *
 * Finally emit the role/pin/baud diagnostic. This is initialization, not a peer
 * handshake or proof that allocation, task startup or physical baud succeeded.
 * Existing worker/callback bodies have separately recorded review status.
 */
void link_init(int role)
{
    if (role == 0)
        LINK_TX_INITIAL_FIFO_LIMIT = 32;
    int tx_pin = role == 1 ? 1 : 2;
    int rx_pin = role == 1 ? 2 : 1;

    for (unsigned int channel = 0; channel < 3; ++channel)
        LINK_TX_MUTEX_HANDLES.slot[channel] = xQueueCreateMutex();
    LINK_TX_COMPLETION_SEMAPHORE = xQueueGenericCreate(1, 0);
    for (unsigned int channel = 0; channel < 3; ++channel)
        LINK_TX_QUEUE_HANDLES.slot[channel] = xQueueGenericCreate(
            LINK_TX_QUEUE_CAPACITY, sizeof(LinkTxQueueItem));
    link_parser_init(LINK_RX_PARSER, link_receive_publish, 0);

    UartConfig configuration = {0};
    configuration.baud_rate = LINK_STARTUP_BAUD;
    configuration.data_bits = UART_DATA_8_BITS;
    configuration.stop_bits = UART_STOP_BITS_1;
    configuration.source_clock = UART_CLOCK_APB;
    if (uart_param_config(LINK_UART_NUMBER, &configuration) != 0)
        abort();
    if (uart_set_pin(LINK_UART_NUMBER, tx_pin, rx_pin, -1, -1) != 0)
        abort();

    UartRegisterView *uart = LINK_UART1;
    memw();
    unsigned int conf1 = uart->conf1;
    memw();
    uart->conf1 = (conf1 & 0xfffffc00U) | 32U;
    memw();
    unsigned int memory_configuration = uart->mem_conf;
    memw();
    uart->mem_conf = (memory_configuration & 0xf801ffffU) | (20U << 17);
    memw();
    conf1 = uart->conf1;
    memw();
    uart->conf1 = conf1 | 0x00800000U;
    memw();
    conf1 = uart->conf1;
    memw();
    uart->conf1 = (conf1 & 0xfff003ffU) | (16U << 10);

    (void)xTaskCreatePinnedToCore(link_receive_task, "link_rx", 8192, 0, 12,
        (RtosTask **)&LINK_RX_TASK_HANDLE, 0);
    memw();
    (void)uart->interrupt_enable; /* Native read is observable even though unused. */
    memw();
    uart->interrupt_enable = 0;
    memw();
    uart->interrupt_clear = 0xffffffffU;

    int interrupt_source = UART1_INTERRUPT_SOURCE;
    int interrupt_flags = INTR_FLAG_IRAM |
        (role == 0 ? ESP_INTR_FLAG_LEVEL2 : ESP_INTR_FLAG_LEVEL3);
    if (esp_intr_alloc(interrupt_source, interrupt_flags, link_uart_interrupt_handler,
                       0, (InterruptHandle **)&LINK_UART_IRQ_HANDLE) != 0)
        abort();
    (void)xPortEnterCriticalTimeout(&LINK_TX_LOCK, -1);
    memw();
    unsigned int enabled_interrupts = uart->interrupt_enable;
    memw();
    uart->interrupt_enable = enabled_interrupts | LINK_UART_RX_IRQS;
    vPortExitCritical(&LINK_TX_LOCK);

    (void)xTaskCreatePinnedToCore(link_transmit_task, "link_tx", 3072, 0, 13,
        (RtosTask **)&LINK_TX_TASK_HANDLE, RTOS_NO_CORE_AFFINITY);
    if (role == 1)
        (void)xTaskCreatePinnedToCore(link_baud_task, "link_baud", 3072, 0, 2,
                                     0, RTOS_NO_CORE_AFFINITY);
    unsigned int timestamp = esp_log_timestamp();
    const char *role_name = role == 1 ? "HOST" : "DEVICE";
    esp_log_write(3, LINK_LOG_TAG,
        "I (%lu) %s: link up: role=%s UART%d tx=%d rx=%d baud=%d\n",
        (unsigned long)timestamp, LINK_LOG_TAG, role_name,
        LINK_UART_NUMBER, tx_pin, rx_pin, LINK_STARTUP_BAUD);
}

/* Native entry: 0x42021a38. */
/* Original function-byte SHA-256:
 * 6cf3b9bce65f86882f322c2b9db82f6acfd3b5781fc55b669a8a57826b3d3e3e. */
/*
 * Low8 type/flags and low16 length; call frame enqueue wait0/suppress0, discard
 * its result. Both mutex and queue admission use zero wait, but encoding/logging
 * and task notification can still execute. No admission/delivery result.
 */
void medius_link_send_nowait(unsigned char type,unsigned char flags,
    const void *payload,unsigned short length)
{
    (void)link_frame_enqueue(type,flags,(void *)payload,length,0,0);
}

/* Native entry: 0x4037b688. */
/* Original function-byte SHA-256:
 * f6a3fa6abc820b80480c51dde5ddddd7b11949adaa9666a4563c72dc478cbf7a. */
/* Encode and enqueue one UART frame from an ISR-capable context. scratch is
 * caller-owned storage for the 522-byte queue item; payload is borrowed for the
 * encoder call. Type/flags truncate to bytes, length to low16. Queue slot is 0
 * for type0x10, 2 for type0x1c, otherwise1. A NULL initial handle returns0 before
 * touching scratch. Encode at scratch+2 with capacity520. A negative encoder
 * result returns0 without storing encoded_length. Otherwise reload the CURRENT
 * selected queue, store the result's low16 into scratch, and ISR-send at back0
 * with the caller's woken pointer. Only queue result1 succeeds. Then read the
 * CURRENT TX task and notify index0 if non-NULL, passing the SAME woken pointer.
 * Return1 after accepted queueing,0 otherwise. No mutex, immediate yield, local
 * wake reset, scratch clearing or lifetime/bounds validation is added. */
int medius_link_send_from_isr(LinkTxQueueItem *scratch, unsigned char type,
    unsigned char flags, void *payload, unsigned int length, int *woken)
{
    unsigned int slot = type == 0x10 ? 0U : type == 0x1c ? 2U : 1U;
    if (LINK_TX_QUEUE_HANDLES.slot[slot] == NULL) return 0;
    int encoded = link_frame_encode(scratch->encoded_frame, 520, type, flags, payload, length & 65535U);
    if (encoded < 0) return 0;
    RtosQueue *queue = LINK_TX_QUEUE_HANDLES.slot[slot];
    scratch->encoded_length = (unsigned short)encoded;
    if (xQueueGenericSendFromISR(queue, scratch, woken, 0) != 1) return 0;
    RtosTask *task = LINK_TX_TASK_HANDLE;
    if (task != NULL) vTaskGenericNotifyGiveFromISR(task, 0, woken);
    return 1;
}

/* Native entry: 0x4037f714. */
/* Original function-byte SHA-256:
 * 706595b05aa8d8210588a2e125d5649083e4283c6c5413ae6b5ebedb2d008b11. */
/* Queue type/flags/payload/length with zero wait ticks and suppress-drop-log1.
 * Type and flags are truncated to8 bits, length to16; return the enqueue
 * helper's complete32-bit result. No retry, delay, acknowledgement or drain.
 * Payload validity, admission, copying and queue behavior belong to that helper. */
unsigned int medius_link_send_now(unsigned char type,unsigned char flags,
    const void *payload,unsigned short length)
{
    return link_frame_enqueue(type,flags,(void *)payload,length,0,1);
}

/* Native entry: 0x42021a54. */
/* Original function-byte SHA-256:
 * f2e4bf3f3a1603bdfc5aa4c94c4cb68b6a99f6bbc064113b28153cb13926dcdd. */
/* Encode one task-context UART frame using caller-owned522-byte scratch.
 * Low8 type/flags select queue0 for0x10,2 for0x1c,otherwise1; low16 length
 * reaches the encoder at scratch+2/capacity520. A NULL initial queue returns0
 * without touching scratch. Negative encode returns0 without storing length.
 * Reload the selected queue AFTER encoding, then store low16 encoded_length
 * and send at back0/wait0. Only exact queue result1 succeeds. Read the current
 * TX task once and notify index0,value0,action2/increment,NULL previous-value
 * pointer if non-NULL; notification status is ignored. Return1 for accepted
 * queueing,0 otherwise, not physical UART delivery. No mutex, scratch clear,
 * validation, wait, retry or yield; the caller must serialize shared scratch.
 */
int medius_link_send_with_scratch(LinkTxQueueItem *scratch,unsigned char type,
    unsigned char flags,const void *payload,unsigned int length)
{
    unsigned int slot = type == 0x10 ? 0U : type == 0x1c ? 2U : 1U;
    if (LINK_TX_QUEUE_HANDLES.slot[slot] == NULL) return 0;
    int encoded = link_frame_encode(scratch->encoded_frame,520,type,flags,
        (void *)payload,length & 65535U);
    if (encoded < 0) return 0;
    RtosQueue *queue = LINK_TX_QUEUE_HANDLES.slot[slot];
    scratch->encoded_length = (unsigned short)encoded;
    if (xQueueGenericSend(queue,scratch,0,0) != 1) return 0;
    RtosTask *task = LINK_TX_TASK_HANDLE;
    if (task != NULL) (void)xTaskGenericNotify(task,0,0,2,NULL);
    return 1;
}
