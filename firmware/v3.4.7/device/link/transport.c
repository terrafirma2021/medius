/* Medius v3.4.7 device — link/transport.c.
 * Recovered C and native assembly, grouped for source navigation.
 * Original entry addresses, firmware-byte hashes and function comments follow.
 */

#include "../include/types.h"

/* Native entry: 0x4037cbd8. */
/*
 * Medius v3.4.7 — device application; 0x4037cbd8.
 *
 * Copies validated frames into the RX payload/descriptor rings and wakes the receive task.
 *
 * Calls: _frxt_setup_switch, vTaskGenericNotifyGiveFromISR, esp_timer_get_time, memcpy.
 *
 * Indirect calls: the typed direct handler and RX observer callbacks.
 *
 * Original function-byte SHA-256:
 * 03da9014c296b09e082ef245f50e0e406cc6909a04e437e6e11a7a3d34681173.
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
    (void)unused_context;
    LinkRxDirectHandler direct_handler = LINK_RX_POLICY.direct_handler;
    if (direct_handler != 0 && LINK_RX_POLICY.direct_type == type) {
        memw();
        int has_counted_pending = LINK_RX_COUNTED_PENDING != 0;
        if (direct_handler(flags, payload, length, has_counted_pending) != 0) {
            unsigned int now_us_low = (unsigned int)esp_timer_get_time();
            memw();
            LINK_LAST_DIRECT_RX_US = now_us_low;
            return;
        }
    }

    memw();
    unsigned int descriptor_write = LINK_RX_CURSOR_STATE.descriptor_write;
    unsigned int next_descriptor_write = (descriptor_write + 1U) % LINK_RX_DESCRIPTOR_SLOTS;
    memw();
    unsigned int descriptor_read = LINK_RX_CURSOR_STATE.descriptor_read;
    if (descriptor_read == next_descriptor_write)
        goto drop_frame;
    memw();
    unsigned int payload_write_offset = LINK_RX_CURSOR_STATE.payload_write;
    memw();
    unsigned int payload_read_offset = LINK_RX_CURSOR_STATE.payload_read;
    unsigned int used_payload_bytes = (payload_write_offset - payload_read_offset) & LINK_RX_PAYLOAD_MASK;
    unsigned int payload_end_offset = payload_write_offset + (unsigned int)length;
    unsigned int copy_offset;
    unsigned short descriptor_offset;
    if (payload_end_offset <= LINK_RX_PAYLOAD_BYTES) {
        if (used_payload_bytes + (unsigned int)length > LINK_RX_PAYLOAD_MASK)
            goto drop_frame;
        memw();
        LINK_RX_CURSOR_STATE.payload_write = payload_end_offset & LINK_RX_PAYLOAD_MASK;
        if ((int)payload_write_offset < 0)
            goto drop_frame;
        copy_offset = payload_write_offset;
        descriptor_offset = (unsigned short)payload_write_offset;
    } else {
        unsigned int reservation_bytes = used_payload_bytes + (LINK_RX_PAYLOAD_BYTES - payload_write_offset)
            + (unsigned int)length;
        if (reservation_bytes > LINK_RX_PAYLOAD_MASK)
            goto drop_frame;
        memw();
        LINK_RX_CURSOR_STATE.payload_write = length & LINK_RX_PAYLOAD_MASK;
        copy_offset = 0;
        descriptor_offset = 0;
    }
    if (length != 0)
        memcpy((unsigned char *)((unsigned int)LINK_RX_PAYLOAD + copy_offset),payload,length);

    volatile LinkRxDescriptor *descriptor = (volatile LinkRxDescriptor *)
        ((unsigned int)LINK_RX_DESCRIPTORS + descriptor_write * 16U);
    descriptor->type_and_flags = (unsigned short)((unsigned int)type | ((unsigned int)flags << 8));
    descriptor->length = length;
    descriptor->payload_offset = descriptor_offset;
    unsigned int received_at_us_low = 0;
    if (type == 2 || type == 0x25)
        received_at_us_low = (unsigned int)esp_timer_get_time();
    unsigned char counted_pending_marker = LINK_RX_POLICY.accounting_enabled;
    descriptor->received_at_us_low = received_at_us_low;
    if (counted_pending_marker != 0) {
        if (LINK_RX_POLICY.direct_type == type ||
            (LINK_RX_POLICY.uncounted_types[type >> 5] & (1U << (type & 31))) != 0) {
            counted_pending_marker = 0;
        } else {
            memw();
            unsigned int pending_count = LINK_RX_COUNTED_PENDING;
            memw();
            LINK_RX_COUNTED_PENDING = pending_count + 1U;
        }
    }
    LinkRxObserver observer = LINK_RX_POLICY.observer;
    memw();
    unsigned int consumer_snapshot = LINK_RX_CURSOR_STATE.descriptor_read;
    descriptor->counted = counted_pending_marker;
    if (observer != 0 && ((type == 0x10 && length >= 6) || (type == 0x1c && length >= 8)))
        observer(type, flags, payload, length);
    memw();
    LINK_RX_CURSOR_STATE.descriptor_write = next_descriptor_write;
    if (consumer_snapshot != descriptor_write)
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
    volatile unsigned int *drop_counter =
        (type == 0x10 || type == 0x36 || type == 0x39 || type == 0x3a)
        ? &LINK_RX_SELECTED_TYPE_DROPS : &LINK_RX_OTHER_TYPE_DROPS;
    memw();
    unsigned int previous_drop_count = *drop_counter;
    memw();
    *drop_counter = previous_drop_count + 1U;
    return;
}
}

/* Native entry: 0x40383d50. */
/* Original function-byte SHA-256:
 * 7cbfd4c1c6f046bf11cf9b823b821d6fb24a49da94e535366f9dcc83c56abdce. */
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
    unsigned int log_timestamp;
    const char *error_format;
    RtosQueue *channel_mutex = LINK_TX_MUTEX_HANDLES.slot[channel];
    if (xQueueSemaphoreTake(channel_mutex,wait_ticks == 0 ? 0U : 0xffffffffU) != 1) {
        if ((unsigned char)suppress_drop_log != 0) return 0;
        log_timestamp = esp_log_timestamp();
        error_format = "W (%lu) %s: tx drop type=0x%02x (link busy)\n";
        goto report_drop;
    }
    volatile LinkTxQueueItem *queue_item = &LINK_TX_CHANNEL_ITEMS[channel];
    int encoded_length = link_frame_encode((unsigned char *)queue_item->encoded_frame,
        520,(unsigned char)type,flags,payload,(unsigned short)length);
    if (encoded_length < 0) {
        channel_mutex = LINK_TX_MUTEX_HANDLES.slot[channel];
        (void)xQueueGenericSend(channel_mutex,0,0,0);
    } else {
        RtosQueue *transmit_queue = LINK_TX_QUEUE_HANDLES.slot[channel];
        queue_item->encoded_length = (unsigned short)encoded_length;
        int queue_send_status = xQueueGenericSend(transmit_queue,(const LinkTxQueueItem *)queue_item,wait_ticks,0);
        channel_mutex = LINK_TX_MUTEX_HANDLES.slot[channel];
        (void)xQueueGenericSend(channel_mutex,0,0,0);
        if (queue_send_status == 1) {
            RtosTask *task = LINK_TX_TASK_HANDLE;
            if (task != 0) (void)xTaskGenericNotify(task,0,0,2,0);
            return 1;
        }
    }
    if ((unsigned char)suppress_drop_log != 0) return 0;
    log_timestamp = esp_log_timestamp();
    error_format = "W (%lu) %s: tx drop type=0x%02x (queue full)\n";
report_drop:
    esp_log_write(2,"link",error_format,log_timestamp,"link",type);
    return 0;
}

/* Native entry: 0x40383e3c. */
/* Original function-byte SHA-256:
 * 715aa4abb20530390aa7e6be8afec4e9cfbf6297546f57c5dad832f485dbccd1. */
/*
 * Snapshot the third (low-priority) link TX queue handle. Return1 for NULL or
 * zero queued messages, otherwise0. This measures queue occupancy only, not
 * encoder activity, UART FIFO emptiness, physical transmission or peer receipt.
 */
int link_low_priority_queue_empty(void)
{
    RtosQueue *transmit_queue = LINK_TX_QUEUE_HANDLES.slot[2];
    return transmit_queue == 0 || uxQueueMessagesWaiting(transmit_queue) == 0;
}

/* Native entry: 0x40383e54. */
/* Original function-byte SHA-256:
 * 54de61fc52a6964f62a452621fcdabc2687992d3fc4b20146abd019e44afbc69. */
/*
 * Low8 type/flags and low16 length; borrow payload and call frame enqueue with
 * queue wait100 ticks/suppress0, returning its0/1 result unchanged. Mutex wait
 * can still be UINT_MAX;100 ticks is not a whole-call or physical-send bound.
 */
unsigned int link_send_wait100(unsigned char type,unsigned char flags,
    const void *payload,unsigned short length)
{
    return link_frame_enqueue(type,flags,(void *)payload,length,100,0);
}

/* Native entry: 0x4038f574. */
/* Original function-byte SHA-256:
 * cad62a9a849dfc4f4f4c80bb8edb83b1dbff99d27da447dd355290d5afbf9add. */

/*
 * Publishes inter-chip link activity, then dispatches the received application opcode.
 * opcode/sequence are bytes; payload is borrowed, mutable storage for length bytes.
 * Handlers perform their own additional validation. Returns no value.
 *
 * Cache sequence and clock, take the activity mux, publish LOW/HIGH and seen=1,
 * then unlock before routing. Unknown opcodes still publish activity.
 *
 * Clone fragment0x11 checks busy under a separate mux. Busy sets dropped_while_busy
 * and stops. Otherwise unlock before checking/resetting assembly error and accepting
 * a fragment. Completion publishes busy=1, exchanges active to0 (order4), then sends
 * event1 to the freshly loaded queue. Exact send result1 succeeds; old active0 then
 * emits USB event6. Failure restores active=1 only for cached nonzero, resets the
 * assembly, clears busy and sets retry. Cached zero preserves intervening active writes.
 * Disconnect0x12 resets only on a fresh busy0, clears active, emits USB event7,
 * then sends event2 through a fresh queue handle, ignoring send status.
 * Normal startup creates an eight-item queue of one-byte events; no queue guard here.
 * The clone mux does not serialize the later acceptance/claim/queue work.
 *
 * Log0x03 always emits the bounded host string. A six-byte PANIC prefix and no
 * received PC control frame also save min(length,159) bytes and a NUL terminator.
 * Reports0x10/0x1c require6/8 bytes, dispatch, then complete the freshly reread endpoint.
 * Profile0x17 requires nonempty input, calls the baseline handler, then rereads byte0:
 * 0xff clears the profile notice count. Motion feedback0x36 requires26 bytes and
 * copies exactly26 into aligned32-byte temporary storage, retaining its six-byte tail.
 * The typed feedback consumer reads only bytes16..23 of that borrowed snapshot.
 * All other named routes retain their native arguments without extra local gates.
 *
 * All explicit native MEMWs, fresh flag/queue/payload reads and ignored handler
 * statuses are retained. Handlers must copy borrowed temporary storage before return.
 * Completion of an assembly or queue send does not establish USB activation/delivery.
 */

void device_link_message(unsigned char opcode,unsigned char sequence,unsigned char *payload,unsigned short length)
{
    unsigned int sequence_id = sequence;
    unsigned long long activity_time_us = (unsigned long long)esp_timer_get_time();
    xPortEnterCriticalTimeout(&DEVICE_LINK_MONITOR_LOCK,0xffffffffU);
    volatile DeviceLinkMonitor *link_monitor = DEVICE_LINK_MONITOR;
    link_monitor->activity_low = (unsigned int)activity_time_us;
    link_monitor->activity_high = (unsigned int)(activity_time_us >> 32);
    link_monitor->seen = 1;
    vPortExitCritical(&DEVICE_LINK_MONITOR_LOCK);

    volatile CloneHandoffFlags *handoff_flags =
        DEVICE_CLONE_HANDOFF_FLAGS;
    CloneAssembly *clone_assembly = DEVICE_CLONE_ASSEMBLY;
    union {
        unsigned char payload_bytes[32];
        unsigned char queue_event;
        HostMotionFeedback motion_feedback;
    } message_temporary __attribute__((aligned(4)));
    switch (opcode) {
    case 0x03: {
        unsigned int log_timestamp = esp_log_timestamp();
        esp_log_write(3,DEVICE_HOST_LOG_TAG,"I (%lu) %s: %.*s\n",
                      log_timestamp,DEVICE_HOST_LOG_TAG,(unsigned int)length,payload);
        if (length >= 6 && memcmp(payload,"PANIC ",6) == 0 &&
            control_pc_has_sent_frame() == 0) {
            unsigned int copied_bytes = length < 159 ? length : 159;
            memcpy((void *)DEVICE_HOST_PANIC_LOG,payload,copied_bytes);
            DEVICE_HOST_PANIC_LOG[copied_bytes] = 0;
        }
        break;
    }
    case 0x10:
        if (length >= 6) {
            link_report_decode(payload,length);
            unsigned char interface_id = *(const volatile unsigned char *)payload;
            report_complete(interface_id);
        }
        break;
    case 0x11:
        xPortEnterCriticalTimeout(&DEVICE_CLONE_HANDOFF_LOCK,0xffffffffU);
        memw();
        if (handoff_flags->busy != 0) {
            memw();
            handoff_flags->dropped_while_busy = 1;
            vPortExitCritical(&DEVICE_CLONE_HANDOFF_LOCK);
            break;
        }
        vPortExitCritical(&DEVICE_CLONE_HANDOFF_LOCK);
        if (((const volatile CloneAssembly *)clone_assembly)->error != 0)
            clone_assembly_reset(clone_assembly);
        if (clone_section_accept(clone_assembly,payload,length) != 0) {
            memw();
            memw();
            handoff_flags->busy = 1;
            unsigned int previous_active = atomic_exchange_byte((unsigned char *)&handoff_flags->active,0,4);
            RtosQueue *event_queue = DEVICE_CLONE_EVENT_QUEUE;
            message_temporary.queue_event = 1;
            int queue_send_status = xQueueGenericSend(event_queue,&message_temporary.queue_event,0,0);
            if (queue_send_status == 1) {
                if (previous_active == 0)
                    capture_forward_usb_bus_event(6,0,0);
            } else {
                if (previous_active != 0) {
                    memw();
                    memw();
                    handoff_flags->active = 1;
                }
                clone_assembly_reset(clone_assembly);
                memw();
                memw();
                handoff_flags->busy = 0;
                memw();
                memw();
                handoff_flags->retry = 1;
            }
        }
        break;
    case 0x12:
        memw();
        {
            unsigned char busy_snapshot = handoff_flags->busy;
            memw();
            if (busy_snapshot == 0)
                clone_assembly_reset(clone_assembly);
        }
        memw();
        memw();
        handoff_flags->active = 0;
        capture_forward_usb_bus_event(7,0,0);
        {
            RtosQueue *event_queue = DEVICE_CLONE_EVENT_QUEUE;
            message_temporary.queue_event = 2;
            xQueueGenericSend(event_queue,&message_temporary.queue_event,0,0);
        }
        break;
    case 0x14:
        ep0_accept_short_reply(sequence_id,payload,length);
        break;
    case 0x17:
        if (length != 0) {
            unsigned char subtype = *(const volatile unsigned char *)payload;
            profile_accept_baseline(subtype,payload + 1,(unsigned int)(length - 1U) & 0xffffU);
            if (*(const volatile unsigned char *)payload == 255)
                DEVICE_PROFILE_NOTICE_COUNT = 0;
        }
        break;
    case 0x1a:
        ep0_accept_fragmented_reply(sequence_id,payload,length);
        break;
    case 0x1c:
        if (length >= 8) {
            device_receive_in_report(payload,length);
            unsigned char interface_id = *(const volatile unsigned char *)payload;
            report_complete(interface_id);
        }
        break;
    case 0x21:
        nonzero_control_response((unsigned char)sequence_id,payload,length);
        break;
    case 0x23:
        nonzero_control_response_fragment((unsigned char)sequence_id,payload,length);
        break;
    case 0x26:
        clone_accept_report_fragment(payload,length);
        break;
    case 0x29:
    case 0x2e:
        update_receive_host_reply(opcode,payload,length);
        break;
    case 0x32:
    case 0x34:
        device_receive_control_reply(sequence_id,payload,length);
        break;
    case 0x36:
        if (length >= 26) {
            memcpy(message_temporary.payload_bytes,payload,26);
            input_apply_host_motion_feedback(&message_temporary.motion_feedback); /* Last six bytes remain uninitialized. */
        }
        break;
    case 0x37:
        motion_receive_host_status(payload,length);
        break;
    case 0x3c:
        device_receive_clone_limit(payload,length);
        break;
    case 0x3d:
        device_receive_out_completion(payload,length);
        break;
    case 0x43:
        request_remote_wakeup();
        break;
    case 0x44:
        device_receive_halt_reply(payload,length);
        break;
    default:
        break;
    }
}

/* Native entry: 0x42021b68. */
/* Original function-byte SHA-256:
 * a7c83fb2c034ecf992c303a4991773de4f8beae3c089d56ffa73f55b5f48059a. */
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
    unsigned int dispatch_time_us_low = (unsigned int)esp_timer_get_time();
    memw(); LINK_LAST_DIRECT_RX_US = dispatch_time_us_low;
    if (type == 0x25 && length >= 16) {
        LinkSyncReply sync_reply;
        volatile LinkSyncReply *reply_view = &sync_reply;
        reply_view->request_words[0] = 0;
        reply_view->request_words[1] = 0;
        reply_view->received_at_low = 0;
        reply_view->zero = 0;
        memcpy(sync_reply.request_words,payload,8);
        memcpy(&sync_reply.received_at_low,&received_at_low,4);
        (void)link_frame_enqueue(2,(unsigned char)flags,&sync_reply,16,0,0);
        return;
    }
    if (type == 2 && length >= 16) {
        LinkSyncSample sync_sample;
        volatile LinkSyncSample *sample_view = &sync_sample;
        sample_view->payload_words[0] = 0;
        sample_view->payload_words[1] = 0;
        sample_view->payload_words[2] = 0;
        sample_view->received_at_low = received_at_low;
        const unsigned char *payload_bytes = payload;
        memcpy(&sync_sample.payload_words[0],payload_bytes + 4,4);
        memcpy(&sync_sample.payload_words[1],payload_bytes + 8,4);
        memcpy(&sync_sample.payload_words[2],payload_bytes + 12,4);
        RtosQueue *event_queue = LINK_SYNC_QUEUE;
        if (event_queue != 0) (void)xQueueGenericSend(event_queue,&sync_sample,0,0);
        return;
    }
    LinkApplicationFrameHandler callback = LINK_APPLICATION_HANDLER;
    if (callback != 0) {
        void *context = LINK_APPLICATION_CONTEXT;
        callback(type,flags,payload,length,context);
    }
}

/* Native entry: 0x4202277c. */
/* Original function-byte SHA-256:
 * 2941fd8c88c8413b171e56253151e7b3dee535173ba669e5d01d657b324804a6. */
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

/* Native entry: 0x4202278c. */
/*
 * Medius v3.4.7 — device application; 0x4202278c.
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
 * 87de4845133761ec5c1d59926a5492a8ce3cfe191e4ba57e520fd99f1f6e72f2.
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
        LINK_TX_MUTEX_HANDLES.slot[channel] = rtos_create_mutex_type(1);
    LINK_TX_COMPLETION_SEMAPHORE = rtos_create_queue_type(1,0,3);
    for (unsigned int channel = 0; channel < 3; ++channel)
        LINK_TX_QUEUE_HANDLES.slot[channel] = rtos_create_queue_type(
            LINK_TX_QUEUE_CAPACITY,sizeof(LinkTxQueueItem),0);
    link_parser_init(LINK_RX_PARSER, link_receive_publish, 0);

    UartConfig configuration;
    volatile unsigned int *configuration_tail =
        (volatile unsigned int *)((unsigned int)&configuration + 8U);
    for (unsigned int word_index = 0; word_index < 6; ++word_index)
        configuration_tail[word_index] = 0;
    volatile UartConfig *configuration_view = &configuration;
    configuration_view->baud_rate = LINK_STARTUP_BAUD;
    configuration_view->data_bits = UART_DATA_8_BITS;
    configuration_view->stop_bits = UART_STOP_BITS_1;
    configuration_view->source_clock = UART_CLOCK_APB;
    if (uart_param_config(LINK_UART_NUMBER, &configuration) != 0)
        abort();
    if (uart_set_pin(LINK_UART_NUMBER, tx_pin, rx_pin, -1, -1) != 0)
        abort();

    UartRegisterView *uart_registers = LINK_UART1;
    memw();
    unsigned int configuration1 = uart_registers->conf1;
    memw();
    uart_registers->conf1 = (configuration1 & 0xfffffc00U) | 32U;
    memw();
    unsigned int memory_configuration_word = uart_registers->mem_conf;
    memw();
    uart_registers->mem_conf = (memory_configuration_word & 0xf801ffffU) | (20U << 17);
    memw();
    configuration1 = uart_registers->conf1;
    memw();
    uart_registers->conf1 = configuration1 | 0x00800000U;
    memw();
    configuration1 = uart_registers->conf1;
    memw();
    uart_registers->conf1 = (configuration1 & 0xfff003ffU) | (16U << 10);

    (void)xTaskCreatePinnedToCore(link_receive_task, "link_rx", 8192, 0, 12,
        (RtosTask **)&LINK_RX_TASK_HANDLE, 0);
    memw();
    (void)uart_registers->interrupt_enable; /* Native read is observable even though unused. */
    memw();
    uart_registers->interrupt_enable = 0;
    memw();
    uart_registers->interrupt_clear = 0xffffffffU;

    int interrupt_source = UART1_INTERRUPT_SOURCE;
    int interrupt_flags = INTR_FLAG_IRAM |
        (role == 0 ? ESP_INTR_FLAG_LEVEL2 : ESP_INTR_FLAG_LEVEL3);
    if (esp_intr_alloc(interrupt_source, interrupt_flags, link_uart_interrupt_handler,
                       0, (InterruptHandle **)&LINK_UART_IRQ_HANDLE) != 0)
        abort();
    (void)xPortEnterCriticalTimeout(&LINK_TX_LOCK, -1);
    memw();
    unsigned int enabled_interrupt_mask = uart_registers->interrupt_enable;
    memw();
    uart_registers->interrupt_enable = enabled_interrupt_mask | LINK_UART_RX_IRQS;
    vPortExitCritical(&LINK_TX_LOCK);

    (void)xTaskCreatePinnedToCore(link_transmit_task, "link_tx", 3072, 0, 13,
        (RtosTask **)&LINK_TX_TASK_HANDLE, RTOS_NO_CORE_AFFINITY);
    if (role == 1)
        (void)xTaskCreatePinnedToCore(link_baud_task, "link_baud", 3072, 0, 2,
                                     0, RTOS_NO_CORE_AFFINITY);
    unsigned int log_timestamp = esp_log_timestamp();
    const char *role_name = role == 1 ? "HOST" : "DEVICE";
    esp_log_write(3, LINK_LOG_TAG,
        "I (%lu) %s: link up: role=%s UART%d tx=%d rx=%d baud=%d\n",
        (unsigned long)log_timestamp, LINK_LOG_TAG, role_name,
        LINK_UART_NUMBER, tx_pin, rx_pin, LINK_STARTUP_BAUD);
}


/* Native entry: 0x42022a04. */
/* Original function-byte SHA-256:
 * 3c31032f8ce9db3333e95637eadad42da87db01463efab4f4930e55e152e2c09. */
/* Opcode LOW8 selects queue0 for0x10, queue2 for0x1c, otherwise queue1.
 * Snapshot selected queue only to gate encoding; NULL returns0 untouched.
 * Encode into caller's522-byte queue item at+2 with capacity520, metadata LOW8
 * and length LOW16. Negative encoder result returns0; otherwise RELOAD queue
 * BEFORE writing encoded-length HALFWORD, then send the WHOLE item with wait0/
 * back. Only exact queue result1 succeeds. On success, snapshot TX task handle
 * and increment its notification index0 (value0, action2) if non-NULL; ignore
 * notification result and return1. Other queue results return0, retaining any
 * encoded scratch bytes. No mutex, retry, tail clearing or delivery guarantee.
 * Caller must supply522-byte scratch and serialize its reuse; unused frame
 * storage is copied too. A disappearing queue is not revalidated after encode. */
int link_queue_encoded_frame(LinkTxQueueItem *item,unsigned char opcode,
    unsigned char metadata,const void *payload,unsigned int length)
{
    unsigned int channel = opcode == 0x10 ? 0 : opcode == 0x1c ? 2 : 1;
    if (LINK_TX_QUEUE_HANDLES.slot[channel] == NULL)
        return 0;
    int encoded_length = link_frame_encode(item->encoded_frame,520,opcode,metadata,
        payload,(unsigned short)length);
    if (encoded_length < 0)
        return 0;
    RtosQueue *event_queue = LINK_TX_QUEUE_HANDLES.slot[channel];
    item->encoded_length = (unsigned short)encoded_length;
    if (xQueueGenericSend(event_queue,item,0,0) != 1)
        return 0;
    RtosTask *task = LINK_TX_TASK_HANDLE;
    if (task != NULL)
        xTaskGenericNotify(task,0,0,2,NULL);
    return 1;
}

/* Native entry: 0x42022580. */
/* Original function-byte SHA-256:
 * d3cc7b425a19abf50245ec457971ad5bad38dc333c5b95abee0aac7527536cd2. */
/*
 * MEMW then read the full inter-chip RX "other frame type" drop counter once.
 * The transport overflow path increments this WORD for the unselected frame
 * category; the control status response exposes it. Return the wrapping count
 * unchanged. No reset, lock, retry or coherent snapshot with other counters.
 */
unsigned int link_get_other_rx_drops(void)
{
    memw();
    return LINK_RX_OTHER_TYPE_DROPS;
}
