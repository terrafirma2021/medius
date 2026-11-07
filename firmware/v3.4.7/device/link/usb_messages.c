/* Medius v3.4.7 device: USB messages and bridge relay services. */
#include "../include/types.h"

/* Local reconstruction utilities: the native signed binding count is
 * trusted. Preserve wrapping 32-bit addressing without a twelve-entry cap. */
static inline __attribute__((always_inline)) const volatile CreditBinding *
usb_message_binding(unsigned int index)
{
    return (const volatile CreditBinding *)
        ((unsigned int)CREDIT_BINDING_RECORDS + index * 8U);
}

/* Native entry: 0x42022568. */
/* Original function-byte SHA-256:
 * fadc7b719a0116adf975abd89fda3c5bd431af3a770afef3f20d97312cdcfd9f. */
/* Return selected-type drops plus RX FIFO overflow drops, wrapping at 32 bits.
 * MEMW/read selected-type count, then MEMW/read FIFO count. The two samples are
 * independent; this does not count every possible link loss or reset counters. */
unsigned int link_get_selected_and_fifo_rx_drops(void)
{
    memw();
    unsigned int selected_type_drops=LINK_RX_SELECTED_TYPE_DROPS;
    memw();
    unsigned int fifo_overflow_drops=LINK_RX_FIFO_OVERFLOW_COUNT;
    return selected_type_drops+fifo_overflow_drops;
}

/* Native entry: 0x4203345c. */
/* Original function-byte SHA-256:
 * 102110b5874873e739da7e7e19eedce8da71cc39c44cd794a2ce046524b438a4. */
/* Sample current OUT generation, then last forwarded generation, with MEMW
 * before each WORD read. If unsigned forwarded < current, forward that cached
 * current generation with skip_out_wait=0. Do not reread current, handle wrap,
 * acquire a local lock or force forwarding when generations compare equal. */
void control_forward_pending_generation(void)
{
    memw();
    unsigned int current_generation=DEVICE_OUT_GENERATION;
    memw();
    unsigned int forwarded_generation=CONTROL_FORWARDED_GENERATION;
    if (forwarded_generation<current_generation)
        control_forward_generations(current_generation,0);
}

/* Native entry: 0x4203349c. */
/* Original function-byte SHA-256:
 * 33253306d2302f7a8ba420fd034578514ccd6016d357e3c48cade5aeefd45cd9. */
/* Return the last unaligned-IN diagnostic. MEMW/read endpoint BYTE, then
 * MEMW/read source-address WORD before writing endpoint and address outputs.
 * Finally MEMW/read length WORD and write it. Source address is returned as raw
 * 32-bit bits. No NULL/output-alias check, lock or coherent-snapshot guarantee;
 * a larger object supplied for endpoint receives only its first byte. */
void usbd_read_last_unaligned_write(unsigned char *endpoint_out,
    unsigned int *source_address_out,unsigned int *length_out)
{
    memw();
    unsigned char endpoint=USBD_UNALIGNED_WRITE->endpoint;
    memw();
    unsigned int source_address=(unsigned int)USBD_UNALIGNED_WRITE->source_buffer;
    *(volatile unsigned char *)endpoint_out=endpoint;
    *(volatile unsigned int *)source_address_out=source_address;
    memw();
    unsigned int length=USBD_UNALIGNED_WRITE->length;
    *(volatile unsigned int *)length_out=length;
}

/* Native entry: 0x420335c8. */
/* Original function-byte SHA-256:
 * 2f9846d14b87e3b8d0713cd015d45be9e3ec6704145c8a609457e7f26146a6a5. */
/* Handle a forwarded IN report or secondary-IN stall notification (opcode 0x1c).
 * Require eight bytes, clone-active, configured bus0, and a matching endpoint in
 * the raw signed binding count (not clamped to 12). Endpoint must be IN and its
 * secondary queue slot <6. Flags bit1 selects stall handling; other reports are
 * rewritten with traffic class7/direction1 and a 64-byte aligned scratch buffer.
 * On rewrite success enqueue with a freshly read endpoint, cached LE source
 * stamp, kind1, synthetic0 and flags=(incoming bit0 | rewrite flags).
 * Stall payloads with any bytes first pass byte8 through sequence admission;
 * rejection returns, admission reloads endpoint. Under the credit spinlock,
 * rescan fresh bindings/count, set the matching slot's stall-pending BYTE after
 * MEMW, then pump using the binding INDEX (not that slot). Ignore lock status;
 * release on every acquired path. No packet snapshot, count/capacity bound or
 * atomic guarantee across the pre-lock lookup, rewrite and locked rescan. */
void device_receive_in_report(unsigned char *payload,unsigned short length)
{
    if (length<8)
        return;
    memw();
    if (CLONE_ACTIVE==0 || !usb_device_is_configured(0))
        return;
    const volatile ForwardedInMessage *message=(const volatile void *)payload;
    unsigned int endpoint=message->endpoint;
    int binding_count=CREDIT_BINDINGS.count;
    if (binding_count<1)
        return;
    unsigned int binding_index;
    for (binding_index=0;binding_index<(unsigned int)binding_count;++binding_index) {
        if (usb_message_binding(binding_index)->endpoint==endpoint)
            break;
    }
    if (binding_index==(unsigned int)binding_count || !(endpoint&0x80U) ||
        usb_message_binding(binding_index)->queue_slot>=6)
        return;
    unsigned char incoming_flags=message->flags;
    unsigned int report_length=(unsigned short)(length-8);
    if (!(incoming_flags&2U)) {
        unsigned int stamp_byte1=message->source_stamp_le[1];
        unsigned int stamp_byte0=message->source_stamp_le[0];
        unsigned int stamp_byte2=message->source_stamp_le[2];
        unsigned int stamp_byte3=message->source_stamp_le[3];
        unsigned int source_stamp=stamp_byte0|(stamp_byte1<<8)|(stamp_byte2<<16)|(stamp_byte3<<24);
        unsigned char rewrite_buffer[64] __attribute__((aligned(4)));
        unsigned char *rewritten_report;
        unsigned short rewritten_length;
        unsigned char rewrite_flags;
        unsigned int rewrite_result=report_apply_rewrite(7,endpoint,1,payload+8,
            report_length,rewrite_buffer,&rewritten_report,&rewritten_length,&rewrite_flags);
        if (rewrite_result==0) {
            unsigned char combined_flags=(incoming_flags&1U)|rewrite_flags;
            unsigned int fresh_endpoint=message->endpoint;
            report_enqueue_secondary(fresh_endpoint,rewritten_report,rewritten_length,
                1,source_stamp,0,combined_flags);
        }
        return;
    }
    if (report_length!=0) {
        unsigned char sequence=message->report[0];
        if (!report_sequence_allowed(endpoint,sequence))
            return;
        endpoint=message->endpoint;
    }
    (void)xPortEnterCriticalTimeout(&CREDIT_LOCK,-1);
    binding_count=CREDIT_BINDINGS.count;
    if (binding_count>0) {
        for (binding_index=0;binding_index<(unsigned int)binding_count;++binding_index) {
            if (usb_message_binding(binding_index)->endpoint!=endpoint)
                continue;
            if (endpoint&0x80U) {
                unsigned int queue_slot=usb_message_binding(binding_index)->queue_slot;
                if (queue_slot<6) {
                    memw();
                    REPORT_SECONDARY_STALL_PENDING[queue_slot]=1;
                    report_pump_secondary(binding_index);
                }
            }
            break;
        }
    }
    vPortExitCritical(&CREDIT_LOCK);
}

/* Native entry: 0x4203374c. */
/* Original function-byte SHA-256:
 * beee9b6658bffbeb5e4d6db60642ac6c5a69ba08c7a3c1027cb0f77c92a67cbf. */
/* Consume a three-byte OUT completion/credit message (opcode 0x3d).
 * Under the OUT spinlock, accept a nonzero OUT endpoint matching one of exactly
 * ten records. Sequence advance is modulo256 and must be nonzero and no greater
 * than outstanding sent-minus-ack sequence. Sample recovery flag before storing
 * the new ack sequence. Clear recovery only with no completion debt and signed
 * modulo8 sequence beyond its marker. Add advance to acknowledged credits with
 * byte wrap; clear blocked when unsigned produced-minus-new credits <2.
 * Record uptime LOW then HIGH. Status1 requests stall only if neither a stall
 * nor an older/recovered sequence already covers it. After setting the latch,
 * reread status; status2 adds advance to the wrapping WORD drop count.
 * Always release the lock before querying bus0 configuration, including invalid
 * endpoint/sequence cases (whose query result is discarded). For accepted data
 * and configured USB, reread packet endpoint: newly requested stall calls stall,
 * otherwise drain pending OUT work. Ignore lock/stall results. No packet/record
 * snapshot, NULL/capacity check or atomic behavior across the unlocked calls. */
void device_receive_out_completion(unsigned char *payload,unsigned short length)
{
    if (length<3)
        return;
    const volatile OutCompletionMessage *message=(const volatile void *)payload;
    (void)xPortEnterCriticalTimeout(DEVICE_OUT_LOCK,-1);
    unsigned int endpoint=message->endpoint;
    if (!(endpoint&0x7fU) || (endpoint&0x80U))
        goto rejected;
    unsigned int index;
    for (index=0;index<10;++index) {
        if (DEVICE_OUT_ENDPOINTS[index].endpoint==endpoint)
            break;
    }
    if (index==10)
        goto rejected;
    volatile DeviceOutEndpoint *endpoint_state=&DEVICE_OUT_ENDPOINTS[(unsigned short)index];
    unsigned int sequence=message->sequence;
    unsigned int previous_ack_sequence=endpoint_state->rebase_sequence;
    unsigned int sequence_advance=(sequence-previous_ack_sequence)&255U;
    if (sequence_advance==0)
        goto rejected;
    unsigned int sent_sequence=endpoint_state->sent_sequence;
    if (sequence_advance>((sent_sequence-previous_ack_sequence)&255U))
        goto rejected;
    unsigned char recovery_pending=endpoint_state->completion_recovery_pending;
    endpoint_state->rebase_sequence=(unsigned char)sequence;
    if (recovery_pending && endpoint_state->completion_debt==0 &&
        (signed char)(sequence-endpoint_state->sequence_marker)>0)
        endpoint_state->completion_recovery_pending=0;
    unsigned int acknowledged_credits=endpoint_state->acknowledged;
    unsigned char blocked=endpoint_state->blocked;
    unsigned int updated_credits=(acknowledged_credits+sequence_advance)&255U;
    endpoint_state->acknowledged=(unsigned char)updated_credits;
    if (blocked && (((unsigned int)endpoint_state->produced-updated_credits)&255U)<2)
        endpoint_state->blocked=0;
    unsigned long long completion_time_us=(unsigned long long)esp_timer_get_time();
    volatile DeviceOutEndpoint *timestamp_endpoint_state=&DEVICE_OUT_ENDPOINTS[index];
    timestamp_endpoint_state->last_forward_us_low=(unsigned int)completion_time_us;
    timestamp_endpoint_state->last_forward_us_high=(unsigned int)(completion_time_us>>32);
    unsigned int status=message->status;
    unsigned int request_stall=0;
    if (status==1) {
        if (endpoint_state->halt_requested)
            goto already_stalled;
        if (endpoint_state->completion_recovery_pending &&
            (signed char)((unsigned int)message->sequence-endpoint_state->sequence_marker)<=0)
            goto already_stalled;
        endpoint_state->halt_requested=1;
        status=message->status;
        request_stall=1;
    }
    if (status==2) {
        memw();
        unsigned int drop_count=DEVICE_OUT_DROPS;
        memw();
        DEVICE_OUT_DROPS=drop_count+sequence_advance;
    }
    vPortExitCritical(DEVICE_OUT_LOCK);
    if (!usb_device_is_configured(0))
        return;
    endpoint=message->endpoint;
    if (request_stall)
        (void)usb_device_set_stall(0,(unsigned char)endpoint);
    else
        out_drain_pending(endpoint);
    return;
already_stalled:
    vPortExitCritical(DEVICE_OUT_LOCK);
    if (usb_device_is_configured(0))
        out_drain_pending(message->endpoint);
    return;
rejected:
    vPortExitCritical(DEVICE_OUT_LOCK);
    (void)usb_device_is_configured(0);
}

/* Native entry: 0x42033b4c. */
/* Original function-byte SHA-256:
 * b1e18ae31ac72f1301496e5a29e5715ee4b8cb1c4fee2b1ba507de0a35649273. */
/* Accept a two-byte endpoint-halt acknowledgement only while waiting and its
 * sequence matches. Read packet sequence before MEMW/expected-sequence read.
 * Read result, MEMW/publish it, MEMW/clear waiting, then MEMW/read EP0 waiting.
 * If EP0 also waits and its sampled signal is non-NULL, MEMW/clear EP0 waiting
 * and give that cached signal nonblocking. Ignore send status. No waiter lock,
 * timeout, generation check, result validation or queue lifetime protection. */
void device_receive_halt_reply(unsigned char *payload,unsigned short length)
{
    if (length<2)
        return;
    memw();
    if (ENDPOINT_HALT_REPLY->waiting==0)
        return;
    const volatile EndpointHaltAck *ack=(const volatile void *)payload;
    unsigned char sequence=ack->sequence;
    memw();
    if (sequence!=ENDPOINT_HALT_REPLY->sequence)
        return;
    unsigned char acknowledgement_result=ack->result;
    memw();
    ENDPOINT_HALT_REPLY->result=acknowledgement_result;
    memw();
    ENDPOINT_HALT_REPLY->waiting=0;
    memw();
    if (EP0_REPLY_WAITING==0)
        return;
    RtosQueue *reply_signal=CONTROL_ENDPOINT_REPLY_SIGNAL;
    if (reply_signal!=NULL) {
        memw();
        EP0_REPLY_WAITING=0;
        (void)xQueueGenericSend(reply_signal,NULL,0,0);
    }
}

/* Native entry: 0x42033be4. */
/* Original function-byte SHA-256:
 * 18da2dc57f8c1fd3a4137cb80c819830fe242ce757976e117df62407bd9892fe. */
/* Flush pending synthetic input only if its sampled BYTE count is nonzero.
 * The native wrapper adds no MEMW, lock, count reset, retry or return status. */
void input_flush_if_pending(void)
{
    if (INPUT_PENDING_COUNT!=0)
        input_flush_pending();
}

/* Native entry: 0x42033bf4. */
/* Original function-byte SHA-256:
 * a2f44c70eeeaa7c8d605b2e926df69ca899b82b58486abd7dbdf09a4b6514a96. */
/* Try to relay the device's selected configuration to the host. Cache published
 * generation after MEMW, then gate on clone-active, not quiescing, cached
 * generation !=UINT32_MAX, not suspended and configured bus0. Suspension is
 * sampled even when the cached generation is invalid. Sample control operation
 * WORD between two MEMWs; only zero attempts generation acquisition.
 * On success MEMW/read configuration BYTE, then sequence-window latest BYTE;
 * send opcode0x24/metadata0 with [configuration,1,latest_sequence] and length3.
 * Ignore send result, then give a non-NULL freshly sampled forward gate without
 * blocking. Do not release the acquired generation here, retry sends, resample
 * generation or provide an atomic snapshot across any of these gates. */
void device_relay_current_configuration(void)
{
    memw();
    unsigned int published_generation=USB_PUBLISHED_CONFIGURATION_GENERATION;
    memw();
    if (CLONE_ACTIVE==0)
        return;
    memw();
    if (CLONE_QUIESCING!=0)
        return;
    memw();
    unsigned char suspended=USB_SUSPENDED;
    if (published_generation==0xffffffffU || suspended!=0 || !usb_device_is_configured(0))
        return;
    memw();
    unsigned int control_operation=CONTROL_OPERATION_ACTIVE;
    memw();
    if (control_operation!=0 || !control_forward_acquire_generation(published_generation))
        return;
    memw();
    unsigned char configuration=USB_PUBLISHED_CONFIGURATION_INDEX;
    unsigned char latest_sequence=REPORT_SEQUENCE_WINDOW.latest_sequence;
    unsigned char message[3];
    volatile unsigned char *message_bytes=message;
    message_bytes[2]=latest_sequence;
    message_bytes[0]=configuration;
    message_bytes[1]=1;
    (void)link_send_wait100(0x24,0,message,3);
    RtosQueue *forward_gate=CONTROL_FORWARD_GATE;
    if (forward_gate!=NULL)
        (void)xQueueGenericSend(forward_gate,NULL,0,0);
}

/* Native entry: 0x42033e50. */
/* Original function-byte SHA-256:
 * 46398fab02b3e98ec723ec322f12e5caeabaa74fd1717a6024c97e783c5a5975. */
/* Route a control reply by correlation bit7. Low correlations require external
 * waiting, then MEMW/read expected sequence even when length<2. On a match copy
 * at most504 bytes from offset2; publish status WORD before memcpy. Cache signal
 * after copy, MEMW/store actual HALFWORD, MEMW/store completed sequence BYTE,
 * then give the cached signal unconditionally (including NULL), nonblocking.
 * Waiting is not cleared here. High correlations use the optional rewrite mutex
 * and playback waiting/sequence: deliver status BYTE/payload/length-2 only when
 * waiting, matching and length>1. Release a freshly read mutex after delivery or
 * mismatch on the locked path; initially NULL plus not waiting returns directly.
 * No pointer, generation, payload snapshot, lock-result or send-result check.
 */
void device_receive_control_reply(unsigned char correlation,
    unsigned char *payload,unsigned short length)
{
    const volatile ControlReplyMessage *message=(const volatile void *)payload;
    if (!(correlation&0x80U)) {
        ExternalControlReply *reply=EXTERNAL_CONTROL_REPLY;
        memw();
        if (reply->waiting==0)
            return;
        memw();
        unsigned char expected_sequence=reply->sequence;
        if (length<2 || expected_sequence!=correlation)
            return;
        unsigned int reply_length=(unsigned short)(length-2);
        if (reply_length>504)
            reply_length=504;
        unsigned int status=message->status;
        memw();
        reply->status=status;
        memcpy(reply->payload,payload+2,reply_length);
        RtosQueue *reply_signal=reply->signal;
        memw();
        reply->actual=(unsigned short)reply_length;
        memw();
        reply->completed_sequence=correlation;
        (void)xQueueGenericSend(reply_signal,NULL,0,0);
        return;
    }
    RtosQueue *rewrite_mutex=REWRITE_MUTEX;
    if (rewrite_mutex!=NULL) {
        (void)xQueueSemaphoreTake(rewrite_mutex,0xffffffffU);
        if (!PLAYBACK_CONTROL_REQUEST->waiting)
            goto release_mutex;
    } else if (!PLAYBACK_CONTROL_REQUEST->waiting) {
        return;
    }
    if (PLAYBACK_CONTROL_SEQUENCE==correlation && length>1)
        playback_control_complete(message->status,payload+2,(unsigned short)(length-2));
release_mutex:
    rewrite_mutex=REWRITE_MUTEX;
    if (rewrite_mutex!=NULL)
        (void)xQueueGenericSend(rewrite_mutex,NULL,0,0);
}

/* Native entry: 0x42037c40. */
/* Original function-byte SHA-256:
 * 48f7b036c6f5e56198777c996a18e27a37e8188a4a0eb81d48caee6e14ac145a. */
/* Truncate all three arguments to BYTE and forward them to USB bus-event
 * capture. This wrapper adds no state, filtering, timestamp or return value. */
void capture_forward_usb_bus_event(unsigned char event,unsigned char value0,
    unsigned char value1)
{
    capture_usb_bus_event(event,value0,value1);
}

/* Native entry: 0x42038780. */
/* Original function-byte SHA-256:
 * 91fe1647607da1c7106904054e92ed0a060f677eb374d30b6a74c8131df6af11. */
/* Atomically consume the descriptor-patch refresh flag with exchange-to-zero,
 * memory-order argument4. A zero old BYTE returns0 without mutex/checker calls.
 * Otherwise sample the rewrite mutex: when non-NULL take it indefinitely,
 * discard acquisition status, call the refresh checker, then give a freshly
 * reread non-NULL mutex. Initially NULL calls the checker without a later give.
 * Return its raw BYTE widened to unsigned int. No flag restoration on failure,
 * retry, local timeout or mutex-lifetime guarantee is supplied. */
unsigned int descriptor_service_patch_refresh(void)
{
    if (atomic_exchange_byte((unsigned char *)&IMPERFECT_PATCH_REFRESH,0,4)==0)
        return 0;
    RtosQueue *rewrite_mutex=REWRITE_MUTEX;
    if (rewrite_mutex==NULL)
        return descriptor_patches_need_refresh();
    (void)xQueueSemaphoreTake(rewrite_mutex,0xffffffffU);
    unsigned int refresh_required=descriptor_patches_need_refresh();
    rewrite_mutex=REWRITE_MUTEX;
    if (rewrite_mutex!=NULL)
        (void)xQueueGenericSend(rewrite_mutex,NULL,0,0);
    return refresh_required;
}

/* Native entry: 0x42039960. */
/* Original function-byte SHA-256:
 * 45f52428f324a8f00963f9eae4c040e6d64c0a35e96048f85a504310b0d04fe7. */
/* Log a seven-byte host cloning-limit notice (opcode0x3c). With an optional
 * report mutex, clear runtime clone state only when clone-active is zero.
 * A NULL initial mutex with active clone skips both clear and release; other
 * paths release a freshly sampled non-NULL mutex after the optional clear.
 * Then read value-high, vendor-high, product-high, value-low, product-low,
 * vendor-low, reason, preserving native BYTE load order. Reasons1/2/4 log
 * configuration bytes/hub ports/table bytes with the supplied unsigned value;
 * every other reason logs a hub behind a hub, without that value argument.
 * Fresh timestamp, error level1 and tag usbdev are used. No clone transition
 * when already active, reason validation, retry or send/status return exists. */
void device_receive_clone_limit(unsigned char *payload,unsigned short length)
{
    if (length<7)
        return;
    RtosQueue *report_mutex=REPORT_MUTEX;
    if (report_mutex==NULL) {
        memw();
        if (CLONE_ACTIVE)
            goto emit_log;
    } else {
        (void)xQueueSemaphoreTake(report_mutex,0xffffffffU);
        memw();
        if (CLONE_ACTIVE)
            goto release_mutex;
    }
    usb_clone_clear_runtime_state();
release_mutex:
    report_mutex=REPORT_MUTEX;
    if (report_mutex!=NULL)
        (void)xQueueGenericSend(report_mutex,NULL,0,0);
emit_log:;
    const volatile CloneLimitNotice *notice=(const volatile void *)payload;
    unsigned int value_high=notice->value_le[1];
    unsigned int vendor_high=notice->vendor_le[1];
    unsigned int product_high=notice->product_le[1];
    unsigned int value_low=notice->value_le[0];
    unsigned int product_low=notice->product_le[0];
    unsigned int vendor_low=notice->vendor_le[0];
    unsigned int reason=notice->reason;
    unsigned int reported_value=value_low|(value_high<<8);
    unsigned int vendor_id=vendor_low|(vendor_high<<8);
    unsigned int product_id=product_low|(product_high<<8);
    const char *log_format;
    unsigned int log_timestamp;
    if (reason==1) {
        log_timestamp=esp_log_timestamp();
        log_format="E (%lu) %s: %04X:%04X configuration of %u bytes, past the host chip\'s buffer -> not cloning\n";
    } else if (reason==2) {
        log_timestamp=esp_log_timestamp();
        log_format="E (%lu) %s: %04X:%04X hub with %u ports, past what the host chip holds -> not cloning\n";
    } else if (reason==4) {
        log_timestamp=esp_log_timestamp();
        log_format="E (%lu) %s: %04X:%04X configuration\'s tables need %u bytes, more than the host chip has free -> not cloning\n";
    } else {
        log_timestamp=esp_log_timestamp();
        esp_log_write(1,"usbdev","E (%lu) %s: %04X:%04X hub behind a hub -> not cloning\n",
            log_timestamp,"usbdev",vendor_id,product_id);
        return;
    }
    esp_log_write(1,"usbdev",log_format,log_timestamp,"usbdev",vendor_id,product_id,reported_value);
}
