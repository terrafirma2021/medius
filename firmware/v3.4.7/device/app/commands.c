/* Device UART application command dispatch and activity timestamp. */
#include "../include/types.h"

/* Source reconstruction utilities: little-endian reply BYTE encoding,
 * not additional native functions. Replies are private until the send call. */
static __attribute__((always_inline)) inline void control_query_put_u16(
    unsigned char *output,unsigned int value)
{
    output[0]=(unsigned char)value;
    output[1]=(unsigned char)(value>>8);
}
static __attribute__((always_inline)) inline void control_query_put_u32(
    unsigned char *output,unsigned int value)
{
    output[0]=(unsigned char)value;
    output[1]=(unsigned char)(value>>8);
    output[2]=(unsigned char)(value>>16);
    output[3]=(unsigned char)(value>>24);
}

/* Native entry: 0x4200a7a0. */
/* Original function-byte SHA-256:
 * 7b6d98aef9a9b30126917926e3de5897fc0b93e7eff539225350141cd7ffdf20. */
/* Dispatch one externally framed control command; framing/CRC belong to the
 * caller. Opcode/sequence are raw BYTES, length is LOW16, context is ignored.
 * Payload is borrowed and must remain valid for its declared length. BYTE
 * samples below retain native order, including repeated reads after callbacks.
 * There is no blanket payload-pointer check, acknowledgement or dispatcher lock.
 *
 * QUERY(5) flushes pending input first. Its selectors are version 0, health 1,
 * device 2, capabilities 3, rate 4, statistics 5, locks 6, catch 7, options 9, clip 10,
 * firmware 11, rewrite-summary 12, rewrite-entry 13, patches 14, patch-entry 15 and
 * transforms 16. Selector 8, unknown/short selectors and option 3 send no reply.
 * Normal replies use opcode 6 and the request sequence. Encoders supply their
 * own selector; their full-WORD lengths are forwarded unchanged. Only the two
 * global entry-query buffers cap a nonzero encoder length to 512; zero skips
 * their send. Fixed replies are little endian. Product scan reads byte 0 then
 * at most bytes 1..127, copies at most 127 bytes and calls memcpy even for zero
 * length/NULL product. Statistics retain ordered independent getter snapshots,
 * saturation to 8/16 bits, and wrapping 32-bit aggregate-drop addition.
 * Every QUERY, even empty/unknown, finishes with begin_change(0), a fresh clock
 * sample and locked MEMW/LOW, MEMW/HIGH last-command publication.
 *
 * Other opcodes first call begin_change(((opcode-4) modulo 256)>1), sample time
 * and publish it under the LED-control spinlock. MOVE 1 skips the input flush;
 * every other nonquery flushes before routing. MOVE accepts cursor selector 0
 * at length>=6 and wheel/pan 1/2 at>=4, rejects flags with both bits 1/2 set and
 * forwards only low 3 flag bits. INJECT 3 requires four bytes and class<3.
 * RESET 4 requires byte 0<=1, resets session/releases overrides, rereads byte 0
 * and optionally factory-resets, confirms image and reboots. Every RESET path
 * returns directly, including invalid requests, without the common sequence
 * increment. REBOOT 7 maps 0/2 to local download/run and 1/3 to host link opcode 4.
 *
 * LED 9 samples target, link-value, mode and local-value in that order; byte 2
 * is deliberately read twice. Under the control lock target 0/2 updates local
 * LED and ownership, target 1/2 updates host ownership. Send cached mode/first
 * value to host after unlocking. Other targets only take/release the lock.
 * LOCK 10/CATCH 11 require six bytes; OPTION 17 routes 0..6 with per-field minimum
 * sizes, and changed imperfect/emit options request reboot. CLIP 18/19/20 and
 * UPDATE 23 preserve raw helper arguments, including zero-length append/update.
 * TRIGGER 21 checks packet classes 4..9 separately: length>=8+2*match_length;
 * other classes use the six-byte input-trigger boundary. RAW 25 and TRANSFER 26
 * call the permission getter with all three outputs and require allow != 0.
 * Transfer publishes a
 * cached endpoint and BYTE status, sends header only on nonzero full-WORD
 * status, otherwise LOW16(actual+2), with 504-byte response capacity. Denial is
 * status 0xfc; the shared 506-byte response has no dispatcher serialization.
 * REWRITE 28 validates both match/mask spans and total forwarded size<=512.
 * PATCH 29 handles 0xfe apply/0xff clear regardless of extra bytes; other kinds
 * require length 5..510 and are passed raw to the helper. TRANSFORM 30 needs 8.
 * Unknown/short nonqueries still advance the change sequence once, except
 * RESET. Helper errors and send status are ignored unless explicitly tested.
 * No extra bounds normalization, rollback, timing or concurrency guarantee. */
void control_command_dispatch(unsigned char opcode,unsigned char sequence,
    const unsigned char *payload,unsigned short length,void *context)
{
    (void)context;
    const volatile unsigned char *wire=payload;
    if (opcode==CONTROL_COMMAND_QUERY) {
        input_flush_if_pending();
        unsigned char reply[512];
        unsigned char *query_output=reply;
        unsigned int reply_length=0;
        unsigned char send_reply=0;
        if (length!=0) {
            unsigned char selector=wire[0];
            switch (selector) {
            case CONTROL_QUERY_VERSION:
                query_version_send(sequence);
                break;
            case CONTROL_QUERY_HEALTH: {
                unsigned int flags=health_flags_get();
                memw();
                unsigned char host_connected=LED_CONTROL_FLAGS->host_connected;
                memw();
                unsigned char primary_selected=LED_CONTROL_FLAGS->primary_interface_selected;
                flags=(flags|host_connected|((unsigned int)primary_selected<<1))&65535U;
                reply[0]=1;
                control_query_put_u16(reply+1,flags);
                reply_length=3;send_reply=1;
                break;
            }
            case CONTROL_QUERY_DEVICE: {
                unsigned short vid=0,pid=0,bcd_device=0,bcd_usb=0;
                unsigned char flags=0;
                (void)device_info_get(&vid,&pid,&bcd_device,&bcd_usb,&flags);
                unsigned int saved_vid=vid,saved_usb=bcd_usb,saved_pid=pid;
                unsigned int saved_device=bcd_device;
                unsigned char saved_flags=flags;
                unsigned int kind=device_kind_get();
                reply[0]=2;
                control_query_put_u16(reply+1,saved_vid);
                control_query_put_u16(reply+3,saved_pid);
                control_query_put_u16(reply+5,saved_device);
                control_query_put_u16(reply+7,saved_usb);
                reply[9]=saved_flags;reply[10]=(unsigned char)kind;
                const char *product=device_product_get();
                unsigned int product_length=0;
                if (product!=NULL && ((const volatile unsigned char *)product)[0]!=0) {
                    product_length=127;
                    for (unsigned int index=1;index<=127;++index) {
                        if (((const volatile unsigned char *)product)[index]==0) {
                            product_length=index;
                            break;
                        }
                    }
                }
                memcpy(reply+11,product,product_length);
                reply_length=(unsigned short)(product_length+11U);send_reply=1;
                break;
            }
            case CONTROL_QUERY_CAPABILITIES: {
                unsigned char buttons=0,mouse_flags=0,mouse_interfaces=0;
                (void)mouse_caps_get(&buttons,&mouse_flags,&mouse_interfaces);
                unsigned char keyboard_limit=0,keyboard_flags=0;
                (void)keyboard_caps_get(&keyboard_limit,&keyboard_flags);
                reply[0]=3;reply[1]=buttons;reply[2]=mouse_flags;
                reply[3]=mouse_interfaces;reply[4]=keyboard_limit;reply[5]=keyboard_flags;
                reply[6]=(keyboard_limit!=0 || keyboard_flags!=0)?2:0;
                reply_length=7;send_reply=1;
                break;
            }
            case CONTROL_QUERY_RATE: {
                unsigned short measured_period=0,endpoint_period=0;
                unsigned char confident=0,keyboard_fallback=0;
                (void)rate_get(&measured_period,&endpoint_period,
                    &confident,&keyboard_fallback);
                reply[0]=4;
                control_query_put_u16(reply+1,measured_period);
                control_query_put_u16(reply+3,endpoint_period);
                reply[5]=(unsigned char)(((unsigned int)keyboard_fallback<<1)|confident);
                reply_length=6;send_reply=1;
                break;
            }
            case CONTROL_QUERY_STATISTICS: {
                unsigned int emissions=input_emission_count();
                unsigned int primary_drops=report_primary_fallback_drop_count();
                unsigned int merged_reports=report_merge_accept_count();
                unsigned int depth_high_water=report_queue_depth_high_water();
                unsigned int busy_watchdogs=report_busy_watchdog_count();
                unsigned int wakeup_resumes=report_wakeup_resume_count();
                unsigned int resets=usbd_get_reset_count();
                unsigned int configurations=usbd_get_configuration_event_count();
                unsigned int counted_drops=link_get_selected_and_fifo_rx_drops();
                unsigned int host_counted_drops=status_get_host_counted_rx_drops();
                unsigned int aggregate_drops=forwarding_drop_count();
                aggregate_drops+=link_get_other_rx_drops();
                aggregate_drops+=control_rx_drop_count();
                unsigned int epoch=input_change_epoch();
                reply[0]=5;
                control_query_put_u32(reply+1,emissions);
                control_query_put_u16(reply+5,primary_drops<65535U?primary_drops:65535U);
                control_query_put_u16(reply+7,merged_reports<65535U?merged_reports:65535U);
                reply[9]=(unsigned char)(depth_high_water<255U?depth_high_water:255U);
                reply[10]=(unsigned char)(busy_watchdogs<255U?busy_watchdogs:255U);
                control_query_put_u16(reply+11,wakeup_resumes<65535U?wakeup_resumes:65535U);
                control_query_put_u16(reply+13,resets<65535U?resets:65535U);
                control_query_put_u16(reply+15,configurations<65535U?configurations:65535U);
                control_query_put_u32(reply+17,counted_drops);
                control_query_put_u32(reply+21,host_counted_drops);
                control_query_put_u32(reply+25,aggregate_drops);
                control_query_put_u16(reply+29,epoch);
                reply_length=31;send_reply=1;
                break;
            }
            case CONTROL_QUERY_LOCKS:
                reply_length=locks_encode(reply);send_reply=1;break;
            case CONTROL_QUERY_CATCH:
                reply_length=capture_status_encode(reply);send_reply=1;break;
            case CONTROL_QUERY_OPTIONS:
                if (length>=2) {
                    switch (wire[1]) {
                    case CONTROL_OPTION_IMPERFECT: {
                        unsigned char allow=0,over_capacity=0,imperfect=0;
                        option_get_imperfect(&allow,&over_capacity,&imperfect);
                        reply[0]=9;reply[1]=0;reply[2]=allow;
                        reply[3]=over_capacity;reply[4]=imperfect;
                        reply_length=5;send_reply=1;break;
                    }
                    case CONTROL_OPTION_MOVEMENT_RIDING: {
                        unsigned int window=option_get_movement_riding_ms();
                        reply[0]=9;reply[1]=1;control_query_put_u16(reply+2,window);
                        reply_length=4;send_reply=1;break;
                    }
                    case CONTROL_OPTION_EMISSION: {
                        unsigned char pace=0,forced_active=0;
                        unsigned short requested=0,effective=0,forced=0,learned=0;
                        option_get_emit(&pace,&requested,&effective,&forced,&learned,&forced_active);
                        reply[0]=9;reply[1]=2;reply[2]=pace;
                        control_query_put_u16(reply+3,requested);
                        control_query_put_u16(reply+5,effective);
                        control_query_put_u16(reply+7,forced);
                        control_query_put_u16(reply+9,learned);
                        reply[11]=forced_active;reply_length=12;send_reply=1;break;
                    }
                    case CONTROL_OPTION_BEARING: {
                        unsigned int window=option_get_bearing_window_ms();
                        unsigned char coupled=option_get_bearing_coupled();
                        reply[0]=9;reply[1]=4;control_query_put_u16(reply+2,window);
                        reply[4]=coupled;reply_length=5;send_reply=1;break;
                    }
                    case CONTROL_OPTION_RENDER: {
                        unsigned char profile=0,scope=0,armed=0;
                        option_get_render(&profile,&scope,&armed);
                        reply[0]=9;reply[1]=5;reply[2]=profile;reply[3]=scope;reply[4]=armed;
                        reply_length=5;send_reply=1;break;
                    }
                    case CONTROL_OPTION_SPREAD: {
                        unsigned short configured=0;
                        unsigned int effective_duration=0;
                        option_get_spread(&configured,&effective_duration);
                        reply[0]=9;reply[1]=6;control_query_put_u16(reply+2,configured);
                        control_query_put_u32(reply+4,effective_duration);
                        reply_length=8;send_reply=1;break;
                    }
                    default:break;
                    }
                }
                break;
            case CONTROL_QUERY_CLIP:
                reply_length=clip_status_encode(reply);send_reply=1;break;
            case CONTROL_QUERY_FIRMWARE:
                reply_length=firmware_info_encode(reply);send_reply=1;break;
            case CONTROL_QUERY_REWRITE_SUMMARY:
                reply_length=rewrite_summary_encode(reply);send_reply=1;break;
            case CONTROL_QUERY_REWRITE_ENTRY:
                if (length>=2) {
                    query_output=CONTROL_REWRITE_QUERY_BUFFER;
                    unsigned int encoded=rewrite_rule_encode(query_output,wire[1]);
                    if (encoded!=0) {reply_length=encoded<512U?encoded:512U;send_reply=1;}
                }
                break;
            case CONTROL_QUERY_PATCHES:
                reply_length=patches_encode(reply);send_reply=1;break;
            case CONTROL_QUERY_PATCH_ENTRY:
                if (length>=2) {
                    query_output=CONTROL_PATCH_QUERY_BUFFER;
                    unsigned int encoded=patch_entry_encode(query_output,wire[1]);
                    if (encoded!=0) {reply_length=encoded<512U?encoded:512U;send_reply=1;}
                }
                break;
            case CONTROL_QUERY_TRANSFORMS:
                reply_length=transforms_encode(reply);send_reply=1;break;
            default:break;
            }
        }
        if (send_reply)
            control_send_frame(6,sequence,query_output,reply_length);
        input_begin_change(0);
        unsigned long long now=(unsigned long long)esp_timer_get_time();
        (void)xPortEnterCriticalTimeout(LED_CONTROL_LOCK,-1);
        memw();CONTROL_LAST_COMMAND_US->low=(unsigned int)now;
        memw();CONTROL_LAST_COMMAND_US->high=(unsigned int)(now>>32);
        vPortExitCritical(LED_CONTROL_LOCK);
        return;
    }

    input_begin_change((unsigned char)(opcode-4U)>1U);
    unsigned long long now=(unsigned long long)esp_timer_get_time();
    (void)xPortEnterCriticalTimeout(LED_CONTROL_LOCK,-1);
    memw();CONTROL_LAST_COMMAND_US->low=(unsigned int)now;
    memw();CONTROL_LAST_COMMAND_US->high=(unsigned int)(now>>32);
    vPortExitCritical(LED_CONTROL_LOCK);
    if (opcode!=CONTROL_COMMAND_MOVE)
        input_flush_if_pending();
    switch (opcode) {
    case CONTROL_COMMAND_MOVE:
        if (length>=4) {
            unsigned char selector=wire[0];
            if (length>=6 && selector==0) {
                unsigned char flags=wire[5];
                if ((flags&6U)!=6U) {
                    unsigned int y_high=wire[4],x_high=wire[2],y_low=wire[3],x_low=wire[1];
                    move_cursor((short)((x_high<<8)|x_low),
                        (short)((y_high<<8)|y_low),flags&7U);
                }
            } else if (selector==1 || selector==2) {
                unsigned char flags=wire[3];
                if ((flags&6U)!=6U) {
                    unsigned int high=wire[2],low=wire[1];
                    short delta=(short)((high<<8)|low);
                    if (selector==1) move_wheel(delta,flags&7U);
                    else move_pan(delta,flags&7U);
                }
            }
        }
        break;
    case CONTROL_COMMAND_INJECT:
        if (length>=4) {
            unsigned char input_class=wire[0];
            if (input_class<3) {
                unsigned int high=wire[2],low=wire[1];
                unsigned char action=wire[3];
                inject_usage(input_class,(unsigned short)((high<<8)|low),action);
            }
        }
        break;
    case CONTROL_COMMAND_RESET:
        if (length==0 || wire[0]>=2)
            return;
        session_reset();
        (void)control_release_led_overrides();
        if (wire[0]&1U) {
            (void)factory_reset_storage();
            confirm_running_image();
            reboot_to_run();
        }
        return;
    case CONTROL_COMMAND_REBOOT:
        if (length!=0) {
            unsigned char download=0,run=1;
            unsigned char target=wire[0];
            if (target==0) reboot_to_download();
            else if (target==1) (void)link_send_wait100(4,0,&download,1);
            else if (target==2) reboot_to_run();
            else if (target==3) (void)link_send_wait100(4,0,&run,1);
        }
        break;
    case CONTROL_COMMAND_LED:
        if (length>=3) {
            unsigned char target=wire[0],link_value=wire[2],mode=wire[1],local_value=wire[2];
            unsigned short host_command=(unsigned short)((unsigned int)mode|((unsigned int)link_value<<8));
            (void)xPortEnterCriticalTimeout(LED_CONTROL_LOCK,-1);
            if ((target&0xfdU)==0) {
                led_override_set(mode,local_value);
                memw();LED_CONTROL_FLAGS->device_override_owned=mode!=0;
            }
            if ((unsigned char)(target-1U)<2U) {
                memw();LED_CONTROL_FLAGS->host_override_owned=mode!=0;
                vPortExitCritical(LED_CONTROL_LOCK);
                (void)link_send_wait100(0x1b,0,&host_command,2);
            } else vPortExitCritical(LED_CONTROL_LOCK);
        }
        break;
    case CONTROL_COMMAND_LOCK:
        if (length>=6) {
            unsigned int percent_high=wire[5],percent_low=wire[4],id_high=wire[2],id_low=wire[1];
            unsigned char direction=wire[3],input_class=wire[0];
            lock_input(input_class,(unsigned short)((id_high<<8)|id_low),direction,
                (short)((percent_high<<8)|percent_low));
        }
        break;
    case CONTROL_COMMAND_CATCH:
        if (length>=6) {
            unsigned int id_high=wire[2],id_low=wire[1];
            unsigned char capture=wire[5],present=wire[4],direction=wire[3],input_class=wire[0];
            capture_subscription_update(input_class,(unsigned short)((id_high<<8)|id_low),
                direction,present,capture);
        }
        break;
    case CONTROL_COMMAND_OPTION:
        if (length!=0) {
            switch (wire[0]) {
            case CONTROL_OPTION_IMPERFECT:
                if (length>=2 && option_set_imperfect(wire[1]!=0)!=0)
                    reboot_to_run();
                break;
            case CONTROL_OPTION_MOVEMENT_RIDING:
                if (length>=3) {
                    unsigned int high=wire[2],low=wire[1];
                    option_set_movement_riding((unsigned short)((high<<8)|low));
                }
                break;
            case CONTROL_OPTION_EMISSION:
                if (length>=6) {
                    unsigned int force_high=wire[5],rate_high=wire[3],force_low=wire[4],rate_low=wire[2];
                    unsigned char pace=wire[1];
                    if (option_set_emit(pace,(unsigned short)((rate_high<<8)|rate_low),
                        (force_high<<8)|force_low)!=0) reboot_to_run();
                }
                break;
            case CONTROL_OPTION_NAME:
                option_set_name(payload+1,(unsigned short)(length-1U));break;
            case CONTROL_OPTION_BEARING:
                if (length>=4) {
                    unsigned int high=wire[2],low=wire[1];
                    unsigned char coupled=wire[3];
                    option_set_bearing((high<<8)|low,coupled);
                }
                break;
            case CONTROL_OPTION_RENDER:
                if (length>=3) {
                    unsigned char scope=wire[2],profile=wire[1];
                    (void)option_set_render(profile,scope);
                }
                break;
            case CONTROL_OPTION_SPREAD:
                if (length>=3) {
                    unsigned int high=wire[2],low=wire[1];
                    (void)option_set_spread((unsigned short)((high<<8)|low));
                }
                break;
            default:break;
            }
        }
        break;
    case CONTROL_COMMAND_CLIP_APPEND:
        clip_append(payload,length,sequence);break;
    case CONTROL_COMMAND_CLIP_CONTROL:
        if (length!=0) clip_control(wire[0]);break;
    case CONTROL_COMMAND_CLIP_SETTING:
        if (length>=2) {
            unsigned char value=wire[1],setting=wire[0];
            clip_set(setting,value);
        }
        break;
    case CONTROL_COMMAND_CLIP_TRIGGER:
        if (length!=0) {
            unsigned char input_class=wire[0];
            if ((unsigned char)(input_class-4U)<6U) {
                if (length>=8) {
                    unsigned int match_length=wire[7];
                    if ((match_length+4U)*2U<=length) {
                        unsigned int high=wire[2],low=wire[1];
                        unsigned char selector_length=wire[6],flags=wire[5],action=wire[4],direction=wire[3];
                        clip_packet_trigger_update(input_class,(unsigned short)((high<<8)|low),
                            direction,action,flags,selector_length,(unsigned char)match_length,
                            payload+8,payload+match_length+8);
                    }
                }
            } else if (length>=6) {
                unsigned int high=wire[2],low=wire[1];
                unsigned char trigger_flags=wire[5],action=wire[4],edge=wire[3];
                clip_input_trigger_update(input_class,(unsigned short)((high<<8)|low),edge,action,trigger_flags);
            }
        }
        break;
    case CONTROL_COMMAND_UPDATE:
        update_command_dispatch(sequence,payload,length);break;
    case CONTROL_COMMAND_RAW_ENDPOINT:
        if (length>=2) {
            unsigned char allow=0,over_capacity,imperfect;
            option_get_imperfect(&allow,&over_capacity,&imperfect);
            if (allow!=0) {
                unsigned char direction=wire[1],endpoint=wire[0];
                raw_endpoint_send(endpoint,direction,payload+2,(unsigned short)(length-2U));
            }
        }
        break;
    case CONTROL_COMMAND_TRANSFER:
        if (length>=9) {
            unsigned char allow=0,over_capacity,imperfect;
            option_get_imperfect(&allow,&over_capacity,&imperfect);
            unsigned char endpoint=wire[0];
            CONTROL_TRANSFER_REPLY->endpoint=endpoint;
            unsigned int response_length=2;
            if (allow==0) {
                CONTROL_TRANSFER_REPLY->status=0xfc;
            } else {
                unsigned short actual=0;
                unsigned int status=control_transfer_request(endpoint,payload+1,
                    payload+9,(unsigned short)(length-9U),
                    (void *)CONTROL_TRANSFER_REPLY->data,504,&actual);
                CONTROL_TRANSFER_REPLY->status=(unsigned char)status;
                if (status==0) response_length=(unsigned short)(actual+2U);
            }
            control_send_frame(0x1b,sequence,(const void *)CONTROL_TRANSFER_REPLY,response_length);
        }
        break;
    case CONTROL_COMMAND_REWRITE:
        if (length>=9) {
            unsigned int match_length=wire[8];
            unsigned int replacement_offset=match_length*2U+9U;
            if (replacement_offset<=length) {
                unsigned short replacement_length=(unsigned short)(length-9U-match_length*2U);
                if (match_length*2U+11U+replacement_length<=512U) {
                    unsigned int offset_high=wire[7],id_high=wire[2],offset_low=wire[6],id_low=wire[1];
                    unsigned char action=wire[5],present=wire[4],direction=wire[3],input_class=wire[0];
                    rewrite_command(input_class,(unsigned short)((id_high<<8)|id_low),
                        direction,present,action,(unsigned short)((offset_high<<8)|offset_low),
                        (unsigned char)match_length,payload+9,payload+match_length+9,
                        payload+replacement_offset,replacement_length);
                }
            }
        }
        break;
    case CONTROL_COMMAND_PATCH:
        if (length!=0) {
            unsigned char kind=wire[0];
            if (kind==0xfe) descriptor_patch_apply();
            else if (kind==0xff) descriptor_patch_clear();
            else if (length>=5 && (unsigned int)length+2U<=512U) {
                unsigned int high=wire[4],low=wire[3];
                unsigned char index=wire[2],configuration=wire[1];
                descriptor_patch_store(kind,configuration,index,(unsigned short)((high<<8)|low),
                    payload+5,(unsigned short)(length-5U));
            }
        }
        break;
    case CONTROL_COMMAND_TRANSFORM:
        if (length>=8) {
            unsigned int destination_high=wire[6],source_high=wire[3],destination_low=wire[5],source_low=wire[2];
            unsigned char present=wire[7],destination_class=wire[4],source_class=wire[1],mode=wire[0];
            transform_update(mode,source_class,(unsigned short)((source_high<<8)|source_low),
                destination_class,(unsigned short)((destination_high<<8)|destination_low),present);
        }
        break;
    default:break;
    }
    input_advance_change_sequence();
}

/* Native entry: 0x42033f38. */
/* Original function-byte SHA-256:
 * 2fca564e4fa0d5dc5d1eeef1631d102d741edbbbd3e49aea4d13e51987928492.
 */
/*
 * Return the saved fast-report activity timestamp as signed 64-bit clock bits.
 * Takes CREDIT_LOCK with an infinite wait and ignores acquisition status.
 * Executes MEMW, samples LOW at 0x3fcbfed8, executes MEMW, then samples HIGH.
 * Unlocks before returning the cached pair; unlock-side changes cannot alter it.
 * No arguments, timestamp write, clock query, freshness check or retry.
 * All writers must respect the lock to prevent mixed-word snapshots; volatile
 * loads and MEMW alone do not provide mutual exclusion.
 */
long long fast_report_get_activity_time(void)
{
    (void)xPortEnterCriticalTimeout(&CREDIT_LOCK,-1);
    memw();
    unsigned int timestamp_low = REPORT_LAST_WORKER_TIME.low;
    memw();
    unsigned int timestamp_high = REPORT_LAST_WORKER_TIME.high;
    vPortExitCritical(&CREDIT_LOCK);
    return (long long)(((unsigned long long)timestamp_high << 32) | timestamp_low);
}
