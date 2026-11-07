/* Medius v3.4.7 host — usb/control.c.
 * Recovered C and native assembly, grouped for source navigation.
 * Original entry addresses, firmware-byte hashes and function comments follow.
 */

#include "../include/types.h"

/* Native entry: 0x4201f8d0. */
/* Original function-byte SHA-256:
 * 283c431903714459e8b5f2f642dcd36a9481c7449dacd441d516cce99e4278bd. */
/* Return the shared control-status buffer address, without a memory read,
 * fence, copy, allocation or lock. This is not a snapshot of its contents
 * or an assertion about their current length or lifetime. */
unsigned char *medius_host_control_status_data(void)
{
    return MEDIUS_HOST_CONTROL_STATUS_BUFFER;
}

/* Native entry: 0x4201f8d8. */
/* Original function-byte SHA-256:
 * 5de69ebad4d12187953bca3ea203edc37d66f166976e90adf2f7c790de092fb2. */
/* Fence and return the full32-bit shared control-status count. No capacity
 * clamp or atomic pairing with the independently accessed buffer is supplied. */
unsigned int medius_host_control_status_length(void)
{
    memw();
    return MEDIUS_HOST_CONTROL_STATUS_ACTUAL;
}

/* Native entry: 0x4202645c. */
/* Original function-byte SHA-256:
 * 8a645f763258e0defd5c7351ce6b9362aae97ac829f80c4d7d7d4645a1487f52. */
/* Forward one borrowed fragment as link type1Ahex. Read the raw sequence
 * byte from context once before calling send; narrow length to16 by the ABI.
 * Ignore send result. No NULL/span check, allocation, lifetime retention or retry.
 * The fragment and context must remain readable through the delegated call. */
void medius_ep0_send_response_fragment(const unsigned char *fragment,unsigned short length,void *context)
{
    unsigned char sequence = *(const volatile unsigned char *)context;
    link_send_wait100(0x1a,sequence,fragment,length);
}

/* Native entry: 0x42026474. */
/* Original function-byte SHA-256:
 * 4df9dcc849b94275cadf1258f7be5b80500fc13108d134eb2e72bb97639ac01c. */
/* Forward one borrowed fragment as link type23hex. Read the raw sequence
 * byte from context once before calling send; narrow length to16 by the ABI.
 * Ignore send result. No NULL/span check, allocation, lifetime retention or retry.
 * The fragment and context must remain readable through the delegated call. */
void medius_nonzero_send_response_fragment(const unsigned char *fragment,unsigned short length,void *context)
{
    unsigned char sequence = *(const volatile unsigned char *)context;
    link_send_wait100(0x23,sequence,fragment,length);
}

/* Native entry: 0x42026ff0. */
/* Original function-byte SHA-256:
 * 5bfa773604fbb7d713c7ef0a71764acc1eaad82ec09d70fe1bb3a9379087433f. */
/* Retry a synchronous EP0 request up to three times against one start time.
 * port: Live writable control port; connected is sampled before each attempt.
 * started_us: Original signed64 microsecond reference. Compare modulo64 elapsed
 * as signed: >420000 returns the last result; equality/negative elapsed admit.
 * request_type/request: Form low16(request_type | request<<8), without masking
 * request_type to8 before OR. value/index/length are native low16 words.
 * Return signed submit result, or signed URB actual for submit0. Initial last
 * result=-14. Stop on nonnegative result, -4,-3,-8, disconnect/deadline, or the
 * third other negative result. No inter-attempt delay or deadline shortening.
 *
 * Cache EP0 address once. Each admitted attempt writes the shared SETUP first
 * halfword, captures the current mutex BEFORE value/length/index stores, then
 * takes that mutex and populates the embedded URB in native store order.
 * Timeout100, raw length with no2112 cap, shared data buffer, NULL callback/context.
 * Release freshly loaded mutex even if take failed; ignore wrapper statuses.
 * No initial NULL/capacity/ownership check or rollback. Caller must serialize
 * shared SETUP/data and retain port, descriptors and RTOS objects. */
int medius_host_control_retry(MediusHostHubPortPrefix *port,long long started_us,
    unsigned int request_type,unsigned int request,unsigned short value,
    unsigned short index,unsigned short length)
{
    unsigned short request_pair = (unsigned short)(request_type | (request << 8));
    unsigned char *endpoint = port->ep0_descriptor;
    volatile MediusHostHubPortPrefix *live_port = port;
    volatile MediusHostUrb *urb = &port->control_urb;
    volatile MediusUsbSetup *setup = MEDIUS_HOST_SHARED_SETUP;
    int last_result = -14;
    for (unsigned int attempt = 0; attempt < 3; ++attempt) {
        if (live_port->connected == 0) return last_result;
        unsigned long long elapsed = (unsigned long long)esp_timer_get_time() -
            (unsigned long long)started_us;
        if ((long long)elapsed > 420000LL) return last_result;
        *(volatile unsigned short *)setup = request_pair;
        void *mutex = live_port->control_mutex;
        setup->value = value;
        setup->length = length;
        setup->index = index;
        usb_osal_mutex_take(mutex);
        urb->endpoint = endpoint;
        urb->remaining = length;
        urb->buffer = MEDIUS_HOST_CONTROL_DATA;
        urb->hubport = port;
        urb->setup = (unsigned char *)setup;
        urb->timeout = 100;
        urb->complete = NULL;
        urb->context = NULL;
        last_result = usbh_submit_urb((MediusHostUrb *)urb);
        if (last_result == 0) last_result = (int)urb->actual;
        usb_osal_mutex_give(live_port->control_mutex);
        if (last_result >= 0 || last_result == -4 || last_result == -3 || last_result == -8)
            return last_result;
    }
    return last_result;
}

/* Native entry: 0x42027aa8. */
/* Original function-byte SHA-256:
 * 18037eb024b1a1059111f537ea83d89acba249ef5a0f8a2eda8b8bd8ef116854. */
/* Zero-data control request with one selected retry and identity verification.
 * port: Unchecked live port. request_type/request low8; value/index low16;
 * force_recovery tests LOW8 EXACT1, not generic nonzero. Return1 for a final
 * nonnegative result,0 for ordinary failures/clone flag, otherwise full verifier
 * return unchanged. Cache setup/mutex/field bytes and EP0 address as shown.
 * Setup byte stores precede mutex take; timeout500,remaining0,enumeration scratch,
 * NULL completion/context. Submit0 reads signed actual; freshly read mutex is
 * released despite ignored take status. Only first-12/-11/-9 repeats once, using
 * fresh setup/mutex but cached request fields/endpoint. A final connected failure
 * -14 or[-12,-8] sets fenced clone-active1 for -12/-11/-9 or force_low8==1;
 * otherwise delegates identity verification after unlock. Other failures leave
 * the clone flag untouched. No initial connection/NULL guard, shared-buffer
 * lock before setup writes, rollback, timeout recovery or hardware assurance. */
uint medius_host_control_no_data_retry(
    MediusHostHubPortPrefix *port,uint request_type,uint request,uint value,uint index,
    uint force_recovery)
{
    volatile uchar *setup = *(uchar * const volatile *)&port->setup;
    setup[0] = (uchar)request_type;
    setup[1] = (uchar)request;
    void *mutex = *(void * const volatile *)&port->control_mutex;
    uchar value_high = (uchar)(value >> 8);
    uchar index_high = (uchar)(index >> 8);
    setup[3] = value_high;
    setup[5] = index_high;
    setup[6] = 0;
    setup[7] = 0;
    setup[2] = (uchar)value;
    setup[4] = (uchar)index;
    usb_osal_mutex_take(mutex);
    volatile MediusHostUrb *urb = &port->control_urb;
    uchar *endpoint = port->ep0_descriptor;
    urb->endpoint = endpoint;
    urb->setup = (uchar *)setup;
    urb->timeout = 500;
    urb->hubport = port;
    urb->buffer = MEDIUS_HOST_ENUMERATION_DATA;
    urb->remaining = 0;
    urb->complete = 0;
    urb->context = 0;
    int request_result = usbh_submit_urb((MediusHostUrb *)urb);
    if (request_result == 0)
        request_result = (int)urb->actual;
    usb_osal_mutex_give(*(void * const volatile *)&port->control_mutex);
    if (request_result == -12 || request_result == -11 || request_result == -9) {
        setup = *(uchar * const volatile *)&port->setup;
        setup[0] = (uchar)request_type;
        setup[1] = (uchar)request;
        mutex = *(void * const volatile *)&port->control_mutex;
        setup[3] = value_high;
        setup[5] = index_high;
        setup[6] = 0;
        setup[7] = 0;
        setup[2] = (uchar)value;
        setup[4] = (uchar)index;
        usb_osal_mutex_take(mutex);
        urb->endpoint = endpoint;
        urb->setup = (uchar *)setup;
        urb->remaining = 0;
        urb->complete = 0;
        urb->context = 0;
        urb->hubport = port;
        urb->buffer = MEDIUS_HOST_ENUMERATION_DATA;
        urb->timeout = 500;
        request_result = usbh_submit_urb((MediusHostUrb *)urb);
        if (request_result == 0)
            request_result = (int)urb->actual;
        usb_osal_mutex_give(*(void * const volatile *)&port->control_mutex);
    }
    if (request_result >= 0)
        return 1;
    if ((request_result == -14 || (request_result >= -12 && request_result <= -8)) &&
        *(const volatile uchar *)&port->connected != 0) {
        if (request_result != -12 && request_result != -11 && request_result != -9 &&
            (force_recovery & 0xffU) != 1)
            return medius_host_verify_device_identity(port);
        memw();
        MEDIUS_HOST_CLONE_ACTIVE = 1;
    }
    return 0;
}

/* Native entry: 0x4202a2ac. */
/* Original function-byte SHA-256:
 * 8da1a17b7999ab31a1612ae12c71d167c52bfa7c18255d60925ca24cdf6281be. */
/* Serialize resume events, queued control requests and idle configuration work.
 * FreeRTOS entry: no argument/result, infinite loop, priority7/core0/4096 bytes.
 * Publish current task once. A fenced resume-pending sample takes precedence;
 * busy/pending stores precede power-state and cached-port admission. Only
 * power-state1 reads the saved event timestamp LOW/HIGH and enters state2.
 * Connected desired-remote+wanted-suspend sends43hex before resume handling.
 * Keep cached port/bus/event across callbacks. Remaining time is signed
 * modulo64(event+30000-now); positive values delay by the native wrapped
 * low32(milliseconds)*1000/1000+1 calculation. Deassert resume, delay11 ticks,
 * optionally re-suspend/delay21/gate clock, or finish resume. Exact suspend0
 * selects the delayed branch; flags/connection are refreshed where shown.
 *
 * Only queue result1 processes work; receive timeout0. Cache work generation
 * BEFORE fenced applied-generation comparison. Restart rejects with FF and
 * suppresses only response_type0. Otherwise cache port and request-type byte.
 * Nonzero kind low nibble scans all256 interface indices, retaining each
 * table/count/table observation, alternate span and endpoint count. First
 * control-type endpoint with nonzero number/MPS and matching LOW nibble wins;
 * direction is not matched. Missing endpoints or kind0 reject only direct
 * families21/34; other families may use EP0. Connection/power/HID-pause gates
 * retain their distinct nonzero versus exact1 tests and fresh type reads.
 *
 * Set activity, copy SETUP8 before the USB mutex, copy raw admitted OUT length,
 * then fill cached port's embedded synchronous URB in native store order.
 * Timeout500; IN remaining=min(wLength,2112), OUT remaining=wLength. SETUP
 * wLength is not rewritten. Ignore mutex statuses; submit0 uses signed actual.
 * IN data count<=8 yields0; otherwise narrow(count-8) to16 BEFORE cap2112.
 * OUT/zero-wLength copies up to256 driver status bytes while still holding
 * the mutex. Mutex handle is freshly loaded for every take/give.
 *
 * STALL(-8)->FD; other errors->FE. HID17 non-STALL errors while connected
 * run a second EP0 GET_DESCRIPTOR baseline, timeout50,18 bytes. This probe
 * tests the SUBMIT result directly (never substitutes actual). -14/-10 sends
 *17/FC, logs, then conditionally queues recovery with native selector/VID/PID
 * snapshots; it does not set restart or identity-refresh here. Other probe
 * outcomes remain errors, optionally replaced by a cached HID report.
 *
 * Responses:32/34 are kind,status,data, data>504 gives FC with no data.
 *21/23 cap2048 and send21 up to512 total, otherwise fragment as23 with limit506.
 * Other families have status,data: successful IN above504 (or2048 for1A)
 * gives FD; OUT/other paths clip. HID17 instead clips successful data to504.
 * Empty/error17 searches all6 active HID slots: capture interface once,
 * sample report ID per candidate, read nonzero cached length then reread it
 * before copying min(length,504) from a64-byte-stride slot. A hit overrides
 * error with success, even when its second length read became0. Cache lengths
 * must obey the producer's <=64 invariant to avoid crossing slot boundaries.
 * Copy callbacks can change live work; sequence/type refreshes remain explicit.
 *
 * Idle: fenced applied/current comparison; unequal applies fresh applied+1.
 * Otherwise inspect/clear pending selector under the ordered mux, admit only
 * matching epoch+empty ring, then gate deferred configuration on precapture,
 * pending-capture and power. A consumed-but-gated selector is not requeued.
 * No pending work waits on notification(index0,clear1,infinite).
 * No local pointer/span/queue-admission/lifetime checks or rollback are added.
 * Shared buffers, flags, raw byte states and delegated locks are not an atomic
 * snapshot. Programmed USB timeouts and tick delays are not measured timing. */
void medius_task_ctrlwk(void)
{
    volatile MediusControlWork *work = MEDIUS_HOST_CURRENT_CONTROL_WORK;
    volatile MediusUsbSetup *setup = MEDIUS_HOST_SHARED_SETUP;
    volatile MediusHostPowerStateView *power = MEDIUS_HOST_POWER;
    volatile unsigned char *response = MEDIUS_HOST_CONTROL_RESPONSE;
    unsigned char small_response[16];
    MEDIUS_HOST_CONTROL_WORKER_TASK = xTaskGetCurrentTaskHandle();
    for (;;) {
        memw();
        unsigned char pending = MEDIUS_HOST_RESUME_PENDING;
        if (pending != 0) {
            memw(); MEDIUS_HOST_CONTROL_BUSY = 1;
            memw(); MEDIUS_HOST_RESUME_PENDING = 0;
            unsigned char power_state = power->state;
            memw(); MediusHostHubPortPrefix *port = MEDIUS_HOST_CONTROL_PORT;
            if (power_state == 1) {
                unsigned char remote_wakeup = power->desired_remote_wakeup;
                power->state = 2;
                unsigned int event_low = MEDIUS_HOST_RESUME_EVENT_US->low;
                unsigned int event_high = MEDIUS_HOST_RESUME_EVENT_US->high;
                int announce = remote_wakeup != 0 && power->requested_suspend != 0;
                if (port == NULL || ((volatile MediusHostHubPortPrefix *)port)->connected == 0) {
                    unsigned char restore = power->preexisting_pause ^ 1U;
                    power->state = 0;
                    medius_host_finish_resume(port,restore);
                } else {
                    if (announce) link_send_wait100(0x43,0,NULL,0);
                    MediusHostBusPrefix *bus = ((volatile MediusHostHubPortPrefix *)port)->bus_context;
                    unsigned char bus_id = ((volatile MediusHostBusPrefix *)bus)->id;
                    if ((medius_dwc2_host_port_raw(bus_id) & 0x40U) == 0)
                        medius_dwc2_host_resume_control(bus_id,1);
                    unsigned long long now = (unsigned long long)esp_timer_get_time();
                    unsigned long long event = ((unsigned long long)event_high << 32) | event_low;
                    unsigned long long remaining = event + 30000ULL - now;
                    if ((long long)remaining > 0) {
                        long long milliseconds = (long long)remaining / 1000;
                        unsigned int ticks = ((unsigned int)milliseconds * 1000U) / 1000U + 1U;
                        vTaskDelay(ticks);
                    }
                    medius_dwc2_host_resume_control(bus_id,0);
                    vTaskDelay(11);
                    if (power->desired_remote_wakeup == 0 && power->requested_suspend != 0 &&
                        ((volatile MediusHostHubPortPrefix *)port)->connected != 0) {
                        power->state = 1;
                        memw(); MEDIUS_HOST_RESUME_ARMED = 1;
                    }
                    memw();
                    if (MEDIUS_HOST_RESUME_ARMED != 0 && medius_dwc2_host_suspend(bus_id) == 0) {
                        vTaskDelay(21);
                        memw();
                        if (MEDIUS_HOST_RESUME_ARMED != 0 &&
                            ((volatile MediusHostHubPortPrefix *)port)->connected != 0)
                            medius_dwc2_host_gate_suspended_clock(bus_id,1);
                    } else {
                        unsigned char restore = power->preexisting_pause ^ 1U;
                        memw(); MEDIUS_HOST_RESUME_ARMED = 0;
                        power->state = 0;
                        medius_host_finish_resume(port,restore);
                    }
                }
            }
            memw(); MEDIUS_HOST_CONTROL_BUSY = 0;
            continue;
        }

        if (xQueueReceive(MEDIUS_HOST_CONTROL_WORK_QUEUE,(void *)work,0) != 1) {
            memw(); unsigned int applied = MEDIUS_HOST_APPLIED_GENERATION;
            memw(); unsigned int current = MEDIUS_HOST_CURRENT_GENERATION;
            if (applied != current) {
                memw(); MEDIUS_HOST_CONTROL_BUSY = 1;
                memw(); unsigned int target = MEDIUS_HOST_APPLIED_GENERATION + 1U;
                medius_host_apply_generation(target);
                memw(); MEDIUS_HOST_CONTROL_BUSY = pending; /* Captured zero. */
                continue;
            }
            xPortEnterCriticalTimeout(&MEDIUS_HOST_ORDERED_LOCK,-1);
            unsigned int selector = MEDIUS_HOST_PENDING_CONFIGURATION;
            if (selector == 0) {
                vPortExitCritical(&MEDIUS_HOST_ORDERED_LOCK);
            } else {
                unsigned int epoch = MEDIUS_HOST_PENDING_CONFIGURATION_EPOCH;
                if (epoch == MEDIUS_HOST_ORDERED_EPOCH && MEDIUS_HOST_ORDERED_COUNT == 0) {
                    MEDIUS_HOST_PENDING_CONFIGURATION = 0;
                    vPortExitCritical(&MEDIUS_HOST_ORDERED_LOCK);
                    memw(); MEDIUS_HOST_CONTROL_BUSY = 1;
                    memw(); unsigned int generation = MEDIUS_HOST_CURRENT_GENERATION;
                    memw();
                    if (MEDIUS_HOST_PRECAPTURE_STATE == 0) {
                        memw();
                        if (MEDIUS_HOST_CAPTURE_PENDING == 0 && power->state == 0)
                            medius_host_apply_configuration((selector - 1U) & 255U,generation,1);
                    }
                    memw(); MEDIUS_HOST_CONTROL_BUSY = 0;
                    continue;
                }
                MEDIUS_HOST_PENDING_CONFIGURATION = 0;
                vPortExitCritical(&MEDIUS_HOST_ORDERED_LOCK);
            }
            ulTaskGenericNotifyTake(0,1,0xffffffffU);
            continue;
        }

        memw(); MEDIUS_HOST_CONTROL_BUSY = 1;
        unsigned int queued_generation = work->generation;
        memw();
        if (MEDIUS_HOST_APPLIED_GENERATION < queued_generation)
            medius_host_apply_generation(queued_generation);
        memw();
        if (MEDIUS_HOST_RESTART_GATE != 0) {
            unsigned char type = work->response_type;
            memw(); MEDIUS_HOST_CONTROL_BUSY = 0;
            if (type == 0x21 || type == 0x23) {
                small_response[0] = work->kind;
                unsigned char sequence = work->sequence;
                small_response[1] = 0xff;
                link_send_wait100(0x21,sequence,small_response,2);
            } else if (type == 0x32 || type == 0x34) {
                small_response[0] = work->kind;
                unsigned char sequence = work->sequence;
                small_response[1] = 0xff;
                link_send_wait100(type,sequence,small_response,2);
            } else if (type != 0) {
                unsigned char sequence = work->sequence;
                small_response[0] = 0xff;
                link_send_wait100(type,sequence,small_response,1);
            }
            continue;
        }
        memw(); MediusHostHubPortPrefix *port = MEDIUS_HOST_CONTROL_PORT;
        unsigned int request_type = work->setup[0];
        unsigned char response_type;
        unsigned char *endpoint = NULL;
        unsigned int data_length = 0, response_length = 1;
        unsigned char status = 0;
        if (port == NULL) {
            response_type = work->response_type;
            if (response_type == 0x21 || response_type == 0x34) {
                memw(); MEDIUS_HOST_CONTROL_BUSY = 0;
                status = 0xff;
                goto direct_endpoint_error;
            }
            goto disconnected;
        }
        unsigned char kind = work->kind;
        if ((kind & 15U) != 0) {
            for (unsigned int index = 0; index != 256; ++index) {
                volatile MediusHostHubPortPrefix *live_port = port;
                MediusHostInterfacePrefix *table = live_port->interfaces;
                memw(); unsigned int count = live_port->interface_count;
                memw();
                if (table == NULL || live_port->interfaces != table || (index & 65535U) >= count) continue;
                volatile MediusHostInterfacePrefix *entry = &table[index & 65535U];
                unsigned int alternates = entry->alternate_count;
                if (alternates == 0) continue;
                MediusHostAlternatePrefix *alternate = entry->alternates;
                unsigned int end = (unsigned int)alternate + alternates * 16U;
                do {
                    volatile MediusHostAlternatePrefix *live_alternate = alternate;
                    unsigned int endpoints = live_alternate->endpoint_count;
                    if (endpoints != 0) {
                        const volatile unsigned char *descriptor = live_alternate->endpoints;
                        do {
                            if ((descriptor[3] & 3U) == 0) {
                                unsigned char address = descriptor[2];
                                if ((address & 15U) != 0) {
                                    unsigned int high = descriptor[5];
                                    unsigned int low = descriptor[4];
                                    if ((((high << 8) | low) & 2047U) != 0 && ((kind ^ address) & 15U) == 0) {
                                        endpoint = (unsigned char *)descriptor;
                                        response_type = work->response_type;
                                        goto endpoint_resolved;
                                    }
                                }
                            }
                            descriptor += 7;
                        } while (--endpoints != 0);
                    }
                    alternate = (void *)((unsigned int)alternate + 16U);
                } while ((unsigned int)alternate != end);
            }
            response_type = work->response_type;
            if (response_type == 0x21 || response_type == 0x34) goto missing_endpoint;
        } else {
            response_type = work->response_type;
            if (response_type == 0x21 || response_type == 0x34) goto missing_endpoint;
        }
endpoint_resolved:
        if (((volatile MediusHostHubPortPrefix *)port)->connected == 0) {
            response_type = work->response_type;
            goto disconnected;
        }
        if (power->state != 0) {
            if (response_type == 0x17) {
                memw();
                if (MEDIUS_HOST_HID_PAUSED != 0) {
                    response_type = work->response_type;
                    goto disconnected;
                }
            } else {
                response_type = work->response_type;
                if (response_type == 0x17) goto baseline_probe;
                memw(); MEDIUS_HOST_CONTROL_BUSY = 0;
                status = 0xfe;
                goto error_response;
            }
        } else {
            memw();
            if (MEDIUS_HOST_HID_PAUSED == 1 && response_type == 0x17) {
                response_type = work->response_type;
                goto disconnected;
            }
        }
        memw(); MEDIUS_HOST_CONTROL_ACTIVITY = 1;
        memcpy((void *)setup,(const void *)work->setup,8);
        unsigned int remaining;
        if ((request_type & 128U) != 0) {
            usb_osal_mutex_take(((volatile MediusHostHubPortPrefix *)port)->control_mutex);
            remaining = setup->length;
            if (remaining > 2112) remaining = 2112;
        } else {
            unsigned int out_length = work->out_length;
            if (out_length != 0) memcpy(MEDIUS_HOST_CONTROL_DATA,(const void *)work->data,out_length);
            usb_osal_mutex_take(((volatile MediusHostHubPortPrefix *)port)->control_mutex);
            remaining = setup->length;
        }
        if (endpoint == NULL) endpoint = port->ep0_descriptor;
        volatile MediusHostUrb *urb = &port->control_urb;
        urb->setup = (unsigned char *)setup;
        urb->timeout = 500;
        urb->buffer = MEDIUS_HOST_CONTROL_DATA;
        urb->complete = NULL;
        urb->context = NULL;
        urb->hubport = port;
        urb->remaining = remaining;
        urb->endpoint = endpoint;
        int result = usbh_submit_urb((MediusHostUrb *)urb);
        if (result == 0) result = (int)urb->actual;
        if (result < 0) {
            usb_osal_mutex_give(((volatile MediusHostHubPortPrefix *)port)->control_mutex);
            response_type = work->response_type;
            if (response_type == 0x17) {
                if (result != -8 && ((volatile MediusHostHubPortPrefix *)port)->connected != 0)
                    goto baseline_probe;
                memw(); MEDIUS_HOST_CONTROL_BUSY = 0;
                status = result == -8 ? 0xfd : 0xfe;
                goto cached_hid;
            }
            memw(); MEDIUS_HOST_CONTROL_BUSY = 0;
            status = result == -8 ? 0xfd : 0xfe;
            goto error_response;
        }
        if ((request_type & 128U) != 0 && setup->length != 0) {
            if (result > 8) {
                data_length = ((unsigned int)result - 8U) & 65535U;
                if (data_length > 2112) data_length = 2112;
            }
            usb_osal_mutex_give(((volatile MediusHostHubPortPrefix *)port)->control_mutex);
        } else {
            data_length = medius_host_control_status_length();
            if (data_length > 255) data_length = 256;
            if (data_length != 0) {
                unsigned char *data = medius_host_control_status_data();
                memcpy(MEDIUS_HOST_CONTROL_DATA,data,data_length);
            }
            usb_osal_mutex_give(((volatile MediusHostHubPortPrefix *)port)->control_mutex);
        }
        response_type = work->response_type;
        memw(); MEDIUS_HOST_CONTROL_BUSY = 0;
        if (response_type == 0x17) {
            if (data_length == 0) goto cached_hid;
            if (data_length > 504) data_length = 504;
            goto status_success;
        }
        if (response_type == 0x32 || response_type == 0x34) {
            response[0] = work->kind;
            if (data_length > 504) { response[1] = 0xfc; response_length = 2; }
            else {
                response[1] = 0;
                response_length = 2;
                if (data_length != 0) {
                    response_length = (data_length + 2U) & 65535U;
                    memcpy((void *)(response + 2),MEDIUS_HOST_CONTROL_DATA,data_length);
                    response_type = work->response_type;
                }
            }
            goto send_direct;
        }
        if (response_type == 0x21 || response_type == 0x23) {
            *(volatile unsigned short *)response = work->kind;
            if (data_length > 2048) {
                memcpy((void *)(response + 2),MEDIUS_HOST_CONTROL_DATA,2048);
                response_length = 2050;
                goto fragment_endpoint;
            }
            response_length = 2;
            if (data_length != 0) {
                memcpy((void *)(response + 2),MEDIUS_HOST_CONTROL_DATA,data_length);
                response_length = (data_length + 2U) & 65535U;
                if (response_length > 512) goto fragment_endpoint;
            }
            goto send_endpoint;
        }
        {
            unsigned int cap = response_type == 0x1a ? 2048 : 504;
            if ((request_type & 128U) != 0 && data_length > cap) {
                status = 0xfd;
                goto status_error;
            }
            if (data_length > cap) data_length = cap;
            goto status_success;
        }

missing_endpoint:
        status = ((volatile MediusHostHubPortPrefix *)port)->connected != 0 ? 0xfe : 0xff;
        memw(); MEDIUS_HOST_CONTROL_BUSY = 0;
direct_endpoint_error:
        if (response_type == 0x34) {
            response[0] = work->kind;
            response[1] = status;
            response_length = 2;
            goto send_direct;
        }
        *(volatile unsigned short *)response = work->kind | ((unsigned int)status << 8);
        response_length = 2;
        goto send_endpoint;

disconnected:
        memw(); MEDIUS_HOST_CONTROL_BUSY = 0;
        status = 0xff;
        if (response_type == 0x17) goto cached_hid;
error_response:
        if (response_type == 0x32 || response_type == 0x34) {
            response[0] = work->kind;
            response[1] = status;
            response_length = 2;
            goto send_direct;
        }
        if (response_type == 0x21 || response_type == 0x23) {
            *(volatile unsigned short *)response = work->kind | ((unsigned int)status << 8);
            response_length = 2;
            goto send_endpoint;
        }
        goto status_error;

baseline_probe:
        /* Native DROM words are written HIGH word then LOW, before the mutex. */
        ((volatile unsigned int *)setup)[1] = 0x00120000U;
        ((volatile unsigned int *)setup)[0] = 0x01000680U;
        usb_osal_mutex_take(((volatile MediusHostHubPortPrefix *)port)->control_mutex);
        volatile MediusHostUrb *probe = &port->control_urb;
        probe->endpoint = port->ep0_descriptor;
        probe->setup = (unsigned char *)setup;
        probe->buffer = MEDIUS_HOST_CONTROL_DATA;
        probe->remaining = 18;
        probe->timeout = 50;
        probe->hubport = port;
        probe->complete = NULL;
        probe->context = NULL;
        int baseline_result = usbh_submit_urb((MediusHostUrb *)probe);
        usb_osal_mutex_give(((volatile MediusHostHubPortPrefix *)port)->control_mutex);
        memw(); MEDIUS_HOST_CONTROL_BUSY = 0;
        if (baseline_result == -14 || baseline_result == -10) {
            unsigned char sequence = work->sequence;
            small_response[0] = 0xfc;
            link_send_wait100(0x17,sequence,small_response,1);
            medius_host_log_formatted("EP0 stopped answering after a baseline request; re-enumerating the device");
            if (MEDIUS_HOST_CONFIGURATION_QUEUE != NULL) {
                memw(); if (MEDIUS_HOST_RESTART_GATE != 0) continue;
                memw(); if (MEDIUS_HOST_CONFIGURATION_SWITCH_GATE != 0) continue;
                memw(); if (MEDIUS_HOST_PRECAPTURE_STATE != 0) continue;
                unsigned char selector = MEDIUS_HOST_CURRENT_CONFIGURATION;
                memw(); MEDIUS_HOST_REQUESTED_CONFIGURATION = selector;
                long long milliseconds = esp_timer_get_time() / 1000;
                unsigned short vendor = MEDIUS_HOST_CURRENT_VENDOR_ID;
                memw(); MEDIUS_HOST_RESTART_REQUESTED_MS = (unsigned int)milliseconds;
                MEDIUS_HOST_PREVIOUS_VENDOR_ID = vendor;
                unsigned short product = MEDIUS_HOST_CURRENT_PRODUCT_ID;
                RtosQueue *queue = MEDIUS_HOST_CONFIGURATION_QUEUE;
                MEDIUS_HOST_PREVIOUS_PRODUCT_ID = product;
                xQueueGenericSend(queue,NULL,0,0);
            }
            continue;
        }
        response_type = work->response_type;
        status = 0xfe;
        if (response_type != 0x17) goto error_response;

cached_hid:
        {
            unsigned char interface_number = work->setup[4];
            for (unsigned int slot = 0; slot < 6; ++slot) {
                memw(); if (MEDIUS_HOST_HID_ENDPOINTS[slot].active == 0) continue;
                if (MEDIUS_HOST_HID_ENDPOINTS[slot].interface_number != interface_number) continue;
                memw(); if (MEDIUS_HID_CACHED_LENGTHS[slot] == 0) continue;
                unsigned char report_id = work->setup[2];
                if (report_id != 0 && MEDIUS_HID_CACHED_REPORTS[slot][0] != report_id) continue;
                memw(); data_length = MEDIUS_HID_CACHED_LENGTHS[slot];
                if (data_length > 504) data_length = 504;
                memcpy(MEDIUS_HOST_CONTROL_DATA,MEDIUS_HID_CACHED_REPORTS[slot],data_length);
                goto status_success;
            }
        }
status_error:
        response[0] = status;
        goto emit_status;
status_success:
        response[0] = 0;
        if (data_length != 0) {
            response_length = (data_length + 1U) & 65535U;
            memcpy((void *)(response + 1),MEDIUS_HOST_CONTROL_DATA,data_length);
        }
emit_status:
        response_type = work->response_type;
        if (response_type == 0x1a) {
            control_fragment_emit((unsigned char *)response,(unsigned short)response_length,506,
                medius_ep0_send_response_fragment,(void *)work);
            continue;
        }
send_direct:
        link_send_wait100(response_type,work->sequence,(const void *)response,(unsigned short)response_length);
        continue;
send_endpoint:
        link_send_wait100(0x21,work->sequence,(const void *)response,(unsigned short)response_length);
        continue;
fragment_endpoint:
        control_fragment_emit((unsigned char *)response,(unsigned short)response_length,506,
            medius_nonzero_send_response_fragment,(void *)work);
    }
}

/* Native entry: 0x4202e678. */
/* Original function-byte SHA-256:
 * 62716d4dccc3c57d11ed0606a625718739d9092ed0bee3d0f0a4419947d69cbd. */
/* Admit a direct EP0 request (link13hex); queue a response14hex work item.
 * sequence/payload/length: Borrowed request, native low8/low16 scalars.
 * Require>=8 bytes, read wLength HIGH then LOW, admit both directions only
 * at<=504. Zero2068-byte work, set response type then sequence, copy SETUP8.
 * Read LIVE direction after that copy; a nonzero OUT requires length>=8+wLength,
 * copies cached wLength bytes and stores that cached length. IN ignores trailing
 * bytes. Any nonzero enqueue result succeeds; otherwise send14hex/[FE] once.
 * No port/endpoint/sequence/connection check, local lock or excess-byte rejection.
 * A changing payload can make copied SETUP disagree with the later direction
 * test; the earlier wLength remains the copy/admission bound. */
void medius_usb_control_request_enqueue(unsigned char sequence,const unsigned char *payload,unsigned short length)
{
    unsigned char error = 0xfe;
    const volatile unsigned char *input = payload;
    if (length < 8) goto reject;
    unsigned int high = input[7];
    unsigned int low = input[6];
    unsigned int requested = (high << 8) | low;
    if (requested > 504) goto reject;
    MediusControlWork work;
    memset(&work,0,sizeof(work));
    work.response_type = 0x14;
    work.sequence = sequence;
    memcpy(work.setup,payload,8);
    if ((input[0] & 128U) == 0 && requested != 0) {
        if (length <= requested + 7U) goto reject;
        memcpy(work.data,payload + 8,requested);
        work.out_length = (unsigned short)requested;
    }
    if (medius_control_work_enqueue(&work) != 0) return;
reject:
    link_send_wait100(0x14,sequence,&error,1);
}

/* Native entry: 0x4202e71c. */
/* Original function-byte SHA-256:
 * 8cffc7eabcc514c4164f11b5d60eb8f20a9c92e597b81fbb8e7b98ebb8e28a08. */
/* Admit endpoint+SETUP+data (link20hex), queue a response21hex work item.
 * Require>=9 bytes. Read wLength HIGH, cache error endpoint, then read LOW;
 * admit both directions only at<=2048. Zero2068-byte work and reread endpoint
 * for kind, set sequence/type21, copy SETUP8. LIVE direction after the copy
 * gates OUT length>=9+wLength and exact cached-length copy/out_length store.
 * Any nonzero enqueue succeeds. Otherwise send21hex/[cached endpoint,FE];
 * length<9 uses endpoint0 and never reads payload. A later endpoint change
 * can affect work.kind while the error reply retains its earlier byte.
 * No endpoint-number/direction/port/lifetime check or trailing-byte rejection. */
void medius_nonzero_request_enqueue(unsigned char sequence,const unsigned char *payload,unsigned short length)
{
    unsigned short error = 0xfe00;
    const volatile unsigned char *input = payload;
    if (length < 9) goto reject;
    unsigned int high = input[8];
    unsigned char endpoint = input[0];
    unsigned int low = input[7];
    error = (unsigned short)(0xfe00U | endpoint);
    unsigned int requested = (high << 8) | low;
    if (requested > 2048) goto reject;
    MediusControlWork work;
    memset(&work,0,sizeof(work));
    work.kind = input[0];
    work.sequence = sequence;
    work.response_type = 0x21;
    memcpy(work.setup,payload + 1,8);
    if ((input[1] & 128U) == 0 && requested != 0) {
        if (length <= requested + 8U) goto reject;
        memcpy(work.data,payload + 9,requested);
        work.out_length = (unsigned short)requested;
    }
    if (medius_control_work_enqueue(&work) != 0) return;
reject:
    link_send_wait100(0x21,sequence,&error,2);
}

/* Native entry: 0x4202e984. */
/* Original function-byte SHA-256:
 * 8a4cb7b0199437919533474c31f3c53ec9196ae30d4d8e7aab4fbc409459c9de. */
/* Reassemble link22hex endpoint requests into response23hex control work.
 * Share one assembly, with no sequence correlation, timeout or local lock.
 * Partial/ignored continuation returns silently. Parser error clears total16
 * then used/active/error as ONE32-bit store and replies21hex/[00,FE].
 * Completion caches total and, when nonzero, error endpoint BEFORE the same
 * metadata reset. Require>=9 logical bytes, read wLength HIGH/LOW and cap2048
 * for both directions. Zero2068-byte work, reread endpoint for kind, copy SETUP8;
 * read live direction afterward. Nonzero OUT requires total>=9+wLength, then
 * copies cached length and stores out_length. Any nonzero enqueue succeeds.
 * Other failures send21hex/[cached endpoint,FE], endpoint0 for total0.
 * Completing fragment's sequence labels the work/error, irrespective of earlier
 * fragment sequences. Reset leaves payload intact and occurs before validation
 * and delegated copies; concurrent/reentrant activity can replace that payload. */
void medius_nonzero_request_fragment(unsigned char sequence,const unsigned char *fragment,unsigned short length)
{
    ControlAssembly *assembly = MEDIUS_HOST_NONZERO_ASSEMBLY;
    volatile ControlAssembly *state = assembly;
    int accepted = control_fragment_accept(assembly,fragment,length);
    if (accepted == 0) {
        if (state->error == 0) return;
        unsigned short error = 0xfe00;
        state->total = 0;
        state->progress_flags = 0;
        link_send_wait100(0x21,sequence,&error,2);
        return;
    }
    unsigned int total = state->total;
    unsigned short error = 0xfe00;
    if (total != 0) error = (unsigned short)(0xfe00U | state->payload[0]);
    state->total = 0;
    state->progress_flags = 0;
    if (total < 9) goto reject;
    unsigned int high = state->payload[8];
    unsigned int low = state->payload[7];
    unsigned int requested = (high << 8) | low;
    if (requested > 2048) goto reject;
    MediusControlWork work;
    memset(&work,0,sizeof(work));
    work.kind = state->payload[0];
    work.sequence = sequence;
    work.response_type = 0x23;
    memcpy(work.setup,assembly->payload + 1,8);
    if ((state->payload[1] & 128U) == 0 && requested != 0) {
        if (total <= requested + 8U) goto reject;
        memcpy(work.data,assembly->payload + 9,requested);
        work.out_length = (unsigned short)requested;
    }
    if (medius_control_work_enqueue(&work) != 0) return;
reject:
    link_send_wait100(0x21,sequence,&error,2);
}

/* Native entry: 0x4202ea70. */
/* Original function-byte SHA-256:
 * 88d7e636e35ea28f83589ad7905e938e6b4793c5810abeb6367c1e43a6c14687. */
/* Reassemble link19hex EP0 requests into response1Ahex control work.
 * One shared assembly; no sequence correlation, timeout or lock. Parser0 with
 * error0 returns. Parser error clears total16 then used/active/error as ONE32
 * store before fragmenting a one-byte FE response, with the current sequence.
 * Complete messages require total>=8. Cache direction byte THEN aligned
 * wLength halfword. OUT alone is capped2048; IN admits any16-bit wLength.
 * Zero2068-byte work, set sequence/type1A, copy SETUP8 from payload base.
 * Cached OUT+nonzero length requires total>=low16(wLength+8), then copies
 * cached wLength and stores work.out_length. Native code does NOT temporarily
 * overwrite/restore the assembly's length bytes as the old pseudocode showed.
 * Any nonzero enqueue succeeds. Invalid complete input/queue failure emits
 * fragmented FE too, retaining completed total/used metadata and payload;
 * only parser error resets them. Completing fragment sequence labels work and
 * reply. Callback is synchronous and must not retain the borrowed stack bytes. */
void medius_ep0_request_fragment(unsigned char sequence,const unsigned char *fragment,unsigned short length)
{
    ControlAssembly *assembly = MEDIUS_HOST_EP0_ASSEMBLY;
    volatile ControlAssembly *state = assembly;
    int accepted = control_fragment_accept(assembly,fragment,length);
    unsigned char error = 0xfe;
    if (accepted == 0) {
        if (state->error == 0) return;
        state->total = 0;
        state->progress_flags = 0;
        goto reject;
    }
    unsigned int total = state->total;
    if (total < 8) goto reject;
    unsigned int out = (state->payload[0] & 128U) == 0;
    unsigned int requested = *(const volatile unsigned short *)&state->payload[6];
    if (requested > 2048 && out) goto reject;
    MediusControlWork work;
    memset(&work,0,sizeof(work));
    work.sequence = sequence;
    work.response_type = 0x1a;
    memcpy(work.setup,assembly->payload,8);
    if (requested != 0 && out) {
        if (total < ((requested + 8U) & 65535U)) goto reject;
        memcpy(work.data,assembly->payload + 8,requested);
        work.out_length = (unsigned short)requested;
    }
    if (medius_control_work_enqueue(&work) != 0) return;
reject:
    control_fragment_emit(&error,1,506,medius_ep0_send_response_fragment,&sequence);
}

