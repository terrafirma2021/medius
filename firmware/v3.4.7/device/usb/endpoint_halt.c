/* Medius v3.4.7 device — endpoint-halt acknowledgement and report recovery. */
#include "../include/types.h"

/* Endpoint-halt reconstruction utilities; inlined native repetitions, not
 * additional firmware entry points. Counts are deliberately not clamped. */
static __inline__ __attribute__((always_inline)) void halt_clear_wait_flags(void)
{
    memw();
    MEDIUS_EP0_REPLY_CHANNEL->waiting = 0;
    memw();
    ENDPOINT_HALT_REPLY->waiting = 0;
    memw();
    MEDIUS_EP0_REPLY_CHANNEL->ep0_worker_busy = 0;
}
static __inline__ __attribute__((always_inline)) int
halt_find_binding(unsigned int endpoint, unsigned int *slot_out)
{
    int count = CREDIT_BINDINGS.count;
    for (int index = 0; index < count; ++index) {
        if (CREDIT_BINDING_RECORDS[index].endpoint != endpoint)
            continue;
        unsigned int slot = CREDIT_BINDING_RECORDS[index].queue_slot;
        if (slot < 6) {
            *slot_out = slot;
            return index;
        }
        break;
    }
    return -1;
}

/* Native entry: 0x420338ac. */
/* Original function-byte SHA-256:
 * 27d254d15d267c849712edb26b4368da966dccd0c2f7a6164c18f14a9df8b6d4. */
/*
 * Prepare a bus0 non-EP0 halt change through the ordered OUT-control queue.
 * bus/halted use low8; endpoint uses low8 and rejects low7==0 from this path.
 * Return1 to permit local handling for another bus, EP0, inactive/quiescing clone
 * or missing queue/semaphore. Otherwise snapshot CURRENT generation, zero an
 * 80-byte message, store clock LOW/endpoint/action low8(2-halted)/generation and
 * sequence, publish busy/sequence/cancel/resultFE/wait flags, then retry queue
 * sends with20 ticks and completion waits250 ticks until1.5s signed elapsed.
 * All queue/semaphore handles used in retries are freshly loaded.
 *
 * Keep the raw pending BYTE OR successful-send bit as a WORD marker; it is not
 * normalized to bool. First-send failure or expiry with cached pending0 clears
 * matching sequence time and, if generation still matches, increments drops and
 * returns1 (local handling still allowed). Later cancellation clears its flag,
 * consumes the handler and returns0. Otherwise read result BYTE BEFORE generation:
 * result0/current generation/nonzero marker permits handling. Failure clears the
 * endpoint-transition flag; a fresh generation change rejects. Same-generation
 * failures clear/consume the stall only when marker low8!=1 or result==FE.
 *
 * No lock spans send/wait, no global elapsed stats and no delivery guarantee.
 * The timeout includes scheduler/queue delays; send1 means queued, not delivered.
 * Busy, waiting and acknowledgement fields retain separate fenced BYTE accesses.
 */
int medius_clone_prepare_endpoint_halt(unsigned char bus, unsigned int endpoint,
    unsigned char halted)
{
    unsigned int address = (unsigned char)endpoint;
    if (bus != 0 || (address & 127U) == 0)
        return 1;
    memw();
    if (CLONE_ACTIVE == 0)
        return 1;
    memw();
    if (MEDIUS_EP0_REPLY_LIFETIME->quiescing != 0)
        return 1;
    if (DEVICE_OUT_FORWARD_QUEUE == NULL || MEDIUS_EP0_REPLY_CHANNEL->signal == NULL)
        return 1;
    memw();
    unsigned int generation = DEVICE_OUT_GENERATION;
    MediusDeviceOutMessage message;
    memset(&message, 0, 80);
    message.stamp = (unsigned int)esp_timer_get_time();
    message.endpoint = (unsigned char)address;
    message.state_action = (unsigned char)(2U - halted);
    message.generation = generation;
    unsigned int sequence = medius_report_record_sequence_event(address);
    memw();
    MEDIUS_EP0_REPLY_CHANNEL->ep0_worker_busy = 1;
    memw();
    unsigned char ep0_sequence = MEDIUS_EP0_REPLY_CHANNEL->sequence;
    ep0_sequence = (unsigned char)(ep0_sequence + 1U);
    RtosQueue *signal = MEDIUS_EP0_REPLY_CHANNEL->signal;
    memw();
    MEDIUS_EP0_REPLY_CHANNEL->sequence = ep0_sequence;
    message.state_sequence = (unsigned char)sequence;
    xQueueSemaphoreTake(signal, 0);
    unsigned char wire_sequence = *(volatile unsigned char *)&message.state_sequence;
    memw();
    MEDIUS_EP0_REPLY_LIFETIME->cancelled = 0;
    memw();
    ENDPOINT_HALT_REPLY->sequence = wire_sequence;
    memw();
    ENDPOINT_HALT_REPLY->result = 0xfe;
    memw();
    ENDPOINT_HALT_REPLY->waiting = 1;
    memw();
    MEDIUS_EP0_REPLY_CHANNEL->waiting = 1;
    unsigned long long started = (unsigned long long)esp_timer_get_time();
    unsigned int pending_sample = 0;
    unsigned int marker = 0;
    for (;;) {
        memw();
        if (DEVICE_OUT_GENERATION != generation)
            goto expired;
        memw();
        if (MEDIUS_EP0_REPLY_LIFETIME->cancelled != 0)
            goto expired;
        unsigned long long elapsed = (unsigned long long)esp_timer_get_time() - started;
        if ((long long)elapsed >= 1500000LL)
            goto expired;
        int sent = xQueueGenericSend(DEVICE_OUT_FORWARD_QUEUE, &message, 20, 0);
        marker = pending_sample | (sent == 1);
        if (marker == 0) {
            halt_clear_wait_flags();
            goto rollback_sequence;
        }
        signal = MEDIUS_EP0_REPLY_CHANNEL->signal;
        memw();
        MEDIUS_EP0_REPLY_CHANNEL->waiting = 1;
        xQueueSemaphoreTake(signal, 250);
        memw();
        pending_sample = ENDPOINT_HALT_REPLY->waiting;
        if (pending_sample == 0) {
            halt_clear_wait_flags();
            break;
        }
    }
finished:
    memw();
    if (MEDIUS_EP0_REPLY_LIFETIME->cancelled != 0) {
        memw();
        MEDIUS_EP0_REPLY_LIFETIME->cancelled = 0;
        medius_ep0_mark_handler_consumed(0);
        return 0;
    }
    memw();
    unsigned int result = ENDPOINT_HALT_REPLY->result;
    memw();
    unsigned int current_generation = DEVICE_OUT_GENERATION;
    if (current_generation == generation && result == 0 && marker != 0)
        return 1;
    memw();
    MEDIUS_REPORT_ENDPOINT_TRANSITION_PENDING = 0;
    memw();
    if (DEVICE_OUT_GENERATION != generation)
        return 0;
    if (((marker ^ 1U) & 255U) != 0 || result == 0xfe)
        medius_ep0_clear_stall_and_consume(0);
    return 0;

expired:
    halt_clear_wait_flags();
    marker = 0;
    if (pending_sample != 0)
        goto finished;
rollback_sequence:
    wire_sequence = *(volatile unsigned char *)&message.state_sequence;
    xPortEnterCriticalTimeout(&REPORT_SEQUENCE_LOCK, -1);
    unsigned int slot = wire_sequence & 15U;
    if (REPORT_SEQUENCE_WINDOW.entries[slot].sequence == wire_sequence)
        REPORT_SEQUENCE_WINDOW.entries[slot].time_low = 0;
    vPortExitCritical(&REPORT_SEQUENCE_LOCK);
    memw();
    if (DEVICE_OUT_GENERATION != generation)
        return 0;
    memw();
    unsigned int drops = DEVICE_OUT_DROPS;
    memw();
    DEVICE_OUT_DROPS = drops + 1U;
    return 1;
}

/* Native entry: 0x40395b94. */
/* Original function-byte SHA-256:
 * fc03f39a9e7f6336ac85638eedb661752e463d011176e3c93fc274f58022f302. */
/*
 * Apply local report/accounting consequences of a halt change. bus is ignored;
 * drivers use bus0. endpoint and halted use low8. EP0 (low7==0) returns immediately.
 * SET on OUT has no work. CLEAR OUT rebases the first of ten matching accounting
 * slots (ordered BYTE reads, one sequence/debt HALFWORD store, reset14/reset13
 * BYTEs), unlocks and drains that endpoint's pending OUT messages even if absent.
 *
 * SET IN gates matching primary/secondary reports under the credit lock, stalls
 * the driver outside it, then relocks: mark attached input states dirty and
 * detach their WORD pointers; clear queue extra_pending/window_active/
 * pending_short_multiple and submitted split using BYTE stores. These are NOT
 * the WORD clears shown by Ghidra. Clear secondary in-flight and transition flag.
 *
 * CLEAR IN takes report mutex, gates selected interfaces/secondary binding and
 * cancels hardware IN under the credit lock. Unlock, wait for endpoint disable,
 * sample fixed DIEPCTL and initial clock, then relock. Only when sampled EPENA
 * was clear recover primary and secondary data, unlock, cancel FIFO and clear
 * stall. A negative signed control snapshot skips recovery/FIFO/clear-stall.
 * Later always obtain a fresh clock/relock, clear gates, conditionally resume
 * scheduling and pump the first matching secondary binding. Some scans cache
 * counts; scans containing helper calls reread the live signed count each pass.
 *
 * Recovery capture uses the last successful primary payload/flags, possibly
 * overwritten by secondary recovery; primary copies cap64, the secondary helper
 * retains its unchecked copy length into the native64-byte stack buffer. Emit
 * class9 only if recovered!=0 and capture bit9 enabled, with endpoint LOW NIBBLE,
 * initial clock LOW32 and zero-length flag2. No rollback, hardware timing proof,
 * whole-operation lock or new bounds are added. Return no value.
 */
void medius_clone_endpoint_halt_changed(unsigned int bus, unsigned int endpoint,
    unsigned char halted)
{
    (void)bus;
    unsigned int address = (unsigned char)endpoint;
    if ((address & 127U) == 0)
        return;
    if ((address & 128U) == 0) {
        if (halted != 0)
            return;
        xPortEnterCriticalTimeout(DEVICE_OUT_LOCK, -1);
        for (unsigned int index = 0; index != 10; ++index) {
            volatile DeviceOutEndpoint *state = &DEVICE_OUT_ENDPOINTS[index];
            if (state->endpoint != address)
                continue;
            unsigned int rebase = state->rebase_sequence;
            unsigned int produced = state->produced;
            unsigned int acknowledged = state->acknowledged;
            unsigned int sent = state->sent_sequence;
            unsigned char debt = (unsigned char)(rebase + produced - acknowledged - sent);
            state->sequence_and_debt = (unsigned short)(sent | ((unsigned int)debt << 8));
            state->reset_flag14 = rebase != sent || debt != 0;
            state->reset_flag13 = 0;
            break;
        }
        vPortExitCritical(DEVICE_OUT_LOCK);
        out_drain_pending(address);
        return;
    }
    unsigned int secondary_slot;
    if (halted != 0) {
        xPortEnterCriticalTimeout(&CREDIT_LOCK, -1);
        int count = USB_INTERFACE_COUNT;
        for (int index = 0; index < count; ++index) {
            if (USB_INTERFACE_ENDPOINTS[index] == address) {
                memw();
                REPORT_SUBMIT_BLOCKED_WRITABLE[index] = 1;
                memw();
                REPORT_SERVICE_ACTIVE[index] = 0;
            }
        }
        if (halt_find_binding(address, &secondary_slot) >= 0) {
            memw();
            REPORT_SECONDARY_STALLED[secondary_slot] = 1;
            memw();
            REPORT_SECONDARY_STALL_PENDING[secondary_slot] = 0;
        }
        vPortExitCritical(&CREDIT_LOCK);
        usb_device_set_stall(0, (unsigned char)address);
        xPortEnterCriticalTimeout(&CREDIT_LOCK, -1);
        count = USB_INTERFACE_COUNT;
        for (int index = 0; index < count;) {
            if (USB_INTERFACE_ENDPOINTS[index] == address) {
                InputStateView *input = REPORT_SUBMIT_INPUT_STATES[index];
                if (input != NULL) {
                    input_mark_dirty(input);
                    REPORT_SUBMIT_INPUT_STATES[index] = NULL;
                }
                volatile CreditInterfaceQueue *queue = &REPORT_INTERFACE_QUEUES_WRITABLE[index];
                queue->extra_pending = 0;
                queue->window_active = 0;
                queue->pending_short_multiple = 0;
                REPORT_SUBMIT_SPLIT[index] = 0;
            }
            count = USB_INTERFACE_COUNT;
            ++index;
        }
        if (halt_find_binding(address, &secondary_slot) >= 0) {
            memw();
            REPORT_SECONDARY_IN_FLIGHT[secondary_slot] = 0;
        }
        vPortExitCritical(&CREDIT_LOCK);
        memw();
        MEDIUS_REPORT_ENDPOINT_TRANSITION_PENDING = 0;
        return;
    }

    unsigned int endpoint_number = address & 15U;
    RtosQueue *mutex = REPORT_MUTEX;
    if (mutex != NULL)
        xQueueSemaphoreTake(mutex, 0xffffffffU);
    xPortEnterCriticalTimeout(&CREDIT_LOCK, -1);
    unsigned int selected = 0;
    int count = USB_INTERFACE_COUNT;
    for (int index = 0; index < count; ++index) {
        if (USB_INTERFACE_ENDPOINTS[index] == address) {
            memw();
            REPORT_SUBMIT_BLOCKED_WRITABLE[index] = 0;
            memw();
            REPORT_SERVICE_ACTIVE[index] = 0;
            memw();
            REPORT_INTERFACE_BLOCKED[index] = 1;
            selected |= 1U << (index & 31U);
        }
    }
    int binding_index = halt_find_binding(address, &secondary_slot);
    if (binding_index >= 0) {
        memw();
        REPORT_SECONDARY_STALLED[secondary_slot] = 0;
        memw();
        REPORT_SECONDARY_STALL_PENDING[secondary_slot] = 0;
        memw();
        MEDIUS_REPORT_SECONDARY_BLOCKED_WRITABLE[secondary_slot] = 1;
    }
    medius_dwc2_cancel_in(0, (unsigned char)(endpoint_number | 128U));
    vPortExitCritical(&CREDIT_LOCK);
    medius_dwc2_wait_in_endpoints_disabled(1U << endpoint_number);
    memw();
    unsigned int control = DWC2_IN_CONTROL(endpoint_number);
    unsigned char capture[64];
    unsigned char recovery_flags = 0, capture_length = 0;
    unsigned char capture_flags = 0;
    unsigned int recovered = 0;
    unsigned int capture_stamp = (unsigned int)esp_timer_get_time();
    xPortEnterCriticalTimeout(&CREDIT_LOCK, -1);
    if ((int)control >= 0) {
        count = USB_INTERFACE_COUNT;
        for (int index = 0; index < count;) {
            if ((selected & (1U << (index & 31U))) != 0) {
                unsigned int accepted = report_recover_interface_in(index, &recovery_flags);
                if (accepted != 0) {
                    unsigned int report_length = REPORT_SUBMIT_LENGTH[index];
                    unsigned int copied = report_length < 64 ? report_length : 64;
                    memw();
                    unsigned int metadata = REPORT_SUBMIT_METADATA42[index];
                    capture_flags = recovery_flags | metadata;
                    capture_length = (unsigned char)copied;
                    recovered = accepted;
                    memcpy(capture, REPORT_SUBMIT_STORAGE + index * 64U, copied);
                }
            }
            count = USB_INTERFACE_COUNT;
            ++index;
        }
        if (binding_index >= 0)
            recovered = (unsigned char)(recovered |
                medius_report_recover_secondary_in(address, capture, &capture_length));
        vPortExitCritical(&CREDIT_LOCK);
        medius_dwc2_in_fifo_cancel(0, (unsigned char)address);
        usbd_ep_clear_stall(0, (unsigned char)address);
    } else
        vPortExitCritical(&CREDIT_LOCK);
    unsigned long long resumed_at = (unsigned long long)esp_timer_get_time();
    xPortEnterCriticalTimeout(&CREDIT_LOCK, -1);
    count = USB_INTERFACE_COUNT;
    for (int index = 0; index < count;) {
        if ((selected & (1U << (index & 31U))) != 0) {
            memw();
            REPORT_INTERFACE_BLOCKED[index] = 0;
            if ((int)control >= 0) {
                memw();
                if (USB_SUSPENDED == 0) {
                    volatile CreditInterfaceQueue *queue = &REPORT_INTERFACE_QUEUES_WRITABLE[index];
                    if (queue->extra_pending == 0 && queue->record_count != 0) {
                        unsigned int period = MEDIUS_RAW_INTERFACE_LENGTH_LIMITS[index];
                        report_schedule_candidate((CreditInterfaceQueue *)queue,
                            resumed_at, resumed_at, (unsigned short)period, index, 0);
                    }
                }
            }
        }
        count = USB_INTERFACE_COUNT;
        ++index;
    }
    binding_index = halt_find_binding(address, &secondary_slot);
    if (binding_index >= 0) {
        memw();
        MEDIUS_REPORT_SECONDARY_BLOCKED_WRITABLE[secondary_slot] = 0;
        if ((int)control >= 0)
            report_pump_secondary(binding_index);
    }
    vPortExitCritical(&CREDIT_LOCK);
    mutex = REPORT_MUTEX;
    if (mutex != NULL)
        xQueueGenericSend(mutex, NULL, 0, 0);
    if (recovered != 0) {
        memw();
        if ((CAPTURE_ENABLED_CLASSES & 0x200U) != 0) {
            unsigned char flags = capture_flags | (capture_length == 0 ? 2U : 0U);
            medius_capture_record_transfer(9, endpoint_number, 1, flags, capture_stamp,
                1, capture, capture_length);
        }
    }
}
