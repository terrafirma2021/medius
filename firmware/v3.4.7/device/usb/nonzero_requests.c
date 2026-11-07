/* Medius v3.4.7 device — Nonzero-control reply and SETUP admission. */
#include "../include/types.h"

/* Native entry: 0x40396990. */
/* Original function-byte SHA-256:
 * 8877c101b873917f43a1f2354f9d9f2b2f280a0c9f5bb5e1fad8e1715c7008fb. */
/*
 * Admit a reply only with at least endpoint/status bytes, an existing signal,
 * active slot0/1, matching sequence, endpoint and record generation. Each shared
 * BYTE is sampled once at its native fence; there is no state/duplicate check
 * or recheck after copying. Copy min(length-2,2048) bytes into the slot buffer,
 * including for error status, without clamping to the USB requested length.
 *
 * Read status BYTE after the copy; publish actual HALFWORD, status BYTE, then
 * completed sequence BYTE, with MEMW before each store. Give the response
 * semaphore with zero wait and ignore its result. Reload its handle only after
 * a nonempty copy; an empty reply uses the initially sampled handle. No local
 * lock or pointer validation. Buffer and slot storage must remain accessible.
 */
void nonzero_control_response(unsigned char sequence,
    unsigned char *payload,unsigned short length)
{
    if (length < 2)
        return;
    MediusNonzeroControlReply *reply = MEDIUS_NONZERO_REPLY;
    RtosQueue *signal = reply->signal;
    if (signal == NULL)
        return;
    memw();
    unsigned int slot = MEDIUS_NONZERO_ACTIVE_SLOT;
    if (slot >= 2)
        return;
    memw();
    if (reply->expected_sequence != sequence)
        return;
    volatile MediusNonzeroControlState *state = &MEDIUS_NONZERO_CONTROL_STATES[slot];
    unsigned char endpoint = *(const volatile unsigned char *)payload;
    if (endpoint != state->endpoint)
        return;
    memw();
    unsigned char generation = state->generation;
    memw();
    if (generation != reply->expected_generation)
        return;
    unsigned int actual = length - 2U;
    if (actual > 2048U)
        actual = 2048U;
    if (actual != 0) {
        memcpy(MEDIUS_NONZERO_CONTROL_BUFFERS + slot * 2048U,payload + 2,actual);
        signal = reply->signal;
    }
    unsigned char status = *(const volatile unsigned char *)(payload + 1);
    memw();
    reply->actual = (unsigned short)actual;
    memw();
    reply->status = status;
    memw();
    reply->completed_sequence = sequence;
    xQueueGenericSend(signal,NULL,0,0);
}

/* Native entry: 0x40396a50. */
/* Original function-byte SHA-256:
 * 5c5790006779fcff9678a50bb6ddf0beed8b7b15a0e1b1eb7c9249e583e590d6. */
/*
 * Accept a fragment only while the active-slot BYTE has bit7 clear and the
 * freshly sampled expected sequence matches the argument. Values2..127 pass
 * this precheck; the final response handler independently requires slot0/1.
 * Pass fragment/low16 length to the shared parser. On parser success, forward
 * that sampled matching sequence, assembly payload and total HALFWORD; then
 * clear total with a HALFWORD store and used/active/error with one WORD store.
 * The native code does not sample expected sequence before its active check.
 *
 * Rejected/incomplete fragments retain parser state. Completed assembly resets
 * even when the final handler rejects it. No lock, timeout, generation/endpoint
 * check here; the fixed assembly's progress WORD is naturally aligned.
 */
void nonzero_control_response_fragment(unsigned char sequence,
    unsigned char *fragment,unsigned short length)
{
    memw();
    if ((MEDIUS_NONZERO_ACTIVE_SLOT & 0x80U) != 0)
        return;
    memw();
    unsigned char expected_sequence = MEDIUS_NONZERO_REPLY->expected_sequence;
    if (expected_sequence != sequence)
        return;
    ControlAssembly *assembly = MEDIUS_NONZERO_RESPONSE_ASSEMBLY;
    if (control_fragment_accept(assembly,fragment,length) == 0)
        return;
    unsigned short total = *(const volatile unsigned short *)&assembly->total;
    nonzero_control_response(expected_sequence,assembly->payload,total);
    *(volatile unsigned short *)&assembly->total = 0;
    MEDIUS_NONZERO_ASSEMBLY_PROGRESS = 0;
}

/* Native entry: 0x4203442c. */
/* Original function-byte SHA-256:
 * 99764877a534ce56afcb19560689260b6cff2382fc943da4c15e41b92b1f791a. */
/*
 * Initialize the first of at most two published nonzero-control endpoint slots
 * matching endpoint's low nibble. bus is ignored; all driver calls use bus0.
 * Clear IN then the original endpoint's stall, increment generation BYTE with
 * wrapping arithmetic, and copy eight SETUP bytes into shared record storage.
 * Read wLength high BYTE before low BYTE, store requested HALFWORD, then read
 * direction, clear actual HALFWORD and needs_zlp BYTE, in that native order.
 *
 * Length>2048 clears state and stalls IN then freshly read OUT endpoint. A
 * nonempty OUT request publishes state1 and starts a read into the persistent
 * slot buffer; negative submission takes the same stall path. IN/empty requests
 * sample queue handle before publishing state2 and send a one-BYTE slot index
 * from ISR. Missing queue/send result!=1 clears state without stalling. Yield
 * when the sampled higher-priority-task-woken WORD is nonzero, even on failure.
 * No NULL/queue-size checks, slot lock or atomic ownership of shared SETUP.
 */
void medius_nonzero_control_setup(unsigned char bus,unsigned char endpoint,
    const unsigned char *setup)
{
    (void)bus;
    int count = MEDIUS_NONZERO_ENDPOINT_COUNT;
    if (count <= 0)
        return;
    unsigned int slot;
    unsigned char endpoint_number = endpoint & 15U;
    if (MEDIUS_NONZERO_ENDPOINT_IDS[0] == endpoint_number)
        slot = 0;
    else {
        if (count == 1 || MEDIUS_NONZERO_ENDPOINT_IDS[1] != endpoint_number)
            return;
        slot = 1;
    }
    usbd_ep_clear_stall(0,endpoint | 0x80U);
    usbd_ep_clear_stall(0,endpoint);
    volatile MediusNonzeroControlState *state = &MEDIUS_NONZERO_CONTROL_STATES[slot];
    memw();
    unsigned char generation = state->generation;
    memw();
    state->generation = (unsigned char)(generation + 1U);
    memcpy((void *)state->setup,setup,8);
    unsigned int high = *(const volatile unsigned char *)(setup + 7);
    unsigned int low = *(const volatile unsigned char *)(setup + 6);
    unsigned int requested = (high << 8) | low;
    state->requested = (unsigned short)requested;
    unsigned char request_type = *(const volatile unsigned char *)setup;
    state->direction_in = request_type >> 7;
    state->actual = 0;
    state->needs_zlp = 0;
    if (requested <= 2048U) {
        if (requested == 0 || (request_type & 0x80U) != 0) {
            RtosQueue *queue = NONZERO_CONTROL_QUEUE;
            memw();
            state->state = 2;
            unsigned char queued_slot = (unsigned char)slot;
            int task_woken = 0;
            if (queue == NULL) {
                memw();
                state->state = 0;
                return;
            }
            int sent = xQueueGenericSendFromISR(queue,&queued_slot,&task_woken,0);
            int should_switch = *(volatile int *)&task_woken;
            if (sent != 1) {
                memw();
                state->state = 0;
            }
            if (should_switch != 0)
                _frxt_setup_switch();
            return;
        }
        unsigned char target_endpoint = state->endpoint;
        memw();
        state->state = 1;
        if (usbd_ep_start_read(0,target_endpoint,
                MEDIUS_NONZERO_CONTROL_BUFFERS + slot * 2048U,requested) >= 0)
            return;
    }
    unsigned char target_endpoint = state->endpoint;
    memw();
    state->state = 0;
    usb_device_set_stall(0,target_endpoint | 0x80U);
    usb_device_set_stall(0,state->endpoint);
}
