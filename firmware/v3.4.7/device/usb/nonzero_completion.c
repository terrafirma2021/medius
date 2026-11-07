/* Medius v3.4.7 device — Nonzero-control transfer completion callbacks. */
#include "../include/types.h"

/* Native entry: 0x420288e4. */
/* Original function-byte SHA-256:
 * 9446629a11a96ca8694c6ce50a97068dd5b049018aaf3cf4283557644d13d027. */
/*
 * Complete a nonzero-control OUT transfer in ISR context. bus is ignored; the
 * driver call uses bus0. endpoint's low nibble selects the first matching slot
 * from the published endpoint BYTEs; a count>1 permits slot1, never a third.
 * actual is a full unsigned WORD. Rearm SETUP reception BEFORE comparing actual
 * with the slot's requested HALFWORD; oversized completion leaves state alone.
 *
 * State1 accepts min(actual,2048), loads the queue handle before publishing
 * state2, then queues the one-BYTE slot index at the back. Missing queue or send
 * result!=1 clears state0. A nonzero higher-priority-task-woken WORD requests a
 * switch even if send failed. Other states are reread after another fence;
 * state4 becomes0. No copy, stall, generation check or per-slot lock is added.
 * Return no value. Queue must have item size1 and state storage remain live.
 */
void medius_nonzero_control_out_complete(unsigned char bus,
    unsigned char endpoint, unsigned int actual)
{
    (void)bus;
    int count = MEDIUS_NONZERO_ENDPOINT_COUNT;
    if (count <= 0)
        return;
    unsigned char endpoint_number = endpoint & 15U;
    unsigned int slot;
    if (MEDIUS_NONZERO_ENDPOINT_IDS[0] == endpoint_number)
        slot = 0;
    else {
        if (count == 1 || MEDIUS_NONZERO_ENDPOINT_IDS[1] != endpoint_number)
            return;
        slot = 1;
    }
    medius_dwc2_arm_setup_size(0, endpoint_number);
    volatile MediusNonzeroControlState *state = &MEDIUS_NONZERO_CONTROL_STATES[slot];
    unsigned int requested = state->requested;
    if (actual > requested)
        return;
    memw();
    if (state->state == 1) {
        state->actual = (unsigned short)(actual < 2048 ? actual : 2048);
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
        int sent = xQueueGenericSendFromISR(queue, &queued_slot, &task_woken, 0);
        int should_switch = *(volatile int *)&task_woken;
        if (sent != 1) {
            memw();
            state->state = 0;
        }
        if (should_switch != 0)
            _frxt_setup_switch();
    } else {
        memw();
        if (state->state == 4) {
            memw();
            state->state = 0;
        }
    }
}

/* Native entry: 0x4202c50c. */
/* Original function-byte SHA-256:
 * ceb0c95fcf56634106b80dabc978157874c05d837e915ebcdf9ae4718274aa43. */
/*
 * Complete nonzero-control IN data/ZLP or status in ISR context. bus and actual
 * are ignored; all driver calls use bus0. Match endpoint's low nibble to slot0
 * or, when count>1, slot1. In state3, a nonzero needs_zlp BYTE causes one empty
 * IN write after clearing that flag; state stays3. Otherwise publish state4 and
 * arm an empty OUT status read into the slot's persistent2048-byte buffer.
 *
 * Negative submission result rereads endpoint, clears state0 and stalls IN,
 * then rereads endpoint again and stalls OUT. Nonnegative returns immediately.
 * Other states are fenced/reread; state4 clears to0. No new ZLP decision, payload
 * copy, completion-length validation, generation test or synchronization beyond
 * the native per-state fences. Return no value; caller keeps slot/buffer alive.
 */
void medius_nonzero_control_in_complete(unsigned char bus,
    unsigned char endpoint, unsigned int actual)
{
    (void)bus;
    (void)actual;
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
    volatile MediusNonzeroControlState *state = &MEDIUS_NONZERO_CONTROL_STATES[slot];
    memw();
    if (state->state != 3) {
        memw();
        if (state->state == 4) {
            memw();
            state->state = 0;
        }
        return;
    }
    unsigned int needs_zlp = state->needs_zlp;
    unsigned char stalled_endpoint;
    if (needs_zlp != 0) {
        unsigned char target_endpoint = state->endpoint;
        state->needs_zlp = 0;
        int submitted = usb_device_write_aligned(0, target_endpoint | 0x80U, NULL, 0);
        if (submitted >= 0)
            return;
        stalled_endpoint = state->endpoint;
        memw();
        state->state = 0;
    } else {
        memw();
        state->state = 4;
        unsigned char target_endpoint = state->endpoint;
        int submitted = usbd_ep_start_read(0, target_endpoint,
            MEDIUS_NONZERO_CONTROL_BUFFERS + slot * 2048U, 0);
        if (submitted >= 0)
            return;
        stalled_endpoint = state->endpoint;
        memw();
        state->state = 0;
    }
    usb_device_set_stall(0, stalled_endpoint | 0x80U);
    usb_device_set_stall(0, state->endpoint);
}
