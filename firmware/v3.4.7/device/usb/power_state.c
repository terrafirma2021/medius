/* Medius v3.4.7 device — ordered USB power-state publication. */
#include "../include/types.h"

/* Native entry: 0x42029348. */
/* Original function-byte SHA-256:
 * f00f2d61b545ba507a5e075f824c6bf33cac1099e43854d4fe5b66106d748422. */
/*
 * Queue type0x41 with two RAW bytes: USB suspend then remote-wakeup enable.
 * Read each state with its own preceding MEMW, then fence/read generation,
 * then fence/read quiescing. Reject quiescing or an initially NULL OUT queue
 * after these snapshots, without changing counters or taking a clock sample.
 * Host dispatch decodes0x41 as the ordered power request and normalizes the
 * two bytes there; this producer does not normalize them.
 *
 * Zero an80-byte OUT message; store clock LOW, control_type BYTE0x41, cached
 * generation WORD, copy the two saved bytes, then store length BYTE2. Increment
 * active-control atomically with arguments1/3 and send with a FRESH queue
 * pointer,20 ticks and back position. Exact status1 leaves balancing to the
 * forwarding worker. Failure atomically decrements active-control, then fences
 * the non-atomic drop WORD read and separately fences its incremented store.
 * No acquired lock, retry, queue-replacement guard, transport acknowledgement,
 * error result or timestamp/generation refresh is supplied here.
 */
void out_publish_power_state(void)
{
    unsigned char power[2];
    memw();
    power[0] = USB_SUSPENDED;
    memw();
    power[1] = MEDIUS_USB_REMOTE_WAKE_ENABLED;
    memw();
    unsigned int generation = DEVICE_OUT_GENERATION;
    memw();
    if (CLONE_QUIESCING != 0 || DEVICE_OUT_FORWARD_QUEUE == NULL)
        return;
    MediusDeviceOutMessage message;
    memset(&message,0,sizeof(message));
    message.stamp = (unsigned int)esp_timer_get_time();
    message.control_type = 0x41;
    message.generation = generation;
    memcpy(message.payload,power,2U);
    message.length = 2;
    (void)atomic_fetch_add_u32(&CONTROL_OPERATION_ACTIVE,1,3);
    if (xQueueGenericSend(DEVICE_OUT_FORWARD_QUEUE,&message,20,0) != 1) {
        (void)atomic_fetch_sub_u32(&CONTROL_OPERATION_ACTIVE,1,3);
        memw();
        unsigned int drops = DEVICE_OUT_DROPS;
        ++drops;
        memw();
        DEVICE_OUT_DROPS = drops;
    }
}
