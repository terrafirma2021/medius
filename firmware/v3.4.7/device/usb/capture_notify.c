/* Medius v3.4.7 device: recovered usb/capture_notify.c. */

#include "../include/types.h"

/* Native entry: 0x40393128. */
/* Original function-byte SHA-256:
 * e7bbbde3ea8e89c9806005e4b1a8a60e9b3a060d40690bc93106042cd54bd6db. */

/*
 * Parameters: None.
 * Returns: Nothing.
 * Queries ISR context, THEN loads capture-task handle.
 * Task context uses indexed notification(0,0,eIncrement2,NULL). ISR context
 * uses give-from-ISR(index0,&zeroed_wake). Ignores both status and wake result;
 * does not request a yield. No NULL check, lock or ownership transfer: caller
 * must supply a live initialized capture task and coordinate teardown.
 */
void capture_notify_task(void)
{
    int in_isr = xPortInIsrContext();
    RtosTask *task = CAPTURE_TASK;
    if (in_isr == 0) {
        xTaskGenericNotify(task, 0, 0, 2, NULL);
    } else {
        int higher_priority_woken = 0;
        vTaskGenericNotifyGiveFromISR(task, 0, &higher_priority_woken);
    }
}
