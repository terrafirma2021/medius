/* Medius v3.4.7 device — ISR fast-transmit wake notification. */
#include "../include/types.h"

/* Native entry: 0x4037d16c. */
/* Original function-byte SHA-256:
 * 4fd59ba0eb713335643b84a9a39b1d3c1bb099a1c8baf444b8beeaeaea919f98. */
/* Capture the UART link TX task handle BEFORE MEMW/publishing fast_pending=1.
 * Even a NULL handle leaves the pending BYTE set. A captured non-NULL handle
 * receives notification-give at index0, with a zero-initialized local wake flag;
 * request an ISR switch only when that flag becomes nonzero. A concurrently
 * replaced global handle does not change the notification target. No queue
 * insertion, extra context check, task creation, waiting or lock. */
void link_wake_fast_transmit_from_isr(void)
{
    RtosTask *transmit_task = LINK_TX_TASK_HANDLE;
    memw();
    LINK_TX_FAST_PENDING = 1;
    if (transmit_task == NULL) return;
    int higher_priority_task_woken = 0;
    vTaskGenericNotifyGiveFromISR(transmit_task, 0, &higher_priority_task_woken);
    if (higher_priority_task_woken != 0) _frxt_setup_switch();
}
