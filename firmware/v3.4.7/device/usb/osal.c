/* Medius v3.4.7 device — usb/osal.c.
 * Recovered C and native assembly, grouped for source navigation.
 * Original entry addresses, firmware-byte hashes and function comments follow.
 */

#include "../include/types.h"

/* Native entry: 0x40382928. */
/*
 * Medius v3.4.7 — device application; 0x40382928.
 *
 * Forwards only the low8 delay bits to scheduler routine4038779C.
 *
 * Calls: vTaskDelay.
 *
 * Called by: usb_dc_init, usbd_set_remote_wakeup.
 *
 * Original function-byte SHA-256:
 * 079f439044f4bbcf5e9f3a5ed87f8b52e7f62f0af1f121617bc8f7c545e6f1a4.
 */

/*
 * delay: Scheduler tick count; only the low eight bits are forwarded.
 * Returns: Nothing; returns after vTaskDelay returns.
 * Requirements/effects: Calls vTaskDelay exactly once, including when truncation yields zero.
 *   Values wrap modulo 256; no conversion from milliseconds is performed by this wrapper. Requires
 *   a context in which the scheduler operation is permitted. Actual wake time depends on the RTOS
 *   and scheduling.
 */

void medius_usb_scheduler_delay_u8(unsigned int delay)
{
    vTaskDelay(delay & 255U);
}

/* Native entry: 0x40382940. */
/* Original function-byte SHA-256:
 * 5c7f20b487cf33fd78b7ca9a2e075f5b73ac9339b53de225a680aae55cdd395c. */
/*
 * Receives into caller storage using the task or ISR FreeRTOS queue API.
 * ISR context ignores timeout, initializes higher_priority_task_woken to zero
 * and requests a switch only on successful receive and an exact flag of 1.
 * Task context maps -1 to UINT32_MAX; other timeouts become
 * ((uint32_t)timeout * 1000 modulo 2^32) / 1000 ticks, including negatives
 * other than -1. This conversion must not simplify to timeout.
 * Returns 0 only for queue result 1, otherwise -14. Queue item width controls
 * the write extent; no handle/output validation or elapsed-time guarantee.
 */
int usb_osal_mq_recv(void *queue,void *output,int timeout)
{
    int higher_priority_task_woken = 0;
    if (xPortInIsrContext() != 0) {
        if (xQueueReceiveFromISR(queue,output,&higher_priority_task_woken) != 1)
            return -14;
        if (higher_priority_task_woken == 1) _frxt_setup_switch();
        return 0;
    }
    unsigned int ticks = timeout == -1 ? 0xffffffffU :
        ((unsigned int)timeout * 1000U) / 1000U;
    return xQueueReceive(queue,output,ticks) == 1 ? 0 : -14;
}

/* Native entry: 0x4038299c. */
/* Original function-byte SHA-256:
 * 3861e2cf4d79a939fc49bfca52fe9fa0d51473191fd3cf9a0ebdcdc943f16b8e. */
/*
 * Places the by-value 32-bit message in local storage and sends its address
 * to the queue, using back insertion (copy_position 0). In task context the
 * wait is UINT32_MAX. In ISR context there is no wait; initializes the woken
 * flag to zero and requests a switch only after result 1 and exact flag 1.
 * Returns 0 for result 1, otherwise -14. The queue owns the copy width:
 * callers must use a four-byte-item queue, as constructed by this OSAL.
 * No queue validation or pointed-to payload ownership transfer occurs.
 */
int usb_osal_mq_send(void *queue,unsigned int value)
{
    unsigned int message = value;
    int higher_priority_task_woken = 0;
    if (xPortInIsrContext() != 0) {
        if (xQueueGenericSendFromISR(queue,&message,&higher_priority_task_woken,0) != 1)
            return -14;
        if (higher_priority_task_woken == 1) _frxt_setup_switch();
        return 0;
    }
    return xQueueGenericSend(queue,&message,0xffffffffU,0) == 1 ? 0 : -14;
}

/* Native entry: 0x42008a98. */
/*
 * Medius v3.4.7 — device application; 0x42008a98.
 *
 * Uses the reserved EP0 task resources once, otherwise creates a dynamic task.
 *
 * Calls: strcmp, usb_osal_thread_create, xTaskCreateStaticPinnedToCore.
 *
 * Called by: usbd_initialize.
 *
 * Original function-byte SHA-256:
 * 3c2ebc7c597d13f8e74a5fc148886b5faba30398cd86a254bc2c101a8a6b5eae.
 */

/*
 * name: Readable task name; NULL is passed to strcmp without a guard.
 * stack_bytes: Requested byte count; at most 6144 admits the reserved path.
 * priority: Mapped to unsigned32(24-priority) without validation.
 * task_entry: Task entry callback, void(void *).
 * argument: Borrowed task argument retained by the created task.
 * Returns: The selected static or dynamic creation result, including NULL.
 * Requirements/effects: Checks exact name usbd_ep0. Only a matching name reads the reserved stack
 *   pointer; that read precedes size admission. Reserved path also requires non-NULL stack and a
 *   nonzero availability byte, then reads the TCB pointer and requests a 6144-byte core-0 task.
 *   Publishes the returned handle before clearing availability, even on static failure; there is
 *   no dynamic retry after that failure. Other paths delegate all original inputs to
 *   usb_osal_thread_create and preserve reserved state. There is no pre-call reservation,
 *   extent/TCB validation or lock, so callers must serialize resource ownership.
 */

void *medius_usb_osal_thread_create(char *name,unsigned int stack_bytes,
    unsigned int priority,TaskEntry task_entry,void *argument)
{
    MediusUsbEp0TaskResources *resources = MEDIUS_USB_EP0_TASK_RESOURCES;
    int name_comparison = strcmp(name,"usbd_ep0");
    unsigned int *reserved_stack = 0;
    if (name_comparison == 0)
        reserved_stack = resources->stack;
    if (name_comparison == 0 && stack_bytes <= 6144U && reserved_stack != 0 &&
        USB_EP0_TASK_STORAGE_AVAILABLE != 0) {
        RtosTask *created_thread = xTaskCreateStaticPinnedToCore(
            task_entry,name,6144U,argument,24U - priority,(unsigned char *)reserved_stack,resources->tcb,0);
        resources->task = created_thread;
        USB_EP0_TASK_STORAGE_AVAILABLE = 0;
        return created_thread;
    }
    return usb_osal_thread_create(name,stack_bytes,priority,task_entry,argument);
}

/* Native entry: 0x42008b0c. */
/*
 * Medius v3.4.7 — device application; 0x42008b0c.
 *
 * Deletes the task and conditionally makes reserved EP0 resources available based on caller
 * affinity.
 *
 * Calls: vTaskDelete, usb_osal_thread_delete, xTaskGetCoreID.
 *
 * Called by: FUN_42021a18.
 *
 * Original function-byte SHA-256:
 * 0cc6968edd76f2de54ac8f8507e3e1c987672d27b04a07bf677759db0c50b439.
 */

/*
 * thread: Task handle; NULL and nonmatching handles delegate to ordinary deletion.
 * Returns: Nothing; self-deletion can prevent the remaining stores and return.
 * Requirements/effects: NULL bypasses the retained-handle read. For a matching nonzero retained
 *   handle, caches it, queries the calling task affinity with xTaskGetCoreID(NULL), and deletes
 *   that cached handle. If deletion returns, clears retained handle before setting availability to
 *   exactly (saved affinity == 0). Delegated changes to those slots are overwritten on this path;
 *   the ordinary path preserves them. No lock, generation check or wait for deferred reclamation
 *   establishes safe reuse.
 */

void medius_usb_osal_thread_delete(void *thread)
{
    if (thread == 0) {
        usb_osal_thread_delete(thread);
        return;
    }
    MediusUsbEp0TaskResources *resources = MEDIUS_USB_EP0_TASK_RESOURCES;
    RtosTask *retained_thread = resources->task;
    if (retained_thread != thread) {
        usb_osal_thread_delete(thread);
        return;
    }
    int caller_affinity = xTaskGetCoreID(0);
    vTaskDelete(retained_thread);
    resources->task = 0;
    USB_EP0_TASK_STORAGE_AVAILABLE = (unsigned char)(caller_affinity == 0);
}

/* Native entry: 0x42021698. */
/*
 * Medius v3.4.7 — device application; 0x42021698.
 *
 * Creates a core-0 task and returns the output handle, ignoring SDK status.
 *
 * Calls: xTaskCreatePinnedToCore.
 *
 * Called by: medius_usb_osal_thread_create.
 *
 * Original function-byte SHA-256:
 * 179e0188c10b496557dde223d882a80a22d1280a954a4a4095dcd54dd19f4a17.
 */

/*
 * name: Task name pointer forwarded to FreeRTOS.
 * stack_bytes: Requested stack length in bytes, forwarded unchanged.
 * priority: USB abstraction priority; mapped to unsigned 32-bit 24-priority without a range check.
 * task_entry: Task entry callback with the Xtensa/FreeRTOS void(void *) ABI.
 * argument: Opaque argument retained by the created task.
 * Returns: The output task handle, including NULL, regardless of the delegated creation status.
 * Requirements/effects: Initializes one local handle to NULL and calls xTaskCreatePinnedToCore
 *   with core 0. The output slot is borrowed only for this synchronous call. No
 *   entry/name/stack/priority validation or allocation recovery occurs here; successful scheduling
 *   and task lifetime are RTOS responsibilities. Values above priority 24 wrap in the forwarded
 *   priority expression.
 */

void *usb_osal_thread_create(char *name,unsigned int stack_bytes,
    unsigned int priority,TaskEntry task_entry,void *argument)
{
    RtosTask *created_thread = 0;
    xTaskCreatePinnedToCore(task_entry,name,stack_bytes,argument,
        24U - priority,&created_thread,0);
    return created_thread;
}

/* Native entry: 0x420216bc. */
/*
 * Medius v3.4.7 — device application; 0x420216bc.
 *
 * Forwards task deletion to FreeRTOS.
 *
 * Calls: vTaskDelete.
 *
 * Called by: medius_usb_osal_thread_delete.
 *
 * Original function-byte SHA-256:
 * 9459dc51e60f94e22b407e7eaf16c8adba9658ced80b368ec421b5ba8a0ab279.
 */

/*
 * thread: Task handle forwarded unchanged; NULL selects the current task in FreeRTOS.
 * Returns: No wrapper result; self-deletion can prevent a return to the caller.
 * Requirements/effects: Calls vTaskDelete once. Task cleanup, deferred reclamation and
 *   waiter/concurrent lifetime rules are delegated. The wrapper does not clear a retained caller
 *   handle or perform extra synchronization.
 */

void usb_osal_thread_delete(void *thread)
{
    vTaskDelete(thread);
}

/* Native entry: 0x420216cc. */
/*
 * Medius v3.4.7 — device application; 0x420216cc.
 *
 * Requests a queue of four-byte values.
 *
 * Calls: xQueueGenericCreate.
 *
 * Called by: usbd_initialize.
 *
 * Original function-byte SHA-256:
 * 70d07a61fcbb6aa6ef39a7159ec0349df829b6127daa407a46e8ccc84dc62615.
 */

/*
 * length: Requested number of four-byte queue items, forwarded unchanged.
 * Returns: The queue constructor result, including NULL.
 * Requirements/effects: Calls xQueueGenericCreate(length, 4). Native code also prepares source
 *   queue-type 0, which this optimized callee does not consume. No zero-length, size-overflow or
 *   allocation-failure handling occurs locally. Four-byte item copies do not transfer ownership of
 *   any referenced payload.
 */

void *usb_osal_mq_create(unsigned int length)
{
    return xQueueGenericCreate(length,4U);
}

/* Native entry: 0x420216e0. */
/*
 * Medius v3.4.7 — device application; 0x420216e0.
 *
 * Forwards queue deletion without draining or releasing message payloads.
 *
 * Calls: FUN_40386888.
 *
 * Called by: FUN_42021a18, usbd_initialize.
 *
 * Original function-byte SHA-256:
 * 8c8450c0efbee484646158d63f60574725f2551bc260d7bba376d45cf7c752e3.
 */

/*
 * queue: Live queue handle under the RTOS destruction/lifetime rules.
 * Returns: Nothing.
 * Requirements/effects: Forwards one queue-deletion call. It does not receive pending values, free
 *   pointed-to messages, clear caller state or synchronize concurrent users.
 */

void usb_osal_mq_delete(void *queue)
{
    vQueueDelete(queue);
}
