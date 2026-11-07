/* Medius v3.4.7 host — usb/osal.c.
 * Recovered C and native assembly, grouped for source navigation.
 * Original entry addresses, firmware-byte hashes and function comments follow.
 */

#include "../include/types.h"

/* Native entry: 0x42020850. */
/*
 * Medius v3.4.7 — host application; 0x42020850.
 *
 * Creates a core-0 task and returns the output handle, ignoring SDK status.
 *
 * Calls: xTaskCreatePinnedToCore.
 *
 * Called by: usbh_hub_initialize.
 *
 * Original function-byte SHA-256:
 * d570d5d8aa1378b1ccf33454efebc0df9bcddc0ec1f07299263054a5d42a65f1.
 */

/* Creates a core-0 task and returns the output handle, ignoring SDK status. Initializes a local
   four-byte handle to NULL, then calls
   xTaskCreatePinnedToCore(entry,name,stack_bytes,argument,unsigned32(24-priority),&handle,0). Stack
   size is forwarded unchanged; no division by StackType_t occurs. Ignores the SDK status and
   returns the subsequently loaded handle. The SDK receives a borrowed stack-local output address;
   no persistent copy of that address is made here. Boundaries: No local handle/pointer validation,
   ownership tracking or synchronization. RTOS/SDK/heap internals and concurrent object lifetime are
   separate; delegated calls must return for the wrapper to continue. No priority range, size, name
   or callback check; priorities above24 wrap. A non-NULL SDK output on error is still returned, and
   a success without an output still returns NULL. Does not guarantee task execution or pinning
   acceptance. */

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

void * usb_osal_thread_create(char *name,uint stack_bytes,uint priority,TaskEntry task_entry,void *argument)

{
  RtosTask *created_thread;

  created_thread = (void *)0x0;
  xTaskCreatePinnedToCore(task_entry,name,stack_bytes,argument,24U - priority,&created_thread,0);
  return created_thread;
}

/* Native entry: 0x42020874. */
/*
 * Medius v3.4.7 — host application; 0x42020874.
 *
 * Forwards task deletion to FreeRTOS.
 *
 * Calls: vTaskDelete.
 *
 * Called by: usbh_hub_thread.
 *
 * Original function-byte SHA-256:
 * b8c6f4ad878620d5624369f2b724aca0d973d49b25e662be3e97a1f163651ec7.
 */

/* Forwards task deletion to FreeRTOS. Calls vTaskDelete at 403828FC with the original handle once.
   No local memory writes except call frame; ignores any returned register value. Boundaries: No
   local handle/pointer validation, ownership tracking or synchronization. RTOS/SDK/heap internals
   and concurrent object lifetime are separate; delegated calls must return for the wrapper to
   continue. NULL/current-task deletion semantics, reclamation and whether the call returns are
   delegated to FreeRTOS. */

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
  return;
}

/* Native entry: 0x42020884. */
/*
 * Medius v3.4.7 — host application; 0x42020884.
 *
 * Temporarily lowers the current task priority, yields, then restores its saved priority.
 *
 * Calls: vPortYield, uxTaskPriorityGet, vTaskPrioritySet, xTaskGetCurrentTaskHandle.
 *
 * Called by: medius_host_hid_class_disconnect.
 *
 * Original function-byte SHA-256:
 * 19238bbf384b581ee434fc97f8fd3c79afffdbc45f2e25c0835b2b5780e2b78c.
 */

/* Temporarily lowers the current task priority, yields, then restores its saved priority. Calls
   current-task getter403836B0, passes that returned handle still in a10 to priority getter40382AE0,
   saves the full32 priority, calls priority setter40382B14(handle,0), yields through40381F40, then
   calls the setter(handle,saved_priority). Uses the saved handle even if scheduler context changes.
   No wrapper-local lock or error branch. Boundaries: No local handle/pointer validation, ownership
   tracking or synchronization. RTOS/SDK/heap internals and concurrent object lifetime are separate;
   delegated calls must return for the wrapper to continue. Does not guarantee another task runs.
   Lowering priority can itself reschedule. Priority changes by other contexts can be overwritten by
   saved-priority restoration. SDK helper bodies remain separately unreviewed. */

/*
 * Returns: Nothing, after the final priority restore returns.
 * Requirements/effects: Captures the current task handle and priority, sets that captured task to
 *   priority 0, calls vPortYield and restores its saved priority on the same handle. Requires a
 *   live task and valid task context. Lowering priority can itself reschedule; there is no
 *   guarantee another task runs or that concurrent priority changes survive the restoration.
 */

void usb_osal_thread_schedule_other(void)

{
  RtosTask *task;
  uint saved_priority;

  task = xTaskGetCurrentTaskHandle();
  saved_priority = uxTaskPriorityGet(task);
  vTaskPrioritySet(task,0);
  vPortYield();
  vTaskPrioritySet(task,saved_priority);
  return;
}

/* Native entry: 0x420208b4. */
/*
 * Medius v3.4.7 — host application; 0x420208b4.
 *
 * Creates a counting semaphore with maximum count one.
 *
 * Calls: xQueueCreateCountingSemaphore.
 *
 * Called by: usb_hc_init, usbh_hub_initialize.
 *
 * Original function-byte SHA-256:
 * 8cfbecd3ac7184ef050d3b690c0ebcb0306f32d66bbd41a3656de933b5932488.
 */

/* Creates a counting semaphore with maximum count one. Calls counting semaphore
   constructor4038145C(1,initial_count); returns its result unchanged. No local clamp, normalization
   or initial-token give call. Boundaries: No local handle/pointer validation, ownership tracking or
   synchronization. RTOS/SDK/heap internals and concurrent object lifetime are separate; delegated
   calls must return for the wrapper to continue. Values above1 reach the RTOS constructor
   validation; NULL allocation is returned directly. */

/*
 * initial_count: Requested initial count, forwarded without clamping.
 * Returns: The delegated semaphore handle or NULL.
 * Requirements/effects: Requests a counting semaphore with maximum count 1. Values above 1 reach
 *   the RTOS constructor unchanged; the wrapper performs no separate initial give, allocation test
 *   or synchronization.
 */

void * usb_osal_sem_create(uint initial_count)

{
  void *semaphore;

  semaphore = (void *)xQueueCreateCountingSemaphore(1,initial_count);
  return semaphore;
}

/* Native entry: 0x420208c8. */
/*
 * Medius v3.4.7 — host application; 0x420208c8.
 *
 * Forwards semaphore/mutex destruction to the RTOS queue deleter.
 *
 * Calls: vQueueDelete.
 *
 * Called by: FUN_4201fef4, medius_usbh_hub_shutdown.
 *
 * Original function-byte SHA-256:
 * 869b7b6d800ace86904805b62d4de86689e96b8076ee0d86b2a8a035c0ca3a6f.
 */

/* Forwards semaphore/mutex destruction to the RTOS queue deleter. Calls40381B30(handle) once; no
   local pointer clearing or ownership checks and no additional operations. Boundaries: No local
   handle/pointer validation, ownership tracking or synchronization. RTOS/SDK/heap internals and
   concurrent object lifetime are separate; delegated calls must return for the wrapper to continue.
   Waiters, held-mutex behavior and invalid handles are delegated; this does not establish safe
   concurrent deletion. */

/*
 * handle: Live semaphore handle; caller must satisfy RTOS deletion/lifetime rules.
 * Returns: Nothing.
 * Requirements/effects: Calls the RTOS queue deleter once. Does not drain waiters, clear the
 *   caller handle or establish safe concurrent deletion.
 */

void usb_osal_sem_delete(void *handle)

{
  vQueueDelete(handle);
  return;
}

/* Native entry: 0x420208d8. */
/*
 * Medius v3.4.7 — host application; 0x420208d8.
 *
 * Takes a semaphore with a wrapping finite timeout conversion and an infinite sentinel.
 *
 * Calls: xQueueSemaphoreTake.
 *
 * Called by: medius_usbh_hub_shutdown, usbh_submit_urb.
 *
 * Original function-byte SHA-256:
 * 9cc3d606c07287b86b0956b7cbb5b52a690aaa5d75194e5d7d99e2eae28d8a1d.
 */

/* Takes a semaphore with a wrapping finite timeout conversion and an infinite sentinel.
   Milliseconds FFFFFFFF is forwarded unchanged to xQueueSemaphoreTake. Otherwise Finite timeout
   conversion is floor(unsigned32(milliseconds*1000)/1000), using the original reciprocal-multiply
   sequence. Multiplication wraps before division:4294967 becomes4294967 ticks,4294968 becomes0,
   andFFFFFFFE becomes4294965. This is not saturating conversion. Calls the RTOS take once; only
   exact result1 maps to0; all other32-bit results map to-14. No ISR-context test. Boundaries: No
   local handle/pointer validation, ownership tracking or synchronization. RTOS/SDK/heap internals
   and concurrent object lifetime are separate; delegated calls must return for the wrapper to
   continue. Task-context blocking requirements come from the delegated API. No error distinction
   between timeout and other failures; a failure result does not undo any delegated side effects. */

/*
 * semaphore: Live semaphore handle appropriate for the delegated take.
 * milliseconds: Timeout input; UINT32_MAX is the infinite sentinel.
 * Returns: 0 only for exact delegated result 1; -14 for every other result.
 * Requirements/effects: Task-context call with one xQueueSemaphoreTake. Infinite input passes
 *   through unchanged; finite input uses unsigned32(milliseconds * 1000) / 1000, so multiplication
 *   wraps before division. For example 4294968 maps to zero ticks. There is no ISR check or
 *   distinction between timeout and other failures, and delegated side effects are not rolled
 *   back.
 */

int usb_osal_sem_take(void *semaphore,uint milliseconds)

{
  int result;

  if (milliseconds == 0xffffffff) {
    result = xQueueSemaphoreTake(semaphore,0xffffffff);
  }
  else {
    result = xQueueSemaphoreTake(semaphore,(milliseconds * 1000) / 1000);
  }
  if (result == 1) {
    result = 0;
  }
  else {
    result = -0xe;
  }
  return result;
}

/* Native entry: 0x42020918. */
/*
 * Medius v3.4.7 — host application; 0x42020918.
 *
 * Signals a semaphore through task or ISR APIs with exact success/woken checks.
 *
 * Calls: xQueueGiveFromISR, _frxt_setup_switch, xPortInIsrContext, xQueueGenericSend.
 *
 * Called by: USBH_IRQHandler, medius_usbh_account_and_rearm_in, medius_usbh_cancel_urb,
 * medius_usbh_complete_urb, usbh_hub_thread.
 *
 * Original function-byte SHA-256:
 * c5cbdfa2155d255065c680175ba6399a9528a152d1c8194fc4bdf7a9b644f97d.
 */

/* Signals a semaphore through task or ISR APIs with exact success/woken checks. Initializes local32
   woken=0 then calls xPortInIsrContext once. Zero context calls
   xQueueGenericSend(semaphore,NULL,0,0). Any nonzero context calls
   xQueueGiveFromISR40381728(semaphore,&woken). Only result exactly1 succeeds. On ISR success only,
   calls yield40381E30 if local woken is exactly1; other nonzero values do not yield. Task path has
   no explicit yield. Boundaries: No local handle/pointer validation, ownership tracking or
   synchronization. RTOS/SDK/heap internals and concurrent object lifetime are separate; delegated
   calls must return for the wrapper to continue. Borrowed woken output exists only during this
   invocation. Failure never yields, even if delegated call sets woken1; no rollback of external
   effects. */

/*
 * semaphore: Live semaphore handle usable by the selected task/ISR API.
 * Returns: 0 on exact delegated result 1, otherwise -14.
 * Requirements/effects: Initializes a signed 32-bit higher-priority-task-woken output to zero and
 *   queries ISR context once. Task context uses a nonblocking queue send; any nonzero context uses
 *   the ISR semaphore give. Only ISR success with woken exactly 1 calls _frxt_setup_switch. A
 *   failure never requests that switch, even if the delegated call writes woken=1. No rollback or
 *   local handle validation occurs.
 */

int usb_osal_sem_give(void *semaphore)

{
  int result;
  int higher_priority_woken;

  higher_priority_woken = 0;
  result = xPortInIsrContext();
  if (result == 0) {
    result = xQueueGenericSend(semaphore,(void *)0x0,0,0);
    if (result == 1) {
      return 0;
    }
  }
  else {
    result = xQueueGiveFromISR(semaphore,&higher_priority_woken);
    if (result == 1) {
      if (higher_priority_woken == 1) {
        _frxt_setup_switch();
      }
      return 0;
    }
  }
  return -0xe;
}

/* Native entry: 0x42020960. */
/*
 * Medius v3.4.7 — host application; 0x42020960.
 *
 * Requests an ordinary FreeRTOS mutex.
 *
 * Calls: xQueueCreateMutex.
 *
 * Called by: usbh_hub_thread.
 *
 * Original function-byte SHA-256:
 * 0cf11d583592a323f6b0431643cd0a1282dd550e7e2faf93312c2a28e8139c22.
 */

/* Requests an ordinary FreeRTOS mutex. Prepares literal1 as the source queue-type argument to
   xQueueCreateMutex4038158C. Optimized callee does not consume this argument; its existing
   void-parameter signature remains intentional. Returns the constructor result unchanged.
   Boundaries: No local handle/pointer validation, ownership tracking or synchronization.
   RTOS/SDK/heap internals and concurrent object lifetime are separate; delegated calls must return
   for the wrapper to continue. The wrapper does not acquire the created mutex or inspect allocation
   success. */

/*
 * Returns: The constructor result, including NULL.
 * Requirements/effects: Calls the optimized xQueueCreateMutex implementation once and returns its
 *   handle. Native code prepares queue-type 1, but this optimized callee consumes no parameter;
 *   the recovered void-parameter signature is retained. The wrapper does not acquire or inspect
 *   the mutex.
 */

void * usb_osal_mutex_create(void)

{
  void *mutex;

  mutex = xQueueCreateMutex();
  return mutex;
}

/* Native entry: 0x42020970. */
/*
 * Medius v3.4.7 — host application; 0x42020970.
 *
 * Forwards semaphore/mutex destruction to the RTOS queue deleter.
 *
 * Calls: vQueueDelete.
 *
 * Called by: usbh_hubport_release.
 *
 * Original function-byte SHA-256:
 * d5ea658e0de3c2342702bdd49ac9ddc28b72e6638ca6e2c87ea0c93bbe166dc7.
 */

/* Forwards semaphore/mutex destruction to the RTOS queue deleter. Calls40381B30(handle) once; no
   local pointer clearing or ownership checks and no additional operations. Boundaries: No local
   handle/pointer validation, ownership tracking or synchronization. RTOS/SDK/heap internals and
   concurrent object lifetime are separate; delegated calls must return for the wrapper to continue.
   Waiters, held-mutex behavior and invalid handles are delegated; this does not establish safe
   concurrent deletion. */

/*
 * handle: Live mutex handle; deletion and concurrent ownership constraints are the caller/RTOS
 *   responsibility.
 * Returns: Nothing.
 * Requirements/effects: Calls the RTOS queue deleter once without clearing the caller handle,
 *   releasing ownership or supplying an extra wait/recovery path.
 */

void usb_osal_mutex_delete(void *handle)

{
  vQueueDelete(handle);
  return;
}

/* Native entry: 0x42020980. */
/*
 * Medius v3.4.7 — host application; 0x42020980.
 *
 * Takes a mutex with the infinite timeout sentinel.
 *
 * Calls: xQueueSemaphoreTake.
 *
 * Called by: medius_host_apply_generation, medius_host_apply_remote_wakeup,
 * medius_host_capture_descriptors_and_probe_controls, medius_host_classify_control_probe,
 * medius_host_control_no_data_retry, medius_host_control_retry,
 * medius_host_verify_device_identity, medius_task_ctrlwk, usbh_control_transfer,
 * usbh_hubport_release.
 *
 * Original function-byte SHA-256:
 * 84989f2d3d6cdc90c4313054bb5c1b9aa3f9957de82c708dab3d4aa41f7cab23.
 */

/* Takes a mutex with the infinite timeout sentinel. Calls xQueueSemaphoreTake(mutex,FFFFFFFF);
   exact result1 maps to0, every other value to-14. No ISR detection. Boundaries: No local
   handle/pointer validation, ownership tracking or synchronization. RTOS/SDK/heap internals and
   concurrent object lifetime are separate; delegated calls must return for the wrapper to continue.
   Can wait indefinitely; no local timeout, ownership check or recovery. */

/*
 * mutex: Live mutex handle in valid task context.
 * Returns: 0 for exact RTOS result 1; -14 otherwise.
 * Requirements/effects: Calls xQueueSemaphoreTake with UINT32_MAX and can wait indefinitely. No
 *   ISR detection, independent timeout, owner validation or recovery occurs here.
 */

int usb_osal_mutex_take(void *mutex)

{
  int take_result;
  int status;

  take_result = xQueueSemaphoreTake(mutex,0xffffffff);
  status = -0xe;
  if (take_result == 1) {
    status = 0;
  }
  return status;
}

/* Native entry: 0x42020998. */
/*
 * Medius v3.4.7 — host application; 0x42020998.
 *
 * Gives a mutex using a nonblocking queue send.
 *
 * Calls: xQueueGenericSend.
 *
 * Called by: medius_host_apply_generation, medius_host_apply_remote_wakeup,
 * medius_host_capture_descriptors_and_probe_controls, medius_host_classify_control_probe,
 * medius_host_control_no_data_retry, medius_host_control_retry,
 * medius_host_verify_device_identity, medius_task_ctrlwk, usbh_control_transfer.
 *
 * Original function-byte SHA-256:
 * c90ce3f3fa9b6fb950b6bc567615d2995d7d1788758fcbc0ce68693bfcb82c43.
 */

/* Gives a mutex using a nonblocking queue send. Calls xQueueGenericSend(mutex,NULL,0,0); exact
   result1 maps to0, every other value to-14. No ISR detection, explicit yield or rollback.
   Boundaries: No local handle/pointer validation, ownership tracking or synchronization.
   RTOS/SDK/heap internals and concurrent object lifetime are separate; delegated calls must return
   for the wrapper to continue. Valid task context/ownership and mutex semantics are delegated; this
   wrapper itself supplies zero wait. */

/*
 * mutex: Live mutex handle owned as required by the RTOS give operation.
 * Returns: 0 for exact RTOS result 1; -14 otherwise.
 * Requirements/effects: Calls xQueueGenericSend(mutex, NULL, 0, 0) once. Supplies zero wait,
 *   performs no ISR check, explicit switch request or rollback, and relies on valid task/ownership
 *   context.
 */

int usb_osal_mutex_give(void *mutex)

{
  int give_result;
  int status;

  give_result = xQueueGenericSend(mutex,(void *)0x0,0,0);
  status = -0xe;
  if (give_result == 1) {
    status = 0;
  }
  return status;
}

/* Native entry: 0x420209b4. */
/*
 * Medius v3.4.7 — host application; 0x420209b4.
 *
 * Requests a queue of four-byte values.
 *
 * Calls: xQueueGenericCreate.
 *
 * Called by: usbh_hub_initialize.
 *
 * Original function-byte SHA-256:
 * 8a8e199064d95f777cd90b39a2527c3d142817bcd2e5c72aee7fa5765fb4188b.
 */

/* Requests a queue of four-byte values. Prepares xQueueGenericCreate arguments (length,4,0), where0
   is the source queue type. The optimized callee ignores this third argument; its existing
   two-argument signature is intentionally retained. Returns the allocation result unchanged.
   Boundaries: No local handle/pointer validation, ownership tracking or synchronization.
   RTOS/SDK/heap internals and concurrent object lifetime are separate; delegated calls must return
   for the wrapper to continue. No local zero-length, multiplication-overflow or allocation-failure
   handling. The wrapper establishes requested item width4, not a successful allocation or ownership
   of any pointed-to payload. */

/*
 * length: Requested number of four-byte queue items, forwarded unchanged.
 * Returns: The queue constructor result, including NULL.
 * Requirements/effects: Calls xQueueGenericCreate(length, 4). Native code also prepares source
 *   queue-type 0, which this optimized callee does not consume. No zero-length, size-overflow or
 *   allocation-failure handling occurs locally. Four-byte item copies do not transfer ownership of
 *   any referenced payload.
 */

void * usb_osal_mq_create(uint length)

{
  void *queue;

  queue = xQueueGenericCreate(length,4);
  return queue;
}

/* Native entry: 0x420209c8. */
/*
 * Medius v3.4.7 — host application; 0x420209c8.
 *
 * Forwards queue deletion without draining or releasing message payloads.
 *
 * Calls: vQueueDelete.
 *
 * Called by: usbh_hub_thread.
 *
 * Original function-byte SHA-256:
 * 25087920d70a4f30cebbf4f2fa61f5d03c375f0fc5ac987d5eae0b200f0cf509.
 */

/* Forwards queue deletion without draining or releasing message payloads. Calls vQueueDelete at
   40381B30 once with original handle; ignores return. Does not receive pending items or free
   objects represented by the queued four-byte values. Boundaries: No local handle/pointer
   validation, ownership tracking or synchronization. RTOS/SDK/heap internals and concurrent object
   lifetime are separate; delegated calls must return for the wrapper to continue. Queue deletion
   and waiter handling remain RTOS responsibilities; this wrapper cannot establish payload
   reclamation. */

/*
 * queue: Live queue handle under the RTOS destruction/lifetime rules.
 * Returns: Nothing.
 * Requirements/effects: Forwards one queue-deletion call. It does not receive pending values, free
 *   pointed-to messages, clear caller state or synchronize concurrent users.
 */

void usb_osal_mq_delete(void *queue)

{
  vQueueDelete(queue);
  return;
}

/* Native entry: 0x420209d8. */
/*
 * Medius v3.4.7 — host application; 0x420209d8.
 *
 * Copies a four-byte value to a queue using task or ISR APIs.
 *
 * Calls: xQueueGenericSendFromISR, _frxt_setup_switch, xPortInIsrContext, xQueueGenericSend.
 *
 * Called by: medius_usbh_hub_interrupt_complete, medius_usbh_hub_shutdown, medius_usbh_notify_hub.
 *
 * Original function-byte SHA-256:
 * 63f076387fb5b3f44c268181a38a67596f22c5611fc0a53029a7b6fb6974fd36.
 */

/* Copies a four-byte value to a queue using task or ISR APIs. Stores value in a local32 word and
   initializes separate local woken=0. Queries ISR context once. Zero calls
   xQueueGenericSend(queue,&value,FFFFFFFF,0); any nonzero calls
   xQueueGenericSendFromISR40381670(queue,&value,&woken,0). Only result1 succeeds. Only ISR success
   with exact woken1 calls yield40381E30. Other nonzero woken values do not yield. All other results
   map to-14. Boundaries: No local handle/pointer validation, ownership tracking or synchronization.
   RTOS/SDK/heap internals and concurrent object lifetime are separate; delegated calls must return
   for the wrapper to continue. Source is a borrowed stack-local four-byte value; queue item size
   must match and the queue API must copy before return. A value may represent a pointer, but
   pointed-to payload is never copied here. Infinite task wait does not guarantee delivery. */

/*
 * queue: Live queue configured for four-byte items.
 * value: Four-byte value copied synchronously by the queue API; a pointed-to payload remains
 *   external.
 * Returns: 0 for exact delegated success 1, otherwise -14.
 * Requirements/effects: Stages value and a zeroed signed 32-bit woken flag. Task context uses an
 *   infinite-wait send; any nonzero ISR-context result selects send-from-ISR. Only ISR success
 *   with woken exactly 1 requests _frxt_setup_switch. Stack output/value slots are borrowed for
 *   the synchronous call. There is no local pointer/payload ownership transfer or rollback.
 */

int medius_usbh_queue_send_value(void *queue,uint value)

{
  int result;
  int higher_priority_woken;
  uint queued_value;

  higher_priority_woken = 0;
  queued_value = value;
  result = xPortInIsrContext();
  if (result == 0) {
    result = xQueueGenericSend(queue,&queued_value,0xffffffff,0);
    if (result == 1) {
      return 0;
    }
  }
  else {
    result = xQueueGenericSendFromISR(queue,&queued_value,&higher_priority_woken,0);
    if (result == 1) {
      if (higher_priority_woken == 1) {
        _frxt_setup_switch();
      }
      return 0;
    }
  }
  return -0xe;
}

/* Native entry: 0x42020a2c. */
/*
 * Medius v3.4.7 — host application; 0x42020a2c.
 *
 * Receives a four-byte queue value with context-specific timeout and yield behavior.
 *
 * Calls: xQueueReceiveFromISR, _frxt_setup_switch, xPortInIsrContext, xQueueReceive.
 *
 * Called by: usbh_hub_thread.
 *
 * Original function-byte SHA-256:
 * b6a6fa1e7d227c5544e861fa6ebb1f3276ddf9eca48e76793b8191f5ba04ca8f.
 */

/* Receives a four-byte queue value with context-specific timeout and yield behavior. Initializes
   local32 woken=0 and queries context once. Nonzero context calls
   xQueueReceiveFromISR40381A78(queue,value,&woken), ignoring timeout entirely. Zero context calls
   xQueueReceive(queue,value,ticks), with FFFFFFFF passed unchanged; otherwise Finite timeout
   conversion is floor(unsigned32(milliseconds*1000)/1000), using the original reciprocal-multiply
   sequence. Multiplication wraps before division:4294967 becomes4294967 ticks,4294968 becomes0,
   andFFFFFFFE becomes4294965. This is not saturating conversion. Exact result1 returns0; other
   results return-14. Only ISR success and exact woken1 invokes yield40381E30. Boundaries: No local
   handle/pointer validation, ownership tracking or synchronization. RTOS/SDK/heap internals and
   concurrent object lifetime are separate; delegated calls must return for the wrapper to continue.
   Does not validate output capacity or queue item size. Output memory is delegated directly, not
   staged; any delegated output changes survive even failure. No pointed-to payload copy/free, no
   rollback. */

/*
 * queue: Live queue with four-byte item size.
 * value: Writable four-byte destination supplied directly to the RTOS receive.
 * milliseconds: Task timeout: UINT32_MAX sentinel or finite wrapping conversion; ignored on the
 *   ISR path.
 * Returns: 0 for exact delegated result 1, otherwise -14.
 * Requirements/effects: Queries context once. Task receive uses unsigned32(milliseconds*1000)/1000
 *   for finite input and passes the infinite sentinel unchanged. ISR receive supplies a zeroed
 *   signed woken flag and requests a switch only on success with woken exactly 1. Destination
 *   changes from a failing delegated call are retained. No output capacity, queue-width or payload
 *   ownership check occurs.
 */

int usb_osal_mq_recv(void *queue,uint *value,uint milliseconds)

{
  int result;
  int higher_priority_woken;

  higher_priority_woken = 0;
  result = xPortInIsrContext();
  if (result == 0) {
    if (milliseconds == 0xffffffff) {
      result = xQueueReceive(queue,value,0xffffffff);
    }
    else {
      result = xQueueReceive(queue,value,(milliseconds * 1000) / 1000);
    }
    if (result != 1) {
      return -0xe;
    }
  }
  else {
    result = xQueueReceiveFromISR(queue,value,&higher_priority_woken);
    if (result != 1) {
      return -0xe;
    }
    if (higher_priority_woken == 1) {
      _frxt_setup_switch();
    }
  }
  return 0;
}

/* Native entry: 0x42020a98. */
/*
 * Medius v3.4.7 — host application; 0x42020a98.
 *
 * Allocates a twenty-byte timer wrapper and registers an ESP task-dispatched callback.
 *
 * Calls: vPortFree, esp_timer_create, pvPortMalloc.
 *
 * Called by: medius_usbh_hub_attach.
 *
 * Original function-byte SHA-256:
 * 0e969f732e1a0640e7073b064dbb1595e76c93b1e22d5143f61adfca4f4a46f4.
 */

/* Allocates a twenty-byte timer wrapper and registers an ESP task-dispatched callback. Calls
   pvPortMalloc(20). NULL immediately returns NULL with no SDK call/free. On success stores
   handler+0,argument+4,periodic low8+8,milliseconds+12; bytes9..11 remain allocator contents and
   handle+16 is left to SDK output. Builds stack-local ESP timer args:
   callback42020B6C,argument=wrapper,dispatch0,name unchanged,skip_unhandled_events byte1. Calls
   esp_timer_create(&args,&wrapper->timer). Exact SDK0 returns wrapper; every other result calls
   vPortFree(wrapper) then returns NULL, without stopping/deleting any handle the failed call might
   have written. Boundaries: No local handle/pointer validation, ownership tracking or
   synchronization. RTOS/SDK/heap internals and concurrent object lifetime are separate; delegated
   calls must return for the wrapper to continue. No callback/name/interval validation, no
   allocation zero-fill and no normalization of raw periodic bytes beyond low8. The SDK must
   consume/copy stack config synchronously. Timer owns its wrapper; callback argument/name ownership
   is external. Successful creation does not start timer. */

/*
 * name: Borrowed timer name retained as needed by the SDK.
 * milliseconds: Stored 32-bit interval; creation does not start the timer.
 * handler: Non-NULL callback required for a valid later dispatch.
 * argument: Borrowed argument retained until callback use ends.
 * periodic: Raw byte: zero selects one-shot, any nonzero selects periodic on start.
 * Returns: A newly allocated 20-byte wrapper on exact esp_timer_create success 0, otherwise NULL.
 * Requirements/effects: Allocates through pvPortMalloc, stores callback/argument/periodic/interval
 *   and passes one 20-byte create-argument object to esp_timer_create. Registers
 *   medius_usb_osal_timer_dispatch with task dispatch and skip_unhandled_events=1. Padding bytes
 *   are not initialized. Allocation failure returns immediately; SDK failure frees the wrapper
 *   without separate cleanup of any handle written by that failed call. No callback/name/interval
 *   validation occurs. Each wrapper owns a logical software timer instance; task-dispatched
 *   callbacks share the ESP timer task and underlying alarm service. Callback timing depends on
 *   interrupt latency, scheduler load, locks and preceding callbacks, so punctual delivery is not
 *   guaranteed.
 */

MediusUsbOsalTimer *usb_osal_timer_create(char *name,uint milliseconds,
    MediusUsbTimerCallback handler,void *argument,uchar periodic)
{
    MediusUsbOsalTimer *timer = pvPortMalloc(20);
    if (timer == NULL)
        return NULL;
    EspTimerCreateArgs create_args;
    create_args.skip_unhandled_events = 1;
    create_args.dispatch = 0;
    create_args.name = name;
    create_args.argument = timer;
    create_args.callback = medius_usb_osal_timer_dispatch;
    volatile MediusUsbOsalTimer *published = timer;
    published->handler = handler;
    published->argument = argument;
    published->periodic = periodic;
    published->milliseconds = milliseconds;
    if (esp_timer_create(&create_args,&timer->timer) == 0)
        return timer;
    vPortFree(timer);
    return NULL;
}

/* Native entry: 0x42020ae0. */
/*
 * Medius v3.4.7 — host application; 0x42020ae0.
 *
 * Stops/deletes the SDK timer then frees the wrapper regardless of errors.
 *
 * Calls: vPortFree, esp_timer_delete, esp_timer_stop.
 *
 * Called by: medius_usbh_hub_disconnect.
 *
 * Original function-byte SHA-256:
 * a7a6ac987e40d168ec26e3fa476a26f09b5d057b4bd49ced20c92d118b78b24b.
 */

/* Stops/deletes the SDK timer then frees the wrapper regardless of errors. Loads timer->handle and
   calls esp_timer_stop. Rereads handle from+16 and calls esp_timer_delete, then vPortFree(wrapper).
   Both SDK statuses are ignored; later calls occur even after failure. Does not clear wrapper
   fields or synchronize callbacks. Boundaries: No local handle/pointer validation, ownership
   tracking or synchronization. RTOS/SDK/heap internals and concurrent object lifetime are separate;
   delegated calls must return for the wrapper to continue. Stop/delete failure can leave delegated
   lifecycle unresolved while wrapper is freed. Callback quiescence and double-delete prevention
   must be established elsewhere. No NULL wrapper guard. */

/*
 * timer: Live exclusively owned 20-byte wrapper; callback quiescence must be established by the
 *   caller/lifecycle.
 * Returns: Nothing.
 * Requirements/effects: Calls esp_timer_stop, reloads the handle, calls esp_timer_delete, then
 *   frees the wrapper. Both statuses are ignored, so free occurs even after stop/delete failure.
 *   Fields are not cleared and no NULL guard or callback synchronization occurs. Caller must
 *   prevent stale dispatch or repeated deletion.
 */

void usb_osal_timer_delete(MediusUsbOsalTimer *timer)
{
    const volatile MediusUsbOsalTimer *live = timer;
    (void)esp_timer_stop(live->timer);
    (void)esp_timer_delete(live->timer);
    vPortFree(timer);
}

/* Native entry: 0x42020afc. */
/*
 * Medius v3.4.7 — host application; 0x42020afc.
 *
 * Stops the timer then starts once or periodically using a full64-bit microsecond interval.
 *
 * Calls: esp_timer_start_once, esp_timer_start_periodic, esp_timer_stop.
 *
 * Called by: medius_usbh_hub_attach, medius_usbh_hub_interrupt_complete, usbh_hub_thread.
 *
 * Original function-byte SHA-256:
 * b36264ba87b7ccec958b6d3720565959dabc189abd24b9b42cd8fa4d1f3ece62.
 */

/* Stops the timer then starts once or periodically using a full64-bit microsecond interval. Loads
   handle+16 and calls esp_timer_stop, ignoring result. After stop returns, reloads milliseconds,
   periodic byte and handle. Computes unsigned64(milliseconds)*1000 with low multiply and unsigned
   high multiply, preserving all bits. Nonzero periodic byte calls esp_timer_start_periodic; zero
   calls esp_timer_start_once. Xtensa call args are handle in a10, unused alignment slota11,
   interval low/high in a12/a13. Both start statuses are ignored; stop failure does not prevent
   start. Boundaries: No local handle/pointer validation, ownership tracking or synchronization.
   RTOS/SDK/heap internals and concurrent object lifetime are separate; delegated calls must return
   for the wrapper to continue. No finite-time overflow here:FFFFFFFF milliseconds
   becomes4294967295000 microseconds. Zero interval reaches SDK. Fields can change during stop; they
   are not an atomic snapshot. No guarantee of successful arming, elapsed time or callback delivery.
    */

/*
 * timer: Live wrapper with valid SDK timer; field changes must obey the surrounding lifecycle
 *   rules.
 * Returns: Nothing; stop and start results are ignored.
 * Requirements/effects: Stops the current handle, then reloads milliseconds, periodic selector and
 *   handle. Uses the full 64-bit product milliseconds*1000 for the microsecond interval;
 *   UINT32_MAX becomes 4294967295000 and does not wrap to 32 bits. Zero interval is forwarded.
 *   Zero periodic selects start_once, nonzero selects start_periodic, even if stop failed. Each
 *   wrapper owns a logical software timer instance; task-dispatched callbacks share the ESP timer
 *   task and underlying alarm service. Callback timing depends on interrupt latency, scheduler
 *   load, locks and preceding callbacks, so punctual delivery is not guaranteed.
 */

void usb_osal_timer_start(MediusUsbOsalTimer *timer)
{
    const volatile MediusUsbOsalTimer *live = timer;
    (void)esp_timer_stop(live->timer);
    uint milliseconds = live->milliseconds;
    uchar periodic = live->periodic;
    EspTimer *handle = live->timer;
    ulonglong interval_us = (ulonglong)milliseconds * 1000ULL;
    if (periodic == 0)
        (void)esp_timer_start_once(handle,interval_us);
    else
        (void)esp_timer_start_periodic(handle,interval_us);
}

/* Native entry: 0x42020b2c. */
/*
 * Medius v3.4.7 — host application; 0x42020b2c.
 *
 * Delays by a wrapping converted tick count without an infinite sentinel.
 *
 * Calls: vTaskDelay.
 *
 * Called by: FUN_4201fef4, medius_usbh_cancel_urb, medius_usbh_hub_attach, usb_hc_init,
 * usbh_enumerate, usbh_hub_thread, usbh_roothub_control.
 *
 * Original function-byte SHA-256:
 * 39d020392b4ca4e6b403b183fb7ccfd337d80b7a95e4c53e98626c61f8f1897f.
 */

/* Delays by a wrapping converted tick count without an infinite sentinel. Always computes
   floor(unsigned32(milliseconds*1000)/1000) and calls vTaskDelay40382A7C once. Unlike
   sem_take/mq_recv there is no FFFFFFFF special case: that value becomes4294966 ticks;4294968
   becomes0. Boundaries: No local handle/pointer validation, ownership tracking or synchronization.
   RTOS/SDK/heap internals and concurrent object lifetime are separate; delegated calls must return
   for the wrapper to continue. Tick rate, actual scheduling delay and context validity remain RTOS
   concerns. A zero converted tick request is still forwarded. */

/*
 * milliseconds: Finite input converted by unsigned32 multiply before divide, including UINT32_MAX.
 * Returns: Nothing; returns after vTaskDelay returns.
 * Requirements/effects: Always forwards unsigned32(milliseconds*1000)/1000 ticks once. There is no
 *   infinite sentinel: 4294968 maps to zero, UINT32_MAX maps to 4294966. Requires valid scheduler
 *   context. Scheduler/preemption and tick handling determine actual delay; this wrapper
 *   guarantees no wall-clock duration.
 */

void usb_osal_msleep(uint milliseconds)

{
  vTaskDelay((milliseconds * 1000) / 1000);
  return;
}

/* Native entry: 0x42020b4c. */
/*
 * Medius v3.4.7 — host application; 0x42020b4c.
 *
 * Forwards a full32 allocation size to the C heap allocator.
 *
 * Calls: malloc.
 *
 * Called by: medius_host_parse_configuration, usbh_enumerate.
 *
 * Original function-byte SHA-256:
 * 4750d5671ee2f099ef339a38b6dff9a9c652b80c0bf0dcfcc816a35c1e78d38c.
 */

/* Forwards a full32 allocation size to the C heap allocator. Calls malloc4038B1A0(size) once and
   returns the full32 result unchanged. No zero-fill, retry or extra allocation metadata here.
   Boundaries: No local handle/pointer validation, ownership tracking or synchronization.
   RTOS/SDK/heap internals and concurrent object lifetime are separate; delegated calls must return
   for the wrapper to continue. Heap limits/alignment/zero-size semantics and allocation failure are
   delegated. */

/*
 * size: Full 32-bit allocation size forwarded unchanged.
 * Returns: The C allocator result, including NULL.
 * Requirements/effects: Calls malloc once. No zero-fill, retry, wrapper metadata or size
 *   validation occurs. Heap failure/alignment/zero-size behavior follows the reviewed allocator;
 *   allocated storage ownership passes to the caller.
 */

void * usb_osal_malloc(uint size)

{
  void *allocation;

  allocation = (void *)malloc(size);
  return allocation;
}

/* Native entry: 0x42020b5c. */
/*
 * Medius v3.4.7 — host application; 0x42020b5c.
 *
 * Forwards a pointer to the C heap deallocator.
 *
 * Calls: free.
 *
 * Called by: medius_host_parse_configuration, medius_usbh_retire_descriptor_storage,
 * usbh_enumerate.
 *
 * Original function-byte SHA-256:
 * c623938361d3a93fdfc03ca28c948262216b0ca465de3dfff5d9e2301c388296.
 */

/* Forwards a pointer to the C heap deallocator. Calls free4038B1D4(pointer) once and ignores any
   returned register value. No pointer clearing or additional reclamation. Boundaries: No local
   handle/pointer validation, ownership tracking or synchronization. RTOS/SDK/heap internals and
   concurrent object lifetime are separate; delegated calls must return for the wrapper to continue.
   Valid allocation provenance and double-free prevention are caller responsibilities. */

/*
 * pointer: NULL or a live allocation with valid C-heap provenance, released exactly once.
 * Returns: Nothing.
 * Requirements/effects: Calls free once. Does not clear the caller pointer or release separately
 *   referenced objects. Concurrent use and double-free prevention remain caller responsibilities.
 */

void usb_osal_free(void *pointer)

{
  free(pointer);
  return;
}

/* Native entry: 0x42020b6c. */
/*
 * Medius v3.4.7 — host application; 0x42020b6c.
 *
 * Dispatches the stored timer callback with its stored argument.
 *
 * Indirect callback: timer->handler(timer->argument).
 *
 * Original function-byte SHA-256:
 * 603fcb35bb05b178da9d95350150cf8e0d365f48511748219053706e5c9b4338.
 */

/* Dispatches the stored timer callback with its stored argument. Loads callback pointer first, then
   argument; calls callback(argument) with no NULL check and ignores returned register value. No
   local stores, freeing, rearming or state change. Boundaries: No local handle/pointer validation,
   ownership tracking or synchronization. RTOS/SDK/heap internals and concurrent object lifetime are
   separate; delegated calls must return for the wrapper to continue. A stale wrapper or NULL
   handler reaches an invalid access/call. Constructor registers this trampoline in ESP task-dispatch mode. The hub attachment caller
   supplies medius_usbh_hub_poll with the external-hub state; live wrapper and callback-argument
   lifetime are required until dispatch completes. */

/*
 * timer_argument: Live wrapper with a valid handler and borrowed argument for the duration of
 *   callback execution.
 * Returns: Nothing after the handler returns.
 * Requirements/effects: Reads the stored handler first and argument second, then invokes
 *   handler(argument) once. No NULL check, free, rearm or state update occurs locally. Known hub
 *   attachment registers medius_usbh_hub_poll with the external-hub context through this adapter.
 *   Each wrapper owns a logical software timer instance; task-dispatched callbacks share the ESP
 *   timer task and underlying alarm service. Callback timing depends on interrupt latency,
 *   scheduler load, locks and preceding callbacks, so punctual delivery is not guaranteed.
 */

void medius_usb_osal_timer_dispatch(void *timer_argument)

{
  const volatile MediusUsbOsalTimer *stored = timer_argument;
  MediusUsbTimerCallback handler = stored->handler;
  void *argument = stored->argument;
  handler(argument);
  return;
}

