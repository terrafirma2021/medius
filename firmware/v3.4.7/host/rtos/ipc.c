/* Medius v3.4.7 host — rtos/ipc.c.
 * Recovered C and native assembly, grouped for source navigation.
 * Original entry addresses, firmware-byte hashes and function comments follow.
 */

#include "../include/types.h"

/* Native entry: 0x40375f3c. */
/*
 * Medius v3.4.7 — host application; 0x40375f3c.
 * Instruction-checked recovered C.
 * Original function-byte SHA-256:
 * e2322a8a3d51d27e6e9e25dc1d030648141a479174ed9085f10a6a99b2033468.
 */

/* Dedicated IPC task entry: argument encodes its CPU0/1 slot and must match
 * current PRID bit13 or assert. Initialize that CPU's IPC interrupt, then wait
 * indefinitely on notification index0, clearing the notification count on take.
 * Run ready nonblocking callback first: check pointer, reload it for invocation,
 * sample argument, invoke, then clear ready byte BEFORE clearing pointer.
 * For ordinary work, cache callback, argument and wait mode BEFORE clearing its
 * published pointer; sample acknowledgement AFTER that clear. Mode1 gives ack
 * before callback (started); mode2 calls before ack (finished); other mode aborts.
 * Ignore semaphore-give results. Process at most one ordinary slot per wake;
 * pointer absence returns to notification wait. No worker-side submission mux,
 * callback ownership transfer, execution deadline or exception recovery. */
void ipc_task(void *argument)
{
    unsigned int core = (unsigned int)argument;
    if (core != ((xtensa_read_prid() >> 13) & 1U))
        __assert_func(0,0,0,0);
    esp_ipc_isr_init();
    IpcDispatchState *state = IPC_DISPATCH_STATE;
    for (;;) {
        (void)ulTaskGenericNotifyTake(0,1,0xffffffffU);
        memw();
        if (state->nonblocking_ready[core]) {
            memw();
            if (state->nonblocking_callbacks[core]) {
                memw();
                IpcCallback callback = state->nonblocking_callbacks[core];
                memw();
                void *callback_argument = state->nonblocking_arguments[core];
                callback(callback_argument);
                memw();
                state->nonblocking_ready[core] = 0;
                memw();
                state->nonblocking_callbacks[core] = NULL;
            }
        }
        memw();
        if (!state->callbacks[core])
            continue;
        memw();
        IpcCallback callback = state->callbacks[core];
        memw();
        void *callback_argument = state->arguments[core];
        memw();
        unsigned int wait_mode = state->wait_mode[core];
        memw();
        state->callbacks[core] = NULL;
        RtosQueue *ack = state->acknowledgements[core];
        if (wait_mode == 1) {
            (void)xQueueGenericSend(ack,NULL,0,0);
            callback(callback_argument);
        } else if (wait_mode == 2) {
            callback(callback_argument);
            (void)xQueueGenericSend(ack,NULL,0,0);
        } else {
            abort();
        }
    }
}

/* Native entry: 0x4037f974. */
/*
 * Medius v3.4.7 — host application; 0x4037f974.
 *
 * Asserts CPU0/1, clears and writes the two split RTC stall fields to the encoded0x86 pattern for
 * the chosen CPU. Writes OPTIONS0 then SW_CPU_STALL using separate read/modify/write cycles. It
 * does not independently reject the current CPU or wait for a stall acknowledgement.
 *
 * Calls: __assert_func.
 *
 * Called by: rtc_brownout_isr_handler, FUN_420030e0, esp_restart_noos.
 *
 * Original function-byte SHA-256:
 * 42f135ff5ecf3b650006f6edd659e2cd6a6441d4b746c8e52d3d9017ecf7785c.
 */

/* Reference: ESP-IDF v5.4.4 components/esp_hw_support/cpu.c and
   components/hal/esp32s3/include/hal/cpu_utility_ll.h. */

/*
 * cpu: CPU0 or CPU1; any other value asserts.
 * Returns: Nothing.
 * Requirements/effects: Writes split RTC stall fields to the encoded0x86 pattern with separate RMW
 *   operations. Does not reject the current CPU or wait for acknowledgement; caller must choose
 *   the intended target.
 */

void esp_cpu_stall(int cpu)
{
  if ((uint)cpu > 1U) __assert_func(0,0,0,0);
  uint options_clear_mask = cpu == 0 ? 0xfffffff3U : 0xfffffffcU;
  uint options_pattern = cpu == 0 ? 8U : 2U;
  uint stall_clear_mask = cpu == 0 ? 0x03ffffffU : 0xfc0fffffU;
  uint stall_pattern = cpu == 0 ? 0x84000000U : 0x02100000U;

  memw();
  uint value = RTC_OPTIONS0_REGISTER;
  memw();
  RTC_OPTIONS0_REGISTER = value & options_clear_mask;
  memw();
  value = RTC_OPTIONS0_REGISTER;
  memw();
  RTC_OPTIONS0_REGISTER = value | options_pattern;
  memw();
  value = RTC_CPU_STALL_REGISTER;
  memw();
  RTC_CPU_STALL_REGISTER = value & stall_clear_mask;
  memw();
  value = RTC_CPU_STALL_REGISTER;
  memw();
  RTC_CPU_STALL_REGISTER = value | stall_pattern;
}

/* Native entry: 0x4037f9e0. */
/*
 * Medius v3.4.7 — host application; 0x4037f9e0.
 *
 * Asserts CPU0/1 and clears both split RTC stall fields for that CPU. Preserves separate OPTIONS0
 * and SW_CPU_STALL read/modify/write operations; does not reset CPU state or wait for an
 * acknowledgement.
 *
 * Calls: __assert_func.
 *
 * Called by: esp_restart_noos, firmware_entry.
 *
 * Original function-byte SHA-256:
 * c4ff3af9072cb76825b57d2a8462bef18014c40021f3205f924818d8f3d136e9.
 */

/* Reference: ESP-IDF v5.4.4 components/esp_hw_support/cpu.c and
   components/hal/esp32s3/include/hal/cpu_utility_ll.h. */

/*
 * cpu: CPU0 or CPU1; any other value asserts.
 * Returns: Nothing.
 * Requirements/effects: Clears both split RTC stall fields while preserving the other register
 *   bits. Does not reset the CPU or wait for acknowledgement.
 */

void esp_cpu_unstall(int cpu)
{
  if ((uint)cpu > 1U) __assert_func(0,0,0,0);
  memw();
  uint value = RTC_OPTIONS0_REGISTER;
  uint options_clear_mask = cpu == 0 ? 0xfffffff3U : 0xfffffffcU;
  uint stall_clear_mask = cpu == 0 ? 0x03ffffffU : 0xfc0fffffU;
  memw();
  RTC_OPTIONS0_REGISTER = value & options_clear_mask;
  memw();
  value = RTC_CPU_STALL_REGISTER;
  memw();
  RTC_CPU_STALL_REGISTER = value & stall_clear_mask;
}

/* Native entry: 0x42003608. */
/*
 * Medius v3.4.7 — host application; 0x42003608.
 *
 * Submits a callback to the selected CPU IPC task using caller-priority propagation, a submission mutex and an acknowledgement semaphore. Runs recursive calls directly in that same IPC task; wait mode 2 acknowledges completion.
 *
 * Calls: uxTaskPriorityGet, vTaskPrioritySet, xTaskGetCurrentTaskHandle, xTaskGenericNotify, xQueueGenericSend,
 * xQueueSemaphoreTake.
 *
 * Called by: esp_ipc_call_blocking.
 *
 * Indirect call: recursive submissions invoke callback(argument) in the current IPC task.
 *
 * Original function-byte SHA-256:
 * 2520320744dc45020cbf48858281fda68a73b9c44e9ca5ac1b8e21cc25ba74e1.
 */

/* Submits a callback to the selected CPU IPC task using caller-priority propagation, a submission mutex and an acknowledgement semaphore. Runs recursive calls directly in that same IPC task; wait mode 2 acknowledges completion.
   SDK match: ESP-IDF v5.4.4 components/esp_system/esp_ipc.c. */

/*
 * cpu_id: Validated CPU0 orCPU1 with initialized IPC task/semaphores. This internal body does not
 *   bounds-check.
 * callback: Non-NULL callback invoked with argument in the target IPC task.
 * argument: Opaque callback context; lifetime must cover callback execution.
 * wait_for: IPC acknowledgement policy; public blocking caller passes2 for completion.
 * Returns: 0 on normal completion; semaphore wait results are not checked.
 * Requirements/effects: Task-context internal path. Recursive calls from the target IPC task
 *   invoke the callback directly. Otherwise propagates caller priority, serializes publication
 *   with a submission mutex, notifies the target, waits indefinitely for acknowledgement, then
 *   releases the mutex. Waiting-for-start mode need not mean the callback has finished. Provides
 *   no timeout or cancellation.
 */

int esp_ipc_call_and_wait(uint cpu_id,IpcCallback callback,void *argument,uint wait_for)
{
  IpcDispatchState *state = IPC_DISPATCH_STATE;
  RtosTask *current_task = xTaskGetCurrentTaskHandle();
  RtosTask *volatile *task_slot = &state->tasks[cpu_id];
  RtosTask *target_task = *task_slot;
  if (current_task == target_task) {
    callback(argument);
    return 0;
  }

  uint priority = uxTaskPriorityGet(current_task);
  target_task = *task_slot;
  uint target_priority = uxTaskPriorityGet(target_task);
  if (target_priority < priority) {
    target_task = *task_slot;
    vTaskPrioritySet(target_task,priority);
  }
  RtosQueue *mutex = state->submission_mutexes[cpu_id];
  (void)xQueueSemaphoreTake(mutex,0xffffffffU);
  target_task = *task_slot;
  vTaskPrioritySet(target_task,priority);
  memw();
  state->arguments[cpu_id] = argument;
  target_task = *task_slot;
  memw();
  state->wait_mode[cpu_id] = wait_for;
  memw();
  state->callbacks[cpu_id] = callback;
  (void)xTaskGenericNotify(target_task,0,0,2,0);
  RtosQueue *acknowledgement = state->acknowledgements[cpu_id];
  (void)xQueueSemaphoreTake(acknowledgement,0xffffffffU);
  mutex = state->submission_mutexes[cpu_id];
  (void)xQueueGenericSend(mutex,0,0,0);
  return 0;
}

/* Native entry: 0x42003744. */
/*
 * Medius v3.4.7 — host application; 0x42003744.
 *
 * Validates the target CPU/task and running scheduler, then submits an IPC callback with wait-for-completion mode 2. Returns 0, invalid argument 0x102 or invalid state 0x103.
 *
 * Calls: xTaskGetSchedulerState, esp_ipc_call_and_wait.
 *
 * Called by: esp_intr_free.
 *
 * Original function-byte SHA-256:
 * f1af7df1db14bf2cf876b05cc02fcd9328cae73570f7a43ca2f2f5178bb560a6.
 */

/* Validates the target CPU/task and running scheduler, then submits an IPC callback with wait-for-completion mode 2. Returns 0, invalid argument 0x102 or invalid state 0x103.
   SDK match: ESP-IDF v5.4.4 components/esp_system/esp_ipc.c. */

/*
 * cpu_id: Target CPU0 orCPU1.
 * callback: Non-NULL callback required; not explicitly validated by this wrapper.
 * argument: Context kept valid until the callback returns.
 * Returns: 0 after completion,0x102 for invalid CPU,0x103 for missing IPC task or scheduler not
 *   running.
 * Requirements/effects: Task context. Checks target and scheduler before submitting completion-
 *   wait mode2. Can wait indefinitely; recursive target-IPC calls execute directly.
 */

int esp_ipc_call_blocking(uint cpu_id,IpcCallback callback,void *argument)
{
  if (cpu_id >= 2U) return 0x102;
  IpcDispatchState *state = IPC_DISPATCH_STATE;
  if (state->tasks[cpu_id] == 0) return 0x103;
  int scheduler_state = xTaskGetSchedulerState();
  if (scheduler_state != 2) return 0x103;
  (void)esp_ipc_call_and_wait(cpu_id,callback,argument,2);
  return 0;
}

/* Native entry: 0x4200377c. */
/*
 * Medius v3.4.7 — host application; 0x4200377c.
 *
 * Atomically claims the selected CPU nonblocking callback slot, publishes the argument and notifies its IPC task. Uses the ISR-safe notification path from interrupts; returns -1 when the previous slot is occupied.
 *
 * Calls: vTaskPrioritySet, xTaskGetSchedulerState, xTaskGenericNotify, vTaskGenericNotifyGiveFromISR,
 * esp_cpu_compare_and_set, xPortInIsrContext.
 *
 * Called by: spi_flash_disable_interrupts_caches_and_other_cpu.
 *
 * Original function-byte SHA-256:
 * 4074cc9653f14a8b3693fe07bd8f159219d3009fa711e7266afea33661f0849a.
 */

/* Atomically claims the selected CPU nonblocking callback slot, publishes the argument and notifies its IPC task. Uses the ISR-safe notification path from interrupts; returns -1 when the previous slot is occupied.
   SDK match: ESP-IDF v5.4.4 components/esp_system/esp_ipc.c. */

/*
 * cpu_id: Target CPU0 orCPU1 with an initialized IPC task.
 * callback: Non-NULL function pointer required for the empty-slot protocol; this body does not
 *   reject NULL.
 * argument: Opaque context that remains valid until the asynchronously submitted callback
 *   finishes.
 * Returns: 0 when published, -1 when the callback slot cannot be claimed,0x102 for invalid CPU or
 *   absent task,0x103 when targeting this CPU while its scheduler is not running.
 * Requirements/effects: Claims the callback slot using compare-and-exchange, then publishes
 *   argument and ready flag with MEMWs. ISR callers use notify-give without waiting; task callers
 *   raise target priority to24 and notify. No completion acknowledgement, timeout or cancellation
 *   is supplied. Remote-target calls do not apply the same current-CPU scheduler-state check.
 */

int esp_ipc_call_nonblocking(uint cpu_id,IpcCallback callback,void *argument)
{
  if (cpu_id >= 2U) return 0x102;
  IpcDispatchState *state = IPC_DISPATCH_STATE;
  if (state->tasks[cpu_id] == 0) return 0x102;
  uint current_core = (xtensa_read_prid() >> 13) & 1U;
  if (cpu_id == current_core && xTaskGetSchedulerState() != 2) return 0x103;
  bool claimed = esp_cpu_compare_and_set(
      (volatile uint *)&state->nonblocking_callbacks[cpu_id],0,(uint)callback);
  if (!claimed) return -1;
  memw();
  state->nonblocking_arguments[cpu_id] = argument;
  memw();
  state->nonblocking_ready[cpu_id] = 1;
  int in_isr = xPortInIsrContext();
  RtosTask *target_task = state->tasks[cpu_id];
  if (in_isr != 0) {
    vTaskGenericNotifyGiveFromISR(target_task,0,0);
  } else {
    vTaskPrioritySet(target_task,24);
    target_task = state->tasks[cpu_id];
    (void)xTaskGenericNotify(target_task,0,0,2,0);
  }
  return 0;
}

/* Native entry: 0x42003294. */
/*
 * Medius v3.4.7 — host application; 0x42003294.
 * Instruction-checked recovered C.
 * Original function-byte SHA-256:
 * 5611024417287ea327585f23b7b560836e481b93d0d2c0027aaef593e93ecf3a.
 */

/* Select CPU from PRID bit13 and initialize that CPU's IPC interrupt routing.
 * On CPU1 only, MEMW then publish stall state RUNNING1; CPU0 leaves it untouched.
 * No wait for the other CPU, semaphore creation, callback invocation or status. */
void esp_ipc_isr_init(void)
{
    unsigned int core = (xtensa_read_prid() >> 13) & 1U;
    esp_ipc_isr_port_init((int)core);
    if (core != 0) {
        memw();
        IPC_ISR_STALL_STATE = 1;
    }
}

/* Native entry: 0x420032b4. */
/*
 * Medius v3.4.7 — host application; 0x420032b4.
 * Instruction-checked recovered C.
 * Original function-byte SHA-256:
 * 7280f4e3e21cd7b06f11c105154ef8d21b46f7df60bcf740737168a9bbbc4407.
 */

/* Disable current CPU interrupt28, route source81+core to interrupt28 on the
 * requested CPU, then re-enable current CPU interrupt28. Caller supplies the
 * matching valid CPU (the wrapper uses PRID bit13). No independent bounds check,
 * prior-enable restoration, handler installation, allocation or return status.
 * Source addition retains native32 wrap for out-of-contract core values. */
void esp_ipc_isr_port_init(int core)
{
    esp_intr_disable_source(28);
    intr_matrix_set(core,(int)((unsigned int)core + 81U),28);
    esp_intr_enable_source(28);
}
