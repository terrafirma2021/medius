/* Medius v3.4.7 device — interprocessor callbacks and CPU stall control. */
#include "../include/types.h"

/* Native entry: 0x40376340. */
/* Original function-byte SHA-256:
 * 470a84be0cafe9086a84b47e6314cbd9f5726b489b11c03d281f3724de89383c. */
/*
 * argument: CPU slot encoded in the 32-bit pointer value; must equal PRID bit 13.
 * Returns: Never normally; assertion failure and an invalid wait mode do not return.
 *
 * Asserts a core mismatch with four zero arguments, then initializes this CPU's
 * IPC interrupt. The dedicated worker waits on notification index 0 with
 * clear-on-take=1 and UINT32_MAX ticks, ignoring the returned count.
 *
 * Processes ready nonblocking work first. Reads the raw ready BYTE, checks its
 * callback WORD, reloads that callback for invocation, then samples its argument.
 * After return, clears ready before clearing the callback pointer. A nonzero
 * ready byte with a NULL callback is left unchanged. Ordinary work is checked
 * afterwards: reload callback, argument and full wait-mode WORD, clear its
 * published callback pointer, then sample the acknowledgement handle. Mode 1
 * gives acknowledgement before the callback; mode 2 gives it after the callback.
 * Any other mode aborts. Semaphore-give results are ignored.
 *
 * Preserves the native MEMWs and repeated loads. Processes at most one ordinary
 * request per wake. Creates no task/semaphore here, takes no submission mux and
 * supplies no callback lifetime ownership, execution deadline, rollback, or
 * recovery if a callback fails to return. Required live per-core state and
 * serialization come from initialization and the submission protocol.
 */
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

/* Native entry: 0x403841ac. */
/* Original function-byte SHA-256:
 * 577f64a6bf1da178b2fb165b0726aa57f6e1f4d9695e547bf9d419b1061b1530. */
/*
 * cpu: Signed WORD selecting CPU 0 or 1; any other bit pattern asserts.
 * Returns: No value if execution reaches the epilogue.
 *
 * Programs the split RTC stall code 0x86. For the selected CPU, clears its C0
 * field in OPTIONS0, freshly rereads and sets C0=2, clears its C1 field in
 * SW_CPU_STALL, then freshly rereads and sets C1=0x21. Each of the four separate
 * read/modify/write pairs preserves unrelated bits and retains both native MEMWs.
 * CPU0 uses C0 shift 2/C1 shift 26; CPU1 uses shifts 0/20.
 *
 * Does not reject the current CPU, lock either register, restore prior fields,
 * reset CPU state, or wait for acknowledgement. Caller chooses the target and
 * coordinates competing register writers; physical stall effects are hardware.
 */
void esp_cpu_stall(int cpu)
{
  if ((unsigned int)cpu > 1U) __assert_func(0,0,0,0);
  unsigned int options_clear_mask = cpu == 0 ? 0xfffffff3U : 0xfffffffcU;
  unsigned int options_pattern = cpu == 0 ? 8U : 2U;
  unsigned int stall_clear_mask = cpu == 0 ? 0x03ffffffU : 0xfc0fffffU;
  unsigned int stall_pattern = cpu == 0 ? 0x84000000U : 0x02100000U;

  memw();
  unsigned int value = RTC_OPTIONS0_REGISTER;
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

/* Native entry: 0x40384218. */
/* Original function-byte SHA-256:
 * e0608b89cea66602e53cca5fb907988e7cb0c51f53e31355b075cbcc19f918a8. */
/*
 * cpu: Signed WORD selecting CPU 0 or 1; all other values assert.
 * Returns: No value.
 *
 * Clears that CPU's C0 field in RTC OPTIONS0, then its C1 field in SW_CPU_STALL.
 * Keeps the separate read/modify/write pairs and four native MEMWs; unrelated
 * register bits come from each individual read. CPU0 masks clear bits 2..3 and
 * 26..31; CPU1 masks clear bits 0..1 and 20..25.
 *
 * Does not restore a previous field value, reset the CPU, prevent selecting the
 * current CPU, lock other register writers, or wait for a hardware acknowledgement.
 */
void esp_cpu_unstall(int cpu)
{
  if ((unsigned int)cpu > 1U) __assert_func(0,0,0,0);
  memw();
  unsigned int value = RTC_OPTIONS0_REGISTER;
  unsigned int options_clear_mask = cpu == 0 ? 0xfffffff3U : 0xfffffffcU;
  unsigned int stall_clear_mask = cpu == 0 ? 0x03ffffffU : 0xfc0fffffU;
  memw();
  RTC_OPTIONS0_REGISTER = value & options_clear_mask;
  memw();
  value = RTC_CPU_STALL_REGISTER;
  memw();
  RTC_CPU_STALL_REGISTER = value & stall_clear_mask;
}

/* Native entry: 0x420038d4. */
/* Original function-byte SHA-256:
 * b26c72493587a0e3a671c70df7cebe6e7602fa8ec383ef51216c505c1c5a7f88. */
/*
 * cpu_id: Full unsigned WORD; caller must supply an initialized CPU slot 0 or 1.
 * callback: Required live void(void*) callback; no local NULL check.
 * argument: Borrowed context; must remain valid until callback execution finishes.
 * wait_for: Full WORD; worker accepts 1 (acknowledge start) or 2 (acknowledge end).
 * Returns: 0 on every returning path, even when semaphore/notification APIs fail.
 *
 * This internal body does not validate the CPU, target handle or scheduler state.
 * If the current task equals the selected live target slot, calls callback
 * directly and returns; this recursive path ignores wait_for and takes no mux.
 * Otherwise snapshots caller priority, reloads target for its priority query,
 * and reloads it again before raising it when its priority is lower. Takes the
 * per-core submission mutex indefinitely, ignoring the result; reloads target
 * and assigns caller priority again, even if that lowers the target's priority.
 *
 * Publishes argument, samples target, publishes mode, then publishes callback,
 * retaining each native MEMW. Notifies the captured target on index 0 with
 * action 2/value 0 and no previous-value output. Samples acknowledgement after
 * notify and waits indefinitely; reloads mutex after that wait and gives it.
 * Ignores all take/give/notify results. Provides no timeout, cancellation,
 * priority restoration or submission rollback. Mode 1 can return before callback
 * completion; mode 2 acknowledges completion only when the worker/protocol runs
 * successfully. Lifetimes and cross-core synchronization remain caller duties.
 */
int esp_ipc_call_and_wait(unsigned int cpu_id,IpcCallback callback,void *argument,unsigned int wait_for)
{
  IpcDispatchState *state = IPC_DISPATCH_STATE;
  RtosTask *current_task = xTaskGetCurrentTaskHandle();
  RtosTask *volatile *task_slot = &state->tasks[cpu_id];
  RtosTask *target_task = *task_slot;
  if (current_task == target_task) {
    callback(argument);
    return 0;
  }

  unsigned int priority = uxTaskPriorityGet(current_task);
  target_task = *task_slot;
  unsigned int target_priority = uxTaskPriorityGet(target_task);
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

/* Native entry: 0x42003a10. */
/* Original function-byte SHA-256:
 * 9a17ae30b49a7f16dd6c67ced605e593c7ec4db1b51a6470ec86c73e5560f012. */
/*
 * cpu_id: Full unsigned CPU index; only 0 and 1 are accepted.
 * callback: Required live void(void*) callback; NULL is not checked here.
 * argument: Borrowed context retained through callback completion.
 * Returns: 0x102 for an invalid CPU, 0x103 for a NULL task slot or a scheduler
 * state other than exactly 2; otherwise 0 after the internal call returns.
 *
 * Checks CPU before table access and task before querying scheduler state.
 * Passes mode 2 to esp_ipc_call_and_wait and discards that helper's return value.
 * Does not revalidate the target after scheduler query, check ISR context, or
 * add a timeout/lifecycle lock. Recursive target-task execution is direct.
 * Completion and waiting behavior depend on the helper and live worker protocol;
 * this wrapper supplies no independent acknowledgement validation.
 */
int esp_ipc_call_blocking(unsigned int cpu_id,IpcCallback callback,void *argument)
{
  if (cpu_id >= 2U) return 0x102;
  IpcDispatchState *state = IPC_DISPATCH_STATE;
  if (state->tasks[cpu_id] == 0) return 0x103;
  int scheduler_state = xTaskGetSchedulerState();
  if (scheduler_state != 2) return 0x103;
  (void)esp_ipc_call_and_wait(cpu_id,callback,argument,2);
  return 0;
}

/* Native entry: 0x42003a48. */
/* Original function-byte SHA-256:
 * eed294d6d580687dd648fde4d8226590df457301ec362b26a58535306cce479b. */
/*
 * cpu_id: Full unsigned CPU index; only 0 and 1 with a non-NULL task slot qualify.
 * callback: Live void(void*) callback required by the slot protocol. NULL is
 *   accepted by this body and can leave a ready flag without executable work.
 * argument: Borrowed context kept live until asynchronous execution finishes.
 * Returns: 0x102 for invalid CPU or absent target; 0x103 for a same-core target
 * whose scheduler state is not exactly 2; -1 when compare-and-set fails; else 0.
 *
 * Reads PRID only after target validation. Scheduler check is applied only to a
 * same-core submission. Claims callback WORD from 0 using compare-and-set; on
 * failure publishes no argument or ready flag. Success publishes argument then
 * ready BYTE=1 with native MEMWs, then queries ISR context and samples target.
 * ISR path gives notification index 0 with no wake-result pointer. Task path
 * assigns priority 24, reloads target and sends index 0/action 2/value 0.
 * All notification results are ignored; no acknowledgement, timeout, priority
 * restoration, cancellation or rollback occurs. Caller owns payload lifetime.
 */
int esp_ipc_call_nonblocking(unsigned int cpu_id,IpcCallback callback,void *argument)
{
  if (cpu_id >= 2U) return 0x102;
  IpcDispatchState *state = IPC_DISPATCH_STATE;
  if (state->tasks[cpu_id] == 0) return 0x102;
  unsigned int current_core = (xtensa_read_prid() >> 13) & 1U;
  if (cpu_id == current_core && xTaskGetSchedulerState() != 2) return 0x103;
  bool claimed = esp_cpu_compare_and_set(
      (volatile unsigned int *)&state->nonblocking_callbacks[cpu_id],0,(unsigned int)callback);
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

/* Native entry: 0x42003560. */
/* Original function-byte SHA-256:
 * e8677c015da8fdcd238a33ea59ffffbe92c65065927a6f1e37e2a0ffcf48969f. */
/*
 * Samples PRID bit 13 once and initializes that CPU's IPC interrupt routing.
 * CPU1 then publishes stall state RUNNING=1 with a preceding MEMW; CPU0 leaves
 * it untouched. Returns no value and waits for no other core. Creates no task
 * or semaphore, invokes no submitted callback and reports no setup status.
 */
void esp_ipc_isr_init(void)
{
    unsigned int core = (xtensa_read_prid() >> 13) & 1U;
    esp_ipc_isr_port_init((int)core);
    if (core != 0) {
        memw();
        IPC_ISR_STALL_STATE = 1;
    }
}

/* Native entry: 0x42003580. */
/* Original function-byte SHA-256:
 * b04c4a78f7c7480527a272b687d8b16fb66142a780d46eaa123b26167f072bb4. */
/*
 * core: Native signed WORD selecting the requested routing CPU; wrapper passes 0/1.
 * Returns: No value.
 *
 * Disables interrupt 28 on the executing CPU, routes source 81+core to interrupt
 * 28 on the requested CPU, then enables interrupt 28 on the executing CPU.
 * Source addition retains modulo-2^32 native arithmetic for out-of-contract
 * arguments. Does not validate core, restore the prior enable state, install a
 * handler or allocate an interrupt. Caller must match requested/executing CPUs.
 */
void esp_ipc_isr_port_init(int core)
{
    esp_intr_disable_source(28);
    intr_matrix_set(core,(int)((unsigned int)core + 81U),28);
    esp_intr_enable_source(28);
}
