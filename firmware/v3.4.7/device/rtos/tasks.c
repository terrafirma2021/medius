/* Medius v3.4.7 device — rtos/tasks.c.
 * Recovered C and native assembly, grouped for source navigation.
 * Original entry addresses, firmware-byte hashes and function comments follow.
 */

#include "../include/types.h"

/* Native entry: 0x40386e10. */
/* Original function-byte SHA-256:
 * 4e4562c3d2d7b044edba89772f123f34bd8f4100321864a6a76ce12e03bbbb98. */
/* Allocate the idle stack first (1536 bytes), then its 340-byte task control block.
 * task_buffer, stack_buffer and stack_bytes must be writable output slots.
 * Either allocation failure asserts before any output is written; a successful
 * partial allocation is not freed. Publish TCB, byte-stack pointer and byte
 * length in that order. Each invocation allocates new, uninitialized buffers.
 */
void vApplicationGetIdleTaskMemory
               (RtosTask **task_buffer,unsigned char **stack_buffer,unsigned int *stack_bytes)

{
  unsigned char *idle_stack;
  RtosTask *idle_task;

  idle_stack = pvPortMalloc(0x600);
  idle_task = pvPortMalloc(0x154);
  if ((idle_task == (RtosTask *)0x0) || (idle_stack == (unsigned char *)0x0)) {
                    /* WARNING: Subroutine does not return */
    __assert_func((char *)0x0,0,(char *)0x0,(char *)0x0);
  }
  *task_buffer = idle_task;
  *stack_buffer = idle_stack;
  *stack_bytes = 0x600;
  return;
}

/* Native entry: 0x40387138. */
/* Original function-byte SHA-256:
 * 64cfbc5a1bd8026e754fe3c2f54e00f42bbdf6aeb9959e072de2bcf411315065. */
/* Decide whether making task ready requires preemption. Caller holds kernel lock.
 * task is a live TCB; priority is a full unsigned WORD and must be <=24.
 * Exactly yield_equal_priority==1 includes equal-priority tasks in comparison.
 * Affinity 0/1 selects one core; INT32_MAX permits both. Check the current core
 * first and return 1 only when its running priority is lower and scheduling is
 * unsuspended. Otherwise test the compatible other core and request its yield
 * asynchronously, returning 0. Invalid affinity values also return 0.
 * No task selection, local yield, lock acquisition or execution deadline here.
 */
int prvIsYieldRequiredSMP(RtosTask *task,unsigned int priority,int yield_equal_priority)
{
  if (priority > 24U) __assert_func(0,0,0,0);
  unsigned int core = (xtensa_read_prid() >> 13) & 1U;
  unsigned int affinity = (unsigned int)((volatile RtosTask *)task)->core_id;
  unsigned int threshold = priority + (yield_equal_priority == 1 ? 1U : 0U);
  if (affinity == core || affinity == 0x7fffffffU) {
    memw();
    RtosTask *current = RTOS_CURRENT_TASKS[core];
    unsigned int current_priority = ((volatile RtosTask *)current)->priority;
    if (current_priority < threshold) {
      memw();
      if (RTOS_SCHEDULER_SUSPEND_COUNTS[core] == 0) return 1;
    }
    if (affinity == core) return 0;
  }
  unsigned int other_core = core == 0 ? 1U : 0U;
  if (affinity != other_core && affinity != 0x7fffffffU) return 0;
  memw();
  RtosTask *current = RTOS_CURRENT_TASKS[other_core];
  unsigned int current_priority = ((volatile RtosTask *)current)->priority;
  if (current_priority < threshold) {
    memw();
    if (RTOS_SCHEDULER_SUSPEND_COUNTS[other_core] == 0)
      vPortYieldOtherCore((int)other_core);
  }
  return 0;
}

/* Native entry: 0x40387208. */
/* Original function-byte SHA-256:
 * 4a5df9c05667f80abefe068409bd51a23f101beb6ab6c308070c60c42bc70089. */
/* Caller holds kernel lock and supplies a valid blocking context. Sample tick
 * count once, then select current core from PRID bit13. A task already on the
 * termination list is left untouched (another core may have deleted it).
 * Otherwise clear delay_aborted byte and remove its state item from its list;
 * discard removal count. UINT32_MAX plus nonzero can_block_indefinitely inserts
 * the state item before the suspended-list index with native publication order
 * and repeated current-slot/index-link loads. No wake deadline is set there.
 * Other waits set state.value=tick_snapshot+ticks modulo32 and insert in sorted
 * active or overflow delayed list. Only a nonwrapped earlier deadline lowers
 * next_unblock_tick. Does not lock, yield, alter event item or wait for time to
 * pass. Barriers and fresh current-task reads retain the native list sequence. */
void prvAddCurrentTaskToDelayedList(unsigned int ticks_to_wait,int can_block_indefinitely)
{
    memw();
    unsigned int tick_snapshot = *CLOCK_TICK_COUNT;
    unsigned int core = (xtensa_read_prid() >> 13) & 1U;
    memw();
    volatile RtosTask *current = RTOS_CURRENT_TASKS[core];
    memw();
    if (current->state_item.container == RTOS_TERMINATION_LIST)
        return;
    memw();
    volatile RtosTask *task_to_clear = RTOS_CURRENT_TASKS[core];
    memw();
    RtosTask *task_to_remove = RTOS_CURRENT_TASKS[core];
    task_to_clear->delay_aborted = 0;
    (void)uxListRemove(&task_to_remove->state_item);
    if (ticks_to_wait == 0xffffffffU && can_block_indefinitely != 0) {
        RtosList *suspended = RTOS_SUSPENDED_LIST;
        memw();
        volatile RtosListItem *index = ((volatile RtosList *)suspended)->index;
        memw();
        current = RTOS_CURRENT_TASKS[core];
        memw();
        current->state_item.next = (RtosListItem *)index;
        memw();
        current = RTOS_CURRENT_TASKS[core];
        memw();
        RtosListItem *previous = index->previous;
        memw();
        current->state_item.previous = previous;
        memw();
        RtosTask *task = RTOS_CURRENT_TASKS[core];
        memw();
        previous = index->previous;
        memw();
        ((volatile RtosListItem *)previous)->next = &task->state_item;
        memw();
        task = RTOS_CURRENT_TASKS[core];
        memw();
        index->previous = &task->state_item;
        memw();
        current = RTOS_CURRENT_TASKS[core];
        memw();
        current->state_item.container = suspended;
        memw();
        unsigned int count = ((volatile RtosList *)suspended)->count;
        memw();
        ((volatile RtosList *)suspended)->count = count + 1U;
    } else {
        memw();
        current = RTOS_CURRENT_TASKS[core];
        unsigned int wake_tick = tick_snapshot + ticks_to_wait;
        memw();
        current->state_item.value = wake_tick;
        if (wake_tick < tick_snapshot) {
            memw();
            RtosList *delayed = RTOS_OVERFLOW_DELAYED_LIST;
            memw();
            RtosTask *task = RTOS_CURRENT_TASKS[core];
            vListInsert(delayed,&task->state_item);
        } else {
            memw();
            RtosList *delayed = RTOS_ACTIVE_DELAYED_LIST;
            memw();
            RtosTask *task = RTOS_CURRENT_TASKS[core];
            vListInsert(delayed,&task->state_item);
            memw();
            unsigned int next_unblock = RTOS_NEXT_UNBLOCK_TICK;
            if (wake_tick < next_unblock) {
                memw();
                RTOS_NEXT_UNBLOCK_TICK = wake_tick;
            }
        }
    }
}

/* Native entry: 0x403872fc. */
/* Original function-byte SHA-256:
 * da8c42f98fc174d5a7a9d6441d985af8ba3d5a8f441aeb6c8849f21d59849bb5. */
/* Insert initialized, unlinked task into its priority ready list under kernel lock.
 * task must contain valid priority 0..24, affinity and state-item owner; this
 * routine does not validate them or allocate memory. Increment task count; a
 * fresh count of exactly 1 initializes all 25 ready lists, both delayed lists,
 * two pending-ready lists, termination and suspended lists, then their pointers.
 * Prefer an empty compatible CPU0 slot, then CPU1. Before scheduler start,
 * replace a compatible current task of no higher priority, preferring CPU0.
 * Increment task number, raise top-ready priority if needed, then link the state
 * item before the ready-list index using repeated native predecessor reads.
 * With scheduler running, request local/remote preemption for equal priority.
 * Counts wrap modulo 2^32; lock return status is ignored. No rollback or wait.
 */
void prvAddNewTaskToReadyList(RtosTask *task)
{
  (void)xPortEnterCriticalTimeout(RTOS_KERNEL_LOCK,-1);
  memw();
  unsigned int count = RTOS_TASK_COUNT;
  memw();
  RTOS_TASK_COUNT = count + 1U;
  memw();
  if (RTOS_TASK_COUNT == 1) {
    for (unsigned int priority = 0; priority < 25U; ++priority)
      vListInitialise(&RTOS_READY_LISTS[priority]);
    vListInitialise(RTOS_DELAYED_LIST1);
    vListInitialise(RTOS_DELAYED_LIST2);
    vListInitialise(&RTOS_PENDING_READY_LISTS[0]);
    vListInitialise(&RTOS_PENDING_READY_LISTS[1]);
    vListInitialise(RTOS_TERMINATION_LIST);
    vListInitialise(RTOS_SUSPENDED_LIST);
    memw();
    RTOS_ACTIVE_DELAYED_LIST = RTOS_DELAYED_LIST1;
    memw();
    RTOS_OVERFLOW_DELAYED_LIST = RTOS_DELAYED_LIST2;
  }
  volatile RtosTask *state = task;
  unsigned int priority = state->priority;
  bool selected = false;
  memw();
  if (RTOS_CURRENT_TASKS[0] == 0) {
    int affinity = state->core_id;
    if (affinity == 0 || affinity == 0x7fffffff) {
      memw();
      RTOS_CURRENT_TASKS[0] = task;
      selected = true;
    }
  }
  if (!selected) {
    memw();
    if (RTOS_CURRENT_TASKS[1] == 0) {
      int affinity = state->core_id;
      if (affinity == 1 || affinity == 0x7fffffff) {
        memw();
        RTOS_CURRENT_TASKS[1] = task;
        selected = true;
      }
    }
  }
  if (!selected) {
    memw();
    if (RTOS_SCHEDULER_RUNNING == 0) {
      memw();
      if (RTOS_CURRENT_TASKS[0] != 0) {
        int affinity = state->core_id;
        if (affinity == 0 || affinity == 0x7fffffff) {
          memw();
          RtosTask *current = RTOS_CURRENT_TASKS[0];
          if (((volatile RtosTask *)current)->priority <= priority) {
            memw();
            RTOS_CURRENT_TASKS[0] = task;
            selected = true;
          }
        }
      }
      if (!selected) {
        memw();
        if (RTOS_CURRENT_TASKS[1] != 0) {
          int affinity = state->core_id;
          if (affinity == 1 || affinity == 0x7fffffff) {
            memw();
            RtosTask *current = RTOS_CURRENT_TASKS[1];
            if (((volatile RtosTask *)current)->priority <= priority) {
              memw();
              RTOS_CURRENT_TASKS[1] = task;
            }
          }
        }
      }
    }
  }
  unsigned int task_number = RTOS_TASK_NUMBER;
  memw();
  unsigned int top_priority = RTOS_TOP_READY_PRIORITY;
  RTOS_TASK_NUMBER = task_number + 1U;
  if (top_priority < priority) {
    memw();
    RTOS_TOP_READY_PRIORITY = priority;
  }
  RtosList *ready_list = &RTOS_READY_LISTS[priority];
  volatile RtosList *ready = ready_list;
  RtosListItem *item = &task->state_item;
  memw();
  RtosListItem *index = ready->index;
  memw();
  state->state_item.next = index;
  memw();
  RtosListItem *previous = ((volatile RtosListItem *)index)->previous;
  memw();
  state->state_item.previous = previous;
  memw();
  previous = ((volatile RtosListItem *)index)->previous;
  memw();
  ((volatile RtosListItem *)previous)->next = item;
  memw();
  ((volatile RtosListItem *)index)->previous = item;
  memw();
  state->state_item.container = ready_list;
  memw();
  count = ready->count;
  memw();
  ready->count = count + 1U;
  memw();
  if (RTOS_SCHEDULER_RUNNING != 0 && prvIsYieldRequiredSMP(task,priority,1) == 1) {
    unsigned int core = (xtensa_read_prid() >> 13) & 1U;
    esp_crosscore_int_send_yield((int)core);
  }
  vPortExitCritical(RTOS_KERNEL_LOCK);
}

/* Native entry: 0x403874b0. */
/* Original function-byte SHA-256:
 * cf2b880220cec6df7f982f4d0fcd18e2798096702d3ea8d6a078fb3ae68a1953. */
/* Release a terminated task after scheduler/list references are no longer live.
 * task must be a valid 340-byte TCB. Run port TLS/coprocessor cleanup, then
 * reclaim its embedded Newlib context before reading allocation_kind BYTE337.
 * Kind 0 frees stack_base then TCB; 1 frees only TCB; 2 frees neither.
 * Any other raw byte asserts after cleanup. No list removal, locking, pointer
 * clearing, reference pinning or recovery of an invalid/partly freed task.
 */
void prvDeleteTCB(RtosTask *task)

{
  unsigned char allocation_kind;

  vPortTCBPreDeleteHook(task);
  newlib_reclaim_reent(&task->libc_reent);
  allocation_kind = task->allocation_kind;
  if (allocation_kind == '\0') {
    vPortFree(task->stack_base);
    vPortFree(task);
  }
  else if (allocation_kind == '\x01') {
    vPortFree(task);
  }
  else if (allocation_kind != '\x02') {
                    /* WARNING: Subroutine does not return */
    __assert_func((char *)0x0,0,(char *)0x0,(char *)0x0);
  }
  return;
}

/* Native entry: 0x403874f8. */
/* Original function-byte SHA-256:
 * 7cd9d8cf63a80d8703069c95ccee31bd9a4e6c4116d14bfbc4dfac9e043c9c1b. */
/* Per-core idle task entry; argument unused. While deferred deletions exist,
 * hold the kernel mux, scan termination-list owners and skip tasks still current
 * on either CPU. Sample CPU0 BEFORE owner; sample CPU1 only if CPU0 differs.
 * Unlink one eligible state item, decrement total/deferred counts modulo32 with
 * native MEMWs, then unlock before deleting its TCB/resources. Restart cleanup
 * immediately after a non-NULL deletion; run idle hooks only after no eligible
 * deletion (or the native NULL-owner branch). Never free a still-running task.
 * No periodic delay or yield is requested here; hooks may veto interrupt-wait.
 * There is no independent NULL-owner/list validation, idle budget or deadline. */
void prvIdleTask(void *argument)
{
    (void)argument;
    for (;;) {
recheck_deletions:
        memw();
        if (RTOS_PENDING_DELETIONS != 0) {
            (void)xPortEnterCriticalTimeout(RTOS_KERNEL_LOCK,-1);
            memw();
            unsigned int count = ((volatile RtosList *)RTOS_TERMINATION_LIST)->count;
            if (count != 0) {
                memw();
                volatile RtosListItem *item =
                    ((volatile RtosList *)RTOS_TERMINATION_LIST)->end_marker.next;
                while (item != RTOS_TERMINATION_END) {
                    memw();
                    RtosTask *running0 = RTOS_CURRENT_TASKS[0];
                    RtosTask *task = item->owner;
                    bool still_running = task == running0;
                    if (!still_running) {
                        memw();
                        still_running = task == RTOS_CURRENT_TASKS[1];
                    }
                    if (!still_running) {
                        (void)uxListRemove(&task->state_item);
                        memw();
                        unsigned int tasks = RTOS_DELETION_TASK_COUNT;
                        memw();
                        RTOS_DELETION_TASK_COUNT = tasks - 1U;
                        memw();
                        unsigned int pending = RTOS_PENDING_DELETIONS;
                        memw();
                        RTOS_PENDING_DELETIONS = pending - 1U;
                        vPortExitCritical(RTOS_KERNEL_LOCK);
                        if (task) {
                            prvDeleteTCB(task);
                            goto recheck_deletions;
                        }
                        goto run_idle_hooks;
                    }
                    memw();
                    item = item->next;
                }
            }
            vPortExitCritical(RTOS_KERNEL_LOCK);
        }
run_idle_hooks:
        esp_vApplicationIdleHook();
    }
}

/* Native entry: 0x40387590. */
/* Original function-byte SHA-256:
 * 7e11bed5b134678595840a3ead5e111832dd990a872f32eafb7833259f3c56be. */
/* Initialize a task's stack, selected TCB fields and initial processor frame.
 * task is writable with live stack_base storage covering stack_bytes bytes.
 * entry/argument become the task callback and its opaque argument; neither is
 * validated. name is optional readable text: copy through its first NUL or 16
 * bytes, then force name[15]=NUL. NULL name leaves all name bytes unchanged.
 * Fill the supplied stack with 0xa5 before computing its aligned top as
 * (base+stack_bytes-1) modulo 2^32, rounded down to 16 bytes. Zero length is not
 * rejected; adequate space for the initial frame is the caller's obligation.
 * Store stack_end, then name, before asserting priority<=24. Set priority,
 * unchecked core_id affinity, base priority, list containers/owners and event
 * value 25-priority. Initialize the 240-byte Newlib context and store the frame
 * initializer's returned pointer as top_of_stack. Optional created_task receives
 * task last. Does not clear the remaining TCB, allocate or enter a ready list.
 */
void prvInitialiseNewTask
               (TaskEntry entry,char *name,unsigned int stack_bytes,void *argument,unsigned int priority,
               RtosTask **created_task,RtosTask *task,int core_id)

{
  char name_character;
  unsigned char *stack_pointer;

  memset(task->stack_base,0xa5,stack_bytes);
  stack_pointer = (unsigned char *)(((unsigned int)task->stack_base + stack_bytes - 1U) & 0xfffffff0U);
  task->stack_end = stack_pointer;
  if (name != (char *)0x0) {
    /* Native LOOP limit is16; a NUL exits before the next iteration. */
    for (unsigned int name_index = 0; name_index < 16; ++name_index) {
      name_character = name[name_index];
      task->name[name_index] = name_character;
      if (name_character == '\0') break;
    }
    task->name[0xf] = '\0';
  }
  if (0x18 < priority) {
                    /* WARNING: Subroutine does not return */
    __assert_func((char *)0x0,0,(char *)0x0,(char *)0x0);
  }
  volatile RtosTask *state = task;
  state->priority = priority;
  state->core_id = core_id;
  state->base_priority = priority;
  vListInitialiseItem(&task->state_item);
  vListInitialiseItem(&task->event_item);
  (task->state_item).owner = task;
  memw();
  (task->event_item).value = 25U - priority;
  (task->event_item).owner = task;
  esp_reent_init(&task->libc_reent);
  stack_pointer = pxPortInitialiseStack(stack_pointer,entry,argument);
  task->top_of_stack = stack_pointer;
  if (created_task != (RtosTask **)0x0) {
    *created_task = task;
  }
  return;
}

/* Native entry: 0x4038761c. */
/* Original function-byte SHA-256:
 * 688d60cd27ac84d5adc91f58b66265018c867c546ac9fe2e17dc91c73ed6c729. */
/*
 * task: TCB to delete, or NULL for the current task. Idle tasks and invalid TCBs are not safe
 *   inputs.
 * Returns: Nothing; deleting the running task requests a switch and its continuation must not be
 *   relied on.
 * Requirements/effects: Unlinks state/event items under the kernel lock. Tasks running on either
 *   CPU enter the termination list for idle cleanup; inactive tasks are released through
 *   prvDeleteTCB after dropping the lock. No wait for a remote task to finish. Self-deletion
 *   asserts if scheduling is suspended.
 */
void vTaskDelete(RtosTask *task)
{
  (void)xPortEnterCriticalTimeout(RTOS_KERNEL_LOCK,-1);
  unsigned int core = (xtensa_read_prid() >> 13) & 1U;
  if (task == 0) {
    unsigned int previous_ps;
    __asm__ volatile ("rsil %0,3" : "=a"(previous_ps) :: "memory");
    unsigned int current_core = (xtensa_read_prid() >> 13) & 1U;
    memw();
    task = RTOS_CURRENT_TASKS[current_core];
    (void)_xtos_set_intlevel((int)previous_ps);
  }
  volatile RtosTask *state = task;
  RtosListItem *item = &task->state_item;
  (void)uxListRemove(item);
  memw();
  if (state->event_item.container != 0) (void)uxListRemove(&task->event_item);
  unsigned int task_number = RTOS_TASK_NUMBER;
  memw();
  RtosTask *local_task = RTOS_CURRENT_TASKS[core];
  RTOS_TASK_NUMBER = task_number + 1U;
  if (local_task == task) {
    vListInsertEnd(RTOS_TERMINATION_LIST,item);
    memw();
    unsigned int pending = RTOS_PENDING_DELETIONS;
    memw();
    RTOS_PENDING_DELETIONS = pending + 1U;
    vPortExitCritical(RTOS_KERNEL_LOCK);
    (void)xPortEnterCriticalTimeout(RTOS_KERNEL_LOCK,-1);
    memw();
    if (RTOS_SCHEDULER_RUNNING != 0) {
      unsigned int previous_ps;
      __asm__ volatile ("rsil %0,3" : "=a"(previous_ps) :: "memory");
      memw();
      if (RTOS_SCHEDULER_RUNNING != 0) {
        unsigned int current_core = (xtensa_read_prid() >> 13) & 1U;
        memw();
        if (RTOS_SCHEDULER_SUSPEND_COUNTS[current_core] != 0) {
          (void)_xtos_set_intlevel((int)previous_ps);
          __assert_func(0,0,0,0);
        }
      }
      (void)_xtos_set_intlevel((int)previous_ps);
      unsigned int current_core = (xtensa_read_prid() >> 13) & 1U;
      esp_crosscore_int_send_yield((int)current_core);
    }
  } else {
    unsigned int other_core = core == 0 ? 1U : 0U;
    memw();
    if (RTOS_CURRENT_TASKS[other_core] == task) {
      vListInsertEnd(RTOS_TERMINATION_LIST,item);
      memw();
      unsigned int pending = RTOS_PENDING_DELETIONS;
      memw();
      RTOS_PENDING_DELETIONS = pending + 1U;
      vPortYieldOtherCore((int)other_core);
      vPortExitCritical(RTOS_KERNEL_LOCK);
    } else {
      memw();
      unsigned int count = RTOS_TASK_COUNT;
      memw();
      RTOS_TASK_COUNT = count - 1U;
      memw();
      RtosList *delayed = RTOS_ACTIVE_DELAYED_LIST;
      memw();
      unsigned int delayed_count = ((volatile RtosList *)delayed)->count;
      if (delayed_count == 0) {
        memw();
        RTOS_NEXT_UNBLOCK_TICK = 0xffffffffU;
      } else {
        memw();
        delayed = RTOS_ACTIVE_DELAYED_LIST;
        memw();
        RtosListItem *first = ((volatile RtosList *)delayed)->end_marker.next;
        memw();
        unsigned int wake_tick = ((volatile RtosListItem *)first)->value;
        memw();
        RTOS_NEXT_UNBLOCK_TICK = wake_tick;
      }
      vPortExitCritical(RTOS_KERNEL_LOCK);
      prvDeleteTCB(task);
    }
    (void)xPortEnterCriticalTimeout(RTOS_KERNEL_LOCK,-1);
    memw();
    (void)RTOS_SCHEDULER_RUNNING;
  }
  vPortExitCritical(RTOS_KERNEL_LOCK);
}

/* Native entry: 0x4038779c. */
/* Original function-byte SHA-256:
 * 17e3cd3a818291209af61438b1d6d3a698ec1d6b3a29cddd70faf02337605b52. */
/* Relative task delay in kernel ticks; zero skips list/lock/assert work and
 * only requests this core's yield. For nonzero delay, RSIL3 saves the full PS,
 * then test this core's scheduler-suspend count only if scheduler is running.
 * Restore PS.INTLEVEL through ROM before a fatal suspension assertion, or on
 * the ordinary path before acquiring kernel mux. Add current task to delayed
 * lists with indefinite blocking disabled, unlock, sample PRID afresh and
 * request a local crosscore yield. UINT32_MAX is therefore a finite wrapping
 * delay here. This establishes a wake tick, not an exact resume time: tick
 * delivery, ready-task priorities, critical sections and scheduler availability
 * govern when the task next executes. No wall-clock conversion is performed. */
void vTaskDelay(unsigned int ticks_to_delay)
{
    if (ticks_to_delay != 0) {
        unsigned int previous_ps;
        __asm__ volatile ("rsil %0,3" : "=a"(previous_ps) : : "memory");
        memw();
        if (RTOS_SCHEDULER_RUNNING != 0) {
            unsigned int core = (xtensa_read_prid() >> 13) & 1U;
            memw();
            if (RTOS_SCHEDULER_SUSPEND_COUNTS[core] != 0) {
                (void)_xtos_set_intlevel((int)previous_ps);
                __assert_func(0,0,0,0);
            }
        }
        (void)_xtos_set_intlevel((int)previous_ps);
        (void)xPortEnterCriticalTimeout(RTOS_KERNEL_LOCK,-1);
        prvAddCurrentTaskToDelayedList(ticks_to_delay,0);
        vPortExitCritical(RTOS_KERNEL_LOCK);
    }
    esp_crosscore_int_send_yield((xtensa_read_prid() >> 13) & 1U);
}

/* Native entry: 0x40387800. */
/* Original function-byte SHA-256:
 * 0c1e41c82f09f56cf0418a3f1a5c7e8a01860d173a810aef0814c9a7c665808a. */
/* Return the task's current effective priority, including mutex inheritance.
 * task is a live TCB, or NULL to select this CPU's current task. Hold the kernel
 * mux while resolving the handle and reading priority WORD44 once; retain that
 * snapshot across unlock. NULL selection briefly uses RSIL3, then restores only
 * PS.INTLEVEL through ROM using the saved PS word. No base-priority read, stale-handle validation, lifetime
 * extension, scheduler suspension or task completion guarantee.
 */
uint uxTaskPriorityGet(RtosTask *task)
{
  (void)xPortEnterCriticalTimeout(RTOS_KERNEL_LOCK,-1);
  if (task == 0) {
    uint previous_ps;
    __asm__ volatile ("rsil %0,3" : "=a"(previous_ps) :: "memory");
    uint core = (xtensa_read_prid() >> 13) & 1U;
    memw();
    task = RTOS_CURRENT_TASKS[core];
    (void)_xtos_set_intlevel((int)previous_ps);
  }
  uint priority = ((volatile RtosTask *)task)->priority;
  vPortExitCritical(RTOS_KERNEL_LOCK);
  return priority;
}

/* Native entry: 0x40387834. */
/* Original function-byte SHA-256:
 * 849d860c061b03630584d1d71b7866654344eaf922928c57480959f6b98e03bc. */
/* Set a live task's base priority; NULL selects this CPU's current task.
 * Reject unsigned priority>24 before acquiring the kernel mux. When unchanged,
 * unlock without other task writes or yield. Raising a nonrunning task checks
 * whether equal-priority preemption is needed. Lowering a locally running task
 * requests a local yield; lowering a remotely running task requests its yield.
 * Effective priority changes only if it equals the captured old base priority;
 * otherwise retain the inherited value, even if the new base is higher.
 * Read event value before publishing the base. Preserve bit-31-marked event
 * values; otherwise store 25-priority. An already-blocked event item is not
 * removed/reinserted here. A state item in its old ready list is unlinked and
 * appended before its new effective-priority ready-list index, retaining fresh
 * priority/predecessor/count reads and all native MEMWs. Raise top-ready priority
 * if needed; do not lower it here. Request any local yield before unlock.
 * No task-context restoration, reference pinning, other-core completion wait or
 * rollback. Valid TCB/list state and task context are the caller's obligation.
 */
void vTaskPrioritySet(RtosTask *task,uint priority)
{
  if (priority > 24U) __assert_func(0,0,0,0);
  (void)xPortEnterCriticalTimeout(RTOS_KERNEL_LOCK,-1);
  uint core = (xtensa_read_prid() >> 13) & 1U;
  if (task == 0) {
    uint previous_ps;
    __asm__ volatile ("rsil %0,3" : "=a"(previous_ps) :: "memory");
    uint current_core = (xtensa_read_prid() >> 13) & 1U;
    memw();
    task = RTOS_CURRENT_TASKS[current_core];
    (void)_xtos_set_intlevel((int)previous_ps);
  }
  volatile RtosTask *state = task;
  uint old_base = state->base_priority;
  if (priority != old_base) {
    int local_yield_required;
    if (old_base < priority) {
      local_yield_required = 0;
      memw();
      RtosTask *running0 = RTOS_CURRENT_TASKS[0];
      if (running0 != task) {
        memw();
        RtosTask *running1 = RTOS_CURRENT_TASKS[1];
        if (running1 != task) {
          local_yield_required = prvIsYieldRequiredSMP(task,priority,1);
          old_base = state->base_priority;
        }
      }
    } else {
      local_yield_required = 1;
      memw();
      if (RTOS_CURRENT_TASKS[core] != task) {
        local_yield_required = 0;
        uint other_core = core == 0 ? 1U : 0U;
        memw();
        if (RTOS_CURRENT_TASKS[other_core] == task) {
          vPortYieldOtherCore((int)other_core);
          old_base = state->base_priority;
        }
      }
    }
    uint old_priority = state->priority;
    if (old_priority == old_base) state->priority = priority;
    memw();
    uint event_value = state->event_item.value;
    state->base_priority = priority;
    if ((event_value & 0x80000000U) == 0) {
      memw();
      state->event_item.value = 25U - priority;
    }
    RtosList *old_ready = &RTOS_READY_LISTS[old_priority];
    memw();
    if (state->state_item.container == old_ready) {
      RtosListItem *item = &task->state_item;
      (void)uxListRemove(item);
      uint ready_priority = state->priority;
      memw();
      if (RTOS_TOP_READY_PRIORITY < ready_priority) {
        memw();
        RTOS_TOP_READY_PRIORITY = ready_priority;
      }
      RtosList *ready_list = &RTOS_READY_LISTS[ready_priority];
      volatile RtosList *ready = ready_list;
      memw();
      RtosListItem *index = ready->index;
      memw();
      state->state_item.next = index;
      memw();
      RtosListItem *previous = ((volatile RtosListItem *)index)->previous;
      memw();
      state->state_item.previous = previous;
      memw();
      previous = ((volatile RtosListItem *)index)->previous;
      memw();
      ((volatile RtosListItem *)previous)->next = item;
      memw();
      ((volatile RtosListItem *)index)->previous = item;
      memw();
      state->state_item.container = ready_list;
      memw();
      uint count = ready->count;
      memw();
      ready->count = count + 1U;
    }
    if (local_yield_required != 0) {
      uint current_core = (xtensa_read_prid() >> 13) & 1U;
      esp_crosscore_int_send_yield((int)current_core);
    }
  }
  vPortExitCritical(RTOS_KERNEL_LOCK);
}

/* Native entry: 0x40387968. */
/* Original function-byte SHA-256:
 * 34ed776b15a67a915596e464557bd2ec1329e561365b019a944f9a9fa1a8bd6e. */
/* Suspend scheduling on this CPU by incrementing its nesting count under the
 * shared kernel mux. Select CPU0/1 using PRID bit13, MEMW/read the count, then
 * MEMW/publish count+1 modulo 2^32 and unlock. Overflow is not rejected.
 * No parameters or return value. Balance with resume; this does not suspend the
 * other CPU, retain the mux or leave interrupts masked after unlock.
 */
void vTaskSuspendAll(void)
{
    (void)xPortEnterCriticalTimeout(RTOS_KERNEL_LOCK,-1);
    unsigned int processor_id;
    __asm__ volatile ("rsr.prid %0" : "=a"(processor_id));
    unsigned int core = (processor_id >> 13) & 1U;
    memw();
    unsigned int suspend_count = RTOS_SCHEDULER_SUSPEND_COUNTS[core];
    memw();
    RTOS_SCHEDULER_SUSPEND_COUNTS[core] = suspend_count + 1U;
    vPortExitCritical(RTOS_KERNEL_LOCK);
}

/* Native entry: 0x403879a8. */
/* Original function-byte SHA-256:
 * 0bdd8efef1f9fa1efbf43e1cc7a55a3ed0952cada69360c3893c51ebb6dd78bc. */
/* Snapshot the unsigned32 tick count under the kernel mux with indefinite lock
 * acquisition; ignore lock result. MEMW occurs BEFORE the tick load. Unlock
 * and return the saved count without conversion or reservation. Wrap is native
 * modulo32; snapshot may be stale immediately after unlock. ISR caller must
 * meet the port's interrupt-priority/locking rules; this entry checks neither. */
unsigned int xTaskGetTickCountFromISR(void)
{
    (void)xPortEnterCriticalTimeout(RTOS_KERNEL_LOCK,-1);
    memw();
    unsigned int ticks = *CLOCK_TICK_COUNT;
    vPortExitCritical(RTOS_KERNEL_LOCK);
    return ticks;
}

/* Native entry: 0x403879fc. */
/* Original function-byte SHA-256:
 * aac9542fbecba40d560f796937e79a15085ad35758b9effb7e0cb0986de9743c. */
/* Process one kernel tick on CPU0; a CPU1 caller asserts before taking the mux.
 * No parameters. Return 0/1 indicating a CPU0 scheduling request; this function
 * does not switch context or issue a remote yield. ISR-context probe results
 * before lock and before unlock are discarded; lock acquisition waits indefinitely.
 * If CPU0 scheduling is suspended, increment only pended_ticks modulo 2^32.
 * Otherwise increment/publish the tick. On wrap, assert that the old active
 * delayed list is empty, reread and swap active/overflow pointers, increment the
 * overflow count modulo 2^32 and recompute the next deadline from the new list.
 * When tick reaches the deadline, unlink due tasks' state and optional event
 * items, then append their state items to effective-priority ready lists. Keep
 * fresh link/container/index/count reads and native MEMW/store order throughout.
 * An earlier unexpired head becomes the next deadline; an empty list uses UINT32_MAX.
 * An eligible higher-priority CPU0 task requests a local switch. An unpinned
 * task is considered for CPU1 only when it does not preempt CPU0; all other
 * nonzero/non-INT32_MAX affinity values take the native CPU1 branch unchecked.
 * CPU1 preemption only stores its pending-yield flag. Finally read both CPU0's
 * same-priority ready count and pending-yield flag, even if one already requests
 * a switch. This is tick accounting and readiness, not an execution deadline.
 */
int xTaskIncrementTick(void)
{
    unsigned int processor_id;
    __asm__ volatile ("rsr.prid %0" : "=a"(processor_id));
    if (((processor_id >> 13) & 1U) != 0U)
        __assert_func(0,0,0,0);

    (void)xPortInIsrContext();
    (void)xPortEnterCriticalTimeout(RTOS_KERNEL_LOCK,-1);
    unsigned int switch_required = 0;
    memw();
    unsigned int suspend_count = RTOS_SCHEDULER_SUSPEND_COUNTS[0];
    if (suspend_count == 0U) {
        memw();
        unsigned int tick = *CLOCK_TICK_COUNT + 1U;
        memw();
        *CLOCK_TICK_COUNT = tick;
        if (tick == 0U) {
            /* Observe the active list again after the wrap check. Neither list
             * pointer is prefetched before the suspension test or tick store. */
            memw();
            volatile RtosList *active = RTOS_ACTIVE_DELAYED_LIST;
            memw();
            if (active->count != 0U)
                __assert_func(0,0,0,0);
            memw();
            RtosList *previous_active = RTOS_ACTIVE_DELAYED_LIST;
            memw();
            RtosList *previous_overflow = RTOS_OVERFLOW_DELAYED_LIST;
            memw();
            RTOS_ACTIVE_DELAYED_LIST = previous_overflow;
            memw();
            RTOS_OVERFLOW_DELAYED_LIST = previous_active;
            memw();
            unsigned int overflow_count = RTOS_TICK_OVERFLOWS;
            memw();
            RTOS_TICK_OVERFLOWS = overflow_count + 1U;
            memw();
            active = RTOS_ACTIVE_DELAYED_LIST;
            memw();
            unsigned int delayed_count = active->count;
            unsigned int next_unblock = 0xffffffffU;
            if (delayed_count != 0U) {
                memw();
                active = RTOS_ACTIVE_DELAYED_LIST;
                memw();
                volatile RtosListItem *first = active->end_marker.next;
                memw();
                next_unblock = first->value;
            }
            memw();
            RTOS_NEXT_UNBLOCK_TICK = next_unblock;
        }

        memw();
        unsigned int next_unblock = RTOS_NEXT_UNBLOCK_TICK;
        if (tick >= next_unblock) {
            memw();
            volatile RtosList *active = RTOS_ACTIVE_DELAYED_LIST;
            memw();
            unsigned int delayed_count = active->count;
            while (delayed_count != 0U) {
                memw();
                active = RTOS_ACTIVE_DELAYED_LIST;
                memw();
                volatile RtosListItem *first = active->end_marker.next;
                RtosTask *task = first->owner;
                volatile RtosTask *task_view = task;
                memw();
                unsigned int wake_tick = task_view->state_item.value;
                if (tick < wake_tick) {
                    memw();
                    RTOS_NEXT_UNBLOCK_TICK = wake_tick;
                    break;
                }

                /* The native unlink sequences reread both links, and update
                 * the list cursor only when it names the removed item. */
                volatile RtosListItem *state = &task_view->state_item;
                RtosListItem *state_identity = &task->state_item;
                memw();
                volatile RtosList *owning_list = state->container;
                memw();
                volatile RtosListItem *next = state->next;
                memw();
                RtosListItem *previous = state->previous;
                memw();
                next->previous = previous;
                memw();
                volatile RtosListItem *previous_view = state->previous;
                memw();
                RtosListItem *next_identity = state->next;
                memw();
                previous_view->next = next_identity;
                memw();
                RtosListItem *cursor = owning_list->index;
                if (cursor == state_identity) {
                    memw();
                    previous = state->previous;
                    memw();
                    owning_list->index = previous;
                }
                memw();
                state->container = 0;
                memw();
                unsigned int count = owning_list->count;
                memw();
                owning_list->count = count - 1U;

                volatile RtosListItem *event = &task_view->event_item;
                memw();
                RtosList *event_container = event->container;
                if (event_container != 0) {
                    memw();
                    owning_list = event->container;
                    memw();
                    next = event->next;
                    memw();
                    previous = event->previous;
                    memw();
                    next->previous = previous;
                    memw();
                    previous_view = event->previous;
                    memw();
                    next_identity = event->next;
                    memw();
                    previous_view->next = next_identity;
                    memw();
                    cursor = owning_list->index;
                    if (cursor == &task->event_item) {
                        memw();
                        previous = event->previous;
                        memw();
                        owning_list->index = previous;
                    }
                    memw();
                    event->container = 0;
                    memw();
                    count = owning_list->count;
                    memw();
                    owning_list->count = count - 1U;
                }

                unsigned int priority = task_view->priority;
                memw();
                unsigned int top_priority = RTOS_TOP_READY_PRIORITY;
                if (top_priority < priority) {
                    memw();
                    RTOS_TOP_READY_PRIORITY = priority;
                }
                RtosList *ready_identity = &RTOS_READY_LISTS[priority];
                volatile RtosList *ready = ready_identity;
                memw();
                RtosListItem *index_identity = ready->index;
                volatile RtosListItem *index = index_identity;
                int affinity = task_view->core_id;
                memw();
                state->next = index_identity;
                memw();
                previous = index->previous;
                memw();
                state->previous = previous;
                memw();
                previous_view = index->previous;
                memw();
                previous_view->next = state_identity;
                memw();
                index->previous = state_identity;
                memw();
                state->container = ready_identity;
                memw();
                count = ready->count;
                memw();
                ready->count = count + 1U;

                if (affinity == 0 || affinity == 0x7fffffff) {
                    memw();
                    volatile RtosTask *current = RTOS_CURRENT_TASKS[0];
                    if (current->priority < priority) {
                        switch_required = 1;
                    } else if (affinity == 0x7fffffff) {
                        memw();
                        current = RTOS_CURRENT_TASKS[1];
                        if (current->priority < priority) {
                            memw();
                            RTOS_YIELD_PENDING[1] = 1;
                        }
                    }
                } else {
                    /* Native code trusts affinity validity: every remaining
                     * value takes the CPU1 branch without bounds checking. */
                    memw();
                    volatile RtosTask *current = RTOS_CURRENT_TASKS[1];
                    if (current->priority < priority) {
                        memw();
                        RTOS_YIELD_PENDING[1] = 1;
                    }
                }
                memw();
                active = RTOS_ACTIVE_DELAYED_LIST;
                memw();
                delayed_count = active->count;
            }
            if (delayed_count == 0U) {
                memw();
                RTOS_NEXT_UNBLOCK_TICK = 0xffffffffU;
            }
        }

        /* Both observations occur, even if time slicing already requests a
         * switch. Using short-circuit || would suppress the yield-flag read. */
        memw();
        volatile RtosTask *current = RTOS_CURRENT_TASKS[0];
        unsigned int priority = current->priority;
        memw();
        unsigned int ready_count = ((volatile RtosList *)RTOS_READY_LISTS)[priority].count;
        memw();
        unsigned int yield_pending = RTOS_YIELD_PENDING[0];
        switch_required |= (ready_count > 1U) | (yield_pending != 0U);
    } else {
        memw();
        unsigned int pended_ticks = RTOS_PENDED_TICKS;
        memw();
        RTOS_PENDED_TICKS = pended_ticks + 1U;
    }
    (void)xPortInIsrContext();
    vPortExitCritical(RTOS_KERNEL_LOCK);
    return (int)switch_required;
}

/* Native entry: 0x40387cc4. */
/* Original function-byte SHA-256:
 * f7306c52f7b486fcec9cbc9347110bc3b837b1460b3c0ab48fd0504db222f369. */
/* Resume scheduling on this CPU; no parameters. Return 1 only if this call
 * requests a local yield, otherwise 0. Under RSIL3, assert scheduler-running
 * and a nonzero suspension count, restoring only PS.INTLEVEL before either
 * assertion. Restore that level normally, take the kernel mux, sample PRID afresh and
 * decrement that CPU's count modulo 2^32; reread it before deciding outermost resume.
 * If nesting remains or task count is zero, unlock and return 0. Otherwise drain
 * this CPU's pending-ready list: unlink each event item, then its state item,
 * and append the state item to its effective-priority ready list. Preserve fresh
 * native links/containers/counts and the priority read before the old count store.
 * A yield-helper result of exactly 1 sets this CPU's pending flag. Recompute
 * next_unblock_tick only after draining at least one pending task.
 * CPU0 alone snapshots/replays pended ticks and clears their count after the
 * saved number of iterations; CPU1 skips replay. A nonzero pending-yield flag
 * requests a local yield using a fresh PRID sample while the mux remains held.
 * No context restoration, remote-completion wait, timeout or replay budget here.
 */
int xTaskResumeAll(void)
{
    unsigned int saved_processor_status;
    __asm__ volatile ("rsil %0,3" : "=a"(saved_processor_status) : : "memory");
    memw();
    if (RTOS_SCHEDULER_RUNNING == 0U) {
        (void)_xtos_set_intlevel(saved_processor_status);
        __assert_func(0,0,0,0);
    }
    unsigned int processor_id;
    __asm__ volatile ("rsr.prid %0" : "=a"(processor_id));
    memw();
    if (RTOS_SCHEDULER_SUSPEND_COUNTS[(processor_id >> 13) & 1U] == 0U) {
        (void)_xtos_set_intlevel(saved_processor_status);
        __assert_func(0,0,0,0);
    }
    (void)_xtos_set_intlevel(saved_processor_status);
    (void)xPortEnterCriticalTimeout(RTOS_KERNEL_LOCK,-1);
    __asm__ volatile ("rsr.prid %0" : "=a"(processor_id));
    unsigned int core = (processor_id >> 13) & 1U;
    memw();
    unsigned int suspend_count = RTOS_SCHEDULER_SUSPEND_COUNTS[core];
    memw();
    RTOS_SCHEDULER_SUSPEND_COUNTS[core] = suspend_count - 1U;
    memw();
    suspend_count = RTOS_SCHEDULER_SUSPEND_COUNTS[core];
    int yielded = 0;
    if (suspend_count == 0U) {
        memw();
        unsigned int task_count = RTOS_TASK_COUNT;
        if (task_count != 0U) {
            volatile RtosList *pending = &RTOS_PENDING_READY_LISTS[core];
            memw();
            unsigned int pending_count = pending->count;
            if (pending_count != 0U) {
                do {
                    memw();
                    volatile RtosListItem *first = pending->end_marker.next;
                    RtosTask *task = first->owner;
                    volatile RtosTask *task_view = task;
                    volatile RtosListItem *event = &task_view->event_item;
                    memw();
                    volatile RtosList *owning_list = event->container;
                    memw();
                    volatile RtosListItem *next = event->next;
                    memw();
                    RtosListItem *previous = event->previous;
                    memw();
                    next->previous = previous;
                    memw();
                    volatile RtosListItem *previous_view = event->previous;
                    memw();
                    RtosListItem *next_identity = event->next;
                    memw();
                    previous_view->next = next_identity;
                    memw();
                    RtosListItem *cursor = owning_list->index;
                    if (cursor == &task->event_item) {
                        memw();
                        previous = event->previous;
                        memw();
                        owning_list->index = previous;
                    }
                    memw();
                    event->container = 0;
                    memw();
                    unsigned int count = owning_list->count;
                    memw();
                    owning_list->count = count - 1U;

                    volatile RtosListItem *state = &task_view->state_item;
                    RtosListItem *state_identity = &task->state_item;
                    memw();
                    owning_list = state->container;
                    memw();
                    next = state->next;
                    memw();
                    previous = state->previous;
                    memw();
                    next->previous = previous;
                    memw();
                    previous_view = state->previous;
                    memw();
                    next_identity = state->next;
                    memw();
                    previous_view->next = next_identity;
                    memw();
                    cursor = owning_list->index;
                    if (cursor == state_identity) {
                        memw();
                        previous = state->previous;
                        memw();
                        owning_list->index = previous;
                    }
                    memw();
                    state->container = 0;
                    memw();
                    count = owning_list->count;
                    unsigned int priority = task_view->priority;
                    memw();
                    owning_list->count = count - 1U;
                    memw();
                    unsigned int top_priority = RTOS_TOP_READY_PRIORITY;
                    if (top_priority < priority) {
                        memw();
                        RTOS_TOP_READY_PRIORITY = priority;
                    }
                    RtosList *ready_identity = &RTOS_READY_LISTS[priority];
                    volatile RtosList *ready = ready_identity;
                    memw();
                    RtosListItem *index_identity = ready->index;
                    volatile RtosListItem *index = index_identity;
                    memw();
                    state->next = index_identity;
                    memw();
                    previous = index->previous;
                    memw();
                    state->previous = previous;
                    memw();
                    previous_view = index->previous;
                    memw();
                    previous_view->next = state_identity;
                    memw();
                    index->previous = state_identity;
                    memw();
                    state->container = ready_identity;
                    memw();
                    count = ready->count;
                    memw();
                    ready->count = count + 1U;
                    if (prvIsYieldRequiredSMP(task,priority,1) == 1) {
                        memw();
                        RTOS_YIELD_PENDING[core] = 1;
                    }
                    memw();
                    pending_count = pending->count;
                } while (pending_count != 0U);

                /* Recompute the deadline only after draining at least one
                 * pending task; retain the fresh pointer read on this path. */
                memw();
                volatile RtosList *active = RTOS_ACTIVE_DELAYED_LIST;
                memw();
                unsigned int delayed_count = active->count;
                unsigned int next_unblock = 0xffffffffU;
                if (delayed_count != 0U) {
                    memw();
                    active = RTOS_ACTIVE_DELAYED_LIST;
                    memw();
                    volatile RtosListItem *first = active->end_marker.next;
                    memw();
                    next_unblock = first->value;
                }
                memw();
                RTOS_NEXT_UNBLOCK_TICK = next_unblock;
            }
            if (core == 0U) {
                memw();
                unsigned int ticks_remaining = RTOS_PENDED_TICKS;
                if (ticks_remaining != 0U) {
                    do {
                        if (xTaskIncrementTick() != 0) {
                            memw();
                            RTOS_YIELD_PENDING[0] = 1;
                        }
                        --ticks_remaining;
                    } while (ticks_remaining != 0U);
                    memw();
                    RTOS_PENDED_TICKS = 0;
                }
            }
            memw();
            unsigned int yield_pending = RTOS_YIELD_PENDING[core];
            if (yield_pending != 0U) {
                __asm__ volatile ("rsr.prid %0" : "=a"(processor_id));
                esp_crosscore_int_send_yield((processor_id >> 13) & 1U);
                yielded = 1;
            }
        }
    }
    vPortExitCritical(RTOS_KERNEL_LOCK);
    return yielded;
}

/* Native entry: 0x40387ed8. */
/* Original function-byte SHA-256:
 * 25c0c833a4609e8dd1f25e32a62d9822ffb5ac0e0b89fd393b3fa785b80b3e27. */
/* Select a ready task for this core; assembly restores its processor context.
 * No parameters or return value. Probe ISR context and take the kernel mux;
 * discard probe/lock results. If scheduling is suspended, set this core's yield
 * flag, probe again, unlock and return without stack checks or list selection.
 * Otherwise clear the flag and inspect the current task's first four stack-base
 * WORDs for 0xa5a5a5a5, stopping at the first mismatch. On failure, reread the
 * current handle and name pointer separately for the fatal overflow hook.
 * Sample PRID again, read signed top-ready priority and assert if negative.
 * Search downward, retaining the highest nonempty priority even if its tasks
 * cannot run on this core. For each list, reset the index to its end marker,
 * walk candidates once by owner identity, skip the other CPU's running task,
 * then require affinity matching this CPU or INT32_MAX. No upper-priority clamp.
 * Publish the chosen current handle before resetting the index, unlinking its
 * state item and reinserting it at the tail for best-effort round robin. Retain
 * native cursor/link/count rereads, temporary container clear and MEMW order.
 * Exhausting priorities through zero asserts; valid idle tasks normally prevent
 * that path. There is no idle fallback manufactured outside the ready lists.
 * Probe ISR context again and unlock after selection. No Newlib pointer/errno
 * update, frame restoration, callback execution or timing guarantee in this body.
 */
void vTaskSwitchContext(void)
{
    (void)xPortInIsrContext();
    (void)xPortEnterCriticalTimeout(RTOS_KERNEL_LOCK,-1);
    unsigned int processor_id;
    __asm__ volatile ("rsr.prid %0" : "=a"(processor_id));
    unsigned int core = (processor_id >> 13) & 1U;
    memw();
    unsigned int suspend_count = RTOS_SCHEDULER_SUSPEND_COUNTS[core];
    if (suspend_count != 0U) {
        memw();
        RTOS_YIELD_PENDING[core] = 1;
        (void)xPortInIsrContext();
        vPortExitCritical(RTOS_KERNEL_LOCK);
        return;
    }
    memw();
    RTOS_YIELD_PENDING[core] = 0;
    memw();
    volatile RtosTask *current = RTOS_CURRENT_TASKS[core];
    volatile unsigned int *guard = current->stack_base;
    if (guard[0] != 0xa5a5a5a5U || guard[1] != 0xa5a5a5a5U ||
        guard[2] != 0xa5a5a5a5U || guard[3] != 0xa5a5a5a5U) {
        memw();
        RtosTask *overflow_task = RTOS_CURRENT_TASKS[core];
        memw();
        RtosTask *name_task = RTOS_CURRENT_TASKS[core];
        vApplicationStackOverflowHook(overflow_task,name_task->name);
    }
    __asm__ volatile ("rsr.prid %0" : "=a"(processor_id));
    core = (processor_id >> 13) & 1U;
    memw();
    int priority = (int)RTOS_TOP_READY_PRIORITY;
    if (priority < 0)
        __assert_func(0,0,0,0);
    bool higher_nonempty_priority_seen = false;
    for (;;) {
        RtosList *ready_identity = &RTOS_READY_LISTS[priority];
        volatile RtosList *ready = ready_identity;
        RtosListItem *end_marker = (RtosListItem *)&ready_identity->end_marker;
        memw();
        unsigned int ready_count = ready->count;
        if (ready_count != 0U) {
            if (!higher_nonempty_priority_seen) {
                memw();
                RTOS_TOP_READY_PRIORITY = (unsigned int)priority;
            }
            memw();
            ready->index = end_marker;
            memw();
            volatile RtosListItem *index = ready->index;
            memw();
            RtosListItem *next_identity = index->next;
            memw();
            ready->index = next_identity;
            memw();
            RtosListItem *cursor = ready->index;
            if (cursor == end_marker) {
                memw();
                index = ready->index;
                memw();
                next_identity = index->next;
                memw();
                ready->index = next_identity;
            }
            memw();
            index = ready->index;
            RtosTask *first_candidate = index->owner;
            RtosTask *candidate = first_candidate;
            do {
                /* PRID was masked to one bit, so this is exactly the native
                 * CPU0/CPU1 exclusion before examining candidate affinity. */
                memw();
                RtosTask *other_current = RTOS_CURRENT_TASKS[core ^ 1U];
                if (candidate != other_current) {
                    volatile RtosTask *candidate_view = candidate;
                    int affinity = candidate_view->core_id;
                    if (affinity == (int)core || affinity == 0x7fffffff) {
                        memw();
                        RTOS_CURRENT_TASKS[core] = candidate;
                        memw();
                        ready->index = end_marker;
                        volatile RtosListItem *state = &candidate_view->state_item;
                        RtosListItem *state_identity = &candidate->state_item;
                        memw();
                        volatile RtosList *owning_list = state->container;
                        memw();
                        volatile RtosListItem *next = state->next;
                        memw();
                        RtosListItem *previous = state->previous;
                        memw();
                        next->previous = previous;
                        memw();
                        volatile RtosListItem *previous_view = state->previous;
                        memw();
                        next_identity = state->next;
                        memw();
                        previous_view->next = next_identity;
                        memw();
                        cursor = owning_list->index;
                        if (cursor == state_identity) {
                            memw();
                            previous = state->previous;
                            memw();
                            owning_list->index = previous;
                        }
                        memw();
                        state->container = 0;
                        memw();
                        unsigned int count = owning_list->count;
                        memw();
                        owning_list->count = count - 1U;
                        memw();
                        RtosListItem *index_identity = ready->index;
                        index = index_identity;
                        memw();
                        state->next = index_identity;
                        memw();
                        previous = index->previous;
                        memw();
                        state->previous = previous;
                        memw();
                        previous_view = index->previous;
                        memw();
                        previous_view->next = state_identity;
                        memw();
                        index->previous = state_identity;
                        memw();
                        state->container = ready_identity;
                        memw();
                        count = ready->count;
                        memw();
                        ready->count = count + 1U;
                        (void)xPortInIsrContext();
                        vPortExitCritical(RTOS_KERNEL_LOCK);
                        return;
                    }
                }
                memw();
                index = ready->index;
                memw();
                next_identity = index->next;
                memw();
                ready->index = next_identity;
                memw();
                cursor = ready->index;
                if (cursor == end_marker) {
                    memw();
                    index = ready->index;
                    memw();
                    next_identity = index->next;
                    memw();
                    ready->index = next_identity;
                }
                memw();
                index = ready->index;
                candidate = index->owner;
            } while (candidate != first_candidate);
            higher_nonempty_priority_seen = true;
        }
        --priority;
        if (priority == -1)
            __assert_func(0,0,0,0);
    }
}

/* Native entry: 0x40388100. */
/* Original function-byte SHA-256:
 * fd3b074cb0b4ffea78eb8e0affbca459c56e4720003732e1da37cd3654ffd91b. */
/* Queue the current task's event item in event_list, then block its state item.
 * event_list must be a nonnull initialized priority-sorted list; NULL asserts
 * before lock acquisition. ticks_to_wait is an unsigned tick delta; UINT32_MAX
 * enables indefinite suspension through the delayed-list helper's second arg 1.
 * Under the kernel mux, sample PRID/current handle, insert event_item (+24), then
 * call the helper, which samples the current task again. No direct yield here.
 * Caller supplies valid blocking context, unlinked event item and the queue's
 * own lock where applicable; no allocation, timeout conversion or rollback.
 */
void vTaskPlaceOnEventList(RtosList *event_list,unsigned int ticks_to_wait)
{
    if (event_list == 0)
        __assert_func(0,0,0,0);
    (void)xPortEnterCriticalTimeout(RTOS_KERNEL_LOCK,-1);
    unsigned int processor_id;
    __asm__ volatile ("rsr.prid %0" : "=a"(processor_id));
    memw();
    RtosTask *current = RTOS_CURRENT_TASKS[(processor_id >> 13) & 1U];
    vListInsert(event_list,&current->event_item);
    prvAddCurrentTaskToDelayedList(ticks_to_wait,1);
    vPortExitCritical(RTOS_KERNEL_LOCK);
}

/* Native entry: 0x40388144. */
/* Original function-byte SHA-256:
 * e6d354ce12e443a8d9fefa6b1c5cf46ac48ce8fafbdb5d08cbed88b2086b08f0. */
/* Remove the first waiter from a valid event_list; an empty list returns 0.
 * No NULL-list check. Probe ISR context, acquire kernel mux and read count before
 * sampling PRID or head owner. A nonempty list with a NULL owner asserts.
 * Unlink its event item, sampling affinity between count read and decrement store.
 * Pinned affinity indexes the suspension-count array unchecked. INT32_MAX allows
 * readiness if either CPU is unsuspended (read CPU1 only when CPU0 is suspended).
 * If readying is deferred, reassert the selected CPU is suspended, then append
 * the event item to that CPU's pending-ready list; retain the state item in its
 * delayed/suspended list. An unpinned deferred task uses this CPU's pending list.
 * Otherwise unlink the state item and append it to its effective-priority ready
 * list, raising top-ready priority if necessary. Preserve native link/cursor
 * rereads, temporary container clears, wrapping counts and MEMW/store ordering.
 * Call the yield helper with equal-priority preemption disabled on either path.
 * An exact result 1 sets this CPU's pending-yield flag and returns 1; otherwise
 * return 0, possibly after a remote request by the helper. Probe again and unlock.
 * No local context switch, next-wake recomputation or remote-completion wait.
 */
int xTaskRemoveFromEventList(RtosList *event_list)
{
    (void)xPortInIsrContext();
    (void)xPortEnterCriticalTimeout(RTOS_KERNEL_LOCK,-1);
    volatile RtosList *event_list_view = event_list;
    int local_yield = 0;
    memw();
    unsigned int waiter_count = event_list_view->count;
    if (waiter_count != 0U) {
        unsigned int processor_id;
        __asm__ volatile ("rsr.prid %0" : "=a"(processor_id));
        unsigned int core = (processor_id >> 13) & 1U;
        memw();
        volatile RtosListItem *first = event_list_view->end_marker.next;
        RtosTask *task = first->owner;
        if (task == 0)
            __assert_func(0,0,0,0);
        volatile RtosTask *task_view = task;
        RtosListItem *event_identity = &task->event_item;
        volatile RtosListItem *event = &task_view->event_item;
        memw();
        volatile RtosList *owning_list = event->container;
        memw();
        volatile RtosListItem *next = event->next;
        memw();
        RtosListItem *previous = event->previous;
        memw();
        next->previous = previous;
        memw();
        volatile RtosListItem *previous_view = event->previous;
        memw();
        RtosListItem *next_identity = event->next;
        memw();
        previous_view->next = next_identity;
        memw();
        RtosListItem *cursor = owning_list->index;
        if (cursor == event_identity) {
            memw();
            previous = event->previous;
            memw();
            owning_list->index = previous;
        }
        memw();
        event->container = 0;
        memw();
        unsigned int count = owning_list->count;
        int affinity = task_view->core_id;
        memw();
        owning_list->count = count - 1U;

        bool defer_ready;
        unsigned int pending_core;
        if (affinity == 0x7fffffff) {
            memw();
            unsigned int suspended_cpu0 = RTOS_SCHEDULER_SUSPEND_COUNTS[0];
            defer_ready = false;
            if (suspended_cpu0 != 0U) {
                memw();
                defer_ready = RTOS_SCHEDULER_SUSPEND_COUNTS[1] != 0U;
            }
            pending_core = core;
        } else {
            pending_core = (unsigned int)affinity;
            memw();
            defer_ready = RTOS_SCHEDULER_SUSPEND_COUNTS[pending_core] != 0U;
        }

        unsigned int priority;
        RtosList *destination_identity;
        RtosListItem *item_identity;
        volatile RtosListItem *item;
        if (defer_ready) {
            /* A deferred task retains its delayed/suspended state item. Its
             * event item is queued on the selected CPU's pending-ready list. */
            memw();
            if (RTOS_SCHEDULER_SUSPEND_COUNTS[pending_core] == 0U)
                __assert_func(0,0,0,0);
            priority = task_view->priority;
            destination_identity = &RTOS_PENDING_READY_LISTS[pending_core];
            item_identity = event_identity;
            item = event;
        } else {
            item_identity = &task->state_item;
            item = &task_view->state_item;
            memw();
            owning_list = item->container;
            memw();
            next = item->next;
            memw();
            previous = item->previous;
            memw();
            next->previous = previous;
            memw();
            previous_view = item->previous;
            memw();
            next_identity = item->next;
            memw();
            previous_view->next = next_identity;
            memw();
            cursor = owning_list->index;
            if (cursor == item_identity) {
                memw();
                previous = item->previous;
                memw();
                owning_list->index = previous;
            }
            memw();
            item->container = 0;
            memw();
            count = owning_list->count;
            memw();
            owning_list->count = count - 1U;
            priority = task_view->priority;
            memw();
            unsigned int top_priority = RTOS_TOP_READY_PRIORITY;
            if (top_priority < priority) {
                memw();
                RTOS_TOP_READY_PRIORITY = priority;
            }
            destination_identity = &RTOS_READY_LISTS[priority];
        }

        volatile RtosList *destination = destination_identity;
        memw();
        RtosListItem *index_identity = destination->index;
        volatile RtosListItem *index = index_identity;
        memw();
        item->next = index_identity;
        memw();
        previous = index->previous;
        memw();
        item->previous = previous;
        memw();
        previous_view = index->previous;
        memw();
        previous_view->next = item_identity;
        memw();
        index->previous = item_identity;
        memw();
        item->container = destination_identity;
        memw();
        count = destination->count;
        memw();
        destination->count = count + 1U;
        if (prvIsYieldRequiredSMP(task,priority,0) == 1) {
            memw();
            RTOS_YIELD_PENDING[core] = 1;
            local_yield = 1;
        }
    }
    (void)xPortInIsrContext();
    vPortExitCritical(RTOS_KERNEL_LOCK);
    return local_yield;
}

/* Native entry: 0x40388308. */
/* Original function-byte SHA-256:
 * ce8f0c6971eed37f158b0a63f8cb77987e05d9fb2dec4d067f3d02bda948aafd. */
/* Initialize the writable 8-byte timeout record without acquiring a lock.
 * MEMW/read overflow WORD, store its bits to signed overflow_count at offset 0,
 * then MEMW/read tick WORD and store entered_at_tick at offset 4. No NULL check.
 * Caller supplies the critical context needed for a coherent two-field snapshot;
 * neither the barriers nor this record establish a timer or execution deadline.
 */
void vTaskInternalSetTimeOutState(RtosTimeout *timeout)
{
    memw();
    unsigned int overflow_count = RTOS_TICK_OVERFLOWS;
    timeout->overflow_count = (int)overflow_count;
    memw();
    unsigned int tick = *CLOCK_TICK_COUNT;
    timeout->entered_at_tick = tick;
}

/* Native entry: 0x40388324. */
/* Original function-byte SHA-256:
 * d98892668950f67a249929217a7464ec0ff16df956f577ffba6e9264060e8450. */
/* Check an initialized timeout and update the writable unsigned tick budget.
 * Both pointers are required; either NULL asserts before taking the kernel mux.
 * Snapshot tick first, then PRID/current task and delay_aborted BYTE338. A nonzero
 * abort flag is cleared through a fresh current-handle read and returns 1 without
 * touching budget or timeout. Otherwise UINT32_MAX budget returns 0 unchanged.
 * For finite waits, read saved overflow, current overflow and saved start tick
 * in native order. Changed overflow with current_tick>=start, or modular elapsed
 * >=budget, zeros only the budget and returns 1. A continuing wait subtracts
 * elapsed modulo 2^32, rereads overflow and tick before any output write, then
 * stores remaining budget, refreshed overflow and refreshed tick in that order.
 * Return 0 after that refresh. Unlock on every normal path; no timer creation,
 * wakeup reservation, wall-clock conversion or exact-resume guarantee.
 */
int xTaskCheckForTimeOut(RtosTimeout *timeout,unsigned int *ticks_remaining)
{
    if (timeout == 0 || ticks_remaining == 0)
        __assert_func(0,0,0,0);
    (void)xPortEnterCriticalTimeout(RTOS_KERNEL_LOCK,-1);
    volatile RtosTimeout *timeout_view = timeout;
    volatile unsigned int *budget_view = ticks_remaining;
    memw();
    unsigned int current_tick = *CLOCK_TICK_COUNT;
    unsigned int processor_id;
    __asm__ volatile ("rsr.prid %0" : "=a"(processor_id));
    unsigned int core = (processor_id >> 13) & 1U;
    memw();
    volatile RtosTask *current = RTOS_CURRENT_TASKS[core];
    unsigned char delay_aborted = current->delay_aborted;
    int expired = 0;
    if (delay_aborted != 0U) {
        memw();
        current = RTOS_CURRENT_TASKS[core];
        current->delay_aborted = 0;
        expired = 1;
    } else {
        unsigned int budget = *budget_view;
        if (budget != 0xffffffffU) {
            unsigned int previous_overflow = (unsigned int)timeout_view->overflow_count;
            memw();
            unsigned int overflow_count = RTOS_TICK_OVERFLOWS;
            unsigned int start_tick = timeout_view->entered_at_tick;
            unsigned int elapsed = current_tick - start_tick;
            if ((previous_overflow != overflow_count && current_tick >= start_tick) ||
                elapsed >= budget) {
                *budget_view = 0;
                expired = 1;
            } else {
                unsigned int remaining = budget - current_tick + start_tick;
                memw();
                unsigned int refreshed_overflow = RTOS_TICK_OVERFLOWS;
                memw();
                unsigned int refreshed_tick = *CLOCK_TICK_COUNT;
                *budget_view = remaining;
                timeout_view->overflow_count = (int)refreshed_overflow;
                timeout_view->entered_at_tick = refreshed_tick;
            }
        }
    }
    vPortExitCritical(RTOS_KERNEL_LOCK);
    return expired;
}

/* Native entry: 0x403883d0. */
/* Original function-byte SHA-256:
 * 9bb9000590a18d0aefc32077bf21c0a2cb5dc01b0657f5ae32f578d9383d01c2. */
/* Return raw TLS word 0 or 1 from a live task; NULL selects this CPU's task.
 * index is a signed WORD checked as unsigned: negatives and values>=2 return
 * NULL before task resolution. For NULL task, RSIL3 saves PS, PRID selects the
 * current handle, then ROM restores only PS.INTLEVEL from that saved word.
 * Read the TLS word after restoration without a kernel mux. Slot 0 is the
 * application value; slot 1 exposes its deletion callback's raw representation.
 * No callback invocation, conversion, validation, reference pinning or ownership
 * transfer. Caller keeps the TCB live throughout the unprotected final read.
 */
void *pvTaskGetThreadLocalStoragePointer(RtosTask *task,int index)
{
    if ((unsigned int)index >= 2U)
        return 0;
    if (task == 0) {
        unsigned int saved_processor_status;
        __asm__ volatile ("rsil %0,3" : "=a"(saved_processor_status) : : "memory");
        unsigned int processor_id;
        __asm__ volatile ("rsr.prid %0" : "=a"(processor_id));
        memw();
        task = RTOS_CURRENT_TASKS[(processor_id >> 13) & 1U];
        (void)_xtos_set_intlevel(saved_processor_status);
    }
    /* The firmware accepts both words, including the callback representation;
     * this deliberately retains the native raw-slot exposure. */
    return task->raw_tls_words[index];
}

/* Native entry: 0x40388400. */
/* Original function-byte SHA-256:
 * f0107b65bf3c5fca1c5b4dde095834126af7282367c22a0f90590bbf97fa5505. */
/* Return this CPU's current TCB pointer, which can be NULL before selection.
 * No parameters. RSIL3 saves full PS and raises local interrupt level to 3;
 * PRID bit13 selects CPU0/1, then MEMW/read its current-handle WORD once.
 * Pass saved PS to ROM to restore only PS.INTLEVEL and return the cached handle.
 * No cross-core mux, TCB dereference, retained reference or lifetime guarantee.
 */
RtosTask *xTaskGetCurrentTaskHandle(void)
{
    unsigned int saved_processor_status;
    __asm__ volatile ("rsil %0,3" : "=a"(saved_processor_status) : : "memory");
    unsigned int processor_id;
    __asm__ volatile ("rsr.prid %0" : "=a"(processor_id));
    memw();
    RtosTask *current = RTOS_CURRENT_TASKS[(processor_id >> 13) & 1U];
    (void)_xtos_set_intlevel(saved_processor_status);
    return current;
}

/* Native entry: 0x40388420. */
/* Original function-byte SHA-256:
 * 203d8b5999d457472abf0e550d05cc5e7d50d64ec2f9e16c62ea33b97831e495. */
/*
 * Returns the FreeRTOS scheduler-state snapshot: NOT_STARTED=1 when the global
 * running flag is zero; otherwise RUNNING=2 for this CPU's zero suspension
 * count, or SUSPENDED=0 for any nonzero count. No parameters.
 *
 * Saves PS and sets local PS.INTLEVEL to 3, reads the running flag after MEMW,
 * and only if running reads PRID bit 13 and the corresponding suspension count
 * after a second MEMW. Calls ROM _xtos_set_intlevel with the saved PS word to
 * restore its interrupt-level bits; it does not write back the whole PS.
 * Returns an integer BaseType_t-sized result, not the raw decompiler's char.
 *
 * No kernel spinlock, allocation, wait or scheduler-state mutation is supplied.
 * Requires the privileged Xtensa/ROM environment and initialized kernel globals.
 * Local interrupt masking prevents migration during the CPU-specific snapshot;
 * this is not a synchronized snapshot of every CPU's scheduler state.
 */
int xTaskGetSchedulerState(void)
{
    unsigned int saved_ps;
    __asm__ volatile ("rsil %0, 3" : "=a"(saved_ps) : : "memory");
    int state = SCHEDULER_STATE_NOT_STARTED;
    memw();
    unsigned int running = RTOS_SCHEDULER_RUNNING;
    if (running != 0) {
        unsigned int current_core = (xtensa_read_prid() >> 13) & 1U;
        memw();
        unsigned int suspension_count = RTOS_SCHEDULER_SUSPEND_COUNTS[current_core];
        state = suspension_count == 0
            ? SCHEDULER_STATE_RUNNING : SCHEDULER_STATE_SUSPENDED;
    }
    (void)_xtos_set_intlevel((int)saved_ps);
    return state;
}

/* Native entry: 0x40388454. */
/* Original function-byte SHA-256:
 * cf266c1ca2f4ab3f1eed4712c97f27cb1a6467f1532198d7dd13dc429a568fd1. */
/* Apply this CPU's waiting task priority to a mutex holder under kernel mux.
 * mutex_holder may be NULL, returning 0 after the ordinary lock/unlock sequence.
 * For a live holder, sample current handle, holder priority and waiter priority
 * in native order. If holder priority is lower, update an unmarked event value
 * using a fresh waiter-priority read; preserve bit-31-marked event values.
 * Relink only a state item in its old priority ready list. Reread waiter priority
 * after unlink (or on the nonready path), then assign effective priority. Ready
 * insertion retains fresh index/predecessor/count reads and all native MEMWs.
 * Return 1 for that inheritance, or when an already-high-enough holder's base
 * priority is below a fresh waiter priority; otherwise 0. This return does not
 * mean priority changed on every successful call. No base-priority/count change,
 * waiter-list reordering, yield, allocation or priority-range validation here.
 */
int xTaskPriorityInherit(RtosTask *mutex_holder)
{
    (void)xPortEnterCriticalTimeout(RTOS_KERNEL_LOCK,-1);
    unsigned int processor_id;
    __asm__ volatile ("rsr.prid %0" : "=a"(processor_id));
    unsigned int core = (processor_id >> 13) & 1U;
    int inherited = 0;
    if (mutex_holder != 0) {
        volatile RtosTask *holder = mutex_holder;
        memw();
        volatile RtosTask *current = RTOS_CURRENT_TASKS[core];
        unsigned int previous_priority = holder->priority;
        unsigned int waiter_priority = current->priority;
        if (previous_priority < waiter_priority) {
            memw();
            unsigned int event_value = holder->event_item.value;
            if ((event_value & 0x80000000U) == 0U) {
                memw();
                current = RTOS_CURRENT_TASKS[core];
                unsigned int event_priority = current->priority;
                memw();
                holder->event_item.value = 25U - event_priority;
            }
            memw();
            RtosList *container = holder->state_item.container;
            if (container == &RTOS_READY_LISTS[previous_priority]) {
                RtosListItem *state_identity = &mutex_holder->state_item;
                (void)uxListRemove(state_identity);
                memw();
                current = RTOS_CURRENT_TASKS[core];
                unsigned int priority = current->priority;
                memw();
                unsigned int top_priority = RTOS_TOP_READY_PRIORITY;
                holder->priority = priority;
                if (top_priority < priority) {
                    memw();
                    RTOS_TOP_READY_PRIORITY = priority;
                }
            RtosList *ready_identity = &RTOS_READY_LISTS[priority];
            volatile RtosList *ready = ready_identity;
            volatile RtosListItem *state = &holder->state_item;
            memw();
            RtosListItem *index_identity = ready->index;
            volatile RtosListItem *index = index_identity;
            memw();
            state->next = index_identity;
            memw();
            RtosListItem *previous = index->previous;
            memw();
            state->previous = previous;
            memw();
            volatile RtosListItem *previous_view = index->previous;
            memw();
            previous_view->next = state_identity;
            memw();
            index->previous = state_identity;
            memw();
            state->container = ready_identity;
            memw();
            unsigned int count = ready->count;
            memw();
            ready->count = count + 1U;
            } else {
                memw();
                current = RTOS_CURRENT_TASKS[core];
                unsigned int priority = current->priority;
                holder->priority = priority;
            }
            inherited = 1;
        } else {
            memw();
            current = RTOS_CURRENT_TASKS[core];
            unsigned int base_priority = holder->base_priority;
            waiter_priority = current->priority;
            inherited = base_priority < waiter_priority;
        }
    }
    vPortExitCritical(RTOS_KERNEL_LOCK);
    return inherited;
}

/* Native entry: 0x4038853c. */
/* Original function-byte SHA-256:
 * 36159904104a564ad90638c4ba4e551b5ee92b2116ae2f16099bbed5f5b6d9ff. */
/* Release one mutex-hold count for the current task; NULL holder returns 0.
 * Take the kernel mux first. A nonnull holder must equal this CPU's current TCB
 * and have a nonzero mutexes_held WORD, or assert before decrementing it.
 * Read effective/base priority before storing the decremented count. Only when
 * priorities differ and this was the last held mutex, unlink the state item,
 * reread base priority, overwrite event value with 25-base even if bit31 was set,
 * then assign effective priority and reinsert into that priority's ready list.
 * Preserve the native top-priority read before the effective-priority store,
 * repeated predecessor reads, MEMWs and wrapping list counts. Return 1 only on
 * that restoration, otherwise 0. Caller handles any yield; no mutex unlock,
 * list-membership validation, reference pinning or callback is supplied here.
 */
int xTaskPriorityDisinherit(RtosTask *mutex_holder)
{
    (void)xPortEnterCriticalTimeout(RTOS_KERNEL_LOCK,-1);
    int priority_changed = 0;
    if (mutex_holder != 0) {
        volatile RtosTask *holder = mutex_holder;
        unsigned int processor_id;
        __asm__ volatile ("rsr.prid %0" : "=a"(processor_id));
        memw();
        RtosTask *current = RTOS_CURRENT_TASKS[(processor_id >> 13) & 1U];
        if (current != mutex_holder)
            __assert_func(0,0,0,0);
        unsigned int held_count = holder->mutexes_held;
        if (held_count == 0U)
            __assert_func(0,0,0,0);
        unsigned int remaining_mutexes = held_count - 1U;
        unsigned int previous_priority = holder->priority;
        unsigned int previous_base_priority = holder->base_priority;
        holder->mutexes_held = remaining_mutexes;
        if (previous_priority != previous_base_priority && remaining_mutexes == 0U) {
            RtosListItem *state_identity = &mutex_holder->state_item;
            (void)uxListRemove(state_identity);
            unsigned int priority = holder->base_priority;
            /* Unlike timeout disinheritance, release overwrites the event
             * ordering word even if its high bit was set. */
            memw();
            holder->event_item.value = 25U - priority;
            memw();
            unsigned int top_priority = RTOS_TOP_READY_PRIORITY;
            holder->priority = priority;
            if (top_priority < priority) {
                memw();
                RTOS_TOP_READY_PRIORITY = priority;
            }
            RtosList *ready_identity = &RTOS_READY_LISTS[priority];
            volatile RtosList *ready = ready_identity;
            volatile RtosListItem *state = &holder->state_item;
            memw();
            RtosListItem *index_identity = ready->index;
            volatile RtosListItem *index = index_identity;
            memw();
            state->next = index_identity;
            memw();
            RtosListItem *previous = index->previous;
            memw();
            state->previous = previous;
            memw();
            volatile RtosListItem *previous_view = index->previous;
            memw();
            previous_view->next = state_identity;
            memw();
            index->previous = state_identity;
            memw();
            state->container = ready_identity;
            memw();
            unsigned int count = ready->count;
            memw();
            ready->count = count + 1U;
            priority_changed = 1;
        }
    }
    vPortExitCritical(RTOS_KERNEL_LOCK);
    return priority_changed;
}

/* Native entry: 0x403885fc. */
/* Original function-byte SHA-256:
 * 59f110c6ba23a16db2ccd7a4d87ed46309c6fe47294b12858ad4a1c914975458. */
/* Reconsider inheritance after timeout; NULL holder is a no-op under the mux.
 * A nonnull holder must have a nonzero mutexes_held count. Compute unsigned
 * max(base_priority, highest_waiter_priority), with no range check or clamp to
 * the old effective priority. Only a count of exactly 1 and a differing result
 * permit a change; then assert the holder is not this CPU's current task.
 * Read event value before storing the new effective priority. Preserve its bit31
 * marker; otherwise set 25-new modulo 2^32. Relink the state item only when it
 * belonged to the old priority's ready list, using a fresh effective-priority
 * read after unlink and native index/predecessor/count/MEMW ordering.
 * No held-count/base-priority change, mutex release, yield or event-list relink.
 * Valid inputs normally reduce priority; unchecked input can also raise it.
 */
void vTaskPriorityDisinheritAfterTimeout(RtosTask *mutex_holder,unsigned int highest_waiter_priority)
{
    (void)xPortEnterCriticalTimeout(RTOS_KERNEL_LOCK,-1);
    if (mutex_holder != 0) {
        volatile RtosTask *holder = mutex_holder;
        unsigned int held_count = holder->mutexes_held;
        if (held_count == 0U)
            __assert_func(0,0,0,0);
        unsigned int base_priority = holder->base_priority;
        unsigned int previous_priority = holder->priority;
        unsigned int reduced_priority = highest_waiter_priority > base_priority
            ? highest_waiter_priority : base_priority;
        if (held_count == 1U && previous_priority != reduced_priority) {
            unsigned int processor_id;
            __asm__ volatile ("rsr.prid %0" : "=a"(processor_id));
            memw();
            RtosTask *current = RTOS_CURRENT_TASKS[(processor_id >> 13) & 1U];
            if (current == mutex_holder)
                __assert_func(0,0,0,0);
            memw();
            unsigned int event_value = holder->event_item.value;
            holder->priority = reduced_priority;
            if ((event_value & 0x80000000U) == 0U) {
                memw();
                holder->event_item.value = 25U - reduced_priority;
            }
            memw();
            RtosList *container = holder->state_item.container;
            if (container == &RTOS_READY_LISTS[previous_priority]) {
                RtosListItem *state_identity = &mutex_holder->state_item;
                (void)uxListRemove(state_identity);
                unsigned int priority = holder->priority;
                memw();
                unsigned int top_priority = RTOS_TOP_READY_PRIORITY;
                if (top_priority < priority) {
                    memw();
                    RTOS_TOP_READY_PRIORITY = priority;
                }
            RtosList *ready_identity = &RTOS_READY_LISTS[priority];
            volatile RtosList *ready = ready_identity;
            volatile RtosListItem *state = &holder->state_item;
            memw();
            RtosListItem *index_identity = ready->index;
            volatile RtosListItem *index = index_identity;
            memw();
            state->next = index_identity;
            memw();
            RtosListItem *previous = index->previous;
            memw();
            state->previous = previous;
            memw();
            volatile RtosListItem *previous_view = index->previous;
            memw();
            previous_view->next = state_identity;
            memw();
            index->previous = state_identity;
            memw();
            state->container = ready_identity;
            memw();
            unsigned int count = ready->count;
            memw();
            ready->count = count + 1U;
            }
        }
    }
    vPortExitCritical(RTOS_KERNEL_LOCK);
}

/* Native entry: 0x403886cc. */
/* Original function-byte SHA-256:
 * 123d2e9cfa5f8116359f6f402a56aca1d9542e62c563edd0565ede0482947a65. */
/* Under the kernel mux, sample this CPU's current handle and, if nonnull,
 * sample it again before incrementing mutexes_held WORD80 modulo 2^32. Sample
 * the current handle a third time for the return value, retaining each MEMW.
 * No parameters. Return that final handle (possibly NULL) after unlock. This
 * accounts for ownership; it does not acquire a mutex, validate task lifetime,
 * guard overflow or manufacture a task when called before task selection.
 */
RtosTask *pvTaskIncrementMutexHeldCount(void)
{
    (void)xPortEnterCriticalTimeout(RTOS_KERNEL_LOCK,-1);
    unsigned int processor_id;
    __asm__ volatile ("rsr.prid %0" : "=a"(processor_id));
    unsigned int core = (processor_id >> 13) & 1U;
    memw();
    RtosTask *selected = RTOS_CURRENT_TASKS[core];
    if (selected != 0) {
        memw();
        volatile RtosTask *current = RTOS_CURRENT_TASKS[core];
        unsigned int held_count = current->mutexes_held;
        current->mutexes_held = held_count + 1U;
    }
    memw();
    RtosTask *current = RTOS_CURRENT_TASKS[core];
    vPortExitCritical(RTOS_KERNEL_LOCK);
    return current;
}

/* Native entry: 0x4038870c. */
/* Original function-byte SHA-256:
 * 7e77132d502336aa9c4c31ca7715edc6ac9a3a9762d6a13209a2e99c7708f06e. */
/* Consume this task's single notification count; only index 0 is accepted.
 * Any other unsigned index asserts before locking. clear_count_on_exit is a
 * full signed WORD: any nonzero clears a consumed count; zero decrements it.
 * First lock/PRID/current/count snapshot: if count is zero, reread current and
 * store WAITING BYTE1 even for a zero-tick poll. A nonzero ticks_to_wait calls
 * the delayed-list helper with indefinite blocking enabled and requests a yield
 * using a fresh PRID sample while still locked. UINT32_MAX may wait indefinitely.
 * Unlock, relock and sample PRID/current/count again. Return this second saved
 * count, not the first. When nonzero, reread current and publish zero or count-1;
 * then always reread current and set notification state to IDLE BYTE0, and unlock.
 * No allocation or separate status return. The lock gap permits notification,
 * timeout and task migration; a positive wait does not guarantee notification
 * delivery or exact execution at the deadline. Caller supplies valid task context.
 */
unsigned int ulTaskGenericNotifyTake(unsigned int index,int clear_count_on_exit,unsigned int ticks_to_wait)
{
    if (index != 0U)
        __assert_func(0,0,0,0);
    (void)xPortEnterCriticalTimeout(RTOS_KERNEL_LOCK,-1);
    unsigned int processor_id;
    __asm__ volatile ("rsr.prid %0" : "=a"(processor_id));
    unsigned int core = (processor_id >> 13) & 1U;
    memw();
    volatile RtosTask *current = RTOS_CURRENT_TASKS[core];
    memw();
    unsigned int available = current->notification_value;
    if (available == 0U) {
        memw();
        current = RTOS_CURRENT_TASKS[core];
        memw();
        current->notification_state = RTOS_NOTIFICATION_WAITING;
        if (ticks_to_wait != 0U) {
            prvAddCurrentTaskToDelayedList(ticks_to_wait,1);
            __asm__ volatile ("rsr.prid %0" : "=a"(processor_id));
            esp_crosscore_int_send_yield((processor_id >> 13) & 1U);
        }
    }
    vPortExitCritical(RTOS_KERNEL_LOCK);
    (void)xPortEnterCriticalTimeout(RTOS_KERNEL_LOCK,-1);
    __asm__ volatile ("rsr.prid %0" : "=a"(processor_id));
    core = (processor_id >> 13) & 1U;
    memw();
    current = RTOS_CURRENT_TASKS[core];
    memw();
    available = current->notification_value;
    if (available != 0U) {
        memw();
        current = RTOS_CURRENT_TASKS[core];
        unsigned int remaining = clear_count_on_exit != 0 ? 0U : available - 1U;
        memw();
        current->notification_value = remaining;
    }
    memw();
    current = RTOS_CURRENT_TASKS[core];
    memw();
    current->notification_state = RTOS_NOTIFICATION_IDLE;
    vPortExitCritical(RTOS_KERNEL_LOCK);
    return available;
}

/* Native entry: 0x403887c0. */
/* Original function-byte SHA-256:
 * 9095d5f9f591eabdc2b06c84ed3b5a77e6225531004e3121715dcad21d84a2ec. */
/* Wait for this task's single notification state; only index 0 is accepted.
 * Reject other unsigned indices before locking. In the first lock phase, only
 * state RECEIVED BYTE2 bypasses entry-mask clearing and blocking. Otherwise
 * clear entry bits as value XOR (mask AND value), then store WAITING BYTE1 even
 * for a zero-tick poll. A nonzero ticks_to_wait calls the delayed-list helper
 * with indefinite blocking enabled and requests a yield using a fresh PRID.
 * Unlock/relock and select the current CPU/task again. Optional notification_value
 * receives the current WORD before state testing and exit-mask clearing, even
 * on timeout. Output may affect later reads if it aliases task storage.
 * Only exact state BYTE2 clears exit bits and returns 1; all other states return
 * 0. Always reset state to IDLE BYTE0. Preserve fresh native current-handle/value
 * reads, both lock phases and MEMWs. No notification allocation, retry loop,
 * delivery guarantee or exact-resume deadline; caller supplies live task context.
 */
int xTaskGenericNotifyWait(unsigned int index,unsigned int clear_bits_on_entry,unsigned int clear_bits_on_exit,unsigned int *notification_value,unsigned int ticks_to_wait)
{
    if (index != 0U)
        __assert_func(0,0,0,0);
    (void)xPortEnterCriticalTimeout(RTOS_KERNEL_LOCK,-1);
    unsigned int processor_id;
    __asm__ volatile ("rsr.prid %0" : "=a"(processor_id));
    unsigned int core = (processor_id >> 13) & 1U;
    memw();
    volatile RtosTask *current = RTOS_CURRENT_TASKS[core];
    memw();
    unsigned char state = current->notification_state;
    if (state != RTOS_NOTIFICATION_RECEIVED) {
        memw();
        current = RTOS_CURRENT_TASKS[core];
        memw();
        unsigned int previous = current->notification_value;
        memw();
        current->notification_value = previous ^ (clear_bits_on_entry & previous);
        memw();
        current = RTOS_CURRENT_TASKS[core];
        memw();
        current->notification_state = RTOS_NOTIFICATION_WAITING;
        if (ticks_to_wait != 0U) {
            prvAddCurrentTaskToDelayedList(ticks_to_wait,1);
            __asm__ volatile ("rsr.prid %0" : "=a"(processor_id));
            esp_crosscore_int_send_yield((processor_id >> 13) & 1U);
        }
    }
    vPortExitCritical(RTOS_KERNEL_LOCK);
    (void)xPortEnterCriticalTimeout(RTOS_KERNEL_LOCK,-1);
    __asm__ volatile ("rsr.prid %0" : "=a"(processor_id));
    core = (processor_id >> 13) & 1U;
    if (notification_value != 0) {
        memw();
        current = RTOS_CURRENT_TASKS[core];
        memw();
        unsigned int value = current->notification_value;
        *notification_value = value;
    }
    memw();
    current = RTOS_CURRENT_TASKS[core];
    memw();
    state = current->notification_state;
    int received = state == RTOS_NOTIFICATION_RECEIVED;
    if (received) {
        memw();
        current = RTOS_CURRENT_TASKS[core];
        memw();
        unsigned int previous = current->notification_value;
        memw();
        current->notification_value = previous ^ (clear_bits_on_exit & previous);
    }
    memw();
    current = RTOS_CURRENT_TASKS[core];
    memw();
    current->notification_state = RTOS_NOTIFICATION_IDLE;
    vPortExitCritical(RTOS_KERNEL_LOCK);
    return received;
}

/* Native entry: 0x403888a8. */
/* Original function-byte SHA-256:
 * bf68b9b9aa1c569c5491e43aed563fc3e2a1fdd4ff8373124ffbacfe45862ac6. */
/* Notify a live destination task at index 0; NULL task/other index assert first.
 * Under the kernel mux, optional previous_value receives the old count before
 * capturing the old state BYTE. Publish RECEIVED BYTE2 before applying action:
 * 0 leaves value unchanged, 1 ORs bits, 2 increments modulo 2^32, 3 overwrites,
 * 4 overwrites only if the old state was not RECEIVED. Action 4 rejection returns
 * 0 after unlock; its RECEIVED store and optional old-value output already occurred.
 * action is a full unsigned WORD. Invalid values assert only when the tick count
 * is nonzero; at tick 0 they continue with no value change and normal wake handling.
 * If the old state was WAITING BYTE1, unlink its state item and insert it into
 * its effective-priority ready list before asserting no event-list membership.
 * Preserve that partial-mutation failure order and all native cursor/link/count
 * rereads and MEMWs. Then check strict-priority preemption, requesting a local
 * yield only for helper result 1; the helper may request a remote yield itself.
 * Return 1 on other normal paths. No suspension deferral, next-wake recomputation,
 * reference pinning or remote-completion wait. Output aliases keep native order.
 */
int xTaskGenericNotify(RtosTask *task,unsigned int index,unsigned int value,unsigned int action,unsigned int *previous_value)
{
    if (index != 0U || task == 0)
        __assert_func(0,0,0,0);
    (void)xPortEnterCriticalTimeout(RTOS_KERNEL_LOCK,-1);
    volatile RtosTask *target = task;
    if (previous_value != 0) {
        memw();
        unsigned int previous = target->notification_value;
        *previous_value = previous;
    }
    memw();
    unsigned char previous_state = target->notification_state;
    memw();
    target->notification_state = RTOS_NOTIFICATION_RECEIVED;
    switch (action) {
    case RTOS_NOTIFY_NO_ACTION:
        break;
    case RTOS_NOTIFY_SET_BITS: {
        memw();
        unsigned int previous = target->notification_value;
        memw();
        target->notification_value = previous | value;
        break;
    }
    case RTOS_NOTIFY_INCREMENT: {
        memw();
        unsigned int previous = target->notification_value;
        memw();
        target->notification_value = previous + 1U;
        break;
    }
    case RTOS_NOTIFY_SET_IF_NOT_PENDING:
        if (previous_state == RTOS_NOTIFICATION_RECEIVED) {
            vPortExitCritical(RTOS_KERNEL_LOCK);
            return 0;
        }
        /* Native overwrite action shares this store. */
        __attribute__((fallthrough));
    case RTOS_NOTIFY_OVERWRITE:
        memw();
        target->notification_value = value;
        break;
    default:
        /* Retain the compiled firmware's tick-dependent assertion. The
         * received-state store above has already occurred on this path. */
        memw();
        if (*CLOCK_TICK_COUNT != 0U)
            __assert_func(0,0,0,0);
        break;
    }
    if (previous_state == RTOS_NOTIFICATION_WAITING) {
        unsigned int priority;
        volatile RtosListItem *state = &target->state_item;
        RtosListItem *state_identity = &task->state_item;
        memw();
        volatile RtosList *owning_list = state->container;
        memw();
        volatile RtosListItem *next = state->next;
        memw();
        RtosListItem *previous = state->previous;
        memw();
        next->previous = previous;
        memw();
        volatile RtosListItem *previous_view = state->previous;
        memw();
        RtosListItem *next_identity = state->next;
        memw();
        previous_view->next = next_identity;
        memw();
        RtosListItem *cursor = owning_list->index;
        if (cursor == state_identity) {
            memw();
            previous = state->previous;
            memw();
            owning_list->index = previous;
        }
        memw();
        state->container = 0;
        memw();
        unsigned int count = owning_list->count;
        memw();
        owning_list->count = count - 1U;
        priority = target->priority;
        memw();
        unsigned int top_priority = RTOS_TOP_READY_PRIORITY;
        if (top_priority < priority) {
            memw();
            RTOS_TOP_READY_PRIORITY = priority;
        }
        RtosList *ready_identity = &RTOS_READY_LISTS[priority];
        volatile RtosList *ready = ready_identity;
        memw();
        RtosListItem *index_identity = ready->index;
        volatile RtosListItem *ready_index = index_identity;
        memw();
        state->next = index_identity;
        memw();
        previous = ready_index->previous;
        memw();
        state->previous = previous;
        memw();
        previous_view = ready_index->previous;
        memw();
        previous_view->next = state_identity;
        memw();
        ready_index->previous = state_identity;
        memw();
        state->container = ready_identity;
        memw();
        count = ready->count;
        memw();
        ready->count = count + 1U;
        /* Native task-context notification checks this only after readying
         * the state item; the ISR variants check it before changing lists. */
        memw();
        if (target->event_item.container != 0)
            __assert_func(0,0,0,0);
        if (prvIsYieldRequiredSMP(task,priority,0) == 1) {
            unsigned int processor_id;
            __asm__ volatile ("rsr.prid %0" : "=a"(processor_id));
            esp_crosscore_int_send_yield((processor_id >> 13) & 1U);
        }
    }
    vPortExitCritical(RTOS_KERNEL_LOCK);
    return 1;
}

/* Native entry: 0x40388a04. */
/* Original function-byte SHA-256:
 * fba9a41ac6c07b7bbeafae01123086afe5d3bec2dc4c499eaa5a5e749df4d0fd. */
/* ISR notification action on a live task/index 0; NULL task/other index assert.
 * Under kernel mux, capture caller CPU, optionally output the old value, capture
 * old state, then publish RECEIVED BYTE2. Apply action 0/1/2/3/4 as no change,
 * OR, wrapping increment, overwrite, or overwrite only when old state was not 2.
 * Action 4 rejection returns 0 after the state store/output. Invalid unsigned
 * actions assert only for nonzero tick count; tick 0 continues without value change.
 * Only an old WAITING BYTE1 checks event-list membership and attempts waking.
 * This assertion precedes list changes but follows notification value/state writes.
 * An unpinned task can run if either CPU is unsuspended; other raw affinities
 * index suspension counts unchecked. If deferred, append its event item to the
 * CALLER CPU's pending-ready list even when pinned elsewhere; retain its blocked
 * state item. Otherwise unlink the state item and append it to its ready list.
 * Preserve the deferred priority sample between predecessor read/store and all
 * native cursor/link/count rereads, wrapping arithmetic and MEMWs.
 * Helper result exactly 1 first sets optional higher_priority_task_woken=1, then
 * sets this CPU's pending flag. Never clear either caller flag; NULL output does
 * not skip waking/helper work. Return 1 on other normal paths and unlock.
 * No direct local switch/yield call, ISR-priority validation or completion wait.
 */
int xTaskGenericNotifyFromISR(RtosTask *task,unsigned int index,unsigned int value,unsigned int action,unsigned int *previous_value,int *higher_priority_task_woken)
{
    if (task == 0 || index != 0U)
        __assert_func(0,0,0,0);
    (void)xPortEnterCriticalTimeout(RTOS_KERNEL_LOCK,-1);
    unsigned int processor_id;
    __asm__ volatile ("rsr.prid %0" : "=a"(processor_id));
    unsigned int core = (processor_id >> 13) & 1U;
    volatile RtosTask *target = task;
    if (previous_value != 0) {
        memw();
        unsigned int previous = target->notification_value;
        *previous_value = previous;
    }
    memw();
    unsigned char previous_state = target->notification_state;
    memw();
    target->notification_state = RTOS_NOTIFICATION_RECEIVED;
    switch (action) {
    case RTOS_NOTIFY_NO_ACTION:
        break;
    case RTOS_NOTIFY_SET_BITS: {
        memw();
        unsigned int previous = target->notification_value;
        memw();
        target->notification_value = previous | value;
        break;
    }
    case RTOS_NOTIFY_INCREMENT: {
        memw();
        unsigned int previous = target->notification_value;
        memw();
        target->notification_value = previous + 1U;
        break;
    }
    case RTOS_NOTIFY_SET_IF_NOT_PENDING:
        if (previous_state == RTOS_NOTIFICATION_RECEIVED) {
            vPortExitCritical(RTOS_KERNEL_LOCK);
            return 0;
        }
        /* Native overwrite action shares this store. */
        __attribute__((fallthrough));
    case RTOS_NOTIFY_OVERWRITE:
        memw();
        target->notification_value = value;
        break;
    default:
        /* Retain the compiled firmware's tick-dependent assertion. The
         * received-state store above has already occurred on this path. */
        memw();
        if (*CLOCK_TICK_COUNT != 0U)
            __assert_func(0,0,0,0);
        break;
    }
    if (previous_state == RTOS_NOTIFICATION_WAITING) {
        memw();
        if (target->event_item.container != 0)
            __assert_func(0,0,0,0);
        int affinity = target->core_id;
        bool defer_ready;
        if (affinity == 0x7fffffff) {
            memw();
            unsigned int suspended_cpu0 = RTOS_SCHEDULER_SUSPEND_COUNTS[0];
            defer_ready = false;
            if (suspended_cpu0 != 0U) {
                memw();
                defer_ready = RTOS_SCHEDULER_SUSPEND_COUNTS[1] != 0U;
            }
        } else {
            memw();
            defer_ready = RTOS_SCHEDULER_SUSPEND_COUNTS[(unsigned int)affinity] != 0U;
        }
        unsigned int priority;
        if (defer_ready) {
            /* This ISR queues on its own core, including when the target is
             * pinned to the other core. Its state item remains blocked. */
            RtosList *pending_identity = &RTOS_PENDING_READY_LISTS[core];
            volatile RtosList *pending = pending_identity;
            volatile RtosListItem *event = &target->event_item;
            RtosListItem *event_identity = &task->event_item;
            memw();
            RtosListItem *index_identity = pending->index;
            volatile RtosListItem *pending_index = index_identity;
            memw();
            event->next = index_identity;
            memw();
            RtosListItem *previous = pending_index->previous;
            priority = target->priority;
            memw();
            event->previous = previous;
            memw();
            volatile RtosListItem *previous_view = pending_index->previous;
            memw();
            previous_view->next = event_identity;
            memw();
            pending_index->previous = event_identity;
            memw();
            event->container = pending_identity;
            memw();
            unsigned int count = pending->count;
            memw();
            pending->count = count + 1U;
        } else {
            volatile RtosListItem *state = &target->state_item;
            RtosListItem *state_identity = &task->state_item;
            memw();
            volatile RtosList *owning_list = state->container;
            memw();
            volatile RtosListItem *next = state->next;
            memw();
            RtosListItem *previous = state->previous;
            memw();
            next->previous = previous;
            memw();
            volatile RtosListItem *previous_view = state->previous;
            memw();
            RtosListItem *next_identity = state->next;
            memw();
            previous_view->next = next_identity;
            memw();
            RtosListItem *cursor = owning_list->index;
            if (cursor == state_identity) {
                memw();
                previous = state->previous;
                memw();
                owning_list->index = previous;
            }
            memw();
            state->container = 0;
            memw();
            unsigned int count = owning_list->count;
            memw();
            owning_list->count = count - 1U;
            priority = target->priority;
            memw();
            unsigned int top_priority = RTOS_TOP_READY_PRIORITY;
            if (top_priority < priority) {
                memw();
                RTOS_TOP_READY_PRIORITY = priority;
            }
            RtosList *ready_identity = &RTOS_READY_LISTS[priority];
            volatile RtosList *ready = ready_identity;
            memw();
            RtosListItem *index_identity = ready->index;
            volatile RtosListItem *ready_index = index_identity;
            memw();
            state->next = index_identity;
            memw();
            previous = ready_index->previous;
            memw();
            state->previous = previous;
            memw();
            previous_view = ready_index->previous;
            memw();
            previous_view->next = state_identity;
            memw();
            ready_index->previous = state_identity;
            memw();
            state->container = ready_identity;
            memw();
            count = ready->count;
            memw();
            ready->count = count + 1U;
        }
        if (prvIsYieldRequiredSMP(task,priority,0) == 1) {
            if (higher_priority_task_woken != 0)
                *higher_priority_task_woken = 1;
            memw();
            RTOS_YIELD_PENDING[core] = 1;
        }
    }
    vPortExitCritical(RTOS_KERNEL_LOCK);
    return 1;
}

/* Native entry: 0x40388be4. */
/* Original function-byte SHA-256:
 * 3d36d6a12a8e547bc0372facf6f180443ff31487cd0c18c80b45ea9efaf3420f. */
/* ISR give for a live task/index 0; NULL task/other index assert before lock.
 * Under kernel mux, sample caller CPU and old state BYTE336, publish RECEIVED
 * BYTE2, then increment count WORD332 modulo 2^32. Only an old WAITING BYTE1
 * checks that event_item is unlinked; a failure retains those notification writes.
 * Ready a compatible unsuspended target by unlinking its state item and inserting
 * it into its effective-priority ready list. Otherwise append the event item to
 * this CALLER CPU's pending-ready list, retaining the blocked state item, even
 * when target affinity names the other CPU. Unpinned affinity checks CPU1 only
 * if CPU0 is suspended; other raw affinities index suspension counts unchecked.
 * Preserve native predecessor/count/priority read order and all MEMWs. A yield
 * helper result exactly 1 sets optional higher_priority_task_woken=1 before the
 * local pending flag; never clear the output. NULL output still performs the work.
 * Return void after unlock; no direct context switch, allocation, overflow guard,
 * ISR-priority validation, next-wake recomputation or completion wait.
 */
void vTaskGenericNotifyGiveFromISR(RtosTask *task,unsigned int index,int *higher_priority_task_woken)
{
    if (task == 0 || index != 0U)
        __assert_func(0,0,0,0);
    (void)xPortEnterCriticalTimeout(RTOS_KERNEL_LOCK,-1);
    unsigned int processor_id;
    __asm__ volatile ("rsr.prid %0" : "=a"(processor_id));
    unsigned int core = (processor_id >> 13) & 1U;
    volatile RtosTask *target = task;
    memw();
    unsigned char previous_state = target->notification_state;
    memw();
    target->notification_state = RTOS_NOTIFICATION_RECEIVED;
    memw();
    unsigned int previous = target->notification_value;
    memw();
    target->notification_value = previous + 1U;
    if (previous_state == RTOS_NOTIFICATION_WAITING) {
        memw();
        if (target->event_item.container != 0)
            __assert_func(0,0,0,0);
        int affinity = target->core_id;
        bool defer_ready;
        if (affinity == 0x7fffffff) {
            memw();
            unsigned int suspended_cpu0 = RTOS_SCHEDULER_SUSPEND_COUNTS[0];
            defer_ready = false;
            if (suspended_cpu0 != 0U) {
                memw();
                defer_ready = RTOS_SCHEDULER_SUSPEND_COUNTS[1] != 0U;
            }
        } else {
            memw();
            defer_ready = RTOS_SCHEDULER_SUSPEND_COUNTS[(unsigned int)affinity] != 0U;
        }
        unsigned int priority;
        if (defer_ready) {
            /* This ISR queues on its own core, including when the target is
             * pinned to the other core. Its state item remains blocked. */
            RtosList *pending_identity = &RTOS_PENDING_READY_LISTS[core];
            volatile RtosList *pending = pending_identity;
            volatile RtosListItem *event = &target->event_item;
            RtosListItem *event_identity = &task->event_item;
            memw();
            RtosListItem *index_identity = pending->index;
            volatile RtosListItem *pending_index = index_identity;
            memw();
            event->next = index_identity;
            memw();
            RtosListItem *previous = pending_index->previous;
            priority = target->priority;
            memw();
            event->previous = previous;
            memw();
            volatile RtosListItem *previous_view = pending_index->previous;
            memw();
            previous_view->next = event_identity;
            memw();
            pending_index->previous = event_identity;
            memw();
            event->container = pending_identity;
            memw();
            unsigned int count = pending->count;
            memw();
            pending->count = count + 1U;
        } else {
            volatile RtosListItem *state = &target->state_item;
            RtosListItem *state_identity = &task->state_item;
            memw();
            volatile RtosList *owning_list = state->container;
            memw();
            volatile RtosListItem *next = state->next;
            memw();
            RtosListItem *previous = state->previous;
            memw();
            next->previous = previous;
            memw();
            volatile RtosListItem *previous_view = state->previous;
            memw();
            RtosListItem *next_identity = state->next;
            memw();
            previous_view->next = next_identity;
            memw();
            RtosListItem *cursor = owning_list->index;
            if (cursor == state_identity) {
                memw();
                previous = state->previous;
                memw();
                owning_list->index = previous;
            }
            memw();
            state->container = 0;
            memw();
            unsigned int count = owning_list->count;
            memw();
            owning_list->count = count - 1U;
            priority = target->priority;
            memw();
            unsigned int top_priority = RTOS_TOP_READY_PRIORITY;
            if (top_priority < priority) {
                memw();
                RTOS_TOP_READY_PRIORITY = priority;
            }
            RtosList *ready_identity = &RTOS_READY_LISTS[priority];
            volatile RtosList *ready = ready_identity;
            memw();
            RtosListItem *index_identity = ready->index;
            volatile RtosListItem *ready_index = index_identity;
            memw();
            state->next = index_identity;
            memw();
            previous = ready_index->previous;
            memw();
            state->previous = previous;
            memw();
            previous_view = ready_index->previous;
            memw();
            previous_view->next = state_identity;
            memw();
            ready_index->previous = state_identity;
            memw();
            state->container = ready_identity;
            memw();
            count = ready->count;
            memw();
            ready->count = count + 1U;
        }
        if (prvIsYieldRequiredSMP(task,priority,0) == 1) {
            if (higher_priority_task_woken != 0)
                *higher_priority_task_woken = 1;
            memw();
            RTOS_YIELD_PENDING[core] = 1;
        }
    }
    vPortExitCritical(RTOS_KERNEL_LOCK);
}

/* Native entry: 0x40388d74. */
/* Original function-byte SHA-256:
 * 18835783c67e84883939d11d353ade02a6b8658ae050657976a022ce6b38e27c. */
/* CPU1 tick-side scheduling check; CPU0 asserts before reading scheduler state.
 * No parameters; return 0/1. Read this core's suspension count without kernel
 * mux; a nonzero value returns 0 without acquiring it. Otherwise lock, sample
 * current priority and ready-list count, unlock, then read yield_pending even
 * if multiple same-priority tasks already require a switch. OR the two tests.
 * Preserve MEMWs and these distinct observation points. No shared tick advance,
 * delayed-task removal, context switch or coherent all-CPU snapshot here.
 */
int xTaskIncrementTickOtherCores(void)
{
    unsigned int processor_id;
    __asm__ volatile ("rsr.prid %0" : "=a"(processor_id));
    unsigned int core = (processor_id >> 13) & 1U;
    if (core == 0U)
        __assert_func(0,0,0,0);
    memw();
    unsigned int suspend_count = RTOS_SCHEDULER_SUSPEND_COUNTS[core];
    if (suspend_count != 0U)
        return 0;
    (void)xPortEnterCriticalTimeout(RTOS_KERNEL_LOCK,-1);
    memw();
    volatile RtosTask *current = RTOS_CURRENT_TASKS[core];
    unsigned int priority = current->priority;
    memw();
    unsigned int ready_count = ((volatile RtosList *)RTOS_READY_LISTS)[priority].count;
    vPortExitCritical(RTOS_KERNEL_LOCK);
    memw();
    unsigned int yield_pending = RTOS_YIELD_PENDING[core];
    return (yield_pending != 0U) | (ready_count > 1U);
}

/* Native entry: 0x40388ddc. */
/* Original function-byte SHA-256:
 * 18977a61498f6ef0cc916ba397b7534411a707f2005cd9c0b276e7fe2dcc219d. */
/* Create a task with a heap-allocated byte stack and 340-byte TCB.
 * Accept core_id 0/1/INT32_MAX; other raw signed values assert before allocation.
 * entry/argument form TaskEntry(void*); optional name and created_task pass to
 * the initializer. stack_bytes is the raw unsigned allocation/fill byte count;
 * priority is validated later by that initializer after stack/TCB writes.
 * Allocate stack first, then TCB. Either failure returns -1, freeing only the
 * successful stack if TCB allocation failed. Do not clear created_task on failure.
 * Zero the full TCB, store stack_base then allocation_kind BYTE0, initialize
 * the task and publish any created_task output, then insert it into ready lists.
 * Return 1. Ready insertion may request preemption before this call returns.
 * No explicit stack-size/entry/name validation or rollback from later assertions.
 * Kernel ownership of successful buffers follows the dynamic allocation flag.
 */
int xTaskCreatePinnedToCore(TaskEntry entry,char *name,unsigned int stack_bytes,void *argument,unsigned int priority,RtosTask **created_task,int core_id)
{
    if ((unsigned int)core_id > 1U && core_id != 0x7fffffff)
        __assert_func(0,0,0,0);
    void *stack = pvPortMalloc(stack_bytes);
    if (stack == 0)
        return -1;
    RtosTask *task = pvPortMalloc(sizeof(RtosTask));
    if (task == 0) {
        vPortFree(stack);
        return -1;
    }
    memset(task,0,sizeof(RtosTask));
    task->stack_base = stack;
    task->allocation_kind = 0;
    prvInitialiseNewTask(entry,name,stack_bytes,argument,priority,created_task,task,core_id);
    prvAddNewTaskToReadyList(task);
    return 1;
}

/* Native entry: 0x40388e78. */
/* Original function-byte SHA-256:
 * 989328937f33b2dcb4bad0c7519ece7faad6f190a70ba02a9a5120ee8b633c39. */
/* Create a task using caller-owned BYTE stack and writable 340-byte TCB.
 * entry/name/argument/priority pass to the initializer; optional name is copied
 * there, and priority<=24 is asserted after earlier construction effects.
 * Validate stack address first, then TCB address, then core_id 0/1/INT32_MAX.
 * Any admission/core failure asserts before NULL checks or clearing the TCB.
 * Preserve the volatile local size WORD340 store/read/compare/discarded-read
 * sequence and its three MEMWs. Only then return NULL for missing stack/TCB.
 * Zero TCB340, store stack_base and allocation_kind BYTE2, initialize through
 * a local created-task output, make the TCB ready, then return that local handle.
 * No allocation, complete buffer-extent check, ownership transfer or rollback.
 * Buffers must remain live for the task; static deletion frees neither one.
 */
RtosTask *xTaskCreateStaticPinnedToCore(TaskEntry entry,char *name,unsigned int stack_bytes,void *argument,unsigned int priority,unsigned char *stack,RtosTask *task_buffer,int core_id)
{
    if (xPortcheckValidStackMem(stack) == 0U)
        __assert_func(0,0,0,0);
    if (xPortCheckValidTCBMem(task_buffer) == 0U)
        __assert_func(0,0,0,0);
    if ((unsigned int)core_id > 1U && core_id != 0x7fffffff)
        __assert_func(0,0,0,0);

    /* ESP-IDF's static-TCB size assertion uses a volatile local, then reads
     * it a second time for its discarded-value expression. Keep all accesses. */
    volatile unsigned int static_task_size;
    memw();
    static_task_size = 340U;
    memw();
    unsigned int observed_size = static_task_size;
    if (observed_size != sizeof(RtosTask))
        __assert_func(0,0,0,0);
    memw();
    (void)static_task_size;
    if (task_buffer == 0 || stack == 0)
        return 0;
    memset(task_buffer,0,sizeof(RtosTask));
    task_buffer->stack_base = stack;
    task_buffer->allocation_kind = 2;
    RtosTask *created_task;
    prvInitialiseNewTask(entry,name,stack_bytes,argument,priority,&created_task,task_buffer,core_id);
    prvAddNewTaskToReadyList(task_buffer);
    return created_task;
}

/* Native entry: 0x40388f1c. */
/* Original function-byte SHA-256:
 * 75a8a25e95253ddd92db5b741dde4d22b501658f5820d03e93094fc6af09c35c. */
/* Start scheduling after creating per-core priority-0 IDLE0 and IDLE1 tasks.
 * No parameters. For each core obtain a fresh stack/TCB from the application
 * allocation hook, pass their BYTE stack/length to the static-task constructor,
 * publish its handle, then test for failure. Stop on the first NULL; no cleanup
 * rolls back earlier buffers or tasks. Pass the idle entry and NULL argument.
 * If both succeeded, call xTimerCreateTimerTask. The linked weak stub returns 1
 * and creates no FreeRTOS timer daemon. Result -1 asserts; other non-1 values
 * return through the final debugger-bound read without starting the port.
 * On result 1, RSIL3 discards saved PS, enter the kernel mux, MEMW/store next
 * unblock UINT32_MAX, running flag 1, and tick 0 in that order; unlock and call
 * the scheduler port. No PS restoration or global Newlib-context update here.
 * The linked port transfers control without a normal return. Any returning
 * startup path retains the MEMW/discarded uxTopUsedPriority debugger-bound read.
 */
void vTaskStartScheduler(void)
{
    bool idle_tasks_created = true;
    for (unsigned int core = 0; core < 2U; ++core) {
        char idle_name[16];
        idle_name[0] = 'I';
        idle_name[1] = 'D';
        idle_name[2] = 'L';
        idle_name[3] = 'E';
        idle_name[4] = (char)('0' + core);
        idle_name[5] = '\0';
        RtosTask *task_buffer = 0;
        unsigned char *stack = 0;
        unsigned int stack_bytes;
        vApplicationGetIdleTaskMemory(&task_buffer,&stack,&stack_bytes);
        RtosTask *idle_task = xTaskCreateStaticPinnedToCore(
            prvIdleTask,idle_name,stack_bytes,0,0,stack,task_buffer,(int)core);
        RTOS_IDLE_TASK_HANDLES[core] = idle_task;
        if (idle_task == 0) {
            idle_tasks_created = false;
            break;
        }
    }
    if (idle_tasks_created) {
        int timer_task_result = xTimerCreateTimerTask();
        if (timer_task_result == 1) {
            unsigned int discarded_processor_status;
            __asm__ volatile ("rsil %0,3" : "=a"(discarded_processor_status) : : "memory");
            (void)xPortEnterCriticalTimeout(RTOS_KERNEL_LOCK,-1);
            memw();
            RTOS_NEXT_UNBLOCK_TICK = 0xffffffffU;
            memw();
            RTOS_SCHEDULER_RUNNING = 1;
            memw();
            *CLOCK_TICK_COUNT = 0;
            vPortExitCritical(RTOS_KERNEL_LOCK);
            (void)xPortStartScheduler();
        } else if (timer_task_result == -1) {
            __assert_func(0,0,0,0);
        }
    }
    /* Keep the native discarded read that retains OpenOCD's priority-list
     * bound. It is reached only on paths that return from startup. */
    memw();
    (void)RTOS_DEBUGGER_TOP_USED_PRIORITY;
}

/* Native entry: 0x40388fc4. */
/* Original function-byte SHA-256:
 * 41624daccb36788f394bcc820c9b902e16a3e90690a162285cbbc72800bdc6be. */
/* Read raw signed task affinity WORD68; task is a live TCB or NULL for current.
 * NULL selection uses RSIL3, PRID bit13 and a MEMW current-pointer read, then
 * restores only PS.INTLEVEL through ROM before reading affinity. No NULL-current
 * guard, mux, lifetime pinning or affinity validation. Normal stored values
 * are 0/1/INT32_MAX; an explicit TCB's other raw values are returned unchanged.
 */
int xTaskGetCoreID(RtosTask *task)
{
    if (task == 0) {
        unsigned int saved_processor_status;
        __asm__ volatile ("rsil %0,3" : "=a"(saved_processor_status) : : "memory");
        unsigned int processor_id;
        __asm__ volatile ("rsr.prid %0" : "=a"(processor_id));
        memw();
        task = RTOS_CURRENT_TASKS[(processor_id >> 13) & 1U];
        (void)_xtos_set_intlevel(saved_processor_status);
    }
    return task->core_id;
}

/* Native entry: 0x40388fec. */
/* Original function-byte SHA-256:
 * c650bf600080d90b068363e8cad4a229cdb7f894d61dd8391d9788dcaa1fa81e. */
/* Return the cached nonnull idle-task handle for core_id 0 or 1.
 * Unsigned validation rejects negative and >=2 values before indexing. A NULL
 * handle asserts. No explicit MEMW, kernel mux, TCB dereference or retained
 * reference; caller supplies a valid initialized scheduler lifetime.
 */
RtosTask *xTaskGetIdleTaskHandleForCore(int core_id)
{
    if ((unsigned int)core_id >= 2U)
        __assert_func(0,0,0,0);
    RtosTask *idle_task = RTOS_IDLE_TASK_HANDLES[core_id];
    if (idle_task == 0)
        __assert_func(0,0,0,0);
    return idle_task;
}

/* Native entry: 0x40389010. */
/* Original function-byte SHA-256:
 * d5be4a6e0ac8881643c5eb11fe577de35c463914039e2dc687af91f842a3dbf2. */
/* Return a snapshot of the selected core's current task, possibly NULL.
 * core_id is signed but checked as unsigned: only 0/1 pass, others assert.
 * MEMW precedes the single current-pointer WORD read. No kernel mux, interrupt
 * mask, TCB dereference, reference pinning or task-completion guarantee.
 */
RtosTask *xTaskGetCurrentTaskHandleForCore(int core_id)
{
    if ((unsigned int)core_id >= 2U)
        __assert_func(0,0,0,0);
    memw();
    return RTOS_CURRENT_TASKS[core_id];
}

/* Native entry: 0x40389034. */
/* Original function-byte SHA-256:
 * dd4f72a15059761e9c078bc9e0dfd85e380c48aec471d98e9a697821a996d705. */
/* Set a live task's application TLS value and deletion callback under kernel mux.
 * task may be NULL to select current via RSIL3/PRID/MEMW, restoring only
 * PS.INTLEVEL through ROM before the stores. callback is void(int,void*) or NULL;
 * it is stored, not invoked, and the overwritten value/callback is not disposed.
 * Native signed index>=1 returns before any lock or task access. Index 0 is
 * valid; negative indices are also accepted and shift both stores before the
 * TLS fields. Preserve that missing guard and modulo-32 address arithmetic:
 * value at task+4*index+84, callback at task+4*index+88, in that order.
 * No callback validation, allocation, bounds repair, rollback or lifetime pin.
 */
void vTaskSetThreadLocalStoragePointerAndDelCallback(RtosTask *task,int index,void *value,TlsDeleteCallback callback)
{
    if (index >= 1)
        return;
    (void)xPortEnterCriticalTimeout(RTOS_KERNEL_LOCK,-1);
    if (task == 0) {
        unsigned int saved_processor_status;
        __asm__ volatile ("rsil %0,3" : "=a"(saved_processor_status) : : "memory");
        unsigned int processor_id;
        __asm__ volatile ("rsr.prid %0" : "=a"(processor_id));
        memw();
        task = RTOS_CURRENT_TASKS[(processor_id >> 13) & 1U];
        (void)_xtos_set_intlevel(saved_processor_status);
    }
    /* Preserve native modulo32 address arithmetic for the missing negative-
     * index guard. For index0 these are the named TCB fields; a negative
     * index shifts both stores before those fields and can corrupt storage. */
    unsigned int indexed_address = (unsigned int)task + (unsigned int)index * 4U;
    volatile RtosTask *indexed_task = (RtosTask *)indexed_address;
    indexed_task->thread_local_storage = value;
    indexed_task->tls_delete_callback = callback;
    vPortExitCritical(RTOS_KERNEL_LOCK);
}


/* Native entry: 0x403879c8. */
/* Original function-byte SHA-256:
 * 82d05ad9306538d507c93e3403c2a9091d8c1813cc506ff99ec6ca78b7e4e558. */
/*
 * Returns a borrowed pointer to the selected task's 16-byte name field.
 *
 * task: live task control block, or NULL to select this CPU's current task.
 * Returns task->name at TCB offset 0x34. Does not copy or validate the text,
 * check its terminator, or extend the task's lifetime.
 *
 * The native NULL path inlines xTaskGetCurrentTaskHandle: interrupt level 3,
 * a fresh PRID bit-13 selection of pxCurrentTCBs, a MEMW-ordered pointer read,
 * then restoration of the interrupt-level bits of the previous PS word.
 * A missing selected TCB asserts after
 * processor status has been restored. An explicit handle takes the direct
 * field-address path without changing interrupt level.
 */
char *pcTaskGetName(RtosTask *task)
{
    if (task == 0) {
        unsigned int saved_processor_status;
        __asm__ volatile ("rsil %0,3" : "=a"(saved_processor_status) : : "memory");
        unsigned int processor_id;
        __asm__ volatile ("rsr.prid %0" : "=a"(processor_id));
        memw();
        task = RTOS_CURRENT_TASKS[(processor_id >> 13) & 1U];
        (void)_xtos_set_intlevel(saved_processor_status);
        if (task == 0)
            __assert_func(0,0,0,0);
    }
    return task->name;
}

/* Native entry: 0x40387998. */
/* Original function-byte SHA-256:
 * 7d3235e3e4c9d8c666e06a44e21a9ece745fb52e2bf98917d854e7bbbf9a568f. */
/* MEMW, then return the single native32 kernel tick word. No critical section,
 * scheduler-state test, per-core selection, unit conversion or retry. The result
 * wraps modulo32 as the kernel tick count advances; it is not elapsed wall time. */
unsigned int xTaskGetTickCount(void)
{
    memw();
    return *CLOCK_TICK_COUNT;
}
