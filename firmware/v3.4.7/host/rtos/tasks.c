/* Medius v3.4.7 host — rtos/tasks.c.
 * Recovered C and native assembly, grouped for source navigation.
 * Original entry addresses, firmware-byte hashes and function comments follow.
 */

#include "../include/types.h"

/* Native entry: 0x403820f0. */
/*
 * Medius v3.4.7 — host application; 0x403820f0.
 *
 * Allocates a 1536-byte idle stack and 340-byte TCB, asserts allocation success and returns their addresses.
 *
 * Calls: __assert_func, pvPortMalloc.
 *
 * Called by: vTaskStartScheduler.
 *
 * Original function-byte SHA-256:
 * 18b007a2b635f1a78d63125febeb03c7699480b2a665c22f461303bd776c8f19.
 */

/* Allocates a 1536-byte idle stack and 340-byte TCB, asserts allocation success and returns their addresses.
   SDK match: ESP-IDF v5.4.4 components/freertos/port_common.c.
   Recovered types/control flow retain the original function bytes and non-returning assertion paths. */

/*
 * task_buffer: Required writable output receiving a newly allocated340-byte idle-task TCB.
 * stack_buffer: Required writable output receiving a newly allocated1536-byte stack buffer.
 * stack_bytes: Required writable uint32 output receiving1536, in the byte units used by this
 *   build.
 * Returns: Nothing; either failed allocation asserts.
 * Requirements/effects: Performs two heap allocations each time, then publishes all outputs. Does
 *   not free a successful partial allocation if the other allocation fails before aborting.
 */

void vApplicationGetIdleTaskMemory
               (RtosTask **task_buffer,uint **stack_buffer,uint *stack_bytes)

{
  uint *idle_stack;
  RtosTask *idle_task;

  idle_stack = pvPortMalloc(0x600);
  idle_task = pvPortMalloc(0x154);
  if ((idle_task == (RtosTask *)0x0) || (idle_stack == (uint *)0x0)) {
                    /* WARNING: Subroutine does not return */
    __assert_func((char *)0x0,0,(char *)0x0,(char *)0x0);
  }
  *task_buffer = idle_task;
  *stack_buffer = idle_stack;
  *stack_bytes = 0x600;
  return;
}

/* Native entry: 0x40382418. */
/*
 * Medius v3.4.7 — host application; 0x40382418.
 *
 * Checks affinity and scheduler suspension; requests a remote yield or returns whether this core must yield.
 *
 * Calls: FUN_40381d8c, __assert_func.
 *
 * Called by: prvAddNewTaskToReadyList, vTaskPrioritySet, xTaskResumeAll, xTaskRemoveFromEventList, xTaskGenericNotify, vTaskGenericNotifyGiveFromISR.
 *
 * Original function-byte SHA-256:
 * 7853c806e503e96459d5373f58924a70225b751cac296582bd53ead0ec47b7f3.
 */

/* Checks affinity and scheduler suspension; requests a remote yield or returns whether this core must yield.
   SDK match: ESP-IDF v5.4.4 components/freertos/FreeRTOS-Kernel/tasks.c.
   Recovered types/control flow retain the original function bytes and non-returning assertion paths. */

/*
 * task: Valid TCB whose core affinity is inspected.
 * priority: Ready priority, asserted at most 24 before any equal-priority adjustment.
 * yield_equal_priority: Exactly 1 raises the comparison threshold by one, allowing equal
 *   priorities to preempt.
 * Returns: 1 if this CPU should yield; otherwise 0, possibly after requesting a remote yield.
 * Requirements/effects: Requires scheduler state and affinity values 0, 1 or INT32_MAX. A
 *   suspended target scheduler is skipped. Sends a remote request asynchronously; does not choose
 *   a new task.
 */

int prvIsYieldRequiredSMP(RtosTask *task,uint priority,int yield_equal_priority)
{
  if (priority > 24U) __assert_func(0,0,0,0);
  uint core = (xtensa_read_prid() >> 13) & 1U;
  uint affinity = (uint)((volatile RtosTask *)task)->core_id;
  uint threshold = priority + (yield_equal_priority == 1 ? 1U : 0U);
  if (affinity == core || affinity == 0x7fffffffU) {
    memw();
    RtosTask *current = RTOS_CURRENT_TASKS[core];
    uint current_priority = ((volatile RtosTask *)current)->priority;
    if (current_priority < threshold) {
      memw();
      if (RTOS_SCHEDULER_SUSPEND_COUNTS[core] == 0) return 1;
    }
    if (affinity == core) return 0;
  }
  uint other_core = core == 0 ? 1U : 0U;
  if (affinity != other_core && affinity != 0x7fffffffU) return 0;
  memw();
  RtosTask *current = RTOS_CURRENT_TASKS[other_core];
  uint current_priority = ((volatile RtosTask *)current)->priority;
  if (current_priority < threshold) {
    memw();
    if (RTOS_SCHEDULER_SUSPEND_COUNTS[other_core] == 0)
      vPortYieldOtherCore((int)other_core);
  }
  return 0;
}

/* Native entry: 0x403824e8. */
/*
 * Medius v3.4.7 — host application; 0x403824e8.
 * Instruction-checked recovered C.
 * Original function-byte SHA-256:
 * 9ab85110c10f633c3424f8ce23b35d98ecb34eec3a34cf72d151d545615ccec9.
 */

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

/* Native entry: 0x403825dc. */
/*
 * Medius v3.4.7 — host application; 0x403825dc.
 *
 * Initializes scheduler lists for the first task, adds a new task to its ready list and requests preemption as needed.
 *
 * Calls: esp_crosscore_int_send_yield, vListInitialise, prvIsYieldRequiredSMP, vPortExitCritical, xPortEnterCriticalTimeout.
 *
 * Called by: xTaskCreateStaticPinnedToCore, xTaskCreatePinnedToCore.
 *
 * Original function-byte SHA-256:
 * 5d96b2c92546194c3e3fd9e83a255be7d02691ea9e949926e641504a825f21a7.
 */

/* Initializes scheduler lists for the first task, adds a new task to its ready list and requests preemption as needed.
   SDK match: ESP-IDF v5.4.4 components/freertos/FreeRTOS-Kernel/tasks.c.
   Recovered types/control flow retain the original function bytes and non-returning assertion paths. */

/*
 * task: Initialized unlinked TCB with valid priority, affinity and state-item owner.
 * Returns: Nothing.
 * Requirements/effects: Under the kernel lock, initializes global lists for the first task,
 *   updates task numbering and top priority, and links the state item. Before scheduler start it
 *   also selects provisional current tasks; during execution it requests preemption when needed.
 *   Does not allocate TCB or stack.
 */

void prvAddNewTaskToReadyList(RtosTask *task)
{
  (void)xPortEnterCriticalTimeout(RTOS_KERNEL_LOCK,-1);
  memw();
  uint count = RTOS_TASK_COUNT;
  memw();
  RTOS_TASK_COUNT = count + 1U;
  memw();
  if (RTOS_TASK_COUNT == 1) {
    for (uint priority = 0; priority < 25U; ++priority)
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
  uint priority = state->priority;
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
  uint task_number = RTOS_TASK_NUMBER;
  memw();
  uint top_priority = RTOS_TOP_READY_PRIORITY;
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
    uint core = (xtensa_read_prid() >> 13) & 1U;
    esp_crosscore_int_send_yield((int)core);
  }
  vPortExitCritical(RTOS_KERNEL_LOCK);
}

/* Native entry: 0x40382790. */
/*
 * Medius v3.4.7 — host application; 0x40382790.
 *
 * Runs task deletion/TLS cleanup and frees only the stack/TCB allocations owned by the kernel.
 *
 * Calls: vPortFree, __assert_func, newlib_reclaim_reent, vPortTCBPreDeleteHook.
 *
 * Called by: prvIdleTask, vTaskDelete.
 *
 * Original function-byte SHA-256:
 * 6b206500012e878801bba4c200877284aa67d6573b4241ac4140fc75676b77ed.
 */

/* Runs task deletion/TLS cleanup and frees only the stack/TCB allocations owned by the kernel.
   SDK match: ESP-IDF v5.4.4 components/freertos/FreeRTOS-Kernel/tasks.c.
   Recovered types/control flow retain the original function bytes and non-returning assertion paths. */

/* Runs TLS deletion/coprocessor cleanup, reclaims the task Newlib context and frees only the stack/TCB allocations owned by the kernel.
   Reference: ESP-IDF v5.4.4 components/freertos/FreeRTOS-Kernel/tasks.c. */

/*
 * task: Terminated live TCB, no longer scheduled or used by another task.
 * Returns: Nothing; invalid allocation kind asserts after cleanup.
 * Requirements/effects: Runs port pre-delete/TLS cleanup and reclaims the embedded Newlib context.
 *   Kind0 frees stack and TCB, kind1 frees only TCB, kind2 frees neither. Does not remove
 *   scheduler list items itself or protect concurrent references.
 */

void prvDeleteTCB(RtosTask *task)

{
  uchar allocation_kind;

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

/* Native entry: 0x403827d8. */
/*
 * Medius v3.4.7 — host application; 0x403827d8.
 * Instruction-checked recovered C.
 * Original function-byte SHA-256:
 * aa08ac3b6543913e7218bf6eb1c389949543026220214fe419e58cf57eb44e99.
 */

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

/* Native entry: 0x40382870. */
/*
 * Medius v3.4.7 — host application; 0x40382870.
 *
 * Fills the stack with 0xA5, aligns its top, initializes the TCB/list items and constructs the initial task context.
 *
 * Calls: esp_reent_init, pxPortInitialiseStack, vListInitialiseItem, __assert_func, memset.
 *
 * Called by: xTaskCreateStaticPinnedToCore, xTaskCreatePinnedToCore.
 *
 * Original function-byte SHA-256:
 * ba658f88cfec68df8e509cfd8bb519766bbf603cb082e027893e24171396991f.
 */

/* Fills the stack with 0xA5, aligns its top, initializes the TCB/list items and constructs the initial task context.
   SDK match: ESP-IDF v5.4.4 components/freertos/FreeRTOS-Kernel/tasks.c.
   Recovered types/control flow retain the original function bytes and non-returning assertion paths. */

/* Initializes the task stack, scheduler list items and 240-byte Newlib context, constructs the initial Xtensa context and optionally returns the created TCB.
   Reference: ESP-IDF v5.4.4 components/freertos/FreeRTOS-Kernel/tasks.c. */

/* Fills the stack with 0xa5, aligns its top, initializes task/list/Newlib fields and stores the stack initializer RETURN value as the TCB saved stack pointer. Copies at most 16 name bytes and enforces a trailing NUL; priorities above 24 assert.
   Reference: ESP-IDF v5.4.4 components/freertos/FreeRTOS-Kernel/tasks.c. */

/*
 * entry: Task entry address placed into the initial processor frame.
 * name: Optional readable NUL-terminated name; at most16 bytes are read and byte15 is forced to
 *   NUL.
 * stack_bytes: Nonzero valid stack buffer length in bytes, sufficient for the frame below its
 *   aligned top.
 * argument: Opaque task entry argument.
 * priority: Initial priority0..24; larger values assert after stack/name writes.
 * created_task: Optional output receiving task after initialization.
 * task: Writable initialized340-byte TCB whose stack_base points to adequate live storage.
 * core_id: Affinity value already validated by the caller; stored without a check here.
 * Returns: Nothing; an invalid priority aborts through assertion.
 * Requirements/effects: Fills the entire supplied stack with0xa5, aligns its top down to16, sets
 *   priority/base/affinity, initializes embedded list items and owners, sets inverse event
 *   priority, initializes the240-byte Newlib context and creates the saved CPU frame. Does not
 *   allocate, add the task to ready lists, clear every TCB field or validate stack extent. NULL
 *   name leaves name bytes unchanged.
 */

void prvInitialiseNewTask
               (TaskEntry entry,char *name,uint stack_bytes,void *argument,uint priority,
               RtosTask **created_task,RtosTask *task,int core_id)

{
  char name_character;
  uint *stack_pointer;

  memset(task->stack_base,0xa5,stack_bytes);
  stack_pointer = (uint *)((int)task->stack_base + (stack_bytes - 1) & 0xfffffff0);
  task->stack_end = stack_pointer;
  if (name != (char *)0x0) {
    /* Native LOOP limit is16; a NUL exits before the next iteration. */
    for (uint name_index = 0; name_index < 16; ++name_index) {
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
  task->priority = priority;
  task->core_id = core_id;
  task->base_priority = priority;
  vListInitialiseItem(&task->state_item);
  vListInitialiseItem(&task->event_item);
  (task->state_item).owner = task;
  memw();
  (task->event_item).value = -(priority - 0x19);
  (task->event_item).owner = task;
  esp_reent_init(&task->libc_reent);
  stack_pointer = pxPortInitialiseStack(stack_pointer,entry,argument);
  task->top_of_stack = stack_pointer;
  if (created_task != (RtosTask **)0x0) {
    *created_task = task;
  }
  return;
}

/* Native entry: 0x403828fc. */
/*
 * Medius v3.4.7 — host application; 0x403828fc.
 *
 * Removes a task from scheduler/event lists; defers a running task for idle cleanup or deletes an inactive TCB.
 *
 * Calls: esp_crosscore_int_send_yield, FUN_40381d8c, vListInsertEnd, uxListRemove, prvDeleteTCB, __assert_func,
 * _xtos_set_intlevel, vPortExitCritical, xPortEnterCriticalTimeout.
 *
 * Called by: FUN_42013f48, main_task, usb_osal_thread_delete.
 *
 * Original function-byte SHA-256:
 * db0ecd1056ea2d8f2a8fec5fcf0101616f2d64e9371dbfdb589ecec39134a18d.
 */

/* Removes a task from scheduler/event lists; defers a running task for idle cleanup or deletes an inactive TCB.
   SDK match: ESP-IDF v5.4.4 components/freertos/FreeRTOS-Kernel/tasks.c.
   Recovered types/control flow retain the original function bytes and non-returning assertion paths. */

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
  RtosListItem *item = &task->state_item;
  (void)uxListRemove(item);
  memw();
  if (state->event_item.container != 0) (void)uxListRemove(&task->event_item);
  uint task_number = RTOS_TASK_NUMBER;
  memw();
  RtosTask *local_task = RTOS_CURRENT_TASKS[core];
  RTOS_TASK_NUMBER = task_number + 1U;
  if (local_task == task) {
    vListInsertEnd(RTOS_TERMINATION_LIST,item);
    memw();
    uint pending = RTOS_PENDING_DELETIONS;
    memw();
    RTOS_PENDING_DELETIONS = pending + 1U;
    vPortExitCritical(RTOS_KERNEL_LOCK);
    (void)xPortEnterCriticalTimeout(RTOS_KERNEL_LOCK,-1);
    memw();
    if (RTOS_SCHEDULER_RUNNING != 0) {
      uint previous_ps;
      __asm__ volatile ("rsil %0,3" : "=a"(previous_ps) :: "memory");
      memw();
      if (RTOS_SCHEDULER_RUNNING != 0) {
        uint current_core = (xtensa_read_prid() >> 13) & 1U;
        memw();
        if (RTOS_SCHEDULER_SUSPEND_COUNTS[current_core] != 0) {
          (void)_xtos_set_intlevel((int)previous_ps);
          __assert_func(0,0,0,0);
        }
      }
      (void)_xtos_set_intlevel((int)previous_ps);
      uint current_core = (xtensa_read_prid() >> 13) & 1U;
      esp_crosscore_int_send_yield((int)current_core);
    }
  } else {
    uint other_core = core == 0 ? 1U : 0U;
    memw();
    if (RTOS_CURRENT_TASKS[other_core] == task) {
      vListInsertEnd(RTOS_TERMINATION_LIST,item);
      memw();
      uint pending = RTOS_PENDING_DELETIONS;
      memw();
      RTOS_PENDING_DELETIONS = pending + 1U;
      vPortYieldOtherCore((int)other_core);
      vPortExitCritical(RTOS_KERNEL_LOCK);
    } else {
      memw();
      uint count = RTOS_TASK_COUNT;
      memw();
      RTOS_TASK_COUNT = count - 1U;
      memw();
      RtosList *delayed = RTOS_ACTIVE_DELAYED_LIST;
      memw();
      uint delayed_count = ((volatile RtosList *)delayed)->count;
      if (delayed_count == 0) {
        memw();
        RTOS_NEXT_UNBLOCK_TICK = 0xffffffffU;
      } else {
        memw();
        delayed = RTOS_ACTIVE_DELAYED_LIST;
        memw();
        RtosListItem *first = ((volatile RtosList *)delayed)->end_marker.next;
        memw();
        uint wake_tick = ((volatile RtosListItem *)first)->value;
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

/* Native entry: 0x40382a7c. */
/*
 * Medius v3.4.7 — host application; 0x40382a7c.
 * Instruction-checked recovered C.
 * Original function-byte SHA-256:
 * be40a7be38b9d006e8b152643a57d57a1b6753a4dc4ee41a19209871607c797b.
 */

/* Relative task delay in kernel ticks; zero skips list/lock/assert work and
 * only requests this core's yield. For nonzero delay, RSIL3 saves the full PS,
 * then test this core's scheduler-suspend count only if scheduler is running.
 * Restore PS through ROM before a fatal suspended-scheduler assertion, or on
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

/* Native entry: 0x40382ae0. */
/*
 * Medius v3.4.7 — host application; 0x40382ae0.
 *
 * Returns the effective task priority under the scheduler lock. NULL selects the current task on the calling CPU.
 *
 * Calls: _xtos_set_intlevel, vPortExitCritical, xPortEnterCriticalTimeout.
 *
 * Called by: esp_ipc_call_and_wait, usb_osal_thread_schedule_other.
 *
 * Original function-byte SHA-256:
 * 8c8e79b57c0973adbde29863398dd7c6c55ee05c861a83f8da0b89f2220bc05f.
 */

/* Returns the effective task priority under the scheduler lock. NULL selects the current task on the calling CPU.
   SDK match: ESP-IDF v5.4.4 components/freertos/FreeRTOS-Kernel/tasks.c. */

/*
 * task: Live TCB or NULL for this CPU current task.
 * Returns: Effective priority, including any inherited priority.
 * Requirements/effects: Uses the kernel lock. NULL selection briefly masks interrupts while
 *   reading the PRID-selected current pointer. Does not return base priority or protect a caller-
 *   supplied stale TCB.
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

/* Native entry: 0x40382b14. */
/*
 * Medius v3.4.7 — host application; 0x40382b14.
 *
 * Changes a task base priority and updates scheduler ready-list state.
 *
 * Calls: esp_crosscore_int_send_yield, FUN_40381d8c, uxListRemove, prvIsYieldRequiredSMP, __assert_func, _xtos_set_intlevel,
 * vPortExitCritical, xPortEnterCriticalTimeout.
 *
 * Called by: esp_ipc_call_and_wait, esp_ipc_call_nonblocking, usb_osal_thread_schedule_other.
 *
 * Original function-byte SHA-256:
 * 7a5b61478f2125975cbe802e81479f588185a405a09f3c76b1672301f09deede.
 */

/* NULL selects the calling core current task. Valid priorities are 0 through 24. Updates
 * base/effective priorities and ready/event-list bookkeeping under the scheduler lock, preserving
 * the priority-inheritance distinction, then requests rescheduling when required. IPC submission
 * and the USB OSAL scheduling helper use this routine.
 */

/* Changes base/effective priority under the scheduler lock, preserves active mutex inheritance where required, updates event and ready-list ordering, and requests local/remote rescheduling. NULL selects this CPU current task; priorities above 24 assert.
   Reference: ESP-IDF v5.4.4 components/freertos/FreeRTOS-Kernel/tasks.c. */

/*
 * task: Live TCB to change, or NULL for this CPU current task.
 * priority: New base priority from 0 through 24; higher values assert.
 * Returns: Nothing.
 * Requirements/effects: Under the kernel lock updates base priority, changes effective priority
 *   only when it matched the old base, preserves bit-31-marked event values and relinks ready
 *   tasks. Requests local or remote preemption as required. Does not itself restore a new task
 *   context.
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

/* Native entry: 0x40382c48. */
/*
 * Medius v3.4.7 — host application; 0x40382c48.
 *
 * Enters the scheduler spinlock, selects CPU via PRID bit13, increments that CPU scheduler-
 * suspension count, then exits the critical section. Suspension is nestable and local to that CPU
 * in this port; it does not hold interrupts disabled after return or block the other CPU.
 *
 * Calls: vPortExitCritical, xPortEnterCriticalTimeout.
 *
 * Called by: spi_flash_op_block_func, spi_flash_disable_interrupts_caches_and_other_cpu, esp_restart.
 *
 * Original function-byte SHA-256:
 * fa2800782b7222dc488781abbcebcc8475a33f5d86360bb8b9a3021347e3a007.
 */

/* Reference: ESP-IDF v5.4.4 components/freertos/FreeRTOS-Kernel/tasks.c. The literal lock address
   is the scheduler spinlock; the PRID field selects CPU0 or CPU1. */

/*
 * Returns: Nothing.
 * Requirements/effects: Increments the current CPU nestable scheduler-suspension count under its
 *   spinlock. Does not suspend the other CPU or leave interrupts masked; caller must balance with
 *   resume.
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

/* Native entry: 0x40382c88. */
/*
 * Medius v3.4.7 — host application; 0x40382c88.
 * Instruction-checked recovered C.
 * Original function-byte SHA-256:
 * 8175818fbe46d3177cc1534ca2799fef522ebcf7f298bb3baae62422be400821.
 */

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

/* Native entry: 0x40382cdc. */
/*
 * Medius v3.4.7 — host application; 0x40382cdc.
 *
 * Advances core-0 kernel time, swaps delayed lists on wrap, wakes expired tasks and reports whether scheduling is needed.
 *
 * Calls: __assert_func, vPortExitCritical, xPortEnterCriticalTimeout, xPortInIsrContext.
 *
 * Called by: SysTickIsrHandler, xTaskResumeAll.
 *
 * Original function-byte SHA-256:
 * 1f96af026ecbcd765aefdb058f08a8cd01647e3f75010c973cddff79b18975d0.
 */

/* Advances core-0 kernel time, swaps delayed lists on wrap, wakes expired tasks and reports whether scheduling is needed.
   SDK match: ESP-IDF v5.4.4 components/freertos/FreeRTOS-Kernel/tasks.c.
   Recovered types/control flow retain the original function bytes and non-returning assertion paths. */

/*
 * Returns: Nonzero when CPU0 should reschedule, otherwise 0. Remote yield-pending state can also
 *   be set.
 * Requirements/effects: CPU0 tick path only; a different PRID core asserts. Under the kernel lock
 *   increments the tick count, swaps delayed lists on wrap and asserts that the expired list is
 *   empty at that wrap. Removes due waiters from state/event lists and relinks them by priority.
 *   While scheduling is suspended, only counts a pended tick. Includes same-priority time slicing;
 *   it does not itself switch context.
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

/* Native entry: 0x40382fa4. */
/*
 * Medius v3.4.7 — host application; 0x40382fa4.
 *
 * Resumes this core scheduling, moves pending-ready tasks, replays pended ticks and reports whether it yielded.
 *
 * Calls: esp_crosscore_int_send_yield, prvIsYieldRequiredSMP, xTaskIncrementTick, __assert_func, _xtos_set_intlevel,
 * vPortExitCritical, xPortEnterCriticalTimeout.
 *
 * Called by: spi_flash_op_block_func, spi_flash_disable_interrupts_caches_and_other_cpu, spi_flash_enable_interrupts_caches_and_other_cpu.
 *
 * Original function-byte SHA-256:
 * 60d7e265cfa2183c0a5f4cee12a2db14faa4a726413df1c4c9c846ab81ff13a1.
 */

/* Resumes this core scheduling, moves pending-ready tasks, replays pended ticks and reports whether it yielded.
   SDK match: ESP-IDF v5.4.4 components/freertos/FreeRTOS-Kernel/tasks.c.
   Recovered types/control flow retain the original function bytes and non-returning assertion paths. */

/*
 * Returns: 1 when this call requested a local yield, otherwise 0.
 * Requirements/effects: Requires a running scheduler and a matching suspend on this CPU; otherwise
 *   asserts. Decrements nesting under the kernel lock. At the outermost resume, drains pending-
 *   ready tasks, recomputes next wake time, and on CPU0 replays pended ticks. The asynchronous
 *   yield request occurs while the kernel lock is held.
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

/* Native entry: 0x403831b8. */
/*
 * Medius v3.4.7 — host application; 0x403831b8.
 *
 * Checks the task stack and selects the highest-priority runnable task compatible with the current core.
 *
 * Calls: vApplicationStackOverflowHook, __assert_func, vPortExitCritical, xPortEnterCriticalTimeout,
 * xPortInIsrContext.
 *
 * Called by: _frxt_dispatch.
 *
 * Original function-byte SHA-256:
 * 3c290a1787929254e667d348a3fbed89a0fe6c2b7d5bf7ca35809bdd07a317bc.
 */

/* Checks the task stack and selects the highest-priority runnable task compatible with the current core.
   SDK match: ESP-IDF v5.4.4 components/freertos/FreeRTOS-Kernel/tasks.c.
   Recovered types/control flow retain the original function bytes and non-returning assertion paths. */

/*
 * Returns: Nothing after selecting a task or deferring the switch; asserts if no eligible ready
 *   task can be found.
 * Requirements/effects: Kernel context-switch path. Under the kernel lock, a suspended scheduler
 *   records a pending yield. Otherwise checks four stack-fill words, then searches priorities from
 *   highest to lowest, skipping tasks running on the other CPU or with incompatible affinity.
 *   Moves the selected task to the end of its ready list and updates the current TCB. This C body
 *   selects the TCB; assembly restores its CPU context.
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

/* Native entry: 0x403833e0. */
/*
 * Medius v3.4.7 — host application; 0x403833e0.
 *
 * Block the current task on a priority-ordered event list and delay list.
 *
 * Calls: vListInsert, prvAddCurrentTaskToDelayedList, __assert_func, vPortExitCritical, xPortEnterCriticalTimeout.
 *
 * Called by: prvSendAcquireGeneric, prvReceiveGeneric, xQueueGenericSend, xQueuePeek, xQueueReceive,
 * xQueueSemaphoreTake.
 *
 * Original function-byte SHA-256:
 * 526d9f8517f7020f9037bf74359fbfe1d2452a31bf127b8d3a644730a303d93a.
 */

/*
 * Block the current task on a priority-ordered event list and delay list.
 *
 * Assert a non-NULL event list and acquire the kernel lock. Select
 * the current task for this CPU, insert its event-list item (TCB +0x18)
 * in priority order, then add the task to the delayed/suspended lists with
 * ticks_to_wait and indefinite waiting permitted. Release the kernel lock.
 * The calling queue/ring-buffer code must hold its own object lock to avoid
 * a lost wakeup; this helper does not itself request the subsequent yield.
 *
 * Evidence: ESP-IDF v5.4.4 components/freertos/FreeRTOS-Kernel/tasks.c;
 * matched scheduler globals, event/timeout layout and queue callers.
 */

/* Inserts the current task into a priority-ordered event list and a delayed/suspended list.
   SDK match: ESP-IDF v5.4.4 components/freertos/FreeRTOS-Kernel/tasks.c.
   Recovered types/control flow retain the original function bytes and non-returning assertion paths. */

/*
 * event_list: Non-NULL initialized event list; task event-item values encode inverse task
 *   priority.
 * ticks_to_wait: Wait duration in ticks; UINT32_MAX allows indefinite blocking through the
 *   delayed-list helper.
 * Returns: Nothing.
 * Requirements/effects: Inserts the current task into the ordered event list, then moves its state
 *   item into a delayed or suspended list under the kernel lock. The caller must arrange the
 *   eventual scheduler yield and valid task blocking context.
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

/* Native entry: 0x40383424. */
/*
 * Medius v3.4.7 — host application; 0x40383424.
 *
 * Unblocks the highest-priority event waiter or defers it until scheduler resume; returns the local-yield decision.
 *
 * Calls: prvIsYieldRequiredSMP, __assert_func, vPortExitCritical, xPortEnterCriticalTimeout,
 * xPortInIsrContext.
 *
 * Called by: prvSendAcquireGeneric, vRingbufferReturnItem, FUN_4038127c, FUN_403812e0, FUN_40381670, FUN_40381728,
 * FUN_40381a78, xQueueGenericSend, xQueuePeek, xQueueReceive, xQueueSemaphoreTake.
 *
 * Original function-byte SHA-256:
 * 37c7c6e0d416403b33533153c6b889506de73636370afe14cf7aaa90a8a937c8.
 */

/* Unblocks the highest-priority event waiter or defers it until scheduler resume; returns the local-yield decision.
   SDK match: ESP-IDF v5.4.4 components/freertos/FreeRTOS-Kernel/tasks.c.
   Recovered types/control flow retain the original function bytes and non-returning assertion paths. */

/*
 * event_list: Valid initialized event list; an empty list is allowed and returns 0.
 * Returns: 1 if the unblocked task requires a local yield, otherwise 0; a remote yield may also be
 *   requested.
 * Requirements/effects: Under the kernel lock removes the first event waiter. A runnable affinity
 *   moves its state item into a ready list; suspended scheduler affinity queues its event item for
 *   later readying. Updates the local yield-pending flag when needed. Does not perform the actual
 *   context switch.
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

/* Native entry: 0x403835e8. */
/*
 * Medius v3.4.7 — host application; 0x403835e8.
 *
 * Snapshot tick overflow and tick count for an internal timeout.
 *
 * Called by: prvSendAcquireGeneric, prvReceiveGeneric, xQueueGenericSend, xQueuePeek, xQueueReceive,
 * xQueueSemaphoreTake.
 *
 * Original function-byte SHA-256:
 * 46d1c0dfc0cbcfcf4282c08328a86800f90a28a62f81d7558de7d832a2e885bc.
 */

/*
 * Snapshot tick overflow and tick count for an internal timeout.
 *
 * Store xNumOfOverflows (0x3fca7430) in timeout[0] and xTickCount
 * (0x3fca7448) in timeout[1], with MEMW before each read. This internal
 * helper does not acquire the kernel lock or validate its output pointer;
 * the caller must protect the two-field snapshot from concurrent updates.
 *
 * Evidence: ESP-IDF v5.4.4 components/freertos/FreeRTOS-Kernel/tasks.c;
 * matched scheduler globals, event/timeout layout and queue callers.
 */

/* Snapshots tick-overflow count and current tick for the caller-owned timeout state.
   SDK match: ESP-IDF v5.4.4 components/freertos/FreeRTOS-Kernel/tasks.c.
   Recovered types/control flow retain the original function bytes and non-returning assertion paths. */

/*
 * timeout: Writable timeout record receiving overflow count and tick count.
 * Returns: Nothing.
 * Requirements/effects: Reads the two scheduler globals with memory barriers but takes no lock.
 *   Its caller must provide the scheduler/critical context needed for a coherent snapshot.
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

/* Native entry: 0x40383604. */
/*
 * Medius v3.4.7 — host application; 0x40383604.
 *
 * Check a blocking deadline and update the caller remaining tick budget.
 *
 * Calls: __assert_func, vPortExitCritical, xPortEnterCriticalTimeout.
 *
 * Called by: prvSendAcquireGeneric, prvReceiveGeneric, xQueueGenericSend, xQueuePeek, xQueueReceive,
 * xQueueSemaphoreTake.
 *
 * Original function-byte SHA-256:
 * 746d0b3d85f8317b6882f707501b91f236e8a26a6124973d97232cb4527266c3.
 */

/*
 * Check a blocking deadline and update the caller remaining tick budget.
 *
 * Assert non-NULL timeout/budget pointers and hold the kernel lock.
 * If the current task's delay-aborted flag is set, clear it and return 1
 * without consuming the budget. A 0xffffffff budget is an indefinite wait
 * and returns 0. Otherwise use tick/overflow snapshots to detect expiry
 * across counter wrap. On expiry set remaining ticks to zero and return 1;
 * if time remains, subtract elapsed ticks, refresh the snapshot and return 0.
 * Release the kernel lock on all normal paths.
 *
 * Evidence: ESP-IDF v5.4.4 components/freertos/FreeRTOS-Kernel/tasks.c;
 * matched scheduler globals, event/timeout layout and queue callers.
 */

/* Checks abort/indefinite/wrap cases, updates the remaining wait budget and returns whether the timeout expired.
   SDK match: ESP-IDF v5.4.4 components/freertos/FreeRTOS-Kernel/tasks.c.
   Recovered types/control flow retain the original function bytes and non-returning assertion paths. */

/*
 * timeout: Non-NULL timeout record initialized when the wait began.
 * ticks_remaining: Non-NULL in/out tick budget; UINT32_MAX means indefinite wait.
 * Returns: 1 for an aborted delay or expired budget; 0 while waiting remains possible.
 * Requirements/effects: Under the kernel lock handles overflow, consumes elapsed ticks and
 *   refreshes the record on a continuing finite wait. Clears the current task delay-aborted flag
 *   when set. Aborted-delay and indefinite paths do not zero the budget; only the expired finite-
 *   wait path does.
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

/* Native entry: 0x403836b0. */
/*
 * Medius v3.4.7 — host application; 0x403836b0.
 *
 * Reads this core current TCB atomically with interrupts temporarily masked.
 *
 * Calls: _xtos_set_intlevel.
 *
 * Called by: xQueueGiveMutexRecursive, xQueueTakeMutexRecursive, esp_ipc_call_and_wait, FUN_42012e48, esp_task_wdt_add,
 * esp_task_wdt_reset, medius_host_get_control_generation, medius_task_ctrlwk,
 * usb_osal_thread_schedule_other.
 *
 * Original function-byte SHA-256:
 * baf8d943302e509ff5d3812f3004a6504b2f34825f35087478ebf99c3f212ad5.
 */

/* Reads this core current TCB atomically with interrupts temporarily masked.
   SDK match: ESP-IDF v5.4.4 components/freertos/FreeRTOS-Kernel/tasks.c.
   Recovered types/control flow retain the original function bytes and non-returning assertion paths. */

/*
 * Returns: Current CPU TCB pointer; can be NULL before task selection.
 * Requirements/effects: Raises interrupt level to 3 around the PRID-selected pointer read, then
 *   restores the previous processor status. Does not acquire the cross-core kernel lock.
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

/* Native entry: 0x403836d0. */
/*
 * Medius v3.4.7 — host application; 0x403836d0.
 *
 * Read whether the FreeRTOS scheduler is stopped, suspended or running.
 *
 * Calls: _xtos_set_intlevel.
 *
 * Called by: lock_acquire_generic, FUN_40376a1c, _lock_release, _lock_release_recursive, spi_flash_disable_interrupts_caches_and_other_cpu, spi_flash_enable_interrupts_caches_and_other_cpu,
 * spi_flash_os_yield, esp_log_impl_lock, esp_log_impl_lock_timeout, esp_log_impl_unlock, esp_log_timestamp, esp_ipc_call_blocking,
 * esp_ipc_call_nonblocking, xQueueGenericSend, xQueuePeek, xQueueReceive, xQueueSemaphoreTake.
 *
 * Original function-byte SHA-256:
 * 3aeeb5438ad0fa07075fc212db1e63bff6594700caf263dfb82744e89fd106d6.
 */

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

/* Native entry: 0x40383704. */
/*
 * Medius v3.4.7 — host application; 0x40383704.
 *
 * Raises a mutex holder to the waiting task priority and moves its ready-list item when required.
 *
 * Calls: uxListRemove, vPortExitCritical, xPortEnterCriticalTimeout.
 *
 * Called by: xQueueSemaphoreTake.
 *
 * Original function-byte SHA-256:
 * f9272e2ac5bdbdc19c6a6175a0aad5931b0ba5f089330e0231753f7204c8b20a.
 */

/* Raises a mutex holder to the waiting task priority and moves its ready-list item when required.
   SDK match: ESP-IDF v5.4.4 components/freertos/FreeRTOS-Kernel/tasks.c.
   Recovered types/control flow retain the original function bytes and non-returning assertion paths. */

/*
 * mutex_holder: Mutex owner TCB, or NULL when there is no holder.
 * Returns: 1 if the owner is raised, or its base priority is below the waiter even when it already
 *   has an inherited priority; otherwise 0.
 * Requirements/effects: Uses current task priority under the kernel lock. Preserves event values
 *   marked with bit 31. Moves an owner already in its old ready list to the new priority list;
 *   other state-list placement is retained. Does not increment the held-mutex count or perform a
 *   context switch.
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

/* Native entry: 0x403837ec. */
/*
 * Medius v3.4.7 — host application; 0x403837ec.
 *
 * Decrements the current holder mutex count; restores base priority after its final held mutex is released.
 *
 * Calls: uxListRemove, __assert_func, vPortExitCritical, xPortEnterCriticalTimeout.
 *
 * Called by: FUN_403811f4.
 *
 * Original function-byte SHA-256:
 * e4dd02841f91517e41ddd91382a2e489a47b02151748d081d8b2b1eb1db035e2.
 */

/* Decrements the current holder mutex count; restores base priority after its final held mutex is released.
   SDK match: ESP-IDF v5.4.4 components/freertos/FreeRTOS-Kernel/tasks.c.
   Recovered types/control flow retain the original function bytes and non-returning assertion paths. */

/*
 * mutex_holder: Current task owning the released mutex, or NULL.
 * Returns: 1 only when base priority is restored after the final held mutex; otherwise 0.
 * Requirements/effects: Asserts a non-NULL holder is the current task and holds at least one
 *   mutex. Under the kernel lock decrements the count; after the last mutex removes and reinserts
 *   the ready item at base priority and updates its event ordering value. Caller decides whether
 *   to yield.
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

/* Native entry: 0x403838ac. */
/*
 * Medius v3.4.7 — host application; 0x403838ac.
 *
 * After a waiter times out, reduces a singly-held mutex owner to max(base priority, highest remaining waiter).
 *
 * Calls: uxListRemove, __assert_func, vPortExitCritical, xPortEnterCriticalTimeout.
 *
 * Called by: xQueueSemaphoreTake.
 *
 * Original function-byte SHA-256:
 * 923b7a0fdba1f0e63b65a855fd98a9de95504741923573cbdc561fef8fa76e5f.
 */

/* After a waiter times out, reduces a singly-held mutex owner to max(base priority, highest remaining waiter).
   SDK match: ESP-IDF v5.4.4 components/freertos/FreeRTOS-Kernel/tasks.c.
   Recovered types/control flow retain the original function bytes and non-returning assertion paths. */

/*
 * mutex_holder: Mutex owner TCB, or NULL.
 * highest_waiter_priority: Priority of the highest remaining waiter; used with the base priority
 *   to select the reduced priority.
 * Returns: Nothing.
 * Requirements/effects: Requires a non-NULL holder to hold at least one mutex. Only changes a
 *   singly-held owner whose priority differs from max(base, remaining waiter); asserts that owner
 *   is not the current task. Preserves bit-31-marked event values and only relinks a ready state
 *   item. Does not release the mutex.
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

/* Native entry: 0x4038397c. */
/*
 * Medius v3.4.7 — host application; 0x4038397c.
 *
 * Increments this core current task mutex-hold count and returns its TCB.
 *
 * Calls: vPortExitCritical, xPortEnterCriticalTimeout.
 *
 * Called by: xQueueSemaphoreTake.
 *
 * Original function-byte SHA-256:
 * 5426a8b32d4904ce1af7406e7857f11b71d8eef3e3af435314d2045ea24598de.
 */

/* Increments this core current task mutex-hold count and returns its TCB.
   SDK match: ESP-IDF v5.4.4 components/freertos/FreeRTOS-Kernel/tasks.c.
   Recovered types/control flow retain the original function bytes and non-returning assertion paths. */

/*
 * Returns: Current CPU TCB, or NULL if no task is selected.
 * Requirements/effects: Under the kernel lock increments the current task mutex-hold count when
 *   non-NULL. Does not allocate or acquire a mutex and provides no counter-overflow guard.
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

/* Native entry: 0x403839bc. */
/*
 * Medius v3.4.7 — host application; 0x403839bc.
 *
 * Waits for a notification count, returns its pre-consumption value and clears or decrements the count.
 *
 * Calls: esp_crosscore_int_send_yield, prvAddCurrentTaskToDelayedList, __assert_func, vPortExitCritical, xPortEnterCriticalTimeout.
 *
 * Called by: ipc_task, medius_task_credit, medius_task_ctrlwk, esp_timer_task,
 * link_receive_task, link_transmit_task, medius_task_render.
 *
 * Original function-byte SHA-256:
 * f9c6dd55c6515cff34e28b437298a4161217f0085f841f029c1ea0823624c7ad.
 */

/* Waits for a notification count, returns its pre-consumption value and clears or decrements the count.
   SDK match: ESP-IDF v5.4.4 components/freertos/FreeRTOS-Kernel/tasks.c.
   Recovered types/control flow retain the original function bytes and non-returning assertion paths. */

/*
 * index: Notification slot; this build supports only 0 and asserts otherwise.
 * clear_count_on_exit: Zero consumes one count; any nonzero value clears the count.
 * ticks_to_wait: Maximum blocking ticks when the count is zero; 0 is a poll and UINT32_MAX allows
 *   an indefinite wait.
 * Returns: Notification count before consumption, or 0 if none is available after the wait.
 * Requirements/effects: Task context with valid current TCB. Uses the kernel lock in two phases
 *   separated by a possible block/yield. Resets notification state to idle on exit. Count
 *   consumption and state changes are synchronized; a positive wait is not a promise of immediate
 *   scheduling at its deadline.
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

/* Native entry: 0x40383a70. */
/*
 * Medius v3.4.7 — host application; 0x40383a70.
 *
 * Applies a task notification action, optionally returns the previous value and wakes a waiting task.
 *
 * Calls: esp_crosscore_int_send_yield, prvIsYieldRequiredSMP, __assert_func, vPortExitCritical, xPortEnterCriticalTimeout.
 *
 * Called by: FUN_4038ba90, FUN_4038bb18, esp_ipc_call_and_wait, esp_ipc_call_nonblocking, FUN_42021a54, FUN_42032300,
 * FUN_42032384, FUN_420324e8, medius_control_work_enqueue, link_frame_enqueue,
 * medius_ordered_change_enqueue, medius_ordered_configuration_request.
 *
 * Original function-byte SHA-256:
 * 1caefe35df8388e3ce92315ebe6f9f20ffbd520d43eeef0c1ba386ec75b444ae.
 */

/* Applies a task notification action, optionally returns the previous value and wakes a waiting task.
   SDK match: ESP-IDF v5.4.4 components/freertos/FreeRTOS-Kernel/tasks.c.
   Recovered types/control flow retain the original function bytes and non-returning assertion paths. */

/*
 * task: Non-NULL destination TCB.
 * index: Slot 0; other indices assert.
 * value: Bits or replacement value, depending on action.
 * action: 0 marks pending without changing value; 1 ORs bits; 2 increments; 3 overwrites; 4
 *   overwrites only when no notification was pending.
 * previous_value: Optional output receiving the old value before applying the action.
 * Returns: 0 when action 4 finds an already pending notification; 1 on the normal success paths.
 * Requirements/effects: Task-context API under the kernel lock. A waiting target is removed from
 *   its blocked state and made ready, with preemption requested as needed. State is set to
 *   received even when action 4 fails. Out-of-range actions assert only when xTickCount is nonzero
 *   in this compiled build; callers must still supply a valid action. Waiting targets must not be
 *   linked on an event list.
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

/* Native entry: 0x40383bcc. */
/*
 * Medius v3.4.7 — host application; 0x40383bcc.
 *
 * Increments a task notification count from ISR context and unblocks or defers a notification waiter.
 *
 * Calls: prvIsYieldRequiredSMP, __assert_func, vPortExitCritical, xPortEnterCriticalTimeout.
 *
 * Called by: FUN_4037b688, FUN_4037d3cc, esp_ipc_call_nonblocking, medius_credit_receive,
 * medius_host_publish_resume_event, link_receive_publish.
 *
 * Original function-byte SHA-256:
 * 8b72e791b7d1abcfb49880a4803f914f2f154afe8deb60e2fa98aa8a31b1badc.
 */

/* Increments a task notification count from ISR context and unblocks or defers a notification waiter.
   SDK match: ESP-IDF v5.4.4 components/freertos/FreeRTOS-Kernel/tasks.c.
   Recovered types/control flow retain the original function bytes and non-returning assertion paths. */

/*
 * task: Non-NULL destination TCB.
 * index: Slot 0; other indices assert.
 * higher_priority_task_woken: Optional in/out flag, set to 1 on required local preemption and
 *   otherwise left unchanged.
 * Returns: Nothing.
 * Requirements/effects: Under the kernel lock marks the notification received and increments its
 *   uint32 count without overflow protection. A waiting target must have no event-list owner. It
 *   becomes ready immediately or is placed on this CPU pending-ready list while scheduling is
 *   suspended. Records yield-pending state; caller arranges ISR-exit yielding.
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

/* Native entry: 0x40383d5c. */
/*
 * Medius v3.4.7 — host application; 0x40383d5c.
 *
 * For a nonzero core, checks pending yield and equal-priority ready tasks without advancing the shared tick.
 *
 * Calls: __assert_func, vPortExitCritical, xPortEnterCriticalTimeout.
 *
 * Called by: SysTickIsrHandler.
 *
 * Original function-byte SHA-256:
 * b517ce8712d5317d15fe3d167e5d2a02d4168f98a8a0417e0c870a37887b5499.
 */

/* For a nonzero core, checks pending yield and equal-priority ready tasks without advancing the shared tick.
   SDK match: ESP-IDF v5.4.4 components/freertos/esp_additions/freertos_tasks_c_additions.h.
   Recovered types/control flow retain the original function bytes and non-returning assertion paths. */

/*
 * Returns: 1 for a pending yield or multiple ready tasks at the current priority, otherwise 0.
 * Requirements/effects: CPU1-only tick path; CPU0 asserts. Returns 0 while this scheduler is
 *   suspended. Takes the kernel lock to read the ready-list count, then reads yield-pending after
 *   unlocking. Does not advance shared tick time or remove delayed tasks.
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

/* Native entry: 0x40383dc4. */
/*
 * Medius v3.4.7 — host application; 0x40383dc4.
 *
 * Allocates a task stack and TCB, initializes the task, and schedules it on the requested core.
 *
 * Calls: vPortFree, prvAddNewTaskToReadyList, prvInitialiseNewTask, __assert_func, memset, pvPortMalloc.
 *
 * Called by: FUN_420036bc, FUN_42013f48, FUN_42023a40, FUN_420325a8, app_main,
 * medius_host_workers_init, link_init, link_start_sync_task,
 * medius_out_start_worker, medius_vendor_start_workers, usb_osal_thread_create.
 *
 * Original function-byte SHA-256:
 * 388f962e4f0e4db17a800df1c3891f584b5abc51fc999eff15d0f28e84d50e6f.
 */

/* Allocates a task stack and TCB, initializes the task, and schedules it on the requested core.
   Evidence: Core validation accepts 0, 1 or 0x7fffffff; allocations use stack_bytes and a
   0x154-byte TCB; all task-label/entry registrations converge here. Matches ESP-IDF FreeRTOS task
   creation. */

/* Allocates an internal byte-addressable stack and 340-byte TCB, initializes and makes the task ready. Accepts cores 0/1 or no affinity 0x7fffffff. Returns 1 on success or -1 on allocation failure; frees the stack if TCB allocation fails.
   Reference: ESP-IDF v5.4.4 components/freertos/esp_additions/freertos_tasks_c_additions.h. */

/*
 * entry: Task entry used to initialize its saved frame.
 * name: Task name source; copied/truncated by the initializer.
 * stack_bytes: Allocation size and initializer stack length in bytes.
 * argument: Opaque task entry argument.
 * priority: Initial task priority passed to the initializer.
 * created_task: Optional output passed through to the initializer.
 * core_id: 0, 1 or INT32_MAX for no affinity; other values assert.
 * Returns: 1 on success, -1 if stack or TCB allocation fails.
 * Requirements/effects: Allocates stack then a 340-byte TCB. Frees stack if TCB allocation fails;
 *   clears and marks dynamic TCB, initializes it and makes it ready. Does not retain ownership of
 *   caller name storage. Caller must supply an adequate stack and valid entry.
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

/* Native entry: 0x40383e60. */
/*
 * Medius v3.4.7 — host application; 0x40383e60.
 *
 * Constructs a pinned task using caller-owned stack and TCB storage, then makes it ready.
 *
 * Calls: xPortCheckValidTCBMem, xPortcheckValidStackMem, prvAddNewTaskToReadyList, prvInitialiseNewTask, __assert_func, memset.
 *
 * Called by: vTaskStartScheduler.
 *
 * Original function-byte SHA-256:
 * d4e0a6f46bb8add27e1d9f39e320d7b1502812c9b979505cd9b2194e70cc1321.
 */

/* Constructs a pinned task using caller-owned stack and TCB storage, then makes it ready.
   SDK match: ESP-IDF v5.4.4 components/freertos/FreeRTOS-Kernel/tasks.c.
   Recovered types/control flow retain the original function bytes and non-returning assertion paths. */

/* Validates stack/TCB memory and core, zeroes caller-owned TCB storage, marks both allocations static, initializes the task and makes it ready. Returns the TCB or NULL for absent storage after validation. Static stack admission differs between device and host; no allocation occurs here.
   Reference: ESP-IDF v5.4.4 components/freertos/esp_additions/freertos_tasks_c_additions.h. */

/*
 * entry: Task entry address for the saved initial frame.
 * name: Task name source passed to the initializer.
 * stack_bytes: Caller-provided stack size in bytes.
 * argument: Opaque task entry argument.
 * priority: Initial task priority.
 * stack: Caller-owned stack storage with required size/alignment.
 * task_buffer: Caller-owned writable 340-byte TCB.
 * core_id: 0, 1 or INT32_MAX for no affinity.
 * Returns: Initialized TCB pointer on success; NULL on the compiled post-admission NULL path.
 * Requirements/effects: Address admission and affinity failures assert before construction. Clears
 *   TCB, marks stack and TCB static, initializes it and makes it ready. Does not allocate or
 *   verify full buffer extents; admitted storage must remain valid for the task lifetime.
 */

RtosTask *xTaskCreateStaticPinnedToCore(TaskEntry entry,char *name,unsigned int stack_bytes,void *argument,unsigned int priority,unsigned int *stack,RtosTask *task_buffer,int core_id)
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

/* Native entry: 0x40383f04. */
/*
 * Medius v3.4.7 — host application; 0x40383f04.
 *
 * Creates per-core idle tasks, initializes scheduler time/state and starts the Xtensa scheduler port.
 *
 * Calls: xPortStartScheduler, vApplicationGetIdleTaskMemory, xTaskCreateStaticPinnedToCore, xTimerCreateTimerTask, __assert_func, vPortExitCritical,
 * xPortEnterCriticalTimeout.
 *
 * Called by: FUN_42023a40.
 *
 * Original function-byte SHA-256:
 * b16c8674ce8b6aaa34214343f2d204d64963c0c2fa84d7c34156d87b92208b44.
 */

/* Creates per-core idle tasks, initializes scheduler time/state and starts the Xtensa scheduler port.
   SDK match: ESP-IDF v5.4.4 components/freertos/FreeRTOS-Kernel/tasks.c.
   Recovered types/control flow retain the original function bytes and non-returning assertion paths. */

/*
 * Returns: Normally transfers control to the port scheduler. Can return if idle creation fails,
 *   or timer-task creation returns a value other than 1. The linked port does not return.
 * Requirements/effects: Startup-only. Creates priority-0 IDLE0 and IDLE1 with per-core static-task
 *   APIs using buffers allocated by the application hook. If both idle creations and timer-task
 *   creation succeed, masks interrupts and publishes next-wakeup, running and tick state in order.
 *   Timer-task result -1 asserts. No rollback frees partial startup allocations here.
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
        unsigned int *stack = 0;
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

/* Native entry: 0x40383fac. */
/*
 * Medius v3.4.7 — host application; 0x40383fac.
 *
 * Returns task affinity (0, 1 or 0x7fffffff); NULL selects the current task.
 *
 * Calls: _xtos_set_intlevel.
 *
 * Called by: esp_intr_free, FUN_42013158.
 *
 * Original function-byte SHA-256:
 * ea26fe8949711db5682ff9c6d3ea0a80f96f97ef2c5e0676e60f70fc7b4b4cf6.
 */

/* Returns task affinity (0, 1 or 0x7fffffff); NULL selects the current task.
   SDK match: ESP-IDF v5.4.4 components/freertos/esp_additions/freertos_tasks_c_additions.h.
   Recovered types/control flow retain the original function bytes and non-returning assertion paths. */

/*
 * task: TCB whose affinity is requested; NULL selects this CPU current task.
 * Returns: Configured affinity: 0, 1, or INT32_MAX for no affinity.
 * Requirements/effects: For NULL, masks interrupts at level 3 only while snapshotting the current
 *   TCB, then restores status before reading affinity. Requires a live selected task and does not
 *   pin its lifetime.
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

/* Native entry: 0x40383fd4. */
/*
 * Medius v3.4.7 — host application; 0x40383fd4.
 *
 * Validates the core and initialized idle handle, then returns that core idle task.
 *
 * Calls: __assert_func.
 *
 * Called by: FUN_42012f40.
 *
 * Original function-byte SHA-256:
 * 5aa4f235aa108d56dd943f1d8d0fdfd2d1b612076f5d03ddc873b112f1bb653b.
 */

/* Validates the core and initialized idle handle, then returns that core idle task.
   SDK match: ESP-IDF v5.4.4 components/freertos/esp_additions/freertos_tasks_c_additions.h.
   Recovered types/control flow retain the original function bytes and non-returning assertion paths. */

/*
 * core_id: CPU0 or CPU1; unsigned validation also rejects negative values.
 * Returns: Selected non-NULL idle TCB.
 * Requirements/effects: Asserts on invalid CPU or uninitialized idle handle. Does not lock the
 *   kernel or acquire ownership of the returned task.
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

/* Native entry: 0x40383ff8. */
/*
 * Medius v3.4.7 — host application; 0x40383ff8.
 *
 * Returns the selected core current task; the returned TCB is a snapshot without lifetime protection.
 *
 * Calls: __assert_func.
 *
 * Called by: FUN_42009038, FUN_42013260.
 *
 * Original function-byte SHA-256:
 * f5955a30f6dc90489b0ba070d8e1414d30795d185d45104f89eefc3ed24fcac7.
 */

/* Returns the selected core current task; the returned TCB is a snapshot without lifetime protection.
   SDK match: ESP-IDF v5.4.4 components/freertos/esp_additions/freertos_tasks_c_additions.h.
   Recovered types/control flow retain the original function bytes and non-returning assertion paths. */

/*
 * core_id: CPU0 or CPU1; unsigned validation rejects negative values.
 * Returns: Snapshot of the selected current TCB, possibly NULL before scheduler initialization.
 * Requirements/effects: Asserts on invalid CPU. Memory barrier precedes the pointer read; no lock
 *   or task-lifetime protection is provided.
 */

RtosTask *xTaskGetCurrentTaskHandleForCore(int core_id)
{
    if ((unsigned int)core_id >= 2U)
        __assert_func(0,0,0,0);
    memw();
    return RTOS_CURRENT_TASKS[core_id];
}


/* Native entry: 0x40382ca8. */
/*
 * Medius v3.4.7 — host application; 0x40382ca8.
 *
 * Returns the explicit or current task's borrowed name field.
 *
 * Calls: _xtos_set_intlevel, __assert_func.
 *
 * Called by: FUN_42009038, medius_worker_watchdog_add, esp_task_wdt_print_triggered_tasks, FUN_42013260.
 *
 * Original function-byte SHA-256:
 * fd957c429e187290d5bd11f80e90b7ed6d712caaf1545ef7175b1a6b7c7143b1.
 */

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
 * A missing selected TCB asserts after the interrupt level has been restored. An explicit handle takes the direct
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

/* Native entry: 0x40382c78. */
/* Original function-byte SHA-256:
 * 889040e8add3dc95a3abb5d993e3b4dc26bffba1123e246c5d68d177caa24b11. */
/* MEMW, then return the single native32 kernel tick word. No critical section,
 * scheduler-state test, per-core selection, unit conversion or retry. The result
 * wraps modulo32 as the kernel tick count advances; it is not elapsed wall time. */
unsigned int xTaskGetTickCount(void)
{
    memw();
    return *CLOCK_TICK_COUNT;
}
