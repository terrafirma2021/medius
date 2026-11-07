/* Medius v3.4.7 host — rtos/queues.c.
 * Recovered C and native assembly, grouped for source navigation.
 * Original entry addresses, firmware-byte hashes and function comments follow.
 */

#include "../include/types.h"

/* Native entry: 0x403813e0. */
/*
 * Medius v3.4.7 — host application; 0x403813e0.
 *
 * Allocates and initializes a FreeRTOS queue with the requested length and item size.
 *
 * Calls: xQueueGenericReset, __assert_func, pvPortMalloc.
 *
 * Called by: FUN_4038145c, FUN_42021598, medius_host_workers_init, link_init,
 * link_start_sync_task, medius_out_start_worker, medius_vendor_start_workers,
 * usb_osal_mq_create.
 *
 * Original function-byte SHA-256:
 * ad90cd57e65cbd3e49231eae0bc77c38457dfd468dd6451cf4d5999856c6e12c.
 */

/*
 * Allocates one 84-byte queue control block plus capacity*item_size bytes of
 * contiguous data storage through pvPortMalloc. capacity must be nonzero;
 * multiplication and addition of the control size must fit unsigned 32 bits.
 * Invalid size arguments assert before allocation. Returns NULL on allocator
 * failure, otherwise the initialized queue pointer; there is no fabricated
 * pointer-valued return from the fatal assertion path.
 *
 * Marks dynamic allocation, sets head just after the control block for data
 * items or to the block itself for zero-size items, stores capacity/item_size,
 * resets as a new queue, and clears set_container. Initial message count is
 * zero, including zero-size semaphore-style objects. Does not clear payload
 * storage or padding. Allocation has the wrapper's internal/8-bit capabilities.
 * Requires allocator/kernel initialization; caller owns the returned object's
 * lifetime. This specialized entry does not read a queue-type argument.
 */
RtosQueue *xQueueGenericCreate(unsigned int capacity, unsigned int item_size)
{
    unsigned long long storage_bytes = (unsigned long long)capacity * item_size;
    if (capacity == 0 || storage_bytes > 0xffffffffULL - sizeof(RtosQueue))
        __assert_func(0, 0, 0, 0);

    unsigned int allocation_bytes = (unsigned int)storage_bytes + sizeof(RtosQueue);
    RtosQueue *queue = pvPortMalloc(allocation_bytes);
    if (queue == 0)
        return 0;
    unsigned char *head = item_size == 0
        ? (unsigned char *)queue : (unsigned char *)(queue + 1);
    queue->statically_allocated = 0;
    queue->head = head;
    queue->capacity = capacity;
    queue->item_size = item_size;
    (void)xQueueGenericReset(queue, 1);
    queue->set_container = 0;
    return queue;
}

/* Native entry: 0x40381498. */
/*
 * Medius v3.4.7 — host application; 0x40381498.
 *
 * Copies an item into a queue, optionally waiting for space, and wakes a receiver.
 *
 * Calls: esp_crosscore_int_send_yield, prvCopyDataToQueue, prvNotifyQueueSetContainer, vTaskPlaceOnEventList, xTaskRemoveFromEventList, vTaskInternalSetTimeOutState,
 * xTaskCheckForTimeOut, xTaskGetSchedulerState, __assert_func, vPortExitCritical, xPortEnterCriticalTimeout.
 *
 * Called by: ipc_task, FUN_40376a1c, _lock_release, link_frame_dispatch, prvSendAcquireGeneric, xQueueGiveMutexRecursive,
 * FUN_40381610, esp_log_impl_unlock, FUN_40388f68, FUN_4038bb84, esp_ipc_call_and_wait, uart_wait_tx_done,
 * uart_flush_input, FUN_42021a54, FUN_4202563c, FUN_42026220, FUN_42026320, FUN_420265c4,
 * FUN_4202e370, FUN_4202f918, FUN_4202fa24, FUN_42030438, FUN_42030490, FUN_42030610; plus 41
 * other direct targets.
 *
 * Original function-byte SHA-256:
 * e9e801b604ed11a9549275150bce57c02f8df59b18073acb7b7f6a3343b86984.
 */

/*
 * Sends one item or returns a semaphore/mutex token, optionally waiting for
 * space. queue must be initialized; item must cover item_size readable bytes
 * unless item_size is zero, when NULL is permitted. wait_ticks is a mutable
 * unsigned tick budget, not a guaranteed wall-clock deadline. copy_position
 * uses 0=back, 1=front, 2=overwrite; other nonzero values follow the front-copy
 * helper path. Overwrite asserts that the queue capacity is exactly one.
 *
 * Returns 1 after copying/admitting the item, or 0 when full with no remaining
 * wait or when the timeout helper expires. Asserts a non-NULL queue, valid
 * item pointer and overwrite capacity, and disallows nonzero waits while this
 * CPU's scheduler is suspended. Always samples scheduler state before looping.
 *
 * Under the queue spinlock, admits when space exists or overwrite is selected.
 * Retains a fresh pre-copy message count for queue-set overwrite handling.
 * A nonempty member overwrite skips both set notification and its yield path.
 * Other members notify their set. A standalone queue wakes a receiver if one
 * exists; only when none exists is the copy helper's mutex-disinherit yield
 * result used. A required yield sends an interrupt to the CPU selected by a
 * fresh PRID bit-13 read while still holding the queue lock, then unlocks.
 *
 * A full queue starts timeout tracking on the first blocking attempt, checks
 * and updates the remaining ticks, and links the current task into the send
 * wait list before requesting a local yield and releasing the lock. Retried
 * admission checks space before checking time again. The item remains borrowed
 * across this wait and is copied only when admitted. No complete-operation
 * mutex or allocation is supplied here; callers must provide valid kernel
 * task context, queue storage, item lifetime and copy/overwrite invariants.
 */
int xQueueGenericSend(RtosQueue *queue, const void *item,
                       unsigned int wait_ticks, int copy_position)
{
    if (queue == 0 || (item == 0 && queue->item_size != 0) ||
        (copy_position == QUEUE_OVERWRITE && queue->capacity != 1))
        __assert_func(0, 0, 0, 0);
    int scheduler_state = xTaskGetSchedulerState();
    if (scheduler_state == SCHEDULER_STATE_SUSPENDED && wait_ticks != 0)
        __assert_func(0, 0, 0, 0);

    int overwriting = copy_position == QUEUE_OVERWRITE;
    int timeout_started = 0;
    RtosTimeout timeout;
    for (;;) {
        (void)xPortEnterCriticalTimeout(&queue->lock, -1);
        memw();
        unsigned int messages = queue->messages_waiting;
        unsigned int capacity = queue->capacity;
        if (messages < capacity || overwriting) {
            memw();
            unsigned int previous_messages = queue->messages_waiting;
            int yield_required = prvCopyDataToQueue(queue, item, copy_position);
            if (queue->set_container != 0) {
                if (previous_messages != 0 && overwriting)
                    yield_required = 0;
                else
                    yield_required = prvNotifyQueueSetContainer(queue);
            } else {
                memw();
                unsigned int waiting_receivers = queue->waiting_to_receive.count;
                if (waiting_receivers != 0)
                    yield_required = xTaskRemoveFromEventList(&queue->waiting_to_receive);
            }
            if (yield_required != 0) {
                unsigned int current_core = (xtensa_read_prid() >> 13) & 1U;
                esp_crosscore_int_send_yield((int)current_core);
            }
            vPortExitCritical(&queue->lock);
            return 1;
        }

        if (wait_ticks == 0) {
            vPortExitCritical(&queue->lock);
            return 0;
        }
        if (!timeout_started)
            vTaskInternalSetTimeOutState(&timeout);
        if (xTaskCheckForTimeOut(&timeout, &wait_ticks) != 0) {
            vPortExitCritical(&queue->lock);
            return 0;
        }
        vTaskPlaceOnEventList(&queue->waiting_to_send, wait_ticks);
        unsigned int current_core = (xtensa_read_prid() >> 13) & 1U;
        esp_crosscore_int_send_yield((int)current_core);
        vPortExitCritical(&queue->lock);
        timeout_started = 1;
    }
}

/* Native entry: 0x4038158c. */
/*
 * Medius v3.4.7 — host application; 0x4038158c.
 *
 * Creates a FreeRTOS mutex and makes its initial token available.
 *
 * Calls: xQueueGenericReset, pvPortMalloc, xQueueGenericSend.
 *
 * Called by: lock_acquire_generic, FUN_40376b30, FUN_40376b58, esp_log_impl_lock, esp_log_impl_lock_timeout, spi_flash_init_lock,
 * FUN_4202448c, FUN_420255dc, link_init, medius_out_start_worker,
 * medius_vendor_start_workers, usb_osal_mutex_create.
 *
 * Original function-byte SHA-256:
 * 4ef5c60f8d84986e590c5718b1a33b9a4f5ae718284f6e3c9b669542c9bd2d93.
 */

/*
 * Allocates and initializes an available, unowned FreeRTOS mutex.
 * No native input is read; an incoming SDK queue-type value is unused in this
 * specialized entry. Returns NULL if the 84-byte control allocation fails,
 * otherwise the mutex queue pointer. Allocation uses pvPortMalloc capabilities.
 *
 * Marks dynamic allocation, initializes a capacity-one/zero-item-size queue
 * with a temporary self head, and resets it as new. Clears set membership,
 * owner, head and recursion count, then reinitializes its spinlock exactly as
 * native. The retained write pointer still points at the control block.
 * Gives its initial token through xQueueGenericSend(NULL item, zero wait,
 * back position), ignoring that result, so a newly created mutex is available.
 * No whole-object clear or extra cleanup/fallback path is supplied. Requires
 * working allocator/kernel primitives and exclusive initialization ownership.
 */
RtosQueue *xQueueCreateMutex(void)
{
    RtosQueue *queue = pvPortMalloc(sizeof(RtosQueue));
    if (queue == 0)
        return 0;

    queue->statically_allocated = 0;
    queue->capacity = 1;
    queue->head = (unsigned char *)queue;
    queue->item_size = 0;
    (void)xQueueGenericReset(queue, 1);
    queue->set_container = 0;
    queue->storage.semaphore.holder = 0;
    queue->head = 0;
    queue->storage.semaphore.recursion_count = 0;
    queue->lock.owner = PORTMUX_FREE_OWNER;
    queue->lock.count = 0;
    (void)xQueueGenericSend(queue, 0, 0, QUEUE_SEND_TO_BACK);
    return queue;
}

/* Native entry: 0x403815cc. */
/*
 * Medius v3.4.7 — host application; 0x403815cc.
 *
 * Asserts a non-NULL mutex and returns 0 if the current task is not its holder. The holder
 * decrements the unsigned recursion count; when it reaches zero, gives the semaphore via
 * xQueueGenericSend with NULL item, zero wait and back-of-queue position, ignoring that result.
 * Returns 1 for the holder. Relies on the ownership/count invariant; a zero starting count wraps
 * rather than being rejected.
 *
 * Calls: xTaskGetCurrentTaskHandle, __assert_func, xQueueGenericSend.
 *
 * Called by: FUN_40376a1c, _lock_release_recursive, spi_flash_op_unlock.
 *
 * Original function-byte SHA-256:
 * 37ec3d2bf132ac1938dd0d8d6b2210f691a47fdf5f6073ff7456e6e8861ea586.
 */

/* Reference: ESP-IDF v5.4.4 components/freertos/FreeRTOS-Kernel/queue.c. */

/*
 * mutex: Live full 84-byte FreeRTOS recursive-mutex queue; holder/depth use the semaphore overlay.
 *   NULL asserts.
 * Returns: 1 for the current owner,0 for another task.
 * Requirements/effects: Owner decrements uint32 recursion; reaching0 sends a NULL item with zero
 *   wait and ignores send status. Requires correct ownership/depth; zero starting depth wraps.
 */

int xQueueGiveMutexRecursive(RtosQueue *mutex)

{
  if (mutex == 0) __assert_func(0,0,0,0);
  volatile RtosQueue *state = mutex;
  RtosTask *holder = state->storage.semaphore.holder;
  RtosTask *current_task = xTaskGetCurrentTaskHandle();
  if (holder != current_task) return 0;

  uint remaining_depth = state->storage.semaphore.recursion_count - 1U;
  state->storage.semaphore.recursion_count = remaining_depth;
  if (remaining_depth == 0) {
    /* The prefix belongs to the full live queue described by the contract. */
    (void)xQueueGenericSend((RtosQueue *)mutex,0,0,QUEUE_SEND_TO_BACK);
  }
  return 1;
}

/* Native entry: 0x403817a4. */
/*
 * Medius v3.4.7 — host application; 0x403817a4.
 *
 * Receives and removes a queue item, optionally waiting for it.
 *
 * Calls: esp_crosscore_int_send_yield, vTaskPlaceOnEventList, xTaskRemoveFromEventList, vTaskInternalSetTimeOutState, xTaskCheckForTimeOut, xTaskGetSchedulerState,
 * __assert_func, memcpy, vPortExitCritical, xPortEnterCriticalTimeout.
 *
 * Called by: medius_task_ctrlwk, medius_task_hidfwd, link_receive_task, link_sync_task,
 * link_transmit_task, medius_task_outrelay, medius_task_vendfwd, medius_task_vintr,
 * usb_osal_mq_recv.
 *
 * Original function-byte SHA-256:
 * 410e50730056ae5d47ab4b928816c2e7d72002fdd998b83331dd6179f910d7ef.
 */

/*
 * Receives and removes one queue item, waiting when empty if requested.
 * queue: initialized object; item: writable item_size-byte destination that
 * does not overlap queue metadata/storage. NULL is permitted for zero-size
 * items. wait_ticks: mutable unsigned tick budget passed to timeout helpers.
 * Returns 1 on removal or 0 on empty/no wait or timeout. Asserts a non-NULL
 * queue, valid destination and no nonzero wait while the scheduler is suspended.
 *
 * Under the queue spinlock, samples message count once. For a data item,
 * advances the native read cursor by item_size with unsigned 32-bit wrap
 * arithmetic, wraps to head when at/past tail, and memcpy copies the item.
 * Decrements the saved count after MEMW, then may unblock a waiting sender
 * and request a yield interrupt on the CPU selected by fresh PRID bit 13.
 * A zero-size receive only consumes a token; no mutex-owner/priority or
 * held-mutex-count bookkeeping is performed here.
 *
 * Empty queues initialize timeout state on the first blocking attempt, check
 * the remaining ticks, link this task into the receive wait list, request a
 * local yield and release the queue lock before retrying. Availability is
 * checked before the next timeout check. The destination must remain valid
 * across waits. No allocation or wall-clock timing guarantee is supplied.
 * Requires valid queue/list/storage invariants and kernel task context.
 */
int xQueueReceive(RtosQueue *queue, void *item, unsigned int wait_ticks)
{
    if (queue == 0 || (item == 0 && queue->item_size != 0))
        __assert_func(0, 0, 0, 0);
    int scheduler_state = xTaskGetSchedulerState();
    if (scheduler_state == SCHEDULER_STATE_SUSPENDED && wait_ticks != 0)
        __assert_func(0, 0, 0, 0);

    int timeout_started = 0;
    RtosTimeout timeout;
    for (;;) {
        (void)xPortEnterCriticalTimeout(&queue->lock, -1);
        memw();
        unsigned int messages = queue->messages_waiting;
        if (messages != 0) {
            unsigned int item_bytes = queue->item_size;
            if (item_bytes != 0) {
                unsigned int current_read = (unsigned int)queue->storage.queue.read_from;
                unsigned int tail = (unsigned int)queue->storage.queue.tail;
                unsigned int next_read = current_read + item_bytes;
                queue->storage.queue.read_from = (unsigned char *)next_read;
                if (next_read >= tail) {
                    next_read = (unsigned int)queue->head;
                    queue->storage.queue.read_from = (unsigned char *)next_read;
                }
                memcpy(item, (const void *)next_read, item_bytes);
            }
            unsigned int next_messages = messages - 1U;
            memw();
            queue->messages_waiting = next_messages;
            memw();
            unsigned int waiting_senders = queue->waiting_to_send.count;
            if (waiting_senders != 0 &&
                xTaskRemoveFromEventList(&queue->waiting_to_send) != 0) {
                unsigned int current_core = (xtensa_read_prid() >> 13) & 1U;
                esp_crosscore_int_send_yield((int)current_core);
            }
            vPortExitCritical(&queue->lock);
            return 1;
        }
        if (wait_ticks == 0) {
            vPortExitCritical(&queue->lock);
            return 0;
        }
        if (!timeout_started)
            vTaskInternalSetTimeOutState(&timeout);
        if (xTaskCheckForTimeOut(&timeout, &wait_ticks) != 0) {
            vPortExitCritical(&queue->lock);
            return 0;
        }
        vTaskPlaceOnEventList(&queue->waiting_to_receive, wait_ticks);
        unsigned int current_core = (xtensa_read_prid() >> 13) & 1U;
        esp_crosscore_int_send_yield((int)current_core);
        vPortExitCritical(&queue->lock);
        timeout_started = 1;
    }
}

/* Native entry: 0x40381880. */
/*
 * Medius v3.4.7 — host application; 0x40381880.
 *
 * Takes a semaphore or mutex with an optional timeout.
 *
 * Calls: esp_crosscore_int_send_yield, vTaskPlaceOnEventList, xTaskRemoveFromEventList, vTaskInternalSetTimeOutState, xTaskCheckForTimeOut, xTaskGetSchedulerState,
 * xTaskPriorityInherit, vTaskPriorityDisinheritAfterTimeout, pvTaskIncrementMutexHeldCount, __assert_func, vPortExitCritical,
 * xPortEnterCriticalTimeout.
 *
 * Called by: lock_acquire_generic, xQueueTakeMutexRecursive, esp_log_impl_lock, esp_log_impl_lock_timeout, FUN_40388f68, esp_ipc_call_and_wait,
 * uart_wait_tx_done, uart_flush_input, FUN_420140b8, FUN_4202563c, FUN_42026220, FUN_42026320,
 * FUN_42030438, FUN_42030490, FUN_42030584, FUN_420305ac, FUN_420305d4, FUN_420305f0,
 * FUN_42030610, FUN_420307a0, FUN_42030860, FUN_42030b5c, link_frame_enqueue,
 * link_uart_transmit_wait; plus 18 other direct targets.
 *
 * Original function-byte SHA-256:
 * c8180f5a56f06f13355353e712193fbf19c9625700938d8b86409d08e68c7d6d.
 */

/*
 * Takes one semaphore/mutex token with an optional unsigned tick budget.
 * queue must be a non-NULL initialized zero-item-size object; those checks
 * assert. A nonzero wait while the local scheduler is suspended also asserts.
 * Returns 1 on acquisition or 0 when empty with no wait or after timeout.
 * No data buffer is copied or allocated.
 *
 * Under the queue spinlock, samples the token count once and snapshots head
 * before publishing the decremented count after MEMW. A NULL head identifies
 * a mutex: increments the current task's held-mutex count and stores that
 * task as holder. May unblock a waiting sender and request a local yield.
 *
 * Empty queues initialize timeout tracking once. Before blocking on a mutex,
 * attempts priority inheritance for its current holder and remembers that
 * attempt's result (not an accumulated OR). Links this task into the receive
 * wait list, requests a yield on fresh PRID bit 13, unlocks and retries.
 *
 * If the timeout helper expires and the remembered inheritance result is
 * nonzero, derives the highest remaining waiter priority as 25 minus the
 * first receive-event value, or zero when the list is empty, then asks the
 * holder to disinherit as appropriate. Native subtraction is unsigned and
 * is not clamped. A direct empty/no-wait return skips this cleanup branch.
 * Availability is checked before timeout on retries. Requires valid queue,
 * event-list/priority invariants and kernel task context. No recursive-owner
 * shortcut, complete-operation mutex or wall-clock guarantee is supplied.
 */
int xQueueSemaphoreTake(RtosQueue *queue, unsigned int wait_ticks)
{
    if (queue == 0 || queue->item_size != 0)
        __assert_func(0, 0, 0, 0);
    int scheduler_state = xTaskGetSchedulerState();
    if (scheduler_state == SCHEDULER_STATE_SUSPENDED && wait_ticks != 0)
        __assert_func(0, 0, 0, 0);

    int timeout_started = 0;
    int inheritance_result = 0;
    RtosTimeout timeout;
    for (;;) {
        (void)xPortEnterCriticalTimeout(&queue->lock, -1);
        memw();
        unsigned int messages = queue->messages_waiting;
        if (messages != 0) {
            unsigned int next_messages = messages - 1U;
            unsigned char *head = queue->head;
            memw();
            queue->messages_waiting = next_messages;
            if (head == 0)
                queue->storage.semaphore.holder = pvTaskIncrementMutexHeldCount();
            memw();
            unsigned int waiting_senders = queue->waiting_to_send.count;
            if (waiting_senders != 0 &&
                xTaskRemoveFromEventList(&queue->waiting_to_send) != 0) {
                unsigned int current_core = (xtensa_read_prid() >> 13) & 1U;
                esp_crosscore_int_send_yield((int)current_core);
            }
            vPortExitCritical(&queue->lock);
            return 1;
        }
        if (wait_ticks == 0) {
            vPortExitCritical(&queue->lock);
            return 0;
        }
        if (!timeout_started)
            vTaskInternalSetTimeOutState(&timeout);
        if (xTaskCheckForTimeOut(&timeout, &wait_ticks) != 0) {
            if (inheritance_result != 0) {
                memw();
                unsigned int waiting_receivers = queue->waiting_to_receive.count;
                unsigned int highest_waiter_priority = 0;
                if (waiting_receivers != 0) {
                    memw();
                    RtosListItem *first_waiter =
                        queue->waiting_to_receive.end_marker.next;
                    memw();
                    unsigned int event_value = first_waiter->value;
                    highest_waiter_priority = RTOS_PRIORITY_LEVELS - event_value;
                }
                vTaskPriorityDisinheritAfterTimeout(queue->storage.semaphore.holder,
                                                      highest_waiter_priority);
            }
            vPortExitCritical(&queue->lock);
            return 0;
        }
        if (queue->head == 0)
            inheritance_result = xTaskPriorityInherit(queue->storage.semaphore.holder);
        vTaskPlaceOnEventList(&queue->waiting_to_receive, wait_ticks);
        unsigned int current_core = (xtensa_read_prid() >> 13) & 1U;
        esp_crosscore_int_send_yield((int)current_core);
        vPortExitCritical(&queue->lock);
        timeout_started = 1;
    }
}

/* Native entry: 0x4038196c. */
/*
 * Medius v3.4.7 — host application; 0x4038196c.
 *
 * Asserts a non-NULL mutex, compares its holder with the current task and increments the unsigned
 * recursion count immediately for the owner. Otherwise calls xQueueSemaphoreTake with wait_ticks;
 * increments the count and returns 1 on success, or returns 0 on failure. The owner path does not
 * block or re-run the semaphore priority-inheritance path. No overflow check or independent lock
 * surrounds the owner-only recursion update.
 *
 * Calls: xTaskGetCurrentTaskHandle, __assert_func, xQueueSemaphoreTake.
 *
 * Called by: lock_acquire_generic, spi_flash_op_lock.
 *
 * Original function-byte SHA-256:
 * 269ba84456f8ddb4e4d6c71acd1f362fb00e4f244724d8c1871928d52fd2ced7.
 */

/* Reference: ESP-IDF v5.4.4 components/freertos/FreeRTOS-Kernel/queue.c. */

/*
 * mutex: Live full 84-byte recursive-mutex queue; holder/depth are at offsets 8/12.
 *   NULL asserts.
 * wait_ticks: RTOS wait budget forwarded to semaphore take when the current task is not already
 *   owner.
 * Returns: 1 for successful ownership/recursion,0 when semaphore take fails.
 * Requirements/effects: Owner recursion increments without blocking or rerunning inheritance. Uses
 *   queue API for a new take; uint32 depth has no overflow check.
 */

int xQueueTakeMutexRecursive(RtosQueue *mutex,uint wait_ticks)

{
  if (mutex == 0) __assert_func(0,0,0,0);
  volatile RtosQueue *state = mutex;
  RtosTask *holder = state->storage.semaphore.holder;
  RtosTask *current_task = xTaskGetCurrentTaskHandle();
  if (holder != current_task) {
    int result = xQueueSemaphoreTake((RtosQueue *)mutex,wait_ticks);
    if (result == 0) return 0;
  }
  uint depth = state->storage.semaphore.recursion_count;
  state->storage.semaphore.recursion_count = depth + 1U;
  return 1;
}

/* Native entry: 0x403819a4. */
/*
 * Medius v3.4.7 — host application; 0x403819a4.
 *
 * Copies the next queue item without removing it.
 *
 * Calls: esp_crosscore_int_send_yield, vTaskPlaceOnEventList, xTaskRemoveFromEventList, vTaskInternalSetTimeOutState, xTaskCheckForTimeOut, xTaskGetSchedulerState,
 * __assert_func, memcpy, vPortExitCritical, xPortEnterCriticalTimeout.
 *
 * Called by: link_transmit_task, medius_task_vintr.
 *
 * Original function-byte SHA-256:
 * afe0da00605b873e08dcdc7cde8a1696220f38810a535129092514740fc7c11f.
 */

/*
 * Copies the next item while retaining it in the queue. queue must be an
 * initialized object; item must cover item_size writable bytes without overlap
 * with queue metadata/storage. NULL is permitted for a zero-size item.
 * wait_ticks is a mutable unsigned timeout-helper budget, not a wall-clock
 * guarantee. Returns 1 when an item/token is present, otherwise 0 after a
 * no-wait empty check or timeout. Invalid queue/destination or a nonzero wait
 * while this CPU's scheduler is suspended asserts.
 *
 * Holds the queue spinlock while inspecting availability. Saves the read word
 * even for zero-size items; data items temporarily advance/wrap that cursor
 * and memcpy copy the payload. After MEMW, snapshots receive-waiter count and
 * restores the saved read word. Message count is not changed. May unblock a
 * receiver and request a local yield because the item is still available.
 * No sender is unblocked by this peek, and no mutex is acquired for the caller.
 *
 * Empty-queue waits initialize timeout tracking once, check remaining ticks,
 * link this task into the receive wait list, request a current-CPU yield and
 * release the lock before retrying. Checks availability before timeout on
 * retry. Requires valid queue/list/storage state, task context and a live
 * destination across waits. No allocation or payload lifetime extension.
 */
int xQueuePeek(RtosQueue *queue, void *item, unsigned int wait_ticks)
{
    if (queue == 0 || (item == 0 && queue->item_size != 0))
        __assert_func(0, 0, 0, 0);
    int scheduler_state = xTaskGetSchedulerState();
    if (scheduler_state == SCHEDULER_STATE_SUSPENDED && wait_ticks != 0)
        __assert_func(0, 0, 0, 0);

    int timeout_started = 0;
    RtosTimeout timeout;
    for (;;) {
        (void)xPortEnterCriticalTimeout(&queue->lock, -1);
        memw();
        unsigned int messages = queue->messages_waiting;
        if (messages != 0) {
            unsigned int item_bytes = queue->item_size;
            unsigned int saved_read = (unsigned int)queue->storage.queue.read_from;
            if (item_bytes != 0) {
                unsigned int next_read = saved_read + item_bytes;
                unsigned int tail = (unsigned int)queue->storage.queue.tail;
                queue->storage.queue.read_from = (unsigned char *)next_read;
                if (next_read >= tail) {
                    next_read = (unsigned int)queue->head;
                    queue->storage.queue.read_from = (unsigned char *)next_read;
                }
                memcpy(item, (const void *)next_read, item_bytes);
            }
            memw();
            unsigned int waiting_receivers = queue->waiting_to_receive.count;
            queue->storage.queue.read_from = (unsigned char *)saved_read;
            if (waiting_receivers != 0 &&
                xTaskRemoveFromEventList(&queue->waiting_to_receive) != 0) {
                unsigned int current_core = (xtensa_read_prid() >> 13) & 1U;
                esp_crosscore_int_send_yield((int)current_core);
            }
            vPortExitCritical(&queue->lock);
            return 1;
        }
        if (wait_ticks == 0) {
            vPortExitCritical(&queue->lock);
            return 0;
        }
        if (!timeout_started)
            vTaskInternalSetTimeOutState(&timeout);
        if (xTaskCheckForTimeOut(&timeout, &wait_ticks) != 0) {
            vPortExitCritical(&queue->lock);
            return 0;
        }
        vTaskPlaceOnEventList(&queue->waiting_to_receive, wait_ticks);
        unsigned int current_core = (xtensa_read_prid() >> 13) & 1U;
        esp_crosscore_int_send_yield((int)current_core);
        vPortExitCritical(&queue->lock);
        timeout_started = 1;
    }
}

/* Native entry: 0x40381af0. */
/*
 * Medius v3.4.7 — host application; 0x40381af0.
 *
 * Returns a FreeRTOS queue/semaphore queued-item count under its spinlock.
 *
 * Calls: __assert_func, vPortExitCritical, xPortEnterCriticalTimeout.
 *
 * Called by: medius_host_apply_configuration.
 *
 * Original function-byte SHA-256:
 * 659c8e139407d45d541af5431896a4dd97c0b8eeb06df353f49c883dca77048e.
 */

/*
 * Returns a momentary unsigned queued-item/token count. queue must be a live
 * initialized object; NULL asserts rather than returning a defined zero.
 * Holds its spinlock with an infinite acquisition timeout, reads the count
 * after MEMW and releases the lock. The lock result is ignored as native.
 * No payload copy, count mutation, item reservation, ownership transfer or
 * wait for data is supplied. The snapshot can change immediately after unlock;
 * it does not establish that a worker is idle or that queued work is complete.
 */
unsigned int uxQueueMessagesWaiting(RtosQueue *queue)
{
    if (queue == 0)
        __assert_func(0, 0, 0, 0);
    (void)xPortEnterCriticalTimeout(&queue->lock, -1);
    memw();
    unsigned int messages = queue->messages_waiting;
    vPortExitCritical(&queue->lock);
    return messages;
}

/* Native entry: 0x403811f4. */
/*
 * Medius v3.4.7 — host application; 0x403811f4.
 *
 * Copies one queue item or returns a semaphore/mutex token.
 *
 * Calls: xTaskPriorityDisinherit, memcpy.
 *
 * Called by: prvNotifyQueueSetContainer, FUN_40381670, xQueueGenericSend.
 *
 * Original function-byte SHA-256:
 * abd4b1276aaf8ac017c723be9f2e1bf17de729a3c5801b4cf79da7e55121d0d4.
 */

/*
 * Copies one item into a queue, or returns a semaphore/mutex token.
 * queue: initialized object already protected by its owning critical section.
 * item: item_size readable bytes for data queues; unused for zero-size items.
 * position: 0 appends, 2 overwrites at the front, all other values prepend.
 * Returns the priority-disinherit result when releasing a mutex, otherwise 0.
 *
 * Increments the saved message count, except overwrite uses max(old_count, 1).
 * Data copies use memcpy and the native circular write/read pointer updates.
 * A zero-size mutex disinherits its holder and clears that holder pointer.
 * MEMW separates the native count snapshot and final publication. No capacity
 * check, allocation, lock acquisition or waiter notification is performed.
 * Caller must supply valid queue storage, bounds, position and any required
 * overwrite/capacity invariant. Address arithmetic is explicitly 32-bit to
 * retain the native subtract-before-wrap comparison at the queue front.
 */
int prvCopyDataToQueue(RtosQueue *queue, const void *item, int position)
{
    unsigned int item_bytes = queue->item_size;
    memw();
    unsigned int messages = queue->messages_waiting;
    int yield_required = 0;
    if (item_bytes == 0) {
        ++messages;
        if (queue->head == 0) {
            yield_required = xTaskPriorityDisinherit(queue->storage.semaphore.holder);
            queue->storage.semaphore.holder = 0;
        }
    } else if (position == 0) {
        ++messages;
        memcpy(queue->write_to, item, item_bytes);
        unsigned int current_write = (unsigned int)queue->write_to;
        unsigned int stored_item_bytes = queue->item_size;
        unsigned int tail = (unsigned int)queue->storage.queue.tail;
        unsigned int next_write = current_write + stored_item_bytes;
        queue->write_to = (unsigned char *)next_write;
        if (next_write >= tail)
            queue->write_to = queue->head;
    } else {
        memcpy(queue->storage.queue.read_from, item, item_bytes);
        unsigned int stored_item_bytes = queue->item_size;
        unsigned int current_read = (unsigned int)queue->storage.queue.read_from;
        unsigned int head = (unsigned int)queue->head;
        unsigned int previous_read = current_read - stored_item_bytes;
        queue->storage.queue.read_from = (unsigned char *)previous_read;
        if (previous_read < head)
            queue->storage.queue.read_from =
                (unsigned char *)((unsigned int)queue->storage.queue.tail - stored_item_bytes);
        if (position == 2) {
            if (messages == 0)
                messages = 1;
        } else {
            ++messages;
        }
    }
    memw();
    queue->messages_waiting = messages;
    return yield_required;
}

/* Native entry: 0x4038127c. */
/*
 * Medius v3.4.7 — host application; 0x4038127c.
 *
 * Notifies a queue-set container and returns the required yield decision.
 *
 * Calls: prvCopyDataToQueue, xTaskRemoveFromEventList, __assert_func, vPortExitCritical, xPortEnterCriticalTimeout,
 * xPortInIsrContext.
 *
 * Called by: FUN_40381670, xQueueGiveFromISR, xQueueGenericSend.
 *
 * Original function-byte SHA-256:
 * dc02e9771c495e8343c81b60b7b4b7adee11dbe190ff94a0bfae0262dc469988.
 */

/*
 * Posts a member queue's handle to its queue-set container and wakes a waiter.
 * member: valid queue whose set_container is non-NULL; caller already holds
 * the member's critical section. Returns the copy helper's yield decision,
 * forced to 1 if removing a container waiter requires a local yield.
 *
 * Asserts non-NULL container and available space before locking it. Calls the
 * ISR-context probe, acquires the container lock indefinitely, and rechecks space.
 * If space remains, copies the member pointer as one back-of-queue item, then
 * optionally unblocks a receiver. A container found full after locking returns 0.
 * Calls the ISR probe again before unlocking; both probe results are discarded.
 *
 * Requires initialized compatible queue-set storage (pointer-sized items),
 * correct lock ordering and kernel-valid calling context. No allocation or
 * immediate task switch occurs. A nonzero return requests a yield in its caller;
 * this return was incorrectly rendered void in the raw decompilation.
 */
int prvNotifyQueueSetContainer(const RtosQueue *member)
{
    RtosQueue *container = member->set_container;
    const RtosQueue *member_handle = member;
    if (container == 0)
        __assert_func(0, 0, 0, 0);
    memw();
    unsigned int observed_messages = container->messages_waiting;
    unsigned int capacity = container->capacity;
    if (observed_messages >= capacity)
        __assert_func(0, 0, 0, 0);

    (void)xPortInIsrContext();
    (void)xPortEnterCriticalTimeout(&container->lock, -1);
    memw();
    unsigned int locked_messages = container->messages_waiting;
    unsigned int locked_capacity = container->capacity;
    int yield_required = 0;
    if (locked_messages < locked_capacity) {
        yield_required = prvCopyDataToQueue(container, &member_handle, 0);
        memw();
        unsigned int waiting_receivers = container->waiting_to_receive.count;
        if (waiting_receivers != 0 &&
            xTaskRemoveFromEventList(&container->waiting_to_receive) != 0)
            yield_required = 1;
    }
    (void)xPortInIsrContext();
    vPortExitCritical(&container->lock);
    return yield_required;
}

/* Native entry: 0x40381728. */
/*
 * Medius v3.4.7 — host application; 0x40381728.
 *
 * Gives a semaphore token from ISR context and reports a task wakeup.
 *
 * Calls: prvNotifyQueueSetContainer, xTaskRemoveFromEventList, __assert_func, vPortExitCritical, xPortEnterCriticalTimeout.
 *
 * Called by: FUN_40376a1c, _lock_release, FUN_4038d550, link_uart_interrupt_handler, medius_out_complete,
 * usb_osal_sem_give.
 *
 * Original function-byte SHA-256:
 * cc2c05859f344811c301647449e5e9dd4c1598191935b688d335d2f84a8e814b.
 */

/*
 * Gives one semaphore token from interrupt context; returns1 on admission or 0
 * if its count already equals/exceeds capacity. queue must be non-NULL and
 * item_size must be 0; a mutex with a non-NULL holder also asserts.
 * higher_priority_task_woken is optional writable int output. It is only set
 * to 1 when a waiter requires a local yield and is never cleared here.
 *
 * Takes the queue spinlock with an infinite wait, checks capacity, and increments
 * the saved token count with native MEMW ordering. A queue-set member notifies
 * its set container; otherwise an existing receive waiter is unblocked. The
 * set-container pointer is sampled before publishing the increment, as native.
 * Releases the lock on both full and admitted paths. Does not allocate, copy
 * item data, block for space, or request an actual task switch itself.
 * Requires kernel-compatible ISR priority and initialized queue/list/lock
 * state. Caller handles a nonzero woken flag and semaphore saturation.
 */
int xQueueGiveFromISR(RtosQueue *queue, int *higher_priority_task_woken)
{
    if (queue == 0 || queue->item_size != 0 ||
        (queue->head == 0 && queue->storage.semaphore.holder != 0))
        __assert_func(0, 0, 0, 0);

    (void)xPortEnterCriticalTimeout(&queue->lock, -1);
    memw();
    unsigned int messages = queue->messages_waiting;
    unsigned int capacity = queue->capacity;
    int result = 0;
    if (messages < capacity) {
        unsigned int next_messages = messages + 1U;
        RtosQueue *container = queue->set_container;
        memw();
        queue->messages_waiting = next_messages;
        int yield_required = 0;
        if (container != 0) {
            yield_required = prvNotifyQueueSetContainer(queue);
        } else {
            memw();
            unsigned int waiting_receivers = queue->waiting_to_receive.count;
            if (waiting_receivers != 0)
                yield_required = xTaskRemoveFromEventList(&queue->waiting_to_receive);
        }
        if (higher_priority_task_woken != 0 && yield_required != 0)
            *higher_priority_task_woken = 1;
        result = 1;
    }
    vPortExitCritical(&queue->lock);
    return result;
}

/* Native entry: 0x403812e0. */
/*
 * Medius v3.4.7 — host application; 0x403812e0.
 *
 * Empties and initializes/resets a FreeRTOS queue.
 *
 * Calls: esp_crosscore_int_send_yield, vListInitialise, xTaskRemoveFromEventList, __assert_func, vPortExitCritical,
 * xPortEnterCriticalTimeout.
 *
 * Called by: FUN_40381374, FUN_40381610, xQueueCreateMutex, xQueueGenericCreate.
 *
 * Original function-byte SHA-256:
 * f902398682c2b2fc3d891266e0a2ddc2c79bdb849fc85db6cc8df88364b72702.
 */

/*
 * Empties and initializes/reset a queue's circular storage state.
 * queue must be non-NULL with nonzero capacity and a capacity*item_size product
 * fitting 32 bits; invalid conditions assert. new_queue==1 initializes its
 * spinlock before checking capacity/product. Any nonzero new_queue initializes
 * both wait lists; zero retains the existing lists and uses the existing lock.
 * Noncanonical nonzero values therefore do not initialize the lock themselves.
 * Returns 1 after reset; no ordinary failure result is supplied.
 *
 * Under the queue lock, reloads item_size/capacity/head, clears message count
 * after MEMW, sets tail=head+storage_bytes, write_to=head, and read_from to
 * head+storage_bytes-item_size using native unsigned 32-bit address arithmetic.
 * Zero-size objects retain the corresponding head-address values in these words.
 *
 * For an existing queue, a waiting sender may be unblocked and a yield interrupt
 * requested on fresh PRID bit 13 before unlocking. Receive waiters remain linked.
 * New queues instead initialize both lists under the new lock. No payload
 * clearing, allocation, ownership transfer or queue-set notification occurs.
 * Requires adequate live storage and exclusive initialization/reset ownership;
 * allocation flag and set-container fields are left for the caller to establish.
 */
int xQueueGenericReset(RtosQueue *queue, int new_queue)
{
    if (queue == 0)
        __assert_func(0, 0, 0, 0);
    if (new_queue == 1) {
        queue->lock.owner = PORTMUX_FREE_OWNER;
        queue->lock.count = 0;
    }
    unsigned int capacity = queue->capacity;
    if (capacity == 0 ||
        ((unsigned long long)capacity * queue->item_size >> 32) != 0)
        __assert_func(0, 0, 0, 0);

    (void)xPortEnterCriticalTimeout(&queue->lock, -1);
    unsigned int item_bytes = queue->item_size;
    unsigned int locked_capacity = queue->capacity;
    unsigned int head_address = (unsigned int)queue->head;
    unsigned int storage_bytes = item_bytes * locked_capacity;
    /* Keep the four native reset stores ordered without adding a barrier. */
    volatile RtosQueue *reset_state = queue;
    memw();
    reset_state->messages_waiting = 0;
    reset_state->storage.queue.tail = (unsigned char *)(head_address + storage_bytes);
    reset_state->write_to = (unsigned char *)head_address;
    reset_state->storage.queue.read_from =
        (unsigned char *)(head_address + storage_bytes - item_bytes);
    if (new_queue == 0) {
        memw();
        unsigned int waiting_senders = queue->waiting_to_send.count;
        if (waiting_senders != 0 &&
            xTaskRemoveFromEventList(&queue->waiting_to_send) != 0) {
            unsigned int current_core = (xtensa_read_prid() >> 13) & 1U;
            esp_crosscore_int_send_yield((int)current_core);
        }
    } else {
        vListInitialise(&queue->waiting_to_send);
        vListInitialise(&queue->waiting_to_receive);
    }
    vPortExitCritical(&queue->lock);
    return 1;
}

/* Native entry: 0x40381374. */
/*
 * Medius v3.4.7 — host application; 0x40381374.
 *
 * Initializes a queue in caller-provided static storage.
 *
 * Calls: xQueueGenericReset, __assert_func.
 *
 * Called by: FUN_420036bc.
 *
 * Original function-byte SHA-256:
 * f9722cf40070cdc0340cfb889f75ed1ad39bd6706a40ed066e251d019213d3ca.
 */

/*
 * Initializes a queue using caller-provided storage, with no allocation.
 * capacity must be nonzero and control must be writable 84-byte queue storage.
 * For nonzero item_size, storage must be non-NULL and cover capacity*item_size
 * bytes; for zero item_size, storage must be NULL. Violations assert. Returns
 * control after initialization; no NULL-on-failure path is present.
 *
 * Retains the native volatile local size check: the opaque static control type
 * occupies 84 bytes in this image and is compared with the actual queue layout.
 * The subsequent otherwise-unused volatile read and MEMW ordering are retained.
 * This does not inspect or validate the caller's allocated buffer extent.
 *
 * Sets static-allocation flag 1 and capacity, selects head=control for zero-size
 * items or the supplied data storage, stores item_size, resets as a new queue,
 * then clears set_container. The reset helper validates multiplication overflow
 * after these header stores. Payload storage and alignment padding are not
 * cleared. Caller retains ownership/lifetime of both buffers and must ensure
 * valid alignment, adequate extents and exclusive initialization access.
 * This specialized native entry does not read a queue-type argument.
 */
RtosQueue *xQueueGenericCreateStatic(unsigned int capacity, unsigned int item_size,
                                           unsigned char *storage,
                                           RtosQueue *control)
{
    if (control == 0 || capacity == 0 ||
        (storage != 0 && item_size == 0) || (storage == 0 && item_size != 0))
        __assert_func(0, 0, 0, 0);

    volatile unsigned int static_control_bytes;
    memw();
    static_control_bytes = 84U;
    memw();
    if (static_control_bytes != sizeof(RtosQueue))
        __assert_func(0, 0, 0, 0);

    unsigned char *head = item_size == 0 ? (unsigned char *)control : storage;
    control->statically_allocated = 1;
    control->capacity = capacity;
    memw();
    (void)static_control_bytes;
    control->head = head;
    control->item_size = item_size;
    (void)xQueueGenericReset(control, 1);
    control->set_container = 0;
    return control;
}

/* Native entry: 0x40381610. */
/*
 * Medius v3.4.7 — host application; 0x40381610.
 *
 * Creates a mutex in caller-provided static control storage.
 *
 * Calls: xQueueGenericReset, __assert_func, xQueueGenericSend.
 *
 * Called by: FUN_420036bc, FUN_42007054.
 *
 * Original function-byte SHA-256:
 * e9bbd1ca3659323486b6f86236880223bedfa436446faefbee7e7fbc79c59a72.
 */

/*
 * Creates an available, unowned mutex in caller-provided 84-byte control storage.
 * queue_type is an unused SDK byte argument; retaining it preserves the native
 * second-argument position of control. control must be non-NULL, writable,
 * aligned storage with a lifetime covering every use of the mutex. Returns
 * control after initialization, correcting the raw decompiler's void result.
 *
 * Retains the volatile local 84-byte static-control size assertion, its later
 * discarded reload and all three native MEMWs. This checks the build's layout,
 * not the caller's actual buffer extent. Marks static allocation, sets capacity
 * one/zero item size/self head, resets as new, then clears set membership, owner,
 * head and recursion count and reinitializes the spinlock. The write pointer
 * remains the control address. Gives the initial token with zero wait/back
 * xQueueGenericSend, ignoring its result. No allocation or whole-object clear.
 * Requires initialized kernel primitives and exclusive construction ownership.
 */
RtosQueue *xQueueCreateMutexStatic(unsigned char queue_type,
                                         RtosQueue *control)
{
    (void)queue_type;
    if (control == 0)
        __assert_func(0, 0, 0, 0);
    volatile unsigned int static_control_bytes;
    memw();
    static_control_bytes = 84U;
    memw();
    if (static_control_bytes != sizeof(RtosQueue))
        __assert_func(0, 0, 0, 0);

    /* Preserve header-store ordering around the native volatile size reload. */
    volatile RtosQueue *initial_state = control;
    initial_state->statically_allocated = 1;
    initial_state->capacity = 1;
    memw();
    (void)static_control_bytes;
    initial_state->head = (unsigned char *)control;
    initial_state->item_size = 0;
    (void)xQueueGenericReset(control, 1);
    control->set_container = 0;
    control->storage.semaphore.holder = 0;
    control->head = 0;
    control->storage.semaphore.recursion_count = 0;
    control->lock.owner = PORTMUX_FREE_OWNER;
    control->lock.count = 0;
    (void)xQueueGenericSend(control, 0, 0, QUEUE_SEND_TO_BACK);
    return control;
}

/* Native entry: 0x40381670. */
/*
 * Medius v3.4.7 — host application; 0x40381670.
 *
 * Copies a queue item from ISR context and reports a task wakeup.
 *
 * Calls: prvCopyDataToQueue, prvNotifyQueueSetContainer, xTaskRemoveFromEventList, __assert_func, vPortExitCritical,
 * xPortEnterCriticalTimeout.
 *
 * Called by: FUN_4037b688, medius_hid_report_enqueue, medius_hid_special_enqueue,
 * medius_usbh_queue_send_value, medius_vendor_complete.
 *
 * Original function-byte SHA-256:
 * ce6e729f0bdaa29bf7152c49d4c6e283b09c6e9bc2e9699bbcaf1d745ecbacda.
 */

/*
 * Sends/copies one item from interrupt context. queue must be initialized;
 * item covers item_size readable bytes without overlap with queue storage or
 * metadata. NULL is permitted for zero-size items. copy_position is 0=back,
 * 2=overwrite, with other nonzero values taking the front-copy helper path.
 * NULL queue, invalid item pointer and overwrite capacity other than one assert.
 *
 * Returns 1 on admission or 0 for a full non-overwrite queue. Acquires the queue
 * spinlock indefinitely but never waits for queue space. Retains the first
 * fenced count load even in overwrite mode, then a second fresh fenced count
 * before copying. The copy helper's return is discarded in this ISR entry.
 *
 * A nonempty queue-set member overwrite suppresses notification and wake output.
 * Other member sends notify the set; standalone sends may unblock a receiver.
 * higher_priority_task_woken is optional writable int output, only set to 1
 * when the corresponding waiter/set notification requires a local yield. It is
 * never cleared, and a NULL output does not suppress waiter removal/notification.
 * No task-switch request, allocation, scheduling timeout or payload lifetime
 * extension occurs here. Caller handles the wake flag. Requires valid queue
 * invariants, kernel-compatible ISR priority and normal ISR-safe object use.
 */
int xQueueGenericSendFromISR(RtosQueue *queue, const void *item,
                              int *higher_priority_task_woken, int copy_position)
{
    if (queue == 0 || (item == 0 && queue->item_size != 0) ||
        (copy_position == QUEUE_OVERWRITE && queue->capacity != 1))
        __assert_func(0, 0, 0, 0);
    int overwriting = copy_position == QUEUE_OVERWRITE;
    (void)xPortEnterCriticalTimeout(&queue->lock, -1);
    memw();
    unsigned int messages = queue->messages_waiting;
    if (!overwriting && messages >= queue->capacity) {
        vPortExitCritical(&queue->lock);
        return 0;
    }
    memw();
    unsigned int previous_messages = queue->messages_waiting;
    (void)prvCopyDataToQueue(queue, item, copy_position);
    int yield_required = 0;
    if (queue->set_container != 0) {
        if (!(overwriting && previous_messages != 0))
            yield_required = prvNotifyQueueSetContainer(queue);
    } else {
        memw();
        unsigned int waiting_receivers = queue->waiting_to_receive.count;
        if (waiting_receivers != 0)
            yield_required = xTaskRemoveFromEventList(&queue->waiting_to_receive);
    }
    if (higher_priority_task_woken != 0 && yield_required != 0)
        *higher_priority_task_woken = 1;
    vPortExitCritical(&queue->lock);
    return 1;
}

/* Native entry: 0x40381a78. */
/*
 * Medius v3.4.7 — host application; 0x40381a78.
 *
 * Removes a queue item from ISR context and reports a sender wakeup.
 *
 * Calls: xTaskRemoveFromEventList, __assert_func, memcpy, vPortExitCritical, xPortEnterCriticalTimeout.
 *
 * Called by: lock_acquire_generic, usb_osal_mq_recv.
 *
 * Original function-byte SHA-256:
 * c726a750fec0ec5cce7a58a5dee6b503f96d85c79faeff92bcc07a76a9323461.
 */

/*
 * Removes/copies one item from interrupt context, without waiting for data.
 * queue must be initialized; item must cover item_size writable bytes without
 * overlapping queue metadata/storage, or may be NULL for zero-size items.
 * Invalid queue/destination conditions assert. Returns 1 on removal, 0 if empty.
 *
 * Holds the queue spinlock, reads message count after MEMW, and for data items
 * advances/wraps the circular read pointer using native unsigned 32-bit address
 * arithmetic before memcpy. Publishes the decremented saved count after MEMW,
 * then may remove a blocked sender from its event list. An optional writable
 * higher_priority_task_woken is only set to 1 for a required local yield and
 * is never cleared. A NULL output does not skip sender removal.
 *
 * A zero-size receive only consumes a token; no mutex ownership/held-count or
 * priority-inheritance bookkeeping is performed here. No task-switch request,
 * allocation, data wait or queue-set cleanup is added. Caller handles the wake
 * flag and must supply valid queue/storage/lifetime invariants and a kernel-
 * compatible ISR context. Spinlock entry waits indefinitely and ignores status.
 */
int xQueueReceiveFromISR(RtosQueue *queue, void *item,
                          int *higher_priority_task_woken)
{
    if (queue == 0 || (item == 0 && queue->item_size != 0))
        __assert_func(0, 0, 0, 0);
    (void)xPortEnterCriticalTimeout(&queue->lock, -1);
    memw();
    unsigned int messages = queue->messages_waiting;
    int result = 0;
    if (messages != 0) {
        unsigned int item_bytes = queue->item_size;
        if (item_bytes != 0) {
            unsigned int current_read = (unsigned int)queue->storage.queue.read_from;
            unsigned int tail = (unsigned int)queue->storage.queue.tail;
            unsigned int next_read = current_read + item_bytes;
            queue->storage.queue.read_from = (unsigned char *)next_read;
            if (next_read >= tail) {
                next_read = (unsigned int)queue->head;
                queue->storage.queue.read_from = (unsigned char *)next_read;
            }
            memcpy(item, (const void *)next_read, item_bytes);
        }
        unsigned int next_messages = messages - 1U;
        memw();
        queue->messages_waiting = next_messages;
        memw();
        unsigned int waiting_senders = queue->waiting_to_send.count;
        if (waiting_senders != 0) {
            int yield_required = xTaskRemoveFromEventList(&queue->waiting_to_send);
            if (higher_priority_task_woken != 0 && yield_required != 0)
                *higher_priority_task_woken = 1;
        }
        result = 1;
    }
    vPortExitCritical(&queue->lock);
    return result;
}

/* Native entry: 0x40381b18. */
/*
 * Medius v3.4.7 — host application; 0x40381b18.
 *
 * Returns the unprotected queued-item count from ISR context.
 *
 * Calls: __assert_func.
 *
 * Called by: medius_vendor_complete.
 *
 * Original function-byte SHA-256:
 * 40e27e257a5082e0440a67ffea9ec63d80821c7a116e0c153af6fe53dd5eff59.
 */

/*
 * Returns the raw unsigned queued-item/token count after MEMW. queue must be
 * a live initialized object; NULL asserts. This ISR getter acquires no queue
 * lock and does not mask interrupts, wait, reserve an item or mutate state.
 * The aligned 32-bit snapshot may change immediately and does not synchronize
 * other queue fields or establish worker completion. Requires valid lifetime
 * and the kernel's queue layout/alignment; no bounds or ownership check.
 */
unsigned int uxQueueMessagesWaitingFromISR(const RtosQueue *queue)
{
    if (queue == 0)
        __assert_func(0, 0, 0, 0);
    memw();
    return queue->messages_waiting;
}

/* Native entry: 0x40381b30. */
/*
 * Medius v3.4.7 — host application; 0x40381b30.
 *
 * Frees dynamic queue storage and retains static storage.
 *
 * Calls: vPortFree, __assert_func.
 *
 * Called by: FUN_40376a70, usb_osal_mq_delete, usb_osal_mutex_delete, usb_osal_sem_delete.
 *
 * Original function-byte SHA-256:
 * a62a79a609e820aab57f1fc50e3e5535796b99b167e97d3352b9420745be6fcd.
 */

/*
 * Deletes a dynamically allocated queue through vPortFree; returns no value.
 * queue must be non-NULL or the native assertion path is taken. Reads its raw
 * allocation byte without a barrier: zero frees the complete dynamic block;
 * any nonzero value leaves caller-owned static storage untouched.
 *
 * No queue lock, waiter cancellation/unlinking, payload cleanup, buffer wipe
 * or caller-handle clearing is performed. Requires exclusive deletion access,
 * no remaining users/waiters and a valid ownership tag. The dynamic pointer
 * becomes invalid after freeing; this routine does not validate double-free
 * or malformed handles. The already-reviewed allocator handles the release.
 */
void vQueueDelete(RtosQueue *queue)
{
    if (queue == 0)
        __assert_func(0, 0, 0, 0);
    if (queue->statically_allocated == 0)
        vPortFree(queue);
}

/* Native entry: 0x4038142c. */
/* Original function-byte SHA-256:
 * ab885827076ec32ca26b651d26dffe323e49fdbab5795009707f891f0db71272. */
/* Assert a nonNULL queue, enter its embedded +0x4c critical section, and
 * return holder at +8 only when head at +0 is NULL (mutex representation).
 * Other queue kinds return NULL. Exit the same critical section before return;
 * this is a snapshot, not a lifetime/ownership guarantee. No explicit MEMW. */
RtosTask *xQueueGetMutexHolder(RtosQueue *queue)
{
    if (queue == 0)
        __assert_func(0,0,0,0);
    (void)xPortEnterCriticalTimeout(&queue->lock,-1);
    const volatile RtosQueue *q = queue;
    RtosTask *holder = 0;
    if (q->head == 0)
        holder = q->storage.semaphore.holder;
    vPortExitCritical(&queue->lock);
    return holder;
}

/* Native entry: 0x4038145c. */
/* Original function-byte SHA-256:
 * 0bedce85a31b986e6cf13fe300b01a452379486516ee7f9a247aa761ef7a9b9b. */
/* Create a counting semaphore with nonzero capacity and initial_count<=capacity.
 * Invalid arguments invoke the fatal assertion boundary with four zero WORDs;
 * no fabricated pointer return is supplied for that path. Call the generic
 * queue constructor with item_size0 and queue_type2 (the linked constructor
 * ignores that third argument). Return null on allocation failure. Otherwise
 * execute MEMW, store initial_count to the queue's messages_waiting WORD+0x38
 * and return the initialized queue. No payload allocation, token give loop,
 * independent lock or wakeup is performed here. Caller owns its lifetime. */
RtosQueue *xQueueCreateCountingSemaphore(unsigned int capacity,unsigned int initial_count)
{
    if (capacity==0U || capacity<initial_count) __assert_func(0,0,0,0);
    RtosQueue *queue=medius_rtos_create_queue_with_type(capacity,0,2);
    if (queue) {
        memw();
        queue->messages_waiting=initial_count;
    }
    return queue;
}
