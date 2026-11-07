/* Medius v3.4.7 device — FreeRTOS queues, semaphores and mutexes. */
#include "../include/types.h"

/* Native entry: 0x4038618c. */
/* Original function-byte SHA-256:
 * 3435727e193199f7507e2a14293abb7d96050a8d29151f4b55e91454902a5265. */
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

/* Native entry: 0x40386208. */
/* Original function-byte SHA-256:
 * 9310a7306d89f7706a483415b9b89734314ddc5cd539477f1212f30cfb439d50. */
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

/* Native entry: 0x403862fc. */
/* Original function-byte SHA-256:
 * 8886f7308af4a1d35d105cd21753daf80e8e407f2f86f23a3be1e5e968a90437. */
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

/* Native entry: 0x4038633c. */
/* Original function-byte SHA-256:
 * 4c2a45c20c75d32999664170f8fc73abf79b4e90f3e6d6f156d3c48ade79e048. */
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

  unsigned int remaining_depth = state->storage.semaphore.recursion_count - 1U;
  state->storage.semaphore.recursion_count = remaining_depth;
  if (remaining_depth == 0) {
    (void)xQueueGenericSend(mutex,0,0,QUEUE_SEND_TO_BACK);
  }
  return 1;
}

/* Native entry: 0x40386514. */
/* Original function-byte SHA-256:
 * 04fd64a8e9928729bb66211cdf88a81b4883d202665f4e1202c602d301a16d49. */
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

/* Native entry: 0x403865f0. */
/* Original function-byte SHA-256:
 * 4c5137282e6d3309f9f30e48bc5641150c53baf8cdcd6d2ec14f64e86c0ea79c. */
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

/* Native entry: 0x403866dc. */
/* Original function-byte SHA-256:
 * 9411fd8eb5453b06a85ef3a4570318f5ec6f99b7f9cc8a5622b0c060337dec59. */
/*
 * mutex: Live full 84-byte recursive-mutex queue; holder/depth are at offsets 8/12.
 *   NULL asserts.
 * wait_ticks: RTOS wait budget forwarded to semaphore take when the current task is not already
 *   owner.
 * Returns: 1 for successful ownership/recursion,0 when semaphore take fails.
 * Requirements/effects: Owner recursion increments without blocking or rerunning inheritance. Uses
 *   queue API for a new take; uint32 depth has no overflow check.
 */
int xQueueTakeMutexRecursive(RtosQueue *mutex,unsigned int wait_ticks)

{
  if (mutex == 0) __assert_func(0,0,0,0);
  volatile RtosQueue *state = mutex;
  RtosTask *holder = state->storage.semaphore.holder;
  RtosTask *current_task = xTaskGetCurrentTaskHandle();
  if (holder != current_task) {
    int result = xQueueSemaphoreTake(mutex,wait_ticks);
    if (result == 0) return 0;
  }
  unsigned int depth = state->storage.semaphore.recursion_count;
  state->storage.semaphore.recursion_count = depth + 1U;
  return 1;
}

/* Native entry: 0x40386714. */
/* Original function-byte SHA-256:
 * 3033f75e71e25229d5ef81f64669758210ee23c60187348968be358c33492d45. */
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

/* Native entry: 0x40386860. */
/* Original function-byte SHA-256:
 * df2205ad2f9ed8b9164e966954e7584bafb5ec9209dc91dcb8866568befb4d90. */
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

/* Native entry: 0x40385fa0. */
/* Original function-byte SHA-256:
 * 7e5d706cd2c2f88f1998750df01c76d998ae903712a1b2aaedeb9ae649485e4d. */
/*
 * Copies one item into a queue, or returns a semaphore/mutex token.
 * queue: initialized object already protected by its owning critical section.
 * item: item_size readable bytes for data queues; unused for zero-size items.
 * position: 0 appends, 2 overwrites at the front, all other values prepend.
 * Returns the priority-disinherit result when releasing a mutex, otherwise 0.
 *
 * Data overwrite uses max(old_count, 1); ordinary data sends increment the saved count.
 * Zero-size token/mutex operations increment modulo 2^32 even in overwrite mode;
 * no capacity clamp is inserted for that native case.
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

/* Native entry: 0x40386028. */
/* Original function-byte SHA-256:
 * a0def1a5ef33fe043b927b921da8ea6920f36796556f3afceb8aa4e6a858dcbb. */
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
 * the caller handles that request after this routine unlocks the container.
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

/* Native entry: 0x40386498. */
/* Original function-byte SHA-256:
 * 35a1c856d949bd712b1c7168b426b49398bdc60cf91fb05212cd5475404e3225. */
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

/* Native entry: 0x4038608c. */
/* Original function-byte SHA-256:
 * cfc47adf18027e8fdd2e599723288b21dc7a5429245642d75f85393f16f4a21a. */
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

/* Native entry: 0x40386120. */
/* Original function-byte SHA-256:
 * ab00dc7392cd995008018df8e423c3a72a211572c99342ff8000b7945a7e3c91. */
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

/* Native entry: 0x40386380. */
/* Original function-byte SHA-256:
 * c3eefc88cddbea3b225f8b33aa64f345a103c9b63f1e3b266a4471e0d34896b8. */
/*
 * Creates an available, unowned mutex in caller-provided 84-byte control storage.
 * queue_type is an unused SDK byte argument; retaining it preserves the native
 * second-argument position of control. control must be non-NULL, writable,
 * aligned storage with a lifetime covering every use of the mutex. Returns
 * control after initialization.
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

/* Native entry: 0x403863e0. */
/* Original function-byte SHA-256:
 * e9fb18468a011e69b429ec9e6a47c62bd770fb883d93c3af5903cd53e6f7ac35. */
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

/* Native entry: 0x403867e8. */
/* Original function-byte SHA-256:
 * 53a54ce39b05fee353df1303aa6c98ac589ca34d1f989db9d8ce57cff328926b. */
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

/* Native entry: 0x40386888. */
/* Original function-byte SHA-256:
 * 6db344fa4fae113e51aa767d25583aa6a1012f6ba02452d8b05beb167a123d0f. */
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
 * or malformed handles. The allocator handles the release.
 */
void vQueueDelete(RtosQueue *queue)
{
    if (queue == 0)
        __assert_func(0, 0, 0, 0);
    if (queue->statically_allocated == 0)
        vPortFree(queue);
}

/* Native entry: 0x403861d8. */
/* Original function-byte SHA-256:
 * f89d9b2a8beca2a16282c692dee9193a053760fe47f3cc044fff54dca10ef032. */
/* Assert a nonNULL queue, enter its embedded +0x4c critical section, and
 * return holder at +8 only when head at +0 is NULL (mutex representation).
 * Other queue kinds return NULL. Exit the same critical section before return;
 * this is a snapshot, not a lifetime/ownership guarantee. No explicit MEMW. */
RtosTask *xQueueGetMutexHolder(RtosQueue *queue)
{
    if (queue == 0)
        __assert_func(0,0,0,0);
    (void)xPortEnterCriticalTimeout(&queue->lock,-1);
    const volatile RtosQueue *state = queue;
    RtosTask *holder = 0;
    if (state->head == 0)
        holder = state->storage.semaphore.holder;
    vPortExitCritical(&queue->lock);
    return holder;
}
