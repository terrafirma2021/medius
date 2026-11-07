/* Medius v3.4.7 host — platform/timers.c.
 * Recovered C and native assembly, grouped for source navigation.
 * Original entry addresses, firmware-byte hashes and function comments follow.
 */

#include "../include/types.h"

/* Native entry: 0x40376dc0. */
/*
 * Medius v3.4.7 — host application; 0x40376dc0.
 *
 * Stores one of two dispatch deadlines and programs SYSTIMER alarm 2 to the earlier deadline under the time-update lock. Asserts for an alarm_id above 1; the timestamps use microseconds.
 *
 * Calls: systimer_hal_set_alarm_target, __assert_func, vPortExitCritical, xPortEnterCriticalTimeout,
 * xPortInIsrContext.
 *
 * Called by: timer_insert, timer_remove, esp_timer_task.
 *
 * Original function-byte SHA-256:
 * 6da5d9ca6fc768c3366f9ead50d210b0ec7ea61a1ab0554c1ca95fe73431b81c.
 */

/* Stores one of two dispatch deadlines and programs SYSTIMER alarm 2 to the earlier deadline under the time-update lock. Asserts for an alarm_id above 1; the timestamps use microseconds.
   SDK match: ESP-IDF v5.4.4 components/esp_timer/src/esp_timer_impl_systimer.c. */

/*
 * timestamp: Absolute microsecond deadline; UINT64_MAX represents no scheduled deadline.
 * alarm_id: Dispatch-class index0 or1; larger indices assert.
 * Returns: Nothing.
 * Requirements/effects: Stores the dispatch deadline under the time-update lock and programs
 *   shared hardware SYSTIMER comparator2 with the earlier of the two values. Does not dedicate a
 *   hardware comparator to each software timer or wait for callback completion.
 */

void esp_timer_impl_set_alarm_id(ulonglong timestamp,uint alarm_id)

{
  if (alarm_id > 1) __assert_func(0,0,0,0);
  (void)xPortInIsrContext();
  (void)xPortEnterCriticalTimeout(ESP_TIMER_DEADLINE_LOCK,-1);
  ESP_TIMER_DEADLINES[alarm_id].low = (uint)timestamp;
  ESP_TIMER_DEADLINES[alarm_id].high = (uint)(timestamp >> 32);
  uint task_high = ESP_TIMER_DEADLINES[0].high;
  uint interrupt_high = ESP_TIMER_DEADLINES[1].high;
  uint task_low = ESP_TIMER_DEADLINES[0].low;
  uint interrupt_low = ESP_TIMER_DEADLINES[1].low;
  bool task_is_earlier = task_high < interrupt_high ||
      (task_high == interrupt_high && task_low < interrupt_low);
  uint earliest_low = task_is_earlier ? task_low : interrupt_low;
  uint earliest_high = task_is_earlier ? task_high : interrupt_high;
  systimer_hal_set_alarm_target(CLOCK_HAL,2,((ulonglong)earliest_high << 32) | earliest_low);
  (void)xPortInIsrContext();
  vPortExitCritical(ESP_TIMER_DEADLINE_LOCK);
}

/* Native entry: 0x4037d3ec. */
/*
 * Medius v3.4.7 — host application; 0x4037d3ec.
 *
 * Inserts by ascending absolute alarm time, placing equal deadlines after existing entries. Maintains intrusive next/previous links and updates the shared hardware alarm when a new list head requires it. Caller owns the list lock; the SDK constant-zero return is optimized out in these images.
 *
 * Calls: esp_timer_impl_set_alarm_id.
 *
 * Called by: esp_timer_delete, esp_timer_start_once, esp_timer_start_periodic,
 * esp_timer_task.
 *
 * Original function-byte SHA-256:
 * 8d6c2bef13af2abcb5d6dee566d889ce0c178b31e4d89cd6a33e4d4f23180445.
 */

/* Inserts by ascending absolute alarm time, placing equal deadlines after existing entries. Maintains intrusive next/previous links and updates the shared hardware alarm when a new list head requires it. Caller owns the list lock; the SDK constant-zero return is optimized out in these images.
   SDK match: ESP-IDF v5.4.4 components/esp_timer/src/esp_timer.c. */

/*
 * timer: Valid unlinked timer with absolute alarm time and dispatch flag initialized.
 * without_update_alarm: Nonzero suppresses hardware-deadline update; zero updates when insertion
 *   creates the head.
 * Returns: Nothing; SDK constant-zero result is optimized out.
 * Requirements/effects: Caller owns the timer dispatch-list lock. Inserts in ascending 64-bit
 *   alarm order after existing equal deadlines. Maintains next and pointer-to-predecessor-link
 *   fields; does not allocate or invoke callbacks.
 */

void timer_insert(EspTimer *timer,int without_update_alarm)

{
  volatile EspTimer *state = timer;
  uint alarm_id = state->flags & 1U;
  EspTimer *volatile *head_slot = ESP_TIMER_LISTS + alarm_id;
  EspTimer *successor = *head_slot;
  if (successor == 0) {
    state->next = 0;
    *head_slot = timer;
    state->previous = head_slot;
  } else {
    uint new_low = state->alarm_low;
    uint new_high = state->alarm_high;
    for (;;) {
      volatile EspTimer *following = successor;
      uint successor_high = following->alarm_high;
      if (successor_high > new_high ||
          (successor_high == new_high && following->alarm_low > new_low)) {
        EspTimer *volatile *predecessor_link = following->previous;
        state->next = successor;
        state->previous = predecessor_link;
        *predecessor_link = timer;
        following->previous = &timer->next;
        break;
      }
      EspTimer *next = following->next;
      if (next == 0) {
        state->next = 0;
        following->next = timer;
        state->previous = &successor->next;
        break;
      }
      successor = next;
    }
    if (without_update_alarm != 0 || timer != *head_slot) return;
  }
  if (without_update_alarm != 0) return;
  uint alarm_low = state->alarm_low;
  uint alarm_high = state->alarm_high;
  esp_timer_impl_set_alarm_id(((ulonglong)alarm_high << 32) | alarm_low,alarm_id);
}

/* Native entry: 0x4037d45c. */
/*
 * Medius v3.4.7 — host application; 0x4037d45c.
 *
 * Unlinks the timer, clears alarm and period while preserving flags, and updates the shared alarm if the removed timer was the list head. Empty lists use UINT64_MAX. Its nested critical section uses the same recursive dispatch lock; the constant-zero return is optimized out.
 *
 * Calls: esp_timer_impl_set_alarm_id, vPortExitCritical, xPortEnterCriticalTimeout, xPortInIsrContext.
 *
 * Called by: esp_timer_stop.
 *
 * Original function-byte SHA-256:
 * caa74dd09ea5539b3c3b17536a6bcc9824e47aef7c7f3c178739b4c15711501e.
 */

/* Unlinks the timer, clears alarm and period while preserving flags, and updates the shared alarm if the removed timer was the list head. Empty lists use UINT64_MAX. Its nested critical section uses the same recursive dispatch lock; the constant-zero return is optimized out.
   SDK match: ESP-IDF v5.4.4 components/esp_timer/src/esp_timer.c. */

/*
 * timer: Currently linked timer with valid previous-link pointer.
 * Returns: Nothing; SDK constant-zero result is optimized out.
 * Requirements/effects: Takes its dispatch-list lock recursively, unlinks the object and clears
 *   alarm and56-bit period while preserving flags. If it was the head, programs the next deadline
 *   or UINT64_MAX. Does not clear stale next/previous fields or free the object.
 */

void timer_remove(EspTimer *timer)

{
  volatile EspTimer *state = timer;
  uint alarm_id = state->flags & 1U;
  PortMuxWords *lock = &ESP_TIMER_LIST_LOCKS[alarm_id];
  (void)xPortInIsrContext();
  (void)xPortEnterCriticalTimeout(lock,-1);
  EspTimer *next_timer = state->next;
  EspTimer *previous_head = ESP_TIMER_LISTS[alarm_id];
  if (next_timer != 0) {
    ((volatile EspTimer *)next_timer)->previous = state->previous;
  }
  *state->previous = next_timer;
  uint saved_flags = state->period_high_and_flags & 0xff000000U;
  state->alarm_low = 0;
  state->alarm_high = 0;
  state->period_low = 0;
  state->period_high_and_flags = saved_flags;
  if (timer == previous_head) {
    next_timer = ESP_TIMER_LISTS[alarm_id];
    ulonglong next_alarm = 0xffffffffffffffffULL;
    if (next_timer != 0) {
      uint low = ((volatile EspTimer *)next_timer)->alarm_low;
      uint high = ((volatile EspTimer *)next_timer)->alarm_high;
      next_alarm = ((ulonglong)high << 32) | low;
    }
    esp_timer_impl_set_alarm_id(next_alarm,alarm_id);
  }
  (void)xPortInIsrContext();
  vPortExitCritical(lock);
}

/* Native entry: 0x4037d4c8. */
/*
 * Medius v3.4.7 — host application; 0x4037d4c8.
 *
 * Arms an inactive software timer for now plus the 64-bit microsecond timeout. Rejects NULL, an uninitialized timer service or an already armed timer. Clears the periodic interval while preserving flags.
 *
 * Calls: timer_insert, esp_timer_get_time, vPortExitCritical, xPortEnterCriticalTimeout,
 * xPortInIsrContext.
 *
 * Called by: medius_motion_grid_timer_cb, FUN_4200f380, FUN_4202448c, medius_host_enumeration_timer_restart,
 * usb_osal_timer_start.
 *
 * Original function-byte SHA-256:
 * 96be3f3d1c571e121c92d4c643b6d8657f9a0dbdc732bbf73f8cc42966fc4b80.
 */

/* Arms an inactive software timer for now plus the 64-bit microsecond timeout. Rejects NULL, an uninitialized timer service or an already armed timer. Clears the periodic interval while preserving flags.
   SDK match: ESP-IDF v5.4.4 components/esp_timer/src/esp_timer.c. */

/*
 * timer: Live inactive timer object. NULL is rejected.
 * timeout_us: Unsigned64-bit delay added to the current microsecond clock; not separately range-
 *   checked.
 * Returns: 0 on success,0x102 for NULL,0x103 for uninitialized service or an already armed timer.
 * Requirements/effects: Samples current time before acquiring the dispatch lock, then checks
 *   inactivity and inserts. Clears periodic interval while preserving flags. Absolute-time
 *   addition can wrap; no callback-deadline guarantee, hardware-completion wait or allocation
 *   occurs here.
 */

int esp_timer_start_once(EspTimer *timer,ulonglong timeout_us)
{
  if (timer == 0) return 0x102;
  if (*ESP_TIMER_TASK_SLOT == 0) return 0x103;
  ulonglong now_us = (ulonglong)esp_timer_get_time();
  volatile EspTimer *state = timer;
  uint alarm_id = state->flags & 1U;
  PortMuxWords *lock = &ESP_TIMER_LIST_LOCKS[alarm_id];
  (void)xPortInIsrContext();
  (void)xPortEnterCriticalTimeout(lock,-1);
  uint alarm_high = state->alarm_high;
  uint alarm_low = state->alarm_low;
  int status = 0x103;
  if ((alarm_low | alarm_high) == 0) {
    uint saved_flags = state->period_high_and_flags & 0xff000000U;
    ulonglong expiration = now_us + timeout_us;
    state->alarm_low = (uint)expiration;
    state->alarm_high = (uint)(expiration >> 32);
    state->period_low = 0;
    state->period_high_and_flags = saved_flags;
    timer_insert(timer,0);
    status = 0;
  }
  (void)xPortInIsrContext();
  vPortExitCritical(lock);
  return status;
}

/* Native entry: 0x4037d544. */
/*
 * Medius v3.4.7 — host application; 0x4037d544.
 *
 * Clamps the requested period to 50 microseconds and arms an inactive timer for now plus that period under the dispatch-list lock. Stores the low 56 period bits while preserving flags; rejects NULL, uninitialized or already armed state.
 *
 * Calls: timer_insert, esp_timer_impl_get_min_period_us, esp_timer_get_time, vPortExitCritical,
 * xPortEnterCriticalTimeout, xPortInIsrContext.
 *
 * Called by: FUN_4200f588, medius_host_workers_init, usb_osal_timer_start.
 *
 * Original function-byte SHA-256:
 * a1ed30739eea01cb87d78d80d47cd5321e80155887cbc61dff7eac4a22cbb457.
 */


/* Clamps the requested period to 50 microseconds and arms an inactive timer for now plus that period under the dispatch-list lock. Stores the low 56 period bits while preserving flags; rejects NULL, uninitialized or already armed state.
   SDK match: ESP-IDF v5.4.4 components/esp_timer/src/esp_timer.c. */


/*
 * timer: Live inactive timer object. NULL is rejected.
 * interval_us: Requested unsigned64-bit period, clamped to a minimum of50 microseconds.
 * Returns: 0 on success,0x102 for NULL,0x103 for uninitialized service or an already armed timer.
 * Requirements/effects: Samples time before the dispatch lock, stores low56 period bits while
 *   preserving flags, and arms the first alarm at now plus the clamped full64-bit input. No upper-
 *   bound rejection exists. Software callback execution depends on scheduling, lock availability
 *   and other callbacks; the minimum period does not guarantee punctual dispatch.
 */

int esp_timer_start_periodic(EspTimer *timer,ulonglong interval_us)
{
  if (timer == 0) return 0x102;
  if (*ESP_TIMER_TASK_SLOT == 0) return 0x103;
  ulonglong minimum = esp_timer_impl_get_min_period_us();
  if (interval_us <= minimum) interval_us = esp_timer_impl_get_min_period_us();
  ulonglong now_us = (ulonglong)esp_timer_get_time();
  volatile EspTimer *state = timer;
  uint alarm_id = state->flags & 1U;
  PortMuxWords *lock = &ESP_TIMER_LIST_LOCKS[alarm_id];
  (void)xPortInIsrContext();
  (void)xPortEnterCriticalTimeout(lock,-1);
  uint alarm_low = state->alarm_low;
  uint alarm_high = state->alarm_high;
  int status = 0x103;
  if ((alarm_low | alarm_high) == 0) {
    uint saved_flags = state->period_high_and_flags & 0xff000000U;
    ulonglong expiration = now_us + interval_us;
    state->period_low = (uint)interval_us;
    state->period_high_and_flags = saved_flags | ((uint)(interval_us >> 32) & 0x00ffffffU);
    state->alarm_low = (uint)expiration;
    state->alarm_high = (uint)(expiration >> 32);
    timer_insert(timer,0);
    status = 0;
  }
  (void)xPortInIsrContext();
  vPortExitCritical(lock);
  return status;
}

/* Native entry: 0x4037d5d8. */
/*
 * Medius v3.4.7 — host application; 0x4037d5d8.
 *
 * Removes an armed timer under its dispatch-list lock. Returns invalid argument for NULL or invalid state for an uninitialized service/inactive timer; does not free the timer object.
 *
 * Calls: timer_remove, vPortExitCritical, xPortEnterCriticalTimeout, xPortInIsrContext.
 *
 * Called by: medius_motion_grid_timer_cb, FUN_4200f414, medius_hid_on_class_removed,
 * medius_host_enumeration_timer_restart, medius_usb_host_event, usb_osal_timer_delete,
 * usb_osal_timer_start.
 *
 * Original function-byte SHA-256:
 * cf8bbaf92425bd0bb76c6122dcf4bd591b675c8fae12a5b40edd32754a8b918a.
 */

/* Removes an armed timer under its dispatch-list lock. Returns invalid argument for NULL or invalid state for an uninitialized service/inactive timer; does not free the timer object.
   SDK match: ESP-IDF v5.4.4 components/esp_timer/src/esp_timer.c. */

/*
 * timer: Live timer to stop; NULL is rejected.
 * Returns: 0 after removing an armed timer,0x102 for NULL,0x103 for an uninitialized service or
 *   inactive timer.
 * Requirements/effects: Checks service state before taking the dispatch-list lock, then checks
 *   alarm activity and removes. Does not free the object or wait for a callback already
 *   selected/executing outside the lock.
 */

int esp_timer_stop(EspTimer *timer)
{
  if (timer == 0) return 0x102;
  if (*ESP_TIMER_TASK_SLOT == 0) return 0x103;
  volatile EspTimer *state = timer;
  uint alarm_id = state->flags & 1U;
  PortMuxWords *lock = &ESP_TIMER_LIST_LOCKS[alarm_id];
  (void)xPortInIsrContext();
  (void)xPortEnterCriticalTimeout(lock,-1);
  uint alarm_low = state->alarm_low;
  uint alarm_high = state->alarm_high;
  int status = 0x103;
  if ((alarm_low | alarm_high) != 0) {
    timer_remove(timer);
    status = 0;
  }
  (void)xPortInIsrContext();
  vPortExitCritical(lock);
  return status;
}

/* Native entry: 0x4037d62c. */
/*
 * Medius v3.4.7 — host application; 0x4037d62c.
 *
 * Returns the compiled minimum periodic ESP timer interval of 50 microseconds. This lower bound is not a guarantee of callback dispatch latency.
 *
 * Called by: esp_timer_start_periodic.
 *
 * Original function-byte SHA-256:
 * d8c854e681a4412d2eb99c7fe539db04e37752d0f02026ff36313c4674323d02.
 */

/* Returns the compiled minimum periodic ESP timer interval of 50 microseconds. This lower bound is not a guarantee of callback dispatch latency.
   SDK match: ESP-IDF v5.4.4 components/esp_timer/src/esp_timer_impl_common.c. */

/*
 * Returns: 50 microseconds as an unsigned64-bit value.
 * Requirements/effects: Constant compiled lower bound for periodic interval admission; no hardware
 *   action, scheduling guarantee or callback is performed.
 */

ulonglong esp_timer_impl_get_min_period_us(void)

{
  return 0x32;
}

/* Native entry: 0x42007528. */
/* Original function-byte SHA-256:
 * bab8f4ebc20e6ca41c20776cf1cdc5a4a96c5c08414a97e5000a57855d79bdba. */
/*
 * Acquires shared peripheral module0x24. Only prior reference count0 enables
 * SYSTEM clock bit29 and pulses reset bit29 with three fresh MEMW read/write
 * pairs. Always calls acquire-exit with that saved reference count. Reads the
 * two pinned tick conversion callbacks into a local8-byte ops object before
 * HAL init, then installs them, enables counter0, sets alarm2 to one-shot mode0,
 * connects alarm2 to counter0 and allows counter0 to stall on CPU0 AND CPU1.
 * Returns0; no local validation, interrupt enable/allocation, timer task,
 * alarm deadline, reload of the running count or driver lock is supplied.
 */
int esp_timer_impl_early_init(void)
{
    unsigned char reference_count = periph_rcc_acquire_enter(0x24);
    if (reference_count == 0) {
        memw(); unsigned int word = TIME_RCC_SYSTEM->peripheral_clock_enable0;
        memw(); TIME_RCC_SYSTEM->peripheral_clock_enable0 = word | 0x20000000U;
        memw(); word = TIME_RCC_SYSTEM->peripheral_reset_enable0;
        memw(); TIME_RCC_SYSTEM->peripheral_reset_enable0 = word | 0x20000000U;
        memw(); word = TIME_RCC_SYSTEM->peripheral_reset_enable0;
        memw(); TIME_RCC_SYSTEM->peripheral_reset_enable0 = word & 0xdfffffffU;
    }
    periph_rcc_acquire_exit(0x24,reference_count);
    SystimerTickOps ops;
    ops.ticks_to_us = TIME_TICK_CONVERSION_OPS->ticks_to_us;
    ops.us_to_ticks = TIME_TICK_CONVERSION_OPS->us_to_ticks;
    systimer_hal_init(CLOCK_HAL);
    systimer_hal_set_tick_rate_ops(CLOCK_HAL,&ops);
    systimer_hal_enable_counter(CLOCK_HAL,0);
    systimer_hal_select_alarm_mode(CLOCK_HAL,2,0);
    systimer_hal_connect_alarm_counter(CLOCK_HAL,2,0);
    systimer_hal_counter_can_stall_by_cpu(CLOCK_HAL,0,0,1);
    systimer_hal_counter_can_stall_by_cpu(CLOCK_HAL,0,1,1);
    return 0;
}

/* Native entry: 0x42013d28. */
/*
 * Medius v3.4.7 — host application; 0x42013d28.
 *
 * Dispatches due ESP software timer callbacks serially from the shared timer task.
 *
 * Calls: esp_timer_impl_set_alarm_id, timer_insert, ulTaskGenericNotifyTake, free, __udivdi3, esp_timer_get_time,
 * vPortExitCritical, xPortEnterCriticalTimeout, xPortInIsrContext.
 *
 * Indirect call: invokes the selected timer callback with its stored argument after unlocking.
 *
 * Original function-byte SHA-256:
 * 91cfec3ddcac8d67635ed40f2906bada499684f4b5c6849ebacd445ea65e19a1.
 */

/* Scheduling review: esp_timer: priority 22, stack 4096 bytes, core 0, creator 0x42013f48. Drains
 * due timer alarms after notification, handles periodic reinsertion/skip policy and deletion
 * markers, and invokes callbacks outside the list lock. Callbacks share one task and execute
 * serially; they do not get separate FreeRTOS priorities or stacks.
 */

/* ESP timer service task. Evidence: Runtime task label "esp_timer" passed with this entry address
   to xTaskCreatePinnedToCore by 0x42013f48; stack 4096 bytes, priority 22, core 0. Analyst symbol
   preserves the runtime label, not an original C symbol. */

/* Drains due software timers serially after a task notification. Reinserts periodic timers, clears one-shot alarms and frees deferred deletion events. Releases the timer-list lock around each callback. Overdue periods catch up unless the skip flag suppresses a backlog; the task argument is unused.
   SDK match: ESP-IDF v5.4.4 components/esp_timer/src/esp_timer.c. */


/*
 * argument: Unused task entry argument.
 * Returns: Never returns; repeats notification waits and due-timer dispatch.
 * Requirements/effects: Shared task-dispatch service, not a dedicated hardware timer per callback.
 *   Holds the list lock while selecting/unlinking/rearming, but releases it before invoking each
 *   callback serially. Long callbacks, higher-priority work and lock contention delay subsequent
 *   callbacks. One-shots clear their alarm; periodic timers reinsert before callback. Skip-
 *   unhandled mode uses now plus period when the signed low32-bit skipped count exceeds1;
 *   otherwise advances from the old alarm. Internal delete events free the object without invoking
 *   its marker.
 */

void esp_timer_task(void *argument)
{
  (void)argument;
  PortMuxWords *lock = &ESP_TIMER_LIST_LOCKS[0];
  for (;;) {
    (void)ulTaskGenericNotifyTake(0,1,0xffffffffU);
    (void)xPortInIsrContext();
    (void)xPortEnterCriticalTimeout(lock,-1);
    bool processed_any = false;
    for (;;) {
      EspTimer *timer = ESP_TIMER_LISTS[0];
      ulonglong now_us = (ulonglong)esp_timer_get_time();
      if (timer == 0) {
        if (processed_any) esp_timer_impl_set_alarm_id(0xffffffffffffffffULL,0);
        break;
      }
      volatile EspTimer *state = timer;
      uint alarm_high = state->alarm_high;
      uint alarm_low = state->alarm_low;
      ulonglong expiration = ((ulonglong)alarm_high << 32) | alarm_low;
      if (now_us < expiration) {
        esp_timer_impl_set_alarm_id(expiration,0);
        break;
      }
      EspTimer *next = state->next;
      if (next != 0) ((volatile EspTimer *)next)->previous = state->previous;
      EspTimer *volatile *predecessor_link = state->previous;
      uint event_id = state->event_id;
      *predecessor_link = next;
      if (event_id == ESP_TIMER_DELETE_EVENT) {
        free(timer);
      } else {
        uint period_high = state->period_high_and_flags & 0x00ffffffU;
        uint period_low = state->period_low;
        ulonglong period = ((ulonglong)period_high << 32) | period_low;
        if (period == 0) {
          state->alarm_low = 0;
          state->alarm_high = 0;
        } else {
          ulonglong elapsed = now_us - expiration;
          int skipped_periods = (int)(uint)rom_unsigned_divide_u64(elapsed,period);
          bool skip_backlog = false;
          if (skipped_periods > 1) skip_backlog = (state->flags & 2U) != 0;
          ulonglong next_expiration = (skip_backlog ? now_us : expiration) + period;
          /* The periodic rearm stores HIGH then LOW; one-shot clearing does the reverse. */
          state->alarm_high = (uint)(next_expiration >> 32);
          state->alarm_low = (uint)next_expiration;
          timer_insert(timer,1);
        }
        EspTimerCallback callback = state->callback;
        void *callback_argument = state->argument;
        (void)xPortInIsrContext();
        vPortExitCritical(lock);
        callback(callback_argument);
        (void)xPortInIsrContext();
        (void)xPortEnterCriticalTimeout(lock,-1);
      }
      processed_any = true;
    }
    (void)xPortInIsrContext();
    vPortExitCritical(lock);
  }
}

/* Native entry: 0x42013e60. */
/*
 * Medius v3.4.7 — host application; 0x42013e60.
 *
 * Allocates a task-dispatched software timer on the shared ESP timer service.
 *
 * Calls: heap_caps_calloc.
 *
 * Called by: FUN_4200f380, FUN_4200f588, FUN_4202448c, medius_host_workers_init,
 * usb_osal_timer_create.
 *
 * Original function-byte SHA-256:
 * 60ee3e7b6e5a9caa3b2dc798339695dccde7bc11ed35b5e25cad1cdcfbe80640.
 */

/* Scheduling review: Requires initialized timer task, non-NULL args/callback/output and
 * dispatch==0. Allocates 32 bytes, stores callback/argument and the skip flag, returns the
 * handle. No timer task or hardware channel is created per call. Creation does not start the
 * timer. This body admits task dispatch only.
 */

/* SDK boundary identity and ABI only. ESP-IDF v5.4.4 components/esp_timer/include/esp_timer.h and
   src/esp_timer.c; original callers and local SDK argument consumers match. The64-bit interval uses
   the Xtensa aligned register pair after a handle. This annotation does not establish a complete
   behavioral contract. */

/* Allocates a 32-byte task-dispatched timer, stores callback/argument/skip flags and returns its handle. Validates initialization and arguments; creation alone does not arm it.
   SDK match: ESP-IDF v5.4.4 components/esp_timer/src/esp_timer.c. */

/*
 * args: Creation arguments with a non-NULL callback and dispatch0 (shared task dispatch).
 * handle: Required writable output receiving the allocated timer pointer.
 * Returns: 0 on success,0x103 if service is uninitialized,0x102 for invalid
 *   arguments/dispatch,0x101 for allocation failure.
 * Requirements/effects: Allocates and zeroes32 bytes with capability mask0x804 (INTERNAL|8BIT),
 *   sets callback/argument/flags and publishes handle only on success. This build rejects ISR
 *   dispatch. Does not arm the timer. skip_unhandled_events is multiplied by2 into the flag byte
 *   rather than independently range-checked; name is unused with profiling disabled.
 */

int esp_timer_create(const EspTimerCreateArgs *args,EspTimer **handle)
{
  if (*ESP_TIMER_TASK_SLOT == 0) return 0x103;
  if (args == 0) return 0x102;
  const volatile EspTimerCreateArgs *fields = args;
  EspTimerCallback initial_callback = fields->callback;
  if (initial_callback == 0 || handle == 0) return 0x102;
  if (fields->dispatch != 0) return 0x102;
  EspTimer *timer = heap_caps_calloc(1,32,0x804);
  if (timer == 0) return 0x101;
  uint dispatch = fields->dispatch;
  unsigned char skip = fields->skip_unhandled_events;
  EspTimerCallback callback = fields->callback;
  void *callback_argument = fields->argument;
  volatile EspTimer *state = timer;
  state->callback = callback;
  state->argument = callback_argument;
  state->flags = (unsigned char)((dispatch != 0) | ((uint)skip << 1));
  *(EspTimer *volatile *)handle = timer;
  return 0;
}

/* Native entry: 0x42013ed0. */
/*
 * Medius v3.4.7 — host application; 0x42013ed0.
 *
 * Schedules deletion of an inactive timer through the shared timer task. Forces task dispatch, replaces the callback union with delete event 0xf0de1e1e and queues a current-time alarm; the timer task later frees it. Rejects NULL or an armed timer.
 *
 * Calls: timer_insert, esp_timer_get_time, vPortExitCritical, xPortEnterCriticalTimeout,
 * xPortInIsrContext.
 *
 * Called by: FUN_4200f414, usb_osal_timer_delete.
 *
 * Original function-byte SHA-256:
 * c370c3562dd60ce4bdd5be9a429c7ea77758b38f88e5b2c9cfaf0112d2cc656d.
 */

/* Schedules deletion of an inactive timer through the shared timer task. Forces task dispatch, replaces the callback union with delete event 0xf0de1e1e and queues a current-time alarm; the timer task later frees it. Rejects NULL or an armed timer.
   SDK match: ESP-IDF v5.4.4 components/esp_timer/src/esp_timer.c. */

/*
 * timer: Live inactive timer object; NULL is rejected and armed timers must first be stopped.
 * Returns: 0 when deletion is queued,0x102 for NULL,0x103 if still armed.
 * Requirements/effects: Samples time, then under the task-dispatch lock clears ISR dispatch,
 *   writes the internal delete marker and inserts a zero-period event. The shared timer task later
 *   frees the object. Successful return is asynchronous; caller must relinquish the pointer.
 *   Unlike start/stop, this body has no separate service-initialized check.
 */

int esp_timer_delete(EspTimer *timer)
{
  if (timer == 0) return 0x102;
  ulonglong now_us = (ulonglong)esp_timer_get_time();
  PortMuxWords *lock = &ESP_TIMER_LIST_LOCKS[0];
  (void)xPortInIsrContext();
  (void)xPortEnterCriticalTimeout(lock,-1);
  volatile EspTimer *state = timer;
  uint alarm_high = state->alarm_high;
  uint alarm_low = state->alarm_low;
  int status = 0x103;
  if ((alarm_low | alarm_high) == 0) {
    state->flags = state->flags & 0xfeU;
    uint saved_flags = state->period_high_and_flags & 0xff000000U;
    state->event_id = ESP_TIMER_DELETE_EVENT;
    state->alarm_low = (uint)now_us;
    state->alarm_high = (uint)(now_us >> 32);
    state->period_low = 0;
    state->period_high_and_flags = saved_flags;
    timer_insert(timer,0);
    status = 0;
  }
  (void)xPortInIsrContext();
  vPortExitCritical(lock);
  return status;
}

/* Native entry: 0x420074bc. */
/* Original function-byte SHA-256:
 * d7379ef8c7fa31447fb92d7ad8f0c65773fc265f85fb8ef29590b7546517c012. */
/*
 * Calls esp_timer_impl_early_init, discards its status, then calls system-time
 * correction initialization and returns0. No local short-circuit/error handling,
 * timer-task creation, interrupt allocation or software-timer scheduling occurs.
 */
int esp_timer_early_init(void)
{
    (void)esp_timer_impl_early_init();
    esp_timer_impl_init_system_time();
    return 0;
}

/* Native entry: 0x4037d3cc. */
/* Original function-byte SHA-256:
 * 8eac069271d2dc4fd35323f6bf6d4301712989cc126571d450c9727cbc6a79a3. */
/*
 * Ignores argument. Reads the shared ESP timer task handle, sets a local woken
 * WORD0 and gives task notification index0 through the ISR API. Requests a
 * switch only when the returned woken WORD equals1, not for every nonzero value.
 * No null-handle guard, alarm register operation, callback dispatch or timer
 * list processing occurs here. Deferred callbacks run in the shared timer task.
 */
void timer_alarm_handler(void *argument)
{
    (void)argument;
    int higher_priority_task_woken = 0;
    RtosTask *task = *ESP_TIMER_TASK_SLOT;
    vTaskGenericNotifyGiveFromISR(task,0,&higher_priority_task_woken);
    if (higher_priority_task_woken == 1) _frxt_setup_switch();
}

/* Native entry: 0x420075d0. */
/* Original function-byte SHA-256:
 * 9ae4a0c890394af663803b3238c27227246b908e59c87f52344c1693bfbfea8d. */
/*
 * Rejects a nonnull saved interrupt handle with0x103. Otherwise allocates source59
 * with flags0xc02, timer_alarm_isr and NULL argument, publishing via that slot.
 * Allocation failure returns its status. On success, if the alarm-handler slot
 * is empty, stores the supplied callback (evenNULL) then enables SYSTIMER alarm2
 * interrupt through the HAL. Rereads the interrupt handle and calls esp_intr_enable.
 * Returns its status; enable failure retains the handle/callback/alarm setup.
 * All three diagnostic paths test the current log-level WORD and, if nonzero,
 * call timestamp/ROM ets_printf. No allocation cleanup, rollback, lock or callback
 * validation. This installs an interrupt service; no software deadline is added.
 */
int esp_timer_impl_init(ClockAlarmHandler alarm_handler)
{
    if (*ESP_TIMER_INTERRUPT_SLOT != 0) {
        if (LOG_OUTPUT->default_level != 0) {
            unsigned int timestamp = esp_log_timestamp();
            ets_printf("E (%lu) %s: timer ISR is already initialized\n",timestamp,"esp_timer_systimer");
        }
        return 0x103;
    }
    int status = esp_intr_alloc(59,0xc02,timer_alarm_isr,0,(InterruptHandle **)ESP_TIMER_INTERRUPT_SLOT);
    if (status != 0) {
        if (LOG_OUTPUT->default_level != 0) {
            unsigned int timestamp = esp_log_timestamp();
            ets_printf("E (%lu) %s: esp_intr_alloc failed (0x%x)\n",timestamp,"esp_timer_systimer",status);
        }
        return status;
    }
    if (*CLOCK_ALARM_HANDLER == 0) {
        *CLOCK_ALARM_HANDLER = alarm_handler;
        systimer_hal_enable_alarm_int(CLOCK_HAL,2);
    }
    InterruptHandle *intr = *ESP_TIMER_INTERRUPT_SLOT;
    status = esp_intr_enable(intr);
    if (status != 0 && LOG_OUTPUT->default_level != 0) {
        unsigned int timestamp = esp_log_timestamp();
        ets_printf("E (%lu) %s: Can not enable ISR (0x%0x)\n",timestamp,"esp_timer_systimer",status);
    }
    return status;
}

/* Native entry: 0x42013f48. */
/* Original function-byte SHA-256:
 * 1a0c32a003e1c0b4af7768c13df3487500e7f236110e5488ed6998faff372720. */
/*
 * If the shared task slot is already nonnull, optionally ROM-logs and returns
 *0x103. Otherwise creates esp_timer_task named esp_timer with4096 stack
 * bytes, NULL argument, priority22 and CPU0, outputting through that slot.
 * Any creation result other than1 optionally logs and returns0x101; no cleanup
 * of a partially published task is supplied on that path. Success installs
 * timer_alarm_handler through esp_timer_impl_init. If installation fails,
 * optionally logs, REREADS the task slot and deletes/clears it if nonnull, then
 * returns the original ISR status. Any saved interrupt/callback setup is retained.
 * No service lock, deadline creation or guaranteed callback timing is supplied;
 * alarm processing is shared by the timer task and other scheduled work.
 */
int esp_timer_init(void)
{
    if (*ESP_TIMER_TASK_SLOT != 0) {
        if (LOG_OUTPUT->default_level != 0) {
            unsigned int timestamp = esp_log_timestamp();
            ets_printf("E (%lu) %s: Task is already initialized\n",timestamp,"esp_timer");
        }
        return 0x103;
    }
    int created = xTaskCreatePinnedToCore(esp_timer_task,"esp_timer",4096,0,22,
        (RtosTask **)ESP_TIMER_TASK_SLOT,0);
    if (created != 1) {
        if (LOG_OUTPUT->default_level != 0) {
            unsigned int timestamp = esp_log_timestamp();
            ets_printf("E (%lu) %s: Not enough memory to create timer task\n",timestamp,"esp_timer");
        }
        return 0x101;
    }
    int status = esp_timer_impl_init(timer_alarm_handler);
    if (status != 0) {
        if (LOG_OUTPUT->default_level != 0) {
            unsigned int timestamp = esp_log_timestamp();
            ets_printf("E (%lu) %s: ISR init failed\n",timestamp,"esp_timer");
        }
        RtosTask *task = *ESP_TIMER_TASK_SLOT;
        if (task != 0) {
            vTaskDelete(task);
            *ESP_TIMER_TASK_SLOT = 0;
        }
    }
    return status;
}

/* Native entry: 0x42013fec. */
/* Original function-byte SHA-256:
 * e1b8df5e08a4611e384829a64d8b25a534319d42aa3a89ef50d4c49610753544. */
/* OS startup wrapper: calls esp_timer_init and returns its unchanged status.
 * No retry, additional initialization, task creation or error translation here. */
int esp_timer_init_os(void)
{
    return esp_timer_init();
}
