/* Medius v3.4.7 device — shared software timers and SYSTIMER alarm setup. */
#include "../include/types.h"

/* Native entry: 0x40377138. */
/* Original function-byte SHA-256:
 * acb001376505f2e7c28d9fa73217a52bde87b85c239af575990f2820a878ff43. */
/* Store an absolute unsigned microsecond deadline for dispatch class 0 or 1.
 * Larger unsigned IDs call the native assertion boundary with four zero args.
 * Under the deadline lock, store LOW then HIGH, read both HIGHs then both LOWs,
 * and program shared SYSTIMER alarm 2 with the unsigned earlier deadline.
 * Equal timestamps select class 1. UINT64_MAX means no scheduled deadline.
 * This does not allocate a comparator per software timer or wait for callbacks. */
void esp_timer_impl_set_alarm_id(unsigned long long timestamp,unsigned int alarm_id)

{
  if (alarm_id > 1) __assert_func(0,0,0,0);
  (void)xPortInIsrContext();
  (void)xPortEnterCriticalTimeout(ESP_TIMER_DEADLINE_LOCK,-1);
  ESP_TIMER_DEADLINES[alarm_id].low = (unsigned int)timestamp;
  ESP_TIMER_DEADLINES[alarm_id].high = (unsigned int)(timestamp >> 32);
  unsigned int task_high = ESP_TIMER_DEADLINES[0].high;
  unsigned int interrupt_high = ESP_TIMER_DEADLINES[1].high;
  unsigned int task_low = ESP_TIMER_DEADLINES[0].low;
  unsigned int interrupt_low = ESP_TIMER_DEADLINES[1].low;
  bool task_is_earlier = task_high < interrupt_high ||
      (task_high == interrupt_high && task_low < interrupt_low);
  unsigned int earliest_low = task_is_earlier ? task_low : interrupt_low;
  unsigned int earliest_high = task_is_earlier ? task_high : interrupt_high;
  systimer_hal_set_alarm_target(CLOCK_HAL,2,((unsigned long long)earliest_high << 32) | earliest_low);
  (void)xPortInIsrContext();
  vPortExitCritical(ESP_TIMER_DEADLINE_LOCK);
}

/* Native entry: 0x4037ec84. */
/* Original function-byte SHA-256:
 * 00db2051756d4ed674d5b9955705e7a99d773e42c99d57cbc921866910ab1790. */
/* Insert an unlinked, initialized timer into its dispatch class's sorted list.
 * Compare unsigned 64-bit alarms; equal deadlines stay before the new entry.
 * Maintain next and previous (the address of the predecessor's link/head slot).
 * Caller owns the list lock. Any nonzero without_update_alarm suppresses the
 * shared deadline update; otherwise update only when this timer is the head.
 * No allocation, callback or SDK constant-zero return remains in this body. */
void timer_insert(EspTimer *timer,int without_update_alarm)

{
  volatile EspTimer *state = timer;
  unsigned int alarm_id = state->flags & 1U;
  EspTimer *volatile *head_slot = ESP_TIMER_LISTS + alarm_id;
  EspTimer *successor = *head_slot;
  if (successor == 0) {
    state->next = 0;
    *head_slot = timer;
    state->previous = head_slot;
  } else {
    unsigned int new_low = state->alarm_low;
    unsigned int new_high = state->alarm_high;
    for (;;) {
      volatile EspTimer *following = successor;
      unsigned int successor_high = following->alarm_high;
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
  unsigned int alarm_low = state->alarm_low;
  unsigned int alarm_high = state->alarm_high;
  esp_timer_impl_set_alarm_id(((unsigned long long)alarm_high << 32) | alarm_low,alarm_id);
}

/* Native entry: 0x4037ecf4. */
/* Original function-byte SHA-256:
 * ea3e0280790823b50b01f428468529b185e9da1d0f5bab9055758c548f339323. */
/* Recursively lock the linked timer's dispatch list, unlink it, and clear
 * alarm and the low 56 period bits while retaining all flag bits. next and
 * previous remain stale. If removing the old head, update the shared deadline
 * from the new head or UINT64_MAX. timer and its previous link must be valid.
 * No free, callback wait or SDK constant-zero return remains in this body. */
void timer_remove(EspTimer *timer)

{
  volatile EspTimer *state = timer;
  unsigned int alarm_id = state->flags & 1U;
  PortMuxWords *lock = &ESP_TIMER_LIST_LOCKS[alarm_id];
  (void)xPortInIsrContext();
  (void)xPortEnterCriticalTimeout(lock,-1);
  EspTimer *next_timer = state->next;
  EspTimer *previous_head = ESP_TIMER_LISTS[alarm_id];
  if (next_timer != 0) {
    ((volatile EspTimer *)next_timer)->previous = state->previous;
  }
  *state->previous = next_timer;
  unsigned int saved_flags = state->period_high_and_flags & 0xff000000U;
  state->alarm_low = 0;
  state->alarm_high = 0;
  state->period_low = 0;
  state->period_high_and_flags = saved_flags;
  if (timer == previous_head) {
    next_timer = ESP_TIMER_LISTS[alarm_id];
    unsigned long long next_alarm = 0xffffffffffffffffULL;
    if (next_timer != 0) {
      unsigned int low = ((volatile EspTimer *)next_timer)->alarm_low;
      unsigned int high = ((volatile EspTimer *)next_timer)->alarm_high;
      next_alarm = ((unsigned long long)high << 32) | low;
    }
    esp_timer_impl_set_alarm_id(next_alarm,alarm_id);
  }
  (void)xPortInIsrContext();
  vPortExitCritical(lock);
}

/* Native entry: 0x4037ed60. */
/* Original function-byte SHA-256:
 * 525ad26acbfbba5bbc520b938f006ae6058f220a3bdd51775226a4002bb18e48. */
/* Arm a live inactive timer once at current time plus timeout_us modulo 2^64.
 * NULL returns 0x102; missing service task or active alarm returns 0x103.
 * Sample time before locking, then test activity (HIGH followed by LOW).
 * Store alarm LOW/HIGH and clear the period while preserving flags; insert
 * with deadline update. Return 0 on success. No allocation or timeout bound.
 * An alarm wrapping to zero still gets inserted; no native repair is added.
 * Callback timing depends on scheduling, other callbacks and lock contention. */
int esp_timer_start_once(EspTimer *timer,unsigned long long timeout_us)
{
  if (timer == 0) return 0x102;
  if (*ESP_TIMER_TASK_SLOT == 0) return 0x103;
  unsigned long long now_us = (unsigned long long)esp_timer_get_time();
  volatile EspTimer *state = timer;
  unsigned int alarm_id = state->flags & 1U;
  PortMuxWords *lock = &ESP_TIMER_LIST_LOCKS[alarm_id];
  (void)xPortInIsrContext();
  (void)xPortEnterCriticalTimeout(lock,-1);
  unsigned int alarm_high = state->alarm_high;
  unsigned int alarm_low = state->alarm_low;
  int status = 0x103;
  if ((alarm_low | alarm_high) == 0) {
    unsigned int saved_flags = state->period_high_and_flags & 0xff000000U;
    unsigned long long expiration = now_us + timeout_us;
    state->alarm_low = (unsigned int)expiration;
    state->alarm_high = (unsigned int)(expiration >> 32);
    state->period_low = 0;
    state->period_high_and_flags = saved_flags;
    timer_insert(timer,0);
    status = 0;
  }
  (void)xPortInIsrContext();
  vPortExitCritical(lock);
  return status;
}

/* Native entry: 0x4037eddc. */
/* Original function-byte SHA-256:
 * 32b48d5e862cdaedd13293fe2a96569cf24621ffd0b1dd0e5fb1e793d0596f27. */
/* Clamp the unsigned 64-bit interval to 50 us; the native code calls the
 * minimum-period getter again when input <= its first result. Sample time
 * before locking. Reject NULL with 0x102 and missing service/active timer with
 * 0x103. On success store the low 56 period bits, retain flags, then store the
 * first alarm from now plus the full clamped input modulo 2^64 and insert.
 * Return 0. No upper-bound rejection or punctual callback guarantee is added. */
int esp_timer_start_periodic(EspTimer *timer,unsigned long long interval_us)
{
  if (timer == 0) return 0x102;
  if (*ESP_TIMER_TASK_SLOT == 0) return 0x103;
  unsigned long long minimum = esp_timer_impl_get_min_period_us();
  if (interval_us <= minimum) interval_us = esp_timer_impl_get_min_period_us();
  unsigned long long now_us = (unsigned long long)esp_timer_get_time();
  volatile EspTimer *state = timer;
  unsigned int alarm_id = state->flags & 1U;
  PortMuxWords *lock = &ESP_TIMER_LIST_LOCKS[alarm_id];
  (void)xPortInIsrContext();
  (void)xPortEnterCriticalTimeout(lock,-1);
  unsigned int alarm_low = state->alarm_low;
  unsigned int alarm_high = state->alarm_high;
  int status = 0x103;
  if ((alarm_low | alarm_high) == 0) {
    unsigned int saved_flags = state->period_high_and_flags & 0xff000000U;
    unsigned long long expiration = now_us + interval_us;
    state->period_low = (unsigned int)interval_us;
    state->period_high_and_flags = saved_flags | ((unsigned int)(interval_us >> 32) & 0x00ffffffU);
    state->alarm_low = (unsigned int)expiration;
    state->alarm_high = (unsigned int)(expiration >> 32);
    timer_insert(timer,0);
    status = 0;
  }
  (void)xPortInIsrContext();
  vPortExitCritical(lock);
  return status;
}

/* Native entry: 0x4037ee70. */
/* Original function-byte SHA-256:
 * 1e56534e8f2609c66d2de850abfecf4fdb8550f7d350f028615db9f5e4aed4be. */
/* Return 0x102 for NULL and 0x103 for missing service or an inactive alarm.
 * Under the selected dispatch lock, read alarm LOW then HIGH and remove an
 * active timer through the recursively locked helper; return 0. Does not free
 * it or wait for a callback already selected/executing outside the list lock. */
int esp_timer_stop(EspTimer *timer)
{
  if (timer == 0) return 0x102;
  if (*ESP_TIMER_TASK_SLOT == 0) return 0x103;
  volatile EspTimer *state = timer;
  unsigned int alarm_id = state->flags & 1U;
  PortMuxWords *lock = &ESP_TIMER_LIST_LOCKS[alarm_id];
  (void)xPortInIsrContext();
  (void)xPortEnterCriticalTimeout(lock,-1);
  unsigned int alarm_low = state->alarm_low;
  unsigned int alarm_high = state->alarm_high;
  int status = 0x103;
  if ((alarm_low | alarm_high) != 0) {
    timer_remove(timer);
    status = 0;
  }
  (void)xPortInIsrContext();
  vPortExitCritical(lock);
  return status;
}

/* Native entry: 0x4037eec4. */
/* Original function-byte SHA-256:
 * d8c854e681a4412d2eb99c7fe539db04e37752d0f02026ff36313c4674323d02. */
/* Return the compiled unsigned 64-bit minimum periodic interval: 50 us.
 * This is an admission limit, with no hardware action or latency guarantee. */
unsigned long long esp_timer_impl_get_min_period_us(void)

{
  return 0x32;
}

/* Native entry: 0x42007af4. */
/* Original function-byte SHA-256:
 * e8d82d7bc573ff0d29f0e2cda150035ea1e9689dde8de08875851014fe9c5fda. */
/* Acquire SYSTIMER's peripheral reference guard. Only a zero previous byte
 * enables SYSTEM clock bit 29 and pulses reset through three fresh read/write
 * pairs; release with the original byte. Read both pinned conversion pointers
 * before either local store, then initialize HAL and install the eight-byte pair.
 * Enable counter 0, select one-shot alarm 2, connect it to counter 0 and allow
 * counter 0 to stall with either CPU. Return 0. No counter-value reload, deadline,
 * interrupt installation/enable, software task or all-HAL writer lock here. */
int esp_timer_impl_early_init(void)
{
    unsigned char reference_count = periph_rcc_acquire_enter(PERIPH_SYSTIMER_MODULE);
    if (reference_count == 0) {
        memw(); unsigned int word = TIME_RCC_SYSTEM->peripheral_clock_enable0;
        memw(); TIME_RCC_SYSTEM->peripheral_clock_enable0 = word | 0x20000000U;
        memw(); word = TIME_RCC_SYSTEM->peripheral_reset_enable0;
        memw(); TIME_RCC_SYSTEM->peripheral_reset_enable0 = word | 0x20000000U;
        memw(); word = TIME_RCC_SYSTEM->peripheral_reset_enable0;
        memw(); TIME_RCC_SYSTEM->peripheral_reset_enable0 = word & 0xdfffffffU;
    }
    periph_rcc_acquire_exit(PERIPH_SYSTIMER_MODULE,reference_count);
    SystimerTickOps ops;
    SystimerConvert ticks_to_us = TIME_TICK_CONVERSION_OPS->ticks_to_us;
    SystimerConvert us_to_ticks = TIME_TICK_CONVERSION_OPS->us_to_ticks;
    ops.ticks_to_us = ticks_to_us;
    ops.us_to_ticks = us_to_ticks;
    systimer_hal_init(CLOCK_HAL);
    systimer_hal_set_tick_rate_ops(CLOCK_HAL,&ops);
    systimer_hal_enable_counter(CLOCK_HAL,0);
    systimer_hal_select_alarm_mode(CLOCK_HAL,2,0);
    systimer_hal_connect_alarm_counter(CLOCK_HAL,2,0);
    systimer_hal_counter_can_stall_by_cpu(CLOCK_HAL,0,0,1);
    systimer_hal_counter_can_stall_by_cpu(CLOCK_HAL,0,1,1);
    return 0;
}

/* Native entry: 0x42011734. */
/* Original function-byte SHA-256:
 * d73311dbba749237d7bcd23d8763b24a6f2efe426bbe340b72d7ba4adfa91604. */
/* Shared ESP software-timer task: notification index 0, clear-on-take, infinite
 * wait. This build creates it on CPU 0, priority 22, with a 4096-byte stack.
 * Lock task list 0; read its head, then sample time even when the list is empty.
 * Due timers are unlinked before dispatch. Internal delete events are freed.
 * One-shots clear alarm LOW/HIGH; periodic timers read period HIGH/flags then
 * LOW, divide unsigned elapsed time by period, and test the signed low 32 bits
 * of the quotient. Read skip flag only if that signed value exceeds one.
 * With skip set use now + period; otherwise old alarm + period, modulo 2^64.
 * Store periodic alarm HIGH then LOW and reinsert before calling the callback.
 * Read callback and argument while locked, unlock for the call, then relock.
 * Callbacks run serially. Blocking callbacks, higher-priority work and locks
 * delay later callbacks; software timers have no punctual execution guarantee.
 * Program the next future head, or UINT64_MAX only if work emptied the list.
 * argument is unused. The task never returns; no callback-null check is added. */
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
      unsigned long long now_us = (unsigned long long)esp_timer_get_time();
      if (timer == 0) {
        if (processed_any) esp_timer_impl_set_alarm_id(0xffffffffffffffffULL,0);
        break;
      }
      volatile EspTimer *state = timer;
      unsigned int alarm_high = state->alarm_high;
      unsigned int alarm_low = state->alarm_low;
      unsigned long long expiration = ((unsigned long long)alarm_high << 32) | alarm_low;
      if (now_us < expiration) {
        esp_timer_impl_set_alarm_id(expiration,0);
        break;
      }
      EspTimer *next = state->next;
      if (next != 0) ((volatile EspTimer *)next)->previous = state->previous;
      EspTimer *volatile *predecessor_link = state->previous;
      unsigned int event_id = state->event_id;
      *predecessor_link = next;
      if (event_id == ESP_TIMER_DELETE_EVENT) {
        free(timer);
      } else {
        unsigned int period_high = state->period_high_and_flags & 0x00ffffffU;
        unsigned int period_low = state->period_low;
        unsigned long long period = ((unsigned long long)period_high << 32) | period_low;
        if (period == 0) {
          state->alarm_low = 0;
          state->alarm_high = 0;
        } else {
          unsigned long long elapsed = now_us - expiration;
          int skipped_periods = (int)(unsigned int)rom_unsigned_divide_u64(elapsed,period);
          bool skip_backlog = false;
          if (skipped_periods > 1) skip_backlog = (state->flags & 2U) != 0;
          unsigned long long next_expiration = (skip_backlog ? now_us : expiration) + period;
          /* The periodic rearm stores HIGH then LOW; one-shot clearing does the reverse. */
          state->alarm_high = (unsigned int)(next_expiration >> 32);
          state->alarm_low = (unsigned int)next_expiration;
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

/* Native entry: 0x4201186c. */
/* Original function-byte SHA-256:
 * 3bb060b2901c9a33b01f07e6735d97b4f7c9f5a019e19ed8032053c22e92c0b2. */
/* Require an initialized service, non-NULL args/output/callback and dispatch 0.
 * Return 0x103 for missing service, 0x102 for invalid arguments, 0x101 on memory
 * failure. Allocate 32 zeroed bytes with INTERNAL|8BIT capabilities (0x804).
 * After allocation reread dispatch, raw skip BYTE, callback and argument in
 * that order. Store callback/argument and flags = !!dispatch | (skip << 1),
 * narrowed to a BYTE; publish the output only on success and return 0.
 * No name read, profiling, arm operation or skip-byte range check is present.
 * ISR dispatch is rejected at admission; callers keep args stable throughout. */
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
  unsigned int dispatch = fields->dispatch;
  unsigned char skip = fields->skip_unhandled_events;
  EspTimerCallback callback = fields->callback;
  void *callback_argument = fields->argument;
  volatile EspTimer *state = timer;
  state->callback = callback;
  state->argument = callback_argument;
  state->flags = (unsigned char)((dispatch != 0) | ((unsigned int)skip << 1));
  *(EspTimer *volatile *)handle = timer;
  return 0;
}

/* Native entry: 0x420118dc. */
/* Original function-byte SHA-256:
 * c765bc2fdba03ba9b91fe2d191b87ecee766c5ccfef6f1b0f974324f3a75ccb1. */
/* Queue deletion of a live inactive timer; NULL returns 0x102, active returns
 * 0x103. Unlike start/stop, no service-initialized test occurs. Sample time
 * before locking task list 0; test alarm HIGH then LOW. Clear dispatch bit 0,
 * retain other flags, write the delete marker in the callback union, store
 * current alarm LOW/HIGH, clear period and insert with deadline update.
 * Return 0 after queueing. The task frees it later; relinquish the pointer.
 * No synchronous free, duplicate-delete guard or callback wait is supplied. */
int esp_timer_delete(EspTimer *timer)
{
  if (timer == 0) return 0x102;
  unsigned long long now_us = (unsigned long long)esp_timer_get_time();
  PortMuxWords *lock = &ESP_TIMER_LIST_LOCKS[0];
  (void)xPortInIsrContext();
  (void)xPortEnterCriticalTimeout(lock,-1);
  volatile EspTimer *state = timer;
  unsigned int alarm_high = state->alarm_high;
  unsigned int alarm_low = state->alarm_low;
  int status = 0x103;
  if ((alarm_low | alarm_high) == 0) {
    state->flags = state->flags & 0xfeU;
    unsigned int saved_flags = state->period_high_and_flags & 0xff000000U;
    state->event_id = ESP_TIMER_DELETE_EVENT;
    state->alarm_low = (unsigned int)now_us;
    state->alarm_high = (unsigned int)(now_us >> 32);
    state->period_low = 0;
    state->period_high_and_flags = saved_flags;
    timer_insert(timer,0);
    status = 0;
  }
  (void)xPortInIsrContext();
  vPortExitCritical(lock);
  return status;
}

/* Native entry: 0x42007a88. */
/* Original function-byte SHA-256:
 * d7379ef8c7fa31447fb92d7ad8f0c65773fc265f85fb8ef29590b7546517c012. */
/* Call the implementation's early initialization, discard its status, then
 * initialize system-time correction and return 0. No local failure shortcut. */
int esp_timer_early_init(void)
{
    (void)esp_timer_impl_early_init();
    esp_timer_impl_init_system_time();
    return 0;
}

/* Native entry: 0x4037ec64. */
/* Original function-byte SHA-256:
 * 6cf8c427a6119f11df55c931ce811ea8d4fa15a324bf9504aebdbad25dfca67d. */
/* Ignore argument. Read the service task handle, zero the local woken WORD,
 * then give notification index 0 through the ISR API. Request a context switch
 * only when woken equals 1, not every nonzero value. No NULL-handle guard,
 * register/list access or callback dispatch; work is deferred to the task. */
void timer_alarm_handler(void *argument)
{
    (void)argument;
    RtosTask *task = *ESP_TIMER_TASK_SLOT;
    int higher_priority_task_woken = 0;
    vTaskGenericNotifyGiveFromISR(task,0,&higher_priority_task_woken);
    if (higher_priority_task_woken == 1) _frxt_setup_switch();
}

/* Native entry: 0x42007b9c. */
/* Original function-byte SHA-256:
 * 88f22a6491e4e5a05b858c8393c6f6457f5a56fd46382265330d9ec367278abc. */
/* If the saved interrupt handle is non-NULL, optionally log and return 0x103.
 * Otherwise allocate source 59, flags 0xc02 (level 1, IRAM, initially disabled),
 * timer_alarm_isr and NULL argument, publishing to the handle slot. Return any
 * allocation error. On success, only an empty handler slot is assigned the
 * supplied callback (even NULL) and alarm 2 interrupt is then enabled.
 * Reread the saved handle, enable the CPU interrupt and return that status.
 * Enable failure retains the handle/callback/alarm state. Each diagnostic
 * tests the live log-level WORD for nonzero, then timestamps and ROM-prints.
 * No callback validation, cleanup, rollback, service lock or deadline here. */
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
    InterruptHandle *interrupt_handle = *ESP_TIMER_INTERRUPT_SLOT;
    status = esp_intr_enable(interrupt_handle);
    if (status != 0 && LOG_OUTPUT->default_level != 0) {
        unsigned int timestamp = esp_log_timestamp();
        ets_printf("E (%lu) %s: Can not enable ISR (0x%0x)\n",timestamp,"esp_timer_systimer",status);
    }
    return status;
}

/* Native entry: 0x42011954. */
/* Original function-byte SHA-256:
 * f35336bff9ac15c3d6d1d63c73a418267fa951e821ca5afb9e500c7824701256. */
/* Reject an existing task with optional ROM log and 0x103. Otherwise create
 * esp_timer_task named "esp_timer": 4096 stack bytes, priority 22, CPU 0, NULL
 * argument, output through the task slot. Any creation result other than 1
 * logs if enabled and returns 0x101 without partial-task cleanup.
 * Success installs timer_alarm_handler. On installation failure optionally log,
 * reread the task slot, delete/clear it if non-NULL, and return the ISR status.
 * Saved interrupt/callback setup remains. No service lock or timing guarantee. */
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

/* Native entry: 0x420119f8. */
/* Original function-byte SHA-256:
 * e1b8df5e08a4611e384829a64d8b25a534319d42aa3a89ef50d4c49610753544. */
/* OS-startup wrapper: return esp_timer_init's unchanged status. No retry,
 * extra initialization, task creation or error translation in this body. */
int esp_timer_init_os(void)
{
    return esp_timer_init();
}
