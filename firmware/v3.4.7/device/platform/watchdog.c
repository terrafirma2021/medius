/* Medius v3.4.7 device — interrupt and task hardware watchdogs. */
#include "../include/types.h"

/* Native entry: 0x40375f3c. */
/* Original function-byte SHA-256:
 * a1c29350fe84c5b61ca44163c5bf2d1a679b353408769c54f5db16f0719b0746. */
/*
 * Returns: No value; the CPU1 and CPU0-without-progress paths make no watchdog ROM calls.
 * Requirements/effects: Snapshots PRID bit 13 once. CPU1 stores the shared byte as 1 and returns.
 *   CPU0 reads the raw byte once and accepts any nonzero value. It then passes the static 8-byte
 *   HAL context to ROM: unlock, stage0/600 ticks/interrupt, stage1/1200 ticks/system reset, feed,
 *   lock; finally stores the shared byte as 0. Timeout values are hardware watchdog ticks; this
 *   function does not establish their clock rate. The final clear follows all five calls even if a
 *   delegated call changes the flag. The HAL instance and register pointer must already be
 *   initialized. No per-call mux or atomic handoff protocol is supplied; simultaneous CPU1
 *   publication can race with consumption.
 */
void esp_int_wdt_tick_hook(void)
{
    unsigned int core = (xtensa_read_prid() >> 13) & 1U;
    if (core != 0) {
        memw();
        INTERRUPT_WATCHDOG_CPU1_TICKED = 1;
        return;
    }

    memw();
    unsigned char cpu1_ticked = INTERRUPT_WATCHDOG_CPU1_TICKED;
    if (cpu1_ticked == 0)
        return;

    wdt_hal_write_protect_disable(INTERRUPT_WATCHDOG_CONTEXT);
    wdt_hal_config_stage(INTERRUPT_WATCHDOG_CONTEXT, WDT_STAGE0,
        600U, WDT_STAGE_ACTION_INT);
    wdt_hal_config_stage(INTERRUPT_WATCHDOG_CONTEXT, WDT_STAGE1,
        1200U, WDT_STAGE_ACTION_RESET_SYSTEM);
    wdt_hal_feed(INTERRUPT_WATCHDOG_CONTEXT);
    wdt_hal_write_protect_enable(INTERRUPT_WATCHDOG_CONTEXT);
    /* Consume the CPU1 tick only after completing the entire ROM sequence. */
    memw();
    INTERRUPT_WATCHDOG_CPU1_TICKED = 0;
}

/* Native entry: 0x42002f68. */
/* Original function-byte SHA-256:
 * 65dfda46fb92dbed4d8a7be6331ae8d0f923aca8b7a91bc0dd00fc83b1f0e513. */
/*
 * Returns: No value.
 * Requirements/effects: Acquires peripheral11 (TIMG1) and keeps its existing unsigned-byte
 *   reference count. Only count0 enables system clock bit15, pulses reset bit15 high then low
 *   using a fresh reset-word read, and clears timer-group1 watchdog FLASHBOOT_MOD_EN bit14. Other
 *   register bits are preserved by each native read/modify/write. Calls
 *   periph_rcc_acquire_exit(11, previous_count) even when count is nonzero. ROM initializes the
 *   static 8-byte HAL context as MWDT1, prescaler40000, level interrupt enabled; then unlocks,
 *   sets stage0 to10000 watchdog ticks/interrupt and stage1 to10000 ticks/system reset, enables
 *   the watchdog, and restores write protection. The two stage durations are successive stages,
 *   not one combined deadline. Tick-hook code later reconfigures their counts. A real-time
 *   duration requires the actual watchdog source clock; the function supplies no timing
 *   measurement, error return or rollback.
 */
void esp_int_wdt_init(void)
{
    unsigned char reference_count = periph_rcc_acquire_enter(11); /* TIMG1 */
    if (reference_count == 0) {
        memw();
        unsigned int clocks = WATCHDOG_SYSTEM_CLOCK_REGISTERS->peripheral_clock_enable0;
        memw();
        WATCHDOG_SYSTEM_CLOCK_REGISTERS->peripheral_clock_enable0 = clocks | 0x8000U;
        memw();
        unsigned int resets = WATCHDOG_SYSTEM_CLOCK_REGISTERS->peripheral_reset_enable0;
        memw();
        WATCHDOG_SYSTEM_CLOCK_REGISTERS->peripheral_reset_enable0 = resets | 0x8000U;
        memw();
        resets = WATCHDOG_SYSTEM_CLOCK_REGISTERS->peripheral_reset_enable0;
        memw();
        WATCHDOG_SYSTEM_CLOCK_REGISTERS->peripheral_reset_enable0 = resets & ~0x8000U;
        memw();
        unsigned int watchdog = WATCHDOG_TIMER_GROUP1_REGISTERS->watchdog_config0;
        memw();
        WATCHDOG_TIMER_GROUP1_REGISTERS->watchdog_config0 = watchdog & ~0x4000U;
    }
    periph_rcc_acquire_exit(11, reference_count);

    wdt_hal_init(INTERRUPT_WATCHDOG_CONTEXT, WDT_MWDT1, 40000U, true);
    wdt_hal_write_protect_disable(INTERRUPT_WATCHDOG_CONTEXT);
    wdt_hal_config_stage(INTERRUPT_WATCHDOG_CONTEXT, WDT_STAGE0,
        10000U, WDT_STAGE_ACTION_INT);
    wdt_hal_config_stage(INTERRUPT_WATCHDOG_CONTEXT, WDT_STAGE1,
        10000U, WDT_STAGE_ACTION_RESET_SYSTEM);
    wdt_hal_enable(INTERRUPT_WATCHDOG_CONTEXT);
    wdt_hal_write_protect_enable(INTERRUPT_WATCHDOG_CONTEXT);
}

/* Native entry: 0x4200300c. */
/* Original function-byte SHA-256:
 * f25e97dc060603b6277ac64646fa0f9680a1c1e290bb6de9f55378a72658e296. */
/*
 * Returns: No value.
 * Requirements/effects: Snapshots PRID bit 13 for
 *   esp_register_freertos_tick_hook_for_cpu(esp_int_wdt_tick_hook, core), and ignores its status.
 *   Disables CPU interrupt 24, reads PRID again, routes timer-group watchdog source 55 to
 *   interrupt 24 on that fresh core, then re-enables interrupt 24. It neither allocates a C
 *   interrupt handler nor configures watchdog timeout stages here. Hook capacity and physical
 *   watchdog behavior are supplied by separate dependencies.
 */
void esp_int_wdt_cpu_init(void)
{
    unsigned int registration_core = (xtensa_read_prid() >> 13) & 1U;
    /* The native code ignores hook-registration failure. */
    (void)esp_register_freertos_tick_hook_for_cpu(esp_int_wdt_tick_hook,
        registration_core);
    esp_intr_disable_source(24);
    unsigned int routing_core = (xtensa_read_prid() >> 13) & 1U;
    intr_matrix_set(routing_core, 55, 24);
    esp_intr_enable_source(24);
}

/* Native entry: 0x42010964. */
/* Original function-byte SHA-256:
 * 71e952ece05c9c1bef1ca0c2e63d994d2972688e24f3d1d76e63b5bcd6816bd5. */
/*
 * is_task: Full native WORD: any nonzero value selects a task handle; zero selects a user name.
 *   SDK callers supply bool 0/1; no BYTE narrowing is inserted here.
 * entry_data: Task handle or user-name pointer, stored unchanged in its corresponding node field.
 *   Not validated or dereferenced here.
 * entry_out: Writable entry-pointer output required on success; written only after unlocking.
 *   Untouched by this caller on errors.
 * Returns: 0 on success; 0x101 when calloc fails, 0x103 when state is NULL after lock entry, or
 *   0x102 for a duplicate task handle or user-entry pointer.
 * Requirements/effects: Allocates and zeroes one 16-byte subscription node before acquiring the
 *   watchdog mux. Stores task or user-name data, then enters the critical section with
 *   timeout_cycles=-1; the lock API result is ignored. Reads state after entry. For task mode,
 *   scans the entire list for matching task handles; for user mode, compares node addresses with
 *   the newly allocated node, not user-name strings. Excludes matching nodes from an 8-bit OR
 *   accumulation of has_reset XOR 1. On duplicate/state errors, conditionally logs through ROM
 *   when the full diagnostic-control word is nonzero, unlocks, then frees the new node. On
 *   success, inserts at the head. Any nonzero raw waiting byte causes timer restart, whose status
 *   is ignored; global state is reloaded before clearing its waiting byte. Uses the native byte
 *   accumulator XOR 1 as a nonzero feed gate, retaining behavior for all raw flag representations.
 *   If feeding, reloads the current global context, ignores the feed status, then reloads the
 *   current list and clears each reset byte,loading each next link after its store. Unlocks before
 *   publishing the new pointer. No output-pointer check, cycle detection, backend rollback, or
 *   outer lifecycle protection is supplied; callers must preserve live acyclic descriptors and
 *   state ownership.
 */
int task_wdt_add_entry(unsigned int is_task, void *entry_data,
                          TaskWatchdogEntry **entry_out)
{
    TaskWatchdogEntry *created = calloc(1, sizeof(*created));
    if (created == NULL) {
        return 0x101;
    }
    if (is_task) {
        created->task = (RtosTask *)entry_data;
    } else {
        created->user_name = (const char *)entry_data;
    }

    (void)xPortEnterCriticalTimeout(&TASK_WATCHDOG_LOCK, -1);
    TaskWatchdogState *state = TASK_WATCHDOG_STATE;
    int result;
    if (state == NULL) {
        if (TASK_WATCHDOG_DIAGNOSTICS != 0) {
            unsigned int timestamp = esp_log_timestamp();
            ets_printf("E (%lu) %s: %s(%d): task watchdog was never initialized\n",
                       timestamp, "task_wdt", "add_entry", 0xbb);
        }
        result = 0x103;
    } else {
        TaskWatchdogEntry *head = state->entries;
        bool duplicate = false;
        unsigned char other_pending = 0;
        for (TaskWatchdogEntry *entry = head; entry != NULL; entry = entry->next) {
            bool matches = is_task ? entry->task == created->task : entry == created;
            if (matches) {
                duplicate = true;
            } else {
                other_pending = (unsigned char)(other_pending | (entry->has_reset ^ 1U));
            }
        }

        if (duplicate) {
            if (TASK_WATCHDOG_DIAGNOSTICS != 0) {
                unsigned int timestamp = esp_log_timestamp();
                if (is_task) {
                    ets_printf("E (%lu) %s: %s(%d): task is already subscribed\n",
                               timestamp, "task_wdt", "add_entry", 0xc0);
                } else {
                    ets_printf("E (%lu) %s: %s(%d): user is already subscribed\n",
                               timestamp, "task_wdt", "add_entry", 0xc3);
                }
            }
            result = 0x102;
        } else {
            created->next = head;
            unsigned char was_waiting = state->waiting_for_task;
            state->entries = created;
            if (was_waiting != 0) {
                (void)esp_task_wdt_impl_timer_restart(state->timer_context);
                TASK_WATCHDOG_STATE->waiting_for_task = 0;
            }

            /* Preserve the native byte XOR, including noncanonical flags. */
            if ((unsigned char)(other_pending ^ 1U) != 0) {
                (void)esp_task_wdt_impl_timer_feed(TASK_WATCHDOG_STATE->timer_context);
                for (TaskWatchdogEntry *entry = TASK_WATCHDOG_STATE->entries;
                     entry != NULL; entry = entry->next) {
                    entry->has_reset = 0;
                }
            }
            vPortExitCritical(&TASK_WATCHDOG_LOCK);
            *entry_out = created;
            return 0;
        }
    }

    vPortExitCritical(&TASK_WATCHDOG_LOCK);
    free(created);
    return result;
}

/* Native entry: 0x42010af8. */
/* Original function-byte SHA-256:
 * 467dd6ee56c43864f895216779f9a1f8449c8067e589e967be56119e23a7df0a. */
/*
 * current_core: Native unsigned BYTE: any nonzero low byte selects current-core diagnostic
 *   wording. SDK callers pass bool 0/1; upper input-register bits are discarded.
 * Returns: No value. Snapshot failure asserts; success transfers the saved frame to exception
 *   handling. Native RET is retained if that handler returns.
 * Requirements/effects: Initializes all three pointers in a 12-byte task snapshot to NULL. The
 *   first full diagnostic-control word gates the Aborting message. Sets reset hint 6
 *   (ESP_RST_TASK_WDT), queries the current task, then requests its snapshot. Tests the full
 *   32-bit snapshot result against 1; every other result calls the nonreturning four-zero silent
 *   assertion before either panic flag is set. Captures snapshot.top_of_stack, then stores byte 1
 *   to both g_panic_abort and g_twdt_isr locations. These are independent constant stores, with no flag readback between them. Rereads the diagnostic-control word
 *   for the CPU message. A fresh PRID bit 13 is sampled after that message timestamp only when
 *   diagnostics are enabled. Uses current-core wording for any nonzero low argument byte, and
 *   ordinary CPU wording for zero,matching the native 8-bit parameter transfer. Finally passes the
 *   captured frame to xt_unhandled_exception; later diagnostic side effects do not make it reread
 *   the snapshot. The native RET epilogue remains if that delegate returns. No frame validation,
 *   stack unwinding, global flag rollback, scheduler stop, or lock is implemented here; the caller
 *   must provide a safe panic/snapshot context and the debug and exception implementations supply
 *   their own semantics. No watchdog-state object is read.
 */
void task_wdt_timeout_abort(unsigned char current_core)
{
    TaskSnapshot snapshot;
    snapshot.task_control_block = NULL;
    snapshot.top_of_stack = NULL;
    snapshot.end_of_stack = NULL;
    if (TASK_WATCHDOG_DIAGNOSTICS != 0) {
        unsigned int timestamp = esp_log_timestamp();
        ets_printf("E (%lu) %s: Aborting.\n", timestamp, "task_wdt");
    }

    esp_reset_reason_set_hint(6); /* ESP_RST_TASK_WDT */
    RtosTask *task = xTaskGetCurrentTaskHandle();
    if (vTaskGetSnapshot(task, &snapshot) != 1) {
        __assert_func(NULL, 0, NULL, NULL);
    }

    /* Preserve the native frame-read / two flag-stores / diagnostic-read order. */
    void *frame = *(unsigned char *volatile *)&snapshot.top_of_stack;
    *(volatile unsigned char *)&PANIC_ABORT_IN_PROGRESS = 1;
    *(volatile unsigned char *)&TASK_WATCHDOG_ISR_ACTIVE = 1;

    if (*(volatile unsigned int *)&TASK_WATCHDOG_DIAGNOSTICS != 0) {
        unsigned int timestamp = esp_log_timestamp();
        unsigned int core = (xtensa_read_prid() >> 13) & 1U;
        if (current_core) {
            ets_printf("E (%lu) %s: Print CPU %d (current core) backtrace\n",
                       timestamp, "task_wdt", core);
        } else {
            ets_printf("E (%lu) %s: Print CPU %d backtrace\n",
                       timestamp, "task_wdt", core);
        }
    }
    xt_unhandled_exception(frame);
}

/* Native entry: 0x42010ba4. */
/* Original function-byte SHA-256:
 * 6ad548a1f2b8bf0f3d84cd6f4e20ea1c9e85a78f821c2edc509c1d3b17738c73. */
/*
 * task: Task handle to subscribe. NULL resolves the current task; its returned handle is forwarded
 *   without another local NULL test.
 * Returns: 0x103 when global watchdog state is NULL; otherwise the unchanged 32-bit add-entry
 *   result.
 * Requirements/effects: Checks global initialization before querying the current task. Logs the
 *   exact public error diagnostic with source line 0x29d if uninitialized. Passes true, the
 *   explicit or resolved task handle, and the address of a local entry pointer to
 *   task_wdt_add_entry. The local output is one 4-byte pointer and is never read by this wrapper. No extra lock, allocation, rollback,
 *   duplicate check, or post-query initialization check occurs here; the helper supplies
 *   registration and state validation.
 */
int esp_task_wdt_add(RtosTask *task)
{
    if (TASK_WATCHDOG_STATE == NULL) {
        unsigned int timestamp = esp_log_timestamp();
        esp_log_write(1, "task_wdt", "E (%lu) %s: %s(%d): TWDT was never initialized\n",
                      timestamp, "task_wdt", "esp_task_wdt_add", 0x29d);
        return 0x103;
    }

    if (task == NULL) {
        task = xTaskGetCurrentTaskHandle();
    }
    TaskWatchdogEntry *created_entry;
    return task_wdt_add_entry(true, task, &created_entry);
}

/* Native entry: 0x42010bf0. */
/* Original function-byte SHA-256:
 * d753fa5c53276c917f657f53c857b551aa9c688219991dbb1067d2d67a8553bd. */
/*
 * core_mask: Unsigned 32-bit core mask. Zero does nothing. Valid live idle-task handles must exist
 *   for all selected cores.
 * Returns: No value. A NULL idle handle asserts; any nonzero 32-bit watchdog-add or hook-
 *   registration status aborts.
 * Requirements/effects: Scans selected mask bits in ascending order. For each bit, obtains that
 *   core's idle-task handle, asserts if NULL, passes that exact handle to esp_task_wdt_add, then
 *   registers the bool(void) task-watchdog idle hook on the same core. Passes the selected task handle explicitly. Each API status is tested as a full 32-bit value; hook
 *   registration is skipped after an add error, and later cores are skipped after either error.
 *   Earlier additions and hook registrations, and any side effects of a failing delegated API,
 *   remain; there is no rollback or outer lock. This helper does not restrict the mask to two
 *   cores; its initializer normally validates the mask to 0..3. Direct callers must select
 *   supported cores and serialize any required lifecycle changes. NULL-handle assertion receives
 *   four zero arguments.
 */
void subscribe_idle(unsigned int core_mask)
{
    unsigned int core = 0;
    while (core_mask != 0) {
        if ((core_mask & 1U) != 0) {
            RtosTask *idle_task = xTaskGetIdleTaskHandleForCore((int)core);
            if (idle_task == NULL) {
                __assert_func(NULL, 0, NULL, NULL);
            }

            /* The raw decompile omitted this task-handle argument. */
            if (esp_task_wdt_add(idle_task) != 0) {
                abort();
            }
            if (esp_register_freertos_idle_hook_for_cpu(task_wdt_idle_hook_cb,
                                                       core) != 0) {
                abort();
            }
        }
        core_mask >>= 1;
        ++core;
    }
}

/* Native entry: 0x42010c48. */
/* Original function-byte SHA-256:
 * c8fd27132dd820fd4e141849bcee14082083143f756214a8e7f08d615eab5e1a. */
/*
 * configuration: Readable 12-byte watchdog configuration; initial idle_core_mask must be 0..3. The
 *   backend receives the same pointer.
 * Returns: 0 on success; 0x102 invalid arguments, 0x103 already initialized, 0x101 calloc failure,
 *   or the unchanged 32-bit backend allocation error. Restart errors are ignored.
 * Requirements/effects: Checks NULL configuration and the full unsigned idle-core mask before
 *   reading global state; masks >=4 fail. Already initialized state fails before allocation.
 *   Allocates one zeroed 16-byte state, copies the raw panic byte at configuration offset 8 to
 *   state offset 12, and calls the timer allocator with configuration, the native task_wdt_isr
 *   callback and an explicit context output pointer at state offset 0. Tests the full 32-bit
 *   allocator result. Only on success, rereads the configuration mask, publishes the new global
 *   state and saves that mask at state offset 8; a backend mutation is not revalidated here. A
 *   nonzero mask is passed to subscribe_idle, passing that mask explicitly, and global
 *   state is then reloaded. Mask 0 uses the allocated state without that reload. An empty
 *   subscription list sets waiting_for_task to 1; otherwise samples timer_context before clearing
 *   waiting_for_task and calls timer restart, ignoring its return status. Invalid arguments,
 *   existing state and calloc failure log exact native error diagnostics; their seventh variadic
 *   argument is the pinned source line. Postallocation failures call free, including free(NULL)
 *   after calloc failure. No backend rollback, global-state clear, outer lock, or protection
 *   against simultaneous initialization is provided. Callers must serialize initialization and
 *   provide live readable configuration and valid backend-owned state; timeout validation and
 *   timer behavior belong to the backend.
 */
int esp_task_wdt_init(const TaskWatchdogConfig *configuration)
{
    if (configuration == NULL || configuration->idle_core_mask >= 4U) {
        unsigned int timestamp = esp_log_timestamp();
        esp_log_write(1, "task_wdt", "E (%lu) %s: %s(%d): Invalid arguments\n",
                      timestamp, "task_wdt", "esp_task_wdt_init", 0x202);
        return 0x102;
    }

    if (TASK_WATCHDOG_STATE != NULL) {
        unsigned int timestamp = esp_log_timestamp();
        esp_log_write(1, "task_wdt", "E (%lu) %s: %s(%d): TWDT already initialized\n",
                      timestamp, "task_wdt", "esp_task_wdt_init", 0x203);
        return 0x103;
    }

    TaskWatchdogState *state = calloc(1, sizeof(*state));
    int result;
    if (state == NULL) {
        unsigned int timestamp = esp_log_timestamp();
        esp_log_write(1, "task_wdt", "E (%lu) %s: %s(%d): insufficient memory\n",
                      timestamp, "task_wdt", "esp_task_wdt_init", 0x209);
        result = 0x101;
    } else {
        /* Read the bool object's representation as the native l8ui does. */
        state->panic = *(const unsigned char *)&configuration->trigger_panic;
        result = esp_task_wdt_impl_timer_allocate(configuration, task_wdt_isr,
                                                  &state->timer_context);
        if (result == 0) {
            unsigned int core_mask = configuration->idle_core_mask;
            TASK_WATCHDOG_STATE = state;
            state->idle_core_mask = core_mask;
            if (core_mask != 0) {
                subscribe_idle(core_mask);
                state = TASK_WATCHDOG_STATE;
            }

            if (state->entries == NULL) {
                state->waiting_for_task = 1;
            } else {
                TaskWatchdogTimerContext context = state->timer_context;
                state->waiting_for_task = 0;
                (void)esp_task_wdt_impl_timer_restart(context);
            }
            return 0;
        }
    }

    free(state);
    return result;
}

/* Native entry: 0x42010d30. */
/* Original function-byte SHA-256:
 * c8864f32634e1148569ac22d29f8f801f34e48771102d7db65be9bc06fcef54b. */
/*
 * Returns: 0x103 if uninitialized; 0x105 if the current task is not in the locked list; otherwise
 *   0 even if the backend feed reports an error.
 * Requirements/effects: Checks global state before querying the current task, then enters the
 *   watchdog mux with timeout_cycles=-1 and ignores the lock API status. Reloads state after entry
 *   without a second NULL guard; callers must keep it alive. Scans the full list, retaining the
 *   last matching task node and excluding every matching node from the 8-bit OR accumulation of
 *   other has_reset bytes XOR 1. Marks the selected target byte 1. Feeds only when that
 *   accumulated byte is zero, ignoring the backend result; then reloads global state and walks its
 *   current list to clear all reset bytes. Noncanonical flag bytes are preserved in the scan
 *   rather than normalized to C bool. A missing task optionally emits the exact ROM diagnostic
 *   under the lock, controlled by a full nonzero diagnostic word. The uninitialized public error
 *   log occurs outside the lock. All returning locked paths exit exactly once. Does not allocate,
 *   subscribe tasks, reset the waiting flag, or validate list cycles; descriptors must remain live
 *   and acyclic.
 */
int esp_task_wdt_reset(void)
{
    if (TASK_WATCHDOG_STATE == NULL) {
        unsigned int timestamp = esp_log_timestamp();
        esp_log_write(1, "task_wdt", "E (%lu) %s: %s(%d): TWDT was never initialized\n",
                      timestamp, "task_wdt", "esp_task_wdt_reset", 0x2b8);
        return 0x103;
    }

    RtosTask *task = xTaskGetCurrentTaskHandle();
    (void)xPortEnterCriticalTimeout(&TASK_WATCHDOG_LOCK, -1);
    TaskWatchdogState *state = TASK_WATCHDOG_STATE;
    TaskWatchdogEntry *target = NULL;
    unsigned char other_pending = 0;
    for (TaskWatchdogEntry *entry = state->entries; entry != NULL;
         entry = entry->next) {
        if (entry->task == task) {
            target = entry;
        } else {
            other_pending = (unsigned char)(other_pending | (entry->has_reset ^ 1U));
        }
    }

    int result;
    if (target == NULL) {
        if (TASK_WATCHDOG_DIAGNOSTICS != 0) {
            unsigned int timestamp = esp_log_timestamp();
            ets_printf("E (%lu) %s: %s(%d): task not found\n",
                       timestamp, "task_wdt", "esp_task_wdt_reset", 0x2c1);
        }
        result = 0x105;
    } else {
        target->has_reset = 1;
        if (other_pending == 0) {
            (void)esp_task_wdt_impl_timer_feed(state->timer_context);
            /* Feed can change the global state: walk its current list. */
            for (TaskWatchdogEntry *entry = TASK_WATCHDOG_STATE->entries;
                 entry != NULL; entry = entry->next) {
                entry->has_reset = 0;
            }
        }
        result = 0;
    }
    vPortExitCritical(&TASK_WATCHDOG_LOCK);
    return result;
}

/* Native entry: 0x42010dfc. */
/* Original function-byte SHA-256:
 * 6ccebb1a78e52d17c61b5b24c73a7c2bdb0ec63ed8bf9b45f734b26db28378b5. */
/*
 * Returns: Boolean true if esp_task_wdt_reset returns, regardless of its 32-bit status.
 * Requirements/effects: Idle-hook callback with the verified bool(void) ABI. Calls
 *   esp_task_wdt_reset exactly once with no arguments and discards its status; then returns true.
 *   Does not check watchdog initialization or subscription, retry failures, log an error itself,
 *   or read the core ID. Reset, logging, locking and any actual feed are supplied by
 *   esp_task_wdt_reset. A true return does not establish that a feed succeeded. If reset does not
 *   return, this hook does not reach its return.
 */
bool task_wdt_idle_hook_cb(void)
{
    (void)esp_task_wdt_reset();
    return true;
}

/* Native entry: 0x42010e08. */
/* Original function-byte SHA-256:
 * 41df8f12e275dc51ac93f6d5d16a8e21c199fe6d464daf90c3c17e36912b72a9. */
/*
 * Reports subscribers whose reset byte is zero.
 *
 * handler: optional text-fragment callback. NULL selects ROM diagnostics.
 * opaque: passed unchanged as the callback's first argument.
 * failed_core_mask: optional in/out mask; failing affinities are ORed into
 *   its existing value. This function does not initialize it.
 *
 * Returns -1 if the initial subscriber list is empty; otherwise returns 0,
 * even when every subscriber has reset or diagnostics are disabled.
 *
 * A callback receives the caption once, then "\n - ", the saved name and
 * the CPU suffix as three separate calls per failing entry. A task name
 * comes from pcTaskGetName; user entries use user_name directly. Task core
 * affinities 0 and 1 select one bit; NULL tasks and all other affinities
 * select both cores. Passes the selected task handle explicitly.
 *
 * Reloads the list head after an emitted caption and the task handle after
 * name lookup. Loads each next link after output callbacks. Acquires no
 * lock and does not check watchdog initialization. The caller must provide
 * live state, names and acyclic nodes, and control their lifetime while
 * callbacks run. The callback receives text, not a printf format string.
 */
int esp_task_wdt_print_triggered_tasks(TaskWatchdogMessageHandler handler,
                                      void *opaque, int *failed_core_mask)
{
    TaskWatchdogEntry *entry = TASK_WATCHDOG_STATE->entries;
    if (entry == NULL) {
        return -1;
    }

    const char *caption =
        "Task watchdog got triggered. The following tasks/users did not reset the watchdog in time:";
    if (handler != NULL) {
        handler(opaque, caption);
        entry = TASK_WATCHDOG_STATE->entries;
    } else if (TASK_WATCHDOG_DIAGNOSTICS != 0) {
        unsigned int timestamp = esp_log_timestamp();
        ets_printf("E (%lu) %s: %s\n", timestamp, "task_wdt", caption);
        entry = TASK_WATCHDOG_STATE->entries;
    }

    for (; entry != NULL; entry = entry->next) {
        if (entry->has_reset != 0) {
            continue;
        }

        const char *name;
        const char *cpu = " (CPU 0/1)";
        unsigned int affinity = 3U;
        RtosTask *task = entry->task;
        if (task == NULL) {
            name = entry->user_name;
        } else {
            name = pcTaskGetName(task);
            task = entry->task;
            if (task != NULL) {
                unsigned int core = (unsigned int)xTaskGetCoreID(task);
                if (core < 2U) {
                    affinity = 1U << core;
                    cpu = core == 0 ? " (CPU 0)" : " (CPU 1)";
                }
            }
        }

        if (failed_core_mask != NULL) {
            *failed_core_mask |= (int)affinity;
        }
        if (handler != NULL) {
            handler(opaque, "\n - ");
            handler(opaque, name);
            handler(opaque, cpu);
        } else if (TASK_WATCHDOG_DIAGNOSTICS != 0) {
            unsigned int timestamp = esp_log_timestamp();
            ets_printf("E (%lu) %s:  - %s%s\n",
                       timestamp, "task_wdt", name, cpu);
        }
    }
    return 0;
}

/* Native entry: 0x42011078. */
/* Original function-byte SHA-256:
 * f1b6f4d6140cc61d21794405ceb38d76514d0d5e1f4c3fcb4b32c875519e8b39. */
/*
 * configuration: Readable 12-byte watchdog configuration. This backend reads timeout_ms separately
 *   for each hardware stage.
 * callback: Interrupt handler passed unchanged to esp_intr_alloc; NULL is forwarded without local
 *   rejection.
 * context_out: Writable opaque-context output. Remains unpublished by this caller until all
 *   backend setup operations return.
 * Returns: 0x103 for NULL configuration/output; otherwise 0 after setup, even if esp_intr_alloc
 *   reports an error.
 * Requirements/effects: Rejects NULL configuration or context output with 0x103 before any API
 *   call or memory access through those pointers. Does not reject a NULL callback. Uses one static
 *   12-byte TIMG0/MWDT0 hardware context shared by all invocations; no heap allocation or timer
 *   start occurs in this function. Requests interrupt source 0x34, flags 0,the supplied
 *   void(void*)callback,NULL callback argument,and the static interrupt-handle output at context
 *   offset 8. Ignores the full interrupt-allocation status and continues,including on failure.
 *   Acquires peripheral 10 using the existing 8-bit reference-count ABI. Only for reference count
 *   0,performs eight MEMW-ordered accesses: clock-enable register OR 0x2000,reset register OR
 *   0x2000,then a fresh reset read AND ~0x2000,and watchdog config AND ~0x4000 to disable flash-
 *   boot protection restored by reset. Unrelated bits come from each individual read snapshot.
 *   Always exits the RCC acquire operation with the same reference byte before HAL setup. Calls
 *   ROM wdt_hal_init with MWDT0, prescaler 40000,and level interrupt enabled; passes the fourth level-interrupt argument explicitly. Disables write protection,reads timeout_ms and programs stage 0
 *   with uint32(timeout_ms*2) and interrupt action 1,then separately rereads timeout_ms and
 *   programs stage 1 with uint32(timeout_ms*4) and system-reset action 3. Arithmetic wraps modulo
 *   2^32 and no timeout bounds are checked here. Enables write protection and only then publishes
 *   the static context through context_out. Provides no repeat-initialization guard,interrupt
 *   cleanup,or rollback if a dependency does not return. Callers must own the shared context
 *   lifecycle and provide live configuration/output pointers plus the synchronization required by
 *   the backend. This is a hardware watchdog with two stages, not a FreeRTOS software timer.
 */
int esp_task_wdt_impl_timer_allocate(const TaskWatchdogConfig *configuration,
                                   TaskWatchdogIsr callback,
                                   TaskWatchdogTimerContext *context_out)
{
    if (configuration == NULL || context_out == NULL) {
        return 0x103;
    }

    TaskWatchdogHardwareContext *hardware = TASK_WATCHDOG_HARDWARE_CONTEXT;
    (void)esp_intr_alloc(0x34, 0, callback, NULL, &hardware->interrupt_handle);

    unsigned char reference_count = periph_rcc_acquire_enter(10);
    if (reference_count == 0) {
        /* Enable and reset TIMG0 only for its first peripheral-clock user. */
        memw();
        unsigned int clock_enable = WATCHDOG_SYSTEM_CLOCK_ENABLE;
        memw();
        WATCHDOG_SYSTEM_CLOCK_ENABLE = clock_enable | 0x2000U;

        memw();
        unsigned int reset = WATCHDOG_SYSTEM_RESET;
        memw();
        WATCHDOG_SYSTEM_RESET = reset | 0x2000U;
        memw();
        reset = WATCHDOG_SYSTEM_RESET;
        memw();
        WATCHDOG_SYSTEM_RESET = reset & ~0x2000U;

        /* The module reset re-enables flash-boot protection; clear it again. */
        memw();
        unsigned int watchdog_config = TIMER_GROUP0_WATCHDOG_CONFIGURATION0;
        memw();
        TIMER_GROUP0_WATCHDOG_CONFIGURATION0 = watchdog_config & ~0x4000U;
    }
    periph_rcc_acquire_exit(10, reference_count);

    WatchdogHalContext *hal = &hardware->hal;
    wdt_hal_init(hal, WDT_MWDT0, 40000U, true);
    wdt_hal_write_protect_disable(hal);

    /* Native 32-bit products wrap. Each stage rereads timeout_ms separately. */
    unsigned int first_stage_ticks = configuration->timeout_ms * 2U;
    wdt_hal_config_stage(hal, WDT_STAGE0, first_stage_ticks,
                         WDT_STAGE_ACTION_INT);
    unsigned int second_stage_ticks = configuration->timeout_ms * 4U;
    wdt_hal_config_stage(hal, WDT_STAGE1, second_stage_ticks,
                         WDT_STAGE_ACTION_RESET_SYSTEM);
    wdt_hal_write_protect_enable(hal);

    *context_out = hardware;
    return 0;
}

/* Native entry: 0x42011140. */
/* Original function-byte SHA-256:
 * 480813410e95c788f85a213bc222abc9531eef7e02b9290469ba571ab8ab5ebe. */
/*
 * context: Opaque timer-group backend context. Its first member is the HAL; a non-NULL pointer
 *   must remain valid for all three ROM calls.
 * Returns: 0x103 for NULL; otherwise 0 after all three HAL calls return.
 * Requirements/effects: Checks context for NULL before any ROM operation. Passes the unchanged
 *   HAL-at-offset-zero pointer to wdt_hal_write_protect_disable, wdt_hal_feed and
 *   wdt_hal_write_protect_enable, in order. Does not enable the timer, acknowledge its interrupt,
 *   reconfigure a stage, validate a task subscription, or add a lock. HAL functions return void;
 *   this wrapper does not infer success from a hardware status read. Required synchronization and
 *   physical register effects belong to the caller and ROM HAL; no cleanup runs if a dependency
 *   does not return.
 */
int esp_task_wdt_impl_timer_feed(TaskWatchdogTimerContext context)
{
    if (context == NULL) {
        return 0x103;
    }

    WatchdogHalContext *hal = (WatchdogHalContext *)context;
    wdt_hal_write_protect_disable(hal);
    wdt_hal_feed(hal);
    wdt_hal_write_protect_enable(hal);
    return 0;
}

/* Native entry: 0x42011168. */
/* Original function-byte SHA-256:
 * b5010bbdefa95da1fb869572efe35c7370094e246d720fd3d6061543c77c109a. */
/*
 * context: Opaque timer-group backend context; NULL is a no-op. A non-NULL pointer must identify
 *   live HAL storage at offset zero.
 * Returns: No value.
 * Requirements/effects: For a non-NULL context, calls ROM wdt_hal_write_protect_disable,
 *   wdt_hal_handle_intr and wdt_hal_write_protect_enable with the unchanged context pointer. The
 *   middle ROM operation feeds the watchdog and acknowledges its interrupt, as identified by the
 *   pinned timer-group implementation and ROM map. This wrapper supplies no stage reconfiguration,
 *   task inspection, application callback, extra lock or error status. Earlier ROM effects remain
 *   if a later operation does not return. Actual hardware access and required synchronization are
 *   delegated to ROM and the caller.
 */
void esp_task_wdt_impl_timeout_triggered(TaskWatchdogTimerContext context)
{
    if (context != NULL) {
        WatchdogHalContext *hal = (WatchdogHalContext *)context;
        wdt_hal_write_protect_disable(hal);
        /* ROM feeds the watchdog and acknowledges its interrupt. */
        wdt_hal_handle_intr(hal);
        wdt_hal_write_protect_enable(hal);
    }
}

/* Native entry: 0x42011188. */
/* Original function-byte SHA-256:
 * eaee52d6d900b5f8c06e17cfbc96df181b516aa861266140f893382512320bbd. */
/*
 * context: Opaque task-watchdog timer-group backend context. Its first member is the 8-byte
 *   WatchdogHalContext; a non-NULL context must remain valid across all four ROM calls.
 * Returns: 0x103 for NULL; otherwise 0 after all four HAL calls return.
 * Requirements/effects: Rejects NULL before any HAL call. Passes the unchanged context pointer, at
 *   HAL offset 0 in the 12-byte hardware context, to ROM wdt_hal_write_protect_disable,
 *   wdt_hal_enable, wdt_hal_feed and wdt_hal_write_protect_enable, in that order. Does not
 *   dereference the context or inspect a HAL return value in this wrapper. Adds no lock, timeout,
 *   interrupt acknowledge, stage reconfiguration, or cleanup if a delegated operation does not
 *   return. Register access, actual counter behavior and required synchronization belong to the
 *   ROM HAL and caller.
 */
int esp_task_wdt_impl_timer_restart(TaskWatchdogTimerContext context)
{
    if (context == NULL) {
        return 0x103;
    }

    /* The HAL is the first member of this backend's timer-group context. */
    WatchdogHalContext *hal = (WatchdogHalContext *)context;
    wdt_hal_write_protect_disable(hal);
    wdt_hal_enable(hal);
    wdt_hal_feed(hal);
    wdt_hal_write_protect_enable(hal);
    return 0;
}

/* Native entry: 0x4200c8e8. */
/* Original function-byte SHA-256:
 * 4aca22da8e76c6502a56fb0019d7ae9dff1d1c317c2e6a25f8143b25ca8f11c2. */
/* Add NULL/current task to the shared SDK task watchdog. On nonzero error,
 * snapshot log time BEFORE asking for current task name, then log that name and
 * raw error. Ignore success/failure afterward; no abort, retry, return result,
 * separate timer or watchdog configuration is supplied by this wrapper. */
void watch_current_task(void)
{
    int result = esp_task_wdt_add(NULL);
    if (result != 0) {
        unsigned int timestamp = esp_log_timestamp();
        char *name = pcTaskGetName(NULL);
        esp_log_write(1,WORKER_WATCHDOG_LOG_TAG,"E (%lu) %s: %s unwatched (err 0x%x)\n",
            timestamp,WORKER_WATCHDOG_LOG_TAG,name,result);
    }
}

/* Native entry: 0x4200c91c. */
/* Original function-byte SHA-256:
 * 26e4fdc20d2e7d1407d77efcaa90354ec661d90ae76cfe5a4dd74c6f1013b6e1. */
/* Feed the SDK current-task subscription once, ignoring its result. No
 * subscription creation, independent timer, retry or local state is supplied. */
void feed_current_task_watchdog(void)
{
    esp_task_wdt_reset();
}

/* Native entry: 0x4202854c. */
/* Original function-byte SHA-256:
 * 9ebb62f52ea91c512c7e15b8d0fc960a2bf5013aa4008abeec7520e7871df38f. */
/* Timer callback, argument unused. Snapshot borrowed txwd task handle;
 * if present, set notification index0 BIT0 (value1, action1), ignoring result.
 * Repeated calls coalesce that bit. No watchdog feed, worker work, timer creation
 * or rearm here. This is a maintenance wakeup on the shared software timer
 * dispatcher; its scheduling/latency is not guaranteed by this function. */
void transmit_watchdog_timer_callback(void *argument)
{
    (void)argument;
    RtosTask *task = MOTION_TXWD_TASK;
    if (task != NULL)
        xTaskGenericNotify(task,0,1,1,NULL);
}

/* Native entry: 0x42010f10. */
/* Original function-byte SHA-256:
 * 70251d2485b9664f8bbb1139e3b2b73ec5520f9001b407bea543dbd93db144ec. */
/* Handle task-watchdog timeout under its port lock. Ignore the ISR argument
 * and lock-acquisition result. Trigger/feed the backend using the first state
 * snapshot, then reload global state and cache its panic BYTE. Ask the report
 * API for the timed-out CPU mask; an error only unlocks/returns. On success,
 * optionally print current task names with separate live diagnostic-gate
 * samples. This permits CPU1 output even if CPU0 output was skipped.
 *
 * Unlock BEFORE calling the linked panic-capture hook, then require a nonzero
 * CPU mask. Read current CPU from PRID bit13. Nonpanic mode prints local depth100
 * backtrace and/or requests the other CPU's trace according to mask bits.
 * Panic mode: both bits set prints local trace, requests remote abort and
 * spins forever; remote-only requests remote abort and spins; otherwise invoke
 * local timeout_abort(true). Diagnostic gate controls text only, not actions.
 * No recovery wait, cross-core acknowledgement, stateNULL check or lock retry.
 * Backend/panic routines retain their own contracts; no runtime timing claim.
 */
void task_wdt_isr(void *argument)
{
    (void)argument;
    xPortEnterCriticalTimeout(&TASK_WATCHDOG_LOCK,-1);
    TaskWatchdogState *state = *(TaskWatchdogState *volatile *)&TASK_WATCHDOG_STATE;
    TaskWatchdogTimerContext timer = ((volatile TaskWatchdogState *)state)->timer_context;
    esp_task_wdt_impl_timeout_triggered(timer);
    state = *(TaskWatchdogState *volatile *)&TASK_WATCHDOG_STATE;
    unsigned int panic = ((volatile TaskWatchdogState *)state)->panic;
    int timed_out_cores = 0;
    int result = esp_task_wdt_print_triggered_tasks(NULL,NULL,&timed_out_cores);
    if (result != 0) {
        vPortExitCritical(&TASK_WATCHDOG_LOCK);
        return;
    }
    int core = 0;
    if (*(volatile unsigned int *)&TASK_WATCHDOG_DIAGNOSTICS == 0)
        goto consider_cpu1;
    unsigned int timestamp = esp_log_timestamp();
    ets_printf("E (%lu) %s: %s\n",timestamp,"task_wdt","Tasks currently running:");
    if (*(volatile unsigned int *)&TASK_WATCHDOG_DIAGNOSTICS == 0)
        goto consider_cpu1;
    do {
        timestamp = esp_log_timestamp();
        RtosTask *task = xTaskGetCurrentTaskHandleForCore(core);
        char *name = pcTaskGetName(task);
        ets_printf("E (%lu) %s: CPU %d: %s\n",timestamp,"task_wdt",core,name);
        if (core == 1)
            break;
consider_cpu1:
        unsigned int diagnostics = *(volatile unsigned int *)&TASK_WATCHDOG_DIAGNOSTICS;
        core = 1;
        if (diagnostics == 0)
            break;
    } while (true);
    vPortExitCritical(&TASK_WATCHDOG_LOCK);
    /* The weak hook is linked to this non-NULL firmware entry. */
    panic_capture_watchdog_tasks();
    unsigned int mask = (unsigned int)*(volatile int *)&timed_out_cores;
    if (mask == 0)
        __assert_func(NULL,0,NULL,NULL);
    unsigned int processor_id;
    __asm__ volatile ("rsr.prid %0" : "=a"(processor_id));
    unsigned int current_core = (processor_id >> 13) & 1U;
    unsigned int other_core = current_core == 0;
    if (panic == 0) {
        if ((mask & (1U << current_core)) != 0) {
            if (*(volatile unsigned int *)&TASK_WATCHDOG_DIAGNOSTICS != 0) {
                timestamp = esp_log_timestamp();
                ets_printf("E (%lu) %s: Print CPU %d (current core) backtrace\n",timestamp,"task_wdt",current_core);
            }
            esp_backtrace_print(100);
        }
        if ((mask & (1U << other_core)) != 0) {
            if (*(volatile unsigned int *)&TASK_WATCHDOG_DIAGNOSTICS != 0) {
                timestamp = esp_log_timestamp();
                ets_printf("E (%lu) %s: Print CPU %d backtrace\n",timestamp,"task_wdt",other_core);
            }
            esp_crosscore_int_send_print_backtrace(other_core);
        }
        return;
    }
    if ((mask & 3U) == 3U) {
        if (*(volatile unsigned int *)&TASK_WATCHDOG_DIAGNOSTICS != 0) {
            timestamp = esp_log_timestamp();
            ets_printf("E (%lu) %s: Print CPU %d (current core) backtrace\n",timestamp,"task_wdt",current_core);
        }
        esp_backtrace_print(100);
        esp_crosscore_int_send_twdt_abort(other_core);
        for (;;) __asm__ volatile ("" ::: "memory");
    }
    if ((mask & (1U << other_core)) != 0) {
        esp_crosscore_int_send_twdt_abort(other_core);
        for (;;) __asm__ volatile ("" ::: "memory");
    }
    task_wdt_timeout_abort(true);
}
