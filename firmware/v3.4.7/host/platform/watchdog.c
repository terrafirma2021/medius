/* Medius v3.4.7 host — platform/watchdog.c.
 * Recovered C and native assembly, grouped for source navigation.
 * Original entry addresses, firmware-byte hashes and function comments follow.
 */

#include "../include/types.h"

/* Native entry: 0x40375b6c. */
/*
 * Medius v3.4.7 — host application; 0x40375b6c.
 *
 * Records CPU1 tick progress, or feeds the interrupt watchdog from CPU0 after observing that progress.
 *
 * Calls: FUN_40000dd4, FUN_40000de0, FUN_40000dec, FUN_40000e1c.
 *
 * Original function-byte SHA-256:
 * c2a721454e5a13a16fd658b8cb8b4cb5846f8e4bbc5417c51057c27efc5e0cb8.
 */

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
    uint core = (xtensa_read_prid() >> 13) & 1U;
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

/* Native entry: 0x420028a8. */
/*
 * Medius v3.4.7 — host application; 0x420028a8.
 *
 * Acquires timer-group1 clock ownership and initializes the interrupt watchdog HAL, startup timeout stages and enable state.
 *
 * Calls: wdt_hal_init, wdt_hal_config_stage, wdt_hal_write_protect_disable, wdt_hal_write_protect_enable, wdt_hal_enable, periph_rcc_acquire_enter,
 * periph_rcc_acquire_exit.
 *
 * Called by: esp_startup_start_app.
 *
 * Original function-byte SHA-256:
 * c4d9096ab3527aee2945e7e6aac89da2910b0e0044a9a59ede558e24a601ad2d.
 */

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

/* Native entry: 0x4200294c. */
/*
 * Medius v3.4.7 — host application; 0x4200294c.
 *
 * Registers the interrupt-watchdog tick hook and routes its fixed watchdog interrupt on the current core.
 *
 * Calls: esp_intr_enable_source, esp_intr_disable_source, esp_register_freertos_tick_hook_for_cpu, intr_matrix_set.
 *
 * Called by: FUN_42023a40, esp_startup_start_app_other_cores.
 *
 * Original function-byte SHA-256:
 * 8ac77fc5b70f3c4b4db00ab1177536f694c64f6b422115b390448235da0ef860.
 */

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
    uint registration_core = (xtensa_read_prid() >> 13) & 1U;
    /* The native code ignores hook-registration failure. */
    (void)esp_register_freertos_tick_hook_for_cpu(esp_int_wdt_tick_hook,
        registration_core);
    esp_intr_disable_source(24);
    uint routing_core = (xtensa_read_prid() >> 13) & 1U;
    intr_matrix_set(routing_core, 55, 24);
    esp_intr_enable_source(24);
}

/* Native entry: 0x4200ef1c. */
/* Original function-byte SHA-256:
 * ed6f197f6aa8f8d20f7f4095f713f10c875c9dc151693476d81f0f7d8790e5a8. */
/* Subscribe the current task through esp_task_wdt_add(NULL). Zero status
 * returns without logging. For any nonzero status, sample log timestamp FIRST,
 * obtain pcTaskGetName(NULL) second and issue one level1 wdt error diagnostic
 * containing that name and the original status. Return normally after the
 * diagnostic; no retry, abort, alternate subscription or status is returned.
 * Timeout configuration and shared watchdog state belong to the SDK service;
 * this wrapper creates no dedicated software/hardware timer per worker.
 */
void medius_worker_watchdog_add(void)
{
    int status = esp_task_wdt_add(NULL);
    if (status == 0) return;
    unsigned int timestamp = esp_log_timestamp();
    char *task_name = pcTaskGetName(NULL);
    esp_log_write(1,MEDIUS_WORKER_WDT_LOG_TAG,"E (%lu) %s: %s unwatched (err 0x%x)\n",
        timestamp,MEDIUS_WORKER_WDT_LOG_TAG,task_name,status);
}

/* Native entry: 0x4200ef50. */
/* Original function-byte SHA-256:
 * c95fb7df989995aa6326d6a471911a6e6c0a6f75e9a867b71b4ff1dc2e9aea69. */
/* Call esp_task_wdt_reset once for the current task and discard its status.
 * No local validation, logging, retry, timer creation or error result. Feeding
 * the shared watchdog and handling a missing subscription are callee behavior;
 * a successful hardware feed or a particular future deadline is not guaranteed
 * by this forwarding function.
 */
void medius_worker_watchdog_feed(void)
{
    (void)esp_task_wdt_reset();
}

/* Native entry: 0x42012cb4. */
/*
 * Medius v3.4.7 — host application; 0x42012cb4.
 *
 * Adds an entry to the task watchdog subscriber list.
 *
 * Calls: esp_log_timestamp, calloc, free, FUN_42013490, FUN_420134d8, ets_printf,
 * vPortExitCritical, xPortEnterCriticalTimeout.
 *
 * Called by: esp_task_wdt_add.
 *
 * Original function-byte SHA-256:
 * 65e244bfa70f37039a008887564aed09f9b8c846a61767e09907c101eca18897.
 */

/*
 * is_task: SDK bool ABI: true selects a task-handle entry, false a user-name entry.
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

int task_wdt_add_entry(bool is_task, void *entry_data,
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

/* Native entry: 0x42012e48. */
/*
 * Medius v3.4.7 — host application; 0x42012e48.
 *
 * Transfers a task-watchdog timeout to the current task exception frame after snapshot validation.
 *
 * Calls: esp_reset_reason_set_hint, xt_unhandled_exception, xTaskGetCurrentTaskHandle, vTaskGetSnapshot, esp_log_timestamp, __assert_func,
 * ets_printf.
 *
 * Called by: FUN_4037d2b0, FUN_42013260.
 *
 * Original function-byte SHA-256:
 * 1bdcd927df7108feecb94196e7a988d1de50ccd3ae429ca33c3b5f314d348128.
 */

/*
 * current_core: SDK bool parameter; selects whether the CPU diagnostic identifies this as the
 *   current core. Native transfer uses the low 8 bits.
 * Returns: No value. Snapshot failure asserts; success transfers the saved frame to exception
 *   handling. Native RET is retained if that handler returns.
 * Requirements/effects: Initializes all three pointers in a 12-byte task snapshot to NULL. The
 *   first full diagnostic-control word gates the Aborting message. Sets reset hint 6
 *   (ESP_RST_TASK_WDT), queries the current task, then requests its snapshot. Tests the full
 *   32-bit snapshot result against 1; every other result calls the nonreturning four-zero silent
 *   assertion before either panic flag is set. Captures snapshot.top_of_stack, then stores byte 1
 *   to both g_panic_abort and g_twdt_isr locations. These are independent constant stores; the raw
 *   decompile misleadingly implied a readback between flags. Rereads the diagnostic-control word
 *   for the CPU message. A fresh PRID bit 13 is sampled after that message timestamp only when
 *   diagnostics are enabled. Uses current-core wording for any nonzero low argument byte, and
 *   ordinary CPU wording for zero,matching the native 8-bit parameter transfer. Finally passes the
 *   captured frame to xt_unhandled_exception; later diagnostic side effects do not make it reread
 *   the snapshot. The native RET epilogue remains if that delegate returns. No frame validation,
 *   stack unwinding, global flag rollback, scheduler stop, or lock is implemented here; the caller
 *   must provide a safe panic/snapshot context and the debug and exception implementations supply
 *   their own semantics. No watchdog-state object is read.
 */

void task_wdt_timeout_abort(bool current_core)
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

    void *frame = snapshot.top_of_stack;
    PANIC_ABORT_IN_PROGRESS = 1;
    TASK_WATCHDOG_ISR_ACTIVE = 1;

    if (TASK_WATCHDOG_DIAGNOSTICS != 0) {
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

/* Native entry: 0x42012ef4. */
/*
 * Medius v3.4.7 — host application; 0x42012ef4.
 *
 * Registers a task with the task watchdog.
 *
 * Calls: xTaskGetCurrentTaskHandle, esp_log_timestamp, esp_log_write, task_wdt_add_entry.
 *
 * Called by: medius_worker_watchdog_add, FUN_42012f40.
 *
 * Original function-byte SHA-256:
 * 8452e5d1bc684834d0254e2e22424c61b3f1f3b1cb267e1abd149b42ece6f355.
 */

/*
 * task: Task handle to subscribe. NULL resolves the current task; its returned handle is forwarded
 *   without another local NULL test.
 * Returns: 0x103 when global watchdog state is NULL; otherwise the unchanged 32-bit add-entry
 *   result.
 * Requirements/effects: Checks global initialization before querying the current task. Logs the
 *   exact public error diagnostic with source line 0x29d if uninitialized. Passes true, the
 *   explicit or resolved task handle, and the address of a local entry pointer to
 *   task_wdt_add_entry. Corrects the misleading 48-byte local-array rendering: the output is
 *   one 4-byte pointer and is never read by this wrapper. No extra lock, allocation, rollback,
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

/* Native entry: 0x42012f40. */
/*
 * Medius v3.4.7 — host application; 0x42012f40.
 *
 * Subscribes selected cores' idle tasks to the task watchdog and registers their idle hooks.
 *
 * Calls: xTaskGetIdleTaskHandleForCore, __assert_func, esp_register_freertos_idle_hook_for_cpu, abort, esp_task_wdt_add.
 *
 * Called by: esp_task_wdt_init.
 *
 * Original function-byte SHA-256:
 * 77af0c3d41b6bd20ba3eeff6ca6ddc73808bbdfd01a78f3c24f2ac540cfe2d5c.
 */

/*
 * core_mask: Unsigned 32-bit core mask. Zero does nothing. Valid live idle-task handles must exist
 *   for all selected cores.
 * Returns: No value. A NULL idle handle asserts; any nonzero 32-bit watchdog-add or hook-
 *   registration status aborts.
 * Requirements/effects: Scans selected mask bits in ascending order. For each bit, obtains that
 *   core's idle-task handle, asserts if NULL, passes that exact handle to esp_task_wdt_add, then
 *   registers the bool(void) task-watchdog idle hook on the same core. Restores the task argument
 *   omitted by the raw decompile. Each API status is tested as a full 32-bit value; hook
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

/* Native entry: 0x42012f98. */
/*
 * Medius v3.4.7 — host application; 0x42012f98.
 *
 * Initializes the task watchdog.
 *
 * Calls: esp_log_timestamp, esp_log_write, calloc, free, subscribe_idle, esp_task_wdt_impl_timer_allocate,
 * esp_task_wdt_impl_timer_restart.
 *
 * Called by: main_task.
 *
 * Original function-byte SHA-256:
 * 6751995000625d39d4a29f00851b091b887dea12c34ff44bdfd043a97db2a1ad.
 */



/*
 * Initializes the shared task watchdog and its timer backend.
 *
 * configuration: readable 12-byte configuration; idle_core_mask must be 0..3
 * at entry. timeout_ms validation is delegated to the timer allocator.
 *
 * Returns 0 on success, 0x102 for NULL/invalid mask, 0x103 when already
 * initialized, 0x101 for allocation failure, or the timer allocator's error.
 * The full 32-bit allocator result is tested and returned without narrowing.
 *
 * Copies the panic byte before allocating the backend. On success, rereads
 * the configuration mask, publishes the state, and subscribes requested idle
 * tasks. Reloads global state after that subscription call. Starts the timer
 * only when the selected state has subscriptions; otherwise sets its waiting
 * flag. The timer restart result is ignored. Restores the idle-mask argument
 * omitted by the raw decompile.
 *
 * Failure frees the newly allocated object, including free(NULL) after a
 * failed calloc. This caller does not unwind backend side effects. It provides
 * no lock against simultaneous initialization;
 * callers must serialize initialization and supply live configuration/state.
 */

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
 *   nonzero mask is passed to subscribe_idle, restoring the argument omitted by Ghidra, and global
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

/* Native entry: 0x42013080. */
/*
 * Medius v3.4.7 — host application; 0x42013080.
 *
 * Feeds the task watchdog for the current task.
 *
 * Calls: xTaskGetCurrentTaskHandle, esp_log_timestamp, esp_log_write, FUN_42013490, ets_printf, vPortExitCritical,
 * xPortEnterCriticalTimeout.
 *
 * Called by: medius_worker_watchdog_feed, FUN_4201314c.
 *
 * Original function-byte SHA-256:
 * ce84aea79f2e7e39ca02a835acd573e4b6d4cc81724ad69de8c1ece8d43787f1.
 */

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

/* Native entry: 0x4201314c. */
/*
 * Medius v3.4.7 — host application; 0x4201314c.
 *
 * Calls task-watchdog reset from the idle hook and returns true, ignoring reset status.
 *
 * Calls: esp_task_wdt_reset.
 *
 * Original function-byte SHA-256:
 * 6ccebb1a78e52d17c61b5b24c73a7c2bdb0ec63ed8bf9b45f734b26db28378b5.
 */

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

/* Native entry: 0x42013158. */
/*
 * Medius v3.4.7 — host application; 0x42013158.
 *
 * Reports timed-out task and user subscriptions and accumulates their CPU-affinity mask.
 *
 * Calls: pcTaskGetName, xTaskGetCoreID, esp_log_timestamp, ets_printf.
 *
 * Called by: FUN_42009038, FUN_42013260.
 *
 * Four typed text-fragment callback sites.
 *
 * Original function-byte SHA-256:
 * 34e8ba7228542ccee665ba35cbea6f7805f53eecb7b250c43c263996a03680ee.
 */

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
 * select both cores. Restores the task argument omitted by Ghidra.
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

/* Native entry: 0x420133c8. */
/*
 * Medius v3.4.7 — host application; 0x420133c8.
 *
 * Configures the shared TIMG0 task-watchdog backend, without starting its counter.
 *
 * Calls: wdt_hal_init, wdt_hal_config_stage, wdt_hal_write_protect_disable, wdt_hal_write_protect_enable, periph_rcc_acquire_enter, periph_rcc_acquire_exit,
 * esp_intr_alloc.
 *
 * Called by: esp_task_wdt_init.
 *
 * Original function-byte SHA-256:
 * 3afdf8461e21bd1635b75de9aee7d2adb7e255bc4e0f1aa0dac966d81cfc7fc0.
 */

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
 *   ROM wdt_hal_init with MWDT0, prescaler 40000,and level interrupt enabled; restores the fourth
 *   argument omitted by Ghidra. Disables write protection,reads timeout_ms and programs stage 0
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

/* Native entry: 0x42013490. */
/*
 * Medius v3.4.7 — host application; 0x42013490.
 *
 * Feeds the task-watchdog hardware backend under ROM write protection.
 *
 * Calls: wdt_hal_write_protect_disable, wdt_hal_write_protect_enable, wdt_hal_feed.
 *
 * Called by: esp_task_wdt_reset, task_wdt_add_entry.
 *
 * Original function-byte SHA-256:
 * e5a403ef1cf5ba6926abd93f9f6bd0ff32063a81f47d49e9dba796a059507823.
 */

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

/* Native entry: 0x420134b8. */
/*
 * Medius v3.4.7 — host application; 0x420134b8.
 *
 * Handles the watchdog interrupt through the ROM feed-and-acknowledge operation.
 *
 * Calls: wdt_hal_write_protect_disable, wdt_hal_write_protect_enable, wdt_hal_handle_intr.
 *
 * Called by: FUN_42013260.
 *
 * Original function-byte SHA-256:
 * 119723752a5db11d39c6d2044a6554e216a8e572403d9f9d2d90ab08d82febea.
 */

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

/* Native entry: 0x420134d8. */
/*
 * Medius v3.4.7 — host application; 0x420134d8.
 *
 * Restarts the task-watchdog timer-group backend through the four ROM HAL operations.
 *
 * Calls: wdt_hal_write_protect_disable, wdt_hal_write_protect_enable, wdt_hal_enable, wdt_hal_feed.
 *
 * Called by: esp_task_wdt_init, task_wdt_add_entry.
 *
 * Original function-byte SHA-256:
 * 32186ae566d4fe5fbaeb9dac0cae93d2c6048690a39b835dc67ba74392739a83.
 */

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

/* Native entry: 0x42013260. */
/* Original function-byte SHA-256:
 * 3ced95d1ab5c5b8a490c4a08417953bef54a15057946453dda210086cf3831ac. */
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
    unsigned int mask = *(volatile unsigned int *)&timed_out_cores;
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
