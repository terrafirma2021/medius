/* Medius v3.4.7 device — FreeRTOS idle and tick hook registries. */
#include "../include/types.h"

/* Native entry: 0x4037641c. */
/* Original function-byte SHA-256:
 * d5cca9df0e6a0b898aba87ddef12a892035d2afae73793ccd64b09dc47d6746a. */
/*
 * Runs the current CPU's eight void(void) tick callbacks in ascending slot order.
 *
 * Samples PRID bit 13 once, then reads each slot once immediately before its
 * NULL check and call. Later slots remain live reads, so an earlier callback can
 * change what a later slot contains. Empty slots are skipped; duplicates run at
 * each occupied slot. Returns no value and ignores callback return registers.
 *
 * Called from the tick ISR. Callbacks must be valid and ISR-safe; their execution
 * adds to ISR latency. Dispatch holds no registry mux, captures no whole-table
 * snapshot and provides no lifetime protection or fixed execution deadline.
 */
void esp_vApplicationTickHook(void)
{
  unsigned int core = (xtensa_read_prid() >> 13) & 1U;
  for (unsigned int slot = 0; slot < 8; ++slot) {
    FreertosTickHook callback = FREERTOS_TICK_HOOKS[core][slot];
    if (callback != 0) {
      callback();
    }
  }
}

/* Native entry: 0x42003b1c. */
/* Original function-byte SHA-256:
 * 6edf0277ffa73deb8a71490ad0a73caa13e24da81ed032b70a065dcd3ef4bf58. */
/*
 * hook: bool(void) callback value to store; NULL and duplicate values are accepted.
 * core: Full unsigned 32-bit index; only 0 and 1 are accepted.
 * Returns 0 after storing in the first empty slot, 0x101 for a full row, or
 * 0x102 for an invalid core before any lock/table access.
 *
 * Enters the shared idle/tick mux with timeout_cycles=-1 and ignores its result.
 * Reads up to eight callback WORDs in ascending order; stores hook only in the
 * first NULL slot. A NULL hook leaves that slot empty but still succeeds. Unlocks
 * on both returning locked paths. Does not invoke callbacks, change other rows,
 * reject duplicates, or synchronize against a callback already captured by the
 * separate dispatcher. Caller/dependencies supply valid callback lifetimes.
 */
int esp_register_freertos_idle_hook_for_cpu(FreertosIdleHook hook,
    unsigned int core)
{
    if (core >= 2U)
        return 0x102; /* ESP_ERR_INVALID_ARG */

    PortMuxWords *lock = FREERTOS_HOOKS_LOCK;
    (void)xPortEnterCriticalTimeout(lock, -1);
    for (unsigned int slot = 0; slot < 8U; ++slot) {
        if (FREERTOS_IDLE_HOOKS[core][slot] == 0) {
            /* NULL and duplicate callbacks are accepted. */
            FREERTOS_IDLE_HOOKS[core][slot] = hook;
            vPortExitCritical(lock);
            return 0;
        }
    }
    vPortExitCritical(lock);
    return 0x101; /* ESP_ERR_NO_MEM */
}

/* Native entry: 0x42003b70. */
/* Original function-byte SHA-256:
 * e5013153c673701c4d45c9fbed8f4c70de1d7c5a9fc51addd9430efe794a24c2. */
/*
 * hook: void(void) callback value to store; NULL and duplicates are accepted.
 * core: Full unsigned 32-bit index; only 0 and 1 are accepted.
 * Returns 0 after the first-empty-slot store, 0x101 for a full eight-slot row,
 * or 0x102 for an invalid core before any lock or table access.
 *
 * Enters the shared idle/tick mux with timeout_cycles=-1, ignoring its status.
 * Reads callback WORDs in ascending slot order and stores only into the first
 * NULL slot. Storing NULL succeeds while leaving the slot free. Unlocks on every
 * returning locked path. This body does not invoke callbacks or protect the
 * separate tick dispatcher; unregistering/changing a slot cannot retract a
 * pointer already loaded by that dispatcher. Callback storage must remain live.
 */
int esp_register_freertos_tick_hook_for_cpu(FreertosTickHook hook,
    unsigned int core)
{
    if (core >= 2U)
        return 0x102; /* ESP_ERR_INVALID_ARG */

    PortMuxWords *lock = FREERTOS_HOOKS_LOCK;
    (void)xPortEnterCriticalTimeout(lock, -1);
    for (unsigned int slot = 0; slot < 8U; ++slot) {
        if (FREERTOS_TICK_HOOKS[core][slot] == 0) {
            /* NULL and duplicate callback values are accepted by this API. */
            FREERTOS_TICK_HOOKS[core][slot] = hook;
            vPortExitCritical(lock);
            return 0;
        }
    }
    vPortExitCritical(lock);
    return 0x101; /* ESP_ERR_NO_MEM: all eight slots are occupied */
}

/* Native entry: 0x42003bc4. */
/* Original function-byte SHA-256:
 * b68419327529aeabc2fd33942858e00f0ac37d4ad84a4e912c5c1c8e2186ea9a. */
/*
 * hook: bool(void) callback value to match, including NULL.
 * core: Full unsigned 32-bit index; values >=2 return without lock/table access.
 * Returns no value or match count.
 *
 * Enters the shared idle/tick mux with timeout_cycles=-1, ignoring its result.
 * Reads all eight callback WORDs in ascending order and stores NULL into every
 * matching slot, including every duplicate and explicit zero-to-zero writes
 * when hook is NULL. Always unlocks after a complete valid-core scan. Does not
 * invoke callbacks, stop at the first match, change other rows, or wait for a
 * callback already captured by the unlocked idle dispatcher to finish.
 */
void esp_deregister_freertos_idle_hook_for_cpu(FreertosIdleHook hook,
    unsigned int core)
{
    if (core >= 2U)
        return;

    PortMuxWords *lock = FREERTOS_HOOKS_LOCK;
    (void)xPortEnterCriticalTimeout(lock, -1);
    for (unsigned int slot = 0; slot < 8U; ++slot) {
        if (FREERTOS_IDLE_HOOKS[core][slot] == hook)
            FREERTOS_IDLE_HOOKS[core][slot] = 0;
    }
    vPortExitCritical(lock);
}

/* Native entry: 0x42003ae8. */
/* Original function-byte SHA-256:
 * e83b2f855c70b2bf36cbfad9ec297187777aac77504ea202d0161cd972b2ee8e. */
/*
 * Runs the current CPU's eight bool(void) idle callbacks in ascending slot order.
 * Samples PRID bit 13 once; each slot is loaded once before its NULL check/call.
 * ANDs callback results into permission initially 1 and continues after a veto.
 * Duplicate callbacks execute at every occupied slot; empty slots are skipped.
 * If all hooks allow idle, or the row is empty, calls esp_cpu_wait_for_intr once.
 * Returns no value after that delegate returns; any false result skips the wait.
 *
 * Callbacks must obey the SDK bool 0/1 return ABI, remain valid and avoid blocking.
 * This dispatcher holds no table mux and does not snapshot later slots early.
 * It creates no task/timer, supplies no callback lifetime protocol, and does not
 * guarantee when an interrupt resumes execution. Waiting is delegated, not an
 * emulated interrupt wait or a deadline measured by this body.
 */
void esp_vApplicationIdleHook(void)
{
    unsigned int core = (xtensa_read_prid() >> 13) & 1U;
    unsigned int idle_allowed = 1;
    for (unsigned int slot = 0; slot < 8U; ++slot) {
        FreertosIdleHook callback = FREERTOS_IDLE_HOOKS[core][slot];
        if (callback)
            idle_allowed &= (unsigned int)callback();
    }
    if (idle_allowed)
        esp_cpu_wait_for_intr();
}
