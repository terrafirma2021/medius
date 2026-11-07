/* Medius v3.4.7 host — rtos/hooks.c.
 * Recovered C and native assembly, grouped for source navigation.
 * Original entry addresses, firmware-byte hashes and function comments follow.
 */

#include "../include/types.h"

/* Native entry: 0x40376018. */
/*
 * Medius v3.4.7 — host application; 0x40376018.
 *
 * Calls each non-NULL callback in this CPU eight-slot tick-hook table in ascending slot order,
 * with no arguments, in tick ISR context. No lock is held around invocation and no task is
 * created. Hook execution time adds to tick ISR latency.
 *
 * Called by: SysTickIsrHandler.
 *
 * Indirect call: invokes each current CPU tick-hook callback without arguments.
 *
 * Original function-byte SHA-256:
 * ec79b5ec1873d4b341f3db1908ddd77692ea75304ff990a442dfd93ca46092d6.
 */

/* Calls each non-NULL callback in this CPU eight-slot tick-hook table in ascending slot order,
   with no arguments, in tick ISR context. No lock is held around invocation and no task is
   created. Hook execution time adds to tick ISR latency. Reference: ESP-IDF v5.4.4
   components/esp_system/freertos_hooks.c. */

/*
 * Returns: Nothing; invokes non-NULL hooks for the current CPU.
 * Requirements/effects: Tick ISR context. Hooks take no arguments, must be ISR-safe and extend ISR
 *   latency. No lock protects invocation.
 */

void esp_vApplicationTickHook(void)
{
  uint core = (xtensa_read_prid() >> 13) & 1U;
  for (uint slot = 0; slot < 8; ++slot) {
    FreertosTickHook callback = FREERTOS_TICK_HOOKS[core][slot];
    if (callback != 0) {
      callback();
    }
  }
}

/* Native entry: 0x42003850. */
/*
 * Medius v3.4.7 — host application; 0x42003850.
 *
 * Stores a bool(void) idle callback in the selected core's first empty hook slot.
 *
 * Calls: vPortExitCritical, xPortEnterCriticalTimeout.
 *
 * Called by: FUN_42012f40, main_task.
 *
 * Original function-byte SHA-256:
 * 4b529a244c5c407234b4672bddd240d4f82f9edf70cc17362306eb38f999feba.
 */

/*
 * hook: bool(void) idle callback value to store; never invoked by this registration routine. NULL
 *   and duplicates are accepted.
 * core: Unsigned core index, restricted to0 or1.
 * Returns: 0 for the first available slot,0x101 (ESP_ERR_NO_MEM) for a full eight-entry
 *   row,or0x102 (ESP_ERR_INVALID_ARG) for core>=2.
 * Requirements/effects: Invalid cores return before locking or reading the table. Otherwise enters
 *   the same 8-byte mux used by the tick registry with timeout0xffffffff cycles and ignores entry
 *   status. Reads up to eight 32-bit callback slots in ascending order, stores the supplied
 *   pointer in the first NULL slot, exits the mux and succeeds. NULL input leaves that slot empty
 *   but succeeds. Full rows exit the mux and return exhaustion. Other rows and occupied slots are
 *   not changed by this body. Native hardware-LOOP bookkeeping is reconstructed as a bounded loop,
 *   not an invented extra predicate.
 */

int esp_register_freertos_idle_hook_for_cpu(FreertosIdleHook hook,
    unsigned int core)
{
    if (core >= 2U)
        return 0x102; /* ESP_ERR_INVALID_ARG */

    (void)xPortEnterCriticalTimeout(FREERTOS_HOOKS_LOCK, 0xffffffffU);
    for (unsigned int slot = 0; slot < 8U; ++slot) {
        if (FREERTOS_IDLE_HOOKS[core][slot] == 0) {
            /* NULL and duplicate callbacks are accepted. */
            FREERTOS_IDLE_HOOKS[core][slot] = hook;
            vPortExitCritical(FREERTOS_HOOKS_LOCK);
            return 0;
        }
    }
    vPortExitCritical(FREERTOS_HOOKS_LOCK);
    return 0x101; /* ESP_ERR_NO_MEM */
}

/* Native entry: 0x420038a4. */
/*
 * Medius v3.4.7 — host application; 0x420038a4.
 *
 * Stores a tick callback in the first empty slot of the selected core's eight-entry hook table.
 *
 * Calls: vPortExitCritical, xPortEnterCriticalTimeout.
 *
 * Called by: FUN_4200294c.
 *
 * Original function-byte SHA-256:
 * f551c2a96d7c2f29669ae8d4fceeb0c2dabef5546734294d3704287762f90cf4.
 */

/*
 * hook: void(void) callback value to store. NULL and duplicates are accepted; this routine does
 *   not invoke it.
 * core: Unsigned core index; only 0 and 1 are accepted.
 * Returns: 0 on a free slot, 0x101 (ESP_ERR_NO_MEM) when all eight slots are occupied, or 0x102
 *   (ESP_ERR_INVALID_ARG) for a core index >=2.
 * Requirements/effects: Invalid core values return before reading the table or entering its mux.
 *   For a valid core, enters the shared hook mux with timeout 0xffffffff cycles, ignoring its
 *   return status; scans exactly eight 32-bit function-pointer slots in ascending order. Stores in
 *   the first NULL slot, exits that same mux and returns success. A NULL input leaves the slot
 *   empty but still succeeds. A full row exits the mux and returns exhaustion. The apparent extra
 *   loop condition in the raw decompilation was Xtensa hardware-LOOP bookkeeping, not another
 *   native predicate. The two-core table is 64 bytes; other rows and occupied slots are not
 *   modified by this body.
 */

int esp_register_freertos_tick_hook_for_cpu(FreertosTickHook hook,
    unsigned int core)
{
    if (core >= 2U)
        return 0x102; /* ESP_ERR_INVALID_ARG */

    (void)xPortEnterCriticalTimeout(FREERTOS_HOOKS_LOCK, 0xffffffffU);
    for (unsigned int slot = 0; slot < 8U; ++slot) {
        if (FREERTOS_TICK_HOOKS[core][slot] == 0) {
            /* NULL and duplicate callback values are accepted by this API. */
            FREERTOS_TICK_HOOKS[core][slot] = hook;
            vPortExitCritical(FREERTOS_HOOKS_LOCK);
            return 0;
        }
    }
    vPortExitCritical(FREERTOS_HOOKS_LOCK);
    return 0x101; /* ESP_ERR_NO_MEM: all eight slots are occupied */
}

/* Native entry: 0x420038f8. */
/*
 * Medius v3.4.7 — host application; 0x420038f8.
 *
 * Clears every slot matching an idle callback in the selected core's hook row.
 *
 * Calls: vPortExitCritical, xPortEnterCriticalTimeout.
 *
 * Called by: main_task.
 *
 * Original function-byte SHA-256:
 * 594aae3353f6825a7e8d8eea67b6973215a19e26dd1846a7ef08e600c1581d11.
 */

/*
 * hook: bool(void) callback value to match. NULL is accepted and causes explicit zero stores to
 *   every already-empty matching slot.
 * core: Unsigned core index; values>=2 are silent no-ops.
 * Returns: No value and no indication of whether any match was found.
 * Requirements/effects: For a valid core, enters the shared idle/tick hook mux with
 *   timeout0xffffffff cycles, ignoring entry status; reads all eight callback words in ascending
 *   order and clears every matching slot, including all duplicates. It does not stop after the
 *   first match or skip zero-to-zero matching stores. Exits the same mux after the complete scan.
 *   No callback is invoked and other rows are untouched by this body. The native loop has exactly
 *   eight iterations; decompiler phantom loop-state conditions are removed. The routine supplies
 *   no guarantee about a callback already captured by the separate idle dispatcher.
 */

void esp_deregister_freertos_idle_hook_for_cpu(FreertosIdleHook hook,
    unsigned int core)
{
    if (core >= 2U)
        return;

    (void)xPortEnterCriticalTimeout(FREERTOS_HOOKS_LOCK, 0xffffffffU);
    for (unsigned int slot = 0; slot < 8U; ++slot) {
        if (FREERTOS_IDLE_HOOKS[core][slot] == hook)
            FREERTOS_IDLE_HOOKS[core][slot] = 0;
    }
    vPortExitCritical(FREERTOS_HOOKS_LOCK);
}

/* Native entry: 0x4200381c. */
/*
 * Medius v3.4.7 — host application; 0x4200381c.
 * Instruction-checked recovered C.
 * Original function-byte SHA-256:
 * 3774186705b1907cc2827b88c4f2d4108c349d9d85affe013dc90ecd4c5c362e.
 */

/* Sample this core once and walk all8 idle-hook slots in ascending order.
 * Load each slot ONCE, call non-NULL callback without arguments, AND its result
 * with idle permission (initial1). Continue after a veto; callback ABI returns
 * bool0/1. If all registered hooks permit, enter CPU interrupt-wait; an empty
 * table also permits it. No table mux, task dispatch, timer, slot reload after
 * check or guarantee when an interrupt will resume execution. */
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
