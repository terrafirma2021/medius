/* Medius v3.4.7 host — drivers/apb_backup.c.
 * Recovered C and native assembly, grouped for source navigation.
 * Original entry addresses, firmware-byte hashes and function comments follow.
 */

#include "../include/types.h"

/* Native entry: 0x40375b48. */
/*
 * Medius v3.4.7 — host application; 0x40375b48.
 *
 * Releases the shared APB backup DMA critical section after the retained ISR-context query.
 *
 * Calls: vPortExitCritical, xPortInIsrContext.
 *
 * Original function-byte SHA-256:
 * abb4c7fdc875cab4146c4da1764191ad5c450bdfd50df7bd1a2e248f709fecd0.
 */

/*
 * Returns: No value.
 * Requirements/effects: Calls xPortInIsrContext and ignores its result, retaining the query's
 *   interrupt-state side effects. The SDK task/ISR branches compile to the same API here; no
 *   conditional native branch remains. Then calls vPortExitCritical on the shared 8-byte static
 *   APB backup DMA mux. The caller must have the corresponding critical section held; this wrapper
 *   does not check ownership or nesting itself.
 */

void apb_backup_dma_unlock(void)
{
    /* The context query still executes although its result is unused. */
    (void)xPortInIsrContext();
    vPortExitCritical(&APB_BACKUP_DMA_MUX);
}

/* Native entry: 0x40375b58. */
/*
 * Medius v3.4.7 — host application; 0x40375b58.
 *
 * Enters the shared APB backup DMA critical section after the retained ISR-context query.
 *
 * Calls: xPortEnterCriticalTimeout, xPortInIsrContext.
 *
 * Original function-byte SHA-256:
 * 0112f5d2208058f314273654f5502808b36308f321068400ac53953335da9787.
 */

/*
 * Returns: No value.
 * Requirements/effects: Calls xPortInIsrContext and ignores its result, retaining the query's
 *   interrupt-state side effects. The SDK task/ISR branches compile to the same API here; no
 *   conditional native branch remains. Then calls xPortEnterCriticalTimeout on the shared 8-byte
 *   static APB backup DMA mux with timeout 0xffffffff cycles and ignores its status. No additional
 *   timeout, failure handling or rollback is supplied.
 */

void apb_backup_dma_lock(void)
{
    /* Both SDK context branches compile to this same critical-entry API. */
    (void)xPortInIsrContext();
    (void)xPortEnterCriticalTimeout(&APB_BACKUP_DMA_MUX, 0xffffffffU);
}

/* Native entry: 0x42002894. */
/*
 * Medius v3.4.7 — host application; 0x42002894.
 *
 * Registers the APB backup DMA lock and unlock callbacks with the ESP32-S3 ROM.
 *
 * Calls: ets_apb_backup_init_lock_func.
 *
 * Called by: FUN_420022b8.
 *
 * Original function-byte SHA-256:
 * b3ed7fe1af791b82aa08e7d8c0e3e131305a5fa8fc61f21bacf41a4724d5f074.
 */

/*
 * Returns: No value.
 * Requirements/effects: Passes two void(void) function pointers to ROM address 0x40000630, lock
 *   first and unlock second. Both callbacks share the same 8-byte static portMUX. This routine
 *   does not itself acquire or release that mux, test prior registration, or initialize/reset mux
 *   storage. Any registration lifetime, DMA use or callback invocation is supplied by ROM.
 */

void esp_apb_backup_dma_lock_init(void)
{
    ets_apb_backup_init_lock_func(apb_backup_dma_lock, apb_backup_dma_unlock);
}

