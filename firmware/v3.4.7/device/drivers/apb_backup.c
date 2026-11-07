/* Medius v3.4.7 device — drivers/apb_backup.c.
 * Recovered C and native assembly, grouped for source navigation.
 * Original entry addresses, firmware-byte hashes and function comments follow.
 */

#include "../include/types.h"

/* Native entry: 0x40375f18. */
/*
 * Medius v3.4.7 — device application; 0x40375f18.
 *
 * Releases the shared APB backup DMA critical section after the retained ISR-context query.
 *
 * Calls: xPortInIsrContext, vPortExitCritical.
 *
 * Original function-byte SHA-256:
 * 8139d3908ac202d92076b635f1e8e3d906acf534ac4f76239f80efb641f0faf9.
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

/* Native entry: 0x40375f28. */
/*
 * Medius v3.4.7 — device application; 0x40375f28.
 *
 * Enters the shared APB backup DMA critical section after the retained ISR-context query.
 *
 * Calls: xPortInIsrContext, xPortEnterCriticalTimeout.
 *
 * Original function-byte SHA-256:
 * 8685b052caac8caf4aaf10059235908568db8d573f6742bc4b088ba47413cda0.
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

/* Native entry: 0x42002f54. */
/*
 * Medius v3.4.7 — device application; 0x42002f54.
 *
 * Registers the APB backup DMA lock and unlock callbacks with the ESP32-S3 ROM.
 *
 * Calls: ets_apb_backup_init_lock_func.
 *
 * Called by: FUN_42002980.
 *
 * Original function-byte SHA-256:
 * b4a746e2c55384ac22de708c4dda5395fe6ed9e99d567b577594c09d6e8606d1.
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

