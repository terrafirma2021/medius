/* Medius v3.4.7 device — platform/panic_dispatch.c.
 */

#include "../include/types.h"

/* Native entry: 0x40375ff4. */
/* Original function-byte SHA-256:
 * 043689f1cafc7163e5bd29637a1f31c72826871bddd8db965c75502816dfae5f. */
/*
 * Forward a saved exception frame to the common panic dispatcher with
 * exception_context=1. The task-watchdog snapshot path uses zero;
 * the architectural panic/level4 entries use the separate one-valued wrapper.
 *
 * Read PRID before the cache query. If caches are disabled, first clear the
 * shared IPC stall state, then invoke the no-OS cache restoration wrapper.
 * A caller-specific alias preserves PRID bit 13 in the native A10 argument;
 * the reviewed callee ignores it. No second cache query or recovery check.
 *
 * frame: borrowed writable native exception-frame pointer, forwarded unchanged;
 * it is not dereferenced or validated here. No local allocation, logging,
 * interrupt-level write or lock. Return normally if the dispatcher returns.
 */
void panic_from_exception(XtensaExceptionFrame *frame)
{
    unsigned int native_core=(xtensa_read_prid()>>13)&1U;
    if (!spi_flash_cache_enabled()) {
        panic_clear_ipc_stall();
        panic_restore_caches_boundary(native_core);
    }
    panic_dispatch_frame(frame,1U);
}

/* Native entry: 0x40376018. */
/* Original function-byte SHA-256:
 * faad9e939d8dca9be958ae043d0fd8e064679b82728d8fc9d4c08b818643b4ec. */
/*
 * Forward a saved exception frame to the common panic dispatcher with
 * exception_context=0. The task-watchdog snapshot path uses zero;
 * the architectural panic/level4 entries use the separate one-valued wrapper.
 *
 * Read PRID before the cache query. If caches are disabled, first clear the
 * shared IPC stall state, then invoke the no-OS cache restoration wrapper.
 * A caller-specific alias preserves PRID bit 13 in the native A10 argument;
 * the reviewed callee ignores it. No second cache query or recovery check.
 *
 * frame: borrowed writable native exception-frame pointer, forwarded unchanged;
 * it is not dereferenced or validated here. No local allocation, logging,
 * interrupt-level write or lock. Return normally if the dispatcher returns.
 */
void xt_unhandled_exception(XtensaExceptionFrame *frame)
{
    unsigned int native_core=(xtensa_read_prid()>>13)&1U;
    if (!spi_flash_cache_enabled()) {
        panic_clear_ipc_stall();
        panic_restore_caches_boundary(native_core);
    }
    panic_dispatch_frame(frame,0U);
}

/* Native entry: 0x4037603c. */
/* Original function-byte SHA-256:
 * 468f0b2e73a36c0518f4979f410dc169fa9ed1d3b8d2b86721b699e4fa265a2d. */
/* MEMW then store WORD zero to the shared IPC ISR stall-state location.
 * No state read, CPU selection, wait for acknowledgement or local interrupt/
 * cache change. Other IPC code publishes RUNNING=1 to this same WORD. */
void panic_clear_ipc_stall(void)
{
    memw();
    IPC_ISR_STALL_STATE=0;
}
