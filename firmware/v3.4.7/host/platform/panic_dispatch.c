/* Medius v3.4.7 host — platform/panic_dispatch.c.
 */

#include "../include/types.h"

/* Native entry: 0x40375c24. */
/* Original function-byte SHA-256:
 * 79b3e0dc419072e8d23a0bd2634c75724315e01fd7ee58cec236c537e6f120d9. */
/*
 * Forward a saved exception frame to the common panic dispatcher with
 * exception_context=1. The task-watchdog snapshot path uses zero;
 * the architectural panic/level4 entries use the separate one-valued wrapper.
 *
 * Read PRID before the cache query. If caches are disabled, first clear the
 * shared IPC stall state, then invoke the no-OS cache restoration wrapper.
 * Native A10 supplies PRID bit13 to that call, but the reviewed callee ignores
 * it and has no used C parameters. No second cache query or recovery check.
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
        (void)native_core; /* Ignored native argument to this no-OS build. */
        spi_flash_enable_interrupts_caches_no_os();
    }
    panic_dispatch_frame(frame,1U);
}

/* Native entry: 0x40375c48. */
/* Original function-byte SHA-256:
 * 6064f2104ccbd2574732269ea95819566f34bcab298f14afaa3b0c2200ef6a49. */
/*
 * Forward a saved exception frame to the common panic dispatcher with
 * exception_context=0. The task-watchdog snapshot path uses zero;
 * the architectural panic/level4 entries use the separate one-valued wrapper.
 *
 * Read PRID before the cache query. If caches are disabled, first clear the
 * shared IPC stall state, then invoke the no-OS cache restoration wrapper.
 * Native A10 supplies PRID bit13 to that call, but the reviewed callee ignores
 * it and has no used C parameters. No second cache query or recovery check.
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
        (void)native_core; /* Ignored native argument to this no-OS build. */
        spi_flash_enable_interrupts_caches_no_os();
    }
    panic_dispatch_frame(frame,0U);
}

/* Native entry: 0x40375c6c. */
/* Original function-byte SHA-256:
 * a936199aa2b3de33aa4c15c0eecc6d09f8c0095218767db10c8b9e47175d91e1. */
/* MEMW then store WORD zero to the shared IPC ISR stall-state location.
 * No state read, CPU selection, wait for acknowledgement or local interrupt/
 * cache change. Other IPC code publishes RUNNING=1 to this same WORD. */
void panic_clear_ipc_stall(void)
{
    memw();
    IPC_ISR_STALL_STATE=0;
}
