/* Medius v3.4.7 host — SDK application information and component startup.
 * SDK names/order checked against ESP-IDF v5.4.4; native bytes are authority.
 */
#include "../include/types.h"

/* Native entry: 0x42002150. */
/* Original function-byte SHA-256:
 * 86c00df47ddc1368c930bdd72d861e41621a9f4ecc99945613423b92de3bf2cd. */
/* SDK CORE/CPU0 priority1 eFuse-error startup check. Call the public check
 * and restart on ANY nonzero WORD result; zero returns0. The native ESP32-S3
 * utility is a success-only stub, so this call chain does not inspect eFuse
 * registers in this build. Keep the call and failure branch; do not infer that
 * coding errors or other security conditions have actually been validated.
 */
int __esp_system_init_fn_init_efuse_check(void)
{
    int status = esp_efuse_check_errors();
    if (status != 0)
        esp_restart();
    return status;
}

/* Native entry: 0x420022a0. */
/* Original function-byte SHA-256:
 * 9af5fda0779b55dc708d7f4c11bb44bea7c873f7a94a7c20471f1be7843f0bfa. */
/* SDK CORE/CPU0 priority104 brownout initializer. Call esp_brownout_init
 * once and return0 after it returns. No local argument, status check, retry,
 * allocation or hardware access; detector/interrupt effects are in the callee.
 * A fatal/nonreturning callee path prevents this success return.
 */
int __esp_system_init_fn_init_brownout(void)
{
    esp_brownout_init();
    return 0;
}

/* Native entry: 0x420022ac. */
/* Original function-byte SHA-256:
 * fa7932a8ff944d4668533d8cbb172115e435b696c9ddca37f938a91a51f0bc13. */
/* SDK CORE/CPU0 priority105 Newlib-time initializer. This image's resolved
 * call goes directly to esp_time_impl_init, which initializes the RTC-based
 * system-time offset. Return0 after that void call; no local timer allocation,
 * clock read, retry, argument or status propagation is supplied here.
 */
int __esp_system_init_fn_init_newlib_time(void)
{
    esp_time_impl_init();
    return 0;
}

/* Native entry: 0x420022b8. */
/* Original function-byte SHA-256:
 * 8b22be6b848656d058baef3ce8e46ee186f7735d55b242bddbbff848beeccf61. */
/* SDK SECONDARY/CPU0 priority203 APB backup-DMA initializer. Register the
 * reviewed ROM lock/unlock callbacks through esp_apb_backup_dma_lock_init,
 * then return0. This wrapper does not take their mutex, transfer data, test
 * prior registration, check a return status or add a hardware fence.
 */
int __esp_system_init_fn_init_apb_dma(void)
{
    esp_apb_backup_dma_lock_init();
    return 0;
}

/* Native entry: 0x420022c4. */
/* Original function-byte SHA-256:
 * e1af8cdf6a7c34a985c8d767f239e76963ff184e124ccc9db3e070eb6857ae42. */
/* SDK SECONDARY/CPU0 priority999 bootloader RTC-watchdog disable callback.
 * Build an eight-byte stack HAL context: register pointer0x60008000 first,
 * then instance RWDT0. Pass that same context to ROM write-protect-disable
 * (40000de0), watchdog-disable (40000e04), write-protect-enable (40000dec),
 * in that order, and return0. Ghidra incorrectly inferred a void return.
 * This body adds no feed, timeout programming, interrupt clear, lock, status
 * check or explicit MEMW. Hardware effects and context use are delegated to
 * those ROM routines; the stack context is only live during these calls.
 */
int __esp_system_init_fn_init_disable_rtc_wdt(void)
{
    WatchdogHalContext rtc;
    volatile WatchdogHalContext *initial = &rtc;
    initial->rwdt_registers = (RtcWatchdogRegisters *)0x60008000U;
    initial->instance = WDT_RWDT;
    wdt_hal_write_protect_disable(&rtc);
    wdt_hal_disable(&rtc);
    wdt_hal_write_protect_enable(&rtc);
    return 0;
}

/* Native entry: 0x420022ec. */
/* Original function-byte SHA-256:
 * cecf51770fb1d0f1d1db556b9ad47a658141cf0fac36d9340cad3a926fdd5eef. */
/* SDK CORE/CPU0 priority130 flash initializer. Initialize the application
 * flash mutex/guard/OS callbacks first, ignoring that status. Initialize the
 * default flash chip next and assert on ANY nonzero status. On success, call
 * the reviewed brownout-reset check, then return the cached zero status.
 * No rollback of prior initialization, retry, independent size validation,
 * flash erase/program operation or synchronization is added by this wrapper.
 */
int __esp_system_init_fn_init_flash(void)
{
    (void)esp_flash_app_init();
    int status = esp_flash_init_default_chip();
    if (status != 0)
        __assert_func(NULL,0,NULL,NULL);
    spi_flash_needs_reset_check();
    return status;
}
