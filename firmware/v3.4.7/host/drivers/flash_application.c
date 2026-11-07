/* Medius v3.4.7 host — main-flash application OS initialization. */
#include "../include/types.h"

/* Native entry: 0x42012c14. */
/* Original function-byte SHA-256:
 * 670b055f24755cfdb79e638d2eaf9bda1489fbc1251039f3cb44b35ed961b72f. */
/* Initialize this build's application flash access. Create/assert the
 * recursive flash mutex through spi_flash_init_lock, install the static
 * default guard table, then enable OS callbacks on the FIXED default-chip
 * object (not a reload through esp_flash_default_chip). Return the enable
 * status unchanged. No bus-lock acquisition, dynamic OS context, counters
 * reset, voltage reservation or error cleanup is present in this image.
 * Repeated calls reinitialize the mutex and shared OS context without a guard.
 */
int esp_flash_app_init(void)
{
    spi_flash_init_lock();
    spi_flash_guard_set(FLASH_DEFAULT_GUARD);
    return esp_flash_app_enable_os_functions((EspFlash *)DEFAULT_FLASH_OBJECT);
}

/* Native entry: 0x42012c30. */
/* Original function-byte SHA-256:
 * a07706c7e391eb53f117f554724f96977fa8ba845a294a0d470ff7987e4754be. */
/* Bind the caller's flash object to the shared main-flash OS callbacks.
 * First read the device-lock WORD from its DROM slot (zero in these images),
 * then store it to shared context+0. Clear context WORDs+4,+8,+12 in order:
 * protection flag AND its padding, acquisition time and release time. Publish
 * the callback-table pointer to chip+8, then the shared-context pointer to
 * chip+12; return0. The context is reset before either chip store, including
 * on an invalid/NULL chip. Requires a writable flash object; no NULL check,
 * per-chip allocation, lock, MEMW, previous-context cleanup or ROM call.
 * All chips passed here share this context and its later timing/protection
 * state. Ghidra's constant0 assignment hid the initial DROM lock-pointer read.
 */
int esp_flash_app_enable_os_functions(EspFlash *chip)
{
    void *device_lock = MAIN_FLASH_DEVICE_LOCK;
    volatile FlashOsContext *context = MAIN_FLASH_OS_CONTEXT;
    context->device_lock = device_lock;
    context->protection_word = 0;
    context->acquired_since_us = 0;
    context->released_since_us = 0;
    volatile EspFlash *target = chip;
    target->os_functions = MAIN_FLASH_OS_FUNCTIONS;
    target->os_context = (FlashOsContext *)context;
    return 0;
}
