/* Medius v3.4.7 host: flash callbacks used without the application OS hooks. */
#include "../include/types.h"

/* Native entry: 0x4037d278. */
/* Original function-byte SHA-256:
 * 4d4121599a0292f3f22c6b680344007ab1f1827c2892036b7d0b1121a5928b82. */
/* Ignore context, forward the full unsigned microsecond WORD to ROM delay
 *0x40000600, then return0. No scheduler sleep, timeout check or error handling. */
int flash_no_os_delay_us(void *unused_context,unsigned int microseconds)
{
    (void)unused_context;
    esp_rom_delay_us(microseconds);
    return 0;
}

/* Native entry: 0x4037d288. */
/* Original function-byte SHA-256:
 * 2a7a31145e33e3145adc8ba212c82190ffce939de66bb88fb34a4c3de4bfe4f3. */
/* Ignore context; resume external cache level1/ALL2, then return0. This
 * wrapper does not restore interrupts/scheduling or release an OS lock. Saved
 * autoload state and register operations belong to the already reviewed HAL. */
int flash_no_os_end(FlashOsContext *unused_context)
{
    (void)unused_context;
    cache_hal_resume(1,CACHE_TYPE_ALL);
    return 0;
}

/* Native entry: 0x4037d29c. */
/* Original function-byte SHA-256:
 * e9224686e5164b9bb9d5fc82753925e32cd2bc4da52fac909dcee5c8ac6e721d. */
/* Ignore context; suspend external cache level1/ALL2, then return0. No local
 * interrupt masking, scheduler exclusion, mutex, nesting or status validation.
 * Cache state saving and hardware polling are delegated to the reviewed HAL. */
int flash_no_os_start(FlashOsContext *unused_context)
{
    (void)unused_context;
    cache_hal_suspend(1,CACHE_TYPE_ALL);
    return 0;
}
