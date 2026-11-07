/* Medius v3.4.7 device: flash callbacks used without application OS hooks. */
#include "../include/types.h"

/* Native entry: 0x4037eb10. */
/* Original function-byte SHA-256:
 * 8a09440c7ee3d9470999037899926130db2cf3205a8e99c42d9895de4896d1e2. */
/* Ignore context, forward the full unsigned microsecond WORD to ROM delay
 *0x40000600, then return0. No scheduler sleep, timeout check or error handling. */
int flash_no_os_delay_us(void *unused_context,unsigned int microseconds)
{
    (void)unused_context;
    esp_rom_delay_us(microseconds);
    return 0;
}

/* Native entry: 0x4037eb20. */
/* Original function-byte SHA-256:
 * 17e2081483bd12d29bf14ac1585f11fda70038dd9b2f52dca7b89afb1cffb52a. */
/* Ignore context; resume external cache level1/ALL2, then return0. This
 * wrapper does not restore interrupts/scheduling or release an OS lock. Saved
 * autoload state and register operations belong to the already reviewed HAL. */
int flash_no_os_end(FlashOsContext *unused_context)
{
    (void)unused_context;
    cache_hal_resume(1,CACHE_TYPE_ALL);
    return 0;
}

/* Native entry: 0x4037eb34. */
/* Original function-byte SHA-256:
 * 2bf77d6196a7eb0ec7f234f7c53adf77d619ca6568f7a440a54555454c720f28. */
/* Ignore context; suspend external cache level1/ALL2, then return0. No local
 * interrupt masking, scheduler exclusion, mutex, nesting or status validation.
 * Cache state saving and hardware polling are delegated to the reviewed HAL. */
int flash_no_os_start(FlashOsContext *unused_context)
{
    (void)unused_context;
    cache_hal_suspend(1,CACHE_TYPE_ALL);
    return 0;
}
