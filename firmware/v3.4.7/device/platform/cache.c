/* Medius v3.4.7 device: recovered platform/cache.c.
 * Native entry addresses and firmware-byte hashes are retained.
 */

#include "../include/types.h"

/* Native entry: 0x4037de48. */
/* Original function-byte SHA-256:
 * 9160d44f908f604f328678efc48a284b252ddb9c86180a2eb871a9d60c128b8e. */

/*
 * No parameters. Returns the cache HAL result for external-memory level1 and
 * ALL(2), requiring data and instruction cache enabled. No local read/write,
 * lock or validation. Native six-instruction wrapper matches ESP-IDF's
 * spi_flash_cache_enabled; actual fences and register reads belong to its HAL.
 */
bool spi_flash_cache_enabled(void)
{
    return cache_hal_is_cache_enabled(1, CACHE_TYPE_ALL);
}

/* Native entry: 0x40389254. */
/* Original function-byte SHA-256:
 * 1fc31469c758beb29387c21b4a7ba51db3c7cad9997a3c0bca724983c28fe51a. */

/*
 * cache_level: unused by this ESP32-S3 specialization. type: DATA(0) reads
 * DCACHE_ENABLE; INSTRUCTION(1) reads ICACHE_ENABLE; every other value requires
 * both, short-circuiting when data cache disabled. Fences before each actual
 * register read. Returns bit0 normalized as bool; no writes, locks or cache
 * maintenance. Register enable bits alone do not prove address validity or
 * completion of cache/flash operations. Matches pinned ESP-IDF cache_hal.c and
 * ESP32-S3 cache_ll.h; native addresses/bits verified against extmem_reg.h.
 */
bool cache_hal_is_cache_enabled(unsigned int cache_level, CacheType type)
{
    (void)cache_level;
    if (type == CACHE_TYPE_DATA) {
        memw();
        return (EXTMEM_CACHE->dcache_ctrl & 1U) != 0;
    }
    if (type != CACHE_TYPE_INSTRUCTION) {
        memw();
        if ((EXTMEM_CACHE->dcache_ctrl & 1U) == 0)
            return false;
    }
    memw();
    return (EXTMEM_CACHE->icache_ctrl & 1U) != 0;
}
