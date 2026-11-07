/* Medius v3.4.7 host: mapped-flash cache maintenance and startup dispatch. */
#include "../include/types.h"

/* Inline reconstruction utilities preserve the explicit eFuse read barrier;
 * this helper is not an additional firmware entry. */
static __inline__ __attribute__((always_inline)) void flash_support_barrier(void)
{
    __asm__ volatile ("memw" ::: "memory");
}

/* Native entry: 0x4037c280. */
/* Original function-byte SHA-256:
 * 7d7aa2c5c7a6c39e36bdeaa1ac49d080ad8e2b2163e6c5db3d32e86dbfee84fa. */
/* MEMW, read eFuse shadow WORD0x6000703c and return FLASH_TYPE bit9 as bool:
 * 0 means four flash lines,1 eight. No cached value, polling, validation or lock. */
bool bootloader_flash_is_octal_mode_enabled(void)
{
    flash_support_barrier();
    unsigned int shadow = *(const volatile unsigned int *)0x6000703cU;
    return ((shadow >> 9) & 1U) != 0;
}

/* Native entry: 0x4037c5a8. */
/* Original function-byte SHA-256:
 * 6962c593658869b632817cdd7ec5950258cf3c3d03921252f3d34f262c56a326. */
/* Compiled no-OS restoration wrapper only calls spi_flash_restore_cache.
 * No used parameters, local interrupt enable, scheduler restore or status. */
void spi_flash_enable_interrupts_caches_no_os(void)
{
    spi_flash_restore_cache();
}

/* Native entry: 0x4037c5c4. */
/* Original function-byte SHA-256:
 * d901843213c8b71aa446fa7c8334796c2b8c83a0be8d0fbf06319d67293fee0e. */
/* First store output0 and initialize local caps0. Query tracked physical-page
 * capabilities; on error returnfalse with output0. On success initialize local
 * vaddr0 and ask MMU0 for FLASH target1, INST type2 if EXEC bit0 is set, DATA
 * type1 otherwise. Ignore the HAL result, copy local vaddr and returntrue even
 * when no hardware entry was found (local stays0). No output NULL check, target
 * filter in the allocator lookup, own lock or cleanup. Output must be writable. */
bool flash_page_is_mapped(unsigned int physical_address,unsigned int *virtual_address)
{
    *virtual_address = 0;
    volatile unsigned int caps = 0;
    int status = esp_mmu_paddr_find_caps(physical_address,(unsigned int *)&caps);
    if (status != 0)
        return false;
    unsigned int capabilities = caps;
    volatile unsigned int mapped = (unsigned int)status;
    unsigned int type = (capabilities & 1U) != 0 ? 2U : 1U;
    (void)mmu_hal_paddr_to_vaddr(0,physical_address,1,type,(unsigned int *)&mapped);
    *virtual_address = mapped;
    return true;
}

/* Native entry: 0x4037c60c. */
/* Original function-byte SHA-256:
 * 3db2a7c3bb8eb41673878e7f4952390604018e1989f960429e3292dc995b9a26. */
/* Cover the requested bytes with64KiB pages, rounding with native unsigned32
 * arithmetic. For each page reread ROM legacy pointer/chip size; page>=size
 * immediately returnsfalse, overriding an earlier successful invalidation.
 * For a tracked page with nonzero hardware alias enter cache-sync critical
 * section, invalidate exactly64KiB, discard its status and exit. Returntrue
 * if any page was invalidated and no later out-of-size page occurred. Empty
 * or wrapping computed intervals returnfalse; size0 at unaligned start can
 * still cover one page. No own allocator lock or timeout; callbacks may abort. */
bool spi_flash_check_and_flush_cache(size_t start_address,size_t length)
{
    unsigned int page = start_address & 0xffff0000U;
    unsigned int end = page + ((length + 0xffffU + start_address - page) & 0xffff0000U);
    bool flushed = false;
    while (page < end) {
        volatile RomFlashLegacy *legacy = ROM_FLASH_LEGACY;
        if (page >= legacy->chip.chip_size)
            return false;
        volatile unsigned int mapped;
        bool found = flash_page_is_mapped(page,(unsigned int *)&mapped);
        if (found) {
            unsigned int address = mapped;
            volatile unsigned int saved_address = address;
            if (address != 0) {
                esp_cache_sync_ops_enter_critical_section();
                (void)cache_hal_invalidate_addr(saved_address,0x10000U);
                esp_cache_sync_ops_exit_critical_section();
                flushed = found;
            }
        }
        page += 0x10000U;
    }
    return flushed;
}

/* Native entry: 0x4037c668. */
/* Original function-byte SHA-256:
 * 54640dca4463a46bb168b675aeca7a3434b5062c0de53e591caf23d9cbbe0450. */
/* Replace guard-table pointer at0x3fccbb70 with one WORD store. Accept NULL;
 * no table copy, callback call, ownership, explicit barrier or synchronization. */
void spi_flash_guard_set(const FlashGuardFunctions *functions)
{
    FLASH_GUARD = functions;
}

/* Native entry: 0x4037c674. */
/* Original function-byte SHA-256:
 * 01f030ac7411b4834970e29cf46e220930f7a7b99a64a7f2c2b0476aae1f33f0. */
/* Read octal eFuse flag once. If set call ROM pin configuration0x40000894,
 * then set MSPI pad drive strength3. Quad mode does nothing. No result,
 * chip probe, pin reservation or call-site error handling is supplied. */
void esp_mspi_pin_init(void)
{
    if (bootloader_flash_is_octal_mode_enabled()) {
        esp_rom_opiflash_pin_config();
        mspi_set_all_pin_drive_3();
    }
}

/* Native entry: 0x4037c68c. */
/* Original function-byte SHA-256:
 * 035e2de43def108070bb52129d3bbd29fe6c4567f463cd707180d71f665bc524. */
/* Read octal eFuse flag. In octal mode reread the ROM legacy pointer/device ID
 * and return the octal-init result. Otherwise return the high-performance-mode
 * initializer result (the compiled callee here is a return0 stub). No own
 * validation, locking, mode change, error translation or additional cleanup. */
int spi_flash_init_chip_state(void)
{
    if (bootloader_flash_is_octal_mode_enabled()) {
        const volatile RomFlashLegacy *legacy = ROM_FLASH_LEGACY;
        return esp_opiflash_init(legacy->chip.device_id);
    }
    return spi_flash_enable_high_performance_mode();
}

/* Native entry: 0x4038d33c. */
/* Original function-byte SHA-256:
 * 92c9598ac7519d458b9e367d0d7b28064c9bff38bae50b088825d1dda27f16a4. */
/* Compiled HPM-disabled specialization: return ESP_OK0 without reading any
 * state or configuring hardware. No used parameters or side effects. */
int spi_flash_enable_high_performance_mode(void)
{
    return 0;
}

/* Native entry: 0x4037c454. */
/* Original function-byte SHA-256:
 * 0d79190451531c76823598f7764e300213e3c73eaa2d9197b265b1fca8fadc2c. */
/* Forward directly to external-memory cache suspension. No used parameters,
 * local status, lock, interrupt masking or saved-state output in this body. */
void flash_suspend_cache(void)
{
    esp_cache_suspend_ext_mem_cache();
}

/* Native entry: 0x4037c464. */
/* Original function-byte SHA-256:
 * 0d79190451531c76823598f7764e300213e3c73eaa2d9197b265b1fca8fadc2c. */
/* Forward directly to external-memory cache resumption. The callee uses saved
 * HAL autoload state; this wrapper restores no interrupts or scheduler state. */
void flash_resume_cache(void)
{
    esp_cache_resume_ext_mem_cache();
}
