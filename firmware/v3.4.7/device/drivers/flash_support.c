/* Medius v3.4.7 device: mapped-flash cache maintenance and startup dispatch. */
#include "../include/types.h"

/* Inline reconstruction utilities preserve the explicit eFuse read barrier;
 * this helper is not an additional firmware entry. */
static __inline__ __attribute__((always_inline)) void flash_support_barrier(void)
{
    __asm__ volatile ("memw" ::: "memory");
}

/* Native entry: 0x4037db18. */
/* Original function-byte SHA-256:
 * db4dd776d1c3a4f3f09eb8f6b3469706268a630b5047aaf8660fa10e1ece2915. */
/* MEMW, read eFuse shadow WORD0x6000703c and return FLASH_TYPE bit9 as bool:
 * 0 means four flash lines,1 eight. No cached value, polling, validation or lock. */
bool bootloader_flash_is_octal_mode_enabled(void)
{
    flash_support_barrier();
    unsigned int shadow = *(const volatile unsigned int *)0x6000703cU;
    return ((shadow >> 9) & 1U) != 0;
}

/* Native entry: 0x4037de40. */
/* Original function-byte SHA-256:
 * 6962c593658869b632817cdd7ec5950258cf3c3d03921252f3d34f262c56a326. */
/* Compiled no-OS restoration wrapper only calls spi_flash_restore_cache.
 * No used parameters, local interrupt enable, scheduler restore or status. */
void spi_flash_enable_interrupts_caches_no_os(void)
{
    spi_flash_restore_cache();
}

/* Native entry: 0x4037de5c. */
/* Original function-byte SHA-256:
 * fdf5de8de3c7023b09d7d21897f1ac679b14d26149bcf65e8e740d8eaaf1f212. */
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

/* Native entry: 0x4037dea4. */
/* Original function-byte SHA-256:
 * d5d75f9b6cf501592ff3495b543d9fd3842bfe5c298ba88ac5a5a0327f0477b9. */
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

/* Native entry: 0x4037df00. */
/* Original function-byte SHA-256:
 * ac77edd48a304ab01ab6174d4d761a8740e34dc1c194f80977424fbcfa62b236. */
/* Replace guard-table pointer at0x3fcd8660 with one WORD store. Accept NULL;
 * no table copy, callback call, ownership, explicit barrier or synchronization. */
void spi_flash_guard_set(const FlashGuardFunctions *functions)
{
    FLASH_GUARD = functions;
}

/* Native entry: 0x4037df0c. */
/* Original function-byte SHA-256:
 * efd77fbd022c76ced824a7d0fce1a3e9df632bc2cb1453fb6bdcc610e0ed73a1. */
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

/* Native entry: 0x4037df24. */
/* Original function-byte SHA-256:
 * 7032b552b500f266de71b9c64ff20690c70d8b1a1d4cdda624a2bce0d56ac4dd. */
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

/* Native entry: 0x40391574. */
/* Original function-byte SHA-256:
 * 92c9598ac7519d458b9e367d0d7b28064c9bff38bae50b088825d1dda27f16a4. */
/* Compiled HPM-disabled specialization: return ESP_OK0 without reading any
 * state or configuring hardware. No used parameters or side effects. */
int spi_flash_enable_high_performance_mode(void)
{
    return 0;
}
