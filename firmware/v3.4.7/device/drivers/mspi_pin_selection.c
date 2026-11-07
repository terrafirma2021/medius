/* Medius v3.4.7 device: MSPI/PSRAM pin selection and reservation. */
#include "../include/types.h"

/* Inline reconstruction utilities retain native register barriers and do not
 * add firmware entry points. */
static __inline__ __attribute__((always_inline)) void mspi_pin_selection_barrier(void)
{
    __asm__ volatile ("memw" ::: "memory");
}

/* Native entry: 0x403857a8. */
/* Original function-byte SHA-256:
 * 46f73d42b28fcbdb38d9a5ced2bda8fc59bdac9359d3047214affc5b09fcd061. */
/* Read the current PSRAM CS pin byte at0x3fcaa7b0 and zero-extend it. No
 * initialization, pin-range validation, lock or register barrier is supplied. */
unsigned char esp_psram_impl_get_cs_io(void)
{
    return *(const volatile unsigned char *)0x3fcaa7b0U;
}

/* Native entry: 0x420083c0. */
/* Original function-byte SHA-256:
 * 37d6d192d33a2c1c6d6c717e349be3c42c16de7c148bb5fb2b740803b6faddb5. */
/* Forward to implementation-specific PSRAM CS pin getter. Return its byte;
 * no local validation, fallback selection, state read or synchronization. */
unsigned char esp_psram_io_get_cs_io(void)
{
    return esp_psram_impl_get_cs_io();
}

/* Native entry: 0x4201065c. */
/* Original function-byte SHA-256:
 * 55f0b9263573cb28610abdbef6defb92db32296ca6ae99e9c48cba3a67edc684. */
/* Select a pin for CLK0,MISO1,MOSI2,CS0=3,HD4,WP5,DQS6,D4=7..D7=10,CS1=11.
 * CS1 bypasses validation and returns PSRAM getter. Other indices>10 assert.
 * WP uses ROM WP value masked63, except exact0x3f falls back to GPIO28.
 * Indices0..4 use ROM SPI config;6..10 use OPI eFuse config. A zero config
 * selects the linked default byte table at0x3c046800:30,31,32,29,27,28,37,
 * 33,34,35,36. Otherwise extract the index's6-bit pin. Preserve native shift
 * count modulo32. No selected-pin validity/reservation or hardware change. */
unsigned char esp_mspi_get_io(unsigned int signal_role)
{
    if (signal_role == 11)
        return esp_psram_io_get_cs_io();
    if (signal_role > 10)
        __assert_func(NULL,0,NULL,NULL);
    if (signal_role == 5) {
        unsigned int pin = esp_rom_efuse_get_flash_wp_gpio();
        return pin == 0x3fU ? 28 : (unsigned char)(pin & 0x3fU);
    }
    unsigned int config;
    if (signal_role < 5) {
        config = esp_rom_efuse_get_flash_gpio_info();
        if (config != 0)
            return (unsigned char)((config >> ((signal_role * 6U) & 31U)) & 0x3fU);
    } else {
        config = esp_rom_efuse_get_opiconfig();
        if (config != 0)
            return (unsigned char)((config >> ((signal_role * 6U - 36U) & 31U)) & 0x3fU);
    }
    return MSPI_DEFAULT_PINS[signal_role];
}

/* Native entry: 0x420106e0. */
/* Original function-byte SHA-256:
 * 7551828e29c92ad5456acec4323d17dde19be4f0a8a51a4e8f52974d22f2e849. */
/* Walk all12 MSPI roles. Reread octal eFuse flag for EVERY role, skipping
 * DQS/D4..D7 indices6..10 when clear. Query pin, form bit1<<(pin&31), select
 * low/high mask by pin bit5 and accumulate only if pin<=63. Duplicate pins
 * collapse; an invalid pin contributes nothing. Call GPIO reserve once with
 * combined64-bit mask and discard its return. No own lock or pin remux. */
void esp_mspi_pin_reserve(void)
{
    unsigned int low = 0;
    unsigned int high = 0;
    for (unsigned int signal_role = 0; signal_role < 12; ++signal_role) {
        bool octal = bootloader_flash_is_octal_mode_enabled();
        if (!octal && signal_role - 6U < 5U)
            continue;
        unsigned int pin = esp_mspi_get_io(signal_role);
        unsigned int bit = 1U << (pin & 31U);
        unsigned int low_bit = (pin & 32U) == 0 ? bit : 0;
        unsigned int high_bit = (pin & 32U) != 0 ? bit : 0;
        if (pin <= 63) {
            low |= low_bit;
            high |= high_bit;
        }
    }
    (void)esp_gpio_reserve(((unsigned long long)high << 32) | low);
}

/* Native entry: 0x420111b8. */
/* Original function-byte SHA-256:
 * 8362d611d95db90cf0b7b82dc07016dd09aabcca4c54c4c324e480fedad14c04. */
/* MEMW/read eFuse MAC_SPI_SYS2 then MEMW/read SYS3. Pack DQS,D4,D5,D6,D7
 * six-bit pin fields into30 bits: low>>20 | (high&0x3ffff)<<12. Return0 for
 * both all-zero and all-one fields; otherwise return packed config. No eFuse
 * refresh/burn, error flag check, lock or per-pin validity check. */
unsigned int esp_rom_efuse_get_opiconfig(void)
{
    mspi_pin_selection_barrier();
    unsigned int low = *(const volatile unsigned int *)0x6000704cU;
    mspi_pin_selection_barrier();
    unsigned int high = *(const volatile unsigned int *)0x60007050U;
    unsigned int config = (low >> 20) | ((high & 0x3ffffU) << 12);
    if (config == 0 || config == 0x3fffffffU)
        return 0;
    return config;
}
