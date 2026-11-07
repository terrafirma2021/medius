/* Medius v3.4.7 host: MSPI pin selection and reservation. */
#include "../include/types.h"

/* Inline reconstruction utilities retain native register barriers and do not
 * add firmware entry points. */
static __inline__ __attribute__((always_inline)) void mspi_pin_selection_barrier(void)
{
    __asm__ volatile ("memw" ::: "memory");
}

/* Native entry: 0x42012988. */
/* Original function-byte SHA-256:
 * 902738149958c3b38e97ef9a85156b4255daa6a12476292ab0d8934a793c7060. */
/* Select a pin for CLK0,MISO1,MOSI2,CS0=3,HD4,WP5,DQS6,D4=7..D7=10.
 * This host build has no CS1 role: all indices>10 assert.
 * WP uses ROM WP value masked63, except exact0x3f falls back to GPIO28.
 * Indices0..4 use ROM SPI config;6..10 use OPI eFuse config. A zero config
 * selects the linked default byte table at0x3c050f1c:30,31,32,29,27,28,37,
 * 33,34,35,36. Otherwise extract the index's6-bit pin. Preserve native shift
 * count modulo32. No selected-pin validity/reservation or hardware change. */
unsigned char esp_mspi_get_io(unsigned int io)
{
    if (io > 10)
        __assert_func(NULL,0,NULL,NULL);
    if (io == 5) {
        unsigned int pin = esp_rom_efuse_get_flash_wp_gpio();
        return pin == 0x3fU ? 28 : (unsigned char)(pin & 0x3fU);
    }
    unsigned int config;
    if (io < 5) {
        config = esp_rom_efuse_get_flash_gpio_info();
        if (config != 0)
            return (unsigned char)((config >> ((io * 6U) & 31U)) & 0x3fU);
    } else {
        config = esp_rom_efuse_get_opiconfig();
        if (config != 0)
            return (unsigned char)((config >> ((io * 6U - 36U) & 31U)) & 0x3fU);
    }
    return MSPI_DEFAULT_PINS[io];
}

/* Native entry: 0x42012a00. */
/* Original function-byte SHA-256:
 * c969e1e3d4434e226851129e5b0ee6cfcb54bde48145c03539c56123505e442c. */
/* Walk all11 MSPI roles. Reread octal eFuse flag for EVERY role, skipping
 * DQS/D4..D7 indices6..10 when clear. Query pin, form bit1<<(pin&31), select
 * low/high mask by pin bit5 and accumulate only if pin<=63. Duplicate pins
 * collapse; an invalid pin contributes nothing. Call GPIO reserve once with
 * combined64-bit mask and discard its return. No own lock or pin remux. */
void esp_mspi_pin_reserve(void)
{
    unsigned int low = 0;
    unsigned int high = 0;
    for (unsigned int io = 0; io < 11; ++io) {
        bool octal = bootloader_flash_is_octal_mode_enabled();
        if (!octal && io - 6U < 5U)
            continue;
        unsigned int pin = esp_mspi_get_io(io);
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

/* Native entry: 0x42013508. */
/* Original function-byte SHA-256:
 * dc094e1419b2cc1d5a33047215962d1a5a85d0a8bc0bc234239be8129feae541. */
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
