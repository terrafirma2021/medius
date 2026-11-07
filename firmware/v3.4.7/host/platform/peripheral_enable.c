/* Medius v3.4.7 host — legacy peripheral clock/reset masks and enable.
 * SDK identities: esp_hw_support/periph_ctrl.c and hal/esp32s3/clk_gate_ll.h.
 * Register selection and masks are checked against the native instructions.
 */
#include "../include/types.h"

/* Peripheral reconstruction utilities: register selection inlines into enable;
 * this helper is not an additional native function.
 */
static __attribute__((always_inline)) inline PeripheralRegisterPair
peripheral_registers(unsigned int module)
{
    switch (module) {
    case PERIPH_DEDIC_GPIO_MODULE:
        return (PeripheralRegisterPair){(volatile unsigned int *)0x600c0008U,
            (volatile unsigned int *)0x600c000cU};
    case PERIPH_RNG_MODULE: case PERIPH_WIFI_MODULE: case PERIPH_BT_MODULE:
    case PERIPH_WIFI_BT_COMMON_MODULE: case PERIPH_BT_BASEBAND_MODULE: case PERIPH_BT_LC_MODULE:
        return (PeripheralRegisterPair){(volatile unsigned int *)0x60026014U,
            (volatile unsigned int *)0x60026018U};
    case PERIPH_UART2_MODULE: case PERIPH_SDMMC_MODULE: case PERIPH_LCD_CAM_MODULE:
    case PERIPH_GDMA_MODULE: case PERIPH_HMAC_MODULE: case PERIPH_DS_MODULE:
    case PERIPH_AES_MODULE: case PERIPH_SHA_MODULE: case PERIPH_RSA_MODULE:
        return (PeripheralRegisterPair){&SYSTEM_PERIPHERAL_REGISTERS->clock_enable1,
            &SYSTEM_PERIPHERAL_REGISTERS->reset_enable1};
    default:
        return (PeripheralRegisterPair){&SYSTEM_PERIPHERAL_REGISTERS->clock_enable0,
            &SYSTEM_PERIPHERAL_REGISTERS->reset_enable0};
    }
}

/* Native entry: 0x42004990. */
/* Original function-byte SHA-256:
 * e9650c576f657f0fb6e31979e0c910db1c90802916c8f0c81c2c56570fe3bba6. */
/* Return the clock-enable mask WORD for the raw peripheral ID.
 * Pure lookup: no register access, validation, synchronization or side effects.
 * Different modules can use the same bit in DIFFERENT register banks; callers
 * must select the matching bank separately. PWM2/3, WIFI, BT, temperature and
 * PHY-calibration IDs have no clock mask in this specialized native entry;
 * unsupported IDs, including all unsigned values>=42, return0. The combined
 * WiFi/BT module does have mask0x0078078f. Do not invent enable bits for IDs
 * whose native path returns zero.
 */
unsigned int periph_ll_get_clk_en_mask(unsigned int module)
{
    switch (module) {
    case PERIPH_LEDC_MODULE: return 0x800U;
    case PERIPH_UART0_MODULE: return 0x4U;
    case PERIPH_UART1_MODULE: return 0x20U;
    case PERIPH_UART2_MODULE: return 0x200U;
    case PERIPH_USB_MODULE: return 0x800000U;
    case PERIPH_I2C0_MODULE: return 0x80U;
    case PERIPH_I2C1_MODULE: return 0x40000U;
    case PERIPH_I2S0_MODULE: return 0x10U;
    case PERIPH_I2S1_MODULE: return 0x200000U;
    case PERIPH_LCD_CAM_MODULE: return 0x100U;
    case PERIPH_TIMG0_MODULE: return 0x2000U;
    case PERIPH_TIMG1_MODULE: return 0x8000U;
    case PERIPH_PWM0_MODULE: return 0x20000U;
    case PERIPH_PWM1_MODULE: return 0x100000U;
    case PERIPH_UHCI0_MODULE: return 0x100U;
    case PERIPH_UHCI1_MODULE: return 0x1000U;
    case PERIPH_RMT_MODULE: return 0x200U;
    case PERIPH_PCNT_MODULE: return 0x400U;
    case PERIPH_SPI_MODULE: return 0x2U;
    case PERIPH_SPI2_MODULE: return 0x40U;
    case PERIPH_SPI3_MODULE: return 0x10000U;
    case PERIPH_SDMMC_MODULE: return 0x80U;
    case PERIPH_TWAI_MODULE: return 0x80000U;
    case PERIPH_RNG_MODULE: return 0x8000U;
    case PERIPH_WIFI_BT_COMMON_MODULE: return 0x78078fU;
    case PERIPH_BT_BASEBAND_MODULE: return 0x800U;
    case PERIPH_BT_LC_MODULE: return 0x30000U;
    case PERIPH_AES_MODULE: return 0x2U;
    case PERIPH_SHA_MODULE: return 0x4U;
    case PERIPH_HMAC_MODULE: return 0x20U;
    case PERIPH_DS_MODULE: return 0x10U;
    case PERIPH_RSA_MODULE: return 0x8U;
    case PERIPH_SYSTIMER_MODULE: return 0x20000000U;
    case PERIPH_GDMA_MODULE: return 0x40U;
    case PERIPH_DEDIC_GPIO_MODULE: return 0x80U;
    case PERIPH_SARADC_MODULE: return 0x10000000U;
    default: return 0;
    }
}

/* Native entry: 0x42004b24. */
/* Original function-byte SHA-256:
 * 64b9cf587fd41d23713e97c28da577fa0593829a3908444adc8cfd9ae871fa21. */
/* Return the reset mask WORD for a raw peripheral ID and enable WORD.
 * Zero enable returns the unit-only reset mask; any nonzero enable also clears
 * dependent units for AES (0x12), SHA (0x34), and RSA (0x18). Other supported
 * masks ignore enable. WIFI uses0x4 and BT uses0x3e08, while RNG, combined
 * WiFi/BT, BT baseband/LC, PWM2/3, temperature, PHY-calibration and unsupported
 * IDs return0. This is a pure lookup, not a hardware reset or enable operation;
 * caller must select the correct register bank and choose set versus clear.
 */
unsigned int periph_ll_get_rst_en_mask(unsigned int module,unsigned int enable)
{
    switch (module) {
    case PERIPH_LEDC_MODULE: return 0x800U;
    case PERIPH_UART0_MODULE: return 0x4U;
    case PERIPH_UART1_MODULE: return 0x20U;
    case PERIPH_UART2_MODULE: return 0x200U;
    case PERIPH_USB_MODULE: return 0x800000U;
    case PERIPH_I2C0_MODULE: return 0x80U;
    case PERIPH_I2C1_MODULE: return 0x40000U;
    case PERIPH_I2S0_MODULE: return 0x10U;
    case PERIPH_I2S1_MODULE: return 0x200000U;
    case PERIPH_LCD_CAM_MODULE: return 0x100U;
    case PERIPH_TIMG0_MODULE: return 0x2000U;
    case PERIPH_TIMG1_MODULE: return 0x8000U;
    case PERIPH_PWM0_MODULE: return 0x20000U;
    case PERIPH_PWM1_MODULE: return 0x100000U;
    case PERIPH_UHCI0_MODULE: return 0x100U;
    case PERIPH_UHCI1_MODULE: return 0x1000U;
    case PERIPH_RMT_MODULE: return 0x200U;
    case PERIPH_PCNT_MODULE: return 0x400U;
    case PERIPH_SPI_MODULE: return 0x2U;
    case PERIPH_SPI2_MODULE: return 0x40U;
    case PERIPH_SPI3_MODULE: return 0x10000U;
    case PERIPH_SDMMC_MODULE: return 0x80U;
    case PERIPH_TWAI_MODULE: return 0x80000U;
    case PERIPH_WIFI_MODULE: return 0x4U;
    case PERIPH_BT_MODULE: return 0x3e08U;
    case PERIPH_AES_MODULE: return enable != 0 ? 0x12U : 0x2U;
    case PERIPH_SHA_MODULE: return enable != 0 ? 0x34U : 0x4U;
    case PERIPH_HMAC_MODULE: return 0x20U;
    case PERIPH_DS_MODULE: return 0x10U;
    case PERIPH_RSA_MODULE: return enable != 0 ? 0x18U : 0x8U;
    case PERIPH_SYSTIMER_MODULE: return 0x20000000U;
    case PERIPH_GDMA_MODULE: return 0x40U;
    case PERIPH_DEDIC_GPIO_MODULE: return 0x80U;
    case PERIPH_SARADC_MODULE: return 0x10000000U;
    default: return 0;
    }
}

/* Native entry: 0x42004cf0. */
/* Original function-byte SHA-256:
 * 26b12d50f0e476da3fc446af17d1450a52648c3b890d18ea59714b799c76f83b. */
/* Acquire one legacy peripheral reference. Assert on module>=42 before
 * touching the lock or counter. Query ISR context, then call the common
 * critical-enter boundary with timeout WORD0xffffffff; both results are
 * ignored. Read the current reference BYTE once. Only when it is zero, select
 * the module's register pair and perform two ordered RMWs: MEMW/read clock,
 * call clock-mask helper, MEMW/write OR; then MEMW/read reset, call reset-mask
 * helper(module,1), MEMW/write AND-complement. Registers are touched even when
 * a valid module has a zero mask. In particular, RNG selects the WiFi/core bank
 * and its reset mask is zero, so the reset WORD is still read/written unchanged.
 *
 * Store low8(cached_reference+1), query ISR context again, then exit the SAME
 * critical section. Counts wrap255->0 without saturation; that next zero can
 * cause another hardware-enable sequence. No count reload after the hardware
 * calls, status return, readiness wait, driver initialization or rollback.
 * Concurrent users rely on the existing common spinlock/critical API.
 */
void periph_module_enable(unsigned int module)
{
    if (module >= PERIPH_MODULE_MAX)
        __assert_func(NULL,0,NULL,NULL);
    (void)xPortInIsrContext();
    (void)xPortEnterCriticalTimeout(PERIPHERAL_RCC_LOCK,-1);
    unsigned char references = PERIPHERAL_REFERENCES[module];
    if (references == 0) {
        PeripheralRegisterPair registers = peripheral_registers(module);
        memw();
        unsigned int value = *registers.clock;
        unsigned int mask = periph_ll_get_clk_en_mask(module);
        memw();
        *registers.clock = value | mask;
        memw();
        value = *registers.reset;
        mask = periph_ll_get_rst_en_mask(module,1);
        memw();
        *registers.reset = value & ~mask;
    }
    PERIPHERAL_REFERENCES[module] = (unsigned char)(references + 1U);
    (void)xPortInIsrContext();
    vPortExitCritical(PERIPHERAL_RCC_LOCK);
}
