/* Medius v3.4.7 device — drivers/gpio.c.
 * Recovered C and native assembly, grouped for source navigation.
 * Original entry addresses, firmware-byte hashes and function comments follow.
 */

#include "../include/types.h"


/* reconstruction utilities: the mask-only sleep helpers omit the signed
 * rejection used by other APIs. All unchecked address calculations wrap at
 * 32 bits; do not infer array bounds for the native pin/signal aliases. */
static __inline__ __attribute__((always_inline)) int gpio_mask_allows(unsigned int pin)
{
    unsigned int index = pin & 63U;
    return index <= 21U || (index >= 26U && index <= 48U);
}
static __inline__ __attribute__((always_inline)) volatile unsigned int *
gpio_iomux_table_register(unsigned int pin)
{
    unsigned int slot = (unsigned int)(uintptr_t)GPIO_IOMUX_TABLE + pin * 4U;
    return *(volatile unsigned int * const *)(uintptr_t)slot;
}
static __inline__ __attribute__((always_inline)) volatile unsigned int *
gpio_direct_iomux_register(unsigned int pin)
{
    return (volatile unsigned int *)(uintptr_t)(0x60009004U + pin * 4U);
}
static __inline__ __attribute__((always_inline)) volatile unsigned int *
gpio_route_register(GpioRegisters *device,unsigned int offset,unsigned int index)
{
    return (volatile unsigned int *)(uintptr_t)
        ((unsigned int)(uintptr_t)device + offset + index * 4U);
}

/* Native entry: 0x4200d250. */
/* Original function-byte SHA-256:
 * 9f46ab00c8022517a3277b082b3de667c487dc91f149f91e5a0a3551b92ef1ad. */
/* UINT_MAX is an unconnected pin and succeeds without calls. Otherwise use
 * the native signed/six-bit GPIO mask, retaining positive>=64 aliases. Select
 * its GPIO pad, connect output with both inversion flags0, then unhold.
 * Invalid pins log and return102; signal index is not checked. No rollback,
 * explicit output-enable operation or hardware-completion wait is added. */
unsigned int phy_configure_pin_output(unsigned int pin,unsigned int signal)
{
    if (pin == 0xffffffffU) return 0;
    if (gpio_native_pin_valid(pin)) {
        gpio_pad_select_gpio(pin);
        gpio_matrix_out(pin,signal,0,0);
        gpio_pad_unhold(pin);
        return 0;
    }
    unsigned int timestamp = esp_log_timestamp();
    esp_log_write(1,"usb_phy","E (%lu) %s: %s(%d): io_num argument is invalid\n",timestamp,"usb_phy",
                  "phy_configure_pin_output",84);
    return 0x102;
}

/* Native entry: 0x4200d9bc. */
/* Original function-byte SHA-256:
 * 2753ccb379befa61d8c1d3a6f992427a8116665a9cd52ca08266559409d3703f. */
/* Clear sleep pull-down bit 2 under the GPIO spinlock.
 * Validate only the native SIX-BIT mask: no signed-negative rejection exists
 * here. Accepted aliases index the FULL pin value in the IO-MUX table, with
 * wrapping address arithmetic. Preserve unrelated bits through one fresh RMW.
 * Invalid pins log and return without a status. No active pull configuration,
 * reservation, readback, timeout or critical-entry error handling is supplied. */
void gpio_sleep_pulldown_dis(unsigned int pin)
{
    if (gpio_mask_allows(pin)) {
        xPortEnterCriticalTimeout(&GPIO_CONFIGURATION_LOCK,-1);
        volatile unsigned int *reg = gpio_iomux_table_register(pin);
        memw();
        unsigned int configuration = *reg;
        memw();
        *reg = configuration & ~ 4U;
        vPortExitCritical(&GPIO_CONFIGURATION_LOCK);
    }
    else {
        unsigned int stamp = esp_log_timestamp();
        esp_log_write(1,"gpio","E (%lu) %s: %s(%d): %s\n",stamp,"gpio","gpio_sleep_pulldown_dis",0x35d,"GPIO number error");
    }
}

/* Native entry: 0x4200da44. */
/* Original function-byte SHA-256:
 * d9d18f57531206964a8faa2cd15a6c136e9b5707b74e72be93435d0fbfcdb267. */
/* Set sleep pull-down bit 2 under the GPIO spinlock.
 * Validate only the native SIX-BIT mask: no signed-negative rejection exists
 * here. Accepted aliases index the FULL pin value in the IO-MUX table, with
 * wrapping address arithmetic. Preserve unrelated bits through one fresh RMW.
 * Invalid pins log and return without a status. No active pull configuration,
 * reservation, readback, timeout or critical-entry error handling is supplied. */
void gpio_sleep_pulldown_en(unsigned int pin)
{
    if (gpio_mask_allows(pin)) {
        xPortEnterCriticalTimeout(&GPIO_CONFIGURATION_LOCK,-1);
        volatile unsigned int *reg = gpio_iomux_table_register(pin);
        memw();
        unsigned int configuration = *reg;
        memw();
        *reg = configuration | 4U;
        vPortExitCritical(&GPIO_CONFIGURATION_LOCK);
    }
    else {
        unsigned int stamp = esp_log_timestamp();
        esp_log_write(1,"gpio","E (%lu) %s: %s(%d): %s\n",stamp,"gpio","gpio_sleep_pulldown_en",0x352,"GPIO number error");
    }
}

/* Native entry: 0x4200dacc. */
/* Original function-byte SHA-256:
 * 397baaba493cb0e26cd5e70e1acb34694d53dc11ba2d56e40e53443ad98123a7. */
/* Clear sleep pull-up bit 3 under the GPIO spinlock.
 * Validate only the native SIX-BIT mask: no signed-negative rejection exists
 * here. Accepted aliases index the FULL pin value in the IO-MUX table, with
 * wrapping address arithmetic. Preserve unrelated bits through one fresh RMW.
 * Invalid pins log and return without a status. No active pull configuration,
 * reservation, readback, timeout or critical-entry error handling is supplied. */
void gpio_sleep_pullup_dis(unsigned int pin)
{
    if (gpio_mask_allows(pin)) {
        xPortEnterCriticalTimeout(&GPIO_CONFIGURATION_LOCK,-1);
        volatile unsigned int *reg = gpio_iomux_table_register(pin);
        memw();
        unsigned int configuration = *reg;
        memw();
        *reg = configuration & ~ 8U;
        vPortExitCritical(&GPIO_CONFIGURATION_LOCK);
    }
    else {
        unsigned int stamp = esp_log_timestamp();
        esp_log_write(1,"gpio","E (%lu) %s: %s(%d): %s\n",stamp,"gpio","gpio_sleep_pullup_dis",0x347,"GPIO number error");
    }
}

/* Native entry: 0x4200db54. */
/* Original function-byte SHA-256:
 * 1574be291be7a9d04186b6351ab36b866d6c8abcf42b7c12fd162921b3e30499. */
/* Set sleep pull-up bit 3 under the GPIO spinlock.
 * Validate only the native SIX-BIT mask: no signed-negative rejection exists
 * here. Accepted aliases index the FULL pin value in the IO-MUX table, with
 * wrapping address arithmetic. Preserve unrelated bits through one fresh RMW.
 * Invalid pins log and return without a status. No active pull configuration,
 * reservation, readback, timeout or critical-entry error handling is supplied. */
void gpio_sleep_pullup_en(unsigned int pin)
{
    if (gpio_mask_allows(pin)) {
        xPortEnterCriticalTimeout(&GPIO_CONFIGURATION_LOCK,-1);
        volatile unsigned int *reg = gpio_iomux_table_register(pin);
        memw();
        unsigned int configuration = *reg;
        memw();
        *reg = configuration | 8U;
        vPortExitCritical(&GPIO_CONFIGURATION_LOCK);
    }
    else {
        unsigned int stamp = esp_log_timestamp();
        esp_log_write(1,"gpio","E (%lu) %s: %s(%d): %s\n",stamp,"gpio","gpio_sleep_pullup_en",0x33c,"GPIO number error");
    }
}

/* Native entry: 0x4200dbdc. */
/* Original function-byte SHA-256:
 * 1461583d1916d45ea6b5a2a67ead0fe819a17af4e8206983315d00579bd12e2d. */
/* Reject pins failing the signed/six-bit GPIO mask, retaining positive
 * >=64 aliases. Call the RTC-pin predicate but ignore its result, then under
 * the GPIO spinlock set IO-MUX pull-up bit 8 using the FULL pin table index.
 * No range repair, RTC-only branch, reservation or readback. Return 0 or log
 * 0x102. The critical-entry result is ignored. */
unsigned int gpio_pullup_en(unsigned int pin)
{
    if (gpio_native_pin_valid(pin)) {
        rtc_gpio_is_valid_gpio((int)pin);
        xPortEnterCriticalTimeout(&GPIO_CONFIGURATION_LOCK,-1);
        volatile unsigned int *reg = gpio_iomux_table_register(pin);
        memw();
        unsigned int configuration = *reg;
        memw();
        *reg = configuration | 0x100U;
        vPortExitCritical(&GPIO_CONFIGURATION_LOCK);
        return 0;
    }
    unsigned int stamp = esp_log_timestamp();
    esp_log_write(1,"gpio","E (%lu) %s: %s(%d): %s\n",stamp,"gpio","gpio_pullup_en",0x55,
        "GPIO number error (input-only pad has no internal PU)");
    return 0x102;
}

/* Native entry: 0x4200dc74. */
/* Original function-byte SHA-256:
 * b9464e4ec85a2a2657b13c3138c53a280b263d669c9f07d265050b15800c9a12. */
/* Validate the signed/six-bit pin mask, then set input-enable bit 9 at
 * 0x60009004+4*pin with wrapping 32-bit address calculation. The FULL pin
 * value is used, including accepted positive>=64 aliases; no IO-MUX table or
 * lock is involved. Return 0, or log and return 0x102 for an invalid pin. */
unsigned int gpio_input_enable(unsigned int pin)
{
    if (gpio_native_pin_valid(pin)) {
        volatile unsigned int *reg = gpio_direct_iomux_register(pin);
        memw();
        unsigned int configuration = *reg;
        memw();
        *reg = configuration | 0x200U;
        return 0;
    }
    unsigned int stamp = esp_log_timestamp();
    esp_log_write(1,"gpio","E (%lu) %s: %s(%d): %s\n",stamp,"gpio","gpio_input_enable",0xd0,"GPIO number error");
    return 0x102;
}

/* Native entry: 0x4200dcf0. */
/* Original function-byte SHA-256:
 * dcec0afc60e730d51cd082bde52c4b5fe5d5d75882ccd38f33e3fa3e9fa597ff. */
/* Validate the signed/six-bit pin mask, then load the current GPIO HAL
 * and device pointers once. Pins<32 directly write ENABLE_W1TC (no read).
 * All other accepted pins RMW ENABLE1_W1TC: preserve its upper ten bits and
 * replace the lower 22 with (1<<(pin&31))&0x3fffff. This native W1TC read is
 * retained, rather than replaced with an assumed direct write.
 * Use pin's LOW BYTE for the remaining routing/pad accesses: clear output
 * enable inversion bit 11, then freshly set GPIO enable control bit 10; for
 * low-byte pins 19/20 clear USB Serial/JTAG pad-enable bit 14. Finally select
 * GPIO function 1 in IO-MUX bits 12..14. No lock, reservation release, input
 * disable, output-level change or readback. Return 0 or logged 0x102. */
unsigned int gpio_output_disable(unsigned int pin)
{
    if (gpio_native_pin_valid(pin)) {
        GpioHal *hal = *GPIO_HAL_SLOT;
        GpioRegisters *device = hal->device;
        unsigned int bit = 1U << (pin & 31U);
        if (pin < 32U) {
            memw();
            device->output_enable_clear = bit;
        }
        else {
            memw();
            unsigned int previous = device->output_enable_high_clear;
            memw();
            device->output_enable_high_clear = (previous & 0xffc00000U) | (bit & 0x003fffffU);
        }
        unsigned int pad = (unsigned char)pin;
        volatile unsigned int *route = gpio_route_register(device,0x554U,pad);
        memw();
        unsigned int configuration = *route;
        memw();
        *route = configuration & ~0x800U;
        memw();
        configuration = *route;
        memw();
        *route = configuration | 0x400U;
        if ((unsigned char)(pin - 19U) < 2U) {
            memw();
            unsigned int usb = USB_SERIAL_JTAG_CONFIGURATION;
            memw();
            USB_SERIAL_JTAG_CONFIGURATION = usb & ~0x4000U;
        }
        volatile unsigned int *mux = gpio_direct_iomux_register(pad);
        memw();
        configuration = *mux;
        memw();
        *mux = (configuration & ~0x7000U) | 0x1000U;
        return 0;
    }
    unsigned int stamp = esp_log_timestamp();
    esp_log_write(1,"gpio","E (%lu) %s: %s(%d): %s\n",stamp,"gpio","gpio_output_disable",0xd7,"GPIO number error");
    return 0x102;
}

/* Native entry: 0x4200ddf4. */
/* Original function-byte SHA-256:
 * 6c165da4ac8c9d72b94a66ffb6d04acd606b5931baa9db51dc0e4d6ab917b7a5. */
/* Validate the native signed/six-bit pin mask, then unsigned strength<4;
 * failures log102 (pin error takes precedence). Call the RTC-pin predicate
 * but ignore its result, lock GPIO configuration, and swap strength bits0/1
 * for exact pin17/18. Fence/read IO_MUX[pin], replace bits10/11, fence/write,
 * unlock and return0. No pin-range repair, rollback or readback is supplied.
 * Positive pin aliases accepted by the mask still index the FULL pin value. */
unsigned int gpio_set_drive_capability(unsigned int pin,unsigned int strength)
{
    unsigned int timestamp,source_line;
    const char *reason;
    if (!gpio_native_pin_valid(pin)) {
        timestamp = esp_log_timestamp();
        reason = "GPIO number error";
        source_line = 687;
        goto invalid_argument;
    }
    if (strength >= 4) {
        timestamp = esp_log_timestamp();
        reason = "GPIO drive capability error";
        source_line = 688;
        goto invalid_argument;
    }
    rtc_gpio_is_valid_gpio((int)pin);
    xPortEnterCriticalTimeout(&GPIO_CONFIGURATION_LOCK,-1);
    if (pin - 17U < 2U)
        strength = ((strength & 1U) << 1) | (strength >> 1);
    volatile unsigned int *mux = gpio_direct_iomux_register(pin);
    memw();
    unsigned int configuration = *mux;
    memw();
    *mux = (configuration & 0xfffff3ffU) | (strength << 10);
    vPortExitCritical(&GPIO_CONFIGURATION_LOCK);
    return 0;
invalid_argument:
    esp_log_write(1,GPIO_LOG_TAG,"E (%lu) %s: %s(%d): %s\n",timestamp,GPIO_LOG_TAG,
                  "gpio_set_drive_capability",source_line,reason);
    return 0x102;
}

/* Native entry: 0x4200dec0. */
/* Original function-byte SHA-256:
 * 1c07e19e8dd7d2796db71a6c2cfb07f327b6590afb43f626d52d2e8a2b863c2e. */
/* Select a dedicated peripheral input by clearing its matrix-select bit
 * 7 at GPIO+0x154+4*signal. Then enable the pad input at IO-MUX+4*pin (bit 9).
 * Read the HAL/device once; all address arithmetic wraps at 32 bits. No index
 * validation, pin truncation, lock, reservation, function selection or status. */
void gpio_iomux_in(unsigned int pin,unsigned int signal)
{
    GpioHal *hal = *GPIO_HAL_SLOT;
    GpioRegisters *device = hal->device;
    volatile unsigned int *route = gpio_route_register(device,0x154U,signal);
    memw();
    unsigned int configuration = *route;
    memw();
    *route = configuration & ~0x80U;
    volatile unsigned int *mux = gpio_direct_iomux_register(pin);
    memw();
    configuration = *mux;
    memw();
    *mux = configuration | 0x200U;
}

/* Native entry: 0x4200def8. */
/* Original function-byte SHA-256:
 * 41bc30b3f308b7d5e9bc701c2a0d93f985ee71098dc3e60e1b8a81a4430384f9. */
/* Use pin's LOW BYTE, with no validity check. In its output-route word,
 * freshly clear bit 11 (enable inversion), then separately clear bit 10 to
 * select peripheral output-enable control. For pins 19/20 release the USB
 * Serial/JTAG pads; finally replace IO-MUX function bits 12..14 with function&7.
 * No lock, status, pin ownership or input enable. Only two arguments are
 * consumed by this native body; the SDK's out_en_inv parameter is unused. */
void gpio_iomux_out(unsigned int pin,unsigned int function)
{
    unsigned int pad = (unsigned char)pin;
    GpioHal *hal = *GPIO_HAL_SLOT;
    GpioRegisters *device = hal->device;
    volatile unsigned int *route = gpio_route_register(device,0x554U,pad);
    memw();
    unsigned int configuration = *route;
    memw();
    *route = configuration & ~0x800U;
    memw();
    configuration = *route;
    memw();
    *route = configuration & ~0x400U;
    if ((unsigned char)(pad - 19U) < 2U) {
        memw();
        unsigned int usb = USB_SERIAL_JTAG_CONFIGURATION;
        memw();
        USB_SERIAL_JTAG_CONFIGURATION = usb & ~0x4000U;
    }
    volatile unsigned int *mux = gpio_direct_iomux_register(pad);
    memw();
    configuration = *mux;
    memw();
    *mux = (configuration & ~0x7000U) | ((function & 7U) << 12);
}

/* Native entry: 0x4200df70. */
/* Original function-byte SHA-256:
 * 499824354f3987ef4843a08e95c7dc009b23aaacbe1c8473bea396b5b4c0eaec. */
/* Require a nonnegative pin allowed by the six-bit GPIO mask; otherwise
 * log and return 0x102. Independently replace IO-MUX sleep input-enable bit 4
 * from mode bit 0, then sleep output-enable bit 0 from mode bit 1, each through
 * a fresh RMW. The first successful table lookup supplies both accesses.
 * Extra mode bits are ignored; no lock, active-mode change or rollback.
 *
 * Native code repeats complementary valid/invalid mask tests. On this S3
 * image every initially accepted pin also passes the inner tests, including
 * positive>=64 aliases. The retained inner diagnostic paths are unreachable
 * for such inputs and still return 0. An additional native output-only guard
 * diagnostic ("io_num=%d can only be input") is likewise unreachable after
 * the initial test; it performs no reachable operation and is described here.
 * Table indexing uses the FULL pin and wraps at 32 bits, without a bound check. */
int gpio_sleep_set_direction(unsigned int pin,unsigned int mode)
{
    if (!gpio_native_pin_valid(pin))
        goto invalid_pin;
    volatile unsigned int *reg;
    if (gpio_mask_allows(pin)) {
        reg = gpio_iomux_table_register(pin);
        memw();
        unsigned int configuration = *reg;
        if ((mode & 1U) != 0) {
            memw();
            *reg = configuration | 0x10U;
        }
        else {
            memw();
            *reg = configuration & ~0x10U;
        }
    }
    else {
        unsigned int stamp = esp_log_timestamp();
        const char *function = (mode & 1U) != 0 ? "gpio_sleep_input_enable" : "gpio_sleep_input_disable";
        unsigned int line = (mode & 1U) != 0 ? 0x36fU : 0x368U;
        esp_log_write(1,"gpio","E (%lu) %s: %s(%d): %s\n",stamp,"gpio",function,line,"GPIO number error");
        stamp = esp_log_timestamp();
        function = (mode & 2U) != 0 ? "gpio_sleep_output_enable" : "gpio_sleep_output_disable";
        line = (mode & 2U) != 0 ? 0x37dU : 0x376U;
        const char *reason = (mode & 2U) != 0 ? "GPIO output gpio_num error" : "GPIO number error";
        esp_log_write(1,"gpio","E (%lu) %s: %s(%d): %s\n",stamp,"gpio",function,line,reason);
        return 0;
    }
    memw();
    unsigned int configuration = *reg;
    if ((mode & 2U) != 0) {
        memw();
        *reg = configuration | 1U;
    }
    else {
        memw();
        *reg = configuration & ~1U;
    }
    return 0;
invalid_pin:
    {
        unsigned int stamp = esp_log_timestamp();
        esp_log_write(1,"gpio","E (%lu) %s: %s(%d): %s\n",stamp,"gpio","gpio_sleep_set_direction",0x384,"GPIO number error");
    }
    return 0x102;
}

/* Native entry: 0x4200e1d4. */
/* Original function-byte SHA-256:
 * 37a7abcbd911a1ddbdd76939fb1d83a1c8299930055550120d795924d5a3bb6b. */
/* Validate the signed/six-bit GPIO mask and set IO-MUX sleep-select
 * bit 1 under the GPIO spinlock. The FULL pin indexes the table, including
 * accepted positive>=64 aliases; no table bounds/NULL check. Return 0 or
 * logged 0x102. No pad state copy, sleep entry or reservation operation. */
unsigned int gpio_sleep_sel_en(unsigned int pin)
{
    if (gpio_native_pin_valid(pin)) {
        xPortEnterCriticalTimeout(&GPIO_CONFIGURATION_LOCK,-1);
        volatile unsigned int *reg = gpio_iomux_table_register(pin);
        memw();
        unsigned int configuration = *reg;
        memw();
        *reg = configuration | 2U;
        vPortExitCritical(&GPIO_CONFIGURATION_LOCK);
        return 0;
    }
    unsigned int stamp = esp_log_timestamp();
    esp_log_write(1,"gpio","E (%lu) %s: %s(%d): %s\n",stamp,"gpio","gpio_sleep_sel_en",0x3c2,"GPIO number error");
    return 0x102;
}

/* Native entry: 0x4200e268. */
/* Original function-byte SHA-256:
 * 92e7fa445740fc03a4eb2f77e4bc180e07a63d0b14ed3635dfe3efbfd98b568e. */
/* Validate the native signed/six-bit GPIO mask, retaining positive>=64
 * aliases. Under the GPIO spinlock, load this pin's IO-MUX register address
 * from the flash table and clear sleep-select bit 1 through one fresh RMW.
 * No table bounds or NULL-entry guard. Return 0, or log and return 0x102 for
 * an invalid pin. Critical-entry status is ignored; no reservation change. */
int gpio_sleep_sel_dis(unsigned int pin)
{
    if (gpio_native_pin_valid(pin)) {
        xPortEnterCriticalTimeout(GPIO_SLEEP_LOCK,-1);
        volatile unsigned int *reg = gpio_iomux_table_register(pin);
        memw();
        unsigned int configuration = *reg;
        memw();
        *reg = configuration & ~2U;
        vPortExitCritical(GPIO_SLEEP_LOCK);
        return 0;
    }
    unsigned int stamp = esp_log_timestamp();
    esp_log_write(1,"gpio","E (%lu) %s: %s(%d): %s\n",stamp,"gpio","gpio_sleep_sel_dis",0x3cd,"GPIO number error");
    return 0x102;
}

/* Native entry: 0x4200e2fc. */
/* Original function-byte SHA-256:
 * 9b664d6bc271a5a7b50d4e019849ad7a9fdd1f3883908b7a4f9d62c499eff041. */
/* Validate the signed/six-bit pin mask, then use the LOW BYTE for pad
 * operations. For low-byte 19/20 clear USB Serial/JTAG pad-enable bit 14
 * first; replace IO-MUX function bits 12..14 with function&7. No output-route
 * change, input enable, lock or ownership check. Return 0 or logged 0x102. */
int gpio_func_sel(unsigned int pin,unsigned int function)
{
    if (gpio_native_pin_valid(pin)) {
        if ((unsigned char)(pin - 19U) < 2U) {
            memw();
            unsigned int usb = USB_SERIAL_JTAG_CONFIGURATION;
            memw();
            USB_SERIAL_JTAG_CONFIGURATION = usb & ~0x4000U;
        }
        volatile unsigned int *reg = gpio_direct_iomux_register((unsigned char)pin);
        memw();
        unsigned int configuration = *reg;
        memw();
        *reg = (configuration & ~0x7000U) | ((function & 7U) << 12);
        return 0;
    }
    unsigned int stamp = esp_log_timestamp();
    esp_log_write(1,"gpio","E (%lu) %s: %s(%d): %s\n",stamp,"gpio","gpio_func_sel",0x455,"GPIO number error");
    return 0x102;
}

/* Native entry: 0x4200e3a4. */
/* Original function-byte SHA-256:
 * aeefc2ddf76ff541df211ea7e47a97b4a9c30001f3e5ae76a4daee7a1399a29a. */
/* Signed pin>48 returns0. Otherwise read the signed-byte RTC mapping table
 * at0x3c0470f8+pin and return1 when its high bit is clear. There is NO lower
 * bounds check: negative pins read before the table. No lock/fence or GPIO
 * range normalization is supplied. The image maps pins0..21 to RTC0..21. */
unsigned int rtc_gpio_is_valid_gpio(int pin)
{
    if (pin > 48) return 0;
    const volatile unsigned char *mapping = (const volatile void *)0x3c0470f8U;
    unsigned char rtc_index = *(const volatile unsigned char *)((unsigned int)mapping+(unsigned int)pin);
    return ((unsigned int)rtc_index & 128U) == 0;
}

/* Native entry: 0x42011714. */
/* Original function-byte SHA-256:
 * 8b8835865cabfa32ddd7603b52aed4215f53249319b6358cd9890adaed9672a5. */
/* Clear the requested bits in software GPIO reservations using a 64-bit
 * AND with the complement mask, order 5. Return the full previous mask.
 * No owner check, pad reset/disconnection or conflict handling is supplied. */
unsigned long long esp_gpio_revoke(unsigned long long mask)
{
    return atomic_fetch_and_u64(GPIO_RESERVED_MASK,~mask,5);
}

/* Native entry: 0x420116fc. */
/* Original function-byte SHA-256:
 * 7b5567c812d70a997d8d943b436fdf45362ef8ee8a134a11327a97421fc4dca6. */
/* OR all requested bits into the shared GPIO reservation word and return
 * its previous 64-bit value. Use sequential-consistency order 5 at the atomic
 * helper boundary. Conflicts are neither rejected nor rolled back; no pin
 * validity test, pad configuration or ownership identity is supplied here.
 * Native callers pass a single uint64 mask, not two API parameters. */
unsigned long long esp_gpio_reserve(unsigned long long mask)
{
    return atomic_fetch_or_u64(GPIO_RESERVED_MASK,mask,5);
}
