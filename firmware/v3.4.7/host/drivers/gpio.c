/* Medius v3.4.7 host — drivers/gpio.c.
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

/* Native entry: 0x4200f750. */
/* Original function-byte SHA-256:
 * 3e42d5e82813ab4b30471b636a27ec141d4fb11e0da68f58c86c254365079204. */
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

/* Native entry: 0x4200febc. */
/* Original function-byte SHA-256:
 * 9c6b264e17b573594afdae13bf3d349e91ce9672f06b0b6737655fd566b65381. */
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

/* Native entry: 0x4200ff44. */
/* Original function-byte SHA-256:
 * 653ced23b1c4bfe35cac55752287a8c5b321d1b8c5254ae916c5a142c458a691. */
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

/* Native entry: 0x4200ffcc. */
/* Original function-byte SHA-256:
 * aef29efe746b9d1fbbc9f6218c41ab6727278894737b03e340d94e88a44f82e9. */
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

/* Native entry: 0x42010054. */
/* Original function-byte SHA-256:
 * e1c1c3edabb420b8634be64534cb851f71319f1f06fd16736c0dd3b76a98efbf. */
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

/* Native entry: 0x420100dc. */
/* Original function-byte SHA-256:
 * eec3f34156b6ddd99c4d2555805654b0b9329ae88a2bc8502838ee12e6722ac4. */
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

/* Native entry: 0x42010174. */
/* Original function-byte SHA-256:
 * 414f9f22c00244f768d354da55ca6959b4d29d7cb10d3ba3479698339e526287. */
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

/* Native entry: 0x420101f0. */
/* Original function-byte SHA-256:
 * 34e49ecffa336c513df5ce54133886a557b690d319baa74b3e85c03f62a87ae0. */
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

/* Native entry: 0x420102f4. */
/* Original function-byte SHA-256:
 * 68f8911ec1da71c3ff57c7b6d77cce37f8a2e03101d65b238d7c7b413c2c697d. */
/* Validate the native signed/six-bit pin mask, then unsigned strength<4;
 * failures log102 (pin error takes precedence). Call the RTC-pin predicate
 * but ignore its result, lock GPIO configuration, and swap strength bits0/1
 * for exact pin17/18. Fence/read IO_MUX[pin], replace bits10/11, fence/write,
 * unlock and return0. No pin-range repair, rollback or readback is supplied.
 * Positive pin aliases accepted by the mask still index the FULL pin value. */
unsigned int gpio_set_drive_capability(unsigned int pin,unsigned int strength)
{
    unsigned int timestamp,line;
    const char *reason;
    if (!gpio_native_pin_valid(pin)) {
        timestamp = esp_log_timestamp();reason = "GPIO number error";line = 687;
        goto invalid_argument;
    }
    if (strength >= 4) {
        timestamp = esp_log_timestamp();reason = "GPIO drive capability error";line = 688;
        goto invalid_argument;
    }
    rtc_gpio_is_valid_gpio((int)pin);
    xPortEnterCriticalTimeout(&GPIO_CONFIGURATION_LOCK,-1);
    if (pin-17U < 2U) strength = ((strength & 1U) << 1) | (strength >> 1);
    volatile unsigned int *mux = (volatile void *)(0x60009004U+pin*4U);
    memw(); unsigned int value = *mux;
    memw(); *mux = (value & 0xfffff3ffU) | (strength << 10);
    vPortExitCritical(&GPIO_CONFIGURATION_LOCK);
    return 0;
invalid_argument:
    esp_log_write(1,(const char *)0x3c043320U,"E (%lu) %s: %s(%d): %s\n",timestamp,(const char *)0x3c043320U,
                  "gpio_set_drive_capability",line,reason);
    return 0x102;
}

/* Native entry: 0x420103c0. */
/* Original function-byte SHA-256:
 * fc6709b9d07ca6fa0f8cb0e59d708950670a9c563ecb085ebb0690950fc8a1f3. */
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

/* Native entry: 0x420103f8. */
/* Original function-byte SHA-256:
 * 646fe71685d1797803a5f9d89768b77b1148eeabc0bf49fc7f00aafabbb1b39a. */
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

/* Native entry: 0x42010470. */
/* Original function-byte SHA-256:
 * 501fc7ebd5bd51ff24bebcf8df962778136ac6daf54abd7519db63d29aef3ef4. */
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

/* Native entry: 0x420106d4. */
/* Original function-byte SHA-256:
 * 7ea26b52c3278e99ef5b935909693c125da97ee8d1bfc9ee4eac43995c15b50d. */
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

/* Native entry: 0x420107fc. */
/* Original function-byte SHA-256:
 * cfb5477a46d9c54ff143678f707cfdc14764978eb9147d8ec47cef9c0550db19. */
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

/* Native entry: 0x420108a4. */
/* Original function-byte SHA-256:
 * 8b5991d893f3fada4ce37737dae6dfd9c114081f4fa8827e25a56d07d3af46f8. */
/* Signed pin>48 returns0. Otherwise read the signed-byte RTC mapping table
 * at0x3c051814+pin and return1 when its high bit is clear. There is NO lower
 * bounds check: negative pins read before the table. No lock/fence or GPIO
 * range normalization is supplied. The image maps pins0..21 to RTC0..21. */
unsigned int rtc_gpio_is_valid_gpio(int pin)
{
    if (pin > 48) return 0;
    const volatile unsigned char *mapping = (const volatile void *)0x3c051814U;
    unsigned char index = *(const volatile unsigned char *)((unsigned int)mapping+(unsigned int)pin);
    return ((unsigned int)index & 128U) == 0;
}

/* Native entry: 0x42013be4. */
/* Original function-byte SHA-256:
 * 61ce1d59b33cf80abcbb6a50769679fbcc1d6689a3e6d91f8d6ddc548ced3a37. */
/* Clear the requested bits in software GPIO reservations using a 64-bit
 * AND with the complement mask, order 5. Return the full previous mask.
 * No owner check, pad reset/disconnection or conflict handling is supplied. */
unsigned long long esp_gpio_revoke(unsigned long long mask)
{
    return atomic_fetch_and_u64(GPIO_RESERVED_MASK,~mask,5);
}

/* Native entry: 0x42013bcc. */
/* Original function-byte SHA-256:
 * a0d534de187ef1d82f9403c6a4004f6633c5433f397b57630dd4707c35b2895f. */
/* OR all requested bits into the shared GPIO reservation word and return
 * its previous 64-bit value. Use sequential-consistency order 5 at the atomic
 * helper boundary. Conflicts are neither rejected nor rolled back; no pin
 * validity test, pad configuration or ownership identity is supplied here.
 * Native callers pass a single uint64 mask, not two API parameters. */
unsigned long long esp_gpio_reserve(unsigned long long mask)
{
    return atomic_fetch_or_u64(GPIO_RESERVED_MASK,mask,5);
}

/* Native entry: 0x42010768. */
/* Original function-byte SHA-256:
 * b20d8baf04f9cc145362463a9a367ec9e21fe5fec04c15ff6e89700329cb4b83. */
/* Validate the native signed/six-bit GPIO mask, retaining positive>=64
 * aliases. Under the GPIO spinlock, load this pin's IO-MUX register address
 * from the flash table and clear sleep-select bit 1 through one fresh RMW.
 * No table bounds or NULL-entry guard. Return 0, or log and return 0x102 for
 * an invalid pin. Critical-entry status is ignored; no reservation change. */
int gpio_sleep_sel_dis(unsigned int pin)
{
    if (gpio_native_pin_valid(pin)) {
        xPortEnterCriticalTimeout(GPIO_SLEEP_LOCK,-1);
        unsigned int slot = (unsigned int)(uintptr_t)GPIO_IOMUX_TABLE + pin * 4U;
        volatile unsigned int *reg = *(volatile unsigned int * const *)(uintptr_t)slot;
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
