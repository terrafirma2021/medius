/* Medius v3.4.7 host — sleep pull-mode validation and dispatch. */
#include "../include/types.h"

/* Native entry: 0x42010610. */
/* Original function-byte SHA-256:
 * e0f984309a613d126a6c5ce6b49dff5ec3bcd4bc78b2c86df98b8dc4549cf469. */
/* Set one pin's sleep pulls using mode0 up-only,1 down-only,2 both,3 float.
 * Preserve the native validator: reject signed-negative pin WORDs; otherwise
 * test the49-pin validity mask using pin modulo64. There is NO independent
 * pin<=48 check, so sufficiently large nonnegative IDs can alias a valid mask
 * bit and reach the lower helpers with the ORIGINAL pin value unchanged.
 * Pin errors take precedence over mode errors. Reject unsigned mode>=4.
 *
 * On error, take one timestamp, log the native GPIO number/mode diagnostic
 * with source line926/927 through esp_log_write, and return0x102. Success calls
 * pulldown en/dis FIRST, then pullup en/dis, with the pin supplied to BOTH
 * calls (Ghidra omitted two arguments). Return0. The void helpers' internal
 * side effects/errors are not checked; no whole-pair lock, pin reservation,
 * sleep-select change, active-pull change or rollback is added here.
 */
int gpio_sleep_set_pull_mode(unsigned int pin,unsigned int mode)
{
    unsigned int timestamp;
    unsigned int source_line;
    const char *message;
    if ((int)pin < 0 || ((GPIO_SLEEP_VALID_MASK >> (pin & 63U)) & 1U) == 0) {
        timestamp = esp_log_timestamp();
        source_line = 926;
        message = "GPIO number error";
    } else if (mode >= 4U) {
        timestamp = esp_log_timestamp();
        source_line = 927;
        message = "GPIO pull mode error";
    } else {
        switch (mode) {
        case GPIO_SLEEP_PULLUP_ONLY:
            gpio_sleep_pulldown_dis(pin);
            gpio_sleep_pullup_en(pin);
            break;
        case GPIO_SLEEP_PULLDOWN_ONLY:
            gpio_sleep_pulldown_en(pin);
            gpio_sleep_pullup_dis(pin);
            break;
        case GPIO_SLEEP_PULL_BOTH:
            gpio_sleep_pulldown_en(pin);
            gpio_sleep_pullup_en(pin);
            break;
        default: /* Only mode3 remains after the unsigned bound check. */
            gpio_sleep_pulldown_dis(pin);
            gpio_sleep_pullup_dis(pin);
            break;
        }
        return 0;
    }
    esp_log_write(1,"gpio","E (%lu) %s: %s(%d): %s\n",timestamp,"gpio",
        "gpio_sleep_set_pull_mode",source_line,message);
    return 0x102;
}
