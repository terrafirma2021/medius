/* Medius v3.4.7 host — app/led.c.
 * Recovered C and native assembly, grouped for source navigation.
 * Original entry addresses, firmware-byte hashes and function comments follow.
 */

#include "../include/types.h"

/* Native entry: 0x4200f49c. */
/* Original function-byte SHA-256:
 * 3c6e539d7ce409d38d44545ae50c6cdee13946c60fb1d56efcebeba6f998d90e. */
/* Timer callback: read override ownership FIRST, then pattern and brightness
 * through separate native MEMW/load sites. Owned pattern 1 is steady, 2 slow
 * blink, other patterns off. Without ownership, status 2 is steady, 1/3 blink,
 * other statuses off. All paths call esp_timer_get_time once, even steady/off.
 * Status is read a second time: initial 1/3 chooses fast only if the SECOND
 * read is 3, otherwise slow; other second reads are retained but discarded.
 * No coherent cross-field/status snapshot or per-call lock is provided.
 *
 * Automatic brightness is 100; overrides use the full unsigned byte. Slow
 * blink uses signed time%666000, on while its unsigned LOW word<333000; fast
 * uses time%160000/<80000. This is wall-clock phase, with no reset on override.
 * On logical change, map active-low to 255-brightness, cache the new logical
 * value BEFORE requesting duty and latch, and ignore both errors. Failed PWM
 * operations may not retry until brightness changes. No hardware/timing wait.
 * The timer argument is unused. Initialization requests task dispatch/50ms;
 * actual callback delivery and output timing have not been measured. */
void led_timer_cb(void *argument)
{
    (void)argument;
    unsigned int brightness;
    long long now;
    long long cycle;
    unsigned int on_time;
    memw();
    unsigned char owned = LED_RUNTIME->override_owned;
    if (owned != 0) {
        memw();
        unsigned int pattern = LED_RUNTIME->override_pattern;
        memw();
        brightness = LED_RUNTIME->override_brightness;
        now = esp_timer_get_time();
        if (pattern == 1)
            goto apply;
        if (pattern != 2) {
            brightness = 0;
            goto apply;
        }
        cycle = 666000;
        on_time = 333000;
    }
    else {
        memw();
        unsigned int status = LED_RUNTIME->status;
        if (status == 2) {
            memw();
            (void)LED_RUNTIME->status;
            (void)esp_timer_get_time();
            brightness = 100;
            goto apply;
        }
        if (status != 1 && status != 3) {
            memw();
            (void)LED_RUNTIME->status;
            (void)esp_timer_get_time();
            brightness = 0;
            goto apply;
        }
        memw();
        unsigned int current_status = LED_RUNTIME->status;
        if (current_status == 3) {
            now = esp_timer_get_time();
            cycle = 160000;
            on_time = 80000;
        }
        else {
            now = esp_timer_get_time();
            cycle = 666000;
            on_time = 333000;
        }
        brightness = 100;
    }
    if ((unsigned int)signed_remainder_i64(now,cycle) >= on_time)
        brightness = 0;
apply:
    if (LED_OUTPUT->logical_brightness != brightness) {
        unsigned char active_high = LED_OUTPUT->active_high;
        unsigned int duty = active_high != 0 ? brightness : 255U - brightness;
        LED_OUTPUT->logical_brightness = brightness;
        ledc_set_duty(0,0,duty);
        ledc_update_duty(0,0);
    }
}

/* Native entry: 0x4200f624. */
/* Original function-byte SHA-256:
 * 20de73056355b5a58bbbd61bdd74f6efc06ba351f44f435dd154588dc8a0ef1b. */
/* Consume only each argument's LOW BYTE. Mode 1 publishes owned off
 * (pattern0,brightness0); mode 2 owned steady (pattern1,supplied brightness);
 * mode 3 owned slow blink (pattern2,supplied brightness). Other modes release
 * ownership without clearing pattern/value. Store pattern, THEN brightness,
 * THEN ownership, with a MEMW before EACH store. No lock or atomic combined
 * snapshot: an already-owned override may be observed partway through update.
 * No LEDC call, blink phase reset, range clamp or returned status. */
void medius_host_led_override_set(unsigned char mode,unsigned char brightness)
{
    if (mode == 2) {
        memw();
        LED_RUNTIME->override_pattern = 1;
        memw();
        LED_RUNTIME->override_brightness = brightness;
        memw();
        LED_RUNTIME->override_owned = 1;
    }
    else if (mode == 3) {
        memw();
        LED_RUNTIME->override_pattern = 2;
        memw();
        LED_RUNTIME->override_brightness = brightness;
        memw();
        LED_RUNTIME->override_owned = 1;
    }
    else if (mode == 1) {
        memw();
        LED_RUNTIME->override_pattern = 0;
        memw();
        LED_RUNTIME->override_brightness = 0;
        memw();
        LED_RUNTIME->override_owned = 1;
    }
    else {
        memw();
        LED_RUNTIME->override_owned = 0;
    }
}

/* Native entry: 0x4200f588. */
/* Original function-byte SHA-256:
 * 075f31b4c7e99e8008a2822ca8e39b2430e597ea4759ee545a34cb8cffbfcf5e. */
/* Store polarity's LOW BYTE, then configure LEDC timer 0, mode 0,
 * resolution 8, requested 5000Hz and AUTO clock. Configure channel 0 on the
 * supplied GPIO with all other fields zero. Both configuration results are
 * ignored. If cached logical brightness is nonzero, cache 0 and request off
 * duty (0 active-high,255 active-low), ignoring duty/latch errors. If already
 * zero, skip that correction even though channel setup requested duty 0.
 *
 * Create a task-dispatched timer named "led", argument NULL, skip-unhandled
 * false; request a 50000us period. Neither result is checked. The output handle
 * slot is deliberately NOT initialized: failed creation can leave an
 * indeterminate stack value passed to start_periodic. No stored cleanup handle,
 * duplicate-init prevention or rollback; repeated successful calls add timers.
 * These are requested carrier/callback settings, not measured timing. */
void led_initialize(int gpio_pin,unsigned char active_high)
{
    LED_OUTPUT->active_high = active_high;
    LedcTimerConfig timer = {0};
    timer.frequency_hz = 5000;
    timer.duty_resolution = 8;
    ledc_timer_config(&timer);
    LedcChannelConfig channel = {0};
    channel.gpio_pin = gpio_pin;
    ledc_channel_config(&channel);
    if (LED_OUTPUT->logical_brightness != 0) {
        unsigned char polarity = LED_OUTPUT->active_high;
        unsigned int duty = polarity != 0 ? 0U : 255U;
        LED_OUTPUT->logical_brightness = 0;
        ledc_set_duty(0,0,duty);
        ledc_update_duty(0,0);
    }
    EspTimerCreateArgs arguments = {
        .callback = led_timer_cb,
        .argument = NULL,
        .dispatch = 0,
        .name = "led",
        .skip_unhandled_events = 0,
        .padding17 = {0,0,0}
    };
    EspTimer *created_timer;
    esp_timer_create(&arguments,&created_timer);
    esp_timer_start_periodic(created_timer,50000);
}


/* Native entry: 0x4200f614. */
/* Original function-byte SHA-256:
 * 904ec5c1f724ca602c7a2cac13a37fece72dc95ce01f7c26494d84820cfa09ec. */
/* Publish the unchecked status word after MEMW. The callback interprets
 * 1 as slow blink, 2 as steady100, 3 as fast blink and other values as off.
 * No immediate duty change, phase reset, ownership change or lock occurs. */
void led_set_status(unsigned int status)
{
    memw();
    LED_RUNTIME->status = status;
}
