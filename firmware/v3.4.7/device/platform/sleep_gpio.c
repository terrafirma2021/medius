/* Medius v3.4.7 device — GPIO isolation, sleep selection and EXT1 wake cleanup.
 * SDK identities checked against ESP-IDF v5.4.4 esp_hw_support/sleep_gpio.c.
 * Native instructions and each image's tables determine the recovered behavior.
 */
#include "../include/types.h"

/* GPIO sleep reconstruction utilities: the pin-mask test inlines into the
 * two 49-pin loops and is not an additional recovered native function.
 * pin must be below 64; both callers restrict it to 0..48.
 */
static __attribute__((always_inline)) inline bool sleep_gpio_is_valid(unsigned int pin)
{
    return ((GPIO_SLEEP_VALID_MASK >> pin) & 1U) != 0;
}

/* Native entry: 0x42005344. */
/* Original function-byte SHA-256:
 * 894526dd1836596dd1e393cd7077fabb8fc8790fc8e3d2184304391a4666b25a. */
/* Prepare sleep configuration for GPIO0..48, skipping absent pins22..25.
 * Optionally log at unsigned level >= 3, then for each valid pin disable sleep
 * input/output (mode 0), followed by floating sleep pulls (mode 3). Ignore all
 * returned statuses. Next query/apply pull-up-only mode 0 individually to MSPI
 * CLK,MISO,MOSI,HD,WP in that order; CS0/CS1 are not included. Query octal-flash
 * mode once; if true, do the same for DQS,D4,D5,D6,D7 in order. Do not cache
 * pin assignments, validate the getter's selected pin, or add PSRAM detection.
 * No function-wide lock, sleep entry, immediate GPIO-direction change, rollback
 * or status return. These calls prepare the separate sleep settings only.
 */
void esp_sleep_config_gpio_isolate(void)
{
    if (SYSTEM_EARLY_LOG_LEVEL >= 3U) {
        unsigned int timestamp = esp_log_timestamp();
        ets_printf("I (%lu) %s: Configure to isolate all GPIO pins in sleep state\n",
            timestamp,"sleep_gpio");
    }
    for (unsigned int pin = 0; pin < 49; ++pin) {
        if (sleep_gpio_is_valid(pin)) {
            (void)gpio_sleep_set_direction(pin,0);
            (void)gpio_sleep_set_pull_mode(pin,GPIO_SLEEP_FLOATING);
        }
    }
    (void)gpio_sleep_set_pull_mode(esp_mspi_get_io(ESP_MSPI_IO_CLK),GPIO_SLEEP_PULLUP_ONLY);
    (void)gpio_sleep_set_pull_mode(esp_mspi_get_io(ESP_MSPI_IO_Q),GPIO_SLEEP_PULLUP_ONLY);
    (void)gpio_sleep_set_pull_mode(esp_mspi_get_io(ESP_MSPI_IO_D),GPIO_SLEEP_PULLUP_ONLY);
    (void)gpio_sleep_set_pull_mode(esp_mspi_get_io(ESP_MSPI_IO_HD),GPIO_SLEEP_PULLUP_ONLY);
    (void)gpio_sleep_set_pull_mode(esp_mspi_get_io(ESP_MSPI_IO_WP),GPIO_SLEEP_PULLUP_ONLY);
    if (bootloader_flash_is_octal_mode_enabled()) {
        (void)gpio_sleep_set_pull_mode(esp_mspi_get_io(ESP_MSPI_IO_DQS),GPIO_SLEEP_PULLUP_ONLY);
        (void)gpio_sleep_set_pull_mode(esp_mspi_get_io(ESP_MSPI_IO_D4),GPIO_SLEEP_PULLUP_ONLY);
        (void)gpio_sleep_set_pull_mode(esp_mspi_get_io(ESP_MSPI_IO_D5),GPIO_SLEEP_PULLUP_ONLY);
        (void)gpio_sleep_set_pull_mode(esp_mspi_get_io(ESP_MSPI_IO_D6),GPIO_SLEEP_PULLUP_ONLY);
        (void)gpio_sleep_set_pull_mode(esp_mspi_get_io(ESP_MSPI_IO_D7),GPIO_SLEEP_PULLUP_ONLY);
    }
}

/* Native entry: 0x4200541c. */
/* Original function-byte SHA-256:
 * afef07b401e69d4c5109d3882faa3eb24f93a68b49700d67e953bcb72125b3a2. */
/* Set automatic sleep-configuration switching for GPIO0..48, excluding
 * absent pins22..25. Consume the raw enable BYTE: zero disables, any nonzero
 * byte enables. Optionally log the choice at unsigned level >= 3. Device excludes
 * dynamically mapped PSRAM CS1 first, then flash CS0.
 * Chip-select mapping is queried afresh for each eligible pin, in the written
 * short-circuit order, even when enable is zero. Excluded pins always receive
 * sleep_sel_dis; all others follow enable. Ignore each API status; no rollback,
 * cached assignment, whole-loop lock, pin-direction change or sleep entry.
 */
void esp_sleep_enable_gpio_switch(unsigned char enable)
{
    if (SYSTEM_EARLY_LOG_LEVEL >= 3U) {
        unsigned int timestamp = esp_log_timestamp();
        ets_printf("I (%lu) %s: %s automatic switching of GPIO sleep configuration\n",
            timestamp,"sleep_gpio",enable != 0 ? "Enable" : "Disable");
    }
    for (unsigned int pin = 0; pin < 49; ++pin) {
        if (!sleep_gpio_is_valid(pin))
            continue;
        if (pin == esp_mspi_get_io(ESP_MSPI_IO_CS1) ||
            pin == esp_mspi_get_io(ESP_MSPI_IO_CS0) || enable == 0)
            (void)gpio_sleep_sel_dis(pin);
        else
            (void)gpio_sleep_sel_en(pin);
    }
}

/* Native entry: 0x420054b8. */
/* Original function-byte SHA-256:
 * 3bb943434a31b3d9e3da4c72a3ad59780f7a525e1437a4af4298139eccccd630. */
/* SDK SECONDARY/CPU0 priority105 sleep-GPIO initializer. Configure isolation
 * first, then request automatic switching with enable BYTE1, and return0.
 * These void wrappers ignore lower API errors. No sleep transition, GPIO hold,
 * extra initialization, allocation or early failure propagation is added.
 */
int __esp_system_init_fn_esp_sleep_startup_init(void)
{
    esp_sleep_config_gpio_isolate();
    esp_sleep_enable_gpio_switch(1);
    return 0;
}

/* Native entry: 0x420054cc. */
/* Original function-byte SHA-256:
 * cf1b5793fab19c3d534e40fa35946c1f9045165427e3d06e6edff9e2805b8cf3. */
/* Clear EXT1 wake selection before releasing the selected RTC pad holds.
 * MEMW/read selection to capture pending bits0..21, then MEMW/read it AGAIN
 * and MEMW/write only that second snapshot's upper10 bits. This clear occurs
 * even when the first pending mask was zero. Changes between the reads are
 * not merged into the cached pending mask; there is no enclosing lock.
 *
 * While pending is nonzero, scan GPIO0..48 through the signed RTC-channel BYTE
 * table. Test the corresponding low-five-bit shift (non-RTC -1 maps to bit31,
 * absent from the22-bit pending mask). For each selected channel, MEMW/read
 * pad_hold, read its descriptor's force-hold WORD at offset0x28/stride56, remove
 * the channel from cached pending, then MEMW/write hold &~force_mask. Stop as
 * soon as pending becomes zero or all49 GPIO entries have been examined.
 * No pad remux, GPIO-driver call, EXT1 status read/clear, delay, extra hold
 * restoration or status return. Descriptor/map storage belongs to the image.
 */
void esp_deep_sleep_wakeup_io_reset(void)
{
    RtcSleepWakeRegisters *wake_registers = RTC_SLEEP_WAKE_REGISTERS;
    memw();
    unsigned int pending_channels = wake_registers->ext1_selection & 0x003fffffU;
    memw();
    unsigned int selection_snapshot = wake_registers->ext1_selection;
    memw();
    wake_registers->ext1_selection = selection_snapshot & 0xffc00000U;
    for (unsigned int pin = 0; pin < 49 && pending_channels != 0; ++pin) {
        int rtc_channel = RTC_GPIO_CHANNEL_MAP[pin];
        unsigned int channel_mask = 1U << ((unsigned int)rtc_channel & 31U);
        if ((pending_channels & channel_mask) != 0) {
            memw();
            unsigned int hold_snapshot = wake_registers->pad_hold;
            unsigned int force_mask = RTC_PAD_DESCRIPTORS[rtc_channel].force_hold_mask;
            pending_channels &= ~channel_mask;
            memw();
            wake_registers->pad_hold = hold_snapshot & ~force_mask;
        }
    }
}
