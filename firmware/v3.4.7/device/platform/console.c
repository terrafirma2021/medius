/* Medius v3.4.7 device — platform/console.c.
 * Recovered C and native assembly, grouped for source navigation.
 * Original entry addresses, firmware-byte hashes and function comments follow.
 */

#include "../include/types.h"

/* Native entry: 0x40385f64. */
/*
 * Medius v3.4.7 — device application; 0x40385f64.
 *
 * Caches and installs a typed ROM output callback for channel one or two.
 *
 * Calls: ets_install_putc1, ets_install_putc2.
 *
 * Called by: call_start_cpu1.
 *
 * Original function-byte SHA-256:
 * 2b1349bc23011207ede74f904cb605bbe022da02978b9803e872bb363abe69dd.
 */

/*
 * channel: Only exact values 1 and 2 are acted upon; every other signed/raw 32-bit value is
 *   ignored.
 * putc: Borrowed void(char) callback, or NULL to disable the selected output channel. Its lifetime
 *   is managed by the caller.
 * Returns: No value.
 * Requirements/effects: Stores the callback in the selected application cache before calling the
 *   corresponding ROM installer. Other callback slots are preserved. The pointer is not copied,
 *   invoked or restored after the installer; no local lock or validation is provided.
 */

void esp_rom_install_channel_putc(int channel, RomPutc putc)
{
    if (channel == 1) {
        ROM_PUTC1_CACHE = putc;
        ets_install_putc1(putc);
    } else if (channel == 2) {
        ROM_PUTC2_CACHE = putc;
        ets_install_putc2(putc);
    }
}

