/* Medius v3.4.7 host — platform/console.c.
 * Recovered C and native assembly, grouped for source navigation.
 * Original entry addresses, firmware-byte hashes and function comments follow.
 */

#include "../include/types.h"

/* Native entry: 0x403811c0. */
/*
 * Medius v3.4.7 — host application; 0x403811c0.
 *
 * Installs the ROM UART character output and enables UART/USB print flags.
 *
 * Calls: ets_install_uart_printf.
 *
 * Called by: call_start_cpu1.
 *
 * Original function-byte SHA-256:
 * 773aca9fe11ec76c468528e50d6b69ffb3310fa963b8ea29ebb501f35a8b9fbc.
 */

/*
 * Returns: No value.
 * Requirements/effects: Caches the ROM UART output function at 0x400006b4, stores 1 to ROM
 *   g_uart_print at 0x3fceffb9 and then g_usb_print at 0x3fceffb8, and calls
 *   ets_install_uart_printf. Does not restore callback or flags after that ROM call and supplies
 *   no lock.
 */

void esp_rom_install_uart_printf(void)
{
    ROM_PUTC1_CACHE = ets_write_char_uart;
    *(volatile unsigned char *)0x3fceffb9U = 1; /* ROM g_uart_print */
    *(volatile unsigned char *)0x3fceffb8U = 1; /* ROM g_usb_print */
    ets_install_uart_printf();
}

