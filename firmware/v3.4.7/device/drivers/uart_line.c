/* Medius v3.4.7 device — drivers/uart_line.c.
 */

#include "../include/types.h"

/* Native entry: 0x42012014. */
/*
 * Medius v3.4.7 — device application; 0x42012014.
 * Instruction-checked recovered C.
 * Original function-byte SHA-256:
 * f8a65bec61985923faf8ad0d9e5810f1bb9500fb7dc8fb9cdd0282872d512d43.
 */

/* Resolve this port's source clock at cached precision BEFORE taking its port
 * spinlock. Propagate clock-query failure after native Invalid src_clk log.
 * Reject baud0 or a source divider outside1..256 without register writes. Compute
 * ceil(source_hz/(4095*baud_rate)) in64 bits, then use the low32 bits of source_hz<<4
 * and baud_rate*source_divider in native QUOU. Read CLKDIV BEFORE that divide; write integer
 * low12 and fractional bits20..23 using separate fresh read/modify/writes.
 * Finally replace CLK_CONF bits12..19 via its native volatile stack snapshot
 * sequence; retain every explicit MEMW and all other register bits. Unlock and
 * return0. Invalid port/unachievable rate logs line0x173/0x188 and returns-1.
 * No driver-install check, output drain, clock-change retry or VFS lock. */
int uart_set_baudrate(unsigned int port,unsigned int baud_rate)
{
    unsigned int timestamp_ms;
    const char *error_format;
    int source_line;
    if (port >= 3U) {
        timestamp_ms=esp_log_timestamp();
        error_format="E (%lu) %s: %s(%d): uart_num error\n";
        source_line=0x173;
    } else {
        unsigned int source_clock;
        unsigned int source_hz;
        uart_hal_get_sclk(&UART_DRIVER_CONTEXTS[port].hal,&source_clock);
        int frequency_status=esp_clk_tree_src_get_freq_hz(source_clock,0,&source_hz);
        if (frequency_status != 0) {
            timestamp_ms=esp_log_timestamp();
            esp_log_write(1,UART_LOG_TAG,"E (%lu) %s: %s(%d): Invalid src_clk\n",
                timestamp_ms,UART_LOG_TAG,"uart_set_baudrate",0x179);
            return frequency_status;
        }
        PortMuxWords *port_lock=&UART_DRIVER_CONTEXTS[port].spinlock;
        (void)xPortEnterCriticalTimeout(port_lock,-1);
        if (baud_rate != 0) {
            unsigned int baud_source_hz=source_hz;
            unsigned long long maximum_baud_span=(unsigned long long)baud_rate*4095ULL;
            unsigned int source_divider=(unsigned int)rom_unsigned_divide_u64(
                (unsigned long long)baud_source_hz+maximum_baud_span-1ULL,maximum_baud_span);
            if (source_divider-1U < 256U) {
                UartRegisterView *registers=UART_DRIVER_CONTEXTS[port].hal.dev;
                unsigned int denominator=baud_rate*source_divider;
                memw();
                unsigned int integer_register=registers->clkdiv;
                unsigned int divider=uart_unsigned_divide(baud_source_hz<<4,denominator);
                memw();
                registers->clkdiv=(integer_register & 0xfffff000U) | ((divider>>4)&0xfffU);
                memw();
                unsigned int fraction_register=registers->clkdiv;
                memw();
                registers->clkdiv=(fraction_register & 0xff0fffffU) | ((divider&15U)<<20);
                memw();
                unsigned int clock_register=registers->clk_conf;
                memw();
                volatile unsigned int clock_configuration_snapshot=clock_register;
                memw();
                clock_register=clock_configuration_snapshot;
                clock_register=(clock_register&0xfff00fffU) | (((source_divider-1U)&0xffU)<<12);
                memw();
                clock_configuration_snapshot=clock_register;
                memw();
                clock_register=clock_configuration_snapshot;
                memw();
                registers->clk_conf=clock_register;
                vPortExitCritical(port_lock);
                return 0;
            }
        }
        vPortExitCritical(port_lock);
        timestamp_ms=esp_log_timestamp();
        error_format="E (%lu) %s: %s(%d): baud rate unachievable\n";
        source_line=0x188;
    }
    esp_log_write(1,UART_LOG_TAG,error_format,timestamp_ms,
        UART_LOG_TAG,"uart_set_baudrate",source_line);
    return -1;
}
