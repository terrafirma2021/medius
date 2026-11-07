/* Medius v3.4.7 device — drivers/uart_config.c.
 */

#include "../include/types.h"

/* Native entry: 0x42012688. */
/*
 * Medius v3.4.7 — device application; 0x42012688.
 * Instruction-checked recovered C.
 * Original function-byte SHA-256:
 * fa6c5922edec7d179bba19d384ef5d058bb72b61a5cd2aabff302dd9d88ca5cf.
 */

/* Apply the 32-byte configuration with native validation and side-effect order.
 * Reject bad unsigned port, NULL record, threshold bit7, flow>=4 or data>=4 with
 * ESP_FAIL(-1); flags low2 return NOT_SUPPORTED(0x106). Parity/stop/baud are not
 * validated at entry. Other flag/padding bits are ignored. Enable module first,
 * then sample source clock (0 defaults toAPB4). RTC9 acquires a reference whose
 * boolean result is ignored; frequency failure logs and propagates its status,
 * retaining module/RTC side effects. Under port spinlock initialize HAL and call
 * source-enable routine. Select4/9/11 in CLK_CONF; any other successfully resolved
 * clock aborts AFTER initialization, without unlocking. Cache parity BEFORE baud.
 * Baud0/unachievable divider skips baud writes but still applies parity, fresh
 * data/stop fields, TX idle0 and fresh flow/threshold; then unlocks and resets RX
 * followed by TX FIFO before logging/returning-1. Successful baud uses64-bit
 * ceiling and native32-bit QUOU, CLKDIV read before divide, separate integer/
 * fraction updates and the CLK_CONF stack/MEMW sequence, then same line/reset work.
 * Return0 only on full success. No rollback, TX drain, installed-driver check,
 * configuration snapshot or post-unlock FIFO serialization is provided. */
int uart_param_config(unsigned int port,const UartConfig *configuration)
{
    unsigned int timestamp_ms;
    const char *error_format;
    int source_line;
    const volatile UartConfig *configuration_words=configuration;
    if (port >= 3U) {
        timestamp_ms=esp_log_timestamp();
        error_format="E (%lu) %s: %s(%d): uart_num error\n";
        source_line=0x3e3;
    } else if (!configuration) {
        timestamp_ms=esp_log_timestamp();
        error_format="E (%lu) %s: %s(%d): param null\n";
        source_line=0x3e4;
    } else if (configuration_words->rx_flow_control_threshold&0x80U) {
        timestamp_ms=esp_log_timestamp();
        error_format="E (%lu) %s: %s(%d): rx flow thresh error\n";
        source_line=0x3e5;
    } else if (configuration_words->flow_control >= 4U) {
        timestamp_ms=esp_log_timestamp();
        error_format="E (%lu) %s: %s(%d): hw_flowctrl mode error\n";
        source_line=0x3e6;
    } else if (configuration_words->data_bits >= 4U) {
        timestamp_ms=esp_log_timestamp();
        error_format="E (%lu) %s: %s(%d): data bit error\n";
        source_line=0x3e7;
    } else goto configure;
invalid:
    esp_log_write(1,UART_LOG_TAG,error_format,timestamp_ms,
        UART_LOG_TAG,"uart_param_config",source_line);
    return -1;
configure:
    if (configuration_words->flags&3U) {
        timestamp_ms=esp_log_timestamp();
        esp_log_write(1,UART_LOG_TAG,"E (%lu) %s: %s(%d): not able to power down in light sleep\n",
            timestamp_ms,UART_LOG_TAG,"uart_param_config",0x3eb);
        return 0x106;
    }
    uart_module_enable(port);
    unsigned int source_clock=configuration_words->source_clock;
    if (source_clock == 0) source_clock=4;
    if (source_clock == 9) (void)periph_rtc_dig_clk8m_enable();
    unsigned int source_hz;
    int frequency_status=esp_clk_tree_src_get_freq_hz(source_clock,0,&source_hz);
    if (frequency_status != 0) {
        timestamp_ms=esp_log_timestamp();
        esp_log_write(1,UART_LOG_TAG,"E (%lu) %s: %s(%d): Invalid src_clk\n",
            timestamp_ms,UART_LOG_TAG,"uart_param_config",0x416);
        return frequency_status;
    }
    PortMuxWords *port_lock=&UART_DRIVER_CONTEXTS[port].spinlock;
    (void)xPortEnterCriticalTimeout(port_lock,-1);
    UartHal *uart_hal=&UART_DRIVER_CONTEXTS[port].hal;
    uart_hal_init(uart_hal,port);
    (void)esp_clk_tree_enable_src(source_clock,true);
    UartRegisterView *registers=uart_hal->dev;
    if (source_clock==4 || source_clock==9) {
        memw();
        unsigned int clock_configuration=registers->clk_conf;
        unsigned int clock_source_bits=source_clock==4 ? 0x100000U : 0x200000U;
        memw();
        registers->clk_conf=(clock_configuration&0xffcfffffU)|clock_source_bits;
    } else if (source_clock==11) {
        memw();
        unsigned int clock_configuration=registers->clk_conf;
        memw();
        registers->clk_conf=clock_configuration|0x300000U;
    } else abort();

    unsigned int parity_mode=configuration_words->parity;
    unsigned int baud_rate=(unsigned int)configuration_words->baud_rate;
    bool baud_set=false;
    if (baud_rate != 0) {
        unsigned long long maximum_baud_span = (unsigned long long)baud_rate * 4095ULL;
        unsigned int source_divider = (unsigned int)rom_unsigned_divide_u64(
            (unsigned long long)source_hz + maximum_baud_span - 1ULL,
            maximum_baud_span);
        if (source_divider-1U < 256U) {
            memw();
            unsigned int integer_register=registers->clkdiv;
            unsigned int divider=uart_unsigned_divide(source_hz<<4,baud_rate*source_divider);
            memw();
            registers->clkdiv=(integer_register&0xfffff000U)|((divider>>4)&0xfffU);
            memw();
            unsigned int fraction_register=registers->clkdiv;
            memw();
            registers->clkdiv=(fraction_register&0xff0fffffU)|((divider&15U)<<20);
            memw();
            unsigned int clock_register=registers->clk_conf;
            memw();
            volatile unsigned int clock_configuration_snapshot=clock_register;
            memw();
            clock_register=clock_configuration_snapshot;
            clock_register=(clock_register&0xfff00fffU)|(((source_divider-1U)&0xffU)<<12);
            memw();
            clock_configuration_snapshot = clock_register;
            memw();
            clock_register = clock_configuration_snapshot;
            memw();
            registers->clk_conf = clock_register;
            baud_set=true;
        }
    }
    uart_hal_set_parity(uart_hal,parity_mode);
    uart_hal_set_data_bit_num(uart_hal,configuration_words->data_bits);
    uart_hal_set_stop_bits(uart_hal,configuration_words->stop_bits);
    uart_hal_set_tx_idle_num(uart_hal,0);
    unsigned char receive_threshold=configuration_words->rx_flow_control_threshold;
    unsigned int flow_control_mode=configuration_words->flow_control;
    uart_hal_set_hw_flow_ctrl(uart_hal,flow_control_mode,receive_threshold);
    vPortExitCritical(port_lock);
    uart_hal_rxfifo_rst(uart_hal);
    uart_hal_txfifo_rst(uart_hal);
    if (baud_set) return 0;
    timestamp_ms=esp_log_timestamp();
    error_format="E (%lu) %s: %s(%d): baud rate unachievable\n";
    source_line=0x432;
    goto invalid;
}
