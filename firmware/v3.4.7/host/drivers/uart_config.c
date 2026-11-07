/* Medius v3.4.7 host — drivers/uart_config.c.
 */

#include "../include/types.h"

/* Native entry: 0x42008368. */
/*
 * Medius v3.4.7 — host application; 0x42008368.
 * Instruction-checked recovered C.
 * Original function-byte SHA-256:
 * e7b34048538dea3e8c8fbde758f740457e237818c2f8b77c15edfbaea8d3934f.
 */

/* Apply the 32-byte configuration with native validation and side-effect order.
 * Reject bad unsigned port, NULL record, threshold bit7, flow>=4 or data>=4 with
 * ESP_FAIL(-1); flags low2 return NOT_SUPPORTED(0x106). Parity/stop/baud are not
 * validated at entry. Other flag/padding bits are ignored. Enable module first,
 * then sample source clock (0 defaults toAPB4). RTC9 acquires a reference whose
 * boolean result is ignored; frequency failure logs and propagates its status,
 * retaining module/RTC side effects. Under port spinlock initialize HAL and call
 * source-enable stub. Select4/9/11 in CLK_CONF; any other successfully resolved
 * clock aborts AFTER initialization, without unlocking. Cache parity BEFORE baud.
 * Baud0/unachievable divider skips baud writes but still applies parity, fresh
 * data/stop fields, TX idle0 and fresh flow/threshold; then unlocks and resets RX
 * followed by TX FIFO before logging/returning-1. Successful baud uses64-bit
 * ceiling and native32-bit QUOU, CLKDIV read before divide, separate fraction/
 * integer updates and the CLK_CONF stack/MEMW sequence, then same line/reset work.
 * Return0 only on full success. No rollback, TX drain, installed-driver check,
 * configuration snapshot or post-unlock FIFO serialization is provided. */
int uart_param_config(unsigned int port,const UartConfig *configuration)
{
    unsigned int timestamp;
    const char *format;
    int source_line;
    const volatile UartConfig *in=configuration;
    if (port >= 3U) {
        timestamp=esp_log_timestamp();
        format="E (%lu) %s: %s(%d): uart_num error\n";
        source_line=0x3e3;
    } else if (!configuration) {
        timestamp=esp_log_timestamp();
        format="E (%lu) %s: %s(%d): param null\n";
        source_line=0x3e4;
    } else if (in->rx_flow_control_threshold&0x80U) {
        timestamp=esp_log_timestamp();
        format="E (%lu) %s: %s(%d): rx flow thresh error\n";
        source_line=0x3e5;
    } else if (in->flow_control >= 4U) {
        timestamp=esp_log_timestamp();
        format="E (%lu) %s: %s(%d): hw_flowctrl mode error\n";
        source_line=0x3e6;
    } else if (in->data_bits >= 4U) {
        timestamp=esp_log_timestamp();
        format="E (%lu) %s: %s(%d): data bit error\n";
        source_line=0x3e7;
    } else goto configure;
invalid:
    esp_log_write(1,UART_LOG_TAG,format,timestamp,
        UART_LOG_TAG,"uart_param_config",source_line);
    return -1;
configure:
    if (in->flags&3U) {
        timestamp=esp_log_timestamp();
        esp_log_write(1,UART_LOG_TAG,"E (%lu) %s: %s(%d): not able to power down in light sleep\n",
            timestamp,UART_LOG_TAG,"uart_param_config",0x3eb);
        return 0x106;
    }
    uart_module_enable(port);
    unsigned int source_clock=in->source_clock;
    if (source_clock == 0) source_clock=4;
    if (source_clock == 9) (void)periph_rtc_dig_clk8m_enable();
    unsigned int source_hz;
    int error=esp_clk_tree_src_get_freq_hz(source_clock,0,&source_hz);
    if (error != 0) {
        timestamp=esp_log_timestamp();
        esp_log_write(1,UART_LOG_TAG,"E (%lu) %s: %s(%d): Invalid src_clk\n",
            timestamp,UART_LOG_TAG,"uart_param_config",0x416);
        return error;
    }
    PortMuxWords *lock=&UART_DRIVER_CONTEXTS[port].spinlock;
    (void)xPortEnterCriticalTimeout(lock,-1);
    UartHal *hal=&UART_DRIVER_CONTEXTS[port].hal;
    uart_hal_init(hal,port);
    (void)esp_clk_tree_enable_src(source_clock,true);
    UartRegisterView *uart=hal->dev;
    if (source_clock==4 || source_clock==9) {
        memw();
        unsigned int setting=uart->clk_conf;
        unsigned int selected=source_clock==4 ? 0x100000U : 0x200000U;
        memw();
        uart->clk_conf=(setting&0xffcfffffU)|selected;
    } else if (source_clock==11) {
        memw();
        unsigned int setting=uart->clk_conf;
        memw();
        uart->clk_conf=setting|0x300000U;
    } else abort();

    unsigned int parity=in->parity;
    unsigned int baud=(unsigned int)in->baud_rate;
    bool baud_set=false;
    if (baud != 0) {
        unsigned long long span=(unsigned long long)baud*4095ULL;
        unsigned int coarse=(unsigned int)(((unsigned long long)source_hz+span-1ULL)/span);
        if (coarse-1U < 256U) {
            memw();
            unsigned int integer_register=uart->clkdiv;
            unsigned int divider=uart_unsigned_divide(source_hz<<4,baud*coarse);
            memw();
            uart->clkdiv=(integer_register&0xfffff000U)|((divider>>4)&0xfffU);
            memw();
            unsigned int fraction_register=uart->clkdiv;
            memw();
            uart->clkdiv=(fraction_register&0xff0fffffU)|((divider&15U)<<20);
            memw();
            unsigned int clock_register=uart->clk_conf;
            memw();
            volatile unsigned int snapshot=clock_register;
            memw();
            clock_register=snapshot;
            clock_register=(clock_register&0xfff00fffU)|(((coarse-1U)&0xffU)<<12);
            memw(); snapshot=clock_register;
            memw(); clock_register=snapshot;
            memw(); uart->clk_conf=clock_register;
            baud_set=true;
        }
    }
    uart_hal_set_parity(hal,parity);
    uart_hal_set_data_bit_num(hal,in->data_bits);
    uart_hal_set_stop_bits(hal,in->stop_bits);
    uart_hal_set_tx_idle_num(hal,0);
    unsigned char threshold=in->rx_flow_control_threshold;
    unsigned int flow=in->flow_control;
    uart_hal_set_hw_flow_ctrl(hal,flow,threshold);
    vPortExitCritical(lock);
    uart_hal_rxfifo_rst(hal);
    uart_hal_txfifo_rst(hal);
    if (baud_set) return 0;
    timestamp=esp_log_timestamp();
    format="E (%lu) %s: %s(%d): baud rate unachievable\n";
    source_line=0x432;
    goto invalid;
}
