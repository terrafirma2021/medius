/* Medius v3.4.7 host — UART GPIO routing, reservations and module enable.
 * Host preserves console UART0 during module enable. */

#include "../include/types.h"

/* Source reconstruction utilities; not additional native firmware entries. */
extern void uart_pin_iomux_output(unsigned char,int,bool) __asm__("gpio_iomux_out");
extern void uart_pin_iomux_input(unsigned int,unsigned int) __asm__("gpio_iomux_in");
extern int uart_pin_output_disable(int) __asm__("gpio_output_disable");
extern int uart_pin_sleep_enable(int) __asm__("gpio_sleep_sel_en");
extern int uart_pin_sleep_disable(int) __asm__("gpio_sleep_sel_dis");
extern int uart_pin_function_select(int,unsigned int) __asm__("gpio_func_sel");
extern int uart_pin_pullup_enable(int) __asm__("gpio_pullup_en");
extern unsigned long long uart_pin_reserve(unsigned long long) __asm__("esp_gpio_reserve");
extern unsigned long long uart_pin_revoke(unsigned long long) __asm__("esp_gpio_revoke");
static __inline__ __attribute__((always_inline)) unsigned int uart_pin_matrix_signal(unsigned int port,unsigned int signal)
{
    return UART_SIGNAL_CONNECTIONS[port].pins[signal].raw >> 20;
}
static __inline__ __attribute__((always_inline)) volatile unsigned int *uart_pin_reserved_words(volatile UartDriverContext *context)
{
    return (volatile unsigned int *)&context->reserved_gpio_mask;
}
static __inline__ __attribute__((always_inline)) unsigned long long uart_pin_bit(int gpio)
{
    return 1ULL << ((unsigned int)gpio & 63U);
}
static __inline__ __attribute__((always_inline)) unsigned int uart_pin_invalid_gpio(int gpio)
{
    return (unsigned int)((0xfffe000003c00000ULL >> ((unsigned int)gpio & 63U)) & 1ULL);
}
static __inline__ __attribute__((always_inline)) UartRegisterView *uart_pin_fixed_peripheral(unsigned int port)
{
    return (UartRegisterView *)(port==0 ? 0x60000000U : (port==1 ? 0x60010000U : 0x6002e000U));
}

/* Native entry: 0x42007678. */
/*
 * Medius v3.4.7 — host application; 0x42007678.
 * Instruction-checked recovered C.
 * Original function-byte SHA-256:
 * 22a108229c02e4c07ac24e1558dd66bf9909c7ac2e1748124c47382319304a2d.
 */

/* Load the packed signal descriptor BEFORE validating the port. Reject mux -1,
 * default GPIO -1 or a nonmatching signed15-bit default GPIO. On a match with
 * unsigned port<3, call IOMUX output using GPIO's low byte and signed4-bit mux;
 * input descriptors additionally enable their IOMUX input signal. Return1 for
 * a match even when port>=3 skipped both calls, otherwise0. No port/signal-table
 * bounds protection, lock or GPIO-result handling. The caller must supply a
 * valid descriptor address; negative/default fields retain native sign extension. */
int uart_try_set_iomux_pin(unsigned int port,unsigned int gpio,int signal_index)
{
    unsigned int offset=(port*5U+(unsigned int)signal_index)*4U;
    UartSignalPin descriptor;
    descriptor.raw=*(const volatile unsigned int *)((unsigned int)UART_SIGNAL_CONNECTIONS+offset);
    if (descriptor.iomux_function == -1 || descriptor.default_gpio == -1 ||
        (unsigned int)descriptor.default_gpio != gpio) return 0;
    if (port < 3U) {
        uart_pin_iomux_output((unsigned char)descriptor.default_gpio,descriptor.iomux_function,false);
        if (descriptor.input) uart_pin_iomux_input((unsigned int)descriptor.default_gpio,descriptor.signal);
    }
    return 1;
}

/* Native entry: 0x420076c8. */
/*
 * Medius v3.4.7 — host application; 0x420076c8.
 * Instruction-checked recovered C.
 * Original function-byte SHA-256:
 * 3797047b379d866b9cf25c0cbb3bac34fe6e16b80767d3ed62b39fa35045eb8c.
 */

/* For selected, assigned TX/RTS pins disable output; RX/CTS disconnect to matrix
 * constant1(0x38)/constant0(0x3c). Restore sleep selection for TX/RX only, then
 * reload each pin for release accounting and store -1 in that slot. Cache TX/
 * RTS pin for the check and first call; later accesses remain fresh across calls.
 * Release accounting is deliberately32-bit: pins with bit5 set contribute0,
 * other pins contribute1<<(pin&31). Revoke held_low&released with upper argument0;
 * after that call reload held_low, clear released bits, write LOW then zero HIGH.
 * No port check or lock. The native loss of upper reservation bits is retained. */
void uart_release_pin(int port,int release_tx,int release_rx,int release_rts,int release_cts)
{
    volatile UartDriverContext *context=&UART_DRIVER_CONTEXTS[port];
    unsigned int released=0;
    if (release_tx) {
        int gpio=context->tx_gpio;
        if (gpio >= 0) {
            (void)uart_pin_output_disable(gpio);
            (void)uart_pin_sleep_enable(context->tx_gpio);
            unsigned int current=(unsigned int)context->tx_gpio;
            released=(current&32U) ? 0U : (1U<<(current&31U));
            context->tx_gpio=-1;
        }
    }
    if (release_rx && context->rx_gpio >= 0) {
        gpio_matrix_in(0x38,uart_pin_matrix_signal((unsigned int)port,1),0);
        (void)uart_pin_sleep_enable(context->rx_gpio);
        unsigned int current=(unsigned int)context->rx_gpio;
        released |= (current&32U) ? 0U : (1U<<(current&31U));
        context->rx_gpio=-1;
    }
    if (release_rts) {
        int gpio=context->rts_gpio;
        if (gpio >= 0) {
            (void)uart_pin_output_disable(gpio);
            unsigned int current=(unsigned int)context->rts_gpio;
            released |= (current&32U) ? 0U : (1U<<(current&31U));
            context->rts_gpio=-1;
        }
    }
    if (release_cts && context->cts_gpio >= 0) {
        gpio_matrix_in(0x3c,uart_pin_matrix_signal((unsigned int)port,3),0);
        unsigned int current=(unsigned int)context->cts_gpio;
        released |= (current&32U) ? 0U : (1U<<(current&31U));
        context->cts_gpio=-1;
    }
    volatile unsigned int *held=uart_pin_reserved_words(context);
    unsigned int previous=held[0];
    (void)uart_pin_revoke((unsigned long long)(previous&released));
    previous=held[0];
    held[0]=previous&~released;
    held[1]=0;
}

/* Native entry: 0x42007838. */
/*
 * Medius v3.4.7 — host application; 0x42007838.
 * Instruction-checked recovered C.
 * Original function-byte SHA-256:
 * 411f75f2e60e544d4330174605d55c83092f4316ddc4ee26cc796557cd951a5c.
 */

/* Acquire module-lock SLOT using port's low16 bits, but access enabled/pin state
 * using the full32-bit port index. A nonzero enabled byte skips setup. For0..2,
 * enable bus clock under RCC lock: UART0/1 use CLOCK0 masks0x4/0x20; UART2 CLOCK1
 * bit0x200. Preserve this image's console port without reset; all other ports
 * route RX to constant1 only when its stored pin equals-1, then under RCC lock
 * clear reset, set CLK_CONF bit23, set reset, clear reset, clear bit23. Every
 * MMIO read/write has native MEMW. Use fixed peripheral addresses, not mutable
 * HAL pointers. Mark full-index enabled byte1 AFTER hardware setup and release
 * original lock slot. Out-of-range index still accesses/marks context storage;
 * caller must supply valid storage. No clock-status poll, timeout or GPIO check. */
void uart_module_enable(unsigned int port)
{
    NewlibLock *module_lock=&UART_DRIVER_CONTEXTS[port&0xffffU].module_lock;
    _lock_acquire(module_lock);
    volatile UartDriverContext *context=&UART_DRIVER_CONTEXTS[port];
    if (context->hardware_enabled == 0) {
        if (port < 3U) {
            volatile unsigned int *bus_clock=port==2 ? &UART_BUS_CLOCK1 : &UART_BUS_CLOCK0;
            volatile unsigned int *bus_reset=port==2 ? &UART_BUS_RESET1 : &UART_BUS_RESET0;
            unsigned int mask=port==0 ? 4U : (port==1 ? 0x20U : 0x200U);
            periph_rcc_enter();
            memw();
            unsigned int setting=*bus_clock;
            memw();
            *bus_clock=setting|mask;
            periph_rcc_exit();
            if ((int)port != UART_CONSOLE_PORT) {
                if (context->rx_gpio == -1)
                    gpio_matrix_in(0x38,uart_pin_matrix_signal(port,1),0);
                UartRegisterView *uart=uart_pin_fixed_peripheral(port);
                periph_rcc_enter();
                memw(); setting=*bus_reset;
                memw(); *bus_reset=setting&~mask;
                memw(); setting=uart->clk_conf;
                memw(); uart->clk_conf=setting|0x800000U;
                memw(); setting=*bus_reset;
                memw(); *bus_reset=setting|mask;
                memw(); setting=*bus_reset;
                memw(); *bus_reset=setting&~mask;
                memw(); setting=uart->clk_conf;
                memw(); uart->clk_conf=setting&0xff7fffffU;
                periph_rcc_exit();
            }
        }
        context->hardware_enabled=1;
    }
    _lock_release(module_lock);
}

/* Native entry: 0x42007e48. */
/*
 * Medius v3.4.7 — host application; 0x42007e48.
 * Instruction-checked recovered C.
 * Original function-byte SHA-256:
 * 2e4535242253d883bf7fc1530a991ae07690fae66ee269550e7f6ce212f05c6f.
 */

/* Validate unsigned port<3, then TX/RX/RTS/CTS in that order using native GPIO
 * mask tests. Negative pins mean unchanged. Nonnegative pin validation aliases
 * modulo64: reject low6-bit positions22..25 and49..63; no additional >=64 guard.
 * Bad argument logs native line0x338/0x33a..0x33d and returns-1 BEFORE release.
 * Release replaced pins, then form a reservation candidate from STRICTLY POSITIVE
 * pins (GPIO0 omitted). Configure TX, RX, RTS, CTS in order; prefer dedicated
 * IOMUX except shared TX/RX forces matrix. Sleep selection is disabled for TX/RX.
 * Matrix RX/CTS remove their candidate bit; CTS also enables pullup. All GPIO
 * statuses are ignored. Store reserved HIGH word then LOW, reserve mask, warn
 * once per already-busy bit in ascending order, and return0 even on conflicts.
 * No rollback, module/port lock, distinct-pin test or installed-driver check. */
int uart_set_pin(int port,int tx,int rx,int rts,int cts)
{
    unsigned int timestamp;
    const char *format;
    int source_line;
    if ((unsigned int)port >= 3U) {
        timestamp=esp_log_timestamp();
        format="E (%lu) %s: %s(%d): uart_num error\n";
        source_line=0x338;
    } else if (tx >= 0 && uart_pin_invalid_gpio(tx)) {
        timestamp=esp_log_timestamp();
        format="E (%lu) %s: %s(%d): tx_io_num error\n";
        source_line=0x33a;
    } else if (rx >= 0 && uart_pin_invalid_gpio(rx)) {
        timestamp=esp_log_timestamp();
        format="E (%lu) %s: %s(%d): rx_io_num error\n";
        source_line=0x33b;
    } else if (rts >= 0 && uart_pin_invalid_gpio(rts)) {
        timestamp=esp_log_timestamp();
        format="E (%lu) %s: %s(%d): rts_io_num error\n";
        source_line=0x33c;
    } else if (cts >= 0 && uart_pin_invalid_gpio(cts)) {
        timestamp=esp_log_timestamp();
        format="E (%lu) %s: %s(%d): cts_io_num error\n";
        source_line=0x33d;
    } else goto configure;
    esp_log_write(1,UART_LOG_TAG,format,timestamp,
        UART_LOG_TAG,"uart_set_pin",source_line);
    return -1;
configure:
    uart_release_pin(port,tx>=0,rx>=0,rts>=0,cts>=0);
    unsigned long long reserved=0;
    if (tx>0) reserved|=uart_pin_bit(tx);
    if (rx>0) reserved|=uart_pin_bit(rx);
    if (rts>0) reserved|=uart_pin_bit(rts);
    if (cts>0) reserved|=uart_pin_bit(cts);
    volatile UartDriverContext *context=&UART_DRIVER_CONTEXTS[port];
    if (tx>=0) {
        context->tx_gpio=tx;
        (void)uart_pin_sleep_disable(tx);
        if (tx==rx || !uart_try_set_iomux_pin((unsigned int)port,(unsigned int)tx,0)) {
            (void)uart_pin_function_select(tx,1);
            gpio_matrix_out((unsigned int)tx,uart_pin_matrix_signal((unsigned int)port,0),0,0);
        }
    }
    if (rx>=0) {
        context->rx_gpio=rx;
        (void)uart_pin_sleep_disable(rx);
        if (tx==rx || !uart_try_set_iomux_pin((unsigned int)port,(unsigned int)rx,1)) {
            reserved&=~uart_pin_bit(rx);
            (void)gpio_input_enable((unsigned int)rx);
            gpio_matrix_in((unsigned int)rx,uart_pin_matrix_signal((unsigned int)port,1),0);
        }
    }
    if (rts>=0) {
        context->rts_gpio=rts;
        if (!uart_try_set_iomux_pin((unsigned int)port,(unsigned int)rts,2)) {
            (void)uart_pin_function_select(rts,1);
            gpio_matrix_out((unsigned int)rts,uart_pin_matrix_signal((unsigned int)port,2),0,0);
        }
    }
    if (cts>=0) {
        context->cts_gpio=cts;
        if (!uart_try_set_iomux_pin((unsigned int)port,(unsigned int)cts,3)) {
            reserved&=~uart_pin_bit(cts);
            (void)uart_pin_pullup_enable(cts);
            (void)gpio_input_enable((unsigned int)cts);
            gpio_matrix_in((unsigned int)cts,uart_pin_matrix_signal((unsigned int)port,3),0);
        }
    }
    volatile unsigned int *held=uart_pin_reserved_words(context);
    held[1]=(unsigned int)(reserved>>32);
    held[0]=(unsigned int)reserved;
    unsigned long long conflicts=uart_pin_reserve(reserved)&reserved;
    while (conflicts != 0) {
        unsigned int gpio=(unsigned int)__builtin_ctzll(conflicts);
        conflicts&=conflicts-1ULL;
        timestamp=esp_log_timestamp();
        esp_log_write(2,UART_LOG_TAG,
            "W (%lu) %s: GPIO %d is not usable, maybe used by others\n",
            timestamp,UART_LOG_TAG,gpio);
    }
    return 0;
}
