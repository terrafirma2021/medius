/* Medius v3.4.7 device — UART GPIO routing, reservations and module enable.
 * Device resets every enabled UART, including UART0. */

#include "../include/types.h"

/* Source reconstruction utilities; not additional native firmware entries. */
extern void uart_pin_iomux_output(unsigned char gpio,int function,bool invert_output) __asm__("gpio_iomux_out");
extern void uart_pin_iomux_input(unsigned int gpio,unsigned int signal) __asm__("gpio_iomux_in");
extern int uart_pin_output_disable(int gpio) __asm__("gpio_output_disable");
extern int uart_pin_sleep_enable(int gpio) __asm__("gpio_sleep_sel_en");
extern int uart_pin_sleep_disable(int gpio) __asm__("gpio_sleep_sel_dis");
extern int uart_pin_function_select(int gpio,unsigned int function) __asm__("gpio_func_sel");
extern int uart_pin_pullup_enable(int gpio) __asm__("gpio_pullup_en");
extern unsigned long long uart_pin_reserve(unsigned long long mask) __asm__("esp_gpio_reserve");
extern unsigned long long uart_pin_revoke(unsigned long long mask) __asm__("esp_gpio_revoke");
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

/* Native entry: 0x42011c9c. */
/*
 * Medius v3.4.7 — device application; 0x42011c9c.
 * Instruction-checked recovered C.
 * Original function-byte SHA-256:
 * f8b8aa4b552736702ecadf709aa12d96ad30e2d24f228d3e66f06e1286735f61.
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

/* Native entry: 0x42011cec. */
/*
 * Medius v3.4.7 — device application; 0x42011cec.
 * Instruction-checked recovered C.
 * Original function-byte SHA-256:
 * 3bc30efd9740b06d222eb43e85bba23c6a501f449dfe76e1775545f414138fbb.
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
    unsigned int released_mask=0;
    if (release_tx) {
        int gpio=context->tx_gpio;
        if (gpio >= 0) {
            (void)uart_pin_output_disable(gpio);
            (void)uart_pin_sleep_enable(context->tx_gpio);
            unsigned int current_gpio=(unsigned int)context->tx_gpio;
            released_mask=(current_gpio&32U) ? 0U : (1U<<(current_gpio&31U));
            context->tx_gpio=-1;
        }
    }
    if (release_rx && context->rx_gpio >= 0) {
        gpio_matrix_in(0x38,uart_pin_matrix_signal((unsigned int)port,1),0);
        (void)uart_pin_sleep_enable(context->rx_gpio);
        unsigned int current_gpio=(unsigned int)context->rx_gpio;
        released_mask |= (current_gpio&32U) ? 0U : (1U<<(current_gpio&31U));
        context->rx_gpio=-1;
    }
    if (release_rts) {
        int gpio=context->rts_gpio;
        if (gpio >= 0) {
            (void)uart_pin_output_disable(gpio);
            unsigned int current_gpio=(unsigned int)context->rts_gpio;
            released_mask |= (current_gpio&32U) ? 0U : (1U<<(current_gpio&31U));
            context->rts_gpio=-1;
        }
    }
    if (release_cts && context->cts_gpio >= 0) {
        gpio_matrix_in(0x3c,uart_pin_matrix_signal((unsigned int)port,3),0);
        unsigned int current_gpio=(unsigned int)context->cts_gpio;
        released_mask |= (current_gpio&32U) ? 0U : (1U<<(current_gpio&31U));
        context->cts_gpio=-1;
    }
    volatile unsigned int *reservation_words=uart_pin_reserved_words(context);
    unsigned int previous_reservations=reservation_words[0];
    (void)uart_pin_revoke((unsigned long long)(previous_reservations&released_mask));
    previous_reservations=reservation_words[0];
    reservation_words[0]=previous_reservations&~released_mask;
    reservation_words[1]=0;
}

/* Native entry: 0x42011e24. */
/*
 * Medius v3.4.7 — device application; 0x42011e24.
 * Instruction-checked recovered C.
 * Original function-byte SHA-256:
 * 9d19c94bc7350c8836f43d5051781fa2067e8ba70b4ca72e2ba190341431f202.
 */

/* Acquire module-lock SLOT using port's low16 bits, but access enabled/pin state
 * using the full32-bit port index. A nonzero enabled byte skips setup. For0..2,
 * enable bus clock under RCC lock: UART0/1 use CLOCK0 masks0x4/0x20; UART2 CLOCK1
 * bit0x200. This image resets every valid port, including UART0 (console=-1).
 * Route RX to constant1 only when its stored pin equals-1, then under RCC lock
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
            unsigned int register_value=*bus_clock;
            memw();
            *bus_clock=register_value|mask;
            periph_rcc_exit();
            if ((int)port != UART_CONSOLE_PORT) {
                if (context->rx_gpio == -1)
                    gpio_matrix_in(0x38,uart_pin_matrix_signal(port,1),0);
                UartRegisterView *registers=uart_pin_fixed_peripheral(port);
                periph_rcc_enter();
                memw();
                register_value=*bus_reset;
                memw();
                *bus_reset=register_value&~mask;
                memw();
                register_value=registers->clk_conf;
                memw();
                registers->clk_conf=register_value|0x800000U;
                memw();
                register_value=*bus_reset;
                memw();
                *bus_reset=register_value|mask;
                memw();
                register_value=*bus_reset;
                memw();
                *bus_reset=register_value&~mask;
                memw();
                register_value=registers->clk_conf;
                memw();
                registers->clk_conf=register_value&0xff7fffffU;
                periph_rcc_exit();
            }
        }
        context->hardware_enabled=1;
    }
    _lock_release(module_lock);
}

/* Native entry: 0x42012168. */
/*
 * Medius v3.4.7 — device application; 0x42012168.
 * Instruction-checked recovered C.
 * Original function-byte SHA-256:
 * 02b6009ecb61b70c1cd34dc7233409ca29cc0dec842d8c3df9a0a80170a301f2.
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
int uart_set_pin(int port,int tx_gpio,int rx_gpio,int rts_gpio,int cts_gpio)
{
    unsigned int timestamp_ms;
    const char *error_format;
    int source_line;
    if ((unsigned int)port >= 3U) {
        timestamp_ms=esp_log_timestamp();
        error_format="E (%lu) %s: %s(%d): uart_num error\n";
        source_line=0x338;
    } else if (tx_gpio >= 0 && uart_pin_invalid_gpio(tx_gpio)) {
        timestamp_ms=esp_log_timestamp();
        error_format="E (%lu) %s: %s(%d): tx_io_num error\n";
        source_line=0x33a;
    } else if (rx_gpio >= 0 && uart_pin_invalid_gpio(rx_gpio)) {
        timestamp_ms=esp_log_timestamp();
        error_format="E (%lu) %s: %s(%d): rx_io_num error\n";
        source_line=0x33b;
    } else if (rts_gpio >= 0 && uart_pin_invalid_gpio(rts_gpio)) {
        timestamp_ms=esp_log_timestamp();
        error_format="E (%lu) %s: %s(%d): rts_io_num error\n";
        source_line=0x33c;
    } else if (cts_gpio >= 0 && uart_pin_invalid_gpio(cts_gpio)) {
        timestamp_ms=esp_log_timestamp();
        error_format="E (%lu) %s: %s(%d): cts_io_num error\n";
        source_line=0x33d;
    } else goto configure;
    esp_log_write(1,UART_LOG_TAG,error_format,timestamp_ms,
        UART_LOG_TAG,"uart_set_pin",source_line);
    return -1;
configure:
    uart_release_pin(port,tx_gpio>=0,rx_gpio>=0,rts_gpio>=0,cts_gpio>=0);
    unsigned long long reservation_mask=0;
    if (tx_gpio>0) reservation_mask|=uart_pin_bit(tx_gpio);
    if (rx_gpio>0) reservation_mask|=uart_pin_bit(rx_gpio);
    if (rts_gpio>0) reservation_mask|=uart_pin_bit(rts_gpio);
    if (cts_gpio>0) reservation_mask|=uart_pin_bit(cts_gpio);
    volatile UartDriverContext *context=&UART_DRIVER_CONTEXTS[port];
    if (tx_gpio>=0) {
        context->tx_gpio=tx_gpio;
        (void)uart_pin_sleep_disable(tx_gpio);
        if (tx_gpio==rx_gpio || !uart_try_set_iomux_pin((unsigned int)port,(unsigned int)tx_gpio,0)) {
            (void)uart_pin_function_select(tx_gpio,1);
            gpio_matrix_out((unsigned int)tx_gpio,uart_pin_matrix_signal((unsigned int)port,0),0,0);
        }
    }
    if (rx_gpio>=0) {
        context->rx_gpio=rx_gpio;
        (void)uart_pin_sleep_disable(rx_gpio);
        if (tx_gpio==rx_gpio || !uart_try_set_iomux_pin((unsigned int)port,(unsigned int)rx_gpio,1)) {
            reservation_mask&=~uart_pin_bit(rx_gpio);
            (void)gpio_input_enable((unsigned int)rx_gpio);
            gpio_matrix_in((unsigned int)rx_gpio,uart_pin_matrix_signal((unsigned int)port,1),0);
        }
    }
    if (rts_gpio>=0) {
        context->rts_gpio=rts_gpio;
        if (!uart_try_set_iomux_pin((unsigned int)port,(unsigned int)rts_gpio,2)) {
            (void)uart_pin_function_select(rts_gpio,1);
            gpio_matrix_out((unsigned int)rts_gpio,uart_pin_matrix_signal((unsigned int)port,2),0,0);
        }
    }
    if (cts_gpio>=0) {
        context->cts_gpio=cts_gpio;
        if (!uart_try_set_iomux_pin((unsigned int)port,(unsigned int)cts_gpio,3)) {
            reservation_mask&=~uart_pin_bit(cts_gpio);
            (void)uart_pin_pullup_enable(cts_gpio);
            (void)gpio_input_enable((unsigned int)cts_gpio);
            gpio_matrix_in((unsigned int)cts_gpio,uart_pin_matrix_signal((unsigned int)port,3),0);
        }
    }
    volatile unsigned int *reservation_words=uart_pin_reserved_words(context);
    reservation_words[1]=(unsigned int)(reservation_mask>>32);
    reservation_words[0]=(unsigned int)reservation_mask;
    unsigned long long conflict_mask=uart_pin_reserve(reservation_mask)&reservation_mask;
    while (conflict_mask != 0) {
        unsigned int gpio=(unsigned int)__builtin_ctzll(conflict_mask);
        conflict_mask&=conflict_mask-1ULL;
        timestamp_ms=esp_log_timestamp();
        esp_log_write(2,UART_LOG_TAG,
            "W (%lu) %s: GPIO %d is not usable, maybe used by others\n",
            timestamp_ms,UART_LOG_TAG,gpio);
    }
    return 0;
}
