/* Medius v3.4.7 host — drivers/uart_line.c.
 */

#include "../include/types.h"

/* Native entry: 0x42007800. */
/*
 * Medius v3.4.7 — host application; 0x42007800.
 * Instruction-checked recovered C.
 * Original function-byte SHA-256:
 * 2478927f2b748005a91444f6ca4867b1d63464cd35f42ca2aee713da998ae7a1.
 */

/* Subtract consumed bytes modulo2^32 from each queued pattern position. Cache
 * driver, starting read index and positions pointer, but reload ring length and
 * write index on each iteration. Advance index, keeping it only if its SIGNED
 * value is below signed length, otherwise wrap to0. A negative adjusted position
 * advances the stored read cursor; nonnegative positions remain queued. Empty
 * queue returns without loading its array. No driver/port/bounds checks or lock;
 * caller must serialize a valid installed driver's queue. */
void uart_pattern_queue_update(int port,int consumed_bytes)
{
    MediusUartDriverSelectPrefix *driver = MEDIUS_UART_DRIVER_SELECT_OBJECTS[port];
    unsigned int index = driver->pattern_read;
    if (index != driver->pattern_write) {
        volatile int *positions = driver->pattern_positions;
        do {
            volatile int *slot = (volatile int *)((unsigned int)positions + index*4U);
            int adjusted = (int)((unsigned int)*slot - (unsigned int)consumed_bytes);
            ++index;
            *slot = adjusted;
            if ((int)index >= driver->pattern_length) index=0;
            if (adjusted < 0) driver->pattern_read=index;
        } while (index != driver->pattern_write);
    }
}

/* Native entry: 0x420079dc. */
/*
 * Medius v3.4.7 — host application; 0x420079dc.
 * Instruction-checked recovered C.
 * Original function-byte SHA-256:
 * 94bfc8ec805c359475e13821d4a1ea928e45161bea8e70876a590413f7fde3e6.
 */

/* Accept unsigned port0..2 and data encoding0..3 (5..8 bits). Enter the cached
 * port spinlock with timeout-1, call HAL using this port's context and release
 * the same lock. Return0. Invalid port/encoding logs native line0x13d/0x13e and
 * returns-1 without hardware writes. Does not require an installed UART driver,
 * check peripheral enable state or take the VFS write lock. */
int uart_set_word_length(unsigned int port,unsigned int data_bits)
{
    unsigned int timestamp;
    const char *format;
    int source_line;
    if (port >= 3U) {
        timestamp=esp_log_timestamp();
        format="E (%lu) %s: %s(%d): uart_num error\n";
        source_line=0x13d;
    } else if (data_bits >= 4U) {
        timestamp=esp_log_timestamp();
        format="E (%lu) %s: %s(%d): data bit error\n";
        source_line=0x13e;
    } else {
        PortMuxWords *lock=&UART_DRIVER_CONTEXTS[port].spinlock;
        (void)xPortEnterCriticalTimeout(lock,-1);
        uart_hal_set_data_bit_num(&UART_DRIVER_CONTEXTS[port].hal,data_bits);
        vPortExitCritical(lock);
        return 0;
    }
    esp_log_write(1,UART_LOG_TAG,format,timestamp,
        UART_LOG_TAG,"uart_set_word_length",source_line);
    return -1;
}

/* Native entry: 0x42007a50. */
/*
 * Medius v3.4.7 — host application; 0x42007a50.
 * Instruction-checked recovered C.
 * Original function-byte SHA-256:
 * ebb731280580bcb8e3c8f165ee4c9dbff1a18484881bae97c54e6e0cba0edd14.
 */

/* For unsigned port0..2, HAL reads the word-length field once and writes the
 * unchecked output. Return0 without any lock or installed/enabled-driver test.
 * Other ports log uart_num error at0x147 and return-1 without writing output. */
int uart_get_word_length(unsigned int port,unsigned int *data_bits)
{
    if (port < 3U) {
        uart_hal_get_data_bit_num(&UART_DRIVER_CONTEXTS[port].hal,data_bits);
        return 0;
    }
    unsigned int timestamp=esp_log_timestamp();
    esp_log_write(1,UART_LOG_TAG,"E (%lu) %s: %s(%d): uart_num error\n",
        timestamp,UART_LOG_TAG,"uart_get_word_length",0x147);
    return -1;
}

/* Native entry: 0x42007a94. */
/*
 * Medius v3.4.7 — host application; 0x42007a94.
 * Instruction-checked recovered C.
 * Original function-byte SHA-256:
 * a9937bec331534b18ef838df799fa4a207e913d591003c87413135b15cc071da.
 */

/* Accept unsigned port0..2 and stop encoding0..3, including native acceptance
 * of encoding0; 1/2/3 encode1/1.5/2 stop bits. Set HAL field under the cached port
 * spinlock, return0. Invalid port/encoding logs native line0x14e/0x14f, returns-1.
 * No installed/enabled-driver test or VFS-level lock. */
int uart_set_stop_bits(unsigned int port,unsigned int stop_bits)
{
    unsigned int timestamp;
    const char *format;
    int source_line;
    if (port >= 3U) {
        timestamp=esp_log_timestamp();
        format="E (%lu) %s: %s(%d): uart_num error\n";
        source_line=0x14e;
    } else if (stop_bits >= 4U) {
        timestamp=esp_log_timestamp();
        format="E (%lu) %s: %s(%d): stop bit error\n";
        source_line=0x14f;
    } else {
        PortMuxWords *lock=&UART_DRIVER_CONTEXTS[port].spinlock;
        (void)xPortEnterCriticalTimeout(lock,-1);
        uart_hal_set_stop_bits(&UART_DRIVER_CONTEXTS[port].hal,stop_bits);
        vPortExitCritical(lock);
        return 0;
    }
    esp_log_write(1,UART_LOG_TAG,format,timestamp,
        UART_LOG_TAG,"uart_set_stop_bits",source_line);
    return -1;
}

/* Native entry: 0x42007b08. */
/*
 * Medius v3.4.7 — host application; 0x42007b08.
 * Instruction-checked recovered C.
 * Original function-byte SHA-256:
 * aaf4b6ec31b44006d62d1410bc365cc71d2428d122b3a18a42388239b79bdd05.
 */

/* For unsigned port0..2, read HAL stop field into unchecked output under the
 * cached port spinlock and return0. Other ports log line0x158 and return-1,
 * leaving output untouched. No installed/enabled-driver test or output check. */
int uart_get_stop_bits(unsigned int port,unsigned int *stop_bits)
{
    if (port < 3U) {
        PortMuxWords *lock=&UART_DRIVER_CONTEXTS[port].spinlock;
        (void)xPortEnterCriticalTimeout(lock,-1);
        uart_hal_get_stop_bits(&UART_DRIVER_CONTEXTS[port].hal,stop_bits);
        vPortExitCritical(lock);
        return 0;
    }
    unsigned int timestamp=esp_log_timestamp();
    esp_log_write(1,UART_LOG_TAG,"E (%lu) %s: %s(%d): uart_num error\n",
        timestamp,UART_LOG_TAG,"uart_get_stop_bits",0x158);
    return -1;
}

/* Native entry: 0x42007b64. */
/*
 * Medius v3.4.7 — host application; 0x42007b64.
 * Instruction-checked recovered C.
 * Original function-byte SHA-256:
 * 4c8f6c73ddc4e44b9ed65380f612dd749dd6d99542579e15785e6d6161fd6069.
 */

/* For unsigned port0..2 pass the complete parity-mode word to HAL under the
 * cached port spinlock, return0. Mode is NOT validated; normal0/2/3 encode
 * disabled/even/odd. Invalid port logs line0x161 and returns-1. No installed/
 * enabled-driver test, output drain or VFS-level lock. */
int uart_set_parity(unsigned int port,unsigned int parity_mode)
{
    if (port < 3U) {
        PortMuxWords *lock=&UART_DRIVER_CONTEXTS[port].spinlock;
        (void)xPortEnterCriticalTimeout(lock,-1);
        uart_hal_set_parity(&UART_DRIVER_CONTEXTS[port].hal,parity_mode);
        vPortExitCritical(lock);
        return 0;
    }
    unsigned int timestamp=esp_log_timestamp();
    esp_log_write(1,UART_LOG_TAG,"E (%lu) %s: %s(%d): uart_num error\n",
        timestamp,UART_LOG_TAG,"uart_set_parity",0x161);
    return -1;
}

/* Native entry: 0x42007bc0. */
/*
 * Medius v3.4.7 — host application; 0x42007bc0.
 * Instruction-checked recovered C.
 * Original function-byte SHA-256:
 * 020f4088fef3621ecef51cbb6ebc127c700781afcfa840c5c04f19f38cf6523f.
 */

/* For unsigned port0..2 read HAL parity into unchecked output under the cached
 * spinlock and return0. Invalid port logs line0x16a and returns-1 without output
 * writes. No installed/enabled-driver test; enabled parity can require two
 * separate HAL register reads rather than a single atomic snapshot. */
int uart_get_parity(unsigned int port,unsigned int *parity_mode)
{
    if (port < 3U) {
        PortMuxWords *lock=&UART_DRIVER_CONTEXTS[port].spinlock;
        (void)xPortEnterCriticalTimeout(lock,-1);
        uart_hal_get_parity(&UART_DRIVER_CONTEXTS[port].hal,parity_mode);
        vPortExitCritical(lock);
        return 0;
    }
    unsigned int timestamp=esp_log_timestamp();
    esp_log_write(1,UART_LOG_TAG,"E (%lu) %s: %s(%d): uart_num error\n",
        timestamp,UART_LOG_TAG,"uart_get_parity",0x16a);
    return -1;
}

/* Native entry: 0x42007c1c. */
/*
 * Medius v3.4.7 — host application; 0x42007c1c.
 * Instruction-checked recovered C.
 * Original function-byte SHA-256:
 * 1286b0e48640a52efd127d29e1bd77ea3bb89b965fa7be95c15e699230af1ac9.
 */

/* Resolve this port's source clock at cached precision BEFORE taking its port
 * spinlock. Propagate clock-query failure after native Invalid src_clk log.
 * Reject baud0 or coarse divider outside1..256 without register writes. Compute
 * ceil(source_hz/(4095*baud)) in64 bits, then use the low32 bits of source_hz<<4
 * and baud*coarse in native QUOU. Read CLKDIV BEFORE that divide; write integer
 * low12 and fractional bits20..23 using separate fresh read/modify/writes.
 * Finally replace CLK_CONF bits12..19 via its native volatile stack snapshot
 * sequence; retain every explicit MEMW and all other register bits. Unlock and
 * return0. Invalid port/unachievable rate logs line0x173/0x188 and returns-1.
 * No driver-install check, output drain, clock-change retry or VFS lock. */
int uart_set_baudrate(unsigned int port,unsigned int baud)
{
    unsigned int timestamp;
    const char *format;
    int source_line;
    if (port >= 3U) {
        timestamp=esp_log_timestamp();
        format="E (%lu) %s: %s(%d): uart_num error\n";
        source_line=0x173;
    } else {
        unsigned int source_clock;
        unsigned int source_hz;
        uart_hal_get_sclk(&UART_DRIVER_CONTEXTS[port].hal,&source_clock);
        int error=esp_clk_tree_src_get_freq_hz(source_clock,0,&source_hz);
        if (error != 0) {
            timestamp=esp_log_timestamp();
            esp_log_write(1,UART_LOG_TAG,"E (%lu) %s: %s(%d): Invalid src_clk\n",
                timestamp,UART_LOG_TAG,"uart_set_baudrate",0x179);
            return error;
        }
        PortMuxWords *lock=&UART_DRIVER_CONTEXTS[port].spinlock;
        (void)xPortEnterCriticalTimeout(lock,-1);
        if (baud != 0) {
            unsigned long long span=(unsigned long long)baud*4095ULL;
            unsigned int coarse=(unsigned int)(((unsigned long long)source_hz+span-1ULL)/span);
            if (coarse-1U < 256U) {
                UartRegisterView *uart=UART_DRIVER_CONTEXTS[port].hal.dev;
                unsigned int denominator=baud*coarse;
                memw();
                unsigned int integer_register=uart->clkdiv;
                unsigned int divider=uart_unsigned_divide(source_hz<<4,denominator);
                memw();
                uart->clkdiv=(integer_register & 0xfffff000U) | ((divider>>4)&0xfffU);
                memw();
                unsigned int fraction_register=uart->clkdiv;
                memw();
                uart->clkdiv=(fraction_register & 0xff0fffffU) | ((divider&15U)<<20);
                memw();
                unsigned int clock_register=uart->clk_conf;
                memw();
                volatile unsigned int snapshot=clock_register;
                memw();
                clock_register=snapshot;
                clock_register=(clock_register&0xfff00fffU) | (((coarse-1U)&0xffU)<<12);
                memw();
                snapshot=clock_register;
                memw();
                clock_register=snapshot;
                memw();
                uart->clk_conf=clock_register;
                vPortExitCritical(lock);
                return 0;
            }
        }
        vPortExitCritical(lock);
        timestamp=esp_log_timestamp();
        format="E (%lu) %s: %s(%d): baud rate unachievable\n";
        source_line=0x188;
    }
    esp_log_write(1,UART_LOG_TAG,format,timestamp,
        UART_LOG_TAG,"uart_set_baudrate",source_line);
    return -1;
}

/* Native entry: 0x42007d70. */
/*
 * Medius v3.4.7 — host application; 0x42007d70.
 * Instruction-checked recovered C.
 * Original function-byte SHA-256:
 * 1d85b956f8ecff7a83ae40152528ef3598bb964a4c9e77fe2b98a1a1ae46b467.
 */

/* Validate unsigned port0..2; sample reset register first, clock-enable register
 * only if that port is not reset. Bits0x4/0x20/0x200 select UART0/1/2. Disabled
 * port logs line0x18f and returns-1. Read source selection and resolve cached
 * frequency BEFORE taking port spinlock; a clock error logs line0x195 and is
 * propagated. Under the cached lock, HAL samples CLKDIV/CLK_CONF and stores the
 * computed rate through unchecked output, then unlocks and returns0. Bad port
 * logs line0x18e and returns-1. No enable recheck, VFS lock or output NULL check. */
int uart_get_baudrate(unsigned int port,unsigned int *baud)
{
    unsigned int timestamp;
    const char *format;
    int source_line;
    if (port >= 3U) {
        timestamp=esp_log_timestamp();
        format="E (%lu) %s: %s(%d): uart_num error\n";
        source_line=0x18e;
    } else {
        unsigned int mask=port==0 ? 4U : (port==1 ? 0x20U : 0x200U);
        memw();
        unsigned int reset=MEDIUS_UART_SYSTEM_RESET0;
        if ((reset&mask)==0) {
            memw();
            unsigned int clock=MEDIUS_UART_SYSTEM_CLOCK0;
            if (clock&mask) {
                unsigned int source_clock;
                unsigned int source_hz;
                uart_hal_get_sclk(&UART_DRIVER_CONTEXTS[port].hal,&source_clock);
                int error=esp_clk_tree_src_get_freq_hz(source_clock,0,&source_hz);
                if (error != 0) {
                    timestamp=esp_log_timestamp();
                    esp_log_write(1,UART_LOG_TAG,"E (%lu) %s: %s(%d): Invalid src_clk\n",
                        timestamp,UART_LOG_TAG,"uart_get_baudrate",0x195);
                    return error;
                }
                PortMuxWords *lock=&UART_DRIVER_CONTEXTS[port].spinlock;
                (void)xPortEnterCriticalTimeout(lock,-1);
                uart_hal_get_baudrate(&UART_DRIVER_CONTEXTS[port].hal,baud,source_hz);
                vPortExitCritical(lock);
                return 0;
            }
        }
        timestamp=esp_log_timestamp();
        format="E (%lu) %s: %s(%d): uart port not enabled, unable to get register values\n";
        source_line=0x18f;
    }
    esp_log_write(1,UART_LOG_TAG,format,timestamp,
        UART_LOG_TAG,"uart_get_baudrate",source_line);
    return -1;
}
