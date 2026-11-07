/* Medius v3.4.7 host — drivers/uart_hal.c.
 */

#include "../include/types.h"

/* Native entry: 0x40385e6c. */
/*
 * Medius v3.4.7 — host application; 0x40385e6c.
 * Instruction-checked recovered C.
 * Original function-byte SHA-256:
 * 8963599601dfb0813497f0c5b23d09de773259409fc0370b374ecf1a9003ee02.
 */

/* Cache the peripheral, set RXFIFO_RST bit17 in CONF0, then freshly reread and
 * clear bit17. MEMW precedes both reads and writes. No wait, timeout, other FIFO
 * reset, driver-buffer adjustment, argument validation or lock is supplied. */
void uart_hal_rxfifo_rst(UartHal *hal)
{
    UartRegisterView *uart=hal->dev;
    memw();
    unsigned int setting=uart->conf0;
    memw();
    uart->conf0=setting|0x20000U;
    memw();
    setting=uart->conf0;
    memw();
    uart->conf0=setting&0xfffdffffU;
}

/* Native entry: 0x4201eabc. */
/*
 * Medius v3.4.7 — host application; 0x4201eabc.
 * Instruction-checked recovered C.
 * Original function-byte SHA-256:
 * d41301e76681f7ea32c8bfdbd9b525f0dac93febb399b14fc3c9e16f9499094f.
 */

/* After MEMW read CLK_CONF bits20..21 once. Encode selection2 as RTC clock9,
 * selection3 as XTAL11, otherwise APB4 (including selection0). Write unchecked
 * 32-bit output. No frequency lookup, validation or synchronization lock. */
void uart_hal_get_sclk(UartHal *hal,unsigned int *source_clock)
{
    UartRegisterView *uart=hal->dev;
    memw();
    unsigned int selection=(uart->clk_conf>>20)&3U;
    *(volatile unsigned int *)source_clock=selection==2 ? 9U : (selection==3 ? 11U : 4U);
}

/* Native entry: 0x4201eae0. */
/*
 * Medius v3.4.7 — host application; 0x4201eae0.
 * Instruction-checked recovered C.
 * Original function-byte SHA-256:
 * 3ab5a4a8c928243069c010e87cb770289e1a547eb9bd61a952907ae2ed09c12f.
 */

/* Read CLKDIV once then CLK_CONF once with explicit MEMW. Preserve the latter's
 * volatile stack store/reload and both intervening barriers. Reconstruct the
 * 12.4 divider, multiply by coarse bits12..19 plus1, then native QUOU using the
 * low32 bits of source_hz<<4. Store unchecked output. No zero-divisor guard,
 * source-clock lookup, counter retry or lock; native divide behavior is retained. */
void uart_hal_get_baudrate(UartHal *hal,unsigned int *baud,unsigned int source_hz)
{
    UartRegisterView *uart=hal->dev;
    unsigned int numerator=source_hz<<4;
    memw();
    unsigned int divider=uart->clkdiv;
    memw();
    unsigned int clock=uart->clk_conf;
    memw();
    volatile unsigned int snapshot=clock;
    memw();
    clock=snapshot;
    unsigned int combined=((divider&0xfffU)<<4)|((divider>>20)&15U);
    unsigned int denominator=combined*(((clock>>12)&0xffU)+1U);
    *(volatile unsigned int *)baud=uart_unsigned_divide(numerator,denominator);
}

/* Native entry: 0x4201eb18. */
/*
 * Medius v3.4.7 — host application; 0x4201eb18.
 * Instruction-checked recovered C.
 * Original function-byte SHA-256:
 * 406a146b79a002910980a51f1fa4514f15f4dc9f62794834f6c983bf7a001094.
 */

/* Replace CONF0 bits4..5 with the low2 stop-encoding bits using one cached
 * peripheral and a single read/modify/write. MEMW before read and write. No
 * encoding validation, port lookup, output wait or lock. Other bits retained. */
void uart_hal_set_stop_bits(UartHal *hal,unsigned int stop_bits)
{
    UartRegisterView *uart=hal->dev;
    unsigned int encoded=(stop_bits&3U)<<4;
    memw();
    unsigned int setting=uart->conf0;
    memw();
    uart->conf0=(setting&0xffffffcfU)|encoded;
}

/* Native entry: 0x4201eb38. */
/*
 * Medius v3.4.7 — host application; 0x4201eb38.
 * Instruction-checked recovered C.
 * Original function-byte SHA-256:
 * abfd1490ac1af991126556f88b1204e1e868d0456f3176fc492d9a17653bbda6.
 */

/* MEMW, one CONF0 read, extract bits4..5 and store unchecked 32-bit output.
 * No lock, encoding translation, port validation or peripheral-enable check. */
void uart_hal_get_stop_bits(UartHal *hal,unsigned int *stop_bits)
{
    UartRegisterView *uart=hal->dev;
    memw();
    *(volatile unsigned int *)stop_bits=(uart->conf0>>4)&3U;
}

/* Native entry: 0x4201eb4c. */
/*
 * Medius v3.4.7 — host application; 0x4201eb4c.
 * Instruction-checked recovered C.
 * Original function-byte SHA-256:
 * 653cf7b94a2f2b3c17aa435e008868e8f676f85b08260c07cc5f7fd758baaeb6.
 */

/* Replace CONF0 bits2..3 with low2 word-length bits (0..3 means5..8). Cache
 * peripheral and preserve other bits in one read/modify/write with MEMW before
 * read and write. No input validation, port lookup, lock or transmit drain. */
void uart_hal_set_data_bit_num(UartHal *hal,unsigned int data_bits)
{
    UartRegisterView *uart=hal->dev;
    unsigned int encoded=(data_bits&3U)<<2;
    memw();
    unsigned int setting=uart->conf0;
    memw();
    uart->conf0=(setting&0xfffffff3U)|encoded;
}

/* Native entry: 0x4201eb6c. */
/*
 * Medius v3.4.7 — host application; 0x4201eb6c.
 * Instruction-checked recovered C.
 * Original function-byte SHA-256:
 * a0e6c4ea9729185963ba1158d2902d450d351ab84e1a4fe59204639993bd76ad.
 */

/* MEMW, one CONF0 read, extract bits2..3 and store unchecked 32-bit output.
 * Returns hardware encoding0..3, not numeric bit count; no validation or lock. */
void uart_hal_get_data_bit_num(UartHal *hal,unsigned int *data_bits)
{
    UartRegisterView *uart=hal->dev;
    memw();
    *(volatile unsigned int *)data_bits=(uart->conf0>>2)&3U;
}

/* Native entry: 0x4201eb80. */
/*
 * Medius v3.4.7 — host application; 0x4201eb80.
 * Instruction-checked recovered C.
 * Original function-byte SHA-256:
 * 993c880eaf2dc4fd743a0c9d00101671e57f01ab13d4950e754dfb4c5d71edab.
 */

/* For any nonzero mode first replace CONF0 bit0 with mode bit0. Then ALWAYS
 * freshly read/modify/write enable bit1 from mode bit1. Zero mode preserves bit0
 * while disabling parity. Each read/write has preceding MEMW; cache peripheral,
 * preserve unrelated bits, and perform no mode validation or lock. Arbitrary
 * modes retain these bit operations rather than being normalized to0/2/3. */
void uart_hal_set_parity(UartHal *hal,unsigned int parity_mode)
{
    UartRegisterView *uart=hal->dev;
    unsigned int setting;
    if (parity_mode != 0) {
        memw();
        setting=uart->conf0;
        memw();
        uart->conf0=(setting&0xfffffffeU)|(parity_mode&1U);
    }
    memw();
    setting=uart->conf0;
    memw();
    uart->conf0=(setting&0xfffffffdU)|(parity_mode&2U);
}

/* Native entry: 0x4201ebb8. */
/*
 * Medius v3.4.7 — host application; 0x4201ebb8.
 * Instruction-checked recovered C.
 * Original function-byte SHA-256:
 * 1afedc2fb958ae87b7bd44b69f1cb6202a929defb55d155cf9f32287b43b3610.
 */

/* MEMW/read CONF0 enable bit1. If clear store0 without a second read; otherwise
 * another MEMW/read samples bit0 and stores2|bit0. The two samples may differ;
 * do not fold them into one snapshot. Unchecked HAL/output pointers, no lock. */
void uart_hal_get_parity(UartHal *hal,unsigned int *parity_mode)
{
    UartRegisterView *uart=hal->dev;
    unsigned int mode=0;
    memw();
    unsigned int enabled=uart->conf0;
    if (enabled&2U) {
        memw();
        mode=2U|(uart->conf0&1U);
    }
    *(volatile unsigned int *)parity_mode=mode;
}

/* Native entry: 0x40385e44. */
/*
 * Medius v3.4.7 — host application; 0x40385e44.
 * Instruction-checked recovered C.
 * Original function-byte SHA-256:
 * f9f6e6a05df770664d5543443e2199b5fb5642222b7bb50b1214bd41801abc4b.
 */

/* Pulse TXFIFO_RST bit18 using a cached peripheral: read/set, then FRESH read/
 * clear. MEMW before all four accesses. No drain, timeout, queue bookkeeping,
 * input validation or lock. The caller owns serialization and pending data. */
void uart_hal_txfifo_rst(UartHal *hal)
{
    UartRegisterView *uart=hal->dev;
    memw(); unsigned int setting=uart->conf0;
    memw(); uart->conf0=setting|0x40000U;
    memw(); setting=uart->conf0;
    memw(); uart->conf0=setting&0xfffbffffU;
}

/* Native entry: 0x4201386c. */
/*
 * Medius v3.4.7 — host application; 0x4201386c.
 * Instruction-checked recovered C.
 * Original function-byte SHA-256:
 * 9802ea2c2c831dc72e39e77815ed3cadfa1dc71db1269b5f9ecee34ceb4c58a9.
 */

/* Interpret mode bit0 as RX/RTS flow and bit1 as TX/CTS flow, ignoring higher
 * bits. RX enabled: replace MEM_CONF bits7..16 with zero-extended threshold byte,
 * then separately set CONF1 bit22. RX disabled: clear CONF1 bit22 without touching
 * threshold. Then freshly read CONF0 and set/clear bit15 from mode bit1. Cache
 * peripheral; MEMW precedes each MMIO read/write. No range check, lock or wait. */
void uart_hal_set_hw_flow_ctrl(UartHal *hal,unsigned int mode,unsigned char threshold)
{
    UartRegisterView *uart=hal->dev;
    unsigned int setting;
    if (mode&1U) {
        memw(); setting=uart->mem_conf;
        memw(); uart->mem_conf=(setting&0xfffe007fU)|((unsigned int)threshold<<7);
        memw(); setting=uart->conf1;
        memw(); uart->conf1=setting|0x400000U;
    } else {
        memw(); setting=uart->conf1;
        memw(); uart->conf1=setting&0xffbfffffU;
    }
    memw(); setting=uart->conf0;
    setting=(mode&2U) ? setting|0x8000U : setting&0xffff7fffU;
    memw(); uart->conf0=setting;
}

/* Native entry: 0x420138dc. */
/*
 * Medius v3.4.7 — host application; 0x420138dc.
 * Instruction-checked recovered C.
 * Original function-byte SHA-256:
 * 57ff8c5d7da5bc201623dda6dea651c4dcfce2feefa77cc4335331a5e5f6b759.
 */

/* Replace IDLE_CONF bits10..19 with low10 bits of requested TX-idle register
 * count. One cached peripheral and read/modify/write, MEMW before both accesses.
 * No range validation, clock/baud conversion, delay or synchronization lock. */
void uart_hal_set_tx_idle_num(UartHal *hal,unsigned int idle_count)
{
    UartRegisterView *uart=hal->dev;
    memw(); unsigned int setting=uart->idle_conf;
    memw(); uart->idle_conf=(setting&0xfff003ffU)|((idle_count&0x3ffU)<<10);
}

/* Native entry: 0x42013900. */
/*
 * Medius v3.4.7 — host application; 0x42013900.
 * Instruction-checked recovered C.
 * Original function-byte SHA-256:
 * 401d121557c04139b0d8a6c593c902380c9265e9d4ed0d289c2f3e81c2d33cd0.
 */

/* Initialize the cached UART through TEN separate fresh read/modify/writes:
 * clear RS485 enable/delay0/delay1 separately; clear IRDA and parity enable;
 * select8 data bits and1 stop bit; clear TX idle; disable RX then TX hardware
 * flow. Preserve unrelated bits at each step, MEMW before every read and write.
 * The SDK port argument is accepted but unused by this image. No FIFO reset,
 * baud/source programming, validation or lock is supplied by this function. */
void uart_hal_init(UartHal *hal,unsigned int port)
{
    (void)port;
    UartRegisterView *uart=hal->dev;
    memw(); unsigned int setting=uart->rs485_conf;
    memw(); uart->rs485_conf=setting&0xfffffffeU;
    memw(); setting=uart->rs485_conf;
    memw(); uart->rs485_conf=setting&0xfffffff7U;
    memw(); setting=uart->rs485_conf;
    memw(); uart->rs485_conf=setting&0xffffffefU;
    memw(); setting=uart->conf0;
    memw(); uart->conf0=setting&0xfffeffffU;
    memw(); setting=uart->conf0;
    memw(); uart->conf0=setting&0xfffffffdU;
    memw(); setting=uart->conf0;
    memw(); uart->conf0=setting|0xcU;
    memw(); setting=uart->conf0;
    memw(); uart->conf0=(setting&0xffffffcfU)|0x10U;
    memw(); setting=uart->idle_conf;
    memw(); uart->idle_conf=setting&0xfff003ffU;
    memw(); setting=uart->conf1;
    memw(); uart->conf1=setting&0xffbfffffU;
    memw(); setting=uart->conf0;
    memw(); uart->conf0=setting&0xffff7fffU;
}
