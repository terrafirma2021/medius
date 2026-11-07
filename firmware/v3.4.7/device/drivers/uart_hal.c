/* Medius v3.4.7 device — drivers/uart_hal.c.
 */

#include "../include/types.h"

/* Native entry: 0x4202137c. */
/*
 * Medius v3.4.7 — device application; 0x4202137c.
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

/* Native entry: 0x420213a0. */
/*
 * Medius v3.4.7 — device application; 0x420213a0.
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

/* Native entry: 0x420213c0. */
/*
 * Medius v3.4.7 — device application; 0x420213c0.
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

/* Native entry: 0x420213e0. */
/*
 * Medius v3.4.7 — device application; 0x420213e0.
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

/* Native entry: 0x4038af00. */
/*
 * Medius v3.4.7 — device application; 0x4038af00.
 * Instruction-checked recovered C.
 * Original function-byte SHA-256:
 * fe69c81fb7162b466e2929e8b99469809e841011fe7d7c92eb24a576765ca9ea.
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

/* Native entry: 0x4038af28. */
/*
 * Medius v3.4.7 — device application; 0x4038af28.
 * Instruction-checked recovered C.
 * Original function-byte SHA-256:
 * d2d6d386e018dcf32ee87bba88b5bd33d894ad9daa1ae5d06ed0aa4497cfde0c.
 */

/* Pulse RXFIFO_RST bit17 with a cached peripheral and separate fresh read/set,
 * read/clear operations. MEMW before every MMIO access. No wait, timeout, RX
 * driver/ring state update, validation or lock; caller owns serialization. */
void uart_hal_rxfifo_rst(UartHal *hal)
{
    UartRegisterView *uart=hal->dev;
    memw(); unsigned int setting=uart->conf0;
    memw(); uart->conf0=setting|0x20000U;
    memw(); setting=uart->conf0;
    memw(); uart->conf0=setting&0xfffdffffU;
}

/* Native entry: 0x420178c4. */
/*
 * Medius v3.4.7 — device application; 0x420178c4.
 * Instruction-checked recovered C.
 * Original function-byte SHA-256:
 * 7de7709d23b863bca9acb5d728869703bd1468d73e2070dc74b6ca2f6787e248.
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

/* Native entry: 0x42017934. */
/*
 * Medius v3.4.7 — device application; 0x42017934.
 * Instruction-checked recovered C.
 * Original function-byte SHA-256:
 * 5e33ec2a7288665bf4c4ced0ee52871e49257f4b14e8458c1d538987c49cf5f4.
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

/* Native entry: 0x42017958. */
/*
 * Medius v3.4.7 — device application; 0x42017958.
 * Instruction-checked recovered C.
 * Original function-byte SHA-256:
 * c65d3e10ffc3358b31bb052ed974331a9c60d0ea719bf0e63540d68c4c58d378.
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
