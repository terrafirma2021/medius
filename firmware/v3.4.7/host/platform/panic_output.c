/* Medius v3.4.7 host — panic diagnostic output. */
#include "../include/types.h"

/* Native entry: 0x42002a4c. */
/* Original function-byte SHA-256:
 * 46dad07154da58baf38e3289327dd76b396840b8093e038b2ad46391a3d8c620. */
/*
 * Write a NUL-terminated panic string directly through the configured UART HAL
 * at0x3fc9da08 (image initial pointer: UART0/0x60000000). Read the first text
 * byte even for an empty string. For each nonzero byte, snapshot hal->dev once,
 * zero the local write count, then repeatedly MEMW/read STATUS until the 10-bit
 * TX occupancy differs from128. Call the HAL for one byte and ignore its count.
 * The next text byte is fetched after that call; HAL pointer changes are seen
 * on the next character. No allocation, NULL check, timeout, retry on a zero
 * HAL write, TX completion wait or lock. String bytes are sent unchanged.
 */
void panic_print_str(const char *text)
{
    unsigned char character=(unsigned char)*text;
    while (character!=0) {
        UartRegisterView *uart=MEDIUS_PANIC_UART_HAL->dev;
        volatile unsigned int written=0;
        do {
            memw();
        } while (((uart->status>>16)&0x3ffU)==128U);
        uart_hal_write_txfifo(MEDIUS_PANIC_UART_HAL,&character,1U,
                             (unsigned int *)&written);
        character=(unsigned char)*++text;
    }
}

/* Native entry: 0x42002a8c. */
/* Original function-byte SHA-256:
 * 2e1cb25668f66b2f1700e4ab3205edddf1b3dfe6157f7da01b2ed692bb0c6b15. */

/*
 * Print exactly eight lowercase hexadecimal digits, high nibble first, with
 * leading zeroes and no prefix/newline. Each digit snapshots the UART pointer,
 * initializes the write count to0, waits while STATUS TX occupancy equals128,
 * and requests one HAL byte. Shift the unsigned value left4 after each call.
 * Writes/counts are not retried or checked. No timeout, completion wait or lock.
 */
void panic_print_hex(unsigned int value)
{
    for (unsigned int remaining=8;remaining!=0;--remaining) {
        unsigned int nibble=value>>28;
        UartRegisterView *uart=MEDIUS_PANIC_UART_HAL->dev;
        unsigned char character=(unsigned char)(nibble+(nibble<10U?'0':('a'-10)));
        volatile unsigned int written=0;
        do {
            memw();
        } while (((uart->status>>16)&0x3ffU)==128U);
        uart_hal_write_txfifo(MEDIUS_PANIC_UART_HAL,&character,1U,
                             (unsigned int *)&written);
        value<<=4;
    }
}

/* Native entry: 0x42002a08. */
/* Original function-byte SHA-256:
 * a00fcff39e96676d4ee4a5e04513dc645aa6ddacb3bfa9c531d11db8aa6f3487. */
/* Abort-detail callback; the supplied exception frame is ignored. Load the
 * global details pointer once, dereference its first byte without a NULL
 * check, and emit through the UART until NUL. Pointer updates during output
 * do not switch strings. Each byte snapshots HAL->dev, clears a write-count
 * local, waits while TX occupancy==128 and requests one byte, ignoring count.
 * No timeout, allocation, output lock or completion wait. */
void panic_print_abort_details(const void *unused_frame)
{
    const char *text=PANIC_ABORT_DETAILS;
    unsigned char character=(unsigned char)*text;
    while (character!=0) {
        UartRegisterView *uart=MEDIUS_PANIC_UART_HAL->dev;
        volatile unsigned int written=0;
        do {
            memw();
        } while (((uart->status>>16)&0x3ffU)==128U);
        uart_hal_write_txfifo(MEDIUS_PANIC_UART_HAL,&character,1U,
                             (unsigned int *)&written);
        character=(unsigned char)*++text;
    }
}

/* Native entry: 0x42002ae4. */
/* Original function-byte SHA-256:
 * f31009c6e6a98244403f818fd59d990d037e6dfe4600df5be7635cb4d37a2f50. */
/*
 * Send exactly two panic UART bytes: signed division by10 gives the tens value;
 * emit space when it is0, otherwise lowBYTE(quotient+'0'), then emit
 * lowBYTE(value-quotient*10+'0'). Native division truncates toward0. No sign,
 * saturation or decimal-range check: negatives and values>99 produce the same
 * arithmetic bytes rather than a general integer string. Each byte separately
 * snapshots the UART pointer, zeros a write-count local, waits with fresh
 * MEMW/STATUS reads while occupancy==128, and requests one HAL byte. Counts
 * are ignored. No timeout, TX completion wait, allocation or lock.
 */
void panic_print_dec(int value)
{
    int tens=value/10;
    int ones=value-tens*10;
    UartRegisterView *uart=MEDIUS_PANIC_UART_HAL->dev;
    unsigned char character=tens==0?' ':(unsigned char)((unsigned int)tens+'0');
    volatile unsigned int written=0;
    do {
        memw();
    } while (((uart->status>>16)&0x3ffU)==128U);
    uart_hal_write_txfifo(MEDIUS_PANIC_UART_HAL,&character,1U,
                         (unsigned int *)&written);

    uart=MEDIUS_PANIC_UART_HAL->dev;
    character=(unsigned char)(ones+'0');
    written=0;
    do {
        memw();
    } while (((uart->status>>16)&0x3ffU)==128U);
    uart_hal_write_txfifo(MEDIUS_PANIC_UART_HAL,&character,1U,
                         (unsigned int *)&written);
}
