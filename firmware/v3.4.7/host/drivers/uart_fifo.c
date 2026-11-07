/* Medius v3.4.7 host — polled UART FIFO write. */
#include "../include/types.h"

/* Native entry: 0x40385e94. */
/* Original function-byte SHA-256:
 * 3e82bc058552387955921af489e7f3c31dec4426b5041171a852302d7fba8aa2. */
/*
 * Snapshot hal->dev once, MEMW/read STATUS, then compute available space as
 * uint16_t(128-((status>>16)&0x3ff)). Choose min(length,available) and publish
 * *written before reading any payload byte. For that many bytes, load BYTE
 * then MEMW/write it as a zero-extended FIFO WORD. Zero length still reads
 * STATUS and stores0 to *written. No wait, pointer check, mutex or completion.
 * Occupancy>128 deliberately wraps the16-bit subtraction; it is not clamped.
 * The count store may alias the input buffer/context; data is read afterwards,
 * while the previously captured UART pointer remains fixed for the loop.
 */
void uart_hal_write_txfifo(UartHal *hal,const unsigned char *data,
                          unsigned int length,unsigned int *written)
{
    UartRegisterView *uart=hal->dev;
    memw();
    unsigned int occupancy=(uart->status>>16)&0x3ffU;
    unsigned int count=(unsigned short)(128U-occupancy);
    if (length<count) count=length;
    *written=count;
    for (unsigned int index=0;index<count;++index) {
        unsigned int character=data[index];
        memw();
        uart->fifo=character;
    }
}
