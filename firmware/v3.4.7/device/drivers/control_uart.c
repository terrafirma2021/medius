/* Medius v3.4.7 device — drivers/control_uart.c.
 * Recovered C and native assembly, grouped for source navigation.
 * Original entry addresses, firmware-byte hashes and function comments follow.
 */

#include "../include/types.h"

/* Native entry: 0x4037c768. */
/*
 * Medius v3.4.7 — device application; 0x4037c768.
 *
 * Services the control UART0 interrupt.
 *
 * Calls: link_parser_check_rx_gap, esp_timer_get_time, link_parser_feed, link_parser_reset,
 * vPortExitCritical, xPortEnterCriticalTimeout.
 *
 * Original function-byte SHA-256:
 * 51138fc9a37b5e54d49ced06e7c76db887b0150715ea6a8d5a2218d439df992d.
 */

/*
 * Services one snapshot of the enabled UART0 interrupt sources.
 *
 * argument: unused interrupt-registration context. Returns no value.
 *
 * RX-full/timeout handling snapshots the FIFO byte count, checks the parser's
 * receive gap against 50,000 us, and feeds exactly that many bytes in chunks
 * of at most 64. Bytes arriving afterward are left for another interrupt.
 * Processing RX precedes handling overflow or parity/framing errors from the
 * same status snapshot, so valid-frame callbacks can run before error reset.
 *
 * RX overflow clears the source, pulses the hardware FIFO reset, resets the
 * parser, and increments one overflow-event counter. Parity/framing errors
 * clear both error bits and reset parsing without incrementing that counter.
 *
 * TX-empty handling holds the shared TX spinlock, copies queued bytes into
 * the space reported by the 128-byte hardware FIFO, and advances the 4 KiB
 * software-ring read cursor. It disables TX-empty interrupts only if the
 * final cursor reads show an empty software ring. Other IRQs remain enabled.
 *
 * Requires initialized UART0/parser/ring state, valid FIFO counts and cursors,
 * and writers using the same TX lock. The critical-section result is ignored
 * with an infinite wait. Frame callbacks run in interrupt context; no task
 * deferral, independent timeout timer or general error recovery is added.
 * Explicit MEMW operations retain the native order of each shared/MMIO access.
 */
void control_uart_interrupt_handler(void *argument)
{
    (void)argument;
    UartRegisterView *uart = CONTROL_UART0;
    LinkParser *parser = CONTROL_RX_PARSER;
    const unsigned int rx_data_irqs =
        UART_RX_FULL_IRQ | UART_RX_TIMEOUT_IRQ;

    memw();
    unsigned int pending_irqs = uart->interrupt_status;
    if ((pending_irqs & rx_data_irqs) != 0) {
        memw();
        unsigned int rx_status = uart->status;
        unsigned int now_us_low = (unsigned int)esp_timer_get_time();
        unsigned int remaining_bytes = rx_status & UART_FIFO_COUNT_MASK;
        link_parser_check_rx_gap(parser, now_us_low, 50000);

        unsigned char received_bytes[64];
        while (remaining_bytes != 0) {
            unsigned int chunk_bytes = remaining_bytes < sizeof(received_bytes)
                ? remaining_bytes : sizeof(received_bytes);
            for (unsigned int index = 0; index < chunk_bytes; ++index) {
                memw();
                received_bytes[index] = (unsigned char)uart->fifo;
            }
            remaining_bytes -= chunk_bytes;
            link_parser_feed(parser, received_bytes, chunk_bytes);
        }
        memw();
        uart->interrupt_clear = rx_data_irqs;
    }

    if ((pending_irqs & UART_RX_OVERFLOW_IRQ) != 0) {
        memw();
        uart->interrupt_clear = UART_RX_OVERFLOW_IRQ;
        memw();
        unsigned int configuration = uart->conf0;
        memw();
        uart->conf0 = configuration | UART_RX_FIFO_RESET;
        memw();
        configuration = uart->conf0;
        memw();
        uart->conf0 = configuration & ~UART_RX_FIFO_RESET;
        link_parser_reset(parser);
        memw();
        unsigned int overflow_events = CONTROL_UART_RX_FIFO_OVERFLOW_COUNT;
        memw();
        CONTROL_UART_RX_FIFO_OVERFLOW_COUNT = overflow_events + 1U;
    }

    if ((pending_irqs & UART_RX_ERROR_IRQS) != 0) {
        memw();
        uart->interrupt_clear = UART_RX_ERROR_IRQS;
        link_parser_reset(parser);
    }

    if ((pending_irqs & UART_TX_EMPTY_IRQ) == 0)
        return;

    (void)xPortEnterCriticalTimeout(&CONTROL_TX_LOCK, -1);
    memw();
    uart->interrupt_clear = UART_TX_EMPTY_IRQ;
    memw();
    unsigned int tx_status = uart->status;
    unsigned int fifo_count = (tx_status >> 16) & UART_FIFO_COUNT_MASK;
    unsigned int fifo_space = UART_FIFO_CAPACITY - fifo_count;

    while (fifo_space != 0) {
        memw();
        unsigned int observed_read = CONTROL_TX_READ_OFFSET;
        memw();
        unsigned int observed_write = CONTROL_TX_WRITE_OFFSET;
        if (observed_read == observed_write)
            break;

        memw();
        unsigned int write_snapshot = CONTROL_TX_WRITE_OFFSET;
        memw();
        unsigned int read_snapshot = CONTROL_TX_READ_OFFSET;
        memw();
        unsigned int tail_read = CONTROL_TX_READ_OFFSET;
        unsigned int queued_bytes =
            (write_snapshot - read_snapshot) & CONTROL_TX_CURSOR_MASK;
        unsigned int tail_bytes = CONTROL_TX_RING_BYTES - tail_read;
        unsigned int chunk_bytes = queued_bytes < tail_bytes ? queued_bytes : tail_bytes;
        if (fifo_space < chunk_bytes)
            chunk_bytes = fifo_space;

        memw();
        unsigned int source_offset = CONTROL_TX_READ_OFFSET;
        if (chunk_bytes == 0) {
            /* Preserve the native normalization/retry path and its fresh load. */
            memw();
            unsigned int current_read = CONTROL_TX_READ_OFFSET;
            memw();
            CONTROL_TX_READ_OFFSET = current_read & CONTROL_TX_CURSOR_MASK;
            continue;
        }

        const unsigned char *source = CONTROL_TX_RING + source_offset;
        for (unsigned int index = 0; index < chunk_bytes; ++index) {
            unsigned int byte_to_send = source[index];
            memw();
            uart->fifo = byte_to_send;
        }
        memw();
        unsigned int completed_read = CONTROL_TX_READ_OFFSET;
        fifo_space -= chunk_bytes;
        unsigned int next_read =
            (completed_read + chunk_bytes) & CONTROL_TX_CURSOR_MASK;
        memw();
        CONTROL_TX_READ_OFFSET = next_read;
    }

    memw();
    unsigned int final_read = CONTROL_TX_READ_OFFSET;
    memw();
    unsigned int final_write = CONTROL_TX_WRITE_OFFSET;
    if (final_read == final_write) {
        memw();
        unsigned int enabled_irqs = uart->interrupt_enable;
        memw();
        uart->interrupt_enable = enabled_irqs & ~UART_TX_EMPTY_IRQ;
    }
    vPortExitCritical(&CONTROL_TX_LOCK);
}

/* Native entry: 0x4200a25c. */
/*
 * Medius v3.4.7 — device application; 0x4200a25c.
 *
 * Initializes control UART0 and its receive task.
 *
 * Calls: abort, esp_intr_alloc, link_parser_init, uart_param_config, uart_set_pin,
 * vPortExitCritical, xPortEnterCriticalTimeout, xQueueCreateMutex, xTaskCreatePinnedToCore.
 *
 * Called by: app_main.
 *
 * Original function-byte SHA-256:
 * 0a29d3a5252bb6d9d96728be7e0b98d5735f14a272794721729b984b15bb16f9.
 */

/*
 * Initializes the external control UART0 and its receive-dispatch task.
 * No parameters or return value; aborts on UART configuration, pin setup or
 * interrupt-allocation failure. Allocation of the TX mutex and creation of
 * ctrl_rx are not checked, and failure does not unwind earlier resources.
 *
 * Creates the TX mutex and clears/configures the 536-byte receive parser with
 * control_receive_publish and NULL context. Sets 6,000,000 baud, 8 data bits,
 * no parity, one stop bit, no hardware flow control, APB source and zero sleep
 * flags. TX/RX use GPIO43/44; RTS/CTS are left unchanged (-1). Actual baud
 * accuracy depends on the driver's source-clock/divider configuration.
 *
 * Programs RX-full threshold 32, creates ctrl_rx with a 6144-byte stack,
 * priority12 and CPU0 affinity, then sets TX-empty threshold16, receive-timeout
 * threshold20 and enables hardware RX timeout. These are register threshold
 * values, not a task scheduling guarantee or a software timer interval.
 *
 * Retains the native read of interrupt-enable before clearing it, clears all
 * pending sources, and installs the IRAM-capable UART0 ISR on the calling CPU.
 * Under the TX spinlock, enables RX-full, timeout, parity, framing and overflow
 * sources (0x11d). TX-empty remains for the enqueue path to enable as needed.
 *
 * Requires normal startup/task context with working allocator, clock/GPIO
 * drivers and FreeRTOS. This is not idempotent: there is no duplicate-init
 * guard, resource teardown, ring-cursor reset or software-counter reset.
 */
void control_uart_init(void)
{
    /* Preserve the native type-1 creator argument at this call boundary.
     * The specialized implementation ignores it. */
    CONTROL_TX_MUTEX = rtos_create_mutex_type(1);
    link_parser_init(CONTROL_RX_PARSER, control_receive_publish, 0);

    UartConfig configuration = {0};
    configuration.baud_rate = 6000000;
    configuration.data_bits = UART_DATA_8_BITS;
    configuration.stop_bits = UART_STOP_BITS_1;
    configuration.source_clock = UART_CLOCK_APB;
    if (uart_param_config(0, &configuration) != 0)
        abort();
    if (uart_set_pin(0, 43, 44, -1, -1) != 0)
        abort();

    memw();
    unsigned int conf1 = CONTROL_UART_CONF1;
    memw();
    CONTROL_UART_CONF1 = (conf1 & ~0x3ffU) | 32U;
    (void)xTaskCreatePinnedToCore(control_receive_task, "ctrl_rx", 6144, 0, 12,
                                   (RtosTask **)&CONTROL_RX_TASK, 0);
    memw();
    conf1 = CONTROL_UART_CONF1;
    memw();
    CONTROL_UART_CONF1 = (conf1 & ~(0x3ffU << 10)) | (16U << 10);
    memw();
    unsigned int memory_configuration = CONTROL_UART_MEM_CONF;
    memw();
    CONTROL_UART_MEM_CONF =
        (memory_configuration & ~(0x3ffU << 17)) | (20U << 17);
    memw();
    conf1 = CONTROL_UART_CONF1;
    memw();
    CONTROL_UART_CONF1 = conf1 | 0x00800000U;

    /* Keep the native table-byte read after the timeout-enable store. */
    int interrupt_source =
        *(const volatile unsigned char *)&UART0_INTERRUPT_SOURCE;
    memw();
    (void)CONTROL_UART0->interrupt_enable;
    memw();
    CONTROL_UART0->interrupt_enable = 0;
    memw();
    CONTROL_UART0->interrupt_clear = 0xffffffffU;
    if (esp_intr_alloc(interrupt_source, INTR_FLAG_IRAM,
                        control_uart_interrupt_handler, 0,
                        (InterruptHandle **)&CONTROL_UART_IRQ_HANDLE) != 0)
        abort();

    (void)xPortEnterCriticalTimeout(&CONTROL_TX_LOCK, -1);
    memw();
    unsigned int enabled_irqs = CONTROL_UART0->interrupt_enable;
    memw();
    CONTROL_UART0->interrupt_enable = enabled_irqs |
        UART_RX_FULL_IRQ | UART_RX_TIMEOUT_IRQ |
        UART_RX_ERROR_IRQS | UART_RX_OVERFLOW_IRQ;
    vPortExitCritical(&CONTROL_TX_LOCK);
}

