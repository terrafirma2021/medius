/* Medius v3.4.7 host — drivers/link_uart.c.
 * Recovered C and native assembly, grouped for source navigation.
 * Original entry addresses, firmware-byte hashes and function comments follow.
 */

#include "../include/types.h"

/* Native entry: 0x4037b2ec. */
/*
 * Medius v3.4.7 — host application; 0x4037b2ec.
 *
 * Services inter-chip UART1 receive, transmit-refill and transmit-complete interrupts.
 *
 * Calls: xQueueGiveFromISR, _frxt_setup_switch, link_parser_feed, link_parser_reset,
 * vPortExitCritical, xPortEnterCriticalTimeout.
 *
 * Original function-byte SHA-256:
 * f82fce4bbcf39a8e0bbfa87f935da401bbbd4ebb73ebf5d338844e917d66c7c4.
 */

/*
 * Handles one snapshot of UART1 RX, TX-refill and TX-done interrupt sources.
 * argument is unused registration context. Returns no value.
 *
 * RX snapshots the FIFO count and feeds that many bytes in chunks of at most 64 bytes into
 * the shared parser. Newly arriving bytes wait for a later interrupt. No
 * receive-gap clock check is performed. Parsing and frame callbacks happen
 * before overflow/parity/framing handling from the same status snapshot.
 * Overflow clears the IRQ, pulses RX FIFO reset, resets parsing and counts
 * one event. Parity/framing errors reset parsing without incrementing it.
 *
 * TX-empty copies from the borrowed TX cursor, limited by hardware FIFO space
 * and the sampled 16-bit remaining count. Fresh pointer/count loads and native
 * MEMW publication order are retained. The copy itself is outside the TX
 * spinlock. At zero remaining, clears stale TX-done, then under that lock
 * disables refill and enables TX-done through separate read/modify/writes.
 *
 * A TX-done bit from the original status snapshot clears/disables that source
 * and gives the optional completion semaphore. Only a nonzero woken flag asks
 * for an interrupt-exit task switch; a full semaphore result is ignored.
 *
 * Requires initialized UART/parser/shared TX state, valid FIFO counts at most 128,
 * one transmitter with compatible ISR scheduling, and a live borrowed buffer
 * until refill cannot access it. No TX copy allocation, complete-operation
 * lock, payload lifetime extension or timeout recovery is supplied here.
 */
void link_uart_interrupt_handler(void *argument)
{
    (void)argument;
    UartRegisterView *uart = LINK_UART1;
    LinkParser *parser = LINK_RX_PARSER;
    const unsigned int rx_data_irqs =
        UART_RX_FULL_IRQ | UART_RX_TIMEOUT_IRQ;
    memw();
    unsigned int pending_irqs = uart->interrupt_status;

    if ((pending_irqs & rx_data_irqs) != 0) {
        memw();
        unsigned int remaining_bytes = uart->status & UART_FIFO_COUNT_MASK;
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
        unsigned int overflow_events = LINK_RX_FIFO_OVERFLOW_COUNT;
        memw();
        LINK_RX_FIFO_OVERFLOW_COUNT = overflow_events + 1U;
    }
    if ((pending_irqs & UART_RX_ERROR_IRQS) != 0) {
        memw();
        uart->interrupt_clear = UART_RX_ERROR_IRQS;
        link_parser_reset(parser);
    }

    if ((pending_irqs & UART_TX_EMPTY_IRQ) != 0) {
        memw();
        uart->interrupt_clear = UART_TX_EMPTY_IRQ;
        memw();
        unsigned int fifo_status = uart->status;
        unsigned int fifo_space = UART_FIFO_CAPACITY -
            ((fifo_status >> 16) & UART_FIFO_COUNT_MASK);
        memw();
        unsigned short remaining_snapshot = LINK_TX_REMAINING_BYTES;
        unsigned int refill_bytes = fifo_space;
        if (remaining_snapshot < refill_bytes) {
            memw();
            refill_bytes = LINK_TX_REMAINING_BYTES;
        }
        if (refill_bytes != 0) {
            memw();
            const unsigned char *source = LINK_TX_CURSOR;
            for (unsigned int index = 0; index < refill_bytes; ++index) {
                unsigned int byte_to_send = source[index];
                memw();
                uart->fifo = byte_to_send;
            }
            memw();
            const unsigned char *current_cursor = LINK_TX_CURSOR;
            memw();
            LINK_TX_CURSOR = current_cursor + refill_bytes;
            memw();
            unsigned short current_remaining = LINK_TX_REMAINING_BYTES;
            unsigned short next_remaining =
                (unsigned short)(current_remaining - refill_bytes);
            memw();
            LINK_TX_REMAINING_BYTES = next_remaining;
        }
        memw();
        unsigned short final_remaining = LINK_TX_REMAINING_BYTES;
        if (final_remaining == 0) {
            memw();
            uart->interrupt_clear = UART_TX_DONE_IRQ;
            (void)xPortEnterCriticalTimeout(&LINK_TX_LOCK, -1);
            memw();
            unsigned int enabled_irqs = uart->interrupt_enable;
            memw();
            uart->interrupt_enable = enabled_irqs & ~UART_TX_EMPTY_IRQ;
            memw();
            enabled_irqs = uart->interrupt_enable;
            memw();
            uart->interrupt_enable = enabled_irqs | UART_TX_DONE_IRQ;
            vPortExitCritical(&LINK_TX_LOCK);
        }
    }

    if ((pending_irqs & UART_TX_DONE_IRQ) != 0) {
        memw();
        uart->interrupt_clear = UART_TX_DONE_IRQ;
        (void)xPortEnterCriticalTimeout(&LINK_TX_LOCK, -1);
        memw();
        unsigned int enabled_irqs = uart->interrupt_enable;
        memw();
        uart->interrupt_enable = enabled_irqs & ~UART_TX_DONE_IRQ;
        vPortExitCritical(&LINK_TX_LOCK);

        RtosQueue *completion = LINK_TX_COMPLETION_SEMAPHORE;
        if (completion != 0) {
            int higher_priority_task_woken = 0;
            (void)xQueueGiveFromISR(completion, &higher_priority_task_woken);
            if (higher_priority_task_woken != 0)
                _frxt_setup_switch();
        }
    }
}

/* Native entry: 0x4037b480. */
/*
 * Medius v3.4.7 — host application; 0x4037b480.
 *
 * Starts a UART1 frame transmission and waits for transmit completion.
 *
 * Calls: link_frame_patch_payload, esp_log_timestamp, esp_log_write, esp_timer_get_time, vPortExitCritical,
 * xPortEnterCriticalTimeout, xQueueSemaphoreTake.
 *
 * Called by: link_transmit_task.
 *
 * Original function-byte SHA-256:
 * 918e6c1b8afcea9baaaaa4ed77dd22b6a6c8ee98f1acdd1e24762574a290ddbc.
 */

/*
 * Starts one UART1 frame and waits up to 50 RTOS ticks on its completion token.
 * frame: writable borrowed frame buffer; frame_length: unsigned32-bit byte size.
 * Returns no value, including on timeout. Reads frame[1] before checking length,
 * so at least two readable bytes are required even for a zero-length call.
 *
 * For type 0x25 or 0x02, samples low 32 microseconds and attempts a four-byte payload
 * patch at offset 4 or 12, respectively, ignoring patch failure. This happens
 * before the zero-length return. The CRC is updated by the patch helper.
 *
 * With nonzero length, holds the TX spinlock, clears refill/done sources and
 * fills min(frame_length, FIFO space, configured initial-fill limit) bytes directly.
 * Publishes the borrowed remainder pointer and a 16-bit remaining count, then
 * enables refill if any remain, otherwise TX-done. Releases the lock before
 * waiting on the completion semaphore. Tail bytes are not copied into a ring.
 *
 * Any take result other than1 disables refill/done under the lock, releases it,
 * then separately reacquires it to zero remaining count. Logs a warning after
 * unlocking. Does not flush hardware FIFO, clear the borrowed cursor, drain
 * completion tokens, retry, or verify hardware state after a successful take.
 * The 50-tick wait is a scheduler timeout, not guaranteed wall-clock completion.
 *
 * Requires initialized UART/lock/semaphore, valid FIFO counts, one transmitter,
 * frame_length fitting the 16-bit remainder design, and buffer ownership until
 * outstanding ISR access is excluded. No complete-operation mutex is supplied;
 * the refill loop can run outside the spinlock, so this function alone does
 * not provide cross-core buffer-lifetime synchronization on cancellation.
 */
void link_uart_transmit_wait(unsigned char *frame, unsigned int frame_length)
{
    unsigned char type = frame[1];
    if (type == 0x25U || type == 0x02U) {
        unsigned int timestamp_us_low = (unsigned int)esp_timer_get_time();
        unsigned short payload_offset = type == 0x25U ? 4U : 12U;
        (void)link_frame_patch_payload(frame, frame_length, payload_offset,
                                              &timestamp_us_low, 4);
    }
    if (frame_length == 0)
        return;

    UartRegisterView *uart = LINK_UART1;
    (void)xPortEnterCriticalTimeout(&LINK_TX_LOCK, -1);
    memw();
    uart->interrupt_clear = UART_TX_EMPTY_IRQ | UART_TX_DONE_IRQ;
    memw();
    unsigned int fifo_status = uart->status;
    unsigned int initial_limit = LINK_TX_INITIAL_FIFO_LIMIT;
    unsigned int fifo_space = UART_FIFO_CAPACITY -
        ((fifo_status >> 16) & UART_FIFO_COUNT_MASK);
    unsigned int direct_bytes = fifo_space < frame_length ? fifo_space : frame_length;
    if (initial_limit < direct_bytes)
        direct_bytes = initial_limit;
    for (unsigned int index = 0; index < direct_bytes; ++index) {
        unsigned int byte_to_send = frame[index];
        memw();
        uart->fifo = byte_to_send;
    }
    const unsigned char *remaining_cursor = frame + direct_bytes;
    unsigned short remaining_bytes = (unsigned short)(frame_length - direct_bytes);
    memw();
    LINK_TX_CURSOR = remaining_cursor;
    memw();
    LINK_TX_REMAINING_BYTES = remaining_bytes;
    memw();
    unsigned short remaining_snapshot = LINK_TX_REMAINING_BYTES;
    memw();
    unsigned int enabled_irqs = uart->interrupt_enable;
    unsigned int next_irq = remaining_snapshot != 0
        ? UART_TX_EMPTY_IRQ : UART_TX_DONE_IRQ;
    memw();
    uart->interrupt_enable = enabled_irqs | next_irq;
    vPortExitCritical(&LINK_TX_LOCK);

    if (xQueueSemaphoreTake(LINK_TX_COMPLETION_SEMAPHORE, 50) == 1)
        return;

    (void)xPortEnterCriticalTimeout(&LINK_TX_LOCK, -1);
    memw();
    enabled_irqs = uart->interrupt_enable;
    memw();
    uart->interrupt_enable = enabled_irqs &
        ~(UART_TX_EMPTY_IRQ | UART_TX_DONE_IRQ);
    vPortExitCritical(&LINK_TX_LOCK);
    (void)xPortEnterCriticalTimeout(&LINK_TX_LOCK, -1);
    memw();
    LINK_TX_REMAINING_BYTES = 0;
    vPortExitCritical(&LINK_TX_LOCK);

    unsigned int timestamp_ms = esp_log_timestamp();
    esp_log_write(2, LINK_LOG_TAG,
                    "W (%lu) %s: tx did not drain type=0x%02x len=%u\n",
                    (unsigned long)timestamp_ms, LINK_LOG_TAG,
                    (unsigned int)frame[1], frame_length);
}

