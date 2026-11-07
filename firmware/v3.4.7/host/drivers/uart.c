/* Medius v3.4.7 host — drivers/uart.c.
 * Recovered C and native assembly, grouped for source navigation.
 * Original entry addresses, firmware-byte hashes and function comments follow.
 */

#include "../include/types.h"

/* Native entry: 0x420086d8. */
/*
 * Medius v3.4.7 — host application; 0x420086d8.
 * Instruction-checked recovered C.
 * Original function-byte SHA-256:
 * e6df8730121b0b5bcc95e7b53db660bc492c896e99600fb2dda2ce615b221939.
 */

/* Serialize against TX writers using the installed driver's TX mutex. The tick
 * budget includes mutex acquisition and setup. Invalid unsigned port or missing
 * driver logs/returns -1; mutex/completion timeout returns 0x107, success 0.
 * Under the port mux, sample TX_DONE enable once: disabled half-duplex RS485
 * requires RAW TX_DONE clear (otherwise fatal assert); other disabled modes
 * clear stale TX_DONE. Consume one stale semaphore token, request a 2us ROM
 * delay, then test FIFO count and TX FSM through the SAME sampled peripheral.
 * If busy, enable TX_DONE and await the ISR token for max(budget-elapsed,0),
 * using modulo-32 tick subtraction. Always give the TX mutex after acquiring
 * it. Driver slots are reloaded at the native call boundaries; there is no
 * object lifetime lock, interrupt rollback on timeout or physical timing proof. */
int uart_wait_tx_done(unsigned int port,unsigned int ticks_to_wait)
{
    unsigned int timestamp;
    const char *format;
    int source_line;
    if (port >= 3U) {
        timestamp = esp_log_timestamp();
        format = "E (%lu) %s: %s(%d): uart_num error\n";
        source_line = 0x5c3;
    } else if (!MEDIUS_UART_DRIVER_SELECT_OBJECTS[port]) {
        timestamp = esp_log_timestamp();
        format = "E (%lu) %s: %s(%d): uart driver error\n";
        source_line = 0x5c4;
    } else {
        unsigned int started = xTaskGetTickCount();
        if (!xQueueSemaphoreTake(MEDIUS_UART_DRIVER_SELECT_OBJECTS[port]->tx_mutex,
                                 ticks_to_wait))
            return 0x107;
        PortMuxWords *lock = MEDIUS_UART_DRIVER_RX_LOCK(port);
        (void)xPortEnterCriticalTimeout(lock,-1);
        UartRegisterView *registers = UART_DRIVER_CONTEXTS[port].hal.dev;
        MediusUartDriverSelectPrefix *driver = MEDIUS_UART_DRIVER_SELECT_OBJECTS[port];
        memw();
        unsigned int enabled = registers->interrupt_enable;
        int mode = driver->mode;
        if ((enabled & 0x4000U) == 0) {
            if (mode == 1) {
                memw();
                if (registers->interrupt_raw & 0x4000U)
                    __assert_func(0,0,0,0);
            } else {
                memw();
                registers->interrupt_clear = 0x4000U;
            }
        }
        vPortExitCritical(lock);
        (void)xQueueSemaphoreTake(MEDIUS_UART_DRIVER_SELECT_OBJECTS[port]->tx_done_sem,0);
        esp_rom_delay_us(2);
        registers = UART_DRIVER_CONTEXTS[port].hal.dev;
        memw();
        unsigned int queued = (registers->status >> 16) & 0x3ffU;
        if (queued == 0) {
            memw();
            if (((registers->fsm_status >> 4) & 15U) == 0) {
                (void)xQueueGenericSend(MEDIUS_UART_DRIVER_SELECT_OBJECTS[port]->tx_mutex,
                                        NULL,0,0);
                return 0;
            }
        }
        (void)xPortEnterCriticalTimeout(lock,-1);
        registers = UART_DRIVER_CONTEXTS[port].hal.dev;
        memw();
        enabled = registers->interrupt_enable;
        memw();
        registers->interrupt_enable = enabled | 0x4000U;
        vPortExitCritical(lock);
        unsigned int elapsed = xTaskGetTickCount() - started;
        unsigned int remaining = elapsed <= ticks_to_wait ? ticks_to_wait - elapsed : 0;
        int completed = xQueueSemaphoreTake(
            MEDIUS_UART_DRIVER_SELECT_OBJECTS[port]->tx_done_sem,remaining);
        (void)xQueueGenericSend(MEDIUS_UART_DRIVER_SELECT_OBJECTS[port]->tx_mutex,NULL,0,0);
        return completed ? 0 : 0x107;
    }
    esp_log_write(1,MEDIUS_UART_DRIVER_LOG_TAG,format,timestamp,
        MEDIUS_UART_DRIVER_LOG_TAG,"uart_wait_tx_done",source_line);
    return -1;
}

/* Native entry: 0x420088ec. */
/*
 * Medius v3.4.7 — host application; 0x420088ec.
 * Instruction-checked recovered C.
 * Original function-byte SHA-256:
 * 5d840e18614ef7793a57a7545a267e735b2daae7095c9c3d323c72609933b30e.
 */

/* Discard driver RX ring items and any successfully requeued full-buffer stash,
 * reset hardware RX FIFO, then clear/enable RX-full+timeout bits (0x101) selected
 * by the current user interrupt mask. Cache the initial driver for its ring and
 * RX mutex; reload the installed slot for counters/stash/user mask. Ignore the
 * indefinite mutex-take result, as native code does. Subtract each borrowed
 * item's length modulo32 under the port mux and rebase pattern positions before
 * returning storage. Successful stash send clears its flag BEFORE publishing
 * the saved byte-count increment. At drain end clear the full flag; force any
 * nonzero residual count to zero and log the inconsistency before FIFO reset.
 * Invalid unsigned port/missing driver logs and returns -1, otherwise 0. This
 * does not clear VFS lookahead, validate driver lifetime, or propagate ignored
 * semaphore statuses; RX interrupt bits are restored from user mask, not from
 * their entry-time enabled state. Borrowed items never escape this routine. */
int uart_flush_input(unsigned int port)
{
    unsigned int timestamp;
    const char *format;
    int source_line;
    MediusUartDriverSelectPrefix *initial_driver;
    if (port < 3U) {
        initial_driver = MEDIUS_UART_DRIVER_SELECT_OBJECTS[port];
        if (initial_driver) {
            (void)xQueueSemaphoreTake(initial_driver->rx_mutex,0xffffffffU);
            PortMuxWords *lock = MEDIUS_UART_DRIVER_RX_LOCK(port);
            (void)xPortEnterCriticalTimeout(lock,-1);
            UartRegisterView *registers = UART_DRIVER_CONTEXTS[port].hal.dev;
            memw();
            unsigned int enabled = registers->interrupt_enable;
            memw();
            registers->interrupt_enable = enabled & ~0x101U;
            vPortExitCritical(lock);
            size_t item_bytes;
            void *item;
            while ((item = xRingbufferReceive(initial_driver->rx_ring,&item_bytes,0)) != NULL) {
                (void)xPortEnterCriticalTimeout(lock,-1);
                MediusUartDriverSelectPrefix *driver = MEDIUS_UART_DRIVER_SELECT_OBJECTS[port];
                driver->buffered_rx_length = (int)((unsigned int)driver->buffered_rx_length - item_bytes);
                uart_pattern_queue_update((int)port,(int)item_bytes);
                vPortExitCritical(lock);
                vRingbufferReturnItem(initial_driver->rx_ring,item);
                driver = MEDIUS_UART_DRIVER_SELECT_OBJECTS[port];
                if (driver->rx_buffer_full) {
                    unsigned int stash_bytes = driver->rx_stash_length;
                    unsigned char *stash = driver->rx_stash;
                    MediusRingbuffer *ring = driver->rx_ring;
                    if (xRingbufferSend(ring,stash,stash_bytes,0) == 1) {
                        (void)xPortEnterCriticalTimeout(lock,-1);
                        driver = MEDIUS_UART_DRIVER_SELECT_OBJECTS[port];
                        unsigned int buffered = (unsigned int)driver->buffered_rx_length;
                        stash_bytes = driver->rx_stash_length;
                        driver->rx_buffer_full = 0;
                        driver->buffered_rx_length = (int)(buffered + stash_bytes);
                        vPortExitCritical(lock);
                    }
                }
            }
            (void)xPortEnterCriticalTimeout(lock,-1);
            MediusUartDriverSelectPrefix *driver = MEDIUS_UART_DRIVER_SELECT_OBJECTS[port];
            int buffered = driver->buffered_rx_length;
            if (buffered == 0) {
                driver->rx_buffer_full = 0;
                vPortExitCritical(lock);
                uart_hal_rxfifo_rst(&UART_DRIVER_CONTEXTS[port].hal);
            } else {
                driver->buffered_rx_length = 0;
                driver->rx_buffer_full = 0;
                vPortExitCritical(lock);
                timestamp = esp_log_timestamp();
                esp_log_write(1,MEDIUS_UART_DRIVER_LOG_TAG,"E (%lu) %s: rx_buffered_len error\n",
                              timestamp,MEDIUS_UART_DRIVER_LOG_TAG);
                uart_hal_rxfifo_rst(&UART_DRIVER_CONTEXTS[port].hal);
            }
            (void)xPortEnterCriticalTimeout(lock,-1);
            unsigned int mask = MEDIUS_UART_DRIVER_SELECT_OBJECTS[port]->rx_interrupt_user_mask;
            registers = UART_DRIVER_CONTEXTS[port].hal.dev;
            mask &= 0x101U;
            memw();
            registers->interrupt_clear = mask;
            memw();
            enabled = registers->interrupt_enable;
            memw();
            registers->interrupt_enable = enabled | mask;
            vPortExitCritical(lock);
            (void)xQueueGenericSend(initial_driver->rx_mutex,NULL,0,0);
            return 0;
        }
        timestamp = esp_log_timestamp();
        format = "E (%lu) %s: %s(%d): uart driver error\n";
        source_line = 0x6fe;
    } else {
        timestamp = esp_log_timestamp();
        format = "E (%lu) %s: %s(%d): uart_num error\n";
        source_line = 0x6fd;
    }
    esp_log_write(1,MEDIUS_UART_DRIVER_LOG_TAG,format,timestamp,
                  MEDIUS_UART_DRIVER_LOG_TAG,"uart_flush_input",source_line);
    return -1;
}

/* Native entry: 0x42008878. */
/*
 * Medius v3.4.7 — host application; 0x42008878.
 * Instruction-checked recovered C.
 * Original function-byte SHA-256:
 * 3a639e0a1000ff5e1590523bd03248106602aaed23b563c384e5d8ab3700c119.
 */

/* Validate unsigned port<3 and a driver pointer before taking that port's RX
 * mux. Reload driver AFTER locking, copy buffered length at+0x14 to the unchecked
 * output, unlock, return0. Invalid port/missing driver logs the native UART error
 * and returns-1 without touching output. No pointer lifetime protection across
 * the preliminary check. Counts driver bytes, not VFS lookahead or hardware FIFO. */
int medius_uart_driver_get_buffered_length(unsigned int port,unsigned int *length)
{
    unsigned int timestamp;
    const char *format;
    int source_line;
    if (port >= 3U) {
        timestamp = esp_log_timestamp();
        format = "E (%lu) %s: %s(%d): uart_num error\n";
        source_line = 0x6a0;
    } else if (!MEDIUS_UART_DRIVER_SELECT_OBJECTS[port]) {
        timestamp = esp_log_timestamp();
        format = "E (%lu) %s: %s(%d): uart driver error\n";
        source_line = 0x6a1;
    } else {
        PortMuxWords *lock = MEDIUS_UART_DRIVER_RX_LOCK(port);
        (void)xPortEnterCriticalTimeout(lock,-1);
        unsigned int buffered = MEDIUS_UART_DRIVER_SELECT_OBJECTS[port]->buffered_rx_length;
        *(volatile unsigned int *)length = buffered;
        vPortExitCritical(lock);
        return 0;
    }
    esp_log_write(1,MEDIUS_UART_DRIVER_LOG_TAG,format,timestamp,
        MEDIUS_UART_DRIVER_LOG_TAG,"uart_get_buffered_data_len",source_line);
    return -1;
}

/* Native entry: 0x42008ac4. */
/*
 * Medius v3.4.7 — host application; 0x42008ac4.
 * Instruction-checked recovered C.
 * Original function-byte SHA-256:
 * 0a0ded2ccc8b5a1f464f51f9dc8d8ce1670ed049ad063beae430fc097d482766.
 */

/* Return exactly1 when unsigned port<3 and its current driver pointer is not
 * NULL; otherwise0. No dereference, mux, ownership or lifetime guarantee. */
int medius_uart_driver_is_installed(unsigned int port)
{
    return port < 3U && MEDIUS_UART_DRIVER_SELECT_OBJECTS[port] != NULL;
}

/* Native entry: 0x42008ae0. */
/*
 * Medius v3.4.7 — host application; 0x42008ae0.
 * Instruction-checked recovered C.
 * Original function-byte SHA-256:
 * 757cb9698d8d93390cea3c1fcfb97bc7ec2460f310737fb3cce02e993927a8bc.
 */

/* For unsigned port<3 sample its driver pointer once and, if non-NULL, replace
 * select-notification callback at+0x54. NULL callback disables notification.
 * Otherwise do nothing. No status, mux, invocation or lifetime protection;
 * the surrounding selection path supplies its own select lock. */
void medius_uart_driver_set_select_notify(unsigned int port,MediusUartSelectNotify callback)
{
    if (port < 3U) {
        MediusUartDriverSelectPrefix *driver = MEDIUS_UART_DRIVER_SELECT_OBJECTS[port];
        if (driver) driver->select_notify = callback;
    }
}

/* Native entry: 0x42008af8. */
/*
 * Medius v3.4.7 — host application; 0x42008af8.
 * Instruction-checked recovered C.
 * Original function-byte SHA-256:
 * c222513df13024aff32f55032e0788fe52cf2a7a8e2a2df42f19320059771da8.
 */

/* Return the fixed borrowed UART-driver select mux. Does not enter/initialize
 * the lock or depend on whether any UART driver is installed. */
PortMuxWords *medius_uart_driver_get_select_lock(void)
{
    return MEDIUS_UART_DRIVER_SELECT_LOCK;
}
