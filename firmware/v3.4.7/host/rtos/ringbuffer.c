/* Medius v3.4.7 host — rtos/ringbuffer.c.
 * Recovered C and native assembly, grouped for source navigation.
 * Original entry addresses, firmware-byte hashes and function comments follow.
 */

#include "../include/types.h"

/* Native entry: 0x40380cfc. */
/*
 * Medius v3.4.7 — host application; 0x40380cfc.
 * Instruction-checked recovered C.
 * Original function-byte SHA-256:
 * 9e6cf5c320acbb414251c3dcad9d25590678d627561fa6aad72ec18a41d29feb.
 */

/* Reserve one no-split payload; caller supplies capacity validation and ring
 * mux. Assert acquire is 4-aligned, head<=acquire<tail and signed32 tail-acquire
 * >=8. Add an 8-byte header to payload rounded to4, with native unsigned32
 * wrap. If it crosses tail, mark old header DUMMY (flags2 THEN length0) and
 * wrap to head. Initialize new length/flags0, advance acquire and wrap if fewer
 * than8 bytes remain. Sample free BEFORE storing acquire; if equal set FULL4.
 * Return borrowed payload at header+8. Does not copy data, advance write/read,
 * count readable items or mark WRITTEN. No independent size/capacity/NULL check. */
void *prvAcquireItemNoSplit(MediusRingbuffer *ring,size_t item_bytes)
{
    unsigned char *acquire = ring->acquire;
    unsigned char *tail = ring->tail;
    if (((unsigned int)acquire & 3U) != 0)
        __assert_func(0,0,0,0);
    unsigned char *head = ring->head;
    unsigned int tail_space = (unsigned int)tail - (unsigned int)acquire;
    if ((unsigned int)acquire < (unsigned int)head ||
        (unsigned int)acquire >= (unsigned int)tail || (int)tail_space < 8)
        __assert_func(0,0,0,0);
    unsigned int total = ((item_bytes + 3U) & ~3U) + 8U;
    if (tail_space < total) {
        MediusRingItemHeader *dummy = (MediusRingItemHeader *)acquire;
        dummy->flags = 2;
        dummy->length = 0;
        acquire = head;
    }
    unsigned char *next = (unsigned char *)((unsigned int)acquire + total);
    MediusRingItemHeader *header = (MediusRingItemHeader *)acquire;
    header->length = item_bytes;
    header->flags = 0;
    if ((unsigned int)tail - (unsigned int)next < 8U)
        next = head;
    unsigned char *free_position = ring->free;
    ring->acquire = next;
    if (next == free_position)
        ring->flags = ring->flags | 4U;
    return acquire + 8;
}

/* Native entry: 0x40380f98. */
/*
 * Medius v3.4.7 — host application; 0x40380f98.
 * Instruction-checked recovered C.
 * Original function-byte SHA-256:
 * 5ae3aef1aea3bd9e33baacfda5977db8c7d22c784cb9cc9fc916cc8e028d9c6f.
 */

/* Assert handle and item (NULL permitted only for size0). Reject size above
 * max_item_size with0. Zero-length BYTE_BUFFER send succeeds1 without locking,
 * copying or wakeup. Otherwise invoke the generic copy path with no acquired
 * pointer, forwarding the original tick budget and its result unchanged.
 * Caller retains its source; the copy callback owns storage formatting. */
int xRingbufferSend(MediusRingbuffer *ring,const void *item,size_t item_bytes,
                    unsigned int ticks_to_wait)
{
    if (!ring || (!item && item_bytes != 0))
        __assert_func(0,0,0,0);
    if (item_bytes > ring->max_item_size)
        return 0;
    if ((ring->flags & 2U) && item_bytes == 0)
        return 1;
    return prvSendAcquireGeneric(ring,item,NULL,item_bytes,ticks_to_wait);
}

/* Native entry: 0x40380fdc. */
/*
 * Medius v3.4.7 — host application; 0x40380fdc.
 * Instruction-checked recovered C.
 * Original function-byte SHA-256:
 * 12f46ef0fe7d93d94d834040f33538293e0ab951d9a87366a36da7d6b9b76612.
 */

/* Assert non-NULL handle/output-size and ALLOW_SPLIT clear. Receive one borrowed
 * item (no max-byte cap, no split-tail outputs), forwarding tick budget as the
 * generic helper's seventh stack-passed argument. Return NULL unless helper
 * returns exactly1; size output is whatever helper wrote, not cleared here on
 * failure. Caller must return a successful borrowed pointer to the SAME ring. */
void *xRingbufferReceive(MediusRingbuffer *ring,size_t *item_bytes,
                         unsigned int ticks_to_wait)
{
    if (!ring || !item_bytes || (ring->flags & 1U))
        __assert_func(0,0,0,0);
    void *item;
    int received = prvReceiveGeneric(ring,&item,NULL,item_bytes,NULL,0,ticks_to_wait);
    return received == 1 ? item : NULL;
}

/* Native entry: 0x40381018. */
/*
 * Medius v3.4.7 — host application; 0x40381018.
 * Instruction-checked recovered C.
 * Original function-byte SHA-256:
 * f5f3e53ed10d5dc05d9fab962e2fa9c21495b89bf8c707c301d562545a34003e.
 */

/* Return an outstanding borrowed item under ring mux through the configured
 * release callback (+0x18). Assert handle/item non-NULL; callback validates or
 * releases according to ring mode. After MEMW sample send-wait-list count;
 * remove one waiter if nonzero and request this core's crosscore yield only
 * when removal returns exactly1. Exit mux. No independent ownership/bounds
 * validation, payload copy or waiting for senders to run. */
void vRingbufferReturnItem(MediusRingbuffer *ring,void *item)
{
    if (!ring || !item)
        __assert_func(0,0,0,0);
    (void)xPortEnterCriticalTimeout(&ring->lock,-1);
    ring->return_item(ring,item);
    memw();
    if (*(volatile unsigned int *)&ring->waiting_to_send.count != 0 &&
        xTaskRemoveFromEventList(&ring->waiting_to_send) == 1)
        esp_crosscore_int_send_yield((xtensa_read_prid() >> 13) & 1U);
    vPortExitCritical(&ring->lock);
}

/* Native entry: 0x40380d68. */
/*
 * Medius v3.4.7 — host application; 0x40380d68.
 * Instruction-checked recovered C.
 * Original function-byte SHA-256:
 * aba3471dfbe86ddca0b44e145bd36dcc528bcf603f5d065eda1fa041a644e1f3.
 */

/* Generic send/acquire. Caller validates mode, size and source/output pointers.
 * Under ring mux, fit callback must return exactly1. For acquired!=NULL reserve
 * no-split storage and store pointer without publishing readable data. Otherwise
 * copy through callback; if queue_set non-NULL, unlock then RELOAD the queue
 * handle and send the ring pointer with zero wait (ignore result). With no set,
 * MEMW then wake one receiver and request this core's yield if removal==1.
 * Return1 after fit success, independent of notification result. If no fit,
 * zero wait returns0; otherwise initialize timeout once, let timeout helper
 * reduce remaining budget, enqueue on send list, request this core's yield
 * while mux held, unlock and retry. Expiration returns0 after unlocking. No
 * unlocked busy polling or copy outside callback; callback owns ring counters. */
int prvSendAcquireGeneric(MediusRingbuffer *ring,const void *item,void **acquired,
                          size_t item_bytes,unsigned int ticks_to_wait)
{
    bool timeout_initialized = false;
    RtosTimeout timeout;
    for (;;) {
        (void)xPortEnterCriticalTimeout(&ring->lock,-1);
        if (ring->check_fits(ring,item_bytes) == 1) {
            if (acquired) {
                *acquired = prvAcquireItemNoSplit(ring,item_bytes);
                vPortExitCritical(&ring->lock);
            } else {
                ring->copy_item(ring,item,item_bytes);
                if (ring->queue_set) {
                    vPortExitCritical(&ring->lock);
                    (void)xQueueGenericSend(ring->queue_set,&ring,0,0);
                } else {
                    memw();
                    if (*(volatile unsigned int *)&ring->waiting_to_receive.count != 0 &&
                        xTaskRemoveFromEventList(&ring->waiting_to_receive) == 1)
                        esp_crosscore_int_send_yield((xtensa_read_prid() >> 13) & 1U);
                    vPortExitCritical(&ring->lock);
                }
            }
            return 1;
        }
        if (!ticks_to_wait) {
            vPortExitCritical(&ring->lock);
            return 0;
        }
        if (!timeout_initialized)
            vTaskInternalSetTimeOutState(&timeout);
        if (xTaskCheckForTimeOut(&timeout,&ticks_to_wait)) {
            vPortExitCritical(&ring->lock);
            return 0;
        }
        vTaskPlaceOnEventList(&ring->waiting_to_send,ticks_to_wait);
        esp_crosscore_int_send_yield((xtensa_read_prid() >> 13) & 1U);
        timeout_initialized = true;
        vPortExitCritical(&ring->lock);
    }
}

/* Native entry: 0x40380e60. */
/*
 * Medius v3.4.7 — host application; 0x40380e60.
 * Instruction-checked recovered C.
 * Original function-byte SHA-256:
 * 2244c8d1534b82896c44ad704997eac39bf4d26b2bbd519b96b3b3a0a128297b.
 */

/* Borrow data under ring mux; caller supplies outputs required by its mode.
 * BYTE_BUFFER requires read==free (no outstanding borrow), positive unread
 * count and write!=read or FULL. Item modes require positive count, distinct
 * read/write or FULL; no-split additionally requires header WRITTEN8. Get
 * callback receives max_bytes only for byte mode; item mode gets split output
 * and zero limit. Reload mode flags BEFORE storing head pointer. In split mode,
 * split==1 fetches tail and stores it before asserting unsigned tail<head and
 * split reset0; otherwise store NULL tail without touching tail-size output.
 * Success1 transfers a borrow, not a copy; caller later returns its item(s).
 * On unavailable data use zero/remaining tick budget: timeout starts once,
 * enqueue on receive list, yield this core while mux held, unlock/retry.
 * Timeout returns0 without clearing outputs. No general pointer or mode
 * validation, independent callback-result validation or hardware timing claim. */
int prvReceiveGeneric(MediusRingbuffer *ring,void **head_item,void **tail_item,
                       size_t *head_bytes,size_t *tail_bytes,size_t max_bytes,
                       unsigned int ticks_to_wait)
{
    bool timeout_initialized = false;
    RtosTimeout timeout;
    for (;;) {
        (void)xPortEnterCriticalTimeout(&ring->lock,-1);
        unsigned int flags = ring->flags;
        bool available = false;
        if (flags & 2U) {
            unsigned char *read_position = ring->read;
            if (read_position == ring->free && ring->items_waiting > 0)
                available = ring->write != read_position || (flags & 4U);
        } else if (ring->items_waiting > 0) {
            unsigned char *read_position = ring->read;
            if (read_position != ring->write || (flags & 4U))
                available = (flags & 3U) ||
                    (((MediusRingItemHeader *)read_position)->flags & 8U);
        }
        if (available) {
            int split = 0;
            void *head;
            if (flags & 2U)
                head = ring->get_item(ring,NULL,max_bytes,head_bytes);
            else
                head = ring->get_item(ring,&split,0,head_bytes);
            flags = ring->flags;
            *(void * volatile *)head_item = head;
            if (flags & 1U) {
                if (split == 1) {
                    void *tail = ring->get_item(ring,&split,0,tail_bytes);
                    *(void * volatile *)tail_item = tail;
                    if ((unsigned int)tail >= (unsigned int)*(void * volatile *)head_item || split != 0)
                        __assert_func(0,0,0,0);
                } else {
                    *(void * volatile *)tail_item = NULL;
                }
            }
            vPortExitCritical(&ring->lock);
            return 1;
        }
        if (!ticks_to_wait) {
            vPortExitCritical(&ring->lock);
            return 0;
        }
        if (!timeout_initialized)
            vTaskInternalSetTimeOutState(&timeout);
        if (xTaskCheckForTimeOut(&timeout,&ticks_to_wait)) {
            vPortExitCritical(&ring->lock);
            return 0;
        }
        vTaskPlaceOnEventList(&ring->waiting_to_receive,ticks_to_wait);
        esp_crosscore_int_send_yield((xtensa_read_prid() >> 13) & 1U);
        vPortExitCritical(&ring->lock);
        timeout_initialized = true;
    }
}
