/* Medius v3.4.7 device — link/routing.c.
 * Recovered link registration and task-context handoff interfaces.
 * Native addresses and original firmware-byte hashes identify every entry.
 */

#include "../include/types.h"

/* Native entry: 0x42022590. */
/* Medius v3.4.7 device; original function-byte SHA-256:
 * 53ea22b42c2c391a8f447c03b3b7bfcc16e1d1c62db0dd02fe7a57517e07fa81. */

/*
 * observer: synchronous callback used by the RX publisher for type 0x10 with
 * at least six payload bytes and type 0x1c with at least eight. NULL disables it.
 * Returns: no value. Stores only the pointer at policy+44; no lock, barrier,
 * validation, allocation, wake or ownership transfer. Caller must coordinate
 * replacement and keep callback code live until in-flight calls finish.
 */
void link_set_receive_observer(LinkRxObserver observer)
{
    LINK_RX_POLICY.observer = observer;
}

/* Native entry: 0x4202259c. */
/* Medius v3.4.7 device; original function-byte SHA-256:
 * 1ef6b468b908ccb53fa99f945736c770b00209e5bcba3cd8ea5aebdd3394c040. */

/*
 * Replaces the direct RX handler and the 256-type pending-count exemption map.
 * direct_type: byte matched by the RX publisher before normal ring insertion.
 * handler: synchronous direct callback; NULL disables that callback, while the
 *   selected type remains exempt from pending accounting when accounting is on.
 * uncounted_types: borrowed byte list, read only during this call; NULL disables
 *   accounting. count: unsigned byte count, 0..255, not a signed loop bound.
 * Returns: no value and no allocation status.
 *
 * Clears all eight bitmap words first. For a non-NULL, nonempty list, ORs one
 * bit per input byte; repeats are harmless and byte values select words 0..7.
 * Only AFTER building the map stores accounting_enabled=(list!=NULL). Thus a
 * non-NULL empty list enables accounting with an empty exemption bitmap.
 * If list is non-NULL, lazily creates a 16-item queue of 100-byte RX copies
 * when its current handle is NULL; stores the allocator result even on failure.
 * Then publishes direct_type followed by handler, irrespective of allocation.
 *
 * NULL list does not delete an existing queue. Does not reset descriptors,
 * pending count, observer or other link state. There is no lock, MEMW, atomic
 * configuration swap, callback-lifetime management, wake or retry loop here.
 * Requires initialized allocator/kernel and serialized configuration against
 * RX activity; readers can otherwise see a cleared/partially filled bitmap or
 * a new type with an old handler. Concurrent lazy creation can leak a queue.
 */
void link_configure_receive(unsigned char direct_type,
    LinkRxDirectHandler handler, const unsigned char *uncounted_types,
    unsigned char count)
{
    memset((void *)LINK_RX_POLICY.uncounted_types, 0,
           sizeof(LINK_RX_POLICY.uncounted_types));
    if (uncounted_types != NULL && count != 0) {
        for (unsigned int type_index = 0; type_index < count; ++type_index) {
            unsigned int type = uncounted_types[type_index];
            LINK_RX_POLICY.uncounted_types[type >> 5] |=
                1U << (type & 31U);
        }
    }
    LINK_RX_POLICY.accounting_enabled = uncounted_types != NULL;
    if (uncounted_types != NULL && LINK_RX_OPTIONAL_QUEUE == NULL)
        LINK_RX_OPTIONAL_QUEUE =
            xQueueGenericCreate(16, sizeof(LinkRxQueueItem));
    LINK_RX_POLICY.direct_type = direct_type;
    LINK_RX_POLICY.direct_handler = handler;
}

/* Native entry: 0x42022620. */
/* Medius v3.4.7 device; original function-byte SHA-256:
 * 1cc0b3d9c165e6545ffa7857dc49f99549ed658f9cb4980e8587367ce55c3cdf. */

/*
 * Copies an application frame into the optional RX task's fallback queue.
 * type,flags: low bytes of the native word arguments. payload: borrowed source
 * valid for length bytes during memcpy. length: unsigned 16-bit byte count.
 * Returns 1 on exact queue-send success, otherwise 0. No error is logged.
 *
 * Rejects a NULL initial queue handle or length>96 without copying/notifying.
 * Zeroes the payload with 24 WORD stores, writes the length halfword, then the
 * packed type/flags halfword, and calls memcpy even for length zero. Reloads the queue handle
 * AFTER the copy and sends the entire 100-byte local item at back with no wait.
 * Queue result other than exact 1 returns 0. On success reloads the RX task
 * handle; a non-NULL task receives notification(index0,value0,eIncrement=2,
 * previous_value=NULL). Notify status is ignored and absence of a task still
 * returns 1. There is no direct dispatch or pending-count increment here.
 *
 * Requires an initialized 100-byte queue and synchronous queue copying before
 * the stack item expires. Does not validate payload, reserve queue space, lock
 * reconfiguration, wait for delivery or prove the RX task runs. The initial
 * handle check does not protect the later reloaded handle. No ISR API is used;
 * this is the task-context fallback path.
 */
int link_enqueue_rx_copy(unsigned char type, unsigned char flags,
                                const void *payload, unsigned short length)
{
    if (LINK_RX_OPTIONAL_QUEUE == NULL || length > 96)
        return 0;
    LinkRxQueueItem item __attribute__((aligned(4)));
    volatile unsigned int *payload_words =
        (volatile unsigned int *)(void *)item.payload;
    for (unsigned int word_index = 0; word_index < 24; ++word_index)
        payload_words[word_index] = 0;
    volatile LinkRxQueueItem *item_view = &item;
    item_view->length = length;
    item_view->type_and_flags = (unsigned short)(type | ((unsigned int)flags << 8));
    memcpy(item.payload, payload, length);
    if (xQueueGenericSend(LINK_RX_OPTIONAL_QUEUE, &item, 0, 0) != 1)
        return 0;
    RtosTask *task = LINK_RX_TASK_HANDLE;
    if (task != NULL)
        xTaskGenericNotify(task, 0, 0, 2, NULL);
    return 1;
}

/* Native entry: 0x42022770. */
/* Medius v3.4.7 device; original function-byte SHA-256:
 * d23c3bf5f34c73abd88dc69cdad5345673822bb60aadc7cf23375de72bb0fb13. */

/*
 * handler: fast TX payload builder, or NULL to disable it. The TX worker calls
 * it with type_out, payload_out and capacity 64; the returned word is a length.
 * Returns: no value. Replaces only the callback pointer, without a pending-flag
 * change, notification, lock, barrier or code-lifetime protection. A worker
 * that already cached the old pointer may still call it. Caller must coordinate
 * replacement and satisfy the worker's output-buffer/length requirements.
 */
void link_set_fast_transmit_handler(LinkFastTxHandler handler)
{
    LINK_TX_FAST_HANDLER = handler;
}
