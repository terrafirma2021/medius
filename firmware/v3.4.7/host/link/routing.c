/* Medius v3.4.7 host — link/routing.c.
 * Recovered link registration and task-context handoff interfaces.
 * Native addresses and original firmware-byte hashes identify every entry.
 */

#include "../include/types.h"

/* Native entry: 0x42021598. */
/* Medius v3.4.7 host; original function-byte SHA-256:
 * 19ddb6ac5434c4bd05712358ed4ccaf448041714dcada5196985f0fbcb48de8d. */

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
        for (unsigned int i = 0; i < count; ++i) {
            unsigned int type = uncounted_types[i];
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

/* Native entry: 0x42021790. */
/* Medius v3.4.7 host; original function-byte SHA-256:
 * ab85750f67b56bd3263bba1d0e55fd0dcd5760b964578a77e92a59a0e29f5806. */

/*
 * handler: TX admission callback, NULL permits all selected queued frames.
 * context: opaque 32-bit word forwarded to the callback, not owned here.
 * Returns: no value. Stores handler first, then context; no lock, barrier,
 * validation, notification or pending-state change. A concurrent worker can
 * observe a mixed handler/context pair; configure while externally serialized.
 * Queue 1 applies this callback only above 200 encoded bytes; queue 2 always
 * applies it when non-NULL. The worker is priority 13 and owns the call context.
 */
void medius_link_set_tx_admission(LinkTxAdmissionHandler handler,
                                   unsigned int context)
{
    LINK_TX_ADMISSION = handler;
    LINK_TX_ADMISSION_CONTEXT = context;
}

/* Native entry: 0x420217a0. */
/* Medius v3.4.7 host; original function-byte SHA-256:
 * 4d47b6450f6022542ec89d5c22900b297508e2b02623f726447fc60dc7a9b5ce. */

/*
 * inhibit: byte stored verbatim; any nonzero value inhibits baud probing.
 * Returns: no value. For zero input only, fences and reads the previous byte.
 * If that byte was nonzero, samples the clock, fences, then writes its low32
 * bits as the last-direct-RX timestamp. Finally fences and stores the new byte.
 * Nonzero input skips the old-byte/clock read; repeated zero does not refresh
 * the timestamp. No normalization to boolean, parser reset, UART change,
 * notification or lock. The read/update pair is not an atomic transition;
 * caller must serialize concurrent state changes. This delays the baud task's
 * next age test but establishes neither a real received frame nor peer liveness.
 */
void medius_link_set_baud_probe_inhibit(unsigned char inhibit)
{
    if (inhibit == 0) {
        memw();
        if (LINK_BAUD_PROBE_INHIBIT != 0) {
            unsigned int now_us_low = (unsigned int)esp_timer_get_time();
            memw();
            LINK_LAST_DIRECT_RX_US = now_us_low;
        }
    }
    memw();
    LINK_BAUD_PROBE_INHIBIT = inhibit;
}
