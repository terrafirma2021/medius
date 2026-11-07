/* Medius v3.4.7 device — alternate-setting report/capture support. */
#include "../include/types.h"

/* Native entry: 0x40392564. */
/* Original function-byte SHA-256:
 * 304827d0623df102497078aa1e7f6ff6cb0c049faadb12a8fe56a4d67fc57c4f. */
/* Drain pending OUT work for every raw-control endpoint, then every served
 * binding whose address has bit 7 clear. Preserve table order and duplicates;
 * EP0 is not excluded. Reload each signed WORD count after every iteration,
 * including callbacks, rather than snapshotting or clamping it. The served
 * address is read once for both direction test and call. No local lock, table
 * validation, completion wait or aggregate result is supplied.
 */
void out_drain_all_served_endpoints(void)
{
    int index = 0;
    while (index < MEDIUS_RAW_CONTROL_ENDPOINT_COUNT) {
        unsigned int endpoint = MEDIUS_RAW_CONTROL_ENDPOINT_ADDRESSES[index];
        ++index;
        out_drain_pending(endpoint);
    }
    index = 0;
    while (index < CREDIT_BINDINGS.count) {
        unsigned int endpoint = CREDIT_BINDING_RECORDS[index].endpoint;
        if ((endpoint & 0x80U) == 0)
            out_drain_pending(endpoint);
        ++index;
    }
}
