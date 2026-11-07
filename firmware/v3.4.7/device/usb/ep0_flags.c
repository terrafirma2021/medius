/* Medius v3.4.7 device — EP0 consumption, stall and route flags. */
#include "../include/types.h"

/* Native entry: 0x40382a90. */
/* Original function-byte SHA-256:
 * 6df1afd60efb60dd45249ec0431376e2278f7b1744f41657bdfd6e58a2d6c8ca. */
/* Bus low BYTE 0: MEMW then store handler-consumed=1. Other bus values
 * return without a memory read, write or barrier; only the bus-0 slot exists
 * in this helper. No previous-value test, clearing, validation or lock. */
void medius_ep0_mark_handler_consumed(unsigned char bus)
{
    if (bus != 0) return;
    memw();
    MEDIUS_EP0_HANDLER_CONSUMED_FLAGS[0] = 1;
}

/* Native entry: 0x40382aa8. */
/* Original function-byte SHA-256:
 * 92fb2d496a261239a320eda1dae906e51db1a5f61444460c1bf34b57fb321971. */
/* Bus low BYTE 0: MEMW then store setup-consumed=1. Other bus values
 * return without a memory read, write or barrier; only the bus-0 slot exists
 * in this helper. No previous-value test, clearing, validation or lock. */
void medius_ep0_mark_setup_consumed(unsigned char bus)
{
    if (bus != 0) return;
    memw();
    MEDIUS_EP0_SETUP_CONSUMED_FLAGS[0] = 1;
}

/* Native entry: 0x40382ac0. */
/* Original function-byte SHA-256:
 * e140c191084a8b6ad909e3014797e2e32296b4685d308dd141843085d83e06ab. */
/* Bus low BYTE 0: MEMW then store length-override=1. Other bus values
 * return without a memory read, write or barrier; only the bus-0 slot exists
 * in this helper. No previous-value test, clearing, validation or lock. */
void medius_ep0_mark_length_override(unsigned char bus)
{
    if (bus != 0) return;
    memw();
    MEDIUS_EP0_LENGTH_OVERRIDE_FLAGS[0] = 1;
}

/* Native entry: 0x40391788. */
/* Original function-byte SHA-256:
 * 19b47da6d1c23e201685f5fd8f720d1f389d1d73a184c6f5693e4a62a6efaa8f. */
/* MEMW then unconditionally clear the shared EP0 stall BYTE before calling
 * the bus-0-only consume marker. A nonzero bus still clears stall but does not
 * publish consumed. No controller endpoint-stall register is changed here. */
void medius_ep0_clear_stall_and_consume(unsigned char bus)
{
    memw();
    MEDIUS_EP0_REQUEST_STATE->stall = 0;
    medius_ep0_mark_handler_consumed(bus);
}

/* Native entry: 0x40391b98. */
/* Original function-byte SHA-256:
 * e22bde8a64a248ce1ecf93959522f3b140c1dd911c5afa091587bb19b5e4e643. */
/* MEMW then load the raw shared route BYTE and zero-extend it.
 * No normalization, clearing, previous-direction test or lock. */
unsigned char medius_ep0_get_route(void)
{
    memw();
    return MEDIUS_EP0_REQUEST_STATE->route;
}

/* Native entry: 0x40391bac. */
/* Original function-byte SHA-256:
 * bd7b68108d453321108bcc8a15e7c03f6a8cf9c4b392ed9b70f020e8619c256c. */
/* MEMW then load the raw shared out_payload_suppressed BYTE and zero-extend it.
 * No normalization, clearing, previous-direction test or lock. */
unsigned char medius_ep0_get_out_payload_suppressed(void)
{
    memw();
    return MEDIUS_EP0_REQUEST_STATE->out_payload_suppressed;
}
