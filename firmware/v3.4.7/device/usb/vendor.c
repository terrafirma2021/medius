/* Medius v3.4.7 device — usb/vendor.c.
 * Recovered C and native assembly, grouped for source navigation.
 * Original entry addresses, firmware-byte hashes and function comments follow.
 */

#include "../include/types.h"

/* Native entry: 0x4202c478. */
/* Original function-byte SHA-256:
 * e21224e3fac789ea6413011eca4e115fbe23b6b88e38aa2667e62222e3b3707b. */
/*
 * Registered vendor OUT completion: bus is ignored; endpoint is low8. Enter
 * credit lock forever, snapshot signed auxiliary count, scan eight-byte records
 * for first exact address match and cache transfer-type BYTE. Unlock BEFORE
 * enqueue(endpoint,actual,type,type==2?7:6). Missing/nonpositive count unlocks
 * without forwarding. No count cap, direction test, payload copy, generation
 * snapshot or status result here; shared completion helper bounds actual64.
 */
void medius_vendor_device_out_complete(unsigned char bus,unsigned char endpoint,unsigned int actual)
{
    (void)bus;
    (void)xPortEnterCriticalTimeout(&CREDIT_LOCK,-1);
    int count = CREDIT_BINDINGS.count;
    for (int index = 0; index < count; ++index) {
        if (CREDIT_BINDINGS.entry[index].endpoint != endpoint) continue;
        unsigned char type = CREDIT_BINDINGS.entry[index].kind;
        vPortExitCritical(&CREDIT_LOCK);
        medius_out_complete_enqueue(endpoint,actual,type,type == 2 ? 7 : 6);
        return;
    }
    vPortExitCritical(&CREDIT_LOCK);
}
