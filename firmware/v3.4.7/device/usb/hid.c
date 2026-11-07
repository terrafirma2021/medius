/* Medius v3.4.7 device — usb/hid.c.
 * Recovered C and native assembly, grouped for source navigation.
 * Original entry addresses, firmware-byte hashes and function comments follow.
 */

#include "../include/types.h"

/* Native entry: 0x4202c4dc. */
/* Original function-byte SHA-256:
 * d894483291c1ba247a74050bd665be857e903bfe1d95d534dc5b2527a04a9da9. */
/*
 * Registered HID OUT completion: ignore bus, sample signed endpoint-list count
 * once. First matching endpoint BYTE forwards(endpoint,actual,type3,kind5),
 * then returns. Nonpositive count/missing address does nothing. No lock, count
 * bound, generation/direction validation or copy here; shared helper handles
 * actual<=64 and subsequent accounting. List stability is an external invariant.
 */
void medius_hid_device_out_complete(unsigned char bus,unsigned char endpoint,unsigned int actual)
{
    (void)bus;
    int count = MEDIUS_RAW_CONTROL_ENDPOINT_COUNT;
    for (int index = 0; index < count; ++index) {
        if (MEDIUS_RAW_CONTROL_ENDPOINT_ADDRESSES[index] != endpoint) continue;
        medius_out_complete_enqueue(endpoint,actual,3,5);
        return;
    }
}
