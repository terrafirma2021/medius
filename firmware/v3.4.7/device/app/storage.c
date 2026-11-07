/* Medius v3.4.7 device — app/storage.c.
 * Recovered C and native assembly, grouped for source navigation.
 * Original entry addresses, firmware-byte hashes and function comments follow.
 */

#include "../include/types.h"

/* Native entry: 0x42036394. */
/* Original function-byte SHA-256:
 * 0a2df769b5d2ca1232fec3898d65977a096f4118c665b82cd4c2ebb8e91f1777. */
/* Return the profile-storage erase helper's normalized success unchanged:
 *1 when its ready-gated default NVS erase succeeds,0 when not ready or failed.
 * This four-instruction wrapper adds no arguments, lock, error translation,
 * reinitialization or restart. It is NOT an ESP error-code return; the helper
 * logs the underlying erase status and returns a success boolean as an int.
 */
int factory_reset_storage(void)
{
    return profile_storage_erase();
}
