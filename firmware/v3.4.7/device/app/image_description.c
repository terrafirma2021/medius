/* Device mapped application description. */
#include "../include/types.h"

/* Native entry: 0x42002518. */
/* Original function-byte SHA-256:
 * 3b3228b48c28ca95be263c6f5468b602c0913e7b173ebb7fbd99e0011f0466ce. */
/* Return the borrowed256-byte ESP-IDF application descriptor at0x3c040020.
 * One literal load and return: no descriptor read, validation, allocation,
 * mutation or failure path. Field layout is pinned to the image/IDF5.4 format. */
const EspAppDescription *get_app_description(void)
{
    return (const EspAppDescription *)0x3c040020U;
}
