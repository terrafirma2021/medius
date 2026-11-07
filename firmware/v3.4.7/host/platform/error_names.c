/* Medius v3.4.7 host — linked error-name fallback. */
#include "../include/types.h"

/* Native entry: 0x42003930. */
/* Original function-byte SHA-256:
 * 05190d0b5fba1901a6597a68da8b73771d3180e29068ef6c0b6ed2af58b4f4c3. */
/* Return the pinned immutable string "UNKNOWN ERROR" at0x3c0454f0.
 * The error argument is unused: no error-code table, numeric formatting,
 * allocation, output, hardware read or failure path in this linked image. */
const char *esp_err_to_name(int unused_error)
{
    return (const char *)0x3c0454f0U;
}
