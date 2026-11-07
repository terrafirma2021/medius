/* Medius v3.4.7 device — linked error-name fallback. */
#include "../include/types.h"

/* Native entry: 0x42003bfc. */
/* Original function-byte SHA-256:
 * 89126654902de2b6466e86774cf3a1006cccab7673ac08254a3bfbc8e3590d79. */
/* Return the pinned immutable string "UNKNOWN ERROR" at0x3c045f40.
 * The error argument is unused: no error-code table, numeric formatting,
 * allocation, output, hardware read or failure path in this linked image. */
const char *esp_err_to_name(int unused_error)
{
    return (const char *)0x3c045f40U;
}
