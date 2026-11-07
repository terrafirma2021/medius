/* Medius v3.4.7 device — PSRAM initialization-state observation. */
#include "../include/types.h"

/* Native entry: 0x403771b4. */
/* Original function-byte SHA-256:
 * a3421bf949c74838f411d537ec076326f6f760c1ef1df96709720655fb41f07e. */
/* Return the zero-extended raw PSRAM initialized BYTE. This SDK predicate is
 * normally0/1, but native L8UI does not normalize a corrupted nonzero byte.
 * No MEMW, lock, device access, initialization attempt or lifetime guarantee;
 * the separate initializer owns this shared byte's state changes. */
unsigned char esp_psram_is_initialized(void)
{
    return PSRAM_INITIALIZED;
}
