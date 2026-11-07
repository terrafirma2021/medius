/* Medius v3.4.7 host: platform/init_noops.c. */
#include "../include/types.h"

/* Native entry: 0x4201e740. */
/* Original function-byte SHA-256:
 * 92c9598ac7519d458b9e367d0d7b28064c9bff38bae50b088825d1dda27f16a4. */
/* Registered int(void) no-op in the system-init table: stage 0,
 * core-mask 1 (CPU0 only). Return ESP_OK/zero without reading arguments,
 * accessing state, making calls or adding barriers. The dispatcher handles
 * filtering and abort-on-error; this callback cannot report an error.
 * Its original SDK spelling is not encoded in the table; the descriptive
 * name records the proven registration and complete three-instruction body. */
int system_init_stage_zero_noop(void)
{
    return 0;
}

/* Native entry: 0x4201e7b4. */
/* Original function-byte SHA-256:
 * 92c9598ac7519d458b9e367d0d7b28064c9bff38bae50b088825d1dda27f16a4. */
/* Registered int(void) no-op in the system-init table: stage 1,
 * core-mask 1 (CPU0 only). Return ESP_OK/zero without reading arguments,
 * accessing state, making calls or adding barriers. The dispatcher handles
 * filtering and abort-on-error; this callback cannot report an error.
 * Its original SDK spelling is not encoded in the table; the descriptive
 * name records the proven registration and complete three-instruction body. */
int system_init_stage_one_noop(void)
{
    return 0;
}
