/* Medius v3.4.7 device — configuration transition publication. */
#include "../include/types.h"

/* Native entry: 0x40396ac8. */
/* Original function-byte SHA-256:
 * 10a3f26595c555fda78a330741cc1445c083bc5233094002a5c1402d1f8e5bc2. */
/* MEMW then store the raw low BYTE into the report fast-path transition gate.
 * Nonzero blocks the reviewed fast report paths until configuration handling
 * clears it. No boolean normalization, rebind operation, readback or lock. */
void medius_report_set_endpoint_transition_pending(unsigned char pending)
{
    memw();
    REPORT_FAST_GATE96 = pending;
}

/* Native entry: 0x40396be4. */
/* Original function-byte SHA-256:
 * e96b10c295ce4eb9dc7213eefda808c6f98aa3d5ea07f09b37b888c1072de853. */
/* MEMW/store the requested configuration BYTE before acquiring the shared
 * portMUX. Call the ISR-context helper, acquire with timeout -1 (result ignored),
 * MEMW/clear alternate-override count, then MEMW/clear the virtual configuration.
 * Call the context helper again and release. Does not clear override records,
 * activate endpoints, normalize configuration, or roll back a failed acquire. */
void medius_clone_note_set_configuration(unsigned char configuration)
{
    memw();
    MEDIUS_CLONE_REQUESTED_CONFIGURATION = configuration;
    (void)xPortInIsrContext();
    (void)xPortEnterCriticalTimeout(MEDIUS_CLONE_CONFIGURATION_LOCK, -1);
    memw();
    MEDIUS_CLONE_CONFIGURATION_OVERRIDE_COUNT = 0;
    memw();
    MEDIUS_CLONE_VIRTUAL_CONFIGURATION = 0;
    (void)xPortInIsrContext();
    vPortExitCritical(MEDIUS_CLONE_CONFIGURATION_LOCK);
}
