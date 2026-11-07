/* Medius v3.4.7 host: app/motion_startup.c. */
#include "../include/types.h"

/* Native entry: 0x4202448c. */
/* Original function-byte SHA-256:
 * a30d0db394bc6604978405dd41d34e960af904754ac285348d8fd5ef08dd8b43. */
/* Initialize motion output and the software timing grid. Create/publish a type 1
 * mutex only if its slot is NULL; allocation failure is not checked. Store eight
 * WORDs 0x00640064, setting all 16 coefficient HALFWORDs to 100 (not a diagonal
 * matrix), then clear eight fractional WORDs ascending and coupled fractions
 * in order index 1 then 0. Other transform fields and an existing mutex remain.
 * Start the renderer with the motion completion callback; false logs a warning.
 * Create task-dispatch software timer mgrid with NULL argument, skip=false and
 * all three padding BYTES zero. On success start it once for 1,000 us; create or
 * start failure logs one error. Always force status publication afterward.
 * No rollback, duplicate timer cleanup, lock, hardware timer allocation or timing
 * guarantee is supplied; the callback itself schedules subsequent grid work. */
void medius_host_motion_init(void)
{
    if (MEDIUS_MOTION_REPORT_TX_MUTEX==NULL)
        MEDIUS_MOTION_REPORT_TX_MUTEX=rtos_create_mutex_type(1);
    for (unsigned int row=0;row<4;++row) {
        MEDIUS_MOTION_TRANSFORM->coefficient_pairs[row][0]=0x00640064U;
        MEDIUS_MOTION_TRANSFORM->coefficient_pairs[row][1]=0x00640064U;
    }
    for (unsigned int row=0;row<4;++row) {
        MEDIUS_MOTION_TRANSFORM->fractions[row][0]=0;
        MEDIUS_MOTION_TRANSFORM->fractions[row][1]=0;
    }
    MEDIUS_MOTION_TRANSFORM->coupled_fractions[1]=0;
    MEDIUS_MOTION_TRANSFORM->coupled_fractions[0]=0;
    if (!medius_motion_start_renderer(medius_motion_complete_output)) {
        unsigned int timestamp=esp_log_timestamp();
        esp_log_write(2,"motion","W (%lu) %s: render engine did not start\n",timestamp,"motion");
    }
    EspTimerCreateArgs arguments;
    volatile EspTimerCreateArgs *initialization=&arguments;
    initialization->callback=medius_motion_grid_timer_dispatch;
    initialization->argument=NULL;
    initialization->name="mgrid";
    initialization->dispatch=0;
    /* The native initializer clears skip and all three padding bytes together. */
    *(volatile unsigned int *)((unsigned char *)&arguments+
        offsetof(EspTimerCreateArgs,skip_unhandled_events))=0;
    int result=esp_timer_create(&arguments,(EspTimer **)(void *)&MEDIUS_MOTION_GRID_TIMER);
    if (result!=0 || esp_timer_start_once(MEDIUS_MOTION_GRID_TIMER,1000ULL)!=0) {
        unsigned int timestamp=esp_log_timestamp();
        esp_log_write(1,"motion","E (%lu) %s: motion grid did not start\n",timestamp,"motion");
    }
    medius_motion_publish_status(1);
}
