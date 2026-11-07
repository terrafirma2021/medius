/* Medius v3.4.7 device — link/clock.c.
 * Recovered link-sync startup/status; native identities follow.
 */

#include "../include/types.h"

/* Native entry: 0x42022698. */
/* Original function-byte SHA-256:
 * dea2826c006eadba7d3ce8133e155191b1594201e6e89de979af6e125efaadc9. */
/* Zero624 bytes of link-sync filter/history scratch, then create a four-item
 * queue with16-byte records and publish the returned handle, including NULL.
 * Create link_sync with3072-byte stack,priority10,argument LOW8 encoded as a
 * pointer,NULL output handle and no-affinity0x7fffffff. Ignore task status;
 * queue failure still attempts task creation. Shared estimate and sync period
 * are not reset here. No repeated-call guard, prior-task stop, cleanup, rollback,
 * lock or worker-lifetime guarantee. Worker body is a separate review. */
void link_start_sync_task(unsigned int startup_role)
{
    memset(LINK_SYNC_FILTER_SCRATCH,0,624);
    RtosQueue *created_queue = xQueueGenericCreate(4,16);
    LINK_SYNC_QUEUE = created_queue;
    xTaskCreatePinnedToCore(link_sync_task,"link_sync",3072,
        (void *)(startup_role & 255U),10,NULL,0x7fffffff);
}

/* Native entry: 0x420226dc. */
/* Original function-byte SHA-256:
 * 2aed3478e8ea205627ead2782b15a067569424c4fdf4e91fd2e2a4db5fb6bc64. */
/* Read six sync-status outputs from one locked estimate snapshot.
 * Lock sync mux indefinitely, ignoring status. Cache ready8,drift-valid8,
 * offset32,drift32,round-trip32,reference-low32 IN THAT ORDER; unlock before
 * ALWAYS sampling time. Compute unsigned32 low-time age. Fresh means age is
 * <=59999999us. Only ready BIT0 survives the freshness mask. If it is clear,
 * output ready/offset/drift/drift-valid0 and ageFFFF. Round-trip still reports
 * the ORIGINAL cached value saturated to65535, even for a stale estimate.
 * If fresh/ready, age is floor(age_us/1000), offset remains raw. Drift-valid0
 * zeroes drift and leaves ready1; otherwise ready becomes RAW drift-valid byte,
 * with raw drift and drift-valid preserved. No boolean normalization is added.
 * Publish VOLATILE outputs in native order:ready8,offset32,drift32,round-trip16,
 * drift-valid8,age16. Every output is required/writable, including stale cases.
 * No NULL check, timer recheck or atomic output publication; aliasing outputs
 * observe that write order. Actual synchronization accuracy is not established. */
void link_read_sync_status(unsigned int *offset_us,unsigned int *drift_ppb,
    unsigned short *round_trip_us,unsigned short *sample_age_ms,
    unsigned char *ready,unsigned char *drift_valid)
{
    xPortEnterCriticalTimeout(&LINK_CLOCK_LOCK,-1);
    unsigned char sampled_ready = LINK_CLOCK_ESTIMATE->ready;
    unsigned char sampled_drift_valid = LINK_CLOCK_ESTIMATE->drift_valid;
    unsigned int offset_snapshot = LINK_CLOCK_ESTIMATE->offset_us;
    unsigned int drift_snapshot = (unsigned int)LINK_CLOCK_ESTIMATE->drift_ppb;
    unsigned int round_trip_snapshot = LINK_CLOCK_ESTIMATE->round_trip_us;
    unsigned int reference_us_low = LINK_CLOCK_ESTIMATE->reference_us_low;
    vPortExitCritical(&LINK_CLOCK_LOCK);
    unsigned int age_us = (unsigned int)esp_timer_get_time() - reference_us_low;
    unsigned char effective_ready = sampled_ready & (unsigned char)(age_us <= 59999999U);
    unsigned short age_ms;
    if (effective_ready == 0) {
        age_ms = 0xffff;
        sampled_drift_valid = 0;
        drift_snapshot = 0;
        offset_snapshot = 0;
    } else {
        age_ms = (unsigned short)(age_us / 1000U);
        if (sampled_drift_valid == 0) drift_snapshot = 0;
        else effective_ready = sampled_drift_valid;
    }
    *(volatile unsigned char *)ready = effective_ready;
    *(volatile unsigned int *)offset_us = offset_snapshot;
    *(volatile unsigned int *)drift_ppb = drift_snapshot;
    *(volatile unsigned short *)round_trip_us = (unsigned short)(round_trip_snapshot < 65535U ? round_trip_snapshot : 65535U);
    *(volatile unsigned char *)drift_valid = sampled_drift_valid;
    *(volatile unsigned short *)sample_age_ms = age_ms;
}
