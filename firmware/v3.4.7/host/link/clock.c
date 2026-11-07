/* Medius v3.4.7 host — link/clock.c.
 * Recovered clock-estimate conversion; native identities follow.
 */

#include "../include/types.h"

/* Native entry: 0x42021708. */
/* Original function-byte SHA-256:
 * bf2f659197c2704104e8c6afdcace2244a1968ed29f6c9a8790b2cf26971501f. */
/* Convert remote microseconds32 using the latest shared link-clock estimate.
 * Lock sync mux indefinitely (status ignored). Cache offset32,drift32,ready8,
 * drift-valid8,reference-low32 IN THAT ORDER, then unlock before sampling time.
 * Always call esp_timer_get_time, even on invalid flags. Return raw ready&valid;
 * disjoint nonzero flag bits fail. Unsigned32(now_low-reference)>1000000 fails.
 * Failure leaves output untouched. Snapshot freshness is one modulo32 check.
 *
 * delta32 = remote-(offset+reference), modulo32 then signed. Multiply signed
 * delta by signed drift ppb, divide by1e9 truncating toward0, retain LOW32.
 * error32 = offset+correction-remote+now_low modulo32. Sign-extend that error,
 * subtract from the FULL sampled time modulo64; publish output LOW then HIGH
 * as separate volatile32 stores. No success-path NULL/alignment check, output
 * atomicity, flag normalization, timer-age recheck or physical clock guarantee.
 * The 20-byte struct is a view of shared storage, not an allocation claim. */
unsigned char medius_link_remote_to_local_us(unsigned int remote_us,long long *local_us)
{
    xPortEnterCriticalTimeout(&LINK_CLOCK_LOCK,-1);
    unsigned int offset = LINK_CLOCK_ESTIMATE->offset_us;
    int drift = LINK_CLOCK_ESTIMATE->drift_ppb;
    unsigned char ready = LINK_CLOCK_ESTIMATE->ready;
    unsigned char drift_valid = LINK_CLOCK_ESTIMATE->drift_valid;
    unsigned int reference = LINK_CLOCK_ESTIMATE->reference_us_low;
    vPortExitCritical(&LINK_CLOCK_LOCK);
    unsigned long long now = (unsigned long long)esp_timer_get_time();
    unsigned char valid = ready & drift_valid;
    if (valid == 0 || (unsigned int)now - reference > 1000000U) return 0;
    unsigned int delta = remote_us - (offset + reference);
    long long correction = ((long long)(int)delta * drift) / 1000000000LL;
    unsigned int error = offset + (unsigned int)correction - remote_us + (unsigned int)now;
    unsigned long long converted = now - (unsigned long long)(long long)(int)error;
    volatile ClockWords *output = (volatile void *)local_us;
    output->low = (unsigned int)converted;
    output->high = (unsigned int)(converted >> 32);
    return valid;
}

/* Native entry: 0x4202161c. */
/* Original function-byte SHA-256:
 * 23dda19f85843658a40e6be22a50f950a8b7bdcdcea9aa89ef803e3fe0dbfcb1. */
/* Select raw32 period input, using100 only when input is EXACTLY zero.
 * Fence, then publish one32-bit store. No transient default store, unit
 * conversion, clamp, task notification, mutex or post-store fence. The worker
 * consumes this field separately; this setter does not guarantee cadence. */
void medius_link_set_sync_period(unsigned int period)
{
    unsigned int selected = period == 0 ? 100U : period;
    memw(); LINK_SYNC_PERIOD = selected;
}

/* Native entry: 0x42021630. */
/* Original function-byte SHA-256:
 * c913ec912981c9ee83b3e392e3a592ff2af96e73e4a49705caf363352de62c93. */
/* Zero624 bytes of link-sync filter/history scratch, then create a four-item
 * queue with16-byte records and publish the returned handle, including NULL.
 * Create link_sync with3072-byte stack,priority10,argument LOW8 encoded as a
 * pointer,NULL output handle and no-affinity0x7fffffff. Ignore task status;
 * queue failure still attempts task creation. Shared estimate and sync period
 * are not reset here. No repeated-call guard, prior-task stop, cleanup, rollback,
 * lock or worker-lifetime guarantee. Worker body is a separate review. */
void link_start_sync_task(unsigned int argument)
{
    memset(LINK_SYNC_FILTER_SCRATCH,0,624);
    RtosQueue *queue = xQueueGenericCreate(4,16);
    LINK_SYNC_QUEUE = queue;
    xTaskCreatePinnedToCore(link_sync_task,"link_sync",3072,
        (void *)(argument & 255U),10,NULL,0x7fffffff);
}

/* Native entry: 0x42021674. */
/* Original function-byte SHA-256:
 * 6601d7d72994c99375e86effd58f2bd7835b7840210fe364f4b8061d153d9094. */
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
    unsigned char valid = LINK_CLOCK_ESTIMATE->drift_valid;
    unsigned int offset = LINK_CLOCK_ESTIMATE->offset_us;
    unsigned int drift = (unsigned int)LINK_CLOCK_ESTIMATE->drift_ppb;
    unsigned int round_trip = LINK_CLOCK_ESTIMATE->round_trip_us;
    unsigned int reference = LINK_CLOCK_ESTIMATE->reference_us_low;
    vPortExitCritical(&LINK_CLOCK_LOCK);
    unsigned int age = (unsigned int)esp_timer_get_time() - reference;
    unsigned char effective_ready = sampled_ready & (unsigned char)(age <= 59999999U);
    unsigned short age_ms;
    if (effective_ready == 0) {
        age_ms = 0xffff;
        valid = 0;
        drift = 0;
        offset = 0;
    } else {
        age_ms = (unsigned short)(age / 1000U);
        if (valid == 0) drift = 0;
        else effective_ready = valid;
    }
    *(volatile unsigned char *)ready = effective_ready;
    *(volatile unsigned int *)offset_us = offset;
    *(volatile unsigned int *)drift_ppb = drift;
    *(volatile unsigned short *)round_trip_us = (unsigned short)(round_trip < 65535U ? round_trip : 65535U);
    *(volatile unsigned char *)drift_valid = valid;
    *(volatile unsigned short *)sample_age_ms = age_ms;
}
