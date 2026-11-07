/* Device capture-status serialization. Native identity and byte hash follow. */

#include "../include/types.h"

/* Native entry: 0x42037c54. */
/* Original function-byte SHA-256:
 * 80bc8f2aaa2011becdc17af0600fd809ec3bfed71343e7f9e74b4c600adaaba4. */
/* Encode QUERY(CATCH), selector7, into at least243 writable bytes.
 * output must not alias the live capture/clock state. No capacity is passed.
 *
 * Read six clock-status outputs before locking the capture table. The ready
 * byte is intentionally unused; invalid drift is encoded as0x80000000. The
 * clock helper supplies saturated round-trip microseconds and age milliseconds.
 * Capture flags/counts and the earlier clock estimate form separate snapshots.
 *
 * Under the capture lock, serialize a19-byte header and at most32 seven-byte
 * subscription records, using native BYTE output stores and little-endian
 * fields. Preserve HIGH-before-LOW ID stores and fresh count/response-count
 * reads. Every scanned subscription reads its drop HALFWORD, even after the
 * output cap is reached. Valid updater state contains at most32 subscriptions;
 * corrupt larger raw counts can read beyond the backing table. There is no
 * local count repair, capacity check, timeout recovery or allocation.
 *
 * Return19+7*emitted_count, at most243, after releasing the capture lock.
 */
unsigned int capture_status_encode(unsigned char *output)
{
    unsigned int clock_offset_bits = 0;
    unsigned int drift_ppb_bits = 0;
    unsigned short roundtrip_us = 0;
    unsigned short clock_age_ms = 0xffff;
    unsigned char clock_ready = 0;
    unsigned char drift_valid = 0;
    link_read_sync_status(&clock_offset_bits,&drift_ppb_bits,&roundtrip_us,
        &clock_age_ms,&clock_ready,&drift_valid);
    if (drift_valid == 0)
        drift_ppb_bits = 0x80000000U;

    (void)xPortInIsrContext();
    (void)xPortEnterCriticalTimeout(CAPTURE_SUBSCRIPTION_LOCK,-1);
    memw();
    unsigned int total_drops = CAPTURE_TOTAL_DROPS;
    unsigned char table_full = CAPTURE_SUBSCRIPTION_FULL;
    volatile CaptureStatusWireHeader *header = (volatile void *)output;
    header->clock_offset_us_le[0] = (unsigned char)clock_offset_bits;
    header->clock_offset_us_le[1] = (unsigned char)(clock_offset_bits >> 8);
    header->total_drops_le[0] = (unsigned char)total_drops;
    header->clock_offset_us_le[2] = (unsigned char)(clock_offset_bits >> 16);
    header->drift_ppb_le[0] = (unsigned char)drift_ppb_bits;
    header->drift_ppb_le[1] = (unsigned char)(drift_ppb_bits >> 8);
    header->selector = 7;
    header->table_full = table_full;
    header->total_drops_le[1] = (unsigned char)(total_drops >> 8);
    header->total_drops_le[2] = (unsigned char)(total_drops >> 16);
    header->total_drops_le[3] = (unsigned char)(total_drops >> 24);
    header->clock_offset_us_le[3] = (unsigned char)(clock_offset_bits >> 24);
    header->drift_ppb_le[2] = (unsigned char)(drift_ppb_bits >> 16);
    header->drift_ppb_le[3] = (unsigned char)(drift_ppb_bits >> 24);
    header->round_trip_us_le[0] = (unsigned char)roundtrip_us;
    header->count = 0;
    header->round_trip_us_le[1] = (unsigned char)(roundtrip_us >> 8);
    header->sample_age_ms_le[0] = (unsigned char)clock_age_ms;
    header->sample_age_ms_le[1] = (unsigned char)(clock_age_ms >> 8);

    unsigned int write_offset = sizeof(CaptureStatusWireHeader);
    if (CAPTURE_SUBSCRIPTION_COUNT != 0) {
        unsigned int subscription_index = 0;
        const volatile CaptureSubscription *subscription = CAPTURE_EDITABLE_SUBSCRIPTIONS;
        unsigned char emitted_count = 0;
        for (;;) {
            memw();
            unsigned short drops = CAPTURE_SUBSCRIBER_DROPS[subscription_index];
            ++subscription_index;
            volatile CaptureStatusWireRecord *record = (volatile void *)(output + write_offset);
            if (emitted_count < 32) {
                unsigned char capture_length = subscription->capture_length;
                unsigned short subscription_id = subscription->id;
                unsigned char traffic_class = subscription->traffic_class;
                unsigned char direction = subscription->direction;
                record->traffic_class = traffic_class;
                record->id_le[1] = (unsigned char)(subscription_id >> 8);
                record->id_le[0] = (unsigned char)subscription_id;
                record->direction = direction;
                record->capture_length = capture_length;
                record->drops_le[0] = (unsigned char)drops;
                record->drops_le[1] = (unsigned char)(drops >> 8);
                write_offset = (write_offset + sizeof(CaptureStatusWireRecord)) & 0xffffU;
                header->count = (unsigned char)(header->count + 1U);
            }
            ++subscription;
            if (CAPTURE_SUBSCRIPTION_COUNT <= (subscription_index & 255U))
                break;
            emitted_count = header->count;
        }
    }
    (void)xPortInIsrContext();
    vPortExitCritical(CAPTURE_SUBSCRIPTION_LOCK);
    return write_offset;
}
