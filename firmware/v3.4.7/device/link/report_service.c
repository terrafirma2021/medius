/* Medius v3.4.7 device: recovered interface idle/buffered-report service. */

#include "../include/types.h"

/* Local reconstruction utilities: native byte counts are trusted. Record
 * addresses retain wrapping 32-bit arithmetic without an eight-record limit. */
static inline __attribute__((always_inline)) const volatile CreditInterfaceRecord *
report_service_record(const volatile CreditInterfaceQueue *queue,unsigned int index)
{
    return (const volatile CreditInterfaceRecord *)((unsigned int)queue + index * 84U);
}

/* Native entry: 0x4037a50c. */
/* Original function-byte SHA-256:
 * 8ee8dea0a95639dfe8176032cce6bf71853fa9f3d9c58dcb438cdb2a939223fc. */

/*
 * Services the idle/stall path of one configured USB interface.
 *
 * interface: valid index into interface arrays and the 960-byte queue views.
 * force: nonzero bypasses ONLY the extra_pending == 1 return.
 * Returns no value. Caller supplies serialization and valid buffered storage;
 * no local lock/allocation. USB stall status is ignored.
 *
 * Fence/test service_active, require a mapped endpoint, then fence/test blocked.
 * Require empty history from separate fenced write/read samples. Cache record
 * count and return if any of those records has kind != 1. A recent matching
 * input-0 interface (signed modular age < 200000 us, including negative ages)
 * returns for primary/secondary activity or for kind 1 in a NEW count snapshot.
 *
 * If a buffered length is present, sample the clock, read mode byte +4, reread its length, and
 * derive the mode from bytes +4,+0xdb,+0x11f of that interface's mode view. Two fenced
 * recovery-epoch snapshots admit recovery for age < 3000 us and mode <= 1.
 * Call the queue updater with kind 2, then clear buffered length unconditionally.
 * A result with dropped == 0 returns; otherwise increment the primary drop
 * counter with fences. The updater is recovered in report_queue.c.
 *
 * With no buffer, or after that drop: fence/clear service_active, reread endpoint,
 * fence/set submit-blocked, and request bus-0 endpoint stall. The two count and
 * timestamp snapshots are deliberately independent; no bounds/state repair.
 */
void report_service_interface(unsigned int interface,int force)
{
    memw();
    if (REPORT_SERVICE_ACTIVE[interface] == 0)
        return;
    const volatile unsigned char *endpoint_address =
        (const volatile unsigned char *)((unsigned int)&CREDIT_INTERFACES + interface);
    if (*endpoint_address == 0)
        return;
    memw();
    if (REPORT_INTERFACE_BLOCKED[interface] != 0)
        return;
    volatile CreditInterfaceQueue *queue_state = (volatile CreditInterfaceQueue *)
        ((unsigned int)REPORT_HISTORY_QUEUES + interface * 960U);
    if (queue_state->extra_pending == 1 && force == 0)
        return;
    memw();
    unsigned int history_write_count = queue_state->history_write_count;
    memw();
    unsigned int history_read_count = queue_state->history_read_count;
    if (history_write_count != history_read_count)
        return;
    unsigned int record_count = queue_state->record_count;
    for (unsigned int record_index = 0; record_index < record_count; ++record_index)
        if (report_service_record(queue_state,record_index)->kind != 1)
            return;

    if (REPORT_BLOCK0_ACTIVE != 0 &&
        REPORT_BLOCK0_INTERFACE == (int)interface) {
        unsigned long long now_us = esp_timer_get_time();
        unsigned int low = REPORT_LAST_INPUT[interface].low;
        unsigned int high = REPORT_LAST_INPUT[interface].high;
        unsigned long long previous_input_us = ((unsigned long long)high << 32) | low;
        if ((long long)(now_us - previous_input_us) < 200000) {
            if (input_has_primary_activity(INPUT0_STATE) != 0)
                return;
            if (input_has_secondary_activity(INPUT0_STATE) != 0)
                return;
            record_count = queue_state->record_count;
            for (unsigned int record_index = 0; record_index < record_count; ++record_index)
                if (report_service_record(queue_state,record_index)->kind == 1)
                    return;
        }
    }
    if (REPORT_BUFFERED_LENGTH[interface] != 0) {
        unsigned long long now_us = esp_timer_get_time();
        const volatile ReportInterfaceMode *interface_mode =
            (const volatile ReportInterfaceMode *)
            ((unsigned int)REPORT_INTERFACE_MODES + interface * 304U);
        unsigned int initial_mode_flag = interface_mode->block4;
        unsigned int buffered_length = REPORT_BUFFERED_LENGTH[interface];
        unsigned int mode = initial_mode_flag != 0 || interface_mode->block_db != 0 || interface_mode->block_11f != 0;
        unsigned int allow_recovery = 0;
        memw();
        unsigned int first_low = REPORT_RECOVERY_EPOCH.low;
        memw();
        unsigned int first_high = REPORT_RECOVERY_EPOCH.high;
        if ((first_low | first_high) != 0) {
            memw();
            unsigned int low = REPORT_RECOVERY_EPOCH.low;
            memw();
            unsigned int high = REPORT_RECOVERY_EPOCH.high;
            unsigned long long recovery_epoch_us = ((unsigned long long)high << 32) | low;
            if ((long long)(now_us - recovery_epoch_us) < 3000)
                allow_recovery = REPORT_RECOVERY_MODE <= 1;
        }
        unsigned int report_period = REPORT_INTERFACE_PERIODS[interface];
        ReportQueueResult queue_result = report_queue_update(
            (CreditInterfaceQueue *)queue_state,(const unsigned char *)((unsigned int)REPORT_BUFFERED_STORAGE + interface * 64U),
            buffered_length,2,0,0,mode,0,0,0,interface,allow_recovery,now_us,report_period,interface,0xffffffffU);
        REPORT_BUFFERED_LENGTH[interface] = 0;
        if (queue_result.dropped == 0)
            return;
        memw();
        unsigned int drop_count = REPORT_PRIMARY_FALLBACK_DROPS;
        memw();
        REPORT_PRIMARY_FALLBACK_DROPS = drop_count + 1U;
    }
    memw();
    REPORT_SERVICE_ACTIVE[interface] = 0;
    unsigned int endpoint = *endpoint_address;
    memw();
    REPORT_SUBMIT_BLOCKED_WRITABLE[interface] = 1;
    usb_device_set_stall(0,endpoint);
}
