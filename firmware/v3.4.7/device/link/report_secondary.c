/* Medius v3.4.7 device: recovered secondary USB report interception/pump. */

#include "../include/types.h"

/* Local reconstruction utilities: retain unchecked native binding/record
 * address arithmetic. Neither helper reads memory or caps a slot/head value. */
static inline __attribute__((always_inline)) const volatile CreditBinding *
report_secondary_binding(unsigned int binding_index)
{
    return (const volatile CreditBinding *)((unsigned int)CREDIT_BINDINGS.entry +
        binding_index * 8U);
}

static inline __attribute__((always_inline)) const volatile CreditSecondaryRecord *
report_secondary_record(unsigned int slot,unsigned int head_index)
{
    return (const volatile CreditSecondaryRecord *)((unsigned int)REPORT_SECONDARY_QUEUES +
        slot * 528U + head_index * 66U);
}

/* Native entry: 0x40399be8. */
/* Original function-byte SHA-256:
 * 5bfb68e06a2a980bce4d11f14b413d31c7e0f4658622bf98d9e47523b02461f8. */

/*
 * endpoint/flags: byte inputs; source_stamp: forwarded unchanged.
 * report/length: borrowed readable report span; length is 16-bit, not capped.
 * Returns 0 unless fast mode, bus-0 configuration, first matching IN binding and
 * slot < 6 admit interception. After admission returns configuration's true
 * value, including drops/filter rejection, missing second lookup or USB failure.
 * This consumes the route; it does not report USB completion.
 *
 * Flag bit 2 requests a stall: nonempty input first passes sequence admission
 * using report[0]. Under the credit lock, rescan a NEW binding-count snapshot,
 * fence/set stall_pending for a valid slot, and pump that BINDING INDEX.
 * Otherwise apply class-6/direction-1 rewrite into 64-byte scratch and enqueue
 * the returned pointer/length only when rewrite returns 0. Scratch is borrowed
 * until enqueue returns. Gate/table/storage initialization and serialization
 * are required; lock statuses are ignored, and first-match behavior is retained.
 */
int report_intercept_secondary(unsigned char endpoint,unsigned int source_stamp,
    unsigned char *report,unsigned short length,unsigned char flags)
{
    memw();
    if (REPORT_FAST_ENABLED == 0)
        return 0;
    int usb_configured = usb_device_is_configured(0);
    if (usb_configured == 0)
        return 0;
    int binding_count = CREDIT_BINDINGS.count;
    for (int binding_index = 0; binding_index < binding_count; ++binding_index) {
        const volatile CreditBinding *binding_entry = report_secondary_binding(binding_index);
        if (binding_entry->endpoint != endpoint)
            continue;
        if ((endpoint & 128U) == 0 || binding_entry->queue_slot >= 6)
            return 0;
        if ((flags & 4U) != 0) {
            if (length != 0 && report_sequence_allowed(endpoint,
                    ((const volatile unsigned char *)report)[0]) == 0)
                return usb_configured;
            xPortEnterCriticalTimeout(&CREDIT_LOCK,0xffffffffU);
            binding_count = CREDIT_BINDINGS.count;
            for (int current_binding_index = 0; current_binding_index < binding_count; ++current_binding_index) {
                const volatile CreditBinding *current_entry =
                    report_secondary_binding(current_binding_index);
                if (current_entry->endpoint != endpoint)
                    continue;
                unsigned int slot = current_entry->queue_slot;
                if (slot < 6) {
                    memw();
                    REPORT_SECONDARY_STALL_PENDING[slot] = 1;
                    report_pump_secondary(current_binding_index);
                }
                break;
            }
            vPortExitCritical(&CREDIT_LOCK);
        } else {
            unsigned char scratch[64];
            unsigned char *rewritten;
            unsigned short rewritten_length;
            unsigned char rewritten_flags;
            if (report_apply_rewrite(6,endpoint,1,report,length,scratch,
                    &rewritten,&rewritten_length,&rewritten_flags) == 0)
                report_enqueue_secondary(endpoint,rewritten,rewritten_length,
                    0,source_stamp,0,rewritten_flags);
        }
        return usb_configured;
    }
    return 0;
}

/* Native entry: 0x40399e40. */
/* Original function-byte SHA-256:
 * a2a91e0290faa12ebe031140573e3d57944c101eca3afdf940ced1523ceb6368. */

/*
 * binding_index: configured binding, not the queue slot. Returns no value.
 * Caller supplies serialization and accessible binding, queue and TX storage.
 * Slot/head/count and the full record-length BYTE are trusted; there is no local
 * lock, bounds check, allocation or 64-byte length clamp.
 * Separately fenced stalled, in-flight and blocked bytes gate all work.
 * Empty queue: fence/test stall_pending; if set, fence/clear it, reread endpoint,
 * fence/set stalled and request bus-0 stall. Otherwise leave all state alone.
 *
 * Nonempty queue: fence/read head, cache that record's length, copy to the FIRST
 * slot's 64-byte TX storage. Reread slot for record credit marker, in-flight,
 * length and timestamp publication. Reread slot AGAIN before LOW/HIGH time stores
 * and use that fresh slot for the USB buffer; endpoint is also reread.
 * Reread slot after USB call. Negative status fence/clears its in-flight byte.
 * Nonnegative status fence/publishes (cached_head+1)&7, then separately fenced
 * fresh count read and decrement/store, wrapping at 8 bits. Binding slot samples
 * are deliberately distinct, and accepted start does not mean completed USB IN.
 */
void report_pump_secondary(unsigned int binding_index)
{
    const volatile CreditBinding *binding_entry = report_secondary_binding(binding_index);
    unsigned int first_slot = binding_entry->queue_slot;
    memw();
    if (REPORT_SECONDARY_STALLED[first_slot] != 0)
        return;
    memw();
    if (REPORT_SECONDARY_IN_FLIGHT[first_slot] != 0)
        return;
    memw();
    if (REPORT_SECONDARY_BLOCKED[first_slot] != 0)
        return;
    memw();
    if (REPORT_SECONDARY_COUNTS[first_slot] == 0) {
        memw();
        if (REPORT_SECONDARY_STALL_PENDING[first_slot] != 0) {
            memw();
            REPORT_SECONDARY_STALL_PENDING[first_slot] = 0;
            unsigned int endpoint = binding_entry->endpoint;
            memw();
            REPORT_SECONDARY_STALLED[first_slot] = 1;
            usb_device_set_stall(0,endpoint);
        }
        return;
    }
    memw();
    unsigned int head_index = REPORT_SECONDARY_HEADS[first_slot];
    const volatile CreditSecondaryRecord *first_record =
        report_secondary_record(first_slot,head_index);
    unsigned int report_length = first_record->length;
    memcpy(REPORT_SECONDARY_STORAGE + first_slot * 64U,
        (const void *)first_record->data,report_length);
    unsigned int metadata_slot = binding_entry->queue_slot;
    unsigned int credit_marker =
        report_secondary_record(metadata_slot,head_index)->credit_marker;
    REPORT_SECONDARY_WEIGHT[metadata_slot] = credit_marker;
    memw();
    REPORT_SECONDARY_IN_FLIGHT[metadata_slot] = 1;
    REPORT_SECONDARY_LENGTH[metadata_slot] = report_length;
    unsigned long long now = esp_timer_get_time();
    unsigned int buffer_slot = binding_entry->queue_slot;
    memw();
    REPORT_SECONDARY_TIME[metadata_slot].low = (unsigned int)now;
    unsigned int endpoint = binding_entry->endpoint;
    memw();
    REPORT_SECONDARY_TIME[metadata_slot].high = (unsigned int)(now >> 32);
    int usb_status = usb_device_write_aligned(0,endpoint,
        REPORT_SECONDARY_STORAGE + buffer_slot * 64U,report_length);
    unsigned int final_slot = binding_entry->queue_slot;
    if (usb_status < 0) {
        memw();
        REPORT_SECONDARY_IN_FLIGHT[final_slot] = 0;
    } else {
        memw();
        REPORT_SECONDARY_HEADS[final_slot] = (head_index + 1U) & 7U;
        memw();
        unsigned int count = REPORT_SECONDARY_COUNTS[final_slot];
        memw();
        REPORT_SECONDARY_COUNTS[final_slot] = count - 1U;
    }
}
