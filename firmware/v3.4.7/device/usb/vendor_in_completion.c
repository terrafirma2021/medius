/* Medius v3.4.7 device — auxiliary/vendor IN completion. */
#include "../include/types.h"

/* Native entry: 0x4202c148. */
/* Original function-byte SHA-256:
 * 9b18b829bac75521a36a755a9362bf42187bfe9852e8ec718d95e07b84ed6e96. */
/*
 * Complete the first exact auxiliary binding for endpoint; ignore bus. Sample
 * the initial clock before entering the credit lock and retain only its LOW
 * word for capture. Lock-entry status is ignored. Cache the signed binding
 * count once, with no twelve-entry cap. Reject an unmatched endpoint, a first
 * match without its IN bit, slot>=6, or a fenced nonzero blocked BYTE; unlock
 * and return without pumping, capture or notification in these cases.
 *
 * Cache capture class9 from one fenced HALFWORD read. If enabled, copy
 * min(actual,64) bytes from the slot's 64-byte storage to the local buffer,
 * then reload the binding's slot BYTE without repeating bounds/blocked tests.
 * Read transfer type after the copy. Type2 skips the weight/credit observer.
 * Other types read the slot's weight: zero skips the observer and final link
 * wake. Nonzero weight samples a second clock, reloads slot yet again, reads
 * submission LOW then HIGH with separate MEMW barriers, and calls the credit
 * observer with endpoint's low nibble, both 64-bit times and unshortened actual.
 *
 * Fence/clear in-flight BYTE, then fence/set completion-seen BYTE; pump by the
 * full binding index while still locked. Unlock and, for type2 or nonzero
 * weight only, wake link TX using its ISR API. Enabled capture follows outside
 * the lock: class9, endpoint number, source-kind1, flag2 iff copied length0,
 * initial clock LOW, subtype1, saved payload/length. It uses the cached class
 * decision even if subscriptions changed during pumping.
 *
 * No allocation, software timer, generation validation or coherent state
 * snapshot. Concurrent slot changes after either reload remain unchecked;
 * initial table length and later memory access safety are caller invariants.
 * Static instruction review does not verify hardware timing or race behavior.
 */
void medius_vendor_device_in_complete(unsigned char bus,unsigned char endpoint,
    unsigned int actual)
{
    (void)bus;
    unsigned int capture_stamp = (unsigned int)esp_timer_get_time();
    (void)xPortEnterCriticalTimeout(&CREDIT_LOCK,-1);
    int count = CREDIT_BINDINGS.count;
    unsigned int binding_index = 0;
    for (; binding_index < (unsigned int)(count > 0 ? count : 0); ++binding_index) {
        if (CREDIT_BINDINGS.entry[binding_index].endpoint == endpoint) break;
    }
    if (count <= 0 || binding_index == (unsigned int)count || (endpoint & 0x80U) == 0) {
        vPortExitCritical(&CREDIT_LOCK);
        return;
    }

    const volatile CreditBinding *binding =
        (const volatile CreditBinding *)
        ((unsigned int)&CREDIT_BINDINGS + binding_index * 8U);
    unsigned int slot = binding->queue_slot;
    if (slot >= 6) {
        vPortExitCritical(&CREDIT_LOCK);
        return;
    }
    memw();
    unsigned char blocked = REPORT_SECONDARY_BLOCKED[slot];
    if (blocked != 0) {
        vPortExitCritical(&CREDIT_LOCK);
        return;
    }
    memw();
    unsigned short classes = CAPTURE_ENABLED_CLASSES;
    unsigned short capture_mask = classes & 0x200U;
    unsigned short copied_length = 0;
    unsigned char captured[64];
    if (capture_mask != 0) {
        copied_length = (unsigned short)(actual < 64U ? actual : 64U);
        const unsigned char *storage = (const unsigned char *)
            ((unsigned int)REPORT_SECONDARY_STORAGE + slot * 64U);
        memcpy(captured,storage,copied_length);
        slot = binding->queue_slot;
    }

    unsigned char kind = binding->kind;
    int wake_link = 1;
    if (kind != 2) {
        unsigned char weight = REPORT_SECONDARY_WEIGHT[slot];
        if (weight == 0) {
            wake_link = 0;
        } else {
            unsigned long long now_us = (unsigned long long)esp_timer_get_time();
            slot = binding->queue_slot;
            memw();
            unsigned int submitted_low = REPORT_SECONDARY_TIME[slot].low;
            memw();
            unsigned int submitted_high = REPORT_SECONDARY_TIME[slot].high;
            unsigned long long submitted_us =
                ((unsigned long long)submitted_high << 32) | submitted_low;
            credit_observe_in_completion(endpoint & 15U,now_us,submitted_us,actual);
        }
    }
    memw();
    REPORT_SECONDARY_IN_FLIGHT[slot] = 0;
    memw();
    REPORT_SECONDARY_COMPLETION_SEEN[slot] = 1;
    report_pump_secondary(binding_index);
    vPortExitCritical(&CREDIT_LOCK);
    if (wake_link) link_wake_fast_transmit_from_isr();
    if (capture_mask != 0)
        medius_capture_record_transfer(9,endpoint & 15U,1,
            copied_length == 0 ? 2 : 0,capture_stamp,1,captured,copied_length);
}
