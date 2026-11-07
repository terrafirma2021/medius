/* Medius v3.4.7 device — usb/state.c.
 * Recovered C and native assembly, grouped for source navigation.
 * Original entry addresses, firmware-byte hashes and function comments follow.
 */

#include "../include/types.h"

/* Native entry: 0x42029ba0. */
/* Original function-byte SHA-256:
 * b2edb8dcdb51947573e0b230a126027776a8f460407b37718a49652d562201b7. */
/*
 * Reset-generation relay task; argument is unused. Wait forever on notification
 * index0, clearing its count on exit; ignore the returned notification count.
 * Fence/read requested generation WORD, then fence/read forwarded generation
 * WORD. If requested>forwarded using ordinary UNSIGNED comparison, forward the
 * cached requested value with skip_out_wait=0. Always return to notification
 * wait after one decision. No wrap-aware ordering, requested-value reload,
 * coalescing loop, local lock or local update of forwarded generation.
 *
 * Worker initialization registers this entry as rstrelay, priority21,
 * stack3072 bytes, no core affinity. This records its configured scheduling;
 * it does not guarantee when notifications or forwarding complete at runtime.
 */
void reset_relay_task(void *unused_argument)
{
    (void)unused_argument;
    for (;;) {
        (void)ulTaskGenericNotifyTake(0,1,0xffffffffU);
        memw();
        unsigned int requested = DEVICE_OUT_GENERATION;
        memw();
        unsigned int forwarded = CONTROL_FORWARDED_GENERATION;
        if (requested > forwarded)
            control_forward_generations(requested,0);
    }
}

/* Native entry: 0x420284a0. */
/* Original function-byte SHA-256:
 * 4cc4b33fd3a4f1d389e1462b6a974127df14628707dc09d7e00e2eca661f7fce. */
/* Under sequence spinlock, obtain clock LOW32, read latest sequence BYTE,
 * increment modulo256 and select new_sequence&15. Store timestamp|1 WORD first,
 * publish latest sequence BYTE second, then store one HALFWORD containing
 * sequence low8 and endpoint low8. Other record bytes/high clock are untouched.
 * Endpoint is not validated. Timestamp bit0 is forced1 (not exact microseconds).
 * Ignore critical-enter result. Return the newly published sequence as a
 * zero-extended WORD after unlocking. No notification or allocation. */
unsigned int medius_report_record_sequence_event(unsigned int endpoint)
{
    xPortEnterCriticalTimeout(&REPORT_SEQUENCE_LOCK,-1);
    unsigned int time_low = (unsigned int)esp_timer_get_time();
    unsigned char previous = REPORT_SEQUENCE_WINDOW.latest_sequence;
    unsigned char sequence = (unsigned char)(previous + 1);
    unsigned int slot = sequence & 15U;
    REPORT_SEQUENCE_WINDOW.entries[slot].time_low = time_low | 1U;
    REPORT_SEQUENCE_WINDOW.latest_sequence = sequence;
    REPORT_SEQUENCE_WINDOW.entries[slot].sequence_endpoint =
        (unsigned short)((unsigned int)sequence | (endpoint << 8));
    vPortExitCritical(&REPORT_SEQUENCE_LOCK);
    return sequence;
}


/* Native entry: 0x42028590. */
/* Original function-byte SHA-256:
 * 83c3a77a4227a766cb205d5e944caf0d8da0af049fb1fae892d15c40c533c7de. */
/* Log USB slot summary at info level: snapshot time, then secondary count,
 * media slot, keyboard slot, mouse slot, interface count in native read order.
 * Format arguments are label/count/mouse/keyboard/media/secondary. Reload count
 * after logging; when positive, loop over current interfaces. Each iteration
 * obtains FRESH log time, reads report-length HALFWORD BEFORE interface-id BYTE
 * and endpoint BYTE, then logs those three fields only (raw Ghidra added unused
 * arguments). Reload signed count BEFORE incrementing index/comparing again.
 * No label NULL check, array bound, coherent snapshot, lock or result. A growing
 * live count can extend iteration; caller must keep descriptor tables valid. */
void medius_usb_log_interface_slots(const char *label)
{
    unsigned int stamp = esp_log_timestamp();
    int secondary_count = MOTION_AUX_COUNT;
    int media_slot = REPORT_BLOCK2_INTERFACE;
    int keyboard_slot = REPORT_BLOCK1_INTERFACE;
    int mouse_slot = REPORT_BLOCK0_INTERFACE;
    int interface_count = USB_INTERFACE_COUNT;
    esp_log_write(3,"usbdev","I (%lu) %s: %s: %d hid, mouse slot %d, kbd slot %d, media slot %d, %d secondary\n",
        stamp,"usbdev",label,interface_count,mouse_slot,keyboard_slot,media_slot,secondary_count);
    interface_count = USB_INTERFACE_COUNT;
    if (interface_count < 1)
        return;
    unsigned int index = 0;
    do {
        stamp = esp_log_timestamp();
        unsigned int report_length = USB_INTERFACE_REPORT_LENGTHS[index];
        unsigned int interface_id = REPORT_CAPTURE_INTERFACE_IDS[index];
        unsigned int endpoint = USB_INTERFACE_ENDPOINTS[index];
        esp_log_write(3,"usbdev","I (%lu) %s:   intf %u ep 0x%02X rpt %u\n",
            stamp,"usbdev",interface_id,endpoint,report_length);
        interface_count = USB_INTERFACE_COUNT;
        ++index;
    } while ((int)index < interface_count);
}

/* Native entry: 0x42028250. */
/* Original function-byte SHA-256:
 * 64e139ec8e53c563761e0fab6e70f384891e8029c5533790413f8ca03cdc2bdc. */
/*
 * Reset one secondary interface's queue flags: head,count,in-flight,completion
 * seen,blocked, then publish global queues-dirty=1 BEFORE clearing stalled,
 * expected-length,stall-pending. MEMW precedes all stores except expected-length
 * (eight fences total); every store is a BYTE. No old-state read, call, lock,
 * validation or success result. Full32-bit index is not narrowed or bounded;
 * invalid indices address outside their arrays. No atomic reset guarantee.
 */
void medius_interface_clear_runtime_flags(unsigned int interface_index)
{
    memw(); REPORT_SECONDARY_HEADS[interface_index] = 0;
    memw(); REPORT_SECONDARY_COUNTS[interface_index] = 0;
    memw(); REPORT_SECONDARY_IN_FLIGHT[interface_index] = 0;
    memw(); REPORT_SECONDARY_COMPLETION_SEEN[interface_index] = 0;
    memw(); MEDIUS_REPORT_SECONDARY_BLOCKED_RW[interface_index] = 0;
    memw(); REPORT_QUEUES_DIRTY = 1;
    memw(); REPORT_SECONDARY_STALLED[interface_index] = 0;
    REPORT_SECONDARY_EXPECTED_LENGTH[interface_index] = 0;
    memw(); REPORT_SECONDARY_STALL_PENDING[interface_index] = 0;
}
