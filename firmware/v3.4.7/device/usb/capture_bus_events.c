/* Medius v3.4.7 device — USB lifecycle-event capture. */
#include "../include/types.h"

/* Native entry: 0x403782b4. */
/* Original function-byte SHA-256:
 * 88659f23178b0732fdfa7685c8fe224b328be0bc28146ee52aa8c8753039dd70. */
/*
 * Emit a class10 USB lifecycle event when capture class bit10 is enabled and
 * the sampled subscription bank contains a match. event/value0/value1 are native
 * WORDs; wire event uses low8, and the two-byte value is low16(value0|value1<<8),
 * preserving overlap from high value0 bits rather than separately masking them.
 * Return no value. Fence/sample bank BYTE, fence/read enabled HALFWORD, then
 * cache unchecked bank count. Class10 matches only endpointFFFF (score4),
 * wildcardFF ignores endpoint (score0); any nonzero kind adds1. First best wins.
 *
 * Read selected payload limit BYTE before obtaining clock LOW32. Wire header
 * stores time,0xffff0a01,zero BYTE,event BYTE and original payload length2. Limit0
 * means two bytes; otherwise copy min(limit,2), submit12+copied bytes to capture
 * ring class10/kind0x16 with bit(selected&31), and notify only on nonzero submit
 * result. No timestamp-high, whole-stack clearing, subscriber-index validation,
 * locking or payload lifetime extension. Submit must copy its borrowed stack data.
 */
void capture_usb_bus_event(unsigned int event, unsigned int value0,
    unsigned int value1)
{
    memw();
    unsigned int bank_index = CAPTURE_ACTIVE_BANK;
    memw();
    unsigned int enabled = CAPTURE_ENABLED_CLASSES;
    if ((enabled & 0x400U) == 0)
        return;
    const volatile MediusCaptureSubscriptionBank *bank = &MEDIUS_CAPTURE_BANKS[bank_index];
    unsigned int count = bank->count;
    unsigned int selected = 0xffffffffU;
    int best_score = -1;
    for (unsigned int index = 0; index != count; ++index) {
        const volatile MediusCaptureRule *rule = &bank->rules[index];
        unsigned int traffic_class = rule->traffic_class;
        int score;
        if (traffic_class == 10) {
            if (rule->endpoint != 65535)
                continue;
            score = 4;
        } else if (traffic_class == 255) {
            score = 0;
        } else {
            continue;
        }
        if (rule->kind != 0)
            ++score;
        if (score > best_score) {
            best_score = score;
            selected = index;
        }
    }
    unsigned short value = (unsigned short)(value0 | (value1 << 8));
    if (selected == 0xffffffffU)
        return;
    unsigned int limit = bank->rules[selected].payload_limit;
    MediusCaptureBusEvent wire;
    wire.time_low = (unsigned int)esp_timer_get_time();
    wire.endpoint_class = 0xffff0a01U;
    wire.zero = 0;
    wire.event = (unsigned char)event;
    wire.original_length = 2;
    unsigned int copied = limit == 0 ? 2 : limit < 2 ? limit : 2;
    memcpy(wire.payload, &value, copied);
    if (capture_submit_event(10, 1U << (selected & 31U), 0x16,
            &wire, copied + 12U) != 0)
        capture_notify_task();
}
