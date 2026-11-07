/* Medius v3.4.7 device — medius_capture_control_build. */
#include "../include/types.h"

/* Native entry: 0x40392ad4. */
/* Original function-byte SHA-256:
 * c2116e1cfafae942c0711f544b9af232da24174fa1b440c09bbdf8bc6e64eb91. */
/*
 * Build and submit one control capture using caller-owned scratch/output.
 * Sample bank BYTE then enabled-classes HALFWORD after separate MEMWs, even on
 * rejection. Enabled bit uses class modulo32; rule equality uses the full WORD.
 * Cache bank/count; no bank/count bounds check or coherent configuration lock.
 *
 * Kind0 accepts either direction. Other kinds require low8(direction_out+1).
 * Exact class/endpoint scores4/5, exact class/FFFF scores2/3, classFF wildcard
 * scores0/1 while ignoring its endpoint. First highest score wins. Query classFF
 * still takes the exact-class branch first. Cache selected payload-limit BYTE.
 *
 * Always copy eight SETUP bytes to scratch. For nonnull nonempty payload copy
 * min(length,172) after them, then sample time once. Original length is8 for
 * NULL payload, otherwise low16(length+8), even when fewer bytes were copied.
 * Apply nonzero subscriber limit, then cap emitted payload at180. This retains
 * the original16-bit wrap and does not initialize unused scratch/output bytes.
 *
 * Write version,reserved7,source-kind, four timestamp BYTEs,class,endpoint,flags
 * and original-length low/high BYTEs in native order. Copy admitted scratch
 * bytes, submit kind0x16 with size12+copied and subscriber bit(index modulo32),
 * and notify only on nonzero submission result. No separate room hint here.
 * Return no value. Caller supplies at least180 scratch/192 output bytes and
 * readable SETUP/payload storage; no NULL check, pointer repair or delivery
 * guarantee. Native callbacks/capture routing are separate functions.
 */
void medius_capture_control_build(unsigned int traffic_class,unsigned int endpoint,
    unsigned char *setup,unsigned char direction_out,unsigned char flags,
    unsigned char *payload,unsigned short length,unsigned char *scratch,unsigned char *output)
{
    memw();
    unsigned int bank_index = CAPTURE_ACTIVE_BANK;
    memw();
    unsigned int enabled = CAPTURE_ENABLED_CLASSES;
    if ((enabled & (1U << (traffic_class & 31U))) == 0)
        return;
    const volatile MediusCaptureSubscriptionBank *bank = &MEDIUS_CAPTURE_BANKS[bank_index];
    unsigned int count = bank->count;
    if (count == 0)
        return;
    unsigned char source_kind = (unsigned char)(direction_out + 1U);
    unsigned int selected = 0xffffffffU;
    int best_score = -1;
    for (unsigned int index = 0; index < count; ++index) {
        const volatile MediusCaptureRule *rule = &bank->rules[index];
        unsigned int kind = rule->kind;
        if (kind != 0 && kind != source_kind)
            continue;
        unsigned int rule_class = rule->traffic_class;
        int score;
        if (rule_class == traffic_class) {
            unsigned int rule_endpoint = rule->endpoint;
            if (rule_endpoint == endpoint)
                score = 4 + (kind != 0);
            else if (rule_endpoint == 65535U)
                score = 2 + (kind != 0);
            else
                continue;
        } else if (rule_class == 255U) {
            score = kind != 0;
        } else {
            continue;
        }
        if (score > best_score) {
            best_score = score;
            selected = index;
        }
    }
    if (selected == 0xffffffffU)
        return;
    unsigned int limit = bank->rules[selected].payload_limit;
    memcpy(scratch,setup,8);
    if (length != 0 && payload != NULL) {
        unsigned int copied = length < 172U ? length : 172U;
        memcpy(scratch + 8,payload,copied);
    }
    unsigned int timestamp = (unsigned int)esp_timer_get_time();
    unsigned short original_length = payload == NULL ? 8U : (unsigned short)(length + 8U);
    unsigned int effective = original_length;
    if (limit != 0 && limit < effective)
        effective = limit;
    unsigned int copied = effective < 180U ? effective : 180U;
    volatile MediusControlCaptureWire *wire = (volatile MediusControlCaptureWire *)output;
    wire->version = 1;
    wire->reserved7 = 0;
    wire->source_kind = source_kind;
    wire->time_le[0] = (unsigned char)timestamp;
    wire->time_le[1] = (unsigned char)(timestamp >> 8);
    wire->time_le[2] = (unsigned char)(timestamp >> 16);
    wire->time_le[3] = (unsigned char)(timestamp >> 24);
    wire->traffic_class = (unsigned char)traffic_class;
    wire->endpoint = (unsigned char)endpoint;
    wire->flags = flags;
    wire->original_length_le[0] = (unsigned char)original_length;
    wire->original_length_le[1] = (unsigned char)(original_length >> 8);
    if (effective != 0)
        memcpy(output + 12,scratch,copied);
    if (capture_submit_event(traffic_class,1U << (selected & 31U),0x16,
            output,(unsigned short)(copied + 12U)) != 0)
        capture_notify_task();
}
