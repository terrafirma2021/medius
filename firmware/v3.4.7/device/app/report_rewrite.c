/* Medius v3.4.7 device: recovered catch/rewrite rule application. */

#include "../include/types.h"

/* Native entry: 0x4202c5e8. */
/* Original function-byte SHA-256:
 * 3421c0fce5ed11deb230a7479d9763811e54312aa5eaaa46c81f4809f6a125f7. */

/*
 * traffic_class/direction: full comparison words; endpoint: low nibble matched.
 * report/length: borrowed input; scratch: writable 64-byte output workspace.
 * report_out/length_out/flags_out: required, separate writable output objects.
 * Initially publish input pointer, LOW16(length), flags=0 in that order.
 * Returns 1 for a catch-rule drop or rewrite action 1; otherwise 0. Changed
 * output can therefore accompany return 0, signaled by flags=0x80 and scratch.
 * No local allocation or explicit MEMW occurs. Tables/pool/counts must be valid;
 * native counts, prefix lengths and pool offsets are not bounds-checked here.
 *
 * Zero rules with catch disabled returns immediately without touching mutex.
 * Other paths optionally take the current mutex forever, ignore its status,
 * and conditionally run catch rules. Count/enable reloads differ when no mutex
 * exists; retain the initial count only for nonzero rules/no mutex/no catch.
 * Cleanup rereads the GLOBAL mutex and gives that handle if non-NULL, even if
 * it changed or no handle was taken. Caller must serialize handle reconfiguration.
 *
 * Match exact class+endpoint (base 2), exact class+wildcard endpoint (base 1),
 * or wildcard class (base 0, endpoint ignored). Direction 0 is wildcard.
 * Prefix must equal input & mask; stored prefix is NOT masked. Reread masks
 * for popcount after matching. Score = base*100000 + mask_bits*10 + specific
 * direction. First strict maximum wins. Saturate its cached hit counter at MAX.
 *
 * A nonzero action first copies min(length,64), even for drop. Then reread rule
 * payload offset, action and payload length in that order. Actions 2/7 patch
 * only when the whole range fits; 3/4/8 replace, capped at 64; 1 drops with flag
 * 0x80. Unknown nonzero actions retain the clamped copy. Changed length/data
 * publishes scratch, length and 0x80; equal data leaves original outputs.
 * Zero-length replacement of zero-length input skips comparison/publication.
 */
unsigned int report_apply_rewrite(unsigned int traffic_class,unsigned int endpoint,
    unsigned int direction,unsigned char *report,unsigned int length,unsigned char *scratch,
    unsigned char **report_out,unsigned short *length_out,unsigned char *flags_out)
{
    unsigned char *volatile *output = report_out;
    volatile unsigned short *output_length = length_out;
    volatile unsigned char *output_flags = flags_out;
    *output = report;
    *output_length = length;
    *output_flags = 0;
    unsigned int rule_count = REWRITE_COUNT;
    unsigned int endpoint_number = endpoint & 15U;
    unsigned int run_catch,refresh_count;
    RtosQueue *mutex;
    if (rule_count == 0) {
        if (PACKET_TRIGGER_COUNT == 0)
            return 0;
        mutex = REWRITE_MUTEX;
        if (mutex != NULL) {
            xQueueSemaphoreTake(mutex,0xffffffffU);
            run_catch = PACKET_TRIGGER_COUNT != 0;
        } else {
            run_catch = 1;
        }
        refresh_count = 1;
    } else {
        mutex = REWRITE_MUTEX;
        if (mutex != NULL) {
            xQueueSemaphoreTake(mutex,0xffffffffU);
            run_catch = PACKET_TRIGGER_COUNT != 0;
            refresh_count = 1;
        } else {
            run_catch = PACKET_TRIGGER_COUNT != 0;
            refresh_count = run_catch;
        }
    }
    unsigned int result = 0;
    if (run_catch != 0 && clip_packet_rules_evaluate(
            traffic_class,endpoint_number,direction,report,length) != 0) {
        result = 1;
        goto release;
    }
    if (refresh_count != 0)
        rule_count = REWRITE_COUNT;
    if (rule_count == 0)
        goto release;
    int best_score = -1;
    unsigned int selected_index = 0xffffffffU;
    for (unsigned int index = 0; index < rule_count; ++index) {
        const volatile RewriteRule *rule = &REWRITE_RULES[index];
        unsigned int rule_class = rule->traffic_class;
        unsigned int rule_endpoint = rule->endpoint;
        unsigned int rule_direction = rule->direction;
        unsigned int prefix_length = rule->prefix_length;
        int base;
        if (rule_endpoint == endpoint_number && traffic_class == rule_class)
            base = 2;
        else if (rule_endpoint == 0xffffU && traffic_class == rule_class)
            base = 1;
        else if (rule_class == 255)
            base = 0;
        else
            continue;
        unsigned int specific_direction = rule_direction != 0;
        if (direction != rule_direction && specific_direction != 0)
            continue;
        unsigned int mask_bits = 0;
        if (prefix_length != 0) {
            if (length < prefix_length || report == NULL)
                continue;
            /* Retain native offsets even when the prefix length exceeds16. */
            const volatile unsigned char *rule_bytes = (const volatile void *)rule;
            for (unsigned int byte = 0; byte < prefix_length; ++byte) {
                unsigned int mask = rule_bytes[21U+byte];
                unsigned int input = ((const volatile unsigned char *)report)[byte];
                unsigned int prefix = rule_bytes[5U+byte];
                if (prefix != (input & mask))
                    goto next_rule;
            }
            for (unsigned int byte = 0; byte < prefix_length; ++byte)
                mask_bits += __popcountsi2(rule_bytes[21U+byte]);
        }
        int score = base * 100000 + mask_bits * 10U + specific_direction;
        if (score > best_score) {
            best_score = score;
            selected_index = index;
        }
next_rule:
        ;
    }
    if (selected_index == 0xffffffffU)
        goto release;
    volatile RewriteRule *chosen = &REWRITE_RULES[selected_index];
    unsigned int hits = chosen->hits;
    if (hits != 0xffffffffU)
        chosen->hits = hits + 1U;
    if (chosen->action == 0)
        goto release;
    unsigned int rewritten_length = length < 64 ? length : 64;
    memcpy(scratch,report,rewritten_length);
    chosen = &REWRITE_RULES[(unsigned short)selected_index];
    unsigned int payload_offset = chosen->payload_offset;
    unsigned int action = chosen->action;
    unsigned int payload_length = chosen->payload_length;
    const unsigned char *payload = REWRITE_PAYLOAD_POOL + payload_offset;
    if (action == 1) {
        *output_flags = 0x80;
        result = 1;
        goto release;
    }
    if (action == 2 || action == 7) {
        unsigned int patch_offset = chosen->patch_offset;
        if (patch_offset + payload_length <= rewritten_length)
            memcpy(scratch + patch_offset,payload,payload_length);
    } else if (action == 3 || action == 4 || action == 8) {
        if (payload_length == 0) {
            rewritten_length = 0;
            if (length == 0)
                goto release;
            goto publish;
        }
        rewritten_length = payload_length < 64 ? payload_length : 64;
        memcpy(scratch,payload,rewritten_length);
    }
    if (length == rewritten_length && memcmp(scratch,report,rewritten_length) == 0)
        goto release;
publish:
    *output = scratch;
    *output_length = rewritten_length;
    *output_flags = 0x80;
release:
    mutex = REWRITE_MUTEX;
    if (mutex != NULL)
        xQueueGenericSend(mutex,NULL,0,0);
    return result;
}
