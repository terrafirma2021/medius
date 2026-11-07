/* Device clip packet-rule selection and RUN edge matching. */
#include "../include/types.h"

/* Packet matching reconstruction utilities: inline native byte walks,
 * not additional native entries. Caller checks payload and length. Read mask,
 * payload, then expected BYTE for every visited position; stop on mismatch.
 */
static __attribute__((always_inline)) inline unsigned int clip_rule_bytes_match(
    const volatile ClipPacketTrigger *rule,const unsigned char *payload,
    unsigned int count)
{
    for (unsigned int index = 0; index < count; ++index) {
        unsigned int mask = rule->mask[index];
        unsigned int actual = ((const volatile unsigned char *)payload)[index];
        unsigned int expected = rule->match[index];
        if ((actual & mask) != expected)
            return 0;
    }
    return 1;
}

/* Native entry: 0x4039319c. */
/* Original function-byte SHA-256:
 * bf4e89a375b163b1d186f96bd7dc37e8162b505a045a429bd47ea72a366b5b29. */
/*
 * Evaluate packet-trigger rules and return the winning consume bit, else0.
 * Class/endpoint/direction/length remain full WORD inputs; payload is borrowed
 * and not written. Fence/read reset BYTE BEFORE caching rule count BYTE.
 * Pending reset fences/clears its BYTE once, then clears previous_match for
 * every cached-count slot, even if no rule subsequently matches. Empty count
 * returns0. No mutex or atomic snapshot is established by these fences.
 *
 * Read each rule's class BYTE, ID HALFWORD, direction BYTE and match length
 * BYTE before deciding eligibility. Score exact class+ID200000, same class
 * wildcard-ID100000, wildcard class0xff0 regardless of ID; require direction
 * equality unless either incoming or rule direction is0. A nonempty match
 * needs enough payload bytes and a non-NULL payload. Match the whole masked
 * prefix, then reread every mask byte for popcount: score adds10 per set mask
 * bit and1 for a nonzero rule direction. Strictly higher score replaces the
 * winner, so equal scores retain the earliest slot. Length/count are trusted
 * storage bytes, without new caps or repairs for corrupt state.
 *
 * Read RUN accounting BYTE, then cache the winner's previous_match BYTE before
 * refreshing any RUN states. When RUN accounting is nonzero, visit all cached
 * slots with flags bit2 and EXACT class/ID/direction. An unmatched/short/NULL
 * selector prefix leaves previous_match unchanged. After selector success,
 * test the full match again and publish previous_match BYTE1/0; insufficient
 * full data clears it. This pass runs even without a winner. A winner gets
 * one saturating hit WORD increment, then a fresh flags BYTE supplies consume
 * and RUN behavior. RUN with cached previous_match nonzero returns consume
 * immediately, without queue access or timer scheduling.
 *
 * Otherwise read action-count BYTE ONCE then winner action BYTE. A matching
 * last queued action is coalesced except action5; coalescing still requests
 * the catch timer. Count exactly8 shifts7 bytes down with memmove and appends
 * at7, retaining count8. Other counts increment modulo256, with no >=8 repair.
 * Publish count BEFORE action BYTE; the full-queue path uses memmove's returned
 * destination. If its handle exists, start the catch-action timer once with
 * 1 microsecond, ignoring status. No timer restart/cancel, worker notification,
 * delivery/timing guarantee or payload copy is supplied here.
 *
 * traffic_class, endpoint and direction are full-width packet keys; no entry
 * truncation or range check is applied. payload is borrowed read-only storage
 * of length bytes, and NULL is accepted only by zero-length matching paths.
 * length is an unsigned 32-bit availability, not a truncated wire length.
 * Returns 0 or 1 from the winning consume flag, including a suppressed RUN.
 */
unsigned char clip_packet_rules_evaluate(unsigned int traffic_class,unsigned int endpoint,
    unsigned int direction,const unsigned char *payload,unsigned int length)
{
    volatile ClipPacketTriggerTable *table = CLIP_PACKET_TRIGGER_TABLE;
    memw();
    unsigned int reset = CLIP_RULES_RESET_PENDING;
    unsigned int count = table->count;
    if (reset != 0) {
        memw();
        CLIP_RULES_RESET_PENDING = 0;
        for (unsigned int index = 0; index < count; ++index)
            table->records[index].previous_match = 0;
    }
    if (count == 0)
        return 0;
    int best_score = -1;
    unsigned int selected = 0xffffffffU;
    for (unsigned int index = 0; index < count; ++index) {
        volatile ClipPacketTrigger *rule = table->records + index;
        unsigned int rule_class = rule->traffic_class;
        unsigned int rule_id = rule->id;
        unsigned int rule_direction = rule->direction;
        unsigned int match_length = rule->match_length;
        int specificity;
        if (rule_id == endpoint && rule_class == traffic_class)
            specificity = 2;
        else if (rule_id == 0xffffU && rule_class == traffic_class)
            specificity = 1;
        else if (rule_class == 0xffU)
            specificity = 0;
        else
            continue;
        if (rule_direction != 0 && direction != rule_direction && direction != 0)
            continue;
        unsigned int mask_bits = 0;
        if (match_length != 0) {
            if (length < match_length || payload == NULL)
                continue;
            if (clip_rule_bytes_match(rule,payload,match_length) == 0)
                continue;
            for (unsigned int byte_index = 0; byte_index < match_length; ++byte_index)
                mask_bits += (unsigned int)__popcountsi2(rule->mask[byte_index]);
        }
        int score = specificity * 100000 + (int)(mask_bits * 10U) + (rule_direction != 0);
        if (score > best_score) {
            selected = index;
            best_score = score;
        }
    }
    unsigned int run_count = table->run_edge_count;
    unsigned int previous_match = 0;
    if (selected != 0xffffffffU)
        previous_match = table->records[selected].previous_match;
    if (run_count != 0) {
        for (unsigned int index = 0; index < count; ++index) {
            volatile ClipPacketTrigger *rule = table->records + index;
            if ((rule->flags & 4U) == 0 || rule->traffic_class != traffic_class ||
                rule->id != endpoint || rule->direction != direction)
                continue;
            unsigned int selector_length = rule->selector_length;
            if (selector_length != 0) {
                if (length < selector_length || payload == NULL)
                    continue;
                if (clip_rule_bytes_match(rule,payload,selector_length) == 0)
                    continue;
            }
            unsigned int match_length = rule->match_length;
            unsigned int matches = 1;
            if (match_length != 0) {
                if (length < match_length || payload == NULL)
                    matches = 0;
                else
                    matches = clip_rule_bytes_match(rule,payload,match_length);
            }
            rule->previous_match = matches;
        }
    }
    if (selected == 0xffffffffU)
        return 0;
    volatile ClipPacketTrigger *winner = table->records + selected;
    unsigned int hits = winner->hits;
    if (hits != 0xffffffffU)
        winner->hits = hits + 1U;
    unsigned int flags = winner->flags;
    unsigned char consume = (flags >> 1) & 1U;
    if ((flags & 4U) != 0 && previous_match != 0)
        return consume;
    unsigned int queued = PLAYBACK_ACTION_COUNT;
    unsigned char action = winner->action;
    volatile unsigned char *actions = PLAYBACK_ACTION_STORAGE;
    if (queued != 0 && actions[queued - 1U] == action && action != 5U)
        goto schedule;
    unsigned int index = queued;
    unsigned char new_count;
    if (queued == 0) {
        new_count = 1;
    } else if (queued == 8U) {
        actions = memmove((void *)actions,(const void *)(actions + 1U),7U);
        index = 7;
        new_count = 8;
    } else {
        new_count = (unsigned char)(queued + 1U);
    }
    PLAYBACK_ACTION_COUNT = new_count;
    actions[index] = action;
schedule:;
    EspTimer *timer = CLIP_ACTION_TIMER;
    if (timer != NULL)
        (void)esp_timer_start_once(timer,1ULL);
    return consume;
}
