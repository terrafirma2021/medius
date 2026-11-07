/* Device clip packet-trigger configuration. */
#include "../include/types.h"

/* Packet-trigger reconstruction utilities: repeated inline accounting loops,
 * not another native function. Callers clear accounting at their native points.
 * Read flags then match_length once per cached-count record; sum in16 bits and
 * RUN count in8 bits. Publish total once, followed by RUN count only if seen.
 */
static __attribute__((always_inline)) inline void clip_packet_recount(unsigned int count)
{
    volatile ClipPacketTriggerTable *table = CLIP_PACKET_TRIGGER_TABLE;
    unsigned short match_bytes = 0;
    unsigned char run_count = 0;
    unsigned int saw_run = 0;
    for (unsigned int index = 0; index < count; ++index) {
        unsigned int flags = table->records[index].flags;
        if ((flags & 4U) != 0) {
            run_count = (unsigned char)(run_count + 1U);
            saw_run = 1;
        }
        match_bytes = (unsigned short)(match_bytes + table->records[index].match_length);
    }
    table->total_match_length = match_bytes;
    if (saw_run != 0)
        table->run_edge_count = run_count;
}

/* Native entry: 0x42036a9c. */
/* Original function-byte SHA-256:
 * 06c72c76e2dfd8f2c42be42da8df8ea7283f2bdc8f38b5146a61159b08588d5a. */
/*
 * Add/replace or remove the first exact class/ID/direction/length/match/mask
 * rule. Byte parameters narrow to8 bits and ID to16; two borrowed arrays must
 * provide match_length readable bytes when nonzero; the arrays must not alias
 * editable rule storage. No NULL check. Take the optional rewrite mutex for
 * UINT32_MAX ticks before validation, ignoring status, and always sample the
 * rewrite permission byte. Classes outside 4..9 with initially NULL mutex
 * returns without reloading it; other exits give a freshly sampled mutex.
 *
 * Shared validation requires direction0..2, length<=16, classes4/9 not
 * direction2, class5 not direction1, and every match byte contained by its
 * corresponding mask. Search the cached count using class BYTE, ID HALFWORD,
 * direction BYTE, length BYTE, then match/mask memcmp; skip both comparisons
 * for length0. Removal (flags bit0 clear) bypasses action/other flag/selector
 * validation, compacts later48-byte records with memcpy, publishes count-1,
 * zeroes the tail, then clears RUN count, reads fresh count, clears total and
 * rebuilds accounting over that fresh count. Absent removals are ignored.
 *
 * Upsert requires action<=5 and flags<=7. Consume(bit1) requires class!=8 and
 * sampled permission EXACTLY1. RUN(bit2) requires class!=8, nonwildcard ID,
 * nonzero direction, selector_length<match_length and at least one nonzero
 * mask byte AFTER the selector prefix; all suffix bytes are read. Non-RUN
 * requires selector_length0. Store flags bits1/2 only. New rules require cached
 * count<8 and stored total+length<=112; zero the slot, publish direction BYTE,
 * class BYTE, ID HALFWORD, packed action/flags HALFWORD, selector BYTE and
 * length BYTE, then copy match followed by mask. Reload count after copying,
 * clear RUN count, publish incremented byte count, clear total and recount
 * old_count+1 slots unless the increment wraps to0.
 *
 * Existing rules with unchanged action/flags/selector do nothing. Otherwise
 * store those three BYTEs, clear hit WORD, clear RUN count, clear previous
 * match BYTE, clear total and recount the ORIGINAL cached count. Each recount
 * accumulates locally and publishes total HALFWORD once before nonzero RUN
 * count BYTE. Padding is retained on edits; no new fence, notification or
 * defensive repair of corrupt counts/accounting is supplied. Returns no status.
 *
 * traffic_class, direction, action, flags, selector_length and match_length
 * are unsigned byte arguments; id is an unsigned halfword. flags bit 0 selects
 * upsert; bits 1/2 select consume/RUN and are the only bits stored. Match/mask
 * pointers are borrowed for this call; zero-length rules do not read them.
 */
void clip_packet_trigger_update(unsigned char traffic_class,unsigned short id,
    unsigned char direction,unsigned char action,unsigned char flags,
    unsigned char selector_length,unsigned char match_length,
    const unsigned char *match_bytes,const unsigned char *mask_bytes)
{
    RtosQueue *mutex = REWRITE_MUTEX;
    unsigned int had_mutex = mutex != NULL;
    if (mutex != NULL)
        (void)xQueueSemaphoreTake(mutex,0xffffffffU);
    unsigned int rewrite_allowed = REWRITE_ALLOWED;
    if ((unsigned char)(traffic_class - 4U) > 5U) {
        if (had_mutex == 0)
            return;
        goto unlock;
    }
    if (direction > 2U || match_length > 16U)
        goto unlock;
    if (direction == 2) {
        if (traffic_class == 4 || traffic_class == 9)
            goto unlock;
    } else if (traffic_class == 5 && direction == 1) {
        goto unlock;
    }
    for (unsigned int index = 0; index < match_length; ++index) {
        unsigned int mask = ((const volatile unsigned char *)mask_bytes)[index];
        unsigned int match = ((const volatile unsigned char *)match_bytes)[index];
        if ((match & ~mask) != 0)
            goto unlock;
    }
    volatile ClipPacketTriggerTable *table = CLIP_PACKET_TRIGGER_TABLE;
    unsigned int count = table->count;
    unsigned int selected = 0xffffffffU;
    for (unsigned int index = 0; index < count; ++index) {
        volatile ClipPacketTrigger *rule = table->records + index;
        if (rule->traffic_class != traffic_class || rule->id != id ||
            rule->direction != direction || rule->match_length != match_length)
            continue;
        if (match_length != 0) {
            if (memcmp((const void *)rule->match,match_bytes,match_length) != 0)
                continue;
            if (memcmp((const void *)rule->mask,mask_bytes,match_length) != 0)
                continue;
        }
        selected = index;
        break;
    }
    if ((flags & 1U) == 0) {
        if (selected == 0xffffffffU)
            goto unlock;
        for (unsigned int next = selected + 1U; next < count; ++next)
            memcpy((void *)(table->records + next - 1U),
                (const void *)(table->records + next),48U);
        unsigned char remaining = (unsigned char)(count - 1U);
        table->count = remaining;
        memset((void *)(table->records + remaining),0,48U);
        table->run_edge_count = 0;
        unsigned int current_count = table->count;
        table->total_match_length = 0;
        if (current_count != 0)
            clip_packet_recount(current_count);
        goto unlock;
    }
    if (action > 5U || flags > 7U)
        goto unlock;
    if ((flags & 2U) != 0 && (traffic_class == 8 || rewrite_allowed != 1))
        goto unlock;
    if ((flags & 4U) != 0) {
        if (traffic_class == 8 || id == 0xffffU || direction == 0 ||
            selector_length >= match_length)
            goto unlock;
        unsigned int suffix_mask = 0;
        for (unsigned int index = selector_length; index < match_length; ++index)
            suffix_mask |= ((const volatile unsigned char *)mask_bytes)[index];
        if (suffix_mask == 0)
            goto unlock;
    } else if (selector_length != 0) {
        goto unlock;
    }
    unsigned int stored_flags = flags & 6U;
    if (selected == 0xffffffffU) {
        if (count >= 8U)
            goto unlock;
        if (table->total_match_length + (unsigned int)match_length > 112U)
            goto unlock;
        volatile ClipPacketTrigger *rule = table->records + count;
        memset((void *)rule,0,48U);
        rule->direction = direction;
        rule->traffic_class = traffic_class;
        rule->id = id;
        rule->action_flags = (unsigned short)(action | (stored_flags << 8));
        rule->selector_length = selector_length;
        rule->match_length = match_length;
        if (match_length != 0) {
            memcpy((void *)rule->match,match_bytes,match_length);
            memcpy((void *)rule->mask,mask_bytes,match_length);
        }
        unsigned int previous_count = table->count;
        table->run_edge_count = 0;
        unsigned char published_count = (unsigned char)(previous_count + 1U);
        table->count = published_count;
        table->total_match_length = 0;
        if (published_count != 0)
            clip_packet_recount(previous_count + 1U);
    } else {
        volatile ClipPacketTrigger *rule = table->records + selected;
        if (rule->action == action && rule->flags == stored_flags &&
            rule->selector_length == selector_length)
            goto unlock;
        rule->action = action;
        rule->flags = stored_flags;
        rule->selector_length = selector_length;
        rule->hits = 0;
        table->run_edge_count = 0;
        rule->previous_match = 0;
        table->total_match_length = 0;
        if (count != 0)
            clip_packet_recount(count);
    }
unlock:
    mutex = REWRITE_MUTEX;
    if (mutex != NULL)
        (void)xQueueGenericSend(mutex,NULL,0,0);
}
