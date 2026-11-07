/* Medius v3.4.7 device — app/rewrite.c.
 * Recovered C and native assembly, grouped for source navigation.
 * Original entry addresses, firmware-byte hashes and function comments follow.
 */

#include "../include/types.h"

/* Rewrite reconstruction utilities: repeated inline slot removal,
 * not another native entry. Move later records in increasing order, publish
 * count BYTE before clearing its tail slot, then call the native compactor.
 */
static __attribute__((always_inline)) inline void rewrite_remove_rule(
    unsigned int selected,unsigned int count)
{
    volatile RewriteRuleStore *store = REWRITE_STORE;
    for (unsigned int next = selected + 1U; next < count; ++next)
        memcpy((void *)(REWRITE_RULES + next - 1U),(const void *)(REWRITE_RULES + next),48U);
    unsigned char remaining = (unsigned char)(count - 1U);
    store->count = remaining;
    memset((void *)(REWRITE_RULES + remaining),0,48U);
    rewrite_compact_payload();
}

/* Native entry: 0x42028474. */
/* Original function-byte SHA-256:
 * 63225571d4684b955f59a297281ea30a33650b1eae8e0fbd09cac80383632906. */
/* Snapshot shared rewrite/report mutex once. Non-NULL gives that exact
 * handle via queue-send(NULL,wait0,back), ignoring the result. NULL is a no-op.
 * No ownership validation, lock lifecycle change, retry or return result. */
void rewrite_unlock(void)
{
    RtosQueue *mutex = REWRITE_MUTEX;
    if (mutex != NULL)
        xQueueGenericSend(mutex,NULL,0,0);
}

/* Native entry: 0x4202848c. */
/* Original function-byte SHA-256:
 * 551933ff41a8f7bd3ca652d8693fff9667af559176c5718241b932c56a41434a. */
/* Snapshot shared rewrite/report mutex once. Non-NULL takes that exact
 * handle with infinite tick wait; ignore the result. NULL is a no-op. No
 * recursive-owner check, allocation, bounded wait or success return. */
void rewrite_lock(void)
{
    RtosQueue *mutex = REWRITE_MUTEX;
    if (mutex != NULL)
        xQueueSemaphoreTake(mutex,0xffffffffU);
}

/* Native entry: 0x42029b3c. */
/* Original function-byte SHA-256:
 * 2a1bd8351cabbdd37ec58b6f046c10430e9eb3d751b9233740a4feec73990af0. */
/*
 * Compact replacement bytes in rule order through a2048-byte stack scratch
 * buffer (native frame0x820), then publish used HALFWORD. No lock or bounds
 * check: admission must have kept live offsets/lengths and total within pool.
 * Empty rules get offset0. Nonempty rules copy the initially sampled length,
 * then RELOAD length before storing their new offset and adding that fresh
 * length to used modulo65536. After every record, increment the BYTE index,
 * reload live count and advance the full48-byte cursor; count is not cached
 * for the whole walk. Copy scratch back only when final used is nonzero.
 * No byte clearing, generation increment or full-flag change is supplied.
 */
void rewrite_compact_payload(void)
{
    volatile RewriteRuleStore *store = REWRITE_STORE;
    unsigned char scratch[2048];
    unsigned short used = 0;
    unsigned int count = store->count;
    if (count != 0) {
        volatile RewriteRule *rule = REWRITE_RULES;
        unsigned char index = 0;
        do {
            unsigned int length = rule->payload_length;
            if (length == 0) {
                rule->payload_offset = 0;
            } else {
                unsigned int offset = rule->payload_offset;
                memcpy(scratch + used,(const void *)(REWRITE_PAYLOAD_POOL + offset),length);
                unsigned int current_length = rule->payload_length;
                rule->payload_offset = used;
                used = (unsigned short)(used + current_length);
            }
            index = (unsigned char)(index + 1U);
            count = store->count;
            ++rule;
        } while (index < count);
        if (used != 0)
            memcpy((void *)store->payload,scratch,used);
    }
    store->payload_used = used;
}

/* Native entry: 0x42029e20. */
/* Original function-byte SHA-256:
 * 29d08ed8416083a15348ce96c06bdafbbe1389188bd8c9ff54012c3048e1f72b. */
/*
 * Maintain rewrite rules without taking a lock; caller serializes this store.
 * Class, endpoint, direction, enabled and action retain their FULL native
 * WORD inputs. Offset/length are16-bit and prefix_length8-bit. A disabled
 * class0xff/endpoint0xffff clears the whole0xe08-byte store when count!=0,
 * preserving old_generation+1 modulo256 afterward; full becomes0 even when
 * already empty. This sentinel ignores direction/prefix/action validation.
 *
 * Other keys require low8(class-4)<=5 or full class==0xff, direction<=2 and
 * prefix_length<=16. Full class/endpoint/direction compare against stored
 * BYTE/HALFWORD/BYTE fields; no new argument normalization is added. Match
 * prefix then mask with memcmp, skipping both for length0. Prefix bytes are
 * NOT checked against masks. Disabled existing keys compact later48-byte
 * records, publish decremented count BYTE, zero tail, compact payload, then
 * freshly read/increment generation BYTE and clear full. Missing removal
 * leaves all state unchanged. Action/payload checks apply only to upserts.
 *
 * Action1 rejects classes8/0xff; action2 requires offset+length<=64, or2056
 * for class8; action3 bounds length by that same limit. Larger action WORDs
 * require low8(action-4)<=4 and full class8. Full action7 bounds offset+length
 * by2056; low8 actions4/8 bound length by2056; actions5/6 add no such bound.
 * Values with high action/class bits retain the native low-byte validation
 * and later truncating stores. Pool checks separately enforce2048 total.
 *
 * A new key needs used+length<=2048 and cached count<32. An existing key
 * loads action then old length; unchanged action/offset/length/payload is a
 * no-op. Otherwise require unsigned32(used+new_length-old_length)<=2048,
 * remove/compact the old slot, and append at a FRESH count without rechecking
 * capacity. Replacement resets hits and moves the rule to the end, changing
 * stable tie order. Capacity rejection sets sticky full1; other invalid/no-op
 * requests retain it. Successful mutation clears it.
 *
 * Zero the new48-byte slot; write endpoint HALFWORD, combined class/direction
 * HALFWORD, action BYTE, prefix-length BYTE, offset HALFWORD, then prefix/mask
 * copies. Read used once and store length/used as ONE packed WORD. Nonempty
 * payload copies into that offset, then adds length to a FRESH used HALFWORD.
 * Finally read generation BYTE BEFORE count BYTE, increment each modulo256
 * and publish ONE count/generation HALFWORD. Empty payload retains the current
 * used offset until compaction. No NULL/overlap/pool repair, timer or fence.
 */
void rewrite_update_rule(unsigned int traffic_class,unsigned int endpoint,
    unsigned int direction,int enabled,unsigned int action,unsigned short patch_offset,
    unsigned char prefix_length,const unsigned char *prefix,const unsigned char *mask,
    const unsigned char *payload,unsigned short payload_length)
{
    volatile RewriteRuleStore *store = REWRITE_STORE;
    if (enabled == 0 && traffic_class == 0xffU && endpoint == 0xffffU) {
        if (store->count != 0) {
            unsigned int generation = store->generation;
            memset((void *)store,0,sizeof(*store));
            store->generation = (unsigned char)(generation + 1U);
        }
        store->full = 0;
        return;
    }
    if ((unsigned char)(traffic_class - 4U) > 5U && traffic_class != 0xffU)
        return;
    if (direction > 2U || prefix_length > 16U)
        return;
    unsigned int count = store->count;
    unsigned int selected = 0xffffffffU;
    for (unsigned int index = 0; index < count; ++index) {
        volatile RewriteRule *rule = REWRITE_RULES + index;
        if (rule->traffic_class != traffic_class || rule->endpoint != endpoint ||
            rule->direction != direction || rule->prefix_length != prefix_length)
            continue;
        if (prefix_length != 0) {
            if (memcmp((const void *)rule->prefix,prefix,prefix_length) != 0)
                continue;
            if (memcmp((const void *)rule->mask,mask,prefix_length) != 0)
                continue;
        }
        selected = index;
        break;
    }
    if (enabled == 0) {
        if (selected != 0xffffffffU) {
            rewrite_remove_rule(selected,count);
            unsigned int generation = store->generation;
            store->generation = (unsigned char)(generation + 1U);
            store->full = 0;
        }
        return;
    }
    if (action < 4U) {
        unsigned int maximum = traffic_class == 8U ? 2056U : 64U;
        if (action == 1U) {
            if (traffic_class == 8U || traffic_class == 0xffU)
                return;
        } else if (action == 2U) {
            if ((unsigned int)patch_offset + payload_length > maximum)
                return;
        } else if (action == 3U && payload_length > maximum) {
            return;
        }
    } else {
        unsigned int low_action = (unsigned char)(action - 4U);
        if (low_action > 4U || traffic_class != 8U)
            return;
        if (action == 7U) {
            if ((unsigned int)patch_offset + payload_length > 2056U)
                return;
        } else if ((low_action & 0xfbU) == 0 && payload_length > 2056U) {
            return;
        }
    }
    if (selected == 0xffffffffU) {
        unsigned int used = store->payload_used;
        if (used + payload_length > 2048U || count >= 32U) {
            store->full = 1;
            return;
        }
    } else {
        volatile RewriteRule *old = REWRITE_RULES + selected;
        unsigned int previous_action = old->action;
        unsigned int previous_length = old->payload_length;
        if (previous_action == action && old->patch_offset == patch_offset &&
            previous_length == payload_length) {
            if (payload_length == 0)
                return;
            unsigned int offset = old->payload_offset;
            if (memcmp((const void *)(REWRITE_PAYLOAD_POOL + offset),payload,payload_length) == 0)
                return;
        }
        unsigned int used = store->payload_used;
        if (used + payload_length - previous_length > 2048U) {
            store->full = 1;
            return;
        }
        rewrite_remove_rule(selected,count);
        count = store->count;
    }
    volatile RewriteRule *rule = REWRITE_RULES + count;
    memset((void *)rule,0,sizeof(*rule));
    rule->endpoint = (unsigned short)endpoint;
    rule->class_direction = (unsigned short)(traffic_class | (direction << 8));
    rule->action = (unsigned char)action;
    rule->prefix_length = prefix_length;
    rule->patch_offset = patch_offset;
    if (prefix_length != 0) {
        memcpy((void *)rule->prefix,prefix,prefix_length);
        memcpy((void *)rule->mask,mask,prefix_length);
    }
    unsigned int offset = store->payload_used;
    rule->payload_extent = payload_length | (offset << 16);
    if (payload_length != 0) {
        memcpy((void *)(REWRITE_PAYLOAD_POOL + offset),payload,payload_length);
        unsigned int current_used = store->payload_used;
        store->payload_used = (unsigned short)(current_used + payload_length);
    }
    unsigned int generation = store->generation;
    unsigned int current_count = store->count;
    unsigned int next_generation = (unsigned char)(generation + 1U);
    unsigned int next_count = (unsigned char)(current_count + 1U);
    store->count_generation = (unsigned short)(next_count | (next_generation << 8));
    store->full = 0;
}

/* Native entry: 0x42037db8. */
/* Original function-byte SHA-256:
 * ee384bf16dade1ac6bf1db81ed6d0cd0aa28aab010a8bffc5e22408c9c6ca34f. */
/*
 * REWRITE command boundary: narrow class/direction/present/action/prefix count
 * to8 bits and ID/offset/replacement length to16. Take the optional rewrite
 * mutex with an infinite tick wait, ignoring status. Read the permission BYTE
 * once; any nonzero value admits the call. With permission0, only the normalized
 * class0xff/ID0xffff/present0 all-clear sentinel reaches the updater. Its
 * direction and other fields are not checked here. Forward all11 arguments,
 * preserving borrowed pointer identities, then reload/give the optional mutex.
 * The updater owns key/action/pool checks; no result, retry or persistence.
 */
void rewrite_command(unsigned char traffic_class,unsigned short id,
    unsigned char direction,unsigned char present,unsigned char action,unsigned short offset,
    unsigned char match_length,const unsigned char *match_bytes,const unsigned char *mask_bytes,
    const unsigned char *replacement,unsigned short replacement_length)
{
    RtosQueue *mutex = REWRITE_MUTEX;
    if (mutex != NULL)
        (void)xQueueSemaphoreTake(mutex,0xffffffffU);
    unsigned int allow = REWRITE_ALLOWED;
    if (allow != 0 || (traffic_class == 0xffU && id == 0xffffU && present == 0))
        rewrite_update_rule(traffic_class,id,direction,present,action,offset,
            match_length,match_bytes,mask_bytes,replacement,replacement_length);
    mutex = REWRITE_MUTEX;
    if (mutex != NULL)
        (void)xQueueGenericSend(mutex,NULL,0,0);
}

/* Native entry: 0x42037e4c. */
/* Original function-byte SHA-256:
 * 0a2dbbe21bd8be72bce4ae147c8756bb6d56e624fea225f0643571c217f3dd2b. */
/*
 * Serialize selector0x0c/full/generation/count plus12 bytes per emitted rule.
 * Caller provides writable output separate from state, normally>=388 bytes.
 * No capacity argument. Take optional mutex with an infinite tick wait,
 * ignoring status.
 * Initially NULL path reads generation then full and writes selector/full/
 * generation/count0 without reloading the mutex. Non-NULL path reads generation
 * then full after take, writes generation/full/selector/count0 in native order,
 * reads rule count, then caches a FRESH mutex pointer for eventual give.
 *
 * For a nonempty table, increment BYTE walk index before the per-rule test.
 * Cached emitted count initially0; after each continuing iteration reload
 * output[3]. Emit only when that cached value<32. Read hits WORD, ID HALFWORD,
 * direction BYTE, class BYTE, action BYTE, offset HALFWORD, prefix BYTE and
 * payload length HALFWORD before writing the record. ID and offset write HIGH
 * BYTE before LOW; payload length and saturated16-bit hits write LOW then HIGH.
 * Increment freshly read output[3] after the record; offset wraps16 on+12.
 * Advance the full48-byte rule cursor and reload live count each iteration,
 * including skipped records; stop when BYTE walked>=live count. Output is
 * not prezeroed or copied atomically. Return used length,4 for empty table.
 * Give cached mutex, not a final reload; no allocation, fence or generation
 * consistency check. The388-byte bound assumes exclusive caller output.
 */
unsigned int rewrite_summary_encode(unsigned char *output)
{
    volatile unsigned char *out = output;
    volatile RewriteRuleStore *store = REWRITE_STORE;
    RtosQueue *mutex = REWRITE_MUTEX;
    unsigned int count;
    if (mutex == NULL) {
        unsigned int generation = store->generation;
        unsigned int full = store->full;
        out[0] = 0x0c;
        out[1] = full;
        out[2] = generation;
        out[3] = 0;
        count = store->count;
    } else {
        (void)xQueueSemaphoreTake(mutex,0xffffffffU);
        unsigned int generation = store->generation;
        unsigned int full = store->full;
        out[2] = generation;
        out[1] = full;
        out[0] = 0x0c;
        out[3] = 0;
        count = store->count;
        mutex = REWRITE_MUTEX;
    }
    unsigned int used = 4;
    if (count != 0) {
        volatile RewriteRule *rule = REWRITE_RULES;
        unsigned char walked = 0;
        unsigned int emitted = 0;
        for (;;) {
            walked = (unsigned char)(walked + 1U);
            if (emitted < 32U) {
                unsigned int hits = rule->hits;
                unsigned int id = rule->endpoint;
                unsigned int direction = rule->direction;
                unsigned int traffic_class = rule->traffic_class;
                unsigned int action = rule->action;
                unsigned int offset = rule->patch_offset;
                unsigned int prefix_length = rule->prefix_length;
                unsigned int payload_length = rule->payload_length;
                out[used] = traffic_class;
                out[used + 2U] = id >> 8;
                out[used + 1U] = id;
                out[used + 3U] = direction;
                out[used + 4U] = action;
                out[used + 5U] = prefix_length;
                out[used + 7U] = offset >> 8;
                out[used + 6U] = offset;
                unsigned int reported_hits = hits < 65535U ? hits : 65535U;
                out[used + 8U] = payload_length;
                out[used + 9U] = payload_length >> 8;
                out[used + 10U] = reported_hits;
                out[used + 11U] = reported_hits >> 8;
                used = (unsigned short)(used + 12U);
                out[3] = (unsigned char)(out[3] + 1U);
            }
            ++rule;
            count = store->count;
            if (walked >= count)
                break;
            emitted = out[3];
        }
    }
    if (mutex != NULL)
        (void)xQueueGenericSend(mutex,NULL,0,0);
    return used;
}

/* Native entry: 0x42037f68. */
/* Original function-byte SHA-256:
 * cdece571a0fb13f1a5e07583512beb24d5a2010bab26b524a0190df0dda200f7. */
/*
 * Serialize selector0x0d and one BYTE-indexed rule. Take optional mutex with
 * an infinite tick wait, ignoring status. Index>=live count returns0 without output writes;
 * this path still reloads/gives the mutex, even when initially NULL.
 * Cache ID, payload offset, patch offset, class, direction, action, prefix
 * length and payload length in that native order. Write ID LOW at output3
 * BEFORE selector/index/class, then ID HIGH/direction/present1/action/offset
 * LOW/HIGH/prefix length. Header is11 bytes; copy prefix then mask only when
 * nonempty, then replacement only when nonempty using cached offset/length.
 * Return11+2*prefix_length+payload_length, narrowed16 ONLY after a nonempty
 * payload copy. Updater-admitted state may need2091 writable bytes; no local
 * capacity, corruption or borrowed-pool-lifetime check. Output must be separate
 * from store. No payload length field is added to this wire response.
 */
unsigned int rewrite_rule_encode(unsigned char *output,unsigned char index)
{
    RtosQueue *mutex = REWRITE_MUTEX;
    if (mutex != NULL)
        (void)xQueueSemaphoreTake(mutex,0xffffffffU);
    volatile RewriteRuleStore *store = REWRITE_STORE;
    unsigned int used = 0;
    if (index < store->count) {
        volatile RewriteRule *rule = REWRITE_RULES + index;
        unsigned int id = rule->endpoint;
        unsigned int payload_offset = rule->payload_offset;
        unsigned int patch_offset = rule->patch_offset;
        unsigned int traffic_class = rule->traffic_class;
        unsigned int direction = rule->direction;
        unsigned int action = rule->action;
        unsigned int prefix_length = rule->prefix_length;
        unsigned int payload_length = rule->payload_length;
        volatile unsigned char *out = output;
        out[3] = id;
        out[0] = 0x0d;
        out[1] = index;
        out[2] = traffic_class;
        out[4] = id >> 8;
        out[5] = direction;
        out[6] = 1;
        out[7] = action;
        out[8] = patch_offset;
        out[9] = patch_offset >> 8;
        out[10] = prefix_length;
        used = 11;
        if (prefix_length != 0) {
            memcpy(output + used,(const void *)rule->prefix,prefix_length);
            used += prefix_length;
            memcpy(output + used,(const void *)rule->mask,prefix_length);
            used += prefix_length;
        }
        if (payload_length != 0) {
            memcpy(output + used,(const void *)(REWRITE_PAYLOAD_POOL + payload_offset),payload_length);
            used = (unsigned short)(used + payload_length);
        }
    }
    mutex = REWRITE_MUTEX;
    if (mutex != NULL)
        (void)xQueueGenericSend(mutex,NULL,0,0);
    return used;
}
