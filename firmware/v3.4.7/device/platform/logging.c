/* Medius v3.4.7 device — platform/logging.c.
 * Recovered C and native assembly, grouped for source navigation.
 * Original entry addresses, firmware-byte hashes and function comments follow.
 */

#include "../include/types.h"

/* Native entry: 0x4038f414. */
/* Original function-byte SHA-256:
 * c8286c5ffd3bad8f6a00cae38add2602fe4782bfe8065422c60faa6d04839ed1. */
/*
 * Samples the shared mutex WORD and creates/stores a mutex when NULL, before
 * querying scheduler state. Scheduler state 1 returns without taking it;
 * every other state rereads the mutex and waits with UINT32_MAX ticks.
 * Constructor and take failures are ignored. No creation guard, allocation
 * retry in this call, ISR-specific API or MEMW; concurrent first callers can
 * create different mutexes. This routine returns no acquisition status.
 */
void esp_log_impl_lock(void)
{
    if (LOG_STATE->mutex == 0)
        LOG_STATE->mutex = log_create_mutex(1);
    if (xTaskGetSchedulerState() != 1)
        xQueueSemaphoreTake(LOG_STATE->mutex,0xffffffffU);
}

/* Native entry: 0x4038f438. */
/* Original function-byte SHA-256:
 * b8f01734688ff7bf6ba1c76e31555cf9e1fc916ff9fd4fc46e47a8cd8e41c015. */
/*
 * Lazily creates/stores a mutex before checking scheduler state, without
 * guarding concurrent creation or testing constructor failure. State 1
 * returns true without a take. Other states reread the shared mutex WORD,
 * call the task semaphore API with timeout 10 ticks and return result == 1.
 * Ten is a tick argument, not a measured timeout; no ISR-specific path/MEMW.
 */
bool esp_log_impl_lock_timeout(void)
{
    if (LOG_STATE->mutex == 0)
        LOG_STATE->mutex = log_create_mutex(1);
    if (xTaskGetSchedulerState() == 1) return true;
    return xQueueSemaphoreTake(LOG_STATE->mutex,10) == 1;
}

/* Native entry: 0x4038f468. */
/* Original function-byte SHA-256:
 * 6a92df0b08b160c6801fc7df757dade97b564007d8e0a39e9597d649cf7b587b. */
/*
 * Queries scheduler state first. State 1 does nothing; other states read
 * the current shared mutex and give it through queue-send(NULL,0,0).
 * Ignores the result and does not create or validate the handle, confirm
 * prior acquisition, choose an ISR API or protect later output callbacks.
 */
void esp_log_impl_unlock(void)
{
    if (xTaskGetSchedulerState() != 1)
        xQueueGenericSend(LOG_STATE->mutex,0,0,0);
}

/* Native entry: 0x4038f484. */
/* Original function-byte SHA-256:
 * 4a710a4d387689fac33ff3e15baf389662f8b1a1863b4ac9b08d52e27f6f8c67. */
/*
 * Scheduler state 1 returns CCOUNT sampled BEFORE the ROM CPU-frequency call,
 * divided by (CPU ticks/us * 1000 modulo 2^32). No zero-divisor protection.
 * Other states sample cached early-base WORD; only when zero and PRID bit13
 * clear recapture/store that same early-time calculation. A captured zero
 * remains the recapture sentinel. No cross-core initialization lock or MEMW.
 *
 * Selects ISR or task tick getter from xPortInIsrContext, then rereads the
 * early-base WORD and returns ticks+base modulo 2^32. This binary performs
 * no tick scaling. Does not measure UART/log delivery time or ensure
 * monotonicity across cycle wrap, clock changes, startup or concurrent calls.
 */
unsigned int esp_log_timestamp(void)
{
    if (xTaskGetSchedulerState() == 1) {
        unsigned int cycles = esp_cpu_get_cycle_count();
        unsigned int frequency = ets_get_cpu_frequency();
        return cycles / (frequency * 1000U);
    }
    if (LOG_STATE->early_base_ms == 0 &&
        (xtensa_read_prid() & 0x2000U) == 0) {
        unsigned int cycles = esp_cpu_get_cycle_count();
        unsigned int frequency = ets_get_cpu_frequency();
        LOG_STATE->early_base_ms = cycles / (frequency * 1000U);
    }
    unsigned int ticks;
    if (xPortInIsrContext() != 0) ticks = xTaskGetTickCountFromISR();
    else ticks = xTaskGetTickCount();
    return ticks + LOG_STATE->early_base_ms;
}

/* Native entry: 0x4038f4ec. */
/* Original function-byte SHA-256:
 * 07a9ddf821ff9a633be99800f9036fa1c46d292f1c6bea6e89693609c34ac49e. */
/*
 * True variadic logger entry. Builds the native Xtensa va_list and looks up
 * the tag threshold. Zero THRESHOLD or unsigned level > threshold suppresses
 * output; requested level zero still passes a positive threshold.
 * On admission reads the print callback WORD once and calls it with format
 * and the va_list, ignoring its result. Tag is a filter key, not an injected
 * printf argument. No NULL callback/format check or output-duration lock.
 * Stack/register varargs follow the compiler's 12-byte windowed Xtensa ABI;
 * no fixed six-argument decompiler signature is retained.
 */
void esp_log_write(unsigned int level,const char *tag,const char *format,...)
{
    va_list arguments;
    va_start(arguments,format);
    unsigned int threshold = esp_log_level_get_timeout(tag);
    if (threshold != 0 && level <= threshold) {
        LogVprintf print = LOG_OUTPUT->print;
        print(format,arguments);
    }
    va_end(arguments);
}

/* Native entry: 0x4038f534. */
/* Original function-byte SHA-256:
 * f97fd4703b20753550e7b759fe752ed77cd936e17a20a95b7c4ec9dd23680d00. */
/*
 * Samples default level WORD once before checking tag or acquiring a lock.
 * NULL tag returns that sample without locking. Other tags attempt the
 * ten-tick logger lock; failure returns zero without an unlock or lookup.
 * Success checks the pointer-key cache. A miss searches the string-key list,
 * leaving the sampled default if absent, then adds the resolved level to
 * cache. Always unlocks after successful acquisition and returns local level.
 * No tag copy, lifetime validation or guarantee of eventual output delivery.
 */
unsigned int esp_log_level_get_timeout(const char *tag)
{
    unsigned int level = LOG_OUTPUT->default_level;
    if (tag == 0) return level;
    if (!esp_log_impl_lock_timeout()) return 0;
    if (!esp_log_cache_get_level(tag,&level)) {
        esp_log_linked_list_get_level(tag,&level);
        esp_log_cache_add(tag,level);
    }
    esp_log_impl_unlock();
    return level;
}

/* Native entry: 0x420272f4. */
/* Original function-byte SHA-256:
 * e4e77a971bf18d1ec66df5a9520dfc90411865daca63770c34fe8916b5d2e0bf. */
/*
 * Calls the logger lock wrapper, reads the old callback WORD, stores the
 * supplied callback WORD and unlocks, then returns the old callback.
 * NULL is accepted and no acquisition status is available. Serializes this
 * replacement through the wrapper, not the duration of later log output;
 * readers load the callback without holding this mutex for the invocation.
 */
LogVprintf esp_log_set_vprintf(LogVprintf callback)
{
    esp_log_impl_lock();
    LogVprintf previous = LOG_OUTPUT->print;
    LOG_OUTPUT->print = callback;
    esp_log_impl_unlock();
    return previous;
}

/* Native entry: 0x42003d1c. */
/* Original function-byte SHA-256:
 * a191d2d4e04864973193c9977393d526323eafedd89ceabe25ce7c06c910819d. */
/*
 * Samples list head WORD once, then follows next WORDs until NULL or the
 * first strcmp(tag,node-name-at+5) match. On match reads level BYTE at+4,
 * stores its zero-extended value to caller's WORD and returns true.
 * A miss returns false without writing output. No default fallback, copies,
 * cycle detection, NULL-string/output validation or local synchronization.
 */
bool esp_log_linked_list_get_level(const char *tag,unsigned int *level)
{
    const volatile LogTagListNode *node = LOG_STATE->list;
    while (node != 0) {
        if (strcmp(tag,(const char *)node->tag) == 0) {
            *(volatile unsigned int *)level = node->level;
            return true;
        }
        node = node->next;
    }
    return false;
}

/* Native entry: 0x42003d48. */
/* Original function-byte SHA-256:
 * 9798906b431379b26a43ee493815d1a9b58485a5b3d28a38a6b43fd83f6e9131. */
/*
 * For signed index <= 14, samples left then right child generations (packed
 * WORD >> 3), choosing the lower child, with ties selecting RIGHT. Swaps
 * child tag/packed WORDs with parent tag/packed WORDs, then repeats from that
 * child. No parent-generation comparison stops a swap. Reads child tag,
 * child packed, parent tag, parent packed before the four stores in that
 * order. Does not read cache_count; assumes the full 31-entry heap.
 * Signed negative indices are not rejected; address/child arithmetic wraps.
 * No local lock, allocation, bounds checks or generation update.
 */
void esp_log_cache_heap_bubble_down(int index)
{
    while (index <= 14) {
        unsigned int left = (unsigned int)index * 2U + 1U;
        unsigned int right = left + 1U;
        volatile LogCacheEntry *left_entry =
            (volatile LogCacheEntry *)((unsigned int)LOG_STATE->entries + left * 8U);
        volatile LogCacheEntry *right_entry =
            (volatile LogCacheEntry *)((unsigned int)LOG_STATE->entries + right * 8U);
        unsigned int left_generation = left_entry->packed_level_generation >> 3;
        unsigned int right_generation = right_entry->packed_level_generation >> 3;
        unsigned int child_index = left_generation < right_generation ? left : right;
        volatile LogCacheEntry *child =
            (volatile LogCacheEntry *)((unsigned int)LOG_STATE->entries + child_index * 8U);
        volatile LogCacheEntry *parent =
            (volatile LogCacheEntry *)((unsigned int)LOG_STATE->entries + (unsigned int)index * 8U);
        const char *child_tag = child->tag;
        unsigned int child_packed = child->packed_level_generation;
        const char *parent_tag = parent->tag;
        unsigned int parent_packed = parent->packed_level_generation;
        parent->tag = child_tag;
        parent->packed_level_generation = child_packed;
        child->tag = parent_tag;
        child->packed_level_generation = parent_packed;
        index = (int)child_index;
    }
}

/* Native entry: 0x42003d9c. */
/* Original function-byte SHA-256:
 * 5c517926ea1cb0498c9327784c561d526645ff6127aefa20a82c682a0293a535. */
/*
 * Samples cache_count once and scans pointer-identical tag keys, not strings.
 * Before each index > 0, reads parent then child generation WORDs and calls
 * fatal __assert_func(NULL,0,NULL,NULL) unless parent < child. Count is not
 * bounded to 31. A miss increments the wrapping miss-counter WORD, returns
 * false and leaves output untouched.
 *
 * A hit stores packed low three bits to output WORD. Only cached count == 31
 * then rereads packed low bits, samples generation, publishes refreshed entry
 * before incremented generation, and bubbles that index down. If cached
 * increment equals 0x1fffffff, rebases exactly 31 entries in increasing order
 * preserving level, then stores generation 31. Returns true. No local lock,
 * tag copying, output/bounds validation or generation-overflow repair otherwise.
 */
bool esp_log_cache_get_level(const char *tag,unsigned int *level)
{
    unsigned int count = LOG_STATE->cache_count;
    for (unsigned int index = 0; index < count; ++index) {
        volatile LogCacheEntry *entry =
            (volatile LogCacheEntry *)((unsigned int)LOG_STATE->entries + index * 8U);
        if (index != 0) {
            const volatile LogCacheEntry *parent =
                (const volatile LogCacheEntry *)((unsigned int)LOG_STATE->entries +
                                                       ((index - 1U) >> 1) * 8U);
            unsigned int parent_generation = parent->packed_level_generation >> 3;
            unsigned int child_generation = entry->packed_level_generation >> 3;
            if (parent_generation >= child_generation) __assert_func(0,0,0,0);
        }
        if (entry->tag == tag) {
            *(volatile unsigned int *)level = entry->packed_level_generation & 7U;
            if (count == 31U) {
                unsigned int old_level = entry->packed_level_generation & 7U;
                unsigned int generation = LOG_STATE->cache_generation;
                unsigned int next_generation = generation + 1U;
                entry->packed_level_generation = old_level | (generation << 3);
                LOG_STATE->cache_generation = next_generation;
                esp_log_cache_heap_bubble_down((int)index);
                if (next_generation == 0x1fffffffU) {
                    for (unsigned int slot = 0; slot < 31U; ++slot) {
                        unsigned int packed = LOG_STATE->entries[slot].packed_level_generation;
                        LOG_STATE->entries[slot].packed_level_generation =
                            (packed & 7U) | (slot << 3);
                    }
                    LOG_STATE->cache_generation = 31;
                }
            }
            return true;
        }
    }
    unsigned int misses = LOG_STATE->cache_misses;
    LOG_STATE->cache_misses = misses + 1U;
    return false;
}

/* Native entry: 0x42003e54. */
/* Original function-byte SHA-256:
 * 94be4781ebeb3780124eeb5ed8770cc8e5497b2eec90227ff4875b5eeb356788. */
/*
 * Reads generation then count WORDs, stores generation+1 modulo 2^32, packs
 * old generation into high 29 bits and level's low three bits. Count <= 30
 * appends tag WORD then packed WORD, then stores count+1. Otherwise replaces
 * root tag then packed and bubbles index 0 down, without changing count.
 * Tag pointer is borrowed; duplicate/pointer validity is not checked.
 *
 * If cached next generation equals 0x1fffffff, rereads count and rebases that
 * many entries with a native do/while, then stores that cached count as the
 * generation. A corrupt zero count still enters the loop and underflows its
 * iteration counter; it is not converted to a safe no-op. No bounds clamp,
 * local lock, allocation or other overflow handling.
 */
void esp_log_cache_add(const char *tag,unsigned int level)
{
    unsigned int generation = LOG_STATE->cache_generation;
    unsigned int count = LOG_STATE->cache_count;
    unsigned int next_generation = generation + 1U;
    LOG_STATE->cache_generation = next_generation;
    unsigned int packed = (level & 7U) | (generation << 3);
    if (count <= 30U) {
        volatile LogCacheEntry *entry =
            (volatile LogCacheEntry *)((unsigned int)LOG_STATE->entries + count * 8U);
        entry->tag = tag;
        entry->packed_level_generation = packed;
        LOG_STATE->cache_count = count + 1U;
    } else {
        LOG_STATE->entries[0].tag = tag;
        LOG_STATE->entries[0].packed_level_generation = packed;
        esp_log_cache_heap_bubble_down(0);
    }
    if (next_generation == 0x1fffffffU) {
        unsigned int rebase_count = LOG_STATE->cache_count;
        unsigned int remaining = rebase_count;
        unsigned int index = 0;
        do {
            volatile LogCacheEntry *entry =
                (volatile LogCacheEntry *)((unsigned int)LOG_STATE->entries + index * 8U);
            unsigned int old_packed = entry->packed_level_generation;
            entry->packed_level_generation = (old_packed & 7U) | (index << 3);
            ++index;
        } while (--remaining != 0);
        LOG_STATE->cache_generation = rebase_count;
    }
}
