/* Device learned-profile registry and reconstruction utilities.
 * Inline parsing represents the repeated eight-instruction-loop operation;
 * it is not an additional native function entry. */
#include "../include/types.h"

static __inline__ __attribute__((always_inline)) int
profile_parse_identity(const char *key,unsigned int *identity)
{
    unsigned int value = 0;
    for (unsigned int digit = 0; digit < 8; ++digit) {
        unsigned int character = (unsigned char)key[digit + 1];
        unsigned int nibble = character - '0';
        if ((unsigned char)nibble > 9) {
            if ((unsigned char)(character - 'a') > 5)
                return 0;
            nibble = character - 'a' + 10U;
        }
        value = (value << 4) | nibble;
    }
    *identity = value;
    return 1;
}

/* Native entry: 0x42008b48. */
/* Original function-byte SHA-256:
 * 0358a30351f4e57a4573f17b7691d837a88fb3ea0a0e785c70f482ece042b6e5. */
/* Try to erase one least-stamped learned identity from read/write namespace
 * mbase. No ready gate or local application-mutex acquisition is supplied;
 * write callers invoke this while holding their optional storage mutex.
 * Iterate default partition nvs, any type. Accept only nonempty keys with
 * exactly eight LOWERCASE hex digits after b/m/p and NUL at key[9]. Native
 * loop parses all eight digits before checking that terminator/prefix mask.
 * Ignore namespace/type fields in returned metadata. Compare extracted16-bit
 * identities against FULL32 input identities when preserve_current ==1.
 * Also exclude the live protected pair and every saved-count pending stamp
 * pair; count is not clamped to8. These snapshots are unlocked/unfenced.
 * Read each candidate's u stamp into an initially zero WORD; ignore lookup
 * error. Select minimum unsigned stamp, retaining the first on ties. Duplicate
 * b/m/p entries are not deduplicated. Iterator errors terminate enumeration;
 * release iterator even after initial find failure (initialized NULL).
 * For a selected pair, clear matching stamp-cache valid BYTE BEFORE erasing.
 * Erase b,m,p,u in order, continuing after errors; x patches and g capture
 * flags are retained. Commit even after an erase error. Return1 only if all
 * erase results are0/NOT_FOUND and commit0; log success/failure, then close.
 * Open/no-candidate failures return0 silently. No rollback/cache restoration. */
int profile_evict_one(int preserve_current,unsigned int identity_first,
    unsigned int identity_second)
{
    NvsHandle handle;
    if (nvs_open("mbase",1,&handle) != 0)
        return 0;
    NvsIterator iterator = NULL;
    unsigned int selected_first = 0,selected_second = 0,oldest_stamp = 0;
    int found = 0;
    int iteration = nvs_entry_find("nvs","mbase",0xff,&iterator);
    while (iteration == 0) {
        NvsEntryInfo info;
        if (nvs_entry_info(iterator,&info) == 0) {
            unsigned int prefix = (unsigned char)info.key[0];
            unsigned int identity;
            if (prefix != 0 && profile_parse_identity(info.key,&identity)) {
                unsigned int prefix_bit = (unsigned char)(prefix - 'b');
                if (info.key[9] == '\0' && prefix_bit <= 14 &&
                    ((0x4801U >> prefix_bit) & 1U) != 0) {
                    unsigned int candidate_first = identity >> 16;
                    unsigned int candidate_second = identity & 65535U;
                    if (preserve_current == 1 && identity_first == candidate_first && identity_second == candidate_second)
                        goto next_entry;
                    if (PROFILE_PROTECTED_VALID != 0 &&
                        PROFILE_PROTECTED_FIRST == candidate_first &&
                        PROFILE_PROTECTED_SECOND == candidate_second)
                        goto next_entry;
                    volatile ProfileStampQueue *queue = PROFILE_STAMP_QUEUE;
                    unsigned int count = queue->count;
                    for (unsigned int index = 0; index < count; ++index) {
                        const volatile unsigned short *pair = (const volatile void *)
                            ((unsigned int)(uintptr_t)queue + index * 2U);
                        if (pair[1] == candidate_first && pair[9] == candidate_second)
                            goto next_entry;
                    }
                    char stamp_key[16];
                    newlib_snprintf(stamp_key,16,"%c%04x%04x",'u',candidate_first,candidate_second);
                    unsigned int stamp = 0;
                    nvs_get_u32(handle,stamp_key,&stamp);
                    if (!found || stamp < oldest_stamp) {
                        selected_first = candidate_first;
                        selected_second = candidate_second;
                        oldest_stamp = stamp;
                    }
                    found = 1;
                }
            }
        }
next_entry:
        iteration = nvs_entry_next(&iterator);
    }
    nvs_release_iterator(iterator);
    if (!found) {
        nvs_close(handle);
        return 0;
    }
    if (PROFILE_STAMP_CACHE_VALID != 0 &&
        PROFILE_STAMP_CACHED_FIRST == selected_first &&
        PROFILE_STAMP_CACHED_SECOND == selected_second)
        PROFILE_STAMP_CACHE_VALID = 0;
    const unsigned char *prefixes = (const unsigned char *)0x3c042bccU; /* bmpu,NUL */
    unsigned int prefix = 'b';
    unsigned int erased = 1;
    do {
        char key[16];
        newlib_snprintf(key,16,"%c%04x%04x",prefix,selected_first,selected_second);
        int result = nvs_erase_key(handle,key);
        prefix = *++prefixes;
        erased &= result == 0 || result == 0x1102;
    } while (prefix != 0);
    int committed = nvs_commit(handle);
    unsigned int success = erased & (committed == 0);
    if (success != 0) {
        unsigned int timestamp = esp_log_timestamp();
        esp_log_write(2,"bstore","W (%lu) %s: full: dropped what was learned of %04x:%04x\n",
            timestamp,"bstore",selected_first,selected_second);
    } else {
        unsigned int timestamp = esp_log_timestamp();
        esp_log_write(2,"bstore","W (%lu) %s: full: could not drop %04x:%04x\n",
            timestamp,"bstore",selected_first,selected_second);
    }
    nvs_close(handle);
    return (int)success;
}

/* Native entry: 0x42009030. */
/* Original function-byte SHA-256:
 * 7e6275a0565b3ace9edbc17c69a562e7647fca0560b7ea24cab0157fa206406e. */
/* Run once, guarded by started BYTE, set BEFORE static mutex creation/NVS init.
 * A failed initialization is not retried by later calls. Save the returned
 * static mutex handle even if NULL. On NO_FREE_PAGES110d or NEW_VERSION1110,
 * erase the entire default NVS partition, log both results, then retry init
 * regardless of erase success. Publish ready=(init==0) BYTE. Other init errors
 * are logged; afterward RELOAD ready, allowing a callback mutation to admit
 * the following scan. Successful init goes directly to read-only mbase open.
 * Enumerate U32 entries in partition nvs. Parse exactly eight lowercase hex
 * digits after any nonempty prefix, then require key[9]NUL and prefix u.
 * Successful get_u32 values strictly above the LIVE stamp counter replace
 * counter WORD, cached-first16, cached-second16, cache-valid BYTE, in order.
 * Equal/zero stamps do not replace a zero/current counter. Do not reset old
 * counter/cache/queue/protection state. Release iterator even on find error,
 * then close; open failure is silent. No application-mutex lock surrounds scan. */
void profile_storage_initialize(void)
{
    if (PROFILE_STORE_STARTED != 0)
        return;
    PROFILE_STORE_STARTED = 1;
    PROFILE_STORE_MUTEX = xQueueCreateMutexStatic(1,PROFILE_STORE_MUTEX_CONTROL);
    int result = nvs_flash_init();
    if (result == 0x110d || result == 0x1110) {
        int erased = nvs_flash_erase();
        unsigned int timestamp = esp_log_timestamp();
        esp_log_write(2,"bstore","W (%lu) %s: nvs wiped (init=%d erase=%d)\n",
            timestamp,"bstore",result,erased);
        result = nvs_flash_init();
    }
    PROFILE_STORE_READY = result == 0;
    if (result != 0) {
        unsigned int timestamp = esp_log_timestamp();
        esp_log_write(2,"bstore","W (%lu) %s: nvs init %d -> persistence disabled\n",
            timestamp,"bstore",result);
        if (PROFILE_STORE_READY == 0)
            return;
    }
    NvsHandle handle;
    if (nvs_open("mbase",0,&handle) != 0)
        return;
    NvsIterator iterator = NULL;
    int iteration = nvs_entry_find("nvs","mbase",4,&iterator);
    while (iteration == 0) {
        unsigned int stamp = 0;
        NvsEntryInfo info;
        if (nvs_entry_info(iterator,&info) == 0) {
            unsigned int prefix = (unsigned char)info.key[0],identity;
            if (prefix != 0 && profile_parse_identity(info.key,&identity) &&
                info.key[9] == '\0' && prefix == 'u' &&
                nvs_get_u32(handle,info.key,&stamp) == 0 &&
                PROFILE_STAMP_COUNTER < stamp) {
                PROFILE_STAMP_COUNTER = stamp;
                PROFILE_STAMP_CACHED_FIRST = (unsigned short)(identity >> 16);
                PROFILE_STAMP_CACHED_SECOND = (unsigned short)identity;
                PROFILE_STAMP_CACHE_VALID = 1;
            }
        }
        iteration = nvs_entry_next(&iterator);
    }
    nvs_release_iterator(iterator);
    nvs_close(handle);
}

/* Native entry: 0x42009188. */
/* Original function-byte SHA-256:
 * dc16170e8c4dbd73e3bdb5b923785a3df9a38aa5188eeafd5045568783354a67. */
/* Set protected identity and move/append its stamp request to the queue tail.
 * Inputs narrow to16 bits. Optional mutex take waits forever, result ignored;
 * only a nonnull acquired-handle path reloads the later release handle.
 * Store protected-first HALFWORD, snapshot queue-count BYTE, store protected-
 * second HALFWORD, then protected-valid BYTE1, in that native order.
 * Scan the saved count without an eight-entry clamp. A matching pair shifts
 * later entries forward, with BOTH next HALFWORD reads before the two stores,
 * and is reinserted at saved_count-1 without changing total count. No match
 * at count8 moves first-array14bytes then second-array14bytes and inserts7.
 * Other counts insert at saved_count and publish LOW8(saved_count+1), including
 * malformed counts above8. Append first16, second16, then count BYTE. Give
 * saved release handle if nonnull; no ready gate or hardware fence. */
void profile_protect_and_queue_stamp(unsigned short identity_first,unsigned short identity_second)
{
    RtosQueue *mutex = PROFILE_STORE_MUTEX;
    if (mutex != NULL) {
        xQueueSemaphoreTake(mutex,0xffffffffU);
        mutex = PROFILE_STORE_MUTEX;
    }
    volatile ProfileStampQueue *queue = PROFILE_STAMP_QUEUE;
    PROFILE_PROTECTED_FIRST = identity_first;
    unsigned int count = queue->count;
    PROFILE_PROTECTED_SECOND = identity_second;
    PROFILE_PROTECTED_VALID = 1;
    unsigned int insertion = count,published_count = count;
    unsigned int index;
    for (index = 0; index < count; ++index) {
        const volatile unsigned short *pair = (const volatile void *)
            ((unsigned int)(uintptr_t)queue + index * 2U);
        if (pair[1] == identity_first && pair[9] == identity_second)
            break;
    }
    if (index < count) {
        for (unsigned int slot = index; slot + 1U < count; ++slot) {
            volatile unsigned short *pair = (volatile void *)
                ((unsigned int)(uintptr_t)queue + slot * 2U);
            unsigned short next_first = pair[2];
            unsigned short next_second = pair[10];
            pair[1] = next_first;
            pair[9] = next_second;
        }
        insertion = (count - 1U) & 255U;
    } else if (count == 8) {
        memmove((void *)queue->identity_first,(const void *)(queue->identity_first + 1),14);
        memmove((void *)queue->identity_second,(const void *)(queue->identity_second + 1),14);
        insertion = 7;
    } else {
        published_count = (count + 1U) & 255U;
    }
    volatile unsigned short *pair = (volatile void *)
        ((unsigned int)(uintptr_t)queue + insertion * 2U);
    pair[1] = identity_first;
    pair[9] = identity_second;
    queue->count = (unsigned char)published_count;
    if (mutex != NULL)
        xQueueGenericSend(mutex,NULL,0,0);
}

/* Native entry: 0x420094ac. */
/* Original function-byte SHA-256:
 * cbaa868f75ae61a86b2b50d1d63a38844898582c91192b55ed98300f251d1bab. */
/* If live ready BYTE is nonzero, erase the ENTIRE default NVS partition,
 * log its result and return normalized success. Does not clear ready, started,
 * cached identities, queues or mutex, and does not reinitialize the partition.
 * No local application lock; caller must account for other storage users. */
int profile_storage_erase(void)
{
    if (PROFILE_STORE_READY == 0)
        return 0;
    int result = nvs_flash_erase();
    unsigned int timestamp = esp_log_timestamp();
    esp_log_write(2,"bstore","W (%lu) %s: nvs erased (%d)\n",timestamp,"bstore",result);
    return result == 0;
}
