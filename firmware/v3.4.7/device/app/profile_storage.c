/* Device identity-keyed NVS profile storage. */

#include "../include/types.h"

/* Native entry: 0x42009950. */
/* Original function-byte SHA-256:
 * bc9b6d21f35c2d1c43b92c3cd0f59d1fe05b21e77fcc50914b4fa7c707095eaa. */
/* Load the b profile blob from read-only NVS namespace mbase. Snapshot ready
 * BYTE first; require it nonzero and both output pointers nonnull. Format
 * keyb%04x%04x with two16-bit identities and16-byte key capacity. Initial blob
 * capacity is the16-bit capacity argument, including0. Always close an opened
 * handle before testing the read result or storing LOW16(returned length).
 * Success returns the SAVED ready BYTE unchanged; failure returns0 and leaves
 * output length untouched. The NVS reader may already have modified output.
 * No local lock, extra64-byte cap, output clear or retry is supplied. */
unsigned char profile_load_baseline(unsigned short identity_first,unsigned short identity_second,
    void *output,unsigned short *length_out,unsigned short capacity)
{
    unsigned char ready = PROFILE_STORE_READY;
    if (ready == 0 || output == NULL || length_out == NULL)
        return 0;
    NvsHandle handle;
    if (nvs_open("mbase",0,&handle) != 0)
        return 0;
    char key[16];
    newlib_snprintf(key,16,"%c%04x%04x",'b',identity_first,identity_second);
    size_t length = capacity;
    int result = nvs_get_blob(handle,key,output,&length);
    nvs_close(handle);
    if (result != 0)
        return 0;
    *(volatile unsigned short *)length_out = (unsigned short)length;
    return ready;
}

/* Native entry: 0x420099d0. */
/* Original function-byte SHA-256:
 * 33c02cf6d3671c9513d52d5667df50b73ae8feafc93dfd0ecc421f0ea3af9a0d. */
/* Load the m profile blob from read-only NVS namespace mbase. Snapshot ready
 * BYTE first; require it nonzero and both output pointers nonnull. Format
 * keym%04x%04x with two16-bit identities and16-byte key capacity. Initial blob
 * capacity is the16-bit capacity argument, including0. Always close an opened
 * handle before testing the read result or storing LOW16(returned length).
 * Success returns the SAVED ready BYTE unchanged; failure returns0 and leaves
 * output length untouched. The NVS reader may already have modified output.
 * No local lock, extra64-byte cap, output clear or retry is supplied. */
unsigned char profile_load_normalization(unsigned short identity_first,unsigned short identity_second,
    void *output,unsigned short *length_out,unsigned short capacity)
{
    unsigned char ready = PROFILE_STORE_READY;
    if (ready == 0 || output == NULL || length_out == NULL)
        return 0;
    NvsHandle handle;
    if (nvs_open("mbase",0,&handle) != 0)
        return 0;
    char key[16];
    newlib_snprintf(key,16,"%c%04x%04x",'m',identity_first,identity_second);
    size_t length = capacity;
    int result = nvs_get_blob(handle,key,output,&length);
    nvs_close(handle);
    if (result != 0)
        return 0;
    *(volatile unsigned short *)length_out = (unsigned short)length;
    return ready;
}

/* Native entry: 0x420099b8. */
/* Original function-byte SHA-256:
 * de1c981bee94989a920bcfb0fde4e019211f3248f2610f187f79b79bdbfb3971. */
/* Forward prefix'b', two16-bit identities, borrowed payload and16-bit length
 * to the shared profile writer. Return its raw BYTE result. This wrapper adds
 * no validation, copy, lock, commit, fallback or retry of its own. */
unsigned char profile_store_baseline(unsigned short identity_first,unsigned short identity_second,
    const void *payload,unsigned short length)
{
    return profile_store_blob('b',identity_first,identity_second,payload,length);
}

/* Native entry: 0x42009a38. */
/* Original function-byte SHA-256:
 * b9c56b0b6108f22649bbe7461cb43e88dabeeb4b37613f044f1d39b6b89911c9. */
/* Forward prefix'm', two16-bit identities, borrowed payload and16-bit length
 * to the shared profile writer. Return its raw BYTE result. This wrapper adds
 * no validation, copy, lock, commit, fallback or retry of its own. */
unsigned char profile_store_normalization(unsigned short identity_first,unsigned short identity_second,
    const void *payload,unsigned short length)
{
    return profile_store_blob('m',identity_first,identity_second,payload,length);
}

/* Native entry: 0x42009a50. */
/* Original function-byte SHA-256:
 * d08cff262eabd0dec08d8d8da97a1e1620340f2c4f9d61dc8e21e40ef7744a95. */
/* Load x%04x%04x from read-only mbase. Snapshot ready BYTE, then require ready
 * and both pointers; only after admission clear output-length HALFWORD to0.
 * Namespace-open NOT_FOUND(0x1102) is successful empty patches with saved raw
 * ready BYTE. Other open errors return0. Once open, read using16-bit capacity,
 * close BEFORE checking result, then treat NOT_FOUND as successful empty too.
 * On read0 store LOW16(returned length) and return saved ready; other failures
 * retain length0 and return0, although output may have changed. No lock/retry,
 * payload initialization,64-byte cap or extra descriptor parsing is added. */
unsigned char profile_load_patches(unsigned short identity_first,
    unsigned short identity_second,void *output,unsigned short *length_out,unsigned short capacity)
{
    unsigned char ready = PROFILE_STORE_READY;
    if (ready == 0 || output == NULL || length_out == NULL)
        return 0;
    *(volatile unsigned short *)length_out = 0;
    NvsHandle handle;
    int result = nvs_open("mbase",0,&handle);
    if (result == 0x1102)
        return ready;
    if (result != 0)
        return 0;
    char key[16];
    newlib_snprintf(key,16,"%c%04x%04x",'x',identity_first,identity_second);
    size_t length = capacity;
    result = nvs_get_blob(handle,key,output,&length);
    nvs_close(handle);
    if (result == 0x1102)
        return ready;
    if (result != 0)
        return 0;
    *(volatile unsigned short *)length_out = (unsigned short)length;
    return ready;
}

/* Native entry: 0x42009c40. */
/* Original function-byte SHA-256:
 * 0ed3dd583d06e851b2c5aa36ff0e402f432da2fbbe2aa21a59061092a881af34. */
/* Require nonnull output BEFORE reading store-ready BYTE. With ready nonzero,
 * open read-only mbase and read p%04x%04x into a local HALFWORD with capacity2.
 * Close before testing the result and LOW16(returned size)==2. Success copies
 * that HALFWORD to output and returns saved raw ready BYTE. Failure returns0
 * without writing output. The size test is16-bit, not full size_t equality.
 * No output clear, zero-period rejection, mutex, range conversion or retry. */
unsigned char profile_load_period(unsigned short identity_first,
    unsigned short identity_second,unsigned short *period_out)
{
    if (period_out == NULL)
        return 0;
    unsigned char ready = PROFILE_STORE_READY;
    if (ready == 0)
        return 0;
    NvsHandle handle;
    if (nvs_open("mbase",0,&handle) != 0)
        return 0;
    char key[16];
    newlib_snprintf(key,16,"%c%04x%04x",'p',identity_first,identity_second);
    size_t length = 2;
    unsigned short period;
    int result = nvs_get_blob(handle,key,&period,&length);
    nvs_close(handle);
    if (result != 0 || (unsigned short)length != 2)
        return 0;
    *(volatile unsigned short *)period_out = period;
    return ready;
}

/* Native entry: 0x42009ca4. */
/* Original function-byte SHA-256:
 * a98d738dd4fd03ca73076930d38141e348b17615088441177411527fc772d105. */
/* Save the little-endian16-bit period as prefix'p' through the shared writer.
 * Both identity words are16-bit. Return its raw BYTE result without local
 * conversion, validation, locking or retry; the local period lives through call. */
unsigned char profile_store_period(unsigned short identity_first,
    unsigned short identity_second,unsigned short period)
{
    return profile_store_blob('p',identity_first,identity_second,&period,2);
}

/* Native entry: 0x42009cc4. */
/* Original function-byte SHA-256:
 * 62f390de195685e208b7aaa7ffb4f258adb575a0608150506da89704960b99c5. */
/* Snapshot ready BYTE and initialize local flag0. If ready, open read-only
 * mbase and read g%04x%04x with capacity1. Close before testing error and
 * LOW16(returned length)==1. Return normalized flag!=0 only on that success;
 * otherwise0. This does not return raw ready or modify globals. No mutex,
 * logging, retry or profile activation is performed. */
unsigned char profile_capture_is_stored(unsigned short identity_first,
    unsigned short identity_second)
{
    unsigned char ready = PROFILE_STORE_READY;
    unsigned char flag = 0;
    if (ready == 0)
        return 0;
    NvsHandle handle;
    if (nvs_open("mbase",0,&handle) != 0)
        return 0;
    char key[16];
    newlib_snprintf(key,16,"%c%04x%04x",'g',identity_first,identity_second);
    size_t length = 1;
    int result = nvs_get_blob(handle,key,&flag,&length);
    nvs_close(handle);
    if (result != 0 || (unsigned short)length != 1)
        return 0;
    return flag != 0;
}

/* Native entry: 0x42009d2c. */
/* Original function-byte SHA-256:
 * 9bcd3624c8d0049a75e142392e19f313696be7b7d26cf943a6dac8aa2f277338. */
/* Pass a local BYTE1 as g%04x%04x to the shared profile writer with length1.
 * Return the writer's raw BYTE result; this wrapper has no erase/clear mode,
 * additional validation, lock or retry. Identity parameters are16-bit. */
unsigned char profile_store_capture_flag(unsigned short identity_first,
    unsigned short identity_second)
{
    unsigned char flag = 1;
    return profile_store_blob('g',identity_first,identity_second,&flag,1);
}

/* Native entry: 0x4200927c. */
/* Original function-byte SHA-256:
 * bd1b29ed6a0408e81365f2c7923529148be8dcf0688394eac8bd2b0c6523ddef. */
/* Read ready BYTE first; if0 return0 without reading queued-stamp count.
 * Otherwise return normalized pending-count BYTE!=0. These are separate live
 * reads, without a mutex, MEMW, counter mutation or persistence operation. */
unsigned char profile_stamp_pending(void)
{
    if (PROFILE_STORE_READY == 0)
        return 0;
    return PROFILE_STAMP_QUEUE->count != 0;
}

/* Native entry: 0x42008dac. */
/* Original function-byte SHA-256:
 * 1ea2fdd7a7c2f26e06f85f43b14fbb3c4e777e45bff3cf9fc4eab73da9cf66e8. */
/* Store an identity-keyed profile blob in NVS namespace mbase. Snapshot ready
 * BYTE; require ready, payload nonnull and LOW16(length-1)<=63. This admits
 * lengths whose low16 bits are1..64; the FULL32 size is still passed onward.
 * Format a16-byte key using full32 prefix/identity arguments. Open mode1,
 * compare existing blob via64-byte local scratch and full returned size.
 * Identical data closes and returns saved ready without write, commit or stamp.
 *
 * For changed data take optional storage mutex indefinitely, ignoring status.
 * Attempt nvs_set_blob up to9 times. Only NOT_ENOUGH_SPACE(0x1105) can retry:
 * call eviction(1,first,second) between attempts and stop if it returns0.
 * Reload/release optional mutex BEFORE commit. Any set/commit failure logs
 * its saved error, closes and returns0. Open failure logs separately.
 *
 * Successful commit queues an identity for stamp processing only when bit
 * ((prefix-'b')&31) in0x4801 is set (ordinary b,m,p; full-word aliases remain).
 * A null-mutex/count0 fast path stores first16,second16,count1 in that order.
 * Otherwise optionally take mutex, snapshot count BYTE then release handle,
 * scan saved count entries comparing each stored16 identity to FULL32 args.
 * A duplicate is shifted out with first/second loads BEFORE first/second
 * stores, then appended at count-1 without changing total count. No match at
 * count8 memmoves the two seven-HALFWORD arrays separately and appends at7.
 * Other counts append at saved count and publish LOW8(count+1); no >8 clamp.
 * These general append paths store first16, count BYTE, second16, then give
 * the SAVED release handle if nonnull. Payloads are not retained by this code.
 * Return saved ready BYTE after commit regardless of ignored queue/lock status.
 * No explicit MEMW, hardware execution or durability guarantee beyond called
 * NVS results is implied. Invalid counts/full-word sizes retain native hazards. */
unsigned char profile_store_blob(unsigned int prefix,unsigned int identity_first,
    unsigned int identity_second,const void *payload,size_t length)
{
    unsigned char ready = PROFILE_STORE_READY;
    if (ready == 0 || ((length - 1U) & 65535U) > 63U || payload == NULL)
        return 0;
    NvsHandle handle;
    int result = nvs_open("mbase",1,&handle);
    if (result != 0) {
        unsigned int timestamp = esp_log_timestamp();
        esp_log_write(2,"bstore","W (%lu) %s: nvs_open w failed %d\n",timestamp,"bstore",result);
        return 0;
    }
    char key[16];
    newlib_snprintf(key,16,"%c%04x%04x",prefix,identity_first,identity_second);
    unsigned char previous[64];
    size_t previous_length = 64;
    result = nvs_get_blob(handle,key,previous,&previous_length);
    if (result == 0 && previous_length == length && memcmp(previous,payload,previous_length) == 0) {
        nvs_close(handle);
        return ready;
    }
    RtosQueue *mutex = PROFILE_STORE_MUTEX;
    if (mutex != NULL)
        xQueueSemaphoreTake(mutex,0xffffffffU);
    unsigned int attempts_remaining = 9;
    do {
        result = nvs_set_blob(handle,key,payload,length);
        --attempts_remaining;
        if (result != 0x1105 || attempts_remaining == 0)
            break;
    } while (profile_evict_one(1,identity_first,identity_second) != 0);
    mutex = PROFILE_STORE_MUTEX;
    if (mutex != NULL)
        xQueueGenericSend(mutex,NULL,0,0);
    if (result == 0)
        result = nvs_commit(handle);
    if (result != 0) {
        unsigned int timestamp = esp_log_timestamp();
        esp_log_write(2,"bstore","W (%lu) %s: persist FAILED for %04x:%04x: %d (not durable)\n",
            timestamp,"bstore",identity_first,identity_second,result);
        nvs_close(handle);
        return 0;
    }
    if (((0x4801U >> ((prefix - (unsigned int)'b') & 31U)) & 1U) != 0) {
        mutex = PROFILE_STORE_MUTEX;
        volatile ProfileStampQueue *queue = PROFILE_STAMP_QUEUE;
        unsigned int count;
        if (mutex == NULL) {
            count = queue->count;
            if (count == 0) {
                queue->identity_first[0] = (unsigned short)identity_first;
                queue->identity_second[0] = (unsigned short)identity_second;
                queue->count = 1;
                goto close_success;
            }
        } else {
            xQueueSemaphoreTake(mutex,0xffffffffU);
            count = queue->count;
            mutex = PROFILE_STORE_MUTEX;
        }
        unsigned int insertion = count;
        unsigned int published_count = count;
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
        pair[1] = (unsigned short)identity_first;
        queue->count = (unsigned char)published_count;
        pair[9] = (unsigned short)identity_second;
        if (mutex != NULL)
            xQueueGenericSend(mutex,NULL,0,0);
    }

close_success:
    nvs_close(handle);
    return ready;
}

/* Native entry: 0x42009acc. */
/* Original function-byte SHA-256:
 * 868d7de266f087a47222101a00015eb122fcad50134c07f75be666558dad7ef0. */
/* Save or erase x%04x%04x in read/write mbase. Snapshot ready BYTE, narrow
 * both identities and length to16 bits. Ready0, nonzero length with NULL
 * payload, or open error returns0; NULL payload is allowed for length0.
 * Always read existing blob into shared1200-byte scratch BEFORE choosing
 * operation. Positive identical length/data closes and returns saved ready.
 * Positive changed data takes optional storage mutex, ignores take status,
 * attempts set_blob up to9 times and retries only1105 after successful
 * eviction(1,first,second). Reload/release optional mutex BEFORE commit.
 * Length0 plus read NOT_FOUND closes as successful no-op. Other length0
 * cases erase key WITHOUT this optional storage lock; erase0 or1102 commits,
 * other errors fail. A set error also skips commit. Commit0 returns saved raw
 * ready; any final failure logs saved error and returns0. Always close opened
 * handle. No1200-byte input cap, scratch mutex, stamp queue or extra retry on
 * commit/delete is added. Caller must serialize shared scratch if required. */
unsigned char profile_store_patches(unsigned short identity_first,
    unsigned short identity_second,const void *payload,unsigned short length)
{
    unsigned char ready = PROFILE_STORE_READY;
    if (ready == 0 || (length != 0 && payload == NULL))
        return 0;
    NvsHandle handle;
    if (nvs_open("mbase",1,&handle) != 0)
        return 0;
    char key[16];
    newlib_snprintf(key,16,"%c%04x%04x",'x',identity_first,identity_second);
    size_t previous_length = 1200;
    int result = nvs_get_blob(handle,key,PROFILE_PATCH_SCRATCH,&previous_length);
    if (length != 0) {
        if (result == 0 && previous_length == length &&
            memcmp(PROFILE_PATCH_SCRATCH,payload,length) == 0) {
            nvs_close(handle);
            return ready;
        }
        RtosQueue *mutex = PROFILE_STORE_MUTEX;
        if (mutex != NULL)
            xQueueSemaphoreTake(mutex,0xffffffffU);
        unsigned int attempts = 9;
        do {
            result = nvs_set_blob(handle,key,payload,length);
            --attempts;
            if (result != 0x1105 || attempts == 0)
                break;
        } while (profile_evict_one(1,identity_first,identity_second) != 0);
        mutex = PROFILE_STORE_MUTEX;
        if (mutex != NULL)
            xQueueGenericSend(mutex,NULL,0,0);
        if (result != 0)
            goto failure;
    } else {
        if (result == 0x1102) {
            nvs_close(handle);
            return ready;
        }
        result = nvs_erase_key(handle,key);
        if (result != 0 && result != 0x1102)
            goto failure;
    }
    result = nvs_commit(handle);
    if (result == 0) {
        nvs_close(handle);
        return ready;
    }
failure:
    unsigned int timestamp = esp_log_timestamp();
    esp_log_write(2,"bstore","W (%lu) %s: patches persist FAILED for %04x:%04x: %d\n",
        timestamp,"bstore",identity_first,identity_second,result);
    nvs_close(handle);
    return 0;
}

/* Native entry: 0x42009294. */
/* Original function-byte SHA-256:
 * b82b11f12ff3e4e1fe4f5695b72ffcc0dd091f407f5f85c07663a0e8227ee03a. */
/* Process the first queued profile identity when ready and count BYTE nonzero.
 * Snapshot head first16, cached-valid BYTE, then head second16. If valid cache
 * matches both IDs, skip NVS work. Otherwise open mbase mode1 and look for any
 * b,m,p key, in that order, using find_key; returned type is ignored. No key
 * or open failure still proceeds to REMOVE the saved identity from live queue.
 * If a key exists, read its u%04x%04x WORD stamp. Read success with nonzero
 * value equal to live global counter skips writing without updating cache.
 *
 * Otherwise take optional storage mutex indefinitely, ignoring status, and
 * try set_u32(key, FRESH counter+1) up to9 times. Only1105 retries, after
 * eviction(1,saved first,saved second) succeeds. Reload/release optional mutex
 * before commit. Set/commit error logs but STILL dequeues the saved identity.
 * Commit success rereads counter and increments it independently of the value
 * passed to set_u32, then writes cached first16, second16 and valid1 in order.
 * Close every opened handle before queue removal. No counter wrap repair.
 *
 * Queue removal independently takes the then-current optional mutex, snapshots
 * live count BYTE then (only for a taken mutex) its release handle. Initial
 * null mutex keeps NULL for release. Scan saved count for the original pair;
 * if found shift later first/second HALFWORDs left, loading both before storing
 * either, then publish LOW8(count-1). Missing pair leaves count unchanged.
 * Give the SAVED nonnull release handle. No >8 count clamp, payload clear,
 * explicit MEMW, persistence retry queue or error result is added. */
void profile_process_pending_stamp(void)
{
    if (PROFILE_STORE_READY == 0)
        return;
    volatile ProfileStampQueue *queue = PROFILE_STAMP_QUEUE;
    if (queue->count == 0)
        return;
    unsigned short identity_first = queue->identity_first[0];
    unsigned char cache_valid = PROFILE_STAMP_CACHE_VALID;
    unsigned short identity_second = queue->identity_second[0];
    if (cache_valid != 0 && PROFILE_STAMP_CACHED_FIRST == identity_first &&
        PROFILE_STAMP_CACHED_SECOND == identity_second)
        goto remove_identity;
    NvsHandle handle;
    if (nvs_open("mbase",1,&handle) != 0)
        goto remove_identity;
    char key[16];
    unsigned int type;
    unsigned int prefix_index = 0;
    int result;
    do {
        unsigned int prefix = (unsigned char)"bmp"[prefix_index];
        newlib_snprintf(key,16,"%c%04x%04x",prefix,identity_first,identity_second);
        result = nvs_find_key(handle,key,&type);
        ++prefix_index;
    } while (prefix_index < 3 && result != 0);
    if (result != 0)
        goto close_handle;
    newlib_snprintf(key,16,"%c%04x%04x",'u',identity_first,identity_second);
    unsigned int stamp = 0;
    result = nvs_get_u32(handle,key,&stamp);
    if (result == 0 && stamp == PROFILE_STAMP_COUNTER && stamp != 0)
        goto close_handle;
    RtosQueue *mutex = PROFILE_STORE_MUTEX;
    if (mutex != NULL)
        xQueueSemaphoreTake(mutex,0xffffffffU);
    unsigned int attempts_remaining = 9;
    do {
        result = nvs_set_u32(handle,key,PROFILE_STAMP_COUNTER + 1U);
        --attempts_remaining;
        if (result != 0x1105 || attempts_remaining == 0)
            break;
    } while (profile_evict_one(1,identity_first,identity_second) != 0);
    mutex = PROFILE_STORE_MUTEX;
    if (mutex != NULL)
        xQueueGenericSend(mutex,NULL,0,0);
    if (result == 0)
        result = nvs_commit(handle);
    if (result == 0) {
        PROFILE_STAMP_COUNTER = PROFILE_STAMP_COUNTER + 1U;
        PROFILE_STAMP_CACHED_FIRST = identity_first;
        PROFILE_STAMP_CACHED_SECOND = identity_second;
        PROFILE_STAMP_CACHE_VALID = 1;
    } else {
        unsigned int timestamp = esp_log_timestamp();
        esp_log_write(2,"bstore","W (%lu) %s: stamp persist FAILED for %04x:%04x: %d\n",
            timestamp,"bstore",identity_first,identity_second,result);
    }
close_handle:
    nvs_close(handle);
remove_identity:
    mutex = PROFILE_STORE_MUTEX;
    unsigned int count;
    if (mutex == NULL) {
        count = queue->count;
        if (count == 0)
            return;
    } else {
        xQueueSemaphoreTake(mutex,0xffffffffU);
        count = queue->count;
        mutex = PROFILE_STORE_MUTEX;
    }
    for (unsigned int index = 0; index < count; ++index) {
        volatile unsigned short *pair = (volatile void *)
            ((unsigned int)(uintptr_t)queue + index * 2U);
        if (pair[1] != identity_first || pair[9] != identity_second)
            continue;
        for (unsigned int slot = index; slot + 1U < count; ++slot) {
            volatile unsigned short *moving = (volatile void *)
                ((unsigned int)(uintptr_t)queue + slot * 2U);
            unsigned short next_first = moving[2];
            unsigned short next_second = moving[10];
            moving[1] = next_first;
            moving[9] = next_second;
        }
        queue->count = (unsigned char)(count - 1U);
        break;
    }
    if (mutex != NULL)
        xQueueGenericSend(mutex,NULL,0,0);
}
