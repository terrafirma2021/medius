/* Medius v3.4.7 device: persistent scalar and string settings. */
#include "../include/types.h"

/* Native entry: 0x420094e0. */
/* Original function-byte SHA-256:
 * 34fbee0edfe52d238c5a8ea4ae51ec0d070ccd45d3f9789c4d882f6f9dd70f0b. */
/* Snapshot ready BYTE before validating nonnull key/output. Open mbase
 * read-only, initialize one local BYTE0, read U8 and close before checking
 * result. On success write normalized(value!=0) BYTE and return SAVED raw
 * ready BYTE; on failure return0 and leave output untouched. Empty key is
 * delegated to NVS. No mutex, logging or bounds beyond pointer gates. */
unsigned char settings_load_flag(const char *key,unsigned char *output)
{
    unsigned char ready = PROFILE_STORE_READY;
    if (ready == 0 || key == NULL || output == NULL)
        return 0;
    NvsHandle handle;
    if (nvs_open("mbase",0,&handle) != 0)
        return 0;
    unsigned char value = 0;
    int result = nvs_get_u8(handle,key,&value);
    nvs_close(handle);
    if (result != 0)
        return 0;
    *output = value != 0;
    return ready;
}

/* Native entry: 0x42009658. */
/* Original function-byte SHA-256:
 * 433df56dd5852d459ff7c227f9ddf20ffd1428a80c2ecd37701b1ecd18d79b9f. */
/* Snapshot ready BYTE, require nonnull key/output, open read-only mbase.
 * Read U16 into an initially zero local HALFWORD; close before result test
 * and output store. Success writes HALFWORD and returns saved raw ready BYTE.
 * Failure returns0 without output update. No mutex or key-content check. */
unsigned char settings_load_u16(const char *key,unsigned short *output)
{
    unsigned char ready = PROFILE_STORE_READY;
    if (ready == 0 || key == NULL || output == NULL)
        return 0;
    NvsHandle handle;
    if (nvs_open("mbase",0,&handle) != 0)
        return 0;
    unsigned short value = 0;
    int result = nvs_get_u16(handle,key,&value);
    nvs_close(handle);
    if (result != 0)
        return 0;
    *output = value;
    return ready;
}

/* Native entry: 0x420097cc. */
/* Original function-byte SHA-256:
 * b78deafdd743603a3acf590784168539e8b568dc45601fb853cbe02d109410b4. */
/* Require ready BYTE nonzero and nonnull key/output plus nonzero full32
 * capacity. Open read-only mbase, pass a LOCAL32 size initialized to capacity
 * to get_str, close, and return normalized(result==0). Do not return the
 * resulting size or initialize/terminate output independently; NVS may change
 * it even on failure. No local mutex or signed-positive capacity test. */
int settings_load_string(const char *key,char *output,size_t capacity)
{
    if (PROFILE_STORE_READY == 0 || key == NULL || output == NULL || capacity == 0)
        return 0;
    NvsHandle handle;
    if (nvs_open("mbase",0,&handle) != 0)
        return 0;
    size_t length = capacity;
    int result = nvs_get_str(handle,key,output,&length);
    nvs_close(handle);
    return result == 0;
}

/* Native entry: 0x42009538. */
/* Original function-byte SHA-256:
 * c1762bc9269cab691833000fac8504b382a370b4980bdc1568e16238789bb2ec. */
/* Store LOW8(value) under key in mbase; flag values are not normalized.
 * Snapshot ready BYTE even when key NULL; admission requires ready EXACTLY1.
 * Read previous 8-bit value (initial255); equal successful read closes and
 * returns1 without write/commit/lock. Otherwise optional storage-mutex take
 * waits forever, ignored result. Try setter at most9 times; only1105 may
 * retry, after successful eviction(0,0,0), at most8 evictions. Fresh release
 * handle is sampled after all attempts and given BEFORE commit; initial and
 * release handles may differ. Commit only setter0. Open/set/commit failures
 * log saved error and return0; opened handles close. No stamp enqueue or key
 * content validation. Each eviction receives three zero arguments. */
unsigned char settings_store_flag(const char *key,unsigned char value)
{
    unsigned char ready = PROFILE_STORE_READY;
    if (key == NULL || ready != 1)
        return 0;
    NvsHandle handle;
    int result = nvs_open("mbase",1,&handle);
    if (result != 0) {
        unsigned int timestamp = esp_log_timestamp();
        esp_log_write(2,"bstore","W (%lu) %s: nvs_open w failed %d\n",timestamp,"bstore",result);
        return 0;
    }
    unsigned char previous = 255;
    result = nvs_get_u8(handle,key,&previous);
    if (result == 0 && previous == value) {
        nvs_close(handle);
        return 1;
    }
    RtosQueue *mutex = PROFILE_STORE_MUTEX;
    if (mutex != NULL)
        xQueueSemaphoreTake(mutex,0xffffffffU);
    unsigned int attempts = 9;
    do {
        result = nvs_set_u8(handle,key,value);
        --attempts;
        if (result != 0x1105 || attempts == 0)
            break;
    } while (profile_evict_one(0,0,0) != 0);
    mutex = PROFILE_STORE_MUTEX;
    if (mutex != NULL)
        xQueueGenericSend(mutex,NULL,0,0);
    if (result == 0)
        result = nvs_commit(handle);
    unsigned char success = result == 0;
    if (!success) {
        unsigned int timestamp = esp_log_timestamp();
        esp_log_write(2,"bstore","W (%lu) %s: flag '%s' persist FAILED: %d\n",timestamp,"bstore",key,result);
    }
    nvs_close(handle);
    return success;
}

/* Native entry: 0x420096ac. */
/* Original function-byte SHA-256:
 * d8056f75686f1ad97625964e88907ca7f10995b95eee2e1d76b497ff82224596. */
/* Store the unsigned LOW16(value) under key in mbase.
 * Snapshot ready BYTE even when key NULL; admission requires ready EXACTLY1.
 * Read previous 16-bit value (initial0); equal successful read closes and
 * returns1 without write/commit/lock. Otherwise optional storage-mutex take
 * waits forever, ignored result. Try setter at most9 times; only1105 may
 * retry, after successful eviction(0,0,0), at most8 evictions. Fresh release
 * handle is sampled after all attempts and given BEFORE commit; initial and
 * release handles may differ. Commit only setter0. Open/set/commit failures
 * log saved error and return0; opened handles close. No stamp enqueue or key
 * content validation. Each eviction receives three zero arguments. */
unsigned char settings_store_u16(const char *key,unsigned short value)
{
    unsigned char ready = PROFILE_STORE_READY;
    if (key == NULL || ready != 1)
        return 0;
    NvsHandle handle;
    int result = nvs_open("mbase",1,&handle);
    if (result != 0) {
        unsigned int timestamp = esp_log_timestamp();
        esp_log_write(2,"bstore","W (%lu) %s: nvs_open w failed %d\n",timestamp,"bstore",result);
        return 0;
    }
    unsigned short previous = 0;
    result = nvs_get_u16(handle,key,&previous);
    if (result == 0 && previous == value) {
        nvs_close(handle);
        return 1;
    }
    RtosQueue *mutex = PROFILE_STORE_MUTEX;
    if (mutex != NULL)
        xQueueSemaphoreTake(mutex,0xffffffffU);
    unsigned int attempts = 9;
    do {
        result = nvs_set_u16(handle,key,value);
        --attempts;
        if (result != 0x1105 || attempts == 0)
            break;
    } while (profile_evict_one(0,0,0) != 0);
    mutex = PROFILE_STORE_MUTEX;
    if (mutex != NULL)
        xQueueGenericSend(mutex,NULL,0,0);
    if (result == 0)
        result = nvs_commit(handle);
    unsigned char success = result == 0;
    if (!success) {
        unsigned int timestamp = esp_log_timestamp();
        esp_log_write(2,"bstore","W (%lu) %s: u16 '%s' persist FAILED: %d\n",timestamp,"bstore",key,result);
    }
    nvs_close(handle);
    return success;
}

/* Native entry: 0x42009824. */
/* Original function-byte SHA-256:
 * 9c51689d1a5120d2d101c9500f3f104f0417108fb538874bcebb65a7ea910712. */
/* Snapshot ready BYTE; require nonzero plus nonnull key/value. Read/write
 * mbase open; get_str into64 local bytes with size64, strcmp only on get0.
 * Equal string closes and returns saved raw ready BYTE without lock/write.
 * Changed/error read uses optional mutex take, set_str at most9 times with
 * 1105-only eviction(0,0,0) retry, at most8 evictions. Reload/give mutex BEFORE
 * commit. Setter0 commits; success returns saved raw ready BYTE, not current
 * ready. Failures log saved error and return0. Value length is not capped64
 * by this wrapper; read capacity only controls the equality check. No stamp,
 * pointer-content/termination validation or callback-result checks. */
unsigned char settings_store_string(const char *key,const char *value)
{
    unsigned char ready = PROFILE_STORE_READY;
    if (ready == 0 || key == NULL || value == NULL)
        return 0;
    NvsHandle handle;
    int result = nvs_open("mbase",1,&handle);
    if (result != 0) {
        unsigned int timestamp = esp_log_timestamp();
        esp_log_write(2,"bstore","W (%lu) %s: nvs_open w failed %d\n",timestamp,"bstore",result);
        return 0;
    }
    char previous[64];
    size_t length = 64;
    result = nvs_get_str(handle,key,previous,&length);
    if (result == 0 && strcmp(previous,value) == 0) {
        nvs_close(handle);
        return ready;
    }
    RtosQueue *mutex = PROFILE_STORE_MUTEX;
    if (mutex != NULL)
        xQueueSemaphoreTake(mutex,0xffffffffU);
    unsigned int attempts = 9;
    do {
        result = nvs_set_str(handle,key,value);
        --attempts;
        if (result != 0x1105 || attempts == 0)
            break;
    } while (profile_evict_one(0,0,0) != 0);
    mutex = PROFILE_STORE_MUTEX;
    if (mutex != NULL)
        xQueueGenericSend(mutex,NULL,0,0);
    unsigned char success = ready;
    if (result == 0)
        result = nvs_commit(handle);
    if (result != 0) {
        unsigned int timestamp = esp_log_timestamp();
        esp_log_write(2,"bstore","W (%lu) %s: str '%s' persist FAILED: %d\n",timestamp,"bstore",key,result);
        success = 0;
    }
    nvs_close(handle);
    return success;
}
