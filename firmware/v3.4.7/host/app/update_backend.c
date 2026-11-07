/* Medius host: recovered update/SHA support. */
#include "../include/types.h"

/* Native entry: 0x4200f120. */
/* Original function-byte SHA-256:
 * 20d5b11ec0ccb2f5e3325194963150abfa2b7fbdd0ff0388ef89216de774916d. */
/* Ignore opaque context and select the next update partition from NULL.
 * Store that candidate even if NULL; NULL returns -1000. Begin OTA with the
 * requested size and the shared handle output. 0x1506 maps to -1001; 0x105,
 * 0x1501,0x101,0x102 log "begin refused" and map to -1002. These paths retain
 * previous staged/write-active state. For other results clear staged first:
 * success sets write_active1; failure logs and aborts the LIVE shared handle,
 * ignoring abort's result. Failure does not otherwise clear write_active.
 * No lock, handle initialization, old-session cleanup or activation occurs. */
int update_flash_begin(void *context,unsigned int image_size)
{
    (void)context;
    const EspPartition *candidate = esp_ota_get_next_update_partition(NULL);
    UPDATE_BACKEND->candidate_partition = candidate;
    if (candidate == NULL)
        return -1000;
    int result = esp_ota_begin(candidate,image_size,&UPDATE_BACKEND->ota_handle);
    if (result == 0x1506)
        return -1001;
    if (result == 0x105 || result == 0x1501 || (unsigned int)result - 0x101U <= 1U) {
        unsigned int stamp = esp_log_timestamp();
        esp_log_write(1,UPDATE_LOG_TAG,"E (%lu) %s: begin refused %d\n",stamp,UPDATE_LOG_TAG,result);
        return -1002;
    }
    UPDATE_BACKEND->staged_partition = NULL;
    if (result == 0)
        UPDATE_BACKEND->write_active = 1;
    else {
        unsigned int stamp = esp_log_timestamp();
        esp_log_write(1,UPDATE_LOG_TAG,"E (%lu) %s: begin %d\n",stamp,UPDATE_LOG_TAG,result);
        esp_ota_abort(UPDATE_BACKEND->ota_handle);
    }
    return result;
}

/* Native entry: 0x4200f0fc. */
/* Original function-byte SHA-256:
 * 1f43d745fdf239c09f2a7c65f8d852ba26010389a5964530329d076b13354abe. */
/* Ignore opaque context. If the write-active BYTE is nonzero, forward
 * the live OTA handle, payload and LOW16 length to esp_ota_write and return
 * its result. Otherwise return -1000. No payload/length validation, lock,
 * flag update, hash update or rollback occurs in this wrapper. */
int update_flash_write(void *context,const void *payload,unsigned short length)
{
    (void)context;
    if (UPDATE_BACKEND->write_active == 0)
        return -1000;
    return esp_ota_write(UPDATE_BACKEND->ota_handle,payload,length);
}

/* Native entry: 0x4200f0a4. */
/* Original function-byte SHA-256:
 * 0ffba295909a8606fd8c40cd2920bd7779f8281ac7755f8fb49b25f632843f2b. */
/* Ignore opaque context. Inactive returns -1000 without other effects.
 * Otherwise read the handle BEFORE clearing write_active, then call OTA end.
 * Success reloads the candidate partition and publishes it as staged. Failure
 * logs first, then clears staged. Return the original end result; neither
 * boot selection nor restart occurs. No lock or restoration of write_active. */
int update_flash_finish(void *context)
{
    (void)context;
    if (UPDATE_BACKEND->write_active == 0)
        return -1000;
    unsigned int handle = UPDATE_BACKEND->ota_handle;
    UPDATE_BACKEND->write_active = 0;
    int result = esp_ota_end(handle);
    if (result != 0) {
        unsigned int stamp = esp_log_timestamp();
        esp_log_write(1,UPDATE_LOG_TAG,"E (%lu) %s: end %d\n",stamp,UPDATE_LOG_TAG,result);
        UPDATE_BACKEND->staged_partition = NULL;
    }
    else {
        const EspPartition *candidate = UPDATE_BACKEND->candidate_partition;
        UPDATE_BACKEND->staged_partition = candidate;
    }
    return result;
}

/* Native entry: 0x4200f208. */
/* Original function-byte SHA-256:
 * 28971652a45233ad37a6e2643c2534ab4dc611d784fc95f842e18a3873d72ecb. */
/* Ignore opaque context. If writing, abort the live handle and THEN
 * clear write_active, ignoring the abort result. Snapshot hash-active BEFORE
 * clearing staged_partition; when that snapshot is nonzero, zeroize the hash
 * context and clear hash-active. Candidate partition and handle are retained.
 * No lock, return status, flash erase or boot-partition change is supplied. */
void update_flash_abort(void *context)
{
    (void)context;
    if (UPDATE_BACKEND->write_active != 0) {
        esp_ota_abort(UPDATE_BACKEND->ota_handle);
        UPDATE_BACKEND->write_active = 0;
    }
    unsigned char hash_active = UPDATE_BACKEND->hash_active;
    UPDATE_BACKEND->staged_partition = NULL;
    if (hash_active != 0) {
        mbedtls_sha256_free(&UPDATE_BACKEND->hash_context);
        UPDATE_BACKEND->hash_active = 0;
    }
}

/* Native entry: 0x4200f1dc. */
/* Original function-byte SHA-256:
 * 4f6377dd7452195ccc8ac04e5952189ae9e50bd98dbd5a6fe438e659a7358b18. */
/* Ignore opaque context. Zeroize an already-active context, then call
 * SHA init and starts(is224=0), ignoring starts' result; finally publish
 * hash-active1. Init and starts each clear the full 116-byte context, so that
 * duplicate clearing is intentional. No allocation or wrapper-level lock. */
void update_hash_reset(void *context)
{
    (void)context;
    if (UPDATE_BACKEND->hash_active != 0)
        mbedtls_sha256_free(&UPDATE_BACKEND->hash_context);
    mbedtls_sha256_init(&UPDATE_BACKEND->hash_context);
    mbedtls_sha256_starts(&UPDATE_BACKEND->hash_context,0);
    UPDATE_BACKEND->hash_active = 1;
}

/* Native entry: 0x4200f26c. */
/* Original function-byte SHA-256:
 * 46a3621453944e19c0b90561869138fdb68596f61009f997957a8de046b81b65. */
/* Ignore opaque context. If hash-active is nonzero, append payload with
 * LOW16 length to the shared SHA context and ignore the SHA update result.
 * Inactive is a silent no-op. No validation, flag update or wrapper lock. */
void update_hash_update(void *context,const void *payload,unsigned short length)
{
    (void)context;
    if (UPDATE_BACKEND->hash_active != 0)
        mbedtls_sha256_update(&UPDATE_BACKEND->hash_context,payload,length);
}

/* Native entry: 0x4200f240. */
/* Original function-byte SHA-256:
 * 97d8c0e6970178d651c9394765fa2c35205e570a7394e1e8ee5ff61822c775be. */
/* Zero all 32 output bytes BEFORE snapshotting hash-active. If active,
 * finish into that output, ignore its result, zeroize the SHA context and
 * clear hash-active. Return the ORIGINAL raw active BYTE, including any
 * noncanonical nonzero value. This reports prior activity, not SHA success.
 * Inactive leaves 32 zero bytes and returns0. No lock or output validation;
 * output aliasing backend state is not protected. Opaque context is ignored. */
unsigned char update_hash_digest(void *context,unsigned char output[32])
{
    (void)context;
    memset(output,0,32);
    unsigned char active = UPDATE_BACKEND->hash_active;
    if (active != 0) {
        mbedtls_sha256_finish(&UPDATE_BACKEND->hash_context,output);
        mbedtls_sha256_free(&UPDATE_BACKEND->hash_context);
        UPDATE_BACKEND->hash_active = 0;
    }
    return active;
}
