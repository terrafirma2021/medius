/* Medius device: recovered update/SHA support. */
#include "../include/types.h"

/* Native entry: 0x4200caec. */
/* Original function-byte SHA-256:
 * 6e00be7c14c7dbafc4c2f9bdf0af1a228f4f6c4c8cfb1995443a3b56e3aec38c. */
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

/* Native entry: 0x4200cac8. */
/* Original function-byte SHA-256:
 * 7ef6d9232224e4f33529d0fc2af2fa37df1a87dc31ddbd1d3b4a480465686c9f. */
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

/* Native entry: 0x4200ca70. */
/* Original function-byte SHA-256:
 * 25c25670f0ce285c1716a6c8dbcedef4e791848de6da70197a6aaaa1e28ac587. */
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

/* Native entry: 0x4200cbd4. */
/* Original function-byte SHA-256:
 * 225393fe50ed530194ba5c4c693afa39edb5d352c7b74392fa2031516ef68329. */
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

/* Native entry: 0x4200cba8. */
/* Original function-byte SHA-256:
 * 44798fa67717abcdf782d01c5bce88e0c7809fa48506fb3d72059ec85afb7329. */
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

/* Native entry: 0x4200cc38. */
/* Original function-byte SHA-256:
 * 5c65d7744fbd92f532b7e181be83e08554403b94baf931e56cf59846fdae14c6. */
/* Ignore opaque context. If hash-active is nonzero, append payload with
 * LOW16 length to the shared SHA context and ignore the SHA update result.
 * Inactive is a silent no-op. No validation, flag update or wrapper lock. */
void update_hash_update(void *context,const void *payload,unsigned short length)
{
    (void)context;
    if (UPDATE_BACKEND->hash_active != 0)
        mbedtls_sha256_update(&UPDATE_BACKEND->hash_context,payload,length);
}

/* Native entry: 0x4200cc0c. */
/* Original function-byte SHA-256:
 * 226b06fd506af97788828c61110c38fe183ab8ce28be4a2e87c6c2eb5e039f32. */
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
