/* Medius v3.4.7 device — descriptor patch commands and persistence. */
#include "../include/types.h"

/* Native entry: 0x420384a4. */
/* Original function-byte SHA-256:
 * 00fc8e8290ed5f4208897871af1beec15a947ff47533b47d0fe743640d0c7c83. */
/*
 * Store/remove a keyed descriptor patch for kind0..4. If a rewrite mutex exists,
 * take indefinitely and ignore its result. Require identity-ready then cache-
 * loaded BYTEs. Without an entry mutex, failed readiness returns directly;
 * locked failure releases a freshly sampled current handle.
 *
 * MEMW/read identity first HALFWORD at9dce, then MEMW/second at9dcc; cache table
 * generation BYTE and invoke the separate mutation helper. Unchanged generation
 * only releases the current mutex. A change clears refused BYTE, writes count
 * to shared save-buffer BYTE0, then serializes seven header bytes plus payload
 * per ten-byte record, trusting pool offsets and the live count. Header stores
 * retain native order. The payload-length HALFWORD is reread after memcpy when
 * advancing the wrapping16 cursor; count is then reread and index wraps8.
 *
 * Reject serialization past1137 by passing the nonnull buffer with length0 to
 * persistence. An empty table instead passes NULL/0. Unlock before saving the
 * captured identity pair; discard save status. No apply/rebuild, cache-loaded
 * update, rollback, source-pointer validation or persistence mutex is added.
 * Shared save buffer and helper mutation require external lifetime/serialization.
 */
void descriptor_patch_store(unsigned char kind,unsigned char configuration,
    unsigned char index,unsigned short offset,const void *bytes,unsigned short length)
{
    if (kind > 4U)
        return;
    RtosQueue *mutex = REWRITE_MUTEX;
    if (mutex == NULL) {
        if (MEDIUS_CLONE_PATCH_IDENTITY_READY == 0)
            return;
        if (MEDIUS_DESCRIPTOR_PATCH_CACHE_LOADED == 0)
            return;
    } else {
        xQueueSemaphoreTake(mutex,0xffffffffU);
        if (MEDIUS_CLONE_PATCH_IDENTITY_READY == 0 || MEDIUS_DESCRIPTOR_PATCH_CACHE_LOADED == 0)
            goto unlock;
    }
    memw();
    unsigned short first = INPUT_REQUESTED_IDENTITY[1];
    memw();
    unsigned short second = INPUT_REQUESTED_IDENTITY[0];
    volatile DescriptorPatchTable *table = MEDIUS_DESCRIPTOR_PATCH_STORED_RW;
    unsigned char old_generation = table->generation;
    medius_descriptor_patch_mutate(kind,configuration,index,offset,bytes,length);
    if (table->generation == old_generation)
        goto unlock;
    unsigned int count = table->count;
    unsigned char *buffer = MEDIUS_DESCRIPTOR_PATCH_SAVE_BUFFER;
    CLONE_PATCH_REFUSED = 0;
    *(volatile unsigned char *)buffer = (unsigned char)count;
    unsigned int cursor = 1;
    if (count == 0) {
        buffer = NULL;
        cursor = 0;
    } else {
        unsigned char record_index = 0;
        volatile DescriptorPatchRecord *record = table->records;
        do {
            unsigned int payload_length = record->length;
            if (cursor + 7U + payload_length > 1137U) {
                cursor = 0;
                break;
            }
            volatile unsigned char *wire = buffer;
            unsigned char record_kind = record->kind;
            wire[cursor] = record_kind;
            unsigned char record_configuration = record->configuration;
            unsigned char descriptor_index = record->descriptor_index;
            wire[(unsigned short)(cursor + 1U)] = record_configuration;
            wire[(unsigned short)(cursor + 2U)] = descriptor_index;
            unsigned int patch_offset = record->offset;
            record_index = (unsigned char)(record_index + 1U);
            wire[(unsigned short)(cursor + 3U)] = (unsigned char)patch_offset;
            wire[(unsigned short)(cursor + 4U)] = (unsigned char)(patch_offset >> 8);
            wire[(unsigned short)(cursor + 5U)] = (unsigned char)payload_length;
            unsigned int pool_offset = record->payload_offset;
            wire[(unsigned short)(cursor + 6U)] = (unsigned char)(payload_length >> 8);
            memcpy(buffer + cursor + 7U,(const void *)(table->payload + pool_offset),payload_length);
            unsigned int next_length = record->length;
            unsigned int current_count = table->count;
            cursor = (unsigned short)((unsigned short)(cursor + 7U) + next_length);
            ++record;
            if (record_index >= current_count)
                break;
        } while (1);
    }
    mutex = REWRITE_MUTEX;
    if (mutex != NULL)
        xQueueGenericSend(mutex,NULL,0,0);
    profile_store_patches(first,second,buffer,(unsigned short)cursor);
    return;
unlock:
    mutex = REWRITE_MUTEX;
    if (mutex != NULL)
        xQueueGenericSend(mutex,NULL,0,0);
}

/* Native entry: 0x42038660. */
/* Original function-byte SHA-256:
 * 4339b4514975da387606e0fe6293603f4850b6fce1ee20915cb1591bc48074ee. */
/*
 * Ask the reviewed stored-versus-served comparison whether re-cloning is needed;
 * only a nonzero result MEMW/sets refresh BYTE1. With no entry mutex, call and
 * return without an unlock-handle reload. Otherwise take indefinitely, ignore
 * take status, call comparison, then cache the current mutex BEFORE any refresh
 * store and give that cached nonnull handle. No synchronous application, USB
 * detach, persistence, rollback or readiness validation occurs here.
 */
void descriptor_patch_apply(void)
{
    RtosQueue *mutex = REWRITE_MUTEX;
    if (mutex == NULL) {
        if (descriptor_patches_need_refresh() != 0) {
            memw();
            IMPERFECT_PATCH_REFRESH = 1;
        }
        return;
    }
    xQueueSemaphoreTake(mutex,0xffffffffU);
    unsigned int changed = descriptor_patches_need_refresh();
    mutex = REWRITE_MUTEX;
    if (changed != 0) {
        memw();
        IMPERFECT_PATCH_REFRESH = 1;
    }
    if (mutex != NULL)
        xQueueGenericSend(mutex,NULL,0,0);
}

/* Native entry: 0x420386ac. */
/* Original function-byte SHA-256:
 * 7faf8a69f78ec2c707f8b082d4337aeac72c0b96e38a6918783bc6e565eef2bd. */
/*
 * Optionally take the rewrite mutex indefinitely, ignoring take status. Cache
 * generation BYTE then zero the entire1190-byte stored patch table. Read the
 * persistence-marker BYTE, then MEMW/first identity HALFWORD and MEMW/second.
 * Write old-generation+1 modulo256 and refused0 BYTEs without another fence.
 * If stored/served comparison differs, MEMW/set refresh1. Release a fresh mutex.
 *
 * A zero saved persistence marker returns. Otherwise remove persistent patches
 * for the captured identity with four arguments(first,second,NULL,0). On save
 * failure return; on success optionally reacquire the current mutex, MEMW/check
 * first identity then MEMW/check second, and mark cache-loaded1 only on both
 * matches. A first mismatch without an entry mutex returns directly; a locked
 * mismatch releases a fresh current handle. No rollback, generation/readiness
 * revalidation or hardware re-cloning occurs here. Return no value.
 */
void descriptor_patch_clear(void)
{
    RtosQueue *mutex = REWRITE_MUTEX;
    if (mutex != NULL)
        xQueueSemaphoreTake(mutex,0xffffffffU);
    volatile DescriptorPatchTable *table = MEDIUS_DESCRIPTOR_PATCH_STORED_RW;
    unsigned char old_generation = table->generation;
    memset((void *)table,0,1190);
    unsigned char persistence_marker = MEDIUS_DESCRIPTOR_PATCH_PERSISTENCE_MARKER;
    memw();
    unsigned short first = INPUT_REQUESTED_IDENTITY[1];
    memw();
    unsigned short second = INPUT_REQUESTED_IDENTITY[0];
    table->generation = (unsigned char)(old_generation + 1U);
    CLONE_PATCH_REFUSED = 0;
    if (descriptor_patches_need_refresh() != 0) {
        memw();
        IMPERFECT_PATCH_REFRESH = 1;
    }
    mutex = REWRITE_MUTEX;
    if (mutex != NULL)
        xQueueGenericSend(mutex,NULL,0,0);
    if (persistence_marker == 0 || profile_store_patches(first,second,NULL,0) == 0)
        return;
    mutex = REWRITE_MUTEX;
    if (mutex == NULL) {
        memw();
        if (INPUT_REQUESTED_IDENTITY[1] != first)
            return;
    } else {
        xQueueSemaphoreTake(mutex,0xffffffffU);
        memw();
        if (INPUT_REQUESTED_IDENTITY[1] != first)
            goto unlock;
    }
    memw();
    if (INPUT_REQUESTED_IDENTITY[0] == second)
        MEDIUS_DESCRIPTOR_PATCH_CACHE_LOADED = 1;
unlock:
    mutex = REWRITE_MUTEX;
    if (mutex != NULL)
        xQueueGenericSend(mutex,NULL,0,0);
}
