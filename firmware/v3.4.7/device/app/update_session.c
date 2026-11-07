/* Medius v3.4.7 device: recovered application firmware-update session core. */

#include "../include/types.h"

/* reconstruction utilities: native abort tests BOTH state bytes together and
 * snapshots the optional callback once. Clearing uses one 16-bit store after
 * any callback. It leaves sizes, counters, digest and callback tables intact. */
static __inline__ __attribute__((always_inline)) void
update_session_abort_and_clear_state(UpdateSession *session)
{
    if (session->state.word != 0) {
        UpdateAbort abort_operation = session->storage->abort;
        if (abort_operation != NULL)
            abort_operation(session->backend_context);
    }
    session->state.word = 0;
}

/* Native entry: 0x4200c924. */
/* Original function-byte SHA-256:
 * 35bddb50433eb215cb9fefb320f110724301b5b0db9396ae52c038dace6c95b1. */
/* Zero all 64 bytes, then store storage operations, hash operations and
 * the shared backend context in that order. No table/pointer validation,
 * callback, allocation, hardware operation, lock or return value. This resets
 * an existing session without first invoking its abort callback. */
void update_session_initialize(UpdateSession *session,
    const UpdateStorageOps *storage,const UpdateHashOps *hash,void *backend_context)
{
    memset(session,0,sizeof(*session));
    session->storage = storage;
    session->hash = hash;
    session->backend_context = backend_context;
}

/* Native entry: 0x4200c93c. */
/* Original function-byte SHA-256:
 * 741be0f7b67ff771b54aa7d44c55e8e73be7b1472fa4b94cc3c1d2bcd6a1a94d. */
/* Snapshot active BYTE before clearing *detail. If active, return 0x10.
 * Require image size 1..0xf0000; otherwise detail=max and return 0x12. Call
 * storage.begin(context,size): -1000/-1001/-1002 map to 0x11/0x1b/0x1c,
 * retaining the previous staged byte. Other results clear staged first;
 * nonzero returns 0x14 with the raw backend error in detail, without abort.
 * Success resets the hash, copies exactly 32 expected-digest bytes, reads the
 * acknowledgement interval (0 means 16), then marks active, stores size,
 * clears written count and BOTH 16-bit counters in one word store. Return 1
 * with the effective acknowledgement interval in detail. No NULL/hash-copy
 * bounds checks, lock, alias protection or rollback of callback effects. */
unsigned int update_session_begin(UpdateSession *session,unsigned int image_size,
    const unsigned char *expected_sha256,unsigned int *detail)
{
    unsigned char active = session->state.bytes.active;
    *detail = 0;
    if (active != 0)
        return 0x10;
    if (image_size - 1U > 0xeffffU) {
        *detail = 0xf0000U;
        return 0x12;
    }
    /* Native callback loads: table, context, then operation. */
    const UpdateStorageOps *storage = session->storage;
    void *backend_context = session->backend_context;
    UpdateBegin begin_operation = storage->begin;
    int result = begin_operation(backend_context,image_size);
    if (result == -1000)
        return 0x11;
    if (result == -1001)
        return 0x1b;
    if (result == -1002)
        return 0x1c;
    session->state.bytes.staged = 0;
    if (result != 0) {
        *detail = (unsigned int)result;
        return 0x14;
    }
    const UpdateHashOps *hash = session->hash;
    backend_context = session->backend_context;
    void (*reset_operation)(void *) = hash->reset;
    reset_operation(backend_context);
    memcpy(session->expected_sha256,expected_sha256,32);
    unsigned int interval = session->acknowledgement_interval;
    if (interval == 0)
        interval = 16;
    session->state.bytes.active = 1;
    session->image_size = image_size;
    session->bytes_written = 0;
    session->sequence.word = 0;
    *detail = interval;
    return 1;
}

/* Native entry: 0x4200c9d0. */
/* Original function-byte SHA-256:
 * b375c7cf17eb7ce08a483fbd060d51f8de682ec09963b79951fc71ce59f1278e. */
/* Snapshot active BYTE before clearing detail. Inactive returns0x1a,
 * leaving any staged flag unchanged. If written!=total, report unsigned32
 * remaining bytes, abort/clear both state bytes and return0x1a. Otherwise ask
 * hash.digest for 32 bytes: zero result or memcmp mismatch aborts/clears and
 * returns0x15. Nonzero digest result is success, not an ESP-style zero code.
 * Call storage.finish after a matching digest, then clear BOTH state bytes
 * BEFORE interpreting its result. -1000 gives detail0/0x1a; other nonzero
 * gives raw error/0x16; zero sets staged1 and detail=live total,return3.
 * No image activation here. Sizes, counters and expected digest survive state
 * clearing. No lock, pointer validation, timing-safe comparison or rollback. */
unsigned int update_session_finish(UpdateSession *session,unsigned int *detail)
{
    unsigned char active = session->state.bytes.active;
    *detail = 0;
    if (active == 0)
        return 0x1a;
    unsigned int written = session->bytes_written;
    unsigned int total = session->image_size;
    if (written != total) {
        *detail = total - written;
        update_session_abort_and_clear_state(session);
        return 0x1a;
    }
    unsigned char digest[32];
    const UpdateHashOps *hash = session->hash;
    void *backend_context = session->backend_context;
    unsigned char (*digest_operation)(void *,unsigned char *) = hash->digest;
    unsigned char hash_active = digest_operation(backend_context,digest);
    if (hash_active == 0 || memcmp(digest,session->expected_sha256,32) != 0) {
        update_session_abort_and_clear_state(session);
        return 0x15;
    }
    const UpdateStorageOps *storage = session->storage;
    backend_context = session->backend_context;
    UpdateFinish finish_operation = storage->finish;
    int result = finish_operation(backend_context);
    session->state.word = 0;
    if (result == -1000) {
        *detail = 0;
        return 0x1a;
    }
    if (result != 0) {
        *detail = (unsigned int)result;
        return 0x16;
    }
    total = session->image_size;
    session->state.bytes.staged = 1;
    *detail = total;
    return 3;
}

/* Native entry: 0x42020fc4. */
/* Original function-byte SHA-256:
 * b6484c5391bf42e4cd16ed60e4649caf3215b1e2daef519b34578536d3074aaf. */
/* Snapshot active BYTE, then clear the acknowledgement output. Sequence
 * and length use only LOW16. Inactive: detail0/return0x1a. After any bytes have
 * been written, sequence==expected-1 (mod65536) is accepted as a duplicate:
 * return0,ack1,detail=expected WITHOUT checking length, payload or its digest.
 * Other sequence mismatch aborts with detail=expected/return0x13.
 *
 * New chunks require length1..504; malformed length aborts,detail504/0x1a.
 * The unsigned32 written+length sum is compared with total size; no separate
 * wrap check. Oversize aborts,detail=total/0x12. storage.write -1000 aborts with
 * detail0/0x1a; other failures abort with raw error/0x14. Successful storage
 * write is followed by hash.update with ignored result. Reload next-sequence,
 * pending-ack count, written total and interval, in that order; increment with
 * native 16/32-bit wrapping, store written/sequence/pending in that order.
 * Interval0 means16. Reaching it resets pending and emits ack; exact total
 * completion also emits ack. Detail is the new next sequence, return0.
 * No per-chunk comparison, lock, NULL checks, callback rollback or byte copy. */
unsigned int update_session_write(UpdateSession *session,unsigned int sequence,
    const void *payload,unsigned int length,unsigned int *detail,unsigned char *acknowledge)
{
    unsigned char active = session->state.bytes.active;
    *acknowledge = 0;
    unsigned short chunk_sequence = (unsigned short)sequence;
    unsigned short chunk_length = (unsigned short)length;
    if (active == 0) {
        *detail = 0;
        return 0x1a;
    }
    unsigned int written = session->bytes_written;
    unsigned short expected = session->sequence.fields.next;
    if (written != 0 && (unsigned short)(expected - 1U) == chunk_sequence) {
        *detail = expected;
        *acknowledge = 1;
        return 0;
    }
    if (chunk_sequence != expected) {
        *detail = expected;
        update_session_abort_and_clear_state(session);
        return 0x13;
    }
    if ((unsigned short)(chunk_length - 1U) >= 504U) {
        *detail = 504;
        update_session_abort_and_clear_state(session);
        return 0x1a;
    }
    unsigned int total = session->image_size;
    if (total < written + (unsigned int)chunk_length) {
        *detail = total;
        update_session_abort_and_clear_state(session);
        return 0x12;
    }
    const UpdateStorageOps *storage = session->storage;
    void *backend_context = session->backend_context;
    UpdateWrite write_operation = storage->write;
    int result = write_operation(backend_context,payload,chunk_length);
    if (result == -1000) {
        *detail = 0;
        update_session_abort_and_clear_state(session);
        return 0x1a;
    }
    if (result != 0) {
        *detail = (unsigned int)result;
        update_session_abort_and_clear_state(session);
        return 0x14;
    }
    const UpdateHashOps *hash = session->hash;
    backend_context = session->backend_context;
    void (*update_operation)(void *,const void *,unsigned short) = hash->update;
    update_operation(backend_context,payload,chunk_length);
    unsigned short next = session->sequence.fields.next;
    unsigned short pending = session->sequence.fields.pending_acknowledgement;
    written = session->bytes_written;
    unsigned int interval = session->acknowledgement_interval;
    next = (unsigned short)(next + 1U);
    pending = (unsigned short)(pending + 1U);
    written += chunk_length;
    session->bytes_written = written;
    session->sequence.fields.next = next;
    session->sequence.fields.pending_acknowledgement = pending;
    if (interval == 0)
        interval = 16;
    if (pending >= interval) {
        session->sequence.fields.pending_acknowledgement = 0;
        *acknowledge = 1;
    }
    if (written == session->image_size)
        *acknowledge = 1;
    *detail = next;
    return 0;
}

/* Native entry: 0x420210f0. */
/* Original function-byte SHA-256:
 * 6ec7e69328ff84e47b1b696ef332e062545a7eff2fa54b1532761bef428abecc. */
/* If EITHER active/staged byte is nonzero and storage.abort is present,
 * call it once with the live backend context. Then clear both state bytes in
 * one 16-bit store, even if no callback ran. No other session field is reset;
 * no lock, status, pointer validation or callback-error handling is supplied. */
void update_session_abort(UpdateSession *session)
{
    update_session_abort_and_clear_state(session);
}

/* Native entry: 0x4202110c. */
/* Original function-byte SHA-256:
 * beb71ab790f16619bc72b609fabfa9f232a540e91963fcd1a7dfe43e9a16b34c. */
/* Return the staged BYTE verbatim, without boolean normalization,
 * locking, validation or backend inspection. */
unsigned char update_session_is_staged(const UpdateSession *session)
{
    return session->state.bytes.staged;
}

/* Native entry: 0x42021114. */
/* Original function-byte SHA-256:
 * d87dd8169f446f3904abe453b5331acd7270340b2e45308ef1849b341fefce1a. */
/* Return the active BYTE verbatim, without boolean normalization,
 * locking, validation or backend inspection. */
unsigned char update_session_is_active(const UpdateSession *session)
{
    return session->state.bytes.active;
}

/* Native entry: 0x4200ccec. */
/* Original function-byte SHA-256:
 * 33a2a51483011366629d7f9af558145d4b5c398bdc6bf3091d961d150c8f75f7. */
/* Return the pinned four-entry storage table (begin/write/finish/abort).
 * The functions use MCU-local OTA globals; no table copy or initialization. */
const UpdateStorageOps *update_storage_operations(void)
{
    return UPDATE_STORAGE_OPERATIONS;
}

/* Native entry: 0x4200ccf4. */
/* Original function-byte SHA-256:
 * 81049504c967295fc28d86b0377455531cf970b8bcaf44c4a7bc6571dbace2a5. */
/* Return the pinned three-entry hash table (reset/update/digest).
 * Digest returns its previous hash-active byte; reset/update results are not
 * consumed. No table copy, initialization or validation occurs here. */
const UpdateHashOps *update_hash_operations(void)
{
    return UPDATE_HASH_OPERATIONS;
}

/* Native entry: 0x4202111c. */
/* Original function-byte SHA-256:
 * 92c9598ac7519d458b9e367d0d7b28064c9bff38bae50b088825d1dda27f16a4. */
/* Return NULL. These firmware tables use their MCU-local globals and
 * ignore the common opaque-context argument; no allocation or state read. */
void *update_backend_context(void)
{
    return NULL;
}
