/* Medius host: recovered update/SHA support. */
#include "../include/types.h"

/* Native entry: 0x42014f70. */
/* Original function-byte SHA-256:
 * 5650a8e4c43f190633217757a3429d9b38c167e33eaaa7a304aae5e1d4a4a696. */
/* Clear exactly 116 bytes of the supplied SHA context. No NULL check,
 * hardware access, lock, allocation or returned status. */
void mbedtls_sha256_init(Sha256Context *context)
{
    memset(context,0,sizeof(*context));
}

/* Native entry: 0x42014f84. */
/* Original function-byte SHA-256:
 * 1af433dd998dbdd89641b9c71b66e7e396bc4e393c727b3ea51812a937289029. */
/* Clear all 116 bytes, then select hardware SHA mode2 (SHA-256) if
 * is224==0, otherwise mode1 (SHA-224). Every nonzero word selects SHA-224;
 * no canonical-boolean validation. Return0 unconditionally. No block hashing,
 * hardware register write, NULL check or hardware-resource acquisition. */
int mbedtls_sha256_starts(Sha256Context *context,int is224)
{
    memset(context,0,sizeof(*context));
    context->mode = is224 == 0 ? 2U : 1U;
    return 0;
}

/* Native entry: 0x4201ebe0. */
/* Original function-byte SHA-256:
 * d96d08ce24fed657f36b67bf26a4eea42b894f0af19918f2c9630bd14abd9eb6. */
/* NULL is a no-op. Otherwise overwrite exactly 116 consecutive bytes
 * with zero, using a MEMW BEFORE EACH byte store so the wipe is retained.
 * This clears caller-owned storage; it does not free heap memory, disable a
 * hardware engine, acquire/release a lock or change an external active flag. */
void mbedtls_sha256_free(Sha256Context *context)
{
    if (context == NULL)
        return;
    volatile unsigned char *bytes = (volatile unsigned char *)context;
    for (unsigned int index = 0; index < sizeof(*context); ++index) {
        memw();
        bytes[index] = 0;
    }
}

/* Native entry: 0x42014fa4. */
/* Original function-byte SHA-256:
 * a62113fd0c1750a46710bebaaedcda117b77cce5c1e3ae0e62b1ed0b427b374d. */
/* Append bytes to this116-byte hardware/resumable SHA-224/256 context.
 * Length0 returns0 before accessing either pointer. Otherwise advance the
 * low byte-count WORD first, then increment the high WORD on carry, both with
 *32-bit wrap. Complete any pending64-byte buffer before submitting it and
 * the remaining whole64-byte input blocks to the shared backend. A short tail
 * only copies into the context; it does not acquire hardware.
 *
 * Acquire/reset hardware when at least one full block is available. Engine
 * state0 sets first_block1 then state1. State1 samples mode, clears first_block,
 * restores saved digest state and freshly reads first_block again. Other raw
 * state values retain both fields and use first_block!=0. Sample mode again
 * for the backend call. On error, release hardware and return the status:
 * counts, completed buffer and engine-state changes are NOT rolled back, and
 * no digest save or remaining-tail copy occurs. On success, sample mode again,
 * save digest state, release hardware, then copy the remaining tail. A positive
 * post-fill length that was an exact block multiple still issues memcpy(...,0).
 *
 * Caller supplies live context and readable input; no NULL/length/overlap check,
 * context-wide mutex, allocation, software compression or final padding here.
 * The separate backend chooses block/DMA processing and has its own review.
 */
int mbedtls_sha256_update(Sha256Context *context,const unsigned char *payload,size_t length)
{
    if (length == 0)
        return 0;
    volatile Sha256Context *observed = context;
    unsigned int old_low = observed->total[0];
    unsigned int buffered = old_low & 63U;
    unsigned int new_low = old_low + length;
    observed->total[0] = new_low;
    if (new_low < length)
        observed->total[1] = observed->total[1] + 1U;
    unsigned int buffered_block_length = 0;
    unsigned int fill = 64U - buffered;
    if (buffered != 0 && length >= fill) {
        memcpy(context->buffer + buffered,payload,fill);
        payload += fill;
        length -= fill;
        buffered = 0;
        buffered_block_length = 64;
    }
    unsigned int whole_length = length & ~63U;
    if (whole_length != 0 || buffered_block_length != 0) {
        esp_sha_acquire_hardware();
        unsigned int engine_state = observed->engine_state;
        unsigned char first;
        if (engine_state == 0) {
            observed->first_block = 1;
            observed->engine_state = 1;
            first = 1;
        } else if (engine_state == 1) {
            unsigned int mode = observed->mode;
            observed->first_block = 0;
            esp_sha_write_digest_state(mode,context->state);
            first = observed->first_block != 0;
        } else {
            first = observed->first_block != 0;
        }
        int status = esp_sha_dma(observed->mode,payload,whole_length,
            context->buffer,buffered_block_length,first);
        if (status != 0) {
            esp_sha_release_hardware();
            return status;
        }
        esp_sha_read_digest_state(observed->mode,context->state);
        esp_sha_release_hardware();
        if (length == 0)
            return 0;
        payload += whole_length;
        length -= whole_length;
    }
    memcpy(context->buffer + buffered,payload,length);
    return 0;
}

/* Native entry: 0x42015090. */
/* Original function-byte SHA-256:
 * 67c4acf8e0f55d0b70610ce30e517c3bd6906c9c20a2a8a17c1a77f579daa10c. */
/* Finalize the current SHA-224/256 stream in place. Read total LOW then HIGH
 * WORDs and encode the ORIGINAL bit length modulo2^64 in big-endian stack
 * storage (low encoded WORD at+4, then high at+0). Choose padding56-last when
 * last=low&63 is below56, otherwise120-last; the image's64-byte padding begins
 * with0x80 and all remaining bytes are zero. Update with that padding first,
 * then the8-byte encoded length. Stop at either nonzero status without writing
 * output. Context totals/state already changed by either call are retained.
 *
 * After both succeed, freshly read mode: exact1 copies28 raw state bytes,
 * every other value copies32. Output tail bytes for SHA-224 remain untouched.
 * Return the update status0. No output/context NULL check, extra byte swapping
 * of the saved digest, reset, zeroization, hardware lock across both updates
 * or repeated-finalization guard. Caller provides adequate live buffers.
 */
int mbedtls_sha256_finish(Sha256Context *context,unsigned char output[32])
{
    volatile Sha256Context *observed = context;
    unsigned int low = observed->total[0];
    unsigned int high = observed->total[1];
    unsigned int bit_low = low << 3;
    unsigned int bit_high = (high << 3) | (low >> 29);
    unsigned int encoded_length[2];
    ((volatile unsigned int *)encoded_length)[1] = __builtin_bswap32(bit_low);
    ((volatile unsigned int *)encoded_length)[0] = __builtin_bswap32(bit_high);
    unsigned int last = low & 63U;
    unsigned int padding_length = last < 56U ? 56U - last : 120U - last;
    int status = mbedtls_sha256_update(context,SHA256_PADDING,padding_length);
    if (status != 0)
        return status;
    status = mbedtls_sha256_update(context,(const unsigned char *)encoded_length,8);
    if (status == 0)
        memcpy(output,context->state,observed->mode == SHA_MODE_SHA224 ? 28U : 32U);
    return status;
}
