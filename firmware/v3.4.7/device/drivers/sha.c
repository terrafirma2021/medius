/* Medius v3.4.7 device — resumable SHA hardware access and HAL operations.
 * Names/behavior checked against ESP-IDF v5.4.4 SHA DMA port and sha_hal.c.
 */
#include "../include/types.h"

/* SHA reconstruction utilities: these native-inlined operations are not
 * additional recovered functions. Read every busy WORD after a MEMW.
 */
static __attribute__((always_inline)) inline void sha_wait_idle_inline(void)
{
    do {
        memw();
    } while (SHA_REGISTERS->busy != 0);
}
static __attribute__((always_inline)) inline unsigned int sha_state_words(unsigned int mode)
{
    if (mode < 3U)
        return mode == 0 ? 5U : 8U;
    return mode - 3U <= 4U ? 16U : 0U;
}

/* Native entry: 0x420173b4. */
/* Original function-byte SHA-256:
 * e092ce7ceeda24a3cb8b58543fb6318922a5bee1eae97908264954c26a863ebf. */
/* Forward mode and caller-owned saved-state pointer unchanged to the HAL
 * write helper. No idle wait, lock, size check, byte conversion or status in
 * this wrapper. The HAL writes5/8/16 WORDs for modes0/1..2/3..7 respectively;
 * unsupported modes are a no-op there. Caller must own the hardware resource.
 */
void esp_sha_write_digest_state(unsigned int mode,const void *state)
{
    sha_hal_write_digest(mode,state);
}

/* Native entry: 0x420173c4. */
/* Original function-byte SHA-256:
 * d4f9d20d77832c648617bdabcbb3d70b6959892739d47091c22094ef6a6ba172. */
/* Forward mode and writable saved-state pointer unchanged to the HAL read
 * helper. It waits for idle, copies the selected5/8/16 WORDs and aborts on an
 * all-zero digest, including the unsupported-mode/zero-length case. No local
 * lock, conversion, error status, allocation or extra hardware action here.
 */
void esp_sha_read_digest_state(unsigned int mode,void *state)
{
    sha_hal_read_digest(mode,state);
}

/* Native entry: 0x420173d4. */
/* Original function-byte SHA-256:
 * 86afbf7c083e75862328b572d68fa1ed0347173b957cf45ffcd2a1e907ba4fec. */
/* Acquire the shared SHA/AES lock, then enter the peripheral-RCC critical
 * section. Through FIVE separate MEMW/read-MEMW/write pairs: enable SHA clock
 * bit2, assert SHA reset bit2, clear SHA reset bit2, clear DS reset bit4, then
 * clear HMAC reset bit5. Exit only the RCC section; retain the shared lock
 * until release_hardware. No DMA clock/reset manipulation, busy wait, clock
 * reference-count update, saved-context restoration or allocation in this body.
 * Resetting the engine means callers must restore prior digest state themselves.
 */
void esp_sha_acquire_hardware(void)
{
    esp_crypto_sha_aes_lock_acquire();
    periph_rcc_enter();
    SystemPeripheralRegistersPrefix *system = SYSTEM_PERIPHERAL_REGISTERS;
    memw();
    unsigned int value = system->clock_enable1;
    memw();
    system->clock_enable1 = value | 4U;
    memw();
    value = system->reset_enable1;
    memw();
    system->reset_enable1 = value | 4U;
    memw();
    value = system->reset_enable1;
    memw();
    system->reset_enable1 = value & ~4U;
    memw();
    value = system->reset_enable1;
    memw();
    system->reset_enable1 = value & ~0x10U;
    memw();
    value = system->reset_enable1;
    memw();
    system->reset_enable1 = value & ~0x20U;
    periph_rcc_exit();
}

/* Native entry: 0x42017438. */
/* Original function-byte SHA-256:
 * 342dc9a35af707605abd2042dedec5134e0b8256cd9c7354560fc89fe8088ff5. */
/* Enter peripheral RCC, MEMW/read clock-enable1 and MEMW/write it with SHA
 * bit2 cleared, exit RCC, THEN release the shared SHA/AES lock. No busy wait,
 * digest save, DMA teardown, reset assertion or reference-count update. Caller
 * must complete required processing/readback before this gate is disabled.
 */
void esp_sha_release_hardware(void)
{
    periph_rcc_enter();
    memw();
    unsigned int value = SYSTEM_PERIPHERAL_REGISTERS->clock_enable1;
    memw();
    SYSTEM_PERIPHERAL_REGISTERS->clock_enable1 = value & ~4U;
    periph_rcc_exit();
    esp_crypto_sha_aes_lock_release();
}

/* Native entry: 0x42017a14. */
/* Original function-byte SHA-256:
 * 52c2adef39fa1a0d80210264d4322a51580d407e018f49682843cccc7c4e9312. */
/* Wait on fresh MEMW/busy-WORD reads until0, then transfer input WORDs to
 * SHA text registers. Each input WORD is read BEFORE MEMW/the corresponding
 * MMIO write. If raw word_count is nonzero, the wrapped native loop count is
 * ((word_count*4-4)>>2)+1; it is not clamped to the32-WORD text window. Zero
 * count skips input entirely. Address arithmetic below wraps as32-bit native.
 * Then MEMW/write raw mode, and MEMW/write1 to START for any nonzero low BYTE
 * first_block, otherwise CONTINUE. Return immediately after triggering; no
 * completion wait, lock, mode/pointer/bounds validation, copy allocation or
 * timeout. Caller supplies aligned readable WORDs and owns the SHA engine.
 */
void sha_hal_hash_block(unsigned int mode,const void *input,unsigned int word_count,unsigned char first_block)
{
    sha_wait_idle_inline();
    if (word_count != 0) {
        unsigned int count = ((word_count * 4U - 4U) >> 2) + 1U;
        for (unsigned int index = 0; index < count; ++index) {
            unsigned int value = *(const volatile unsigned int *)((unsigned int)input + index * 4U);
            memw();
            *(volatile unsigned int *)(0x6003b080U + index * 4U) = value;
        }
    }
    memw();
    SHA_REGISTERS->mode = mode;
    memw();
    if (first_block != 0)
        SHA_REGISTERS->start = 1;
    else
        SHA_REGISTERS->continue_block = 1;
}

/* Native entry: 0x42017a70. */
/* Original function-byte SHA-256:
 * d092d523dc8ec5410ab13ed4d872900f82dbee989eefab95a51dfe572eb37d2b. */
/* Wait until the full busy WORD is0 through repeated MEMW/read pairs.
 * MEMW/write raw block_count, MEMW/write raw mode, then MEMW/write1 to DMA_START
 * for a nonzero first_block BYTE, otherwise DMA_CONTINUE. Zero blocks still
 * trigger. No descriptor setup, alignment/range/type validation, allocation,
 * lock, timeout or wait for the triggered operation to finish occurs here.
 */
void sha_hal_hash_dma(unsigned int mode,unsigned int block_count,unsigned char first_block)
{
    sha_wait_idle_inline();
    memw();
    SHA_REGISTERS->block_count = block_count;
    memw();
    SHA_REGISTERS->mode = mode;
    memw();
    if (first_block != 0)
        SHA_REGISTERS->dma_start = 1;
    else
        SHA_REGISTERS->dma_continue = 1;
}

/* Native entry: 0x42017aac. */
/* Original function-byte SHA-256:
 * a49145ae1e619a2df731f581a37aa120b24d25e7a5961064894f72938c7c24cb. */
/* Poll the FULL busy WORD with a fresh MEMW/read every iteration until0.
 * No delay, timeout, scheduler yield, lock, other status check or return value.
 * A stuck engine can keep this call busy-waiting indefinitely.
 */
void sha_hal_wait_idle(void)
{
    sha_wait_idle_inline();
}

/* Native entry: 0x42017abc. */
/* Original function-byte SHA-256:
 * c94b95e8d2a4e384717aae04978c3c356dc221b796b447f3346bf5404e039fda. */
/* Read digest state after waiting for busy0. Mode0 selects5 WORDs,1/2 select8,
 *3..7 select16; other raw modes select0. Pass the state pointer, H-register base
 * and count to the DPORT WORD-copy helper. Scan the copied WORDs in order and
 * return at the first nonzero value; if every WORD is zero, abort. Unsupported
 * modes therefore still poll, call copy with count0, then abort. This is the
 * SDK all-zero fault-injection guard, not a digest-correctness verification.
 * No lock, mode programming, byte swap, NULL/capacity check or error status.
 */
void sha_hal_read_digest(unsigned int mode,void *state)
{
    unsigned int words = sha_state_words(mode);
    sha_wait_idle_inline();
    esp_dport_access_read_buffer(state,0x6003b040U,words);
    const volatile unsigned int *digest = state;
    for (unsigned int index = 0; index < words; ++index) {
        if (digest[index] != 0)
            return;
    }
    abort();
}

/* Native entry: 0x42017b18. */
/* Original function-byte SHA-256:
 * 76b22b40d291853b895528630302fa28e62caede159e8bdcff9c240e38cb05be. */
/* Restore5 digest WORDs for SHA1 mode0,8 for modes1/2,16 for modes3..7.
 * Unsupported raw modes return before touching the pointer or registers.
 * For each WORD, read caller storage, then MEMW/write the same value to the
 * next H register. No idle polling, mode/start write, byte swap, all-zero check,
 * lock or validation. Caller must own an idle engine and enough aligned state.
 */
void sha_hal_write_digest(unsigned int mode,const void *state)
{
    unsigned int words = sha_state_words(mode);
    for (unsigned int index = 0; index < words; ++index) {
        unsigned int value = ((const volatile unsigned int *)state)[index];
        memw();
        SHA_REGISTERS->digest[index] = value;
    }
}

/* Native entry: 0x42011684. */
/* Original function-byte SHA-256:
 * d22be290e6f46dcb63062056fe00b3da206bb8b2b54d7efb3d246fb58254b1fc. */
/* Acquire the shared SHA/AES Newlib lock SLOT at3fcd868c through ordinary
 * _lock_acquire. No arguments or local status, validation, hardware access,
 * explicit MEMW or recursive acquisition. Lower startup/context rules apply.
 */
void esp_crypto_sha_aes_lock_acquire(void)
{
    _lock_acquire(CRYPTO_SHA_AES_LOCK);
}

/* Native entry: 0x42011694. */
/* Original function-byte SHA-256:
 * d0d3023950a8612f350abb0b8148064b9831794ed44f5c56bb2ccf776fedb88f. */
/* Release the SAME shared SHA/AES Newlib lock slot through ordinary
 * _lock_release. No local state write, status, hardware gate or explicit MEMW.
 * Lower scheduler-not-started bypass and context-specific give rules apply.
 */
void esp_crypto_sha_aes_lock_release(void)
{
    _lock_release(CRYPTO_SHA_AES_LOCK);
}

/* Native entry: 0x42021418. */
/* Original function-byte SHA-256:
 * 268daf1c78cc5fb1ff78505970f8ea98f0f2986dc3a252083bdc59c050a91e66. */
/* Copy DPORT/MMIO WORDs to caller storage. Zero count returns without touching
 * either address. For nonzero raw count, preserve native wrapped loop length
 * ((word_count*4-4)>>2)+1 and32-bit source/destination address progression.
 * Each iteration performs MEMW, one source WORD read, then one destination WORD
 * write; no separate store fence, range/alignment/NULL check, lock or overlap
 * repair. Copy proceeds forward. No returned pointer or status.
 */
void esp_dport_access_read_buffer(unsigned int *destination,unsigned int source_address,unsigned int word_count)
{
    if (word_count == 0)
        return;
    unsigned int count = ((word_count * 4U - 4U) >> 2) + 1U;
    for (unsigned int index = 0; index < count; ++index) {
        memw();
        unsigned int value = *(const volatile unsigned int *)(source_address + index * 4U);
        *(volatile unsigned int *)((unsigned int)destination + index * 4U) = value;
    }
}

/* Native entry: 0x42017464. */
/* Original function-byte SHA-256:
 * 3091797c672b85eb79be41fc1348daaf23744f158422e51a60dfdf4430c1b75a. */
/* Hash full SHA blocks through registers or the shared GDMA channels.
 * Modes0..2 use64 bytes; modes3..7 use128. Reject a prefix longer than
 * one block, but do NOT require either length to be a block multiple.
 * The input external-DMA predicate is called even for length0. Its raw BYTE
 * is not normalized: fallback tests bit0 of (external | internal) ^ 1.
 * Prefix bounce selection instead tests that expression's full low BYTE.
 * With a
 * nonempty non-DMA input, the register fallback hashes one FULL prefix block
 * whenever buffer_length!=0, then floor(input_length/block_size) input blocks.
 * Thus a short prefix still requires a readable full block. Trailing input
 * bytes are ignored; the final register-triggered block is not waited for here.
 * Unsupported mode in that fallback calls the native assertion with four0s.
 *
 * On the DMA path, probe both pointers for external RAM, including length0,
 * and request cache writeback with flags6, ignoring its status. An incapable
 * nonempty prefix is copied to an exact-size 8BIT|DMA|INTERNAL allocation.
 * Input is split at3968 bytes; the prefix accompanies only the first chunk.
 * Preserve the native32-bit input_length+3967 wrap: a positive input whose
 * sum becomes smaller than3968 performs no DMA and returns0 after cleanup.
 * Empty input otherwise submits once, even with a NULL descriptor head.
 *
 * Every chunk clears input descriptor before prefix descriptor, packs raw
 * size/length/owner/EOF fields, starts GDMA, triggers SHA, then waits for idle.
 * Return0 on completion; allocation, unsupported DMA mode and GDMA-start
 * errors log and return-1. Free the bounce pointer (including NULL) on every
 * DMA cleanup path. No descriptor/channel release, state save, implicit
 * padding, caller-length repair or lock acquisition here. The caller must
 * serialize access to the shared channels, hardware and descriptor storage.
 */
int esp_sha_dma(unsigned int mode,const void *input,unsigned int input_length,
    const void *buffer,unsigned int buffer_length,unsigned char first_block)
{
    unsigned int block_size = mode < 3U ? 64U : (mode - 3U < 5U ? 128U : 0U);
    if (buffer_length > block_size) {
        unsigned int timestamp = esp_log_timestamp();
        esp_log_write(1,"esp-sha",
            "E (%lu) %s: SHA DMA buf_len cannot exceed max size for a single block\n",
            timestamp,"esp-sha");
        return -1;
    }

    unsigned int external_input_dma = esp_ptr_dma_ext_capable((void *)input);
    unsigned int internal_input_dma = (unsigned int)input - 0x3fc88000U < 0x78000U;
    if ((((external_input_dma | internal_input_dma) ^ 1U) & 1U) != 0 && input_length != 0) {
        if (block_size == 0)
            __assert_func(0,0,0,0);
        unsigned int words_per_block = block_size / 4U;
        unsigned int input_blocks = input_length / block_size;
        if (buffer_length != 0) {
            sha_hal_hash_block(mode,buffer,words_per_block,first_block);
            first_block = 0;
        }
        for (unsigned int block = 0; block < input_blocks; ++block) {
            sha_hal_hash_block(mode,input,words_per_block,first_block);
            input = (const void *)((unsigned int)input + block_size);
            first_block = 0;
        }
        return 0;
    }

    if (esp_ptr_external_ram((void *)input))
        (void)esp_cache_msync((void *)input,input_length,6U);
    if (esp_ptr_external_ram((void *)buffer))
        (void)esp_cache_msync((void *)buffer,buffer_length,6U);
    unsigned int internal_prefix_dma = (unsigned int)buffer - 0x3fc88000U < 0x78000U;
    unsigned int external_prefix_dma = esp_ptr_dma_ext_capable((void *)buffer);
    void *bounce_buffer = 0;
    int result = 0;
    if ((((internal_prefix_dma | external_prefix_dma) ^ 1U) & 0xffU) != 0 && buffer_length != 0) {
        bounce_buffer = heap_caps_malloc(buffer_length,0x80cU);
        if (bounce_buffer == 0) {
            unsigned int timestamp = esp_log_timestamp();
            esp_log_write(1,"esp-sha","E (%lu) %s: Failed to allocate buf memory\n",
                timestamp,"esp-sha");
            result = -1;
            goto cleanup;
        }
        memcpy(bounce_buffer,buffer,buffer_length);
        buffer = bounce_buffer;
    }

    unsigned int operations = 1;
    if (input_length != 0) {
        unsigned int rounded_length = input_length + 3967U;
        if (rounded_length < 3968U)
            goto cleanup;
        operations = rounded_length / 3968U;
    }
    if (block_size == 0) {
        unsigned int timestamp = esp_log_timestamp();
        esp_log_write(1,"esp-sha","E (%lu) %s: Unsupported SHA type\n",
            timestamp,"esp-sha");
        result = -1;
        goto cleanup;
    }

    for (unsigned int operation = 0; operation < operations; ++operation) {
        unsigned int chunk_length = input_length < 3968U ? input_length : 3968U;
        unsigned int block_count = (chunk_length + buffer_length) / block_size;
        CryptoDmaDescriptor *head = 0;
        memset(SHA_INPUT_DESCRIPTOR,0,12U);
        memset(SHA_PREFIX_DESCRIPTOR,0,12U);
        if (input_length != 0) {
            unsigned int previous = SHA_INPUT_DESCRIPTOR->control;
            SHA_INPUT_DESCRIPTOR->control =
                ((chunk_length << 12 | chunk_length | 0xc0000000U) & 0xc0ffffffU) |
                (previous & 0x3f000000U);
            SHA_INPUT_DESCRIPTOR->buffer = input;
            head = SHA_INPUT_DESCRIPTOR;
        }
        if (buffer_length != 0) {
            unsigned int previous = SHA_PREFIX_DESCRIPTOR->control;
            unsigned int flags = input_length == 0 ? 0xc0000000U : 0x80000000U;
            SHA_PREFIX_DESCRIPTOR->control =
                ((buffer_length << 12 | buffer_length | flags) & 0xc0ffffffU) |
                (previous & 0x3f000000U);
            SHA_PREFIX_DESCRIPTOR->buffer = buffer;
            if (input_length != 0)
                SHA_PREFIX_DESCRIPTOR->next = SHA_INPUT_DESCRIPTOR;
            head = SHA_PREFIX_DESCRIPTOR;
        }
        if (esp_sha_dma_start(head) != 0) {
            unsigned int timestamp = esp_log_timestamp();
            esp_log_write(1,"esp-sha",
                "E (%lu) %s: esp_sha_dma_start failed, no DMA channel available\n",
                timestamp,"esp-sha");
            result = -1;
            goto cleanup;
        }
        sha_hal_hash_dma(mode,block_count,first_block);
        sha_hal_wait_idle();
        input_length -= chunk_length;
        input = (const void *)((unsigned int)input + chunk_length);
        buffer_length = 0;
        first_block = 0;
    }
cleanup:
    free(bounce_buffer);
    return result;
}

/* Native entry: 0x42017754. */
/* Original function-byte SHA-256:
 * a46b5d14527dc5d8dcba88dc2c1dd042a500fe1a22b25976714e40e0bdf630c0. */
/* Submit a SHA input descriptor chain through the shared crypto GDMA
 * starter (peripheral5), with output descriptor NULL. Return its status
 * unchanged; no local validation, channel acquisition lock or completion wait.
 */
int esp_sha_dma_start(const CryptoDmaDescriptor *input)
{
    return esp_crypto_shared_gdma_start(input,0,5U);
}
