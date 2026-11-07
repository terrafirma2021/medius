/* Medius v3.4.7 device — PSRAM heap registration and sparse diagnostics. */
#include "../include/types.h"

/* Native entry: 0x42008080. */
/* Original function-byte SHA-256:
 * f79fafc0d2372964a9ea3c2b45171ddda28aabe77da59c17ee71368abb140b9c. */
/*
 * Destructive sparse PSRAM test: for byte_length>=4, write one WORD every32
 * bytes using (word_index^0xaaaaaaaa), with word_index=0,8,16,... below
 * floor(byte_length/4). Complete the write pass before the read pass, MEMW
 * before each WORD access. Do not restore original contents or check other
 * bytes. Length<4 succeeds without dereferencing start. No pointer/range,
 * alignment, ownership, concurrent-user or cache-coherency validation.
 *
 * Count all mismatching samples and retain the first failing BYTE offset.
 * Return full-WORD0 on any mismatch; log when level!=0. The failure denominator
 * is byte_length>>5 (floor), although sample count rounds up: lengths4..31 can
 * report1/0. Otherwise return1 and log success only at level>=3. No retry,
 * allocation, memory initialization guarantee or full memory-test claim.
 */
int psram_sparse_memory_test(unsigned int start_address,unsigned int byte_length)
{
    unsigned int word_count = byte_length >> 2;
    if (word_count != 0) {
        unsigned int sample_count = ((word_count - 1U) >> 3) + 1U;
        for (unsigned int sample = 0; sample < sample_count; ++sample) {
            unsigned int word_index = sample * 8U;
            memw();
            *(volatile unsigned int *)(uintptr_t)(start_address + word_index * 4U) =
                word_index ^ 0xaaaaaaaaU;
        }
        unsigned int failure_count = 0;
        unsigned int first_failure_offset = 0xffffffffU;
        for (unsigned int sample = 0; sample < sample_count; ++sample) {
            unsigned int word_index = sample * 8U;
            memw();
            unsigned int actual = *(const volatile unsigned int *)(uintptr_t)
                (start_address + word_index * 4U);
            if (actual != (word_index ^ 0xaaaaaaaaU)) {
                if (failure_count == 0)
                    first_failure_offset = word_index * 4U;
                ++failure_count;
            }
        }
        if (failure_count != 0) {
            if (PSRAM_LOG_LEVEL != 0) {
                unsigned int timestamp_ms = esp_log_timestamp();
                ets_printf("E (%lu) %s: SPI SRAM memory test fail. %d/%d writes failed, first @ %X\n",
                    timestamp_ms, PSRAM_LOG_TAG, failure_count, byte_length >> 5,
                    start_address + first_failure_offset);
            }
            return 0;
        }
    }
    if (PSRAM_LOG_LEVEL >= 3U) {
        unsigned int timestamp_ms = esp_log_timestamp();
        ets_printf("I (%lu) %s: SPI SRAM memory test OK\n", timestamp_ms, PSRAM_LOG_TAG);
    }
    return 1;
}

/* Native entry: 0x420082f0. */
/* Original function-byte SHA-256:
 * 503ec6e1eec9dedbe26b4bcbb296f9a19c05b32699b6b98708bd942b551006e0. */
/*
 * Add primary PSRAM heap region using copied capability priorities
 * {0x1400,0,0x100006}. Read end then start from the shared context before the
 * first call. Return its error immediately. If secondary size is nonzero,
 * load its start and assert-fatally if0; load end after that check, copy
 * {0x1400,0,2}, and add it. Secondary failure is returned without undoing the
 * successful primary registration. On success, optional level>=3 info output
 * reports the fresh sum of both sizes modulo32, shifted right10, after getting
 * its timestamp. Returns0. No initialized check, duplicate-registration guard,
 * allocator rollback or local lock; the heap API supplies its own validation.
 */
int esp_psram_extram_add_to_heap_allocator(void)
{
    unsigned int cap0=PSRAM_PRIMARY_CAPABILITIES->priority[0];
    unsigned int cap1=PSRAM_PRIMARY_CAPABILITIES->priority[1];
    unsigned int cap2=PSRAM_PRIMARY_CAPABILITIES->priority[2];
    unsigned int end=PSRAM_CONTEXT->heap_regions[0].end;
    unsigned int start=PSRAM_CONTEXT->heap_regions[0].start;
    PsramHeapCapabilities primary={{cap0,cap1,cap2}};
    int status=heap_caps_add_region_with_caps(&primary,start,end);
    if (status!=0) return status;
    if (PSRAM_CONTEXT->heap_regions[1].size!=0) {
        start=PSRAM_CONTEXT->heap_regions[1].start;
        if (start==0) __assert_func(NULL,0,NULL,NULL);
        end=PSRAM_CONTEXT->heap_regions[1].end;
        cap0=PSRAM_SECONDARY_CAPABILITIES->priority[0];
        cap1=PSRAM_SECONDARY_CAPABILITIES->priority[1];
        cap2=PSRAM_SECONDARY_CAPABILITIES->priority[2];
        PsramHeapCapabilities secondary={{cap0,cap1,cap2}};
        int secondary_status=heap_caps_add_region_with_caps(&secondary,start,end);
        if (secondary_status!=0) return secondary_status;
    }
    if (PSRAM_LOG_LEVEL>=3U) {
        unsigned int timestamp=esp_log_timestamp();
        unsigned int primary_size=PSRAM_CONTEXT->heap_regions[0].size;
        unsigned int secondary_size=PSRAM_CONTEXT->heap_regions[1].size;
        ets_printf("I (%lu) %s: Adding pool of %dK of PSRAM memory to heap allocator\n",
                   timestamp,PSRAM_LOG_TAG,(primary_size+secondary_size)>>10);
    }
    return status;
}

/* Native entry: 0x42008370. */
/* Original function-byte SHA-256:
 * b1d017afb7d255bd67367575e9f4a4dba25840abec5fbc6600eba38e4cbb8635. */
/* Startup hook: return0 immediately when the initialized BYTE is0. Otherwise
 * add PSRAM regions to the heap. Return0 on success; on any error, optionally
 * log at nonzero level then abort. No recovery, retries or initialized reset.
 * This wrapper adds no independent lock or allocation test. */
int psram_add_heap_if_initialized(void)
{
    if (PSRAM_INITIALIZED==0) return 0;
    if (esp_psram_extram_add_to_heap_allocator()==0) return 0;
    if (PSRAM_LOG_LEVEL!=0) {
        unsigned int timestamp=esp_log_timestamp();
        ets_printf("E (%lu) %s: External RAM could not be added to heap!\n",
                   timestamp,PSRAM_LOG_TAG);
    }
    abort();
}

/* Native entry: 0x420083a8. */
/* Original function-byte SHA-256:
 * 69a3d12cb5d45a342e00dd3964eb06e892e4347b7af4f7bf23b2fbc593264e00. */
/* Initialize a local size WORD to0, query the implementation's available size,
 * and return its written value only for status0; otherwise return0. No state
 * BYTE check, memory probe, mapping-size sum or independent synchronization.
 * This image's available-size implementation returns the cached physical size. */
size_t esp_psram_get_size(void)
{
    unsigned int size=0;
    int status=esp_psram_impl_get_available_size(&size);
    return status==0?size:0U;
}

/* Native entry: 0x420083d0. */
/* Original function-byte SHA-256:
 * 7d494f93bab2495b52b4f8ac8e8d140b116a8e57d6b7d47907c7558c51605347. */
/* Test the primary mapped region, loading its size before its start. Return0
 * on failure. Only after success, load secondary size; if nonzero, load its
 * start and test it too. Forward the last full-WORD result. No initialized
 * check, bounds repair, skipped reserved span, lock or additional diagnostics. */
int esp_psram_extram_test(void)
{
    unsigned int size=PSRAM_CONTEXT->mapped_regions[0].size;
    unsigned int start=PSRAM_CONTEXT->mapped_regions[0].start;
    int success=psram_sparse_memory_test(start,size);
    if (success!=0) {
        size=PSRAM_CONTEXT->mapped_regions[1].size;
        if (size!=0) {
            start=PSRAM_CONTEXT->mapped_regions[1].start;
            success=psram_sparse_memory_test(start,size);
        }
    }
    return success;
}
