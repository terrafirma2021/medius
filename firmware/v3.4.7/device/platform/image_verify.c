/* Medius v3.4.7 device: ESP-IDF application image parser and SHA lifetime. */
#include "../include/types.h"

/* Native entry: 0x4200f5d0. */
/* Original function-byte SHA-256:
 * 53422c5bf94094ed53d26e73e7aec1a6aa7bee15da3edb74a5ae41d70b63eb02. */
/* Read main flash into the borrowed output buffer.
 * Only the low byte of allow_decrypt is consumed. A nonzero byte selects an
 * encrypted read only when flash encryption is enabled. The two flash APIs
 * have different address/output argument order; both receive a NULL chip.
 * Return the flash status unchanged. No local range or buffer validation.
 */
int bootloader_flash_read(unsigned int address,void *output,unsigned int size,unsigned char allow_decrypt)
{
    if (allow_decrypt != 0 && esp_flash_encryption_enabled())
        return esp_flash_read_encrypted(NULL,address,output,size);
    return esp_flash_read(NULL,output,address,size);
}

/* Native entry: 0x4200f61c. */
/* Original function-byte SHA-256:
 * a6f70bb8e139ae54ba80e00819ca1bb5ad0cd594d9d1ddf7f56beb84f0416862. */
/* Append padding and the XOR checksum to the recorded image length.
 * Include one checksum byte, then round up to a 16-byte boundary. Read the
 * padding when SHA is active or skip_checksum is not exactly 1. Compare its
 * last byte with the XOR of all four checksum_word bytes unless skipping.
 * A mismatch returns 0x2002 and logs only when silent is zero. Hash padding
 * when SHA is active, then add its length to a fresh metadata length read.
 * Without SHA and with skip_checksum == 1, publish the aligned length only.
 * Arithmetic wraps at 32 bits. Read failure or checksum mismatch leaves the
 * length unchanged; SHA assertion failure does not return. No bounds check.
 */
int image_process_checksum(Sha256Context *sha,unsigned int checksum_word,
    ImageMetadataScratch *metadata,unsigned int silent,unsigned int skip_checksum)
{
    volatile ImageMetadata *info = &metadata->value;
    unsigned int old_length = info->image_len;
    union { unsigned int alignment[4]; unsigned char bytes[16]; } padding = {{0,0,0,0}};
    unsigned int aligned_length = (old_length + 16U) & ~15U;
    if (sha != NULL || skip_checksum != 1) {
        unsigned int padding_length = aligned_length - old_length;
        int result = bootloader_flash_read(info->start_addr + old_length,padding.bytes,padding_length,1);
        if (result != 0)
            return result;
        unsigned int calculated = (checksum_word ^ (checksum_word >> 8) ^
            (checksum_word >> 16) ^ (checksum_word >> 24)) & 0xffU;
        unsigned int stored = padding.bytes[padding_length - 1U];
        if (stored != calculated && skip_checksum != 1) {
            if (silent == 0) {
                unsigned int timestamp = esp_log_timestamp();
                esp_log_write(1,"esp_image","E (%lu) %s: Checksum failed. Calculated 0x%x read 0x%x\n",
                    timestamp,"esp_image",calculated,stored);
            }
            return 0x2002;
        }
        if (sha != NULL)
            bootloader_sha256_data(sha,padding.bytes,padding_length);
        aligned_length = padding_length + info->image_len;
    }
    info->image_len = aligned_length;
    return 0;
}

/* Native entry: 0x4200f6bc. */
/* Original function-byte SHA-256:
 * 4b2055342718cf19261dd8966a318661609c7aa2e425fd6b7206abff0b593265. */
/* Clear all 264 metadata bytes, set start_addr and read the 24-byte header.
 * With verify nonzero, allocate and publish SHA before validating the header
 * if hash_appended is nonzero and out_sha exists. Hash that header immediately;
 * allocation failure returns 0x101. Require magic 0xe9, admitted chip/revision
 * and at most 16 segments. Magic/count failures return 0x2002 with optional
 * diagnostics; flash/chip errors propagate. Publish image_len = 24 on success.
 * This function never frees an allocated SHA context on a later error; its
 * caller owns cleanup. It does not clear out_sha. Flags use full-word tests.
 */
int image_process_header(ImageMetadataScratch *metadata,unsigned int address,
    Sha256Context **out_sha,unsigned int verify,unsigned int silent)
{
    bzero(metadata,264);
    volatile ImageMetadata *info = &metadata->value;
    info->start_addr = address;
    int result = bootloader_flash_read(address,&metadata->value.image,24,1);
    if (result != 0)
        return result;
    if (verify != 0) {
        if (info->image.hash_appended != 0 && out_sha != NULL) {
            Sha256Context *sha = bootloader_sha256_start();
            *(Sha256Context *volatile *)out_sha = sha;
            if (sha == NULL)
                return 0x101;
            bootloader_sha256_data(sha,&metadata->value.image,24);
        }
        unsigned int magic = info->image.magic;
        unsigned int start = info->start_addr;
        if (magic == 0xe9) {
            result = bootloader_common_check_chip_validity(
                (const ImageRevisionHeader *)&metadata->value.image,1);
            if (result != 0)
                return result;
            if (info->image.segment_count > 16) {
                if (silent == 0) {
                    unsigned int timestamp = esp_log_timestamp();
                    unsigned int count = info->image.segment_count;
                    esp_log_write(1,"esp_image","E (%lu) %s: image at 0x%lx segment count %d exceeds max %d\n",
                        timestamp,"esp_image",start,count,16);
                }
                return 0x2002;
            }
        } else {
            if (silent == 0) {
                unsigned int timestamp = esp_log_timestamp();
                esp_log_write(1,"esp_image","E (%lu) %s: image at 0x%lx has invalid magic byte (nothing flashed here?)\n",
                    timestamp,"esp_image",start);
            }
            return 0x2002;
        }
    }
    info->image_len = 24;
    return 0;
}

/* Native entry: 0x4200f77c. */
/* Original function-byte SHA-256:
 * 48cff933764eb91cdef044f974c8812d30769bb9470b4998ae09af3752813f76. */
/* Walk segment headers and optionally checksum/hash their flash contents.
 * Read each 8-byte header and hash it before validating its length. Lengths
 * must be divisible by four. Publish a 64 KiB MMU page size; mapped addresses
 * in 0x42000000..0x43ffffff or 0x3c000000..0x3dffffff must have the same low
 * 16 bits as the flash data address. Query free MMU pages once per segment,
 * including empty segments. Chunk capacity is (pages - unaligned_page) << 16
 * with 32-bit wrapping. A NULL checksum skips mapping and data/SHA processing.
 * For each mapped chunk of segment zero with nonzero image start, read the
 * app maximum revision at +178, then minimum at +176, before checking size.
 * XOR every mapped word into the live checksum. At each 1024-byte boundary,
 * hash up to 1024 bytes. Unmap every successful mapping; a zero-size mapping
 * is retried and can fail to progress. Map/read failures always log; other
 * malformed-header/offset errors log only when silent is zero.
 * Publish each data offset before rereading header length and segment count.
 * The native loop has no new count bound after callbacks; integer address
 * arithmetic retains its possible accesses past the 16 declared slots.
 * On a nonwrapped final offset, add consumed bytes to a fresh image_len read.
 * Errors retain partial metadata/checksum/SHA changes. No RAM segment loading.
 */
int image_process_segments(ImageMetadataScratch *metadata,unsigned int silent,
    Sha256Context *sha,unsigned int *checksum)
{
    volatile ImageMetadata *info = &metadata->value;
    unsigned int start = info->start_addr;
    unsigned int old_length = info->image_len;
    unsigned int count = info->image.segment_count;
    unsigned int first_header = start + old_length;
    unsigned int next_header = first_header;
    if (count != 0) {
        unsigned int index = 0;
        do {
            /* The native index is not bounded again after external calls. */
            ImageSegmentHeader *header = (ImageSegmentHeader *)(
                (uintptr_t)&metadata->value.segments[0] + index * sizeof(ImageSegmentHeader));
            int result = bootloader_flash_read(next_header,header,8,1);
            if (result != 0) {
                unsigned int timestamp = esp_log_timestamp();
                esp_log_write(1,"esp_image","E (%lu) %s: bootloader_flash_read failed at 0x%08lx\n",
                    timestamp,"esp_image",next_header);
                return result;
            }
            if (sha != NULL)
                bootloader_sha256_data(sha,header,8);
            unsigned int length = ((volatile ImageSegmentHeader *)header)->data_len;
            unsigned int data_address = next_header + 8U;
            if ((length & 3U) != 0) {
                if (silent == 0) {
                    unsigned int timestamp = esp_log_timestamp();
                    unsigned int current_length = ((volatile ImageSegmentHeader *)header)->data_len;
                    esp_log_write(1,"esp_image","E (%lu) %s: invalid segment length 0x%lx\n",
                        timestamp,"esp_image",current_length);
                }
                return 0x2002;
            }
            unsigned int load_address = ((volatile ImageSegmentHeader *)header)->load_addr;
            info->mmu_page_size = 0x10000;
            bool mapped_segment = load_address - 0x42000000U < 0x02000000U ||
                load_address - 0x3c000000U < 0x02000000U;
            if (mapped_segment && ((load_address ^ data_address) & 0xffffU) != 0) {
                if (silent == 0) {
                    unsigned int timestamp = esp_log_timestamp();
                    esp_log_write(1,"esp_image","E (%lu) %s: Segment %d load address 0x%08lx, doesn\'t match data 0x%08lx\n",
                        timestamp,"esp_image",index,load_address,data_address);
                }
                return 0x2002;
            }
            if (silent == 0) {
                unsigned int timestamp = esp_log_timestamp();
                esp_log_write(3,"esp_image","I (%lu) %s: segment %d: paddr=%08lx vaddr=%08x size=%05lxh (%6lu) %s\n",
                    timestamp,"esp_image",index,data_address,load_address,length,length,mapped_segment ? "map" : "");
            }
            unsigned int free_pages = bootloader_mmap_get_free_pages();
            unsigned int remaining = length;
            unsigned int chunk_address = data_address;
            while (remaining != 0) {
                unsigned int capacity = (free_pages - ((chunk_address & 0xffffU) != 0)) << 16;
                unsigned int chunk_size = capacity < remaining ? capacity : remaining;
                if (checksum != NULL) {
                    const void *mapped = bootloader_mmap(chunk_address,chunk_size);
                    if (mapped == NULL) {
                        unsigned int timestamp = esp_log_timestamp();
                        esp_log_write(1,"esp_image","E (%lu) %s: bootloader_mmap(0x%lx, 0x%lx) failed\n",
                            timestamp,"esp_image",chunk_address,chunk_size);
                        return -1;
                    }
                    if (index == 0 && info->start_addr != 0) {
                        const volatile AppEfuseRevisionFields *app =
                            (const volatile AppEfuseRevisionFields *)mapped;
                        unsigned int maximum = app->maximum_revision;
                        unsigned int minimum = app->minimum_revision;
                        result = bootloader_common_check_efuse_blk_validity(minimum,maximum);
                        if (result != 0) {
                            bootloader_munmap(mapped);
                            return result;
                        }
                    }
                    if (chunk_size == 0) {
                        bootloader_munmap(mapped);
                        continue;
                    }
                    const volatile unsigned int *words = mapped;
                    unsigned int byte_offset = 0;
                    do {
                        unsigned int word = *words;
                        unsigned int previous = *(volatile unsigned int *)checksum;
                        *(volatile unsigned int *)checksum = previous ^ word;
                        if (sha != NULL && (byte_offset & 0x3ffU) == 0) {
                            unsigned int hash_size = chunk_size - byte_offset;
                            if (hash_size > 0x400U)
                                hash_size = 0x400;
                            bootloader_sha256_data(sha,(const void *)words,hash_size);
                        }
                        byte_offset += 4U;
                        ++words;
                    } while (byte_offset < chunk_size);
                    bootloader_munmap(mapped);
                }
                remaining -= chunk_size;
                chunk_address += chunk_size;
            }
            volatile unsigned int *data_offset_slot = (volatile unsigned int *)(
                (uintptr_t)&metadata->value.segment_data[0] + index * sizeof(unsigned int));
            *data_offset_slot = data_address;
            unsigned int current_length = ((volatile ImageSegmentHeader *)header)->data_len;
            ++index;
            next_header = data_address + current_length;
            count = info->image.segment_count;
        } while (index < count);
        start = info->start_addr;
    }
    if (next_header < start) {
        if (silent == 0) {
            unsigned int timestamp = esp_log_timestamp();
            esp_log_write(1,"esp_image","E (%lu) %s: image offset has wrapped\n",timestamp,"esp_image");
        }
        return 0x2002;
    }
    info->image_len = info->image_len - first_header + next_header;
    return 0;
}

/* Native entry: 0x4200fa5c. */
/* Original function-byte SHA-256:
 * 0495361e5aac271a99d2203c50d55267b25b620975ee845d89613c1a6d6c1231. */
/* Read an appended digest and enforce the final partition length.
 * If hash_appended is nonzero, read 32 bytes at start_addr + image_len, then
 * add 32 to a fresh length read and publish it. Flash errors propagate.
 * Only afterward compare with partition_size; excess returns 0x2002 with
 * optional logging. Images without a digest receive the same length check.
 * No signature, pre-read bounds check or integer-overflow check is added.
 */
int image_process_appended_hash(ImageMetadataScratch *metadata,
    unsigned int partition_size,unsigned int silent)
{
    volatile ImageMetadata *info = &metadata->value;
    unsigned int appended = info->image.hash_appended;
    unsigned int length = info->image_len;
    if (appended != 0) {
        unsigned int address = info->start_addr;
        int result = bootloader_flash_read(address + length,metadata->value.image_digest,32,1);
        if (result != 0)
            return result;
        length = info->image_len + 32U;
        info->image_len = length;
    }
    if (partition_size < length) {
        if (silent == 0) {
            unsigned int timestamp = esp_log_timestamp();
            esp_log_write(1,"esp_image","E (%lu) %s: Image length %lu doesn\'t fit in partition length %lu\n",
                timestamp,"esp_image",length,partition_size);
        }
        return 0x2002;
    }
    return 0;
}

/* Native entry: 0x4200fab4. */
/* Original function-byte SHA-256:
 * 8eece327608bfbd6435b13a423df63f7a6ab76d8eab1e5cb66f2f122e1233946. */
/* Verify an application image without executing or loading it into RAM.
 * Mode 1 selects conditional silence; every other word value also verifies.
 * NULL position/metadata returns 0x102 without touching output. Seed XOR with
 * 0xef, process header and segments, check padding/checksum, read any appended
 * digest, then enforce partition length. A nonzero flash offset allows SHA.
 * Sample external debugger register 0x10200c bit 0 before the checksum, and
 * separately before SHA comparison: the samples can bypass different checks.
 * Active SHA still hashes padding. This is a corruption check, not signature
 * authentication. Finalize/free acquired SHA on success or discard it on error.
 * A SHA mismatch always logs and returns 0x2002, even in silent mode. Any error
 * after argument validation clears all 264 output bytes. Metadata remains on
 * success. Digest finalization consumes the context before comparison.
 */
int image_load(unsigned int mode,const ImagePosition *position,
    ImageMetadataScratch *metadata)
{
    unsigned int checksum = 0xef;
    Sha256Context *published_sha = NULL;
    if (metadata == NULL || position == NULL)
        return 0x102;
    unsigned int address = ((const volatile ImagePosition *)position)->offset;
    unsigned int silent = mode == 1;
    int result = image_process_header(metadata,address,
        address == 0 ? NULL : &published_sha,1,silent);
    Sha256Context *sha = *(Sha256Context *volatile *)&published_sha;
    if (result != 0)
        goto failure;
    result = image_process_segments(metadata,silent,sha,&checksum);
    if (result != 0)
        goto failure;
    unsigned int debug_status;
    __asm__ volatile ("rer %0, %1" : "=a"(debug_status) : "a"(0x10200cU) : "memory");
    result = image_process_checksum(sha,*(volatile unsigned int *)&checksum,
        metadata,silent,debug_status & 1U);
    if (result != 0)
        goto failure;
    unsigned int partition_size = ((const volatile ImagePosition *)position)->size;
    result = image_process_appended_hash(metadata,partition_size,silent);
    if (result != 0)
        goto failure;
    if (sha == NULL)
        return 0;
    if (address != 0) {
        __asm__ volatile ("rer %0, %1" : "=a"(debug_status) : "a"(0x10200cU) : "memory");
        if ((debug_status & 1U) == 0) {
            unsigned int digest[8] = {0,0,0,0,0,0,0,0};
            bootloader_sha256_finish(sha,(unsigned char *)digest);
            bootloader_debug_buffer(digest,32,"Calculated hash");
            if (memcmp(metadata->value.image_digest,digest,32) == 0)
                return 0;
            unsigned int timestamp = esp_log_timestamp();
            esp_log_write(1,"esp_image","E (%lu) %s: Image hash failed - image is corrupt\n",timestamp,"esp_image");
            bootloader_debug_buffer(metadata->value.image_digest,32,"Expected hash");
            result = 0x2002;
            goto clear_output;
        }
    }
    bootloader_sha256_finish(sha,NULL);
    return 0;
failure:
    if (sha != NULL)
        bootloader_sha256_finish(sha,NULL);
clear_output:
    bzero(metadata,264);
    return result;
}

/* Native entry: 0x4200fbc8. */
/* Original function-byte SHA-256:
 * 09773d3e9e98072ad8167de40128346a623cfdab2a890771b3ea0fe4fd0457bf. */
/* Forward mode, position and metadata to image_load and return its status.
 * This wrapper adds no validation, cleanup or policy.
 */
int esp_image_verify(unsigned int mode,const ImagePosition *position,
    ImageMetadataScratch *metadata)
{
    return image_load(mode,position,metadata);
}

/* Native entry: 0x4200fbd8. */
/* Original function-byte SHA-256:
 * 13405b0355e4124dfb22730b20e8d443c6d147ec0a09102a9b76723ba0ed71af. */
/* Allocate and initialize an owned 116-byte SHA-256 context.
 * Start SHA-256 with is224 = 0. Return the context on success, or NULL when
 * allocation/start fails. The native start-failure path leaks its allocation;
 * no cleanup is added.
 */
Sha256Context *bootloader_sha256_start(void)
{
    Sha256Context *sha = malloc(116);
    if (sha == NULL)
        return NULL;
    mbedtls_sha256_init(sha);
    if (mbedtls_sha256_starts(sha,0) != 0)
        return NULL;
    return sha;
}

/* Native entry: 0x4200fc00. */
/* Original function-byte SHA-256:
 * a79bf4148ba7722fe375bb52655fb4aa3f224dfb682711b112da004fe1807273. */
/* Feed borrowed data and size to an existing SHA-256 context.
 * Assert sha is non-NULL and the SHA update status is zero. The assertion
 * boundary does not return. There is no buffer validation or error result.
 */
void bootloader_sha256_data(Sha256Context *sha,const void *data,unsigned int size)
{
    if (sha == NULL)
        __assert_func(NULL,0,NULL,NULL);
    if (mbedtls_sha256_update(sha,data,size) != 0)
        __assert_func(NULL,0,NULL,NULL);
}

/* Native entry: 0x4200fc24. */
/* Original function-byte SHA-256:
 * 9908316ac58fce9ccf4b04b7f639a81435f486ab1a4f7b06175eb70c0c77bf2d. */
/* Finish or discard an owned SHA context, then release it.
 * Assert sha is non-NULL. A non-NULL output receives 32 digest bytes and the
 * finish status must be zero. NULL output skips finalization. Then clear/free
 * SHA resources and free its heap allocation. Assertion failure never reaches
 * cleanup; no output-capacity check or normal error result is supplied.
 */
void bootloader_sha256_finish(Sha256Context *sha,unsigned char *output)
{
    if (sha == NULL)
        __assert_func(NULL,0,NULL,NULL);
    if (output != NULL && mbedtls_sha256_finish(sha,output) != 0)
        __assert_func(NULL,0,NULL,NULL);
    mbedtls_sha256_free(sha);
    free(sha);
}

/* Native entry: 0x420211a8. */
/* Original function-byte SHA-256:
 * a50f595a12cc6e7e90d28fa2424790fbfac53a684610d6fe5637b2112f16f23d. */
/* Compiled-out debug-buffer output: the native body is ENTRY/RET only.
 * Accept the three observed caller arguments without reading them. No logging,
 * allocation, formatting or validation occurs.
 */
void bootloader_debug_buffer(const void *data,unsigned int size,const char *label)
{
    (void)data;
    (void)size;
    (void)label;
}
