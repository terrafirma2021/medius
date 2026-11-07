/* Medius v3.4.7 host: ESP-IDF application image parser and SHA lifetime. */
#include "../include/types.h"

/* Native entry: 0x420119dc. */
/* Original function-byte SHA-256:
 * 0ffa6541240d1199b9ad32245e1b091e03e4db19b58f82164b573399eaf40013. */
/* * Read bytes from main flash. Only the low BYTE of allow_decrypt is consumed.
 * If nonzero and flash encryption is enabled, use encrypted read with its
 * address/output argument order; otherwise use raw flash read. Pass chipNULL
 * to select default flash and return its status. No local range/buffer checks.
 */
int bootloader_flash_read(unsigned int address,void *output,unsigned int size,unsigned char allow_decrypt)
{
    if (allow_decrypt != 0 && esp_flash_encryption_enabled())
        return esp_flash_read_encrypted(NULL,address,output,size);
    return esp_flash_read(NULL,output,address,size);
}

/* Native entry: 0x42011a28. */
/* Original function-byte SHA-256:
 * 60d8663c80c7a729f33bd85c1e253d267d599d0b377b0de05683144702c360a4. */
/* * Pad image length to the next16-byte boundary including one checksum BYTE.
 * Read the padding/checksum if SHA is active or skip_checksum is not exactly1.
 * XOR the four checksum-word bytes and compare the last padding BYTE; mismatch
 * returns0x2002 (optionally logs) unless skip_checksum==1. Hash all padding on
 * success when SHA exists, then add to a fresh image_len read. With no SHA and
 * skip==1 only publish aligned length. Native sums wrap32; no partition bound
 * or pointer validation. Read/hash failure leaves image_len unchanged here.
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

/* Native entry: 0x42011ac8. */
/* Original function-byte SHA-256:
 * 7ecdc9fbc8e2dce894a587f19a99c86572d60efb4333d0a407068d1ccad455f6. */
/* * Zero264-byte metadata, publish start address, and read the24-byte image header
 * with decryption allowed. A read error returns directly. With verification
 * enabled, allocate/publish a SHA context and hash the header when hash_appended
 * is nonzero and a handle-output pointer exists; allocation failure returns101.
 * This occurs BEFORE magic/chip/segment-count validation. Magic must be e9;
 * then apply chip/revision admission and require segment_count<=16. Invalid
 * magic/count returns2002 with optional diagnostics. Publish image_len24 only
 * on success. Does not free a context on later error or clear metadata again;
 * the caller owns that cleanup. Flags are full32-bit nonzero tests.
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

/* Native entry: 0x42011b88. */
/* Original function-byte SHA-256:
 * d7197cc057b134af3912df7fb8b3e95b96bb49a05fe272ad9a98248526287256. */
/* * Read each8-byte segment header, optionally hash it, reject lengths not
 * divisible by4, and publish MMU page size64KiB. Flash-mapped load addresses
 * in42000000..43ffffff or3c000000..3dffffff must match the physical data offset
 * modulo64KiB. Optional informational logging preserves cached header values.
 * Query free MMU pages once per segment, even empty ones. Split remaining data
 * by (free_pages - within_page_nonzero)<<16 with32-bit wrap. With checksumNULL
 * skip mappings/hash/data checks; otherwise map each chunk, check app eFuse
 * revisions at mapped+176/178 for segment0/nonzero start, XOR each WORD into
 * the live checksum, and hash up to1024 bytes at each1024-byte boundary. Read
 * max revision HALF before min; no descriptor-size check precedes these reads.
 * Zero-sized successful mappings are unmapped/retried and can fail to progress.
 * Map failure logs even in silent mode and returns-1. Read failure also always
 * logs. Other malformed-header/wrap errors return2002 with conditional logs.
 * Publish segment physical offset before rereading its length/count. Only at
 * final nonwrapped end add consumed bytes to a fresh image_len read. Partial
 * metadata/checksum/SHA mutations survive errors; no RAM loading occurs here.
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
            ImageSegmentHeader *header = &metadata->value.segments[index];
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
                    unsigned int current_length = info->segments[index].data_len;
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
            info->segment_data[index] = data_address;
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

/* Native entry: 0x42011e68. */
/* Original function-byte SHA-256:
 * a55a530ec25367340f8553fff0b2c3a8f3acf14e0caef2af486aa7c2ae84ca06. */
/* * If hash_appended is nonzero, read32 digest bytes at start+image_len and then
 * add32 to a fresh image_len read. Propagate read errors. Compare resulting
 * length with partition_size only AFTER that read/publication; oversize returns
 *2002 with optional diagnostic. No signature verification, pre-read bounds or
 * overflow checks. Non-hash images still receive the final length check.
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

/* Native entry: 0x42011ec0. */
/* Original function-byte SHA-256:
 * ddc4c5340df6c50ca883077aa762dabf7b35eb79c781cac5555b4cf49a97abfa. */
/* * Application-mode image verification; mode==1 selects conditional silence,
 * other modes still verify. Reject NULL position/metadata with102 without
 * touching output. Seed XOR checksum ef, process header and all segments,
 * pad/check checksum, read appended digest and check final partition length.
 * For nonzero flash offset allow a SHA handle. Read external debugger status
 * register10200c bit0 before checksum and, separately, before simple SHA
 * comparison. The first sample can skip checksum; the second can skip digest
 * comparison. Active SHA still hashes padding. This image contains corruption
 * hash comparison, not signature authentication. Finalize/free every acquired
 * context even on error; NULL output discards digest. Hash mismatch always
 * logs, even silent mode, and returns2002. Any later error clears264-byte output;
 * success retains metadata. No firmware execution or RAM segment loading.
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

/* Native entry: 0x42011fd4. */
/* Original function-byte SHA-256:
 * 09773d3e9e98072ad8167de40128346a623cfdab2a890771b3ea0fe4fd0457bf. */
/* * Forward all three native WORD arguments to the image verifier and return
 * its status. This wrapper adds no validation, cleanup or policy.
 */
int esp_image_verify(unsigned int mode,const ImagePosition *position,
    ImageMetadataScratch *metadata)
{
    return image_load(mode,position,metadata);
}

/* Native entry: 0x42011fe4. */
/* Original function-byte SHA-256:
 * b3c1d4fa1892bfe39178e2eb4241a0be9013f5a6c18bd1e7f2c01874495dd285. */
/* * Allocate a116-byte resumable SHA-256 context, initialize it, and start SHA256
 * (is224=0). Return the owned context, or NULL on allocation/start failure.
 * The native start-failure path leaks its allocation; no cleanup is added.
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

/* Native entry: 0x4201200c. */
/* Original function-byte SHA-256:
 * f39158eafc53fb4354eda0c81429324323bbf9d3fab5d1898eb50ce0ade07f4b. */
/* * Assert context non-NULL, feed the borrowed data/length to SHA update, and
 * assert its status is0. Assertions terminate through the native nonreturning
 * assertion boundary; no normal error result or buffer validation is supplied.
 */
void bootloader_sha256_data(Sha256Context *sha,const void *data,unsigned int size)
{
    if (sha == NULL)
        __assert_func(NULL,0,NULL,NULL);
    if (mbedtls_sha256_update(sha,data,size) != 0)
        __assert_func(NULL,0,NULL,NULL);
}

/* Native entry: 0x42012030. */
/* Original function-byte SHA-256:
 * 31ed28698f26684cf3d452393c618ddd5b22068d8f4dd41e39c35f412c3bc41e. */
/* * Assert context non-NULL. With output non-NULL finalize32 bytes and assert
 * status0; outputNULL discards the digest without finalizing it. Then free SHA
 * resources/clear context via mbedtls free, and free its heap allocation.
 * A failing assertion does not reach cleanup; context must be owned/allocated.
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

/* Native entry: 0x4201eab4. */
/* Original function-byte SHA-256:
 * a50f595a12cc6e7e90d28fa2424790fbfac53a684610d6fe5637b2112f16f23d. */
/* * Compiled-out bootloader debug-buffer output: native ENTRY/RET only. Accept
 * the three observed caller arguments and return without reading any input.
 * No allocation, formatting, validation or logging occurs.
 */
void bootloader_debug_buffer(const void *data,unsigned int size,const char *label)
{
    (void)data;
    (void)size;
    (void)label;
}
