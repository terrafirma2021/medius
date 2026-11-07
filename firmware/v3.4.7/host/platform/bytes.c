/* Medius v3.4.7 host — platform/bytes.c.
 * Recovered C and native assembly, grouped for source navigation.
 * Original entry addresses, firmware-byte hashes and function comments follow.
 */

#include "../include/types.h"

/* Native entry: 0x4037b900. */
/*
 * Medius v3.4.7 — host application; 0x4037b900.
 *
 * Updates a non-reflected CRC-16 using polynomial 0x1021; returns the accumulator.
 *
 * Called by: link_frame_patch_payload, link_frame_encode, link_parser_feed.
 *
 * Original function-byte SHA-256:
 * 9eecd42d059d310f50bf67e48b5d91e21b97432c51ef3116a9d7fa41ca7ff364.
 */

/*
 * Updates a non-reflected CRC-16 accumulator using the image's256-entry
 * polynomial0x1021 lookup table. crc is the initial16-bit accumulator;
 * data must cover length readable bytes and is not read when length is zero.
 * Returns the updated16-bit accumulator, with no final XOR or byte reversal.
 *
 * Each byte selects table[(crc>>8) XOR byte], then XORs that word with the
 * accumulator shifted left8 and truncated to16 bits. length is unsigned32-bit.
 * Does not modify input or shared state, allocate, lock, or choose the seed.
 * Callers composing a Medius frame supply0xffff and may chain updates.
 */
unsigned short crc16_update(unsigned short crc, const unsigned char *data,
                                    unsigned int length)
{
    unsigned int accumulator = crc;
    while (length != 0) {
        unsigned int table_index = (accumulator >> 8) ^ *data;
        accumulator = CRC16_TABLE[table_index] ^ ((accumulator & 0xffU) << 8);
        ++data;
        --length;
    }
    return (unsigned short)accumulator;
}

/* Native entry: 0x4202f1ec. */
/*
 * Medius v3.4.7 — host application; 0x4202f1ec.
 *
 * Copies forward using aligned source word snapshots and byte/word stores; large block counts
 * narrow to16 bits.
 *
 * Called by: medius_host_capture_descriptors_and_probe_controls,
 * medius_host_capture_string_descriptor, medius_host_merge_hid_descriptor_blob.
 *
 * Original function-byte SHA-256:
 * cfb80c2ffe16cbddde910817dbbf936abb8ddfdcd739e1e6a69ec4013bf26865.
 */

/* Copies forward using aligned source word snapshots and byte/word stores; large block counts
   narrow to16 bits. Zero length performs no memory access, including NULL/NULL. With matching
   source/destination modulo4 alignment, copies leading bytes until destination alignment,
   then16-byte groups as four sequential load32/store32 pairs, remaining4-byte words and final
   bytes. With differing alignment, copies leading bytes until source alignment, then16-byte groups
   as four sequential aligned word loads each followed by four byte stores, remaining4-byte word
   snapshots as byte stores, then final bytes. For ordinary bounded lengths, this copies exactly
   length bytes and returns no meaningful pointer. It is forward-only: overlapping destination above
   source can overwrite data read by later words/bytes; positive overlaps<4 use one4-byte snapshot
   at a time, not a simple byte-copy model. No memmove overlap preservation is promised. After
   leading bytes, let N be remaining length>=16. Matching alignment uses B=(((N-16)>>4)&65535)+1
   block iterations, then N&15 residual bytes; both pointers advance by the actual narrowed block
   span. Differing alignment computes b=(N>>4)&65535 and B=((((b*16-16)&FFFFFFFFhex)>>4)+1). When
   b=0, B=10000000hex blocks, a4GiB copy attempt rather than0. Otherwise B=b. After that block loop,
   differing-alignment pointers are advanced to the original untruncated floor(N/16)*16 offset for
   residual work, so a narrowed loop can leave a large hole before the tail. Tests verify loop
   registers before accesses and, at N=100011hex, the first16 copied bytes and distant tail pointers
   before the next load. Boundaries: No NULL, capacity, alignment exception, overlap or
   integer-range validation. Descriptor-sized lengths<=65535 are tested across all alignments;
   merger supplies a16-bit descriptor length. Other callers are not thereby proven bounded. The
   equal-alignment16-block count first truncates at remaining100010hex; the differing-alignment
   zero-count expansion occurs at remaining100000hex. Such malformed lengths are stopped before
   unsafe transfers; no assertion is made that real firmware inputs reach them. Register return
   value is not a consistent destination or status. No local cache/DMA synchronization is provided.
    */

/*
 * destination: Writable borrowed storage; must cover every native addressed write.
 * source: Readable borrowed storage; aliases are processed forward with word snapshots, without
 *   memmove preservation.
 * length: Full32-bit requested byte count; malformed large counts preserve native
 *   narrowing/expansion behavior.
 * Returns: No meaningful value; does not return a consistent destination or status.
 * Requirements/effects: Zero length dereferences neither pointer. Equal modulo4 alignment copies a
 *   byte prefix until destination alignment, then four sequential aligned word load/store pairs
 *   per16-byte block, remaining words and bytes. Its block count is (((remaining-16)>>4)&65535)+1;
 *   pointers advance by the actual shortened block span. Unequal alignment copies until source
 *   alignment, then snapshots four aligned words per block into byte stores, using1/2/3/0 order
 *   for the first three words and0/1/2/3 for the fourth. Its narrowed block count
 *   b=(remaining>>4)&65535 expands b=0 to0x10000000 iterations; otherwise b iterations. After that
 *   loop, residual pointers jump by the full untruncated remaining&~15 span, potentially leaving a
 *   hole. Remaining word snapshots store bytes0/1/2/3, then final bytes. Forward overlaps can
 *   overwrite future input; no backward copy, NULL/capacity/length guard, lock, cache or DMA
 *   synchronization. Raw unsigned32-bit address arithmetic and volatile accesses retain native
 *   memory widths/order and address wrap; callers must supply valid mapped storage. Oversize
 *   unsafe prefixes require separate analysis rather than completing their invalid transfers.
 */

void medius_copy_forward_words(uchar *destination,const uchar *source,uint length)
{
    uint destination_address = (uint)destination;
    uint source_address = (uint)source;
    if (((source_address ^ destination_address) & 3U) == 0) {
        while ((destination_address & 3U) != 0) {
            if (length == 0)
                return;
            uchar value = *(const volatile uchar *)source_address;
            *(volatile uchar *)destination_address = value;
            ++source_address;
            ++destination_address;
            --length;
        }
        if (length >= 16) {
            uint block_iterations = (((length - 16U) >> 4) & 0xffffU) + 1U;
            do {
                uint value = *(const volatile uint *)source_address;
                *(volatile uint *)destination_address = value;
                value = *(const volatile uint *)(source_address + 4U);
                *(volatile uint *)(destination_address + 4U) = value;
                value = *(const volatile uint *)(source_address + 8U);
                *(volatile uint *)(destination_address + 8U) = value;
                value = *(const volatile uint *)(source_address + 12U);
                *(volatile uint *)(destination_address + 12U) = value;
                source_address += 16U;
                destination_address += 16U;
            } while (--block_iterations != 0);
            length &= 15U;
        }
        if (length >= 4) {
            uint word_iterations = (((length - 4U) >> 2) & 0xffffU) + 1U;
            do {
                uint value = *(const volatile uint *)source_address;
                *(volatile uint *)destination_address = value;
                source_address += 4U;
                destination_address += 4U;
            } while (--word_iterations != 0);
            length &= 3U;
        }
    } else {
        if (length == 0)
            return;
        while ((source_address & 3U) != 0) {
            uchar value = *(const volatile uchar *)source_address;
            *(volatile uchar *)destination_address = value;
            ++source_address;
            ++destination_address;
            if (--length == 0)
                return;
        }
        if (length >= 16) {
            uint source_block = source_address;
            uint destination_block = destination_address;
            uint narrowed_blocks = (length >> 4) & 0xffffU;
            uint block_iterations = (((narrowed_blocks * 16U - 16U) >> 4) + 1U);
            do {
                /* First three word snapshots store bytes1/2/3/0; the fourth
                 * stores0/1/2/3. Preserve that native order even for overlaps. */
                uint value = *(const volatile uint *)(source_block + 0U);
                *(volatile uchar *)(destination_block + 1U) = (uchar)(value >> 8);
                *(volatile uchar *)(destination_block + 2U) = (uchar)(value >> 16);
                *(volatile uchar *)(destination_block + 3U) = (uchar)(value >> 24);
                *(volatile uchar *)(destination_block + 0U) = (uchar)value;
                value = *(const volatile uint *)(source_block + 4U);
                *(volatile uchar *)(destination_block + 5U) = (uchar)(value >> 8);
                *(volatile uchar *)(destination_block + 6U) = (uchar)(value >> 16);
                *(volatile uchar *)(destination_block + 7U) = (uchar)(value >> 24);
                *(volatile uchar *)(destination_block + 4U) = (uchar)value;
                value = *(const volatile uint *)(source_block + 8U);
                *(volatile uchar *)(destination_block + 9U) = (uchar)(value >> 8);
                *(volatile uchar *)(destination_block + 10U) = (uchar)(value >> 16);
                *(volatile uchar *)(destination_block + 11U) = (uchar)(value >> 24);
                *(volatile uchar *)(destination_block + 8U) = (uchar)value;
                value = *(const volatile uint *)(source_block + 12U);
                *(volatile uchar *)(destination_block + 12U) = (uchar)value;
                *(volatile uchar *)(destination_block + 13U) = (uchar)(value >> 8);
                *(volatile uchar *)(destination_block + 14U) = (uchar)(value >> 16);
                *(volatile uchar *)(destination_block + 15U) = (uchar)(value >> 24);
                source_block += 16U;
                destination_block += 16U;
            } while (--block_iterations != 0);
            /* Native tail addresses use the FULL span, even when the block
             * loop above narrowed its count or expanded zero to0x10000000. */
            uint full_block_span = length & 0xfffffff0U;
            source_address += full_block_span;
            destination_address += full_block_span;
            length &= 15U;
        }
        if (length >= 4) {
            uint word_iterations = length >> 2;
            do {
                uint value = *(const volatile uint *)source_address;
                *(volatile uchar *)destination_address = (uchar)value;
                *(volatile uchar *)(destination_address + 1U) = (uchar)(value >> 8);
                *(volatile uchar *)(destination_address + 2U) = (uchar)(value >> 16);
                *(volatile uchar *)(destination_address + 3U) = (uchar)(value >> 24);
                source_address += 4U;
                destination_address += 4U;
            } while (--word_iterations != 0);
            length &= 3U;
        }
    }
    while (length != 0) {
        uchar value = *(const volatile uchar *)source_address;
        *(volatile uchar *)destination_address = value;
        ++source_address;
        ++destination_address;
        --length;
    }
}

