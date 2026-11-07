/* Medius v3.4.7 device — platform/bytes.c.
 * Recovered C and native assembly, grouped for source navigation.
 * Original entry addresses, firmware-byte hashes and function comments follow.
 */

#include "../include/types.h"

/* Native entry: 0x4037d198. */
/*
 * Medius v3.4.7 — device application; 0x4037d198.
 *
 * Updates a non-reflected CRC-16 using polynomial 0x1021; returns the accumulator.
 *
 * Called by: link_frame_patch_payload, link_frame_encode, link_parser_feed.
 *
 * Original function-byte SHA-256:
 * 9f646bcb04ad263d658f73a84940837d8c88536287bc4b1b82aaceb0dc5386f5.
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

