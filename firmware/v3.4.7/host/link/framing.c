/* Medius v3.4.7 host — link/framing.c.
 * Recovered C and native assembly, grouped for source navigation.
 * Original entry addresses, firmware-byte hashes and function comments follow.
 */

#include "../include/types.h"

/* Native entry: 0x4037b6f4. */
/*
 * Medius v3.4.7 — host application; 0x4037b6f4.
 *
 * Encodes a link frame: A5, type, flags, 16-bit LE payload length, payload, then 16-bit LE CRC.
 *
 * Calls: crc16_update, memcpy.
 *
 * Called by: FUN_4037b688, FUN_42021a54, link_frame_enqueue, link_transmit_task.
 *
 * Original function-byte SHA-256:
 * b84534be160d509472eb780baf4766690a09ba0638184ae650ca6be1bba72b88.
 */

/*
 * Encodes A5 | type:u8 | flags:u8 | length:u16le | payload | CRC:u16le.
 * output: writable capacity-byte destination, not overlapping payload.
 * capacity: unsigned byte capacity; type/flags: the two frame header bytes.
 * payload: readable length-byte source, unused when length is zero.
 * length: native input narrows to16 bits before checks and CRC processing.
 *
 * Returns length+7 on success, or -1 if length>512 or capacity<length+8.
 * The capacity check intentionally requires one more byte than is written.
 * Rejection leaves output untouched. Successful encoding writes exactly
 * length+7 bytes; spare capacity is not cleared.
 *
 * CRC is seeded with0xffff, covers the four bytes after A5 followed by the
 * payload, and is stored little-endian without a final XOR. Calculates CRC
 * before writing the header, copies a nonempty payload with memcpy, then
 * writes CRC low/high bytes. No callback, allocation, lock or transmission.
 */
int link_frame_encode(unsigned char *output, unsigned int capacity,
                              unsigned char type, unsigned char flags,
                              const void *payload, unsigned short length)
{
    unsigned int payload_bytes = length;
    if (payload_bytes > 512U || capacity < payload_bytes + 8U)
        return -1;

    unsigned char crc_header[4] = {
        type, flags, (unsigned char)length, (unsigned char)(length >> 8)
    };
    unsigned short crc = crc16_update(0xffffU, crc_header, sizeof(crc_header));
    if (payload_bytes != 0)
        crc = crc16_update(crc, payload, payload_bytes);

    output[0] = 0xa5U;
    if (payload_bytes == 0) {
        output[1] = type;
        output[2] = flags;
        output[3] = 0;
        output[4] = 0;
    } else {
        output[4] = (unsigned char)(length >> 8);
        output[1] = type;
        output[2] = flags;
        output[3] = (unsigned char)length;
        memcpy(output + 5, payload, payload_bytes);
    }
    output[payload_bytes + 5U] = (unsigned char)crc;
    output[payload_bytes + 6U] = (unsigned char)(crc >> 8);
    return (int)(payload_bytes + 7U);
}

/* Native entry: 0x4037b7a8. */
/*
 * Medius v3.4.7 — host application; 0x4037b7a8.
 *
 * Replaces a bounded range within an encoded frame payload and recomputes its CRC16.
 *
 * Calls: crc16_update, memcpy.
 *
 * Called by: link_uart_transmit_wait.
 *
 * Original function-byte SHA-256:
 * 654204a99d1f683958f41b2254120b6b06b5d38c0d0a1db426a626462dbf1321.
 */

/*
 * Replaces a bounded range in an encoded frame and recomputes its CRC.
 * frame: writable frame_length-byte buffer; frame_length: complete byte size.
 * payload_offset/patch_length: native arguments narrow to16 bits at entry.
 * patch: readable patch_length-byte source, not overlapping the destination.
 *
 * Returns0 without writes when frame_length<7, the encoded length plus7
 * disagrees with frame_length, or offset+patch_length exceeds that payload
 * length. Otherwise memcpy patches at frame+5+offset, recomputes CRC over
 * type/flags/length/payload from seed0xffff, stores its low/high bytes, returns1.
 * A zero-byte patch still invokes memcpy and recomputes/stores the checksum.
 *
 * Checks neither the A5 marker nor the existing CRC and does not impose the
 * encoder's512-byte payload limit. Requires exclusive ownership of the frame
 * and valid source/destination ranges. No allocation, locking or transmission.
 */
int link_frame_patch_payload(unsigned char *frame, unsigned int frame_length,
                                     unsigned short payload_offset, const void *patch,
                                     unsigned short patch_length)
{
    if (frame_length < 7U)
        return 0;

    unsigned int payload_bytes =
        (unsigned int)frame[3] | ((unsigned int)frame[4] << 8);
    if (payload_bytes + 7U != frame_length ||
        (unsigned int)payload_offset + patch_length > payload_bytes)
        return 0;

    memcpy(frame + 5U + payload_offset, patch, patch_length);
    unsigned short crc = crc16_update(0xffffU, frame + 1, payload_bytes + 4U);
    frame[payload_bytes + 5U] = (unsigned char)crc;
    frame[payload_bytes + 6U] = (unsigned char)(crc >> 8);
    return 1;
}

/* Native entry: 0x4037b7f4. */
/*
 * Medius v3.4.7 — host application; 0x4037b7f4.
 *
 * Consumes UART bytes through the A5/header/payload/CRC framing state machine and invokes a
 * callback for valid frames.
 *
 * Calls: crc16_update.
 *
 * Called by: link_uart_interrupt_handler.
 *
 * Indirect call: parser->on_frame(type, flags, payload, length, context).
 *
 * Original function-byte SHA-256:
 * d9ac9ff1b04826ea1f17fb6bbd4bc42e8c546f843b769e59e1d56c734d26c69c.
 */

/*
 * Consumes length bytes from data through an eight-state A5 framing parser.
 * A frame is A5 | type:u8 | flags:u8 | length:u16le | payload | CRC:u16le.
 * CRC starts at 0xffff and covers type, flags, length and payload, not A5.
 *
 * parser: initialized, exclusively owned state with a 512-byte payload array.
 * data: readable input of length bytes; not read when length is zero.
 * Returns no value. Partial frames are retained across calls.
 *
 * Declared lengths above 512 discard that header and resume marker search on
 * the next byte. A zero-length frame proceeds directly to its CRC. Invalid
 * state values discard the current byte and reset marker search. There is no
 * byte escaping or immediate reinterpretation of a rejected byte as A5.
 *
 * A matching CRC invokes the optional five-argument callback synchronously,
 * lending the parser's payload buffer until return. The state remains
 * READ_CRC_HIGH during that call and is unconditionally reset afterward;
 * recursive feeding or concurrent mutation of this parser is not supported.
 * CRC failures reset state silently. Length/count/CRC and the four bytes at +0x14
 * otherwise retain their last values. This function does not check timeouts.
 */
void link_parser_feed(LinkParser *parser, const unsigned char *data,
                              unsigned int length)
{
    if (length == 0)
        return;

    const unsigned char *end = data + length;
    do {
        unsigned char received_byte = *data;
        switch (parser->state) {
        case FRAME_WAIT_MARKER:
            if (received_byte == 0xa5U)
                parser->state = FRAME_READ_TYPE;
            break;
        case FRAME_READ_TYPE:
            parser->type = received_byte;
            parser->state = FRAME_READ_FLAGS;
            break;
        case FRAME_READ_FLAGS:
            parser->flags = received_byte;
            parser->state = FRAME_READ_LENGTH_LOW;
            break;
        case FRAME_READ_LENGTH_LOW:
            parser->payload_length = received_byte;
            parser->state = FRAME_READ_LENGTH_HIGH;
            break;
        case FRAME_READ_LENGTH_HIGH:
            parser->payload_length |= (unsigned short)((unsigned int)received_byte << 8);
            parser->payload_used = 0;
            if (parser->payload_length > sizeof(parser->payload))
                parser->state = FRAME_WAIT_MARKER;
            else
                parser->state = parser->payload_length == 0
                    ? FRAME_READ_CRC_LOW : FRAME_READ_PAYLOAD;
            break;
        case FRAME_READ_PAYLOAD: {
            unsigned short payload_index = parser->payload_used;
            parser->payload_used = (unsigned short)(payload_index + 1U);
            parser->payload[payload_index] = received_byte;
            if (parser->payload_used >= parser->payload_length)
                parser->state = FRAME_READ_CRC_LOW;
            break;
        }
        case FRAME_READ_CRC_LOW:
            parser->received_crc = received_byte;
            parser->state = FRAME_READ_CRC_HIGH;
            break;
        case FRAME_READ_CRC_HIGH: {
            unsigned char header[4] = {
                parser->type, parser->flags,
                (unsigned char)parser->payload_length,
                (unsigned char)(parser->payload_length >> 8)
            };
            parser->received_crc |= (unsigned short)((unsigned int)received_byte << 8);
            unsigned short calculated_crc = crc16_update(0xffffU, header, sizeof(header));
            if (parser->payload_length != 0)
                calculated_crc = crc16_update(calculated_crc, parser->payload,
                                                      parser->payload_length);
            if (parser->received_crc == calculated_crc && parser->on_frame != 0)
                parser->on_frame(parser->type, parser->flags, parser->payload,
                                   parser->payload_length, parser->context);
            parser->state = FRAME_WAIT_MARKER;
            break;
        }
        default:
            parser->state = FRAME_WAIT_MARKER;
            break;
        }
        ++data;
    } while (data != end);
}

/* Native entry: 0x4037d784. */
/*
 * Medius v3.4.7 — host application; 0x4037d784.
 *
 * Resets framing state, payload length and received-byte count.
 *
 * Called by: link_uart_interrupt_handler, link_baud_task.
 *
 * Original function-byte SHA-256:
 * a285fbfd37f39c122f501aec0007161effa83a7db694af9e279506e6eb59f335.
 */

/*
 * Abandons the current partial frame by resetting state, payload_used and
 * payload_length, in that order. parser must point to a writable parser.
 * Returns no value. Callback/context, type/flags, received CRC, payload bytes
 * and the four-byte slot at +0x14 are retained. No allocation, locking or clearing
 * of the payload buffer is performed.
 */
void link_parser_reset(LinkParser *parser)
{
    parser->state = FRAME_WAIT_MARKER;
    parser->payload_used = 0;
    parser->payload_length = 0;
}

/* Native entry: 0x4200f6a4. */
/*
 * Medius v3.4.7 — host application; 0x4200f6a4.
 *
 * Clears the 536-byte parser object and installs its frame callback and context.
 *
 * Calls: memset.
 *
 * Called by: link_init.
 *
 * Original function-byte SHA-256:
 * dbf78735fbe688b78b57e6746c9e290d655473ecca1f395a38ff6e9f3dab3b80.
 */

/*
 * Initializes parser by clearing its complete 536-byte object, then storing
 * callback, context and the marker-wait state. Returns no value.
 *
 * parser must be writable, exclusively owned storage of sizeof(*parser).
 * callback may be NULL; context is borrowed and passed through unchanged.
 * Clears payload, length/count, CRC, type/flags and the four-byte slot at +0x14.
 * No callback runs, memory is not allocated, and no lock is acquired.
 */
void link_parser_init(LinkParser *parser, FrameCallback callback,
                              void *context)
{
    memset(parser, 0, sizeof(*parser));
    parser->on_frame = callback;
    parser->context = context;
    parser->state = FRAME_WAIT_MARKER;
}

