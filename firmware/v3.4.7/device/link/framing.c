/* Medius v3.4.7 device — link/framing.c.
 * Recovered C and native assembly, grouped for source navigation.
 * Original entry addresses, firmware-byte hashes and function comments follow.
 */

#include "../include/types.h"

/* Native entry: 0x4037c9cc. */
/*
 * Medius v3.4.7 — device application; 0x4037c9cc.
 *
 * Encodes a link frame: A5, type, flags, 16-bit LE payload length, payload, then 16-bit LE CRC.
 *
 * Calls: crc16_update, memcpy.
 *
 * Called by: control_send_frame, FUN_42022a04, link_frame_enqueue, control_event_task,
 * link_transmit_task.
 *
 * Original function-byte SHA-256:
 * 03334fd54939de94878e1b8c749d5c60c2db424d498dfb0822cddc0653db1369.
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
    volatile unsigned char *wire = output;
    unsigned int payload_bytes = length;
    if (payload_bytes > 512U || capacity < payload_bytes + 8U)
        return -1;

    unsigned char crc_header[4] = {
        type, flags, (unsigned char)length, (unsigned char)(length >> 8)
    };
    unsigned short crc = crc16_update(0xffffU, crc_header, sizeof(crc_header));
    if (payload_bytes != 0)
        crc = crc16_update(crc, payload, payload_bytes);

    wire[0] = 0xa5U;
    if (payload_bytes == 0) {
        wire[1] = type;
        wire[2] = flags;
        wire[3] = 0;
        wire[4] = 0;
    } else {
        wire[4] = (unsigned char)(length >> 8);
        wire[1] = type;
        wire[2] = flags;
        wire[3] = (unsigned char)length;
        memcpy(output + 5, payload, payload_bytes);
    }
    wire[payload_bytes + 5U] = (unsigned char)crc;
    wire[payload_bytes + 6U] = (unsigned char)(crc >> 8);
    return (int)(payload_bytes + 7U);
}

/* Native entry: 0x4037ca80. */
/*
 * Medius v3.4.7 — device application; 0x4037ca80.
 *
 * Replaces a bounded range within an encoded frame payload and recomputes its CRC16.
 *
 * Calls: crc16_update, memcpy.
 *
 * Called by: link_uart_transmit_wait.
 *
 * Original function-byte SHA-256:
 * f1486025137601a207dba2708ab6346f109b74e8d6269fa6764eaaff07ace687.
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

    volatile unsigned char *wire = frame;
    unsigned int length_high = wire[4];
    unsigned int length_low = wire[3];
    unsigned int payload_bytes = length_low | (length_high << 8);
    if (payload_bytes + 7U != frame_length ||
        (unsigned int)payload_offset + patch_length > payload_bytes)
        return 0;

    memcpy(frame + 5U + payload_offset, patch, patch_length);
    unsigned short crc = crc16_update(0xffffU, frame + 1, payload_bytes + 4U);
    wire[payload_bytes + 5U] = (unsigned char)crc;
    wire[payload_bytes + 6U] = (unsigned char)(crc >> 8);
    return 1;
}

/* Native entry: 0x4037cacc. */
/*
 * Medius v3.4.7 — device application; 0x4037cacc.
 *
 * Consumes UART bytes through the A5/header/payload/CRC framing state machine and invokes a
 * callback for valid frames.
 *
 * Calls: crc16_update.
 *
 * Called by: control_uart_interrupt_handler, link_uart_interrupt_handler.
 *
 * Indirect call: parser->on_frame, using the five-argument frame callback ABI.
 *
 * Original function-byte SHA-256:
 * 26c358a1b389f772bd8f4b1bfb5014e3957443638a18c8f3aedde7c0c3459743.
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
 * CRC failures reset state silently. Length/count/CRC and timestamp fields
 * otherwise retain their last values. This function does not check timeouts.
 */
void link_parser_feed(LinkParser *parser, const unsigned char *data,
                              unsigned int length)
{
    if (length == 0)
        return;

    volatile LinkParser *state = parser;
    const unsigned char *end = data + length;
    do {
        unsigned int parser_state = state->state;
        unsigned char received_byte = *(const volatile unsigned char *)data;
        switch (parser_state) {
        case FRAME_WAIT_MARKER:
            if (received_byte == 0xa5U)
                state->state = FRAME_READ_TYPE;
            break;
        case FRAME_READ_TYPE:
            state->type = received_byte;
            state->state = FRAME_READ_FLAGS;
            break;
        case FRAME_READ_FLAGS:
            state->flags = received_byte;
            state->state = FRAME_READ_LENGTH_LOW;
            break;
        case FRAME_READ_LENGTH_LOW:
            state->payload_length = received_byte;
            state->state = FRAME_READ_LENGTH_HIGH;
            break;
        case FRAME_READ_LENGTH_HIGH: {
            unsigned short payload_length = state->payload_length |
                (unsigned short)((unsigned int)received_byte << 8);
            state->payload_length = payload_length;
            state->payload_used = 0;
            if (payload_length > sizeof(state->payload))
                state->state = FRAME_WAIT_MARKER;
            else
                state->state = payload_length == 0
                    ? FRAME_READ_CRC_LOW : FRAME_READ_PAYLOAD;
            break;
        }
        case FRAME_READ_PAYLOAD: {
            unsigned short payload_index = state->payload_used;
            unsigned short next_used = (unsigned short)(payload_index + 1U);
            state->payload_used = next_used;
            *(volatile unsigned char *)((unsigned int)parser + 24U + payload_index) = received_byte;
            if (next_used >= state->payload_length)
                state->state = FRAME_READ_CRC_LOW;
            break;
        }
        case FRAME_READ_CRC_LOW:
            state->received_crc = received_byte;
            state->state = FRAME_READ_CRC_HIGH;
            break;
        case FRAME_READ_CRC_HIGH: {
            unsigned short received_crc = state->received_crc |
                (unsigned short)((unsigned int)received_byte << 8);
            /* Native aligned WORD read of type, flags and little-endian length. */
            unsigned int header_word = *(const volatile unsigned int *)
                ((unsigned int)parser + 12U);
            state->received_crc = received_crc;
            unsigned short calculated_crc = crc16_update(0xffffU,
                (const unsigned char *)&header_word, sizeof(header_word));
            unsigned short payload_length = state->payload_length;
            if (payload_length != 0)
                calculated_crc = crc16_update(calculated_crc, parser->payload,
                                             payload_length);
            if (state->received_crc == calculated_crc) {
                FrameCallback callback = state->on_frame;
                if (callback != NULL) {
                    void *context = state->context;
                    unsigned short callback_length = state->payload_length;
                    unsigned char flags = state->flags;
                    unsigned char type = state->type;
                    callback(type, flags, parser->payload, callback_length, context);
                }
            }
            state->state = FRAME_WAIT_MARKER;
            break;
        }
        default:
            state->state = FRAME_WAIT_MARKER;
            break;
        }
        ++data;
    } while (data != end);
}

/* Native entry: 0x4037f08c. */
/*
 * Medius v3.4.7 — device application; 0x4037f08c.
 *
 * Resets framing state, payload length and received-byte count.
 *
 * Called by: control_uart_interrupt_handler, link_uart_interrupt_handler, link_baud_task.
 *
 * Original function-byte SHA-256:
 * a285fbfd37f39c122f501aec0007161effa83a7db694af9e279506e6eb59f335.
 */

/*
 * Abandons the current partial frame by resetting state, payload_used and
 * payload_length, in that order. parser must point to a writable parser.
 * Returns no value. Callback/context, type/flags, received CRC, payload bytes
 * and last receive timestamp are retained. No allocation, locking or clearing
 * of the payload buffer is performed.
 */
void link_parser_reset(LinkParser *parser)
{
    volatile LinkParser *state = parser;
    state->state = FRAME_WAIT_MARKER;
    state->payload_used = 0;
    state->payload_length = 0;
}

/* Native entry: 0x40396c70. */
/* Original function-byte SHA-256:
 * 340d933bae7874abded2f59f9f5a3d0a7a75043a1ab62d1297dbf608c0cfd77d.
 */

/*
 * packet/length: borrowed readable inter-chip report payload and 16-bit size.
 * Returns no value. Length < 6 returns without touching packet. Header is
 * endpoint +0, little-endian source stamp +1..4, flags +5. Stamp bytes are read
 * in native order 2,1,3,4; no unaligned word load is inferred.
 * Flag bit 0 with at least 26 remaining bytes copies an opaque 26-byte extension
 * to aligned local storage, advances report to +32, then reloads flags.
 * Otherwise report starts at +6 and extension is NULL, even if bit 0 was set.
 *
 * Reread endpoint and try secondary interception first. A handled result stops
 * processing. Otherwise reread flags THEN endpoint: bit 2 routes to primary
 * buffering; other reports reach the ordinary processor with the cached stamp,
 * borrowed local extension and flag bit 1. Callbacks must consume/copy borrowed
 * packet/extension data before returning. This decoder owns no lock, allocation,
 * clock or explicit fence; downstream route bodies provide their own behavior.
 */
void link_report_decode(unsigned char *packet,unsigned short length)
{
    if (length < 6)
        return;
    const volatile unsigned char *wire = packet;
    unsigned int byte2 = wire[2];
    unsigned int byte1 = wire[1];
    unsigned int byte3 = wire[3];
    unsigned int byte4 = wire[4];
    unsigned int source_stamp = byte1 | (byte2 << 8) | (byte3 << 16) | (byte4 << 24);
    unsigned short report_length = length - 6;
    unsigned int flags = wire[5];
    unsigned char *report = packet + 6;
    ReportExtension26 extension;
    unsigned short *extension_words = NULL;
    if (report_length >= 26 && (flags & 1U) != 0) {
        memcpy(&extension,report,26);
        report_length = length - 32;
        flags = wire[5];
        report = packet + 32;
        extension_words = extension.words;
    }
    unsigned int endpoint = wire[0];
    if (report_intercept_secondary(endpoint,source_stamp,report,report_length,flags) != 0)
        return;
    flags = wire[5];
    endpoint = wire[0];
    if ((flags & 4U) != 0)
        report_buffer_primary(endpoint,report,report_length);
    else
        report_process(endpoint,source_stamp,report,report_length,
            (const unsigned char *)extension_words,(flags >> 1) & 1U);
}

/* Native entry: 0x4200c4dc. */
/*
 * Medius v3.4.7 — device application; 0x4200c4dc.
 *
 * Clears the 536-byte parser object and installs its frame callback and context.
 *
 * Calls: memset.
 *
 * Called by: control_uart_init, link_init.
 *
 * Original function-byte SHA-256:
 * 041d5ab178c9cb55d8666adfb7d52de31870e8ac92652ed3e504b871c8830e6c.
 */

/*
 * Initializes parser by clearing its complete 536-byte object, then storing
 * callback, context and the marker-wait state. Returns no value.
 *
 * parser must be writable, exclusively owned storage of sizeof(*parser).
 * callback may be NULL; context is borrowed and passed through unchanged.
 * Clears payload, length/count, CRC, type/flags and receive timestamp.
 * No callback runs, memory is not allocated, and no lock is acquired.
 */
void link_parser_init(LinkParser *parser, FrameCallback callback,
                              void *context)
{
    volatile LinkParser *state = parser;
    memset(parser, 0, sizeof(*parser));
    state->on_frame = callback;
    state->context = context;
    state->state = FRAME_WAIT_MARKER;
}

/* Native entry: 0x4037f09c. */
/*
 * Medius v3.4.7 — device application; 0x4037f09c.
 *
 * Checks the time since the previous UART receive-gap sample.
 *
 * Called by: control_uart_interrupt_handler.
 *
 * Original function-byte SHA-256:
 * d84cda87533f20b22f6ce0dabe66fd405c3279d697acc6001485d6136b85d912.
 */

/*
 * Resets a partial frame if its sampled receive gap exceeds timeout_us.
 * parser: exclusively owned, initialized parser; now_us_low: low 32 bits of
 * the current microsecond clock; timeout_us: signed 32-bit threshold.
 * Returns no value. Always records now_us_low, even when already idle.
 *
 * Native subtraction wraps to 32 bits and the comparison is SIGNED (BGE).
 * Consequently a gap whose low-word difference has bit 31 set does not time
 * out against the normal positive threshold. Keep that behavior rather than
 * silently converting this to an unsigned elapsed-time comparison.
 *
 * On expiry clears state, payload_used and payload_length only. Callback,
 * context, type/flags, CRC and payload bytes are retained. No timer is armed:
 * the caller must invoke this when it wants a receive-gap sample checked.
 */
void link_parser_check_rx_gap(LinkParser *parser,
                                     unsigned int now_us_low, int timeout_us)
{
    volatile LinkParser *state = parser;
    if (state->state != FRAME_WAIT_MARKER) {
        int elapsed_us = (int)(now_us_low - state->last_rx_time_us_low);
        if (elapsed_us > timeout_us) {
            state->state = FRAME_WAIT_MARKER;
            state->payload_used = 0;
            state->payload_length = 0;
        }
    }
    state->last_rx_time_us_low = now_us_low;
}
