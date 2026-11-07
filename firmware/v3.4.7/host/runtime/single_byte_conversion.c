/* Medius v3.4.7 host: single-byte/16-bit character conversions. */
#include "../include/types.h"

/* Native entry: 0x4201ee30. */
/* Original function-byte SHA-256:
 * f15f75179cadb97cb937b474cf39191293d3b422752bdb9ac4255743f9124c90. */
/* Ignore context. Use a private halfword when output is null. Null input
 * returns 0 without reading/storing a character; nonnull input with available
 * count 0 returns -2. Otherwise load one unsigned byte, store it as one unsigned
 * halfword, then reload input byte 0 and return 0 for NUL or 1 otherwise.
 * The second read is retained when input/output alias or memory changes.
 * Any nonzero count permits this single-byte operation. No encoding/state
 * validation, errno update, output extent check or multibyte accumulation. */
int medius_single_byte_decode_u16(void *unused_context,volatile unsigned short *output,
    const volatile unsigned char *input,unsigned int available)
{
    (void)unused_context;
    volatile unsigned short scratch;
    volatile unsigned short *destination = output != 0 ? output : &scratch;
    if (input == 0)
        return 0;
    if (available == 0)
        return -2;
    unsigned int character = *input;
    *destination = (unsigned short)character;
    return *input == 0 ? 0 : 1;
}

/* Native entry: 0x4201ee50. */
/* Original function-byte SHA-256:
 * c0dca5a77a02895a080d77da59f560a54aca82be8205b64227d8f315a79b57ba. */
/* Retain only the input low halfword. Null output returns 0 without checking
 * its range or accessing context. For values 0..255 store one byte and return
 * 1, including NUL. Larger values set reent errno 138 (EILSEQ), leave output
 * untouched and return -1. No context validation, multibyte expansion, state,
 * output-length argument or terminator beyond the single requested character. */
int medius_single_byte_encode_u16(NewlibReent *reent,volatile unsigned char *output,
    unsigned short character)
{
    if (output == 0)
        return 0;
    if (character > 255) {
        reent->error_number = 138;
        return -1;
    }
    *output = (unsigned char)character;
    return 1;
}
