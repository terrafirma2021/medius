/* Medius v3.4.7 device — EP0 and nonzero-control fragment transmit callbacks. */
#include "../include/types.h"

/* Native entry: 0x4202842c. */
/* Original function-byte SHA-256:
 * ca19af8d82d26dddc19837c476f51772d3ae6b9b645dbe35b71f0c416bbbbffc. */
/*
 * Send a borrowed control fragment as link opcode0x19. fragment is passed
 * unchanged; length contributes its low16 bits; sequence_pointer must address
 * a readable BYTE loaded before transport is called. No local validation,
 * payload mutation or retention occurs. Return no value and discard the send
 * result; transport owns its copying, wait and lifetime behavior.
 */
void medius_ep0_send_request_fragment(const unsigned char *fragment,
    unsigned short length, void *sequence_pointer)
{
    unsigned char sequence = *(const volatile unsigned char *)sequence_pointer;
    link_send_wait100(0x19, sequence, fragment, length);
}

/* Native entry: 0x42028444. */
/* Original function-byte SHA-256:
 * 032675c644226bf4d12a749e97e691f7db346fdfb90d00216b36ca0cb218d421. */
/*
 * Send a borrowed nonzero-control fragment as link opcode0x22. Read the BYTE
 * sequence from sequence_pointer, pass fragment unchanged with the low16 length,
 * and discard the transport result. Return no value. No local bounds/NULL
 * checks, payload changes, retry or retained pointer; transport owns its waits
 * and copying. Context and fragment must remain valid during the call.
 */
void medius_nonzero_send_request_fragment(const unsigned char *fragment,
    unsigned short length, void *sequence_pointer)
{
    unsigned char sequence = *(const volatile unsigned char *)sequence_pointer;
    link_send_wait100(0x22, sequence, fragment, length);
}
