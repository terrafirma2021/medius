/* Medius v3.4.7 device — link_enqueue_nowait_silent. */
#include "../include/types.h"

/* Native entry: 0x420229e8. */
/* Original function-byte SHA-256:
 * 1989be86c38539c7ae2b1c087ac92da52572dd090ba6bbf81a41d10537099f80. */
/*
 * Enqueue a borrowed link frame with wait_ticks0 and suppress_drop_log1.
 * Forward opcode/metadata low BYTEs, unchanged payload pointer and low16 length;
 * return the enqueue result WORD unchanged. No validation, copying, retry,
 * readiness wait or ISR adaptation is performed here. This four-argument
 * boundary includes payload/length that Ghidra omitted from one caller.
 * The reviewed underlying enqueue function owns encoding and buffer lifetime.
 */
unsigned int link_enqueue_nowait_silent(unsigned char opcode,
    unsigned char metadata,void *payload,unsigned short length)
{
    return link_frame_enqueue(opcode,metadata,payload,length,0,1);
}
