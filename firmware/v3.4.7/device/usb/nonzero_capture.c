/* Medius v3.4.7 device — medius_capture_nonzero_control. */
#include "../include/types.h"

/* Native entry: 0x40392ab0. */
/* Original function-byte SHA-256:
 * 94609c0229ba6be209d264d10e375d9628a9b18db0114dde53954494e8f67df2. */
/*
 * Adapt a borrowed nonzero-control capture to the shared builder with class8.
 * Supply separate224-byte scratch and192-byte output stack areas without
 * initialization. Forward endpoint WORD, setup/payload pointers, direction and
 * flags BYTEs and length HALFWORD; the builder owns filtering/copying/emission.
 * No validation, persistent state, lock or local branching. Return no value.
 * Both temporary regions expire on return; the callee must finish using them
 * synchronously. The shared builder owns filtering and wire emission.
 */
void medius_capture_nonzero_control(unsigned int endpoint,unsigned char *setup,
    unsigned char direction_out,unsigned char flags,unsigned char *payload,unsigned short length)
{
    MediusControlCaptureWorkspace workspace;
    medius_capture_control_build(8,endpoint,setup,direction_out,flags,
        payload,length,workspace.scratch,workspace.output);
}
