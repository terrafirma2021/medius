/* Medius v3.4.7 device — parsed auxiliary endpoint collection. */
#include "../include/types.h"

/* Native entry: 0x42039af4. */
/* Original function-byte SHA-256:
 * 5800568226822f69cc85e6ab541b7d889c5837b62ff43e0f1c9cf4aa68759dee. */
/*
 * Collect a non-primary endpoint in the116-byte parsed-configuration view.
 * Endpoint low7 zero returns without state access. Type low2==1 sets only the
 * isochronous BYTE. Bulk/interrupt scan signed-positive endpoint count for
 * exact full-WORD address equality with stored BYTEs; duplicate or count==12
 * sets conflict. Reject a low7 collision with first/second control endpoint.
 * Append address OR(type<<8) HALFWORD, min(unsigned MPS,64) HALFWORD and zero
 * HALFWORD at+4, retaining+6/+7; publish wrapping WORD count+1, then bulk BYTE1
 * only for type2. Raw address high bits may pollute the stored type byte.
 *
 * Type0 ignores a matching control low7 number before checking collisions or
 * capacity. Otherwise scan signed-positive noncontrol count for low7 equality,
 * ignoring direction; a collision or control count==2 sets conflict. Append
 * low7 address BYTE and min(MPS,64) HALFWORD, then wrapping control count WORD.
 * Never clear flags. Equality caps do not validate negative/oversized counts:
 * raw32 address arithmetic deliberately retains native out-of-view accesses.
 * No calls, locks, pointer checks, clamp repair or USB register accesses.
 */
void medius_clone_collect_aux_endpoint(MediusCloneAuxEndpointState *storage,
    unsigned int endpoint_address,unsigned int attributes,unsigned int maximum_packet_size)
{
    unsigned int endpoint_number = endpoint_address & 0x7fU;
    if (endpoint_number == 0)
        return;
    volatile MediusCloneAuxEndpointState *state = storage;
    unsigned int type = attributes & 3U;
    if (type == 1) {
        state->has_isochronous = 1;
        return;
    }
    if (type != 0) {
        int count = state->endpoint_count;
        if (count > 0) {
            for (unsigned int index = 0; index < (unsigned int)count; ++index) {
                unsigned int address = *(const volatile unsigned char *)
                    ((unsigned int)storage + index * 8U);
                if (address == endpoint_address)
                    goto conflict;
            }
            if (count == 12)
                goto conflict;
        }
        int control_count = state->control_count;
        if (control_count > 0) {
            if (state->control_endpoint[0] == endpoint_number)
                goto conflict;
            if (control_count != 1 && state->control_endpoint[1] == endpoint_number)
                goto conflict;
        }
        volatile MediusCloneAuxEndpoint *record = (volatile MediusCloneAuxEndpoint *)
            ((unsigned int)storage + (unsigned int)count * 8U);
        record->address_and_type = (unsigned short)(endpoint_address | (type << 8));
        record->max_packet = (unsigned short)(maximum_packet_size < 64U ? maximum_packet_size : 64U);
        record->cleared4 = 0;
        state->endpoint_count = (int)((unsigned int)count + 1U);
        if (type == 2)
            state->has_bulk = 1;
        return;
    }
    int control_count = state->control_count;
    if (control_count > 0) {
        if (state->control_endpoint[0] == endpoint_number)
            return;
        if (control_count != 1 && state->control_endpoint[1] == endpoint_number)
            return;
    }
    int count = state->endpoint_count;
    if (count > 0) {
        for (unsigned int index = 0; index < (unsigned int)count; ++index) {
            unsigned int address = *(const volatile unsigned char *)
                ((unsigned int)storage + index * 8U);
            if (((endpoint_address ^ address) & 0x7fU) == 0)
                goto conflict;
        }
    }
    if (control_count == 2)
        goto conflict;
    *(volatile unsigned char *)((unsigned int)storage + 100U + (unsigned int)control_count) =
        (unsigned char)endpoint_number;
    *(volatile unsigned short *)((unsigned int)storage + 102U + (unsigned int)control_count * 2U) =
        (unsigned short)(maximum_packet_size < 64U ? maximum_packet_size : 64U);
    state->control_count = (int)((unsigned int)control_count + 1U);
    return;
conflict:
    state->conflict = 1;
}
