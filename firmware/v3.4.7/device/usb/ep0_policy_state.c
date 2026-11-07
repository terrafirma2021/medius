/* Medius v3.4.7 device — native policy pointer/mask and BOS queries. */
#include "../include/types.h"

/* Native entry: 0x40396a9c. */
/* Original function-byte SHA-256:
 * ce8a3d01b09dfbdf2060f27747cecd80f9e4db859da107f629d01702ba23fee5. */
/* Return the raw SET_INTERFACE stall mask with a single unsigned HALFWORD
 * load. No MEMW, normalization, mask evaluation, lock or state update; the
 * standard classifier evaluates the selected bits using the request index. */
unsigned short medius_ep0_get_set_interface_stall_mask(void)
{
    return MEDIUS_EP0_POLICY_MASKS->set_interface_stall_mask;
}

/* Native entry: 0x40396ab0. */
/* Original function-byte SHA-256:
 * ff8cddc0ba9c20dd9594e3054077f60dbad469fd9e30cb4050b8a8521bda6d6d. */
/* Return the raw endpoint GET_STATUS stall mask with a single unsigned HALFWORD
 * load. No MEMW, normalization, mask evaluation, lock or state update; the
 * standard classifier evaluates the selected bits using the request index. */
unsigned short medius_ep0_get_endpoint_status_stall_mask(void)
{
    return MEDIUS_EP0_POLICY_MASKS->endpoint_status_stall_mask;
}

/* Native entry: 0x40396abc. */
/* Original function-byte SHA-256:
 * 9126d2e59d1270aac4eb9631a036b1d6a389a93e3ec1d32827727f27c5b0ed58. */
/* Return the raw unavailable-interface default-route mask with a single unsigned HALFWORD
 * load. No MEMW, normalization, mask evaluation, lock or state update; the
 * standard classifier evaluates the selected bits using the request index. */
unsigned short medius_ep0_get_missing_interface_default_mask(void)
{
    return MEDIUS_EP0_POLICY_MASKS->missing_interface_default_mask;
}

/* Native entry: 0x40396aa8. */
/* Original function-byte SHA-256:
 * 75bb760d59408078647561703a8362c50818d89f959282c4ecfc17228c4cde05. */
/* Return the fixed mutable request-policy address 0x3fccf3f8. The const view
 * documents this accessor's read-only use; no policy BYTE is actually loaded,
 * allocated, copied or validated, and no MEMW or synchronization occurs. */
const volatile MediusEp0RequestPolicy *medius_ep0_get_request_policy(void)
{
    return MEDIUS_EP0_REQUEST_POLICY;
}

/* Native entry: 0x40399cfc. */
/* Original function-byte SHA-256:
 * 2a876c6cb8e89d1080d0a272829f9f0ffff86dc9c457abe0caf139c14c5e212b. */
/* Load the BOS-presence WORD once and return exactly whether it is nonzero.
 * No descriptor dereference, size/content validation, MEMW or state update. */
bool medius_clone_has_bos_descriptor(void)
{
    return QUERY_BOS_PRESENT != 0;
}
