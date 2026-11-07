/* Medius v3.4.7 device — compact/fragment reply delivery and cancellation. */
#include "../include/types.h"

/* Native entry: 0x4039687c. */
/* Original function-byte SHA-256:
 * 49c4ac23675a03494d7cda44ffcab980e167b0a0b5366da381ebe94f32e79aef. */
/*
 * Accept a compact reply only while waiting and the low-byte sequence matches.
 * Read waiting after MEMW; when nonzero, MEMW/read the sequence EVEN for length
 * zero, then reject zero length or mismatched sequence without touching payload.
 * Sign-extend response[0] into the 32-bit status; copy min(length-1,2048) bytes
 * from response+1, including a zero-length copy for length1. MEMW precedes the
 * status store, not the first payload read. After copying, capture the signal
 * handle BEFORE MEMW/publishing the 16-bit data length, then give it through
 * xQueueGenericSend(NULL item,0 wait,back), ignoring the return value.
 * No handle/payload validation, waiting clear, cancellation/generation check,
 * assembly reset, retry or lock; a queued token can already be present.
 */
void ep0_accept_short_reply(unsigned char sequence,
                                  const unsigned char *response, unsigned short length)
{
    memw();
    unsigned char waiting = MEDIUS_EP0_REPLY_CHANNEL->waiting;
    if (waiting == 0) return;
    memw();
    unsigned char expected_sequence = MEDIUS_EP0_REPLY_CHANNEL->sequence;
    if (length == 0 || expected_sequence != sequence) return;
    unsigned int payload_length = (unsigned short)(length - 1U);
    if (payload_length > 2048U) payload_length = 2048U;
    int status = (signed char)response[0];
    memw();
    MEDIUS_EP0_REPLY_STORAGE->status = status;
    memcpy(MEDIUS_EP0_REPLY_STORAGE->payload, response + 1, payload_length);
    RtosQueue *signal = MEDIUS_EP0_REPLY_CHANNEL->signal;
    memw();
    MEDIUS_EP0_REPLY_STORAGE->length = (unsigned short)payload_length;
    (void)xQueueGenericSend(signal, NULL, 0, 0);
}

/* Native entry: 0x403968f4. */
/* Original function-byte SHA-256:
 * ee1c968dcdc532259166b9ee5936db88a246dab455f920654b6369b89316172a. */
/*
 * Same waiting/sequence gates as compact replies, then pass the low16 length
 * to the shared fragment assembler without a local zero-length shortcut.
 * An incomplete/rejected assembly returns without signalling. On completion,
 * read its total HALFWORD at+2058. A zero total captures the signal handle,
 * MEMW/stores status -1 and gives the signal, leaving old payload/length intact.
 * Otherwise sign-extend assembled payload[0], MEMW/publish status, copy at most
 * 2048 following bytes, capture signal, MEMW/publish length and give it.
 * No waiting clear, generation/cancellation recheck, independent lock, explicit
 * assembly reset or check of the queue-send result. Assembler side effects are
 * those of the separately reviewed control_fragment_accept function.
 */
void ep0_accept_fragmented_reply(unsigned char sequence,
                                       const unsigned char *fragment, unsigned short length)
{
    memw();
    unsigned char waiting = MEDIUS_EP0_REPLY_CHANNEL->waiting;
    if (waiting == 0) return;
    memw();
    unsigned char expected_sequence = MEDIUS_EP0_REPLY_CHANNEL->sequence;
    if (expected_sequence != sequence) return;
    ControlAssembly *assembly = MEDIUS_EP0_FRAGMENT_ASSEMBLY;
    if (control_fragment_accept(assembly, fragment, length) == 0) return;
    unsigned short total = ((volatile ControlAssembly *)assembly)->total;
    if (total == 0) {
        RtosQueue *signal = MEDIUS_EP0_REPLY_CHANNEL->signal;
        memw();
        MEDIUS_EP0_REPLY_STORAGE->status = -1;
        (void)xQueueGenericSend(signal, NULL, 0, 0);
        return;
    }
    unsigned int payload_length = (unsigned short)(total - 1U);
    if (payload_length > 2048U) payload_length = 2048U;
    int status = (signed char)((volatile ControlAssembly *)assembly)->payload[0];
    memw();
    MEDIUS_EP0_REPLY_STORAGE->status = status;
    memcpy(MEDIUS_EP0_REPLY_STORAGE->payload, assembly->payload + 1, payload_length);
    RtosQueue *signal = MEDIUS_EP0_REPLY_CHANNEL->signal;
    memw();
    MEDIUS_EP0_REPLY_STORAGE->length = (unsigned short)payload_length;
    (void)xQueueGenericSend(signal, NULL, 0, 0);
}

/* Native entry: 0x40396c20. */
/* Original function-byte SHA-256:
 * cf5243e643da474aa902c280bf3dfef35ae82cd012f6ba997827ebfa515b9876. */
/*
 * Snapshot current clone generation into the request generation (MEMW/read,
 * MEMW/write), then MEMW/read waiting. If waiting and signal handle are both
 * nonzero, retain that handle, MEMW/set cancelled=1, MEMW/clear waiting, and
 * give the semaphore from ISR with a zero-initialized local wake flag. Request
 * a switch only when that flag becomes nonzero; ignore the give return value.
 * The generation snapshot occurs even when nothing waits. A NULL signal keeps
 * waiting/cancelled unchanged. No queue drain, status/length/payload update,
 * fragment reset, inter-core lock or caller-context test is performed here.
 */
void medius_ep0_cancel_pending_reply(void)
{
    memw();
    unsigned int generation = DEVICE_OUT_GENERATION;
    memw();
    MEDIUS_EP0_REPLY_LIFETIME->request_generation = generation;
    memw();
    unsigned char waiting = MEDIUS_EP0_REPLY_CHANNEL->waiting;
    if (waiting == 0) return;
    RtosQueue *signal = MEDIUS_EP0_REPLY_CHANNEL->signal;
    if (signal == NULL) return;
    memw();
    MEDIUS_EP0_REPLY_LIFETIME->cancelled = 1;
    memw();
    MEDIUS_EP0_REPLY_CHANNEL->waiting = 0;
    int higher_priority_task_woken = 0;
    (void)xQueueGiveFromISR(signal, &higher_priority_task_woken);
    if (higher_priority_task_woken != 0) _frxt_setup_switch();
}
