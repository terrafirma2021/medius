/* Device control event storage and selection. */

#include "../include/types.h"

/* Native entry: 0x4203347c. */
/* Original function-byte SHA-256:
 * 240d4d3bbe4def79c11a46ed38380aae71b9875140f254eb4fe06dfd290930a6. */
/* MEMW then read the live reset-generation WORD. No increment, lock,
 * snapshot of associated state or calls; comparison is the event task's job. */
unsigned int control_event_generation(void)
{
    memw();
    return CONTROL_EVENT_GENERATION;
}


/* Native entry: 0x420389a4. */
/* Original function-byte SHA-256:
 * 0b01a34714b34ff7ff197f4e67198c2032d3cdfc69c551655ed63639121bfa80. */
/* Store the borrowed event-consumer task handle into the same slot used by
 * capture notifications. NULL disables that destination. No lock, MEMW,
 * notification, allocation, handle validation or lifetime ownership. */
void control_event_set_task(RtosTask *task)
{
    CAPTURE_TASK = task;
}


/* Native entry: 0x420389b0. */
/* Original function-byte SHA-256:
 * 78bd3891918401bc8b9def98a61e48a90dd660fa259c31cad248e2d446a5d3c4. */
/* Forward four output pointers unchanged and LOW8 pressure to event
 * selection; return its complete32-bit result. Direct inputs such as0x100
 * become pressure0. No local output initialization, lock, bounds or copy. */
int control_event_take(unsigned char *opcode,unsigned char *sequence,
    void *payload,unsigned short *length,unsigned int pressure)
{
    return control_event_select(opcode,sequence,payload,length,
        (unsigned char)pressure);
}


/* Native entry: 0x420294e4. */
/* Original function-byte SHA-256:
 * 9c0eddcaf72533c9652379b39b423f18fc24ac02707b6a13fe9fa655ccea00f5. */
/* Scan four event rings in fixed priority order. Count prechecks are
 * unlocked HALFWORD reads; a possible item is popped under the shared spinlock,
 * with no retry if that ring became empty. Any full-word skip_last_ring!=0
 * stops BEFORE ring4's count read. Initial strides/capacities are132/32,
 * 80/32,196/8,80/32, proven by the image's four12-byte descriptors.
 * On success read opcode and declared length from the stack record; write
 * opcode, then length, copy EXACT declared length from its payload, then
 * increment shared sequence BYTE before writing its saved old value to output.
 * The sequence is allocated outside the ring lock. Return1; no item returns0
 * without touching outputs. No fairness, NULL/capacity checks or ownership pin.
 * Native flaw retained: ring_pop may shorten a malformed item's copy without
 * fixing its copied length field. This function trusts that header, so malformed
 * stored lengths can read beyond the local192-byte payload and overflow caller
 * storage. Requires valid ring records/output capacity; no repair is invented. */
int control_event_select(unsigned char *opcode,unsigned char *sequence,
    void *payload,unsigned short *length,int skip_last_ring)
{
    ControlEventRecord item;
    for (unsigned int index = 0; index < 4; ++index) {
        if (index == 3 && skip_last_ring != 0)
            return 0;
        ControlEventRing *ring = &CONTROL_EVENT_RINGS[index];
        if (ring->count == 0)
            continue;
        (void)xPortEnterCriticalTimeout(CONTROL_EVENT_LOCK,-1);
        int popped = control_event_ring_pop(ring,&item);
        vPortExitCritical(CONTROL_EVENT_LOCK);
        if (popped == 0)
            continue;
        unsigned char item_opcode = item.opcode;
        unsigned short declared_length = item.length;
        *opcode = item_opcode;
        *length = declared_length;
        memcpy(payload,item.payload,declared_length);
        unsigned char next_sequence = CONTROL_EVENT_SEQUENCE;
        CONTROL_EVENT_SEQUENCE = (unsigned char)(next_sequence + 1);
        *sequence = next_sequence;
        return 1;
    }
    return 0;
}


/* Native entry: 0x420284ec. */
/* Original function-byte SHA-256:
 * 8c3afa78373668251f0fd56a7f5fec0ac185cbc0103f092294e219e7caf9e168. */
/* Pop the oldest stored slot, without acquiring its lock. Count HALFWORD0
 * returns0 unchanged. Read capacity, next-write index and stride; compute
 * LOW16((next+capacity-count) SIGNED-remainder capacity), multiply by stride,
 * then load storage pointer and locate the source. Copy its length HALFWORD
 * through memcpy; reload stride and limit copy length to stride when needed.
 * BUG RETAINED: the temporary shortened length is NOT written into the source
 * or copied header. Copy raw slot prefix, then reload/decrement count modulo16
 * and return1. Consumers can still see an oversized declared payload length.
 * No count<=capacity, capacity!=0, stride>=4, output-size or pointer checks.
 * A stride<4 underflows the clamp to LOW16(stride-4)+4, permitting a large copy.
 * Requires valid initialized descriptors and caller serialization for ordinary
 * operation; a concurrent/aliasing mutation can invalidate those invariants. */
int control_event_ring_pop(ControlEventRing *ring,void *output)
{
    unsigned int count = ring->count;
    if (count == 0)
        return 0;
    unsigned int capacity = ring->capacity;
    unsigned int next_write = ring->next_write;
    unsigned int stride = ring->stride;
    int oldest_bits = (int)(next_write + capacity - count);
    unsigned short oldest = (unsigned short)(oldest_bits % (int)capacity);
    unsigned char *source = ring->storage + (unsigned int)oldest * stride;
    unsigned short declared_length;
    memcpy(&declared_length,source + 2,2);
    unsigned int copy_bytes = (unsigned int)declared_length + 4;
    unsigned int current_stride = ring->stride;
    if (current_stride < copy_bytes) {
        unsigned short shortened_length = (unsigned short)(current_stride - 4U);
        copy_bytes = (unsigned int)shortened_length + 4U;
    }
    memcpy(output,source,copy_bytes);
    ring->count = (unsigned short)(ring->count - 1U);
    return 1;
}

/* Native entry: 0x4202a254. */
/* Original function-byte SHA-256:
 * 1f60ccb61dcd5642125cef243492287df70af4dab3bbb123de8932f1f2e83f52. */
/* Clear the260-byte editable capture profile and all32 drop HALFWORDs under
 * the subscription spinlock. Call xPortInIsrContext before entry and before
 * exit but ignore its result, as native does. Each drop store has MEMW.
 * MEMW/read generation WORD, MEMW/store generation+1 wrapping32, then MEMW/read
 * profile selector BYTE. Copy260 bytes to slot(selector XOR1), without masking
 * it to0/1. After memcpy, read class-mask HALFWORD from editable+256 BEFORE
 * MEMW/store new selector BYTE and MEMW/store that saved mask. Raw Ghidra
 * misplaced this mask read after the selector publication.
 * Records, flags and count within the editable span are zeroed; publishing
 * only overwrites the selected260-byte slot. Caller needs valid initialized
 * shared storage; no selector bounds check or extra notification is added. */
void capture_clear_subscriptions(void)
{
    (void)xPortInIsrContext();
    (void)xPortEnterCriticalTimeout(CAPTURE_SUBSCRIPTION_LOCK,-1);
    memset(CAPTURE_EDITABLE_PROFILE,0,260);
    for (unsigned int index = 0; index < 32; ++index) {
        memw();
        CAPTURE_SUBSCRIBER_DROPS[index] = 0;
    }
    memw();
    unsigned int generation = CONTROL_EVENT_GENERATION;
    memw();
    CONTROL_EVENT_GENERATION = generation + 1U;
    memw();
    unsigned int selector = CAPTURE_PROFILE_INDEX ^ 1U;
    memcpy((unsigned char *)CAPTURE_PROFILES + selector * 260U,
        CAPTURE_EDITABLE_PROFILE,260);
    unsigned short class_mask = CAPTURE_EDITABLE_PROFILE->class_mask;
    memw();
    CAPTURE_PROFILE_INDEX = (unsigned char)selector;
    memw();
    CAPTURE_CLASS_MASK = class_mask;
    (void)xPortInIsrContext();
    vPortExitCritical(CAPTURE_SUBSCRIPTION_LOCK);
}
