/* Device clip decoding, retained byte-ring operations and status serialization. */
#include "../include/types.h"

/* reconstruction utilities: native inline byte operations, not native entries.
 * Output helpers require writable nonoverlapping private storage. The reader
 * requires two readable bytes and deliberately samples HIGH before LOW. */
static __inline__ __attribute__((always_inline)) void
clip_status_put_u16(unsigned char *output,unsigned int value)
{
    volatile unsigned char *bytes = output;
    bytes[0] = (unsigned char)value;
    bytes[1] = (unsigned char)(value >> 8);
}
static __inline__ __attribute__((always_inline)) void
clip_status_put_u32(unsigned char *output,unsigned int value)
{
    volatile unsigned char *bytes = output;
    bytes[0] = (unsigned char)value;
    bytes[1] = (unsigned char)(value >> 8);
    bytes[2] = (unsigned char)(value >> 16);
    bytes[3] = (unsigned char)(value >> 24);
}
static __inline__ __attribute__((always_inline)) unsigned short
clip_read_le16_high_first(const unsigned char *input)
{
    const volatile unsigned char *bytes = input;
    unsigned int high = bytes[1];
    unsigned int low = bytes[0];
    return (unsigned short)((high << 8) | low);
}

/* Native entry: 0x42009d48. */
/* Original function-byte SHA-256:
 * bd82e12582264121f5d41c1bdd5bb530c4d4d52f07e7a6cedcd4e0cab0d68705. */
/*
 * ring: Ring to read without advancing; scratch and storage must not overlap.
 * length: Bytes to copy, no more than unread bytes, ring capacity or scratch capacity.
 * Returns: Nothing.
 * Requirements/effects: Copies at most two physical spans into scratch. Performs no bounds or
 *   unread-count validation. Initialized ring with a nonzero power-of-two capacity, valid backing
 *   storage and consistent unsigned positions; caller serializes producer/decoder access.
 */

void clip_ring_peek(const ClipRing *ring,unsigned int length)
{
    const volatile ClipRing *live = ring;
    unsigned int capacity = live->capacity;
    unsigned int read_position = live->read_position;
    unsigned int offset = read_position & (capacity - 1U);
    unsigned int contiguous = capacity - offset;
    unsigned int first = length < contiguous ? length : contiguous;
    unsigned char *storage = live->storage;
    unsigned char *scratch = live->scratch;
    memcpy(scratch,storage + offset,first);
    if (length > contiguous) {
        scratch = live->scratch;
        storage = live->storage;
        memcpy(scratch + first,storage,length - first);
    }
}

/* Native entry: 0x42009d7c. */
/* Original function-byte SHA-256:
 * 0550cb640d96017c0c704d4620f1cd71a75f08275a94b44f9e48f2b9023fdc41. */
/*
 * bytes: Readable scratch window containing at least one byte; variable record pointers borrow it.
 * available: Valid input length from1 through512 bytes, as supplied by the ring decoder.
 * decoded: Writable aligned80-byte ClipDecodedEntry output; must not
 *   overlap input.
 * Returns: Consumed byte count on success,0 for incomplete input, or-1 for invalid tag/count or a
 *   variable record exceeding the512-byte entry limit.
 * Requirements/effects: Clears the whole output first, then may leave partially decoded fields on
 *   failure. Tag0 is a three-byte delay; other tag bits select XY, wheel, usage changes, pan,
 *   packets and controls. Usage and packet counts must be1..8; control count must be nonzero and
 *   is otherwise constrained by byte limits. Variable-record pointers remain valid only until
 *   scratch is overwritten. Native reads each little-endian input HALFWORD
 *   HIGH byte before LOW and wraps variable cursors to16 bits. No NULL/first-byte
 *   guard, allocation, scheduling or locking.
 */

int clip_parse_entry(const unsigned char *bytes,unsigned int available,
    ClipDecodedEntry *decoded)
{
    volatile ClipDecodedEntry *entry = decoded;
    const volatile unsigned char *input = bytes;
    memset(decoded,0,sizeof(*decoded));
    unsigned int tag = input[0];
    if (tag == 0) {
        if (available < 3) return 0;
        entry->is_delay = 1;
        entry->delay_ticks = clip_read_le16_high_first(bytes + 1);
        return 3;
    }
    if (tag > 0x3f) return -1;

    unsigned int offset = 1;
    if (tag & 1U) {
        if (available < 5) return 0;
        entry->has_xy = 1;
        entry->x = clip_read_le16_high_first(bytes + 1);
        entry->y = clip_read_le16_high_first(bytes + 3);
        offset = 5;
    }
    if (tag & 2U) {
        if (available - offset < 2) return 0;
        entry->has_wheel = 1;
        entry->wheel = clip_read_le16_high_first(bytes + offset);
        offset = (offset + 2U) & 0xffffU;
    }
    if (tag & 8U) {
        if (available - offset < 2) return 0;
        entry->has_pan = 1;
        entry->pan = clip_read_le16_high_first(bytes + offset);
        offset = (offset + 2U) & 0xffffU;
    }
    if (tag & 4U) {
        if (offset == available) return 0;
        unsigned int count = input[offset];
        unsigned int record_offset = (offset + 1U) & 0xffffU;
        if (count == 0 || count > 8) return -1;
        if (available - record_offset < count * 4) return 0;
        entry->usage_count = count;
        /* Native LOOP executes exactly count four-byte input records. */
        for (unsigned int index = 0; index < count; ++index) {
            volatile ClipUsageChange *change = &entry->usage_changes[index];
            change->target_kind = input[record_offset];
            change->usage = clip_read_le16_high_first(bytes + ((record_offset + 1U) & 0xffffU));
            change->value = input[(record_offset + 3U) & 0xffffU];
            record_offset = (record_offset + 4U) & 0xffffU;
        }
        offset = record_offset;
    }
    if (tag & 0x10U) {
        if (offset == available) return 0;
        unsigned int count = input[offset];
        unsigned int records_start = (offset + 1U) & 0xffffU;
        if (count == 0 || count > 8) return -1;
        offset = records_start;
        for (unsigned int index = 0; index < count; ++index) {
            unsigned int payload_offset = (offset + 4U) & 0xffffU;
            if (512U - offset < 4) return -1;
            if (available - offset < 4) return 0;
            unsigned int payload_length = clip_read_le16_high_first(bytes + offset + 2U);
            if (512U - payload_offset < payload_length) return -1;
            if (available - payload_offset < payload_length) return 0;
            offset = (payload_offset + payload_length) & 0xffffU;
        }
        entry->packet_count = count;
        entry->packet_records = bytes + records_start;
        entry->packet_bytes = offset - records_start;
        if (!(tag & 0x20U)) return offset;
        if (offset == 512) return -1;
    }
    if (!(tag & 0x20U)) return offset;
    if (available == offset) return 0;

    unsigned int count = input[offset];
    unsigned int records_start = (offset + 1U) & 0xffffU;
    if (count == 0) return -1;
    offset = records_start;
    for (unsigned int index = 0; index < count; ++index) {
        unsigned int flags_offset = offset + 1;
        if (512U - offset < 9) return -1;
        if (available - offset < 9) return 0;
        offset = (offset + 9U) & 0xffffU;
        if (!(input[flags_offset] & 0x80U)) {
            unsigned int payload_length = clip_read_le16_high_first(bytes + flags_offset + 6U);
            if (512U - offset < payload_length) return -1;
            if (available - offset < payload_length) return 0;
            offset = (offset + payload_length) & 0xffffU;
        }
    }
    entry->control_count = count;
    entry->control_records = bytes + records_start;
    entry->control_bytes = offset - records_start;
    return offset;
}

/* Native entry: 0x42009fd0. */
/* Original function-byte SHA-256:
 * 54359e8615df838961eff451a9b23bfaf00003db220b40fcdfd7902486d149fb. */
/*
 * ring: Ring receiving data; storage must not overlap the source.
 * bytes: Readable source of length bytes.
 * length: Whole append size, accepted atomically or rejected for insufficient free capacity.
 * Returns: Length on success,0 when insufficient space; a zero-length append also returns0.
 * Requirements/effects: Does not reject finalized state itself; command-layer callers enforce that
 *   policy. Advances write position after at most two copies. Initialized ring with a nonzero
 *   power-of-two capacity, valid backing storage and consistent unsigned positions; caller
 *   serializes producer/decoder access.
 */

unsigned int clip_ring_append(ClipRing *ring,const unsigned char *bytes,
    unsigned int length)
{
    volatile ClipRing *live = ring;
    unsigned int capacity = live->capacity;
    unsigned int retained_start = live->retained_start;
    unsigned int write_position = live->write_position;
    unsigned int free_bytes = capacity + retained_start - write_position;
    if (length > free_bytes)
        return 0;
    unsigned int offset = write_position & (capacity - 1U);
    unsigned int contiguous = capacity - offset;
    unsigned int first = length < contiguous ? length : contiguous;
    unsigned char *storage = live->storage;
    memcpy(storage + offset,bytes,first);
    if (length > contiguous) {
        storage = live->storage;
        memcpy(storage,bytes + first,length - first);
    }
    live->write_position = live->write_position + length;
    return length;
}

/* Native entry: 0x4200a01c. */
/* Original function-byte SHA-256:
 * f6486f0cd6c922d580c7ab07a07c4a46aae99b563b5e98b50be63f836c355d90. */
/*
 * ring: Ring with a scratch buffer of at least512 bytes.
 * decoded: Writable aligned80-byte decoded-entry structure. Variable records borrow scratch storage.
 * Returns: 1 after consuming a complete entry;0 when empty or awaiting more input;-1 for malformed
 *   input or an incomplete finalized entry.
 * Requirements/effects: Peeks up to64 unread bytes and retries up to512 only if parsing is
 *   incomplete and more than64 bytes are unread. Empty finalized rings still return0. Advances
 *   read position only on success and does not release retained bytes. Borrowed pointers must be
 *   consumed before the next peek. Initialized ring with a nonzero power-of-two capacity, valid
 *   backing storage and consistent unsigned positions; caller serializes producer/decoder access.
 *   If parsing remains incomplete, returns the negative raw finalized BYTE;
 *   a corrupt value above1 is not normalized to-1.
 */

int clip_ring_decode_next(ClipRing *ring,ClipDecodedEntry *decoded)
{
    volatile ClipRing *live = ring;
    unsigned int write_position = live->write_position;
    unsigned int read_position = live->read_position;
    unsigned int unread = write_position - read_position;
    if (write_position == read_position)
        return 0;
    unsigned int window = unread < 64U ? unread : 64U;
    clip_ring_peek(ring,window);
    int consumed = clip_parse_entry(live->scratch,window,decoded);
    if (consumed == 0 && unread > 64U) {
        window = unread < 512U ? unread : 512U;
        clip_ring_peek(ring,window);
        consumed = clip_parse_entry(live->scratch,window,decoded);
    }
    if (consumed == -1)
        return -1;
    if (consumed == 0)
        return -(int)live->finalized;
    live->read_position = live->read_position + (unsigned int)consumed;
    return 1;
}

/* Native entry: 0x42020d5c. */
/* Original function-byte SHA-256:
 * d4ccd86085a67105ee44f5c2c8aaac50ee9b4f3f54378f69c3d7c67721294fa8. */
/*
 * ring: Writable ring context.
 * storage: Caller-owned backing storage of capacity bytes.
 * capacity: Nonzero power of two, required but not checked.
 * scratch: Caller-owned contiguous scratch, at least512 bytes for decode_next.
 * Returns: Nothing.
 * Requirements/effects: Stores pointers/capacity and clears all positions and finalization. Does
 *   not allocate, clear buffers or validate capacity. Storage and scratch must remain live and
 *   nonoverlapping.
 */

void clip_ring_init(ClipRing *ring,unsigned char *storage,unsigned int capacity,
    unsigned char *scratch)
{
    volatile ClipRing *live = ring;
    live->storage = storage;
    live->scratch = scratch;
    live->capacity = capacity;
    live->write_position = 0;
    live->read_position = 0;
    live->retained_start = 0;
    live->finalized = 0;
}

/* Native entry: 0x42020d74. */
/* Original function-byte SHA-256:
 * 71320c25bd6b1f057bfd13010f878dd27d00009caa659fd0b808233194bfcd51. */
/*
 * ring: Live ring context; caller serializes access.
 * Returns: Nothing.
 * Requirements/effects: Resets positions and finalization while retaining pointer/capacity
 *   settings. Does not erase storage or scratch bytes.
 */

void clip_ring_clear(ClipRing *ring)
{
    volatile ClipRing *live = ring;
    live->write_position = 0;
    live->read_position = 0;
    live->retained_start = 0;
    live->finalized = 0;
}

/* Native entry: 0x42020d84. */
/* Original function-byte SHA-256:
 * ddb18fa11f78ea304c97c56eef8fee54364d6c7761ba2267bad79a1dc7c3a522. */
/*
 * ring: Live ring with valid write/retained positions.
 * Returns: Unsigned write_position minus retained_start, including already decoded bytes still
 *   held for replay.
 * Requirements/effects: No lock or mutation. Position invariants keep this modular difference
 *   within capacity.
 */

unsigned int clip_ring_retained_bytes(const ClipRing *ring)
{
    const volatile ClipRing *live = ring;
    unsigned int write_position = live->write_position;
    unsigned int retained_start = live->retained_start;
    return write_position - retained_start;
}

/* Native entry: 0x42020d90. */
/* Original function-byte SHA-256:
 * 42eb471e5d74b8df43e2c83b409a924c684ec4f2fe937ca643b1ad464f650d2b. */
/*
 * ring: Live ring with valid retained occupancy.
 * Returns: Capacity minus retained occupancy, using modular unsigned arithmetic.
 * Requirements/effects: Decoded bytes remain occupied until release_consumed moves retained_start.
 *   No lock or bounds validation.
 */

unsigned int clip_ring_free_bytes(const ClipRing *ring)
{
    const volatile ClipRing *live = ring;
    unsigned int capacity = live->capacity;
    unsigned int retained_start = live->retained_start;
    unsigned int write_position = live->write_position;
    return capacity + retained_start - write_position;
}

/* Native entry: 0x42020da0. */
/* Original function-byte SHA-256:
 * 25839d36ef3bc0dec2994e87c7fc6ffb4d3281353d46aeb8896c793fa5fa296b. */
/*
 * ring: Live ring with valid read/retained positions.
 * Returns: Byte count decoded since retained_start; not an entry count.
 * Requirements/effects: No lock or mutation; uses modular unsigned position subtraction.
 */

unsigned int clip_ring_consumed_bytes(const ClipRing *ring)
{
    const volatile ClipRing *live = ring;
    unsigned int read_position = live->read_position;
    unsigned int retained_start = live->retained_start;
    return read_position - retained_start;
}

/* Native entry: 0x42020dac. */
/* Original function-byte SHA-256:
 * f4bc19b6c5ecdb018f511cafe36e555e42e92f4c1fe843dfba0cfe0ae729bf8b. */
/*
 * ring: Live ring context.
 * Returns: True when read_position equals write_position.
 * Requirements/effects: Independent of finalized state and retained occupancy. No mutation or
 *   locking.
 */

bool clip_ring_at_end(const ClipRing *ring)
{
    const volatile ClipRing *live = ring;
    unsigned int read_position = live->read_position;
    unsigned int write_position = live->write_position;
    return read_position == write_position;
}

/* Native entry: 0x42020dc0. */
/* Original function-byte SHA-256:
 * c13ae629381a377161e48180a66913a05c923dd18c325e1e90064cab9f8af113. */
/*
 * ring: Live ring context.
 * Returns: Stored finalized byte.
 * Requirements/effects: Does not consume bytes or independently check decoder completion. No
 *   mutation or locking.
 */

unsigned char clip_ring_is_finalized(const ClipRing *ring)
{
    return ((const volatile ClipRing *)ring)->finalized;
}

/* Native entry: 0x42020dc8. */
/* Original function-byte SHA-256:
 * 6376e87efeeb5ec538e61c77d3d6f0b8c0746e89968c4f390af18b3be56aa3ba. */
/*
 * ring: Live ring; caller serializes access.
 * Returns: Nothing.
 * Requirements/effects: Sets finalized to1 without consuming or clearing bytes. Append rejection
 *   is enforced by the command layer, not by ring_append.
 */

void clip_ring_finalize(ClipRing *ring)
{
    ((volatile ClipRing *)ring)->finalized = 1;
}

/* Native entry: 0x42020dd4. */
/* Original function-byte SHA-256:
 * 5c41cece15ce14151191f3082c2d7a56ba7e5c7563d3ce24bc21441164ed1641. */
/*
 * ring: Live ring whose retained bytes remain valid.
 * Returns: Nothing.
 * Requirements/effects: Sets read_position to retained_start for replay. Does not change
 *   retained/write positions or finalization.
 */

void clip_ring_rewind(ClipRing *ring)
{
    volatile ClipRing *live = ring;
    live->read_position = live->retained_start;
}

/* Native entry: 0x42020de0. */
/* Original function-byte SHA-256:
 * fa014d1e0d334b210c7d571831e4eed9e89583a0430ab3cb8ef68cdae252c9e8. */
/*
 * ring: Live ring; caller serializes producer/decoder access.
 * Returns: Nothing.
 * Requirements/effects: Moves retained_start to read_position, making decoded bytes reclaimable.
 *   Does not change unread bytes or finalization and does not erase backing storage.
 */

void clip_ring_release_consumed(ClipRing *ring)
{
    volatile ClipRing *live = ring;
    live->retained_start = live->read_position;
}

/* Native entry: 0x420370fc. */
/* Original function-byte SHA-256:
 * 8d50131a53230937d67f648036964c045161e52261ce34484886b8e9bf33930e. */
/*
 * output: private writable 507-byte span for updater-admitted state, separate
 * from live input/trigger/ring storage; no capacity argument or bound check.
 * Returns a LOW 16 byte length:35 for empty state, at most 507 under the limits
 * of 40 held usages,8 input triggers,8 packet triggers and 112 total match bytes.
 * Snapshot playback/ring counters under the optional config mutex, then encode
 * selector 10/header 31, held[class,id 16] records, playback flags, input bindings
 * and packet triggers. All wire integers use little-endian BYTE stores.
 *
 * Primary button 0..15, keyboard forced usages, then consumer forced usages
 * share the 40-record limit. Each usage enumerator receives capacity 40, not the
 * remaining wire slots; extra returned usages are walked without emission.
 * Its nonzero WORD result is converted through native LOW 16 LOOP arithmetic.
 * Input-trigger count is sampled once; packet-trigger count is reloaded after
 * every record and its source index wraps 8 bits. Sources are not read after
 * their category's 8 output slots fill; the source cursor still advances.
 * Saturate packet hit counts to 65535, but trust each raw match length: no local
 * per-rule 16-byte or aggregate 112-byte budget check is added. The updater must
 * enforce these invariants. No allocation, playback step or state reset.
 * Initial indefinite mutex take ignores status; release rereads the current
 * handle. A missing mutex requires external quiescence. No hardware timing or
 * atomic combined snapshot guarantee; borrowed output is ready only on return.
 */

unsigned int clip_status_encode(unsigned char *output)
{
    unsigned short usages[40];
    RtosQueue *configuration_mutex = REWRITE_MUTEX;
    if (configuration_mutex != NULL) xQueueSemaphoreTake(configuration_mutex,0xffffffffU);
    unsigned int mode = PLAYBACK_MODE;
    unsigned int free_bytes = clip_ring_free_bytes(PLAYBACK_RING);
    unsigned int retained_bytes = clip_ring_retained_bytes(PLAYBACK_RING);
    unsigned int consumed_bytes = clip_ring_consumed_bytes(PLAYBACK_RING);
    unsigned int steps = PLAYBACK_STEPS;
    unsigned short underflows = PLAYBACK_UNDERFLOWS;
    unsigned short short_writes = CLIP_APPEND_SHORT_WRITES;
    unsigned short sequence_errors = CLIP_APPEND_SEQUENCE_ERRORS;
    volatile ClipStatusWireHeader *header = (volatile void *)output;
    /* Native order: interleaved BYTE stores and fresh status-field reads. */
    header->selector = 10;
    header->mode = (unsigned char)mode;
    header->free_bytes_le[2] = (unsigned char)(free_bytes >> 16);
    header->retained_bytes_le[2] = (unsigned char)(retained_bytes >> 16);
    header->retained_bytes_le[1] = (unsigned char)(retained_bytes >> 8);
    header->free_bytes_le[0] = (unsigned char)free_bytes;
    header->free_bytes_le[1] = (unsigned char)(free_bytes >> 8);
    header->free_bytes_le[3] = (unsigned char)(free_bytes >> 24);
    header->retained_bytes_le[0] = (unsigned char)retained_bytes;
    unsigned short control_successes = PLAYBACK_CONTROL_SUCCESSES;
    header->retained_bytes_le[3] = (unsigned char)(retained_bytes >> 24);
    header->sequence_errors_le[0] = (unsigned char)sequence_errors;
    header->consumed_bytes_le[2] = (unsigned char)(consumed_bytes >> 16);
    unsigned short control_errors = PLAYBACK_CONTROL_ERRORS;
    header->consumed_bytes_le[3] = (unsigned char)(consumed_bytes >> 24);
    header->control_successes_le[0] = (unsigned char)control_successes;
    header->steps_le[1] = (unsigned char)(steps >> 8);
    header->steps_le[2] = (unsigned char)(steps >> 16);
    header->steps_le[3] = (unsigned char)(steps >> 24);
    header->consumed_bytes_le[0] = (unsigned char)consumed_bytes;
    header->underflows_le[1] = (unsigned char)(underflows >> 8);
    header->short_writes_le[1] = (unsigned char)(short_writes >> 8);
    header->control_successes_le[1] = (unsigned char)(control_successes >> 8);
    unsigned short dropped = IMPERFECT_CLIP_DROPPED;
    header->short_writes_le[0] = (unsigned char)short_writes;
    header->consumed_bytes_le[1] = (unsigned char)(consumed_bytes >> 8);
    header->dropped_le[0] = (unsigned char)dropped;
    unsigned char primary_enabled = FIXED_INPUTS[0].enabled;
    header->steps_le[0] = (unsigned char)steps;
    header->underflows_le[0] = (unsigned char)underflows;
    header->sequence_errors_le[1] = (unsigned char)(sequence_errors >> 8);
    header->control_errors_le[0] = (unsigned char)control_errors;
    header->control_errors_le[1] = (unsigned char)(control_errors >> 8);
    header->dropped_le[1] = (unsigned char)(dropped >> 8);
    header->held_count = 0;
    volatile unsigned char *wire = output;
    unsigned int offset = 31;
    if (primary_enabled != 0) {
        unsigned int forced_buttons = input_forced_buttons(
            (const InputStateView *)&FIXED_INPUTS[0].state);
        for (unsigned int button = 0; button < 16; ++button)
            if ((forced_buttons & (1U<<button)) != 0 && header->held_count < 40) {
                wire[offset] = 0;
                wire[offset+1U] = button;
                wire[offset+2U] = 0;
                header->held_count += 1;
                offset = (unsigned short)(offset+3U);
            }
    }
    if (FIXED_INPUTS[1].enabled != 0) {
        unsigned int count = input_list_forced_keys(
            (const InputStateView *)&FIXED_INPUTS[1].state,usages,40);
        if (count != 0) {
            unsigned int loop_count = ((((count&0xffffU)*2U)-2U)>>1)+1U;
            for (unsigned int index = 0; index < loop_count; ++index)
                if (header->held_count < 40) {
                    unsigned short usage = usages[index];
                    wire[offset] = 1;
                    clip_status_put_u16(output+offset+1U,usage);
                    offset = (unsigned short)(offset+3U);
                    header->held_count += 1;
                }
        }
    }
    if (FIXED_INPUTS[2].enabled != 0) {
        unsigned int count = input_list_forced_consumers(
            (const InputStateView *)&FIXED_INPUTS[2].state,usages,40);
        if (count != 0) {
            unsigned int loop_count = ((((count&0xffffU)*2U)-2U)>>1)+1U;
            for (unsigned int index = 0; index < loop_count; ++index)
                if (header->held_count < 40) {
                    unsigned short usage = usages[index];
                    wire[offset] = 2;
                    clip_status_put_u16(output+offset+1U,usage);
                    offset = (unsigned short)(offset+3U);
                    header->held_count += 1;
                }
        }
    }
    unsigned char retain_bits = (unsigned char)(PLAYBACK_TRANSFORMS.retain*2U);
    unsigned char repeat_bits = PLAYBACK_TRANSFORMS.repeat;
    unsigned char finalized = clip_ring_is_finalized(PLAYBACK_RING);
    unsigned char timed_motion_bits = (unsigned char)(PLAYBACK_TRANSFORMS.timed_motion<<3);
    unsigned char selection = PLAYBACK_TRANSFORMS.selection;
    wire[offset] = selection;
    wire[offset+1U] = repeat_bits | retain_bits | (finalized<<2) | timed_motion_bits;
    unsigned int input_count = INPUT_TRIGGER_COUNT;
    volatile unsigned char *input_count_field = output+((offset+2U)&0xffffU);
    *input_count_field = 0;
    offset = (unsigned short)(offset+3U);
    for (unsigned int index = 0; index < input_count; ++index) {
        if (*input_count_field >= 8) continue;
        const volatile ClipInputTrigger *trigger = &CLIP_INPUT_TRIGGERS[index];
        unsigned short usage = trigger->usage;
        unsigned char input_class = trigger->input_class;
        unsigned char edge = trigger->edge;
        unsigned char action = trigger->action;
        unsigned char consume = trigger->consume;
        wire[offset] = input_class;
        clip_status_put_u16(output+offset+1U,usage);
        wire[offset+3U] = edge;
        wire[offset+4U] = action;
        wire[offset+5U] = consume;
        offset = (unsigned short)(offset+6U);
        *input_count_field += 1;
    }
    volatile unsigned char *packet_count_field = output+offset;
    *packet_count_field = 0;
    offset = (unsigned short)(offset+1U);
    if (PACKET_TRIGGER_COUNT != 0) {
        unsigned int source_index = 0,emitted = 0;
        const volatile ClipPacketTrigger *trigger = CLIP_PACKET_TRIGGERS;
        for (;;) {
            if (emitted < 8) {
                unsigned char direction = trigger->direction;
                unsigned short id = trigger->id;
                unsigned char action = trigger->action;
                unsigned char traffic_class = trigger->traffic_class;
                unsigned char flags = trigger->flags;
                unsigned int hits = trigger->hits;
                unsigned int match_length = trigger->match_length;
                unsigned char selector_length = trigger->selector_length;
                wire[offset] = traffic_class;
                clip_status_put_u16(output+offset+1U,id);
                wire[offset+3U] = direction;
                wire[offset+4U] = action;
                wire[offset+5U] = flags;
                wire[offset+6U] = selector_length;
                wire[offset+7U] = match_length;
                clip_status_put_u16(output+offset+8U,hits < 65535U ? hits : 65535U);
                unsigned int payload_offset = offset+10U;
                if (match_length != 0) {
                    memcpy(output+payload_offset,(const void *)trigger->match,match_length);
                    memcpy(output+payload_offset+match_length,(const void *)trigger->mask,match_length);
                }
                *packet_count_field += 1;
                offset = (unsigned short)(payload_offset+2U*match_length);
            }
            source_index = (unsigned char)(source_index+1U);
            unsigned int live_count = PACKET_TRIGGER_COUNT;
            ++trigger;
            if (source_index >= live_count) break;
            emitted = *packet_count_field;
        }
    }
    configuration_mutex = REWRITE_MUTEX;
    if (configuration_mutex != NULL) xQueueGenericSend(configuration_mutex,NULL,0,0);
    return offset;
}

/* Native entry: 0x420370f0. */
/* Original function-byte SHA-256:
 * d8701fec7b0e0339a876743ffa4f9a7f355f9cf268bd9d7e6ba44cfddbbf57a7. */
/*
 * Read the configured clip-ring allocation capacity WORD once, with NO MEMW.
 * Worker initialization publishes 65536/16384/8192 bytes on allocation success
 * or 0 when all attempts fail; this accessor does not validate or recompute it.
 * app_main uses it for storage diagnostics. No allocation, free-space/used-byte
 * calculation, locking, retry or synchronization of ring initialization.
 */

unsigned int clip_get_allocation_capacity(void)
{
    return CLIP_ALLOCATION_CAPACITY;
}
