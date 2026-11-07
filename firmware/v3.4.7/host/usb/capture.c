/* Medius v3.4.7 host — usb/capture.c.
 * Recovered C and native assembly, grouped for source navigation.
 * Original entry addresses, firmware-byte hashes and function comments follow.
 */

#include "../include/types.h"

/* Native entry: 0x4200ed20. */
/*
 * Medius v3.4.7 — host application; 0x4200ed20.
 *
 * Fragments one snapshot section into a seven-byte header and up to512 payload bytes using shared
 * scratch.
 *
 * Calls: memcpy.
 *
 * Called by: medius_clone_publish.
 *
 * Indirect call: the caller-supplied synchronous fragment callback.
 *
 * Original function-byte SHA-256:
 * b0ceada8dfcd8be4d6ddc4eaa6c82a74cb50a6f59e7dce7a1a64c38c38dd411a.
 */

/*
 * section: Only low eight bits enter the wire header.
 * data: Readable section bytes; each chunk is read after the previous callback returns.
 * length: Only low 16 bits determine total and termination.
 * maximum_chunk: Low 16 bits clamped to 1..512.
 * callback: Required synchronous callback accepting borrowed shared packet bytes.
 * context: Opaque value forwarded unchanged to every callback.
 * Returns: No value. Calls the callback at least once, including zero-length sections.
 * Requirements/effects: Uses one shared 519-byte access view. Each iteration writes a word at
 *   offset 0, a halfword at 4, then a byte at 6, encoding
 *   [section,totalLE16,offsetLE16,countLE16]. Copies only a nonzero payload, calls the callback
 *   with count+7, ignores its return register, and advances a 16-bit offset. The narrowed total
 *   guarantees progress with the clamped chunk. Inputs and header fields stay cached across
 *   callbacks; later payload bytes are read fresh. No validation, local lock, reentrancy guard or
 *   delivery acknowledgement occurs. A callback retaining bytes must copy them before another use
 *   of the scratch packet. Known clone calls use chunk 256 and the message-0x11 adapter.
 */

void medius_snapshot_emit_section
               (uint section,uchar *data,uint length,uint maximum_chunk,
               FragmentCallback callback,void *context)

{
  uint offset;
  uint chunk_limit;
  uint remaining;
  uint chunk_length;
  MediusSnapshotSectionHeader *header = (MediusSnapshotSectionHeader *)medius_snapshot_section_packet;

  chunk_limit = maximum_chunk & 0xffffU;
  if (chunk_limit > 512U)
    chunk_limit = 512U;
  if (chunk_limit == 0)
    chunk_limit = 1;
  offset = 0;
  do {
    remaining = ((length & 0xffffU) - offset) & 0xffffU;
    chunk_length = remaining < chunk_limit ? remaining : chunk_limit;
    /* Native 4200ed77/79/7c publish word, halfword, then final byte. */
    header->section_total_offset_low =
         (section & 0xffU) | ((length & 0xffffU) << 8) | (offset << 24);
    header->offset_high_count_low = (ushort)((offset >> 8) | ((chunk_length & 0xffU) << 8));
    header->count_high = (uchar)(chunk_length >> 8);
    if (chunk_length != 0) {
      memcpy(medius_snapshot_section_packet + 7,data + offset,chunk_length);
    }
    (*callback)(medius_snapshot_section_packet,(ushort)(chunk_length + 7),context);
    offset = (chunk_length + offset) & 0xffffU;
  } while (offset < (length & 0xffff));
  return;
}

/* Native entry: 0x4201e8ec. */
/*
 * Medius v3.4.7 — host application; 0x4201e8ec.
 *
 * Invokes a callback with the seven-byte section6 end marker.
 *
 * Called by: medius_clone_publish.
 *
 * Indirect call: the caller-supplied synchronous fragment callback.
 *
 * Original function-byte SHA-256:
 * 5cc7aa4e7024da988fe40bbbe3c2076c34a25f49a56ac2b11dbc4c94d3df6377.
 */

/*
 * callback: Required callback; packet storage is valid only during this call.
 * context: Forwarded unchanged.
 * Returns: No value; ignores the callback return register.
 * Requirements/effects: Publishes the exact seven bytes 06 00 00 00 00 00 00 using stack
 *   word/halfword/byte stores, then calls callback once with length 7. C layout has one unused
 *   alignment-padding byte, which is not sent. No null check, retry, shared buffer or
 *   acknowledgement is supplied. An asynchronous consumer must copy these bytes before returning.
 */

void medius_snapshot_emit_commit_marker(FragmentCallback callback,void *context)

{
  MediusSnapshotSectionHeader marker;

  marker.section_total_offset_low = 6;
  marker.offset_high_count_low = 0;
  marker.count_high = 0;
  (*callback)((const uchar *)&marker,7,context);
  return;
}

/* Native entry: 0x4202643c. */
/*
 * Medius v3.4.7 — host application; 0x4202643c.
 *
 * Sends a snapshot frame as message11hex using a shared incrementing sequence byte.
 *
 * Calls: link_send_wait100.
 *
 * Original function-byte SHA-256:
 * aab7ce4f06eeaeff8429dd8b5b260124b1ee2026dd8d7a6c8b3f83e118c4b6af.
 */

/*
 * packet: Borrowed bytes forwarded unchanged, including NULL; local code does not access their
 *   contents.
 * length: 16-bit transport payload length.
 * ignored_context: Unused callback context.
 * Returns: No value; transport result is ignored.
 * Requirements/effects: Reads the sequence byte once, stores cached sequence+1 modulo 256, then
 *   delegates message 0x11 with the cached old sequence and given packet/length. No lock or
 *   admission check occurs; send failure does not restore the sequence. The helper owns
 *   transport/copy lifetime requirements. No asynchronous retention or delivery guarantee follows
 *   from this adapter.
 */

void medius_snapshot_send_section_frame(const uchar *packet,ushort length,void *ignored_context)

{
  MediusHostControlByte sequence;

  (void)ignored_context;
  sequence = *(const volatile uchar *)&medius_snapshot_sequence;
  *(volatile uchar *)&medius_snapshot_sequence = (uchar)(sequence + 1U);
  link_send_wait100(0x11,sequence,(void *)packet,length);
  return;
}

/* Native entry: 0x42026548. */
/*
 * Medius v3.4.7 — host application; 0x42026548.
 *
 * Sends HID descriptor bytes as message26hex fragments through one shared264-byte packet.
 *
 * Calls: link_send_wait100, memcpy.
 *
 * Called by: medius_clone_publish, medius_host_publish_hid_descriptor_blob.
 *
 * Original function-byte SHA-256:
 * eb9f536256c312095c87132c32f362c7de4fc98b54b65862e0ab149cdcb80402.
 */

/*
 * configuration: Full 32-bit OR input; high bits can affect adjacent header bytes.
 * interface_index: Full 32-bit input shifted left eight bits without narrowing.
 * descriptor: Readable borrowed bytes; later chunks are reread after each send call.
 * length: Full 32-bit loop limit, although offset and remaining amount wrap to 16 bits.
 * Returns: No value. Lengths at least 65536 never complete normally.
 * Requirements/effects: Always executes once, with count=min((length-offset)&65535,256). Writes
 *   offset/count word at byte 4 before the cached configuration/interface/total word at byte 0.
 *   Calls memcpy even for count 0, then message-0x26 send with sequence 0 and count+8; ignores
 *   both results. Shared packet access view is 264 bytes, with no local ownership, lock or
 *   capacity check. For length 0 sends one empty frame. Length 1..65535 terminates with complete
 *   contiguous coverage. Larger lengths reach their low16 total then repeatedly send empty frames
 *   because the 16-bit offset cannot reach the full32 limit. This reproduces the firmware behavior
 *   rather than adding an invented rejection.
 */

void medius_host_send_hid_descriptor_fragments
               (uint configuration,uint interface_index,const uchar *descriptor,uint length)

{
  uint offset;
  uint chunk_length;
  MediusHidDescriptorFrameHeader *header =
      (MediusHidDescriptorFrameHeader *)medius_hid_descriptor_packet;
  uint cached_header = configuration | (interface_index << 8) | ((length & 0xffffU) << 16);

  offset = 0;
  do {
    chunk_length = (length - offset) & 0xffffU;
    if (chunk_length > 256U)
      chunk_length = 256U;
    header->offset_count = offset | (chunk_length << 16);
    header->configuration_interface_total = cached_header;
    memcpy(medius_hid_descriptor_packet + 8,descriptor + offset,chunk_length);
    link_send_wait100(0x26,0,medius_hid_descriptor_packet,(chunk_length + 8) & 0xffffU);
    offset = (offset + chunk_length) & 0xffffU;
  } while (offset < length);
  return;
}

/* Native entry: 0x42026ccc. */
/*
 * Medius v3.4.7 — host application; 0x42026ccc.
 *
 * Walks counted interface/length/data records and emits each descriptor through message26hex
 * fragmentation.
 *
 * Calls: medius_host_send_hid_descriptor_fragments.
 *
 * Called by: medius_clone_publish, medius_snapshot_timer_cb.
 *
 * Original function-byte SHA-256:
 * 34f813b1644a9fd0683bb08a856a06bc0b85cc8e93d3034610df2a6a904aa8cd.
 */

/*
 * configuration: Full configuration word forwarded unchanged for every admitted record.
 * available_bytes: Supplied readable prefix length; no independent 6144-byte allocation bound is
 *   enforced.
 * Returns: No value. Silently stops at the first incomplete record.
 * Requirements/effects: Reads blob count once even when available_bytes is zero, then walks
 *   [interface,lengthLE16,data] records with an 8-bit record index and 16-bit offset starting at
 *   1. Checks the full32 header end before reading length high byte, length low byte, then
 *   interface byte in that native order. Interface is read before checking the full32 data end.
 *   Calls the fragment sender only if data fits the supplied prefix, including empty records.
 *   Count/current length/configuration/available size stay cached across callbacks; later headers
 *   are freshly read. Offset wraps after each record; exaggerated available sizes can admit out-
 *   of-allocation reads or wrap to earlier records. No local lock, error count or delivery proof
 *   is provided.
 */

void medius_host_publish_hid_descriptor_blob(uint configuration,uint available_bytes)

{
  uchar record_count;
  uchar record_index;
  uint header_end;
  uint offset;
  uint length;

  record_count = *(const volatile uchar *)medius_hid_descriptor_blob;
  record_index = '\0';
  offset = 1;
  if (record_count != 0) {
    do {
      header_end = offset + 3;
      if (available_bytes < header_end) {
        return;
      }
      const volatile uchar *record = medius_hid_descriptor_blob + offset;
      uint length_high = record[2];
      uint length_low = record[1];
      length = (length_high << 8) | length_low;
      uint interface_index = record[0];
      if (available_bytes < length + header_end) {
        return;
      }
      medius_host_send_hid_descriptor_fragments
                (configuration,interface_index,
                 medius_hid_descriptor_blob + offset + 3,length);
      record_index = record_index + '\x01';
      offset = (length + (header_end & 0xffffU)) & 0xffffU;
    } while (record_count != record_index);
  }
  return;
}

/* Native entry: 0x42026d28. */
/*
 * Medius v3.4.7 — host application; 0x42026d28.
 *
 * Finds the first matching cached string and converts at most126 UTF-16LE code units to one-byte
 * ASCII with replacement.
 *
 * Called by: medius_host_capture_descriptors_and_probe_controls.
 *
 * Original function-byte SHA-256:
 * c78c26882ee44441a16c960c036441d3626237922c33ac17284981ba7da5aa15.
 */

/*
 * string_index: Full32 ID compared with record byte;0 returns early and values above255 cannot
 *   match.
 * language: Low16 language ID; ignored when string_index is0xee.
 * output: Writable127-byte destination for the maximum126 code units plus terminator; not NULL-
 *   checked.
 * Returns: Converted code-unit count, including embedded NUL/control units;0 for no admitted
 *   matching record.
 * Requirements/effects: Clears output[0] BEFORE index/used/header checks. Caches used16 and walks
 *   complete five-byte-header records using declared payload length and full record-end bounds,
 *   without an independent1536-byte allocation guard. First matching ID/language wins; its nonzero
 *   status terminates failure rather than searching duplicates. Language reads are high byte then
 *   low byte;0xee skips them. Selected status0 uses min(payload length,payload bLength), requiring
 *   at least4 bytes; no descriptor-type check occurs. Converts floor((effective-2)/2), at most126
 *   UTF16LE units, reading each high byte then low byte; values<=127 pass through and others
 *   become?. Appends NUL even for a selected zero-unit result. Forward overlapping reads/writes
 *   can alter later source units; initial clear can alter archive admission. No calls, locks,
 *   allocation or ownership transfer occurs.
 */

uint medius_host_cached_string_ascii(uint string_index,ushort language,char *output)
{
    volatile char *destination = output;
    destination[0] = 0;
    if (string_index == 0)
        return 0;
    uint used = *(const volatile ushort *)&medius_string_descriptor_archive_used;
    if (used < 5)
        return 0;
    uint offset = 0;
    const volatile uchar *archive = medius_string_descriptor_archive;
    for (;;) {
        uint payload_length = archive[offset + 4];
        uint record_end = offset + 5U + payload_length;
        if (record_end > used)
            return 0;
        uchar record_index = archive[offset];
        int matches = record_index == string_index;
        if (matches && string_index != 0xee) {
            uint language_high = archive[offset + 2];
            uint language_low = archive[offset + 1];
            matches = ((language_high << 8) | language_low) == language;
        }
        if (matches) {
            if (archive[offset + 3] != 0)
                return 0;
            uint converted = 0;
            if (payload_length >= 2) {
                const volatile uchar *payload = archive + offset + 5;
                uint effective_length = payload[0];
                if (effective_length > payload_length)
                    effective_length = payload_length;
                if (effective_length >= 4) {
                    uint units = (effective_length - 2U) / 2U;
                    for (; converted < units; ++converted) {
                        uint high = payload[3U + converted * 2U];
                        uint low = payload[2U + converted * 2U];
                        uint code_unit = (high << 8) | low;
                        destination[converted] = code_unit <= 127U ? (char)code_unit : '?';
                    }
                }
            }
            destination[converted] = 0;
            return converted;
        }
        offset = record_end & 0xffffU;
        if (offset + 4U >= used)
            return 0;
    }
}

/* Native entry: 0x42026e14. */
/*
 * Medius v3.4.7 — host application; 0x42026e14.
 *
 * Requests and optionally archives a USB string descriptor under a shared timeout/retry budget.
 *
 * Calls: esp_timer_get_time, medius_copy_forward_words, usbh_control_transfer.
 *
 * Called by: medius_host_capture_descriptors_and_probe_controls.
 *
 * Original function-byte SHA-256:
 * b177f8548a71bcd2ce38a1face7b351b76ea7b9b5db2ce6957bdcd97ee6fffe4.
 */

/*
 * port: Live port whose SETUP pointer is cached even when the initial timeout count rejects.
 * budget: Shared12-byte capture budget; start words/count are read fresh at native boundaries.
 * string_index: wValue low16 is index OR0x0300; archive index is low8.
 * language_id: Wire/archive language uses low16.
 * requested_length: Wire wLength is only low8, while positive raw result-8 is checked against this
 *   full signed32 value.
 * Returns: 0 when timeout-count or signed elapsed-time budget rejects; otherwise1 on terminal
 *   outcomes, including errors, invalid descriptors or dropped archive records.
 * Requirements/effects: Reads budget count BEFORE caching SETUP; count>=2 then rejects without
 *   timer/control calls. Each attempt samples time, reads start LOW then HIGH once and rejects
 *   signed wrapping elapsed>=2000000 microseconds; negative elapsed is admitted. Builds SETUP in
 *   native byte order and delegates using cached SETUP plus shared256-byte scratch. Exact -8 may
 *   append a five-byte failure record, publishing used16 BEFORE header bytes. Positive raw>9
 *   considers raw-8 bytes only when within full signed requested_length and scratch type3; appends
 *   header, copies payload then adds extent to freshly read used16. No bLength/content validation
 *   or second post-copy capacity check occurs. One-byte payload length truncates above255;
 *   overreported lengths can cross the scratch allocation despite fitting the archive. Exact -14
 *   increments fresh timeout count modulo256 and retries while below2, without delay or reset of
 *   successful counts. Other outcomes return1 immediately. No local mutex, connection, pointer or
 *   lifetime validation is supplied.
 */

int medius_host_capture_string_descriptor(
    MediusHostHubPortPrefix *port,MediusStringCaptureBudget *budget,uint string_index,
    uint language_id,int requested_length)
{
    volatile MediusStringCaptureBudget *live_budget = budget;
    uchar initial_timeouts = live_budget->timeout_count;
    volatile uchar *setup = *(uchar * const volatile *)&port->setup;
    if (initial_timeouts >= 2)
        return 0;
    for (;;) {
        ulonglong now = (ulonglong)esp_timer_get_time();
        uint start_low = live_budget->start_low;
        uint start_high = live_budget->start_high;
        ulonglong elapsed = now - (((ulonglong)start_high << 32) | start_low);
        if (elapsed < 0x8000000000000000ULL && elapsed >= 2000000ULL)
            return 0;
        uchar index_low = (uchar)string_index;
        uchar language_low = (uchar)language_id;
        uchar language_high = (uchar)(language_id >> 8);
        setup[0] = 0x80;
        setup[1] = 6;
        setup[2] = index_low;
        setup[7] = 0;
        setup[3] = (uchar)((string_index >> 8) | 3U);
        setup[4] = language_low;
        setup[5] = language_high;
        setup[6] = (uchar)requested_length;
        int result = usbh_control_transfer(port,(uchar *)setup,medius_string_descriptor_scratch);
        if (result == -8) {
            uint used = *(const volatile ushort *)&medius_string_descriptor_archive_used;
            if (used + 5U <= 1536U) {
                *(volatile ushort *)&medius_string_descriptor_archive_used = (ushort)(used + 5U);
                volatile MediusStringArchiveRecordHeader *record =
                    (volatile MediusStringArchiveRecordHeader *)(medius_string_descriptor_archive + used);
                record->index = index_low;
                record->language_high = language_high;
                record->status = 1;
                record->language_low = language_low;
                record->payload_length = 0;
            }
            return 1;
        }
        if (result > 9) {
            uint payload_length = (uint)(result - 8);
            if (requested_length < (int)payload_length ||
                ((const volatile uchar *)medius_string_descriptor_scratch)[1] != 3)
                return 1;
            uint used = *(const volatile ushort *)&medius_string_descriptor_archive_used;
            if (used + 5U + payload_length <= 1536U) {
                volatile MediusStringArchiveRecordHeader *record =
                    (volatile MediusStringArchiveRecordHeader *)(medius_string_descriptor_archive + used);
                record->index = index_low;
                record->language_high = language_high;
                record->status = 0;
                record->language_low = language_low;
                record->payload_length = (uchar)payload_length;
                medius_copy_forward_words(medius_string_descriptor_archive + used + 5,
                                          medius_string_descriptor_scratch,payload_length);
                ushort current_used = *(const volatile ushort *)&medius_string_descriptor_archive_used;
                *(volatile ushort *)&medius_string_descriptor_archive_used =
                    (ushort)((uint)current_used + 5U + payload_length);
            }
            return 1;
        }
        if (result != -14)
            return 1;
        uchar timeouts = (uchar)(live_budget->timeout_count + 1U);
        live_budget->timeout_count = timeouts;
        if (timeouts >= 2)
            return 0;
    }
}

/* Native entry: 0x42026f40. */
/*
 * Medius v3.4.7 — host application; 0x42026f40.
 *
 * Collects up to48 unique nonzero string IDs from the copied device descriptor and a descriptor
 * chain, returning the count.
 *
 * Called by: medius_host_capture_descriptors_and_probe_controls.
 *
 * Original function-byte SHA-256:
 * 7cd52141e39051f83a784ca9a5a78794baadb3bd503e00840e1b7e641f9d0b42.
 */

/*
 * descriptors: Readable descriptor chain; NULL is not dereferenced for length0/1 after the device-
 *   ID phase.
 * length: Full unsigned32 admission/continuation length, with native signed end comparison
 *   retained.
 * ids: Writable48-byte output prefix; not cleared or terminated and may alias source storage.
 * Returns: Count0..48 of distinct nonzero IDs appended this call; malformed/truncated input
 *   returns the prefix count.
 * Requirements/effects: First reads copied device descriptor string IDs14/15/16 in order,
 *   deduplicating against the growing output. Then parses bLength/type, accepting
 *   configuration/interface/IAD IDs at bytes6/8/7 only with minimum lengths9/9/8. Native full32
 *   signed end comparison rejects lengths>=0x80000000 after bLength admission; offset advancement
 *   is low16 and continuation uses full unsigned length. Duplicate IDs still scan after
 *   capacity48, while a new unique ID at capacity returns48. Only a newly appended descriptor ID
 *   causes bLength to be reread after the output write; aliases can change advancement. No local
 *   chain-size cap, cycle detection, allocation or lock occurs; a65536-byte chain can wrap and
 *   repeat forever. Returned IDs are byte values, with no descriptor ownership or completeness
 *   claim.
 */

uint medius_host_collect_string_ids(const uchar *descriptors,uint length,uchar *ids)
{
    uint count = 0;
    volatile uchar *output = ids;
    const volatile uchar *device_ids = CAPTURE_DEVICE_STRING_IDS;
    for (uint device_field = 0; device_field < 3; ++device_field) {
        uchar candidate = device_ids[device_field];
        if (candidate == 0)
            continue;
        uint existing = 0;
        while (existing < count && output[existing] != candidate)
            ++existing;
        if (existing == count) {
            if (count >= 48)
                return count;
            output[count] = candidate;
            count = (count + 1U) & 0xffU;
        }
    }
    uint offset = 0;
    if (length < 2)
        return count;
    do {
        const volatile uchar *descriptor = (const volatile uchar *)((uint)descriptors + offset);
        uint descriptor_length = descriptor[0];
        if (descriptor_length < 2)
            return count;
        uint next_offset = offset + descriptor_length;
        /* Native signed end comparison; next_offset is at most65535+255. */
        if ((length & 0x80000000U) != 0 || next_offset > length)
            return count;
        uchar type = descriptor[1];
        uchar candidate = 0;
        if (type == 2 && descriptor_length >= 9)
            candidate = descriptor[6];
        else if (type == 4 && descriptor_length >= 9)
            candidate = descriptor[8];
        else if (type == 11 && descriptor_length >= 8)
            candidate = descriptor[7];
        if (candidate != 0) {
            uint existing = 0;
            while (existing < count && output[existing] != candidate)
                ++existing;
            if (existing == count) {
                if (count >= 48)
                    return count;
                output[count] = candidate;
                count = (count + 1U) & 0xffU;
                next_offset = offset + descriptor[0]; /* Native reread AFTER append. */
            }
        }
        offset = next_offset & 0xffffU;
    } while (offset + 2U <= length);
    return count;
}

/* Native entry: 0x420272e0. */
/*
 * Medius v3.4.7 — host application; 0x420272e0.
 *
 * Replaces one configuration in a bounded descriptor archive, with provisional records, selective
 * eviction and sticky partial failure.
 *
 * Calls: medius_copy_forward_words, memmove.
 *
 * Called by: medius_host_prepare_configuration_capture, medius_snapshot_timer_cb.
 *
 * Original function-byte SHA-256:
 * f2043e05270d995081da89ec071682fb5085dfa6966b361d7063d1e53b79ec22.
 */

/*
 * configuration: Full32 target for comparisons, narrowed to low8 only when committing an appended
 *   record.
 * available_bytes: Advertised input-byte bound used only in initial validation; no
 *   physical6144-byte cap is enforced.
 * protected_configuration: Full32 configuration excluded from capacity eviction; provisional255
 *   still has separate removal rules.
 * Returns: 1 unless any input record is capacity-rejected or an eviction cannot proceed; earlier
 *   changes remain on0. Publication-guard failure alone does not set0.
 * Requirements/effects: Caches input count once. Validates header/end for each input with high-
 *   before-low byte length reads and16-bit narrowed end. Purges all existing target records before
 *   appending and truncates malformed archive tail, even for input count0. Existing strides
 *   narrow(length+4)16; zero stride can repeat forever. Each input reloads capacity then high/low
 *   length/interface without revalidating later mutations. Preflight caches base/used and counts
 *   reclaimable provisional, matching-interface or other unprotected records. Successful preflight
 *   removes first matching target/interface and first provisional255 even without space pressure,
 *   then evicts first other unprotected records as needed. Native deletion paths reload used after
 *   memmove and subtract cached unsigned length+4 modulo65536; no rollback. Header fields
 *   publish255/interface/length-low/length-high with fresh base per store, then a fifth base is
 *   cached before used publication and copy. Copy includes length0. Fresh base and conditional
 *   used read guard cached payload-start range only before committing target byte; guard failure
 *   retains255. Counts, used, offsets, lengths and callback snapshots preserve native
 *   widths/order. Caller must provide accessible advertised input/archive storage and
 *   serialization; no lock, transaction, lifetime check or actual peripheral timing guarantee is
 *   provided.
 */

int medius_host_merge_hid_descriptor_blob(
    uint configuration,uint available_bytes,uint protected_configuration)
{
    const volatile uchar *blob = medius_hid_descriptor_blob;
    volatile MediusHidDescriptorArchive *archive = &medius_hid_descriptor_archive;
    uchar record_count = blob[0];
    if (record_count != 0) {
        uint offset = 1;
        for (uint index = 0; index < record_count; ++index) {
            if (available_bytes < offset + 3U)
                return 0;
            uchar high = blob[offset + 2U];
            uchar low = blob[offset + 1U];
            offset = (offset + 3U + ((uint)high << 8) + low) & 0xffffU;
            if (available_bytes < offset)
                return 0;
        }
    }
    uint used = archive->used;
    if (used >= 4) {
        uint offset = 0;
        do {
            uchar *base = archive->data;
            volatile MediusHidArchiveRecordHeader *record =
                (volatile MediusHidArchiveRecordHeader *)((uint)base + offset);
            uchar high = record->length_high;
            uchar low = record->length_low;
            uint length = ((uint)high << 8) | low;
            uint next = offset + ((length + 4U) & 0xffffU);
            if (used < next) {
                archive->used = (ushort)offset;
                break;
            }
            next &= 0xffffU;
            if (record->configuration == configuration) {
                if (used < next) {
                    archive->used = (ushort)offset;
                    used = offset;
                } else {
                    memmove((void *)record,(void *)((uint)base + next),used - next);
                    uint fresh_used = archive->used;
                    used = (fresh_used - 4U - length) & 0xffffU;
                    archive->used = (ushort)used;
                }
            } else {
                used = archive->used;
                offset = next;
            }
        } while (offset + 3U < used);
    }
    if (record_count == 0)
        return 1;

    int all_admitted = 1;
    uint input_offset = 1;
    for (uint index = 0; index < record_count; ++index) {
        uint capacity = archive->capacity;
        uchar length_high = blob[input_offset + 2U];
        uchar length_low = blob[input_offset + 1U];
        uint length = ((uint)length_high << 8) | length_low;
        uchar interface_id = blob[input_offset];
        uint required = length + 4U;
        uint payload_offset = (input_offset + 3U) & 0xffffU;
        if (required > capacity)
            goto rejected;
        used = archive->used;
        if (used >= 4) {
            uint reclaimable = 0;
            uchar *base = archive->data;
            uint offset = 0;
            do {
                const volatile MediusHidArchiveRecordHeader *record =
                    (const volatile MediusHidArchiveRecordHeader *)((uint)base + offset);
                uchar high = record->length_high;
                uchar low = record->length_low;
                uint stride = ((((uint)high << 8) | low) + 4U) & 0xffffU;
                uint next = offset + stride;
                if (used < next)
                    break;
                uchar stored_configuration = record->configuration;
                if (stored_configuration == 255 ||
                    (stored_configuration == configuration
                        ? record->interface_id == interface_id
                        : stored_configuration != protected_configuration))
                    reclaimable += stride;
                offset = next & 0xffffU;
            } while (offset + 3U < used);
            if (required + used - reclaimable > capacity)
                goto rejected;

            /* Same base and used snapshot as preflight, until a removal occurs. */
            offset = 0;
            do {
                volatile MediusHidArchiveRecordHeader *record =
                    (volatile MediusHidArchiveRecordHeader *)((uint)base + offset);
                uchar high = record->length_high;
                uchar low = record->length_low;
                uint next = offset + (((((uint)high << 8) | low) + 4U) & 0xffffU);
                if (used < next)
                    break;
                uint narrowed_next = next & 0xffffU;
                if (record->configuration == configuration && record->interface_id == interface_id) {
                    high = record->length_high;
                    low = record->length_low;
                    uint removed_length = ((uint)high << 8) | low;
                    uint end = (offset + removed_length + 4U) & 0xffffU;
                    if (end > used) {
                        used = offset;
                    } else {
                        memmove((void *)record,(void *)((uint)base + end),used - end);
                        uint fresh_used = archive->used;
                        used = (fresh_used - 4U - removed_length) & 0xffffU;
                    }
                    archive->used = (ushort)used;
                    break;
                }
                offset = narrowed_next;
            } while (offset + 3U < used);

            if (used >= 4) {
                base = archive->data;
                offset = 0;
                do {
                    volatile MediusHidArchiveRecordHeader *record =
                        (volatile MediusHidArchiveRecordHeader *)((uint)base + offset);
                    uchar high = record->length_high;
                    uchar low = record->length_low;
                    uint next = offset + (((((uint)high << 8) | low) + 4U) & 0xffffU);
                    if (used < next)
                        break;
                    uint narrowed_next = next & 0xffffU;
                    if (record->configuration == 255) {
                        high = record->length_high;
                        low = record->length_low;
                        uint removed_length = ((uint)high << 8) | low;
                        uint end = (offset + removed_length + 4U) & 0xffffU;
                        if (end > used) {
                            capacity = archive->capacity;
                            used = offset;
                        } else {
                            memmove((void *)record,(void *)((uint)base + end),used - end);
                            uint fresh_used = archive->used;
                            capacity = archive->capacity;
                            used = (fresh_used - 4U - removed_length) & 0xffffU;
                        }
                        archive->used = (ushort)used;
                        goto evict_for_capacity;
                    }
                    offset = narrowed_next;
                } while (offset + 3U < used);
            }
            capacity = archive->capacity;
        }
evict_for_capacity:
        while (required + used > capacity) {
            if (used < 4)
                goto rejected;
            uchar *base = archive->data;
            uint offset = 0;
            for (;;) {
                volatile MediusHidArchiveRecordHeader *record =
                    (volatile MediusHidArchiveRecordHeader *)((uint)base + offset);
                uchar high = record->length_high;
                uchar low = record->length_low;
                uint removed_length = ((uint)high << 8) | low;
                uint end = offset + ((removed_length + 4U) & 0xffffU);
                if (used < end)
                    goto rejected;
                uchar stored_configuration = record->configuration;
                end &= 0xffffU;
                if (stored_configuration != configuration &&
                    stored_configuration != protected_configuration) {
                    if (used < end) {
                        archive->used = (ushort)offset;
                        used = offset;
                    } else {
                        memmove((void *)record,(void *)((uint)base + end),used - end);
                        uint fresh_used = archive->used;
                        capacity = archive->capacity;
                        used = (fresh_used - 4U - removed_length) & 0xffffU;
                        archive->used = (ushort)used;
                    }
                    break;
                }
                if (end + 3U >= used)
                    goto rejected;
                offset = end;
            }
        }
        {
            uchar *base = archive->data;
            *(volatile uchar *)((uint)base + used) = 255;
            base = archive->data;
            *(volatile uchar *)((uint)base + used + 1U) = interface_id;
            base = archive->data;
            *(volatile uchar *)((uint)base + used + 2U) = length_low;
            base = archive->data;
            *(volatile uchar *)((uint)base + used + 3U) = length_high;
            base = archive->data;
            archive->used = (ushort)(used + required);
            uchar *destination = (uchar *)((uint)base + used + 4U);
            medius_copy_forward_words(destination,(const uchar *)((uint)blob + payload_offset),length);
            base = archive->data;
            if ((uint)destination >= (uint)base + 4U) {
                uint published_used = archive->used;
                if ((uint)destination <= (uint)base + published_used)
                    *(volatile uchar *)((uint)destination - 4U) = (uchar)configuration;
            }
        }
        goto next_record;
rejected:
        all_admitted = 0;
next_record:
        input_offset = (payload_offset + length) & 0xffffU;
    }
    return all_admitted;
}

/* Native entry: 0x4202767c. */
/*
 * Medius v3.4.7 — host application; 0x4202767c.
 *
 * Classifies one control request and selected error recovery, publishing the original raw result
 * separately.
 *
 * Calls: usb_osal_mutex_give, usb_osal_mutex_take, usbh_submit_urb.
 *
 * Called by: medius_host_capture_descriptors_and_probe_controls,
 * medius_host_probe_response_padding.
 *
 * Original function-byte SHA-256:
 * 7c8232927835b7c96deff116d99eccfabaabd38a27b72ad729989989cf93cc6a.
 */

/*
 * port: Live port containing EP0 descriptor, writable embedded URB, shared SETUP pointer and
 *   mutex.
 * request_type: Only low8 enters bmRequestType.
 * request: Only low8 enters bRequest.
 * value: Only low16 enters wValue.
 * index: Only low16 enters wIndex.
 * length: Low16 request length, also used for the nonnegative result classification.
 * result: Optional writable int32 output for the FIRST raw result, published after mutex release
 *   and never overwritten by recovery.
 * timeout: Full32 first-request timeout; descriptor recovery uses500.
 * Returns: Full32 classification: first nonnegative result gives4 if raw-8 exceeds length_low16,
 *   otherwise1; first -8 gives2; selected recovered failures give0/3; other failures give255.
 * Requirements/effects: Writes SETUP before taking the mutex, capturing mutex after bytes0/1.
 *   Ignores take/give statuses. Fills only
 *   setup/buffer/hubport/endpoint/remaining/timeout/completion/context in the embedded URB,
 *   submits once and uses actual interpreted signed32 only when submit returns0. Release uses a
 *   freshly read mutex handle. Publishes original raw result before classification/recovery. Only
 *   first -12/-11/-14/-10/-9 issue one fresh-setup DEVICE18 request, timeout500, to shared
 *   scratch. A second nonnegative or -8 returns3 for original -14/-10, otherwise0. Other second
 *   negatives return255; second -14/-10 also MEMW/sets shared gate1. No connected, NULL, scratch
 *   capacity, exact-length, ownership or rollback guard occurs. Captured setup/endpoint and
 *   original result remain stable across delegated mutations; later setup/mutex handles are
 *   freshly read.
 */

uint medius_host_classify_control_probe(
    MediusHostHubPortPrefix *port,uint request_type,uint request,uint value,uint index,
    uint length,int *result,uint timeout)
{
    volatile uchar *setup = *(uchar * const volatile *)&port->setup;
    setup[0] = (uchar)request_type;
    setup[1] = (uchar)request;
    void *mutex = *(void * const volatile *)&port->control_mutex;
    setup[2] = (uchar)value;
    setup[3] = (uchar)(value >> 8);
    setup[4] = (uchar)index;
    setup[5] = (uchar)(index >> 8);
    setup[6] = (uchar)length;
    setup[7] = (uchar)(length >> 8);
    usb_osal_mutex_take(mutex);
    volatile MediusHostUrb *urb = &port->control_urb;
    uchar *endpoint = port->ep0_descriptor;
    urb->setup = (uchar *)setup;
    urb->buffer = MEDIUS_HOST_ENUMERATION_DATA;
    urb->hubport = port;
    urb->endpoint = endpoint;
    urb->remaining = length & 0xffffU;
    urb->timeout = timeout;
    urb->complete = 0;
    urb->context = 0;
    int first_result = usbh_submit_urb((MediusHostUrb *)urb);
    if (first_result == 0)
        first_result = (int)urb->actual;
    usb_osal_mutex_give(*(void * const volatile *)&port->control_mutex);
    if (result != 0)
        *(volatile int *)result = first_result;
    if (first_result >= 0)
        return first_result - 8 > (int)(length & 0xffffU) ? 4U : 1U;
    if (first_result == -8)
        return 2;
    if (first_result != -12 && first_result != -11 && first_result != -14 &&
        first_result != -10 && first_result != -9)
        return 255;

    setup = *(uchar * const volatile *)&port->setup;
    setup[0] = 0x80;
    setup[1] = 6;
    mutex = *(void * const volatile *)&port->control_mutex;
    setup[3] = 1;
    setup[6] = 18;
    setup[2] = 0;
    setup[4] = 0;
    setup[5] = 0;
    setup[7] = 0;
    usb_osal_mutex_take(mutex);
    urb->remaining = 18;
    urb->setup = (uchar *)setup;
    urb->hubport = port;
    urb->endpoint = endpoint;
    urb->buffer = MEDIUS_HOST_ENUMERATION_DATA;
    urb->timeout = 500;
    urb->complete = 0;
    urb->context = 0;
    int recovery_result = usbh_submit_urb((MediusHostUrb *)urb);
    if (recovery_result == 0)
        recovery_result = (int)urb->actual;
    usb_osal_mutex_give(*(void * const volatile *)&port->control_mutex);
    if (recovery_result >= 0 || recovery_result == -8)
        return first_result == -14 || first_result == -10 ? 3U : 0U;
    if (recovery_result == -14 || recovery_result == -10) {
        memw();
        MEDIUS_HOST_CLONE_ACTIVE = 1;
    }
    return 255;
}

/* Native entry: 0x420277cc. */
/*
 * Medius v3.4.7 — host application; 0x420277cc.
 *
 * Probes response counts and zero padding with64-byte and low16(expected+3)-byte control requests.
 *
 * Calls: medius_host_classify_control_probe.
 *
 * Called by: medius_host_capture_descriptors_and_probe_controls.
 *
 * Original function-byte SHA-256:
 * 7a9c59f2915c8107f0978656ec09e8396dc2ce4750a786175893a34809d8c27e.
 */

/*
 * port: Borrowed live port passed to each classifier invocation.
 * request_type: Forwarded full32 to classifier, which narrows SETUP fields.
 * request: Forwarded full32 request selector.
 * index: Forwarded full32 index.
 * expected_length: Full32 comparison/index input; request and threshold additions narrow to16
 *   bits.
 * Returns: Initial non1 classifier code passes through. Initial small raw result gives1. Fully
 *   matching two-stage zero padding gives5; mismatch gives6. Second255 passes through.
 * Requirements/effects: First requests64 bytes with value0/timeout500 and a scalar int32 raw-
 *   result output. Only code1 with signed raw result greater than low16(expected+8) enters padding
 *   analysis; it must equal72. Reads zero bytes at fixed transfer scratch[expected..63], then
 *   requests low16(expected+3). Second code1 must have raw result low16(second_length+8), and
 *   scratch[expected..second_length-1] must be zero; code255 is retained, all other second codes
 *   fail6. Full32 expected is compared with narrowed request lengths, so exaggerated values can
 *   skip reads or admit far-tail indices without any local capacity guard. No buffer clearing,
 *   scratch restoration, lock, allocation or authenticated identity test occurs. The scratch is
 *   adjacent to the separate64-byte credit packet and is not an extension of that object.
 */

uint medius_host_probe_response_padding(
    MediusHostHubPortPrefix *port,uint request_type,uint request,uint index,uint expected_length)
{
    int raw_result;
    uint code = medius_host_classify_control_probe(
        port,request_type,request,0,index,64,&raw_result,500);
    if (code != 1)
        return code;
    if (raw_result <= (int)((expected_length + 8U) & 0xffffU))
        return 1;
    if (raw_result != 72)
        return 6;
    const volatile uchar *response = (const volatile uchar *)MEDIUS_HOST_ENUMERATION_DATA;
    for (uint offset = expected_length; offset < 64; ++offset) {
        if (response[offset] != 0)
            return 6;
    }
    uint second_length = (expected_length + 3U) & 0xffffU;
    code = medius_host_classify_control_probe(
        port,request_type,request,0,index,second_length,&raw_result,500);
    if (code == 255)
        return 255;
    if (code != 1 || (uint)raw_result != ((second_length + 8U) & 0xffffU))
        return 6;
    for (uint offset = expected_length; offset < second_length; ++offset) {
        if (response[offset] != 0)
            return 6;
    }
    return 5;
}

/* Native entry: 0x4202788c. */
/*
 * Medius v3.4.7 — host application; 0x4202788c.
 *
 * Checks current device and selected configuration responses against saved bytes across at most
 * three attempts.
 *
 * Calls: memcmp, usb_osal_mutex_give, usb_osal_mutex_take, usbh_submit_urb.
 *
 * Called by: medius_host_capture_descriptors_and_probe_controls,
 * medius_host_control_no_data_retry.
 *
 * Original function-byte SHA-256:
 * aed635e995eeabe95b0a1235bc12899eed4c8f946483e62f2b553a4c5bb01bb0.
 */

/*
 * port: Live port with EP0 SETUP/mutex/URB and readable stored device descriptor.
 * Returns: 1 when selected descriptor/configuration comparisons succeed; otherwise0 after failure
 *   or at most three attempts.
 * Requirements/effects: Each attempt requests DEVICE18/timeout500 to fixed shared scratch, uses
 *   actual only on submit0 and releases a freshly read mutex before comparisons. Requires raw26
 *   and ROM memcmp18 against current port descriptor. A cached saved GET_CONFIGURATION result9/-8
 *   selects a one-byte GET_CONFIGURATION request; afterwards compares a freshly read saved result,
 *   accepting matching negative or matching nonnegative plus fresh saved byte. Otherwise saved
 *   configuration length<9 accepts device match alone; length>=9 requests descriptor0 length9 and
 *   requires raw>=17 plus nine matching bytes. Comparison access order is scratch word0 then
 *   reference word0, reference word4 then scratch word4, reference byte8 then scratch byte8,
 *   stopping at mismatch. Unexpected results retry only when nonnegative/-12/-11/-9; byte/value
 *   mismatches separately retry. On final failure reads connected, and last raw>=0/-14/[-12,-8]
 *   MEMW/sets gate1. All SETUP writes precede mutex acquisition; take/give errors are ignored.
 *   Endpoint address stays cached, setup/mutex and later saved values are refreshed. No initial
 *   connected, NULL, buffer capacity or authentication exchange is provided; shared
 *   response/reference comparisons occur after unlock and do not form one atomic identity
 *   snapshot.
 */

uint medius_host_verify_device_identity(MediusHostHubPortPrefix *port)
{
    volatile MediusHostUrb *urb = &port->control_urb;
    uchar *endpoint = port->ep0_descriptor;
    int last_result = 0;
    for (uint attempts_left = 3; attempts_left != 0; --attempts_left) {
        volatile uchar *setup = *(uchar * const volatile *)&port->setup;
        setup[0] = 0x80;
        setup[1] = 6;
        void *mutex = *(void * const volatile *)&port->control_mutex;
        setup[3] = 1;
        setup[2] = 0;
        setup[4] = 0;
        setup[5] = 0;
        setup[6] = 18;
        setup[7] = 0;
        usb_osal_mutex_take(mutex);
        urb->remaining = 18;
        urb->complete = 0;
        urb->context = 0;
        urb->hubport = port;
        urb->endpoint = endpoint;
        urb->setup = (uchar *)setup;
        urb->buffer = MEDIUS_HOST_ENUMERATION_DATA;
        urb->timeout = 500;
        last_result = usbh_submit_urb((MediusHostUrb *)urb);
        if (last_result == 0)
            last_result = (int)urb->actual;
        usb_osal_mutex_give(*(void * const volatile *)&port->control_mutex);
        if (last_result != 26)
            goto unexpected_result;
        if (memcmp((const void *)MEDIUS_HOST_ENUMERATION_DATA,port->device_descriptor,18) != 0)
            continue;

        int saved_configuration_result = HOST_CAPTURE_CONFIGURATION_RESULT;
        if (saved_configuration_result == 9 || saved_configuration_result == -8) {
            setup = *(uchar * const volatile *)&port->setup;
            setup[0] = 0x80;
            setup[1] = 8;
            mutex = *(void * const volatile *)&port->control_mutex;
            setup[2] = 0;
            setup[3] = 0;
            setup[4] = 0;
            setup[5] = 0;
            setup[6] = 1;
            setup[7] = 0;
            usb_osal_mutex_take(mutex);
            urb->setup = (uchar *)setup;
            urb->remaining = 1;
            urb->complete = 0;
            urb->context = 0;
            urb->hubport = port;
            urb->endpoint = endpoint;
            urb->buffer = MEDIUS_HOST_ENUMERATION_DATA;
            urb->timeout = 500;
            last_result = usbh_submit_urb((MediusHostUrb *)urb);
            if (last_result == 0)
                last_result = (int)urb->actual;
            usb_osal_mutex_give(*(void * const volatile *)&port->control_mutex);
            int current_saved_result = HOST_CAPTURE_CONFIGURATION_RESULT;
            if (current_saved_result != last_result)
                goto unexpected_result;
            if (last_result < 0)
                return 1;
            uchar response_value = *(const volatile uchar *)MEDIUS_HOST_ENUMERATION_DATA;
            uchar current_saved_value = HOST_CAPTURE_CONFIGURATION_VALUE;
            if (response_value == current_saved_value)
                return 1;
            continue;
        }
        ushort saved_configuration_length = HOST_CAPTURED_CONFIGURATION_LENGTH;
        if (saved_configuration_length < 9)
            return 1;
        setup = *(uchar * const volatile *)&port->setup;
        setup[0] = 0x80;
        setup[1] = 6;
        mutex = *(void * const volatile *)&port->control_mutex;
        setup[3] = 2;
        setup[2] = 0;
        setup[4] = 0;
        setup[5] = 0;
        setup[6] = 9;
        setup[7] = 0;
        usb_osal_mutex_take(mutex);
        urb->remaining = 9;
        urb->setup = (uchar *)setup;
        urb->hubport = port;
        urb->endpoint = endpoint;
        urb->buffer = MEDIUS_HOST_ENUMERATION_DATA;
        urb->timeout = 500;
        urb->complete = 0;
        urb->context = 0;
        last_result = usbh_submit_urb((MediusHostUrb *)urb);
        if (last_result == 0)
            last_result = (int)urb->actual;
        usb_osal_mutex_give(*(void * const volatile *)&port->control_mutex);
        if (last_result < 17)
            goto unexpected_result;
        uint response_first = HOST_CONTROL_CONFIGURATION_HEADER->first_word;
        uint saved_first = HOST_CAPTURED_CONFIGURATION_HEADER->first_word;
        if (response_first != saved_first)
            continue;
        uint saved_second = HOST_CAPTURED_CONFIGURATION_HEADER->second_word;
        uint response_second = HOST_CONTROL_CONFIGURATION_HEADER->second_word;
        if (saved_second != response_second)
            continue;
        uchar saved_ninth = HOST_CAPTURED_CONFIGURATION_HEADER->final_byte;
        uchar response_ninth = HOST_CONTROL_CONFIGURATION_HEADER->final_byte;
        if (saved_ninth == response_ninth)
            return 1;
        continue;

unexpected_result:
        if (last_result < 0 && last_result != -12 && last_result != -11 && last_result != -9)
            break;
    }
    if (*(const volatile uchar *)&port->connected != 0 &&
        (last_result >= 0 || last_result == -14 || (last_result >= -12 && last_result <= -8))) {
        memw();
        MEDIUS_HOST_CLONE_ACTIVE = 1;
    }
    return 0;
}

/* Native entry: 0x42027bf8. */
/*
 * Medius v3.4.7 — host application; 0x42027bf8.
 *
 * Returns a requested configuration index only for the tracked VID/PID, rereading the index after
 * identity match.
 *
 * Called by: usbh_enumerate.
 *
 * Original function-byte SHA-256:
 * 155281304c9c1ff5ac37fd8cdd5f2b73cb69ccd3eb06adbfd91b32970dc59986.
 */

/*
 * port: Optional port whose stored device descriptor identity is compared; NULL returns 0.
 * Returns: Fresh selector byte on identity match after initial nonzero admission; otherwise 0.
 * Requirements/effects: MEMW before initial selector read. Caches the aligned word at port+16,
 *   then byte at port+15; compares reconstructed VID against the target halfword before
 *   reading/comparing target PID. On both matches executes MEMW and rereads selector, which may
 *   now be zero. No calls, writes, descriptor-valid or connected checks occur. The word snapshot
 *   also reads the descriptor byte at port+19; identity and selector/targets are not one atomic
 *   sample.
 */

uchar medius_host_select_enumeration_configuration(MediusHostHubPortPrefix *port)
{
    if (port == 0)
        return 0;
    memw();
    uchar requested = MEDIUS_HOST_REQUESTED_CONFIGURATION;
    if (requested == 0)
        return 0;
    /* Native aligned port word+16 precedes identity low byte+15. */
    uint identity_word = *(const volatile uint *)((uint)port + 16U);
    uint vendor_low = ((const volatile uchar *)port)[15];
    ushort target_vendor = MEDIUS_HOST_CURRENT_VENDOR_ID;
    if (target_vendor != ((identity_word & 0xffU) << 8 | vendor_low))
        return 0;
    ushort target_product = MEDIUS_HOST_CURRENT_PRODUCT_ID;
    if (target_product != ((identity_word >> 8) & 0xffffU))
        return 0;
    memw();
    return MEDIUS_HOST_REQUESTED_CONFIGURATION;
}

/* Native entry: 0x4202823c. */
/*
 * Medius v3.4.7 — host application; 0x4202823c.
 *
 * Fetches a configuration header then its bounded full descriptor into shared scratch, retaining
 * bytes on failure and returning the saved length only after the encoded transfer-count checks.
 *
 * Calls: medius_host_log_formatted, usbh_control_transfer.
 *
 * Called by: medius_host_capture_descriptors_and_probe_controls.
 *
 * Original function-byte SHA-256:
 * 26520ec4cdb47a74bb3372817738ab9a5feb4a1508f12dc97fa5e7a042819fca.
 */

/*
 * port: Live port with writable8-byte SETUP buffer; pointer is cached for both requests.
 * configuration_index: Low8 selects the wire descriptor index; full32 is retained for diagnostics.
 * Returns: Saved first-header total9..2048 only when second signed result>=8 and low16(result-8)
 *   equals that saved total; otherwise0.
 * Requirements/effects: Builds eight request bytes in native order and fetches a nine-byte header
 *   into shared scratch. Requires first result>=17 before reading/checking type2, then reads
 *   total16 ONCE and admits9..2048. Updates only cached SETUP length bytes and fetches full
 *   length; changes to port.setup/other request fields are retained without rebuilding. Second
 *   header/type/total are not revalidated. Failure logs the appropriate format plus full index/raw
 *   result/saved total and leaves request/response bytes intact. Positive multiples of65536 in the
 *   encoded second result can pass the low16 equality. No bLength, connection, ownership, local
 *   lock, retry or rollback check is added; scratch capacity and physical transfers remain
 *   delegated requirements.
 */

uint medius_host_fetch_configuration_descriptor(MediusHostHubPortPrefix *port,uint configuration_index)
{
    volatile uchar *setup = *(uchar * const volatile *)&port->setup;
    setup[0] = 0x80;
    setup[1] = 6;
    setup[3] = 2;
    setup[4] = 0;
    setup[5] = 0;
    setup[7] = 0;
    setup[2] = (uchar)configuration_index;
    setup[6] = 9;
    int header_result = usbh_control_transfer(port,(uchar *)setup,MEDIUS_HOST_ENUMERATION_DATA);
    if (header_result < 17 || ((const volatile uchar *)MEDIUS_HOST_ENUMERATION_DATA)[1] != 2) {
        medius_host_log_formatted("config %u header fetch failed (r=%d)",configuration_index,header_result);
        return 0;
    }
    ushort total_length = *(const volatile ushort *)(MEDIUS_HOST_ENUMERATION_DATA + 2);
    if (total_length < 9 || total_length > 2048) {
        medius_host_log_formatted("config %u wTotalLength %u does not fit",configuration_index,(uint)total_length);
        return 0;
    }
    setup[6] = (uchar)total_length;
    setup[7] = (uchar)(total_length >> 8);
    int full_result = usbh_control_transfer(port,(uchar *)setup,MEDIUS_HOST_ENUMERATION_DATA);
    if (full_result >= 8 && (((uint)full_result - 8U) & 0xffffU) == total_length)
        return total_length;
    medius_host_log_formatted("config %u full read r=%d != %u",configuration_index,full_result,(uint)total_length);
    return 0;
}

/* Native entry: 0x42028768. */
/*
 * Medius v3.4.7 — host application; 0x42028768.
 *
 * Selects unvisited HID configurations for pre-capture, or schedules restoration of configuration
 * index0.
 *
 * Calls: __divdi3, esp_timer_get_time, medius_host_log_formatted,
 * medius_host_merge_hid_descriptor_blob, xQueueGenericSend.
 *
 * Called by: medius_snapshot_timer_cb.
 *
 * Original function-byte SHA-256:
 * 0a4d65f15ea6757caa231f48c2ee03d06f5b9e2e7b480fff214f08c1e2a55769.
 */

/*
 * Returns: 1 when a HID candidate or return-to-zero is scheduled, otherwise0; queue success does
 *   not affect this result.
 * Requirements/effects: Caches current VID, configuration count and PID once, resetting archive
 *   identity/used/completion before phase admission if changed. Active identity mismatch logs
 *   abandonment and clears phase/selector. Phase0 requires count>=2 and incomplete capture, saves
 *   identity, marks low3(current index), and optionally merges current HID blob; phase1 marks
 *   low3(requested index), loads blob length before publishing visited, rereads requested and
 *   optionally merges, logging zero/255/merge0. Other phases clear phase and mark complete.
 *   Selects first unvisited HID configuration among indices0..7 using cached advertised lengths.
 *   Other configurations walk little-endian total lengths, reading high byte then low; bounds use
 *   full sum but traversal offset narrows16. Descriptor scan reads length then type before
 *   validating length, advances offset modulo65536, and counts only
 *   type4/length>=9/alternate0/class3. A prior match survives malformed tail. Candidate
 *   phase/request are published before log, selector after log. Exhaustion freshly reads current
 *   index: zero completes, otherwise phase2/selector0 schedules restoration. Scheduling calls
 *   signed64 time/1000, caches wake handle before timestamp store, sends nonblocking NULL item if
 *   cached handle is nonNULL, ignores result. No local USB configuration transfer, rollback,
 *   capacity or NULL-pointer checks, lock or real-time guarantee. Valid advertised storage and
 *   serialized caller lifecycle are required; malformed large spans may wrap/repeat. Raw integer
 *   address arithmetic avoids imposing nonexistent C object bounds.
 */

int medius_host_prepare_configuration_capture(void)
{
    volatile MediusConfigurationCaptureState *capture =
        MEDIUS_HOST_PRECAPTURE;
    ushort current_vendor = capture->current_vendor;
    uchar configuration_count = HOST_CAPTURE_CONFIGURATION_COUNT;
    ushort archive_vendor = HOST_CAPTURE_ARCHIVE_VENDOR;
    ushort current_product = capture->current_product;
    if (archive_vendor != current_vendor ||
        HOST_CAPTURE_ARCHIVE_PRODUCT != current_product) {
        HOST_CAPTURE_ARCHIVE_VENDOR = current_vendor;
        ((volatile MediusHidDescriptorArchive *)&medius_hid_descriptor_archive)->used = 0;
        HOST_CAPTURE_ARCHIVE_PRODUCT = current_product;
        memw();
        MEDIUS_HOST_PRECAPTURE_COMPLETE = 0;
    }
    memw();
    uchar admission_phase = capture->phase;
    if (admission_phase != 0) {
        memw();
        ushort saved_vendor = capture->saved_vendor;
        if (saved_vendor != current_vendor)
            goto abandoned;
        memw();
        if (capture->saved_product != current_product)
            goto abandoned;
    }
    memw();
    uchar phase = capture->phase;
    if (phase == 0) {
        if (configuration_count < 2)
            return 0;
        memw();
        if (MEDIUS_HOST_PRECAPTURE_COMPLETE != 0)
            return 0;
        uchar current_index = MEDIUS_HOST_CURRENT_CONFIGURATION;
        memw();
        capture->saved_vendor = current_vendor;
        ushort blob_length = *(const volatile ushort *)&medius_hid_descriptor_blob_used;
        memw();
        capture->saved_product = current_product;
        memw();
        capture->visited = (uchar)(1U << (current_index & 7U));
        if (blob_length != 0 && current_index != 255)
            medius_host_merge_hid_descriptor_blob(current_index,blob_length,255);
    } else if (phase == 1) {
        memw();
        uchar requested_index = capture->requested;
        memw();
        uchar visited = capture->visited;
        uchar next_visited = visited | (uchar)(1U << (requested_index & 7U));
        ushort blob_length = *(const volatile ushort *)&medius_hid_descriptor_blob_used;
        memw();
        capture->visited = next_visited;
        memw();
        uchar merge_index = capture->requested;
        if (blob_length == 0 || merge_index == 255 ||
            medius_host_merge_hid_descriptor_blob(merge_index,blob_length,255) == 0) {
            memw();
            uchar logged_index = capture->requested;
            medius_host_log_formatted(
                "configuration %u report descriptors did not fit the pre-capture budget",
                logged_index);
        }
        if (configuration_count == 0)
            goto exhausted;
    } else {
        memw();
        capture->phase = 0;
        memw();
        MEDIUS_HOST_PRECAPTURE_COMPLETE = 1;
        return 0;
    }
    memw();
    uchar initial_visited = capture->visited;
    ushort other_length = HOST_OTHER_CONFIGURATION_LENGTH;
    ushort first_length = HOST_CAPTURED_CONFIGURATION_LENGTH;
    for (uint candidate = 0; candidate < configuration_count && candidate < 8; ++candidate) {
        uchar visited;
        if (candidate == 0) {
            visited = initial_visited;
        } else {
            memw();
            visited = capture->visited;
        }
        if ((visited & (1U << candidate)) != 0)
            continue;
        const volatile uchar *descriptors = 0;
        uint span_length = 0;
        if (candidate == 0) {
            if (first_length > 1) {
                descriptors = HOST_FIRST_CONFIGURATION_BYTES;
                span_length = first_length;
            }
        } else if (other_length >= 4) {
            uint offset = 0;
            for (uint remaining = candidate - 1U;; --remaining) {
                const volatile uchar *header =
                    (const volatile uchar *)((uint)HOST_OTHER_CONFIGURATION_BYTES + offset);
                uchar length_high = header[3];
                uchar length_low = header[2];
                uint length = ((uint)length_high << 8) | length_low;
                uint next_offset = (offset + length) & 0xffffU;
                if (length < 4 || offset + length > other_length)
                    break;
                if (remaining == 0) {
                    descriptors = header;
                    span_length = length;
                    break;
                }
                offset = next_offset;
                if (offset + 4U > other_length)
                    break;
            }
        }
        uint hid_interfaces = 0;
        if (descriptors != 0) {
            uint offset = 0;
            do {
                const volatile uchar *descriptor =
                    (const volatile uchar *)((uint)descriptors + offset);
                uchar length = descriptor[0];
                offset = (offset + length) & 0xffffU;
                uchar type = descriptor[1]; /* Read even when length fails below. */
                if (length < 2 || offset > span_length)
                    break;
                if (type == 4 && length > 8) {
                    uchar alternate = descriptor[3];
                    if (alternate == 0 && descriptor[5] == 3)
                        ++hid_interfaces;
                }
            } while (offset + 1U < span_length);
        }
        if (hid_interfaces != 0) {
            memw();
            capture->phase = 1;
            memw();
            capture->requested = (uchar)candidate;
            medius_host_log_formatted("pre-capturing configuration %u of %u",
                                      candidate,configuration_count);
            memw();
            capture->selector = (uchar)candidate;
            goto scheduled;
        }
        memw();
        uchar fresh_visited = capture->visited;
        memw();
        capture->visited = fresh_visited | (uchar)(1U << candidate);
    }
exhausted:
    if (MEDIUS_HOST_CURRENT_CONFIGURATION == 0) {
        memw();
        capture->phase = 0;
        memw();
        MEDIUS_HOST_PRECAPTURE_COMPLETE = 1;
        return 0;
    }
    memw();
    capture->phase = 2;
    memw();
    capture->selector = 0;
scheduled:
    {
        longlong now = esp_timer_get_time();
        uint milliseconds = (uint)__divdi3(now,1000);
        void *wake = capture->wake;
        memw();
        capture->timestamp_ms = milliseconds;
        if (wake != 0)
            xQueueGenericSend(wake,0,0,0);
        return 1;
    }
abandoned:
    medius_host_log_formatted("device changed during pre-capture; abandoned");
    memw();
    capture->phase = 0;
    memw();
    capture->selector = 0;
    return 0;
}

/* Native entry: 0x42028a90. */
/*
 * Medius v3.4.7 — host application; 0x42028a90.
 *
 * Claims one capture snapshot and routes configuration binding, identity-change detach,
 * pre-capture or clone publication.
 *
 * Calls: medius_clone_publish, medius_host_log_formatted, medius_host_merge_hid_descriptor_blob,
 * medius_host_prepare_configuration_capture, medius_host_publish_hid_descriptor_blob,
 * link_send_wait100.
 *
 * Original function-byte SHA-256:
 * b91ae257bb35e83a67242f6767e0f258492cc60d622fc4b5339dd9a15d616878.
 */

/*
 * Returns: No value; once admitted, the claimed flag remains set on every return path.
 * Requirements/effects: Rejects disabled or already-claimed state. MEMW-snapshots configuration
 *   switch then pending BEFORE one claim store. Cached pending normalizes pending1 and returns;
 *   otherwise freshly reads clone state, and clone-active/switch0/pre-capture0 likewise defers.
 *   Switch0 proceeds to preparation. Switch nonzero snapshots current VID, previous VID, current
 *   PID, previous PID in that order; identity-refresh is read only for equal IDs. Equal
 *   IDs/refresh0 clear switch with cached zero, read selector then blob length, and publish
 *   nonempty blob. Reload selector then used after publication; merge only non255 selector/nonzero
 *   used, ignoring result. Logs fresh selector but pre-merge cached used, then publishes the fresh
 *   tracked port to control port. Used0 still performs an extra selector read before the log read.
 *   Changed identity rereads clone state; active sets pending before logging. Logs all four cached
 *   IDs, clears switch/refresh/selector/pre-capture-complete/archive used, and sends an empty
 *   type0x12 frame with four explicit arguments. Cached active then returns; inactive proceeds to
 *   preparation. Any nonzero preparation result returns. On0, fresh forwarding-inhibit0 clones,
 *   otherwise sets deferred1, then publishes fresh tracked port. No argument is consumed, flag
 *   clearing, lock, connection/lifetime check, rollback or dependency-status propagation. Mixed
 *   cached/fresh fields form no atomic snapshot; timer dispatch and dependencies determine when
 *   this work runs.
 */

void medius_snapshot_timer_cb(void)
{
    if (MEDIUS_HOST_DESCRIPTORS_READY == 0)
        return;
    if (MEDIUS_HOST_CAPTURE_READY != 0)
        return;
    memw();
    uchar configuration_switch = MEDIUS_HOST_CONFIGURATION_SWITCH_GATE;
    memw();
    uchar pending = MEDIUS_HOST_CAPTURE_PENDING;
    MEDIUS_HOST_CAPTURE_READY = 1; /* Claim only once. */
    if (pending != 0)
        goto defer_reclone;
    memw();
    uchar clone_active = MEDIUS_HOST_CLONE_ACTIVE;
    if (clone_active != 0 && configuration_switch == 0) {
        memw();
        if (MEDIUS_HOST_PRECAPTURE->phase == 0)
            goto defer_reclone;
    }
    if (configuration_switch == 0)
        goto prepare_capture;

    uint current_vendor = MEDIUS_HOST_CURRENT_VENDOR_ID;
    uint previous_vendor = MEDIUS_HOST_PREVIOUS_VENDOR_ID;
    uint current_product = MEDIUS_HOST_CURRENT_PRODUCT_ID;
    uint previous_product = MEDIUS_HOST_PREVIOUS_PRODUCT_ID;
    uchar identity_refresh = 1;
    if (current_vendor == previous_vendor && current_product == previous_product) {
        memw();
        identity_refresh = MEDIUS_HOST_IDENTITY_REFRESH;
    }
    if (identity_refresh == 0) {
        memw();
        MEDIUS_HOST_CONFIGURATION_SWITCH_GATE = identity_refresh;
        memw();
        uchar selector = MEDIUS_HOST_REQUESTED_CONFIGURATION;
        uint available_bytes = *(const volatile ushort *)&medius_hid_descriptor_blob_used;
        if (available_bytes != 0) {
            medius_host_publish_hid_descriptor_blob(selector,available_bytes);
            memw();
            selector = MEDIUS_HOST_REQUESTED_CONFIGURATION;
            available_bytes = *(const volatile ushort *)&medius_hid_descriptor_blob_used;
            if (selector != 255 && available_bytes != 0)
                medius_host_merge_hid_descriptor_blob(selector,available_bytes,255);
        } else {
            /* Native code still performs this otherwise unused selector read. */
            memw();
            (void)MEDIUS_HOST_REQUESTED_CONFIGURATION;
        }
        memw();
        uint logged_selector = MEDIUS_HOST_REQUESTED_CONFIGURATION;
        medius_host_log_formatted(
            "configuration %u bound; %u B of report descriptors pushed, clone left up",
            logged_selector,available_bytes);
        goto publish_control_port;
    }
    memw();
    clone_active = MEDIUS_HOST_CLONE_ACTIVE;
    if (clone_active != 0) {
        memw();
        MEDIUS_HOST_CAPTURE_PENDING = 1;
    }
    medius_host_log_formatted(
        "device changed during the restart (%04x:%04x -> %04x:%04x); re-cloning it instead",
        previous_vendor,previous_product,current_vendor,current_product);
    memw();
    MEDIUS_HOST_CONFIGURATION_SWITCH_GATE = 0;
    memw();
    MEDIUS_HOST_IDENTITY_REFRESH = 0;
    memw();
    MEDIUS_HOST_REQUESTED_CONFIGURATION = 0;
    memw();
    MEDIUS_HOST_PRECAPTURE_COMPLETE = 0;
    *(volatile ushort *)&medius_hid_descriptor_archive.used = 0;
    link_send_wait100(0x12,0,0,0);
    if (clone_active != 0)
        return;

prepare_capture:
    if (medius_host_prepare_configuration_capture() != 0)
        return;
    memw();
    if (MEDIUS_HOST_FORWARDING_INHIBIT == 0) {
        medius_clone_publish();
    } else {
        memw();
        MEDIUS_HOST_CLONE_PUBLICATION_PENDING = 1;
    }
publish_control_port:
    memw();
    MediusHostHubPortPointer port =
        MEDIUS_HOST_CAPTURED_PORT;
    memw();
    MEDIUS_HOST_CONTROL_PORT = port;
    return;
defer_reclone:
    memw();
    MEDIUS_HOST_CAPTURE_PENDING = 1;
}

/* Native entry: 0x4202ae2c. */
/*
 * Medius v3.4.7 — host application; 0x4202ae2c.
 *
 * Captures device/configuration/string/speed descriptors, profiles control-request behavior,
 * publishes HID deviations and failure caches, and flags endpoint-count anomalies.
 *
 * Calls: __divdi3, esp_timer_get_time, medius_copy_forward_words, medius_host_cached_string_ascii,
 * medius_host_capture_string_descriptor, medius_host_classify_control_probe,
 * medius_host_collect_string_ids, medius_host_control_no_data_retry,
 * medius_host_fetch_configuration_descriptor, medius_host_log_formatted,
 * medius_host_probe_response_padding, medius_host_verify_device_identity,
 * medius_out_reset_toggles_resume, medius_vendor_reset_selection_state, memcmp, memcpy, memmove,
 * memset, usb_osal_mutex_give, usb_osal_mutex_take, usbh_control_transfer, usbh_submit_urb.
 *
 * Called by: medius_hid_attach_interface, medius_usb_host_event.
 *
 * Original function-byte SHA-256:
 * 74e566d59e18301268e8138a9c8d183868630fc36072d774e65aeb155c5ec002.
 */

/*
 * port: Borrowed initialized host port with live SETUP, control URB, mutex and device descriptor.
 *   Shared scratch and archive ownership must be serialized by its caller.
 * Returns: No value. Captures and profiles the attached device, updates metadata/recovery caches,
 *   and scans for endpoint-count anomalies on every exit.
 * Requirements/effects: Resets HID, vendor and OUT state, then snapshots the 18-byte device
 *   descriptor and index-zero base configuration (local limit: 2,048 bytes). Retains up to 6,144
 *   bytes of additional configurations. String capture shares a budget across up to 48 IDs and
 *   four languages, with a 1,536-byte archive and three 128-byte ASCII outputs. Each next live
 *   string ID is read before the previous string length is published. BOS, qualifier and other-
 *   speed limits are 256, 10 and 1,024 bytes. Matching identity can reuse metadata; otherwise a
 *   59-byte payload is serialized into a 512-byte archive with a 69-byte initial prefix. The
 *   selected descriptor scan derives interface and endpoint masks, the first endpoint, maximum
 *   alternate setting and up to 16 HID candidates. Runs the original 23-row control/padding table
 *   and descriptor, interface, endpoint, wakeup, alternate-setting and configuration probes.
 *   Ordinary admission uses unsigned low-32-bit elapsed milliseconds <= 2,000; dependent
 *   readbacks, restoration and cleanup can run without another time check. Full-width classifier
 *   result 255 aborts before the current byte is stored. Direct URBs retain the saved SETUP
 *   pointer while reloading mutex handles; specified lock/submit results are ignored. Prunes
 *   selected HID records, appends bounded differences and preserves stale tails. Failure
 *   serialization preserves the raw 16-bit status and updates four-slot quirk or eight-slot
 *   exclusion caches using trusted old indices. Every exit clears capture-running and scans for
 *   the first interface with more complete endpoint descriptors than declared; the observed count
 *   wraps at eight bits. Access widths, mutable-memory ordering, cached versus fresh fields,
 *   partial side effects, the saved baseline pointer, full-width alternate comparison and signed
 *   raw transfer counts are retained in the body. This routine supplies neither an atomic cross-
 *   core snapshot nor a whole-function timing guarantee.
 */

void medius_host_capture_descriptors_and_probe_controls(MediusHostHubPortPrefix *port)
{
    volatile MediusHostHubPortPrefix *live_port = port;
    volatile MediusHostCapturedConfigurations *configurations =
        (volatile MediusHostCapturedConfigurations *)0x3fcace08U;
    volatile MediusHostCapturedDevice *device =
        (volatile MediusHostCapturedDevice *)0x3fcad618U;
    volatile MediusConfigurationCaptureState *selection =
        (volatile MediusConfigurationCaptureState *)0x3fcaff00U;
    volatile MediusHostControlProbeCache *cache =
        (volatile MediusHostControlProbeCache *)0x3fca96d0U;
    MediusHostCaptureScratch scratch;
    MediusHostCaptureResults results;
    ushort languages[4];
    MediusStringCaptureBudget string_budget;
    uint anomaly_base_length;
    /* The native caller spills and reloads this pointer separately from the
       fixed archive addresses used for selected type/count reads below. */
    volatile uchar *volatile base_descriptor;

    /* Configuration/device archive capture. Each helper retains borrowed data
       only for its stated call; publications preserve the native store order. */
    memw();
    *(volatile uchar *)0x3fca9770U = 0;
    *(volatile uchar *)0x3fcad635U = 1;
    memw();
    medius_host_hid_paused = 0;
    medius_vendor_reset_selection_state();
    medius_out_reset_toggles_resume();
    memw();
    *(volatile uchar *)0x3fcaff26U = 0;
    *(volatile uchar *)0x3fcad634U = 0;
    medius_hid_endpoint_count = 0;
    memw();
    *(MediusHostHubPortPrefix *volatile *)0x3fca97ecU = port;
    medius_hid_descriptor_blob[0] = 0;
    medius_hid_descriptor_blob_used = 1;
    device->length = 18;
    memcpy((void *)device->descriptor, port->device_descriptor, 18);
    *(volatile uchar *)0x3fcaa818U = live_port->speed;
    uint vendor_high = *(volatile uchar *)((uint)port + 16U);
    uint vendor_low = *(volatile uchar *)((uint)port + 15U);
    selection->current_vendor = (vendor_high << 8) | vendor_low;
    uint product_word = *(volatile uint *)((uint)port + 16U);
    uchar device_configuration_count = *(volatile uchar *)((uint)port + 24U);
    selection->current_product = product_word >> 8;
    configurations->base_length = 0;
    configurations->additional_length = 0;
    configurations->archived_count = 1;

    uint selected_index = 0;
    if (device_configuration_count < 2) {
        configurations->selected_index = 0;
        if (device_configuration_count == 0)
            configurations->selected_index = 0;
    } else {
        memw();
        uchar requested = selection->selector;
        if (requested == 0) {
            configurations->selected_index = 0;
        } else {
            memw();
            requested = selection->selector;
            configurations->selected_index = requested;
            if (requested >= device_configuration_count) {
                configurations->selected_index = 0;
            } else {
                selected_index = requested;
            }
        }
    }

    /* The selection value used above is cached by the native branch. A raw
       index0 source is used only on that branch, even if a helper changes it. */
    uchar *raw_configuration = 0;
    if (selected_index == 0)
        raw_configuration = live_port->raw_configuration;
    if (raw_configuration != 0) {
        uint high = *(volatile uchar *)(raw_configuration + 3);
        uint low = *(volatile uchar *)(raw_configuration + 2);
        uint length = (high << 8) | low;
        if (length > 2048)
            length = 2048;
        base_descriptor = configurations->base;
        memcpy((void *)configurations->base, raw_configuration, length);
        configurations->base_length = length;
    } else {
        uint length = medius_host_fetch_configuration_descriptor(port, 0);
        base_descriptor = configurations->base;
        if (((length - 1U) & 65535U) < 2048U) {
            memcpy((void *)configurations->base, (void *)0x3fc9ffe8U, length);
            configurations->base_length = length;
        }
    }
    device_configuration_count = *(volatile uchar *)((uint)port + 24U);
    if (device_configuration_count > 1) {
        configurations->archived_count = 1;
        uint used = 0;
        uint index = 1;
        do {
            uint length = medius_host_fetch_configuration_descriptor(port, index);
            if (length == 0)
                break;
            uint next = used + length;
            if (next > 6144U) {
                medius_host_log_formatted("config %u (%u B) does not fit the extra-config budget", index, length);
                break;
            }
            memcpy((void *)(0x3fca1a30U + used), (void *)0x3fc9ffe8U, length);
            uchar count = configurations->archived_count;
            index++;
            configurations->archived_count = count + 1;
            used = next & 65535U;
        } while ((index & 255U) < device_configuration_count);
        configurations->additional_length = used;
    }

    /* String phase: one shared two-second/retry budget, four language IDs,
      48 merged nonzero string IDs, then three cached ASCII strings. */
    medius_string_descriptor_archive_used = 0;
    ulonglong started = (ulonglong)esp_timer_get_time();
    string_budget.start_low = (uint)started;
    string_budget.start_high = started >> 32;
    string_budget.timeout_count = 0;
    uint capture_continues = medius_host_capture_string_descriptor(port, &string_budget, 0, 0, 255);
    uint archive_used = medius_string_descriptor_archive_used;
    uint language_count = 0;
    if (archive_used > 4) {
        uint cursor = 0;
        for (;;) {
            uint payload_length = *(volatile uchar *)(medius_string_descriptor_archive + cursor + 4);
            uint payload = cursor + 5;
            uint next = payload + payload_length;
            if (next > archive_used)
                break;
            uchar id = *(volatile uchar *)(medius_string_descriptor_archive + cursor);
            if (id == 0) {
                uchar status = *(volatile uchar *)(medius_string_descriptor_archive + cursor + 3);
                if (status != 0 || payload_length < 2)
                    break;
                uchar type = *(volatile uchar *)(medius_string_descriptor_archive + payload + 1);
                if (type != 3)
                    break;
                uint reported_length = *(volatile uchar *)(medius_string_descriptor_archive + payload);
                uint effective = reported_length < payload_length ? reported_length : payload_length;
                if (effective < 4)
                    break;
                uint last = ((effective - 4U) >> 1) & 127U;
                uint offset = payload + 2;
                for (uint count = 0; count < 4; count++) {
                    uint high = *(volatile uchar *)(medius_string_descriptor_archive + offset + 1);
                    uint low = *(volatile uchar *)(medius_string_descriptor_archive + offset);
                    languages[count] = (high << 8) | low;
                    language_count = (count + 1U) & 255U;
                    if (last == count)
                        break;
                    offset += 2;
                }
                break;
            }
            cursor = next & 65535U;
            if (cursor + 4U >= archive_used)
                break;
        }
    }
    if (language_count == 0) {
        languages[0] = 0x409;
        language_count = 1;
    }
    ushort preferred_language = languages[0];
    uint device_string_count = medius_host_collect_string_ids(0, 0, results.string_ids);
    uint string_count = medius_host_collect_string_ids((const uchar *)base_descriptor,
        configurations->base_length, results.string_ids);
    uchar archived_count = configurations->archived_count;
    if (archived_count > 1) {
        uint extra_used = configurations->additional_length;
        if (extra_used >= 4) {
            uint limit = (archived_count - 1U) & 255U;
            for (uint ordinal = 0; ordinal < limit; ordinal++) {
                uint cursor = 0;
                uint remaining = ordinal;
                for (;;) {
                    uint high = *(volatile uchar *)(0x3fca1a33U + cursor);
                    uint low = *(volatile uchar *)(0x3fca1a32U + cursor);
                    uint length = (high << 8) | low;
                    uint next = (cursor + length) & 65535U;
                    if (length < 4 || cursor + length > extra_used)
                        goto collected_string_ids;
                    if (remaining == 0) {
                        uint found = medius_host_collect_string_ids((const uchar *)(0x3fca1a30U + cursor),
                            length, scratch.string_ids);
                        for (uint item = 0; item < found; item++) {
                            uchar id = scratch.string_ids[item];
                            if (id == 0)
                                continue;
                            uint match = 0;
                            for (uint old = 0; old < string_count; old++)
                                if (results.string_ids[old] == id) {
                                    match = 1;
                                    break;
                                }
                            if (!match && string_count < 48)
                                results.string_ids[string_count++] = id;
                        }
                        break;
                    }
                    remaining = (remaining - 1U) & 255U;
                    cursor = next;
                    if (next + 4U > extra_used)
                        goto collected_string_ids;
                }
            }
        }
    }
collected_string_ids:
    uint has_english = 0;
    for (uint language = 0; language < language_count; language++)
        has_english |= languages[language] == 0x409;
    if (device_string_count != 0 && capture_continues != 0) {
        uint id_index = 0;
        do {
            uchar id = results.string_ids[id_index];
            uint language = 0;
            do {
                capture_continues = medius_host_capture_string_descriptor(port, &string_budget,
                    id, languages[language], 255);
                language++;
                if (language >= language_count) {
                    if (capture_continues != 0 && !has_english)
                        capture_continues = medius_host_capture_string_descriptor(port, &string_budget,
                            id, 0x409, 255);
                    break;
                }
            } while (capture_continues != 0);
            id_index++;
            /* Native continuation tests the full helper result with bitwise AND
               against the0/1 loop predicate, not a general nonzero test. */
            if ((capture_continues & (id_index < device_string_count)) == 0)
                break;
        } while (1);
    }
    if (capture_continues != 0) {
        capture_continues = medius_host_capture_string_descriptor(port, &string_budget, 238, 0, 18);
        if (capture_continues != 0) {
            uint id_index = device_string_count;
            while (id_index < string_count) {
                uchar id = results.string_ids[id_index];
                uint language = 0;
                do {
                    capture_continues = medius_host_capture_string_descriptor(port, &string_budget,
                        id, languages[language], 255);
                    language++;
                    if (language >= language_count)
                        break;
                } while (capture_continues != 0);
                id_index++;
                if (capture_continues == 0)
                    break;
            }
        }
    }
    for (uint language = 0; language < language_count; language++)
        if (languages[language] == 0x409)
            preferred_language = 0x409;
    uint text_length = medius_host_cached_string_ascii(live_port->device_descriptor[14],
        preferred_language, (char *)0x3fcab584U);
    /* Each next live ID is sampled before publishing the previous count. */
    uint next_string_id = live_port->device_descriptor[15];
    *(volatile ushort *)0x3fcaa820U = text_length;
    text_length = medius_host_cached_string_ascii(next_string_id,
        preferred_language, (char *)0x3fcab504U);
    next_string_id = live_port->device_descriptor[16];
    *(volatile ushort *)0x3fcaa81eU = text_length;
    text_length = medius_host_cached_string_ascii(next_string_id,
        preferred_language, (char *)0x3fcab484U);
    *(volatile ushort *)0x3fcaa81cU = text_length;
    if (capture_continues == 0)
        medius_host_log_formatted("strings: %u B captured, the rest asked for live",
            (uint)medius_string_descriptor_archive_used);

    /* BOS descriptor capture. */
    /* The two BOS attempts share the original SETUP pointer and buffer. A
       successful full transfer is judged against the saved header length. */
    uint bos_length = 0;
    uint usb_version = (*(volatile uint *)((uint)port + 8U) >> 8) & 65535U;
    if (usb_version > 0x200U) {
        volatile uchar *setup = live_port->setup;
        volatile uchar *bos = (volatile uchar *)0x3fca1130U;
        memset((void *)bos, 0, 256);
        uint attempt = 0;
        for (;;) {
            setup[0] = 0x80;
            setup[2] = 0;
            setup[4] = 0;
            setup[5] = 0;
            setup[7] = 0;
            setup[1] = 6;
            setup[3] = 15;
            setup[6] = 5;
            int received = usbh_control_transfer(port, (uchar *)setup, (uchar *)bos);
            if (received > 12 && bos[1] == 15) {
                ushort declared = *(volatile ushort *)(bos + 2);
                if (((declared - 5U) & 65535U) >= 252U)
                    goto bos_attempt_failed;
                uint expected = declared;
                setup[6] = declared;
                setup[7] = declared >> 8;
                received = usbh_control_transfer(port, (uchar *)setup, (uchar *)bos);
                uint effective = received < 7 ? 7U : (uint)received;
                if (effective - 8U == expected) {
                    bos_length = expected;
                    usb_version = (*(volatile uint *)((uint)port + 8U) >> 8) & 65535U;
                    break;
                }
            }
bos_attempt_failed:
            if (attempt != 0) {
                memset((void *)bos, 0, 256);
                usb_version = (*(volatile uint *)((uint)port + 8U) >> 8) & 65535U;
                break;
            }
            attempt = 1;
        }
    }
    *(volatile ushort *)0x3fcaa81aU = bos_length;

    /* Qualifier and other-speed capture. */
    /* Status0 means a nonnegative payload length after the eight-byte control
       prefix,1 is the distinguished -8 response,2 another short/error return,
       and3 an other-speed descriptor declaring more than1024 bytes. */
    volatile uchar *speed_record = (volatile uchar *)0x3fcaaa70U;
    uint speed_record_length = 5;
    if (usb_version < 0x200U) {
        *(volatile uint *)speed_record = 0x00ff00ffU;
        speed_record[4] = 0;
    } else {
        volatile uchar *setup = live_port->setup;
        setup[1] = 6;
        setup[3] = 6;
        setup[0] = 0x80;
        setup[2] = 0;
        setup[4] = 0;
        setup[5] = 0;
        setup[6] = 10;
        setup[7] = 0;
        int received = usbh_control_transfer(port, (uchar *)setup, (uchar *)0x3fc9ffe8U);
        uint qualifier_status;
        uint qualifier_length = 0;
        if (received == -8) {
            qualifier_status = 1;
        } else if (received < 8) {
            qualifier_status = 2;
        } else {
            qualifier_status = 0;
            qualifier_length = received - 8;
            if (qualifier_length > 10)
                qualifier_length = 10;
            /* Even an empty successful qualifier calls the ROM copy. */
            memcpy(scratch.qualifier, (void *)0x3fc9ffe8U, qualifier_length);
        }
        setup = live_port->setup;
        setup[6] = 9;
        setup[0] = 0x80;
        setup[1] = 6;
        setup[2] = 0;
        setup[3] = 7;
        setup[4] = 0;
        setup[5] = 0;
        setup[7] = 0;
        received = usbh_control_transfer(port, (uchar *)setup, (uchar *)0x3fc9ffe8U);
        uint other_status = 0;
        uint other_length = 0;
        if (received == -8) {
            other_status = 1;
        } else if (received < 8) {
            other_status = 2;
        } else {
            other_length = received - 8;
            if (other_length >= 4) {
                ushort declared = *(volatile ushort *)0x3fc9ffeaU;
                if (declared > 1024) {
                    other_status = 3;
                    other_length = 0;
                } else {
                    if (other_length < declared) {
                        setup = live_port->setup;
                        setup[6] = declared;
                        setup[7] = declared >> 8;
                        setup[0] = 0x80;
                        setup[1] = 6;
                        setup[2] = 0;
                        setup[3] = 7;
                        setup[4] = 0;
                        setup[5] = 0;
                        received = usbh_control_transfer(port, (uchar *)setup,
                            (uchar *)0x3fc9ffe8U);
                        if (received == -8) {
                            other_status = 1;
                            other_length = 0;
                        } else if (received < 8) {
                            other_status = 2;
                            other_length = 0;
                        } else {
                            other_length = received - 8;
                        }
                    }
                    if (other_length > 1024)
                        other_length = 1024;
                }
            }
        }
        speed_record_length = 5 + qualifier_length + other_length;
        speed_record[0] = qualifier_status;
        speed_record[1] = qualifier_length;
        if (qualifier_length != 0)
            medius_copy_forward_words((uchar *)speed_record + 2,
                scratch.qualifier, qualifier_length);
        speed_record[qualifier_length + 2] = other_status;
        speed_record[qualifier_length + 3] = other_length;
        speed_record[qualifier_length + 4] = other_length >> 8;
        if (other_length != 0)
            medius_copy_forward_words((uchar *)speed_record + qualifier_length + 5,
                (uchar *)0x3fc9ffe8U, other_length);
    }

    /* Metadata identity and serialization. */
    /* Keep these snapshots before the gates and serialized-length store: later
       callbacks may change the live identity or precapture byte. */
    uint current_product = *(volatile ushort *)0x3fcaff0cU;
    memw();
    *(volatile uchar *)0x3fca9771U = 1;
    uint current_vendor = *(volatile ushort *)0x3fcaff0eU;
    memw();
    uint precapture = *(volatile uchar *)0x3fcaff0aU;
    uint previous_key = *(volatile uint *)0x3fcaaa68U;
    *(volatile ushort *)0x3fcaaa6cU = speed_record_length;
    /* Publish speed metadata. */
    uint identity_key = (current_vendor << 16) | current_product;
    if (identity_key == previous_key) {
        memw();
        uint switching = *(volatile uchar *)0x3fcaff1cU;
        if (switching != 0) {
            memw();
            if (medius_host_identity_refresh == 0)
                goto scan_endpoint_counts;
        }
        if (precapture != 0)
            goto metadata_ready;
    }
    {
        volatile uchar *payload = (volatile uchar *)medius_clone_metadata_source + 8;
        volatile uchar *encoded = (volatile uchar *)medius_clone_metadata_buffer;
        memset((void *)payload, 0, 59);
        *(volatile ushort *)(medius_clone_metadata_source + 6) = 0;
        *(volatile ushort *)(medius_clone_metadata_source + 0) = 0;
        *(volatile ushort *)(medius_clone_metadata_source + 2) = 0;
        *(volatile ushort *)(medius_clone_metadata_source + 4) = 0;
        encoded[0] = 59;
        /* WORD snapshots and interleaved BYTE stores preserve the native
           serializer, including its observable order under shared storage. */
        for (uint block = 0; block < 48; block += 16) {
            volatile uchar *source = payload + block;
            volatile uchar *destination = encoded + 1 + block;
            uint word8 = *(volatile uint *)(source + 8);
            uint word12 = *(volatile uint *)(source + 12);
            uint word0 = *(volatile uint *)(source + 0);
            destination[11] = word8 >> 24;
            uint word4 = *(volatile uint *)(source + 4);
            destination[13] = word12 >> 8;
            destination[8] = word8;
            destination[14] = word12 >> 16;
            destination[12] = word12;
            destination[0] = word0;
            destination[1] = word0 >> 8;
            destination[2] = word0 >> 16;
            destination[3] = word0 >> 24;
            destination[4] = word4;
            destination[5] = word4 >> 8;
            destination[6] = word4 >> 16;
            destination[7] = word4 >> 24;
            destination[9] = word8 >> 8;
            destination[10] = word8 >> 16;
            destination[15] = word12 >> 24;
        }
        uint word52 = *(volatile uint *)(payload + 52);
        uchar byte57 = payload[57];
        uchar byte58 = payload[58];
        uchar byte56 = payload[56];
        encoded[58] = byte57;
        encoded[59] = byte58;
        uint word48 = *(volatile uint *)(payload + 48);
        encoded[54] = word52 >> 8;
        encoded[56] = word52 >> 24;
        encoded[57] = byte56;
        encoded[49] = word48;
        encoded[50] = word48 >> 8;
        encoded[51] = word48 >> 16;
        encoded[52] = word48 >> 24;
        encoded[53] = word52;
        encoded[55] = word52 >> 16;
        *(volatile uint *)(encoded + 60) = 0;
        *(volatile uint *)(encoded + 64) = 0;
        encoded[68] = 0;
        *(volatile ushort *)0x3fcaa822U = 69;
        *(volatile uint *)0x3fcaaa68U = identity_key;
    }
metadata_ready:
    /* Selected configuration lookup. */
    /* Counts are producer-owned bytes: the native scans do not clamp damaged
       counts to the nominal four/eight slots. Preserve that precondition. */
    uint excluded_count = cache->exclusion_count;
    for (uint slot = 0; slot < excluded_count; slot++) {
        uint excluded_key = *(volatile uint *)((uint)cache + 48U + 4U * slot);
        if (excluded_key == identity_key)
            goto scan_endpoint_counts;
    }
    uint selected_length = configurations->base_length;
    anomaly_base_length = selected_length;
    volatile uchar *selected_configuration = base_descriptor;
    uint selector = configurations->selected_index;
    if (selector != 0) {
        uint used = configurations->additional_length;
        if (used < 4)
            goto scan_endpoint_counts_cached;
        uint cursor = 0;
        uint remaining = (selector - 1U) & 255U;
        for (;;) {
            uint high = *(volatile uchar *)(0x3fca1a33U + cursor);
            uint low = *(volatile uchar *)(0x3fca1a32U + cursor);
            uint length = (high << 8) | low;
            uint next = (cursor + length) & 65535U;
            if (length < 4 || cursor + length > used)
                goto scan_endpoint_counts_cached;
            if (remaining == 0) {
                selected_configuration = (volatile uchar *)(0x3fca1a30U + cursor);
                selected_length = length;
                break;
            }
            remaining = (remaining - 1U) & 255U;
            cursor = next;
            if (next + 4U > used)
                goto scan_endpoint_counts_cached;
        }
    }
    if (selected_length < 9)
        goto scan_endpoint_counts_cached;
    if (precapture == 0) {
        volatile uchar *setup = live_port->setup;
        setup[0] = 0x80;
        setup[1] = 8;
        void *mutex = live_port->control_mutex;
        setup[6] = 1;
        setup[2] = 0;
        setup[3] = 0;
        setup[4] = 0;
        setup[5] = 0;
        setup[7] = 0;
        usb_osal_mutex_take(mutex);
        live_port->control_urb.endpoint = port->ep0_descriptor;
        live_port->control_urb.remaining = 1;
        live_port->control_urb.setup = (uchar *)setup;
        live_port->control_urb.hubport = port;
        live_port->control_urb.buffer = (uchar *)0x3fc9ffe8U;
        live_port->control_urb.timeout = 500;
        live_port->control_urb.complete = 0;
        live_port->control_urb.context = 0;
        int status = usbh_submit_urb(&port->control_urb);
        if (status == 0)
            status = live_port->control_urb.actual;
        usb_osal_mutex_give(live_port->control_mutex);
        uchar value = *(volatile uchar *)0x3fc9ffe8U;
        *(volatile int *)0x3fca9724U = status;
        *(volatile uchar *)0x3fca9720U = value;
    }

    /* Interface, alternate and endpoint inventory. */
    int chosen_interface = -1;
    /* Reload the saved full-width maximum before constructing wValue. Native
       request narrowing is separate from the full-width readback comparison. */
    volatile int maximum_alternate = -1;
    int current_interface = -1;
    int first_endpoint = -1;
    uint nonvendor_interfaces = 0;
    uint alternate_interfaces = 0;
    uint all_interfaces = 0;
    uint has_interface_255 = 0;
    uint endpoint_numbers = 1;
    uint endpoint_directions = 0;
    uint hid_count = 0;
    uint scan_cursor = 0;
    for (;;) {
        volatile uchar *descriptor = selected_configuration + scan_cursor;
        uint length = descriptor[0];
        if (length < 2 || scan_cursor + length > selected_length)
            break;
        uint type = descriptor[1];
        uint add_hid = 0;
        if (type == 4 && length >= 9) {
            uint alternate = descriptor[3];
            uint id = descriptor[2];
            uint interface_class = alternate == 0 ? descriptor[5] : 0;
            current_interface = alternate == 0 ? (int)id : -1;
            if (chosen_interface == -1)
                chosen_interface = id;
            if (chosen_interface == (int)id && maximum_alternate < (int)alternate)
                maximum_alternate = alternate;
            if (id < 16) {
                all_interfaces |= 1U << id;
                if (alternate != 0)
                    alternate_interfaces |= 1U << id;
                else if (interface_class != 255)
                    nonvendor_interfaces |= 1U << id;
            }
            has_interface_255 |= id == 255;
            add_hid = alternate == 0 && interface_class == 3;
        } else if (type == 0x21) {
            add_hid = current_interface >= 0;
        } else if (type == 5 && length >= 7) {
            uint endpoint = descriptor[2];
            if (first_endpoint == -1)
                first_endpoint = endpoint;
            endpoint_numbers |= 1U << (endpoint & 15U);
            endpoint_directions |= 1U << ((endpoint & 15U) | ((endpoint >> 7) << 4));
        }
        if (add_hid != 0) {
            uint present = 0;
            for (uint slot = 0; slot < hid_count; slot++)
                present |= scratch.hid_interfaces[slot] == current_interface;
            if (present == 0 && hid_count < 16)
                scratch.hid_interfaces[hid_count++] = current_interface;
        }
        scan_cursor = (scan_cursor + length) & 65535U;
        if (scan_cursor + 1U >= selected_length)
            break;
    }

    /* Control-request and padding table. */
    int cached_quirk_slot = -1;
    uint quirk_count = cache->quirk_count;
    for (uint slot = 0; slot < quirk_count; slot++)
        if (*(volatile uint *)((uint)cache + 24U + 4U * slot) == identity_key)
            cached_quirk_slot = slot;
    uint probe_started_ms = (uint)(esp_timer_get_time() / 1000LL);
    volatile uchar *probe_metadata = (volatile uchar *)medius_clone_metadata_source + 8;
    int recovery_code = -1;
    if (precapture != 0)
        goto final_status;
    {
        const MediusHostControlProbeRow *row = (const MediusHostControlProbeRow *)0x3c045c54U;
        for (uint index = 0; index < 23; index++, row++) {
            if (row->skip_when_primary_three != 0 && probe_metadata[0] == 3)
                continue;
            uint padding_length = row->padding_expected_length;
            uint now = (uint)(esp_timer_get_time() / 1000LL);
            uint code = 0;
            if (now - probe_started_ms <= 2000U) {
                if (padding_length == 0) {
                    uint length = row->length;
                    code = medius_host_classify_control_probe(port, row->request_type,
                        row->request, row->value, 0, length, &results.transfer_result,
                        length == 0 ? 100 : 500);
                } else {
                    code = medius_host_probe_response_padding(port, row->request_type,
                        row->request, 0, padding_length);
                }
                if (code == 255)
                    goto capture_failed;
            }
            probe_metadata[row->destination] = code;
        }
    }
    /* Descriptor controls. */
    if (probe_metadata[4] == 3) {
        *(volatile uchar *)0x3fc9ffe8U = 0;
        uint code = 0;
        if ((uint)(esp_timer_get_time() / 1000LL) - probe_started_ms <= 2000U) {
            code = medius_host_classify_control_probe(port, 3, 1, 0, 0, 1,
                &results.transfer_result, 500);
            if (code == 255)
                goto capture_failed;
        }
        probe_metadata[5] = code;
    }
    if ((uint)(esp_timer_get_time() / 1000LL) - probe_started_ms <= 2000U) {
        volatile uchar *setup = live_port->setup;
        setup[0] = 0x80;
        setup[1] = 6;
        void *mutex = live_port->control_mutex;
        setup[3] = 1;
        setup[2] = 0;
        setup[4] = 0;
        setup[5] = 0;
        setup[6] = 18;
        setup[7] = 0;
        usb_osal_mutex_take(mutex);
        live_port->control_urb.endpoint = port->ep0_descriptor;
        live_port->control_urb.hubport = port;
        live_port->control_urb.complete = 0;
        live_port->control_urb.setup = (uchar *)setup;
        live_port->control_urb.context = 0;
        live_port->control_urb.buffer = (uchar *)0x3fc9ffe8U;
        live_port->control_urb.remaining = 18;
        live_port->control_urb.timeout = 500;
        int status = usbh_submit_urb(&port->control_urb);
        if (status == 0)
            status = live_port->control_urb.actual;
        usb_osal_mutex_give(live_port->control_mutex);
        if (status >= 0) {
            uint code = 0;
            if ((uint)(esp_timer_get_time() / 1000LL) - probe_started_ms <= 2000U) {
                code = medius_host_classify_control_probe(port, 0, 7, 0x7f00, 0, 0,
                    &results.transfer_result, 100);
                if (code == 255)
                    goto capture_failed;
            }
            probe_metadata[56] = code;
        }
    }
    if ((uint)(esp_timer_get_time() / 1000LL) - probe_started_ms <= 2000U) {
        volatile uchar *setup = live_port->setup;
        setup[0] = 0;
        setup[1] = 1;
        void *mutex = live_port->control_mutex;
        setup[2] = 1;
        setup[3] = 0;
        setup[4] = 0;
        setup[5] = 0;
        setup[6] = 0;
        setup[7] = 0;
        usb_osal_mutex_take(mutex);
        live_port->control_urb.endpoint = port->ep0_descriptor;
        live_port->control_urb.hubport = port;
        live_port->control_urb.remaining = 0;
        live_port->control_urb.setup = (uchar *)setup;
        live_port->control_urb.complete = 0;
        live_port->control_urb.buffer = (uchar *)0x3fc9ffe8U;
        live_port->control_urb.timeout = 100;
        live_port->control_urb.context = 0;
        int status = usbh_submit_urb(&port->control_urb);
        if (status == 0)
            status = live_port->control_urb.actual;
        usb_osal_mutex_give(live_port->control_mutex);
        if (status >= 0 || status == -8) {
            uint code = 0;
            if ((uint)(esp_timer_get_time() / 1000LL) - probe_started_ms <= 2000U) {
                code = medius_host_classify_control_probe(port, 0, 7, 0x7f00, 0, 0,
                    &results.transfer_result, 100);
                if (code == 255)
                    goto capture_failed;
            }
            probe_metadata[57] = code;
        }
    }
    uint after_descriptor_probe = probe_metadata[56];
    uint after_clear_probe = after_descriptor_probe != 0 ? probe_metadata[57] : 0;
    if (after_descriptor_probe != 0 && after_clear_probe != 0 &&
        after_descriptor_probe != after_clear_probe) {
        if ((uint)(esp_timer_get_time() / 1000LL) - probe_started_ms <= 2000U) {
            volatile uchar *setup = live_port->setup;
            setup[0] = 0x80;
            setup[1] = 6;
            void *mutex = live_port->control_mutex;
            setup[3] = 1;
            setup[2] = 0;
            setup[4] = 0;
            setup[5] = 0;
            setup[6] = 18;
            setup[7] = 0;
            usb_osal_mutex_take(mutex);
            live_port->control_urb.setup = (uchar *)setup;
            live_port->control_urb.remaining = 18;
            live_port->control_urb.timeout = 500;
            live_port->control_urb.hubport = port;
            live_port->control_urb.endpoint = port->ep0_descriptor;
            live_port->control_urb.buffer = (uchar *)0x3fc9ffe8U;
            live_port->control_urb.complete = 0;
            live_port->control_urb.context = 0;
            int status = usbh_submit_urb(&port->control_urb);
            if (status == 0)
                status = live_port->control_urb.actual;
            usb_osal_mutex_give(live_port->control_mutex);
            if (status >= 0) {
                *(volatile uchar *)0x3fc9ffe8U = 0;
                uint code = medius_host_classify_control_probe(port, 0, 7, 0x7f00,
                    0, 1, &results.transfer_result, 100);
                if (code == 255)
                    goto capture_failed;
                probe_metadata[58] = code;
            }
        }
    }

    /* Selected-interface controls. */
    uint configuration_count = live_port->device_descriptor[17];
    if (configuration_count != 255) {
        uint code = 0;
        if ((uint)(esp_timer_get_time() / 1000LL) - probe_started_ms <= 2000U) {
            code = medius_host_classify_control_probe(port, 0x80, 6,
                configuration_count | 0x200U, 0, 9, &results.transfer_result, 500);
            if (code == 255)
                goto capture_failed;
        }
        probe_metadata[9] = code;
        if (code == 1 && (results.transfer_result != 17 || configurations->base_length < 9 ||
            *(volatile uint *)0x3fc9ffe8U != *(volatile uint *)base_descriptor ||
            *(volatile uint *)0x3fc9ffecU != *(volatile uint *)(base_descriptor + 4) ||
            *(volatile uchar *)0x3fc9fff0U != base_descriptor[8]))
            probe_metadata[9] = 4;
    }
    if (chosen_interface != -1) {
        /* These ordered rows share one selected interface. The zero-length
           pair samples its primary-status gate once, before both requests. */
        static const uchar interface_probes[10][5] = {
            {6,0x81,8,1,0}, {18,0x81,0,2,0}, {19,0x81,0,1,0},
            {21,0x81,10,1,0}, {53,0x81,0,2,1}, {54,0x81,10,1,1},
            {20,0x81,0,0,0}, {22,0x81,10,0,0}, {37,1,3,0,0}, {36,1,1,0,0}
        };
        uint skip_zero_length_queries = 0;
        for (uint row = 0; row < 10; row++) {
            if (row == 6 && skip_zero_length_queries != 0)
                row = 8;
            uint code = 0;
            if ((uint)(esp_timer_get_time() / 1000LL) - probe_started_ms <= 2000U) {
                uint length = interface_probes[row][3];
                if (interface_probes[row][4] != 0)
                    code = medius_host_probe_response_padding(port, interface_probes[row][1],
                        interface_probes[row][2], chosen_interface, length);
                else
                    code = medius_host_classify_control_probe(port, interface_probes[row][1],
                        interface_probes[row][2], 0, chosen_interface, length,
                        &results.transfer_result, length == 0 ? 100 : 500);
                if (code == 255)
                    goto capture_failed;
            }
            /* The native gate read precedes the final padding-result store;
               both subsequent zero-length queries use this one snapshot. */
            if (row == 5)
                skip_zero_length_queries = probe_metadata[0] == 3;
            probe_metadata[interface_probes[row][0]] = code;
        }
    }

    /* Sparse interface probes. */
    {
        uint code = 0;
        if ((uint)(esp_timer_get_time() / 1000LL) - probe_started_ms <= 2000U) {
            code = medius_host_classify_control_probe(port, 0x82, 12, 0,
                first_endpoint == -1 ? 0x80 : (uint)first_endpoint, 2,
                &results.transfer_result, 500);
            if (code == 255)
                goto capture_failed;
        }
        probe_metadata[30] = code;
    }
    for (uint id = 0; id < 16; id++) {
        if ((uint)(esp_timer_get_time() / 1000LL) - probe_started_ms > 2000U)
            break;
        if ((all_interfaces & (1U << id)) == 0) {
            uint code = medius_host_classify_control_probe(port, 0x81, 0, 0, id, 2, 0, 500);
            if (code == 255)
                goto capture_failed;
            if (code != 1) {
                probe_metadata[25] = code;
                break;
            }
            volatile ushort *accepted = (volatile ushort *)(medius_clone_metadata_source + 4);
            *accepted = *accepted | (1U << id);
        }
    }
    if (has_interface_255 == 0) {
        uint code = 0;
        if ((uint)(esp_timer_get_time() / 1000LL) - probe_started_ms <= 2000U) {
            code = medius_host_classify_control_probe(port, 0x81, 0, 0, 255, 2,
                &results.transfer_result, 500);
            if (code == 255)
                goto capture_failed;
        }
        probe_metadata[26] = code;
    }
    uint tested_interfaces = 0;
    for (uint id = 0; id < 16; id++) {
        if ((uint)(esp_timer_get_time() / 1000LL) - probe_started_ms > 2000U)
            break;
        if ((nonvendor_interfaces & (1U << id)) != 0) {
            uint code = medius_host_classify_control_probe(port, 1, 11, 0, id, 0, 0, 100);
            if (code == 255)
                goto capture_failed;
            uint bit = 1U << id;
            if (code == 2) {
                volatile ushort *rejected = (volatile ushort *)medius_clone_metadata_source;
                *rejected = *rejected | bit;
            }
            tested_interfaces |= bit;
        }
    }
    if (tested_interfaces != 0 && tested_interfaces == nonvendor_interfaces &&
        *(volatile ushort *)medius_clone_metadata_source == tested_interfaces)
        *(volatile ushort *)medius_clone_metadata_source = tested_interfaces |
            ((alternate_interfaces | nonvendor_interfaces) ^ 65535U);

    /* Sparse and opposite-direction endpoint probes. */
    {
        uint last_missing = 0;
        uint halted = 0;
        for (uint endpoint = 1; endpoint < 16; endpoint++) {
            if ((endpoint_numbers & (1U << endpoint)) != 0)
                continue;
            last_missing = endpoint;
            if (halted != 0)
                continue;
            if ((uint)(esp_timer_get_time() / 1000LL) - probe_started_ms > 2000U)
                continue;
            uint code = medius_host_classify_control_probe(port, 0x82, 0, 0,
                endpoint | 0x80U, 2, 0, 500);
            if (code == 255)
                goto capture_failed;
            if (code == 1) {
                volatile ushort *accepted = (volatile ushort *)(medius_clone_metadata_source + 2);
                *accepted = *accepted | (1U << endpoint);
            } else {
                probe_metadata[27] = code;
                halted = 1;
            }
        }
        if (last_missing != 0) {
            uint code = 0;
            if ((uint)(esp_timer_get_time() / 1000LL) - probe_started_ms <= 2000U) {
                code = medius_host_classify_control_probe(port, 2, 1, 0,
                    last_missing | 0x80U, 0, &results.transfer_result, 100);
                if (code == 255)
                    goto capture_failed;
            }
            probe_metadata[28] = code;
        }
        if (first_endpoint != -1) {
            uint opposite = (first_endpoint ^ 0x80U) & 255U;
            uint bit = (opposite & 15U) | ((opposite >> 7) << 4);
            if ((endpoint_directions & (1U << bit)) == 0) {
                uint code = 0;
                if ((uint)(esp_timer_get_time() / 1000LL) - probe_started_ms <= 2000U) {
                    code = medius_host_classify_control_probe(port, 0x82, 0, 0,
                        opposite, 2, &results.transfer_result, 500);
                    if (code == 255)
                        goto capture_failed;
                }
                probe_metadata[29] = code;
            }
        }
    }
    /* Remote wakeup and quirk handling. */
    {
        uint capable = selected_configuration[7] & 0x20U;
        uint secondary = capable;
        if ((uint)(esp_timer_get_time() / 1000LL) - probe_started_ms <= 2000U) {
            uint code = medius_host_classify_control_probe(port, 0, 3, 1, 0, 0, 0, 100);
            if (code == 255)
                goto wakeup_failed;
            if (capable == 0)
                probe_metadata[40] = code;
            if (code == 1) {
                secondary = 1;
                code = medius_host_classify_control_probe(port, 0x80, 0, 0, 0, 2,
                    &results.transfer_result, 500);
                if (code == 255)
                    goto wakeup_failed;
                if (code == 1 && results.transfer_result == 10)
                    probe_metadata[42] = (*(volatile uchar *)0x3fc9ffe8U & 2U) != 0 ? 1 : 2;
            }
        } else if (capable == 0) {
            probe_metadata[40] = 0;
        }
        if (secondary != 0) {
            uint code = 0;
            if ((uint)(esp_timer_get_time() / 1000LL) - probe_started_ms <= 2000U) {
                code = medius_host_classify_control_probe(port, 0, 3, 1, 1, 0,
                    &results.transfer_result, 100);
                if (code == 255)
                    goto wakeup_failed;
            }
            probe_metadata[41] = code;
        }
        volatile uchar *setup = live_port->setup;
        setup[0] = 0;
        setup[1] = 1;
        void *mutex = live_port->control_mutex;
        setup[2] = 1;
        setup[3] = 0;
        setup[4] = 0;
        setup[5] = 0;
        setup[6] = 0;
        setup[7] = 0;
        usb_osal_mutex_take(mutex);
        live_port->control_urb.endpoint = port->ep0_descriptor;
        live_port->control_urb.hubport = port;
        live_port->control_urb.buffer = (uchar *)0x3fc9ffe8U;
        live_port->control_urb.setup = (uchar *)setup;
        live_port->control_urb.timeout = 100;
        live_port->control_urb.remaining = 0;
        live_port->control_urb.complete = 0;
        live_port->control_urb.context = 0;
        int status = usbh_submit_urb(&port->control_urb);
        if (status == 0)
            status = live_port->control_urb.actual;
        usb_osal_mutex_give(live_port->control_mutex);
        if (cached_quirk_slot != -1) {
            probe_metadata[43] = *(volatile uchar *)((uint)cache + 20U + cached_quirk_slot);
        } else if (status >= 0 && probe_metadata[0] != 3 &&
            (uint)(esp_timer_get_time() / 1000LL) - probe_started_ms <= 2000U) {
            *(volatile uchar *)0x3fc9ffe8U = 0;
            uint code = medius_host_classify_control_probe(port, 0, 1, 1, 0, 1,
                &results.transfer_result, 100);
            if (code == 255) {
                memw();
                if (*(volatile uchar *)0x3fca9772U == 0)
                    goto wakeup_failed;
                recovery_code = ((uint)results.transfer_result & 0xfffffffbU) == 0xfffffff2U ? 3 : 0;
                goto clear_wakeup_after_failure;
            }
            probe_metadata[43] = code;
            if (code != 1 && medius_host_verify_device_identity(port) == 0) {
                memw();
                if (*(volatile uchar *)0x3fca9772U == 0)
                    goto wakeup_failed;
                recovery_code = code;
                goto clear_wakeup_after_failure;
            }
        }
    }

    /* Alternate-setting probes. */
    if (chosen_interface == -1)
        goto final_status;
    if (maximum_alternate <= 254 &&
        (uint)(esp_timer_get_time() / 1000LL) - probe_started_ms <= 2000U) {
        uint restore_alternate = 1;
        if ((uint)(esp_timer_get_time() / 1000LL) - probe_started_ms <= 2000U) {
            uint invalid_alternate = (uint)maximum_alternate + 1U;
            uint code = medius_host_classify_control_probe(port, 1, 11,
                invalid_alternate & 65535U, chosen_interface, 0, &results.transfer_result, 100);
            if (code == 255)
                goto restore_alternate_after_failure;
            probe_metadata[32] = code;
            if (code == 1) {
                code = medius_host_classify_control_probe(port, 0x81, 10, 0,
                    chosen_interface, 1, &results.transfer_result, 500);
                if (code == 255)
                    goto restore_alternate_after_failure;
                if (code == 1 && results.transfer_result == 9)
                    probe_metadata[33] = *(volatile uchar *)0x3fc9ffe8U == invalid_alternate ? 1 : 2;
            } else if (code == 2) {
                restore_alternate = 0;
            }
        } else {
            probe_metadata[32] = 0;
        }
        if (restore_alternate != 0 &&
            medius_host_control_no_data_retry(port, 1, 11, 0, chosen_interface, 0) == 0)
            goto restore_alternate_after_failure;
    }
    if (selected_configuration[5] == 0)
        goto final_status;

    /* Unconfigured-state probes. */
    if ((uint)(esp_timer_get_time() / 1000LL) - probe_started_ms > 2000U)
        goto final_status;
    {
        uint code = medius_host_classify_control_probe(port, 0, 9, 0, 0, 0, 0, 100);
        if (code == 255)
            goto restore_configuration_after_failure;
        if (code == 2)
            goto final_status;
        if (code != 1)
            goto restore_configuration;
        code = 0;
        if ((uint)(esp_timer_get_time() / 1000LL) - probe_started_ms <= 2000U) {
            code = medius_host_classify_control_probe(port, 0x81, 0, 0, chosen_interface,
                2, &results.transfer_result, 500);
            if (code == 255)
                goto restore_configuration_after_failure;
        }
        probe_metadata[44] = code;
        if (hid_count != 0) {
            code = 0;
            if ((uint)(esp_timer_get_time() / 1000LL) - probe_started_ms <= 2000U) {
                code = medius_host_classify_control_probe(port, 0x81, 6, 0x2200,
                    scratch.hid_interfaces[0], 255, &results.transfer_result, 500);
                if (code == 255)
                    goto restore_configuration_after_failure;
            }
            probe_metadata[45] = code;
        }
        code = 0;
        if ((uint)(esp_timer_get_time() / 1000LL) - probe_started_ms <= 2000U) {
            if (first_endpoint == -1)
                first_endpoint = 0x80;
            code = medius_host_classify_control_probe(port, 0x82, 12, 0,
                first_endpoint, 2, &results.transfer_result, 500);
            if (code == 255)
                goto restore_configuration_after_failure;
        }
        probe_metadata[46] = code;
        code = 0;
        if ((uint)(esp_timer_get_time() / 1000LL) - probe_started_ms <= 2000U) {
            code = medius_host_classify_control_probe(port, 0x82, 0, 0, 0, 2,
                &results.transfer_result, 500);
            if (code == 255)
                goto restore_configuration_after_failure;
        }
        probe_metadata[47] = code;
    }

    /* Unused configuration value probes. */
    {
        uint candidate = (live_port->device_descriptor[17] + 1U) & 255U;
        if (candidate != 0) {
            uint base_length = configurations->base_length;
            uint base_value = base_descriptor[5];
            uint count = configurations->archived_count;
            uint used = configurations->additional_length;
choose_unused_configuration:
            if (base_length > 5) {
                while (base_value == candidate) {
                    candidate = (base_value + 1U) & 255U;
                    if (candidate == 0)
                        goto restore_configuration;
                }
            }
            if (count > 1 && used > 3) {
                uint ordinal = 0;
                do {
                    uint cursor = 0;
                    uint remaining = ordinal;
                    for (;;) {
                        uint high = *(volatile uchar *)(0x3fca1a33U + cursor);
                        uint low = *(volatile uchar *)(0x3fca1a32U + cursor);
                        uint length = (high << 8) | low;
                        uint next = (cursor + length) & 65535U;
                        if (length < 4 || cursor + length > used)
                            break;
                        if (remaining == 0) {
                            if (length > 5 && *(volatile uchar *)(0x3fca1a35U + cursor) == candidate) {
                                candidate = (candidate + 1U) & 255U;
                                if (candidate == 0)
                                    goto restore_configuration;
                                goto choose_unused_configuration;
                            }
                            break;
                        }
                        remaining = (remaining - 1U) & 255U;
                        cursor = next;
                        if (next + 4U > used)
                            break;
                    }
                    ordinal = (ordinal + 1U) & 255U;
                } while (ordinal + 1U < count);
            }
            if ((uint)(esp_timer_get_time() / 1000LL) - probe_started_ms <= 2000U) {
                uint code = medius_host_classify_control_probe(port, 0, 9, candidate, 0,
                    0, &results.transfer_result, 100);
                if (code == 255)
                    goto restore_configuration_after_failure;
                probe_metadata[48] = code;
                if (code == 1) {
                    code = medius_host_classify_control_probe(port, 0x80, 8, 0, 0, 1,
                        &results.transfer_result, 500);
                    if (code == 255)
                        goto restore_configuration_after_failure;
                    if (code == 1 && results.transfer_result == 9)
                        probe_metadata[49] = *(volatile uchar *)0x3fc9ffe8U == candidate ? 1 : 2;
                }
            } else {
                probe_metadata[48] = 0;
            }
        }
    }
restore_configuration:
    /* Restore selected configuration. */
    if (medius_host_control_no_data_retry(port, 0, 9, selected_configuration[5], 0, 1) == 0)
        goto restore_configuration_after_failure;
    goto final_status;

restore_alternate_after_failure:
    memw();
    if (*(volatile uchar *)0x3fca9772U == 0)
        medius_host_control_no_data_retry(port, 1, 11, 0, chosen_interface, 0);
    goto capture_failed;
restore_configuration_after_failure:
    /* Configuration restoration after failure. */
    memw();
    if (*(volatile uchar *)0x3fca9772U == 0)
        medius_host_control_no_data_retry(port, 0, 9, selected_configuration[5], 0, 1);
    goto capture_failed;
wakeup_failed:
    recovery_code = -1;
clear_wakeup_after_failure:
    /* Remote-wakeup cleanup. */
    memw();
    if (*(volatile uchar *)0x3fca9772U == 0) {
        volatile uchar *setup = live_port->setup;
        setup[1] = 1;
        setup[0] = 0;
        void *mutex = live_port->control_mutex;
        setup[2] = 1;
        setup[3] = 0;
        setup[4] = 0;
        setup[5] = 0;
        setup[6] = 0;
        setup[7] = 0;
        usb_osal_mutex_take(mutex);
        live_port->control_urb.endpoint = port->ep0_descriptor;
        live_port->control_urb.hubport = port;
        live_port->control_urb.buffer = (uchar *)0x3fc9ffe8U;
        live_port->control_urb.setup = (uchar *)setup;
        live_port->control_urb.remaining = 0;
        live_port->control_urb.timeout = 100;
        live_port->control_urb.complete = 0;
        live_port->control_urb.context = 0;
        usbh_submit_urb(&port->control_urb);
        usb_osal_mutex_give(live_port->control_mutex);
    }
    goto serialize_failure;
final_status:
    /* Final device status. */
    {
        uint code = medius_host_classify_control_probe(port, 0x80, 0, 0, 0, 2,
            &results.transfer_result, 500);
        if (code == 255)
            goto capture_failed;
        if (code == 1) {
            if (results.transfer_result == 10) {
                ushort raw_status = *(volatile ushort *)0x3fc9ffe8U;
                probe_metadata[12] = 1;
                *(volatile ushort *)(medius_clone_metadata_source + 6) = raw_status;
            } else {
                probe_metadata[12] = 0;
            }
        } else {
            probe_metadata[12] = code;
        }
    }

    /* Remove old records for the selected configuration. */
    {
        volatile uchar *encoded = (volatile uchar *)medius_clone_metadata_buffer;
        uint saved_used = *(volatile ushort *)0x3fcaa822U;
        if (saved_used > 68) {
            uint count = encoded[68];
            uint write = 69;
            uint kept = 0;
            if (count != 0) {
                uint selected_value = selected_configuration[5];
                uint read = 69;
                uint processed = 0;
                do {
                    if (read + 4U > saved_used)
                        break;
                    uint length = encoded[read + 3] + 4U;
                    uint next = read + length;
                    if (next > saved_used)
                        break;
                    if (encoded[read] != selected_value) {
                        memmove((void *)(encoded + write), (void *)(encoded + read), length);
                        write = (write + length) & 65535U;
                        kept = (kept + 1U) & 255U;
                    }
                    read = next & 65535U;
                    processed = (processed + 1U) & 255U;
                    count = encoded[68];
                } while (processed < count);
            }
            encoded[68] = kept;
            *(volatile ushort *)0x3fcaa822U = write;
        }
    }

    /* Capture HID descriptor differences. */
    /* Unlike ordinary probes, each saved HID ID is queried without a fresh
       budget check. Compare against the selected configuration's type21. */
    for (uint slot = 0; slot < hid_count; slot++) {
        uint id = scratch.hid_interfaces[slot];
        uint code = medius_host_classify_control_probe(port, 0x81, 6, 0x2100, id,
            255, &results.transfer_result, 500);
        if (code == 255)
            goto capture_failed;
        if (code == 0 || (code == 1 && results.transfer_result < 8))
            continue;
        uint length = code == 1 ? ((uint)results.transfer_result - 8U) & 255U : 0;
        uint status = code == 2 ? 1U : code == 3 ? 2U : 0U;
        uint cursor = 0;
        int descriptor_interface = -1;
        uint found = 0;
        for (;;) {
            volatile uchar *descriptor = selected_configuration + cursor;
            uint size = descriptor[0];
            if (size < 2 || cursor + size > selected_length)
                break;
            uint type = descriptor[1];
            if (type == 4) {
                if (size >= 9)
                    descriptor_interface = descriptor[2];
            } else if (type == 0x21 && descriptor_interface == (int)id) {
                found = 1;
                if (status == 0 && size == length &&
                    memcmp((void *)0x3fc9ffe8U, (void *)descriptor, length) == 0)
                    goto next_hid_id;
                break;
            }
            cursor = (cursor + size) & 65535U;
            if (cursor + 1U >= selected_length)
                break;
        }
        if (found == 0 && status == 1)
            continue;
        uint configuration_value = selected_configuration[5];
        if (status != 0)
            length = 0;
        uint used = *(volatile ushort *)0x3fcaa822U;
        volatile uchar *encoded = (volatile uchar *)medius_clone_metadata_buffer;
        if (used > 68 && used + length + 4U <= 512U && encoded[68] != 255) {
            encoded[used] = configuration_value;
            encoded[used + 1] = id;
            encoded[used + 2] = status;
            encoded[used + 3] = length;
            if (length != 0) {
                medius_copy_forward_words((uchar *)encoded + used + 4,
                    (uchar *)0x3fc9ffe8U, length);
                used = *(volatile ushort *)0x3fcaa822U;
            }
            uint count = encoded[68];
            *(volatile ushort *)0x3fcaa822U = used + length + 4U;
            encoded[68] = count + 1U;
        }
next_hid_id:
        ;
    }

    /* Final endpoint controls and identity check. */
    if (precapture == 0 &&
        (uint)(esp_timer_get_time() / 1000LL) - probe_started_ms <= 2000U) {
        const volatile uchar *endpoints = (const volatile uchar *)0x3c045c50U;
        for (uint index = 0; index < 2; index++) {
            uint endpoint = endpoints[index];
            uint code = medius_host_classify_control_probe(port, 2, 3, 0,
                endpoint, 0, 0, 100);
            if (code == 255)
                goto capture_failed;
            probe_metadata[51 + index] = code;
            volatile uchar *setup = live_port->setup;
            setup[0] = 2;
            setup[1] = 1;
            void *mutex = live_port->control_mutex;
            setup[4] = endpoint;
            setup[5] = 0;
            setup[2] = 0;
            setup[3] = 0;
            setup[6] = 0;
            setup[7] = 0;
            usb_osal_mutex_take(mutex);
            live_port->control_urb.endpoint = port->ep0_descriptor;
            live_port->control_urb.hubport = port;
            live_port->control_urb.buffer = (uchar *)0x3fc9ffe8U;
            live_port->control_urb.setup = (uchar *)setup;
            live_port->control_urb.remaining = 0;
            live_port->control_urb.timeout = 100;
            live_port->control_urb.complete = 0;
            live_port->control_urb.context = 0;
            usbh_submit_urb(&port->control_urb);
            usb_osal_mutex_give(live_port->control_mutex);
        }
        if (medius_host_verify_device_identity(port) == 0)
            goto capture_failed;
    }
    if (cache->retry_key == identity_key) {
        anomaly_base_length = configurations->base_length;
        cache->retry_key = 0;
        goto scan_endpoint_counts_cached;
    }
    goto scan_endpoint_counts;
capture_failed:
    recovery_code = -1;
serialize_failure:
    /* Failure serialization and retry/exclusion caches. */
    {
        volatile uchar *payload = (volatile uchar *)medius_clone_metadata_source + 8;
        volatile uchar *encoded = (volatile uchar *)medius_clone_metadata_buffer;
        memset((void *)payload, 0, 59);
        /* Preserve the raw GET_STATUS halfword at source+6 on this path. */
        *(volatile ushort *)(medius_clone_metadata_source + 0) = 0;
        *(volatile ushort *)(medius_clone_metadata_source + 2) = 0;
        *(volatile ushort *)(medius_clone_metadata_source + 4) = 0;
        encoded[0] = 59;
        for (uint block = 0; block < 48; block += 16) {
            volatile uchar *source = payload + block;
            volatile uchar *destination = encoded + 1 + block;
            uint word8 = *(volatile uint *)(source + 8);
            uint word12 = *(volatile uint *)(source + 12);
            uint word0 = *(volatile uint *)(source + 0);
            destination[11] = word8 >> 24;
            uint word4 = *(volatile uint *)(source + 4);
            destination[13] = word12 >> 8;
            destination[8] = word8;
            destination[14] = word12 >> 16;
            destination[12] = word12;
            destination[0] = word0;
            destination[1] = word0 >> 8;
            destination[2] = word0 >> 16;
            destination[3] = word0 >> 24;
            destination[4] = word4;
            destination[5] = word4 >> 8;
            destination[6] = word4 >> 16;
            destination[7] = word4 >> 24;
            destination[9] = word8 >> 8;
            destination[10] = word8 >> 16;
            destination[15] = word12 >> 24;
        }
        uint word52 = *(volatile uint *)(payload + 52);
        uchar byte57 = payload[57];
        uchar byte58 = payload[58];
        uchar byte56 = payload[56];
        encoded[58] = byte57;
        encoded[59] = byte58;
        encoded[55] = word52 >> 16;
        encoded[56] = word52 >> 24;
        uint word48 = *(volatile uint *)(payload + 48);
        encoded[57] = byte56;
        encoded[49] = word48;
        encoded[50] = word48 >> 8;
        encoded[51] = word48 >> 16;
        encoded[52] = word48 >> 24;
        encoded[53] = word52;
        encoded[54] = word52 >> 8;
        *(volatile uint *)(encoded + 60) = 0;
        *(volatile uint *)(encoded + 64) = 0;
        encoded[68] = 0;
        *(volatile ushort *)0x3fcaa822U = 69;
    }
    if (recovery_code != -1) {
        uint index = cache->quirk_next;
        cache->quirk_next = (index + 1U) & 3U;
        uint count = cache->quirk_count;
        *(volatile uint *)((uint)cache + 24U + 4U * index) = identity_key;
        *(volatile uchar *)((uint)cache + 20U + index) = recovery_code;
        anomaly_base_length = configurations->base_length;
        if (count < 4)
            cache->quirk_count = count + 1U;
        goto scan_endpoint_counts_cached;
    }
    memw();
    if (*(volatile uchar *)0x3fca9772U == 0 && cache->retry_key != identity_key) {
        cache->retry_key = identity_key;
        anomaly_base_length = configurations->base_length;
        goto scan_endpoint_counts_cached;
    }
    {
        uint index = cache->exclusion_next;
        uint count = cache->exclusion_count;
        cache->retry_key = 0;
        *(volatile uint *)((uint)cache + 48U + 4U * index) = identity_key;
        cache->exclusion_next = (index + 1U) & 7U;
        if (count < 8)
            cache->exclusion_count = count + 1U;
    }
scan_endpoint_counts:
    anomaly_base_length = configurations->base_length;
scan_endpoint_counts_cached:
    /* Endpoint-count anomaly scan. */
    memw();
    *(volatile uchar *)0x3fca9771U = 0;
    if (anomaly_base_length >= 2) {
        volatile uchar *saved_base = base_descriptor;
        uint cursor = 0;
        int interface_id = -1;
        uint declared = 0;
        uint observed = 0;
        uint valid = 0;
        for (;;) {
            uint length = saved_base[cursor];
            valid = interface_id != -1;
            if (length < 2 || cursor + length > anomaly_base_length)
                break;
            uint type = configurations->base[cursor + 1];
            if (type == 5) {
                if (length >= 7) {
                    valid = 0;
                    if (interface_id != -1) {
                        observed = (observed + 1U) & 255U;
                        valid = 1;
                    }
                }
            } else if (type == 4 || type == 11 || type == 2) {
                if (valid != 0 && declared < observed)
                    goto base_endpoint_anomaly;
                if (type == 4 && length >= 9) {
                    declared = configurations->base[cursor + 4];
                    interface_id = saved_base[cursor + 2];
                    valid = 1;
                    observed = 0;
                } else {
                    interface_id = -1;
                }
            }
            cursor = (cursor + length) & 65535U;
            if (cursor + 2U > anomaly_base_length)
                break;
        }
        if (declared < observed && valid != 0) {
base_endpoint_anomaly:
            configurations->endpoint_anomaly[0] = 4;
            configurations->endpoint_anomaly[1] = interface_id;
            configurations->endpoint_anomaly[2] = observed;
            configurations->anomaly_available = 1;
            return;
        }
    }
    uint anomaly_archived_count = configurations->archived_count;
    configurations->anomaly_available = 0;
    uint anomaly_extra_used = configurations->additional_length;
    if (anomaly_archived_count < 2 || anomaly_extra_used < 4)
        return;
    for (uint ordinal = 0; ordinal + 1U < anomaly_archived_count; ordinal++) {
        uint cursor = 0;
        uint remaining = ordinal;
        uint total;
        for (;;) {
            uint high = *(volatile uchar *)(0x3fca1a33U + cursor);
            uint low = *(volatile uchar *)(0x3fca1a32U + cursor);
            total = (high << 8) | low;
            uint next = (cursor + total) & 65535U;
            if (total < 4 || cursor + total > anomaly_extra_used)
                return;
            if (remaining == 0)
                break;
            remaining = (remaining - 1U) & 255U;
            cursor = next;
            if (next + 4U > anomaly_extra_used)
                return;
        }
        volatile uchar *configuration = (volatile uchar *)(0x3fca1a30U + cursor);
        uint offset = 0;
        int interface_id = -1;
        uint declared = 0;
        uint observed = 0;
        uint valid = 0;
        for (;;) {
            volatile uchar *descriptor = configuration + offset;
            uint length = descriptor[0];
            valid = interface_id != -1;
            if (length < 2 || offset + length > total)
                break;
            uint type = descriptor[1];
            if (type == 5) {
                if (length >= 7) {
                    valid = 0;
                    if (interface_id != -1) {
                        observed = (observed + 1U) & 255U;
                        valid = 1;
                    }
                }
            } else if (type == 4 || type == 11 || type == 2) {
                if (valid != 0 && declared < observed)
                    goto extra_endpoint_anomaly;
                if (type == 4 && length >= 9) {
                    interface_id = descriptor[2];
                    declared = descriptor[4];
                    valid = 1;
                    observed = 0;
                } else {
                    interface_id = -1;
                }
            }
            offset = (offset + length) & 65535U;
            if (offset + 2U > total)
                break;
        }
        if (declared < observed && valid != 0) {
extra_endpoint_anomaly:
            configurations->anomaly_available = 1;
            configurations->endpoint_anomaly[2] = observed;
            configurations->endpoint_anomaly[1] = interface_id;
            configurations->endpoint_anomaly[0] = 4;
            return;
        }
    }
}

