/* Medius v3.4.7 host — usb/descriptors.c.
 * Recovered C and native assembly, grouped for source navigation.
 * Original entry addresses, firmware-byte hashes and function comments follow.
 */

#include "../include/types.h"

/* Native entry: 0x42009928. */
/*
 * Medius v3.4.7 — host application; 0x42009928.
 *
 * Builds a contiguous interface/alternate/endpoint graph in two passes, reclaiming retired
 * generations before replacing current descriptor storage.
 *
 * Calls: medius_host_report_enumeration_limit, medius_usbh_critical_enter,
 * medius_usbh_critical_exit, medius_usbh_retire_descriptor_storage, memset, usb_osal_free,
 * usb_osal_malloc.
 *
 * Called by: usbh_enumerate.
 *
 * Original function-byte SHA-256:
 * 5b50b228fcde02444c73e4115765c5ebe22da2e5c10ecba69041510096687263.
 */

/*
 * port: Live164-byte host port whose descriptor graph is replaced after retirement cleanup; no
 *   NULL/lifetime/reentrancy check.
 * data: Borrowed configuration bytes, reread in both passes; header and short-interface reads can
 *   precede supplied-length bounds.
 * length: Unsigned32 parser bound; advertised header total/interface count do not limit either
 *   pass.
 * Returns: -2 for header bytes other than9/2; -1 on positive-size allocation failure;0 otherwise,
 *   including malformed tails and valid-header length<=9 no-op.
 * Requirements/effects: Copies header with native halfword28/30,word32,byte36 accesses; clears256
 *   private16-bit capacities with128 word stores. Two scans start9, stop malformed prefix without
 *   error, trust32-bit offset arithmetic. Type4 reads endpoint count before minimum9 check; valid
 *   first pass increments16-bit occurrence capacity, unsigned span and32-bit endpoint capacity.
 *   Second pass uses fresh table/count/pointer, caches input alternate byte once, searches entire
 *   current byte-count list retaining LAST match, or appends with byte wrap. Native9/7 copy uses
 *   aligned word transfers where relative alignment agrees, otherwise aligns source and emits word
 *   bytes0..3; descriptor length reread after copied interface/endpoint. Duplicates overwrite
 *   prior pointer while still advancing reserved endpoint cursor by7*declared count; unknown
 *   records retain context, short interfaces disable it, missing/extra endpoints remain
 *   zero/ignored. Between passes caches retired count under critical token, owner read once,
 *   stable owner-before-pointer compaction, collects matching allocations includingNULL into
 *   unchecked eight-pointer local list, publishes retained count then unlocks and frees matches in
 *   order. Clears count then caches current storage, MEMW/clears interfaces/storage, retires
 *   cached old pointer after frees. Size32*span+16*sum(capacity)+7*endpoint capacity wraps32;
 *   failure reports reason4/saturated16 size after old ownership lost. Zero-size skips
 *   malloc/zero. Builds per-interface alternate pointers and publishes storage before interfaces
 *   with count0; rereads borrowed input. Finally insertion-sorts actual byte-count alternate
 *   records by unsigned byte3 using native word snapshots/shift ordering, including endpoint
 *   pointers; MEMW then publishes span16. No graph bound, allocation rollback, duplicate
 *   ownership, retired-count<=8 enforcement, USB validity, physical alignment/timing or concurrent
 *   reader proof. Input changes can escape first-pass allocation; preserved prefix not repaired.
 */

int medius_host_parse_configuration(MediusHostHubPortPrefix *port,uchar *data,uint length)
{
    volatile MediusHostHubPortPrefix *live = port;
    const volatile uchar *input = data;
    if (input[0] != 9 || input[1] != 2)
        return -2;
    if (length <= 9)
        return 0;
    *(volatile ushort *)((uint)port + 28U) = 0x0209;
    ushort total_length = *(const volatile ushort *)((uint)data + 2U);
    *(volatile ushort *)((uint)port + 30U) = total_length;
    uint configuration_fields = *(const volatile uint *)((uint)data + 4U);
    *(volatile uint *)((uint)port + 32U) = configuration_fields;
    uchar max_power = input[8];
    *(volatile uchar *)((uint)port + 36U) = max_power;

    /* Native private sizing array is cleared with128 aligned word stores. */
    ushort capacities[256] __attribute__((aligned(4)));
    volatile uint *capacity_words = (volatile uint *)capacities;
    for (uint index = 0; index < 128; ++index)
        capacity_words[index] = 0;
    uint span = 0;
    uint alternate_capacity = 0;
    uint endpoint_capacity = 0;
    uint endpoint_cursor = 0;
    uint current_alternate = 0;
    uint declared_endpoints = 255;
    uchar endpoint_index = 255;

    for (uint pass = 0; pass < 2; ++pass) {
        int invalid_interface = 1;
        uint offset = 9;
        uint record = (uint)data + 9U;
        if (length != 10) {
            do {
                uint descriptor_length = *(const volatile uchar *)record;
                if (descriptor_length < 2)
                    break;
                uint next_offset = offset + descriptor_length;
                if (length < next_offset)
                    break;
                uchar type = *(const volatile uchar *)(record + 1U);
                uint copy_destination = 0;
                uint copy_length = 0;
                int copied_interface = 0;
                if (type == 4) {
                    declared_endpoints = *(const volatile uchar *)(record + 4U);
                    if (descriptor_length < 9) {
                        invalid_interface = 1;
                        endpoint_index = 0;
                    } else {
                        uint number = *(const volatile uchar *)(record + 2U);
                        if (pass == 0) {
                            if ((int)span <= (int)number)
                                span = number + 1U;
                            ushort capacity = capacities[number];
                            capacities[number] = (ushort)(capacity + 1U);
                            endpoint_capacity += declared_endpoints;
                            invalid_interface = 0;
                            endpoint_index = 0;
                        } else {
                            MediusHostInterfacePrefix *table = live->interfaces;
                            volatile MediusHostInterfacePrefix *interface =
                                (volatile MediusHostInterfacePrefix *)((uint)table + number * 32U);
                            uchar count = interface->alternate_count;
                            MediusHostAlternatePrefix *alternates = interface->alternates;
                            current_alternate = (uint)alternates;
                            if (count == 0) {
                                interface->alternate_count = 1;
                            } else {
                                uchar setting = *(const volatile uchar *)(record + 3U);
                                current_alternate = 0;
                                for (uint index = 0; index < count; ++index) {
                                    uint alternate = (uint)alternates + index * 16U;
                                    uchar existing_setting = *(const volatile uchar *)(alternate + 3U);
                                    if (existing_setting == setting)
                                        current_alternate = alternate; /* Last match wins. */
                                }
                                if (current_alternate == 0) {
                                    current_alternate = (uint)alternates + (uint)count * 16U;
                                    interface->alternate_count = (uchar)(count + 1U);
                                }
                            }
                            copy_destination = current_alternate;
                            copy_length = 9;
                            copied_interface = 1;
                        }
                    }
                } else if (type == 5 && !invalid_interface && pass == 1) {
                    if (endpoint_index < declared_endpoints && descriptor_length >= 7) {
                        uint endpoints = *(const volatile uint *)(current_alternate + 12U);
                        copy_destination = endpoints + (uint)endpoint_index * 7U;
                        copy_length = 7;
                    }
                }
                if (copy_length != 0) {
                    uint source = record;
                    uint destination = copy_destination;
                    uint remaining = copy_length;
                    if (((destination ^ source) & 3U) == 0) {
                        while ((destination & 3U) != 0 && remaining != 0) {
                            uchar value = *(const volatile uchar *)source;
                            *(volatile uchar *)destination = value;
                            ++source;
                            ++destination;
                            --remaining;
                        }
                        while (remaining >= 4) {
                            uint value = *(const volatile uint *)source;
                            *(volatile uint *)destination = value;
                            source += 4;
                            destination += 4;
                            remaining -= 4;
                        }
                    } else {
                        while ((source & 3U) != 0 && remaining != 0) {
                            uchar value = *(const volatile uchar *)source;
                            *(volatile uchar *)destination = value;
                            ++source;
                            ++destination;
                            --remaining;
                        }
                        while (remaining >= 4) {
                            uint value = *(const volatile uint *)source;
                            ((volatile uchar *)destination)[0] = (uchar)value;
                            ((volatile uchar *)destination)[1] = (uchar)(value >> 8);
                            ((volatile uchar *)destination)[2] = (uchar)(value >> 16);
                            ((volatile uchar *)destination)[3] = (uchar)(value >> 24);
                            source += 4;
                            destination += 4;
                            remaining -= 4;
                        }
                    }
                    while (remaining != 0) {
                        uchar value = *(const volatile uchar *)source;
                        *(volatile uchar *)destination = value;
                        ++source;
                        ++destination;
                        --remaining;
                    }
                    if (copied_interface) {
                        *(volatile uint *)(current_alternate + 12U) =
                            declared_endpoints == 0 ? 0 : endpoint_cursor;
                        invalid_interface = 0;
                        endpoint_index = 0;
                        descriptor_length = *(const volatile uchar *)record;
                        endpoint_cursor += declared_endpoints * 7U;
                    } else {
                        descriptor_length = *(const volatile uchar *)record;
                        endpoint_index = (uchar)(endpoint_index + 1U);
                        invalid_interface = 0;
                    }
                    next_offset = offset + descriptor_length;
                }
                record += descriptor_length;
                offset = next_offset;
            } while (offset + 2U <= length);
        }
        if (pass == 1)
            break;
        for (uint index = 0; index < span; ++index)
            alternate_capacity += capacities[index];

        void *reclaimed[8];
        uchar matched = 0;
        uchar retained = 0;
        uint token = medius_usbh_critical_enter();
        uchar retired_count = *(const volatile uchar *)&medius_retired_descriptor_count;
        if (retired_count != 0) {
            for (uint index = 0; index < retired_count; ++index) {
                const volatile MediusRetiredDescriptor *old =
                    (const volatile MediusRetiredDescriptor *)((uint)medius_retired_descriptors + index * 8U);
                MediusHostHubPortPrefix *owner = old->owner;
                if (owner == port) {
                    void *allocation = old->allocation;
                    reclaimed[matched] = allocation; /* Native list has no bound check. */
                    matched = (uchar)(matched + 1U);
                } else {
                    void *allocation = old->allocation;
                    volatile MediusRetiredDescriptor *destination =
                        (volatile MediusRetiredDescriptor *)((uint)medius_retired_descriptors + (uint)retained * 8U);
                    destination->owner = owner;
                    destination->allocation = allocation;
                    retained = (uchar)(retained + 1U);
                }
            }
            *(volatile uchar *)&medius_retired_descriptor_count = retained;
        }
        medius_usbh_critical_exit(token);
        for (uint index = 0; index < matched; ++index)
            usb_osal_free(reclaimed[index]); /* NULL is forwarded too. */
        live->interface_count = 0;
        void *previous_storage = live->descriptor_storage;
        memw();
        live->interfaces = 0;
        live->descriptor_storage = 0;
        if (previous_storage != 0)
            medius_usbh_retire_descriptor_storage(port,previous_storage);

        uint allocation_size = (((span & 0xffffU) * 2U + alternate_capacity) * 16U) +
            endpoint_capacity * 7U;
        MediusHostInterfacePrefix *allocation = 0;
        if (allocation_size != 0) {
            allocation = usb_osal_malloc(allocation_size);
            if (allocation == 0) {
                uint report_size = allocation_size < 65535 ? allocation_size : 65535;
                medius_host_report_enumeration_limit(port,4,(ushort)report_size);
                return -1;
            }
            memset(allocation,0,allocation_size);
        }
        uint alternate_cursor = (uint)allocation + (span & 0xffffU) * 32U;
        endpoint_cursor = alternate_cursor + alternate_capacity * 16U;
        for (uint index = 0; index < span; ++index) {
            ushort capacity = capacities[index];
            volatile MediusHostInterfacePrefix *interface =
                (volatile MediusHostInterfacePrefix *)((uint)allocation + index * 32U);
            interface->alternates = capacity == 0 ? 0 : (MediusHostAlternatePrefix *)alternate_cursor;
            alternate_cursor += (uint)capacity * 16U;
        }
        live->descriptor_storage = allocation;
        live->interfaces = allocation;
    }
    if (span != 0) {
        MediusHostInterfacePrefix *table = live->interfaces;
        for (uint index = 0; index < (span & 0xffffU); ++index) {
            const volatile MediusHostInterfacePrefix *interface =
                (const volatile MediusHostInterfacePrefix *)((uint)table + index * 32U);
            uchar count = interface->alternate_count;
            if (count < 2)
                continue;
            uint base = (uint)interface->alternates;
            for (uchar sorted = 1; sorted != count; ++sorted) {
                uint selected = base + (uint)sorted * 16U;
                uint saved_endpoints = *(const volatile uint *)(selected + 12U);
                uint saved_prefix = *(const volatile uint *)selected;
                uint saved_class = *(const volatile uint *)(selected + 4U);
                uint saved_tail = *(const volatile uint *)(selected + 8U);
                uchar setting = *(const volatile uchar *)(selected + 3U);
                uint preceding = selected - 16U;
                uint insertion;
                for (;;) {
                    uchar preceding_setting = *(const volatile uchar *)(preceding + 3U);
                    if (preceding_setting <= setting) {
                        insertion = preceding + 16U;
                        break;
                    }
                    uint prefix = *(const volatile uint *)preceding;
                    uint class_fields = *(const volatile uint *)(preceding + 4U);
                    *(volatile uint *)(preceding + 16U) = prefix;
                    uint tail = *(const volatile uint *)(preceding + 8U);
                    *(volatile uint *)(preceding + 20U) = class_fields;
                    uint endpoints = *(const volatile uint *)(preceding + 12U);
                    *(volatile uint *)(preceding + 24U) = tail;
                    *(volatile uint *)(preceding + 28U) = endpoints;
                    if (preceding == base) {
                        insertion = base;
                        break;
                    }
                    preceding -= 16U;
                }
                *(volatile uint *)insertion = saved_prefix;
                *(volatile uint *)(insertion + 4U) = saved_class;
                *(volatile uint *)(insertion + 8U) = saved_tail;
                *(volatile uint *)(insertion + 12U) = saved_endpoints;
            }
        }
    }
    memw();
    live->interface_count = (ushort)span;
    return 0;
}

/* Native entry: 0x42025528. */
/* Original function-byte SHA-256:
 * 36b48de8bcf7c498b8d85b29f5db3713fb9c1546c8d2add3e2b4fe0c81e8bce6. */
/* Test whether this endpoint's motion report may be suppressed. Acquire the
 * motion spinlock with timeout -1 and discard the acquisition status. Read the
 * configuration-ready BYTE, then the configured endpoint BYTE. Release the lock
 * on every path; only a ready, nonzero, matching endpoint queries program-ready
 * and then pending state. Return the pending BYTE as an int without normalizing
 * it to boolean. Neither predicate runs under this lock; this is not an atomic
 * snapshot of all three states. No USB connection or descriptor check occurs. */
int medius_endpoint_suppression_active(unsigned char endpoint)
{
    (void)xPortEnterCriticalTimeout(&MEDIUS_MOTION_PENDING_LOCK,-1);
    if (MEDIUS_MOTION_CONFIGURATION_READY==0) {
        vPortExitCritical(&MEDIUS_MOTION_PENDING_LOCK);
        return 0;
    }
    unsigned char configured_endpoint=MEDIUS_MOTION_WIRE_CONFIGURATION->endpoint;
    if (configured_endpoint==0 || configured_endpoint!=endpoint) {
        vPortExitCritical(&MEDIUS_MOTION_PENDING_LOCK);
        return 0;
    }
    vPortExitCritical(&MEDIUS_MOTION_PENDING_LOCK);
    if (medius_motion_input_program_ready()==0)
        return 0;
    return medius_motion_pending();
}

/* Native entry: 0x420271a8. */
/* Original function-byte SHA-256:
 * 18bfbe1d9f9ad74bad5ae9dc957dac60023eec342fa4fe77ca64995aac2c26b0. */
/* Pick the first interrupt endpoint in each direction for one interface/alt.
 * Sample interfaces, MEMW, interface_count, MEMW, then reread interfaces. A NULL
 * or changed table, out-of-range unsigned interface number, empty alternate
 * list or missing alternate clears OUT then IN and returns. Compare each BYTE
 * alternate setting with the full unsigned alternate argument; retain the first
 * matching record. Clear OUT then IN before reading its endpoint count.
 * Scan exactly that BYTE count of seven-byte descriptors. Attributes low two
 * bits must equal 3; address bit 7 selects direction. Reread the corresponding
 * output pointer each time and store only when NULL, preserving output aliasing
 * effects. No port/output-pointer, graph-capacity, endpoint number, speed, MPS,
 * interval, connection or descriptor-lifetime validation is performed. */
void medius_host_pick_interrupt_endpoints(MediusHostHubPortPrefix *port,
    unsigned int interface_number,unsigned int alternate,
    unsigned char **in_endpoint,unsigned char **out_endpoint)
{
    const volatile MediusHostHubPortPrefix *live=port;
    const volatile MediusHostInterfacePrefix *interfaces=live->interfaces;
    memw();
    unsigned int interface_count=live->interface_count;
    memw();
    if (interfaces==NULL || interfaces!=live->interfaces || interface_number>=interface_count)
        goto no_match;
    const volatile MediusHostInterfacePrefix *interface=&interfaces[interface_number];
    unsigned int alternate_count=interface->alternate_count;
    if (alternate_count==0)
        goto no_match;
    const volatile MediusHostAlternatePrefix *candidate=interface->alternates;
    for (unsigned int index=0;index<alternate_count;++index,++candidate) {
        if ((unsigned int)candidate->alternate_setting!=alternate)
            continue;
        *(unsigned char *volatile *)out_endpoint=NULL;
        *(unsigned char *volatile *)in_endpoint=NULL;
        unsigned int endpoint_count=candidate->endpoint_count;
        if (endpoint_count==0)
            return;
        unsigned char *descriptor=candidate->endpoints;
        for (unsigned int remaining=endpoint_count;remaining!=0;--remaining,descriptor+=7) {
            const volatile MediusHostEndpointDescriptor *endpoint=(const volatile void *)descriptor;
            if ((endpoint->attributes&3U)!=3U)
                continue;
            if (endpoint->address&0x80U) {
                if (*(unsigned char *volatile *)in_endpoint==NULL)
                    *(unsigned char *volatile *)in_endpoint=descriptor;
            } else if (*(unsigned char *volatile *)out_endpoint==NULL) {
                *(unsigned char *volatile *)out_endpoint=descriptor;
            }
        }
        return;
    }
no_match:
    *(unsigned char *volatile *)out_endpoint=NULL;
    *(unsigned char *volatile *)in_endpoint=NULL;
}

/* Native entry: 0x42027d0c. */
/*
 * Medius v3.4.7 — host application; 0x42027d0c.
 *
 * Publishes live/archived HID descriptors, ordered snapshot sections, identity metadata and a
 * final section6 marker.
 *
 * Calls: medius_get_firmware_label, medius_host_log_formatted,
 * medius_host_publish_hid_descriptor_blob, medius_host_send_hid_descriptor_fragments,
 * link_send_wait100, medius_snapshot_emit_commit_marker, medius_snapshot_emit_section.
 *
 * Called by: FUN_4202d78c, medius_clone_publish_request, medius_snapshot_timer_cb.
 *
 * Original function-byte SHA-256:
 * d2948b1f78014df3cc97b21be3795bf1ec9702e43211a89962303de17f038da0.
 */

/*
 * Returns: No value.
 * Requirements/effects: Sends opcode0x26 descriptor reset with two stack words255/0, then
 *   optionally emits current live blob. Archive identity gating caches current VID, used, saved
 *   VID and base in native order; only matching VID reads/compares PID. Archive lengths read high
 *   then low once; emits non255/noncurrent records, refreshing used/base/current after each
 *   callback while retaining next offset. Coverage scans cached archive for interfaces0 then1 for
 *   each index0..7 regardless of identity gate; current index always counts. Logs coverage, reads
 *   device length before resetting sequence, then emits required0..5 and optional7/13/14 with
 *   independently fresh16-bit lengths. Matching fresh packed PID/VID enables section16: length0
 *   initializes tag3b, copies48 bytes in native word-read/byte-store order, writes
 *   byte68=0/length69; then always caches source halfwords6/4/2/0 and repeats48-byte copy,
 *   rewrites source bytes56..66 into buffer49..59, and stores reordered halfwords in two words
 *   at64 then60. Existing nonzero metadata length/tag/tail are retained, even if length shorter
 *   than writes. Emits10 speed, optional15 three borrowed stack bytes, optional11 other
 *   configurations, optional12 selected index, then commit marker. Post-marker
 *   speed/IDs/count/index/blob-length snapshots precede firmware-label call and final log. Every
 *   transport/section/log return is ignored. Advertised lengths, callback lifetimes and all
 *   storage are trusted; no admission lock, rollback, remote acceptance or timer/deadline
 *   guarantee. Archive stride(length+4) narrows16 and zero can loop without progress. Fresh loads
 *   allow mixed snapshots under mutation; synchronous consumption/copy of global/stack payloads is
 *   required.
 */

void medius_clone_publish(void)
{
    uint stack_payload[2];
    *(volatile uint *)&stack_payload[0] = 255;
    *(volatile uint *)&stack_payload[1] = 0;
    link_send_wait100(0x26,0,(uchar *)stack_payload,8);
    ushort blob_length = *(const volatile ushort *)&medius_hid_descriptor_blob_used;
    uchar current = MEDIUS_HOST_CURRENT_CONFIGURATION;
    if (blob_length != 0) {
        medius_host_publish_hid_descriptor_blob(current,blob_length);
        current = MEDIUS_HOST_CURRENT_CONFIGURATION;
    }
    const volatile MediusHidDescriptorArchive *archive = &medius_hid_descriptor_archive;
    ushort current_vendor = MEDIUS_HOST_CURRENT_VENDOR_ID;
    uint used = archive->used;
    ushort archive_vendor = HOST_CAPTURE_ARCHIVE_VENDOR;
    uchar *base = archive->data;
    uint sent_records = 0;
    if (current_vendor == archive_vendor) {
        ushort current_product = MEDIUS_HOST_CURRENT_PRODUCT_ID;
        ushort archive_product = HOST_CAPTURE_ARCHIVE_PRODUCT;
        if (current_product == archive_product) {
            uint offset = 0;
            while (offset + 3U < used) {
                const volatile MediusHidArchiveRecordHeader *record =
                    (const volatile MediusHidArchiveRecordHeader *)((uint)base + offset);
                uchar high = record->length_high;
                uchar low = record->length_low;
                uint length = ((uint)high << 8) | low;
                uint next = offset + ((length + 4U) & 0xffffU);
                const uchar *payload = (const uchar *)((uint)base + offset + 4U);
                if (used < next)
                    break;
                uchar configuration = record->configuration;
                offset = next & 0xffffU;
                if (configuration == 255 || configuration == current)
                    continue;
                uchar interface_id = record->interface_id;
                ++sent_records;
                medius_host_send_hid_descriptor_fragments(configuration,interface_id,payload,length);
                used = archive->used;
                base = archive->data;
                current = MEDIUS_HOST_CURRENT_CONFIGURATION;
            }
        }
    }
    uint covered = 0;
    for (uint configuration = 0; configuration < 8; ++configuration) {
        if (current == configuration) {
            ++covered;
            continue;
        }
        if (used < 4)
            continue;
        int found = 0;
        for (uint interface_id = 0; interface_id < 2 && !found; ++interface_id) {
            uint offset = 0;
            do {
                const volatile MediusHidArchiveRecordHeader *record =
                    (const volatile MediusHidArchiveRecordHeader *)((uint)base + offset);
                uchar high = record->length_high;
                uchar low = record->length_low;
                uint next = offset + (((((uint)high << 8) | low) + 4U) & 0xffffU);
                offset = next & 0xffffU;
                if (used < next)
                    break;
                if (record->configuration == configuration && record->interface_id == interface_id) {
                    found = 1;
                    break;
                }
            } while (offset + 3U < used);
        }
        if (found)
            ++covered;
    }
    uchar configuration_count = HOST_CAPTURE_CONFIGURATION_COUNT;
    medius_host_log_formatted(
        "report descriptors pushed: configuration %u live, %d more (%u configurations covered of %u)",
        current,(int)sent_records,covered,configuration_count);
    ushort device_length = HOST_DEVICE_DESCRIPTOR_LENGTH;
    *(volatile uchar *)&medius_snapshot_sequence = 0;
    medius_snapshot_emit_section(0,HOST_DEVICE_DESCRIPTOR_BYTES,device_length,256,
                                medius_snapshot_send_section_frame,0);
    ushort length = HOST_CAPTURED_CONFIGURATION_LENGTH;
    medius_snapshot_emit_section(1,(uchar *)HOST_FIRST_CONFIGURATION_BYTES,length,256,
                                medius_snapshot_send_section_frame,0);
    length = *(const volatile ushort *)&medius_hid_descriptor_blob_used;
    medius_snapshot_emit_section(2,medius_hid_descriptor_blob,length,256,
                                medius_snapshot_send_section_frame,0);
    length = HOST_MANUFACTURER_ASCII_LENGTH;
    medius_snapshot_emit_section(3,HOST_MANUFACTURER_ASCII,length,256,
                                medius_snapshot_send_section_frame,0);
    length = HOST_PRODUCT_ASCII_LENGTH;
    medius_snapshot_emit_section(4,HOST_PRODUCT_ASCII,length,256,
                                medius_snapshot_send_section_frame,0);
    length = HOST_SERIAL_ASCII_LENGTH;
    medius_snapshot_emit_section(5,HOST_SERIAL_ASCII,length,256,
                                medius_snapshot_send_section_frame,0);
    length = HOST_BOS_DESCRIPTOR_LENGTH;
    if (length != 0)
        medius_snapshot_emit_section(7,HOST_BOS_DESCRIPTOR_BYTES,length,256,
                                    medius_snapshot_send_section_frame,0);
    length = *(const volatile ushort *)&medius_string_descriptor_archive_used;
    if (length != 0)
        medius_snapshot_emit_section(13,medius_string_descriptor_archive,length,256,
                                    medius_snapshot_send_section_frame,0);
    length = HOST_SPEED_DESCRIPTOR_RECORD_LENGTH;
    if (length != 0)
        medius_snapshot_emit_section(14,HOST_SPEED_DESCRIPTOR_RECORD,length,256,
                                    medius_snapshot_send_section_frame,0);
    ushort metadata_product = MEDIUS_HOST_CURRENT_PRODUCT_ID;
    ushort metadata_vendor = MEDIUS_HOST_CURRENT_VENDOR_ID;
    uint stored_identity = HOST_CLONE_METADATA_IDENTITY;
    if ((((uint)metadata_vendor << 16) | metadata_product) == stored_identity) {
        ushort metadata_length = HOST_CLONE_METADATA_LENGTH;
        volatile uchar *metadata = medius_clone_metadata_buffer;
        if (metadata_length == 0) {
            metadata[0] = 0x3b;
            for (uint block = 0; block < 3; ++block) {
                uint source = (uint)medius_clone_metadata_source + 8U + block * 16U;
                volatile uchar *destination = (volatile uchar *)
                        ((uint)medius_clone_metadata_buffer + 1U + block * 16U);
                uint third = *(const volatile uint *)(source + 8U);
                uint fourth = *(const volatile uint *)(source + 12U);
                uint first = *(const volatile uint *)source;
                destination[11] = (uchar)(third >> 24);
                uint second = *(const volatile uint *)(source + 4U);
                destination[13] = (uchar)(fourth >> 8);
                destination[8] = (uchar)third;
                destination[14] = (uchar)(fourth >> 16);
                destination[10] = (uchar)(third >> 16);
                destination[0] = (uchar)first;
                destination[1] = (uchar)(first >> 8);
                destination[2] = (uchar)(first >> 16);
                destination[3] = (uchar)(first >> 24);
                destination[4] = (uchar)second;
                destination[5] = (uchar)(second >> 8);
                destination[6] = (uchar)(second >> 16);
                destination[7] = (uchar)(second >> 24);
                destination[9] = (uchar)(third >> 8);
                destination[12] = (uchar)fourth;
                destination[15] = (uchar)(fourth >> 24);
            }

            metadata[68] = 0;
            HOST_CLONE_METADATA_LENGTH = 69;
            metadata_length = 69;
        }
        ushort source_half6 = *(const volatile ushort *)((uint)medius_clone_metadata_source + 6U);
        ushort source_half4 = *(const volatile ushort *)((uint)medius_clone_metadata_source + 4U);
        ushort source_half2 = *(const volatile ushort *)((uint)medius_clone_metadata_source + 2U);
        ushort source_half0 = *(const volatile ushort *)medius_clone_metadata_source;
        for (uint block = 0; block < 3; ++block) {
            uint source = (uint)medius_clone_metadata_source + 8U + block * 16U;
            volatile uchar *destination = (volatile uchar *)
                ((uint)medius_clone_metadata_buffer + 1U + block * 16U);
            uint third = *(const volatile uint *)(source + 8U);
            uint fourth = *(const volatile uint *)(source + 12U);
            uint first = *(const volatile uint *)source;
            destination[11] = (uchar)(third >> 24);
            uint second = *(const volatile uint *)(source + 4U);
            destination[13] = (uchar)(fourth >> 8);
            destination[8] = (uchar)third;
            destination[14] = (uchar)(fourth >> 16);
            destination[10] = (uchar)(third >> 16);
            destination[0] = (uchar)first;
            destination[1] = (uchar)(first >> 8);
            destination[2] = (uchar)(first >> 16);
            destination[3] = (uchar)(first >> 24);
            destination[4] = (uchar)second;
            destination[5] = (uchar)(second >> 8);
            destination[6] = (uchar)(second >> 16);
            destination[7] = (uchar)(second >> 24);
            destination[9] = (uchar)(third >> 8);
            destination[12] = (uchar)fourth;
            destination[15] = (uchar)(fourth >> 24);
        }

        uint tail_first = *(const volatile uint *)((uint)medius_clone_metadata_source + 56U);
        uint tail_second = *(const volatile uint *)((uint)medius_clone_metadata_source + 60U);
        uchar source66 = ((const volatile uchar *)medius_clone_metadata_source)[66];
        uchar source65 = ((const volatile uchar *)medius_clone_metadata_source)[65];
        metadata[58] = source65;
        uchar source64 = ((const volatile uchar *)medius_clone_metadata_source)[64];
        metadata[59] = source66;
        metadata[49] = (uchar)tail_first;
        metadata[53] = (uchar)tail_second;
        metadata[56] = (uchar)(tail_second >> 24);
        *(volatile uint *)((uint)metadata + 64U) = (uint)source_half2 | ((uint)source_half0 << 16);
        metadata[50] = (uchar)(tail_first >> 8);
        metadata[51] = (uchar)(tail_first >> 16);
        metadata[52] = (uchar)(tail_first >> 24);
        metadata[54] = (uchar)(tail_second >> 8);
        metadata[55] = (uchar)(tail_second >> 16);
        *(volatile uint *)((uint)metadata + 60U) = (uint)source_half6 | ((uint)source_half4 << 16);
        metadata[57] = source64;
        medius_snapshot_emit_section(16,medius_clone_metadata_buffer,metadata_length,256,
                                    medius_snapshot_send_section_frame,0);
    }
    medius_snapshot_emit_section(10,(uchar *)&HOST_CAPTURED_SPEED,1,256,medius_snapshot_send_section_frame,0);
    uchar section15_present = HOST_ENDPOINT_ANOMALY_AVAILABLE;
    if (section15_present != 0) {
        ushort section15_low = *(const volatile ushort *)medius_clone_section15_data;
        uchar section15_high = ((const volatile uchar *)medius_clone_section15_data)[2];
        *(volatile ushort *)stack_payload = section15_low;
        ((volatile uchar *)stack_payload)[2] = section15_high;
        medius_snapshot_emit_section(15,(uchar *)stack_payload,3,256,
                                    medius_snapshot_send_section_frame,0);
    }
    length = HOST_OTHER_CONFIGURATION_LENGTH;
    if (length != 0)
        medius_snapshot_emit_section(11,(uchar *)HOST_OTHER_CONFIGURATION_BYTES,length,256,
                                    medius_snapshot_send_section_frame,0);
    uchar selected_index = MEDIUS_HOST_CURRENT_CONFIGURATION;
    if (selected_index != 0)
        medius_snapshot_emit_section(12,(uchar *)&MEDIUS_HOST_CURRENT_CONFIGURATION,1,256,
                                    medius_snapshot_send_section_frame,0);
    medius_snapshot_emit_commit_marker(medius_snapshot_send_section_frame,0);
    uchar logged_speed = HOST_CAPTURED_SPEED;
    ushort logged_vendor = MEDIUS_HOST_CURRENT_VENDOR_ID;
    ushort logged_product = MEDIUS_HOST_CURRENT_PRODUCT_ID;
    uchar logged_count = HOST_CAPTURE_CONFIGURATION_COUNT;
    uchar logged_index = MEDIUS_HOST_CURRENT_CONFIGURATION;
    ushort logged_blob_length = *(const volatile ushort *)&medius_hid_descriptor_blob_used;
    char *label = medius_get_firmware_label();
    medius_host_log_formatted(
        "snapshot sent vid=%04x pid=%04x speed=%u cfgs=%u active=%u (%u B) fw=%s",
        logged_vendor,logged_product,logged_speed,logged_count,logged_index,logged_blob_length,label);
}

/* Native entry: 0x42029200. */
/* Original function-byte SHA-256:
 * 0096e9794fb4eea954adce965b1ae845194ae15711bad74d4ce999bf30afc3ab. */
/* Restore the current selector or publish a host restart request.
 * selector/generation are full32; deferred is full32 nonzero policy. No return.
 * Fence restart then switch gates; otherwise cache configuration semaphore and
 * inspect queued tokens. Busy paths fence requested selector; equal returns
 * after fenced deferred-recovery read and, only when zero, an additional fenced
 * UNUSED control-port read. Unequal deferred requests return; others publish.
 * Idle/different selector publishes unless deferred and fenced control port is
 * NULL. Publication requires a nonNULL semaphore sampled before flag stores.
 * Fence/set restart1, fence/store selector LOW8, sample signed microseconds/1000
 * and cache current vendor16 BEFORE fence/time-low32 publication. Cache product16,
 * store previous vendor, read CURRENT semaphore, store previous product, then
 * nonblocking give that cached handle; ignore result. Comparison does not
 * truncate selector or use generation to order/reject restart requests.
 *
 * Idle/equal selector: fence deferred-recovery then control port; require live
 * connected port and, for deferred calls, fenced global HID pause!=0. Sample
 * time once, then fence pause again. If unpaused, wait on queued-through
 * generation until empty or signed modulo64 elapsed>49999, delaying1 tick per
 * retry, then pause all HID. Cache configuration_value BEFORE fenced activity1;
 * retry SET_CONFIGURATION(0,9,value,0,0) using the original start. Disconnection
 * returns; connected failure requests recovery with fixed reason/force0.
 *
 * Success clears IN/OUT toggles and fenced needs-rearm/special-retry/special-valid/
 * halt/pause for six active records with handles. For each nonzero of256 saved
 * HID selections, cache interface table, fence/read count16, fence/recheck table
 * even if NULL. Stable in-range entries with alternates, FIRST class3 and handle
 * restore alternate0/allow_rearm0. Selection bytes are not locally cleared.
 * Restore vendor configuration, reset/resume OUT, then fence global HID pause0.
 * Scan six fenced-active entries with fenced period<2; rearm negatives except-6
 * fence/set needs-rearm1 and global retry1. After EVERY rearm, disconnected port
 * cancels the freshly read nonNULL class IN URB, then continues later slots.
 * No pointer/count validation, lock, atomic snapshot, rollback, physical delay
 * or callback-lifetime guarantee. Timeout permits restoration to proceed. */
void medius_host_apply_configuration(unsigned int selector,unsigned int generation,int deferred)
{
    memw(); if (MEDIUS_HOST_RESTART_GATE != 0) goto busy;
    memw(); if (MEDIUS_HOST_CONFIGURATION_SWITCH_GATE != 0) goto busy;
    RtosQueue *queue = MEDIUS_HOST_CONFIGURATION_QUEUE;
    if (queue != NULL && uxQueueMessagesWaiting(queue) != 0) goto busy;
    if (MEDIUS_HOST_CURRENT_CONFIGURATION != selector) {
        if (deferred != 0) {
            memw(); if (MEDIUS_HOST_CONTROL_PORT == NULL) return;
        }
        goto publish;
    }
    memw(); if (MEDIUS_HOST_RECOVERY_DEFERRED != 0) return;
    memw(); MediusHostHubPortPrefix *port = MEDIUS_HOST_CONTROL_PORT;
    volatile MediusHostHubPortPrefix *live_port = port;
    if (port == NULL || live_port->connected == 0) return;
    if (deferred != 0) {
        memw(); if (MEDIUS_HOST_HID_PAUSED == 0) return;
    }
    unsigned long long started = (unsigned long long)esp_timer_get_time();
    memw();
    if (MEDIUS_HOST_HID_PAUSED == 0) {
        while (medius_out_has_queued_through(generation) != 0) {
            unsigned long long elapsed = (unsigned long long)esp_timer_get_time() - started;
            if ((long long)elapsed > 49999LL) break;
            vTaskDelay(1);
        }
        medius_host_pause_all_hid();
    }
    unsigned short configuration = live_port->configuration_value;
    memw(); MEDIUS_HOST_CONTROL_ACTIVITY = 1;
    int result = medius_host_control_retry(port,(long long)started,0,9,configuration,0,0);
    if (live_port->connected == 0) return;
    if (result < 0) {
        medius_host_request_recovery("SET_CONFIGURATION failed after a bus reset",0);
        return;
    }
    for (unsigned int slot = 0; slot < 6; ++slot) {
        volatile MediusHidEndpointState *state = &MEDIUS_HOST_HID_ENDPOINTS[slot];
        memw(); if (state->active == 0) continue;
        MediusHostHidClass *hid = state->interface_handle;
        if (hid == NULL) continue;
        ((volatile MediusHostHidClass *)hid)->in_urb.toggle = 0;
        ((volatile MediusHostHidClass *)hid)->out_urb.toggle = 0;
        memw(); state->needs_rearm = 0;
        memw(); state->special_retry = 0;
        memw(); state->special_valid = 0;
        memw(); state->halted = 0;
        memw(); state->paused = 0;
    }
    for (unsigned int index = 0; index < 256; ++index) {
        if (MEDIUS_HID_ALTERNATE_SELECTIONS[index] == 0) continue;
        MediusHostInterfacePrefix *table = live_port->interfaces;
        memw(); unsigned int count = live_port->interface_count;
        memw();
        if (table == NULL || live_port->interfaces != table || index >= count) continue;
        volatile MediusHostInterfacePrefix *entry = &table[index];
        if (entry->alternate_count == 0) continue;
        const volatile unsigned char *alternate = (const volatile void *)entry->alternates;
        if (alternate[5] != 3) continue;
        MediusHostHidClass *hid = entry->private_data;
        if (hid != NULL) medius_host_restore_hid_alternate(port,hid,0,0);
    }
    medius_vendor_restore_configuration(port);
    medius_out_reset_toggles_resume();
    memw(); MEDIUS_HOST_HID_PAUSED = 0;
    for (unsigned int slot = 0; slot < 6; ++slot) {
        volatile MediusHidEndpointState *state = &MEDIUS_HOST_HID_ENDPOINTS[slot];
        memw(); if (state->active == 0) continue;
        memw(); if (state->poll_period >= 2) continue;
        int rearmed = medius_hid_rearm_with_credit_gate((MediusHidEndpointState *)state);
        if (rearmed < 0 && rearmed != -6) {
            memw(); state->needs_rearm = 1;
            memw(); MEDIUS_HID_RETRY_PENDING = 1;
        }
        if (live_port->connected == 0) {
            MediusHostHidClass *hid = state->interface_handle;
            if (hid != NULL) usbh_kill_urb(&hid->in_urb);
        }
    }
    return;
busy:
    memw();
    if (MEDIUS_HOST_REQUESTED_CONFIGURATION == selector) {
        memw();
        if (MEDIUS_HOST_RECOVERY_DEFERRED == 0) {
            memw(); (void)MEDIUS_HOST_CONTROL_PORT;
        }
        return;
    }
    if (deferred != 0) return;
publish:
    if (MEDIUS_HOST_CONFIGURATION_QUEUE == NULL) return;
    memw(); MEDIUS_HOST_RESTART_GATE = 1;
    memw(); MEDIUS_HOST_REQUESTED_CONFIGURATION = (unsigned char)selector;
    unsigned int requested_ms = (unsigned int)(esp_timer_get_time() / 1000LL);
    unsigned short vendor = MEDIUS_HOST_CURRENT_VENDOR_ID;
    memw(); MEDIUS_HOST_RESTART_REQUESTED_MS = requested_ms;
    unsigned short product = MEDIUS_HOST_CURRENT_PRODUCT_ID;
    MEDIUS_HOST_PREVIOUS_VENDOR_ID = vendor;
    queue = MEDIUS_HOST_CONFIGURATION_QUEUE;
    MEDIUS_HOST_PREVIOUS_PRODUCT_ID = product;
    xQueueGenericSend(queue,NULL,0,0);
}

/* Native entry: 0x4202e2b0. */
/* Original function-byte SHA-256:
 * da8992bb36e203b832c92c57f2ee541f4e53fd0fad10c1d89ac6c7a548c2f20f. */
/*
 * Fence/sample control port; NULL returns without checking readiness. Nonnull
 * port additionally needs capture-ready BYTE!=0. Then fence/sample forwarding
 * inhibit: zero calls clone publication immediately, nonzero fences/stores
 * publication-pending1. Does not clear pending on the immediate path, capture
 * descriptors, lock the port or return delivery status. Readiness/inhibit are
 * separate samples; a reset can change them while publication is running.
 */
void medius_clone_publish_request(void)
{
    memw();
    if (MEDIUS_HOST_CONTROL_PORT == 0 || MEDIUS_HOST_CAPTURE_READY == 0) return;
    memw();
    if (MEDIUS_HOST_FORWARDING_INHIBIT == 0) medius_clone_publish();
    else {
        memw(); MEDIUS_HOST_CLONE_PUBLICATION_PENDING = 1;
    }
}
