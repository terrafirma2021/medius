/* Medius v3.4.7 device — configuration, report and endpoint reconstruction. */
#include "../include/types.h"

/* Configuration-parser reconstruction utilities: inline phases of the single
 * native entry below. Workspace grouping supplies readable names; it does not
 * assert the original source's stack objects or add native function entries. */
typedef struct CloneParserSelection {
    unsigned short primary_packet[6],alternate_mask[6],out_packet[4];
    unsigned char primary_address[6],out_address[4];
    unsigned int interface_count,out_count;
} CloneParserSelection;

static __attribute__((always_inline)) inline void parser_preflight_capacity(unsigned int count)
{
    bool exceeded = false;
    for (unsigned int configuration = 0; configuration != count; ++configuration) {
        unsigned int offset = MEDIUS_CLONE_CONFIGURATION_OFFSETS[configuration];
        unsigned int length = MEDIUS_CLONE_CONFIGURATION_LENGTHS[configuration];
        const volatile unsigned char *bytes = MEDIUS_CLONE_CONFIGURATION_POOL + offset;
        unsigned char maximum[16] = {0};
        unsigned int cursor = 0;
        unsigned int interface = 0xffffffffU;
        unsigned int endpoints = 0;
        if (length >= 2) {
            do {
                unsigned int size = bytes[cursor];
                if (size < 2 || cursor + size > length)
                    break;
                unsigned int type = bytes[cursor + 1U];
                if (type == 4 && size >= 9) {
                    if (interface != 0xffffffffU && maximum[interface] < endpoints)
                        maximum[interface] = (unsigned char)endpoints;
                    interface = bytes[cursor + 2U];
                    endpoints = 0;
                    if (interface > 15)
                        interface = 0xffffffffU;
                } else if (type == 5 && size >= 7 && interface != 0xffffffffU) {
                    unsigned int address = bytes[cursor + 2U];
                    if ((address & 0x80U) != 0 || (bytes[cursor + 3U] & 3U) == 0)
                        endpoints = (unsigned char)(endpoints + 1U);
                }
                cursor = (unsigned short)(cursor + size);
            } while (cursor + 2U <= length);
            if (interface != 0xffffffffU && maximum[interface] < endpoints)
                maximum[interface] = (unsigned char)endpoints;
        }
        unsigned int sum = 0;
        for (unsigned int index = 0; index != 16; ++index)
            sum = (unsigned char)(sum + maximum[index]);
        exceeded |= sum > 4;
    }
    if (exceeded)
        MEDIUS_CLONE_OVER_CAPACITY = 1;
}

static __attribute__((always_inline)) inline void parser_load_report(
    unsigned int slot, unsigned int configuration, unsigned int interface)
{
    configuration = (unsigned char)configuration;
    if (configuration == 255)
        goto missing;
    unsigned int used = MEDIUS_REPORT_ARCHIVE->used;
    if (used < 4)
        goto missing;
    const volatile unsigned char *base = MEDIUS_REPORT_ARCHIVE->data;
    unsigned int cursor = 0;
    do {
        const volatile unsigned char *record = base + cursor;
        unsigned int high = record[3];
        unsigned int low = record[2];
        unsigned int next = cursor + (unsigned short)(((high << 8) | low) + 4U);
        unsigned int narrowed_next = (unsigned short)next;
        if (next > used)
            goto missing;
        if (record[0] == configuration && record[1] == interface) {
            /* Match rereads length, rather than reusing the stride's bytes. */
            high = record[3];
            low = record[2];
            unsigned int length = (high << 8) | low;
            if (length > 2048)
                goto missing;
            unsigned char *destination = REPORT_BUFFER_STORAGE + slot * 2048U;
            memcpy(destination, (const void *)(record + 4), length);
            const volatile DescriptorPatchTable *patches = DESCRIPTOR_PATCH_SERVED;
            unsigned int count = patches->count;
            MEDIUS_CLONE_HID_REPORT_LENGTHS[slot] = (unsigned short)length;
            MEDIUS_CLONE_HID_REPORT_EMPTY[slot] = length == 0;
            if (count != 0) {
                unsigned int index = 0;
                const volatile DescriptorPatchRecord *patch = (const volatile void *)patches;
                do {
                    if (patch->kind == 2 && patch->configuration == configuration &&
                        patch->descriptor_index == interface) {
                        unsigned int offset = patch->offset;
                        unsigned int bytes = patch->length;
                        if (offset + bytes <= length) {
                            unsigned int source_offset = patch->payload_offset;
                            memcpy(destination + offset, (const void *)((unsigned int)patches + 160U + source_offset), bytes);
                        }
                    }
                    index = (unsigned char)(index + 1U);
                    count = patches->count;
                    patch = (const volatile void *)((unsigned int)patch + 10U);
                } while (index < count);
            }
            return;
        }
        cursor = narrowed_next;
    } while (cursor + 3U < used);
missing:
    MEDIUS_CLONE_HID_REPORT_LENGTHS[slot] = 0;
    MEDIUS_CLONE_HID_REPORT_EMPTY[slot] = 0;
}

/* All-alternate policy: suppress exact noncontrol duplicates and the conflict
 * introduced solely by sharing a low7 number across control/noncontrol views.
 * The collector still runs in the sharing case; restore only its conflict BYTE. */
static __attribute__((always_inline)) inline void parser_collect_union(
    unsigned int address, unsigned int attributes, unsigned int packet)
{
    volatile MediusCloneAuxEndpointState *state = MEDIUS_CLONE_ALL_ALTERNATE_AUXILIARY;
    unsigned int type = attributes & 3U;
    unsigned int number = address & 0x7fU;
    bool sharing = false;
    if (type == 2 || type == 3) {
        int count = state->endpoint_count;
        for (int index = 0; index < count; ++index) {
            if (*(const volatile unsigned char *)((unsigned int)state + (unsigned int)index * 8U) == address)
                return;
        }
    } else if (number != 0 && type == 0) {
        int count = state->endpoint_count;
        for (int index = 0; index < count; ++index) {
            if (((*(const volatile unsigned char *)((unsigned int)state + (unsigned int)index * 8U) ^ address) & 0x7fU) == 0) {
                sharing = true;
                break;
            }
        }
    }
    if (number != 0 && type != 0) {
        int count = state->control_count;
        if (count > 0) {
            sharing = state->control_endpoint[0] == number;
            if (!sharing && count != 1)
                sharing = state->control_endpoint[1] == number;
        }
    }
    if (sharing) {
        unsigned char conflict = state->conflict;
        medius_clone_collect_aux_endpoint((MediusCloneAuxEndpointState *)state, address, attributes, packet);
        state->conflict = conflict;
    } else {
        medius_clone_collect_aux_endpoint((MediusCloneAuxEndpointState *)state, address, attributes, packet);
    }
}

static __attribute__((always_inline)) inline void parser_assign_channels(
    int count, unsigned int *directions_within_capacity)
{
    volatile MediusCloneAuxEndpointState *active = MEDIUS_CLONE_ACTIVE_AUXILIARY;
    unsigned int inputs = 0, outputs = 0;
    if (count > 0) {
        /* Native loop setup multiplies in32 bits before shifting back; retain
         * its truncation for a corrupted count with nonzero upper three bits. */
        unsigned int iterations = (((unsigned int)count * 8U - 8U) >> 3) + 1U;
        for (unsigned int index = 0; index != iterations; ++index) {
            volatile MediusCloneAuxEndpoint *record = (volatile void *)
                ((unsigned int)active + index * 8U);
            unsigned int address = record->address;
            record->channel = 255;
            if ((address & 0x80U) != 0)
                inputs = (unsigned char)(inputs + 1U);
            else
                outputs = (unsigned char)(outputs + 1U);
        }
    }
    MEDIUS_CLONE_NEW_CHANNELS = 0;
    unsigned char retained[6] = {0};
    volatile MediusCloneRetainedInBinding *channels = MEDIUS_CLONE_RETAINED_IN_BINDINGS;
    if (count > 0) {
        for (unsigned int index = 0; index != (unsigned int)count; ++index) {
            volatile MediusCloneAuxEndpoint *record = (volatile void *)
                ((unsigned int)active + index * 8U);
            if ((record->address & 0x80U) == 0)
                continue;
            for (unsigned int channel = 0; channel != 6; ++channel) {
                if (retained[channel] != 0)
                    continue;
                unsigned int old_identity = channels[channel].endpoint_descriptor;
                unsigned int identity = record->address_and_type;
                if (old_identity != identity)
                    continue;
                unsigned int old_packet = channels[channel].max_packet;
                unsigned int packet = record->max_packet;
                if (old_packet == packet) {
                    record->channel = (unsigned char)channel;
                    retained[channel] = 1;
                    break;
                }
            }
        }
    }
    *directions_within_capacity = inputs <= 6 && outputs <= 6;
    for (unsigned int channel = 0; channel != 6; ++channel) {
        if (retained[channel] == 0)
            *(volatile unsigned char *)&channels[channel].endpoint_descriptor = 0;
    }
    if (count > 0) {
        unsigned int changed = MEDIUS_CLONE_NEW_CHANNELS;
        bool assigned = false;
        for (unsigned int index = 0; index != (unsigned int)count; ++index) {
            volatile MediusCloneAuxEndpoint *record = (volatile void *)
                ((unsigned int)active + index * 8U);
            unsigned int address = record->address;
            if ((address & 0x80U) == 0 || record->channel != 255)
                continue;
            unsigned int channel = 0;
            while (channel != 6 && *(volatile unsigned char *)&channels[channel].endpoint_descriptor != 0)
                ++channel;
            if (channel == 6)
                break; /* Leave this and all later unassigned IN channels at FF. */
            unsigned int type = record->transfer_type;
            unsigned int packet = record->max_packet;
            channels[channel].endpoint_descriptor = (unsigned short)(address | (type << 8));
            channels[channel].max_packet = (unsigned short)packet;
            record->channel = (unsigned char)channel;
            changed = (unsigned char)(changed | (1U << channel));
            assigned = true;
        }
        if (assigned)
            MEDIUS_CLONE_NEW_CHANNELS = (unsigned char)changed;
    }
}

static __attribute__((always_inline)) inline void parser_build_lookup(
    CloneParserSelection *selection, int auxiliary_count, unsigned short flags,
    unsigned char conflict, signed char lookup[16])
{
    memw();
    signed char previous = CREDIT_ENDPOINT_INTERFACE[0];
    MEDIUS_CLONE_ACTIVE_AUXILIARY->transfer_flags = flags;
    MEDIUS_CLONE_ACTIVE_AUXILIARY->conflict = conflict;
    for (unsigned int endpoint = 0; endpoint != 16; ++endpoint) {
        signed char chosen = -1;
        bool primary = false;
        for (unsigned int slot = 0; slot != selection->interface_count; ++slot) {
            unsigned int address = selection->primary_address[slot];
            if (address != 0 && (address & 15U) == endpoint) {
                chosen = (signed char)slot;
                primary = true;
                break;
            }
        }
        if (!primary) {
            bool auxiliary = false;
            if (endpoint != 0 && auxiliary_count > 0) {
                for (unsigned int index = 0; index != (unsigned int)auxiliary_count; ++index) {
                    unsigned int address = *(const volatile unsigned char *)
                        ((unsigned int)MEDIUS_CLONE_ACTIVE_AUXILIARY + index * 8U);
                    if (address == (0x80U | endpoint)) {
                        auxiliary = true;
                        break;
                    }
                }
            }
            if (auxiliary) {
                chosen = -2;
            } else if (previous >= 0 && (unsigned int)previous < selection->interface_count) {
                chosen = (selection->alternate_mask[(unsigned int)previous] & (1U << endpoint)) != 0 ? previous : -2;
            } else if (previous == -1) {
                for (unsigned int slot = 0; slot != selection->interface_count; ++slot) {
                    if ((selection->alternate_mask[slot] & (1U << endpoint)) != 0) {
                        chosen = (signed char)slot;
                        break;
                    }
                }
            } else {
                chosen = -2;
            }
        }
        lookup[endpoint] = chosen;
        if (endpoint != 15) {
            memw();
            previous = CREDIT_ENDPOINT_INTERFACE[endpoint + 1U];
        }
    }
}

static __attribute__((always_inline)) inline void parser_scan_selected(
    CloneParserSelection *selection, unsigned int copy_reports, unsigned int total)
{
    const volatile unsigned char *bytes = MEDIUS_CLONE_CONFIGURATION_POOL;
    unsigned int configuration = 0xffffffffU;
    bool selected = false;
    bool active_alternate = true; /* Native orphan-endpoint behavior. */
    bool auxiliary_suppressed = false;
    bool first_in_seen = false;
    int hid_slot = -1;
    unsigned int cursor = 0;
    do {
        const volatile unsigned char *descriptor = bytes + cursor;
        unsigned int size = descriptor[0];
        unsigned int type = descriptor[1];
        if (size < 2 || cursor + size > total) {
            MEDIUS_CLONE_BAD_CONFIGURATION_CHAIN = 1;
            break;
        }
        unsigned int next = (unsigned short)(cursor + size);
        if (type == 2) {
            ++configuration;
            selected = MEDIUS_CLONE_CONFIGURATION_INDEX == configuration;
            hid_slot = -1;
            active_alternate = false;
            auxiliary_suppressed = false;
            first_in_seen = false;
        } else if (type == 0x21 && size >= 9) {
            if (hid_slot >= 0 && descriptor[1] == 0x21) {
                unsigned int count = descriptor[5];
                if (count != 0) {
                    unsigned int final_offset = (unsigned char)(count - 1U) * 3U;
                    unsigned int offset = 0;
                    for (;;) {
                        unsigned int entry_type = descriptor[offset + 6U];
                        if (entry_type == 0x22) {
                            unsigned int high = descriptor[offset + 8U];
                            unsigned int low = descriptor[offset + 7U];
                            if (((high << 8) | low) > 2048)
                                MEDIUS_CLONE_REPORT_CAPTURE_EXCEEDED = 1;
                            break;
                        }
                        unsigned int required = offset + 12U;
                        if (offset == final_offset)
                            break;
                        offset += 3;
                        if (size < required)
                            break;
                    }
                }
            }
        } else if (type == 4 && size >= 9) {
            first_in_seen = false;
            auxiliary_suppressed = false;
            if (!selected) {
                hid_slot = -1;
                active_alternate = false;
            } else {
                unsigned int interface = descriptor[2];
                unsigned int alternate = descriptor[3];
                unsigned int active = ((const volatile unsigned char *)CLONE_ALTERNATE_SETTINGS)[interface];
                unsigned int interface_class = descriptor[5];
                active_alternate = alternate == active;
                if (interface_class != 3) {
                    hid_slot = -1;
                } else {
                    unsigned int subclass = descriptor[6];
                    unsigned int protocol = descriptor[7];
                    unsigned int slot = 0;
                    while (slot != selection->interface_count && MEDIUS_CLONE_HID_INTERFACE_IDS[slot] != interface)
                        ++slot;
                    if (slot == selection->interface_count) {
                        if (slot == 6) {
                            MEDIUS_CLONE_OVER_CAPACITY = 1;
                            auxiliary_suppressed = true;
                            hid_slot = -1;
                            goto advance;
                        }
                        MEDIUS_CLONE_HID_INTERFACE_IDS[slot] = (unsigned char)interface;
                        if (copy_reports != 0)
                            parser_load_report(slot, configuration, interface);
                        ++selection->interface_count;
                    }
                    hid_slot = (int)slot;
                    if (active_alternate) {
                        MEDIUS_CLONE_HID_MOUSE_PROTOCOL[slot] = protocol == 2;
                        MEDIUS_CLONE_HID_BOOT_INTERFACES[slot].boot_subclass = subclass == 1;
                        MEDIUS_CLONE_HID_BOOT_INTERFACES[slot].protocol = (unsigned char)protocol;
                    }
                }
            }
        } else if (type == 5 && size >= 7) {
            unsigned int high = descriptor[5];
            unsigned int address = descriptor[2];
            unsigned int low = descriptor[4];
            unsigned int attributes = descriptor[3];
            unsigned int packet = ((high << 8) | low) & 0x7ffU;
            unsigned int number = address & 0x7fU;
            unsigned int transfer_type = attributes & 3U;
            if (number >= 7)
                MEDIUS_CLONE_ENDPOINT_INDEX_EXCEEDED = 1;
            if (packet > 64)
                MEDIUS_CLONE_PACKET_SIZE_EXCEEDED = 1;
            if (hid_slot >= 0) {
                if (number == 0)
                    goto advance;
                if (transfer_type == 1) {
                    MEDIUS_CLONE_HID_ISOCHRONOUS = 1;
                } else if (transfer_type == 3 && (address & 0x80U) != 0 && !first_in_seen) {
                    selection->alternate_mask[hid_slot] |= (unsigned short)(1U << (address & 15U));
                    first_in_seen = true;
                    if (active_alternate) {
                        selection->primary_address[hid_slot] = (unsigned char)address;
                        selection->primary_packet[hid_slot] = (unsigned short)packet;
                    }
                } else if (transfer_type == 3 && (address & 0x80U) == 0) {
                    if (active_alternate) {
                        bool duplicate = false;
                        for (unsigned int index = 0; index != selection->out_count; ++index)
                            duplicate |= selection->out_address[index] == address;
                        if (selection->out_count == 4 || duplicate) {
                            MEDIUS_CLONE_OUT_ENDPOINT_CONFLICT = 1;
                        } else {
                            unsigned int index = selection->out_count;
                            selection->out_address[index] = (unsigned char)address;
                            selection->out_packet[index] = (unsigned short)packet;
                            ++selection->out_count;
                        }
                    }
                } else {
                    if (selected)
                        parser_collect_union(address, attributes, packet);
                    if (active_alternate)
                        medius_clone_collect_aux_endpoint((MediusCloneAuxEndpointState *)MEDIUS_CLONE_ACTIVE_AUXILIARY,
                            address, attributes, packet);
                }
            } else if (!auxiliary_suppressed) {
                if (selected)
                    parser_collect_union(address, attributes, packet);
                if (active_alternate)
                    medius_clone_collect_aux_endpoint((MediusCloneAuxEndpointState *)MEDIUS_CLONE_ACTIVE_AUXILIARY,
                        address, attributes, packet);
            }
        }
advance:
        cursor = next;
        total = MEDIUS_CLONE_CONFIGURATION_TOTAL;
    } while (cursor + 1U < total);
}

/* The native other-configuration collector is inlined. Only address BYTEs,
 * counts and flags are used; record MPS/type/tails remain uninitialized here. */
static __attribute__((always_inline)) inline void parser_other_collect(
    MediusCloneAuxEndpointState *state, unsigned int address, unsigned int type)
{
    unsigned int number = address & 0x7fU;
    if (number == 0)
        return;
    if (type == 1) {
        state->has_isochronous = 1;
        return;
    }
    if (type != 0) {
        int count = state->endpoint_count;
        for (int index = 0; index < count; ++index) {
            if (state->endpoints[index].address == address)
                return; /* Union precheck suppresses an exact duplicate. */
        }
        bool sharing = state->control_count > 0 &&
            (state->control_endpoint[0] == number ||
             (state->control_count != 1 && state->control_endpoint[1] == number));
        if (count == 12 || sharing) {
            if (!sharing)
                state->conflict = 1;
            return;
        }
        state->endpoints[count].address = (unsigned char)address;
        state->endpoint_count = count + 1;
        if (type == 2)
            state->has_bulk = 1;
        return;
    }
    int control_count = state->control_count;
    if (control_count > 0 && (state->control_endpoint[0] == number ||
            (control_count != 1 && state->control_endpoint[1] == number)))
        return;
    bool sharing = false;
    for (int index = 0; index < state->endpoint_count; ++index) {
        if (((state->endpoints[index].address ^ address) & 0x7fU) == 0) {
            sharing = true;
            break;
        }
    }
    if (sharing || control_count == 2) {
        if (!sharing)
            state->conflict = 1;
        return;
    }
    state->control_endpoint[control_count] = (unsigned char)number;
    state->control_count = control_count + 1;
}

static __attribute__((always_inline)) inline bool parser_archive_contains(
    const volatile unsigned char *base, unsigned int used,
    unsigned int configuration, unsigned int interface)
{
    if (used < 4)
        return false;
    unsigned int cursor = 0;
    do {
        const volatile unsigned char *record = base + cursor;
        unsigned int high = record[3];
        unsigned int low = record[2];
        unsigned int next = cursor + (unsigned short)(((high << 8) | low) + 4U);
        if (next > used)
            return false;
        if (record[0] == configuration && record[1] == interface)
            return true; /* Zero or oversized payloads still establish presence. */
        cursor = (unsigned short)next;
    } while (cursor + 3U < used);
    return false;
}

static __attribute__((always_inline)) inline void parser_check_other_configurations(void)
{
    unsigned int count = MEDIUS_CLONE_CONFIGURATION_COUNT;
    if (count == 0)
        return;
    unsigned int selected = MEDIUS_CLONE_CONFIGURATION_INDEX;
    unsigned int used = MEDIUS_REPORT_ARCHIVE->used;
    const volatile unsigned char *archive = MEDIUS_REPORT_ARCHIVE->data;
    bool exceeded = false;
    bool missing = false;
    for (unsigned int configuration = 0; configuration != count;
            configuration = (unsigned char)(configuration + 1U)) {
        if (configuration == selected)
            continue;
        unsigned int offset = MEDIUS_CLONE_CONFIGURATION_OFFSETS[configuration];
        unsigned int length = MEDIUS_CLONE_CONFIGURATION_LENGTHS[configuration];
        const volatile unsigned char *bytes = MEDIUS_CLONE_CONFIGURATION_POOL + offset;
        MediusCloneAuxEndpointState auxiliary;
        auxiliary.endpoint_count = 0;
        auxiliary.control_count = 0;
        auxiliary.has_bulk = 0;
        auxiliary.has_isochronous = 0;
        auxiliary.conflict = 0;
        unsigned char hid_interfaces[7];
        unsigned char out_addresses[5];
        unsigned int hid_count = 0, out_count = 0;
        bool local_excess = false;
        if (length >= 2) {
            bool hid = false;
            bool alternate_zero = false;
            bool first_in_seen = false;
            unsigned int cursor = 0;
            do {
                const volatile unsigned char *descriptor = bytes + cursor;
                unsigned int size = descriptor[0];
                unsigned int type = descriptor[1];
                if (size < 2 || cursor + size > length)
                    break;
                if (type == 4 && size >= 9) {
                    unsigned int alternate = descriptor[3];
                    unsigned int interface_class = descriptor[5];
                    alternate_zero = alternate == 0;
                    first_in_seen = false;
                    hid = interface_class == 3;
                    if (hid) {
                        unsigned int interface = descriptor[2];
                        bool found = false;
                        for (unsigned int index = 0; index != hid_count; ++index)
                            found |= hid_interfaces[index] == interface;
                        if (!found) {
                            if (hid_count == 7)
                                local_excess = true;
                            else
                                hid_interfaces[hid_count++] = (unsigned char)interface;
                        }
                    }
                } else if (type == 5 && size >= 7) {
                    unsigned int address = descriptor[2];
                    unsigned int attributes = descriptor[3];
                    unsigned int transfer_type = attributes & 3U;
                    if (hid) {
                        if ((address & 0x7fU) != 0) {
                            if (transfer_type == 1) {
                                MEDIUS_CLONE_HID_ISOCHRONOUS = 1;
                            } else if (transfer_type == 3 && (address & 0x80U) != 0 && !first_in_seen) {
                                first_in_seen = true;
                            } else if (transfer_type == 3 && (address & 0x80U) == 0) {
                                if (alternate_zero) {
                                    bool duplicate = false;
                                    for (unsigned int index = 0; index != out_count; ++index)
                                        duplicate |= out_addresses[index] == address;
                                    if (duplicate || out_count == 5)
                                        local_excess = true;
                                    else
                                        out_addresses[out_count++] = (unsigned char)address;
                                }
                            } else {
                                parser_other_collect(&auxiliary, address, transfer_type);
                            }
                        }
                    } else {
                        parser_other_collect(&auxiliary, address, transfer_type);
                    }
                }
                cursor = (unsigned short)(cursor + size);
            } while (cursor + 1U < length);
        }
        unsigned int published_iso = MEDIUS_CLONE_SERVED_AUXILIARY->has_isochronous;
        unsigned int published_bulk = MEDIUS_CLONE_SERVED_AUXILIARY->has_bulk;
        MEDIUS_CLONE_SERVED_AUXILIARY->transfer_flags = (unsigned short)
            ((published_bulk | auxiliary.has_bulk) |
             ((published_iso | auxiliary.has_isochronous) << 8));
        exceeded |= local_excess || hid_count > 6 || out_count > 4 || auxiliary.conflict != 0;
        for (unsigned int index = 0; index != hid_count; ++index) {
            if (!parser_archive_contains(archive, used, configuration, hid_interfaces[index]))
                missing = true;
        }
    }
    if (exceeded)
        MEDIUS_CLONE_OVER_CAPACITY = 1;
    if (missing)
        MEDIUS_CLONE_REPORT_MISSING = 1;
}

/* Native entry: 0x4202e958. */
/* Original function-byte SHA-256:
 * 04255c2acb77f0d82904f462b729cd1244f68fd37f08c8998e55184cbc2a2cb2. */
/* Reconstruct selected HID reports, active and all-alternate endpoint views,
 * retained auxiliary IN channels and the16-entry endpoint lookup. Return no
 * value. copy_reports is a full WORD: nonzero imports each newly encountered
 * selected HID interface's first matching archive record and applies kind2
 * patches in order; zero retains its old report bytes/length/empty flag.
 *
 * Reset table counts/flags and listed descriptor diagnostics, retaining record
 * tails, controls, unused HID slots and the previous bad-chain flag. Preflight
 * each initially counted configuration with16 wrapping BYTE maxima, counting
 * IN/control endpoints per interface/alternate; wrapped sum>4 latches capacity.
 * No four-configuration/8192-byte storage cap is enforced. Selected parsing walks
 * the aggregate pool with freshly reloaded total HALFWORD after each descriptor.
 * Length<2/widened end beyond total latches bad-chain and still proceeds to
 * publication; a trailing single BYTE is ignored. Configuration type2 increments
 * a full WORD index and resets eligibility even when the descriptor is short.
 * Full HID interfaces deduplicate six IDs across alternates; seventh distinct
 * ID latches capacity and suppresses auxiliary fallback. Active alternate comes
 * from the256-byte table. Before the first configuration, orphan non-HID
 * endpoints can enter the active auxiliary table.
 *
 * Archive search snapshots used then base anew for each selected HID ID. The
 * stride is low16(length+4), with widened end check before narrowed cursor reuse;
 * length65532 can therefore make an unmatched walk nonprogressing. Configuration
 * FF is rejected. A match rereads HIGH/LOW length; <=2048 copies, publishes length
 * and explicit-empty, then applies matching patches against that saved length.
 * Initial patch count is read before publication; subsequent counts reload after
 * each record. Source offsets/counts remain unchecked; zero-length copies occur.
 * Missing/malformed/oversized matches publish length0,empty0 without clearing old
 * payload. Oversized archive content alone does not latch report-capture excess.
 *
 * Endpoint descriptors flag low7 number>=7 and masked11 packet>64 regardless of
 * selection. Tracked HID ignores number0, flags iso on any alternate, uses the
 * first interrupt-IN per interface descriptor for its mask and active primary,
 * admits at most four active interrupt-OUT addresses, and sends other endpoints
 * through auxiliary policy. HID descriptor triplets flag declared report>2048.
 * The all-alternate auxiliary union suppresses exact duplicates and only the
 * conflict caused by sharing control/noncontrol numbers; active collection uses
 * the separate native collector unchanged, including its raw equality caps.
 *
 * Preserve the first unused old auxiliary IN channel matching identity/MPS.
 * Clear only address BYTEs of unretained channels; assign first empty of six in
 * active-record order, latching changed bits. Exhaustion leaves later channelsFF.
 * More than six wrapped IN/OUT counts forces conflict; otherwise OR union/active
 * conflicts. Lookup prefers active primary HID, then reserves auxiliary IN as-2
 * (except endpoint0), then validates old HID indices against alternate masks.
 * Old-1 can choose the first mask; another invalid old value becomes-2.
 *
 * Under the credit lock copy116-byte active table, clear runtime flags for each
 * freshly read changed bit, clear that mask, copy primary addresses6/MPS12 and
 * lookup16, store interface count WORD, then unlock. Many preceding writes are
 * outside this lock. After unlock snapshot count/selection/archive for all other
 * configurations: track seven HID IDs/five alternate0 OUT addresses and a union
 * with the same duplicate/sharing policy. OR bulk/iso flags into published bytes
 * through a HALFWORD, latch capacity/missing archive records, but do not publish
 * other-configuration conflicts into the active conflict BYTE. Presence alone
 * accepts empty/oversized archive records. Archive nonprogress remains possible.
 * Finally publish degradation low8, HID OUT MPS8/addresses4/count WORD; reconcile
 * an ordered list of HID OUT then auxiliary OUT entries capped at ten, without
 * final deduplication. No pointer/count repair, rollback, helper-status handling,
 * hardware timing, whole-state atomicity or concurrency guarantee is supplied.
 */
void medius_clone_parse_configuration_reports(unsigned int copy_reports)
{
    CloneParserSelection selection = {0};
    volatile MediusCloneAuxEndpointState *active = MEDIUS_CLONE_ACTIVE_AUXILIARY;
    volatile MediusCloneAuxEndpointState *all = MEDIUS_CLONE_ALL_ALTERNATE_AUXILIARY;
    active->endpoint_count = 0;
    active->control_count = 0;
    active->transfer_flags = 0;
    active->conflict = 0;
    MEDIUS_CLONE_ENDPOINT_INDEX_EXCEEDED = 0;
    MEDIUS_CLONE_PACKET_SIZE_EXCEEDED = 0;
    MEDIUS_CLONE_OUT_ENDPOINT_CONFLICT = 0;
    MEDIUS_CLONE_HID_ISOCHRONOUS = 0;
    MEDIUS_CLONE_REPORT_CAPTURE_EXCEEDED = 0;
    unsigned int configuration_count = MEDIUS_CLONE_CONFIGURATION_COUNT;
    MEDIUS_CLONE_REPORT_MISSING = 0;
    MEDIUS_CLONE_OVER_CAPACITY = 0;
    all->endpoint_count = 0;
    all->control_count = 0;
    all->transfer_flags = 0;
    all->conflict = 0;
    parser_preflight_capacity(configuration_count);
    *(volatile unsigned int *)MEDIUS_CLONE_HID_MOUSE_PROTOCOL = 0;
    *(volatile unsigned short *)(MEDIUS_CLONE_HID_MOUSE_PROTOCOL + 4) = 0;
    for (unsigned int slot = 0; slot != 6; ++slot) {
        MEDIUS_CLONE_HID_BOOT_INTERFACES[slot].boot_subclass = 0;
        MEDIUS_CLONE_HID_BOOT_INTERFACES[slot].protocol = 0;
    }
    unsigned int total = MEDIUS_CLONE_CONFIGURATION_TOTAL;
    int auxiliary_count = 0;
    unsigned short transfer_flags = 0;
    unsigned int union_conflict = 0;
    if (total >= 2) {
        parser_scan_selected(&selection, copy_reports, total);
        unsigned int active_bulk = active->has_bulk;
        unsigned int union_iso = all->has_isochronous;
        unsigned int union_bulk = all->has_bulk;
        unsigned int active_iso = active->has_isochronous;
        auxiliary_count = active->endpoint_count;
        union_conflict = all->conflict;
        transfer_flags = (unsigned short)((active_bulk | union_bulk) | ((active_iso | union_iso) << 8));
    }
    unsigned int directions_within_capacity;
    parser_assign_channels(auxiliary_count, &directions_within_capacity);
    unsigned char conflict = 1;
    if (directions_within_capacity != 0)
        conflict = (unsigned char)(union_conflict | active->conflict);
    signed char lookup[16];
    parser_build_lookup(&selection, auxiliary_count, transfer_flags, conflict, lookup);
    xPortEnterCriticalTimeout(&CREDIT_LOCK, -1);
    memcpy((void *)MEDIUS_CLONE_SERVED_AUXILIARY, (const void *)active, 116);
    for (unsigned int slot = 0; slot != 6; ++slot) {
        if ((MEDIUS_CLONE_NEW_CHANNELS & (1U << slot)) != 0)
            medius_interface_clear_runtime_flags(slot);
    }
    MEDIUS_CLONE_NEW_CHANNELS = 0;
    memcpy(MEDIUS_CLONE_PRIMARY_ADDRESSES, selection.primary_address, 6);
    memcpy(MEDIUS_CLONE_PRIMARY_PACKETS, selection.primary_packet, 12);
    memcpy((void *)CREDIT_ENDPOINT_INTERFACE, lookup, 16);
    MEDIUS_CLONE_INTERFACE_COUNT = (int)selection.interface_count;
    vPortExitCritical(&CREDIT_LOCK);
    parser_check_other_configurations();
    MEDIUS_CLONE_DEGRADED = clone_degradation_status();
    memcpy(MEDIUS_CLONE_HID_OUT_PACKETS, selection.out_packet, 8);
    memcpy(MEDIUS_CLONE_HID_OUT_ADDRESSES, selection.out_address, 4);
    unsigned int out_count = selection.out_count;
    MEDIUS_CLONE_HID_OUT_COUNT = (int)out_count;
    unsigned char out_addresses[10];
    unsigned short out_packets[10];
    if (out_count != 0) {
        memcpy(out_addresses, selection.out_address, out_count);
        memcpy(out_packets, selection.out_packet, (unsigned short)out_count * 2U);
    }
    int count = MEDIUS_CLONE_SERVED_AUXILIARY->endpoint_count;
    if (count > 0) {
        for (unsigned int index = 0; index != (unsigned int)count; ++index) {
            const volatile MediusCloneAuxEndpoint *record = (const volatile void *)
                ((unsigned int)MEDIUS_CLONE_SERVED_AUXILIARY + index * 8U);
            unsigned int address = record->address;
            if ((address & 0x80U) == 0) {
                unsigned int packet = record->max_packet;
                out_addresses[out_count] = (unsigned char)address;
                out_packets[out_count] = (unsigned short)packet;
                ++out_count;
                if (out_count == 10)
                    break;
            }
        }
    }
    medius_out_reconcile_endpoints(out_addresses, out_packets, (int)out_count);
}
