/* Medius v3.4.7 device — served clone descriptor construction/policy. */
#include "../include/types.h"

/* Descriptor-builder reconstruction utilities: inline phases of the single
 * native entry below, not additional firmware functions. Shared loads/stores
 * keep their native widths/order. Required inputs/counts/pools remain unchecked.
 */
static __attribute__((always_inline)) inline unsigned int clone_build_intervals(
    unsigned int total,unsigned int selector,unsigned char *edited)
{
    *edited = 0;
    if (selector == 0 || total < 2U)
        return 0;
    const volatile unsigned char *bytes = MEDIUS_CLONE_CONFIGURATION_BYTES;
    unsigned int cursor = 0;
    do {
        unsigned int length = bytes[cursor];
        unsigned int end = cursor + length;
        if (length < 2U || end > total)
            return 0xffffffffU;
        cursor = (unsigned short)end;
    } while (cursor + 1U < total);
    cursor = 0;
    unsigned int changes = 0;
    int hid = 0;
    do {
        unsigned int length = bytes[cursor];
        unsigned int type = bytes[cursor + 1U];
        if (length < 2U || cursor + length > total)
            break;
        if (type == 4) {
            hid = 0;
            if (length >= 9U)
                hid = bytes[cursor + 5U] == 3;
        } else if (type == 2) {
            hid = 0;
        } else if (type == 5 && length >= 7U && hid) {
            unsigned int endpoint = bytes[cursor + 2U];
            if ((endpoint & 0x7fU) != 0) {
                unsigned int attributes = bytes[cursor + 3U];
                if ((attributes & 3U) == 3U && (endpoint & 0x80U) != 0) {
                    volatile unsigned char *interval = MEDIUS_CLONE_CONFIGURATION_BYTES + cursor + 6U;
                    if (*interval != selector) {
                        *interval = (unsigned char)selector;
                        changes = (unsigned short)(changes + 1U);
                    }
                }
            }
        }
        cursor = (unsigned short)(cursor + length);
    } while (cursor + 1U < total);
    *edited = changes != 0;
    return changes;
}

static __attribute__((always_inline)) inline char *clone_build_apply_patches(
    volatile MediusCloneSource *source,int bos_present,unsigned int *configuration_count)
{
    unsigned char original_headers[16];
    unsigned int configurations = *configuration_count;
    if (configurations != 0) {
        unsigned int index = 0;
        do {
            unsigned int offset = MEDIUS_CLONE_CONFIGURATION_OFFSETS_RW[index];
            memcpy(original_headers + (unsigned short)index * 4U,
                MEDIUS_CLONE_CONFIGURATION_BYTES + offset,4);
            ++index;
            configurations = MEDIUS_CLONE_CONFIGURATION_COUNT;
        } while ((unsigned char)index < configurations);
    }
    const volatile DescriptorPatchTable *patches = DESCRIPTOR_PATCH_SERVED;
    unsigned int device_length = MEDIUS_CLONE_DEVICE_LENGTH;
    if (patches->count != 0) {
        unsigned char index = 0;
        const volatile DescriptorPatchRecord *patch = patches->records;
        do {
            if (patch->kind == 0) {
                unsigned int offset = patch->offset;
                unsigned int length = patch->length;
                if (offset + length <= device_length) {
                    unsigned int payload_offset = patch->payload_offset;
                    memcpy(MEDIUS_CLONE_DEVICE_BYTES + offset,
                        (const void *)(patches->payload + payload_offset),length);
                }
            }
            index = (unsigned char)(index + 1U);
            unsigned int count = patches->count;
            ++patch;
            if (index >= count)
                break;
        } while (1);
        configurations = MEDIUS_CLONE_CONFIGURATION_COUNT;
    }
    if (configurations != 0) {
        unsigned char configuration = 0;
        do {
            unsigned int patch_count = patches->count;
            unsigned int offset = MEDIUS_CLONE_CONFIGURATION_OFFSETS_RW[configuration];
            unsigned int length = MEDIUS_CLONE_CONFIGURATION_LENGTHS_RW[configuration];
            if (patch_count != 0) {
                unsigned char index = 0;
                const volatile DescriptorPatchRecord *patch = patches->records;
                do {
                    if (patch->kind == 1 && patch->configuration == configuration) {
                        unsigned int patch_offset = patch->offset;
                        unsigned int patch_length = patch->length;
                        if (patch_offset + patch_length <= length) {
                            unsigned int payload_offset = patch->payload_offset;
                            memcpy(MEDIUS_CLONE_CONFIGURATION_BYTES + offset + patch_offset,
                                (const void *)(patches->payload + payload_offset),patch_length);
                        }
                    }
                    index = (unsigned char)(index + 1U);
                    unsigned int count = patches->count;
                    ++patch;
                    if (index >= count)
                        break;
                } while (1);
            }
            configuration = (unsigned char)(configuration + 1U);
            unsigned int current_count = MEDIUS_CLONE_CONFIGURATION_COUNT;
            if (configuration >= current_count)
                break;
        } while (1);
    }
    if (bos_present) {
        unsigned int length = source->section_7_length;
        if (patches->count != 0) {
            unsigned char index = 0;
            const volatile DescriptorPatchRecord *patch = patches->records;
            do {
                if (patch->kind == 4) {
                    unsigned int offset = patch->offset;
                    unsigned int patch_length = patch->length;
                    if (offset + patch_length <= length) {
                        unsigned int payload_offset = patch->payload_offset;
                        memcpy(MEDIUS_CLONE_BOS_BYTES + offset,
                            (const void *)(patches->payload + payload_offset),patch_length);
                    }
                }
                index = (unsigned char)(index + 1U);
                unsigned int count = patches->count;
                ++patch;
                if (index >= count)
                    break;
            } while (1);
        }
    }
    const volatile unsigned char *device = MEDIUS_CLONE_DEVICE_BYTES;
    if (MEDIUS_CLONE_DEVICE_LENGTH >= 2U) {
        const volatile unsigned char *original = source->device;
        unsigned int actual = device[0];
        unsigned int expected = original[0];
        if (actual != expected)
            return "a descriptor's length or type field was patched";
        expected = original[1];
        actual = device[1];
        if (actual != expected)
            return "a descriptor's length or type field was patched";
    }
    configurations = MEDIUS_CLONE_CONFIGURATION_COUNT;
    for (unsigned int index = 0; index < configurations; ++index) {
        unsigned int length = MEDIUS_CLONE_CONFIGURATION_LENGTHS_RW[index];
        if (length >= 4U) {
            unsigned int offset = MEDIUS_CLONE_CONFIGURATION_OFFSETS_RW[index];
            const volatile unsigned char *bytes = MEDIUS_CLONE_CONFIGURATION_BYTES + offset;
            if (bytes[0] != original_headers[index * 4U] ||
                    bytes[1] != original_headers[index * 4U + 1U] ||
                    bytes[2] != original_headers[index * 4U + 2U] ||
                    bytes[3] != original_headers[index * 4U + 3U])
                return "a descriptor's length or type field was patched";
        }
    }
    if (bos_present) {
        unsigned int length = source->section_7_length;
        const unsigned char *original = source->section_7;
        if (memcmp(MEDIUS_CLONE_BOS_BYTES,original,length < 4U ? length : 4U) != 0)
            return "a descriptor's length or type field was patched";
    }
    *configuration_count = configurations;
    return NULL;
}

static __attribute__((always_inline)) inline void clone_build_import_reports(
    const volatile unsigned char *input,unsigned int input_length,unsigned int selected)
{
    if (input == NULL || input_length == 0 || selected == 255U)
        return;
    unsigned int count = input[0];
    if (count != 0) {
        unsigned int cursor = 1;
        unsigned char index = 0;
        do {
            unsigned int header_end = cursor + 3U;
            index = (unsigned char)(index + 1U);
            if (header_end > input_length)
                return;
            unsigned int high = input[cursor + 2U];
            unsigned int low = input[cursor + 1U];
            cursor = (unsigned short)(header_end + ((high << 8) | low));
            if (cursor > input_length)
                return;
        } while (index != count);
    }
    volatile MediusReportArchive *archive = MEDIUS_REPORT_ARCHIVE;
    unsigned int used = archive->used;
    if (used >= 4U) {
        unsigned int cursor = 0;
        do {
            unsigned char *base = archive->data;
            const volatile unsigned char *record = base + cursor;
            unsigned int high = record[3];
            unsigned int low = record[2];
            unsigned int length = (high << 8) | low;
            unsigned int end = cursor + (unsigned short)(length + 4U);
            if (end > used) {
                archive->used = (unsigned short)cursor;
                break;
            }
            unsigned int next = (unsigned short)end;
            if (record[0] == selected) {
                if (next > used) {
                    archive->used = (unsigned short)cursor;
                    used = cursor;
                } else {
                    memmove(base + cursor,base + next,used - next);
                    used = (unsigned short)(archive->used - 4U - length);
                    archive->used = (unsigned short)used;
                }
            } else {
                used = archive->used;
                cursor = next;
            }
        } while (cursor + 3U < used);
    }
    if (count == 0)
        return;
    unsigned int cursor = 1;
    unsigned char index = 0;
    do {
        unsigned int high = input[cursor + 2U];
        unsigned int low = input[cursor + 1U];
        unsigned int length = (high << 8) | low;
        unsigned int interface_number = input[cursor];
        unsigned char *payload = medius_report_archive_reserve(selected,interface_number,length,selected);
        cursor = (unsigned short)(cursor + 3U);
        if (payload != NULL) {
            memcpy(payload,(const void *)(input + cursor),length);
            unsigned char *base = archive->data;
            if ((unsigned int)payload >= (unsigned int)base + 4U) {
                unsigned int current_used = archive->used;
                if ((unsigned int)payload <= (unsigned int)base + current_used)
                    *(volatile unsigned char *)(payload - 4) = (unsigned char)selected;
            }
        }
        index = (unsigned char)(index + 1U);
        cursor = (unsigned short)(cursor + length);
    } while (index != count);
}

static __attribute__((always_inline)) inline char *clone_build_acceptance(
    volatile unsigned char *imperfect,int *interface_count_out)
{
    if (MEDIUS_CLONE_ENDPOINT_INDEX_EXCEEDED != 0)
        return "config has an endpoint index >6 (S3 OTG has only EP0..6)";
    if (MEDIUS_CLONE_PACKET_SIZE_EXCEEDED != 0)
        return "config has an endpoint wMaxPacketSize >64 (FS/dwc2 limit)";
    if (MEDIUS_CLONE_OUT_ENDPOINT_CONFLICT != 0)
        return "config has an unsupported OUT endpoint (duplicate/over-cap)";
    if (MEDIUS_CLONE_BAD_CONFIGURATION_CHAIN != 0)
        return "config descriptor does not parse as a clean chain (truncated or bad bLength)";
    if (MEDIUS_CLONE_SERVED_AUXILIARY->conflict != 0)
        return "non-HID interface has an unrelayable endpoint (control/duplicate/over-cap)";
    unsigned int allow = IMPERFECT_FORWARDING_ALLOWED;
    unsigned int configurations_missing = MEDIUS_CLONE_CONFIGURATIONS_MISSING;
    *imperfect = (unsigned char)(allow ^ 1U);
    if (configurations_missing != 0 && IMPERFECT_FORWARDING_ALLOWED == 0) {
        unsigned int captured = MEDIUS_CLONE_CONFIGURATION_COUNT;
        unsigned int declared = MEDIUS_CLONE_DECLARED_CONFIGURATIONS;
        newlib_snprintf(MEDIUS_CLONE_ERROR_BUFFER,192,
            "device declares %u configurations but only %u were captured",declared,captured);
        return MEDIUS_CLONE_ERROR_BUFFER;
    }
    if (MEDIUS_CLONE_SERVED_AUXILIARY->has_bulk != 0 && IMPERFECT_FORWARDING_ALLOWED == 0)
        return "vendor bulk endpoint (relays below native throughput)";
    if ((MEDIUS_CLONE_HID_ISOCHRONOUS != 0 || MEDIUS_CLONE_SERVED_AUXILIARY->has_isochronous != 0) &&
            IMPERFECT_FORWARDING_ALLOWED == 0)
        return "isochronous endpoint (presented but never fed)";
    if (MEDIUS_CLONE_REPORT_CAPTURE_EXCEEDED != 0 && IMPERFECT_FORWARDING_ALLOWED == 0) {
        newlib_snprintf(MEDIUS_CLONE_ERROR_BUFFER,192,
            "report descriptor larger than the %u-byte capture cap",2048U);
        return MEDIUS_CLONE_ERROR_BUFFER;
    }
    if (MEDIUS_CLONE_HIGH_SPEED != 0) {
        if (IMPERFECT_FORWARDING_ALLOWED == 0)
            return "high-speed device on a full/low-speed PHY";
        goto missing_after_capacity;
    }
    if (MEDIUS_CLONE_OVER_CAPACITY != 0) {
        if (IMPERFECT_FORWARDING_ALLOWED == 0) {
            newlib_snprintf(MEDIUS_CLONE_ERROR_BUFFER,192,
                "over-capacity device (more than %d IN endpoints live at once, or more than %d HID interfaces, in any configuration it offers)",4,6);
            return MEDIUS_CLONE_ERROR_BUFFER;
        }
        goto missing_after_capacity;
    }
    if (MEDIUS_CLONE_REPORT_MISSING != 0) {
        if (IMPERFECT_FORWARDING_ALLOWED == 0)
            return "a configuration this device offers has a HID interface whose report descriptor was never captured";
        goto accepted;
    }
    goto extra_endpoints;
missing_after_capacity:
    if (MEDIUS_CLONE_REPORT_MISSING != 0)
        goto accepted;
extra_endpoints:
    {
        const volatile unsigned char *extra = MEDIUS_CLONE_EXCESS_ENDPOINT_INFO;
        if (extra[0] != 0 && IMPERFECT_FORWARDING_ALLOWED == 0) {
            unsigned int endpoint_count = extra[2];
            unsigned int interface_number = extra[1];
            newlib_snprintf(MEDIUS_CLONE_ERROR_BUFFER,192,
                "interface %u carries %u endpoint descriptors, more than it declares",
                interface_number,endpoint_count);
            return MEDIUS_CLONE_ERROR_BUFFER;
        }
    }
accepted:
    *imperfect = 0;
    unsigned int degradation = clone_degradation_status();
    int interface_count = USB_INTERFACE_COUNT;
    MEDIUS_CLONE_DEGRADED = (unsigned char)degradation;
    *interface_count_out = interface_count;
    if (interface_count > 0) {
        for (unsigned int index = 0; index < (unsigned int)interface_count; ++index) {
            unsigned int length = USB_INTERFACE_REPORT_LENGTHS[index];
            if (length == 0 && REPORT_BUFFER_ENABLED[index] == 0) {
                unsigned int interface_number = REPORT_CAPTURE_INTERFACE_IDS[index];
                newlib_snprintf(MEDIUS_CLONE_ERROR_BUFFER,192,
                    "intf %u missing report-desc",interface_number);
                return MEDIUS_CLONE_ERROR_BUFFER;
            }
        }
    }
    return NULL;
}

static __attribute__((always_inline)) inline unsigned char clone_build_problem_bits(
    int bos_present,int interface_count)
{
    unsigned int problems = 0;
    if (MEDIUS_CLONE_DEVICE_LENGTH >= 4U) {
        unsigned int bcd_usb = *(const volatile unsigned short *)(MEDIUS_CLONE_DEVICE_BYTES + 2);
        problems = bcd_usb > 0x200U && !bos_present;
    }
    unsigned int configurations = MEDIUS_CLONE_CONFIGURATION_COUNT;
    if (configurations != 0) {
        unsigned int selected = MEDIUS_CLONE_CONFIGURATION_INDEX;
        unsigned int archive_used = MEDIUS_REPORT_ARCHIVE->used;
        const volatile unsigned char *archive = MEDIUS_REPORT_ARCHIVE->data;
        unsigned char configuration = 0;
        do {
            unsigned int offset = MEDIUS_CLONE_CONFIGURATION_OFFSETS_RW[configuration];
            unsigned int total = MEDIUS_CLONE_CONFIGURATION_LENGTHS_RW[configuration];
            const volatile unsigned char *bytes = MEDIUS_CLONE_CONFIGURATION_BYTES + offset;
            if (total >= 2U) {
                unsigned int cursor = 0;
                unsigned int current_interface = 0;
                unsigned int mapped = 0xffffffffU;
                do {
                    const volatile unsigned char *descriptor = bytes + cursor;
                    unsigned int length = descriptor[0];
                    unsigned int type = descriptor[1];
                    if (length < 2U || cursor + length > total)
                        break;
                    if (type == 4 && length >= 9U) {
                        current_interface = descriptor[2];
                        mapped = 0xffffffffU;
                        if (selected == configuration && interface_count > 0) {
                            for (unsigned int index = 0; index < (unsigned int)interface_count; ++index) {
                                if (REPORT_CAPTURE_INTERFACE_IDS[index] == current_interface) {
                                    mapped = index;
                                    break;
                                }
                            }
                        }
                    } else if (type == 0x21U && length >= 9U) {
                        if (archive_used >= 4U) {
                            unsigned int record_offset = 0;
                            do {
                                const volatile unsigned char *record = archive + record_offset;
                                unsigned int high = record[3];
                                unsigned int low = record[2];
                                unsigned int stride = (unsigned short)(((high << 8) | low) + 4U);
                                unsigned int end = record_offset + stride;
                                if (end > archive_used)
                                    break;
                                if (record[0] == configuration && record[1] == current_interface) {
                                    high = record[3];
                                    low = record[2];
                                    unsigned int report_length = (high << 8) | low;
                                    if (report_length != 0 && descriptor[1] == 0x21U) {
                                        unsigned int count = descriptor[5];
                                        if (count != 0) {
                                            unsigned int triplet = 0;
                                            do {
                                                if (triplet + 9U > length)
                                                    break;
                                                if (descriptor[triplet + 6U] == 0x22U) {
                                                    unsigned int report_high = descriptor[triplet + 8U];
                                                    unsigned int report_low = descriptor[triplet + 7U];
                                                    if (report_length != ((report_high << 8) | report_low))
                                                        problems |= 2U;
                                                    break;
                                                }
                                                triplet += 3U;
                                            } while (triplet != count * 3U);
                                        }
                                    }
                                    break;
                                }
                                record_offset = (unsigned short)end;
                            } while (record_offset + 3U < archive_used);
                        }
                    } else if (type == 5 && length >= 7U && mapped != 0xffffffffU &&
                            selected == configuration) {
                        unsigned int endpoint = descriptor[2];
                        if ((endpoint & 0x80U) != 0) {
                            unsigned int attributes = descriptor[3];
                            if ((attributes & 3U) == 3U) {
                                unsigned int high = descriptor[5];
                                unsigned int low = descriptor[4];
                                unsigned int report_length = MEDIUS_CLONE_PRIMARY_REPORT_WIRE_LENGTH(mapped);
                                if ((((high << 8) | low) & 0x7ffU) < report_length)
                                    problems |= 4U;
                            }
                        }
                    }
                    cursor = (unsigned short)(cursor + length);
                } while (cursor + 1U < total);
            }
            configuration = (unsigned char)(configuration + 1U);
        } while (configuration != configurations);
    }
    return (unsigned char)problems;
}

/* Native entry: 0x42030730. */
/* Original function-byte SHA-256:
 * 148f81d3bcfb542dba7b5d0cf36e331f1a244d37ca2ccd9e30c822bfafab7b57. */
/*
 * Build served descriptor state from a32-byte borrowed source. Cache initial
 * device length/pointer before clearing output BYTEs, copy without local size
 * admission, then reload source lengths for publication. Copy primary config;
 * append section11 only when nonnull/nonempty and the cached sum<=8192. After
 * that copy add fresh global/source lengths modulo16. Old tails remain.
 *
 * Tile at most four configuration records using bLength>=9,type2,total>=9 and
 * widened end<=copied total; require exact exhaustion. Publish captured count
 * after the scan, not during it. Failure restores primary total/count1/offset0/
 * length and marks truncation, retaining copied tails/other table entries.
 * Interval selector0 or total<2 gives result0. Otherwise preflight the complete
 * chain (one trailing byte allowed), then edit only nonzero IN interrupt HID
 * endpoints, comparing interval BYTE against the full selector WORD. Result is
 * wrapping16 edit count, or UINT_MAX on bad preflight; source BOS pointer is
 * sampled before MEMW/edited BYTE and output result WORD publication.
 *
 * Copy admitted BOS section7 length1..256; invalid/missing sections retain old
 * bytes. Nonzero patch mode snapshots each configuration's first4 bytes, applies
 * device/configuration/BOS destination-bounded records with unchecked pool source
 * offsets/live counts, then validates device first2, config first4 and BOS first
 * min(length,4) against their respective originals. Error returns retain writes.
 * Patch mode0 skips both patching and this protected-header validation.
 *
 * Select source configuration index clamped0, publish pointer/length, declared
 * count and missing-config flag; adjust device byte17 even for short copies.
 * Clear alternate table/pending/upload pointer. Import a valid counted report
 * list, preserving its16-bit end-check wrap, selected-config purge/compaction,
 * provisional allocation skips and guarded configuration-byte commits. Most
 * construction precedes optional rewrite mutex acquisition.
 *
 * Parse reports(copy1), refresh HID reports, give current mutex, then evaluate
 * fatal/conditional policy diagnostics in native order. Set imperfect to raw
 * allow XOR1 before soft failures; accepted policy clears it. Publish degradation
 * before checking missing report descriptions. Final problem BYTE has bit1 for
 * USB>2.00 without admitted BOS, bit2 for first HID report-length mismatch, bit4
 * for selected interrupt-IN packet size below report wire length. Patch mode
 * forces degraded1 after publishing problems. Return NULL on acceptance, fixed
 * diagnostic or shared192-byte error buffer otherwise; problem bits alone allow.
 *
 * Inline phase utilities describe this single980-instruction native entry.
 * No rollback, source/null/overlap repair, external mutation protection, mutex
 * take-result enforcement or runtime timing/concurrency guarantee. Unchecked
 * counts can overrun snapshots/tables; zero-stride malformed archives can loop.
 * Parser/HID/formatter implementation reviews remain separate native entries.
 */
char *medius_clone_build_descriptors(MediusCloneSource *input,unsigned int interval_selector,
    int *interval_result,unsigned int patch_mode,unsigned char *imperfect,unsigned char *problem_bits)
{
    volatile MediusCloneSource *source = input;
    unsigned int device_length = source->device_length;
    const unsigned char *device_source = source->device;
    *(volatile unsigned char *)imperfect = 0;
    *(volatile unsigned char *)problem_bits = 0;
    memcpy(MEDIUS_CLONE_DEVICE_BYTES,device_source,device_length);
    unsigned int published_device_length = source->device_length;
    const unsigned char *configuration_source = source->configuration;
    unsigned int configuration_length = source->configuration_length;
    MEDIUS_CLONE_DEVICE_LENGTH = (unsigned short)published_device_length;
    memcpy(MEDIUS_CLONE_CONFIGURATION_BYTES,configuration_source,configuration_length);
    unsigned int total = source->configuration_length;
    const unsigned char *append = source->section_11;
    MEDIUS_CLONE_CONFIGURATION_TOTAL = (unsigned short)total;
    if (append != NULL) {
        unsigned int append_length = source->section_11_length;
        if (append_length != 0 && total + append_length <= 8192U) {
            memcpy(MEDIUS_CLONE_CONFIGURATION_BYTES + total,append,append_length);
            unsigned int current_total = MEDIUS_CLONE_CONFIGURATION_TOTAL;
            unsigned int current_append = source->section_11_length;
            total = (unsigned short)(current_total + current_append);
            MEDIUS_CLONE_CONFIGURATION_TOTAL = (unsigned short)total;
        }
    }
    MEDIUS_CLONE_CONFIGURATION_TRUNCATED = 0;
    MEDIUS_CLONE_CONFIGURATION_COUNT = 0;
    int tiled = 0;
    if (total >= 4U) {
        const volatile unsigned char *bytes = MEDIUS_CLONE_CONFIGURATION_BYTES;
        unsigned int cursor = 0;
        unsigned char captured = 0;
        for (unsigned int index = 0; index < 4U; ++index) {
            if (bytes[cursor] < 9U || bytes[cursor + 1U] != 2U)
                break;
            unsigned int high = bytes[cursor + 3U];
            unsigned int low = bytes[cursor + 2U];
            unsigned int length = (high << 8) | low;
            unsigned int end = cursor + length;
            if (length < 9U || end > total)
                break;
            MEDIUS_CLONE_CONFIGURATION_OFFSETS_RW[index] = (unsigned short)cursor;
            cursor = (unsigned short)end;
            MEDIUS_CLONE_CONFIGURATION_LENGTHS_RW[index] = (unsigned short)length;
            captured = (unsigned char)(captured + 1U);
            if (cursor + 3U >= total)
                break;
        }
        if (captured != 0) {
            MEDIUS_CLONE_CONFIGURATION_COUNT = captured;
            tiled = cursor == total;
        }
    }
    if (!tiled) {
        total = source->configuration_length;
        MEDIUS_CLONE_CONFIGURATION_TOTAL = (unsigned short)total;
        MEDIUS_CLONE_CONFIGURATION_COUNT = 1;
        MEDIUS_CLONE_CONFIGURATION_OFFSETS_RW[0] = 0;
        MEDIUS_CLONE_CONFIGURATION_LENGTHS_RW[0] = (unsigned short)total;
        MEDIUS_CLONE_CONFIGURATION_TRUNCATED = 1;
    }
    unsigned char interval_edited;
    unsigned int interval_changes = clone_build_intervals(total,interval_selector,&interval_edited);
    const unsigned char *bos = source->section_7;
    memw();
    MEDIUS_CLONE_INTERVAL_EDITED_RW = interval_edited;
    *(volatile int *)interval_result = (int)interval_changes;
    int bos_present = 0;
    if (bos != NULL) {
        unsigned int bos_length = source->section_7_length;
        if ((unsigned short)(bos_length - 1U) < 256U) {
            memcpy(MEDIUS_CLONE_BOS_BYTES,bos,bos_length);
            bos_present = 1;
        }
    }
    unsigned int configurations = MEDIUS_CLONE_CONFIGURATION_COUNT;
    if (patch_mode != 0) {
        char *error = clone_build_apply_patches(source,bos_present,&configurations);
        if (error != NULL)
            return error;
    }
    unsigned int selected = source->configuration_index;
    if (selected >= configurations)
        selected = 0;
    unsigned int selected_offset = MEDIUS_CLONE_CONFIGURATION_OFFSETS_RW[selected];
    MEDIUS_CLONE_CONFIGURATION_INDEX = (unsigned char)selected;
    unsigned int selected_length = MEDIUS_CLONE_CONFIGURATION_LENGTHS_RW[selected];
    MEDIUS_CLONE_SELECTED_CONFIGURATION = MEDIUS_CLONE_CONFIGURATION_BYTES + selected_offset;
    unsigned int captured_declared = *(const volatile unsigned char *)(MEDIUS_CLONE_DEVICE_BYTES + 17);
    unsigned int current_device_length = source->device_length;
    MEDIUS_CLONE_SELECTED_LENGTH = (unsigned short)selected_length;
    unsigned int declared = current_device_length >= 18U ? captured_declared : 1U;
    MEDIUS_CLONE_DECLARED_CONFIGURATIONS = (unsigned char)declared;
    MEDIUS_CLONE_CONFIGURATIONS_MISSING = configurations < declared;
    if (configurations != captured_declared)
        *(volatile unsigned char *)(MEDIUS_CLONE_DEVICE_BYTES + 17) = (unsigned char)configurations;
    memset(CLONE_ALTERNATE_SETTINGS,0,256);
    const unsigned char *reports = source->section_2;
    unsigned int reports_length = source->section_2_length;
    memw();
    CLONE_ALTERNATE_PENDING = 0;
    MEDIUS_CLONE_REPORT_ASSEMBLY = NULL;
    selected = MEDIUS_CLONE_CONFIGURATION_INDEX;
    clone_build_import_reports(reports,reports_length,selected);
    unsigned int truncated = MEDIUS_CLONE_CONFIGURATION_TRUNCATED;
    RtosQueue *mutex = REWRITE_MUTEX;
    MEDIUS_CLONE_BAD_CONFIGURATION_CHAIN = (unsigned char)truncated;
    if (mutex != NULL)
        xQueueSemaphoreTake(mutex,0xffffffffU);
    medius_clone_parse_configuration_reports(1);
    hid_refresh_reports();
    mutex = REWRITE_MUTEX;
    if (mutex != NULL)
        xQueueGenericSend(mutex,NULL,0,0);
    int interface_count;
    char *error = clone_build_acceptance(imperfect,&interface_count);
    if (error != NULL)
        return error;
    unsigned char problems = clone_build_problem_bits(bos_present,interface_count);
    *(volatile unsigned char *)problem_bits = problems;
    if (patch_mode != 0)
        MEDIUS_CLONE_DEGRADED = 1;
    return NULL;
}
