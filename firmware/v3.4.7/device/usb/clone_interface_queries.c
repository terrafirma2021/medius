/* Medius v3.4.7 device — interface and HID descriptor presence. */
#include "../include/types.h"

/* Native entry: 0x40396b60. */
/* Original function-byte SHA-256:
 * e474633bf63d8327c056a1c3325da899f448379165ee75988abed7c6709d5c8f. */
/* MEMW/read attachment, then capture configuration length and pointer only
 * when attached and length>=2. Walk with a 16-bit wrapping cursor. Read both
 * length/type bytes before checking length>=2 and full record end<=total.
 * Return true at the first type4/length>=9 descriptor with this low-byte
 * interface number. No active-alternate filter, interface-index clamp, NULL
 * validation, state update, lock or further MEMW. Malformed/end returns false. */
bool medius_clone_interface_exists(unsigned char interface)
{
    memw();
    if (CLONE_ACTIVE == 0) return false;
    unsigned short total = QUERY_CONFIGURATION_LENGTH;
    if (total < 2U) return false;
    const volatile unsigned char *configuration = QUERY_CONFIGURATION;
    unsigned int offset = 0;
    do {
        const volatile unsigned char *descriptor = configuration + offset;
        unsigned char length = descriptor[0];
        unsigned char type = descriptor[1];
        unsigned int end = offset + length;
        if (length < 2U || end > total) return false;
        if (type == 4 && length >= 9U && descriptor[2] == interface) return true;
        offset = (unsigned short)end;
    } while (offset + 1U < total);
    return false;
}

/* Native entry: 0x4037bd28. */
/* Original function-byte SHA-256:
 * 9d78076382bca36f96c2b2196763b6a7ac799df5e28d9186bd465ce32cf786ca. */
/* Same bounded descriptor walk as interface_exists, additionally requiring
 * bAlternateSetting==alternate after matching interface. Both parameters use
 * only their low BYTE. First match returns true; no state is changed and no
 * check is made that the alternate is active or has any endpoint. */
bool medius_clone_interface_alternate_exists(unsigned char interface, unsigned char alternate)
{
    memw();
    if (CLONE_ACTIVE == 0) return false;
    unsigned short total = QUERY_CONFIGURATION_LENGTH;
    if (total < 2U) return false;
    const volatile unsigned char *configuration = QUERY_CONFIGURATION;
    unsigned int offset = 0;
    do {
        const volatile unsigned char *descriptor = configuration + offset;
        unsigned char length = descriptor[0];
        unsigned char type = descriptor[1];
        unsigned int end = offset + length;
        if (length < 2U || end > total) return false;
        if (type == 4 && length >= 9U && descriptor[2] == interface && descriptor[3] == alternate)
            return true;
        offset = (unsigned short)end;
    } while (offset + 1U < total);
    return false;
}

/* Native entry: 0x40399dfc. */
/* Original function-byte SHA-256:
 * 68f0a67b9b5a4ad7fb30803d5d3b7bfbafa8d197b3a6f6492cb0da68b630740a. */
/* MEMW/read attachment and return false when detached. Capture signed logical
 * interface count once; nonpositive returns false. Scan raw interface IDs in
 * order, returning whether the first matching ID's cached report-length
 * HALFWORD is nonzero. Duplicate IDs after that first match are ignored.
 * No descriptor contents/type/length consistency check, count clamp, data
 * pointer read, further MEMW or lock. Does not filter active alternates. */
bool medius_clone_has_report_descriptor(unsigned char interface)
{
    memw();
    if (CLONE_ACTIVE == 0) return false;
    int count = USB_INTERFACE_COUNT;
    for (int i = 0; i < count; ++i) {
        if (REPORT_CAPTURE_INTERFACE_IDS[i] == interface)
            return USB_INTERFACE_REPORT_LENGTHS[i] != 0;
    }
    return false;
}

/* Native entry: 0x40399d0c. */
/* Original function-byte SHA-256:
 * 857266faf03a294dbaf9df5217eeb7988d3fc50fed441b273e20bb7b03c6f3ba. */
/*
 * Query HID descriptor presence for the low BYTE interface. MEMW/read and
 * retain raw attachment; detached returns0. Capture patch count and, if nonzero,
 * current configuration index; any kind1 patch for that configuration skips
 * custom-HID records and proceeds to the live configuration scan. No apply bit,
 * patch interface, descriptor index, payload length or count cap is checked.
 *
 * Otherwise capture current configuration length and custom-HID pointer. With
 * configuration length>=6, capture its pointer and bConfigurationValue even if
 * the custom list is NULL; shorter configurations use value0 for custom lookup.
 * A non-NULL list of >=4 bytes is walked using low16(cursor+4+record.length).
 * First matching configuration/interface returns the captured raw attachment,
 * without reading action byte2 or validating record payload extent. On no
 * custom match, reload the live configuration pointer but retain the earlier
 * length. Patch bypass also loads the pointer BEFORE testing total>=2.
 *
 * Walk live descriptors: length>=2 and end<=total are required before reading
 * type. A type4/length>=9 descriptor changes the remembered interface; a type4
 * shorter than9 leaves it unchanged. Any type0x21 record under the requested
 * remembered interface returns raw attachment, with no HID-specific size check
 * or alternate filter. No lock, allocation, state update or additional MEMW.
 */
unsigned char medius_clone_has_hid_descriptor(unsigned int requested_interface)
{
    unsigned char interface = (unsigned char)requested_interface;
    memw();
    unsigned char attached = CLONE_ACTIVE;
    if (attached == 0) return 0;
    unsigned short total;
    const volatile unsigned char *configuration;
    unsigned char patch_count = DESCRIPTOR_PATCH_SERVED->count;
    if (patch_count != 0) {
        unsigned char configuration_index = MEDIUS_CLONE_CONFIGURATION_INDEX;
        const volatile DescriptorPatchRecord *patches =
            (const volatile DescriptorPatchRecord *)DESCRIPTOR_PATCH_SERVED;
        for (unsigned int i = 0; i < patch_count; ++i) {
            if (patches[i].kind == 1 && patches[i].configuration == configuration_index) {
                total = QUERY_CONFIGURATION_LENGTH;
                goto reload_configuration;
            }
        }
    }
    total = QUERY_CONFIGURATION_LENGTH;
    const volatile unsigned char *custom = MEDIUS_EP0_HID_OVERRIDES->data;
    unsigned char configuration_value;
    unsigned short custom_length;
    if (total >= 6U) {
        configuration = QUERY_CONFIGURATION;
        configuration_value = configuration[5];
        if (custom == NULL) goto scan_configuration;
        custom_length = MEDIUS_EP0_HID_OVERRIDES->length;
        if (custom_length < 4U) goto scan_configuration;
    } else {
        if (custom == NULL) goto reload_configuration;
        custom_length = MEDIUS_EP0_HID_OVERRIDES->length;
        if (custom_length < 4U) goto reload_configuration;
        configuration_value = 0;
    }
    unsigned int custom_offset = 0;
    do {
        const volatile MediusEp0HidOverrideRecord *record =
            (const volatile MediusEp0HidOverrideRecord *)(custom + custom_offset);
        if (record->configuration == configuration_value && record->interface == interface)
            return attached;
        custom_offset = (unsigned short)(custom_offset + 4U + record->length);
    } while (custom_offset + 3U < custom_length);
reload_configuration:
    configuration = QUERY_CONFIGURATION;
    if (total < 2U) return 0;
scan_configuration: ;
    unsigned int offset = 0;
    unsigned int current_interface = 0xffffffffU;
    do {
        const volatile unsigned char *descriptor = configuration + offset;
        unsigned char length = descriptor[0];
        if (length < 2U || offset + length > total) return 0;
        unsigned char type = descriptor[1];
        if (type == 4) {
            if (length >= 9U) current_interface = descriptor[2];
        } else if (type == 0x21 && current_interface == interface) return attached;
        offset = (unsigned short)(offset + length);
    } while (offset + 1U < total);
    return 0;
}
