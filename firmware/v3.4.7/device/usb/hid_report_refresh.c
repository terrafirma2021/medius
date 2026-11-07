/* Medius v3.4.7 device — HID descriptor refresh and Input-length estimation. */
#include "../include/types.h"

/* HID refresh reconstruction utilities: the estimator is inline code inside
 * 0x420289a0, not another native function or the full HID metadata decoder. */
static __attribute__((always_inline)) inline unsigned short hid_estimate_maximum_input_bytes(
    const volatile unsigned char *descriptor, unsigned int length)
{
    volatile MediusHidInputEstimateScratch scratch;
    for (unsigned int index = 0; index != 16; ++index)
        scratch.bits[index] = 0;
    for (unsigned int index = 0; index != 4; ++index)
        scratch.id_words[index] = 0;
    unsigned int id_count = 1; /* ID0 already occupies the first map entry. */
    unsigned int report_size = 0;
    unsigned int report_count = 0;
    unsigned int current_id = 0;
    unsigned int has_report_id = 0;
    unsigned int cursor = 0;
    while (cursor < length) {
        const volatile unsigned char *item = descriptor + cursor;
        unsigned int prefix = item[0];
        if (prefix == 0xfe) {
            if (cursor + 2U >= length)
                return 0;
            unsigned int payload_length = item[1];
            unsigned int end = cursor + 3U + payload_length;
            if (length < end)
                return 0;
            cursor = (unsigned short)end;
            continue; /* The long-item tag and payload are not interpreted. */
        }
        unsigned int width = prefix & 3U;
        unsigned int type = (prefix >> 2) & 3U;
        unsigned int tag = prefix >> 4;
        if (width == 3)
            width = 4;
        if (length < cursor + 1U + width)
            return 0;
        unsigned int value = 0;
        for (unsigned int byte = 0; byte < width; ++byte)
            value |= (unsigned int)item[byte + 1U] << (byte * 8U);
        cursor = (unsigned short)((unsigned short)(cursor + 1U) + width);
        if (type == 1) { /* Global items: no signed decoding or stack support. */
            if (tag == 7)
                report_size = value;
            else if (tag == 9)
                report_count = value;
            else if (tag == 8) {
                current_id = (unsigned char)value;
                has_report_id = 1;
            } else if (tag == 10 || tag == 11) {
                return 0; /* Push and Pop fail the whole estimate. */
            }
        } else if (type == 0 && tag == 8) { /* Main Input, including constants. */
            unsigned int slot = 0;
            while (slot != id_count && scratch.ids[slot] != current_id)
                ++slot;
            if (slot == id_count) {
                if (id_count == 16)
                    return 0;
                scratch.ids[id_count] = (unsigned char)current_id;
                scratch.bits[id_count] = 0;
                id_count = (unsigned char)(id_count + 1U);
            }
            unsigned long long product = (unsigned long long)report_size * report_count;
            if ((unsigned int)(product >> 32) != 0 || (unsigned int)product > 8192)
                return 0;
            unsigned int accumulated = scratch.bits[slot] + (unsigned int)product;
            scratch.bits[slot] = accumulated;
            if (accumulated > 8192)
                return 0;
        }
    }
    unsigned int maximum_bits = 0;
    for (unsigned int slot = 0; slot != id_count; ++slot) {
        unsigned int bits = scratch.bits[slot];
        if (maximum_bits < bits)
            maximum_bits = bits;
    }
    if (maximum_bits == 0)
        return 0;
    unsigned int bytes = ((maximum_bits + 7U) >> 3) + has_report_id;
    return bytes <= 65535 ? (unsigned short)bytes : 0;
}

/* Native entry: 0x420289a0. */
/* Original function-byte SHA-256:
 * 77c54027cada7da51ca9dc8179974d545180d7787a1abdfde9e57a00a36600b5. */
/* Refresh HID metadata and publish maximum Input-report lengths. Return no
 * value. First sample the signed interface count; while positive, call the
 * separate metadata decoder for each interface. Descriptor/length indices use
 * low16(index), metadata advances304 bytes using the full wrapping WORD index.
 * Reload count after every decoder call, before increment/comparison. There is
 * no six-interface cap in this first pass, no 2048-byte descriptor-span cap and
 * no decoder-status check. The LAST count read is reused for the second pass;
 * do not add a fresh read between decoding and estimating.
 *
 * Estimate exactly six slots against that saved count. For an active slot read
 * its descriptor length HALFWORD once; parse the advertised span with the inline
 * estimator. Long items are skipped after bounds checks. Short items have0/1/2/4
 * unsigned little-endian data bytes. Only Global Size/Count/ID and Main Input
 * affect the estimate; Push/Pop fail it. ID0 starts reserved, up to15 other IDs
 * can be added. Every ID item adds one eventual ID byte, even ID0/zero-sized ID.
 * All Input bits count, including constants; Output/Feature items do not. Reject
 * truncated items, a full new-ID map, unsigned64 product overflow or product /
 * accumulated per-ID bits>8192. These failures and empty reports all estimate0.
 * Otherwise use ceil(maximum accumulated bits/8)+has_ID, retaining the native
 * final<=65535 guard (locally bounded to1025). Publish each result as HALFWORD
 * first to the comparison-length table, then to its960-byte queue record.
 *
 * Finally visit six metadata records: clear304 bytes if slot>=signed count or
 * endpoint BYTE==0. Slot0 uses the saved count; slots1..5 reload it after the
 * previous slot, including any memset call. Active mapped metadata is retained
 * even when its estimate failed. Fixed loops replace spurious Ghidra PS tests.
 * No lock, notification, allocation, capacity repair, rollback or error return;
 * shared descriptor/count/endpoint changes are not made coherent here. The
 * metadata decoder is a separately queued native-body review.
 */
void hid_refresh_reports(void)
{
    int count = USB_INTERFACE_COUNT;
    if (count > 0) {
        unsigned int interface = 0;
        do {
            unsigned int descriptor_index = (unsigned short)interface;
            unsigned int length = MEDIUS_HID_REPORT_DESCRIPTOR_LENGTHS[descriptor_index];
            const unsigned char *descriptor = (const unsigned char *)(uintptr_t)
                ((unsigned int)(uintptr_t)MEDIUS_HID_REPORT_DESCRIPTOR_BYTES +
                 descriptor_index * 2048U);
            HidReportLayout *layout = (HidReportLayout *)(uintptr_t)
                ((unsigned int)(uintptr_t)HID_REPORT_LAYOUTS + interface * 304U);
            (void)medius_hid_decode_report_metadata_boundary(descriptor, (unsigned short)length, layout);
            count = USB_INTERFACE_COUNT;
            ++interface;
        } while ((int)interface < count);
    }
    int estimated_count = count;
    for (unsigned int interface = 0; interface != 6; ++interface) {
        unsigned short maximum_length = 0;
        if ((int)interface < estimated_count) {
            unsigned int length = MEDIUS_HID_REPORT_DESCRIPTOR_LENGTHS[interface];
            maximum_length = hid_estimate_maximum_input_bytes(
                MEDIUS_HID_REPORT_DESCRIPTOR_BYTES + interface * 2048U, length);
        }
        MEDIUS_REPORT_COMPARISON_LIMITS_WRITABLE[interface] = maximum_length;
        REPORT_INTERFACE_QUEUES_WRITABLE[interface].comparison_limit = maximum_length;
    }
    for (unsigned int interface = 0; interface != 6; ++interface) {
        if ((int)interface >= count || USB_INTERFACE_ENDPOINTS[interface] == 0)
            memset(&HID_REPORT_LAYOUTS[interface], 0, 304);
        if (interface != 5)
            count = USB_INTERFACE_COUNT;
    }
}
