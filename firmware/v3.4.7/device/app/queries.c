/* Device information, capabilities, health and descriptor-patch replies. */

#include "../include/types.h"

/* Native entry: 0x42039528. */
/* Original function-byte SHA-256:
 * 663c5b2dbfa1f55b3dd4b703df821ad3800ef99e891808a3352d9dd2c75d61e0. */
/*
 * QUERY(DEVICE_INFO): MEMW then sample the raw clone-active BYTE once. If zero,
 * return0 without touching outputs. Otherwise sample descriptor length once;
 * write bcdUSB/VID/PID/bcdDevice in that order, using HALFWORD reads only at
 * lengths>=4/10/12/14 and zero for missing fields. Then write flags: bit0 is
 * the strings-present BYTE!=0; bit1 is the BOS-presence WORD!=0.
 * Returns the sampled active BYTE unchanged, not a second read or a bool.
 * Outputs must be valid and HALFWORD-aligned where applicable. No lock, null
 * checks or coherent descriptor snapshot; concurrent replacement can mix data.
 */
unsigned char device_info_get(unsigned short *vendor_id,unsigned short *product_id,
    unsigned short *bcd_device,unsigned short *bcd_usb,unsigned char *flags)
{
    memw();
    unsigned char active = CLONE_ACTIVE;
    if (active == 0) return 0;
    unsigned short length = QUERY_DEVICE_LENGTH;
    unsigned short device_revision = 0;
    if (length < 4) {
        *bcd_usb = 0;
        *vendor_id = 0;
        *product_id = 0;
    } else {
        *bcd_usb = QUERY_DEVICE_DESCRIPTOR->bcd_usb;
        if (length < 10) {
            *vendor_id = 0;
            *product_id = 0;
        } else {
            *vendor_id = QUERY_DEVICE_DESCRIPTOR->vendor;
            if (length < 12) {
                *product_id = 0;
            } else {
                *product_id = QUERY_DEVICE_DESCRIPTOR->product;
                if (length >= 14)
                    device_revision = QUERY_DEVICE_DESCRIPTOR->bcd_device;
            }
        }
    }
    *bcd_device = device_revision;
    unsigned char available = QUERY_STRINGS_PRESENT != 0;
    if (QUERY_BOS_PRESENT != 0) available |= 2;
    *flags = available;
    return active;
}

/* Native entry: 0x420395b4. */
/* Original function-byte SHA-256:
 * 5d45ed2cac8492437e8254c280839cd4a09003dd4fb0cef0be5f2cd9abdc2730. */
/*
 * MEMW/read active clone; return0 if absent. Classify at most six parsed report
 * layouts with boot-interface hints. A nonzero result is returned unchanged;
 * only zero triggers configuration-descriptor fallback. The fallback samples
 * its HALFWORD length before its current pointer. No mutex/snapshot/bounds
 * checks beyond those in the two classifiers; no descriptor reparsing here.
 */
unsigned int device_kind_get(void)
{
    memw();
    if (CLONE_ACTIVE == 0) return 0;
    int count = USB_INTERFACE_COUNT;
    unsigned char kind = classify_report_interfaces(HID_REPORT_LAYOUTS,
        QUERY_BOOT_INTERFACES,count);
    if (kind != 0) return kind;
    unsigned short length = QUERY_CONFIGURATION_LENGTH;
    const unsigned char *configuration = QUERY_CONFIGURATION;
    return classify_boot_interfaces(configuration,length);
}

/* Native entry: 0x420395f0. */
/* Original function-byte SHA-256:
 * 422c993458b01cffcce6850c28f015a441f712ea2c9c6d18540b04be3d0b2ca7. */
/*
 * MEMW/read active clone once and return borrowed product text when nonzero,
 * else the pinned empty NUL string. No copy, length/termination validation,
 * allocation, lock or ownership transfer; cached text can change later.
 */
const char *device_product_get(void)
{
    memw();
    return CLONE_ACTIVE != 0 ? QUERY_PRODUCT : QUERY_EMPTY_PRODUCT;
}

/* Native entry: 0x4203960c. */
/* Original function-byte SHA-256:
 * f9c254c6122ab24f8ad966b8a6eedc7f8de1120451c6e38a6a557e62890a6870. */
/*
 * QUERY(CAPS) mouse fields: MEMW/sample active BYTE once; inactive returns0
 * without outputs. Otherwise write low8(interface count), zero button/flags,
 * then read selected mouse index once. Negative index retains zero mouse data;
 * a nonnegative index is trusted, with native304-byte report-layout stride.
 * Button count is capped16. Flag bits0/1/2/4 report enabled X/Y/wheel/pan;
 * bit3 means a nonzero report ID. Each metadata BYTE is read once in that order.
 * Return the raw sampled active BYTE. No null checks, index bound or lock.
 */
unsigned char mouse_caps_get(unsigned char *button_count,
    unsigned char *capability_flags,unsigned char *interface_count)
{
    memw();
    unsigned char active = CLONE_ACTIVE;
    if (active == 0) return 0;
    *interface_count = (unsigned char)USB_INTERFACE_COUNT;
    *button_count = 0;
    *capability_flags = 0;
    int index = FIXED_INPUTS[0].interface;
    if (index < 0) return active;
    const volatile HidReportLayout *layout = &HID_REPORT_LAYOUTS[index];
    unsigned char buttons = layout->button_count;
    *button_count = buttons < 16 ? buttons : 16;
    unsigned char capabilities = layout->axes[0].enabled != 0;
    if (layout->axes[1].enabled != 0) capabilities |= 2;
    if (layout->axes[2].enabled != 0) capabilities |= 4;
    if (layout->axes[3].enabled != 0) capabilities |= 16;
    if (layout->report_id != 0) capabilities |= 8;
    *capability_flags = capabilities;
    return active;
}

/* Native entry: 0x420396a0. */
/* Original function-byte SHA-256:
 * 866d9c1964468beb139815c004e7e4107a213e7005f90f2d1657123d8083305b. */
/*
 * Read the selected keyboard index once; negative returns0 without outputs.
 * Otherwise write0xff for nonzero bitmap mode, else the array key count.
 * Reread bitmap mode for the flags BYTE, retaining its RAW value; OR bit3 for
 * nonzero keyboard report ID and bit1 for a bound consumer interface. Return1.
 * No clone-active gate, index bound, null check, lock or metadata snapshot.
 */
unsigned int keyboard_caps_get(unsigned char *key_limit,unsigned char *capability_flags)
{
    int index = FIXED_INPUTS[1].interface;
    if (index < 0) return 0;
    const volatile HidKeyboardLayout *keyboard = &HID_REPORT_LAYOUTS[index].keyboard;
    unsigned char limit = 255;
    if (keyboard->bitmap_mode == 0) limit = keyboard->key_count;
    *key_limit = limit;
    unsigned char capabilities = keyboard->bitmap_mode;
    if (keyboard->report_id != 0) capabilities |= 8;
    if (FIXED_INPUTS[2].interface >= 0) capabilities |= 2;
    *capability_flags = capabilities;
    return 1;
}

/* Native entry: 0x420396fc. */
/* Original function-byte SHA-256:
 * 42f7258f36b35e3e21ceafb6e21f8df4e9758f0ffdd2418b55a3e65f3283302c. */
/*
 * QUERY(RATE) returns PERIODS, not Hz. Cache mouse then keyboard indices;
 * if both negative return0 without outputs. A mouse with sample_count>255
 * supplies MEMW/read learned period, saturated65535, and confidence1.
 * Otherwise measured period=0/confidence0, preferring a keyboard endpoint
 * whenever bound, even if a mouse exists. keyboard_fallback reports that choice.
 * Endpoint period is raw descriptor bInterval *1000, saturated65535. The
 * helper returns a BYTE, but native masks16 before multiplying. No speed or
 * transfer-type conversion (e.g. high-speed exponent) is performed here.
 * Outputs are stored measured/endpoint/confidence/fallback, then return1.
 * No active-clone gate, endpoint/index bound, null check or snapshot/lock.
 */
unsigned int rate_get(unsigned short *measured_period_us,unsigned short *endpoint_period_us,
    unsigned char *confident,unsigned char *keyboard_fallback)
{
    int mouse = FIXED_INPUTS[0].interface;
    int keyboard = FIXED_INPUTS[1].interface;
    if (mouse < 0 && keyboard < 0) return 0;
    if (mouse >= 0 && REPORT_INTERVAL_HISTORY.sample_count > 255) {
        memw();
        unsigned int measured = REPORT_LEARNED_PERIOD;
        *measured_period_us = measured < 65535U ? measured : 65535U;
        unsigned int interval = clone_endpoint_interval_byte(USB_INTERFACE_ENDPOINTS[mouse]);
        unsigned int period_us = (interval & 65535U) * 1000U;
        *endpoint_period_us = period_us < 65535U ? period_us : 65535U;
        *confident = 1;
        *keyboard_fallback = 0;
        return 1;
    }
    unsigned char use_keyboard = keyboard >= 0;
    int interface = use_keyboard ? keyboard : mouse;
    *measured_period_us = 0;
    unsigned int interval = clone_endpoint_interval_byte(USB_INTERFACE_ENDPOINTS[interface]);
    unsigned int period_us = (interval & 65535U) * 1000U;
    *endpoint_period_us = period_us < 65535U ? period_us : 65535U;
    *confident = 0;
    *keyboard_fallback = use_keyboard;
    return 1;
}

/* Native entry: 0x420397a4. */
/* Original function-byte SHA-256:
 * 67fb8a3ab487691a14a11311ec7d70a851c278d6d6e7db51396a53caf5efcc9c. */
/*
 * QUERY(HEALTH): optionally take configuration mutex with UINT_MAX ticks;
 * ignore its result. MEMW/read clone-active and, if set, put configured(bus0)
 * in bit2. For enabled mouse, bit3 means primary/secondary activity when render
 * bit0 is clear, render bit3 when bit0 is set, an unexpired nonzero low32-us
 * activity stamp (<8000 modulo2^32), or forced/cleared buttons. The immediate
 * paths still call the button-override reader and ignore its result. Otherwise
 * sample time, clear an expired nonzero stamp, and use the override result.
 * If mouse does not set bit3, enabled keyboard then consumer forced controls
 * are tested with short-circuit order. No keyboard/consumer recent-time test.
 *
 * Bit4: bound mouse plus interval sample_count>255. Bit5: enabled mouse,
 * keyboard or consumer has transforms (not merely held buttons). Bit6: capture
 * class HALFWORD!=0. Bit7: keyboard bound. Bits8/9/10: rewrite/patch/observed
 * button-rule counts nonzero. The dispatcher adds its separate ownership bits.
 * Reload the release mutex BEFORE capture-class/remaining flag reads, then
 * send(NULL,0ticks,back) through that cached handle if nonnull. It can differ
 * from the acquired handle. No take/send failure handling or coherent snapshot;
 * WORD timestamps wrap and MEMW does not make this whole query atomic.
 */
unsigned int health_flags_get(void)
{
    RtosQueue *mutex = REWRITE_MUTEX;
    if (mutex != 0) (void)xQueueSemaphoreTake(mutex,0xffffffffU);
    unsigned int flags = 0;
    memw();
    if (CLONE_ACTIVE != 0)
        flags = ((unsigned int)usb_device_is_configured(0) << 2) & 65535U;
    const InputStateView *mouse = (const InputStateView *)&FIXED_INPUTS[0].state;
    const InputStateView *keyboard = (const InputStateView *)&FIXED_INPUTS[1].state;
    const InputStateView *consumer = (const InputStateView *)&FIXED_INPUTS[2].state;
    bool active = false;
    if (FIXED_INPUTS[0].enabled != 0) {
        memw();
        unsigned char render = MOTION_RENDER_STATE;
        if ((render & 1) == 0) {
            active = input_has_primary_activity(mouse) != 0 ||
                     input_has_secondary_activity(mouse) != 0;
        } else {
            memw();
            active = (MOTION_RENDER_STATE & 8) != 0;
        }
        if (active) {
            (void)input_has_button_overrides(mouse);
        } else {
            unsigned long long now_us = esp_timer_get_time();
            memw();
            unsigned int stamp = QUERY_MOTION_RECENT_TIME;
            if (stamp != 0 && (unsigned int)((unsigned int)now_us - stamp) < 8000U) {
                (void)input_has_button_overrides(mouse);
                active = true;
            } else {
                if (stamp != 0) {
                    memw(); QUERY_MOTION_RECENT_TIME = 0;
                }
                active = input_has_button_overrides(mouse) != 0;
            }
        }
    }
    if (!active)
        active = (FIXED_INPUTS[1].enabled != 0 && input_has_forced_controls(keyboard) != 0) ||
                 (FIXED_INPUTS[2].enabled != 0 && input_has_forced_controls(consumer) != 0);
    if (active) flags |= 8;
    if (FIXED_INPUTS[0].interface >= 0 && REPORT_INTERVAL_HISTORY.sample_count > 255)
        flags |= 16;
    if ((FIXED_INPUTS[0].enabled != 0 && input_has_transforms(mouse) != 0) ||
        (FIXED_INPUTS[1].enabled != 0 && input_has_transforms(keyboard) != 0) ||
        (FIXED_INPUTS[2].enabled != 0 && input_has_transforms(consumer) != 0))
        flags |= 32;
    RtosQueue *release_mutex = REWRITE_MUTEX;
    memw();
    if (CAPTURE_CLASS_MASK != 0) flags |= 64;
    if (FIXED_INPUTS[1].interface >= 0) flags |= 128;
    if (REWRITE_COUNT != 0) flags |= 256;
    if (QUERY_PATCH_COUNT != 0) flags |= 512;
    if (OBSERVED_BUTTON_RULE_COUNT != 0) flags |= 1024;
    if (release_mutex != 0) (void)xQueueGenericSend(release_mutex,0,0,0);
    return flags;
}

/* Native entry: 0x4200a738. */
/* Original function-byte SHA-256:
 * 0ed9b33f599e8339c04a5b982bf8eb26772ea6d759f185f82181b5e3f0bcc173. */
/*
 * Build QUERY(VERSION) reply. Copy pinned prefix00 09 03 04 07 00, then zero
 * bytes6..42. MEMW/read eFuse MAC low WORD, MEMW/read high WORD; place its six
 * bytes in network display order at offsets5..10, overwriting prefix byte5.
 * Store offsets8,9,5,6,7,10 in native order, then copy up to32 name bytes at11.
 * Send opcode6 with low8 request sequence and low16(name_length+11). Name
 * helper handles configured/default text; no terminator is part of wire length.
 * No eFuse API, derived interface MAC, allocation, retry or send-result handling.
 * This stack payload contains43 meaningful bytes; native frame is80 bytes.
 */
void query_version_send(unsigned char sequence)
{
    VersionQueryWire reply;
    memcpy(reply.bytes,VERSION_QUERY_PREFIX,6);
    memset(reply.bytes + 6,0,37);
    memw(); unsigned int mac_low = VERSION_QUERY_MAC->low;
    memw(); unsigned int mac_high = VERSION_QUERY_MAC->high;
    volatile unsigned char *mac_bytes = reply.base_mac;
    mac_bytes[3] = (unsigned char)(mac_low >> 16);
    mac_bytes[4] = (unsigned char)(mac_low >> 8);
    mac_bytes[0] = (unsigned char)(mac_high >> 8);
    mac_bytes[1] = (unsigned char)mac_high;
    mac_bytes[2] = (unsigned char)(mac_low >> 24);
    mac_bytes[5] = (unsigned char)mac_low;
    unsigned int name_length = option_copy_name(reply.name,32);
    control_send_frame(6,sequence,reply.bytes,(unsigned short)(name_length + 11U));
}

/* Native entry: 0x420387c4. */
/* Original function-byte SHA-256:
 * f078f8b2b8c58001bbd6ac20313d9b852791579ae8c34e5a62bb1324b37b8d01. */
/*
 * QUERY(PATCHES): optionally take configuration mutex forever, ignoring result;
 * after a take reload/cache its handle for eventual release. Cache served
 * count, stored count and patch-refused BYTE. Flags: bit0 served count!=0,
 * bit1 stored/served differ, OR(raw refused<<2), OR(raw stored apply<<3),
 * truncated to a BYTE. When counts match, compare ALL count entries without
 * bounding16: identity HALF, descriptor-index BYTE, offset HALF, served then
 * stored length HALF, then memcmp(stored payload,served payload,served length).
 * Skip reserved byte3; payload offsets need not match when bytes match.
 *
 * Write selector14, zero output count, then flags. If stored count!=0, walk
 * its records, reloading stored count after EACH iteration, emitting while
 * output count<16. Each seven-byte summary is kind/configuration/index plus
 * little-endian offset/length, with offset HIGH written before LOW natively.
 * After sixteen emissions the remaining records are walked without reads.
 * Cursor wraps16, iteration wraps8; output-count reloads are retained. Release
 * the earlier cached mutex with send(NULL,0,back), and return cursor (3..115 in
 * stable valid tables). No output capacity, table/payload bounds, alias check
 * or take/send error handling; admission invariants are required for safety.
 */
unsigned int patches_encode(unsigned char *output)
{
    RtosQueue *release_mutex = REWRITE_MUTEX;
    if (release_mutex != 0) {
        (void)xQueueSemaphoreTake(release_mutex,0xffffffffU);
        release_mutex = REWRITE_MUTEX;
    }
    const volatile DescriptorPatchTable *stored = DESCRIPTOR_PATCH_STORED;
    const volatile DescriptorPatchTable *served = DESCRIPTOR_PATCH_SERVED;
    unsigned int served_count = served->count;
    unsigned int stored_count = stored->count;
    unsigned char refused = CLONE_PATCH_REFUSED;
    unsigned char flags = served_count != 0;
    bool different = served_count != stored_count;
    if (!different) {
        for (unsigned int index = 0; index < served_count; ++index) {
            const volatile DescriptorPatchRecord *wanted = &stored->records[index];
            const volatile DescriptorPatchRecord *active = &served->records[index];
            unsigned short stored_identity = wanted->identity;
            unsigned short served_identity = active->identity;
            if (stored_identity != served_identity) { different = true; break; }
            unsigned char stored_index = wanted->descriptor_index;
            unsigned char served_index = active->descriptor_index;
            if (stored_index != served_index) { different = true; break; }
            unsigned short stored_offset = wanted->offset;
            unsigned short served_offset = active->offset;
            if (stored_offset != served_offset) { different = true; break; }
            unsigned short served_length = active->length;
            unsigned short stored_length = wanted->length;
            if (stored_length != served_length) { different = true; break; }
            unsigned short served_payload = active->payload_offset;
            unsigned short stored_payload = wanted->payload_offset;
            if (memcmp((const unsigned char *)stored->payload + stored_payload,
                (const unsigned char *)served->payload + served_payload,served_length) != 0) {
                different = true; break;
            }
        }
    }
    if (different) flags |= 2;
    unsigned char apply = stored->apply;
    flags |= (unsigned char)((unsigned int)refused << 2 | (unsigned int)apply << 3);
    volatile unsigned char *wire = output;
    wire[0] = 14;
    wire[2] = 0;
    wire[1] = flags;
    unsigned short cursor = 3;
    if (stored->count != 0) {
        const volatile DescriptorPatchRecord *record = stored->records;
        unsigned char walked = 0,emitted = 0;
        for (;;) {
            ++walked;
            if (emitted < 16) {
                unsigned short offset = record->offset;
                unsigned char kind = record->kind;
                unsigned char configuration = record->configuration;
                unsigned char descriptor_index = record->descriptor_index;
                unsigned short length = record->length;
                wire[cursor] = kind;
                wire[cursor + 1U] = configuration;
                wire[cursor + 2U] = descriptor_index;
                wire[cursor + 4U] = (unsigned char)(offset >> 8);
                wire[cursor + 3U] = (unsigned char)offset;
                wire[cursor + 5U] = (unsigned char)length;
                wire[cursor + 6U] = (unsigned char)(length >> 8);
                unsigned char count = wire[2];
                cursor = (unsigned short)(cursor + 7U);
                wire[2] = (unsigned char)(count + 1U);
            }
            ++record;
            if (walked >= stored->count) break;
            emitted = wire[2];
        }
    }
    if (release_mutex != 0) (void)xQueueGenericSend(release_mutex,0,0,0);
    return cursor;
}

/* Native entry: 0x42038924. */
/* Original function-byte SHA-256:
 * 3fd1803775c103b5d34ac4fb5f5c30f42fd422f4d565cf744b6415155b2213b2. */
/*
 * QUERY(PATCH_ENTRY): low8 index; optionally take configuration mutex forever,
 * ignoring failure. Missing entry returns0 with no output. Otherwise read
 * offset HALF, kind/configuration/index BYTEs, length HALF and payload-offset
 * HALF; write selector15, request index, those three fields, offset LOW/HIGH,
 * then copy length payload bytes when nonzero. Return low16(length+7), even
 * when that wraps. Reload current mutex for release, unlike list encoder's
 * cached handle. No output capacity, count<=16, payload bound or NULL checks.
 */
unsigned int patch_entry_encode(unsigned char *output,unsigned char index)
{
    RtosQueue *mutex = REWRITE_MUTEX;
    if (mutex != 0) (void)xQueueSemaphoreTake(mutex,0xffffffffU);
    unsigned int result = 0;
    if (index < DESCRIPTOR_PATCH_STORED->count) {
        const volatile DescriptorPatchRecord *record = &DESCRIPTOR_PATCH_STORED->records[index];
        unsigned short offset = record->offset;
        unsigned char kind = record->kind;
        unsigned char configuration = record->configuration;
        unsigned char descriptor_index = record->descriptor_index;
        unsigned short length = record->length;
        unsigned short payload = record->payload_offset;
        volatile unsigned char *wire = output;
        wire[0] = 15;
        wire[1] = index;
        wire[2] = kind;
        wire[3] = configuration;
        wire[4] = descriptor_index;
        wire[5] = (unsigned char)offset;
        wire[6] = (unsigned char)(offset >> 8);
        if (length != 0)
            memcpy(output + 7,(const unsigned char *)DESCRIPTOR_PATCH_STORED->payload + payload,length);
        result = (unsigned short)(length + 7U);
    }
    mutex = REWRITE_MUTEX;
    if (mutex != 0) (void)xQueueGenericSend(mutex,0,0,0);
    return result;
}
