/* Medius v3.4.7 device — usb/descriptors.c.
 * Recovered C and native assembly, grouped for source navigation.
 * Original entry addresses, firmware-byte hashes and function comments follow.
 */

#include "../include/types.h"

/* Native entry: 0x4200c4f8. */
/* Original function-byte SHA-256:
 * 8e94e646110a8c7def552306bf28df5c2d71cc92bf0b2be60b22619e9b9d2d4b. */
/*
 * Recompute only assembly->complete. Sections0..5 must be present and have
 * received==expected; optional6..16 are checked only when present. Mandatory
 * counts read received THEN expected, optional counts expected THEN received,
 * as separate native HALFWORD loads. Stop at the first missing/mismatched
 * section and store complete0; all seventeen passing stores complete1.
 * Does not test end_seen, error, section lengths or payload contents. Thus
 * present sections with zero expected/received counts satisfy this test.
 * Assembly pointer is trusted; no lock/fence or coherent multi-field snapshot.
 */
void medius_clone_assembly_check(CloneAssembly *assembly)
{
    volatile CloneAssembly *state = assembly;
    for (unsigned int section = 0; section != 17; ++section) {
        unsigned char present = state->present[section];
        if (section < 6) {
            if (present == 0) goto incomplete;
            unsigned short received = state->received[section];
            unsigned short expected = state->expected[section];
            if (received != expected) goto incomplete;
        } else if (present != 0) {
            unsigned short expected = state->expected[section];
            unsigned short received = state->received[section];
            if (received != expected) goto incomplete;
        }
    }
    state->complete = 1;
    return;
incomplete:
    state->complete = 0;
}

/* Native entry: 0x4200c550. */
/* Original function-byte SHA-256:
 * 11c7ee33f6609e50b8bdd7e0ab7f5059ac36075486faeaa3046f118c85949eb4. */
/*
 * Clear exactly0x471e (18,206) bytes of the clone assembly, including descriptor
 * storage, lengths/counts, present flags, end_seen/complete/error. No validation,
 * synchronization, allocation/free, publication or return status. Caller must
 * provide the full writable object and exclude concurrent users if needed.
 */
void clone_assembly_reset(CloneAssembly *assembly)
{
    memset(assembly,0,0x471e);
}

/* Native entry: 0x4200c564. */
/*
 * Medius v3.4.7 — device application; 0x4200c564.
 *
 * Receives ordered snapshot fragments into fixed section buffers and updates
 * reset/error/end/completion bookkeeping.
 *
 * Calls: medius_clone_assembly_check, memcpy, memset.
 *
 * Called by: device_link_message.
 *
 * Original function-byte SHA-256:
 * 522428e75075fd27e3bfab94ba4ccbc6c71776c5ae2b8162819daf15909e0aa0.
 */

/*
 * assembly: Writable18206-byte clone assembly; frame may alias it, with reset/copy effects
 *   retained.
 * frame: Borrowed frame bytes, read only after minimum-length admission; payload must remain
 *   mapped through copying.
 * length: Raw16-bit frame length; header admission compares (count+7) modulo65536 after requiring
 *   length>=7.
 * Returns: 0 for malformed/error-latched frames or a snapshot not yet complete; otherwise the
 *   current completion byte, including stale nonzero values for reserved IDs.
 * Requirements/effects: Reads count HIGH then LOW, then total HIGH, offset HIGH, total LOW, offset
 *   LOW and section, caching all before any reset. Section0/offset0 clears the whole assembly
 *   before capacity/prior-error checks; error is then read freshly. Marker6 sets end_seen and
 *   checks completion, ignoring its other metadata/payload after common length admission.
 *   Reserved8/9/>16 return fresh complete without mutation. Supported fixed sections require
 *   total<=capacity, full offset+count<=total and current received==offset. Nonzero copy reloads
 *   received afterward; zero copy retains the earlier received snapshot. Publishes expected,total
 *   length,received+count modulo16 and present in that order; totals may change between fragments.
 *   String sections3/4/5 write a terminator at cached total even for partial/zero chunks. Fresh
 *   end_seen0 clears complete to its cached zero; otherwise runs the checker and returns fresh
 *   complete. Error is not rechecked after copy. Rejection latches error without clearing existing
 *   complete. No lock, sequence/session identity, timeout, rollback, input preservation, memmove
 *   overlap handling or semantic USB validation; completion is bookkeeping, not activation.
 */

uchar clone_section_accept(CloneAssembly *assembly,const uchar *frame,ushort length)
{
    volatile CloneAssembly *state = assembly;
    if (length < 7) {
        state->error = 1;
        return 0;
    }
    const volatile MediusCloneFragmentHeader *header =
        (const volatile MediusCloneFragmentHeader *)frame;
    uint count_high = header->count_high;
    uint count_low = header->count_low;
    uint count = (count_high << 8) | count_low;
    if (((count + 7U) & 0xffffU) != length) {
        state->error = 1;
        return 0;
    }
    /* These cached bytes survive a section0 reset, even if frame aliases it. */
    uint total_high = header->total_high;
    uint offset_high = header->offset_high;
    uint total_low = header->total_low;
    uint offset_low = header->offset_low;
    uint section = header->section;
    ushort total = (ushort)((total_high << 8) | total_low);
    uint offset = (offset_high << 8) | offset_low;
    if (section == 0 && offset == 0)
        memset(assembly,0,0x471e);
    if (state->error != 0)
        return 0;
    if (section == 6) {
        state->end_seen = 1;
        medius_clone_assembly_check(assembly);
        return state->complete;
    }
    uchar *section_data;
    uint capacity;
    switch (section) {
    case 0: section_data = assembly->section_0; capacity = 18; break;
    case 1: section_data = assembly->section_1; capacity = 2048; break;
    case 2: section_data = assembly->section_2; capacity = 6144; break;
    case 3: section_data = assembly->section_3; capacity = 126; break;
    case 4: section_data = assembly->section_4; capacity = 126; break;
    case 5: section_data = assembly->section_5; capacity = 126; break;
    case 7: section_data = assembly->section_7; capacity = 256; break;
    case 10: section_data = assembly->section_10; capacity = 1; break;
    case 11: section_data = assembly->section_11; capacity = 6144; break;
    case 12: section_data = assembly->section_12; capacity = 1; break;
    case 13: section_data = assembly->section_13; capacity = 1536; break;
    case 14: section_data = assembly->section_14; capacity = 1039; break;
    case 15: section_data = assembly->section_15; capacity = 3; break;
    case 16: section_data = assembly->section_16; capacity = 512; break;
    default:
        return state->complete;
    }
    if (total > capacity || offset + count > total) {
        state->error = 1;
        return 0;
    }
    ushort received = state->received[section];
    if (received != offset) {
        state->error = 1;
        return 0;
    }
    if (count != 0) {
        memcpy((void *)((uint)section_data + offset),frame + 7,count);
        received = state->received[section];
    }
    state->expected[section] = total;
    state->lengths[section] = total;
    state->received[section] = (ushort)(received + count);
    state->present[section] = 1;
    if (section == 3 || section == 4 || section == 5)
        *(volatile uchar *)((uint)section_data + total) = 0;
    uchar end_seen = state->end_seen;
    if (end_seen == 0) {
        state->complete = end_seen;
        return end_seen;
    }
    medius_clone_assembly_check(assembly);
    return state->complete;
}

/* Native entry: 0x4200c7ac. */
/*
 * Medius v3.4.7 — device application; 0x4200c7ac.
 *
 * Returns a borrowed present section pointer and its current declared length, independently of
 * completion or error.
 *
 * Called by: app_main.
 *
 * Original function-byte SHA-256:
 * 5373aa50eabc375f81e5fc5c8df023ad2a010aa4b8f33131b96aed93457f5498.
 */

/*
 * assembly: Live clone-assembly storage with at least the verified fixed section views.
 * section: Raw eight-bit section ID; only 0..16 can pass initial admission.
 * length: Optional writable16-bit output, written before section pointer dispatch; may alias
 *   assembly storage.
 * Returns: Borrowed fixed section pointer when present and supported. IDs6/8/9 return NULL even
 *   after reporting their declared length; other absent/out-of-range IDs report length0 and NULL.
 * Requirements/effects: Tests present only once after the range guard. For a present ID writes its
 *   current declared length to a non-NULL output before selecting the fixed section address. Does
 *   not recheck presence after an aliased output store and does not inspect
 *   complete/error/end_seen/received/expected or clamp length to capacity. A supported section
 *   pointer can therefore describe a zero-length, partial, erroneous or corrupted snapshot. No
 *   allocation, copying, helper call or ownership transfer occurs. Caller must validate snapshot
 *   state and synchronize against reset/fragments; returned bytes alias mutable assembly storage
 *   and can be invalidated by later reuse.
 */

unsigned char *clone_section_get(CloneAssembly *assembly,
    unsigned char section, unsigned short *length)
{
    unsigned int section_index = section;
    if (section_index >= 17 || assembly->present[section_index] == 0) {
        if (length != NULL)
            *length = 0;
        return NULL;
    }
    /* An aliased output may change assembly bytes; admission is not repeated. */
    if (length != NULL)
        *length = assembly->lengths[section_index];
    switch (section_index) {
    case 0: return assembly->section_0;
    case 1: return assembly->section_1;
    case 2: return assembly->section_2;
    case 3: return assembly->section_3;
    case 4: return assembly->section_4;
    case 5: return assembly->section_5;
    case 7: return assembly->section_7;
    case 10: return assembly->section_10;
    case 11: return assembly->section_11;
    case 12: return assembly->section_12;
    case 13: return assembly->section_13;
    case 14: return assembly->section_14;
    case 15: return assembly->section_15;
    case 16: return assembly->section_16;
    default: return NULL;
    }
}

/* Native entry: 0x420274e4. */
/*
 * Medius v3.4.7 — device application; 0x420274e4.
 *
 * Resets the consumed clone assembly, clears its busy/pending flags and returns the cached pending
 * byte.
 *
 * Calls: clone_assembly_reset, link_send_wait100, vPortExitCritical,
 * xPortEnterCriticalTimeout.
 *
 * Called by: app_main.
 *
 * Original function-byte SHA-256:
 * 3c2f454995aa877fe0077ec124ede3f3a586982f2e706a00b44e3c625b4a4cd3.
 */

/*
 * notify: Full32 nonzero permits a release notification when the cached pending byte is nonzero.
 * Returns: The zero-extended pending byte captured under the mux, unaffected by later unlock/send
 *   outcomes.
 * Requirements/effects: Resets assembly before locking, invalidating borrowed assembly data.
 *   Ignores critical-entry status, then MEMW/busy=0, MEMW/read pending, MEMW/pending=0 and unlock.
 *   A nonzero cached pending byte plus nonzero notify sends message 0x15, sequence 0, NULL
 *   payload, length 0; return status is ignored. No writes or rereads occur after unlock. A newly
 *   set pending byte after the clear remains for another consumer. Reset is outside this mux;
 *   sequential ordering does not establish race freedom or delivery.
 */

uint clone_release_assembly(uint notify)
{
    clone_assembly_reset(DEVICE_CLONE_ASSEMBLY);
    xPortEnterCriticalTimeout(&DEVICE_CLONE_HANDOFF_LOCK,0xffffffffU);
    memw();
    DEVICE_CLONE_HANDOFF_FLAGS->busy = 0;
    memw();
    uint pending = DEVICE_CLONE_HANDOFF_FLAGS->dropped_while_busy;
    memw();
    DEVICE_CLONE_HANDOFF_FLAGS->dropped_while_busy = 0;
    vPortExitCritical(&DEVICE_CLONE_HANDOFF_LOCK);
    if (pending != 0 && notify != 0)
        link_send_wait100(0x15,0,0,0);
    return pending;
}

/* Native entry: 0x42028708. */
/*
 * Medius v3.4.7 — device application; 0x42028708.
 *
 * Registers completion callbacks for cloned HID, vendor and nonzero control endpoints.
 *
 * Calls: esp_log_timestamp, esp_log_write, usbd_add_endpoint.
 *
 * Called by: FUN_40391df4, FUN_4203456c, usb_clone_configure, medius_usb_device_event.
 *
 * Original function-byte SHA-256:
 * 69ec6f9888faf7789e1b0a811c9ca091fea100860f002f4640ea10db74f0e60f.
 */

/* Registers completion callbacks for cloned HID, vendor and nonzero control endpoints. Evidence:
   For each nonzero HID IN address registers medius_hid_device_in_complete; HID OUT list registers
   medius_hid_device_out_complete. Vendor direction selects vendor IN/OUT completion. Nonzero
   control entries increment generation, clear pending flag, store address/MPS and register OUT plus
   address|0x80 IN handlers. Emits diagnostic logs for every registration. */

/*
 * Returns: No value.
 * Requirements/effects: Registers bus0 callbacks in HID-IN, HID-OUT, vendor, then nonzero-control
 *   order. Signed live counts are checked initially and after every iteration; no local capacity
 *   or negative-data validation is supplied. HID IN alone skips address0. Eight-byte registration
 *   padding is retained. Vendor callback selection uses the cached address bit7; diagnostic type2
 *   is bulk, every other type is intr. Calls to endpoint registration and logging ignore status.
 *   Each timestamp is obtained before fresh diagnostic source reads: HID report length then
 *   interface ID then address; vendor type then MPS then address; control MPS then address. For
 *   each20-byte control state, snapshots generation before MPS and endpoint, increments generation
 *   modulo256, writes MPS/address and clears state; other state fields remain. OUT registration
 *   uses the cached endpoint, IN reloads it after the OUT call and writes its callback before
 *   address|0x80. Counts and diagnostics can therefore reflect mutations made by callees. No lock,
 *   buffer reset, endpoint activation, deduplication, rollback or registration-success check is
 *   provided. Caller must supply valid storage/counts and serialize any incompatible mutations;
 *   memory barriers alone do not establish lifetime safety.
 */

void medius_usb_register_clone_endpoints(void)
{
    const volatile int *hid_in_count = &USB_INTERFACE_COUNT;
    for (uint index = 0; (int)index < *hid_in_count; ++index) {
        const volatile uchar *source_address = USB_INTERFACE_ENDPOINTS + index;
        uchar address = *source_address;
        if (address == 0)
            continue;
        volatile MediusUsbEndpointRegistration *registration =
            &USB_CLONE_HID_IN_REGISTRATIONS[index];
        registration->address = address;
        registration->complete = medius_hid_device_in_complete;
        usbd_add_endpoint(0,(MediusUsbEndpointRegistration *)registration);
        uint timestamp = esp_log_timestamp();
        ushort report_length = USB_INTERFACE_REPORT_LENGTHS[index];
        uchar interface_id = MEDIUS_CLONE_HID_INTERFACE_IDS[index];
        uchar logged_address = *source_address;
        esp_log_write(3,"usbdev","I (%lu) %s:   intf %u in ep 0x%02X rpt %u\n",
                      timestamp,"usbdev",interface_id,logged_address,report_length);
    }
    const volatile int *hid_out_count = &MEDIUS_CLONE_HID_OUT_COUNT;
    for (uint index = 0; (int)index < *hid_out_count; ++index) {
        const volatile uchar *source_address =
            (const volatile uchar *)MEDIUS_CLONE_HID_OUT_ADDRESSES + index;
        uchar address = *source_address;
        volatile MediusUsbEndpointRegistration *registration =
            &USB_CLONE_HID_OUT_REGISTRATIONS[index];
        registration->address = address;
        registration->complete = medius_hid_device_out_complete;
        usbd_add_endpoint(0,(MediusUsbEndpointRegistration *)registration);
        uint timestamp = esp_log_timestamp();
        uchar logged_address = *source_address;
        esp_log_write(3,"usbdev","I (%lu) %s:   out ep 0x%02X\n",
                      timestamp,"usbdev",logged_address);
    }
    const volatile int *vendor_count = &MEDIUS_CLONE_SERVED_ENDPOINTS->noncontrol_count;
    for (uint index = 0; (int)index < *vendor_count; ++index) {
        const volatile MediusCloneVendorEndpoint *description =
            &MEDIUS_CLONE_SERVED_ENDPOINTS->noncontrol[index];
        uchar address = description->address;
        MediusUsbEndpointCompletion complete = (address & 0x80U)
            ? medius_vendor_device_in_complete : medius_vendor_device_out_complete;
        volatile MediusUsbEndpointRegistration *registration =
            &USB_CLONE_VENDOR_REGISTRATIONS[index];
        registration->address = address;
        registration->complete = complete;
        usbd_add_endpoint(0,(MediusUsbEndpointRegistration *)registration);
        uint timestamp = esp_log_timestamp();
        uchar transfer_type = description->transfer_type;
        ushort max_packet = description->max_packet;
        uchar logged_address = description->address;
        const char *type_name = transfer_type == 2 ? "bulk" : "intr";
        esp_log_write(3,"usbdev","I (%lu) %s:   vendor ep 0x%02X %s mps %u\n",
                      timestamp,"usbdev",logged_address,type_name,max_packet);
    }
    const volatile int *control_count = &MEDIUS_CLONE_SERVED_ENDPOINTS->control_count;
    for (uint index = 0; (int)index < *control_count; ++index) {
        volatile MediusNonzeroControlState *state = &MEDIUS_NONZERO_CONTROL_STATES[index];
        const volatile ushort *source_max_packet =
            (const volatile ushort *)((uint)MEDIUS_CLONE_SERVED_ENDPOINTS + 0x66U + index * 2U);
        const volatile uchar *source_address =
            (const volatile uchar *)((uint)MEDIUS_CLONE_SERVED_ENDPOINTS + 0x64U + index);
        memw();
        uchar generation = state->generation;
        ushort max_packet = *source_max_packet;
        uchar address = *source_address;
        memw();
        state->generation = (uchar)(generation + 1U);
        state->max_packet = max_packet;
        state->endpoint = address;
        memw();
        state->state = 0;
        volatile MediusUsbEndpointRegistration *out_registration =
            &USB_CLONE_CONTROL_REGISTRATIONS[index * 2U];
        out_registration->address = address;
        out_registration->complete = medius_nonzero_control_out_complete;
        usbd_add_endpoint(0,(MediusUsbEndpointRegistration *)out_registration);
        uchar device_in_address = *source_address;
        volatile MediusUsbEndpointRegistration *device_in_registration =
            (volatile MediusUsbEndpointRegistration *)((uint)out_registration + 8U);
        device_in_registration->complete = medius_nonzero_control_in_complete;
        device_in_registration->address = device_in_address | 0x80U;
        usbd_add_endpoint(0,(MediusUsbEndpointRegistration *)device_in_registration);
        uint timestamp = esp_log_timestamp();
        ushort logged_max_packet = *source_max_packet;
        uchar logged_address = *source_address;
        esp_log_write(3,"usbdev","I (%lu) %s:   control ep %u mps %u\n",
                      timestamp,"usbdev",logged_address,logged_max_packet);
    }
}

/* Native entry: 0x4203491c. */
/*
 * Medius v3.4.7 — device application; 0x4203491c.
 *
 * Consumes a clone snapshot, validates metadata and patch policy, registers USB
 * descriptors/interfaces, restores reports and starts the control task.
 *
 * Calls: esp_log_timestamp, esp_log_write, FUN_42003ed0, heap_caps_get_largest_free_block, FUN_42009188, profile_load_baseline,
 * profile_load_normalization, profile_load_patches, FUN_42009c40, FUN_4200c8b4, FUN_420282b8, FUN_42028590,
 * FUN_42029070, FUN_42029c14, FUN_4202a820, FUN_4202cb20, FUN_4202d3c0,
 * medius_clone_build_descriptors, link_send_wait100, medius_usb_register_clone_endpoints,
 * medius_usbd_ep0_task_exists, memcpy, memset, strnlen; plus 5 other direct targets.
 *
 * Called by: app_main.
 *
 * Original function-byte SHA-256:
 * 0ab5ab1ec4f3e786bf6a9a6c596f39a48adca943874344568c4a1441c8efe9db.
 */

/*
 * device_descriptor: Borrowed device descriptor; no NULL check; length>=12 permits native
 *   byte9/11/8/10 identity reads.
 * device_length: Low16 length, admitted1..18; cached independently of supplied backing capacity.
 * configuration: Borrowed configuration passed to descriptor builder.
 * configuration_length: Low16 length, admitted1..2048.
 * section_11: Borrowed section11 passed to builder.
 * section_11_length: Low16 section11 length.
 * section_2: Borrowed section2 passed to builder.
 * section_2_length: Low16 section2 length.
 * string_3: Optional string read up to127 bytes, copied and NUL-terminated into128-byte storage;
 *   NULL clears first byte only.
 * string_4: Second optional string with the same127-byte read cap and retained tail.
 * string_5: Third optional string with the same127-byte read cap and retained tail.
 * section_7: Optional section7 pointer controls extra-descriptor registration; builder receives
 *   pointer/length.
 * section_7_length: Low16 length;1..256 with nonNULL pointer publishes extra descriptor.
 * section_13: Optional section13 payload copied only within1536-byte cap.
 * section_13_length: Low16 length; zero accepted without payload copy; rejected argument clears
 *   published length only.
 * section_14: Optional section14 payload copied only within1039-byte cap.
 * section_14_length: Low16 length; rejected argument clears published length only.
 * speed: Low8 stored unchanged; separate exact3 flag is published.
 * configuration_index: Low8 selector in32-byte builder source; source padding remains
 *   uninitialized.
 * section_15: Optional at-least3-byte source for fixed3-byte copy after destination clear.
 * section_15_length: Low16 length; requires>=3 for copy.
 * section_16: Optional metadata blob copied before validation; invalid input clears parsed cache
 *   and retains raw bytes.
 * section_16_length: Low16 length;1..512 copied, then grammar requires>=69 and exact end.
 * Returns: 1 on local admission/build rejection or when EP0 task exists after attempted
 *   initialization;0 when task does not exist. USB initialization status is logged and does not
 *   select success.
 * Requirements/effects: Optional outer/patch/sync mutex takes do not gate work on failure.
 *   Retains native MEMW barriers around shared flags, identity, generation and restoration
 *   fields. Preserves the second active-byte snapshot, native metadata59/category/record checks,
 *   word64-before-word60 loads/stores, cache-ID byte reads and conditional cached halfword reads.
 *   Reload clears1190-byte patch cache, parses bounded7-byte headers with bytewise native
 *   argument-read ordering before payload fit, forwards six args and clears on negative record
 *   result; loaded flag remains loader low8 even parse failure. Active patch clear and optional
 *   enable-byte gates precede fresh release. Always builds baseline; eligible cache copied under
 *   optional lock with release handle cached before copy and generation read after. Patched errors
 *   or newly introduced bits1/2/4 trigger fallback with active clear; generation-sensitive blocked
 *   flag set only for successful fallback. Fresh/cached mutex handles follow each native path,
 *   including reads before blocked/count publication. Negative tiling logs and advertises
 *   interval0; final error rejects before registration. Successful path caches diagnostic
 *   IDs/count/length before version callback; extra descriptor length/data stored before pointer
 *   publication, six interfaces and sentinels, generation/sync/count updates and reset callback.
 *   Signed selected index gates report/period/feature restoration without upper bound. Report
 *   ID/length<=64 gates first copy; second freshly reloads helper length. Period125..31999
 *   admission precedes low16 clamp truncation/nearest1000 rounding; sticky changed flag only when
 *   different, no deadline guarantee. Feature helper length compared with freshly read table byte,
 *   consuming at most first two bytes without validating helper length<=2. Startup result depends
 *   on task existence, preserves partial state on every error, releases fresh outer handle before
 *   freshly sampled one-byte notification. No mandatory pointer/storage capacity/source
 *   snapshot/rollback or hardware/DMA/USB/concurrent ownership proof.
 */

unsigned int usb_clone_configure(
    unsigned char *device_descriptor,unsigned short device_length,
    unsigned char *configuration,unsigned short configuration_length,
    unsigned char *section_11,unsigned short section_11_length,
    unsigned char *section_2,unsigned short section_2_length,
    char *string_3,char *string_4,char *string_5,
    unsigned char *section_7,unsigned short section_7_length,
    unsigned char *section_13,unsigned short section_13_length,
    unsigned char *section_14,unsigned short section_14_length,
    unsigned char speed,unsigned char configuration_index,
    unsigned char *section_15,unsigned short section_15_length,
    unsigned char *section_16,unsigned short section_16_length)
{
    void *configuration_mutex = REPORT_MUTEX;
    if (configuration_mutex != 0)
        xQueueSemaphoreTake(configuration_mutex,0xffffffffU);
    if ((unsigned short)(configuration_length - 1U) > 2047 ||
        (unsigned short)(device_length - 1U) > 17) {
        unsigned int timestamp = esp_log_timestamp();
        esp_log_write(1,"usbdev",
            "E (%lu) %s: bad device/config (dev=%u cfg=%u) -> not cloning\n",
            timestamp,"usbdev",device_length,configuration_length);
        goto rejected;
    }
    memw();
    if (CLONE_ACTIVE != 0) {
        memw();
        unsigned char still_active = CLONE_ACTIVE;
        if (still_active == 0) {
            usb_clone_clear_runtime_state();
            MEDIUS_CLONE_CONFIGURATION_COUNT = 1;
            MEDIUS_CLONE_CONFIGURATION_INDEX = still_active;
        } else {
            memw();
            CLONE_QUIESCING = 1;
            medius_usb_clone_quiesce_and_clear();
        }
    }
    USB_CLONE_SPEED = speed;
    MEDIUS_CLONE_HIGH_SPEED = speed == 3;
    memset(MEDIUS_CLONE_EXCESS_ENDPOINT_INFO,0,3);
    if (section_15 != 0 && section_15_length >= 3)
        memcpy(MEDIUS_CLONE_EXCESS_ENDPOINT_INFO,section_15,3);
    if (string_3 == 0) {
        USB_CLONE_STRING3[0] = 0;
    } else {
        unsigned int string_length = strnlen(string_3,127);
        memcpy(USB_CLONE_STRING3,string_3,string_length);
        USB_CLONE_STRING3[string_length] = 0;
    }
    if (string_4 == 0) {
        USB_CLONE_STRING4[0] = 0;
    } else {
        unsigned int string_length = strnlen(string_4,127);
        memcpy(USB_CLONE_STRING4,string_4,string_length);
        USB_CLONE_STRING4[string_length] = 0;
    }
    if (string_5 == 0) {
        USB_CLONE_STRING5[0] = 0;
    } else {
        unsigned int string_length = strnlen(string_5,127);
        memcpy(USB_CLONE_STRING5,string_5,string_length);
        USB_CLONE_STRING5[string_length] = 0;
    }
    if (section_13 == 0 || section_13_length > 1536) {
        USB_CLONE_SECTION13_LENGTH = 0;
    } else {
        USB_CLONE_SECTION13_LENGTH = section_13_length;
        if (section_13_length != 0)
            memcpy(USB_CLONE_SECTION13_BYTES,section_13,section_13_length);
    }
    if (section_14 == 0 || section_14_length > 1039) {
        USB_CLONE_SECTION14_LENGTH = 0;
    } else {
        USB_CLONE_SECTION14_LENGTH = section_14_length;
        if (section_14_length != 0)
            memcpy(USB_CLONE_SECTION14_BYTES,section_14,section_14_length);
    }
    /* Copy metadata first, then validate categories and exact record boundaries. */
    if ((unsigned short)(section_16_length - 1U) < 512 && section_16 != 0) {
        memcpy(USB_CLONE_RAW_METADATA,section_16,section_16_length);
        memset(&USB_CLONE_PARSED_METADATA,0,76);
        if (section_16_length > 68 && USB_CLONE_RAW_METADATA[0] == 59) {
            for (unsigned int index = 1; index <= 59; ++index) {
                unsigned char category = ((const volatile unsigned char *)USB_CLONE_RAW_METADATA)[index];
                if (category > 6)
                    goto metadata_done;
            }
            unsigned char count = ((const volatile unsigned char *)USB_CLONE_RAW_METADATA)[68];
            unsigned short offset = 69;
            for (unsigned int index = 0; index < count; ++index) {
                unsigned int header_end = (unsigned int)offset + 4U;
                if (section_16_length < header_end)
                    goto metadata_done;
                unsigned char type = ((const volatile unsigned char *)USB_CLONE_RAW_METADATA)[offset + 2U];
                if (type > 2)
                    goto metadata_done;
                unsigned char payload_length = ((const volatile unsigned char *)USB_CLONE_RAW_METADATA)[offset + 3U];
                if (type != 0 && payload_length != 0)
                    goto metadata_done;
                offset = (unsigned short)(header_end + payload_length);
                if (section_16_length < offset)
                    goto metadata_done;
            }
            if (section_16_length == offset) {
                memcpy(USB_CLONE_PARSED_METADATA.categories,USB_CLONE_RAW_METADATA + 1,59);
                unsigned int metadata_word64 = *(const volatile unsigned int *)(USB_CLONE_RAW_METADATA + 64);
                unsigned int metadata_word60 = *(const volatile unsigned int *)(USB_CLONE_RAW_METADATA + 60);
                USB_CLONE_PARSED_METADATA.word64 = metadata_word64;
                USB_CLONE_PARSED_METADATA.word60 = metadata_word60;
                USB_CLONE_PARSED_METADATA.records = USB_CLONE_RAW_METADATA + 69;
                USB_CLONE_PARSED_METADATA.records_length = (unsigned short)(section_16_length - 69U);
            }
        }
    } else {
        memset(&USB_CLONE_PARSED_METADATA,0,76);
    }
metadata_done:
    ;
    /* Load identity-specific patches only when the cached identity is stale. */
    unsigned short vendor = 0;
    unsigned short product = 0;
    if (device_length >= 12) {
        unsigned char vendor_high = ((const volatile unsigned char *)device_descriptor)[9];
        unsigned char product_high = ((const volatile unsigned char *)device_descriptor)[11];
        unsigned char vendor_low = ((const volatile unsigned char *)device_descriptor)[8];
        unsigned char product_low = ((const volatile unsigned char *)device_descriptor)[10];
        vendor = (unsigned short)(((unsigned int)vendor_high << 8) | vendor_low);
        product = (unsigned short)(((unsigned int)product_high << 8) | product_low);
    }
    int reload_patch_cache = MEDIUS_DESCRIPTOR_PATCH_CACHE_LOADED == 0;
    if (!reload_patch_cache) {
        memw();
        unsigned short cached_vendor = USB_CLONE_PATCH_VENDOR;
        if (cached_vendor != vendor)
            reload_patch_cache = 1;
        else {
            memw();
            if (USB_CLONE_PATCH_PRODUCT != product)
                reload_patch_cache = 1;
        }
    }
    unsigned short patch_length = 0;
    unsigned int patch_load_status = 0;
    if (reload_patch_cache)
        patch_load_status = profile_load_patches(vendor,product,USB_CLONE_PATCH_LOAD_BUFFER,&patch_length,1137);
    void *patch_lock = REWRITE_MUTEX;
    if (patch_lock != 0)
        xQueueSemaphoreTake(patch_lock,0xffffffffU);
    memw();
    USB_CLONE_PATCH_VENDOR = vendor;
    memw();
    USB_CLONE_PATCH_PRODUCT = product;
    MEDIUS_CLONE_PATCH_IDENTITY_READY = 1;
    MEDIUS_DESCRIPTOR_PATCH_PERSISTENCE_MARKER = 1;
    if (reload_patch_cache) {
        memset(&USB_CLONE_CACHED_PATCH,0,1190);
        if (patch_load_status != 0) {
            /* Native keeps this length across subsequent clears and record callbacks. */
            unsigned short patch_blob_length = patch_length;
            if (patch_blob_length != 0) {
                memset(&USB_CLONE_CACHED_PATCH,0,1190);
                unsigned char count = ((const volatile unsigned char *)USB_CLONE_PATCH_LOAD_BUFFER)[0];
                unsigned short offset = 1;
                for (unsigned int index = 0; index < count; ++index) {
                    unsigned int header_end = (unsigned int)offset + 7U;
                    if (patch_blob_length < header_end) {
                        memset(&USB_CLONE_CACHED_PATCH,0,1190);
                        break;
                    }
                    const volatile unsigned char *record = USB_CLONE_PATCH_LOAD_BUFFER + offset;
                    unsigned int payload_high = record[6];
                    unsigned int payload_low = record[5];
                    unsigned int word_high = record[4];
                    unsigned int word_low = record[3];
                    unsigned char field0 = record[0];
                    unsigned char field1 = record[1];
                    unsigned char field2 = record[2];
                    unsigned int payload_length = (payload_high << 8) | payload_low;
                    unsigned int field_word = (word_high << 8) | word_low;
                    if (patch_blob_length < header_end + payload_length) {
                        memset(&USB_CLONE_CACHED_PATCH,0,1190);
                        break;
                    }
                    int record_result = medius_descriptor_patch_mutate(field0,field1,field2,field_word,
                        USB_CLONE_PATCH_LOAD_BUFFER + header_end,payload_length);
                    if (record_result < 0) {
                        memset(&USB_CLONE_CACHED_PATCH,0,1190);
                        break;
                    }
                    offset = (unsigned short)((unsigned short)header_end + payload_length);
                }
            }
        }
        MEDIUS_DESCRIPTOR_PATCH_CACHE_LOADED = (unsigned char)patch_load_status;
        CLONE_PATCH_REFUSED = 0;
    }
    memset(&USB_CLONE_ACTIVE_PATCH,0,1190);
    int patch_eligible = 0;
    if (IMPERFECT_FORWARDING_ALLOWED != 0)
        patch_eligible = DESCRIPTOR_PATCH_STORED->count != 0;
    patch_lock = REWRITE_MUTEX;
    if (patch_lock != 0)
        xQueueGenericSend(patch_lock,0,0,0);

    /* Build baseline descriptors, then try eligible patches and a guarded fallback. */
    MediusCloneSource descriptor_source;
    descriptor_source.device = device_descriptor;
    descriptor_source.configuration = configuration;
    descriptor_source.section_11 = section_11;
    descriptor_source.section_2 = section_2;
    descriptor_source.section_7 = section_7;
    descriptor_source.device_length = device_length;
    descriptor_source.configuration_length = configuration_length;
    descriptor_source.section_11_length = section_11_length;
    descriptor_source.section_2_length = section_2_length;
    descriptor_source.section_7_length = section_7_length;
    descriptor_source.configuration_index = configuration_index;
    unsigned int advertised_interval = clone_forced_interval();
    int tiling_result;
    unsigned char baseline_imperfect;
    unsigned char baseline_bits;
    unsigned char patched_imperfect = 0;
    unsigned char patched_bits = 0;
    const char *final_error = medius_clone_build_descriptors(&descriptor_source,advertised_interval,
        &tiling_result,0,&baseline_imperfect,&baseline_bits);
    const char *patch_error = 0;
    patch_lock = REWRITE_MUTEX;
    if (!patch_eligible) {
        if (patch_lock != 0) {
            xQueueSemaphoreTake(patch_lock,0xffffffffU);
            patch_lock = REWRITE_MUTEX;
        }
        CLONE_PATCH_REFUSED = 0;
        if (patch_lock != 0)
            xQueueGenericSend(patch_lock,0,0,0);
    } else {
        if (patch_lock != 0) {
            xQueueSemaphoreTake(patch_lock,0xffffffffU);
            patch_lock = REWRITE_MUTEX; /* Cached before the delegated copy. */
        }
        memcpy(&USB_CLONE_ACTIVE_PATCH,&USB_CLONE_CACHED_PATCH,1190);
        unsigned char copied_generation = DESCRIPTOR_PATCH_STORED->generation;
        if (patch_lock != 0)
            xQueueGenericSend(patch_lock,0,0,0);
        patch_error = medius_clone_build_descriptors(&descriptor_source,advertised_interval,
            &tiling_result,1,&patched_imperfect,&patched_bits);
        if (patch_error == 0) {
            unsigned int added_bits = final_error == 0 ? (unsigned int)patched_bits & ~(unsigned int)baseline_bits : 0;
            if (added_bits & 1U)
                patch_error = "bcdUSB >= 2.01 with no BOS";
            else if (added_bits & 2U)
                patch_error = "HID wDescriptorLength no longer equals the served report descriptor";
            else if (added_bits & 4U)
                patch_error = "an endpoint wMaxPacketSize is below the report it must carry";
        }
        if (patch_error == 0) {
            final_error = 0;
            patch_lock = REWRITE_MUTEX;
            if (patch_lock != 0) {
                xQueueSemaphoreTake(patch_lock,0xffffffffU);
                patch_lock = REWRITE_MUTEX;
            }
            CLONE_PATCH_REFUSED = 0;
            if (patch_lock != 0)
                xQueueGenericSend(patch_lock,0,0,0);
        } else {
            patch_lock = REWRITE_MUTEX;
            if (patch_lock != 0)
                xQueueSemaphoreTake(patch_lock,0xffffffffU);
            memset(&USB_CLONE_ACTIVE_PATCH,0,1190);
            patch_lock = REWRITE_MUTEX;
            if (patch_lock != 0)
                xQueueGenericSend(patch_lock,0,0,0);
            final_error = medius_clone_build_descriptors(&descriptor_source,advertised_interval,
                &tiling_result,0,&baseline_imperfect,&baseline_bits);
            patch_lock = REWRITE_MUTEX;
            if (patch_lock != 0) {
                xQueueSemaphoreTake(patch_lock,0xffffffffU);
                patch_lock = REWRITE_MUTEX;
            }
            unsigned char fresh_generation = DESCRIPTOR_PATCH_STORED->generation;
            CLONE_PATCH_REFUSED = final_error == 0 && copied_generation == fresh_generation;
            if (patch_lock != 0)
                xQueueGenericSend(patch_lock,0,0,0);
        }
    }
    if (tiling_result < 0) {
        unsigned int timestamp = esp_log_timestamp();
        esp_log_write(2,"usbdev",
            "W (%lu) %s: config descriptors do not tile -> serving them at the rate the device declared\n",
            timestamp,"usbdev");
        advertised_interval = 0;
    }
    if (final_error != 0) {
        unsigned int timestamp = esp_log_timestamp();
        const char *outcome = baseline_imperfect == 0 ? "not cloning" :
            "refusing; opt into imperfect-clone to allow";
        esp_log_write(1,"usbdev","E (%lu) %s: %s -> %s\n",
            timestamp,"usbdev",final_error,outcome);
        goto rejected;
    }
    if (patch_error != 0) {
        unsigned int timestamp = esp_log_timestamp();
        esp_log_write(1,"usbdev",
            "E (%lu) %s: descriptor patch refused (%s) -> cloning the device unpatched\n",
            timestamp,"usbdev",patch_error);
    }
    unsigned int active_timestamp = esp_log_timestamp();
    unsigned short served_length = MEDIUS_CLONE_DEVICE_LENGTH;
    unsigned int served_vendor = 0;
    unsigned int served_product = 0;
    if (served_length >= 10) {
        served_vendor = QUERY_DEVICE_DESCRIPTOR->vendor;
        if (served_length >= 12)
            served_product = QUERY_DEVICE_DESCRIPTOR->product;
    }
    unsigned short served_configuration_length = MEDIUS_CLONE_SELECTED_LENGTH;
    int served_interfaces = USB_INTERFACE_COUNT;
    const char *version = device_version_string();
    esp_log_write(3,"usbdev",
        "I (%lu) %s: clone active: VID=%04X PID=%04X cfg=%u ifs=%d fw=%s\n",
        active_timestamp,"usbdev",served_vendor,served_product,served_configuration_length,
        served_interfaces,version);
    /* Publish descriptor/interface registrations and advance session bookkeeping. */
    MediusCloneExtraDescriptor *extra_descriptor = 0;
    if ((unsigned short)(section_7_length - 1U) < 256 && section_7 != 0) {
        USB_CLONE_EXTRA_DESCRIPTOR.length = section_7_length;
        USB_CLONE_EXTRA_DESCRIPTOR.data = MEDIUS_CLONE_BOS_BYTES;
        extra_descriptor = &USB_CLONE_EXTRA_DESCRIPTOR;
    }
    USB_CLONE_EXTRA_DESCRIPTOR_POINTER = extra_descriptor;
    usbd_desc_register(0,USB_CLONE_DESCRIPTOR_TABLE);
    for (unsigned int index = 0; index < 6; ++index)
        usbd_add_interface(0,(unsigned char *)&HID_INTERFACES[index]);
    for (unsigned int index = 0; index < 6; ++index)
        USB_CLONE_GENERATION_SLOTS[index] = 0xffffffffU;
    memw();
    unsigned int generation = DEVICE_OUT_GENERATION_RW;
    void *sync_gate = CONTROL_FORWARD_GATE;
    MEDIUS_EP0_CACHE_GENERATION = generation;
    if (sync_gate != 0) {
        int taken = xQueueSemaphoreTake(sync_gate,500);
        memw();
        unsigned int latest_generation = DEVICE_OUT_GENERATION_RW;
        memw();
        CONTROL_FORWARDED_GENERATION = latest_generation;
        if (taken == 1) {
            sync_gate = CONTROL_FORWARD_GATE;
            xQueueGenericSend(sync_gate,0,0,0);
        }
    }
    memw();
    USB_PUBLISHED_CONFIGURATION_GENERATION = 0xffffffffU;
    memw();
    unsigned int revision = REPORT_NORMALIZATION_EPOCH;
    patch_lock = REWRITE_MUTEX;
    memw();
    REPORT_NORMALIZATION_EPOCH = revision + 1U;
    if (patch_lock != 0)
        xQueueSemaphoreTake(patch_lock,0xffffffffU);
    clone_refresh_report_bindings(1,0);
    patch_lock = REWRITE_MUTEX;
    if (patch_lock != 0)
        xQueueGenericSend(patch_lock,0,0,0);

    /* Restore selected-interface report, period and feature state from the profile. */
    int selected_interface = FIXED_INPUTS->interface;
    unsigned char restored_report[64];
    if (selected_interface >= 0) {
        memw();
        unsigned short current_vendor = USB_CLONE_RESTORE_VENDOR;
        memw();
        unsigned short current_product = USB_CLONE_RESTORE_PRODUCT;
        profile_protect_and_queue_stamp(current_vendor,current_product);
        memw();
        current_vendor = USB_CLONE_RESTORE_VENDOR;
        memw();
        current_product = USB_CLONE_RESTORE_PRODUCT;
        volatile unsigned short report_length = 0;
        int report_status = profile_load_baseline(current_vendor,current_product,restored_report,
            (unsigned short *)&report_length,64);
        unsigned int report_id_address = (unsigned int)HID_REPORT_LAYOUTS +
            (unsigned int)selected_interface * 304U + 4U;
        unsigned char report_id = *(const volatile unsigned char *)report_id_address;
        int matches_id = 1;
        if (report_id != 0) {
            unsigned short received = report_length;
            if (received == 0)
                goto report_done;
            matches_id = restored_report[0] == report_id;
        }
        if (report_status != 0) {
            unsigned short received = report_length;
            unsigned short expected = FIXED_INPUTS->expected_length;
            if (received == expected && received <= 64 && matches_id) {
                memcpy(USB_CLONE_REPORT_PRIMARY,restored_report,received);
                unsigned short second_length = report_length;
                memcpy(USB_CLONE_REPORT_SECONDARY,restored_report,second_length);
                memw();
                USB_CLONE_REPORT_RESTORED = 1;
            }
        }
report_done:
        ;
        unsigned char endpoint = USB_INTERFACE_ENDPOINTS[selected_interface];
        volatile unsigned short requested_period = 0;
        unsigned int endpoint_interval = clone_endpoint_interval_byte(endpoint);
        memw();
        current_vendor = USB_CLONE_RESTORE_VENDOR;
        memw();
        current_product = USB_CLONE_RESTORE_PRODUCT;
        int period_status = profile_load_period(current_vendor,current_product,(unsigned short *)&requested_period);
        if (period_status != 0) {
            unsigned int period = requested_period;
            if ((unsigned short)(period - 125U) < 31875) {
                unsigned int minimum = (endpoint_interval & 65535U) * 1000U;
                if (period < minimum) {
                    requested_period = (unsigned short)minimum;
                    period = minimum & 65535U;
                }
                unsigned int rounded;
                unsigned int phase;
                if (period + 500U < 1000) {
                    rounded = 1000;
                    phase = 500;
                } else {
                    rounded = ((period + 500U) / 1000U) * 1000U;
                    phase = (((rounded - 500U) / 1000U) + 1U) * 1000U - 500U;
                }
                memw();
                REPORT_LEARNED_PERIOD = rounded;
                memw();
                REPORT_ACTIVE_THRESHOLD = phase;
                if (rounded != period) {
                    memw();
                    PROFILE_PERIOD_PENDING = 1;
                }
            }
        }
        unsigned int feature_length_address = (unsigned int)HID_REPORT_LAYOUTS +
            (unsigned int)selected_interface * 304U + 216U;
        unsigned char feature_expected = *(const volatile unsigned char *)feature_length_address;
        if (feature_expected != 0) {
            memw();
            current_vendor = USB_CLONE_RESTORE_VENDOR;
            memw();
            current_product = USB_CLONE_RESTORE_PRODUCT;
            unsigned char feature[2];
            volatile unsigned short feature_length = 0;
            int feature_status = profile_load_normalization(current_vendor,current_product,feature,
                (unsigned short *)&feature_length,2);
            if (feature_status != 0) {
                unsigned short received = feature_length;
                unsigned char expected = *(const volatile unsigned char *)feature_length_address;
                if (received == expected && received != 0) {
                    unsigned char first_byte = feature[0];
                    USB_CLONE_RESTORED_FEATURE[0] = first_byte;
                    if (received != 1) {
                        unsigned char second_byte = feature[1];
                        USB_CLONE_RESTORED_FEATURE[1] = second_byte;
                    }
                }
            }
        }
        memw();
        PROFILE_NORMALIZATION_PENDING = 0;
    }
    /* Startup success is the existence of the EP0 task, independent of init status. */
    medius_usb_log_interface_slots("clone bound");
    medius_usb_register_clone_endpoints();
    unsigned int free_internal = heap_caps_get_free_size(0x804);
    unsigned int largest_internal = heap_caps_get_largest_free_block(0x804);
    int initialized = usbd_initialize(0,(void *)0x60080000U,medius_usb_device_event);
    int task_exists = medius_usbd_ep0_task_exists(0);
    if (task_exists != 0) {
        memw();
        USB_CLONE_ADVERTISED_INTERVAL = (unsigned char)advertised_interval;
        memw();
        CLONE_ACTIVE = 1;
        unsigned int timestamp = esp_log_timestamp();
        esp_log_write(3,"usbdev",
            "I (%lu) %s: usbd_initialize rc=%d, internal RAM %u free, %u in one block\n",
            timestamp,"usbdev",initialized,free_internal,largest_internal);
        configuration_mutex = REPORT_MUTEX;
        if (configuration_mutex != 0)
            xQueueGenericSend(configuration_mutex,0,0,0);
        memw();
        unsigned char notification = USB_CLONE_ADVERTISED_INTERVAL;
        link_send_wait100(0x30,0,&notification,1);
        return 1;
    }
    unsigned int timestamp = esp_log_timestamp();
    esp_log_write(1,"usbdev",
        "E (%lu) %s: clone not started: no RAM for the control task (%u free, %u in one block)\n",
        timestamp,"usbdev",free_internal,largest_internal);
    configuration_mutex = REPORT_MUTEX;
    if (configuration_mutex != 0)
        xQueueGenericSend(configuration_mutex,0,0,0);
    return 0;
rejected:
    configuration_mutex = REPORT_MUTEX;
    if (configuration_mutex != 0)
        xQueueGenericSend(configuration_mutex,0,0,0);
    return 1;
}

/* Native entry: 0x420282b8. */
/* Original function-byte SHA-256:
 * dad439d96ed2fe7d31dd17a8a74f9630a5632d2fe63476f11d7f57e3893eeacb. */
/*
 * Return the first matching selected-alternate endpoint's raw bInterval BYTE,
 * else0. Cache configuration HALFWORD length; length<2 returns0 before pointer
 * read. Then cache configuration pointer, initially accepting endpoints before
 * any full interface descriptor. Read descriptor size THEN type before checking
 * size>=2 and offset+size<=length; malformed chain returns0. A>=9-byte interface
 * updates eligibility from alternate_settings[bInterfaceNumber]==bAlternateSetting
 * (unchecked index); short interfaces leave eligibility unchanged. A>=7-byte
 * endpoint matches its complete address BYTE against the full-WORD argument,
 * with no low-byte masking or transfer-type test. Advance offset modulo65536.
 * No speed-dependent decoding, timeout, lock, null checks or descriptor copy.
 */
unsigned char clone_endpoint_interval_byte(unsigned int endpoint)
{
    unsigned short length = QUERY_CONFIGURATION_LENGTH;
    if (length < 2) return 0;
    const volatile unsigned char *configuration = QUERY_CONFIGURATION;
    const volatile unsigned char *alternates = CLONE_ALTERNATE_SETTINGS;
    unsigned int offset = 0;
    bool selected = true;
    do {
        const volatile unsigned char *descriptor = configuration + offset;
        unsigned int size = descriptor[0];
        unsigned int type = descriptor[1];
        if (size < 2 || offset + size > length) return 0;
        if (type == 4 && size >= 9) {
            unsigned char interface = descriptor[2];
            unsigned char alternate = descriptor[3];
            selected = alternates[interface] == alternate;
        } else if (type == 5 && size >= 7 && selected && descriptor[2] == endpoint) {
            return descriptor[6];
        }
        offset = (unsigned short)(offset + size);
    } while (offset + 1U < length);
    return 0;
}

/* Native entry: 0x42028328. */
/* Original function-byte SHA-256:
 * 2be5d3b16ef02e519a84b1c99980d5809b5ffc4cc08430e8f13c127aa4b490fc. */
/*
 * Return the first nonzero raw BYTE in this order: capacity exceeded, high
 * speed, served bulk endpoint present, configurations missing, HID isochronous,
 * served isochronous endpoint present, report-capture exceeded, report missing,
 * MEMW/read interval-edited. Only if all nine are zero, return the excess-
 * endpoint-info BYTE!=0 as0/1. Each field is read once; no lock, write or call.
 * This is neither a count nor a bitmask; non-boolean flag bytes survive intact.
 * Sequential observations do not prove the clone is coherent or usable.
 */
unsigned char clone_degradation_status(void)
{
    unsigned char problem = CLONE_CAPACITY_EXCEEDED;
    if (problem != 0) return problem;
    problem = MEDIUS_CLONE_HIGH_SPEED;
    if (problem != 0) return problem;
    problem = MEDIUS_CLONE_SERVED_ENDPOINTS->has_bulk;
    if (problem != 0) return problem;
    problem = MEDIUS_CLONE_CONFIGURATIONS_MISSING;
    if (problem != 0) return problem;
    problem = MEDIUS_CLONE_HID_ISOCHRONOUS;
    if (problem != 0) return problem;
    problem = MEDIUS_CLONE_SERVED_ENDPOINTS->has_isochronous;
    if (problem != 0) return problem;
    problem = MEDIUS_CLONE_REPORT_CAPTURE_EXCEEDED;
    if (problem != 0) return problem;
    problem = MEDIUS_CLONE_REPORT_MISSING;
    if (problem != 0) return problem;
    memw(); problem = MEDIUS_CLONE_INTERVAL_EDITED;
    if (problem != 0) return problem;
    return *MEDIUS_CLONE_EXCESS_ENDPOINT_INFO != 0;
}

/* Native entry: 0x42029a30. */
/* Original function-byte SHA-256:
 * f7cf42164027e17bcf996041c7f6dbc1c147d12906348b4a618e9a969948599e. */
/*
 * Determine whether descriptor patches require reapplication. Read identity-
 * ready first; zero returns0. Then sample raw imperfect-allow BYTE. Disabled
 * or empty stored table returns served-count!=0. Refused patches return0.
 * Otherwise unequal served/stored counts, or the first unequal record/payload,
 * return the sampled RAW allow byte. Equal nonempty tables return0.
 * Compare identity HALF, descriptor-index BYTE, offset HALF, served then stored
 * length HALF, then memcmp(stored bytes,served bytes,served length). Skip byte3
 * and compare payload contents rather than pool offsets. Counts/pool offsets
 * are trusted without16/1024 bounds. No mutation,fence,local lock or snapshot.
 */
unsigned char descriptor_patches_need_refresh(void)
{
    if (MEDIUS_CLONE_PATCH_IDENTITY_READY == 0) return 0;
    unsigned char allow = IMPERFECT_FORWARDING_ALLOWED;
    const volatile DescriptorPatchTable *stored = DESCRIPTOR_PATCH_STORED;
    const volatile DescriptorPatchTable *served = DESCRIPTOR_PATCH_SERVED;
    if (allow == 0) return served->count != 0;
    unsigned int stored_count = stored->count;
    if (stored_count == 0) return served->count != 0;
    if (CLONE_PATCH_REFUSED != 0) return 0;
    unsigned int served_count = served->count;
    if (served_count != stored_count) return allow;
    for (unsigned int index = 0; index < served_count; ++index) {
        const volatile DescriptorPatchRecord *wanted = &stored->records[index];
        const volatile DescriptorPatchRecord *active = &served->records[index];
        unsigned short stored_identity = wanted->identity;
        unsigned short served_identity = active->identity;
        if (stored_identity != served_identity) return allow;
        unsigned char stored_index = wanted->descriptor_index;
        unsigned char served_index = active->descriptor_index;
        if (stored_index != served_index) return allow;
        unsigned short stored_offset = wanted->offset;
        unsigned short served_offset = active->offset;
        if (stored_offset != served_offset) return allow;
        unsigned short served_length = active->length;
        unsigned short stored_length = wanted->length;
        if (stored_length != served_length) return allow;
        unsigned short served_payload = active->payload_offset;
        unsigned short stored_payload = wanted->payload_offset;
        if (memcmp((const unsigned char *)stored->payload + stored_payload,
            (const unsigned char *)served->payload + served_payload,served_length) != 0)
            return allow;
    }
    return 0;
}

/* Native entry: 0x403942a0. */
/* Original function-byte SHA-256:
 * c55c31a37a1a5284463bcca7e50efc1d95e84133eee09ff698c6fd48837628c7. */
/*
 * Device-descriptor callback in the registered table at 0x3fcaa7c4, slot 0.
 * Return the shared clone device-descriptor buffer at 0x3fcb4258 for every
 * speed value. No descriptor inspection, length check, copy, allocation,
 * validation or MEMW; callers borrow the buffer while descriptor builders may
 * update it. The speed parameter is supplied by the USB core and ignored.
 */
const unsigned char *medius_clone_get_device_descriptor(unsigned int speed)
{
    (void)speed;
    return MEDIUS_CLONE_DEVICE_BYTES;
}
