/* Medius v3.4.7 device — usb/device_core.c.
 * Recovered C and native assembly, grouped for source navigation.
 * Original entry addresses, firmware-byte hashes and function comments follow.
 */

#include "../include/types.h"

/* EP0 reconstruction utilities: inline native copy paths, not extra entries.
 * length is admitted at <= 2048 by the owning worker. Volatile accesses retain
 * the native forward copy widths/order, including overlapping-buffer effects.
 */
static __attribute__((always_inline)) inline void ep0_copy_response(
    unsigned char *destination_buffer,const unsigned char *source_buffer,
    unsigned int length)
{
    volatile unsigned char *destination = destination_buffer;
    const volatile unsigned char *source = source_buffer;
    if ((((unsigned int)destination ^ (unsigned int)source) & 3U) == 0) {
        while (((unsigned int)destination & 3U) != 0 && length != 0) {
            unsigned char byte = *source++;
            *destination++ = byte;
            --length;
        }
        while (length >= 16U) {
            unsigned int word = *(const volatile unsigned int *)(source + 0);
            *(volatile unsigned int *)(destination + 0) = word;
            word = *(const volatile unsigned int *)(source + 4);
            *(volatile unsigned int *)(destination + 4) = word;
            word = *(const volatile unsigned int *)(source + 8);
            *(volatile unsigned int *)(destination + 8) = word;
            word = *(const volatile unsigned int *)(source + 12);
            *(volatile unsigned int *)(destination + 12) = word;
            source += 16;
            destination += 16;
            length -= 16;
        }
        while (length >= 4U) {
            unsigned int word = *(const volatile unsigned int *)source;
            source += 4;
            *(volatile unsigned int *)destination = word;
            destination += 4;
            length -= 4;
        }
    } else {
        while (((unsigned int)source & 3U) != 0 && length != 0) {
            unsigned char byte = *source++;
            *destination++ = byte;
            --length;
        }
        while (length >= 16U) {
            unsigned int word = *(const volatile unsigned int *)(source + 0);
            destination[1] = (unsigned char)(word >> 8);
            destination[2] = (unsigned char)(word >> 16);
            destination[3] = (unsigned char)(word >> 24);
            destination[0] = (unsigned char)word;
            word = *(const volatile unsigned int *)(source + 4);
            destination[5] = (unsigned char)(word >> 8);
            destination[6] = (unsigned char)(word >> 16);
            destination[7] = (unsigned char)(word >> 24);
            destination[4] = (unsigned char)word;
            word = *(const volatile unsigned int *)(source + 8);
            destination[9] = (unsigned char)(word >> 8);
            destination[10] = (unsigned char)(word >> 16);
            destination[11] = (unsigned char)(word >> 24);
            destination[8] = (unsigned char)word;
            word = *(const volatile unsigned int *)(source + 12);
            destination[12] = (unsigned char)word;
            destination[13] = (unsigned char)(word >> 8);
            destination[14] = (unsigned char)(word >> 16);
            destination[15] = (unsigned char)(word >> 24);
            source += 16;
            destination += 16;
            length -= 16;
        }
        while (length >= 4U) {
            unsigned int word = *(const volatile unsigned int *)source;
            source += 4;
            destination[0] = (unsigned char)word;
            destination[1] = (unsigned char)(word >> 8);
            destination[2] = (unsigned char)(word >> 16);
            destination[3] = (unsigned char)(word >> 24);
            destination += 4;
            length -= 4;
        }
    }
    while (length != 0) {
        unsigned char byte = *source++;
        *destination++ = byte;
        --length;
    }
}

/* Native entry: 0x4037b2b0. */
/* Original function-byte SHA-256:
 * d23798f16daf2ab276e7da936c96f4692d8e9875d729010999ddc0b08752dc06. */
/*
 * Starts a controller write, copying only non-NULL unaligned buffers through
 * the shared 2,048-byte bounce area. Aligned buffers and NULL buffers pass
 * through with the original length, without a size check.
 *
 * For unaligned input, records endpoint BYTE, source WORD, length WORD and
 * wrapping counter WORD in that order, with the native MEMW before each
 * access. Zero length then selects NULL; length above 2,048 returns -1 after
 * recording diagnostics. Otherwise copies exactly length bytes and forwards
 * the bounce pointer. Returns the underlying write result.
 * No lock, private bounce allocation or asynchronous lifetime protection.
 */
int usb_device_write_aligned(unsigned char bus,unsigned char endpoint,
                              unsigned char *buffer,unsigned int length)
{
    if (buffer != 0 && ((unsigned int)buffer & 3U) != 0) {
        volatile UsbdUnalignedWriteDiagnostics *diagnostics =
            USBD_UNALIGNED_WRITE;
        memw();
        diagnostics->endpoint = endpoint;
        memw();
        diagnostics->source_buffer = buffer;
        memw();
        diagnostics->length = length;
        memw();
        unsigned int count = diagnostics->unaligned_count;
        memw();
        diagnostics->unaligned_count = count + 1U;
        if (length == 0) {
            buffer = 0;
        } else {
            if (length > 2048U) return -1;
            memcpy(MEDIUS_USBD_IN_BOUNCE,buffer,length);
            buffer = MEDIUS_USBD_IN_BOUNCE;
        }
    }
    return usbd_ep_start_write(bus,endpoint,buffer,length);
}

/* Native entry: 0x4037b328. */
/*
 * Medius v3.4.7 — device application; 0x4037b328.
 *
 * Records endpoint activity and either refreshes the first matching interface timestamp or
 * disables the shared IN-activity interrupt bit.
 *
 * Calls: esp_timer_get_time, vPortExitCritical, xPortEnterCriticalTimeout.
 *
 * Called by: USBD_IRQHandler.
 *
 * Original function-byte SHA-256:
 * 4e747ea4ec39215ee631ab1724cc6a3e9bdd779fd38b65ca56100b19bec9577d.
 */

/*
 * ignored_bus: Unused native argument; this helper uses fixed controller/state addresses.
 * endpoint: Only low four bits select one of sixteen timestamp entries.
 * Returns: No value; critical-entry status is ignored.
 * Requirements/effects: Samples software time before entering the activity mux. For nonzero
 *   endpoint reads its previous low word then high word once and computes a wrapping64 age. Signed
 *   age>999 selects the stale path: snapshots signed interface count and, only if positive, scans
 *   endpoint-map bytes for the first low4 match, storing current interface time low then high. No
 *   match/nonpositive count still preserves the interrupt mask. Endpoint0 or age<=999 (including
 *   negative age) instead MEMW/reads DIEPMSK, MEMW/clears only bit13. Every path stores endpoint
 *   time low then high before unlock. No notification, payload copy, bus validation, map-capacity
 *   clamp or local timeout occurs. Time words are separate accesses under this mux; no
 *   hardware/coherent cross-reader timing claim follows.
 */

void medius_usb_in_endpoint_activity_update(unsigned int ignored_bus,unsigned int endpoint)
{
    (void)ignored_bus;
    unsigned long long now = (unsigned long long)esp_timer_get_time();
    unsigned int now_low = (unsigned int)now;
    unsigned int now_high = (unsigned int)(now >> 32);
    xPortEnterCriticalTimeout(&CREDIT_LOCK,0xffffffffU);
    unsigned int endpoint_index = endpoint & 15U;
    volatile TimestampWords *endpoint_time =
        &USB_IN_ACTIVITY_TIMESTAMPS[endpoint_index];
    int stale = 0;
    if (endpoint_index != 0) {
        unsigned int previous_low = endpoint_time->low;
        unsigned int previous_high = (unsigned int)endpoint_time->high;
        unsigned long long previous = ((unsigned long long)previous_high << 32) | previous_low;
        unsigned long long age = now - previous;
        /* Native signed64(age)>999, expressed without signed-overflow arithmetic. */
        stale = age < 0x8000000000000000ULL && age > 999ULL;
    }
    if (stale) {
        int interface_count = USB_INTERFACE_COUNT;
        if (interface_count > 0) {
            const volatile unsigned char *endpoint_map = USB_INTERFACE_ENDPOINTS;
            for (unsigned int interface_index = 0; interface_index < (unsigned int)interface_count; ++interface_index) {
                unsigned char mapped_endpoint = endpoint_map[interface_index];
                if ((mapped_endpoint & 15U) == endpoint_index) {
                    volatile TimestampWords *interface_time =
                        &REPORT_LAST_IN_ACTIVITY[interface_index];
                    interface_time->low = now_low;
                    interface_time->high = now_high;
                    break;
                }
            }
        }
    } else {
        memw();
        unsigned int enabled_interrupts = MEDIUS_USB_DEVICE_IN_INTERRUPT_MASK;
        memw();
        MEDIUS_USB_DEVICE_IN_INTERRUPT_MASK = enabled_interrupts & 0xffffdfffU;
    }
    endpoint_time->low = now_low;
    endpoint_time->high = now_high;
    vPortExitCritical(&CREDIT_LOCK);
}

/* Native entry: 0x40380720. */
/* Original function-byte SHA-256:
 * 25988b426cda13d6b0d8764fff8c567fc062d16bdb9e441f29052b40f0c2b8b5. */
/*
 * Replaces DCFG address bits 4..10 using two distinct read/modify/write
 * operations: first clear the field, then reread DCFG and OR the low seven
 * address bits. Retains MEMW before each of the two reads and two writes.
 * bus is the unchecked byte index into eight-byte controller bindings.
 * Returns zero; no validation, status wait or lock is supplied.
 */
int usbd_set_address(unsigned char bus,unsigned char address)
{
    volatile MediusDwc2CoreRegisters *registers =
        MEDIUS_USBD_CONTROLLERS[bus].registers;
    memw();
    unsigned int configuration = registers->device_configuration;
    memw();
    registers->device_configuration = configuration & 0xfffff80fU;
    memw();
    configuration = registers->device_configuration;
    memw();
    registers->device_configuration = configuration | ((address & 0x7fU) << 4);
    return 0;
}

/* Native entry: 0x4038075c. */
/* Original function-byte SHA-256:
 * 58944aa28ae91cd918df475255786e2881e7143cb2e347f5b669db3359bccb03. */
/*
 * Returns -1 if one DSTS sample has suspend bit 0 clear. Otherwise sets
 * DCTL remote-wakeup bit 0, calls the scheduler-delay wrapper with 10, then
 * reloads the controller pointer and clears bit 0 in its current DCTL.
 * Returns zero after clearing; the delay is not a measured pulse duration.
 * Five native MEMW boundaries are retained. No bus bounds check or lock;
 * the controller binding can differ between the set and clear operations.
 */
int usbd_set_remote_wakeup(unsigned char bus)
{
    const volatile MediusUsbdControllerBinding *binding =
        &MEDIUS_USBD_CONTROLLERS[bus];
    volatile MediusDwc2CoreRegisters *registers = binding->registers;
    memw();
    if ((registers->device_status & 1U) == 0) return -1;
    memw();
    unsigned int control = registers->device_control;
    memw();
    registers->device_control = control | 1U;
    medius_usb_scheduler_delay_u8(10);
    registers = binding->registers;
    memw();
    control = registers->device_control;
    memw();
    registers->device_control = control & ~1U;
    return 0;
}

/* Native entry: 0x403807ac. */
/* Original function-byte SHA-256:
 * 1d7c88aa0a20c9ab9fcabff0a51b2ebeb70e34c423d17cafbcaee772aff32151. */
/*
 * Samples DSTS once after MEMW and decodes bits 1..2: 0 returns 3 (high),
 * 4 returns 1 (low), and 2 or 6 returns 2 (full/default).
 * Uses an unchecked byte bus index; no polling, lock or status validation.
 */
unsigned char usbd_get_port_speed(unsigned char bus)
{
    volatile MediusDwc2CoreRegisters *registers =
        MEDIUS_USBD_CONTROLLERS[bus].registers;
    memw();
    unsigned int speed_encoding = registers->device_status & 6U;
    if (speed_encoding == 0) return 3;
    return speed_encoding == 4U ? 1 : 2;
}

/* Native entry: 0x403829e4. */
/*
 * Medius v3.4.7 — device application; 0x403829e4.
 *
 * Tests the current CherryUSB device configuration byte.
 *
 * Called by: FUN_40377854, FUN_403919a8, FUN_40395180, FUN_40395694, FUN_40396168, FUN_40399be8,
 * FUN_4202dd98, input_timer_cb, transmit_watchdog_task, FUN_420334c4, FUN_420335c8, FUN_4203374c,
 * FUN_42033bf4, FUN_420355c8, raw_endpoint_send, health_flags_get, report_process,
 * outbound_forward_task.
 *
 * Original function-byte SHA-256:
 * 58b1b2f43e536bcc0bd58e9a8cd7f2372ee8c93fb4331cc9241bfe4c90432d48.
 */

/*
 * bus_id: low8 selects a bus configuration-byte view with native stride0xaf4.
 * Returns true iff that byte is nonzero. No MEMW, locks, pointer/index bounds,
 * cable/suspend check or endpoint inspection. The view begins at each bus's
 * configuration field (+0x81c from its core object), not its allocation start.
 * Requires an initialized accessible bus; values outside configured bus count
 * still form/read the native unchecked address.
 */
bool usb_device_is_configured(unsigned int bus_id)
{
    return MEDIUS_USB_CONFIGURED_VIEWS[(unsigned char)bus_id].configuration != 0;
}

/* Native entry: 0x40382a04. */
/*
 * Medius v3.4.7 — device application; 0x40382a04.
 *
 * Dispatches a USB class event to registered objects, optionally selecting their interface-number
 * byte.
 *
 * Called by: usbd_setup_request_handler, medius_usbd_reset_event.
 *
 * Indirect calls: cached class notification callbacks, with optional interface filtering.
 *
 * Original function-byte SHA-256:
 * 43e61e120eafc4770bbf40d93d609f6426d13e3329606e21cade593a52632a3a.
 */

/*
 * bus: Full32 bus word; count address uses all bits, pointer-list address uses low16.
 * event: Full32 event forwarded unchanged to each callable class.
 * descriptor: Optional filter data; non-NULL requires at least three readable bytes and selects
 *   descriptor byte2.
 * Returns: No value. Callback return registers are ignored.
 * Requirements/effects: Initial zero count returns without loading a class pointer. Otherwise
 *   loads each pointer once, skips NULL object/callback, broadcasts for NULL descriptor or invokes
 *   only when a freshly read descriptor byte2 matches the class interface byte24. Callback at
 *   object+12 is cached before filtering and invocation. After every iteration increments byte
 *   index, rereads live count, advances list pointer four bytes and stops when index>=count.
 *   Changes to later pointers/count/filter bytes affect subsequent entries. No local lock, list-
 *   capacity, callback lifetime or descriptor-length check occurs. At most255 entries are visited;
 *   mismatched full32/low16 bus arithmetic and wrapped raw addresses are retained.
 */

void medius_usbd_class_event_notify(unsigned int bus,unsigned int event,unsigned char *descriptor)
{
    const volatile unsigned char *count = &MEDIUS_USBD_WAKE_BUSES[bus].interface_count;
    if (*count == 0)
        return;
    MediusUsbdClassEventView * const volatile *entry =
        (MediusUsbdClassEventView * const volatile *)
            &MEDIUS_USBD_WAKE_BUSES[bus & 0xffffU].interface_objects[0];
    unsigned char index = 0;
    do {
        MediusUsbdClassEventView *object = *entry;
        if (object != 0) {
            MediusUsbdClassEventHandler callback = object->notify;
            if (callback != 0) {
                if (descriptor == 0) {
                    callback(bus,event,0);
                } else {
                    unsigned char requested_interface = ((const volatile unsigned char *)descriptor)[2];
                    unsigned char object_interface = object->interface_number;
                    if (requested_interface == object_interface)
                        callback(bus,event,descriptor);
                }
            }
        }
        index = (unsigned char)(index + 1U);
        unsigned char live_count = *count;
        entry = (MediusUsbdClassEventView * const volatile *)((unsigned int)entry + 4U);
        if (index >= live_count)
            break;
    } while (1);
}

/* Native entry: 0x40382ad8. */
/* Original function-byte SHA-256:
 * 3e367bc547916e6cec513f6525e60e768defa6d405bc18519b8e1bff137913fb. */
/*
 * Advances EP0 only from cached state 1 (IN data) or 3 (IN status). Consumes
 * min(remaining,bytes), stores the advanced cursor then reduced remaining,
 * and submits another IN write if bytes remain. A pending ZLP is cleared
 * and submitted as NULL/0 without changing the state.
 *
 * Otherwise reads SETUP length as HALF, then request type as BYTE. For a
 * nonempty IN request, reads the per-bus status flag after MEMW, sets state 4
 * and arms NULL/0 OUT status only when that cached flag is zero. In other
 * cases cached state 3 becomes 0; state 1 stays unchanged. Ignores endpoint
 * and all driver results. Unchecked byte bus, cursor arithmetic wraps at
 * 32 bits, and no lock or lifetime protection is supplied.
 */
void usbd_event_ep0_in_complete_handler(unsigned char bus,
                                       unsigned int unused_endpoint,unsigned int bytes)
{
    (void)unused_endpoint;
    volatile MediusUsbdWakeBusView *core = &MEDIUS_USBD_WAKE_BUSES[bus];
    unsigned char state = core->state.ep0_next_state;
    if ((state & 0xfdU) != 1U) return;
    unsigned int remaining = core->transfer_remaining;
    unsigned char *cursor = core->transfer_cursor;
    unsigned int consumed = remaining < bytes ? remaining : bytes;
    cursor = (unsigned char *)((unsigned int)cursor + consumed);
    remaining -= consumed;
    core->transfer_cursor = cursor;
    core->transfer_remaining = remaining;
    if (remaining != 0) {
        usb_device_write_aligned(bus,0x80,cursor,remaining);
        return;
    }
    if (core->send_zlp != 0) {
        core->send_zlp = 0;
        usb_device_write_aligned(bus,0x80,0,0);
        return;
    }
    if (core->setup.length != 0 && (core->setup.request_type & 0x80U) != 0) {
        memw();
        unsigned char status_suppressed = MEDIUS_USBD_EP0_STATUS_FLAGS[bus];
        core->state.ep0_next_state = 4;
        if (status_suppressed == 0) usbd_ep_start_read(bus,0,0,0);
        return;
    }
    if (state == 3) core->state.ep0_next_state = 0;
}

/* Native entry: 0x40382b64. */
/* Original function-byte SHA-256:
 * 50fec17a85257d62caa1177f0cf16c596ecb3c9911c3acee901789f59fd8f10b. */
/*
 * Nonzero byte completions consume min(remaining,bytes), store cursor then
 * remaining, and queue event value 2 when exhausted; otherwise rearm EP0 OUT
 * with the remaining buffer. This path does not test the current EP0 state.
 *
 * Zero-byte completions abort EP0 IN only if the current state BYTE is 1,
 * then clear remaining WORD and pending-ZLP BYTE. Regardless of that state,
 * MEMW precedes clearing the per-bus status flag BYTE, then EP0 state BYTE.
 * Ignores endpoint and all subordinate return values. No bus/queue/buffer
 * checks or lock; cursor increments use wrapping 32-bit address arithmetic.
 */
void usbd_event_ep0_out_complete_handler(unsigned char bus,
                                        unsigned int unused_endpoint,unsigned int bytes)
{
    (void)unused_endpoint;
    volatile MediusUsbdWakeBusView *core = &MEDIUS_USBD_WAKE_BUSES[bus];
    if (bytes == 0) {
        if (core->state.ep0_next_state == 1) {
            medius_dwc2_abort_ep0_in(bus);
            core->transfer_remaining = 0;
            core->send_zlp = 0;
        }
        memw();
        MEDIUS_USBD_EP0_STATUS_FLAGS[bus] = 0;
        core->state.ep0_next_state = 0;
        return;
    }
    unsigned int remaining = core->transfer_remaining;
    unsigned char *cursor = core->transfer_cursor;
    unsigned int consumed = remaining < bytes ? remaining : bytes;
    cursor = (unsigned char *)((unsigned int)cursor + consumed);
    remaining -= consumed;
    core->transfer_cursor = cursor;
    core->transfer_remaining = remaining;
    if (remaining == 0) usb_osal_mq_send(core->ep0_queue,2);
    else usbd_ep_start_read(bus,0,cursor,remaining);
}

/* Native entry: 0x40382be4. */
/* Original function-byte SHA-256:
 * 42f70df2cac008517e7de3a6371aa453bdcd4833075378fcf3de4bc8ebd1b2b6. */
/*
 * Copies exactly eight caller SETUP bytes to the selected core, then reads
 * its queue handle and sends event value 0. Only low eight bus bits select
 * the unchecked 0xaf4-byte stride. Ignores the send result.
 *
 * Aligned input uses WORD read/store at 0, then WORD read/store at 4.
 * Unaligned input copies BYTE pairs until source alignment, reads the next
 * WORD and writes its four bytes low-to-high, then copies remaining BYTE
 * pairs. Preserves this forward-copy profile; overlap is not made memmove-
 * safe and no NULL/extent checks, lock or MEMW are introduced.
 */
void usbd_event_ep0_setup_complete_handler(unsigned int bus,const void *setup)
{
    unsigned char selected_bus = (unsigned char)bus;
    volatile MediusUsbdWakeBusView *core = &MEDIUS_USBD_WAKE_BUSES[selected_bus];
    const volatile unsigned char *source = setup;
    volatile unsigned char *destination = core->setup.bytes;
    if (((unsigned int)source & 3U) == 0) {
        unsigned int word = *(const volatile unsigned int *)source;
        core->setup.words[0] = word;
        word = *(const volatile unsigned int *)(source + 4);
        core->setup.words[1] = word;
    } else {
        unsigned int remaining = 8;
        while (((unsigned int)source & 3U) != 0) {
            unsigned char byte = *source++;
            *destination++ = byte;
            --remaining;
        }
        while (remaining >= 4U) {
            unsigned int word = *(const volatile unsigned int *)source;
            source += 4;
            destination[0] = (unsigned char)word;
            destination[1] = (unsigned char)(word >> 8);
            destination[2] = (unsigned char)(word >> 16);
            destination[3] = (unsigned char)(word >> 24);
            destination += 4;
            remaining -= 4;
        }
        while (remaining != 0) {
            unsigned char byte = *source++;
            *destination++ = byte;
            --remaining;
        }
    }
    usb_osal_mq_send(core->ep0_queue,0);
}

/* Native entry: 0x40382ca0. */
/* Original function-byte SHA-256:
 * d122ae6a5f7ba0856a158665bf5e8054f11c4e0903ba484efc37299c4252efef. */
/*
 * Loads the IN metadata callback WORD once and calls it only when non-NULL,
 * forwarding byte bus/endpoint and the full 32-bit byte count unchanged.
 * Uses all seven endpoint-number bits with 12-byte entries and bus stride
 * 0xaf4, regardless of the endpoint direction bit. No range/ownership check,
 * lock, MEMW or callback result processing; index >= 16 crosses the array.
 */
void usbd_event_ep_in_complete_handler(unsigned char bus,unsigned char endpoint,
                                      unsigned int bytes)
{
    const volatile MediusUsbEndpointMetadata *metadata =
        (const volatile MediusUsbEndpointMetadata *)(0x3fcbba9cU +
            (unsigned int)bus * 0xaf4U + 0x970U + (endpoint & 0x7fU) * 12U);
    MediusUsbEndpointCompletion callback = metadata->complete;
    if (callback != 0) callback(bus,endpoint,bytes);
}

/* Native entry: 0x40382cd0. */
/* Original function-byte SHA-256:
 * 765f5497ddfda0b01715556976da5c099fd629e31c66bdaf1696ec4d53c3e6aa. */
/*
 * Loads the OUT metadata callback WORD once and calls it only when non-NULL,
 * forwarding byte bus/endpoint and the full 32-bit byte count unchanged.
 * Uses all seven endpoint-number bits with 12-byte entries and bus stride
 * 0xaf4, regardless of the endpoint direction bit. No range/ownership check,
 * lock, MEMW or callback result processing; index >= 16 crosses the array.
 */
void usbd_event_ep_out_complete_handler(unsigned char bus,unsigned char endpoint,
                                       unsigned int bytes)
{
    const volatile MediusUsbEndpointMetadata *metadata =
        (const volatile MediusUsbEndpointMetadata *)(0x3fcbba9cU +
            (unsigned int)bus * 0xaf4U + 0xa30U + (endpoint & 0x7fU) * 12U);
    MediusUsbEndpointCompletion callback = metadata->complete;
    if (callback != 0) callback(bus,endpoint,bytes);
}

/* Native entry: 0x40382d00. */
/* Original function-byte SHA-256:
 * 750ee92193993810ff215fb8bfdc055ed540a71da06263599270b89f3da58d1f. */
/*
 * Returns the raw multiplier BYTE at offset 1 of the selected 12-byte
 * endpoint metadata entry. Direction bit 7 selects IN; the index is the
 * full remaining seven bits, not a four-bit endpoint number. bus strides
 * by 0xaf4. No range check: index >= 16 can read beyond the metadata array.
 * This is one RAM read, with no MMIO access, conversion, lock or MEMW.
 */
unsigned char usbd_get_ep_mult(unsigned char bus,unsigned char endpoint)
{
    unsigned int table_offset = (endpoint & 0x80U) != 0 ? 0x970U : 0xa30U;
    unsigned int index = endpoint & 0x7fU;
    const volatile MediusUsbEndpointMetadata *metadata =
        (const volatile MediusUsbEndpointMetadata *)(0x3fcbba9cU +
            (unsigned int)bus * 0xaf4U + table_offset + index * 12U);
    return metadata->multiplier;
}

/* Native entry: 0x40382d48. */
/* Original function-byte SHA-256:
 * eb1310a7f10a7b06e6b828a322376c8ef87ecce016df3374cf3fe10f80961ade. */
/*
 * Reads descriptor MPS high BYTE, endpoint BYTE, then MPS low BYTE. Stores
 * low 11 MPS bits as HALF and bits 11..12 as multiplier BYTE in that
 * direction's metadata record. Metadata indexing uses the FULL 32-bit bus
 * and all seven endpoint-number bits, with wrapping address arithmetic;
 * controller-open calls receive only low eight bus bits.
 *
 * For nonzero control endpoints, copies seven descriptor bytes, toggles its
 * direction, stores the opposite metadata and opens that direction first.
 * A failed opposite open returns 0 without opening the original. Otherwise
 * opens the original and returns 1 only on result zero. Metadata changes
 * remain on failure; no rollback, bounds/NULL/descriptor validation or lock.
 */
int medius_usbd_open_descriptor_endpoint(unsigned int bus,unsigned char *descriptor)
{
    const volatile MediusUsbEndpointDescriptor *wire =
        (const volatile MediusUsbEndpointDescriptor *)descriptor;
    unsigned char maximum_high = wire->max_packet_high;
    unsigned char address = wire->address;
    unsigned char maximum_low = wire->max_packet_low;
    unsigned int packet_bits = ((unsigned int)maximum_high << 8) | maximum_low;
    unsigned short maximum_packet = (unsigned short)(packet_bits & 0x7ffU);
    unsigned char multiplier = (unsigned char)((packet_bits >> 11) & 3U);
    unsigned int index = address & 0x7fU;
    unsigned int table_offset = (address & 0x80U) != 0 ? 0x970U : 0xa30U;
    volatile MediusUsbEndpointMetadata *metadata =
        (volatile MediusUsbEndpointMetadata *)(0x3fcbba9cU + bus * 0xaf4U +
                                               table_offset + index * 12U);
    metadata->max_packet = maximum_packet;
    metadata->multiplier = multiplier;
    if (index != 0 && (wire->attributes & 3U) == 0) {
        MediusUsbEndpointDescriptor opposite;
        memcpy(&opposite,descriptor,7);
        unsigned char opposite_address = address ^ 0x80U;
        opposite.address = opposite_address;
        table_offset = (opposite_address & 0x80U) != 0 ? 0x970U : 0xa30U;
        metadata = (volatile MediusUsbEndpointMetadata *)(0x3fcbba9cU + bus * 0xaf4U +
                                                         table_offset + index * 12U);
        metadata->max_packet = maximum_packet;
        metadata->multiplier = multiplier;
        if (medius_usbd_open_endpoint((unsigned char)bus,&opposite) != 0) return 0;
    }
    return medius_usbd_open_endpoint((unsigned char)bus,
        (const MediusUsbEndpointDescriptor *)descriptor) == 0;
}

/* Native entry: 0x403837d0. */
/* Original function-byte SHA-256:
 * 257685a970cad155fda2f80c631a27d408d06852641d7ed9f2a1677684955756. */
/*
 * EP0 task: the low eight bits of argument select an unchecked 0xaf4-byte
 * core. Repeatedly receives with timeout -1, retries negative results and
 * ignores all event words except SETUP 0 and completed OUT data 2. The
 * initializer requests USB priority 4/6144-byte stack through its OSAL hook.
 * USB completion callbacks execute separately; this is not a timer callback.
 *
 * SETUP clears the status flag. OUT requests above 2048 stall IN immediately
 * without resetting EP0 state; other requests initialize cursor, remaining,
 * response length and ZLP. Nonempty OUT requests enter state 2 and arm a read.
 * Others clear three handler flags and dispatch with a local reply pointer.
 * Failure resets state, then stalls both directions unless the consumed flag
 * suppresses that reply. Success consumes the setup-handled flag or selects
 * response length (clamped to SETUP length unless overridden), storing it as
 * remaining. Length above 2048 resets state and stalls IN; otherwise copies
 * a different reply pointer into the core cursor with the native forward
 * BYTE/WORD access profiles, then reloads remaining after that copy.
 *
 * Zero remaining with a zero-length or OUT SETUP selects IN-status state 3.
 * All other accepted replies select IN-data state 1, set the status flag and
 * arm NULL/0 OUT before submitting IN. Fresh remaining/cursor reads supply
 * the IN write. Afterwards calls the descriptor table's device callback with
 * current speed; byte 7 selects EP0 MPS, defaulting to 64 for NULL/zero.
 * A fresh nonzero response shorter than SETUP length and divisible by that
 * MPS sets the pending-ZLP BYTE. This happens after submitting the write.
 *
 * Event 2 clears consumed/override flags, resets cursor to the core buffer,
 * and dispatches with the core cursor address. A consumed flag resets state
 * and suppresses reply; failure resets state and stalls IN. Otherwise enters
 * state 3 and writes NULL/0, except a nonzero override flag plus nonzero
 * response length selects the current cursor/length and clears that flag.
 * All controller results are ignored. Native MEMW boundaries and flag/cache
 * ordering are retained; no validation, cancellation, lock or race repair.
 */
void usbd_ep0_thread(void *argument)
{
    unsigned char bus = (unsigned char)(unsigned int)argument;
    volatile MediusUsbdWakeBusView *core = &MEDIUS_USBD_WAKE_BUSES[bus];
    unsigned char *request_buffer = (unsigned char *)core->request_buffer;
    volatile unsigned char *consumed_flag = &MEDIUS_EP0_HANDLER_CONSUMED_FLAGS[bus];
    volatile unsigned char *setup_consumed_flag = &MEDIUS_EP0_SETUP_CONSUMED_FLAGS[bus];
    volatile unsigned char *length_override_flag = &MEDIUS_EP0_LENGTH_OVERRIDE_FLAGS[bus];
    for (;;) {
        unsigned int event;
        if (usb_osal_mq_recv(core->ep0_queue,&event,-1) < 0) continue;
        if (event == 2) {
            memw();
            *consumed_flag = 0;
            memw();
            *length_override_flag = 0;
            core->transfer_cursor = request_buffer;
            unsigned int accepted = medius_usbd_dispatch_request(bus,
                (MediusUsbSetupPacket *)&core->setup,
                (unsigned char **)&core->transfer_cursor,
                (unsigned int *)&core->response_length);
            memw();
            unsigned char consumed = *consumed_flag;
            if (consumed != 0) {
                memw();
                *consumed_flag = 0;
                core->state.ep0_next_state = 0;
                continue;
            }
            if (accepted == 0) {
                core->state.ep0_next_state = 0;
                usb_device_set_stall(bus,0x80);
                continue;
            }
            memw();
            unsigned char length_override = *length_override_flag;
            core->state.ep0_next_state = 3;
            if (length_override != 0) {
                unsigned int response_length = core->response_length;
                if (response_length != 0) {
                    unsigned char *response = core->transfer_cursor;
                    memw();
                    *length_override_flag = 0;
                    usb_device_write_aligned(bus,0x80,response,response_length);
                    continue;
                }
            }
            usb_device_write_aligned(bus,0x80,0,0);
            continue;
        }
        if (event != 0) continue;

        unsigned int requested_length = core->setup.length;
        memw();
        MEDIUS_USBD_EP0_STATUS_FLAGS[bus] = 0;
        if (requested_length > 2048U && (core->setup.request_type & 0x80U) == 0) {
            usb_device_set_stall(bus,0x80);
            continue;
        }
        core->transfer_cursor = request_buffer;
        core->transfer_remaining = requested_length;
        core->response_length = requested_length;
        core->send_zlp = 0;
        unsigned char *response_buffer = request_buffer;
        /* The oversize-IN branch already sampled direction above; it does
         * not reread the request-type byte before dispatch. */
        if (requested_length <= 2048U && requested_length != 0 &&
            (core->setup.request_type & 0x80U) == 0) {
            core->state.ep0_next_state = 2;
            usbd_ep_start_read(bus,0,request_buffer,requested_length);
            continue;
        }
        memw();
        *consumed_flag = 0;
        memw();
        *setup_consumed_flag = 0;
        memw();
        *length_override_flag = 0;
        unsigned int accepted = medius_usbd_dispatch_request(bus,
            (MediusUsbSetupPacket *)&core->setup,&response_buffer,
            (unsigned int *)&core->response_length);
        if (accepted == 0) {
            memw();
            unsigned char consumed = *consumed_flag;
            core->state.ep0_next_state = 0;
            if (consumed == 0) {
                usb_device_set_stall(bus,0);
                usb_device_set_stall(bus,0x80);
            } else {
                memw();
                *consumed_flag = 0;
            }
            continue;
        }
        memw();
        if (*setup_consumed_flag != 0) {
            memw();
            *setup_consumed_flag = 0;
            core->state.ep0_next_state = 0;
            continue;
        }
        memw();
        unsigned char length_override = *length_override_flag;
        unsigned int response_length = core->response_length;
        if (length_override == 0) {
            unsigned int setup_length = core->setup.length;
            if (response_length > setup_length) response_length = setup_length;
        }
        core->transfer_remaining = response_length;
        if (response_length > 2048U) {
            core->state.ep0_next_state = 0;
            usb_device_set_stall(bus,0x80);
            continue;
        }
        unsigned char *destination = core->transfer_cursor;
        if (destination != response_buffer) {
            ep0_copy_response(destination,response_buffer,response_length);
            response_length = core->transfer_remaining;
        }
        if (response_length == 0 && (core->setup.length == 0 ||
                                     (core->setup.request_type & 0x80U) == 0)) {
            core->state.ep0_next_state = 3;
        } else {
            core->state.ep0_next_state = 1;
            memw();
            MEDIUS_USBD_EP0_STATUS_FLAGS[bus] = 1;
            usbd_ep_start_read(bus,0,0,0);
        }
        unsigned int write_length = core->transfer_remaining;
        unsigned char *write_buffer = core->transfer_cursor;
        usb_device_write_aligned(bus,0x80,write_buffer,write_length);
        MediusUsbdDescriptorPrefix *table = core->descriptors;
        unsigned int speed = core->state.speed;
        MediusUsbDeviceDescriptorCallback get_device_descriptor = table->device_descriptor;
        const volatile unsigned char *device_descriptor = get_device_descriptor(speed);
        unsigned int maximum_packet = 64;
        if (device_descriptor != 0) {
            maximum_packet = device_descriptor[7];
            if (maximum_packet == 0) maximum_packet = 64;
        }
        unsigned int actual_length = core->response_length;
        if (actual_length != 0 && actual_length < core->setup.length &&
            actual_length % maximum_packet == 0) core->send_zlp = 1;
    }
}

/* Native entry: 0x403917a0. */
/* Original function-byte SHA-256:
 * 04249b03b6b621cd7686b3dde1980d2e056109a7a858a72d3e4b2724fba38523. */
/*
 * Clears the single global EP0-related flag BYTE after MEMW when the
 * endpoint's low seven bits are zero (0x00 or 0x80), then forwards bus and
 * endpoint to the controller stall routine. Returns its result unchanged.
 * The flag clears even if stalling fails; it is not indexed by bus.
 * No other validation, synchronization or state repair is performed.
 */
int usb_device_set_stall(unsigned char bus,unsigned char endpoint)
{
    if ((endpoint & 0x7fU) == 0) {
        memw();
        MEDIUS_USBD_EP0_STALL_FLAG = 0;
    }
    return usbd_ep_set_stall(bus,endpoint);
}

/* Native entry: 0x420216f0. */
/* Original function-byte SHA-256:
 * ee862d9296cfaf9d54c79504436ef16e259f3b245c6b402357bc72acaf70a991. */
/* Cache the bus event callback, clear suspended, then call it with event6.
 * The bus byte selects a0xaf4-byte record without bounds/NULL checks. No
 * fence, lock, controller register operation or callback-result handling. */
void usbd_event_resume_handler(unsigned char bus)
{
    volatile MediusUsbdWakeBusView *core = MEDIUS_USBD_WAKE_BUSES+bus;
    MediusUsbdBusEventHandler callback = core->event_handler;
    core->state.is_suspend = 0;
    callback(bus,6);
}

/* Native entry: 0x4202171c. */
/* Original function-byte SHA-256:
 * baef96e2a5827925d74d4c5d26b84d608ef50b9c3588c6f8f2350a8a838b31e4. */
/*
 * Acts only when the selected core's device-address BYTE is nonzero;
 * this gate does not test the configuration byte. Caches the event callback,
 * stores suspended BYTE = 1 and calls the cached callback(bus,5).
 * A zero address leaves state untouched. No callback NULL test, bus bounds
 * check, lock or MEMW; core storage has native stride 0xaf4.
 */
void usbd_event_suspend_handler(unsigned char bus)
{
    volatile MediusUsbdWakeBusView *core = &MEDIUS_USBD_WAKE_BUSES[bus];
    if (core->state.device_address == 0) return;
    MediusUsbdBusEventHandler callback = core->event_handler;
    core->state.is_suspend = 1;
    callback(bus,5);
}

/* Native entry: 0x42021750. */
/*
 * Medius v3.4.7 — device application; 0x42021750.
 *
 * Resets core USB state, opens EP0 in both directions from the descriptor packet size, then
 * broadcasts reset notifications.
 *
 * Calls: medius_usbd_class_event_notify, memset, usbd_ep_open, usbd_set_address.
 *
 * Called by: USBD_IRQHandler.
 *
 * Indirect calls: the descriptor-table callback and freshly loaded application event handler.
 *
 * Original function-byte SHA-256:
 * 38b4a17c6db399ccbfcd8a29dbc1fe980e0ca3fd198fe26c26fd1f58e0464586.
 */

/*
 * bus: Raw8 bus index; no local controller/core allocation bounds check.
 * Returns: No value. NULL device-descriptor callback enters an infinite self-loop; other bad
 *   pointers can fault.
 * Requirements/effects: Sets address0, clears configuration/address together as16 bits, clears256
 *   alternate-setting bytes, then loads descriptor-table pointer before clearing speed and EP0
 *   state. Caches table callback before clearing remote-wakeup-enabled. A NULL callback never
 *   returns. Otherwise calls descriptor callback with literal speed0 and reads byte7, accepting
 *   only EP0 MPS8/16/32/64 and defaulting every other byte to64. Builds seven stack bytes, opens
 *   IN EP0, changes only address byte2 to OUT and opens again. Ignores both open results,
 *   broadcasts class reset(bus,1,NULL), freshly loads the application event callback and invokes
 *   it(bus,1). There is no local lock, application-callback NULL guard, descriptor length check or
 *   rollback. Other core bytes/class list/count are retained. Open helpers must consume/copy the
 *   borrowed stack descriptor before return; callback changes can affect later opens and the final
 *   callback. Hardware acceptance and concurrent lifetime are delegated.
 */

void medius_usbd_reset_event(unsigned char bus)
{
    usbd_set_address(bus,0);
    volatile MediusUsbdCoreState *state = &MEDIUS_USBD_WAKE_BUSES[bus].state;
    *(volatile unsigned short *)&state->configuration = 0; /* configuration and device address */
    memset((void *)MEDIUS_USBD_WAKE_BUSES[bus].alternate_settings,0,256);

    /* Cache table before the first flags; cache its callback before the last. */
    MediusUsbdDescriptorPrefix *table =
        MEDIUS_USBD_WAKE_BUSES[bus].descriptors;
    state->speed = 0;
    state->ep0_next_state = 0;
    MediusUsbDeviceDescriptorCallback device_descriptor = table->device_descriptor;
    state->remote_wakeup_enabled = 0;
    if (device_descriptor == 0) {
        for (;;) { }
    }
    const unsigned char *descriptor = device_descriptor(0);
    unsigned char reported_packet_size = ((const volatile unsigned char *)descriptor)[7];
    unsigned short maximum_packet_size = 64;
    if (reported_packet_size == 8 || reported_packet_size == 16 ||
        reported_packet_size == 32 || reported_packet_size == 64)
        maximum_packet_size = reported_packet_size;

    MediusUsbdEp0DescriptorPacket endpoint;
    endpoint.header = 0x00800507U; /* length7, ENDPOINT5, address0x80, CONTROL0 */
    endpoint.maximum_packet_size = maximum_packet_size;
    endpoint.interval = 0;
    usbd_ep_open(bus,(const MediusUsbEndpointDescriptor *)&endpoint);
    ((volatile unsigned char *)&endpoint)[2] = 0; /* Only the address byte changes for OUT. */
    usbd_ep_open(bus,(const MediusUsbEndpointDescriptor *)&endpoint);
    medius_usbd_class_event_notify((unsigned int)bus,1,0);
    MediusUsbdApplicationEvent callback =
        MEDIUS_USBD_WAKE_BUSES[bus].event_handler;
    callback((unsigned int)bus,1);
}

/* Native entry: 0x4202181c. */
/* Original function-byte SHA-256:
 * 56839e087ee66721781ba40beecb26ba8f5c9b3b1659f6d3a44983d2f526857e. */
/*
 * Zeros the entire selected 0xaf4-byte USB core, including handles and its
 * event callback, then installs the caller's descriptor-table pointer at
 * +24. Initializes EP0 IN address 0x80/callback, clears interface count,
 * then initializes EP0 OUT address 0/callback, preserving native store order.
 * Other metadata fields remain zero. bus is an unchecked byte index.
 * No descriptor validation, object allocation, lock or MEMW is supplied.
 */
void usbd_desc_register(unsigned char bus,void *descriptors)
{
    volatile MediusUsbdWakeBusView *core = &MEDIUS_USBD_WAKE_BUSES[bus];
    memset((void *)core,0,0xaf4U);
    core->descriptors = descriptors;
    core->input_metadata[0].address = 0x80;
    core->input_metadata[0].complete = medius_usbd_ep0_in_callback;
    core->interface_count = 0;
    core->output_metadata[0].address = 0;
    core->output_metadata[0].complete = medius_usbd_ep0_out_callback;
}

/* Native entry: 0x42021874. */
/* Original function-byte SHA-256:
 * 170c486cfb000509e775d098578ac45b33aae5b916f386bff250445603c479e3. */
/*
 * Reads the interface-count BYTE once, stores it as the object's interface
 * number at +24, stores the object pointer at core+0x82c+count*4, and writes
 * count+1 modulo 256. Does not check table capacity, NULL, bus or duplicates.
 * interface_storage is the caller-owned class object, not copied storage.
 * Uses native BYTE/WORD accesses without a lock or MEMW.
 */
void usbd_add_interface(unsigned char bus,unsigned char *interface_storage)
{
    volatile MediusUsbdWakeBusView *core = &MEDIUS_USBD_WAKE_BUSES[bus];
    unsigned char count = core->interface_count;
    volatile MediusUsbdClassEventView *interface =
        (volatile MediusUsbdClassEventView *)interface_storage;
    MediusUsbdClassEventView * volatile *slot =
        (MediusUsbdClassEventView * volatile *)((unsigned int)core +
                                                0x82cU + (unsigned int)count * 4U);
    interface->interface_number = count;
    *slot = (MediusUsbdClassEventView *)interface_storage;
    core->interface_count = (unsigned char)(count + 1U);
}

/* Native entry: 0x420218ac. */
/* Original function-byte SHA-256:
 * 883173cf77585b6be29a58dad5aa82835dead6c693ae287db6de8c3cad73f19d. */
/*
 * Caches the caller registration's address BYTE and callback WORD, then
 * stores those into the selected 12-byte metadata record in that order.
 * Bit 7 chooses IN; all seven remaining bits index the table. bus strides
 * 0xaf4. Preserves multiplier, max-packet and the uninterpreted word.
 * No NULL, bus, index, callback or capacity checks; index >= 16 writes past
 * the corresponding metadata array. No allocation, lock or MEMW.
 */
void usbd_add_endpoint(unsigned char bus,MediusUsbEndpointRegistration *registration)
{
    const volatile MediusUsbEndpointRegistration *source = registration;
    unsigned char address = source->address;
    MediusUsbEndpointCompletion callback = source->complete;
    unsigned int table_offset = (address & 0x80U) != 0 ? 0x970U : 0xa30U;
    unsigned int index = address & 0x7fU;
    volatile MediusUsbEndpointMetadata *metadata =
        (volatile MediusUsbEndpointMetadata *)(0x3fcbba9cU +
            (unsigned int)bus * 0xaf4U + table_offset + index * 12U);
    metadata->address = address;
    metadata->complete = callback;
}

/* Native entry: 0x42021908. */
/* Original function-byte SHA-256:
 * 2f127dde8e3a3463daa2445937d09d51f7fb4167b87d3abc347b9769da3ce10f. */
/* Check support, host-enabled remote wake and suspended in that order. A zero
 * byte returns-1 without controller access. Otherwise return the bus controller
 * wake operation's status unchanged. No bus bounds check, local lock or fence. */
int usbd_send_remote_wakeup(unsigned char bus)
{
    const volatile MediusUsbdCoreState *state = &MEDIUS_USBD_WAKE_BUSES[bus].state;
    if (state->remote_wakeup_support == 0 || state->remote_wakeup_enabled == 0 || state->is_suspend == 0)
        return -1;
    return usbd_set_remote_wakeup(bus);
}

/* Native entry: 0x42021948. */
/* Original function-byte SHA-256:
 * 9b48d0b76900d74be36d836140405ae5e58402e85c576ca15b9198402eced642. */
/*
 * Returns one raw endpoint-zero next-state BYTE at core+0x81e, with bus
 * selecting the unchecked 0xaf4-byte core stride. No state normalization,
 * bounds check, lock, MEMW or task interaction.
 */
unsigned char usbd_get_ep0_next_state(unsigned char bus)
{
    return MEDIUS_USBD_WAKE_BUSES[bus].state.ep0_next_state;
}

/* Native entry: 0x42021964. */
/* Original function-byte SHA-256:
 * 28891e8cc9bfc94adf65e2b223feacd954c2608d41d381ede9d2af8b8a191327. */
/*
 * Supports only bus BYTE 0; any other value spins forever before writes.
 * Stores the supplied controller base, creates a one-item/four-byte EP0
 * queue and task "usbd_ep0" with requested 6144-byte stack/USB priority 4.
 * Queue failure clears the task handle and returns -1; task failure deletes
 * the stored queue, clears its handle and returns -1. Controller base remains.
 *
 * On task success, reads class count BEFORE publishing the event callback.
 * A nonzero count starts a sequential pointer-table walk: skip NULL objects
 * or notify pointers, otherwise call notify(0,11,NULL); wrap the BYTE index
 * and reload count after each slot. The pointer advances even on index wrap.
 * After that walk reloads the application callback; with initial count zero
 * uses the supplied callback directly. Calls it(0,11) without a NULL test,
 * then returns usb_dc_init(0). Controller failure does not free the task or
 * queue. No repeated-init guard, table capacity check, lock or MEMW.
 */
int usbd_initialize(unsigned char bus,void *controller_registers,
                    MediusUsbdBusEventHandler callback)
{
    if (bus != 0) for (;;) { __asm__ volatile ("" ::: "memory"); }
    MEDIUS_USBD_CONTROLLERS[0].registers = controller_registers;
    volatile MediusUsbdWakeBusView *core = &MEDIUS_USBD_WAKE_BUSES[0];
    void *queue = usb_osal_mq_create(1);
    core->ep0_queue = queue;
    if (queue == 0) {
        core->ep0_task = 0;
        return -1;
    }
    void *task = medius_usb_osal_thread_create("usbd_ep0",0x1800,4,
                                              medius_usbd_ep0_task_entry,0);
    core->ep0_task = task;
    if (task == 0) {
        usb_osal_mq_delete(core->ep0_queue);
        core->ep0_queue = 0;
        return -1;
    }
    unsigned char count = core->interface_count;
    core->event_handler = callback;
    if (count != 0) {
        MediusUsbdClassEventView * const volatile *slot =
            (MediusUsbdClassEventView * const volatile *)0x3fcbc2c8U;
        unsigned char index = 0;
        do {
            MediusUsbdClassEventView *interface = *slot;
            if (interface != 0) {
                MediusUsbdClassEventHandler notify = interface->notify;
                if (notify != 0) notify(0,11,0);
            }
            index = (unsigned char)(index + 1U);
            count = core->interface_count;
            ++slot;
        } while (index < count);
        callback = core->event_handler;
    }
    callback(0,11);
    return usb_dc_init(0);
}

/* Native entry: 0x420219f8. */
/* Original function-byte SHA-256:
 * 6f53eb79ff4e6a05a5dd1b0a4bbabc07f60428d956802a336eb6e73ee6069000. */
/*
 * Reads the selected core's EP0 task-handle WORD at +0x828 once and returns
 * exactly 0 for NULL or 1 otherwise. Does not query the scheduler or prove
 * the task is running. bus is an unchecked byte index with stride 0xaf4;
 * no lock, MEMW or other state check.
 */
int medius_usbd_ep0_task_exists(unsigned char bus)
{
    return MEDIUS_USBD_WAKE_BUSES[bus].ep0_task != 0;
}

/* Native entry: 0x42034418. */
/*
 * Medius v3.4.7 — device application; 0x42034418.
 *
 * Returns whether the shared USB speed-selection byte is exactly1.
 *
 * Called by: usb_dc_init.
 *
 * Original function-byte SHA-256:
 * 7e68da4b4cea5f594dbf2959041a17205ee95b64c7d701fa6a9eb23118d07027.
 */

/*
 * Returns: Exactly 1 when the shared speed-selection byte equals 1; 0 for every other byte value.
 * Requirements/effects: Samples the configuration byte once. The device initializer uses true to
 *   request the DWC2 low-speed configuration; the value does not measure bus speed or confirm PHY
 *   negotiation. No lock or write occurs.
 */

unsigned int medius_usb_low_speed_requested(void)
{
    return USB_CLONE_SPEED == 1;
}

/* Native entry: 0x42021a18. */
/* Original function-byte SHA-256:
 * e86858796e79b5a04e8ca9823fa6d106881e0ada444c3a573b328dc7847175ac. */
/* Deinitialize the sole compiled USB device bus. A nonzero bus BYTE spins
 * forever, matching the compiled assertion. For bus0, ignore controller
 * deinit status; delete a currently nonnull EP0 thread, then a freshly read
 * nonnull EP0 queue. Their stored handles are not cleared here.
 * Invoke the application callback unconditionally with (0,12), then each
 * nonnull registered interface notify callback with (0,12,NULL). The third
 * argument was missing in the raw decompilation. Reload interface count BYTE
 * after each callback and wrap the loop index to8 bits; no capacity clamp.
 * Return0 regardless of driver status. Callbacks may mutate the live table;
 * no local lock, resource rollback or explicit MEMW is supplied. */
int usbd_deinitialize(unsigned char bus)
{
    if (bus != 0)
        for (;;) { }
    usb_dc_deinit(0);
    void *thread = MEDIUS_USBD_EP0_THREAD;
    if (thread != NULL)
        medius_usb_osal_thread_delete(thread);
    void *queue = MEDIUS_USBD_EP0_QUEUE;
    if (queue != NULL)
        usb_osal_mq_delete(queue);
    MEDIUS_USBD_WAKE_BUSES[0].event_handler(0,12);
    if (MEDIUS_USBD_CLASS_COUNT != 0) {
        unsigned int index = 0;
        do {
            MediusUsbdClassEventView *interface = MEDIUS_USBD_CLASS_TABLE[index];
            if (interface != NULL) {
                MediusUsbdClassEventHandler notify = interface->notify;
                if (notify != NULL)
                    notify(0,12,NULL);
            }
            unsigned int count = MEDIUS_USBD_CLASS_COUNT;
            index = (index + 1U) & 255U;
            if (index >= count)
                break;
        } while (1);
    }
    return 0;
}

/* Native entry: 0x4203348c. */
/* Original function-byte SHA-256:
 * fa4ed7ae24482e8274e9cc09c2c7d742d5b3e501168f54bb2101c787de9c1bed. */
/*
 * MEMW then read the unaligned USB IN-write diagnostic count at struct+12.
 * The USB write path increments it when the source address needs a bounce
 * buffer, even before later length rejection. Return its full wrapping WORD;
 * this is not a successful-transfer count. No clear, lock or snapshot of the
 * accompanying endpoint, length and source-buffer fields.
 */
unsigned int usbd_get_unaligned_write_count(void)
{
    memw();
    return USBD_UNALIGNED_WRITE->unaligned_count;
}
