/* Medius v3.4.7 host — usb/hub.c.
 * Recovered C and native assembly, grouped for source navigation.
 * Original entry addresses, firmware-byte hashes and function comments follow.
 */

#include "../include/types.h"

/* Native entry: 0x4200982c. */
/*
 * Medius v3.4.7 — host application; 0x4200982c.
 *
 * Finds a connected child through hub-class interfaces, with unchecked direct indexing and an
 * abnormal recursive-miss path.
 *
 * Calls: medius_usbh_find_port_in_hub, strcmp.
 *
 * Called by: medius_usbh_find_port_in_hub, usbh_find_hubport.
 *
 * Original function-byte SHA-256:
 * b6c8e9c29572b46b5cecb1a8a1a7e108c46603031491a2eadf13ea00368661e5.
 */

/* Finds a connected child through hub-class interfaces, with unchecked direct indexing and an
   abnormal recursive-miss path. Compares hub.index byte+2 with full32 requested index. If equal,
   calculates u32(hub+20hex+164*(port_number-1)), reads only its connected byte, returns that
   pointer if nonzero elseNULL. Does not inspect hub.connected or port_count on this path. If index
   differs, snapshots byte hub.port_count+5 and scans that many child records ascending. Skips
   disconnected child or16-bit interface_count0. For each connected child, caches table pointer+28
   and count+2C and scans20hex-byte interface entries. Requires nonNULL class_driver+10, nonNULL
   driver_name atdriver+0, strcmp(name,"hub")==0, nonNULL interface.private+14 and nonzero private
   hub.connected. It does not test interface.alternate_count. On first eligible private hub,
   recursively calls itself with original full32 index/port. NonNULL result returns immediately.
   NULL recursive result does NOT continue siblings: MEMW at420098C3 then L16UI a8,a10,0x2C
   at420098C6 with a10=0, followed by BREAK1,15 at420098C9. If scanning encounters no eligible
   private hub, returnsNULL normally. Child span/interface count/table remain snapshots across
   strcmp; private pointer/activity are loaded after it. No local data writes. Boundaries: No
   pointer, port>=1, port<=count, hub-index range, tree depth or cycle validation. Directport0
   reads132 bytes before hub; larger values can point beyond four child slots and arithmetic
   wraps32. A nonzero connected byte there is enough to return that address. Recursive miss reaches
   a null-relative load before BREAK; actual fault vector, debugger behavior and any continuation
   depend on hardware/execution environment. Tests stop before the load and do not claim a normal
   return or sibling fallback. Recursive cycles can exhaust stack. Returned child is borrowed, not
   retained or copied. */

/*
 * hub: Borrowed hub with readable child/interface records; NULL is not guarded.
 * hub_index: Full32 requested index compared against the current hub index byte.
 * port_number: Full32 one-based port used in wrapping address arithmetic without range checks.
 * Returns: Borrowed connected child pointer on a direct match or first successful recursive
 *   search; NULL only on ordinary misses or externally continued abnormal path.
 * Requirements/effects: Direct index match computes unsigned32(hub+32+164*(port-1)) and reads its
 *   connected byte, ignoring hub connected/count. Otherwise caches child count, and for each
 *   connected child caches16-bit interface count and table pointer. Skips NULL driver/name or non-
 *   hub name, then freshly reads private hub/connected after strcmp. First eligible hub is
 *   recursively searched with unchanged full32 arguments. Non-NULL returns immediately; a
 *   recursive NULL reaches native MEMW, halfword load at NULL+44, then BREAK1,15, with no sibling
 *   fallback. Fault/debugger continuation is environment-dependent; if both instructions are
 *   externally continued, returns NULL. Counts/table stay cached across strcmp, later
 *   entries/private activity are read fresh. No lock, pointer/range/depth/cycle validation occurs;
 *   invalid direct arithmetic and child spans can escape allocation, recursive cycles can exhaust
 *   stack and returned pointers have no retained ownership.
 */

MediusHostHubPortPrefix *medius_usbh_find_port_in_hub(
    MediusHostHubState *hub,uint hub_index,uint port_number)
{
    if (*(const volatile uchar *)&hub->index == hub_index) {
        uint address = (uint)hub + 32U + 164U * (port_number - 1U);
        return *(const volatile uchar *)address != 0 ? (MediusHostHubPortPrefix *)address : 0;
    }
    uchar child_count = *(const volatile uchar *)&hub->port_count;
    for (uint child_index = 0; child_index < (uint)child_count; ++child_index) {
        MediusHostHubPortPrefix *child =
            (MediusHostHubPortPrefix *)((uint)hub + 32U + child_index * 164U);
        if (*(const volatile uchar *)&child->connected == 0)
            continue;
        ushort interface_count = *(const volatile ushort *)&child->interface_count;
        if (interface_count == 0)
            continue;
        MediusHostInterfacePrefix *interfaces =
            *(MediusHostInterfacePrefix * const volatile *)&child->interfaces;
        for (uint interface_index = 0; interface_index < (uint)interface_count; ++interface_index) {
            MediusHostInterfacePrefix *interface =
                (MediusHostInterfacePrefix *)((uint)interfaces + interface_index * 32U);
            void *driver = *(void * const volatile *)&interface->class_driver;
            if (driver == 0)
                continue;
            const char *driver_name = *(const char * const volatile *)driver;
            if (driver_name == 0 || strcmp(driver_name,"hub") != 0)
                continue;
            MediusHostHubState *nested =
                *(MediusHostHubState * const volatile *)&interface->private_data;
            if (nested == 0 || *(const volatile uchar *)&nested->connected == 0)
                continue;
            MediusHostHubPortPrefix *found = medius_usbh_find_port_in_hub(nested,hub_index,port_number);
            if (found != 0)
                return found;
            /* Native recursive miss loads NULL+44 BEFORE BREAK1,15. Use assembly
             * so a C null-dereference optimization cannot erase the actual path.
             * Only externally continued execution past both can return NULL. */
            uint fault_probe;
            __asm__ volatile ("memw\n\tl16ui %0, %1, 44\n\tbreak 1, 15"
                              : "=a"(fault_probe) : "a"(found) : "memory");
            return found;
        }
    }
    return 0;
}

/* Native entry: 0x42009f04. */
/*
 * Medius v3.4.7 — host application; 0x42009f04.
 *
 * Disconnects a live port, releases its address and interface callbacks, deletes the mutex and
 * retires detached descriptor storage.
 *
 * Calls: medius_usbh_retire_descriptor_storage, usb_osal_mutex_delete, usb_osal_mutex_take,
 * usbh_kill_urb.
 *
 * Called by: medius_usbh_hub_disconnect, usbh_hub_thread.
 *
 * Unresolved indirect call sites: 4.
 *
 * Original function-byte SHA-256:
 * f48e069ec52f65cdfe45a578851eb5d6f1be99c8eddc92a3f44432e01ebd9346.
 */

/* Disconnects a live port, releases its address and interface callbacks, deletes the mutex and
   retires detached descriptor storage. If initial connected byte0 is0, returns without
   writes/calls. Otherwise saves that nonzero byte, clears connected, calls usbh_kill_urb(port+5C)
   and ignores error. Rereads device_address byte2; only addresses1..126 are eligible. In current
   bus address_bitmap at+31C+4*(address>>5), clears bit(address&31) only if set; other bits
   unchanged. Reads16-bit interface_count+2C and scans indices ascending using table+20hex*index.
   Entry participates only if byte+1C (alternate_count) is nonzero. For participating entry,
   optionally calls class_driver+8 disconnect(port,index low8) when both driver pointer+10 and
   callback nonNULL; ignores callback result. Then reloads port.bus,parent,port_number and invokes
   event(bus.id,parent.index,port_number,index low8,11). Count is reloaded after this event;
   nonparticipating entries retain the prior count snapshot. The loop compares low16(index+1)
   against count; table is reloaded each iteration. If no participating entry emitted an event,
   emits one event11 with interfaceFF. Clears byte port+20 (configuration descriptor
   bNumInterfaces); takes current mutex ignoring status, reloads and deletes mutex. Emits event4
   with fresh bus/parent/port ids and interfaceFF before clearing table/count. Then clears count+2C,
   captures current descriptor_storage+30, executes MEMW, clears interfaces+28 and storage+30.
   NonNULL captured allocation is retired through420098D0(port,allocation). Boundaries: No NULL
   port/parent/bus/callback checks. Table capacity and nonzero alternate count are trusted; 16-bit
   scan indices are truncated to8 bits for callbacks, so indices256+ repeat callback numbers. The
   mutex handle is retained after deletion, as are device address, parent, setup and other fields.
   Cancellation/lock/callback errors do not stop teardown. Count/table/ids/storage are separate
   snapshots across delegated calls. Original assembly passes TWO arguments to retirement; earlier
   untyped C showed only port, which was incomplete ABI recovery. MEMW orders the local stores but
   does not prove readers have stopped; retirement itself provides no quiescence guarantee. */

/*
 * port: Live164-byte hub-port object with valid bus/parent/table and delegated handles when
 *   connected.
 * Returns: No value.
 * Requirements/effects: A zero initial connected byte is an exact no-op. Otherwise clears
 *   connected before cancellation, ignores cancellation result and releases address1..126 only if
 *   its cached bitmap bit is set. Scans a cached16-bit interface count with a full32-bit index,
 *   compares low16(index) after each increment and reloads the table every iteration. A nonzero
 *   alternate count optionally calls the driver disconnect callback with low8 index, then loads
 *   fresh bus/parent/callback/IDs and emits event11; only this path refreshes count. No
 *   participating entry emits one fallback event11/interface255. Snapshots mutex before clearing
 *   descriptor interface count, takes it ignoring status, reloads/deletes it, then emits event4
 *   before clearing interface count. Captures allocation, MEMW-clears table/storage and retires
 *   nonNULL allocation with both port and allocation arguments. Retains address, mutex and other
 *   fields. No bounds, callback lifetime, null parent/bus/event, quiescence or lock-success check;
 *   errors do not roll back cleanup.
 */

void usbh_hubport_release(MediusHostHubPortPrefix *port)
{
    volatile MediusHostHubPortPrefix *live = port;
    uchar was_connected = live->connected;
    if (was_connected == 0)
        return;
    live->connected = 0;
    usbh_kill_urb(&port->control_urb);
    uint address = live->device_address;
    if (((address - 1U) & 0xffU) < 126U) {
        volatile MediusHostBusPrefix *bus = live->bus_context;
        volatile uint *bitmap = &bus->address_bitmap[address >> 5];
        uint allocated = *bitmap;
        uint bit = 1U << (address & 31U);
        if (allocated & bit)
            *bitmap = allocated & ~bit;
    }
    uint interface_count = live->interface_count;
    uint index = 0;
    int emitted_interface_event = 0;
    if (interface_count != 0) {
        do {
            MediusHostInterfacePrefix *interfaces = live->interfaces;
            volatile MediusHostInterfacePrefix *entry =
                (volatile MediusHostInterfacePrefix *)((uint)interfaces + (index << 5));
            if (entry->alternate_count != 0) {
                const volatile MediusHostDisconnectDriverView *driver = entry->class_driver;
                if (driver != 0) {
                    MediusHostClassDisconnect disconnect = driver->disconnect;
                    if (disconnect != 0)
                        disconnect(port,(uchar)index);
                }
                volatile MediusHostBusPrefix *bus = live->bus_context;
                MediusHostHubPrefix *parent = live->parent;
                MediusHostEventHandler callback = bus->event;
                uint hub_index = ((const volatile uchar *)parent)[2];
                uint port_number = live->port_number;
                uint bus_id = bus->id;

                callback(bus_id,hub_index,port_number,index & 0xffU,11);
                interface_count = live->interface_count;
                emitted_interface_event = was_connected;
            }
            ++index;
        } while ((index & 0xffffU) < interface_count);
    }
    if (!emitted_interface_event) {
        volatile MediusHostBusPrefix *bus = live->bus_context;
        MediusHostHubPrefix *parent = live->parent;
        MediusHostEventHandler callback = bus->event;
        uint hub_index = ((const volatile uchar *)parent)[2];
        uint port_number = live->port_number;
        uint bus_id = bus->id;
        callback(bus_id,hub_index,port_number,255,11);
    }
    /* Native code snapshots the take handle BEFORE clearing this byte. */
    void *take_mutex = live->control_mutex;
    live->descriptor_interface_count = 0;
    usb_osal_mutex_take(take_mutex);
    void *delete_mutex = live->control_mutex;
    usb_osal_mutex_delete(delete_mutex);
    {
        volatile MediusHostBusPrefix *bus = live->bus_context;
        MediusHostHubPrefix *parent = live->parent;
        MediusHostEventHandler callback = bus->event;
        uint hub_index = ((const volatile uchar *)parent)[2];
        uint port_number = live->port_number;
        uint bus_id = bus->id;
        callback(bus_id,hub_index,port_number,255,4);
    }
    live->interface_count = 0;
    void *allocation = live->descriptor_storage;
    memw();
    live->interfaces = 0;
    live->descriptor_storage = 0;
    if (allocation != 0)
        medius_usbh_retire_descriptor_storage(port,allocation);
}

/* Native entry: 0x4200a774. */
/*
 * Medius v3.4.7 — host application; 0x4200a774.
 *
 * Cancels hub activity, releases children, clears its allocator bit and zeros the hub while
 * retaining parent/interface aliases.
 *
 * Calls: memset, usb_osal_timer_delete, usbh_hubport_release, usbh_kill_urb.
 *
 * Original function-byte SHA-256:
 * 75d91bbc5a577d045890e9f13553bb8a5498eff62515102af1b8c4b2c6b974d4.
 */

/* Cancels hub activity, releases children, clears its allocator bit and zeros the hub while
   retaining parent/interface aliases. Loads and caches private hub pointer; NULL returns0. If
   hub.interrupt_endpoint+2B8 nonzero, calls usbh_kill_urb(hub+2BC), ignoring result. Rereads
   timer+304 after cancellation and deletes it if nonzero. For byte child count+5 nonzero, releases
   each child at hub+20hex+i*A4, then explicitly clears that child.parent+48. Count is reread after
   each release and loop counter is low8. Reads current hub.index+2 after children; if
   low8(index-2)<32, clears that bit of allocator3FCA8254. Finally zeros exactly308 cached hub
   bytes, including timer/URB/children, and returns0. Boundaries: No private-pointer bounds, active
   flag, capacity, queue drain or callback quiescence check. Negative cancellation/timer deletion
   does not prevent zeroing/reuse. Parent+4C and interface.private remain pointing at the zeroed
   singleton; this function does not clear either alias. Mutable count can exceed the four allocated
   child records; caller must preserve valid bounds. The allocator guard is a generic32-bit index
   rule even though attachment reserves onlybit0. */

/*
 * port: Live parent port with readable interface table.
 * interface_index: Raw byte interface index; no local bounds check.
 * Returns: 0 after delegated cleanup returns, including NULL private hub.
 * Requirements/effects: Caches the interface private hub. If present, conditionally cancels its
 *   interrupt URB, then freshly reads/caches the timer and conditionally deletes it. For a nonzero
 *   child count, releases children at hub+32+164*i, clears each parent pointer after release,
 *   rereads the count and compares an 8-bit loop index. Afterwards reads the hub index, clears bit
 *   low8(index-2) only if below 32, and zeroes exactly 776 bytes. Errors do not stop cleanup.
 *   Parent/interface aliases, queues and potential callbacks are not cleared or proven quiescent.
 *   Mutable child counts above four can walk outside allocated child storage; no capacity or
 *   lifecycle guard is added.
 */

int medius_usbh_hub_disconnect(MediusHostHubPortPrefix *port,uchar interface_index)
{
    MediusHostHubState *hub = port->interfaces[interface_index].private_data;
    if (hub == 0)
        return 0;
    volatile MediusHostHubState *state = hub;
    if (state->interrupt_endpoint != 0)
        usbh_kill_urb(&hub->interrupt_urb);
    MediusUsbOsalTimer *timer = state->interrupt_timer;
    if (timer != 0)
        usb_osal_timer_delete(timer);
    if (*(const volatile uchar *)&hub->port_count != 0) {
        uchar child_index = 0;
        MediusHostHubPortPrefix *child = hub->ports;
        do {
            usbh_hubport_release(child);
            *(MediusHostHubPrefix * volatile *)&child->parent = 0;
            child_index = (uchar)(child_index + 1U);
            uchar child_count = *(const volatile uchar *)&hub->port_count;
            child = (MediusHostHubPortPrefix *)((uint)child + 164U);
            if (child_index >= child_count)
                break;
        } while (1);
    }
    uint slot = ((uint)state->index - 2U) & 0xffU;
    if (slot < 32)
        HOST_EXTERNAL_HUB_SLOTS &= ~(1U << slot);
    memset(hub,0,0x308);
    return 0;
}

/* Native entry: 0x4200a7fc. */
/*
 * Medius v3.4.7 — host application; 0x4200a7fc.
 *
 * Prepares a one-byte asynchronous hub interrupt transfer and ignores submission status.
 *
 * Calls: usbh_submit_urb.
 *
 * Original function-byte SHA-256:
 * 6584629906df756e30f2f7dd14229f1eb5aea0e40d46b8f0a40ff7e41b340a3e.
 */

/* Prepares a one-byte asynchronous hub interrupt transfer and ignores submission status. Captures
   interrupt buffer,upstream port andendpoint. On embedded URB+2BC writes setup=NULL at+2D4,timeout0
   at+2E8,buffer at+2D8,complete4200A860 at+2F8,hubport at+2C4,endpoint at+2C8,remaining1
   at+2DC,context=hub at+2FC. Reads upstream speed byte3 and endpoint interval byte6. Speed<3 stores
   interval*1000 at+2D0; otherwise stores unsigned32(125 << ((interval-1)&31)). Calls
   usbh_submit_urb(hub+2BC) once. No explicit recovery/rearm after a failed immediate submission.
   Boundaries: No connected,root,endpoint direction/type/size or pointer checks. Other URB bytes are
   preserved locally, including previous actual/error/channel/toggle. The requested transfer writes
   one byte; worker later reads two bitmap bytes. Known attachment admits at most four child ports,
   so its meaningful change bits fit the first byte. Raw interval0 and values beyondUSB-valid range
   still follow masked32-bit shift behavior. SDK/peripheral reachability and pending transfer
   lifetime are separate. */

/*
 * hub: Live external hub with valid upstream port, endpoint and interrupt buffer.
 * Returns: No value; submission status is ignored.
 * Requirements/effects: Fills only
 *   setup/timeout/buffer/completion/hubport/endpoint/remaining/context and interval in its
 *   embedded URB, preserving other URB fields. Caches upstream/endpoint/buffer, reads upstream
 *   speed before endpoint interval, then uses interval*1000 for speed<3 or
 *   unsigned32(125<<((interval-1)&31)) otherwise. Requests one byte asynchronously with the hub as
 *   completion context. No pointer, connection, interval-range, endpoint-type or immediate-failure
 *   recovery check occurs. Hub and buffer lifetime must cover the pending URB and callback. A
 *   later worker reads a two-byte bitmap; attachment admits at most four meaningful child bits.
 */

void medius_usbh_hub_poll(MediusHostHubState *hub)
{
    volatile MediusHostHubState *state = hub;
    uchar *buffer = state->interrupt_buffer;
    MediusHostHubPortPrefix *upstream = state->upstream_port;
    state->interrupt_urb.setup = 0;
    state->interrupt_urb.timeout = 0;
    uchar *endpoint = state->interrupt_endpoint;
    state->interrupt_urb.buffer = buffer;
    state->interrupt_urb.complete = medius_usbh_hub_interrupt_complete;
    state->interrupt_urb.hubport = upstream;
    state->interrupt_urb.endpoint = endpoint;
    state->interrupt_urb.remaining = 1;
    state->interrupt_urb.context = hub;
    uchar speed = *(const volatile uchar *)&upstream->speed;
    uint interval = ((const volatile uchar *)endpoint)[6];
    uint interval_us = speed < 3 ? interval * 1000U : 125U << ((interval - 1U) & 31U);
    state->interrupt_urb.interval_us = interval_us;
    usbh_submit_urb(&hub->interrupt_urb);
}

/* Native entry: 0x4200a860. */
/*
 * Medius v3.4.7 — host application; 0x4200a860.
 *
 * Publishes a positive hub interrupt result, retries exact-10, and ignores every other completion.
 *
 * Calls: medius_usbh_queue_send_value, usb_osal_timer_start.
 *
 * Original function-byte SHA-256:
 * 21f2fb531961fb8d9ccd0b5ca47cfe598d6bc38d56f57a82bdef7953e8393fb1.
 */

/* Publishes a positive hub interrupt result, retries exact-10, and ignores every other completion.
   If result>0, reads hub.bus+2B4 then bus.queue+330 and sends the hub pointer as a32-bit queue
   value. If result==-10, reads hub.timer+304 and calls usb_osal_timer_start. Zero and all other
   negative values perform no delegated calls. Queue send/restart outcomes are ignored; no local
   state writes. Boundaries: No pointer/connected or queue/timer validity guard. Positive completion
   does not inspect bitmap contents here. Task-context queue send may block indefinitely through
   OSAL; callback execution context is delegated. Queue failure does not schedule a retry. Retained
   hub must outlive both callback and queued pointer consumption. */

/*
 * context: Borrowed hub callback context retained through URB completion and any queued pointer
 *   consumption.
 * result: Signed completion result; positive publishes, exact -10 restarts timer.
 * Returns: No value.
 * Requirements/effects: Positive results enqueue the hub pointer through its current bus queue;
 *   exact -10 restarts its current software timer. Zero and other negatives do nothing. Both
 *   delegated statuses are ignored, with no bitmap inspection, local state writes, connection
 *   guard or recovery after failed enqueue. The software timer is dispatched by the shared ESP
 *   timer task and is not guaranteed to run on time: scheduler load, task priority, interrupts,
 *   critical sections and earlier callbacks can delay it. Queue blocking depends on execution
 *   context through OSAL.
 */

void medius_usbh_hub_interrupt_complete(void *context,int result)
{
    MediusHostHubState *hub = context;
    if (result > 0)
        medius_usbh_queue_send_value(hub->bus->hub_queue,(uint)hub);
    else if (result == -10)
        usb_osal_timer_start(hub->interrupt_timer);
}

/* Native entry: 0x4200a884. */
/*
 * Medius v3.4.7 — host application; 0x4200a884.
 *
 * Issues hub GET_STATUS and copies four external-hub status bytes on any nonnegative transfer
 * result.
 *
 * Calls: usbh_control_transfer, usbh_roothub_control.
 *
 * Called by: medius_usbh_hub_attach, usbh_hub_thread.
 *
 * Original function-byte SHA-256:
 * b988086557eef1a738158ea5732482b90c69ee9f58ba69456e2c100811735a18.
 */

/* Issues hub GET_STATUS and copies four external-hub status bytes on any nonnegative transfer
   result. Nonzero is_root byte builds borrowed stack setup[A3,00,00,00,portlo,porthi,04,00] and
   calls usbh_roothub_control(hub.bus,setup,status), returning its result. External route captures
   hub.upstream and its setup pointer+44, writes shared setup[A3,00,00,00,portlow8,00,04,00], reads
   bus.id byte4 and submits control to scratch3FC9FF84+32*id. On negative return leaves output
   untouched locally. On ANY nonnegative result, rereads hub.bus and id and copies exactly4 bytes
   from that current scratch slot to status. Aligned destination uses a32-bit load/store. Unaligned
   destination uses32-bit and16-bit source reads, a16-bit destination store followed by bytes2/3.
   Source is always4-aligned, making the generic equal-misalignment prefix/tail copy branches
   unreachable for this fixed source calculation. Boundaries: No output capacity, port range or
   bus-index bounds check, and no requirement that returned actual equals4. Short success can copy
   stale scratch bytes. Bus change can select a different scratch slot than the transfer
   destination. External setup writes occur BEFORE the control helper takes its mutex; the helper
   lock alone does not serialize request construction. Output/input overlap and physical
   misaligned-access behavior are not promised; emulator cases include all four alignments without
   asserting hardware acceptance. Root output writes are delegated and may occur even on failure. */

/*
 * hub: Live root or external hub; no local pointer/connection validation.
 * port: Root forwards all16 bits; external request stores only low8.
 * status: Writable four-byte output, with native word or potentially unaligned halfword stores on
 *   the external path.
 * Returns: The root/control request result unchanged, including short nonnegative results.
 * Requirements/effects: Root builds eight stack SETUP bytes with four ordered halfword stores,
 *   preserves16-bit port and delegates output handling. External builds A3 00 00 00 port_low 00 04
 *   00 in the upstream shared SETUP buffer before its control mutex. Captures bus pointer during
 *   construction, reads its ID afterwards and requests data at fixed scratch+32*ID. Negative
 *   result makes no local output copy. Any nonnegative result freshly reads hub bus/ID and copies
 *   four bytes from that current slot, even after a short transfer or bus change. Aligned
 *   destination gets one word read/store; other alignments get source word then source halfword,
 *   destination halfword then bytes2/3. No capacity, bus-range, port-range, output-alignment or
 *   actual==4 guard occurs. Stale/mixed source data and misaligned hardware faults are possible;
 *   no physical alignment acceptance or ownership guarantee is supplied.
 */

int medius_usbh_hub_get_port_status(MediusHostHubState *hub,ushort port,uchar *status)
{
    if (hub->is_root != 0) {
        MediusHostBusPrefix *bus = hub->bus;
        MediusUsbSetup setup;
        *(volatile ushort *)&setup.request_type = 0x00a3;
        *(volatile ushort *)&setup.value = 0;
        *(volatile ushort *)&setup.index = port;
        *(volatile ushort *)&setup.length = 4;
        return usbh_roothub_control(bus,(uchar *)&setup,status);
    }
    MediusHostHubPortPrefix *upstream = hub->upstream_port;
    volatile uchar *setup = upstream->setup;
    setup[0] = 0xa3;
    setup[1] = 0;
    MediusHostBusPrefix *transfer_bus = *(MediusHostBusPrefix * const volatile *)&hub->bus;
    setup[5] = 0;
    setup[4] = (uchar)port;
    setup[2] = 0;
    setup[3] = 0;
    setup[6] = 4;
    setup[7] = 0;
    uchar transfer_bus_id = *(const volatile uchar *)&transfer_bus->id;
    uchar *transfer_data = (uchar *)(0x3fc9ff84U + (uint)transfer_bus_id * 32U);
    int result = usbh_control_transfer(upstream,(uchar *)setup,transfer_data);
    if (result >= 0) {
        MediusHostBusPrefix *copy_bus = *(MediusHostBusPrefix * const volatile *)&hub->bus;
        uchar copy_bus_id = *(const volatile uchar *)&copy_bus->id;
        uint source = 0x3fc9ff84U + (uint)copy_bus_id * 32U;
        uint word = *(const volatile uint *)source;
        if (((uint)status & 3U) == 0) {
            *(volatile uint *)status = word;
        } else {
            ushort low = *(const volatile ushort *)source;
            *(volatile ushort *)status = low;
            ((volatile uchar *)status)[2] = (uchar)(word >> 16);
            ((volatile uchar *)status)[3] = (uchar)(word >> 24);
        }
    }
    return result;
}

/* Native entry: 0x4200a95c. */
/*
 * Medius v3.4.7 — host application; 0x4200a95c.
 *
 * Builds the hub port-feature request with low8 port/feature fields. Emits reset notification
 * after successful SET_FEATURE4.
 *
 * Calls: usbh_control_transfer, usbh_roothub_control.
 *
 * Called by: medius_host_apply_generation, medius_usbh_hub_attach, usbh_hub_thread.
 *
 * Unresolved indirect call sites: 1.
 *
 * Original function-byte SHA-256:
 * 6ade008cf12d29fb4a44b11f6fa77c15995f7897d0262a2dc9cadee473654c21.
 */

/* Builds the hub port-feature request with low8 port/feature fields. Emits reset notification after
   successful SET_FEATURE4. Builds setup[23,03,feature,00,port,00,00,00]. Nonzero is_root uses
   an8-byte stack descriptor and usbh_roothub_control(bus,setup,NULL). External path writes the
   upstream port setup before calling usbh_control_transfer(upstream,setup,NULL). On nonnegative
   result and low8 feature==4 only, rereads hub.bus,hub.index and bus.id/callback, then calls
   callback(bus.id,hub.index,portlow8,FF,2). Callback result is ignored and original request result
   preserved. Boundaries: No port/feature/callback/pointer validation or local lock. External shared
   setup construction precedes control mutex acquisition. Request success only means a nonnegative
   local result; callback is unconditionally invoked when its SET4 conditions hold, without NULL
   check. Callback metadata is loaded after the request and may have changed. */

/*
 * hub: Live hub with bus or upstream port/setup pointers.
 * port: Low8 port number; no range check.
 * feature: Low8 feature selector; forwarded without validation.
 * Returns: The delegated request result unchanged; any event callback result is ignored.
 * Requirements/effects: Builds SETUP [23,03,feature,00,port,00,00,00]. Root path uses four
 *   halfword stores to an eight-byte stack packet; external path uses eight byte stores to shared
 *   upstream SETUP before delegated locking. Both use NULL data. For a nonnegative result and
 *   feature4 only, freshly loads bus, hub index, event callback and bus ID in that order, then
 *   calls event(id,index,port,255,2) while preserving request result. No callback NULL guard
 *   occurs. No local lock, pointer, feature or port validation is added. The root/control helper
 *   owns USB effects and any borrowed-buffer lifetime requirements.
 */

int medius_usbh_hub_set_port_feature(MediusHostHubState *hub,uchar port,uchar feature)
{
    int result;
    if (hub->is_root != 0) {
        MediusHostBusPrefix *bus = hub->bus;
        MediusUsbSetup setup;
        *(volatile ushort *)&setup.request_type = 0x0323;
        *(volatile ushort *)&setup.value = feature;
        *(volatile ushort *)&setup.index = port;
        *(volatile ushort *)&setup.length = 0;
        result = usbh_roothub_control(bus,(uchar *)&setup,0);
    } else {
        MediusHostHubPortPrefix *upstream = hub->upstream_port;
        volatile uchar *setup = upstream->setup;
        setup[0] = 0x23;
        setup[1] = 3;
        setup[2] = feature;
        setup[3] = 0;
        setup[4] = port;
        setup[5] = 0;
        setup[6] = 0;
        setup[7] = 0;
        result = usbh_control_transfer(upstream,(uchar *)setup,0);
    }
    if (result >= 0 && feature == 4) {
        MediusHostBusPrefix *bus = *(MediusHostBusPrefix * const volatile *)&hub->bus;
        uchar hub_index = *(const volatile uchar *)&hub->index;
        MediusHostEventHandler callback = *(MediusHostEventHandler const volatile *)&bus->event;
        uchar bus_id = *(const volatile uchar *)&bus->id;
        callback((uint)bus_id,(uint)hub_index,(uint)port,255,2);
    }
    return result;
}

/* Native entry: 0x4200a9e0. */
/*
 * Medius v3.4.7 — host application; 0x4200a9e0.
 *
 * Reserves the single external hub, copies its descriptor, powers ports and creates its polling
 * timer without rollback on later failures.
 *
 * Calls: FUN_4201654c, medius_host_report_enumeration_limit, medius_usbh_hub_get_port_status,
 * medius_usbh_hub_set_port_feature, memset, usb_osal_msleep, usb_osal_timer_create,
 * usb_osal_timer_start, usbh_control_transfer, usbh_roothub_control.
 *
 * Original function-byte SHA-256:
 * dd6531693b2c855168c1bbc16cb49ab5e4fdcb4e248b823d3d3b3cae77cc1b28.
 */

/* Reserves the single external hub, copies its descriptor, powers ports and creates its polling
   timer without rollback on later failures. If allocator bit0 is already set, reports(port,3,0)
   through4202F130 and returns-1 without reservation changes. Otherwise ORs bit0, zeros exactly308
   hub bytes, sets index2,address fromport+2,speed fromport+3,upstream pointer and bus fromport+50.
   Stores hub into port+4C and interface[low8 index]*20hex+14 BEFORE validating depth. Depth byte4>5
   returns-2 with reservation and aliases retained. Exact speed5 and nonzero depth issue
   SET_HUB_DEPTH[20,0C,depth-1 as16bit,0,0]; negative result is returned. Its root route exists in
   the assembly but ordinary zero-initialization leaves is_root0; a concurrent mutation is needed to
   select it. Then reloads upstream/speed/bus as in the original body and issues GET_DESCRIPTOR
   A0/06,value2A00,length11 for exact speed5, otherwise2900,length9, into3FC9FF84+32*bus.id.
   Negative result returns; any nonnegative result copies all11/9 bytes from the freshly reloaded
   bus-id scratch slot, without actual-length/type validation. USB2 descriptor bytes copy to
   hub+9..17, SS bytes to+18..28. Port count=descriptor byte2, power delay=low8(2*byte5); TT
   think-time=descriptor characteristic bits5..6 forUSB2,0 forSS. Count>4
   reports(port,2,count),returns-1. Count0 is allowed. For each admitted child i, writes port number
   i+1,parent=hub,bus=the freshly loaded port+50; the rest remains zero. Sets multi-TT byte8 iff
   parent descriptor byte13==2. Loads selected interface alternate pointer+18, requires
   endpoint-count byte+4 nonzero and first endpoint address byte2 IN bit7. No transfer-type check.
   Captures endpoint at hub+2B8. Powers ports1..current count using SET_FEATURE8, rereading count
   after each call; any negative returns directly. Delays by current power-delay byte, then
   GET_STATUS for ports1..current count using a borrowed stack output, returning immediately on
   negative. Sets hub.connected1, formats /dev/hub<index> into the interface name field with
   limit16, ignoring formatting result. Computes interrupt buffer=3FC9FF7C+4*(2*current
   bus.id+current hub.index-1). Creates timer hubint_tim with
   callback4200A7FC,argument=hub,periodic0. For parent speed<3, timeout milliseconds=raw endpoint
   interval byte; otherwise computes int32(125 << ((interval-1)&31))/1000 with SIGNED truncation
   toward zero, then passes the quotient bits as uint32 milliseconds. Stores timer result+304; NULL
   returns-1 with active hub retained. Non-NULL timer is started and returns0 regardless of start
   outcome. Boundaries: No cleanup on any post-reservation failure; caller must invoke detach
   through retained aliases. One slot does not imply more than four child records. Mutable counts in
   power/status loops are not revalidated against4; pointer/count/descriptor lifetimes and
   concurrent modifications require external control. Shared setup construction precedes mutex
   acquisition. Short successful descriptors can retain stale scratch bytes; no descriptor
   length/type, interface index or endpoint-array capacity check. For invalid high interval bytes,
   signed timer division can produce negative quotient bits interpreted as very large milliseconds;
   generated C previously rendered unsigned-looking division, so original MULSH/SRAI/SUB
   at4200ACAE..BA and executed cases are authoritative. The subsequent poll helper retains the
   raw32-bit shifted microseconds, a different conversion. Synthetic tests exercise a root-flag
   mutation explicitly; this is not a normal root-hub attachment path. */

/*
 * port: Live parent hub-port object with setup, bus, descriptor and interface storage; not locally
 *   validated.
 * interface_index: Low8 index into the parent interface table, with no count check.
 * Returns: 0 after starting a nonNULL polling timer, -1 for occupied slot/too many ports/missing
 *   IN endpoint/timer allocation, -2 for depth>5, or first negative request result. Timer-start
 *   status is ignored.
 * Requirements/effects: Reserves external slot bit0 from one cached word, zeroes776 bytes,
 *   publishes hub identity/upstream/bus/parent and interface aliases before depth validation;
 *   every later failure retains them. Exact speed5 and nonzero depth issues SET_HUB_DEPTH using
 *   root stack or upstream shared SETUP route, then GET_DESCRIPTOR9 or11 bytes. Copies full
 *   advertised descriptor despite short nonnegative result using a fresh bus scratch slot, native
 *   word/halfword/byte snapshots and store order. Derives count/power delay/TT, admits count0..4,
 *   initializes children from cached count and fresh parent bus each. Requires a nonempty selected
 *   alternate and first endpoint IN bit, without checking transfer type. Powers live-count ports,
 *   waits the current low8 doubled delay, then status-checks live-count ports; failures return
 *   without rollback. Publishes connected before formatting name, reloads bus/index/endpoint/speed
 *   and computes interrupt-buffer slot. For speed>=3, interval conversion is
 *   signed32(125U<<((interval-1)&31))/1000, then uint32 milliseconds; this is not the poll helper
 *   microsecond conversion. Creates nonperiodic OSAL timer and starts even if start may fail.
 *   Caller must serialize reservation, shared SETUP, pointers and mutable counts; no
 *   lock/capacity/short-descriptor validation, timer deadline guarantee or lifetime proof is
 *   provided. Root depth route requires externally changed root flag after zeroing.
 */

int medius_usbh_hub_attach(MediusHostHubPortPrefix *port,uchar interface_index)
{
    uint slots = HOST_EXTERNAL_HUB_SLOTS;
    if (slots & 1U) {
        medius_host_report_enumeration_limit(port,3,0);
        return -1;
    }
    HOST_EXTERNAL_HUB_SLOTS = slots | 1U;
    MediusHostHubState *hub = HOST_EXTERNAL_HUB;
    volatile MediusHostHubState *state = hub;
    volatile MediusHostHubPortPrefix *upstream_state = port;
    memset(hub,0,0x308);
    state->index = 2;
    uchar address = upstream_state->device_address;
    MediusHostBusPrefix *bus = upstream_state->bus_context;
    MediusHostInterfacePrefix *interfaces = upstream_state->interfaces;
    state->upstream_port = port;
    state->bus = bus;
    state->device_address = address;
    uchar initial_speed = upstream_state->speed;
    *(MediusHostHubState * volatile *)((uint)port + 0x4cU) = hub;
    state->speed = initial_speed;
    ((volatile MediusHostInterfacePrefix *)((uint)interfaces + (uint)interface_index * 32U))
        ->private_data = hub;
    uchar depth = upstream_state->depth;
    if (depth > 5)
        return -2;
    MediusUsbSetup scratch; /* Reused as the later four-byte GET_STATUS output. */
    if (depth != 0 && initial_speed == 5) {
        uchar root = state->is_root;
        ushort value = (ushort)(depth - 1U);
        int result;
        if (root != 0) {
            *(volatile ushort *)&scratch.request_type = 0x0c20;
            *(volatile ushort *)&scratch.value = value;
            *(volatile ushort *)&scratch.index = 0;
            *(volatile ushort *)&scratch.length = 0;
            result = usbh_roothub_control(bus,(uchar *)&scratch,0);
        } else {
            MediusHostHubPortPrefix *upstream = state->upstream_port;
            volatile uchar *setup = ((const volatile MediusHostHubPortPrefix *)upstream)->setup;
            setup[0] = 0x20;
            setup[1] = 0x0c;
            setup[2] = (uchar)value;
            setup[3] = (uchar)(value >> 8);
            setup[4] = 0;
            setup[5] = 0;
            setup[6] = 0;
            setup[7] = 0;
            result = usbh_control_transfer(upstream,(uchar *)setup,0);
        }
        if (result < 0)
            return result;
        bus = state->bus;
    }
    uchar transfer_bus_id = ((const volatile MediusHostBusPrefix *)bus)->id;
    MediusHostHubPortPrefix *upstream = state->upstream_port;
    uchar descriptor_speed = upstream_state->speed;
    volatile uchar *setup = ((const volatile MediusHostHubPortPrefix *)upstream)->setup;
    uchar *transfer_data = (uchar *)((uint)HOST_HUB_STATUS_SCRATCH + (uint)transfer_bus_id * 32U);
    setup[0] = 0xa0;
    setup[1] = 6;
    setup[3] = descriptor_speed == 5 ? 0x2a : 0x29;
    setup[2] = 0;
    setup[4] = 0;
    setup[5] = 0;
    setup[6] = descriptor_speed == 5 ? 11 : 9;
    setup[7] = 0;
    int result = usbh_control_transfer(upstream,(uchar *)setup,transfer_data);
    if (result < 0)
        return result;
    MediusHostBusPrefix *copy_bus = state->bus;
    uchar copy_bus_id = ((const volatile MediusHostBusPrefix *)copy_bus)->id;
    uint source = (uint)HOST_HUB_STATUS_SCRATCH + (uint)copy_bus_id * 32U;
    uchar port_count;
    uchar think_time;
    if (descriptor_speed == 5) {
        uint second_word = *(const volatile uint *)(source + 4U);
        uint first_word = *(const volatile uint *)source;
        ushort first_half = *(const volatile ushort *)source;
        ushort second_half = *(const volatile ushort *)(source + 4U);
        ushort third_half = *(const volatile ushort *)(source + 8U);
        uchar last_byte = *(const volatile uchar *)(source + 10U);
        port_count = (uchar)(first_word >> 16);
        *(volatile ushort *)&state->superspeed_descriptor[0] = first_half;
        state->superspeed_descriptor[2] = port_count;
        state->superspeed_descriptor[3] = (uchar)(first_word >> 24);
        *(volatile ushort *)&state->superspeed_descriptor[4] = second_half;
        state->superspeed_descriptor[6] = (uchar)(second_word >> 16);
        state->superspeed_descriptor[7] = (uchar)(second_word >> 24);
        *(volatile ushort *)&state->superspeed_descriptor[8] = third_half;
        state->superspeed_descriptor[10] = last_byte;
        state->port_count = port_count;
        state->power_on_delay_ms = (uchar)((second_word >> 8) * 2U);
        think_time = 0;
    } else {
        uint first_word = *(const volatile uint *)source;
        uint second_word = *(const volatile uint *)(source + 4U);
        state->hub_descriptor[3] = (uchar)(first_word >> 24);
        state->hub_descriptor[4] = (uchar)second_word;
        uchar last_byte = *(const volatile uchar *)(source + 8U);
        ushort characteristics = *(const volatile ushort *)&state->hub_descriptor[3];
        port_count = (uchar)(first_word >> 16);
        state->hub_descriptor[0] = (uchar)first_word;
        state->hub_descriptor[1] = (uchar)(first_word >> 8);
        state->hub_descriptor[2] = port_count;
        state->hub_descriptor[5] = (uchar)(second_word >> 8);
        state->hub_descriptor[6] = (uchar)(second_word >> 16);
        state->hub_descriptor[7] = (uchar)(second_word >> 24);
        state->hub_descriptor[8] = last_byte;
        state->port_count = port_count;
        state->power_on_delay_ms = (uchar)((second_word >> 8) * 2U);
        think_time = (uchar)((characteristics >> 5) & 3U);
    }
    state->tt_think_time = think_time;
    if (port_count > 4) {
        medius_host_report_enumeration_limit(port,2,port_count);
        return -1;
    }
    for (uint child = 0; child < port_count; ++child) {
        volatile MediusHostHubPortPrefix *child_state = &state->ports[child];
        child_state->port_number = (uchar)(child + 1U);
        MediusHostBusPrefix *child_bus = upstream_state->bus_context;
        child_state->parent = (MediusHostHubPrefix *)hub;
        child_state->bus_context = child_bus;
    }
    uchar protocol = upstream_state->device_descriptor[6];
    interfaces = upstream_state->interfaces;
    MediusHostAlternatePrefix *alternate = ((const volatile MediusHostInterfacePrefix *)
        ((uint)interfaces + (uint)interface_index * 32U))->alternates;
    state->multi_tt = protocol == 2;
    if (((const volatile MediusHostAlternatePrefix *)alternate)->endpoint_count == 0)
        return -1;
    uchar *endpoint = ((const volatile MediusHostAlternatePrefix *)alternate)->endpoints;
    if ((((const volatile uchar *)endpoint)[2] & 0x80U) == 0)
        return -1;
    state->interrupt_endpoint = endpoint;
    uchar powered_port = 0;
    uint power_count = port_count;
    while (powered_port < power_count) {
        powered_port = (uchar)(powered_port + 1U);
        result = medius_usbh_hub_set_port_feature(hub,powered_port,8);
        if (result < 0)
            return result;
        power_count = state->port_count;
    }
    uchar delay_ms = state->power_on_delay_ms;
    usb_osal_msleep(delay_ms);
    uchar status_port = 0;
    for (;;) {
        uchar status_count = state->port_count;
        if (status_port >= status_count)
            break;
        status_port = (uchar)(status_port + 1U);
        result = medius_usbh_hub_get_port_status(hub,status_port,(uchar *)&scratch);
        if (result < 0)
            return result;
    }
    interfaces = upstream_state->interfaces;
    uchar name_index = state->index;
    state->connected = 1;
    MEDIUS_HOST_SNPRINTF((char *)((uint)interfaces + (uint)interface_index * 32U),16,
                 "/dev/hub%d",name_index);
    MediusHostBusPrefix *interrupt_bus = state->bus;
    uchar interrupt_index = state->index;
    uchar interrupt_bus_id = ((const volatile MediusHostBusPrefix *)interrupt_bus)->id;
    state->interrupt_buffer = (uchar *)((uint)HOST_HUB_INTERRUPT_BUFFERS +
        ((uint)interrupt_bus_id * 2U + (uint)interrupt_index - 1U) * 4U);
    endpoint = state->interrupt_endpoint;
    uchar timer_speed = upstream_state->speed;
    uchar interval = ((const volatile uchar *)endpoint)[6];
    uint milliseconds = interval;
    if (timer_speed >= 3) {
        uint shifted_microseconds = 125U << ((interval - 1U) & 31U);
        milliseconds = (uint)((int)shifted_microseconds / 1000);
    }
    MediusUsbOsalTimer *timer = usb_osal_timer_create("hubint_tim",milliseconds,
        (MediusUsbTimerCallback)medius_usbh_hub_poll,hub,0);
    state->interrupt_timer = timer;
    if (timer == 0)
        return -1;
    usb_osal_timer_start(timer);
    return 0;
}

/* Native entry: 0x4200ace0. */
/*
 * Medius v3.4.7 — host application; 0x4200ace0.
 *
 * Builds the hub port-feature request with low8 port/feature fields.
 *
 * Calls: usbh_control_transfer, usbh_roothub_control.
 *
 * Called by: usbh_hub_thread.
 *
 * Original function-byte SHA-256:
 * eb982372c98cb0660f38f118d1a9631ba5e64689dd9fa1e2c43adc6124016bec.
 */

/* Builds the hub port-feature request with low8 port/feature fields. Builds
   setup[23,01,feature,00,port,00,00,00]. Nonzero is_root uses an8-byte stack descriptor and
   usbh_roothub_control(bus,setup,NULL). External path writes the upstream port setup before calling
   usbh_control_transfer(upstream,setup,NULL). There is no post-request event callback. Boundaries:
   No port/feature/callback/pointer validation or local lock. External shared setup construction
   precedes control mutex acquisition. Request success only means a nonnegative local result;
   callback is unconditionally invoked when its SET4 conditions hold, without NULL check. No
   reset/clear-state effects are performed locally beyond setup bytes. */

/*
 * hub: Live hub with bus or upstream port/setup pointers.
 * port: Low8 port number; no range check.
 * feature: Low8 feature selector; forwarded without validation.
 * Returns: The delegated request result unchanged; any event callback result is ignored.
 * Requirements/effects: Builds SETUP [23,01,feature,00,port,00,00,00]. Root path uses four
 *   halfword stores to an eight-byte stack packet; external path uses eight byte stores to shared
 *   upstream SETUP before delegated locking. Both use NULL data. There is no completion event
 *   callback or local reset/clear-state update. No local lock, pointer, feature or port validation
 *   is added. The root/control helper owns USB effects and any borrowed-buffer lifetime
 *   requirements.
 */

int medius_usbh_hub_clear_port_feature(MediusHostHubState *hub,uchar port,uchar feature)
{
    int result;
    if (hub->is_root != 0) {
        MediusHostBusPrefix *bus = hub->bus;
        MediusUsbSetup setup;
        *(volatile ushort *)&setup.request_type = 0x0123;
        *(volatile ushort *)&setup.value = feature;
        *(volatile ushort *)&setup.index = port;
        *(volatile ushort *)&setup.length = 0;
        result = usbh_roothub_control(bus,(uchar *)&setup,0);
    } else {
        MediusHostHubPortPrefix *upstream = hub->upstream_port;
        volatile uchar *setup = upstream->setup;
        setup[0] = 0x23;
        setup[1] = 1;
        setup[2] = feature;
        setup[3] = 0;
        setup[4] = port;
        setup[5] = 0;
        setup[6] = 0;
        setup[7] = 0;
        result = usbh_control_transfer(upstream,(uchar *)setup,0);
    }
    return result;
}

/* Native entry: 0x4200ad3c. */
/*
 * Medius v3.4.7 — host application; 0x4200ad3c.
 *
 * Processes hub changes, debounce, reset, enumeration and shutdown.
 *
 * Calls: FUN_4201fef4, medius_usbh_critical_enter, medius_usbh_critical_exit,
 * medius_usbh_hub_clear_port_feature, medius_usbh_hub_get_port_status,
 * medius_usbh_hub_set_port_feature, memset, usb_hc_init, usb_osal_mq_delete, usb_osal_mq_recv,
 * usb_osal_msleep, usb_osal_mutex_create, usb_osal_sem_give, usb_osal_thread_delete,
 * usb_osal_timer_start, usbh_enumerate, usbh_hubport_release.
 *
 * Unresolved indirect call sites: 2.
 *
 * Original function-byte SHA-256:
 * 5259b744b63e69bbe6bd2a8d8a36e6dc380594ab715265ef7519e115856f20d8.
 */

/* Scheduling review: usbh_hub0: USB priority 0 maps to FreeRTOS 24; stack 8192 bytes, core 0,
 * creator 0x4200b090. Waits on a seven-word hub event queue. External-hub polling timer callbacks
 * submit asynchronous transfers; completion queues change notification for this worker. This task
 * handles port reset/debounce/enumeration and restarts external-hub one-shot polling after
 * processing. NULL queue value requests ordered shutdown. The hub worker can temporarily drop to
 * priority 0 through the HID disconnect scheduling helper.
 */

/* Processes hub change bitmaps, debounce/reset/enumeration and ordered shutdown, including an
   unbounded change-clear retry and a real allocation-failure guard. Calls initial
   callback(bus.id,0,0,FF,12), then usb_hc_init(bus), ignoring result. Repeatedly receives queue
   values with FFFFFFFF; negative receive results retry immediately. NULL value triggers shutdown.
   Non-NULL inactive hub.connected0 is skipped without rearming. For active hub, enters driver
   critical section, copies exactly TWO bytes from current interrupt_buffer+300 into local16 bitmap
   through byte loads, then unlocks. Shared bitmap is not cleared. Scans port numbers1..byte count
   with child pointer hub+20hex+(port-1)*A4. Bit test uses port modulo32; only local bitmap is
   cleared. An unselected port is skipped. Selected GET_STATUS negative skips that port. For
   returned change mask, scans16 bits ascending and CLEAR_FEATURE(16+bit); each negative clear
   result retries the SAME feature indefinitely without delay or decrement limit. Only after all
   initial change bits clear does initial connection-change bit0 trigger debounce. Debounce starts
   previous connected0,stable0 and budget60. Each successful sample without fresh C_CONNECTION and
   equal connected bit adds25 to a16-bit stable counter; stable>=100 completes immediately without a
   final25 delay. Changed connected bit or fresh C_CONNECTION resets stable0; the latter also
   attempts CLEAR_FEATURE16 but ignores its result. Successful nonterminal samples sleep25 and
   update previous connected. Failed GET_STATUS consumes an attempt without sleeping or replacing
   prior state. Budget exhaustion abandons the rest of this hub event (rather than continuing
   remaining ports). Stable disconnect releases the current child. Stable connect emits
   callback(current bus.id,hub.index,port,FF,3), then SET_FEATURE4; negative reset request skips
   port without release. For external hub only, performs up to80 iterations of sleep10 then
   GET_STATUS; negative result or reset bit4 clear ends polling, but even timeout/error proceeds to
   sleep50 and a final GET_STATUS. Root hubs omit that80-loop and still sleep50/final status.
   Negative final read skips port. Final status must satisfy (status&12hex)==2 (enabled and not
   reset), else child is released. If final C_RESET bit4 is set, CLEAR_FEATURE20 failure skips port
   without release. Speed decoding: if status bit8 set,bit10 selects3,otherwise bit9 selects1
   versus2; if bit8 clear,bit9 selects5; neither bit8 nor9 skips without release. No separate final
   connection-bit check. For accepted speed, releases old child, zeros exactlyA4 bytes, stores
   parent hub,depth=1 or low8(upstream.depth+1),port low8,speed,connected1,bus fromhub. Creates
   mutex and stores child+A0. NULL enters original unconditional self-jump4200AFD5 with initialized
   child retained; no cleanup. Otherwise calls enumeration4200A178; a negative result releases child
   again. Rereads hub.port_count when advancing. After processing or debounce abort, external
   still-active hub restarts its timer; root or now-inactive hub does not. On NULL queue value,
   releases root children atbus+30+i*A4 using freshly read root count, calls controller
   deinit4201FEF4(bus), deletes current queue, gives current semaphore, deletes current task
   viaNULL, then returns only if self-deletion returns. Worker itself does not clear bus handles.
   Boundaries: Borrowed queued hub pointers and child arrays require valid lifetimes; no source
   queue-item,bitmap length or count-capacity validation. Normal external attachment admits<=4
   children and root initialization1, while this worker trusts later byte counts. Local bitmap and
   later object fields are separate snapshots; callbacks may change bus/count/activity. Change-clear
   retry and receive loop have no local completion guarantee. Debounce is an attempt/delay
   algorithm, not measured1500ms wall time: failed status calls do not sleep and other requests can
   block. The80 reset wait can expire yet enumeration still proceed if final status admits it. Mutex
   allocation failure is a byte-confirmed nonreturn guard; three self-jump cycles are executed
   before deliberate test interruption. Repeated clear failure likewise is observed for three
   complete retries then interrupted, not claimed to terminate. Controller internals,
   enumeration/release internals, callback target sets and concurrent cleanup remain separate. A
   failed queue deletion or semaphore give is ignored, and self-deletion normally need not return.
    */

/*
 * bus: Worker-owned828-byte bus with event callback, queue, shutdown semaphore and embedded root
 *   hub at+16; valid borrowed hub/child lifetimes are required.
 * Returns: Normally runs indefinitely or self-deletes; returns only after NULL-queue shutdown if
 *   self-deletion returns. Mutex failure is a real nonreturning self-branch.
 * Requirements/effects: Loads initial bus ID before callback pointer and emits event12, then
 *   ignores controller-init status. Fresh queue receives wait forever; negative statuses retry,
 *   inactive hub values skip. Under driver critical boundary copies exactly2 interrupt bytes
 *   without clearing source. Scans ascending ports with raw164-byte child strides; unselected
 *   ports retain cached count, selected paths reload count when advancing. Clears every initial
 *   change bit ascending; each failed clear retries same feature indefinitely. Fresh result
 *   changes bit0 triggers up to60 debounce samples: failed reads consume attempts without delay,
 *   equal connected/no-change adds25 to16-bit stable, stable>=100 exits before sleep, changed/new-
 *   change resets stable and new-change attempts clear16 ignoring result. Nonterminal successful
 *   samples delay25 ticks-equivalent milliseconds through OSAL. Exhaustion abandons remaining
 *   ports in this event. Stable disconnect releases child. Connect emits fresh bus/hub event3 then
 *   reset4; negative reset skips release. External reset waits at most80 sleep10/status
 *   iterations, then both root/external delay50 and final status regardless of reset
 *   timeout/error. Requires(final status&0x12)==2; bad status releases, failed final read/C_RESET-
 *   clear skips. Cached final speed bits decode3/1/2/5; unknown skips. Releases/zeros child164,
 *   loads upstream before parent store, publishes wrapped depth/port/speed then fresh
 *   bus/connected, stores mutex; NULL halts retaining child. Enumeration failure releases again.
 *   External still-active hub rearms timer after event. NULL queue releases embedded root children
 *   with fresh byte count, deinitializes controller, deletes fresh queue, gives fresh semaphore,
 *   deletes NULL self without clearing handles. No count-capacity/pointer/connection/lifetime
 *   validation or rollback; delays and attempt budgets are not wall-time or scheduling guarantees.
 *   Caller must serialize mutable objects and callbacks; MMIO and OSAL boundaries do not prove
 *   physical timing or concurrency safety.
 */

void usbh_hub_thread(MediusHostBusPrefix *bus)
{
    volatile MediusHostBusPrefix *bus_state = bus;
    uchar initial_id = bus_state->id;
    MediusHostEventHandler initial_event = bus_state->event;
    initial_event(initial_id,0,0,255,12);
    usb_hc_init(bus);
    for (;;) {
        MediusHostHubState *hub;
        void *queue = bus_state->hub_queue;
        if (usb_osal_mq_recv(queue,(uint *)&hub,0xffffffffU) < 0)
            continue;
        if (hub == 0) {
            const volatile MediusHostHubState *root =
                (const volatile MediusHostHubState *)((uint)bus + 16U);
            uchar count = root->port_count;
            uchar released = 0;
            uint child_address = (uint)bus + 0x30U;
            while (released < count) {
                usbh_hubport_release((MediusHostHubPortPrefix *)child_address);
                released = (uchar)(released + 1U);
                count = root->port_count;
                child_address += 164U;
            }
            usb_hc_deinit(bus);
            void *delete_queue = bus_state->hub_queue;
            usb_osal_mq_delete(delete_queue);
            void *semaphore = bus_state->hub_shutdown_semaphore;
            usb_osal_sem_give(semaphore);
            usb_osal_thread_delete(0);
            return; /* Only reached if self-deletion returns. */
        }
        volatile MediusHostHubState *state = hub;
        if (state->connected == 0)
            continue;
        uint token = medius_usbh_critical_enter();
        const volatile uchar *interrupt_data = state->interrupt_buffer;
        uchar bitmap_low = interrupt_data[0];
        uchar bitmap_high = interrupt_data[1];
        ushort bitmap = (ushort)(bitmap_low | ((uint)bitmap_high << 8));
        medius_usbh_critical_exit(token);
        uint port_count = state->port_count;
        uint port_number = 1;
        uint child_address = (uint)hub + 32U;
        if (port_count != 0) {
            for (;;) {
                if ((bitmap & (1U << (port_number & 31U))) != 0) {
                    bitmap &= (ushort)~(1U << (port_number & 31U));
                    MediusHostHubPortStatus status;
                    int result = medius_usbh_hub_get_port_status(hub,(ushort)port_number,
                                                                (uchar *)&status);
                    if (result >= 0) {
                        ushort changes = status.changes;
                        ushort last_status = status.status;
                        if (changes != 0) {
                            ushort pending_changes = changes;
                            uint change_bit = 0;
                            while (pending_changes != 0) {
                                ushort mask = (ushort)(1U << (change_bit & 31U));
                                if ((pending_changes & mask) != 0) {
                                    do {
                                        result = medius_usbh_hub_clear_port_feature(
                                            hub,(uchar)port_number,(uchar)(16U + change_bit));
                                    } while (result < 0);
                                    pending_changes &= (ushort)~mask;
                                }
                                ++change_bit;
                            }
                            ushort fresh_changes = status.changes;
                            if (fresh_changes & 1U) {
                                uint previous_connected = 0;
                                uint stable_ms = 0;
                                uint attempts = 60;
                                uint connected;
                                for (;;) {
                                    result = medius_usbh_hub_get_port_status(
                                        hub,(ushort)port_number,(uchar *)&status);
                                    if (result < 0) {
                                        if (--attempts == 0) {
                                            if (stable_ms < 100)
                                                goto event_done;
                                            connected = last_status & 1U;
                                            break;
                                        }
                                        continue;
                                    }
                                    last_status = status.status;
                                    ushort sampled_changes = status.changes;
                                    connected = last_status & 1U;
                                    if ((sampled_changes & 1U) != 0) {
                                        medius_usbh_hub_clear_port_feature(hub,(uchar)port_number,16);
                                        stable_ms = 0;
                                    } else if (connected != previous_connected) {
                                        stable_ms = 0;
                                    } else {
                                        stable_ms = (stable_ms + 25U) & 0xffffU;
                                        if (stable_ms >= 100)
                                            break;
                                    }
                                    --attempts;
                                    usb_osal_msleep(25);
                                    if (attempts == 0)
                                        goto event_done;
                                    previous_connected = connected;
                                }
                                MediusHostHubPortPrefix *child =
                                    (MediusHostHubPortPrefix *)child_address;
                                if (connected == 0) {
                                    usbh_hubport_release(child);
                                } else {
                                    MediusHostBusPrefix *event_bus = state->bus;
                                    uchar hub_index = state->index;
                                    uchar bus_id = ((const volatile MediusHostBusPrefix *)event_bus)->id;
                                    MediusHostEventHandler event =
                                        ((const volatile MediusHostBusPrefix *)event_bus)->event;
                                    event(bus_id,hub_index,port_number,255,3);
                                    if (medius_usbh_hub_set_port_feature(hub,(uchar)port_number,4) < 0)
                                        goto advance_selected;
                                    if (state->is_root == 0) {
                                        for (uint remaining = 80; remaining != 0; --remaining) {
                                            usb_osal_msleep(10);
                                            result = medius_usbh_hub_get_port_status(
                                                hub,(ushort)port_number,(uchar *)&status);
                                            if (result < 0)
                                                break;
                                            ushort reset_status = status.status;
                                            if ((reset_status & 16U) == 0)
                                                break;
                                        }
                                    }
                                    usb_osal_msleep(50);
                                    result = medius_usbh_hub_get_port_status(
                                        hub,(ushort)port_number,(uchar *)&status);
                                    if (result < 0)
                                        goto advance_selected;
                                    ushort final_status = status.status;
                                    if ((final_status & 0x12U) != 2) {
                                        usbh_hubport_release(child);
                                    } else {
                                        ushort final_changes = status.changes;
                                        if ((final_changes & 16U) != 0 &&
                                            medius_usbh_hub_clear_port_feature(
                                                hub,(uchar)port_number,20) < 0)
                                            goto advance_selected;
                                        uchar speed;
                                        if (final_status & 0x100U)
                                            speed = (final_status & 0x400U) ? 3
                                                : (final_status & 0x200U) ? 1 : 2;
                                        else if (final_status & 0x200U)
                                            speed = 5;
                                        else
                                            goto advance_selected;
                                        usbh_hubport_release(child);
                                        memset(child,0,164);
                                        MediusHostHubPortPrefix *upstream = state->upstream_port;
                                        volatile MediusHostHubPortPrefix *child_state = child;
                                        child_state->parent = (MediusHostHubPrefix *)hub;
                                        uchar depth = upstream == 0 ? 1 : (uchar)
                                            (((const volatile MediusHostHubPortPrefix *)upstream)->depth + 1U);
                                        child_state->depth = depth;
                                        child_state->port_number = (uchar)port_number;
                                        child_state->speed = speed;
                                        MediusHostBusPrefix *child_bus = state->bus;
                                        child_state->connected = 1;
                                        child_state->bus_context = child_bus;
                                        void *mutex = usb_osal_mutex_create();
                                        child_state->control_mutex = mutex;
                                        if (mutex == 0) {
                                            __asm__ volatile ("1: j 1b" ::: "memory");
                                            __builtin_unreachable();
                                        }
                                        if (usbh_enumerate(child) < 0)
                                            usbh_hubport_release(child);
                                    }
                                }
                            }
                        }
                    }
advance_selected:
                    port_count = state->port_count;
                }
                child_address += 164U;
                uint previous_port = port_number & 255U;
                ++port_number;
                if (previous_port >= port_count)
                    break;
            }
        }
event_done:
        if (state->is_root == 0 && state->connected != 0) {
            MediusUsbOsalTimer *timer = state->interrupt_timer;
            usb_osal_timer_start(timer);
        }
    }
}

/* Native entry: 0x4200b080. */
/*
 * Medius v3.4.7 — host application; 0x4200b080.
 *
 * Sends the hub pointer by value to its bus event queue.
 *
 * Calls: medius_usbh_queue_send_value.
 *
 * Called by: USBH_IRQHandler.
 *
 * Original function-byte SHA-256:
 * d0db7175116211ec4fe36755a8fb35528cf0ce23c986fe8997d6b2e291782f95.
 */

/* Sends the hub pointer by value to its bus event queue. Evidence: Loads bus pointer from
   hub+0x2b4, loads queue handle from bus+0x330, and calls0x420209d8(queue,hub). Ignores the
   returned queue status. Reads no hub event bitmap itself and modifies no hub field locally. */

/*
 * hub: Live hub storage whose bus points to a valid host bus and event queue.
 * Returns: Nothing; delegated queue status is ignored.
 * Requirements/effects: Copies the hub pointer bits as one four-byte queue item to
 *   hub->bus->hub_queue. The queue-send adapter chooses task/ISR behavior. No bitmap read, local
 *   hub mutation, lifetime transfer or recovery occurs here; hub storage must remain valid until
 *   queued consumers finish.
 */

void medius_usbh_notify_hub(MediusHostHubState *hub)

{
  medius_usbh_queue_send_value(hub->bus->hub_queue,(uint)hub);
  return;
}

/* Native entry: 0x4200b090. */
/*
 * Medius v3.4.7 — host application; 0x4200b090.
 *
 * Initializes root hub fields, allocates queue/semaphore and starts the core-0 hub task, retaining
 * partial resources on failure.
 *
 * Calls: FUN_4201654c, usb_osal_mq_create, usb_osal_sem_create, usb_osal_thread_create.
 *
 * Called by: usbh_initialize.
 *
 * Original function-byte SHA-256:
 * bff96fde4afaae051d87eb1f3a32104e7704c2d44715aa85de404ea21a7434c3.
 */

/* Initializes root hub fields, allocates queue/semaphore and starts the core-0 hub task, retaining
   partial resources on failure. Zeros32 bytes of local task-name storage. Writes bus+10..13 bytes
   all1 (root connected/is_root/index/address), root port_count byte+15=1, root upstream
   pointer+2C0=NULL, root bus pointer+2C4=bus and root interrupt buffer+310=bus+D. Other bus/root
   fields are not cleared. Creates a7-item four-byte OSAL queue and stores bus.queue+330. NULL
   returns-1 leaving old semaphore/task fields unchanged. Otherwise creates semaphore initial0 and
   stores+334; NULL returns-1 retaining queue and old task handle. Formats usbh_hub<bus.id> with
   limit32, ignores result, then creates task(name,8192 bytes,USB priority0,entry4200AD3C,argbus).
   Stores task handle+32C and returns0 iff non-NULL. Original OSAL maps priority0 toRTOS24 and
   requests core0. Boundaries: No bus/null/reinitialization check or rollback. Queue/semaphore/task
   creation may retain resources on subsequent failure. Stack task-name pointer is borrowed by the
   task-create API and must be consumed before return. Root interrupt bytes atbus+D are not zeroed
   here. Requested task creation does not prove running worker/controller initialization. */

/*
 * bus: Writable bus/root storage; no NULL or repeated-initialization guard.
 * Returns: 0 only when queue, semaphore and task creation return non-NULL; otherwise -1.
 * Requirements/effects: Zeroes eight stack words for a 32-byte task name. Writes root
 *   connected/is_root/index/address as two halfwords, upstream NULL, port_count 1, interrupt
 *   buffer bus+13 and bus backpointer. Creates a seven-item queue and zero-initialized semaphore
 *   in order, publishing each handle before its failure test. Formats usbh_hub<bus.id> with limit
 *   32, ignores formatter status and creates the hub task with stack8192 and USB priority0. The
 *   reviewed OSAL maps this to RTOS priority24/core0. Failure retains earlier resources and
 *   untouched later handles; no rollback occurs. The task API must consume/copy the stack name
 *   before this function returns. Other bus/root fields are preserved; task creation alone does
 *   not prove a running initialized controller.
 */

int usbh_hub_initialize(MediusHostBusPrefix *bus)
{
    uint task_name_words[8];
    for (uint word = 0; word < 8; ++word)
        task_name_words[word] = 0;
    char *task_name = (char *)task_name_words;
    volatile MediusHostHubState *root = (volatile MediusHostHubState *)((uint)bus + 16U);
    *(volatile ushort *)&root->connected = 0x0101;
    *(volatile ushort *)&root->index = 0x0101;
    root->upstream_port = 0;
    root->port_count = 1;
    root->interrupt_buffer = (uchar *)((uint)bus + 13U);
    root->bus = bus;
    void *queue = usb_osal_mq_create(7);
    *(void * volatile *)&bus->hub_queue = queue;
    if (queue == 0)
        return -1;
    void *semaphore = usb_osal_sem_create(0);
    *(void * volatile *)&bus->hub_shutdown_semaphore = semaphore;
    if (semaphore == 0)
        return -1;
    MEDIUS_HOST_SNPRINTF(task_name,32,"usbh_hub%u",(uint)((const volatile MediusHostBusPrefix *)bus)->id);
    void *task = usb_osal_thread_create(task_name,8192,0,(TaskEntry)usbh_hub_thread,bus);
    *(void * volatile *)&bus->hub_task = task;
    return task == 0 ? -1 : 0;
}

/* Native entry: 0x4200b104. */
/*
 * Medius v3.4.7 — host application; 0x4200b104.
 *
 * Requests hub-worker shutdown, waits for its semaphore, deletes it and publishes deinitialization
 * regardless of wrapper errors.
 *
 * Calls: medius_usbh_queue_send_value, usb_osal_sem_delete, usb_osal_sem_take.
 *
 * Called by: usbh_deinitialize.
 *
 * Unresolved indirect call sites: 1.
 *
 * Original function-byte SHA-256:
 * 7c9d0b9610b4a1ac991f0d814b2a72b61fe3d40ee4648038b33d602a9edc880e.
 */

/* Requests hub-worker shutdown, waits for its semaphore, deletes it and publishes deinitialization
   regardless of wrapper errors. Returns-2 if either initial queue or semaphore isNULL. Otherwise
   sends NULL value to the queue, rereads semaphore and takes it with FFFFFFFF, rereads semaphore
   again and deletes that handle. Ignores send/take statuses. After deletion captures callback and
   bus.id, clears queue+330 and semaphore+334, then calls callback(id,0,0,FF,13) and returns0,
   ignoring callback result. Task handle+32C and all other root/controller fields remain untouched.
   Boundaries: No NULL callback check or timeout/recovery path. If sending fails, waiting may hang;
   if take reports failure, cleanup still proceeds without proof the worker stopped. Worker owns
   actual queue deletion and controller shutdown; this caller does neither directly. Fresh semaphore
   reads can target different objects if state changes. Callback is invoked after handle clearing
   and can replace that state again. */

/*
 * bus: Live bus with readable shutdown handles and required event callback.
 * Returns: Initial NULL queue/semaphore returns -2; otherwise 0 after delegated calls and callback
 *   return.
 * Requirements/effects: Caches the initial queue, validates the initial semaphore, enqueues NULL,
 *   then separately rereads semaphore for infinite take and deletion. Ignores all wrapper errors.
 *   After deletion captures the callback then bus ID, clears queue then semaphore and invokes
 *   cached callback(id,0,0,255,13). Task handle and other fields remain untouched. No NULL
 *   callback check or stop acknowledgement beyond the delegated semaphore wait occurs. Failed send
 *   can leave the wait blocked; failed take still permits cleanup. Worker owns actual
 *   controller/queue shutdown. Fresh semaphore reads and callback-side changes are preserved
 *   rather than assuming one stable object.
 */

int medius_usbh_hub_shutdown(MediusHostBusPrefix *bus)
{
    void *queue = *(void * const volatile *)&bus->hub_queue;
    if (queue == 0 || *(void * const volatile *)&bus->hub_shutdown_semaphore == 0)
        return -2;
    medius_usbh_queue_send_value(queue,0);
    usb_osal_sem_take(*(void * const volatile *)&bus->hub_shutdown_semaphore,0xffffffffU);
    usb_osal_sem_delete(*(void * const volatile *)&bus->hub_shutdown_semaphore);
    MediusHostEventHandler callback = *(MediusHostEventHandler const volatile *)&bus->event;
    uchar bus_id = *(const volatile uchar *)&bus->id;
    *(void * volatile *)&bus->hub_queue = 0;
    *(void * volatile *)&bus->hub_shutdown_semaphore = 0;
    callback(bus_id,0,0,255,13);
    return 0;
}

/* Native entry: 0x42020290. */
/* Original function-byte SHA-256:
 * c9ab6dd74b87c4736653a358dc6cbc9623daac5c5cf10905241e35370aba8cc8. */
/* Emulate this build's single root-hub port control requests over DWC2 HPRT.
 * Only request_type low two bits are tested; zero means success without action.
 * Recognized requests (0 status,1 clear,3 set) require only index LOW byte ==1;
 * direction, class, index HIGH, setup length and output capacity are ignored.
 * Unknown requests succeed. Unsupported features return -5; bad port returns -2.
 * Clear 1 disables enable,8 clears power,16/17/19 clear cached change BYTES;
 * 2/18/20 are no-ops. Set 2 is a no-op,8 conditionally powers on,4 resets.
 * Reset writes the filtered saved HPRT with reset set, requests 51 ms sleep,
 * writes that same saved value with reset clear through a freshly loaded bus
 * base, then requests 10 ms sleep. Retry enable at most ten additional 10 ms
 * sleeps; a fresh disconnected read returns -4 and the eleventh failed check
 * returns -14. These are sleep requests and iteration bounds, not timing proof.
 * Status combines three cached change flags with a saved HPRT; enabled speed
 * requires one fresh HPRT speed sample, and a second when the first is not low.
 * Write four little-endian bytes, using one WORD store only for aligned output.
 * No NULL, controller-id, MMIO validity, port ownership or synchronization check
 * is added. W1C filtering and cached-versus-fresh accesses retain native behavior.
 */
int usbh_roothub_control(MediusHostBusPrefix *bus,unsigned char *setup,
                        unsigned char *status_bytes)
{
    const volatile MediusHostBusPrefix *live=bus;
    const volatile unsigned char *request=setup;
    if ((request[0]&3U)==0)
        return 0;
    unsigned int operation=request[1];
    unsigned int port_number=request[4];
    if (operation!=0 && operation!=1 && operation!=3)
        return 0;
    if (port_number!=1)
        return -2;
    if (operation==1 || operation==3) {
        unsigned int feature_high=request[3];
        unsigned int feature_low=request[2];
        unsigned int feature=(feature_high<<8)|feature_low;
        if (operation==1) {
            if (feature==2 || feature==18 || feature==20)
                return 0;
            if (feature==16 || feature==17 || feature==19) {
                unsigned int controller=live->controller_id;
                volatile MediusDwc2HostContextPrefix *context=MEDIUS_HOST_HCD_CONTEXT(controller);
                memw();
                if (feature==16)
                    context->connect_changed=0;
                else if (feature==17)
                    context->enable_changed=0;
                else
                    context->overcurrent_changed=0;
                return 0;
            }
            if (feature==1) {
                volatile MediusDwc2HostRegisters *registers=(volatile void *)live->register_base;
                memw();
                unsigned int port=registers->port;
                memw();
                registers->port=port&~4U;
                return 0;
            }
            if (feature!=8)
                return -5;
            volatile MediusDwc2HostRegisters *registers=(volatile void *)live->register_base;
            volatile unsigned int saved_port;
            memw();
            saved_port=0;
            memw();
            unsigned int port=registers->port;
            memw();
            saved_port=port;
            memw();
            unsigned int filtered_port=saved_port&~0x2eU;
    memw();
    saved_port=filtered_port;
            memw();
            (void)saved_port;
            memw();
            if (saved_port&0x1000U) {
                memw();
                unsigned int power_off=saved_port&~0x1000U;
                memw();
                registers->port=power_off;
            }
            return 0;
        }
        if (feature==2)
            return 0;
        if (feature==8) {
            volatile MediusDwc2HostRegisters *registers=(volatile void *)live->register_base;
            volatile unsigned int saved_port;
            memw();
            saved_port=0;
            memw();
            unsigned int port=registers->port;
            memw();
            saved_port=port;
            memw();
            unsigned int filtered_port=saved_port&~0x2eU;
    memw();
    saved_port=filtered_port;
            memw();
            if (!(saved_port&0x1000U)) {
                memw();
                unsigned int power_on=saved_port|0x1000U;
                memw();
                registers->port=power_on;
            }
            memw();
            (void)saved_port;
            return 0;
        }
        if (feature!=4)
            return -5;
        volatile MediusDwc2HostRegisters *registers=(volatile void *)live->register_base;
        volatile unsigned int saved_port;
        volatile unsigned int retries;
        memw();
        saved_port=0;
        memw();
        retries=0;
        memw();
        unsigned int port=registers->port;
        memw();
        saved_port=port;
        memw();
        unsigned int filtered_port=saved_port&~0xeeU;
    memw();
    saved_port=filtered_port;
        memw();
        unsigned int asserted=saved_port|0x100U;
        memw();
        registers->port=asserted;
        usb_osal_msleep(51);
        memw();
        unsigned int deasserted=saved_port&~0x100U;
        registers=(volatile void *)live->register_base;
        memw();
        registers->port=deasserted;
        usb_osal_msleep(10);
        registers=(volatile void *)live->register_base;
        memw();
        unsigned int current_port=registers->port;
        while (!(current_port&4U)) {
            memw();
            if (!(registers->port&1U))
                return -4;
            memw();
            unsigned int next_retry=retries+1;
            memw();
            retries=next_retry;
            memw();
            if (retries>10)
                return -14;
            usb_osal_msleep(10);
            registers=(volatile void *)live->register_base;
            memw();
            current_port=registers->port;
        }
        return 0;
    }
    /* GET_STATUS uses cached connection/enable/overcurrent change BYTES. */
    unsigned int register_base=live->register_base;
    unsigned int controller=live->controller_id;
    volatile MediusDwc2HostRegisters *registers=(volatile void *)register_base;
    const volatile MediusDwc2HostContextPrefix *context=MEDIUS_HOST_HCD_CONTEXT(controller);
    memw();
    unsigned int port=registers->port;
    volatile unsigned int saved_port;
    memw();
    saved_port=port;
    memw();
    unsigned int connection_changed=context->connect_changed;
    unsigned int status=connection_changed ? 0x10000U : 0;
    memw();
    if (context->enable_changed)
        status|=0x20000U;
    memw();
    if (context->overcurrent_changed)
        status|=0x80000U;
    memw();
    if (saved_port&1U)
        status|=1U;
    memw();
    if (saved_port&4U) {
        volatile unsigned int speed_sample;
        memw();
        speed_sample=0;
        memw();
        unsigned int fresh_port=registers->port;
        memw();
        speed_sample=fresh_port;
        memw();
        unsigned int speed=(speed_sample>>17)&3U;
        status|=2U;
        if (speed==2) {
            status|=0x200U;
        } else {
            volatile unsigned int second_speed_sample;
            memw();
            second_speed_sample=0;
            memw();
            fresh_port=registers->port;
            memw();
            second_speed_sample=fresh_port;
            memw();
            if (((second_speed_sample>>17)&3U)==0)
                status|=0x400U;
        }
    }
    memw();
    if (saved_port&0x10U)
        status|=8U;
    memw();
    if (saved_port&0x100U)
        status|=0x10U;
    memw();
    if (saved_port&0x1000U)
        status|=0x100U;
    if (((unsigned int)status_bytes&3U)==0) {
        *(volatile unsigned int *)status_bytes=status;
    } else {
        volatile unsigned char *output=status_bytes;
        output[0]=(unsigned char)status;
        output[1]=(unsigned char)(status>>8);
        output[2]=(unsigned char)(status>>16);
        output[3]=(unsigned char)(status>>24);
    }
    return 0;
}

