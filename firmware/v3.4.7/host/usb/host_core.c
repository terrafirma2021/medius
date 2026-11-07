/* Medius v3.4.7 host — usb/host_core.c.
 * Recovered C and native assembly, grouped for source navigation.
 * Original entry addresses, firmware-byte hashes and function comments follow.
 */

#include "../include/types.h"

/* Native entry: 0x4037f308. */
/* Original function-byte SHA-256:
 * fde53b1666ed0c1148d0af99c4c9ac9b14391de874d4719ccb2e41fb7cb8cb7d. */
/* Submit a host URB. Cache hubport/endpoint/bus during NULL validation (-2).
 * Misaligned setup/data pointers enter the native infinite alignment assertion
 * before connectivity checks. A disconnected root or cached port returns-4;
 * existing error-6 returns-6. Read MPS HIGH/LOW once, then check RX FIFO for IN,
 * nonperiodic TX for OUT, plus periodic TX for odd OUT endpoint types (-7).
 *
 * Under the first driver lock, cache controller/count and claim the first
 * unused channel whose sampled HCCHAR enable bit is clear. Count is raw5-bit,
 * not capped16. No candidate returns-1. After unlocking, refresh controller and
 * clear the split-phase HALFWORD; under a second lock refresh controller again,
 * set number/URB link and clear split-enabled BYTE. Non-high-speed devices on
 * a sampled high-speed root get phase HALFWORD1 and routing HALFWORD from the
 * parent hub address/child port. Claim, phase-clear and binding can therefore
 * affect different controller snapshots. Set URB channel/error-6/actual0.
 *
 * After unlock, reread endpoint type. Control arms stage0; bulk/interrupt arm
 * noncontrol with cached binding's parity byte0 or scheduling_flags bit0.
 * Type1 deliberately claims a channel without arming any transfer. Fresh
 * timeout0 returns0 asynchronously. Other timeouts wait on the cached binding:
 * negative wait clears timeout, cancels and returns WAIT status; nonnegative
 * wait clears timeout, caches URB error, then releases cached channel links
 * under lock and returns that cached error. No callback in successful cleanup,
 * index/packet validity repair, DMA-capacity check or allocation rollback. */
int usbh_submit_urb(MediusHostUrb *urb)
{
    volatile MediusHostUrb *live = urb;
    if (live == 0)
        return -2;
    const volatile MediusHostHubPortPrefix *port = live->hubport;
    if (port == 0)
        return -2;
    const volatile MediusHostEndpointDescriptor *endpoint = (const volatile void *)live->endpoint;
    if (endpoint == 0)
        return -2;
    MediusHostBusPrefix *bus = port->bus_context;
    if (bus == 0)
        return -2;
    const volatile MediusHostBusPrefix *live_bus = bus;
    if (((unsigned int)(uintptr_t)live->setup & 3U) != 0 ||
        ((unsigned int)(uintptr_t)live->buffer & 3U) != 0) {
        for (;;) __asm__ volatile ("" : : : "memory");
    }
    const volatile MediusDwc2HostRegisters *registers = (const volatile void *)live_bus->register_base;
    memw();
    if ((registers->port & 1U) == 0 || port->connected == 0)
        return -4;
    if (live->error == -6)
        return -6;
    unsigned int high = endpoint->max_packet[1];
    unsigned int low = endpoint->max_packet[0];
    unsigned int address = endpoint->address;
    unsigned int max_packet = ((high << 8) | low) & 2047U;
    unsigned int controller = live_bus->controller_id;
    const volatile MediusDwc2HostContextPrefix *context = (const volatile void *)(0x3fca7c24U+controller*668U);
    if ((address & 128U) != 0) {
        if ((unsigned int)context->rx_fifo_words*4U < max_packet)
            return -7;
    } else {
        unsigned int attributes = endpoint->attributes;
        if ((attributes & 1U) != 0 && (unsigned int)context->periodic_tx_fifo_words*4U < max_packet)
            return -7;
        if ((unsigned int)context->nonperiodic_tx_fifo_words*4U < max_packet)
            return -7;
    }
    unsigned int token = medius_usbh_critical_enter();
    controller = live_bus->controller_id;
    context = (const volatile void *)(0x3fca7c24U+controller*668U);
    unsigned int count = (context->hardware_capabilities >> 6) & 31U;
    unsigned int channel = 0;
    for (; channel < count; ++channel) {
        volatile MediusHostChannel *candidate = (volatile void *)(0x3fca7c80U+controller*668U+channel*36U);
        if (candidate->in_use != 0)
            continue;
        const volatile MediusDwc2HostChannelRegisters *hardware = (const volatile void *)
            (live_bus->register_base+0x500U+(channel & 65535U)*32U);
        memw();
        if ((hardware->characteristics & 0x80000000U) != 0)
            continue;
        candidate->in_use = 1;
        break;
    }
    medius_usbh_critical_exit(token);
    if (channel == count)
        return -1;
    controller = live_bus->controller_id;
    volatile MediusHostChannel *binding = (volatile void *)(0x3fca7c80U+controller*668U+channel*36U);
    binding->split_phase = 0;
    token = medius_usbh_critical_enter();
    controller = live_bus->controller_id;
    binding = (volatile void *)(0x3fca7c80U+controller*668U+channel*36U);
    binding->number = (unsigned char)channel;
    port = live->hubport;
    binding->urb = urb;
    binding->split_enabled = 0;
    if (port->speed != 3) {
        registers = (const volatile void *)live_bus->register_base;
        memw();
        volatile unsigned int sampled_port = 0;
        memw();
        unsigned int root = registers->port;
        memw();
        sampled_port = root;
        memw();
        root = sampled_port;
        if (((root >> 17) & 3U) == 0) {
            binding->split_phase = 1;
            const volatile MediusHostHubPrefix *parent = port->parent;
            unsigned int port_number = port->port_number;
            unsigned int hub_address = parent->device_address;
            binding->split_route = (unsigned short)(hub_address | (port_number << 8));
        }
    }
    live->channel = (MediusHostChannel *)(uintptr_t)
        (0x3fca7c80U+controller*668U+(channel & 65535U)*36U);
    live->error = -6;
    live->actual = 0;
    medius_usbh_critical_exit(token);
    endpoint = (const volatile void *)live->endpoint;
    unsigned int type = endpoint->attributes & 3U;
    if (type == 0) {
        unsigned char *setup = live->setup;
        binding->control_state = 0;
        unsigned int length = live->remaining;
        unsigned char *buffer = live->buffer;
        dwc2_host_start_control(bus,channel,urb,setup,buffer,length);
    } else if (type == 2 || type == 3) {
        unsigned int parity = type == 3 ? live->scheduling_flags & 1U : 0;
        unsigned int length = live->remaining;
        unsigned char *buffer = live->buffer;
        binding->keep_frame_parity = (unsigned char)parity;
        dwc2_host_start_noncontrol(bus,channel,urb,buffer,length);
    }
    unsigned int timeout = live->timeout;
    if (timeout == 0)
        return 0;
    int wait_status = usb_osal_sem_take(binding->semaphore,timeout);
    if (wait_status < 0) {
        live->timeout = 0;
        (void)medius_usbh_cancel_urb(urb,0);
        return wait_status;
    }
    live->timeout = 0;
    int result = live->error;
    token = medius_usbh_critical_enter();
    MediusHostUrb *linked = binding->urb;
    binding->bounce_destination = 0;
    binding->retry_count = 0;
    if (linked != 0) {
        ((volatile MediusHostUrb *)linked)->channel = 0;
        binding->urb = 0;
    }
    binding->in_use = 0;
    medius_usbh_critical_exit(token);
    return result;
}

/* Native entry: 0x4037f5bc. */
/* Original function-byte SHA-256:
 * 1a27889e824a4b81125b602c6cc8219646fd27a5b27264e02b2333facfcdb743. */
/* Query ISR context (discard result), then enter the host-driver lock with
 * timeout-1. Discard acquisition status and return token0 unconditionally.
 * The companion exit ignores this token. */
unsigned int medius_usbh_critical_enter(void)
{
    (void)xPortInIsrContext();
    (void)xPortEnterCriticalTimeout(&MEDIUS_HOST_DRIVER_LOCK,-1);
    return 0;
}

/* Native entry: 0x4037f5d0. */
/* Original function-byte SHA-256:
 * 967a8977f28f76c87ee8d3c10c7690f83ea6f0c30e38818f5b27306436248c7e. */
/* Ignore caller token, query ISR context (discard result), and exit the same
 * host-driver lock. No acquisition/ownership validation occurs in this wrapper. */
void medius_usbh_critical_exit(unsigned int ignored_token)
{
    (void)ignored_token;
    (void)xPortInIsrContext();
    vPortExitCritical(&MEDIUS_HOST_DRIVER_LOCK);
}

/* Native entry: 0x420098d0. */
/*
 * Medius v3.4.7 — host application; 0x420098d0.
 *
 * Queues detached descriptor storage in eight pointer/owner records; evicts and frees the oldest
 * outside the driver lock.
 *
 * Calls: medius_usbh_critical_enter, medius_usbh_critical_exit, memmove, usb_osal_free.
 *
 * Called by: medius_host_parse_configuration, usbh_hubport_release.
 *
 * Original function-byte SHA-256:
 * 7eb64d4e89720d7ea61b79936dc60b60ad4ebe43b1bfb75f444d4a54ce56a52c.
 */



/*
 * owner: Borrowed port identity stored with the allocation, including NULL.
 * allocation: Pointer to retire, including NULL; uniqueness/ownership is not checked.
 * Returns: No value.
 * Requirements/effects: Enters the driver critical section and reads the count byte once. Exact
 *   count 8 selects eviction: only then loads the oldest pointer, moves 56 bytes, appends
 *   allocation/owner at the returned destination+56/+60, restores cached count 8, unlocks and
 *   frees a non-NULL cached oldest pointer. Otherwise appends allocation then owner before
 *   publishing count+1 modulo 256 and unlocking. Counts above 8 are not rejected and can write
 *   outside the eight-record table. No duplicate, reference-count, age or concurrent-reader
 *   validation occurs. Reusing the oldest pointer as incoming allocation can leave a newly
 *   enqueued freed pointer. Unlock-side changes do not alter the cached eviction target.
 */

void medius_usbh_retire_descriptor_storage(MediusHostHubPortPrefix *owner,void *allocation)
{
    uint token = medius_usbh_critical_enter();
    uchar count = *(const volatile uchar *)&medius_retired_descriptor_count;
    if (count == 8) {
        void *oldest = *(void * const volatile *)&medius_retired_descriptors[0].allocation;
        void *shifted = memmove(medius_retired_descriptors,
                                (uchar *)medius_retired_descriptors + 8,56);
        volatile MediusRetiredDescriptor *last =
            (volatile MediusRetiredDescriptor *)((uint)shifted + 56U);
        last->allocation = allocation;
        last->owner = owner;
        *(volatile uchar *)&medius_retired_descriptor_count = count;
        medius_usbh_critical_exit(token);
        if (oldest != 0)
            usb_osal_free(oldest);
    } else {
        volatile MediusRetiredDescriptor *slot =
            (volatile MediusRetiredDescriptor *)((uint)medius_retired_descriptors + (uint)count * 8U);
        slot->allocation = allocation;
        slot->owner = owner;
        *(volatile uchar *)&medius_retired_descriptor_count = (uchar)(count + 1U);
        medius_usbh_critical_exit(token);
    }
}

/* Native entry: 0x4200a004. */
/*
 * Medius v3.4.7 — host application; 0x4200a004.
 *
 * Clears the single host bus, appends it to the list, installs class bounds/event handler and
 * starts hub services while ignoring their result.
 *
 * Calls: memset, usbh_hub_initialize.
 *
 * Called by: FUN_4202e370, app_main, medius_task_cfgswitch.
 *
 * Original function-byte SHA-256:
 * fc9408743c50c3d21cf7c60f90bbb68d06e2fa558fb9321e1430d0f04e742a0d.
 */

/*
 * bus_id: Raw bus byte; only zero is accepted. Nonzero enters a permanent self-loop.
 * register_base: Full controller base word, stored without validation.
 * handler: Optional five-argument host event callback; NULL selects the default sink.
 * Returns: Always 0 after the hub initializer returns, regardless of its status; invalid bus IDs
 *   do not return.
 * Requirements/effects: Zeroes exactly 828 bytes of the singleton, writes ID/controller
 *   ID/register base/last-address 127, then walks local next-link pointers and appends the
 *   singleton at the first NULL link. It does not write singleton.next during traversal. Publishes
 *   class-table begin, clears singleton.next, publishes event handler, then publishes class-table
 *   end before calling hub services. No lock, cycle detection, repeated-init guard or rollback
 *   occurs. Reinitializing an already linked singleton clears its old next pointer before
 *   traversal and can lose the following tail. A separate cycle excluding the zeroed singleton
 *   prevents termination. Caller must establish valid node storage and exclusive lifecycle
 *   ownership; success does not establish hardware/service availability.
 */

int usbh_initialize(uchar bus_id, uint register_base, MediusHostEventHandler handler)
{
    if (bus_id != 0) {
        for (;;) { }
    }
    memset((MediusHostBusPrefix *)MEDIUS_HOST_BUSES, 0, 0x33c);
    volatile MediusHostBusPrefix *published = (MediusHostBusPrefix *)MEDIUS_HOST_BUSES;
    published->id = bus_id;
    published->controller_id = bus_id;
    published->register_base = register_base;
    published->last_address = 0x7f;

    /* Native A8/A2 walk link words; they do not update singleton.next here. */
    void * volatile *tail_link = (void * volatile *)&HOST_BUS_LIST;
    MediusHostBusPrefix *node;
    while ((node = *tail_link) != (MediusHostBusPrefix *)0)
        tail_link = (void * volatile *)&node->next;
    *tail_link = (MediusHostBusPrefix *)MEDIUS_HOST_BUSES;
    if (handler == 0)
        handler = medius_usbh_default_event_handler;

    HOST_CLASS_MATCH_BEGIN = (const MediusHostClassMatchEntry *)0x3c0524ccU;
    published->next = (void *)0;
    published->event = handler;
    HOST_CLASS_MATCH_END = (const MediusHostClassMatchEntry *)0x3c05261cU;
    usbh_hub_initialize((MediusHostBusPrefix *)MEDIUS_HOST_BUSES);
    return 0;
}

/* Native entry: 0x4200a064. */
/*
 * Medius v3.4.7 — host application; 0x4200a064.
 *
 * Requests single-bus hub shutdown, unlinks its first list occurrence and returns success even
 * when shutdown fails.
 *
 * Calls: medius_usbh_hub_shutdown.
 *
 * Called by: FUN_4202e370, medius_task_cfgswitch.
 *
 * Original function-byte SHA-256:
 * 17cb5dbc19f467528410778355a9f9dfccb207a3eddac4aa0766732a8e96c0d6.
 */

/*
 * bus_id: Raw bus byte; only zero is accepted. Nonzero enters a permanent self-loop.
 * Returns: 0 after shutdown/list traversal returns, including missing singleton or shutdown
 *   failure.
 * Requirements/effects: Calls hub shutdown on the singleton and ignores its status. Then freshly
 *   traverses the list by local pointer-to-link values. On the first matching singleton link,
 *   replaces only that link with the singleton next value. Otherwise a NULL link ends without
 *   writes. Does not clear the removed node next field or any other bus field, remove duplicates,
 *   wait for reclamation or repair cycles. A cycle without a matching node/NULL does not
 *   terminate. Shutdown-side list changes are observed when traversal starts; no local lock proves
 *   safe concurrent lifetime.
 */

int usbh_deinitialize(uchar bus_id)
{
    if (bus_id != 0) {
        for (;;) { }
    }
    medius_usbh_hub_shutdown((MediusHostBusPrefix *)MEDIUS_HOST_BUSES);
    void * volatile *link = (void * volatile *)&HOST_BUS_LIST;
    MediusHostBusPrefix *node;
    while ((node = *link) != (MediusHostBusPrefix *)0) {
        if (node == (MediusHostBusPrefix *)MEDIUS_HOST_BUSES) {
            *link = *(void * const volatile *)&node->next;
            return 0;
        }
        link = (void * volatile *)&node->next;
    }
    return 0;
}

/* Native entry: 0x4200a090. */
/*
 * Medius v3.4.7 — host application; 0x4200a090.
 *
 * Submits a synchronous control URB under the port mutex, retrying up to three times except
 * timeout.
 *
 * Calls: usb_osal_mutex_give, usb_osal_mutex_take, usbh_submit_urb.
 *
 * Called by: medius_host_capture_descriptors_and_probe_controls,
 * medius_host_capture_string_descriptor, medius_host_fetch_configuration_descriptor,
 * medius_usbh_hub_attach, medius_usbh_hub_clear_port_feature, medius_usbh_hub_get_port_status,
 * medius_usbh_hub_set_port_feature, usbh_enumerate, usbh_hid_get_report_descriptor,
 * usbh_hid_set_idle.
 *
 * Original function-byte SHA-256:
 * 987ccdab5e2742b9e0b4887d3f24bf2fd2b10d9f32d96b4934f47f8c4d9c9c15.
 */



/*
 * port: Live connected port with control mutex, EP0 descriptor and embedded URB.
 * setup: Readable eight-byte SETUP buffer, retained for the delegated transfer lifetime; NULL is
 *   rejected.
 * data: Data-phase storage valid for the requested direction and low16 wLength; forwarded without
 *   a capacity/alignment check.
 * Returns: Effective signed32 submission/actual result. NULL port/setup returns -2; disconnected
 *   port returns -3.
 * Requirements/effects: MEMW then validates pointers/connected byte. Requests the current port
 *   mutex once and ignores take status. For at most three attempts rereads SETUP bytes 7 then 6,
 *   fills remaining/timeout500/hubport/EP0/setup/data and clears completion/context, leaving other
 *   URB fields to the controller. Nonzero submit result is used directly; zero substitutes actual
 *   interpreted as signed32. Any nonnegative result or exact -14 stops; other negatives retry with
 *   native MEMWs and no delay/reconnect check. Finally rereads the mutex handle, gives it and
 *   returns the cached result, ignoring give status. SETUP can change between retries; failure
 *   does not roll back output or delegated state.
 */

int usbh_control_transfer(MediusHostHubPortPrefix *port,uchar *setup,uchar *data)
{
    memw();
    volatile uchar attempts_left = 3;
    if (port == NULL || setup == NULL)
        return -2;
    volatile MediusHostHubPortPrefix *live = port;
    if (live->connected == 0)
        return -3;
    volatile MediusHostUrb *urb = &port->control_urb;
    uchar *endpoint = port->ep0_descriptor;
    (void)usb_osal_mutex_take(live->control_mutex);
    int result;
    for (;;) {
        /* SETUP can be unaligned: native reads HIGH then LOW bytes. */
        uint length_high = ((const volatile uchar *)setup)[7];
        uint length_low = ((const volatile uchar *)setup)[6];
        urb->remaining = (length_high << 8) | length_low;
        urb->timeout = 500;
        urb->hubport = port;
        urb->endpoint = endpoint;
        urb->setup = setup;
        urb->buffer = data;
        urb->complete = NULL;
        urb->context = NULL;
        result = usbh_submit_urb(&port->control_urb);
        if (result == 0)
            result = (int)urb->actual;
        if (result >= 0 || result == -14)
            break;
        memw();
        uchar remaining = attempts_left;
        remaining = (uchar)(remaining - 1U);
        memw();
        attempts_left = remaining;
        memw();
        if (attempts_left == 0)
            break;
    }
    (void)usb_osal_mutex_give(live->control_mutex);
    return result;
}

/* Native entry: 0x4200a144. */
/*
 * Medius v3.4.7 — host application; 0x4200a144.
 *
 * Runs hub lookup under the driver critical section, truncating all indices to bytes without
 * checking the single-bus bound.
 *
 * Calls: medius_usbh_critical_enter, medius_usbh_critical_exit, medius_usbh_find_port_in_hub.
 *
 * Called by: medius_usb_host_event.
 *
 * Original function-byte SHA-256:
 * dcc578678e82cdfbb944b7f06bafe0d5a08b42e231355e2a78c3d378e1d58dfd.
 */

/* Runs hub lookup under the driver critical section, truncating all indices to bytes without
   checking the single-bus bound. Enters medius_usbh_critical_enter and saves returned token.
   Computes root hub=3FCA7F1C+828*(bus_id&FF). Calls4200982C(root,hub_index&FF,port_number&FF).
   Saves result, exits driver critical with original token and returns saved pointer regardless of
   unlock return. The lock covers strcmp and all recursive traversal. No range or initialized-state
   checks. Boundaries: Only one bus singleton is established by initialization, but this wrapper
   accepts all byte bus indices and can address unrelated/out-of-range state. NormalNULL result
   still unlocks. Recursive null-load/BREAK prefix never reaches local unlock before that abnormal
   operation; hardware exception recovery is not modeled. Returned pointer escapes the lock without
   a lifetime/reference guarantee, and future release/reuse remains possible. */

/*
 * bus_id: Raw byte bus index; only bus0 is initialized by this firmware.
 * hub_index: Requested byte hub index passed to recursive lookup.
 * port_number: Raw byte port number; no local range check.
 * Returns: The borrowed hub-port pointer from lookup, including NULL, after normal helper return.
 * Requirements/effects: Acquires driver critical state and preserves its token. Computes root
 *   address as unsigned32(singleton + 828*bus_id + 16), then calls recursive lookup and exits with
 *   the saved token. No bus-range/initialization or reference-lifetime check occurs. Returned
 *   storage escapes the lock. A delegated invalid recursive path can fault before this wrapper
 *   reaches unlock.
 */

MediusHostHubPortPrefix * usbh_find_hubport(uchar bus_id,uchar hub_index,uchar port_number)

{
  uint token;
  MediusHostHubPortPrefix *port;

  token = medius_usbh_critical_enter();
  port = medius_usbh_find_port_in_hub
                     ((MediusHostHubState *)((uint)(MediusHostBusPrefix *)MEDIUS_HOST_BUSES + (uint)bus_id * 0x33cU + 0x10U),
                      (uint)hub_index,(uint)port_number);
  medius_usbh_critical_exit(token);
  return port;
}

/* Native entry: 0x4200a178. */
/*
 * Medius v3.4.7 — host application; 0x4200a178.
 *
 * Enumerates a host device, reserves its address, fetches/parses descriptors, selects class
 * drivers and frees the temporary raw configuration.
 *
 * Calls: medius_host_enumeration_timer_restart, medius_host_parse_configuration,
 * medius_host_report_enumeration_limit, medius_host_select_enumeration_configuration,
 * usb_osal_free, usb_osal_malloc, usb_osal_msleep, usbh_control_transfer.
 *
 * Called by: usbh_hub_thread.
 *
 * Indirect calls: three five-argument host events and one two-argument class connect.
 *
 * Original function-byte SHA-256:
 * 81a42dfc7b6207bdf45c9b28079569308d8585febc5ff3d4aaf342cf4d04db3e.
 */



/*
 * port: Live164-byte connected port with parent/bus/table/descriptor state; setup/scratch slot
 *   arithmetic trusts IDs and port number, without local capacity checks.
 * Returns: First propagated signed request/parser status, -2 for first invalid device header, -1
 *   for oversized configuration/allocation failure, or0 after finish and on address-sentinel
 *   exhaustion. Class-connect failures do not fail enumeration.
 * Requirements/effects: Caches computed eight-byte setup slot and publishes native EP0
 *   bytes/speed-based MPS/address0. Three outer device8 attempts use freshly read16-bit0/40/150
 *   delays, native setup word stores and fresh bus scratch; nonnegative accepts short results,
 *   exact-3/-4 stop. First header18/1 required; USB>=0x300 exponent is masked31 and narrowed16.
 *   Cached allocator last-address sentinel is compared before each bitmap test; free bit/last
 *   update precedes SET_ADDRESS and never roll back. Success delays10 then publishes address. Full
 *   device18 invalid header retains old descriptor but continues. Config9/full fetches each
 *   require parser result0; total length<=2048. NULL malloc overwrites/leaks old temporary and
 *   returns directly. Otherwise caches configuration value, copies cached length with native
 *   aligned-word or unaligned-byte access order, reloads raw pointer for NUL, then
 *   SET_CONFIGURATION/event5. Interface scan uses full32 index with low16 continuation and low8
 *   callback/event index; zero alternate count skips without fresh count. Caches first-alternate
 *   class fields and device identity word/byte;16-byte catalog flags4/8/16/32 gate
 *   class/subclass/protocol/number, lowbits gate exact VID/PID pairs unless pointerNULL, VID0
 *   terminates. First matching NULLdriver blocks later entries. Loads connect before publishing
 *   driver then calls unchecked; nonnegative emits10, no match emits9, negative leaves binding
 *   without event/failure. Fresh count follows participation. Finish result ignored and success
 *   forced0. Common cleanup loads current temporary once, frees if nonNULL and clears field even
 *   if free replaced it; address sentinel also cleans up, NULL malloc does not. Native callback
 *   snapshots, field widths/order and literal alignment retained. No lock, allocation rollback,
 *   real-length/capacity/lifetime check, physical USB/timer guarantee or concurrent-ownership
 *   proof.
 */

int usbh_enumerate(MediusHostHubPortPrefix *port)
{
    volatile MediusHostHubPortPrefix *live = port;
    MediusHostHubPrefix *initial_parent = live->parent;
    MediusHostBusPrefix *initial_bus = live->bus_context;
    uchar parent_index = *(const volatile uchar *)((uint)initial_parent + 2U);
    uchar initial_bus_id = ((const volatile MediusHostBusPrefix *)initial_bus)->id;
    uchar initial_port = live->port_number;
    uint setup_address = (uint)HOST_ENUMERATION_SETUP_POOL +
        ((((uint)initial_bus_id * 2U + parent_index - 1U) * 4U + initial_port - 1U) * 8U);
    volatile uchar *setup = (volatile uchar *)setup_address;
    uchar speed = live->speed;
    live->ep0_descriptor[2] = 0;
    live->ep0_descriptor[3] = 0;
    live->setup = (uchar *)setup;
    live->ep0_descriptor[1] = 5;
    uint initial_mps = speed == 1 ? 8 : (uchar)(speed - 5U) < 2 ? 512 : 64;
    live->ep0_descriptor[4] = (uchar)initial_mps;
    live->ep0_descriptor[5] = (uchar)(initial_mps >> 8);
    live->ep0_descriptor[6] = 0;
    live->ep0_descriptor[0] = 7;
    live->device_address = 0;
    int result = 0;
    for (uint attempt = 0; attempt < 3; ++attempt) {
        ushort delay_ms = HOST_ENUMERATION_RETRY_DELAYS[attempt];
        if (delay_ms != 0)
            usb_osal_msleep(delay_ms);
        *(volatile uint *)setup = 0x01000680U;
        MediusHostBusPrefix *transfer_bus = live->bus_context;
        *(volatile uint *)(setup_address + 4U) = 0x00080000U;
        uchar id = ((const volatile MediusHostBusPrefix *)transfer_bus)->id;
        uchar *data = (uchar *)((uint)HOST_ENUMERATION_SCRATCH + (uint)id * 2048U);
        result = usbh_control_transfer(port,(uchar *)setup,data);
        if (result >= 0)
            break;
        if (result == -3 || result == -4 || attempt == 2)
            goto cleanup;
    }
    MediusHostBusPrefix *allocator = live->bus_context;
    uchar read_bus_id = ((const volatile MediusHostBusPrefix *)allocator)->id;
    uint scratch = (uint)HOST_ENUMERATION_SCRATCH + (uint)read_bus_id * 2048U;
    if (*(const volatile uchar *)scratch != 18 ||
        *(const volatile uchar *)(scratch + 1U) != 1) {
        result = -2;
        goto cleanup;
    }
    ushort usb_version = *(const volatile ushort *)(scratch + 2U);
    uchar packet_byte = *(const volatile uchar *)(scratch + 7U);
    uint reported_mps = usb_version <= 0x2ff ? packet_byte :
        (1U << (packet_byte & 31U)) & 0xffffU;
    live->ep0_descriptor[5] = (uchar)(reported_mps >> 8);
    live->ep0_descriptor[4] = (uchar)reported_mps;
    volatile MediusHostBusPrefix *allocation_state = allocator;
    uchar last_address = allocation_state->last_address;
    uint candidate = last_address;
    uint bitmap_word;
    uint bitmap_address;
    for (;;) {
        candidate = (candidate + 1U) & 255U;
        if (candidate & 128U)
            candidate = 2;
        if (candidate == last_address) {
            result = 0;
            goto cleanup;
        }
        bitmap_address = (uint)allocator + 0x31cU + (candidate >> 5) * 4U;
        bitmap_word = *(const volatile uint *)bitmap_address;
        if ((bitmap_word & (1U << (candidate & 31U))) == 0)
            break;
    }
    *(volatile uint *)bitmap_address = bitmap_word | (1U << (candidate & 31U));
    allocation_state->last_address = (uchar)candidate;
    *(volatile ushort *)setup = 0x0500;
    *(volatile ushort *)(setup_address + 2U) = (ushort)candidate;
    *(volatile uint *)(setup_address + 4U) = 0;
    result = usbh_control_transfer(port,(uchar *)setup,0);
    if (result < 0)
        goto cleanup;
    usb_osal_msleep(10);
    live->device_address = (uchar)candidate;
    *(volatile uint *)setup = 0x01000680U;
    MediusHostBusPrefix *transfer_bus = live->bus_context;
    *(volatile uint *)(setup_address + 4U) = 0x00120000U;
    uchar transfer_id = ((const volatile MediusHostBusPrefix *)transfer_bus)->id;
    result = usbh_control_transfer(port,(uchar *)setup,
        (uchar *)((uint)HOST_ENUMERATION_SCRATCH + (uint)transfer_id * 2048U));
    if (result < 0)
        goto cleanup;
    MediusHostBusPrefix *descriptor_bus = live->bus_context;
    uchar descriptor_bus_id = ((const volatile MediusHostBusPrefix *)descriptor_bus)->id;
    scratch = (uint)HOST_ENUMERATION_SCRATCH + (uint)descriptor_bus_id * 2048U;
    uchar descriptor_length = *(const volatile uchar *)scratch;
    if (descriptor_length == 18) {
        uchar descriptor_type = *(const volatile uchar *)(scratch + 1U);
        if (descriptor_type == 1) {
            live->device_descriptor[1] = descriptor_type;
            live->device_descriptor[0] = descriptor_length;
            ushort version = *(const volatile ushort *)(scratch + 2U);
            live->device_descriptor[3] = (uchar)(version >> 8);
            live->device_descriptor[2] = (uchar)version;
            for (uint index = 4; index < 8; ++index) {
                uchar value = *(const volatile uchar *)(scratch + index);
                live->device_descriptor[index] = value;
            }
            ushort device_version = *(const volatile ushort *)(scratch + 12U);
            ushort vendor = *(const volatile ushort *)(scratch + 8U);
            ushort product = *(const volatile ushort *)(scratch + 10U);
            live->device_descriptor[8] = (uchar)vendor;
            live->device_descriptor[9] = (uchar)(vendor >> 8);
            live->device_descriptor[10] = (uchar)product;
            live->device_descriptor[11] = (uchar)(product >> 8);
            live->device_descriptor[12] = (uchar)device_version;
            live->device_descriptor[13] = (uchar)(device_version >> 8);
            for (uint index = 14; index < 18; ++index) {
                uchar value = *(const volatile uchar *)(scratch + index);
                live->device_descriptor[index] = value;
            }
        }
    }
    uchar selector = medius_host_select_enumeration_configuration(port);
    ushort descriptor_value = (ushort)((uint)selector | 0x0200U);
    *(volatile ushort *)setup = 0x0680;
    transfer_bus = live->bus_context;
    *(volatile uint *)(setup_address + 4U) = 0x00090000U;
    *(volatile ushort *)(setup_address + 2U) = descriptor_value;
    transfer_id = ((const volatile MediusHostBusPrefix *)transfer_bus)->id;
    result = usbh_control_transfer(port,(uchar *)setup,
        (uchar *)((uint)HOST_ENUMERATION_SCRATCH + (uint)transfer_id * 2048U));
    if (result < 0)
        goto cleanup;
    MediusHostBusPrefix *parse_bus = live->bus_context;
    uchar parse_id = ((const volatile MediusHostBusPrefix *)parse_bus)->id;
    result = medius_host_parse_configuration(port,
        (uchar *)((uint)HOST_ENUMERATION_SCRATCH + (uint)parse_id * 2048U),9);
    if (result != 0)
        goto cleanup;
    MediusHostBusPrefix *length_bus = live->bus_context;
    uchar length_bus_id = ((const volatile MediusHostBusPrefix *)length_bus)->id;
    scratch = (uint)HOST_ENUMERATION_SCRATCH + (uint)length_bus_id * 2048U;
    uint length = *(const volatile ushort *)(scratch + 2U);
    if (length > 2048) {
        medius_host_report_enumeration_limit(port,1,(ushort)length);
        result = -1;
        goto cleanup;
    }
    *(volatile ushort *)(setup_address + 4U) = 0;
    *(volatile ushort *)setup = 0x0680;
    *(volatile ushort *)(setup_address + 2U) = descriptor_value;
    *(volatile ushort *)(setup_address + 6U) = (ushort)length;
    result = usbh_control_transfer(port,(uchar *)setup,(uchar *)scratch);
    if (result < 0)
        goto cleanup;
    parse_bus = live->bus_context;
    parse_id = ((const volatile MediusHostBusPrefix *)parse_bus)->id;
    result = medius_host_parse_configuration(port,
        (uchar *)((uint)HOST_ENUMERATION_SCRATCH + (uint)parse_id * 2048U),length);
    if (result != 0)
        goto cleanup;
    uchar *allocation = usb_osal_malloc(length + 1U);
    live->raw_configuration = allocation;
    if (allocation == 0)
        return -1;
    MediusHostBusPrefix *copy_bus = live->bus_context;
    uchar copy_id = ((const volatile MediusHostBusPrefix *)copy_bus)->id;
    uint source = (uint)HOST_ENUMERATION_SCRATCH + (uint)copy_id * 2048U;
    uint destination = (uint)allocation;
    uchar configuration_value = *(const volatile uchar *)(source + 5U);
    uint remaining = length;
    if (((destination ^ source) & 3U) == 0) {
        while ((destination & 3U) != 0 && remaining != 0) {
            uchar value = *(const volatile uchar *)source;
            *(volatile uchar *)destination = value;
            ++source;
            ++destination;
            --remaining;
        }
        while (remaining >= 16) {
            for (uint word = 0; word < 4; ++word) {
                uint value = *(const volatile uint *)(source + word * 4U);
                *(volatile uint *)(destination + word * 4U) = value;
            }
            source += 16;
            destination += 16;
            remaining -= 16;
        }
        while (remaining >= 4) {
            uint value = *(const volatile uint *)source;
            *(volatile uint *)destination = value;
            source += 4;
            destination += 4;
            remaining -= 4;
        }
    } else {
        while (remaining >= 16) {
            for (uint word = 0; word < 3; ++word) {
                uint value = *(const volatile uint *)(source + word * 4U);
                volatile uchar *bytes = (volatile uchar *)(destination + word * 4U);
                bytes[1] = (uchar)(value >> 8);
                bytes[2] = (uchar)(value >> 16);
                bytes[3] = (uchar)(value >> 24);
                bytes[0] = (uchar)value;
            }
            uint value = *(const volatile uint *)(source + 12U);
            ((volatile uchar *)destination)[12] = (uchar)value;
            ((volatile uchar *)destination)[13] = (uchar)(value >> 8);
            ((volatile uchar *)destination)[14] = (uchar)(value >> 16);
            ((volatile uchar *)destination)[15] = (uchar)(value >> 24);
            source += 16;
            destination += 16;
            remaining -= 16;
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
    uchar *terminated = live->raw_configuration;
    *(volatile uchar *)((uint)terminated + length) = 0;
    *(volatile ushort *)setup = 0x0900;
    *(volatile ushort *)(setup_address + 2U) = configuration_value;
    *(volatile uint *)(setup_address + 4U) = 0;
    result = usbh_control_transfer(port,(uchar *)setup,0);
    if (result < 0)
        goto cleanup;
    {
        MediusHostBusPrefix *event_bus = live->bus_context;
        MediusHostHubPrefix *parent = live->parent;
        MediusHostEventHandler event = ((const volatile MediusHostBusPrefix *)event_bus)->event;
        uchar hub_index = *(const volatile uchar *)((uint)parent + 2U);
        uchar port_number = live->port_number;
        uchar bus_id = ((const volatile MediusHostBusPrefix *)event_bus)->id;
        event(bus_id,hub_index,port_number,255,5);

    }
    uint interface_count = live->interface_count;
    if (interface_count != 0) {
        uint interface_index = 0;
        do {
            MediusHostInterfacePrefix *table = live->interfaces;
            volatile MediusHostInterfacePrefix *interface = (volatile MediusHostInterfacePrefix *)
                ((uint)table + interface_index * 32U);
            if (interface->alternate_count != 0) {
                const volatile MediusHostAlternateClassView *alternate =
                    (const volatile MediusHostAlternateClassView *)interface->alternates;
                uint identity_word = *(const volatile uint *)((uint)port + 16U);
                uchar subclass = alternate->interface_subclass;
                uchar vendor_low = live->device_descriptor[8];
                uchar interface_class = alternate->interface_class;
                uchar protocol = alternate->interface_protocol;
                uchar number = alternate->interface_number;
                const volatile MediusHostClassMatchEntry *entry =
                    HOST_CLASS_MATCH_BEGIN;
                const MediusHostClassMatchEntry *end =
                    HOST_CLASS_MATCH_END;
                uint vendor = ((identity_word & 255U) << 8) | vendor_low;
                uint product = (identity_word >> 8) & 0xffffU;
                const MediusHostConnectDriverView *driver = 0;
                for (; (uint)entry < (uint)end; entry =
                    (const volatile MediusHostClassMatchEntry *)((uint)entry + 16U)) {
                    uchar flags = entry->flags;
                    if ((flags & 4U) && entry->interface_class != interface_class)
                        continue;
                    if ((flags & 8U) && entry->interface_subclass != subclass)
                        continue;
                    if ((flags & 16U) && entry->interface_protocol != protocol)
                        continue;
                    if ((flags & 32U) && entry->interface_number != number)
                        continue;
                    if (flags & 3U) {
                        const volatile MediusHostDeviceIdPair *pair = entry->ids;
                        if (pair != 0) {
                            ushort pair_vendor = pair->vendor;
                            int matched = 0;
                            while (pair_vendor != 0) {
                                if (pair_vendor == vendor && pair->product == product) {
                                    matched = 1;
                                    break;
                                }
                                pair = (const volatile MediusHostDeviceIdPair *)((uint)pair + 4U);
                                pair_vendor = pair->vendor;
                            }
                            if (!matched)
                                continue;
                        }
                    }
                    driver = entry->driver;
                    break; /* Matching NULL driver blocks later entries. */
                }
                if (driver != 0) {
                    MediusHostClassConnect connect =
                        ((const volatile MediusHostConnectDriverView *)driver)->connect;
                    interface->class_driver = (void *)driver;
                    int connected = connect(port,(uchar)interface_index); /* No NULL guard. */
                    if (connected >= 0) {
                        MediusHostBusPrefix *event_bus = live->bus_context;
                        MediusHostHubPrefix *parent = live->parent;
                        MediusHostEventHandler event = ((const volatile MediusHostBusPrefix *)event_bus)->event;
                        uchar hub_index = *(const volatile uchar *)((uint)parent + 2U);
                        uchar port_number = live->port_number;
                        uchar bus_id = ((const volatile MediusHostBusPrefix *)event_bus)->id;
                        event(bus_id,hub_index,port_number,(uchar)interface_index,10);

                    }
                } else {
                    MediusHostBusPrefix *event_bus = live->bus_context;
                    MediusHostHubPrefix *parent = live->parent;
                    MediusHostEventHandler event = ((const volatile MediusHostBusPrefix *)event_bus)->event;
                    uchar hub_index = *(const volatile uchar *)((uint)parent + 2U);
                    uchar port_number = live->port_number;
                    uchar bus_id = ((const volatile MediusHostBusPrefix *)event_bus)->id;
                    event(bus_id,hub_index,port_number,(uchar)interface_index,9);

                }
                interface_count = live->interface_count;
            }
            ++interface_index;
        } while ((interface_index & 0xffffU) < interface_count);
    }
    medius_host_enumeration_timer_restart(port);
    result = 0;
cleanup:
    {
        uchar *temporary = live->raw_configuration;
        if (temporary != 0) {
            usb_osal_free(temporary);
            live->raw_configuration = 0;
        }
    }
    return result;
}

/* Native entry: 0x4201e870. */
/*
 * Medius v3.4.7 — host application; 0x4201e870.
 *
 * Default host event sink returns immediately.
 *
 * Original function-byte SHA-256:
 * a50f595a12cc6e7e90d28fa2424790fbfac53a684610d6fe5637b2112f16f23d.
 */

/* Default host event sink returns immediately. Original body is ENTRY a1,0x20 followed by RETW.N;
   no local data access or delegated calls. Boundaries: Normal Xtensa windowed ABI entry/return
   requires valid caller stack/window context. Tests initialize the incoming window directly; no
   architectural ENTRY/RETW simulation claim. */

/*
 * bus: Ignored raw bus argument.
 * hub: Ignored raw hub argument.
 * port: Ignored raw port argument.
 * interface_index: Ignored interface argument.
 * event: Ignored event argument.
 * Returns: Nothing.
 * Requirements/effects: Default event sink returns immediately. It performs no callback, state
 *   change, allocation or validation. Requires the normal Xtensa windowed call/return context.
 */

void medius_usbh_default_event_handler(uint bus,uint hub,uint port,uint interface_index,uint event)

{
  (void)bus;
  (void)hub;
  (void)port;
  (void)interface_index;
  (void)event;
  return;
}

/* Native entry: 0x4202063c. */
/* Original function-byte SHA-256:
 * ace2a9f666774242b1e7f5604673f8f650d52e854e192a300a15d11936108ef3. */
/* Cancel without partial-byte output. Return the delegated signed status;
 * no extra validation, output write or ownership guarantee. */
int usbh_kill_urb(MediusHostUrb *urb)
{
    return medius_usbh_cancel_urb(urb,0);
}

/* Native entry: 0x420282e4. */
/*
 * Medius v3.4.7 — host application; 0x420282e4.
 *
 * Disables HID activity, performs bounded shared-activity waits, removes tracked/vendor/OUT state
 * and optionally sends a detach message.
 *
 * Calls: vTaskDelay, medius_host_set_frame_clock_blocked, esp_timer_get_time, medius_dwc2_host_resume_control,
 * medius_host_log_formatted, medius_host_set_sof_interrupt, link_send_wait100,
 * medius_out_reset_toggles_resume, medius_out_unregister, medius_vendor_reset_selection_state,
 * medius_vendor_stop_mode_interfaces, memset.
 *
 * Called by: medius_hid_on_class_removed, medius_usb_host_event.
 *
 * Original function-byte SHA-256:
 * 9f7b5e8e7ca2d9efaea9b4fd7b612083a23a6dd48d9e01569a31686c4a42c399.
 */


/* WARNING: Removing unreachable block (ram,0x42028377) */
/* WARNING: Removing unreachable block (ram,0x420283bc) */
/* WARNING: Removing unreachable block (ram,0x42028490) */
/* Disables HID activity, performs bounded shared-activity waits, removes tracked/vendor/OUT state
   and optionally sends a detach message. MEMW precedes each of six explicit stores clearing polling
   record.active+0F, independent of endpoint_count. Calls medius_host_set_sof_interrupt(0), ignores
   result. Takes a64-bit timer snapshot and waits while3FCA9735 is nonzero, with
   deadline=start+600000. While busy, samples time; signed64 now<deadline delays1 scheduler tick
   then rereads the flag, else continues teardown. Takes a fresh start for a50000-unit wait
   while3FCA9736!=0 OR credit_busy3FCA9734!=0, short-circuiting the credit read when the first flag
   is nonzero. Takes a third fresh start for a50000-unit wait that scans all six in_callback
   bytes+12hex in index order; the first nonzero triggers a timer comparison/delay and a new scan.
   All-zero scan exits immediately. These three snapshots occur even when their corresponding
   activity is already zero. Clears endpoint_count word then memsets exactly256 HID
   alternate-selection bytes. MEMW then snapshots tracked port3FCA97EC and clears enable3FCAD635.
   NonNULL cached port is passed to medius_out_unregister(port,0), ignoring result. Both
   NULL/nonNULL paths then clear control port and tracked port to0 with MEMW before each store, and
   call medius_vendor_stop_mode_interfaces(). Takes a fourth fresh timer start and waits on
   control_busy3FCA97E8 with deadline=start+600000, delay1 while signed64 now<deadline. After clear
   OR timeout, a nonNULL cached port is passed to medius_out_unregister(port,0) again. NULL cached
   port causes no unregister, even if a later callback repopulates a global port pointer. Clears
   reset3FCADAC8,HID paused3FCA9775,recovery-deferred3FCA9773,resume-armed3FCA9759 and
   resume-pending3FCA9758, each preceded by MEMW. Power.state3FCA975C is sampled before the
   resume-pending clear; if that cached byte is nonzero, calls medius_dwc2_host_resume_control(0,0)
   and42026320(0), ignoring results. Then clears power.state,+3 applied remote wakeup,+4 preexisting
   pause and the32-bit HID suspend-restore mask3FCA974C. Power+1 desired remote wakeup and+2 are
   retained. Calls medius_vendor_reset_selection_state(), then medius_out_reset_toggles_resume().
   Reads configuration-switch gate3FCAFF1C; only if0 reads pre-capture gate3FCAFF0A. Both0
   clears3FCAFEFD and identity-refresh3FCA976E to the cached zero pre-capture byte, each after MEMW,
   sends link_send_wait100(type12hex,sequence0,NULL,0), ignores send result and logs
   detached. Either nonzero suppresses the send and preserves those two refresh bytes; this branch
   rereads configuration-switch gate to choose configuration-switch versus pre-capture log reason.
   All ordinary paths return after one final log. Boundaries: All four deadlines use modulo2^64
   addition followed by a signed64 comparison implemented by signed high-word and unsigned low-word
   branches. Equal timestamps end the wait. This is original machine arithmetic, not a guarantee of
   defined signed-C overflow. The four raw unreachable-block warnings describe low-word branches
   actually executed; current C folds them into64-bit expressions. Timeout continues cleanup without
   clearing the observed busy/in_callback flags or returning a quiescence status. Locally only the
   six active bytes are cleared in HID records; handles,endpoint descriptors,URBs,cache/report
   lengths and other record state are retained. Original code performs no direct HID URB
   cancellation here. The tracked port is cached across both unregister calls and vendor shutdown;
   global pointers repopulated after their clear remain populated. No final
   connected/pointer/lifetime check or global lock exists. Power and detach gating mix cached and
   fresh reads as stated; sequential mutation tests verify those instructions but do not establish
   safe concurrent publication. Suppression reason can change after admission to the suppressed
   branch. SETUP/USB scheduling, timer advancement, control-worker termination, cancellation
   completion and physical UART detach delivery are not proved by the local body. A busy flag with a
   nonadvancing timer can keep a wait running indefinitely despite its deadline arithmetic. */

/*
 * Returns: No value or quiescence status; a busy flag with a nonadvancing timer can wait
 *   indefinitely.
 * Requirements/effects: MEMW-clears all six HID active bytes regardless of endpoint count and
 *   disables SOF. Takes four unconditional timer starts:600000us for first activity,50000us for
 *   second activity/credit (credit read short-circuited),50000us for six callback bytes
 *   and600000us for control-worker activity after vendor stop. Polls busy state freshly and delays
 *   one scheduler tick only while signed64 now is before deadline; unsigned addition preserves
 *   modulo2^64 native deadlines, sign-bit bias preserves native signed ordering. Equality/timeouts
 *   continue cleanup without clearing busy/callback bytes. Clears endpoint count and256
 *   alternates; MEMW-snapshots tracked port before clearing enable, optionally unregisters the
 *   cached port, clears control/tracked pointers, then stops vendor interfaces. After fourth wait
 *   optionally unregisters that same cached port again, retaining any newly published global
 *   pointers. Clears reset/paused/recovery/armed; snapshots power state BEFORE pending clear and
 *   conditionally resumes hardware/control. Clears power state/applied wake/preexisting pause and
 *   restore mask, retaining power bytes1/2; resets vendor selection and OUT toggles. Detach only
 *   when cached configuration-switch and cached pre-capture bytes are zero: publishes the cached
 *   zero to two refresh bytes, sends type0x12 empty message and logs detached. Suppression rereads
 *   configuration-switch to choose the logged reason. Ignores all delegated results; no global
 *   lock, final lifetime check, HID URB cancellation, rollback or proof of DMA/callback
 *   completion. Software delays depend on scheduler priority/load and timer progress; no exact
 *   elapsed-time or delivery guarantee.
 */

void medius_host_teardown_interfaces(void)
{
    for (uint slot = 0; slot < 6; ++slot) {
        memw();
        MEDIUS_HOST_HID_ENDPOINTS[slot].active = 0;
    }
    medius_host_set_sof_interrupt(0);
    const ulonglong sign_bit = 0x8000000000000000ULL;
    /* Unsigned addition retains native wrap; sign-bit bias implements the
     * signed high-word/unsigned low-word comparison without signed overflow. */
    ulonglong deadline = (ulonglong)esp_timer_get_time() + 600000ULL;
    for (;;) {
        memw();
        if (MEDIUS_HID_SHARED_BUSY_FLAGS[0] == 0)
            break;
        ulonglong now = (ulonglong)esp_timer_get_time();
        if ((now ^ sign_bit) >= (deadline ^ sign_bit))
            break;
        vTaskDelay(1);
    }
    deadline = (ulonglong)esp_timer_get_time() + 50000ULL;
    for (;;) {
        memw();
        uchar activity = MEDIUS_HID_POLL_POLICY_UPDATING;
        if (activity == 0) {
            memw();
            if (MEDIUS_HID_CREDIT_BUSY == 0)
                break;
        }
        ulonglong now = (ulonglong)esp_timer_get_time();
        if ((now ^ sign_bit) >= (deadline ^ sign_bit))
            break;
        vTaskDelay(1);
    }
    deadline = (ulonglong)esp_timer_get_time() + 50000ULL;
    for (;;) {
        uint slot;
        for (slot = 0; slot < 6; ++slot) {
            memw();
            if (MEDIUS_HOST_HID_ENDPOINTS[slot].in_callback != 0)
                break;
        }
        if (slot == 6)
            break;
        ulonglong now = (ulonglong)esp_timer_get_time();
        if ((now ^ sign_bit) >= (deadline ^ sign_bit))
            break;
        vTaskDelay(1);
    }
    MEDIUS_HID_ENDPOINT_COUNT = 0;
    memset((void *)MEDIUS_HID_ALTERNATE_SELECTIONS,0,256);
    memw();
    MediusHostHubPortPointer port =
        MEDIUS_HOST_CAPTURED_PORT;
    MEDIUS_HOST_DESCRIPTORS_READY = 0;
    if (port != 0)
        medius_out_unregister(port,0);
    memw();
    MEDIUS_HOST_CONTROL_PORT = 0;
    memw();
    MEDIUS_HOST_CAPTURED_PORT = 0;
    medius_vendor_stop_mode_interfaces();
    deadline = (ulonglong)esp_timer_get_time() + 600000ULL;
    for (;;) {
        memw();
        if (MEDIUS_HOST_CONTROL_BUSY == 0)
            break;
        ulonglong now = (ulonglong)esp_timer_get_time();
        if ((now ^ sign_bit) >= (deadline ^ sign_bit))
            break;
        vTaskDelay(1);
    }
    if (port != 0)
        medius_out_unregister(port,0);
    memw();
    MEDIUS_HOST_RESET_PENDING = 0;
    memw();
    MEDIUS_HOST_HID_PAUSED = 0;
    memw();
    MEDIUS_HOST_RECOVERY_DEFERRED = 0;
    memw();
    MEDIUS_HOST_RESUME_ARMED = 0;
    uchar power_state = MEDIUS_HOST_POWER->state;
    memw();
    MEDIUS_HOST_RESUME_PENDING = 0;
    if (power_state != 0) {
        medius_dwc2_host_resume_control(0,0);
        medius_host_set_frame_clock_blocked(0);
    }
    volatile MediusHostPowerStateView *power = MEDIUS_HOST_POWER;
    power->state = 0;
    power->applied_remote_wakeup = 0;
    power->preexisting_pause = 0;
    MEDIUS_HID_SUSPEND_RESTORE_MASK = 0;
    medius_vendor_reset_selection_state();
    medius_out_reset_toggles_resume();
    memw();
    uchar configuration_switch = MEDIUS_HOST_CONFIGURATION_SWITCH_GATE;
    uchar pre_capture = 0;
    int send_detach = 0;
    if (configuration_switch == 0) {
        memw();
        pre_capture = MEDIUS_HOST_PRECAPTURE->phase;
        send_detach = pre_capture == 0;
    }
    if (send_detach) {
        /* Both stores use the cached pre-capture zero, without another read. */
        memw();
        MEDIUS_HOST_PRECAPTURE_COMPLETE = pre_capture;
        memw();
        MEDIUS_HOST_IDENTITY_REFRESH = pre_capture;
        link_send_wait100(0x12,0,0,0);
        medius_host_log_formatted("detached");
    } else {
        memw();
        configuration_switch = MEDIUS_HOST_CONFIGURATION_SWITCH_GATE;
        const char *reason = configuration_switch != 0 ? "configuration switch" : "pre-capture";
        medius_host_log_formatted("stack restart of our own (%s); no detach sent",reason);
    }
}

/* Native entry: 0x4202d61c. */
/* Original function-byte SHA-256:
 * 44198dc22a7fcf9d5f1bbb8f9cb56f59cb147ee966f800aef03c914f568b39d8. */
/* Handle the host stack's events using the low BYTE of bus/hub/port/event;
 * interface_index is ignored. Event 3 records the low WORD of signed uptime
 * microseconds /1000, replacing zero with 1. Event 5 clears the enumeration
 * start and restart words, then captures a found non-hub device only while the
 * descriptor-ready BYTE is zero. Event 4 clears the start word and, if both
 * configuration-switch and precapture gates are zero, stores the sampled zero
 * precapture BYTE as the requested configuration (no second read).
 * Event 11 matches the captured port by its parent hub index and port number;
 * it does not compare bus or interface. Clear clone-active after sampling
 * descriptor-ready. If that snapshot or the fresh HID endpoint count is nonzero,
 * cache the snapshot timer, publish reset-pending=1, stop the cached timer
 * (discard status), and tear down interfaces. Other events do nothing. The
 * individual volatile/MEMW accesses do not establish an atomic state snapshot. */
void medius_usb_host_event(unsigned int bus_id,unsigned int hub_id,
    unsigned int port_number,unsigned int interface_index,unsigned int event_code)
{
    (void)interface_index;
    unsigned char bus=(unsigned char)bus_id;
    unsigned char hub=(unsigned char)hub_id;
    unsigned char port_id=(unsigned char)port_number;
    unsigned char event=(unsigned char)event_code;
    if (event==3) {
        long long milliseconds=esp_timer_get_time()/1000LL;
        unsigned int started=(unsigned int)milliseconds;
        if (started==0)
            started=1;
        memw();
        MEDIUS_HOST_ENUMERATION_STARTED_MS=started;
    } else if (event==5) {
        memw();
        MEDIUS_HOST_ENUMERATION_STARTED_MS=0;
        MEDIUS_HOST_ENUMERATION_RESTART_COUNT=0;
        MediusHostHubPortPrefix *port=usbh_find_hubport(bus,hub,port_id);
        if (port!=NULL && ((const volatile MediusHostHubPortPrefix *)port)->device_descriptor[4]!=9 &&
            MEDIUS_HOST_DESCRIPTORS_READY==0)
            medius_host_capture_descriptors_and_probe_controls(port);
    } else if (event==4) {
        memw();
        MEDIUS_HOST_ENUMERATION_STARTED_MS=0;
        memw();
        if (MEDIUS_HOST_CONFIGURATION_SWITCH_GATE==0) {
            memw();
            unsigned char precapture=MEDIUS_HOST_PRECAPTURE_STATE;
            if (precapture==0) {
                memw();
                MEDIUS_HOST_REQUESTED_CONFIGURATION=precapture;
            }
        }
    } else if (event==11) {
        memw();
        const volatile MediusHostHubPortPrefix *port=MEDIUS_HOST_CAPTURED_PORT;
        if (port==NULL)
            return;
        const volatile MediusHostHubPrefix *parent=port->parent;
        if (parent==NULL || parent->index!=hub || port->port_number!=port_id)
            return;
        unsigned char descriptors_ready=MEDIUS_HOST_DESCRIPTORS_READY;
        memw();
        MEDIUS_HOST_CLONE_ACTIVE=0;
        if (descriptors_ready==0 && MEDIUS_HID_ENDPOINT_COUNT==0)
            return;
        EspTimer *timer=MEDIUS_HOST_SNAPSHOT_TIMER;
        memw();
        MEDIUS_HOST_RESET_PENDING=1;
        (void)esp_timer_stop(timer);
        medius_host_teardown_interfaces();
    }
}

/* Native entry: 0x4202f130. */
/*
 * Medius v3.4.7 — host application; 0x4202f130.
 *
 * Sends a seven-byte link diagnostic with reason, detail and optional device identity.
 *
 * Calls: link_send_wait100.
 *
 * Called by: medius_host_parse_configuration, medius_usbh_hub_attach, usbh_enumerate.
 *
 * Original function-byte SHA-256:
 * 6eea5fdee31f177a2bea05b1a21a560b35896f6964232bc015ec798849fe59bc.
 */

/* Sends a seven-byte link diagnostic with reason, detail and optional device identity. Builds
   borrowed7-byte stack payload[reason,detailLE16,VIDLE16,PIDLE16]. NonNULL port suppliesVID
   from+0F/+10 andPID from+11/+12 via byte+word loads;NULL supplies four zero identity bytes. Calls
   link_send_wait100(type3C,sequence0,payload,7) exactly once and ignores its result. No
   local retry/state writes. Boundaries: No connected/descriptor validation, so stale identity is
   possible. Payload pointer is borrowed for the call; transport owns any needed copy. Known local
   callers use reason1 for total configuration length>2048,reason2 for excessive external hub
   ports,reason3 for an occupied external hub slot,reason4 for configuration storage allocation
   failure. Other raw reason values are not rejected. */

/*
 * port: Optional source of stored descriptor identity; NULL supplies four zero identity bytes.
 * reason: Raw eight-bit diagnostic reason.
 * detail: Raw sixteen-bit diagnostic detail.
 * Returns: No value; send result is ignored.
 * Requirements/effects: Non-NULL port is read as aligned word at +16 then byte at +15. Builds
 *   [reason,detailLE16,VIDLE16,PIDLE16] with native word/halfword/byte stack stores, then sends
 *   exactly seven borrowed bytes as message 0x3c sequence 0. No retry, connection or descriptor
 *   validity check occurs. Transport must copy any retained packet before return. Known reasons
 *   are configuration length above 2048 (1), too many hub ports (2), occupied hub slot (3) and
 *   configuration allocation failure (4); other values are forwarded.
 */

void medius_host_report_enumeration_limit(MediusHostHubPortPrefix *port,uchar reason,ushort detail)
{
    uint identity_word = 0;
    uint vendor_low = 0;
    if (port != 0) {
        identity_word = *(const volatile uint *)((uint)port + 16U);
        vendor_low = ((const volatile uchar *)port)[15];
    }
    /* Seven initialized wire bytes, followed only by unsent C alignment padding. */
    MediusEnumerationLimitPacket packet;
    packet.reason_detail_vendor_low = (uint)reason | ((uint)detail << 8) | (vendor_low << 24);
    packet.vendor_high_product_low = (ushort)identity_word;
    packet.product_high = (uchar)(identity_word >> 16);
    link_send_wait100(0x3c,0,&packet,7);
}

/* Native entry: 0x4202f17c. */
/*
 * Medius v3.4.7 — host application; 0x4202f17c.
 *
 * Restarts the tracked enumeration timer for15000 microseconds when its gates and port identity
 * permit.
 *
 * Calls: esp_timer_start_once, esp_timer_stop.
 *
 * Called by: usbh_enumerate.
 *
 * Original function-byte SHA-256:
 * 52333b6f927a508b69e0d7c69564efec6ca6baf9678aaf9fd724feaaff21d7ca.
 */

/* Restarts the tracked enumeration timer for15000 microseconds when its gates and port identity
   permit. Returns unless enable is nonzero and inhibit is0. MEMW then compares tracked port pointer
   with input; mismatch returns. Calls esp_timer_stop(current handle), ignores result, rereads timer
   handle and calls esp_timer_start_once(fresh handle,64-bit15000), ignoring result. Does not
   recheck gates/identity after stop and makes no local writes. Boundaries: No timer NULL guard;
   inputNULL matches trackedNULL and can restart a timer. Requested15000us delay is not measured
   scheduling/timing proof. Stop may fail or a changed handle may be started. Callback effects and
   gate-setting policies remain in their own functions. */

/*
 * port: Identity pointer compared with the tracked port; NULL may match a tracked NULL.
 * Returns: No value. Both software-timer API return codes are ignored.
 * Requirements/effects: Reads enable then inhibit, rejecting zero enable or nonzero inhibit. MEMW
 *   before tracked-port comparison. On identity match reads/stops the current timer, freshly reads
 *   its handle and requests one-shot delay 15000 microseconds. No NULL-handle check, gate recheck,
 *   rollback or measured deadline is supplied. This is a software timer dispatched by the shared
 *   ESP timer task; actual callback time depends on scheduling, interrupts, critical sections,
 *   task priorities, earlier callbacks and load, and is not guaranteed to equal the requested
 *   delay.
 */

void medius_host_enumeration_timer_restart(MediusHostHubPortPrefix *port)
{
    if (MEDIUS_HOST_DESCRIPTORS_READY == 0)
        return;
    if (MEDIUS_HOST_CAPTURE_READY != 0)
        return;
    memw();
    if (MEDIUS_HOST_CAPTURED_PORT != port)
        return;
    EspTimer *timer = MEDIUS_HOST_SNAPSHOT_TIMER;
    esp_timer_stop(timer);
    timer = MEDIUS_HOST_SNAPSHOT_TIMER;
    esp_timer_start_once(timer,15000ULL);
}
