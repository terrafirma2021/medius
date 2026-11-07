/* Medius v3.4.7 host — usb/dwc2.c.
 * Recovered C and native assembly, grouped for source navigation.
 * Original entry addresses, firmware-byte hashes and function comments follow.
 */

#include "../include/types.h"

/* Source reconstruction utilities for repeated control-stage enable blocks
 * inside native4201f20c. This is not an additional native entry. Every stage
 * enters the lock before refreshing base/controller, then samples frame parity
 * and consumes the live keep-parity byte. Keep three distinct HCCHAR reads and
 * the fenced volatile scratch sequence used to clear CHDIS and set CHENA. */
static void dwc2_control_enable_channel(MediusHostBusPrefix *bus,unsigned int channel)
{
    unsigned int token = medius_usbh_critical_enter();
    const volatile MediusHostBusPrefix *live_bus = bus;
    unsigned int base = live_bus->register_base;
    volatile MediusDwc2HostChannelRegisters *registers = (volatile void *)(base+channel*32U+0x500U);
    memw();
    registers->interrupt_mask = 2;
    unsigned int controller = live_bus->controller_id;
    volatile MediusHostChannel *state = (volatile void *)(0x3fca7c80U+controller*668U+channel*36U);
    const volatile MediusDwc2HostRegisters *global = (const volatile void *)base;
    memw();
    unsigned int parity = global->frame_number & 1U;
    if (state->keep_frame_parity == 0)
        parity ^= 1U;
    else
        state->keep_frame_parity = 0;
    memw();
    unsigned int characteristics = registers->characteristics;
    memw();
    registers->characteristics = characteristics & 0xdfffffffU;
    memw();
    characteristics = registers->characteristics;
    memw();
    registers->characteristics = characteristics | (parity << 29);
    memw();
    characteristics = registers->characteristics;
    memw();
    volatile unsigned int enabled = characteristics;
    memw();
    characteristics = enabled;
    memw();
    enabled = characteristics & 0xbfffffffU;
    memw();
    characteristics = enabled;
    memw();
    enabled = characteristics | 0x80000000U;
    memw();
    characteristics = enabled;
    memw();
    registers->characteristics = characteristics;
    medius_usbh_critical_exit(token);
}


/* Native entry: 0x4037d7f4. */
/* Original function-byte SHA-256:
 * 41279119be30e3badf07e8294e73b92484e1340cf2bbb000b857d1b47b4dc3fe. */
/* Interrupt-allocation callback: interpret the argument's low byte as the
 * host bus index and forward it to USBH_IRQHandler. No NULL/dereference test:
 * a NULL argument selects bus0. The upper pointer bits are discarded. */
void medius_usb_host_irq_trampoline(void *argument)
{
    USBH_IRQHandler((unsigned int)argument & 255U);
}

/* Native entry: 0x4037d800. */
/*
 * Medius v3.4.7 — host application; 0x4037d800.
 *
 * Dispatches host port/global/channel interrupts, with distinct IN/OUT accounting, split
 * handshakes, control stages and completion ownership.
 *
 * Calls: dwc2_calc_frame_interval, dwc2_host_start_control, dwc2_host_start_noncontrol,
 * medius_dwc2_host_clock_gate, medius_hid_sof_schedule, medius_host_publish_resume_event,
 * medius_usbh_account_and_rearm_in, medius_usbh_complete_urb, medius_usbh_copy_received,
 * medius_usbh_critical_enter, medius_usbh_critical_exit, medius_usbh_notify_hub,
 * medius_usbh_rearm_in_with_alignment, usb_osal_sem_give.
 *
 * Called by: medius_usb_host_irq_trampoline.
 *
 * Indirect calls: fixed USB helpers and the optional URB completion callback.
 *
 * Original function-byte SHA-256:
 * 231b9a9bcc37cd0d42926e168baae9a6425ec0ea7d2d88b81a700ce07af9c3b8.
 */

/*
 * bus_index: Low8 selects an828-byte bus slot; controller_id selects668-byte HCD state. No index,
 *   endpoint, callback lifetime or raw channel-count validation.
 * Returns: No value. Captured pending selects port/disconnect/channels/SOF/wake in that order;
 *   helper waits and callbacks are outside any timing guarantee.
 * Requirements/effects: Separate status/mask/status reads precede all gates; host mode uses second
 *   status and pending uses first. Port change selection/preservation use distinct reads; connect
 *   notification precedes change flag, enable configuration uses distinct compare/update reads,
 *   HFIR upper16 cached before calculator. Disconnect ID/bitmap pointer loaded before flag
 *   publication. Channel count read before HAINT/mask; raw count/ID refreshed each iteration, bit
 *   selection aliases modulo16; HCCHAR read before URB pointer. Null URB acknowledges raw cause,
 *   associated requires CHH; no HCINTMSK filtering. One cause priority
 *   XFRC/AHB/STALL/NAK/ACK/NYET/TXERR/babble/toggle/frame. IN XFRC first residue/second PID
 *   snapshots with native programmed/base/bounce order; wrap actual/remaining, store toggle before
 *   complete-split read/account stores; zero-length bounce copy still called. OUT three
 *   size/packet/PID snapshots with native endpoint-byte reads; actual wraps and remaining
 *   saturates only stage2 or null setup; cached stage retained across split clearing. Setup length
 *   high/low bytes, stage-specific setup/data/status continuations and setup8-byte offset
 *   retained. Distinct IN/OUT ACK/NAK/NYET type/phase/frame read order, no ISO completion in these
 *   branches. Retry only progressed nonsplit interrupt IN for TXERR/toggle/frame and count<3;
 *   clear bounce/increment before helper, failure retains event error, toggle/frame use actual
 *   completion helper. Inline completion reads timeout before error store/channel link; async
 *   cached linkedURB before bounce/retry clears, follows trusted crosslink, clears active after
 *   link, exits local lock before callback. Synchronous gives semaphore and retains association.
 *   Callback pointer then error/context/conditional actual snapshots; base refreshed after
 *   completion/helpers but not no-op channel branches. SOF acknowledges before scheduler; wake
 *   mask/clock/HPRT/resume sequence retains cached register base. No physical
 *   USB/DMA/W1C/timing/concurrent lifetime proof.
 */

void USBH_IRQHandler(uint bus_index)
{
    uint index = bus_index & 255U;
    volatile MediusHostBusPrefix *bus = &MEDIUS_HOST_BUSES[index];
    volatile MediusDwc2HostRegisters *registers =
        (volatile MediusDwc2HostRegisters *)bus->register_base;

    memw();
    uint first_status = registers->interrupt_status;
    memw();
    uint interrupt_mask = registers->interrupt_mask;
    memw();
    uint second_status = registers->interrupt_status;
    uint pending = first_status & interrupt_mask;
    if ((second_status & 1U) == 0 || pending == 0)
        return;

    if ((pending & 0x01000000U) != 0) {
        volatile uint *port_register = &registers->port;
        memw();
        uint changes = *port_register;
        memw();
        uint port_value = *port_register & 0xffffff51U;
        if ((changes & 2U) != 0) {
            if ((changes & 1U) != 0) {
                uchar *bitmap = *(uchar *volatile *)((uint)bus + 0x310U);
                *(volatile uchar *)bitmap = 2;
                medius_usbh_notify_hub((void *)((uint)bus + 16U));
                registers = (volatile MediusDwc2HostRegisters *)bus->register_base;
                port_register = &registers->port;
            }
            port_value |= 2U;
            uint controller_id = bus->controller_id;
            volatile MediusDwc2HostContextPrefix *controller =
                (volatile MediusDwc2HostContextPrefix *)(0x3fca7c24U + controller_id * 668U);
            memw();
            controller->connect_changed = 1;
        }
        if ((changes & 8U) != 0) {
            port_value |= 8U;
            uint controller_id = bus->controller_id;
            volatile MediusDwc2HostContextPrefix *controller =
                (volatile MediusDwc2HostContextPrefix *)(0x3fca7c24U + controller_id * 668U);
            memw();
            controller->enable_changed = 1;
            if ((changes & 4U) != 0) {
                uchar keep_clock = controller->keep_clock_configuration;
                if (keep_clock == 0) {
                    uint requested_clock = ((changes >> 17) & 3U) == 2U ? 2U : 1U;
                    memw();
                    uint previous_clock = registers->configuration;
                    if ((previous_clock & 3U) != requested_clock) {
                        memw();
                        uint live_clock = registers->configuration;
                        memw();
                        registers->configuration = (live_clock & ~3U) | requested_clock;
                    }
                }
                memw();
                uint old_interval = registers->frame_interval;
                uint interval = dwc2_calc_frame_interval((MediusHostBusPrefix *)bus);
                memw();
                registers->frame_interval = (old_interval & 0xffff0000U) | interval;
            }
        }
        if ((changes & 0x20U) != 0) {
            port_value |= 0x20U;
            uint controller_id = bus->controller_id;
            volatile MediusDwc2HostContextPrefix *controller =
                (volatile MediusDwc2HostContextPrefix *)(0x3fca7c24U + controller_id * 668U);
            memw();
            controller->overcurrent_changed = 1;
        }
        memw();
        *port_register = port_value;
    }

    if ((pending & 0x20000000U) != 0) {
        uint controller_id = bus->controller_id;
        uchar *bitmap = *(uchar *volatile *)((uint)bus + 0x310U);
        volatile MediusDwc2HostContextPrefix *controller =
            (volatile MediusDwc2HostContextPrefix *)(0x3fca7c24U + controller_id * 668U);
        memw();
        controller->connect_changed = 1;
        *(volatile uchar *)bitmap = 2;
        medius_usbh_notify_hub((void *)((uint)bus + 16U));
        registers = (volatile MediusDwc2HostRegisters *)bus->register_base;
        memw();
        registers->interrupt_status = 0x20000000U;
    }

    if ((pending & 0x02000000U) != 0) {
        uint controller_id = bus->controller_id;
        registers = (volatile MediusDwc2HostRegisters *)bus->register_base;
        volatile MediusDwc2HostContextPrefix *controller =
            (volatile MediusDwc2HostContextPrefix *)(0x3fca7c24U + controller_id * 668U);
        uint count = (controller->hardware_capabilities >> 6) & 31U;
        memw();
        uint channel_status = registers->channel_interrupt_status;
        memw();
        uint channel_mask = registers->channel_interrupt_mask;
        uint selected = channel_status & channel_mask & 65535U;
        uint channel = 0;
        while ((channel & 255U) < count) {
            if ((selected & (1U << (channel & 15U))) != 0) {
                volatile MediusDwc2HostChannelRegisters *channel_registers =
                    (volatile MediusDwc2HostChannelRegisters *)((uint)registers + 0x500U + 32U * channel);
                volatile MediusHostChannel *state = (volatile MediusHostChannel *)
                    (0x3fca7c80U + controller_id * 668U + channel * 36U);
                memw();
                uint characteristics = channel_registers->characteristics;
                volatile MediusHostUrb *urb = state->urb;
                memw();
                uint cause = channel_registers->interrupt_status;
                if (urb == 0) {
                    memw();
                    channel_registers->interrupt_status = cause;
                    goto next_channel;
                }
                if ((cause & 2U) == 0)
                    goto next_channel;
                memw();
                channel_registers->interrupt_status = cause;

                uint type, timeout, actual, remaining, delta;
                uchar *endpoint, *buffer, *setup;
                uchar split, stage;
                int error;

                if ((cause & 1U) != 0) {
                    if ((characteristics & 0x8000U) != 0) {
                        uint programmed = state->programmed_bytes;
                        registers = (volatile MediusDwc2HostRegisters *)bus->register_base;
                        channel_registers = (volatile MediusDwc2HostChannelRegisters *)
                            ((uint)registers + 0x500U + 32U * channel);
                        memw();
                        uint residue = channel_registers->transfer_size & 0x7ffffU;
                        delta = programmed - residue;
                        uchar *bounce_destination = state->bounce_destination;
                        if (bounce_destination != 0) {
                            medius_usbh_copy_received(bounce_destination,
                                (uchar *)(0x3fc9f23cU + channel * 64U), delta);
                            registers = (volatile MediusDwc2HostRegisters *)bus->register_base;
                            state->bounce_destination = 0;
                            channel_registers = (volatile MediusDwc2HostChannelRegisters *)
                                ((uint)registers + 0x500U + 32U * channel);
                        }
                        memw();
                        uint pid = (channel_registers->transfer_size >> 29) & 3U;
                        remaining = urb->remaining;
                        actual = urb->actual;
                        urb->toggle = pid != 0;
                        uchar complete_split = state->complete_split;
                        actual += delta;
                        remaining = remaining - programmed + residue;
                        urb->actual = actual;
                        urb->remaining = remaining;
                        if (complete_split != 0) {
                            registers = (volatile MediusDwc2HostRegisters *)bus->register_base;
                            state->complete_split = 0;
                            channel_registers = (volatile MediusDwc2HostChannelRegisters *)
                                ((uint)registers + 0x500U + 32U * channel);
                            memw();
                            uint route = channel_registers->split;
                            memw();
                            channel_registers->split = route & ~0x10000U;
                        }
                        endpoint = urb->endpoint;
                        type = *(volatile uchar *)(endpoint + 3) & 3U;
                        if (type == 0) {
                            stage = state->control_state;
                            if (stage == 1) {
                                split = state->split_enabled;
                                setup = urb->setup;
                                buffer = urb->buffer;
                                if (split != 0 && remaining != 0) {
                                    uint high = *(volatile uchar *)(endpoint + 5);
                                    uint low = *(volatile uchar *)(endpoint + 4);
                                    if (delta == (((high << 8) | low) & 2047U)) {
                                        buffer = (uchar *)((uint)buffer + actual - 8U);
                                        goto start_control;
                                    }
                                }
                                state->control_state = 4;
                                goto start_control;
                            }
                            if (stage == 3) {
                                state->control_state = 0;
                                timeout = urb->timeout;
                                *(volatile uint *)0x3fca7c20U = delta;
                                error = 0;
                                goto complete_with_timeout;
                            }
                            goto reload_registers;
                        }
                        if (type == 1)
                            goto reload_registers;
                        split = state->split_enabled;
                        if (split != 0 && remaining != 0) {
                            uint high = *(volatile uchar *)(endpoint + 5);
                            uint low = *(volatile uchar *)(endpoint + 4);
                            if (delta == (((high << 8) | low) & 2047U)) {
                                buffer = urb->buffer;
                                buffer = (uchar *)((uint)buffer + actual);
                                goto start_noncontrol;
                            }
                        }
                        error = 0;
                        goto complete;
                    }

                    /* OUT size, packet count and PID come from three reads. */
                    memw();
                    uint last_bytes = channel_registers->transfer_size & 0x7ffffU;
                    endpoint = urb->endpoint;
                    uint high = *(volatile uchar *)(endpoint + 5);
                    memw();
                    uint packets_left = (channel_registers->transfer_size >> 19) & 1023U;
                    uint low = *(volatile uchar *)(endpoint + 4);
                    uint initial_packets = state->initial_packets;
                    actual = urb->actual;
                    memw();
                    uint pid = (channel_registers->transfer_size >> 29) & 3U;
                    delta = (initial_packets - 1U - packets_left) *
                        (((high << 8) | low) & 2047U) + last_bytes;
                    actual += delta;
                    urb->actual = actual;
                    stage = state->control_state;
                    if (stage == 2 || urb->setup == 0) {
                        remaining = urb->remaining;
                        urb->remaining = delta < remaining ? remaining - delta : 0;
                    }
                    urb->toggle = pid != 0;
                    uchar complete_split = state->complete_split;
                    if (complete_split != 0) {
                        registers = (volatile MediusDwc2HostRegisters *)bus->register_base;
                        state->complete_split = 0;
                        channel_registers = (volatile MediusDwc2HostChannelRegisters *)
                            ((uint)registers + 0x500U + 32U * channel);
                        memw();
                        uint route = channel_registers->split;
                        memw();
                        channel_registers->split = route & ~0x10000U;
                    }
                    type = *(volatile uchar *)(endpoint + 3) & 3U;
                    if (type == 0) {
                        if (stage == 0) {
                            setup = urb->setup;
                            uint length_high = *(volatile uchar *)(setup + 7);
                            uint length_low = *(volatile uchar *)(setup + 6);
                            uchar next_stage = 3;
                            if (((length_high << 8) | length_low) != 0)
                                next_stage = (*(volatile uchar *)setup & 128U) != 0 ? 1 : 2;
                            state->control_state = next_stage;
                            remaining = urb->remaining;
                            buffer = urb->buffer;
                            goto start_control;
                        }
                        if (stage == 2) {
                            remaining = urb->remaining;
                            split = state->split_enabled;
                            setup = urb->setup;
                            buffer = urb->buffer;
                            if (split != 0 && remaining != 0)
                                buffer = (uchar *)((uint)buffer + actual - 8U);
                            else
                                state->control_state = 3;
                            goto start_control;
                        }
                        if (stage == 4) {
                            state->control_state = 0;
                            error = 0;
                            goto complete;
                        }
                        goto reload_registers;
                    }
                    if (type == 1)
                        goto reload_registers;
                    split = state->split_enabled;
                    if (split != 0) {
                        remaining = urb->remaining;
                        if (remaining != 0) {
                            buffer = urb->buffer;
                            buffer = (uchar *)((uint)buffer + actual);
                            goto start_noncontrol;
                        }
                    }
                    error = 0;
                    goto complete;
                }

                /* Priority: AHBERR, STALL, NAK, ACK, NYET, TXERR,
                   babble, data-toggle error, frame overrun. */
                if ((cause & 4U) != 0) {
                    error = -12;
                    goto complete;
                }
                if ((cause & 8U) != 0) {
                    error = -8;
                    goto complete;
                }
                if ((cause & 16U) != 0) {
                    if ((characteristics & 0x8000U) != 0) {
                        endpoint = urb->endpoint;
                        split = state->split_enabled;
                        type = *(volatile uchar *)(endpoint + 3) & 3U;
                    } else {
                        split = state->split_enabled;
                        if (split == 0) {
                            error = -10;
                            goto complete;
                        }
                        endpoint = urb->endpoint;
                        type = *(volatile uchar *)(endpoint + 3) & 3U;
                    }
                    if (split == 0) {
                        if (type == 3) {
                            actual = urb->actual;
                            if (actual != 0)
                                goto account_in;
                            memw();
                            uint residue = channel_registers->transfer_size & 0x7ffffU;
                            uint programmed = state->programmed_bytes;
                            if (residue != programmed)
                                goto account_in;
                        }
                        error = -10;
                        goto complete;
                    }
                    if (type == 0 || type == 2) {
                        actual = urb->actual;
                        buffer = urb->buffer;
                        remaining = urb->remaining;
                        if (type == 0)
                            setup = urb->setup;
                        state->complete_split = 0;
                        buffer = (uchar *)((uint)buffer + actual - (type == 0 ? 8U : 0U));
                        if (type == 0)
                            goto start_control;
                        goto start_noncontrol;
                    }
                    if (type == 3) {
                        memw();
                        uint route = channel_registers->split;
                        state->complete_split = 0;
                        timeout = urb->timeout;
                        memw();
                        channel_registers->split = route & ~0x10000U;
                        error = -10;
                        goto complete_with_timeout;
                    }
                    goto next_channel;
                }
                if ((cause & 32U) != 0) {
                    if ((characteristics & 0x8000U) != 0) {
                        endpoint = urb->endpoint;
                        split = state->split_enabled;
                        type = *(volatile uchar *)(endpoint + 3) & 3U;
                        if (split == 0) {
                            if (type == 3)
                                goto account_in;
                            goto next_channel;
                        }
                        memw();
                        uint frame = registers->frame_number;
                        state->complete_split = 1;
                        state->split_frame = (frame >> 3) & 2047U;
                    } else {
                        split = state->split_enabled;
                        if (split == 0)
                            goto next_channel;
                        goto record_split_handshake;
                    }
                    goto restart_split;
                }
                if ((cause & 64U) != 0) {
                    split = state->split_enabled;
                    if (split == 0) {
                        error = -10;
                        goto complete;
                    }
record_split_handshake:
                    memw();
                    {
                        uint frame = registers->frame_number;
                        endpoint = urb->endpoint;
                        state->complete_split = 1;
                        state->split_frame = (frame >> 3) & 2047U;
                        type = *(volatile uchar *)(endpoint + 3) & 3U;
                    }
restart_split:
                    if (type == 0) {
                        actual = urb->actual;
                        buffer = urb->buffer;
                        remaining = urb->remaining;
                        setup = urb->setup;
                        buffer = (uchar *)((uint)buffer + actual - 8U);
                        goto start_control;
                    }
                    if (type == 2 || type == 3) {
                        actual = urb->actual;
                        buffer = urb->buffer;
                        remaining = urb->remaining;
                        buffer = (uchar *)((uint)buffer + actual);
                        goto start_noncontrol;
                    }
                    goto next_channel;
                }
                if ((cause & 128U) != 0)
                    error = -12;
                else if ((cause & 256U) != 0) {
                    error = -9;
                    goto complete;
                } else if ((cause & 1024U) != 0)
                    error = -11;
                else if ((cause & 512U) != 0)
                    error = -12;
                else
                    goto next_channel;

                if ((characteristics & 0x8000U) != 0) {
                    endpoint = urb->endpoint;
                    type = *(volatile uchar *)(endpoint + 3) & 3U;
                    if (type == 3 && state->split_enabled == 0 && urb->actual != 0) {
                        uchar retries = state->retry_count;
                        if (retries < 3) {
                            state->bounce_destination = 0;
                            state->retry_count = retries + 1;
                            if (medius_usbh_rearm_in_with_alignment((void *)bus, channel,
                                    (MediusHostChannel *)state, (MediusHostUrb *)urb) != 0)
                                goto reload_registers;
                        }
                    }
                    if ((cause & 128U) == 0) {
                        urb->error = error;
                        medius_usbh_complete_urb((MediusHostUrb *)urb);
                        goto reload_registers;
                    }
                }
                goto complete;

account_in:
                medius_usbh_account_and_rearm_in((void *)bus, channel,
                    (MediusHostChannel *)state, (MediusHostUrb *)urb);
                goto reload_registers;
start_control:
                dwc2_host_start_control((void *)bus, channel, (MediusHostUrb *)urb,
                    setup, buffer, remaining);
                goto reload_registers;
start_noncontrol:
                dwc2_host_start_noncontrol((void *)bus, channel, (MediusHostUrb *)urb,
                    buffer, remaining);
                goto reload_registers;
complete:
                timeout = urb->timeout;
complete_with_timeout:
                urb->error = error;
                {
                    volatile MediusHostChannel *owned_channel = urb->channel;
                    if (timeout == 0) {
                        uint critical_token = medius_usbh_critical_enter();
                        volatile MediusHostUrb *linked_urb = owned_channel->urb;
                        owned_channel->bounce_destination = 0;
                        owned_channel->retry_count = 0;
                        if (linked_urb != 0) {
                            linked_urb->channel = 0;
                            owned_channel->urb = 0;
                        }
                        owned_channel->in_use = 0;
                        medius_usbh_critical_exit(critical_token);
                    } else {
                        void *semaphore = owned_channel->semaphore;
                        usb_osal_sem_give(semaphore);
                    }
                    void (*complete_callback)(void *, int) = urb->complete;
                    if (complete_callback != 0) {
                        int result = urb->error;
                        void *context = urb->context;
                        if (result >= 0)
                            result = (int)urb->actual;
                        complete_callback(context, result);
                    }
                }
reload_registers:
                registers = (volatile MediusDwc2HostRegisters *)bus->register_base;
            }
next_channel:
            controller_id = bus->controller_id;
            channel++;
            controller = (volatile MediusDwc2HostContextPrefix *)
                (0x3fca7c24U + controller_id * 668U);
            count = (controller->hardware_capabilities >> 6) & 31U;
        }
        memw();
        registers->interrupt_status = 0x02000000U;
    }

    if ((pending & 8U) != 0) {
        registers = (volatile MediusDwc2HostRegisters *)bus->register_base;
        memw();
        registers->interrupt_status = 8;
        /* Native a10 carries the bus index; this helper consumes no argument. */
        medius_hid_sof_schedule();
    }
    if ((pending & 0x80000000U) != 0) {
        registers = (volatile MediusDwc2HostRegisters *)bus->register_base;
        memw();
        registers->interrupt_status = 0x80000000U;
        memw();
        uint mask = registers->interrupt_mask;
        memw();
        registers->interrupt_mask = mask & 0x7fffffffU;
        medius_dwc2_host_clock_gate((void *)bus, 0);
        memw();
        uint port = registers->port;
        memw();
        registers->port = (port & 0xffffff11U) | 64U;
        /* The native helper likewise ignores the caller's bus-index register. */
        medius_host_publish_resume_event();
    }
}

/* Native entry: 0x4037ef3c. */
/* Original function-byte SHA-256:
 * bd93033601af6ade2de14749b5306833349a91916f6f775bdee2deb2405430e5. */
/* Program a host noncontrol transfer. Cache controller_id before reading the
 * endpoint's unaligned packet word HIGH byte then LOW. Split mode limits the
 * request to one MPS. Zero length uses one packet; otherwise unsigned32 ceil
 * arithmetic wraps, quotient truncates16, then caps1023. Nonzero nonsplit
 * length reaches QUOU even for zero MPS. Retain that CPU operation explicitly
 * so the zero-divisor path is not converted into undefined C division.
 * IN programs packet_count*MPS bytes, even for a zero-length request; OUT keeps
 * the selected request length. Save full programmed length/packet count before
 * channel configuration. HCTSIZ keeps only LOW19 bytes and normalizes toggle
 * to bit30, so cached/programmed hardware extents can differ for large inputs.
 *
 * Write size and DMA address before locking. After entering the driver lock,
 * refresh bus base/controller_id, set interrupt mask2, sample frame bit0 and
 * consume the current controller's one-shot parity flag. Update HCCHAR parity
 * through two fresh read/modify/writes. Enable using a third MMIO read and a
 * separately fenced volatile scratch word, clearing bit30 and setting bit31.
 * No channel/DMA-span validation or allocation; caller owns URB/descriptor
 * lifetime. The initial state and post-lock state may belong to different bus
 * controller snapshots. No USB/DMA completion or physical timing is implied. */
void dwc2_host_start_noncontrol(MediusHostBusPrefix *bus,unsigned int channel,
    MediusHostUrb *urb,unsigned char *buffer,unsigned int length)
{
    const volatile MediusHostBusPrefix *live_bus = bus;
    const volatile MediusHostUrb *live_urb = urb;
    unsigned int controller = live_bus->controller_id;
    const volatile MediusHostEndpointDescriptor *endpoint = (const volatile void *)live_urb->endpoint;
    unsigned int high = endpoint->max_packet[1];
    unsigned int low = endpoint->max_packet[0];
    unsigned int packet_word = (high << 8) | low;
    volatile MediusHostChannel *state = (volatile void *)
        (0x3fca7c80U+controller*668U+channel*36U);
    unsigned int max_packet = packet_word & 2047U;
    if (state->split_enabled != 0 && length > max_packet)
        length = max_packet;
    unsigned int address = endpoint->address;
    unsigned int packets = 1;
    if (length != 0) {
        unsigned int numerator = max_packet-1U+length;
        unsigned int quotient;
        __asm__ volatile ("quou %0,%1,%2" : "=a"(quotient)
            : "a"(numerator),"a"(max_packet) : "memory");
        packets = (unsigned short)quotient;
        if (packets > 1023)
            packets = 1023;
    }
    const volatile MediusHostHubPortPrefix *port = live_urb->hubport;
    if ((address & 128U) != 0)
        length = packets*max_packet;
    state->programmed_bytes = length;
    state->initial_packets = (unsigned short)packets;
    unsigned int attributes = endpoint->attributes;
    unsigned int speed = port->speed;
    unsigned int device = port->device_address;
    dwc2_host_channel_configure(bus,channel,device,address,attributes & 3U,max_packet,
        (unsigned char)(((packet_word >> 11) & 3U)+1U),(unsigned char)speed);
    unsigned int toggle = live_urb->toggle != 0;
    unsigned int base = live_bus->register_base;
    volatile MediusDwc2HostChannelRegisters *registers = (volatile void *)(base+channel*32U+0x500U);
    memw();
    registers->transfer_size = (toggle << 30) | (packets << 19) | (length & 0x7ffffU);
    memw();
    registers->dma_address = (unsigned int)(uintptr_t)buffer;
    unsigned int token = medius_usbh_critical_enter();
    base = live_bus->register_base;
    registers = (volatile void *)(base+channel*32U+0x500U);
    memw();
    registers->interrupt_mask = 2;
    controller = live_bus->controller_id;
    state = (volatile void *)(0x3fca7c80U+controller*668U+channel*36U);
    volatile MediusDwc2HostRegisters *global = (volatile void *)base;
    memw();
    unsigned int parity = global->frame_number & 1U;
    if (state->keep_frame_parity == 0)
        parity ^= 1U;
    else
        state->keep_frame_parity = 0;
    memw();
    unsigned int characteristics = registers->characteristics;
    memw();
    registers->characteristics = characteristics & 0xdfffffffU;
    memw();
    characteristics = registers->characteristics;
    memw();
    registers->characteristics = characteristics | (parity << 29);
    memw();
    characteristics = registers->characteristics;
    memw();
    volatile unsigned int enabled = characteristics;
    memw();
    characteristics = enabled;
    memw();
    enabled = characteristics & 0xbfffffffU;
    memw();
    characteristics = enabled;
    memw();
    enabled = characteristics | 0x80000000U;
    memw();
    characteristics = enabled;
    memw();
    registers->characteristics = characteristics;
    medius_usbh_critical_exit(token);
}

/* Native entry: 0x4037f0a4. */
/* Original function-byte SHA-256:
 * 658678778c1e5c9a749e2acfab36e1d19782e707c2c071743cba7dcdd8a31370. */
/* Disable this channel's interrupts, acknowledge statusUINT_MAX, and OR its
 * LOW4 channel bit into global HAINTMSK. Build HCCHAR using endpoint LOW4,
 * direction bit7, device LOW7 and multiplier LOW2; type and max_packet are not
 * masked. Speed1 adds low-speed bit17 unless sampled root speed is2. Type3
 * adds parity bit29. The HPRT sample uses a separately fenced volatile local.
 * After HCCHAR, freshly read controller_id and split state. Disabled split
 * writes0; enabled split combines raw hub_address<<7, complete_split<<16,
 * hub_port and bit31 without field bounds checks. No lock, channel cap, URB
 * ownership change or channel enable is supplied by this function. */
void dwc2_host_channel_configure(MediusHostBusPrefix *bus,unsigned int channel,
    unsigned int device_address,unsigned int endpoint,unsigned int type,
    unsigned int max_packet,unsigned char multiplier,unsigned char speed)
{
    const volatile MediusHostBusPrefix *live_bus = bus;
    unsigned int base = live_bus->register_base;
    volatile MediusDwc2HostChannelRegisters *registers = (volatile void *)(base+channel*32U+0x500U);
    volatile MediusDwc2HostRegisters *global = (volatile void *)base;
    memw();
    registers->interrupt_mask = 0;
    memw();
    registers->interrupt_status = 0xffffffffU;
    memw();
    unsigned int interrupt_mask = global->channel_interrupt_mask;
    unsigned int characteristics = ((unsigned int)(multiplier & 3U) << 20) | max_packet |
        (type << 18) | ((endpoint & 15U) << 11) | ((device_address & 127U) << 22);
    memw();
    global->channel_interrupt_mask = interrupt_mask | (1U << (channel & 15U));
    if ((endpoint & 128U) != 0)
        characteristics |= 0x8000U;
    if (speed == 1) {
        memw();
        volatile unsigned int sampled_port = 0;
        memw();
        unsigned int port = global->port;
        memw();
        sampled_port = port;
        memw();
        port = sampled_port;
        if (((port >> 17) & 3U) != 2)
            characteristics |= 0x20000U;
    }
    if (type == 3)
        characteristics |= 0x20000000U;
    memw();
    registers->characteristics = characteristics;
    unsigned int controller = live_bus->controller_id;
    const volatile MediusHostChannel *state = (const volatile void *)
        (0x3fca7c80U+controller*668U+channel*36U);
    unsigned int split = state->split_enabled;
    if (split != 0) {
        unsigned int hub_address = state->hub_address;
        unsigned int complete = state->complete_split;
        unsigned int hub_port = state->hub_port;
        split = (hub_address << 7) | (complete << 16) | hub_port | 0x80000000U;
    }
    memw();
    registers->split = split;
}

/* Native entry: 0x40389328. */
/*
 * Medius v3.4.7 — host application; 0x40389328.
 *
 * Samples host frame registers between timer reads and estimates frame origin in nanoseconds.
 *
 * Calls: __divdi3, esp_timer_get_time, vPortExitCritical, xPortEnterCriticalTimeout.
 *
 * Called by: FUN_4202563c, FUN_42026220, medius_host_get_frame_timing.
 *
 * Original function-byte SHA-256:
 * fe64c36f2a3426e222edf7f23b2d6f007e1603ebdee627c458c944fe540083e4.
 */

/*
 * snapshot: Writable 32-byte snapshot view on an admitted path; only its first 26 bytes
 *   are written.
 * Returns: 1 after publication; 0 on a gate rejection, leaving the output and cached low-rate flag
 *   unchanged.
 * Requirements/effects: Requests mux 0x3fc9de0c indefinitely and ignores entry status. Rejects
 *   nonzero SOF-mask gate, blocked flag or clear HPRT port-enable bit. Selects 6 ticks/us for HCFG
 *   low2==2, otherwise 48. Samples timer-before, HFNUM, HFIR and timer-after under the lock, then
 *   unlocks. Publishes the low-rate byte; elapsed_ns is floor((I-R)*1000/rate) when remaining
 *   R<=interval I, otherwise zero. Writes nominal ticks/ms, low16 interval, raw16 frame, period
 *   floor((I+1)*1000/rate), then base (before_us+after_us)*500-elapsed_ns, with native modulo-64
 *   arithmetic. Six trailing bytes are untouched. There is no sampling retry, duration/freshness
 *   check, NULL guard or atomic multi-output publication. Hardware register/oscillator accuracy
 *   and lock-respecting writers are external requirements.
 */

int medius_dwc2_host_frame_clock_snapshot(MediusHostFrameClockSnapshot *snapshot)
{
    xPortEnterCriticalTimeout(&MEDIUS_HOST_SOF_MASK_LOCK,-1);
    if (MEDIUS_HOST_SOF_MASK_GATE != 0) {
        vPortExitCritical(&MEDIUS_HOST_SOF_MASK_LOCK);
        return 0;
    }
    memw();
    if (MEDIUS_HOST_FRAME_CLOCK_BLOCKED != 0) {
        vPortExitCritical(&MEDIUS_HOST_SOF_MASK_LOCK);
        return 0;
    }
    memw();
    uint port_status = MEDIUS_HOST_USB_REGISTERS->port;
    if ((port_status & 4U) == 0) {
        vPortExitCritical(&MEDIUS_HOST_SOF_MASK_LOCK);
        return 0;
    }
    memw();
    uint clock_config = MEDIUS_HOST_USB_REGISTERS->configuration;
    bool low_rate = (clock_config & 3U) == 2U;
    uint ticks_per_us = low_rate ? 6U : 48U;
    uint nominal_ticks_per_ms = low_rate ? 6000U : 48000U;
    longlong before_us = esp_timer_get_time();
    memw();
    uint frame_word = MEDIUS_HOST_USB_REGISTERS->frame_number;
    memw();
    uint interval_word = MEDIUS_HOST_USB_REGISTERS->frame_interval;
    longlong after_us = esp_timer_get_time();
    vPortExitCritical(&MEDIUS_HOST_SOF_MASK_LOCK);

    memw();
    MEDIUS_HOST_FRAME_LOW_RATE = low_rate;
    uint interval_ticks = interval_word & 0xffffU;
    uint remaining_ticks = frame_word >> 16;
    longlong elapsed_ns = 0;
    if (remaining_ticks <= interval_ticks)
        elapsed_ns = __divdi3((longlong)(interval_ticks - remaining_ticks) * 1000LL,
                              (longlong)ticks_per_us);

    /* Only these 26 bytes are published; the six trailing bytes stay untouched. */
    volatile MediusHostFrameClockSnapshot *output = snapshot;
    output->nominal_ticks_per_ms = nominal_ticks_per_ms;
    output->interval_ticks_minus_one = interval_ticks;
    output->frame = (ushort)frame_word;
    longlong period_ns = __divdi3((longlong)(interval_ticks + 1U) * 1000LL,
                                  (longlong)ticks_per_us);
    ulonglong summed_us = (ulonglong)before_us + (ulonglong)after_us;
    output->period_ns = period_ns;
    output->base_ns = (longlong)(summed_us * 500ULL - (ulonglong)elapsed_ns);
    return 1;
}

/* Native entry: 0x4201ee74. */
/* Original function-byte SHA-256:
 * 8c1f695f78a224f580bf8fbe923ff56b890711a82723def0ba125e5eff97db91. */
/* Create the internal OTG PHY with all six configuration words zero except
 * otg_mode=1 (host). Store its handle at 0x3fca7ec4. On success, read bus.id
 * AFTER the PHY call and allocate source38/flags14 with the IRQ trampoline
 * and that byte as its argument; store the interrupt handle at 0x3fca7ec0.
 * PHY failure skips allocation. Both error results are discarded; no cleanup,
 * retry, bus validation or success result is provided to usb_hc_init. */
void usb_hc_low_level_init(MediusHostBusPrefix *bus)
{
    MediusUsbPhyConfiguration configuration = {0,0,1,0,0,0};
    if (usb_new_phy(&configuration,(MediusUsbPhyContext **)0x3fca7ec4U) == 0) {
        unsigned int id = ((const volatile MediusHostBusPrefix *)bus)->id;
        esp_intr_alloc(38,14,medius_usb_host_irq_trampoline,(void *)id,
                       (InterruptHandle **)0x3fca7ec0U);
    }
}

/* Native entry: 0x4201eed0. */
/* Original function-byte SHA-256:
 * f72f90eec002c2be201d93ba19530edeb9133f687a1418fef3682577c49ab270. */
/* Copy the fixed 64-byte parameter image at 0x3c045bf4; register_base is
 * unused. Aligned destinations receive interleaved word loads/stores.
 * Otherwise read each source word and byte-store it: the first three words
 * in each 16-byte block use byte order1/2/3/0, the fourth uses0/1/2/3.
 * This is a raw image copy including padding, with no validation or allocation.
 * The source's known alignment makes the native byte-prefix/tail path
 * unreachable here. Volatile accesses retain the native copy ordering. */
void dwc2_get_user_params(unsigned int register_base,void *destination)
{
    (void)register_base;
    const volatile unsigned int *source = (const volatile void *)0x3c045bf4U;
    if (((unsigned int)destination & 3U) == 0) {
        volatile unsigned int *words = destination;
        for (unsigned int block = 0; block < 4; ++block) {
            words[0] = source[0];
            words[1] = source[1];
            words[2] = source[2];
            words[3] = source[3];
            source += 4;
            words += 4;
        }
    } else {
        volatile unsigned char *bytes = destination;
        for (unsigned int block = 0; block < 4; ++block) {
            for (unsigned int word = 0; word < 3; ++word) {
                unsigned int value = source[word];
                bytes[4*word+1] = (unsigned char)(value >> 8);
                bytes[4*word+2] = (unsigned char)(value >> 16);
                bytes[4*word+3] = (unsigned char)(value >> 24);
                bytes[4*word] = (unsigned char)value;
            }
            unsigned int value = source[3];
            bytes[12] = (unsigned char)value;
            bytes[13] = (unsigned char)(value >> 8);
            bytes[14] = (unsigned char)(value >> 16);
            bytes[15] = (unsigned char)(value >> 24);
            source += 4;
            bytes += 16;
        }
    }
}

/* Native entry: 0x4201f20c. */
/* Original function-byte SHA-256:
 * e444320c1ee578096c54f7deea407d792be565f3ec68591339954ca30644d0b2. */
/* Program one cached control stage:0 SETUP,1 data IN,2 data OUT,3 status IN,
 *4 status OUT. Other stage bytes return without writes. Cache controller_id,
 * endpoint number, split-enabled and stage in native order. Data MPS is read
 * HIGH/LOW for split and LOW/HIGH for nonsplit. Split data clips length to MPS
 * and normalizes toggle into PID0/2; nonsplit data always uses PID2. Nonempty
 * data uses wrapped32 ceil, LOW16 quotient then cap1023. Zero data length uses
 * packet1; IN programs packets*MPS, OUT the selected length. QUOU is explicit
 * to retain its zero-divisor CPU boundary.
 *
 * SETUP uses supplied setup DMA,8 bytes,PID3 and untruncated ceil(8/MPS), cap1023.
 * Status IN initially saves MPS/packet1 and configures unmodified channel MPS,
 * then caps saved/programmed bytes to256, clears the shared status-actual word
 * and uses shared status DMA with PID2. Status OUT uses byte0/packet1/PID2/NULL
 * DMA, saving packet count before byte count. Input/setup data paths preserve
 * their own native metadata-store order.
 *
 * Configure type0/multiplier1, refresh base for HCTSIZ/HCDMA, then enter the
 * shared enable continuation (fresh base/controller, parity/one-shot flag,
 * CHH mask and HCCHAR updates under lock). No stage advancement, logical URB
 * accounting, channel/DMA bounds check or hardware completion wait. */
void dwc2_host_start_control(MediusHostBusPrefix *bus,unsigned int channel,
    MediusHostUrb *urb,unsigned char *setup,unsigned char *buffer,unsigned int length)
{
    const volatile MediusHostBusPrefix *live_bus = bus;
    const volatile MediusHostUrb *live_urb = urb;
    unsigned int controller = live_bus->controller_id;
    volatile MediusHostChannel *state = (volatile void *)(0x3fca7c80U+controller*668U+channel*36U);
    const volatile MediusHostEndpointDescriptor *endpoint = (const volatile void *)live_urb->endpoint;
    unsigned int number = endpoint->address & 15U;
    unsigned int split = state->split_enabled;
    unsigned int stage = state->control_state;
    unsigned int max_packet,packets,bytes,pid,direction;
    unsigned char *dma;
    const volatile MediusHostHubPortPrefix *port;
    if (stage == 0) {
        unsigned int high = endpoint->max_packet[1];
        unsigned int low = endpoint->max_packet[0];
        max_packet = ((high << 8) | low) & 2047U;
        unsigned int numerator = max_packet+7U;
        unsigned int quotient;
        __asm__ volatile ("quou %0,%1,%2" : "=a"(quotient)
            : "a"(numerator),"a"(max_packet) : "memory");
        packets = quotient < 1023 ? quotient : 1023;
        port = live_urb->hubport;
        state->initial_packets = (unsigned short)packets;
        state->programmed_bytes = 8;
        bytes = 8;
        pid = 3;
        direction = number;
        dma = setup;
    } else if (stage == 1 || stage == 2) {
        unsigned int low,high;
        if (split != 0) {
            high = endpoint->max_packet[1];
            low = endpoint->max_packet[0];
            unsigned int toggle = live_urb->toggle;
            max_packet = ((high << 8) | low) & 2047U;
            if (length > max_packet)
                length = max_packet;
            pid = toggle != 0 ? 2 : 0;
        } else {
            low = endpoint->max_packet[0];
            high = endpoint->max_packet[1];
            max_packet = ((high << 8) | low) & 2047U;
            pid = 2;
        }
        packets = 1;
        if (length != 0) {
            unsigned int numerator = max_packet-1U+length;
            unsigned int quotient;
            __asm__ volatile ("quou %0,%1,%2" : "=a"(quotient)
                : "a"(numerator),"a"(max_packet) : "memory");
            packets = (unsigned short)quotient;
            if (packets > 1023)
                packets = 1023;
        }
        bytes = stage == 1 ? packets*max_packet : length;
        port = live_urb->hubport;
        state->programmed_bytes = bytes;
        state->initial_packets = (unsigned short)packets;
        direction = number | (stage == 1 ? 128U : 0U);
        dma = buffer;
    } else if (stage == 3) {
        unsigned int high = endpoint->max_packet[1];
        unsigned int low = endpoint->max_packet[0];
        port = live_urb->hubport;
        max_packet = ((high << 8) | low) & 2047U;
        state->programmed_bytes = max_packet;
        state->initial_packets = 1;
        bytes = max_packet;
        packets = 1;
        pid = 2;
        direction = number | 128U;
        dma = MEDIUS_HOST_CONTROL_STATUS_BUFFER;
    } else if (stage == 4) {
        port = live_urb->hubport;
        unsigned int high = endpoint->max_packet[1];
        unsigned int low = endpoint->max_packet[0];
        state->initial_packets = 1;
        state->programmed_bytes = 0;
        max_packet = ((high << 8) | low) & 2047U;
        bytes = 0;
        packets = 1;
        pid = 2;
        direction = number;
        dma = 0;
    } else {
        return;
    }
    unsigned int speed = port->speed;
    unsigned int device = port->device_address;
    dwc2_host_channel_configure(bus,channel,device,direction,0,max_packet,1,(unsigned char)speed);
    if (stage == 3 && bytes > 256) {
        bytes = 256;
        state->programmed_bytes = 256;
    }
    unsigned int base = live_bus->register_base;
    volatile MediusDwc2HostChannelRegisters *registers = (volatile void *)(base+channel*32U+0x500U);
    if (stage == 3) {
        memw();
        MEDIUS_HOST_CONTROL_STATUS_ACTUAL = 0;
    }
    memw();
    registers->transfer_size = (pid << 29) | (packets << 19) | (bytes & 0x7ffffU);
    memw();
    registers->dma_address = (unsigned int)(uintptr_t)dma;
    dwc2_control_enable_channel(bus,channel);
}

/* Native entry: 0x4201f814. */
/* Original function-byte SHA-256:
 * 4e8250087eda4a9bc998fbf88fe17384779195bc079b49bf492e3a33d23a084d. */
/* Cache register base, fence/sample GUSBCFG, then fence/sample HPRT BEFORE
 * selecting a clock. Without PHYSELbit6, masked8058 equal8 selects30,8008
 * selects48, all others60. With PHYSEL, cache controller_id and the first
 * hardware-capability word: type3 selects48 directly. Other types select48
 * for type2/PHYIF16clear, otherwise60, then a fresh capability read using the
 * SAME cached controller can override to48 for type1. Do not collapse these
 * independent observations into one generic PHY-type expression.
 * Cached root speed0 returns125*clock-1. Other speeds fence/read HCFG: LOW2==2
 * returns5999, otherwise1000*clock-1. No register writes, lock or validation. */
unsigned int dwc2_calc_frame_interval(MediusHostBusPrefix *bus)
{
    const volatile MediusHostBusPrefix *live_bus = bus;
    const volatile MediusDwc2HostRegisters *registers = (const volatile void *)live_bus->register_base;
    memw();
    unsigned int usb_configuration = registers->usb_configuration;
    memw();
    unsigned int port = registers->port;
    unsigned int clock;
    if ((usb_configuration & 64U) == 0) {
        unsigned int selection = usb_configuration & 0x8058U;
        clock = selection == 8 ? 30U : selection == 0x8008U ? 48U : 60U;
    } else {
        unsigned int controller = live_bus->controller_id;
        const volatile MediusDwc2HostContextPrefix *context = (const volatile void *)
            (0x3fca7c24U+controller*668U);
        unsigned int first = context->hardware_capabilities;
        unsigned int type = (first >> 13) & 3U;
        if (type == 3) {
            clock = 48;
        } else {
            clock = (usb_configuration & 0x48U) == 0x40U && type == 2 ? 48U : 60U;
            unsigned int second = context->hardware_capabilities;
            if (((second >> 13) & 3U) == 1)
                clock = 48;
        }
    }
    if (((port >> 17) & 3U) == 0)
        return clock*125U-1U;
    memw();
    unsigned int host_configuration = registers->configuration;
    return (host_configuration & 3U) == 2 ? 5999U : clock*1000U-1U;
}

/* Native entry: 0x4201f8e8. */
/* Original function-byte SHA-256:
 * e5adc3bcef7c4c4d0e9d4c1115a3f044ec13139ee52f0d71e0706f9d69c4d1b5. */
/* Initialize a host controller: clear its 668-byte context, initialize the
 * PHY/IRQ, snapshot GSNPSID/GHWCFG1..4, pack capabilities, copy user parameters
 * and create per-channel semaphores. PHY/IRQ/semaphore errors are unchecked.
 * The controller id is refreshed after external calls, so context snapshots
 * need not refer to one controller; channel counts are not capped locally.
 *
 * Unsupported DMA architecture, excessive requested FIFO sum, unavailable
 * high-speed PHY or undersized hardware FIFO partitions enter native infinite
 * assertion loops. Zero UTMI width becomes8; zero total FIFO uses hardware.
 * Initial AHB-idle/core-reset timeouts are ignored. New cores use reset-done
 * bit29 and old cores wait for bit0 clear. Force host mode, then sleep10 until
 * status bit0 is set, refreshing register_base after each sleep without limit.
 *
 * Configure PHY/host speed, channels, FIFO partitions and flush TX then RX.
 * TX flush/idle timeouts are ignored; RX idle/flush timeout sets return-1.
 * Either result STILL programs DMA/burst7 and interrupt mask23000000, powers
 * the port if needed, sleeps200 and enables global interrupts at the freshly
 * read bus base. Success returns0. Poll limits are 200000 actual MMIO reads,
 * with a volatile increment/fence before each read and a final timeout test.
 * No NULL, bounds, resource-rollback or physical-duration guarantee is added. */
unsigned int usb_hc_init(MediusHostBusPrefix *bus)
{
    const volatile MediusHostBusPrefix *live_bus = bus;
    unsigned int controller = live_bus->controller_id;
    memset((void *)(0x3fca7c24U+controller*668U),0,668);
    usb_hc_low_level_init(bus);
    volatile MediusDwc2HostRegisters *registers = (volatile void *)live_bus->register_base;
    controller = live_bus->controller_id;
    memw();
    unsigned int core_id = registers->core_id;
    memw();
    unsigned int configuration1 = registers->hardware_configuration[0];
    memw();
    unsigned int configuration2 = registers->hardware_configuration[1];
    memw();
    unsigned int configuration3 = registers->hardware_configuration[2];
    memw();
    unsigned int configuration4 = registers->hardware_configuration[3];
    volatile MediusDwc2HostContextPrefix *state = (volatile void *)(0x3fca7c24U+controller*668U);
    unsigned int capabilities =
        (configuration2 & 31U) |
        (((configuration2 >> 19) & 1U) << 5) |
        ((((configuration2 >> 14) & 15U)+1U) << 6) |
        (((configuration2 >> 6) & 3U) << 11) |
        (((configuration2 >> 8) & 3U) << 13) |
        (((configuration2 >> 10) & 15U) << 15) |
        (((configuration2 >> 22) & 3U) << 20) |
        (((configuration2 >> 24) & 3U) << 23) |
        (((configuration2 >> 26) & 31U) << 25);
    unsigned int fifo_capabilities =
        (((1U << (((configuration3 >> 4) & 7U)+4U))-1U) & 65535U) |
        (((configuration3 >> 8) & 1U) << 11) |
        ((configuration3 >> 16) << 12) |
        (((configuration3 >> 15) & 1U) << 28) |
        (((configuration4 >> 25) & 1U) << 29);
    unsigned int features =
        ((configuration4 & 15U) << 4) | ((configuration4 >> 26) & 15U) |
        (((configuration4 >> 30) & 1U) << 8) |
        (((configuration4 >> 4) & 1U) << 9) |
        (((configuration4 >> 6) & 1U) << 10) |
        (((configuration4 >> 14) & 3U) << 11) |
        (((configuration4 >> 12) & 1U) << 13) |
        (((configuration4 >> 11) & 1U) << 14) |
        (((configuration4 >> 10) & 1U) << 15);
    unsigned int old_capabilities = state->hardware_capabilities;
    unsigned int old_fifo_capabilities = state->fifo_capabilities;
    unsigned int old_transfer_limit = state->transfer_limit_bits;
    state->core_id = core_id;
    state->hardware_capabilities = (old_capabilities & 0xc0000000U) | (capabilities & 0x3fffffffU);
    state->fifo_capabilities = (old_fifo_capabilities & 0xc0000000U) | fifo_capabilities;
    state->device_endpoint_directions = configuration1;
    state->transfer_limit_bits = (old_transfer_limit & 0xfc000000U) |
        (((1U << ((configuration3 & 15U)+11U))-1U) & 0x03ffffffU);
    state->hardware_features = (unsigned short)features;
    dwc2_get_user_params((unsigned int)registers,(void *)&state->parameters);

    controller = live_bus->controller_id;
    state = (volatile void *)(0x3fca7c24U+controller*668U);
    if (state->parameters.phy_utmi_width == 0)
        state->parameters.phy_utmi_width = 8;
    if (state->parameters.total_fifo_words == 0)
        state->parameters.total_fifo_words = (state->fifo_capabilities >> 12) & 65535U;
    if (((state->hardware_capabilities >> 6) & 31U) != 0) {
        unsigned int channel = 0;
        do {
            void *semaphore = usb_osal_sem_create(0);
            volatile MediusHostChannel *slot = (volatile void *)(0x3fca7c80U+controller*668U+channel*36U);
            slot->semaphore = semaphore;
            controller = live_bus->controller_id;
            ++channel;
            state = (volatile void *)(0x3fca7c24U+controller*668U);
        } while ((channel & 255U) < ((state->hardware_capabilities >> 6) & 31U));
    }
    state = (volatile void *)(0x3fca7c24U+controller*668U);
    if (((state->hardware_capabilities >> 3) & 3U) != 2)
        for (;;) __asm__ volatile ("" : : : "memory");
    unsigned int nonperiodic_words = state->nonperiodic_tx_fifo_words;
    unsigned int rx_words = state->rx_fifo_words;
    unsigned int periodic_words = state->periodic_tx_fifo_words;
    if (state->parameters.total_fifo_words < rx_words+nonperiodic_words+periodic_words)
        for (;;) __asm__ volatile ("" : : : "memory");

    registers = (volatile void *)live_bus->register_base;
    memw();
    unsigned int value = registers->ahb_configuration;
    unsigned int general_configuration = state->parameters.host_general_configuration;
    memw();
    registers->ahb_configuration = value & 0xfffffffeU;
    memw();
    registers->general_configuration = general_configuration;
    unsigned int phy_type = state->parameters.phy_type;
    if (phy_type == 0) {
        memw();
        value = registers->usb_configuration;
        memw();
        registers->usb_configuration = value | 0x40U;
    } else {
        if (((state->hardware_capabilities >> 11) & 3U) == 0)
            for (;;) __asm__ volatile ("" : : : "memory");
        memw();
        value = registers->usb_configuration;
        if (phy_type == 1) {
            value &= 0xffc5ffa7U;
            if (state->parameters.phy_utmi_width == 16)
                value |= 8U;
        } else if (phy_type == 2) {
            value = (value & 0xffc5ff37U) | 0x10U;
        } else {
            value &= 0xffc5ffbfU;
        }
        memw();
        registers->usb_configuration = value;
    }

    memw();
    volatile unsigned int reset_polls = 0;
    for (;;) {
        memw();
        unsigned int next = reset_polls+1U;
        memw();
        reset_polls = next;
        if (next > 200000U) goto force_host_mode;
        memw();
        if ((registers->reset_control & 0x80000000U) != 0) break;
    }
    memw();
    reset_polls = 0;
    memw();
    value = registers->reset_control;
    core_id = state->core_id;
    memw();
    registers->reset_control = value | 1U;
    if (core_id <= 0x4f544209U) {
        for (;;) {
            memw();
            unsigned int next = reset_polls+1U;
            memw();
            reset_polls = next;
            if (next > 200000U) break;
            memw();
            if ((registers->reset_control & 1U) == 0) break;
        }
    } else {
        for (;;) {
            memw();
            unsigned int next = reset_polls+1U;
            memw();
            reset_polls = next;
            if (next > 200000U) goto force_host_mode;
            memw();
            if ((registers->reset_control & 0x20000000U) != 0) break;
        }
        memw();
        value = registers->reset_control;
        memw();
        registers->reset_control = value & 0xfffffffeU;
        memw();
        value = registers->reset_control;
        memw();
        registers->reset_control = value | 0x20000000U;
    }

force_host_mode:
    memw();
    value = registers->usb_configuration;
    memw();
    registers->usb_configuration = value & 0x9fffffffU;
    memw();
    value = registers->usb_configuration;
    memw();
    registers->usb_configuration = value | 0x20000000U;
    memw();
    value = registers->interrupt_status;
    while ((value & 1U) == 0) {
        usb_osal_msleep(10);
        registers = (volatile void *)live_bus->register_base;
        memw();
        value = registers->interrupt_status;
    }
    controller = live_bus->controller_id;
    state = (volatile void *)(0x3fca7c24U+controller*668U);
    memw();
    unsigned int available = registers->rx_fifo_size;
    rx_words = state->rx_fifo_words;
    if ((available & 65535U) < rx_words)
        for (;;) __asm__ volatile ("" : : : "memory");
    memw();
    available = registers->nonperiodic_tx_fifo_size;
    nonperiodic_words = state->nonperiodic_tx_fifo_words;
    if ((available >> 16) < nonperiodic_words)
        for (;;) __asm__ volatile ("" : : : "memory");
    memw();
    available = registers->periodic_tx_fifo_size;
    periodic_words = state->periodic_tx_fifo_words;
    if ((available >> 16) < periodic_words)
        for (;;) __asm__ volatile ("" : : : "memory");
    memw();
    value = registers->otg_control;
    unsigned int nonperiodic_fifo = *(const volatile unsigned int *)&state->rx_fifo_words;
    memw();
    registers->otg_control = value & 0xffffffbfU;
    memw();
    value = registers->otg_control;
    memw();
    registers->otg_control = value & 0xffffff7fU;
    memw();
    value = registers->usb_configuration;
    memw();
    registers->usb_configuration = value | 7U;
    memw();
    registers->clock_control = 0;
    memw();
    value = registers->configuration;
    memw();
    registers->configuration = value & 0xfffffffbU;
    memw();
    value = registers->configuration;
    memw();
    registers->configuration = value & 0xfffffffcU;
    if (state->parameters.phy_type == 0) {
        ((volatile MediusHostBusPrefix *)bus)->root_speed = 2;
        memw();
        value = registers->configuration;
        memw();
        registers->configuration = value | 1U;
    } else {
        ((volatile MediusHostBusPrefix *)bus)->root_speed = 3;
        memw();
        value = registers->configuration;
        memw();
        registers->configuration = value;
    }
    if (state->core_id > 0x4f54292aU) {
        memw();
        value = registers->frame_interval;
        memw();
        registers->frame_interval = value | 0x10000U;
    }
    unsigned int channels = (state->hardware_capabilities >> 6) & 31U;
    for (unsigned int channel = 0; channel < channels; ++channel) {
        volatile MediusDwc2HostChannelRegisters *slot = (volatile void *)
            ((unsigned int)registers+0x500U+channel*32U);
        memw();
        slot->interrupt_status = 0xffffffffU;
        memw();
        slot->interrupt_mask = 0;
    }
    memw();
    registers->interrupt_mask = 0;
    memw();
    registers->interrupt_status = 0xffffffffU;
    memw();
    registers->rx_fifo_size = rx_words;
    memw();
    registers->nonperiodic_tx_fifo_size = nonperiodic_fifo;
    memw();
    registers->periodic_tx_fifo_size = (periodic_words << 16) | (rx_words+nonperiodic_words);

    memw();
    volatile unsigned int tx_polls = 0;
    for (;;) {
        memw();
        unsigned int next = tx_polls+1U;
        memw();
        tx_polls = next;
        if (next > 200000U) goto flush_receive;
        memw();
        if ((registers->reset_control & 0x80000000U) != 0) break;
    }
    memw();
    tx_polls = 0;
    memw();
    registers->reset_control = 0x420U;
    for (;;) {
        memw();
        unsigned int next = tx_polls+1U;
        memw();
        tx_polls = next;
        if (next > 200000U) break;
        memw();
        if ((registers->reset_control & 0x20U) == 0) break;
    }

flush_receive:
    memw();
    volatile unsigned int rx_polls = 0;
    unsigned int result;
    for (;;) {
        memw();
        unsigned int next = rx_polls+1U;
        memw();
        rx_polls = next;
        if (next > 200000U) { result = 0xffffffffU; goto enable_bus_mastering; }
        memw();
        if ((registers->reset_control & 0x80000000U) != 0) break;
    }
    memw();
    rx_polls = 0;
    memw();
    registers->reset_control = 0x10U;
    for (;;) {
        memw();
        unsigned int next = rx_polls+1U;
        memw();
        rx_polls = next;
        if (next > 200000U) { result = 0xffffffffU; goto enable_bus_mastering; }
        memw();
        value = registers->reset_control;
        result = value & 0x10U;
        if (result == 0) break;
    }

enable_bus_mastering:
    memw();
    value = registers->ahb_configuration;
    memw();
    registers->ahb_configuration = value & 0xffffffe1U;
    memw();
    value = registers->ahb_configuration;
    memw();
    registers->ahb_configuration = value | 0xeU;
    memw();
    value = registers->ahb_configuration;
    memw();
    registers->ahb_configuration = value | 0x20U;
    memw();
    value = registers->interrupt_mask;
    memw();
    registers->interrupt_mask = value | 0x23000000U;
    memw();
    volatile unsigned int port = 0;
    memw();
    value = registers->port;
    memw();
    port = value;
    memw();
    value = port;
    memw();
    port = value & 0xffffffd1U;
    memw();
    if ((port & 0x1000U) == 0) {
        memw();
        value = port;
        memw();
        registers->port = value | 0x1000U;
    }
    memw();
    value = port;
    usb_osal_msleep(200);
    registers = (volatile void *)live_bus->register_base;
    memw();
    value = registers->ahb_configuration;
    memw();
    registers->ahb_configuration = value | 1U;
    return result;
}

/* Native entry: 0x4202010c. */
/* Original function-byte SHA-256:
 * 8455e34761ccaeed40ec74fc1f62f4390c0aff3131cb29f22b28610285790f68. */
/* Under the driver lock, sample the selected bus's root port. Both bits0/2
 * must be set; otherwise unlock and return-4 without writes. On success,
 * acknowledge global bit31, OR it into the freshly read global mask, then
 * write port=(sample&FFFFFF11)|80. Unlock and return0. No connection retry,
 * bus bounds check, clock gating or suspension-completion wait. */
int medius_dwc2_host_suspend(unsigned char bus)
{
    unsigned int token = medius_usbh_critical_enter();
    volatile MediusDwc2HostRegisters *registers = (volatile void *)
        MEDIUS_HOST_BUSES[bus].register_base;
    memw();
    unsigned int port = registers->port;
    if ((port & 5U) != 5U) {
        medius_usbh_critical_exit(token);
        return -4;
    }
    memw();
    registers->interrupt_status = 0x80000000U;
    memw();
    unsigned int mask = registers->interrupt_mask;
    memw();
    registers->interrupt_mask = mask | 0x80000000U;
    memw();
    registers->port = (port & 0xffffff11U) | 0x80U;
    medius_usbh_critical_exit(token);
    return 0;
}

/* Native entry: 0x42020170. */
/* Original function-byte SHA-256:
 * 57df2bddaf6067a98ae8c4e51e2da0d9bfa749ca6afa8c60096989a6ed2431eb. */
/* If initially gated, freshly reread/clear clock bit0, then run a fenced,
 * volatile150-increment settle loop. This precedes the driver lock. After
 * locking, refresh the bus register base, clear global interrupt-mask bit31,
 * acknowledge status bit31, and write port=(freshread&FFFFFF11), optionally
 * OR40 for any nonzero signal byte. No port-enabled gate or completion wait.
 * Settle iterations are not a guaranteed physical duration. */
void medius_dwc2_host_resume_control(unsigned char bus,unsigned char signal_resume)
{
    volatile MediusDwc2HostRegisters *registers = (volatile void *)
        MEDIUS_HOST_BUSES[bus].register_base;
    memw();
    unsigned int clock = registers->clock_control;
    if ((clock & 1U) != 0) {
        memw();
        clock = registers->clock_control;
        memw();
        registers->clock_control = clock & 0xfffffffeU;
        memw();
        volatile unsigned int settle = 0;
        memw();
        while (settle <= 149) {
            memw();
            unsigned int next = settle+1U;
            memw();
            settle = next;
            memw();
        }
    }
    unsigned int token = medius_usbh_critical_enter();
    registers = (volatile void *)MEDIUS_HOST_BUSES[bus].register_base;
    memw();
    unsigned int mask = registers->interrupt_mask;
    memw();
    registers->interrupt_mask = mask & 0x7fffffffU;
    memw();
    registers->interrupt_status = 0x80000000U;
    memw();
    unsigned int port = registers->port & 0xffffff11U;
    if (signal_resume != 0)
        port |= 0x40U;
    memw();
    registers->port = port;
    medius_usbh_critical_exit(token);
}

/* Native entry: 0x42020214. */
/* Original function-byte SHA-256:
 * ca42bb8f02dd5197d9ab2ab056ddd0f1f826339bc8d461d96dec77c094974bbc. */
/* Read selected bus HPRT once after a fence. Return every raw bit. No lock,
 * bus validation, status acknowledgement or interpretation. */
unsigned int medius_dwc2_host_port_raw(unsigned char bus)
{
    const volatile MediusDwc2HostRegisters *registers = (const volatile void *)
        MEDIUS_HOST_BUSES[bus].register_base;
    memw();
    return registers->port;
}

/* Native entry: 0x42020668. */
/* Original function-byte SHA-256:
 * 7b46deb2832fbe6f39ee05a746590a994d693113fda02cc44c004fee5fe3ddba. */
/* Sample PCGCCTL before testing gated. Any nonzero gated writes the INITIAL
 * sample OR1. For gated0, do nothing when that sample is ungated; otherwise
 * freshly reread/clear bit0 and run a fenced volatile150-increment settle loop.
 * No driver lock or physical-duration/completion guarantee is provided. */
void medius_dwc2_host_clock_gate(MediusHostBusPrefix *bus,int gated)
{
    const volatile MediusHostBusPrefix *live_bus = bus;
    volatile MediusDwc2HostRegisters *registers = (volatile void *)live_bus->register_base;
    memw();
    unsigned int clock = registers->clock_control;
    if (gated != 0) {
        memw();
        registers->clock_control = clock | 1U;
    } else if ((clock & 1U) != 0) {
        memw();
        clock = registers->clock_control;
        memw();
        registers->clock_control = clock & 0xfffffffeU;
        memw();
        volatile unsigned int settle = 0;
        memw();
        while (settle <= 149) {
            memw();
            unsigned int next = settle+1U;
            memw();
            settle = next;
            memw();
        }
    }
}

/* Native entry: 0x42025618. */
/* Original function-byte SHA-256:
 * 17b08050acbddd2e6bcff4261348916b9522f933480e250e8e7eea64fff053db. */
/* Suppress frame-interval register updates by incrementing a shared depth.
 * Lock the SOF mask mux with infinite timeout, add modulo32, then unlock.
 * Lock status is ignored; no ISR-context query, saturation or error feedback.
 * Depth FFFFFFFF wraps to zero and therefore reopens the update gate. */
void medius_host_block_frame_interval_updates(void)
{
    xPortEnterCriticalTimeout(&MEDIUS_HOST_SOF_MASK_LOCK,-1);
    unsigned int depth = MEDIUS_HOST_SOF_MASK_GATE;
    MEDIUS_HOST_SOF_MASK_GATE = depth + 1U;
    vPortExitCritical(&MEDIUS_HOST_SOF_MASK_LOCK);
}

/* Native entry: 0x420255dc. */
/* Original function-byte SHA-256:
 * 1e98f05c20d0a5e19f10ad4cb1d9723858f6e727616e2ffab4472ba5ea43e5b9. */
/* Lazily create the frame-clock mutex, then release one positive gate depth.
 * An absent mutex is created outside the SOF mux and the result is published,
 * including NULL failure. Creation has no compare/exchange or retry loop.
 * Lock the SOF mux indefinitely, decrement only when signed32(depth)>0, then
 * unlock. Zero and high-bit-set depths remain unchanged; this is not an
 * unsigned saturating decrement. Ignore creation/lock outcomes. No local
 * frame register write or frame-clock timestamp reset occurs. */
void medius_host_resume_frame_interval_updates(void)
{
    if (MEDIUS_HOST_FRAME_CLOCK_MUTEX == NULL)
        MEDIUS_HOST_FRAME_CLOCK_MUTEX = xQueueCreateMutex();
    xPortEnterCriticalTimeout(&MEDIUS_HOST_SOF_MASK_LOCK,-1);
    unsigned int depth = MEDIUS_HOST_SOF_MASK_GATE;
    if ((int)depth > 0) MEDIUS_HOST_SOF_MASK_GATE = depth - 1U;
    vPortExitCritical(&MEDIUS_HOST_SOF_MASK_LOCK);
}

/* Native entry: 0x4202557c. */
/* Original function-byte SHA-256:
 * 218e2de5c8cde4ead67f76e152ac3f534817a4d357da9777f42ed2afab0a9931. */
/* Apply a DWC2 host frame-interval adjustment only when the update gate is open.
 * nominal_ticks/offset_ticks: Raw32 words; candidate=nominal-1+offset modulo32.
 * Take the SOF mux indefinitely, ignoring status. Nonzero gate skips all MMIO.
 * Otherwise fence/read HCFG: low2==2 selects6000 ticks, every other code48000.
 * Only an exact nominal match fence/reads HFIR; bit16 must be set. Compare the
 * FULL candidate against old low16 before narrowing. A difference fence/writes
 * old high16 plus candidate low16; no clamp, speed validation or overflow check.
 * Thus candidate+65536 can cause a write even when the low16 value is unchanged.
 * Always unlock. No ISR-context query, time sample or physical timing promise. */
void medius_host_apply_frame_interval_adjustment(unsigned int nominal_ticks,int offset_ticks)
{
    xPortEnterCriticalTimeout(&MEDIUS_HOST_SOF_MASK_LOCK,-1);
    if (MEDIUS_HOST_SOF_MASK_GATE == 0) {
        memw(); unsigned int configuration = MEDIUS_HOST_USB_REGISTERS->configuration;
        unsigned int nominal = (configuration & 3U) == 2 ? 6000U : 48000U;
        if (nominal == nominal_ticks) {
            memw(); unsigned int interval = MEDIUS_HOST_USB_REGISTERS->frame_interval;
            if ((interval & 0x10000U) != 0) {
                unsigned int candidate = nominal - 1U + (unsigned int)offset_ticks;
                if (candidate != (interval & 65535U)) {
                    memw();
                    MEDIUS_HOST_USB_REGISTERS->frame_interval =
                        (interval & 0xffff0000U) | (candidate & 65535U);
                }
            }
        }
    }
    vPortExitCritical(&MEDIUS_HOST_SOF_MASK_LOCK);
}

/* Native entry: 0x42020234. */
/* Original function-byte SHA-256:
 * 13c0843af1b3582a36c34fef2c73cbba750c741c2235b83aef8740a82e99a7ca. */
/* Gate a suspended bus's clock only when the native mask/port bits permit it.
 * bus_index: Low8 selects an unchecked828-byte bus slot. gated: Raw low8 value.
 * Zero ungates immediately without a local critical section or mask/port reads.
 * Nonzero enters the USB critical wrapper, then caches that bus's register base.
 * Fence/read GINTMSK bit31; only when set fence/read HPRT bit7. Both set gates
 * the clock through its separate helper. Always exit with the captured token.
 * No bus/connection validation or lifetime/physical-duration guarantee occurs. */
void medius_dwc2_host_gate_suspended_clock(unsigned int bus_index,unsigned char gated)
{
    MediusHostBusPrefix *bus = (void *)((unsigned int)MEDIUS_HOST_BUSES + (bus_index & 255U) * 828U);
    if (gated == 0) {
        medius_dwc2_host_clock_gate(bus,0);
        return;
    }
    unsigned int token = medius_usbh_critical_enter();
    volatile MediusDwc2HostRegisters *registers =
        (volatile void *)((volatile MediusHostBusPrefix *)bus)->register_base;
    memw(); unsigned int mask = registers->interrupt_mask;
    if ((mask & 0x80000000U) != 0) {
        memw();
        if ((registers->port & 128U) != 0) medius_dwc2_host_clock_gate(bus,1);
    }
    medius_usbh_critical_exit(token);
}

/* Native entry: 0x4201eea8. */
/* Original function-byte SHA-256:
 * aa5e28049701d98a72b6628a8cf5db786575d877df2680a3e9ad24eb4e70216d. */
/* Release the host controller's single global IRQ and PHY handles; bus is
 * ignored. Sample IRQ once, free it when non-NULL, then clear its slot even if
 * freeing failed. Only afterward sample/delete/clear PHY in the same way.
 * Return no status. No MEMW, lock, retry, bus lookup or rollback is supplied. */
void usb_hc_low_level_deinit(MediusHostBusPrefix *ignored_bus)
{
    (void)ignored_bus;
    InterruptHandle *interrupt=MEDIUS_HOST_USB_INTERRUPT;
    if (interrupt!=NULL) {
        (void)esp_intr_free(interrupt);
        MEDIUS_HOST_USB_INTERRUPT=NULL;
    }
    MediusUsbPhyContext *phy=MEDIUS_HOST_USB_PHY;
    if (phy!=NULL) {
        (void)usb_del_phy(phy);
        MEDIUS_HOST_USB_PHY=NULL;
    }
}

/* Native entry: 0x4201fef4. */
/* Original function-byte SHA-256:
 * 67031787b50595c2aca918c7cc8a715239a58df512ac2eab2074974276132086. */
/* Shut down one DWC2 host controller, always returning zero. Cache its MMIO
 * base once, clear global interrupt enable, and attempt all-TX then RX FIFO
 * flushes. Each idle/flush poll increments before reading hardware and stops at
 * iteration 200001. An idle timeout skips that command; all timeouts are ignored.
 * Sample the raw five-bit channel count once for halting (not capped at 16).
 * For each channel, cache enable before reading AHB DMA mode; halt when DMA is
 * off or that cached enable was set. Clear channel interrupt mask, OR halt and
 * enable into a fresh characteristics sample, poll enable clear with the same
 * iteration bound, then read/write channel interrupt status to acknowledge it.
 * Disable global interrupt mask, acknowledge host/global pending status, and
 * conditionally power off the cached MMIO port using native W1C filtering.
 * Request 200 ms sleep. Semaphore deletion rereads controller id and its raw
 * channel count after every deletion; it does not clear the stored handles.
 * Finally release global IRQ/PHY handles. No cancellation callback, URB cleanup,
 * NULL/index check, locking, error propagation or timeout/timing guarantee exists.
 */
int usb_hc_deinit(MediusHostBusPrefix *bus)
{
    const volatile MediusHostBusPrefix *live=bus;
    volatile MediusDwc2HostRegisters *registers=(volatile void *)live->register_base;
    memw();
    unsigned int ahb=registers->ahb_configuration;
    memw();
    registers->ahb_configuration=ahb&~1U;
    volatile unsigned int tx_polls;
    memw();
    tx_polls=0;
    for (;;) {
        memw();
        unsigned int next=tx_polls+1;
        memw();
        tx_polls=next;
        if (next>200000)
            break;
        memw();
        if (registers->reset_control&0x80000000U) {
            memw();
            tx_polls=0;
            memw();
            registers->reset_control=0x420;
            for (;;) {
                memw();
                next=tx_polls+1;
                memw();
                tx_polls=next;
                if (next>200000)
                    break;
                memw();
                if (!(registers->reset_control&0x20U))
                    break;
            }
            break;
        }
    }
    volatile unsigned int rx_polls;
    memw();
    rx_polls=0;
    for (;;) {
        memw();
        unsigned int next=rx_polls+1;
        memw();
        rx_polls=next;
        if (next>200000)
            break;
        memw();
        if (registers->reset_control&0x80000000U) {
            memw();
            rx_polls=0;
            memw();
            registers->reset_control=0x10;
            for (;;) {
                memw();
                next=rx_polls+1;
                memw();
                rx_polls=next;
                if (next>200000)
                    break;
                memw();
                if (!(registers->reset_control&0x10U))
                    break;
            }
            break;
        }
    }
    unsigned int controller=live->controller_id;
    unsigned int channels=(MEDIUS_HOST_HCD_CONTEXT(controller)->hardware_capabilities>>6)&31U;
    for (unsigned int channel=0;channel<channels;++channel) {
        volatile MediusDwc2HostChannelRegisters *hardware=(volatile void *)
            ((unsigned int)registers+0x500U+channel*32U);
        memw();
        unsigned int enabled=hardware->characteristics>>31;
        volatile unsigned int saved_enabled;
        memw();
        saved_enabled=enabled;
        volatile unsigned int polls;
        memw();
        polls=0;
        memw();
        unsigned int ahb_mode=registers->ahb_configuration;
        if ((ahb_mode&0x20U)!=0) {
            memw();
            if (saved_enabled==0)
                continue;
        }
        memw();
        hardware->interrupt_mask=0;
        memw();
        unsigned int characteristics=hardware->characteristics;
        volatile unsigned int halt;
        memw();
        halt=characteristics;
        memw();
        unsigned int halt_requested=halt|0x40000000U;
        memw();
        halt=halt_requested;
        memw();
        unsigned int enable_requested=halt|0x80000000U;
        memw();
        halt=enable_requested;
        memw();
        unsigned int halted=halt;
        memw();
        hardware->characteristics=halted;
        for (;;) {
            memw();
            unsigned int next=polls+1;
            memw();
            polls=next;
            if (next>200000)
                break;
            memw();
            if (!(hardware->characteristics&0x80000000U))
                break;
        }
        memw();
        unsigned int interrupts=hardware->interrupt_status;
        memw();
        hardware->interrupt_status=interrupts;
    }
    memw();
    registers->interrupt_mask=0;
    memw();
    registers->channel_interrupt_status=0xffffffffU;
    memw();
    registers->interrupt_status=0xffffffffU;
    volatile unsigned int power;
    memw();
    power=0;
    memw();
    unsigned int port=registers->port;
    memw();
    power=port;
    memw();
    unsigned int filtered_power=power&~0x2eU;
    memw();
    power=filtered_power;
    memw();
    (void)power;
    memw();
    if (power&0x1000U) {
        memw();
        unsigned int power_off=power&~0x1000U;
        memw();
        registers->port=power_off;
    }
    usb_osal_msleep(200);
    controller=live->controller_id;
    unsigned int channel=0;
    if (((MEDIUS_HOST_HCD_CONTEXT(controller)->hardware_capabilities>>6)&31U)!=0) {
        do {
            volatile MediusHostChannel *binding=MEDIUS_HOST_HCD_CHANNEL(controller,channel);
            void *semaphore=binding->semaphore;
            ++channel;
            (void)usb_osal_sem_delete(semaphore);
            controller=live->controller_id;
            channels=(MEDIUS_HOST_HCD_CONTEXT(controller)->hardware_capabilities>>6)&31U;
        } while ((unsigned char)channel<channels);
    }
    usb_hc_low_level_deinit(bus);
    return 0;
}
