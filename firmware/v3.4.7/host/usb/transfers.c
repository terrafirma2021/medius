/* Medius v3.4.7 host — usb/transfers.c.
 * Recovered C and native assembly, grouped for source navigation.
 * Original entry addresses, firmware-byte hashes and function comments follow.
 */

#include "../include/types.h"

/* Source reconstruction utilities for the identical completion tails in
 * native4037f1ec/4037f2c0, not another native function. Caller already sampled
 * timeout/channel in native order. Cache channel->urb AFTER lock entry but
 * BEFORE clearing bounce/retry. Trust that cross-link even when it names a
 * different URB. Synchronous completion gives the semaphore and retains links.
 * Callback/error/context are sampled after unlock/give; context precedes the
 * conditional actual-count sample. No ownership/lifetime validation is added. */
static void usbh_finish_urb(volatile MediusHostUrb *urb,unsigned int timeout,
    volatile MediusHostChannel *channel)
{
    if (timeout == 0) {
        unsigned int token = medius_usbh_critical_enter();
        MediusHostUrb *linked = channel->urb;
        channel->bounce_destination = 0;
        channel->retry_count = 0;
        if (linked != 0) {
            ((volatile MediusHostUrb *)linked)->channel = 0;
            channel->urb = 0;
        }
        channel->in_use = 0;
        medius_usbh_critical_exit(token);
    } else {
        (void)usb_osal_sem_give(channel->semaphore);
    }
    void (*callback)(void *,int) = urb->complete;
    if (callback != 0) {
        int result = urb->error;
        void *context = urb->context;
        if (result >= 0)
            result = (int)urb->actual;
        callback(context,result);
    }
}


/* Native entry: 0x4037f198. */
/* Original function-byte SHA-256:
 * 8291d4a8704a4848cd6226d458e69dd2486b920631d0ea216b1797a505831ce3. */
/* Rearm remaining input at wrapping32(buffer+actual), reading actual first.
 * Aligned destinations go directly to start_noncontrol, including MPS0; no
 * bounce pointer is cleared on this path. Unaligned destinations read MPS
 * HIGH then LOW once. MPS0 returns0 before reading remaining. Otherwise require
 * unsigned32((remaining-1+MPS) - ((remaining-1+MPS)%MPS))<=64. This arithmetic
 * intentionally wraps and can accept an enormous remaining value as size0.
 * Save bounce_destination and substitute bounce_base+FULL32(channel)*64.
 * Return1 after start_noncontrol,0 on either rejection, without local locking,
 * buffer-capacity validation or overflow repair. */
int medius_usbh_rearm_in_with_alignment(MediusHostBusPrefix *bus,unsigned int channel,
    MediusHostChannel *state,MediusHostUrb *urb)
{
    const volatile MediusHostUrb *live = urb;
    unsigned int actual = live->actual;
    unsigned int base = (unsigned int)(uintptr_t)live->buffer;
    unsigned char *destination = (unsigned char *)(uintptr_t)(base+actual);
    unsigned char *dma = destination;
    unsigned int length;
    if (((unsigned int)(uintptr_t)destination & 3U) == 0) {
        length = live->remaining;
    } else {
        const volatile MediusHostEndpointDescriptor *endpoint = (const volatile void *)live->endpoint;
        unsigned int high = endpoint->max_packet[1];
        unsigned int low = endpoint->max_packet[0];
        unsigned int max_packet = ((high << 8) | low) & 2047U;
        if (max_packet == 0)
            return 0;
        length = live->remaining;
        unsigned int rounded = length-1U+max_packet;
        rounded -= rounded % max_packet;
        if (rounded > 64)
            return 0;
        ((volatile MediusHostChannel *)state)->bounce_destination = destination;
        dma = (unsigned char *)(uintptr_t)((unsigned int)(uintptr_t)MEDIUS_HOST_IN_BOUNCE_BASE+channel*64U);
    }
    dwc2_host_start_noncontrol(bus,channel,urb,dma,length);
    return 1;
}

/* Native entry: 0x4037f1ec. */
/* Original function-byte SHA-256:
 * 0db6184671d61d357f6fa4db21bbdd9bd5bd993bdacecb9a1fd149cf044d2e26. */
/* Account/rearm an input segment. Fence/read HCTSIZ LOW19 BEFORE reading the
 * cached programmed length; received=programmed-residue wraps32. A saved bounce
 * destination causes a copy, even for received0, from bounce_base+LOW16(channel)
 * *64, then is cleared. Copy callbacks can change live bus/URB/state fields;
 * the original programmed/residue/received values remain cached.
 *
 * Read remaining after the copy. Only for received!=0, refresh bus base, cache
 * actual before the second fenced HCTSIZ sample, derive toggle from PID!=0,
 * wrap actual+=received and remaining-=received, and clear retry. Successful
 * rearm returns immediately. Failure rereads remaining: nonzero completes-12,
 * zero completes0. Cache timeout BEFORE storing error, then read channel and
 * release/wake/callback using the common native tail. No clamp to logical
 * remaining, DMA capacity or MPS; caller supplies live URB/channel pointers. */
void medius_usbh_account_and_rearm_in(MediusHostBusPrefix *bus,unsigned int channel,
    MediusHostChannel *state,MediusHostUrb *urb)
{
    const volatile MediusHostBusPrefix *live_bus = bus;
    volatile MediusHostChannel *live_state = state;
    volatile MediusHostUrb *live = urb;
    unsigned int base = live_bus->register_base;
    const volatile MediusDwc2HostChannelRegisters *registers = (const volatile void *)(base+channel*32U+0x500U);
    memw();
    unsigned int residue = registers->transfer_size & 0x7ffffU;
    unsigned int programmed = live_state->programmed_bytes;
    unsigned char *destination = live_state->bounce_destination;
    unsigned int received = programmed-residue;
    if (destination != 0) {
        unsigned char *source = (unsigned char *)(uintptr_t)
            ((unsigned int)(uintptr_t)MEDIUS_HOST_IN_BOUNCE_BASE+(channel & 65535U)*64U);
        medius_usbh_copy_received(destination,source,received);
        live_state->bounce_destination = 0;
    }
    unsigned int remaining = live->remaining;
    if (received != 0) {
        base = live_bus->register_base;
        unsigned int actual = live->actual;
        registers = (const volatile void *)(base+channel*32U+0x500U);
        memw();
        unsigned int pid = (registers->transfer_size >> 29) & 3U;
        remaining = remaining-programmed+residue;
        live->toggle = pid != 0;
        live->actual = actual+received;
        live->remaining = remaining;
        live_state->retry_count = 0;
    }
    int error = 0;
    if (remaining != 0) {
        if (medius_usbh_rearm_in_with_alignment(bus,channel,state,urb) != 0)
            return;
        if (live->remaining != 0)
            error = -12;
    }
    unsigned int timeout = live->timeout;
    live->error = error;
    volatile MediusHostChannel *linked_channel = live->channel;
    usbh_finish_urb(live,timeout,linked_channel);
}

/* Native entry: 0x4037f2c0. */
/* Original function-byte SHA-256:
 * 7475d801b960a1f96f125d62f58ff8df196630e76bca789035d7d197772765b1. */
/* Cache timeout, then channel, and perform native completion ownership/callback
 * handling. Timeout0 releases the linked channel under the driver lock; other
 * values signal its semaphore while retaining ownership. The supplied URB's
 * error is not changed here. Callback receives negative error or raw actual
 * bits through its int argument. See the reconstruction utility for exact
 * cross-link/cache order; NULL/lifetime consistency is the caller's duty. */
void medius_usbh_complete_urb(MediusHostUrb *urb)
{
    volatile MediusHostUrb *live = urb;
    unsigned int timeout = live->timeout;
    volatile MediusHostChannel *channel = live->channel;
    usbh_finish_urb(live,timeout,channel);
}

/* Native entry: 0x4201eff4. */
/* Original function-byte SHA-256:
 * 49ff3aaf8c7e0c201d092975272ca9aa92adda21030b72835a8816df87320449. */
/* Cancel a linked URB. NULL returns-2; other validation occurs under the driver
 * lock and is repeated after competing cancellations sleep1ms. That retry has
 * no bound. Claim cancelling, mask channel IRQs and, if initially enabled, OR
 * CHDIS into that cached HCCHAR sample. Unlock, refresh base/number, sample
 * frame BEFORE HCCHAR and poll while enabled. Poll ends on unsuitable port,
 *20001 port reads, three frame changes or a disabled channel; no poll error is
 * returned. Reenter the outer lock, refresh registers and clear cancelling.
 *
 * actual_out is optional and is NOT initialized here. OUT with nonzero saved
 * bytes and zero remaining packets writes the saved byte count, not URB actual.
 * Bulk/interrupt IN qualifies progress from one HCTSIZ sample; zero packets or
 * a non-MPS-multiple delta qualifies. Committed bytes use a SECOND HCTSIZ sample
 * and cached programmed count, added to cached URB actual with wrap32. Bounce
 * copy uses the cached channel number; afterward refresh endpoint/base/type,
 * clear bounce, publish actual_out, then reread number. Without copy, only the
 * number is refreshed after publication, preserving the cached base. No count
 * clamp or actual/remaining mutation is supplied by this accounting code.
 *
 * With actual_out and eligible endpoint type, separately sample packet count
 * and PID to update toggle only when packets advanced. Then clear mask/ack
 * status, cache timeout BEFORE error=-13, release async ownership under a
 * NESTED lock or give the synchronous semaphore. Fresh callback/error/context
 * are invoked while the OUTER lock is still held. Return0 after outer unlock.
 * Cross-links, endpoint pointers, callback lifetime and actual_out are trusted.
 */
int medius_usbh_cancel_urb(MediusHostUrb *urb,unsigned int *actual_out)
{
    if (urb == 0)
        return -2;
    volatile MediusHostUrb *live = urb;
    volatile MediusHostChannel *channel;
    const volatile MediusHostBusPrefix *bus;
    unsigned int token;
    for (;;) {
        token = medius_usbh_critical_enter();
        channel = live->channel;
        if (channel == 0) {
            medius_usbh_critical_exit(token);
            return -2;
        }
        const volatile MediusHostHubPortPrefix *port = live->hubport;
        if (port == 0 || (bus = port->bus_context) == 0) {
            medius_usbh_critical_exit(token);
            return -2;
        }
        if (channel->cancelling == 0)
            break;
        medius_usbh_critical_exit(token);
        usb_osal_msleep(1);
    }
    unsigned int base = bus->register_base;
    unsigned int number = channel->number;
    volatile MediusDwc2HostChannelRegisters *registers = (volatile void *)(base+0x500U+number*32U);
    channel->cancelling = 1;
    memw();
    registers->interrupt_mask = 0;
    memw();
    unsigned int characteristics = registers->characteristics;
    if ((characteristics & 0x80000000U) != 0) {
        memw();
        registers->characteristics = characteristics | 0x40000000U;
    }
    medius_usbh_critical_exit(token);
    base = bus->register_base;
    number = channel->number;
    registers = (volatile void *)(base+0x500U+number*32U);
    const volatile MediusDwc2HostRegisters *global = (const volatile void *)base;
    memw();
    unsigned int previous_frame = global->frame_number & 65535U;
    memw();
    characteristics = registers->characteristics;
    if ((characteristics & 0x80000000U) != 0) {
        unsigned int budget = 20001,changes = 0;
        for (;;) {
            memw();
            unsigned int port = global->port;
            --budget;
            if ((port & 0x84U) != 4 || budget == 0)
                break;
            memw();
            unsigned int frame = global->frame_number & 65535U;
            if (frame != previous_frame && ++changes >= 3)
                break;
            memw();
            characteristics = registers->characteristics;
            previous_frame = frame;
            if ((characteristics & 0x80000000U) == 0)
                break;
        }
    }
    unsigned int outer_token = medius_usbh_critical_enter();
    unsigned int cached_base = bus->register_base;
    number = channel->number;
    unsigned int channel_offset = number*32U;
    channel->cancelling = 0;
    registers = (volatile void *)(cached_base+0x500U+channel_offset);
    if (actual_out != 0) {
        const volatile MediusHostEndpointDescriptor *endpoint = (const volatile void *)live->endpoint;
        unsigned int address = endpoint->address;
        unsigned int attributes = endpoint->attributes;
        unsigned int toggle_allowed = (attributes & 3U) != 0;
        if ((address & 128U) == 0) {
            unsigned int programmed = channel->programmed_bytes;
            if (programmed != 0) {
                memw();
                unsigned int packets = (registers->transfer_size >> 19) & 1023U;
                if (packets == 0)
                    *actual_out = programmed;
            }
        } else if ((attributes & 2U) != 0) {
            memw();
            unsigned int first_size = registers->transfer_size;
            unsigned int programmed = channel->programmed_bytes;
            unsigned int residue = first_size & 0x7ffffU;
            unsigned int eligible = 0;
            if (programmed != residue) {
                if (((first_size >> 19) & 1023U) == 0) {
                    eligible = 1;
                } else {
                    unsigned int high = endpoint->max_packet[1];
                    unsigned int low = endpoint->max_packet[0];
                    unsigned int max_packet = ((high << 8) | low) & 2047U;
                    eligible = max_packet != 0 && (programmed-residue)%max_packet != 0;
                }
            }
            if (eligible != 0) {
                memw();
                unsigned int committed_size = registers->transfer_size;
                unsigned char *destination = channel->bounce_destination;
                unsigned int actual = live->actual;
                unsigned int received = programmed-(committed_size & 0x7ffffU);
                if (destination != 0) {
                    unsigned char *source = (unsigned char *)(uintptr_t)
                        ((unsigned int)(uintptr_t)MEDIUS_HOST_IN_BOUNCE_BASE+number*64U);
                    medius_usbh_copy_received(destination,source,received);
                    endpoint = (const volatile void *)live->endpoint;
                    channel->bounce_destination = 0;
                    unsigned int fresh_base = bus->register_base;
                    attributes = endpoint->attributes;
                    *actual_out = actual+received;
                    channel_offset = (unsigned int)channel->number*32U;
                    registers = (volatile void *)(fresh_base+0x500U+channel_offset);
                    toggle_allowed = (attributes & 3U) != 0;
                } else {
                    *actual_out = actual+received;
                    channel_offset = (unsigned int)channel->number*32U;
                    registers = (volatile void *)(cached_base+0x500U+channel_offset);
                }
            }
        }
        if (toggle_allowed != 0) {
            memw();
            unsigned int packets = (registers->transfer_size >> 19) & 1023U;
            unsigned int initial = channel->initial_packets;
            if (packets < initial) {
                memw();
                unsigned int pid = (registers->transfer_size >> 29) & 3U;
                live->toggle = pid != 0;
                registers = (volatile void *)(bus->register_base+0x500U+channel_offset);
            }
        }
    }
    memw();
    registers->interrupt_mask = 0;
    memw();
    registers->interrupt_status = 0xffffffffU;
    unsigned int timeout = live->timeout;
    live->error = -13;
    if (timeout == 0) {
        unsigned int nested_token = medius_usbh_critical_enter();
        MediusHostUrb *linked = channel->urb;
        channel->bounce_destination = 0;
        channel->retry_count = 0;
        if (linked != 0) {
            ((volatile MediusHostUrb *)linked)->channel = 0;
            channel->urb = 0;
        }
        channel->in_use = 0;
        medius_usbh_critical_exit(nested_token);
    } else {
        (void)usb_osal_sem_give(channel->semaphore);
    }
    void (*callback)(void *,int) = live->complete;
    if (callback != 0) {
        int result = live->error;
        void *context = live->context;
        callback(context,result);
    }
    medius_usbh_critical_exit(outer_token);
    return 0;
}

/* Native entry: 0x42020650. */
/* Original function-byte SHA-256:
 * 659f4eb3a5715096a4fd3e8168d4711b65bf769f4d8c2ce3d0a317a51167743d. */
/* Store actual_out0 BEFORE delegated cancellation, even for an invalid URB.
 * Return its signed status unchanged. actual_out must be writable/non-NULL;
 * output remains0 if cancellation never replaces it. No count clamp. */
int medius_usbh_kill_urb_with_actual(MediusHostUrb *urb,unsigned int *actual_out)
{
    *actual_out = 0;
    return medius_usbh_cancel_urb(urb,actual_out);
}

/* Native entry: 0x420206c0. */
/* Original function-byte SHA-256:
 * f8741589bc4118f2fc4e7c45cfe9efaa21a827487e2461724a4d58e6b44f7e6d. */
/* Forward DMA copy, not memmove. Matching LOW2 alignments first byte-copy to
 * word alignment, then interleave word reads/stores in16-byte blocks, remaining
 * words and byte tails. Differing alignments read source words directly and
 * emit destination bytes: first three words of each16-byte block store offsets
 *1/2/3/0, fourth stores0/1/2/3; remaining words store0/1/2/3. Preserve this native
 * access order with volatile word/byte views. Overlap can propagate earlier
 * writes; it is not repaired. Source word alignment/readable span and writable
 * destination are caller requirements; no NULL, capacity or overlap checks.
 * Word loops after16-byte blocks see only the low four remaining length bits,
 * so their native16-bit loop bound does not truncate an additional large span. */
void medius_usbh_copy_received(unsigned char *destination,unsigned char *source,unsigned int length)
{
    volatile unsigned char *out = destination;
    const volatile unsigned char *in = source;
    if ((((unsigned int)(uintptr_t)out ^ (unsigned int)(uintptr_t)in) & 3U) == 0) {
        while (((unsigned int)(uintptr_t)out & 3U) != 0) {
            if (length == 0)
                return;
            unsigned int byte = *in++;
            *out++ = (unsigned char)byte;
            --length;
        }
        while (length >= 16) {
            for (unsigned int word = 0; word < 4; ++word) {
                unsigned int value = *(const volatile unsigned int *)(in+word*4U);
                *(volatile unsigned int *)(out+word*4U) = value;
            }
            in += 16;
            out += 16;
            length -= 16;
        }
        while (length >= 4) {
            unsigned int value = *(const volatile unsigned int *)in;
            in += 4;
            *(volatile unsigned int *)out = value;
            out += 4;
            length -= 4;
        }
    } else {
        while (length >= 16) {
            for (unsigned int word = 0; word < 4; ++word) {
                unsigned int value = *(const volatile unsigned int *)(in+word*4U);
                volatile unsigned char *bytes = out+word*4U;
                if (word != 3) {
                    bytes[1] = (unsigned char)(value >> 8);
                    bytes[2] = (unsigned char)(value >> 16);
                    bytes[3] = (unsigned char)(value >> 24);
                    bytes[0] = (unsigned char)value;
                } else {
                    bytes[0] = (unsigned char)value;
                    bytes[1] = (unsigned char)(value >> 8);
                    bytes[2] = (unsigned char)(value >> 16);
                    bytes[3] = (unsigned char)(value >> 24);
                }
            }
            in += 16;
            out += 16;
            length -= 16;
        }
        while (length >= 4) {
            unsigned int value = *(const volatile unsigned int *)in;
            in += 4;
            out[0] = (unsigned char)value;
            out[1] = (unsigned char)(value >> 8);
            out[2] = (unsigned char)(value >> 16);
            out[3] = (unsigned char)(value >> 24);
            out += 4;
            length -= 4;
        }
    }
    while (length != 0) {
        unsigned int byte = *in++;
        *out++ = (unsigned char)byte;
        --length;
    }
}

/* Native entry: 0x42026b58. */
/* Original function-byte SHA-256:
 * 7299b3f6dc9896e35f049c4fd1cc3f4b95f39f1feba0baee66b0540a8ea134f3. */
/*
 * Validate a direct USB transfer request: full32 length must exceed8; payload
 * holds endpoint BYTE, SETUP8, then optional OUT data. Read wLength HIGH,
 * endpoint, then wLength LOW as separate bytes. wLength0..504 accepted; larger
 * values fail. Error response is {endpoint,fc}, endpoint0 for length<9.
 * Zero2068-byte work, store low16(sequence | response_opcode<<8) as ONE HALFWORD
 * (full sequence can contaminate response byte), reread endpoint into kind,
 * and copy8 SETUP bytes. For OUT direction with wLength!=0 require SIGNED32
 * length>wLength+8, copy that many bytes from payload+9 and set OUT length.
 * IN and zero-length requests ignore trailing bytes. No payload NULL guard,
 * endpoint admission, direction normalization or imperfect-clone gate here.
 * Nonzero control enqueue result returns; otherwise send the2-byte error with
 * low8 response opcode/sequence and discard link result. No USB completion wait.
 */
void medius_host_transfer_enqueue(unsigned int sequence,const unsigned char *payload,
    unsigned int length,unsigned int response_opcode)
{
    union { unsigned short word; unsigned char bytes[2]; } failure = {0xfc00};
    if (length > 8) {
        const volatile unsigned char *header = payload;
        unsigned int high = header[8];
        unsigned char endpoint = header[0];
        unsigned int low = header[7];
        failure.bytes[0] = endpoint;
        unsigned int requested = low | (high << 8);
        if (requested <= 504) {
            MediusControlWork work;
            memset(&work,0,sizeof(work));
            unsigned char current_endpoint = header[0];
            work.sequence_response = (unsigned short)(sequence | (response_opcode << 8));
            work.kind = current_endpoint;
            memcpy(work.setup,payload + 1,8);
            if ((header[1] & 0x80U) == 0 && requested != 0) {
                if ((int)length <= (int)(requested + 8U)) goto send_failure;
                memcpy(work.data,payload + 9,requested);
                work.out_length = (unsigned short)requested;
            }
            if (medius_control_work_enqueue(&work) != 0) return;
        }
    }
send_failure:
    (void)link_send_wait100((unsigned char)response_opcode,
        (unsigned char)sequence,&failure,2);
}

/* Native entry: 0x4202e7b4. */
/* Original function-byte SHA-256:
 * 69ed151a12c3f5eb8cfbf9958e67f7fbd389453a04d2154f2ebf11d144721660. */
/*
 * Narrow sequence to8 and length to16 bits, borrow endpoint/SETUP/data payload,
 * and delegate direct USB transfer admission with response opcode32. No local
 * validation, copy or result; the common helper reports admission errors and
 * the control worker performs USB I/O. Selected by incoming link opcode31.
 */
void medius_host_transfer_ep0_enqueue(unsigned char sequence,const unsigned char *payload,
    unsigned short length)
{
    medius_host_transfer_enqueue(sequence,payload,length,0x32);
}

/* Native entry: 0x4202e7c8. */
/* Original function-byte SHA-256:
 * e394d7c679906798a8179b2e4ed072e9c92cd39eb29073f444d1bf1ce7e17941. */
/*
 * Narrow sequence to8 and length to16 bits, borrow endpoint/SETUP/data payload,
 * and delegate direct USB transfer admission with response opcode34. No local
 * validation, copy or result. Despite this analyst name, the wrapper does not
 * require a nonzero endpoint; selected by incoming link opcode33.
 */
void medius_host_transfer_nonzero_enqueue(unsigned char sequence,const unsigned char *payload,
    unsigned short length)
{
    medius_host_transfer_enqueue(sequence,payload,length,0x34);
}

/* Native entry: 0x4202eb5c. */
/* Original function-byte SHA-256:
 * 5e4f2b25d455faf44e4ba4f25834887159da870aa0e82c673d7059d4646bc9e3. */
/*
 * Queue an HID class/interface INPUT GET_REPORT: low8 sequence/interface/report
 * id and low16 requested length. Only lengths1..504 are admitted. Zero a2068-
 * byte control record; response_type17, setup={a1,01,report_id,01,interface,00,
 * length_lo,length_hi}. Other fields, including OUT length/generation, start0.
 * Submit to the shared control-work helper. Any nonzero result returns without
 * replying here. Invalid length or zero enqueue result sends one byteff using
 * link type17 and the supplied sequence; ignore transport admission result.
 * No device/interface/report validation, local lock, timeout or transfer wait;
 * the control worker performs USB I/O later. No generic GET_REPORT type selector.
 */
void medius_hid_get_report_enqueue(unsigned char sequence,unsigned char interface_number,
    unsigned char report_id,unsigned short requested_length)
{
    unsigned char failure = 0xff;
    if ((unsigned short)(requested_length - 1U) <= 503) {
        MediusControlWork work;
        memset(&work,0,sizeof(work));
        work.response_type = 0x17;
        work.setup[1] = 1;
        work.setup[3] = 1;
        work.sequence = sequence;
        work.setup[0] = 0xa1;
        work.setup[2] = report_id;
        work.setup[4] = interface_number;
        work.setup[5] = 0;
        work.setup[6] = (unsigned char)requested_length;
        work.setup[7] = (unsigned char)(requested_length >> 8);
        if (medius_control_work_enqueue(&work) != 0) return;
    }
    (void)link_send_wait100(0x17,sequence,&failure,1);
}
