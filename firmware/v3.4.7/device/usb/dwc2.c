/* Medius v3.4.7 device — usb/dwc2.c.
 * Recovered C and native assembly, grouped for source navigation.
 * Original entry addresses, firmware-byte hashes and function comments follow.
 */

#include "../include/types.h"

/* DWC2 reconstruction utilities: inlined native paths, not extra entries.
 * Queue callers supply the original count sample and independently selected
 * count/entry addresses; one native caller truncates only the entry bus index.
 */
static __attribute__((always_inline)) inline int dwc2_remove_queue_first(
    volatile unsigned char *entries,volatile unsigned char *count_slot,
    unsigned int count,unsigned int endpoint)
{
    for (unsigned int index = 0; index < count; ++index) {
        unsigned char current = *(const volatile unsigned char *)((unsigned int)entries + index);
        if (current == endpoint) {
            unsigned char reduced = (unsigned char)(count - 1U);
            *count_slot = reduced;
            memmove((void *)((unsigned int)entries + index),
                    (const void *)((unsigned int)entries + index + 1U),
                    (unsigned int)reduced - index);
            return 1;
        }
    }
    return 0;
}

/* Poll limits count increments, not elapsed time. Both timeout exits leave
 * the caller to continue its native cleanup/start path without an error.
 * Volatile counter accesses retain the original stack read/store profile.
 */
static __attribute__((always_inline)) inline void dwc2_flush_selected_fifo(
    volatile MediusDwc2CoreRegisters *registers,unsigned int fifo,
    volatile unsigned int *polls)
{
    memw();
    *polls = 0;
    for (;;) {
        memw();
        unsigned int attempts = *polls + 1U;
        memw();
        *polls = attempts;
        if (attempts > 200000U) return;
        memw();
        if ((registers->reset_control & 0x80000000U) != 0) break;
    }
    memw();
    *polls = 0;
    memw();
    registers->reset_control = (fifo << 6) | 0x20U;
    for (;;) {
        memw();
        unsigned int attempts = *polls + 1U;
        memw();
        *polls = attempts;
        if (attempts > 200000U) return;
        memw();
        if ((registers->reset_control & 0x20U) == 0) return;
    }
}

/* Native entry: 0x4037f124. */
/* Original function-byte SHA-256:
 * a467cecf46c908e47e3e7bcbcaeda610beb0b27f4e553e69452c1e1c312ddbda. */
/*
 * Reads the context's FIFO-count low nibble once. Returns preferred unchanged
 * if it is <= count and its allocation bit is clear, including preferred 0.
 * Otherwise returns 0 for count zero, or scans indices 1..count using ONE
 * fresh allocation BYTE sample. Does not reserve a bit or reload it per slot.
 * The allocation bitmap has only eight bits, so indices >= 8 test clear.
 * Full 32-bit bus selects wrapping 0x3e4 context and BYTE bitmap offsets.
 * No bounds check, MEMW or lock. Zero is also the no-FIFO sentinel.
 */
unsigned int medius_dwc2_find_free_fifo(unsigned int bus,unsigned int preferred)
{
    const volatile MediusDwc2DeviceContext *context =
        (const volatile MediusDwc2DeviceContext *)(MEDIUS_DWC2_CONTEXT_BASE + bus * 0x3e4U);
    unsigned int count = context->device_capabilities & 15U;
    if (preferred <= count) {
        unsigned int allocated = MEDIUS_DWC2_ALLOCATED[bus];
        if ((allocated & (1U << (preferred & 31U))) == 0) return preferred;
    }
    if (count == 0) return 0;
    unsigned int allocated = MEDIUS_DWC2_ALLOCATED[bus];
    for (unsigned int fifo = 1; fifo <= count; ++fifo)
        if ((allocated & (1U << (fifo & 31U))) == 0) return fifo;
    return 0;
}

/* Native entry: 0x4037f174. */
/* Original function-byte SHA-256:
 * 491e67f23e5c876a31966dffac358785e99c0a4281f5a3d805d3480cdb7e0b85. */
/*
 * Caches the priority-mask HALF once and returns 0 unless the requested bit
 * (endpoint modulo 32) is set. Uses the context's cached IN-endpoint count
 * from capability bits 15..18, then scans endpoints 1..count. Counts other
 * marked endpoints only when their assigned-FIFO BYTE is nonzero.
 * Returns (occupied_other+1) < FIFO-count low nibble, retaining the strict
 * inequality. Full endpoint is used for exclusion, not its masked bit index.
 * Full bus address arithmetic wraps; no range check, reservation, MEMW or lock.
 */
int medius_dwc2_fifo_priority_eligible(unsigned int bus,unsigned int endpoint)
{
    unsigned int priority_mask = MEDIUS_DWC2_PRIORITY_MASKS[bus];
    if (((priority_mask >> (endpoint & 31U)) & 1U) == 0) return 0;
    const volatile MediusDwc2DeviceContext *context =
        (const volatile MediusDwc2DeviceContext *)(MEDIUS_DWC2_CONTEXT_BASE + bus * 0x3e4U);
    unsigned int endpoint_count = (context->core_capabilities >> 15) & 15U;
    unsigned int occupied_other = 0;
    for (unsigned int index = 1; index <= endpoint_count; ++index) {
        if (index != endpoint && (priority_mask & (1U << index)) != 0) {
            const volatile MediusDwc2Endpoint *transfer =
                (const volatile MediusDwc2Endpoint *)((unsigned int)context + 0x64U + index * 28U);
            if (transfer->fifo_index != 0) ++occupied_other;
        }
    }
    return occupied_other + 1U < (context->device_capabilities & 15U);
}

/* Native entry: 0x4037f200. */
/* Original function-byte SHA-256:
 * 5011f4ec2b6c18758b48eaa6d2d1bc14a0f8645e2c4021617c89411080403246. */
/*
 * Searches ready entries, then token-wait entries, returning exactly 1 on the
 * first BYTE equal to the full 32-bit endpoint argument, otherwise 0.
 * Each queue's count BYTE is sampled once when reached; count is not clamped
 * to its 16-entry storage. Values > 16 read beyond the array. Full bus uses
 * native 17-byte queue stride and wrapping addresses. No MEMW, lock or edits.
 */
int medius_dwc2_endpoint_is_queued(unsigned int bus,unsigned int endpoint)
{
    const volatile MediusEndpointQueue *ready =
        (const volatile MediusEndpointQueue *)(MEDIUS_DWC2_READY_BASE + bus * 17U);
    unsigned int count = ready->count;
    for (unsigned int index = 0; index < count; ++index)
        if (*(const volatile unsigned char *)((unsigned int)ready + index) == endpoint) return 1;
    const volatile MediusEndpointQueue *waiting =
        (const volatile MediusEndpointQueue *)(MEDIUS_DWC2_TOKEN_WAIT_BASE + bus * 17U);
    count = waiting->count;
    for (unsigned int index = 0; index < count; ++index)
        if (*(const volatile unsigned char *)((unsigned int)waiting + index) == endpoint) return 1;
    return 0;
}

/* Native entry: 0x4037f24c. */
/* Original function-byte SHA-256:
 * 0cc49259d4a3b97b5569d19cf4ca447bfcc575d0e7e20c8c324ea07fb996e2ea. */
/*
 * Removes the first BYTE equal to full endpoint, publishing count-1 before
 * memmove of the suffix and rereading count afterwards. Other duplicates
 * remain. A resulting count > 15 rejects insertion; a full queue can still
 * move an existing match. Corrupt counts are scanned before this size gate.
 *
 * at_front != 0 moves count bytes right, rereads count, stores endpoint's low
 * BYTE at the head, then stores reread count+1. Tail insertion stores count+1
 * BEFORE storing endpoint at the cached old count. Full endpoint > 255 never
 * matches an existing BYTE but is truncated when inserted. No lock or MEMW;
 * queue requires valid storage and serialization by its caller.
 */
void medius_dwc2_endpoint_queue_insert(unsigned char *queue,unsigned int endpoint,int at_front)
{
    volatile unsigned char *count_slot = (volatile unsigned char *)queue + 16;
    unsigned int count = *count_slot;
    if (count != 0) {
        for (unsigned int index = 0; index < count; ++index) {
            unsigned char current = *(const volatile unsigned char *)((unsigned int)queue + index);
            if (current == endpoint) {
                unsigned char reduced = (unsigned char)(count - 1U);
                *count_slot = reduced;
                memmove((void *)((unsigned int)queue + index),
                        (const void *)((unsigned int)queue + index + 1U),
                        (unsigned int)reduced - index);
                count = *count_slot;
                break;
            }
        }
        if (count > 15U) return;
    }
    if (at_front != 0) {
        memmove(queue + 1,queue,count);
        unsigned char current_count = *count_slot;
        *(volatile unsigned char *)queue = (unsigned char)endpoint;
        *count_slot = (unsigned char)(current_count + 1U);
    } else {
        *count_slot = (unsigned char)(count + 1U);
        *(volatile unsigned char *)((unsigned int)queue + count) = (unsigned char)endpoint;
    }
}

/* Native entry: 0x4037f2b0. */
/* Original function-byte SHA-256:
 * c8b011fa28b8efe368a5eab1dcea8486250626f42601ec3b86c4dcfe9e8fd968. */
/*
 * Caches the controller binding and writes DOEPTSIZ = 0x20080008 after MEMW:
 * setup-count 1, packet-count 1, transfer-size 8. Uses the full endpoint BYTE
 * as a 0x20-byte register index, without stripping direction or range checks.
 * No endpoint enable, buffer setup, wait or lock is performed here.
 */
void medius_dwc2_arm_setup_size(unsigned char bus,unsigned char endpoint)
{
    unsigned int controller = (unsigned int)MEDIUS_USBD_CONTROLLERS[bus].registers;
    volatile MediusDwc2OutEndpointRegisters *registers =
        (volatile MediusDwc2OutEndpointRegisters *)(controller + 0xb00U + (unsigned int)endpoint * 32U);
    memw();
    registers->transfer_size = 0x20080008U;
}

/* Native entry: 0x4037f2d4. */
/* Original function-byte SHA-256:
 * 00e01fd59b8830e25a9970c8bfdb99d001af9c5c2c5481d9f4df911a89cf55d6. */
/*
 * Caches the selected controller and samples EP0 IN EPENA. When set, performs
 * separate SNAK and EPDIS read/modify/writes, polls EPENA with a volatile
 * counter (up to 50,001 increments), then acknowledges disable even on timeout.
 * Polls AHB-idle with a second counter (up to 200,001 increments); only success
 * issues TX-FIFO0 flush 0x20 and polls its clear with the same limit. All paths
 * acknowledge transfer-complete. Thresholds are iteration counts, not time.
 *
 * Queries ISR context, enters the driver mux with -1, ignores its result,
 * reloads the controller binding and clears FIFO-empty bit 0. Queries ISR
 * context again, exits the mux, then clears EP0 requested/actual WORDs in RAM.
 * Retains native MEMW around local counter and MMIO accesses, fresh polling
 * reads and separate RMWs. No error return, bus check or queue/FIFO reclamation.
 */
void medius_dwc2_abort_ep0_in(unsigned char bus)
{
    volatile MediusDwc2CoreRegisters *registers = MEDIUS_USBD_CONTROLLERS[bus].registers;
    volatile Dwc2InEndpointRegisters *endpoint =
        (volatile Dwc2InEndpointRegisters *)((unsigned int)registers + 0x900U);
    volatile unsigned int disable_polls;
    volatile unsigned int reset_polls;
    memw();
    disable_polls = 0;
    memw();
    unsigned int control = endpoint->control;
    if ((control & 0x80000000U) != 0) {
        memw();
        control = endpoint->control;
        memw();
        endpoint->control = control | 0x08000000U;
        memw();
        control = endpoint->control;
        memw();
        endpoint->control = control | 0x40000000U;
        for (;;) {
            memw();
            unsigned int attempts = disable_polls + 1U;
            memw();
            disable_polls = attempts;
            if (attempts > 50000U) break;
            memw();
            if ((endpoint->control & 0x80000000U) == 0) break;
        }
        memw();
        endpoint->interrupt_status = 2;
    }
    memw();
    reset_polls = 0;
    for (;;) {
        memw();
        unsigned int attempts = reset_polls + 1U;
        memw();
        reset_polls = attempts;
        if (attempts > 200000U) goto acknowledge_transfer;
        memw();
        if ((registers->reset_control & 0x80000000U) != 0) break;
    }
    memw();
    reset_polls = 0;
    memw();
    registers->reset_control = 0x20;
    for (;;) {
        memw();
        unsigned int attempts = reset_polls + 1U;
        memw();
        reset_polls = attempts;
        if (attempts > 200000U) break;
        memw();
        if ((registers->reset_control & 0x20U) == 0) break;
    }
acknowledge_transfer:
    memw();
    endpoint->interrupt_status = 1;
    xPortInIsrContext();
    xPortEnterCriticalTimeout(MEDIUS_DWC2_DRIVER_LOCK,-1);
    registers = MEDIUS_USBD_CONTROLLERS[bus].registers;
    memw();
    unsigned int empty_mask = registers->device_in_fifo_empty_mask;
    memw();
    registers->device_in_fifo_empty_mask = empty_mask & ~1U;
    xPortInIsrContext();
    vPortExitCritical(MEDIUS_DWC2_DRIVER_LOCK);
    volatile MediusDwc2DeviceContext *context =
        (volatile MediusDwc2DeviceContext *)(MEDIUS_DWC2_CONTEXT_BASE + (unsigned int)bus * 0x3e4U);
    context->input_endpoints[0].requested = 0;
    context->input_endpoints[0].actual = 0;
}

/* Native entry: 0x4037f3d0. */
/* Original function-byte SHA-256:
 * d38b764d947199d7ab44b620d5027d9262084f403266a089c50111b049c9d8e0. */
/*
 * Writes length's low 16 bits to the endpoint FIFO aperture. For each full
 * four-byte chunk, reads a source WORD, executes MEMW and writes the FIFO
 * WORD; the controller base is cached once for this bulk loop. Source WORD
 * alignment is the caller's responsibility and is not repaired here.
 *
 * A remaining one byte is read alone. For two/three bytes, reads byte 1 then
 * byte 0, then byte 2 only for a three-byte tail. Assembles a zero-padded
 * little-endian WORD, reloads the controller binding and writes after MEMW.
 * Zero length reads no source/controller. Endpoint BYTE directly selects
 * base+0x1000+endpoint*0x1000; no direction/range/FIFO-space check or lock.
 */
void dwc2_ep_write(unsigned char bus,unsigned char endpoint,unsigned char *source,
                    unsigned short length)
{
    const volatile unsigned char *cursor = source;
    unsigned int words = (unsigned int)length >> 2;
    if (words != 0) {
        unsigned int controller = (unsigned int)MEDIUS_USBD_CONTROLLERS[bus].registers;
        volatile unsigned int *fifo = (volatile unsigned int *)(controller + 0x1000U +
                                                        (unsigned int)endpoint * 0x1000U);
        do {
            unsigned int word = *(const volatile unsigned int *)cursor;
            memw();
            *fifo = word;
            cursor += 4;
        } while (--words != 0);
    }
    unsigned int tail = length & 3U;
    if (tail != 0) {
        unsigned int word;
        if (tail == 1) word = cursor[0];
        else {
            unsigned int high = cursor[1];
            unsigned int low = cursor[0];
            word = (high << 8) | low;
            if (tail == 3) word |= (unsigned int)cursor[2] << 16;
        }
        unsigned int controller = (unsigned int)MEDIUS_USBD_CONTROLLERS[bus].registers;
        volatile unsigned int *fifo = (volatile unsigned int *)(controller + 0x1000U +
                                                        (unsigned int)endpoint * 0x1000U);
        memw();
        *fifo = word;
    }
}

/* Native entry: 0x4037f450. */
/*
 * Medius v3.4.7 — device application; 0x4037f450.
 *
 * Fills a device IN FIFO in packet chunks using a cached initial free-space threshold.
 *
 * Calls: dwc2_ep_write.
 *
 * Called by: USBD_IRQHandler, medius_dwc2_assign_fifo_and_start, usbd_ep_start_write.
 *
 * Original function-byte SHA-256:
 * de41293ae09fb85d14f2b1028c3f744dd0622d5d21e73f55cc66d1f2ab73e3ef.
 */

/*
 * bus: Configured bus with live transfer records/controller mapping; no bounds check.
 * endpoint: Raw IN endpoint index; callers must supply a valid hardware/software endpoint slot.
 * Returns: Nothing; advances transfer state and may clear the FIFO-empty interrupt mask bit.
 * Requirements/effects: Uses a 28-byte transfer record and 32-byte endpoint register block. Caches
 *   requested/actual counts and full 16-bit max packet, computes ceil(min(u32(requested-actual),
 *   max_packet)/4) once, and retains that original free-word threshold across iterations. Writes
 *   chunks through dwc2_ep_write, reloads actual before MEMW/FIFO status, then publishes the
 *   captured source pointer plus chunk and the observed actual plus chunk, before rereading
 *   requested. Repeats while the original threshold fits. Type 1 updates parity bits
 *   from DSTS and programs one multi-count before each chunk. Completion clears DIEPEMPMSK bit
 *   (endpoint & 15); an incomplete transfer retains it. No lock, timeout, DMA programming or
 *   transfer admission check occurs here. Buffer extent must cover the outstanding bytes, and the
 *   FIFO writer requires suitable alignment for full-word loads. Zero max packet can prevent
 *   forward progress. Volatile MMIO reads/writes and their MEMWs retain polling order.
 */

void dwc2_tx_fifo_empty_process(unsigned char bus,unsigned char endpoint)
{
    unsigned int endpoint_index = endpoint;
    volatile MediusDwc2Endpoint *transfer =
        (volatile MediusDwc2Endpoint *)(MEDIUS_DWC2_CONTEXT_BASE +
            (unsigned int)bus * 0x3e4U + 0x64U + endpoint_index * 28U);
    unsigned int requested_bytes = transfer->requested;
    unsigned int actual_bytes = transfer->actual;
    volatile MediusDwc2CoreRegisters *controller = MEDIUS_USBD_CONTROLLERS[bus].registers;
    unsigned int max_packet = transfer->max_packet;
    unsigned int initial_remaining = requested_bytes - actual_bytes;
    volatile Dwc2InEndpointRegisters *registers =
        (volatile Dwc2InEndpointRegisters *)((unsigned int)controller +
                                                0x900U + endpoint_index * 32U);
    memw();
    unsigned int fifo_free_words = registers->fifo_space & 0xffffU;
    unsigned int initial_packet = initial_remaining < max_packet ? initial_remaining : max_packet;
    unsigned int required_fifo_words = (initial_packet + 3U) >> 2;

    /* Keep this initial threshold even when the final packet will be smaller. */
    while (required_fifo_words <= fifo_free_words && actual_bytes < requested_bytes) {
        unsigned int remaining_bytes = requested_bytes - actual_bytes;
        unsigned int packet_bytes = remaining_bytes < max_packet ? remaining_bytes : max_packet;
        if (transfer->transfer_type == 1) {
            memw();
            unsigned int device_status = controller->device_status;
            unsigned int clear_parity = (device_status & 0x100U) == 0 ? 0x10000000U : 0x20000000U;
            unsigned int set_parity = (device_status & 0x100U) == 0 ? 0x20000000U : 0x10000000U;
            memw();
            unsigned int control = registers->control;
            memw();
            registers->control = control & ~clear_parity;
            memw();
            control = registers->control;
            memw();
            registers->control = control | set_parity;
            memw();
            unsigned int transfer_size = registers->transfer_size;
            memw();
            registers->transfer_size = transfer_size & 0x9fffffffU;
            memw();
            transfer_size = registers->transfer_size;
            memw();
            registers->transfer_size = transfer_size | 0x20000000U;
        }
        unsigned char *source = transfer->buffer;
        dwc2_ep_write(bus,endpoint,source,(unsigned short)packet_bytes);
        unsigned int observed_actual = transfer->actual;
        memw();
        fifo_free_words = registers->fifo_space & 0xffffU;
        actual_bytes = observed_actual + packet_bytes;
        transfer->buffer = source + packet_bytes;
        transfer->actual = actual_bytes;
        requested_bytes = transfer->requested;
    }
    if (actual_bytes >= requested_bytes) {
        memw();
        unsigned int empty_mask = controller->device_in_fifo_empty_mask;
        memw();
        controller->device_in_fifo_empty_mask = empty_mask & ~(1U << (endpoint_index & 15U));
    }
}

/* Native entry: 0x4037f5b4. */
/* Original function-byte SHA-256:
 * 7f5c6c33aca93943121732d9e81f8d939bdd2469c418f3fdc725956eda882754. */
/*
 * Marks allocation BYTE with 1<<(fifo modulo 32), stores low FIFO BYTE and
 * clears disable_pending BYTE in the selected IN transfer. Uses FULL bus,
 * endpoint and FIFO words for address/bit arithmetic: no bounds validation.
 * Rewrites DIEPCTL as (old & 0x3c3fffff) | (fifo<<22), without masking FIFO
 * to the TXFNUM field. Samples DSTS then DIEPTSIZ, stores low eight packet-
 * count bits and 11-bit frame, caches requested then actual, and enables
 * EPENA/CNAK with 0x84000000. Native MMIO MEMW boundaries are retained.
 *
 * Equal cached requested/actual ends processing. Otherwise interrupt type 3
 * primes the FIFO using low bus/endpoint bytes, then reloads actual before
 * requested and enables FIFO-empty only if actual < requested. Other types
 * enable it directly. Mask bit uses endpoint modulo 16 and cached controller
 * base. No allocation rollback, queue changes, lock or transfer-result check.
 */
void medius_dwc2_assign_fifo_and_start(unsigned int bus,unsigned int endpoint,unsigned int fifo)
{
    unsigned int allocated = MEDIUS_DWC2_ALLOCATED[bus];
    volatile MediusDwc2Endpoint *transfer =
        (volatile MediusDwc2Endpoint *)(MEDIUS_DWC2_CONTEXT_BASE + bus * 0x3e4U +
                                       0x64U + endpoint * 28U);
    MEDIUS_DWC2_ALLOCATED[bus] = (unsigned char)(allocated | (1U << (fifo & 31U)));
    transfer->fifo_index = (unsigned char)fifo;
    transfer->disable_pending = 0;
    volatile MediusDwc2CoreRegisters *registers =
        *(volatile MediusDwc2CoreRegisters * const volatile *)(0x3fcd85c8U + bus * 8U);
    volatile Dwc2InEndpointRegisters *endpoint_registers =
        (volatile Dwc2InEndpointRegisters *)((unsigned int)registers + 0x900U + endpoint * 32U);
    memw();
    unsigned int control = endpoint_registers->control;
    memw();
    endpoint_registers->control = (control & 0x3c3fffffU) | (fifo << 22);
    memw();
    unsigned int status = registers->device_status;
    memw();
    unsigned int size = endpoint_registers->transfer_size;
    transfer->last_packet_count = (unsigned char)(size >> 19);
    memw();
    control = endpoint_registers->control;
    transfer->last_progress_frame = (unsigned short)((status >> 8) & 0x7ffU);
    unsigned int requested = transfer->requested;
    unsigned int actual = transfer->actual;
    memw();
    endpoint_registers->control = control | 0x84000000U;
    if (requested == actual) return;
    if (transfer->transfer_type == 3) {
        dwc2_tx_fifo_empty_process((unsigned char)bus,(unsigned char)endpoint);
        actual = transfer->actual;
        requested = transfer->requested;
        if (actual >= requested) return;
    }
    memw();
    unsigned int empty_mask = registers->device_in_fifo_empty_mask;
    memw();
    registers->device_in_fifo_empty_mask = empty_mask | (1U << (endpoint & 15U));
}

/* Native entry: 0x4037f690. */
/* Original function-byte SHA-256:
 * 8fee86f147e1208071ec5a7a91c9b51152e365d389768f5cf2c2400d4a60f773. */
/*
 * Samples ready-count BYTE, then repeatedly samples the head endpoint and
 * asks for a FIFO using that preferred index. A zero result leaves the queue
 * unchanged and returns. Otherwise publishes cached count-1 modulo 256,
 * memmoves that many bytes left, starts the transfer, then rereads count.
 * Full bus uses wrapping 17-byte queue stride and is forwarded to scheduling.
 * No capacity validation, MEMW or local lock; FIFO lookup does not reserve,
 * so serialization with other scheduler users is the caller's responsibility.
 */
void medius_dwc2_drain_ready_queue(unsigned int bus)
{
    volatile MediusEndpointQueue *queue =
        (volatile MediusEndpointQueue *)(MEDIUS_DWC2_READY_BASE + bus * 17U);
    unsigned char count = queue->count;
    while (count != 0) {
        unsigned int endpoint = queue->entries[0];
        unsigned int fifo = medius_dwc2_find_free_fifo(bus,endpoint);
        if (fifo == 0) return;
        unsigned char reduced = (unsigned char)(count - 1U);
        queue->count = reduced;
        memmove((void *)queue,(const void *)((unsigned int)queue + 1U),reduced);
        medius_dwc2_assign_fifo_and_start(bus,endpoint,fifo);
        count = queue->count;
    }
}

/* Native entry: 0x4037f6e8. */
/* Original function-byte SHA-256:
 * 887a74398d6a7075fe8ff3db850a139bca285bd4f172c8f881bfb8f56f804744. */
/*
 * Returns immediately if the cached assigned-FIFO BYTE is zero or one
 * DIEPCTL sample has EPENA set. Otherwise clears disable_pending, polls AHB
 * idle and flushes the cached FIFO with 200,001-increment timeout limits.
 * Either timeout still proceeds with release; no failure is returned.
 *
 * MEMW precedes one FIFO-empty-mask WORD read, then the allocation BYTE is
 * sampled. MEMW precedes clearing endpoint modulo-32 mask bit, followed by
 * clearing assigned FIFO BYTE, clearing cached FIFO modulo-32 allocation bit
 * in that cached BYTE, then draining ready work. Full bus/endpoint index RAM
 * and MMIO through wrapping arithmetic. No local lock or ownership checks.
 */
void medius_dwc2_release_idle_fifo(unsigned int bus,unsigned int endpoint)
{
    volatile MediusDwc2Endpoint *transfer =
        (volatile MediusDwc2Endpoint *)(MEDIUS_DWC2_CONTEXT_BASE + bus * 0x3e4U +
                                       0x64U + endpoint * 28U);
    unsigned int fifo = transfer->fifo_index;
    if (fifo == 0) return;
    volatile MediusDwc2CoreRegisters *registers =
        *(volatile MediusDwc2CoreRegisters * const volatile *)(0x3fcd85c8U + bus * 8U);
    volatile Dwc2InEndpointRegisters *endpoint_registers =
        (volatile Dwc2InEndpointRegisters *)((unsigned int)registers + 0x900U + endpoint * 32U);
    memw();
    if ((endpoint_registers->control & 0x80000000U) != 0) return;
    transfer->disable_pending = 0;
    volatile unsigned int polls;
    dwc2_flush_selected_fifo(registers,fifo,&polls);
    memw();
    unsigned int empty_mask = registers->device_in_fifo_empty_mask;
    unsigned int allocated = MEDIUS_DWC2_ALLOCATED[bus];
    memw();
    registers->device_in_fifo_empty_mask = empty_mask & ~(1U << (endpoint & 31U));
    transfer->fifo_index = 0;
    MEDIUS_DWC2_ALLOCATED[bus] = (unsigned char)(allocated & ~(1U << (fifo & 31U)));
    medius_dwc2_drain_ready_queue(bus);
}

/* Native entry: 0x4037f7c8. */
/* Original function-byte SHA-256:
 * 7855cb556eb8fcb6a0f5a66ee3c7c5beb95d57a52fc0a9e592f55c39b75f6fcd. */
/*
 * Removes the first matching BYTE from ready, then token-wait, publishing
 * each reduced count before moving the suffix. Compares full endpoint and
 * does not clamp count to 16. Ready uses full bus; token-wait count reads/
 * writes use full bus but its entry scan/move uses LOW 16 bus bits. Retains
 * this native mismatch for out-of-range callers. If either match exists,
 * clears requested WORD then actual WORD before reading assigned FIFO BYTE.
 *
 * An assigned FIFO with force_release == 0 and priority eligibility is kept:
 * bounded idle/flush polling, FIFO-empty mask bit cleared, disable_pending
 * BYTE cleared, without clearing assignment/allocation. Timeout still takes
 * that path and EPENA is not tested. Otherwise calls release_idle_fifo even
 * for assignment zero; that routine can decline active hardware. No lock,
 * bounds check or return status; full address and bit arithmetic wraps.
 */
void medius_dwc2_remove_scheduled_transfer(unsigned int bus,unsigned int endpoint,int force_release)
{
    volatile MediusEndpointQueue *ready =
        (volatile MediusEndpointQueue *)(MEDIUS_DWC2_READY_BASE + bus * 17U);
    unsigned int count = ready->count;
    int removed_ready = dwc2_remove_queue_first((volatile unsigned char *)ready,
                                               &ready->count,count,endpoint);
    volatile MediusEndpointQueue *waiting =
        (volatile MediusEndpointQueue *)(MEDIUS_DWC2_TOKEN_WAIT_BASE + bus * 17U);
    count = waiting->count;
    volatile unsigned char *waiting_entries =
        (volatile unsigned char *)(MEDIUS_DWC2_TOKEN_WAIT_BASE + (bus & 0xffffU) * 17U);
    int removed_waiting = dwc2_remove_queue_first(waiting_entries,&waiting->count,count,endpoint);
    volatile MediusDwc2Endpoint *transfer =
        (volatile MediusDwc2Endpoint *)(MEDIUS_DWC2_CONTEXT_BASE + bus * 0x3e4U +
                                       0x64U + endpoint * 28U);
    if (removed_ready || removed_waiting) {
        transfer->requested = 0;
        transfer->actual = 0;
    }
    unsigned int fifo = transfer->fifo_index;
    if (fifo == 0 || force_release != 0 ||
        medius_dwc2_fifo_priority_eligible(bus,endpoint) == 0) {
        medius_dwc2_release_idle_fifo(bus,endpoint);
        return;
    }
    volatile MediusDwc2CoreRegisters *registers =
        *(volatile MediusDwc2CoreRegisters * const volatile *)(0x3fcd85c8U + bus * 8U);
    volatile unsigned int polls;
    dwc2_flush_selected_fifo(registers,fifo,&polls);
    memw();
    unsigned int empty_mask = registers->device_in_fifo_empty_mask;
    memw();
    registers->device_in_fifo_empty_mask = empty_mask & ~(1U << (endpoint & 31U));
    transfer->disable_pending = 0;
}

/* Native entry: 0x4037f96c. */
/* Original function-byte SHA-256:
 * 7438759dd9ef25c7c7b867f2baa8eab1d6bcdded95d60cfd8386005a230707cd. */
/*
 * Reads requested WORD and MPS HALF. Packet count is 1 for requested zero;
 * otherwise computes (requested-1+MPS modulo 2^32)/MPS. Nonzero requested
 * with MPS zero retains a native unsigned divide-by-zero operation.
 * Acknowledges 0x2002, reads DIEPTSIZ, computes wrapped
 * (packet_count-packets_remaining)*MPS and clamps that result to requested.
 * Reads initial_buffer, then rewrites DIEPTSIZ preserving high three bits
 * and ORing unmasked packets_remaining<<19 plus remaining byte count.
 *
 * Stores actual WORD, then buffer WORD = initial_buffer+completed modulo
 * 2^32. Releases the idle FIFO, then reads cancelled BYTE; zero appends to
 * token-wait with at_front 0. All arguments retain full 32-bit addressing;
 * native MEMW boundaries retained. No validation, rollback or local lock.
 */
void medius_dwc2_rewind_partial_in(unsigned int bus,unsigned int endpoint,unsigned int packets_remaining)
{
    volatile MediusDwc2Endpoint *transfer =
        (volatile MediusDwc2Endpoint *)(MEDIUS_DWC2_CONTEXT_BASE + bus * 0x3e4U +
                                       0x64U + endpoint * 28U);
    unsigned int requested = transfer->requested;
    unsigned int maximum_packet = transfer->max_packet;
    unsigned int packets = requested == 0 ? 1U : (requested - 1U + maximum_packet) / maximum_packet;
    unsigned int controller = *(const volatile unsigned int *)(0x3fcd85c8U + bus * 8U);
    volatile Dwc2InEndpointRegisters *registers =
        (volatile Dwc2InEndpointRegisters *)(controller + 0x900U + endpoint * 32U);
    memw();
    registers->interrupt_status = 0x2002U;
    memw();
    unsigned int old_size = registers->transfer_size;
    unsigned int completed = (packets - packets_remaining) * maximum_packet;
    if (completed > requested) completed = requested;
    unsigned char *initial_buffer = transfer->initial_buffer;
    memw();
    registers->transfer_size = (old_size & 0xe0000000U) |
                                (packets_remaining << 19) | (requested - completed);
    transfer->actual = completed;
    transfer->buffer = (unsigned char *)((unsigned int)initial_buffer + completed);
    medius_dwc2_release_idle_fifo(bus,endpoint);
    if (transfer->cancelled == 0) {
        unsigned char *waiting = (unsigned char *)(MEDIUS_DWC2_TOKEN_WAIT_BASE + bus * 17U);
        medius_dwc2_endpoint_queue_insert(waiting,endpoint,0);
    }
}

/* Native entry: 0x4037fa14. */
/* Original function-byte SHA-256:
 * cf8eb3a771106242408c01bd08506642c5570405f52bf924f8444373ba204b0d. */
/*
 * Caches assigned FIFO before computing priority eligibility, then removes
 * the first endpoint match from ready and token-wait. Counts are sampled
 * independently, published before memmove and never clamped to 16.
 * With no assignment, tries a free FIFO only when priority is nonzero or the
 * fresh ready count is zero; otherwise inserts ready at head for priority,
 * tail for nonpriority. Arguments and endpoint comparisons are full words.
 *
 * Nonpriority nonempty work with a cached FIFO and other ready work releases
 * its idle FIFO, then rereads ready count and either tries allocation or
 * queues. Other assigned paths reuse the CACHED FIFO. If EPENA is clear,
 * samples FIFO-space low HALF then configured-depth high HALF; a shortfall
 * triggers bounded idle/flush polling. Timeout still starts the transfer.
 * Immediate starts delegate to assign_fifo_and_start, which enables hardware.
 * Full bus/endpoint addresses wrap; no lock, bounds check or error return.
 */
void medius_dwc2_schedule_in(unsigned int bus,unsigned int endpoint,unsigned int length)
{
    const volatile MediusDwc2Endpoint *transfer =
        (const volatile MediusDwc2Endpoint *)(MEDIUS_DWC2_CONTEXT_BASE + bus * 0x3e4U +
                                             0x64U + endpoint * 28U);
    unsigned int fifo = transfer->fifo_index;
    int priority = medius_dwc2_fifo_priority_eligible(bus,endpoint);
    volatile MediusEndpointQueue *ready =
        (volatile MediusEndpointQueue *)(MEDIUS_DWC2_READY_BASE + bus * 17U);
    unsigned int count = ready->count;
    dwc2_remove_queue_first((volatile unsigned char *)ready,&ready->count,count,endpoint);
    volatile MediusEndpointQueue *waiting =
        (volatile MediusEndpointQueue *)(MEDIUS_DWC2_TOKEN_WAIT_BASE + bus * 17U);
    count = waiting->count;
    dwc2_remove_queue_first((volatile unsigned char *)waiting,&waiting->count,count,endpoint);
    if (fifo == 0) goto allocate_or_queue;
    if (((unsigned int)priority ^ 1U) % 256U != 0 && length != 0 && ready->count != 0) {
        medius_dwc2_release_idle_fifo(bus,endpoint);
        goto check_ready;
    }
    {
        volatile MediusDwc2CoreRegisters *registers =
            *(volatile MediusDwc2CoreRegisters * const volatile *)(0x3fcd85c8U + bus * 8U);
        volatile Dwc2InEndpointRegisters *endpoint_registers =
            (volatile Dwc2InEndpointRegisters *)((unsigned int)registers + 0x900U + endpoint * 32U);
        memw();
        if ((endpoint_registers->control & 0x80000000U) == 0) {
            memw();
            unsigned int space = endpoint_registers->fifo_space;
            memw();
            unsigned int configured = *(const volatile unsigned int *)
                ((unsigned int)registers + 0x100U + fifo * 4U);
            if ((space & 0xffffU) < (configured >> 16)) {
                volatile unsigned int polls;
                dwc2_flush_selected_fifo(registers,fifo,&polls);
            }
        }
    }
start:
    medius_dwc2_assign_fifo_and_start(bus,endpoint,fifo);
    return;
allocate_or_queue:
    if (priority != 0) goto allocate;
check_ready:
    if (ready->count != 0) goto queue;
allocate:
    fifo = medius_dwc2_find_free_fifo(bus,endpoint);
    if (fifo != 0) goto start;
queue:
    medius_dwc2_endpoint_queue_insert((unsigned char *)ready,endpoint,priority);
}

/* Native entry: 0x4037fbb4. */
/* Original function-byte SHA-256:
 * d2472fc466787028e8fe2080b5ba23d7c298131692c88e79260f9649edcb1a16. */
/*
 * Drains floor(length/4) RX FIFO WORDs into destination WORDs, with MEMW
 * before each FIFO read and one cached controller base for the bulk loop.
 * A 1..3-byte tail reloads the controller binding, reads one FIFO WORD after
 * MEMW and stores only the requested bytes low-to-high. Zero length touches
 * no controller or destination. length is a HALF and bus is a BYTE.
 * Destination alignment/extent and FIFO availability are unchecked; no
 * endpoint selection, ownership protection or lock is supplied here.
 */
void dwc2_ep_read(unsigned char bus,unsigned char *destination,unsigned short length)
{
    volatile unsigned char *cursor = destination;
    unsigned int words = (unsigned int)length >> 2;
    if (words != 0) {
        unsigned int controller = (unsigned int)MEDIUS_USBD_CONTROLLERS[bus].registers;
        const volatile unsigned int *fifo = (const volatile unsigned int *)(controller + 0x1000U);
        do {
            memw();
            unsigned int word = *fifo;
            *(volatile unsigned int *)cursor = word;
            cursor += 4;
        } while (--words != 0);
    }
    unsigned int tail = length & 3U;
    if (tail != 0) {
        unsigned int controller = (unsigned int)MEDIUS_USBD_CONTROLLERS[bus].registers;
        const volatile unsigned int *fifo = (const volatile unsigned int *)(controller + 0x1000U);
        memw();
        unsigned int word = *fifo;
        cursor[0] = (unsigned char)word;
        if ((tail & 2U) != 0) {
            cursor[1] = (unsigned char)(word >> 8);
            if (tail == 3) cursor[2] = (unsigned char)(word >> 16);
        }
    }
}

/* Native entry: 0x4037fc18. */
/* Original function-byte SHA-256:
 * 3e3126080adeabfb97eb5bcc341067f35b4b1d7ee7a24a91bfa545badbaa5a8e. */
/*
 * Queries ISR context, enters driver mux with -1 and ignores its result.
 * Uses byte bus and endpoint's low seven bits. Samples ready count BEFORE
 * setting cancelled BYTE to 1, removes the first match from ready, then
 * samples/removes the first match from token-wait. A match in either queue
 * suppresses hardware disable; other duplicates and byte counts remain.
 *
 * With no match, loads controller binding, samples DIEPCTL after MEMW and,
 * only if EPENA is set, performs distinct SNAK and EPDIS RMWs with MEMW
 * before each read/write. No polling, FIFO release or length reset occurs.
 * Queries ISR context again and exits mux on every path. Counts and endpoint
 * range are unchecked; cancelled remains set even when no work was present.
 */
void medius_dwc2_cancel_in(unsigned char bus,unsigned char endpoint)
{
    xPortInIsrContext();
    xPortEnterCriticalTimeout(MEDIUS_DWC2_DRIVER_LOCK,-1);
    unsigned int index = endpoint & 0x7fU;
    volatile MediusEndpointQueue *ready =
        (volatile MediusEndpointQueue *)(MEDIUS_DWC2_READY_BASE + (unsigned int)bus * 17U);
    unsigned int count = ready->count;
    volatile MediusDwc2Endpoint *transfer =
        (volatile MediusDwc2Endpoint *)(MEDIUS_DWC2_CONTEXT_BASE + (unsigned int)bus * 0x3e4U +
                                       0x64U + index * 28U);
    transfer->cancelled = 1;
    int removed_ready = dwc2_remove_queue_first((volatile unsigned char *)ready,&ready->count,count,index);
    volatile MediusEndpointQueue *waiting =
        (volatile MediusEndpointQueue *)(MEDIUS_DWC2_TOKEN_WAIT_BASE + (unsigned int)bus * 17U);
    count = waiting->count;
    int removed_waiting = dwc2_remove_queue_first((volatile unsigned char *)waiting,&waiting->count,count,index);
    if (!removed_ready && !removed_waiting) {
        unsigned int controller = (unsigned int)MEDIUS_USBD_CONTROLLERS[bus].registers;
        volatile Dwc2InEndpointRegisters *registers =
            (volatile Dwc2InEndpointRegisters *)(controller + 0x900U + index * 32U);
        memw();
        unsigned int control = registers->control;
        if ((control & 0x80000000U) != 0) {
            memw();
            control = registers->control;
            memw();
            registers->control = control | 0x08000000U;
            memw();
            control = registers->control;
            memw();
            registers->control = control | 0x40000000U;
        }
    }
    xPortInIsrContext();
    vPortExitCritical(MEDIUS_DWC2_DRIVER_LOCK);
}

/* Native entry: 0x4037fd44. */
/* Original function-byte SHA-256:
 * d396f8d5b35fa1ef9e0dc57a39f1413e094a98203ae776744d5736ba2ee66f91. */
/*
 * Enters driver mux after an ISR-context query, samples dynamic-mode BYTE
 * BEFORE storing the new mask HALF, then reconciles only when mode is nonzero
 * and the first capability sample reports endpoints. Starts at endpoint 1;
 * reloads capability bits 15..18 after each slot and advances transfer pointer
 * by 28 even if that reported limit changes. Reloads controller binding and
 * samples DIEPCTL before each priority query; assigned FIFO is sampled after.
 *
 * An assigned, disabled, noneligible endpoint releases its FIFO only when
 * disable_pending is zero. Eligible endpoints already in ready are removed
 * and inserted at the head. Otherwise a cached unassigned/disabled endpoint
 * absent from both queues can reserve a free FIFO if a fresh control read
 * has USBAEP set. Stores assignment BYTE, MEMW/reads control, updates allocation
 * BYTE, MEMW/writes TXFNUM without enabling a transfer. Uses cached state for
 * admission and does not recheck EPENA after calls. Repeated head moves reverse
 * eligible ready order. Always drains ready then queries ISR context/exits mux,
 * even with mode zero. No bounds checks, rollback or acquisition-result check.
 */
void dwc2_set_priority_mask(unsigned char bus,unsigned short mask)
{
    xPortInIsrContext();
    xPortEnterCriticalTimeout(MEDIUS_DWC2_DRIVER_LOCK,-1);
    unsigned char dynamic_mode = MEDIUS_DWC2_DYNAMIC_FIFO_MODE[bus];
    MEDIUS_DWC2_PRIORITY_MASKS[bus] = mask;
    volatile MediusDwc2DeviceContext *context =
        (volatile MediusDwc2DeviceContext *)(MEDIUS_DWC2_CONTEXT_BASE + (unsigned int)bus * 0x3e4U);
    volatile MediusEndpointQueue *ready =
        (volatile MediusEndpointQueue *)(MEDIUS_DWC2_READY_BASE + (unsigned int)bus * 17U);
    if (dynamic_mode != 0 && ((context->core_capabilities >> 15) & 15U) != 0) {
        unsigned int endpoint = 1;
        volatile MediusDwc2Endpoint *transfer = &context->input_endpoints[1];
        for (;;) {
            unsigned int controller = (unsigned int)MEDIUS_USBD_CONTROLLERS[bus].registers;
            volatile Dwc2InEndpointRegisters *registers =
                (volatile Dwc2InEndpointRegisters *)(controller + 0x900U +
                                                          (endpoint & 0xffffU) * 32U);
            memw();
            unsigned int control = registers->control;
            int eligible = medius_dwc2_fifo_priority_eligible(bus,endpoint);
            unsigned char assigned_fifo = transfer->fifo_index;
            if (assigned_fifo != 0 && (control & 0x80000000U) == 0 &&
                (((unsigned int)eligible ^ 1U) & 255U) != 0) {
                if (transfer->disable_pending == 0)
                    medius_dwc2_release_idle_fifo(bus,endpoint);
            } else if (eligible != 0) {
                unsigned int count = ready->count;
                int moved = dwc2_remove_queue_first((volatile unsigned char *)ready,
                    &ready->count,count,endpoint & 255U);
                if (moved) {
                    medius_dwc2_endpoint_queue_insert((unsigned char *)ready,endpoint,1);
                } else if (assigned_fifo == 0 && (control & 0x80000000U) == 0 &&
                           medius_dwc2_endpoint_is_queued(bus,endpoint) == 0) {
                    memw();
                    if ((registers->control & 0x8000U) != 0) {
                        unsigned int fifo = medius_dwc2_find_free_fifo(bus,endpoint);
                        if (fifo != 0) {
                            transfer->fifo_index = (unsigned char)fifo;
                            memw();
                            unsigned int current_control = registers->control;
                            unsigned int allocated = MEDIUS_DWC2_ALLOCATED[bus];
                            MEDIUS_DWC2_ALLOCATED[bus] =
                                (unsigned char)(allocated | (1U << (fifo & 31U)));
                            memw();
                            registers->control = (current_control & 0x3c3fffffU) | (fifo << 22);
                        }
                    }
                }
            }
            unsigned int capability = context->core_capabilities;
            ++endpoint;
            transfer = (volatile MediusDwc2Endpoint *)((unsigned int)transfer + 28U);
            if ((endpoint & 255U) > ((capability >> 15) & 15U)) break;
        }
    }
    medius_dwc2_drain_ready_queue(bus);
    xPortInIsrContext();
    vPortExitCritical(MEDIUS_DWC2_DRIVER_LOCK);
}

/* Native entry: 0x4037fedc. */
/* Original function-byte SHA-256:
 * 18b5352e47293374158943859f38975035921c54d2cb9ec9eda66dabef08b07c. */
/*
 * Under driver mux, samples DIEPCTL after MEMW and returns 1 immediately
 * through cleanup if EPENA is set. Otherwise queries ready/token queues;
 * a nonzero result is retained. Only an unqueued disabled endpoint reads
 * disable_pending BYTE, returning 0 for zero and 1 otherwise.
 * Uses byte bus and endpoint low seven bits without bounds validation.
 * ISR-context queries bracket the ignored-result -1 lock request and exit.
 * Does not test cancelled, byte lengths, FIFO assignment or future activity.
 */
int dwc2_in_endpoint_is_busy(unsigned char bus,unsigned char endpoint)
{
    xPortInIsrContext();
    xPortEnterCriticalTimeout(MEDIUS_DWC2_DRIVER_LOCK,-1);
    unsigned int index = endpoint & 0x7fU;
    unsigned int controller = (unsigned int)MEDIUS_USBD_CONTROLLERS[bus].registers;
    const volatile Dwc2InEndpointRegisters *registers =
        (const volatile Dwc2InEndpointRegisters *)(controller + 0x900U + index * 32U);
    memw();
    int busy = 1;
    if ((registers->control & 0x80000000U) == 0) {
        busy = medius_dwc2_endpoint_is_queued(bus,index);
        if (busy == 0) {
            const volatile MediusDwc2Endpoint *transfer =
                (const volatile MediusDwc2Endpoint *)(MEDIUS_DWC2_CONTEXT_BASE +
                    (unsigned int)bus * 0x3e4U + 0x64U + index * 28U);
            busy = transfer->disable_pending != 0;
        }
    }
    xPortInIsrContext();
    vPortExitCritical(MEDIUS_DWC2_DRIVER_LOCK);
    return busy;
}

/* Native entry: 0x4037ff44. */
/*
 * Medius v3.4.7 — device application; 0x4037ff44.
 *
 * Initializes device capabilities/PHY/reset/FIFO/interrupt state with seven real guard loops, an
 * unbounded device-mode wait and RX-only final timeout status.
 *
 * Calls: medius_dwc2_device_params, medius_usb_low_speed_requested, medius_usb_scheduler_delay_u8,
 * memset, usb_dc_low_level_init.
 *
 * Called by: usbd_initialize.
 *
 * Original function-byte SHA-256:
 * 4fad077ec6add74d624f90f6581e046c20fd098e9b6db8be5f26fe28fef1d311.
 */

/*
 * bus: Only low8 selects raw0x3e4 context and8-byte controller-slot strides; no bus bound check.
 * Returns: 0 when the final RX flush clears; -1 on final RX idle/flush timeout. Earlier reset/TX
 *   timeouts and platform failures do not determine return; seven guards and device-mode wait can
 *   fail to return.
 * Requirements/effects: Clears selected996-byte context only, ignores platform init outcome;
 *   captures controller before five ordered capability reads. Preserves native reserved capability
 *   bits and field store/read widths, copies live64-byte parameters through wrapper, defaults
 *   width8 and capacity from hardware only when zero. Uses explicit typed
 *   controller/context/parameter layouts, MEMW before every native MMIO/counter load/store,
 *   ordered volatile RMWs and fresh controller reloads at
 *   native boundaries. Three reset waits count before read,200000 reads maximum/counter200001; old
 *   revision waits bit0 clear, new waits bit29 then independent fresh clear/ack RMWs. Reset
 *   timeout continues to device forcing. Mode wait delegates delay10 without local timeout, then
 *   checks RX and all N+1 TX existing depths before clearing15 dedicated sizes. Session override
 *   uses separate bit6/7 RMWs. Speed clear applies old DCFG pointer; PHY0 queries speed then
 *   reloads controller, other PHY requires HS capability and retains unchanged old-pointer RMW.
 *   Programs masks/ack, samples DMA before initial mask write, enforces architecture2 for DMA,
 *   programs burst/config through separate RMWs. RX layout caches requested RX/count/capacity,
 *   reads RX before each live TX depth and fresh preceding depth sums; offset is not masked.
 *   Requested sum guard follows each write, RX minimum47/159 follows layout. Independent TX and RX
 *   idle/flush waits use volatile counters and200000-read bounds; TX errors discarded, final RX
 *   only sets result. Final finite path always enables global interrupt and clears soft
 *   disconnect, including RX error. True self-jump guards preserve partial state. External
 *   scheduling state outside context remains intact. No hardware
 *   reset/W1C/PHY/DMA/timing/concurrency or SDK resource success proof.
 */

int usb_dc_init(unsigned int bus)
{
    unsigned int selected_bus = bus & 255U;
    unsigned int context_address = MEDIUS_DWC2_CONTEXT_BASE + selected_bus * 0x3e4U;
    volatile MediusDwc2DeviceContext *context = (volatile MediusDwc2DeviceContext *)context_address;
    volatile MediusUsbdControllerBinding *binding = &MEDIUS_USBD_CONTROLLERS[selected_bus];
    memset((void *)context_address,0,0x3e4);
    usb_dc_low_level_init(selected_bus);
    unsigned int initial_base = (unsigned int)binding->registers;
    volatile MediusDwc2CoreRegisters *registers = (volatile MediusDwc2CoreRegisters *)initial_base;
    memw();
    unsigned int revision = registers->core_id;
    memw();
    unsigned int endpoint_directions = registers->hardware_config1;
    memw();
    unsigned int hardware_configuration2 = registers->hardware_config2;
    memw();
    unsigned int hardware_configuration3 = registers->hardware_config3;
    memw();
    unsigned int hardware_configuration4 = registers->hardware_config4;
    unsigned int reserved_packet_capabilities = context->packet_fifo_capabilities & 0xc0000000U;
    unsigned int reserved_transfer_bits = context->max_transfer_size & 0xfc000000U;
    unsigned int reserved_core_capabilities = context->core_capabilities & 0xc0000000U;
    context->core_id = revision;
    context->max_transfer_size = reserved_transfer_bits | ((1U << ((hardware_configuration3 & 15U) + 11U)) - 1U);
    context->core_capabilities = reserved_core_capabilities | (hardware_configuration2 & 31U) |
        ((hardware_configuration2 >> 19) & 1U) << 5 | (((hardware_configuration2 >> 14) & 15U) + 1U) << 6 |
        ((hardware_configuration2 >> 6) & 3U) << 11 | ((hardware_configuration2 >> 8) & 3U) << 13 |
        ((hardware_configuration2 >> 10) & 15U) << 15 | ((hardware_configuration2 >> 22) & 3U) << 20 |
        ((hardware_configuration2 >> 24) & 3U) << 23 | ((hardware_configuration2 >> 26) & 31U) << 25;
    context->endpoint_directions = endpoint_directions;
    context->packet_fifo_capabilities = reserved_packet_capabilities |
        ((1U << (((hardware_configuration3 >> 4) & 7U) + 4U)) - 1U) |
        ((hardware_configuration3 >> 8) & 1U) << 11 | (hardware_configuration3 >> 16) << 12 |
        ((hardware_configuration3 >> 15) & 1U) << 28 | ((hardware_configuration4 >> 25) & 1U) << 29;
    *(volatile unsigned short *)&context->device_capabilities = (unsigned short)(
        ((hardware_configuration4 >> 26) & 15U) | (hardware_configuration4 & 15U) << 4 |
        ((hardware_configuration4 >> 30) & 1U) << 8 | ((hardware_configuration4 >> 4) & 1U) << 9 |
        ((hardware_configuration4 >> 6) & 1U) << 10 | ((hardware_configuration4 >> 14) & 3U) << 11 |
        ((hardware_configuration4 >> 12) & 1U) << 13 | ((hardware_configuration4 >> 11) & 1U) << 14 |
        ((hardware_configuration4 >> 10) & 1U) << 15);
    medius_dwc2_device_params(initial_base,(unsigned char *)(context_address + 36U));
    if (context->parameters.phy_width == 0)
        context->parameters.phy_width = 8;
    if (context->parameters.fifo_capacity == 0) {
        unsigned int capabilities = context->packet_fifo_capabilities;
        context->parameters.fifo_capacity = (capabilities >> 12) & 65535U;
    }
    registers = (volatile MediusDwc2CoreRegisters *)(unsigned int)binding->registers;
    {
        memw();
        unsigned int current_ahb_configuration = registers->ahb_configuration;
        memw();
        registers->ahb_configuration = current_ahb_configuration & 0xfffffffeU;
    }
    memw();
    unsigned int device_control = registers->device_control;
    unsigned int general_core_configuration = context->parameters.general_core_configuration;
    memw();
    registers->device_control = device_control | 2U;
    memw();
    registers->general_core_configuration = general_core_configuration;
    unsigned char phy_type = context->parameters.phy_type;
    memw();
    unsigned int usb_configuration = registers->usb_configuration;
    if (phy_type == 0) {
        usb_configuration |= 0x40U;
    } else if (phy_type == 1) {
        unsigned char width = context->parameters.phy_width;
        usb_configuration &= 0xffc5ffa7U;
        if (width == 16)
            usb_configuration |= 8U;
    } else if (phy_type == 2) {
        usb_configuration = (usb_configuration & 0xffc5ff37U) | 0x10U;
    } else {
        usb_configuration &= 0xffc5ffbfU;
    }
    memw();
    registers->usb_configuration = usb_configuration;

    /* Reset waits have bounded register reads; their timeout still permits setup to continue. */
    volatile unsigned int reset_counter;
    memw();
    reset_counter = 0;
    for (;;) {
        memw();
        unsigned int attempt = reset_counter + 1U;
        memw();
        reset_counter = attempt;
        if (attempt > 200000)
            goto force_device;
        memw();
        if (registers->reset_control & 0x80000000U)
            break;
    }
    memw();
    reset_counter = 0;
    memw();
    unsigned int reset_request = registers->reset_control;
    unsigned int reset_revision = context->core_id;
    memw();
    registers->reset_control = reset_request | 1U;
    if (reset_revision <= 0x4f544209U) {
        for (;;) {
            memw();
            unsigned int attempt = reset_counter + 1U;
            memw();
            reset_counter = attempt;
            if (attempt > 200000)
                goto force_device;
            memw();
            if ((registers->reset_control & 1U) == 0)
                break;
        }
    } else {
        for (;;) {
            memw();
            unsigned int attempt = reset_counter + 1U;
            memw();
            reset_counter = attempt;
            if (attempt > 200000)
                goto force_device;
            memw();
            if (registers->reset_control & 0x20000000U)
                break;
        }
        {
            memw();
            unsigned int current_reset_control = registers->reset_control;
            memw();
            registers->reset_control = current_reset_control & 0xfffffffeU;
        }
        {
            memw();
            unsigned int current_reset_control = registers->reset_control;
            memw();
            registers->reset_control = current_reset_control | 0x20000000U;
        }
    }
force_device:
    /* The device-mode wait has no timeout and reloads the binding after each delay. */
    {
        memw();
        unsigned int current_usb_configuration = registers->usb_configuration;
        memw();
        registers->usb_configuration = current_usb_configuration & 0x9fffffffU;
    }
    {
        memw();
        unsigned int current_usb_configuration = registers->usb_configuration;
        memw();
        registers->usb_configuration = current_usb_configuration | 0x40000000U;
    }
    memw();
    unsigned int mode = registers->interrupt_status;
    while (mode & 1U) {
        medius_usb_scheduler_delay_u8(10);
        registers = (volatile MediusDwc2CoreRegisters *)(unsigned int)binding->registers;
        memw();
        mode = registers->interrupt_status;
    }
    memw();
    unsigned int rx_fifo = registers->receive_fifo_size;
    unsigned short rx_required = context->parameters.receive_fifo_words;
    if ((rx_fifo & 65535U) < rx_required) {
        __asm__ volatile("1: j 1b" ::: "memory");
        __builtin_unreachable();
    }
    unsigned int fifo_count = context->device_capabilities & 15U;
    memw();
    unsigned int existing_tx = registers->nonperiodic_tx_fifo_size;
    for (unsigned int index = 0;; ++index) {
        unsigned short required = context->parameters.transmit_fifo_words[index];
        if ((existing_tx >> 16) < required) {
            __asm__ volatile("1: j 1b" ::: "memory");
            __builtin_unreachable();
        }
        if (index == fifo_count)
            break;
        memw();
        existing_tx = registers->dedicated_tx_fifo_size[index];
    }
    if (context->parameters.session_override != 0) {
        {
            memw();
            unsigned int current_otg_control = registers->otg_control;
            memw();
            registers->otg_control = current_otg_control | 0x40U;
        }
        {
            memw();
            unsigned int current_otg_control = registers->otg_control;
            memw();
            registers->otg_control = current_otg_control | 0x80U;
        }
    }
    {
        memw();
        unsigned int current_usb_configuration = registers->usb_configuration;
        memw();
        registers->usb_configuration = current_usb_configuration | 7U;
    }
    for (unsigned int index = 0; index < 15; ++index) {
        memw();
        registers->dedicated_tx_fifo_size[index] = 0;
    }
    memw();
    registers->power_clock_gate = 0;
    volatile unsigned int *earlier_dcfg = &registers->device_configuration;
    {
        memw();
        unsigned int current_configuration = *earlier_dcfg;
        memw();
        *earlier_dcfg = current_configuration & 0xfffffffcU;
    }
    if (context->parameters.phy_type == 0) {
        unsigned int low_speed = medius_usb_low_speed_requested();
        registers = (volatile MediusDwc2CoreRegisters *)(unsigned int)binding->registers;
        unsigned int speed;
        if (low_speed != 0)
            speed = 2;
        else
            speed = ((context->core_capabilities >> 11) & 3U) == 0 ? 3 : 1;
        {
            memw();
            unsigned int current_device_configuration = registers->device_configuration;
            memw();
            registers->device_configuration = current_device_configuration | speed;
        }
    } else {
        if (((context->core_capabilities >> 11) & 3U) == 0) {
            __asm__ volatile("1: j 1b" ::: "memory");
            __builtin_unreachable();
        }
        registers = (volatile MediusDwc2CoreRegisters *)(unsigned int)binding->registers;
        {
            memw();
            unsigned int current_configuration = *earlier_dcfg;
            memw();
            *earlier_dcfg = current_configuration;
        }
    }
    memw();
    registers->device_in_endpoint_mask = 0;
    memw();
    registers->out_endpoint_mask = 0;
    memw();
    registers->all_endpoint_mask = 0;
    memw();
    registers->interrupt_mask = 0;
    memw();
    registers->interrupt_status = 0xbfffffffU;
    unsigned char dma_enabled = context->parameters.dma_enabled;
    memw();
    registers->interrupt_mask = 0x800c3800U;
    if (dma_enabled == 0) {
        {
            memw();
            unsigned int current_interrupt_mask = registers->interrupt_mask;
            memw();
            registers->interrupt_mask = current_interrupt_mask | 0x10U;
        }
    } else {
        if (((context->core_capabilities >> 3) & 3U) != 2) {
            __asm__ volatile("1: j 1b" ::: "memory");
            __builtin_unreachable();
        }
        {
            memw();
            unsigned int current_device_configuration = registers->device_configuration;
            memw();
            registers->device_configuration = current_device_configuration & 0xff7fffffU;
        }
        {
            memw();
            unsigned int current_ahb_configuration = registers->ahb_configuration;
            memw();
            registers->ahb_configuration = current_ahb_configuration & 0xffffffe1U;
        }
        {
            memw();
            unsigned int current_ahb_configuration = registers->ahb_configuration;
            memw();
            registers->ahb_configuration = current_ahb_configuration | 0x2eU;
        }
    }
    {
        memw();
        unsigned int current_device_configuration = registers->device_configuration;
        memw();
        registers->device_configuration = current_device_configuration | 0x1800U;
    }
    memw();
    unsigned int interrupt_mask = registers->interrupt_mask;
    unsigned int requested_rx = context->parameters.receive_fifo_words;
    memw();
    registers->interrupt_mask = interrupt_mask | 0x8000U;
    memw();
    registers->receive_fifo_size = requested_rx;
    /* Check the accumulated requested size after publishing each FIFO layout word. */
    unsigned int layout_count = context->device_capabilities & 15U;
    unsigned int capacity = context->parameters.fifo_capacity;
    unsigned int requested_total = requested_rx;
    for (unsigned int index = 0; index <= layout_count; ++index) {
        memw();
        unsigned int start = registers->receive_fifo_size;
        unsigned int depth = context->parameters.transmit_fifo_words[index];
        if (index == 0) {
            memw();
            registers->nonperiodic_tx_fifo_size = (depth << 16) | start;
        } else {
            memw();
            start += registers->nonperiodic_tx_fifo_size >> 16;
            for (unsigned int earlier = 0; earlier + 1U < index; ++earlier) {
                memw();
                start += registers->dedicated_tx_fifo_size[earlier] >> 16;
            }
            memw();
            registers->dedicated_tx_fifo_size[index - 1U] = (depth << 16) | start;
        }
        requested_total += depth;
        if (capacity < requested_total) {
            __asm__ volatile("1: j 1b" ::: "memory");
            __builtin_unreachable();
        }
    }
    if (context->parameters.phy_type == 0) {
        if (requested_rx < 47) {
            __asm__ volatile("1: j 1b" ::: "memory");
            __builtin_unreachable();
        }
    } else if (requested_rx < 159) {
        __asm__ volatile("1: j 1b" ::: "memory");
        __builtin_unreachable();
    }
    /* TX errors are discarded; only the final independent RX flush controls the result. */
    volatile unsigned int tx_counter;
    memw();
    tx_counter = 0;
    for (;;) {
        memw();
        unsigned int attempt = tx_counter + 1U;
        memw();
        tx_counter = attempt;
        if (attempt > 200000)
            goto flush_receive;
        memw();
        if (registers->reset_control & 0x80000000U)
            break;
    }
    memw();
    tx_counter = 0;
    memw();
    registers->reset_control = 0x420;
    for (;;) {
        memw();
        unsigned int attempt = tx_counter + 1U;
        memw();
        tx_counter = attempt;
        if (attempt > 200000)
            break;
        memw();
        if ((registers->reset_control & 0x20U) == 0)
            break;
    }
flush_receive:
    ;
    volatile unsigned int rx_counter;
    memw();
    rx_counter = 0;
    unsigned int result;
    for (;;) {
        memw();
        unsigned int attempt = rx_counter + 1U;
        memw();
        rx_counter = attempt;
        if (attempt > 200000) {
            result = 0xffffffffU;
            goto reconnect;
        }
        memw();
        if (registers->reset_control & 0x80000000U)
            break;
    }
    memw();
    rx_counter = 0;
    memw();
    registers->reset_control = 0x10;
    for (;;) {
        memw();
        unsigned int attempt = rx_counter + 1U;
        memw();
        rx_counter = attempt;
        if (attempt > 200000) {
            result = 0xffffffffU;
            break;
        }
        memw();
        unsigned int reset_status = registers->reset_control;
        result = reset_status & 0x10U;
        if (result == 0)
            break;
    }
reconnect:
    /* Both success and finite RX failure enable interrupts and clear soft disconnect. */
    {
        memw();
        unsigned int current_ahb_configuration = registers->ahb_configuration;
        memw();
        registers->ahb_configuration = current_ahb_configuration | 1U;
    }
    {
        memw();
        unsigned int current_device_control = registers->device_control;
        memw();
        registers->device_control = current_device_control & 0xfffffffdU;
    }
    return (int)result;
}

/* Native entry: 0x403805e4. */
/*
 * Medius v3.4.7 — device application; 0x403805e4.
 *
 * Soft-disconnects and masks the device controller, attempts TX/RX flushes, clears four scheduling
 * bytes and tears down shared PHY/IRQ handles.
 *
 * Calls: xPortInIsrContext, usb_dc_low_level_deinit, vPortExitCritical, xPortEnterCriticalTimeout.
 *
 * Called by: FUN_42021a18.
 *
 * Original function-byte SHA-256:
 * 4cfe72ea5378a423db39de0baccac33b89748181cb7e09f68b0d96aefcd80837.
 */

/*
 * bus: Full32-bit caller value; low8 selects controller slot stride8 and scheduling-byte/queue
 *   views without a bounds guard.
 * Returns: Always0, including every flush timeout and ignored critical-entry/SDK release failure.
 * Requirements/effects: Caches controller once. MEMW-reads/writes GAHBCFG bit0 clear and DCTL
 *   soft-disconnect bit1 set; acknowledges IN then OUT endpoint interrupt registers with0xfb7f for
 *   exactly endpoints0..14. Endpoint15/all endpoint CTLs remain untouched. Clears
 *   DIEPMSK,DOEPMSK,DAINTMSK,GINTMSK and acknowledges GINTSTS0xbfffffff; preserves
 *   DEACHINTMSK/DIEPEMPMSK. Independently attempts TX-all and RX flushes: each first waits AHBIDL,
 *   issues its command only if idle succeeds, then waits its flush bit clear. Each of four phases
 *   MEMW-loads its counter, MEMW-stores the increment, then compares that cached attempt
 *   before a separately fenced MMIO read, allowing200000 reads and
 *   ending200001 on timeout; TX failure does not skip RX. All MMIO precedes local lock. Queries
 *   ISR context, enters shared mux with infinite timeout ignoring status, clears only selected bus
 *   dynamic mode/FIFO bitmap/ready count/token-wait count, queries ISR again and unlocks. Queue
 *   entries, priority mask, endpoint records, buffers and controller parameters are retained.
 *   Calls shared low-level IRQ/PHY teardown after unlock, then returns0. No controller/index
 *   validation, transfer callbacks, local rollback, whole software reset or quiescence result;
 *   iteration bounds do not guarantee elapsed time or hardware flush success. Peripheral changes
 *   occur outside the local lock.
 */

int usb_dc_deinit(unsigned int bus)
{
    unsigned int bus_index = bus & 0xffU;
    volatile MediusDwc2CoreRegisters *registers = MEDIUS_USBD_CONTROLLERS[bus_index].registers;
    unsigned int controller = (unsigned int)registers;
    volatile unsigned int *ahb_configuration = &registers->ahb_configuration;
    memw();
    unsigned int ahb = *ahb_configuration;
    memw();
    *ahb_configuration = ahb & ~1U;
    volatile unsigned int *device_control = &registers->device_control;
    memw();
    unsigned int control = *device_control;
    memw();
    *device_control = control | 2U; /* Soft disconnect. */
    volatile Dwc2InEndpointRegisters *input_registers =
        (volatile Dwc2InEndpointRegisters *)(controller + 0x900U);
    volatile MediusDwc2OutEndpointRegisters *output_registers =
        (volatile MediusDwc2OutEndpointRegisters *)(controller + 0xb00U);
    for (unsigned int endpoint = 0; endpoint < 15; ++endpoint) {
        memw();
        input_registers[endpoint].interrupt_status = 0xfb7fU; /* DIEPINT */
        memw();
        output_registers[endpoint].interrupt_status = 0xfb7fU; /* DOEPINT */
    }
    memw();
    registers->device_in_endpoint_mask = 0; /* DIEPMSK */
    memw();
    registers->out_endpoint_mask = 0; /* DOEPMSK */
    memw();
    registers->all_endpoint_mask = 0; /* DAINTMSK */
    memw();
    registers->interrupt_mask = 0; /* GINTMSK */
    memw();
    registers->interrupt_status = 0xbfffffffU; /* GINTSTS */
    volatile unsigned int *reset_control = &registers->reset_control;
    memw();
    volatile unsigned int transmit_polls = 0;
    for (;;) {
        memw();
        unsigned int attempt = transmit_polls + 1U;
        memw();
        transmit_polls = attempt;
        if (attempt > 200000U)
            goto receive_flush;
        memw();
        if ((*reset_control & 0x80000000U) != 0)
            break;
    }
    memw();
    transmit_polls = 0;
    memw();
    *reset_control = 0x420U; /* All TX FIFOs: TXFNUM16 | TXFFLSH. */
    for (;;) {
        memw();
        unsigned int attempt = transmit_polls + 1U;
        memw();
        transmit_polls = attempt;
        if (attempt > 200000U)
            break;
        memw();
        if ((*reset_control & 0x20U) == 0)
            break;
    }
receive_flush:
    memw();
    volatile unsigned int receive_polls = 0;
    for (;;) {
        memw();
        unsigned int attempt = receive_polls + 1U;
        memw();
        receive_polls = attempt;
        if (attempt > 200000U)
            goto reset_scheduling;
        memw();
        if ((*reset_control & 0x80000000U) != 0)
            break;
    }
    memw();
    receive_polls = 0;
    memw();
    *reset_control = 0x10U; /* RXFFLSH */
    for (;;) {
        memw();
        unsigned int attempt = receive_polls + 1U;
        memw();
        receive_polls = attempt;
        if (attempt > 200000U)
            break;
        memw();
        if ((*reset_control & 0x10U) == 0)
            break;
    }
reset_scheduling:
    xPortInIsrContext();
    xPortEnterCriticalTimeout(MEDIUS_DWC2_DRIVER_LOCK,0xffffffffU);
    USB_DWC2_DYNAMIC_FIFO_MODES[bus_index] = 0;
    MEDIUS_DWC2_ALLOCATED[bus_index] = 0;
    volatile MediusEndpointQueue *ready =
        (volatile MediusEndpointQueue *)(MEDIUS_DWC2_READY_BASE + bus_index * 17U);
    volatile MediusEndpointQueue *token_wait =
        (volatile MediusEndpointQueue *)(MEDIUS_DWC2_TOKEN_WAIT_BASE + bus_index * 17U);
    ready->count = 0;
    token_wait->count = 0;
    xPortInIsrContext();
    vPortExitCritical(MEDIUS_DWC2_DRIVER_LOCK);
    usb_dc_low_level_deinit(); /* Shared PHY/IRQ resources, independent of bus. */
    return 0;
}

/* Native entry: 0x403807d8. */
/*
 * Medius v3.4.7 — device application; 0x403807d8.
 *
 * Configures device IN/OUT endpoints, migrates exhausted TX FIFOs into dynamic scheduling and
 * preserves explicit timeout/nonreturn behavior.
 *
 * Calls: xPortInIsrContext, medius_dwc2_fifo_priority_eligible, medius_dwc2_find_free_fifo,
 * medius_dwc2_remove_scheduled_transfer, vPortExitCritical, xPortEnterCriticalTimeout.
 *
 * Called by: FUN_40391bc0, FUN_42028cbc, medius_usbd_open_descriptor_endpoint,
 * medius_usbd_reset_event.
 *
 * Original function-byte SHA-256:
 * b21d7d1dd7bff64337f87b530335d7d12bac2245b3878761b78f097865080f46.
 */

/*
 * bus: Low8 bus index; controller stride8 and context stride996, without a bus-range check.
 * descriptor: Borrowed seven-byte endpoint descriptor; length/type bytes are not validated, MPS
 *   reads high then low, attributes/interval are sampled at the stated stages.
 * Returns: 0 on every returning path, including disable/flush timeout. Invalid hardware endpoint
 *   index or insufficient FIFO depth enters an actual nonreturning self-branch.
 * Requirements/effects: Low7 endpoint index is checked against hardware-count nibble before any
 *   lock/state writes. OUT stores MPS/type only, adds interrupt mask and ORs preserved control
 *   bits; nonzero type0 freshly tests EPENA before setup size0x20080008. IN enters mux, reads
 *   MPS/interval/controller/retained FIFO; retained/EP0 updates interval only before depth check.
 *   Unassigned static allocation failure publishes dynamic1, snapshots hardware count BEFORE
 *   frame, then migrates assignments: enabled records store frame then low8 packets; disabled
 *   nonpriority records flush with200000-read bounds, read empty mask once BEFORE allocation
 *   bitmap and release even on timeout. Requested allocation then requires priority; already-
 *   dynamic path skips migration. New FIFO/interval publish as one halfword. FIFO0 nonzero
 *   endpoint checks depth at register0x104; EP0 uses0x28. Insufficient depth retains
 *   lock/allocation/interval changes. Nonzero IN adds mask, optionally SNAK/EPDIS and polls at
 *   most50000 times with counter increments only for still-enabled reads. Counter loads and
 *   increment stores are independently fenced; bounds compare the cached attempt, not a reread.
 *   The native disable bound49999 admits attempts1..49999 for another read, always acknowledging2
 *   afterwards. Reads control BEFORE sampling dynamic mode, masks0x3c1fffff; sampled mode invokes
 *   removal then refreshes base/FIFO/attributes but keeps cached MPS and earlier software type.
 *   Final control OR preserves old fields and includes FIFO. EP0 or nonzero FIFO gets
 *   independent200000-read idle/flush waits/counter200001; normal IN exits critical and returns0
 *   even on timeout. No descriptor/capacity/lifetime/lock-result validation, rollback, elapsed-
 *   time guarantee or peripheral-success assertion; caller must serialize valid storage/controller
 *   state.
 */

int usbd_ep_open(unsigned char bus,const MediusUsbEndpointDescriptor *descriptor)
{
    const volatile MediusUsbEndpointDescriptor *description = descriptor;
    unsigned char address = description->address;
    volatile MediusDwc2DeviceContext *context = (volatile MediusDwc2DeviceContext *)
        (MEDIUS_DWC2_CONTEXT_BASE + (unsigned int)bus * sizeof(MediusDwc2DeviceContext));
    const volatile unsigned int *hardware_word = &context->core_capabilities;
    unsigned int endpoint_count = (*hardware_word >> 15) & 15U;
    unsigned int index = address & 0x7fU;
    if (index > endpoint_count) {
        __asm__ volatile ("1: j 1b" ::: "memory");
        __builtin_unreachable();
    }
    volatile MediusUsbdControllerBinding *binding = &MEDIUS_USBD_CONTROLLERS[bus];
    if ((address & 0x80U) == 0) {
        unsigned char high = description->max_packet_high;
        unsigned char low = description->max_packet_low;
        unsigned int max_packet = (((unsigned int)high << 8) | low) & 0x7ffU;
        volatile MediusDwc2Endpoint *transfer = (volatile MediusDwc2Endpoint *)
            &context->output_endpoints[index];
        transfer->max_packet = (unsigned short)max_packet;
        unsigned char attributes = description->attributes;
        unsigned int type = attributes & 3U;
        transfer->transfer_type = (unsigned char)type;
        unsigned int controller = (unsigned int)binding->registers;
        volatile unsigned int *interrupt_mask = (volatile unsigned int *)(controller + 0x81cU);
        volatile MediusDwc2OutEndpointRegisters *registers =
            (volatile MediusDwc2OutEndpointRegisters *)(controller + 0xb00U + index * 32U);
        memw();
        unsigned int enabled = *interrupt_mask;
        memw();
        *interrupt_mask = enabled | (1U << ((index + 16U) & 31U));
        if (index == 0) {
            unsigned int encoding = max_packet == 8 ? 3 : max_packet == 16 ? 2 : max_packet == 32 ? 1 : 0;
            memw();
            unsigned int control = registers->control;
            memw();
            registers->control = control | (type << 18) | encoding | 0x10008000U;
            return 0;
        }
        memw();
        unsigned int control = registers->control;
        memw();
        registers->control = control & 0x3fdfffffU;
        memw();
        control = registers->control;
        memw();
        registers->control = control | (type << 18) | max_packet | 0x10008000U;
        if (type == 0) {
            memw();
            unsigned int final_control = registers->control;
            if ((final_control & 0x80000000U) == 0) {
                memw();
                registers->transfer_size = 0x20080008U;
            }
        }
        return 0;
    }
    xPortInIsrContext();
    xPortEnterCriticalTimeout(MEDIUS_DWC2_DRIVER_LOCK,0xffffffffU);
    unsigned char high = description->max_packet_high;
    unsigned char low = description->max_packet_low;
    unsigned int max_packet = (((unsigned int)high << 8) | low) & 0x7ffU;
    unsigned char interval = description->interval;
    unsigned int controller = (unsigned int)binding->registers;
    volatile MediusDwc2Endpoint *transfer = (volatile MediusDwc2Endpoint *)
        &context->input_endpoints[index];
    unsigned int fifo = transfer->fifo_index;
    volatile unsigned char *dynamic_mode = &USB_DWC2_DYNAMIC_FIFO_MODES[bus];
    volatile unsigned char *allocation_bitmap = &MEDIUS_DWC2_ALLOCATED[bus];
    if (index == 0 || fifo != 0) {
        transfer->interval = interval;
    } else {
        unsigned int allocated_fifo = 0;
        if (*dynamic_mode == 0) {
            allocated_fifo = medius_dwc2_find_free_fifo(bus,index);
            if (allocated_fifo == 0) {
                *dynamic_mode = 1;
                unsigned int migration_count = (*hardware_word >> 15) & 15U;
                memw();
                unsigned int device_status = *(const volatile unsigned int *)(controller + 0x808U);
                unsigned short frame = (unsigned short)((device_status >> 8) & 0x7ffU);
                for (unsigned int candidate = 1; (unsigned char)candidate <= migration_count; ++candidate) {
                    volatile MediusDwc2Endpoint *existing = (volatile MediusDwc2Endpoint *)
                        &context->input_endpoints[candidate];
                    unsigned int assigned_fifo = existing->fifo_index;
                    if (assigned_fifo == 0)
                        continue;
                    volatile Dwc2InEndpointRegisters *existing_registers =
                        (volatile Dwc2InEndpointRegisters *)(controller + 0x900U + candidate * 32U);
                    memw();
                    unsigned int control = existing_registers->control;
                    if (control & 0x80000000U) {
                        memw();
                        unsigned int size = existing_registers->transfer_size;
                        existing->last_progress_frame = frame;
                        existing->last_packet_count = (unsigned char)(size >> 19);
                    } else if (medius_dwc2_fifo_priority_eligible(bus,candidate) == 0) {
                        volatile unsigned int *reset_control = (volatile unsigned int *)(controller + 0x10U);
                        memw();
                        volatile unsigned int migration_polls = 0;
                        for (;;) {
                            memw();
                            unsigned int attempt = migration_polls + 1U;
                            memw();
                            migration_polls = attempt;
                            if (attempt > 200000U)
                                goto release_assignment;
                            memw();
                            if ((*reset_control & 0x80000000U) != 0)
                                break;
                        }
                        memw();
                        migration_polls = 0;
                        memw();
                        *reset_control = (assigned_fifo << 6) | 0x20U;
                        for (;;) {
                            memw();
                            unsigned int attempt = migration_polls + 1U;
                            memw();
                            migration_polls = attempt;
                            if (attempt > 200000U)
                                break;
                            memw();
                            if ((*reset_control & 0x20U) == 0)
                                break;
                        }
release_assignment:
                        {
                            volatile unsigned int *empty_mask = (volatile unsigned int *)(controller + 0x834U);
                            memw();
                            unsigned int enabled = *empty_mask;
                            unsigned char allocated = *allocation_bitmap;
                            memw();
                            *empty_mask = enabled & ~(1U << (candidate & 31U));
                            existing->fifo_index = 0;
                            *allocation_bitmap = (unsigned char)(allocated & ~(1U << (assigned_fifo & 31U)));
                        }
                    }
                }
                if (medius_dwc2_fifo_priority_eligible(bus,index) != 0)
                    allocated_fifo = medius_dwc2_find_free_fifo(bus,index);
            }
        } else if (medius_dwc2_fifo_priority_eligible(bus,index) != 0) {
            allocated_fifo = medius_dwc2_find_free_fifo(bus,index);
        }
        if (allocated_fifo != 0) {
            unsigned char allocated = *allocation_bitmap;
            *allocation_bitmap = (unsigned char)(allocated | (1U << (allocated_fifo & 31U)));
            *(volatile unsigned short *)((unsigned int)transfer + 16U) =
                (unsigned short)((allocated_fifo & 255U) | ((unsigned int)interval << 8));
            fifo = allocated_fifo;
        } else {
            transfer->interval = interval;
            fifo = 0;
        }
    }
    unsigned int fifo_size_address = index == 0 ? controller + 0x28U
        : controller + 0x104U + (fifo != 0 ? fifo - 1U : 0U) * 4U;
    memw();
    unsigned int fifo_size = *(const volatile unsigned int *)fifo_size_address;
    if ((fifo_size >> 16) * 4U < max_packet) {
        __asm__ volatile ("1: j 1b" ::: "memory");
        __builtin_unreachable();
    }
    transfer->max_packet = (unsigned short)max_packet;
    unsigned char attributes = description->attributes;
    transfer->transfer_type = attributes & 3U;
    volatile Dwc2InEndpointRegisters *registers =
        (volatile Dwc2InEndpointRegisters *)(controller + 0x900U + index * 32U);
    volatile unsigned int *interrupt_mask = (volatile unsigned int *)(controller + 0x81cU);
    memw();
    unsigned int enabled = *interrupt_mask;
    memw();
    *interrupt_mask = enabled | (1U << (index & 31U));
    unsigned int packet_field = max_packet;
    if (index == 0) {
        packet_field = max_packet == 8 ? 3 : max_packet == 16 ? 2 : max_packet == 32 ? 1 : 0;
    } else {
        memw();
        unsigned int initial_control = registers->control;
        if (initial_control & 0x80000000U) {
            memw();
            volatile unsigned int disable_polls = 0;
            memw();
            unsigned int control = registers->control;
            memw();
            registers->control = control | 0x08000000U;
            memw();
            control = registers->control;
            memw();
            registers->control = control | 0x40000000U;
            for (;;) {
                memw();
                control = registers->control;
                if ((control & 0x80000000U) == 0)
                    break;
                memw();
                unsigned int attempt = disable_polls + 1U;
                memw();
                disable_polls = attempt;
                if (attempt >= 50000U)
                    break;
            }
            memw();
            registers->interrupt_status = 2;
        }
        memw();
        unsigned int control = registers->control;
        unsigned char sampled_mode = *dynamic_mode;
        memw();
        registers->control = control & 0x3c1fffffU;
        if (sampled_mode != 0) {
            medius_dwc2_remove_scheduled_transfer(bus,index,0);
            controller = (unsigned int)binding->registers;
            fifo = transfer->fifo_index;
            attributes = description->attributes;
            registers = (volatile Dwc2InEndpointRegisters *)(controller + 0x900U + index * 32U);
        }
    }
    memw();
    unsigned int control = registers->control;
    memw();
    registers->control = control | ((unsigned int)(attributes & 3U) << 18) | packet_field |
                         (fifo << 22) | 0x10008000U;
    if (fifo != 0 || index == 0) {
        volatile unsigned int *reset_control = (volatile unsigned int *)(controller + 0x10U);
        memw();
        volatile unsigned int final_polls = 0;
        for (;;) {
            memw();
            unsigned int attempt = final_polls + 1U;
            memw();
            final_polls = attempt;
            if (attempt > 200000U)
                goto unlocked;
            memw();
            if ((*reset_control & 0x80000000U) != 0)
                break;
        }
        memw();
        final_polls = 0;
        memw();
        *reset_control = (fifo << 6) | 0x20U;
        for (;;) {
            memw();
            unsigned int attempt = final_polls + 1U;
            memw();
            final_polls = attempt;
            if (attempt > 200000U)
                break;
            memw();
            if ((*reset_control & 0x20U) == 0)
                break;
        }
    }
unlocked:
    xPortInIsrContext();
    vPortExitCritical(MEDIUS_DWC2_DRIVER_LOCK);
    return 0;
}

/* Native entry: 0x40380de8. */
/*
 * Medius v3.4.7 — device application; 0x40380de8.
 *
 * Closes an endpoint with direction-specific disable polling, low3 routing-mask selection and
 * forced IN queue/FIFO cleanup.
 *
 * Calls: xPortInIsrContext, medius_dwc2_remove_scheduled_transfer, vPortExitCritical,
 * xPortEnterCriticalTimeout.
 *
 * Called by: usbd_setup_request_handler, FUN_40391bc0, FUN_42028cbc.
 *
 * Original function-byte SHA-256:
 * e25b8cd4372a1bc9609e6f5d371dd897c67adbacc1b2c013efd54ce21b50a4a8.
 */

/*
 * bus: Raw8 controller-slot index with stride8; no bus/storage bounds guard.
 * endpoint: Raw8 USB address: bit7 chooses IN, low7 selects the register index, but LOW3 selects
 *   routing-mask bit.
 * Returns: Always0, including timeout and ignored critical-entry/cleanup failures.
 * Requirements/effects: Initializes a volatile poll counter. OUT performs no local lock; IN
 *   queries ISR context/enters shared driver mux with infinite wait ignoring status, then loads
 *   controller base. Initial EPENAset causes fresh CTL read/OR SNAK and another fresh CTL read/OR
 *   literal EPDIS0x40000000. Poll increments before >50000 admission, allowing50000 reads and
 *   ending50001 on timeout: counter load/increment store have separate MEMW barriers and the
 *   bound compares the cached increment. OUT waits DOEPINT bit1 set, IN waits DIEPCTL EPENAclear. Both
 *   acknowledge interrupt2 after the attempt; initially disabled skips disable/poll/ack. Clears
 *   DEACHINTMSK then DAINTMSK bit(low3 endpoint for IN,16+low3 for OUT). Reads current CTL, writes
 *   masked0x3fdfffff then a separate literal0. IN nonzero endpoint always delegates scheduled
 *   removal(bus,low7,force1) under lock regardless of dynamic mode; IN EP0 skips it. IN then
 *   queries ISR context/unlocks. No local endpoint record/count/buffer/DMA reset, completion
 *   callback, pointer/index/hardware-count validation, rollback or physical disable guarantee. Raw
 *   register index8 may therefore clear routing bit0. Timeout cleanup continues and iteration
 *   bounds are not elapsed-time guarantees; delegated forced release and concurrent lifetime
 *   remain separate.
 */

int usbd_ep_close(unsigned char bus,unsigned char endpoint)
{
    unsigned int index = endpoint & 0x7fU;
    int input_direction = (endpoint & 0x80U) != 0;
    memw();
    volatile unsigned int poll_count = 0;
    if (input_direction) {
        xPortInIsrContext();
        xPortEnterCriticalTimeout(MEDIUS_DWC2_DRIVER_LOCK,0xffffffffU);
    }
    volatile MediusDwc2CoreRegisters *registers = MEDIUS_USBD_CONTROLLERS[bus].registers;
    unsigned int controller = (unsigned int)registers;
    unsigned int endpoint_registers = controller + (input_direction ? 0x900U : 0xb00U) + index * 32U;
    volatile unsigned int *control = (volatile unsigned int *)endpoint_registers; /* DIEPCTL / DOEPCTL */
    volatile unsigned int *interrupt_status = (volatile unsigned int *)(endpoint_registers + 8U);
    memw();
    unsigned int initial_control = *control;
    if (initial_control & 0x80000000U) { /* EPENA */
        memw();
        unsigned int current_control = *control;
        memw();
        *control = current_control | 0x08000000U; /* SNAK */
        memw();
        current_control = *control;
        memw();
        *control = current_control | 0x40000000U; /* EPDIS, not a ROM symbol. */
        memw();
        poll_count = 0;
        for (;;) {
            memw();
            unsigned int attempt = poll_count + 1U;
            memw();
            poll_count = attempt;
            if (attempt > 50000U)
                break;
            memw();
            if (input_direction) {
                if ((*control & 0x80000000U) == 0)
                    break;
            } else if ((*interrupt_status & 2U) != 0) {
                break;
            }
        }
        memw();
        *interrupt_status = 2;
    }
    unsigned int routing_bit = (endpoint & 7U) + (input_direction ? 0U : 16U);
    unsigned int retain_mask = ~(1U << routing_bit);
    volatile unsigned int *each_interrupt_mask = &registers->each_endpoint_mask; /* DEACHINTMSK */
    volatile unsigned int *all_interrupt_mask = &registers->all_endpoint_mask; /* DAINTMSK */
    memw();
    unsigned int enabled = *each_interrupt_mask;
    memw();
    *each_interrupt_mask = enabled & retain_mask;
    memw();
    enabled = *all_interrupt_mask;
    memw();
    *all_interrupt_mask = enabled & retain_mask;
    memw();
    unsigned int current_control = *control;
    memw();
    *control = current_control & 0x3fdfffffU; /* EPENA/EPDIS/STALL clear. */
    memw();
    *control = 0; /* A second distinct register write. */
    if (input_direction) {
        if (index != 0)
            medius_dwc2_remove_scheduled_transfer(bus,index,1);
        xPortInIsrContext();
        vPortExitCritical(MEDIUS_DWC2_DRIVER_LOCK);
    }
    return 0;
}

/* Native entry: 0x40380f74. */
/*
 * Medius v3.4.7 — device application; 0x40380f74.
 *
 * Sets endpoint STALL, applying direction/EP0-specific cleanup and preserving live register and
 * timeout behavior.
 *
 * Calls: xPortInIsrContext, medius_dwc2_remove_scheduled_transfer, vPortExitCritical,
 * xPortEnterCriticalTimeout.
 *
 * Called by: usb_device_set_stall.
 *
 * Original function-byte SHA-256:
 * d5cbd098b434429892ac5bfb198f801d12e7f9a9ad26cc60eb39cf7f1b3ebb97.
 */

/*
 * bus: Raw8 controller/context selector; no bus bounds guard.
 * endpoint: Raw8 direction plus low7 register/record index; empty-mask selection narrows to low5.
 * Returns: Always0 on ordinary paths, including disable/flush timeouts and ignored critical-
 *   entry/cleanup statuses.
 * Requirements/effects: OUT has no lock: reads initial CTL and a fresh snapshot; only initially
 *   disabled nonzero endpoint clears EPDIS, then rereads for STALL. Enabled OUT/OUT EP0 simply OR
 *   STALL from a fresh read. IN locks first and loads base afterward. IN EP0 performs two
 *   additional CTL reads and uses only the last for STALL, skipping all polling/cleanup/count
 *   clearing. Initially enabled nonzero IN uses separate SNAK/EPDIS RMWs and a50000-read EPENA
 *   wait ending counter50001. Reads dynamic byte BEFORE acknowledgement2. Static mode snapshots
 *   CTL/FIFO before200000-read idle/flush waits; timeout counter200001 continues mask clearing.
 *   Dynamic mode instead removes scheduled work and reloads controller/register. Samples final CTL
 *   sign BEFORE locally clearing requested/actual. Initially disabled nonzero IN skips local
 *   polling/flush/mask/count clearing; dynamic still removes scheduled work/reloads base, static
 *   simply rereads CTL. Final handling uses cached sign but fresh RMW values: enabled ORs STALL
 *   only; disabled clears EPDIS then rereads/ORs STALL. Later snapshots may reintroduce EPDIS or
 *   enable. IN unlocks before returning or EP0 rearm. Either EP0 direction then freshly samples
 *   DMA; nonzero reloads base, writes OUTEP0 size0x20080008/setup DMA=context base and fresh
 *   OUTCTL OR0x80008000. Nonzero endpoints never rearm setup. No hardware-count/pointer/lifetime
 *   validation, local rollback or quiescence status. Stalled does not imply canceled software
 *   counts; iteration limits do not guarantee elapsed time, flush/disable success or physical
 *   STALL/DMA/W1C behavior.
 */

int usbd_ep_set_stall(unsigned char bus,unsigned char endpoint)
{
    unsigned int index = endpoint & 0x7fU;
    volatile MediusUsbdControllerBinding *binding = &MEDIUS_USBD_CONTROLLERS[bus];
    volatile MediusDwc2DeviceContext *context = (volatile MediusDwc2DeviceContext *)
        (MEDIUS_DWC2_CONTEXT_BASE + (unsigned int)bus * sizeof(MediusDwc2DeviceContext));
    if ((endpoint & 0x80U) == 0) {
        unsigned int controller = (unsigned int)binding->registers;
        volatile MediusDwc2OutEndpointRegisters *registers =
            (volatile MediusDwc2OutEndpointRegisters *)(controller + 0xb00U + index * 32U);
        memw();
        unsigned int initial_control = registers->control;
        memw();
        unsigned int current_control = registers->control;
        if ((initial_control & 0x80000000U) == 0 && index != 0) {
            memw();
            registers->control = current_control & 0xbfffffffU;
            memw();
            current_control = registers->control;
        }
        memw();
        registers->control = current_control | 0x00200000U;
        if (index != 0)
            return 0;
    } else {
        xPortInIsrContext();
        xPortEnterCriticalTimeout(MEDIUS_DWC2_DRIVER_LOCK,0xffffffffU);
        unsigned int controller = (unsigned int)binding->registers;
        volatile Dwc2InEndpointRegisters *registers =
            (volatile Dwc2InEndpointRegisters *)(controller + 0x900U + index * 32U);
        memw();
        unsigned int initial_control = registers->control;
        if (index == 0) {
            memw();
            (void)registers->control; /* First additional EP0 snapshot is discarded. */
            memw();
            unsigned int last_control = registers->control;
            memw();
            registers->control = last_control | 0x00200000U;
        } else {
            unsigned int decision_control;
            if (initial_control & 0x80000000U) {
                memw();
                volatile unsigned int disable_polls = 0;
                memw();
                unsigned int current_control = registers->control;
                memw();
                registers->control = current_control | 0x08000000U;
                memw();
                current_control = registers->control;
                memw();
                registers->control = current_control | 0x40000000U;
                for (;;) {
                    memw();
                    unsigned int attempt = disable_polls + 1U;
                    memw();
                    disable_polls = attempt;
                    if (attempt > 50000U)
                        break;
                    memw();
                    if ((registers->control & 0x80000000U) == 0)
                        break;
                }
                unsigned char dynamic_mode = USB_DWC2_DYNAMIC_FIFO_MODES[bus];
                memw();
                registers->interrupt_status = 2;
                if (dynamic_mode == 0) {
                    memw();
                    unsigned int fifo_control = registers->control; /* Snapshot BEFORE idle wait. */
                    volatile unsigned int *reset_control = (volatile unsigned int *)(controller + 0x10U);
                    memw();
                    volatile unsigned int flush_polls = 0;
                    for (;;) {
                        memw();
                        unsigned int attempt = flush_polls + 1U;
                        memw();
                        flush_polls = attempt;
                        if (attempt > 200000U)
                            goto clear_empty_interrupt;
                        memw();
                        if ((*reset_control & 0x80000000U) != 0)
                            break;
                    }
                    memw();
                    flush_polls = 0;
                    memw();
                    *reset_control = ((fifo_control >> 16) & 0x3c0U) | 0x20U;
                    for (;;) {
                        memw();
                        unsigned int attempt = flush_polls + 1U;
                        memw();
                        flush_polls = attempt;
                        if (attempt > 200000U)
                            break;
                        memw();
                        if ((*reset_control & 0x20U) == 0)
                            break;
                    }
clear_empty_interrupt:
                    {
                        volatile unsigned int *empty_mask = (volatile unsigned int *)(controller + 0x834U);
                        memw();
                        unsigned int enabled = *empty_mask;
                        memw();
                        *empty_mask = enabled & ~(1U << (index & 31U));
                    }
                } else {
                    medius_dwc2_remove_scheduled_transfer(bus,index,0);
                    controller = (unsigned int)binding->registers;
                    registers = (volatile Dwc2InEndpointRegisters *)(controller + 0x900U + index * 32U);
                }
                volatile MediusDwc2Endpoint *transfer = (volatile MediusDwc2Endpoint *)
                    &context->input_endpoints[index];
                memw();
                decision_control = registers->control; /* Sign decision precedes count clears. */
                transfer->requested = 0;
                transfer->actual = 0;
            } else {
                if (USB_DWC2_DYNAMIC_FIFO_MODES[bus] != 0) {
                    medius_dwc2_remove_scheduled_transfer(bus,index,0);
                    controller = (unsigned int)binding->registers;
                    registers = (volatile Dwc2InEndpointRegisters *)(controller + 0x900U + index * 32U);
                }
                memw();
                decision_control = registers->control;
            }
            memw();
            unsigned int current_control = registers->control;
            if ((decision_control & 0x80000000U) == 0) {
                memw();
                registers->control = current_control & 0xbfffffffU;
                memw();
                current_control = registers->control;
            }
            memw();
            registers->control = current_control | 0x00200000U;
        }
        xPortInIsrContext();
        vPortExitCritical(MEDIUS_DWC2_DRIVER_LOCK);
        if (index != 0)
            return 0;
    }
    /* Either EP0 direction samples DMA AFTER its STALL write / IN unlock. */
    if (context->parameters.dma_enabled != 0) {
        unsigned int controller = (unsigned int)binding->registers;
        volatile MediusDwc2OutEndpointRegisters *setup =
            (volatile MediusDwc2OutEndpointRegisters *)(controller + 0xb00U);
        memw();
        setup->transfer_size = 0x20080008U;
        memw();
        setup->dma_address = (unsigned int)context;
        memw();
        unsigned int control = setup->control;
        memw();
        setup->control = control | 0x80008000U; /* EPENA | USBAEP, not CNAK. */
    }
    return 0;
}

/* Native entry: 0x40381208. */
/*
 * Medius v3.4.7 — device application; 0x40381208.
 *
 * Clears endpoint STALL with distinct OUT reread and IN single-snapshot enable/PID rules.
 *
 * Calls: xPortInIsrContext, vPortExitCritical, xPortEnterCriticalTimeout.
 *
 * Called by: usbd_setup_request_handler, FUN_40395b94, medius_nonzero_control_setup.
 *
 * Original function-byte SHA-256:
 * a0d903b0f7bbe94a07affa4a77cf1a047f00680dcf5784798fe49849fe992edc.
 */

/*
 * bus: Configured controller/transfer-state slot; no bounds check.
 * endpoint: Encoded endpoint address: bit 7 selects IN, low seven bits select the raw index.
 * Returns: Always 0 after the selected register operations.
 * Requirements/effects: OUT clears STALL bit 21 with a control-register read/modify/write;
 *   software types exactly 2 or 3 then perform a fresh control read/OR of DATA0 bit 28. OUT takes
 *   no lock. IN requests the driver critical section indefinitely, ignores entry status, samples
 *   control once, clears STALL/EPENA/EPDIS, and adds DATA0 only when the original EPENA was clear
 *   and software type is 2 or 3. It then writes that derived snapshot once and unlocks. All other
 *   original control bits are retained according to the masks. EP0 follows the same rules. Raw
 *   endpoint indices/types are not validated. No disable polling, transfer-count update, FIFO
 *   cleanup, DMA operation or completion callback occurs here. Fresh OUT and cached IN behavior
 *   differ deliberately; neither path confirms a physical PID reset or USB handshake.
 */

int usbd_ep_clear_stall(unsigned char bus,unsigned char endpoint)
{
    unsigned int endpoint_index = endpoint & 0x7fU;
    volatile MediusDwc2DeviceContext *context = (volatile MediusDwc2DeviceContext *)
        (MEDIUS_DWC2_CONTEXT_BASE + (unsigned int)bus * sizeof(MediusDwc2DeviceContext));
    if ((endpoint & 0x80U) == 0) {
        unsigned int controller = (unsigned int)MEDIUS_USBD_CONTROLLERS[bus].registers;
        volatile MediusDwc2OutEndpointRegisters *registers =
            (volatile MediusDwc2OutEndpointRegisters *)(controller + 0xb00U + endpoint_index * 32U);
        memw();
        unsigned int control_snapshot = registers->control;
        memw();
        registers->control = control_snapshot & 0xffdfffffU;
        unsigned char type = context->output_endpoints[endpoint_index].transfer_type;
        if ((unsigned char)(type - 2U) < 2U) {
            memw();
            control_snapshot = registers->control;
            memw();
            registers->control = control_snapshot | 0x10000000U;
        }
    } else {
        xPortInIsrContext();
        xPortEnterCriticalTimeout(MEDIUS_DWC2_DRIVER_LOCK,0xffffffffU);
        unsigned int controller = (unsigned int)MEDIUS_USBD_CONTROLLERS[bus].registers;
        volatile Dwc2InEndpointRegisters *registers =
            (volatile Dwc2InEndpointRegisters *)(controller + 0x900U + endpoint_index * 32U);
        memw();
        unsigned int control_snapshot = registers->control;
        unsigned int next_control = control_snapshot & 0x3fdfffffU;
        if ((control_snapshot & 0x80000000U) == 0) {
            unsigned char type = context->input_endpoints[endpoint_index].transfer_type;
            if ((unsigned char)(type - 2U) < 2U)
                next_control |= 0x10000000U;
        }
        memw();
        registers->control = next_control;
        xPortInIsrContext();
        vPortExitCritical(MEDIUS_DWC2_DRIVER_LOCK);
    }
    return 0;
}

/* Native entry: 0x403812d0. */
/*
 * Medius v3.4.7 — device application; 0x403812d0.
 *
 * Removes idle dynamic IN work or flushes an idle assigned hardware FIFO, with path-specific
 * transfer-count locking.
 *
 * Calls: xPortInIsrContext, medius_dwc2_remove_scheduled_transfer, vPortExitCritical,
 * xPortEnterCriticalTimeout.
 *
 * Called by: FUN_40395b94.
 *
 * Original function-byte SHA-256:
 * d2b4c6f6d92a309f565c97f6296d3feef155aab4955fc4fa2c5d4edcf5ef6d42.
 */

/*
 * bus: Raw8 bus; controller pointer slot stride8 and transfer context stride0x3e4 have no bounds
 *   guard.
 * endpoint: Raw8 endpoint; low7 selects IN register/record, low5 selects the empty-interrupt-mask
 *   bit.
 * Returns: No value or timeout/quiescence status.
 * Requirements/effects: EP0 snapshots controller and performs one volatile DIEPCTL0 read, then
 *   returns without lock or writes. Nonzero dynamic mode enters the driver mux with infinite wait,
 *   ignoring entry status; freshly rechecks mode and, if still set, reads fresh controller/EPENA.
 *   Idle dynamic endpoint delegates scheduled removal, clears requested/actual under lock and
 *   returns after unlock. Disappearing mode or enabled dynamic endpoint unlocks and falls through.
 *   Ordinary path snapshots controller/CTL FIFO nibble; FIFO0 returns before a second CTL read.
 *   Nonzero FIFO independently rereads EPENA and returns if enabled. Otherwise locks, reloads
 *   controller but retains FIFO and never rechecks enable/assignment. Two poll phases increment a
 *   volatile counter before >200000 admission, permitting200000 MMIO reads and ending at200001 on
 *   timeout. Idle timeout skips command; otherwise commands cached FIFO/TX flush and polls bit5.
 *   Both outcomes clear fresh-controller DIEPEMPMSK bit(index&31), unlock, THEN clear
 *   requested/actual. Buffer pointers, flags, FIFO assignment and bitmap remain locally unchanged;
 *   delegated cleanup has separate effects. No index, capacity, lock-success or concurrent-
 *   lifetime validation. Iteration bounds do not guarantee elapsed time, successful flush or
 *   hardware quiescence.
 */

void medius_dwc2_in_fifo_cancel(unsigned char bus,unsigned char endpoint)
{
    unsigned int index = endpoint & 0x7fU;
    volatile MediusUsbdControllerBinding *binding = &MEDIUS_USBD_CONTROLLERS[bus];
    volatile MediusDwc2DeviceContext *context = (volatile MediusDwc2DeviceContext *)
        (MEDIUS_DWC2_CONTEXT_BASE + (unsigned int)bus * sizeof(MediusDwc2DeviceContext));
    if (index == 0) {
        unsigned int controller = (unsigned int)binding->registers;
        volatile Dwc2InEndpointRegisters *registers =
            (volatile Dwc2InEndpointRegisters *)(controller + 0x900U);
        memw();
        (void)registers->control; /* Native EP0 path is not read-free. */
        return;
    }
    volatile unsigned char *dynamic_mode =
        &USB_DWC2_DYNAMIC_FIFO_MODES[bus];
    volatile MediusDwc2Endpoint *transfer = (volatile MediusDwc2Endpoint *)
        &context->input_endpoints[index];
    if (*dynamic_mode != 0) {
        xPortInIsrContext();
        xPortEnterCriticalTimeout(MEDIUS_DWC2_DRIVER_LOCK,0xffffffffU);
        if (*dynamic_mode != 0) {
            unsigned int controller = (unsigned int)binding->registers;
            volatile Dwc2InEndpointRegisters *registers =
                (volatile Dwc2InEndpointRegisters *)(controller + 0x900U + index * 32U);
            memw();
            if ((registers->control & 0x80000000U) == 0) {
                medius_dwc2_remove_scheduled_transfer(bus,index,0);
                transfer->requested = 0;
                transfer->actual = 0;
                xPortInIsrContext();
                vPortExitCritical(MEDIUS_DWC2_DRIVER_LOCK);
                return;
            }
        }
        xPortInIsrContext();
        vPortExitCritical(MEDIUS_DWC2_DRIVER_LOCK);
    }
    unsigned int controller = (unsigned int)binding->registers;
    volatile Dwc2InEndpointRegisters *registers =
        (volatile Dwc2InEndpointRegisters *)(controller + 0x900U + index * 32U);
    memw();
    unsigned int fifo = (registers->control >> 22) & 15U;
    if (fifo == 0)
        return;
    memw();
    if ((registers->control & 0x80000000U) != 0)
        return;
    xPortInIsrContext();
    xPortEnterCriticalTimeout(MEDIUS_DWC2_DRIVER_LOCK,0xffffffffU);
    controller = (unsigned int)binding->registers; /* Fresh base, but keep the earlier FIFO. */
    volatile unsigned int *reset_control = (volatile unsigned int *)(controller + 0x10U); /* GRSTCTL */
    memw();
    volatile unsigned int poll_count = 0;
    for (;;) {
        memw();
        unsigned int attempt = poll_count + 1U;
        memw();
        poll_count = attempt;
        if (attempt > 200000U)
            goto clear_empty_interrupt;
        memw();
        if ((*reset_control & 0x80000000U) != 0) /* AHBIDL */
            break;
    }
    memw();
    poll_count = 0;
    memw();
    *reset_control = (fifo << 6) | 0x20U; /* TXFNUM / TXFFLSH */
    for (;;) {
        memw();
        unsigned int attempt = poll_count + 1U;
        memw();
        poll_count = attempt;
        if (attempt > 200000U)
            break;
        memw();
        if ((*reset_control & 0x20U) == 0)
            break;
    }
clear_empty_interrupt:
    {
        volatile unsigned int *empty_mask = (volatile unsigned int *)(controller + 0x834U); /* DIEPEMPMSK */
        memw();
        unsigned int enabled = *empty_mask;
        unsigned int remaining = enabled & ~(1U << (index & 31U));
        memw();
        *empty_mask = remaining;
    }
    xPortInIsrContext();
    vPortExitCritical(MEDIUS_DWC2_DRIVER_LOCK);
    /* Ordinary cancellation clears counts AFTER the lock is released. */
    transfer->requested = 0;
    transfer->actual = 0;
}

/* Native entry: 0x40381424. */
/*
 * Medius v3.4.7 — device application; 0x40381424.
 *
 * Reads one selected endpoint control snapshot and stores STALL bit21 as a single output byte.
 *
 * Called by: usbd_setup_request_handler.
 *
 * Original function-byte SHA-256:
 * 4aa3fb4b0a2e9017f76af1d695a1dadd573ff29347380eabd329d9f9216524e5.
 */

/*
 * bus: Configured controller slot; no bounds check is supplied.
 * endpoint: Encoded address: bit 7 selects IN, low seven bits select the raw register index.
 * stalled: Writable byte output; must remain valid through the synchronous call.
 * Returns: Always 0 after storing STALL bit 21 as a 0/1 byte.
 * Requirements/effects: Reads the current controller base, executes MEMW and samples one endpoint
 *   control register at base+0x900 (IN) or +0xb00 (OUT), with stride 0x20. No write to hardware or
 *   lock occurs. Raw indices are not restricted to the hardware endpoint count. The result is one
 *   register snapshot, with no USB handshake or concurrent-state guarantee.
 */

int usbd_ep_is_stalled(unsigned char bus,unsigned char endpoint,unsigned char *stalled)
{
    unsigned int controller = (unsigned int)MEDIUS_USBD_CONTROLLERS[bus].registers;
    unsigned int endpoint_index = endpoint & 0x7fU;
    unsigned int direction_offset = (endpoint & 0x80U) != 0 ? 0x900U : 0xb00U;
    const volatile unsigned int *control = (const volatile unsigned int *)
        (controller + direction_offset + endpoint_index * 32U);
    memw();
    unsigned int control_snapshot = *control;
    *stalled = (unsigned char)((control_snapshot >> 21) & 1U);
    return 0;
}

/* Native entry: 0x40381460. */
/*
 * Medius v3.4.7 — device application; 0x40381460.
 *
 * Publishes an IN transfer and selects immediate FIFO service, dynamic queueing or DMA, preserving
 * distinct zero-length and failure paths.
 *
 * Calls: xPortInIsrContext, dwc2_tx_fifo_empty_process, medius_dwc2_schedule_in, usbd_get_ep_mult,
 * vPortExitCritical, xPortEnterCriticalTimeout.
 *
 * Called by: usb_device_write_aligned.
 *
 * Original function-byte SHA-256:
 * 8d9aa7d8b9a10ae6620812a932261657c24aa53fb4e84cd03a4fd253ae47d2c8.
 */

/*
 * bus: Raw8 controller/context selector, without local bus bounds checks.
 * endpoint: Raw8 address; low7 always selects IN state/registers, raw direction is retained only
 *   for multiplier lookup and low4 for empty-mask bit.
 * buffer: Borrowed readable aligned4 storage retained as both current and original buffer;
 *   lifetime must cover asynchronous FIFO/DMA/queued use.
 * length: Full32-bit request; EP0 caps a positive input to full16 software MPS, others retain
 *   requested while hardware fields narrow independently.
 * Returns: 0 after delegated/armed transfer and unlock; -1 for NULL/nonzero length; -2 for nonzero
 *   endpoint hardware MPS0. Misalignment self-loops; software MPS0 can reach QUOU fault after
 *   partial publication.
 * Requirements/effects: Alignment guard precedes all state access; NULL/nonzero rejects before
 *   controller load. Caches base and admits nonzero endpoint only for CTL low11 MPS!=0. Clears
 *   cancelled, reads size, then publishes EP0 buffers/current+original/requested/actual0 or
 *   nonzero actual0/buffers/requested, all before lock. Performs packet-count clear then fresh
 *   size clear. Original length0 sets one packet, locks, and fresh dynamic nonzero endpoint
 *   schedules0 regardless DMA; EP0/static reload base and arm, skipping
 *   DMA/type/parity/multiplier/empty-mask work. Positive EP0 caps requested and uses one packet;
 *   cap0 stays positive. Positive nonzero reads MPS once, unsigned-wraps numerator and executes
 *   QUOU, narrowing packet10/size19 bits. Fresh exact type1 uses DSTS/frame parity through
 *   separate CTL RMWs. Cached type1/3 clears multiplier bits, calls getter with raw endpoint,
 *   reloads base and ORs returned-byte-plus1 low2 into fresh size. Locks ignoring entry status;
 *   samples DMA BEFORE optional nonzero-endpoint mode read. Cached DMA nonzero reloads base/writes
 *   original buffer/arms, taking priority over dynamic scheduling. DMA0/dynamic schedules
 *   effective length; otherwise reloads base/arms locally. Effective length0 skips empty mask.
 *   Positive EP0 sets low4 mask bit; other endpoints freshly read type, service exact3, then read
 *   actual BEFORE requested and set bit only if still incomplete; other types set it directly.
 *   Mask uses pre-service cached base despite global pointer mutation. Unlocks; all helper
 *   statuses ignored. No capacity/busy/hardware-index guard, submission copy, cancellation
 *   callback, rollback or ownership transfer. Fault dispatch, physical DMA/USB/scheduling and
 *   concurrent lifetime remain external.
 */

int usbd_ep_start_write(unsigned char bus,unsigned char endpoint,unsigned char *buffer,unsigned int length)
{
    if (((unsigned int)buffer & 3U) != 0) {
        __asm__ volatile ("1: j 1b" ::: "memory");
        __builtin_unreachable();
    }
    if (buffer == 0 && length != 0)
        return -1;
    volatile MediusDwc2DeviceContext *context = (volatile MediusDwc2DeviceContext *)
        (MEDIUS_DWC2_CONTEXT_BASE + (unsigned int)bus * sizeof(MediusDwc2DeviceContext));
    volatile MediusUsbdControllerBinding *binding = &MEDIUS_USBD_CONTROLLERS[bus];
    unsigned int controller = (unsigned int)binding->registers;
    unsigned int endpoint_index = endpoint & 0x7fU;
    volatile Dwc2InEndpointRegisters *registers =
        (volatile Dwc2InEndpointRegisters *)(controller + 0x900U + endpoint_index * 32U);
    volatile MediusDwc2Endpoint *transfer = (volatile MediusDwc2Endpoint *)
        ((unsigned int)context + __builtin_offsetof(MediusDwc2DeviceContext,input_endpoints) + endpoint_index * sizeof(MediusDwc2Endpoint));
    if (endpoint_index != 0) {
        memw();
        if ((registers->control & 0x7ffU) == 0)
            return -2;
    }
    transfer->cancelled = 0;
    memw();
    unsigned int size = registers->transfer_size;
    if (endpoint_index == 0) {
        transfer->buffer = buffer;
        transfer->initial_buffer = buffer;
        transfer->requested = length;
        transfer->actual = 0;
    } else {
        transfer->actual = 0;
        transfer->buffer = buffer;
        transfer->initial_buffer = buffer;
        transfer->requested = length;
    }
    memw();
    registers->transfer_size = size & 0xe007ffffU;
    memw();
    size = registers->transfer_size;
    memw();
    registers->transfer_size = size & 0xfff80000U;
    if (length == 0) {
        memw();
        size = registers->transfer_size;
        memw();
        registers->transfer_size = size | 0x80000U;
        xPortInIsrContext();
        xPortEnterCriticalTimeout(MEDIUS_DWC2_DRIVER_LOCK,0xffffffffU);
        if (endpoint_index != 0 && USB_DWC2_DYNAMIC_FIFO_MODES[bus] != 0) {
            medius_dwc2_schedule_in(bus,endpoint_index,0);
        } else {
            controller = (unsigned int)binding->registers;
            registers = (volatile Dwc2InEndpointRegisters *)(controller + 0x900U + endpoint_index * 32U);
            memw();
            unsigned int control = registers->control;
            memw();
            registers->control = control | 0x84000000U;
        }
        goto unlock_driver;
    }
    if (endpoint_index == 0) {
        unsigned int maximum_packet = transfer->max_packet;
        memw();
        size = registers->transfer_size;
        length = length < maximum_packet ? length : maximum_packet;
        transfer->requested = length;
        memw();
        registers->transfer_size = size | 0x80000U;
        memw();
        size = registers->transfer_size;
        memw();
        registers->transfer_size = size | length;
    } else {
        unsigned int maximum_packet = transfer->max_packet;
        unsigned int numerator = length - 1U + maximum_packet;
        unsigned int packets;
        __asm__ volatile ("quou %0,%1,%2" : "=a"(packets) : "a"(numerator),"a"(maximum_packet) : "memory");
        memw();
        size = registers->transfer_size;
        memw();
        registers->transfer_size = size | ((packets & 0x3ffU) << 19);
        memw();
        size = registers->transfer_size;
        memw();
        registers->transfer_size = size | (length & 0x7ffffU);
    }
    unsigned char transfer_type = transfer->transfer_type;
    if (transfer_type == 1) {
        memw();
        unsigned int device_status = ((const volatile MediusDwc2CoreRegisters *)controller)->device_status;
        memw();
        unsigned int control = registers->control;
        if ((device_status & 0x100U) == 0) {
            memw();
            registers->control = control & 0xefffffffU;
            memw();
            control = registers->control;
            memw();
            registers->control = control | 0x20000000U;
        } else {
            memw();
            registers->control = control & 0xdfffffffU;
            memw();
            control = registers->control;
            memw();
            registers->control = control | 0x10000000U;
        }
    }
    if (transfer_type == 1 || transfer_type == 3) {
        memw();
        size = registers->transfer_size;
        memw();
        registers->transfer_size = size & 0x9fffffffU;
        unsigned char multiplier = usbd_get_ep_mult(bus,endpoint); /* Retain raw direction. */
        controller = (unsigned int)binding->registers;
        registers = (volatile Dwc2InEndpointRegisters *)(controller + 0x900U + endpoint_index * 32U);
        memw();
        size = registers->transfer_size;
        memw();
        registers->transfer_size = size | (((unsigned int)(multiplier + 1U) & 3U) << 29);
    }
    xPortInIsrContext();
    xPortEnterCriticalTimeout(MEDIUS_DWC2_DRIVER_LOCK,0xffffffffU);
    /* DMA is sampled BEFORE mode, and retained across that later read. */
    unsigned char dma_enabled = context->parameters.dma_enabled;
    unsigned char dynamic_mode = 0;
    if (endpoint_index != 0)
        dynamic_mode = USB_DWC2_DYNAMIC_FIFO_MODES[bus];
    if (dma_enabled != 0) {
        controller = (unsigned int)binding->registers;
        registers = (volatile Dwc2InEndpointRegisters *)(controller + 0x900U + endpoint_index * 32U);
        memw();
        registers->dma_address = (unsigned int)buffer;
        memw();
        unsigned int control = registers->control;
        memw();
        registers->control = control | 0x84000000U;
    } else if (dynamic_mode != 0) {
        medius_dwc2_schedule_in(bus,endpoint_index,length);
    } else {
        controller = (unsigned int)binding->registers;
        registers = (volatile Dwc2InEndpointRegisters *)(controller + 0x900U + endpoint_index * 32U);
        memw();
        unsigned int control = registers->control;
        memw();
        registers->control = control | 0x84000000U;
        if (length != 0) {
            if (endpoint_index != 0 && transfer->transfer_type == 3) {
                dwc2_tx_fifo_empty_process(bus,(unsigned char)endpoint_index);
                unsigned int actual = transfer->actual;
                unsigned int requested = transfer->requested;
                if (actual >= requested)
                    goto unlock_driver;
            }
            /* Keep this arm-time controller even if FIFO service changes slot. */
            volatile unsigned int *empty_mask = (volatile unsigned int *)(controller + 0x834U);
            memw();
            unsigned int enabled = *empty_mask;
            memw();
            *empty_mask = enabled | (1U << (endpoint & 15U));
        }
    }
unlock_driver:
    xPortInIsrContext();
    vPortExitCritical(MEDIUS_DWC2_DRIVER_LOCK);
    return 0;
}

/* Native entry: 0x40381810. */
/*
 * Medius v3.4.7 — device application; 0x40381810.
 *
 * Publishes an OUT receive buffer and arms the endpoint, with cached DMA mode, distinct
 * original-zero behavior and no local lock.
 *
 * Called by: usbd_event_ep0_in_complete_handler, usbd_event_ep0_out_complete_handler, medius_nonzero_control_in_complete,
 * medius_nonzero_control_setup, medius_out_try_rearm, usbd_ep0_thread.
 *
 * Original function-byte SHA-256:
 * 76524074ac8aed036f2142775ec45300296d7e33f9e13bcf0eba1fd7d4153756.
 */

/*
 * bus: Raw8 bus index; context stride0x3e4/controller slot stride8 have no bounds checks.
 * endpoint: Raw8 address; low7 selects OUT record/register regardless of direction bit.
 * buffer: Borrowed writable aligned4 buffer retained for asynchronous receive; NULL is rejected
 *   only for nonzero length.
 * length: Full32-bit request; software counts and separately narrowed hardware size/packet fields
 *   may differ.
 * Returns: 0 after arm, -1 for NULL/nonzero length, -2 for a nonzero endpoint with hardware MPS0.
 *   Unaligned buffer self-loops; nonzero endpoint/software MPS0 executes QUOU and can fault after
 *   partial publication.
 * Requirements/effects: Alignment guard precedes every data/state access, even length0. Samples
 *   DMA byte once before NULL validation, then caches controller. EP0 bypasses hardware-MPS
 *   admission; nonzero requires CTL low11!=0. Reads old size before publishing EP0
 *   buffer/requested/actual0, or nonzero actual0/buffer/requested, preserving other record fields.
 *   Writes packet-count clear, then a fresh size-field clear. Original length0 programs one
 *   packet/full16 software MPS, arms directly and skips DMA/type/parity, retaining requested0 and
 *   stale DMA. Positive EP0 caps requested to min(length,full16 MPS), programs one packet and
 *   capped size; cap0 still uses the positive path. Positive nonzero reads software MPS once,
 *   unsigned-wraps length-1+MPS, executes QUOU, masks packets10 bits and size19 bits. Division0
 *   reaches the architecture fault instruction after state/size clears. Cached DMA nonzero writes
 *   original buffer; freshly read exact type1 reads DSTS frame bit8 and uses two fresh CTL RMWs
 *   for parity. Final fresh CTL OR arms EPENA/CNAK. Controller remains cached despite pointer
 *   changes. No helper, lock, busy/type/hardware-index/capacity check, data copy, completion
 *   callback or rollback. Buffer lifetime, physical DMA/USB acceptance, fault dispatch and
 *   concurrent ownership are external; NULL/zero can arm MPS bytes without refreshing DMA.
 */

int usbd_ep_start_read(unsigned char bus,unsigned char endpoint,unsigned char *buffer,unsigned int length)
{
    if (((unsigned int)buffer & 3U) != 0) {
        __asm__ volatile ("1: j 1b" ::: "memory"); /* Native alignment guard never returns. */
        __builtin_unreachable();
    }
    volatile MediusDwc2DeviceContext *context = (volatile MediusDwc2DeviceContext *)
        (MEDIUS_DWC2_CONTEXT_BASE + (unsigned int)bus * sizeof(MediusDwc2DeviceContext));
    unsigned char dma_enabled = context->parameters.dma_enabled;
    if (buffer == 0 && length != 0)
        return -1;
    unsigned int controller = (unsigned int)MEDIUS_USBD_CONTROLLERS[bus].registers;
    unsigned int endpoint_index = endpoint & 0x7fU; /* The direction bit never selects IN storage. */
    volatile MediusDwc2OutEndpointRegisters *registers =
        (volatile MediusDwc2OutEndpointRegisters *)(controller + 0xb00U + endpoint_index * 32U);
    volatile MediusDwc2Endpoint *transfer = (volatile MediusDwc2Endpoint *)
        ((unsigned int)context + __builtin_offsetof(MediusDwc2DeviceContext,output_endpoints) + endpoint_index * sizeof(MediusDwc2Endpoint));
    if (endpoint_index != 0) {
        memw();
        if ((registers->control & 0x7ffU) == 0)
            return -2;
    }
    memw();
    unsigned int size = registers->transfer_size;
    if (endpoint_index == 0) {
        transfer->buffer = buffer;
        transfer->requested = length;
        transfer->actual = 0;
    } else {
        transfer->actual = 0;
        transfer->buffer = buffer;
        transfer->requested = length;
    }
    memw();
    registers->transfer_size = size & 0xe007ffffU; /* Clear packet count. */
    memw();
    size = registers->transfer_size;
    memw();
    registers->transfer_size = size & 0xfff80000U; /* Fresh size-field clear. */
    if (length == 0) {
        memw();
        size = registers->transfer_size;
        memw();
        registers->transfer_size = size | 0x80000U;
        unsigned int maximum_packet = transfer->max_packet;
        memw();
        size = registers->transfer_size;
        memw();
        registers->transfer_size = size | maximum_packet;
        /* Original-zero request keeps software requested0 and stale DMA address. */
        goto arm_endpoint;
    }
    if (endpoint_index == 0) {
        unsigned int maximum_packet = transfer->max_packet;
        memw();
        size = registers->transfer_size;
        unsigned int accepted = maximum_packet < length ? maximum_packet : length;
        transfer->requested = accepted;
        memw();
        registers->transfer_size = size | 0x80000U;
        memw();
        size = registers->transfer_size;
        memw();
        registers->transfer_size = size | accepted;
    } else {
        unsigned int maximum_packet = transfer->max_packet;
        unsigned int numerator = length - 1U + maximum_packet;
        unsigned int packets;
        /* Preserve the real QUOU divide-by-zero exception, without C /0 UB. */
        __asm__ volatile ("quou %0,%1,%2" : "=a"(packets) : "a"(numerator),"a"(maximum_packet) : "memory");
        memw();
        size = registers->transfer_size;
        memw();
        registers->transfer_size = size | ((packets & 0x3ffU) << 19);
        memw();
        size = registers->transfer_size;
        memw();
        registers->transfer_size = size | (length & 0x7ffffU);
    }
    if (dma_enabled != 0) {
        memw();
        registers->dma_address = (unsigned int)buffer;
    }
    if (transfer->transfer_type == 1) {
        memw();
        unsigned int device_status = ((const volatile MediusDwc2CoreRegisters *)controller)->device_status; /* DSTS */
        memw();
        unsigned int control = registers->control;
        if ((device_status & 0x100U) == 0) {
            memw();
            registers->control = control & 0xefffffffU;
            memw();
            control = registers->control;
            memw();
            registers->control = control | 0x20000000U;
        } else {
            memw();
            registers->control = control & 0xdfffffffU;
            memw();
            control = registers->control;
            memw();
            registers->control = control | 0x10000000U;
        }
    }
arm_endpoint:
    memw();
    unsigned int control = registers->control;
    memw();
    registers->control = control | 0x84000000U; /* EPENA | CNAK */
    return 0;
}

/* Native entry: 0x40381a40. */
/*
 * Medius v3.4.7 — device application; 0x40381a40.
 *
 * Services device RX, endpoint completion, reset/enumeration, dynamic FIFO EOPF scheduling and
 * global USB events.
 *
 * Calls: FUN_4037b3c4, xPortInIsrContext, FUN_403917c0, dwc2_ep_read, dwc2_tx_fifo_empty_process,
 * medius_dwc2_abort_ep0_in, medius_dwc2_drain_ready_queue, medius_dwc2_endpoint_queue_insert,
 * medius_dwc2_fifo_priority_eligible, medius_dwc2_find_free_fifo, medius_dwc2_release_idle_fifo,
 * medius_dwc2_rewind_partial_in, medius_nonzero_control_setup,
 * medius_usb_in_endpoint_activity_update, medius_usbd_reset_event, memmove, memset,
 * usbd_dwc2_get_system_clock, usbd_event_ep_in_complete_handler,
 * usbd_event_ep_out_complete_handler, usbd_event_resume_handler, usbd_event_suspend_handler,
 * usbd_get_ep0_next_state, vPortExitCritical; plus 1 other direct targets.
 *
 * Called by: medius_usb_device_irq_trampoline.
 *
 * Original function-byte SHA-256:
 * 6782e36efa4f5da8f5052ceb85de6cf6af69cf59391e15102250213c4adbe043.
 */

/*
 * bus: Low8 selects raw controller-slot8/context996/queue17 strides, dynamic/bitmap byte offsets;
 *   no bus bounds or lifetime check.
 * Returns: No value; one captured pending snapshot selects all branches. Helpers can block or fail
 *   outside the local interrupt model.
 * Requirements/effects: Reads status/mask/second status once in native order before zero/host-mode
 *   gates, then DMA byte. Non-DMA RX consumes one popped status, raw11-bit counts and low4
 *   endpoint; data callback followed by fresh buffer read before fresh controller read/pointer
 *   advance, setup writes context without8-byte clamp. OUT/IN DAINT mask snapshots select
 *   ascending endpoints; raw endpoint status ack precedes masking. Retains native
 *   residue/requested read order, actual/requested stores and callback snapshots, simultaneous
 *   SETUP, EP0 state rechecks, abort-before-setup, conditional DMA setup rearm and distinct direct
 *   FIFO path. Dynamic IN completion snapshots mode/FIFO across lock/unlock/callback then rechecks
 *   mode/FIFO/EPENA/priority before release; pending clears at native point. Separate non-DMA
 *   FIFO-empty gate locks and checks mode/FIFO or clears mask. Reset acknowledges then locks,
 *   independently fenced MMIO accesses and counter loads/stores. Four waits compare cached
 *   incremented attempts, permit200000 status reads and end at200001; reset continues after
 *   timeout and resets inclusive
 *   hardware count endpoints and all16 software slots, preserves queue entries/priority, unlocks
 *   before notification. Enumeration uses unsigned clock intervals, separate TRDT clear/read/OR,
 *   setup rearm/DMA. Acks21/20 then EOPF; caches mode before ack/rechecks under mux, cached token-
 *   controller scan/raw endpoint bytes/first duplicate removal/count-before-move, priority queue
 *   insertion. Progress uses live count, cached transfer/control/packet8, conditional frame
 *   snapshot, strict wrapped11-bit age>interval+1,500 poll reads plus independent final read; only
 *   disabled final snapshot clears pending/rewinds cached fresh packet8. Mode exit preserves
 *   pending/queue checks, fresh controller reads in first scan/cached last base second scan, one
 *   cached bitmap free-count read and assignment controller snapshot, allocator full return for
 *   shifts with low8 FIFO/map storage; zero return unchecked. Every finite EOPF calls frame
 *   handler after unlock, including static mode; ordinary SOF ignored. Suspend/wake acknowledge
 *   before callbacks; OTG ORs two separate reads. No physical W1C/FIFO/DMA/timing/concurrent
 *   lifetime or valid hardware-state proof.
 */

void USBD_IRQHandler(unsigned char bus)
{
    unsigned int context_address = MEDIUS_DWC2_CONTEXT_BASE + (unsigned int)bus * 996U;
    volatile MediusDwc2DeviceContext *context = (volatile MediusDwc2DeviceContext *)context_address;
    volatile MediusUsbdControllerBinding *binding = &MEDIUS_USBD_CONTROLLERS[bus];
    volatile unsigned char *dynamic_mode = &USB_DWC2_DYNAMIC_FIFO_MODES[bus];
    volatile unsigned char *allocated_fifos = &MEDIUS_DWC2_ALLOCATED[bus];
    volatile MediusEndpointQueue *ready_queue = (volatile MediusEndpointQueue *)
        (MEDIUS_DWC2_READY_BASE + (unsigned int)bus * 17U);
    volatile MediusEndpointQueue *token_queue = (volatile MediusEndpointQueue *)
        (MEDIUS_DWC2_TOKEN_WAIT_BASE + (unsigned int)bus * 17U);
    volatile MediusDwc2CoreRegisters *controller_registers = binding->registers;
    memw();
    unsigned int first_status = controller_registers->interrupt_status;
    memw();
    unsigned int interrupt_mask = controller_registers->interrupt_mask;
    memw();
    unsigned int second_status = controller_registers->interrupt_status;
    unsigned int pending_interrupts = first_status & interrupt_mask;
    if (pending_interrupts == 0 || (second_status & 1U) != 0)
        return;
    unsigned char dma_enabled = context->parameters.dma_enabled;
    if (dma_enabled == 0 && (pending_interrupts & 0x10U) != 0) {
        {
            memw();
            unsigned int register_snapshot = controller_registers->interrupt_mask;
            memw();
            controller_registers->interrupt_mask = register_snapshot & 0xffffffefU;
        }
        memw();
        unsigned int receive_status = controller_registers->receive_status_pop;
        unsigned int packet_status = (receive_status >> 17) & 15U;
        unsigned int received_bytes = (receive_status >> 4) & 2047U;
        if (packet_status == 2 && received_bytes != 0) {
            unsigned int endpoint = receive_status & 15U;
            volatile MediusDwc2Endpoint *transfer = &context->output_endpoints[endpoint];
            unsigned char *buffer = transfer->buffer;
            dwc2_ep_read(bus,buffer,(unsigned short)received_bytes);
            unsigned char *current_buffer = transfer->buffer;
            controller_registers = binding->registers;
            transfer->buffer = (unsigned char *)((unsigned int)current_buffer + received_bytes);
        } else if (packet_status == 6) {
            dwc2_ep_read(bus,(unsigned char *)context_address,(unsigned short)received_bytes);
            controller_registers = binding->registers;
        }
        {
            memw();
            unsigned int register_snapshot = controller_registers->interrupt_mask;
            memw();
            controller_registers->interrupt_mask = register_snapshot | 0x10U;
        }
    }
    if (pending_interrupts & 0x80000U) {
        controller_registers = binding->registers;
        memw();
        unsigned int endpoint_status = controller_registers->all_endpoint_status;
        memw();
        unsigned int endpoint_mask = controller_registers->all_endpoint_mask;
        unsigned int selected_endpoints = (endpoint_status & endpoint_mask) >> 16;
        unsigned int endpoint = 0;
        while (selected_endpoints != 0) {
            if (selected_endpoints & 1U) {
                controller_registers = binding->registers;
                volatile MediusDwc2OutEndpointRegisters *endpoint_registers =
                    (volatile MediusDwc2OutEndpointRegisters *)
                    ((unsigned int)controller_registers + 0xb00U + (endpoint & 65535U) * 32U);
                memw();
                unsigned int raw_status = endpoint_registers->interrupt_status;
                memw();
                endpoint_registers->interrupt_status = raw_status;
                memw();
                unsigned int out_mask = controller_registers->out_endpoint_mask;
                unsigned int status = raw_status & out_mask;
                unsigned int setup_pending = status & 8U;
                volatile MediusDwc2Endpoint *transfer = &context->output_endpoints[endpoint];
                if (status & 1U) {
                    if (endpoint == 0) {
                        unsigned char next_state = usbd_get_ep0_next_state(bus);
                        if (next_state != 0) {
                            unsigned int requested = transfer->requested;
                            unsigned int actual = requested;
                            if (requested != 0) {
                                controller_registers = binding->registers;
                                volatile MediusDwc2OutEndpointRegisters *ep0 =
                                    (volatile MediusDwc2OutEndpointRegisters *)((unsigned int)controller_registers + 0xb00U);
                                memw();
                                unsigned int residue = ep0->transfer_size;
                                actual = requested - (residue & 0x7ffffU);
                            }
                            transfer->actual = actual;
                            transfer->requested = 0;
                            usbd_event_ep_out_complete_handler(bus,0,actual);
                            next_state = usbd_get_ep0_next_state(bus);
                            if (next_state == 0) {
                                controller_registers = binding->registers;
                                unsigned char ep0_dma = context->parameters.dma_enabled;
                                volatile MediusDwc2OutEndpointRegisters *ep0 =
                                    (volatile MediusDwc2OutEndpointRegisters *)((unsigned int)controller_registers + 0xb00U);
                                memw();
                                ep0->transfer_size = 0x20080008U;
                                if (ep0_dma != 0) {
                                    memw();
                                    ep0->dma_address = context_address;
                                    {
                                        memw();
                                        unsigned int register_snapshot = ep0->control;
                                        memw();
                                        ep0->control = register_snapshot | 0x80008000U;
                                    }
                                }
                            } else if (setup_pending != 0) {
                                controller_registers = binding->registers;
                            }
                        } else if (setup_pending != 0) {
                            controller_registers = binding->registers;
                        }
                    } else {
                        memw();
                        unsigned int residue = endpoint_registers->transfer_size;
                        unsigned int requested = transfer->requested;
                        unsigned int actual = requested - (residue & 0x7ffffU);
                        transfer->actual = actual;
                        transfer->requested = 0;
                        usbd_event_ep_out_complete_handler(bus,(unsigned char)endpoint,actual);
                        if (setup_pending != 0) {
                            controller_registers = binding->registers;
                            endpoint_registers = (volatile MediusDwc2OutEndpointRegisters *)
                                ((unsigned int)controller_registers + 0xb00U + (endpoint & 65535U) * 32U);
                        }
                    }
                }
                if (setup_pending != 0) {
                    if (endpoint == 0) {
                        volatile Dwc2InEndpointRegisters *ep0 =
                            (volatile Dwc2InEndpointRegisters *)((unsigned int)controller_registers + 0x900U);
                        memw();
                        if (ep0->control & 0x80000000U)
                            medius_dwc2_abort_ep0_in(bus);
                        medius_ep0_process_setup(bus,(volatile MediusUsbSetupPacket *)context_address);
                    } else {
                        memw();
                        endpoint_registers->transfer_size = 0x20080008U;
                        medius_nonzero_control_setup(bus,(unsigned char)endpoint,(unsigned char *)context_address);
                    }
                }
            }
            selected_endpoints >>= 1;
            ++endpoint;
        }
    }
    if (pending_interrupts & 0x40000U) {
        controller_registers = binding->registers;
        memw();
        unsigned int endpoint_status = controller_registers->all_endpoint_status;
        memw();
        unsigned int endpoint_mask = controller_registers->all_endpoint_mask;
        unsigned int selected_endpoints = (endpoint_status & endpoint_mask) & 65535U;
        unsigned int endpoint = 0;
        while (selected_endpoints != 0) {
            if (selected_endpoints & 1U) {
                controller_registers = binding->registers;
                memw();
                unsigned int input_mask = controller_registers->device_in_endpoint_mask;
                memw();
                unsigned int empty_mask = controller_registers->device_in_fifo_empty_mask;
                volatile Dwc2InEndpointRegisters *endpoint_registers =
                    (volatile Dwc2InEndpointRegisters *)
                    ((unsigned int)controller_registers + 0x900U + (endpoint & 65535U) * 32U);
                memw();
                unsigned int raw_status = endpoint_registers->interrupt_status;
                memw();
                endpoint_registers->interrupt_status = raw_status;
                unsigned int status = raw_status & (input_mask | (((empty_mask >> (endpoint & 15U)) & 1U) << 7));
                if ((status & 0x2001U) == 0x2000U)
                    medius_usb_in_endpoint_activity_update(bus,endpoint);
                volatile MediusDwc2Endpoint *transfer = &context->input_endpoints[endpoint];
                if (status & 1U) {
                    if (endpoint == 0) {
                        controller_registers = binding->registers;
                        volatile Dwc2InEndpointRegisters *ep0 =
                            (volatile Dwc2InEndpointRegisters *)((unsigned int)controller_registers + 0x900U);
                        memw();
                        unsigned int residue = ep0->transfer_size;
                        unsigned int requested = transfer->requested;
                        unsigned int actual = requested - (residue & 0x7ffffU);
                        transfer->actual = actual;
                        transfer->requested = 0;
                        usbd_event_ep_in_complete_handler(bus,0x80,actual);
                        unsigned char next_state = usbd_get_ep0_next_state(bus);
                        if (next_state == 0) {
                            controller_registers = binding->registers;
                            unsigned char ep0_dma = context->parameters.dma_enabled;
                            volatile MediusDwc2OutEndpointRegisters *out_ep0 =
                                (volatile MediusDwc2OutEndpointRegisters *)((unsigned int)controller_registers + 0xb00U);
                            memw();
                            out_ep0->transfer_size = 0x20080008U;
                            if (ep0_dma != 0) {
                                memw();
                                out_ep0->dma_address = context_address;
                                {
                                    memw();
                                    unsigned int register_snapshot = out_ep0->control;
                                    memw();
                                    out_ep0->control = register_snapshot | 0x80008000U;
                                }
                            } else if (status & 0x80U) {
                                xPortInIsrContext();
                                xPortEnterCriticalTimeout(MEDIUS_DWC2_DRIVER_LOCK,0xffffffffU);
                                dwc2_tx_fifo_empty_process(bus,0);
                                xPortInIsrContext();
                                vPortExitCritical(MEDIUS_DWC2_DRIVER_LOCK);
                            }
                            goto next_input_endpoint;
                        }
                    } else {
                        unsigned int requested = transfer->requested;
                        controller_registers = binding->registers;
                        volatile Dwc2InEndpointRegisters *current_endpoint_registers =
                            (volatile Dwc2InEndpointRegisters *)
                            ((unsigned int)controller_registers + 0x900U + (endpoint & 65535U) * 32U);
                        memw();
                        unsigned int residue = current_endpoint_registers->transfer_size;
                        unsigned int actual = requested - (residue & 0x7ffffU);
                        unsigned char was_dynamic = *dynamic_mode;
                        transfer->actual = actual;
                        transfer->requested = 0;
                        unsigned char callback_endpoint = (unsigned char)endpoint | 0x80;
                        if (was_dynamic != 0) {
                            xPortInIsrContext();
                            xPortEnterCriticalTimeout(MEDIUS_DWC2_DRIVER_LOCK,0xffffffffU);
                            if (*dynamic_mode != 0) {
                                unsigned char old_fifo = transfer->fifo_index;
                                xPortInIsrContext();
                                vPortExitCritical(MEDIUS_DWC2_DRIVER_LOCK);
                                unsigned int callback_actual = transfer->actual;
                                usbd_event_ep_in_complete_handler(bus,callback_endpoint,callback_actual);
                                if (old_fifo != 0) {
                                    xPortInIsrContext();
                                    xPortEnterCriticalTimeout(MEDIUS_DWC2_DRIVER_LOCK,0xffffffffU);
                                    unsigned char still_dynamic = *dynamic_mode;
                                    transfer->disable_pending = 0;
                                    if (still_dynamic != 0 && transfer->fifo_index == old_fifo) {
                                        controller_registers = binding->registers;
                                        current_endpoint_registers = (volatile Dwc2InEndpointRegisters *)
                                            ((unsigned int)controller_registers + 0x900U + (endpoint & 65535U) * 32U);
                                        memw();
                                        unsigned int control = current_endpoint_registers->control;
                                        if ((control & 0x80000000U) == 0 &&
                                            medius_dwc2_fifo_priority_eligible(bus,endpoint) == 0)
                                            medius_dwc2_release_idle_fifo(bus,endpoint);
                                    }
                                    xPortInIsrContext();
                                    vPortExitCritical(MEDIUS_DWC2_DRIVER_LOCK);
                                }
                                goto input_fifo_empty;
                            }
                            xPortInIsrContext();
                            vPortExitCritical(MEDIUS_DWC2_DRIVER_LOCK);
                            actual = transfer->actual;
                        }
                        usbd_event_ep_in_complete_handler(bus,callback_endpoint,actual);
                    }
                }
input_fifo_empty:
                ;
                unsigned char fifo_dma = context->parameters.dma_enabled;
                if (fifo_dma == 0 && (status & 0x80U) != 0) {
                    xPortInIsrContext();
                    xPortEnterCriticalTimeout(MEDIUS_DWC2_DRIVER_LOCK,0xffffffffU);
                    if (endpoint == 0 || *dynamic_mode == 0 || transfer->fifo_index != 0) {
                        dwc2_tx_fifo_empty_process(bus,(unsigned char)endpoint);
                    } else {
                        controller_registers = binding->registers;
                        memw();
                        unsigned int mask = controller_registers->device_in_fifo_empty_mask;
                        memw();
                        controller_registers->device_in_fifo_empty_mask = mask & ~(1U << (endpoint & 31U));
                    }
                    xPortInIsrContext();
                    vPortExitCritical(MEDIUS_DWC2_DRIVER_LOCK);
                }
            }
next_input_endpoint:
            selected_endpoints >>= 1;
            ++endpoint;
        }
    }
    if (pending_interrupts & 0x1000U) {
        controller_registers = binding->registers;
        memw();
        controller_registers->interrupt_status = 0x1000;
        {
            memw();
            unsigned int register_snapshot = controller_registers->device_control;
            memw();
            controller_registers->device_control = register_snapshot & 0xfffffffeU;
        }
        xPortInIsrContext();
        xPortEnterCriticalTimeout(MEDIUS_DWC2_DRIVER_LOCK,0xffffffffU);
        controller_registers = binding->registers;
        memw();
        volatile unsigned int tx_counter = 0;
        for (;;) {
            memw();
            unsigned int attempt = tx_counter + 1U;
            memw();
            tx_counter = attempt;
            if (attempt > 200000U)
                goto reset_receive;
            memw();
            if (controller_registers->reset_control & 0x80000000U)
                break;
        }
        memw();
        tx_counter = 0;
        memw();
        controller_registers->reset_control = 0x420;
        for (;;) {
            memw();
            unsigned int attempt = tx_counter + 1U;
            memw();
            tx_counter = attempt;
            if (attempt > 200000U)
                break;
            memw();
            if ((controller_registers->reset_control & 0x20U) == 0)
                break;
        }
reset_receive:
        ;
        memw();
        volatile unsigned int rx_counter = 0;
        for (;;) {
            memw();
            unsigned int attempt = rx_counter + 1U;
            memw();
            rx_counter = attempt;
            if (attempt > 200000U)
                goto reset_endpoints;
            memw();
            if (controller_registers->reset_control & 0x80000000U)
                break;
        }
        memw();
        rx_counter = 0;
        memw();
        controller_registers->reset_control = 0x10;
        for (;;) {
            memw();
            unsigned int attempt = rx_counter + 1U;
            memw();
            rx_counter = attempt;
            if (attempt > 200000U)
                break;
            memw();
            if ((controller_registers->reset_control & 0x10U) == 0)
                break;
        }
reset_endpoints:
        ;
        unsigned int endpoint_count = (context->core_capabilities >> 15) & 15U;
        volatile Dwc2InEndpointRegisters *input =
            (volatile Dwc2InEndpointRegisters *)((unsigned int)controller_registers + 0x900U);
        volatile MediusDwc2OutEndpointRegisters *output =
            (volatile MediusDwc2OutEndpointRegisters *)((unsigned int)controller_registers + 0xb00U);
        memw();
        input->control = 0x08000000;
        memw();
        output->control = 0x08000000;
        for (unsigned int endpoint = 0;; ++endpoint) {
            memw();
            input->transfer_size = 0;
            memw();
            input->interrupt_status = 0xfbff;
            memw();
            output->transfer_size = 0;
            memw();
            output->interrupt_status = 0xfbff;
            if (endpoint == endpoint_count)
                break;
            ++input;
            ++output;
            {
                memw();
                unsigned int register_snapshot = input->control;
                memw();
                input->control = register_snapshot & 0x3fdfffffU;
            }
            {
                memw();
                unsigned int register_snapshot = output->control;
                memw();
                output->control = register_snapshot & 0x3fdfffffU;
            }
            memw();
            unsigned int input_control = input->control;
            memw();
            input->control = (input_control & 0x80000000U) != 0 ? 0x48000000U : 0;
            memw();
            unsigned int output_control = output->control;
            memw();
            output->control = (output_control & 0x80000000U) != 0 ? 0x48000000U : 0;
        }
        {
            memw();
            unsigned int register_snapshot = controller_registers->all_endpoint_mask;
            memw();
            controller_registers->all_endpoint_mask = register_snapshot | 0x10001U;
        }
        memw();
        controller_registers->out_endpoint_mask = 9;
        memw();
        controller_registers->device_in_endpoint_mask = 1;
        token_queue->count = 0;
        *allocated_fifos = 0;
        *dynamic_mode = 0;
        ready_queue->count = 0;
        memset((void *)(context_address + 100U),0,448);
        memset((void *)(context_address + 548U),0,448);
        xPortInIsrContext();
        vPortExitCritical(MEDIUS_DWC2_DRIVER_LOCK);
        medius_usbd_reset_event(bus);
    }
    if (pending_interrupts & 0x2000U) {
        controller_registers = binding->registers;
        memw();
        controller_registers->interrupt_status = 0x2000;
        unsigned int clock_hz = usbd_dwc2_get_system_clock();
        controller_registers = binding->registers;
        memw();
        unsigned int status = controller_registers->device_status;
        unsigned int turnaround = 9;
        if (status & 2U) {
            if (clock_hz - 14200000U < 800000U)
                turnaround = 15;
            else if (clock_hz - 15000000U < 1000000U)
                turnaround = 14;
            else if (clock_hz - 16000000U < 1200000U)
                turnaround = 13;
            else if (clock_hz - 17200000U < 1300000U)
                turnaround = 12;
            else if (clock_hz - 18500000U < 1500000U)
                turnaround = 11;
            else if (clock_hz - 20000000U < 1800000U)
                turnaround = 10;
            else if (clock_hz - 21800000U < 2200000U)
                turnaround = 9;
            else if (clock_hz - 24000000U < 3700000U)
                turnaround = 8;
            else if (clock_hz - 27700000U < 4300000U)
                turnaround = 7;
            else
                turnaround = 6;
        }
        {
            memw();
            unsigned int register_snapshot = controller_registers->usb_configuration;
            memw();
            controller_registers->usb_configuration = register_snapshot & 0xffffc3ffU;
        }
        {
            memw();
            unsigned int register_snapshot = controller_registers->usb_configuration;
            memw();
            controller_registers->usb_configuration = register_snapshot | (turnaround << 10);
        }
        {
            memw();
            unsigned int register_snapshot = controller_registers->device_control;
            memw();
            controller_registers->device_control = register_snapshot | 0x100U;
        }
        unsigned char setup_dma = context->parameters.dma_enabled;
        volatile MediusDwc2OutEndpointRegisters *ep0 =
            (volatile MediusDwc2OutEndpointRegisters *)((unsigned int)controller_registers + 0xb00U);
        memw();
        ep0->transfer_size = 0x20080008U;
        if (setup_dma != 0) {
            memw();
            ep0->dma_address = context_address;
            {
                memw();
                unsigned int register_snapshot = ep0->control;
                memw();
                ep0->control = register_snapshot | 0x80008000U;
            }
        }
    }
    if (pending_interrupts & 0x200000U) {
        controller_registers = binding->registers;
        memw();
        controller_registers->interrupt_status = 0x200000;
    }
    if (pending_interrupts & 0x100000U) {
        controller_registers = binding->registers;
        memw();
        controller_registers->interrupt_status = 0x100000;
    }
    if (pending_interrupts & 0x8000U) {
        controller_registers = binding->registers;
        unsigned char frame_dynamic = *dynamic_mode;
        memw();
        controller_registers->interrupt_status = 0x8000;
        if (frame_dynamic != 0) {
            xPortInIsrContext();
            xPortEnterCriticalTimeout(MEDIUS_DWC2_DRIVER_LOCK,0xffffffffU);
            if (*dynamic_mode != 0) {
                controller_registers = binding->registers;
                memw();
                unsigned int frame = (controller_registers->device_status >> 8) & 2047U;
                unsigned char token_count = token_queue->count;
                unsigned char cursor = 0;
                while (cursor < token_count) {
                    unsigned char endpoint = token_queue->entries[cursor];
                    volatile Dwc2InEndpointRegisters *endpoint_registers =
                        (volatile Dwc2InEndpointRegisters *)
                        ((unsigned int)controller_registers + 0x900U + (unsigned int)endpoint * 32U);
                    memw();
                    unsigned int token_status = endpoint_registers->interrupt_status;
                    if (token_status & 0x2000U) {
                        memw();
                        endpoint_registers->interrupt_status = 0x2000;
                        for (unsigned int index = 0; index < token_count; ++index) {
                            unsigned char queued = token_queue->entries[index];
                            if (queued == endpoint) {
                                unsigned char remaining = (unsigned char)(token_count - 1U);
                                token_queue->count = remaining;
                                memmove((void *)((unsigned int)token_queue + index),
                                    (void *)((unsigned int)token_queue + index + 1U),(unsigned int)remaining - index);
                                break;
                            }
                        }
                        unsigned int priority = medius_dwc2_fifo_priority_eligible(bus,endpoint);
                        medius_dwc2_endpoint_queue_insert((unsigned char *)ready_queue,endpoint,priority);
                    } else {
                        cursor = (unsigned char)(cursor + 1U);
                    }
                    token_count = token_queue->count;
                }
                unsigned int hardware_endpoints = (context->core_capabilities >> 15) & 15U;
                if (hardware_endpoints != 0) {
                    unsigned int endpoint = 1;
                    do {
                        volatile MediusDwc2Endpoint *transfer = &context->input_endpoints[endpoint];
                        if (transfer->fifo_index != 0) {
                            controller_registers = binding->registers;
                            volatile Dwc2InEndpointRegisters *endpoint_registers =
                                (volatile Dwc2InEndpointRegisters *)
                                ((unsigned int)controller_registers + 0x900U + (endpoint & 65535U) * 32U);
                            memw();
                            unsigned int transfer_size = endpoint_registers->transfer_size;
                            memw();
                            unsigned int control = endpoint_registers->control;
                            unsigned char packets = (unsigned char)(transfer_size >> 19);
                            if ((control & 0x80000000U) == 0) {
                                if (transfer->disable_pending != 0) {
                                    transfer->disable_pending = 0;
                                    if (packets != 0)
                                        medius_dwc2_rewind_partial_in(bus,endpoint,packets);
                                } else if ((control & 0x8000U) == 0 ||
                                    medius_dwc2_fifo_priority_eligible(bus,endpoint) == 0) {
                                    medius_dwc2_release_idle_fifo(bus,endpoint);
                                }
                            } else {
                                unsigned char previous_packets = transfer->last_packet_count;
                                if (previous_packets != packets) {
                                    transfer->last_packet_count = packets;
                                    transfer->last_progress_frame = (unsigned short)frame;
                                } else if (transfer->disable_pending == 0 && transfer->cancelled == 0 &&
                                    ready_queue->count != 0 && medius_dwc2_fifo_priority_eligible(bus,endpoint) == 0) {
                                    unsigned short previous_frame = transfer->last_progress_frame;
                                    unsigned char interval = transfer->interval;
                                    if (((frame - previous_frame) & 2047U) > (unsigned int)interval + 1U) {
                                        memw();
                                        volatile unsigned int disable_counter = 0;
                                        transfer->disable_pending = 1;
                                        {
                                            memw();
                                            unsigned int register_snapshot = endpoint_registers->control;
                                            memw();
                                            endpoint_registers->control = register_snapshot | 0x08000000U;
                                        }
                                        {
                                            memw();
                                            unsigned int register_snapshot = endpoint_registers->control;
                                            memw();
                                            endpoint_registers->control = register_snapshot | 0x40000000U;
                                        }
                                        for (;;) {
                                            memw();
                                            unsigned int enabled = endpoint_registers->control;
                                            if ((enabled & 0x80000000U) == 0)
                                                break;
                                            memw();
                                            unsigned int attempt = disable_counter + 1U;
                                            memw();
                                            disable_counter = attempt;
                                            if (attempt >= 500U)
                                                break;
                                        }
                                        memw();
                                        unsigned int final_control = endpoint_registers->control;
                                        if ((final_control & 0x80000000U) == 0) {
                                            transfer->disable_pending = 0;
                                            memw();
                                            unsigned int remaining = endpoint_registers->transfer_size;
                                            unsigned char fresh_packets = (unsigned char)(remaining >> 19);
                                            if (fresh_packets != 0)
                                                medius_dwc2_rewind_partial_in(bus,endpoint,fresh_packets);
                                        }
                                    }
                                }
                            }
                        }
                        hardware_endpoints = (context->core_capabilities >> 15) & 15U;
                        ++endpoint;
                    } while ((endpoint & 255U) <= hardware_endpoints);
                }
                medius_dwc2_drain_ready_queue(bus);
                hardware_endpoints = (context->core_capabilities >> 15) & 15U;
                unsigned char active_endpoints = 0;
                unsigned int last_base = 0;
                for (unsigned int endpoint = 1; endpoint <= hardware_endpoints; ++endpoint) {
                    volatile MediusDwc2Endpoint *transfer = &context->input_endpoints[endpoint];
                    if (transfer->disable_pending != 0)
                        goto frame_unlock;
                    controller_registers = binding->registers;
                    last_base = (unsigned int)controller_registers;
                    volatile Dwc2InEndpointRegisters *endpoint_registers =
                        (volatile Dwc2InEndpointRegisters *)((unsigned int)controller_registers + 0x900U + endpoint * 32U);
                    memw();
                    unsigned int control = endpoint_registers->control;
                    if (control & 0x8000U)
                        active_endpoints = (unsigned char)(active_endpoints + 1U);
                }
                if (ready_queue->count != 0 || token_queue->count != 0)
                    goto frame_unlock;
                unsigned int fifo_count = context->device_capabilities & 15U;
                if (active_endpoints > fifo_count)
                    goto frame_unlock;
                unsigned char unassigned = 0;
                for (unsigned int endpoint = 1; endpoint <= hardware_endpoints; ++endpoint) {
                    volatile Dwc2InEndpointRegisters *endpoint_registers =
                        (volatile Dwc2InEndpointRegisters *)(last_base + 0x900U + endpoint * 32U);
                    memw();
                    unsigned int control = endpoint_registers->control;
                    if ((control & 0x8000U) != 0 && context->input_endpoints[endpoint].fifo_index == 0)
                        unassigned = (unsigned char)(unassigned + 1U);
                }
                if (fifo_count != 0) {
                    unsigned char bitmap = *allocated_fifos;
                    unsigned char free_count = 0;
                    for (unsigned int fifo = 1; fifo <= fifo_count; ++fifo)
                        free_count = (unsigned char)(free_count + (((unsigned int)bitmap >> (fifo & 31U) & 1U) ^ 1U));
                    if (free_count < unassigned)
                        goto frame_unlock;
                } else if (unassigned != 0) {
                    goto frame_unlock;
                }
                if (hardware_endpoints != 0) {
                    controller_registers = binding->registers;
                    for (unsigned int endpoint = 1; (endpoint & 255U) <= hardware_endpoints; ++endpoint) {
                        volatile Dwc2InEndpointRegisters *endpoint_registers =
                            (volatile Dwc2InEndpointRegisters *)((unsigned int)controller_registers + 0x900U + endpoint * 32U);
                        memw();
                        unsigned int control = endpoint_registers->control;
                        volatile MediusDwc2Endpoint *transfer = &context->input_endpoints[endpoint];
                        if ((control & 0x8000U) != 0 && transfer->fifo_index == 0) {
                            unsigned int fifo = medius_dwc2_find_free_fifo(bus,endpoint);
                            transfer->fifo_index = (unsigned char)fifo;
                            memw();
                            unsigned int fresh_control = endpoint_registers->control;
                            unsigned char bitmap = *allocated_fifos;
                            memw();
                            endpoint_registers->control = (fresh_control & 0x3c3fffffU) | (fifo << 22);
                            *allocated_fifos = (unsigned char)((unsigned int)bitmap | (1U << (fifo & 31U)));
                        }
                    }
                }
                *dynamic_mode = 0;
            }
frame_unlock:
            xPortInIsrContext();
            vPortExitCritical(MEDIUS_DWC2_DRIVER_LOCK);
        }
        medius_usb_frame_schedule_reports(bus);
    }
    if (pending_interrupts & 0x800U) {
        controller_registers = binding->registers;
        memw();
        controller_registers->interrupt_status = 0x800;
        usbd_event_suspend_handler(bus);
    }
    if (pending_interrupts & 0x80000000U) {
        controller_registers = binding->registers;
        memw();
        controller_registers->interrupt_status = 0x80000000U;
        usbd_event_resume_handler(bus);
    }
    if (pending_interrupts & 4U) {
        controller_registers = binding->registers;
        memw();
        unsigned int first_otg = controller_registers->otg_interrupt;
        memw();
        unsigned int second_otg = controller_registers->otg_interrupt;
        memw();
        controller_registers->otg_interrupt = first_otg | second_otg;
    }
}

/* Native entry: 0x40382794. */
/*
 * Medius v3.4.7 — device application; 0x40382794.
 *
 * Truncates the registered interrupt argument to a byte and forwards it to the device IRQ.
 *
 * Calls: USBD_IRQHandler.
 *
 * Original function-byte SHA-256:
 * cd3a2f865e46949eb842a52917155632daf6c691e3bb14e523cf7c08c8d6becd.
 */

/*
 * argument: Registered interrupt context; its pointer bits encode the bus number, truncated to
 *   eight bits.
 * Returns: Nothing; returns when the device IRQ handler returns.
 * Requirements/effects: Invokes USBD_IRQHandler once with the encoded bus. This entry supplies no
 *   validation, lock, peripheral acknowledgement or extra scheduling work; those effects belong to
 *   the handler.
 */

void medius_usb_device_irq_trampoline(void *argument)
{
    USBD_IRQHandler((unsigned char)(unsigned int)argument);
}

/* Native entry: 0x403827a0. */
/*
 * Medius v3.4.7 — device application; 0x403827a0.
 *
 * Builds a24-byte device PHY configuration and allocates the shared IRQ only after PHY creation
 * returns success.
 *
 * Calls: esp_intr_alloc, usb_new_phy.
 *
 * Called by: usb_dc_init.
 *
 * Original function-byte SHA-256:
 * bb7ec33d1f446c797064bfe11d1fd7e0fd3dee6206ea6c045719e84d59dd8679.
 */

/*
 * bus: Controller number encoded into the interrupt argument using only its low eight bits.
 * Returns: Nothing; PHY and interrupt allocation errors are not propagated.
 * Requirements/effects: Passes one 24-byte PHY configuration: controller 0 (OTG), target 0
 *   (internal), OTG mode 2 (device), speed 0 and NULL external/OTG I/O configurations. Only exact
 *   usb_new_phy success 0 proceeds to esp_intr_alloc(source 38, flags 0x0e, device IRQ trampoline,
 *   bus_low8, shared output slot). IRQ allocation status is ignored. Existing global handle slots
 *   are not cleared before either call, and no failure/reinitialization rollback or lock occurs.
 *   Outputs written by failed callees remain stored. The slots are shared storage across
 *   invocations; flag 0x0e selects allowed interrupt levels and does not itself request a shared
 *   interrupt.
 */

void usb_dc_low_level_init(unsigned int bus)
{
    MediusUsbPhyConfig configuration = {0};
    configuration.otg_mode = 2;
    unsigned int phy_result = usb_new_phy(&configuration,
        (MediusUsbPhyHandle *)USB_DEVICE_PHY_HANDLE_SLOT);
    if (phy_result == 0) {
        esp_intr_alloc(38,0x0e,medius_usb_device_irq_trampoline,
            (void *)(bus & 255U),(InterruptHandle **)USB_DEVICE_IRQ_HANDLE_SLOT);
    }
}

/* Native entry: 0x403827dc. */
/*
 * Medius v3.4.7 — device application; 0x403827dc.
 *
 * Frees the current shared IRQ handle then deletes the current shared PHY handle, clearing each
 * nonzero slot regardless of returned errors.
 *
 * Calls: esp_intr_free, usb_del_phy.
 *
 * Called by: usb_dc_deinit.
 *
 * Original function-byte SHA-256:
 * 5eea2668e205c85326686628eefc102a83688239e7768508479884efc52b5bca.
 */

/*
 * Returns: Nothing; both delegated release statuses are ignored.
 * Requirements/effects: Samples the shared IRQ handle once, frees it when nonzero and clears that
 *   slot even on error. Then freshly samples the PHY handle, deletes it when nonzero and clears
 *   its slot even on error. IRQ teardown precedes PHY lookup, so a PHY-slot change during IRQ
 *   release affects the following call. A replacement IRQ slot written by its release call is
 *   overwritten by the local clear; changes during the later PHY call survive. No lock, retry,
 *   per-bus selection or rollback occurs. Slot clearing does not prove release or callback
 *   quiescence; callers must establish safe resource lifetime.
 */

void usb_dc_low_level_deinit(void)
{
    InterruptHandle *irq_handle = *USB_DEVICE_IRQ_HANDLE_SLOT;
    if (irq_handle != 0) {
        esp_intr_free(irq_handle);
        *USB_DEVICE_IRQ_HANDLE_SLOT = 0;
    }
    MediusUsbPhyHandle phy_handle = *USB_DEVICE_PHY_HANDLE_SLOT;
    if (phy_handle != 0) {
        usb_del_phy(phy_handle);
        *USB_DEVICE_PHY_HANDLE_SLOT = 0;
    }
}

/* Native entry: 0x40382804. */
/*
 * Medius v3.4.7 — device application; 0x40382804.
 *
 * Copies exactly64 live bytes from the aligned RAM default template to the supplied parameter
 * buffer.
 *
 * Called by: medius_dwc2_device_params.
 *
 * Original function-byte SHA-256:
 * 65aee9a456ea0f5340a4b0599f08e016f3b8b4430ed8c1875409575ab140049f.
 */

/*
 * unused_base: Ignored; the native source address is fixed aligned RAM.
 * parameters: Writable64-byte destination; alignment selects word or byte stores.
 * Returns: No value.
 * Requirements/effects: Copies sixteen live aligned source words from the RAM defaults without a
 *   helper or lock. Aligned destination receives each word immediately after its source load.
 *   Unaligned destination receives four16-byte blocks: first three words store byte1,2,3,0; fourth
 *   stores0,1,2,3. This order is retained even when buffers overlap, so no memmove or atomic-
 *   snapshot guarantee is made. Source is mutable RAM; later loads can observe intervening writes.
 *   No NULL, capacity or overlap checks occur and no parameter interpretation/DMA override is
 *   added. Generic prefix/tail branches in the shared native copy body are unreachable because
 *   this source is aligned and length is fixed64.
 */

void dwc2_get_user_params(unsigned int unused_base,unsigned char *parameters)
{
    (void)unused_base;
    const volatile unsigned int *source = USB_DWC2_DEFAULT_PARAMETER_WORDS;
    if (((unsigned int)parameters & 3U) == 0) {
        volatile unsigned int *destination = (volatile unsigned int *)parameters;
        for (unsigned int word_index = 0; word_index < 16; ++word_index) {
            unsigned int word = source[word_index];
            destination[word_index] = word;
        }
    } else {
        volatile unsigned char *destination = parameters;
        for (unsigned int block = 0; block < 4; ++block) {
            for (unsigned int word_index = 0; word_index < 4; ++word_index) {
                unsigned int offset = block * 16U + word_index * 4U;
                unsigned int word = source[block * 4U + word_index];
                /* Native unaligned stores reorder the first three low bytes. */
                if (word_index == 3)
                    destination[offset] = (unsigned char)word;
                destination[offset + 1] = (unsigned char)(word >> 8);
                destination[offset + 2] = (unsigned char)(word >> 16);
                destination[offset + 3] = (unsigned char)(word >> 24);
                if (word_index != 3)
                    destination[offset] = (unsigned char)word;
            }
        }
    }
}

/* Native entry: 0x40382934. */
/* Original function-byte SHA-256:
 * b7a2222b64765cc5e8dcaff3aeebd6df67a1ed1d35a3da31039f2d0fb68adcd6. */
/*
 * Returns one cached 32-bit clock word from RAM at 0x3fcab588, unchanged.
 * Does not measure hardware, convert units, validate freshness or synchronize.
 */
unsigned int usbd_dwc2_get_system_clock(void)
{
    return *(const volatile unsigned int *)0x3fcab588U;
}

/* Native entry: 0x42008a30. */
/*
 * Medius v3.4.7 — device application; 0x42008a30.
 *
 * Loads the shared64-byte defaults then forces device DMA-enable byte2 to zero.
 *
 * Calls: dwc2_get_user_params.
 *
 * Called by: usb_dc_init.
 *
 * Original function-byte SHA-256:
 * cafa879595ac651b1dae7171937162e33a3d76f4ad0496b132bf596979174b41.
 */

/*
 * register_base: Controller base forwarded unchanged to the parameter provider.
 * parameters: Writable 64-byte parameter storage, valid for the delegated provider copy.
 * Returns: Nothing.
 * Requirements/effects: Calls dwc2_get_user_params, then writes parameter byte 2 to zero to
 *   disable device DMA. The other 63 bytes retain the provider result. No pointer, length or
 *   hardware-capability check and no lock occur.
 */

void medius_dwc2_device_params(unsigned int register_base,unsigned char *parameters)
{
  dwc2_get_user_params(register_base,parameters);
  ((volatile MediusDwc2DeviceParameters *)parameters)->dma_enabled = 0;
}

/* Native entry: 0x40394a40. */
/* Original function-byte SHA-256:
 * f4a8285f3ea5020774f27c7a45c68ca6f6badcfc0799aa2cb6ab512b4139a4a7. */
/*
 * Sample64-bit clock even for mask0, then visit selected IN endpoints1..15
 * (bit0 and bits16..31 ignored). MEMW/read each DIEPCTL WORD at bus0 base
 *60080900+32*endpoint. If EPENA(bit31) is set, repeatedly sample clock; break
 * this endpoint when signed modular64 age>=1000us, otherwise MEMW/reread EPENA
 * and stop when clear. All endpoints share the SAME start/budget, not1ms each.
 * Timed-out endpoints do not abort later initial control reads. No USB writes,
 * delay/yield, timeout status or lock; expired age skips the final register
 * reread. Clock rollback/wrap/interrupt delays prevent a wall-time bound.
 */
void medius_dwc2_wait_in_endpoints_disabled(unsigned int endpoint_mask)
{
    unsigned long long start = esp_timer_get_time();
    for (unsigned int endpoint = 1; endpoint < 16; ++endpoint) {
        if ((endpoint_mask & (1U << endpoint)) == 0) continue;
        memw(); unsigned int control = DEVICE_DWC2_IN_REGISTERS[endpoint].control;
        if ((control & 0x80000000U) == 0) continue;
        for (;;) {
            unsigned long long now = esp_timer_get_time();
            if ((long long)(now - start) >= 1000) break;
            memw(); control = DEVICE_DWC2_IN_REGISTERS[endpoint].control;
            if ((control & 0x80000000U) == 0) break;
        }
    }
}
