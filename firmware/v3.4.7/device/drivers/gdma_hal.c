/* Medius v3.4.7 device: recovered AHB GDMA HAL and callback table. */

#include "../include/types.h"

/* reconstruction utilities: retain native 32-bit wrapping channel addresses
 * and fresh MEMW/read/MEMW/write pairs. These helpers always inline, adding no
 * firmware calls. All native operations below require a readable HAL context;
 * channel IDs are unchecked, and only direction 1 means RX. Every other
 * direction means TX. No operation supplies a lock or transfer-completion wait. */
static __inline__ __attribute__((always_inline)) GdmaChannelRegisters *
gdma_ahb_channel(GdmaHal *hal,int channel_id)
{
    GdmaDeviceRegisters *device = ((const volatile GdmaHal *)hal)->device;
    unsigned int address = (unsigned int)(uintptr_t)device + (unsigned int)channel_id * 0xc0U;
    return (GdmaChannelRegisters *)(uintptr_t)address;
}

static __inline__ __attribute__((always_inline)) void gdma_ahb_replace_bits(
    volatile unsigned int *reg,unsigned int clear_mask,unsigned int set_bits)
{
    memw();
    unsigned int previous = *reg;
    memw();
    *reg = (previous & ~clear_mask) | set_bits;
}

/* Native entry: 0x403893d8. */
/*
 * Medius v3.4.7 — device application; 0x403893d8.
 * Instruction-checked recovered C.
 * Original function-byte SHA-256:
 * 272f6f620daa002a91854698ec03b2a0cb160cd7f801f50a639c0876f81ce96f.
 */

/* Request descriptor-chain restart: RX link bit 23, TX link bit 22.
 * One fresh link RMW preserves other bits. No descriptor update, idle check,
 * acknowledgement or status; the common unchecked channel/direction rules apply. */
void gdma_ahb_hal_append(GdmaHal *hal,int channel_id,int direction)
{
    GdmaChannelRegisters *channel = gdma_ahb_channel(hal,channel_id);
    if (direction == GDMA_DIRECTION_RECEIVE)
        gdma_ahb_replace_bits(&channel->rx.link,0,1U << 23);
    else
        gdma_ahb_replace_bits(&channel->tx.link,0,1U << 22);
}

/* Native entry: 0x40389414. */
/*
 * Medius v3.4.7 — device application; 0x40389414.
 * Instruction-checked recovered C.
 * Original function-byte SHA-256:
 * 82c97c51f0331edf9b8668db23ffcc4fd723d78bfd254cd26716f00a7bbab6e9.
 */

/* Write the complete event mask directly to the selected interrupt-clear
 * register after MEMW. This is W1C, not an RMW; no read or mask filtering.
 * Return no status. Unchecked channel/direction rules apply. */
void gdma_ahb_hal_clear_intr(GdmaHal *hal,int channel_id,int direction,unsigned int events)
{
    GdmaChannelRegisters *channel = gdma_ahb_channel(hal,channel_id);
    memw();
    if (direction == GDMA_DIRECTION_RECEIVE)
        channel->rx.interrupt_clear = events;
    else
        channel->tx.interrupt_clear = events;
}

/* Native entry: 0x40389434. */
/*
 * Medius v3.4.7 — device application; 0x40389434.
 * Instruction-checked recovered C.
 * Original function-byte SHA-256:
 * 54db4e752f12403dbec7e1739c0bed6468e2c20b61795331590e7c50f84b08d5.
 */

/* Return one MEMW/read snapshot of the EOF descriptor-address register.
 * RX chooses success (+0x28) for nonzero LOW BYTE of success, error (+0x2c)
 * for zero. TX always reads its success register and ignores success.
 * No descriptor dereference, flag clear or address masking. */
unsigned int gdma_ahb_hal_get_eof_desc_addr(GdmaHal *hal,int channel_id,
    int direction,unsigned char success)
{
    GdmaChannelRegisters *channel = gdma_ahb_channel(hal,channel_id);
    if (direction == GDMA_DIRECTION_RECEIVE) {
        memw();
        return success ? channel->rx.eof_descriptor : channel->rx.error_or_previous_eof_descriptor;
    }
    memw();
    return channel->tx.eof_descriptor;
}

/* Native entry: 0x40389468. */
/*
 * Medius v3.4.7 — device application; 0x40389468.
 * Instruction-checked recovered C.
 * Original function-byte SHA-256:
 * fc3fc42299146692ef067225ac1cf38506c624c75328e76277d8def9c69c8f46.
 */

/* Read raw interrupt status when the LOW BYTE of raw is nonzero, otherwise
 * masked status. Exactly one MEMW/read of the selected RX/TX register; return
 * the complete word without filtering, clearing flags or acknowledging events. */
unsigned int gdma_ahb_hal_read_intr_status(GdmaHal *hal,int channel_id,
    int direction,unsigned char raw)
{
    GdmaChannelRegisters *channel = gdma_ahb_channel(hal,channel_id);
    GdmaDirectionRegisters *registers = direction == GDMA_DIRECTION_RECEIVE ? &channel->rx : &channel->tx;
    memw();
    return raw ? registers->interrupt_raw : registers->interrupt_status;
}

/* Native entry: 0x403894a0. */
/*
 * Medius v3.4.7 — device application; 0x403894a0.
 * Instruction-checked recovered C.
 * Original function-byte SHA-256:
 * 484a63fec2fc1bb91f253d28bcf9715b90e8c76d3d89529be58b6e19d295733a.
 */

/* Pulse the selected channel CONF0 reset bit: set bit 0, then clear it
 * using a SECOND fresh read. Native RX/TX FSM/FIFO reset request, with no
 * delay, completion poll, descriptor rewrite or returned status. */
void gdma_ahb_hal_reset(GdmaHal *hal,int channel_id,int direction)
{
    GdmaChannelRegisters *channel = gdma_ahb_channel(hal,channel_id);
    volatile unsigned int *configuration = direction == GDMA_DIRECTION_RECEIVE ? &channel->rx.configuration0 : &channel->tx.configuration0;
    gdma_ahb_replace_bits(configuration,0,1);
    gdma_ahb_replace_bits(configuration,1,0);
}

/* Native entry: 0x403894f4. */
/*
 * Medius v3.4.7 — device application; 0x403894f4.
 * Instruction-checked recovered C.
 * Original function-byte SHA-256:
 * 1cb3a1d1c03bf83dbe24a7acfea244a233ab75725cdb0a4939078af061722729.
 */

/* Replace only link bits 0..19 with the descriptor address's LOW 20 BITS,
 * then take a fresh link read and set START (RX bit 22, TX bit 21). Preserve
 * all upper link bits on the address write. No alignment/range validation,
 * descriptor dereference, memory ownership check, stop/wait or status. */
void gdma_ahb_hal_start_with_desc(GdmaHal *hal,int channel_id,int direction,
    unsigned int descriptor_address)
{
    GdmaChannelRegisters *channel = gdma_ahb_channel(hal,channel_id);
    if (direction == GDMA_DIRECTION_RECEIVE) {
        gdma_ahb_replace_bits(&channel->rx.link,0xfffffU,descriptor_address & 0xfffffU);
        gdma_ahb_replace_bits(&channel->rx.link,0,1U << 22);
    } else {
        gdma_ahb_replace_bits(&channel->tx.link,0xfffffU,descriptor_address & 0xfffffU);
        gdma_ahb_replace_bits(&channel->tx.link,0,1U << 21);
    }
}

/* Native entry: 0x40389560. */
/*
 * Medius v3.4.7 — device application; 0x40389560.
 * Instruction-checked recovered C.
 * Original function-byte SHA-256:
 * d3ca57f4d208646ca3709fb6b42580055f2d2175dc4ea16d4f47ed46c15ba544.
 */

/* Request STOP through one fresh link RMW (RX bit 21, TX bit 20).
 * Preserve other bits; do not wait for idle, clear START/restart, free a
 * descriptor or report completion. Unchecked channel/direction rules apply. */
void gdma_ahb_hal_stop(GdmaHal *hal,int channel_id,int direction)
{
    GdmaChannelRegisters *channel = gdma_ahb_channel(hal,channel_id);
    if (direction == GDMA_DIRECTION_RECEIVE)
        gdma_ahb_replace_bits(&channel->rx.link,0,1U << 21);
    else
        gdma_ahb_replace_bits(&channel->tx.link,0,1U << 20);
}

/* Native entry: 0x420243ec. */
/*
 * Medius v3.4.7 — device application; 0x420243ec.
 * Instruction-checked recovered C.
 * Original function-byte SHA-256:
 * 182478d76c5e1544f83ca90c8342ac8a58a27ead09d134e877a8eac7785021b9.
 */

/* Program owner checking from the LOWEST BIT of its byte in CONF1 bit 12.
 * RX ignores descriptor_writeback/eof_till_popped (writeback is inherent).
 * TX then uses separate fresh CONF0 RMWs for descriptor-writeback bit 2 and
 * EOF-mode bit 3, each from its argument's LOWEST BIT, not general truth.
 * No validation, descriptor operation, locking or returned status. */
void gdma_ahb_hal_set_strategy(GdmaHal *hal,int channel_id,int direction,
    unsigned char owner_check,unsigned char descriptor_writeback,unsigned char eof_till_popped)
{
    GdmaChannelRegisters *channel = gdma_ahb_channel(hal,channel_id);
    if (direction == GDMA_DIRECTION_RECEIVE) {
        gdma_ahb_replace_bits(&channel->rx.configuration1,0x1000U,(owner_check & 1U) << 12);
    } else {
        gdma_ahb_replace_bits(&channel->tx.configuration1,0x1000U,(owner_check & 1U) << 12);
        gdma_ahb_replace_bits(&channel->tx.configuration0,4,(descriptor_writeback & 1U) << 2);
        gdma_ahb_replace_bits(&channel->tx.configuration0,8,(eof_till_popped & 1U) << 3);
    }
}

/* Native entry: 0x42024474. */
/*
 * Medius v3.4.7 — device application; 0x42024474.
 * Instruction-checked recovered C.
 * Original function-byte SHA-256:
 * aea0c8688dd570480ccf37a94b342117bfbf81f64a33bb16a57b348ac96d4874.
 */

/* Load the HAL device pointer, then accept burst sizes 16/32/64 as codes
 * 0/1/2 in selected CONF1 bits 13..14. Other sizes abort before MMIO. Hardware
 * documentation marks some encodings reserved; this routine still accepts
 * 64 and writes code 2, matching the compiled SDK helper. No alignment or
 * transfer validation, cached configuration, lock or status. */
void gdma_ahb_hal_set_burst_size(GdmaHal *hal,int channel_id,int direction,
    unsigned int burst_bytes)
{
    GdmaChannelRegisters *channel = gdma_ahb_channel(hal,channel_id);
    unsigned int code;
    if (burst_bytes == 16U)
        code = 0;
    else if (burst_bytes == 32U)
        code = 1;
    else if (burst_bytes == 64U)
        code = 2;
    else
        abort();
    volatile unsigned int *configuration = direction == GDMA_DIRECTION_RECEIVE ? &channel->rx.configuration1 : &channel->tx.configuration1;
    gdma_ahb_replace_bits(configuration,0x6000U,code << 13);
}

/* Native entry: 0x420244e8. */
/*
 * Medius v3.4.7 — device application; 0x420244e8.
 * Instruction-checked recovered C.
 * Original function-byte SHA-256:
 * a6d454f65777d9c6f4cae9015c8a2202f5799d017ba375aacd8de7a3999943a5.
 */

/* Initialize a writable 68-byte HAL context from a readable group config.
 * Read group_id once: group 0 selects the GDMA register base; EVERY other
 * value installs a NULL device. Populate all fifteen callbacks even for an
 * unsupported group, and publish the static private-data pointer LAST.
 * Explicit volatile output stores retain the native publication order,
 * including burst-size after EOF and interrupt-status-address after read.
 * No context allocation, group error/status, peripheral MMIO, lock, barrier
 * or hardware initialization. Later operations do not guard the NULL device. */
void gdma_ahb_hal_init(GdmaHal *hal,const GdmaHalConfig *configuration)
{
    int group_id = ((const volatile GdmaHalConfig *)configuration)->group_id;
    volatile GdmaHal *output = hal;
    output->device = group_id == 0 ? GDMA_DEVICE : NULL;
    output->start_with_desc = gdma_ahb_hal_start_with_desc;
    output->stop = gdma_ahb_hal_stop;
    output->append = gdma_ahb_hal_append;
    output->reset = gdma_ahb_hal_reset;
    output->set_priority = gdma_ahb_hal_set_priority;
    output->connect_peripheral = gdma_ahb_hal_connect_peri;
    output->disconnect_peripheral = gdma_ahb_hal_disconnect_peri;
    output->enable_burst = gdma_ahb_hal_enable_burst;
    output->set_strategy = gdma_ahb_hal_set_strategy;
    output->enable_interrupt = gdma_ahb_hal_enable_intr;
    output->clear_interrupt = gdma_ahb_hal_clear_intr;
    output->read_interrupt_status = gdma_ahb_hal_read_intr_status;
    output->get_interrupt_status_register = gdma_ahb_hal_get_intr_status_reg;
    output->get_eof_descriptor = gdma_ahb_hal_get_eof_desc_addr;
    output->set_burst_size = gdma_ahb_hal_set_burst_size;
    output->private_data = GDMA_AHB_PRIVATE;
}

/* Native entry: 0x4202454c. */
/*
 * Medius v3.4.7 — device application; 0x4202454c.
 * Instruction-checked recovered C.
 * Original function-byte SHA-256:
 * 2a0508c25b1cd74ed059491279c11f77b6ed91d417ba722107a136bfc6dd56f2.
 */

/* Replace selected channel priority bits 0..3 with priority & 15, preserving
 * the remaining word through one fresh RMW. Values above 15 are truncated,
 * not rejected. Unchecked channel/direction rules; no lock or status. */
void gdma_ahb_hal_set_priority(GdmaHal *hal,int channel_id,int direction,unsigned int priority)
{
    GdmaChannelRegisters *channel = gdma_ahb_channel(hal,channel_id);
    volatile unsigned int *reg = direction == GDMA_DIRECTION_RECEIVE ? &channel->rx.priority : &channel->tx.priority;
    gdma_ahb_replace_bits(reg,15,priority & 15U);
}

/* Native entry: 0x42024590. */
/*
 * Medius v3.4.7 — device application; 0x42024590.
 * Instruction-checked recovered C.
 * Original function-byte SHA-256:
 * 31b9e9ac0ae7d949f0753d0230d298da439b9a25231e031bd66f229a3a701c84.
 */

/* Set all six peripheral-selector bits to 63. RX additionally clears the
 * memory-to-memory bit 4 in CONF0 using a fresh RMW AFTER selector update.
 * TX has no second write. No reset, STOP, idle wait, lock or status. */
void gdma_ahb_hal_disconnect_peri(GdmaHal *hal,int channel_id,int direction)
{
    GdmaChannelRegisters *channel = gdma_ahb_channel(hal,channel_id);
    if (direction == GDMA_DIRECTION_RECEIVE) {
        gdma_ahb_replace_bits(&channel->rx.peripheral,0,63);
        gdma_ahb_replace_bits(&channel->rx.configuration0,16,0);
    } else {
        gdma_ahb_replace_bits(&channel->tx.peripheral,0,63);
    }
}

/* Native entry: 0x420245dc. */
/*
 * Medius v3.4.7 — device application; 0x420245dc.
 * Instruction-checked recovered C.
 * Original function-byte SHA-256:
 * d4a2a8712029a30603a947aa108ad12ba8e2d16b095c7cbf33722b9d3d34f39f.
 */

/* Set data-burst then descriptor-burst from the LOWEST BIT of each byte.
 * RX uses CONF0 bits 3/2; TX uses bits 5/4. Keep two separate fresh RMWs;
 * preserve unrelated bits. Does not set burst length or start a transfer.
 * No lock, memory-access validation or returned status. */
void gdma_ahb_hal_enable_burst(GdmaHal *hal,int channel_id,int direction,
    unsigned char data_burst,unsigned char descriptor_burst)
{
    GdmaChannelRegisters *channel = gdma_ahb_channel(hal,channel_id);
    if (direction == GDMA_DIRECTION_RECEIVE) {
        gdma_ahb_replace_bits(&channel->rx.configuration0,8,(data_burst & 1U) << 3);
        gdma_ahb_replace_bits(&channel->rx.configuration0,4,(descriptor_burst & 1U) << 2);
    } else {
        gdma_ahb_replace_bits(&channel->tx.configuration0,32,(data_burst & 1U) << 5);
        gdma_ahb_replace_bits(&channel->tx.configuration0,16,(descriptor_burst & 1U) << 4);
    }
}

/* Native entry: 0x4202465c. */
/*
 * Medius v3.4.7 — device application; 0x4202465c.
 * Instruction-checked recovered C.
 * Original function-byte SHA-256:
 * ce9be90843c97d25708298c05db645a4aad6381fddd1960539d50a0284065d68.
 */

/* Return the 32-bit ADDRESS of the selected masked interrupt-status
 * register (RX +0x0c, TX +0x6c), not its contents. Read HAL device once;
 * channel arithmetic wraps at 32 bits. No MMIO read, MEMW, validation or lock. */
unsigned int gdma_ahb_hal_get_intr_status_reg(GdmaHal *hal,int channel_id,int direction)
{
    GdmaChannelRegisters *channel = gdma_ahb_channel(hal,channel_id);
    unsigned int address = (unsigned int)(uintptr_t)channel;
    return address + (direction == GDMA_DIRECTION_RECEIVE ? 0x0cU : 0x6cU);
}

/* Native entry: 0x4202467c. */
/*
 * Medius v3.4.7 — device application; 0x4202467c.
 * Instruction-checked recovered C.
 * Original function-byte SHA-256:
 * bb29d0e4e8df71fa88a87c614770e316436fb1349da5b083631797fc6277e181.
 */

/* Take one MEMW/read of interrupt-enable, then OR events for nonzero LOW
 * BYTE of enabled, or clear events for zero; MEMW/write follows. Preserve
 * other bits without filtering the event mask. No W1C acknowledgement, lock,
 * status return or CPU interrupt allocation/enable in this operation. */
void gdma_ahb_hal_enable_intr(GdmaHal *hal,int channel_id,int direction,
    unsigned int events,unsigned char enabled)
{
    GdmaChannelRegisters *channel = gdma_ahb_channel(hal,channel_id);
    volatile unsigned int *reg = direction == GDMA_DIRECTION_RECEIVE ? &channel->rx.interrupt_enable : &channel->tx.interrupt_enable;
    memw();
    unsigned int previous = *reg;
    memw();
    *reg = enabled ? previous | events : previous & ~events;
}

/* Native entry: 0x420246d4. */
/*
 * Medius v3.4.7 — device application; 0x420246d4.
 * Instruction-checked recovered C.
 * Original function-byte SHA-256:
 * 59bb0c5a885b702c2474589154fcef90062bb85744af99c044ecd5fbac117d50.
 */

/* Reset the selected channel with separate CONF0 bit-0 set/clear RMWs,
 * then replace the six-bit peripheral ID with peripheral_id & 63. RX finally
 * sets memory-to-memory bit 4 iff peripheral_type is EXACTLY 0 (M2M), clearing
 * it for all other types through another fresh RMW. TX ignores the type.
 * No peripheral ID/type validation, descriptor update, idle wait or status. */
void gdma_ahb_hal_connect_peri(GdmaHal *hal,int channel_id,int direction,
    int peripheral_type,int peripheral_id)
{
    GdmaChannelRegisters *channel = gdma_ahb_channel(hal,channel_id);
    if (direction == GDMA_DIRECTION_RECEIVE) {
        gdma_ahb_replace_bits(&channel->rx.configuration0,0,1);
        gdma_ahb_replace_bits(&channel->rx.configuration0,1,0);
        gdma_ahb_replace_bits(&channel->rx.peripheral,63,(unsigned int)peripheral_id & 63U);
        gdma_ahb_replace_bits(&channel->rx.configuration0,16,peripheral_type == 0 ? 16 : 0);
    } else {
        gdma_ahb_replace_bits(&channel->tx.configuration0,0,1);
        gdma_ahb_replace_bits(&channel->tx.configuration0,1,0);
        gdma_ahb_replace_bits(&channel->tx.peripheral,63,(unsigned int)peripheral_id & 63U);
    }
}

/* Native entry: 0x4038959c. */
/*
 * Medius v3.4.7 — device application; 0x4038959c.
 * Instruction-checked recovered C.
 * Original function-byte SHA-256:
 * 237719130764221958d9de5d2f07e6067c04ad73dcc42ea3237592c41a43ae42.
 */

/* Dispatch clear_interrupt from HAL offset 0x38 with unchanged context,
 * channel, direction and full event mask. No validation, direct MMIO, MEMW
 * or status return here. The installed AHB implementation performs W1C. */
void gdma_hal_clear_intr(GdmaHal *hal,int channel_id,int direction,unsigned int events)
{
    hal->clear_interrupt(hal,channel_id,direction,events);
}

/* Native entry: 0x403895b0. */
/*
 * Medius v3.4.7 — device application; 0x403895b0.
 * Instruction-checked recovered C.
 * Original function-byte SHA-256:
 * 23f852fdf74c6543159fb9d207336c60888062f013b60ef578fcefa613e090c8.
 */

/* Dispatch start_with_desc from offset 0x08, forwarding the full descriptor
 * address and other arguments unchanged. Address truncation belongs to the
 * AHB callback, not this wrapper. No NULL check, MMIO, wait or status. */
void gdma_hal_start_with_desc(GdmaHal *hal,int channel_id,int direction,
    unsigned int descriptor_address)
{
    hal->start_with_desc(hal,channel_id,direction,descriptor_address);
}

/* Native entry: 0x42024778. */
/*
 * Medius v3.4.7 — device application; 0x42024778.
 * Instruction-checked recovered C.
 * Original function-byte SHA-256:
 * 2a8ded8a20c01220a93c8a02a611e2cf40d42e8b6cf20610e3b4d58ba1cb4e9f.
 */

/* Clear ONLY the first context word (device pointer). Keep private data
 * and every callback untouched. No hardware STOP/reset, interrupt disable,
 * memory release, MEMW, lock or status. Later dispatch is not prevented. */
void gdma_hal_deinit(GdmaHal *hal)
{
    ((volatile GdmaHal *)hal)->device = NULL;
}

/* Native entry: 0x42024784. */
/*
 * Medius v3.4.7 — device application; 0x42024784.
 * Instruction-checked recovered C.
 * Original function-byte SHA-256:
 * bcd1f47ae1460e04f1fab95dc46a948aa1add256449190602b78ef1d3711440b.
 */

/* Dispatch set_priority from offset 0x18, forwarding priority unchanged.
 * The AHB callback truncates to four bits; this wrapper does not. No NULL
 * check, validation, MMIO, lock, wait or returned status. */
void gdma_hal_set_priority(GdmaHal *hal,int channel_id,int direction,unsigned int priority)
{
    hal->set_priority(hal,channel_id,direction,priority);
}

/* Native entry: 0x42024798. */
/*
 * Medius v3.4.7 — device application; 0x42024798.
 * Instruction-checked recovered C.
 * Original function-byte SHA-256:
 * e058439c149094ec6fa2d2045d4507b7d1893b138aebce964ed9ab22fa44c371.
 */

/* Dispatch connect_peripheral from offset 0x1c with channel, direction,
 * peripheral type and peripheral ID unchanged. Reset, selector truncation
 * and RX M2M handling belong to the callback. No guard, MMIO or status here. */
void gdma_hal_connect_peri(GdmaHal *hal,int channel_id,int direction,
    int peripheral_type,int peripheral_id)
{
    hal->connect_peripheral(hal,channel_id,direction,peripheral_type,peripheral_id);
}

/* Native entry: 0x420247ac. */
/*
 * Medius v3.4.7 — device application; 0x420247ac.
 * Instruction-checked recovered C.
 * Original function-byte SHA-256:
 * e80c1f3dec7b11e4c9048004ec76e839531ee53f1f146caa6b8ea8b55efc5b7a.
 */

/* Dispatch disconnect_peripheral at offset 0x20 with unchanged context,
 * channel and direction. No NULL check, direct hardware access, lock, STOP,
 * acknowledgement or return status; selector changes belong to the callback. */
void gdma_hal_disconnect_peri(GdmaHal *hal,int channel_id,int direction)
{
    hal->disconnect_peripheral(hal,channel_id,direction);
}

/* Native entry: 0x420247bc. */
/*
 * Medius v3.4.7 — device application; 0x420247bc.
 * Instruction-checked recovered C.
 * Original function-byte SHA-256:
 * 4b5076e1399c8a7ffa4499fe5c1435be8a9d590786f1578a4d200bea22946074.
 */

/* Dispatch enable_burst at offset 0x24. Forward LOW BYTE of each burst
 * argument without normalizing nonzero values to 1; the AHB callback uses
 * only their low bits. No callback guard, MMIO, lock or returned status. */
void gdma_hal_enable_burst(GdmaHal *hal,int channel_id,int direction,
    unsigned char data_burst,unsigned char descriptor_burst)
{
    hal->enable_burst(hal,channel_id,direction,data_burst,descriptor_burst);
}

/* Native entry: 0x420247d4. */
/*
 * Medius v3.4.7 — device application; 0x420247d4.
 * Instruction-checked recovered C.
 * Original function-byte SHA-256:
 * be156e7140c2fbcd7796fd1aad677e5f07489e5ef4db72e5500848d3f8793f95.
 */

/* Read optional set_burst_size callback at offset 0x28 ONCE. If NULL,
 * return silently; otherwise call that saved pointer with unchanged arguments.
 * Do not reread the slot between the test and call, or validate burst size
 * here. No direct MMIO, MEMW, lock or returned success/error status. */
void gdma_hal_set_burst_size(GdmaHal *hal,int channel_id,int direction,unsigned int burst_bytes)
{
    void (*set_burst_size)(GdmaHal *,int,int,unsigned int) = hal->set_burst_size;
    if (set_burst_size != NULL)
        set_burst_size(hal,channel_id,direction,burst_bytes);
}

/* Native entry: 0x420247e8. */
/*
 * Medius v3.4.7 — device application; 0x420247e8.
 * Instruction-checked recovered C.
 * Original function-byte SHA-256:
 * 718f5cc013d7ee1b73416fac47b7736673f213ae47fc5beb3037d7895c43038e.
 */

/* Dispatch enable_interrupt at offset 0x34. Forward the complete event
 * mask and LOW BYTE of enabled unchanged; the AHB callback treats that byte
 * as truth. No callback guard, direct MMIO, CPU interrupt allocation, lock
 * or returned status in this wrapper. */
void gdma_hal_enable_intr(GdmaHal *hal,int channel_id,int direction,
    unsigned int events,unsigned char enabled)
{
    hal->enable_interrupt(hal,channel_id,direction,events,enabled);
}
