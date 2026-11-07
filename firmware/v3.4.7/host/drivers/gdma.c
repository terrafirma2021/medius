/* Medius v3.4.7 host: recovered GDMA driver ownership and channel control. */

#include "../include/types.h"

/* reconstruction utilities: native indexed table addresses wrap at 32 bits.
 * Do not add C array-bounds assumptions to the unchecked group/pair IDs.
 * All helpers inline; volatile table accesses retain the native live loads. */
static __inline__ __attribute__((always_inline)) volatile unsigned int *
gdma_driver_reference(volatile unsigned int *base,int index)
{
    unsigned int address = (unsigned int)(uintptr_t)base + (unsigned int)index * 4U;
    return (volatile unsigned int *)(uintptr_t)address;
}
static __inline__ __attribute__((always_inline)) GdmaGroup *volatile *
gdma_driver_group_slot(int index)
{
    unsigned int address = (unsigned int)(uintptr_t)&GDMA_PLATFORM->groups[0] + (unsigned int)index * 4U;
    return (GdmaGroup *volatile *)(uintptr_t)address;
}
static __inline__ __attribute__((always_inline)) GdmaPair *volatile *
gdma_driver_pair_slot(GdmaGroup *group,int index)
{
    unsigned int address = (unsigned int)(uintptr_t)&group->pairs[0] + (unsigned int)index * 4U;
    return (GdmaPair *volatile *)(uintptr_t)address;
}

/* Native entry: 0x4037fab4. */
/*
 * Medius v3.4.7 — host application; 0x4037fab4.
 * Instruction-checked recovered C.
 * Original function-byte SHA-256:
 * fbcc4c3e87ad396a965258bea980be47671b1ef7fed3f772aab11f5318d8cba6.
 */

/* Reject NULL with 0x102 and a channel whose ETM-control flag byte has bit
 * 0 set with 0x103. Each error prints only when the live early-log level is
 * nonzero. Save pair/group before entering the channel spinlock; call the
 * ISR-context selector before both lock and unlock, ignoring its result.
 * Under that lock, freshly read direction then pair ID and dispatch START
 * with the descriptor address unchanged. Return 0 after unlock. No descriptor
 * validation, peripheral-state check, idle wait or hardware-completion status. */
int gdma_start(GdmaChannel *channel,unsigned int descriptor_address)
{
    if (channel == NULL) {
        if (SYSTEM_EARLY_LOG_LEVEL != 0) {
            unsigned int timestamp = esp_log_timestamp();
            ets_printf("E (%lu) %s: %s(%d): invalid argument\n",timestamp,"gdma","gdma_start",532);
        }
        return 0x102;
    }
    if (channel->flags.bits & 1U) {
        if (SYSTEM_EARLY_LOG_LEVEL != 0) {
            unsigned int timestamp = esp_log_timestamp();
            ets_printf("E (%lu) %s: %s(%d): channel is controlled by ETM\n",timestamp,"gdma","gdma_start",533);
        }
        return 0x103;
    }
    GdmaPair *pair = channel->pair;
    GdmaGroup *group = pair->group;
    (void)xPortInIsrContext();
    (void)xPortEnterCriticalTimeout(&channel->lock,-1);
    int direction = channel->direction;
    int pair_id = pair->pair_id;
    gdma_hal_start_with_desc(&group->hal,pair_id,direction,descriptor_address);
    (void)xPortInIsrContext();
    vPortExitCritical(&channel->lock);
    return 0;
}

/* Native entry: 0x42022e3c. */
/*
 * Medius v3.4.7 — host application; 0x42022e3c.
 * Instruction-checked recovered C.
 * Original function-byte SHA-256:
 * 88704f3f5b02e95155ebd6f5d4c839e5eac7d0ed4c967f548bcb52ce34fd542f.
 */

/* NULL logs and returns 0x102. Otherwise read pair, direction, group and
 * pair ID, dispatch priority 0, then freshly load the channel's destruction
 * callback and return its result unchanged. No channel lock, STOP, peripheral
 * disconnect, ETM check or callback-NULL guard is added by this API. */
int gdma_del_channel(GdmaChannel *channel)
{
    if (channel == NULL) {
        unsigned int timestamp = esp_log_timestamp();
        esp_log_write(1,"gdma","E (%lu) %s: %s(%d): invalid argument\n",timestamp,"gdma","gdma_del_channel",235);
        return 0x102;
    }
    GdmaPair *pair = channel->pair;
    int direction = channel->direction;
    GdmaGroup *group = pair->group;
    int pair_id = pair->pair_id;
    gdma_hal_set_priority(&group->hal,pair_id,direction,0);
    return channel->destroy(channel);
}

/* Native entry: 0x42022e84. */
/*
 * Medius v3.4.7 — host application; 0x42022e84.
 * Instruction-checked recovered C.
 * Original function-byte SHA-256:
 * 546d732e44745f0a5c104d140a5fac30a35eb36a1971a34f57fb361bdc04e81f.
 */

/* NULL channel logs and returns 0x102. Otherwise cache its pair pointer,
 * optionally write group ID, then optionally write pair ID, returning 0.
 * Both output pointers may be NULL. Do not snapshot pair ID before the first
 * output write: native pointer aliasing can affect the later read. No lock. */
int gdma_get_group_channel_id(GdmaChannel *channel,int *group_id,int *channel_id)
{
    if (channel == NULL) {
        unsigned int timestamp = esp_log_timestamp();
        esp_log_write(1,"gdma","E (%lu) %s: %s(%d): invalid argument\n",timestamp,"gdma","gdma_get_group_channel_id",251);
        return 0x102;
    }
    GdmaPair *pair = channel->pair;
    if (group_id != NULL)
        *(volatile int *)group_id = pair->group->group_id;
    if (channel_id != NULL)
        *(volatile int *)channel_id = pair->pair_id;
    return 0;
}

/* Native entry: 0x42022ff4. */
/*
 * Medius v3.4.7 — host application; 0x42022ff4.
 * Instruction-checked recovered C.
 * Original function-byte SHA-256:
 * 0d8878befd9b02659ca3c42c49a7ecb5be520db8a6fe5ef214c1223b3b2018ab.
 */

/* NULL logs/returns 0x102; peripheral sentinel 63 logs/returns 0x103.
 * Save peripheral ID, pair/group and direction. For a nonnegative ID, clear
 * its bit in TX mask when direction is 0, otherwise RX mask, under the group
 * spinlock. Native shifts use ID modulo 32; no upper-ID validation. Negative
 * IDs skip mask bookkeeping. After unlock freshly read direction again.
 * Dispatch disconnect using a fresh pair ID, then set channel peripheral ID
 * to 63 and return 0. No channel lock, STOP, transfer-idle check or rollback. */
int gdma_disconnect(GdmaChannel *channel)
{
    if (channel == NULL) {
        unsigned int timestamp = esp_log_timestamp();
        esp_log_write(1,"gdma","E (%lu) %s: %s(%d): invalid argument\n",timestamp,"gdma","gdma_disconnect",307);
        return 0x102;
    }
    int peripheral_id = channel->peripheral_id;
    if (peripheral_id == 63) {
        unsigned int timestamp = esp_log_timestamp();
        esp_log_write(1,"gdma","E (%lu) %s: %s(%d): no peripheral is connected to the channel\n",timestamp,"gdma","gdma_disconnect",308);
        return 0x103;
    }
    GdmaPair *pair = channel->pair;
    int direction = channel->direction;
    GdmaGroup *group = pair->group;
    if (peripheral_id >= 0) {
        (void)xPortEnterCriticalTimeout(&group->lock,-1);
        unsigned int bit = 1U << ((unsigned int)peripheral_id & 31U);
        if (direction == GDMA_DIRECTION_TRANSMIT)
            group->tx_peripherals &= ~bit;
        else
            group->rx_peripherals &= ~bit;
        vPortExitCritical(&group->lock);
        direction = channel->direction;
    }
    gdma_hal_disconnect_peri(&group->hal,pair->pair_id,direction);
    channel->peripheral_id = 63;
    return 0;
}

/* Native entry: 0x420230cc. */
/*
 * Medius v3.4.7 — host application; 0x420230cc.
 * Instruction-checked recovered C.
 * Original function-byte SHA-256:
 * e9cafaf5e62bab0fdee7eb1ef4b766bde675f104f53db9c906ac02ab5bac43f0.
 */

/* Validate non-NULL channel/config and require a nonzero burst request to
 * be a power of two; errors log and return 0x102 before HAL writes. Burst 0
 * disables data burst while keeping descriptor burst enabled. Nonzero enables
 * both first, then calls optional burst-size programming. The AHB callback can
 * abort for power-of-two sizes outside 16/32/64 AFTER burst has been enabled.
 *
 * Only RX direction 1 with nonzero burst gets internal alignment 4 and external
 * alignment equal to that burst. All other cases use 1/1. Read the external-
 * access byte after HAL calls and BEFORE publishing internal alignment; zero
 * forces external alignment to 0x80000000. Nonzero bytes are truth, not low-bit
 * flags. Publish internal then external alignment and return 0. No lock,
 * descriptor/buffer validation, cache operation or transfer start. */
int gdma_config_transfer(GdmaChannel *channel,const GdmaTransferConfig *configuration)
{
    if (channel == NULL || configuration == NULL) {
        unsigned int timestamp = esp_log_timestamp();
        esp_log_write(1,"gdma","E (%lu) %s: %s(%d): invalid argument\n",timestamp,"gdma","gdma_config_transfer",353);
        return 0x102;
    }
    unsigned int burst = configuration->max_data_burst_size;
    if (burst != 0 && ((burst - 1U) & burst) != 0) {
        unsigned int timestamp = esp_log_timestamp();
        esp_log_write(1,"gdma","E (%lu) %s: %s(%d): invalid max_data_burst_size: %lu\n",timestamp,"gdma","gdma_config_transfer",357,burst);
        return 0x102;
    }
    GdmaPair *pair = channel->pair;
    GdmaGroup *group = pair->group;
    unsigned int internal_alignment = 1;
    unsigned int external_alignment = 1;
    if (burst != 0) {
        gdma_hal_enable_burst(&group->hal,pair->pair_id,channel->direction,1,1);
        gdma_hal_set_burst_size(&group->hal,pair->pair_id,channel->direction,burst);
        if (channel->direction == GDMA_DIRECTION_RECEIVE) {
            internal_alignment = 4;
            external_alignment = burst;
        }
    } else {
        gdma_hal_enable_burst(&group->hal,pair->pair_id,channel->direction,0,1);
    }
    unsigned char external_access = configuration->access_external_memory;
    channel->internal_alignment = internal_alignment;
    channel->external_alignment = external_access ? external_alignment : 0x80000000U;
    return 0;
}

/* Native entry: 0x42022750. */
/*
 * Medius v3.4.7 — host application; 0x42022750.
 * Instruction-checked recovered C.
 * Original function-byte SHA-256:
 * c84680766baa25e103b070ab10a25dbc704ebffdc009d4ad9c3e213d0ae5db98.
 */

/* Read group ID, then decrement its platform reference word under the
 * platform lock. Arithmetic wraps at 32 bits; zero-to-UINT_MAX is not rejected.
 * A nonzero result only unlocks. At zero, assert that the indexed group slot
 * is non-NULL (not that it equals this argument), clear it, then unlock.
 * Clear only the HAL device pointer, lock peripheral RCC, clear GDMA clock
 * enable bit 6 using a fresh MEMW/RMW, unlock RCC and free the supplied group.
 * No bounds check, channel-idle wait, reset assertion or returned status. */
void gdma_release_group_handle(GdmaGroup *group)
{
    int group_id = group->group_id;
    (void)xPortEnterCriticalTimeout(&GDMA_PLATFORM->lock,-1);
    volatile unsigned int *reference = gdma_driver_reference(&GDMA_PLATFORM->group_references[0],group_id);
    unsigned int remaining = *reference - 1U;
    *reference = remaining;
    if (remaining != 0) {
        vPortExitCritical(&GDMA_PLATFORM->lock);
        return;
    }
    GdmaGroup *volatile *slot = gdma_driver_group_slot(group_id);
    if (*slot == NULL)
        __assert_func(0,0,0,0);
    *slot = NULL;
    vPortExitCritical(&GDMA_PLATFORM->lock);
    gdma_hal_deinit(&group->hal);
    periph_rcc_enter();
    memw();
    unsigned int clock = GDMA_RCC->clock_enable1;
    memw();
    GDMA_RCC->clock_enable1 = clock & ~0x40U;
    periph_rcc_exit();
    free(group);
}

/* Native entry: 0x420227c8. */
/*
 * Medius v3.4.7 — host application; 0x420227c8.
 * Instruction-checked recovered C.
 * Original function-byte SHA-256:
 * 78a32e202c7ee22680f8e3e8712d2f7d11fb3858ef8a584fd67266156bc06788.
 */

/* Save pair group/ID and decrement that pair's group reference word while
 * holding the group lock. Native 32-bit wrap is retained without underflow
 * validation. At nonzero only unlock. At zero assert the indexed pair slot is
 * non-NULL, clear it, unlock, free this pair, then release its group reference.
 * IDs are unchecked; slot identity and channel emptiness are not tested.
 * No pair lock, hardware access, wait or returned status in this routine. */
void gdma_release_pair_handle(GdmaPair *pair)
{
    GdmaGroup *group = pair->group;
    int pair_id = pair->pair_id;
    (void)xPortEnterCriticalTimeout(&group->lock,-1);
    volatile unsigned int *reference = gdma_driver_reference(&group->pair_references[0],pair_id);
    unsigned int remaining = *reference - 1U;
    *reference = remaining;
    if (remaining != 0) {
        vPortExitCritical(&group->lock);
        return;
    }
    GdmaPair *volatile *slot = gdma_driver_pair_slot(group,pair_id);
    if (*slot == NULL)
        __assert_func(0,0,0,0);
    *slot = NULL;
    vPortExitCritical(&group->lock);
    free(pair);
    gdma_release_group_handle(group);
}

/* Native entry: 0x42022824. */
/*
 * Medius v3.4.7 — host application; 0x42022824.
 * Instruction-checked recovered C.
 * Original function-byte SHA-256:
 * fab84e17f316a88bcda99535408d44dca21a0a17648e5302aca6614f1e07d3db.
 */

/* Cache pair/group/ID, then under the pair lock read occupancy, clear RX
 * slot and publish occupancy with bit 0 cleared. After unlock freshly read
 * the channel interrupt handle. If present, free it (ignore status), relock
 * the pair, disable every RX interrupt using the CACHED ID, then clear every
 * RX interrupt using a FRESH pair-ID read. Unlock, free channel storage, release
 * pair reference and return 0. No NULL/ownership check, STOP, idle wait or
 * peripheral-use-mask cleanup; those operations are not silently added here. */
int gdma_del_rx_channel(GdmaChannel *channel)
{
    GdmaPair *pair = channel->pair;
    GdmaGroup *group = pair->group;
    int pair_id = pair->pair_id;
    (void)xPortEnterCriticalTimeout(&pair->lock,-1);
    unsigned int occupancy = pair->occupancy;
    pair->rx_channel = NULL;
    pair->occupancy = occupancy & ~1U;
    vPortExitCritical(&pair->lock);
    InterruptHandle *interrupt = channel->interrupt;
    if (interrupt != NULL) {
        (void)esp_intr_free(interrupt);
        (void)xPortEnterCriticalTimeout(&pair->lock,-1);
        gdma_hal_enable_intr(&group->hal,pair_id,GDMA_DIRECTION_RECEIVE,0xffffffffU,0);
        gdma_hal_clear_intr(&group->hal,pair->pair_id,GDMA_DIRECTION_RECEIVE,0xffffffffU);
        vPortExitCritical(&pair->lock);
    }
    free(channel);
    gdma_release_pair_handle(pair);
    return 0;
}

/* Native entry: 0x4202289c. */
/*
 * Medius v3.4.7 — host application; 0x4202289c.
 * Instruction-checked recovered C.
 * Original function-byte SHA-256:
 * 060facccb9d81d8d886d9e30c7889651916083fcf34c83703265555b3fd0db7f.
 */

/* Cache pair/group/ID. Under pair lock read occupancy, clear TX slot, then
 * publish occupancy with bit 1 cleared. After unlock read interrupt handle;
 * when present, free it ignoring status, relock, disable all TX events with
 * cached ID, clear all TX events with fresh pair-ID read, then unlock. Free
 * channel, release pair reference and return 0. No NULL/ownership validation,
 * STOP/idle wait, peripheral-use-mask cleanup or descriptor release. */
int gdma_del_tx_channel(GdmaChannel *channel)
{
    GdmaPair *pair = channel->pair;
    GdmaGroup *group = pair->group;
    int pair_id = pair->pair_id;
    (void)xPortEnterCriticalTimeout(&pair->lock,-1);
    unsigned int occupancy = pair->occupancy;
    pair->tx_channel = NULL;
    pair->occupancy = occupancy & ~2U;
    vPortExitCritical(&pair->lock);
    InterruptHandle *interrupt = channel->interrupt;
    if (interrupt != NULL) {
        (void)esp_intr_free(interrupt);
        (void)xPortEnterCriticalTimeout(&pair->lock,-1);
        gdma_hal_enable_intr(&group->hal,pair_id,GDMA_DIRECTION_TRANSMIT,0xffffffffU,0);
        gdma_hal_clear_intr(&group->hal,pair->pair_id,GDMA_DIRECTION_TRANSMIT,0xffffffffU);
        vPortExitCritical(&pair->lock);
    }
    free(channel);
    gdma_release_pair_handle(pair);
    return 0;
}

/* Native entry: 0x42022ec8. */
/*
 * Medius v3.4.7 — host application; 0x42022ec8.
 * Instruction-checked recovered C.
 * Original function-byte SHA-256:
 * 6bf4c8994f453e5c8a33987db199dced0dce15fb918c38353aca4e94577fdc7c.
 */

/* The trigger is a 12-byte value carried in native A3/A4/A5: type, signed
 * instance ID, bus ID. NULL channel or bus mismatch logs/returns 0x102. An
 * existing peripheral other than sentinel 63, or a claimed trigger bit, logs/
 * returns 0x103. A bus ID of -1 bypasses bus matching.
 *
 * Nonnegative instance IDs claim one mask bit under group lock: TX mask only
 * for direction 0, RX mask otherwise. Native bit selection uses ID modulo 32;
 * negative IDs bypass bookkeeping. After a successful claim reload direction,
 * dispatch connection with a fresh pair ID, store the ORIGINAL signed instance
 * ID and return 0. No upper-ID/type validation, channel lock or rollback.
 * Two shared log emission sites retain the native diagnostic argument shapes. */
int gdma_connect(GdmaChannel *channel,GdmaTrigger trigger)
{
    unsigned int timestamp;
    const char *message;
    int source_line;
    if (channel == NULL) {
        timestamp = esp_log_timestamp();
        message = "E (%lu) %s: %s(%d): invalid argument\n";
        source_line = 265;
invalid_argument:
        esp_log_write(1,"gdma",message,timestamp,"gdma","gdma_connect",source_line);
        return 0x102;
    }
    int error_id;
    if (channel->peripheral_id != 63) {
        timestamp = esp_log_timestamp();
        error_id = channel->peripheral_id;
        message = "E (%lu) %s: %s(%d): channel is using by peripheral: %d\n";
        source_line = 266;
        goto invalid_state;
    }
    GdmaPair *pair = channel->pair;
    GdmaGroup *group = pair->group;
    if (trigger.bus_id != -1 && group->bus_id != trigger.bus_id) {
        timestamp = esp_log_timestamp();
        message = "E (%lu) %s: %s(%d): peripheral and DMA system bus mismatch\n";
        source_line = 273;
        goto invalid_argument;
    }
    int direction = channel->direction;
    if (trigger.instance_id >= 0) {
        (void)xPortEnterCriticalTimeout(&group->lock,-1);
        unsigned int bit = 1U << ((unsigned int)trigger.instance_id & 31U);
        volatile unsigned int *mask = direction == GDMA_DIRECTION_TRANSMIT ? &group->tx_peripherals : &group->rx_peripherals;
        unsigned int occupied = *mask;
        if ((occupied & bit) != 0) {
            vPortExitCritical(&group->lock);
            timestamp = esp_log_timestamp();
            error_id = trigger.instance_id;
            message = "E (%lu) %s: %s(%d): peripheral %d is already used by another channel\n";
            source_line = 299;
            goto invalid_state;
        }
        *mask = occupied | bit;
        vPortExitCritical(&group->lock);
        direction = channel->direction;
    }
    gdma_hal_connect_peri(&group->hal,pair->pair_id,direction,trigger.peripheral_type,trigger.instance_id);
    channel->peripheral_id = trigger.instance_id;
    return 0;
invalid_state:
    esp_log_write(1,"gdma",message,timestamp,"gdma","gdma_connect",source_line,error_id);
    return 0x103;
}

/* Native entry: 0x42022914. */
/*
 * Medius v3.4.7 — host application; 0x42022914.
 * Instruction-checked recovered C.
 * Original function-byte SHA-256:
 * d8d3547859b4538b34fe2633c93e2d5d207bd2fc6a82ab2893adf80e5ab9ec93.
 */

/* Allocate TX (52 bytes) for direction 0 or RX (56 bytes) for direction 1.
 * All allocations use capability mask 0x804 (internal, byte-addressable) and
 * zeroed storage. Input/output pointers must be non-NULL; failures do not clear
 * the caller's output. Read reserve-sibling FLAG BYTE before direction; read
 * the full flags WORD again when publishing the selected channel.
 *
 * With a supplied sibling, require its pair and a different direction, then
 * add a pair reference without claiming occupancy bits. Same-direction error
 * frees this call's allocation and RELEASES the supplied pair despite not yet
 * acquiring a reference. Without a sibling, search the single AHB group and
 * five pairs, claiming RX bit 0/TX bit 1 (both when reserving a sibling).
 * Allocate candidate group/pair storage BEFORE checking the existing slots;
 * memory pressure can therefore fail even when an existing object is reusable.
 *
 * Group/pair slots are published under their owning locks BEFORE initializing
 * object IDs, spinlocks and HAL. Preserve that native publication order. Group
 * creation enables/resets GDMA under RCC lock, then fills the HAL. Every pair
 * acquisition adds a temporary reference; a new pair also owns a group reference.
 * On a successful claim, add the channel's permanent pair reference, then drop
 * temporary pair/group references before registering the channel. Registration
 * writes the pair's channel slot before the channel metadata; the caller's output
 * is published before initializing that channel's lock.
 *
 * Unsupported directions are not given a new validation rule: no sibling and
 * no reserve flag asserts; other admitted paths can acquire/claim references
 * without allocating a channel, then initialize the lock of the EXISTING *out.
 * Errors return 0x102 (argument/sibling), 0x101 (memory), or 0x105 (no free pair).
 * Counts and indexed reference addresses retain 32-bit wrapping. No whole-
 * allocation lock, object-ready wait, transfer start or automatic interrupt
 * installation. Callback/user-data tails remain zero from allocation. */
int do_allocate_gdma_channel(const GdmaAllocConfig *configuration,GdmaChannel **out)
{
    unsigned int timestamp;
    const char *error_message;
    int source_line;
    int status;
    GdmaTxChannel *tx = NULL;
    GdmaRxChannel *rx = NULL;
    GdmaChannel *sibling;
    GdmaPair *pair;
    GdmaGroup *group;
    if (configuration == NULL || out == NULL) {
        timestamp = esp_log_timestamp();
        error_message = "E (%lu) %s: %s(%d): invalid argument\n";
        source_line = 83;
invalid_argument:
        esp_log_write(1,"gdma",error_message,timestamp,"gdma","do_allocate_gdma_channel",source_line);
        return 0x102;
    }
    unsigned char reserve_flags = configuration->flags.bits;
    int direction = configuration->direction;
    unsigned int search_mask = (reserve_flags & 1U) ? 3 : 0;
    if (direction == GDMA_DIRECTION_TRANSMIT) {
        tx = heap_caps_calloc(1,sizeof(*tx),0x804);
        if (tx == NULL) {
            timestamp = esp_log_timestamp();
            error_message = "E (%lu) %s: %s(%d): no mem for gdma tx channel\n";
            source_line = 91;
channel_allocation_failed:
            esp_log_write(1,"gdma",error_message,timestamp,"gdma","do_allocate_gdma_channel",source_line);
            return 0x101;
        }
        sibling = configuration->sibling;
        if (sibling == NULL) {
            search_mask |= 2;
            goto search_group;
        }
        pair = sibling->pair;
        if (pair == NULL) {
            timestamp = esp_log_timestamp();
            esp_log_write(1,"gdma","E (%lu) %s: %s(%d): invalid sibling channel\n",timestamp,"gdma","do_allocate_gdma_channel",100);
            free(tx);
            return 0x102;
        }
        int sibling_direction = sibling->direction;
        int requested_direction = configuration->direction;
        if (sibling_direction == requested_direction) {
            timestamp = esp_log_timestamp();
            esp_log_write(1,"gdma","E (%lu) %s: %s(%d): sibling channel should have a different direction\n",timestamp,"gdma","do_allocate_gdma_channel",101);
            free(tx);
            gdma_release_pair_handle(pair);
            return 0x102;
        }
    } else if (direction == GDMA_DIRECTION_RECEIVE) {
        rx = heap_caps_calloc(1,sizeof(*rx),0x804);
        if (rx == NULL) {
            timestamp = esp_log_timestamp();
            error_message = "E (%lu) %s: %s(%d): no mem for gdma rx channel\n";
            source_line = 95;
            goto channel_allocation_failed;
        }
        sibling = configuration->sibling;
        if (sibling == NULL) {
            search_mask |= 1;
            goto search_group;
        }
        pair = sibling->pair;
        if (pair == NULL) {
            timestamp = esp_log_timestamp();
            esp_log_write(1,"gdma","E (%lu) %s: %s(%d): invalid sibling channel\n",timestamp,"gdma","do_allocate_gdma_channel",100);
            free(rx);
            return 0x102;
        }
        int requested_direction = configuration->direction;
        int sibling_direction = sibling->direction;
        if (requested_direction == sibling_direction) {
            timestamp = esp_log_timestamp();
            esp_log_write(1,"gdma","E (%lu) %s: %s(%d): sibling channel should have a different direction\n",timestamp,"gdma","do_allocate_gdma_channel",101);
            free(rx);
            gdma_release_pair_handle(pair);
            return 0x102;
        }
    } else {
        sibling = configuration->sibling;
        if (sibling != NULL)
            goto unsupported_direction_sibling;
        if (search_mask == 0)
            __assert_func(0,0,0,0);
        search_mask = 3;
        goto search_group;
    }

attach_sibling:
    group = pair->group;
    (void)xPortEnterCriticalTimeout(&group->lock,-1);
    volatile unsigned int *sibling_reference = gdma_driver_reference(&group->pair_references[0],pair->pair_id);
    *sibling_reference = *sibling_reference + 1U;
    vPortExitCritical(&group->lock);
    goto register_channels;

search_group:
    GdmaGroup *candidate_group = heap_caps_calloc(1,sizeof(*candidate_group),0x804);
    if (candidate_group == NULL) {
        timestamp = esp_log_timestamp();
        esp_log_write(1,"gdma","E (%lu) %s: %s(%d): no mem for group(%d)\n",timestamp,"gdma","do_allocate_gdma_channel",115,0);
        status = 0x101;
        goto free_allocated_channels;
    }
    (void)xPortEnterCriticalTimeout(&GDMA_PLATFORM->lock,-1);
    unsigned int group_references = GDMA_PLATFORM->group_references[0];
    group = GDMA_PLATFORM->groups[0];
    ++group_references;
    GDMA_PLATFORM->group_references[0] = group_references;
    if (group == NULL) {
        GDMA_PLATFORM->groups[0] = candidate_group;
        vPortExitCritical(&GDMA_PLATFORM->lock);
        candidate_group->group_id = 0;
        *(volatile unsigned int *)&candidate_group->lock.owner = 0xb33fffffU;
        *(volatile unsigned int *)&candidate_group->lock.count = 0;
        periph_rcc_enter();
        memw();
        unsigned int clock = GDMA_RCC->clock_enable1;
        memw();
        GDMA_RCC->clock_enable1 = clock | 0x40U;
        memw();
        unsigned int reset = GDMA_RCC->reset_enable1;
        memw();
        GDMA_RCC->reset_enable1 = reset | 0x40U;
        memw();
        reset = GDMA_RCC->reset_enable1;
        memw();
        GDMA_RCC->reset_enable1 = reset & ~0x40U;
        periph_rcc_exit();
        GdmaHalConfig hal_configuration = { .group_id = 0 };
        gdma_ahb_hal_init(&candidate_group->hal,&hal_configuration);
        group = candidate_group;
    } else {
        vPortExitCritical(&GDMA_PLATFORM->lock);
        free(candidate_group);
    }
    group->bus_id = 0;
    for (int pair_id = 0; pair_id < 5; ++pair_id) {
        GdmaPair *candidate_pair = heap_caps_calloc(1,sizeof(*candidate_pair),0x804);
        if (candidate_pair == NULL) {
            timestamp = esp_log_timestamp();
            esp_log_write(1,"gdma","E (%lu) %s: %s(%d): no mem for pair(%d,%d)\n",timestamp,"gdma","do_allocate_gdma_channel",119,0,pair_id);
            if (tx != NULL)
                free(tx);
            if (rx != NULL)
                free(rx);
            gdma_release_group_handle(group);
            return 0x101;
        }
        (void)xPortEnterCriticalTimeout(&group->lock,-1);
        unsigned int references = group->pair_references[pair_id];
        pair = group->pairs[pair_id];
        ++references;
        group->pair_references[pair_id] = references;
        if (pair == NULL) {
            group->pairs[pair_id] = candidate_pair;
            vPortExitCritical(&group->lock);
            *(volatile unsigned int *)&candidate_pair->lock.owner = 0xb33fffffU;
            *(volatile unsigned int *)&candidate_pair->lock.count = 0;
            candidate_pair->group = group;
            candidate_pair->pair_id = pair_id;
            (void)xPortEnterCriticalTimeout(&GDMA_PLATFORM->lock,-1);
            volatile unsigned int *reference = gdma_driver_reference(&GDMA_PLATFORM->group_references[0],group->group_id);
            *reference = *reference + 1U;
            vPortExitCritical(&GDMA_PLATFORM->lock);
            pair = candidate_pair;
        } else {
            vPortExitCritical(&group->lock);
            free(candidate_pair);
        }
        (void)xPortEnterCriticalTimeout(&pair->lock,-1);
        unsigned int occupancy = pair->occupancy;
        if ((occupancy & search_mask) == 0) {
            pair->occupancy = occupancy | search_mask;
            vPortExitCritical(&pair->lock);
            (void)xPortEnterCriticalTimeout(&group->lock,-1);
            volatile unsigned int *reference = gdma_driver_reference(&group->pair_references[0],pair->pair_id);
            *reference = *reference + 1U;
            vPortExitCritical(&group->lock);
            gdma_release_pair_handle(pair);
            gdma_release_group_handle(group);
            goto register_channels;
        }
        vPortExitCritical(&pair->lock);
        gdma_release_pair_handle(pair);
    }
    gdma_release_group_handle(group);
    timestamp = esp_log_timestamp();
    esp_log_write(1,"gdma","E (%lu) %s: %s(%d): no free gdma channel, search code=%d\n",timestamp,"gdma","do_allocate_gdma_channel",141,search_mask);
    status = 0x105;
free_allocated_channels:
    if (tx != NULL)
        free(tx);
    if (rx != NULL)
        free(rx);
    return status;

register_channels:
    if (tx != NULL) {
        unsigned int flags = configuration->flags.word;
        unsigned char previous_flags = tx->base.flags.bits;
        pair->tx_channel = &tx->base;
        tx->base.flags.bits = (previous_flags & 0xfdU) | (flags & 2U);
        tx->base.direction = GDMA_DIRECTION_TRANSMIT;
        tx->base.destroy = gdma_del_tx_channel;
        tx->base.pair = pair;
        tx->base.peripheral_id = 63;
        *(GdmaChannel *volatile *)out = &tx->base;
    }
    GdmaChannel *selected;
    if (rx != NULL) {
        unsigned int flags = configuration->flags.word;
        unsigned char previous_flags = rx->base.flags.bits;
        pair->rx_channel = &rx->base;
        rx->base.flags.bits = (previous_flags & 0xfdU) | (flags & 2U);
        rx->base.direction = GDMA_DIRECTION_RECEIVE;
        rx->base.destroy = gdma_del_rx_channel;
        rx->base.pair = pair;
        rx->base.peripheral_id = 63;
        selected = &rx->base;
        *(GdmaChannel *volatile *)out = selected;
    } else {
        selected = *(GdmaChannel *volatile *)out;
    }
    *(volatile unsigned int *)&selected->lock.owner = 0xb33fffffU;
    *(volatile unsigned int *)&selected->lock.count = 0;
    return 0;

unsupported_direction_sibling:
    pair = sibling->pair;
    if (pair == NULL) {
        timestamp = esp_log_timestamp();
        error_message = "E (%lu) %s: %s(%d): invalid sibling channel\n";
        source_line = 100;
        goto invalid_argument;
    }
    if (direction == sibling->direction) {
        timestamp = esp_log_timestamp();
        esp_log_write(1,"gdma","E (%lu) %s: %s(%d): sibling channel should have a different direction\n",timestamp,"gdma","do_allocate_gdma_channel",101);
        gdma_release_pair_handle(pair);
        return 0x102;
    }
    goto attach_sibling;
}
