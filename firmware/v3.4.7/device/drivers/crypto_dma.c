/* Medius v3.4.7 device — shared SHA/AES GDMA channel management. */
#include "../include/types.h"

/* Native entry: 0x42017764. */
/* Original function-byte SHA-256:
 * 656bae5189ffc6211800bfc57aa36af1761e7da662cf99a4f3ca37a701e0a1b4. */
/* Allocate independent TX then RX GDMA handles for shared AES/SHA use.
 * Each side gets at most11 allocation attempts with vTaskDelay(100 ticks)
 * between failures. These are scheduler ticks, not a wall-clock timeout.
 * Final TX failure clears TX before logging. Final RX failure clears RX,
 * deletes the freshly loaded TX handle (ignoring status), then logs. Both
 * slots are cleared TX-first after the diagnostic; return the ORIGINAL
 * allocator error, not delete/log status. Existing unrelated RX ownership
 * is not recovered after TX failure. No reentry guard or local lock.
 *
 * Success requests external-memory access and16-byte TX burst, then0-byte
 * RX burst. The transfer-config padding remains uninitialized. Ignore both
 * configuration statuses, connect RX then TX to one cached AES trigger, and
 * return0 even if configuration/connection failed. No failure rollback after
 * allocation success. Shared lock/initialization serialization belongs outside.
 */
int crypto_shared_gdma_init(void)
{
    GdmaAllocConfig tx_config;
    GdmaAllocConfig rx_config;
    tx_config.sibling = NULL;
    rx_config.sibling = NULL;
    rx_config.direction = GDMA_DIRECTION_RECEIVE;
    tx_config.direction = GDMA_DIRECTION_TRANSMIT;
    tx_config.flags.word = 0;
    rx_config.flags.word = 0;
    int allocation_error;
    unsigned int attempts_left = 11;
    for (;;) {
        allocation_error = do_allocate_gdma_channel(&tx_config,
            (GdmaChannel **)&CRYPTO_TX_CHANNEL);
        --attempts_left;
        if (allocation_error == 0)
            break;
        if (attempts_left == 0) {
            CRYPTO_TX_CHANNEL = 0;
            goto failure;
        }
        vTaskDelay(100U);
    }
    attempts_left = 11;
    for (;;) {
        allocation_error = do_allocate_gdma_channel(&rx_config,
            (GdmaChannel **)&CRYPTO_RX_CHANNEL);
        --attempts_left;
        if (allocation_error == 0)
            break;
        if (attempts_left == 0) {
            GdmaChannel *tx = CRYPTO_TX_CHANNEL;
            CRYPTO_RX_CHANNEL = 0;
            (void)gdma_del_channel(tx);
            goto failure;
        }
        vTaskDelay(100U);
    }
    /* Native channel snapshots precede the corresponding stack-field writes.
     * Transfer-config padding remains untouched. */
    GdmaChannel *transmit_channel = CRYPTO_TX_CHANNEL;
    GdmaTransferConfig transfer_config;
    transfer_config.max_data_burst_size = 16U;
    transfer_config.access_external_memory = 1;
    (void)gdma_config_transfer(transmit_channel,&transfer_config);
    GdmaChannel *receive_channel = CRYPTO_RX_CHANNEL;
    transfer_config.max_data_burst_size = 0;
    (void)gdma_config_transfer(receive_channel,&transfer_config);
    receive_channel = CRYPTO_RX_CHANNEL;
    GdmaTrigger trigger;
    trigger.peripheral_type = CRYPTO_AES_TRIGGER->peripheral_type;
    trigger.instance_id = CRYPTO_AES_TRIGGER->instance_id;
    trigger.bus_id = CRYPTO_AES_TRIGGER->bus_id;
    (void)gdma_connect(receive_channel,trigger);
    (void)gdma_connect(CRYPTO_TX_CHANNEL,trigger);
    return 0;
failure:
    ;
    unsigned int timestamp = esp_log_timestamp();
    esp_log_write(1,"crypto_shared_gdma",
        "E (%lu) %s: Failed to acquire DMA channel, Err=%d\n",
        timestamp,"crypto_shared_gdma",allocation_error);
    CRYPTO_TX_CHANNEL = 0;
    CRYPTO_RX_CHANNEL = 0;
    return allocation_error;
}

/* Native entry: 0x42017830. */
/* Original function-byte SHA-256:
 * 4b505732281f24ec79e4a26240ebff845947803995ee87c54f54bd642ad424fd. */
/* Start shared crypto DMA for AES(4) or SHA(5). Lazily initialize only
 * when TX is NULL, propagating that allocation error; an existing TX does
 * not imply RX is checked. Disconnect TX BEFORE validating peripheral, so
 * invalid selection returns0x102 after a disconnect and possible allocation.
 * Copy selected DROM trigger fields in native order bus,type,instance, then
 * reconnect a freshly loaded TX. Ignore disconnect/connect/query/start errors.
 *
 * RX channel ID starts0; query its ID, then pulse RX configuration bit0 with
 * two separately fenced read/modify/write pairs. The address calculation wraps
 * at32 bits without bounds validation. A failed query that leaves ID untouched
 * therefore targets RX0. Start freshly loaded TX then RX; output may be NULL
 * (as for SHA), and this function still calls the RX starter with address0.
 * Return0 without verifying either start or waiting for completion. Caller
 * owns serialization, descriptor validity and subsequent completion handling.
 */
int esp_crypto_shared_gdma_start(const CryptoDmaDescriptor *input,
    const CryptoDmaDescriptor *output,unsigned int peripheral)
{
    GdmaChannel *tx = CRYPTO_TX_CHANNEL;
    int rx_channel_id = 0;
    if (tx == 0) {
        int status = crypto_shared_gdma_init();
        if (status != 0)
            return status;
        tx = CRYPTO_TX_CHANNEL;
    }
    (void)gdma_disconnect(tx);
    const volatile GdmaTrigger *selected;
    if (peripheral == 5U)
        selected = CRYPTO_SHA_TRIGGER;
    else if (peripheral == 4U)
        selected = CRYPTO_AES_TRIGGER;
    else
        return 0x102;
    GdmaTrigger trigger;
    trigger.bus_id = selected->bus_id;
    trigger.peripheral_type = selected->peripheral_type;
    trigger.instance_id = selected->instance_id;
    (void)gdma_connect(CRYPTO_TX_CHANNEL,trigger);
    (void)gdma_get_group_channel_id(CRYPTO_RX_CHANNEL,0,&rx_channel_id);
    unsigned int rx_register_address = 0x6003f000U + (unsigned int)rx_channel_id * 0xc0U;
    GdmaDirectionRegisters *rx_registers = (GdmaDirectionRegisters *)rx_register_address;
    memw();
    unsigned int configuration = rx_registers->configuration0;
    memw();
    rx_registers->configuration0 = configuration | 1U;
    memw();
    configuration = rx_registers->configuration0;
    memw();
    rx_registers->configuration0 = configuration & ~1U;
    (void)gdma_start(CRYPTO_TX_CHANNEL,(unsigned int)input);
    (void)gdma_start(CRYPTO_RX_CHANNEL,(unsigned int)output);
    return 0;
}
