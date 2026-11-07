/* Medius v3.4.7 device: NVS item CRCs and header consistency. */
#include "../include/types.h"

/* Native entry: 0x420149cc. */
/* Original function-byte SHA-256:
 * 851bad5621a9e7b39ee5b9f2ab16dad7f9d634c02cd7a48cac01c418d61baaea. */
/* Chain ROM CRC32 over header bytes0..3, all16 key bytes, then all8 value
 * bytes, seeded with0xffffffff. Exclude the stored CRC word at4. Return the
 * ROM result unchanged; do not validate the item or complement the result. */
unsigned int nvs_item_crc32(const NvsItem *item)
{
    unsigned int crc = esp_rom_crc32_le(0xffffffffU,item,4);
    crc = esp_rom_crc32_le(crc,item->key,16);
    return esp_rom_crc32_le(crc,item->data,8);
}

/* Native entry: 0x420149f8. */
/* Original function-byte SHA-256:
 * 44f8babc8d47120d0b7df2c2494403d91f5254fe17ae23c0e11737841f23ccf2. */
/* Hash an item's identity: chain ROM CRC32 over namespace byte0, all16 key
 * bytes, then chunk-index byte3, starting at0xffffffff. Type, span, stored
 * CRC and value are excluded. Return all32 hash bits without validation. */
unsigned int nvs_item_identity_crc32(const NvsItem *item)
{
    unsigned int crc = esp_rom_crc32_le(0xffffffffU,item,1);
    crc = esp_rom_crc32_le(crc,item->key,16);
    return esp_rom_crc32_le(crc,&item->chunk_index,1);
}

/* Native entry: 0x42014a38. */
/* Original function-byte SHA-256:
 * 790bc0d219bf510a3dd8eff4ca4f7a8a2db488af03f175842d772a0681d33b0d. */
/* Check the saved CRC before interpreting the live type and payload fields.
 * Integer types require span1. BLOB_IDX48 requires span1, chunk0xff and a
 * size <=508000; its chunk count/version are not checked. Variable types
 *21/41/42 must fit the remaining byte capacity/span and their rounded length
 * must agree with span. BLOB_DATA42 additionally rejects chunk0xff.
 * entry_index narrows to a byte; capacity/span arithmetic wraps to16/8 bits
 * without a separate index bound. Reject unknown types. No data CRC check,
 * mutation, log call or pointer validation occurs here. */
bool nvs_item_header_is_consistent(const NvsItem *item,
    unsigned int entry_index)
{
    const volatile NvsItem *live_item = item;
    unsigned int expected_crc = live_item->crc32;
    unsigned int crc = esp_rom_crc32_le(0xffffffffU,item,4);
    crc = esp_rom_crc32_le(crc,item->key,16);
    crc = esp_rom_crc32_le(crc,item->data,8);
    entry_index &= 255U;
    if (expected_crc != crc)
        return false;

    unsigned int type = live_item->type;
    switch (type) {
    case NVS_ITEM_TYPE_U8: case NVS_ITEM_TYPE_U16:
    case NVS_ITEM_TYPE_U32: case NVS_ITEM_TYPE_U64:
    case NVS_ITEM_TYPE_I8: case NVS_ITEM_TYPE_I16:
    case NVS_ITEM_TYPE_I32: case NVS_ITEM_TYPE_I64:
        return live_item->span == 1;
    case NVS_ITEM_TYPE_BLOB_INDEX:
        if (live_item->span != 1)
            return false;
        if (live_item->chunk_index != 0xff)
            return false;
        return live_item->blob_index.data_size <= 0x7c060U;
    case NVS_ITEM_TYPE_BLOB_DATA:
        if (live_item->chunk_index == 0xff)
            return false;
        break;
    case NVS_ITEM_TYPE_STRING: case NVS_ITEM_TYPE_BLOB:
        break;
    default:
        return false;
    }
    unsigned int maximum_bytes = ((125U - entry_index) << 5) & 0xffffU;
    unsigned int length = live_item->variable.data_size;
    if (length > maximum_bytes)
        return false;
    unsigned int maximum_span = (126U - entry_index) & 255U;
    unsigned int span = live_item->span;
    if (span > maximum_span)
        return false;
    unsigned int calculated_span = ((((length + 31U) >> 5) & 255U) + 1U) & 255U;
    return calculated_span == span;
}
