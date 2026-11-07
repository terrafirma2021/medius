/* Medius v3.4.7 device — quad PSRAM probing and controller setup. */
#include "../include/types.h"

/* Inline reconstruction utilities for native inlined ROM command setup.
 * These are source helpers, not additional firmware function entries. */
static __inline__ __attribute__((always_inline))
void psram_command_setup(RomSpiCommand *command,unsigned short opcode,
    unsigned int *address,unsigned int address_bits,unsigned int *transmit_data,unsigned int transmit_bits,
    unsigned int *receive_data,unsigned int receive_bits)
{
    command->opcode = opcode;
    command->opcode_bits = 8;
    command->address = address;
    command->address_bits = address_bits;
    command->transmit_data = transmit_data;
    command->transmit_bits = transmit_bits;
    command->receive_data = receive_data;
    command->receive_bits = receive_bits;
    command->dummy_bits = 0;
}

/* Native entry: 0x403857b4. */
/* Original function-byte SHA-256:
 * e57d843c6e83f5893880773a4c4357f8e5a99e66161f14e526d8476b78d86e04. */
/*
 * Read48 ID bits over SPI1, ROM mode5 and CS mask2, then test the APS3204 2T
 * extended-ID pattern. Clear both response WORDs before selecting mode; use
 * command0x9f/8 bits, zero24-bit address, no TX data,48 RX bits and no dummy.
 * ROM command calls supply no status; start uses is_write_erase=false. Read response
 * HIGH WORD first, then the HALFWORD at+2, forming ID bits47..16. Byte-swap
 * that32-bit chunk and return true when bits5..24 equal0x8a445. Do not infer
 * success from transport status or change the cached size here. No MEMW,
 * logging, retries, pointer arguments or inter-core lock. The caller uses true
 * only to reduce an otherwise8MiB size to4MiB.
 */
bool psram_has_aps3204_2t_id(void)
{
    volatile unsigned int response[2]={0,0};
    esp_rom_spi_set_op_mode(1,5);
    unsigned int address=0;
    RomSpiCommand command;
    psram_command_setup(&command,0x9f,&address,24,NULL,0,
                              (unsigned int *)response,48);
    esp_rom_spi_cmd_config(1,&command);
    esp_rom_spi_cmd_start(1,(unsigned char *)response,6,2,false);
    unsigned int high=response[1];
    unsigned int low=*(const volatile unsigned short *)((unsigned int)response+2U);
    unsigned int id_bits_47_to_16=(high<<16)|low;
    unsigned int id_big_endian=__builtin_bswap32(id_bits_47_to_16);
    return ((id_big_endian>>5)&0xfffffU)==0x8a445U;
}

/* Native entry: 0x40385834. */
/* Original function-byte SHA-256:
 * 2a6358021caf4ef89ad1c4afbbef6ebc0230a12184b92806397fb0617b95e06a. */
/*
 * Enable this image's quad PSRAM. Select CS GPIO26, use eFuse SPI/WP routing
 * when present (default WP28), and reserve the64-bit GPIO mask. The raw WP
 * result selects a mask bit modulo64; only its low BYTE is passed to ROM pin
 * routing. Configure SPI0 CS timing and enter low-speed mode before SPI1 work.
 * Exit quad mode with0xf5, then write/read0x5a6b7c8d at address0. Mismatch logs
 * if enabled and returns0x106 with earlier pin/MMIO/clock effects retained.
 * No original RAM content is restored and no high-speed cleanup runs on error.
 *
 * Read24 ID bits with0x9f. If manufacturer BYTE[1]!=0x5d, repeat once; a second
 * mismatch warns at level>=2 but still derives size. BYTE[2]==0x26 selects8MiB;
 * otherwise density bits21..23 map0/1/2 to2/4/8MiB and all others to0. For8MiB,
 * the separate48-bit APS3204 2T probe may reduce size to4MiB. A zero derived size
 * does not cause an error return here. Cache the size before subsequent work.
 *
 * Send reset-enable0x66, reset0x99 and quad-enable0x35 in mode5. The linked
 * timing-tuning hook returns immediately. Configure SPI0 quad cache access,
 * write/read opcodes0x38/0xeb with8 command bits, dummy/address/control fields,
 * and disable CS0 while enabling CS1 (MISC bit0 set, bit1 clear).
 * Every register RMW and staged stack WORD access retains its MEMW. Reuse the
 * original command/address/readback slots for those staged control words.
 * Finish with mspi_timing_enter_high_speed_mode(1) and return0. ROM command
 * config/start calls supply no status; the GPIO reservation result is ignored. Every command
 * uses CS mask2 and false write/erase, including the loopback write. No lock,
 * transfer timeout, memory test, allocation or initialized-BYTE update here.
 */
int esp_psram_impl_enable(void)
{
    memw(); unsigned int register_value=PSRAM_CS_IOMUX;
    memw(); PSRAM_CS_IOMUX=register_value&0xffff8fffU;
    PSRAM_CS_GPIO=26;
    unsigned int spi_configuration=ets_efuse_get_spiconfig();
    unsigned char write_protect_pin=28;
    unsigned long long reserved_pin_mask=0x14000000ULL;
    if (spi_configuration!=0) {
        unsigned int raw_write_protect_pin=ets_efuse_get_wp_pad();
        reserved_pin_mask=(1ULL<<(raw_write_protect_pin&63U))|(1ULL<<26);
        write_protect_pin=(unsigned char)raw_write_protect_pin;
    }
    esp_rom_spiflash_select_qio_pins(write_protect_pin,spi_configuration);
    (void)esp_gpio_reserve(reserved_pin_mask);
    memw(); register_value=MSPI0->smem_ac;
    memw(); MSPI0->smem_ac=register_value|2U;
    memw(); register_value=MSPI0->smem_ac;
    memw(); MSPI0->smem_ac=register_value&0xfffff07fU;
    memw(); register_value=MSPI0->smem_ac;
    memw(); MSPI0->smem_ac=register_value|1U;
    memw(); register_value=MSPI0->smem_ac;
    memw(); MSPI0->smem_ac=register_value&0xffffff83U;
    mspi_timing_enter_low_speed_mode(1);

    volatile unsigned int chip_id=0;
    esp_rom_spi_set_op_mode(1,0);
    memw(); register_value=MSPI1->ctrl;
    memw(); MSPI1->ctrl=register_value|0x100U;
    PsramCommandStorage storage;
    volatile unsigned int address_scratch=0;
    psram_command_setup(&storage.command,0xf5,(unsigned int *)&address_scratch,
                              0,NULL,0,NULL,0);
    esp_rom_spi_cmd_config(1,&storage.command);
    esp_rom_spi_cmd_start(1,NULL,0,2,false);

    volatile unsigned int readback=0;
    volatile unsigned int reference=0x5a6b7c8dU;
    esp_rom_spi_set_op_mode(1,5);
    address_scratch=0;
    psram_command_setup(&storage.command,0x02,(unsigned int *)&address_scratch,
                              24,(unsigned int *)&reference,32,NULL,0);
    esp_rom_spi_cmd_config(1,&storage.command);
    esp_rom_spi_cmd_start(1,NULL,0,2,false);
    esp_rom_spi_set_op_mode(1,5);
    address_scratch=0;
    psram_command_setup(&storage.command,0x03,(unsigned int *)&address_scratch,
                              24,NULL,0,(unsigned int *)&readback,32);
    esp_rom_spi_cmd_config(1,&storage.command);
    esp_rom_spi_cmd_start(1,(unsigned char *)&readback,4,2,false);
    unsigned int received_pattern=readback;
    unsigned int expected_pattern=reference;
    if (received_pattern!=expected_pattern) {
        if (PSRAM_LOG_LEVEL!=0) {
            unsigned int timestamp=esp_log_timestamp();
            ets_printf("E (%lu) %s: PSRAM chip is not connected, or wrong PSRAM line mode\n",
                       timestamp,QUAD_PSRAM_LOG_TAG);
        }
        return 0x106;
    }
    esp_rom_spi_set_op_mode(1,5);
    address_scratch=0;
    psram_command_setup(&storage.command,0x9f,(unsigned int *)&address_scratch,
                              24,NULL,0,(unsigned int *)&chip_id,24);
    esp_rom_spi_cmd_config(1,&storage.command);
    esp_rom_spi_cmd_start(1,(unsigned char *)&chip_id,3,2,false);
    unsigned int chip_id_snapshot=chip_id;
    if (((chip_id_snapshot>>8)&0xffU)!=0x5dU) {
        esp_rom_spi_set_op_mode(1,5);
        address_scratch=0;
        psram_command_setup(&storage.command,0x9f,(unsigned int *)&address_scratch,
                                  24,NULL,0,(unsigned int *)&chip_id,24);
        esp_rom_spi_cmd_config(1,&storage.command);
        esp_rom_spi_cmd_start(1,(unsigned char *)&chip_id,3,2,false);
        chip_id_snapshot=chip_id;
        if (((chip_id_snapshot>>8)&0xffU)!=0x5dU && PSRAM_LOG_LEVEL>=2U) {
            unsigned int timestamp=esp_log_timestamp();
            ets_printf("W (%lu) %s: PSRAM ID read error: 0x%08x, fallback to use default driver pattern\n",
                       timestamp,QUAD_PSRAM_LOG_TAG,chip_id);
            chip_id_snapshot=chip_id;
        }
    }
    unsigned int physical_size;
    if (((chip_id_snapshot>>16)&0xffU)==0x26U) physical_size=0x800000U;
    else {
        unsigned int density_code=(chip_id_snapshot>>21)&7U;
        physical_size=density_code==0?0x200000U:density_code==1?0x400000U:density_code==2?0x800000U:0U;
    }
    PSRAM_PHYSICAL_SIZE=physical_size;
    if (physical_size==0x800000U && psram_has_aps3204_2t_id())
        PSRAM_PHYSICAL_SIZE=0x400000U;

    esp_rom_spi_set_op_mode(1,5);
    address_scratch=0;
    psram_command_setup(&storage.command,0x66,(unsigned int *)&address_scratch,0,NULL,0,NULL,0);
    esp_rom_spi_cmd_config(1,&storage.command);
    esp_rom_spi_cmd_start(1,NULL,0,2,false);
    esp_rom_spi_set_op_mode(1,5);
    address_scratch=0;
    psram_command_setup(&storage.command,0x99,(unsigned int *)&address_scratch,0,NULL,0,NULL,0);
    esp_rom_spi_cmd_config(1,&storage.command);
    esp_rom_spi_cmd_start(1,NULL,0,2,false);
    esp_rom_spi_set_op_mode(1,5);
    address_scratch=0;
    psram_command_setup(&storage.command,0x35,(unsigned int *)&address_scratch,0,NULL,0,NULL,0);
    esp_rom_spi_cmd_config(1,&storage.command);
    esp_rom_spi_cmd_start(1,NULL,0,2,false);
    mspi_timing_psram_tuning();

    volatile unsigned int *staged_control=&storage.words[0];
    memw(); register_value=MSPI0->cache_sctrl;
    memw(); *staged_control=register_value;
    memw(); register_value=*staged_control;
    memw(); *staged_control=register_value&0xfffffff9U;
    memw(); register_value=*staged_control;
    memw(); *staged_control=register_value|4U;
    memw(); register_value=*staged_control;
    memw(); MSPI0->cache_sctrl=register_value;
    memw(); register_value=MSPI0->cache_sctrl;
    memw(); MSPI0->cache_sctrl=register_value|0x100000U;
    memw(); register_value=MSPI0->sram_dwr_cmd;
    memw(); MSPI0->sram_dwr_cmd=(register_value&0x0fffffffU)|0x70000000U;
    memw(); register_value=MSPI0->sram_dwr_cmd;
    memw(); readback=register_value;
    memw(); register_value=readback;
    memw(); readback=(register_value&0xffff0000U)|0x38U;
    memw(); register_value=readback;
    memw(); MSPI0->sram_dwr_cmd=register_value;
    memw(); register_value=MSPI0->cache_sctrl;
    memw(); MSPI0->cache_sctrl=register_value|0x20U;
    memw(); register_value=MSPI0->sram_drd_cmd;
    memw(); MSPI0->sram_drd_cmd=(register_value&0x0fffffffU)|0x70000000U;
    memw(); register_value=MSPI0->sram_drd_cmd;
    memw(); address_scratch=register_value;
    memw(); register_value=address_scratch;
    memw(); address_scratch=(register_value&0xffff0000U)|0xebU;
    memw(); register_value=address_scratch;
    memw(); MSPI0->sram_drd_cmd=register_value;
    memw(); register_value=MSPI0->cache_sctrl;
    memw(); MSPI0->cache_sctrl=(register_value&0xfff03fffU)|0x5c000U;
    memw(); register_value=MSPI0->cache_sctrl;
    memw(); MSPI0->cache_sctrl=register_value|0x10U;
    memw(); register_value=MSPI0->cache_sctrl;
    memw(); MSPI0->cache_sctrl=(register_value&0xfffff03fU)|0x140U;
    memw(); register_value=MSPI0->misc;
    memw(); MSPI0->misc=register_value|1U;
    memw(); register_value=MSPI0->misc;
    memw(); MSPI0->misc=register_value&0xfffffffdU;
    mspi_timing_enter_high_speed_mode(1);
    return 0;
}
