/* Medius v3.4.7 host — Macronix octal STR startup and ROM cache configuration.
 */

#include "../include/types.h"

/* Native entry: 0x403810e4. */
/* Original function-byte SHA-256:
 * d822cee73164b27fe854fba981d43bc489610ac2dc18511606df3f27d479478c. */
/* Set SPI0 read_mode through ROM, then separately clear USER.MOSI and enable
 * USER.ADDR/MISO, reloading USER between writes. A null cache ends after those
 * effects. Otherwise use the borrowed six-byte descriptor: set address width
 * through ROM, enable/disable dummy phase, and when enabled replace USER1's
 * low6 bits with (dummy_bits-1+ROM dummy_len_plus[0])&63. A zero dummy count
 * disables the phase without modifying USER1. The ROM legacy pointer is read
 * after USER1; the descriptor's dummy BYTE is captured before USER is read.
 *
 * Replace USER2 command low16, then reload USER2 and replace its high4 command
 * length bits with (command_bits-1) modulo16. Zero command_bits therefore
 * encodes15; no descriptor range validation occurs. Set DDR.VAR_DUMMY bit1
 * from variable_dummy bit0, leaving all other bits unchanged. Keep every native
 * MEMW and separate volatile read/write, including HALF/BYTE descriptor load
 * order. No SPI1 change, allocation, lock, timeout or status return is added. */
void esp_rom_opiflash_cache_mode_config(int read_mode,const volatile OpiFlashCacheRead *cache)
{
    esp_rom_spi_set_op_mode(0,read_mode);
    MspiRegisters *spi=MSPI0;
    memw();
    unsigned int user=spi->user;
    memw();
    spi->user=user&0xf7ffffffU; /* MOSI off */
    memw();
    user=spi->user;
    memw();
    spi->user=user|0x50000000U; /* ADDR and MISO on */
    if (!cache) return;

    unsigned char address_bits=cache->address_bits;
    esp_rom_spi_set_address_bit_len(0,address_bits);
    unsigned int dummy_bits=cache->dummy_bits;
    memw();
    user=spi->user;
    if (dummy_bits==0U) {
        memw();
        spi->user=user&0xdfffffffU;
    } else {
        memw();
        spi->user=user|0x20000000U;
        memw();
        unsigned int user1=spi->user1;
        const volatile RomFlashLegacy *legacy=ROM_FLASH_LEGACY;
        unsigned int correction=legacy->dummy_len_plus[0];
        unsigned int cycles=(dummy_bits-1U+correction)&63U;
        memw();
        spi->user1=(user1&0xffffffc0U)|cycles;
    }
    unsigned int command=cache->command;
    memw();
    unsigned int user2=spi->user2;
    memw();
    spi->user2=(user2&0xffff0000U)|command;
    memw();
    user2=spi->user2;
    unsigned int command_bits=cache->command_bits;
    memw();
    spi->user2=(user2&0x0fffffffU)|((command_bits-1U)<<28);
    unsigned int variable_dummy=cache->variable_dummy;
    memw();
    unsigned int ddr=spi->ddr;
    memw();
    spi->ddr=(ddr&0xfffffffdU)|((variable_dummy&1U)<<1);
}

/* Native entry: 0x4038d344. */
/* Original function-byte SHA-256:
 * 106cba49d1feffa393643f3a27980a50217661409f3ab4743dc94ce4dfbd0c00. */
/* Accept only chip_id>>16 ==0xc2 and memory-type nibble bits12..15 ==8.
 * On success write one BYTE0xc2 to vendor and return0; vendor is not null-
 * checked. Every rejected ID returns0x105 without a vendor write. Non-MXIC
 * rejection is silent. MXIC with another type emits the native early error
 * only when the diagnostic gate WORD is nonzero. No device I/O is performed. */
int mxic_probe_octal_flash(unsigned int chip_id,unsigned char *vendor)
{
    if ((chip_id>>16)!=0xc2U) return 0x105;
    if (((chip_id>>12)&15U)==8U) {
        *(volatile unsigned char *)vendor=0xc2;
        return 0;
    }
    if (SYSTEM_EARLY_LOG_LEVEL!=0U) {
        unsigned int timestamp=esp_log_timestamp();
        ets_printf("E (%lu) %s: Detected MXIC Flash, but memory type is not Octal\n",
            timestamp,"Octal Flash");
    }
    return 0x105;
}

/* Native entry: 0x4038d388. */
/* Original function-byte SHA-256:
 * 91da9326d5f8cf76585f4f0629d48dfa80a4c442b01f721061de19e992138e21. */
/* Ignore chip ID and disable both write/read DTR byte swaps through ROM on
 * SPI0, then SPI1. The linked STR path never requests a swap. Returns void;
 * no local register poll, synchronization or error handling occurs here. */
void mxic_disable_dtr_byte_swaps(unsigned int unused_chip_id)
{
    (void)unused_chip_id;
    esp_rom_spi_set_dtr_swap_mode(0,false,false);
    esp_rom_spi_set_dtr_swap_mode(1,false,false);
}

/* Native entry: 0x4038d3a8. */
/* Original function-byte SHA-256:
 * fbf577ea9f47e671b67967faf0c09adaa60281bb818fc573077f6fd6b889e0bc. */
/* Install the embedded92-byte MXIC STR command set into ROM, then wait idle.
 * Read one status BYTE with0x05 and one configuration BYTE with0x15 on SPI1
 * in FASTRD mode4. Set configuration low3 driver-strength bits, preserve all
 * other bits/status, request write-enable and send combined16 bits with0x01.
 * All four generic command calls use eight command bits, CS mask1 and false
 * write/erase classification, including both writes; retain that native flag.
 *
 * Wait again, OR clock-pad drive bits0x0c into SPI0.DATE and CS0/GPIO29 drive
 * bits0xc00 into IO_MUX, with separate MEMW read/write pairs. Change only the
 * low BYTE of the shared status/configuration HALF to1, request write-enable,
 * then send0x72/address0 with32 address bits and eight data bits to enter STR.
 * Configure SPI0 cache using the live ROM command-set pointer's +0x54 view
 * and read_mode, clear both DTR swap flags on SPI0/SPI1, finally wait OPI idle.
 *
 * ROM chip/command pointers are reloaded where the native code reloads them.
 * Wait/write-enable results are ignored. No readback, rollback, independent
 * timeout, cache exclusion or lock is supplied; callers arrange safe startup.
 * Embedded cache descriptor: address32, dummy20, command0x13ec/16 bits,
 * variable-dummy1. ROM wait routines may block; no runtime timing is asserted. */
void mxic_initialize_str_flash(int read_mode)
{
    esp_rom_opiflash_legacy_driver_init(MXIC_STR_COMMANDS);
    esp_rom_spiflash_wait_idle(&ROM_FLASH_LEGACY->chip);
    OpiFlashSetupRegisters registers;
    registers.status_configuration=0;
    registers.status=0;
    registers.configuration=0;
    esp_rom_opiflash_exec_cmd(1,4,0x05,8,0,0,0,0,0,&registers.status,8,1,false);
    esp_rom_opiflash_exec_cmd(1,4,0x15,8,0,0,0,0,0,&registers.configuration,8,1,false);
    unsigned int configuration=registers.configuration|7U;
    unsigned int status=registers.status;
    RomFlashLegacy *legacy=ROM_FLASH_LEGACY;
    registers.status_configuration=(unsigned short)(status|(configuration<<8));
    esp_rom_spiflash_write_enable(&legacy->chip);
    esp_rom_opiflash_exec_cmd(1,4,0x01,8,0,0,0,
        (unsigned char *)&registers.status_configuration,16,0,0,1,false);
    esp_rom_spiflash_wait_idle(&ROM_FLASH_LEGACY->chip);
    memw();
    unsigned int clock_drive=MSPI0->date;
    memw();
    MSPI0->date=clock_drive|0x0cU;
    volatile unsigned int *cs0_iomux=(volatile unsigned int *)0x60009078U;
    memw();
    unsigned int cs_drive=*cs0_iomux;
    memw();
    *cs0_iomux=cs_drive|0x0c00U;
    legacy=ROM_FLASH_LEGACY;
    registers.mode=1;
    esp_rom_spiflash_write_enable(&legacy->chip);
    esp_rom_opiflash_exec_cmd(1,4,0x72,8,0,32,0,
        (unsigned char *)&registers.status_configuration,8,0,0,1,false);
    const volatile OpiFlashCommandSet *commands=ROM_OPI_FLASH_COMMANDS;
    esp_rom_opiflash_cache_mode_config(read_mode,&commands->cache_read);
    esp_rom_spi_set_dtr_swap_mode(0,false,false);
    esp_rom_spi_set_dtr_swap_mode(1,false,false);
    esp_rom_opiflash_wait_idle();
}

/* Native entry: 0x4038d4e8. */
/* Original function-byte SHA-256:
 * e1347da622d2a4dbbb77cca263d6bc34c50e25c6accc95a163ca8384c9325d1b. */
/* Probe the null-terminated registry, passing chip_id and one zero-initialized
 * vendor BYTE to each probe until it returns0. This image's registry contains
 * the MXIC callbacks and a null sentinel. No registry/callback bounds check or
 * local lock is supplied. On success reload the selected slot and capture its
 * initializer before recording chip_id; initialize with STR mode6, install the
 * embedded52-byte OPI legacy table in ROM and publish the selected slot address.
 * Return0. The vendor BYTE is not otherwise consumed.
 *
 * If no probe succeeds, read the diagnostic gate, publish the sentinel slot,
 * optionally emit the native early error, then abort. No recoverable error
 * code, fallback mode or cleanup follows. The published value is a pointer
 * to a registry SLOT, rather than directly to its callback table. */
int esp_opiflash_init(unsigned int chip_id)
{
    OpiFlashChipSlot slot=OPI_FLASH_CHIP_REGISTRY;
    const volatile OpiFlashChipFunctions *functions=*slot;
    unsigned char vendor=0;
    while (functions) {
        int result=functions->probe(chip_id,&vendor);
        if (result==0) {
            functions=*slot;
            void (*initialize)(int)=functions->initialize;
            OPI_FLASH_CHIP_ID=chip_id;
            initialize(6);
            ROM_FLASH_LEGACY_FUNCTIONS=OPI_FLASH_LEGACY_FUNCTIONS;
            OPI_FLASH_SELECTED_SLOT=slot;
            return 0;
        }
        functions=slot[1];
        ++slot;
    }
    unsigned int diagnostic=SYSTEM_EARLY_LOG_LEVEL;
    OPI_FLASH_SELECTED_SLOT=slot;
    if (diagnostic!=0U) {
        unsigned int timestamp=esp_log_timestamp();
        ets_printf("E (%lu) %s: No detected Flash chip, please check the menuconfig to see if the chip is supported\n",
            timestamp,"Octal Flash");
    }
    abort();
}
