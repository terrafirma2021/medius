/* Medius v3.4.7 device: flash clock divider and HAL context initialization. */
#include "../include/types.h"

/* Inline reconstruction utilities retain explicit native division, including
 * unguarded operands, and the clock-context MEMW. They add no firmware entries. */
static __inline__ __attribute__((always_inline)) int
flash_hal_quotient_signed(int numerator,int denominator)
{
    int result;
    __asm__ volatile ("quos %0,%1,%2" : "=a"(result) : "a"(numerator),"a"(denominator) : "memory");
    return result;
}
static __inline__ __attribute__((always_inline)) unsigned int
flash_hal_quotient_unsigned(unsigned int numerator,unsigned int denominator)
{
    unsigned int result;
    __asm__ volatile ("quou %0,%1,%2" : "=a"(result) : "a"(numerator),"a"(denominator) : "memory");
    return result;
}
static __inline__ __attribute__((always_inline)) void flash_hal_init_barrier(void)
{
    __asm__ volatile ("memw" ::: "memory");
}

/* Native entry: 0x420111f0. */
/* Original function-byte SHA-256:
 * 19ca7f6c01e25964bbf86a4b70516a325c3ad2b73d0a586f72661206f5965f70. */
/* Read signed source MHz then desired MHz. Source<desired logs error/aborts.
 * Otherwise compute signed QUOS of wrapping32(source+desired-1)/desired BEFORE
 * ROM div(source,desired); keep that first quotient as return bits. Save both
 * div result WORDs, warn at level2 if its remainder is nonzero, using its
 * quotient (not actual flash MHz) as the diagnostic integer. No positive/zero
 * frequency, addition-overflow or division-error guard; original native QUOS
 * behavior is retained explicitly. No configuration or hardware writes. */
unsigned int flash_get_clock_divider(const MemspiHostConfig *config)
{
    const volatile MemspiHostConfig *state = config;
    int source = state->clock_src_freq;
    int desired = state->freq_mhz;
    if (source < desired) {
        unsigned int timestamp = esp_log_timestamp();
        esp_log_write(1,"flash_hal","E (%lu) %s: Target frequency %dMHz higher than supported.\n",
            timestamp,"flash_hal",desired);
        abort();
    }
    int numerator = (int)((unsigned int)source + (unsigned int)desired - 1U);
    int divider = flash_hal_quotient_signed(numerator,desired);
    div_t parts = div(source,desired);
    volatile int saved_quotient = parts.quot;
    volatile int saved_remainder = parts.rem;
    (void)&saved_remainder;
    if (parts.rem != 0) {
        unsigned int timestamp = esp_log_timestamp();
        int reported = saved_quotient;
        esp_log_write(2,"flash_hal","W (%lu) %s: Flash clock frequency round down to %d\n",
            timestamp,"flash_hal",reported);
    }
    return (unsigned int)divider;
}

/* Native entry: 0x42011250. */
/* Original function-byte SHA-256:
 * 4f8caa2c5ef8062e7ebb13d728a7f2dfa8997cd0bf7ed2de1a6e0dc12ff76025. */
/* Validate signed CS upper limits:host0<2,host1<6,other<3; negative CS passes.
 * An invalid other host ID aborts only after its CS limit passes. Choose SPI1
 *60002000/SPI2 60024000/SPI3 60025000. Cache driver,CS/setup BYTE8/hold BYTE4,
 * I/O mode and frequency before zeroing all12 context WORDs, including padding.
 * Write setup/hold, reread tuning BYTE38, then publish preserved driver,SPI,CS,
 * initial mode/frequency. Tuned mode requires cached host0/CS0 or aborts; copy
 * extra-dummy low BYTE and clock WORD, with clock read BEFORE its MEMW/store.
 * Otherwise calculate extra dummy from wrapping32(input_delay+1)*80, clamping
 * products<-999 to0; retain unsigned then signed APB divisions and BYTE result.
 * IOMUX is not read in this S3 specialization. Reload host ID and get divider
 * again, truncate to8 bits, build MSPI/GPSPI clock fields, reload mode, MEMW/store
 * clock. Divider BYTE1 selects bit31; other values use native unmasked low part.
 * Fresh auto-suspend flag enables bits0/1 and copies TSUS/PES bytes; fresh octal
 * flag enables bit2. Mode17 sets slicer bit0 using initial mode on tuned path,
 * reloaded mode otherwise. Return0. No NULL, lower-bound CS, zero-divider,
 * alias, lock, entire-object validity or rollback guard; partial writes remain.
 * This prepares context; it does not program SPI registers or validate timing. */
int spi_flash_hal_init(FlashHostView *host,const MemspiHostConfig *config)
{
    const volatile MemspiHostConfig *cfg = config;
    int host_id = cfg->host_id;
    int cs_num = cfg->cs_num;
    volatile unsigned int *registers;
    if (host_id == 0) {
        if (cs_num >= 2)
            return 0x102;
        registers = (volatile unsigned int *)0x60002000U;
    } else if (host_id == 1) {
        if (cs_num >= 6)
            return 0x102;
        registers = (volatile unsigned int *)0x60024000U;
    } else {
        if (cs_num >= 3)
            return 0x102;
        if (host_id != 2)
            abort();
        registers = (volatile unsigned int *)0x60025000U;
    }
    volatile FlashHostView *state = host;
    const volatile FlashHostDriverView *driver = state->driver;
    unsigned char setup = cfg->timing.cs_setup;
    unsigned char hold = *(const volatile unsigned char *)&cfg->timing.cs_hold;
    unsigned int mode = cfg->default_io_mode;
    int frequency = cfg->freq_mhz;
    volatile unsigned int *words = (volatile unsigned int *)host;
    for (unsigned int index = 0; index < 12; ++index)
        words[index] = 0;
    state->cs_setup = setup;
    state->cs_hold = hold;
    unsigned char tuned = cfg->using_timing_tuning;
    state->driver = driver;
    state->spi = registers;
    state->cs_num = cs_num;
    state->base_io_mode = mode;
    state->freq_mhz = frequency;
    if (tuned != 0) {
        if (cs_num != 0 || host_id != 0)
            abort();
        unsigned int extra = cfg->timing.extra_dummy;
        state->extra_dummy = (unsigned char)extra;
        unsigned int clock = cfg->timing.clock_config;
        flash_hal_init_barrier();
        state->clock_conf = clock;
    } else {
        int input_delay = cfg->input_delay_ns;
        unsigned int divider = flash_get_clock_divider(config);
        int scaled = (int)(((unsigned int)input_delay + 1U) * 80U);
        unsigned char extra = 0;
        if (scaled >= -999) {
            unsigned int effective_clock = flash_hal_quotient_unsigned(80000000U,divider);
            int period = scaled / 1000;
            int apb_clocks = flash_hal_quotient_signed(80000000,(int)effective_clock);
            extra = (unsigned char)flash_hal_quotient_signed(period,apb_clocks);
        }
        state->extra_dummy = extra;
        unsigned int clock;
        if (cfg->host_id == 0) {
            unsigned int divider8 = flash_get_clock_divider(config) & 0xffU;
            if (divider8 == 1) {
                clock = 0x80000000U;
            } else {
                unsigned int low = divider8 - 1U;
                unsigned int half = (unsigned int)((int)low / 2);
                clock = (half << 8) | ((low & 0xffU) << 16) | low;
            }
        } else {
            unsigned int divider8 = flash_get_clock_divider(config) & 0xffU;
            if (divider8 == 1) {
                clock = 0x80000000U;
            } else {
                unsigned int low = divider8 - 1U;
                clock = ((((divider8 >> 1) - 1U) & 0xffU) << 6) |
                    ((low & 0xffU) << 12) | low;
            }
        }
        mode = cfg->default_io_mode;
        flash_hal_init_barrier();
        state->clock_conf = clock;
    }
    if (cfg->auto_sus_en != 0) {
        state->flags = state->flags | 3U;
        state->tsus_val = cfg->tsus_val;
        state->auto_waiti_pes = cfg->auto_waiti_pes;
    }
    if (cfg->octal_mode_en != 0)
        state->flags = state->flags | 4U;
    if (mode == 17)
        state->slicer_flags = state->slicer_flags | 1U;
    return 0;
}
