/* Medius v3.4.7 device: recovered ESP32-S3 LED PWM HAL. */

#include "../include/types.h"

/* reconstruction utilities: read speed mode before device, then retain native
 * modulo-32 address arithmetic. Mode/channel IDs are unchecked; ESP32-S3 has
 * one low-speed group, but this routine does not invent bounds guards. */
static __inline__ __attribute__((always_inline)) LedcChannelRegisters *
ledc_hal_channel(const LedcHal *hal,int channel_id)
{
    unsigned int mode = (unsigned int)hal->speed_mode;
    unsigned int base = (unsigned int)(uintptr_t)hal->device;
    unsigned int address = base + (unsigned int)channel_id * 0x14U + mode * 0xa0U;
    return (LedcChannelRegisters *)(uintptr_t)address;
}

/* Native entry: 0x403895c4. */
/*
 * Medius v3.4.7 — device application; 0x403895c4.
 * Instruction-checked recovered C.
 * Original function-byte SHA-256:
 * 50a80ebb9fd79222f3a6668683446c75f2353c2576742cd82225abf467535422.
 */

/* Request duty/fade start by setting CONF1 bit 31 through one fresh
 * MEMW/read/MEMW/write. Preserve the remaining word. No parameter validation,
 * clock/output enable, update-latch request, completion wait, lock or status. */
void ledc_hal_set_duty_start(LedcHal *hal,int channel_id)
{
    LedcChannelRegisters *channel = ledc_hal_channel(hal,channel_id);
    memw();
    unsigned int configuration = channel->configuration1;
    memw();
    channel->configuration1 = configuration | 0x80000000U;
}

/* Native entry: 0x403895ec. */
/*
 * Medius v3.4.7 — device application; 0x403895ec.
 * Instruction-checked recovered C.
 * Original function-byte SHA-256:
 * 68ca2d5cfe7d8f8cd396010e381fdbb24f68be9186983f19beb8edb947492d2a.
 */

/* Set integer duty using only duty & 0x7fff, shifted left by 4 into the
 * 19-bit DUTY field. Clear its four fractional bits, preserve register bits
 * 19..31, and keep the native fresh MEMW/RMW pair. No range error, timer
 * resolution check, start/update request, lock or returned status. */
void ledc_hal_set_duty_int_part(LedcHal *hal,int channel_id,unsigned int duty)
{
    LedcChannelRegisters *channel = ledc_hal_channel(hal,channel_id);
    memw();
    unsigned int previous = channel->duty;
    memw();
    channel->duty = (previous & ~0x7ffffU) | ((duty & 0x7fffU) << 4);
}

/* Native entry: 0x40389624. */
/*
 * Medius v3.4.7 — device application; 0x40389624.
 * Instruction-checked recovered C.
 * Original function-byte SHA-256:
 * 896eaaf9ff993a326a5296c92bf68613a4a97f228b23618d2cda9fc9509844ef.
 */

/* Only range 0 is supported: other values abort BEFORE reading the HAL or
 * hardware. Read CONF1 once and copy it into volatile stack scratch. Edit that
 * copy in order: direction bit 30, step bits 20..29, cycle bits 10..19, scale
 * bits 0..9. Each field uses only its low 1/10/10/10 bits. Preserve START bit
 * 31 from the ORIGINAL snapshot, then write the final complete word once.
 *
 * Retain all twelve native MEMW sites, including the scratch stores/loads.
 * The seventh argument, step, arrives on the caller stack and is read after
 * the direction scratch update; the explicit volatile access keeps that load
 * at this point. Four scratch edits are not four hardware-register writes.
 * No channel/mode bounds check, timer configuration, start/latch request, lock
 * or completion/status. Concurrent hardware updates after the snapshot are
 * not merged into the final write. C scratch placement is compiler-selected. */
void ledc_hal_set_fade_param(const LedcHal *hal,int channel_id,unsigned int range,
    unsigned int direction,unsigned int cycle,unsigned int scale,unsigned int step)
{
    if (range != 0)
        abort();
    LedcChannelRegisters *channel = ledc_hal_channel(hal,channel_id);
    memw();
    unsigned int original = channel->configuration1;
    memw();
    volatile unsigned int scratch = original;
    memw();
    unsigned int previous = scratch;
    memw();
    scratch = (previous & ~0x40000000U) | ((direction & 1U) << 30);
    unsigned int native_step = *(const volatile unsigned int *)&step;
    memw();
    previous = scratch;
    memw();
    scratch = (previous & ~0x3ff00000U) | ((native_step & 0x3ffU) << 20);
    memw();
    previous = scratch;
    memw();
    scratch = (previous & ~0xffc00U) | ((cycle & 0x3ffU) << 10);
    memw();
    previous = scratch;
    memw();
    scratch = (previous & ~0x3ffU) | (scale & 0x3ffU);
    memw();
    unsigned int result = scratch;
    memw();
    channel->configuration1 = result;
}

/* Native entry: 0x403896bc. */
/*
 * Medius v3.4.7 — device application; 0x403896bc.
 * Instruction-checked recovered C.
 * Original function-byte SHA-256:
 * ba3a3e10e61433a46e648fc5795017407bc7391f42335f13b008a06dfe7f14ca.
 */

/* Request the selected channel's low-speed parameter latch through CONF0
 * bit 4. One fresh MEMW/RMW preserves unrelated bits; the speed-mode field
 * still participates in unchecked native address calculation. No mode switch,
 * duty start, clock setup, lock, acknowledgement or returned status. */
void ledc_hal_ls_channel_update(LedcHal *hal,int channel_id)
{
    LedcChannelRegisters *channel = ledc_hal_channel(hal,channel_id);
    memw();
    unsigned int configuration = channel->configuration0;
    memw();
    channel->configuration0 = configuration | 0x10U;
}

/* Native entry: 0x403896e4. */
/*
 * Medius v3.4.7 — device application; 0x403896e4.
 * Instruction-checked recovered C.
 * Original function-byte SHA-256:
 * 88c3593866e7ef234f819602fb33dc425504daed1f18a813b72a8acc38b2b7e5.
 */

/* Replace HPOINT bits 0..13 with hpoint & 0x3fff through one fresh
 * MEMW/RMW, preserving bits 14..31. Values are truncated without an error.
 * No timer-resolution check, update/start, lock, wait or returned status. */
void ledc_hal_set_hpoint(LedcHal *hal,int channel_id,unsigned int hpoint)
{
    LedcChannelRegisters *channel = ledc_hal_channel(hal,channel_id);
    memw();
    unsigned int previous = channel->hpoint;
    memw();
    channel->hpoint = (previous & ~0x3fffU) | (hpoint & 0x3fffU);
}
