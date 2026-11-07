/* Medius v3.4.7 host: recovered sleep submode accounting. */

#include "../include/types.h"

/* Native entry: 0x42006ddc. */
/*
 * Medius v3.4.7 — host application; 0x42006ddc.
 * Instruction-checked recovered C.
 * Original function-byte SHA-256:
 * 5b6d239fae917b403026a402828a9e5629fa5f5f36dfd60553bf44fb007d2d73.
 */

/* Outlined sleep-submode adjustment; caller validates unsigned mode<7. Probe
 * ISR context, enter sleep-config mux indefinitely, read signed32 RTC-retained
 * count once, then add1 for any nonzero FULL-WORD activate or subtract1 for0.
 * Native arithmetic wraps32; publish that result before testing its sign.
 * A negative result (including INT_MAX+1 wrap) optionally logs at early level
 * >=2 WHILE LOCKED, then clamps count to0. Probe ISR again and unlock. Return0
 * even on underflow. No index bounds check, saturation at INT_MAX, rollback,
 * clock switch or ownership of the returned counter storage is provided. */
int sleep_submode_adjust(unsigned int mode,unsigned int activate)
{
    (void)xPortInIsrContext();
    (void)xPortEnterCriticalTimeout(SLEEP_CONFIGURATION_LOCK,-1);
    volatile int *count = &SLEEP_SUBMODE_COUNTS[mode];
    unsigned int previous = (unsigned int)*count;
    unsigned int changed = previous + (activate ? 1U : 0xffffffffU);
    *count = (int)changed;
    if ((int)changed < 0) {
        if (SYSTEM_EARLY_LOG_LEVEL >= 2U) {
            unsigned int timestamp = esp_log_timestamp();
            const char *name = SLEEP_SUBMODE_NAMES[mode];
            ets_printf("W (%lu) %s: %s disabled multiple times!! (If this log appears only once after OTA upgrade, it can be ignored.)\n",
                       timestamp,"sleep",name);
        }
        *count = 0;
    }
    (void)xPortInIsrContext();
    vPortExitCritical(SLEEP_CONFIGURATION_LOCK);
    return 0;
}

/* Native entry: 0x42006e44. */
/*
 * Medius v3.4.7 — host application; 0x42006e44.
 * Instruction-checked recovered C.
 * Original function-byte SHA-256:
 * d7e5016c2ceb373e24cdd09c43aac288310639314e57ff07a955286ea9e51d5b.
 */

/* Caller validates mode<7. Probe ISR, take sleep-config mux indefinitely, store
 * count0 in RTC-retained array, probe ISR again, then unlock. All references
 * are discarded, not decremented. Lock/probe results ignored; no clock action,
 * index validation, error output or restoration of displaced references. */
void sleep_submode_clear(unsigned int mode)
{
    (void)xPortInIsrContext();
    (void)xPortEnterCriticalTimeout(SLEEP_CONFIGURATION_LOCK,-1);
    *(volatile int *)&SLEEP_SUBMODE_COUNTS[mode] = 0;
    (void)xPortInIsrContext();
    vPortExitCritical(SLEEP_CONFIGURATION_LOCK);
}

/* Native entry: 0x42006e78. */
/*
 * Medius v3.4.7 — host application; 0x42006e78.
 * Instruction-checked recovered C.
 * Original function-byte SHA-256:
 * 531f3e057d11736bb36bbb0048b64c3441fda7423eef7d055645386d99af1882.
 */

/* Accept unsigned mode0..6; reject other values with0x102 and no lock/access.
 * Forward only LOW BYTE of activate to the outlined full-word truthiness
 * helper; ignore helper result and return0 after accepted update/clamp. */
int esp_sleep_sub_mode_config(unsigned int mode,unsigned char activate)
{
    if (mode >= SLEEP_SUBMODE_COUNT)
        return 0x102;
    (void)sleep_submode_adjust(mode,activate);
    return 0;
}

/* Native entry: 0x42006e90. */
/*
 * Medius v3.4.7 — host application; 0x42006e90.
 * Instruction-checked recovered C.
 * Original function-byte SHA-256:
 * a047dc1bd77c6d9096e1eb6645397d12a6202645d404a690a9f86873e07c6f98.
 */

/* Reject unsigned mode>=7 with0x102 and no lock/access; otherwise clear ALL
 * references for that exact mode under sleep-config mux and return0. The raw
 * decompile lost this helper's mode argument. No hardware clock switch. */
int esp_sleep_sub_mode_force_disable(unsigned int mode)
{
    if (mode >= SLEEP_SUBMODE_COUNT)
        return 0x102;
    sleep_submode_clear(mode);
    return 0;
}

/* Native entry: 0x42006ea4. */
/*
 * Medius v3.4.7 — host application; 0x42006ea4.
 * Instruction-checked recovered C.
 * Original function-byte SHA-256:
 * 070ab787416155e52e87218b21c803c3fc4b330da05c7bea0f2e4d2e7e4b9708.
 */

/* Always return borrowed mutable pointer to seven signed32 RTC-retained mode
 * counters. With NULL stream, do nothing else. Otherwise walk modes0..6 without
 * locking: read each count ONCE, then its name pointer; print name, ENABLED
 * for nonzero or DISABLED for0, and THAT SAME count as signed long32. Ignore
 * every fprintf result and continue after I/O failure. The original decompile
 * omitted the final count variadic argument recovered from A14. No snapshot
 * consistency across rows, count modification or ownership transfer. */
int *esp_sleep_sub_mode_dump_config(NewlibFile *stream)
{
    if (stream) {
        for (unsigned int mode = 0; mode < SLEEP_SUBMODE_COUNT; ++mode) {
            int count = *(volatile int *)&SLEEP_SUBMODE_COUNTS[mode];
            const char *name = SLEEP_SUBMODE_NAMES[mode];
            (void)newlib_fprintf(stream,"%s : %s (cnt = %ld)\n",name,
                                      count ? "ENABLED" : "DISABLED",(long)count);
        }
    }
    return SLEEP_SUBMODE_COUNTS;
}

/* Native entry: 0x403805f4. */
/*
 * Medius v3.4.7 — host application; 0x403805f4.
 * Instruction-checked recovered C.
 * Original function-byte SHA-256:
 * 750f7288c277ab5faa1dc7ad41feb4dcbd820bce134430c65dd7be8b88dd9694.
 */

/* Apply the packed RTC sleep force-power-up configuration carried in A2.
 * The SDK's nine one-bit fields occupy this 32-bit word; named masks below
 * expose that native ABI without relying on C bitfield allocation. CPU/I2S
 * bits 2/3 and bits above 8 are ignored by this firmware implementation.
 *
 * Update digital sleep memory, then RTC fast/slow memories, front-end DC/PBUS/
 * AGC, baseband FFT/DC estimator, receiver rotation/Viterbi/demapper, front-end
 * IQ estimator, and transmit interpolator in that order. SRAM bit 7 controls
 * all eleven SRAM power-up bits; ROM bit 8 controls all three ROM power-up bits.
 * Every field update retains its own fresh MEMW/read/MEMW/write, including
 * separate fields in the same register and the final SRAM/ROM pair.
 * Clearing a force-power-up bit releases that override; it does not itself
 * request or verify power-down. No lock, delay, sleep entry, acknowledgement,
 * rollback, configuration validation or return status is supplied. */
void rtc_sleep_pu(unsigned int configuration)
{
    unsigned int digital = (configuration & SLEEP_FORCE_DIGITAL) != 0;
    memw();
    unsigned int power = SLEEP_POWER_REGISTERS->digital_memory;
    memw();
    SLEEP_POWER_REGISTERS->digital_memory = (power & ~0x10U) | (digital << 4);
    unsigned int rtc = (configuration & SLEEP_FORCE_RTC) != 0;
    memw();
    power = SLEEP_POWER_REGISTERS->rtc_memory;
    memw();
    SLEEP_POWER_REGISTERS->rtc_memory = (power & ~0x100U) | (rtc << 8);
    memw();
    power = SLEEP_POWER_REGISTERS->rtc_memory;
    memw();
    SLEEP_POWER_REGISTERS->rtc_memory = (power & ~0x800U) | (rtc << 11);

    unsigned int frontend = (configuration & SLEEP_FORCE_FRONTEND) != 0;
    memw();
    power = SLEEP_SYSCON_REGISTERS->frontend_memory;
    memw();
    SLEEP_SYSCON_REGISTERS->frontend_memory = (power & ~0x10U) | (frontend << 4);
    memw();
    power = SLEEP_SYSCON_REGISTERS->frontend_memory;
    memw();
    SLEEP_SYSCON_REGISTERS->frontend_memory = (power & ~4U) | (frontend << 2);
    memw();
    power = SLEEP_SYSCON_REGISTERS->frontend_memory;
    memw();
    SLEEP_SYSCON_REGISTERS->frontend_memory = (power & ~1U) | frontend;

    unsigned int baseband = (configuration & SLEEP_FORCE_BASEBAND) != 0;
    memw();
    power = SLEEP_BASEBAND_POWER_REGISTER;
    memw();
    SLEEP_BASEBAND_POWER_REGISTER = (power & ~8U) | (baseband << 3);
    memw();
    power = SLEEP_BASEBAND_POWER_REGISTER;
    memw();
    SLEEP_BASEBAND_POWER_REGISTER = (power & ~2U) | (baseband << 1);

    unsigned int receiver = (configuration & SLEEP_FORCE_RECEIVER) != 0;
    memw();
    power = SLEEP_RECEIVER_POWER_REGISTER;
    memw();
    SLEEP_RECEIVER_POWER_REGISTER = (power & ~0x20U) | (receiver << 5);
    memw();
    power = SLEEP_RECEIVER_POWER_REGISTER;
    memw();
    SLEEP_RECEIVER_POWER_REGISTER = (power & ~8U) | (receiver << 3);
    memw();
    power = SLEEP_RECEIVER_POWER_REGISTER;
    memw();
    SLEEP_RECEIVER_POWER_REGISTER = (power & ~2U) | (receiver << 1);
    memw();
    power = SLEEP_IQ_ESTIMATOR_POWER_REGISTER;
    memw();
    SLEEP_IQ_ESTIMATOR_POWER_REGISTER = (power & ~0x20U) | (frontend << 5);
    memw();
    power = SLEEP_TX_INTERPOLATOR_POWER_REGISTER;
    memw();
    SLEEP_TX_INTERPOLATOR_POWER_REGISTER = (power & ~0x400U) | (frontend << 10);

    memw();
    power = SLEEP_SYSCON_REGISTERS->memory_power_up;
    memw();
    if (configuration & SLEEP_FORCE_SRAM)
        SLEEP_SYSCON_REGISTERS->memory_power_up = power | 0x3ff8U;
    else
        SLEEP_SYSCON_REGISTERS->memory_power_up = power & ~0x3ff8U;
    memw();
    power = SLEEP_SYSCON_REGISTERS->memory_power_up;
    memw();
    if (configuration & SLEEP_FORCE_ROM)
        SLEEP_SYSCON_REGISTERS->memory_power_up = power | 7U;
    else
        SLEEP_SYSCON_REGISTERS->memory_power_up = power & ~7U;
}
