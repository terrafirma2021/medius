/* Medius v3.4.7 device: recovered sleep submode accounting. */

#include "../include/types.h"

/* Native entry: 0x42007210. */
/*
 * Medius v3.4.7 — device application; 0x42007210.
 * Instruction-checked recovered C.
 * Original function-byte SHA-256:
 * f25ae35ead147e56c64a5a622c383e1df2cbb1dd26058ff8fb5cf882d9e7a110.
 */

/* Outlined sleep-submode adjustment; caller validates unsigned mode < 7. Probe
 * ISR context, enter sleep-config mux indefinitely, read signed 32-bit RTC-retained
 * count once, then add 1 for any nonzero FULL-WORD activate or subtract 1 for 0.
 * Native arithmetic wraps modulo 2^32; publish that result before testing its sign.
 * A negative result (including INT_MAX+1 wrap) optionally logs at early level
 * >=2 WHILE LOCKED, then clamps count to 0. Probe ISR again and unlock. Return 0
 * even on underflow. No index bounds check, saturation at INT_MAX, rollback,
 * clock switch or failure status is provided. */
int sleep_submode_adjust(unsigned int submode,unsigned int activate_word)
{
    (void)xPortInIsrContext();
    (void)xPortEnterCriticalTimeout(SLEEP_CONFIGURATION_LOCK,-1);
    volatile int *reference_count = &SLEEP_SUBMODE_COUNTS[submode];
    unsigned int previous_count_bits = (unsigned int)*reference_count;
    unsigned int updated_count_bits = previous_count_bits + (activate_word ? 1U : 0xffffffffU);
    *reference_count = (int)updated_count_bits;
    if ((int)updated_count_bits < 0) {
        if (SYSTEM_EARLY_LOG_LEVEL >= 2U) {
            unsigned int timestamp = esp_log_timestamp();
            const char *name = SLEEP_SUBMODE_NAMES[submode];
            ets_printf("W (%lu) %s: %s disabled multiple times!! (If this log appears only once after OTA upgrade, it can be ignored.)\n",
                       timestamp,"sleep",name);
        }
        *reference_count = 0;
    }
    (void)xPortInIsrContext();
    vPortExitCritical(SLEEP_CONFIGURATION_LOCK);
    return 0;
}

/* Native entry: 0x42007278. */
/*
 * Medius v3.4.7 — device application; 0x42007278.
 * Instruction-checked recovered C.
 * Original function-byte SHA-256:
 * 24c2ebed0bcbc48f8ebc4cef80cd30807b41ff64c73d1a134b65b2497f51ec88.
 */

/* Caller validates mode < 7. Probe ISR, take sleep-config mux indefinitely, store
 * count 0 in RTC-retained array, probe ISR again, then unlock. All references
 * are discarded, not decremented. Lock/probe results ignored; no clock action,
 * index validation, error output or restoration of displaced references. */
void sleep_submode_clear(unsigned int submode)
{
    (void)xPortInIsrContext();
    (void)xPortEnterCriticalTimeout(SLEEP_CONFIGURATION_LOCK,-1);
    *(volatile int *)&SLEEP_SUBMODE_COUNTS[submode] = 0;
    (void)xPortInIsrContext();
    vPortExitCritical(SLEEP_CONFIGURATION_LOCK);
}

/* Native entry: 0x420072ac. */
/*
 * Medius v3.4.7 — device application; 0x420072ac.
 * Instruction-checked recovered C.
 * Original function-byte SHA-256:
 * 531f3e057d11736bb36bbb0048b64c3441fda7423eef7d055645386d99af1882.
 */

/* Accept unsigned mode 0..6; reject other values with 0x102 and no lock/access.
 * Forward only LOW BYTE of activate to the outlined full-word truthiness
 * helper; ignore helper result and return 0 after accepted update/clamp. */
int esp_sleep_sub_mode_config(unsigned int submode,unsigned char activate)
{
    if (submode >= SLEEP_SUBMODE_COUNT)
        return 0x102;
    (void)sleep_submode_adjust(submode,activate);
    return 0;
}

/* Native entry: 0x420072c4. */
/*
 * Medius v3.4.7 — device application; 0x420072c4.
 * Instruction-checked recovered C.
 * Original function-byte SHA-256:
 * a047dc1bd77c6d9096e1eb6645397d12a6202645d404a690a9f86873e07c6f98.
 */

/* Reject unsigned mode >= 7 with 0x102 and no lock/access; otherwise clear ALL
 * references for that exact mode under sleep-config mux and return 0. The raw
 * decompile lost this helper's mode argument. No hardware clock switch. */
int esp_sleep_sub_mode_force_disable(unsigned int submode)
{
    if (submode >= SLEEP_SUBMODE_COUNT)
        return 0x102;
    sleep_submode_clear(submode);
    return 0;
}

/* Native entry: 0x420072d8. */
/*
 * Medius v3.4.7 — device application; 0x420072d8.
 * Instruction-checked recovered C.
 * Original function-byte SHA-256:
 * 8f363d89a0700692aeefa753a879f96b6db3ebd82dc2f37e86a73a20d2273943.
 */

/* Always return borrowed mutable pointer to seven signed 32-bit RTC-retained mode
 * counters. With NULL stream, do nothing else. Otherwise walk modes0..6 without
 * locking: read each count ONCE, then its name pointer; print name, ENABLED
 * for nonzero or DISABLED for 0, and THAT SAME count as signed 32-bit long. Ignore
 * every fprintf result and continue after I/O failure. The original decompile
 * omitted the final count variadic argument recovered from A14. No snapshot
 * consistency across rows, count modification or ownership transfer. The
 * stream is passed unchanged to the formatter; no FILE field is accessed. */
int *esp_sleep_sub_mode_dump_config(NewlibFile *stream)
{
    if (stream) {
        for (unsigned int submode = 0; submode < SLEEP_SUBMODE_COUNT; ++submode) {
            int reference_count = *(volatile int *)&SLEEP_SUBMODE_COUNTS[submode];
            const char *name = SLEEP_SUBMODE_NAMES[submode];
            (void)newlib_fprintf(stream,"%s : %s (cnt = %ld)\n",name,
                                      reference_count ? "ENABLED" : "DISABLED",(long)reference_count);
        }
    }
    return SLEEP_SUBMODE_COUNTS;
}

/* Native entry: 0x40384ec8. */
/*
 * Medius v3.4.7 — device application; 0x40384ec8.
 * Instruction-checked recovered C.
 * Original function-byte SHA-256:
 * 84448492a08b7be796b5d583e89f7aa8dfdaffe80ea73c453056d5a30425a5c0.
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
void rtc_sleep_pu(unsigned int configuration_word)
{
    unsigned int digital_force_on = (configuration_word & SLEEP_FORCE_DIGITAL) != 0;
    memw();
    unsigned int register_value = SLEEP_POWER_REGISTERS->digital_memory;
    memw();
    SLEEP_POWER_REGISTERS->digital_memory = (register_value & ~0x10U) | (digital_force_on << 4);
    unsigned int rtc_force_on = (configuration_word & SLEEP_FORCE_RTC) != 0;
    memw();
    register_value = SLEEP_POWER_REGISTERS->rtc_memory;
    memw();
    SLEEP_POWER_REGISTERS->rtc_memory = (register_value & ~0x100U) | (rtc_force_on << 8);
    memw();
    register_value = SLEEP_POWER_REGISTERS->rtc_memory;
    memw();
    SLEEP_POWER_REGISTERS->rtc_memory = (register_value & ~0x800U) | (rtc_force_on << 11);

    unsigned int frontend_force_on = (configuration_word & SLEEP_FORCE_FRONTEND) != 0;
    memw();
    register_value = SLEEP_SYSCON_REGISTERS->frontend_memory;
    memw();
    SLEEP_SYSCON_REGISTERS->frontend_memory = (register_value & ~0x10U) | (frontend_force_on << 4);
    memw();
    register_value = SLEEP_SYSCON_REGISTERS->frontend_memory;
    memw();
    SLEEP_SYSCON_REGISTERS->frontend_memory = (register_value & ~4U) | (frontend_force_on << 2);
    memw();
    register_value = SLEEP_SYSCON_REGISTERS->frontend_memory;
    memw();
    SLEEP_SYSCON_REGISTERS->frontend_memory = (register_value & ~1U) | frontend_force_on;

    unsigned int baseband_force_on = (configuration_word & SLEEP_FORCE_BASEBAND) != 0;
    memw();
    register_value = SLEEP_BASEBAND_POWER_REGISTER;
    memw();
    SLEEP_BASEBAND_POWER_REGISTER = (register_value & ~8U) | (baseband_force_on << 3);
    memw();
    register_value = SLEEP_BASEBAND_POWER_REGISTER;
    memw();
    SLEEP_BASEBAND_POWER_REGISTER = (register_value & ~2U) | (baseband_force_on << 1);

    unsigned int receiver_force_on = (configuration_word & SLEEP_FORCE_RECEIVER) != 0;
    memw();
    register_value = SLEEP_RECEIVER_POWER_REGISTER;
    memw();
    SLEEP_RECEIVER_POWER_REGISTER = (register_value & ~0x20U) | (receiver_force_on << 5);
    memw();
    register_value = SLEEP_RECEIVER_POWER_REGISTER;
    memw();
    SLEEP_RECEIVER_POWER_REGISTER = (register_value & ~8U) | (receiver_force_on << 3);
    memw();
    register_value = SLEEP_RECEIVER_POWER_REGISTER;
    memw();
    SLEEP_RECEIVER_POWER_REGISTER = (register_value & ~2U) | (receiver_force_on << 1);
    memw();
    register_value = SLEEP_IQ_ESTIMATOR_POWER_REGISTER;
    memw();
    SLEEP_IQ_ESTIMATOR_POWER_REGISTER = (register_value & ~0x20U) | (frontend_force_on << 5);
    memw();
    register_value = SLEEP_TX_INTERPOLATOR_POWER_REGISTER;
    memw();
    SLEEP_TX_INTERPOLATOR_POWER_REGISTER = (register_value & ~0x400U) | (frontend_force_on << 10);

    memw();
    register_value = SLEEP_SYSCON_REGISTERS->memory_power_up;
    memw();
    if (configuration_word & SLEEP_FORCE_SRAM)
        SLEEP_SYSCON_REGISTERS->memory_power_up = register_value | 0x3ff8U;
    else
        SLEEP_SYSCON_REGISTERS->memory_power_up = register_value & ~0x3ff8U;
    memw();
    register_value = SLEEP_SYSCON_REGISTERS->memory_power_up;
    memw();
    if (configuration_word & SLEEP_FORCE_ROM)
        SLEEP_SYSCON_REGISTERS->memory_power_up = register_value | 7U;
    else
        SLEEP_SYSCON_REGISTERS->memory_power_up = register_value & ~7U;
}
