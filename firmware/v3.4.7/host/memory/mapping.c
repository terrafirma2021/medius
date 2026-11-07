/* Medius v3.4.7 host — memory/mapping.c.
 * Recovered C and native assembly, grouped for source navigation.
 * Original entry addresses, firmware-byte hashes and function comments follow.
 */

#include "../include/types.h"

/* Native entry: 0x4037fa38. */
/*
 * Medius v3.4.7 — host application; 0x4037fa38.
 *
 * Tests whether an address lies in an executable address region; device also admits configured external RAM.
 *
 * Called by: FUN_40375ce0, FUN_40375d38, FUN_420030e0, vPortTCBPreDeleteHook.
 *
 * Original function-byte SHA-256:
 * c901e7d17bdb014c90367367d407b7736e0f51b42441aed83c657993a72c9e8a.
 */

/*
 * Classify one address without reading the pointed-to bytes. pointer may be
 * NULL or unaligned; neither is specially rejected beyond region membership.
 * Returns a C bool. Unsigned 32-bit subtraction implements half-open ranges:
 * IROM [0x42000000,0x44000000), IRAM [0x40370000,0x403e0000), ROM
 * [0x40000000,0x40060000), and RTC fast memory [0x600fe000,0x60100000).
 * No instruction decoding, execute-permission lookup, cache readiness, buffer
 * extent or allocation/lifetime validation is performed. Membership can admit
 * data bytes or an invalid function start within one of those address ranges.
 * This host build has no PSRAM helper call or mapping-state reads. There
 * are no callees, target-memory reads, state writes, locks or allocations.
 * Matches the linked ESP-IDF v5.4.4 esp_memory_utils.c implementation.
 */
bool esp_ptr_executable(const void *pointer)
{
  unsigned int address = (unsigned int)pointer;
  return address - 0x42000000U < 0x2000000U ||
         address - 0x40370000U < 0x70000U ||
         address - 0x40000000U < 0x60000U ||
         address - 0x600fe000U < 0x2000U;
}

/* Native entry: 0x4037fa88. */
/*
 * Medius v3.4.7 — host application; 0x4037fa88.
 *
 * Tests byte-addressable DRAM/RTC ranges; the device also checks initialized PSRAM mappings. Does not dereference the pointer or validate a buffer length.
 *
 * Called by: xPortCheckValidTCBMem, xPortcheckValidStackMem.
 *
 * Original function-byte SHA-256:
 * b4c0b8eeaf4aa4e2b3e767c467547f620026e9a09648dbe184188ccf2efe688c.
 */

/* Tests byte-addressable DRAM/RTC ranges; the device also checks initialized PSRAM mappings. Does not dereference the pointer or validate a buffer length.
   Reference: ESP-IDF v5.4.4 components/esp_hw_support/esp_memory_utils.c. */

/*
 * pointer: Address to classify without dereferencing.
 * Returns: True for either compiled internal byte-addressable range.
 * Requirements/effects: Checks [0x600fe000,0x60100000) and [0x3fc88000,0x3fd00000). No length,
 *   allocation ownership or lifetime validation.
 */

bool esp_ptr_byte_accessible(const void *pointer)
{
    unsigned int address = (unsigned int)pointer;
    return address - 0x600fe000U < 0x2000U ||
           address - 0x3fc88000U < 0x78000U;
}

/* Native entry: 0x42013b38. */
/*
 * Medius v3.4.7 — host application; 0x42013b38.
 *
 * Configures the five native illegal 512-MiB regions, then region 1 for data read/write.
 *
 * Calls: mpu_hal_set_region_access, memcpy.
 *
 * Called by: FUN_42011940.
 *
 * Original function-byte SHA-256:
 * efcf17936999e0f50740651c092c8b7dfd996630aeefc0d76c044873794f3ca6.
 */

/*
 * Returns: No value.
 * Requirements/effects: Copies the pinned twenty-byte DROM list {0, 4, 5, 6, 7} into a private
 *   array, configures each region as ILLEGAL in that order, then explicitly calls
 *   mpu_hal_set_region_access(1, MPU_REGION_RW). Both final arguments are 1 in the instructions;
 *   the raw decompiler omitted the permission argument. No result, allocation, lock, status check
 *   or restoration is added.
 */

void esp_cpu_configure_region_protection(void)
{
    unsigned int illegal_regions[5];
    /* The pinned native DROM table contains exactly {0, 4, 5, 6, 7}. */
    memcpy(illegal_regions, ILLEGAL_MPU_REGIONS, sizeof(illegal_regions));
    for (unsigned int index = 0; index < 5; index++)
        mpu_hal_set_region_access(illegal_regions[index], MPU_REGION_ILLEGAL);

    /* Both arguments are 1 in the native final call. */
    mpu_hal_set_region_access(1, MPU_REGION_RW);
}

/* Native entry: 0x4201ebf8. */
/*
 * Medius v3.4.7 — host application; 0x4201ebf8.
 *
 * Writes the selected Xtensa region translation bank(s) and synchronization instructions using typed MPU access modes.
 *
 * Called by: esp_cpu_configure_region_protection.
 *
 * Original function-byte SHA-256:
 * 28972646dab358f6a4231e05410cb543282e199cca8ce69571dcfbcd2d5f2b20.
 */

/*
 * region: Signed raw region ID. Its unsigned low-32-bit shift by 29 selects a 512-MiB base; no
 *   range check is performed, so IDs alias modulo eight.
 * access: ILLEGAL (0), RW (1), X (2), or RWX (3). Every other raw value leaves both translation
 *   banks unchanged.
 * Returns: No value.
 * Requirements/effects: ILLEGAL writes I-TLB attribute 15, ISYNC, D-TLB attribute 15, then DSYNC.
 *   RW writes only D-TLB attribute 0 and DSYNC; X writes only I-TLB attribute 3 and ISYNC; RWX
 *   writes only D-TLB attribute 2 and DSYNC. The other bank is not restored by these permissive
 *   modes. Inline assembly states the native attributes/address operand order explicitly. The SDK
 *   API returns void: the original implementation's shifted A2 is an incidental register value,
 *   not a promised result. Physical access enforcement depends on processor translation state and
 *   is not simulated here.
 */

void mpu_hal_set_region_access(int region, MpuAccess access)
{
    /* Regions are 512 MiB. Unsigned shifting retains the native low-32-bit
       operation for every raw ID, including negative/out-of-range inputs. */
    unsigned int address = (unsigned int)region << 29;
    switch (access) {
    case MPU_REGION_ILLEGAL:
        __asm__ volatile ("witlb %0, %1\nisync\nwdtlb %0, %1\ndsync"
            :: "a"(15U), "a"(address) : "memory");
        break;
    case MPU_REGION_RW:
        __asm__ volatile ("wdtlb %0, %1\ndsync"
            :: "a"(0U), "a"(address) : "memory");
        break;
    case MPU_REGION_X:
        __asm__ volatile ("witlb %0, %1\nisync"
            :: "a"(3U), "a"(address) : "memory");
        break;
    case MPU_REGION_RWX:
        __asm__ volatile ("wdtlb %0, %1\ndsync"
            :: "a"(2U), "a"(address) : "memory");
        break;
    default:
        break;
    }
}
