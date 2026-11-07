/* Medius v3.4.7 device — memory/mapping.c.
 * Recovered C and native assembly, grouped for source navigation.
 * Original entry addresses, firmware-byte hashes and function comments follow.
 */

#include "../include/types.h"

/* Native entry: 0x4037718c. */
/*
 * Medius v3.4.7 — device application; 0x4037718c.
 *
 * Returns false before PSRAM initialization; otherwise tests the address against two configured half-open mapped regions. Does not check the length of a buffer starting there.
 *
 * Called by: esp_ptr_dma_ext_capable, esp_ptr_executable, esp_ptr_byte_accessible, esp_ptr_external_ram, esp_stack_ptr_in_extram.
 *
 * Original function-byte SHA-256:
 * a0c91660981a14d688af33f734ec084aefd0cbf5da08e419a3f5b0043adb6377.
 */

/* Returns false before PSRAM initialization; otherwise tests the address against two configured half-open mapped regions. Does not check the length of a buffer starting there.
   Reference: ESP-IDF v5.4.4 components/esp_psram/esp_psram.c. */

/*
 * pointer: Address to classify; not dereferenced.
 * Returns: Zero outside the initialized mappings. The first mapping returns the raw initialized
 *   byte; the second returns 1. Normal startup stores 1 in the initialized byte.
 * Requirements/effects: Checks one address only, without validating a buffer length or current
 *   allocation. Reads initialization/mapping globals without locking.
 */

unsigned char esp_psram_check_ptr_addr(void *pointer)
{
  volatile PsramContext *context = PSRAM_CONTEXT;
  unsigned char initialized = context->initialized;
  if (initialized == 0)
    return 0;

  /* Native BLT compares signed address words and reads each end only after
     that mapping's start admits the address. */
  int address = (int)pointer;
  if (address >= (int)context->mapped_regions[0].start &&
      address < (int)context->mapped_regions[0].end)
    return initialized;
  if (address < (int)context->mapped_regions[1].start)
    return 0;
  return address < (int)context->mapped_regions[1].end;
}

/* Native entry: 0x40384270. */
/*
 * Medius v3.4.7 — device application; 0x40384270.
 *
 * Tests the initialized external PSRAM mappings for this PSRAM-DMA-capable target; the pointer-only test does not establish transfer alignment or length.
 *
 * Calls: esp_psram_check_ptr_addr.
 *
 * Called by: FUN_42017464.
 *
 * Original function-byte SHA-256:
 * baf391fb835a2be15fd61001650988487d12d902528c8f6961589809f7c6878a.
 */

/* Tests the initialized external PSRAM mappings for this PSRAM-DMA-capable target; the pointer-only test does not establish transfer alignment or length.
   Reference: ESP-IDF v5.4.4 components/esp_hw_support/esp_memory_utils.c. */

/*
 * pointer: Address tested against initialized external mappings.
 * Returns: The PSRAM predicate's byte unchanged; nonzero means the address is admitted.
 * Requirements/effects: Does not validate transfer length, alignment, allocation ownership, DMA
 *   configuration or cache coherency.
 */

unsigned char esp_ptr_dma_ext_capable(void *pointer)
{
  return esp_psram_check_ptr_addr(pointer);
}

/* Native entry: 0x4038427c. */
/*
 * Medius v3.4.7 — device application; 0x4038427c.
 *
 * Tests whether an address lies in an executable address region; device also admits configured external RAM.
 *
 * Calls: esp_psram_check_ptr_addr.
 *
 * Called by: FUN_403760b0, FUN_40376120, FUN_420033ac, vPortTCBPreDeleteHook.
 *
 * Original function-byte SHA-256:
 * c2f5a2d2d4295a602a354cf14b305cd5b63a2c53a89a9faebb46268b6f7d7025.
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
 * Device additionally checks initialized PSRAM mappings after ROM and before
 * RTC, through esp_psram_check_ptr_addr. Earlier successful ranges skip that
 * helper. The helper reads mapping state without a lock; its truth is used
 * directly. No local allocation, target-memory read or state write occurs.
 * Matches the linked ESP-IDF v5.4.4 esp_memory_utils.c implementation.
 */
bool esp_ptr_executable(const void *pointer)
{
  unsigned int address = (unsigned int)pointer;
  return address - 0x42000000U < 0x2000000U ||
         address - 0x40370000U < 0x70000U ||
         address - 0x40000000U < 0x60000U ||
         esp_psram_check_ptr_addr((void *)pointer) != 0 ||
         address - 0x600fe000U < 0x2000U;
}

/* Native entry: 0x403842dc. */
/*
 * Medius v3.4.7 — device application; 0x403842dc.
 *
 * Tests byte-addressable DRAM/RTC ranges; the device also checks initialized PSRAM mappings. Does not dereference the pointer or validate a buffer length.
 *
 * Calls: esp_psram_check_ptr_addr.
 *
 * Called by: xPortCheckValidTCBMem, xPortcheckValidStackMem.
 *
 * Original function-byte SHA-256:
 * 8c40c1e0ecaff669f2535823f0fb2e753ab82a7e43cde73620708ce4d815dc19.
 */

/* Tests byte-addressable DRAM/RTC ranges; the device also checks initialized PSRAM mappings. Does not dereference the pointer or validate a buffer length.
   Reference: ESP-IDF v5.4.4 components/esp_hw_support/esp_memory_utils.c. */

/*
 * pointer: Address to classify without dereferencing.
 * Returns: Internal-range membership (0 or 1) OR the PSRAM predicate's raw byte. Nonzero means
 *   byte-accessible; a noncanonical initialized byte is not normalized here.
 * Requirements/effects: Internal ranges are [0x600fe000,0x60100000) and [0x3fc88000,0x3fd00000).
 *   Host does not check PSRAM here. This is not a whole-buffer bounds or allocation check.
 */

unsigned char esp_ptr_byte_accessible(void *pointer)
{
  unsigned int address = (unsigned int)pointer;
  unsigned char internal_member = address - 0x600fe000U < 0x2000U ||
                                  address - 0x3fc88000U < 0x78000U;
  /* The PSRAM helper is called even when internal membership succeeded. */
  unsigned char psram_member = esp_psram_check_ptr_addr(pointer);
  return internal_member | psram_member;
}

/* Native entry: 0x40384318. */
/*
 * Medius v3.4.7 — device application; 0x40384318.
 *
 * For this PSRAM-enabled image, forwards to the initialized external-memory mapping predicate.
 *
 * Calls: esp_psram_check_ptr_addr.
 *
 * Called by: FUN_42017464, esp_restart_noos.
 *
 * Original function-byte SHA-256:
 * dad97cf9239d47221daaef106df050133cd1adf70b2ac1eb2fe607a13f1e5d86.
 */

/* For this PSRAM-enabled image, forwards to the initialized external-memory mapping predicate.
   Reference: ESP-IDF v5.4.4 components/esp_hw_support/esp_memory_utils.c. */

/*
 * pointer: Address forwarded to the PSRAM mapping predicate.
 * Returns: The PSRAM predicate's byte unchanged; nonzero means initialized PSRAM membership.
 * Requirements/effects: Does not touch pointed-to data or validate length, permissions, allocation
 *   ownership or lifetime.
 */

unsigned char esp_ptr_external_ram(void *pointer)
{
  return esp_psram_check_ptr_addr(pointer);
}

/* Native entry: 0x40384324. */
/*
 * Medius v3.4.7 — device application; 0x40384324.
 *
 * Accepts a stack pointer only when it is in initialized PSRAM and is 16-byte aligned.
 *
 * Calls: esp_psram_check_ptr_addr.
 *
 * Called by: FUN_403760b0, FUN_40376120.
 *
 * Original function-byte SHA-256:
 * b46cb412e7d7c31880928f508e030ae52eba08f5481af2567a52bf3a3e01dee3.
 */

/* Accepts a stack pointer only when it is in initialized PSRAM and is 16-byte aligned.
   Reference: ESP-IDF v5.4.4 components/esp_hw_support/esp_memory_utils.c. */

/*
 * stack_pointer: Stack address to classify, not a buffer length.
 * Returns: True when PSRAM mapping admits the address and its low four bits are zero.
 * Requirements/effects: Requires both initialized PSRAM membership and 16-byte alignment. Does not
 *   prove sufficient stack storage.
 */

bool esp_stack_ptr_in_extram(unsigned int stack_pointer)
{
    unsigned char psram_member = esp_psram_check_ptr_addr((void *)stack_pointer);
    return psram_member != 0 && (stack_pointer & 0x0fU) == 0;
}

/* Native entry: 0x420116a4. */
/*
 * Medius v3.4.7 — device application; 0x420116a4.
 *
 * Configures the five native illegal 512-MiB regions, then region 1 for data read/write.
 *
 * Calls: mpu_hal_set_region_access, memcpy.
 *
 * Called by: FUN_4200f534.
 *
 * Original function-byte SHA-256:
 * 0fee84f941c3d9c1092f3dc4cbff6bbf5bd7896819100344d68a9b9506d360a6.
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
    uint illegal_regions[5];
    /* The pinned native DROM table contains exactly {0, 4, 5, 6, 7}. */
    memcpy(illegal_regions, ILLEGAL_MPU_REGIONS, sizeof(illegal_regions));
    for (uint index = 0; index < 5; index++)
        mpu_hal_set_region_access(illegal_regions[index], MPU_REGION_ILLEGAL);

    /* Both arguments are 1 in the native final call. */
    mpu_hal_set_region_access(1, MPU_REGION_RW);
}

/* Native entry: 0x42021330. */
/*
 * Medius v3.4.7 — device application; 0x42021330.
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
    uint address = (uint)region << 29;
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

