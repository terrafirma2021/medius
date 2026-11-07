/* Medius v3.4.7 device: ESP32-S3 memory-protection locks and monitors. */
#include "../include/types.h"

/* Readable reconstruction utilities: inlined native CPU-selection/register logic;
 * these helpers do not introduce additional native function identities. */
static inline __attribute__((always_inline)) bool memprot_core_selected_count(
    unsigned int count,int core)
{
    if (count == 0)
        return false;
    if (MEMPROT_CONFIGURATION.target_cpu[0] == core)
        return true;
    return count != 1 && MEMPROT_CONFIGURATION.target_cpu[1] == core;
}

static inline __attribute__((always_inline)) bool memprot_core_selected(int core)
{
    unsigned int count = MEMPROT_CONFIGURATION.target_cpu_count;
    return memprot_core_selected_count(count,core);
}

static inline __attribute__((always_inline)) MemoryProtectionMonitor *
memprot_monitor_registers(unsigned int memory_type,int core)
{
    if ((unsigned int)core > 1)
        return NULL;
    switch (memory_type) {
    case MEMPROT_IRAM:
        return core == 0 ? MEMPROT_IRAM_MONITOR0 : MEMPROT_IRAM_MONITOR1;
    case MEMPROT_DRAM:
        return core == 0 ? MEMPROT_DRAM_MONITOR0 : MEMPROT_DRAM_MONITOR1;
    default: /* Caller has already restricted this case to RTCFAST. */
        return core == 0 ? MEMPROT_RTC_MONITOR0 : MEMPROT_RTC_MONITOR1;
    }
}

/* Native entry: 0x42005a0c. */
/* Original function-byte SHA-256:
 * 39e13c4b5c89b9b98e2e59790784460c93fa4c4f6c29c8597f326960f380c5b1. */
/*
 * esp_mprot_set_pms_lock: write 1 to the global IRAM/DRAM permission lock.
 * Those two cases ignore core and configured CPU membership. RTCFAST first
 * requires a configured core, then chooses its per-core permission lock.
 * Invalid memory type returns 0xd001; missing configured core returns 0xd008;
 * a configured core other than 0/1 converts HAL error 7 to -1. No readback,
 * unlock operation, software lock or verification of the hardware latch.
 */
int esp_mprot_set_pms_lock(unsigned int memory_type,int core)
{
    if (memory_type == MEMPROT_IRAM) {
        memw();
        MEMPROT_IRAM_PMS_LOCK = 1;
        return 0;
    }
    if (memory_type == MEMPROT_DRAM) {
        memw();
        MEMPROT_DRAM_PMS_LOCK = 1;
        return 0;
    }
    if (memory_type != MEMPROT_RTCFAST)
        return 0xd001;
    if (!memprot_core_selected(core))
        return 0xd008;
    if ((unsigned int)core > 1)
        return esp_mprot_ll_err_to_esp_err(7);
    memw();
    if (core == 0)
        MEMPROT_RTC_PMS_LOCK0 = 1;
    else
        MEMPROT_RTC_PMS_LOCK1 = 1;
    return esp_mprot_ll_err_to_esp_err(0);
}

/* Native entry: 0x42005fb4. */
/* Original function-byte SHA-256:
 * e9c24b5841dbf566745d7b5c00bb39d7c8360e3c59a283891eaeaa71dbc081c3. */
/*
 * esp_mprot_set_monitor_lock: require membership in the saved CPU list BEFORE
 * validating memory type. For IRAM/DRAM/RTCFAST and physical core 0/1, write 1
 * to that monitor's lock word after MEMW. Return the HAL-to-ESP conversion of
 * success; membership failure is 0xd008, bad memory type 0xd001, and a listed
 * core outside 0/1 converts HAL error 7 to -1. No readback or rollback.
 */
int esp_mprot_set_monitor_lock(unsigned int memory_type,int core)
{
    if (!memprot_core_selected(core))
        return 0xd008;
    if (memory_type != MEMPROT_IRAM && memory_type != MEMPROT_DRAM &&
        memory_type != MEMPROT_RTCFAST)
        return 0xd001;
    MemoryProtectionMonitor *monitor = memprot_monitor_registers(memory_type,core);
    if (monitor == NULL)
        return esp_mprot_ll_err_to_esp_err(7);
    memw();
    monitor->lock = 1;
    return esp_mprot_ll_err_to_esp_err(0);
}

/* Native entry: 0x4200605c. */
/* Original function-byte SHA-256:
 * f0924ed2c353a85f6b9df73d133503a04e027f31a67ffa8582f2c3a0b3c165bf. */
/*
 * esp_mprot_get_monitor_lock: reject NULL output (0x102), then an unconfigured
 * core (0xd008), then invalid memory type (0xd001). A listed physical core 0/1
 * selects the corresponding monitor; after MEMW, compare its ENTIRE lock word
 * to 1 and store one output byte. Other listed core IDs convert HAL error 7 to
 * -1 without touching output. No masking to bit 0, no output initialization on
 * errors, and no locking/snapshot across configuration and hardware reads.
 */
int esp_mprot_get_monitor_lock(unsigned int memory_type,unsigned char *locked,int core)
{
    if (locked == NULL)
        return 0x102;
    if (!memprot_core_selected(core))
        return 0xd008;
    if (memory_type != MEMPROT_IRAM && memory_type != MEMPROT_DRAM &&
        memory_type != MEMPROT_RTCFAST)
        return 0xd001;
    MemoryProtectionMonitor *monitor = memprot_monitor_registers(memory_type,core);
    if (monitor == NULL)
        return esp_mprot_ll_err_to_esp_err(7);
    memw();
    unsigned int word = monitor->lock;
    *locked = word == 1;
    return esp_mprot_ll_err_to_esp_err(0);
}

/* Native entry: 0x42006144. */
/* Original function-byte SHA-256:
 * a773df90c9fe5777bdd57c90d7eb7c258a1b658583451564afd326708a3078c5. */
/*
 * esp_mprot_set_monitor_en: truncate enable to its native BYTE and use any
 * nonzero value to set control bit 1; zero clears it. Check configured CPU,
 * memory type and physical core in that order, returning 0xd008/0xd001/-1
 * respectively on failure. Perform one MEMW/read/MEMW/write RMW, retaining all
 * other control bits. Convert HAL success after the write. No atomic RMW,
 * latch/readback check or interrupt synchronization.
 */
int esp_mprot_set_monitor_en(unsigned int memory_type,unsigned char enable,int core)
{
    if (!memprot_core_selected(core))
        return 0xd008;
    if (memory_type != MEMPROT_IRAM && memory_type != MEMPROT_DRAM &&
        memory_type != MEMPROT_RTCFAST)
        return 0xd001;
    MemoryProtectionMonitor *monitor = memprot_monitor_registers(memory_type,core);
    if (monitor == NULL)
        return esp_mprot_ll_err_to_esp_err(7);
    memw();
    unsigned int control = monitor->control;
    control = enable != 0 ? control | 2U : control & ~2U;
    memw();
    monitor->control = control;
    return esp_mprot_ll_err_to_esp_err(0);
}

/* Native entry: 0x42006254. */
/* Original function-byte SHA-256:
 * 943718f13aa5b36f42348981b4cad53d2f63b8d04cab8dcde46b7fb38b5c4826. */
/*
 * esp_mprot_get_monitor_en: reject NULL output, unconfigured CPU, invalid memory
 * type, and listed core outside 0/1 in that order (0x102/0xd008/0xd001/-1).
 * MEMW/read the selected control word and store bit 1 as one 0/1 BYTE, then
 * convert HAL success. Error paths leave output unchanged; other control bits
 * do not affect the result. Configuration and hardware are read without a lock.
 */
int esp_mprot_get_monitor_en(unsigned int memory_type,unsigned char *enabled,int core)
{
    if (enabled == NULL)
        return 0x102;
    if (!memprot_core_selected(core))
        return 0xd008;
    if (memory_type != MEMPROT_IRAM && memory_type != MEMPROT_DRAM &&
        memory_type != MEMPROT_RTCFAST)
        return 0xd001;
    MemoryProtectionMonitor *monitor = memprot_monitor_registers(memory_type,core);
    if (monitor == NULL)
        return esp_mprot_ll_err_to_esp_err(7);
    memw();
    unsigned int control = monitor->control;
    *enabled = (control >> 1) & 1U;
    return esp_mprot_ll_err_to_esp_err(0);
}

/* Native entry: 0x42006320. */
/* Original function-byte SHA-256:
 * b62c5e64d98a6cef87c4d7448deb26be2e372dab5bf462ca5423c1132d06525b. */
/*
 * esp_mprot_monitor_clear_intr: validate configured CPU before memory type,
 * choose its IRAM/DRAM/RTCFAST monitor, and pulse control bit 0. Each edge uses
 * a separate MEMW/read/MEMW/write; the falling edge rereads hardware rather
 * than reusing the rising-edge word. Convert/check HAL status between edges
 * and convert success again afterward. Listed cores outside 0/1 convert error
 * 7 (-1) before MMIO; bad CPU/type return 0xd008/0xd001. No wait, atomic RMW,
 * interrupt masking or guarantee that a violation cannot occur during the pulse.
 */
int esp_mprot_monitor_clear_intr(unsigned int memory_type,int core)
{
    if (!memprot_core_selected(core))
        return 0xd008;
    if (memory_type != MEMPROT_IRAM && memory_type != MEMPROT_DRAM &&
        memory_type != MEMPROT_RTCFAST)
        return 0xd001;
    MemoryProtectionMonitor *monitor = memprot_monitor_registers(memory_type,core);
    if (monitor == NULL) {
        int error = esp_mprot_ll_err_to_esp_err(7);
        if (error != 0)
            return error;
        return esp_mprot_ll_err_to_esp_err(7);
    }
    memw();
    unsigned int control = monitor->control;
    memw();
    monitor->control = control | 1U;
    int error = esp_mprot_ll_err_to_esp_err(0);
    if (error != 0)
        return error;
    memw();
    control = monitor->control;
    memw();
    monitor->control = control & ~1U;
    return esp_mprot_ll_err_to_esp_err(0);
}

/* Native entry: 0x42006404. */
/* Original function-byte SHA-256:
 * 69f41ee3e14cb1639a972e260cf07c53d1158edd91ee6468ef07e246bdf96cc0. */
/*
 * esp_mprot_is_conf_locked_any: OR lock observations into the caller's existing
 * BYTE; it is NOT initialized and is not normalized to bool. NULL returns
 * 0x102. Visit saved mask bits IRAM, DRAM, RTCFAST in order. IRAM/DRAM each read
 * the common split lock, global permission lock, core-0 monitor lock and,
 * when the freshly read CPU count is >=2, core-1 monitor lock. RTCFAST reads
 * per-core permission then monitor locks, core 1 only when count >=2.
 *
 * Every lock compares the whole WORD to exactly 1. CPU membership is checked
 * before each per-core observation; absent membership returns 0xd008 with
 * accumulated output retained. Explicit HAL conversions occur after per-core
 * MMIO reads. Re-read count/mask/list fields at the native boundaries; do not
 * snapshot configuration or stop when a lock is found. Output may already have
 * changed on failure. No writes to hardware or configuration, no software lock.
 */
int esp_mprot_is_conf_locked_any(unsigned char *locked)
{
    if (locked == NULL)
        return 0x102;
    volatile unsigned char *output = locked;
    unsigned int mask = MEMPROT_CONFIGURATION.memory_type_mask;
    unsigned int count,word;
    unsigned char previous;
    int error;
    if ((mask & MEMPROT_IRAM) != 0) {
        memw();
        unsigned int split = MEMPROT_SPLIT_LOCK;
        memw();
        unsigned int permission = MEMPROT_IRAM_PMS_LOCK;
        previous = *output;
        count = MEMPROT_CONFIGURATION.target_cpu_count;
        *output = previous | (split == 1) | (permission == 1);
        if (!memprot_core_selected_count(count,0))
            return 0xd008;
        memw();
        word = MEMPROT_IRAM_MONITOR0->lock;
        error = esp_mprot_ll_err_to_esp_err(0);
        if (error != 0)
            return error;
        previous = *output;
        count = MEMPROT_CONFIGURATION.target_cpu_count;
        *output = previous | (word == 1);
        if (count >= 2) {
            if (!memprot_core_selected_count(count,1))
                return 0xd008;
            memw();
            word = MEMPROT_IRAM_MONITOR1->lock;
            error = esp_mprot_ll_err_to_esp_err(0);
            if (error != 0)
                return error;
            previous = *output;
            mask = MEMPROT_CONFIGURATION.memory_type_mask;
            *output = previous | (word == 1);
        } else
            mask = MEMPROT_CONFIGURATION.memory_type_mask;
    }
    if ((mask & MEMPROT_DRAM) != 0) {
        memw();
        unsigned int split = MEMPROT_SPLIT_LOCK;
        memw();
        unsigned int permission = MEMPROT_DRAM_PMS_LOCK;
        previous = *output;
        count = MEMPROT_CONFIGURATION.target_cpu_count;
        *output = previous | (split == 1) | (permission == 1);
        if (!memprot_core_selected_count(count,0))
            return 0xd008;
        memw();
        word = MEMPROT_DRAM_MONITOR0->lock;
        error = esp_mprot_ll_err_to_esp_err(0);
        if (error != 0)
            return error;
        previous = *output;
        count = MEMPROT_CONFIGURATION.target_cpu_count;
        *output = previous | (word == 1);
        if (count >= 2) {
            if (!memprot_core_selected_count(count,1))
                return 0xd008;
            memw();
            word = MEMPROT_DRAM_MONITOR1->lock;
            error = esp_mprot_ll_err_to_esp_err(0);
            if (error != 0)
                return error;
            previous = *output;
            mask = MEMPROT_CONFIGURATION.memory_type_mask;
            *output = previous | (word == 1);
        } else
            mask = MEMPROT_CONFIGURATION.memory_type_mask;
    }
    if ((mask & MEMPROT_RTCFAST) == 0)
        return 0;
    count = MEMPROT_CONFIGURATION.target_cpu_count;
    if (!memprot_core_selected_count(count,0))
        return 0xd008;
    memw();
    word = MEMPROT_RTC_PMS_LOCK0;
    error = esp_mprot_ll_err_to_esp_err(0);
    if (error != 0)
        return error;
    previous = *output;
    count = MEMPROT_CONFIGURATION.target_cpu_count;
    *output = previous | (word == 1);
    if (!memprot_core_selected_count(count,0))
        return 0xd008;
    memw();
    word = MEMPROT_RTC_MONITOR0->lock;
    error = esp_mprot_ll_err_to_esp_err(0);
    if (error != 0)
        return error;
    previous = *output;
    count = MEMPROT_CONFIGURATION.target_cpu_count;
    *output = previous | (word == 1);
    if (count < 2)
        return 0;
    if (!memprot_core_selected_count(count,1))
        return 0xd008;
    memw();
    word = MEMPROT_RTC_PMS_LOCK1;
    error = esp_mprot_ll_err_to_esp_err(0);
    if (error != 0)
        return error;
    previous = *output;
    count = MEMPROT_CONFIGURATION.target_cpu_count;
    *output = previous | (word == 1);
    if (!memprot_core_selected_count(count,1))
        return 0xd008;
    memw();
    word = MEMPROT_RTC_MONITOR1->lock;
    error = esp_mprot_ll_err_to_esp_err(0);
    if (error != 0)
        return error;
    *output = *output | (word == 1);
    return 0;
}

/* Native entry: 0x42007190. */
/* Original function-byte SHA-256:
 * b6071efee10a3c2b51e25e4cb6551bb692e912319df69b973c85b835b0d16050. */
/*
 * esp_mprot_ll_err_to_esp_err: HAL 0 -> success; 2/3/4/5/6 -> ESP errors
 * 0xd003/0xd004/0xd005/0xd007/0xd006. Every other signed 32-bit value, including
 * core error 7, maps to -1. No state access, errno update or diagnostic output.
 */
int esp_mprot_ll_err_to_esp_err(int hal_error)
{
    switch (hal_error) {
    case 0: return 0;
    case 2: return 0xd003;
    case 3: return 0xd004;
    case 4: return 0xd005;
    case 5: return 0xd007;
    case 6: return 0xd006;
    default: return -1;
    }
}

/* Native entry: 0x42005a8c. */
/* Original function-byte SHA-256:
 * 958cb70580e1a70900c68366077f0ee091b7fe9118d2e17cfc067fed7776b444. */
/*
 * esp_mprot_set_pms_area: replace permissions for one exact area identifier.
 * IRAM/cache areas use API read/write/execute bits 0..2 in 3-bit fields;
 * DRAM areas use only read/write bits in 2-bit fields. These cases ignore core,
 * discard other permission bits and perform one MEMW/read/MEMW/write RMW.
 *
 * RTCFAST first requires configured CPU membership (else 0xd008), then physical
 * core 0/1 (else HAL error 7 -> -1). Its hardware read/write bits are swapped
 * relative to API bits; low/high fields start at bit 0/3. First clear that
 * field with one RMW, then REREAD and replace it with a second RMW, retaining
 * concurrent changes outside the field. Return converted HAL success afterward.
 * Unrecognized area, including combinations of valid IDs, returns 0x106.
 * No software lock, atomic update, readback, or check of hardware lock state.
 */
int esp_mprot_set_pms_area(unsigned int area,unsigned int permissions,int core)
{
    volatile unsigned int *reg;
    unsigned int shift,mask;
    switch (area) {
    case MEMPROT_AREA_IRAM0: shift=0; goto iram;
    case MEMPROT_AREA_IRAM1: shift=3; goto iram;
    case MEMPROT_AREA_IRAM2: shift=6; goto iram;
    case MEMPROT_AREA_IRAM3: shift=9; goto iram;
    case MEMPROT_AREA_ICACHE0: shift=12; goto iram;
    case MEMPROT_AREA_ICACHE1: shift=15; goto iram;
    case MEMPROT_AREA_DRAM0: shift=0; goto dram;
    case MEMPROT_AREA_DRAM1: shift=2; goto dram;
    case MEMPROT_AREA_DRAM2: shift=4; goto dram;
    case MEMPROT_AREA_DRAM3: shift=6; goto dram;
    case MEMPROT_AREA_RTC_LOW: shift=0; break;
    case MEMPROT_AREA_RTC_HIGH: shift=3; break;
    default: return 0x106;
    }
    if (!memprot_core_selected(core))
        return 0xd008;
    if ((unsigned int)core > 1)
        return esp_mprot_ll_err_to_esp_err(7);
    reg = core == 0 ? &MEMPROT_RTC_REGION0->permissions :
                      &MEMPROT_RTC_REGION1->permissions;
    mask = 7U << shift;
    memw();
    unsigned int word = *reg;
    unsigned int encoded = ((permissions & 1U) << 1) | ((permissions & 2U) != 0);
    memw();
    *reg = word & ~mask;
    memw();
    word = *reg;
    encoded |= permissions & 4U;
    memw();
    *reg = word ^ ((word ^ (encoded << shift)) & mask);
    return esp_mprot_ll_err_to_esp_err(0);
iram:
    reg = &MEMPROT_IRAM_PERMISSIONS;
    mask = 7U;
    goto global_area;
dram:
    reg = &MEMPROT_DRAM_PERMISSIONS;
    mask = 3U;
global_area:
    memw();
    word = *reg;
    word = (word & ~(mask << shift)) | ((permissions & mask) << shift);
    memw();
    *reg = word;
    return 0;
}

/* Native entry: 0x42005d80. */
/* Original function-byte SHA-256:
 * d4e7c580a5d4d4ba93f5d795931d392d1446a84923334bc5dfac4434af48482e. */
/*
 * esp_mprot_get_pms_area: NULL output returns 0x102 before area validation.
 * Read exactly one selected permission WORD after MEMW. IRAM/cache return a
 * 3-bit read/write/execute field. DRAM first stores output 0, then 1 when read
 * is enabled, then adds write as a final store if enabled; execute is omitted.
 * These global areas ignore core. Invalid area returns 0xd001, unlike setter.
 *
 * RTCFAST validates configured membership (0xd008), then physical core 0/1
 * (HAL7 -> -1). Read cached hardware bits, convert/check HAL success, swap
 * hardware read/write bits into API order, then store the WORD. High fields
 * use bit 3 on both cores. The native CORE-1 LOW GETTER USES BIT 6, while its
 * setter writes bit 0; preserve this discrepancy rather than silently fixing
 * it from the SDK's intended behavior. Ordinary errors leave output unchanged.
 * No snapshot lock, hardware write or guarantee against concurrent changes.
 */
int esp_mprot_get_pms_area(unsigned int area,unsigned int *permissions,int core)
{
    if (permissions == NULL)
        return 0x102;
    volatile unsigned int *output = permissions;
    volatile unsigned int *reg;
    unsigned int shift;
    switch (area) {
    case MEMPROT_AREA_IRAM0: shift=0; goto iram;
    case MEMPROT_AREA_IRAM1: shift=3; goto iram;
    case MEMPROT_AREA_IRAM2: shift=6; goto iram;
    case MEMPROT_AREA_IRAM3: shift=9; goto iram;
    case MEMPROT_AREA_ICACHE0: shift=12; goto iram;
    case MEMPROT_AREA_ICACHE1: shift=15; goto iram;
    case MEMPROT_AREA_DRAM0: shift=0; goto dram;
    case MEMPROT_AREA_DRAM1: shift=2; goto dram;
    case MEMPROT_AREA_DRAM2: shift=4; goto dram;
    case MEMPROT_AREA_DRAM3: shift=6; goto dram;
    case MEMPROT_AREA_RTC_LOW: shift=0; break;
    case MEMPROT_AREA_RTC_HIGH: shift=3; break;
    default: return 0xd001;
    }
    if (!memprot_core_selected(core))
        return 0xd008;
    if ((unsigned int)core > 1) {
        int error = esp_mprot_ll_err_to_esp_err(7);
        if (error == 0)
            *output = 0;
        return error;
    }
    reg = core == 0 ? &MEMPROT_RTC_REGION0->permissions :
                      &MEMPROT_RTC_REGION1->permissions;
    if (area == MEMPROT_AREA_RTC_LOW && core == 1)
        shift = 6; /* Native 0x42005f00 device / 0x42005acc host. */
    memw();
    unsigned int bits = (*reg >> shift) & 7U;
    int error = esp_mprot_ll_err_to_esp_err(0);
    if (error != 0)
        return error;
    *output = ((bits >> 1) & 1U) | ((bits & 1U) << 1) | (bits & 4U);
    return 0;
iram:
    memw();
    *output = (MEMPROT_IRAM_PERMISSIONS >> shift) & 7U;
    return 0;
dram:
    memw();
    bits = (MEMPROT_DRAM_PERMISSIONS >> shift) & 3U;
    *output = 0;
    if ((bits & 1U) != 0)
        *output = 1;
    if ((bits & 2U) != 0)
        *output = bits;
    return 0;
}

/* Native entry: 0x42005570. */
/* Original function-byte SHA-256:
 * 066f1db6ef2ed8c6f5bac418730001ba34cca7dfb1f9051d19acd974fb8c9cb2. */
/*
 * esp_mprot_set_split_addr: configure one exact IRAM/DRAM/RTCFAST split line.
 * Invalid memory type returns 0xd001; a line not supported by that memory type
 * returns 0xd002. Global SRAM lines ignore core. IRAM accepts [0x40378000,
 * 0x403e0000); DRAM accepts [0x3fc88000,0x3fcf0000). Require 256-byte alignment.
 * Range/alignment failures convert HAL 2/3 to 0xd003/0xd004 before any write.
 *
 * Build seven 2-bit SRAM-bank categories from the firmware's default/high-limit
 * tables: lower banks 0, containing bank 2, higher banks 3. The native copies
 * all seven high limits to stack again on each iteration. For DRAM subtract
 * 0x6f0000 from the IRAM table limit. Pack categories into bits 0..13, address
 * bits 8..15 into bits 14..21, and zero upper bits. MEMW/write the selected
 * complete constraint register; no readback or hardware-lock check.
 *
 * RTCFAST supports main line only, first requires configured CPU membership
 * (0xd008), then range [0x600fe000,0x60100000), 4-byte alignment and physical
 * core 0/1, in that order. Invalid physical core converts HAL 7 to -1. Two
 * MEMW/read/MEMW/write RMWs first clear low 11 address bits, then reread and
 * add shifted address bits that are still clear. Preserve this native XOR/AND
 * expression: a bit set again between the two reads is retained. No atomic
 * update, interrupt masking or rollback. Return converted HAL success.
 */
int esp_mprot_set_split_addr(unsigned int memory_type,unsigned int line_type,
    const void *line_address,int core)
{
    unsigned int address = (uintptr_t)line_address;
    volatile unsigned int *constraint;
    unsigned int table_bias = 0;
    if (memory_type == MEMPROT_IRAM) {
        switch (line_type) {
        case MEMPROT_SPLIT_MAIN:
            constraint = &MEMPROT_SPLIT_REGISTERS->main;
            break;
        case MEMPROT_SPLIT_IRAM0:
            constraint = &MEMPROT_SPLIT_REGISTERS->iram[0];
            break;
        case MEMPROT_SPLIT_IRAM1:
            constraint = &MEMPROT_SPLIT_REGISTERS->iram[1];
            break;
        default: return 0xd002;
        }
        if (address - 0x40378000U >= 0x68000U)
            return esp_mprot_ll_err_to_esp_err(2);
    } else if (memory_type == MEMPROT_DRAM) {
        switch (line_type) {
        case MEMPROT_SPLIT_DRAM0:
            constraint = &MEMPROT_SPLIT_REGISTERS->dram[0];
            break;
        case MEMPROT_SPLIT_DRAM1:
            constraint = &MEMPROT_SPLIT_REGISTERS->dram[1];
            break;
        default: return 0xd002;
        }
        if (address - 0x3fc88000U >= 0x68000U)
            return esp_mprot_ll_err_to_esp_err(2);
        table_bias = 0x6f0000U;
    } else if (memory_type == MEMPROT_RTCFAST) {
        if (line_type != MEMPROT_SPLIT_MAIN)
            return 0xd002;
        if (!memprot_core_selected(core))
            return 0xd008;
        if (address - 0x600fe000U >= 0x2000U)
            return esp_mprot_ll_err_to_esp_err(2);
        if ((address & 3U) != 0)
            return esp_mprot_ll_err_to_esp_err(3);
        if ((unsigned int)core > 1)
            return esp_mprot_ll_err_to_esp_err(7);
        volatile unsigned int *split = core == 0 ?
            &MEMPROT_RTC_REGION0->split_address :
            &MEMPROT_RTC_REGION1->split_address;
        memw();
        unsigned int word = *split;
        memw();
        *split = word & ~0x7ffU;
        memw();
        word = *split;
        memw();
        *split = word ^ (((address >> 2) & (word ^ 0x7ffU)) & 0x7ffU);
        return esp_mprot_ll_err_to_esp_err(0);
    } else
        return 0xd001;
    if ((address & 0xffU) != 0)
        return esp_mprot_ll_err_to_esp_err(3);
    MemoryProtectionSplitWorkspace workspace;
    memcpy(workspace.categories,MEMPROT_SPLIT_DEFAULTS,28);
    for (unsigned int bank=0;bank<7;bank++) {
        memcpy(workspace.high_limits,MEMPROT_SPLIT_HIGH_LIMITS,28);
        unsigned int high = workspace.high_limits[bank] - table_bias;
        if (address <= high) {
            workspace.categories[bank] = 2;
            break;
        }
        workspace.categories[bank] = 0;
    }
    unsigned int encoded = ((address >> 8) & 0xffU) << 14;
    for (unsigned int bank=0;bank<7;bank++)
        encoded |= (workspace.categories[bank] & 3U) << (2 * bank);
    memw();
    *constraint = encoded;
    return esp_mprot_ll_err_to_esp_err(0);
}
