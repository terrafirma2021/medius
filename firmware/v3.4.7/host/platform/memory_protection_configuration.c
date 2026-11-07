/* Medius v3.4.7 host: boot-time ESP32-S3 memory-protection setup. */
#include "../include/types.h"

/* Readable reconstruction utilities for inlined native operations, not extra
 * native entries. Preserve MMIO barriers and ROM-copy boundaries explicitly. */
#define MEMPROT_TRY(operation) do {int error=(operation); if (error!=0) return error;} while (0)

static inline __attribute__((always_inline)) unsigned int memprot_debug_status(void)
{
    unsigned int value;
    __asm__ volatile ("rer %0,%1" : "=a"(value) : "a"(0x10200cU) : "memory");
    return value;
}

static inline __attribute__((always_inline,noreturn)) void memprot_fault_reset(void)
{
    software_reset(); /* ROM 0x400006d8. */
    __asm__ volatile ("ill.n" ::: "memory");
    __builtin_unreachable();
}

static inline __attribute__((always_inline)) unsigned int memprot_split_word(
    MemoryProtectionSplitWorkspace *workspace,unsigned int address,unsigned int bias)
{
    memcpy(workspace->categories,MEMPROT_SPLIT_DEFAULTS,28);
    for (unsigned int bank=0;bank<7;bank++) {
        memcpy(workspace->high_limits,MEMPROT_SPLIT_HIGH_LIMITS,28);
        if (address <= workspace->high_limits[bank]-bias) {
            workspace->categories[bank]=2;
            break;
        }
        workspace->categories[bank]=0;
    }
    unsigned int word=((address >> 8) & 0xffU) << 14;
    for (unsigned int bank=0;bank<7;bank++)
        word |= (workspace->categories[bank] & 3U) << (2*bank);
    return word;
}

static inline __attribute__((always_inline)) void memprot_write_permission_field(
    volatile unsigned int *reg,unsigned int mask,unsigned int bits)
{
    memw();
    unsigned int word=*reg;
    memw();
    *reg=(word & ~mask) | bits;
}

static inline __attribute__((always_inline)) int memprot_route_violation(
    unsigned int memory_type,int core)
{
    unsigned int source;
    int hal_error;
    esp_intr_disable_source(25);
    if (core==0) {
        source=memory_type==1 ? 85 : memory_type==2 ? 86 : 87;
        hal_error=0;
    } else if (core==1) {
        source=memory_type==1 ? 89 : memory_type==2 ? 90 : 91;
        hal_error=0;
    } else {
        source=99;
        hal_error=memory_type==1 ? -1 : 7;
    }
    MEMPROT_TRY(esp_mprot_ll_err_to_esp_err(hal_error));
    intr_matrix_set(core,source,25);
    esp_intr_enable_source(25);
    return 0;
}

/* Native entry: 0x42006244. */
/* Original function-byte SHA-256:
 * 07184a0c7e7f968263ed34d248dd1d51c0caf959781049398fbfd65c21f94604. */
/*
 * esp_mprot_set_prot: configure ESP32-S3 memory protection at boot.
 *
 * Read debugger external register 0x10200c bit 0 first. When attached, three
 * additional reads must all remain set; otherwise ROM software_reset followed
 * by ILL. A stable debugger returns 0 before parameter checks or configuration
 * writes. Otherwise reject NULL (0x102), zero memory mask (0x101), CPU count
 * outside 1..2 or requested CPUs absent from the PREVIOUS saved list (0xd008).
 * Duplicate requested CPUs and unknown nonzero mask bits are accepted.
 *
 * Cache count/mask; disable selected monitors, optionally route their violation
 * sources to CPU interrupt 25, set common SRAM split lines and permissions,
 * set per-core RTCFAST split to 0x600fe000 with low RX/high RW, clear pending
 * monitor interrupts and enable monitoring, then optionally lock all settings.
 * Input core IDs and flag bytes are reloaded where the native routine reads
 * them. Each failed API returns immediately with prior MMIO mutations retained;
 * interrupt routing failure can leave interrupt 25 disabled. No rollback.
 *
 * For any SRAM selection, verify ALL five SRAM split words and all eight
 * IRAM/DRAM area permissions, even when only one memory type was configured.
 * Verify enabled monitors and requested locks for selected IRAM/DRAM only;
 * RTCFAST and cache permissions are not read back here. Mismatch prints the
 * exact fatal diagnostic (register mismatch rereads hardware for printing)
 * then aborts. Configuration is copied as 24 raw bytes ONLY after success.
 * A mask containing only unknown bits simply copies configuration. No runtime
 * software lock, pointer ownership check or timing guarantee.
 */
int esp_mprot_set_prot(const BootMemoryProtectionConfiguration *configuration)
{
    if ((memprot_debug_status() & 1U) != 0) {
        for (unsigned int check=0;check<3;check++)
            if ((memprot_debug_status() & 1U) == 0)
                memprot_fault_reset();
        return 0;
    }
    if (configuration==NULL)
        return 0x102;
    const volatile BootMemoryProtectionConfiguration *input=configuration;
    unsigned int mask=input->memory_type_mask;
    if (mask==0)
        return 0x101;
    unsigned int count=input->target_cpu_count;
    if (count-1U>=2)
        return 0xd008;
    unsigned int old_count=MEMPROT_CONFIGURATION.target_cpu_count;
    if (old_count==0)
        return 0xd008;
    int old_core0=MEMPROT_CONFIGURATION.target_cpu[0];
    int old_core1=MEMPROT_CONFIGURATION.target_cpu[1];
    for (unsigned int index=0;index<count;index++) {
        int core=input->target_cpu[index];
        if (core!=old_core0 && (old_count==1 || core!=old_core1))
            return 0xd008;
    }
    bool use_iram=(mask & MEMPROT_IRAM)!=0;
    bool use_dram=(mask & MEMPROT_DRAM)!=0;
    bool use_rtc=(mask & MEMPROT_RTCFAST)!=0;
    if ((mask & 7U)==0)
        goto save_configuration;
    for (unsigned int type=1;type<=4;type<<=1)
        if ((mask & type)!=0)
            for (unsigned int index=0;index<count;index++)
                MEMPROT_TRY(esp_mprot_set_monitor_en(type,0,input->target_cpu[index]));
    if (input->invoke_panic_handler!=0)
        for (unsigned int type=1;type<=4;type<<=1)
            if ((mask & type)!=0)
                for (unsigned int index=0;index<count;index++)
                    MEMPROT_TRY(memprot_route_violation(type,input->target_cpu[index]));
    unsigned int split=0;
    MemoryProtectionSplitWorkspace workspace;
    if (use_iram || use_dram) {
        split=(uintptr_t)input->split_address;
        if (split==0)
            split=MEMPROT_DEFAULT_SRAM_SPLIT;
        if (split-0x40378000U>=0x68000U)
            return esp_mprot_ll_err_to_esp_err(2);
        if ((split & 0xffU)!=0)
            return esp_mprot_ll_err_to_esp_err(3);
        unsigned int encoded=memprot_split_word(&workspace,split,0);
        memw();
        MEMPROT_SPLIT_REGISTERS->iram[1]=encoded;
        MEMPROT_TRY(esp_mprot_ll_err_to_esp_err(0));
        MEMPROT_TRY(esp_mprot_set_split_addr(1,2,(const void *)(uintptr_t)split,-1));
        MEMPROT_TRY(esp_mprot_set_split_addr(1,1,(const void *)(uintptr_t)split,-1));
        MEMPROT_TRY(esp_mprot_set_split_addr(2,8,(const void *)(uintptr_t)(split-0x6f0000U),-1));
        MEMPROT_TRY(esp_mprot_set_split_addr(2,16,(const void *)(uintptr_t)(split-0x6f0000U),-1));
    }
    if (use_iram) {
        memprot_write_permission_field(&MEMPROT_IRAM_PERMISSIONS,7U<<12,0);
        memprot_write_permission_field(&MEMPROT_IRAM_PERMISSIONS,7U<<15,5U<<15);
        memprot_write_permission_field(&MEMPROT_IRAM_PERMISSIONS,7U,5);
        memprot_write_permission_field(&MEMPROT_IRAM_PERMISSIONS,7U<<3,5U<<3);
        memprot_write_permission_field(&MEMPROT_IRAM_PERMISSIONS,7U<<6,5U<<6);
        memprot_write_permission_field(&MEMPROT_IRAM_PERMISSIONS,7U<<9,0);
    }
    if (use_dram) {
        memprot_write_permission_field(&MEMPROT_DRAM_PERMISSIONS,3U,1);
        memprot_write_permission_field(&MEMPROT_DRAM_PERMISSIONS,3U<<2,3U<<2);
        memprot_write_permission_field(&MEMPROT_DRAM_PERMISSIONS,3U<<4,3U<<4);
        memprot_write_permission_field(&MEMPROT_DRAM_PERMISSIONS,3U<<6,3U<<6);
    }
    if (use_rtc)
        for (unsigned int index=0;index<count;index++) {
            MEMPROT_TRY(esp_mprot_set_split_addr(4,1,(const void *)0x600fe000U,input->target_cpu[index]));
            MEMPROT_TRY(esp_mprot_set_pms_area(0x100,5,input->target_cpu[index]));
            MEMPROT_TRY(esp_mprot_set_pms_area(0x200,3,input->target_cpu[index]));
        }
    for (unsigned int type=1;type<=4;type<<=1)
        if ((mask & type)!=0)
            for (unsigned int index=0;index<count;index++) {
                MEMPROT_TRY(esp_mprot_monitor_clear_intr(type,input->target_cpu[index]));
                MEMPROT_TRY(esp_mprot_set_monitor_en(type,1,input->target_cpu[index]));
            }
    if (input->lock_feature!=0) {
        if (use_iram) {
            memw(); MEMPROT_SPLIT_LOCK=1;
            int core=input->target_cpu[0];
            memw(); MEMPROT_IRAM_PMS_LOCK=1;
            MEMPROT_TRY(esp_mprot_set_monitor_lock(1,core));
            if (count==2)
                MEMPROT_TRY(esp_mprot_set_monitor_lock(1,input->target_cpu[1]));
        }
        if (use_dram) {
            memw(); MEMPROT_SPLIT_LOCK=1;
            int core=input->target_cpu[0];
            memw(); MEMPROT_DRAM_PMS_LOCK=1;
            MEMPROT_TRY(esp_mprot_set_monitor_lock(2,core));
            if (count==2)
                MEMPROT_TRY(esp_mprot_set_monitor_lock(2,input->target_cpu[1]));
        }
        if (use_rtc)
            for (unsigned int index=0;index<count;index++) {
                MEMPROT_TRY(esp_mprot_set_pms_lock(4,input->target_cpu[index]));
                MEMPROT_TRY(esp_mprot_set_monitor_lock(4,input->target_cpu[index]));
            }
    }
    if (use_iram || use_dram) {
        unsigned int expected=memprot_split_word(&workspace,split,0);
        memw();
        unsigned int main=MEMPROT_SPLIT_REGISTERS->main;
        if (main!=expected) {
            memw(); unsigned int stored=MEMPROT_SPLIT_REGISTERS->main;
            ets_printf("Fatal error: Main I/D split line configuration corrupted (expected 0x%08lX, stored 0x%08lX)\n",expected,stored); abort();
        }
        memw(); unsigned int iram0=MEMPROT_SPLIT_REGISTERS->iram[0];
        if (iram0!=main) {
            memw(); unsigned int stored=MEMPROT_SPLIT_REGISTERS->iram[0];
            ets_printf("Fatal error: IRAM0 I_0 split line configuration corrupted (expected 0x%08lX, stored 0x%08lX)\n",main,stored); abort();
        }
        memw(); unsigned int iram1=MEMPROT_SPLIT_REGISTERS->iram[1];
        if (iram1!=iram0) {
            memw(); unsigned int stored=MEMPROT_SPLIT_REGISTERS->iram[1];
            ets_printf("Fatal error: IRAM0 I_1 split line configuration corrupted (expected 0x%08lX, stored 0x%08lX)\n",iram0,stored); abort();
        }
        expected=memprot_split_word(&workspace,split-0x6f0000U,0x6f0000U);
        memw(); unsigned int dram0=MEMPROT_SPLIT_REGISTERS->dram[0];
        if (dram0!=expected) {
            memw(); unsigned int stored=MEMPROT_SPLIT_REGISTERS->dram[0];
            ets_printf("Fatal error: DRAM0 D_0 split line configuration corrupted (expected 0x%08lX, stored 0x%08lX)\n",expected,stored); abort();
        }
        memw(); unsigned int dram1=MEMPROT_SPLIT_REGISTERS->dram[1];
        if (dram1!=dram0) {
            memw(); unsigned int stored=MEMPROT_SPLIT_REGISTERS->dram[1];
            ets_printf("Fatal error: DRAM0 D_1 split line configuration corrupted (expected 0x%08lX, stored 0x%08lX)\n",dram0,stored); abort();
        }
        unsigned int permissions;
        MEMPROT_TRY(esp_mprot_get_pms_area(1,&permissions,-1));
        if (permissions!=5) {ets_printf("Fatal error: IRAM0 PMS AREA_0 configuration corrupted (expected 0x%08lX, stored 0x%08lX)\n",5,permissions); abort();}
        MEMPROT_TRY(esp_mprot_get_pms_area(2,&permissions,-1));
        if (permissions!=5) {ets_printf("Fatal error: IRAM0 PMS AREA_1 configuration corrupted (expected 0x%08lX, stored 0x%08lX)\n",5,permissions); abort();}
        MEMPROT_TRY(esp_mprot_get_pms_area(4,&permissions,-1));
        if (permissions!=5) {ets_printf("Fatal error: IRAM0 PMS AREA_2 configuration corrupted (expected 0x%08lX, stored 0x%08lX)\n",5,permissions); abort();}
        MEMPROT_TRY(esp_mprot_get_pms_area(8,&permissions,-1));
        if (permissions!=0) {ets_printf("Fatal error: IRAM0 PMS AREA_3 configuration corrupted (expected 0x%08lX, stored 0x%08lX)\n",0,permissions); abort();}
        MEMPROT_TRY(esp_mprot_get_pms_area(16,&permissions,-1));
        if (permissions!=1) {ets_printf("Fatal error: DRAM0 PMS AREA_0 configuration corrupted (expected 0x%08lX, stored 0x%08lX)\n",1,permissions); abort();}
        MEMPROT_TRY(esp_mprot_get_pms_area(32,&permissions,-1));
        if (permissions!=3) {ets_printf("Fatal error: DRAM0 PMS AREA_1 configuration corrupted (expected 0x%08lX, stored 0x%08lX)\n",3,permissions); abort();}
        MEMPROT_TRY(esp_mprot_get_pms_area(64,&permissions,-1));
        if (permissions!=3) {ets_printf("Fatal error: DRAM0 PMS AREA_2 configuration corrupted (expected 0x%08lX, stored 0x%08lX)\n",3,permissions); abort();}
        MEMPROT_TRY(esp_mprot_get_pms_area(128,&permissions,-1));
        if (permissions!=3) {ets_printf("Fatal error: DRAM0 PMS AREA_3 configuration corrupted (expected 0x%08lX, stored 0x%08lX)\n",3,permissions); abort();}
        unsigned char enabled;
        if (use_iram)
            for (unsigned int index=0;index<count;index++) {
                MEMPROT_TRY(esp_mprot_get_monitor_en(1,&enabled,input->target_cpu[index]));
                if (enabled==0) {ets_printf("Fatal error: IRAM0 PMS configuration corrupted (memory protection not enabled on core %d)\n",input->target_cpu[index]); abort();}
            }
        if (use_dram)
            for (unsigned int index=0;index<count;index++) {
                MEMPROT_TRY(esp_mprot_get_monitor_en(2,&enabled,input->target_cpu[index]));
                if (enabled==0) {ets_printf("Fatal error: DRAM0 PMS configuration corrupted (memory protection not enabled on core %d)\n",input->target_cpu[index]); abort();}
            }
        if (input->lock_feature!=0) {
            unsigned char locked;
            if (use_iram) {
                memw(); unsigned int word=MEMPROT_SPLIT_LOCK;
                if (word!=1) {ets_printf("Fatal error: IRAM0 PMS configuration corrupted (memory protection not locked - split address lock)\n"); abort();}
                memw(); word=MEMPROT_IRAM_PMS_LOCK;
                locked=word==1;
                if (word!=1) {ets_printf("Fatal error: IRAM0 PMS configuration corrupted (memory protection not locked - global PMS lock)\n"); abort();}
                for (unsigned int index=0;index<count;index++) {
                    MEMPROT_TRY(esp_mprot_get_monitor_lock(1,&locked,input->target_cpu[index]));
                    if (locked==0) {ets_printf("Fatal error: IRAM0 PMS configuration corrupted (memory protection not locked - monitor lock on core %d)\n",input->target_cpu[index]); abort();}
                }
            }
            if (use_dram) {
                memw(); unsigned int word=MEMPROT_SPLIT_LOCK;
                if (word!=1) {ets_printf("Fatal error: DRAM0 PMS configuration corrupted (memory protection not locked - split address lock)\n"); abort();}
                memw(); word=MEMPROT_DRAM_PMS_LOCK;
                locked=word==1;
                if (word!=1) {ets_printf("Fatal error: DRAM0 PMS configuration corrupted (memory protection not locked - global PMS lock)\n"); abort();}
                for (unsigned int index=0;index<count;index++) {
                    MEMPROT_TRY(esp_mprot_get_monitor_lock(2,&locked,input->target_cpu[index]));
                    if (locked==0) {ets_printf("Fatal error: DRAM0 PMS configuration corrupted (memory protection not locked - monitor lock on core %d)\n",input->target_cpu[index]); abort();}
                }
            }
        }
    }
save_configuration:
    memcpy((void *)&MEMPROT_CONFIGURATION,configuration,24);
    return 0;
}
