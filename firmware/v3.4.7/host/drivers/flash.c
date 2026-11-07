/* Medius v3.4.7 host — drivers/flash.c.
 * Recovered C and native assembly, grouped for source navigation.
 * Original entry addresses, firmware-byte hashes and function comments follow.
 */

#include "../include/types.h"

/* Native entry: 0x4037bf40. */
/*
 * Medius v3.4.7 — host application; 0x4037bf40.
 *
 * Asserts transmit/receive lengths <=32 bits, saves SPI1 CTRL/USER/USER1/USER2, configures
 * an8-bit command plus optional address/dummy/data phases and starts USR. Receive mode adds the
 * ROM SPI1 dummy correction. Uses at most four bytes of data through W0, polls the entire CMD
 * word until zero without timeout, restores those four registers and returns the masked response.
 * Lengths are converted to byte copies by division by8; no byte-alignment check, caller lock or
 * general error status is supplied.
 *
 * Calls: __assert_func, memcpy.
 *
 * Called by: bootloader_read_flash_id, bootloader_flash_reset_chip.
 *
 * Original function-byte SHA-256:
 * 2425d026cb56cb42a6969d96a2399e88e85301c66b529e01334ba852833cde06.
 */

/* Reference: ESP-IDF v5.4.4
   components/bootloader_support/bootloader_flash/src/bootloader_flash.c. */

/*
 * command: Eight-bit SPI instruction byte; command phase is configured for8 bits.
 * address_bits: Address-phase width;0 disables it and32 selects four-byte mode. Caller supplies a
 *   supported width.
 * address: Raw32-bit address register value passed unchanged.
 * dummy_bits: Base dummy-clock count; receive operations add the ROM SPI1 correction.
 * mosi_bits: Transmit width in bits,0..32; assertion rejects larger values. Whole-byte copies use
 *   floor(bits/8).
 * mosi_data: Up to32 transmit bits, staged through W0 when the compiled byte-copy path applies.
 * miso_bits: Receive width in bits,0..32; assertion rejects larger values.
 * Returns: Masked receive word; no separate transport status.
 * Requirements/effects: Caller owns SPI1/cache exclusion and valid phase widths. Saves/restores
 *   CTRL/USER/USER1/USER2, programs command/address/dummy/data phases and polls the entire CMD
 *   word to0 without timeout. Two fenced volatile RAM words retain native command/width
 *   bitfield updates. Dummy enable uses the full sum, while its cycle field uses the low byte.
 *   Transmit widths1..7 leave W0 untouched; response copies floor(bits/8) bytes and masks the
 *   final word. Non-byte widths are not independently rejected.
 */

unsigned int bootloader_flash_execute_command_common(unsigned char command,
    unsigned int address_bits,unsigned int address,unsigned char dummy_bits,
    unsigned char mosi_bits,unsigned int mosi_data,unsigned char miso_bits)
{
    unsigned int transmit_bits = mosi_bits;
    unsigned int receive_bits = miso_bits;
    unsigned int transmit_word = mosi_data;
    if (transmit_bits > 32U || receive_bits > 32U)
        __assert_func(0,0,0,0);

    memw();
    unsigned int saved_control = MSPI1->ctrl;
    memw();
    unsigned int saved_user = MSPI1->user;
    memw();
    unsigned int saved_user1 = MSPI1->user1;
    memw();
    unsigned int saved_user2 = MSPI1->user2;
    memw();
    MSPI1->ctrl = 0;
    memw();
    unsigned int configuration = MSPI1->ctrl;
    memw();
    MSPI1->ctrl = configuration | 0x00200000U;
    memw();
    configuration = MSPI1->user;
    memw();
    MSPI1->user = configuration | 0x80000000U;

    /* The native bitfield updates include fenced RAM temporaries. */
    memw();
    configuration = MSPI1->user2;
    memw();
    volatile unsigned int command_configuration = configuration;
    memw();
    unsigned int previous_command = command_configuration;
    memw();
    command_configuration = (previous_command & 0xffff0000U) | command;
    memw();
    unsigned int updated_command = command_configuration;
    memw();
    MSPI1->user2 = updated_command;
    memw();
    configuration = MSPI1->user2;
    memw();
    volatile unsigned int command_width_configuration = configuration;
    memw();
    unsigned int previous_width = command_width_configuration;
    memw();
    command_width_configuration = (previous_width & 0x0fffffffU) | 0x70000000U;
    memw();
    unsigned int updated_width = command_width_configuration;
    memw();
    MSPI1->user2 = updated_width;

    memw();
    configuration = MSPI1->cache_fctrl;
    memw();
    MSPI1->cache_fctrl = (configuration & ~2U) | ((unsigned int)(address_bits == 32U) << 1);
    memw();
    configuration = MSPI1->user1;
    memw();
    MSPI1->user1 = (configuration & 0x03ffffffU) | ((address_bits - 1U) << 26);
    memw();
    configuration = MSPI1->user;
    memw();
    MSPI1->user = (configuration & ~0x40000000U) | ((unsigned int)(address_bits != 0) << 30);
    memw();
    MSPI1->addr = address;

    unsigned int dummy_total = dummy_bits;
    unsigned int dummy_cycles = dummy_bits;
    if (receive_bits != 0) {
        RomFlashLegacy *legacy = ROM_FLASH_LEGACY;
        unsigned char correction = *(const volatile unsigned char *)&legacy->dummy_len_plus[1];
        dummy_total += correction;
        dummy_cycles = (unsigned char)dummy_total;
    }
    memw();
    configuration = MSPI1->user;
    memw();
    MSPI1->user = (configuration & ~0x20000000U) | ((unsigned int)(dummy_total != 0) << 29);
    memw();
    configuration = MSPI1->user1;
    memw();
    MSPI1->user1 = (configuration & ~0x3fU) | ((dummy_cycles - 1U) & 0x3fU);
    memw();
    configuration = MSPI1->user;
    memw();
    MSPI1->user = (configuration & ~0x08000000U) | ((unsigned int)(transmit_bits != 0) << 27);
    memw();
    configuration = MSPI1->mosi_dlen;
    if (transmit_bits == 0) {
        memw();
        MSPI1->mosi_dlen = configuration & ~0x3ffU;
    } else {
        memw();
        MSPI1->mosi_dlen = (configuration & ~0x3ffU) | ((transmit_bits - 1U) & 0x3ffU);
        unsigned int transmit_bytes = transmit_bits >> 3;
        if (((transmit_bytes + 3U) >> 2) == 1U) {
            unsigned int staged_word = 0;
            memcpy(&staged_word,&transmit_word,transmit_bytes);
            memw();
            MSPI1->data[0] = staged_word;
        }
    }
    memw();
    configuration = MSPI1->user;
    memw();
    MSPI1->user = (configuration & ~0x10000000U) | ((unsigned int)(receive_bits != 0) << 28);
    memw();
    configuration = MSPI1->miso_dlen;
    unsigned int receive_length_field = receive_bits == 0 ? 0 : (receive_bits - 1U) & 0x3ffU;
    memw();
    MSPI1->miso_dlen = (configuration & ~0x3ffU) | receive_length_field;
    memw();
    configuration = MSPI1->cmd;
    memw();
    MSPI1->cmd = configuration | 0x00040000U;
    unsigned int command_status;
    do {
        memw();
        command_status = MSPI1->cmd;
    } while (command_status != 0);
    memw();
    MSPI1->ctrl = saved_control;
    memw();
    MSPI1->user = saved_user;
    memw();
    MSPI1->user1 = saved_user1;
    unsigned int response = command_status;
    memw();
    MSPI1->user2 = saved_user2;

    unsigned int receive_bytes = receive_bits >> 3;
    if ((receive_bytes & 3U) == 0) {
        /* Native zero/four-byte copy uses W0 directly without an extra fence. */
        memcpy(&response,(const void *)&MSPI1->data[0],receive_bytes);
    } else {
        memw();
        unsigned int received_word = MSPI1->data[0];
        memcpy(&response,&received_word,receive_bytes);
    }
    if (receive_bits != 32U)
        response &= ~(0xffffffffU << receive_bits);
    return response;
}

/* Native entry: 0x4037c1a0. */
/*
 * Medius v3.4.7 — host application; 0x4037c1a0.
 *
 * Issues JEDEC read-ID command0x9f with24 receive bits and no address/transmit payload, then
 * swaps response bytes0 and2 into vendor/type/capacity order. Returns only24 bits and no separate
 * transport status.
 *
 * Calls: bootloader_flash_execute_command_common.
 *
 * Called by: flash_update_rom_chip_id.
 *
 * Original function-byte SHA-256:
 * abe17a50c59e042ddded46ac2e53911615f870f20dc029512aed294f3dd7d4da.
 */

/* Reference: ESP-IDF v5.4.4
   components/bootloader_support/bootloader_flash/src/bootloader_flash.c. */

/*
 * Returns: Normalized24-bit JEDEC identifier with vendor/type/capacity byte order.
 * Requirements/effects: Issues command0x9f with24 receive bits through the shared command helper.
 *   Caller supplies exclusion; this wrapper exposes no independent status.
 */

unsigned int bootloader_read_flash_id(void)
{
  unsigned int response = bootloader_flash_execute_command_common(0x9f, 0, 0, 0, 0, 0, 24);
  return ((response & 0xffU) << 16) | (response & 0xff00U) | ((response >> 16) & 0xffU);
}

/* Native entry: 0x4037c1d8. */
/*
 * Medius v3.4.7 — host application; 0x4037c1d8.
 *
 * Pulses CTRL2 sync-reset low/high/low on SPI1 then SPI0, sends command0x05 with no data phases
 * to idle the host, and checks SPI1 CMD. Returns -1 if still busy; otherwise sends reset-
 * enable0x66 and reset0x99 and returns0. It ignores command responses and supplies no independent
 * lock or timeout.
 *
 * Calls: bootloader_flash_execute_command_common.
 *
 * Called by: rtc_brownout_isr_handler.
 *
 * Original function-byte SHA-256:
 * 47fd669454d88a1b35e1ebfe8f25eb643ee4aa50628c7a7a2965e71ef81db3fe.
 */

/* Reference: ESP-IDF v5.4.4
   components/bootloader_support/bootloader_flash/src/bootloader_flash.c. */

/*
 * Returns: 0 after issuing reset-enable/reset; -1 if SPI1 CMD remains busy after the initial idle
 *   command.
 * Requirements/effects: Pulses SPI1 and SPI0 CTRL2 reset, uses commands0x05/0x66/0x99 and ignores
 *   command replies. Shared helper polling is unbounded and no independent lock is taken.
 */

int bootloader_flash_reset_chip(void)
{
  unsigned int control2_value;
  unsigned int command_status;

  memw();
  control2_value = MSPI1->ctrl2;
  memw();
  MSPI1->ctrl2 = control2_value & 0x7fffffff;
  memw();
  control2_value = MSPI0->ctrl2;
  memw();
  MSPI0->ctrl2 = control2_value & 0x7fffffff;
  memw();
  control2_value = MSPI1->ctrl2;
  memw();
  MSPI1->ctrl2 = control2_value | 0x80000000;
  memw();
  control2_value = MSPI0->ctrl2;
  memw();
  MSPI0->ctrl2 = control2_value | 0x80000000;
  memw();
  control2_value = MSPI1->ctrl2;
  memw();
  MSPI1->ctrl2 = control2_value & 0x7fffffff;
  memw();
  control2_value = MSPI0->ctrl2;
  memw();
  MSPI0->ctrl2 = control2_value & 0x7fffffff;
  bootloader_flash_execute_command_common(0x05,0,0,0,0,0,0);
  memw();
  command_status = MSPI1->cmd;
  if (command_status != 0)
    return -1;
  bootloader_flash_execute_command_common(0x66,0,0,0,0,0,0);
  bootloader_flash_execute_command_common(0x99,0,0,0,0,0,0);
  return 0;
}

/* Native entry: 0x4037c44c. */
/*
 * Medius v3.4.7 — host application; 0x4037c44c.
 *
 * Compiled S3 specialization delegates to external-memory-cache suspend. SDK CPU/save-state
 * parameters are not consumed in this body; the cache HAL owns the actual saved state. It neither
 * acquires the flash mutex nor masks interrupts on its own.
 *
 * Calls: esp_cache_suspend_ext_mem_cache.
 *
 * Called by: spi_flash_disable_interrupts_caches_and_other_cpu.
 *
 * Original function-byte SHA-256:
 * 2bf4833d054baf31888d50b97edbb025e593cd4b0a57ae7228e475f4d7d9ede2.
 */

/* Reference: ESP-IDF v5.4.4 components/spi_flash/cache_utils.c. */

/*
 * Returns: Nothing.
 * Requirements/effects: Compiled no-argument S3 specialization delegates cache suspension. Caller
 *   already supplies flash exclusion and interrupt/scheduler safety.
 */

void spi_flash_disable_cache(void)

{
  esp_cache_suspend_ext_mem_cache();
  return;
}

/* Native entry: 0x4037c45c. */
/*
 * Medius v3.4.7 — host application; 0x4037c45c.
 *
 * Compiled S3 specialization delegates to external-memory-cache resume. It consumes no CPU or
 * saved-state parameter and does not restore interrupt masks or scheduling by itself.
 *
 * Calls: esp_cache_resume_ext_mem_cache.
 *
 * Called by: spi_flash_op_block_func, spi_flash_enable_interrupts_caches_and_other_cpu, FUN_4037c5a8.
 *
 * Original function-byte SHA-256:
 * 2bf4833d054baf31888d50b97edbb025e593cd4b0a57ae7228e475f4d7d9ede2.
 */

/* Reference: ESP-IDF v5.4.4 components/spi_flash/cache_utils.c. */

/*
 * Returns: Nothing.
 * Requirements/effects: Restores external-memory caches from HAL state; caller handles pairing,
 *   interrupts and scheduling.
 */

void spi_flash_restore_cache(void)

{
  esp_cache_resume_ext_mem_cache();
  return;
}

/* Native entry: 0x4037c46c. */
/*
 * Medius v3.4.7 — host application; 0x4037c46c.
 *
 * Peer-CPU IPC callback: suspends scheduling, masks non-IRAM interrupts, clears completion and
 * publishes ready, then polls volatile completion. Restores caches and interrupts before resuming
 * scheduling. The compiled S3 cache restore consumes no CPU/save-state argument. This valid
 * return path was lost in the old nonvolatile export.
 *
 * Calls: esp_intr_noniram_disable, esp_intr_noniram_enable, spi_flash_restore_cache, vTaskSuspendAll, xTaskResumeAll.
 *
 * Original function-byte SHA-256:
 * 3c0259942f4d700cbafe34af5c2b68d6bff5fed0fb01feeb9c216ca82374fbac.
 */

/* Reference: ESP-IDF v5.4.4 components/spi_flash/cache_utils.c. Volatile global data settings fix
   the loop centrally in the ESP32-S3 Ghidra profile; the restored return is present in the native
   instructions. */

/*
 * unused_cpu_argument: Unused IPC context; CPU ownership is not read from this pointer.
 * Returns: Nothing after the volatile completion handshake.
 * Requirements/effects: Peer-CPU IPC context. Suspends scheduling, masks non-IRAM interrupts,
 *   publishes readiness and waits without timeout. Restores cache/interrupt state before scheduler
 *   resume; caller must eventually publish completion.
 */

void spi_flash_op_block_func(void *unused_cpu_argument)
{
    (void)unused_cpu_argument;
    vTaskSuspendAll();
    esp_intr_noniram_disable();
    memw();
    FLASH_OPERATION_COMPLETE = 0;
    memw();
    FLASH_OPERATION_PEER_READY = 1;
    do {
        memw();
    } while (FLASH_OPERATION_COMPLETE == 0);
    spi_flash_restore_cache();
    esp_intr_noniram_enable();
    xTaskResumeAll();
}

/* Native entry: 0x4037c4a8. */
/*
 * Medius v3.4.7 — host application; 0x4037c4a8.
 *
 * Asserts the current stack is internal DRAM or allowed RTC fast RAM, takes the recursive flash
 * mutex and records its CPU owner. Before scheduler startup permits CPU0 only. Otherwise suspends
 * local scheduling, retries nonblocking IPC until the peer accepts it, then polls the peer-ready
 * flag. Finally masks non-IRAM interrupts and disables the external-memory caches. No timeout is
 * supplied.
 *
 * Calls: esp_intr_noniram_disable, spi_flash_disable_cache, vTaskSuspendAll, xTaskResumeAll, xTaskGetSchedulerState, __assert_func,
 * esp_ipc_call_nonblocking, spi_flash_op_lock.
 *
 * Called by: flash_os_cache_disable.
 *
 * Original function-byte SHA-256:
 * 57e84a69030b24986b2d3a8fc23e52e1ba876ace6863a5c8bbeba5b05c8f7f9c.
 */

/* Reference: ESP-IDF v5.4.4 components/spi_flash/cache_utils.c. */

/*
 * Returns: Nothing on successful guard acquisition; invalid stack/owner/startup CPU asserts.
 * Requirements/effects: Requires internal DRAM or allowed RTC-fast stack. Takes initialized
 *   recursive flash mutex, enforces unowned state and uses peer IPC when scheduling is active.
 *   Scheduler status comparisons retain all32 bits. Readiness/completion are raw BYTE values;
 *   every nonzero byte releases its wait. Busy retries/polls have no timeout; pair with the
 *   enable guard on the same CPU.
 */

void spi_flash_disable_interrupts_caches_and_other_cpu(void)
{
    unsigned int stack_address;
    __asm__ volatile ("mov %0,a1" : "=a"(stack_address));
    int internal_stack = (stack_address - 0x3fc88000U < 0x78000U) ||
                         (stack_address - 0x600fe000U < 0x2000U);
    if (!internal_stack)
        __assert_func(0,0,0,0);
    spi_flash_op_lock();
    unsigned int cpu = (xtensa_read_prid() >> 13) & 1U;
    memw();
    int owner_cpu = FLASH_OPERATION_OWNER;
    if (owner_cpu != -1)
        __assert_func(0,0,0,0);
    memw();
    FLASH_OPERATION_OWNER = (int)cpu;
    int scheduler_state = xTaskGetSchedulerState();
    if (scheduler_state == 1) {
        if (cpu != 0)
            __assert_func(0,0,0,0);
    } else {
        for (;;) {
            vTaskSuspendAll();
            cpu = (xtensa_read_prid() >> 13) & 1U;
            unsigned int peer_cpu = cpu ^ 1U;
            memw();
            FLASH_OPERATION_OWNER = (int)cpu;
            memw();
            FLASH_OPERATION_PEER_READY = 0;
            int ipc_status = esp_ipc_call_nonblocking(peer_cpu,spi_flash_op_block_func,(void *)peer_cpu);
            if (ipc_status == 0)
                break;
            xTaskResumeAll();
        }
        do {
            memw();
        } while (FLASH_OPERATION_PEER_READY == 0);
    }
    esp_intr_noniram_disable();
    spi_flash_disable_cache();
}

/* Native entry: 0x4037c54c. */
/*
 * Medius v3.4.7 — host application; 0x4037c54c.
 *
 * Asserts exit occurs on the recorded CPU and, before scheduler startup, on CPU0. Clears the
 * owner marker, restores caches, signals completion when scheduling is active, restores non-IRAM
 * interrupts, resumes local scheduling and releases the recursive flash mutex. Interrupt
 * restoration precedes scheduling so it occurs on the owning CPU.
 *
 * Calls: esp_intr_noniram_enable, spi_flash_restore_cache, xTaskResumeAll, xTaskGetSchedulerState, __assert_func, spi_flash_op_unlock.
 *
 * Called by: flash_os_cache_enable.
 *
 * Original function-byte SHA-256:
 * 1b978b170cdfc5cef80067fb7ee057c24928372f49b74579a836ffcf2b00fe2f.
 */

/* Reference: ESP-IDF v5.4.4 components/spi_flash/cache_utils.c. */

/*
 * Returns: Nothing on successful release; mismatched owner/startup CPU asserts.
 * Requirements/effects: Matching disable guard must own the operation on this CPU. Clears
 *   ownership, restores caches, signals peer completion when applicable, restores interrupts
 *   before scheduling, and unlocks the recursive mutex. All three scheduler queries compare
 *   their full32-bit results independently; no low-byte normalization is applied.
 */

void spi_flash_enable_interrupts_caches_and_other_cpu(void)
{
    unsigned int cpu = (xtensa_read_prid() >> 13) & 1U;
    memw();
    int owner_cpu = FLASH_OPERATION_OWNER;
    if ((unsigned int)owner_cpu != cpu)
        __assert_func(0,0,0,0);
    int scheduler_state = xTaskGetSchedulerState();
    if (owner_cpu != 0 && scheduler_state == 1)
        __assert_func(0,0,0,0);
    memw();
    FLASH_OPERATION_OWNER = -1;
    spi_flash_restore_cache();
    scheduler_state = xTaskGetSchedulerState();
    if (scheduler_state != 1) {
        memw();
        FLASH_OPERATION_COMPLETE = 1;
    }
    esp_intr_noniram_enable();
    scheduler_state = xTaskGetSchedulerState();
    if (scheduler_state != 1)
        xTaskResumeAll();
    spi_flash_op_unlock();
}

/* Native entry: 0x4037d150. */
/*
 * Medius v3.4.7 — host application; 0x4037d150.
 *
 * Requests vTaskDelay(1) only when scheduler state is RUNNING (2), then records low 32 system
 * microseconds as acquired_since_us and returns 0. The output-status pointer is unused. One tick
 * is a scheduling request, not a guaranteed wall-clock delay; timestamp reset also occurs when no
 * delay was requested.
 *
 * Calls: esp_system_get_time, vTaskDelay, xTaskGetSchedulerState.
 *
 * Original function-byte SHA-256:
 * 04a4a8de7df62824e6507d5110dbba91d081ddacf5abe4e0d43494a83640ea7c.
 */

/* Reference: ESP-IDF v5.4.4 components/spi_flash/spi_flash_os_func_app.c. */

/*
 * context: Writable16-byte flash-OS context receiving the low32 acquired_since_us timestamp.
 * unused_status: Unused status-output pointer; not dereferenced, including when NULL.
 * Returns: 0.
 * Requirements/effects: Delays one tick only in RUNNING scheduler state2, then updates the
 *   timestamp even if no delay occurred. A tick delay is a scheduling request, not a wall-clock
 *   guarantee.
 */

int spi_flash_os_yield(FlashOsContext *context,unsigned int *unused_status)
{
    (void)unused_status;
    int scheduler_state = xTaskGetSchedulerState();
    if (scheduler_state == 2)
        vTaskDelay(1);
    unsigned int now_us = (unsigned int)esp_system_get_time();
    ((volatile FlashOsContext *)context)->acquired_since_us = now_us;
    return 0;
}

/* Native entry: 0x4037d168. */
/*
 * Medius v3.4.7 — host application; 0x4037d168.
 *
 * Asserts chip_status == 0. Uses unsigned low 32-us differences: a release interval >=1000us
 * resets acquired_since_us; otherwise an active interval >=20000us requests yield. Optionally
 * stores request 0/1 and returns TIMEOUT (0x107) or 0. This is a polled budget check, not a
 * software timer or an immediate task switch.
 *
 * Calls: esp_system_get_time, __assert_func.
 *
 * Original function-byte SHA-256:
 * 503cdf2ccc630e79d564e0752ba1f850e21b00d06c0658fbfceab3d1914631f9.
 */

/* Reference: ESP-IDF v5.4.4 components/spi_flash/spi_flash_os_func_app.c. */

/*
 * context: Writable flash-OS context holding low32 acquired/released microsecond timestamps.
 * chip_status: Must equal0; a nonzero value asserts without returning.
 * request: Optional uint32 output; receives1 when yielding is requested, otherwise0.
 * Returns: 0 when the active interval reaches20000us without a recent long release;
 *   otherwise0x107.
 * Requirements/effects: Uses modulo32 unsigned intervals. A release gap>=1000us resets acquisition
 *   time. Only checks a polled budget; does not itself yield or install a timer.
 */

int spi_flash_os_check_yield(FlashOsContext *context,
    unsigned int chip_status,unsigned int *request)
{
    if (chip_status != 0)
        __assert_func(0,0,0,0);
    unsigned int now_us = (unsigned int)esp_system_get_time();
    volatile FlashOsContext *state = context;
    unsigned int released_us = state->released_since_us;
    unsigned int should_yield = 0;
    int status = 0x107;
    if (now_us - released_us >= 1000U) {
        state->acquired_since_us = now_us;
    } else {
        unsigned int acquired_us = state->acquired_since_us;
        if (now_us - acquired_us >= 20000U) {
            should_yield = 1;
            status = 0;
        }
    }
    if (request != 0)
        *request = should_yield;
    return status;
}

/* Native entry: 0x4037d1fc. */
/*
 * Medius v3.4.7 — host application; 0x4037d1fc.
 *
 * Calls ROM esp_rom_delay_us with the requested microseconds and returns 0. Ignores the context
 * and supplies no scheduler-yield, software timer or status check.
 *
 * Calls: FUN_40000600.
 *
 * Original function-byte SHA-256:
 * c2552376518c843706c42415b18acfcb27728cd804e679c34b4373ac4da587c8.
 */

/* Reference: ESP-IDF v5.4.4 components/spi_flash/spi_flash_os_func_app.c delay_us. */

/*
 * unused: Unused callback context; not dereferenced.
 * microseconds: Unsigned duration forwarded to the ROM delay routine at0x40000600.
 * Returns: 0 after the ROM delay returns.
 * Requirements/effects: Supplies no RTOS yield or separate status/timeout mechanism. ROM delay
 *   execution is outside this application body.
 */

int flash_os_delay_us(void *unused,unsigned int microseconds)
{
    (void)unused;
    esp_rom_delay_us(microseconds);
    return 0;
}

/* Native entry: 0x4037d20c. */
/*
 * Medius v3.4.7 — host application; 0x4037d20c.
 *
 * Extracts operation flag bit 0 and forwards it as the one-byte flash-erasing state used by the
 * brownout-reset predicate. It performs no erase itself and returns no status.
 *
 * Calls: spi_flash_set_erasing_flag.
 *
 * Original function-byte SHA-256:
 * ed26145519030c78f6360fb1ad8643a01f5a2bddb240a2bf2aa322c26155b26a.
 */

/* Reference: ESP-IDF v5.4.4 components/spi_flash/spi_flash_os_func_app.c. */

/*
 * flags: Operation flags; only bit0 is forwarded as the flash-erasing state.
 * Returns: Nothing.
 * Requirements/effects: Updates brownout-related erase-state tracking through
 *   spi_flash_set_erasing_flag; performs no flash erase itself.
 */

void main_flash_op_status(unsigned int flags)
{
    spi_flash_set_erasing_flag((unsigned char)(flags & 1U));
}

/* Native entry: 0x4037d218. */
/*
 * Medius v3.4.7 — host application; 0x4037d218.
 *
 * Returns NOT_ALLOWED (0x10d) when the region is not writable. Otherwise returns 0 when
 * no_protect is set or the main-image safety check passes, and NOT_SUPPORTED (0x106) if it fails.
 * The no_protect flag does not bypass the initial read-only-partition check.
 *
 * Calls: FUN_42011624, FUN_42011674.
 *
 * Original function-byte SHA-256:
 * f0951d63f56ee128e28364810a1fb2b9617bdfc12e51ac3ce784a2591983a8ba.
 */

/* Reference: ESP-IDF v5.4.4 components/spi_flash/spi_flash_os_func_app.c. The first dependency is
   the writable-partition predicate; the second checks the main-flash protected region. Their
   bodies need separate review. */

/*
 * context: Flash-OS context whose no_protect byte controls the main-image safety check only.
 * address: Flash byte offset passed to the region-writability and main-image safety predicates.
 * size: Byte extent passed unchanged to those predicates.
 * Returns: 0 for permitted writes,0x10d for a non-writable region, or0x106 when the additional
 *   main-image safety test rejects it.
 * Requirements/effects: Requires a live context. no_protect bypasses only the second predicate; it
 *   never bypasses the initial read-only-region test.
 */

int main_flash_region_protected(FlashOsContext *context,
    unsigned int address,unsigned int size)
{
    if (!esp_partition_is_flash_region_writable(address,size))
        return 0x10d;
    unsigned char no_protect = *(const volatile unsigned char *)&context->no_protect;
    if (no_protect == 0 && !esp_partition_main_flash_region_safe(address,size))
        return 0x106;
    return 0;
}

/* Native entry: 0x4037d248. */
/*
 * Medius v3.4.7 — host application; 0x4037d248.
 *
 * Compiled no-argument adapter to the paired cache/interrupt/other-CPU disable guard. The SDK
 * source callback has an unused argument, but this internal specialization consumes none and its
 * direct callers supply none.
 *
 * Calls: spi_flash_disable_interrupts_caches_and_other_cpu.
 *
 * Called by: spi1_start.
 *
 * Original function-byte SHA-256:
 * 4ae924f46000f3c8943fd565ed6371a71ac5f464c7622466e2a6368cf85bba61.
 */

/* Reference: ESP-IDF v5.4.4 components/spi_flash/spi_flash_os_func_app.c cache_disable. */

/*
 * Returns: Nothing.
 * Requirements/effects: No-argument compiled adapter enters the paired flash/cache/interrupt
 *   guard. Same ownership/stack/startup restrictions apply as to that guard.
 */

void flash_os_cache_disable(void)

{
  spi_flash_disable_interrupts_caches_and_other_cpu();
  return;
}

/* Native entry: 0x4037d250. */
/*
 * Medius v3.4.7 — host application; 0x4037d250.
 *
 * Starts a SPI1 flash operation by invoking the cache-disable adapter and returns 0. This build
 * uses the cache/interrupt guard path, not the optional bus-lock or cache-preserving mutex
 * variants; on_spi_acquired is compiled empty.
 *
 * Calls: flash_os_cache_disable.
 *
 * Original function-byte SHA-256:
 * 348c6758675d1d78d1dfef2012d866493613e705c0e3d10ba50ee8195e4b459b.
 */

/* Reference: ESP-IDF v5.4.4 components/spi_flash/spi_flash_os_func_app.c. */

/*
 * unused_context: Unused SPI1 flash-OS context; this specialization does not dereference it.
 * Returns: 0 after cache-disable adapter returns.
 * Requirements/effects: Uses the cache/interrupt/peer-CPU guard path. Caller must later finish
 *   through the paired end callback.
 */

int spi1_start(FlashOsContext *unused_context)

{
  flash_os_cache_disable();
  return 0;
}

/* Native entry: 0x4037d25c. */
/*
 * Medius v3.4.7 — host application; 0x4037d25c.
 *
 * Compiled no-argument adapter to the paired cache/interrupt/other-CPU restoration guard. The SDK
 * source callback has an unused argument, but this internal specialization consumes none and its
 * direct callers supply none.
 *
 * Calls: spi_flash_enable_interrupts_caches_and_other_cpu.
 *
 * Called by: spi1_end.
 *
 * Original function-byte SHA-256:
 * cd64904bdb76e415814a62c0566018b94e7bf62393efad0f8f2677cbef3c8fb0.
 */

/* Reference: ESP-IDF v5.4.4 components/spi_flash/spi_flash_os_func_app.c cache_enable. */

/*
 * Returns: Nothing.
 * Requirements/effects: No-argument compiled adapter leaves the paired flash/cache/interrupt guard
 *   on its owning CPU.
 */

void flash_os_cache_enable(void)

{
  spi_flash_enable_interrupts_caches_and_other_cpu();
  return;
}

/* Native entry: 0x4037d264. */
/*
 * Medius v3.4.7 — host application; 0x4037d264.
 *
 * Restores caches/interrupts through the enable adapter, records low 32 system microseconds in
 * released_since_us, and returns 0. The timestamp is sampled after restoration, so it is used as
 * the start of the next implicit-yield interval.
 *
 * Calls: esp_system_get_time, flash_os_cache_enable.
 *
 * Original function-byte SHA-256:
 * 6ce5c0d7cfd88bcdd2a2ec5d86726186fc18db4b40010f030fa51a7c3c61f7fd.
 */

/* Reference: ESP-IDF v5.4.4 components/spi_flash/spi_flash_os_func_app.c. */

/*
 * context: Writable flash-OS context receiving the low32 released_since_us timestamp.
 * Returns: 0.
 * Requirements/effects: Requires the matching SPI1 start/flash guard. Restores cache/interrupt
 *   state before sampling system time; the timestamp starts the next release interval.
 */

int spi1_end(FlashOsContext *context)
{
    flash_os_cache_enable();
    unsigned int now_us = (unsigned int)esp_system_get_time();
    ((volatile FlashOsContext *)context)->released_since_us = now_us;
    return 0;
}

/* Native entry: 0x4038bb9c. */
/*
 * Medius v3.4.7 — host application; 0x4038bb9c.
 *
 * Reads the JEDEC vendor field from the ROM legacy flash descriptor and sets the brownout-reset
 * flag when its upper16 bits equal0x20 (XMC). A nonmatching ID leaves the previous flag
 * unchanged; this routine does not reset the flash.
 *
 * Called by: FUN_420022ec.
 *
 * Original function-byte SHA-256:
 * bee145254bd5d09d136a8ea25dc0c0ab4e859820887450633921a1e1f53d8c36.
 */

/* Reference: ESP-IDF v5.4.4 components/spi_flash/flash_brownout_hook.c. */

/*
 * Returns: Nothing.
 * Requirements/effects: Requires a live ROM legacy descriptor. Sets the software brownout-reset
 *   flag for vendor field0x20, read as exactly the HALFWORD at descriptor+2. Nonmatching IDs
 *   leave its existing value unchanged; no full device-ID WORD read or MEMW occurs.
 */

void spi_flash_needs_reset_check(void)
{
    RomFlashLegacy *legacy = ROM_FLASH_LEGACY;
    const volatile unsigned short *device_id_high =
        (const volatile unsigned short *)((unsigned int)&legacy->chip.device_id + 2U);
    unsigned short vendor_field = *device_id_high;
    if (vendor_field == 0x20U)
        FLASH_BROWNOUT_RESET_NEEDED = 1;
}

/* Native entry: 0x4038bbb4. */
/*
 * Medius v3.4.7 — host application; 0x4038bbb4.
 *
 * Stores the one-byte flash-erasing state used by the brownout-reset predicate. No lock, flash
 * operation or hardware status read is supplied.
 *
 * Called by: main_flash_op_status.
 *
 * Original function-byte SHA-256:
 * 201e0392df3318e7bfdf8b33be506b31b3f522a36018dec2f83ebbf0748f15ab.
 */

/* Reference: ESP-IDF v5.4.4 components/spi_flash/flash_brownout_hook.c. */

/*
 * erasing: Raw low8 software erase-state byte, stored unchanged without Boolean normalization.
 * Returns: Nothing.
 * Requirements/effects: Stores one software flag. Does not issue flash operations, sample hardware
 *   status or acquire a lock.
 */

void spi_flash_set_erasing_flag(unsigned char erasing)
{
    FLASH_ERASE_IN_PROGRESS = erasing;
}

/* Native entry: 0x4038bbc0. */
/*
 * Medius v3.4.7 — host application; 0x4038bbc0.
 *
 * Returns true only when the startup-selected flash-brownout-reset flag and the current flash-
 * erasing flag are both true. It reads software state, not flash status, and does not acknowledge
 * or clear either flag.
 *
 * Called by: rtc_brownout_isr_handler.
 *
 * Original function-byte SHA-256:
 * 240396a213d46b8d4a10105141d7cfe39cfb2a9ffc48859606b35402c0d30c9a.
 */

/* Reference: ESP-IDF v5.4.4 components/spi_flash/flash_brownout_hook.c. */

/*
 * Returns: 0 when reset-needed is zero; otherwise returns the raw erasing byte unchanged.
 * Requirements/effects: Reads software flags without clearing them or changing hardware. A true
 *   result requests the caller reset path, not proof that flash has already reset.
 */

unsigned char spi_flash_brownout_need_reset(void)
{
    unsigned char reset_needed = FLASH_BROWNOUT_RESET_NEEDED;
    if (reset_needed != 0)
        return FLASH_ERASE_IN_PROGRESS;
    return reset_needed;
}

/* Native entry: 0x42011a14. */
/*
 * Medius v3.4.7 — host application; 0x42011a14.
 *
 * Snapshots the ROM legacy descriptor pointer, reads the JEDEC ID through the bootloader command
 * helper and writes its normalized 24-bit result into chip.device_id. Does not change the
 * configured chip size or other geometry fields. Behavioral name; the original symbol is not
 * assumed.
 *
 * Calls: bootloader_read_flash_id.
 *
 * Called by: firmware_entry.
 *
 * Original function-byte SHA-256:
 * d8535bfe57839d75505b70e03f25908bc00e829101d6e1277d4a0bb9fcbb20ba.
 */

/* Reference: ESP-IDF v5.4.4 startup JEDEC-ID path and
   components/bootloader_support/bootloader_flash/src/bootloader_flash.c. */

/*
 * Returns: Nothing.
 * Requirements/effects: Requires the ROM legacy flash descriptor to be live. Reads/normalizes
 *   JEDEC ID and updates only chip.device_id; leaves geometry unchanged.
 */

void flash_update_rom_chip_id(void)
{
    RomFlashLegacy *legacy = ROM_FLASH_LEGACY;
    unsigned int device_id = bootloader_read_flash_id();
    ((volatile RomFlashLegacy *)legacy)->chip.device_id = device_id;
}

/* Native entry: 0x420127ec. */
/*
 * Medius v3.4.7 — host application; 0x420127ec.
 *
 * Creates the recursive flash-operation mutex and asserts allocation success. The source queue-
 * type4 argument is unconsumed by this build optimized xQueueCreateMutex specialization.
 * Reinitialization is not guarded and would overwrite the global handle.
 *
 * Calls: __assert_func, xQueueCreateMutex.
 *
 * Called by: FUN_42012c14.
 *
 * Original function-byte SHA-256:
 * 50ec2dd1588d286cacd139b1e3c06be190d2a55d71cf7255ee82f0689b98361e.
 */

/* Reference: ESP-IDF v5.4.4 components/spi_flash/cache_utils.c. */

/*
 * Returns: Nothing; mutex-allocation failure asserts.
 * Requirements/effects: Initialization creates the recursive flash-operation mutex. No repeated-
 *   initialization guard exists, so a later call can overwrite the previous global handle.
 */

void spi_flash_init_lock(void)
{
    RtosQueue *mutex = (RtosQueue *)xQueueCreateMutex();
    FLASH_OPERATION_MUTEX = mutex;
    if (mutex == 0)
        __assert_func(0,0,0,0);
}

/* Native entry: 0x42012810. */
/*
 * Medius v3.4.7 — host application; 0x42012810.
 *
 * Takes the global recursive flash mutex with UINT32_MAX wait ticks and ignores the take result.
 * Requires prior initialization. This is the API serialization lock; it does not itself disable
 * cache or interrupts.
 *
 * Calls: xQueueTakeMutexRecursive.
 *
 * Called by: spi_flash_disable_interrupts_caches_and_other_cpu.
 *
 * Original function-byte SHA-256:
 * 9689645f262c54df48f093914d2500b78b578f2a2de1778640e487b91e2b6aae.
 */

/* Reference: ESP-IDF v5.4.4 components/spi_flash/cache_utils.c. */

/*
 * Returns: Nothing; ignores the recursive mutex-take result.
 * Requirements/effects: Requires an initialized flash mutex and suitable task context. Waits with
 *   UINT32_MAX ticks; this helper alone does not disable caches or interrupts.
 */

void spi_flash_op_lock(void)
{
    RtosQueue *mutex = FLASH_OPERATION_MUTEX;
    xQueueTakeMutexRecursive(mutex,0xffffffffU);
}

/* Native entry: 0x42012824. */
/*
 * Medius v3.4.7 — host application; 0x42012824.
 *
 * Gives the global recursive flash mutex and ignores the result. The matching owner/recursion
 * rules are implemented by the queue mutex API; no cache or interrupt operations occur here.
 *
 * Calls: xQueueGiveMutexRecursive.
 *
 * Called by: spi_flash_enable_interrupts_caches_and_other_cpu.
 *
 * Original function-byte SHA-256:
 * 4481587e23dd800e26ebc83cc813c7a4af0ae2f91dd08171c36fce410939b6e8.
 */

/* Reference: ESP-IDF v5.4.4 components/spi_flash/cache_utils.c. */

/*
 * Returns: Nothing; ignores the recursive mutex-give result.
 * Requirements/effects: Requires the matching mutex ownership/recursion contract. Does not itself
 *   restore cache or interrupt state.
 */

void spi_flash_op_unlock(void)
{
    RtosQueue *mutex = FLASH_OPERATION_MUTEX;
    xQueueGiveMutexRecursive(mutex);
}
