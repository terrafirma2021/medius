/* Medius v3.4.7 device — drivers/flash.c.
 * Recovered C and native assembly, grouped for source navigation.
 * Original entry addresses, firmware-byte hashes and function comments follow.
 */

#include "../include/types.h"

/* Native entry: 0x4037d7d8. */
/*
 * Medius v3.4.7 — device application; 0x4037d7d8.
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
 * 08031b33f1dc276d381e3a187e9f9ab465be5b9dc82735353e47c286bcff4a03.
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
            unsigned int staged_transmit_word = staged_word;
            memw();
            MSPI1->data[0] = staged_transmit_word;
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

/* Native entry: 0x4037da38. */
/*
 * Medius v3.4.7 — device application; 0x4037da38.
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

uint bootloader_read_flash_id(void)
{
  uint response = bootloader_flash_execute_command_common(0x9f, 0, 0, 0, 0, 0, 24);
  return ((response & 0xffU) << 16) | (response & 0xff00U) | ((response >> 16) & 0xffU);
}

/* Native entry: 0x4037da70. */
/*
 * Medius v3.4.7 — device application; 0x4037da70.
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
 * a4a8b0aa0de03121e97accfb797f361d512bfc27ac705c4fa44bdfe54ce2c207.
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
  uint control2_value;
  uint command_status;

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

/* Native entry: 0x4037dce4. */
/*
 * Medius v3.4.7 — device application; 0x4037dce4.
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
 * acd3fa89b299849c3de8cbf7de89f319a85836e395eefc660c17b85d9845c2e2.
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

/* Native entry: 0x4037dcf4. */
/*
 * Medius v3.4.7 — device application; 0x4037dcf4.
 *
 * Compiled S3 specialization delegates to external-memory-cache resume. It consumes no CPU or
 * saved-state parameter and does not restore interrupt masks or scheduling by itself.
 *
 * Calls: esp_cache_resume_ext_mem_cache.
 *
 * Called by: spi_flash_op_block_func, spi_flash_enable_interrupts_caches_and_other_cpu, FUN_4037de40.
 *
 * Original function-byte SHA-256:
 * acd3fa89b299849c3de8cbf7de89f319a85836e395eefc660c17b85d9845c2e2.
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

/* Native entry: 0x4037dd04. */
/*
 * Medius v3.4.7 — device application; 0x4037dd04.
 *
 * Peer-CPU IPC callback: suspends scheduling, masks non-IRAM interrupts, clears completion and
 * publishes ready, then polls volatile completion. Restores caches and interrupts before resuming
 * scheduling. The compiled S3 cache restore consumes no CPU/save-state argument. This valid
 * return path was lost in the old nonvolatile export.
 *
 * Calls: esp_intr_noniram_disable, esp_intr_noniram_enable, spi_flash_restore_cache, vTaskSuspendAll, xTaskResumeAll.
 *
 * Original function-byte SHA-256:
 * b65469fe51867eb67143b1ae772e3d9c10294e3ab7eaf08d1f9967e6cbcea8a5.
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
  bool operation_complete;

  vTaskSuspendAll();
  esp_intr_noniram_disable();
  memw();
  s_flash_op_complete = false;
  memw();
  s_flash_op_can_start = true;
  do {
    memw();
    operation_complete = s_flash_op_complete;
  } while (operation_complete == false);
  spi_flash_restore_cache();
  esp_intr_noniram_enable();
  xTaskResumeAll();
  return;
}

/* Native entry: 0x4037dd40. */
/*
 * Medius v3.4.7 — device application; 0x4037dd40.
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
 * e40ab26c9fc747bf93ad95cf4e3692e0dbdc3d5f54a13c543b53cce3114694ed.
 */

/* Reference: ESP-IDF v5.4.4 components/spi_flash/cache_utils.c. */

/*
 * Returns: Nothing on successful guard acquisition; invalid stack/owner/startup CPU asserts.
 * Requirements/effects: Requires internal DRAM or allowed RTC-fast stack. Takes initialized
 *   recursive flash mutex, enforces unowned state and uses peer IPC when scheduling is active.
 *   Busy retries/polls have no timeout; pair with the enable guard on the same CPU.
 */

void spi_flash_disable_interrupts_caches_and_other_cpu(void)
{
    uint stack_address;
    /* The native entry tests A1 after its 32-byte register-window frame. */
    __asm__ volatile("mov %0, a1" : "=a"(stack_address));
    bool internal_stack = (uint)(stack_address - 0x3fc88000U) < 0x78000U;
    bool rtc_fast_stack = (uint)(stack_address - 0x600fe000U) < 0x2000U;
    if (!internal_stack && !rtc_fast_stack)
        __assert_func(0, 0, 0, 0);

    spi_flash_op_lock();
    uint cpu = (xtensa_read_prid() >> 13) & 1U;
    memw();
    int previous_owner = s_flash_op_cpu;
    if (previous_owner != -1)
        __assert_func(0, 0, 0, 0);
    memw();
    s_flash_op_cpu = cpu;

    int scheduler_state = xTaskGetSchedulerState();
    if (scheduler_state == 1) {
        if (cpu != 0)
            __assert_func(0, 0, 0, 0);
    } else {
        for (;;) {
            vTaskSuspendAll();
            cpu = (xtensa_read_prid() >> 13) & 1U;
            uint peer_cpu = cpu == 0;
            memw();
            s_flash_op_cpu = cpu;
            memw();
            s_flash_op_can_start = false;
            int ipc_result = esp_ipc_call_nonblocking(
                peer_cpu, spi_flash_op_block_func, (void *)peer_cpu);
            if (ipc_result == 0)
                break;
            xTaskResumeAll();
        }
        bool peer_ready;
        do {
            memw();
            peer_ready = s_flash_op_can_start;
        } while (!peer_ready);
    }
    esp_intr_noniram_disable();
    spi_flash_disable_cache();
}

/* Native entry: 0x4037dde4. */
/*
 * Medius v3.4.7 — device application; 0x4037dde4.
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
 * 4f326c10a4e77ce6cc177b0dbba10037aa5dd519bcd5f524f336b2025c197290.
 */

/* Reference: ESP-IDF v5.4.4 components/spi_flash/cache_utils.c. */

/*
 * Returns: Nothing on successful release; mismatched owner/startup CPU asserts.
 * Requirements/effects: Matching disable guard must own the operation on this CPU. Clears
 *   ownership, restores caches, signals peer completion when applicable, restores interrupts
 *   before scheduling, and unlocks the recursive mutex.
 */

void spi_flash_enable_interrupts_caches_and_other_cpu(void)
{
    uint cpu = (xtensa_read_prid() >> 13) & 1U;
    memw();
    int owner_cpu = s_flash_op_cpu;
    if ((uint)owner_cpu != cpu)
        __assert_func(0, 0, 0, 0);
    /* This query occurs even when owner_cpu is zero. */
    int scheduler_state = xTaskGetSchedulerState();
    if (owner_cpu != 0 && scheduler_state == 1)
        __assert_func(0, 0, 0, 0);

    memw();
    s_flash_op_cpu = -1;
    spi_flash_restore_cache();
    scheduler_state = xTaskGetSchedulerState();
    if (scheduler_state != 1) {
        memw();
        s_flash_op_complete = true;
    }
    esp_intr_noniram_enable();
    scheduler_state = xTaskGetSchedulerState();
    if (scheduler_state != 1)
        xTaskResumeAll();
    spi_flash_op_unlock();
}

/* Native entry: 0x4037e9e8. */
/*
 * Medius v3.4.7 — device application; 0x4037e9e8.
 *
 * Requests vTaskDelay(1) only when scheduler state is RUNNING (2), then records low 32 system
 * microseconds as acquired_since_us and returns 0. The output-status pointer is unused. One tick
 * is a scheduling request, not a guaranteed wall-clock delay; timestamp reset also occurs when no
 * delay was requested.
 *
 * Calls: esp_system_get_time, vTaskDelay, xTaskGetSchedulerState.
 *
 * Original function-byte SHA-256:
 * 2715340fdfdca645f52bf5a7e650d2c6cb0ec7d826b2f7380bb271a6a81a402c.
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

int spi_flash_os_yield(FlashOsContext *context,uint *unused_status)

{
  int scheduler_state;
  longlong time_us;

  scheduler_state = xTaskGetSchedulerState();
  if (scheduler_state == 2) {
    vTaskDelay(1);
  }
  time_us = esp_system_get_time();
  context->acquired_since_us = (uint)time_us;
  return 0;
}

/* Native entry: 0x4037ea00. */
/*
 * Medius v3.4.7 — device application; 0x4037ea00.
 *
 * Asserts chip_status == 0. Uses unsigned low 32-us differences: a release interval >=1000us
 * resets acquired_since_us; otherwise an active interval >=20000us requests yield. Optionally
 * stores request 0/1 and returns TIMEOUT (0x107) or 0. This is a polled budget check, not a
 * software timer or an immediate task switch.
 *
 * Calls: esp_system_get_time, __assert_func.
 *
 * Original function-byte SHA-256:
 * 978268ad29b50c47a856ef64a7446e0e710d00eb4524faf86ba21c4573f26b35.
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

int spi_flash_os_check_yield(FlashOsContext *context,uint chip_status,uint *request)
{
    if (chip_status != 0)
        __assert_func(0, 0, 0, 0);

    uint now_us_low = (uint)esp_system_get_time();
    uint yield_requested = 0;
    int result = 0x107;
    if (now_us_low - context->released_since_us >= 1000U) {
        context->acquired_since_us = now_us_low;
    } else if (now_us_low - context->acquired_since_us >= 20000U) {
        yield_requested = 1;
        result = 0;
    }
    if (request != 0)
        *request = yield_requested;
    return result;
}

/* Native entry: 0x4037ea94. */
/*
 * Medius v3.4.7 — device application; 0x4037ea94.
 *
 * Calls ROM esp_rom_delay_us with the requested microseconds and returns 0. Ignores the context
 * and supplies no scheduler-yield, software timer or status check.
 *
 * Calls: esp_rom_delay_us.
 *
 * Original function-byte SHA-256:
 * 67d31ce938b80ca3224ffa73c25869cb7d77b5ccb543fe027bcf5fc40467fd8e.
 */

/* Reference: ESP-IDF v5.4.4 components/spi_flash/spi_flash_os_func_app.c delay_us. */

/*
 * unused: Unused callback context; not dereferenced.
 * microseconds: Unsigned duration forwarded to the ROM delay routine at0x40000600.
 * Returns: 0 after the ROM delay returns.
 * Requirements/effects: Supplies no RTOS yield or separate status/timeout mechanism. ROM delay
 *   execution is outside this application body.
 */

int flash_os_delay_us(void *unused,uint microseconds)

{
  esp_rom_delay_us(microseconds);
  return 0;
}

/* Native entry: 0x4037eaa4. */
/*
 * Medius v3.4.7 — device application; 0x4037eaa4.
 *
 * Extracts operation flag bit 0 and forwards it as the one-byte flash-erasing state used by the
 * brownout-reset predicate. It performs no erase itself and returns no status.
 *
 * Calls: spi_flash_set_erasing_flag.
 *
 * Original function-byte SHA-256:
 * 7c1599f62d45cd851a27efb7ec41190662c9eb88a23d44dd57e9bb9603271ae0.
 */

/* Reference: ESP-IDF v5.4.4 components/spi_flash/spi_flash_os_func_app.c. */

/*
 * flags: Operation flags; only bit0 is forwarded as the flash-erasing state.
 * Returns: Nothing.
 * Requirements/effects: Updates brownout-related erase-state tracking through
 *   spi_flash_set_erasing_flag; performs no flash erase itself.
 */

void main_flash_op_status(uint flags)

{
  spi_flash_set_erasing_flag((bool)((byte)flags & 1));
  return;
}

/* Native entry: 0x4037eab0. */
/*
 * Medius v3.4.7 — device application; 0x4037eab0.
 *
 * Returns NOT_ALLOWED (0x10d) when the region is not writable. Otherwise returns 0 when
 * no_protect is set or the main-image safety check passes, and NOT_SUPPORTED (0x106) if it fails.
 * The no_protect flag does not bypass the initial read-only-partition check.
 *
 * Calls: esp_partition_is_flash_region_writable, esp_partition_main_flash_region_safe.
 *
 * Original function-byte SHA-256:
 * b333393fce797cbed7d7d38f68e3d189f51cbc3c84eace01cfbe818162b84369.
 */

/* Reference: ESP-IDF v5.4.4 components/spi_flash/spi_flash_os_func_app.c.
 * Both partition predicates have their own reviewed definitions. */

/*
 * context: Flash-OS context whose no_protect byte controls the main-image safety check only.
 * address: Flash byte offset passed to the region-writability and main-image safety predicates.
 * size: Byte extent passed unchanged to those predicates.
 * Returns: 0 for permitted writes,0x10d for a non-writable region, or0x106 when the additional
 *   main-image safety test rejects it.
 * Requirements/effects: Requires a live context. no_protect bypasses only the second predicate; it
 *   never bypasses the initial read-only-region test.
 */

int main_flash_region_protected(FlashOsContext *context,uint address,uint size)
{
    if (!esp_partition_is_flash_region_writable(address, size))
        return 0x10d;
    if (!context->no_protect &&
        !esp_partition_main_flash_region_safe(address, size))
        return 0x106;
    return 0;
}

/* Native entry: 0x4037eae0. */
/*
 * Medius v3.4.7 — device application; 0x4037eae0.
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

/* Native entry: 0x4037eae8. */
/*
 * Medius v3.4.7 — device application; 0x4037eae8.
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

/* Native entry: 0x4037eaf4. */
/*
 * Medius v3.4.7 — device application; 0x4037eaf4.
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

/* Native entry: 0x4037eafc. */
/*
 * Medius v3.4.7 — device application; 0x4037eafc.
 *
 * Restores caches/interrupts through the enable adapter, records low 32 system microseconds in
 * released_since_us, and returns 0. The timestamp is sampled after restoration, so it is used as
 * the start of the next implicit-yield interval.
 *
 * Calls: esp_system_get_time, flash_os_cache_enable.
 *
 * Original function-byte SHA-256:
 * db2bbb8cf3e05b238d5a5b723d797390904db0e565d2467c998bbdd0b1ebb387.
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
  longlong time_us;

  flash_os_cache_enable();
  time_us = esp_system_get_time();
  context->released_since_us = (uint)time_us;
  return 0;
}

/* Native entry: 0x4038fdd4. */
/*
 * Medius v3.4.7 — device application; 0x4038fdd4.
 *
 * Reads the JEDEC vendor field from the ROM legacy flash descriptor and sets the brownout-reset
 * flag when its upper16 bits equal0x20 (XMC). A nonmatching ID leaves the previous flag
 * unchanged; this routine does not reset the flash.
 *
 * Called by: FUN_420029b4.
 *
 * Original function-byte SHA-256:
 * f7e24dad10671feb1c552592806dda3e0ec43b54a7a4280201639c2f5cff0128.
 */

/* Reference: ESP-IDF v5.4.4 components/spi_flash/flash_brownout_hook.c. */

/*
 * Returns: Nothing.
 * Requirements/effects: Requires a live ROM legacy descriptor. Sets the software brownout-reset
 *   flag for vendor field0x20; nonmatching IDs leave its existing value unchanged.
 */

void spi_flash_needs_reset_check(void)
{
  /* The native code reads only the upper halfword of device_id. */
  RomFlashLegacy *legacy = rom_spiflash_legacy_data;
  unsigned short vendor_field = *(const volatile unsigned short *)
      ((const unsigned char *)&legacy->chip.device_id + 2);
  if (vendor_field == 0x20U) {
    flash_brownout_needs_reset = true;
  }
}

/* Native entry: 0x4038fdec. */
/*
 * Medius v3.4.7 — device application; 0x4038fdec.
 *
 * Stores the one-byte flash-erasing state used by the brownout-reset predicate. No lock, flash
 * operation or hardware status read is supplied.
 *
 * Called by: main_flash_op_status.
 *
 * Original function-byte SHA-256:
 * 69cd1ccdbd1de958debe39a8bff4170730d3e3d67ef15cdcfeaca2690f6d5dec.
 */

/* Reference: ESP-IDF v5.4.4 components/spi_flash/flash_brownout_hook.c. */

/*
 * erasing: Boolean software erase-state value used by the brownout reset predicate.
 * Returns: Nothing.
 * Requirements/effects: Stores one software flag. Does not issue flash operations, sample hardware
 *   status or acquire a lock.
 */

void spi_flash_set_erasing_flag(bool erasing)

{
  flash_erasing = erasing;
  return;
}

/* Native entry: 0x4038fdf8. */
/*
 * Medius v3.4.7 — device application; 0x4038fdf8.
 *
 * Returns true only when the startup-selected flash-brownout-reset flag and the current flash-
 * erasing flag are both true. It reads software state, not flash status, and does not acknowledge
 * or clear either flag.
 *
 * Called by: rtc_brownout_isr_handler.
 *
 * Original function-byte SHA-256:
 * 898a2feea233c749d5329bc06019ff5d2f1138246de90b92fa4364817c8c4123.
 */

/* Reference: ESP-IDF v5.4.4 components/spi_flash/flash_brownout_hook.c. */

/*
 * Returns: true only when both startup-selected reset-needed and current erasing flags are true.
 * Requirements/effects: Reads software flags without clearing them or changing hardware. A true
 *   result requests the caller reset path, not proof that flash has already reset.
 */

bool spi_flash_brownout_need_reset(void)

{
  FlashStateFlag reset_required;

  reset_required = false;
  if (flash_brownout_needs_reset) {
    reset_required = flash_erasing;
  }
  return reset_required;
}

/* Native entry: 0x4200f608. */
/*
 * Medius v3.4.7 — device application; 0x4200f608.
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
 * 6c0691b9a3ffe1c46a6adbf7a226ab8042d9506735dd572be95fa100b5a73603.
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
  RomFlashLegacyPointer rom_descriptor;
  uint device_id;

  rom_descriptor = rom_spiflash_legacy_data;
  device_id = bootloader_read_flash_id();
  (rom_descriptor->chip).device_id = device_id;
  return;
}

/* Native entry: 0x420104c0. */
/*
 * Medius v3.4.7 — device application; 0x420104c0.
 *
 * Creates the recursive flash-operation mutex and asserts allocation success. The source queue-
 * type4 argument is unconsumed by this build optimized xQueueCreateMutex specialization.
 * Reinitialization is not guarded and would overwrite the global handle.
 *
 * Calls: __assert_func, xQueueCreateMutex.
 *
 * Called by: FUN_420108c4.
 *
 * Original function-byte SHA-256:
 * 6c47ce86eed012ce9144871aa983d3decf048c756b826f13b69f843272c3ea08.
 */

/* Reference: ESP-IDF v5.4.4 components/spi_flash/cache_utils.c. */

/*
 * Returns: Nothing; mutex-allocation failure asserts.
 * Requirements/effects: Initialization creates the recursive flash-operation mutex. No repeated-
 *   initialization guard exists, so a later call can overwrite the previous global handle.
 */

void spi_flash_init_lock(void)

{
  RtosQueue *mutex = rtos_create_mutex_type(4);
  s_flash_op_mutex = mutex;
  if (mutex == NULL) {
                    /* WARNING: Subroutine does not return */
    __assert_func((char *)0x0,0,(char *)0x0,(char *)0x0);
  }
  return;
}

/* Native entry: 0x420104e4. */
/*
 * Medius v3.4.7 — device application; 0x420104e4.
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
 * 08db770c7cbc464aa309373e905fd0cec0e46f557f1dade9acd029ac7a8321e7.
 */

/* Reference: ESP-IDF v5.4.4 components/spi_flash/cache_utils.c. */

/*
 * Returns: Nothing; ignores the recursive mutex-take result.
 * Requirements/effects: Requires an initialized flash mutex and suitable task context. Waits with
 *   UINT32_MAX ticks; this helper alone does not disable caches or interrupts.
 */

void spi_flash_op_lock(void)

{
  xQueueTakeMutexRecursive(s_flash_op_mutex,0xffffffff);
  return;
}

/* Native entry: 0x420104f8. */
/*
 * Medius v3.4.7 — device application; 0x420104f8.
 *
 * Gives the global recursive flash mutex and ignores the result. The matching owner/recursion
 * rules are implemented by the queue mutex API; no cache or interrupt operations occur here.
 *
 * Calls: xQueueGiveMutexRecursive.
 *
 * Called by: spi_flash_enable_interrupts_caches_and_other_cpu.
 *
 * Original function-byte SHA-256:
 * 75a37fea4f29210f26e4061a6499bc35742f87db17ccf4f60d1a854450fb38e3.
 */

/* Reference: ESP-IDF v5.4.4 components/spi_flash/cache_utils.c. */

/*
 * Returns: Nothing; ignores the recursive mutex-give result.
 * Requirements/effects: Requires the matching mutex ownership/recursion contract. Does not itself
 *   restore cache or interrupt state.
 */

void spi_flash_op_unlock(void)

{
  xQueueGiveMutexRecursive(s_flash_op_mutex);
  return;
}
