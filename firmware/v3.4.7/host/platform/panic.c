/* Medius v3.4.7 host — platform/panic.c.
 * Recovered C and native assembly, grouped for source navigation.
 * Original entry addresses, firmware-byte hashes and function comments follow.
 */

#include "../include/types.h"

/* Native entry: 0x40375bd4. */
/*
 * Medius v3.4.7 — host application; 0x40375bd4.
 *
 * Publishes abort state, then executes the fatal illegal instruction.
 *
 * Called by: esp_system_abort.
 *
 * Original function-byte SHA-256:
 * 2cb59ec61def0b4abab0a64415ba75c65615f91f996ae48dca1b427737831109.
 */

/* Publishes abort state before entering the fatal illegal-instruction trap.
   SDK match: ESP-IDF v5.4.4 components/esp_system/panic.c.
   Recovered types/control flow retain the original function bytes and non-returning assertion paths. */

__attribute__((noreturn))

/*
 * details: Diagnostic pointer published unchanged for the panic handler; this body does not
 *   read the pointed-to characters.
 * Returns: Never returns through the normal calling convention.
 * Requirements/effects: Stores the abort BYTE as 1, then the details pointer WORD, then executes
 *   ILL once. These writes identify an explicit abort and its message to the exception handler.
 *   No extra MEMW, formatting, retry or resource release is supplied here.
 */

void panic_abort(const char *details)

{
  PANIC_ABORT_IN_PROGRESS = 1;
  PANIC_ABORT_DETAILS = details;
  __asm__ volatile ("ill" : : : "memory");
  __builtin_unreachable();
}

/* Native entry: 0x403811e4. */
/*
 * Medius v3.4.7 — host application; 0x403811e4.
 *
 * Passes abort details to panic_abort and never returns.
 *
 * Calls: panic_abort.
 *
 * Called by: FUN_40381d98, __assert_func, abort.
 *
 * Original function-byte SHA-256:
 * 64eea8a154a978b3ab025defe301e75340df79f502e336ef22fd10c486239941.
 */

/* Passes abort details to panic_abort and never returns.
   SDK match: ESP-IDF v5.4.4 components/esp_system/port/esp_system_chip.c.
   Recovered types/control flow retain the original function bytes and non-returning assertion paths. */

__attribute__((noreturn))

/*
 * details: Diagnostic pointer passed unchanged to panic_abort.
 * Returns: Never returns.
 * Requirements/effects: Delegates to the fatal trap path; supplies no cleanup or recovery result.
 */

void esp_system_abort(const char *details)

{
                    /* WARNING: Subroutine does not return */
  panic_abort(details);
}

/* Native entry: 0x4038b0c4. */
/* Original function-byte SHA-256:
 * effc07a88ae0d6599aa9cb1ecf343d3fa1046b73693081e871380039f05bd315. */
/*
 * Fatal libc entry. Initializes9-byte PC and2-byte core buffers, then clears
 * a50-byte message. Reads the current window's encoded a0 return address,
 * drops its upper window-size bits, restores firmware PC region0x40000000,
 * and subtracts3 to identify the call instruction. Converts that PC to hex,
 * then reads PRID bit13 and converts core0/1 to decimal through ROM itoa.
 * Four ROM strcat calls join the pinned DRAM prefix, PC, core separator and
 * core text in that order. Calls esp_system_abort with the stack message;
 * an explicit ILL follows if panic handling returns unexpectedly. No logger,
 * heap allocation, lock, retry or normal return. The PC identifies the call
 * site; this routine does not walk stack frames.
 */
void abort(void)
{
    NewlibAbortFrame frame;
    *(volatile unsigned int *)&frame.address_text[4] = 0;
    *(volatile unsigned char *)&frame.address_text[8] = 0;
    *(volatile unsigned char *)&frame.core_text[1] = 0;
    *(volatile unsigned int *)&frame.address_text[0] = 0;
    *(volatile unsigned char *)&frame.core_text[0] = 0;
    memset(frame.message,0,50);
    unsigned int encoded_return;
    __asm__ volatile ("mov %0, a0" : "=a"(encoded_return));
    unsigned int caller_pc = ((encoded_return & 0x3fffffffU) | 0x40000000U) - 3U;
    (void)itoa((int)caller_pc,frame.address_text,16);
    unsigned int core = (xtensa_read_prid() >> 13) & 1U;
    (void)itoa((int)core,frame.core_text,10);
    frame.fragments[1] = frame.address_text;
    frame.fragments[0] = NEWLIB_ABORT_PREFIX;
    frame.fragments[3] = frame.core_text;
    frame.fragments[2] = NEWLIB_ABORT_CORE_SEPARATOR;
    for (unsigned int index = 0; index < 4; ++index)
        (void)strcat(frame.message,frame.fragments[index]);
    newlib_system_abort_boundary(frame.message);
    __asm__ volatile ("ill");
    __builtin_unreachable();
}

/* Native entry: 0x4038b148. */
/*
 * Medius v3.4.7 — host application; 0x4038b148.
 *
 * Silent ESP-IDF assertion failure: formats the call-site address and aborts without returning.
 *
 * Calls: esp_system_abort, itoa.
 *
 * Called by: esp_reset_reason_set_hint, ipc_task, heap_caps_free, heap_caps_aligned_alloc_base, heap_caps_realloc_base, esp_intr_disable,
 * lock_acquire_generic, FUN_40376a1c, FUN_40376a70, _lock_release, _lock_release_recursive, FUN_40376ba0,
 * FUN_40376bcc, FUN_40376bf8, FUN_40376c28, FUN_40376c58, FUN_40376c78, esp_timer_impl_set_alarm_id,
 * bootloader_flash_execute_command_common, spi_flash_disable_interrupts_caches_and_other_cpu, spi_flash_enable_interrupts_caches_and_other_cpu, FUN_4037c9e0, FUN_4037cd3c, spi_flash_os_check_yield; plus 139
 * other direct targets.
 *
 * Original function-byte SHA-256:
 * 83cf83a776b38ed8405b00e771703c559bbdec69950d48c9a373d0a17f3ba9b2.
 */

/* Silent ESP-IDF assertion failure: formats the call-site address and aborts without returning.
   SDK match: ESP-IDF v5.4.4 components/newlib/assert.c.
   Recovered types/control flow retain the original function bytes and non-returning assertion paths. */

__attribute__((noreturn))

/*
 * file: Ignored by this silent-assertion build.
 * line: Ignored by this silent-assertion build.
 * function: Ignored by this silent-assertion build.
 * expression: Ignored by this silent-assertion build.
 * Returns: Never returns.
 * Requirements/effects: Formats the call-site address derived from the return address minus the
 *   three-byte call instruction into a stack message, then calls esp_system_abort. Does not print
 *   or otherwise use the supplied diagnostic arguments.
 */

void __assert_func(const char *file,int line,const char *function,const char *expression)
{
  /* Silent assertions ignore the four diagnostic parameters. The Xtensa return
     address identifies the failing call; CALL/CALLX instructions occupy 3 bytes. */
  char message[sizeof("assert failed: ") + 12] = "assert failed: ";
  char *address = message + sizeof("assert failed: ") - 1;
  address[0] = '0';
  address[1] = 'x';
  unsigned int encoded_return;
  __asm__ volatile ("mov %0, a0" : "=a"(encoded_return));
  unsigned int caller_pc = ((encoded_return & 0x3fffffffU) | 0x40000000U) - 3U;
  itoa((int)caller_pc,address + 2,16);
  esp_system_abort(message);
}

/* Native entry: 0x4201e768. */
/* Original function-byte SHA-256:
 * 601dd368d57d584745de4090efbd6889a15782a91f3ca0aa0465305c2e71e408. */
/* Read and return exactly the saved exception-frame PC word at +4.
 * No PC normalization, executable-address check, MEMW or null validation. */
unsigned int panic_get_address(const void *frame)
{
    return (unsigned int)((const volatile XtensaExceptionFrame *)frame)->pc;
}

/* Native entry: 0x4201e770. */
/* Original function-byte SHA-256:
 * c16f5545312d1a0b0ab08f3f79199d6688948f2b363b46e5fd31ba54430720b2. */
/* Read the saved exception-cause word at +0x50, preserving all 32 bits.
 * No cause decoding, frame validation, hardware register read or MEMW. */
unsigned int panic_get_cause(const void *frame)
{
    return ((const volatile XtensaExceptionFrame *)frame)->exception_cause;
}

/* Native entry: 0x4201e778. */
/* Original function-byte SHA-256:
 * deb23c2ca929c17549c3b0a05f6f3cc126b00f7cbbaf0b90a3b2e8cd84781e6c. */
/* Replace only the exception frame's PC word at +4 with the supplied bits.
 * Panic recovery uses this to install its invalid-PC placeholder. No address
 * validation, cache work, MEMW, other frame writes or return value. */
void panic_set_address(void *frame,unsigned int address)
{
    ((volatile XtensaExceptionFrame *)frame)->pc = (TaskEntry)address;
}
