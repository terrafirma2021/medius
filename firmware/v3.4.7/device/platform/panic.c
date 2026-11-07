/* Medius v3.4.7 device: fatal abort, silent assertion and saved-frame access. */
#include "../include/types.h"

/* Native entry: 0x40375fa4. */
/* Original function-byte SHA-256:
 * 62d8fc24d88338bd83c5f9b7902cc4a6b6a9f1384e521a91007333a4f11bbd27. */
/* Publish the abort BYTE, then the diagnostic pointer WORD, then execute ILL.
 * The diagnostic string is borrowed and is not read here. No extra MEMW,
 * formatting, cleanup or normal return occurs. */
__attribute__((noreturn))
void panic_abort(const char *details)
{
    PANIC_ABORT_IN_PROGRESS = 1;
    PANIC_ABORT_DETAILS = details;
    __asm__ volatile ("ill" : : : "memory");
    __builtin_unreachable();
}

/* Native entry: 0x40385f90. */
/* Original function-byte SHA-256:
 * d0d9aacc86e3a3f583f158289c9ab0a943e7669d25889b60c48695b417f4cc8b. */
/* Forward the borrowed diagnostic pointer to panic_abort; never return.
 * The original byte extent also includes an unreachable ENTRY/RETW pair
 * after the call. It remains part of the original identity, not a return path. */
__attribute__((noreturn))
void esp_system_abort(const char *details)
{
    panic_abort(details);
}

/* Native entry: 0x4038f91c. */
/* Original function-byte SHA-256:
 * df9e4dafec5fe972f6be947c70fe777a11a24248a299896b6d6aa14cc3941b99. */
/* Build the fatal libc message in an 80-byte local storage view.
 * Zero the address/core buffers in native WORD/BYTE order, then clear the
 * 50-byte message. Decode the current window's A0, restore the current code
 * region and subtract the three-byte CALL/CALLX instruction. Convert that PC
 * to hex and PRID bit 13 to decimal; append prefix, PC, separator and core.
 * Call the system-abort boundary, retaining ILL if it unexpectedly returns.
 * No heap allocation, logger, stack walk, lock or normal return is supplied. */
void abort(void)
{
    NewlibAbortFrame frame;
    *(volatile unsigned int *)&frame.address_text[4] = 0;
    *(volatile unsigned char *)&frame.address_text[8] = 0;
    *(volatile unsigned char *)&frame.core_text[1] = 0;
    *(volatile unsigned int *)&frame.address_text[0] = 0;
    *(volatile unsigned char *)&frame.core_text[0] = 0;
    memset(frame.message,0,sizeof(frame.message));
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

/* Native entry: 0x4038f9a0. */
/* Original function-byte SHA-256:
 * 67c489218fe35a505d37d3b253ed944cf8014ecb640ac5e7209a0384a41c106f. */
/* Silent assertion: ignore all four diagnostic arguments and format the
 * caller PC from this window's encoded A0. Read the pinned DRAM prefix in
 * native WORD order 12, 8, 0, 4 and retain the interleaved buffer stores.
 * The 28-byte message contains "assert failed: 0x", eight hex digits and NUL.
 * Forward the stack message to esp_system_abort; never return. The original
 * byte extent includes an unreachable ENTRY/RETW pair after that call. */
__attribute__((noreturn))
void __assert_func(
    const char *file,int line,const char *function,const char *expression)
{
    unsigned int message_storage[7];
    volatile unsigned int *message_words = message_storage;
    char *message = (char *)message_storage;
    unsigned int prefix_last_word = NEWLIB_ASSERT_PREFIX_WORDS[3];
    unsigned int prefix_third_word = NEWLIB_ASSERT_PREFIX_WORDS[2];
    message_words[3] = prefix_last_word;
    unsigned int encoded_return;
    __asm__ volatile ("mov %0, a0" : "=a"(encoded_return) : : "memory");
    unsigned int prefix_first_word = NEWLIB_ASSERT_PREFIX_WORDS[0];
    unsigned int prefix_second_word = NEWLIB_ASSERT_PREFIX_WORDS[1];
    message_words[2] = prefix_third_word;
    message_words[4] = 0;
    *(volatile unsigned char *)&message[15] = '0';
    unsigned int caller_pc = ((encoded_return & 0x3fffffffU) | 0x40000000U) - 3U;
    message_words[5] = 0;
    message_words[6] = 0;
    message_words[0] = prefix_first_word;
    message_words[1] = prefix_second_word;
    *(volatile unsigned char *)&message[16] = 'x';
    (void)itoa((int)caller_pc,message + 17,16);
    esp_system_abort(message);
}

/* Native entry: 0x42020c54. */
/* Original function-byte SHA-256:
 * 601dd368d57d584745de4090efbd6889a15782a91f3ca0aa0465305c2e71e408. */
/* Read the saved exception-frame PC WORD at +4 and return all its bits.
 * No PC normalization, executable-address check, MEMW or NULL validation. */
unsigned int panic_get_address(const void *frame)
{
    return ((const volatile XtensaExceptionFrame *)frame)->pc;
}

/* Native entry: 0x42020c5c. */
/* Original function-byte SHA-256:
 * c16f5545312d1a0b0ab08f3f79199d6688948f2b363b46e5fd31ba54430720b2. */
/* Read the saved exception-cause WORD at +80 and return all its bits.
 * No cause decoding, frame validation, hardware register read or MEMW. */
unsigned int panic_get_cause(const void *frame)
{
    return ((const volatile XtensaExceptionFrame *)frame)->exception_cause;
}

/* Native entry: 0x42020c64. */
/* Original function-byte SHA-256:
 * deb23c2ca929c17549c3b0a05f6f3cc126b00f7cbbaf0b90a3b2e8cd84781e6c. */
/* Replace only the saved PC WORD at +4 with the supplied address bits.
 * The PC is an unsigned machine word, not a task callback. No validation,
 * cache work, MEMW, other frame writes or return value is supplied. */
void panic_set_address(void *frame,unsigned int address)
{
    ((volatile XtensaExceptionFrame *)frame)->pc = address;
}
