/* Medius v3.4.7 host: generic flash OS yield dispatch. */
#include "../include/types.h"

/* Native entry: 0x4038c2d4. */
/* Original function-byte SHA-256:
 * 9bb7486d5b4212e90763b17e9f975126c491e5b487f35af86b4fcf8e66c28e29. */
/* Read OS check_yield callback at +0x18; absent callback returns 0 without
 * accessing the OS context. Otherwise call it with !!wip and a request word.
 * Success with request bit 0 clear returns 0; when set, reload OS functions
 * and context, call yield at +0x1c with a separate status word, and return its
 * result (the word itself is unused). check_yield timeout 0x107 is normalized
 * to success; any other nonzero check error aborts. Yield errors are propagated
 * without that normalization. No OS-table/yield-pointer validation or own wait. */
int spi_flash_chip_generic_yield(EspFlash *chip,unsigned int wip)
{
    const volatile EspFlash *context = chip;
    int (*check_yield)(FlashOsContext *,unsigned int,unsigned int *) =
        context->os_functions->check_yield;
    if (check_yield == 0)
        return 0;
    unsigned int request;
    int result = check_yield(context->os_context,(unsigned int)(wip != 0),&request);
    if (result == 0) {
        if ((request & 1U) == 0)
            return 0;
        const volatile MainFlashOsFunctions *os = context->os_functions;
        FlashOsContext *os_context = context->os_context;
        int (*yield)(FlashOsContext *,unsigned int *) = os->yield;
        unsigned int status;
        return yield(os_context,&status);
    }
    if (result == 0x107)
        return 0;
    abort();
}
