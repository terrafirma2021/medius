/* Medius v3.4.7 host: Newlib formatted string output vectors. */
#include "../include/types.h"

/* Native entry: 0x4201e634. */
/* Original function-byte SHA-256:
 * 9466c5affc1a3bc93a438170eb748f6074de6340f9443637b5016d428f409f24. */
/* Drain input vectors into a string FILE, ignoring the vector count. Skip zero
 * lengths until a nonempty vector appears. Copy at most write_remaining unless
 * length >= remaining and FILE flags 0x480 permit growth. Growth takes the
 * unsigned maximum of used+1+length and signed(truncated32(capacity*3))/2,
 * rounded toward zero. Flag 0x400 allocates a new buffer, copies the used prefix
 * and changes flags to (flags & ~0x480)|0x80. Otherwise realloc the old buffer;
 * realloc failure frees that buffer and leaves FILE pointers/capacity unchanged.
 * Either allocation failure sets reent errno 12 and FILE error flag 0x40,
 * clears request residual/count and returns -1. New-allocation failure keeps
 * the old buffer. Success installs buffer/cursor/capacity/free-space values.
 * memmove each selected fragment, including zero-length truncated fragments;
 * reload and update FILE free-space/cursor, but consume the full vector length
 * from request residual even when a fixed buffer truncated the copy. Return 0
 * with count cleared when residual reaches zero, including initially empty
 * requests. Keep request vector pointer unchanged. No terminator is written.
 * Pointer/counter arithmetic wraps; vector count, extents and residual sums
 * are unchecked. Nonzero residual with only zero vectors scans past the list.
 * No stream lock, output callback or rollback of a partially copied prefix. */
int medius_newlib_write_string_vectors(NewlibReent *reent,
    NewlibFile *stream,MediusNewlibStringWriteRequest *request)
{
    volatile NewlibFile *file = stream;
    volatile MediusNewlibStringWriteRequest *io = request;
    unsigned int residual = io->residual;
    if (residual != 0) {
        const volatile MediusNewlibInputVector *next = io->vectors;
        do {
            const void *input;
            unsigned int length;
            do {
                input = next->base;
                length = next->length;
                next = (const volatile MediusNewlibInputVector *)((unsigned int)next + 8U);
            } while (length == 0);
            unsigned int remaining = (unsigned int)file->write_remaining;
            unsigned int copied = length < remaining ? length : remaining;
            if (length >= remaining) {
                unsigned int flags = file->flags;
                if ((flags & 0x480U) != 0) {
                    unsigned int old_capacity = (unsigned int)file->buffer_capacity;
                    char *old_buffer = file->buffer_base;
                    unsigned int used = (unsigned int)file->cursor - (unsigned int)old_buffer;
                    unsigned int triple = old_capacity * 3U;
                    unsigned int capacity = (unsigned int)((int)triple / 2);
                    unsigned int required = used + 1U + length;
                    if (capacity < required)
                        capacity = required;
                    char *replacement;
                    if ((flags & 0x400U) != 0) {
                        replacement = medius_newlib_malloc_r(reent,capacity);
                        if (replacement == 0)
                            goto allocation_failed;
                        memcpy(replacement,file->buffer_base,used);
                        file->flags = (unsigned short)((file->flags & ~0x480U) | 0x80U);
                    } else {
                        replacement = medius_newlib_realloc_r(reent,old_buffer,capacity);
                        if (replacement == 0) {
                            medius_newlib_free_r(reent,file->buffer_base);
                            goto allocation_failed;
                        }
                    }
                    file->buffer_base = replacement;
                    file->cursor = (char *)((unsigned int)replacement + used);
                    file->buffer_capacity = (int)capacity;
                    file->write_remaining = (int)(capacity - used);
                    copied = length;
                }
            }
            memmove(file->cursor,input,copied);
            file->write_remaining = (int)((unsigned int)file->write_remaining - copied);
            file->cursor = (char *)((unsigned int)file->cursor + copied);
            residual = io->residual - length;
            io->residual = residual;
        } while (residual != 0);
    }
    io->count = 0;
    return 0;

allocation_failed:
    reent->error_number = 12;
    file->flags = (unsigned short)(file->flags | 0x40U);
    io->residual = 0;
    io->count = 0;
    return -1;
}
