/* Medius v3.4.7 device: general FILE vector writes and input refill. */
#include "../include/types.h"

/* Native entry: 0x42018700. */
/* Original function-byte SHA-256:
 * ead52743c4ddac362dbe86dd384510b86c61335642447feb373f5dbd5369bbe2. */
/* * Newlib __sfvwrite_r: drain a residual byte count across8-byte input vectors;
 * vector count and stored vector pointer are not advanced or validated. Empty
 * requests return0 without FILE access. Prepare write mode/buffer when needed;
 * preparation failure returns-1 unchanged. Unbuffered mode calls the writer in
 * chunks<=0x7fffff80. Fully buffered mode copies into available space, flushes
 * full buffers, or writes an INT_MAX-capped whole-buffer multiple directly.
 * Preserve native REMS, including its divide-by-zero trap for capacity0.
 *
 * String mode truncates copies to available room while consuming all input.
 * Flags480 permit growth: max(used+1+length,signed(wrapped(capacity*3))/2).
 * Flag400 uses malloc/copy and changes ownership flags; otherwise realloc,
 * freeing the old allocation and clearing ownership80 on failure. Failure
 * sets errno12, then FILE error40; installed pointers are not rolled back.
 *
 * Line-buffered mode scans for newline, copies/flushes available room or emits
 * one full buffer-capacity chunk directly. Flush at a completed newline BEFORE
 * updating request residual. Failed callbacks/flushes set FILE error40 and
 * return-1, retaining earlier mutations. Positive callback counts are trusted.
 * Success leaves request count unchanged; the separate sprint wrapper clears
 * it. No lock, terminator, vector-bound/pointer/size/overlap validation, retry
 * bound or rollback. All counter/address progression retains32-bit wrap.
 */
int medius_newlib_write_vectors(NewlibReent *reent,NewlibFile *stream,
    MediusNewlibStringWriteRequest *request)
{
    volatile NewlibFile *file = stream;
    volatile MediusNewlibStringWriteRequest *io = request;
    if (io->residual == 0)
        return 0;
    unsigned int flags = file->flags;
    if ((flags & 8U) == 0 || file->buffer_base == NULL) {
        if (medius_newlib_prepare_write(reent,stream) != 0)
            return -1;
    }
    flags = file->flags;
    const volatile MediusNewlibInputVector *next = io->vectors;
    const void *input = NULL;
    unsigned int left = 0;
    if ((flags & 2U) != 0) {
        do {
            while (left == 0) {
                input = next->base;
                left = next->length;
                next = (const volatile MediusNewlibInputVector *)((uintptr_t)next + 8U);
            }
            int (*writer)(NewlibReent *,void *,const char *,int) = file->write_callback;
            void *cookie = file->cookie;
            unsigned int chunk = left < 0x7fffff80U ? left : 0x7fffff80U;
            int written = writer(reent,cookie,input,(int)chunk);
            if (written <= 0)
                goto failed;
            unsigned int residual = io->residual;
            input = (const void *)((uintptr_t)input + (unsigned int)written);
            residual -= (unsigned int)written;
            io->residual = residual;
            left -= (unsigned int)written;
            if (residual == 0)
                return 0;
        } while (true);
    }
    if ((flags & 1U) == 0) {
        do {
            while (left == 0) {
                input = next->base;
                left = next->length;
                next = (const volatile MediusNewlibInputVector *)((uintptr_t)next + 8U);
            }
            flags = file->flags;
            char *cursor = file->cursor;
            unsigned int room = (unsigned int)file->write_remaining;
            unsigned int consumed;
            if ((flags & 0x200U) != 0) {
                unsigned int copied = room < left ? room : left;
                if (left >= room && (flags & 0x480U) != 0) {
                    char *old_buffer = file->buffer_base;
                    unsigned int used = (uintptr_t)cursor - (uintptr_t)old_buffer;
                    unsigned int triple = (unsigned int)file->buffer_capacity * 3U;
                    unsigned int capacity = (unsigned int)((int)triple / 2);
                    unsigned int required = used + 1U + left;
                    if (capacity < required)
                        capacity = required;
                    char *replacement;
                    if ((flags & 0x400U) != 0) {
                        replacement = medius_newlib_malloc_r(reent,capacity);
                        if (replacement == NULL)
                            goto allocation_failed;
                        memcpy(replacement,file->buffer_base,used);
                        file->flags = (file->flags & ~0x480U) | 0x80U;
                    } else {
                        replacement = medius_newlib_realloc_r(reent,old_buffer,capacity);
                        if (replacement == NULL) {
                            medius_newlib_free_r(reent,file->buffer_base);
                            file->flags = file->flags & ~0x80U;
                            goto allocation_failed;
                        }
                    }
                    file->buffer_base = replacement;
                    file->cursor = (char *)((uintptr_t)replacement + used);
                    file->buffer_capacity = (int)capacity;
                    file->write_remaining = (int)(capacity - used);
                    copied = left;
                }
                memmove(file->cursor,input,copied);
                file->write_remaining = (int)((unsigned int)file->write_remaining - copied);
                file->cursor = (char *)((uintptr_t)file->cursor + copied);
                consumed = left;
            } else {
                char *base = file->buffer_base;
                bool buffer_copy = (uintptr_t)base < (uintptr_t)cursor;
                int capacity = 0;
                if (!buffer_copy) {
                    capacity = file->buffer_capacity;
                    buffer_copy = left < (unsigned int)capacity;
                }
                if (buffer_copy) {
                    consumed = room < left ? room : left;
                    memmove(cursor,input,consumed);
                    unsigned int remaining = (unsigned int)file->write_remaining;
                    char *current_cursor = file->cursor;
                    remaining -= consumed;
                    current_cursor = (char *)((uintptr_t)current_cursor + consumed);
                    file->write_remaining = (int)remaining;
                    file->cursor = current_cursor;
                    if (remaining == 0 && medius_newlib_flush_file(reent,stream) != 0)
                        goto failed;
                } else {
                    int chunk = (int)(left < 0x7fffffffU ? left : 0x7fffffffU);
                    int remainder;
                    __asm__ volatile ("rems %0, %1, %2" : "=a"(remainder) : "a"(chunk),"a"(capacity));
                    chunk -= remainder;
                    int (*writer)(NewlibReent *,void *,const char *,int) = file->write_callback;
                    void *cookie = file->cookie;
                    int written = writer(reent,cookie,input,chunk);
                    if (written <= 0)
                        goto failed;
                    consumed = (unsigned int)written;
                }
            }
            unsigned int residual = io->residual;
            input = (const void *)((uintptr_t)input + consumed);
            residual -= consumed;
            io->residual = residual;
            left -= consumed;
            if (residual == 0)
                return 0;
        } while (true);
    }

    bool have_newline_distance = false;
    unsigned int newline_distance = 0;
    do {
        while (left == 0) {
            input = next->base;
            left = next->length;
            have_newline_distance = false;
            next = (const volatile MediusNewlibInputVector *)((uintptr_t)next + 8U);
        }
        if (!have_newline_distance) {
            const void *newline = memchr(input,10,left);
            newline_distance = left + 1U;
            if (newline != NULL)
                newline_distance = (uintptr_t)newline + 1U - (uintptr_t)input;
        }
        int capacity = file->buffer_capacity;
        unsigned int available = (unsigned int)file->write_remaining;
        char *cursor = file->cursor;
        char *base = file->buffer_base;
        unsigned int selected = newline_distance < left ? newline_distance : left;
        available += (unsigned int)capacity;
        unsigned int consumed;
        if ((uintptr_t)base < (uintptr_t)cursor && (int)available < (int)selected) {
            memmove(cursor,input,available);
            file->cursor = (char *)((uintptr_t)file->cursor + available);
            if (medius_newlib_flush_file(reent,stream) != 0)
                goto failed;
            consumed = available;
        } else if ((int)selected < capacity) {
            memmove(cursor,input,selected);
            file->write_remaining = (int)((unsigned int)file->write_remaining - selected);
            file->cursor = (char *)((uintptr_t)file->cursor + selected);
            consumed = selected;
        } else {
            int (*writer)(NewlibReent *,void *,const char *,int) = file->write_callback;
            void *cookie = file->cookie;
            int written = writer(reent,cookie,input,capacity);
            if (written <= 0)
                goto failed;
            consumed = (unsigned int)written;
        }
        newline_distance -= consumed;
        have_newline_distance = true;
        if (newline_distance == 0) {
            if (medius_newlib_flush_file(reent,stream) != 0)
                goto failed;
            have_newline_distance = false;
        }
        unsigned int residual = io->residual;
        input = (const void *)((uintptr_t)input + consumed);
        residual -= consumed;
        io->residual = residual;
        left -= consumed;
        if (residual == 0)
            return 0;
    } while (true);
allocation_failed:
    reent->error_number = 12;
failed:
    file->flags = file->flags | 0x40U;
    return -1;
}

/* Native entry: 0x4201f374. */
/* Original function-byte SHA-256:
 * e7c21231a72aa5222ad30c57e6c28cdf81bd2eb237d2165b0d448aa7d53be48b. */
/* * Newlib __sprint_r: call the vector writer only for nonzero residual. After
 * any such call clear residual even on failure, then always clear vector count.
 * Return writer status or0 for an empty request. Keep stored vectors unchanged;
 * no pointer validation, allocation, lock or independent flush is added.
 */
int medius_newlib_flush_vectors(NewlibReent *reent,NewlibFile *stream,
    MediusNewlibStringWriteRequest *request)
{
    volatile MediusNewlibStringWriteRequest *io = request;
    int result = 0;
    if (io->residual != 0) {
        result = medius_newlib_write_vectors(reent,stream,request);
        io->residual = 0;
    }
    io->count = 0;
    return result;
}

/* Native entry: 0x4201f490. */
/* Original function-byte SHA-256:
 * 5772a8df79e720255344434e84df1ee5d135e45e5b2fcba79ca9297081ffd1fc. */
/* * Stream-walker visitor used before refilling unbuffered/line-buffered input.
 * Ignore supplied reent. If FILE flags contain BOTH line-buffer1 and write8,
 * get current thread reent and return its stream-flush status; otherwise0.
 * No descriptor/output test, lock or local error mutation.
 */
int medius_newlib_flush_line_visitor(NewlibReent *ignored_reent,NewlibFile *stream)
{
    (void)ignored_reent;
    if ((((volatile NewlibFile *)stream)->flags & 9U) == 9U)
        return medius_newlib_flush_file(medius_current_newlib_reent(),stream);
    return 0;
}

/* Native entry: 0x4201f4b0. */
/* Original function-byte SHA-256:
 * 75bd8516ac2ccddce551553e94c78a2bfded7750c5669a0b48eebe3fc95b7cef. */
/* * Newlib __srefill_r. Initialize stdio when non-NULL reent.cleanup is NULL,
 * zero read_remaining, and return-1 immediately for a cached EOF flag20.
 * Require read4 or update10: a non-readable stream sets errno9/error40.
 * Switching write8 to read flushes first; failure returns-1 without new flag
 * mutation. Success clears write8/counters and sets read4. Existing ungetc
 * storage is freed unless inline; clear pointer, restore saved read count and
 * cursor, returning0 when restored bytes exist. No free of inline storage.
 *
 * Create a missing buffer, then for flags1/2 temporarily publish flags1 and
 * walk global streams to flush line output. Restore the cached flags HALF,
 * ignoring walker mutations/status, and conditionally flush this FILE unlocked
 * from the same saved flags. Sample buffer/reader/capacity/cookie, publish cursor
 * then invoke all FOUR reader arguments. Store returned count: positive0success;
 * zero sets EOF20; negative clears count and sets error40. Both failures return
 *-1. No pointer checks, stream lock, callback-null check or retry bound here.
 */
int medius_newlib_refill_file(NewlibReent *reent,NewlibFile *stream)
{
    volatile NewlibReent *context = reent;
    volatile NewlibFile *file = stream;
    if (context != NULL && context->cleanup == NULL)
        medius_newlib_initialize_stdio_context(reent);
    file->read_remaining = 0;
    unsigned int flags = file->flags;
    if ((flags & 0x20U) != 0)
        return -1;
    if ((flags & 4U) == 0) {
        if ((flags & 0x10U) == 0) {
            context->error_number = 9;
            file->flags = flags | 0x40U;
            return -1;
        }
        if ((flags & 8U) != 0) {
            int result = medius_newlib_flush_file(reent,stream);
            if (result != 0)
                return -1;
            flags = file->flags & ~8U;
            file->write_remaining = result;
            file->line_write_remaining = result;
        }
        file->flags = flags | 4U;
    } else {
        char *ungetc = file->ungetc_buffer;
        if (ungetc != NULL) {
            if (ungetc != (char *)stream->inline_ungetc)
                medius_newlib_free_r(reent,ungetc);
            file->ungetc_buffer = NULL;
            int saved = file->saved_read_remaining;
            file->read_remaining = saved;
            if (saved != 0) {
                file->cursor = file->saved_cursor;
                return 0;
            }
        }
    }
    if (file->buffer_base == NULL)
        medius_newlib_make_file_buffer(reent,stream);
    flags = file->flags;
    if ((flags & 3U) != 0) {
        file->flags = 1;
        (void)medius_newlib_walk_streams(MEDIUS_NEWLIB_STARTUP_REENT,
            medius_newlib_flush_line_visitor,MEDIUS_NEWLIB_STDIO_GLUE);
        file->flags = flags;
        if ((flags & 9U) == 9U)
            (void)medius_newlib_flush_file_unlocked(reent,stream);
    }
    char *buffer = file->buffer_base;
    int (*reader)(NewlibReent *,void *,char *,int) = file->read_callback;
    int capacity = file->buffer_capacity;
    void *cookie = file->cookie;
    file->cursor = buffer;
    int count = reader(reent,cookie,buffer,capacity);
    file->read_remaining = count;
    if (count > 0)
        return 0;
    flags = file->flags;
    if (count == 0)
        file->flags = flags | 0x20U;
    else {
        file->read_remaining = 0;
        file->flags = flags | 0x40U;
    }
    return -1;
}
