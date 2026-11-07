/* Medius v3.4.7 device: Newlib file positioning. */
#include "../include/types.h"

/* Native entry: 0x420186e8. */
/* Original function-byte SHA-256:
 * f587552e25492759db8b419b0b4a8ae2f6bac14109adca3fea9b40221ea34ef5. */
/*
 * Newlib _fseek_r wrapper: forward reent, FILE,32-bit signed offset and origin
 * unchanged to _fseeko_r's native implementation, returning its status. No
 * current-context lookup, offset conversion, locking or local validation.
 */
int medius_newlib_seek_file(NewlibReent *reent,NewlibFile *stream,
    long offset,int origin)
{
    return medius_newlib_seek_file_offset(reent,stream,offset,origin);
}

/* Native entry: 0x42018c60. */
/* Original function-byte SHA-256:
 * 5e7dd9aa298cf9320e15d8555076ec28887787d18eb8faa7278d8980bdc968ba. */
/*
 * Newlib _fseeko_r,32-bit off_t. Initialize stdio when reent exists but cleanup
 * is NULL; conditionally acquire recursive FILE lock. Flush append/write streams
 * before caching the seek callback, ignoring this flush result. Missing callback
 * sets errno29/ESPIPE; origin other than0/1/2 sets errno22/EINVAL. Both return-1.
 * SEEK_CUR performs another ignored-status flush, obtains cached/queried offset,
 * adjusts for unread/ungetc or pending-write bytes, adds offset modulo32 and
 * changes origin to SEEK_SET. A failed position query returns-1 immediately.
 *
 * Create a missing buffer, then consider the read-only buffered optimization
 * unless flags81a are set. Without cached optimization400, require standard
 * seek callback, nonnegative descriptor and regular-file fstat; otherwise mark
 * no-optimization800 and fall back. Save reported block size without validation.
 * For SEEK_END obtain size; derive the current buffer's physical span, including
 * saved pre-ungetc data. An in-buffer target changes cursor/count and discards
 * ungetc. Native lower-bound comparison is SIGNED; upper-bound is UNSIGNED.
 * Otherwise seek to target & -block_size, clear/readjust stream, optionally
 * refill and skip bytes. Failure/short refill falls back AFTER these mutations.
 *
 * Fallback flushes and invokes the cached seek callback with current offset/
 * origin. Failure returns-1 without rollback. Success frees noninline ungetc,
 * resets cursor/count, clears EOF20/no-optimization800. Optimized success clears
 * EOF only. Every success zeroes the8-byte multibyte state. Unlock decisions use
 * freshly read secondary flags then FILE flags, even if callbacks changed them;
 * this can differ from the initial acquisition decision. No pointer, block-size,
 * signed-overflow/range or callback ownership validation; native arithmetic wraps.
 */
int medius_newlib_seek_file_offset(NewlibReent *reent,NewlibFile *stream,
    long offset,int origin)
{
    volatile NewlibReent *context = reent;
    volatile NewlibFile *file = stream;
    if (context != NULL && context->cleanup == NULL)
        medius_newlib_initialize_stdio_context(reent);
    if ((file->secondary_flags & 1) == 0 && (file->flags & 0x200U) == 0)
        __retarget_lock_acquire_recursive(file->lock);
    if ((file->flags & 0x108U) == 0x108U)
        (void)medius_newlib_flush_file(reent,stream);
    long (*seek)(NewlibReent *,void *,long,int) = file->seek_callback;
    if (seek == NULL) {
        context->error_number = 29;
        goto failure;
    }
    unsigned int requested = (unsigned int)offset;
    unsigned int current = 0;
    bool have_current = false;
    if (origin == 1) {
        (void)medius_newlib_flush_file(reent,stream);
        if ((file->flags & 0x1000U) != 0)
            current = file->cached_offset_bits;
        else {
            long position = seek(reent,file->cookie,0,1);
            if (position == -1)
                goto failure;
            current = (unsigned int)position;
        }
        unsigned int flags = file->flags;
        if ((flags & 4U) != 0) {
            current -= (unsigned int)file->read_remaining;
            if (file->ungetc_buffer != NULL)
                current -= (unsigned int)file->saved_read_remaining;
        } else if ((flags & 8U) != 0) {
            char *cursor = file->cursor;
            if (cursor != NULL)
                current += (uintptr_t)cursor - (uintptr_t)file->buffer_base;
        }
        requested += current;
        have_current = true;
        origin = 0;
    } else if (((unsigned int)origin & ~2U) != 0) {
        context->error_number = 22;
        goto failure;
    }
    if (file->buffer_base == NULL)
        medius_newlib_make_file_buffer(reent,stream);
    unsigned int flags = file->flags;
    if ((flags & 0x81aU) != 0)
        goto fallback;
    VfsStat status;
    volatile VfsStat *observed_status = &status;
    if ((flags & 0x400U) == 0) {
        if (seek != medius_newlib_stream_seek)
            goto disable_optimization;
        int descriptor = file->file_descriptor;
        if (descriptor < 0 || medius_vfs_status(reent,descriptor,&status) != 0)
            goto disable_optimization;
        if ((observed_status->mode & 0xf000U) != 0x8000U)
            goto disable_optimization;
        long block_size = observed_status->block_size;
        flags = file->flags;
        file->block_size = (int)block_size;
        file->flags = flags | 0x400U;
    }
    unsigned int target = requested;
    if (origin != 0) {
        int descriptor = file->file_descriptor;
        if (medius_vfs_status(reent,descriptor,&status) != 0)
            goto fallback;
        target = requested + (unsigned int)observed_status->size;
    }
    if (!have_current) {
        if ((file->flags & 0x1000U) != 0)
            current = file->cached_offset_bits;
        else {
            long position = seek(reent,file->cookie,0,1);
            if (position == -1)
                goto fallback;
            current = (unsigned int)position;
        }
        current -= (unsigned int)file->read_remaining;
        if (file->ungetc_buffer != NULL)
            current -= (unsigned int)file->saved_read_remaining;
    }
    char *ungetc = file->ungetc_buffer;
    char *base = file->buffer_base;
    unsigned int available = (unsigned int)file->read_remaining;
    unsigned int used,first_offset;
    if (ungetc != NULL) {
        char *saved_cursor = file->saved_cursor;
        first_offset = current + available;
        used = (uintptr_t)saved_cursor - (uintptr_t)base;
        available = (unsigned int)file->saved_read_remaining;
        first_offset -= used;
    } else {
        used = (uintptr_t)file->cursor - (uintptr_t)base;
        first_offset = current - used;
    }
    unsigned int span = available + used;
    if ((int)target >= (int)first_offset && target < first_offset + span) {
        unsigned int within = target - first_offset;
        file->cursor = (char *)((uintptr_t)base + within);
        file->read_remaining = (int)(span - within);
        if (ungetc != NULL) {
            if (ungetc != (char *)stream->inline_ungetc)
                medius_newlib_free_r(reent,ungetc);
            file->ungetc_buffer = NULL;
        }
        file->flags = file->flags & ~0x20U;
        goto success;
    }
    unsigned int aligned = (0U - (unsigned int)file->block_size) & target;
    if (seek(reent,file->cookie,(long)aligned,0) == -1)
        goto fallback;
    file->read_remaining = 0;
    base = file->buffer_base;
    ungetc = file->ungetc_buffer;
    file->cursor = base;
    if (ungetc != NULL) {
        if (ungetc != (char *)stream->inline_ungetc)
            medius_newlib_free_r(reent,ungetc);
        file->ungetc_buffer = NULL;
    }
    file->flags = file->flags & ~0x20U;
    unsigned int skip = target - aligned;
    if (skip != 0) {
        if (medius_newlib_refill_file(reent,stream) != 0)
            goto fallback;
        unsigned int remaining = (unsigned int)file->read_remaining;
        if (remaining < skip)
            goto fallback;
        char *cursor = file->cursor;
        file->cursor = (char *)((uintptr_t)cursor + skip);
        file->read_remaining = (int)(remaining - skip);
    }
    goto success;
disable_optimization:
    file->flags = file->flags | 0x800U;
fallback:
    if (medius_newlib_flush_file(reent,stream) != 0)
        goto failure;
    if (seek(reent,file->cookie,(long)requested,origin) == -1)
        goto failure;
    ungetc = file->ungetc_buffer;
    if (ungetc != NULL) {
        if (ungetc != (char *)stream->inline_ungetc)
            medius_newlib_free_r(reent,ungetc);
        file->ungetc_buffer = NULL;
    }
    file->cursor = file->buffer_base;
    file->read_remaining = 0;
    file->flags = file->flags & ~0x820U;
success:
    memset(&stream->multibyte_state,0,8);
    if ((file->secondary_flags & 1) == 0 && (file->flags & 0x200U) == 0)
        __retarget_lock_release_recursive(file->lock);
    return 0;
failure:
    if ((file->secondary_flags & 1) == 0 && (file->flags & 0x200U) == 0)
        __retarget_lock_release_recursive(file->lock);
    return -1;
}
