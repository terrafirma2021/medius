/* Medius v3.4.7 device — runtime/stdio_buffer.c.
 */

#include "../include/types.h"

/* Source reconstruction utilities; not additional native firmware entries.
 * Use the recovered context type at Newlib's external allocation boundary. */
extern void stdio_release_allocation(NewlibReent *,void *)
    __asm__("_free_r");

/* Native entry: 0x420181a0. */
/*
 * Medius v3.4.7 — device application; 0x420181a0.
 * Instruction-checked recovered C.
 * Original function-byte SHA-256:
 * 86f34d3d8cf69e0abfe20259b634b1376a664e5d5acc35e3d2184f94d333a76b.
 */

/*
 * Close a FILE using the supplied reentrancy context. NULL file returns zero.
 * Initialize a non-NULL context when its cleanup hook is NULL. Unless secondary
 * flag bit 0 is set, acquire the stream lock when primary bit 0x200 is clear.
 * The empty-FILE check is skipped when secondary bit 0 is clear and primary bit
 * 0x200 is set. On the empty path, reread secondary bit 0 and conditionally
 * release the current lock, then return zero.
 *
 * Flush the stream even if the close callback is NULL. A negative close result
 * forces -1; otherwise retain the flush result. Read callback/cookie and later
 * buffer fields after earlier calls. Free the main buffer only under flag 0x80;
 * free non-inline ungetc storage, then clear its pointer; free a non-NULL line
 * buffer, then clear its pointer. Main-buffer/descriptor/counter fields remain.
 * Under the pool lock, clear primary flags, conditionally release the freshly
 * read stream lock under secondary bit 0 only, destroy its current lock, then
 * unlock the pool. This release intentionally does not test primary bit 0x200.
 * There is no rollback, lock-balance repair, errno reset or explicit MEMW.
 */
int medius_newlib_close_file(NewlibReent *reent,NewlibFile *file)
{
    if (!file) return 0;
    if (reent && !((volatile NewlibReent *)reent)->cleanup)
        medius_newlib_initialize_stdio_context(reent);
    volatile NewlibFile *stream = file;
    bool check_empty = true;
    if ((stream->secondary_flags & 1) == 0) {
        if (stream->flags & 0x0200U) check_empty = false;
        else __retarget_lock_acquire_recursive(stream->lock);
    }
    if (check_empty && stream->flags == 0) {
        if ((stream->secondary_flags & 1) == 0)
            __retarget_lock_release_recursive(stream->lock);
        return 0;
    }
    int status = medius_newlib_flush_file_unlocked(reent,file);
    int (*close_callback)(NewlibReent *,void *) = stream->close_callback;
    if (close_callback && close_callback(reent,stream->cookie) < 0)
        status = -1;
    if (stream->flags & 0x0080U)
        stdio_release_allocation(reent,stream->buffer_base);
    char *ungetc_buffer = stream->ungetc_buffer;
    if (ungetc_buffer) {
        if (ungetc_buffer != (char *)file->inline_ungetc)
            stdio_release_allocation(reent,ungetc_buffer);
        stream->ungetc_buffer = NULL;
    }
    char *line_buffer = stream->line_buffer;
    if (line_buffer) {
        stdio_release_allocation(reent,line_buffer);
        stream->line_buffer = NULL;
    }
    medius_newlib_file_pool_lock();
    stream->flags = 0;
    if ((stream->secondary_flags & 1) == 0)
        __retarget_lock_release_recursive(stream->lock);
    __retarget_lock_close_recursive(stream->lock);
    medius_newlib_file_pool_unlock();
    return status;
}

/* Native entry: 0x42018268. */
/*
 * Medius v3.4.7 — device application; 0x42018268.
 * Instruction-checked recovered C.
 * Original function-byte SHA-256:
 * a598e43475f3720eb3f4d795288fdaddb85695c1cf51ecd70e919639473e845d.
 */

/*
 * Flush one accessible FILE without taking a lock or initializing reent.
 * In write mode, cache base/cursor, reset cursor to base, and set write space to
 * capacity only when neither low buffering bit is set. Repeatedly call the
 * freshly read write callback/cookie with the cached advanced buffer and the
 * signed remaining count. Positive partial results advance modulo 2^32; zero or
 * negative results set flag 0x40 and return -1. A result larger than requested
 * is accepted. No NULL callback guard or failed-write cursor repair is added.
 *
 * Otherwise set flag 0x800. With no positive read/saved-read count, or no seek
 * callback, return zero retaining that flag. Save errno, then clear it. Obtain
 * the current offset from the cache only under the INITIAL flag 0x1000; otherwise
 * call seek(cookie,0,SEEK_CUR). Exactly -1 with errno 22 or 29 restores old errno
 * and returns zero immediately. Other nonzero errors set flag 0x40 and return -1.
 * If result -1 leaves errno zero, continue with its full 32-bit value.
 *
 * Under freshly read flag4, subtract read_remaining and, when ungetc is present,
 * saved_read_remaining modulo 2^32. Reread seek callback/cookie and seek absolute.
 * Exactly -1 is tolerated only with errno 0, 22 or 29. On success clear flag 0x800,
 * reset read_remaining/cursor, and update the cached offset only when the flags
 * sampled after seek contained 0x1000 and (result!=-1 or current errno==0).
 * Sample ungetc storage, restore old errno, then free it unless inline and clear
 * its pointer. Free-side errno changes survive. Fresh fields after callbacks,
 * untouched storage and native arithmetic/error distinctions are retained.
 */
int medius_newlib_flush_file_unlocked(NewlibReent *reent,
    NewlibFile *file)
{
    volatile NewlibFile *stream = file;
    volatile NewlibReent *context = reent;
    unsigned short initial_flags = stream->flags;
    if (initial_flags & 0x0008U) {
        unsigned int buffer = (unsigned int)stream->buffer_base;
        if (!buffer) return 0;
        unsigned int pending = (unsigned int)stream->cursor;
        stream->cursor = (char *)buffer;
        pending -= buffer;
        int capacity = 0;
        if ((initial_flags & 3) == 0) capacity = stream->buffer_capacity;
        stream->write_remaining = capacity;
        while ((int)pending >= 1) {
            int (*write_callback)(NewlibReent *,void *,const char *,int) =
                stream->write_callback;
            int written = write_callback(reent,stream->cookie,
                (const char *)buffer,(int)pending);
            if (written < 1) {
                stream->flags = stream->flags | 0x0040U;
                return -1;
            }
            buffer += (unsigned int)written;
            pending -= (unsigned int)written;
        }
        return 0;
    }
    stream->flags = initial_flags | 0x0800U;
    if (stream->read_remaining < 1 && stream->saved_read_remaining < 1)
        return 0;
    long (*seek_callback)(NewlibReent *,void *,long,int) =
        stream->seek_callback;
    if (!seek_callback) return 0;
    int saved_errno = context->error_number;
    context->error_number = 0;
    unsigned int position;
    if (initial_flags & 0x1000U) position = stream->cached_offset_bits;
    else {
        long current = seek_callback(reent,stream->cookie,0,1);
        position = (unsigned int)current;
        if (current == -1) {
            unsigned int error = (unsigned int)context->error_number;
            if (error != 0) {
                if (error == 22 || error == 29) {
                    context->error_number = saved_errno;
                    return 0;
                }
                stream->flags = stream->flags | 0x0040U;
                return -1;
            }
        }
    }
    if (stream->flags & 0x0004U) {
        position -= (unsigned int)stream->read_remaining;
        if (stream->ungetc_buffer)
            position -= (unsigned int)stream->saved_read_remaining;
    }
    seek_callback = stream->seek_callback;
    long result = seek_callback(reent,stream->cookie,(long)position,0);
    unsigned short flags = stream->flags;
    if (result == -1) {
        unsigned int error = (unsigned int)context->error_number;
        if (error != 0 && error != 22 && error != 29) {
            stream->flags = flags | 0x0040U;
            return -1;
        }
    }
    stream->flags = flags & 0xf7ffU;
    stream->read_remaining = 0;
    stream->cursor = stream->buffer_base;
    if ((flags & 0x1000U) && (result != -1 || context->error_number == 0))
        stream->cached_offset = result;
    char *ungetc_buffer = stream->ungetc_buffer;
    context->error_number = saved_errno;
    if (ungetc_buffer) {
        if (ungetc_buffer != (char *)file->inline_ungetc)
            stdio_release_allocation(reent,ungetc_buffer);
        stream->ungetc_buffer = NULL;
    }
    return 0;
}

/* Native entry: 0x4201839c. */
/*
 * Medius v3.4.7 — device application; 0x4201839c.
 * Instruction-checked recovered C.
 * Original function-byte SHA-256:
 * 055dacf504821b941b881b959596ae01bcfbfae88ab543a23b9744c685333fee.
 */

/*
 * Flush one FILE with the native conditional stream-lock protocol. A NULL
 * buffer base returns zero before context initialization or any flags read.
 * Otherwise initialize a non-NULL reent with NULL cleanup hook. Zero primary
 * flags then return zero. Sample secondary bit 0 and the previously read primary
 * bit 0x200 to decide acquisition; pass the current lock handle to the recursive
 * service. Call the unlocked core. Reread secondary flags and, only if bit 0 is
 * clear, primary flags; release the current lock only when bit 0x200 is also
 * clear. Callback mutations therefore affect release independently of acquire.
 * Return the core status unchanged; file must be accessible, and no NULL-file
 * guard, lock-balance repair, errno reset or explicit MEMW is supplied here.
 */
int medius_newlib_flush_file(NewlibReent *reent,NewlibFile *file)
{
    volatile NewlibFile *stream = file;
    if (!stream->buffer_base) return 0;
    if (reent && !((volatile NewlibReent *)reent)->cleanup)
        medius_newlib_initialize_stdio_context(reent);
    unsigned short flags = stream->flags;
    if (flags == 0) return 0;
    if ((stream->secondary_flags & 1) == 0 && (flags & 0x0200U) == 0)
        __retarget_lock_acquire_recursive(stream->lock);
    int result = medius_newlib_flush_file_unlocked(reent,file);
    if ((stream->secondary_flags & 1) == 0 && (stream->flags & 0x0200U) == 0)
        __retarget_lock_release_recursive(stream->lock);
    return result;
}
