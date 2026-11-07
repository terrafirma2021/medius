/* Medius v3.4.7 device — runtime/stdio_setup.c.
 */

#include "../include/types.h"

/* Source reconstruction utilities; not additional native firmware entries.
 * Typed boundaries to separate native functions. Their bodies retain separate
 * review status; this file does not replace the VFS or stream-seek algorithms. */
extern NewlibReent *stdio_current_context(void) __asm__("__getreent");
extern void *stdio_allocate_context(NewlibReent *,unsigned int) __asm__("_malloc_r");
extern void stdio_release_allocation(NewlibReent *,void *) __asm__("_free_r");
extern int stdio_open_context(NewlibReent *,const char *,unsigned int,unsigned int)
    __asm__("FUN_42039ebc");
extern int stdio_seek_context(NewlibReent *,NewlibFile *,long,int)
    __asm__("FUN_420186e8");

/* Native entry: 0x420185e4. */
/*
 * Medius v3.4.7 — device application; 0x420185e4.
 * Instruction-checked recovered C.
 * Original function-byte SHA-256:
 * 74f57397b9e0ecf2a436f0d7d485a602d8ff02e3aa5baafd32432cedc3964e47.
 */

/*
 * Parse mode before reserving a FILE. Invalid mode or failed reservation returns
 * NULL. Open the path through the VFS boundary with parsed flags and mode 0666.
 * A negative descriptor releases the slot under the pool lock: sample its lock
 * BEFORE clearing primary flags, destroy that sampled lock, unlock, return NULL.
 * It does not close a descriptor, free the slot or reset other fields/errno.
 *
 * For a nonnegative descriptor, conditionally acquire the stream lock according
 * to its current secondary bit 0 / primary flag 0x200. Install read callback, low 16-bit
 * descriptor, write callback, parsed primary flags, seek callback, self cookie,
 * then close callback in native order. Descriptor values above 32767 wrap in the
 * signed 16-bit FILE field. Append mode calls the separate stream-seek entry with
 * offset 0 / origin 2 and ignores its result. Reread both lock-control fields and
 * current lock before conditional release; return the FILE even after a failed
 * append seek. No pathname/mode/context validation or extra cleanup is added.
 */
NewlibFile *medius_newlib_open_file(NewlibReent *reent,
    const char *path,const char *mode)
{
    unsigned int open_flags;
    unsigned int flags = medius_newlib_parse_file_mode(reent,mode,&open_flags);
    if (flags == 0) return NULL;
    NewlibFile *file = medius_newlib_allocate_file(reent);
    if (!file) return NULL;
    volatile NewlibFile *stream = file;
    int descriptor = stdio_open_context(reent,path,open_flags,0666);
    if (descriptor < 0) {
        medius_newlib_file_pool_lock();
        NewlibLock lock = stream->lock;
        stream->flags = 0;
        __retarget_lock_close_recursive(lock);
        medius_newlib_file_pool_unlock();
        return NULL;
    }
    if ((stream->secondary_flags & 1) == 0 && (stream->flags & 0x0200U) == 0)
        __retarget_lock_acquire_recursive(stream->lock);
    stream->read_callback = medius_newlib_stream_read;
    stream->file_descriptor = (short)descriptor;
    stream->write_callback = medius_newlib_stream_write;
    stream->flags = (unsigned short)flags;
    stream->seek_callback = medius_newlib_stream_seek;
    stream->cookie = file;
    stream->close_callback = medius_newlib_stream_close;
    if (flags & 0x0100U)
        (void)stdio_seek_context(reent,file,0,2);
    if ((stream->secondary_flags & 1) == 0 && (stream->flags & 0x0200U) == 0)
        __retarget_lock_release_recursive(stream->lock);
    return file;
}

/* Native entry: 0x4201869c. */
/*
 * Medius v3.4.7 — device application; 0x4201869c.
 * Instruction-checked recovered C.
 * Original function-byte SHA-256:
 * 148aff29b813d5dd594ab338559c32a3c2062aa7b6a8bf74ab2309e2290712fc.
 */

/*
 * Obtain the current reentrancy context once, then forward it and the unchanged
 * path/mode pointers to the context-taking opener. Return its FILE pointer,
 * including NULL, unchanged. No local validation, errno reset or extra lock.
 */
NewlibFile *medius_newlib_open_file_current(const char *path,const char *mode)
{
    NewlibReent *reent = stdio_current_context();
    return medius_newlib_open_file(reent,path,mode);
}

/* Native entry: 0x42018bbc. */
/*
 * Medius v3.4.7 — device application; 0x42018bbc.
 * Instruction-checked recovered C.
 * Original function-byte SHA-256:
 * 5c3c29e28915f047d66c81f4103d2a9276873cd248bdb201efadfb452b2d1682.
 */

/*
 * Prepare FILE counters/buffering for writing. Query the CURRENT task's reent
 * once and initialize THAT context if non-NULL with a NULL cleanup hook; errno,
 * frees and buffer creation below use the caller-supplied reent instead.
 * If neither write flag 0x08 nor update flag 0x10 is set, store errno 9 and set error flag 0x40 using
 * the sampled flags, returning -1. When changing read/update to write, release
 * non-inline ungetc storage, clear its pointer after free, reread flags and
 * clear read flag 0x04 / EOF flag 0x20; reset read_remaining and cursor, then set write flag 0x08.
 *
 * With a NULL base, create a buffer unless sampled(flags&0x280)==0x200.
 * Reread flags afterward. Line buffering sets write_remaining=0 then the
 * modulo 2^32 negation of capacity as line_write_remaining. Otherwise write space
 * is capacity, or zero under unbuffered flag 0x02; line_write_remaining is untouched.
 * NULL base is an error only when fresh flags contain owned-buffer flag 0x80.
 * Error paths set 0x40; other cases return zero. No stream lock, pointer guard,
 * generic flushing, saved-read count clear or rollback occurs here.
 */
int medius_newlib_prepare_write(NewlibReent *reent,NewlibFile *file)
{
    NewlibReent *current = stdio_current_context();
    if (current && !((volatile NewlibReent *)current)->cleanup)
        medius_newlib_initialize_stdio_context(current);
    volatile NewlibFile *stream = file;
    unsigned short flags = stream->flags;
    if ((flags & 0x0008U) == 0) {
        if ((flags & 0x0010U) == 0) {
            ((volatile NewlibReent *)reent)->error_number = 9;
            stream->flags = flags | 0x0040U;
            return -1;
        }
        if (flags & 0x0004U) {
            char *ungetc_buffer = stream->ungetc_buffer;
            if (ungetc_buffer) {
                if (ungetc_buffer != (char *)file->inline_ungetc)
                    stdio_release_allocation(reent,ungetc_buffer);
                stream->ungetc_buffer = NULL;
            }
            flags = stream->flags & 0xffdbU;
            stream->read_remaining = 0;
            stream->cursor = stream->buffer_base;
        }
        flags |= 0x0008U;
        stream->flags = flags;
    }
    if (!stream->buffer_base && (flags & 0x0280U) != 0x0200U)
        medius_newlib_make_file_buffer(reent,file);
    flags = stream->flags;
    if (flags & 1) {
        stream->write_remaining = 0;
        stream->line_write_remaining =
            (int)(0U - (unsigned int)stream->buffer_capacity);
    } else {
        int capacity = 0;
        if ((flags & 2) == 0) capacity = stream->buffer_capacity;
        stream->write_remaining = capacity;
    }
    if (!stream->buffer_base && (flags & 0x0080U)) {
        stream->flags = flags | 0x0040U;
        return -1;
    }
    return 0;
}

/* Native entry: 0x420214d8. */
/*
 * Medius v3.4.7 — device application; 0x420214d8.
 * Instruction-checked recovered C.
 * Original function-byte SHA-256:
 * 97f7e48ee012d1ca1c5d13ecc5b1cf6316421429d16a963750464d4b337e3227.
 */

/*
 * Accept only initial 'r', 'w' or 'a': return FILE flags 4, 8, 0x108 respectively.
 * Invalid first byte writes errno 22, returns zero and leaves *open_flags alone.
 * Valid initial bytes scan every suffix byte through NUL. '+' replaces FILE
 * read/write bits with update flag 0x10 and access bits with 2; 'x' adds O_EXCL 0x800.
 * All other suffix bytes are ignored, including 'b' and additional mode letters;
 * repeated '+'/'x' are accepted. Creation bases are 0, 0x600, 0x208 respectively.
 * Store the combined open word only after the scan. No NULL check, suffix
 * grammar restriction, errno reset or length bound is supplied. The valid-mode
 * string must be accessible through its NUL terminator; outputs may alias.
 */
unsigned int medius_newlib_parse_file_mode(NewlibReent *reent,
    const char *mode,unsigned int *open_flags)
{
    const volatile unsigned char *cursor = (const unsigned char *)mode;
    unsigned int flags,access,creation;
    unsigned char first = *cursor;
    if (first == 'r') {flags=4;access=0;creation=0;}
    else if (first == 'w') {flags=8;access=1;creation=0x0600;}
    else if (first == 'a') {flags=0x0108;access=1;creation=0x0208;}
    else {
        ((volatile NewlibReent *)reent)->error_number = 22;
        return 0;
    }
    unsigned char next;
    while ((next = *++cursor) != 0) {
        if (next == '+') {flags=(flags & 0xffffffe3U)|0x10U;access=(access & 0xfffffffcU)|2U;}
        else if (next == 'x') access |= 0x0800U;
    }
    *(volatile unsigned int *)open_flags = access | creation;
    return flags;
}

/* Native entry: 0x4201f398. */
/*
 * Medius v3.4.7 — device application; 0x4201f398.
 * Instruction-checked recovered C.
 * Original function-byte SHA-256:
 * edf32276529f6429825c8368b259c7e677027e257d3b53a4ed969b6b9143ea7b.
 */

/*
 * Select buffer capacity and return FILE seek-optimization flags. A negative
 * signed 16-bit descriptor skips fstat. A negative fstat result uses the same path:
 * sample FILE flags, set *is_character=0, then capacity 64 when owned-buffer flag 0x80
 * is set, otherwise 128; return zero without changing block_size.
 * Nonnegative fstat uses mode&0xf000: publish character status (mode==0x2000),
 * then read signed block_size. Positive values are published as capacity and
 * FILE block_size, returning 0x400 for regular(mode==0x8000), otherwise 0x800.
 * Nonpositive block_size publishes 128 and returns 0x800 without changing FILE
 * block_size. fstat receives a full 88-byte SDK-compatible stat buffer; only
 * mode+4 and block_size+72 are consumed. Fresh fields and native store order
 * are retained; no errno restoration, pointer checks or extra lock occurs.
 */
unsigned int medius_newlib_select_buffer_size(NewlibReent *reent,
    NewlibFile *file,int *capacity,unsigned int *is_character)
{
    volatile NewlibFile *stream = file;
    int descriptor = stream->file_descriptor;
    volatile VfsStat status;
    if (descriptor < 0 || medius_vfs_status(reent,descriptor,(VfsStat *)&status) < 0) {
        unsigned short flags = stream->flags;
        *(volatile unsigned int *)is_character = 0;
        *(volatile int *)capacity = (flags & 0x0080U) ? 64 : 128;
        return 0;
    }
    unsigned int type = status.mode & 0xf000U;
    *(volatile unsigned int *)is_character = type == 0x2000U;
    int preferred = status.block_size;
    if (preferred > 0) {
        *(volatile int *)capacity = preferred;
        stream->block_size = preferred;
        if (type == 0x8000U) return 0x0400U;
    } else *(volatile int *)capacity = 128;
    return 0x0800U;
}

/* Native entry: 0x4201f404. */
/*
 * Medius v3.4.7 — device application; 0x4201f404.
 * Instruction-checked recovered C.
 * Original function-byte SHA-256:
 * 11e4acd5ba918df3d2bd2b015b09697efa8f75acba03d63587a75bd17728f727.
 */

/*
 * Under initial unbuffered flag 0x02, install the FILE's own emergency byte+0x47
 * as cursor/base with capacity 1. Otherwise select capacity/type hints, cache
 * capacity before malloc, then reread FILE flags after allocation.
 * On allocation failure, primary flag 0x200 leaves the stream as callbacks left
 * it. Otherwise clear low buffering bits, set flag 0x02, and install emergency byte.
 * Success sets owned-buffer flag 0x80, then cursor, base and cached capacity. For
 * character devices call the local unsupported-isatty entry; its -1 is nonzero,
 * so clear low buffering bits and set line-buffered flag 0x01. That stub also leaves
 * errno 88. Finally OR the cached seek hints into freshly read primary flags.
 * No old-buffer free, counter reset, memset, rollback or stream lock occurs.
 */
void medius_newlib_make_file_buffer(NewlibReent *reent,NewlibFile *file)
{
    volatile NewlibFile *stream = file;
    if ((stream->flags & 2) == 0) {
        int selected_capacity;
        unsigned int is_character;
        unsigned int hints = medius_newlib_select_buffer_size(reent,file,
            &selected_capacity,&is_character);
        int capacity = selected_capacity;
        char *buffer = stdio_allocate_context(reent,(unsigned int)capacity);
        unsigned short flags = stream->flags;
        if (buffer) {
            stream->flags = flags | 0x0080U;
            stream->cursor = buffer;
            stream->buffer_base = buffer;
            stream->buffer_capacity = capacity;
            if (is_character && medius_newlib_isatty_unsupported(reent,
                    stream->file_descriptor) != 0)
                stream->flags = (stream->flags & 0xfffcU) | 1U;
            stream->flags = stream->flags | (unsigned short)hints;
            return;
        }
        if (flags & 0x0200U) return;
        stream->flags = (flags & 0xfffcU) | 2U;
    }
    char *emergency = (char *)&file->emergency_byte;
    stream->cursor = emergency;
    stream->buffer_base = emergency;
    stream->buffer_capacity = 1;
}

/* Native entry: 0x42020ce8. */
/*
 * Medius v3.4.7 — device application; 0x42020ce8.
 * Instruction-checked recovered C.
 * Original function-byte SHA-256:
 * 840af1ddcd6b8daead17e725bc14a2ed2fb329e99434d230fff37847b633159a.
 */

/*
 * Unsupported isatty context entry: ignore the descriptor, write errno 88 into
 * the supplied accessible reent, and return -1. It never checks a device or
 * calls a VFS backend. The caller tests nonzero, so -1 enables its line-buffer
 * path; this is not evidence that a descriptor names a terminal.
 */
int medius_newlib_isatty_unsupported(NewlibReent *reent,int descriptor)
{
    (void)descriptor;
    ((volatile NewlibReent *)reent)->error_number = 88;
    return -1;
}
