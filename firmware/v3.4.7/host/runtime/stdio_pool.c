/* Medius v3.4.7 host — runtime/stdio_pool.c.
 */

#include "../include/types.h"

/* Source reconstruction utilities; not additional native firmware entries.
 * fclose's body remains a separate native review; this is its typed boundary. */
extern int stdio_close_context(NewlibReent *,NewlibFile *)
    __asm__("FUN_42015d0c");
extern void *stdio_allocate_context(NewlibReent *,unsigned int)
    __asm__("_malloc_r");

/* Native entry: 0x42015f60. */
/*
 * Medius v3.4.7 — host application; 0x42015f60.
 * Instruction-checked recovered C.
 * Original function-byte SHA-256:
 * 2fbbaade68c7d2f44dd75a6149d34255abba834072f0e3f4218819ddb7abf8c5.
 */

/*
 * Initialize selected FILE fields in native store order: cursor/read/write
 * counters, secondary flags, buffer base/capacity and line-write count to zero;
 * low16 flags and descriptor; then exactly 8 zero bytes of multibyte state.
 * Install read/write/seek callbacks, cookie=self, then close callback. Initialize
 * the recursive lock only when file equals one of the three fixed standard
 * FILE addresses. Other fields retain their prior bytes, including the lock
 * for nonstandard FILEs. This is not a full 104-byte clear; there is no free,
 * NULL check, pool lock, owner-context initialization or explicit MEMW here.
 */
void medius_newlib_initialize_file(NewlibFile *file,
    unsigned int flags,int descriptor)
{
    volatile NewlibFile *stream = file;
    stream->cursor = NULL;
    stream->read_remaining = 0;
    stream->write_remaining = 0;
    stream->secondary_flags = 0;
    stream->buffer_base = NULL;
    stream->buffer_capacity = 0;
    stream->line_write_remaining = 0;
    stream->flags = (unsigned short)flags;
    stream->file_descriptor = (short)descriptor;
    memset((void *)&stream->multibyte_state,0,8);
    stream->read_callback = medius_newlib_stream_read;
    stream->write_callback = medius_newlib_stream_write;
    stream->seek_callback = medius_newlib_stream_seek;
    stream->cookie = file;
    stream->close_callback = medius_newlib_stream_close;
    if (file == &MEDIUS_NEWLIB_STANDARD_FILES[1] ||
        file == &MEDIUS_NEWLIB_STANDARD_FILES[0] ||
        file == &MEDIUS_NEWLIB_STANDARD_FILES[2])
        __retarget_lock_init_recursive((NewlibLock *)&stream->lock);
}

/* Native entry: 0x42015fd0. */
/*
 * Medius v3.4.7 — host application; 0x42015fd0.
 * Instruction-checked recovered C.
 * Original function-byte SHA-256:
 * c76a5b3f5fb15e235f892f9e7f6de4bd8f86a25302b61c74512f52c7e7b65b82.
 */

/*
 * Walk the fixed global FILE-glue chain with the startup reentrancy context
 * and the context-taking fclose callback. Discard the combined visitor status.
 * No current-context lookup, extra lock, hook reset, allocation or rollback is
 * supplied here; the walker and close callback own their separate behavior.
 */
void medius_newlib_cleanup_global_streams(void)
{
    (void)medius_newlib_walk_streams(MEDIUS_NEWLIB_STARTUP_REENT,
        stdio_close_context,MEDIUS_NEWLIB_STDIO_GLUE);
}

/* Native entry: 0x42015fe4. */
/*
 * Medius v3.4.7 — host application; 0x42015fe4.
 * Instruction-checked recovered C.
 * Original function-byte SHA-256:
 * 2c4033d344d4bcd2169e4481aabb8a345c969805679ef52653f3e2877fd71963.
 */

/*
 * Sample this context's stdin, stdout and stderr pointers in sequence. Close
 * each pointer that differs from its corresponding fixed shared FILE, passing
 * the supplied reent and the sampled pointer. Read later pointers after earlier
 * close callbacks, so callback mutations affect subsequent decisions. NULL also
 * differs from a shared FILE and is forwarded. Ignore close results; do not
 * clear stream pointers, acquire an extra lock, free the context or add MEMW.
 */
void medius_newlib_cleanup_context(NewlibReent *reent)
{
    volatile NewlibReent *context = reent;
    void *input = context->standard_input;
    if (input != &MEDIUS_NEWLIB_STANDARD_FILES[0])
        (void)stdio_close_context(reent,input);
    void *output = context->standard_output;
    if (output != &MEDIUS_NEWLIB_STANDARD_FILES[1])
        (void)stdio_close_context(reent,output);
    void *error = context->standard_error;
    if (error != &MEDIUS_NEWLIB_STANDARD_FILES[2])
        (void)stdio_close_context(reent,error);
}

/* Native entry: 0x4201601c. */
/*
 * Medius v3.4.7 — host application; 0x4201601c.
 * Instruction-checked recovered C.
 * Original function-byte SHA-256:
 * 6393c28103bb594d196a2fb061ddcae8939d6b4513b8f8aacfb8466fed5395b4.
 */

/*
 * Publish the global cleanup function first, then initialize shared stdin,
 * stdout and stderr in that order with flags/descriptors (4,0), (8,1), (0x12,2).
 * There is no already-initialized guard or local lock here. Publication precedes
 * completion of the three FILE objects; callers supply the pool-lock protocol.
 * No context stream-pointer assignment, old-buffer cleanup or rollback occurs.
 */
void medius_newlib_initialize_standard_streams(void)
{
    MEDIUS_NEWLIB_GLOBAL_CLEANUP = medius_newlib_cleanup_global_streams;
    medius_newlib_initialize_file(&MEDIUS_NEWLIB_STANDARD_FILES[0],4,0);
    medius_newlib_initialize_file(&MEDIUS_NEWLIB_STANDARD_FILES[1],8,1);
    medius_newlib_initialize_file(&MEDIUS_NEWLIB_STANDARD_FILES[2],0x12,2);
}

/* Native entry: 0x42016050. */
/*
 * Medius v3.4.7 — host application; 0x42016050.
 * Instruction-checked recovered C.
 * Original function-byte SHA-256:
 * 5bfaf5cf74da17bf0ba9966cbabfb46a074566008c2da58755dcd6b77cd91085.
 */

/*
 * Acquire the fixed common recursive Newlib mutex by handle. This wrapper does
 * not load a separate handle slot, select a task, reset errno or add a MEMW.
 * The retargetable lock service supplies allocation/scheduler/blocking behavior.
 */
void medius_newlib_file_pool_lock(void)
{
    __retarget_lock_acquire_recursive(MEDIUS_NEWLIB_COMMON_RECURSIVE_MUTEX);
}

/* Native entry: 0x42016060. */
/*
 * Medius v3.4.7 — host application; 0x42016060.
 * Instruction-checked recovered C.
 * Original function-byte SHA-256:
 * 385705d863b84fd8144fb8edcedbe0548ccfe11e33d8dafc383ca66fcd81f184.
 */

/*
 * Release the same fixed common recursive Newlib mutex by handle. No independent
 * result, lock-slot load, errno change or explicit memory barrier is added here.
 */
void medius_newlib_file_pool_unlock(void)
{
    __retarget_lock_release_recursive(MEDIUS_NEWLIB_COMMON_RECURSIVE_MUTEX);
}

/* Native entry: 0x42016070. */
/*
 * Medius v3.4.7 — host application; 0x42016070.
 * Instruction-checked recovered C.
 * Original function-byte SHA-256:
 * 884e84e63dc980864299358566fb76089ed7b39f93140b8aee60d6eb3b4836a6.
 */

/*
 * Return a reserved FILE pointer; the raw decompiler lost this return value.
 * Acquire the pool lock and initialize shared streams only if the global cleanup
 * hook is NULL. Walk each glue node's cached stream pointer/count, selecting the
 * first 16-bit flags==0 entry. Reserve flags 1 / descriptor -1 in one 32-bit store, clear
 * secondary flags, initialize its recursive lock, then release the pool lock.
 * Only afterward clear cursor/write/read counters, buffer fields, line-write
 * count, 8-byte multibyte state and ungetc/line-buffer base/capacity fields, in native order.
 * Other FILE fields retain prior bytes; no callback or owner is installed here.
 *
 * At an exhausted tail, allocate 428 bytes: a 12-byte glue plus four 104-byte FILEs.
 * Set header next=NULL/count=4/streams, clear 416 FILE bytes, then publish tail->next
 * and continue searching the new node. Failed allocation writes tail->next=NULL,
 * unlocks, then writes ENOMEM (12) in reent and returns NULL. Callback mutations may
 * be overwritten by these explicit stores; there is no rollback or extra check.
 * Counts decrement modulo 2^32 before the signed loop test, matching native code.
 * Valid glue/FILE storage is required; no cycle, pointer, count or MEMW guard.
 */
NewlibFile *medius_newlib_allocate_file(NewlibReent *reent)
{
    medius_newlib_file_pool_lock();
    if (!MEDIUS_NEWLIB_GLOBAL_CLEANUP)
        medius_newlib_initialize_standard_streams();
    volatile NewlibGlue *node = MEDIUS_NEWLIB_STDIO_GLUE;
    for (;;) {
        unsigned int address = (unsigned int)node->streams;
        unsigned int remaining = (unsigned int)node->stream_count;
        while ((int)(--remaining) >= 0) {
            NewlibFile *file = (NewlibFile *)address;
            volatile NewlibFile *stream = file;
            if (stream->flags == 0) {
                stream->descriptor_flags = 0xffff0001U;
                stream->secondary_flags = 0;
                __retarget_lock_init_recursive((NewlibLock *)&stream->lock);
                medius_newlib_file_pool_unlock();
                stream->cursor = NULL;
                stream->write_remaining = 0;
                stream->read_remaining = 0;
                stream->buffer_base = NULL;
                stream->buffer_capacity = 0;
                stream->line_write_remaining = 0;
                memset((void *)&stream->multibyte_state,0,8);
                stream->ungetc_buffer = NULL;
                stream->ungetc_capacity = 0;
                stream->line_buffer = NULL;
                stream->line_buffer_capacity = 0;
                return file;
            }
            address += 104;
        }
        NewlibGlue *next = node->next;
        if (!next) {
            MediusNewlibFileBlock *block = stdio_allocate_context(reent,428);
            if (!block) {
                node->next = NULL;
                medius_newlib_file_pool_unlock();
                reent->error_number = 12;
                return NULL;
            }
            volatile NewlibGlue *added = &block->glue;
            added->next = NULL;
            added->stream_count = 4;
            added->streams = block->files;
            memset(block->files,0,416);
            node->next = &block->glue;
            next = &block->glue;
        }
        node = next;
    }
}

/* Native entry: 0x42016124. */
/*
 * Medius v3.4.7 — host application; 0x42016124.
 * Instruction-checked recovered C.
 * Original function-byte SHA-256:
 * 85a8e17daa3331547155955038c7f8ed8c5150f3365b1af72fe2b9189be68b1f.
 */

/*
 * Under the pool lock, sample reent->cleanup. If NULL, install the context
 * cleanup callback before testing the global hook; initialize shared streams
 * only if that hook is also NULL. An existing context cleanup bypasses the
 * global test entirely. Always unlock. There is no NULL-context guard, reset
 * of other reent fields, allocation, local stdio flag update or explicit MEMW.
 */
void medius_newlib_initialize_stdio_context(NewlibReent *reent)
{
    medius_newlib_file_pool_lock();
    volatile NewlibReent *context = reent;
    if (!context->cleanup) {
        context->cleanup = medius_newlib_cleanup_context;
        if (!MEDIUS_NEWLIB_GLOBAL_CLEANUP)
            medius_newlib_initialize_standard_streams();
    }
    medius_newlib_file_pool_unlock();
}

/* Native entry: 0x4201ec7c. */
/*
 * Medius v3.4.7 — host application; 0x4201ec7c.
 * Instruction-checked recovered C.
 * Original function-byte SHA-256:
 * dd63059d9d480b2de7ac86bae31bdf6eddbeb67ea59699a2903f89a8af772963.
 */

/*
 * Walk a non-NULL FILE-glue chain without taking a lock. Cache each node's
 * streams pointer then its count; decrement count modulo 2^32 before the signed
 * loop test. For each 104-byte entry, call visitor(reent,file) only when 16-bit flags
 * is unsigned > 1 and its signed 16-bit descriptor is not -1. OR all return words and
 * keep visiting after errors. Read each next pointer after that node's callbacks;
 * callback changes to later FILEs/next links are observed, while changes to the
 * current node's count/base do not restart its cached iteration. No NULL visitor
 * guard, cycle/count validation, errno handling, allocation or MEMW occurs.
 */
int medius_newlib_walk_streams(NewlibReent *reent,
    MediusNewlibFileVisitor visitor,NewlibGlue *root)
{
    unsigned int combined = 0;
    volatile NewlibGlue *node = root;
    do {
        unsigned int address = (unsigned int)node->streams;
        unsigned int remaining = (unsigned int)node->stream_count;
        while ((int)(--remaining) >= 0) {
            NewlibFile *file = (NewlibFile *)address;
            volatile NewlibFile *stream = file;
            if (stream->flags > 1 && stream->file_descriptor != -1)
                combined |= (unsigned int)visitor(reent,file);
            address += 104;
        }
        node = node->next;
    } while (node);
    return (int)combined;
}
