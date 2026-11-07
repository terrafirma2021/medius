/* Recovered device libc/ROM startup, global stdio and signal-abort adapters. */

#include "../include/types.h"

/* Native entry: 0x42007488. */
/* Original function-byte SHA-256:
 * 892615bfb6ca01525daaef08daf2605d0da81a5c22dfc549b7a9cfcb7ed940a3. */
/*
 * Creates a static ordinary mutex(type1) at the pinned common-mutex buffer,
 * then a recursive mutex(type4) at its own buffer. Each returned queue handle
 * must equal that supplied storage address; otherwise calls __assert_func
 * with four null/zero arguments. Finally passes the same stack-WORD pointer,
 * containing0xbb10c433, as both arguments to the ROM common-mutex initializer.
 * No dynamic allocation, normal error result, context query or extra lock.
 * Assertions do not return normally; native second mismatch shares that site.
 */
void esp_newlib_locks_init(void)
{
    RtosQueue *ordinary = (RtosQueue *)MEDIUS_NEWLIB_COMMON_MUTEX;
    if (xQueueCreateMutexStatic(1,ordinary) != ordinary) __assert_func(0,0,0,0);
    RtosQueue *recursive = (RtosQueue *)MEDIUS_NEWLIB_COMMON_RECURSIVE_MUTEX;
    if (xQueueCreateMutexStatic(4,recursive) != recursive) __assert_func(0,0,0,0);
    unsigned int rom_mutex_magic = 0xbb10c433U;
    esp_rom_newlib_init_common_mutexes(&rom_mutex_magic,&rom_mutex_magic);
}

/* Native entry: 0x420074d0. */
/* Original function-byte SHA-256:
 * 89385d2f37f4cb901e9baab42e242704af1b4634f6d8ad032e321faefe2a5558. */
/*
 * Requires a valid reent. For stdin, stdout and stderr in that order, reads
 * its stream pointer then the corresponding current global stream pointer.
 * When unequal, calls the reviewed close-file routine with BOTH the supplied
 * reent and cached stream pointer, discarding status. Subsequent stream pairs
 * are sampled only after earlier closes return. No null/ownership check, pointer
 * clearing or reent free occurs in this wrapper; a different NULL stream is
 * still forwarded to the close routine. Shared global streams are skipped.
 */
void esp_cleanup_r(NewlibReent *context)
{
    volatile NewlibReent *reent = context;
    const volatile NewlibReent *global = MEDIUS_NEWLIB_STARTUP_REENT;
    void *stream = reent->standard_input;
    void *shared_stream = global->standard_input;
    if (stream != shared_stream) (void)medius_newlib_close_file(context,stream);
    stream = reent->standard_output;
    shared_stream = global->standard_output;
    if (stream != shared_stream) (void)medius_newlib_close_file(context,stream);
    stream = reent->standard_error;
    shared_stream = global->standard_error;
    if (stream != shared_stream) (void)medius_newlib_close_file(context,stream);
}

/* Native entry: 0x42007504. */
/* Original function-byte SHA-256:
 * 851dff5f91130f65f1733eefb94c6ada4ba563cfa0b53bab707e962aab58a5de. */
/* ROM callback adapter: forwards reent and signal0 to this build's _raise_r.
 * It does not select/deliver a signal; that callee unconditionally aborts. */
void raise_r_stub(NewlibReent *reent)
{
    (void)_raise_r((struct _reent *)reent,0);
}

/* Native entry: 0x42007514. */
/* Original function-byte SHA-256:
 * f3f403de451e0852aebb64b2b27e4363c50a2e28a9e9797fd6fd855bd1aec512. */
/*
 * Publishes the pinned syscall table to ROM, memset/clears the12-byte global
 * stdio glue, publishes global reent to ROM, installs esp_cleanup_r and marks
 * stdio initialized(1) to defer lazy setup. malloc(4) supplies an empty environ
 * vector; publishes that pointer before checking NULL and aborts on failure.
 * Clears its first WORD toNULL, then initializes the static/ROM mutexes.
 * No lock, repeated-call guard, stream opening or ordinary failure return.
 * Repeated calls can discard prior environment/glue state; this is startup code.
 */
void esp_newlib_init(void)
{
    MEDIUS_NEWLIB_ROM_SYSCALL_POINTER = MEDIUS_NEWLIB_SYSCALL_TABLE;
    memset(MEDIUS_NEWLIB_STDIO_GLUE,0,12);
    MEDIUS_NEWLIB_ROM_GLOBAL_REENT = MEDIUS_NEWLIB_STARTUP_REENT;
    volatile NewlibReent *global = MEDIUS_NEWLIB_STARTUP_REENT;
    global->cleanup = esp_cleanup_r;
    global->stdio_initialized = 1;
    char **environment = malloc(4);
    MEDIUS_NEWLIB_ENVIRONMENT = environment;
    if (environment == 0) abort();
    *(char *volatile *)environment = 0;
    esp_newlib_locks_init();
}

/* Native entry: 0x42007560. */
/* Original function-byte SHA-256:
 * e1183381dffa1562679f254c05390f478d1d860373edbd513702252d0d66f297. */
/* Core startup wrapper: calls esp_newlib_init and returns0 after it returns.
 * Fatal initialization paths are handled by its callees, not converted to status. */
int init_newlib(void)
{
    esp_newlib_init();
    return 0;
}

/* Native entry: 0x4200756c. */
/* Original function-byte SHA-256:
 * a05097b5eec5a952e079ede973f981ddc4365eaf3631ecd5f53a1a4662ae4349. */
/*
 * Null device_path temporarily clears global cleanup then stdio-initialized,
 * calls the reviewed stdio initializer, restores esp_cleanup_r then flag1.
 * Nonnull path opens r, w, w in that order, publishing stdin/stdout/stderr
 * after each result, includingNULL. After all opens, rereads each global stream
 * and calls prepare-write with the global reent, even for stdin and NULL results:
 * this is the ROM/newlib stdio-setup workaround. All prepare statuses ignored.
 * No caller validation, open failure cleanup, previous-stream close, mutex or
 * repeated-call guard; path and global streams may change across callee calls.
 */
void esp_newlib_init_global_stdio(const char *device_path)
{
    volatile NewlibReent *global = MEDIUS_NEWLIB_STARTUP_REENT;
    if (device_path == 0) {
        global->cleanup = 0;
        global->stdio_initialized = 0;
        medius_newlib_initialize_stdio_context(MEDIUS_NEWLIB_STARTUP_REENT);
        global->cleanup = esp_cleanup_r;
        global->stdio_initialized = 1;
    } else {
        NewlibFile *stream = medius_newlib_open_file_current(device_path,"r");
        global->standard_input = stream;
        stream = medius_newlib_open_file_current(device_path,"w");
        global->standard_output = stream;
        stream = medius_newlib_open_file_current(device_path,"w");
        global->standard_error = stream;
        stream = global->standard_input;
        (void)medius_newlib_prepare_write(MEDIUS_NEWLIB_STARTUP_REENT,stream);
        stream = global->standard_output;
        (void)medius_newlib_prepare_write(MEDIUS_NEWLIB_STARTUP_REENT,stream);
        stream = global->standard_error;
        (void)medius_newlib_prepare_write(MEDIUS_NEWLIB_STARTUP_REENT,stream);
    }
}

/* Native entry: 0x420075d0. */
/* Original function-byte SHA-256:
 * 91840e5fc0805ba738db913a980b96cd686547aaf015ae383664bef2bb3c0e28. */
/* Core startup wrapper: initializes global stdio against /dev/console and
 * returns0. Individual open/setup failures are not converted to a status here. */
int init_newlib_stdio(void)
{
    esp_newlib_init_global_stdio("/dev/console");
    return 0;
}

/* Native entry: 0x420075e0. */
/* Original function-byte SHA-256:
 * 5e39274077a29b0a288c8cd16609325bf81c1299f393ebafd15a8526dd8cf2ad. */
/*
 * This build ignores both reent and signal and calls abort. An explicit ILL
 * instruction follows if that call unexpectedly returns. No signal handlers,
 * errno update, argument check or normal integer result is supplied.
 */
int _raise_r(struct _reent *reent,int signal)
{
    (void)reent; (void)signal;
    medius_newlib_abort_boundary();
    __asm__ volatile ("ill");
    __builtin_unreachable();
}
