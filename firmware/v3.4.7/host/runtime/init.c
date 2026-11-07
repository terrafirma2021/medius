/* Recovered host libc/ROM startup, global stdio and signal-abort adapters. */

#include "../include/types.h"

/* Native entry: 0x42007054. */
/* Original function-byte SHA-256:
 * d570bfc406024cb4936214c91e9d3f670f5907cc375dc1517de3e9111b30411c. */
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

/* Native entry: 0x4200709c. */
/* Original function-byte SHA-256:
 * 2951e23be236b45d648cfd2a2bfc85d370958d21c9af56e45c8f021f8a84d896. */
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

/* Native entry: 0x420070d0. */
/* Original function-byte SHA-256:
 * 851dff5f91130f65f1733eefb94c6ada4ba563cfa0b53bab707e962aab58a5de. */
/* ROM callback adapter: forwards reent and signal0 to this build's _raise_r.
 * It does not select/deliver a signal; that callee unconditionally aborts. */
void raise_r_stub(NewlibReent *reent)
{
    (void)_raise_r((struct _reent *)reent,0);
}

/* Native entry: 0x420070e0. */
/* Original function-byte SHA-256:
 * d8a43aaa258963889d397128af0aeec72d44a0096fd9cd7263b697bdce72562a. */
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

/* Native entry: 0x4200712c. */
/* Original function-byte SHA-256:
 * e1183381dffa1562679f254c05390f478d1d860373edbd513702252d0d66f297. */
/* Core startup wrapper: calls esp_newlib_init and returns0 after it returns.
 * Fatal initialization paths are handled by its callees, not converted to status. */
int init_newlib(void)
{
    esp_newlib_init();
    return 0;
}

/* Native entry: 0x42007138. */
/* Original function-byte SHA-256:
 * 250e21a1dfb20fd7e0436093a07321b7f72039278fb40b687544c65c05950408. */
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

/* Native entry: 0x4200719c. */
/* Original function-byte SHA-256:
 * 0326fb91578d13b5391dff7004c2c95b0a11d90265c31f7e078fea635632c13f. */
/* Core startup wrapper: initializes global stdio against /dev/console and
 * returns0. Individual open/setup failures are not converted to a status here. */
int init_newlib_stdio(void)
{
    esp_newlib_init_global_stdio("/dev/console");
    return 0;
}

/* Native entry: 0x420071ac. */
/* Original function-byte SHA-256:
 * 4347eb0a14e37314733819a4e0c67d1653a16f89da789a026c6726ada286e66f. */
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
