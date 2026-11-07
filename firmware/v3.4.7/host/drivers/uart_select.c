/* Medius v3.4.7 host — drivers/uart_select.c.
 */

#include "../include/types.h"

/* Source reconstruction utilities; not additional native firmware entries.
 * Each fd_set in this native build is exactly two 32-bit words. Explicit views
 * preserve word access and store order without relying on host libc macros. */
static __inline__ __attribute__((always_inline)) volatile unsigned int *uart_select_words(volatile fd_set *set)
{
    return (volatile unsigned int *)set;
}
static __inline__ __attribute__((always_inline)) const volatile unsigned int *uart_select_saved_words(const volatile fd_set *set)
{
    return (const volatile unsigned int *)set;
}
extern void *uart_select_reallocate(void *,unsigned int,unsigned int) __asm__("heap_caps_realloc");

/* Native entry: 0x4037f8b4. */
/*
 * Medius v3.4.7 — host application; 0x4037f8b4.
 * Instruction-checked recovered C.
 * Original function-byte SHA-256:
 * 89e19f410ab4d304d360a99bcbf0b3b50f925eb00c97107b4426f3eb4410ec55.
 */

/* Under the registered-select ISR mux, visit current argument pointers. Kind
 * 0/1/2 means read/write/error. For unsigned port<64, require its saved-set bit,
 * OR it into the caller's live set, then wake the saved select semaphore. Skip
 * NULL entries, other kinds and port>=64. Reload registry base each iteration
 * and count after callbacks. Read destination word before semaphore words; write
 * it before waking. No port<3 gate, destination check, mask clear or local yield.
 * The selected wake backend receives task_woken unchanged. */
void medius_uart_select_notify_isr(int port,int notification,int *task_woken)
{
    (void)xPortEnterCriticalTimeout(MEDIUS_UART_SELECT_REGISTRY_LOCK,-1);
    int index = 0;
    if (MEDIUS_UART_SELECT_REGISTRY_COUNT > 0) {
        do {
            MediusUartSelectArguments *arguments = MEDIUS_UART_SELECT_REGISTRY[index];
            if (arguments && (unsigned int)port < 64U) {
                const volatile fd_set *saved = NULL;
                if (notification == 0) saved = &arguments->original_read;
                else if (notification == 1) saved = &arguments->original_write;
                else if (notification == 2) saved = &arguments->original_error;
                if (saved) {
                    unsigned int word = (unsigned int)port >> 5;
                    unsigned int requested = uart_select_saved_words(saved)[word];
                    unsigned int mask = 1U << ((unsigned int)port & 31U);
                    if (requested & mask) {
                        fd_set *live;
                        if (notification == 0) live = arguments->read_set;
                        else if (notification == 1) live = arguments->write_set;
                        else live = arguments->error_set;
                        unsigned int ready = uart_select_words(live)[word];
                        VfsSelectSemaphore semaphore;
                        semaphore.flags_word = arguments->semaphore.flags_word;
                        semaphore.handle = arguments->semaphore.handle;
                        uart_select_words(live)[word] = ready | mask;
                        medius_vfs_select_triggered_isr(semaphore,task_woken);
                    }
                }
            }
            ++index;
        } while (index < MEDIUS_UART_SELECT_REGISTRY_COUNT);
    }
    vPortExitCritical(MEDIUS_UART_SELECT_REGISTRY_LOCK);
}

/* Native entry: 0x42021b34. */
/*
 * Medius v3.4.7 — host application; 0x42021b34.
 * Instruction-checked recovered C.
 * Original function-byte SHA-256:
 * 7b930fa0cc45385ffd95bc62116b479eacda75c80cdf6ff064048c9977a2c96e.
 */

/* Enter driver-select mux. For non-NULL arguments remove their first registry
 * occurrence under registry mux: replace with last pointer, shrink array, publish
 * realloc return without checking it. Removal status0; not found0x103. Then
 * inspect low saved-mask words for ports0..2, decrement the FIRST selected port's
 * reference count modulo2^32 and clear callback only if that count becomes0.
 * Other selected ports are not decremented. Exit driver mux, free arguments,
 * return removal status; cleanup runs even when removal failed. NULL skips
 * unregister but is then dereferenced. No shrink-failure repair or multi-port
 * balancing is supplied; these native behaviors are deliberately retained. */
int medius_uart_vfs_end_select(void *opaque)
{
    MediusUartSelectArguments *arguments = opaque;
    (void)xPortEnterCriticalTimeout(medius_uart_driver_get_select_lock(),-1);
    int result = 0;
    if (arguments) {
        (void)xPortEnterCriticalTimeout(MEDIUS_UART_SELECT_REGISTRY_LOCK,-1);
        int count = MEDIUS_UART_SELECT_REGISTRY_COUNT;
        result = 0x103;
        if (count > 0) {
            MediusUartSelectArguments **registered = MEDIUS_UART_SELECT_REGISTRY;
            for (int index=0; index<count; ++index) {
                if (((MediusUartSelectArguments * volatile *)registered)[index] == arguments) {
                    unsigned int remaining = (unsigned int)count - 1U;
                    MediusUartSelectArguments *last = ((MediusUartSelectArguments * volatile *)registered)[remaining];
                    ((MediusUartSelectArguments * volatile *)registered)[index] = last;
                    MediusUartSelectArguments **resized = uart_select_reallocate(registered,remaining*4U,0x804U);
                    MEDIUS_UART_SELECT_REGISTRY = resized;
                    MEDIUS_UART_SELECT_REGISTRY_COUNT = (int)remaining;
                    result = 0;
                    break;
                }
            }
        }
        vPortExitCritical(MEDIUS_UART_SELECT_REGISTRY_LOCK);
    }
    unsigned int read_mask = uart_select_saved_words(&arguments->original_read)[0];
    for (unsigned int port=0; port<3U; ++port) {
        unsigned int bit = 1U << port;
        if ((read_mask & bit) || (uart_select_saved_words(&arguments->original_write)[0] & bit) ||
            (uart_select_saved_words(&arguments->original_error)[0] & bit)) {
            unsigned int remaining = MEDIUS_UART_SELECT_REFERENCE_COUNTS[port] - 1U;
            MEDIUS_UART_SELECT_REFERENCE_COUNTS[port] = remaining;
            if (remaining == 0) medius_uart_driver_set_select_notify(port,NULL);
            break;
        }
    }
    vPortExitCritical(medius_uart_driver_get_select_lock());
    free(arguments);
    return result;
}

/* Native entry: 0x42021bf4. */
/*
 * Medius v3.4.7 — host application; 0x42021bf4.
 * Instruction-checked recovered C.
 * Original function-byte SHA-256:
 * 759c4e486d623c79e13df718b224946eba033aee7c57b5bfc50a4a8a9a205c38.
 */

/* Set *end_arguments=NULL; clamp signed count to at most3; require installed
 * drivers only for requested ports. Invalid-state0x103 leaves sets unchanged.
 * Allocate44 internal/8-bit bytes (caps0x804), else return0x101. Save complete
 * 64-bit sets, semaphore and caller pointers, then clear each live set HIGH
 * word before LOW. Under driver-select mux install callback for zero-ref selected
 * ports, increment refs modulo2^32 and immediately wake requested reads with
 * nonempty driver buffers. Append arguments under nested registry mux. Publish
 * table/entry/count, exit BOTH muxes, then publish end_arguments and return0.
 * Registry realloc failure unlocks/frees and returns0x101 WITHOUT undoing refs,
 * callbacks, cleared sets or wakeups. Zero/negative count still copies/clears/
 * registers sets without port loops. No pointer checks, errno or lookahead test.
 * Preserve saved-read snapshots across callbacks and all native field ordering. */
int medius_uart_vfs_start_select(int count,fd_set *read_set,fd_set *write_set,
    fd_set *error_set,VfsSelectSemaphore semaphore,void **end_arguments)
{
    *(void * volatile *)end_arguments = NULL;
    int limit = count < 3 ? count : 3;
    for (int port=0; port<limit; ++port) {
        unsigned int bit = 1U << port;
        if ((uart_select_words(read_set)[0] & bit) || (uart_select_words(write_set)[0] & bit) ||
            (uart_select_words(error_set)[0] & bit)) {
            if (!medius_uart_driver_is_installed((unsigned int)port)) return 0x103;
        }
    }
    MediusUartSelectArguments *arguments = heap_caps_malloc(44,0x804U);
    if (!arguments) return 0x101;
    unsigned int low = uart_select_words(read_set)[0];
    unsigned int high = uart_select_words(read_set)[1];
    uart_select_words(&arguments->original_read)[0] = low;
    uart_select_words(&arguments->original_read)[1] = high;
    low = uart_select_words(write_set)[0];
    high = uart_select_words(write_set)[1];
    uart_select_words(&arguments->original_write)[0] = low;
    uart_select_words(&arguments->original_write)[1] = high;
    low = uart_select_words(error_set)[0];
    high = uart_select_words(error_set)[1];
    arguments->semaphore.flags_word = semaphore.flags_word;
    uart_select_words(&arguments->original_error)[0] = low;
    uart_select_words(&arguments->original_error)[1] = high;
    arguments->semaphore.handle = semaphore.handle;
    arguments->read_set = read_set;
    arguments->write_set = write_set;
    arguments->error_set = error_set;
    uart_select_words(read_set)[1]=0; uart_select_words(read_set)[0]=0;
    uart_select_words(write_set)[1]=0; uart_select_words(write_set)[0]=0;
    uart_select_words(error_set)[1]=0; uart_select_words(error_set)[0]=0;
    (void)xPortEnterCriticalTimeout(medius_uart_driver_get_select_lock(),-1);
    if (count > 0) {
        unsigned int read_mask = uart_select_saved_words(&arguments->original_read)[0];
        for (int port=0; port<limit; ++port) {
            unsigned int bit = 1U << port;
            if ((read_mask & bit) || (uart_select_saved_words(&arguments->original_write)[0] & bit) ||
                (uart_select_saved_words(&arguments->original_error)[0] & bit)) {
                unsigned int references = MEDIUS_UART_SELECT_REFERENCE_COUNTS[port];
                if (references == 0) {
                    medius_uart_driver_set_select_notify((unsigned int)port,medius_uart_select_notify_isr);
                    references = MEDIUS_UART_SELECT_REFERENCE_COUNTS[port];
                    read_mask = uart_select_saved_words(&arguments->original_read)[0];
                }
                MEDIUS_UART_SELECT_REFERENCE_COUNTS[port] = references + 1U;
            }
        }
        int port = 0;
        do {
            unsigned int bit = 1U << port;
            if (read_mask & bit) {
                unsigned int buffered;
                if (medius_uart_driver_get_buffered_length((unsigned int)port,&buffered) == 0 && buffered != 0) {
                    unsigned int ready = uart_select_words(read_set)[0];
                    VfsSelectSemaphore wake;
                    wake.flags_word = arguments->semaphore.flags_word;
                    wake.handle = arguments->semaphore.handle;
                    uart_select_words(read_set)[0] = ready | bit;
                    medius_vfs_select_triggered(wake);
                }
            }
            ++port;
            if (port >= limit) break;
            read_mask = uart_select_saved_words(&arguments->original_read)[0];
        } while (1);
    }
    (void)xPortEnterCriticalTimeout(MEDIUS_UART_SELECT_REGISTRY_LOCK,-1);
    unsigned int new_count = (unsigned int)MEDIUS_UART_SELECT_REGISTRY_COUNT + 1U;
    MediusUartSelectArguments **registered = MEDIUS_UART_SELECT_REGISTRY;
    MediusUartSelectArguments **resized = uart_select_reallocate(registered,new_count*4U,0x804U);
    if (!resized) {
        vPortExitCritical(MEDIUS_UART_SELECT_REGISTRY_LOCK);
        vPortExitCritical(medius_uart_driver_get_select_lock());
        free(arguments);
        return 0x101;
    }
    int insertion = MEDIUS_UART_SELECT_REGISTRY_COUNT;
    MEDIUS_UART_SELECT_REGISTRY = resized;
    ((MediusUartSelectArguments * volatile *)resized)[insertion] = arguments;
    MEDIUS_UART_SELECT_REGISTRY_COUNT = (int)new_count;
    vPortExitCritical(MEDIUS_UART_SELECT_REGISTRY_LOCK);
    vPortExitCritical(medius_uart_driver_get_select_lock());
    *(void * volatile *)end_arguments = arguments;
    return 0;
}
