/* Medius v3.4.7 host — UART filesystem, FIFO callbacks and terminal settings.
 */

#include "../include/types.h"

/* Source reconstruction utilities; not additional native firmware entries.
 * Typed linker boundaries avoid inventing reviewed bodies for driver callees.
 * The table folds the two native balanced baud switches into one explicit map. */
extern int *uart_vfs_current_errno(void) __asm__("__errno");
extern int uart_vfs_register_filesystem(const char *,const VfsOperations *,int,void *)
    __asm__("FUN_4203274c");
extern int uart_vfs_driver_flush_input(unsigned int) __asm__("uart_flush_input");
extern int uart_vfs_driver_wait_tx_done(unsigned int,unsigned int) __asm__("uart_wait_tx_done");
extern int uart_vfs_driver_get_word_length(unsigned int,unsigned int *) __asm__("uart_get_word_length");
extern int uart_vfs_driver_get_stop_bits(unsigned int,unsigned int *) __asm__("uart_get_stop_bits");
extern int uart_vfs_driver_get_parity(unsigned int,unsigned int *) __asm__("uart_get_parity");
extern int uart_vfs_driver_get_baudrate(unsigned int,unsigned int *) __asm__("uart_get_baudrate");
extern int uart_vfs_driver_set_word_length(unsigned int,unsigned int) __asm__("uart_set_word_length");
extern int uart_vfs_driver_set_stop_bits(unsigned int,unsigned int) __asm__("uart_set_stop_bits");
extern int uart_vfs_driver_set_parity(unsigned int,unsigned int) __asm__("uart_set_parity");
extern void uart_vfs_rom_wait_idle(unsigned int) __asm__("uart_tx_wait_idle");
static const unsigned int uart_vfs_standard_baud[31] = {
    0,50,75,110,134,150,200,300,600,1200,1800,2400,4800,9600,19200,38400,
    57600,115200,230400,460800,500000,576000,921600,1000000,1152000,
    1500000,2000000,2500000,3000000,3500000,4000000
};

/* Native entry: 0x4202271c. */
/*
 * Medius v3.4.7 — host application; 0x4202271c.
 * Instruction-checked recovered C.
 * Original function-byte SHA-256:
 * a4b38f0f8d9236754a364b8c1e2fe6fe6d307b4a0272fdba71a55111028b4b8c.
 */

/* Return the fixed borrowed operation-table pointer for this image's selected
 * UART/null backend. No table dereference, validation, allocation or state write
 * occurs. Registered flags determine which callback ABI its consumer uses. */
const VfsOperations *medius_uart_vfs_get_operations(void)
{
    return CONSOLE_INITIAL_BACKEND;
}

/* Native entry: 0x42021acc. */
/*
 * Medius v3.4.7 — host application; 0x42021acc.
 * Instruction-checked recovered C.
 * Original function-byte SHA-256:
 * f009f1067e322b4d64272a78958ec43986c6272ed9e489c9a643bc2c4df6fd6c.
 */

/* Read the low ten STATUS bits once and return the hardware RX FIFO count.
 * The port index and context pointer are unchecked. Cache the peripheral before
 * MEMW; this does not include driver-ring-buffer or VFS lookahead bytes. */
unsigned int medius_uart_vfs_fifo_available(int port)
{
    UartRegisterView *uart = MEDIUS_UART_VFS_CONTEXTS[port]->uart;
    memw();
    return uart->status & UART_FIFO_COUNT_MASK;
}

/* Native entry: 0x42021ae4. */
/*
 * Medius v3.4.7 — host application; 0x42021ae4.
 * Instruction-checked recovered C.
 * Original function-byte SHA-256:
 * aa542a715ec854bdaa098434adb03f71915abf0c26631dd36c3b7b0808009a7e.
 */

/* Poll the cached peripheral until unsigned (128-TX_FIFO_COUNT) is at least
 * two, then write the low byte as one 32-bit FIFO store. Keep the subtraction
 * modulo 2^32: an out-of-range count above 128 also ends this native loop.
 * MEMW precedes each status read and the FIFO write. No timeout, index check,
 * driver buffer, newline conversion or lock is supplied by this callback. */
void medius_uart_vfs_fifo_write_char(int port,int character)
{
    UartRegisterView *uart = MEDIUS_UART_VFS_CONTEXTS[port]->uart;
    unsigned int free_bytes;
    do {
        memw();
        unsigned int queued = (uart->status >> 16) & UART_FIFO_COUNT_MASK;
        free_bytes = UART_FIFO_CAPACITY - queued;
    } while (free_bytes < 2U);
    memw();
    uart->fifo = (unsigned char)character;
}

/* Native entry: 0x42021b0c. */
/*
 * Medius v3.4.7 — host application; 0x42021b0c.
 * Instruction-checked recovered C.
 * Original function-byte SHA-256:
 * 8d39c5b632f093a4c727dc759a75a3f444e8fe57f9d8cc7c5ae348d3b90ad39c.
 */

/* Sample the cached peripheral's RX count after MEMW. Empty returns -1 without
 * reading FIFO; otherwise another MEMW precedes one 32-bit FIFO read, whose low
 * byte is returned as 0..255. Port/context validity and serialization belong to
 * the caller. No driver queue, lookahead or blocking wait is consulted. */
int medius_uart_vfs_fifo_read_char(int port)
{
    UartRegisterView *uart = MEDIUS_UART_VFS_CONTEXTS[port]->uart;
    memw();
    if ((uart->status & UART_FIFO_COUNT_MASK) == 0) return -1;
    memw();
    return (int)(uart->fifo & 0xffU);
}

/* Native entry: 0x42021d80. */
/*
 * Medius v3.4.7 — host application; 0x42021d80.
 * Instruction-checked recovered C.
 * Original function-byte SHA-256:
 * 678b0e3da71fa72dbe46e1fc1e588a8e67e6360aa6cd09720fecdc6b60ebd874.
 */

/* Accept port 0..2 and TCIFLUSH(0) only, forwarding to the UART driver's input
 * flush. Return zero on driver success. Invalid port sets EBADF(9); unsupported
 * queue selection or driver error sets EINVAL(22), returning -1. VFS lookahead
 * is not cleared here; output flushing and a VFS-level lock are not supplied. */
int medius_uart_vfs_flush(int port,int queue_selector)
{
    if ((unsigned int)port >= 3U) {
        *uart_vfs_current_errno() = 9;
        return -1;
    }
    if (queue_selector == 0 && uart_vfs_driver_flush_input(port) == 0) return 0;
    *uart_vfs_current_errno() = 22;
    return -1;
}

/* Native entry: 0x42021db0. */
/*
 * Medius v3.4.7 — host application; 0x42021db0.
 * Instruction-checked recovered C.
 * Original function-byte SHA-256:
 * 4c5692c8101c6c1a27b0bad48bd23c383f1d88921cca3ba4457d153a04052ce2.
 */

/* Wait for driver TX completion on port 0..2 using all-one timeout ticks, then
 * return zero. Invalid port sets EBADF(9); driver failure sets EINVAL(22); both
 * return -1. This does not take the VFS write lock or flush receive/lookahead
 * data. The driver owns timeout/blocking semantics. */
int medius_uart_vfs_drain(int port)
{
    if ((unsigned int)port >= 3U) {
        *uart_vfs_current_errno() = 9;
        return -1;
    }
    if (uart_vfs_driver_wait_tx_done(port,0xffffffffU) == 0) return 0;
    *uart_vfs_current_errno() = 22;
    return -1;
}

/* Native entry: 0x42021ddc. */
/*
 * Medius v3.4.7 — host application; 0x42021ddc.
 * Instruction-checked recovered C.
 * Original function-byte SHA-256:
 * 5290d3f434b7e1c38a434a12ba7b8e4def9a406eedd9b9e59d34fc5555ae49a4.
 */

/* Clear the complete 28-byte terminal record, then encode cached RX newline
 * mode and successive driver reads of word length, stop bits, parity and baud.
 * Invalid port: EBADF(9). NULL output/driver error: EINVAL(22). Unsupported
 * word/stop/parity encoding: ENOSYS(88), including 1.5 stop bits. Return -1 on
 * failure, preserving partial output. Five to eight data bits map to 0..3;
 * one/two stop bits to clear/set CSTOPB; parity disabled/even/odd to 0/0x10/0x30.
 * Standard speeds map to B0..B4000000; other rates retain their numeric value
 * and BOTHER. Set both baud-selection flags and store OUTPUT speed before INPUT.
 * IGNCR represents CRLF conversion here, not generic POSIX CR discard. Output
 * newline settings are not reported. No VFS lock or atomic-settings snapshot. */
int medius_uart_vfs_get_attributes(int port,struct termios *attributes)
{
    if ((unsigned int)port >= 3U) {
        *uart_vfs_current_errno() = 9;
        return -1;
    }
    if (!attributes) goto invalid;
    volatile struct termios *out = attributes;
    memset(attributes,0,sizeof(*attributes));
    int rx_mode = MEDIUS_UART_VFS_CONTEXTS[port]->rx_mode;
    if (rx_mode == MEDIUS_UART_LINE_ENDINGS_CRLF) out->c_iflag |= MEDIUS_TERMIOS_IGNCR;
    else if (rx_mode == MEDIUS_UART_LINE_ENDINGS_CR) out->c_iflag |= MEDIUS_TERMIOS_ICRNL;

    unsigned int setting;
    if (uart_vfs_driver_get_word_length(port,&setting) != 0) goto invalid;
    unsigned short original_flags = out->c_cflag;
    unsigned short cleared_flags = original_flags & 0xfffcU;
    out->c_cflag = cleared_flags;
    switch (setting) {
    case 0: break;
    case 1: out->c_cflag = cleared_flags | 1U; break;
    case 2: out->c_cflag = cleared_flags | 2U; break;
    case 3: out->c_cflag = original_flags | 3U; break;
    default: goto unsupported;
    }
    if (uart_vfs_driver_get_stop_bits(port,&setting) != 0) goto invalid;
    if (setting == 3) out->c_cflag |= MEDIUS_TERMIOS_CSTOPB;
    else if (setting != 1) goto unsupported;
    if (uart_vfs_driver_get_parity(port,&setting) != 0) goto invalid;
    if (setting == 2) out->c_cflag |= MEDIUS_TERMIOS_PARENB;
    else if (setting == 3) out->c_cflag |= MEDIUS_TERMIOS_PARENB | MEDIUS_TERMIOS_PARODD;
    else if (setting != 0) goto unsupported;

    setting = 0;
    if (uart_vfs_driver_get_baudrate(port,&setting) != 0) goto invalid;
    original_flags = out->c_cflag;
    out->c_cflag = original_flags | MEDIUS_TERMIOS_BAUD_FLAGS;
    unsigned int speed = setting;
    unsigned int encoding;
    for (encoding=0; encoding<31U; ++encoding) {
        if (uart_vfs_standard_baud[encoding] == setting) {
            speed = encoding;
            break;
        }
    }
    if (encoding == 31U)
        out->c_cflag = original_flags | MEDIUS_TERMIOS_BAUD_FLAGS | MEDIUS_TERMIOS_BOTHER;
    out->c_ospeed = speed;
    out->c_ispeed = speed;
    return 0;
unsupported:
    *uart_vfs_current_errno() = 88;
    return -1;
invalid:
    *uart_vfs_current_errno() = 22;
    return -1;
}

/* Native entry: 0x42022100. */
/*
 * Medius v3.4.7 — host application; 0x42022100.
 * Instruction-checked recovered C.
 * Original function-byte SHA-256:
 * d376232f0688a570a3b7e0ecb86763769e1e6e385fcd30c94d7af0b7c42fe82f.
 */

/* Apply attributes in native order: action handling, RX conversion, word size,
 * stop bits, parity, then optional baud. TCSADRAIN(1) waits with all-one ticks
 * AND flushes RX; TCSAFLUSH(2) only flushes RX; TCSANOW(0) does neither. Other
 * actions fail. IGNCR selects CRLF conversion, ICRNL selects CR->LF, otherwise
 * leave CR/LF unchanged. No TX conversion or VFS lookahead reset is performed.
 * Word/stop/parity/baud controls are separately sampled across driver calls.
 * Baud is untouched unless flags 0x300 are nonzero. Then input/output speeds
 * must match: BOTHER selects their numeric rate, otherwise decode 0..30 only.
 * Invalid port sets EBADF(9); NULL attributes, bad action/speed or driver failure
 * sets EINVAL(22). Return zero/-1. Earlier side effects survive later failure;
 * no rollback, VFS-level lock or simultaneous hardware update is provided. */
int medius_uart_vfs_set_attributes(int port,int action,const struct termios *attributes)
{
    if ((unsigned int)port >= 3U) {
        *uart_vfs_current_errno() = 9;
        return -1;
    }
    if (!attributes) goto invalid;
    if (action == 1) {
        if (uart_vfs_driver_wait_tx_done(port,0xffffffffU) != 0) goto invalid;
        if (uart_vfs_driver_flush_input(port) != 0) goto invalid;
    } else if (action == 2) {
        if (uart_vfs_driver_flush_input(port) != 0) goto invalid;
    } else if (action != 0) goto invalid;

    const volatile struct termios *in = attributes;
    unsigned short input_flags = in->c_iflag;
    MediusUartVfsContext *context = MEDIUS_UART_VFS_CONTEXTS[port];
    int rx_mode = (input_flags & MEDIUS_TERMIOS_IGNCR) ? MEDIUS_UART_LINE_ENDINGS_CRLF :
        ((input_flags & MEDIUS_TERMIOS_ICRNL) ? MEDIUS_UART_LINE_ENDINGS_CR : MEDIUS_UART_LINE_ENDINGS_LF);
    unsigned short control_flags = in->c_cflag;
    context->rx_mode = rx_mode;
    if (uart_vfs_driver_set_word_length(port,control_flags & 3U) != 0) goto invalid;
    control_flags = in->c_cflag;
    if (uart_vfs_driver_set_stop_bits(port,(control_flags & MEDIUS_TERMIOS_CSTOPB) ? 3U : 1U) != 0)
        goto invalid;
    control_flags = in->c_cflag;
    unsigned int parity = (control_flags & MEDIUS_TERMIOS_PARENB) ?
        ((control_flags & MEDIUS_TERMIOS_PARODD) ? 3U : 2U) : 0U;
    if (uart_vfs_driver_set_parity(port,parity) != 0) goto invalid;
    control_flags = in->c_cflag;
    if ((control_flags & MEDIUS_TERMIOS_BAUD_FLAGS) == 0) return 0;
    unsigned int speed = in->c_ispeed;
    unsigned int output_speed = in->c_ospeed;
    if (speed != output_speed) goto invalid;
    unsigned int baud = speed;
    if ((control_flags & MEDIUS_TERMIOS_BOTHER) == 0) {
        if (speed >= 31U) goto invalid;
        baud = uart_vfs_standard_baud[speed];
    }
    if (uart_set_baudrate(port,baud) != 0) goto invalid;
    return 0;
invalid:
    *uart_vfs_current_errno() = 22;
    return -1;
}

/* Native entry: 0x42022374. */
/*
 * Medius v3.4.7 — host application; 0x42022374.
 * Instruction-checked recovered C.
 * Original function-byte SHA-256:
 * 339f442ec28cd23a322539527ca494b5b648671a3aca3ecc7ea17d92e5e87006.
 */

/* Exact /0, /1 and /2 exist, readable/writable but not executable. F_OK(0)
 * succeeds; other modes require at least one R_OK/W_OK bit and no X_OK bit.
 * Higher mode bits are ignored. Success zero; missing path ENOENT(2), denied
 * mode EACCES(13), both -1. A valid NUL-terminated path is required; only the
 * short-circuited prefix bytes are read, with the initial byte sampled once. */
int medius_uart_vfs_access(const char *path,int access_mode)
{
    const volatile unsigned char *name = (const volatile unsigned char *)path;
    unsigned int first = name[0];
    if ((first=='/' && name[1]=='0' && name[2]==0) ||
        (first=='/' && name[1]=='1' && name[2]==0) ||
        (first=='/' && name[1]=='2' && name[2]==0)) {
        unsigned int mode = (unsigned int)access_mode;
        if (mode == 0 || ((mode & 6U) != 0 && (mode & 1U) == 0)) return 0;
        *uart_vfs_current_errno() = 13;
        return -1;
    }
    *uart_vfs_current_errno() = 2;
    return -1;
}

/* Native entry: 0x420223e0. */
/*
 * Medius v3.4.7 — host application; 0x420223e0.
 * Instruction-checked recovered C.
 * Original function-byte SHA-256:
 * 2cfbd9020da73a98bd0a8ee6d3606636215ab770c6465ad216cc0a2b8c97ad55.
 */

/* Exact /0,/1,/2 return local UART index 0,1,2 after replacing that port's
 * shared nonblocking byte with flags bit14. Ignore mode and every other flag;
 * no ownership/refcount, hardware setup or VFS lock. Multiple opens affect the
 * same flag. Other paths set ENOENT(2), return -1. Initial path byte cached;
 * subsequent comparisons short-circuit and reload bytes as the native does. */
int medius_uart_vfs_open(const char *path,int flags,int mode)
{
    (void)mode;
    const volatile unsigned char *name = (const volatile unsigned char *)path;
    unsigned int first = name[0];
    int port;
    if (first=='/' && name[1]=='0' && name[2]==0) port=0;
    else if (first=='/' && name[1]=='1' && name[2]==0) port=1;
    else if (first=='/' && name[1]=='2' && name[2]==0) port=2;
    else { *uart_vfs_current_errno()=2; return -1; }
    MEDIUS_UART_VFS_CONTEXTS[port]->nonblocking = ((unsigned int)flags >> 14) & 1U;
    return port;
}

/* Native entry: 0x4202244c. */
/*
 * Medius v3.4.7 — host application; 0x4202244c.
 * Instruction-checked recovered C.
 * Original function-byte SHA-256:
 * 5cac2b08dd8e7612da3fe228ab2670176fc4adabd2a9e8e334bbdd156b3bf808.
 */

/* Assert unsigned port<3. F_GETFL(3) returns O_RDWR(2), plus O_NONBLOCK(0x4000)
 * for any nonzero flag byte. F_SETFL(4) replaces that shared byte with argument
 * bit14 and returns zero. Other commands set ENOSYS(88), return -1. No VFS lock,
 * per-open flag isolation, UART driver check or manipulation of other flags. */
int medius_uart_vfs_control(int port,int command,int argument)
{
    if ((unsigned int)port >= 3U) __assert_func(NULL,0,NULL,NULL);
    if (command == 3) return MEDIUS_UART_VFS_CONTEXTS[port]->nonblocking ? 0x4002 : 2;
    if (command == 4) {
        MEDIUS_UART_VFS_CONTEXTS[port]->nonblocking = ((unsigned int)argument >> 14) & 1U;
        return 0;
    }
    *uart_vfs_current_errno() = 88;
    return -1;
}

/* Native entry: 0x420224a0. */
/*
 * Medius v3.4.7 — host application; 0x420224a0.
 * Instruction-checked recovered C.
 * Original function-byte SHA-256:
 * 906561eac15af9a54ce05fabe98a7ff6c21678fb0d890def4c4e921f13be3c0e.
 */

/* Assert unsigned port<3 and return zero. This does not close/delete a UART,
 * clear lookahead/nonblocking state, release a lock or change a reference count. */
int medius_uart_vfs_close(int port)
{
    if ((unsigned int)port >= 3U) __assert_func(NULL,0,NULL,NULL);
    return 0;
}

/* Native entry: 0x420224b8. */
/*
 * Medius v3.4.7 — host application; 0x420224b8.
 * Instruction-checked recovered C.
 * Original function-byte SHA-256:
 * d1dc4d966e5593ea710b49f3eadc628cdd979b4c84408a7b3e3c2cd724131388.
 */

/* Assert port<3; hold the original context's recursive WRITE-lock slot while
 * sending bytes. LF mode(2) sends bytes unchanged; CR mode(1) substitutes CR;
 * CRLF mode(0), and other non-1/non-2 modes, prefix LF with CR. Reload cached
 * TX mode after the CR callback. Original-byte sends use a freshly loaded table
 * context/callback; inserted CR uses the cached context. Unlock the original
 * slot and return requested length bits, even zero or above signed INT_MAX.
 * Native end-pointer arithmetic wraps at 32 bits. No callback status, buffer
 * check, output byte count, timeout or driver-queue completion wait is supplied. */
int medius_uart_vfs_write(int port,const void *data,unsigned int length)
{
    if ((unsigned int)port >= 3U) __assert_func(NULL,0,NULL,NULL);
    MediusUartVfsContext *context = MEDIUS_UART_VFS_CONTEXTS[port];
    NewlibLock *write_lock = &context->write_lock;
    _lock_acquire_recursive(write_lock);
    if (length != 0) {
        unsigned int cursor = (unsigned int)data;
        unsigned int end = cursor + length;
        do {
            unsigned int character = *(const unsigned char *)cursor;
            if (character == '\n' && context->tx_mode != MEDIUS_UART_LINE_ENDINGS_LF) {
                context->write_char(port,'\r');
                if (context->tx_mode == MEDIUS_UART_LINE_ENDINGS_CR) {
                    ++cursor;
                    continue;
                }
            }
            MEDIUS_UART_VFS_CONTEXTS[port]->write_char(port,(int)character);
            ++cursor;
        } while (cursor != end);
    }
    _lock_release_recursive(write_lock);
    return (int)length;
}

/* Native entry: 0x42022524. */
/*
 * Medius v3.4.7 — host application; 0x42022524.
 * Instruction-checked recovered C.
 * Original function-byte SHA-256:
 * a6738a1b486ffa5edea0ec1346551660de799122f34fe84b218ded5978d8a827.
 */

/* Register /dev/uart using its fixed static operation table, flag0x08 and NULL
 * context. Any nonzero registration result aborts; otherwise return zero. This
 * does not install a UART driver, reinitialize contexts or undo earlier state. */
int medius_uart_vfs_register(void)
{
    if (uart_vfs_register_filesystem("/dev/uart",CONSOLE_INITIAL_BACKEND,8,NULL) != 0)
        abort();
    return 0;
}

/* Native entry: 0x42022540. */
/*
 * Medius v3.4.7 — host application; 0x42022540.
 * Instruction-checked recovered C.
 * Original function-byte SHA-256:
 * 50338ffadf4687414e7e730d594c8a96527a264fec4b10bd2ee6318047994367.
 */

/* Assert unsigned port<3, clear the complete 88-byte stat, then set mode to
 * S_IFCHR(0x2000) and return zero. Output is unchecked; no open/live-driver
 * validation, permission bits or error path is supplied. */
int medius_uart_vfs_status(int port,VfsStat *status)
{
    if ((unsigned int)port >= 3U) __assert_func(NULL,0,NULL,NULL);
    memset(status,0,sizeof(*status));
    status->mode = 0x2000U;
    return 0;
}

/* Native entry: 0x4202256c. */
/*
 * Medius v3.4.7 — host application; 0x4202256c.
 * Instruction-checked recovered C.
 * Original function-byte SHA-256:
 * 7f337c9c854ad700be69bfa7c1f111483cc42ccad2df74e7df949b65770aad1b.
 */

/* Assert unsigned port<3; hold the cached context's recursive WRITE-lock slot
 * while ROM waits for TX idle. Unlock the same slot and return zero. Unlike
 * tcdrain, no driver wait status/timeout or errno translation is involved. */
int medius_uart_vfs_sync(int port)
{
    if ((unsigned int)port >= 3U) __assert_func(NULL,0,NULL,NULL);
    NewlibLock *write_lock = &MEDIUS_UART_VFS_CONTEXTS[port]->write_lock;
    _lock_acquire_recursive(write_lock);
    uart_vfs_rom_wait_idle(port);
    _lock_release_recursive(write_lock);
    return 0;
}

/* Native entry: 0x420225a8. */
/*
 * Medius v3.4.7 — host application; 0x420225a8.
 * Instruction-checked recovered C.
 * Original function-byte SHA-256:
 * 67c11d8fe44ec1585ac202ce22dbdca36791e158b664726babf2b905799fd6fc.
 */

/* Read under the cached context's recursive READ-lock slot. Blocking mode first
 * consumes lookahead or calls read_char, even for a zero-length request; basic
 * FIFO callbacks themselves never wait. Nonblocking skips this prefetch. Add
 * available() count, a prefetched byte and any newly present lookahead modulo
 * 2^32, cap to requested length, then emit at most that budget. RX mode1 maps
 * CR to LF; mode0 merges CRLF, retaining a non-LF second byte in lookahead.
 * A trailing CR without lookahead is retained for the next read and returns the
 * prefix already produced. Empty output (including length0) unlocks and returns
 * -1/EWOULDBLOCK(11). A zero-budget prefetch is restored, asserting if its slot
 * was refilled. Assert also on bad port, a promised byte missing during fetch,
 * or a callback-refilled slot that would be overwritten by lookahead pushback.
 * Keep native callback order, cached context, count wrapping, and lookahead
 * snapshots across callbacks. No destination check, NUL terminator or errno
 * clear on success. The caller must provide writable storage for the result. */
int medius_uart_vfs_read(int port,void *data,unsigned int length)
{
    if ((unsigned int)port >= 3U) __assert_func(NULL,0,NULL,NULL);
    MediusUartVfsContext *context = MEDIUS_UART_VFS_CONTEXTS[port];
    NewlibLock *read_lock = &context->read_lock;
    _lock_acquire_recursive(read_lock);
    int current = -1;
    unsigned int available;
    int lookahead;
    if (context->nonblocking) {
        available = context->available(port);
        lookahead = context->lookahead;
    } else {
        current = context->lookahead;
        if (current != -1) context->lookahead = -1;
        else current = context->read_char(port);
        available = context->available(port);
        lookahead = context->lookahead;
        if (current != -1) ++available;
    }
    if (lookahead != -1) ++available;
    unsigned int budget = available < length ? available : length;
    if (budget == 0) {
        if (current != -1) {
            if (lookahead != -1) __assert_func(NULL,0,NULL,NULL);
            context->lookahead = current;
        }
        _lock_release_recursive(read_lock);
        *uart_vfs_current_errno() = 11;
        return -1;
    }
    unsigned int received = 0;
    for (;;) {
        if (current == -1) {
            current = lookahead;
            if (current != -1) context->lookahead = -1;
            else current = context->read_char(port);
            if (current == -1) __assert_func(NULL,0,NULL,NULL);
        }
        unsigned char output = (unsigned char)current;
        if (current == '\r') {
            int rx_mode = context->rx_mode;
            if (rx_mode == MEDIUS_UART_LINE_ENDINGS_CR) output = '\n';
            else if (rx_mode == MEDIUS_UART_LINE_ENDINGS_CRLF) {
                int second = context->lookahead;
                if (second != -1) {
                    context->lookahead = -1;
                } else {
                    second = context->read_char(port);
                    if (second == -1) {
                        if (context->lookahead != -1) __assert_func(NULL,0,NULL,NULL);
                        context->lookahead = '\r';
                        _lock_release_recursive(read_lock);
                        if (received != 0) return (int)received;
                        *uart_vfs_current_errno() = 11;
                        return -1;
                    }
                    if (second != '\n' && context->lookahead != -1)
                        __assert_func(NULL,0,NULL,NULL);
                }
                if (second == '\n') { --budget; output = '\n'; }
                else context->lookahead = second;
            }
        }
        *(unsigned char *)((unsigned int)data + received) = output;
        ++received;
        if (received >= budget) break;
        lookahead = context->lookahead;
        current = -1;
    }
    _lock_release_recursive(read_lock);
    return (int)received;
}
