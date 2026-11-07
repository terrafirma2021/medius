/* Medius v3.4.7 device — drivers/console.c.
 * This image uses /dev/null as its console backing.
 */

#include "../include/types.h"

/* Source reconstruction utilities; not additional native firmware entries. */
extern int *console_current_errno(void) __asm__("__errno");
extern int console_register_filesystem(const char *,const VfsOperations *,int,void *)
    __asm__("FUN_42039cdc");

/* Native entry: 0x42007c44. */
/*
 * Medius v3.4.7 — device application; 0x42007c44.
 * Instruction-checked recovered C.
 * Original function-byte SHA-256:
 * 1a2ce81732e7b7fde8221cf61eac443191f31d7af22ad7c3f890b317d8a75025.
 */

/*
 * Load the selected backing operations, its select subtable, then start_select
 * ONCE each. A NULL callback returns ESP_ERR_NOT_SUPPORTED(0x106); otherwise
 * forward nfds, all three fd-set pointers, the complete 8-byte semaphore value
 * and end_select_arguments, returning the callback word unchanged. The seventh
 * native argument word is the final pointer; the preceding two form semaphore.
 * No context-flag dispatch occurs. The backing table and select subtable must
 * be non-NULL: only the callback is guarded. No allocation, errno write, fd
 * remapping, semaphore validation or local lock is supplied here.
 */
int console_start_select(int count,fd_set *read_set,fd_set *write_set,
    fd_set *error_set,VfsSelectSemaphore semaphore,void **end_select_arguments)
{
    const volatile VfsOperations *operations = CONSOLE_BACKEND_OPERATIONS;
    const volatile VfsSelectOperations *select = operations->select;
    VfsStartSelectOperation callback = select->start;
    if (!callback) return 0x106;
    return callback(count,read_set,write_set,error_set,semaphore,end_select_arguments);
}

/* Native entry: 0x42007c74. */
/*
 * Medius v3.4.7 — device application; 0x42007c74.
 * Instruction-checked recovered C.
 * Original function-byte SHA-256:
 * 5f9ed60e42434d3d2db8b400d7c304598b9c288eeaaf3174aa17aa315b00e0fe.
 */

/*
 * Load backing operations/select/end callback once. A NULL callback returns
 * 0x106; otherwise forward the borrowed end-select pointer and return the full
 * callback result. The outer operations/select pointers are not NULL-checked.
 * No context dispatch, cleanup, argument validation, errno write or extra lock.
 */
int console_end_select(void *arguments)
{
    const volatile VfsOperations *operations = CONSOLE_BACKEND_OPERATIONS;
    const volatile VfsSelectOperations *select = operations->select;
    VfsEndSelectOperation callback = select->end;
    return callback ? callback(arguments) : 0x106;
}

/* Native entry: 0x42007c90. */
/*
 * Medius v3.4.7 — device application; 0x42007c90.
 * Instruction-checked recovered C.
 * Original function-byte SHA-256:
 * aad02c5929fb1431104f3486bb08328184472d37765999507f580b12141f2d88.
 */

/*
 * Ignore the console-local descriptor; sample the single shared backing fd
 * and issue a current-context VFS write with the original data/length. Discard
 * its result, including errors/partial writes, and return all 32 requested length
 * bits as the native signed result. Backend errno changes remain. No open-count
 * gate, retry, NULL-data validation or independent locking occurs here.
 */
int console_write(int descriptor,const void *data,unsigned int length)
{
    (void)descriptor;
    int backing = CONSOLE_DESCRIPTOR;
    (void)vfs_write_current(backing,data,length);
    return (int)length;
}

/* Native entry: 0x42007ca8. */
/*
 * Medius v3.4.7 — device application; 0x42007ca8.
 * Instruction-checked recovered C.
 * Original function-byte SHA-256:
 * b0ed0d58817cf9ca854bf96b48b06feaaece8d2526b1fa890c5fa4dfb5241446.
 */

/* Ignore the local descriptor, sample the shared backing fd once, and forward
 * status storage through current-context fstat. Return the backend word; no
 * open-count gate, status clear, pointer check, errno reset or extra lock. */
int console_status(int descriptor,VfsStat *status)
{
    (void)descriptor;
    return vfs_status_current(CONSOLE_DESCRIPTOR,status);
}

/* Native entry: 0x42007cbc. */
/*
 * Medius v3.4.7 — device application; 0x42007cbc.
 * Instruction-checked recovered C.
 * Original function-byte SHA-256:
 * dbfa3123292638f0527fa152c56982619147947adef124563ae1aeed779a0b6e.
 */

/* Ignore the local descriptor; sample backing fd and forward the original
 * destination/length through current-context read. Return its word unchanged,
 * including zero/negative/partial results. No count gate, buffer access, retry,
 * errno reset or independent lock; the VFS/backend owns validation and IO. */
int console_read(int descriptor,void *data,unsigned int length)
{
    (void)descriptor;
    return vfs_read_current(CONSOLE_DESCRIPTOR,data,length);
}

/* Native entry: 0x42007cd4. */
/*
 * Medius v3.4.7 — device application; 0x42007cd4.
 * Instruction-checked recovered C.
 * Original function-byte SHA-256:
 * b12b7030015cbba5bcd8a192b7b13275cec1171f9c47ea9724778eae40d513b6.
 */

/* Replace the ignored local descriptor with the sampled shared backing fd;
 * forward command and argument word through current-context fcntl. Return its
 * word and retain errno effects. No command filtering, count gate or lock. */
int console_control(int descriptor,int command,int argument)
{
    (void)descriptor;
    return vfs_control_current(CONSOLE_DESCRIPTOR,command,argument);
}

/* Native entry: 0x42007cec. */
/*
 * Medius v3.4.7 — device application; 0x42007cec.
 * Instruction-checked recovered C.
 * Original function-byte SHA-256:
 * b582277bc2f9e85720dff1573dcf8f61c1f2300469eabf3e9d87458dc70fafa7.
 */

/* Ignore the local descriptor and fsync the sampled shared backing fd through
 * the current-context dispatcher. Return its word unchanged. No open-count
 * check, independent device flush, errno reset or additional locking. */
int console_sync(int descriptor)
{
    (void)descriptor;
    return vfs_sync_current(CONSOLE_DESCRIPTOR);
}

/* Native entry: 0x42007d00. */
/*
 * Medius v3.4.7 — device application; 0x42007d00.
 * Instruction-checked recovered C.
 * Original function-byte SHA-256:
 * 043f4372a26326259e72cd844ffae17b617840cb50f999f770ef24067338cc58.
 */

/* Ignore the console-relative path; test the fixed access-probe path
 * using the original access_mode word. Host probes /dev/uart/0; device probes
 * /dev/uart/-1 even though its open path is /dev/null. Return current-context access status unchanged, with
 * no open-fd use, mode validation, count gate or local errno handling. */
int console_access(const char *path,int access_mode)
{
    (void)path;
    return vfs_access_current(CONSOLE_ACCESS_PATH,access_mode);
}

/* Native entry: 0x42007d14. */
/*
 * Medius v3.4.7 — device application; 0x42007d14.
 * Instruction-checked recovered C.
 * Original function-byte SHA-256:
 * c794fa8af4c5a11a5bc77f00fdce1fc4d2132330d4127abf330d83fbe601f6ca.
 */

/* Ignore the console-local descriptor; sample shared backing fd and forward
 * action/borrowed termios pointer unchanged to current-context tcsetattr. No
 * structure access, count gate, option validation, errno reset or extra lock. */
int console_set_attributes(int descriptor,int action,const struct termios *attributes)
{
    (void)descriptor;
    return vfs_set_attributes_current(CONSOLE_DESCRIPTOR,action,attributes);
}

/* Native entry: 0x42007d2c. */
/*
 * Medius v3.4.7 — device application; 0x42007d2c.
 * Instruction-checked recovered C.
 * Original function-byte SHA-256:
 * db2996f33bcf13c26da48727f81dcf7ce71e88c8c8f4f1771c30b57d7a64f46d.
 */

/* Ignore local descriptor; sample backing fd and forward borrowed writable
 * termios storage through current-context tcgetattr. Return status unchanged;
 * no structure clear/access, count gate, errno reset or additional lock. */
int console_get_attributes(int descriptor,struct termios *attributes)
{
    (void)descriptor;
    return vfs_get_attributes_current(CONSOLE_DESCRIPTOR,attributes);
}

/* Native entry: 0x42007d40. */
/*
 * Medius v3.4.7 — device application; 0x42007d40.
 * Instruction-checked recovered C.
 * Original function-byte SHA-256:
 * 0c76de4f52b857d39fccf04b9e60fe16f25d98905abb931f8872c0c8188acc2c.
 */

/* Ignore local descriptor and tcdrain the sampled shared backing fd. Return
 * dispatcher status unchanged; no open-count gate, retry, local wait policy,
 * errno reset or extra lock. The separate backend supplies drain behavior. */
int console_drain(int descriptor)
{
    (void)descriptor;
    return vfs_drain_current(CONSOLE_DESCRIPTOR);
}

/* Native entry: 0x42007d54. */
/*
 * Medius v3.4.7 — device application; 0x42007d54.
 * Instruction-checked recovered C.
 * Original function-byte SHA-256:
 * 40624c5a54168e192269a286d0677630941bdcbc96f610421a43127d36c008f0.
 */

/* Ignore local descriptor; tcflush the sampled shared backing fd with the
 * unchanged queue-selection word. Return dispatcher status. No local queue
 * access, selection validation, open-count gate, errno reset or extra lock. */
int console_flush(int descriptor,int queue)
{
    (void)descriptor;
    return vfs_flush_current(CONSOLE_DESCRIPTOR,queue);
}

/* Native entry: 0x42007d68. */
/*
 * Medius v3.4.7 — device application; 0x42007d68.
 * Instruction-checked recovered C.
 * Original function-byte SHA-256:
 * 013de20514252ae8051a7fe3abb9cd138bc7e0a1c8bbaf9c9d8f5951c8c31acf.
 */

/*
 * Ignore path. Snapshot shared open count. When zero, open the fixed backing
 * path using the original flags/mode; then reread count BEFORE publishing the
 * returned backing fd. Publish cached_or_reread_count+1 modulo 2^32 and return
 * zero unconditionally, even if open returned -1. A nonzero initial count skips
 * both open and the second count read. No lock, fd/error validation or rollback
 * is present; concurrent changes and counter wrap can desynchronize ownership.
 */
int console_open(const char *path,int flags,int mode)
{
    (void)path;
    unsigned int count = CONSOLE_REFERENCE_COUNT;
    if (count == 0) {
        int backing = vfs_open_current(CONSOLE_BACKING_PATH,flags,mode);
        count = CONSOLE_REFERENCE_COUNT;
        CONSOLE_DESCRIPTOR = backing;
    }
    CONSOLE_REFERENCE_COUNT = count + 1U;
    return 0;
}

/* Native entry: 0x42007d90. */
/*
 * Medius v3.4.7 — device application; 0x42007d90.
 * Instruction-checked recovered C.
 * Original function-byte SHA-256:
 * 06f667fcd627505ed049a4a03de2a607305366b58e6f3dc0d918c757dbe5af1f.
 */

/*
 * Ignore local descriptor. Zero initial count sets current errno 9 and returns
 * -1. Otherwise store cached_count-1 modulo 2^32. Only when that stored value is
 * zero, freshly sample backing fd and close it through current-context VFS.
 * Ignore close status and return zero, leaving the backing-fd field intact.
 * No lock, live-fd check, counter reread after the store or rollback is supplied.
 */
int console_close(int descriptor)
{
    (void)descriptor;
    unsigned int count = CONSOLE_REFERENCE_COUNT;
    if (count == 0) {
        *console_current_errno() = 9;
        return -1;
    }
    unsigned int remaining = count - 1U;
    CONSOLE_REFERENCE_COUNT = remaining;
    if (remaining == 0) (void)vfs_close_current(CONSOLE_DESCRIPTOR);
    return 0;
}

/* Native entry: 0x42007dc0. */
/*
 * Medius v3.4.7 — device application; 0x42007dc0.
 * Instruction-checked recovered C.
 * Original function-byte SHA-256:
 * 57987d2d0bee2883a55fa706410466f102494bfb06f17da03a2502840e10894c.
 */

/* Publish the selected backing operations BEFORE registering /dev/console
 * with its fixed static operation table, STATIC flag 0x08 and NULL context. Host
 * selection is UART; device selection is null. Return registration status even
 * on failure, retaining the published pointer. No count/fd reset or rollback. */
int console_register(void)
{
    const VfsOperations *operations = CONSOLE_GET_BACKEND();
    CONSOLE_BACKEND_OPERATIONS = operations;
    return console_register_filesystem("/dev/console",CONSOLE_OPERATIONS,8,NULL);
}
