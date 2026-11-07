/* Medius v3.4.7 host — drivers/console.c.
 * This image uses /dev/uart/0 as its console backing.
 */

#include "../include/types.h"

/* Source reconstruction utilities; not additional native firmware entries. */
extern int *console_current_errno(void) __asm__("__errno");
extern int console_register_filesystem(const char *,const VfsOperations *,int,void *)
    __asm__("FUN_4203274c");

/* Native entry: 0x42008b00. */
/*
 * Medius v3.4.7 — host application; 0x42008b00.
 * Instruction-checked recovered C.
 * Original function-byte SHA-256:
 * d5e541949eddb3a0b379a2fded98eebf45884303198d1a38b715f56f0eeaddc6.
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

/* Native entry: 0x42008b30. */
/*
 * Medius v3.4.7 — host application; 0x42008b30.
 * Instruction-checked recovered C.
 * Original function-byte SHA-256:
 * 3ed826da378b64df25172db4304e1a0504440d35e587f72a4cb9575482e2cfa7.
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

/* Native entry: 0x42008b4c. */
/*
 * Medius v3.4.7 — host application; 0x42008b4c.
 * Instruction-checked recovered C.
 * Original function-byte SHA-256:
 * 28af6af7027428dfc2deea8045afbf1a0a396152bc20bb97ae5d11c4cb889977.
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

/* Native entry: 0x42008b64. */
/*
 * Medius v3.4.7 — host application; 0x42008b64.
 * Instruction-checked recovered C.
 * Original function-byte SHA-256:
 * 0f223128273389796e3af88efbf1b91c765a3e15bb6849f28e78a0fc7cdd9ff2.
 */

/* Ignore the local descriptor, sample the shared backing fd once, and forward
 * status storage through current-context fstat. Return the backend word; no
 * open-count gate, status clear, pointer check, errno reset or extra lock. */
int console_status(int descriptor,VfsStat *status)
{
    (void)descriptor;
    return vfs_status_current(CONSOLE_DESCRIPTOR,status);
}

/* Native entry: 0x42008b78. */
/*
 * Medius v3.4.7 — host application; 0x42008b78.
 * Instruction-checked recovered C.
 * Original function-byte SHA-256:
 * 07f930b593f0618705f0da048f781523c08612a4fb04593a429d57f013debed9.
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

/* Native entry: 0x42008b90. */
/*
 * Medius v3.4.7 — host application; 0x42008b90.
 * Instruction-checked recovered C.
 * Original function-byte SHA-256:
 * 11cb0ff2f58f4abe1a74a575173cab620c7afcaf2a4e6042564724ba442dfc3d.
 */

/* Replace the ignored local descriptor with the sampled shared backing fd;
 * forward command and argument word through current-context fcntl. Return its
 * word and retain errno effects. No command filtering, count gate or lock. */
int console_control(int descriptor,int command,int argument)
{
    (void)descriptor;
    return vfs_control_current(CONSOLE_DESCRIPTOR,command,argument);
}

/* Native entry: 0x42008ba8. */
/*
 * Medius v3.4.7 — host application; 0x42008ba8.
 * Instruction-checked recovered C.
 * Original function-byte SHA-256:
 * 253ac5fb074d0edd8dc0169934cef33910f10b57388e54fccbfac58da50bef66.
 */

/* Ignore the local descriptor and fsync the sampled shared backing fd through
 * the current-context dispatcher. Return its word unchanged. No open-count
 * check, independent device flush, errno reset or additional locking. */
int console_sync(int descriptor)
{
    (void)descriptor;
    return vfs_sync_current(CONSOLE_DESCRIPTOR);
}

/* Native entry: 0x42008bbc. */
/*
 * Medius v3.4.7 — host application; 0x42008bbc.
 * Instruction-checked recovered C.
 * Original function-byte SHA-256:
 * 07427e961c081a44744cc9ea59d9fa5aca74c34f0810c4ed9168d346cfccc533.
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

/* Native entry: 0x42008bd0. */
/*
 * Medius v3.4.7 — host application; 0x42008bd0.
 * Instruction-checked recovered C.
 * Original function-byte SHA-256:
 * b58e0ed851c311d67381120ada9e2252f11372b3c0bb42b84d967c816cbdccea.
 */

/* Ignore the console-local descriptor; sample shared backing fd and forward
 * action/borrowed termios pointer unchanged to current-context tcsetattr. No
 * structure access, count gate, option validation, errno reset or extra lock. */
int console_set_attributes(int descriptor,int action,const struct termios *attributes)
{
    (void)descriptor;
    return vfs_set_attributes_current(CONSOLE_DESCRIPTOR,action,attributes);
}

/* Native entry: 0x42008be8. */
/*
 * Medius v3.4.7 — host application; 0x42008be8.
 * Instruction-checked recovered C.
 * Original function-byte SHA-256:
 * 8beebf7128e3a28782b83f546c28d508d756f9e6634f97914a943c018e7af9bf.
 */

/* Ignore local descriptor; sample backing fd and forward borrowed writable
 * termios storage through current-context tcgetattr. Return status unchanged;
 * no structure clear/access, count gate, errno reset or additional lock. */
int console_get_attributes(int descriptor,struct termios *attributes)
{
    (void)descriptor;
    return vfs_get_attributes_current(CONSOLE_DESCRIPTOR,attributes);
}

/* Native entry: 0x42008bfc. */
/*
 * Medius v3.4.7 — host application; 0x42008bfc.
 * Instruction-checked recovered C.
 * Original function-byte SHA-256:
 * b57ac03c4794c1e4d4b859f73094dc78d223aadc8ed9af8288d92aed88b4fc9f.
 */

/* Ignore local descriptor and tcdrain the sampled shared backing fd. Return
 * dispatcher status unchanged; no open-count gate, retry, local wait policy,
 * errno reset or extra lock. The separate backend supplies drain behavior. */
int console_drain(int descriptor)
{
    (void)descriptor;
    return vfs_drain_current(CONSOLE_DESCRIPTOR);
}

/* Native entry: 0x42008c10. */
/*
 * Medius v3.4.7 — host application; 0x42008c10.
 * Instruction-checked recovered C.
 * Original function-byte SHA-256:
 * 28074f6654f88b77db76031494a40107bcc1a038a453625e73cd53f8ad09137a.
 */

/* Ignore local descriptor; tcflush the sampled shared backing fd with the
 * unchanged queue-selection word. Return dispatcher status. No local queue
 * access, selection validation, open-count gate, errno reset or extra lock. */
int console_flush(int descriptor,int queue)
{
    (void)descriptor;
    return vfs_flush_current(CONSOLE_DESCRIPTOR,queue);
}

/* Native entry: 0x42008c24. */
/*
 * Medius v3.4.7 — host application; 0x42008c24.
 * Instruction-checked recovered C.
 * Original function-byte SHA-256:
 * 0ce07a577dc62707970ddab0727f1c32ea6d65d2d07e75aa9b48f883ea5b8af4.
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

/* Native entry: 0x42008c4c. */
/*
 * Medius v3.4.7 — host application; 0x42008c4c.
 * Instruction-checked recovered C.
 * Original function-byte SHA-256:
 * cdeafea628e6c02d27d9caa5de6b51596b090d5fb58dec8aac164661ccf07e8d.
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

/* Native entry: 0x42008c7c. */
/*
 * Medius v3.4.7 — host application; 0x42008c7c.
 * Instruction-checked recovered C.
 * Original function-byte SHA-256:
 * d9c69a07807e7234b46926ff0d742eae15f4d93cad894bb783ada6d3851ba455.
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
