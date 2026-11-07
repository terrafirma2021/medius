/* Medius v3.4.7 host — runtime/vfs_terminal.c.
 */

#include "../include/types.h"

/* Source reconstruction utilities; not additional native firmware entries. */
extern NewlibReent *terminal_current_reent(void) __asm__("__getreent");
static const volatile VfsDriverEntry *terminal_descriptor_entry(int descriptor)
{
    if ((unsigned int)descriptor >= 64) return NULL;
    int index = MEDIUS_VFS_DESCRIPTORS[descriptor].driver_index;
    if (index < 0) return NULL;
    unsigned int count = VFS_DRIVER_COUNT;
    if ((unsigned int)index >= count) return NULL;
    return VFS_DRIVERS[index];
}

/* Native entry: 0x42032f7c. */
/*
 * Medius v3.4.7 — host application; 0x42032f7c.
 * Instruction-checked recovered C.
 * Original function-byte SHA-256:
 * 999109a5caae50e86468b3b97fbcc48ee47759da30958692914618cefc57bdd3.
 */

/*
 * Validate unsigned fd<64, signed 8-bit driver index>=0 and below freshly read driver
 * count, then non-NULL registered entry. Failure gets current reent ONCE and
 * writes EBADF (9). Success caches local descriptor byte BEFORE current-reent
 * lookup; then freshly loads operations/termios/get callback. Missing termios
 * subtable/callback writes ENOSYS (88). Fresh mount flag 0x02 selects context/local/
 * attributes versus local/attributes. Return backend word unchanged. No outer
 * operations-pointer/attributes check, errno copy/reset, lifetime lock or MEMW.
 */
int vfs_get_attributes_current(int descriptor,struct termios *attributes)
{
    const volatile VfsDriverEntry *entry = terminal_descriptor_entry(descriptor);
    if (!entry) {NewlibReent *reent=terminal_current_reent();reent->error_number=9;return -1;}
    unsigned int local = MEDIUS_VFS_DESCRIPTORS[descriptor].local_descriptor;
    NewlibReent *reent = terminal_current_reent();
    const volatile VfsTerminalOperations *terminal = entry->operations->terminal;
    if (!terminal) {reent->error_number=88;return -1;}
    VfsGetAttributesOperation callback = terminal->get_attributes;
    if (!callback.plain) {reent->error_number=88;return -1;}
    if (entry->flags & 2U) return callback.with_context(entry->context,local,attributes);
    return callback.plain(local,attributes);
}

/* Native entry: 0x42032ff4. */
/*
 * Medius v3.4.7 — host application; 0x42032ff4.
 * Instruction-checked recovered C.
 * Original function-byte SHA-256:
 * 130dcecde6ddf33a20479789bdda25749064417da6ad1e2403e6e0694e3ef87a.
 */

/*
 * Apply the descriptor/index/current-count/entry gates; failure calls current
 * reent once and writes EBADF (9). Cache unsigned local byte before context lookup,
 * then load current operations/termios/set callback, giving ENOSYS (88) if subtable
 * or callback is missing. Fresh flag 0x02 adds current entry context before local
 * fd/action/borrowed termios pointer; otherwise pass local/action/pointer.
 * No action/structure/outer-operations validation, errno reset/copy, MEMW or
 * lifetime lock occurs. The backend result and all 32 action bits pass through.
 */
int vfs_set_attributes_current(int descriptor,int action,const struct termios *attributes)
{
    const volatile VfsDriverEntry *entry = terminal_descriptor_entry(descriptor);
    if (!entry) {NewlibReent *reent=terminal_current_reent();reent->error_number=9;return -1;}
    unsigned int local = MEDIUS_VFS_DESCRIPTORS[descriptor].local_descriptor;
    NewlibReent *reent = terminal_current_reent();
    const volatile VfsTerminalOperations *terminal = entry->operations->terminal;
    if (!terminal) {reent->error_number=88;return -1;}
    VfsSetAttributesOperation callback = terminal->set_attributes;
    if (!callback.plain) {reent->error_number=88;return -1;}
    if (entry->flags & 2U) return callback.with_context(entry->context,local,action,attributes);
    return callback.plain(local,action,attributes);
}

/* Native entry: 0x42033070. */
/*
 * Medius v3.4.7 — host application; 0x42033070.
 * Instruction-checked recovered C.
 * Original function-byte SHA-256:
 * 306777f01e970d8f9f797a3f079513c39be0ce8780126852052b7a433826636a.
 */

/*
 * Gate unsigned fd<64, signed 8-bit nonnegative driver index below current count,
 * and a non-NULL entry. Failure calls current reent once, writes EBADF (9), returns
 * -1. Cache unsigned local byte before current context; freshly load operations,
 * termios and drain callback. Missing subtable/callback gives ENOSYS (88). Fresh
 * flag 0x02 selects context/local versus local. Return backend word without adding
 * a local timeout/wait, errno reset/copy, outer-pointer check, lock or MEMW.
 */
int vfs_drain_current(int descriptor)
{
    const volatile VfsDriverEntry *entry = terminal_descriptor_entry(descriptor);
    if (!entry) {NewlibReent *reent=terminal_current_reent();reent->error_number=9;return -1;}
    unsigned int local = MEDIUS_VFS_DESCRIPTORS[descriptor].local_descriptor;
    NewlibReent *reent = terminal_current_reent();
    const volatile VfsTerminalOperations *terminal = entry->operations->terminal;
    if (!terminal) {reent->error_number=88;return -1;}
    VfsSyncOperation callback = terminal->drain;
    if (!callback.plain) {reent->error_number=88;return -1;}
    if (entry->flags & 2U) return callback.with_context(entry->context,local);
    return callback.plain(local);
}

/* Native entry: 0x420330e4. */
/*
 * Medius v3.4.7 — host application; 0x420330e4.
 * Instruction-checked recovered C.
 * Original function-byte SHA-256:
 * 91e344408cde85a0bb699d164498ef8e7596b9cf5e70240b83e8f1ea716b9fcc.
 */

/*
 * Apply fd/index/current-count/entry gates, giving EBADF (9) via one current-reent
 * lookup on failure. On success cache local byte before current context, then
 * load operations/termios/flush callback; absent subtable/callback gives
 * ENOSYS (88). Fresh flag 0x02 selects context/local/queue versus local/queue. All queue
 * bits and backend status pass through. No local queue access/validation,
 * timeout, errno copy/reset, outer-pointer check, extra lock or MEMW occurs.
 */
int vfs_flush_current(int descriptor,int queue)
{
    const volatile VfsDriverEntry *entry = terminal_descriptor_entry(descriptor);
    if (!entry) {NewlibReent *reent=terminal_current_reent();reent->error_number=9;return -1;}
    unsigned int local = MEDIUS_VFS_DESCRIPTORS[descriptor].local_descriptor;
    NewlibReent *reent = terminal_current_reent();
    const volatile VfsTerminalOperations *terminal = entry->operations->terminal;
    if (!terminal) {reent->error_number=88;return -1;}
    VfsControlOneOperation callback = terminal->flush;
    if (!callback.plain) {reent->error_number=88;return -1;}
    if (entry->flags & 2U) return callback.with_context(entry->context,local,queue);
    return callback.plain(local,queue);
}

/* Native entry: 0x42032cc8. */
/*
 * Medius v3.4.7 — host application; 0x42032cc8.
 * Instruction-checked recovered C.
 * Original function-byte SHA-256:
 * 76cf1f311ad64301a4b7531e4ab9bb58a039d23478391d65b6218d8d436dc698.
 */

/*
 * Apply fd/index/current-count/entry gates. Failure obtains current reent once
 * and writes EBADF (9). Success caches unsigned local byte before current-context
 * lookup, then loads current operations/sync callback directly at +0x28. NULL
 * callback gives ENOSYS (88). Fresh flag 0x02 adds current entry context before local
 * fd; otherwise pass local alone. Return backend result unchanged; no local
 * flush, errno copy/reset, outer-pointer validation, lifetime lock or MEMW.
 */
int vfs_sync_current(int descriptor)
{
    const volatile VfsDriverEntry *entry = terminal_descriptor_entry(descriptor);
    if (!entry) {NewlibReent *reent=terminal_current_reent();reent->error_number=9;return -1;}
    unsigned int local = MEDIUS_VFS_DESCRIPTORS[descriptor].local_descriptor;
    NewlibReent *reent = terminal_current_reent();
    VfsSyncOperation callback = entry->operations->sync;
    if (!callback.plain) {reent->error_number=88;return -1;}
    if (entry->flags & 2U) return callback.with_context(entry->context,local);
    return callback.plain(local);
}

/* Native entry: 0x420071b8. */
/*
 * Medius v3.4.7 — host application; 0x420071b8.
 * Instruction-checked recovered C.
 * Original function-byte SHA-256:
 * 6834188a11cb26825f1c9a8fa8a2d6a4c1af0cb5ae66bc2623a7501e737b97f6.
 */

/*
 * Current-context variadic fcntl facade. Save the native argument area, obtain
 * current reent once and forward fd, command and the first variadic int word to
 * the reviewed VFS control dispatcher. The third word is consumed regardless
 * of command; no default or command-dependent omission is introduced. Native
 * unused va-list bookkeeping is represented by normal va_start/va_end. Return
 * the dispatcher word without local validation, errno reset or extra locking.
 */
int vfs_control_current(int descriptor,int command,...)
{
    va_list arguments;
    va_start(arguments,command);
    NewlibReent *reent = terminal_current_reent();
    int argument = va_arg(arguments,int);
    va_end(arguments);
    return medius_vfs_control(reent,descriptor,command,argument);
}
