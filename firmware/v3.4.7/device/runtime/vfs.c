/* Medius v3.4.7 device — runtime/vfs.c.
 */

#include "../include/types.h"

/* Source reconstruction utilities; not additional native firmware entries. */
extern NewlibReent *vfs_current_reent(void) __asm__("__getreent");

static const volatile VfsDriverEntry *vfs_descriptor_entry(int descriptor)
{
    if ((unsigned int)descriptor >= 64) return NULL;
    int index = MEDIUS_VFS_DESCRIPTORS[descriptor].driver_index;
    if (index < 0) return NULL;
    unsigned int count = VFS_DRIVER_COUNT;
    if ((unsigned int)index >= count) return NULL;
    return VFS_DRIVERS[index];
}

/* Native entry: 0x42039fa4. */
/*
 * Medius v3.4.7 — device application; 0x42039fa4.
 * Instruction-checked recovered C.
 * Original function-byte SHA-256:
 * 8039fb1a8d7ba459d94c5475bbc1d71e5d62e1a6c91b9157cf2a5aadb0b4d653.
 */

/*
 * Dispatch a descriptor write. Reject unsigned descriptor >=64, a negative
 * signed8 driver index, an index >= the current unsigned driver count, or a
 * NULL registered entry: write EBADF (9) into reent and return -1. Otherwise
 * read the operation-table pointer, local descriptor byte, then write callback.
 * A missing callback writes ENOSYS (88) and returns -1. Entry flag bit1 selects
 * context/local-descriptor/data/length versus local-descriptor/data/length.
 * Return the backend word unchanged. The local byte, including 255, is passed
 * unsigned; no buffer/length, operations-pointer or reent validation, lock,
 * MEMW, lifetime protection or errno copy/reset occurs. reent is used only on
 * an error path; successful backend dispatch does not dereference it here.
 */
int medius_vfs_write(NewlibReent *reent,int descriptor,
    const void *data,unsigned int length)
{
    const volatile VfsDriverEntry *entry = vfs_descriptor_entry(descriptor);
    if (!entry) { reent->error_number = 9; return -1; }
    const volatile VfsOperations *operations = entry->operations;
    unsigned int local = MEDIUS_VFS_DESCRIPTORS[descriptor].local_descriptor;
    VfsWriteOperation callback = operations->write;
    if (!callback.plain) { reent->error_number = 88; return -1; }
    unsigned int flags = entry->flags;
    if (flags & 2U) return callback.with_context(entry->context,local,data,length);
    return callback.plain(local,data,length);
}

/* Native entry: 0x4203a010. */
/*
 * Medius v3.4.7 — device application; 0x4203a010.
 * Instruction-checked recovered C.
 * Original function-byte SHA-256:
 * e0228a787d85d1b322a443a5b841df5c5853dc3ae88996294d586490488c8d21.
 */

/*
 * Dispatch a signed32 seek offset/origin through operation slot +4. Apply the
 * same descriptor/index/count/entry gates as write, returning -1 with EBADF9;
 * a missing seek callback returns -1 with ENOSYS88. Read operations pointer,
 * local byte, callback, then flags in that order. Flag bit1 adds the context
 * before the unsigned local byte. Offset/origin and backend result pass through
 * at full32 width. No origin/offset validation, errno reset/copy, lock, MEMW,
 * buffer access or operations-pointer check is added; reent is error-only.
 */
int medius_vfs_seek(NewlibReent *reent,int descriptor,int offset,int origin)
{
    const volatile VfsDriverEntry *entry = vfs_descriptor_entry(descriptor);
    if (!entry) { reent->error_number = 9; return -1; }
    const volatile VfsOperations *operations = entry->operations;
    unsigned int local = MEDIUS_VFS_DESCRIPTORS[descriptor].local_descriptor;
    VfsSeekOperation callback = operations->seek;
    if (!callback.plain) { reent->error_number = 88; return -1; }
    unsigned int flags = entry->flags;
    if (flags & 2U) return callback.with_context(entry->context,local,offset,origin);
    return callback.plain(local,offset,origin);
}

/* Native entry: 0x4203a07c. */
/*
 * Medius v3.4.7 — device application; 0x4203a07c.
 * Instruction-checked recovered C.
 * Original function-byte SHA-256:
 * 2254ca742f9148b9396c0562c783f7ae263a3f29a4c5b275d4d5ec4e5beadde8.
 */

/*
 * Dispatch a read through slot +8. Invalid descriptor/index/count/entry gives
 * reent errno9 and -1; missing callback gives errno88 and -1. Sample the local
 * descriptor byte before the callback slot, then sample flag bit1 to choose
 * context versus plain ABI. Forward destination, unsigned32 length and result
 * unchanged. This wrapper itself never reads/writes the destination and adds
 * no pointer, length, ownership, operations-table or reent check, lock or MEMW.
 * Backend errno handling is not copied into reent; reent is error-only here.
 */
int medius_vfs_read(NewlibReent *reent,int descriptor,
    void *data,unsigned int length)
{
    const volatile VfsDriverEntry *entry = vfs_descriptor_entry(descriptor);
    if (!entry) { reent->error_number = 9; return -1; }
    const volatile VfsOperations *operations = entry->operations;
    unsigned int local = MEDIUS_VFS_DESCRIPTORS[descriptor].local_descriptor;
    VfsReadOperation callback = operations->read;
    if (!callback.plain) { reent->error_number = 88; return -1; }
    unsigned int flags = entry->flags;
    if (flags & 2U) return callback.with_context(entry->context,local,data,length);
    return callback.plain(local,data,length);
}

/* Native entry: 0x4203a0e8. */
/*
 * Medius v3.4.7 — device application; 0x4203a0e8.
 * Instruction-checked recovered C.
 * Original function-byte SHA-256:
 * a1250b237e11164f11ee35eced76fb540547518ef5dc2916d6483a9831197f91.
 */

/*
 * Validate descriptor/index/count/entry, returning -1/errno9 on failure; a NULL
 * close slot +0x18 gives -1/errno88. Cache the local byte and callback before
 * flags, then invoke plain close(local) or context close(context,local). The
 * context form does pass the local descriptor; raw decompilation omitted it.
 *
 * After any backend result, including -1, acquire the descriptor-table lock
 * and reread this global descriptor's current flags. Permanent bit0 preserves
 * its whole row. Otherwise pending-select bit2 sets pending-close bit1 while
 * preserving other flags/bytes. With neither bit set, clear flags and write
 * driver_index=-1, then local_descriptor=255, in that order. Release the lock
 * and return the cached backend result unchanged. Callback/lock-time mutations
 * therefore affect cleanup; this is not a compare-against-original-entry check.
 * Early failures do not lock or alter the row. No explicit MEMW, rollback,
 * operations-pointer validation or backend-errno copy occurs.
 */
int medius_vfs_close(NewlibReent *reent,int descriptor)
{
    const volatile VfsDriverEntry *entry = vfs_descriptor_entry(descriptor);
    if (!entry) { reent->error_number = 9; return -1; }
    const volatile VfsOperations *operations = entry->operations;
    unsigned int local = MEDIUS_VFS_DESCRIPTORS[descriptor].local_descriptor;
    VfsCloseOperation callback = operations->close;
    if (!callback.plain) { reent->error_number = 88; return -1; }
    unsigned int flags = entry->flags;
    int result;
    if (flags & 2U) result = callback.with_context(entry->context,local);
    else result = callback.plain(local);
    _lock_acquire(&MEDIUS_VFS_DESCRIPTOR_LOCK);
    volatile MediusVfsDescriptor *row = &MEDIUS_VFS_DESCRIPTORS[descriptor];
    unsigned char current_flags = row->flags;
    if (!(current_flags & 1U)) {
        if (current_flags & 4U) row->flags = current_flags | 2U;
        else {
            row->flags = 0;
            row->driver_index = -1;
            row->local_descriptor = 255;
        }
    }
    _lock_release(&MEDIUS_VFS_DESCRIPTOR_LOCK);
    return result;
}

/* Native entry: 0x4203a184. */
/*
 * Medius v3.4.7 — device application; 0x4203a184.
 * Instruction-checked recovered C.
 * Original function-byte SHA-256:
 * 1cc86ec8083fcffe87fc585c4956616ff450dcd81c7af3110598b49325ff662d.
 */

/*
 * Dispatch fstat through slot +0x1c. Descriptor/index/count/entry errors write
 * errno9 and return -1; a missing callback writes errno88 and returns -1.
 * Cache the local byte before callback, then choose context/plain ABI via
 * flag bit1. Forward the opaque status pointer and full backend result without
 * inspecting the status layout or adding NULL/capacity checks. No row mutation,
 * lock, MEMW, operations-pointer check or errno copy/reset occurs. reent is
 * dereferenced only when dispatch fails before the backend call.
 */
int medius_vfs_status(NewlibReent *reent,int descriptor,VfsStat *status)
{
    const volatile VfsDriverEntry *entry = vfs_descriptor_entry(descriptor);
    if (!entry) { reent->error_number = 9; return -1; }
    const volatile VfsOperations *operations = entry->operations;
    unsigned int local = MEDIUS_VFS_DESCRIPTORS[descriptor].local_descriptor;
    VfsStatOperation callback = operations->status;
    if (!callback.plain) { reent->error_number = 88; return -1; }
    unsigned int flags = entry->flags;
    if (flags & 2U) return callback.with_context(entry->context,local,status);
    return callback.plain(local,status);
}

/* Native entry: 0x4203a1ec. */
/*
 * Medius v3.4.7 — device application; 0x4203a1ec.
 * Instruction-checked recovered C.
 * Original function-byte SHA-256:
 * 2f879453dede23bd0284db6b7b56c81ac651dba7f004b8be36e5246cebc023e9.
 */

/*
 * Dispatch fixed-argument fcntl through slot +0x20. Apply the descriptor range [0,63]
 * and signed8-index/current-count/entry gates, giving errno9/-1 on failure;
 * missing control callback gives errno88/-1. Sample operations pointer, unsigned
 * local byte, callback and flags in that order. Bit1 adds context before local,
 * command and argument. Forward all32 command/argument/result bits; no command
 * decoding, varargs extraction, lock, MEMW, operations-pointer validation or
 * backend-errno copy/reset occurs. The reent pointer is used only on errors.
 */
int medius_vfs_control(NewlibReent *reent,int descriptor,int command,int argument)
{
    const volatile VfsDriverEntry *entry = vfs_descriptor_entry(descriptor);
    if (!entry) { reent->error_number = 9; return -1; }
    const volatile VfsOperations *operations = entry->operations;
    unsigned int local = MEDIUS_VFS_DESCRIPTORS[descriptor].local_descriptor;
    VfsControlOperation callback = operations->control;
    if (!callback.plain) { reent->error_number = 88; return -1; }
    unsigned int flags = entry->flags;
    if (flags & 2U) return callback.with_context(entry->context,local,command,argument);
    return callback.plain(local,command,argument);
}

/* Native entry: 0x42019000. */
/*
 * Medius v3.4.7 — device application; 0x42019000.
 * Instruction-checked recovered C.
 * Original function-byte SHA-256:
 * 323507a19e07d0541c79e81305738e8360316aeef2b6739e4491c9ddb3b99597.
 */

/*
 * Current-context close facade: call __getreent once, then forward its pointer
 * and the entire descriptor word to the VFS close dispatcher. Return the backend
 * status unchanged. Context selection occurs even for an invalid descriptor;
 * no context allocation, pointer check, errno reset, stream access or extra lock
 * is supplied here. Descriptor cleanup belongs to the called dispatcher.
 */
int vfs_close_current(int descriptor)
{
    NewlibReent *reent = vfs_current_reent();
    return medius_vfs_close(reent,descriptor);
}

/* Native entry: 0x42019018. */
/*
 * Medius v3.4.7 — device application; 0x42019018.
 * Instruction-checked recovered C.
 * Original function-byte SHA-256:
 * bf5e9485ad6dc2eae6c848f35e03d58c9df8daecce349cced3a0cbf76bcac1bb.
 */

/*
 * Obtain the current Newlib context once and dispatch fstat with that pointer,
 * the unchanged descriptor word and the unchanged opaque status pointer.
 * Return the dispatcher result. This facade performs no descriptor/status
 * validation, status-buffer access, allocation, errno reset or extra locking.
 */
int vfs_status_current(int descriptor,VfsStat *status)
{
    NewlibReent *reent = vfs_current_reent();
    return medius_vfs_status(reent,descriptor,status);
}

/* Native entry: 0x42019094. */
/*
 * Medius v3.4.7 — device application; 0x42019094.
 * Instruction-checked recovered C.
 * Original function-byte SHA-256:
 * f0367b9655b15c19573bcb42700de2e3264433fdd4244a8e576900c4f1e6a152.
 */

/*
 * Obtain __getreent once, then forward context, descriptor, destination pointer
 * and all32 unsigned length bits to the read dispatcher. Return its full result
 * without interpreting errors or copying errno. No destination access, length
 * cap, context ownership, pointer validation, lock or MEMW is introduced here.
 */
int vfs_read_current(int descriptor,void *data,unsigned int length)
{
    NewlibReent *reent = vfs_current_reent();
    return medius_vfs_read(reent,descriptor,data,length);
}

/* Native entry: 0x420190b0. */
/*
 * Medius v3.4.7 — device application; 0x420190b0.
 * Instruction-checked recovered C.
 * Original function-byte SHA-256:
 * d2d2b1e315d76f75cbf2d9b989a5adac3caa25fa6b9799f907aff68fb8219f23.
 */

/*
 * Obtain __getreent once and forward context, descriptor, source pointer and
 * unsigned32 length to the write dispatcher. Preserve its full return word.
 * This facade does not read the source, validate arguments, reset/copy errno,
 * allocate storage or add synchronization; the context is a borrowed pointer.
 */
int vfs_write_current(int descriptor,const void *data,unsigned int length)
{
    NewlibReent *reent = vfs_current_reent();
    return medius_vfs_write(reent,descriptor,data,length);
}

/* Native entry: 0x42018b00. */
/*
 * Medius v3.4.7 — device application; 0x42018b00.
 * Instruction-checked recovered C.
 * Original function-byte SHA-256:
 * d6fd8fa830c7b9e4c297cb85d6c000480d40160085827a04fd97472836bce298.
 */

/*
 * Newlib stream close callback. Read the signed16 descriptor at cookie+0x0e,
 * sign-extend it to32 bits, then call VFS close with the supplied reent pointer.
 * Return its status unchanged. The cookie must be readable; no NULL check,
 * context lookup, stream-field write, buffer free or extra lock occurs here.
 */
int medius_newlib_stream_close(NewlibReent *reent,void *cookie)
{
    const volatile NewlibFile *stream = cookie;
    int descriptor = stream->file_descriptor;
    return medius_vfs_close(reent,descriptor);
}
