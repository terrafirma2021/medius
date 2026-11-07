/* Medius v3.4.7 host — runtime/vfs.c.
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

/* Native entry: 0x42032a14. */
/*
 * Medius v3.4.7 — host application; 0x42032a14.
 * Instruction-checked recovered C.
 * Original function-byte SHA-256:
 * b70102d25eaca5b5436f73280168b99f0e05a8fd99573f0e24625d9b68403a59.
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

/* Native entry: 0x42032a80. */
/*
 * Medius v3.4.7 — host application; 0x42032a80.
 * Instruction-checked recovered C.
 * Original function-byte SHA-256:
 * d738c1d63fb6d1604faf602205fec562bc5f0a8d2afe26047c1fbc8ca4e45601.
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

/* Native entry: 0x42032aec. */
/*
 * Medius v3.4.7 — host application; 0x42032aec.
 * Instruction-checked recovered C.
 * Original function-byte SHA-256:
 * 8082c8d67725f6325ce903f82e8b81e9e5c7ca947e03e704401cc0099b04ba7d.
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

/* Native entry: 0x42032b58. */
/*
 * Medius v3.4.7 — host application; 0x42032b58.
 * Instruction-checked recovered C.
 * Original function-byte SHA-256:
 * e9668d5288dbda2fff32767a40b348d21fbcb75351efc1c514e35af9f52e7b3a.
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

/* Native entry: 0x42032bf4. */
/*
 * Medius v3.4.7 — host application; 0x42032bf4.
 * Instruction-checked recovered C.
 * Original function-byte SHA-256:
 * 27ef7ae873ec8d847b67206681d1214ac96b77c1f7795fd39e69e864838422e9.
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

/* Native entry: 0x42032c5c. */
/*
 * Medius v3.4.7 — host application; 0x42032c5c.
 * Instruction-checked recovered C.
 * Original function-byte SHA-256:
 * 2b7aa1aa729279d7fe34a64314e9e1dd7f283d45a9a27489434077e356c59319.
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

/* Native entry: 0x42016b6c. */
/*
 * Medius v3.4.7 — host application; 0x42016b6c.
 * Instruction-checked recovered C.
 * Original function-byte SHA-256:
 * 18b40d1a01f13947a89338e700345bbdc8541c140c31be3a1114279fa81b40f3.
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

/* Native entry: 0x42016b84. */
/*
 * Medius v3.4.7 — host application; 0x42016b84.
 * Instruction-checked recovered C.
 * Original function-byte SHA-256:
 * da78f959e08fe1eee6a4404d0928ed3fd26902ff44f9c3035bfcb75ca3ad5ab5.
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

/* Native entry: 0x42016c00. */
/*
 * Medius v3.4.7 — host application; 0x42016c00.
 * Instruction-checked recovered C.
 * Original function-byte SHA-256:
 * 29ad4beb5834a7581ab8714d484a7e5f8ffcd43598851c691ea339ef10d4af82.
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

/* Native entry: 0x42016c1c. */
/*
 * Medius v3.4.7 — host application; 0x42016c1c.
 * Instruction-checked recovered C.
 * Original function-byte SHA-256:
 * adc5a7e74257430b68f8916b1712cdc5c13657f26ca6eced560b0031bd20f676.
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

/* Native entry: 0x4201666c. */
/*
 * Medius v3.4.7 — host application; 0x4201666c.
 * Instruction-checked recovered C.
 * Original function-byte SHA-256:
 * 887332bdcb994a62778e78924615792db7ef46bf23b587d0941447f85a166481.
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
