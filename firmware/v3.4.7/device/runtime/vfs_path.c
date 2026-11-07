/* Medius v3.4.7 device — runtime/vfs_path.c.
 * VFS operation names also match the firmware's ESP-IDF v5.4.4 interfaces.
 */

#include "../include/types.h"
#include <stdarg.h>

/* Source reconstruction utilities; not additional native firmware entries. */
extern size_t vfs_path_length(const char *) __asm__("strlen");
extern int vfs_path_compare(const char *,const char *,size_t) __asm__("strncmp");
extern int vfs_path_memory_compare(const void *,const void *,size_t) __asm__("memcmp");
extern NewlibReent *vfs_path_current_reent(void) __asm__("__getreent");
extern int *vfs_path_errno(void) __asm__("__errno");
extern void vfs_path_assert(const char *,int,const char *,const char *)
    __asm__("__assert_func") __attribute__((noreturn));

/* Native entry: 0x42039ca4. */
/*
 * Medius v3.4.7 — device application; 0x42039ca4.
 * Instruction-checked recovered C.
 * Original function-byte SHA-256:
 * 1c54e9a73e8b22a604d93c67091972172ca2741a2e8f50599ae019bc070f9114.
 */

/*
 * Cache the mount prefix length, then strncmp(path,prefix,length). A mismatch
 * invokes the nonreturning assertion service with four zero arguments, exactly
 * as present in this firmware. On a match, measure path again. Exact equality
 * returns the fixed "/" string; otherwise return path+cached_length modulo 2^32.
 * No separator check, allocation, normalization or lock occurs in this helper.
 * Mount/prefix/path must be accessible, with a NUL-terminated path. Callers own
 * lookup/lifetime synchronization; prefix length is not reread after calls.
 */
const char *medius_vfs_translate_path(const volatile VfsDriverEntry *entry,
    const char *path)
{
    unsigned int prefix_length = entry->path_prefix_length;
    if (vfs_path_compare(path,(const char *)entry->path_prefix,prefix_length) != 0)
        vfs_path_assert(NULL,0,NULL,NULL);
    size_t length = vfs_path_length(path);
    if (length == prefix_length) return MEDIUS_VFS_ROOT_PATH;
    return (const char *)((unsigned int)path + prefix_length);
}

/* Native entry: 0x42039e40. */
/*
 * Medius v3.4.7 — device application; 0x42039e40.
 * Instruction-checked recovered C.
 * Original function-byte SHA-256:
 * a7063847638040ea0775026263c90d5a4b1dfc54b6006e4e5f016444ca931e48.
 */

/*
 * Measure the path once, then sample the unsigned registered-driver count once.
 * Count zero returns NULL. Otherwise cache the modulo 2^32 end pointer and walk
 * every pointer slot to that end, observing each slot freshly. Skip NULL entries,
 * prefixes longer than the cached path length and the UINT32_MAX ignored marker.
 * Compare prefix bytes using the cached prefix length. An empty prefix is the
 * first fallback match without updating best_length (-1). Other matches require
 * exact path length or a '/' after the prefix, and a strictly greater signed 32-bit
 * prefix length. Equal lengths retain the earlier entry. A later empty prefix
 * can replace the first fallback only when it passes the normal separator and
 * signed-length tests. Flags are not inspected here. No path canonicalization,
 * count cap, registration lock, lifetime protection or errno write is supplied.
 */
const volatile VfsDriverEntry *medius_vfs_find_path(const char *path)
{
    unsigned int path_length = vfs_path_length(path);
    unsigned int count = VFS_DRIVER_COUNT;
    if (count == 0) return NULL;
    unsigned int slot = (unsigned int)VFS_DRIVERS;
    unsigned int end = slot + count * 4U;
    const volatile VfsDriverEntry *best = NULL;
    int best_length = -1;
    do {
        const volatile VfsDriverEntry *entry =
            *(const volatile VfsDriverEntry * volatile *)slot;
        if (entry) {
            unsigned int length = entry->path_prefix_length;
            if (length <= path_length && length != 0xffffffffU &&
                vfs_path_memory_compare(path,(const char *)entry->path_prefix,length) == 0) {
                if (!best && length == 0) best = entry;
                else if ((length >= path_length ||
                         ((const volatile unsigned char *)path)[length] == '/') &&
                        best_length < (int)length) {
                    best_length = (int)length;
                    best = entry;
                }
            }
        }
        slot += 4;
    } while (slot != end);
    return best;
}

/* Native entry: 0x42039ebc. */
/*
 * Medius v3.4.7 — device application; 0x42039ebc.
 * Instruction-checked recovered C.
 * Original function-byte SHA-256:
 * 374985c972b1970eb017daf56dc8189b7bb7fd78fdb67bbdfbd9d3bf3593a915.
 */

/*
 * Resolve the path; missing mount writes ENOENT (2) and returns -1. Sample mount
 * flags before translation. Only nonzero access bits(flags&3) on a read-only
 * mount (flag 0x04) are rejected with EROFS (30); other creation/truncation bits do not
 * independently trigger that gate. Translate, then load the current operation
 * table/open callback. Missing callback gives ENOSYS (88). The cached context flag 0x02
 * selects plain(path,flags,mode) or context/context-path/flags/mode ABI.
 *
 * Any negative backend result copies errno from the CURRENT context's errno
 * pointer into supplied reent, then returns -1. Nonnegative results acquire the
 * global descriptor lock and scan all 64 rows for signed driver_index==-1.
 * At the first free row, sample mount offset then row flags, publish low 8-bit mount
 * index, clear only permanent bit0 in cached row flags, publish low 8-bit local fd,
 * unlock and return the global row number. Neither narrowed value is validated.
 *
 * If full, unlock, then freshly load operations/close and current context flag.
 * Missing close gives ENOSYS (88) and leaves the opened backend descriptor live.
 * Otherwise close the ORIGINAL full-width backend fd, ignore its result, write
 * ENOMEM (12) and return -1. Callback/lock changes affect later fresh fields; no
 * errno reset, mount lifetime lock, rollback of callback effects or MEMW occurs.
 */
int medius_vfs_open(NewlibReent *reent,const char *path,int flags,int mode)
{
    const volatile VfsDriverEntry *entry = medius_vfs_find_path(path);
    if (!entry) {reent->error_number=2;return -1;}
    unsigned int mount_flags = entry->flags;
    if (((unsigned int)flags & 3U) != 0 && (mount_flags & 4U)) {
        reent->error_number=30;return -1;
    }
    const char *relative = medius_vfs_translate_path(entry,path);
    const volatile VfsOperations *operations = entry->operations;
    VfsOpenOperation callback = operations->open;
    if (!callback.plain) {reent->error_number=88;return -1;}
    int local = (mount_flags & 2U) ?
        callback.with_context(entry->context,relative,flags,mode) :
        callback.plain(relative,flags,mode);
    if (local < 0) {
        int *error = vfs_path_errno();
        reent->error_number = *(volatile int *)error;
        return -1;
    }
    _lock_acquire(&MEDIUS_VFS_DESCRIPTOR_LOCK);
    for (int descriptor=0;descriptor<64;++descriptor) {
        if (MEDIUS_VFS_DESCRIPTORS[descriptor].driver_index == -1) {
            int index = entry->offset;
            unsigned char row_flags = MEDIUS_VFS_DESCRIPTORS[descriptor].flags;
            MEDIUS_VFS_DESCRIPTORS[descriptor].driver_index = (signed char)index;
            MEDIUS_VFS_DESCRIPTORS[descriptor].flags = row_flags & 0xfeU;
            MEDIUS_VFS_DESCRIPTORS[descriptor].local_descriptor = (unsigned char)local;
            _lock_release(&MEDIUS_VFS_DESCRIPTOR_LOCK);
            return descriptor;
        }
    }
    _lock_release(&MEDIUS_VFS_DESCRIPTOR_LOCK);
    operations = entry->operations;
    VfsCloseOperation close_callback = operations->close;
    if (!close_callback.plain) {reent->error_number=88;return -1;}
    if (entry->flags & 2U) (void)close_callback.with_context(entry->context,local);
    else (void)close_callback.plain(local);
    reent->error_number = 12;
    return -1;
}

/* Native entry: 0x42019048. */
/*
 * Medius v3.4.7 — device application; 0x42019048.
 * Instruction-checked recovered C.
 * Original function-byte SHA-256:
 * c0ae2fd66a95dfab79b4f53667fae8cfe918d4248745082b051ba31802f5ffb7.
 */

/*
 * Native variadic open facade: establish the Xtensa argument save area, obtain
 * current reent once, then consume the first variadic 32-bit mode word and call VFS
 * open. Mode is consumed unconditionally, including when flags omit creation.
 * Under the normal call ABI the initialized va-list index selects that saved
 * third argument; the alternate stack-argument branches cannot be reached here.
 * No mode default, NULL/context guard, errno reset or local lock is added.
 */
int vfs_open_current(const char *path,int flags,...)
{
    va_list arguments;
    va_start(arguments,flags);
    NewlibReent *reent = vfs_path_current_reent();
    int mode = va_arg(arguments,int);
    va_end(arguments);
    return medius_vfs_open(reent,path,flags,mode);
}

/* Native entry: 0x4203a2c8. */
/*
 * Medius v3.4.7 — device application; 0x4203a2c8.
 * Instruction-checked recovered C.
 * Original function-byte SHA-256:
 * 2bcdf579d2d79b94d3500c853e120f232d76c90d6e396d831b06f549d8f34ed5.
 */

/*
 * Resolve and translate path before loading the current directory subtable and
 * stat callback. Missing mount gives ENOENT (2); NULL subtable/callback gives
 * ENOSYS (88). Sample mount flags after translation and callback lookup: flag 0x02
 * selects context/path/status versus path/status. Return backend status unchanged,
 * preserving backend errno effects. No read-only gate, stat clear, pointer check,
 * registration lock or normalization occurs; status is borrowed storage.
 */
int medius_vfs_stat_path(NewlibReent *reent,const char *path,VfsStat *status)
{
    const volatile VfsDriverEntry *entry = medius_vfs_find_path(path);
    if (!entry) {reent->error_number=2;return -1;}
    const char *relative = medius_vfs_translate_path(entry,path);
    const volatile VfsDirectoryOperations *directory = entry->operations->directory;
    if (!directory) {reent->error_number=88;return -1;}
    VfsPathStatOperation callback = directory->status;
    if (!callback.plain) {reent->error_number=88;return -1;}
    if (entry->flags & 2U) return callback.with_context(entry->context,relative,status);
    return callback.plain(relative,status);
}

/* Native entry: 0x4203a318. */
/*
 * Medius v3.4.7 — device application; 0x4203a318.
 * Instruction-checked recovered C.
 * Original function-byte SHA-256:
 * e0230a188956007c3023f3f12e10b3639750c8f51ba664388db4ecd2db856813.
 */

/*
 * Resolve old path first: missing mount gives ENOENT (2) without looking up new
 * path. Resolve new path next; a different mount, including NULL, gives EXDEV (18).
 * Only then sample read-only flag 0x04, giving EROFS (30). Translate both paths in
 * order, load current directory/link callback and return ENOSYS (88) if absent.
 * Fresh mount flag 0x02 selects context/old/new versus old/new ABI. Both translated
 * pointers are passed; Ghidra omitted the second plain-call argument. Return
 * backend word unchanged; no extra errno copy, lock or lifetime guard occurs.
 */
int medius_vfs_link_path(NewlibReent *reent,const char *old_path,const char *new_path)
{
    const volatile VfsDriverEntry *entry = medius_vfs_find_path(old_path);
    if (!entry) {reent->error_number=2;return -1;}
    const volatile VfsDriverEntry *destination = medius_vfs_find_path(new_path);
    if (entry != destination) {reent->error_number=18;return -1;}
    if (entry->flags & 4U) {reent->error_number=30;return -1;}
    const char *old_relative = medius_vfs_translate_path(entry,old_path);
    const char *new_relative = medius_vfs_translate_path(entry,new_path);
    const volatile VfsDirectoryOperations *directory = entry->operations->directory;
    if (!directory) {reent->error_number=88;return -1;}
    VfsPathPairOperation callback = directory->link;
    if (!callback.plain) {reent->error_number=88;return -1;}
    if (entry->flags & 2U) return callback.with_context(entry->context,old_relative,new_relative);
    return callback.plain(old_relative,new_relative);
}

/* Native entry: 0x4203a390. */
/*
 * Medius v3.4.7 — device application; 0x4203a390.
 * Instruction-checked recovered C.
 * Original function-byte SHA-256:
 * 1df10bf428203b254a7d381018162a48ff8fc97572a29d04f00038e7a29009eb.
 */

/*
 * Resolve path, then cache mount flags. Missing mount gives ENOENT (2); cached
 * read-only flag 0x04 gives EROFS (30) before translation. Translate and load current
 * directory/unlink callback, giving ENOSYS (88) if absent. Cached context flag 0x02
 * selects context/path versus path ABI. Ghidra's duplicate plain argument and
 * missing context-path argument were register-window artifacts. Return backend
 * result unchanged. No errno reset/copy, lifetime lock or pointer guard occurs.
 */
int medius_vfs_unlink_path(NewlibReent *reent,const char *path)
{
    const volatile VfsDriverEntry *entry = medius_vfs_find_path(path);
    if (!entry) {reent->error_number=2;return -1;}
    unsigned int flags = entry->flags;
    if (flags & 4U) {reent->error_number=30;return -1;}
    const char *relative = medius_vfs_translate_path(entry,path);
    const volatile VfsDirectoryOperations *directory = entry->operations->directory;
    if (!directory) {reent->error_number=88;return -1;}
    VfsPathOperation callback = directory->unlink;
    if (!callback.plain) {reent->error_number=88;return -1;}
    if (flags & 2U) return callback.with_context(entry->context,relative);
    return callback.plain(relative);
}

/* Native entry: 0x4203a3e4. */
/*
 * Medius v3.4.7 — device application; 0x4203a3e4.
 * Instruction-checked recovered C.
 * Original function-byte SHA-256:
 * 6113659830f52cfd63b4a677396798e11bc0ef4346d20a994970c58818f21198.
 */

/*
 * Resolve source; missing mount gives ENOENT (2). Cache its flags and reject cached
 * read-only flag 0x04 BEFORE destination lookup. Different destination mount gives
 * EXDEV (18); then reread source read-only flag 0x04 and reject EROFS (30) if now set.
 * Translate source/destination in order, load current directory/rename callback,
 * reject ENOSYS (88) if absent. Use the FIRST cached context flag 0x02 to select the
 * context/source/destination or source/destination ABI. Both plain arguments are
 * restored from native registers. Return backend status unchanged; no rollback,
 * errno copy/reset, registration lock or lifetime protection is supplied.
 */
int medius_vfs_rename_path(NewlibReent *reent,const char *source,const char *destination)
{
    const volatile VfsDriverEntry *entry = medius_vfs_find_path(source);
    if (!entry) {reent->error_number=2;return -1;}
    unsigned int flags = entry->flags;
    if (flags & 4U) {reent->error_number=30;return -1;}
    const volatile VfsDriverEntry *target = medius_vfs_find_path(destination);
    if (entry != target) {reent->error_number=18;return -1;}
    if (entry->flags & 4U) {reent->error_number=30;return -1;}
    const char *source_relative = medius_vfs_translate_path(entry,source);
    const char *destination_relative = medius_vfs_translate_path(entry,destination);
    const volatile VfsDirectoryOperations *directory = entry->operations->directory;
    if (!directory) {reent->error_number=88;return -1;}
    VfsPathPairOperation callback = directory->rename;
    if (!callback.plain) {reent->error_number=88;return -1;}
    if (flags & 2U) return callback.with_context(entry->context,source_relative,destination_relative);
    return callback.plain(source_relative,destination_relative);
}

/* Native entry: 0x4203a464. */
/*
 * Medius v3.4.7 — device application; 0x4203a464.
 * Instruction-checked recovered C.
 * Original function-byte SHA-256:
 * 12db22bf56bdfc89a647dcc3903b054f3894ff55fdf0d6be29321b87b3f363b6.
 */

/*
 * Resolve path FIRST, then get current reent once even when lookup failed.
 * Missing mount gives ENOENT (2). Translate, then load current directory/access
 * callback; NULL subtable/callback gives ENOSYS (88). Fresh mount flag 0x02 chooses
 * context/path/amode or path/amode. Forward all 32 amode bits without local
 * validation or a read-only gate. Return backend word unchanged; no errno reset,
 * permission computation, lock or lifetime protection is performed here.
 */
int vfs_access_current(const char *path,int access_mode)
{
    const volatile VfsDriverEntry *entry = medius_vfs_find_path(path);
    NewlibReent *reent = vfs_path_current_reent();
    if (!entry) {reent->error_number=2;return -1;}
    const char *relative = medius_vfs_translate_path(entry,path);
    const volatile VfsDirectoryOperations *directory = entry->operations->directory;
    if (!directory) {reent->error_number=88;return -1;}
    VfsPathAccessOperation callback = directory->access;
    if (!callback.plain) {reent->error_number=88;return -1;}
    if (entry->flags & 2U) return callback.with_context(entry->context,relative,access_mode);
    return callback.plain(relative,access_mode);
}
