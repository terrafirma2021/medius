/* Medius v3.4.7 device — drivers/null.c.
 */

#include "../include/types.h"

/* Native entry: 0x42007de0. */
/*
 * Medius v3.4.7 — device application; 0x42007de0.
 * Instruction-checked recovered C.
 * Original function-byte SHA-256:
 * 401e66df799637ceffde1026f0f25fb225a2a1b1e0b580f2a900766738fdf77d.
 */

/*
 * Accept exactly the relative path "/"; inspect byte 1 only when byte 0=='/'.
 * Other paths set current errno 2 and return -1 before reading permissions.
 * Snapshot the 32-bit bitmap ONCE, then scan its sixteen two-bit slots from 0.
 * A full snapshot sets EMFILE (24), even when flags&3 would also be invalid.
 * For the first empty slot, access 0/1/2 becomes read 1 / write 2 / read+write 3;
 * access 3 sets EINVAL (22) without allocating. Higher flags and mode are ignored.
 * Publish cached_bitmap|(permission<<(slot*2)) and return the local slot.
 * There is no lock, fresh bitmap merge, buffer allocation or errno reset.
 * Concurrent updates can be overwritten. The close callback does not clear
 * this bitmap, so closing alone does not make a local slot reusable.
 */
int null_vfs_open(const char *path,int flags,int mode)
{
    (void)mode;
    const volatile unsigned char *name = (const unsigned char *)path;
    if (name[0] != '/' || name[1] != 0) {
        *__errno() = 2;
        return -1;
    }
    unsigned int permissions = NULL_VFS_ACCESS_BITMAP;
    unsigned int descriptor = 0;
    while (descriptor < 16 && ((permissions >> (descriptor*2)) & 3U) != 0)
        ++descriptor;
    if (descriptor == 16) {
        *__errno() = 24;
        return -1;
    }
    unsigned int access = (unsigned int)flags & 3U;
    if (access == 3) {
        *__errno() = 22;
        return -1;
    }
    NULL_VFS_ACCESS_BITMAP = permissions | ((access+1U) << (descriptor*2));
    return (int)descriptor;
}

/* Native entry: 0x42007e90. */
/*
 * Medius v3.4.7 — device application; 0x42007e90.
 * Instruction-checked recovered C.
 * Original function-byte SHA-256:
 * 9928daeda4a09feb4b2c116179d6e6d482d19fb6379e9d3d8df400b090d880a5.
 */

/*
 * Require unsigned descriptor < 16 and either permission bit in a fresh bitmap
 * snapshot; otherwise set current errno 9 and return -1. A valid descriptor
 * returns zero for unsigned origin 0, 1, 2, ignoring the full 32-bit offset.
 * Other origins, including negative values, set errno 22 and return -1.
 * No position, data, permissions or errno-on-success change is made.
 */
int null_vfs_seek(int descriptor,int offset,int origin)
{
    (void)offset;
    if ((unsigned int)descriptor >= 16 ||
        ((NULL_VFS_ACCESS_BITMAP >> ((unsigned int)descriptor*2)) & 3U) == 0) {
        *__errno() = 9;
        return -1;
    }
    if ((unsigned int)origin < 3) return 0;
    *__errno() = 22;
    return -1;
}

/* Native entry: 0x42007ecc. */
/*
 * Medius v3.4.7 — device application; 0x42007ecc.
 * Instruction-checked recovered C.
 * Original function-byte SHA-256:
 * 6a771b8c59fd8bd68c0e4eaff66b7b07e5913ccee6ab6a0cd20c0f53632f4132.
 */

/*
 * Any unsigned descriptor < 16 succeeds, even if its permission slot is empty.
 * Clear the complete 88-byte stat, then store mode 0x21b6 (character device, 0666),
 * combined link_count/user_id word 1, group_id halfword 0, then size word 0.
 * Native widths/order are explicit. Larger or negative descriptors set current
 * errno 9 and return -1 without touching status. No bitmap or status-pointer
 * validation occurs; valid-range callers must provide 88 writable bytes.
 */
int null_vfs_status(int descriptor,VfsStat *status)
{
    if ((unsigned int)descriptor >= 16) {
        *__errno() = 9;
        return -1;
    }
    memset(status,0,88);
    volatile VfsStat *result = status;
    result->mode = 0x21b6;
    result->link_user_word = 1;
    result->group_id = 0;
    result->size = 0;
    return 0;
}

/* Native entry: 0x42007f04. */
/*
 * Medius v3.4.7 — device application; 0x42007f04.
 * Instruction-checked recovered C.
 * Original function-byte SHA-256:
 * b0da4cc4b1c350419c1bd0ed9db3b83dc34e7c94252cf201b6aa489630ed0015.
 */

/*
 * Unsupported fcntl: ignore command/argument, set current errno 88 for any
 * unsigned descriptor < 16, or errno 9 otherwise, and return -1. An in-range
 * descriptor need not be open. No bitmap, file state or supplied data is read.
 */
int null_vfs_control(int descriptor,int command,int argument)
{
    (void)command;
    (void)argument;
    *__errno() = (unsigned int)descriptor < 16 ? 88 : 9;
    return -1;
}

/* Native entry: 0x42007f28. */
/*
 * Medius v3.4.7 — device application; 0x42007f28.
 * Instruction-checked recovered C.
 * Original function-byte SHA-256:
 * 11dcbe49f68a4942538de048dd6e24a648d99941f33e79932f94ebcb71e9164e.
 */

/*
 * Require unsigned descriptor < 16 and its write-permission bit in one bitmap
 * snapshot. On success return all 32 length bits as the signed native result,
 * discarding data without reading it. A negative-looking result can therefore
 * occur for lengths above INT_MAX without a new errno. Invalid/nonwritable
 * descriptors set current errno 9 and return -1. No state or bitmap change.
 */
int null_vfs_write(int descriptor,const void *data,unsigned int length)
{
    (void)data;
    if ((unsigned int)descriptor < 16 &&
        (NULL_VFS_ACCESS_BITMAP & (2U << ((unsigned int)descriptor*2))))
        return (int)length;
    *__errno() = 9;
    return -1;
}

/* Native entry: 0x42007fb8. */
/*
 * Medius v3.4.7 — device application; 0x42007fb8.
 * Instruction-checked recovered C.
 * Original function-byte SHA-256:
 * ee7e96278949211406655abcde8b66e4a380990e7398cb81e088e0100cde467f.
 */

/*
 * Require unsigned descriptor < 16 and the read-permission bit. Return zero
 * immediately on success, leaving all destination bytes untouched regardless
 * of requested length. Invalid/nonreadable descriptors set current errno 9 and
 * return -1. No destination access, bitmap update, allocation or errno reset.
 */
int null_vfs_read(int descriptor,void *data,unsigned int length)
{
    (void)data;
    (void)length;
    if ((unsigned int)descriptor < 16 &&
        (NULL_VFS_ACCESS_BITMAP & (1U << ((unsigned int)descriptor*2))))
        return 0;
    *__errno() = 9;
    return -1;
}

/* Native entry: 0x42008008. */
/*
 * Medius v3.4.7 — device application; 0x42008008.
 * Instruction-checked recovered C.
 * Original function-byte SHA-256:
 * 85976c2b1ab771246d799caeb12ddbcbbd8a829909ba083f712813fbae4d7ed6.
 */

/*
 * Positioned-read callback: ignore destination, length and the native 32-bit offset.
 * Apply the same descriptor/read-bit gate as read, returning zero without a
 * buffer write on success. Otherwise set current errno 9 and return -1.
 * The fourth argument is unused natively; its presence follows the matched
 * pread slot/SDK callback ABI. No bitmap, position or success-errno change.
 */
int null_vfs_read_at(int descriptor,void *data,unsigned int length,long offset)
{
    (void)data;
    (void)length;
    (void)offset;
    if ((unsigned int)descriptor < 16 &&
        (NULL_VFS_ACCESS_BITMAP & (1U << ((unsigned int)descriptor*2))))
        return 0;
    *__errno() = 9;
    return -1;
}

/* Native entry: 0x42007fdc. */
/*
 * Medius v3.4.7 — device application; 0x42007fdc.
 * Instruction-checked recovered C.
 * Original function-byte SHA-256:
 * 860f16b725b840ab3db905364f9961c12f7db6491226537b6a3604f6622e0bdf.
 */

/*
 * Positioned-write callback: ignore data and the native 32-bit offset. For an
 * unsigned descriptor < 16 with its write bit set, return all 32 length bits.
 * Otherwise set current errno 9 and return -1. No data access, offset validation,
 * position update, bitmap change or success-errno reset. The unused fourth
 * argument is restored from the matched pwrite slot/SDK ABI.
 */
int null_vfs_write_at(int descriptor,const void *data,unsigned int length,long offset)
{
    (void)data;
    (void)offset;
    if ((unsigned int)descriptor < 16 &&
        (NULL_VFS_ACCESS_BITMAP & (2U << ((unsigned int)descriptor*2))))
        return (int)length;
    *__errno() = 9;
    return -1;
}

/* Native entry: 0x42007f94. */
/*
 * Medius v3.4.7 — device application; 0x42007f94.
 * Instruction-checked recovered C.
 * Original function-byte SHA-256:
 * 237660bb0501e9939f6eb072179f77ec5b29908f9cb238a7be73be036ad36cfb.
 */

/*
 * Unsupported ioctl: descriptor range alone chooses current errno 88(<16) or
 * errno 9(otherwise); return -1. Ignore command and the va-list argument without
 * reading its storage. No open-slot test, permission change or command dispatch.
 * The ignored argument types follow the registered ioctl slot/SDK ABI.
 */
int null_vfs_ioctl(int descriptor,int command,va_list arguments)
{
    (void)command;
    (void)arguments;
    *__errno() = (unsigned int)descriptor < 16 ? 88 : 9;
    return -1;
}

/* Native entry: 0x4200802c. */
/*
 * Medius v3.4.7 — device application; 0x4200802c.
 * Instruction-checked recovered C.
 * Original function-byte SHA-256:
 * fb314aab5d7566e9caca2fedaf372c586620ef66bc35ffc93b183f08c9beaf19.
 */

/*
 * Return zero for every unsigned descriptor < 16, including an unopened slot.
 * Other descriptors set current errno 9 and return -1. IMPORTANT: no permission
 * bits are cleared here, so this close does not release a slot for null_vfs_open.
 * It does not free memory, call a backend, lock or reset errno on success.
 */
int null_vfs_close(int descriptor)
{
    if ((unsigned int)descriptor < 16) return 0;
    *__errno() = 9;
    return -1;
}

/* Native entry: 0x42008048. */
/*
 * Medius v3.4.7 — device application; 0x42008048.
 * Instruction-checked recovered C.
 * Original function-byte SHA-256:
 * b1ece782e26ca68a7ea0fb31c450f4e806c0d26b1e6537318d6fcc28f81c257f.
 */

/*
 * Fsync succeeds for every unsigned descriptor < 16 without checking whether it
 * is open or has write permission. Otherwise set current errno 9 and return -1.
 * No buffering, device flush, permission clear, lock or success-errno reset.
 */
int null_vfs_sync(int descriptor)
{
    if ((unsigned int)descriptor < 16) return 0;
    *__errno() = 9;
    return -1;
}

/* Native entry: 0x42007f54. */
/*
 * Medius v3.4.7 — device application; 0x42007f54.
 * Instruction-checked recovered C.
 * Original function-byte SHA-256:
 * 55af1d104776f4edf4548d5b37daa823d88275d60c1b468b9de1d20c68753aac.
 */

/*
 * Accept exactly "/" and report the synthetic character-device stat. Other
 * paths set current errno 2 and return -1 without touching status. After an
 * 88-byte clear, native stores group_id halfword 0 FIRST, mode 0x21b6 second,
 * combined link_count/user_id word 1 third, size word 0 last. This order differs
 * from the fd status callback. No bitmap, path normalization or pointer guard.
 */
int null_vfs_stat_path(const char *path,VfsStat *status)
{
    const volatile unsigned char *name = (const unsigned char *)path;
    if (name[0] != '/' || name[1] != 0) {
        *__errno() = 2;
        return -1;
    }
    memset(status,0,88);
    volatile VfsStat *result = status;
    result->group_id = 0;
    result->mode = 0x21b6;
    result->link_user_word = 1;
    result->size = 0;
    return 0;
}

/* Native entry: 0x42008064. */
/*
 * Medius v3.4.7 — device application; 0x42008064.
 * Instruction-checked recovered C.
 * Original function-byte SHA-256:
 * 96c15de622b5f355fca349e3d3db7cd9682c8185e12e905b6a9efefce090f1d3.
 */

/*
 * Register "/dev/null" with the fixed firmware operation table, STATIC flag 0x08
 * and NULL context; return the registration service's full status unchanged.
 * No permission-bitmap reset, descriptor open, retry or local allocation occurs.
 * Table pointers are borrowed DROM storage. The separate registration routine
 * supplies allocation, duplicate-path checks and registry synchronization.
 */
int null_vfs_register(void)
{
    return esp_vfs_register_fs("/dev/null",NULL_VFS_OPERATIONS,8,NULL);
}

/* Native entry: 0x42008078. */
/*
 * Medius v3.4.7 — device application; 0x42008078.
 * Instruction-checked recovered C.
 * Original function-byte SHA-256:
 * bf51da9f5d178e9381e4e3ec9964e7c58ae266eef3332eff5e322265073af1b1.
 */

/* Return this image's fixed borrowed /dev/null operation-table pointer.
 * No table dereference, validation, allocation or state write occurs.
 * Registered flags determine which callback ABI its consumer uses. */
const VfsOperations *null_vfs_get_operations(void)
{
    return CONSOLE_INITIAL_BACKEND;
}
