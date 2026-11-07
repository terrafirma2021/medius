/* Medius v3.4.7 host — drivers/null.c.
 */

#include "../include/types.h"

/* Native entry: 0x42008c9c. */
/*
 * Medius v3.4.7 — host application; 0x42008c9c.
 * Instruction-checked recovered C.
 * Original function-byte SHA-256:
 * 9eec0acf7444768715573cef6891d8df68a2fd4c08fcf44112b5d665e3924c5a.
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

/* Native entry: 0x42008d4c. */
/*
 * Medius v3.4.7 — host application; 0x42008d4c.
 * Instruction-checked recovered C.
 * Original function-byte SHA-256:
 * d2e92831b4b30ed68259e1d604031b986e9d02832e538111104d23f122268e49.
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

/* Native entry: 0x42008d88. */
/*
 * Medius v3.4.7 — host application; 0x42008d88.
 * Instruction-checked recovered C.
 * Original function-byte SHA-256:
 * 8f8c426a9d27b21f68496f3e0a7974741b4c7880be8bdd386e6143cfdb651741.
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

/* Native entry: 0x42008dc0. */
/*
 * Medius v3.4.7 — host application; 0x42008dc0.
 * Instruction-checked recovered C.
 * Original function-byte SHA-256:
 * 463e8e116a6b1941e82b3a240a189414139338ef524e444d4da8844fef6c8025.
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

/* Native entry: 0x42008de4. */
/*
 * Medius v3.4.7 — host application; 0x42008de4.
 * Instruction-checked recovered C.
 * Original function-byte SHA-256:
 * 8526f9e1bc5bb8f4162a067ccaf575fc0520dafefcd710b8c33307e590995349.
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

/* Native entry: 0x42008e74. */
/*
 * Medius v3.4.7 — host application; 0x42008e74.
 * Instruction-checked recovered C.
 * Original function-byte SHA-256:
 * 5aba4dcbc774b92c4cf5b7c9e0ae08322c7d4d7bbd76a6e7f700886467824fd5.
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

/* Native entry: 0x42008ec4. */
/*
 * Medius v3.4.7 — host application; 0x42008ec4.
 * Instruction-checked recovered C.
 * Original function-byte SHA-256:
 * 60f598a815465f52429d64d88d5b18c37e686b0a9ed48f4e2d9bfd3526f65a1d.
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

/* Native entry: 0x42008e98. */
/*
 * Medius v3.4.7 — host application; 0x42008e98.
 * Instruction-checked recovered C.
 * Original function-byte SHA-256:
 * 263d1f75d3803415530509c9490afe47b8d5139b80e61e90126e2671f32c0dd5.
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

/* Native entry: 0x42008e50. */
/*
 * Medius v3.4.7 — host application; 0x42008e50.
 * Instruction-checked recovered C.
 * Original function-byte SHA-256:
 * 5e1d7a8f8923cf5c947dbd6515f919964108f9de4c55ca2831405b6ac55a7528.
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

/* Native entry: 0x42008ee8. */
/*
 * Medius v3.4.7 — host application; 0x42008ee8.
 * Instruction-checked recovered C.
 * Original function-byte SHA-256:
 * 7ab427d5fc4eebc37281fd45962bb85810b735c9a4272fb41fb616b2c7130e4d.
 */

/*
 * Return zero for every unsigned descriptor < 16, including an unopened slot.
 * Other descriptors set current errno 9 and return -1. IMPORTANT: no permission
 * bits are cleared here, so this close does not release a slot for null_open.
 * It does not free memory, call a backend, lock or reset errno on success.
 */
int null_vfs_close(int descriptor)
{
    if ((unsigned int)descriptor < 16) return 0;
    *__errno() = 9;
    return -1;
}

/* Native entry: 0x42008f04. */
/*
 * Medius v3.4.7 — host application; 0x42008f04.
 * Instruction-checked recovered C.
 * Original function-byte SHA-256:
 * f86ed32c2b1b2acd858dcc105b4e494a0352c51a931449afc0e0c1c5e60eb93e.
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

/* Native entry: 0x42008e10. */
/*
 * Medius v3.4.7 — host application; 0x42008e10.
 * Instruction-checked recovered C.
 * Original function-byte SHA-256:
 * cfbfb1924361fdbdc885dc1ed76bfae10cacb7e1ef69e94d1c7cfb999026c2c3.
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

/* Native entry: 0x42008f20. */
/*
 * Medius v3.4.7 — host application; 0x42008f20.
 * Instruction-checked recovered C.
 * Original function-byte SHA-256:
 * cb14605de30e529c3b48cbbcdfc8c2a4cefb146036b8edfd2eae603433260837.
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
