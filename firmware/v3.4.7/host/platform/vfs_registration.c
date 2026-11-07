/* Medius v3.4.7 host: VFS table registration and ownership. */
#include "../include/types.h"

/* Native entry: 0x42032640. */
/* Original function-byte SHA-256:
 * 1f6c4fa970f3ec8185b2b2bd9733e711ca6625a30f587baaa8f33db0952fb321. */
/* Register operations in the first free one of eight VFS driver slots.
 * operations must be non-NULL. Length UINT32_MAX skips prefix validation and
 * clears exactly 15 prefix bytes; otherwise reject length 1 or >15, and require
 * '/' at the beginning but not the end when length >=2. Empty names are valid.
 * The supplied length is trusted: strcpy still copies through the first NUL.
 * Return 0x102 for invalid arguments, 0x101 for a full table/allocation failure,
 * or 0x103 if the selected slot becomes occupied on its second read.
 * Advance the high-water count before allocation, with no rollback on failure.
 * Publish the allocated 36-byte entry before initializing it, then copy the
 * prefix and store length, operations, context, slot and flags in native order.
 * On success optionally write the selected index and return zero. No locking,
 * duplicate-prefix test, path-pointer check or operations copy is performed.
 */
int esp_vfs_register_fs_common(const char *base_path,unsigned int prefix_length,
    const volatile VfsOperations *operations,int flags,void *context,
    int *registered_index)
{
    if (operations==NULL)
        return 0x102;
    if (prefix_length!=0xffffffffU) {
        if (prefix_length==1 || prefix_length>15)
            return 0x102;
        if (prefix_length>=2) {
            unsigned char first=(unsigned char)base_path[0];
            if (first!='/')
                return 0x102;
            if ((unsigned char)base_path[prefix_length-1]==first)
                return 0x102;
        }
    }
    unsigned int index;
    for (index=0;index<8;++index) {
        if (VFS_DRIVERS[index]==NULL)
            break;
    }
    if (index==8)
        return 0x101;
    if (VFS_DRIVERS[index]!=NULL)
        return 0x103;
    if (index==VFS_DRIVER_COUNT)
        VFS_DRIVER_COUNT=index+1;
    volatile VfsDriverEntry *entry=heap_caps_malloc(36,0x804);
    if (entry==NULL)
        return 0x101;
    VFS_DRIVERS[index]=entry;
    if (prefix_length==0xffffffffU)
        bzero((void *)entry->path_prefix,15);
    else
        strcpy((char *)entry->path_prefix,base_path);
    entry->path_prefix_length=prefix_length;
    entry->operations=operations;
    entry->context=context;
    entry->offset=(int)index;
    entry->flags=flags;
    if (registered_index!=NULL)
        *registered_index=(int)index;
    return 0;
}

/* Native entry: 0x4203274c. */
/* Original function-byte SHA-256:
 * e6943e8ad76992110e8d2de6cd0a3a829de5b2d3d1253661ed00c0c64fb1e0da. */
/* Register an ESP-IDF VFS operations table under a NUL-terminated prefix.
 * Reject NULL operations with 0x102. Flag bit 3 selects borrowed/static tables;
 * otherwise duplicate optional directory/terminal/select tables (64/28/24 bytes)
 * and the 56-byte main table, using capability mask 0x804 for each allocation.
 * Copy callbacks verbatim; no callback targets are invoked here. Optional table
 * pointers are reloaded after allocation. Main callback reads follow native
 * order: pwrite, pread, open, close, fstat, seek, read, fcntl, ioctl, fsync, write.
 * Allocation failure frees directory, terminal, select in that order and returns
 * 0x101. Registration failure instead reloads/frees terminal, directory, select
 * from the allocated main table, then frees the main table and propagates the
 * error. Success transfers the allocated copies to the VFS registry.
 * Prefix strlen occurs after copying in the owned path; this function supplies
 * no prefix-pointer check, locking or callback/context lifetime management.
 */
int esp_vfs_register_fs(const char *base_path,
    const volatile VfsOperations *operations,int flags,void *context)
{
    if (operations==NULL)
        return 0x102;
    if (flags&8)
        return esp_vfs_register_fs_common(base_path,strlen(base_path),operations,
                                         flags,context,NULL);
    void *directory_copy=NULL;
    void *terminal_copy=NULL;
    void *select_copy=NULL;
    if (operations->directory!=NULL) {
        directory_copy=heap_caps_malloc(64,0x804);
        if (directory_copy==NULL)
            goto allocation_failed;
        memcpy(directory_copy,(const void *)operations->directory,64);
    }
    if (operations->terminal!=NULL) {
        terminal_copy=heap_caps_malloc(28,0x804);
        if (terminal_copy==NULL)
            goto allocation_failed;
        memcpy(terminal_copy,(const void *)operations->terminal,28);
    }
    if (operations->select!=NULL) {
        select_copy=heap_caps_malloc(24,0x804);
        if (select_copy==NULL)
            goto allocation_failed;
        memcpy(select_copy,(const void *)operations->select,24);
    }
    VfsOperations snapshot;
    snapshot.write_at=operations->write_at;
    snapshot.read_at=operations->read_at;
    snapshot.open=operations->open;
    snapshot.close=operations->close;
    snapshot.status=operations->status;
    snapshot.seek=operations->seek;
    snapshot.read=operations->read;
    snapshot.control=operations->control;
    snapshot.ioctl=operations->ioctl;
    snapshot.sync=operations->sync;
    snapshot.write=operations->write;
    snapshot.directory=directory_copy;
    snapshot.terminal=terminal_copy;
    snapshot.select=select_copy;
    VfsOperations *owned=heap_caps_malloc(56,0x804);
    if (owned==NULL)
        goto allocation_failed;
    memcpy(owned,&snapshot,56);
    int result=esp_vfs_register_fs_common(base_path,strlen(base_path),owned,
                                         flags,context,NULL);
    if (result==0)
        return 0;
    const volatile VfsOperations *cleanup=owned;
    free((void *)cleanup->terminal);
    free((void *)cleanup->directory);
    free((void *)cleanup->select);
    free(owned);
    return result;
allocation_failed:
    free(directory_copy);
    free(terminal_copy);
    free(select_copy);
    return 0x101;
}
