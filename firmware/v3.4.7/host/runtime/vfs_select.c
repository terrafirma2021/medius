/* Medius v3.4.7 host — runtime/vfs_select.c.
 */

#include "../include/types.h"

/* Native entry: 0x42032f30. */
/*
 * Medius v3.4.7 — host application; 0x42032f30.
 * Instruction-checked recovered C.
 * Original function-byte SHA-256:
 * 3eff0a123a50b02a18b24c9db2265409e068dd6ccb3da2d0d41b0688b00180f8.
 */

/* Test only the saved flag word's low byte. Nonzero gives the local semaphore
 * with zero wait, ignoring send status. Otherwise scan a snapshot of unsigned
 * driver count and invoke the FIRST stop_socket callback in a non-NULL entry
 * with non-NULL select table/callback. Pass saved handle. Read each slot/table/
 * callback afresh; the entry's operations pointer is not NULL-checked. No lock,
 * errno, result or handle validation. No matching callback means no wake. */
void medius_vfs_select_triggered(VfsSelectSemaphore semaphore)
{
    if ((semaphore.flags_word & 0xffU) != 0) {
        (void)xQueueGenericSend(semaphore.handle,NULL,0,0);
        return;
    }
    unsigned int remaining = VFS_DRIVER_COUNT;
    unsigned int index = 0;
    while (remaining != 0) {
        const volatile VfsDriverEntry *entry = VFS_DRIVERS[index++];
        if (entry) {
            const volatile VfsOperations *operations = entry->operations;
            const volatile VfsSelectOperations *select = operations->select;
            if (select) {
                MediusVfsStopSelectOperation callback = select->stop_socket;
                if (callback) { callback(semaphore.handle); return; }
            }
        }
        --remaining;
    }
}

/* Native entry: 0x4038d550. */
/*
 * Medius v3.4.7 — host application; 0x4038d550.
 * Instruction-checked recovered C.
 * Original function-byte SHA-256:
 * 5e625d48e01f5ead6968afea618811cde23bdab6dd02367681a88e1976331040.
 */

/* ISR counterpart: low flag byte nonzero gives the local semaphore through
 * xQueueGiveFromISR(handle,task_woken), ignoring result. Otherwise scan a snapshot
 * of driver count and invoke the first stop_socket_isr callback with handle and
 * task_woken. Guard entry/select/callback, not operations. No lock, errno, local
 * yield or task_woken initialization; only the selected backend may update it. */
void medius_vfs_select_triggered_isr(VfsSelectSemaphore semaphore,int *task_woken)
{
    if ((semaphore.flags_word & 0xffU) != 0) {
        (void)xQueueGiveFromISR(semaphore.handle,task_woken);
        return;
    }
    unsigned int remaining = VFS_DRIVER_COUNT;
    unsigned int index = 0;
    while (remaining != 0) {
        const volatile VfsDriverEntry *entry = VFS_DRIVERS[index++];
        if (entry) {
            const volatile VfsOperations *operations = entry->operations;
            const volatile VfsSelectOperations *select = operations->select;
            if (select) {
                MediusVfsStopSelectIsrOperation callback = select->stop_socket_isr;
                if (callback) { callback(semaphore.handle,task_woken); return; }
            }
        }
        --remaining;
    }
}
