/* Medius v3.4.7 host: Newlib mutex slots and retargetable ROM locking.
 * Behavior matched against the local ESP-IDF newlib/locks.c and native code. */

#include "../include/types.h"

/* Native entry: 0x4037697c. */
/* Original function-byte SHA-256:
 * 346a09eaf828839bf1023814f1c5654cf51c5aa24b1f3e620d7a1d523ae8168e. */
/* Acquire the mutex handle in *lock, lazily allocating when absent. An absent
 * handle returns success before scheduler startup without allocation; a present
 * handle also returns success at that stage. Otherwise initialize under the
 * shared spinlock, reread the handle after unlock, and assert if still NULL.
 *
 * PS.INTLEVEL==0 selects task acquisition; mutex_type==4 uses recursive take,
 * every other full-word type uses ordinary semaphore take. Nonzero INTLEVEL
 * forbids recursive acquisition and aborts if an ISR take fails with nonzero
 * wait. With wait=0 a failed ISR take returns normally. Yield when its woken
 * flag is nonzero. Return 0 only for take result exactly 1, otherwise -1.
 *
 * The original create call supplies mutex_type in A2; the reviewed specialized
 * constructor reads no argument, so the unused input is omitted here. A valid
 * slot and matching kernel services are required. Allocation failure aborts
 * while the initialization lock is held. Assertions have all-zero arguments in
 * this firmware. No explicit MEMW is present in this wrapper. */
int lock_acquire_generic(NewlibLock *lock,unsigned int wait_ticks,unsigned int mutex_type)
{
    volatile NewlibLock *slot = lock;
    RtosQueue *handle = (RtosQueue *)*slot;
    if (handle == 0) {
        if (xTaskGetSchedulerState() == SCHEDULER_STATE_NOT_STARTED)
            return 0;
        (void)xPortEnterCriticalTimeout(MEDIUS_NEWLIB_INIT_LOCK,-1);
        if (*slot == 0) {
            RtosQueue *created = xQueueCreateMutex();
            if (created == 0)
                abort();
            *slot = (NewlibLock)created;
        }
        vPortExitCritical(MEDIUS_NEWLIB_INIT_LOCK);
        handle = (RtosQueue *)*slot;
        if (handle == 0)
            __assert_func(0,0,0,0);
    }
    if (xTaskGetSchedulerState() == SCHEDULER_STATE_NOT_STARTED)
        return 0;
    unsigned int processor_status;
    __asm__ volatile ("rsr.ps %0" : "=a"(processor_status) : : "memory");
    int result;
    if ((processor_status & 15U) != 0) {
        if (mutex_type == 4)
            abort();
        int higher_priority_task_woken = 0;
        result = xQueueReceiveFromISR(handle,0,&higher_priority_task_woken);
        if (result == 0 && wait_ticks != 0)
            abort();
        if (higher_priority_task_woken != 0)
            _frxt_setup_switch();
    } else if (mutex_type == 4) {
        result = xQueueTakeMutexRecursive((RtosQueue *)handle,wait_ticks);
    } else {
        result = xQueueSemaphoreTake(handle,wait_ticks);
    }
    return result == 1 ? 0 : -1;
}

/* Native entry: 0x40376a1c. */
/* Original function-byte SHA-256:
 * 4645fcc5e98996ea7732327c3b18655d519dbb834cfae7d69fee10ccee404604. */
/* Release the handle in *lock, unless the scheduler has not started. Require a
 * nonNULL handle once started. With PS.INTLEVEL==0, type 4 selects recursive
 * give; other full-word types select ordinary zero-wait/back-position give.
 * Nonzero INTLEVEL aborts for type 4; otherwise give from ISR and request a
 * context switch when its woken flag is nonzero. Discard give results. No slot
 * mutation, ownership check here, or explicit MEMW. Assertions use NULL/0. */
void lock_release_generic(NewlibLock *lock,unsigned int mutex_type)
{
    if (xTaskGetSchedulerState() == SCHEDULER_STATE_NOT_STARTED)
        return;
    RtosQueue *handle = (RtosQueue *)*(volatile NewlibLock *)lock;
    if (handle == 0)
        __assert_func(0,0,0,0);
    unsigned int processor_status;
    __asm__ volatile ("rsr.ps %0" : "=a"(processor_status) : : "memory");
    if ((processor_status & 15U) != 0) {
        if (mutex_type == 4)
            abort();
        int higher_priority_task_woken = 0;
        (void)xQueueGiveFromISR(handle,&higher_priority_task_woken);
        if (higher_priority_task_woken != 0)
            _frxt_setup_switch();
    } else if (mutex_type == 4) {
        (void)xQueueGiveMutexRecursive((RtosQueue *)handle);
    } else {
        (void)xQueueGenericSend(handle,0,0,QUEUE_SEND_TO_BACK);
    }
}

/* Native entry: 0x40376a70. */
/* Original function-byte SHA-256:
 * 7c07c92e4a40abd655bd205d14b66de92ca46f3225fcbd9c45b35352a4bfd77d. */
/* Under the shared initialization spinlock, delete a nonNULL mutex and clear
 * its handle slot. Assert if the locked holder query returns nonNULL; a NULL
 * slot needs no delete. No scheduler-startup bypass. The caller must prevent
 * concurrent use/reinitialization: the spinlock alone does not provide that
 * lifetime guarantee. Invalid slots are not checked. No explicit MEMW. */
void _lock_close(NewlibLock *lock)
{
    (void)xPortEnterCriticalTimeout(MEDIUS_NEWLIB_INIT_LOCK,-1);
    volatile NewlibLock *slot = lock;
    RtosQueue *handle = (RtosQueue *)*slot;
    if (handle != 0) {
        if (xQueueGetMutexHolder(handle) != 0)
            __assert_func(0,0,0,0);
        vQueueDelete(handle);
        *slot = 0;
    }
    vPortExitCritical(MEDIUS_NEWLIB_INIT_LOCK);
}

/* Native entry: 0x40376aa8. */
/* Original function-byte SHA-256:
 * f94bef4e386e24c34514e7209cd13cea96a7a59526874cdafc118226160fe16c. */
/* Acquire the caller's lock slot with wait 0xffffffff and ordinary type 1.
 * Discard the helper's status. Its startup bypass and non-yielding-context
 * abort rules apply; this wrapper adds no validation, state or explicit fence. */
void _lock_acquire(NewlibLock *lock)
{
    (void)lock_acquire_generic(lock,0xffffffffU,1);
}

/* Native entry: 0x40376ab8. */
/* Original function-byte SHA-256:
 * f3c972c9124513113fb2a9ac4c47def7b41689d8bea4e4a4e2753b9187e5f3f9. */
/* Acquire the caller's lock slot with wait 0xffffffff and recursive type 4.
 * Discard status. The helper permits startup no-op and aborts for recursive
 * use with nonzero PS.INTLEVEL. No additional validation or explicit fence. */
void _lock_acquire_recursive(NewlibLock *lock)
{
    (void)lock_acquire_generic(lock,0xffffffffU,4);
}

/* Native entry: 0x40376ac8. */
/* Original function-byte SHA-256:
 * 15c6458b769fb92b88e316d41ebd92a3c87eed51fc7a3a317bb222bb641a3a53. */
/* Inlined ordinary release path. Return before dereferencing lock if the
 * scheduler has not started. Otherwise assert the handle, sample PS.INTLEVEL,
 * and use a zero-wait/back give when zero, an ISR give when nonzero. Yield if
 * the ISR woken flag is nonzero. Ignore give status; no slot write or MEMW. */
void _lock_release(NewlibLock *lock)
{
    if (xTaskGetSchedulerState() == SCHEDULER_STATE_NOT_STARTED)
        return;
    RtosQueue *handle = (RtosQueue *)*(volatile NewlibLock *)lock;
    if (handle == 0)
        __assert_func(0,0,0,0);
    unsigned int processor_status;
    __asm__ volatile ("rsr.ps %0" : "=a"(processor_status) : : "memory");
    if ((processor_status & 15U) == 0) {
        (void)xQueueGenericSend(handle,0,0,QUEUE_SEND_TO_BACK);
    } else {
        int higher_priority_task_woken = 0;
        (void)xQueueGiveFromISR(handle,&higher_priority_task_woken);
        if (higher_priority_task_woken != 0)
            _frxt_setup_switch();
    }
}

/* Native entry: 0x40376b08. */
/* Original function-byte SHA-256:
 * 48ca7f9988b7c876c44c1d554de31274e234cd5721a855d57e42d107c6e113a8. */
/* Inlined recursive release path: startup returns before reading the slot;
 * later require a handle and PS.INTLEVEL==0, aborting otherwise. Give the
 * recursive mutex once and discard status. No slot mutation or explicit MEMW. */
void _lock_release_recursive(NewlibLock *lock)
{
    if (xTaskGetSchedulerState() == SCHEDULER_STATE_NOT_STARTED)
        return;
    RtosQueue *handle = (RtosQueue *)*(volatile NewlibLock *)lock;
    if (handle == 0)
        __assert_func(0,0,0,0);
    unsigned int processor_status;
    __asm__ volatile ("rsr.ps %0" : "=a"(processor_status) : : "memory");
    if ((processor_status & 15U) != 0)
        abort();
    (void)xQueueGiveMutexRecursive((RtosQueue *)handle);
}

/* Native entry: 0x40376b30. */
/* Original function-byte SHA-256:
 * ad3ee048fe149c525dd181800075033c405e489e3d5ef3f7a740d5013f9d9bbc. */
/* Clear the caller's slot BEFORE entering the initialization spinlock; recheck
 * it under that lock, create if still zero, and publish the handle. Native
 * supplies constructor type 1; that specialized callee ignores the input.
 * Allocation failure aborts with the spinlock held. There is no startup bypass
 * or release of an earlier handle overwritten by the initial clear. This is
 * also the matching legacy _lock_init behavior. No explicit MEMW. */
void __retarget_lock_init(NewlibLock *lock)
{
    volatile NewlibLock *slot = lock;
    *slot = 0;
    (void)xPortEnterCriticalTimeout(MEDIUS_NEWLIB_INIT_LOCK,-1);
    if (*slot == 0) {
        RtosQueue *created = xQueueCreateMutex();
        if (created == 0)
            abort();
        *slot = (NewlibLock)created;
    }
    vPortExitCritical(MEDIUS_NEWLIB_INIT_LOCK);
}

/* Native entry: 0x40376b58. */
/* Original function-byte SHA-256:
 * a14de590f53eca820af8fa1f756055e0842bb1ee4528bf488ed01f15d295f1be. */
/* Clear the caller's slot BEFORE entering the initialization spinlock; recheck
 * it under that lock, create if still zero, and publish the handle. Native
 * supplies constructor type 4; that specialized callee ignores the input.
 * Allocation failure aborts with the spinlock held. There is no startup bypass
 * or release of an earlier handle overwritten by the initial clear. This is
 * also the matching legacy _lock_init_recursive behavior. No explicit MEMW. */
void __retarget_lock_init_recursive(NewlibLock *lock)
{
    volatile NewlibLock *slot = lock;
    *slot = 0;
    (void)xPortEnterCriticalTimeout(MEDIUS_NEWLIB_INIT_LOCK,-1);
    if (*slot == 0) {
        RtosQueue *created = xQueueCreateMutex();
        if (created == 0)
            abort();
        *slot = (NewlibLock)created;
    }
    vPortExitCritical(MEDIUS_NEWLIB_INIT_LOCK);
}

/* Native entry: 0x40376b80. */
/* Original function-byte SHA-256:
 * 7050c8c8f6fe566ed827d226ae7f405ff462e41cd35dbce9ac2bfad1a5791399. */
/* Close a BY-VALUE handle through a local slot. _lock_close clears only that
 * local copy after deletion; caller storage remains unchanged. A NULL handle
 * is accepted, ROM magic is not redirected, and no extra validation is added. */
void __retarget_lock_close(NewlibLock lock)
{
    _lock_close(&lock);
}

/* Native entry: 0x40376b90. */
/* Original function-byte SHA-256:
 * 0b2c38c14f37aa449c228373519c46e354a8ebf4113b03e654267829e2a98529. */
/* Close a BY-VALUE handle through a local slot. _lock_close clears only that
 * local copy after deletion; caller storage remains unchanged. A NULL handle
 * is accepted, ROM magic is not redirected, and no extra validation is added. */
void __retarget_lock_close_recursive(NewlibLock lock)
{
    _lock_close(&lock);
}

/* Native entry: 0x40376ba0. */
/* Original function-byte SHA-256:
 * a2219bf8b6584306b91c9a77c271fb64d054174c67012458fbc43009aa7c721c. */
/* Require a nonNULL BY-VALUE handle, then read its first word. ROM magic
 * 0xbb10c433 redirects the LOCAL handle to the shared ordinary mutex;
 * the original marker is untouched. Acquire via a local slot with type 1
 * and wait 0xffffffffU. Discard helper status. Validation/magic sampling happens even
 * before scheduler startup. No additional spinlock, ownership check or MEMW. */
void __retarget_lock_acquire(NewlibLock lock)
{
    if (lock == 0)
        __assert_func(0,0,0,0);
    if (*(const volatile unsigned int *)lock == MEDIUS_NEWLIB_ROM_MUTEX_MAGIC)
        lock = MEDIUS_NEWLIB_COMMON_MUTEX;
    (void)lock_acquire_generic(&lock,0xffffffffU,1);
}

/* Native entry: 0x40376bcc. */
/* Original function-byte SHA-256:
 * c638064a45ab135abbb08158515117f7031e22d96ed87026789606cb69accd03. */
/* Require a nonNULL BY-VALUE handle, then read its first word. ROM magic
 * 0xbb10c433 redirects the LOCAL handle to the shared recursive mutex;
 * the original marker is untouched. Acquire via a local slot with type 4
 * and wait 0xffffffffU. Discard helper status. Validation/magic sampling happens even
 * before scheduler startup. No additional spinlock, ownership check or MEMW. */
void __retarget_lock_acquire_recursive(NewlibLock lock)
{
    if (lock == 0)
        __assert_func(0,0,0,0);
    if (*(const volatile unsigned int *)lock == MEDIUS_NEWLIB_ROM_MUTEX_MAGIC)
        lock = MEDIUS_NEWLIB_COMMON_RECURSIVE_MUTEX;
    (void)lock_acquire_generic(&lock,0xffffffffU,4);
}

/* Native entry: 0x40376bf8. */
/* Original function-byte SHA-256:
 * dcb2e5ead03d12407cb24b89d4b8674639429dddaefc4bd0f6671c3ddc2bb888. */
/* Require a nonNULL BY-VALUE handle, then read its first word. ROM magic
 * 0xbb10c433 redirects the LOCAL handle to the shared ordinary mutex;
 * the original marker is untouched. Acquire via a local slot with type 1
 * and wait 0. Return helper status 0/-1. Validation/magic sampling happens even
 * before scheduler startup. No additional spinlock, ownership check or MEMW. */
int __retarget_lock_try_acquire(NewlibLock lock)
{
    if (lock == 0)
        __assert_func(0,0,0,0);
    if (*(const volatile unsigned int *)lock == MEDIUS_NEWLIB_ROM_MUTEX_MAGIC)
        lock = MEDIUS_NEWLIB_COMMON_MUTEX;
    return lock_acquire_generic(&lock,0,1);
}

/* Native entry: 0x40376c28. */
/* Original function-byte SHA-256:
 * 2c817f310e953f7adae9e4cd1dddc9c6906ab40f5fbfe8a5ab0d65c0cd461333. */
/* Require a nonNULL BY-VALUE handle, then read its first word. ROM magic
 * 0xbb10c433 redirects the LOCAL handle to the shared recursive mutex;
 * the original marker is untouched. Acquire via a local slot with type 4
 * and wait 0. Return helper status 0/-1. Validation/magic sampling happens even
 * before scheduler startup. No additional spinlock, ownership check or MEMW. */
int __retarget_lock_try_acquire_recursive(NewlibLock lock)
{
    if (lock == 0)
        __assert_func(0,0,0,0);
    if (*(const volatile unsigned int *)lock == MEDIUS_NEWLIB_ROM_MUTEX_MAGIC)
        lock = MEDIUS_NEWLIB_COMMON_RECURSIVE_MUTEX;
    return lock_acquire_generic(&lock,0,4);
}

/* Native entry: 0x40376c58. */
/* Original function-byte SHA-256:
 * 41704df5d38d85ed9aff506db464fef4e8e35948da131b383f5628d6a080820d. */
/* Require a nonNULL BY-VALUE handle, then release through a local slot using
 * type 1. Unlike acquire, this entry does not inspect or redirect ROM magic.
 * The nonNULL assertion precedes the helper's scheduler-startup check. No caller
 * handle mutation, extra ownership check, returned status or explicit MEMW. */
void __retarget_lock_release(NewlibLock lock)
{
    if (lock == 0)
        __assert_func(0,0,0,0);
    lock_release_generic(&lock,1);
}

/* Native entry: 0x40376c78. */
/* Original function-byte SHA-256:
 * 628b9c1c2f48fe7452a7eba6a0f9d63e24764f0e0d7e8a91361f368028fcc5c5. */
/* Require a nonNULL BY-VALUE handle, then release through a local slot using
 * type 4. Unlike acquire, this entry does not inspect or redirect ROM magic.
 * The nonNULL assertion precedes the helper's scheduler-startup check. No caller
 * handle mutation, extra ownership check, returned status or explicit MEMW. */
void __retarget_lock_release_recursive(NewlibLock lock)
{
    if (lock == 0)
        __assert_func(0,0,0,0);
    lock_release_generic(&lock,4);
}
