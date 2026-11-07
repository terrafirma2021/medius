/* Medius v3.4.7 device: Newlib mutex slots and retargetable ROM locking.
 * Native register/branch/callee sequences checked against the reviewed host family. */

#include "../include/types.h"

/* Native entry: 0x40376d2c. */
/* Original function-byte SHA-256:
 * 1a308f88b7559c67541fafd0ed59af3464a691ad6a2421f61ff7b1dfff189d30. */
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

/* Native entry: 0x40376dcc. */
/* Original function-byte SHA-256:
 * 8a08fe84415ef066ed4a1f43e29e4744b99ca231d570cae572e58c60216efb57. */
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

/* Native entry: 0x40376e20. */
/* Original function-byte SHA-256:
 * b6972552806c841e3a48f9b94eb80db2561a5edb314baa7a3a5cc781683402ae. */
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

/* Native entry: 0x40376e58. */
/* Original function-byte SHA-256:
 * f94bef4e386e24c34514e7209cd13cea96a7a59526874cdafc118226160fe16c. */
/* Acquire the caller's lock slot with wait 0xffffffff and ordinary type 1.
 * Discard the helper's status. Its startup bypass and non-yielding-context
 * abort rules apply; this wrapper adds no validation, state or explicit fence. */
void _lock_acquire(NewlibLock *lock)
{
    (void)lock_acquire_generic(lock,0xffffffffU,1);
}

/* Native entry: 0x40376e68. */
/* Original function-byte SHA-256:
 * 317a069e822f297c0ab3605fe36964d365708b89f01da2175d29939fe129aad7. */
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

/* Native entry: 0x40376ea8. */
/* Original function-byte SHA-256:
 * f24eaad5f859838229e51cdd9c3015c90c286b6dd87f2ab0f7335ffc8b074b1f. */
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

/* Native entry: 0x40376ed0. */
/* Original function-byte SHA-256:
 * 65ea3e48857d11cd018af7a69d92c447e3b1bcd324662d0343db3bacc4393bd4. */
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

/* Native entry: 0x40376ef8. */
/* Original function-byte SHA-256:
 * d77e1de25adc9ffe497a28cb89895d7ac918e67bc471aadb879bf1acd735d216. */
/* Close a BY-VALUE handle through a local slot. _lock_close clears only that
 * local copy after deletion; caller storage remains unchanged. A NULL handle
 * is accepted, ROM magic is not redirected, and no extra validation is added. */
void __retarget_lock_close(NewlibLock lock)
{
    _lock_close(&lock);
}

/* Native entry: 0x40376f08. */
/* Original function-byte SHA-256:
 * dc4460a00def818095afd4ddb44f723c8b2e595d57538da89f02c7e5816aa940. */
/* Close a BY-VALUE handle through a local slot. _lock_close clears only that
 * local copy after deletion; caller storage remains unchanged. A NULL handle
 * is accepted, ROM magic is not redirected, and no extra validation is added. */
void __retarget_lock_close_recursive(NewlibLock lock)
{
    _lock_close(&lock);
}

/* Native entry: 0x40376f18. */
/* Original function-byte SHA-256:
 * fc9d94f557879a430c04cd7b92a233d2452a7e53cc8373937fb00538c653cdc4. */
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

/* Native entry: 0x40376f44. */
/* Original function-byte SHA-256:
 * ddf56ca9230d61c1f1fb3aec8c470718c4802eb3a1b01248f6fd4500aa7f93f7. */
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

/* Native entry: 0x40376f70. */
/* Original function-byte SHA-256:
 * c23729416b21e406e66a6cda75e64440dc93b99bc7b7c2a24ff1fbc41accdc68. */
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

/* Native entry: 0x40376fa0. */
/* Original function-byte SHA-256:
 * 6b5896a4a89095e4a81b5c8370e3f6d1d3a4b6d65c22d97b56a1c05ec1dc2aaa. */
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

/* Native entry: 0x40376fd0. */
/* Original function-byte SHA-256:
 * 22e62c8fab1e39a81969fd506b467e4ae51424978ddf3bec1d7b55d1b0e02579. */
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

/* Native entry: 0x40376ff0. */
/* Original function-byte SHA-256:
 * b311ef78395491cedf9df5f51a7bc6d356e571895f1b2be81e034cf14438870a. */
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
