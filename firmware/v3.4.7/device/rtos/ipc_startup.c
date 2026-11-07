/* Medius v3.4.7 device — static IPC channel and task construction. */
#include "../include/types.h"

/* Native entry: 0x42003988. */
/* Original function-byte SHA-256:
 * 8af879df2a56c59cf2652ef5f702a22ae673e0d1da29999cf3769f25ee205030. */
/*
 * Construct the two per-core IPC channels and tasks in core order 0, then 1.
 * Copy the linked five-byte "ipcX" literal using a WORD read then a BYTE read,
 * and replace X with the decimal core digit. Each core gets a static available
 * mutex followed by a static empty one-token/zero-item-size acknowledgement
 * queue, using separate arrays of 84-byte queue controls. Publish each handle
 * immediately; the queue constructors' results are not checked here.
 *
 * Create ipc_task as ipc0/ipc1, stack 0x500 BYTES, priority 24, argument
 * (void *)core and matching core affinity. The output points directly into
 * dispatch->tasks[core]. Any creation result other than 1 asserts; earlier
 * channels/tasks remain installed. The native second iteration takes core=1
 * from the checked first creation result. No rollback, reinitialization guard,
 * whole-control zeroing, explicit MEMW or scheduler-start operation here.
 * The native generic static-queue call also supplies an unused fifth value 3;
 * the separately reviewed linked callee reads only the four typed parameters.
 */
void esp_ipc_init(void)
{
    IpcTaskName name;
    name.initial.word = IPC_INITIAL_TASK_NAME->initial.word;
    name.terminator = IPC_INITIAL_TASK_NAME->terminator;
    IpcDispatchState *dispatch = IPC_DISPATCH_STATE;
    for (unsigned int core = 0; core != 2U; ++core) {
        name.initial.bytes[3] = (unsigned char)('0' + core);
        dispatch->submission_mutexes[core] =
            xQueueCreateMutexStatic(1, &IPC_MUTEX_STORAGE[core]);
        dispatch->acknowledgements[core] =
            xQueueGenericCreateStatic(1, 0, NULL, &IPC_ACKNOWLEDGEMENT_STORAGE[core]);
        int status = xTaskCreatePinnedToCore(ipc_task, (char *)&name,
                                             0x500U, (void *)core, 24,
                                             (RtosTask **)&dispatch->tasks[core], (int)core);
        if (status != 1) __assert_func(NULL, 0, NULL, NULL);
    }
}
