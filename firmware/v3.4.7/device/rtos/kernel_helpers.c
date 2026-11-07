/* Medius v3.4.7 device — kernel_helpers.c. */
#include "../include/types.h"

/* Native entry: 0x40386ae4. */
/* Original function-byte SHA-256:
 * 29ec2fb591a3df0b985993e864a3494e68aa297effc935ecc487eb1358314bd8. */
/* Forward core_id unchanged to the cross-core yield-interrupt sender.
 * No core-range check, scheduler-state check, local switch or completion wait
 * is added. The callee supplies its interrupt/mailbox effects. Returns void. */
void vPortYieldOtherCore(int core_id)
{
    esp_crosscore_int_send_yield(core_id);
}

/* Native entry: 0x40386af0. */
/* Original function-byte SHA-256:
 * 1617ec49b442371ac58215c5a7fffdae1a3352e44f338dba935ac81b7e600e18. */
/* Fatal stack-overflow hook; unused_task is not dereferenced. Clear75 stack
 * bytes, concatenate the fixed prefix, task_name and fixed suffix through
 * three strcat calls, feeding each returned destination into the next call.
 * task_name must be a terminated name small enough for the75-byte buffer;
 * no null/length guard or truncation is provided. This preserves the native
 * unbounded concatenation rather than substituting a bounded formatter.
 * Pass the assembled message to esp_system_abort. If it returns, execute the
 * native illegal instruction; there is no normal return or recovery path. */
void vApplicationStackOverflowHook(RtosTask *unused_task,char *task_name)
{
    (void)unused_task;
    char message[75];
    const char *fragments[3]={"***ERROR*** A stack overflow in task ",task_name,
        " has been detected."};
    memset(message,0,sizeof(message));
    char *destination=message;
    for (unsigned int i=0;i<3U;++i) destination=strcat(destination,fragments[i]);
    newlib_system_abort_boundary(message);
    __asm__ volatile("ill");
    __builtin_unreachable();
}

/* Native entry: 0x4038909c. */
/* Original function-byte SHA-256:
 * 0f8835450e9a08a9780627ce9a5726856cd79e2108794332feb524a55be5f9b6. */
/* First check the task address with xPortCheckValidTCBMem, even when snapshot
 * is null. Require its low return BYTE to equal1 exactly, then require a
 * nonnull snapshot; otherwise return0 with no snapshot writes. Admission
 * checks the address region/accessibility, not TCB extent, ownership/lifetime
 * or scheduling state. Caller supplies a real live TCB and writable12 bytes.
 * Read saved stack-top WORD0 and stack-end WORD+0x48 before any destination
 * write, then store TCB, top and end WORDs in that order and return1. No task
 * suspension, critical section or cross-core coherence guarantee is supplied. */
int vTaskGetSnapshot(RtosTask *task,TaskSnapshot *snapshot)
{
    unsigned int valid=rtos_check_tcb_memory_raw(task);
    if ((unsigned char)valid!=1U || !snapshot) return 0;
    const volatile RtosTask *source=task;
    void *top=source->top_of_stack;
    void *end=source->stack_end;
    volatile TaskSnapshot *destination=snapshot;
    destination->task_control_block=task;
    destination->top_of_stack=top;
    destination->end_of_stack=end;
    return 1;
}

/* Native entry: 0x403890cc. */
/* Original function-byte SHA-256:
 * 93e8ed3c1512981fb448b3382b8582ce78752d5006aa89d4441e0c6cc75c4c7f. */
/* Linked ESP-IDF weak timer-task startup stub: return pdPASS(1), with no
 * allocation, task/queue creation, timer initialization or memory writes.
 * vTaskStartScheduler uses this success result to proceed. This entry does
 * not create a FreeRTOS timer daemon; other timer implementations are separate.
 * Identity matches esp_additions/freertos_tasks_c_additions.h and its caller. */
int xTimerCreateTimerTask(void)
{
    return 1;
}
