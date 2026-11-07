/* Medius v3.4.7 device — reserved EP0 task storage. */
#include "../include/types.h"

/* Native entry: 0x42008a44. */
/* Original function-byte SHA-256:
 * a8647e575423993ca6f6f7e034bdf4d6ce4ee400754e402d1e40a5a6bef9de15. */
/*
 * Reserve the device's static usbd_ep0 task backing allocations: first a
 * 6144-byte stack, then a 340-byte TCB, both with caps 0x804 (internal/8-bit).
 * Publish the first result before requesting the second; always attempt both.
 * Publish the second result, then freshly read the shared stack pointer.
 * If either is NULL, free that captured stack pointer, freshly load/free the
 * shared TCB pointer, then clear stack followed by TCB. NULL frees are passed
 * through. Successful allocations retain uninitialized content.
 *
 * No task is created, and retained task handle/availability BYTE are untouched.
 * No return status, logging, lock or explicit MEMW. Repeated calls overwrite
 * earlier pointers without freeing them first; this is a startup reservation
 * helper, not a safe retry or resize API. The OSAL consumer selects these
 * buffers for the exact task name usbd_ep0 and requests a 6144-byte core-0 task.
 */
void control_endpoint_reserve_task_storage(void)
{
    MediusUsbEp0TaskResources *resources = MEDIUS_USB_EP0_TASK_RESOURCES;
    resources->stack = heap_caps_malloc(0x1800U, 0x804U);
    RtosTask *tcb = heap_caps_malloc(0x154U, 0x804U);
    resources->tcb = tcb;
    unsigned int *stack = resources->stack;
    if (tcb == NULL || stack == NULL) {
        heap_caps_free(stack);
        heap_caps_free(resources->tcb);
        resources->stack = NULL;
        resources->tcb = NULL;
    }
}
