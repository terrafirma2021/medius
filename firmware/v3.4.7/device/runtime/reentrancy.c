/* Medius v3.4.7 device — runtime/reentrancy.c.
 * Recovered C and native assembly, grouped for source navigation.
 * Original entry addresses, firmware-byte hashes and function comments follow.
 */

#include "../include/types.h"

/* Native entry: 0x40377010. */
/*
 * Medius v3.4.7 — device application; 0x40377010.
 *
 * Zeroes the 240-byte Newlib context and shares the global standard streams, cleanup function and stdio-initialized marker. This avoids per-task allocations of stdin/stdout/stderr.
 *
 * Calls: memset.
 *
 * Called by: prvInitialiseNewTask.
 *
 * Original function-byte SHA-256:
 * b80b52cb064575ecadfb4d967dbeca92857900fa398d99dd85fe412630c285d2.
 */

/* Zeroes the 240-byte Newlib context and shares the global standard streams, cleanup function and stdio-initialized marker. This avoids per-task allocations of stdin/stdout/stderr.
   Reference: ESP-IDF v5.4.4 components/newlib/reent_init.c. */

/*
 * reent: Writable 240-byte private context, distinct from the startup object, with no live
 *   auxiliary allocations to overwrite.
 * Returns: Nothing.
 * Requirements/effects: Zeroes the context and copies global standard-stream pointers, cleanup
 *   callback and stdio-initialized marker. Does not allocate private standard streams or free
 *   overwritten context resources; global stdio state must already be initialized. No locking
 *   or memory barrier is supplied; the five global fields are read in native order.
 */

void esp_reent_init(NewlibReent *reent)
{
    NewlibCleanup cleanup;
    void *standard_error;
    void *standard_output;
    void *standard_input;
    int stdio_initialized;

    memset(reent, 0, sizeof *reent);
    /* Snapshot in native load order, then publish the five shared fields. */
    cleanup = NEWLIB_STARTUP_CONTEXT->cleanup;
    standard_error = NEWLIB_STARTUP_CONTEXT->standard_error;
    standard_output = NEWLIB_STARTUP_CONTEXT->standard_output;
    standard_input = NEWLIB_STARTUP_CONTEXT->standard_input;
    stdio_initialized = NEWLIB_STARTUP_CONTEXT->stdio_initialized;
    reent->cleanup = cleanup;
    reent->standard_input = standard_input;
    reent->standard_output = standard_output;
    reent->standard_error = standard_error;
    reent->stdio_initialized = stdio_initialized;
}

/* Native entry: 0x40389074. */
/*
 * Medius v3.4.7 — device application; 0x40389074.
 *
 * Returns the current task Newlib context or the global startup fallback.
 *
 * Calls: _xtos_set_intlevel (restores the saved interrupt-level bits).
 *
 * Called by: calloc, FUN_420075ec, FUN_4201869c, FUN_420186b4, FUN_420189ac, FUN_420189e0,
 * vprintf, vsnprintf, FUN_42018bbc, FUN_42018ff0, FUN_42019000, FUN_42019018,
 * FUN_42019030, FUN_42019048, FUN_42019094, FUN_420190b0, FUN_4201f490, FUN_4203a258,
 * FUN_4203a464, FUN_4203a4c0, FUN_4203a538, FUN_4203a5b4, FUN_4203a628.
 *
 * Original function-byte SHA-256:
 * 912144856599ec8859beec3c3d3da99780a539a4982f41a4fc838afba310ba4e.
 */

/* Masks interrupts while reading the current-core TCB pointer, restores the previous interrupt
 * level, then returns TCB+0x5c when present or the global context at 0x3fcabb5c before tasks
 * exist. vprintf/vsnprintf use this for task-local stdio/error state.
 */

/* Reads the calling CPU current TCB with interrupts masked, restores interrupt level and returns its context at offset 0x5c. Returns the global startup context before a task exists.
   Reference: ESP-IDF v5.4.4 freertos_tasks_c_additions.h and current-TCB/context-init instruction paths. */

/*
 * Returns: Current CPU task Newlib context, or the fixed global startup context when no task is
 *   selected.
 * Requirements/effects: Briefly raises interrupt level to3 to snapshot the PRID-selected TCB, then
 *   restores the saved interrupt-level bits. Does not allocate, lock the scheduler or
 *   extend TCB lifetime. Forms the
 *   embedded-context pointer only after checking for a non-NULL TCB.
 */

NewlibReent *__getreent(void)
{
    unsigned int saved_processor_status;
    unsigned int processor_id;
    RtosTask *current_task;

    __asm__ volatile ("rsil %0, 3" : "=a"(saved_processor_status) : : "memory");
    __asm__ volatile ("rsr.prid %0" : "=a"(processor_id));
    memw();
    current_task = RTOS_CURRENT_TASKS[(processor_id >> 13) & 1U];
    _xtos_set_intlevel(saved_processor_status);
    if (current_task == (RtosTask *)0)
        return (NewlibReent *)NEWLIB_STARTUP_CONTEXT;
    return &current_task->libc_reent;
}

/* Native entry: 0x42018f2c. */
/*
 * Medius v3.4.7 — device application; 0x42018f2c.
 *
 * Walks conversion freelists, releases task-local conversion and auxiliary buffers, then invokes the context cleanup callback when present. Skips the global context selected by the runtime pointer. Does not free the context object itself.
 *
 * Calls: medius_newlib_free_r (native _free_r).
 *
 * Called by: prvDeleteTCB.
 *
 * Indirect call: the context cleanup callback, when non-NULL.
 *
 * Original function-byte SHA-256:
 * b4cac61734b1058ca4a0b5ed7c5d837a328b9740143acbf0d49999ffcf92e827.
 */

/* Walks conversion freelists, releases task-local conversion and auxiliary buffers, then invokes the context cleanup callback when present. Skips the global context selected by the runtime pointer. Does not free the context object itself.
   Reference: newlib sys/reent.h layout and original task-deletion/free-wrapper call graph. */

/*
 * reent: Live initialized 240-byte context, reclaimed once with no concurrent users. Cached
 *   chains must be acyclic, with uniquely owned allocations and valid bucket metadata.
 * Returns: Nothing. The runtime global context is skipped.
 * Requirements/effects: For a non-global context walks32 Bigint freelist buckets, frees cached
 *   result and auxiliary buffers/conversion state, then calls the cleanup callback if present.
 *   Does not free the context object, clear freed fields or walk the powers_of_five chain in this
 *   body. Bucket 32 of the 33-slot allocation is not visited. The global pointer is sampled
 *   once before any free; cleanup is sampled after the frees. No NULL-context check or lock is
 *   supplied. Caller must not reclaim the same stale context twice.
 */

void newlib_reclaim_reent(NewlibReent *reent)

{
  MediusBigInt *next_cached_bigint;
  int bucket_index;
  NewlibCleanup cleanup;
  MediusBigInt *cached_bigint;
  MediusBigInt *cached_result;

  if (NEWLIB_GLOBAL_CONTEXT_POINTER != reent) {
    if (reent->mprec != (MediusMprec *)0x0) {
      if (reent->mprec->freelist != (MediusBigInt **)0x0) {
        bucket_index = 0;
        do {
          cached_bigint = reent->mprec->freelist[bucket_index];
          while (cached_bigint != (MediusBigInt *)0) {
            next_cached_bigint = cached_bigint->next;
            medius_newlib_free_r(reent,cached_bigint);
            cached_bigint = next_cached_bigint;
          }
          bucket_index++;
        } while (bucket_index != 32);
        medius_newlib_free_r(reent,reent->mprec->freelist);
      }
      cached_result = reent->mprec->result;
      if (cached_result != (MediusBigInt *)0x0) {
        medius_newlib_free_r(reent,cached_result);
      }
    }
    if (reent->emergency_buffer != (char *)0x0) {
      medius_newlib_free_r(reent,reent->emergency_buffer);
    }
    if (reent->mprec != (MediusMprec *)0x0) {
      medius_newlib_free_r(reent,reent->mprec);
    }
    if (reent->random_state != (void *)0x0) {
      medius_newlib_free_r(reent,reent->random_state);
    }
    if (reent->local_time_buffer != (void *)0x0) {
      medius_newlib_free_r(reent,reent->local_time_buffer);
    }
    if (reent->ascii_time_buffer != (char *)0x0) {
      medius_newlib_free_r(reent,reent->ascii_time_buffer);
    }
    if (reent->signal_buffer != (char *)0x0) {
      medius_newlib_free_r(reent,reent->signal_buffer);
    }
    if (reent->misc != (void *)0x0) {
      medius_newlib_free_r(reent,reent->misc);
    }
    if (reent->conversion_buffer != (char *)0x0) {
      medius_newlib_free_r(reent,reent->conversion_buffer);
    }
    cleanup = reent->cleanup;
    if (cleanup != (NewlibCleanup)0) {
      cleanup(reent);
    }
  }
  return;
}

