/* Medius v3.4.7 host — runtime/reentrancy.c.
 * Recovered C and native assembly, grouped for source navigation.
 * Original entry addresses, firmware-byte hashes and function comments follow.
 */

#include "../include/types.h"

/* Native entry: 0x40376c98. */
/*
 * Medius v3.4.7 — host application; 0x40376c98.
 *
 * Zeroes the 240-byte Newlib context and shares the global standard streams, cleanup function and stdio-initialized marker. This avoids per-task allocations of stdin/stdout/stderr.
 *
 * Calls: memset.
 *
 * Called by: prvInitialiseNewTask.
 *
 * Original function-byte SHA-256:
 * 4177e2cb1458cf54f5fc47aa7cd44d845e3cda6e13626d9fccbee16ee9d26ad2.
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

/* Native entry: 0x4038401c. */
/*
 * Medius v3.4.7 — host application; 0x4038401c.
 *
 * Return the current task Newlib reentrancy structure, or the global fallback.
 *
 * Calls: _xtos_set_intlevel (restores the saved interrupt-level bits).
 *
 * Called by: calloc, FUN_420071b8, FUN_42016208, FUN_42016220, FUN_42016518, FUN_4201654c,
 * vprintf, FUN_42016728, __errno, FUN_42016b6c, FUN_42016b84, FUN_42016b9c,
 * FUN_42016bb4, FUN_42016c00, FUN_42016c1c, FUN_4201cffc, FUN_42032cc8, FUN_42032ed4,
 * FUN_42032f7c, FUN_42032ff4, FUN_42033070, FUN_420330e4, medius_format_bounded_current_context.
 *
 * Original function-byte SHA-256:
 * 514fda24ad3672f927487c5649a26376fcb66271aeff17f0cd89e2edf4e275ea.
 */

/*
 * Return the current task Newlib reentrancy structure, or the global fallback.
 *
 * Raise this CPU's interrupt level to 3, select the CPU from PRID
 * bit 13 and snapshot its current-task pointer at 0x3fca76c8. Restore the
 * saved interrupt state. Return that task's TLS/reentrancy block at +0x5c,
 * or the global structure at 0x3fc9e388 if the task pointer was NULL.
 * The returned pointer is borrowed; no allocation or lifetime extension
 * occurs. Interrupt masking protects the local snapshot, not cross-core
 * access to arbitrary task memory. This is the ESP-IDF/Newlib accessor,
 * previously given the descriptive medius_current_reentrancy_context name.
 *
 * Evidence: ESP-IDF v5.4.4 freertos_tasks_c_additions.h __getreent;
 * matched inlined current-task lookup, fallback and Newlib consumers.
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

/* Native entry: 0x42016a98. */
/*
 * Medius v3.4.7 — host application; 0x42016a98.
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
 * 08ca70938918a62375e9090a2d0ac8911b4024ca1a027c8c84dc1f7693fed0e5.
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
