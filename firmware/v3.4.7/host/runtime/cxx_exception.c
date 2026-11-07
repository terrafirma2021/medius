/* Medius v3.4.7 host: C++ exception TLS and disabled-exception fatal stubs. */
#include "../include/types.h"

/* Native entry: 0x42015740. */
/* Original function-byte SHA-256:
 * 5fbc268a1a4199088c5e0b7e677ac0cdd5b8f95c56ed6d271a8c6a728198d3af. */
/* TLS destructor for the C++ exception-globals allocation; this host body
 * accesses only its first WORD, represented by a prefix view. NULL is a
 * no-op. On a nonempty caught stack, native code caches next then calls the
 * unwind-delete wrapper on prefix+48. That linked wrapper aborts, so later
 * iterations and free are unreachable on this firmware. An empty stack frees
 * the globals allocation. No class check, stack unlink or ownership repair.
 */
void cxx_eh_globals_destroy(void *storage)
{
    if (storage == 0)
        return;
    CxxEhGlobals *globals = storage;
    CxxException *exception = globals->caught_exceptions;
    while (exception != 0) {
        CxxException *next = exception->next_exception;
        cxx_unwind_delete_exception_abort(&exception->unwind_header);
        exception = next;
    }
    free(globals);
}

/* Native entry: 0x42015764. */
/* Original function-byte SHA-256:
 * 6532c4a8faee8a72c006e152fb2f1e0bba4c3a1178b02924f521dd9deeea6e84. */
/* Startup constructor for C++ exception globals. Create a pthread key with
 * cxx_eh_globals_destroy as destructor, then store one BYTE:1 only on status0,
 * else0. Failure selects the shared fallback in both accessors; no log/retry,
 * key deletion, existing-key guard or status return. Does not zero fallback.
 */
void cxx_eh_globals_initialize(void)
{
    int status = pthread_key_create((unsigned int *)&CXX_EH_KEY,cxx_eh_globals_destroy);
    CXX_EH_TLS_ENABLED = status == 0;
}

/* Native entry: 0x42015784. */
/* Original function-byte SHA-256:
 * 376249a430e50ee0ff59e63916242b7f3a65affbb1b2e00cad8568e20f2f9788. */
/* ESP-IDF __wrap__Unwind_DeleteException: ignore the header and abort.
 * No exception cleanup callback, destructor or free occurs. Native ILL follows
 * the noreturn abort call as a terminal trap if its contract were violated.
 */
void cxx_unwind_delete_exception_abort(CxxUnwindException *ignored_header)
{
    abort();
}

/* Native entry: 0x42015790. */
/* Original function-byte SHA-256:
 * 43c14bf0e01d398fe04d8fc08f34e274ea11ac94fa6c26783f1261bca27d6823. */
/* Unconditionally enter the linked abort routine; no arguments, storage or
 * registers are inspected before it. The native trailing ILL traps if abort
 * violated its nonreturning contract. This entry performs no unwinding, cleanup
 * callback, allocation or recovery. Its descriptive name does not assert which
 * of the SDK's identical abort-wrapper symbols occupied this native address.
 */
void medius_cxx_fatal_stub(void)
{
    abort();
}
