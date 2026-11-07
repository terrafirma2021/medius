/* Medius v3.4.7 device — C++ allocation, handlers and exception globals.
 * ABI identities checked against the pinned Xtensa libsupc++ object code;
 * exception wrappers checked against ESP-IDF v5.4.4 and actual native bodies.
 */
#include "../include/types.h"

/* C++ ABI reconstruction utilities: pure arithmetic inlined in both catches.
 * The two accepted classes encode GNU C++ primary/dependent exceptions.
 */
static __attribute__((always_inline)) inline bool cxx_is_gnu_exception(unsigned int low,unsigned int high)
{
    unsigned int low_difference = low + 0xbcd4d500U;
    unsigned int high_difference = high + 0xb8b1aabcU;
    if (low_difference < 0xbcd4d500U)
        ++high_difference;
    return high_difference == 0 && low_difference < 2U;
}

/* Native entry: 0x42017ce4. */
/* Original function-byte SHA-256:
 * 00cf14fcf040e8a719a853f06efcc0b10dd963d98b924d809ad2e33da4249a84. */
/* operator delete[](void*): forward unchanged to scalar operator delete.
 * No array-cookie read or element destruction; NULL handling is delegated.
 */
void cxx_operator_delete_array(void *memory)
{
    cxx_operator_delete(memory);
}

/* Native entry: 0x42017cf4. */
/* Original function-byte SHA-256:
 * 7aae53410a27b4191366f40bcbe0330bcb1c0e500216ba383ff17c128c309819. */
/* std::get_new_handler(): MEMW, one handler-slot WORD load, MEMW.
 * Return the cached pointer, possibly NULL. No call, exchange or setter here.
 */
CxxHandler cxx_get_new_handler(void)
{
    memw();
    CxxHandler handler = CXX_NEW_HANDLER;
    memw();
    return handler;
}

/* Native entry: 0x42017d28. */
/* Original function-byte SHA-256:
 * 00455e7439c050183f903eb5f41209e956cff8edcbc5f802ba7e8d9797c12a72. */
/* operator delete(void*): pass the pointer directly to free, including NULL.
 * No size argument is consumed and no object destructor is called here.
 */
void cxx_operator_delete(void *memory)
{
    free(memory);
}

/* Native entry: 0x42017d38. */
/* Original function-byte SHA-256:
 * 8061776b48bd087cf3ceac7207fc1a5047bcb08e5e49c5163f5a3670a3550bcf. */
/* Begin a C++ catch from the unwind-header pointer,48 bytes after the ABI
 * prefix. Obtain/allocate thread globals first, read class LOW then HIGH, then
 * cache the caught-stack top. Native GNU classes are0x474e5543432b2b00/01
 * (primary/dependent); all other classes are foreign.
 *
 * GNU: increment nonnegative handler count, or change a negative rethrow count
 * to1-count; preserve32-bit wrap. Decrement uncaught count, push this prefix
 * unless already top, then return its adjusted-pointer field. Foreign: require
 * the cached stack to be empty or terminate, then store its pseudo-prefix and
 * return NULL. No foreign-prefix fields are dereferenced. No pointer validity,
 * allocation-header extent, counter bounds or per-thread reentrancy check.
 */
/* The unwind_header argument is a live aligned CxxUnwindException. For GNU
 * classes its containing CxxException/CxxDependentException starts 48 bytes
 * earlier and must be live. A foreign object has no valid C++ prefix; only
 * its unwind class may be read through the saved pseudo-prefix. No allocation
 * extent or null/counter validation is added. The complete ABI header is now
 * 80 bytes; native field offsets and volatile WORD access order are unchanged. */
void *__cxa_begin_catch(CxxUnwindException *unwind_header)
{
    CxxEhGlobals *globals = __cxa_get_globals();
    unsigned int class_low = unwind_header->exception_class.low;
    unsigned int class_high = unwind_header->exception_class.high;
    CxxException *exception =
        (CxxException *)((unsigned int)unwind_header - 48U);
    CxxException *previous = globals->caught_exceptions;
    if (!cxx_is_gnu_exception(class_low,class_high)) {
        if (previous != 0)
            cxx_terminate();
        globals->caught_exceptions = exception;
        return 0;
    }
    int handlers = exception->handler_count;
    unsigned int updated = handlers < 0 ? 1U - (unsigned int)handlers : (unsigned int)handlers + 1U;
    exception->handler_count = (int)updated;
    globals->uncaught_exceptions = globals->uncaught_exceptions - 1U;
    if (previous != exception) {
        exception->next_exception = previous;
        globals->caught_exceptions = exception;
    }
    return exception->adjusted_pointer;
}

/* Native entry: 0x42017d90. */
/* Original function-byte SHA-256:
 * 542f0bcfa9ac1311a1b5345a72cee992263cf2d6d69e0abb9f3b797fe082da90. */
/* End the current catch using the FAST globals accessor; it may return NULL
 * when TLS was never populated, and this entry does not check that pointer.
 * An empty caught stack returns. Foreign exception pops to NULL then invokes
 * the linked unwind-delete wrapper, which ABORTS in this firmware.
 *
 * For GNU classes, a negative rethrow count increments toward0; reaching0
 * pops the saved next pointer, stores count0 and returns without deletion.
 * A nonnegative count decrements with32-bit wrap. Reaching0 pops next and calls
 * the aborting delete wrapper without storing count0. Old count0 becomes-1
 * and terminates before a store. Other counts are stored and return.
 */
/* The complete common C++ header is 80 bytes, with unwind_header at +48.
 * Foreign objects still have no usable C++ prefix fields. Preserve the native
 * order of stack-pop, handler-count stores and fatal delete calls; the linked
 * wrappers prevent the dead continuations from executing. */
void __cxa_end_catch(void)
{
    CxxEhGlobals *globals = __cxa_get_globals_fast();
    CxxException *exception = globals->caught_exceptions;
    if (exception == 0)
        return;
    unsigned int class_low = exception->unwind_header.exception_class.low;
    unsigned int class_high = exception->unwind_header.exception_class.high;
    if (!cxx_is_gnu_exception(class_low,class_high)) {
        globals->caught_exceptions = 0;
        cxx_unwind_delete_exception_abort(&exception->unwind_header);
    }
    int handlers = exception->handler_count;
    if (handlers < 0) {
        int updated = (int)((unsigned int)handlers + 1U);
        if (updated == 0)
            globals->caught_exceptions = exception->next_exception;
        exception->handler_count = updated;
        return;
    }
    int updated = (int)((unsigned int)handlers - 1U);
    if (updated == 0) {
        globals->caught_exceptions = exception->next_exception;
        cxx_unwind_delete_exception_abort(&exception->unwind_header);
    }
    if (updated == -1)
        cxx_terminate();
    exception->handler_count = updated;
}

/* Native entry: 0x42017df0. */
/* Original function-byte SHA-256:
 * e94d9db112b3adf8d5c7142d4e4dabe22eadec973c2e9a839bbba7e472d24bbf. */
/* TLS destructor for the8-byte C++ exception-globals allocation. NULL is a
 * no-op. On a nonempty caught stack, native code caches next then calls the
 * unwind-delete wrapper on prefix+48. That linked wrapper aborts, so later
 * iterations and free are unreachable on this firmware. An empty stack frees
 * the globals allocation. No class check, stack unlink or ownership repair.
 */
/* storage is borrowed by the callback until this routine frees the 8-byte
 * globals object on the empty-stack path. A nonempty stack never reaches
 * free after the linked nonreturning delete call; do not invoke the ABI
 * cleanup callback from the newly named header fields. */
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

/* Native entry: 0x42017e14. */
/* Original function-byte SHA-256:
 * 08b3c1888245510845e710974fdbea6d7d51c979c0d5c7b9998e4ef545c66704. */
/* Return process fallback exception globals when the startup TLS-enable BYTE
 * is0. Otherwise freshly read the pthread key and return pthread_getspecific,
 * even when NULL. No allocation, initialization, fallback-on-miss or lock.
 */
CxxEhGlobals *__cxa_get_globals_fast(void)
{
    if (CXX_EH_TLS_ENABLED != 0)
        return pthread_getspecific(CXX_EH_KEY);
    return CXX_EH_FALLBACK;
}

/* Native entry: 0x42017e34. */
/* Original function-byte SHA-256:
 * 06ae3949840198ac48227be9c5aecbf2177112442569b239bd8a360f18a581e2. */
/* Return the process fallback when TLS startup was unsuccessful, otherwise
 * return an existing thread value. A TLS miss allocates8 bytes, terminates
 * on malloc failure, and publishes the uninitialized allocation through a
 * freshly read key before zeroing caught pointer then uncaught count.
 * pthread_setspecific failure terminates without freeing the allocation.
 * The decompiler's retry loop after terminate is unreachable: terminate never
 * returns. No per-call lock or cleanup of earlier registration is supplied.
 */
CxxEhGlobals *__cxa_get_globals(void)
{
    if (CXX_EH_TLS_ENABLED == 0)
        return CXX_EH_FALLBACK;
    CxxEhGlobals *globals = pthread_getspecific(CXX_EH_KEY);
    if (globals != 0)
        return globals;
    globals = malloc(8U);
    if (globals == 0)
        cxx_terminate();
    if (pthread_setspecific(CXX_EH_KEY,globals) != 0)
        cxx_terminate();
    globals->caught_exceptions = 0;
    globals->uncaught_exceptions = 0;
    return globals;
}

/* Native entry: 0x42017e78. */
/* Original function-byte SHA-256:
 * 8de2e8ac00825368bbba72659d892dadd068689198c23a65a45f63ca6dcf880a. */
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

/* Native entry: 0x42017eb4. */
/* Original function-byte SHA-256:
 * de017ec55e6701797ed70d5013540b77d80594ff6412bc8f3938b9035d6f5f3b. */
/* std::get_terminate(): MEMW, one terminate-handler WORD load, MEMW.
 * Return that cached function pointer; no NULL substitution or invocation.
 */
CxxHandler cxx_get_terminate(void)
{
    memw();
    CxxHandler handler = CXX_TERMINATE_HANDLER;
    memw();
    return handler;
}

/* Native entry: 0x42017ec4. */
/* Original function-byte SHA-256:
 * 3f0f19a9937135235e6057207bc1d6c3940c8baf2e3efbe6dbf3e65b042bad8f. */
/* std::terminate(): load the current handler, pass it to the ABI termination
 * dispatcher and never return. The decompiler's RSIL/return-address return
 * was a false fallthrough into unrelated bytes after this native entry.
 */
void cxx_terminate(void)
{
    cxx_terminate_with_handler(cxx_get_terminate());
}

/* Native entry: 0x42017ed4. */
/* Original function-byte SHA-256:
 * 8d0bfd5b2c6a24182265be104e64fe8e3db7bb75f6acff207d03679ccff53720. */
/* operator new[](size_t): return scalar operator new(bytes), unchanged.
 * No cookie space, overflow check or element construction is added here.
 */
void *cxx_operator_new_array(size_t bytes)
{
    return cxx_operator_new(bytes);
}

/* Native entry: 0x42017ee4. */
/* Original function-byte SHA-256:
 * f419484c6ed966a077ee481051f31e32f1b0c0d5e029a3a54e8205bd0544d14c. */
/* operator new(size_t): malloc(max(bytes,1)); return a non-NULL allocation.
 * After failure load the current new-handler. If present, call it and retry
 * malloc indefinitely if it returns. No delay or attempt bound.
 *
 * No handler calls __wrap___cxa_allocate_exception (native passes4 in a10;
 * this linked zero-argument stub ignores it and ABORTS). Therefore bad_alloc
 * construction/throw never executes on this image. Native dead continuation
 * would store vtable0x3c0475bc, then call __wrap___cxa_throw with typeinfo
 *0x3c047450 and destructor0x42018058; that wrapper also aborts. Retain this
 * firmware-specific fatal path rather than inventing functioning C++ throws.
 */
/* bytes is the full unsigned 32-bit size_t. Returned storage follows malloc
 * ownership; no object is constructed here. The new-handler signature is
 * void(void), may be NULL, and is reread after each failed allocation. The
 * real fatal wrappers take no C arguments, regardless of dead caller slots. */
void *cxx_operator_new(size_t bytes)
{
    size_t allocation_size = bytes == 0 ? 1U : bytes;
    for (;;) {
        void *memory = malloc(allocation_size);
        if (memory != 0)
            return memory;
        CxxHandler handler = cxx_get_new_handler();
        if (handler == 0)
            cxx_allocate_exception_abort();
        handler();
    }
}

/* Native entry: 0x42018160. */
/* Original function-byte SHA-256:
 * 40164293391a9f20ecf20f1a50c63e2c611cc9462bf4b0239deb04436c96229b. */
/* operator delete(void*,size_t): size is ignored; forward pointer unchanged
 * to scalar operator delete. No size verification or destructor invocation.
 */
void cxx_operator_delete_sized(void *memory,size_t ignored_size)
{
    cxx_operator_delete(memory);
}

/* Native entry: 0x42018170. */
/* Original function-byte SHA-256:
 * e3d434aed37d98f3cad574660add520608dd5841dcccc7e8ae2162169be05957. */
/* ESP-IDF __wrap__Unwind_DeleteException: ignore the header and abort.
 * No exception cleanup callback, destructor or free occurs. Native ILL follows
 * the noreturn abort call as a terminal trap if its contract were violated.
 */
void cxx_unwind_delete_exception_abort(CxxUnwindException *ignored_header)
{
    abort();
}

/* Native entry: 0x42018188. */
/* Original function-byte SHA-256:
 * 77c7486ac9e8da0ace08dbc8b774600d9e66e10912c03b649fe3ec37e3526985. */
/* ESP-IDF __wrap___cxa_allocate_exception, linked when C++ exceptions are
 * disabled: zero-argument wrapper unconditionally aborts. Caller size slots
 * are ignored. Allocates nothing; native trailing ILL is a terminal trap.
 */
void cxx_allocate_exception_abort(void)
{
    abort();
}

/* Native entry: 0x42018194. */
/* Original function-byte SHA-256:
 * 5764846d5a9bf0c576dc5eddbdcb815734be890802733c95abc8913f924bee1e. */
/* ESP-IDF __wrap___cxa_throw: zero-argument wrapper unconditionally aborts.
 * Caller object/typeinfo/destructor argument slots are ignored; no unwind,
 * count update or catch dispatch. Native trailing ILL is a terminal trap.
 */
void cxx_throw_abort(void)
{
    abort();
}

/* Native entry: 0x4201817c. */
/* Original function-byte SHA-256:
 * 5a08e921a677c889ac48ab922a5b01ff5a520cc37b7c36034f865ccdd2844a9c. */
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

/* Native entry: 0x42017d04. */
/* Original function-byte SHA-256:
 * 9533b8dde1c6fed518e305d137372ad3aca4f580b802d9262ab26e13f5f5369f. */
/* operator new[](size_t, const std::nothrow_t&): the tag reference is
 * accepted but never read. On the normal route call cxx_operator_new_array
 * with bytes and return its pointer. The exception landing pad at native
 * 42017d15 receives the unwind pointer in A2, calls __cxa_begin_catch, then
 * __cxa_end_catch, and returns NULL. It is reached by original exception
 * metadata, not an ordinary branch or an extra C parameter.
 *
 * C++ behavior: try { return operator new[](bytes); }
 *               catch (...) { return nullptr; }
 * In this image allocation failure without a handler reaches an aborting
 * throw wrapper; this catch is not a guarantee of recoverable exhaustion.
 * No cookie, construction, size validation or additional cleanup here.
 *
 * Imported identity excluded the six catch instructions. They are restored
 * below; complete native extent 42017d04..42017d26 SHA-256:
 * af07025456521d2b1f0398744cd8640fcf0616b304b0cc15d64af220cb9a5bc2.
 * Assembly preserves both native routes and ABI. The original unwind-table
 * association is required to enter the catch label; this C listing is not
 * a replacement linked image or an independently built C++ exception table. */
void *cxx_operator_new_array_nothrow(size_t bytes,const void *nothrow_tag);
__asm__(
    ".section .text.FUN_42017d04,\"ax\",@progbits\n"
    ".p2align 2\n"
    ".global FUN_42017d04\n"
    ".type FUN_42017d04,@function\n"
    ".begin no-transform\n"
    "FUN_42017d04:\n"
    "entry a1,32\n"
    "or a10,a2,a2\n"
    "or a1,a1,a1\n"
    "call8 cxx_operator_new_array\n"
    "mov.n a2,a10\n"
    "j .Lnothrow_return\n"
    ".Lnothrow_catch:\n"
    "mov.n a10,a2\n"
    "or a1,a1,a1\n"
    "call8 __cxa_begin_catch\n"
    "or a1,a1,a1\n"
    "call8 __cxa_end_catch\n"
    "movi.n a2,0\n"
    ".Lnothrow_return:\n"
    "retw.n\n"
    ".end no-transform\n"
    ".size FUN_42017d04,.-FUN_42017d04\n"
    ".previous\n"
);

/* Native entry: 0x42017e98. */
/* Original function-byte SHA-256:
 * 650f55df37af9b2b1f6449acdf9a39cfe674f47f4336560893766b4cffc596d1. */
/* ABI terminate dispatcher. Call the supplied void(void) handler once;
 * a normal return immediately calls abort. If the handler throws, original
 * exception metadata enters native 42017ea4 with the unwind pointer in A2:
 * call __cxa_begin_catch, then abort, without __cxa_end_catch or unwinding
 * cleanup. A NULL/invalid handler is not checked. No lock or normal return.
 *
 * C++ behavior: try { handler(); abort(); } catch (...) { abort(); }
 * The explicit begin-catch instruction is ABI machinery, not an extra
 * user catch parameter or a second invocation of the handler.
 * Native assembly retains the exception-only route and lacks a C compiler
 * prologue. Original unwind metadata is needed to route thrown exceptions;
 * this listing does not create an independently linked exception table. */
void cxx_terminate_with_handler(CxxHandler handler);
__asm__(
    ".section .text.FUN_42017e98,\"ax\",@progbits\n"
    ".p2align 2\n"
    ".literal_position\n"
    ".literal .Lterminate_abort,0x4038f91c\n"
    ".global FUN_42017e98\n"
    ".type FUN_42017e98,@function\n"
    ".begin no-transform\n"
    "FUN_42017e98:\n"
    "entry a1,32\n"
    "callx8 a2\n"
    "l32r a8,.Lterminate_abort\n"
    "callx8 a8\n"
    ".Lterminate_catch:\n"
    "mov.n a10,a2\n"
    "or a1,a1,a1\n"
    "call8 __cxa_begin_catch\n"
    "l32r a8,.Lterminate_abort\n"
    "callx8 a8\n"
    ".end no-transform\n"
    ".size FUN_42017e98,.-FUN_42017e98\n"
    ".previous\n"
);
