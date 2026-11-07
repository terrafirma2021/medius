/* Medius v3.4.7 host — runtime/syscall_facades.c.
 */

#include "../include/types.h"

/* Source reconstruction utilities; not additional native firmware entries. */
extern NewlibReent *facade_current_reent(void) __asm__("__getreent");

/* Native entry: 0x42016b5c. */
/*
 * Medius v3.4.7 — host application; 0x42016b5c.
 * Instruction-checked recovered C.
 * Original function-byte SHA-256:
 * 4a2ed1808f1093cb0be10bf888fd0b6c8048153a68244cd9c52f1ddce02e8124.
 */

/*
 * Obtain current reent once and return its address unchanged as the errno
 * pointer: errno is its signed 32-bit first member at offset 0. No dereference, errno
 * reset, independent NULL check, allocation or lock occurs. __getreent owns
 * task/fallback selection and the returned context remains borrowed.
 */
int *__errno(void)
{
    return (int *)facade_current_reent();
}

/* Native entry: 0x42016b9c. */
/*
 * Medius v3.4.7 — host application; 0x42016b9c.
 * Instruction-checked recovered C.
 * Original function-byte SHA-256:
 * f19d9a76ddf58d3216f68b1d7966eccaad4681d7c657d4772e77b9473a73c3b6.
 */

/*
 * Obtain current reent once, then forward that context, timeval and timezone
 * unchanged to the reviewed _gettimeofday_r implementation. Return its full
 * status word. Even a NULL timeval still performs the context lookup here;
 * the callee supplies its separate NULL/time sampling/lock behavior. No local
 * timezone access, timestamp conversion, errno write or extra lock is added.
 */
int gettimeofday(struct timeval *time,void *timezone)
{
    NewlibReent *reent = facade_current_reent();
    return _gettimeofday_r((struct _reent *)reent,time,timezone);
}
