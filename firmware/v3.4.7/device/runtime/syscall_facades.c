/* Medius v3.4.7 device — runtime/syscall_facades.c.
 */

#include "../include/types.h"

/* Source reconstruction utilities; not additional native firmware entries. */
extern NewlibReent *facade_current_reent(void) __asm__("__getreent");

/* Native entry: 0x42018ff0. */
/*
 * Medius v3.4.7 — device application; 0x42018ff0.
 * Instruction-checked recovered C.
 * Original function-byte SHA-256:
 * 283d7754daab8eb8f8422e4f3fa4395999638aaf6e28fe3f3ceebc5224ed1740.
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

/* Native entry: 0x42019030. */
/*
 * Medius v3.4.7 — device application; 0x42019030.
 * Instruction-checked recovered C.
 * Original function-byte SHA-256:
 * d054a35b5222ee99f3b9cea4b0a99864de481fea7a6845ea3d3d8e1c75f09485.
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
