/* Medius v3.4.7 host — rtos/thread_local.c.
 * Recovered C and native assembly, grouped for source navigation.
 * Original entry addresses, firmware-byte hashes and function comments follow.
 */

#include "../include/types.h"

/* Native entry: 0x42007474. */
/*
 * Medius v3.4.7 — host application; 0x42007474.
 *
 * Allocates a 12-byte key record, assigns one above the current head key under the key-list lock and stores its destructor. Returns zero or ENOMEM=12; key output must be valid.
 *
 * Calls: malloc, vPortExitCritical, xPortEnterCriticalTimeout.
 *
 * Called by: FUN_42015764.
 *
 * Original function-byte SHA-256:
 * a2de3a54a8c0a704e36ca7747fd0bf995d85c2a1d263f01db57860da09058f2d.
 */

/* Allocates a 12-byte key record, assigns one above the current head key under the key-list lock and stores its destructor. Returns zero or ENOMEM=12; key output must be valid.
   Reference: ESP-IDF v5.4.4 components/pthread/pthread_local_storage.c. */

/*
 * key: Required writable output for the allocated uint32 key.
 * destructor: Optional callback for per-task values on cleanup.
 * Returns: 0 on success, ENOMEM (12) on allocation failure.
 * Requirements/effects: Allocates a 12-byte key record. Under the key-list lock chooses 1 for an
 *   empty list or head key plus 1, then prepends. No key-wrap collision check; failure leaves
 *   output unchanged.
 */

int pthread_key_create(unsigned int *key,PthreadDestructor destructor)
{
    PthreadKeyEntry *new_key = malloc(sizeof(PthreadKeyEntry));
    if (new_key == 0)
        return 12;
    (void)xPortEnterCriticalTimeout(PTHREAD_KEY_REGISTRY_LOCK,-1);
    PthreadKeyEntry *previous_head = PTHREAD_REGISTERED_KEYS;
    unsigned int assigned_key = previous_head != 0 ? previous_head->key + 1U : 1U;
    *key = assigned_key;
    new_key->key = assigned_key;
    new_key->destructor = destructor;
    new_key->next = previous_head;
    PTHREAD_REGISTERED_KEYS = new_key;
    vPortExitCritical(PTHREAD_KEY_REGISTRY_LOCK);
    return 0;
}

