/* Medius v3.4.7 device — rtos/thread_local.c.
 * Recovered C and native assembly, grouped for source navigation.
 * Original entry addresses, firmware-byte hashes and function comments follow.
 */

#include "../include/types.h"

/* Native entry: 0x420078a8. */
/* Original function-byte SHA-256:
 * 21d67c1193738017dd85757872b38fcc3107537309bf3c3b6390761fb54c93d7. */
/* Drain and free a nonnull per-task value-list allocation and all its nodes.
 * Unlink the first value before looking up its key under the registry mux.
 * After unlock, read a matched record's destructor once and call it, if nonnull,
 * with the node's opaque value; then free the node and reread the live list head.
 * Preserve the post-unlock destructor read and unpinned registry-record lifetime.
 * A callback can append values, which this loop also drains. There is no fixed
 * destructor-pass limit, task-list lock, TLS-slot clearing or callback exception
 * recovery. Callback/list/key lifetimes and exclusive task-list use are external
 * requirements. Free only the node and final list allocation, not the value itself.
 */
void pthread_cleanup_value_list(PthreadValueList *list)
{
    volatile PthreadValueList *values = list;
    PthreadValueEntry *entry = values->first;
    while (entry != 0) {
        values->first = entry->next;
        unsigned int key = entry->key;
        (void)xPortEnterCriticalTimeout(PTHREAD_KEY_REGISTRY_LOCK,-1);
        PthreadKeyEntry *registered = PTHREAD_REGISTERED_KEYS;
        while (registered != 0 && registered->key != key)
            registered = registered->next;
        vPortExitCritical(PTHREAD_KEY_REGISTRY_LOCK);
        if (registered != 0) {
            /* The original code reads this record AFTER unlocking. Do not
             * move the lookup into the critical section or call it twice. */
            PthreadDestructor destructor = registered->destructor;
            if (destructor != 0)
                destructor(entry->value);
        }
        free(entry);
        entry = values->first;
    }
    free(list);
}

/* Native entry: 0x42007910. */
/* Original function-byte SHA-256:
 * 8e15bc649a77c9584c5a80c75b77f478bd06d099617020a5cc6625088bbf5edb. */
/* FreeRTOS TLS deletion adapter: index is unused; storage must be the live,
 * nonnull per-task value-list allocation. NULL asserts before cleanup. Delegate
 * the entire drain/free operation, including registered destructor calls outside
 * the key mux; return void afterward. No TLS-slot clearing or second ownership
 * check is supplied here. This entry retains its separate native identity even
 * though the compiler split the shared cleanup loop into another function.
 */
void pthread_cleanup_thread_specific_data_callback(int index,void *storage)

{
  if (storage == (void *)0x0) {
                    /* WARNING: Subroutine does not return */
    __assert_func((char *)0x0,0,(char *)0x0,(char *)0x0);
  }
  pthread_cleanup_value_list(storage);
  return;
}

/* Native entry: 0x4200792c. */
/* Original function-byte SHA-256:
 * 1c7accb1d675c4fa3dce7b4c98772ec594292ef8bbbfe8ac136ba3e3dea15cc4. */
/* Allocate/register a pthread key and its optional void(void*) destructor.
 * key is a required writable unsigned-WORD output, without a NULL guard.
 * Allocate a 12-byte record before entering the key mux; failure returns ENOMEM
 * (12) without touching output or registry. Under the mux, choose head.key+1
 * modulo 2^32, or 1 when empty. Store output, record key, destructor and next in
 * native order, then publish the new head and unlock. Return 0. No collision,
 * wrap or maximum-key check; allocation/registration do not create a task value
 * or invoke the destructor. Caller retains ownership of the callback code.
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

/* Native entry: 0x42007974. */
/* Original function-byte SHA-256:
 * f2461758e61ab10432a9a2a97226d81acbd138c006cc65b2ff24fc4291afc3ff. */
/* Read this task's TLS slot 0, then search its value list by unsigned key.
 * Return the first matching node's opaque value, or NULL for no list/match.
 * No global key-registration check, task-list lock, allocation, callback or
 * ownership transfer. The caller keeps the task's list and nodes live; a NULL
 * result does not distinguish an absent key from a stored NULL representation.
 */
void * pthread_getspecific(unsigned int key)

{
  PthreadValueList *value_list;
  PthreadValueEntry *entry;

  value_list = pvTaskGetThreadLocalStoragePointer((RtosTask *)0x0,0);
  if (value_list != (PthreadValueList *)0) {
    for (entry = value_list->first; entry != (PthreadValueEntry *)0; entry = entry->next) {
      if (key == entry->key) {
        return entry->value;
      }
    }
  }
  return (void *)0x0;
}

/* Native entry: 0x420079a0. */
/* Original function-byte SHA-256:
 * 7688813b38daa36edd23f1d592d05153900255a6ac62bf683f0d5d0ea331e187. */
/* Set this task's value for a registered unsigned key; value is borrowed.
 * Search the registry under its mux first; missing key unlocks and returns
 * ENOENT (2) without TLS access or allocation. The registration is not pinned
 * after unlock. Resolve TLS slot 0; if absent, calloc a 4-byte head and install
 * its cleanup callback even when value is NULL. Allocation failure returns 12.
 * Replace a matching nonnull value in place, or unlink/free its node for NULL.
 * Neither operation invokes a destructor or frees the old opaque value. Removal
 * of a non-head match rescans from the saved head to find its predecessor.
 * A missing key with nonnull value allocates a 12-byte node, rereads the list
 * head, stores key/value, then appends with next=NULL after scanning to the tail.
 * NULL with no existing node succeeds without node allocation. Keep an empty
 * installed head until cleanup; later node-allocation failure does not undo it.
 * Return 0 on success. No task-list mux, reference pinning, callback invocation
 * or automatic value lifetime extension; preserve native rereads/store order.
 */
int pthread_setspecific(unsigned int key,const void *value)

{
  PthreadValueList *value_list;
  PthreadValueEntry *predecessor;
  PthreadKeyHead registered_key;
  PthreadValueEntry *tail_cursor;
  PthreadValueEntry *tail;
  PthreadValueEntry *entry;
  PthreadValueEntry *matching_entry;

  (void)xPortEnterCriticalTimeout(PTHREAD_KEY_REGISTRY_LOCK,-1);
  registered_key = PTHREAD_REGISTERED_KEYS;
  while( true ) {
    if (registered_key == (PthreadKeyHead)0x0) {
      vPortExitCritical(PTHREAD_KEY_REGISTRY_LOCK);
      return 2;
    }
    if (key == registered_key->key) break;
    registered_key = registered_key->next;
  }
  vPortExitCritical(PTHREAD_KEY_REGISTRY_LOCK);
  value_list = pvTaskGetThreadLocalStoragePointer((RtosTask *)0x0,0);
  if (value_list == (PthreadValueList *)0) {
    value_list = calloc(1,sizeof(PthreadValueList));
    if (value_list == (PthreadValueList *)0) {
      return 0xc;
    }
    vTaskSetThreadLocalStoragePointerAndDelCallback
              ((RtosTask *)0x0,0,value_list,pthread_cleanup_thread_specific_data_callback);
  }
  entry = value_list->first;
  if (entry != (PthreadValueEntry *)0) {
    matching_entry = entry;
    do {
      if (key == matching_entry->key) {
        if (value != (void *)0x0) {
          matching_entry->value = (void *)value;
          return 0;
        }
        PthreadValueEntry *successor = matching_entry->next;
        if (entry == matching_entry) {
          value_list->first = successor;
        }
        else {
          do {
            predecessor = entry;
            entry = predecessor->next;
          } while (entry != matching_entry);
          predecessor->next = successor;
        }
        free(matching_entry);
        return 0;
      }
      matching_entry = matching_entry->next;
    } while (matching_entry != (PthreadValueEntry *)0);
  }
  if (value != (void *)0x0) {
    entry = malloc(sizeof(PthreadValueEntry));
    if (entry == (PthreadValueEntry *)0) {
      return 0xc;
    }
    tail_cursor = value_list->first;
    entry->key = key;
    entry->value = (void *)value;
    if (tail_cursor == 0) {
      entry->next = (PthreadValueEntry *)0;
      value_list->first = entry;
    }
    else {
      do {
        tail = tail_cursor;
        tail_cursor = tail->next;
      } while (tail_cursor != 0);
      entry->next = (PthreadValueEntry *)0;
      tail->next = entry;
    }
  }
  return 0;
}

