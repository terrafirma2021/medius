/* Medius v3.4.7 host — rtos/lists.c.
 * Recovered C and native assembly, grouped for source navigation.
 * Original entry addresses, firmware-byte hashes and function comments follow.
 */

#include "../include/types.h"

/* Native entry: 0x403822ec. */
/*
 * Medius v3.4.7 — host application; 0x403822ec.
 *
 * Initializes an empty FreeRTOS list with a UINT32_MAX end marker.
 *
 * Called by: FUN_403812e0, prvAddNewTaskToReadyList.
 *
 * Original function-byte SHA-256:
 * f2c6a1f6a9f87496a7532f6f1c8633acbb0718dd55741a40d9114cec7b93f6aa.
 */

/* Initializes an empty FreeRTOS list with a UINT32_MAX end marker.
   SDK match: ESP-IDF v5.4.4 components/freertos/FreeRTOS-Kernel/list.c.
   Recovered types/control flow retain the original function bytes and non-returning assertion paths. */

/*
 * list: Writable list storage; must not currently own live items.
 * Returns: Nothing.
 * Requirements/effects: Initializes count, iteration cursor and circular sentinel links; does not
 *   initialize any separate task items or acquire a lock.
 */

void vListInitialise(RtosList *list)

{
  RtosMiniListItem *end_marker;

  end_marker = &list->end_marker;
  memw();
  list->index = (RtosListItem *)end_marker;
  memw();
  (list->end_marker).value = 0xffffffff;
  memw();
  (list->end_marker).next = (RtosListItem *)end_marker;
  memw();
  (list->end_marker).previous = (RtosListItem *)end_marker;
  memw();
  list->count = 0;
  return;
}

/* Native entry: 0x40382310. */
/*
 * Medius v3.4.7 — host application; 0x40382310.
 *
 * Marks a FreeRTOS list item as not belonging to a list.
 *
 * Called by: prvInitialiseNewTask.
 *
 * Original function-byte SHA-256:
 * bb0e9314324d02d6952385ddb880ded7e62faf7508207dca6262ea3972755c71.
 */

/* Marks a FreeRTOS list item as not belonging to a list.
   SDK match: ESP-IDF v5.4.4 components/freertos/FreeRTOS-Kernel/list.c.
   Recovered types/control flow retain the original function bytes and non-returning assertion paths. */

/*
 * item: Writable list item; must not still be linked in a list.
 * Returns: Nothing.
 * Requirements/effects: Clears only container. Other item fields retain their prior values; this
 *   operation does not unlink a live item.
 */

void vListInitialiseItem(RtosListItem *item)

{
  memw();
  item->container = (RtosList *)0x0;
  return;
}

/* Native entry: 0x4038231c. */
/*
 * Medius v3.4.7 — host application; 0x4038231c.
 *
 * Inserts an item immediately before the list index and increments the list count.
 *
 * Called by: vTaskDelete.
 *
 * Original function-byte SHA-256:
 * 5e68d1cae3e2ee078367e83dcab77aa5ef4c6758fddf61581494033de0734c81.
 */

/* Inserts an item immediately before the list index and increments the list count.
   SDK match: ESP-IDF v5.4.4 components/freertos/FreeRTOS-Kernel/list.c.
   Recovered types/control flow retain the original function bytes and non-returning assertion paths. */

/*
 * list: Initialized circular list with a valid iteration index.
 * item: Unlinked writable item to insert immediately before the current iteration index.
 * Returns: Nothing.
 * Requirements/effects: Sets both links and container, repairs adjacent links and increments
 *   count. Caller provides exclusion from concurrent list mutation.
 */

void vListInsertEnd(RtosList *list,RtosListItem *item)
{
  volatile RtosList *state = list;
  volatile RtosListItem *entry = item;
  memw();
  RtosListItem *index = state->index;
  memw();
  entry->next = index;
  memw();
  RtosListItem *previous = ((volatile RtosListItem *)index)->previous;
  memw();
  entry->previous = previous;
  memw();
  previous = ((volatile RtosListItem *)index)->previous;
  memw();
  ((volatile RtosListItem *)previous)->next = item;
  memw();
  ((volatile RtosListItem *)index)->previous = item;
  memw();
  entry->container = list;
  memw();
  uint count = state->count;
  memw();
  state->count = count + 1U;
}

/* Native entry: 0x40382358. */
/*
 * Medius v3.4.7 — host application; 0x40382358.
 *
 * Inserts an item in ascending value order, with a special UINT32_MAX end-marker case.
 *
 * Called by: prvAddCurrentTaskToDelayedList, vTaskPlaceOnEventList.
 *
 * Original function-byte SHA-256:
 * ec8301153589e0a8eceaa2143a4cf0a9ee3c267a66fc9d26ca567a0d666c4b02.
 */

/* Inserts an item in ascending value order, with a special UINT32_MAX end-marker case.
   SDK match: ESP-IDF v5.4.4 components/freertos/FreeRTOS-Kernel/list.c.
   Recovered types/control flow retain the original function bytes and non-returning assertion paths. */

/*
 * list: Initialized ascending-value circular list.
 * item: Unlinked writable item with its ordering value already initialized.
 * Returns: Nothing.
 * Requirements/effects: Equal-valued items are traversed before insertion, preserving arrival
 *   order. UINT32_MAX is inserted directly before the sentinel to avoid an endless sentinel
 *   comparison. Caller serializes mutation.
 */

void vListInsert(RtosList *list,RtosListItem *item)
{
  volatile RtosList *state = list;
  volatile RtosListItem *entry = item;
  RtosListItem *predecessor;
  memw();
  uint value = entry->value;
  if (value == 0xffffffffU) {
    memw();
    predecessor = state->end_marker.previous;
  } else {
    memw();
    RtosListItem *next = state->end_marker.next;
    predecessor = (RtosListItem *)&list->end_marker;
    memw();
    uint next_value = ((volatile RtosListItem *)next)->value;
    while (next_value <= value) {
      memw();
      predecessor = ((volatile RtosListItem *)predecessor)->next;
      memw();
      next = ((volatile RtosListItem *)predecessor)->next;
      memw();
      next_value = ((volatile RtosListItem *)next)->value;
    }
  }
  memw();
  RtosListItem *successor = ((volatile RtosListItem *)predecessor)->next;
  memw();
  entry->next = successor;
  memw();
  successor = entry->next;
  memw();
  ((volatile RtosListItem *)successor)->previous = item;
  memw();
  entry->previous = predecessor;
  memw();
  ((volatile RtosListItem *)predecessor)->next = item;
  memw();
  entry->container = list;
  memw();
  uint count = state->count;
  memw();
  state->count = count + 1U;
}

/* Native entry: 0x403823c4. */
/*
 * Medius v3.4.7 — host application; 0x403823c4.
 *
 * Unlinks an item, adjusts the owning list index, clears its container and returns the remaining count.
 *
 * Called by: prvAddCurrentTaskToDelayedList, prvIdleTask, vTaskDelete, vTaskPrioritySet, xTaskPriorityInherit, xTaskPriorityDisinherit,
 * vTaskPriorityDisinheritAfterTimeout.
 *
 * Original function-byte SHA-256:
 * 3ffee2a065cd5a874bb4b5b1cbe4b46c60392888667e2acba4172c349207e162.
 */

/* Unlinks an item, adjusts the owning list index, clears its container and returns the remaining count.
   SDK match: ESP-IDF v5.4.4 components/freertos/FreeRTOS-Kernel/list.c.
   Recovered types/control flow retain the original function bytes and non-returning assertion paths. */

/*
 * item: Linked non-sentinel item with valid container and neighboring links.
 * Returns: Owning list count after decrement.
 * Requirements/effects: Unlinks the item, moves the iteration cursor back if necessary and clears
 *   container. Does not clear item links or free storage; caller serializes mutation.
 */

uint uxListRemove(RtosListItem *item)
{
  volatile RtosListItem *entry = item;
  memw();
  RtosList *list = entry->container;
  volatile RtosList *state = list;
  memw();
  RtosListItem *next = entry->next;
  memw();
  RtosListItem *previous = entry->previous;
  memw();
  ((volatile RtosListItem *)next)->previous = previous;
  memw();
  previous = entry->previous;
  memw();
  next = entry->next;
  memw();
  ((volatile RtosListItem *)previous)->next = next;
  memw();
  RtosListItem *index = state->index;
  if (index == item) {
    memw();
    previous = entry->previous;
    memw();
    state->index = previous;
  }
  memw();
  entry->container = 0;
  memw();
  uint count = state->count;
  memw();
  state->count = count - 1U;
  memw();
  return state->count;
}

