/* Medius v3.4.7 device — lists.c. */
#include "../include/types.h"

/* Native entry: 0x4038700c. */
/* Original function-byte SHA-256:
 * f2c6a1f6a9f87496a7532f6f1c8633acbb0718dd55741a40d9114cec7b93f6aa. */
/*
 * list: Required writable 20-byte list; must not currently own live items.
 * Returns no value. Publishes index=&end_marker, sentinel value UINT32_MAX,
 * sentinel next=self, sentinel previous=self, then count=0 in that order, with
 * the five native MEMWs. The sentinel is a 12-byte mini-item at list+8, sharing
 * only the first three fields with a full item; it has no owner/container.
 * No NULL/extent check, item initialization, unlinking, allocation or lock.
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

/* Native entry: 0x40387030. */
/* Original function-byte SHA-256:
 * bb0e9314324d02d6952385ddb880ded7e62faf7508207dca6262ea3972755c71. */
/*
 * item: Required writable 20-byte item; caller must have unlinked it already.
 * Returns no value. After one native MEMW, clears only its container WORD at+16.
 * Value, links and owner remain unchanged. This does not unlink a live item,
 * clear storage, validate ownership or take a lock.
 */
void vListInitialiseItem(RtosListItem *item)

{
  memw();
  item->container = (RtosList *)0x0;
  return;
}

/* Native entry: 0x4038703c. */
/* Original function-byte SHA-256:
 * 5e68d1cae3e2ee078367e83dcab77aa5ef4c6758fddf61581494033de0734c81. */
/*
 * list: Initialized live circular list with a valid current index.
 * item: Writable unlinked non-sentinel item; caller serializes all mutation.
 * Returns no value. Reads index once; stores item.next=index, reads index.previous
 * for item.previous, then rereads index.previous before repairing that node's
 * next link. Writes index.previous=item and item.container=list, then reads and
 * increments count modulo 2^32. Retains every native MEMW and repeated read.
 * Does not change item value/owner or list index, check duplicates/cycles/count
 * overflow, allocate storage, or acquire exclusion.
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
  unsigned int count = state->count;
  memw();
  state->count = count + 1U;
}

/* Native entry: 0x40387078. */
/* Original function-byte SHA-256:
 * ec8301153589e0a8eceaa2143a4cf0a9ee3c267a66fc9d26ca567a0d666c4b02. */
/*
 * list: Live initialized ascending-value circular list; sentinel value UINT32_MAX.
 * item: Writable unlinked non-sentinel item with its unsigned ordering value set.
 * Returns no value. Captures that value once. UINT32_MAX selects sentinel.previous
 * directly; other values traverse while next.value<=value, placing the new item
 * after existing equal values. Each iteration reloads predecessor.next and then
 * next.value with native MEMWs. A corrupt cycle/sentinel can loop indefinitely.
 *
 * Rereads predecessor.next for item.next, then rereads item.next before writing
 * successor.previous. Writes item.previous, predecessor.next and item.container;
 * reads/increments count modulo 2^32. Preserves all native repeated reads/MEMWs.
 * Does not update item owner/value or list index, reject a linked/duplicate item,
 * detect count overflow, allocate, or lock. Caller owns live links/exclusion.
 */
void vListInsert(RtosList *list,RtosListItem *item)
{
  volatile RtosList *state = list;
  volatile RtosListItem *entry = item;
  RtosListItem *predecessor;
  memw();
  unsigned int value = entry->value;
  if (value == 0xffffffffU) {
    memw();
    predecessor = state->end_marker.previous;
  } else {
    memw();
    RtosListItem *next = state->end_marker.next;
    predecessor = (RtosListItem *)&list->end_marker;
    memw();
    unsigned int next_value = ((volatile RtosListItem *)next)->value;
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
  unsigned int count = state->count;
  memw();
  state->count = count + 1U;
}

/* Native entry: 0x403870e4. */
/* Original function-byte SHA-256:
 * 3ffee2a065cd5a874bb4b5b1cbe4b46c60392888667e2acba4172c349207e162. */
/*
 * item: Live linked non-sentinel item with a valid container and neighbor links.
 * Returns the freshly reloaded list count after decrement, not a cached result.
 * Captures container first. Repairs next.previous using captured next/previous;
 * rereads item.previous and item.next before repairing previous.next. If the
 * current list index equals item, rereads item.previous and moves index there.
 * Clears item.container, reads/decrements count modulo 2^32, then rereads count
 * for return. Retains every native MEMW. Does not clear item links/owner/value,
 * validate count, reject detached/sentinel items, free storage or take a lock.
 * Caller supplies exclusive mutation and valid object lifetimes.
 */
unsigned int uxListRemove(RtosListItem *item)
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
  unsigned int count = state->count;
  memw();
  state->count = count - 1U;
  memw();
  return state->count;
}
