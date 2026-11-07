/* Medius v3.4.7 device: NVS hash-block list lifetime. */
#include "../include/types.h"

/* Native entry: 0x42014b44. */
/* Original function-byte SHA-256:
 * 70b1bee2e9937423d6f13c065a860c50f3e7305179be9e51649ef7fa8adb0619. */
/* Unlink and free each hash block, following next captured before free.
 * Maintain previous/next links, head/tail and a wrapping word count. An empty
 * head returns without repairing a stale count/tail. Retain non-NULL previous
 * branches and cached next even if free changes the list. No block-data wipe,
 * count-underflow check or locking occurs. */
void nvs_hash_list_clear(NvsObjectList *list)
{
    volatile NvsObjectList *state = list;
    NvsHashBlockLinks *current = state->head;
    if (current == NULL)
        return;
    for (;;) {
        volatile NvsHashBlockLinks *block = current;
        NvsHashBlockLinks *previous = block->previous;
        NvsHashBlockLinks *next = block->next;
        if (previous != NULL)
            ((volatile NvsHashBlockLinks *)previous)->next = next;
        else
            state->head = next;
        unsigned int count = state->count;
        if (next != NULL) {
            ((volatile NvsHashBlockLinks *)next)->previous = previous;
            state->count = count - 1U;
            free(current);
            current = next;
        } else {
            state->tail = previous;
            state->count = count - 1U;
            free(current);
            return;
        }
    }
}

/* Native entry: 0x4202120c. */
/* Original function-byte SHA-256:
 * a4500f977586ab55e62e2962f938ea2801d4c2a539ea62706c33ab85d6b88b25. */
/* Construct an empty hash-block list with three word stores in order:
 * head, tail, count. No allocation, traversal or release of prior contents. */
void nvs_hash_list_construct(NvsObjectList *list)
{
    volatile NvsObjectList *state = list;
    state->head = NULL;
    state->tail = NULL;
    state->count = 0;
}

/* Native entry: 0x42014b7c. */
/* Original function-byte SHA-256:
 * 798323c1751b4b18d3ea079a9df3145b5b57ccfdf64c55ae1343ec41f721108e. */
/* Destroy a hash list by clearing its blocks. Do not free the list object. */
void nvs_hash_list_destroy(NvsObjectList *list)
{
    nvs_hash_list_clear(list);
}

/* Native entry: 0x42014b88. */
/* Original function-byte SHA-256:
 * 2e85e18643e2e24de2d095709e6dfa40b84e07fc8cc5f74e302255b3faeaaa6d. */
/* Append a packed identity hash/index to the last block if its count <=28;
 * increment that count before storing the slot word. Otherwise allocate128
 * bytes, initialize29 slot words to0x000000ff (index255, hash0), link a new block, then
 * store slot0/count1. Allocation failure returns0x101. The list count used
 * after allocation was sampled before malloc, while links are sampled after
 * it. Index narrows to a byte; hash retains its low24 bits. No deduplication,
 * slot reuse, list-consistency check or lock is provided. */
int nvs_hash_list_insert(NvsObjectList *list,const NvsItem *item,
    size_t entry_index)
{
    unsigned int hash = nvs_item_identity_crc32(item);
    volatile NvsObjectList *state = list;
    unsigned int block_count = state->count;
    unsigned int packed = (hash << 8) | (entry_index & 255U);
    if (block_count != 0) {
        volatile NvsHashBlock *tail = state->tail;
        unsigned int used = tail->count;
        if (used <= 28U) {
            tail->count = used + 1U;
            tail->slots[used].encoded = packed;
            return 0;
        }
    }
    volatile NvsHashBlock *created = malloc(128);
    if (created == NULL)
        return 0x101;
    for (unsigned int slot = 0; slot != 29U; ++slot)
        created->slots[slot].encoded = 0x000000ffU;
    NvsHashBlock *tail = state->tail;
    if (tail != NULL)
        ((volatile NvsHashBlock *)tail)->next = (NvsHashBlock *)created;
    created->previous = tail;
    void *head = state->head;
    created->next = NULL;
    state->tail = (NvsHashBlock *)created;
    if (head == NULL)
        state->head = (NvsHashBlock *)created;
    state->count = block_count + 1U;
    created->slots[0].encoded = packed;
    created->count = 1;
    return 0;
}

/* Native entry: 0x42014c04. */
/* Original function-byte SHA-256:
 * d637cb05eadd3e19b7c92f0fd48255361ba36ee73b70ca5eae00293512219292. */
/* Mark matching index bytes0xff, retaining each slot's hash bytes. The input
 * index is a full word; values >255 cannot match. Return true once a match
 * and another live slot are found, otherwise scan the whole block and free
 * it if no live slots remain. Empty blocks encountered before a match are
 * also removed. An input255 may match already-empty slots. Counts are not
 * bounded to29, nor decremented per slot; list count wraps on block removal.
 * Return false only after exhausting the list without a match. No lock. */
bool nvs_hash_list_erase(NvsObjectList *list,size_t entry_index)
{
    volatile NvsObjectList *state = list;
    volatile NvsHashBlock *block = state->head;
    while (block != NULL) {
        unsigned int count = block->count;
        bool found = false;
        bool have_entries = false;
        for (unsigned int slot = 0; slot != count; ++slot) {
            volatile NvsHashSlot *node = (volatile NvsHashSlot *)
                ((uintptr_t)block + 12U + 4U * slot);
            unsigned int stored_index = node->index;
            if (entry_index == stored_index) {
                node->index = 0xff;
                found = true;
            } else {
                have_entries = have_entries || stored_index != 0xff;
            }
            if (have_entries && found)
                return true;
        }
        if (have_entries) {
            block = block->next;
            if (found)
                return true;
            continue;
        }
        NvsHashBlock *previous = block->previous;
        NvsHashBlock *next = block->next;
        if (previous != NULL)
            ((volatile NvsHashBlock *)previous)->next = next;
        else
            state->head = next;
        unsigned int block_count = state->count;
        if (next != NULL)
            ((volatile NvsHashBlock *)next)->previous = previous;
        else
            state->tail = previous;
        state->count = block_count - 1U;
        free((void *)block);
        if (found)
            return true;
        block = next;
    }
    return false;
}

/* Native entry: 0x42014ca0. */
/* Original function-byte SHA-256:
 * 2f3a1b7f52bb0144fc8ef6bad8eb2180962cabf8facc97a9d7a01b317bb459ae. */
/* Return the first nonempty cached index >=start whose24-bit identity hash
 * matches item, or SIZE_MAX. Compare full-word start against index bytes.
 * For an eligible byte index, load the whole slot word before testing hash
 * and the empty0xff marker; retain the initially sampled index for return.
 * Each block count is sampled once and is unchecked against29. This is a
 * hash candidate lookup, not a key/type/value comparison. No mutation/lock. */
size_t nvs_hash_list_find(NvsObjectList *list,size_t start,
    const NvsItem *item)
{
    unsigned int hash = nvs_item_identity_crc32(item) & 0xffffffU;
    const volatile NvsObjectList *state = list;
    volatile NvsHashBlock *block = state->head;
    while (block != NULL) {
        unsigned int count = block->count;
        for (unsigned int slot = 0; slot != count; ++slot) {
            const volatile NvsHashSlot *node = (const volatile NvsHashSlot *)
                ((uintptr_t)block + 12U + 4U * slot);
            unsigned int index = node->index;
            if (index >= start) {
                unsigned int packed = node->encoded;
                if ((packed >> 8) == hash && index != 0xff)
                    return index;
            }
        }
        block = block->next;
    }
    return (size_t)-1;
}
