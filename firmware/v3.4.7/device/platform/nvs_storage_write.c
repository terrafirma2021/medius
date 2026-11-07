/* Medius v3.4.7 device: NVS replacement writes and multi-page blobs. */
#include "../include/types.h"

/* Inline reconstruction utilities: repeated inlined page searches in the
 * native bodies. No separate native function or extra review is represented.
 * All nonzero find statuses advance the list; each page starts at entry zero. */
static __inline__ __attribute__((always_inline)) NvsPage *
nvs_storage_find_item_page(NvsPage *first,unsigned int namespace_index,
    unsigned int type,const char *key,volatile size_t *position,
    NvsItem *item,unsigned int chunk_index,unsigned int version_offset)
{
    volatile NvsPage *page = first;
    while (page != NULL) {
        *position = 0;
        if (nvs_page_find_item((NvsPage *)page,namespace_index,
                type,key,(size_t *)position,item,chunk_index,version_offset) == 0)
            return (NvsPage *)page;
        page = page->next;
    }
    return NULL;
}

/* Native entry: 0x42013028. */
/* Original function-byte SHA-256:
 * bb3ca3229e27ee22e51b9cc65adae1f137dc8d07254f72a205ad1dd11724669e. */
/* Erase a blob index, then its chunks. Namespace and version retain their
 * full incoming word widths. An unsupported version can erase the index
 * before returning success. Version 0xff also removes a second index and
 * scans all matching chunks, using each returned span to advance the cursor.
 * Index/chunk lookup ignores every nonzero find status; the final sweep
 * advances only on NOT_FOUND and propagates other errors. Erasure is partial
 * on failure; this function supplies no state gate, rollback or locking. */
int nvs_storage_erase_multi_page_blob(NvsStorageView *storage,
    unsigned int namespace_index,const char *key,unsigned int chunk_start)
{
    const volatile NvsStorageView *state = storage;
    NvsItem item;
    const volatile NvsItem *match = &item;
    volatile size_t position;
    NvsPage *page = nvs_storage_find_item_page(state->pages.head,namespace_index,
        NVS_ITEM_TYPE_BLOB_INDEX,key,&position,&item,NVS_ITEM_CHUNK_ANY,chunk_start);
    if (page == NULL)
        return 0x1102;
    size_t found_position = position;
    unsigned int chunk_count = match->blob_index.chunk_count;
    int result = nvs_page_erase_entry_and_span(page,found_position);
    if (result != 0)
        return result;

    if (chunk_start != NVS_ITEM_VERSION_ANY) {
        if (chunk_start != NVS_BLOB_VERSION_0_OFFSET && chunk_start != NVS_BLOB_VERSION_1_OFFSET)
            return 0;
        unsigned int limit = chunk_count;
        if (chunk_start == NVS_BLOB_VERSION_1_OFFSET)
            limit = (chunk_count - NVS_BLOB_VERSION_1_OFFSET) & 255U;
        if (chunk_start >= limit)
            return 0;
        unsigned int chunk = chunk_start;
        do {
            page = nvs_storage_find_item_page(state->pages.head,namespace_index,NVS_ITEM_TYPE_BLOB_DATA,key,
                &position,&item,chunk,NVS_ITEM_VERSION_ANY);
            if (page == NULL)
                return 0x1102;
            found_position = position;
            result = nvs_page_erase_entry_and_span(page,found_position);
            if (result != 0)
                return result;
            ++chunk;
        } while ((chunk & 255U) < limit);
        return 0;
    }

    NvsPage *second_index_head = state->pages.head;
    if (second_index_head == NULL)
        return 0;
    page = nvs_storage_find_item_page(second_index_head,namespace_index,NVS_ITEM_TYPE_BLOB_INDEX,key,
        &position,&item,NVS_ITEM_CHUNK_ANY,NVS_ITEM_VERSION_ANY);
    if (page != NULL) {
        found_position = position;
        result = nvs_page_erase_entry_and_span(page,found_position);
        if (result != 0)
            return result;
    }
    volatile NvsPage *scan = state->pages.head;
    while (scan != NULL) {
        position = 0;
        for (;;) {
            result = nvs_page_find_item((NvsPage *)scan,
                namespace_index,NVS_ITEM_TYPE_BLOB_DATA,key,(size_t *)&position,&item,NVS_ITEM_CHUNK_ANY,NVS_ITEM_VERSION_ANY);
            if (result == 0x1102)
                break;
            if (result != 0)
                return result;
            found_position = position;
            result = nvs_page_erase_entry_and_span(
                (NvsPage *)scan,found_position);
            /* Native reads and advances even when the erase failed. */
            size_t previous_position = position;
            unsigned int span = match->span;
            size_t next_position = previous_position + span;
            position = next_position;
            if (result != 0)
                return result;
            if (next_position >= NVS_PAGE_ENTRY_COUNT)
                break;
        }
        scan = scan->next;
    }
    return 0;
}

/* Native entry: 0x42013724. */
/* Original function-byte SHA-256:
 * 9fcb8c00e12c469c5521ad3559efce83f4185cf6335bb6afa2571fb08cf45315. */
/* Split a blob into page-tail chunks, followed by an eight-byte index.
 * Namespace and starting chunk narrow to bytes; maximum size is 4000 times
 * min(unsigned(managed_pages-1),127), including the zero-page underflow.
 * Track successfully written chunks in allocated list nodes for rollback.
 * PAGE_FULL returns immediately without rollback/freeing; allocation failure
 * cannot roll back the just-written untracked chunk. Rollback numbers chunks
 * from zero even when the requested version starts at 0x80, ignoring errors.
 * No active-state gate, independent lock or atomic replacement is supplied. */
int nvs_storage_write_multi_page_blob(NvsStorageView *storage,
    unsigned int namespace_index,const char *key,const void *value,size_t size,
    unsigned int chunk_start)
{
    const volatile NvsStorageView *state = storage;
    unsigned int maximum_pages = state->managed_page_count - 1U;
    if (maximum_pages > NVS_ITEM_CHUNK_NUMBER_MASK)
        maximum_pages = NVS_ITEM_CHUNK_NUMBER_MASK;
    if (size > maximum_pages * NVS_BLOB_CHUNK_MAX_SIZE)
        return 0x110e;
    namespace_index &= 255U;
    chunk_start &= 255U;
    NvsUsedPage *head = NULL;
    NvsUsedPage *tail = NULL;
    size_t offset = 0;
    size_t remaining = size;
    unsigned int chunk_count = 0;
    int result;

    for (;;) {
        NvsPage *page = state->pages.tail;
        unsigned int room = nvs_page_get_variable_tailroom(page);
        if (chunk_count == 0 &&
            !((room >= size && (room | size) != 0) || (room < size && room >= NVS_BLOB_CHUNK_MAX_SIZE / 10U))) {
            if (((volatile NvsPage *)page)->state != NVS_PAGE_STATE_FULL) {
                result = nvs_page_mark_full(page);
                if (result != 0)
                    return result;
            }
            result = nvs_page_manager_request_new_page(&storage->page_manager);
            if (result != 0)
                return result;
            page = state->pages.tail;
            if (nvs_page_get_variable_tailroom(page) == room)
                return 0x1105;
            /* Native samples tail/tailroom again before testing this gate. */
            continue;
        }
        if (room == 0) {
            result = 0x1105;
            goto rollback;
        }
        size_t chunk_size = remaining < room ? remaining : room;
        unsigned int chunk_index = (chunk_start + chunk_count) & 255U;
        ++chunk_count;
        result = nvs_page_write_item(page,namespace_index,NVS_ITEM_TYPE_BLOB_DATA,key,
            (const void *)((uintptr_t)value + offset),chunk_size,chunk_index);
        remaining -= chunk_size;
        chunk_count &= 255U;
        if (result == 0x110a)
            return result;
        if (result != 0)
            goto rollback;

        volatile NvsUsedPage *created = malloc(sizeof(NvsUsedPage));
        if (created == NULL) {
            result = 0x101;
            goto rollback;
        }
        created->page = page;
        if (tail != NULL)
            ((volatile NvsUsedPage *)tail)->next = (NvsUsedPage *)created;
        created->next = NULL;
        if (head == NULL)
            head = (NvsUsedPage *)created;
        created->previous = tail;
        tail = (NvsUsedPage *)created;

        if (remaining == 0 && room - chunk_size >= NVS_PAGE_ENTRY_SIZE)
            break;
        if (((volatile NvsPage *)page)->state != NVS_PAGE_STATE_FULL) {
            result = nvs_page_mark_full(page);
            if (result != 0)
                goto rollback;
        }
        result = nvs_page_manager_request_new_page(&storage->page_manager);
        if (result != 0)
            goto rollback;
        offset += chunk_size;
        if (remaining == 0)
            break;
    }

    NvsPage *index_page = state->pages.tail;
    volatile NvsBlobIndexPayload index;
    index.data_size = size;
    index.reserved = 0xffff;
    index.count_and_start = (unsigned short)(chunk_count | (chunk_start << 8));
    result = nvs_page_write_item(index_page,namespace_index,NVS_ITEM_TYPE_BLOB_INDEX,key,
        (const void *)&index,sizeof(index),NVS_ITEM_CHUNK_ANY);
    if (result == 0x110a)
        return result;
    if (result == 0)
        goto free_nodes;

rollback:
    if (head == NULL)
        return result;
    unsigned int rollback_chunk = 0;
    volatile NvsUsedPage *used = head;
    do {
        (void)nvs_page_erase_item(used->page,namespace_index,NVS_ITEM_TYPE_BLOB_DATA,key,
            rollback_chunk & 255U,NVS_ITEM_VERSION_ANY);
        used = used->next;
        ++rollback_chunk;
    } while (used != NULL);

free_nodes:
    /* Normally previous is NULL as each head is removed. Retain the native
     * non-NULL branch too: it frees the node without advancing the cursor. */
    for (;;) {
        volatile NvsUsedPage *current = head;
        NvsUsedPage *previous = current->previous;
        NvsUsedPage *next = current->next;
        if (previous != NULL) {
            ((volatile NvsUsedPage *)previous)->next = next;
            if (next != NULL)
                ((volatile NvsUsedPage *)next)->previous = previous;
            free(head);
            continue;
        }
        if (next != NULL) {
            ((volatile NvsUsedPage *)next)->previous = NULL;
            free(head);
            head = next;
            continue;
        }
        free(head);
        return result;
    }
}

/* Native entry: 0x4201395c. */
/* Original function-byte SHA-256:
 * 3a3e75bb4347f9425791e6883148c4a9b0cf7a72525bc7b72ad09493375a390f. */
/* Read indexed blob chunks into successive output offsets. Namespace narrows
 * to a byte; index length must equal size or return -1. Chunk searches narrow
 * the chunk number, but the returned byte is checked against the full running
 * number. Re-read chunk length after the page reader before advancing output.
 * Missing/oversized chunks trigger best-effort erasure only if storage is
 * active. Then a final byte-count mismatch overrides that error with -1.
 * Page-reader errors return directly. Partial output and cleanup effects stay. */
int nvs_storage_read_multi_page_blob(NvsStorageView *storage,
    unsigned int namespace_index,const char *key,void *output,size_t size)
{
    const volatile NvsStorageView *state = storage;
    NvsItem item;
    const volatile NvsItem *match = &item;
    volatile size_t position;
    namespace_index &= 255U;
    NvsPage *page = nvs_storage_find_item_page(state->pages.head,namespace_index,
        NVS_ITEM_TYPE_BLOB_INDEX,key,&position,&item,NVS_ITEM_CHUNK_ANY,NVS_ITEM_VERSION_ANY);
    if (page == NULL)
        return 0x1102;
    unsigned int indexed_size = match->blob_index.data_size;
    unsigned int chunk_count = match->blob_index.chunk_count;
    unsigned int chunk = match->blob_index.chunk_start;
    if (indexed_size != size)
        return -1;
    unsigned int end = chunk + chunk_count;
    size_t offset = 0;
    int result = 0;
    if (chunk_count == 0)
        goto finished;
    do {
        page = nvs_storage_find_item_page(state->pages.head,namespace_index,NVS_ITEM_TYPE_BLOB_DATA,key,
            &position,&item,chunk & 255U,NVS_ITEM_VERSION_ANY);
        if (page == NULL) {
            result = 0x1102;
            goto damaged_blob;
        }
        unsigned int chunk_size = match->variable.data_size;
        size_t found_position = position;
        if (chunk_size > size - offset) {
            result = 0x110c;
            goto damaged_blob;
        }
        result = nvs_page_read_variable_data(page,&item,found_position,
            (void *)((uintptr_t)output + offset));
        if (result != 0)
            return result;
        if (match->chunk_index != chunk)
            return -1;
        offset += match->variable.data_size;
        ++chunk;
    } while (chunk != end);
    goto finished;

damaged_blob:
    if (state->storage_state == NVS_STORAGE_STATE_ACTIVE)
        (void)nvs_storage_erase_multi_page_blob(storage,namespace_index,key,NVS_ITEM_VERSION_ANY);
finished:
    return offset == size ? result : -1;
}

/* Native entry: 0x42013a90. */
/* Original function-byte SHA-256:
 * dee6d75924ab31f6763a8cc945debf3536a4113523373a63d894410bfe483eba. */
/* Compare an indexed blob against value/size without erasing it. A length or
 * CRC difference returns CONTENT_DIFFERS (0x1118). Native CRC checks use the
 * start of value for EVERY chunk; page comparison uses value plus the running
 * offset. Retain that discrepancy. Re-read chunk length after CRC/comparison.
 * Missing chunks pass through the final byte-count test, which can return -1
 * instead of NOT_FOUND. Page comparison errors return directly. Namespace is
 * a byte; running chunk/end arithmetic remains 32-bit. No local state gate. */
int nvs_storage_compare_multi_page_blob(NvsStorageView *storage,
    unsigned int namespace_index,const char *key,const void *value,size_t size)
{
    const volatile NvsStorageView *state = storage;
    NvsItem item;
    const volatile NvsItem *match = &item;
    volatile size_t position;
    namespace_index &= 255U;
    NvsPage *page = nvs_storage_find_item_page(state->pages.head,namespace_index,
        NVS_ITEM_TYPE_BLOB_INDEX,key,&position,&item,NVS_ITEM_CHUNK_ANY,NVS_ITEM_VERSION_ANY);
    if (page == NULL)
        return 0x1102;
    if (match->blob_index.data_size != size)
        return 0x1118;
    unsigned int chunk_count = match->blob_index.chunk_count;
    size_t offset = 0;
    int result = 0;
    if (chunk_count == 0)
        goto finished;
    unsigned int chunk = match->blob_index.chunk_start;
    unsigned int end = chunk + chunk_count;
    do {
        page = nvs_storage_find_item_page(state->pages.head,namespace_index,NVS_ITEM_TYPE_BLOB_DATA,key,
            &position,&item,chunk & 255U,NVS_ITEM_VERSION_ANY);
        if (page == NULL) {
            result = 0x1102;
            break;
        }
        unsigned int chunk_size = match->variable.data_size;
        if (chunk_size > size - offset)
            return 0x1118;
        unsigned int crc = nvs_crc32_data(value,chunk_size,NULL);
        if (crc != match->variable.data_crc32)
            return 0x1118;
        chunk_size = match->variable.data_size;
        result = nvs_page_compare_item(page,namespace_index,NVS_ITEM_TYPE_BLOB_DATA,key,
            (const void *)((uintptr_t)value + offset),chunk_size,chunk & 255U,NVS_ITEM_VERSION_ANY);
        if (result != 0)
            return result;
        if (match->chunk_index != chunk)
            return -1;
        offset += match->variable.data_size;
        ++chunk;
    } while (chunk != end);
finished:
    return offset == size ? result : -1;
}

/* Native entry: 0x42013bb4. */
/* Original function-byte SHA-256:
 * 9ff702e6d0fa2cb3204bc39598493c1a45ec3a1968ac7abd1cfc30df955e0c90. */
/* Replace an NVS item in active storage. Namespace/type narrow to bytes.
 * An equal existing value returns success without writing. Blob replacements
 * alternate chunk versions 0/0x80; other writes retry once on a new page after
 * PAGE_FULL, translating a second PAGE_FULL to NOT_ENOUGH_SPACE (0x1105).
 * Write the new value before removing the old one. Sequence/state checks find
 * an old entry relocated by page management. Removal failure leaves the new
 * write in place; FLASH_OP_FAIL (0x6001) becomes REMOVE_FAILED (0x1108).
 * Search errors are ignored while advancing pages. No independent lock or
 * read-only validation is added at this storage layer. */
int nvs_storage_write_item(NvsStorageView *storage,
    unsigned int namespace_index,unsigned int type,const char *key,
    const void *value,size_t size)
{
    const volatile NvsStorageView *state = storage;
    if (state->storage_state != NVS_STORAGE_STATE_ACTIVE)
        return 0x1101;
    namespace_index &= 255U;
    type &= 255U;
    volatile unsigned int old_sequence = 0xffffffffU;
    NvsItem old_item;
    const volatile NvsItem *old = &old_item;
    volatile size_t position;
    size_t old_position = 0;
    unsigned int next_version = 0;
    int result;
    NvsPage *initial_head = state->pages.head;
    NvsPage *old_page = NULL;
    if (initial_head != NULL) {
        old_page = nvs_storage_find_item_page(initial_head,namespace_index,
            type == NVS_ITEM_TYPE_BLOB ? NVS_ITEM_TYPE_BLOB_INDEX : type,key,&position,&old_item,NVS_ITEM_CHUNK_ANY,NVS_ITEM_VERSION_ANY);
        if (old_page != NULL) {
            old_position = position;
            if (type == NVS_ITEM_TYPE_BLOB) {
                result = nvs_storage_compare_multi_page_blob(storage,
                    namespace_index,key,value,size);
                if (result == 0)
                    return 0;
                unsigned int old_start = old->blob_index.chunk_start;
                if ((old_start & NVS_ITEM_CHUNK_NUMBER_MASK) != 0)
                    return -1;
                next_version = old_start == NVS_BLOB_VERSION_1_OFFSET ? NVS_BLOB_VERSION_0_OFFSET : NVS_BLOB_VERSION_1_OFFSET;
            } else {
                result = nvs_page_get_sequence(old_page,(unsigned int *)&old_sequence);
                if (result != 0)
                    return result;
                if (nvs_page_compare_item(old_page,namespace_index,type,key,
                        value,size,NVS_ITEM_CHUNK_ANY,NVS_ITEM_VERSION_ANY) == 0)
                    return 0;
            }
        } else {
            /* Reload the head only after exhausting a nonempty first scan. */
            old_page = nvs_storage_find_item_page(state->pages.head,namespace_index,NVS_ITEM_TYPE_ANY,key,
                &position,&old_item,NVS_ITEM_CHUNK_ANY,NVS_ITEM_VERSION_ANY);
            if (old_page != NULL) {
                old_position = position;
                result = nvs_page_get_sequence(old_page,(unsigned int *)&old_sequence);
                if (result != 0)
                    return result;
            }
        }
    }

    if (type == NVS_ITEM_TYPE_BLOB) {
        result = nvs_storage_write_multi_page_blob(storage,namespace_index,
            key,value,size,next_version);
        if (result == 0x110a)
            return 0x1105;
    } else {
        NvsPage *page = state->pages.tail;
        result = nvs_page_write_item(page,namespace_index,type,key,value,size,NVS_ITEM_CHUNK_ANY);
        if (result == 0x110a) {
            if (((volatile NvsPage *)page)->state != NVS_PAGE_STATE_FULL) {
                result = nvs_page_mark_full(page);
                if (result != 0)
                    return result;
            }
            result = nvs_page_manager_request_new_page(&storage->page_manager);
            if (result != 0)
                return result;
            page = state->pages.tail;
            result = nvs_page_write_item(page,namespace_index,type,key,value,size,NVS_ITEM_CHUNK_ANY);
            if (result == 0x110a)
                return 0x1105;
        }
    }
    if (result != 0)
        return result;
    if (old_page == NULL)
        return 0;

    unsigned int old_type = old->type;
    if (old_type == NVS_ITEM_TYPE_BLOB_INDEX) {
        if (state->storage_state != NVS_STORAGE_STATE_ACTIVE)
            return 0x1101;
        result = nvs_storage_erase_multi_page_blob(storage,namespace_index,
            key,old->blob_index.chunk_start);
    } else {
        unsigned int page_state = ((volatile NvsPage *)old_page)->state;
        if (page_state == NVS_PAGE_STATE_FULL || page_state == NVS_PAGE_STATE_ACTIVE) {
            result = nvs_page_get_sequence(old_page,(unsigned int *)&position);
            if (result != 0)
                return result;
            unsigned int current_sequence = position;
            unsigned int saved_sequence = old_sequence;
            if (current_sequence == saved_sequence)
                goto erase_old_entry;
            old_type = old->type;
        }
        old_page = nvs_storage_find_item_page(state->pages.head,namespace_index,old_type,key,
            &position,&old_item,NVS_ITEM_CHUNK_ANY,NVS_ITEM_VERSION_ANY);
        if (old_page == NULL)
            return 0x1102;
        old_position = position;
erase_old_entry:
        result = nvs_page_erase_entry_and_span(old_page,old_position);
    }
    return result == 0x6001 ? 0x1108 : result;
}

/* Native entry: 0x42014a20. */
/* Original function-byte SHA-256:
 * 614e0f3d8923cdc82819d1a8fbdbb94cb16386240d2e37863c3920dda02cee37. */
/* Return the ROM little-endian CRC32 of data/size. A NULL initial_crc uses
 * 0xffffffff; otherwise load exactly one seed word. Pass seed, data and full
 * size to ROM 0x40001c98 and return its result unchanged. No extra complement,
 * input-pointer validation, length narrowing or Bluetooth operation occurs. */
unsigned int nvs_crc32_data(const void *data,size_t size,
    const unsigned int *initial_crc)
{
    unsigned int seed = 0xffffffffU;
    if (initial_crc != NULL)
        seed = *(const volatile unsigned int *)initial_crc;
    return esp_rom_crc32_le(seed,data,size);
}
