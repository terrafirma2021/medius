/* Medius v3.4.7 device — medius_report_archive_reserve. */
#include "../include/types.h"

/* Archive reconstruction utilities: inline native unaligned BYTE reads,
 * not additional native entries. The high byte is sampled before the low.
 */
static __attribute__((always_inline)) inline unsigned int archive_payload_length(
    const volatile unsigned char *record)
{
    unsigned int high = record[3];
    unsigned int low = record[2];
    return (high << 8) | low;
}

/* Native entry: 0x4202b298. */
/* Original function-byte SHA-256:
 * 86db880c37fe9651674353c96bdc486308610c0d9daec344f4aac6427e4d0639. */
/*
 * Reserve an uninitialized report payload after a four-BYTE provisional header.
 * configuration/interface/protected values are full WORD comparisons; only
 * exactly255 configuration is rejected initially. required=payload_length+4
 * wraps at32 bits and must fit the initial capacity HALFWORD. No used<=capacity
 * invariant, heap allocation, internal lock or payload-length cap is supplied.
 *
 * Preflight complete headers using one base/used/capacity snapshot. Record
 * stride=(length16+4) modulo65536, cursor+stride is checked before narrowing the
 * next cursor. Reclaim counts every FF provisional, exact config/interface and
 * other unprotected configuration; malformed tails stop preflight unchanged.
 * After admission remove only the first exact duplicate, then first FF record,
 * even if space already suffices. Both reread high/low length BYTEs before their
 * second end check; truncation or memmove updates used HALFWORD. The provisional
 * scan reloads base. A successful memmove's used calculation rereads live used.
 *
 * Reload capacity, then repeatedly evict the first record differing from both
 * requested/protected config until required+used fits. Missing/malformed victims
 * return NULL while retaining prior deletions. Reload used THEN capacity after
 * each eviction memmove. Never reinterpret a high-bit length as signed.
 *
 * Append FF,low8 interface,low8 length,next length BYTE, reloading base before
 * each write. Load return base before publishing low16(used+required), then
 * return base+old_used+4. Payload remains untouched; caller commits configuration.
 * Malformed length65532 has zero stride and may loop forever. Wrapped required
 * values0..3 still write four header bytes. No added bounds repair, concurrent
 * safety or pointer lifetime guarantee; later compaction invalidates the result.
 */
unsigned char *medius_report_archive_reserve(unsigned int configuration,
    unsigned int interface_id,unsigned int payload_length,unsigned int protected_configuration)
{
    if (configuration == 255U)
        return NULL;
    volatile MediusReportArchive *archive = MEDIUS_REPORT_ARCHIVE;
    unsigned int required = payload_length + 4U;
    unsigned int capacity = archive->capacity;
    if (required > capacity)
        return NULL;
    unsigned int used = archive->used;
    if (used < 4U) {
        if (required + used > capacity)
            return NULL;
    } else {
        unsigned char *base = archive->data;
        unsigned int reclaimable = 0,cursor = 0;
        do {
            const volatile unsigned char *record = base + cursor;
            unsigned int stride = (unsigned short)(archive_payload_length(record) + 4U);
            unsigned int end = cursor + stride;
            if (end > used)
                break;
            unsigned int record_configuration = record[0];
            if (record_configuration == 255U) {
                reclaimable += stride;
            } else if (record_configuration == configuration) {
                if (record[1] == interface_id)
                    reclaimable += stride;
            } else if (record_configuration != protected_configuration) {
                reclaimable += stride;
            }
            cursor = (unsigned short)end;
        } while (cursor + 3U < used);
        if (required + used - reclaimable > capacity)
            return NULL;

        /* Duplicate search retains the preflight's cached base and used. */
        cursor = 0;
        do {
            const volatile unsigned char *record = base + cursor;
            unsigned int stride = (unsigned short)(archive_payload_length(record) + 4U);
            unsigned int end = cursor + stride;
            if (end > used)
                break;
            if (record[0] == configuration && record[1] == interface_id) {
                unsigned int length = archive_payload_length(record);
                unsigned int next = (unsigned short)(cursor + length + 4U);
                if (next > used) {
                    used = (unsigned short)cursor;
                } else {
                    memmove(base + cursor,base + next,used - next);
                    used = (unsigned short)(archive->used - 4U - length);
                }
                archive->used = (unsigned short)used;
                break;
            }
            cursor = (unsigned short)end;
        } while (cursor + 3U < used);

        if (used >= 4U) {
            base = archive->data;
            cursor = 0;
            do {
                const volatile unsigned char *record = base + cursor;
                unsigned int stride = (unsigned short)(archive_payload_length(record) + 4U);
                unsigned int end = cursor + stride;
                if (end > used)
                    break;
                if (record[0] == 255U) {
                    unsigned int length = archive_payload_length(record);
                    unsigned int next = (unsigned short)(cursor + length + 4U);
                    if (next > used) {
                        used = (unsigned short)cursor;
                    } else {
                        memmove(base + cursor,base + next,used - next);
                        used = (unsigned short)(archive->used - 4U - length);
                    }
                    archive->used = (unsigned short)used;
                    break;
                }
                cursor = (unsigned short)end;
            } while (cursor + 3U < used);
        }
    }
    capacity = archive->capacity;
    while (required + used > capacity) {
        if (used < 4U)
            return NULL;
        unsigned char *base = archive->data;
        unsigned int cursor = 0;
        for (;;) {
            const volatile unsigned char *record = base + cursor;
            unsigned int length = archive_payload_length(record);
            unsigned int stride = (unsigned short)(length + 4U);
            unsigned int end = cursor + stride;
            if (end > used)
                return NULL;
            unsigned int record_configuration = record[0];
            unsigned int next = (unsigned short)end;
            if (record_configuration != configuration && record_configuration != protected_configuration) {
                if (next > used) {
                    archive->used = (unsigned short)cursor;
                    used = cursor;
                } else {
                    memmove(base + cursor,base + next,used - next);
                    unsigned int current_used = archive->used;
                    capacity = archive->capacity;
                    used = (unsigned short)(current_used - 4U - length);
                    archive->used = (unsigned short)used;
                }
                break;
            }
            if (next + 3U >= used)
                return NULL;
            cursor = next;
        }
    }
    *(volatile unsigned char *)(archive->data + used) = 255;
    *(volatile unsigned char *)(archive->data + used + 1U) = (unsigned char)interface_id;
    *(volatile unsigned char *)(archive->data + used + 2U) = (unsigned char)payload_length;
    *(volatile unsigned char *)(archive->data + used + 3U) = (unsigned char)(payload_length >> 8);
    unsigned char *result_base = archive->data;
    archive->used = (unsigned short)(required + used);
    return result_base + used + 4U;
}
