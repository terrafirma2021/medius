/* Medius v3.4.7 device — report descriptor fragment admission/publication. */
#include "../include/types.h"

/* Report-upload reconstruction utilities: inline native optional semaphore
 * gives, not additional entries. Each call samples the current handle once.
 * The original reset path separately samples its handle before clearing upload.
 */
static __attribute__((always_inline)) inline void report_upload_unlock_rewrite(void)
{
    RtosQueue *mutex = REWRITE_MUTEX;
    if (mutex != NULL)
        xQueueGenericSend(mutex,NULL,0,0);
}
static __attribute__((always_inline)) inline void report_upload_unlock_outer(void)
{
    RtosQueue *mutex = REPORT_MUTEX;
    if (mutex != NULL)
        xQueueGenericSend(mutex,NULL,0,0);
}

/* Native entry: 0x4203456c. */
/* Original function-byte SHA-256:
 * 09d42f45a263bdfb9810eab5c8b03e94a6f1a5f543f85dcf098880174bc9acdf. */
/*
 * Accept an eight-byte report-descriptor header plus fragment bytes. Length uses
 * low16; total high BYTE is read before low and configuration. FF/total0 resets
 * archive used HALFWORD and upload pointer under optional outer-report then
 * rewrite mutexes, ignoring take results. It does not reparse live bindings.
 * Other FF configurations or total>2048 return before locks. Read offset-high,
 * chunk-high,chunk-low,offset-low BYTEs in native order; require offset+chunk<=
 * total and packet length>=chunk+8, then sample interface BYTE and take locks.
 *
 * Offset0 reserves a provisional archive record, protecting current config;
 * publishes interface BYTE,payload WORD,next-offset HALFWORD,configuration BYTE,
 * total HALFWORD in that order even on failure. NULL reservation releases both
 * current mutexes then logs no-room. Continuations require nonnull upload pointer
 * and exact expected offset, then matching config/interface/total. Copy into the
 * cached pointer, publish end HALFWORD; incomplete/stale fragments only unlock.
 *
 * On completion, commit configuration BYTE at payload-4 only if a fresh payload
 * pointer lies within base+4..base+used. Sample active-config BYTE before clearing
 * upload pointer. Different config only unlocks. For active config, MEMW/check
 * clone-active BYTE; inactive skips rebuilding. Otherwise cache signed interface
 * count and first matching interface-id index, then archive used/base snapshots.
 * Scan complete records with length high-before-low, stride modulo16 and end
 * check before cursor narrowing. A matching record with unknown interface index
 * does not rebuild. Known index rebuilds only on missing record, length mismatch,
 * enabled BYTE differing from(total==0), or bytewise descriptor difference.
 *
 * Rebuild parses reports(copy1), refreshes bindings(0,0), releases rewrite mutex,
 * registers endpoints while outer mutex remains held, releases outer, logs and
 * reports rebound slots. Quiet active-config paths call the reviewed rewrite-
 * unlock helper before outer give; ignored paths use direct current-handle gives.
 * No bounds repair, rollback, detach, null-source checks, local timeout or atomic
 * upload ownership. Malformed zero-stride archive records can loop indefinitely;
 * unchecked interface counts/indexes and mutable upload/archive storage persist.
 */
void clone_accept_report_fragment(const unsigned char *packet,unsigned int length)
{
    length = (unsigned short)length;
    if (length < 8U)
        return;
    unsigned int total_high = *(const volatile unsigned char *)(packet + 3);
    unsigned int total_low = *(const volatile unsigned char *)(packet + 2);
    unsigned int configuration = *(const volatile unsigned char *)packet;
    unsigned int total = (total_high << 8) | total_low;
    unsigned char empty = total == 0;
    volatile MediusCloneReportUpload *upload = MEDIUS_CLONE_REPORT_UPLOAD;
    volatile MediusReportArchive *archive = MEDIUS_REPORT_ARCHIVE;
    RtosQueue *mutex;
    if (configuration == 255U && total == 0) {
        mutex = REPORT_MUTEX;
        if (mutex != NULL)
            xQueueSemaphoreTake(mutex,0xffffffffU);
        mutex = REWRITE_MUTEX;
        if (mutex == NULL) {
            archive->used = 0;
            upload->payload = NULL;
        } else {
            xQueueSemaphoreTake(mutex,0xffffffffU);
            archive->used = 0;
            mutex = REWRITE_MUTEX;
            upload->payload = NULL;
            if (mutex != NULL)
                xQueueGenericSend(mutex,NULL,0,0);
        }
        report_upload_unlock_outer();
        return;
    }
    if (total > 2048U || configuration == 255U)
        return;
    unsigned int offset_high = *(const volatile unsigned char *)(packet + 5);
    unsigned int chunk_high = *(const volatile unsigned char *)(packet + 7);
    unsigned int chunk_low = *(const volatile unsigned char *)(packet + 6);
    unsigned int offset_low = *(const volatile unsigned char *)(packet + 4);
    unsigned int offset = (offset_high << 8) | offset_low;
    unsigned int chunk = (chunk_high << 8) | chunk_low;
    unsigned int end = offset + chunk;
    if (end > total || length < chunk + 8U)
        return;
    unsigned int interface_number = *(const volatile unsigned char *)(packet + 1);
    mutex = REPORT_MUTEX;
    if (mutex != NULL)
        xQueueSemaphoreTake(mutex,0xffffffffU);
    mutex = REWRITE_MUTEX;
    if (mutex != NULL)
        xQueueSemaphoreTake(mutex,0xffffffffU);
    unsigned char *destination;
    if (offset == 0) {
        unsigned int protected_configuration = MEDIUS_CLONE_CONFIGURATION_INDEX;
        destination = medius_report_archive_reserve(configuration,interface_number,total,
            protected_configuration);
        upload->interface_number = (unsigned char)interface_number;
        upload->payload = destination;
        upload->next_offset = (unsigned short)offset;
        upload->configuration = (unsigned char)configuration;
        upload->total = (unsigned short)total;
        if (destination == NULL) {
            report_upload_unlock_rewrite();
            report_upload_unlock_outer();
            unsigned int stamp = esp_log_timestamp();
            esp_log_write(2,"usbdev","W (%lu) %s: no room for cfg %u intf %u report descriptor (%u B)\n",
                stamp,"usbdev",configuration,interface_number,total);
            return;
        }
    } else {
        destination = upload->payload;
        if (destination == NULL || upload->next_offset != offset)
            goto ignored;
    }
    if (upload->configuration != configuration || upload->interface_number != interface_number ||
            upload->total != total)
        goto ignored;
    memcpy(destination + offset,packet + 8,chunk);
    upload->next_offset = (unsigned short)end;
    if ((unsigned short)end != total)
        goto ignored;
    unsigned char *published = upload->payload;
    if (published != NULL) {
        unsigned char *base = archive->data;
        if ((unsigned int)published >= (unsigned int)base + 4U) {
            unsigned int used = archive->used;
            if ((unsigned int)published <= (unsigned int)base + used)
                *(volatile unsigned char *)(published - 4) = (unsigned char)configuration;
        }
    }
    unsigned int active_configuration = MEDIUS_CLONE_CONFIGURATION_INDEX;
    upload->payload = NULL;
    if (active_configuration != configuration)
        goto ignored;
    memw();
    if (CLONE_ACTIVE == 0)
        goto quiet;
    int interface_count = USB_INTERFACE_COUNT;
    unsigned int interface_index = 0xffffffffU;
    if (interface_count > 0) {
        for (unsigned int index = 0; index < (unsigned int)interface_count; ++index) {
            if (REPORT_CAPTURE_INTERFACE_IDS[index] == interface_number) {
                interface_index = index;
                break;
            }
        }
    }
    unsigned int used = archive->used;
    if (used >= 4U) {
        unsigned char *base = archive->data;
        unsigned int cursor = 0;
        do {
            const volatile unsigned char *record = base + cursor;
            unsigned int high = record[3];
            unsigned int low = record[2];
            unsigned int stride = (unsigned short)(((high << 8) | low) + 4U);
            unsigned int record_end = cursor + stride;
            if (record_end > used)
                break;
            if (record[0] == configuration && record[1] == interface_number) {
                if (interface_index == 0xffffffffU)
                    goto quiet;
                if (USB_INTERFACE_REPORT_LENGTHS[interface_index] != total ||
                        REPORT_BUFFER_ENABLED[interface_index] != empty)
                    goto rebuild;
                const unsigned char *current = REPORT_BUFFER_STORAGE +
                    (unsigned short)interface_index * 2048U;
                if (memcmp(current,base + cursor + 4U,total) != 0)
                    goto rebuild;
                goto quiet;
            }
            cursor = (unsigned short)record_end;
        } while (cursor + 3U < used);
    }
    if (interface_index == 0xffffffffU)
        goto quiet;
rebuild:
    medius_clone_parse_configuration_reports(1);
    clone_refresh_report_bindings(0,0);
    report_upload_unlock_rewrite();
    medius_usb_register_clone_endpoints();
    report_upload_unlock_outer();
    unsigned int stamp = esp_log_timestamp();
    esp_log_write(3,"usbdev",
        "I (%lu) %s: cfg %u intf %u report descriptor updated (%u B) without dropping the clone\n",
        stamp,"usbdev",configuration,interface_number,total);
    medius_usb_log_interface_slots("rebound");
    return;
quiet:
    rewrite_unlock();
    report_upload_unlock_outer();
    return;
ignored:
    report_upload_unlock_rewrite();
    report_upload_unlock_outer();
}
