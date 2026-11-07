/* Medius v3.4.7 host — app/firmware.c.
 * Recovered C and native assembly, grouped for source navigation.
 * Original entry addresses, firmware-byte hashes and function comments follow.
 */

#include "../include/types.h"

/* Native entry: 0x42002148. */
/*
 * Medius v3.4.7 — host application; 0x42002148.
 *
 * Returns the pinned application-description address in mapped DROM.
 *
 * Called by: FUN_42009318, medius_get_firmware_label.
 *
 * Original function-byte SHA-256:
 * 59fb9b2b52857942048bbec00cc3fc4139a8a348c061bcdda57cc135f4da308a.
 */

/*
 * Returns: Borrowed const pointer to the 256-byte ESP-IDF application description at mapped
 *   DROM0x3c040020.
 * Requirements/effects: One literal load and return. No field reads, validation, allocation,
 *   mutable state or calls; validity and mapping come from the loaded image.
 */

const EspAppDescription *get_app_description(void)
{
    return APPLICATION_DESCRIPTION;
}

/* Native entry: 0x4200c494. */
/* Original function-byte SHA-256:
 * a135d76a18b0c432d905b3326890e49b1590662b40ace6e76acac7f77677295f. */
/* Dispatch host-side UART firmware opcodes. INFO0x2d sends six bytes
 * {3,4,7,slot,state,staged} through0x2e/flags0 and does not refresh activity.
 * Every other opcode, including unknown/empty MODE, stores LOW32 clock us.
 * BEGIN0x27 requires36 bytes, inhibits forwarding/baud probes and sets LED3
 * BEFORE reading image size bytes1,0,2,3. Begin uses size and32 digest bytes;
 * send its status/detail, then restore polling only if status!=1 and not staged.
 * Log the saved enqueue result; it is not confirmation of delivery.
 * DATA0x28 requires3 bytes; sequence reads bytes1,0, data starts+2. Answer
 * errors; on success answer2 only when the session's ack BYTE is nonzero.
 * END0x2a finishes and answers. ABORT0x2b aborts, answers0, then clears
 * forwarding inhibit, baud-probe inhibit and LED in that order. MODE0x2c
 * with nonempty payload normalizes byte0 and sets the same controls/LED.
 * ACTIVATE0x2f requires staged; activation success answers0 then delays50
 * scheduler ticks and restarts even if answer enqueue failed. Missing stage
 * returns0x19/detail0; activation -1000 returns0x19/rawdetail, others0x16.
 * Length gates use unsigned16; no payload NULL checks, framing validation,
 * lock, retry of local operations, UART drain or measured timing guarantee. */
void medius_host_update_link_dispatch(unsigned char opcode,
    const unsigned char *payload,unsigned short length)
{
    unsigned int detail = 0;
    if (opcode == 0x2d) {
        unsigned char slot,state;
        update_running_slot_info(&slot,&state);
        MediusUpdateFirmwareInfo information;
        information.major = 3;
        information.minor = 4;
        information.patch = 7;
        information.slot = slot;
        information.state = state;
        information.staged = update_session_is_staged(UPDATE_SESSION);
        link_send_wait100(0x2e,0,&information,6);
        return;
    }
    MEDIUS_HOST_UPDATE_LAST_ACTIVITY_US = (unsigned int)esp_timer_get_time();
    const volatile unsigned char *bytes = payload;
    switch (opcode) {
    case 0x27: {
        if (length < 36) {
            medius_host_update_send_answer(0x1a,0);
            return;
        }
        medius_host_set_forwarding_inhibit(1);
        medius_link_set_baud_probe_inhibit(1);
        led_set_status(3);
        unsigned int size_byte1 = bytes[1];
        unsigned int size_byte0 = bytes[0];
        unsigned int size_byte2 = bytes[2];
        unsigned int size_byte3 = bytes[3];
        unsigned int image_size = size_byte0 | (size_byte1 << 8) |
                                  (size_byte2 << 16) | (size_byte3 << 24);
        unsigned int status = update_session_begin(UPDATE_SESSION,
            image_size,payload + 4,&detail);
        unsigned int answer_enqueued = medius_host_update_send_answer(status,detail);
        if (status != 1 && update_session_is_staged(UPDATE_SESSION) == 0) {
            medius_host_set_forwarding_inhibit(0);
            medius_link_set_baud_probe_inhibit(0);
            led_set_status(0);
        }
        medius_host_log_formatted("update begin %u bytes -> status %u, answer %s",
            image_size,status,answer_enqueued != 0 ? "sent" : "REFUSED");
        return;
    }
    case 0x28: {
        if (length < 3) {
            medius_host_update_send_answer(0x1a,1);
            return;
        }
        unsigned int sequence_high = bytes[1];
        unsigned int sequence_low = bytes[0];
        unsigned int sequence = sequence_low | (sequence_high << 8);
        unsigned char acknowledge = 0;
        unsigned int status = update_session_write(UPDATE_SESSION,
            sequence,payload + 2,(unsigned short)(length - 2),&detail,&acknowledge);
        if (status != 0)
            medius_host_update_send_answer(status,detail);
        else if (acknowledge != 0)
            medius_host_update_send_answer(2,detail);
        return;
    }
    case 0x2a: {
        unsigned int status = update_session_finish(UPDATE_SESSION,&detail);
        medius_host_update_send_answer(status,detail);
        return;
    }
    case 0x2b:
        update_session_abort(UPDATE_SESSION);
        medius_host_update_send_answer(0,0);
        medius_host_set_forwarding_inhibit(0);
        medius_link_set_baud_probe_inhibit(0);
        led_set_status(0);
        return;
    case 0x2c:
        if (length != 0) {
            unsigned char value = bytes[0];
            unsigned char inhibit = value != 0;
            medius_host_set_forwarding_inhibit(inhibit);
            medius_link_set_baud_probe_inhibit(inhibit);
            led_set_status(value != 0 ? 3 : 0);
        }
        return;
    case 0x2f: {
        if (update_session_is_staged(UPDATE_SESSION) == 0) {
            medius_host_update_send_answer(0x19,0);
            return;
        }
        int result = update_activate_staged();
        if (result == 0) {
            medius_host_update_send_answer(0,0);
            vTaskDelay(50);
            esp_restart();
        }
        medius_host_update_send_answer(result == -1000 ? 0x19 : 0x16,
            (unsigned int)result);
        return;
    }
    default:
        return;
    }
}

/* Native entry: 0x4200eec0. */
/* Original function-byte SHA-256:
 * 502b4b6e31907cbc90624a38e483f53b425b7bda55fbf51c83b6b0029efca7a9. */
/* Delay 60 scheduler ticks, then MEMW and write the FULL value1 to the
 * ROM-download request register, replacing its old word. Call nonreturning
 * esp_restart. No timer conversion, USB/UART drain, acknowledgement or lock. */
void medius_host_reboot_to_download(void)
{
    vTaskDelay(60);
    memw();
    ROM_DOWNLOAD_REQUEST = 1;
    esp_restart();
}

/* Native entry: 0x4200eed8. */
/* Original function-byte SHA-256:
 * 4e136a797ff0a38e9f637a2c11a7f0e06ff0088f5587c3579b39a528668a99c1. */
/* Delay 60 scheduler ticks, then call nonreturning esp_restart. This
 * body does not write or clear the ROM-download request register. No drain,
 * acknowledgement, timer conversion, boot selection or lock is supplied. */
void medius_host_reboot_to_run(void)
{
    vTaskDelay(60);
    esp_restart();
}

/* Native entry: 0x4200eee8. */
/*
 * Medius v3.4.7 — host application; 0x4200eee8.
 *
 * Lazily formats and returns a cached version-plus-hash label.
 *
 * Calls: FUN_4201654c, get_app_description.
 *
 * Called by: app_main, medius_clone_publish.
 *
 * Original function-byte SHA-256:
 * 12a34f54ddfece81b3d28a568ff9d4415bd498ff32704b552fe2c007237aaa79.
 */

/*
 * Returns: The shared writable32-byte label buffer, even if the formatter fails.
 * Requirements/effects: Reads only cache byte0 to decide whether to format. An empty cache gets
 *   the pinned description, snapshots ELF hash bytes in native order1,0,3,2 and formats at most15
 *   version characters plus four two-digit hash bytes and the pinned empty suffix. Formatter
 *   result is ignored; byte0 left zero causes a later retry, any nonzero byte caches indefinitely.
 *   No lock, invalidation, initialization publication or checksum validation. Borrowed
 *   description/version/cache pointers must remain mapped; concurrent first calls can race.
 */

char *medius_get_firmware_label(void)
{
    if (*(const volatile unsigned char *)&(*FIRMWARE_LABEL_BUFFER)[0] == 0) {
        const EspAppDescription *description = get_app_description();
        const volatile unsigned char *hash = description->app_elf_sha256;
        unsigned int hash_second = hash[1];
        unsigned int hash_first = hash[0];
        unsigned int hash_fourth = hash[3];
        unsigned int hash_third = hash[2];
        newlib_snprintf((*FIRMWARE_LABEL_BUFFER),32,"%.15s+%02x%02x%02x%02x%s",
                     description->version,hash_first,hash_second,hash_third,hash_fourth,
                     (const char *)0x3c040dccU);
    }
    return (*FIRMWARE_LABEL_BUFFER);
}

/* Native entry: 0x4200f288. */
/* Original function-byte SHA-256:
 * e8d8bf1235b649f03033e7bf60315fc6fb939d5ceb3aa3c026abbda595ac7d14. */
/* Task-timer callback, argument unused. Under the probation spinlock,
 * a nonzero claimed BYTE only unlocks/returns. Otherwise claim1 before
 * unlocking, log timeout locally, invoke the optional per-image link-log
 * hook, then request invalidation/rollback/reboot. Its error result is ignored:
 * if it returns, claimed remains1 and this callback will not retry.
 * The hook is fixed non-NULL on host and fixed NULL on device; the device's
 * indirect-call diagnostic branch is unreachable, not an unknown live target.
 * No timer stop/delete here; delivery latency and rollback are not measured. */
void ota_grace_timer_cb(void *argument)
{
    (void)argument;
    xPortEnterCriticalTimeout(OTA_PROBATION_LOCK,-1);
    if (OTA_PROBATION->claimed != 0) {
        vPortExitCritical(OTA_PROBATION_LOCK);
        return;
    }
    OTA_PROBATION->claimed = 1;
    vPortExitCritical(OTA_PROBATION_LOCK);
    unsigned int stamp = esp_log_timestamp();
    esp_log_write(1,UPDATE_LOG_TAG,"E (%lu) %s: self-check timed out, rolling back\n",stamp,UPDATE_LOG_TAG);
    if (OTA_LOG_HOOK != NULL)
        medius_host_log_formatted("self-check timed out, rolling back");
    esp_ota_mark_app_invalid_rollback_and_reboot();
}

/* Native entry: 0x4200f2e4. */
/* Original function-byte SHA-256:
 * 5d3685a81d807a9205e5c6bd80706da7d4706b10c19356a5c0cbd1fa1dd962f5. */
/* Snapshot the staged partition pointer. NULL returns -1000; otherwise
 * pass that exact pointer to esp_ota_set_boot_partition. Return its result,
 * logging nonzero errors. No restart, session-flag clearing, staged-pointer
 * clearing, revalidation or lock occurs here. Boot validation belongs to the
 * separately identified SDK operation. */
int update_activate_staged(void)
{
    const EspPartition *partition = UPDATE_BACKEND->staged_partition;
    if (partition == NULL)
        return -1000;
    int result = esp_ota_set_boot_partition(partition);
    if (result != 0) {
        unsigned int stamp = esp_log_timestamp();
        esp_log_write(1,UPDATE_LOG_TAG,"E (%lu) %s: set boot %d\n",stamp,UPDATE_LOG_TAG,result);
    }
    return result;
}


/* Native entry: 0x4200f32c. */
/* Original function-byte SHA-256:
 * abedca435bade2796b9e5ddc213286f9dbd04776bd857df5ac5b48b059ae4e3c. */
/* Initialize slot then state to0xff. Get the running partition; if it
 * exists and subtype-0x10 is unsigned<16, publish that slot byte before the
 * state query. Successful state query maps values0..4 to themselves and all
 * other words to0xff. Query failure retains the initial state byte. No NULL
 * output checks, alias protection, partition-type test, lock or allocation. */
void update_running_slot_info(unsigned char *slot,unsigned char *state)
{
    *slot = 0xff;
    *state = 0xff;
    const EspPartition *partition = esp_ota_get_running_partition();
    if (partition == NULL)
        return;
    unsigned int index = partition->subtype - 0x10U;
    if (index < 16U)
        *slot = (unsigned char)index;
    unsigned int native_state;
    if (esp_ota_get_state_partition(partition,&native_state) == 0)
        *state = native_state <= 4U ? (unsigned char)native_state : 0xffU;
}

/* Native entry: 0x4200f380. */
/* Original function-byte SHA-256:
 * 6e5a82efc0c95fcc68bc0f1d95c92e647fa61fb99a250d6093409e2a15068198. */
/* Unlocked gates: return if a timer already exists or the claimed BYTE
 * is nonzero. Query current slot/state. Only pending state1 creates a timer;
 * other states mark claimed1 under the spinlock without SDK confirmation.
 * Create task-dispatched "ota_grace", argumentNULL, skip-unhandled false,
 * publishing the handle directly into the shared timer slot. Creation failure
 * clears that slot and returns. Success reloads the handle, requests a one-shot
 * (uint64)milliseconds*1000 and logs probation even if start_once failed.
 * No start-error cleanup, duplicate-creation interlock or recheck after query.
 * A failed start can leave a non-NULL handle that prevents a later retry.
 * Delay is requested microseconds, not a guaranteed callback deadline. */
void ota_start_grace(unsigned int milliseconds)
{
    if (OTA_PROBATION->timer != NULL)
        return;
    if (OTA_PROBATION->claimed != 0)
        return;
    unsigned char slot,state;
    update_running_slot_info(&slot,&state);
    if (state != 1) {
        xPortEnterCriticalTimeout(OTA_PROBATION_LOCK,-1);
        if (OTA_PROBATION->claimed == 0)
            OTA_PROBATION->claimed = 1;
        vPortExitCritical(OTA_PROBATION_LOCK);
        return;
    }
    EspTimerCreateArgs arguments = {
        .callback=ota_grace_timer_cb,.argument=NULL,.dispatch=0,
        .name="ota_grace",.skip_unhandled_events=0,.padding17={0,0,0}
    };
    /* SDK output-pointer type has no volatile qualifier; the native output
     * is this same 32-bit shared slot, which is reloaded after the call. */
    if (esp_timer_create(&arguments,(EspTimer **)&OTA_PROBATION->timer) != 0) {
        OTA_PROBATION->timer = NULL;
        return;
    }
    esp_timer_start_once(OTA_PROBATION->timer,(unsigned long long)milliseconds * 1000U);
    unsigned int stamp = esp_log_timestamp();
    esp_log_write(2,UPDATE_LOG_TAG,"W (%lu) %s: image on probation, %u ms to confirm\n",stamp,UPDATE_LOG_TAG,milliseconds);
}


/* Native entry: 0x4200f414. */
/* Original function-byte SHA-256:
 * 448e7186c7876386a6de3bf9933761f53c5f4fadf20afb0a2c5b65c9311edc06. */
/* Snapshot and stop an existing probation timer BEFORE taking the
 * spinlock, ignoring stop's result. Already-claimed state only unlocks and
 * returns. Otherwise set claimed1, unlock, reload the timer slot and, if
 * non-NULL, delete that timer and clear the slot regardless of delete status.
 * Then mark the running image valid and log success/error. Confirmation
 * failure does not reopen the claim or rearm probation; no rollback request
 * occurs here. Timer stop/delete and SDK marking run outside the spinlock. */
void confirm_running_image(void)
{
    EspTimer *timer = OTA_PROBATION->timer;
    if (timer != NULL)
        esp_timer_stop(timer);
    xPortEnterCriticalTimeout(OTA_PROBATION_LOCK,-1);
    if (OTA_PROBATION->claimed != 0) {
        vPortExitCritical(OTA_PROBATION_LOCK);
        return;
    }
    OTA_PROBATION->claimed = 1;
    vPortExitCritical(OTA_PROBATION_LOCK);
    timer = OTA_PROBATION->timer;
    if (timer != NULL) {
        esp_timer_delete(timer);
        OTA_PROBATION->timer = NULL;
    }
    int result = esp_ota_mark_app_valid_cancel_rollback();
    if (result == 0) {
        unsigned int stamp = esp_log_timestamp();
        esp_log_write(3,UPDATE_LOG_TAG,"I (%lu) %s: image confirmed\n",stamp,UPDATE_LOG_TAG);
    }
    else {
        unsigned int stamp = esp_log_timestamp();
        esp_log_write(1,UPDATE_LOG_TAG,"E (%lu) %s: confirm failed %d; the next boot reverts\n",stamp,UPDATE_LOG_TAG,result);
    }
}


/* Native entry: 0x42010fe0. */
/* Original function-byte SHA-256:
 * eb36143d8de2580839ada2a728f0de7b80fa2c5e61648c61da340e35039f87ec. */
/* Forward valid=true to the shared SDK current-image marking routine
 * and return its full error code. No local status conversion or extra action;
 * current-image selection and OTA metadata changes belong to that routine. */
int esp_ota_mark_app_valid_cancel_rollback(void)
{
    return esp_ota_current_ota_is_workable(true);
}


/* Native entry: 0x42010fec. */
/* Original function-byte SHA-256:
 * 410c8b174c6b24816eecc8b810cae5c9d772e8e3604484627f1d870a418d4ae9. */
/* Forward valid=false to the shared SDK marking/rollback routine and
 * return its full error code if it returns. This wrapper is NOT declared
 * nonreturning: rollback/reboot can fail. No local recovery or status mapping. */
int esp_ota_mark_app_invalid_rollback_and_reboot(void)
{
    return esp_ota_current_ota_is_workable(false);
}


/* Native entry: 0x4200c3e8. */
/* Original function-byte SHA-256:
 * 0504331c43cf3193f193931607dbe5f46e1fa28739a5b2d327eab62b2d1817b6. */
/* Send update-answer opcode0x29, flags0, exactly5 bytes: status followed by
 * detail little-endian. Native status is a FULL word ORed with detail<<8;
 * callers use byte-sized codes, but upper status bits are deliberately retained
 * and can contaminate detail bytes. Stack storage has3 unused trailing bytes.
 * Snapshot the64-bit clock BEFORE reading forwarding inhibit. A nonzero inhibit
 * selects2,000,000us, otherwise50,000us; add modulo64, then compare signed64.
 * Attempt enqueue at least once. Return its raw nonzero result immediately;
 * each failure delays ONE scheduler tick, then checks time. At/after deadline,
 * log failure and return the saved zero enqueue result. No UART drain or delivery
 * acknowledgement. Queue success and requested budget do not prove wire timing. */
unsigned int medius_host_update_send_answer(unsigned int status,unsigned int detail)
{
    MediusUpdateAnswerStorage answer;
    answer.first_four_bytes = status | (detail << 8);
    answer.detail_most_significant_byte = (unsigned char)(detail >> 24);
    long long started_us = esp_timer_get_time();
    unsigned char inhibited = medius_host_get_forwarding_inhibit();
    unsigned int budget_us = inhibited != 0 ? 2000000U : 50000U;
    long long deadline_us = (long long)((unsigned long long)started_us + budget_us);
    unsigned int enqueued;
    do {
        enqueued = medius_link_send_now(0x29,0,&answer,5);
        if (enqueued != 0)
            return enqueued;
        vTaskDelay(1);
    } while (esp_timer_get_time() < deadline_us);
    medius_host_log_formatted("the link would not take an update answer");
    return enqueued;
}


/* Native entry: 0x4200c464. */
/* Original function-byte SHA-256:
 * 9e857ae9e1153976f9aae5a1652bd0bd348184d978f688f179728ce2a1510f10. */
/* Save LOW32 clock microseconds as last update activity, then obtain storage
 * operations, hash operations and opaque backend context in that order. Reset
 * the shared64-byte session using those pointers; finally set its BYTE ack
 * interval to6. No abort of prior state, pointer validation, lock or return.
 * The recovered context factory returnsNULL; backend callbacks use MCU globals. */
void medius_host_update_session_init(void)
{
    MEDIUS_HOST_UPDATE_LAST_ACTIVITY_US = (unsigned int)esp_timer_get_time();
    const UpdateStorageOps *storage = update_storage_operations();
    const UpdateHashOps *hash = update_hash_operations();
    void *context = update_backend_context();
    update_session_initialize(UPDATE_SESSION,storage,hash,context);
    UPDATE_SESSION->acknowledgement_interval = 6;
}

/* Native entry: 0x4200c68c. */
/* Original function-byte SHA-256:
 * 5b631bb85b944aabcea4ef6a40c4fead76c36e3baf55c60baed8052adcab1c3e. */
/* LOW32 clock minus last-activity is modulo32, interpreted SIGNED; only
 * values strictly greater than10,000,000us enter recovery. This is not an
 * unsigned wrap-safe timeout over the full32-bit period: bit31 suppresses it.
 * Snapshot forwarding inhibit before reading session active BYTE. Active:
 * abort session, restore polling/baud/LED only if the saved inhibit was nonzero,
 * then always log dropping. Inactive: if saved inhibit nonzero, restore the
 * controls and log polling again; otherwise no action. Last-activity is not
 * refreshed; no lock, transport drain, timer scheduling or result is supplied. */
void medius_host_update_check_timeout(void)
{
    unsigned int now_us = (unsigned int)esp_timer_get_time();
    unsigned int elapsed_bits = now_us - MEDIUS_HOST_UPDATE_LAST_ACTIVITY_US;
    if ((int)elapsed_bits <= 10000000)
        return;
    unsigned char inhibited = medius_host_get_forwarding_inhibit();
    unsigned char active = update_session_is_active(UPDATE_SESSION);
    if (active != 0) {
        update_session_abort(UPDATE_SESSION);
        if (inhibited != 0) {
            medius_host_set_forwarding_inhibit(0);
            medius_link_set_baud_probe_inhibit(0);
            led_set_status(0);
        }
        medius_host_log_formatted("update went quiet, dropping it");
    }
    else if (inhibited != 0) {
        medius_host_set_forwarding_inhibit(0);
        medius_link_set_baud_probe_inhibit(0);
        led_set_status(0);
        medius_host_log_formatted("nothing has driven this update for a while, polling again");
    }
}

