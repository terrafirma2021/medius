/* Device firmware update routing, activation and OTA probation. */

#include "../include/types.h"


/* reconstruction utilities: spell out the seven-byte control response used
 * inline by the native update branches. This is not an extra firmware entry. */
static __inline__ __attribute__((always_inline)) void
update_reply(unsigned char sequence,unsigned char operation,unsigned char target,
    unsigned char status,unsigned int detail)
{
    UpdateResponse response;
    response.operation = operation;
    response.target = target;
    response.status = status;
    response.detail[0] = (unsigned char)detail;
    response.detail[1] = (unsigned char)(detail >> 8);
    response.detail[2] = (unsigned char)(detail >> 16);
    response.detail[3] = (unsigned char)(detail >> 24);
    control_send_frame(0x18,sequence,&response,7);
}

/* Native entry: 0x4200b7a0. */
/* Original function-byte SHA-256:
 * 47f0f348615333691768b87710cb23cb00ce170e0f70dbffb56d1753a702cd05. */
/* External UPDATE body: operation BYTE0, target BYTE1 (0=device,1=host).
 * Truncate sequence to8 and length to16. Fewer than2 bytes silently return;
 * otherwise read target BEFORE operation and refresh LOW32 activity us, even
 * for unknown operations/targets. Op4 ACTIVATE ignores target, reports target0,
 * requires idle activation and at least one staged image, then saves sequence
 * and activity into both activation clocks. Local-only sets state2. Host stage
 * requires live link and slot!=0xff, snapshots generation/slot, clears error,
 * sets answer-pending, sends0x2f (result ignored), THEN sets state1. Failed host
 * availability leaves saved sequence/clocks in place without starting activation.
 * Other operations reject target>=2 silently. While activation is nonzero,
 * only ABORT3 with rechecked state1 can cancel: clear pending/activation/reply/
 * error under lock, log, report activation timeout0x18 to its saved sequence,
 * abort local session, clear host staged/relay, optionally send host abort,
 * acknowledge this ABORT and try idle resume. Other busy requests get0x10.
 * Host BEGIN0 requires36 body bytes, clears suppression/pending under lock,
 * marks relay-active and starts its query clock, suspends clone if needed,
 * clears host staged and relays EXACTLY36 bytes. Failure reports0x17 and resumes
 * if idle. Host DATA1 needs3 bytes and relays the entire remaining body; END2
 * relays no body. Their enqueue failures have no immediate control response.
 * Host ABORT3 clears staged, relays no body, reports0x17 only on failure and
 * tries idle resume on BOTH success and failure. Unavailable host gets0x17.
 * Local BEGIN0 snapshots suspended before setting begin-in-progress, suspends
 * if needed, assembles size bytes3,2,4,5, begins with digest+6, clears the guard
 * and replies; only accepted status1 skips idle resume. DATA1 reads sequence
 * bytes3,2 and writes payload+4/length-4. Errors reply and try resume. Successful
 * ack uses the independently incremented notification sequence (not request
 * sequence) with status2. END2 replies and retains suspension only for staged
 * status3. ABORT3 aborts, replies0 and tries idle resume. Short BEGIN gets0x1a/
 * detail0; short DATA gets0x1a/detail1. Unknown ops silently return.
 * No payload NULL checks, coherent global-state lock, cryptographic decision or
 * wire-delivery guarantee is added here. Native error codes/order are retained. */
void update_command_dispatch(unsigned int sequence,
    const unsigned char *payload,unsigned short length)
{
    unsigned char reply_sequence = (unsigned char)sequence;
    if (length < 2)
        return;
    const volatile unsigned char *bytes = payload;
    unsigned char target = bytes[1];
    unsigned char operation = bytes[0];
    unsigned int detail = 0;
    DEVICE_UPDATE->last_activity_us = (unsigned int)esp_timer_get_time();
    if (operation == 4) {
        if (DEVICE_UPDATE->activation_state != 0) {
            update_reply(reply_sequence,4,0,0x10,0);
            return;
        }
        unsigned char local_staged = update_session_is_staged(UPDATE_SESSION);
        unsigned char host_staged = DEVICE_UPDATE->host_staged;
        if (local_staged == 0 && host_staged == 0) {
            update_reply(reply_sequence,4,0,0x19,0);
            return;
        }
        unsigned int activity_us = DEVICE_UPDATE->last_activity_us;
        DEVICE_UPDATE->activation_sequence = reply_sequence;
        DEVICE_UPDATE->activation_started_us = activity_us;
        DEVICE_UPDATE->activation_poll_us = activity_us;
        if (host_staged == 0) {
            DEVICE_UPDATE->activation_state = 2;
            return;
        }
        if (DEVICE_UPDATE->host_link_state == 0) {
            update_reply(reply_sequence,4,0,0x17,0);
            return;
        }
        unsigned char host_slot = UPDATE_HOST_CACHE->slot;
        if (host_slot == 0xff) {
            update_reply(reply_sequence,4,0,0x17,0);
            return;
        }
        unsigned short generation = DEVICE_UPDATE->host_info_generation;
        UPDATE_HOST_CACHE->activation_initial_slot = host_slot;
        DEVICE_UPDATE->activation_initial_generation = generation;
        DEVICE_UPDATE->activation_error = 0;
        DEVICE_UPDATE->activation_answer_pending = 1;
        link_send_wait100(0x2f,0,NULL,0);
        DEVICE_UPDATE->activation_state = 1;
        return;
    }
    if (target >= 2)
        return;
    if (DEVICE_UPDATE->activation_state != 0) {
        xPortEnterCriticalTimeout(DEVICE_UPDATE_LOCK,-1);
        if (operation != 3 || DEVICE_UPDATE->activation_state != 1) {
            vPortExitCritical(DEVICE_UPDATE_LOCK);
            update_reply(reply_sequence,operation,target,0x10,0);
            return;
        }
        UPDATE_HOST_CACHE->pending_reply = 0xff00;
        DEVICE_UPDATE->activation_state = 0;
        DEVICE_UPDATE->activation_answer_pending = 0;
        DEVICE_UPDATE->activation_error = 0;
        vPortExitCritical(DEVICE_UPDATE_LOCK);
        unsigned int stamp = esp_log_timestamp();
        esp_log_write(2,DEVICE_UPDATE_TAG,"W (%lu) %s: activate abandoned by the control PC\n",stamp,DEVICE_UPDATE_TAG);
        unsigned char activation_sequence = DEVICE_UPDATE->activation_sequence;
        update_reply(activation_sequence,4,0,0x18,0);
        update_session_abort(UPDATE_SESSION);
        DEVICE_UPDATE->host_staged = 0;
        unsigned char link = DEVICE_UPDATE->host_link_state;
        DEVICE_UPDATE->relay_active = 0;
        if (link != 0)
            update_relay_abort();
        update_reply(reply_sequence,3,target,0,0);
        update_resume_clone_if_idle();
        return;
    }
    unsigned short body_length = (unsigned short)(length - 2);
    if (target == 1) {
        if (DEVICE_UPDATE->host_link_state == 0) {
            update_reply(reply_sequence,operation,1,0x17,0);
            return;
        }
        switch (operation) {
        case 0: {
            if (body_length < 36) {
                update_reply(reply_sequence,0,1,0x1a,0);
                return;
            }
            xPortEnterCriticalTimeout(DEVICE_UPDATE_LOCK,-1);
            DEVICE_UPDATE->ignored_abort_answers = 0;
            DEVICE_UPDATE->relay_active = 1;
            DEVICE_UPDATE->staging_query_us = (unsigned int)esp_timer_get_time();
            UPDATE_HOST_CACHE->pending_reply = 0xff00;
            vPortExitCritical(DEVICE_UPDATE_LOCK);
            if (DEVICE_UPDATE->clone_suspended == 0)
                update_suspend_clone();
            DEVICE_UPDATE->host_staged = 0;
            if (update_relay_request(0x27,0,reply_sequence,payload + 2,36) == 0) {
                DEVICE_UPDATE->relay_active = 0;
                update_reply(reply_sequence,0,1,0x17,0);
                update_resume_clone_if_idle();
            }
            return;
        }
        case 1:
            if (body_length < 3) {
                update_reply(reply_sequence,1,1,0x1a,1);
                return;
            }
            update_relay_request(0x28,1,reply_sequence,payload + 2,body_length);
            return;
        case 2:
            update_relay_request(0x2a,2,reply_sequence,NULL,0);
            return;
        case 3:
            DEVICE_UPDATE->host_staged = 0;
            if (update_relay_request(0x2b,3,reply_sequence,NULL,0) == 0) {
                DEVICE_UPDATE->relay_active = 0;
                update_reply(reply_sequence,3,1,0x17,0);
            }
            update_resume_clone_if_idle();
            return;
        default:
            return;
        }
    }
    switch (operation) {
    case 0: {
        if (body_length < 36) {
            update_reply(reply_sequence,0,0,0x1a,0);
            return;
        }
        unsigned char suspended = DEVICE_UPDATE->clone_suspended;
        DEVICE_UPDATE->local_begin_in_progress = 1;
        if (suspended == 0)
            update_suspend_clone();
        unsigned int size_byte1 = bytes[3];
        unsigned int size_byte0 = bytes[2];
        unsigned int size_byte2 = bytes[4];
        unsigned int size_byte3 = bytes[5];
        unsigned int image_size = size_byte0 | (size_byte1 << 8) |
                                  (size_byte2 << 16) | (size_byte3 << 24);
        unsigned int status = update_session_begin(UPDATE_SESSION,
            image_size,payload + 6,&detail);
        unsigned int reply_detail = detail;
        DEVICE_UPDATE->local_begin_in_progress = 0;
        update_reply(reply_sequence,0,0,(unsigned char)status,reply_detail);
        if (status != 1)
            update_resume_clone_if_idle();
        return;
    }
    case 1: {
        if (body_length < 3) {
            update_reply(reply_sequence,1,0,0x1a,1);
            return;
        }
        unsigned int sequence_high = bytes[3];
        unsigned int sequence_low = bytes[2];
        unsigned int chunk_sequence = sequence_low | (sequence_high << 8);
        unsigned char acknowledge = 0;
        unsigned int status = update_session_write(UPDATE_SESSION,
            chunk_sequence,payload + 4,(unsigned short)(length - 4),&detail,&acknowledge);
        if (status != 0) {
            update_reply(reply_sequence,1,0,(unsigned char)status,detail);
            update_resume_clone_if_idle();
        }
        else if (acknowledge != 0) {
            unsigned int reply_detail = detail;
            xPortEnterCriticalTimeout(DEVICE_UPDATE_LOCK,-1);
            unsigned char notification = DEVICE_UPDATE->notification_sequence;
            DEVICE_UPDATE->notification_sequence = (unsigned char)(notification + 1);
            vPortExitCritical(DEVICE_UPDATE_LOCK);
            update_reply(notification,1,0,2,reply_detail);
        }
        return;
    }
    case 2: {
        unsigned int status = update_session_finish(UPDATE_SESSION,&detail);
        update_reply(reply_sequence,2,0,(unsigned char)status,detail);
        if (status != 3)
            update_resume_clone_if_idle();
        return;
    }
    case 3:
        update_session_abort(UPDATE_SESSION);
        update_reply(reply_sequence,3,0,0,0);
        update_resume_clone_if_idle();
        return;
    default:
        return;
    }
}

/* Native entry: 0x4200bf80. */
/* Original function-byte SHA-256:
 * 68021cfe63e2c19bebffe93f27e28cd541f849525c9f2af9d81c8ea5c3085bc1. */
/* Write exactly17 bytes to caller storage; return17. Get local slot/state,
 * then sample host-link BYTE. Selector11/local version3.4.7/local slot/state
 * precede host-known BYTE. For live link, known is read AFTER output byte0;
 * absent link forces known0. Known nonzero snapshots version bytes0,1,2,
 * cached state, then slot; otherwise version0,0,0/slot0xff/state0xff.
 * Bytes12..15 are0,0,15,0. Obtain raw local staged BYTE, reload link BYTE,
 * then host staged BYTE; byte16 is LOW8(local | (host<<1)), no bit masking.
 * If reloaded link nonzero request fresh INFO0x2d/flags0/NULL/0 AFTER building
 * the cached reply; ignore enqueue status. No NULL/capacity/alias checks,
 * coherent cache snapshot, lock or wait for fresh host information. */
unsigned int firmware_info_encode(unsigned char *output)
{
    unsigned char slot,state;
    update_running_slot_info(&slot,&state);
    unsigned char link = DEVICE_UPDATE->host_link_state;
    volatile unsigned char *bytes = output;
    bytes[0] = 11;
    unsigned char known = link != 0 ? DEVICE_UPDATE->host_info_known : 0;
    bytes[1] = 3;
    bytes[2] = 4;
    bytes[3] = 7;
    bytes[4] = slot;
    bytes[5] = state;
    bytes[6] = known;
    unsigned char host_state;
    if (known != 0) {
        unsigned char major = DEVICE_UPDATE->host_version.bytes.major;
        unsigned char minor = DEVICE_UPDATE->host_version.bytes.minor;
        unsigned char patch = DEVICE_UPDATE->host_version.bytes.patch;
        host_state = UPDATE_HOST_CACHE->state;
        unsigned char host_slot = UPDATE_HOST_CACHE->slot;
        bytes[7] = major;
        bytes[8] = minor;
        bytes[9] = patch;
        bytes[10] = host_slot;
    }
    else {
        bytes[7] = 0;
        bytes[8] = 0;
        bytes[9] = 0;
        bytes[10] = 0xff;
        host_state = 0xff;
    }
    bytes[11] = host_state;
    bytes[12] = 0;
    bytes[13] = 0;
    bytes[14] = 15;
    bytes[15] = 0;
    unsigned char local_staged = update_session_is_staged(UPDATE_SESSION);
    link = DEVICE_UPDATE->host_link_state;
    unsigned char host_staged = DEVICE_UPDATE->host_staged;
    bytes[16] = (unsigned char)(local_staged | ((unsigned int)host_staged << 1));
    if (link != 0)
        link_send_wait100(0x2d,0,NULL,0);
    return 17;
}

/* Native entry: 0x4200c88c. */
/* Original function-byte SHA-256:
 * 99391cbda14174a09a361361c406a177ce26e684ef5dc23fe0557be538db9a76. */
/* Delay 60 scheduler ticks, then MEMW and write the FULL value1 to the
 * ROM-download request register, replacing its old word. Call nonreturning
 * esp_restart. No timer conversion, USB/UART drain, acknowledgement or lock. */
void reboot_to_download(void)
{
    vTaskDelay(60);
    memw();
    ROM_DOWNLOAD_REQUEST = 1;
    esp_restart();
}

/* Native entry: 0x4200c8a4. */
/* Original function-byte SHA-256:
 * feda9a80527487a20896e1370e978082a173c13cbd9d1e732d136366c8ef29b7. */
/* Delay 60 scheduler ticks, then call nonreturning esp_restart. This
 * body does not write or clear the ROM-download request register. No drain,
 * acknowledgement, timer conversion, boot selection or lock is supplied. */
void reboot_to_run(void)
{
    vTaskDelay(60);
    esp_restart();
}

/* Native entry: 0x4200cc54. */
/* Original function-byte SHA-256:
 * 6bb8f18637c744222f1682e48ef34db5f2c93ac8adad57eb65741d9115eed931. */
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
        OTA_LOG_HOOK("self-check timed out, rolling back");
    esp_ota_mark_app_invalid_rollback_and_reboot();
}

/* Native entry: 0x4200ce80. */
/* Original function-byte SHA-256:
 * 6a6a5585f12c3056fe1f4f41e4050831e5e382efe6042942d411060674c83388. */
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

/* Native entry: 0x4200ccb4. */
/* Original function-byte SHA-256:
 * e0ed2b7724a1df8c63f613ddc9029e540d7a4f69cbf255d8c29207000793c517. */
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


/* Native entry: 0x4200ccfc. */
/* Original function-byte SHA-256:
 * 5844d64b12d0179353ff80ad48efab9824708b03d17d08b4e72728d3176e73c4. */
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

/* Native entry: 0x4200cd74. */
/* Original function-byte SHA-256:
 * 4e33901383c9a7715272787600a1ceb79f0893501fafd91fb93637618fa1312c. */
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

/* Native entry: 0x4200eae0. */
/* Original function-byte SHA-256:
 * eb36143d8de2580839ada2a728f0de7b80fa2c5e61648c61da340e35039f87ec. */
/* Forward valid=true to the shared SDK current-image marking routine
 * and return its full error code. No local status conversion or extra action;
 * current-image selection and OTA metadata changes belong to that routine. */
int esp_ota_mark_app_valid_cancel_rollback(void)
{
    return esp_ota_current_ota_is_workable(true);
}


/* Native entry: 0x4200eaec. */
/* Original function-byte SHA-256:
 * 410c8b174c6b24816eecc8b810cae5c9d772e8e3604484627f1d870a418d4ae9. */
/* Forward valid=false to the shared SDK marking/rollback routine and
 * return its full error code if it returns. This wrapper is NOT declared
 * nonreturning: rollback/reboot can fail. No local recovery or status mapping. */
int esp_ota_mark_app_invalid_rollback_and_reboot(void)
{
    return esp_ota_current_ota_is_workable(false);
}


/* Native entry: 0x4200cd50. */
/* Original function-byte SHA-256:
 * ae4c0292a9d706035fb6ab1d2c07493acaf32d3334729c63fc1dcdd1a54318ac. */
/* Return canonical true only when the running partition exists, the
 * SDK state query succeeds and its full state word is pending1. NULL/query
 * error/other state returns false. No timer or flag updates and no lock. */
bool ota_running_image_is_pending(void)
{
    const EspPartition *partition = esp_ota_get_running_partition();
    if (partition == NULL)
        return false;
    unsigned int state;
    return esp_ota_get_state_partition(partition,&state) == 0 && state == 1;
}


/* Native entry: 0x4200ce08. */
/* Original function-byte SHA-256:
 * 3083c7f51e31185effa04252bb16667d81c4e241452a0868503f2b0fa749d584. */
/* Stop a snapshot of an existing timer before locking, ignoring stop
 * status. If already claimed, only unlock/return. Otherwise claim1, unlock,
 * log the supplied reason, invoke the optional hook, delay 300 SCHEDULER TICKS
 * and request invalidation/rollback/reboot. The hook is fixed NULL in this
 * device image; its native indirect-call branch cannot run. Ignore rollback
 * result; a returning failure leaves claimed1. No timer delete, rearm, reason
 * validation or millisecond conversion. */
void ota_fail_probation(const char *reason)
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
    unsigned int stamp = esp_log_timestamp();
    esp_log_write(1,UPDATE_LOG_TAG,"E (%lu) %s: %s, rolling back\n",stamp,UPDATE_LOG_TAG,reason);
    if (OTA_LOG_HOOK != NULL)
        OTA_LOG_HOOK("%s, rolling back",reason);
    vTaskDelay(300);
    esp_ota_mark_app_invalid_rollback_and_reboot();
}


/* Native entry: 0x4200b58c. */
/* Original function-byte SHA-256:
 * 9eaa2a7e1eae2b5a748d26fb46a1a3d3f998642cf034116aa26dd9df75104af7. */
/* Under the update spinlock, increment the ignored-abort-answer BYTE unless
 * already255, save LOW32 clock us and reset the pending request HALFWORD to
 * 0xff00. Unlock, then enqueue host ABORT0x2b/flags0/NULL/length0, ignoring
 * success. Even a failed enqueue consumes a future answer-suppression credit.
 * This does not clear relay-active/staged/activation flags or the local session. */
void update_relay_abort(void)
{
    xPortEnterCriticalTimeout(DEVICE_UPDATE_LOCK,-1);
    unsigned char ignored = DEVICE_UPDATE->ignored_abort_answers;
    if (ignored != 255)
        DEVICE_UPDATE->ignored_abort_answers = (unsigned char)(ignored + 1);
    DEVICE_UPDATE->abort_sent_us = (unsigned int)esp_timer_get_time();
    UPDATE_HOST_CACHE->pending_reply = 0xff00;
    vPortExitCritical(DEVICE_UPDATE_LOCK);
    link_send_wait100(0x2b,0,NULL,0);
}


/* Native entry: 0x4200b5dc. */
/* Original function-byte SHA-256:
 * 356f39450f3c2faaba6e935ff0c556cb7860bcb0ba1693b4fce1bd6f69140d91. */
/* Publish LOW16((operation<<8)|sequence) as pending under the spinlock,
 * without masking either full-word input before OR. Unlock and enqueue opcode
 * LOW8, flags0, payload and LOW16 length with the100-tick link wrapper. Return
 * its raw result. On failure log, relock and reset pending to0xff00 regardless
 * of whether another request replaced it. No correlation token, payload checks,
 * caller-state cleanup, acknowledgement wait or lock across enqueue is supplied. */
unsigned int update_relay_request(unsigned int opcode,unsigned int operation,
    unsigned int sequence,const void *payload,unsigned int length)
{
    xPortEnterCriticalTimeout(DEVICE_UPDATE_LOCK,-1);
    UPDATE_HOST_CACHE->pending_reply = (unsigned short)((operation << 8) | sequence);
    vPortExitCritical(DEVICE_UPDATE_LOCK);
    unsigned int enqueued = link_send_wait100((unsigned char)opcode,0,payload,
        (unsigned short)length);
    if (enqueued == 0) {
        unsigned int stamp = esp_log_timestamp();
        esp_log_write(2,DEVICE_UPDATE_TAG,"W (%lu) %s: the link refused a relayed update frame\n",stamp,DEVICE_UPDATE_TAG);
        xPortEnterCriticalTimeout(DEVICE_UPDATE_LOCK,-1);
        UPDATE_HOST_CACHE->pending_reply = 0xff00;
        vPortExitCritical(DEVICE_UPDATE_LOCK);
    }
    return enqueued;
}


/* Native entry: 0x4200b648. */
/* Original function-byte SHA-256:
 * aac874c828bae1779fa1250dae16e65aea1674b2a4e01f448edfa01541a9c777. */
/* Clear suspended BYTE first. If request_reclone is any nonzero full word,
 * set reclone-request BYTE1 under the update spinlock; zero leaves any existing
 * request untouched. Always send host MODE0x2c with one zero byte and log
 * "update over" plus the re-cloning suffix when requested. Enqueue result is
 * ignored; no direct USB re-clone, LED reset or scheduler wait occurs here. */
void update_resume_clone(int request_reclone)
{
    DEVICE_UPDATE->clone_suspended = 0;
    const char *suffix;
    unsigned int stamp;
    if (request_reclone != 0) {
        xPortEnterCriticalTimeout(DEVICE_UPDATE_LOCK,-1);
        DEVICE_UPDATE->reclone_requested = 1;
        vPortExitCritical(DEVICE_UPDATE_LOCK);
        unsigned char enabled = 0;
        link_send_wait100(0x2c,0,&enabled,1);
        stamp = esp_log_timestamp();
        suffix = ", re-cloning";
    }
    else {
        unsigned char enabled = 0;
        link_send_wait100(0x2c,0,&enabled,1);
        stamp = esp_log_timestamp();
        suffix = "";
    }
    esp_log_write(2,DEVICE_UPDATE_TAG,"W (%lu) %s: update over%s\n",stamp,DEVICE_UPDATE_TAG,suffix);
}


/* Native entry: 0x4200b6c4. */
/* Original function-byte SHA-256:
 * 5e4ed17fbf49472b6324811ff53412700614fc3aa6ee144e572aca0bb3b4f687. */
/* Short-circuit gates in native order: local begin not in progress,
 * local session inactive, local session not staged, relay inactive, host not
 * staged, clone currently suspended. Only then request resume with re-cloning.
 * These are separate live reads with no joint lock/recheck. Activation state,
 * link availability and pending-reply word are not gates in this function. */
void update_resume_clone_if_idle(void)
{
    if (DEVICE_UPDATE->local_begin_in_progress != 0)
        return;
    if (update_session_is_active(UPDATE_SESSION) != 0)
        return;
    if (update_session_is_staged(UPDATE_SESSION) != 0)
        return;
    if (DEVICE_UPDATE->relay_active != 0)
        return;
    if (DEVICE_UPDATE->host_staged != 0)
        return;
    if (DEVICE_UPDATE->clone_suspended != 0)
        update_resume_clone(1);
}


/* Native entry: 0x4200b700. */
/* Original function-byte SHA-256:
 * 10c245fa313cc8fb2c767155f527c28d44bda5679aab8f1ed1f1a24a5f429487. */
/* Set suspended BYTE1, save LOW32 clock us for mode refresh, send host
 * MODE0x2c with one byte1, reset clone state/notify host through the identified
 * application boundary, then set LED3 and log. Link enqueue status is ignored.
 * No already-suspended check, lock, rollback of a failed send or direct re-clone. */
void update_suspend_clone(void)
{
    DEVICE_UPDATE->clone_suspended = 1;
    DEVICE_UPDATE->mode_refresh_us = (unsigned int)esp_timer_get_time();
    unsigned char enabled = 1;
    link_send_wait100(0x2c,0,&enabled,1);
    clone_reset_and_notify_host();
    led_set_status(3);
    unsigned int stamp = esp_log_timestamp();
    esp_log_write(2,DEVICE_UPDATE_TAG,"W (%lu) %s: clone down for an update\n",stamp,DEVICE_UPDATE_TAG);
}


/* Native entry: 0x4200b750. */
/* Original function-byte SHA-256:
 * acdf7fffd65fc8eedcf6a3f790f39a1aec0646dcf6e3f08bf195ca51f7fc4799. */
/* Under the update spinlock, snapshot the reclone-request BYTE and clear
 * it to0; unlock and return its saved raw value, without boolean normalization.
 * No cloning, allocation, link message or other flag reset occurs here. */
unsigned char update_take_reclone_request(void)
{
    xPortEnterCriticalTimeout(DEVICE_UPDATE_LOCK,-1);
    unsigned char requested = DEVICE_UPDATE->reclone_requested;
    DEVICE_UPDATE->reclone_requested = 0;
    vPortExitCritical(DEVICE_UPDATE_LOCK);
    return requested;
}


/* Native entry: 0x4200b774. */
/* Original function-byte SHA-256:
 * c76ca4259f7816a4d562e6b4006c7984a1e175d05164332d72e34d31c0b5709a. */
/* Obtain storage operations, hash operations and backend context in that
 * order, then reset the shared64-byte local session. No prior abort, activity
 * clock write, explicit ack-interval override, validation, lock or result.
 * Unlike host initialization, the cleared interval remains0 (effective16). */
void device_update_session_init(void)
{
    const UpdateStorageOps *storage = update_storage_operations();
    const UpdateHashOps *hash = update_hash_operations();
    void *context = update_backend_context();
    update_session_initialize(UPDATE_SESSION,storage,hash,context);
}


/* Native entry: 0x4200b794. */
/* Original function-byte SHA-256:
 * d2865e0717dd8bc593084a3283ecbf49b36a74fcb9934cbd87edc7889706fc2e. */
/* Return the live suspended BYTE unchanged. No lock, normalization or calls. */
unsigned char update_clone_is_suspended(void)
{
    return DEVICE_UPDATE->clone_suspended;
}


/* Native entry: 0x4200bd18. */
/* Original function-byte SHA-256:
 * 40ac322722e0e6019f5f9446e0e6eb2fa5c0b7d5bd16a32f98c97bad650cf44f. */
/* Host INFO0x2e needs6 bytes. Cache version HALFWORD from bytes1,0; read
 * slot3 and publish, then state4 and staged5; normalize staged, increment the
 * generation HALFWORD modulo16, publish patch2, then known1. No lock/epoch
 * publication barrier: readers can observe a partially refreshed cache.
 * ANSWER0x29 needs5 bytes; detail reads2,1,3,4, then status0. Refresh LOW32
 * activity. Under lock, abort-suppression credits expire only when signed32
 * elapsed>500,000us. Otherwise consume one credit and, if activation-answer
 * pending was sampled nonzero, clear it too; drop the answer regardless status.
 * Without suppression, pending activation consumes the answer: clear its BYTE,
 * unlock, and on nonzero status relock/store error BYTE then detail WORD.
 * Otherwise snapshot pending request HALFWORD under lock. Op0xff drops reply;
 * status3 marks host staged, status>=3 clears relay-active, op2/3 also clears it.
 * Op1 uses and increments the separate notification sequence BYTE under lock;
 * other ops use the saved request sequence. Send7 bytes {op,1,status,detailLE}
 * as control0x18. Op3 then resets pending to0xff00 WITHOUT lock and tries idle
 * resume; other ops try resume only for status>=4. No request/response token,
 * rollback on send failure, bounds beyond minimum lengths or payload NULL guard. */
void update_receive_host_reply(unsigned char opcode,
    const unsigned char *payload,unsigned short length)
{
    const volatile unsigned char *bytes = payload;
    if (opcode == 0x2e) {
        if (length < 6)
            return;
        unsigned int minor = bytes[1];
        unsigned int major = bytes[0];
        unsigned char slot = bytes[3];
        DEVICE_UPDATE->host_version.major_minor = (unsigned short)(major | (minor << 8));
        UPDATE_HOST_CACHE->slot = slot;
        unsigned char state = bytes[4];
        unsigned char staged = bytes[5];
        UPDATE_HOST_CACHE->state = state;
        unsigned short generation = DEVICE_UPDATE->host_info_generation;
        DEVICE_UPDATE->host_staged = staged != 0;
        unsigned char patch = bytes[2];
        DEVICE_UPDATE->host_info_generation = (unsigned short)(generation + 1);
        DEVICE_UPDATE->host_version.bytes.patch = patch;
        DEVICE_UPDATE->host_info_known = 1;
        return;
    }
    if (opcode != 0x29 || length < 5)
        return;
    unsigned int detail_byte1 = bytes[2];
    unsigned int detail_byte0 = bytes[1];
    unsigned int detail_byte2 = bytes[3];
    unsigned int detail_byte3 = bytes[4];
    unsigned char status = bytes[0];
    unsigned int detail = detail_byte0 | (detail_byte1 << 8) |
                          (detail_byte2 << 16) | (detail_byte3 << 24);
    DEVICE_UPDATE->last_activity_us = (unsigned int)esp_timer_get_time();
    xPortEnterCriticalTimeout(DEVICE_UPDATE_LOCK,-1);
    if (DEVICE_UPDATE->ignored_abort_answers != 0) {
        unsigned int now_us = (unsigned int)esp_timer_get_time();
        unsigned int elapsed = now_us - DEVICE_UPDATE->abort_sent_us;
        unsigned char activation_pending = DEVICE_UPDATE->activation_answer_pending;
        if ((int)elapsed > 500000) {
            DEVICE_UPDATE->ignored_abort_answers = 0;
        }
        else {
            unsigned char ignored = DEVICE_UPDATE->ignored_abort_answers;
            if (ignored != 0) {
                DEVICE_UPDATE->ignored_abort_answers = (unsigned char)(ignored - 1);
                if (activation_pending != 0)
                    DEVICE_UPDATE->activation_answer_pending = 0;
                vPortExitCritical(DEVICE_UPDATE_LOCK);
                return;
            }
        }
    }
    if (DEVICE_UPDATE->activation_answer_pending != 0) {
        DEVICE_UPDATE->activation_answer_pending = 0;
        vPortExitCritical(DEVICE_UPDATE_LOCK);
        if (status != 0) {
            xPortEnterCriticalTimeout(DEVICE_UPDATE_LOCK,-1);
            DEVICE_UPDATE->activation_error = status;
            DEVICE_UPDATE->activation_error_detail = detail;
            vPortExitCritical(DEVICE_UPDATE_LOCK);
        }
        return;
    }
    unsigned short pending = UPDATE_HOST_CACHE->pending_reply;
    vPortExitCritical(DEVICE_UPDATE_LOCK);
    unsigned char operation = (unsigned char)(pending >> 8);
    if (operation == 0xff)
        return;
    if (status == 3)
        DEVICE_UPDATE->host_staged = 1;
    if (status >= 3)
        DEVICE_UPDATE->relay_active = 0;
    unsigned char sequence = (unsigned char)pending;
    if (operation == 2 || operation == 3)
        DEVICE_UPDATE->relay_active = 0;
    else if (operation == 1) {
        xPortEnterCriticalTimeout(DEVICE_UPDATE_LOCK,-1);
        sequence = DEVICE_UPDATE->notification_sequence;
        DEVICE_UPDATE->notification_sequence = (unsigned char)(sequence + 1);
        vPortExitCritical(DEVICE_UPDATE_LOCK);
    }
    UpdateResponse response;
    response.operation = operation;
    response.target = 1;
    response.status = status;
    response.detail[0] = (unsigned char)detail;
    response.detail[1] = (unsigned char)(detail >> 8);
    response.detail[2] = (unsigned char)(detail >> 16);
    response.detail[3] = (unsigned char)(detail >> 24);
    control_send_frame(0x18,sequence,&response,7);
    if (operation == 3) {
        UPDATE_HOST_CACHE->pending_reply = 0xff00;
        update_resume_clone_if_idle();
    }
    else if (status >= 4)
        update_resume_clone_if_idle();
}


/* Native entry: 0x4200bf0c. */
/* Original function-byte SHA-256:
 * 61d33403b1efeac75b8c31793b20d9cc3249aaf4ae515011dd90fae541781fe0. */
/* Compare/store LOW8 state exactly, without boolean normalization. Unchanged
 * returns. New nonzero saves LOW32 query clock and sends INFO0x2d/flags0/NULL/0.
 * New zero clears known, writes slot then state0xff, clears ignored-abort BYTE
 * under lock, then clears host-staged and relay-active outside it. Cached version,
 * generation, pending request, activation and suspended flags are retained. */
void update_set_host_link_state(unsigned char state)
{
    if (DEVICE_UPDATE->host_link_state == state)
        return;
    DEVICE_UPDATE->host_link_state = state;
    if (state != 0) {
        DEVICE_UPDATE->host_info_query_us = (unsigned int)esp_timer_get_time();
        link_send_wait100(0x2d,0,NULL,0);
        return;
    }
    DEVICE_UPDATE->host_info_known = 0;
    UPDATE_HOST_CACHE->slot = 0xff;
    UPDATE_HOST_CACHE->state = 0xff;
    xPortEnterCriticalTimeout(DEVICE_UPDATE_LOCK,-1);
    DEVICE_UPDATE->ignored_abort_answers = 0;
    vPortExitCritical(DEVICE_UPDATE_LOCK);
    DEVICE_UPDATE->host_staged = 0;
    DEVICE_UPDATE->relay_active = 0;
}

/* Native entry: 0x4200c060. */
/* Original function-byte SHA-256:
 * 44dbada61ee4abd5ecf4626e385d9658ec54502b43e3fd96f62f63bc5534ef68. */
/* Periodic service, now_us is the caller's LOW32 microsecond clock. Every
 * elapsed test subtracts modulo32 then compares SIGNED, strictly greater than
 * its threshold; bit31 therefore suppresses expiry. No software timer or task
 * is created here. Actual service cadence and scheduler latency are unmeasured.
 * Suspended+linked refreshes MODE1 after2,000,000us. Native entry paths retain
 * different link/suspended rechecks; idle_path below records that branch choice.
 * State1 waits for host activation: an error first sampled nonzero is reloaded
 * under lock, CLEARED before detail is read, logged, then host staged cleared/
 * optional abort sent/pending answer cleared. Rechecked state1 becomes0; report
 * saved error/detail and try idle resume. Without error, wait>1,000,000us, then
 * accept known host info only if BOTH generation16 and slot8 changed from their
 * saved values; recheck state1 under lock and set2/clear pending. This is a
 * cache-change heuristic, not proof of firmware bytes or successful probation.
 * Otherwise >20,000,000us logs timeout, conditionally clears state/pending,
 * reports0x18 and resumes with re-cloning, retaining local staged/host flags.
 * While waiting and linked, poll INFO after500,000us.
 * State2: no local stage reports success, clears state and resumes re-cloning.
 * A local stage suspends clone if needed; linked host gets MODE1 then a delay
 * of20 scheduler ticks. Activate local partition. Failure replies0x19 for-1000
 * or0x16 otherwise with raw detail, aborts session, clears state and resumes.
 * Success replies0, resumes without requesting re-clone, sets state3 and saves
 * a FRESH clock. State3 waits>200,000us, then reboot helper adds60 scheduler
 * ticks before restart. Sends are not delivery acknowledgements.
 * Idle paths query unknown linked host after1,000,000us and active relay after
 * 300,000us (relay poll does not require link). If suspended and inactive for
 * >10,000,000us, abort active local session; a live relay gets0x18 using the
 * pending operation/sequence, optional host abort, then relay/staged clear.
 * Reset pending0xff00 outside lock; a previously sampled suspended BYTE decides
 * whether to resume with re-cloning. Unlocked/live reads and native order remain;
 * no additional cleanup, retry, cryptographic validation or timing guarantee. */
void update_service(unsigned int now_us)
{
    enum { CHECK_LINK, LINK_ASSUMED_UP, LINK_ASSUMED_DOWN } idle_path;
    if (DEVICE_UPDATE->clone_suspended == 0) {
        idle_path = CHECK_LINK;
    }
    else if (DEVICE_UPDATE->host_link_state == 0) {
        idle_path = LINK_ASSUMED_DOWN;
    }
    else if ((int)(now_us - DEVICE_UPDATE->mode_refresh_us) > 2000000) {
        DEVICE_UPDATE->mode_refresh_us = now_us;
        unsigned char enabled = 1;
        link_send_wait100(0x2c,0,&enabled,1);
        idle_path = CHECK_LINK;
    }
    else {
        idle_path = LINK_ASSUMED_UP;
    }
    unsigned char activation = DEVICE_UPDATE->activation_state;
    if (activation == 1) {
        unsigned char error = DEVICE_UPDATE->activation_error;
        if (error != 0) {
            xPortEnterCriticalTimeout(DEVICE_UPDATE_LOCK,-1);
            error = DEVICE_UPDATE->activation_error;
            DEVICE_UPDATE->activation_error = 0;
            unsigned int detail = DEVICE_UPDATE->activation_error_detail;
            vPortExitCritical(DEVICE_UPDATE_LOCK);
            unsigned int stamp = esp_log_timestamp();
            esp_log_write(1,DEVICE_UPDATE_TAG,"E (%lu) %s: the other chip refused to commit (%u)\n",stamp,DEVICE_UPDATE_TAG,error);
            unsigned char link = DEVICE_UPDATE->host_link_state;
            DEVICE_UPDATE->host_staged = 0;
            if (link != 0)
                update_relay_abort();
            DEVICE_UPDATE->activation_answer_pending = 0;
            xPortEnterCriticalTimeout(DEVICE_UPDATE_LOCK,-1);
            if (DEVICE_UPDATE->activation_state != 1) {
                vPortExitCritical(DEVICE_UPDATE_LOCK);
                return;
            }
            DEVICE_UPDATE->activation_state = 0;
            vPortExitCritical(DEVICE_UPDATE_LOCK);
            unsigned char sequence = DEVICE_UPDATE->activation_sequence;
            update_reply(sequence,4,0,error,detail);
            update_resume_clone_if_idle();
            return;
        }
        int elapsed_us = (int)(now_us - DEVICE_UPDATE->activation_started_us);
        if (elapsed_us <= 1000000)
            return;
        if (DEVICE_UPDATE->host_info_known != 0 &&
            DEVICE_UPDATE->host_info_generation != DEVICE_UPDATE->activation_initial_generation &&
            UPDATE_HOST_CACHE->slot != UPDATE_HOST_CACHE->activation_initial_slot) {
            xPortEnterCriticalTimeout(DEVICE_UPDATE_LOCK,-1);
            if (DEVICE_UPDATE->activation_state == 1) {
                DEVICE_UPDATE->activation_state = 2;
                DEVICE_UPDATE->activation_answer_pending = error; /* saved zero */
            }
            vPortExitCritical(DEVICE_UPDATE_LOCK);
            return;
        }
        if (elapsed_us > 20000000) {
            unsigned int stamp = esp_log_timestamp();
            esp_log_write(1,DEVICE_UPDATE_TAG,"E (%lu) %s: the other chip did not come back on the new image\n",stamp,DEVICE_UPDATE_TAG);
            xPortEnterCriticalTimeout(DEVICE_UPDATE_LOCK,-1);
            if (DEVICE_UPDATE->activation_state != 1) {
                vPortExitCritical(DEVICE_UPDATE_LOCK);
                return;
            }
            DEVICE_UPDATE->activation_answer_pending = 0;
            DEVICE_UPDATE->activation_state = 0;
            vPortExitCritical(DEVICE_UPDATE_LOCK);
            unsigned char sequence = DEVICE_UPDATE->activation_sequence;
            update_reply(sequence,4,0,0x18,0);
            if (DEVICE_UPDATE->clone_suspended != 0)
                update_resume_clone(1);
            return;
        }
        if (DEVICE_UPDATE->host_link_state != 0 &&
            (int)(now_us - DEVICE_UPDATE->activation_poll_us) > 500000) {
            DEVICE_UPDATE->activation_poll_us = now_us;
            link_send_wait100(0x2d,0,NULL,0);
        }
        return;
    }
    if (activation == 2) {
        if (update_session_is_staged(UPDATE_SESSION) == 0) {
            unsigned char sequence = DEVICE_UPDATE->activation_sequence;
            update_reply(sequence,4,0,0,0);
            unsigned char suspended = DEVICE_UPDATE->clone_suspended;
            DEVICE_UPDATE->activation_state = 0;
            if (suspended != 0)
                update_resume_clone(1);
            return;
        }
        if (DEVICE_UPDATE->clone_suspended == 0)
            update_suspend_clone();
        if (DEVICE_UPDATE->host_link_state != 0) {
            DEVICE_UPDATE->mode_refresh_us = (unsigned int)esp_timer_get_time();
            unsigned char enabled = 1;
            link_send_wait100(0x2c,0,&enabled,1);
            vTaskDelay(20);
        }
        int result = update_activate_staged();
        unsigned char sequence = DEVICE_UPDATE->activation_sequence;
        if (result != 0) {
            update_reply(sequence,4,0,result == -1000 ? 0x19 : 0x16,(unsigned int)result);
            update_session_abort(UPDATE_SESSION);
            unsigned char suspended = DEVICE_UPDATE->clone_suspended;
            DEVICE_UPDATE->activation_state = 0;
            if (suspended != 0)
                update_resume_clone(1);
            return;
        }
        update_reply(sequence,4,0,0,0);
        if (DEVICE_UPDATE->clone_suspended != 0)
            update_resume_clone(0);
        DEVICE_UPDATE->activation_state = 3;
        DEVICE_UPDATE->activation_started_us = (unsigned int)esp_timer_get_time();
        return;
    }
    if (activation == 3) {
        if ((int)(now_us - DEVICE_UPDATE->activation_started_us) > 200000)
            reboot_to_run();
        return;
    }
    /* These three idle entry paths retain native link/suspension snapshots. */
    if (idle_path == LINK_ASSUMED_DOWN) {
        if (DEVICE_UPDATE->relay_active != 0)
            goto poll_staged_host;
        goto check_update_idle;
    }
    if (idle_path == LINK_ASSUMED_UP || DEVICE_UPDATE->host_link_state != 0) {
        if (DEVICE_UPDATE->host_info_known == 0 &&
            (int)(now_us - DEVICE_UPDATE->host_info_query_us) > 1000000) {
            DEVICE_UPDATE->host_info_query_us = now_us;
            link_send_wait100(0x2d,0,NULL,0);
        }
    }
    if (DEVICE_UPDATE->relay_active != 0) {
    poll_staged_host:
        if ((int)(now_us - DEVICE_UPDATE->staging_query_us) > 300000) {
            DEVICE_UPDATE->staging_query_us = now_us;
            link_send_wait100(0x2d,0,NULL,0);
        }
    }
    if (DEVICE_UPDATE->clone_suspended == 0)
        return;
check_update_idle:
    if ((int)(now_us - DEVICE_UPDATE->last_activity_us) <= 10000000)
        return;
    if (update_session_is_active(UPDATE_SESSION) != 0) {
        unsigned int stamp = esp_log_timestamp();
        esp_log_write(2,DEVICE_UPDATE_TAG,"W (%lu) %s: update went quiet, dropping it\n",stamp,DEVICE_UPDATE_TAG);
        update_session_abort(UPDATE_SESSION);
    }
    if (DEVICE_UPDATE->relay_active != 0) {
        unsigned int stamp = esp_log_timestamp();
        esp_log_write(2,DEVICE_UPDATE_TAG,"W (%lu) %s: the relayed update went quiet, dropping it\n",stamp,DEVICE_UPDATE_TAG);
        unsigned short pending = UPDATE_HOST_CACHE->pending_reply;
        if ((pending >> 8) != 0xff)
            update_reply((unsigned char)pending,(unsigned char)(pending >> 8),1,0x18,0);
        if (DEVICE_UPDATE->host_link_state != 0)
            update_relay_abort();
        DEVICE_UPDATE->relay_active = 0;
        DEVICE_UPDATE->host_staged = 0;
    }
    unsigned char suspended = DEVICE_UPDATE->clone_suspended;
    UPDATE_HOST_CACHE->pending_reply = 0xff00;
    if (suspended != 0)
        update_resume_clone(1);
}

