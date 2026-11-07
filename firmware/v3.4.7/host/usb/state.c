/* Medius v3.4.7 host — usb/state.c.
 * Recovered C and native assembly, grouped for source navigation.
 * Original entry addresses, firmware-byte hashes and function comments follow.
 */

#include "../include/types.h"

/* Source reconstruction utilities: four identical backlog waits inside
 * native420294c4. No additional native entry. The caller caches started once;
 * only a nonzero queue predicate samples elapsed, and timeout still proceeds. */
static void medius_generation_wait_out(unsigned int generation,unsigned long long started)
{
    while (medius_out_has_queued_through(generation) != 0) {
        unsigned long long elapsed = (unsigned long long)esp_timer_get_time() - started;
        if ((long long)elapsed > 49999LL) break;
        vTaskDelay(1);
    }
}

/* Native entry: 0x40376efc. */
/* Original function-byte SHA-256:
 * 5a8218e4085df6dce78106d628045ceb41c888424d9533bed0f5935253102aa1. */
/* Fence, then return the raw last ordered-acknowledgement byte. No boolean
 * normalization, lock, acknowledgement consumption or other state change. */
unsigned char medius_ordered_get_last_ack(void)
{
    memw();
    return MEDIUS_HOST_ORDERED_LAST_ACK;
}

/* Native entry: 0x40389f5c. */
/* Original function-byte SHA-256:
 * db6a7f404931f697e31412486152d3ba90bc6185c52fd2bd764402acf1a0a7e4. */
/* Fence and return the raw forwarding-inhibit byte. Nonzero values remain
 * distinct; the accessor neither clears the flag nor synchronizes workers. */
unsigned char medius_host_get_forwarding_inhibit(void)
{
    memw();
    return MEDIUS_HOST_FORWARDING_INHIBIT;
}

/* Native entry: 0x42026640. */
/* Original function-byte SHA-256:
 * bb65c69fde436f6b39963bdfc5069e4e187185ac8dcdb6c37f885e0433a3e94a. */
/* Append one ordered12-byte change with native coalescing/overflow policy.
 * command/arg1/arg2: Raw32 inputs; store low16(command|arg1<<8), low8 arg2.
 * ack_tag: Raw signed16. No return, eviction acknowledgement or failure path.
 * Lock ordered mux indefinitely; ignore status. Cache byte count then head.
 * Only command EXACTLY FC coalesces with a matching tail FC and FULL arg1/arg2
 * equal to its stored bytes; ack_tag is ignored. Coalescing only unlocks.
 *
 * At count8, first remove the oldest FC, shifting its suffix as three32-bit
 * words per record and publishing count7 before the later append. Otherwise
 * incoming EXACT FF discards all records at the normalized old head. Other
 * commands search logical7..1 for the newest FF and retain its suffix. With
 * no such marker, remove newest non-FE in7..1, or slot0 if all those are FE.
 * Marker0 is excluded. Shifts preserve all padding and native word ordering.
 * Normal count0..8 is required; corrupt byte values are not rejected locally.
 *
 * Fence/read generation for the entry, then fence/read generation AGAIN for
 * the later increment. Store command/arg1 HALFWORD, arg2 byte, ack16, count;
 * fence/publish second generation+1 modulo32. Only exact FF increments epoch.
 * Padding+7/+10..11 remains stale on append. Unlock then sample worker once
 * and notify action2/index0/value0 when nonNULL; ignore notification result.
 * No serial-number wrap ordering, payload validation or atomicity beyond the
 * delegated mux is supplied. Two generation reads need not form one snapshot. */
void medius_ordered_change_enqueue(unsigned int command,unsigned int arg1,
    unsigned int arg2,short ack_tag)
{
    xPortEnterCriticalTimeout(&MEDIUS_HOST_ORDERED_LOCK,-1);
    unsigned int count = MEDIUS_HOST_ORDERED_COUNT;
    unsigned int head = MEDIUS_HOST_ORDERED_HEAD;
    unsigned short command_and_arg1 = (unsigned short)(command | (arg1 << 8));
    if (command == 0xfc && count != 0) {
        volatile MediusOrderedChange *tail = &MEDIUS_HOST_ORDERED_CHANGES[(head + count - 1U) & 7U];
        if (tail->command == 0xfc && tail->arg1 == arg1 && tail->arg2 == arg2) {
            vPortExitCritical(&MEDIUS_HOST_ORDERED_LOCK);
            return;
        }
    }
    unsigned int append = count;
    unsigned char next_count = (unsigned char)(count + 1U);
    if (count == 8) {
        unsigned int remove;
        for (remove = 0; remove < 8; ++remove)
            if (MEDIUS_HOST_ORDERED_CHANGES[(head + remove) & 7U].command == 0xfc) break;
        if (remove < 8) {
            for (unsigned int position = remove; position < 7; ++position) {
                volatile MediusOrderedChange *from = &MEDIUS_HOST_ORDERED_CHANGES[(head + position + 1U) & 7U];
                volatile MediusOrderedChange *to = &MEDIUS_HOST_ORDERED_CHANGES[(head + position) & 7U];
                unsigned int generation = from->words[0];
                unsigned int arguments = from->words[1];
                to->words[0] = generation;
                unsigned int acknowledgement = from->words[2];
                to->words[1] = arguments;
                to->words[2] = acknowledgement;
            }
            MEDIUS_HOST_ORDERED_COUNT = 7;
            append = 7;
            next_count = 8;
        } else if (command == 0xff) {
            head = (head + 8U) & 7U;
            MEDIUS_HOST_ORDERED_HEAD = (unsigned char)head;
            append = 0;
            next_count = 1;
        } else {
            unsigned int marker;
            for (marker = 7; marker != 0; --marker)
                if (MEDIUS_HOST_ORDERED_CHANGES[(head + marker) & 7U].command == 0xff) break;
            if (marker != 0) {
                append = (8U - marker) & 255U;
                next_count = (unsigned char)(9U - marker);
                head = (head + marker) & 7U;
                MEDIUS_HOST_ORDERED_HEAD = (unsigned char)head;
            } else {
                for (remove = 7; remove != 0; --remove)
                    if (MEDIUS_HOST_ORDERED_CHANGES[(head + remove) & 7U].command != 0xfe) break;
                for (unsigned int position = remove; position < 7; ++position) {
                    volatile MediusOrderedChange *from = &MEDIUS_HOST_ORDERED_CHANGES[(head + position + 1U) & 7U];
                    volatile MediusOrderedChange *to = &MEDIUS_HOST_ORDERED_CHANGES[(head + position) & 7U];
                    unsigned int generation = from->words[0];
                    unsigned int arguments = from->words[1];
                    to->words[0] = generation;
                    unsigned int acknowledgement = from->words[2];
                    to->words[1] = arguments;
                    to->words[2] = acknowledgement;
                }
                append = 7;
                next_count = 8;
            }
        }
    }
    volatile MediusOrderedChange *entry = &MEDIUS_HOST_ORDERED_CHANGES[(head + append) & 7U];
    memw(); entry->generation = MEDIUS_HOST_CURRENT_GENERATION;
    memw(); unsigned int generation = MEDIUS_HOST_CURRENT_GENERATION;
    entry->command_and_arg1 = command_and_arg1;
    entry->arg2 = (unsigned char)arg2;
    entry->ack_tag = ack_tag;
    MEDIUS_HOST_ORDERED_COUNT = next_count;
    memw(); MEDIUS_HOST_CURRENT_GENERATION = generation + 1U;
    if (command == 0xff) MEDIUS_HOST_ORDERED_EPOCH = MEDIUS_HOST_ORDERED_EPOCH + 1U;
    vPortExitCritical(&MEDIUS_HOST_ORDERED_LOCK);
    RtosTask *worker = MEDIUS_HOST_CONTROL_WORKER_TASK;
    if (worker != NULL) xTaskGenericNotify(worker,0,0,2,NULL);
}

/* Native entry: 0x42027234. */
/* Original function-byte SHA-256:
 * 1e01003bf32212f4e723f921f6a1fc6acbbf3a11d52d20e2b2a171296021c348. */
/* Apply cached desired remote-wakeup policy locally, then mirror upstream.
 * port/started_us: Live port and original retry-window reference; no local
 * port/parent NULL check. Sample desired byte ONCE; zero chooses CLEAR_FEATURE1,
 * any nonzero SET_FEATURE3. Fence/set activity, then retry(port,start,0,request,1,0,0).
 * Cache parent pointer AFTER retry but BEFORE applied-byte publication. Result
 * >=0 or-8 caches original raw desired; other negative cachesFF (unknown/error).
 * This policy does not prove that a STALLed request was accepted by the device.
 *
 * For cached non-root parent, sample upstream pointer and connected. Even after
 * first-request failure, a connected upstream receives the same request/value1.
 * Cache its mutex BEFORE shared SETUP stores: value16,type0,request,index+length
 * as one32-bit zero. Take cached mutex; populate upstream URB in native order,
 * timeout100/remaining0/shared data/NULL completion. Ignore submit result (and
 * actual), then give freshly read mutex. No lock around shared SETUP publication,
 * rollback, post-transfer connection check or coherent parent/policy snapshot. */
void medius_host_apply_remote_wakeup(MediusHostHubPortPrefix *port,long long started_us)
{
    unsigned char desired = MEDIUS_HOST_POWER->desired_remote_wakeup;
    unsigned int request = desired != 0 ? 3 : 1;
    memw(); MEDIUS_HOST_CONTROL_ACTIVITY = 1;
    int result = medius_host_control_retry(port,started_us,0,request,1,0,0);
    MediusHostHubPrefix *parent = ((volatile MediusHostHubPortPrefix *)port)->parent;
    MEDIUS_HOST_POWER->applied_remote_wakeup = (result >= 0 || result == -8) ? desired : 0xff;
    volatile MediusHostHubPrefix *live_parent = parent;
    unsigned char root = live_parent->is_root;
    if (root != 0) return;
    MediusHostHubPortPrefix *upstream = live_parent->upstream_port;
    if (upstream == NULL || ((volatile MediusHostHubPortPrefix *)upstream)->connected == 0) return;
    volatile MediusUsbSetup *setup = MEDIUS_HOST_SHARED_SETUP;
    void *mutex = ((volatile MediusHostHubPortPrefix *)upstream)->control_mutex;
    setup->value = 1;
    setup->request_type = root;
    setup->request = (unsigned char)request;
    ((volatile unsigned int *)setup)[1] = root;
    usb_osal_mutex_take(mutex);
    volatile MediusHostUrb *urb = &upstream->control_urb;
    urb->endpoint = upstream->ep0_descriptor;
    urb->hubport = upstream;
    urb->buffer = MEDIUS_HOST_CONTROL_DATA;
    urb->setup = (unsigned char *)setup;
    urb->remaining = root;
    urb->timeout = 100;
    urb->complete = NULL;
    urb->context = NULL;
    usbh_submit_urb((MediusHostUrb *)urb);
    usb_osal_mutex_give(((volatile MediusHostHubPortPrefix *)upstream)->control_mutex);
}

/* Native entry: 0x42027c40. */
/* Original function-byte SHA-256:
 * 2e5f729ae6a98a890230474c60b10251f7167dd41e0af11a5426a6011eba6ad8. */
/* Fence and sample the current unsigned32 configuration generation. No lock,
 * increment, normalization or pairing with the applied generation occurs. */
unsigned int medius_host_get_current_generation(void)
{
    memw();
    return MEDIUS_HOST_CURRENT_GENERATION;
}

/* Native entry: 0x42027c50. */
/* Original function-byte SHA-256:
 * 47677219f257816687b682586d7699c355f1f6343318aae194efb8479daf0bea. */
/* Get the calling task, then sample the registered control-worker handle.
 * Equal handles permit a fenced read of the active control generation;
 * otherwise return UINT_MAX. The handle read has no preceding native fence.
 * NULL equals NULL here too. No registration, locking or validity test occurs. */
unsigned int medius_host_get_control_generation(void)
{
    RtosTask *current = xTaskGetCurrentTaskHandle();
    if (MEDIUS_HOST_CONTROL_WORKER_TASK != current)
        return 0xffffffffU;
    memw();
    return MEDIUS_HOST_ACTIVE_CONTROL_GENERATION;
}

/* Native entry: 0x42027c70. */
/* Original function-byte SHA-256:
 * ecbbfc2932843da6650dff84dba1fb9f8568019b2260b8656fcba7640f175318. */
/* Fence and sample applied generation once. Return0/1 for unsigned32
 * generation<=applied. This is ordinary ordering, without wraparound/serial
 * number treatment, and does not wait for application or modify state. */
unsigned char medius_host_generation_is_applied(unsigned int generation)
{
    memw();
    unsigned int applied = MEDIUS_HOST_APPLIED_GENERATION;
    return (unsigned char)(generation <= applied);
}

/* Native entry: 0x42028c58. */
/* Original function-byte SHA-256:
 * 653fb4875bd0a1f38683578bfbba9f2e6cd2e956230887a2b0196e2b438c9b50. */
/* Configuration-switch task: consume a signal and restart host bus zero.
 * No argument/result; loops forever. Reload the signal queue for each infinite
 * take; only exact result1 proceeds. Fence/publish restart=1, sample time,
 * then fence/sample control-busy. While busy, wait one tick only when current
 * signed64 time is strictly before modulo64(start+600000); recheck busy after
 * each delay. Deadline expiry permits restart even while control remains busy.
 *
 * Fence/test precapture; only when zero fence/test recovery-active. If both
 * zero, fence/set configuration-switch gate1; otherwise retain that gate.
 * Always fence/clear recovery-active, then fence/sample requested selector for
 * logging. Block frame-interval updates, deinitialize bus0, delay50 ticks,
 * initialize bus0 at60080000 with the same host event callback, resume frame
 * interval updates, then fence/clear restart. Ignore all delegated statuses.
 * The selector is already published shared state, not an initialization arg.
 * No rollback, control cancellation or lock/lifetime guarantee is added.
 * Task priority6/core0, stack8192 bytes; programmed delays are scheduler ticks,
 * not measured elapsed time. A queue failure retries without local backoff. */
void medius_task_cfgswitch(void)
{
    for (;;) {
        while (xQueueSemaphoreTake(MEDIUS_HOST_CONFIGURATION_QUEUE,0xffffffffU) != 1) { }
        memw(); MEDIUS_HOST_RESTART_GATE = 1;
        unsigned long long started_us = (unsigned long long)esp_timer_get_time();
        memw(); unsigned char busy = MEDIUS_HOST_CONTROL_BUSY;
        unsigned long long deadline_us = started_us + 600000ULL;
        while (busy != 0) {
            long long now_us = esp_timer_get_time();
            if (now_us >= (long long)deadline_us) break;
            vTaskDelay(1);
            memw(); busy = MEDIUS_HOST_CONTROL_BUSY;
        }
        memw();
        if (MEDIUS_HOST_PRECAPTURE_STATE == 0) {
            memw();
            if (MEDIUS_HOST_RECOVERY_ACTIVE == 0) {
                memw(); MEDIUS_HOST_CONFIGURATION_SWITCH_GATE = 1;
            }
        }
        memw(); MEDIUS_HOST_RECOVERY_ACTIVE = 0;
        memw(); unsigned char selector = MEDIUS_HOST_REQUESTED_CONFIGURATION;
        medius_host_log_formatted("restarting the host stack into configuration index %u",selector);
        medius_host_block_frame_interval_updates();
        usbh_deinitialize(0);
        vTaskDelay(50);
        usbh_initialize(0,0x60080000U,medius_usb_host_event_callback);
        medius_host_resume_frame_interval_updates();
        memw(); MEDIUS_HOST_RESTART_GATE = 0;
    }
}

/* Native entry: 0x42028d34. */
/* Original function-byte SHA-256:
 * 631f296c832ce7efa811df86d453224a31f5af5a0894deb11ec6e7205e8ba9f9. */
/* Request immediate/deferred re-enumeration under sampled recovery gates.
 * reason: Borrowed string used as data with fixed format. force_identity_refresh:
 * full32 nonzero sets identity-refresh1; zero leaves any old identity flag.
 * Fence/set activity first, then optionally identity flag. Fence/test restart,
 * switch and precapture gates in order; any nonzero returns silently. Next
 * fence/sample forwarding-inhibit. Zero plus nonNULL recovery queue logs the
 * immediate path then schedules with the ORIGINAL force value, without a
 * post-log gate recheck. Otherwise fence/set deferred1, then log delayed recovery.
 * No return/status, mutex, generation change or queue-lifetime guarantee here. */
void medius_host_request_recovery(const char *reason,int force_identity_refresh)
{
    memw(); MEDIUS_HOST_CONTROL_ACTIVITY = 1;
    if (force_identity_refresh != 0) { memw(); MEDIUS_HOST_IDENTITY_REFRESH = 1; }
    memw(); if (MEDIUS_HOST_RESTART_GATE != 0) return;
    memw(); if (MEDIUS_HOST_CONFIGURATION_SWITCH_GATE != 0) return;
    memw(); if (MEDIUS_HOST_PRECAPTURE_STATE != 0) return;
    memw();
    if (MEDIUS_HOST_FORWARDING_INHIBIT == 0 && MEDIUS_HOST_CONFIGURATION_QUEUE != NULL) {
        medius_host_log_formatted("%s; the device is enumerated again",reason);
        medius_host_schedule_reenumeration(force_identity_refresh);
    } else {
        memw(); MEDIUS_HOST_RECOVERY_DEFERRED = 1;
        medius_host_log_formatted("%s; the device is enumerated again after the update",reason);
    }
}

/* Native entry: 0x42028dbc. */
/* Original function-byte SHA-256:
 * 1c48769799ea2ff6198c7a3049d07a9bc5947e70ca261e48701cb7737e16806f. */
/* Validate resumed port/frame progress, then optionally restore HID streams.
 * port: Optional; clear frame-clock blocked state BEFORE any port admission.
 * restore_interfaces: Full32 nonzero permits restore after observed progress.
 * Connected cached port supplies bus.id for raw HPRT. Bit2 clear requests
 * recovery("resume from suspend failed",0), with no frame read/delay. Otherwise
 * fence/read HFNUM, delay4 scheduler ticks, fence/read HFNUM again. Equal LOW16
 * requests recovery("no frames after the resume",0); changed LOW16 and nonzero
 * restore flag restores suspended HID. High frame bits are ignored. No port
 * recheck after delay or continuous/wrap-safe progress proof; no guarantee
 * recovery finishes, callbacks quiesce or the delay matches physical time. */
void medius_host_finish_resume(MediusHostHubPortPrefix *port,int restore_interfaces)
{
    medius_host_set_frame_clock_blocked(0);
    if (port == NULL || ((volatile MediusHostHubPortPrefix *)port)->connected == 0) return;
    MediusHostBusPrefix *bus = ((volatile MediusHostHubPortPrefix *)port)->bus_context;
    unsigned char id = ((volatile MediusHostBusPrefix *)bus)->id;
    unsigned int raw_port = medius_dwc2_host_port_raw(id);
    if ((raw_port & 4U) == 0) {
        medius_host_request_recovery("resume from suspend failed",0);
        return;
    }
    memw(); unsigned int before = MEDIUS_HOST_USB_REGISTERS->frame_number;
    vTaskDelay(4);
    memw(); unsigned int after = MEDIUS_HOST_USB_REGISTERS->frame_number;
    if ((before & 65535U) == (after & 65535U))
        medius_host_request_recovery("no frames after the resume",0);
    else if (restore_interfaces != 0) medius_host_restore_suspended_hid();
}

/* Native entry: 0x420294c4. */
/* Original function-byte SHA-256:
 * 2e03c757647eead6fcbc221091832df1e91202dc6e9c889b831ff253c7cb58bb. */
/* Consume ordered changes whose generation is below target_generation.
 * No result. Generation comparisons are ordinary unsigned32, without serial
 * wrap ordering. Fence/sample applied BEFORE taking the ordered mux. Empty
 * ring chooses current generation; a future head chooses its generation,
 * potentially beyond target. Raise applied if smaller, unlock, fence/read
 * applied and wake OUT only if changed from the pre-lock sample, then return.
 * Head indexes are raw bytes on admission; callers must maintain0..7/count0..8.
 *
 * Pop advances head, reads tag16, publishes decremented count, then caches
 * command/arg bytes. Raise applied to record generation if smaller, unlock and
 * notify any change. Fence/publish active generation before command dispatch.
 * Each command captures its own port after its own fence. No mux spans USB or
 * helper work. The original start timestamp spans backlog waits and USB retries.
 * Backlog waits sample signed modulo64 elapsed and stop above49999 us; timeout
 * continues the operation. They delay one scheduler tick between checks.
 *
 * FE halt: publish full16 active tag under mux. Missing/disconnected port gives
 * FF; recovery gates/reset nonzero skip with0. OUT (bit7 clear, including0)
 * waits/drains older work. First active matching HID endpoint with a class
 * can be managed. SET marks halted before pausing; CLEAR pauses only if not
 * already halted. Vendor/OUT state changes precede endpoint feature request.
 * STALL mapsFD, other negative maps low8(~fresh connected), without bool
 * normalization. Failed SET and all CLEAR requests restore when reset stays0
 * and connection remains nonzero. Restore success argument is the INITIAL
 * connection byte for successful CLEAR, otherwise the admitted reset byte0.
 * Managed HID clears special_valid twice around vendor notification cleanup,
 * publishes early last-ACK, then clears halt/pause/retry/armed. Status0 alone
 * clears class IN toggle. Period<2/globalpause0 rearms; every negative result
 * marks local retry but does NOT publish global retry. Successful SET keeps halt.
 * Cache active=-1,completed tag,result under mux before the common response.
 *
 * FF reset: connected port+parent+clear recovery gates required. Already paused,
 * no activity and power0 only clear remote/pause policy. Otherwise wait/pause
 * all HID, leave any power state (root deasserts resume; external pulses31/11),
 * clear saved mask and frame-clock block, then clear power policy. Root reset
 * uses hub feature4; external reset uses shared23/03/value4/indexport/length0,
 * timeout100, with mutex captured BEFORE SETUP stores. Submit0 reads actual.
 * Ignore-4/-3; other connected reset errors request recovery0. External success
 * delays50 before connection admission. Then delay11, save address/set0, retry
 * SET_ADDRESS and sample connected BEFORE restoring saved address. Error requests
 * recovery0; success delays3 then GET_DESCRIPTOR18. Connected negative descriptor
 * results still clean local HID state. Nonnegative results must match cached
 * descriptor length (FULL result-8) and bytes or force recovery1. Cleanup clears
 * both class toggles and selected HID flags,activity,deferred,identity flags;
 * it leaves global pause/armed/needs_rearm untouched locally.
 *
 * FD alternate: connected/clear recovery gates; wait backlog. Stable initial
 * table/count/table admits draining every signed-positive OUT address across
 * alternates, with native pointer/count refreshes after drain calls. Recheck
 * table/count/table for first-alternate class3/private class, else vendor path.
 * Pause selected path then SET_INTERFACE. Fresh disconnected/reset/not-ready
 * state suppresses follow-up. Negative result logs and restores old path;
 * success delegates HID/vendor alternate restore. ACK remains0 for all outcomes.
 *
 * FC power: snapshot eligibility from port/parent/gates and reset XOR1 LOW BIT,
 * then peek next command under mux. Publish desired remote from arg2!=0.
 * Resume(arg1==0,state1) skips only for a following FF, regardless of suspend
 * eligibility; clear armed, pulse connected bus31/11, state0, finish resume.
 * Suspend(arg1!=0,state0,eligible bit0) waits, applies differing RAW remote
 * policy, then pauses eligible HID handles and records fresh restore mask bits
 * unless already globally paused. Pause vendor/OUT before global pause1.
 * Cache connected BEFORE state1/preexisting-pause/armed publication. Nonnegative
 * suspend blocks frame clock, delays21 and gates it only if armed+connected
 * remain. Lost flags during delay do not roll back. Failure restores interfaces
 * only when this operation introduced the pause. FB remote snapshots RAW applied
 * BEFORE fenced port and desired publication; differing policy requires port,
 * parent,gates,power0, but does not inspect reset. Ordinary0..FA only check
 * precapture/pending-capture/power before configuration delegation.
 *
 * All non-halt acknowledgements use status0, including skipped/delegated failure.
 * Nonnegative signed tags publish low8 ACK and send44hex/sequence0/[tag,status];
 * negatives send nothing. Every consumed record finally fences/publishes
 * applied=record+1 (which can lower a larger value), wakes OUT and repeats.
 * Pointers, counts, cached descriptor spans and shared buffers are trusted.
 * Vendor boundary bodies remain separate reviews; no borrowed-pointer lifetime,
 * physical USB timing, DMA quiescence or race-freedom guarantee is supplied. */
void medius_host_apply_generation(unsigned int target_generation)
{
    volatile MediusHostPowerStateView *power = MEDIUS_HOST_POWER;
    for (;;) {
        memw(); unsigned int previous_applied = MEDIUS_HOST_APPLIED_GENERATION;
        xPortEnterCriticalTimeout(&MEDIUS_HOST_ORDERED_LOCK,-1);
        unsigned int count = MEDIUS_HOST_ORDERED_COUNT;
        unsigned int record_generation;
        volatile MediusOrderedChange *record;
        unsigned int head = 0;
        if (count == 0) {
            memw(); record_generation = MEDIUS_HOST_CURRENT_GENERATION;
            goto stop;
        }
        head = MEDIUS_HOST_ORDERED_HEAD;
        record = &MEDIUS_HOST_ORDERED_CHANGES[head];
        record_generation = record->generation;
        if (record_generation >= target_generation) {
stop:
            memw();
            if (MEDIUS_HOST_APPLIED_GENERATION < record_generation) {
                memw(); MEDIUS_HOST_APPLIED_GENERATION = record_generation;
            }
            vPortExitCritical(&MEDIUS_HOST_ORDERED_LOCK);
            memw();
            if (previous_applied != MEDIUS_HOST_APPLIED_GENERATION) medius_out_wake_worker();
            return;
        }
        MEDIUS_HOST_ORDERED_HEAD = (unsigned char)((head + 1U) & 7U);
        short tag = record->ack_tag;
        MEDIUS_HOST_ORDERED_COUNT = (unsigned char)(count - 1U);
        unsigned int command = record->command;
        unsigned int arg1 = record->arg1;
        unsigned int arg2 = record->arg2;
        memw();
        if (MEDIUS_HOST_APPLIED_GENERATION < record_generation) {
            memw(); MEDIUS_HOST_APPLIED_GENERATION = record_generation;
        }
        vPortExitCritical(&MEDIUS_HOST_ORDERED_LOCK);
        memw();
        if (previous_applied != MEDIUS_HOST_APPLIED_GENERATION) medius_out_wake_worker();
        memw(); MEDIUS_HOST_ACTIVE_CONTROL_GENERATION = record_generation;
        unsigned char status = 0;
        if (command == 0xfe) {
            xPortEnterCriticalTimeout(&MEDIUS_HOST_ORDERED_LOCK,-1);
            MEDIUS_HOST_ENDPOINT_HALT_ACTIVE_TAG = tag;
            vPortExitCritical(&MEDIUS_HOST_ORDERED_LOCK);
            memw(); MediusHostHubPortPrefix *port = MEDIUS_HOST_CONTROL_PORT;
            if (port == NULL) { status = 0xff; goto halt_done; }
            volatile MediusHostHubPortPrefix *live_port = port;
            unsigned char initial_connected = live_port->connected;
            if (initial_connected == 0) { status = 0xff; goto halt_done; }
            memw(); if (MEDIUS_HOST_RESTART_GATE != 0) goto halt_done;
            memw(); if (MEDIUS_HOST_CONFIGURATION_SWITCH_GATE != 0) goto halt_done;
            memw(); if (MEDIUS_HOST_PRECAPTURE_STATE != 0) goto halt_done;
            memw(); unsigned char reset = MEDIUS_HOST_RESET_PENDING;
            if (reset != 0) goto halt_done;
            unsigned long long started = (unsigned long long)esp_timer_get_time();
            if ((arg1 & 128U) == 0) {
                medius_generation_wait_out(record_generation,started);
                medius_out_drain_endpoint((unsigned char)arg1,record_generation);
            }
            volatile MediusHidEndpointState *state = NULL;
            MediusHostHidClass *hid = NULL;
            for (unsigned int slot = 0; slot < 6; ++slot) {
                memw();
                if (MEDIUS_HOST_HID_ENDPOINTS[slot].active != 0 && MEDIUS_HOST_HID_ENDPOINTS[slot].endpoint == arg1) {
                    state = &MEDIUS_HOST_HID_ENDPOINTS[slot];
                    hid = state->interface_handle;
                    break;
                }
            }
            int managed = hid != NULL;
            if (managed) {
                if (arg2 != 0) {
                    memw(); state->halted = 1;
                    medius_host_pause_hid_interface(hid);
                } else {
                    memw();
                    if (state->halted == 0) medius_host_pause_hid_interface(hid);
                }
            }
            if (arg2 != 0) {
                medius_vendor_set_endpoint_halt(arg1,1,0);
                medius_out_set_halted((unsigned char)arg1,1,0);
            } else medius_vendor_prepare_clear_halt((unsigned char)arg1);
            memw(); MEDIUS_HOST_CONTROL_ACTIVITY = 1;
            int result = medius_host_control_retry(port,(long long)started,2,arg2 != 0 ? 3 : 1,0,(unsigned short)arg1,0);
            unsigned char restore_accepted = initial_connected;
            if (result < 0) {
                status = result == -8 ? 0xfd : (unsigned char)~live_port->connected;
                medius_host_log_formatted("ep %02x %s halt not taken by the device (%d)",arg1,arg2 != 0 ? "set" : "clear",result);
                restore_accepted = reset;
            } else if (arg2 != 0) goto halt_early_ack;
            memw();
            if (MEDIUS_HOST_RESET_PENDING != 0 || live_port->connected == 0) goto halt_early_ack;
            if (managed) { memw(); state->special_valid = 0; }
            medius_vendor_clear_stall_notifications((unsigned char)arg1);
            if (tag >= 0) { memw(); MEDIUS_HOST_ORDERED_LAST_ACK = (unsigned char)tag; }
            if (managed) {
                memw(); state->special_valid = 0;
                memw(); state->halted = 0;
                memw(); state->paused = 0;
                memw(); state->needs_rearm = 0;
                memw(); state->special_retry = 0;
                if (status == 0) {
                    MediusHostHidClass *current_hid = state->interface_handle;
                    ((volatile MediusHostHidClass *)current_hid)->in_urb.toggle = 0;
                }
                memw(); state->armed = 0;
                memw(); unsigned int period = state->poll_period;
                if (period < 2) {
                    memw(); unsigned char paused = MEDIUS_HOST_HID_PAUSED;
                    if (paused == 0 && medius_hid_rearm_with_credit_gate((MediusHidEndpointState *)state) < 0) {
                        memw(); state->armed = paused;
                        memw(); state->needs_rearm = 1;
                    }
                }
            }
            medius_vendor_set_endpoint_halt(arg1,0,restore_accepted);
            medius_out_set_halted((unsigned char)arg1,0,restore_accepted);
            goto halt_done;
halt_early_ack:
            if (tag >= 0) { memw(); MEDIUS_HOST_ORDERED_LAST_ACK = (unsigned char)tag; }
halt_done:
            memw(); MEDIUS_HOST_ACTIVE_CONTROL_GENERATION = 0xffffffffU;
            xPortEnterCriticalTimeout(&MEDIUS_HOST_ORDERED_LOCK,-1);
            MEDIUS_HOST_ENDPOINT_HALT_ACTIVE_TAG = -1;
            MEDIUS_HOST_ENDPOINT_HALT_COMPLETED_TAG = tag;
            MEDIUS_HOST_ORDERED_LAST_RESULT = status;
            vPortExitCritical(&MEDIUS_HOST_ORDERED_LOCK);
            goto acknowledge;
        }
        if (command == 0xff) {
            memw(); MediusHostHubPortPrefix *port = MEDIUS_HOST_CONTROL_PORT;
            volatile MediusHostHubPortPrefix *live_port = port;
            if (port == NULL || live_port->connected == 0 || live_port->parent == NULL) goto nonhalt_done;
            memw(); if (MEDIUS_HOST_RESTART_GATE != 0) goto nonhalt_done;
            memw(); if (MEDIUS_HOST_CONFIGURATION_SWITCH_GATE != 0) goto nonhalt_done;
            memw(); if (MEDIUS_HOST_PRECAPTURE_STATE != 0) goto nonhalt_done;
            memw();
            if (MEDIUS_HOST_HID_PAUSED != 0) {
                memw();
                if (MEDIUS_HOST_CONTROL_ACTIVITY == 0 && power->state == 0) {
                    *(volatile unsigned short *)&power->desired_remote_wakeup = 0;
                    power->preexisting_pause = 0;
                    goto nonhalt_done;
                }
            }
            unsigned long long started = (unsigned long long)esp_timer_get_time();
            medius_generation_wait_out(record_generation,started);
            medius_host_pause_all_hid();
            if (power->state != 0) {
                MediusHostHubPrefix *parent = live_port->parent;
                memw(); MEDIUS_HOST_RESUME_ARMED = 0;
                unsigned char root = ((volatile MediusHostHubPrefix *)parent)->is_root;
                MediusHostBusPrefix *bus = live_port->bus_context;
                memw(); MEDIUS_HOST_RESUME_PENDING = 0;
                unsigned char bus_id = ((volatile MediusHostBusPrefix *)bus)->id;
                if (root == 0) {
                    medius_dwc2_host_resume_control(bus_id,1);
                    vTaskDelay(31);
                    medius_dwc2_host_resume_control(bus_id,0);
                    vTaskDelay(11);
                } else medius_dwc2_host_resume_control(bus_id,0);
                MEDIUS_HID_SUSPEND_RESTORE_MASK = 0;
                medius_host_set_frame_clock_blocked(0);
            }
            MediusHostHubPrefix *parent = live_port->parent;
            unsigned char root = ((volatile MediusHostHubPrefix *)parent)->is_root;
            power->state = 0;
            *(volatile unsigned short *)&power->desired_remote_wakeup = 0;
            power->preexisting_pause = 0;
            int result;
            if (root != 0) {
                result = medius_usbh_hub_set_port_feature((MediusHostHubState *)parent,live_port->port_number,4);
                if (live_port->connected == 0 || (unsigned int)(result + 4U) < 2U) goto nonhalt_done;
            } else {
                MediusHostHubPortPrefix *upstream = ((volatile MediusHostHubPrefix *)parent)->upstream_port;
                if (upstream == NULL || ((volatile MediusHostHubPortPrefix *)upstream)->connected == 0) goto nonhalt_done;
                unsigned int number = live_port->port_number;
                void *mutex = ((volatile MediusHostHubPortPrefix *)upstream)->control_mutex;
                volatile MediusUsbSetup *setup = MEDIUS_HOST_SHARED_SETUP;
                ((volatile unsigned int *)setup)[0] = 0x00040323U;
                setup->index = (unsigned short)number;
                setup->length = root;
                usb_osal_mutex_take(mutex);
                volatile MediusHostUrb *urb = &upstream->control_urb;
                urb->setup = (unsigned char *)setup;
                urb->buffer = MEDIUS_HOST_CONTROL_DATA;
                urb->endpoint = upstream->ep0_descriptor;
                urb->timeout = 100;
                urb->hubport = upstream;
                urb->remaining = root;
                urb->complete = NULL;
                urb->context = NULL;
                result = usbh_submit_urb((MediusHostUrb *)urb);
                if (result == 0) result = (int)urb->actual;
                usb_osal_mutex_give(((volatile MediusHostHubPortPrefix *)upstream)->control_mutex);
                if (result < 0) {
                    if (live_port->connected == 0 || (unsigned int)(result + 4U) < 2U) goto nonhalt_done;
                } else {
                    vTaskDelay(50);
                    if (live_port->connected == 0) goto nonhalt_done;
                }
            }
            if (result < 0) {
                medius_host_request_recovery("port reset failed after a bus reset",0);
                goto nonhalt_done;
            }
            vTaskDelay(11);
            unsigned char address = live_port->device_address;
            live_port->device_address = 0;
            result = medius_host_control_retry(port,(long long)started,0,5,address,0,0);
            unsigned char connected = live_port->connected;
            live_port->device_address = address;
            if (connected == 0) goto nonhalt_done;
            if (result < 0) {
                medius_host_request_recovery("SET_ADDRESS failed after a bus reset",0);
                goto nonhalt_done;
            }
            vTaskDelay(3);
            result = medius_host_control_retry(port,(long long)started,0x80,6,0x100,0,18);
            if (live_port->connected == 0) goto nonhalt_done;
            if (result >= 0) {
                unsigned int bytes = (unsigned int)result - 8U;
                if (bytes != MEDIUS_HOST_CACHED_DEVICE_DESCRIPTOR_LENGTH ||
                    memcmp(MEDIUS_HOST_CONTROL_DATA,MEDIUS_HOST_CACHED_DEVICE_DESCRIPTOR,bytes) != 0) {
                    medius_host_request_recovery("identity check failed after a bus reset",1);
                    goto nonhalt_done;
                }
            }
            for (unsigned int slot = 0; slot < 6; ++slot) {
                volatile MediusHidEndpointState *state = &MEDIUS_HOST_HID_ENDPOINTS[slot];
                memw(); if (state->active == 0) continue;
                MediusHostHidClass *hid = state->interface_handle;
                if (hid == NULL) continue;
                ((volatile MediusHostHidClass *)hid)->in_urb.toggle = 0;
                ((volatile MediusHostHidClass *)hid)->out_urb.toggle = 0;
                memw(); state->special_valid = 0;
                memw(); state->halted = 0;
                memw(); state->special_retry = 0;
                memw(); state->paused = 0;
            }
            memw(); MEDIUS_HOST_CONTROL_ACTIVITY = 0;
            memw(); MEDIUS_HOST_RECOVERY_DEFERRED = 0;
            memw(); MEDIUS_HOST_IDENTITY_REFRESH = 0;
            goto nonhalt_done;
        }
        if (command == 0xfd) {
            memw(); MediusHostHubPortPrefix *port = MEDIUS_HOST_CONTROL_PORT;
            volatile MediusHostHubPortPrefix *live_port = port;
            if (port == NULL || live_port->connected == 0) goto nonhalt_done;
            memw(); if (MEDIUS_HOST_RESTART_GATE != 0) goto nonhalt_done;
            memw(); if (MEDIUS_HOST_CONFIGURATION_SWITCH_GATE != 0) goto nonhalt_done;
            memw(); if (MEDIUS_HOST_PRECAPTURE_STATE != 0) goto nonhalt_done;
            unsigned long long started = (unsigned long long)esp_timer_get_time();
            medius_generation_wait_out(record_generation,started);
            MediusHostInterfacePrefix *first = live_port->interfaces;
            memw(); unsigned int initial_count = live_port->interface_count;
            memw(); MediusHostInterfacePrefix *table = live_port->interfaces;
            if (first != NULL && first == table && arg1 < initial_count) {
                volatile MediusHostInterfacePrefix *entry = &first[arg1];
                unsigned int alternate_count = entry->alternate_count;
                if (alternate_count != 0) {
                    MediusHostAlternatePrefix *alternates = entry->alternates;
                    unsigned int alternate_index = 0;
                    do {
                        volatile MediusHostAlternatePrefix *alternate = (void *)((unsigned int)alternates + alternate_index * 16U);
                        unsigned int endpoints = alternate->endpoint_count;
                        if (endpoints != 0) {
                            unsigned int endpoint_index = 0;
                            do {
                                const volatile unsigned char *descriptors = alternate->endpoints;
                                unsigned char endpoint = descriptors[endpoint_index * 7U + 2U];
                                if ((signed char)endpoint > 0) {
                                    medius_out_drain_endpoint(endpoint,record_generation);
                                    alternates = entry->alternates;
                                }
                                alternate = (void *)((unsigned int)alternates + alternate_index * 16U);
                                ++endpoint_index;
                            } while ((endpoint_index & 255U) < alternate->endpoint_count);
                            alternate_count = entry->alternate_count;
                        }
                        ++alternate_index;
                    } while ((alternate_index & 255U) < alternate_count);
                    table = live_port->interfaces;
                }
            }
            memw(); unsigned int current_count = live_port->interface_count;
            memw();
            MediusHostHidClass *hid = NULL;
            if (table != NULL && live_port->interfaces == table && arg1 < current_count) {
                volatile MediusHostInterfacePrefix *entry = &table[arg1];
                if (entry->alternate_count != 0) {
                    const volatile unsigned char *alternate = (const volatile void *)entry->alternates;
                    if (alternate[5] == 3) hid = entry->private_data;
                }
            }
            if (hid != NULL) medius_host_pause_hid_interface(hid);
            else medius_vendor_pause_interface((unsigned char)arg1);
            memw(); MEDIUS_HOST_CONTROL_ACTIVITY = 1;
            int result = medius_host_control_retry(port,(long long)started,1,11,(unsigned short)arg2,(unsigned short)arg1,0);
            if (live_port->connected == 0) goto nonhalt_done;
            memw(); if (MEDIUS_HOST_RESET_PENDING != 0 || MEDIUS_HOST_DESCRIPTORS_READY == 0) goto nonhalt_done;
            if (result < 0) {
                medius_host_log_formatted("intf %u alt %u not taken by the device (%d)",arg1,arg2,result);
                if (hid != NULL) medius_host_restore_hid_interface(hid);
                else medius_vendor_resume_interface((unsigned char)arg1);
            } else if (hid != NULL) medius_host_restore_hid_alternate(port,hid,arg2,1);
            else medius_vendor_restore_alternate(port,arg1,arg2);
            goto nonhalt_done;
        }
        if (command == 0xfc) {
            unsigned char desired = arg2 != 0;
            memw(); MediusHostHubPortPrefix *port = MEDIUS_HOST_CONTROL_PORT;
            volatile MediusHostHubPortPrefix *live_port = port;
            unsigned int eligible = 0;
            if (port != NULL && live_port->connected != 0 && live_port->parent != NULL) {
                memw(); if (MEDIUS_HOST_RESTART_GATE != 0) goto power_peek;
                memw(); if (MEDIUS_HOST_CONFIGURATION_SWITCH_GATE != 0) goto power_peek;
                memw(); if (MEDIUS_HOST_PRECAPTURE_STATE != 0) goto power_peek;
                memw(); eligible = MEDIUS_HOST_RESET_PENDING ^ 1U;
            }
power_peek:
            xPortEnterCriticalTimeout(&MEDIUS_HOST_ORDERED_LOCK,-1);
            int next_is_reset = 0;
            if (MEDIUS_HOST_ORDERED_COUNT != 0)
                next_is_reset = MEDIUS_HOST_ORDERED_CHANGES[MEDIUS_HOST_ORDERED_HEAD].command == 0xff;
            vPortExitCritical(&MEDIUS_HOST_ORDERED_LOCK);
            power->desired_remote_wakeup = desired;
            unsigned char state_before = power->state;
            if (arg1 == 0) {
                if (state_before != 1 || next_is_reset) goto nonhalt_done;
                power->state = 2;
                memw(); MEDIUS_HOST_RESUME_ARMED = 0;
                if (port != NULL && live_port->connected != 0) {
                    MediusHostBusPrefix *bus = live_port->bus_context;
                    unsigned char id = ((volatile MediusHostBusPrefix *)bus)->id;
                    medius_dwc2_host_resume_control(id,1);
                    vTaskDelay(31);
                    medius_dwc2_host_resume_control(id,0);
                    vTaskDelay(11);
                }
                unsigned char restore = power->preexisting_pause ^ 1U;
                power->state = 0;
                medius_host_finish_resume(port,restore);
                goto nonhalt_done;
            }
            if (state_before != 0 || (eligible & 1U) == 0) goto nonhalt_done;
            unsigned long long started = (unsigned long long)esp_timer_get_time();
            medius_generation_wait_out(record_generation,started);
            unsigned char applied = power->applied_remote_wakeup;
            if (applied != power->desired_remote_wakeup) medius_host_apply_remote_wakeup(port,(long long)started);
            memw(); unsigned char already_paused = MEDIUS_HOST_HID_PAUSED;
            if (already_paused == 0) {
                MEDIUS_HID_SUSPEND_RESTORE_MASK = 0;
                for (unsigned int slot = 0; slot < 6; ++slot) {
                    volatile MediusHidEndpointState *state = &MEDIUS_HOST_HID_ENDPOINTS[slot];
                    memw(); if (state->active == 0) continue;
                    MediusHostHidClass *hid = state->interface_handle;
                    if (hid == NULL) continue;
                    memw(); if (state->paused != 0) continue;
                    memw(); if (state->halted != 0) continue;
                    medius_host_pause_hid_interface(hid);
                    MEDIUS_HID_SUSPEND_RESTORE_MASK = MEDIUS_HID_SUSPEND_RESTORE_MASK | (1U << slot);
                }
                medius_vendor_pause_streams();
                medius_out_pause_preserve();
                memw(); MEDIUS_HOST_HID_PAUSED = 1;
            }
            unsigned char connected = live_port->connected;
            power->state = 1;
            power->preexisting_pause = already_paused != 0;
            memw(); MEDIUS_HOST_RESUME_ARMED = 1;
            if (connected != 0) {
                MediusHostBusPrefix *bus = live_port->bus_context;
                unsigned char id = ((volatile MediusHostBusPrefix *)bus)->id;
                if (medius_dwc2_host_suspend(id) >= 0) {
                    medius_host_set_frame_clock_blocked(1);
                    vTaskDelay(21);
                    memw();
                    if (MEDIUS_HOST_RESUME_ARMED != 0 && live_port->connected != 0) {
                        bus = live_port->bus_context;
                        medius_dwc2_host_gate_suspended_clock(((volatile MediusHostBusPrefix *)bus)->id,1);
                    }
                    goto nonhalt_done;
                }
            }
            memw(); MEDIUS_HOST_RESUME_ARMED = 0;
            power->state = 0;
            if (already_paused == 0) medius_host_restore_suspended_hid();
            goto nonhalt_done;
        }
        if (command == 0xfb) {
            unsigned char desired = arg2 != 0;
            unsigned char applied = power->applied_remote_wakeup;
            memw(); MediusHostHubPortPrefix *port = MEDIUS_HOST_CONTROL_PORT;
            power->desired_remote_wakeup = desired;
            volatile MediusHostHubPortPrefix *live_port = port;
            if (applied == desired || port == NULL || live_port->connected == 0 || live_port->parent == NULL) goto nonhalt_done;
            memw(); if (MEDIUS_HOST_RESTART_GATE != 0) goto nonhalt_done;
            memw(); if (MEDIUS_HOST_CONFIGURATION_SWITCH_GATE != 0) goto nonhalt_done;
            memw(); if (MEDIUS_HOST_PRECAPTURE_STATE != 0 || power->state != 0) goto nonhalt_done;
            long long started = esp_timer_get_time();
            medius_host_apply_remote_wakeup(port,started);
            goto nonhalt_done;
        }
        memw(); if (MEDIUS_HOST_PRECAPTURE_STATE != 0) goto nonhalt_done;
        memw(); if (MEDIUS_HOST_CAPTURE_PENDING != 0 || power->state != 0) goto nonhalt_done;
        medius_host_apply_configuration(command,record_generation,0);
nonhalt_done:
        memw(); MEDIUS_HOST_ACTIVE_CONTROL_GENERATION = 0xffffffffU;
        status = 0;
acknowledge:
        if (tag >= 0) {
            unsigned short response = (unsigned short)((unsigned char)tag | ((unsigned int)status << 8));
            memw(); MEDIUS_HOST_ORDERED_LAST_ACK = (unsigned char)tag;
            link_send_wait100(0x44,0,&response,2);
        }
        memw(); MEDIUS_HOST_APPLIED_GENERATION = record_generation + 1U;
        medius_out_wake_worker();
    }
}

/* Native entry: 0x4202d7e4. */
/* Original function-byte SHA-256:
 * 39833135fdff5c4146bcc6c51cb9f4dbd37934742b75fe3f2c2a91242235de6c. */
/* Fence each byte sample and short-circuit in this order: return the raw
 * restart gate if nonzero, then the raw configuration-switch gate if nonzero,
 * then1 if pre-capture state is nonzero, otherwise the raw HID-paused byte.
 * Each reached field is read once. No locks, normalization of raw return
 * bytes, state clearing or atomic snapshot across fields is provided. */
unsigned char medius_host_recovery_gate(void)
{
    memw();
    unsigned char restart = MEDIUS_HOST_RESTART_GATE;
    if (restart != 0) return restart;
    memw();
    unsigned char configuration_switch = MEDIUS_HOST_CONFIGURATION_SWITCH_GATE;
    if (configuration_switch != 0) return configuration_switch;
    memw();
    if (MEDIUS_HOST_PRECAPTURE_STATE != 0) return 1;
    memw();
    return MEDIUS_HOST_HID_PAUSED;
}

/* Native entry: 0x4202e2e8. */
/*
 * Medius v3.4.7 — host application; 0x4202e2e8.
 *
 * Publishes one armed host resume event with a64-bit timestamp, then notifies the control worker.
 *
 * Calls: _frxt_setup_switch, vTaskGenericNotifyGiveFromISR, esp_timer_get_time, vPortExitCritical,
 * xPortEnterCriticalTimeout, xPortInIsrContext.
 *
 * Called by: USBH_IRQHandler.
 *
 * Original function-byte SHA-256:
 * d497ed0f2aae52152576a526424dd5dd625f740248a4763207a0d7f4b48f0a68.
 */

/* Publishes one armed host resume event with a64-bit timestamp, then notifies the control worker.
   Evidence: Samples esp_timer_get_time before locking, queries ISR context (result ignored), enters
   critical mux3fc9ddd4 with timeoutFFFFFFFF (result ignored), then reads armed byte3fca9759. If
   zero, queries context again and exits the critical section without changing timestamp or flags or
   notifying. Otherwise original stores4202e32e/330 write timestamp low/high to3fca9750/54, then
   MEMW and store armed0 at4202e338, then MEMW and store pending1 at4202e340. Queries context and
   unlocks. Rereads control-worker handle; if nonNULL, initializes local woken0,
   calls0x40383bcc(task,0,&woken), ignores result, and yields if woken is any nonzero value. The
   IRQ-supplied bus index is not consumed. */

/*
 * Returns: No value; critical-entry and notification return values are ignored.
 * Requirements/effects: Always samples the 64-bit software timer before entering mux3fc9ddd4 with
 *   infinite timeout, querying ISR context before enter and exit. Under the mux, MEMW then one
 *   armed-byte read gates publication. If armed, stores timestamp low then high, MEMW then
 *   armed=0, MEMW then pending=1, and unlocks. Only afterwards reads the control-worker handle
 *   once. A non-NULL handle receives indexed ISR notification 0 with a single initialized int32
 *   woken output; any nonzero woken value yields, even when notification reports failure. Unarmed
 *   calls preserve timestamp/pending and never notify. No local queueing of multiple events,
 *   acknowledgement, callback quiescence or hardware timing guarantee is supplied.
 */

void medius_host_publish_resume_event(void)
{
    ulonglong event_time = (ulonglong)esp_timer_get_time();
    (void)xPortInIsrContext();
    (void)xPortEnterCriticalTimeout(&MEDIUS_HOST_ORDERED_LOCK,-1);
    memw();
    if (MEDIUS_HOST_RESUME_ARMED == 0) {
        (void)xPortInIsrContext();
        vPortExitCritical(&MEDIUS_HOST_ORDERED_LOCK);
        return;
    }
    MEDIUS_HOST_RESUME_EVENT_US->low = (uint)event_time;
    MEDIUS_HOST_RESUME_EVENT_US->high = (uint)(event_time >> 32);
    memw();
    MEDIUS_HOST_RESUME_ARMED = 0;
    memw();
    MEDIUS_HOST_RESUME_PENDING = 1;
    (void)xPortInIsrContext();
    vPortExitCritical(&MEDIUS_HOST_ORDERED_LOCK);
    RtosTask *worker = MEDIUS_HOST_CONTROL_WORKER_TASK;
    if (worker != NULL) {
        int higher_priority_woken = 0;
        vTaskGenericNotifyGiveFromISR(worker,0,&higher_priority_woken);
        if (higher_priority_woken != 0)
            _frxt_setup_switch();
    }
}

/* Native entry: 0x4202e700. */
/* Original function-byte SHA-256:
 * cc96ba0e3eac8cf4e71e31e0e64ee1ac626b398ae71e05a16f4148d983527c81. */
/* If length>=3, cache tag byte2, alternate byte1, then interface byte0 and
 * enqueue FD/interface/alternate/tag. Ignore shorter input and extra bytes.
 * No endpoint/interface validation, immediate reply, local lock or ownership. */
void medius_ordered_interface_request(const unsigned char *payload,unsigned short length)
{
    if (length < 3) return;
    const volatile unsigned char *input = payload;
    short tag = input[2];
    unsigned int alternate = input[1];
    unsigned int interface_number = input[0];
    medius_ordered_change_enqueue(0xfd,interface_number,alternate,tag);
}

/* Native entry: 0x4202e7dc. */
/* Original function-byte SHA-256:
 * c19ee53c2fd97639b24545e53042d9c6779d1462b9d757c482d659c89fb10e8e. */
/* Admit a configuration selector<251 from a nonempty request.
 * Ordinary requests enqueue the INITIAL selector,0,0 and optional byte2 tag
 * (length>=3), else-1. Flag bit0 in byte1 selects deferred handling instead.
 * Deferred: lock, REREAD selector (no second<251 check), sample epoch BEFORE
 * storing selector+1 as16 bits, then store pending epoch, unlock and notify
 * the freshly sampled worker if present. Deferred admission replaces one slot,
 * ignores any tag, and does not increment generation or enter the change ring.
 * Ignore extra bytes; no immediate response or rollback on notification failure. */
void medius_ordered_configuration_request(const unsigned char *payload,unsigned short length)
{
    if (length == 0) return;
    const volatile unsigned char *input = payload;
    unsigned int selector = input[0];
    if (selector >= 251) return;
    if (length >= 2 && (input[1] & 1U) != 0) {
        xPortEnterCriticalTimeout(&MEDIUS_HOST_ORDERED_LOCK,-1);
        unsigned int current_selector = input[0];
        unsigned int epoch = MEDIUS_HOST_ORDERED_EPOCH;
        MEDIUS_HOST_PENDING_CONFIGURATION = (unsigned short)(current_selector + 1U);
        MEDIUS_HOST_PENDING_CONFIGURATION_EPOCH = epoch;
        vPortExitCritical(&MEDIUS_HOST_ORDERED_LOCK);
        RtosTask *worker = MEDIUS_HOST_CONTROL_WORKER_TASK;
        if (worker != NULL) xTaskGenericNotify(worker,0,0,2,NULL);
        return;
    }
    short tag = length >= 3 ? input[2] : -1;
    medius_ordered_change_enqueue(selector,0,0,tag);
}

/* Native entry: 0x4202e854. */
/* Original function-byte SHA-256:
 * 79d4d799317db0e44e3306d7fe30a859d75bd073076f982cac75a7f9178dc4af. */
/* Enqueue FF/0/0/-1, without admission or immediate response. The queue
 * owns generation/epoch increments and marker-specific overflow policy. */
void medius_ordered_generation_marker(void)
{
    medius_ordered_change_enqueue(0xff,0,0,-1);
}

/* Native entry: 0x4202e868. */
/* Original function-byte SHA-256:
 * aa11dff53f62f3110763dc0f3256e664157180eaa3645caf822f30a63c05a5ef. */
/* Require>=2 bytes. Read byte0 then byte1, normalize both to0/1, publish
 * requested_suspend, then enqueue FC with those CACHED normalized arguments
 * and tag-1. No reread of the published policy, fence or immediate response.
 * Short input is ignored; excess bytes and all bits beyond nonzero are ignored. */
void medius_ordered_power_request(const unsigned char *payload,unsigned short length)
{
    if (length < 2) return;
    const volatile unsigned char *input = payload;
    unsigned int suspend = input[0] != 0;
    unsigned int remote_wakeup = input[1] != 0;
    MEDIUS_HOST_POWER->requested_suspend = (unsigned char)suspend;
    medius_ordered_change_enqueue(0xfc,suspend,remote_wakeup,-1);
}

/* Native entry: 0x4202e894. */
/* Original function-byte SHA-256:
 * 040acc62cc06aa6336b2e525e03fb9715e0ac84fffd1f294df521140c0ee660f. */
/* Require>=1 byte, normalize byte0 to0/1 and enqueue FB/0/value/-1.
 * Short input is ignored. No immediate desired-policy update, response,
 * pointer/lifetime validation or local lock; later dispatch applies the change. */
void medius_ordered_remote_wakeup_request(const unsigned char *payload,unsigned short length)
{
    if (length == 0) return;
    unsigned int enabled = *(const volatile unsigned char *)payload != 0;
    medius_ordered_change_enqueue(0xfb,0,enabled,-1);
}

/* Native entry: 0x4202e8b4. */
/* Original function-byte SHA-256:
 * 7c9ceaa19ada7301698822e02b4c67de57a7fab079d998f77396ef3e215210ac. */
/* Admit a tagged endpoint halt, suppress pending duplicates or replay a result.
 * Require>=3 bytes. Lock then cache tag byte2. Compare against SIGNED16 active
 * tag, then scan raw byte head/count with modulo256 cursor and eight-slot mask
 * for queued FE with matching SIGNED16 ack_tag. A match only unlocks/returns.
 * Otherwise compare signed completed tag. A match snapshots last-result byte
 * immediately BEFORE unlocking; then REREADS payload tag for44hex/[tag,result],
 * sequence0, ignoring send status. Other requests unlock, reread tag,action,
 * endpoint in that order and enqueue FE/endpoint/action/newtag.
 * Duplicate identity is tag-only; endpoint/action are not compared. Unlocking
 * before enqueue and rereading payload prevents an atomic check/admit snapshot.
 * No endpoint/action validation, tag ownership or immediate new-work response. */
void medius_ordered_endpoint_halt_request(const unsigned char *payload,unsigned short length)
{
    if (length < 3) return;
    const volatile unsigned char *input = payload;
    xPortEnterCriticalTimeout(&MEDIUS_HOST_ORDERED_LOCK,-1);
    int tag = input[2];
    if (MEDIUS_HOST_ENDPOINT_HALT_ACTIVE_TAG == tag) goto duplicate;
    unsigned int cursor = MEDIUS_HOST_ORDERED_HEAD;
    unsigned int end = (cursor + MEDIUS_HOST_ORDERED_COUNT) & 255U;
    while (cursor != end) {
        volatile MediusOrderedChange *entry = &MEDIUS_HOST_ORDERED_CHANGES[cursor & 7U];
        if (entry->command == 0xfe && entry->ack_tag == tag) goto duplicate;
        cursor = (cursor + 1U) & 255U;
    }
    if (MEDIUS_HOST_ENDPOINT_HALT_COMPLETED_TAG == tag) {
        unsigned char result = MEDIUS_HOST_ORDERED_LAST_RESULT;
        vPortExitCritical(&MEDIUS_HOST_ORDERED_LOCK);
        unsigned short response = (unsigned short)(input[2] | ((unsigned int)result << 8));
        link_send_wait100(0x44,0,&response,2);
        return;
    }
    vPortExitCritical(&MEDIUS_HOST_ORDERED_LOCK);
    short fresh_tag = input[2];
    unsigned int action = input[1];
    unsigned int endpoint = input[0];
    medius_ordered_change_enqueue(0xfe,endpoint,action,fresh_tag);
    return;
duplicate:
    vPortExitCritical(&MEDIUS_HOST_ORDERED_LOCK);
}


/* Native entry: 0x420265c4. */
/* Original function-byte SHA-256:
 * 2b425d40bd0deccdbb03815db228460f306b644f6c350dfd455347bbeb206384. */
/* Publish an immediate host re-enumeration request and signal cfgswitch.
 * force_identity_refresh: Any nonzero word sets identity-refresh1; zero leaves
 *   its old value. No return/status and no admission/queue NULL check here.
 * Fence/clear deferred recovery, then cache the current configuration BEFORE
 * fenced restart=1 and fenced requested-selector publication. Sample signed64
 * microseconds, divide by1000 toward zero, fence/store low32 milliseconds.
 * Optionally fence/set identity-refresh. Read current VID then PID, cache the
 * current queue BEFORE storing both saved identity halfwords (VID then PID),
 * then nonblocking give that cached queue. Ignore the result; all publications
 * remain even if the signal is already full or fails. No coherent identity
 * snapshot, lock, rollback or task-lifetime retention is supplied. */
void medius_host_schedule_reenumeration(int force_identity_refresh)
{
    memw(); MEDIUS_HOST_RECOVERY_DEFERRED = 0;
    unsigned char selector = MEDIUS_HOST_CURRENT_CONFIGURATION;
    memw(); MEDIUS_HOST_RESTART_GATE = 1;
    memw(); MEDIUS_HOST_REQUESTED_CONFIGURATION = selector;
    long long milliseconds = esp_timer_get_time() / 1000;
    memw(); MEDIUS_HOST_RESTART_REQUESTED_MS = (unsigned int)milliseconds;
    if (force_identity_refresh != 0) {
        memw(); MEDIUS_HOST_IDENTITY_REFRESH = 1;
    }
    unsigned short vendor = MEDIUS_HOST_CURRENT_VENDOR_ID;
    unsigned short product = MEDIUS_HOST_CURRENT_PRODUCT_ID;
    RtosQueue *queue = MEDIUS_HOST_CONFIGURATION_QUEUE;
    MEDIUS_HOST_PREVIOUS_VENDOR_ID = vendor;
    MEDIUS_HOST_PREVIOUS_PRODUCT_ID = product;
    xQueueGenericSend(queue,NULL,0,0);
}

/* Native entry: 0x42026320. */
/* Original function-byte SHA-256:
 * f443d09df3d56dc10e92340b45e419f2f0b6d3cdb7fee0d794a6b0287898911f. */
/* Set the raw frame-clock block byte and refresh an existing reference on open.
 * blocked: Native low8 value, stored verbatim; every nonzero value blocks.
 * Cache mutex for the optional infinite take; ignore take status. Fence/store
 * blocked. Only for zero input read reference LOW then HIGH. A nonzero pair
 * samples time and writes the new reference LOW then HIGH; zero reference or
 * nonzero input performs NO timestamp write. The old decompile's unconditional
 * repeated stores are absent from native instructions and are removed here.
 * Reload mutex for the optional nonblocking give, independently of admission.
 * No local ownership check; a concurrently replaced/created handle can differ
 * from the taken one. Lock status and give result are ignored. */
void medius_host_set_frame_clock_blocked(unsigned char blocked)
{
    RtosQueue *mutex = MEDIUS_HOST_FRAME_CLOCK_MUTEX;
    if (mutex != NULL) xQueueSemaphoreTake(mutex,0xffffffffU);
    memw(); MEDIUS_HOST_FRAME_CLOCK_BLOCKED = blocked;
    if (blocked == 0) {
        unsigned int low = MEDIUS_HOST_FRAME_CLOCK_REFERENCE_US->low;
        unsigned int high = MEDIUS_HOST_FRAME_CLOCK_REFERENCE_US->high;
        if ((low | high) != 0) {
            unsigned long long now = (unsigned long long)esp_timer_get_time();
            MEDIUS_HOST_FRAME_CLOCK_REFERENCE_US->low = (unsigned int)now;
            MEDIUS_HOST_FRAME_CLOCK_REFERENCE_US->high = (unsigned int)(now >> 32);
        }
    }
    mutex = MEDIUS_HOST_FRAME_CLOCK_MUTEX;
    if (mutex != NULL) xQueueGenericSend(mutex,NULL,0,0);
}

/* Native entry: 0x4202d74c. */
/* Original function-byte SHA-256:
 * eb293712bebe1b6d96eeb730cc7009875c1f3a7fc6657318d750de711f2be445. */
/* LED forwarding indicator: signed HID count>=1 skips vendor query; otherwise
 * call first_active and return0 immediately if none. Fence retry-pending; any
 * nonzero returns0. Otherwise fence/read forwarding-inhibit byte and return
 * raw XOR1, without boolean normalization. No port/global-pause/connection gate.
 * Separate snapshots can change between reads; no wait or state publication. */
unsigned char medius_host_forwarding_indicator(void)
{
    if (MEDIUS_HID_ENDPOINT_COUNT < 1 && medius_vendor_first_active() == 0) return 0;
    memw(); if (MEDIUS_HID_RETRY_PENDING != 0) return 0;
    memw(); return MEDIUS_HOST_FORWARDING_INHIBIT ^ 1U;
}

/* Native entry: 0x4202d78c. */
/* Original function-byte SHA-256:
 * f64dcc6fde69ba771965cdc153c45bc24a0eaa91b77cda546a0ae361cbb1a9e6. */
/* Fence/store low8 inhibit. Nonzero returns, leaving pending clone publication.
 * Zero fences/reads pending; nonzero fences/clears it, then fences/reads current
 * control port. NULL or unfenced capture-ready0 drops that pending request.
 * Otherwise fence/recheck inhibit: if nonzero, fence/reassert pending1; if zero,
 * call clone_publish. This reachable native recheck was removed by raw export.
 * No connected test, pointer lifetime check or publication-success return. */
void medius_host_set_forwarding_inhibit(unsigned char inhibit)
{
    memw(); MEDIUS_HOST_FORWARDING_INHIBIT = inhibit;
    if (inhibit != 0) return;
    memw(); if (MEDIUS_HOST_CLONE_PUBLICATION_PENDING == 0) return;
    memw(); MEDIUS_HOST_CLONE_PUBLICATION_PENDING = 0;
    memw(); if (MEDIUS_HOST_CONTROL_PORT == NULL) return;
    if (MEDIUS_HOST_CAPTURE_READY == 0) return;
    memw();
    if (MEDIUS_HOST_FORWARDING_INHIBIT != 0) {
        memw(); MEDIUS_HOST_CLONE_PUBLICATION_PENDING = 1;
    } else medius_clone_publish();
}

/* Native entry: 0x4202d824. */
/* Original function-byte SHA-256:
 * 40173e952d557afeba7013dcea1aad4a3a0ff9f437e05a8bc23dfbebd9182095. */
/* Fence and return the raw32 report-drop total. No reset, lock, saturation,
 * normalization or pairing with another status value. */
unsigned int medius_host_report_drop_count(void)
{
    memw(); return MEDIUS_HID_DROP_COUNT;
}

/* Native entry: 0x4202d834. */
/* Original function-byte SHA-256:
 * 6c44428430e10342b8c69c222315f0a31962675acbefe402e484423ffcae6244. */
/* Scan exactly six HID slots. Fence/cache active byte; only nonzero entries
 * fence/read poll period16. Return the FIRST cached active byte whose period
 * is>=2, otherwise0. No reread of active after the period fence and no boolean
 * normalization, handle check, pause gate or coherent aggregate snapshot. */
unsigned char medius_host_first_slow_hid_active(void)
{
    for (unsigned int slot = 0; slot < 6; ++slot) {
        volatile MediusHidEndpointState *state = &MEDIUS_HOST_HID_ENDPOINTS[slot];
        memw(); unsigned char active = state->active;
        if (active == 0) continue;
        memw(); if (state->poll_period >= 2) return active;
    }
    return 0;
}
