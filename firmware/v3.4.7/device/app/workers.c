/* Medius v3.4.7 device — app/workers.c.
 * Recovered C and native assembly, grouped for source navigation.
 * Original entry addresses, firmware-byte hashes and function comments follow.
 */

#include "../include/types.h"

/* Native entry: 0x42033f60. */
/* Original function-byte SHA-256:
 * ac6d6a774f6520e842a2882528a8961fad8f9558e356e5c28c91fdf9e3045738. */
/* Initialize device report/link callbacks, persisted motion options, tasks,
 * queues and timers. No arguments or return status. Task creation starts work
 * before later state is initialized; this routine supplies no enclosing lock.
 *
 * Always request rptfast: 4096-byte stack, priority 23, CPU 0, saved task handle.
 * Install RX observer/direct-type 0x10 routing, the 16-byte uncounted-type list
 * and fast credit TX callback, then initialize the profile store. Load imperf
 * directly into its live BYTE. U16 settings are applied only on nonzero load
 * status: "o7"/"ob" become WORD microseconds by multiplying by 1000; "oc"<2,
 * "o8"<3, "or"<4 and "os"<2 become BYTES; "ot" is an unfenced HALFWORD;
 * "o9"/"od" are fenced
 * HALFWORDs. Rejected/missing settings leave existing state. Every MEMW below
 * is before the corresponding native store or read, not after it. Loaded
 * setting halfwords are captured before their fence; do not reread the
 * escaped settings-output stack slots after MEMW.
 *
 * Sample pace once. Mode 1 copies the live learned WORD period; mode 2 defaults
 * to 1000 us, but a nonzero first rate sample causes a SECOND rate read and
 * native QUOU(1000000,min(second_sample,1000)). A concurrent change to zero
 * retains native divide-by-zero behavior. Other modes select period zero.
 * Publish period, then notify motion configuration change.
 *
 * Create missing report/input mutexes and empty one-token binary semaphores.
 * A missing txwd timer gates creation of txwd (3072-byte stack,priority 11,
 * CPU 0) and a task-dispatch software timer, periodic 50000 us. Existing timer
 * skips both actions. Create failure skips start; periodic-start status is
 * ignored. A missing decide GPTimer requests source 4,count-up 1,1000000 Hz,
 * priority 3,flags 0, callback/no user context, then enable/start. Publish only
 * after all four calls succeed; otherwise log without delete/disable/rollback.
 * It is a dedicated scheduling timer from the driver's shared allocation pool;
 * no alarm is armed here. Missing t0/t1 ESP timers are created inactive, with
 * task dispatch, NULL argument, skip=false and all argument padding zero.
 * They share the ESP timer task; none of these requests guarantees latency.
 *
 * Reserve EP0 task storage, then always replace CLIP backing allocation:
 * 65536 bytes/caps 0x400, falling back to 16384 then 8192/caps 0x804. Publish each
 * returned pointer and observed capacity; all failures still initialize the
 * ring with NULL/capacity 0 and fixed 512-byte scratch. No previous buffer free.
 * rstrelay is created only after creating its previously missing mutex:
 * 3072-byte stack,priority 21,no affinity,saved handle. OUT queue absence causes
 * an unconditional replacement mutex allocation and 38 x 80-byte data queue;
 * a successful queue requests outfwd:3072 bytes,priority 5,no affinity, no
 * saved handle. Task statuses in these paths are ignored. ctrln uses 4 x 1-byte
 * queue,4096-byte stack,priority 13,CPU 0,no handle; creation status other than 1
 * deletes the fresh live queue handle, restores the entry NULL and logs.
 *
 * Finally allocate 1534 bytes with the same caps fallback 0x400->0x804, clear
 * the 20-byte imperfect-control ring, store its backing pointer, then capacity
 * 1024 and staging pointer=allocation+1024; failure publishes zero/NULL. These
 * final resources are also replaced on repeat entry without freeing old ones.
 * Allocation/most task/timer failures remain unreported. No waits for workers,
 * startup atomicity, comprehensive cleanup or hardware/runtime verification. */
void device_workers_init(void)
{
    (void)xTaskCreatePinnedToCore(report_fast_task,"rptfast",4096,NULL,23,
        (RtosTask **)(void *)&REPORT_FAST_TASK,0);
    link_set_receive_observer(report_receive_observer);
    link_configure_receive(0x10,report_receive_direct,
        REPORT_UNCOUNTED_RECEIVE_TYPES,16);
    link_set_fast_transmit_handler(credit_build_packet);
    profile_storage_initialize();
    (void)settings_load_flag("imperf",
        (unsigned char *)(void *)&REWRITE_ALLOWED);

    unsigned short riding_ms=0;
    if (settings_load_u16("o7",&riding_ms)!=0) {
        unsigned int riding_us=(unsigned int)riding_ms*1000U;
        memw();
        MOVEMENT_RIDING_US=riding_us;
    }
    unsigned short pace=0,rate_hz=0,forced_hz=0,bearing_ms=0,coupled=0;
    if (settings_load_u16("ob",&bearing_ms)!=0) {
        unsigned int bearing_us=(unsigned int)bearing_ms*1000U;
        memw();
        MOTION_OPTIONS.bearing_window_us=bearing_us;
    }
    if (settings_load_u16("oc",&coupled)!=0) {
        unsigned short loaded_coupled=coupled;
        if (loaded_coupled<2) {
            memw();
            BEARING_COUPLED=(unsigned char)loaded_coupled;
        }
    }
    if (settings_load_u16("o8",&pace)!=0) {
        unsigned short loaded_pace=pace;
        if (loaded_pace<3) {
            memw();
            EMISSION_OPTIONS.pace=(unsigned char)loaded_pace;
        }
    }
    unsigned short profile=0;
    if (settings_load_u16("or",&profile)!=0) {
        unsigned short loaded_profile=profile;
        if (loaded_profile<4) {
            memw();
            MOTION_OPTIONS.profile=(unsigned char)loaded_profile;
        }
    }
    unsigned short scope=0;
    if (settings_load_u16("os",&scope)!=0) {
        unsigned short loaded_scope=scope;
        if (loaded_scope<2) {
            memw();
            EMISSION_OPTIONS.scope=(unsigned char)loaded_scope;
        }
    }
    unsigned short spread=0;
    if (settings_load_u16("ot",&spread)!=0)
        MOTION_OPTIONS.spread=spread;
    if (settings_load_u16("o9",&rate_hz)!=0) {
        unsigned short loaded_rate_hz=rate_hz;
        memw();
        EMISSION_OPTIONS.configured_hz=loaded_rate_hz;
    }
    if (settings_load_u16("od",&forced_hz)!=0) {
        unsigned short loaded_forced_hz=forced_hz;
        memw();
        EMISSION_OPTIONS.forced_hz=loaded_forced_hz;
    }
    memw();
    unsigned char selected_pace=EMISSION_OPTIONS.pace;
    unsigned int period_us=0;
    if (selected_pace==1) {
        memw();
        period_us=EMISSION_OPTIONS.learned_period_us;
    } else if (selected_pace==2) {
        period_us=1000;
        memw();
        unsigned short observed_rate=EMISSION_OPTIONS.configured_hz;
        if (observed_rate!=0) {
            memw();
            unsigned int second_rate=EMISSION_OPTIONS.configured_hz;
            unsigned int divisor=second_rate<1000U?second_rate:1000U;
            period_us=xtensa_unsigned_divide(1000000U,divisor);
        }
    }
    memw();
    EMISSION_OPTIONS.period_us=period_us;
    motion_configuration_changed();

    if (REPORT_MUTEX==NULL)
        REPORT_MUTEX=rtos_create_mutex_type(1);
    if (CONTROL_ENDPOINT_REPLY_SIGNAL==NULL)
        CONTROL_ENDPOINT_REPLY_SIGNAL=rtos_create_queue_type(1,0,3);
    if (AUXILIARY_BINARY_SEMAPHORE==NULL)
        AUXILIARY_BINARY_SEMAPHORE=rtos_create_queue_type(1,0,3);
    if (TRANSMIT_WATCHDOG_TIMER==NULL) {
        if (MOTION_TXWD_TASK==NULL)
            (void)xTaskCreatePinnedToCore(transmit_watchdog_task_entry,"txwd",3072,NULL,11,
                (RtosTask **)(void *)&MOTION_TXWD_TASK,0);
        EspTimerCreateArgs arguments;
        volatile EspTimerCreateArgs *initialization=&arguments;
        initialization->argument=NULL;
        initialization->callback=transmit_watchdog_timer_callback;
        initialization->name="txwd";
        initialization->dispatch=0;
        *(volatile unsigned int *)((unsigned char *)&arguments+
            offsetof(EspTimerCreateArgs,skip_unhandled_events))=0;
        if (esp_timer_create(&arguments,
            (EspTimer **)(void *)&TRANSMIT_WATCHDOG_TIMER)==0)
            (void)esp_timer_start_periodic(TRANSMIT_WATCHDOG_TIMER,50000ULL);
    }
    if (DECISION_TIMER_HANDLE==NULL) {
        GptimerConfig configuration;
        volatile GptimerConfig *initialization=&configuration;
        initialization->clock_source=4;
        initialization->direction=1;
        initialization->resolution_hz=1000000;
        initialization->intr_priority=3;
        initialization->flags=0;
        Gptimer *timer=NULL;
        GptimerCallbacks callbacks={.on_alarm=decision_timer_alarm_callback};
        if (gptimer_new_timer(&configuration,&timer)==0 &&
            gptimer_register_event_callbacks(timer,&callbacks,NULL)==0 &&
            gptimer_enable(timer)==0 && gptimer_start(timer)==0) {
            DECISION_TIMER_HANDLE=timer;
        } else {
            unsigned int timestamp=esp_log_timestamp();
            esp_log_write(1,"usbdev","E (%lu) %s: decide timer did not start\n",
                timestamp,"usbdev");
        }
    }
    if (INPUT_TIMER_MUTEX==NULL)
        INPUT_TIMER_MUTEX=rtos_create_mutex_type(1);
    if (INPUT_PUBLICATION_MUTEX==NULL)
        INPUT_PUBLICATION_MUTEX=rtos_create_mutex_type(1);
    if (INPUT_TIMER_HANDLE==NULL) {
        EspTimerCreateArgs arguments;
        volatile EspTimerCreateArgs *initialization=&arguments;
        initialization->callback=input_timer_cb;
        initialization->argument=NULL;
        initialization->name="t0";
        initialization->dispatch=0;
        *(volatile unsigned int *)((unsigned char *)&arguments+
            offsetof(EspTimerCreateArgs,skip_unhandled_events))=0;
        (void)esp_timer_create(&arguments,
            (EspTimer **)(void *)&INPUT_TIMER_HANDLE);
    }
    if (CLIP_ACTION_TIMER==NULL) {
        EspTimerCreateArgs arguments;
        volatile EspTimerCreateArgs *initialization=&arguments;
        initialization->callback=catch_action_timer_cb;
        initialization->argument=NULL;
        initialization->name="t1";
        initialization->dispatch=0;
        *(volatile unsigned int *)((unsigned char *)&arguments+
            offsetof(EspTimerCreateArgs,skip_unhandled_events))=0;
        (void)esp_timer_create(&arguments,
            (EspTimer **)(void *)&CLIP_ACTION_TIMER);
    }
    control_endpoint_reserve_task_storage();
    unsigned char *clip_storage=heap_caps_malloc(65536,0x400);
    CLIP_ALLOCATION_STORAGE=clip_storage;
    unsigned int clip_capacity;
    if (clip_storage!=NULL) {
        clip_capacity=65536;
        CLIP_ALLOCATION_CAPACITY=65536;
    } else {
        CLIP_ALLOCATION_CAPACITY=0;
        clip_storage=heap_caps_malloc(16384,0x804);
        CLIP_ALLOCATION_STORAGE=clip_storage;
        CLIP_ALLOCATION_CAPACITY=clip_storage!=NULL?16384:0;
        clip_capacity=16384;
        if (clip_storage==NULL) {
            clip_storage=heap_caps_malloc(8192,0x804);
            clip_capacity=clip_storage!=NULL?8192:0;
            CLIP_ALLOCATION_STORAGE=clip_storage;
            CLIP_ALLOCATION_CAPACITY=clip_capacity;
        }
    }
    clip_ring_init(PLAYBACK_RING,clip_storage,clip_capacity,
        PLAYBACK_CONTROL_CAPTURE_SCRATCH);
    if (CONTROL_FORWARD_GATE==NULL) {
        RtosQueue *gate=rtos_create_mutex_type(1);
        CONTROL_FORWARD_GATE=gate;
        if (gate!=NULL)
            (void)xTaskCreatePinnedToCore(reset_relay_task,"rstrelay",3072,NULL,21,
                (RtosTask **)(void *)&RESET_RELAY_TASK,0x7fffffff);
    }
    if (DEVICE_OUT_FORWARD_QUEUE==NULL) {
        DEVICE_OUT_OUTER_MUTEX=rtos_create_mutex_type(1);
        RtosQueue *queue=rtos_create_queue_type(38,80,0);
        DEVICE_OUT_FORWARD_QUEUE=queue;
        if (queue!=NULL)
            (void)xTaskCreatePinnedToCore(outbound_forward_task,"outfwd",3072,NULL,5,
                NULL,0x7fffffff);
    }
    if (NONZERO_CONTROL_WORKER_SIGNAL==NULL)
        NONZERO_CONTROL_WORKER_SIGNAL=rtos_create_queue_type(1,0,3);
    RtosQueue *previous_control_queue=NONZERO_CONTROL_QUEUE;
    if (previous_control_queue==NULL) {
        RtosQueue *queue=rtos_create_queue_type(4,1,0);
        NONZERO_CONTROL_QUEUE=queue;
        if (queue!=NULL && xTaskCreatePinnedToCore(nonzero_control_task_entry,"ctrln",
            4096,NULL,13,NULL,0)!=1) {
            vQueueDelete(NONZERO_CONTROL_QUEUE);
            NONZERO_CONTROL_QUEUE=previous_control_queue;
            unsigned int timestamp=esp_log_timestamp();
            esp_log_write(1,"usbdev",
                "E (%lu) %s: ctrln task did not start; control endpoints above 0 cannot be served\n",
                timestamp,"usbdev");
        }
    }
    unsigned char *control_storage=heap_caps_malloc(1534,0x400);
    if (control_storage==NULL)
        control_storage=heap_caps_malloc(1534,0x804);
    memset((void *)IMPERFECT_CLIP_QUEUE,0,sizeof(ImperfectClipQueue));
    IMPERFECT_CLIP_QUEUE->storage=control_storage;
    unsigned int control_capacity=0;
    unsigned char *staging=control_storage;
    if (control_storage!=NULL) {
        staging=(unsigned char *)((unsigned int)control_storage+1024U);
        control_capacity=1024;
    }
    IMPERFECT_CLIP_QUEUE->capacity=control_capacity;
    PLAYBACK_CONTROL_STAGING=staging;
}
