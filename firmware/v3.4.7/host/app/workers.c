/* Medius v3.4.7 host — app/workers.c.
 * Recovered C and native assembly, grouped for source navigation.
 * Original entry addresses, firmware-byte hashes and function comments follow.
 */

#include "../include/types.h"

/* Native entry: 0x4202ebe8. */
/* Original function-byte SHA-256:
 * 4d5f3c6df820e7b3a3d079652d5068635d49e038a7b860277990a313ece6244c. */
/* Create host application queues/workers and register shared software timers.
 * No arguments or result. Publish the 64x80-byte HID queue, then start hidfwd
 * (3072-byte stack, priority15, core0) and credit (3072,16,0), retaining only
 * the credit task handle. Configure direct RX type40hex with credit_receive,
 * NULL accounting list and zero count. Publish the 6x2068-byte control queue,
 * then start ctrlwk (4096,7,0) retaining its handle. Publish a capacity-one,
 * zero-payload signaling queue, initially empty; start cfgswitch (8192,6,0).
 * Queue creation/task statuses are ignored: a failed queue is still published
 * and later tasks/registrations still run. Repeated calls can leak resources.
 *
 * Create snap_emit, then halt_tick: NULL arguments, task dispatch=0 and the
 * complete skip/padding word zero. Snapshot creation status is ignored and
 * that timer is not armed here. Only successful halt creation calls periodic
 * start with 20000 us using the freshly loaded handle; start result ignored.
 * Finally install the TX admission callback/context0 regardless of failures.
 * Both are logical esp_timer software timers on its shared dispatcher. Their
 * callbacks can be delayed by dispatch work, task scheduling and interrupts;
 * deadlines are not guaranteed. No dedicated hardware timer is allocated here.
 * Timer/task/queue internals and callback bodies remain separate functions.
 * Existing no-argument native callbacks ignore the ABI-supplied NULL argument;
 * casts below express those call boundaries without inventing body parameters. */
void medius_host_workers_init(void)
{
    MEDIUS_HID_REPORT_QUEUE = xQueueGenericCreate(64,sizeof(MediusHidWork));
    xTaskCreatePinnedToCore(medius_task_hidfwd,"hidfwd",3072,NULL,15,NULL,0);
    xTaskCreatePinnedToCore(medius_task_credit,"credit",3072,NULL,16,
        (RtosTask **)&MEDIUS_CREDIT_TASK,0);
    link_configure_receive(0x40,medius_credit_receive,NULL,0);
    MEDIUS_HOST_CONTROL_WORK_QUEUE = xQueueGenericCreate(6,2068);
    xTaskCreatePinnedToCore((TaskEntry)medius_task_ctrlwk,"ctrlwk",4096,NULL,7,
        (RtosTask **)&MEDIUS_HOST_CONTROL_WORKER_TASK,0);
    MEDIUS_HOST_CONFIGURATION_QUEUE = xQueueGenericCreate(1,0);
    xTaskCreatePinnedToCore((TaskEntry)medius_task_cfgswitch,"cfgswitch",8192,NULL,6,NULL,0);

    EspTimerCreateArgs snapshot = {
        .callback = (MediusUsbTimerCallback)medius_snapshot_timer_cb,
        .argument = NULL, .dispatch = 0, .name = "snap_emit",
        .skip_unhandled_events = 0, .padding17 = {0,0,0}
    };
    esp_timer_create(&snapshot,(EspTimer **)&MEDIUS_HOST_SNAPSHOT_TIMER);
    EspTimerCreateArgs halt = {
        .callback = (MediusUsbTimerCallback)medius_halt_timer_cb,
        .argument = NULL, .dispatch = 0, .name = "halt_tick",
        .skip_unhandled_events = 0, .padding17 = {0,0,0}
    };
    if (esp_timer_create(&halt,(EspTimer **)&MEDIUS_HOST_HALT_TIMER) == 0) {
        EspTimer *timer = MEDIUS_HOST_HALT_TIMER;
        esp_timer_start_periodic(timer,20000ULL);
    }
    medius_link_set_tx_admission(medius_host_tx_admission,0);
}


/* Native entry: 0x420264e0. */
/* Original function-byte SHA-256:
 * 7d925fe1342be52ce4318760bd7bcc30ece05c34471359ee662f2194c593e05b. */
/* Admit a queued UART frame according to the most recently published HID timing.
 * encoded_length: Only low16 contributes to the hard-coded length/2 us budget
 *   (length*10,000,000 / 20,000,000); actual UART baud is not sampled here.
 * unused_context: Second admission-callback argument; native body ignores it.
 * Return int 0/1. Sample time first, then fenced last-report LOW32, then fenced
 * published delta. Age uses modulo32 subtraction. Age>20000 admits immediately,
 * but both timing words have already been read. Delta 1..20000 requires age
 * strictly below delta AND budget+100 strictly below delta-age. Delta0 or
 * delta>20000 instead admits budget<=300 (encoded low16<=601).
 * No waits, state writes or reservation occur; reads are independent snapshots.
 * This is an admission estimate, not a verified transport/scheduling deadline. */
int medius_host_tx_admission(unsigned int encoded_length,unsigned int unused_context)
{
    (void)unused_context;
    unsigned int now_us_low = (unsigned int)esp_timer_get_time();
    memw();
    unsigned int last_report_us = MEDIUS_HID_LAST_REPORT_US;
    memw();
    unsigned int report_delta_us = MEDIUS_HID_PUBLISHED_REPORT_DELTA;
    unsigned int age_us = now_us_low - last_report_us;
    if (age_us > 20000U)
        return 1;
    unsigned int budget_us = (unsigned int)
        (((unsigned long long)(encoded_length & 65535U) * 10000000ULL) / 20000000ULL);
    if (report_delta_us - 1U > 19999U)
        return budget_us <= 300U;
    if (age_us >= report_delta_us)
        return 0;
    return budget_us + 100U < report_delta_us - age_us;
}
