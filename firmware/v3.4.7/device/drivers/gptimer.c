/* Medius v3.4.7 device — drivers/gptimer.c.
 * Recovered C and native assembly, grouped for source navigation.
 * Original entry addresses, firmware-byte hashes and function comments follow.
 */

#include "../include/types.h"

/* reconstruction utilities: unchecked native indices use unsigned 32-bit
 * address arithmetic. Keep them independent of C array bounds. */
static __inline__ __attribute__((always_inline)) GptimerRegisters *
gptimer_counter_registers(GptimerGroupRegisters *device,unsigned int index)
{
    return (GptimerRegisters *)(uintptr_t)
        ((unsigned int)(uintptr_t)device + index * 0x24U);
}

static __inline__ __attribute__((always_inline)) GptimerGroup *volatile *
gptimer_platform_group_slot(GptimerPlatform *platform,unsigned int index)
{
    return (GptimerGroup *volatile *)(uintptr_t)
        ((unsigned int)(uintptr_t)platform + 4U + index * 4U);
}

static __inline__ __attribute__((always_inline)) volatile unsigned int *
gptimer_platform_reference_slot(GptimerPlatform *platform,unsigned int index)
{
    return (volatile unsigned int *)(uintptr_t)
        ((unsigned int)(uintptr_t)platform + 12U + index * 4U);
}

static __inline__ __attribute__((always_inline)) Gptimer *volatile *
gptimer_group_timer_slot(GptimerGroup *group,unsigned int index)
{
    return (Gptimer *volatile *)(uintptr_t)
        ((unsigned int)(uintptr_t)group + 12U + index * 4U);
}

static __inline__ __attribute__((always_inline)) const GptimerSignals *
gptimer_signal_entry(unsigned int group_id)
{
    return (const GptimerSignals *)(uintptr_t)
        ((unsigned int)(uintptr_t)GPTIMER_SIGNALS + group_id * 12U);
}

static __inline__ __attribute__((always_inline)) unsigned int
gptimer_interrupt_source(unsigned int group_id,unsigned int timer_id)
{
    unsigned int address = (unsigned int)(uintptr_t)GPTIMER_SIGNALS
                         + group_id * 12U + 4U + timer_id * 4U;
    return *(const unsigned int *)(uintptr_t)address;
}

/* Native entry: 0x40383ff0. */
/* Original function-byte SHA-256:
 * 7c17457cdcb497855024d83854d86064113413fecaa3187827802de362f86f5c. */
/*
 * Rejects a null timer or output with0x102, leaving output unchanged. Queries
 * ISR context (ignored), enters the timer mux indefinitely (result ignored),
 * and captures54 bits through the HAL. Writes output HIGH WORD before LOW,
 * queries ISR context again and unlocks. Returns0; no FSM check or timeout.
 */
int gptimer_get_raw_count(Gptimer *timer,unsigned long long *count)
{
    if (timer == 0 || count == 0) return 0x102;
    PortMuxWords *lock = &timer->lock;
    (void)xPortInIsrContext();
    (void)xPortEnterCriticalTimeout(lock,-1);
    unsigned long long captured = timer_hal_capture_and_get_counter_value(&timer->hal);
    volatile unsigned int *words = (volatile unsigned int *)count;
    words[1] = (unsigned int)(captured >> 32);
    words[0] = (unsigned int)captured;
    (void)xPortInIsrContext();
    vPortExitCritical(lock);
    return 0;
}

/* Native entry: 0x40384030. */
/* Original function-byte SHA-256:
 * c17088eac6cea341734aa844c72c36cb4baf4a90185fd4af5c2eeac86480868d. */
/*
 * Null timer returns0x102. Nonnull alarm with flags bit0 and equal64-bit
 * alarm/reload counts is rejected before locking; comparison short-circuits
 * LOW before HIGH. Otherwise takes timer mux, rereads config WORDs in native
 * order and stores reload HIGH/LOW, alarm LOW/HIGH and flags BYTE (bit1 reload,
 * bit2 alarm). Writes hardware reload HIGH/LOW then alarm HIGH/LOW, masking
 * HIGH to22 bits and preserving its other bits. Null alarm only clears the two
 * software bits in this first critical section. Config may change between the
 * initial validation and locked reads; no coherent config snapshot is promised.
 *
 * Unlocks and reacquires the same mux, reloads index/base and two separate
 * flags WORDs: first bit1 programs auto-reload bit29, second bit2 programs
 * alarm bit10. The second flag sample precedes the first register store.
 * Preserves native MEMW order and the gap between critical sections. Returns0;
 * no FSM check, count-range check, interrupt clear or counter restart occurs.
 */
int gptimer_set_alarm_action(Gptimer *timer,const GptimerAlarmConfig *alarm)
{
    if (timer == 0) return 0x102;
    const volatile GptimerAlarmWords *config = (const volatile GptimerAlarmWords *)alarm;
    if (config != 0) {
        unsigned char reload_enabled = *(const volatile unsigned char *)&config->flags;
        if ((reload_enabled & 1U) != 0 && config->alarm_low == config->reload_low &&
            config->alarm_high == config->reload_high) return 0x102;
    }
    (void)xPortInIsrContext();
    PortMuxWords *lock = &timer->lock;
    (void)xPortEnterCriticalTimeout(lock,-1);
    if (config == 0) timer->flags.low_byte &= 0xf9U;
    else {
        unsigned int flags = config->flags;
        unsigned int alarm_high = config->alarm_high;
        unsigned int reload_high = config->reload_high;
        unsigned int reload_low = config->reload_low;
        unsigned int alarm_low = config->alarm_low;
        unsigned char old_flags = timer->flags.low_byte;
        unsigned int index = timer->timer_id;
        GptimerGroupRegisters *dev = timer->hal.dev;
        timer->reload_high = reload_high;
        GptimerRegisters *regs = gptimer_counter_registers(dev,index);
        timer->reload_low = reload_low;
        timer->alarm_low = alarm_low;
        timer->alarm_high = alarm_high;
        timer->flags.low_byte = (old_flags & 0xf9U) | ((flags & 1U) << 1) | 4U;
        memw(); unsigned int high_word = regs->reload_high;
        memw(); regs->reload_high = (high_word & 0xffc00000U) | (reload_high & 0x3fffffU);
        memw(); regs->reload_low = reload_low;
        memw(); high_word = regs->alarm_high;
        memw(); regs->alarm_high = (high_word & 0xffc00000U) | (alarm_high & 0x3fffffU);
        memw(); regs->alarm_low = alarm_low;
    }
    (void)xPortInIsrContext();
    vPortExitCritical(lock);
    (void)xPortInIsrContext();
    (void)xPortEnterCriticalTimeout(lock,-1);
    unsigned int index = timer->timer_id;
    GptimerGroupRegisters *dev = timer->hal.dev;
    GptimerRegisters *regs = gptimer_counter_registers(dev,index);
    unsigned int auto_flags = timer->flags.word;
    memw(); unsigned int configuration = regs->configuration;
    unsigned int alarm_flags = timer->flags.word;
    memw(); regs->configuration = (configuration & 0xdfffffffU) | (((auto_flags >> 1) & 1U) << 29);
    memw(); configuration = regs->configuration;
    memw(); regs->configuration = (configuration & 0xfffffbffU) | (((alarm_flags >> 2) & 1U) << 10);
    (void)xPortInIsrContext();
    vPortExitCritical(lock);
    return 0;
}

/* Native entry: 0x42011b90. */
/* Original function-byte SHA-256:
 * cbcf36cd556b903f55d075d34950f76d6eaff2d6bac76ed70bdbffcf148e0699. */
/*
 * Requires initialized handle and nonzero requested_hz; no local validation.
 * Captures timer index, queries source Hz with precision0, and on failure logs
 * line104 and returns the query status without programming. Success calls the
 * source-enable stub (result ignored), then only accepts APB4 or XTAL11; other
 * sources abort. Sets/clears configuration bit9 before calculating floor(srcHz/
 * requestedHz). Publishes clock_source before checking divisor range2..65536;
 * outside this range aborts (including zero resolution's native divide fault).
 * Replaces divider bits13..28, encoding65536 as0, retaining the native six MEMWs
 * and volatile stack read/write staging, then separately sets bit12. Publishes
 * floor(srcHz/divisor) as actual resolution; a mismatch logs one warning. No
 * lock, rollback, PM-lock creation or source frequency measurement is supplied.
 */
int gptimer_select_periph_clock(Gptimer *timer,unsigned int source,unsigned int requested_hz)
{
    unsigned int index = timer->timer_id;
    volatile unsigned int source_hz = 0;
    int status = esp_clk_tree_src_get_freq_hz(source,0,(unsigned int *)&source_hz);
    if (status == 0) {
        (void)esp_clk_tree_enable_src(source,true);
        GptimerGroupRegisters *dev = timer->hal.dev;
        GptimerRegisters *regs = gptimer_counter_registers(dev,index);
        if (source == 4) {
            memw(); unsigned int word = regs->configuration;
            memw(); regs->configuration = word & 0xfffffdffU;
        } else if (source == 11) {
            memw(); unsigned int word = regs->configuration;
            memw(); regs->configuration = word | 0x200U;
        } else abort();
        unsigned int clock_hz = source_hz;
        unsigned int divisor = xtensa_unsigned_divide(clock_hz,requested_hz);
        timer->clock_source = source;
        if (divisor - 2U > 65534U) abort();
        memw(); unsigned int word = regs->configuration;
        memw(); volatile unsigned int staged_word = word;
        memw(); word = staged_word;
        memw(); staged_word = (word & 0xe0001fffU) | ((divisor & 0xffffU) << 13);
        memw(); word = staged_word;
        memw(); regs->configuration = word;
        memw(); word = regs->configuration;
        unsigned int actual_hz = xtensa_unsigned_divide(clock_hz,divisor);
        memw(); regs->configuration = word | 0x1000U;
        timer->resolution_hz = actual_hz;
        if (actual_hz != requested_hz) {
            unsigned int timestamp = esp_log_timestamp();
            unsigned int published_hz = timer->resolution_hz;
            esp_log_write(2,"gptimer","W (%lu) %s: resolution lost, expect %lu, real %lu\n",
                timestamp,"gptimer",requested_hz,published_hz);
        }
    } else {
        unsigned int timestamp = esp_log_timestamp();
        esp_log_write(1,"gptimer","E (%lu) %s: %s(%d): get clock source frequency failed\n",
            timestamp,"gptimer","gptimer_select_periph_clock",104U);
    }
    return status;
}

/* Native entry: 0x42022b0c. */
/* Original function-byte SHA-256:
 * 10a09f92b0582a236ca6e4b3a544b72edd20a0426f9f433fbfe82e773c578b28. */
/*
 * Validates config/output nonnull, resolution nonzero, then interrupt priority:
 * zero or a nonzero value whose low5 bits are1..3 is accepted. Rejects flags
 * bits1/2 with0x106; other flag bits are ignored except shared-interrupt bit0.
 * Allocates a zeroed88-byte handle with caps0x804. Tries group0 then1, acquiring
 * references and their muxes; reserves first free slot0 then1. Allocation/group
 * failure0x101, exhaustion0x105. Logs registration failure and destroys the new
 * object on these errors, ignoring cleanup status. Output remains untouched.
 *
 * Stores group/index, initializes HAL, selects requested clock/resolution,
 * and on error logs/destroys/returns that original status. On success loads
 * hardware counter0, sets count-up bit30 only for direction==1, disables/clears
 * that group interrupt under its group mux, initializes the timer mux and FSM0,
 * then rereads flags/direction/priority from config before final handle output.
 * No callback/interrupt is installed, no alarm/counting starts and no particular
 * physical counter is guaranteed: allocation comes from the shared group pool.
 * Config may change between initial checks and later reads; no rollback on abort.
 */
int gptimer_new_timer(const GptimerConfig *configuration,Gptimer **output)
{
    const volatile GptimerConfig *config = configuration;
    const char *detail_format;
    unsigned int detail_line,detail_value,timestamp;
    if (config == 0 || output == 0) {
        timestamp = esp_log_timestamp();
        esp_log_write(1,"gptimer","E (%lu) %s: %s(%d): invalid argument\n",timestamp,
            "gptimer","gptimer_new_timer",128U);
        return 0x102;
    }
    if (config->resolution_hz == 0) {
        timestamp = esp_log_timestamp();
        detail_value = config->resolution_hz;
        detail_format = "E (%lu) %s: %s(%d): invalid timer resolution:%lu\n";
        detail_line = 129;
        goto invalid_detail;
    }
    unsigned int priority = config->intr_priority;
    if (priority != 0 && (0xfffffff1U & (1U << (priority & 31U))) != 0) {
        timestamp = esp_log_timestamp();
        detail_value = config->intr_priority;
        detail_format = "E (%lu) %s: %s(%d): invalid interrupt priority:%d\n";
        detail_line = 131;
        goto invalid_detail;
    }
    if ((config->flags & 6U) != 0) {
        timestamp = esp_log_timestamp();
        esp_log_write(1,"gptimer","E (%lu) %s: %s(%d): not able to power down in light sleep\n",
            timestamp,"gptimer","gptimer_new_timer",137U);
        return 0x106;
    }
    Gptimer *timer = heap_caps_calloc(1,88,0x804);
    if (timer == 0) {
        timestamp = esp_log_timestamp();
        esp_log_write(1,"gptimer","E (%lu) %s: %s(%d): no mem for gptimer\n",
            timestamp,"gptimer","gptimer_new_timer",141U);
        return 0x101;
    }
    unsigned int group_id = 0,index;
    int status;
    GptimerGroup *group;
    for (;;) {
        group = gptimer_acquire_group_handle(group_id);
        if (group == 0) {
            timestamp = esp_log_timestamp();
            esp_log_write(1,"gptimer","E (%lu) %s: %s(%d): no mem for group (%d)\n",
                timestamp,"gptimer","gptimer_register_to_group",46U,group_id);
            status = 0x101;
            goto registration_error;
        }
        (void)xPortEnterCriticalTimeout(&group->lock,-1);
        if (group->timers[0] == 0) index = 0;
        else if (group->timers[1] == 0) index = 1;
        else {
            vPortExitCritical(&group->lock);
            gptimer_release_group_handle(group);
            if (group_id == 0) { group_id = 1; continue; }
            timestamp = esp_log_timestamp();
            esp_log_write(1,"gptimer","E (%lu) %s: %s(%d): no free timer\n",
                timestamp,"gptimer","gptimer_register_to_group",65U);
            status = 0x105;
            goto registration_error;
        }
        group->timers[index] = timer;
        vPortExitCritical(&group->lock);
        break;
    }
    unsigned int hardware_group = group->group_id;
    timer->group = group;
    timer->timer_id = index;
    timer_hal_init(&timer->hal,hardware_group,index);
    unsigned int requested_hz = config->resolution_hz;
    unsigned int source = config->clock_source;
    status = gptimer_select_periph_clock(timer,source,requested_hz);
    if (status != 0) goto clock_error;
    timer_hal_set_counter_value(&timer->hal,0);
    GptimerGroupRegisters *dev = timer->hal.dev;
    unsigned int direction = config->direction;
    GptimerRegisters *regs = gptimer_counter_registers(dev,index);
    memw(); unsigned int word = regs->configuration;
    memw(); regs->configuration = (word & 0xbfffffffU) | ((unsigned int)(direction == 1U) << 30);
    (void)xPortEnterCriticalTimeout(&group->lock,-1);
    dev = timer->hal.dev;
    memw(); word = dev->interrupt_enable;
    unsigned int mask = 1U << (index & 31U);
    memw(); dev->interrupt_enable = word & ~mask;
    memw(); dev->interrupt_clear = mask;
    vPortExitCritical(&group->lock);
    *(volatile unsigned int *)&timer->lock.count = 0;
    *(volatile unsigned int *)&timer->lock.owner = 0xb33fffffU;
    memw(); timer->fsm = 0;
    unsigned int flags = config->flags;
    unsigned char old_flags = timer->flags.low_byte;
    direction = config->direction;
    priority = config->intr_priority;
    timer->direction = direction;
    timer->intr_priority = priority;
    timer->flags.low_byte = (old_flags & 0xfeU) | (flags & 1U);
    *output = timer;
    return 0;
registration_error:
    timestamp = esp_log_timestamp();
    esp_log_write(1,"gptimer","E (%lu) %s: %s(%d): register timer failed\n",
        timestamp,"gptimer","gptimer_new_timer",143U);
    goto cleanup;
clock_error:
    timestamp = esp_log_timestamp();
    esp_log_write(1,"gptimer","E (%lu) %s: %s(%d): set periph clock failed\n",
        timestamp,"gptimer","gptimer_new_timer",157U);
cleanup:
    (void)gptimer_destroy(timer);
    return status;
invalid_detail:
    esp_log_write(1,"gptimer",detail_format,timestamp,"gptimer","gptimer_new_timer",detail_line,detail_value);
    return 0x102;
}

/* Native entry: 0x42022da8. */
/* Original function-byte SHA-256:
 * 856cf88ca4644838d932907d779e91db4b6a36b6b4fba6c9cfbc341ade057455. */
/*
 * Rejects null handle/callback table with0x102. Caches group; if no interrupt
 * handle, snapshots group ID/index, performs MEMW/MEMW/FSM read/MEMW and requires
 * FSM0 (otherwise0x103). Allocates interrupt with flags0x800 plus0x100 when
 * shared, plus1<<(priority&31) for nonzero priority; uses signal-table IRQ,
 * status address base+0x78, full shifted mask, default ISR and &timer->intr.
 * Allocation failure logs/returns that status. Existing interrupt bypasses FSM
 * validation. Under cached group mux, rereads index, callback and HAL base,
 * setting/clearing that interrupt-enable bit. Unlocks before REREADING callback
 * and storing it, then user_context. A changing callback table can make enabled
 * IRQ differ from installed callback. No IRAM/context validation in this build,
 * timer start, interrupt service enable or synchronized callback publication.
 */
int gptimer_register_event_callbacks(Gptimer *timer,const GptimerCallbacks *callbacks,void *user_context)
{
    const volatile GptimerCallbacks *cbs = callbacks;
    if (timer == 0 || cbs == 0) {
        unsigned int timestamp = esp_log_timestamp();
        esp_log_write(1,"gptimer","E (%lu) %s: %s(%d): invalid argument\n",timestamp,
            "gptimer","gptimer_register_event_callbacks",262U);
        return 0x102;
    }
    InterruptHandle *intr = timer->intr;
    GptimerGroup *group = timer->group;
    if (intr == 0) {
        unsigned int group_id = group->group_id;
        unsigned int index = timer->timer_id;
        memw(); memw(); unsigned int fsm = timer->fsm; memw();
        if (fsm != 0) {
            unsigned int timestamp = esp_log_timestamp();
            esp_log_write(1,"gptimer","E (%lu) %s: %s(%d): timer not in init state\n",timestamp,
                "gptimer","gptimer_register_event_callbacks",278U);
            return 0x103;
        }
        unsigned char flags = timer->flags.low_byte;
        unsigned int priority = timer->intr_priority;
        GptimerGroupRegisters *dev = timer->hal.dev;
        unsigned int isr_flags = (flags & 1U) ? 0x900U : 0x800U;
        if (priority != 0) isr_flags |= 1U << (priority & 31U);
        unsigned int irq = gptimer_interrupt_source(group_id,index);
        int status = gptimer_alloc_interrupt(irq,isr_flags,(unsigned int)&dev->interrupt_status,
            1U << (index & 31U),gptimer_default_isr,timer,(InterruptHandle **)&timer->intr);
        if (status != 0) {
            unsigned int timestamp = esp_log_timestamp();
            esp_log_write(1,"gptimer","E (%lu) %s: %s(%d): install interrupt service failed\n",timestamp,
                "gptimer","gptimer_register_event_callbacks",284U);
            return status;
        }
    }
    (void)xPortEnterCriticalTimeout(&group->lock,-1);
    unsigned int index = timer->timer_id;
    GptimerAlarmCallback callback = cbs->on_alarm;
    GptimerGroupRegisters *dev = timer->hal.dev;
    unsigned int mask = 1U << (index & 31U);
    memw(); unsigned int enabled = dev->interrupt_enable;
    memw(); dev->interrupt_enable = callback != 0 ? enabled | mask : enabled & ~mask;
    vPortExitCritical(&group->lock);
    timer->on_alarm = cbs->on_alarm;
    timer->user_context = user_context;
    return 0;
}

/* Native entry: 0x42022eec. */
/* Original function-byte SHA-256:
 * c20e36167f04eb444197cf78872a23e48b3c8d602118d870349d8581c351a31d. */
/*
 * Null handle logs/returns0x102. Strong compare-exchange FSM0->1 with both
 * fourth/fifth compiler-call WORDs5; failure logs/returns0x103. Acquires a nonnull PM lock (this
 * build's stub returns0x106), then enables a nonnull interrupt. Either error
 * logs/returns immediately while FSM remains1; no rollback or release occurs.
 * Returns0 if both steps succeed or are absent. Does not start counting.
 */
int gptimer_enable(Gptimer *timer)
{
    if (timer == 0) {
        unsigned int timestamp = esp_log_timestamp();
        esp_log_write(1,"gptimer","E (%lu) %s: %s(%d): invalid argument\n",timestamp,
            "gptimer","gptimer_enable",343U);
        return 0x102;
    }
    unsigned int expected = 0;
    if (gptimer_compare_exchange(&timer->fsm,&expected,1,5,5) == 0) {
        unsigned int timestamp = esp_log_timestamp();
        esp_log_write(1,"gptimer","E (%lu) %s: %s(%d): timer not in init state\n",timestamp,
            "gptimer","gptimer_enable",346U);
        return 0x103;
    }
    int status;
    const char *error_format;
    unsigned int error_line;
    void *pm_lock = timer->pm_lock;
    if (pm_lock != 0 && (status = esp_pm_lock_acquire(pm_lock)) != 0) {
        error_format = "E (%lu) %s: %s(%d): acquire pm_lock failed\n";
        error_line = 351;
        goto error;
    }
    InterruptHandle *intr = timer->intr;
    if (intr == 0) return 0;
    status = esp_intr_enable(intr);
    if (status == 0) return 0;
    error_format = "E (%lu) %s: %s(%d): enable interrupt service failed\n";
    error_line = 356;
error:
    ;
    unsigned int timestamp = esp_log_timestamp();
    esp_log_write(1,"gptimer",error_format,timestamp,"gptimer","gptimer_enable",error_line);
    return status;
}

/* Native entry: 0x40383f68. */
/* Original function-byte SHA-256:
 * c9acd21528cc7d2492e07704035bd084b985b42505acb02e8e4b9beead59410d. */
/*
 * argument: driver handle; no null/range validation. MEMW/samples group
 * interrupt status and returns unless (status & (1<<(index&31)) &3) is nonzero.
 * Caches group and callback before HAL capture, snapshots software alarm LOW
 * then HIGH into a16-byte event, and locks the cached group. Reloads index,
 * HAL base and flags BYTE; clears the event and, for auto-reload bit1, rearms
 * alarm bit10 with a separate MEMW read/write. Unlocks before invoking the
 * cached callback with fresh user_context. Any nonzero WORD return requests
 * _frxt_setup_switch. Uses group lock rather than the per-timer mux; no loop.
 */
void gptimer_default_isr(void *argument)
{
    Gptimer *timer = argument;
    GptimerGroupRegisters *dev = timer->hal.dev;
    unsigned int index = timer->timer_id;
    memw(); unsigned int status = dev->interrupt_status;
    if ((status & (1U << (index & 31U)) & 3U) == 0) return;
    GptimerGroup *group = timer->group;
    GptimerAlarmCallback callback = timer->on_alarm;
    GptimerAlarmEvent event;
    unsigned long long captured = timer_hal_capture_and_get_counter_value(&timer->hal);
    unsigned int alarm_low = timer->alarm_low;
    unsigned int alarm_high = timer->alarm_high;
    volatile unsigned int *event_words = (volatile unsigned int *)&event;
    event_words[2] = alarm_low;
    event_words[3] = alarm_high;
    event_words[0] = (unsigned int)captured;
    event_words[1] = (unsigned int)(captured >> 32);
    (void)xPortEnterCriticalTimeout(&group->lock,-1);
    index = timer->timer_id;
    dev = timer->hal.dev;
    unsigned char flags = timer->flags.low_byte;
    memw(); dev->interrupt_clear = 1U << (index & 31U);
    if ((flags & 2U) != 0) {
        GptimerRegisters *regs = gptimer_counter_registers(dev,index);
        memw(); unsigned int configuration = regs->configuration;
        memw(); regs->configuration = configuration | 0x400U;
    }
    vPortExitCritical(&group->lock);
    if (callback != 0 && callback(timer,&event,timer->user_context) != 0)
        _frxt_setup_switch();
}

/* Native entry: 0x4038aec4. */
/* Original function-byte SHA-256:
 * b95cb6a1a3049bf5a397523c4bd4277717a999978f8c96e7ab408f8e3769eaed. */
/*
 * hal: initialized timer-group base and counter index; neither is validated.
 * MEMW/read UPDATE, MEMW/write bit31 to request capture, then MEMW/poll that
 * bit until hardware clears it. Reads count HIGH first, then LOW, each after
 * MEMW, returning54 bits (HIGH masked to22). No timeout, retry snapshot or
 * lock; caller must serialize register access and provide a running bus.
 */
unsigned long long timer_hal_capture_and_get_counter_value(TimerHal *hal)
{
    unsigned int timer_id = hal->timer_id;
    GptimerGroupRegisters *dev = hal->dev;
    GptimerRegisters *regs = gptimer_counter_registers(dev,timer_id);
    memw();
    unsigned int update = regs->update;
    memw();
    regs->update = update | 0x80000000U;
    do { memw(); } while ((regs->update & 0x80000000U) != 0);
    memw();
    unsigned int high = regs->count_high;
    memw();
    unsigned int low = regs->count_low;
    return ((unsigned long long)(high & 0x3fffffU) << 32) | low;
}

/* Native entry: 0x42024800. */
/* Original function-byte SHA-256:
 * 24d5b4f377b2ebab306e6bcaee33815ea579091cf3781c9e0f93b4c8ad2d2526. */
/*
 * Stores the supplied counter index, treats any nonzero group ID as group1,
 * then MEMW/reads that counter's configuration before publishing the HAL base.
 * Performs three separate MEMW read/write stages clearing counter bit31,
 * auto-reload bit29 and alarm bit10 in order. No index/range validation,
 * reset, clock enable, lock, interrupt configuration or wait is supplied.
 */
void timer_hal_init(TimerHal *hal,unsigned int group_id,unsigned int timer_id)
{
    GptimerGroupRegisters *dev = group_id == 0 ? GPTIMER_GROUP0 : GPTIMER_GROUP1;
    hal->timer_id = timer_id;
    GptimerRegisters *regs = gptimer_counter_registers(dev,timer_id);
    memw();
    unsigned int configuration = regs->configuration;
    hal->dev = dev;
    memw(); regs->configuration = configuration & 0x7fffffffU;
    memw(); configuration = regs->configuration;
    memw(); regs->configuration = configuration & 0xdfffffffU;
    memw(); configuration = regs->configuration;
    memw(); regs->configuration = configuration & 0xfffffbffU;
}

/* Native entry: 0x42024848. */
/* Original function-byte SHA-256:
 * 9ab86012ca46fa1f4e8a433fd37affd7c62e5891187df6548f1ac381432ab460. */
/*
 * value:64-bit input; only54 counter bits are written. Saves reload HIGH,
 * then LOW after separate MEMWs. Rereads HIGH to preserve its upper10 bits,
 * writes new low22 HIGH bits and then LOW, and triggers LOAD with1. Restores
 * the original reload low54 bits with another fresh HIGH read/modify/write,
 * then LOW. All register accesses retain native MEMW order. No wait, lock,
 * argument validation or state change beyond these register operations.
 */
void timer_hal_set_counter_value(TimerHal *hal,unsigned long long value)
{
    unsigned int timer_id = hal->timer_id;
    GptimerGroupRegisters *dev = hal->dev;
    GptimerRegisters *regs = gptimer_counter_registers(dev,timer_id);
    memw(); unsigned int old_high = regs->reload_high;
    memw(); unsigned int old_low = regs->reload_low;
    memw(); unsigned int high_word = regs->reload_high;
    memw(); regs->reload_high = (high_word & 0xffc00000U) | ((unsigned int)(value >> 32) & 0x3fffffU);
    memw(); regs->reload_low = (unsigned int)value;
    memw(); regs->load = 1;
    memw(); high_word = regs->reload_high;
    memw(); regs->reload_high = (high_word & 0xffc00000U) | (old_high & 0x3fffffU);
    memw(); regs->reload_low = old_low;
}

/* Native entry: 0x42011a04. */
/* Original function-byte SHA-256:
 * 591fb0e268dabb8045db06ee51a7e18d2275c27075fe24374334a652f1030147. */
/*
 * group_id indexes the two-slot singleton without a bounds check. Under its
 * newlib mutex, reuses a group or calloc(1,20,0x804); allocation failure unlocks
 * and returnsNULL. A new group is published before initializing lock/group ID,
 * and its reference WORD is incremented with wrap before releasing the mutex.
 * Existing groups only increment/unlock. New groups acquire the peripheral RCC
 * reference using the firmware signal table. If prior count0, enables SYSTEM
 * clock bit13(group0) or15(any nonzero group), pulses its reset bit with fresh
 * reads, then clears watchdog_config0 bit14 in that timer group. Calls RCC
 * acquire-exit with its saved reference count and returns the group. Peripheral
 * reference protects shared timer/watchdog hardware; this does not reserve a
 * counter, install an interrupt or validate lifetime/ranges.
 */
GptimerGroup *gptimer_acquire_group_handle(unsigned int group_id)
{
    GptimerPlatform *platform = GPTIMER_PLATFORM;
    _lock_acquire(&platform->mutex);
    GptimerGroup *volatile *group_slot = gptimer_platform_group_slot(platform,group_id);
    GptimerGroup *group = *group_slot;
    if (group != 0) {
        volatile unsigned int *references = gptimer_platform_reference_slot(platform,group_id);
        *references = *references + 1U;
        _lock_release(&platform->mutex);
        return group;
    }
    group = heap_caps_calloc(1,20,0x804);
    if (group == 0) { _lock_release(&platform->mutex); return 0; }
    volatile unsigned int *reference_slot = gptimer_platform_reference_slot(platform,group_id);
    unsigned int references = *reference_slot;
    *group_slot = group;
    *(volatile unsigned int *)&group->lock.owner = 0xb33fffffU;
    *(volatile unsigned int *)&group->lock.count = 0;
    group->group_id = group_id;
    *reference_slot = references + 1U;
    _lock_release(&platform->mutex);
    int module = gptimer_signal_entry(group_id)->module;
    unsigned char reference_count = periph_rcc_acquire_enter(module);
    if (reference_count == 0) {
        unsigned int mask = group_id == 0 ? 0x2000U : 0x8000U;
        GptimerGroupRegisters *dev = group_id == 0 ? GPTIMER_GROUP0 : GPTIMER_GROUP1;
        memw(); unsigned int word = GPTIMER_SYSTEM->peripheral_clock_enable0;
        memw(); GPTIMER_SYSTEM->peripheral_clock_enable0 = word | mask;
        memw(); word = GPTIMER_SYSTEM->peripheral_reset_enable0;
        memw(); GPTIMER_SYSTEM->peripheral_reset_enable0 = word | mask;
        memw(); word = GPTIMER_SYSTEM->peripheral_reset_enable0;
        memw(); GPTIMER_SYSTEM->peripheral_reset_enable0 = word & ~mask;
        memw(); word = dev->watchdog_config0;
        memw(); dev->watchdog_config0 = word & 0xffffbfffU;
    }
    periph_rcc_acquire_exit(module,reference_count);
    return group;
}

/* Native entry: 0x42011b00. */
/* Original function-byte SHA-256:
 * cf3246d8e346aa7d145f387c82a4037cd286cf5cdcbc87ec79c3efda1217dfc6. */
/*
 * Requires a valid group; uses its group ID to index the singleton unchecked.
 * Under newlib mutex decrements the WORD reference count with wrap. Nonzero
 * result just unlocks/returns. At zero asserts the pool slot is nonnull with
 * four null/zero assertion arguments, clears that slot and unlocks. Acquires
 * the peripheral release reference; only resulting count0 clears SYSTEM clock
 * bit13(group0) or15(other) using MEMW read/write. Always calls release-exit,
 * then frees the supplied group. No timer-slot check, reset or argument/lifetime
 * validation; a zero starting count wraps and does not free anything.
 */
void gptimer_release_group_handle(GptimerGroup *group)
{
    unsigned int group_id = group->group_id;
    GptimerPlatform *platform = GPTIMER_PLATFORM;
    _lock_acquire(&platform->mutex);
    volatile unsigned int *reference_slot = gptimer_platform_reference_slot(platform,group_id);
    unsigned int references = *reference_slot - 1U;
    *reference_slot = references;
    if (references != 0) { _lock_release(&platform->mutex); return; }
    GptimerGroup *volatile *group_slot = gptimer_platform_group_slot(platform,group_id);
    if (*group_slot == 0) __assert_func(0,0,0,0);
    *group_slot = 0;
    _lock_release(&platform->mutex);
    int module = gptimer_signal_entry(group_id)->module;
    unsigned char reference_count = periph_rcc_release_enter(module);
    if (reference_count == 0) {
        memw(); unsigned int word = GPTIMER_SYSTEM->peripheral_clock_enable0;
        unsigned int mask = group_id == 0 ? 0x2000U : 0x8000U;
        memw(); GPTIMER_SYSTEM->peripheral_clock_enable0 = word & ~mask;
    }
    periph_rcc_release_exit(module,reference_count);
    free(group);
}

/* Native entry: 0x42022a7c. */
/* Original function-byte SHA-256:
 * 93e99126a541403ee96ebe6220fd18fc58d59a5297c5b3dc11f10b55e5ab92c9. */
/*
 * Internal cleanup requires a nonnull handle. Deletes a nonnull PM lock first;
 * this build's stub returns0x106, so that case logs line112 and stops. Otherwise
 * frees a nonnull interrupt; failure logs line115 and stops. Then snapshots
 * group/index, clears its timer slot under the group mux, releases the group
 * reference, and frees the timer. Returns0 or the first error; no FSM check,
 * counter stop, HAL deinit, clock-source disable, rollback or null guard.
 */
int gptimer_destroy(Gptimer *timer)
{
    int status;
    const char *error_format;
    unsigned int error_line;
    void *pm_lock = timer->pm_lock;
    if (pm_lock != 0 && (status = esp_pm_lock_delete(pm_lock)) != 0) {
        error_format = "E (%lu) %s: %s(%d): delete pm_lock failed\n";
        error_line = 112;
        goto error;
    }
    InterruptHandle *intr = timer->intr;
    if (intr != 0 && (status = esp_intr_free(intr)) != 0) {
        error_format = "E (%lu) %s: %s(%d): delete interrupt service failed\n";
        error_line = 115;
        goto error;
    }
    GptimerGroup *group = timer->group;
    if (group != 0) {
        unsigned int index = timer->timer_id;
        (void)xPortEnterCriticalTimeout(&group->lock,-1);
        *gptimer_group_timer_slot(group,index) = 0;
        vPortExitCritical(&group->lock);
        gptimer_release_group_handle(group);
    }
    free(timer);
    return 0;
error:
    ;
    unsigned int timestamp = esp_log_timestamp();
    esp_log_write(1,"gptimer",error_format,timestamp,"gptimer","gptimer_destroy",error_line);
    return status;
}

/* Native entry: 0x42022fb8. */
/* Original function-byte SHA-256:
 * e749b5f58ffdec757d6dd3a9f2fd0df8855ada1d5fd5f18c3432efd94df4a932. */
/*
 * Null handle returns0x102 without logging. MEMW/MEMW/reads FSM/MEMW; if3
 * already running returns0 without acquiring a lock. Otherwise strong compare-
 * exchange1->4 with fourth/fifth caller WORDs5 must succeed, else0x103. Under timer mux,
 * reloads index/base and flags WORD, programs alarm bit10 from flag bit2,
 * then separately sets counter-enable bit31, retaining each MEMW read/write.
 * Publishes FSM3 with MEMW/MEMW/store/MEMW before context query/unlock. All
 * context/lock results are ignored. No counter reload, interrupt clear, PM or
 * resolution check; a near alarm may fire as soon as hardware is enabled.
 */
int gptimer_start(Gptimer *timer)
{
    if (timer == 0) return 0x102;
    memw(); memw(); unsigned int fsm = timer->fsm; memw();
    if (fsm == 3) return 0;
    unsigned int expected = 1;
    if (gptimer_compare_exchange(&timer->fsm,&expected,4,5,5) == 0) return 0x103;
    (void)xPortInIsrContext();
    PortMuxWords *lock = &timer->lock;
    (void)xPortEnterCriticalTimeout(lock,-1);
    unsigned int index = timer->timer_id;
    GptimerGroupRegisters *dev = timer->hal.dev;
    unsigned int flags = timer->flags.word;
    GptimerRegisters *regs = gptimer_counter_registers(dev,index);
    memw(); unsigned int word = regs->configuration;
    memw(); regs->configuration = (word & 0xfffffbffU) | (((flags >> 2) & 1U) << 10);
    memw(); word = regs->configuration;
    memw(); regs->configuration = word | 0x80000000U;
    memw(); memw(); timer->fsm = 3; memw();
    (void)xPortInIsrContext();
    vPortExitCritical(lock);
    return 0;
}

/* Native entry: 0x4037f11c. */
/* Original function-byte SHA-256:
 * 47f4a5a620aba814440cfaf6a1ad1852ea9a3dc52d642e04d909ce5361a9ecef. */
/* This build's PM-lock acquisition stub ignores its handle and returns
 * ESP_ERR_NOT_SUPPORTED(0x106). No lock, reference or power state is changed. */
int esp_pm_lock_acquire(void *handle)
{
    (void)handle;
    return 0x106;
}

/* Native entry: 0x42021328. */
/* Original function-byte SHA-256:
 * 47f4a5a620aba814440cfaf6a1ad1852ea9a3dc52d642e04d909ce5361a9ecef. */
/* This build's PM-lock deletion stub ignores its handle and returns
 * ESP_ERR_NOT_SUPPORTED(0x106). It does not release or free a handle. */
int esp_pm_lock_delete(void *handle)
{
    (void)handle;
    return 0x106;
}
