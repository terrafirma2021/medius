/* Medius v3.4.7 host: recovered ESP32-S3 LED PWM driver. */

#include "../include/types.h"

/* reconstruction utilities: unchecked native modulo-32 address arithmetic.
 * Volatile context fields retain separate live loads, not atomicity. */
static __inline__ __attribute__((always_inline)) LedcChannelRegisters *
ledc_driver_channel(const LedcHal *hal,unsigned int channel_id)
{
    unsigned int mode = (unsigned int)hal->speed_mode;
    unsigned int base = (unsigned int)(uintptr_t)hal->device;
    return (LedcChannelRegisters *)(uintptr_t)
        (base + mode * 0xa0U + channel_id * 0x14U);
}
static __inline__ __attribute__((always_inline)) LedcTimerRegisters *
ledc_driver_timer(const LedcHal *hal,unsigned int timer_id)
{
    unsigned int mode = (unsigned int)hal->speed_mode;
    unsigned int base = (unsigned int)(uintptr_t)hal->device;
    return (LedcTimerRegisters *)(uintptr_t)
        (base + (mode * 4U + timer_id) * 8U + 0xa0U);
}
static __inline__ __attribute__((always_inline)) LedcDriverContext *volatile *
ledc_driver_object_slot(unsigned int mode)
{
    return (LedcDriverContext *volatile *)(uintptr_t)
        ((unsigned int)(uintptr_t)LEDC_CONTEXT_SLOT + mode * 4U);
}
static __inline__ __attribute__((always_inline)) LedcFadePrefix *volatile *
ledc_driver_fade_slot(unsigned int mode,unsigned int channel_id)
{
    return (LedcFadePrefix *volatile *)(uintptr_t)
        ((unsigned int)(uintptr_t)LEDC_FADE_SLOTS + (mode * 8U + channel_id) * 4U);
}
static __inline__ __attribute__((always_inline)) volatile unsigned char *
ledc_driver_byte(LedcDriverContext *object,unsigned int offset,unsigned int index)
{
    return (volatile unsigned char *)(uintptr_t)
        ((unsigned int)(uintptr_t)object + offset + index);
}

/* Native entry: 0x420155f0. */
/*
 * Medius v3.4.7 host application; 0x420155f0.
 * Instruction-checked recovered C.
 * Original function-byte SHA-256:
 * adcdbb7b4f3df95d9ec060af49e3cdd15bb087c4dd4ee0f0729ebe5684613b96.
 */

/* Store the unchecked speed mode BEFORE publishing the fixed LEDC register
 * pointer (0x60019000). No MMIO, clock/reset setup or memory-power operation is
 * present in this S3 body; the context pointer must be writable. */
void ledc_hal_init(LedcHal *hal,int speed_mode)
{
    hal->speed_mode = speed_mode;
    hal->device = (LedcDeviceRegistersPrefix *)0x60019000U;
}

/* Native entry: 0x4201403c. */
/*
 * Medius v3.4.7 host application; 0x4201403c.
 * Instruction-checked recovered C.
 * Original function-byte SHA-256:
 * 4ec37d2f7fd096d4af35ea923c4266d545e273ad4b88a43b0195fb837d92eaf8.
 */

/* Under the singleton allocation mutex, allocate a zeroed 40-byte internal
 * context only if absent. Enable SYSTEM clock bit 11 and clear reset bit 11
 * through separate fresh RMWs inside the RCC lock; initialize mode 0, global
 * clock -1 and sleep strategy 3, then publish the object. Return 1 only for a
 * new allocation; an existing context and allocation failure both return 0.
 * The allocation mutex is always released. No deallocation or reset pulse. */
unsigned int ledc_speed_mode_ctx_create(void)
{
    unsigned int created = 0;
    _lock_acquire(LEDC_ALLOCATION_MUTEX);
    if (*LEDC_CONTEXT_SLOT == NULL) {
        LedcDriverContext *object = heap_caps_calloc(1,sizeof(LedcDriverContext),0x804U);
        if (object != NULL) {
            periph_rcc_enter();
            memw();
            unsigned int clock = LEDC_SYSTEM_CLOCK_ENABLE_REGISTER;
            memw();
            LEDC_SYSTEM_CLOCK_ENABLE_REGISTER = clock | 0x800U;
            memw();
            unsigned int reset = LEDC_SYSTEM_RESET_REGISTER;
            memw();
            LEDC_SYSTEM_RESET_REGISTER = reset & ~0x800U;
            periph_rcc_exit();
            ledc_hal_init(&object->hal,0);
            object->global_clock = -1;
            object->sleep_mode = 3;
            *LEDC_CONTEXT_SLOT = object;
            created = 1;
        }
    }
    _lock_release(LEDC_ALLOCATION_MUTEX);
    return created;
}

/* Native entry: 0x420140b8. */
/*
 * Medius v3.4.7 host application; 0x420140b8.
 * Instruction-checked recovered C.
 * Original function-byte SHA-256:
 * c982aaa521b17045fef1145d65a7e214c7c623bf95496735f070562a0ca4b479.
 */

/* If a fade record exists, take its hardware semaphore with UINT32_MAX
 * timeout, then clear the selected fade-end interrupt-enable bit under the
 * driver spinlock. Ignore semaphore/critical-entry results; neither start nor
 * stop a fade here, and leave the semaphore taken for the caller to release.
 * Mode/channel and the context are unchecked. Native SSL/SRC rotates ~1 by
 * (channel+4)&31; retain that wrapping mask even for invalid channel values. */
void ledc_fade_hw_acquire(unsigned int speed_mode,unsigned int channel_id)
{
    LedcFadePrefix *fade = *ledc_driver_fade_slot(speed_mode,channel_id);
    if (fade == NULL)
        return;
    xQueueSemaphoreTake(fade->hardware_semaphore,0xffffffffU);
    xPortEnterCriticalTimeout(LEDC_SPINLOCK,-1);
    LedcDriverContext *object = *ledc_driver_object_slot(speed_mode);
    LedcDeviceRegistersPrefix *device = object->hal.device;
    memw();
    unsigned int interrupts = device->interrupt_enable;
    unsigned int mask = ~(1U << ((channel_id + 4U) & 31U));
    memw();
    device->interrupt_enable = interrupts & mask;
    vPortExitCritical(LEDC_SPINLOCK);
}

/* Native entry: 0x42014110. */
/*
 * Medius v3.4.7 host application; 0x42014110.
 * Instruction-checked recovered C.
 * Original function-byte SHA-256:
 * 59ec7895bd1a0a379daeed5f080ccc0530de3c8fe69835b3c1949657fa37096a.
 */

/* Increment the selected timer's 8-bit sleep-power reference count with
 * wrapping. If its global clock is acquired/configured and not already kept
 * powered, request digital RC_FAST (clock 9, sleep submode 1) or digital XTAL
 * (clock 11, submode 5). Ignore that request's result, reload the global object
 * slot and set its powered flag. Unsupported clocks restore the old count
 * and return the original nonzero acquired byte; other paths return 0.
 * Caller supplies locking and a valid timer; this body does not check either. */
unsigned char ledc_timer_clk_src_set_xpd_in_sleep(unsigned int timer_id)
{
    LedcDriverContext *object = *LEDC_CONTEXT_SLOT;
    volatile unsigned char *references = ledc_driver_byte(object,0x20U,timer_id);
    unsigned char old_count = *references;
    unsigned char acquired = *ledc_driver_byte(object,0x10U,timer_id);
    *references = (unsigned char)(old_count + 1U);
    if (acquired != 0) {
        int clock = object->global_clock;
        if (clock != -1 && object->global_clock_powered == 0) {
            if (clock == 9)
                esp_sleep_sub_mode_config(1,1);
            else if (clock == 11)
                esp_sleep_sub_mode_config(5,1);
            else {
                *references = old_count;
                return acquired;
            }
            (*LEDC_CONTEXT_SLOT)->global_clock_powered = 1;
        }
    }
    return 0;
}

/* Native entry: 0x4201416c. */
/*
 * Medius v3.4.7 host application; 0x4201416c.
 * Instruction-checked recovered C.
 * Original function-byte SHA-256:
 * b9a755cc022dbeac72f42be6f7890400b2b48cea677a7b4403f37ab5c2b58c76.
 */

/* Program the 18-bit divider, then 4-bit resolution, then update bit 25
 * through THREE fresh RMW pairs under the spinlock. Inputs truncate, without
 * divider/frequency/resolution validation. This native S3 body consumes four
 * arguments; no timer-specific clock-source argument is read.
 * Require mode 0, timer<4 and an initialized object. Return 0 on success,
 * 0x102 for invalid arguments or 0x103 when uninitialized, with native logs.
 * Critical-entry result is ignored. No completion wait or rollback. */
int ledc_timer_set(int speed_mode,unsigned int timer_id,unsigned int divider,unsigned int resolution)
{
    const char *error_format;
    unsigned int error_line;
    if (speed_mode != 0) {
        error_format = "E (%lu) %s: %s(%d): speed_mode argument is invalid\n";
        error_line = 0xfd;
        goto invalid;
    }
    if (timer_id >= 4) {
        error_format = "E (%lu) %s: %s(%d): timer_select argument is invalid\n";
        error_line = 0xfe;
        goto invalid;
    }
    if (*LEDC_CONTEXT_SLOT == NULL) {
        unsigned int stamp = esp_log_timestamp();
        esp_log_write(1,"ledc","E (%lu) %s: %s(%d): %s\n",stamp,"ledc","ledc_timer_set",0xff,"LEDC is not initialized");
        return 0x103;
    }
    xPortEnterCriticalTimeout(LEDC_SPINLOCK,-1);
    LedcDriverContext *object = *LEDC_CONTEXT_SLOT;
    LedcTimerRegisters *timer = ledc_driver_timer(&object->hal,timer_id);
    memw();
    unsigned int configuration = timer->configuration;
    memw();
    timer->configuration = (configuration & ~0x3ffff0U) | ((divider & 0x3ffffU) << 4);
    memw();
    configuration = timer->configuration;
    memw();
    timer->configuration = (configuration & ~0xfU) | (resolution & 0xfU);
    memw();
    configuration = timer->configuration;
    memw();
    timer->configuration = configuration | 0x02000000U;
    vPortExitCritical(LEDC_SPINLOCK);
    return 0;
invalid:
    {
        unsigned int stamp = esp_log_timestamp();
        esp_log_write(1,"ledc",error_format,stamp,"ledc","ledc_timer_set",error_line);
    }
    return 0x102;
}

/* Native entry: 0x42014564. */
/*
 * Medius v3.4.7 host application; 0x42014564.
 * Instruction-checked recovered C.
 * Original function-byte SHA-256:
 * f3ceabd9926398e75eb01b073823499c3825bb4b36e1f3cd926873cf53059b01.
 */

/* Validate mode==0, timer<4 and an initialized object; the channel is NOT
 * checked. Read its old timer outside the spinlock. Inside, replace CONF0
 * bits 0..1 and request a channel update, then reload the object. If a channel
 * kept alive in sleep moved timers, decrement the old timer's byte reference
 * only if nonzero and acquire the new timer's sleep-power requirement.
 * An unsupported keep-alive clock warns AFTER unlocking but still returns 0.
 * Invalid arguments return 0x102; no object returns 0x103. */
int ledc_bind_channel_timer(int speed_mode,int channel_id,unsigned int timer_id)
{
    const char *error_format;
    unsigned int error_line;
    if (speed_mode != 0) {
        error_format = "E (%lu) %s: %s(%d): speed_mode argument is invalid\n";
        error_line = 0x151;
        goto invalid;
    }
    if (timer_id >= 4) {
        error_format = "E (%lu) %s: %s(%d): timer_select argument is invalid\n";
        error_line = 0x152;
        goto invalid;
    }
    LedcDriverContext *object = *LEDC_CONTEXT_SLOT;
    if (object == NULL) {
        unsigned int stamp = esp_log_timestamp();
        esp_log_write(1,"ledc","E (%lu) %s: %s(%d): %s\n",stamp,"ledc",
            "ledc_bind_channel_timer",0x153,"LEDC is not initialized");
        return 0x103;
    }
    LedcChannelRegisters *channel = ledc_driver_channel(&object->hal,(unsigned int)channel_id);
    memw();
    unsigned int old_configuration = channel->configuration0;
    xPortEnterCriticalTimeout(LEDC_SPINLOCK,-1);
    object = *LEDC_CONTEXT_SLOT;
    channel = ledc_driver_channel(&object->hal,(unsigned int)channel_id);
    memw();
    unsigned int configuration = channel->configuration0;
    memw();
    channel->configuration0 = (configuration & ~3U) | (timer_id & 3U);
    ledc_hal_ls_channel_update(&object->hal,channel_id);
    object = *LEDC_CONTEXT_SLOT;
    unsigned int old_timer = old_configuration & 3U;
    unsigned char power_error = 0;
    if (*ledc_driver_byte(object,0x18U,(unsigned int)channel_id) != 0 && old_timer != timer_id) {
        unsigned char references = object->timer_power_references[old_timer];
        if (references != 0)
            object->timer_power_references[old_timer] = (unsigned char)(references - 1U);
        power_error = ledc_timer_clk_src_set_xpd_in_sleep(timer_id);
    }
    vPortExitCritical(LEDC_SPINLOCK);
    if (power_error != 0) {
        unsigned int stamp = esp_log_timestamp();
        esp_log_write(2,"ledc","W (%lu) %s: the binded timer can't keep alive in sleep\n",stamp,"ledc");
    }
    return 0;
invalid:
    {
        unsigned int stamp = esp_log_timestamp();
        esp_log_write(1,"ledc",error_format,stamp,"ledc","ledc_bind_channel_timer",error_line);
    }
    return 0x102;
}

/* Native entry: 0x42014690. */
/*
 * Medius v3.4.7 host application; 0x42014690.
 * Instruction-checked recovered C.
 * Original function-byte SHA-256:
 * 8d7c4090e4b9cf38f64bcc0eed82f511cb1c94b119747cb6a781990921d0bc67.
 */

/* Pulse timer reset bit 23 with a SET and a separate fresh CLEAR
 * under the spinlock. Preserve unrelated bits on both accesses; no pause,
 * duty update or software stopped-flag change.
 * Require mode 0, timer<4 and an initialized object. Return 0 on success,
 * 0x102 for invalid arguments or 0x103 when uninitialized, with native logs.
 * Critical-entry result is ignored. No completion wait or rollback. */
int ledc_timer_rst(int speed_mode,unsigned int timer_id)
{
    const char *error_format;
    unsigned int error_line;
    if (speed_mode != 0) {
        error_format = "E (%lu) %s: %s(%d): speed_mode argument is invalid\n";
        error_line = 0x16d;
        goto invalid;
    }
    if (timer_id >= 4) {
        error_format = "E (%lu) %s: %s(%d): timer_select argument is invalid\n";
        error_line = 0x16e;
        goto invalid;
    }
    if (*LEDC_CONTEXT_SLOT == NULL) {
        unsigned int stamp = esp_log_timestamp();
        esp_log_write(1,"ledc","E (%lu) %s: %s(%d): %s\n",stamp,"ledc","ledc_timer_rst",0x16f,"LEDC is not initialized");
        return 0x103;
    }
    xPortEnterCriticalTimeout(LEDC_SPINLOCK,-1);
    LedcDriverContext *object = *LEDC_CONTEXT_SLOT;
    LedcTimerRegisters *timer = ledc_driver_timer(&object->hal,timer_id);
    memw();
    unsigned int configuration = timer->configuration;
    memw();
    timer->configuration = configuration | 0x00800000U;
    memw();
    configuration = timer->configuration;
    memw();
    timer->configuration = configuration & ~0x00800000U;
    vPortExitCritical(LEDC_SPINLOCK);
    return 0;
invalid:
    {
        unsigned int stamp = esp_log_timestamp();
        esp_log_write(1,"ledc",error_format,stamp,"ledc","ledc_timer_rst",error_line);
    }
    return 0x102;
}

/* Native entry: 0x42014754. */
/*
 * Medius v3.4.7 host application; 0x42014754.
 * Instruction-checked recovered C.
 * Original function-byte SHA-256:
 * 3d72c4e772ce80cfd8679553a067f3af45a5ceaaa63ef34d7aba2a401ea0c209.
 */

/* Clear the selected software stopped BYTE before clearing timer pause
 * bit 22 through a fresh RMW under the spinlock. No timer reset or update latch.
 * Require mode 0, timer<4 and an initialized object. Return 0 on success,
 * 0x102 for invalid arguments or 0x103 when uninitialized, with native logs.
 * Critical-entry result is ignored. No completion wait or rollback. */
int ledc_timer_resume(int speed_mode,unsigned int timer_id)
{
    const char *error_format;
    unsigned int error_line;
    if (speed_mode != 0) {
        error_format = "E (%lu) %s: %s(%d): speed_mode argument is invalid\n";
        error_line = 0x184;
        goto invalid;
    }
    if (timer_id >= 4) {
        error_format = "E (%lu) %s: %s(%d): timer_select argument is invalid\n";
        error_line = 0x185;
        goto invalid;
    }
    if (*LEDC_CONTEXT_SLOT == NULL) {
        unsigned int stamp = esp_log_timestamp();
        esp_log_write(1,"ledc","E (%lu) %s: %s(%d): %s\n",stamp,"ledc","ledc_timer_resume",0x186,"LEDC is not initialized");
        return 0x103;
    }
    xPortEnterCriticalTimeout(LEDC_SPINLOCK,-1);
    LedcDriverContext *object = *LEDC_CONTEXT_SLOT;
    LedcTimerRegisters *timer = ledc_driver_timer(&object->hal,timer_id);
    object->timer_stopped[timer_id] = 0;
    memw();
    unsigned int configuration = timer->configuration;
    memw();
    timer->configuration = configuration & ~0x00400000U;
    vPortExitCritical(LEDC_SPINLOCK);
    return 0;
invalid:
    {
        unsigned int stamp = esp_log_timestamp();
        esp_log_write(1,"ledc",error_format,stamp,"ledc","ledc_timer_resume",error_line);
    }
    return 0x102;
}

/* Native entry: 0x42014a38. */
/*
 * Medius v3.4.7 host application; 0x42014a38.
 * Instruction-checked recovered C.
 * Original function-byte SHA-256:
 * 9efe360575605dbc72e9060b14e3039f4801ac5146ba17e1a77115145cc14cfe.
 */

/* Validate mode 0/channel<8/object. Under the driver spinlock, enable
 * channel output (CONF0 bit 2), request duty start, then reload the object and
 * request the channel update latch. Retain ISR-context queries before critical
 * entry and before exit; their return values are unused in this build.
 * Errors use early ets_printf only when the global early-log level is nonzero.
 * Return 0, invalid-argument 0x102 or not-initialized 0x103; no completion wait. */
int ledc_update_duty(int speed_mode,unsigned int channel_id)
{
    if (speed_mode != 0)
        goto invalid_mode;
    if (channel_id >= 8)
        goto invalid_channel;
    if (*LEDC_CONTEXT_SLOT == NULL) {
        if (SYSTEM_EARLY_LOG_LEVEL != 0) {
            unsigned int stamp = esp_log_timestamp();
            ets_printf("E (%lu) %s: %s(%d): %s\n",stamp,"ledc","ledc_update_duty",0x3dc,"LEDC is not initialized");
        }
        return 0x103;
    }
    xPortInIsrContext();
    xPortEnterCriticalTimeout(LEDC_SPINLOCK,-1);
    LedcDriverContext *object = *LEDC_CONTEXT_SLOT;
    LedcChannelRegisters *channel = ledc_driver_channel(&object->hal,channel_id);
    memw();
    unsigned int configuration = channel->configuration0;
    memw();
    channel->configuration0 = configuration | 4U;
    ledc_hal_set_duty_start(&object->hal,(int)channel_id);
    ledc_hal_ls_channel_update(&(*LEDC_CONTEXT_SLOT)->hal,(int)channel_id);
    xPortInIsrContext();
    vPortExitCritical(LEDC_SPINLOCK);
    return 0;
invalid_channel:
    if (SYSTEM_EARLY_LOG_LEVEL != 0) {
        unsigned int stamp = esp_log_timestamp();
        ets_printf("E (%lu) %s: %s(%d): channel argument is invalid\n",stamp,"ledc","ledc_update_duty",0x3db);
    }
    return 0x102;
invalid_mode:
    if (SYSTEM_EARLY_LOG_LEVEL != 0) {
        unsigned int stamp = esp_log_timestamp();
        ets_printf("E (%lu) %s: %s(%d): speed_mode argument is invalid\n",stamp,"ledc","ledc_update_duty",0x3da);
    }
    return 0x102;
}

/* Native entry: 0x42014b1c. */
/*
 * Medius v3.4.7 host application; 0x42014b1c.
 * Instruction-checked recovered C.
 * Original function-byte SHA-256:
 * b26b10fbfaf9d1addec48cd733d80be81a74b958a1866aeed2964d1676decdeb.
 */

/* Configure pending duty for mode 0/channel<8. Require hpoint<0x4000 and write its 14-bit field first.
 * Wait for an existing fade semaphore, then enter the driver spinlock. Duty
 * bit 31 set skips the duty write; other values use the HAL integer-duty
 * truncation. Always configure fade (range 0,direction 1,cycle 1,scale 0,step 1).
 * Unlock, reload the fade slot and give its hardware semaphore with zero wait.
 * Ignore queue/critical return values. No output start or channel latch here.
 * Return 0, argument error 0x102 or missing-object 0x103 with native logs. */
int ledc_set_duty_with_hpoint(int speed_mode,unsigned int channel_id,unsigned int duty,unsigned int hpoint)
{
    const char *error_format;
    unsigned int error_line;
    if (speed_mode != 0) {
        error_format = "E (%lu) %s: %s(%d): speed_mode argument is invalid\n";
        error_line = 0x40c;
        goto invalid;
    }
    if (channel_id >= 8) {
        error_format = "E (%lu) %s: %s(%d): channel argument is invalid\n";
        error_line = 0x40d;
        goto invalid;
    }
    if (hpoint >= 0x4000U) {
        error_format = "E (%lu) %s: %s(%d): hpoint argument is invalid\n";
        error_line = 0x40e;
        goto invalid;
    }
    if (*LEDC_CONTEXT_SLOT == NULL) {
        unsigned int stamp = esp_log_timestamp();
        esp_log_write(1,"ledc","E (%lu) %s: %s(%d): %s\n",stamp,"ledc","ledc_set_duty_with_hpoint",0x40f,"LEDC is not initialized");
        return 0x103;
    }
    ledc_fade_hw_acquire(0,channel_id);
    xPortEnterCriticalTimeout(LEDC_SPINLOCK,-1);
    ledc_hal_set_hpoint(&(*LEDC_CONTEXT_SLOT)->hal,(int)channel_id,hpoint);
    if ((duty & 0x80000000U) == 0)
        ledc_hal_set_duty_int_part(&(*LEDC_CONTEXT_SLOT)->hal,(int)channel_id,duty);
    ledc_hal_set_fade_param(&(*LEDC_CONTEXT_SLOT)->hal,(int)channel_id,0,1,1,0,1);
    vPortExitCritical(LEDC_SPINLOCK);
    LedcFadePrefix *fade = *ledc_driver_fade_slot(0,channel_id);
    if (fade != NULL)
        xQueueGenericSend(fade->hardware_semaphore,NULL,0,0);
    return 0;
invalid:
    {
        unsigned int stamp = esp_log_timestamp();
        esp_log_write(1,"ledc",error_format,stamp,"ledc","ledc_set_duty_with_hpoint",error_line);
    }
    return 0x102;
}

/* Native entry: 0x42014e98. */
/*
 * Medius v3.4.7 host application; 0x42014e98.
 * Instruction-checked recovered C.
 * Original function-byte SHA-256:
 * 8073f4c9ce009e1b0c716b8c95026cd1de582ba3b81feab3f93cbcc6384773fc.
 */

/* Configure pending duty for mode 0/channel<8. Preserve HPOINT.
 * Wait for an existing fade semaphore, then enter the driver spinlock. Duty
 * bit 31 set skips the duty write; other values use the HAL integer-duty
 * truncation. Always configure fade (range 0,direction 1,cycle 1,scale 0,step 1).
 * Unlock, reload the fade slot and give its hardware semaphore with zero wait.
 * Ignore queue/critical return values. No output start or channel latch here.
 * Return 0, argument error 0x102 or missing-object 0x103 with native logs. */
int ledc_set_duty(int speed_mode,unsigned int channel_id,unsigned int duty)
{
    const char *error_format;
    unsigned int error_line;
    if (speed_mode != 0) {
        error_format = "E (%lu) %s: %s(%d): speed_mode argument is invalid\n";
        error_line = 0x423;
        goto invalid;
    }
    if (channel_id >= 8) {
        error_format = "E (%lu) %s: %s(%d): channel argument is invalid\n";
        error_line = 0x424;
        goto invalid;
    }
    if (*LEDC_CONTEXT_SLOT == NULL) {
        unsigned int stamp = esp_log_timestamp();
        esp_log_write(1,"ledc","E (%lu) %s: %s(%d): %s\n",stamp,"ledc","ledc_set_duty",0x425,"LEDC is not initialized");
        return 0x103;
    }
    ledc_fade_hw_acquire(0,channel_id);
    xPortEnterCriticalTimeout(LEDC_SPINLOCK,-1);
    if ((duty & 0x80000000U) == 0)
        ledc_hal_set_duty_int_part(&(*LEDC_CONTEXT_SLOT)->hal,(int)channel_id,duty);
    ledc_hal_set_fade_param(&(*LEDC_CONTEXT_SLOT)->hal,(int)channel_id,0,1,1,0,1);
    vPortExitCritical(LEDC_SPINLOCK);
    LedcFadePrefix *fade = *ledc_driver_fade_slot(0,channel_id);
    if (fade != NULL)
        xQueueGenericSend(fade->hardware_semaphore,NULL,0,0);
    return 0;
invalid:
    {
        unsigned int stamp = esp_log_timestamp();
        esp_log_write(1,"ledc",error_format,stamp,"ledc","ledc_set_duty",error_line);
    }
    return 0x102;
}

/* Native entry: 0x420149b8. */
/*
 * Medius v3.4.7 host application; 0x420149b8.
 * Instruction-checked recovered C.
 * Original function-byte SHA-256:
 * 61f8b41042c9dd64ede8654ab18dd585880ad42d17c7f25ab8e44f8c1575b87f.
 */

/* Select GPIO function 1, reserve the native 64-bit mask and warn if that
 * bit was already reserved; a conflict does not prevent routing or change the
 * zero result. Then route signal_base[speed_mode]+channel with the LOW BYTE
 * of output_inverted and output-enable inversion 0. All indices unchecked.
 * Mask selection uses pin bit 5 and pin&31, reproducing native aliasing for
 * values >=64 rather than using an undefined 64-bit shift. */
int ledc_set_pin_internal(unsigned int pin,unsigned int output_inverted,int speed_mode,int channel_id)
{
    gpio_func_sel(pin,1);
    unsigned int bit = 1U << (pin & 31U);
    unsigned long long mask = (pin & 32U) != 0 ? (unsigned long long)bit << 32 : bit;
    unsigned long long previous = esp_gpio_reserve(mask);
    unsigned int selected_word = (pin & 32U) != 0 ? (unsigned int)(previous >> 32) : (unsigned int)previous;
    if (((selected_word >> (pin & 31U)) & 1U) != 0) {
        unsigned int stamp = esp_log_timestamp();
        esp_log_write(2,"ledc","W (%lu) %s: GPIO %d is not usable, maybe conflict with others\n",stamp,"ledc",pin);
    }
    unsigned int signal = LEDC_SIGNAL_BASES[speed_mode] + (unsigned int)channel_id;
    gpio_matrix_out(pin,signal,(unsigned char)output_inverted,0);
    return 0;
}
