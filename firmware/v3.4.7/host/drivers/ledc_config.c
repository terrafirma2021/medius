/* Medius v3.4.7 host: recovered LED PWM clock and configuration paths. */

#include "../include/types.h"

/* reconstruction utilities: wrap native unchecked timer-byte addressing and
 * retain the explicit ROM division call, including a zero denominator. */
static __inline__ __attribute__((always_inline)) volatile unsigned char *
ledc_config_byte(LedcDriverContext *object,unsigned int offset,unsigned int timer_id)
{
    return (volatile unsigned char *)(uintptr_t)
        ((unsigned int)(uintptr_t)object + offset + timer_id);
}
static __inline__ __attribute__((always_inline)) unsigned int
ledc_config_divider(unsigned int source_hz,unsigned int denominator)
{
    unsigned long long numerator = ((unsigned long long)source_hz << 8) + (denominator >> 1);
    return (unsigned int)rom_unsigned_divide_u64(numerator,denominator);
}

/* Native entry: 0x42014008. */
/*
 * Medius v3.4.7 — host application; 0x42014008.
 * Instruction-checked recovered C.
 * Original function-byte SHA-256:
 * 92f59e6d603b6c7d46e40269b0bc7e18c1ba8344fc1909a9c1ecc3d9db8134fd.
 */

/* Enable/calibrate the peripheral RC_FAST source. On success, copy the
 * peripheral frequency into the LEDC cache; on failure, log and leave that
 * cache unchanged. Return the enable routine's result, not the frequency.
 * No matching disable, cache-validity check or LEDC lock is supplied here. */
int ledc_slow_clk_calibrate(void)
{
    int enabled = periph_rtc_dig_clk8m_enable();
    if (enabled != 0)
        LEDC_RC_FAST_HZ = periph_rtc_dig_clk8m_get_freq();
    else {
        unsigned int stamp = esp_log_timestamp();
        esp_log_write(1,"ledc","E (%lu) %s: Calibrate RC_FAST_CLK failed\n",stamp,"ledc");
    }
    return enabled;
}

/* Native entry: 0x42014254. */
/*
 * Medius v3.4.7 — host application; 0x42014254.
 * Instruction-checked recovered C.
 * Original function-byte SHA-256:
 * 41737e0358ded91afb7253f1802e552bd5968dc9bce92608da4b73fe02129832.
 */

/* Select a global clock and program a timer divider. This native body has
 * four consumed arguments: timer, clock choice, frequency and resolution;
 * speed mode is fixed to 0. AUTO tries APB(4), XTAL(11), RC_FAST(9), in that
 * order. Calibrate uncached RC_FAST before using it. AUTO reuses one frequency
 * output word across ignored query errors; explicit other clocks start at 0.
 * Denominator is frequency << (resolution&31), wrapping at 32 bits. Divide
 * ((uint64)source_hz<<8)+(denominator>>1) through the native ROM routine and
 * test only the LOW 32 bits for 0x100..0x3ffff inclusive. No zero-divisor guard.
 *
 * Under the spinlock, reject a global-clock change while another timer has
 * acquired it. Mark this timer acquired, update cached clock BEFORE enabling
 * the source, reload the context and set the hardware mux (APB=1,RC_FAST=2,
 * XTAL=3,other=0). Prior clock is not released. Honor pending sleep-power
 * references for RC_FAST/XTAL; other clocks clear this timer's reference byte,
 * then warn after programming. Divider programming has its own lock; ignore
 * its result. Reenter the lock and assert if refs remain but power is absent.
 * Return 0 or -1; failed divider selection always logs div_param=0.
 * Context/timer validity and synchronization outside these locks are assumed. */
int ledc_set_timer_div(unsigned int timer_id,int clock_choice,unsigned int frequency_hz,unsigned int resolution)
{
    unsigned int denominator;
    unsigned int divider = 0;
    int clock = clock_choice;
    if (clock_choice == 0) {
        denominator = frequency_hz << (resolution & 31U);
        unsigned int source_hz = 0;
        unsigned int index;
        for (index = 0; index < 3; ++index) {
            clock = LEDC_CLOCK_CHOICES[index];
            if (clock == 9 && LEDC_RC_FAST_HZ == 0 && ledc_slow_clk_calibrate() == 0)
                continue;
            esp_clk_tree_src_get_freq_hz((unsigned int)clock,0,&source_hz);
            divider = ledc_config_divider(source_hz,denominator);
            if (divider - 0x100U <= 0x3feffU)
                break;
        }
        if (index == 3)
            goto frequency_error;
    }
    else if (clock_choice == 9) {
        unsigned int source_hz = LEDC_RC_FAST_HZ;
        if (source_hz == 0) {
            if (ledc_slow_clk_calibrate() == 0)
                goto frequency_error;
            source_hz = LEDC_RC_FAST_HZ;
        }
        denominator = frequency_hz << (resolution & 31U);
        divider = ledc_config_divider(source_hz,denominator);
        if (divider - 0x100U > 0x3feffU)
            goto frequency_error;
    }
    else {
        unsigned int source_hz = 0;
        esp_clk_tree_src_get_freq_hz((unsigned int)clock_choice,0,&source_hz);
        denominator = frequency_hz << (resolution & 31U);
        divider = ledc_config_divider(source_hz,denominator);
        if (divider - 0x100U > 0x3feffU)
            goto frequency_error;
    }
    if (clock == -1)
        __assert_func(NULL,0,NULL,NULL);
    xPortEnterCriticalTimeout(LEDC_SPINLOCK,-1);
    LedcDriverContext *object = *LEDC_CONTEXT_SLOT;
    int previous_clock = object->global_clock;
    if (previous_clock != -1 && previous_clock != clock) {
        for (unsigned int other = 0; other < 4; ++other) {
            if (other != timer_id && object->global_clock_acquired[other] != 0) {
                vPortExitCritical(LEDC_SPINLOCK);
                unsigned int stamp = esp_log_timestamp();
                esp_log_write(1,"ledc","E (%lu) %s: %s(%d): timer clock conflict, already is %d but attempt to %d\n",
                    stamp,"ledc","ledc_set_timer_div",0x2b3,(*LEDC_CONTEXT_SLOT)->global_clock,clock);
                return -1;
            }
        }
    }
    *ledc_config_byte(object,0x10U,timer_id) = 1;
    if (previous_clock != clock) {
        object->global_clock = clock;
        esp_clk_tree_enable_src((unsigned int)clock,true);
        object = *LEDC_CONTEXT_SLOT;
        LedcDeviceRegistersPrefix *device = object->hal.device;
        unsigned int mux = clock == 4 ? 1U : clock == 9 ? 2U : clock == 11 ? 3U : 0U;
        memw();
        unsigned int configuration = device->configuration;
        memw();
        device->configuration = (configuration & ~3U) | mux;
    }
    if (*ledc_config_byte(object,0x20U,timer_id) != 0 && object->global_clock_powered == 0) {
        int power_clock = object->global_clock;
        if (power_clock == 9)
            esp_sleep_sub_mode_config(1,1);
        else if (power_clock == 11)
            esp_sleep_sub_mode_config(5,1);
        else {
            *ledc_config_byte(object,0x20U,timer_id) = 0;
            vPortExitCritical(LEDC_SPINLOCK);
            ledc_timer_set(0,timer_id,divider,resolution);
            xPortEnterCriticalTimeout(LEDC_SPINLOCK,-1);
            object = *LEDC_CONTEXT_SLOT;
            if (*ledc_config_byte(object,0x20U,timer_id) != 0 && object->global_clock_powered == 0)
                __assert_func(NULL,0,NULL,NULL);
            vPortExitCritical(LEDC_SPINLOCK);
            unsigned int stamp = esp_log_timestamp();
            esp_log_write(2,"ledc","W (%lu) %s: the timer can't keep alive in sleep\n",stamp,"ledc");
            return 0;
        }
        (*LEDC_CONTEXT_SLOT)->global_clock_powered = 1;
    }
    vPortExitCritical(LEDC_SPINLOCK);
    ledc_timer_set(0,timer_id,divider,resolution);
    xPortEnterCriticalTimeout(LEDC_SPINLOCK,-1);
    object = *LEDC_CONTEXT_SLOT;
    if (*ledc_config_byte(object,0x20U,timer_id) != 0 && object->global_clock_powered == 0)
        __assert_func(NULL,0,NULL,NULL);
    vPortExitCritical(LEDC_SPINLOCK);
    return 0;
frequency_error:
    {
        unsigned int stamp = esp_log_timestamp();
        esp_log_write(1,"ledc","E (%lu) %s: requested frequency %d and duty resolution %d can not be achieved, try reducing freq_hz or duty_resolution. div_param=%lu\n",
            stamp,"ledc",frequency_hz,resolution,0U);
    }
    return -1;
}

/* Native entry: 0x4201480c. */
/*
 * Medius v3.4.7 — host application; 0x4201480c.
 * Instruction-checked recovered C.
 * Original function-byte SHA-256:
 * 4b38558b5f4725eb5b84f01979d205db2a95e3faacbd985c2d290d61abcf3b94.
 */

/* Validate config, mode 0 and timer<4. A nonzero deconfigure BYTE bypasses
 * frequency/resolution validation: require initialized, acquired AND stopped,
 * clear acquisition, and release RC_FAST/XTAL sleep power if marked powered.
 * The native deletion path checks no other timer's references, does not free
 * the context, stop hardware or clear cached clock/stopped/reference fields.
 * Otherwise require resolution 1..14 and nonzero frequency; create/reuse the
 * context, compute/configure the divider, then resume and reset on success.
 * Return 0, 0x101 allocation failure, 0x102 argument error, 0x103 invalid delete
 * state, or -1 if divider configuration fails. Resume/reset errors are ignored. */
int ledc_timer_config(const LedcTimerConfig *configuration)
{
    const char *error_format;
    unsigned int error_line;
    if (configuration == NULL) {
        error_format = "E (%lu) %s: %s(%d): timer_conf argument is invalid\n";
        error_line = 0x30a;
        goto invalid;
    }
    unsigned int mode = configuration->speed_mode;
    unsigned int timer_id = configuration->timer_id;
    if (mode != 0) {
        error_format = "E (%lu) %s: %s(%d): speed_mode argument is invalid\n";
        error_line = 0x30f;
        goto invalid;
    }
    if (timer_id >= 4) {
        error_format = "E (%lu) %s: %s(%d): timer_num argument is invalid\n";
        error_line = 0x310;
        goto invalid;
    }
    if (configuration->deconfigure != 0) {
        if (*LEDC_CONTEXT_SLOT == NULL) {
            unsigned int stamp = esp_log_timestamp();
            esp_log_write(1,"ledc","E (%lu) %s: %s(%d): %s\n",stamp,"ledc","ledc_timer_del",0x2e5,"LEDC is not initialized");
            return 0x103;
        }
        xPortEnterCriticalTimeout(LEDC_SPINLOCK,-1);
        LedcDriverContext *object = *LEDC_CONTEXT_SLOT;
        if (object->global_clock_acquired[timer_id] == 0 || object->timer_stopped[timer_id] == 0) {
            vPortExitCritical(LEDC_SPINLOCK);
            unsigned int stamp = esp_log_timestamp();
            esp_log_write(1,"ledc","E (%lu) %s: %s(%d): timer hasn't been configured, or it is still running, please stop it with ledc_timer_pause first\n",
                stamp,"ledc","ledc_timer_del",0x304);
            return 0x103;
        }
        unsigned char powered = object->global_clock_powered;
        object->global_clock_acquired[timer_id] = 0;
        if (powered != 0) {
            int clock = object->global_clock;
            if (clock == 9) {
                esp_sleep_sub_mode_config(1,0);
                (*LEDC_CONTEXT_SLOT)->global_clock_powered = 0;
            }
            else if (clock == 11) {
                esp_sleep_sub_mode_config(5,0);
                (*LEDC_CONTEXT_SLOT)->global_clock_powered = 0;
            }
        }
        vPortExitCritical(LEDC_SPINLOCK);
        return 0;
    }
    unsigned int resolution = configuration->duty_resolution;
    unsigned int frequency_hz = configuration->frequency_hz;
    if (resolution - 1U > 13U || frequency_hz == 0) {
        unsigned int stamp = esp_log_timestamp();
        esp_log_write(1,"ledc","E (%lu) %s: freq_hz=%lu duty_resolution=%lu\n",stamp,"ledc",frequency_hz,resolution);
        return 0x102;
    }
    if (ledc_speed_mode_ctx_create() == 0 && *LEDC_CONTEXT_SLOT == NULL)
        return 0x101;
    if (ledc_set_timer_div(timer_id,configuration->clock_choice,frequency_hz,resolution) != 0)
        return -1;
    ledc_timer_resume(0,timer_id);
    ledc_timer_rst(0,timer_id);
    return 0;
invalid:
    {
        unsigned int stamp = esp_log_timestamp();
        esp_log_write(1,"ledc",error_format,stamp,"ledc","ledc_timer_config",error_line);
    }
    return 0x102;
}

/* Native entry: 0x42014c1c. */
/*
 * Medius v3.4.7 — host application; 0x42014c1c.
 * Instruction-checked recovered C.
 * Original function-byte SHA-256:
 * b87842a13f2fce107df71a6007c637655df3d2fc2ccc85ffe7262447565ed6b1.
 */

/* Validate channel<8, mode 0, nonnegative routable GPIO, timer<4,
 * interrupt type<2 and sleep strategy<3; strategy 1 is unsupported (0x106).
 * GPIO validity follows the native bit5/low5 mask selection, including aliasing
 * for positive values >=64. A new context temporarily selects RC_FAST mux 2
 * without updating cached global_clock=-1. Ignore clock/helper results.
 * Configure duty/hpoint, start output, bind timer, set fade-end interrupt,
 * then route GPIO. Errors from those nested configuration calls are ignored.
 * Reload sleep strategy twice: under lock, 0 changes only an unset strategy,
 * while 2 sets sticky channel_keep_alive; after unlocking, 2 additionally
 * acquires timer sleep power and disables GPIO sleep selection. Repeated
 * calls can add references; strategy 0 does not clear keep-alive.
 * Return 0, 0x101 allocation failure, 0x102 argument error or 0x106; a sleep
 * clock warning leaves success intact. No rollback of partial configuration. */
int ledc_channel_config(const LedcChannelConfig *configuration)
{
    const char *error_format;
    unsigned int error_line;
    if (configuration == NULL) {
        error_format = "E (%lu) %s: %s(%d): ledc_conf argument is invalid\n";
        error_line = 0x33f;
        goto invalid;
    }
    unsigned int channel_id = configuration->channel_id;
    unsigned int speed_mode = configuration->speed_mode;
    if (channel_id >= 8) {
        error_format = "E (%lu) %s: %s(%d): ledc_channel argument is invalid\n";
        error_line = 0x348;
        goto invalid;
    }
    if (speed_mode != 0) {
        error_format = "E (%lu) %s: %s(%d): speed_mode argument is invalid\n";
        error_line = 0x349;
        goto invalid;
    }
    unsigned int pin = (unsigned int)configuration->gpio_pin;
    unsigned int invalid_pins = (pin & 32U) != 0 ? 0xfffe0000U : 0x03c00000U;
    if ((pin & 0x80000000U) != 0 || ((invalid_pins >> (pin & 31U)) & 1U) != 0) {
        error_format = "E (%lu) %s: %s(%d): gpio_num argument is invalid\n";
        error_line = 0x34a;
        goto invalid;
    }
    unsigned int timer_id = configuration->timer_id;
    if (timer_id >= 4) {
        error_format = "E (%lu) %s: %s(%d): timer_select argument is invalid\n";
        error_line = 0x34b;
        goto invalid;
    }
    unsigned int interrupt_type = configuration->interrupt_type;
    if (interrupt_type >= 2) {
        error_format = "E (%lu) %s: %s(%d): intr_type argument is invalid\n";
        error_line = 0x34c;
        goto invalid;
    }
    unsigned int sleep_mode = configuration->sleep_mode;
    if (sleep_mode >= 3) {
        error_format = "E (%lu) %s: %s(%d): sleep_mode argument is invalid\n";
        error_line = 0x34d;
        goto invalid;
    }
    if (sleep_mode == 1) {
        unsigned int stamp = esp_log_timestamp();
        esp_log_write(1,"ledc","E (%lu) %s: %s(%d): register back up is not supported\n",stamp,"ledc","ledc_channel_config",0x34f);
        return 0x106;
    }
    unsigned int duty = configuration->duty;
    unsigned int inversion = configuration->flags & 1U;
    unsigned int hpoint = (unsigned int)configuration->hpoint;
    if (ledc_speed_mode_ctx_create() == 0) {
        if (*LEDC_CONTEXT_SLOT == NULL)
            return 0x101;
    }
    else {
        xPortEnterCriticalTimeout(LEDC_SPINLOCK,-1);
        if ((*LEDC_CONTEXT_SLOT)->global_clock == -1) {
            esp_clk_tree_enable_src(9,true);
            LedcDeviceRegistersPrefix *device = (*LEDC_CONTEXT_SLOT)->hal.device;
            memw();
            unsigned int global = device->configuration;
            memw();
            device->configuration = (global & ~3U) | 2U;
        }
        vPortExitCritical(LEDC_SPINLOCK);
    }
    ledc_set_duty_with_hpoint(0,channel_id,duty,hpoint);
    ledc_update_duty(0,channel_id);
    ledc_bind_channel_timer(0,(int)channel_id,timer_id);
    xPortEnterCriticalTimeout(LEDC_SPINLOCK,-1);
    LedcDeviceRegistersPrefix *device = (*LEDC_CONTEXT_SLOT)->hal.device;
    unsigned int bit = 1U << ((channel_id + 4U) & 31U);
    memw();
    unsigned int interrupts = device->interrupt_enable;
    if (interrupt_type == 1) {
        memw();
        device->interrupt_enable = interrupts | bit;
    }
    else {
        memw();
        device->interrupt_enable = interrupts & ~bit;
    }
    vPortExitCritical(LEDC_SPINLOCK);
    ledc_set_pin_internal(pin,inversion,0,(int)channel_id);
    xPortEnterCriticalTimeout(LEDC_SPINLOCK,-1);
    sleep_mode = configuration->sleep_mode;
    if (sleep_mode == 0) {
        LedcDriverContext *object = *LEDC_CONTEXT_SLOT;
        if (object->sleep_mode == 3)
            object->sleep_mode = 0;
    }
    else if (sleep_mode == 2) {
        LedcDriverContext *object = *LEDC_CONTEXT_SLOT;
        object->channel_keep_alive[channel_id] = 1;
        object->sleep_mode = 2;
    }
    vPortExitCritical(LEDC_SPINLOCK);
    if (configuration->sleep_mode != 2)
        return 0;
    xPortEnterCriticalTimeout(LEDC_SPINLOCK,-1);
    unsigned char power_error = ledc_timer_clk_src_set_xpd_in_sleep(timer_id);
    vPortExitCritical(LEDC_SPINLOCK);
    if (power_error != 0) {
        unsigned int stamp = esp_log_timestamp();
        esp_log_write(2,"ledc","W (%lu) %s: the binded timer can't keep alive in sleep\n",stamp,"ledc");
    }
    gpio_sleep_sel_dis(pin);
    return 0;
invalid:
    {
        unsigned int stamp = esp_log_timestamp();
        esp_log_write(1,"ledc",error_format,stamp,"ledc","ledc_channel_config",error_line);
    }
    return 0x102;
}
