/* Medius v3.4.7 device: recovered timekeeping and native clock boundaries. */

#include "../include/types.h"

/* Native entry: 0x4037703c. */
/* Original function-byte SHA-256:
 * 20ad20d450c69137f3f2ba545669635a18296971eff8a3f43cd7a6b17c3f5a1a. */
/* Write raw kernel ticks to tms_stime, then zero tms_cstime, tms_cutime and
 * tms_utime in that native order. The scaling factor is compiled to 1 here.
 * Under the libc time lock, obtain the adjusted boot epoch; unlock before
 * sampling time since boot. Add modulo64, divide UNSIGNED by 1,000,000, and
 * return the quotient's low32 bits as clock_t. The reentrancy pointer is unused;
 * times must be writable (no NULL check). This is not per-task CPU accounting. */
clock_t _times_r(struct _reent *reentrancy,struct tms *times)
{
    (void)reentrancy;
    volatile struct tms *out = times;
    out->tms_stime = (clock_t)xTaskGetTickCount();
    out->tms_cstime = 0;
    out->tms_cutime = 0;
    out->tms_utime = 0;
    _lock_acquire(CLOCK_TIME_LOCK);
    unsigned long long boot = adjust_boot_time();
    _lock_release(CLOCK_TIME_LOCK);
    unsigned long long now = boot + esp_time_impl_get_time_since_boot();
    return (clock_t)(unsigned int)(now / 1000000ULL);
}

/* Native entry: 0x40377084. */
/* Original function-byte SHA-256:
 * fb29d0904c4f08ac41bac34adb1b3b323746dfac3b445b827ae388daaeea55b3. */
/* Return 0. A NULL timeval performs no clock/lock access. Otherwise get the
 * adjusted boot epoch under the libc time lock, unlock, and add a later uptime
 * sample modulo64. Divide UNSIGNED by 1,000,000: store seconds LOW then HIGH at
 * offsets 0/4 and the microsecond remainder at +8. The timeval padding at +12
 * remains untouched. Reentrancy/timezone pointers are ignored, errno is not
 * changed. The two time samples are not one atomic snapshot with clock setters. */
int _gettimeofday_r(struct _reent *reentrancy,struct timeval *time,void *timezone)
{
    (void)reentrancy;
    (void)timezone;
    if (time == 0)
        return 0;
    _lock_acquire(CLOCK_TIME_LOCK);
    unsigned long long boot = adjust_boot_time();
    _lock_release(CLOCK_TIME_LOCK);
    unsigned long long now = boot + esp_time_impl_get_time_since_boot();
    unsigned long long seconds = now / 1000000ULL;
    volatile unsigned int *second_words = (volatile void *)&time->tv_sec;
    second_words[0] = (unsigned int)seconds;
    second_words[1] = (unsigned int)(seconds >> 32);
    ((volatile struct timeval *)time)->tv_usec = (suseconds_t)(now % 1000000ULL);
    return 0;
}

/* Native entry: 0x42007620. */
/* Original function-byte SHA-256:
 * 25d572b649d84f767813df30cc3a88b692ce9223843d46a4476ea175c4b6e305. */
/* Return the 64-bit boot epoch, optionally advancing a pending clock slew.
 * Read the epoch under its own lock. Epoch zero clears slew-start LOW/HIGH and
 * returns without sampling uptime. Otherwise sample uptime and read start HIGH
 * then LOW; a backwards sample clears start, and zero start returns unchanged.
 *
 * Sample uptime again and reread start HIGH/LOW. Correction is (now>>6) minus
 * (start>>6), not (now-start)>>6. Nonpositive correction changes nothing. For a
 * positive step, store start LOW, read remaining HIGH, store start HIGH, then
 * read remaining LOW. This interleaving follows the native instructions.
 *
 * A negative remaining correction moves the epoch backwards; a positive one
 * moves it forwards. If this step finishes the correction, add the entire old
 * remainder and clear start LOW/HIGH, retaining the remainder words. Otherwise
 * update remaining LOW/HIGH and move the epoch by the step. All epoch arithmetic
 * wraps modulo64. Save the epoch through the locked RTC-register writer.
 * Caller supplies the outer time lock. No local outer lock/fence or scheduled
 * timer is added: slew progress occurs when this function is called. */
unsigned long long adjust_boot_time(void)
{
    unsigned long long boot = esp_time_impl_get_boot_time();
    volatile ClockWords *start = CLOCK_ADJUST_START;
    if (boot == 0) {
        start->low = 0;
        start->high = 0;
        return boot;
    }
    unsigned long long observed = esp_time_impl_get_time_since_boot();
    unsigned int start_high = start->high;
    unsigned int start_low = start->low;
    unsigned long long previous = ((unsigned long long)start_high << 32) | start_low;
    if (observed < previous) {
        start->low = 0;
        start->high = 0;
        return boot;
    }
    if (previous == 0)
        return boot;
    unsigned long long now = esp_time_impl_get_time_since_boot();
    start_high = start->high;
    start_low = start->low;
    previous = ((unsigned long long)start_high << 32) | start_low;
    long long correction = (long long)(now >> 6) - (long long)(previous >> 6);
    if (correction <= 0)
        return boot;
    volatile ClockWords *remaining = CLOCK_ADJUST_REMAINING;
    start->low = (unsigned int)now;
    unsigned int remaining_high = remaining->high;
    start->high = (unsigned int)(now >> 32);
    unsigned int remaining_low = remaining->low;
    unsigned long long pending = ((unsigned long long)remaining_high << 32) | remaining_low;
    unsigned long long next;
    if ((int)remaining_high < 0) {
        next = pending + (unsigned long long)correction;
        if ((long long)next < 0) {
            boot -= (unsigned long long)correction;
            remaining->low = (unsigned int)next;
            remaining->high = (unsigned int)(next >> 32);
        } else {
            boot += pending;
            start->low = 0;
            start->high = 0;
        }
    } else {
        next = pending - (unsigned long long)correction;
        if ((long long)next > 0) {
            boot += (unsigned long long)correction;
            remaining->low = (unsigned int)next;
            remaining->high = (unsigned int)(next >> 32);
        } else {
            boot += pending;
            start->low = 0;
            start->high = 0;
        }
    }
    esp_time_impl_set_boot_time(boot);
    return boot;
}

/* Native entry: 0x42007780. */
/* Original function-byte SHA-256:
 * 1e39ebc13390352e800e679a9e34194e460ac18b3a029b8f7797ee497db39962. */
/* Call esp_system_get_time, then read the saved microsecond offset LOW before
 * HIGH and add modulo64. Return both words; Ghidra's void inference discarded
 * this result. Offset sampling is unlocked and not retried for coherence. */
unsigned long long esp_time_impl_get_time_since_boot(void)
{
    unsigned long long system = (unsigned long long)esp_system_get_time();
    unsigned int low = CLOCK_MICROSECONDS_OFFSET->low;
    unsigned int high = CLOCK_MICROSECONDS_OFFSET->high;
    return system + (((unsigned long long)high << 32) | low);
}

/* Native entry: 0x4200779c. */
/* Original function-byte SHA-256:
 * d4d38e86e5f7903d784cf05862a4e1ea370fbaef66f82857413cf7f0e1a1c6e2. */
/* Under the boot-time mutex, write the supplied 64-bit epoch to RTC boot-time
 * storage: MEMW then LOW at 0x60008058, MEMW then HIGH at 0x6000805c. Unlock
 * afterwards. No value/range check, peripheral retry or result is provided. */
void esp_time_impl_set_boot_time(unsigned long long boot_us)
{
    _lock_acquire(CLOCK_BOOT_LOCK);
    memw();
    CLOCK_RTC_BOOT->low = (unsigned int)boot_us;
    memw();
    CLOCK_RTC_BOOT->high = (unsigned int)(boot_us >> 32);
    _lock_release(CLOCK_BOOT_LOCK);
}

/* Native entry: 0x420077c4. */
/* Original function-byte SHA-256:
 * d1e1dd9f53e51c4084f9f015c3719537b1d7d49a4f54f6a85f648f1b17b9fb11. */
/* Under the boot-time mutex, read RTC boot storage LOW then HIGH, each after
 * MEMW. Unlock and return both words. There is no high/low retry; coherent use
 * relies on the corresponding writers honoring this same mutex. */
unsigned long long esp_time_impl_get_boot_time(void)
{
    _lock_acquire(CLOCK_BOOT_LOCK);
    memw();
    unsigned int low = CLOCK_RTC_BOOT->low;
    memw();
    unsigned int high = CLOCK_RTC_BOOT->high;
    _lock_release(CLOCK_BOOT_LOCK);
    return ((unsigned long long)high << 32) | low;
}

/* Native entry: 0x42007704. */
/* Original function-byte SHA-256:
 * 4d26051083ed9c0cbe6528de852aed2da94649e4c27bc7cd3674ab9f1f0d33dc. */
/*
 * Requires a nonnull readable timeval. Under the time mutex reads both WORDs
 * of the slew-start marker; if either is nonzero, applies adjust_boot_time,
 * then clears marker LOW followed by HIGH. Releases that mutex before loading
 * timeval seconds LOW/HIGH and signed32 microseconds. Computes seconds*1000000
 * plus sign-extended microseconds modulo2^64, samples time-since-boot, then
 * sets the RTC boot offset to their difference through its own locked setter.
 * No timezone access, range/normalization check or errno update. Setting time
 * and stopping slew are separate lock scopes; this is the nonnull specialization
 * of ESP-IDF settimeofday, not a claim of original source-file boundaries.
 */
void medius_settimeofday_nonnull(const struct timeval *time)
{
    _lock_acquire(CLOCK_TIME_LOCK);
    unsigned int slew_low = CLOCK_ADJUST_START->low;
    unsigned int slew_high = CLOCK_ADJUST_START->high;
    if ((slew_low | slew_high) != 0) {
        (void)adjust_boot_time();
        CLOCK_ADJUST_START->low = 0;
        CLOCK_ADJUST_START->high = 0;
    }
    _lock_release(CLOCK_TIME_LOCK);
    const volatile MediusTimevalWords *words = (const volatile MediusTimevalWords *)time;
    unsigned int seconds_low = words->seconds_low;
    unsigned int seconds_high = words->seconds_high;
    int microseconds = words->microseconds;
    unsigned long long seconds = ((unsigned long long)seconds_high << 32) | seconds_low;
    unsigned long long requested_us = seconds * 1000000U + (unsigned long long)(long long)microseconds;
    unsigned long long since_boot = esp_time_impl_get_time_since_boot();
    esp_time_impl_set_boot_time(requested_us - since_boot);
}

/* Native entry: 0x42007768. */
/* Original function-byte SHA-256:
 * 0afba1e60bcc0f18f7d7094c455ef07628e8893abbf0c7b3736ff07309b0e46b. */
/*
 * A null timeval succeeds without reading timezone or changing time. A nonnull
 * timeval delegates to the nonnull specialization, which stops the current slew
 * and replaces the RTC boot offset. Always returns0 after it returns; timezone
 * is ignored. No input range check, errno update or realtime-clock measurement.
 */
int settimeofday(const struct timeval *time,const struct timezone *timezone)
{
    (void)timezone;
    if (time != 0) medius_settimeofday_nonnull(time);
    return 0;
}

/* Native entry: 0x42007778. */
/* Original function-byte SHA-256:
 * b2cbd9f9cf0bed78d0b60639986bd4f1966e03d10dda4ee6b07be17aac5a310e. */
/* Initializes the RTC/system-timer offset by calling esp_set_time_from_rtc.
 * No local allocation, validation, lock, counter initialization or return status. */
void esp_time_impl_init(void)
{
    esp_set_time_from_rtc();
}

/* Native entry: 0x420077ec. */
/* Original function-byte SHA-256:
 * 77ddafcd0f63e335afc3f9f8bda8dc16b965a7d5338b1f627801ae5b3a794e7a. */
/*
 * Reads gettimeofday into a local16-byte timeval, then sets that same time
 * with null timezone; both statuses are ignored. Samples RTC microseconds then
 * system time, then reads RTC boot offset LOW/HIGH under its boot mutex with
 * a MEMW before each WORD. Unlocks before reading the RAM microseconds offset
 * LOW/HIGH. Computes new_boot = saved_boot + saved_offset - (RTC - system),
 * all modulo64, and reacquires the boot mutex to MEMW/store LOW then HIGH.
 * Separate get/set/read/write phases allow intervening updates; no whole-operation
 * atomicity, synchronized sample, offset rewrite or hardware clock adjustment.
 */
void esp_sync_timekeeping_timers(void)
{
    struct timeval time;
    (void)gettimeofday(&time,0);
    (void)settimeofday(&time,0);
    unsigned long long rtc_us = esp_rtc_get_time_us();
    unsigned long long system_us = (unsigned long long)esp_system_get_time();
    _lock_acquire(CLOCK_BOOT_LOCK);
    memw(); unsigned int boot_low = CLOCK_RTC_BOOT->low;
    memw(); unsigned int boot_high = CLOCK_RTC_BOOT->high;
    _lock_release(CLOCK_BOOT_LOCK);
    unsigned int offset_low = CLOCK_MICROSECONDS_OFFSET->low;
    unsigned int offset_high = CLOCK_MICROSECONDS_OFFSET->high;
    unsigned long long boot_us = ((unsigned long long)boot_high << 32) | boot_low;
    unsigned long long offset_us = ((unsigned long long)offset_high << 32) | offset_low;
    unsigned long long updated_boot = boot_us + offset_us - (rtc_us - system_us);
    _lock_acquire(CLOCK_BOOT_LOCK);
    memw(); CLOCK_RTC_BOOT->low = (unsigned int)updated_boot;
    memw(); CLOCK_RTC_BOOT->high = (unsigned int)(updated_boot >> 32);
    _lock_release(CLOCK_BOOT_LOCK);
}

/* Native entry: 0x42007880. */
/* Original function-byte SHA-256:
 * cec7dd724da470dff8a70c889aad8b97b6bfd32780231684015e1b56ee3a340e. */
/*
 * Samples retained RTC microseconds first, then esp_system_get_time, and stores
 * their modulo64 difference into the RAM microseconds offset LOW then HIGH.
 * The two samplers have their own behavior; no common lock, retry or coherent
 * paired publication is added. It does not adjust boot time or start a timer.
 */
void esp_set_time_from_rtc(void)
{
    unsigned long long rtc_us = esp_rtc_get_time_us();
    unsigned long long system_us = (unsigned long long)esp_system_get_time();
    unsigned long long offset = rtc_us - system_us;
    CLOCK_MICROSECONDS_OFFSET->low = (unsigned int)offset;
    CLOCK_MICROSECONDS_OFFSET->high = (unsigned int)(offset >> 32);
}
