/* Medius v3.4.7 device — completion-side endpoint credit observation. */
#include "../include/types.h"

/* Native entry: 0x40377210. */
/* Original function-byte SHA-256:
 * 77543e29d19deb305a1ac0e192ba062638ea72d6f15fcba68ae21f2776a14a74. */
/*
 * Observe a completed IN transfer using microsecond timestamps. endpoint is
 * an unchecked full-width index; callers supply its endpoint number. now_us
 * and submitted_us are aligned 64-bit arguments, not six unrelated words.
 * tail_length is the final packet's length, or the caller's fallback length.
 *
 * Read the previous completion LOW/HIGH. An all-zero pair seeds interval=0.
 * Otherwise read the previous interval and credit RX LOW/HIGH. If the old
 * interval is 701..1299us and signed wrapping RX age is nonnegative, two
 * completion-gap windows can set pending_flags[endpoint]=1:
 *   - 1501..2599us, RX age>600us, and signed submission age <= gap/2 plus
 *     the speed/packet estimate below plus 14us;
 *   - 701..1299us and RX age<=149us.
 * No successful observation clears an already pending flag.
 *
 * Packet estimate uses min(tail_length,64): bits=88*length+385. Low-speed
 * setting exactly 1 selects ((ushort)(bits/10+60)*2)/3; every other setting
 * selects bits/120+5. These are firmware heuristics, not verified wire times.
 *
 * The fallback interval saturates positive signed gaps above INT32_MAX.
 * Negative wrapping gaps retain their LOW word. The 1501..2599 window also
 * retains its LOW word on an unmarked path. Finally write interval, then
 * completion LOW/HIGH. No lock, barrier, bounds check or coherent snapshot is
 * supplied here; callers coordinate shared state and supply valid indices.
 */
void credit_observe_in_completion(unsigned int endpoint,
    unsigned long long now_us,unsigned long long submitted_us,
    unsigned int tail_length)
{
    volatile TimestampWords *previous =
        &CREDIT_LAST_IN_COMPLETION[endpoint];
    unsigned int previous_low = previous->low;
    unsigned int previous_high = previous->high;
    unsigned int next_interval = 0;

    if ((previous_low | previous_high) != 0) {
        unsigned int old_interval = CREDIT_IN_INTERVAL_US[endpoint];
        const volatile TimestampWords *received_time =
            (const volatile TimestampWords *)((unsigned int)&CREDIT_STATE +
                                              16U + endpoint * 8U);
        unsigned int rx_low = received_time->low;
        unsigned int rx_high = received_time->high;
        unsigned long long gap = now_us -
            (((unsigned long long)previous_high << 32) | previous_low);
        long long rx_age = (long long)(now_us -
            (((unsigned long long)rx_high << 32) | rx_low));
        int mark_pending = 0;
        int retain_low = 0;

        if (old_interval - 701U < 599U && rx_age >= 0) {
            unsigned int packet_length = tail_length < 64U ? tail_length : 64U;
            unsigned int bits = packet_length * 88U + 385U;
            unsigned char low_speed = CLONE_LOW_SPEED;
            unsigned int packet_us;
            if (low_speed == 1)
                packet_us = ((unsigned short)(bits / 10U + 60U) * 2U) / 3U;
            else
                packet_us = bits / 120U + 5U;

            if (gap - 1501ULL <= 1098ULL) {
                retain_low = 1;
                if (rx_age > 600LL) {
                    long long submitted_age = (long long)(now_us - submitted_us);
                    long long limit = (long long)(gap >> 1) + packet_us + 14LL;
                    if (submitted_age <= limit)
                        mark_pending = 1;
                }
            } else if (gap - 701ULL <= 598ULL && rx_age <= 149LL) {
                mark_pending = 1;
                retain_low = 1;
            }
        }

        if (mark_pending)
            *(volatile unsigned char *)((unsigned int)&CREDIT_STATE + endpoint) = 1;
        if (!retain_low && (long long)gap > 0x7fffffffLL)
            next_interval = 0x7fffffffU;
        else
            next_interval = (unsigned int)gap;
    }

    CREDIT_IN_INTERVAL_US[endpoint] = next_interval;
    previous->low = (unsigned int)now_us;
    previous->high = (unsigned int)(now_us >> 32);
}
