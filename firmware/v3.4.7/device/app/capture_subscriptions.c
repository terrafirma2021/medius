/* Device editable capture subscriptions and publication. */
#include "../include/types.h"

/* Capture subscription reconstruction utilities: native inline class-mask
 * scans, not extra native entries. Address increments wrap at32 bits. This
 * is a do/while walk even when count is0 after corrupt-count wrap; no repair
 * or new zero-count guard. Native SSL/SLL uses class low5 before narrowing
 * to16 bits. Wildcard class0xff produces0x0fff and terminates the walk.
 */
static __attribute__((always_inline)) inline unsigned short capture_subscription_mask(
    unsigned int count)
{
    unsigned int cursor = (unsigned int)CAPTURE_EDITABLE_SUBSCRIPTIONS;
    unsigned int end = cursor + count * 6U;
    unsigned short mask = 0;
    do {
        unsigned int traffic_class = *(const volatile unsigned char *)(cursor + 2U);
        cursor += 6U;
        if (traffic_class == 0xffU)
            return 0x0fffU;
        mask = (unsigned short)(mask | (1U << (traffic_class & 31U)));
    } while (cursor != end);
    return mask;
}

/* Native entry: 0x4203782c. */
/* Original function-byte SHA-256:
 * 90c4915c8359f3eacbf569fbce3dbd90e96dd2912f9c3e838cbba722c47b5cf1. */
/*
 * Change one capture subscription and publish the entire260-byte editable
 * image into the other bank. Arguments narrow to8/16/8/8/8 bits. Take an
 * optional rewrite mutex withUINT32_MAX ticks, snapshot count BYTE BEFORE
 * entering the subscription critical section withUINT32_MAX timeout, and
 * ignore both statuses. These native timeout arguments are full32-bit -1;
 * they are not the byte value255.
 * Ordinary keys admit class0..11 or wildcard0xff, direction0..2, with ID0xffff
 * required for wildcard class. Present is any nonzero byte, not just1.
 *
 * Absent class0xff/ID0xffff with direction0..2 clears all260 editable bytes,
 * reads fresh count then class mask, and zeroes32 subscriber-drop HALFWORDs
 * with a fence before every store. Invalid wildcard removal keys still publish
 * the unchanged image. The extra clear/shift branch in raw decompilation is
 * unreachable: the cached direction cannot be both <=2 and >=3.
 *
 * Ordinary search uses cached count and class BYTE/ID HALFWORD/direction BYTE.
 * Update writes ID HALFWORD, packed class/direction HALFWORD, capture-length
 * BYTE, preserving padding and per-rule drops. Append rejects only count==32,
 * sets sticky full BYTE1 and otherwise publishes count+1 modulo256 BEFORE
 * clearing its drop HALFWORD and storing those fields. Rebuild class mask in
 * a local16-bit accumulator and publish it ONCE; wildcard gives0x0fff.
 *
 * Removal shifts each six-byte record and its editable drop HALFWORD with
 * native access order, decrements count, zeroes all three tail HALFWORDs plus
 * its drop HALFWORD, and recomputes mask once. Then shift the separate32-slot
 * subscriber-drop array from the removed index through30, fencing each read
 * and each write, and fence/clear slot31, even when removed slot was last live.
 * No missing-removal/full/invalid request skips publication or clears full.
 *
 * Publication fences/reads bank BYTE, XORs1 without masking, copies260 bytes,
 * fences/publishes bank BYTE, then fences/publishes cached class mask HALFWORD
 * before leaving the critical section. An ordinary removal from an initially
 * empty in-lock table reads its mask AFTER the bank read and skips baseline
 * reset. Otherwise a pre-critical empty count becoming nonempty clears mouse,
 * keyboard, then consumer capture-valid BYTEs with individual fences. Read
 * signed report-binding count BEFORE the consumer clear; if positive, clear
 * observed-buttons-valid BYTE at each904-byte binding stride. Native trip
 * count is ((count-1) mod2^29)+1. Finally give a freshly reloaded optional
 * mutex. No rollback, allocation, copy bound or bank/count repair is supplied.
 */
void capture_subscription_update(unsigned char traffic_class,unsigned short id,
    unsigned char direction,unsigned char present,unsigned char capture_length)
{
    RtosQueue *mutex = REWRITE_MUTEX;
    if (mutex != NULL)
        (void)xQueueSemaphoreTake(mutex,0xffffffffU);
    volatile CaptureEditableProfile *profile = CAPTURE_EDITABLE_PROFILE;
    unsigned int previous_count = profile->count;
    (void)xPortEnterCriticalTimeout(CAPTURE_SUBSCRIPTION_LOCK,-1);
    unsigned short mask;
    unsigned int has_subscriptions;
    unsigned int empty_removal = 0;
    if (present == 0 && traffic_class == 0xffU) {
        if (id == 0xffffU && direction < 3U) {
            memset((void *)profile,0,260U);
            unsigned int cleared_count = profile->count;
            mask = profile->class_mask;
            for (unsigned int index = 0; index < 32U; ++index) {
                memw();
                CAPTURE_SUBSCRIBER_DROPS[index] = 0;
            }
            has_subscriptions = cleared_count != 0;
        } else {
            has_subscriptions = profile->count != 0;
            mask = profile->class_mask;
        }
    } else {
        unsigned int count = profile->count;
        if ((traffic_class >= 12U && traffic_class != 0xffU) ||
            (traffic_class == 0xffU && id != 0xffffU) || direction >= 3U) {
            has_subscriptions = count != 0;
            mask = profile->class_mask;
            goto publish;
        }
        unsigned int selected = 0;
        while (selected < count) {
            volatile CaptureEditableRule *rule = profile->rules + selected;
            if (rule->traffic_class == traffic_class && rule->id == id &&
                rule->direction == direction)
                break;
            ++selected;
        }
        if (selected < count && present == 0) {
            for (unsigned int next = selected + 1U; next < count; ++next) {
                volatile CaptureEditableRule *source = profile->rules + next;
                volatile CaptureEditableRule *destination = profile->rules + next - 1U;
                unsigned short moved_id = source->id;
                unsigned short moved_class_direction = source->class_direction;
                destination->id = moved_id;
                unsigned short moved_capture_word = source->capture_word;
                unsigned short drops = profile->rule_drops[next];
                profile->rule_drops[next - 1U] = drops;
                destination->class_direction = moved_class_direction;
                destination->capture_word = moved_capture_word;
            }
            unsigned char remaining = (unsigned char)(count - 1U);
            profile->count = remaining;
            volatile CaptureEditableRule *tail = profile->rules + remaining;
            tail->id = 0;
            tail->class_direction = 0;
            tail->capture_word = 0;
            profile->rule_drops[remaining] = 0;
            mask = remaining != 0 ? capture_subscription_mask(remaining) : 0;
            profile->class_mask = mask;
            /* Unsigned loop count retains the native underflow for corrupt
             * selected>31, rather than silently converting it to a no-op. */
            unsigned int shift_count = 31U - selected;
            unsigned int cursor = selected;
            if (selected != 31U) {
                do {
                    memw();
                    unsigned short drops = CAPTURE_SUBSCRIBER_DROPS[cursor + 1U];
                    memw();
                    CAPTURE_SUBSCRIBER_DROPS[cursor] = drops;
                    ++cursor;
                } while (--shift_count != 0);
            }
            memw();
            CAPTURE_SUBSCRIBER_DROPS[31] = 0;
            has_subscriptions = remaining != 0;
        } else if (present != 0) {
            unsigned int result_count = count;
            if (selected == count) {
                if (count == 32U) {
                    mask = profile->class_mask;
                    profile->full = 1;
                    has_subscriptions = 1;
                    goto publish;
                }
                if (count == 0) {
                    profile->rule_drops[0] = count;
                    profile->count = 1;
                    result_count = 1;
                } else {
                    result_count = (unsigned char)(count + 1U);
                    profile->count = result_count;
                    profile->rule_drops[count] = 0;
                }
            }
            volatile CaptureEditableRule *rule = profile->rules + selected;
            rule->id = id;
            rule->class_direction = (unsigned short)(traffic_class | ((unsigned int)direction << 8));
            rule->capture_length = capture_length;
            mask = capture_subscription_mask(result_count);
            profile->class_mask = mask;
            has_subscriptions = 1;
        } else {
            if (count == 0) {
                empty_removal = 1;
                has_subscriptions = 0;
            } else {
                has_subscriptions = 1;
                mask = profile->class_mask;
            }
        }
    }
publish:
    memw();
    unsigned int bank = CAPTURE_ACTIVE_BANK;
    unsigned int next_bank = bank ^ 1U;
    if (empty_removal != 0)
        mask = profile->class_mask;
    memcpy(CAPTURE_BANK_STORAGE + next_bank * 260U,(const void *)profile,260U);
    memw();
    CAPTURE_ACTIVE_BANK = next_bank;
    memw();
    CAPTURE_ENABLED_CLASSES = mask;
    vPortExitCritical(CAPTURE_SUBSCRIPTION_LOCK);
    if (empty_removal == 0 && previous_count == 0 && has_subscriptions != 0) {
        memw();
        REPORT_CAPTURE_BUTTONS_VALID = 0;
        memw();
        REPORT_KEYBOARD_CAPTURE.valid = 0;
        int binding_count = REPORT_BINDING_COUNT;
        memw();
        REPORT_CONSUMER_CAPTURE.valid = 0;
        if (binding_count > 0) {
            unsigned int iterations = (((unsigned int)binding_count - 1U) & 0x1fffffffU) + 1U;
            unsigned int cursor = (unsigned int)REPORT_BINDING_CAPTURE_VALID_BYTES;
            do {
                *(volatile unsigned char *)cursor = 0;
                cursor += 904U;
            } while (--iterations != 0);
        }
    }
    mutex = REWRITE_MUTEX;
    if (mutex != NULL)
        (void)xQueueGenericSend(mutex,NULL,0,0);
}
