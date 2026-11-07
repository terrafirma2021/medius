/* Device logging: severity packets and buffered startup output. */

#include "../include/types.h"

/* Native entry: 0x42027310. */
/* Original function-byte SHA-256:
 * d21edf1bf9b9e071334ea83d95e8cef461e88a485c98ce5f0eb8aee6acdf15bb. */
/*
 * Reads text BYTE 0 even for zero/negative length. If ESC, searches for the
 * first 'm' using unbounded strchr and classifies the following BYTE; missing
 * 'm' defaults to severity 2. Otherwise E/W/I/D/V map to 0/1/2/3/4 and other
 * bytes to 2. ANSI/source bytes themselves are retained in the payload.
 *
 * Signed min(length,160) is passed as the memcpy size, then external control
 * opcode 8/sequence 0 sends [severity|text] with low16(copy_length+1).
 * Negative length therefore becomes a huge unsigned copy; it is not clamped
 * to zero. No source/NUL/extent validation, terminator insertion or local
 * lock. A buffered ANSI line can make strchr read beyond its stored extent.
 */
void control_log_emit(const unsigned char *text,int length)
{
    unsigned char prefix = *(const volatile unsigned char *)text;
    unsigned char severity = 2;
    if (prefix == 0x1b) {
        const char *end_color = strchr((const char *)text,'m');
        if (end_color == 0) goto copy_text;
        prefix = *(const volatile unsigned char *)(end_color + 1);
    }
    switch (prefix) {
        case 'E': severity = 0; break;
        case 'W': severity = 1; break;
        case 'D': severity = 3; break;
        case 'V': severity = 4; break;
        default: severity = 2; break;
    }
copy_text:
    unsigned int copy_length = (unsigned int)(length < 160 ? length : 160);
    ControlLogPacket packet;
    packet.severity = severity;
    memcpy(packet.text,text,copy_length);
    control_send_frame(8,0,&packet,(copy_length + 1U) & 0xffffU);
}

/* Native entry: 0x42027380. */
/* Original function-byte SHA-256:
 * 57d8fd361f03266dab7b18a37b33df8a4c147f755b4cea570376520ec29302f8. */
/*
 * SDK vprintf callback with the native 12-byte Xtensa va_list. MEMW then
 * samples one guard BYTE; busy returns 0 without writing it. Otherwise MEMW
 * sets guard 1 and formats into 160 stack bytes. Negative result clears guard
 * after MEMW and returns 0. Nonnegative result is capped at 159, then only
 * trailing CR/LF bytes are removed from length, without editing text/NUL.
 * Empty output clears guard and returns 0 without testing control traffic.
 *
 * Before PC control traffic, copies that text to the slot selected by a first
 * next-index BYTE sample. After memcpy REREADS next index, then samples count;
 * publishes (reread index+1)%24 BYTE, stores length HALF at that reread index,
 * and increments cached count only if <24. Copies no terminator, and does
 * not repair corrupt indices or the possible two-index mismatch.
 *
 * After traffic, an unset flushed BYTE samples next then count, computes
 * signed (next+24-count)%24, sets flushed BEFORE emission and, when cached
 * count is nonzero, emits buffered records oldest-first. Start is narrowed
 * to BYTE, ordinal is a full WORD, and each iteration compares low8 ordinal
 * against a FRESH count BYTE. Does not clear stored count/lengths. Then emits
 * the current line. Later lines emit directly. Returns retained trimmed
 * length, ignoring transport results. All active exits MEMW-clear guard;
 * this separate load/store guard is not atomic exclusion or a delivery proof.
 */
int device_log_hook(const char *format,va_list arguments)
{
    memw();
    unsigned char busy = DEVICE_LOG_BUSY;
    if (busy != 0) return 0;
    char text[160];
    memw();
    DEVICE_LOG_BUSY = 1;
    int formatted = vsnprintf(text,160,format,arguments);
    if (formatted < 0) {
        memw();
        DEVICE_LOG_BUSY = 0;
        return 0;
    }
    unsigned int length = formatted < 159 ? (unsigned int)formatted : 159U;
    while (length != 0) {
        unsigned char tail = (unsigned char)text[length - 1U];
        if (tail != '\n' && tail != '\r') break;
        --length;
    }
    if (length != 0) {
        volatile DeviceLogHistory *history = DEVICE_LOG_HISTORY;
        if (control_pc_has_sent_frame() == 0) {
            unsigned int copy_slot = history->next;
            unsigned char *destination = (unsigned char *)((unsigned int)history +
                                                            52U + copy_slot * 160U);
            memcpy(destination,text,length);
            unsigned int slot = history->next;
            unsigned int next = (slot + 1U) % 24U;
            unsigned char count = history->count;
            history->next = (unsigned char)next;
            volatile unsigned short *stored_length =
                (volatile unsigned short *)((unsigned int)history + 4U + slot * 2U);
            *stored_length = (unsigned short)length;
            if (count < 24) history->count = (unsigned char)(count + 1U);
        } else {
            if (history->flushed == 0) {
                unsigned int next = history->next;
                unsigned int count = history->count;
                int oldest_signed = ((int)next + 24 - (int)count) % 24;
                history->flushed = 1;
                if (count != 0) {
                    unsigned int oldest = (unsigned char)oldest_signed;
                    unsigned int ordinal = 0;
                    do {
                        unsigned int slot = (oldest + ordinal) % 24U;
                        unsigned int stored_length = history->lengths[slot];
                        control_log_emit((const unsigned char *)history->text[slot],
                                                (int)stored_length);
                        ++ordinal;
                    } while ((ordinal & 255U) < history->count);
                }
            }
            control_log_emit((const unsigned char *)text,(int)length);
        }
    }
    memw();
    DEVICE_LOG_BUSY = 0;
    return (int)length;
}
