/* Device primary baseline capture request and acceptance. */

#include "../include/types.h"

/* Native entry: 0x42038ad8. */
/* Original function-byte SHA-256:
 * b3fba9fc20d9508b858d3c757857ed0f6299ad3fe72e3efc5b91f032fcafbbcc. */
/* Return1 and supply primary interface ID, report ID and expected length only
 * when capture is eligible. Take optional initial rewrite mutex indefinitely;
 * when taken, reload its release handle BEFORE testing primary enabled BYTE.
 * With no initial mutex retain NULL for release, even if one appears later.
 * Require enabled!=0, saved signed interface>=0, MEMW/updated BYTE0, nonnull
 * current layout, layout baseline-block BYTE0 and MEMW/identity-loaded BYTE0.
 * No expected-length cap, upper interface bound or output-pointer check.
 * Store interface ID using SAVED interface, then RELOAD layout pointer before
 * reading/storing report ID, then read/store LIVE expected-length HALFWORD.
 * Outputs may alias shared storage and change those later reads; no recheck.
 * Release the earlier saved nonnull handle on success or rejection; ignore
 * all queue results. Return0 with no output stores on rejected gates. */
int profile_request_baseline(unsigned char *interface_out,
    unsigned char *report_id_out,unsigned short *length_out)
{
    RtosQueue *mutex = REWRITE_MUTEX;
    if (mutex != NULL) {
        xQueueSemaphoreTake(mutex,0xffffffffU);
        mutex = REWRITE_MUTEX;
    }
    volatile FixedInputBinding *primary = FIXED_INPUTS;
    int result = 0;
    if (primary->enabled == 0)
        goto release_mutex;
    int interface = primary->interface;
    if (interface < 0)
        goto release_mutex;
    memw();
    if (primary->updated != 0)
        goto release_mutex;
    const volatile HidReportLayout *layout = primary->state.hid_layout;
    if (layout == NULL || layout->baseline_capture_blocked != 0)
        goto release_mutex;
    memw();
    if (INPUT_IDENTITY_LOADED != 0)
        goto release_mutex;
    *(volatile unsigned char *)interface_out = REPORT_CAPTURE_INTERFACE_IDS[interface];
    layout = primary->state.hid_layout;
    *(volatile unsigned char *)report_id_out = layout->report_id;
    *(volatile unsigned short *)length_out = primary->expected_length;
    result = 1;
release_mutex:
    if (mutex != NULL)
        xQueueGenericSend(mutex,NULL,0,0);
    return result;
}

/* Native entry: 0x42038b90. */
/* Original function-byte SHA-256:
 * 0ed2e83f57189a9d46aa47274a34a35614639ac37c9de09a4507686826f13b63. */
/* MEMW/read active identity[1] HALFWORD, then MEMW/read identity[0]. If either
 * is nonzero call profile-capture lookup with those TWO saved arguments in
 * that order; raw Ghidra omitted them. Otherwise use0. MEMW/store its result
 * to identity-loaded BYTE. No local mutex, output/report change or NVS write. */
void profile_refresh_capture_flag(void)
{
    memw();
    unsigned short identity_first = INPUT_ACTIVE_IDENTITY[1];
    memw();
    unsigned short identity_second = INPUT_ACTIVE_IDENTITY[0];
    unsigned char loaded = 0;
    if ((identity_first | identity_second) != 0)
        loaded = profile_capture_is_stored(identity_first,identity_second);
    memw();
    INPUT_IDENTITY_LOADED = loaded;
}

/* Native entry: 0x42038bc4. */
/* Original function-byte SHA-256:
 * 934e9ccf0fb43a76ea749c446d18279885b81d81c1b03e5bc836d072ec8bdcf2. */
/* Handle capture response action BYTE and16-bit payload length. Action255
 * returns untouched. Any OTHER nonzero action first MEMW/stores loaded1,
 * MEMW/reads identity[1], MEMW/stores pending[1], then repeats for identity[0]
 * and pending[0], finally MEMW/stores pending1. No mutex or payload read here.
 *
 * Action0 requires primary enabled BYTE EXACTLY1 and payload nonnull before
 * optional rewrite-mutex take. Only a taken mutex triggers an enabled!=0
 * recheck. Snapshot layout WORD then expected-length HALFWORD, fence/read
 * updated BYTE0, and require layout plus expected length1..64. With report ID0
 * require full length; with nonzero ID accept full length with matching leading
 * ID or length(expected-1) and prepend it. Copy to64-byte local scratch.
 * Clear descriptor numeric fields through the reviewed helper, then clear
 * each button bit. Read button offset HALFWORD afresh per iteration; narrow
 * offset+index to16 bits. Reload button-count BYTE only after an in-bounds
 * byte update; out-of-bounds bits retain the saved count. Compare LOW8(index).
 * Copy expected bytes to primary last-input, MEMW/store valid1, MEMW/store
 * updated1. Always reload/release current optional mutex at the locked/common
 * exit, even when no mutex was initially taken. Ignore take/give results.
 * No flash write, USB submit, extra payload bound or whole-tail clear. */
void profile_accept_baseline(unsigned char action,const unsigned char *payload,
    unsigned short length)
{
    if (action != 0) {
        if (action == 255)
            return;
        memw();
        INPUT_IDENTITY_LOADED = 1;
        memw();
        unsigned short identity = INPUT_ACTIVE_IDENTITY[1];
        memw();
        INPUT_PENDING_IDENTITY[1] = identity;
        memw();
        identity = INPUT_ACTIVE_IDENTITY[0];
        memw();
        INPUT_PENDING_IDENTITY[0] = identity;
        memw();
        INPUT_IDENTITY_PENDING = 1;
        return;
    }
    volatile FixedInputBinding *primary = FIXED_INPUTS;
    if (primary->enabled != 1 || payload == NULL)
        return;
    RtosQueue *mutex = REWRITE_MUTEX;
    if (mutex != NULL) {
        xQueueSemaphoreTake(mutex,0xffffffffU);
        if (primary->enabled == 0)
            goto release_mutex;
    }
    const volatile HidReportLayout *layout = primary->state.hid_layout;
    unsigned int expected = primary->expected_length;
    memw();
    if (primary->updated != 0)
        goto release_mutex;
    unsigned int without_id = (expected - 1U) & 65535U;
    if (layout == NULL || without_id > 63)
        goto release_mutex;
    unsigned char report_id = layout->report_id;
    unsigned char scratch[64];
    if (report_id == 0) {
        if (length != expected)
            goto release_mutex;
        memcpy(scratch,payload,expected);
    } else if (length == expected) {
        if (*(const volatile unsigned char *)payload != report_id)
            goto release_mutex;
        memcpy(scratch,payload,expected);
    } else {
        if (length != without_id)
            goto release_mutex;
        scratch[0] = report_id;
        memcpy(scratch + 1,payload,without_id);
    }
    report_clear_layout_bits((const BitClearLayout *)layout,scratch,expected);
    unsigned int button_count = layout->button_count;
    if (button_count != 0) {
        unsigned int index = 0;
        do {
            unsigned int bit = (layout->button_bit_offset + index) & 65535U;
            unsigned int byte = bit >> 3;
            ++index;
            if (byte < expected) {
                unsigned char original = ((volatile unsigned char *)scratch)[byte];
                ((volatile unsigned char *)scratch)[byte] =
                    (unsigned char)(original ^ (original & (1U << (bit & 7U))));
                button_count = layout->button_count;
            }
        } while ((index & 255U) < button_count);
    }
    memcpy((void *)primary->last_input,scratch,expected);
    memw();
    primary->last_input_valid = 1;
    memw();
    primary->updated = 1;
release_mutex:
    mutex = REWRITE_MUTEX;
    if (mutex != NULL)
        xQueueGenericSend(mutex,NULL,0,0);
}
