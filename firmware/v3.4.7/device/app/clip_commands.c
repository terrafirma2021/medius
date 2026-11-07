/* Device clip append, control and settings commands. */
#include "../include/types.h"

/* CLIP command reconstruction utilities: repeated inline fault handling,
 * not an additional native entry. Snapshot write_cursor and applied before
 * the active-store fence; restore transforms before clearing their flag.
 */
static __attribute__((always_inline)) inline void clip_append_fault(
    volatile unsigned short *counter)
{
    unsigned int failures = *counter;
    *counter = (unsigned short)(failures + 1U);
    PLAYBACK_MODE = 3;
    unsigned int write_cursor = IMPERFECT_CLIP_QUEUE->write_cursor;
    unsigned int applied = PLAYBACK_TRANSFORMS.applied;
    memw();
    PLAYBACK_ACTIVE = 0;
    IMPERFECT_CLIP_QUEUE->read_cursor = write_cursor;
    IMPERFECT_CLIP_QUEUE->pending_count = 0;
    if (applied != 0) {
        playback_restore_transforms();
        PLAYBACK_TRANSFORMS.applied = 0;
    }
    playback_release_controls();
}

/* Native entry: 0x4203681c. */
/* Original function-byte SHA-256:
 * 3feb1396497a9618a7083ef0c70eeea1ff7a07693d408d1287f500a84623cd46. */
/*
 * Append CLIP bytes, requiring non-NULL bytes and fenced clone state exactly1.
 * length is truncated to16 bits and sequence to8 at the native entry. Take the
 * optional rewrite mutex indefinitely, ignoring acquisition status. A retained
 * finalized ring skips sequence checks, writes and counters, but still unlocks.
 * The first admitted append starts sequence tracking without comparing it.
 * Later mismatches increment a wrapping16-bit counter and fault playback;
 * this DOES NOT reject the append. Publish next_sequence modulo256, then call
 * the ring append even for length0. A return below length faults again using
 * the separate short-write counter. Each fault sets mode3, clears active and
 * pending control transfers, restores applied transforms and releases controls.
 * Neither fault clears the byte ring or sequence-valid flag. Reload the mutex
 * for give; it can differ from the acquired pointer. No send/wake or error
 * return, NULL-buffer exception for length0, or lock-acquisition check is added.
 */
void clip_append(const unsigned char *bytes,unsigned short length,
    unsigned char sequence)
{
    memw();
    unsigned int clone_state = CLONE_ACTIVE;
    if (bytes == NULL || clone_state != 1)
        return;
    RtosQueue *mutex = REWRITE_MUTEX;
    if (mutex != NULL)
        (void)xQueueSemaphoreTake(mutex,0xffffffffU);
    if (PLAYBACK_TRANSFORMS.retain == 0 ||
        clip_ring_is_finalized(PLAYBACK_RING) == 0) {
        if (CLIP_APPEND_SEQUENCE_VALID == 0)
            CLIP_APPEND_SEQUENCE_VALID = 1;
        else if (CLIP_APPEND_NEXT_SEQUENCE != sequence)
            clip_append_fault(&CLIP_APPEND_SEQUENCE_ERRORS);
        CLIP_APPEND_NEXT_SEQUENCE = (unsigned char)(sequence + 1U);
        unsigned int appended = clip_ring_append(PLAYBACK_RING,
            bytes,length);
        if (appended < length)
            clip_append_fault(&CLIP_APPEND_SHORT_WRITES);
    }
    mutex = REWRITE_MUTEX;
    if (mutex != NULL)
        (void)xQueueGenericSend(mutex,NULL,0,0);
}

/* Native entry: 0x4203691c. */
/* Original function-byte SHA-256:
 * 425be82dc301d74c941ca33b776244acad4ac5758226f793d5975cd23a5faf80. */
/*
 * Apply an8-bit CLIP control operation when fenced clone state is nonzero.
 * Optional mutex acquisition usesUINT32_MAX ticks; its return is ignored. Operation6
 * clears pending control count, aligns read_cursor to write_cursor, resets
 * mode/progress/status, fences and clears active then sequence-valid, clears
 * the playback ring, restores applied transforms and releases controls.
 * Operation7 finalizes only a retained ring. Other byte values are passed
 * unchanged to the reviewed playback action dispatcher, including unknown IDs.
 * Fence/read active BEFORE reloading and giving the optional mutex. Use that
 * cached active byte afterward: nonzero ensures the timer is armed, zero calls
 * input_service_after_change(1). No new clone-state check or lock-failure exit.
 */
void clip_control(unsigned char operation)
{
    memw();
    if (CLONE_ACTIVE == 0)
        return;
    RtosQueue *mutex = REWRITE_MUTEX;
    if (mutex != NULL)
        (void)xQueueSemaphoreTake(mutex,0xffffffffU);
    if (operation == 6) {
        unsigned int write_cursor = IMPERFECT_CLIP_QUEUE->write_cursor;
        IMPERFECT_CLIP_QUEUE->pending_count = 0;
        IMPERFECT_CLIP_QUEUE->read_cursor = write_cursor;
        PLAYBACK_MODE = 0;
        PLAYBACK_PROGRESS = 0;
        PLAYBACK_STATUS = 0;
        memw();
        PLAYBACK_ACTIVE = 0;
        CLIP_APPEND_SEQUENCE_VALID = 0;
        clip_ring_clear(PLAYBACK_RING);
        if (PLAYBACK_TRANSFORMS.applied != 0) {
            playback_restore_transforms();
            PLAYBACK_TRANSFORMS.applied = 0;
        }
        playback_release_controls();
    } else if (operation == 7) {
        if (PLAYBACK_TRANSFORMS.retain != 0)
            clip_ring_finalize(PLAYBACK_RING);
    } else {
        (void)playback_apply_action(operation);
    }
    memw();
    unsigned int active = PLAYBACK_ACTIVE;
    mutex = REWRITE_MUTEX;
    if (mutex != NULL)
        (void)xQueueGenericSend(mutex,NULL,0,0);
    if (active != 0)
        input_ensure_timer_armed();
    else
        input_service_after_change(1);
}

/* Native entry: 0x420369dc. */
/* Original function-byte SHA-256:
 * 6b491ff348e457ec90808dd0f68504934a24cf041aea71ba2b1f7131818d0a44. */
/*
 * Set byte-valued CLIP options without requiring an active clone. IDs0/1/2/3
 * select low5 auto-lock bits, boolean repeat, boolean retention and boolean
 * timed motion (riding); ignore other IDs. Retention changes only when the
 * retained-byte helper returns0, even if the requested value is unchanged.
 * An initially non-NULL mutex is taken withUINT32_MAX ticks; status is ignored. For
 * each resulting setting write, reload the mutex BEFORE storing the byte and
 * give that cached pointer afterward if non-NULL. Initially NULL mutex paths
 * for IDs other than2 perform the write/ignore and return without a reload;
 * ID2 always calls the helper then reloads the mutex, including when no change
 * is permitted. No timer scheduling, configuration persistence or new fence.
 */
void clip_set(unsigned char setting,unsigned char value)
{
    RtosQueue *mutex = REWRITE_MUTEX;
    if (mutex == NULL && setting != 2) {
        switch (setting) {
        case 0: PLAYBACK_TRANSFORMS.selection = value & 0x1fU; break;
        case 1: PLAYBACK_TRANSFORMS.repeat = value != 0; break;
        case 3: PLAYBACK_TRANSFORMS.timed_motion = value != 0; break;
        default: break;
        }
        return;
    }
    if (mutex != NULL)
        (void)xQueueSemaphoreTake(mutex,0xffffffffU);
    switch (setting) {
    case 0:
        mutex = REWRITE_MUTEX;
        PLAYBACK_TRANSFORMS.selection = value & 0x1fU;
        break;
    case 1:
        mutex = REWRITE_MUTEX;
        PLAYBACK_TRANSFORMS.repeat = value != 0;
        break;
    case 2: {
        unsigned int retained = clip_ring_retained_bytes(PLAYBACK_RING);
        mutex = REWRITE_MUTEX;
        if (retained == 0)
            PLAYBACK_TRANSFORMS.retain = value != 0;
        break;
    }
    case 3:
        mutex = REWRITE_MUTEX;
        PLAYBACK_TRANSFORMS.timed_motion = value != 0;
        break;
    default:
        mutex = REWRITE_MUTEX;
        break;
    }
    if (mutex != NULL)
        (void)xQueueGenericSend(mutex,NULL,0,0);
}
