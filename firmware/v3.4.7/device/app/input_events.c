/* Device control overrides and input-event publication records. */

#include "../include/types.h"

/* Native entry: 0x42026bf8. */
/* Original function-byte SHA-256:
 * 23fdf0ad71a458a974a247b1d7f0ed3c99c046261f52f192dfbff7b3c5b669ae. */
/* Update an eight-halfword usage set. enabled0 clears EVERY exact full-word
 * value match; nonzero first checks for an existing match,then fills the first
 * zero slot with LOW16(value). A full list silently rejects insertion. Value0
 * can match an empty slot; values>ffff never match existing halfwords but can
 * insert a truncated duplicate. Requires eight writable slots; no status,lock
 * or barrier. Comparison is intentionally not narrowed along with the store. */
void input_usage_set_update(unsigned short *slots,unsigned int value,int enabled)
{
    volatile unsigned short *entries = slots;
    if (enabled == 0) {
        for (unsigned int index = 0; index < 8; ++index)
            if (entries[index] == value)
                entries[index] = 0;
        return;
    }
    for (unsigned int index = 0; index < 8; ++index)
        if (entries[index] == value)
            return;
    for (unsigned int index = 0; index < 8; ++index) {
        if (entries[index] == 0) {
            entries[index] = (unsigned short)value;
            return;
        }
    }
}

/* Native entry: 0x42025d54. */
/* Original function-byte SHA-256:
 * 9e848db2e65af1f84147dc8088a2b26292935e66ace74008fca0696aa3a6f643. */
/* Apply override event: kind 0=button,1=key,2=consumer; action 0=release override,
 * 1=force on,2=force off. Preserve the old changed byte on invalid/no-op paths,
 * but transiently write 0 on EVERY entry. Accepted updates set changed=1 and,
 * when storage exists and active count < 16,append a 4-byte kind/action/value
 * record. Count is published BEFORE record header/value; no lock or barrier.
 * Full active storage drops that record while retaining the override update.
 *
 * Button index is LOW8(value),must be <= 15. Releases work without a layout;
 * force on/off additionally require index<button_count. Key admission tests
 * LOW16(value) in 4..255 and uses its low-byte bitmap address. Consumer value
 * is a full word and must be nonzero; list saturation may leave the masks
 * unchanged yet still produce a changed flag/record. Actions are full integers,
 * not normalized bytes. Caller supplies serialized writable state/storage. */
void input_apply_event(InputStateView *state,unsigned int kind,
    unsigned int value,int action)
{
    volatile InputStateView *input_state = state;
    unsigned char changed = input_state->changed;
    input_state->changed = 0;
    if (kind == 0) {
        unsigned int index = (unsigned char)value;
        if (index > 15)
            goto finish;
        if (action != 0) {
            const volatile HidReportLayout *layout = input_state->hid_layout;
            if (layout == NULL || index >= layout->button_count)
                goto finish;
        }
        unsigned int forced = input_state->forced_buttons;
        unsigned int cleared = input_state->cleared_buttons;
        unsigned int mask = 1U << index;
        if (action == 0) {
            if (((forced | cleared) & mask) == 0)
                goto finish;
            forced &= ~mask;
            cleared &= ~mask;
        } else if (action == 1) {
            if ((forced & mask) != 0 && (cleared & mask) == 0)
                goto finish;
            forced |= mask;
            cleared &= ~mask;
        } else if (action == 2) {
            if ((forced & mask) == 0 && (cleared & mask) != 0)
                goto finish;
            forced &= ~mask;
            cleared |= mask;
        } else {
            goto finish;
        }
        input_state->forced_buttons = (unsigned short)forced;
        input_state->cleared_buttons = (unsigned short)cleared;
    } else if (kind == 1) {
        if (((value - 4U) & 65535U) > 251U)
            goto finish;
        unsigned int byte = (value >> 3) & 31U,mask = 1U << (value & 7U);
        unsigned int forced = input_state->forced_keys[byte];
        unsigned int cleared = input_state->cleared_keys[byte];
        if (action == 0) {
            if (((forced | cleared) & mask) == 0)
                goto finish;
            input_state->forced_keys[byte] = (unsigned char)(forced & ~mask);
            input_state->cleared_keys[byte] &= (unsigned char)~mask;
        } else if (action == 1) {
            if ((forced & mask) != 0 && (cleared & mask) == 0)
                goto finish;
            input_state->forced_keys[byte] = (unsigned char)(forced | mask);
            input_state->cleared_keys[byte] &= (unsigned char)~mask;
        } else if (action == 2) {
            if ((forced & mask) == 0 && (cleared & mask) != 0)
                goto finish;
            input_state->forced_keys[byte] = (unsigned char)(forced & ~mask);
            input_state->cleared_keys[byte] |= (unsigned char)mask;
        } else {
            goto finish;
        }
    } else if (kind == 2) {
        if (value == 0)
            goto finish;
        unsigned int forced = 0,cleared = 0;
        for (unsigned int index = 0; index < 8; ++index) {
            if (input_state->forced_consumers[index] == value) {
                forced = 1;
                break;
            }
        }
        for (unsigned int index = 0; index < 8; ++index) {
            if (input_state->cleared_consumers[index] == value) {
                cleared = 1;
                break;
            }
        }
        if (action < 0 || action > 2)
            goto finish;
        unsigned int want_forced = action == 1,want_cleared = action == 2;
        if (forced == want_forced && cleared == want_cleared)
            goto finish;
        input_usage_set_update(state->forced_consumers,value,(int)want_forced);
        input_usage_set_update(state->cleared_consumers,value,(int)want_cleared);
    } else {
        goto finish;
    }
    volatile InputEventStorage *storage = input_state->event_storage;
    input_state->changed = 1;
    if (storage != NULL) {
        unsigned int count = input_state->active_event_count;
        if (count < 16) {
            input_state->active_event_count = (unsigned char)(count + 1);
            storage->active[count].header = (unsigned short)(kind | ((unsigned int)action << 8));
            storage->active[count].value = (unsigned short)value;
        }
    }
    changed = 1;
finish:
    input_state->changed = changed;
}

/* Native entry: 0x420264ac. */
/* Original function-byte SHA-256:
 * 5c9c380cca97729575e1ae2a5bfb1627ee9e5895c1c4c1da05fade49ecc25f4a. */
/* Admit an event immediately without storage,or with an empty backlog and an
 * open event gate. Otherwise queue LOW8(kind),LOW16(value),action. Full means
 * count==capacity EXACTLY: apply oldest first,then resample storage/capacity,
 * increment the fresh head and insert using the fresh count minus 1. Preserve
 * that sampled count as the final published count. Nonfull queues increment
 * count as a byte. Tail/head wrapping subtracts capacity once. The native zero
 * capacity fallback applies an old slot even when backlog count was zero; no
 * repair is added. Require valid serialized storage/cursors; no lock/fence.
 * Queue header/value are stored before the final queued-count publication. */
void input_enqueue_event(InputStateView *state,unsigned short kind,
    unsigned short value,unsigned char action)
{
    volatile InputStateView *input_state = state;
    volatile InputEventStorage *storage = input_state->event_storage;
    unsigned int event_kind = (unsigned char)kind;
    unsigned short header = (unsigned short)(event_kind | ((unsigned int)action << 8));
    if (storage == NULL) {
        input_apply_event(state,event_kind,value,action);
        return;
    }
    unsigned int count = input_state->queued_event_count;
    unsigned int capacity,head,final_count;
    if (count == 0) {
        if (input_event_would_block(state,event_kind,value) == 0) {
            input_apply_event(state,event_kind,value,action);
            return;
        }
        capacity = storage->capacity;
        head = input_state->queued_event_head;
        final_count = 1;
        if (capacity != 0)
            goto insert;
    } else {
        capacity = storage->capacity;
        head = input_state->queued_event_head;
        if (count != capacity) {
            final_count = (count + 1) & 255U;
            goto insert;
        }
    }
    {
        unsigned int slot = head < capacity ? head : head - capacity;
        const volatile InputEvent *old = &storage->queued[slot];
        unsigned int old_kind = old->kind;
        unsigned int old_action = old->action;
        unsigned int old_value = old->value;
        input_apply_event(state,old_kind,old_value,(int)old_action);
        storage = input_state->event_storage;
        unsigned int next = (unsigned int)input_state->queued_event_head + 1;
        capacity = storage->capacity;
        head = next & 255U;
        if (next >= capacity)
            head = (head - capacity) & 255U;
        final_count = input_state->queued_event_count;
        input_state->queued_event_head = (unsigned char)head;
        count = (final_count - 1) & 255U;
    }
insert:
    {
        unsigned int tail = head + count;
        volatile InputEvent *records = storage->queued;
        tail = tail < capacity ? (unsigned short)tail : tail - capacity;
        records[tail].header = header;
        records[tail].value = value;
        input_state->queued_event_count = (unsigned char)final_count;
    }
}

/* Native entry: 0x42026584. */
/* Original function-byte SHA-256:
 * f0afdd87590f27cbf317935293d092b656697f8c4c21062b870cd7c2fb3f8e4e. */
/* Update saved key (kind 1,value LOW16 in 4..255) or nonzero consumer (kind 2).
 * Compare the RAW LOW8(requested) with old presence before updating. Keys use
 * requested!=0 for the stored bit,so requested 2 can return 1 without changing
 * bytes. Consumers call the bounded set helper,then verify presence equals
 * requested exactly; nonboolean requests can mutate the list yet return 0.
 * Success sets changed=1 and returns 1; invalid/no-op/failure returns0 and leaves
 * changed alone. Consumer saturation is observed by the final presence scan.
 * No event record,local lock or barrier; caller supplies writable state. */
unsigned int input_update_saved_control(InputStateView *state,
    unsigned char kind,unsigned int value,unsigned int requested)
{
    volatile InputStateView *input_state = state;
    unsigned int usage = (unsigned short)value;
    unsigned int desired = (unsigned char)requested;
    if (kind == 1) {
        if (((usage - 4) & 65535U) > 251)
            return 0;
        unsigned int index = (usage >> 3) & 31U,mask = 1U << (usage & 7U);
        unsigned int old = input_state->saved_keys[index];
        if (((old >> (usage & 7U)) & 1U) == desired)
            return 0;
        input_state->saved_keys[index] = (unsigned char)(desired != 0 ? old | mask : old & ~mask);
    } else if (kind == 2 && usage != 0) {
        unsigned int present = 0;
        for (unsigned int index = 0; index < 8; ++index) {
            if (input_state->saved_consumers[index] == usage) {
                present = 1;
                break;
            }
        }
        if (present == desired)
            return 0;
        input_usage_set_update(state->saved_consumers,usage,(int)desired);
        present = 0;
        for (unsigned int index = 0; index < 8; ++index) {
            if (input_state->saved_consumers[index] == usage) {
                present = 1;
                break;
            }
        }
        if (present != desired)
            return 0;
    } else {
        return 0;
    }
    input_state->changed = 1;
    return 1;
}

/* Native entry: 0x42026648. */
/* Original function-byte SHA-256:
 * db6efee49366ac91e01ba4dda65b8befa42dad8100a32d2e851e8d0cb9ae5ef9. */
/* Scan saved key bytes,then consumer halfwords. If all zero return 0 without
 * stores;otherwise clear both complete arrays,set changed=1 and return 1.
 * No button/motion/event-cursor changes,lock or fence. */
unsigned int input_clear_saved_controls(InputStateView *state)
{
    volatile InputStateView *input_state = state;
    for (unsigned int index = 0; index < 32; ++index)
        if (input_state->saved_keys[index] != 0)
            goto clear;
    for (unsigned int index = 0; index < 8; ++index)
        if (input_state->saved_consumers[index] != 0)
            goto clear;
    return 0;
clear:
    memset(state->saved_keys,0,32);
    memset(state->saved_consumers,0,16);
    input_state->changed = 1;
    return 1;
}

/* Native entry: 0x42026988. */
/* Original function-byte SHA-256:
 * 3a018aa78ddc064b78af64059abfc408d59a5598479b266257e92358a14e566e. */
/* Fence/read dirty. Return0 if nonzero,otherwise whether the published
 * halfword is nonzero. This is a publication gate,not a queue-empty test.
 * No writes,lock or null check. */
unsigned int input_publication_is_blocked(const InputStateView *state)
{
    const volatile InputStateView *input_state = state;
    memw();
    if (input_state->dirty != 0)
        return 0;
    return input_state->publication_pair > 65535U;
}

/* Native entry: 0x42026c38. */
/* Original function-byte SHA-256:
 * 2cfd405d47da38d8369857c6e88435d41cbb1abfb7f72013b4947a5453066f08. */
/* Store event-storage pointer,clear queued count/head with one halfword,then
 * clear ONLY published-count byte and active-count byte,in that order. Preserve
 * blocked bytes,dirty/publication/changed flags and record contents. No fence,
 * allocation,ownership transfer or local lock; storage may be NULL. */
void input_bind_event_storage(InputStateView *state,InputEventStorage *storage)
{
    volatile InputStateView *input_state = state;
    input_state->event_storage = storage;
    input_state->queued_cursor = 0;
    input_state->published_event_count = 0;
    input_state->active_event_count = 0;
}

/* Native entry: 0x42026c50. */
/* Original function-byte SHA-256:
 * b8d9a5bd3aeb77c48a905301f5ffe705eea230300258aa041c75f81e277776a6. */
/* Return RAW changed byte if nonzero;otherwise queued_count!=0 as 0/1.
 * No dirty test,fence,mutation or local lock. */
unsigned char input_has_pending_work(const InputStateView *state)
{
    const volatile InputStateView *input_state = state;
    unsigned char changed = input_state->changed;
    if (changed == 0 && input_state->queued_event_count != 0)
        changed = 1;
    return changed;
}

/* Native entry: 0x42026c68. */
/* Original function-byte SHA-256:
 * 57176d741e1456aa8321ddbdbb4704b3ed434210cf4cf0e6696d7b307a15633a. */
/* Return RAW changed byte if nonzero. Otherwise return 0 for empty backlog,
 * or fence/read and return the RAW dirty byte. No writes or local lock. */
unsigned char input_needs_service(const InputStateView *state)
{
    const volatile InputStateView *input_state = state;
    unsigned char changed = input_state->changed;
    if (changed == 0 && input_state->queued_event_count != 0) {
        memw();
        changed = input_state->dirty;
    }
    return changed;
}

/* Native entry: 0x42026c84. */
/* Original function-byte SHA-256:
 * 37305f136c48ed877c9e63f96d91e97fa6f325440321dff9c2229d29d99b0bd5. */
/* Read BOTH forced/cleared button halfwords,return their OR != 0 as 0/1.
 * No fence,write,null check or local lock. */
unsigned int input_has_button_overrides(const InputStateView *state)
{
    const volatile InputStateView *input_state = state;
    unsigned int forced = input_state->forced_buttons;
    unsigned int cleared = input_state->cleared_buttons;
    return (forced | cleared) != 0;
}

/* Native entry: 0x42026c9c. */
/* Original function-byte SHA-256:
 * 5c84a8862ca4793872fec726098cfe59c81e10c2e60dcdf69a2aea1a3037ef7c. */
/* Return raw forced-buttons halfword; no clear-mask test,fence,write or lock. */
unsigned short input_forced_buttons(const InputStateView *state)
{
    return ((const volatile InputStateView *)state)->forced_buttons;
}
