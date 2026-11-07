/* Device playback action dispatch. */

#include "../include/types.h"

/* Native entry: 0x4202a9ac. */
/* Original function-byte SHA-256:
 * 36714ef0b7b0bea6d93aba9f9c69de52b7d537e6ddab7214843c4329bc1d9298. */
/*
 * Dispatch the full 32-bit action: 0 starts/resumes, 1 stops and discards
 * pending controls, 2 pauses mode 1, 3 resumes mode 2, 4 restarts, and
 * 5 toggles (stop mode 1, resume mode 2, otherwise start). Other values do nothing.
 *
 * Pause clears active after MEMW, then sets mode 2. Resume sets mode 1,
 * then MEMW/active 1, reads the clock and stores timestamp low/high words.
 * Other paths leave timestamp updates to the called start/stop functions.
 *
 * Return 0 if the initially fenced active byte was nonzero. Otherwise
 * MEMW/read and return the resulting raw active byte, without normalizing it.
 * No local lock or timer rearm is added.
 */
unsigned int playback_apply_action(unsigned int action)
{
    memw();
    unsigned int was_active = PLAYBACK_ACTIVE;
    switch (action) {
    case 0:
        playback_start(0);
        break;
    case 1:
        playback_stop(1);
        break;
    case 2:
        if (PLAYBACK_MODE == 1) {
            memw();
            PLAYBACK_ACTIVE = 0;
            PLAYBACK_MODE = 2;
        }
        break;
    case 3:
        if (PLAYBACK_MODE != 2)
            break;
        goto resume;
    case 4:
        playback_start(1);
        break;
    case 5: {
        unsigned int mode = PLAYBACK_MODE;
        if (mode == 1) {
            playback_stop(1);
            break;
        }
        if (mode != 2) {
            playback_start(0);
            break;
        }
resume:
        PLAYBACK_MODE = 1;
        memw();
        PLAYBACK_ACTIVE = 1;
        unsigned long long now = (unsigned long long)esp_timer_get_time();
        PLAYBACK_TIME.low = (unsigned int)now;
        PLAYBACK_TIME.high = (unsigned int)(now >> 32);
        break;
    }
    default:
        break;
    }
    if (was_active != 0)
        return 0;
    memw();
    return PLAYBACK_ACTIVE;
}
