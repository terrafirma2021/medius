/* Device control-state publication and LED override expiry. */
#include "../include/types.h"

/* Native entry: 0x4200a718. */
/* Original function-byte SHA-256:
 * 5f03fe0ae1d86af834bdbc3d3208c2dfe8a6955e4df5d2e1ecea41d030371fdc. */
/* Publish raw BYTE host connectivity, then primary-interface selection, with
 * MEMW before each store. These are independent state updates, not normalized
 * booleans or an atomic pair. No lock, ownership change or return status. */
void control_publish_link_and_interface_state(unsigned char host_connected,
    unsigned char primary_interface_selected)
{
    memw();
    LED_CONTROL_FLAGS->host_connected=host_connected;
    memw();
    LED_CONTROL_FLAGS->primary_interface_selected=primary_interface_selected;
}

/* Native entry: 0x4200b4cc. */
/* Original function-byte SHA-256:
 * af70b54dacc4f4e19c2995bc9584203f60e07e0e35581f6f765a39088a254ee1. */
/* Service control-command LED override expiry using a split 64-bit uptime.
 * Under the control spinlock, MEMW/read device ownership, then host ownership
 * only if needed. With any owner, read last-command LOW then HIGH, each after
 * MEMW; with neither owner still read/discard HIGH then LOW before unlocking.
 * Discard lock status. If host_connected's raw BYTE is zero, release overrides
 * immediately and ignore its return. Otherwise release only when signed 64-bit
 * wrapping elapsed time is strictly greater than 1,000,000 us. Borrow and high
 * subtraction use native 32-bit wrapping arithmetic; a negative signed delta
 * does not expire. Only this timed path calls input-commit after a nonzero release BYTE.
 * No resampling, local flag clearing, timer guarantee or lock held across the
 * release/commit callbacks is supplied.
 *
 * now_low/now_high: caller's cached uptime bits, LOW then HIGH words in us.
 * host_connected: raw low byte; zero releases, any nonzero enables time testing.
 * Returns no status; it does not read a new clock sample or normalize inputs.
 */
void control_service_led_expiry(unsigned int now_low,unsigned int now_high,
    unsigned char host_connected)
{
    (void)xPortEnterCriticalTimeout(LED_CONTROL_LOCK,-1);
    memw();
    unsigned char owned=LED_CONTROL_FLAGS->device_override_owned;
    if (!owned) {
        memw();
        owned=LED_CONTROL_FLAGS->host_override_owned;
    }
    if (!owned) {
        memw();
        (void)CONTROL_LAST_COMMAND_US->high;
        memw();
        (void)CONTROL_LAST_COMMAND_US->low;
        vPortExitCritical(LED_CONTROL_LOCK);
        return;
    }
    memw();
    unsigned int last_low=CONTROL_LAST_COMMAND_US->low;
    memw();
    unsigned int last_high=CONTROL_LAST_COMMAND_US->high;
    vPortExitCritical(LED_CONTROL_LOCK);
    if (!host_connected) {
        (void)control_release_led_overrides();
        return;
    }
    unsigned int borrow=now_low<last_low;
    unsigned int elapsed_low=now_low-last_low;
    int elapsed_high=(int)(now_high-last_high-borrow);
    if (elapsed_high>0 || (elapsed_high==0 && elapsed_low>1000000U)) {
        if (control_release_led_overrides()!=0)
            input_commit_change();
    }
}
