/* Medius v3.4.7 device — Device-status filtering policy. */
#include "../include/types.h"

/* Native entry: 0x40395b68. */
/* Original function-byte SHA-256:
 * 6a3c2102377b1ecc4ce97f10e09bf7ca84d74687a89b51b3080a54fd514bd97e. */
/*
 * Filter an EP0 GET_STATUS value. bus is ignored; status contributes low16.
 * Read remote-wakeup mode BYTE then device-status-override mode BYTE. Preserve
 * original bit1 unless wake mode==2. Override mode1 loads a fresh HALFWORD and
 * replaces every other status bit with that value, always excluding its bit1.
 * Return the resulting zero-extended16-bit status WORD. No lock, state mutation,
 * live device query or masking of any other reserved status bits occurs.
 */
unsigned int medius_ep0_filter_device_status(unsigned int bus, unsigned short status)
{
    (void)bus;
    unsigned int wake_mode = MEDIUS_EP0_REQUEST_POLICY->remote_wakeup_status_mode;
    unsigned int override_mode = MEDIUS_EP0_REQUEST_POLICY->device_status_override_mode;
    unsigned int wake_bit = wake_mode == 2 ? 0 : status & 2U;
    unsigned int selected = status;
    if (override_mode == 1)
        selected = MEDIUS_EP0_DEVICE_STATUS_OVERRIDE;
    return wake_bit | (selected & 0xfffdU);
}
