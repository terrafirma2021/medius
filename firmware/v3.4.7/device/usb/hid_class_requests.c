/* Medius v3.4.7 device — default HID class requests. */
#include "../include/types.h"

/* Native entry: 0x4200d128. */
/* Original function-byte SHA-256:
 * a9e75e421454a8cf899c1146b59defe27d296ff4cfdd3116898bf0e7338d950c. */
/* Dispatch HID class request IDs 1/2/3/9/10/11 to the native default hooks.
 * Read request BYTE then low interface-index BYTE even for unsupported IDs;
 * bus is narrowed to its low BYTE. Do not inspect direction, recipient, high
 * interface index or SETUP length. GET_REPORT passes output pointers; GET_IDLE
 * and GET_PROTOCOL cache *data before their hook and publish result BYTE then
 * length WORD 1. SET_REPORT reads *length before *data, then report-type and
 * report-ID BYTEs. Other report requests read high value before low value.
 * Supported IDs return 0 regardless of the hook's effect; others return
 * UINT_MAX without changing outputs. No validation, lock or fence is added.
 */
unsigned int medius_hid_dispatch_class_request(unsigned char bus,
    const MediusUsbSetupPacket *setup, unsigned char **data, unsigned int *length)
{
    const volatile unsigned char *request = (const volatile unsigned char *)setup;
    unsigned int code = request[1];
    unsigned char interface = request[4];
    switch (code) {
    case 1: {
        unsigned char report_type = request[3];
        unsigned char report_id = request[2];
        medius_hid_default_get_report(bus, interface, report_id, report_type, data, length);
        break;
    }
    case 2: {
        unsigned char report_id = request[2];
        unsigned char *destination = *(unsigned char *volatile *)data;
        unsigned char idle = medius_hid_default_get_idle(bus, interface, report_id);
        *(volatile unsigned char *)destination = idle;
        *(volatile unsigned int *)length = 1;
        break;
    }
    case 3: {
        unsigned char *destination = *(unsigned char *volatile *)data;
        unsigned char protocol = medius_hid_default_get_protocol(bus, interface);
        *(volatile unsigned char *)destination = protocol;
        *(volatile unsigned int *)length = 1;
        break;
    }
    case 9: {
        unsigned int payload_length = *(const volatile unsigned int *)length;
        const unsigned char *payload = *(unsigned char *volatile *)data;
        unsigned char report_type = request[3];
        unsigned char report_id = request[2];
        medius_hid_default_set_report(bus, interface, report_id, report_type, payload, payload_length);
        break;
    }
    case 10: {
        unsigned char duration = request[3];
        unsigned char report_id = request[2];
        medius_hid_default_set_idle(bus, interface, report_id, duration);
        break;
    }
    case 11:
        medius_hid_default_set_protocol(bus, interface, request[2]);
        break;
    default:
        return 0xffffffffU;
    }
    return 0;
}

/* Native entry: 0x42021124. */
/* Original function-byte SHA-256:
 * 2dc77f43bf25d93b599e3aa15e30036209605c9f48baef63b90c1ad451181908. */
/* Default GET_REPORT ignores bus/interface/report selection, loads the caller's
 * output pointer, writes one zero BYTE, then stores length WORD 1. No buffer
 * capacity, pointer or SETUP-length check; no lock/fence or persistent state.
 */
void medius_hid_default_get_report(unsigned char bus, unsigned char interface,
    unsigned char report_id, unsigned char report_type,
    unsigned char **data, unsigned int *length)
{
    (void)bus; (void)interface; (void)report_id; (void)report_type;
    unsigned char *destination = *(unsigned char *volatile *)data;
    *(volatile unsigned char *)destination = 0;
    *(volatile unsigned int *)length = 1;
}

/* Native entry: 0x42021134. */
/* Original function-byte SHA-256:
 * 92c9598ac7519d458b9e367d0d7b28064c9bff38bae50b088825d1dda27f16a4. */
/* Default GET_IDLE ignores all selectors and returns a zero register value.
 * Does not read remembered idle duration or change any state.
 */
unsigned char medius_hid_default_get_idle(unsigned char bus,
    unsigned char interface, unsigned char report_id)
{
    (void)bus; (void)interface; (void)report_id;
    return 0;
}

/* Native entry: 0x4202113c. */
/* Original function-byte SHA-256:
 * 92c9598ac7519d458b9e367d0d7b28064c9bff38bae50b088825d1dda27f16a4. */
/* Default GET_PROTOCOL ignores bus/interface and returns zero (boot protocol).
 * No stored protocol is read; SET_PROTOCOL below does not retain its argument.
 */
unsigned char medius_hid_default_get_protocol(unsigned char bus, unsigned char interface)
{
    (void)bus; (void)interface;
    return 0;
}

/* Native entry: 0x42021144. */
/* Original function-byte SHA-256:
 * a50f595a12cc6e7e90d28fa2424790fbfac53a684610d6fe5637b2112f16f23d. */
/* Default SET_REPORT is an empty native body. Ignore selectors, borrowed bytes
 * and full-WORD length; do not validate/read/copy data or change outputs/state.
 */
void medius_hid_default_set_report(unsigned char bus, unsigned char interface,
    unsigned char report_id, unsigned char report_type,
    const unsigned char *payload, unsigned int length)
{
    (void)bus; (void)interface; (void)report_id; (void)report_type;
    (void)payload; (void)length;
}

/* Native entry: 0x4202114c. */
/* Original function-byte SHA-256:
 * a50f595a12cc6e7e90d28fa2424790fbfac53a684610d6fe5637b2112f16f23d. */
/* Default SET_IDLE is empty: no duration/report selection is remembered and
 * no timer is created, restarted or cancelled. All arguments are ignored.
 */
void medius_hid_default_set_idle(unsigned char bus, unsigned char interface,
    unsigned char report_id, unsigned char duration)
{
    (void)bus; (void)interface; (void)report_id; (void)duration;
}

/* Native entry: 0x42021154. */
/* Original function-byte SHA-256:
 * a50f595a12cc6e7e90d28fa2424790fbfac53a684610d6fe5637b2112f16f23d. */
/* Default SET_PROTOCOL is empty: protocol is neither checked nor retained.
 * The dispatcher reports success after this no-op. All arguments are ignored.
 */
void medius_hid_default_set_protocol(unsigned char bus,
    unsigned char interface, unsigned char protocol)
{
    (void)bus; (void)interface; (void)protocol;
}
