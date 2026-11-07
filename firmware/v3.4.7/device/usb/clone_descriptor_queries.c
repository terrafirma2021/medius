/* Medius v3.4.7 device — clone descriptor selection and validation. */
#include "../include/types.h"

/* Native entry: 0x403967e4. */
/* Original function-byte SHA-256:
 * 37971f730ab8aaf5674ddd9839a6b419c96eff797fce9a690fcc7a5ad26f88c3. */
/* Read the raw attached BYTE after one MEMW; no normalization or lock. */
unsigned char medius_clone_get_attached(void)
{
    memw();
    return CLONE_ACTIVE;
}

/* Native entry: 0x403967f8. */
/* Original function-byte SHA-256:
 * eff534562c5848ad3319e8f7b34f06b4f8a97e2aaf0702922ae2d7a11dcedcba. */
/* After MEMW, test the raw attachment byte. Detached or configuration length
 * <8 returns 0 without reading the descriptor pointer. Otherwise read byte 7
 * of the selected configuration and return bmAttributes bit 5 (remote wakeup).
 * No descriptor type/declared-length/pointer validation or second MEMW. */
unsigned char medius_clone_configuration_has_remote_wakeup(void)
{
    memw();
    unsigned char attached = CLONE_ACTIVE;
    if (attached == 0) return 0;
    unsigned short length = QUERY_CONFIGURATION_LENGTH;
    if (length < 8) return 0;
    const volatile unsigned char *configuration = QUERY_CONFIGURATION;
    return (configuration[7] >> 5) & 1U;
}

/* Native entry: 0x40396824. */
/* Original function-byte SHA-256:
 * 3004414889c5a2c7c4388b0f7cb29be15752274af0c7ab2ed29fb448c5d0080e. */
/* Zero configuration is accepted without a directory lookup. The initial raw
 * result is (value==0) | (attached^1), truncated to a BYTE after MEMW; unusual
 * attached values are not normalized. Only a zero initial result scans.
 * Capture the directory count once; test each 16-bit stored length >=6 before
 * loading its 16-bit pool offset and bConfigurationValue at pool+offset+5.
 * First match returns 1, otherwise the initial 0. No table-count cap, descriptor
 * bounds/type validation, MEMW inside the loop, state update or lock. */
unsigned char medius_clone_configuration_value_exists(unsigned char value)
{
    memw();
    unsigned char attached = CLONE_ACTIVE;
    unsigned char accepted = (unsigned char)((value == 0) | (attached ^ 1U));
    if (accepted != 0) return accepted;
    unsigned char count = MEDIUS_CLONE_CONFIGURATION_COUNT;
    for (unsigned int i = 0; i < count; ++i) {
        unsigned short length = MEDIUS_CLONE_CONFIGURATION_LENGTHS[i];
        if (length >= 6U) {
            unsigned short offset = MEDIUS_CLONE_CONFIGURATION_OFFSETS[i];
            if (MEDIUS_CLONE_CONFIGURATION_POOL[(unsigned int)offset + 5U] == value)
                return 1;
        }
    }
    return accepted;
}

/* Native entry: 0x40396adc. */
/* Original function-byte SHA-256:
 * 5bb4c14e73d1a09a2bf217d03c9b10b1ad4d7ce89e16b2387a2fbbaaa6ce07e1. */
/* Test an endpoint against interfaces' currently selected alternate settings.
 * MEMW then read the raw attached BYTE. Detached returns 0; endpoint low7==0
 * returns that raw BYTE (including endpoint 0x80 and non-boolean attachment).
 * Otherwise capture the configuration length and pointer once. Walk descriptors
 * with a 16-bit wrapping cursor, reading length/type before validating length
 * >=2 and record end <= captured total. A valid interface descriptor (type4,
 * length>=9) replaces the active-interface predicate by alternate[interface]
 * == descriptor alternate. Other records leave the predicate unchanged.
 * A type5/length>=7 endpoint descriptor under a matching interface returns 1
 * only for an exact endpoint address, including direction. End/malformed input
 * returns 0. No interface-index clamp, endpoint-type check, lock or extra MEMW.
 */
unsigned char medius_clone_endpoint_is_in_active_alternate(unsigned char endpoint)
{
    memw();
    unsigned char attached = CLONE_ACTIVE;
    if (attached == 0 || (endpoint & 0x7fU) == 0) return attached;
    unsigned short total = QUERY_CONFIGURATION_LENGTH;
    if (total < 2U) return 0;
    const volatile unsigned char *configuration = QUERY_CONFIGURATION;
    unsigned int offset = 0;
    unsigned char active_interface = 0;
    do {
        const volatile unsigned char *descriptor = configuration + offset;
        unsigned char length = descriptor[0];
        unsigned char type = descriptor[1];
        if (length < 2U || offset + length > total) return 0;
        if (type == 4 && length >= 9U) {
            unsigned char interface = descriptor[2];
            unsigned char alternate = descriptor[3];
            active_interface = CLONE_ALTERNATE_SETTINGS[interface] == alternate;
        } else if (type == 5 && length >= 7U && active_interface != 0) {
            if (descriptor[2] == endpoint) return active_interface;
        }
        offset = (unsigned short)(offset + length);
    } while (offset + 1U < total);
    return 0;
}

/* Native entry: 0x40396bc8. */
/* Original function-byte SHA-256:
 * b23f9bdf76d4dde52774883069a20eac668ca0b778a9d54de560a0f7b0e12fd9. */
/* Detached exposes one fallback configuration. Attached reads the stored raw
 * count BYTE (possibly 0), after a single MEMW before the attachment read.
 * No count normalization, directory scan or additional memory barrier. */
unsigned char medius_clone_get_configuration_count(void)
{
    memw();
    return CLONE_ACTIVE != 0 ? MEDIUS_CLONE_CONFIGURATION_COUNT : 1;
}

/* Native entry: 0x403967c4. */
/* Original function-byte SHA-256:
 * 82afbc225539ec600749e3e4a1cb91fc997e563caa8277dead432186136a8790. */
/* Publish the raw descriptor-selection mode BYTE, then index BYTE, with a
 * MEMW before each store. Modes consumed by the pointer getter are 1:first
 * pool descriptor and 2:indexed pool descriptor; others use the current clone.
 * No mode/index validation or atomic pair publication; both bytes are stored
 * even when the selected mode does not use index. */
void medius_clone_set_descriptor_selection(unsigned char mode, unsigned char index)
{
    memw();
    MEDIUS_CLONE_DESCRIPTOR_SELECTION->mode = mode;
    memw();
    MEDIUS_CLONE_DESCRIPTOR_SELECTION->index = index;
}

/* Native entry: 0x40393150. */
/* Original function-byte SHA-256:
 * fcecd683485d8ae8cb83e0297838d75636a7c2e444265d2e34cd7fe7428140f9. */
/* MEMW/read mode once. Mode1 returns the first pool descriptor without
 * reading index/count/current pointer. Mode2 MEMW/reads index, then count; if
 * index<count, MEMW/reads index AGAIN and returns pool+offsets[fresh_index].
 * The second index is not revalidated, preserving the possible mixed-state
 * observation. Other modes or failed admission load the current configuration
 * pointer. No NULL, offset/length/type validation, normalization or lock. */
const unsigned char *medius_clone_selected_configuration_descriptor(void)
{
    memw();
    unsigned char mode = MEDIUS_CLONE_DESCRIPTOR_SELECTION->mode;
    if (mode == 1) return (const unsigned char *)MEDIUS_CLONE_CONFIGURATION_POOL;
    if (mode == 2) {
        memw();
        unsigned char index = MEDIUS_CLONE_DESCRIPTOR_SELECTION->index;
        unsigned char count = MEDIUS_CLONE_CONFIGURATION_COUNT;
        if (index < count) {
            memw();
            unsigned char fresh_index = MEDIUS_CLONE_DESCRIPTOR_SELECTION->index;
            unsigned short offset = MEDIUS_CLONE_CONFIGURATION_OFFSETS[fresh_index];
            return (const unsigned char *)(MEDIUS_CLONE_CONFIGURATION_POOL + offset);
        }
    }
    return QUERY_CONFIGURATION;
}
