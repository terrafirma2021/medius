/* Device configured and factory-derived identity. */
#include "../include/types.h"

/* Native entry: 0x42035ca0. */
/* Original function-byte SHA-256:
 * 70028829a3ad28fda01388298cc4fa574c6264a012efb1b83e154affc026e9bb. */
/* Initialize the shared input/rewrite mutex, profiles and device identity.
 * Create a queue-type1 mutex only if its current handle is NULL; store even a
 * NULL allocation result without retry or abort. The specialized RTOS callee
 * ignores that incoming type. Initialize profile storage, then load setting
 * key "oa" into the 33-byte configured box-name buffer, ignoring load status.
 *
 * Clear a six-byte stack MAC with WORD then HALFWORD stores and request the
 * default factory address. Ignore its status. Format the 33-byte default-name
 * buffer as "Medius-%02X%02X" from bytes4 and5, sampling byte5 before byte4.
 * This does not overwrite the
 * separately loaded configured name. A read failure can leave zero or partially
 * read suffix bytes. Re-entry always reloads profiles/name and rebuilds the
 * default; no lock prevents concurrent initialization. Formatting status is
 * ignored. The factory read can retry indefinitely on burn-counter changes.
 */
void identity_initialize(void)
{
    if (REWRITE_MUTEX == NULL)
        REWRITE_MUTEX = identity_create_mutex(1);
    profile_storage_initialize();
    (void)settings_load_string("oa",BOX_NAME,33);
    unsigned char mac[6] __attribute__((aligned(4)));
    *(volatile unsigned int *)&mac[0] = 0;
    *(volatile unsigned short *)&mac[4] = 0;
    (void)esp_efuse_mac_get_default(mac);
    unsigned int last_mac_byte = ((const volatile unsigned char *)mac)[5];
    unsigned int preceding_mac_byte = ((const volatile unsigned char *)mac)[4];
    (void)newlib_snprintf((char *)BOX_DEFAULT_NAME,33,
        "Medius-%02X%02X",preceding_mac_byte,last_mac_byte);
}

/* Native entry: 0x4200c8b4. */
/* Original function-byte SHA-256:
 * e5a2c788f787065e6aa0599f47d9dae0ea1aa35cab0f2451b1afe873bb63703a. */
/* Return the cached 32-byte firmware version string. A nonzero first BYTE skips
 * formatting. Otherwise obtain the app description, sample ELF SHA bytes in
 * native order 1,0,3,2, then format at most 15 version characters plus '+' and
 * four lowercase two-digit hex bytes. The firmware's suffix literal is empty.
 * Capacity 32 includes NUL; snprintf status is ignored. Return the buffer pointer
 * on both paths (the original decompiler's void return was wrong). No lock,
 * metadata validation, reinitialization or partial-publication protection. */
const char *device_version_string(void)
{
    char *buffer=DEVICE_VERSION_BUFFER;
    if (*(const volatile unsigned char *)buffer==0) {
        const volatile EspAppDescription *description=get_app_description();
        unsigned int sha1=description->app_elf_sha256[1];
        unsigned int sha0=description->app_elf_sha256[0];
        unsigned int sha3=description->app_elf_sha256[3];
        unsigned int sha2=description->app_elf_sha256[2];
        (void)newlib_snprintf(buffer,32,"%.15s+%02x%02x%02x%02x%s",
            (const char *)description->version,sha0,sha1,sha2,sha3,"");
    }
    return buffer;
}
