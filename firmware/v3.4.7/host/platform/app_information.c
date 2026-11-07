/* Medius v3.4.7 host — SDK application information and component startup.
 * SDK names/order checked against ESP-IDF v5.4.4; native bytes are authority.
 */
#include "../include/types.h"

/* Native entry: 0x42002048. */
/* Original function-byte SHA-256:
 * d16a8bd749455401b4ecb430242cdc24c759fca6a91f3a53fb4ac137de5abc2e. */
/* Format the first five application ELF-SHA bytes as lowercase hex.
 * This is the compiler-split SDK esp_app_format_init_elf_sha256 body; callers
 * handle the lazy-initialization probe. For each source BYTE, issue MEMW,
 * read it once, then write its high and low nibble characters separately.
 * Ten characters are written, then byte9 is overwritten with NUL: the visible
 * result is NINE digits, not ten. No whole-buffer clear, capacity check, lock
 * or source hash computation; this displays metadata already in the image.
 * The 32-byte binary SHA and cache padding bytes are left unchanged.
 */
void app_format_elf_sha256(void)
{
    const volatile unsigned char *hash = APPLICATION_DESCRIPTION->app_elf_sha256;
    for (unsigned int index = 0; index < 5; ++index) {
        memw();
        unsigned int value = hash[index];
        unsigned int high = value >> 4;
        unsigned int low = value & 15U;
        APP_ELF_SHA_CACHE->text[2 * index] =
            (char)(high < 10U ? high + '0' : high + ('a' - 10));
        APP_ELF_SHA_CACHE->text[2 * index + 1] =
            (char)(low < 10U ? low + '0' : low + ('a' - 10));
    }
    APP_ELF_SHA_CACHE->text[9] = 0;
}

/* Native entry: 0x42002090. */
/* Original function-byte SHA-256:
 * f30377e0cd50fc98409eadead2ec7ec34b28bb257722336f60a9dd091024f362. */
/* SDK CORE/CPU0 priority20 application-information initializer.
 * Probe the first cache WORD and format it when zero, even if logging is off.
 * At fresh unsigned log levels>=3, emit application header, project name and
 * version through nested checks, using a separate timestamp for each line.
 * Probe/initialize the cache AGAIN after those logs, then copy exactly ten
 * bytes to the stack regardless of the next log level. Snapshot that level,
 * force stack byte9 to NUL, and optionally log the SHA followed by IDF version
 * under another fresh nested check. The SHA has nine visible hex digits.
 * Return0. No locking, metadata validation, build-date/secure-version output
 * or firmware-hash verification. Concurrent cache formatting is not prevented.
 */
int __esp_system_init_fn_init_show_app_info(void)
{
    if (APP_ELF_SHA_CACHE->initialized_word == 0)
        app_format_elf_sha256();
    if (SYSTEM_EARLY_LOG_LEVEL >= 3U) {
        unsigned int timestamp = esp_log_timestamp();
        ets_printf("I (%lu) %s: Application information:\n",timestamp,"app_init");
        if (SYSTEM_EARLY_LOG_LEVEL >= 3U) {
            timestamp = esp_log_timestamp();
            ets_printf("I (%lu) %s: Project name:     %s\n",timestamp,"app_init",
                APPLICATION_DESCRIPTION->project_name);
            if (SYSTEM_EARLY_LOG_LEVEL >= 3U) {
                timestamp = esp_log_timestamp();
                ets_printf("I (%lu) %s: App version:      %s\n",timestamp,"app_init",
                    APPLICATION_DESCRIPTION->version);
            }
        }
    }
    if (APP_ELF_SHA_CACHE->initialized_word == 0)
        app_format_elf_sha256();
    char hash[10];
    memcpy(hash,(const void *)APP_ELF_SHA_CACHE->text,sizeof(hash));
    unsigned int log_level = SYSTEM_EARLY_LOG_LEVEL;
    hash[9] = 0;
    if (log_level >= 3U) {
        unsigned int timestamp = esp_log_timestamp();
        ets_printf("I (%lu) %s: ELF file SHA256:  %s...\n",timestamp,"app_init",hash);
        if (SYSTEM_EARLY_LOG_LEVEL >= 3U) {
            timestamp = esp_log_timestamp();
            ets_printf("I (%lu) %s: ESP-IDF:          %s\n",timestamp,"app_init",
                APPLICATION_DESCRIPTION->idf_version);
        }
    }
    return 0;
}

/* Native entry: 0x42002160. */
/* Original function-byte SHA-256:
 * c9830e7055ec5932869c07f1c4fbd5db263caba7ac7016860e4a88f4dbdc096a. */
/* SDK CORE/CPU0 priority21 chip-revision information initializer.
 * At unsigned log level>=3, print minimum revision0.0. A fresh nested level
 * check permits the maximum0.99 line: obtain its timestamp BEFORE reading the
 * disable-wafer-major flag, then append "(constraint ignored)" for true, or an
 * empty string for false. Both minimum format arguments are zero; Ghidra lost
 * the second one. Read actual chip revision unconditionally, even when all
 * logging is disabled. A fresh level check then logs revision/100, revision%100
 * with a new timestamp. Return0; these lines describe configured limits and
 * observed fields, and do not enforce a revision constraint or alter eFuses.
 */
int __esp_system_init_fn_init_efuse_show_app_info(void)
{
    if (SYSTEM_EARLY_LOG_LEVEL >= 3U) {
        unsigned int timestamp = esp_log_timestamp();
        ets_printf("I (%lu) %s: Min chip rev:     v%d.%d\n",timestamp,"efuse_init",0,0);
        if (SYSTEM_EARLY_LOG_LEVEL >= 3U) {
            timestamp = esp_log_timestamp();
            bool ignore_major = efuse_hal_get_disable_wafer_version_major();
            const char *suffix = ignore_major ? "(constraint ignored)" : "";
            ets_printf("I (%lu) %s: Max chip rev:     v%d.%d %s\n",
                timestamp,"efuse_init",0,99,suffix);
        }
    }
    unsigned int revision = efuse_hal_chip_revision();
    if (SYSTEM_EARLY_LOG_LEVEL >= 3U) {
        unsigned int timestamp = esp_log_timestamp();
        ets_printf("I (%lu) %s: Chip rev:         v%d.%d\n",timestamp,"efuse_init",
            revision / 100U,revision % 100U);
    }
    return 0;
}

/* Native entry: 0x42002258. */
/* Original function-byte SHA-256:
 * ab1105eae5b1434258ee55c7103e94e4aedf6e29e17ea3b12ea6df3fa716290e. */
/* SDK CORE/CPU0 priority10 CPU-frequency information initializer.
 * At unsigned log level>=3, timestamp/log the start-user-code line. Query
 * esp_clk_cpu_freq unconditionally; its reviewed callee converts ROM MHz to
 * a wrapping signed Hz WORD. Under a fresh level check, take a new timestamp
 * and log that cached Hz value. Return0. No measured frequency, clock change,
 * task launch or timing guarantee; no lock or MEMW is added in this wrapper.
 */
int __esp_system_init_fn_init_show_cpu_freq(void)
{
    if (SYSTEM_EARLY_LOG_LEVEL >= 3U) {
        unsigned int timestamp = esp_log_timestamp();
        ets_printf("I (%lu) %s: Pro cpu start user code\n",timestamp,"cpu_start");
    }
    int frequency = esp_clk_cpu_freq();
    if (SYSTEM_EARLY_LOG_LEVEL >= 3U) {
        unsigned int timestamp = esp_log_timestamp();
        ets_printf("I (%lu) %s: cpu freq: %d Hz\n",timestamp,"cpu_start",frequency);
    }
    return 0;
}
