/* Medius v3.4.7 host — chip information used by early startup. */
#include "../include/types.h"

/* Native entry: 0x42005114. */
/* Original function-byte SHA-256:
 * 2e2e6fe96bd1d5be276dfed36be77e4a595891410afa118a3cbc9a2fc0fa8f3e. */
/* Clear all12 output bytes, including padding. Store model9 (ESP32-S3), call
 * the separately reviewed eFuse revision helper, then store cores BYTE2,
 * low16 revision and feature WORD0x12 in that order. Model/features/core count
 * are fixed in this linked body; the core-count value is not discovered by
 * probing a CPU. information must cover12 writable bytes; no null/extent
 * check, lock or allocation is supplied. Returns void. */
void esp_chip_info(BootChipInfo *information)
{
    memset(information,0,sizeof(*information));
    volatile BootChipInfo *output=information;
    output->model=9;
    unsigned int revision=efuse_hal_chip_revision();
    output->cores=2;
    output->revision=(unsigned short)revision;
    output->features=0x12;
}
