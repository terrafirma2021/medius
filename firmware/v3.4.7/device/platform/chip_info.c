/* Medius v3.4.7 device — chip information used by early startup. */
#include "../include/types.h"

/* Native entry: 0x42005548. */
/* Original function-byte SHA-256:
 * 6aba51e31a768e01936cf700cec213727c549e18a25ae603dac0265ea3afba3d. */
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
