/* Medius v3.4.7 host: NVS page initialization. */
#include "../include/types.h"

/* Native entry: 0x42013ff8. */
/* Original function-byte SHA-256:
 * 3cfa801498e2c84d8055c120ee68bac2b14e1e5fe254bb09f2db8527cf81936a. */
/* Initialize the NVS page sector-size word from the main-flash sector-size
 * getter. Store its full return value without validation or a fallback.
 * Registered in the global constructor array at 0x3c0526c4. The getter in this
 * build returns 4096; retain the native call and subsequent WORD store. */
void nvs_page_initialize_sector_size(void)
{
    NVS_SECTOR_SIZE = esp_partition_get_main_flash_sector_size();
}
