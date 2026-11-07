/* Medius v3.4.7 host — link/drop_counts.c.
 */

#include "../include/types.h"

/* Native entry: 0x4037f6cc. */
/*
 * Medius v3.4.7 — host application; 0x4037f6cc.
 * Instruction-checked recovered C.
 * Original function-byte SHA-256:
 * 34640f09df9fa3c06eeade2e2526f48ca866617e4e0504f9f963b4d94108878a.
 */

/*
 * Sample selected-type RX drops after MEMW, then FIFO-overflow events after a
 * second MEMW, and return their modulo32 sum. Neither counter is cleared.
 * The two samples are not atomic or locked and can represent different times.
 */
unsigned int medius_link_counted_rx_drop_count(void)
{
    memw();unsigned int selected=LINK_RX_SELECTED_TYPE_DROPS;
    memw();unsigned int overflow=LINK_RX_FIFO_OVERFLOW_COUNT;
    return selected+overflow;
}

/* Native entry: 0x4037f6e4. */
/*
 * Medius v3.4.7 — host application; 0x4037f6e4.
 * Instruction-checked recovered C.
 * Original function-byte SHA-256:
 * 540ac6fe5af655c52a03fe9791e0caeeedda4dcb488151d0652fb4921da460f7.
 */

/*
 * Return one raw32 sample of other-type RX drops after MEMW. No lock, reset,
 * saturation or combination with FIFO-overflow/selected-type counts is applied.
 */
unsigned int medius_link_other_rx_drop_count(void)
{
    memw();return LINK_RX_OTHER_TYPE_DROPS;
}
