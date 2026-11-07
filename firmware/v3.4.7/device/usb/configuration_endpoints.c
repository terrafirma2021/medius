/* Medius v3.4.7 device — USB lifecycle and configuration transitions. */
#include "../include/types.h"

/* Native entry: 0x42028cbc. */
/* Original function-byte SHA-256:
 * 739c623d72ad610feceea25cb46b6119b12b360aed8c3b18314a8a0c9aefb4b3. */
/* Walk configuration descriptor bytes and close/open their nonzero endpoints
 * on bus0. length is a signed native WORD: <=1 skips everything. Before each
 * record read length then type BYTE, reject length<2 or a widened end beyond
 * length, and advance a wrapping16-bit cursor; an unmatched last BYTE is ignored.
 * A valid interface descriptor (type4,length>=9) updates eligibility: all
 * alternates when default_alternates_only==0, otherwise only alternate0. Before
 * any such interface the initial eligibility is true. Short interfaces leave
 * it unchanged. All other records retain the current eligibility.
 *
 * For eligible type5,length>=7 with low7(address)!=0, copy exactly seven bytes
 * twice into adjacent stack descriptors and XOR the second address with0x80.
 * open!=0 opens the original; open==0 closes its address. Transfer type0 also
 * opens/closes the opposite direction. Ignore every controller result and keep
 * partial transitions on malformed input. No class/type/direction/MPS policy,
 * NULL check, lock, rollback or cycle repair. Cursor wrap can revisit bytes.
 */
void medius_clone_transition_configuration_endpoints(const unsigned char *configuration,
    int length, unsigned int default_alternates_only, unsigned int open)
{
    if (length <= 1)
        return;
    unsigned int cursor = 0;
    bool eligible = true;
    do {
        const volatile unsigned char *descriptor = configuration + cursor;
        unsigned int record_length = descriptor[0];
        unsigned int type = descriptor[1];
        if (record_length < 2 || length < (int)(cursor + record_length))
            return;
        if (type == 4 && record_length >= 9) {
            eligible = default_alternates_only == 0 || descriptor[3] == 0;
        } else if (type == 5 && record_length >= 7 && eligible &&
                   (descriptor[2] & 0x7fU) != 0) {
            /* Native stack order is opposite first, original second. */
            struct {
                MediusUsbEndpointDescriptor opposite, original;
            } endpoints;
            memcpy(&endpoints.original, (const void *)descriptor, 7);
            memcpy(&endpoints.opposite, &endpoints.original, 7);
            endpoints.opposite.address = endpoints.original.address ^ 0x80U;
            unsigned int transfer_type = endpoints.original.attributes & 3U;
            if (open == 0) {
                medius_usbd_close_endpoint(0, endpoints.original.address);
                if (transfer_type == 0)
                    medius_usbd_close_endpoint(0, endpoints.opposite.address);
            } else {
                medius_usbd_open_endpoint(0, &endpoints.original);
                if (transfer_type == 0)
                    medius_usbd_open_endpoint(0, &endpoints.opposite);
            }
        }
        cursor = (unsigned short)(cursor + record_length);
    } while ((int)(cursor + 1U) < length);
}
