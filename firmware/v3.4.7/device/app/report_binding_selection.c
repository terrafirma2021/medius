/* Device primary report-interface selection. */
#include "../include/types.h"

/* Native entry: 0x42020df4. */
/* Original function-byte SHA-256:
 * c51a431b2aa39550a05aba4e19a822e563f50dec9329dfb2bca159c0753b1d7e. */
/* Choose among at most six layouts, eligible when enabled BYTE and first
 * axis enabled BYTE (+0x9b) are both nonzero. Initialize primary=-1 and other
 * count=0, leaving unused index WORDs untouched. Nonpositive signed count
 * returns immediately. First prefer the earliest eligible interface with a
 * nonzero preference BYTE; if none, select the earliest eligible interface.
 * Rescan layouts to append other eligible indices in order, trusting a fresh
 * signed output count <6 and publishing count+1 before its index WORD.
 * Output/input pointers are borrowed and unchecked; no lock/fence or whole
 * layout copy is supplied. Eligibility BYTEs are reread on each scan.
 */
void report_choose_primary_interface(
    const volatile HidReportLayout *layouts,
    const volatile unsigned char *preferred_interfaces, int interface_count,
    ReportInterfaceSelection *selection)
{
    volatile ReportInterfaceSelection *result = selection;
    result->primary = -1;
    result->other_count = 0;
    int limit = interface_count < 6 ? interface_count : 6;
    if (interface_count <= 0)
        return;
    for (int index = 0; index < limit; ++index) {
        if (layouts[index].enabled != 0 && layouts[index].axes[0].enabled != 0 &&
            preferred_interfaces[index] != 0) {
            result->primary = index;
            goto collect_others;
        }
    }
    for (int index = 0; index < limit; ++index) {
        if (layouts[index].enabled != 0 && layouts[index].axes[0].enabled != 0) {
            result->primary = index;
            break;
        }
    }
collect_others:
    int primary = result->primary;
    for (int index = 0; index < limit; ++index) {
        if (index == primary || layouts[index].enabled == 0 ||
            layouts[index].axes[0].enabled == 0)
            continue;
        int slot = result->other_count;
        if (slot < 6) {
            result->other_count = slot + 1;
            result->other[slot] = index;
        }
    }
}
