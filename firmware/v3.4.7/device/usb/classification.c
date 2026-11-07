/* Medius v3.4.7 device: reconstructed classification.c. */

#include "../include/types.h"

/* Native entry: 0x42020e88. */
/* Original function-byte SHA-256:
 * a4751459ef9c6f40f2770dafad55b51ff1ad3bc9618a2c61225cd55b0106847c. */
/*
 * Classify up to min(count,6) parsed HID interfaces:0 none,1 keyboard,2 mouse.
 * Nonpositive count returns0 without reads. Each two-byte boot hint contains
 * subclass/protocol: nonzero subclass plus protocol1/2 updates keyboard/mouse
 * hints using the RAW subclass byte. Enabled report X contributes mouse bit0.
 * Enabled keyboard replaces keyboard presence with bitmap_mode if nonzero,
 * else its RAW enabled byte; bitmap layouts also accumulate key-count>31.
 * Preserve the native precedence/formulas below, including non-boolean bytes
 * and BYTE truncation. Last qualifying hints/keyboard overwrite prior values;
 * mouse report presence and large bitmap observations accumulate. No fences,
 * allocation, mutation, NULL checks or layout validation;304/2-byte strides.
 */
unsigned char classify_report_interfaces(const volatile HidReportLayout *layouts,
    const volatile BootInterfaceHint *boot_interfaces,int count)
{
    if (count < 1) return 0;
    int limit = count < 6 ? count : 6;
    unsigned char boot_keyboard = 0,boot_mouse = 0,keyboard_present = 0,mouse_present = 0;
    bool large_bitmap = false;
    for (int index = 0; index < limit; ++index) {
        unsigned char subclass = boot_interfaces[index].boot_subclass;
        if (subclass != 0) {
            unsigned char protocol = boot_interfaces[index].protocol;
            if (protocol == 2) {
                boot_mouse = subclass;
                mouse_present = subclass;
            } else if (protocol == 1) {
                boot_keyboard = subclass;
                keyboard_present = subclass;
            }
        }
        const volatile HidReportLayout *layout = &layouts[index];
        if (layout->enabled != 0) {
            unsigned char x_enabled = layout->axes[0].enabled;
            mouse_present |= x_enabled != 0;
        }
        unsigned char enabled = layout->keyboard.enabled;
        if (enabled != 0) {
            unsigned char bitmap = layout->keyboard.bitmap_mode;
            keyboard_present = bitmap != 0 ? bitmap : enabled;
            if (bitmap != 0)
                large_bitmap |= layout->keyboard.bitmap_key_count > 31;
        }
    }
    if (keyboard_present != 1 && mouse_present != 0) return 2;
    if (mouse_present != 1 && keyboard_present != 0) return 1;
    if (mouse_present == 0) return 0;
    if (large_bitmap) return (unsigned char)((boot_keyboard & boot_mouse) + 1U);
    return (unsigned char)(2U - (boot_keyboard & (boot_mouse ^ 1U)));
}

/* Native entry: 0x42020f40. */
/* Original function-byte SHA-256:
 * a9777cc5bb3de05f792a78e013d8b9a589e25ea462ee79683447696d464cb537. */
/*
 * Walk a configuration descriptor chain within the low16 length. Length<2
 * returns0. At each descriptor read type THEN size before testing size>=2 and
 * offset+size<=length; stop on malformed length, retaining earlier matches.
 * Only nine-byte-or-longer alternate0 HID/class3 boot/subclass1 interfaces
 * count: protocol1 marks keyboard, protocol2 marks mouse. Return2 for any
 * mouse (also when keyboard exists), else1 for keyboard, else0. Advance offset
 * modulo65536; visit a next header only if offset+1<length. No total-length
 * field, endpoint/report validation, pointer check, fences or allocation.
 */
unsigned char classify_boot_interfaces(const volatile unsigned char *configuration,
    unsigned short length)
{
    if (length < 2) return 0;
    unsigned int offset = 0;
    bool keyboard = false,mouse = false;
    do {
        const volatile unsigned char *descriptor = configuration + offset;
        unsigned int type = descriptor[1];
        unsigned int size = descriptor[0];
        if (size < 2 || offset + size > length) break;
        if (type == 4 && size >= 9 && descriptor[3] == 0 &&
            descriptor[5] == 3 && descriptor[6] == 1) {
            unsigned char protocol = descriptor[7];
            if (protocol == 2) mouse = true;
            else if (protocol == 1) keyboard = true;
        }
        offset = (unsigned short)(offset + size);
    } while (offset + 1U < length);
    return mouse ? 2 : keyboard ? 1 : 0;
}
