/* Medius v3.4.7 host — usb/phy.c.
 * Recovered C and native assembly, grouped for source navigation.
 * Original entry addresses, firmware-byte hashes and function comments follow.
 */

#include "../include/types.h"

/* Native entry: 0x4200f6c0. */
/* Original function-byte SHA-256:
 * 060f836420f87d91b4d1390c5548772709480dce9ec13440c964eb2df8d09d31. */
/* UINT_MAX means no pin and returns0 without calls. Otherwise apply the
 * native signed/six-bit GPIO mask (including its positive>=64 aliases).
 * Accepted pins: select GPIO pad, connect the input with inversion0, enable
 * input (ignore result), unhold. Invalid pins log and return102. Signal index
 * is unchecked; there is no rollback or physical signal-delivery check. */
unsigned int phy_configure_pin_input(unsigned int pin,unsigned int signal)
{
    if (pin == 0xffffffffU) return 0;
    if (gpio_native_pin_valid(pin)) {
        gpio_pad_select_gpio(pin);
        gpio_matrix_in(pin,signal,0);
        gpio_input_enable(pin);
        gpio_pad_unhold(pin);
        return 0;
    }
    unsigned int timestamp = esp_log_timestamp();
    esp_log_write(1,"usb_phy","E (%lu) %s: %s(%d): io_num argument is invalid\n",timestamp,"usb_phy",
                  "phy_configure_pin_input",71);
    return 0x102;
}

/* Native entry: 0x4200f7d8. */
/* Original function-byte SHA-256:
 * 7047fabc2019cfc62f82dbf554eb1208021da65fea518b17dc816cb6414c2219. */
/* Reject NULL handle or unsigned mode>=3 with logged102; non-OTG controller
 * returns loggedFFFFFFFF. Cache target BEFORE storing mode. Target1 returns
 * success without routing; otherwise load the OTG signal table and retain
 * its native NULL assertion. Mode0 still checks that table but routes nothing.
 * Host mode1 routes constant0/0/1/1 to IDDIG/BVALID/VBUSVALID/AVALID, then
 * rereads target. An internal target gets five distinct fenced wrapper RMWs
 * selecting DP/DM pulldowns and enabling overrides. Device mode2 routes
 * constant1/1/1/0 and does not undo those host pull overrides. No lock,
 * lifetime validation or GPIO/physical-mode completion check is supplied. */
unsigned int usb_phy_otg_set_mode(MediusUsbPhyContext *handle,unsigned int mode)
{
    const char *error_format;
    unsigned int timestamp,line;
    if (handle == 0) {
        timestamp = esp_log_timestamp();
        error_format = "E (%lu) %s: %s(%d): handle argument is invalid\n";
        line = 138;
        goto invalid_argument;
    }
    if (mode >= 3) {
        timestamp = esp_log_timestamp();
        error_format = "E (%lu) %s: %s(%d): mode argument is invalid\n";
        line = 139;
        goto invalid_argument;
    }
    volatile MediusUsbPhyContext *live = handle;
    if (live->controller != 0) {
        timestamp = esp_log_timestamp();
        esp_log_write(1,"usb_phy","E (%lu) %s: %s(%d): phy source is not USB_OTG\n",timestamp,"usb_phy",
                      "usb_phy_otg_set_mode",140);
        return 0xffffffffU;
    }
    unsigned int target = live->target;
    live->otg_mode = mode;
    if (target == 1) return 0;
    const volatile MediusUsbPhyOtgSignals *signals = MEDIUS_USB_PHY_SIGNALS->otg;
    if (signals == 0) __assert_func(0,0,0,0);
    if (mode == 1) {
        gpio_matrix_in(60,(unsigned int)signals->iddig,0);
        gpio_matrix_in(60,(unsigned int)signals->bvalid,0);
        gpio_matrix_in(56,(unsigned int)signals->vbusvalid,0);
        gpio_matrix_in(56,(unsigned int)signals->avalid,0);
        if (live->target == 0) {
            volatile unsigned int *configuration = live->wrap.dev;
            memw(); unsigned int value = *configuration;
            memw(); *configuration = value & 0xffffdfffU;
            memw(); value = *configuration;
            memw(); *configuration = value | 0x4000U;
            memw(); value = *configuration;
            memw(); *configuration = value & 0xffff7fffU;
            memw(); value = *configuration;
            memw(); *configuration = value | 0x10000U;
            memw(); value = *configuration;
            memw(); *configuration = value | 0x1000U;
        }
    } else if (mode == 2) {
        gpio_matrix_in(56,(unsigned int)signals->iddig,0);
        gpio_matrix_in(56,(unsigned int)signals->bvalid,0);
        gpio_matrix_in(56,(unsigned int)signals->vbusvalid,0);
        gpio_matrix_in(60,(unsigned int)signals->avalid,0);
    }
    return 0;
invalid_argument:
    esp_log_write(1,"usb_phy",error_format,timestamp,"usb_phy","usb_phy_otg_set_mode",line);
    return 0x102;
}

/* Native entry: 0x4200f938. */
/* Original function-byte SHA-256:
 * 98854f534091b886d3091381ecf6623a25ca730a19e4eff0f81d71857b5fcbfe. */
/* NULL handle returns logged102. Otherwise lock, cache target then controller,
 * decrement references with unsigned wrap, and clear the selected registry
 * slot (2 external,0 internal,anything else UTMI). Internal deletion first
 * clears wrapper pull-override bit12. Unlock, free pins then handle, and lock
 * again. Reread the global controller: if references0, clear its global pointer
 * BEFORE disabling its clock under the RCC lock, then free that cached object
 * after unlocking. Otherwise free(NULL). No ownership, controller existence,
 * double-delete/refcount-underflow test, PHY shutdown wait or rollback. */
unsigned int usb_del_phy(MediusUsbPhyContext *handle)
{
    if (handle == 0) {
        unsigned int timestamp = esp_log_timestamp();
        esp_log_write(1,"usb_phy","E (%lu) %s: %s(%d): handle argument is invalid\n",timestamp,"usb_phy",
                      "usb_del_phy",441);
        return 0x102;
    }
    volatile MediusUsbPhyContext *live = handle;
    xPortEnterCriticalTimeout(&MEDIUS_USB_PHY_LOCK,-1);
    unsigned int target = live->target;
    volatile MediusUsbPhyController *controller = MEDIUS_USB_PHY_CONTROLLER;
    controller->references = controller->references-1U;
    if (target == 2) controller->external = 0;
    else if (target == 0) {
        volatile unsigned int *configuration = live->wrap.dev;
        memw(); unsigned int value = *configuration;
        memw(); *configuration = value & 0xffffefffU;
        controller->internal = 0;
    } else controller->utmi = 0;
    vPortExitCritical(&MEDIUS_USB_PHY_LOCK);
    free(live->external_pins);
    free(handle);
    xPortEnterCriticalTimeout(&MEDIUS_USB_PHY_LOCK,-1);
    controller = MEDIUS_USB_PHY_CONTROLLER;
    if (controller->references == 0) {
        MEDIUS_USB_PHY_CONTROLLER = 0;
        periph_rcc_enter();
        _usb_wrap_hal_disable();
        periph_rcc_exit();
    } else controller = 0;
    vPortExitCritical(&MEDIUS_USB_PHY_LOCK);
    free((void *)controller);
    return 0;
}

/* Native entry: 0x4200fa00. */
/* Original function-byte SHA-256:
 * 4a964a931fd3687ae26ee9657727eb2cf0e83465b6f4b3ca780e89bda0945c07. */
/* Validate unsigned target<=2, then cache the global controller. Invalid target
 * returns logged102; missing controller logged103, leaving status_out untouched.
 * Otherwise cache its selected slot and write0 if NULL, or that context's raw
 * status word. No output-pointer check, lock or normalization is performed;
 * callers must coordinate registry/context lifetime themselves. */
unsigned int usb_phy_get_phy_status(unsigned int target,unsigned int *status_out)
{
    if (target > 2) {
        unsigned int timestamp = esp_log_timestamp();
        esp_log_write(1,"usb_phy","E (%lu) %s: %s(%d): argument is invalid\n",timestamp,"usb_phy",
                      "usb_phy_get_phy_status",463);
        return 0x102;
    }
    const volatile MediusUsbPhyController *controller = MEDIUS_USB_PHY_CONTROLLER;
    if (controller == 0) {
        unsigned int timestamp = esp_log_timestamp();
        esp_log_write(1,"usb_phy","E (%lu) %s: %s(%d): USB_PHY is not initialized\n",timestamp,"usb_phy",
                      "usb_phy_get_phy_status",464);
        return 0x103;
    }
    const volatile MediusUsbPhyContext *selected;
    if (target == 2) selected = controller->external;
    else if (target == 0) selected = controller->internal;
    else selected = controller->utmi;
    *status_out = selected == 0 ? 0 : selected->status;
    return 0;
}

/* Native entry: 0x4200fa8c. */
/* Original function-byte SHA-256:
 * 1bf6c68169c2bb0e8d34f8f35e87ce095de99eec82fae5af1f501b0753827f45. */
/* Create a PHY from the six-word configuration. Cache target first. Validate
 * target<=2, controller<=1, external pins for target2; target1 returns106.
 * Neither configuration nor handle_out is NULL-checked. Install a zeroed16-byte
 * controller with allocate-outside-lock/recheck publication, then allocate a
 * zeroed24-byte context. Under the PHY lock, query occupancy (ignoring result),
 * claim its registry slot and increment references BEFORE initializing fields.
 * Initialize the wrapper HAL under the RCC lock; freshly read controller/target
 * fields select OTG or serial-JTAG routing. Internal pads receive drive3.
 * Publish *handle_out before external-pin allocation/configuration or mode.
 *
 * External pins are copied32 bytes, then all eight pin helpers run and their
 * results are ORed before abort-on-error. Requested mode is read once; nonzero
 * uses the freshly read *handle_out and aborts on error. Optional OTG pins run
 * all eleven helpers similarly when the fresh context controller is OTG.
 * Signal tables and per-call pin values remain separate native snapshots.
 *
 * Allocation errors return101; occupied target103. Failure cleanup frees pins
 * and context where reached, then frees the global controller only if its
 * freshly read reference count is0, without a lock. It does NOT undo a prior
 * claim/refcount increment, clear handle_out, disable clocks or roll back pins.
 * External-pin OOM therefore leaves dangling published handles/registry state.
 * Preserve these native failure behaviors; success returns0. */
unsigned int usb_new_phy(const MediusUsbPhyConfiguration *configuration,MediusUsbPhyContext **handle_out)
{
    const volatile MediusUsbPhyConfiguration *live = configuration;
    unsigned int target = live->target;
    unsigned int timestamp,line,result;
    const char *error_format,*pin_function;
    MediusUsbPhyContext *created;
    goto validate_configuration;
invalid_configuration:
    esp_log_write(1,"usb_phy",error_format,timestamp,"usb_phy","usb_new_phy",line);
    return 0x102;
validate_configuration:
    if (target > 2) {
        timestamp = esp_log_timestamp();
        error_format = "E (%lu) %s: %s(%d): specified PHY argument is invalid\n";
        line = 324; goto invalid_configuration;
    }
    if (live->controller > 1) {
        timestamp = esp_log_timestamp();
        error_format = "E (%lu) %s: %s(%d): specified source argument is invalid\n";
        line = 325; goto invalid_configuration;
    }
    if (target == 2) {
        if (live->external_io_configuration == 0) {
            timestamp = esp_log_timestamp();
            error_format = "E (%lu) %s: %s(%d): ext_io_conf must be provided for ext PHY\n";
            line = 326; goto invalid_configuration;
        }
    } else if (target == 1) {
        timestamp = esp_log_timestamp();
        esp_log_write(1,"usb_phy","E (%lu) %s: %s(%d): UTMI PHY not supported on this target\n",timestamp,
                      "usb_phy","usb_new_phy",331);
        return 0x106;
    }
    xPortEnterCriticalTimeout(&MEDIUS_USB_PHY_LOCK,-1);
    if (MEDIUS_USB_PHY_CONTROLLER == 0) {
        vPortExitCritical(&MEDIUS_USB_PHY_LOCK);
        MediusUsbPhyController *candidate = calloc(1,16);
        if (candidate == 0) {
            timestamp = esp_log_timestamp();
            esp_log_write(1,"usb_phy","E (%lu) %s: %s(%d): no mem for USB_PHY driver\n",timestamp,"usb_phy",
                          "usb_phy_install",280);
            timestamp = esp_log_timestamp();
            esp_log_write(1,"usb_phy","E (%lu) %s: %s(%d): usb_phy driver installation failed\n",timestamp,
                          "usb_phy","usb_new_phy",334);
            return 0x101;
        }
        xPortEnterCriticalTimeout(&MEDIUS_USB_PHY_LOCK,-1);
        if (MEDIUS_USB_PHY_CONTROLLER == 0) {
            MEDIUS_USB_PHY_CONTROLLER = candidate;
            ((volatile MediusUsbPhyController *)candidate)->references = 0;
            vPortExitCritical(&MEDIUS_USB_PHY_LOCK);
        } else {
            vPortExitCritical(&MEDIUS_USB_PHY_LOCK);
            free(candidate);
        }
    } else vPortExitCritical(&MEDIUS_USB_PHY_LOCK);
    created = calloc(1,24);
    if (created == 0) {
        timestamp = esp_log_timestamp();
        esp_log_write(1,"usb_phy","E (%lu) %s: %s(%d): no mem for phy context\n",timestamp,"usb_phy",
                      "usb_new_phy",338);
        result = 0x101; goto release_unused_controller;
    }
    volatile MediusUsbPhyContext *context = created;
    xPortEnterCriticalTimeout(&MEDIUS_USB_PHY_LOCK,-1);
    usb_phy_get_phy_status(target,(unsigned int *)&context->status);
    if (context->status != 0) {
        vPortExitCritical(&MEDIUS_USB_PHY_LOCK);
        timestamp = esp_log_timestamp();
        esp_log_write(1,"usb_phy","E (%lu) %s: %s(%d): selected PHY is in use\n",timestamp,"usb_phy",
                      "usb_new_phy",354);
        result = 0x103; goto release_context;
    }
    volatile MediusUsbPhyController *controller = MEDIUS_USB_PHY_CONTROLLER;
    controller->references = controller->references+1U;
    if (target == 2) controller->external = created;
    else controller->internal = created;
    vPortExitCritical(&MEDIUS_USB_PHY_LOCK);
    unsigned int source = live->controller;
    context->controller = source;
    context->target = target;
    context->status = 1;
    periph_rcc_enter();
    _usb_wrap_hal_init((MediusUsbWrapHal *)&context->wrap);
    periph_rcc_exit();
    source = live->controller;
    if (source == 0) usb_wrap_hal_phy_set_external((MediusUsbWrapHal *)&context->wrap,(unsigned char)(target == 2));
    else if (source == 1) {
        usb_serial_jtag_hal_phy_set_external(0,(unsigned char)(live->target == 2));
        context->otg_mode = 2;
    }
    if (target == 0) {
        const volatile MediusUsbPhyInternalPins *pins = MEDIUS_USB_PHY_SIGNALS->internal;
        if (pins == 0) __assert_func(0,0,0,0);
        gpio_set_drive_capability((unsigned int)pins->dm,3);
        gpio_set_drive_capability((unsigned int)pins->dp,3);
        *handle_out = created;
    } else {
        *handle_out = created;
        void *pins_copy = calloc(1,32);
        context->external_pins = pins_copy;
        if (pins_copy == 0) {
            timestamp = esp_log_timestamp();
            esp_log_write(1,"usb_phy","E (%lu) %s: %s(%d): no mem for storing I/O pins\n",timestamp,"usb_phy",
                          "usb_new_phy",394);
            result = 0x101; goto release_context;
        }
        memcpy(pins_copy,live->external_io_configuration,32);
        const volatile MediusUsbPhyExternalPins *pins = context->external_pins;
        const volatile MediusUsbPhyExternalPins *signals = MEDIUS_USB_PHY_SIGNALS->external;
        if (pins == 0 || signals == 0) {
            timestamp = esp_log_timestamp();pin_function = "phy_external_iopins_configure";line = 95;
            goto invalid_pin_configuration;
        }
        unsigned int errors = phy_configure_pin_input((unsigned int)pins->vp,(unsigned int)signals->vp);
        errors |= phy_configure_pin_input((unsigned int)pins->vm,(unsigned int)signals->vm);
        errors |= phy_configure_pin_input((unsigned int)pins->receive,(unsigned int)signals->receive);
        errors |= phy_configure_pin_output((unsigned int)pins->suspend_n,(unsigned int)signals->suspend_n);
        errors |= phy_configure_pin_output((unsigned int)pins->output_enable_n,(unsigned int)signals->output_enable_n);
        errors |= phy_configure_pin_output((unsigned int)pins->vp_out,(unsigned int)signals->vp_out);
        errors |= phy_configure_pin_output((unsigned int)pins->vm_out,(unsigned int)signals->vm_out);
        errors |= phy_configure_pin_output((unsigned int)pins->full_speed_edge,(unsigned int)signals->full_speed_edge);
        if (errors != 0) abort();
    }
    unsigned int mode = live->otg_mode;
    if (mode != 0 && usb_phy_otg_set_mode(*(MediusUsbPhyContext *volatile *)handle_out,mode) != 0) abort();
    const volatile MediusUsbPhyOtgPins *pins = live->otg_io_configuration;
    if (pins != 0 && context->controller == 0) {
        const volatile MediusUsbPhyOtgSignals *signals = MEDIUS_USB_PHY_SIGNALS->otg;
        if (signals == 0) {
            timestamp = esp_log_timestamp();pin_function = "phy_otg_iopins_configure";line = 115;
            goto invalid_pin_configuration;
        }
        unsigned int errors = phy_configure_pin_input((unsigned int)pins->iddig,(unsigned int)signals->iddig);
        errors |= phy_configure_pin_input((unsigned int)pins->avalid,(unsigned int)signals->avalid);
        errors |= phy_configure_pin_input((unsigned int)pins->vbusvalid,(unsigned int)signals->vbusvalid);
        errors |= phy_configure_pin_input((unsigned int)pins->bvalid,(unsigned int)signals->bvalid);
        errors |= phy_configure_pin_input((unsigned int)pins->session_end,(unsigned int)signals->session_end);
        errors |= phy_configure_pin_output((unsigned int)pins->idpullup,(unsigned int)signals->idpullup);
        errors |= phy_configure_pin_output((unsigned int)pins->dp_pulldown,(unsigned int)signals->dp_pulldown);
        errors |= phy_configure_pin_output((unsigned int)pins->dm_pulldown,(unsigned int)signals->dm_pulldown);
        errors |= phy_configure_pin_output((unsigned int)pins->drive_vbus,(unsigned int)signals->drive_vbus);
        errors |= phy_configure_pin_output((unsigned int)pins->charge_vbus,(unsigned int)signals->charge_vbus);
        errors |= phy_configure_pin_output((unsigned int)pins->discharge_vbus,(unsigned int)signals->discharge_vbus);
        if (errors != 0) abort();
    }
    return 0;
invalid_pin_configuration:
    esp_log_write(1,"usb_phy","E (%lu) %s: %s(%d): argument is invalid\n",timestamp,"usb_phy",pin_function,line);
    abort();
release_context:
    free(context->external_pins);
    free(created);
release_unused_controller:
    controller = MEDIUS_USB_PHY_CONTROLLER;
    unsigned int references = controller->references;
    if (references == 0) {
        free((void *)controller);
        MEDIUS_USB_PHY_CONTROLLER = 0;
    }
    return result;
}

/* Native entry: 0x420139b0. */
/* Original function-byte SHA-256:
 * 13b21fa6764fa3021c0e95ac0a39ad4bf29383dd235732ff25ad77fe00fcfbc4. */
/* Ignore hal. Low8(external) selects serial/JTAG PHY routing. External sets
 * CONF0 bit0, then RTC selection override bit20 and value bit19. Internal
 * clears bit0, sets override20, clears value19, then freshly sets CONF0 pad
 * enable bit14. All are distinct fenced RMWs; external does not clear bit14.
 * No lock or NULL test; passing NULL hal is supported because it is unused. */
void usb_serial_jtag_hal_phy_set_external(void *unused_hal,unsigned char external)
{
    (void)unused_hal;
    memw(); unsigned int value = USB_SERIAL_JTAG_CONFIGURATION;
    memw(); USB_SERIAL_JTAG_CONFIGURATION = external ? value|1U : value&0xfffffffeU;
    memw(); value = MEDIUS_USB_PHY_RTC_SELECTION;
    memw(); MEDIUS_USB_PHY_RTC_SELECTION = value|0x100000U;
    memw(); value = MEDIUS_USB_PHY_RTC_SELECTION;
    memw(); MEDIUS_USB_PHY_RTC_SELECTION = external ? value|0x80000U : value&0xfff7ffffU;
    if (!external) {
        memw(); value = USB_SERIAL_JTAG_CONFIGURATION;
        memw(); USB_SERIAL_JTAG_CONFIGURATION = value|0x4000U;
    }
}

/* Native entry: 0x42013a40. */
/* Original function-byte SHA-256:
 * baa9cd5ea2f26ba3ecdcb12f766e2437ac63c00e50d501d9fa7ee97770de58ee. */
/* Store wrapper base60039000 in hal first, then fence/read/write SYSTEM
 * clock-enable bit23, reset-assert bit23, and freshly reset-deassert bit23.
 * No lock or context validation; caller supplies RCC serialization. */
void _usb_wrap_hal_init(MediusUsbWrapHal *hal)
{
    hal->dev = (volatile unsigned int *)0x60039000U;
    memw(); unsigned int value = MEDIUS_USB_WRAP_CLOCK_ENABLE;
    memw(); MEDIUS_USB_WRAP_CLOCK_ENABLE = value|0x800000U;
    memw(); value = MEDIUS_USB_WRAP_RESET_ENABLE;
    memw(); MEDIUS_USB_WRAP_RESET_ENABLE = value|0x800000U;
    memw(); value = MEDIUS_USB_WRAP_RESET_ENABLE;
    memw(); MEDIUS_USB_WRAP_RESET_ENABLE = value&0xff7fffffU;
}

/* Native entry: 0x42013a7c. */
/* Original function-byte SHA-256:
 * c3f1b7fd2e0bd572bfb2481ad9387a5c804846e82fe2f77ed657bb9264109799. */
/* Fence/read SYSTEM clock-enable, clear only USB wrapper bit23, fence/write.
 * No reset, context access or lock; caller supplies RCC serialization. */
void _usb_wrap_hal_disable(void)
{
    memw(); unsigned int value = MEDIUS_USB_WRAP_CLOCK_ENABLE;
    memw(); MEDIUS_USB_WRAP_CLOCK_ENABLE = value&0xff7fffffU;
}

/* Native entry: 0x42013a94. */
/* Original function-byte SHA-256:
 * d83fc2c10980ff3f62b3206be55b1704ddec0581c8eafae02f52ba3e0a08aa08. */
/* Cache hal.dev. Low8(external) selects wrapper PHY bit2, then RTC routing:
 * override20 is set and value19 is cleared for external, set for internal.
 * Internal additionally sets wrapper pad-enable bit18 from a fresh read.
 * Each RMW has separate fenced read/write; external leaves pad bit18 intact.
 * No lock, validation or hardware-settle delay is supplied. */
void usb_wrap_hal_phy_set_external(MediusUsbWrapHal *hal,unsigned char external)
{
    volatile unsigned int *configuration = hal->dev;
    memw(); unsigned int value = *configuration;
    memw(); *configuration = external ? value|4U : value&0xfffffffbU;
    memw(); value = MEDIUS_USB_PHY_RTC_SELECTION;
    memw(); MEDIUS_USB_PHY_RTC_SELECTION = value|0x100000U;
    memw(); value = MEDIUS_USB_PHY_RTC_SELECTION;
    memw(); MEDIUS_USB_PHY_RTC_SELECTION = external ? value&0xfff7ffffU : value|0x80000U;
    if (!external) {
        memw(); value = *configuration;
        memw(); *configuration = value|0x40000U;
    }
}

