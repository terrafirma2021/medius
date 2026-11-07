# Medius Firmware — Decompiled and Reconstructed Source

Ongoing decompilation and reconstruction of the **Medius v3.4.7** ESP32-S3 host and device application firmware.

The C reconstruction starts from Ghidra decompilation and is reviewed against the original firmware's machine instructions. Corrections repair decompiler mistakes while preserving the firmware's behavior, including its bugs and quirks. This is recovered source, not a rebuilt firmware release or the original buildable source code.

- [Device source](firmware/v3.4.7/device/) — presents the USB device to the PC.
- [Host source](firmware/v3.4.7/host/) — communicates with the attached peripheral.

The `.c` files are grouped by subsystem: application logic, UART, USB/DWC2, clocks, timers, RTOS, memory and runtime support. Recovered structs and declarations live in each MCU's `include/types.h`.

Review replaces decompiler placeholders with readable function names, typed parameters, verified struct layouts and `/* behavior */` comments. Each function retains its native address and original firmware-byte hash. Entries awaiting subsystem placement remain under `pending/`.

**Current exhaustive audit:** 1,500 of 3,399 native functions reviewed. This pass checks function bodies, names, parameters, return types, structs and comments against the firmware. The remaining functions are pending this audit.

## Open to inspection

Medius and other K4 firmware can be examined through reverse engineering to investigate timings, internal behavior, execution paths and potential attack vectors. Explore the code yourself, or ask an AI to help trace functions. Check its conclusions against the firmware.

## MAKCU Belongs to Its Community

I created MAKCU and shared it as a gift, out of my own kindness. Open source made that sharing possible; it does not give anyone ownership of the community.

Pasting AI-generated code does not entitle anyone to claim ownership of the MAKCU community or rename it. Nobody stands above anyone else here—only equals.

Anything built on MAKCU should stand up to scrutiny. Be open about the work, support your claims and give credit where it belongs.

Have fun. Peace.
