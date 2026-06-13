# PT9 Answer-Recovery — distribution

Tool that extracts the **answer configs** from a Packet Tracer **`.pka`** activity file and writes
them per device to a `*.answers.txt`. Works on Cisco Packet Tracer **9.0.x** (64-bit Windows).

## Folder layout
```
README.md            this file
run.bat              all-in-one launcher (menu + command-line)
pka_answers\         the tool (Python package; also contains the PT-dump backend)
vendor\              pymem wheel (offline install) + requirements.txt
```

## Requirements
- **Python 3.10+ (64-bit)** — from https://python.org, with "Add python.exe to PATH" ticked.
- **pymem** — installed offline from `vendor\` via `run.bat` -> option **1**. (The only dependency.)
- **Cisco Packet Tracer 9.0.x** installed — the tool launches it automatically to read the
  decrypted activity.

## Quick start
Double-click **`run.bat`** and pick from the menu:
1. **Setup** — installs pymem (one-time, offline from `vendor\`).
2. **Process a .pka or folder** — close all open Packet Tracer windows first, then give the path.
   Packet Tracer starts automatically (~1-2 min the first time), the tool reads the decrypted
   activity and writes `your.answers.txt` **next to** the `.pka`. The decrypted XML is cached
   (`your.activity.xml`), so a second run is instant.

**Command-line** also works (arguments go straight to the tool):
```
run.bat --file   "C:\path\to\your.pka"
run.bat --folder "C:\folder\with\pka-files"
```
(equivalent to `python -m pka_answers ...` from this folder.)

## How it works
Packet Tracer unpacks a `.pka` internally via `Qt6Core.dll::qUncompress`. The tool launches PT under
a debugger, intercepts that point and saves the **full decrypted activity XML** — without cracking
the wizard password. It then automatically picks the **answer network** (the fully configured one)
and extracts, per device:
- **routers/switches** -> the complete IOS running-config (copy-paste ready),
- **PCs/servers** -> IP settings (IP/mask/gateway/DNS/DHCP/VLAN), best-effort.

Output = **one** `*.answers.txt` per `.pka`, sorted per device.

## Notes
- **Windows 64-bit only**. No administrator rights needed (same user as PT).
- Works on any activity (any number of devices/networks). `qUncompress` is located automatically per
  PT build; a non-standard PT install path can be forced with the `PT_EXE` environment variable.
- Intended as an RE/security exercise on your **own** `.pka` files.
