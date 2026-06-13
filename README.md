# PT9 Answer-Recovery — Distribution

A tool that extracts the **answer configurations** from a Packet Tracer **`.pka`** activity file and neatly saves them per device into a `*.answers.txt` file. Works with **Cisco Packet Tracer 9.0.x** (64-bit Windows).

## Contents

```text
recover_answers.py     launcher
pka_answers\           tool modules (discover / xml_source / parse / render)
qunc_dump.py           runtime-dump backend (starts PT, reads the decrypted XML)
find_export.py         helper (automatically finds qUncompress for each PT build)
vendor\                pymem wheel for offline installation
setup.bat / run_demo.bat / run.bat
```

## Requirements

- **Python 3.10+ (64-bit)** — from <https://python.org>, with **"Add python.exe to PATH"** enabled.
- **pymem** — installed offline from `vendor\` by `setup.bat`. (The only dependency; required for real extraction, not for the demo.)
- For **real extraction**: **Cisco Packet Tracer 9.0.x** installed (the tool launches it automatically).
  The demo does **not** require Packet Tracer.

## Quick Start

### 1. Setup (one-time)

Double-click:

```bat
setup.bat
```

### 2. Real File Extraction (Packet Tracer Required)

1. Close **all** open Packet Tracer windows.
   Otherwise, startup may be redirected to an existing instance and the file may not load correctly.

2. Run a single file:

```bat
run.bat --file "C:\path\to\your.pka"
```

Or process an entire folder:

```bat
run.bat --folder "C:\folder\with\pka\files"
```

3. Packet Tracer starts automatically (first launch may take ~1–2 minutes). The tool reads the decrypted activity and writes:

```text
your.answers.txt
```

next to the original `.pka` file.

The decrypted XML is cached as:

```text
your.activity.xml
```

so subsequent runs complete immediately.

## How It Works

Packet Tracer internally unpacks a `.pka` file using `Qt6Core.dll::qUncompress`.

This tool launches Packet Tracer under a debugger, intercepts that call, and saves the **fully decrypted activity XML**—without cracking the activity wizard password.

It then automatically selects the **answer network** (the fully configured network) and extracts the configuration for each device:

- **Routers / Switches**
  - Complete IOS running configuration
  - Ready to copy and paste

- **PCs / Servers**
  - IP address
  - Subnet mask
  - Default gateway
  - DNS settings
  - DHCP status
  - VLAN information (best effort)

## Output

One `*.answers.txt` file is generated per `.pka`, organized by device.

## Notes

- **Windows 64-bit only**
- No administrator privileges required (must be run under the same user account as Packet Tracer)
- Works with arbitrary activities (any number of devices or networks)
- `qUncompress` is located automatically for each Packet Tracer build
- A custom Packet Tracer installation path can be specified with the `PT_EXE` environment variable
- Intended as a reverse-engineering and security learning exercise on **your own** `.pka` files
