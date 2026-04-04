![alt text](banner.png)
# Analysis — 489.exe (RAT - Remote Access Trojan)
**Date:** 2026-03-28  
**Analyst:** dd1d3
**Skill level:** beginner
**Sample:** `489.exe`  
**Classification:** Telegram-based RAT (Remote Access Trojan)

---

## Disclaimer

This analysis was conducted in an isolated VM environment for educational purposes only. No malicious code was executed outside a sandbox.

---

## Overview

`489.exe` is a Python based RAT compiled with **Nuitka** — a Python-to-C/C++ transpiler. The author chose Nuitka over PyInstaller for a reason: Nuitka compiles Python down to native C code, producing a faster and harder-to-reverse binary compared to a standard PyInstaller bundle. The resulting executable looks like a native C/C++ binary to most tools, which makes initial triage misleading.

The malware uses **Telegram's Bot API as its C2 channel**, communicates over `api.telegram.org:443`, and drops a persistent copy of itself under a disguised name in AppData.

> Note: This is my first real binary analysis. Some conclusions may be incomplete, but everything documented here is based on observed evidence.

---

## Sample Info

| Field | Value |
|-------|-------|
| Filename | `489.exe` |
| File size | 72.98 MiB |
| Architecture | AMD64 (x86_64) |
| File type | PE64 |
| Compiler | Microsoft Visual C/C++ 19.36 |
| Language | Python (compiled via Nuitka) |
| Packer | Nuitka OneFile |
| GUI | No |

---

## Stage 1 — Initial Triage with DIE

Loaded `489.exe` into **Detect It Easy (DIE)**. Key findings:

- **Language: Python** — confirmed Python origin
- **Packer: PyInstaller [overlay; modified]** — outer wrapper is PyInstaller
- **Heuristic packer: Compressed or packed data [Strange overlay]** — suspicious overlay section
- **Overlay:** Raw Deflate stream + ZLIB compression

This told me the outer shell is PyInstaller but something inside is further packed  a double-layer approach.

After extracting with **pyinstxtractor**, the inner binary `contentIndex.exe` showed:

- **Packer: Nuitka [OneFile]**
- **Language: C** (Nuitka output)
- High entropy section `.rsrc` compressed

So the structure is: `489.exe` 

![alt text](preview.png)

![alt text](preview3.png)
---

## Stage 2 — Extraction with pyinstxtractor

```
python pyinstxtractor.py 489.exe
```

Extracted 27 files from the CArchive. Entry points identified:

- `pyiboot01_bootstrap.pyc`
- `pyi_rth_inspect.pyc`
- `main.pyc`

The extracted directory also contained `contentIndex.exe` (61 MB) — the actual payload — along with standard Python DLLs and extension modules.

> Warning during extraction: version mismatch between Python 3.14 (my machine) and Python 3.10 (build environment). This caused `.pyz` extraction to be skipped, but the core binary was still accessible.

![alt text](preview1.png)
![alt text](preview2.png)
---

## Stage 3 — Persistence Mechanism

While `489.exe` ran, Task Manager revealed a suspicious process:

**`SysSettingSvc.exe`** running from:
```
C:\Users\tprjh\AppData\Roaming\Microsoft\Windows\ConfigService\SysSettingSvc.exe
```

Red flags:
- Located in **AppData\Roaming** — not a system path (I could have made a mistake)
- Name mimics a legitimate Windows service (`SysSettingSvc`)
- **No digital signature** — file properties show empty Description, Version, Copyright fields
- Created and modified at the same timestamp  dropped at runtime

This is a classic persistence technique: copy the payload to a disguised location under AppData and name it to blend in with Windows services.

![alt text](preview8.png)

---

## Stage 4 — Ghidra Analysis of SysSettingSvc.exe

### Onefile temp extraction (critical finding)

In the decompiler output, a key function was identified:

```c
uVar13 = FUN_140007c70(&DAT_140047100, L"%TEMP%\\onefile_{PID}_{TIME}", 0x1000);
```

This confirms the **Nuitka OneFile** self-extraction behavior: when the binary runs, it unpacks itself into a temp directory at `%TEMP%\onefile_{PID}_{TIME}`. This is not hiding it is a side effect of the OneFile packaging that the author left intact. The entire unpacked project ends up in that temp folder, which turned out to be a critical mistake.

### Import table (selected)

Notable imports found in the symbol tree:
- `CopyFileW` — file copying (used for persistence drop)
- `CreateDirectoryW` — directory creation
- `CreateFileMappingW` — memory-mapped file operations
- `CreateFileW`, `CreateProcessW`
- `DeleteCriticalSection`, `DeleteFileW`

### CPU identification routine

A separate function block performs **CPUID enumeration**:

```c
puVar3 = (uint *)cpuid_basic_info(0);
if (6 < *puVar3) {
    lVar39 = cpuid_Extended_Feature_Enumeration_info(7);
    uVar30 = *(uint *)(lVar39 + 4) >> 8 & 1;
}
```

This checks for CPU extended features likely used for environment detection or crypto operations (AVX2 support check is common in modern malware for performance-oriented AES).   

![alt text](preview5.png)
![alt text](preview6.png)
![alt text](preview7.png)
---

## Stage 5 — Network Analysis with FakeNet-NG

Running the sample under **FakeNet-NG** captured the following:

```
SysSettingSvc.exe (2880) → DNS query: api.telegram.org
SysSettingSvc.exe (2880) → TCP 192.0.2.123:443
SysSettingSvc.exe (2880) → TCP 127.0.0.1:49705
SysSettingSvc.exe (2880) → TCP 127.0.0.1:49706
```

The malware repeatedly queries `api.telegram.org` — this is the C2 channel. Telegram Bot API over HTTPS port 443 is a common technique to blend C2 traffic with legitimate traffic since Telegram is rarely blocked at the network level.

![alt text](preview10.png)
---

## Stage 6 — x64dbg Live API call

At runtime, x64dbg captured the exact moment of the Telegram API call:

```
rcx: L"api.telegram.org"
r14: L"api.telegram.org"
rsi: L"443"
```

This directly confirms the outbound C2 connection to Telegram's API server on port 443, consistent with FakeNet-NG output.
![alt text](preview14.png)
---

## Stage 7 — Onefile temp folder contents (author's mistake)

Because the author used **Nuitka OneFile** without cleaning up the temp directory, the full unpacked project was accessible at:

```
%TEMP%\onefile_2576_134195020301743770\
```

Contents included `bot_script.dll` — the actual bot logic — along with Python DLLs, `libssl`, `libcrypto`, `tkinter`, and other dependencies. 50 files total.

The presence of `bot_script.dll` is significant it means the bot logic was compiled separately and loaded dynamically.

![alt text](preview12.png)
![alt text](preview11.png)
![alt text](preview14-1.png)
---

## Stage 8 — translations.json (author identity leak)

Inside the temp folder, a `translations.json` file was found. It contained bilingual (RU/EN) strings for the RAT's control panel, including:

```json
"massage_pc_start": {
    "ru": "Компьютер жертвы включён. [...] Оригинальный тгк проекта: \\@batpere",
    "en": "The victim's computer is turned on. [...] Original tgk project: \\@batpere"
}
```

The author **embedded their own Telegram handle** (`@batpere`) in the translation strings as a project credit. This is a direct attribution artifact — the author advertised the RAT's original Telegram channel inside the binary itself.

![alt text](preview13-1.png)
---

## Stage 9 — bot_script.dll string analysis (Ghidra)

Filtered strings in `bot_script.dll` for `telegram`:

```
aiogram.client.telegram
aiogram.dispatcher.event.telegram...
aiogram.types.transaction_partner...
suTelegram Desktop
suC:\Program Files\Telegram Desktop\...
uTelegram.exe
Bot class\n\n  :param ...
uhttps://api.telegram.org/bot{token}/test/{method}
```

Key takeaways:
- Built on **aiogram** — a Python async Telegram bot framework 
- Targets **Telegram Desktop** — likely for session stealing or screenshot capture 
- Contains full Telegram Bot API endpoint template: `https://api.telegram.org/bot{token}/test/{method}`

![alt text](preview15.png)
---

## Summary

| Finding | Evidence |
|---------|----------|
| Python RAT compiled with Nuitka | DIE detection, Ghidra C output |
| PyInstaller outer wrapper | DIE overlay detection, pyinstxtractor |
| Persistence in AppData | SysSettingSvc.exe in ConfigService folder |
| No digital signature | File properties — all fields empty |
| C2 via Telegram Bot API | FakeNet-NG DNS + TCP logs |
| Live API call confirmed | x64dbg rcx/r14 = api.telegram.org |
| Author identity leak   |  in translations.json |
| Bot framework: aiogram | bot_script.dll string table |
| Self-unpacks to %TEMP% | Nuitka OneFile — onefile_{PID}_{TIME} |

---

## IOCs

```
Filename (dropped):  SysSettingSvc.exe
Path:                %APPDATA%\Microsoft\Windows\ConfigService\
C2:                  api.telegram.org:443
Author handle:       @batpere (Telegram)
Bot framework:       aiogram (Python)
Temp path pattern:   %TEMP%\onefile_*
```

---

## Tools Used

| Tool | Purpose |
|------|---------|
| Detect It Easy (DIE) | Initial triage, packer detection |
| pyinstxtractor | PyInstaller unpacking |
| Ghidra | Static analysis, decompilation |
| x64dbg | Dynamic analysis, API call tracing |
| FakeNet-NG | Network traffic interception |
| Task Manager | Process discovery |

---

## Screenshots

All screenshots used in this analysis are located in the `screenshots/` directory:

- `screenshots/banner.png`
- `screenshots/preview.png`
- `screenshots/preview1.png`
- `screenshots/preview2.png`
- `screenshots/preview3.png`
- `screenshots/preview5.png`
- `screenshots/preview6.png`
- `screenshots/preview7.png`
- `screenshots/preview8.png`
- `screenshots/preview10.png`
- `screenshots/preview11.png`
- `screenshots/preview12.png`
- `screenshots/preview13-1.png`
- `screenshots/preview14.png`
- `screenshots/preview14-1.png`
- `screenshots/preview15.png`

---

*First writeup — feedback welcome. Analysis conducted in isolated VM.*
