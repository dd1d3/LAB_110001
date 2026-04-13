<img width="860" height="160" alt="banner" src="https://github.com/user-attachments/assets/21dc13d6-0210-467c-859f-1588246899ca" />

**LAB_110001** — Malware Analysis & Reverse Engineering

![Status](https://img.shields.io/badge/status-active-red?style=flat-square)
![Type](https://img.shields.io/badge/type-educational-orange?style=flat-square)
![RE](https://img.shields.io/badge/reverse--engineering-yes-darkred?style=flat-square)
![License](https://img.shields.io/badge/license-MIT-gray?style=flat-square)

*A public research lab focused on malware dissection, binary reversing, and low-level threat analysis.*

</div>

---

## About

LAB_110001 is where I document my work breaking down malware how it's built, how it runs, and how to detect it. Each entry covers a real sample with a full walkthrough: from initial triage to disassembly, behavioral analysis

---

## What's in here

- Reverse engineering of real malware samples static and dynamic
- Annotated disassembly with IDA / Ghidra
- Behavioral analysis: registry, filesystem, network activity
- Breakdowns of malware families: ransomware, RATs, stealers, loaders
- YARA rules written from each analysis
- Notes on packers, obfuscation, and anti-debug techniques

---

## Repository Layout

```
LAB_110001/
├── samples/            # Malware samples — password protected archives (pw: infected)
│   ├── ransomware/
│   ├── trojans/
│   ├── rats/
│   └── stealers/
│
├── analysis/
│   ├── static/         # PE structure, strings, imports, entropy
│   └── dynamic/        # Runtime behavior, network traffic, process activity
│
├── writeups/           # Full walkthroughs readable format, one file per sample
├── tools/              # Helper scripts, IDA/Ghidra plugins, YARA rules
├── screenshots/        # Debugger and disassembler captures
└── sandbox/            # VM configs — FlareVM, REMnux
```

---

## Analysis Workflow

| Stage | What happens | Tools used |
|-------|-------------|------------|
| Triage | File type, hashes, entropy, packer detection | DIE, PE-Bear, ExifTool |
| Static | Disassembly, string extraction, import analysis | IDA Free, Ghidra, DnSpy |
| Dynamic | Execution in sandbox, behavioral capture | x64dbg, ProcMon |
| Network | C2 traffic, DNS, protocol identification | FakeNet-NG, Wireshark |
| Detection | Writing YARA rules, extracting IOCs | YARA |

---


Recommended analysis environments:

- **[FlareVM](https://github.com/mandiant/flare-vm)** — Windows RE environment (IDA, Ghidra, x64dbg pre-installed)
- **[REMnux](https://remnux.org/)** — Linux distro built for malware analysis


---

## References

- [MalwareBazaar](https://bazaar.abuse.ch/) — public sample database
- [Any.run](https://any.run/) — interactive sandbox
- [Hybrid Analysis](https://www.hybrid-analysis.com/) — free automated sandbox
- [VirusTotal](https://www.virustotal.com/)

---

## Disclaimer

All content in this repository is published for **educational and research purposes only**.

Samples are stored in password-protected archives and must never be executed outside of a controlled, isolated environment. Applying any of the techniques documented here against systems without explicit authorization from the owner is illegal. The author takes no responsibility for misuse of any material in this repository.

---

<div align="center">
<sub>LAB_110001</sub>
</div>
