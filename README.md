<div align="center">

# 🛡️ ShadowLens XDR

**A lightweight, modular forensic file-analysis & threat-triage engine.**
One scan. One score. Every angle covered.

[![Python](https://img.shields.io/badge/Python-3.8%2B-3776AB?style=for-the-badge&logo=python&logoColor=white)](https://www.python.org/)
[![License: MIT](https://img.shields.io/badge/License-MIT-yellow?style=for-the-badge)](LICENSE)
[![Platform](https://img.shields.io/badge/Platform-Kali%20%7C%20Linux-557C94?style=for-the-badge&logo=linux&logoColor=white)](#)
[![Status](https://img.shields.io/badge/Status-Active-brightgreen?style=for-the-badge)](#)
[![Made with ❤](https://img.shields.io/badge/Made%20with-%E2%9D%A4-red?style=for-the-badge)](#)

</div>

---

Point it at a file and it tells you what the file **actually is** (not
just its extension), what's **hidden inside it**, and **how risky it
looks** — with a clear 0–100 score, color-coded terminal report, and
optional JSON/TXT export. Built to unify the five tools an analyst
normally has to juggle (ExifTool, VirusTotal, a URL checker, a
phishing-keyword scan, and manual file inspection) into a single
command.

## 📌 Features

- **Stage 1 — File Ingestion & Type Detection**: identifies true file
  type from magic bytes (not extension), including OOXML sub-typing
  (DOCX/XLSX/PPTX).
- **Stage 2 — Universal Analysis**:
  - Metadata extraction (via `exiftool` if installed) with anomaly
    checks (future-dated timestamps, known malicious-tool signatures).
  - Shannon entropy analysis to flag hidden encrypted/compressed
    payloads.
  - String extraction (ASCII + UTF-16) with URL/IP/email parsing and
    threat-keyword matching.
- **Stage 3 — Format-Specific Modules**: PDF (JS/OpenAction/Launch/
  embedded files), Office (VBA macros, DDE injection, external
  relationships), Archives (password protection, path traversal, zip
  bombs), Images (trailing-data/steganography check), Email (SPF/
  DKIM/DMARC, Reply-To spoofing).
- **Stage 4 — URL Reputation**: suspicious TLDs, known shorteners,
  typosquat detection, live DNS resolution, optional VirusTotal hook.
- **Stage 5 — Phishing/Social Engineering Detection**: urgency
  language, credential-harvesting phrases, Unicode homograph
  characters.
- **Stage 6 — Obfuscation Detection**: Base64/hex blocks, decodes and
  checks for embedded executables, PowerShell `-EncodedCommand`
  detection.
- **Stage 7 — Risk Scoring**: severity-weighted, sigmoid-compressed
  0–100 score with a Clean/Low/Medium/High/Critical verdict.
- **Stage 8 — Reporting**: color-coded terminal report plus optional
  JSON/TXT export.

## ⚙️ Installation

```bash
git clone https://github.com/<your-username>/shadowlens-xdr.git
cd shadowlens-xdr
bash install.sh
```

`install.sh` only installs the optional `exiftool` system package for
richer metadata extraction — the tool works without it.

## 🚀 Usage

```bash
python3 shadowlens.py path/to/file.pdf
python3 shadowlens.py suspicious.docx --save-report --format json
python3 shadowlens.py archive.zip --no-dns
```

### 🔧 Options

| Flag             | Description                                        |
|-------------------|-----------------------------------------------------|
| `--save-report`   | Save the full report into `reports/`                |
| `--format`        | `json` (default) or `txt` report format              |
| `--vt-key KEY`    | Optional VirusTotal API key for URL lookups          |
| `--no-dns`        | Skip live DNS resolution of extracted URLs           |

## 🗂️ Project structure

```
shadowlens/
├── shadowlens.py        # CLI entry point
├── install.sh           # Optional dependency installer
├── requirements.txt
├── modules/
│   ├── filetype.py       # Stage 1
│   ├── metadata.py        # Stage 2
│   ├── entropy.py         # Stage 2
│   ├── string_extractor.py# Stage 2
│   ├── pdf_module.py      # Stage 3
│   ├── office_module.py   # Stage 3
│   ├── archive_module.py  # Stage 3
│   ├── image_module.py    # Stage 3
│   ├── email_module.py    # Stage 3
│   ├── url_reputation.py  # Stage 4
│   ├── phishing.py        # Stage 5
│   ├── obfuscation.py     # Stage 6
│   ├── scoring.py         # Stage 7
│   └── report.py          # Stage 8
└── reports/               # Saved scan reports land here
```

## ⚠️ Disclaimer

This is a defensive triage/learning tool, not a substitute for a full
antivirus/EDR product or professional incident-response process.
Always analyze untrusted files in an isolated/sandboxed environment.

## 📄 License

Released under the [MIT License](LICENSE).

---

<div align="center">
Made for analysts who are tired of juggling five tools for one file. 🔍
</div>
