# 🔍 Windows Forensic Triage Tool v2.1

A Python-based Windows forensic artifact analysis tool developed for **Riphah International University — BS Cybersecurity | Digital Forensics Spring 2026**.

The tool parses six categories of Windows forensic artifacts, correlates events across them, detects anomalies, flags suspicious executions, and produces a full set of audit-grade output files.

---

## 📋 Table of Contents

- [Features](#-features)
- [Architecture](#-architecture)
- [Requirements](#-requirements)
- [Installation](#-installation)
- [Usage](#-usage)
- [Output Files](#-output-files)
- [Anomaly Detection Types](#-anomaly-detection-types)
- [Correlation Engine Scoring](#-correlation-engine-scoring)
- [Forensic Soundness Notice](#️-forensic-soundness-notice)
- [Project Structure](#-project-structure)

---

## ✨ Features

- **6-source artifact parsing** — Prefetch, LNK, Recycle Bin, Jump Lists, Shellbags, and UserAssist
- **Cross-artifact correlation engine** — groups events by filename, file hash, and semantic pattern into scored Correlated Event Chains
- **5-type anomaly detection** — execution without Prefetch, deletion without prior access, silent security tool execution, rapid sequential deletions, and high-value file deletion
- **Suspicious execution detector** — flags executions from TEMP, AppData, Recycle Bin, Downloads, drive roots, and deeply nested paths
- **USB provenance mapping** — extracts volume serial numbers and NetBIOS/MAC data from LNK TrackerDataBlock
- **Interactive HTML timeline** — stacked monthly bar chart + doughnut source breakdown (Chart.js)
- **Dual analysis modes** — `--live` for live triage and `--offline` for forensically sound image analysis
- **Full audit trail** — every file read is MD5 + SHA-256 hashed; all operations are timestamped to `audit_log.txt`

---

## 🏗 Architecture

```
main.py
  ├── PrefetchParser          → C:\Windows\Prefetch\*.pf (v17/23/26/30/31)
  ├── LNKParser               → Recent folder .lnk files + TrackerDataBlock
  ├── RecycleBinParser        → $Recycle.Bin\*\$I* metadata files
  ├── JumpListsParser         → AutomaticDestinations .automaticDestinations-ms
  ├── ShellbagsParser         → NTUSER.DAT / UsrClass.dat BagMRU keys
  ├── UserAssistParser        → NTUSER.DAT UserAssist Count keys (ROT-13 decoded)
  ├── CorrelationEngine       → Filename + hash + semantic cross-artifact correlation
  ├── SuspiciousExecutionDetector → Path-pattern risk analysis
  ├── AnomalyDetector         → 5 forensic anomaly types
  ├── TimelineVisualizer      → Interactive HTML chart
  ├── ForensicSummaryWriter   → Human-readable .txt report
  ├── ReportGenerator         → CSV timeline + full HTML report
  ├── ForensicAuditLogger     → Timestamped audit log + hash verification log
  └── forensic_utils.py       → Shared utilities (FILETIME, path normalisation, etc.)
```

---

## ⚙️ Requirements

- **Python 3.10+** (uses `list[dict]`, `str | None` union syntax)
- **Windows** required for live mode (MAM decompression uses `RtlDecompressBufferEx`)
- Offline mode works on any OS that can mount the image

### Python Dependencies

```
python-registry   # Registry hive parsing (Shellbags, UserAssist)
olefile           # OLE2 compound file parsing (Jump Lists)
```

Install with:

```bash
pip install python-registry olefile
```

---

## 🚀 Installation

```bash
git clone https://github.com/<your-username>/<repo-name>.git
cd <repo-name>
pip install python-registry olefile
```

---

## 📖 Usage

### Live System Triage (fast, academic / IR use)

> ⚠️ Modifies evidence timestamps. Not recommended for court-admissible work.

```bash
python main.py --live --output ./output
```

### Offline Image Analysis (forensically sound)

```bash
# Mount your forensic image first (e.g. with FTK Imager or Arsenal Image Mounter)
python main.py --offline E:\ --output E:\output
```

### Offline with explicit artifact paths

```bash
python main.py --offline E:\ \
    --prefetch "E:\Windows\Prefetch" \
    --users    "E:\Users" \
    --recycle  "E:\$Recycle.Bin" \
    --output   "E:\output"
```

### All flags

| Flag | Description |
|------|-------------|
| `--live` | Analyse the live running system |
| `--offline <PATH>` | Analyse a mounted forensic image rooted at `<PATH>` |
| `--output <DIR>` | Output directory (default: `output`) |
| `--prefetch <DIR>` | Override Prefetch directory path |
| `--users <DIR>` | Override Users directory path |
| `--recycle <DIR>` | Override Recycle Bin directory path |
| `--hive <FILE>` | Provide an explicit NTUSER.DAT path |
| `--username <NAME>` | Target username (default: current user) |
| `--time-window <N>` | Correlation time window in seconds (default: 300) |
| `--debug` | Enable full traceback logging on errors |

---

## 📁 Output Files

All files are written to the `--output` directory:

| File | Description |
|------|-------------|
| `forensic_summary.txt` | Human-readable forensic examination report with Chain of Custody statement |
| `timeline_visual.html` | Interactive stacked bar + doughnut chart (open in any browser) |
| `forensic_report.html` | Full HTML report with all events, chains, anomalies, and USB map |
| `timeline.csv` | Raw event timeline — importable into Excel, Autopsy, or Timeline Explorer |
| `audit_log.txt` | Timestamped audit trail of every operation performed |
| `hashes.txt` | MD5 + SHA-256 of every source artifact file read |

---

## 🚨 Anomaly Detection Types

| Type | Severity | Description |
|------|----------|-------------|
| **TYPE 1** | HIGH | Execution recorded in UserAssist but **no matching Prefetch file** — possible Prefetch disabled or selective clearing |
| **TYPE 2** | MEDIUM | File deleted from Recycle Bin with **no prior access record** in LNK or Jump Lists |
| **TYPE 3** | HIGH | Security/forensic tool confirmed executed via Prefetch but **no UserAssist record** — likely CLI or script execution |
| **TYPE 4** | CRITICAL | **5+ files deleted within 30 seconds** — strong indicator of scripted evidence destruction |
| **TYPE 5** | HIGH/MEDIUM | Deletion of a **high-value file** (`.exe`, `.py`, `.pcap`, `.evtx`, `.kdbx`, `.pem`, etc.) |

---

## 📊 Correlation Engine Scoring

Chains start at a base score of **50** and are capped at **100**:

| Rule | Bonus | Trigger |
|------|-------|---------|
| Extra sources | +15 per source | Each corroborating source beyond the minimum 2 |
| Access → deletion | +25 | File accessed then deleted within the time window |
| Execution → deletion | +20 | Program executed then deleted |
| USB involvement | +15 | Removable drive detected via LNK drive type |
| Bulk deletion | +10 | Part of a bulk deletion event (≥10 files in 60s) |
| Suspicious path | +5 | File path contains TEMP, AppData, Downloads, etc. |
| Security tool + deletion | +10 | Forensic/security tool executed then deleted (anti-forensics) |
| Hash correlation | +8 | Same file content detected under different filenames |

**Significance labels:** Critical (≥85) · High (≥70) · Medium (≥55) · Low (<55)

---

## ⚖️ Forensic Soundness Notice

Running in `--live` mode on an active Windows system **is not forensically sound** for court-admissible evidence. It will:

- Update NTFS last-access timestamps on every file read
- Modify registry `LastWrite` times via `reg save HKEY_CURRENT_USER`
- Alter Prefetch metadata by running Python on the live system

**For legally admissible investigations:**
1. Acquire a full disk image with FTK Imager, `dd`, or Guymager
2. Mount the image read-only
3. Re-run with `python main.py --offline <mount_point>`

The tool documents this distinction in the Chain of Custody section of `forensic_summary.txt`.

---

## 📂 Project Structure

```
.
├── main.py                      # Entry point, argument parser, pipeline orchestrator
├── forensic_utils.py            # Shared utilities: FILETIME conversion, path normalisation
├── audit_logger.py              # Forensic audit logger + hash verification
├── prefetch_parser.py           # Prefetch .pf file parser (v17/23/26/30/31)
├── lnk_parser.py                # LNK shortcut + TrackerDataBlock parser
├── recycle_bin_parser.py        # $Recycle.Bin $I metadata parser
├── jumplists_parser.py          # AutomaticDestinations Jump List parser
├── shellbags_parser.py          # BagMRU shellbag registry parser
├── userassist_parser.py         # UserAssist registry parser (ROT-13)
├── correlator.py                # Cross-artifact correlation engine
├── suspicious_exec_detector.py  # Path-based suspicious execution detector
├── anomaly_detector.py          # 5-type forensic anomaly detection engine
├── timeline_visualizer.py       # Interactive HTML timeline chart
├── forensic_summary_writer.py   # Formatted .txt forensic examination report
└── report_generator.py          # CSV timeline + full HTML report generator
```

---

## 🎓 Academic Context

Developed as a course project for **Digital Forensics — Spring 2026** under **Sir Hummayun Raza** at **Riphah International University**, BS Cybersecurity programme.
