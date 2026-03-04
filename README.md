# EVE - Event Verification Engine

## 📋 Table of Contents

- [Overview](#-overview)
- [Features](#-features)
- [Requirements](#-requirements)
- [Installation](#-installation)
- [Project Structure](#-project-structure)
- [Usage](#-usage)
- [Sample Data](#-sample-data)
- [Architecture](#-architecture)
- [Testing](#-testing)
- [Future Improvements](#-future-improvements)

---

## 🧠 Overview

**EVE (Event Verification Engine)** is a Python-based tool for analyzing Windows Event Logs, with a focus on detecting security-relevant behavior by leveraging **ETW (Event Tracing for Windows)** concepts and **Sysmon** logs.

EVE is designed for **SOC analysts**, **threat hunters**, and anyone working with **Windows-based security telemetry**.

It provides detection capabilities for:

- 🧬 **DLL Hijacking** - Detect suspicious DLL load events by analyzing executable processes
- 🧨 **Unmanaged PowerShell Execution** - Identify CLR injection and PowerShell execution from non-standard processes
- 🧠 **LSASS Dumping Attempts** - Detect attempts to dump LSASS memory for credential theft
- 🧪 **Suspicious Parent-Child Process Relationships (Strange PPID)** - Identify unusual process creation patterns
- 🔐 **Brute Force / Failed Login Attempts** - Detect repeated authentication failures and account lockout patterns
- 🧹 **Event Log Clearing/Tampering** - Identify anti-forensics behavior such as log clearing or logging service disruption
- ⚙️ **New Service Creation/Modification** - Detect suspicious service installation and persistence activity
- ⏰ **Scheduled Task Creation/Modification** - Detect potential persistence via task scheduler abuse
- 👤 **Account Manipulation** - Detect unauthorized account creation and privileged group membership changes

In addition to raw detections, EVE supports **incident aggregation and cross-detection summaries** to reduce duplicate alerts and surface higher-signal incidents.

All detections can be exported to **JSON or CSV format** for further analysis or reporting.

---

## ✨ Features

- 🔍 **Pure Detection Functions**  
  Clean, testable detection logic separated from presentation and user interaction. All functions return structured data (dicts) for composability and reusability.

- 📋 **Context Filtering**  
  Optionally include contextual events around detections for deeper analysis. User configurable via interactive prompts.

- 📁 **Flexible Export Formats**  
  Export detection results to JSON, CSV, or both. Files saved to configurable output directory with automatic naming.

- 📂 **Multi-Format Log Input** ⭐ **NEW**  
  Auto-detects and validates input format with fallback handling:
  - **EVTX** (binary) - Full Windows event log support with rich metadata
  - **CSV** (exported) - Fast parsing from Event Viewer exports (~10x faster than EVTX)
  - **JSON** (PowerShell) - Structured format from `Get-WinEvent | ConvertTo-Json` (~10x faster)
  - **EVT** (legacy) - Detects but recommends conversion to modern formats
  - **Smart Validation** - Checks file magic bytes/headers, not just extension (detects tampered files)
  - **Error Handling** - Clear messages if format is invalid or unsupported

- 🧪 **Comprehensive Unit Tests**  
  62 unit tests validate all detection functions, aggregation logic, risk scoring, and return value structure with 100% pass rate.

- 🔄 **Automatic List Updates (24-hour cache)**  
  Hijackable DLLs and LOLBins lists auto-update from GitHub if older than 24 hours. Supports optional GitHub token for higher API rate limits.

- ⏱️ **Advanced Time-Based Filtering**  
  Filter detected events by time window. Supports flexible input formats:
  - `1m` = 1 minute, `30s` = 30 seconds, `1.5m` = 1.5 minutes
  - Explicit `all` or blank entry for unlimited events from detection onwards
  - Both primary detections and context events filtered by specified window
  - Time-frame metadata exported with JSON (shows applied time window)
  - Progressive event processing with 100-event checkpoint (user can continue loading)

- 🎯 **Multi-Factor Risk Scoring**  
  Intelligent filtering of detections by suspicious behavior patterns:
  - **DLL Hijacking**: Context-aware scoring distinguishes legitimate app-owned DLLs (+5) from suspicious cross-process loads (+30+) and user-writable locations (+50)
  - **Unmanaged PowerShell**: Type-specific scoring for CLR DLL loads, process injection patterns, and network anomalies
  - **LSASS Dump**: Scores by access rights, source process reputation, and user privilege levels
  - **Strange PPID**: Rates parent-child pairs by process type combinations and behavior indicators
  - Shows both high-confidence alerts and full detection list for reference
  - Reduces false positives ~90% while maintaining detection sensitivity

---

## ⚙️ Requirements

- **Python**: 3.11+ (3.12.7 or higher recommended)
- **Dependencies**: Listed in `requirements.txt` (python-evtx, requests)

> 📁 `Get-WinEvent` is used to manually examine logs if needed. No additional installation required on modern Windows systems.

---

## 🧰 Installation

### Prerequisites
Ensure Python 3.11+ is installed. On Linux (Ubuntu/Debian):
```bash
sudo apt install python3 python3-pip python3-venv
```

### Setup

1. **Create virtual environment** (recommended):
```bash
python3 -m venv .venv
source .venv/bin/activate  # On Windows: .venv\Scripts\activate
```

2. **Install dependencies**:
```bash
pip install -r requirements.txt
```

---

## 📁 Project Structure

```
eve-engine/
├── README.md                           # This file
├── requirements.txt                    # Python dependencies
├── LICENSE                             # Project license
├── update_lists.py                     # Utility to update DLL/LOLBins lists from GitHub
│
├── docs/                               # Documentation files
│   ├── changes_summary.md              # Detailed changelog and architecture notes
│   └── eve_application_flowchart.mmd   # Visual application flow and detection logic
│
├── engine/                             # Main application directory
│   ├── __init__.py
│   │
│   ├── src/                           # Application source code
│   │   ├── main.py                    # User interaction & orchestration
│   │   └── scanners.py                # Detection functions + presentation layer
│   │
│   ├── config/                        # Configuration utilities
│   │   ├── utils.py                   # Menu, file I/O, lazy-loaded lists
│   │   ├── logprint.py                # Console formatting utilities
│   │   └── converters.py              # EVTX/CSV conversion utilities
│   │
│   └── data/                          # Reference data, test samples, and exports
│       ├── hijackable_dlls.json       # Known hijackable DLLs (auto-updated from GitHub)
│       ├── lolbins.json               # Living off the Land Binaries (auto-updated from GitHub)
│       ├── manifest.json              # Metadata on generated test data
│       ├── Generate-SecurityTestEvents.ps1  # High-volume test data generator (PowerShell)
│       ├── output/                    # Generated JSON/CSV exports from detections
│       └── test/                      # Sample and generated EVTX files
│           ├── DLLHijack.evtx         # Sample DLL hijacking events
│           ├── PowershellExec.evtx    # Sample unmanaged PowerShell execution
│           ├── LsassDump.evtx         # Sample LSASS dump detection
│           ├── StrangePPID.evtx       # Sample suspicious PPID events
│           ├── brute_force.evtx       # Sample brute force/failed logins
│           ├── log_cleared.evtx       # Sample event log clearing
│           ├── service_system.evtx    # Sample service creation (System log)
│           ├── service_security.evtx  # Sample service creation (Security log)
│           ├── scheduled_task_operational.evtx  # Sample task creation (Operational log)
│           ├── scheduled_task_security.evtx     # Sample task creation (Security log)
│           ├── account_manipulation.evtx        # Sample account/group manipulation
│           └── SecurityLogsLsass.evtx # Sample security logs for LSASS context
│
├── unit_tests/                        # Unit test suite
│   └── test_scanners.py               # 62 pytest tests covering all detections and aggregation
│
└── .git/                              # Git version control
```

---

## 📂 Usage

```bash
cd engine
python3 src/main.py
```

### Runtime Flags

The following behavior is now configured via CLI flags (defaults shown):

- `--include-context` → Include context events (**default: No**)
- `--incident-aggregation` → Aggregate detections into incidents (**default: No**)
- `-e`, `--export-results` → Export format (`json`/`csv`/`both`) (**default: Skip**)
- `-p`, `--evtx-path` → Sysmon `.evtx` path (**default: prompt interactively**)
- `-d`, `--detections` → Detection selection like `1,3,5` or `1-5,9` (**default: menu interactively**)
- `--target-dll` → Optional DLL filter for detections 1 and 2 (e.g., `clr.dll`)
- `--security-evtx-path` → Optional Security `.evtx` path for LSASS context (detection 3)
- `-l`, `--list-detections` → Show detection IDs/names and exit

Optional export path can be provided as the second argument after export type:

```bash
python3 src/main.py --export-results json /path/to/output
python3 src/main.py -e both /path/to/output
```

The program will:
1. Prompt for an EVTX file path
2. Display a menu with detection options
3. Apply CLI flag behavior for context/aggregation/export (or defaults)
4. Show results in the console (raw detections and/or aggregated incidents)

**Menu behavior:**
- If you do **not** pass `-d/--detections`, the interactive menu is shown.
- If you pass `-d/--detections`, the run is non-interactive for detection selection, and EVE prints selected detection names before execution.

### Quick Commands

```bash
# 1) Show detection map and exit
python3 src/main.py -l

# 2) Run non-interactive with explicit detections and JSON export
python3 src/main.py -p /path/to/sysmon.evtx -d 1,3,5 --include-context --incident-aggregation -e json /path/to/output

# 3) Run in interactive mode (menu-driven)
python3 src/main.py
```

### Example Workflow
```bash
# Step 1: list available detections
$ python3 src/main.py --list-detections
1) DLL Hijacking
2) Unmanaged PowerShell
3) LSASS Dump
...

# Step 2: run selected detections non-interactively
$ python3 src/main.py -p /path/to/sysmon.evtx -d 1-3 --include-context --incident-aggregation --target-dll clr.dll --security-evtx-path /path/to/security.evtx -e json /path/to/output

[Selected detections: 1 (DLL Hijacking), 2 (Unmanaged PowerShell), 3 (LSASS Dump)]

[Aggregated incident summary displayed]

[+] JSON export successful: /path/to/output/sysmon_dll_hijacking_<timestamp>.json
```

---

## 🔄 Updating Detection Lists

The detection engine relies on two external reference lists fetched from GitHub:

- **Hijackable DLLs**: Compiled from [wietze/HijackLibs](https://github.com/wietze/HijackLibs) repository
- **LOLBins**: Compiled from [LOLBAS-Project/LOLBAS](https://github.com/LOLBAS-Project/LOLBAS) repository

### Manual Update

To manually update these lists, run:

```bash
python update_lists.py
```

This fetches the latest data from GitHub and saves JSON files to `engine/data/`.

#### 24-Hour Cache

The script automatically checks if existing list files were modified within the last 24 hours. If they're recent, it loads from disk instead of querying GitHub. This:
- ✅ Reduces API quota usage
- ✅ Speeds up execution on repeated runs
- ✅ Works seamlessly for continuous workflows

If you want to force a fresh fetch (ignore the cache), delete the JSON files:
```bash
rm engine/data/hijackable_dlls.json engine/data/lolbins.json
# Then run update_lists.py again
```

### GitHub API Rate Limiting ⚠️

GitHub's public API has rate limits:
- **Authenticated requests**: 5,000 per hour
- **Unauthenticated requests**: 60 per hour

**The script will use fallback lists if API rate limits are exceeded.** To access the full, comprehensive lists and avoid rate limiting, provide a GitHub Personal Access Token (PAT):

#### Setting a GitHub Token

**Option 1: Temporary (current terminal session only)**
```powershell
# PowerShell
$env:GITHUB_TOKEN = "your_pat_here"

# Linux/macOS
export GITHUB_TOKEN="your_pat_here"
```

**Option 2: Permanent (for your user account)**
```powershell
# PowerShell
setx GITHUB_TOKEN "your_pat_here"

# Then restart your terminal or VS Code
```

**Option 3: GitHub Codespaces**
- Go to your repo → Settings → Secrets and variables → Codespaces
- Add a new repository secret named `GITHUB_TOKEN`
- Then restart the Codespace

#### Generating a PAT

1. Go to [GitHub Settings → Tokens](https://github.com/settings/tokens)
2. Create a new **Personal Access Token (PAT)**
3. Select only the `public_repo` scope
4. Copy the token and set it as `GITHUB_TOKEN` (do not commit this to the repository)

### What Happens Without a Token

If the GitHub token is not set, the script will:
1. Attempt to fetch lists from GitHub with unauthenticated requests
2. If rate limited, fall back to hardcoded comprehensive lists (~33 DLLs, ~23 LOLBins)
3. Show a warning message but continue successfully

**Detection still works with fallback lists**, but you'll have fewer DLLs and LOLBins to match against. For comprehensive detection, setting a token is recommended.

---

## 🎯 Input Format Support & Performance

EVE now supports multiple Windows event log formats for flexibility and performance optimization.

### Supported Formats

| Format | Extension | Speed | Best For | Notes |
|--------|-----------|-------|----------|-------|
| **EVTX** | `.evtx` | Medium (~200-500ms/1K events) | Direct log analysis | Native Windows format, richest metadata, optimized with batch processing |
| **CSV** | `.csv` | **Fast** (~100ms/1K events) | ⭐ **Recommended** | Event Viewer export, easily edited/filtered |
| **JSON** | `.json` | **Fast** (~100ms/1K events) | PowerShell pipelines | Structured format, good for API integration |
| **EVT** | `.evt` | Slow | Legacy systems | Windows NT format, limited compatibility |

### EVTX Performance Optimizations

The EVTX parser has been optimized to reduce parsing time by **~40-50%** through:

- **Batch Processing**: Progress indicators every 100 records (instead of logging every record)
- **Cached Namespaces**: Namespace dictionary created once, reused for all records
- **Optimized XPath**: Direct element searches with minimal tree traversals
- **Pre-compiled Datetime Formats**: Faster parsing without exception overhead
- **Filtered Error Reporting**: Only shows first 5 errors (not 1000+)

**Real-world Impact**:
- 10,000 events: ~2-3 seconds (was ~4-5 seconds)
- 100,000 events: ~20-30 seconds (was ~40-50 seconds)

Even with optimizations, **CSV/JSON remain 10-20x faster** due to their text-based format. Use EVTX only when you need direct log access.

### Automatic Format Detection

Eve automatically **detects and validates** the input file format:
```
[*] Detected format: CSV
[*] Parsing CSV (fast format)...
[+] CSV parsed: 1,084 events
```

If the file extension doesn't match the actual format (e.g., .csv renamed to .evtx), EVE will detect the mismatch and report it.

### Converting Logs to Faster Formats

For **best performance** on large log files, export to CSV or JSON:

#### Option 1: Event Viewer → CSV (Easiest)
```powershell
# Export Security log to CSV
Get-WinEvent -LogName Security -MaxEvents 10000 | Select-Object * | Export-Csv -Path "security.csv" -NoTypeInformation

# Export any Sysmon data to CSV
Get-WinEvent -LogName "Microsoft-Windows-Sysmon/Operational" -MaxEvents 10000 | Select-Object * | Export-Csv -Path "sysmon.csv" -NoTypeInformation
```

Then run EVE with the CSV file:
```bash
python3 src/main.py -p security.csv -d 1,3,5 --incident-aggregation
```

#### Option 2: PowerShell → JSON (Structured)
```powershell
# Export to JSON format
Get-WinEvent -LogName Security -MaxEvents 10000 | ConvertTo-Json | Out-File -Path "security.json"
```

**Performance Comparison**:
- EVTX (large files): ~1 minute for 100K events
- CSV/JSON: ~100ms for 100K events
- **Speedup**: 600x faster! ⚡

### Why Format Matters

- **EVTX**: Binary format requires complex parsing, slower but preserves all metadata
- **CSV/JSON**: Text formats, much faster parsing, slightly larger file size but worth it
- **Try CPU-bound detections (DLL Hijacking, PowerShell)**:
  - EVTX: ~30s for 1000 events
  - CSV: ~0.05s for 1000 events

**Recommendation**: For large-scale analysis, convert to CSV first for instant results!

---

## 🧪 Sample Data

The `engine/data/test/` directory contains sample EVTX files for testing and demonstration purposes:

| File | Detection Type | Purpose |
|------|---|---|
| `DLLHijack/DLLHijack.evtx` | DLL Hijacking | Test DLL hijacking detection |
| `PowershellExec/PowershellExec.evtx` | Unmanaged PowerShell | Test CLR/PowerShell injection detection |
| `Dump/LsassDump.evtx` | LSASS Dump | Test LSASS memory dump detection |
| `Dump/SecurityLogs.evtx` | Context Data | Security logs for context filtering |
| `StrangePPID/StrangePPID.evtx` | Strange PPID | Test suspicious parent-child processes |

### Generating Test Data with High-Volume Scenarios

For comprehensive validation and detector tuning, the `Generate-SecurityTestEvents.ps1` PowerShell script creates realistic attack patterns with substantial noise:

```powershell
# Run with default settings (C:\SecurityTestEvtx output)
PS> .\Generate-SecurityTestEvents.ps1

# Specify custom output directory
PS> .\Generate-SecurityTestEvents.ps1 -OutputDir "C:\MyTests"

# Skip noise generation (minimal test files)
PS> .\Generate-SecurityTestEvents.ps1 -SkipNoise

# Run only specific scenarios (1=Brute Force, 2=Log Clear, 3=Services, 4=Tasks, 5=Accounts)
PS> .\Generate-SecurityTestEvents.ps1 -ScenariosToRun @(1,3,5)
```

**What it generates**:
- **Brute Force**: 80-120 failed logins + 200+ successful login noise (validates detection at scale)
- **Service Creation**: 1-2 suspicious services + 15-25 legitimate operations
- **Scheduled Tasks**: 1-2 suspicious tasks + 10-20 legitimate operations
- **Account Manipulation**: 1-2 suspicious accounts + 50+ group query operations
- **Log Clearing**: 1 critical event (low volume by nature)

**Key advantage**: Tests detector accuracy against realistic noise levels. The script maintains version control compatibility for future detector improvements.

### Quick Test
```bash
# Test DLL Hijacking detection with sample data
cd engine
python3 src/main.py
# When prompted: engine/data/test/DLLHijack/DLLHijack.evtx
# Select: 1 (DLL Hijacking Detection)
# Include context: y or n (your choice)
# Time frame: Examples: 1m, 30s, 5 (blank for all)
# Export: json or skip
```

**Time Frame Examples**:
- `1m` → Show detections within 1 minute of earliest event
- `30s` → Show detections within 30 seconds
- `1.5m` → Show detections within 1.5 minutes
- (blank) → Show all detections in the file

---

## 🏗️ Architecture

### Detection Functions (scanners.py)
All detection functions follow this pattern:
- **Input**: Event data rows and optional parameters (target_dll, include_context, etc.)
- **Output**: Dictionary with structured results
- **No side effects**: No printing, no file I/O, no user interaction

Example return structure (DLL Hijacking with risk scoring):
```python
{
    "detected_events": [...],           # All primary detections (raw)
    "high_confidence_events": [...],    # Filtered high-risk events
    "context_events": [...],            # Context-filtered events (if requested)
    "earliest_time": datetime,          # First detection timestamp
    "commands": [...],                  # Extracted command lines
    "detection_type": "DLL Hijacking",
    "count": 77,                        # Total detections
    "high_confidence_count": 8,         # High-risk detections
    "context_count": 12                 # Context events
}
```

### Risk Scoring Layer (scanners.py)
- `score_dll_hijack_risk(event)` - Calculates risk score for each event
- `filter_high_confidence_detections(events)` - Filters by risk threshold (≥40)
- Factors: DLL location, process reputation, suspicious process-DLL combos
- **Result**: 90%+ reduction in false positives for DLL detection

### Presentation Layer (scanners.py)
- `print_detection_result(result)` - Console output with high-confidence highlights
- `print_detection_summary(result)` - Brief summary
- `export_results_to_json(result, evtx_path)` - JSON export with risk scores

### User Interaction (main.py)
- Menu-driven interface with detection selection
- Context filtering prompts
- Export format selection
- Handles all I/O and user input

### File Storage
Exported files are saved to the **same directory as the source EVTX file** with automatic naming:
- Format: `{original_filename}_{detection_type}.json`
- Example: `/path/to/sysmon.evtx` → `/path/to/sysmon_dll_hijacking.json`

### JSON Export Metadata
All JSON exports include high-visibility metadata fields to support analyst workflows:

**Always Included**:
- `detection_type` - Detection name (e.g., "DLL Hijacking")
- `export_date` - ISO timestamp of export
- `time_frame_minutes` - Time window applied (null for unlimited)
- `time_frame_used` - Human-readable time-frame description

**High-Value Analyst Fields**:
- `processes_involved` - Deduplicated list of process basenames involved in detections
  - **Example**: `["cmd.exe", "dism.exe", "explorer.exe"]`
  - **Use**: Quick identification of attack actors without examining individual events
  - **DLL Hijacking**: Source of `Image` field
  - **PowerShell**: Merged from `Image`, `SourceImage`, `TargetImage` fields

- `dlls_targeted` - Deduplicated list of DLL basenames targeted/injected
  - **Example**: `["mscoree.dll", "oleacc.dll", "wininet.dll"]`
  - **Use**: Identify which libraries were abuse vectors
  - **DLL Hijacking**: Source of `ImageLoaded` field
  - **PowerShell**: Merged from CLR DLLs and injected target fields

**Detection Counts**:
- `total_events` / `clr_events` / `injection_events` / `network_events` - Raw detection counts
- `high_confidence_events` - Events meeting risk threshold
- `context_events` - Supporting events (if context filtering enabled)

**Full Example**:
```json
{
  "metadata": {
    "detection_type": "DLL Hijacking",
    "export_date": "2026-03-02T14:30:45.123456",
    "total_events": 15,
    "high_confidence_events": 3,
    "context_events": 8,
    "time_frame_minutes": 5.0,
    "time_frame_used": "5.0 minute(s) from earliest detection",
    "processes_involved": ["cmd.exe", "dism.exe", "explorer.exe"],
    "dlls_targeted": ["mscoree.dll", "oleacc.dll", "wininet.dll"],
    "extracted_commands": [...]
  },
  "detected_events": [
    {
      "EventID": 7,
      "Computer": "HOSTNAME",
      "Image": "C:\\ProgramData\\Dism.exe",
      "ImageLoaded": "C:\\Windows\\System32\\wininet.dll",
      "risk_score": 70,
      "is_high_confidence": true
    },
    ...
  ]
}
```


## 🧪 Testing

The project uses **pytest** (industry-standard Python testing framework) with 62 comprehensive tests.

### Running Tests

Activate the virtual environment, then run:
```bash
# Activate venv (if not already active)
.venv\Scripts\activate  # Windows
source .venv/bin/activate  # Linux/macOS

# Run all tests with verbose output
pytest unit_tests/test_scanners.py -v

# Run specific test
pytest unit_tests/test_scanners.py::test_dll_hijack_no_events -v
```

Expected output: **All 62 tests pass** ✓ (~0.35s execution time)

### Test Coverage

**Detection Functions (50 tests):**
- DLL Hijacking Detection (10 tests)
- Unmanaged PowerShell Execution (5 tests)
- LSASS Dump Detection (6 tests)
- Strange PPID Detection (7 tests)
- Brute Force Detection (5 tests)
- Event Log Clearing Detection (4 tests)
- Service Creation Detection (5 tests)
- Task Creation Detection (4 tests)
- Account Manipulation Detection (6 tests)

**Aggregation Functions (12 tests):**
- `aggregate_incidents()` - Deduplication, grouping, risk filtering, timestamp tracking (8 tests)
- `aggregate_all_detections()` - Multi-detection summary generation (1 test)
- Edge cases: empty results, missing fields (3 tests)

### Test Details

Each test validates detection and aggregation functions independently by:
- Mocking input event data
- Calling detection/aggregation functions
- Using pytest assertions to verify return structures

No side effects, no file I/O, pure business logic testing. Tests follow modern pytest conventions:
- Function-based tests (no class inheritance)
- Clear assert statements
- Descriptive test names

### Installation

Pytest is specified in `requirements.txt`. It's installed automatically when you run:
```bash
pip install -r requirements.txt
```

---

## 🧠 Future Improvements

### High-Priority Detection Additions

The following detections represent core Windows security monitoring capabilities and will be implemented next:

- **Brute Force/Failed Login Attempts**  
  Event IDs 4625 (failed logon), 4648 (explicit credential use), 4740 (account lockouts)  
  Detect repeated authentication failures indicating password spraying or brute force attacks

- **Event Log Clearing/Tampering**  
  Event IDs 1102 (Security log cleared), 1100 (event logging service shutdown)  
  Critical indicator of attacker anti-forensics activities, often seen post-compromise

- **New Service Creation/Modification**  
  Event IDs 7045, 4697 (service installation)  
  Common persistence and privilege escalation technique, especially suspicious when created remotely or with unusual paths

- **Scheduled Task Creation/Modification**  
  Event ID 4698 (scheduled task created)  
  Popular persistence mechanism, monitor for tasks running from suspicious locations or with unusual triggers

- **Account Manipulation**  
  Event IDs 4720 (account created), 4732 (user added to privileged group), 4728 (member added to security-enabled global group)  
  Track unauthorized privilege escalation and backdoor account creation, critical for domain environments

### Secondary Detection Additions

The following detections are valuable but may only be partially implemented, and only after all high-priority detections are complete:

- **Pass-the-Hash/Pass-the-Ticket Detection**  
  Event ID 4624 with logon type 9 (NewCredentials) or type 3 from suspicious sources, NTLM authentication from unusual processes

- **Registry Persistence Mechanisms**  
  Monitor Run keys and services registry modifications (requires Sysmon for best coverage)

- **Sensitive File Access**  
  Event ID 4663 (object access) for SAM/SECURITY/SYSTEM registry hives and NTDS.dit access on domain controllers

- **Kerberos Attacks**  
  Event IDs 4768, 4769, 4770, 4771 (Kerberos ticket operations)  
  Detect Golden/Silver ticket attacks and Kerberoasting

- **Remote Execution/Lateral Movement**  
  Event ID 4624 logon type 3, 10 (remote desktop), WMI activity, PSRemoting session creation

### General Enhancements

- Integration with Sigma rules
- Real-time monitoring via ETW providers
- Excel output support
- Further CLI non-interactive expansion (e.g., security log path and DLL filter flags)
- Web UI dashboard for visualization

---

## 📚 Documentation

- **[changes_summary.md](./docs/changes_summary.md)** - Detailed changelog, architectural decisions, and migration guide for v2.0.0

---

## 📄 License

See [LICENSE](./LICENSE) file for details.

## 🙏 Acknowledgments

- **Security research community** - For sharing offensive tradecraft that informs defensive practices

---

<div align="center">

**Built with 🛡️ for defenders by defenders**

</div>