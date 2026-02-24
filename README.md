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

All detections can be exported to **JSON or CSV format** for further analysis or reporting.

---

## ✨ Features

- 🔍 **Pure Detection Functions**  
  Clean, testable detection logic separated from presentation and user interaction. All functions return structured data (dicts) for composability and reusability.

- 📋 **Context Filtering**  
  Optionally include contextual events around detections for deeper analysis. User configurable via interactive prompts.

- 📁 **Flexible Export Formats**  
  Export detection results to JSON, CSV, or both. Files saved to same directory as source EVTX file with automatic naming.

- 🧪 **Comprehensive Unit Tests**  
  28 unit tests validate all detection functions, risk scoring, and return value structure with 100% pass rate.

- 🔄 **Automatic List Updates (24-hour cache)**  
  Hijackable DLLs and LOLBins lists auto-update from GitHub if older than 24 hours. Supports optional GitHub token for higher API rate limits.

- ⏱️ **Advanced Time-Based Filtering**  
  Filter detected events by time window. Supports flexible input formats:
  - `1m` = 1 minute, `30s` = 30 seconds, `1.5m` = 1.5 minutes
  - Both primary detections and context events filtered by specified window
  - No time filter = show all events (default)

- 🎯 **Multi-Factor Risk Scoring**  
  Intelligent filtering of detections by suspicious behavior patterns:
  - **DLL Hijacking**: Scores based on DLL location, process type, and loaded binary reputation (77 raw → ~8 high-confidence events)
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
├── CHANGES_SUMMARY.md                  # Detailed changelog and architecture notes
├── requirements.txt                    # Python dependencies
├── LICENSE                             # Project license
│
├── engine/                             # Main application directory
│   ├── __init__.py
│   │
│   ├── src/                           # Application source code
│   │   ├── main.py                    # User interaction & orchestration
│   │   ├── scanners.py                # Detection functions + presentation layer
│   │   └── converters.py              # EVTX parsing utilities
│   │
│   ├── config/                        # Configuration utilities
│   │   ├── utils.py                   # Menu, file I/O, lazy-loaded lists
│   │   ├── logprint.py                # Console formatting utilities
│   │   └── converters.py              # EVTX/CSV conversion
│   │
│   └── data/                          # Reference data and test samples
│       ├── hijackable_dlls.txt        # Known hijackable DLLs
│       ├── lolbins.txt                # Living off the Land Binaries
│       └── test/                      # Sample EVTX files for testing
│           ├── DLLHijack/
│           │   └── DLLHijack.evtx     # Sample DLL hijacking events
│           ├── Dump/
│           │   ├── LsassDump.evtx     # Sample LSASS dump events
│           │   └── SecurityLogs.evtx  # Sample security logs
│           ├── PowershellExec/
│           │   └── PowershellExec.evtx # Sample PowerShell execution events
│           └── StrangePPID/
│               └── StrangePPID.evtx   # Sample suspicious PPID events
│
├── unit_tests/                        # Unit test suite
│   └── test_scanners.py               # 18 tests covering all detections
│
└── update_lists.py                    # Utility to update DLL/LOLBins lists from GitHub
```

---

## 📂 Usage

```bash
cd engine
python3 src/main.py
```

The program will:
1. Prompt for an EVTX file path
2. Display a menu with detection options
3. Ask if you want to include context events
4. Show results in the console
5. Offer export options (JSON/CSV/both)

### Example Workflow
```bash
$ python3 src/main.py
Provide path to Sysmon .evtx file:
> /path/to/sysmon.evtx

[Menu displayed with detection options]

Include context events in analysis? (Y/N):
> y

[Results displayed]

Export results to file? (json/csv/both/skip) [default: skip]:
> json

[+] JSON export successful: /path/to/sysmon_dll_hijacking.json
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

## 🧪 Sample Data

The `engine/data/test/` directory contains sample EVTX files for testing and demonstration purposes:

| File | Detection Type | Purpose |
|------|---|---|
| `DLLHijack/DLLHijack.evtx` | DLL Hijacking | Test DLL hijacking detection |
| `PowershellExec/PowershellExec.evtx` | Unmanaged PowerShell | Test CLR/PowerShell injection detection |
| `Dump/LsassDump.evtx` | LSASS Dump | Test LSASS memory dump detection |
| `Dump/SecurityLogs.evtx` | Context Data | Security logs for context filtering |
| `StrangePPID/StrangePPID.evtx` | Strange PPID | Test suspicious parent-child processes |

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

## 🧪 Testing

Run the unit test suite:
```bash
cd /home/moonpie/Documents/GitHub/eve-engine
PYTHONPATH=engine python3 -m unittest unit_tests.test_scanners -v
```

Expected output: All 18 tests pass ✓

**Test Coverage:**
- DLL Hijacking Detection (7 tests)
- Unmanaged PowerShell Detection (3 tests)
- LSASS Dump Detection (4 tests)
- Strange PPID Detection (4 tests)

### Test Details
Each test validates detection functions independently by:
- Mocking input data
- Calling detection functions
- Asserting on returned data structures

No side effects, no file I/O, pure business logic testing.

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
- CLI flags for non-interactive mode (--detection-type, --export-format, etc.)
- Web UI dashboard for visualization

---

## 📚 Documentation

- **[CHANGES_SUMMARY.md](./CHANGES_SUMMARY.md)** - Detailed changelog, architectural decisions, and migration guide for v2.0.0

---

## 📄 License

See [LICENSE](./LICENSE) file for details.
