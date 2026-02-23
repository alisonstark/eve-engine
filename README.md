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
  18 unit tests validate all detection functions independently with 100% pass rate.

- 🔄 **Automatic List Updates**  
  Hijackable DLLs and LOLBins lists auto-update from GitHub if older than 24 hours.

- ⚙️ **Custom Time-Based Filtering**  
  Filter logs based on event time to focus on recent or targeted activity.

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
# Export: json or skip
```

---

## 🏗️ Architecture

### Detection Functions (scanners.py)
All detection functions follow this pattern:
- **Input**: Event data rows and optional parameters (target_dll, include_context, etc.)
- **Output**: Dictionary with structured results
- **No side effects**: No printing, no file I/O, no user interaction

Example return structure:
```python
{
    "detected_events": [...],      # Primary detections
    "context_events": [...],       # Context-filtered events (if requested)
    "earliest_time": datetime,     # First detection timestamp
    "commands": [...],             # Extracted command lines
    "detection_type": "DLL Hijacking",
    "count": 5,                    # Number of detections
    "context_count": 12            # Number of context events
}
```

### Presentation Layer (scanners.py)
- `print_detection_result(result)` - Console output
- `print_detection_summary(result)` - Brief summary
- `export_results_to_json(result, evtx_path)` - JSON export

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
