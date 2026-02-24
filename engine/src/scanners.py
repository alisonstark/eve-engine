# ===============================
# DLL Hijacking Detection Program
# Unmanaged PowerShell Detection Program
# LSASS Dump Detection Program
# ===============================
#
# REFACTORED: Detection functions now return data structures instead of printing.
# Presentation and user interaction are decoupled from detection logic.

import os
import json
from datetime import datetime
from pathlib import Path
from config.converters import security_evtx_parser, evtx_to_csv
import config.utils as conf
from config.logprint import print_sysmon_event, print_security_event

# Lazy load hijackable_dlls and lolbins - only load when actually used
_hijackable_dlls = None
_lolbins = None

def _get_hijackable_dlls_list():
    """Get hijackable DLLs list, loading on first call (lazy loading)."""
    global _hijackable_dlls
    if _hijackable_dlls is None:
        try:
            _hijackable_dlls = conf.get_hijackable_dlls()
        except Exception:
            _hijackable_dlls = []
    return _hijackable_dlls

def _get_lolbins_list():
    """Get LOLBins list, loading on first call (lazy loading)."""
    global _lolbins
    if _lolbins is None:
        try:
            _lolbins = conf.get_lolbins()
        except Exception:
            _lolbins = []
    return _lolbins


def detect_DLLHijack(data_rows, target_dll=None, include_context=False):
    """
    Detects potential DLL hijacking events by identifying suspicious DLL loads by processes.
    
    Args:
        data_rows: List of event dictionaries
        target_dll: Optional specific DLL to search for (e.g., "malicious.dll")
        include_context: If True, filter context events from earliest detection time
    
    Returns:
        {
            "detected_events": [...],       # List of detected DLL load events
            "context_events": [...],        # List of context-filtered events (if include_context=True)
            "earliest_time": datetime,      # Earliest detection time
            "commands": [...],              # Extracted malicious command lines
            "detection_type": "DLL Hijacking",
            "count": int,
            "context_count": int
        }
    """
    spotted_rows = []
    earliest_event_time = None
    hijackable_dlls_lower = [dll.lower() for dll in _get_hijackable_dlls_list()]
    extracted_commands = []

    # ================== DETECTION PHASE ==================
    for row in data_rows:
        event_id = row.get("EventID", "")
        image = row.get("Image", "")
        image_loaded = row.get("ImageLoaded", "")

        if event_id == '7' and image.endswith(".exe") and image_loaded:
            dll_name = os.path.basename(image_loaded).split("\\")[-1].lower()
            event_time = row.get("DateTime", "")
            
            if earliest_event_time is None or (event_time and event_time < earliest_event_time):
                earliest_event_time = event_time

            is_target = target_dll and target_dll.lower() == dll_name
            is_hijackable = not target_dll and dll_name in hijackable_dlls_lower
            
            if is_target or is_hijackable:
                spotted_rows.append(row)
                cmdline = row.get("CommandLine", "")
                if cmdline:
                    extracted_commands.append(cmdline)

    # ================== CONTEXT FILTERING PHASE ==================
    context_events = []
    if include_context and earliest_event_time and spotted_rows:
        context_events, user_minutes = conf.get_events_filtered_by_time(data_rows, earliest_event_time)
        
        # Also filter primary detections by the same time window
        if user_minutes is not None and user_minutes > 0:
            spotted_rows = conf.filter_events_by_time(spotted_rows, earliest_event_time, user_minutes)
        
        for event in context_events:
            cmdline = event.get("CommandLine", "")
            if cmdline and cmdline not in extracted_commands:
                extracted_commands.append(cmdline)

    return {
        "detected_events": spotted_rows,
        "context_events": context_events,
        "earliest_time": earliest_event_time,
        "commands": list(set(extracted_commands)),  # Remove duplicates
        "detection_type": "DLL Hijacking",
        "count": len(spotted_rows),
        "context_count": len(context_events)
    }


def detect_UnmanagedPowerShell(data_rows, target_dll=None, include_context=False):
    """
    Detects unmanaged PowerShell execution by identifying CLR DLL loads (clr.dll, clrjit.dll)
    and correlating them with process injection (Event ID 8, 10) and network activity (Event ID 3).
    
    Args:
        data_rows: List of event dictionaries
        target_dll: Optional specific DLL to search for
        include_context: If True, filter context events from earliest detection time
    
    Returns:
        {
            "clr_events": [...],            # CLR DLL load events
            "injection_events": [...],      # Process injection events
            "network_events": [...],        # Network connection events
            "context_events": [...],        # Context-filtered events
            "earliest_time": datetime,
            "commands": [...],
            "detection_type": "Unmanaged PowerShell",
            "clr_count": int,
            "injection_count": int,
            "network_count": int,
            "context_count": int
        }
    """
    CLR_DLLS = ["clr.dll", "clrjit.dll"]
    EVENT_IMAGE_LOAD = '7'
    EVENT_CREATE_REMOTE_THREAD = '8'
    EVENT_PROCESS_ACCESS = '10'
    EVENT_NETWORK_CONNECT = '3'
    HTTPS_PORT = "443"
    lolbins_lower = [lolbin.lower() for lolbin in _get_lolbins_list()]

    clr_hits = []
    injection_suspects = []
    network_alerts = []
    earliest_event_time = None
    powershell_commands = []

    # ================== COLLECTION PHASE ==================
    for row in data_rows:
        event_id = row.get("EventID", "")

        if event_id == EVENT_IMAGE_LOAD:
            image_loaded = row.get("ImageLoaded", "")
            if not image_loaded:
                continue

            dll_name = os.path.basename(image_loaded).split("\\")[-1].lower()
            is_target_match = target_dll and target_dll.lower() == dll_name
            is_clr_dll = not target_dll and dll_name in CLR_DLLS

            if is_target_match or is_clr_dll:
                clr_hits.append(row)
                cmdline = row.get("CommandLine", "")
                image = row.get("Image", "").lower()
                if cmdline and "powershell" in image:
                    powershell_commands.append(cmdline)

                event_time = row.get('DateTime')
                if earliest_event_time is None or event_time < earliest_event_time:
                    earliest_event_time = event_time

        elif event_id == EVENT_CREATE_REMOTE_THREAD or event_id == EVENT_PROCESS_ACCESS:
            injection_suspects.append(row)
            cmdline = row.get("CommandLine", "")
            image = row.get("Image", "").lower()
            if cmdline and "powershell" in image:
                powershell_commands.append(cmdline)

        elif event_id == EVENT_NETWORK_CONNECT:
            network_alerts.append(row)
            cmdline = row.get("CommandLine", "")
            image = row.get("Image", "").lower()
            if cmdline and "powershell" in image:
                powershell_commands.append(cmdline)

    # ================== CONTEXT FILTERING PHASE ==================
    context_events = []
    filtered_injection_events = []
    filtered_network_events = []

    if include_context and earliest_event_time and clr_hits:
        context_events, user_minutes = conf.get_events_filtered_by_time(data_rows, earliest_event_time)

        # Also filter primary detections by the same time window
        if user_minutes is not None and user_minutes > 0:
            clr_hits = conf.filter_events_by_time(clr_hits, earliest_event_time, user_minutes)
            injection_suspects = conf.filter_events_by_time(injection_suspects, earliest_event_time, user_minutes)
            network_alerts = conf.filter_events_by_time(network_alerts, earliest_event_time, user_minutes)

        for event in context_events:
            event_id = event.get("EventID", "")

            if event_id == EVENT_PROCESS_ACCESS or event_id == EVENT_CREATE_REMOTE_THREAD:
                source_image = event.get("SourceImage", "").lower()
                target_image = event.get("TargetImage", "").lower()
                
                source_binary = os.path.basename(source_image).lower() if source_image else ""
                target_binary = os.path.basename(target_image).lower() if target_image else ""

                if (source_binary in lolbins_lower) or (target_binary in lolbins_lower):
                    filtered_injection_events.append(event)

            elif event_id == EVENT_NETWORK_CONNECT:
                image = event.get("Image", "").lower()
                binary = os.path.basename(image).lower() if image else ""
                dest_port = event.get("DestinationPort", "")

                if (binary in lolbins_lower) and dest_port == HTTPS_PORT:
                    filtered_network_events.append(event)

    return {
        "clr_events": clr_hits,
        "injection_events": filtered_injection_events if include_context else injection_suspects,
        "network_events": filtered_network_events if include_context else network_alerts,
        "context_events": context_events,
        "earliest_time": earliest_event_time,
        "commands": list(set(powershell_commands)),
        "detection_type": "Unmanaged PowerShell",
        "clr_count": len(clr_hits),
        "injection_count": len(filtered_injection_events) if include_context else len(injection_suspects),
        "network_count": len(filtered_network_events) if include_context else len(network_alerts),
        "context_count": len(context_events)
    }


def detect_LsassDump(data_rows, include_context=False, security_logs_rows=None):
    """
    Detects LSASS memory dump attempts by identifying ProcessAccess events (Event ID 10)
    targeting lsass.exe with full memory access rights.
    
    Args:
        data_rows: List of event dictionaries
        include_context: If True, filter context events from security logs
        security_logs_rows: Optional list of security log events for context filtering
    
    Returns:
        {
            "detected_events": [...],       # LSASS dump attempt events
            "context_events": [...],        # Context-filtered security events
            "earliest_time": datetime,
            "commands": [...],
            "detection_type": "LSASS Dump Attempt",
            "count": int,
            "context_count": int
        }
    """
    EVENT_PROCESS_ACCESS = '10'
    FULL_ACCESS_RIGHTS = "0x001fffff"
    TARGET_PROCESS = "lsass.exe"

    spotted_rows = []
    earliest_dump_time = None
    extracted_commands = []

    # ================== DETECTION PHASE ==================
    for row in data_rows:
        event_id = row.get("EventID", "")
        if event_id == EVENT_PROCESS_ACCESS:
            target_image = row.get("TargetImage", "")
            granted_access = row.get("GrantedAccess", "")
            source_user = row.get("SourceUser", "")
            target_user = row.get("TargetUser", "")

            if (target_image.lower().endswith(TARGET_PROCESS) and
                granted_access.lower() == FULL_ACCESS_RIGHTS and
                source_user.split("\\")[-1].lower() != target_user.split("\\")[-1].lower()):

                dump_time = row.get('DateTime')
                if earliest_dump_time is None or (dump_time and dump_time < earliest_dump_time):
                    earliest_dump_time = dump_time

                spotted_rows.append(row)
                cmdline = row.get("CommandLine", "")
                if cmdline:
                    extracted_commands.append(cmdline)

    # ================== CONTEXT FILTERING PHASE ==================
    context_events = []
    if include_context and earliest_dump_time and security_logs_rows:
        context_events, user_minutes = conf.get_events_filtered_by_time(security_logs_rows, earliest_dump_time)
        
        # Also filter primary detections by the same time window
        if user_minutes is not None and user_minutes > 0:
            spotted_rows = conf.filter_events_by_time(spotted_rows, earliest_dump_time, user_minutes)
        
        for event in context_events:
            cmdline = event.get("CommandLine", "")
            if cmdline and cmdline not in extracted_commands:
                extracted_commands.append(cmdline)

    return {
        "detected_events": spotted_rows,
        "context_events": context_events,
        "earliest_time": earliest_dump_time,
        "commands": list(set(extracted_commands)),
        "detection_type": "LSASS Dump Attempt",
        "count": len(spotted_rows),
        "context_count": len(context_events)
    }


def detect_strange_PPID(data_rows):
    """
    Detects suspicious parent-child process relationships (Strange PPID).
    
    Args:
        data_rows: List of event dictionaries
    
    Returns:
        {
            "detected_events": [...],       # Suspicious parent-child pairs
            "earliest_time": datetime,
            "commands": [...],
            "detection_type": "Strange PPID",
            "count": int
        }
    """
    EVENT_PROCESS_CREATE = '1'
    SUSPICIOUS_PAIRS = [
        ("winword.exe", "cmd.exe"),
        ("winword.exe", "powershell.exe"),
        ("excel.exe", "cmd.exe"),
        ("excel.exe", "powershell.exe"),
        ("outlook.exe", "cmd.exe"),
        ("outlook.exe", "powershell.exe"),
        ("powerpnt.exe", "cmd.exe"),
        ("powerpnt.exe", "powershell.exe"),
        ("onenote.exe", "cmd.exe"),
        ("onenote.exe", "powershell.exe"),
        ("chrome.exe", "cmd.exe"),
        ("chrome.exe", "powershell.exe"),
        ("firefox.exe", "cmd.exe"),
        ("firefox.exe", "powershell.exe"),
        ("iexplore.exe", "cmd.exe"),
        ("iexplore.exe", "powershell.exe"),
        ("edge.exe", "cmd.exe"),
        ("edge.exe", "powershell.exe"),
        ("explorer.exe", "cmd.exe"),
        ("explorer.exe", "powershell.exe"),
        ("svchost.exe", "cmd.exe"),
        ("svchost.exe", "powershell.exe"),
        ("services.exe", "cmd.exe"),
        ("services.exe", "powershell.exe"),
        ("werfault.exe", "cmd.exe"),
        ("werfault.exe", "powershell.exe"),
        ("wscript.exe", "cmd.exe"),
        ("wscript.exe", "powershell.exe"),
        ("cscript.exe", "cmd.exe"),
        ("cscript.exe", "powershell.exe"),
        ("mshta.exe", "cmd.exe"),
        ("mshta.exe", "powershell.exe"),
        ("rundll32.exe", "cmd.exe"),
        ("rundll32.exe", "powershell.exe"),
        ("regsvr32.exe", "cmd.exe"),
        ("regsvr32.exe", "powershell.exe"),
        ("wmiprvse.exe", "cmd.exe"),
        ("wmiprvse.exe", "powershell.exe"),
    ]

    spotted_rows = []
    earliest_event_time = None
    extracted_commands = []

    # ================== DETECTION PHASE ==================
    for row in data_rows:
        event_id = row.get("EventID", "")
        if event_id == EVENT_PROCESS_CREATE:
            image = row.get("Image", "").split("\\")[-1].lower()
            parent_image = row.get("ParentImage", "").split("\\")[-1].lower()
            if not image:
                continue

            if (parent_image, image) in SUSPICIOUS_PAIRS:
                spotted_rows.append(row)
                event_time = row.get('DateTime')
                if earliest_event_time is None or (event_time and event_time < earliest_event_time):
                    earliest_event_time = event_time

                cmdline = row.get("CommandLine", "")
                if cmdline:
                    extracted_commands.append(cmdline)

    return {
        "detected_events": spotted_rows,
        "earliest_time": earliest_event_time,
        "commands": list(set(extracted_commands)),
        "detection_type": "Strange PPID",
        "count": len(spotted_rows)
    }


# =====================================================
# PRESENTATION FUNCTIONS (handle all printing logic)
# =====================================================

def print_detection_result(result):
    """
    Pretty-print detection results to console.
    
    Args:
        result: Dict returned from a detect_* function
    """
    detection_type = result.get("detection_type", "Unknown")
    count = result.get("count", 0)

    if count == 0:
        print(f"\033[1;31m[-] No {detection_type} events detected.\033[0m\n")
        return

    print(f"\n\033[31m[!] {count} {detection_type} event(s) detected.\033[0m")

    for event in result.get("detected_events", []):
        print_sysmon_event(event)

    # Print context events if any
    context_events = result.get("context_events", [])
    if context_events:
        print(f"\n\033[32m[+] {len(context_events)} context event(s) filtered:\033[0m")
        for event in context_events:
            print_sysmon_event(event)

    # Print extracted commands if any
    commands = result.get("commands", [])
    if commands:
        print(f"\n\033[32m[+] Extracted commands:\033[0m")
        for cmd in commands:
            print(f"    {cmd}")

    print(f"\n\033[1;32m[+] Analysis complete\033[0m")


def print_detection_summary(result):
    """Print a brief summary of detection results."""
    detection_type = result.get("detection_type", "Unknown")
    count = result.get("count", 0)
    context_count = result.get("context_count", 0)

    print(f"\nDetection type: {detection_type}")
    print(f"Primary detections: {count}")
    if context_count > 0:
        print(f"Context events: {context_count}")


def export_results_to_json(result, evtx_path=None):
    """
    Export detection results to JSON format.
    
    Args:
        result: Dict returned from a detect_* function
        evtx_path: Optional path to EVTX file for filename generation
    """
    all_events = result.get("detected_events", [])
    context_events = result.get("context_events", [])
    all_events.extend(context_events)

    if not all_events:
        print("\033[31m[-] No events to export.\033[0m")
        return

    # Convert DateTime objects to strings
    events_serializable = []
    for event in all_events:
        event_copy = event.copy()
        if 'DateTime' in event_copy and hasattr(event_copy['DateTime'], 'isoformat'):
            event_copy['DateTime'] = event_copy['DateTime'].isoformat()
        events_serializable.append(event_copy)

    # Create JSON structure with metadata
    json_output = {
        "metadata": {
            "detection_type": result.get("detection_type", "Unknown"),
            "export_date": datetime.now().isoformat(),
            "total_events": len(events_serializable),
            "extracted_commands": result.get("commands", [])
        },
        "events": events_serializable
    }

    # Generate filename with timestamp and save to results directory
    results_dir = Path(__file__).resolve().parent.parent / "data" / "test" / "results"
    results_dir.mkdir(parents=True, exist_ok=True)
    
    timestamp = datetime.now().strftime('%Y%m%d_%H%M%S')
    
    if evtx_path:
        evtx_name = Path(evtx_path).stem
        json_filename = f"{evtx_name}_{result['detection_type'].lower().replace(' ', '_')}_{timestamp}.json"
    else:
        json_filename = f"detection_{result['detection_type'].lower().replace(' ', '_')}_{timestamp}.json"
    
    json_path = results_dir / json_filename

    try:
        with open(json_path, 'w', encoding='utf-8') as f:
            json.dump(json_output, f, indent=2, default=str)
        print(f"\033[32m[+] JSON export successful: {json_path}\033[0m")
        return str(json_path)
    except Exception as e:
        print(f"\033[31m[-] JSON export failed: {e}\033[0m")
        return None
