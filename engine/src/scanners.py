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
from engine.config.converters import security_evtx_parser, evtx_to_csv
import engine.config.utils as conf
from engine.config.logprint import print_sysmon_event, print_security_event

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


def score_dll_hijack_risk(event):
    """
    Score the risk level of a DLL load event for potential hijacking.
    
    Risk factors:
    - DLL from non-system location (+40 points)
    - Loading process is a LOLBin (+30 points)
    - DLL in user-writable location like Downloads (+25 points)
    - Parent process suspicious (+20 points if available)
    
    Returns: Risk score (0-100+), event with score added
    """
    risk_score = 0
    lolbins_lower = [b.lower() for b in _get_lolbins_list()]
    
    # Check DLL path location
    image_loaded = event.get("ImageLoaded", "").lower()
    system_paths = ["c:\\windows\\system32\\", "c:\\windows\\syswow64\\", "c:\\program files"]
    
    is_system_path = any(image_loaded.startswith(path) for path in system_paths)
    if not is_system_path and image_loaded:
        # DLL from non-standard location = high risk
        risk_score += 40
        
        # Extra risk if from user-writable location
        if "\\appdata\\" in image_loaded or "\\downloads\\" in image_loaded or "\\temp\\" in image_loaded:
            risk_score += 25
    
    # Check loading process
    image = event.get("Image", "").lower()
    process_name = os.path.basename(image).lower()
    
    if process_name in lolbins_lower:
        # LOLBin loading DLL = suspicious
        risk_score += 30
    
    # Unusual processes loading system DLLs are also suspicious
    # (e.g., Notepad loading clr.dll, cmd.exe loading crypt32.dll)
    suspicious_process_dll_combos = {
        "notepad.exe": ["clr.dll", "jscript.dll", "vbscript.dll"],
        "svchost.exe": ["clr.dll", "powershell.exe"],
        "explorer.exe": ["clr.dll", "jscript.dll"],
    }
    
    dll_name = os.path.basename(image_loaded).lower()
    if process_name in suspicious_process_dll_combos:
        if dll_name in suspicious_process_dll_combos[process_name]:
            risk_score += 20
    
    # Add score to event for reporting
    event_with_score = dict(event)
    event_with_score["risk_score"] = risk_score
    
    return risk_score, event_with_score


def filter_high_confidence_detections(detected_events, threshold=40):
    """
    Filter detected events to only high-confidence potential hijacking attempts.
    
    Args:
        detected_events: List of DLL load events from detect_DLLHijack
        threshold: Minimum risk score to include (default: 40)
    
    Returns: List of events scoring >= threshold, sorted by risk score descending
    """
    scored_events = []
    
    for event in detected_events:
        score, scored_event = score_dll_hijack_risk(event)
        if score >= threshold:
            scored_events.append(scored_event)
    
    # Sort by risk score descending (highest risk first)
    scored_events.sort(key=lambda e: e.get("risk_score", 0), reverse=True)
    
    return scored_events


def score_unmanaged_powershell_risk(event, event_type):
    """
    Score the risk level of unmanaged PowerShell execution events.
    
    Risk factors vary by event type:
    - CLR DLL loads: Loaded from suspicious process (+30), from non-system location (+20)
    - Injection events: Source is LOLBin (+40), target is system process (+20)
    - Network events: Source is LOLBin (+30), connects to non-https port (+10)
    
    Args:
        event: Event dictionary
        event_type: "clr" | "injection" | "network"
    
    Returns: Risk score (0-100+), event with score added
    """
    risk_score = 0
    lolbins_lower = [b.lower() for b in _get_lolbins_list()]
    
    event_with_score = dict(event)
    
    if event_type == "clr":
        # CLR DLL load - check the loading process
        image = event.get("Image", "").lower()
        process_name = os.path.basename(image).lower()
        
        # System processes loading CLR is normal (framework usage)
        # Non-system processes = suspicious
        system_processes = ["svchost.exe", "dllhost.exe", "rundll32.exe", "powershell.exe"]
        if process_name not in system_processes:
            risk_score += 30
        
        # CLR from non-system location is suspicious
        image_loaded = event.get("ImageLoaded", "").lower()
        if not image_loaded.startswith("c:\\windows\\"):
            risk_score += 20
        
        # If process itself is a LOLBin, CLR load is very suspicious
        if process_name in lolbins_lower:
            risk_score += 40
    
    elif event_type == "injection":
        # Process injection events - check source/target
        source_image = event.get("SourceImage", "").lower()
        source_binary = os.path.basename(source_image).lower() if source_image else ""
        
        # Injection from LOLBin = high risk
        if source_binary in lolbins_lower:
            risk_score += 40
        
        # Injection into system process = medium risk
        target_image = event.get("TargetImage", "").lower()
        target_binary = os.path.basename(target_image).lower() if target_image else ""
        
        critical_system_processes = ["lsass.exe", "csrss.exe", "svchost.exe", "system.exe", "explorer.exe"]
        if target_binary in critical_system_processes:
            risk_score += 30
    
    elif event_type == "network":
        # Network connections - check process and destination
        image = event.get("Image", "").lower()
        process_name = os.path.basename(image).lower()
        
        # Network from LOLBin = high risk
        if process_name in lolbins_lower:
            risk_score += 30
        
        # Non-standard ports = higher risk than HTTPS
        dest_port = event.get("DestinationPort", "")
        if dest_port and dest_port != "443":  # Not HTTPS
            risk_score += 20
        
        # Suspicious destination IPs (private ranges = local network, unusual)
        dest_ip = event.get("DestinationIp", "")
        if dest_ip and (dest_ip.startswith("192.168.") or dest_ip.startswith("10.") or dest_ip.startswith("172.")):
            risk_score += 15
    
    event_with_score["risk_score"] = risk_score
    return risk_score, event_with_score


def filter_high_confidence_powershell_events(clr_events, injection_events, network_events, threshold=40):
    """
    Filter PowerShell detection events by risk score.
    
    Args:
        clr_events: CLR DLL load events
        injection_events: Process injection events
        network_events: Network connection events
        threshold: Minimum risk score to include (default: 40)
    
    Returns: Tuple of (high_conf_clr, high_conf_injection, high_conf_network)
    """
    high_conf_clr = []
    for event in clr_events:
        score, scored_event = score_unmanaged_powershell_risk(event, "clr")
        if score >= threshold:
            high_conf_clr.append(scored_event)
    
    high_conf_injection = []
    for event in injection_events:
        score, scored_event = score_unmanaged_powershell_risk(event, "injection")
        if score >= threshold:
            high_conf_injection.append(scored_event)
    
    high_conf_network = []
    for event in network_events:
        score, scored_event = score_unmanaged_powershell_risk(event, "network")
        if score >= threshold:
            high_conf_network.append(scored_event)
    
    # Sort each by risk score descending
    for event_list in [high_conf_clr, high_conf_injection, high_conf_network]:
        event_list.sort(key=lambda e: e.get("risk_score", 0), reverse=True)
    
    return high_conf_clr, high_conf_injection, high_conf_network


def score_lsass_dump_risk(event, threshold=40):
    """
    Score risk of LSASS dump attempt based on source process and access patterns.
    
    Risk Factors:
    - +40 for full memory access rights (0x001fffff)
    - +30 if source is unprivileged user (not SYSTEM)
    - +20 if source process is suspicious tool (cmd, powershell, rundll32, etc.)
    - +15 if accessing from unusual location
    
    Args:
        event: ProcessAccess event dict
        threshold: Minimum score to consider high-confidence (default: 40)
    
    Returns: (risk_score, event_with_score)
    """
    score = 0
    
    # Always high risk - targeting LSASS with full access
    source_user = event.get("SourceUser", "").lower()
    target_user = event.get("TargetUser", "").lower()
    source_process = event.get("SourceProcessImage", "").split("\\")[-1].lower()
    granted_access = event.get("GrantedAccess", "").lower()
    
    # Full access rights (0x001fffff) - already validated in detection
    if granted_access == "0x001fffff":
        score += 40
    
    # Check if source is unprivileged user accessing SYSTEM process
    if source_user and "system" not in source_user and "nt authority" not in source_user:
        score += 30
    
    # Suspicious source processes
    suspicious_sources = [
        "cmd.exe", "powershell.exe", "rundll32.exe", "regsvcs.exe",
        "cscript.exe", "wscript.exe", "mshta.exe", "wmiprvse.exe"
    ]
    if source_process in suspicious_sources:
        score += 20
    
    # Context: source from unusual location
    source_image = event.get("SourceProcessImage", "")
    if source_image and "\\temp\\" in source_image.lower() or "\\users\\" in source_image.lower():
        score += 15
    
    event_with_score = event.copy()
    event_with_score["risk_score"] = score
    
    return score, event_with_score


def filter_high_confidence_lsass_events(events, threshold=40):
    """
    Filter LSASS dump events by risk score.
    
    Args:
        events: List of ProcessAccess events targeting LSASS
        threshold: Minimum risk score to include (default: 40)
    
    Returns: List of high-confidence events sorted by risk score
    """
    high_conf = []
    for event in events:
        score, scored_event = score_lsass_dump_risk(event, threshold)
        if score >= threshold:
            high_conf.append(scored_event)
    
    high_conf.sort(key=lambda e: e.get("risk_score", 0), reverse=True)
    return high_conf


def score_strange_ppid_risk(event):
    """
    Score risk of suspicious parent-child process relationship.
    
    Risk Factors:
    - +50 for Office apps spawning shells (very suspicious)
    - +40 for browsers spawning shells (suspicious)
    - +35 for system tools spawning shells (very suspicious)
    - +25 for script engines spawning shells (suspicious)
    - +10 if spawning powershell (more dangerous than cmd)
    - +5 if command line contains base64 or other encoding indicators
    
    Args:
        event: Process create event dict
    
    Returns: (risk_score, event_with_score)
    """
    score = 0
    parent_image = event.get("ParentImage", "").split("\\")[-1].lower()
    image = event.get("Image", "").split("\\")[-1].lower()
    cmdline = event.get("CommandLine", "").lower()
    
    # Risk by parent process type
    office_apps = ["winword.exe", "excel.exe", "outlook.exe", "powerpnt.exe", "onenote.exe"]
    browser_apps = ["chrome.exe", "firefox.exe", "iexplore.exe", "edge.exe"]
    system_tools = ["explorer.exe", "svchost.exe", "services.exe", "werfault.exe", "wmiprvse.exe"]
    script_engines = ["wscript.exe", "cscript.exe", "mshta.exe", "rundll32.exe", "regsvr32.exe"]
    
    if parent_image in office_apps:
        score += 50
    elif parent_image in system_tools:
        score += 35
    elif parent_image in browser_apps:
        score += 40
    elif parent_image in script_engines:
        score += 25
    else:
        score += 15  # Base score for unexpected parents
    
    # PowerShell is more dangerous than cmd
    if image == "powershell.exe":
        score += 10
    
    # Encoding indicators (base64, hex, etc.)
    encoding_indicators = ["base64", "-enc", "-encodedcommand", "0x", "frombase64"]
    if any(indicator in cmdline for indicator in encoding_indicators):
        score += 5
    
    event_with_score = event.copy()
    event_with_score["risk_score"] = score
    
    return score, event_with_score


def filter_high_confidence_ppid_events(events, threshold=40):
    """
    Filter Strange PPID events by risk score.
    
    Args:
        events: List of process creation events with suspicious parent-child pairs
        threshold: Minimum risk score to include (default: 40)
    
    Returns: List of high-confidence events sorted by risk score
    """
    high_conf = []
    for event in events:
        score, scored_event = score_strange_ppid_risk(event)
        if score >= threshold:
            high_conf.append(scored_event)
    
    high_conf.sort(key=lambda e: e.get("risk_score", 0), reverse=True)
    return high_conf


def detect_DLLHijack(data_rows, target_dll=None, include_context=True):
    """
    Detects potential DLL hijacking events by identifying suspicious DLL loads by processes.
    
    Args:
        data_rows: List of event dictionaries
        target_dll: Optional specific DLL to search for (e.g., "malicious.dll")
        include_context: If True, filter context events from earliest detection time
    
    Returns:
        {
            "detected_events": [...],           # List of ALL detected DLL load events
            "high_confidence_events": [...],    # Filtered high-risk events (risk_score >= 40)
            "context_events": [...],            # List of context-filtered events (if include_context=True)
            "earliest_time": datetime,          # Earliest detection time
            "commands": [...],                  # Extracted malicious command lines
            "detection_type": "DLL Hijacking",
            "count": int,                       # Total detections
            "high_confidence_count": int,       # High-confidence count
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

    # ================== RISK SCORING PHASE ==================
    # Filter to high-confidence detections based on risk scoring
    high_confidence_events = filter_high_confidence_detections(spotted_rows, threshold=40)

    return {
        "detected_events": spotted_rows,
        "high_confidence_events": high_confidence_events,
        "context_events": context_events,
        "earliest_time": earliest_event_time,
        "commands": list(set(extracted_commands)),  # Remove duplicates
        "detection_type": "DLL Hijacking",
        "count": len(spotted_rows),
        "high_confidence_count": len(high_confidence_events),
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
            "clr_events": [...],                    # All CLR DLL load events
            "high_confidence_clr_events": [...],    # High-risk CLR events
            "injection_events": [...],              # All process injection events
            "high_confidence_injection_events": [...], # High-risk injection events
            "network_events": [...],                # All network connection events
            "high_confidence_network_events": [...], # High-risk network events
            "context_events": [...],                # Context-filtered events
            "earliest_time": datetime,
            "commands": [...],
            "detection_type": "Unmanaged PowerShell",
            "clr_count": int,
            "high_confidence_clr_count": int,
            "injection_count": int,
            "high_confidence_injection_count": int,
            "network_count": int,
            "high_confidence_network_count": int,
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

    # ================== RISK SCORING PHASE ==================
    # Filter to high-confidence events based on risk scoring
    high_conf_clr, high_conf_injection, high_conf_network = filter_high_confidence_powershell_events(
        clr_hits, 
        filtered_injection_events if include_context else injection_suspects,
        filtered_network_events if include_context else network_alerts,
        threshold=40
    )

    return {
        "clr_events": clr_hits,
        "high_confidence_clr_events": high_conf_clr,
        "injection_events": filtered_injection_events if include_context else injection_suspects,
        "high_confidence_injection_events": high_conf_injection,
        "network_events": filtered_network_events if include_context else network_alerts,
        "high_confidence_network_events": high_conf_network,
        "context_events": context_events,
        "earliest_time": earliest_event_time,
        "commands": list(set(powershell_commands)),
        "detection_type": "Unmanaged PowerShell",
        "clr_count": len(clr_hits),
        "high_confidence_clr_count": len(high_conf_clr),
        "injection_count": len(filtered_injection_events) if include_context else len(injection_suspects),
        "high_confidence_injection_count": len(high_conf_injection),
        "network_count": len(filtered_network_events) if include_context else len(network_alerts),
        "high_confidence_network_count": len(high_conf_network),
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
            "detected_events": [...],                   # LSASS dump attempt events
            "high_confidence_events": [...],            # Filtered high-risk events (risk_score >= 40)
            "context_events": [...],                    # Context-filtered security events
            "earliest_time": datetime,
            "commands": [...],
            "detection_type": "LSASS Dump Attempt",
            "count": int,
            "high_confidence_count": int,
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

    # ================== RISK SCORING PHASE ==================
    # Filter to high-confidence detections based on risk scoring
    high_confidence_events = filter_high_confidence_lsass_events(spotted_rows, threshold=40)

    return {
        "detected_events": spotted_rows,
        "high_confidence_events": high_confidence_events,
        "context_events": context_events,
        "earliest_time": earliest_dump_time,
        "commands": list(set(extracted_commands)),
        "detection_type": "LSASS Dump Attempt",
        "count": len(spotted_rows),
        "high_confidence_count": len(high_confidence_events),
        "context_count": len(context_events)
    }


def detect_strange_PPID(data_rows):
    """
    Detects suspicious parent-child process relationships (Strange PPID).
    
    Args:
        data_rows: List of event dictionaries
    
    Returns:
        {
            "detected_events": [...],                   # Suspicious parent-child pairs
            "high_confidence_events": [...],            # Filtered high-risk events (risk_score >= 40)
            "earliest_time": datetime,
            "commands": [...],
            "detection_type": "Strange PPID",
            "count": int,
            "high_confidence_count": int
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

    # ================== RISK SCORING PHASE ==================
    # Filter to high-confidence detections based on risk scoring
    high_confidence_events = filter_high_confidence_ppid_events(spotted_rows, threshold=40)

    return {
        "detected_events": spotted_rows,
        "high_confidence_events": high_confidence_events,
        "earliest_time": earliest_event_time,
        "commands": list(set(extracted_commands)),
        "detection_type": "Strange PPID",
        "count": len(spotted_rows),
        "high_confidence_count": len(high_confidence_events)
    }


# =====================================================
# PRESENTATION FUNCTIONS (handle all printing logic)
# =====================================================

def print_detection_result(result):
    """
    Pretty-print detection results to console.
    Handles both DLL Hijacking format (detected_events) and PowerShell format (clr/injection/network_events).
    
    Args:
        result: Dict returned from a detect_* function
    """
    detection_type = result.get("detection_type", "Unknown")
    
    # Handle DLL Hijacking format (single detected_events list)
    if "detected_events" in result:
        count = result.get("count", 0)
        high_confidence_count = result.get("high_confidence_count")
        
        if count == 0:
            print(f"\033[1;31m[-] No {detection_type} events detected.\033[0m\n")
            return

        # Show summary with high-confidence filtering if applicable
        if high_confidence_count is not None:
            print(f"\n\033[31m[!] {count} total {detection_type} event(s) detected.\033[0m")
            print(f"\033[33m[*] {high_confidence_count} HIGH-CONFIDENCE event(s) (risk score >= 40)\033[0m\n")
            
            # Display high-confidence events first if they exist
            if high_confidence_count > 0:
                print("\033[1;33m=== HIGH-CONFIDENCE DETECTIONS ===\033[0m")
                for event in result.get("high_confidence_events", []):
                    risk_score = event.get("risk_score", 0)
                    print(f"\033[32m[RISK SCORE: {risk_score}]\033[0m")
                    print_sysmon_event(event)
                
                # Also show all detections for reference
                print("\n\033[1;36m=== ALL DETECTIONS (for reference) ===\033[0m")
                for event in result.get("detected_events", []):
                    print_sysmon_event(event)
            else:
                print("\033[36m[*] No high-confidence events. Showing all detections:\033[0m")
                for event in result.get("detected_events", []):
                    print_sysmon_event(event)
        else:
            # Fallback for other detection types without risk scoring
            print(f"\n\033[31m[!] {count} {detection_type} event(s) detected.\033[0m")
            for event in result.get("detected_events", []):
                print_sysmon_event(event)

    # Handle Unmanaged PowerShell format (multiple event type lists)
    elif "clr_events" in result or "injection_events" in result or "network_events" in result:
        clr_count = result.get("clr_count", 0)
        injection_count = result.get("injection_count", 0)
        network_count = result.get("network_count", 0)
        total_count = clr_count + injection_count + network_count
        
        hc_clr = result.get("high_confidence_clr_count", 0)
        hc_injection = result.get("high_confidence_injection_count", 0)
        hc_network = result.get("high_confidence_network_count", 0)
        total_hc = hc_clr + hc_injection + hc_network
        
        if total_count == 0:
            print(f"\033[1;31m[-] No {detection_type} events detected.\033[0m\n")
            return
        
        print(f"\n\033[31m[!] {total_count} total {detection_type} event(s) detected.\033[0m")
        print(f"    - CLR: {clr_count} ({hc_clr} high-confidence)")
        print(f"    - Injection: {injection_count} ({hc_injection} high-confidence)")
        print(f"    - Network: {network_count} ({hc_network} high-confidence)")
        print(f"\033[33m[*] {total_hc} total HIGH-CONFIDENCE event(s) (risk score >= 40)\033[0m\n")
        
        if total_hc > 0:
            # Show high-confidence CLR events
            hc_clr_events = result.get("high_confidence_clr_events", [])
            if hc_clr_events:
                print("\033[1;33m=== HIGH-CONFIDENCE CLR EVENTS ===\033[0m")
                for event in hc_clr_events:
                    risk_score = event.get("risk_score", 0)
                    print(f"\033[32m[RISK SCORE: {risk_score}]\033[0m")
                    print_sysmon_event(event)
            
            # Show high-confidence Injection events
            hc_injection_events = result.get("high_confidence_injection_events", [])
            if hc_injection_events:
                print("\n\033[1;33m=== HIGH-CONFIDENCE INJECTION EVENTS ===\033[0m")
                for event in hc_injection_events:
                    risk_score = event.get("risk_score", 0)
                    print(f"\033[32m[RISK SCORE: {risk_score}]\033[0m")
                    print_sysmon_event(event)
            
            # Show high-confidence Network events
            hc_network_events = result.get("high_confidence_network_events", [])
            if hc_network_events:
                print("\n\033[1;33m=== HIGH-CONFIDENCE NETWORK EVENTS ===\033[0m")
                for event in hc_network_events:
                    risk_score = event.get("risk_score", 0)
                    print(f"\033[32m[RISK SCORE: {risk_score}]\033[0m")
                    print_sysmon_event(event)
            
            # Show all detections for reference
            print("\n\033[1;36m=== ALL DETECTIONS (for reference) ===\033[0m")
            for event in result.get("clr_events", []):
                print("\033[36m[CLR]\033[0m", end=" ")
                print_sysmon_event(event)
            for event in result.get("injection_events", []):
                print("\033[36m[INJECTION]\033[0m", end=" ")
                print_sysmon_event(event)
            for event in result.get("network_events", []):
                print("\033[36m[NETWORK]\033[0m", end=" ")
                print_sysmon_event(event)
        else:
            print("\033[36m[*] No high-confidence events. Showing all detections by category:\033[0m")
            if result.get("clr_events"):
                print("\n\033[36m--- CLR Events ---\033[0m")
                for event in result.get("clr_events", []):
                    print_sysmon_event(event)
            if result.get("injection_events"):
                print("\n\033[36m--- Injection Events ---\033[0m")
                for event in result.get("injection_events", []):
                    print_sysmon_event(event)
            if result.get("network_events"):
                print("\n\033[36m--- Network Events ---\033[0m")
                for event in result.get("network_events", []):
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
    context_events = result.get("context_events", [])
    
    # Handle DLL Hijacking format (single detected_events)
    if "detected_events" in result:
        all_events = result.get("detected_events", [])
        high_confidence_events = result.get("high_confidence_events", [])
        
        # Mark high-confidence events
        all_events_with_confidence = []
        for event in all_events:
            event_copy = event.copy()
            event_copy["is_high_confidence"] = any(
                event_copy.get("risk_score") == hc.get("risk_score") 
                for hc in high_confidence_events
            )
            all_events_with_confidence.append(event_copy)
        
        all_events_with_confidence.extend(context_events)
        
        metadata = {
            "detection_type": result.get("detection_type", "Unknown"),
            "export_date": datetime.now().isoformat(),
            "total_events": result.get("count", 0),
            "high_confidence_events": result.get("high_confidence_count", 0),
            "context_events": len(context_events),
            "extracted_commands": result.get("commands", [])
        }
    
    # Handle Unmanaged PowerShell format (multiple event types)
    elif "clr_events" in result:
        all_events_with_confidence = []
        
        # Collect all event types with confidence flags
        for event in result.get("clr_events", []):
            event_copy = event.copy()
            event_copy["event_category"] = "clr"
            event_copy["is_high_confidence"] = any(
                event_copy.get("risk_score") == hc.get("risk_score") 
                for hc in result.get("high_confidence_clr_events", [])
            )
            all_events_with_confidence.append(event_copy)
        
        for event in result.get("injection_events", []):
            event_copy = event.copy()
            event_copy["event_category"] = "injection"
            event_copy["is_high_confidence"] = any(
                event_copy.get("risk_score") == hc.get("risk_score") 
                for hc in result.get("high_confidence_injection_events", [])
            )
            all_events_with_confidence.append(event_copy)
        
        for event in result.get("network_events", []):
            event_copy = event.copy()
            event_copy["event_category"] = "network"
            event_copy["is_high_confidence"] = any(
                event_copy.get("risk_score") == hc.get("risk_score") 
                for hc in result.get("high_confidence_network_events", [])
            )
            all_events_with_confidence.append(event_copy)
        
        all_events_with_confidence.extend(context_events)
        
        metadata = {
            "detection_type": result.get("detection_type", "Unknown"),
            "export_date": datetime.now().isoformat(),
            "clr_events": result.get("clr_count", 0),
            "high_confidence_clr": result.get("high_confidence_clr_count", 0),
            "injection_events": result.get("injection_count", 0),
            "high_confidence_injection": result.get("high_confidence_injection_count", 0),
            "network_events": result.get("network_count", 0),
            "high_confidence_network": result.get("high_confidence_network_count", 0),
            "context_events": len(context_events),
            "extracted_commands": result.get("commands", [])
        }
    
    else:
        print("\033[31m[-] No events to export.\033[0m")
        return

    if not all_events_with_confidence:
        print("\033[31m[-] No events to export.\033[0m")
        return

    # Convert DateTime objects to strings
    events_serializable = []
    for event in all_events_with_confidence:
        event_copy = event.copy()
        if 'DateTime' in event_copy and hasattr(event_copy['DateTime'], 'isoformat'):
            event_copy['DateTime'] = event_copy['DateTime'].isoformat()
        events_serializable.append(event_copy)

    # Create JSON structure with metadata
    json_output = {
        "metadata": metadata,
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
