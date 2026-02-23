# ===============================
# DLL Hijacking Detection Program
# Unmanaged PowerShell Detection Program
# LSASS Dump Detection Program
# ===============================

import os
import json
from datetime import datetime
from config.converters import security_evtx_parser, evtx_to_csv
import config.utils as conf
from config.logprint import print_sysmon_event, print_security_event

hijackable_dlls = conf.get_hijackable_dlls()
lolbins = conf.get_lolbins()

# DEBUG: Function to print the hijackable DLLs
# def print_hijackable_dlls():
#    for dll in hijackable_dlls:
#        print(dll)

# DEBUG: Function to print the LOLBins
# def print_lolbins():
#    for lolbin in lolbins:
#        print(lolbin)

def detect_DLLHijack(data_rows, evtx_path=None, target_dll=None):

    spotted_rows = []
    earliest_event_time = None

    # Precompute the hijackable DLLs in lowercase for efficiency
    hijackable_dlls_lower = [dll.lower() for dll in hijackable_dlls]

    # Check if the loaded image is in the array of target DLLs
    for row in data_rows:
        # Check if the row contains the necessary keys
        # and if the EventID is '7' (DLL loaded) and the Image ends with ".exe"
        # and if the ImageLoaded is not empty
      
        event_id = row.get("EventID", "")
        image = row.get("Image", "")
        image_loaded = row.get("ImageLoaded", "")
            
        # Check if the event ID is '7' (DLL loaded) and the Image ends with ".exe"
        if event_id == '7' and image.endswith(".exe") and image_loaded != "":
            # Check if the loaded image is a DLL
            dll_name = os.path.basename(image_loaded).split("\\")[-1].lower() # TODO: is os.path.basename necessary?

            event_time = row.get("DateTime", "")
            if earliest_event_time is None or earliest_event_time > event_time:
                earliest_event_time = event_time

            # Check if the loaded DLL is in the hijackable array or equals the target DLL
            if target_dll and target_dll.lower() == dll_name:
                print_sysmon_event(row)
                spotted_rows.append(row)

            # If no target DLL is provided, check if the loaded DLL is in the hijackable array
            elif not target_dll and dll_name in hijackable_dlls_lower:
                print_sysmon_event(row)
                spotted_rows.append(row)
    
    # Display all other types of events starting from the earliest possible DLL hijacking time
    # User can choose to capture all events within a fixed time window
    len_of_rows = len(spotted_rows)
    filtered_events = []
    if len_of_rows != 0:
        print(f"\n\033[31m[!]{len_of_rows} potential DLL Hijacking events were detected.\033[0m")
        print("Fetch all events starting from the earliest detection time? (Y/N)")
        
        while True:
            user_input = input("Enter your choice: ").strip().lower()
            if user_input in ['y', 'n']:
                break
            print("\033[31m[-] Invalid input. Please enter 'Y' or 'N'.\033[0m")

        if user_input == 'y':
            filtered_events = conf.get_events_filtered_by_time(data_rows, earliest_event_time)
            for event in filtered_events:
                print_sysmon_event(event)

        else:
            print("\033[31m[-] No additional events filtered.\033[0m")
    
    else:
        print("\033[1;31m[-] No DLL Hijacking events detected.\033[0m")
        print("\033[1;31m[-] No events filtered.\033[0m")
        return
    
    # ================== REPORTING & EXPORT ==================
    _report_and_export_results(
        detection_type="DLL Hijacking",
        primary_events=spotted_rows,
        filtered_events=filtered_events,
        data_rows=data_rows,
        evtx_path=evtx_path
    )

def detect_UnmanagedPowerShell(data_rows, evtx_path=None, target_dll=None):
    """
    Detects unmanaged PowerShell execution by identifying CLR DLL loads (clr.dll, clrjit.dll)
    and correlating them with process injection (Event ID 8, 10) and network activity (Event ID 3).
    """
    # ================== CONFIGURATION ==================
    CLR_DLLS = ["clr.dll", "clrjit.dll"]
    EVENT_IMAGE_LOAD = '7'
    EVENT_CREATE_REMOTE_THREAD = '8'
    EVENT_PROCESS_ACCESS = '10'
    EVENT_NETWORK_CONNECT = '3'
    HTTPS_PORT = "443"
    
    # ================== PHASE 1: COLLECT EVENTS ==================
    clr_hits = []              # Actual CLR DLL loads detected
    injection_suspects = []    # Events with IDs 8, 10 (process injection indicators)
    network_alerts = []        # Events with ID 3 (network connections)
    earliest_event_time = None
    
    for row in data_rows:
        event_id = row.get("EventID", "")
        
        # --- Detect CLR DLL loads (primary indicator of unmanaged PowerShell) ---
        if event_id == EVENT_IMAGE_LOAD:
            image_loaded = row.get("ImageLoaded", "")
            if not image_loaded:
                continue
                
            dll_name = os.path.basename(image_loaded).split("\\")[-1].lower()
            
            # Check for target DLL or CLR DLLs
            is_target_match = target_dll and target_dll.lower() == dll_name
            is_clr_dll = not target_dll and dll_name in CLR_DLLS
            
            if is_target_match or is_clr_dll:
                print_sysmon_event(row)
                clr_hits.append(row)
                
                # Track earliest event time for context filtering
                event_time = row.get('DateTime')
                if earliest_event_time is None or event_time < earliest_event_time:
                    earliest_event_time = event_time
        
        # --- Collect process injection events (Event ID 8: CreateRemoteThread, 10: ProcessAccess) ---
        elif event_id == EVENT_CREATE_REMOTE_THREAD or event_id == EVENT_PROCESS_ACCESS:
            injection_suspects.append(row)
        
        # --- Collect network connection events ---
        elif event_id == EVENT_NETWORK_CONNECT:
            network_alerts.append(row)
    
    # ================== PHASE 2: USER INTERACTION & CONTEXT FILTERING ==================
    if not clr_hits:
        print("\033[1;31m[-] No CLR DLL loads detected.\033[0m\n")
        return
    
    print(f"\n\033[31m[!] {len(clr_hits)} CLR DLL load(s) detected. Fetch suspicious events starting from the earliest detection time? (Y/N)\033[0m")
    
    while True:
        user_input = input("Enter your choice: ").strip().lower()
        if user_input in ['y', 'n']:
            break
        print("\033[31m[-] Invalid input. Please enter 'Y' or 'N'.\033[0m")
    
    filtered_events = []
    if user_input == 'y':
        # Filter all events starting from earliest CLR DLL load
        filtered_events = conf.get_events_filtered_by_time(data_rows, earliest_event_time)
        
        # ================== PHASE 3: ANALYZE FILTERED EVENTS ==================
        # Separate injection and network events from the context filter
        filtered_injection_events = []
        filtered_network_events = []
        
        for event in filtered_events:
            print_sysmon_event(event)
            event_id = event.get("EventID", "")
            
            # --- Check for suspicious process injection with LOLBins ---
            if event_id == EVENT_PROCESS_ACCESS or event_id == EVENT_CREATE_REMOTE_THREAD:
                source_image = event.get("SourceImage", "")
                target_image = event.get("TargetImage", "")
                
                if conf.is_lolbin(source_image) or conf.is_lolbin(target_image):
                    alert_msg = (
                        "process accessed" if event_id == EVENT_PROCESS_ACCESS 
                        else "remote thread created"
                    )
                    print(f"\033[31m[!] Potential process injection: {alert_msg}.\033[0m")
                    print_sysmon_event(event)
                    filtered_injection_events.append(event)
            
            # --- Check for suspicious network connections (LOLBin to HTTPS) ---
            elif event_id == EVENT_NETWORK_CONNECT:
                image = event.get("Image", "")
                dest_port = event.get("DestinationPort", "")
                dest_ip = event.get("DestinationIp", "")
                
                if conf.is_lolbin(image) and dest_port == HTTPS_PORT:
                    print(f"\n\033[31m[!] LOLBin made outbound HTTPS connection to: {dest_ip}:{dest_port}\033[0m")
                    print_sysmon_event(event)
                    filtered_network_events.append(event)
        
        injection_suspects = filtered_injection_events
        network_alerts = filtered_network_events
    else:
        print("\033[31m[-] Event context filtering skipped.\033[0m\n")
    
    # ================== PHASE 4: REPORTING & EXPORT ==================
    _report_and_export_results(
        detection_type="Unmanaged PowerShell",
        primary_events=clr_hits,
        secondary_events_dict={
            "Injection events": injection_suspects,
            "Network alerts": network_alerts
        },
        filtered_events=filtered_events,
        data_rows=data_rows,
        evtx_path=evtx_path
    )


def _report_and_export_results(detection_type, primary_events, secondary_events_dict=None, 
                                filtered_events=None, data_rows=None, evtx_path=None):
    """
    Unified reporting and export function for all detection types.
    
    Args:
        detection_type: str - Name of detection (e.g., "DLL Hijacking", "Unmanaged PowerShell")
        primary_events: list - Main detection events
        secondary_events_dict: dict - Optional dict of {event_type: event_list} for secondary detections
        filtered_events: list - Context-filtered events
        data_rows: list - Total events analyzed
        evtx_path: str - Path to EVTX file for export
    """
    # ================== SUMMARY REPORT ==================
    len_filtered = len(filtered_events) if filtered_events else 0
    len_total = len(data_rows) if data_rows else 0
    
    print("\n\n\033[1;32m[+] Analysis complete\033[0m")
    print(f"Detection type: {detection_type}")
    print(f"Primary detections: {len(primary_events)}")
    
    # Display secondary event counts if provided
    if secondary_events_dict:
        for event_type, events in secondary_events_dict.items():
            print(f"{event_type}: {len(events)}")
    
    if len_filtered > 0:
        print(f"Context events filtered: {len_filtered} of {len_total}\n")
    
    # ================== EXPORT DECISION ==================
    all_events = primary_events.copy()
    if secondary_events_dict:
        for events in secondary_events_dict.values():
            all_events.extend(events)
    
    if len(all_events) == 0:
        print("\033[31m[-] No events to export.\033[0m\n")
        return
    
    print("Export results to JSON (csv/json/both/skip)? [default: json]:")
    
    while True:
        choice = input("Enter your choice: ").strip().lower()
        if choice in ['csv', 'json', 'both', 'skip', 'n', '']:
            break
        print("\033[31m[-] Invalid choice. Please enter 'csv', 'json', 'both', or 'skip'.\033[0m")
    
    # Default to JSON if user just presses Enter
    if choice == '':
        choice = 'json'
    
    if choice == 'skip' or choice == 'n':
        print("\033[31m[-] Results not saved.\033[0m\n")
        return
    
    # ================== EXPORT LOGIC ==================
    if choice in ['json', 'both']:
        _export_to_json(all_events, detection_type, evtx_path)
    
    if choice in ['csv', 'both'] and evtx_path:
        evtx_to_csv(all_events, evtx_path)
        print("\033[32m[+] CSV export successful.\033[0m")
    
    print()


def _export_to_json(events, detection_type, evtx_path):
    """Export events to JSON format with metadata."""
    if not events:
        return
    
    # Convert DateTime objects to strings for JSON serialization
    events_serializable = []
    for event in events:
        event_copy = event.copy()
        if 'DateTime' in event_copy and hasattr(event_copy['DateTime'], 'isoformat'):
            event_copy['DateTime'] = event_copy['DateTime'].isoformat()
        events_serializable.append(event_copy)
    
    # Create JSON structure with metadata
    json_output = {
        "metadata": {
            "detection_type": detection_type,
            "export_date": datetime.now().isoformat(),
            "total_events": len(events),
        },
        "events": events_serializable
    }
    
    # Generate filename
    if evtx_path:
        base_path = evtx_path.rsplit('.', 1)[0]  # Remove .evtx
        json_path = f"{base_path}_{detection_type.lower().replace(' ', '_')}.json"
    else:
        json_path = f"detection_{detection_type.lower().replace(' ', '_')}_{datetime.now().strftime('%Y%m%d_%H%M%S')}.json"
    
    try:
        with open(json_path, 'w', encoding='utf-8') as f:
            json.dump(json_output, f, indent=2, default=str)
        print(f"\033[32m[+] JSON export successful: {json_path}\033[0m")
    except Exception as e:
        print(f"\033[31m[-] JSON export failed: {e}\033[0m")

def detect_LsassDump(data_rows, evtx_path=None, placeholder=None):
    """
    Detects LSASS memory dump attempts by identifying ProcessAccess events 
    (Event ID 10) targeting lsass.exe with full memory access rights.
    """
    EVENT_PROCESS_ACCESS = '10'
    FULL_ACCESS_RIGHTS = "0x001fffff"
    TARGET_PROCESS = "lsass.exe"
    
    # ================== PHASE 1: DETECT LSASS ACCESS EVENTS ==================
    spotted_rows = []
    earliest_dump_time = None

    for row in data_rows:
        event_id = row.get("EventID", "")
        
        if event_id == EVENT_PROCESS_ACCESS:
            target_image = row.get("TargetImage", "")
            granted_access = row.get("GrantedAccess", "")
            source_user = row.get("SourceUser", "")
            target_user = row.get("TargetUser", "")

            # Check if the process is lsass.exe with full memory access from different user
            if (target_image.lower().endswith(TARGET_PROCESS) and
                granted_access.lower() == FULL_ACCESS_RIGHTS and
                source_user.split("\\")[-1].lower() != target_user.split("\\")[-1].lower()):

                dump_time = row.get('DateTime')
                
                # Track earliest event time for context filtering
                if earliest_dump_time is None or dump_time < earliest_dump_time:
                    earliest_dump_time = dump_time
                
                print_sysmon_event(row)
                spotted_rows.append(row)
    
    # ================== PHASE 2: USER INTERACTION & CONTEXT FILTERING ==================
    if not spotted_rows:
        print("\033[1;31m[-] No LSASS dump attempts detected.\033[0m\n")
        return
    
    print(f"\n\033[31m[!] {len(spotted_rows)} LSASS dump attempt(s) detected. Fetch security events starting from the earliest detection time? (Y/N)\033[0m")
    
    while True:
        user_input = input("Enter your choice: ").strip().lower()
        if user_input in ['y', 'n']:
            break
        print("\033[31m[-] Invalid input. Please enter 'Y' or 'N'.\033[0m")
    
    security_events = []
    if user_input == 'y' and placeholder is None:  # TODO: Clarify why placeholder check is needed
        print("You need to provide the path to the Security Logs .evtx file.")
        security_logs_path = conf.get_evtx_path()
        security_logs_rows = security_evtx_parser(security_logs_path)

        security_events = conf.get_events_filtered_by_time(security_logs_rows, earliest_dump_time)      
        for security_event in security_events:
            print_security_event(security_event)
    else:
        print("\033[31m[-] Security event context filtering skipped.\033[0m\n")
    
    # ================== PHASE 3: REPORTING & EXPORT ==================
    _report_and_export_results(
        detection_type="LSASS Dump Attempt",
        primary_events=spotted_rows,
        secondary_events_dict={"Security events": security_events} if security_events else None,
        filtered_events=security_events if security_events else None,
        data_rows=data_rows,
        evtx_path=evtx_path
    )


def detect_strange_PPID(data_rows, evtx_path=None, target_dll=None):
    """
    Detects suspicious parent-child process relationships (Strange PPID).
    Identifies when legitimate parent processes spawn suspicious child processes.
    """
    EVENT_PROCESS_CREATE = '1'
    
    # Suspicious parent-child pairs: (ParentImage, ChildImage)
    SUSPICIOUS_PAIRS = [
        ("werfault.exe", "cmd.exe"),
        ("explorer.exe", "powershell.exe"),
        ("winword.exe", "cmd.exe"),
        ("excel.exe", "powershell.exe"),
        ("outlook.exe", "cmd.exe"),
        ("wscript.exe", "powershell.exe"),
        ("mshta.exe", "powershell.exe"),
        ("svchost.exe", "cmd.exe"),
        ("services.exe", "cmd.exe"),
        ("rundll32.exe", "powershell.exe"),
        ("regsvr32.exe", "powershell.exe")
    ]

    # ================== PHASE 1: DETECT SUSPICIOUS PROCESS RELATIONSHIPS ==================
    spotted_rows = []
    earliest_event_time = None
    
    for row in data_rows:
        event_id = row.get("EventID", "")
        
        if event_id == EVENT_PROCESS_CREATE:
            image = row.get("Image", "").split("\\")[-1].lower()
            parent_image = row.get("ParentImage", "").split("\\")[-1].lower()
            
            if not image:
                continue
            
            # Check if this parent-child pair is suspicious
            if (parent_image, image) in SUSPICIOUS_PAIRS:
                print_sysmon_event(row)
                spotted_rows.append(row)

                # Track earliest event time for potential context filtering
                event_time = row.get('DateTime')
                if earliest_event_time is None or event_time < earliest_event_time:
                    earliest_event_time = event_time

    # ================== PHASE 2: REPORTING & EXPORT ==================
    if not spotted_rows:
        print("\033[1;31m[-] No suspicious parent-child process relationships detected.\033[0m\n")
        return
    
    _report_and_export_results(
        detection_type="Strange PPID",
        primary_events=spotted_rows,
        data_rows=data_rows,
        evtx_path=evtx_path
    )