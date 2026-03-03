# ===============================
# Main Program Loop
# ===============================

from pathlib import Path
import sys
import argparse

# Add the root directory to sys.path so 'engine' module can be imported
sys.path.insert(0, str(Path(__file__).resolve().parent.parent.parent))

from engine.src import scanners as scan
from engine.config.utils import show_menu, get_evtx_path, parse_detection_selection
from engine.config.converters import sysmon_evtx_parser, security_evtx_parser

DETECTION_LABELS = {
    1: "DLL Hijacking",
    2: "Unmanaged PowerShell",
    3: "LSASS Dump",
    4: "Strange PPID",
    5: "Brute Force/Failed Logins",
    6: "Event Log Clearing/Tampering",
    7: "Service Creation",
    8: "Scheduled Task Creation",
    9: "Account Manipulation"
}


def print_detection_catalog():
    """Print available detections and their numeric IDs for CLI selection."""
    print("=== Available Detections ===")
    for det_num, det_name in DETECTION_LABELS.items():
        print(f"{det_num}) {det_name}")
    print("============================")
    print("Use with --detections, examples: 1,3,5 or 1-5,9")

def parse_cli_args():
    """Parse command-line flags for runtime behavior."""
    parser = argparse.ArgumentParser(
        description="EVE - Event Verification Engine"
    )
    parser.add_argument(
        "--include-context",
        action="store_true",
        help="Include context events in analysis (default: disabled)"
    )
    parser.add_argument(
        "--incident-aggregation",
        action="store_true",
        help="Aggregate detections into incidents (default: disabled)"
    )
    parser.add_argument(
        "-e", "--export-results",
        nargs="+",
        metavar="ARG",
        help="Export results as json/csv/both, optionally followed by output directory"
    )
    parser.add_argument(
        "-p", "--evtx-path",
        help="Path to Sysmon .evtx file (optional; if omitted, interactive prompt is used)"
    )
    parser.add_argument(
        "-d", "--detections",
        help="Detection selection (e.g., '1,3,5' or '1-5,9'). Optional; if omitted, interactive menu is used."
    )
    parser.add_argument(
        "--target-dll",
        help="Optional DLL filter for detections 1 and 2 (e.g., example.dll)"
    )
    parser.add_argument(
        "--security-evtx-path",
        help="Optional Security .evtx file path for LSASS context (detection 3)"
    )
    parser.add_argument(
        "-l", "--list-detections",
        action="store_true",
        help="List detection options and exit"
    )

    args = parser.parse_args()

    export_choice = "skip"
    export_output_dir = None

    if args.export_results:
        if len(args.export_results) > 2:
            parser.error("--export-results accepts FORMAT and optional OUTPUT_DIR only")

        export_choice = args.export_results[0].strip().lower()
        if export_choice not in ["json", "csv", "both"]:
            parser.error("--export-results FORMAT must be one of: json, csv, both")

        if len(args.export_results) == 2:
            export_output_dir = args.export_results[1].strip()

    detection_numbers = None
    if args.detections:
        detection_numbers = parse_detection_selection(args.detections.strip())
        if detection_numbers is None:
            parser.error("--detections must use numbers 1-9 with comma/range format (e.g., '1,3,5' or '1-5,9')")

    if args.evtx_path:
        evtx_path = args.evtx_path.strip()
        if not evtx_path.lower().endswith(".evtx"):
            parser.error("--evtx-path must point to a .evtx file")

    target_dll = None
    if args.target_dll:
        target_dll = args.target_dll.strip().lower()
        if not target_dll.endswith(".dll"):
            parser.error("--target-dll must end with .dll")

    security_evtx_path = None
    if args.security_evtx_path:
        security_evtx_path = args.security_evtx_path.strip()
        if not security_evtx_path.lower().endswith(".evtx"):
            parser.error("--security-evtx-path must point to a .evtx file")

    return (
        args.include_context,
        args.incident_aggregation,
        export_choice,
        export_output_dir,
        args.evtx_path,
        detection_numbers,
        target_dll,
        security_evtx_path,
        args.list_detections
    )


(
    include_context_flag,
    incident_mode_flag,
    export_choice_flag,
    export_output_dir_flag,
    evtx_path_flag,
    detection_numbers_flag,
    target_dll_flag,
    security_evtx_path_flag,
    list_detections_flag
) = parse_cli_args()

if list_detections_flag:
    print_detection_catalog()
    raise SystemExit(0)

evtx_path = evtx_path_flag if evtx_path_flag else get_evtx_path()
data_rows = sysmon_evtx_parser(evtx_path)

# Grouping fields for incident aggregation by detection type
INCIDENT_GROUPING = {
    1: ("Image", "ImageLoaded"),           # DLL Hijacking: (process, dll)
    2: ("Image", "TargetImage"),           # Unmanaged PowerShell: (source, target)
    3: ("SourceImage", "TargetImage"),     # LSASS Dump: (source, target)
    4: ("ParentImage", "Image"),           # Strange PPID: (parent, child)
    5: ("TargetUserName", "Workstation"),  # Brute Force: (user, workstation)
    6: ("Computer",),                      # Event Log Clearing: (computer)
    7: ("ServiceName",),                   # Service Creation: (service name)
    8: ("TaskName",),                      # Scheduled Task: (task name)
    9: ("TargetUserName",)                 # Account Manipulation: (user)
}

def apply_incident_aggregation(result, detection_num):
    """
    Apply incident aggregation to detection results if configured.
    
    Args:
        result: Detection result dict
        detection_num: Detection option number (1-9)
    
    Returns:
        Aggregated result dict
    """
    if detection_num not in INCIDENT_GROUPING:
        return result
    
    group_by_fields = INCIDENT_GROUPING[detection_num]
    aggregated = scan.aggregate_incidents(result, group_by_fields, min_incident_count=1, min_risk_score=40)
    
    return aggregated


def run_detection(
    detection_num,
    data_rows,
    evtx_path,
    security_evtx_parser,
    target_dll=None,
    include_context=True,
    non_interactive=False,
    security_evtx_path=None
):
    """
    Run a single detection by detection number.
    
    Args:
        detection_num: Detection option number (1-9)
        data_rows: Parsed event data
        evtx_path: Path to EVTX file
        security_evtx_parser: Parser function for security logs
        target_dll: Optional DLL target for DLL Hijacking/PowerShell
        include_context: Whether to include context events
    
    Returns:
        Detection result dictionary or None if skipped
    """
    result = None
    
    if detection_num == 1:
        # DLL Hijacking Detection
        result = scan.detect_DLLHijack(data_rows, target_dll=target_dll, include_context=include_context)

    elif detection_num == 2:
        # Unmanaged PowerShell Detection
        result = scan.detect_UnmanagedPowerShell(data_rows, target_dll=target_dll, include_context=include_context)

    elif detection_num == 3:
        # LSASS Dump Detection
        include_security_logs = False
        security_logs_rows = None

        if include_context:
            security_logs_path = security_evtx_path

            if not security_logs_path and not non_interactive:
                print("Provide path to Security Logs .evtx file for context filtering (optional, press Enter to skip):")
                security_logs_path = input().strip()

            if security_logs_path:
                try:
                    security_logs_rows = security_evtx_parser(security_logs_path)
                    include_security_logs = True
                except Exception as e:
                    print(f"\033[31m[-] Failed to load security logs: {e}\033[0m")
        
        result = scan.detect_LsassDump(data_rows, include_context=include_security_logs, security_logs_rows=security_logs_rows)

    elif detection_num == 4:
        # Strange PPID Detection (no context filtering option)
        result = scan.detect_strange_PPID(data_rows)

    elif detection_num == 5:
        # Brute Force/Failed Logins Detection
        result = scan.detect_BruteForce(data_rows, include_context=include_context)

    elif detection_num == 6:
        # Event Log Clearing/Tampering Detection
        result = scan.detect_EventLogClearing(data_rows, include_context=include_context)

    elif detection_num == 7:
        # Service Creation Detection
        result = scan.detect_ServiceCreation(data_rows, include_context=include_context)

    elif detection_num == 8:
        # Scheduled Task Creation Detection
        result = scan.detect_ScheduledTaskCreation(data_rows, include_context=include_context)

    elif detection_num == 9:
        # Account Manipulation Detection
        result = scan.detect_AccountManipulation(data_rows, include_context=include_context)
    
    return result


def export_result_bundle(results, data_rows, evtx_path, export_choice, export_output_dir):
    """Export one or more detection results based on export flags."""
    if not results or export_choice == 'skip':
        return

    for result, _ in results:
        if export_choice == 'json':
            scan.export_results_to_json(result, evtx_path, output_dir=export_output_dir)
        elif export_choice == 'csv':
            if data_rows:
                from engine.config.converters import evtx_to_csv
                evtx_to_csv(
                    result.get("detected_events", []) + result.get("context_events", []),
                    evtx_path,
                    output_dir=export_output_dir
                )
        elif export_choice == 'both':
            scan.export_results_to_json(result, evtx_path, output_dir=export_output_dir)
            if data_rows:
                from engine.config.converters import evtx_to_csv
                evtx_to_csv(
                    result.get("detected_events", []) + result.get("context_events", []),
                    evtx_path,
                    output_dir=export_output_dir
                )


def run_selected_detections(detection_numbers, include_context, incident_mode, export_choice, export_output_dir, non_interactive=False):
    """Run one or more detections and optionally export results."""
    target_dll = target_dll_flag

    if non_interactive:
        selection_text = ", ".join(
            f"{det_num} ({DETECTION_LABELS.get(det_num, 'Unknown')})" for det_num in detection_numbers
        )
        print(f"\033[36m[*] Selected detections: {selection_text}\033[0m")

    if not non_interactive and not target_dll and (1 in detection_numbers or 2 in detection_numbers):
        print("\nProvide a specific DLL to help filter search (optional).")
        target_dll = input("Enter the DLL name (e.g., example.dll) or press Enter to skip: ")
        if target_dll and not target_dll.endswith(".dll"):
            target_dll = None
        elif target_dll:
            target_dll = target_dll.strip().lower()

    results = []
    print(f"\n\033[33m[*] Running {len(detection_numbers)} detection(s)...\033[0m\n")

    for det_num in detection_numbers:
        result = run_detection(
            det_num,
            data_rows,
            evtx_path,
            security_evtx_parser,
            target_dll=target_dll,
            include_context=include_context,
            non_interactive=non_interactive,
            security_evtx_path=security_evtx_path_flag
        )
        if result:
            if incident_mode:
                result = apply_incident_aggregation(result, det_num)
                print(f"\033[36m[*] Incident Aggregation: {result.get('total_raw_events', result.get('count', 0))} raw events → {result.get('count', 0)} incident(s)\033[0m")

            results.append((result, det_num))
            scan.print_detection_result(result)
            scan.print_detection_summary(result)
            print("\n" + "=" * 50 + "\n")

    if results:
        print(f"\n\033[32m[+] Completed {len(results)} detection(s)\033[0m")
        export_result_bundle(results, data_rows, evtx_path, export_choice, export_output_dir)
    else:
        print("\033[31m[-] No detections completed.\033[0m")


if detection_numbers_flag:
    run_selected_detections(
        detection_numbers_flag,
        include_context_flag,
        incident_mode_flag,
        export_choice_flag,
        export_output_dir_flag,
        non_interactive=True
    )
    raise SystemExit(0)


while True:
    # Display the menu and get the user's selection
    selection = show_menu()

    if selection[0] == 11:
        print("\033[32m[+] Exiting the program...\033[0m\n")
        break

    # Handle Run Multiple Detections flow
    if selection[0] == 10:
        detection_numbers = selection[1]  # List of detection numbers
        include_context = include_context_flag
        incident_mode = incident_mode_flag
        run_selected_detections(
            detection_numbers,
            include_context,
            incident_mode,
            export_choice_flag,
            export_output_dir_flag,
            non_interactive=False
        )
        
        continue

    # Handle Single Detection flow (options 1-9)
    include_context = include_context_flag
    incident_mode = incident_mode_flag

    # Call appropriate detection function
    result = None
    target_dll = selection[1]

    if target_dll_flag:
        target_dll = target_dll_flag

    result = run_detection(
        selection[0],
        data_rows,
        evtx_path,
        security_evtx_parser,
        target_dll=target_dll,
        include_context=include_context,
        non_interactive=False,
        security_evtx_path=security_evtx_path_flag
    )

    # Print results if any detection occurred
    if result:
        # Apply incident aggregation if enabled
        if incident_mode:
            result = apply_incident_aggregation(result, selection[0])
            print(f"\n\033[36m[*] Incident Aggregation: {result.get('total_raw_events', result.get('count', 0))} raw events → {result.get('count', 0)} incident(s)\033[0m\n")
        
        scan.print_detection_result(result)
        scan.print_detection_summary(result)

        export_result_bundle(
            [(result, selection[0])],
            data_rows,
            evtx_path,
            export_choice_flag,
            export_output_dir_flag
        )