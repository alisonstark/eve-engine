# ===============================
# Main Program Loop
# ===============================

from pathlib import Path
import sys

# Add the parent directory of src to sys.path
sys.path.append(str(Path(__file__).resolve().parent.parent))

import scanners as scan
from config.utils import show_menu, get_evtx_path
from config.converters import sysmon_evtx_parser, security_evtx_parser

evtx_path = get_evtx_path()
data_rows = sysmon_evtx_parser(evtx_path)

def ask_for_context_filtering():
    """Ask user if they want to include context events in analysis."""
    print("\nInclude context events in analysis? (Y/N)")
    while True:
        user_input = input("Enter your choice: ").strip().lower()
        if user_input in ['y', 'n']:
            return user_input == 'y'
        print("\033[31m[-] Invalid input. Please enter 'Y' or 'N'.\033[0m")


def ask_for_export():
    """Ask user if they want to export results and in what format."""
    print("\nExport results to file? (json/csv/both/skip) [default: skip]:")
    while True:
        choice = input("Enter your choice: ").strip().lower()
        if choice in ['json', 'csv', 'both', 'skip', '']:
            return choice if choice else 'skip'
        print("\033[31m[-] Invalid choice. Please enter 'json', 'csv', 'both', or 'skip'.\033[0m")


while True:
    # Display the menu and get the user's selection
    selection = show_menu()

    if selection[0] == 5:
        print("\033[32m[+] Exiting the program...\033[0m\n")
        break

    # Ask about context filtering
    include_context = ask_for_context_filtering()

    # Call appropriate detection function
    result = None
    target_dll = selection[1]

    if selection[0] == 1:
        # DLL Hijacking Detection
        result = scan.detect_DLLHijack(data_rows, target_dll=target_dll, include_context=include_context)

    elif selection[0] == 2:
        # Unmanaged PowerShell Detection
        result = scan.detect_UnmanagedPowerShell(data_rows, target_dll=target_dll, include_context=include_context)

    elif selection[0] == 3:
        # LSASS Dump Detection
        include_security_logs = False
        security_logs_rows = None
        
        if include_context:
            print("Provide path to Security Logs .evtx file for context filtering (optional, press Enter to skip):")
            security_logs_path = input().strip()
            if security_logs_path:
                try:
                    security_logs_rows = security_evtx_parser(security_logs_path)
                    include_security_logs = True
                except Exception as e:
                    print(f"\033[31m[-] Failed to load security logs: {e}\033[0m")
        
        result = scan.detect_LsassDump(data_rows, include_context=include_security_logs, security_logs_rows=security_logs_rows)

    elif selection[0] == 4:
        # Strange PPID Detection (no context filtering option)
        result = scan.detect_strange_PPID(data_rows)

    # Print results if any detection occurred
    if result:
        scan.print_detection_result(result)
        scan.print_detection_summary(result)

        # Ask about export
        export_choice = ask_for_export()
        if export_choice == 'json':
            scan.export_results_to_json(result, evtx_path)
        elif export_choice == 'csv':
            if data_rows:
                from config.converters import evtx_to_csv
                evtx_to_csv(result.get("detected_events", []) + result.get("context_events", []), evtx_path)
        elif export_choice == 'both':
            scan.export_results_to_json(result, evtx_path)
            if data_rows:
                from config.converters import evtx_to_csv
                evtx_to_csv(result.get("detected_events", []) + result.get("context_events", []), evtx_path)