# ===============================
# Auxiliary Functions
# ===============================

import os
import json
from datetime import timedelta, datetime
import subprocess
import time
import sys


def parse_detection_selection(user_input):
    """
    Parse user input for multiple detection selection.
    
    Handles formats like:
    - "1,3,5" -> [1, 3, 5]
    - "1-5" -> [1, 2, 3, 4, 5]
    - "1-3,5,7-9" -> [1, 2, 3, 5, 7, 8, 9]
    
    Args:
        user_input: String like "1,3,5" or "1-5,9"
    
    Returns:
        Sorted list of unique detection numbers (1-9), or None if invalid
    """
    try:
        selections = set()
        parts = [p.strip() for p in user_input.split(',')]
        
        for part in parts:
            if '-' in part:
                # Range like "1-5"
                start, end = part.split('-')
                start, end = int(start.strip()), int(end.strip())
                if start < 1 or end > 9 or start > end:
                    return None
                selections.update(range(start, end + 1))
            else:
                # Single number
                num = int(part)
                if num < 1 or num > 9:
                    return None
                selections.add(num)
        
        return sorted(list(selections))
    except (ValueError, AttributeError):
        return None


def ask_incident_mode():
    """Ask user if they want incident aggregation mode."""
    print("\n\033[1;33m[?] Use Incident Aggregation Mode?\033[0m")
    print("    This groups similar events into incidents and reduces noise.")
    print("    Recommended when dealing with large numbers of events.")
    print("    (Y/N) [default: N]")
    while True:
        user_input = input("Enter your choice: ").strip().lower()
        if user_input in ['y', 'n', '']:
            return user_input == 'y'
        print("\033[31m[-] Invalid input. Please enter 'Y' or 'N'.\033[0m")


def show_menu():
    """Display the main menu and get user's selection."""
    print("=== ETW Log Analyzer Toolbox ===")
    print("1) DLL Hijacking")
    print("2) Unmanaged PowerShell")
    print("3) LSASS Dump")
    print("4) Strange PPID")
    print("5) Brute Force/Failed Logins")
    print("6) Event Log Clearing/Tampering")
    print("7) Service Creation")
    print("8) Scheduled Task Creation")
    print("9) Account Manipulation")
    print("10) Run Multiple Detections")
    print("11) Exit")
    print("=================================")
    print("[*] Tip: Use Incident Aggregation Mode to reduce noise from large events")
    print("=================================\n")

    target_dll = None
    while True:
        try:
            choice = int(input("Select an option (1-11): "))
            if choice in [1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11]:
                if choice == 1 or choice == 2:
                    print("\nProvide a specific DLL to help filter search (optional).")
                    target_dll = input("Enter the DLL name (e.g., example.dll) or press Enter to skip: ")
                    
                    if target_dll and not target_dll.endswith(".dll"):
                        target_dll = input("\033[31m[-] Invalid DLL name. Please include the .dll extension:\033[0m")
                    elif target_dll:
                        target_dll = target_dll.strip().lower()
                    
                    return choice, target_dll if target_dll else None
                elif choice == 10:
                    # Run Multiple - return special tuple
                    print("\n\033[1;33mSelect detections to run (e.g., '1,3,5' or '1-5,9'):\033[0m")
                    selection_input = input("Enter detection numbers: ").strip()
                    selections = parse_detection_selection(selection_input)
                    
                    if selections is None:
                        print("\033[31m[-] Invalid selection format. Please use numbers 1-9, separated by commas or ranges (e.g., '1-5,9').\033[0m\n")
                        continue
                    
                    return choice, selections
                else:
                    return choice, None
            else:
                print("\033[31m[-] Invalid choice. Please select a valid option (1-11).\033[0m")
        except ValueError:
            print("Invalid input. Please enter a number between 1 and 11.")


def _auto_update_lists_if_needed(json_path):
    """If the given JSON file is older than 24h, run update_lists.py to refresh lists."""
    try:
        mtime = os.path.getmtime(json_path)
        now = time.time()
        if now - mtime > 24 * 3600:
            _run_update_lists()
    except FileNotFoundError:
        # If file doesn't exist, force update
        _run_update_lists()


def _run_update_lists():
    """Run update_lists.py in the project root directory."""
    root_dir = os.path.abspath(os.path.join(os.path.dirname(__file__), '../../'))
    script_path = os.path.join(root_dir, 'update_lists.py')
    try:
        subprocess.run([sys.executable, script_path], cwd=root_dir, check=True)
    except Exception as e:
        print(f"[!] Failed to update DLL/LOLBins lists: {e}")



def filter_events_by_time(data_rows, starting_time, user_minutes):
    """Filter events based on a starting time and optional time frame in minutes."""
    if not data_rows:
        print("\033[31m[-] No data rows available.\033[0m")
        return []
    
    if not starting_time:
        print("\033[31m[-] No events filtered.\033[0m")
        return []

    filtered_events = []
    event_count = 0
    max_events = 100

    if user_minutes is None:
        user_minutes = 0
    
    # Parse starting_time from string to datetime, then add the time delta
    try:
        # Handle ISO format timestamps with optional microseconds
        if '.' in str(starting_time):
            start_dt = datetime.fromisoformat(str(starting_time).replace('Z', '+00:00'))
        else:
            start_dt = datetime.fromisoformat(str(starting_time).replace('Z', '+00:00'))
    except ValueError:
        # Fallback: treat as string comparison (works for ISO format)
        print(f"\033[33m[!] Warning: Could not parse datetime '{starting_time}'. Using string comparison.\033[0m")
        start_dt = None
    
    # Calculate end time threshold
    if start_dt:
        end_dt = start_dt + timedelta(minutes=user_minutes)
        start_time_str = start_dt.isoformat()
        end_time_str = end_dt.isoformat()
    else:
        start_time_str = str(starting_time)
        end_time_str = None

    for row in data_rows:
        time_created = row.get('DateTime', "")

        if user_minutes > 0:
            # Time range filter: from start to start + N minutes
            if start_dt:
                try:
                    event_dt = datetime.fromisoformat(str(time_created).replace('Z', '+00:00'))
                    if start_dt <= event_dt <= end_dt:
                        filtered_events.append(row)
                        event_count += 1
                        
                        if event_count > max_events:
                            print(f"\033[31m[!] There are more than {max_events} events. Proceed?\033[0m")
                            user_input = input("Press 'y' to continue or any other key to stop: ").strip().lower()
                            if user_input != 'y':
                                print("\033[31m[!] Stopping the filtering.\033[0m")
                                break
                            else:
                                print("\033[32m[+] Continuing to filter events...\033[0m")
                                event_count = 0
                except ValueError:
                    # Fallback to string comparison for this event
                    if start_time_str <= time_created <= end_time_str:
                        filtered_events.append(row)
                        event_count += 1
                        
                        if event_count > max_events:
                            print(f"\033[31m[!] There are more than {max_events} events. Proceed?\033[0m")
                            user_input = input("Press 'y' to continue or any other key to stop: ").strip().lower()
                            if user_input != 'y':
                                print("\033[31m[!] Stopping the filtering.\033[0m")
                                break
                            else:
                                print("\033[32m[+] Continuing to filter events...\033[0m")
                                event_count = 0
            else:
                # String comparison
                if start_time_str <= time_created <= end_time_str:
                    filtered_events.append(row)
                    event_count += 1
                    
                    if event_count > max_events:
                        print(f"\033[31m[!] There are more than {max_events} events. Proceed?\033[0m")
                        user_input = input("Press 'y' to continue or any other key to stop: ").strip().lower()
                        if user_input != 'y':
                            print("\033[31m[!] Stopping the filtering.\033[0m")
                            break
                        else:
                            print("\033[32m[+] Continuing to filter events...\033[0m")
                            event_count = 0
        else:
            # No time limit: show all events from starting_time onwards
            if start_dt:
                try:
                    event_dt = datetime.fromisoformat(str(time_created).replace('Z', '+00:00'))
                    if event_dt >= start_dt:
                        filtered_events.append(row)
                        event_count += 1
                        
                        if event_count > max_events:
                            print(f"\033[31m[!] There are more than {max_events} events. Proceed?\033[0m")
                            user_input = input("Press 'y' to continue or any other key to stop: ").strip().lower()
                            if user_input != 'y':
                                print("\033[31m[!] Stopping the filtering.\033[0m")
                                break
                            else:
                                print("\033[32m[+] Continuing to filter events...\033[0m")
                                event_count = 0
                except ValueError:
                    # Fallback to string comparison
                    if time_created >= start_time_str:
                        filtered_events.append(row)
                        event_count += 1
                        
                        if event_count > max_events:
                            print(f"\033[31m[!] There are more than {max_events} events. Proceed?\033[0m")
                            user_input = input("Press 'y' to continue or any other key to stop: ").strip().lower()
                            if user_input != 'y':
                                print("\033[31m[!] Stopping the filtering.\033[0m")
                                break
                            else:
                                print("\033[32m[+] Continuing to filter events...\033[0m")
                                event_count = 0
            else:
                # String comparison
                if time_created >= start_time_str:
                    filtered_events.append(row)
                    event_count += 1
                    
                    if event_count > max_events:
                        print(f"\033[31m[!] There are more than {max_events} events. Proceed?\033[0m")
                        user_input = input("Press 'y' to continue or any other key to stop: ").strip().lower()
                        if user_input != 'y':
                            print("\033[31m[!] Stopping the filtering.\033[0m")
                            break
                        else:
                            print("\033[32m[+] Continuing to filter events...\033[0m")
                            event_count = 0

    print("\n\033[32m[+] Filtered events based on the earliest detection time\033[0m\n")
    return filtered_events


def get_evtx_path():
    """Prompt user for and validate .evtx file path."""
    print("Enter the full path to the .evtx file: ")

    while True:
        evtx_path = input()

        if not evtx_path:
            print("\033[31m[-] No path provided. Please provide a path.\033[0m")
            continue
        elif not evtx_path.endswith(".evtx"):
            print("\033[31m[-] Invalid file type. Please provide a .evtx file.\033[0m")
            continue
        else:
            print("[+] File successfully loaded")
            break

    return evtx_path


def get_hijackable_dlls():
    """Load hijackable DLLs from hijackable_dlls.json (generated by update_lists.py)"""
    path = os.path.join(os.path.dirname(__file__), '../data/hijackable_dlls.json')
    _auto_update_lists_if_needed(path)
    with open(path, 'r', encoding='utf-8') as f:
        dlls = json.load(f)
    return [dll.lower() for dll in dlls]


def get_lolbins():
    """Load LOLBins from lolbins.json (generated by update_lists.py)"""
    path = os.path.join(os.path.dirname(__file__), '../data/lolbins.json')
    _auto_update_lists_if_needed(path)
    with open(path, 'r', encoding='utf-8') as f:
        lolbins = json.load(f)
    return [lolbin.lower() for lolbin in lolbins]


def is_lolbin(image_path):
    """Check if the image path is a LOLBin."""
    if not image_path:
        return False
    binary = os.path.basename(image_path).split("\\")[-1].lower()
    return bool(binary and get_lolbins() and binary in get_lolbins())


def get_events_filtered_by_time(events, starting_time):
    """Get events filtered by user-specified time frame. Returns both filtered events and the time window used."""
    user_minutes = None
    while True:
        try:
            time_input = input("Enter time frame from earliest detection:\n  Examples: '1m', '30s', '1.5m'\n  Or type 'all' / leave blank for no upper limit: ").strip().lower()
            if time_input != "" and time_input != "all":
                # Parse time input with suffixes (m for minutes, s for seconds)
                if time_input.endswith('m'):
                    user_minutes = float(time_input[:-1])  # Remove 'm' and convert to float
                elif time_input.endswith('s'):
                    user_seconds = float(time_input[:-1])  # Remove 's' and convert to float
                    user_minutes = user_seconds / 60.0  # Convert seconds to minutes
                else:
                    # Assume input is in minutes if no suffix
                    user_minutes = float(time_input)
                
                if user_minutes < 0:
                    print("\033[31m[-] Invalid time frame. Please enter a positive number.\033[0m")
                    continue
                else:
                    break
            else:
                # Both blank and "all" mean no upper limit
                user_minutes = None
                break
        except ValueError:
            print("\033[31m[-] Invalid input. Please enter a valid number with optional suffix (m/s). Examples: 1m, 30s, 1.5m\033[0m")
            continue
        except Exception as e:
            print(f"An error occurred in `get_events_filtered_by_time()`: {e}")
            continue

    filtered_events = filter_events_by_time(events, starting_time, user_minutes)
    return filtered_events, user_minutes







    


    