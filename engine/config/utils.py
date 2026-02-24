# ===============================
# Auxiliary Functions
# ===============================

import os
import json
from datetime import timedelta, datetime
import subprocess
import time
import sys


def show_menu():
    """Display the main menu and get user's selection."""
    print("=== ETW Log Analyzer Toolbox ===")
    print("1) DLL Hijacking Detection")
    print("2) Unmanaged PowerShell Detection")
    print("3) Detect LSASS Dump")
    print("4) Detect Strange PPID")
    print("5) Exit")
    print("=================================\n")

    target_dll = None
    while True:
        try:
            choice = int(input("Select an option (1-5): "))
            if choice in [1, 2, 3, 4, 5]:
                if choice == 1 or choice == 2:
                    print("\nProvide a specific DLL to help filter search (optional).")
                    target_dll = input("Enter the DLL name (e.g., example.dll) or press Enter to skip: ")
                    
                    if target_dll and not target_dll.endswith(".dll"):
                        target_dll = input("\033[31m[-] Invalid DLL name. Please include the .dll extension:\033[0m")
                    elif target_dll:
                        target_dll = target_dll.strip().lower()
                    
                    return choice, target_dll if target_dll else None
                else:
                    return choice, None
            else:
                print("\033[31m[-] Invalid choice. Please select a valid option (1-5).\033[0m")
        except ValueError:
            print("Invalid input. Please enter a number between 1 and 5.")


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
    max_events = 20

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
                except ValueError:
                    # Fallback to string comparison for this event
                    if start_time_str <= time_created <= end_time_str:
                        filtered_events.append(row)
            else:
                # String comparison
                if start_time_str <= time_created <= end_time_str:
                    filtered_events.append(row)
        else:
            # No time limit: show all events from starting_time onwards
            if start_dt:
                try:
                    event_dt = datetime.fromisoformat(str(time_created).replace('Z', '+00:00'))
                    if event_dt >= start_dt:
                        filtered_events.append(row)
                        event_count += 1
                        
                        if event_count > max_events:
                            print("\033[31m[!] There are more than 20 events. Proceed?\033[0m")
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
            else:
                # String comparison
                if time_created >= start_time_str:
                    filtered_events.append(row)
                    event_count += 1
                    
                    if event_count > max_events:
                        print("\033[31m[!] There are more than 20 events. Proceed?\033[0m")
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
            time_input = input("Enter time frame (e.g., '1m', '30s', '1.5m', or leave blank for all events): ").strip().lower()
            if time_input != "":
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
                break
        except ValueError:
            print("\033[31m[-] Invalid input. Please enter a valid number with optional suffix (m/s). Examples: 1m, 30s, 1.5m\033[0m")
            continue
        except Exception as e:
            print(f"An error occurred in `get_events_filtered_by_time()`: {e}")
            continue

    filtered_events = filter_events_by_time(events, starting_time, user_minutes)
    return filtered_events, user_minutes







    


    