"""
update_lists.py

Fetches and updates hijackable DLLs and LOLBins lists from reputable GitHub sources.
Saves results as JSON files for use by the detection engine.

- Hijackable DLLs: https://github.com/wietze/HijackLibs (YAML files)
- LOLBins: https://github.com/LOLBAS-Project/LOLBAS (YAML files)

Run this script manually or on a schedule to keep your lists up to date.
"""

import requests
import json
import os
import time
from pathlib import Path
from datetime import datetime, timedelta

# Output directory for JSON lists - save to engine/data/ so utils.py can find them
OUTPUT_DIR = Path(__file__).parent / "engine" / "data"
OUTPUT_DIR.mkdir(parents=True, exist_ok=True)

# --- Hijackable DLLs ---
HIJACKLIBS_API_URL = "https://api.github.com/repos/wietze/HijackLibs/contents/yml?ref=main"
HIJACKABLE_DLLS_JSON = OUTPUT_DIR / "hijackable_dlls.json"

# --- LOLBins ---
LOLBINS_API_URL = "https://api.github.com/repos/LOLBAS-Project/LOLBAS/contents/yml?ref=master"
LOLBINS_JSON = OUTPUT_DIR / "lolbins.json"

# Fallback lists in case fetching fails
FALLBACK_DLLS = [
    "kernel32.dll", "ntdll.dll", "msvcrt.dll", "advapi32.dll", "shell32.dll",
    "user32.dll", "gdi32.dll", "ole32.dll", "oleaut32.dll", "ws2_32.dll",
    "version.dll", "shlwapi.dll", "shcore.dll", "combase.dll", "winspool.drv",
    "imm32.dll", "lpk.dll", "usp10.dll", "setupapi.dll", "cfgmgr32.dll",
    "devobj.dll", "display.dll", "hdwwiz.dll", "netapi32.dll", "samlib.dll",
    "urlmon.dll", "winhttp.dll", "sechost.dll", "bcrypt.dll", "ncrypt.dll",
    "crypt32.dll", "wintrust.dll", "cryptui.dll"
]

FALLBACK_LOLBINS = [
    "certutil", "cscript", "mshta", "powershell", "regsvcs", "regasm",
    "rundll32", "wscript", "wmic", "cmd", "taskkill", "tasklist",
    "systeminfo", "whoami", "ipconfig", "net", "pktmon", "fsutil",
    "regedit", "regquery", "reg", "sc", "nltest"
]


def is_file_recent(filepath, hours=24):
    """Check if a file was modified within the last N hours."""
    if not filepath.exists():
        return False
    file_mtime = datetime.fromtimestamp(filepath.stat().st_mtime)
    return datetime.now() - file_mtime < timedelta(hours=hours)


def load_json(path):
    """Load JSON from file."""
    try:
        with open(path, "r", encoding="utf-8") as f:
            return json.load(f)
    except Exception as e:
        print(f"[-] Failed to load {path}: {e}")
        return None


def get_github_headers():
    """Get GitHub API headers with authentication token if available."""
    headers = {}
    # Check for GitHub token in environment variables
    github_token = os.getenv('GITHUB_TOKEN') or os.getenv('PAT_TOKEN')
    if github_token:
        headers['Authorization'] = f'token {github_token}'
    return headers


def make_api_request(url, timeout=10, max_retries=3):
    """Make API request with retry logic and exponential backoff."""
    headers = get_github_headers()
    for attempt in range(max_retries):
        try:
            resp = requests.get(url, headers=headers, timeout=timeout)
            if resp.status_code == 403 and 'rate limit' in resp.text.lower():
                if attempt < max_retries - 1:
                    wait_time = 2 ** attempt  # 1, 2, 4 seconds
                    print(f"[!] Rate limit hit, retrying in {wait_time}s...")
                    time.sleep(wait_time)
                    continue
            resp.raise_for_status()
            return resp
        except requests.exceptions.RequestException as e:
            if attempt == max_retries - 1:
                raise
            wait_time = 2 ** attempt
            print(f"[!] Request failed: {e}, retrying in {wait_time}s...")
            time.sleep(wait_time)
    raise Exception("Max retries exceeded")


def fetch_dll_files_from_github():
    """Fetch DLL file names from HijackLibs GitHub repository."""
    print("Fetching hijackable DLLs list from GitHub...")
    dlls = set()
    
    try:
        # Get list of directories in yml folder
        resp = make_api_request(HIJACKLIBS_API_URL, timeout=10)
        
        items = resp.json()
        print(f"[DEBUG] Found {len(items)} items in yml directory")
        
        # Process each subdirectory to extract yml file names
        for item in items:
            if item['type'] == 'dir':
                print(f"[DEBUG] Processing directory: {item['name']}")
                # Get items in each top-level subdirectory (3rd_party, microsoft, etc.)
                subdir_resp = make_api_request(item['url'], timeout=10)
                subdir_items = subdir_resp.json()
                
                print(f"[DEBUG]   Found {len(subdir_items) if isinstance(subdir_items, list) else 'N/A'} items in {item['name']}")
                
                # Process vendor directories within each subdirectory
                if isinstance(subdir_items, list):
                    yml_count = 0
                    for vendor_dir in subdir_items:
                        # Each vendor directory (adobe, ahnenblatt, etc.) contains .yml files
                        if vendor_dir['type'] == 'dir':
                            vendor_resp = make_api_request(vendor_dir['url'], timeout=10)
                            vendor_files = vendor_resp.json()
                            
                            if isinstance(vendor_files, list):
                                for yml_file in vendor_files:
                                    if yml_file['name'].endswith('.yml'):
                                        # Extract DLL name from filename (e.g., "kernel32.yml" -> "kernel32.dll")
                                        dll_name = yml_file['name'].replace('.yml', '.dll')
                                        dlls.add(dll_name.lower())
                                        yml_count += 1
                    print(f"[DEBUG]   Found {yml_count} .yml files in {item['name']}")
        
        if dlls:
            print(f"Fetched {len(dlls)} hijackable DLLs from GitHub.")
        else:
            print(f"[!] Warning: No DLL files found in repository")
        return sorted(dlls)
    
    except Exception as e:
        print(f"[-] Failed to fetch DLLs from GitHub API: {e}")
        import traceback
        traceback.print_exc()
        print(f"[*] Using fallback DLL list ({len(FALLBACK_DLLS)} entries)")
        return FALLBACK_DLLS


def fetch_lolbins_from_github():
    """Fetch LOLBins names from LOLBAS GitHub repository."""
    print("Fetching LOLBins list from GitHub...")
    lolbins = set()
    
    try:
        # Get list of yml folders (OSBinaries, OSScripts, OSLibraries, etc.)
        resp = make_api_request(LOLBINS_API_URL, timeout=10)
        
        items = resp.json()
        
        # Process each subdirectory to extract file names
        for item in items:
            if item['type'] == 'dir':
                # Get files in each subdirectory
                subdir_resp = make_api_request(item['url'], timeout=10)
                subdir_items = subdir_resp.json()
                
                for subitem in subdir_items:
                    if subitem['name'].endswith('.yml'):
                        # Extract name from filename (e.g., "cmd.yml" -> "cmd")
                        bin_name = subitem['name'].replace('.yml', '')
                        lolbins.add(bin_name.lower())
        
        if lolbins:
            print(f"Fetched {len(lolbins)} LOLBins from GitHub.")
        return sorted(lolbins)
    
    except Exception as e:
        print(f"[-] Failed to fetch LOLBins from GitHub API: {e}")
        print(f"[*] Using fallback LOLBins list ({len(FALLBACK_LOLBINS)} entries)")
        return FALLBACK_LOLBINS


def save_json(data, path):
    with open(path, "w", encoding="utf-8") as f:
        json.dump(data, f, indent=2)
    print(f"Saved {path}")


def main():
    print("\n" + "="*60)
    print("ETW Log Analyzer - Data Lists Update")
    print("="*60)
    if not os.getenv('GITHUB_TOKEN') and not os.getenv('PAT_TOKEN'):
        print("[*] Tip: Set GITHUB_TOKEN environment variable for higher rate limits")
        print("    This allows fetching comprehensive lists from GitHub without rate limiting.\n")
    
    # Check if DLLs list is recent (updated within 24 hours)
    if is_file_recent(HIJACKABLE_DLLS_JSON, hours=24):
        print("[*] Hijackable DLLs list is up to date (modified within 24 hours)")
        hijackable_dlls = load_json(HIJACKABLE_DLLS_JSON)
        if hijackable_dlls is None:
            hijackable_dlls = fetch_dll_files_from_github()
    else:
        print("[*] Updating hijackable DLLs list...")
        hijackable_dlls = fetch_dll_files_from_github()
    
    if hijackable_dlls:
        save_json(hijackable_dlls, HIJACKABLE_DLLS_JSON)

    # Check if LOLBins list is recent (updated within 24 hours)
    if is_file_recent(LOLBINS_JSON, hours=24):
        print("[*] LOLBins list is up to date (modified within 24 hours)")
        lolbins = load_json(LOLBINS_JSON)
        if lolbins is None:
            lolbins = fetch_lolbins_from_github()
    else:
        print("[*] Updating LOLBins list...")
        lolbins = fetch_lolbins_from_github()
    
    if lolbins:
        save_json(lolbins, LOLBINS_JSON)

    print("\n" + "="*60)
    print("Update complete. You can now use these JSON files in your detection engine.")
    print("="*60 + "\n")

if __name__ == "__main__":
    main()
