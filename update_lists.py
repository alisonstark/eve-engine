"""
update_lists.py

Fetches and updates hijackable DLLs and LOLBins lists from reputable GitHub sources.
Saves results as JSON files for use by the detection engine.

- Hijackable DLLs: https://github.com/mandiant/DLLSearchOrderHijackingList (CSV)
- LOLBins: https://github.com/LOLBAS-Project/LOLBAS (YAML/Markdown)

Run this script manually or on a schedule to keep your lists up to date.
"""

import requests
import csv
import json
import os
import re
from pathlib import Path

# Output directory for JSON lists
OUTPUT_DIR = Path(__file__).parent / "config" / "data"
OUTPUT_DIR.mkdir(parents=True, exist_ok=True)

# --- Hijackable DLLs ---
HIJACKABLE_DLLS_URL = "https://raw.githubusercontent.com/mandiant/DLLSearchOrderHijackingList/master/ListOfDLLs.csv"
HIJACKABLE_DLLS_JSON = OUTPUT_DIR / "hijackable_dlls.json"

# --- LOLBins ---
LOLBINS_INDEX_URL = "https://raw.githubusercontent.com/LOLBAS-Project/LOLBAS/master/yml/LOLBins.yaml"
LOLBINS_JSON = OUTPUT_DIR / "lolbins.json"


def fetch_hijackable_dlls():
    print("Fetching hijackable DLLs list...")
    resp = requests.get(HIJACKABLE_DLLS_URL)
    resp.raise_for_status()
    lines = resp.text.splitlines()
    reader = csv.DictReader(lines)
    dlls = []
    for row in reader:
        dll = row.get("DLL", "") or row.get("Dll", "") or row.get("dll", "")
        if dll:
            dlls.append(dll.strip().lower())
    print(f"Fetched {len(dlls)} hijackable DLLs.")
    return sorted(set(dlls))


def fetch_lolbins():
    print("Fetching LOLBins list...")
    # The LOLBAS project uses one YAML file per LOLBin, but the index is in LOLBins.yaml
    resp = requests.get(LOLBINS_INDEX_URL)
    resp.raise_for_status()
    # Extract all 'Name:' fields (YAML)
    names = set(re.findall(r"^\s*-\s*Name:\s*([\w.\-]+)", resp.text, re.MULTILINE))
    print(f"Fetched {len(names)} LOLBins.")
    return sorted(name.lower() for name in names)


def save_json(data, path):
    with open(path, "w", encoding="utf-8") as f:
        json.dump(data, f, indent=2)
    print(f"Saved {path}")


def main():
    hijackable_dlls = fetch_hijackable_dlls()
    save_json(hijackable_dlls, HIJACKABLE_DLLS_JSON)

    lolbins = fetch_lolbins()
    save_json(lolbins, LOLBINS_JSON)

    print("\nUpdate complete. You can now use these JSON files in your detection engine.")

if __name__ == "__main__":
    main()
