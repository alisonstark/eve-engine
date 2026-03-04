# ===============================
# Multi-Format Event Log Parser
# ===============================
# Supports: EVTX (binary), CSV (exported), JSON (PowerShell), EVT (legacy)
# Auto-detects format with validation; routes to appropriate parser

# Python imports
from Evtx.Evtx import Evtx
from datetime import datetime
from pathlib import Path
import csv
import json
import struct
import xml.etree.ElementTree as ET

# ===============================
# FORMAT DETECTION & VALIDATION
# ===============================

def detect_and_validate_format(file_path):
    """
    Detects log file format by extension AND validates actual file content.
    
    Returns: tuple (format_type, is_valid, error_message)
        - format_type: 'evtx', 'csv', 'json', 'evt', or 'unknown'
        - is_valid: bool
        - error_message: str or None
    """
    file_path = Path(file_path)
    extension = file_path.suffix.lower()
    
    try:
        # Check file exists and is readable
        if not file_path.exists():
            return 'unknown', False, f"File not found: {file_path}"
        if not file_path.is_file():
            return 'unknown', False, f"Path is not a file: {file_path}"
        if file_path.stat().st_size == 0:
            return 'unknown', False, "File is empty"
    except Exception as e:
        return 'unknown', False, f"Cannot access file: {e}"
    
    # ========== EVTX Validation ==========
    if extension == '.evtx':
        try:
            with open(file_path, 'rb') as f:
                # EVTX files start with "EVT\0" (0x45, 0x56, 0x54, 0x00)
                magic = f.read(4)
                if magic == b'EVT\x00':
                    return 'evtx', True, None
                else:
                    return 'evtx', False, f"Invalid EVTX magic bytes: {magic!r}"
        except Exception as e:
            return 'evtx', False, f"EVTX validation failed: {e}"
    
    # ========== CSV Validation ==========
    elif extension == '.csv':
        try:
            with open(file_path, 'r', encoding='utf-8') as f:
                # Read first few lines to check CSV validity
                first_line = f.readline()
                if not first_line:
                    return 'csv', False, "CSV file is empty"
                
                # Check for common CSV headers (Event ID, TimeCreated, etc.)
                if ',' in first_line:
                    return 'csv', True, None
                else:
                    return 'csv', False, "File doesn't appear to be valid CSV (no commas in header)"
        except UnicodeDecodeError:
            return 'csv', False, "CSV file is not UTF-8 encoded"
        except Exception as e:
            return 'csv', False, f"CSV validation failed: {e}"
    
    # ========== JSON Validation ==========
    elif extension == '.json':
        try:
            with open(file_path, 'r', encoding='utf-8') as f:
                data = json.load(f)
                # Check if it's an array or object with event-like structure
                if isinstance(data, list) and len(data) > 0:
                    return 'json', True, None
                elif isinstance(data, dict) and ('events' in data or 'records' in data):
                    return 'json', True, None
                else:
                    return 'json', False, "JSON structure doesn't contain events array"
        except json.JSONDecodeError as e:
            return 'json', False, f"Invalid JSON: {e}"
        except Exception as e:
            return 'json', False, f"JSON validation failed: {e}"
    
    # ========== EVT (Legacy) Validation ==========
    elif extension == '.evt':
        try:
            with open(file_path, 'rb') as f:
                # EVT files start with "LfLE" (0x4C, 0x66, 0x4C, 0x45)
                magic = f.read(4)
                if magic == b'LfLE':
                    return 'evt', True, None
                else:
                    return 'evt', False, f"Invalid EVT magic bytes: {magic!r}"
        except Exception as e:
            return 'evt', False, f"EVT validation failed: {e}"
    
    # Unknown extension
    return 'unknown', False, f"Unsupported file extension: {extension}"


def load_event_log(file_path):
    """
    Master loader function: auto-detects format, validates, and routes to appropriate parser.
    
    Returns: list of dicts (event records)
    Raises: ValueError if format is invalid or unsupported
    """
    file_path = Path(file_path)
    detected_format, is_valid, error_msg = detect_and_validate_format(file_path)
    
    # Print detection result
    print(f"\033[36m[*] Detected format: {detected_format.upper()}\033[0m")
    
    # Validation check
    if not is_valid:
        raise ValueError(f"\033[31m[-] Format validation failed: {error_msg}\033[0m")
    
    # Route to appropriate parser
    if detected_format == 'evtx':
        print(f"\033[33m[*] Parsing EVTX (binary format - may take time for large files)...\033[0m")
        return sysmon_evtx_parser(str(file_path))
    
    elif detected_format == 'csv':
        print(f"\033[33m[*] Parsing CSV (fast format)...\033[0m")
        return csv_parser(str(file_path))
    
    elif detected_format == 'json':
        print(f"\033[33m[*] Parsing JSON (fast format)...\033[0m")
        return json_parser(str(file_path))
    
    elif detected_format == 'evt':
        print(f"\033[33m[*] Parsing EVT legacy format...\033[0m")
        return evt_parser(str(file_path))
    
    else:
        raise ValueError(f"Unsupported format: {detected_format}")


# ===============================
# FORMAT-SPECIFIC PARSERS
# ===============================

def csv_parser(csv_path):
    """
    Parse CSV exported from Windows Event Viewer.
    Fast format suitable for large logs.
    """
    all_rows = []
    
    try:
        with open(csv_path, 'r', encoding='utf-8') as f:
            reader = csv.DictReader(f)
            for row in reader:
                # Normalize field names and convert dates
                normalized_row = {}
                for key, value in row.items():
                    if value:  # Only store non-empty values
                        # Handle common DateTime field names
                        if key in ['TimeCreated', 'Date and Time', 'UtcTime']:
                            try:
                                # Try ISO format first
                                dt = datetime.fromisoformat(value.replace('Z', '+00:00'))
                                normalized_row['DateTime'] = dt
                            except:
                                # Keep as string if parse fails
                                normalized_row[key] = value
                        else:
                            normalized_row[key.strip()] = value
                
                if normalized_row:  # Only append non-empty rows
                    all_rows.append(normalized_row)
        
        print(f"\033[32m[+] CSV parsed: {len(all_rows)} events\033[0m")
        return all_rows
    
    except Exception as e:
        print(f"\033[31m[-] CSV parsing error: {e}\033[0m")
        raise


def json_parser(json_path):
    """
    Parse JSON exported from PowerShell Get-WinEvent.
    Fast format suitable for large logs.
    """
    all_rows = []
    
    try:
        with open(json_path, 'r', encoding='utf-8') as f:
            data = json.load(f)
        
        # Handle both array and wrapped formats
        events = data if isinstance(data, list) else data.get('events', data.get('records', []))
        
        for event in events:
            if isinstance(event, dict):
                # Normalize field names
                normalized_row = {}
                for key, value in event.items():
                    if value:  # Only store non-empty values
                        # Handle DateTime conversion if needed
                        if key in ['TimeCreated', 'TimeGenerated'] and isinstance(value, str):
                            try:
                                dt = datetime.fromisoformat(value.replace('Z', '+00:00'))
                                normalized_row['DateTime'] = dt
                            except:
                                normalized_row[key] = value
                        else:
                            normalized_row[key.strip() if isinstance(key, str) else key] = value
                
                if normalized_row:
                    all_rows.append(normalized_row)
        
        print(f"\033[32m[+] JSON parsed: {len(all_rows)} events\033[0m")
        return all_rows
    
    except Exception as e:
        print(f"\033[31m[-] JSON parsing error: {e}\033[0m")
        raise


def evt_parser(evt_path):
    """
    Parse legacy EVT format (Windows NT Event Log format).
    Note: More limited than EVTX format.
    """
    # EVT format support requires more complex binary parsing
    # For now, provide a placeholder that explains limitations
    try:
        with open(evt_path, 'rb') as f:
            # Basic header validation
            magic = f.read(4)
            if magic != b'LfLE':
                raise ValueError("Invalid EVT file format")
        
        print(f"\033[33m[!] EVT legacy format detected. Support is limited.\033[0m")
        print(f"\033[33m[!] Consider exporting to CSV or EVTX for better compatibility.\033[0m")
        
        # For now, return empty list to prevent crashes
        # Full EVT parsing would require reverse-engineering the binary format
        return []
    
    except Exception as e:
        print(f"\033[31m[-] EVT parsing error: {e}\033[0m")
        raise


def sysmon_evtx_parser(evtx_path):
    """
    Optimized Sysmon EVTX parser with batch processing and efficient XPath.
    
    Improvements over v1:
    - Namespace dict cached outside loop
    - Direct XML parsing without intermediate storage
    - Batch progress indicators (every 100 records)
    - Optimized XPath: EventID + Data fields in single parse
    - Pre-compiled datetime parsing logic
    """
    all_rows = []
    ns = {"ns0": "http://schemas.microsoft.com/win/2004/08/events/event"}
    
    # Pre-compile datetime formats for faster parsing (avoid try/except on every record)
    datetime_formats = [
        "%Y-%m-%dT%H:%M:%S.%fZ",      # ISO format
        "%Y-%m-%d %H:%M:%S.%f"         # Space-separated format
    ]
    
    record_count = 0
    error_count = 0
    
    with Evtx(str(evtx_path)) as log:
        for record in log.records():
            record_count += 1
            
            # Progress indicator every 100 records
            if record_count % 100 == 0:
                print(f"\033[36m[*] Processed {record_count} records...\033[0m", end='\r')
            
            try:
                root = ET.fromstring(record.xml())
                row_dict = {}
                
                # Extract EventID directly (avoid unnecessary search)
                event_id_elem = root.find(".//ns0:EventID", ns)
                if event_id_elem is not None and event_id_elem.text:
                    row_dict["EventID"] = event_id_elem.text
                
                # Extract System fields (Computer, TimeCreated, etc.)
                system_elem = root.find(".//ns0:System", ns)
                if system_elem is not None:
                    # Get Computer name
                    computer_elem = system_elem.find(".//ns0:Computer", ns)
                    if computer_elem is not None and computer_elem.text:
                        row_dict["Computer"] = computer_elem.text
                
                # Extract all EventData fields efficiently
                for data in root.findall(".//ns0:Data", ns):           
                    name = data.attrib.get("Name")
                    value = data.text
                    
                    if value:  # Only store non-empty values
                        # Handle UtcTime with optimized parsing
                        if name == "UtcTime":
                            for fmt in datetime_formats:
                                try:
                                    row_dict['DateTime'] = datetime.strptime(value, fmt)
                                    break
                                except ValueError:
                                    pass
                        else:
                            row_dict[name] = value
                
                all_rows.append(row_dict)
                
            except Exception as e:
                error_count += 1
                if error_count <= 5:  # Only print first 5 errors
                    print(f"\033[33m[!] Error on record {record_count}: {e}\033[0m")
    
    # Clear progress line
    print(" " * 60, end='\r')
    print(f"\033[32m[+] EVTX parsed: {len(all_rows)} events ({error_count} errors)\033[0m")
    return all_rows


def security_evtx_parser(evtx_path):
    """
    Optimized Security EVTX parser with batch processing and efficient XPath.
    
    Improvements:
    - Namespace cached outside loop
    - Single XML parsing pass per record
    - Batch progress indicators
    - Optimized datetime parsing
    """
    all_rows = []
    ns = {"ns0": "http://schemas.microsoft.com/win/2004/08/events/event"}
    
    datetime_formats = [
        "%Y-%m-%dT%H:%M:%S.%fZ",
        "%Y-%m-%d %H:%M:%S.%f"
    ]
    
    record_count = 0
    error_count = 0
    
    with Evtx(str(evtx_path)) as log:
        for record in log.records():
            record_count += 1
            
            if record_count % 100 == 0:
                print(f"\033[36m[*] Processed {record_count} records...\033[0m", end='\r')
            
            try:
                root = ET.fromstring(record.xml())
                row_dict = {}
                
                # Extract EventID
                event_id_elem = root.find(".//ns0:EventID", ns)
                if event_id_elem is not None and event_id_elem.text:
                    row_dict["EventID"] = event_id_elem.text
                
                # Extract System/TimeCreated element directly
                system_elem = root.find(".//ns0:System", ns)
                if system_elem is not None:
                    time_elem = system_elem.find(".//ns0:TimeCreated", ns)
                    if time_elem is not None:
                        time_str = time_elem.attrib.get("SystemTime")
                        if time_str:
                            for fmt in datetime_formats:
                                try:
                                    row_dict['DateTime'] = datetime.strptime(time_str, fmt)
                                    break
                                except ValueError:
                                    pass
                
                # Extract EventData fields in single pass
                for data in root.findall(".//ns0:Data", ns):
                    name = data.attrib.get("Name")
                    value = data.text or ""
                    
                    if value:  # Only store non-empty values
                        row_dict[name] = value
                
                all_rows.append(row_dict)
                
            except Exception as e:
                error_count += 1
                if error_count <= 5:
                    print(f"\033[33m[!] Error on record {record_count}: {e}\033[0m")
    
    # Clear progress line
    print(" " * 60, end='\r')
    print(f"\033[32m[+] Security log parsed: {len(all_rows)} events ({error_count} errors)\033[0m")
    return all_rows

def evtx_to_csv(data_rows, evtx_path, output_dir=None):
    """Export parsed events to CSV format."""
    event_data_fields = set()
    for row in data_rows:
        event_data_fields.update(row.keys())

    # Save to output directory (if provided) or default output directory
    if output_dir:
        results_dir = Path(output_dir)
    else:
        results_dir = Path(__file__).resolve().parent.parent / "data" / "output"

    results_dir.mkdir(parents=True, exist_ok=True)
    
    timestamp = datetime.now().strftime('%Y%m%d_%H%M%S')
    evtx_name = Path(evtx_path).stem
    csv_filename = f"{evtx_name}_{timestamp}.csv"
    csv_path = results_dir / csv_filename
    
    with open(csv_path, mode='w', newline='', encoding='utf-8') as f:
            fieldnames = sorted(list(event_data_fields))
            writer = csv.DictWriter(f, fieldnames=fieldnames)
            writer.writeheader()
            writer.writerows(data_rows)
    print(f"\033[32m[+] CSV export successful: {csv_path}\033[0m")