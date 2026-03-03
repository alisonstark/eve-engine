# ===============================
# .evtx to .csv Converter Program
# ===============================

# Python imports
from Evtx.Evtx import Evtx
from datetime import datetime
from pathlib import Path
import csv

import xml.etree.ElementTree as ET

def sysmon_evtx_parser(evtx_path):

    """
    This function parses a Sysmon .evtx file and extracts relevant event data into a list of dictionaries. 
    Each dictionary represents a single event record, with keys corresponding to the event's data fields (e.g., EventID, UtcTime, RuleName, etc.). 
    The function handles both the standard XML structure of Sysmon events and potential variations in the timestamp format. 
    It also includes error handling to catch and report any issues encountered during parsing, such as malformed XML or unexpected data formats. 
    The resulting list of dictionaries can then be easily converted to a CSV file for further analysis or reporting.
    """

    all_rows = []
    ns = {"ns0": "http://schemas.microsoft.com/win/2004/08/events/event"}

    with Evtx(str(evtx_path)) as log:
        for record in log.records():
            
            try:
                root = ET.fromstring(record.xml())
                row_dict = {}
            
                # ACTUAL xml format: <ns0:EventID Qualifiers="">10</ns0:EventID>
                event_id_elem = root.find(".//ns0:EventID", ns)
                if event_id_elem is not None and event_id_elem.text:
                    row_dict["EventID"] = event_id_elem.text

                # ACTUAL xml format: <ns0:EventData><ns0:Data Name="RuleName">-</ns0:Data>
                # Extract all data fields in a single pass
                for data in root.findall(".//ns0:Data", ns):           
                    name = data.attrib.get("Name")
                    value = data.text
                    
                    if name == "UtcTime":
                        try:
                            # Try with T and Z (ideal ISO format)
                            utc_time = datetime.strptime(value, "%Y-%m-%dT%H:%M:%S.%fZ")
                        except ValueError:
                            try:
                                # Fallback to space-separated format (what you have)
                                utc_time = datetime.strptime(value, "%Y-%m-%d %H:%M:%S.%f")
                            except ValueError:
                                print(f"[-] Failed to parse UtcTime: {value}")
                                continue
                        
                        row_dict['DateTime'] = utc_time
                    
                    if value:  # Only store non-empty values
                        row_dict[name] = value

                all_rows.append(row_dict)

            except Exception as e:
                print(f"Error processing Sysmon record: {e}")
                print(f"Record XML: {record.xml()}")

    # for row in all_rows:
    #    print(row) # DEBUG all rows, where all_rows = [row_dict_1, row_dict_2, row_dict_3, ...]

    return all_rows

def security_evtx_parser(evtx_path):

    """
    This function parses a Security .evtx file and extracts relevant event data into a list of dictionaries. 
    Each dictionary represents a single event record, with keys corresponding to the event's data fields (e.g., EventID, TimeCreated, etc.).
    """

    all_rows = []
    ns = {"ns0": "http://schemas.microsoft.com/win/2004/08/events/event"}

    with Evtx(str(evtx_path)) as log:
        for record in log.records():
            try:
                root = ET.fromstring(record.xml())
                row_dict = {}

                # Extract EventID
                event_id_elem = root.find(".//ns0:EventID", ns)
                if event_id_elem is not None and event_id_elem.text:
                    row_dict["EventID"] = event_id_elem.text
                
                # Extract TimeCreated
                time_created_elem = root.find(".//ns0:TimeCreated", ns)
                if time_created_elem is not None and time_created_elem.attrib.get("SystemTime"):
                    time_str = time_created_elem.attrib.get("SystemTime")
                    try:
                        utc_time = datetime.strptime(time_str, "%Y-%m-%dT%H:%M:%S.%fZ")
                    except ValueError:
                        try:
                            utc_time = datetime.strptime(time_str, "%Y-%m-%d %H:%M:%S.%f")
                        except ValueError:
                            print(f"[-] Failed to parse SystemTime: {time_str}")
                            utc_time = None

                    if utc_time:
                        row_dict['DateTime'] = utc_time

                # Extract all data fields in single pass
                for data in root.findall(".//ns0:Data", ns):
                    name = data.attrib.get("Name")
                    value = data.text or ""

                    if value:  # Only store non-empty values
                        row_dict[name] = value

                all_rows.append(row_dict)

            except Exception as e:
                print(f"Error processing Security record: {e}")
                print(f"Record XML: {record.xml()}")

    return all_rows

def evtx_to_csv(data_rows, evtx_path, output_dir=None):
    event_data_fields = set()
    for row in data_rows:
        event_data_fields.update(row.keys())

    # Save to output directory (if provided) or default results directory
    if output_dir:
        results_dir = Path(output_dir)
    else:
        results_dir = Path(__file__).resolve().parent.parent / "data" / "test" / "results"

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
    print("\033[32m[+] Results saved to CSV file:\033[0m " + str(csv_path))