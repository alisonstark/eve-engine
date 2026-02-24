# ===============================
# Log Printing Functions
# ===============================

from pprint import pprint

# Function to print the event details
# This function is called when a potential malicious activity is detected
def print_sysmon_event(event):
    print("\033[1;36m[+] Summary of the activity\033[0m")

    event_id = event.get("EventID", "")
    image = event.get("Image", "")
    source_image = event.get("SourceImage", "")
    target_image = event.get("TargetImage", "")
    utc_time = event.get("UtcTime", "")
    
    # Case of Unmanaged Powershell attacks
    if image == "" or event_id == '8' or event_id == '10':
        print(f"Injector process: {source_image}" + "\n",
              f"Injected process: {target_image}" + "\n", 
              f"Event Time: {utc_time}" + "\n")
    
    else:
        print(f"Initiator process: {image}" + "\n",
          f"Event Time: {utc_time}" + "\n")
    
    pprint(event)
    print("\n")

def print_security_event(event):

    process_name = event.get("ProcessName", "")
    time_created = event.get("TimeCreated", "")

    if process_name != "" and time_created != "":
        print("\033[1;36m\n[+] Summary of the activity\033[0m")
        print(f"Process name: {event['ProcessName']}" + "\n",
            f"Event Time: {event['TimeCreated']}" + "\n")
    pprint(event)
    print("\n")