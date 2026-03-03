"""
Unit tests for detection functions in scanners.py

Tests are clean and simple now that functions return data structures instead of printing.
Converted to pytest for industry-standard testing.
"""

import pytest
from engine.src.scanners import (
    detect_DLLHijack,
    detect_UnmanagedPowerShell,
    detect_LsassDump,
    detect_strange_PPID,
    detect_BruteForce,
    detect_EventLogClearing,
    detect_ServiceCreation,
    detect_ScheduledTaskCreation,
    detect_AccountManipulation,
    aggregate_incidents,
    aggregate_all_detections
)


# ============= DLL HIJACKING DETECTION TESTS =============

def test_dll_hijack_no_events():
    """Should return empty result when no events provided."""
    result = detect_DLLHijack([], target_dll=None, include_context=False)
    assert result["count"] == 0
    assert result["detected_events"] == []
    assert result["high_confidence_count"] == 0
    assert result["high_confidence_events"] == []
    assert result["detection_type"] == "DLL Hijacking"


def test_dll_hijack_returns_required_fields():
    """Should return all required fields in result dict."""
    result = detect_DLLHijack([], target_dll=None, include_context=False)
    required_fields = [
        "detected_events", "high_confidence_events", "context_events",
        "earliest_time", "commands", "detection_type", "count", 
        "high_confidence_count", "context_count"
    ]
    for field in required_fields:
        assert field in result, f"Missing required field: {field}"

def test_dll_hijack_detect_hijackable_dll():
    """Should detect when hijackable DLL is loaded."""
    import engine.src.scanners as scanners
    orig_func = scanners._get_hijackable_dlls_list
    scanners._get_hijackable_dlls_list = lambda: ["malicious.dll"]
    scanners._hijackable_dlls = None

    data_rows = [{
        "EventID": "7",
        "Image": "C:\\Windows\\System32\\notepad.exe",
        "ImageLoaded": "C:\\Windows\\System32\\malicious.dll",
        "DateTime": "2024-01-01T00:00:00"
    }]

    try:
        result = detect_DLLHijack(data_rows, target_dll=None, include_context=False)
        assert result["count"] == 1
        assert len(result["detected_events"]) == 1
        assert "malicious.dll" in result["detected_events"][0]["ImageLoaded"]
        assert "high_confidence_events" in result
        assert "high_confidence_count" in result
    finally:
        scanners._get_hijackable_dlls_list = orig_func
        scanners._hijackable_dlls = None


def test_dll_hijack_high_confidence_has_risk_scores():
    """High-confidence events should have risk_score field."""
    import engine.src.scanners as scanners
    orig_func = scanners._get_hijackable_dlls_list
    scanners._get_hijackable_dlls_list = lambda: ["malicious.dll"]
    scanners._hijackable_dlls = None

    data_rows = [{
        "EventID": "7",
        "Image": "C:\\Windows\\System32\\cmd.exe",
        "ImageLoaded": "C:\\Temp\\malicious.dll",
        "DateTime": "2024-01-01T00:00:00"
    }]

    try:
        result = detect_DLLHijack(data_rows, target_dll=None, include_context=False)
        if result["high_confidence_count"] > 0:
            for event in result["high_confidence_events"]:
                assert "risk_score" in event
                assert event["risk_score"] >= 40
    finally:
        scanners._get_hijackable_dlls_list = orig_func
        scanners._hijackable_dlls = None


def test_dll_hijack_risk_scoring_filters_correctly():
    """Events below threshold should be in detected but not high_confidence."""
    import engine.src.scanners as scanners
    orig_func = scanners._get_hijackable_dlls_list
    scanners._get_hijackable_dlls_list = lambda: ["test.dll"]
    scanners._hijackable_dlls = None

    data_rows = [{
        "EventID": "7",
        "Image": "C:\\Windows\\System32\\svchost.exe",
        "ImageLoaded": "C:\\Windows\\System32\\test.dll",
        "DateTime": "2024-01-01T00:00:00"
    }]

    try:
        result = detect_DLLHijack(data_rows, target_dll=None, include_context=False)
        assert result["count"] > 0
        for event in result["detected_events"]:
            if "risk_score" in event:
                assert isinstance(event["risk_score"], int)
    finally:
        scanners._get_hijackable_dlls_list = orig_func
        scanners._hijackable_dlls = None


def test_dll_hijack_target_dll_matching():
    """Should detect when target DLL matches."""
    data_rows = [{
        "EventID": "7",
        "Image": "C:\\Windows\\System32\\notepad.exe",
        "ImageLoaded": "C:\\Windows\\System32\\target.dll",
        "DateTime": "2024-01-01T00:00:00"
    }]

    result = detect_DLLHijack(data_rows, target_dll="target.dll", include_context=False)
    assert result["count"] == 1


def test_dll_hijack_ignores_non_exe_image():
    """Should ignore events where Image doesn't end with .exe."""
    import engine.src.scanners as scanners
    orig_func = scanners._get_hijackable_dlls_list
    scanners._get_hijackable_dlls_list = lambda: ["malicious.dll"]
    scanners._hijackable_dlls = None

    data_rows = [{
        "EventID": "7",
        "Image": "C:\\Windows\\System32\\notepad.dll",
        "ImageLoaded": "C:\\Windows\\System32\\malicious.dll",
        "DateTime": "2024-01-01T00:00:00"
    }]

    try:
        result = detect_DLLHijack(data_rows, target_dll=None, include_context=False)
        assert result["count"] == 0
    finally:
        scanners._get_hijackable_dlls_list = orig_func
        scanners._hijackable_dlls = None


def test_dll_hijack_ignores_wrong_eventid():
    """Should ignore events with EventID other than 7."""
    import engine.src.scanners as scanners
    orig_func = scanners._get_hijackable_dlls_list
    scanners._get_hijackable_dlls_list = lambda: ["malicious.dll"]
    scanners._hijackable_dlls = None

    data_rows = [{
        "EventID": "1",
        "Image": "C:\\Windows\\System32\\notepad.exe",
        "ImageLoaded": "C:\\Windows\\System32\\malicious.dll",
        "DateTime": "2024-01-01T00:00:00"
    }]

    try:
        result = detect_DLLHijack(data_rows, target_dll=None, include_context=False)
        assert result["count"] == 0
    finally:
        scanners._get_hijackable_dlls_list = orig_func
        scanners._hijackable_dlls = None


def test_dll_hijack_command_extraction():
    """Should extract CommandLine from detected events."""
    import engine.src.scanners as scanners
    orig_func = scanners._get_hijackable_dlls_list
    scanners._get_hijackable_dlls_list = lambda: ["malicious.dll"]
    scanners._hijackable_dlls = None

    data_rows = [{
        "EventID": "7",
        "Image": "C:\\Windows\\System32\\notepad.exe",
        "ImageLoaded": "C:\\Windows\\System32\\malicious.dll",
        "DateTime": "2024-01-01T00:00:00",
        "CommandLine": "notepad.exe evil.txt"
    }]

    try:
        result = detect_DLLHijack(data_rows, target_dll=None, include_context=False)
        assert result["count"] == 1
        assert "notepad.exe evil.txt" in result["commands"]
    finally:
        scanners._get_hijackable_dlls_list = orig_func
        scanners._hijackable_dlls = None


def test_dll_hijack_case_insensitivity():
    """Should detect DLLs regardless of case."""
    import engine.src.scanners as scanners
    orig_func = scanners._get_hijackable_dlls_list
    scanners._get_hijackable_dlls_list = lambda: ["malicious.dll"]
    scanners._hijackable_dlls = None

    data_rows = [{
        "EventID": "7",
        "Image": "C:\\Windows\\System32\\notepad.exe",
        "ImageLoaded": "C:\\Windows\\System32\\MALICIOUS.DLL",
        "DateTime": "2024-01-01T00:00:00"
    }]

    try:
        result = detect_DLLHijack(data_rows, target_dll=None, include_context=False)
        assert result["count"] == 1
    finally:
        scanners._get_hijackable_dlls_list = orig_func
        scanners._hijackable_dlls = None


# ============= UNMANAGED POWERSHELL DETECTION TESTS =============

def test_powershell_no_events():
    """Should return empty result when no events provided."""
    result = detect_UnmanagedPowerShell([], target_dll=None, include_context=False)
    assert result["clr_count"] == 0
    assert result["clr_events"] == []
    assert result["injection_count"] == 0
    assert result["injection_events"] == []
    assert result["network_count"] == 0
    assert result["network_events"] == []


def test_powershell_returns_required_fields():
    """Should return all required fields in result dict."""
    result = detect_UnmanagedPowerShell([], target_dll=None, include_context=False)
    required_fields = [
        "clr_events", "injection_events", "network_events",
        "high_confidence_clr_events", "high_confidence_injection_events", 
        "high_confidence_network_events",
        "clr_count", "injection_count", "network_count",
        "high_confidence_clr_count", "high_confidence_injection_count",
        "high_confidence_network_count",
        "context_events", "earliest_time", "commands", 
        "detection_type"
    ]
    for field in required_fields:
        assert field in result, f"Missing required field: {field}"


def test_powershell_high_confidence_clr_fields_exist():
    """High-confidence CLR events should have separate field."""
    result = detect_UnmanagedPowerShell([], target_dll=None, include_context=False)
    assert "high_confidence_clr_events" in result
    assert "high_confidence_clr_count" in result
    assert result["high_confidence_clr_count"] == 0
    assert result["high_confidence_clr_events"] == []


def test_powershell_detect_clr_dll():
    """Should detect CLR DLL loads."""
    data_rows = [{
        "EventID": "7",
        "Image": "powershell.exe",
        "ImageLoaded": "C:\\Windows\\System32\\clr.dll",
        "DateTime": "2024-01-01T00:00:00"
    }]

    result = detect_UnmanagedPowerShell(data_rows, target_dll=None, include_context=False)
    assert result["clr_count"] == 1


def test_powershell_ignores_non_clr_dlls():
    """Should ignore non-CLR DLLs."""
    data_rows = [{
        "EventID": "7",
        "Image": "notepad.exe",
        "ImageLoaded": "C:\\Windows\\System32\\normal.dll",
        "DateTime": "2024-01-01T00:00:00"
    }]

    result = detect_UnmanagedPowerShell(data_rows, target_dll=None, include_context=False)
    assert result["clr_count"] == 0


# ============= LSASS DUMP DETECTION TESTS =============

def test_lsass_no_events():
    """Should return empty result when no events provided."""
    result = detect_LsassDump([], include_context=False)
    assert result["count"] == 0
    assert result["detected_events"] == []
    assert result["high_confidence_count"] == 0
    assert result["high_confidence_events"] == []


def test_lsass_returns_required_fields():
    """Should return all required fields in result dict."""
    result = detect_LsassDump([], include_context=False)
    required_fields = [
        "detected_events", "high_confidence_events", "context_events",
        "earliest_time", "commands", "detection_type", "count",
        "high_confidence_count", "context_count"
    ]
    for field in required_fields:
        assert field in result, f"Missing required field: {field}"


def test_lsass_detect_lsass_dump():
    """Should detect LSASS dump attempts."""
    data_rows = [{
        "EventID": "10",
        "TargetImage": "C:\\Windows\\System32\\lsass.exe",
        "GrantedAccess": "0x001fffff",
        "SourceUser": "DOMAIN\\attacker",
        "TargetUser": "DOMAIN\\SYSTEM",
        "SourceProcessImage": "C:\\Windows\\System32\\cmd.exe",
        "DateTime": "2024-01-01T00:00:00"
    }]

    result = detect_LsassDump(data_rows, include_context=False)
    assert result["count"] == 1
    assert result["high_confidence_count"] > 0


def test_lsass_dump_has_risk_score():
    """LSASS dump attempts should have risk_score."""
    data_rows = [{
        "EventID": "10",
        "TargetImage": "C:\\Windows\\System32\\lsass.exe",
        "GrantedAccess": "0x001fffff",
        "SourceUser": "DOMAIN\\attacker",
        "TargetUser": "DOMAIN\\SYSTEM",
        "SourceProcessImage": "C:\\Windows\\System32\\rundll32.exe",
        "DateTime": "2024-01-01T00:00:00"
    }]

    result = detect_LsassDump(data_rows, include_context=False)
    if result["high_confidence_count"] > 0:
        for event in result["high_confidence_events"]:
            assert "risk_score" in event
            assert event["risk_score"] >= 40


def test_lsass_ignores_non_lsass():
    """Should ignore events not targeting lsass.exe."""
    data_rows = [{
        "EventID": "10",
        "TargetImage": "C:\\Windows\\System32\\notepad.exe",
        "GrantedAccess": "0x001fffff",
        "SourceUser": "DOMAIN\\attacker",
        "TargetUser": "DOMAIN\\SYSTEM",
        "DateTime": "2024-01-01T00:00:00"
    }]

    result = detect_LsassDump(data_rows, include_context=False)
    assert result["count"] == 0


def test_lsass_ignores_wrong_eventid():
    """Should ignore events with wrong EventID."""
    data_rows = [{
        "EventID": "1",
        "TargetImage": "C:\\Windows\\System32\\lsass.exe",
        "GrantedAccess": "0x001fffff",
        "SourceUser": "DOMAIN\\attacker",
        "TargetUser": "DOMAIN\\SYSTEM",
        "DateTime": "2024-01-01T00:00:00"
    }]

    result = detect_LsassDump(data_rows, include_context=False)
    assert result["count"] == 0


# ============= STRANGE PPID DETECTION TESTS =============

def test_ppid_no_events():
    """Should return empty result when no events provided."""
    result = detect_strange_PPID([])
    assert result["count"] == 0
    assert result["detected_events"] == []
    assert result["high_confidence_count"] == 0
    assert result["high_confidence_events"] == []


def test_ppid_returns_required_fields():
    """Should return all required fields in result dict."""
    result = detect_strange_PPID([])
    required_fields = [
        "detected_events", "high_confidence_events", "earliest_time",
        "commands", "detection_type", "count", "high_confidence_count"
    ]
    for field in required_fields:
        assert field in result, f"Missing required field: {field}"


def test_ppid_detect_suspicious_ppid():
    """Should detect suspicious parent-child process relationships."""
    data_rows = [{
        "EventID": "1",
        "Image": "C:\\Windows\\System32\\cmd.exe",
        "ParentImage": "C:\\Program Files\\Microsoft Office\\winword.exe",
        "CommandLine": "cmd.exe /c malicious.bat",
        "DateTime": "2024-01-01T00:00:00"
    }]

    result = detect_strange_PPID(data_rows)
    assert result["count"] == 1
    assert result["high_confidence_count"] > 0


def test_ppid_has_risk_score():
    """Detected PPIDs should have risk_score."""
    data_rows = [{
        "EventID": "1",
        "Image": "C:\\Windows\\System32\\powershell.exe",
        "ParentImage": "C:\\Program Files\\Microsoft Office\\excel.exe",
        "CommandLine": "powershell.exe -enc <base64>",
        "DateTime": "2024-01-01T00:00:00"
    }]

    result = detect_strange_PPID(data_rows)
    if result["high_confidence_count"] > 0:
        for event in result["high_confidence_events"]:
            assert "risk_score" in event
            assert event["risk_score"] >= 40


def test_ppid_office_to_powershell_higher_risk():
    """PowerShell spawning should score higher than cmd.exe spawning."""
    data_rows_cmd = [{
        "EventID": "1",
        "Image": "C:\\Windows\\System32\\cmd.exe",
        "ParentImage": "C:\\Program Files\\Microsoft Office\\winword.exe",
        "CommandLine": "cmd.exe",
        "DateTime": "2024-01-01T00:00:00"
    }]

    data_rows_ps = [{
        "EventID": "1",
        "Image": "C:\\Windows\\System32\\powershell.exe",
        "ParentImage": "C:\\Program Files\\Microsoft Office\\winword.exe",
        "CommandLine": "powershell.exe",
        "DateTime": "2024-01-01T00:00:00"
    }]

    result_cmd = detect_strange_PPID(data_rows_cmd)
    result_ps = detect_strange_PPID(data_rows_ps)
    
    assert result_cmd["count"] == 1
    assert result_ps["count"] == 1
    assert result_cmd["high_confidence_count"] == 1
    assert result_ps["high_confidence_count"] == 1
    
    cmd_score = result_cmd["high_confidence_events"][0]["risk_score"]
    ps_score = result_ps["high_confidence_events"][0]["risk_score"]
    assert ps_score > cmd_score


def test_ppid_ignores_non_suspicious():
    """Should ignore non-suspicious parent-child pairs."""
    data_rows = [{
        "EventID": "1",
        "Image": "C:\\Windows\\System32\\normal.exe",
        "ParentImage": "C:\\Windows\\System32\\explorer.exe",
        "DateTime": "2024-01-01T00:00:00"
    }]

    result = detect_strange_PPID(data_rows)
    assert result["count"] == 0


def test_ppid_case_insensitive_matching():
    """Should match parent-child pairs case-insensitively."""
    data_rows = [{
        "EventID": "1",
        "Image": "C:\\Path\\To\\CMD.EXE",
        "ParentImage": "C:\\Path\\To\\WINWORD.EXE",
        "DateTime": "2024-01-01T00:00:00"
    }]

    result = detect_strange_PPID(data_rows)
    assert result["count"] == 1


# ============= BRUTE FORCE DETECTION TESTS =============

def test_bruteforce_no_events():
    """Should return empty result when no events provided."""
    result = detect_BruteForce([], include_context=False)
    assert result["count"] == 0
    assert result["detection_type"] == "Brute Force/Failed Logins"


def test_bruteforce_returns_required_fields():
    """Should return all required fields in result dict."""
    result = detect_BruteForce([], include_context=False)
    required_fields = [
        "detected_events", "high_confidence_events", "context_events",
        "earliest_time", "detection_type", "count", "high_confidence_count", "context_count"
    ]
    for field in required_fields:
        assert field in result, f"Missing required field: {field}"


def test_bruteforce_detect_failed_logon():
    """Should detect failed login attempts (Event ID 4625)."""
    data_rows = [
        {
            "EventID": "4625",
            "TargetUserName": "testuser",
            "Workstation": "DESKTOP-ABC",
            "DateTime": "2024-01-01T00:00:00"
        }
    ]
    result = detect_BruteForce(data_rows, include_context=False)
    assert result["count"] == 1


def test_bruteforce_detect_account_lockout():
    """Should detect account lockouts (Event ID 4740)."""
    data_rows = [
        {
            "EventID": "4740",
            "TargetUserName": "admin",
            "DateTime": "2024-01-01T00:00:00"
        }
    ]
    result = detect_BruteForce(data_rows, include_context=False)
    assert result["count"] == 1


def test_bruteforce_high_confidence_multiple_failures():
    """Multiple failures from same source should be high-confidence."""
    data_rows = [
        {
            "EventID": "4625",
            "TargetUserName": "user1",
            "Workstation": "DESKTOP-XYZ",
            "DateTime": "2024-01-01T00:00:00"
        },
        {
            "EventID": "4625",
            "TargetUserName": "user1",
            "Workstation": "DESKTOP-XYZ",
            "DateTime": "2024-01-01T00:00:01"
        },
        {
            "EventID": "4625",
            "TargetUserName": "user1",
            "Workstation": "DESKTOP-XYZ",
            "DateTime": "2024-01-01T00:00:02"
        }
    ]
    result = detect_BruteForce(data_rows, include_context=False)
    assert result["count"] == 3
    assert result["high_confidence_count"] >= 1


# ============= EVENT LOG CLEARING DETECTION TESTS =============

def test_eventlog_no_events():
    """Should return empty result when no events provided."""
    result = detect_EventLogClearing([], include_context=False)
    assert result["count"] == 0
    assert result["detection_type"] == "Event Log Clearing/Tampering"


def test_eventlog_returns_required_fields():
    """Should return all required fields in result dict."""
    result = detect_EventLogClearing([], include_context=False)
    required_fields = [
        "detected_events", "context_events", "earliest_time",
        "detection_type", "count", "context_count"
    ]
    for field in required_fields:
        assert field in result, f"Missing required field: {field}"


def test_eventlog_detect_log_cleared():
    """Should detect when log is cleared (Event ID 1102)."""
    data_rows = [
        {
            "EventID": "1102",
            "Computer": "SERVER-01",
            "DateTime": "2024-01-01T00:00:00"
        }
    ]
    result = detect_EventLogClearing(data_rows, include_context=False)
    assert result["count"] == 1


def test_eventlog_detect_log_service_shutdown():
    """Should detect log service shutdown (Event ID 1100)."""
    data_rows = [
        {
            "EventID": "1100",
            "Computer": "SERVER-02",
            "DateTime": "2024-01-01T00:00:00"
        }
    ]
    result = detect_EventLogClearing(data_rows, include_context=False)
    assert result["count"] == 1


# ============= SERVICE CREATION DETECTION TESTS =============

def test_service_no_events():
    """Should return empty result when no events provided."""
    result = detect_ServiceCreation([], include_context=False)
    assert result["count"] == 0
    assert result["detection_type"] == "Service Creation"


def test_service_returns_required_fields():
    """Should return all required fields in result dict."""
    result = detect_ServiceCreation([], include_context=False)
    required_fields = [
        "detected_events", "high_confidence_events", "context_events",
        "earliest_time", "detection_type", "count", "high_confidence_count", "context_count"
    ]
    for field in required_fields:
        assert field in result, f"Missing required field: {field}"


def test_service_detect_service_creation_sysmon():
    """Should detect service creation (Event ID 7045 - Sysmon)."""
    data_rows = [
        {
            "EventID": "7045",
            "ServiceName": "TestService",
            "ImagePath": "C:\\Windows\\System32\\test.exe",
            "DateTime": "2024-01-01T00:00:00"
        }
    ]
    result = detect_ServiceCreation(data_rows, include_context=False)
    assert result["count"] == 1


def test_service_detect_service_creation_security():
    """Should detect service installation (Event ID 4697 - Security)."""
    data_rows = [
        {
            "EventID": "4697",
            "ServiceName": "SuspiciousService",
            "ServicePath": "C:\\Temp\\malware.exe",
            "DateTime": "2024-01-01T00:00:00"
        }
    ]
    result = detect_ServiceCreation(data_rows, include_context=False)
    assert result["count"] == 1


def test_service_high_confidence_suspicious_path():
    """Services from suspicious paths should be high-confidence."""
    data_rows = [
        {
            "EventID": "4697",
            "ServiceName": "TestService",
            "ServicePath": "C:\\Users\\Public\\malware.exe",
            "DateTime": "2024-01-01T00:00:00"
        }
    ]
    result = detect_ServiceCreation(data_rows, include_context=False)
    assert result["high_confidence_count"] >= 1


# ============= SCHEDULED TASK CREATION DETECTION TESTS =============

def test_task_no_events():
    """Should return empty result when no events provided."""
    result = detect_ScheduledTaskCreation([], include_context=False)
    assert result["count"] == 0
    assert result["detection_type"] == "Scheduled Task Creation"


def test_task_returns_required_fields():
    """Should return all required fields in result dict."""
    result = detect_ScheduledTaskCreation([], include_context=False)
    required_fields = [
        "detected_events", "high_confidence_events", "context_events",
        "earliest_time", "detection_type", "count", "high_confidence_count", "context_count"
    ]
    for field in required_fields:
        assert field in result, f"Missing required field: {field}"


def test_task_detect_task_created():
    """Should detect scheduled task creation (Event ID 4698)."""
    data_rows = [
        {
            "EventID": "4698",
            "TaskName": "\\Microsoft\\Windows\\MyTask",
            "TaskContent": "cmd.exe",
            "DateTime": "2024-01-01T00:00:00"
        }
    ]
    result = detect_ScheduledTaskCreation(data_rows, include_context=False)
    assert result["count"] == 1


def test_task_high_confidence_suspicious_task():
    """Tasks with suspicious content should be high-confidence."""
    data_rows = [
        {
            "EventID": "4698",
            "TaskName": "\\Hidden__Task",
            "TaskContent": "C:\\Temp\\malware.exe base64 -enc",
            "DateTime": "2024-01-01T00:00:00"
        }
    ]
    result = detect_ScheduledTaskCreation(data_rows, include_context=False)
    assert result["high_confidence_count"] >= 1


# ============= ACCOUNT MANIPULATION DETECTION TESTS =============

def test_account_no_events():
    """Should return empty result when no events provided."""
    result = detect_AccountManipulation([], include_context=False)
    assert result["count"] == 0
    assert result["detection_type"] == "Account Manipulation"


def test_account_returns_required_fields():
    """Should return all required fields in result dict."""
    result = detect_AccountManipulation([], include_context=False)
    required_fields = [
        "detected_events", "high_confidence_events", "context_events",
        "earliest_time", "detection_type", "count", "high_confidence_count", "context_count"
    ]
    for field in required_fields:
        assert field in result, f"Missing required field: {field}"


def test_account_detect_account_created():
    """Should detect new account creation (Event ID 4720)."""
    data_rows = [
        {
            "EventID": "4720",
            "TargetUserName": "newuser",
            "DateTime": "2024-01-01T00:00:00"
        }
    ]
    result = detect_AccountManipulation(data_rows, include_context=False)
    assert result["count"] == 1


def test_account_detect_local_group_member_added():
    """Should detect user added to local group (Event ID 4732)."""
    data_rows = [
        {
            "EventID": "4732",
            "TargetGroupName": "Administrators",
            "MemberName": "DOMAIN\\user1",
            "DateTime": "2024-01-01T00:00:00"
        }
    ]
    result = detect_AccountManipulation(data_rows, include_context=False)
    assert result["count"] == 1


def test_account_detect_global_group_member_added():
    """Should detect user added to global group (Event ID 4728)."""
    data_rows = [
        {
            "EventID": "4728",
            "TargetGroupName": "DomainAdmins",
            "MemberName": "DOMAIN\\admin",
            "DateTime": "2024-01-01T00:00:00"
        }
    ]
    result = detect_AccountManipulation(data_rows, include_context=False)
    assert result["count"] == 1


def test_account_high_confidence_admin_group():
    """Adding to privileged groups should be high-confidence."""
    data_rows = [
        {
            "EventID": "4732",
            "TargetGroupName": "Administrators",
            "MemberName": "DOMAIN\\suspicioususer",
            "DateTime": "2024-01-01T00:00:00"
        }
    ]
    result = detect_AccountManipulation(data_rows, include_context=False)
    assert result["high_confidence_count"] >= 1


# ============= INCIDENT AGGREGATION TESTS =============

def test_aggregate_incidents_empty_result():
    """Should handle empty detection result gracefully."""
    result = {"detected_events": [], "count": 0}
    aggregated = aggregate_incidents(result, group_by_fields=("Image", "ImageLoaded"))
    assert aggregated["detected_events"] == []
    assert aggregated["count"] == 0
    assert aggregated["is_aggregated"] == True


def test_aggregate_incidents_single_event():
    """Single event should create one incident."""
    result = {
        "detected_events": [
            {
                "Image": "cmd.exe",
                "ImageLoaded": "malicious.dll",
                "risk_score": 50,
                "DateTime": "2024-01-01T00:00:00",
                "TargetUserName": "user1",
                "Computer": "PC-001"
            }
        ],
        "count": 1
    }
    aggregated = aggregate_incidents(result, group_by_fields=("Image", "ImageLoaded"))
    assert aggregated["count"] == 1
    assert aggregated["detected_events"][0]["event_count"] == 1
    assert aggregated["detected_events"][0]["max_risk_score"] == 50


def test_aggregate_incidents_deduplication():
    """Multiple identical events should deduplicate into one incident."""
    result = {
        "detected_events": [
            {
                "Image": "cmd.exe",
                "ImageLoaded": "malicious.dll",
                "risk_score": 50,
                "DateTime": "2024-01-01T00:00:00",
                "Computer": "PC-001"
            },
            {
                "Image": "cmd.exe",
                "ImageLoaded": "malicious.dll",
                "risk_score": 45,
                "DateTime": "2024-01-01T00:00:01",
                "Computer": "PC-001"
            },
            {
                "Image": "cmd.exe",
                "ImageLoaded": "malicious.dll",
                "risk_score": 55,
                "DateTime": "2024-01-01T00:00:02",
                "Computer": "PC-001"
            }
        ],
        "count": 3
    }
    aggregated = aggregate_incidents(result, group_by_fields=("Image", "ImageLoaded"))
    assert aggregated["count"] == 1
    incident = aggregated["detected_events"][0]
    assert incident["event_count"] == 3
    assert incident["max_risk_score"] == 55


def test_aggregate_incidents_multiple_groups():
    """Different parent-child pairs should create separate incidents."""
    result = {
        "detected_events": [
            {
                "Image": "cmd.exe",
                "ImageLoaded": "malicious1.dll",
                "risk_score": 50,
                "DateTime": "2024-01-01T00:00:00"
            },
            {
                "Image": "powershell.exe",
                "ImageLoaded": "malicious2.dll",
                "risk_score": 60,
                "DateTime": "2024-01-01T00:00:01"
            }
        ],
        "count": 2
    }
    aggregated = aggregate_incidents(result, group_by_fields=("Image", "ImageLoaded"))
    assert aggregated["count"] == 2


def test_aggregate_incidents_risk_score_filtering():
    """Low-risk incidents should be filtered out."""
    result = {
        "detected_events": [
            {
                "Image": "cmd.exe",
                "ImageLoaded": "safe.dll",
                "risk_score": 30,
                "DateTime": "2024-01-01T00:00:00"
            },
            {
                "Image": "powershell.exe",
                "ImageLoaded": "malicious.dll",
                "risk_score": 50,
                "DateTime": "2024-01-01T00:00:01"
            }
        ],
        "count": 2
    }
    aggregated = aggregate_incidents(result, group_by_fields=("Image", "ImageLoaded"), min_risk_score=40)
    assert aggregated["count"] == 1
    assert aggregated["detected_events"][0]["max_risk_score"] == 50


def test_aggregate_incidents_preserves_sample_events():
    """Aggregated incidents should preserve sample events."""
    result = {
        "detected_events": [
            {"Image": "cmd.exe", "ImageLoaded": "bad.dll", "risk_score": 50, "DateTime": "2024-01-01T00:00:00"},
            {"Image": "cmd.exe", "ImageLoaded": "bad.dll", "risk_score": 45, "DateTime": "2024-01-01T00:00:01"},
            {"Image": "cmd.exe", "ImageLoaded": "bad.dll", "risk_score": 55, "DateTime": "2024-01-01T00:00:02"},
            {"Image": "cmd.exe", "ImageLoaded": "bad.dll", "risk_score": 48, "DateTime": "2024-01-01T00:00:03"},
        ],
        "count": 4
    }
    aggregated = aggregate_incidents(result, group_by_fields=("Image", "ImageLoaded"))
    incident = aggregated["detected_events"][0]
    assert len(incident["sample_events"]) <= 3
    assert incident["event_count"] == 4


def test_aggregate_incidents_tracks_first_last_seen():
    """Aggregated incidents should track first and last seen times."""
    result = {
        "detected_events": [
            {"Image": "cmd.exe", "ImageLoaded": "evil.dll", "risk_score": 50, "DateTime": "2024-01-01T10:00:00"},
            {"Image": "cmd.exe", "ImageLoaded": "evil.dll", "risk_score": 50, "DateTime": "2024-01-01T10:00:10"},
            {"Image": "cmd.exe", "ImageLoaded": "evil.dll", "risk_score": 50, "DateTime": "2024-01-01T10:00:20"},
        ],
        "count": 3
    }
    aggregated = aggregate_incidents(result, group_by_fields=("Image", "ImageLoaded"))
    incident = aggregated["detected_events"][0]
    assert incident["first_seen"] == "2024-01-01T10:00:00"
    assert incident["last_seen"] == "2024-01-01T10:00:20"


def test_aggregate_incidents_min_count_filtering():
    """Incidents below min_incident_count threshold should be filtered."""
    result = {
        "detected_events": [
            {"Image": "cmd.exe", "ImageLoaded": "rare.dll", "risk_score": 50, "DateTime": "2024-01-01T00:00:00"},
            {"Image": "powershell.exe", "ImageLoaded": "common.dll", "risk_score": 50, "DateTime": "2024-01-01T00:00:01"},
            {"Image": "powershell.exe", "ImageLoaded": "common.dll", "risk_score": 50, "DateTime": "2024-01-01T00:00:02"},
        ],
        "count": 3
    }
    aggregated = aggregate_incidents(result, group_by_fields=("Image", "ImageLoaded"), min_incident_count=2)
    assert aggregated["count"] == 1
    assert aggregated["detected_events"][0]["event_count"] == 2


def test_aggregate_all_detections_summary():
    """Should create summary of multiple detection results."""
    results = [
        {"count": 10, "is_aggregated": True, "total_raw_events": 100, "detected_events": [
            {"max_risk_score": 50}, {"max_risk_score": 55}, {"max_risk_score": 65}
        ]},
        {"count": 5, "is_aggregated": True, "total_raw_events": 50, "detected_events": [
            {"max_risk_score": 60}, {"max_risk_score": 70}
        ]}
    ]
    summary = aggregate_all_detections(results, ["DLL Hijacking", "Strange PPID"])
    assert summary["total_incidents"] == 15
    assert summary["total_raw_events"] == 150
    assert len(summary["detections"]) == 2


def test_aggregate_incidents_with_missing_fields():
    """Should handle events with missing grouping fields gracefully."""
    result = {
        "detected_events": [
            {"Image": "cmd.exe", "ImageLoaded": "bad.dll", "risk_score": 50, "DateTime": "2024-01-01T00:00:00"},
            {"Image": "cmd.exe", "risk_score": 50, "DateTime": "2024-01-01T00:00:01"},
        ],
        "count": 2
    }
    aggregated = aggregate_incidents(result, group_by_fields=("Image", "ImageLoaded"))
    # Should treat missing field as "unknown"
    assert aggregated["count"] == 2
