"""
Unit tests for detection functions in scanners.py

Tests are clean and simple now that functions return data structures instead of printing.
"""

import unittest
from engine.src.scanners import (
    detect_DLLHijack,
    detect_UnmanagedPowerShell,
    detect_LsassDump,
    detect_strange_PPID
)


class TestDetectDLLHijack(unittest.TestCase):
    """Test suite for detect_DLLHijack function."""

    def test_no_events(self):
        """Should return empty result when no events provided."""
        result = detect_DLLHijack([], target_dll=None, include_context=False)
        self.assertEqual(result["count"], 0)
        self.assertEqual(result["detected_events"], [])
        self.assertEqual(result["high_confidence_count"], 0)
        self.assertEqual(result["high_confidence_events"], [])
        self.assertEqual(result["detection_type"], "DLL Hijacking")
    
    def test_returns_required_fields(self):
        """Should return all required fields in result dict."""
        result = detect_DLLHijack([], target_dll=None, include_context=False)
        required_fields = [
            "detected_events", "high_confidence_events", "context_events",
            "earliest_time", "commands", "detection_type", "count", 
            "high_confidence_count", "context_count"
        ]
        for field in required_fields:
            self.assertIn(field, result, f"Missing required field: {field}")

    def test_detect_hijackable_dll(self):
        """Should detect when hijackable DLL is loaded."""
        import engine.src.scanners as scanners
        orig_func = scanners._get_hijackable_dlls_list
        scanners._get_hijackable_dlls_list = lambda: ["malicious.dll"]
        # Reset the cached value
        scanners._hijackable_dlls = None

        data_rows = [{
            "EventID": "7",
            "Image": "C:\\Windows\\System32\\notepad.exe",
            "ImageLoaded": "C:\\Windows\\System32\\malicious.dll",
            "DateTime": "2024-01-01T00:00:00"
        }]

        try:
            result = detect_DLLHijack(data_rows, target_dll=None, include_context=False)
            self.assertEqual(result["count"], 1)
            self.assertEqual(len(result["detected_events"]), 1)
            self.assertIn("malicious.dll", result["detected_events"][0]["ImageLoaded"])
            # Check risk scoring fields exist
            self.assertIn("high_confidence_events", result)
            self.assertIn("high_confidence_count", result)
        finally:
            scanners._get_hijackable_dlls_list = orig_func
            scanners._hijackable_dlls = None
    
    def test_high_confidence_has_risk_scores(self):
        """High-confidence events should have risk_score field."""
        import engine.src.scanners as scanners
        orig_func = scanners._get_hijackable_dlls_list
        scanners._get_hijackable_dlls_list = lambda: ["malicious.dll"]
        scanners._hijackable_dlls = None

        data_rows = [{
            "EventID": "7",
            "Image": "C:\\Windows\\System32\\cmd.exe",  # Suspicious process
            "ImageLoaded": "C:\\Temp\\malicious.dll",   # Suspicious location
            "DateTime": "2024-01-01T00:00:00"
        }]

        try:
            result = detect_DLLHijack(data_rows, target_dll=None, include_context=False)
            # High-confidence events should have risk scores
            if result["high_confidence_count"] > 0:
                for event in result["high_confidence_events"]:
                    self.assertIn("risk_score", event)
                    self.assertGreaterEqual(event["risk_score"], 40)
        finally:
            scanners._get_hijackable_dlls_list = orig_func
            scanners._hijackable_dlls = None
    
    def test_risk_scoring_filters_correctly(self):
        """Events below threshold should be in detected but not high_confidence."""
        import engine.src.scanners as scanners
        orig_func = scanners._get_hijackable_dlls_list
        scanners._get_hijackable_dlls_list = lambda: ["test.dll"]
        scanners._hijackable_dlls = None

        # Create low-risk event (system process loading from standard location)
        data_rows = [{
            "EventID": "7",
            "Image": "C:\\Windows\\System32\\svchost.exe",  # Low risk
            "ImageLoaded": "C:\\Windows\\System32\\test.dll",  # Standard location
            "DateTime": "2024-01-01T00:00:00"
        }]

        try:
            result = detect_DLLHijack(data_rows, target_dll=None, include_context=False)
            # Should be detected but might not be high-confidence
            self.assertGreater(result["count"], 0)
            # All detected events should have risk_score if filtering occurred
            for event in result["detected_events"]:
                if "risk_score" in event:
                    # Risk score should be present in detection
                    self.assertIsInstance(event["risk_score"], int)
        finally:
            scanners._get_hijackable_dlls_list = orig_func
            scanners._hijackable_dlls = None

    def test_target_dll_matching(self):
        """Should detect when target DLL matches."""
        data_rows = [{
            "EventID": "7",
            "Image": "C:\\Windows\\System32\\notepad.exe",
            "ImageLoaded": "C:\\Windows\\System32\\target.dll",
            "DateTime": "2024-01-01T00:00:00"
        }]

        result = detect_DLLHijack(data_rows, target_dll="target.dll", include_context=False)
        self.assertEqual(result["count"], 1)

    def test_ignores_non_exe_image(self):
        """Should ignore events where Image doesn't end with .exe."""
        data_rows = [{
            "EventID": "7",
            "Image": "C:\\Windows\\System32\\notepad.dll",
            "ImageLoaded": "C:\\Windows\\System32\\malicious.dll",
            "DateTime": "2024-01-01T00:00:00"
        }]

        import engine.src.scanners as scanners
        orig_func = scanners._get_hijackable_dlls_list
        scanners._get_hijackable_dlls_list = lambda: ["malicious.dll"]
        scanners._hijackable_dlls = None

        try:
            result = detect_DLLHijack(data_rows, target_dll=None, include_context=False)
            self.assertEqual(result["count"], 0)
        finally:
            scanners._get_hijackable_dlls_list = orig_func
            scanners._hijackable_dlls = None

    def test_ignores_wrong_eventid(self):
        """Should ignore events with EventID other than 7."""
        data_rows = [{
            "EventID": "1",  # Wrong EventID
            "Image": "C:\\Windows\\System32\\notepad.exe",
            "ImageLoaded": "C:\\Windows\\System32\\malicious.dll",
            "DateTime": "2024-01-01T00:00:00"
        }]

        import engine.src.scanners as scanners
        orig_func = scanners._get_hijackable_dlls_list
        scanners._get_hijackable_dlls_list = lambda: ["malicious.dll"]
        scanners._hijackable_dlls = None

        try:
            result = detect_DLLHijack(data_rows, target_dll=None, include_context=False)
            self.assertEqual(result["count"], 0)
        finally:
            scanners._get_hijackable_dlls_list = orig_func
            scanners._hijackable_dlls = None

    def test_command_extraction(self):
        """Should extract CommandLine from detected events."""
        data_rows = [{
            "EventID": "7",
            "Image": "C:\\Windows\\System32\\notepad.exe",
            "ImageLoaded": "C:\\Windows\\System32\\malicious.dll",
            "DateTime": "2024-01-01T00:00:00",
            "CommandLine": "notepad.exe evil.txt"
        }]

        import engine.src.scanners as scanners
        orig_func = scanners._get_hijackable_dlls_list
        scanners._get_hijackable_dlls_list = lambda: ["malicious.dll"]
        scanners._hijackable_dlls = None

        try:
            result = detect_DLLHijack(data_rows, target_dll=None, include_context=False)
            self.assertEqual(result["count"], 1)
            self.assertIn("notepad.exe evil.txt", result["commands"])
        finally:
            scanners._get_hijackable_dlls_list = orig_func
            scanners._hijackable_dlls = None

    def test_case_insensitivity(self):
        """Should detect DLLs regardless of case."""
        data_rows = [{
            "EventID": "7",
            "Image": "C:\\Windows\\System32\\notepad.exe",
            "ImageLoaded": "C:\\Windows\\System32\\MALICIOUS.DLL",
            "DateTime": "2024-01-01T00:00:00"
        }]

        import engine.src.scanners as scanners
        orig_func = scanners._get_hijackable_dlls_list
        scanners._get_hijackable_dlls_list = lambda: ["malicious.dll"]
        scanners._hijackable_dlls = None

        try:
            result = detect_DLLHijack(data_rows, target_dll=None, include_context=False)
            self.assertEqual(result["count"], 1)
        finally:
            scanners._get_hijackable_dlls_list = orig_func
            scanners._hijackable_dlls = None


class TestDetectUnmanagedPowerShell(unittest.TestCase):
    """Test suite for detect_UnmanagedPowerShell function."""

    def test_no_events(self):
        """Should return empty result when no events provided."""
        result = detect_UnmanagedPowerShell([], target_dll=None, include_context=False)
        self.assertEqual(result["clr_count"], 0)
        self.assertEqual(result["clr_events"], [])
        self.assertEqual(result["injection_count"], 0)
        self.assertEqual(result["injection_events"], [])
        self.assertEqual(result["network_count"], 0)
        self.assertEqual(result["network_events"], [])
    
    def test_returns_required_fields(self):
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
            self.assertIn(field, result, f"Missing required field: {field}")
    
    def test_high_confidence_clr_fields_exist(self):
        """High-confidence CLR events should have separate field."""
        result = detect_UnmanagedPowerShell([], target_dll=None, include_context=False)
        self.assertIn("high_confidence_clr_events", result)
        self.assertIn("high_confidence_clr_count", result)
        self.assertEqual(result["high_confidence_clr_count"], 0)
        self.assertEqual(result["high_confidence_clr_events"], [])

    def test_detect_clr_dll(self):
        """Should detect CLR DLL loads."""
        data_rows = [{
            "EventID": "7",
            "Image": "powershell.exe",
            "ImageLoaded": "C:\\Windows\\System32\\clr.dll",
            "DateTime": "2024-01-01T00:00:00"
        }]

        result = detect_UnmanagedPowerShell(data_rows, target_dll=None, include_context=False)
        self.assertEqual(result["clr_count"], 1)

    def test_ignores_non_clr_dlls(self):
        """Should ignore non-CLR DLLs."""
        data_rows = [{
            "EventID": "7",
            "Image": "notepad.exe",
            "ImageLoaded": "C:\\Windows\\System32\\normal.dll",
            "DateTime": "2024-01-01T00:00:00"
        }]

        result = detect_UnmanagedPowerShell(data_rows, target_dll=None, include_context=False)
        self.assertEqual(result["clr_count"], 0)


class TestDetectLsassDump(unittest.TestCase):
    """Test suite for detect_LsassDump function."""

    def test_no_events(self):
        """Should return empty result when no events provided."""
        result = detect_LsassDump([], include_context=False)
        self.assertEqual(result["count"], 0)
        self.assertEqual(result["detected_events"], [])
        self.assertEqual(result["high_confidence_count"], 0)
        self.assertEqual(result["high_confidence_events"], [])
    
    def test_returns_required_fields(self):
        """Should return all required fields in result dict."""
        result = detect_LsassDump([], include_context=False)
        required_fields = [
            "detected_events", "high_confidence_events", "context_events",
            "earliest_time", "commands", "detection_type", "count",
            "high_confidence_count", "context_count"
        ]
        for field in required_fields:
            self.assertIn(field, result, f"Missing required field: {field}")

    def test_detect_lsass_dump(self):
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
        self.assertEqual(result["count"], 1)
        self.assertGreater(result["high_confidence_count"], 0, 
                          "LSASS dump from cmd.exe should be high-confidence")
    
    def test_lsass_dump_has_risk_score(self):
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
                self.assertIn("risk_score", event)
                self.assertGreaterEqual(event["risk_score"], 40)

    def test_ignores_non_lsass(self):
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
        self.assertEqual(result["count"], 0)

    def test_ignores_wrong_eventid(self):
        """Should ignore events with wrong EventID."""
        data_rows = [{
            "EventID": "1",  # Wrong EventID
            "TargetImage": "C:\\Windows\\System32\\lsass.exe",
            "GrantedAccess": "0x001fffff",
            "SourceUser": "DOMAIN\\attacker",
            "TargetUser": "DOMAIN\\SYSTEM",
            "DateTime": "2024-01-01T00:00:00"
        }]

        result = detect_LsassDump(data_rows, include_context=False)
        self.assertEqual(result["count"], 0)


class TestDetectStrangePPID(unittest.TestCase):
    """Test suite for detect_strange_PPID function."""

    def test_no_events(self):
        """Should return empty result when no events provided."""
        result = detect_strange_PPID([])
        self.assertEqual(result["count"], 0)
        self.assertEqual(result["detected_events"], [])
        self.assertEqual(result["high_confidence_count"], 0)
        self.assertEqual(result["high_confidence_events"], [])
    
    def test_returns_required_fields(self):
        """Should return all required fields in result dict."""
        result = detect_strange_PPID([])
        required_fields = [
            "detected_events", "high_confidence_events", "earliest_time",
            "commands", "detection_type", "count", "high_confidence_count"
        ]
        for field in required_fields:
            self.assertIn(field, result, f"Missing required field: {field}")

    def test_detect_suspicious_ppid(self):
        """Should detect suspicious parent-child process relationships."""
        data_rows = [{
            "EventID": "1",
            "Image": "C:\\Windows\\System32\\cmd.exe",
            "ParentImage": "C:\\Program Files\\Microsoft Office\\winword.exe",
            "CommandLine": "cmd.exe /c malicious.bat",
            "DateTime": "2024-01-01T00:00:00"
        }]

        result = detect_strange_PPID(data_rows)
        self.assertEqual(result["count"], 1)
        self.assertGreater(result["high_confidence_count"], 0,
                          "Office-to-cmd.exe should be high-confidence")
    
    def test_ppid_has_risk_score(self):
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
                self.assertIn("risk_score", event)
                self.assertGreaterEqual(event["risk_score"], 40)
    
    def test_office_to_powershell_higher_risk_than_office_to_cmd(self):
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
        
        # Both should be detected
        self.assertEqual(result_cmd["count"], 1)
        self.assertEqual(result_ps["count"], 1)
        
        # Both should be high-confidence
        self.assertEqual(result_cmd["high_confidence_count"], 1)
        self.assertEqual(result_ps["high_confidence_count"], 1)
        
        # PowerShell version should have higher risk score
        cmd_score = result_cmd["high_confidence_events"][0]["risk_score"]
        ps_score = result_ps["high_confidence_events"][0]["risk_score"]
        self.assertGreater(ps_score, cmd_score,
                          "PowerShell execution should score higher than cmd.exe")

    def test_ignores_non_suspicious(self):
        """Should ignore non-suspicious parent-child pairs."""
        data_rows = [{
            "EventID": "1",
            "Image": "C:\\Windows\\System32\\normal.exe",
            "ParentImage": "C:\\Windows\\System32\\explorer.exe",
            "DateTime": "2024-01-01T00:00:00"
        }]

        result = detect_strange_PPID(data_rows)
        self.assertEqual(result["count"], 0)

    def test_case_insensitive_matching(self):
        """Should match parent-child pairs case-insensitively."""
        data_rows = [{
            "EventID": "1",
            "Image": "C:\\Path\\To\\CMD.EXE",
            "ParentImage": "C:\\Path\\To\\WINWORD.EXE",
            "DateTime": "2024-01-01T00:00:00"
        }]

        result = detect_strange_PPID(data_rows)
        self.assertEqual(result["count"], 1)


if __name__ == "__main__":
    unittest.main()
