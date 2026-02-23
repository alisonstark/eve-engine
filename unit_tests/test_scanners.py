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
        self.assertEqual(result["detection_type"], "DLL Hijacking")

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

    def test_detect_lsass_dump(self):
        """Should detect LSASS dump attempts."""
        data_rows = [{
            "EventID": "10",
            "TargetImage": "C:\\Windows\\System32\\lsass.exe",
            "GrantedAccess": "0x001fffff",
            "SourceUser": "DOMAIN\\attacker",
            "TargetUser": "DOMAIN\\SYSTEM",
            "DateTime": "2024-01-01T00:00:00"
        }]

        result = detect_LsassDump(data_rows, include_context=False)
        self.assertEqual(result["count"], 1)

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

    def test_detect_suspicious_ppid(self):
        """Should detect suspicious parent-child process relationships."""
        data_rows = [{
            "EventID": "1",
            "Image": "C:\\Windows\\System32\\cmd.exe",
            "ParentImage": "C:\\Program Files\\Microsoft Office\\winword.exe",
            "DateTime": "2024-01-01T00:00:00"
        }]

        result = detect_strange_PPID(data_rows)
        self.assertEqual(result["count"], 1)

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
