from __future__ import annotations

from cemi.models import Confidence, Severity
from cemi.rules.startup_rules import StartupPersistenceRule

_SCAN_ID = "scan-startup-001"


class TestStartupPersistenceRule:
    def _rule(self) -> StartupPersistenceRule:
        return StartupPersistenceRule()

    def test_no_findings_when_no_startup_items(self) -> None:
        findings = self._rule().evaluate({"startup": []}, _SCAN_ID)
        assert findings == []

    def test_fires_for_user_writable_path(self) -> None:
        item = {
            "name": "MalwareStartup",
            "source": "registry",
            "scope": "user",
            "command": r"C:\Users\[REDACTED]\AppData\Roaming\malware.exe",
            "path_redacted": r"C:\Users\[REDACTED]\AppData\Roaming\malware.exe",
        }
        findings = self._rule().evaluate({"startup": [item]}, _SCAN_ID)

        assert len(findings) == 1
        f = findings[0]
        assert f.id == "STARTUP-001"
        assert f.severity == Severity.HIGH
        assert f.confidence == Confidence.MEDIUM

    def test_no_fire_for_system_path(self) -> None:
        item = {
            "name": "LegitService",
            "source": "registry",
            "scope": "system",
            "command": r"C:\Program Files\[REDACTED]\service.exe",
            "path_redacted": r"C:\Program Files\[REDACTED]\service.exe",
        }
        findings = self._rule().evaluate({"startup": [item]}, _SCAN_ID)
        assert findings == []

    def test_fires_for_temp_path(self) -> None:
        item = {
            "name": "TempStartup",
            "source": "folder",
            "scope": "user",
            "command": r"C:\Temp\[REDACTED]\exec.exe",
            "path_redacted": r"C:\Temp\[REDACTED]\exec.exe",
        }
        findings = self._rule().evaluate({"startup": [item]}, _SCAN_ID)
        assert len(findings) == 1

    def test_requires_admin_for_system_scope(self) -> None:
        item = {
            "name": "SystemStartup",
            "source": "registry",
            "scope": "system",
            "command": r"C:\Users\[REDACTED]\Downloads\app.exe",
            "path_redacted": r"C:\Users\[REDACTED]\Downloads\app.exe",
        }
        findings = self._rule().evaluate({"startup": [item]}, _SCAN_ID)

        assert len(findings) == 1
        assert findings[0].requires_admin_to_verify is True

    def test_known_vendor_deescalates_confidence_and_sets_reasoning(self) -> None:
        item = {
            "name": "OneDrive",
            "source": "registry",
            "scope": "user",
            "command": r"C:\Users\[REDACTED]\AppData\Roaming\Microsoft\OneDrive\OneDrive.exe",
            "path_redacted": r"C:\Users\[REDACTED]\AppData\Roaming\Microsoft\OneDrive\OneDrive.exe",
        }
        findings = self._rule().evaluate({"startup": [item]}, _SCAN_ID)

        assert len(findings) == 1
        f = findings[0]
        assert f.contextual_confidence == "low"
        assert "Known vendor or common Windows-integrated software detected." in f.reasoning_notes
