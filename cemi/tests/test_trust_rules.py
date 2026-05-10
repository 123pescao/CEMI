from __future__ import annotations

from cemi.models import Confidence, Severity
from cemi.rules.trust_rules import TrustSignatureRule

_SCAN_ID = "scan-trust-001"


class TestTrustSignatureRule:
    def _rule(self) -> TrustSignatureRule:
        return TrustSignatureRule()

    def test_no_findings_when_no_signatures(self) -> None:
        findings = self._rule().evaluate({"signatures": []}, _SCAN_ID)
        assert findings == []

    def test_fires_for_unsigned_user_writable_executable(self) -> None:
        sig = {
            "source_collector": "processes",
            "path_redacted": r"C:\Users\[REDACTED]\AppData\Local\app.exe",
            "exists": True,
            "is_executable": True,
            "sha256": "deadbeef" * 8,
            "signature_status": "unsigned",
            "publisher": None,
        }
        findings = self._rule().evaluate({"signatures": [sig]}, _SCAN_ID)

        assert len(findings) == 1
        f = findings[0]
        assert f.id == "TRUST-001"
        assert f.severity == Severity.HIGH
        assert f.confidence == Confidence.MEDIUM

    def test_no_fire_for_signed_executable(self) -> None:
        sig = {
            "source_collector": "processes",
            "path_redacted": r"C:\Users\[REDACTED]\AppData\Local\app.exe",
            "exists": True,
            "is_executable": True,
            "sha256": "deadbeef" * 8,
            "signature_status": "valid",
            "publisher": "Microsoft Corporation",
        }
        findings = self._rule().evaluate({"signatures": [sig]}, _SCAN_ID)
        assert findings == []

    def test_no_fire_for_system_path(self) -> None:
        sig = {
            "source_collector": "processes",
            "path_redacted": r"C:\Program Files\[REDACTED]\app.exe",
            "exists": True,
            "is_executable": True,
            "sha256": "deadbeef" * 8,
            "signature_status": "unknown",
            "publisher": None,
        }
        findings = self._rule().evaluate({"signatures": [sig]}, _SCAN_ID)
        assert findings == []

    def test_fires_for_unknown_status(self) -> None:
        sig = {
            "source_collector": "processes",
            "path_redacted": r"C:\Users\[REDACTED]\Downloads\tool.exe",
            "exists": True,
            "is_executable": True,
            "sha256": None,
            "signature_status": "unknown",
            "publisher": None,
        }
        findings = self._rule().evaluate({"signatures": [sig]}, _SCAN_ID)
        assert len(findings) == 1

    def test_no_fire_for_non_executable(self) -> None:
        sig = {
            "source_collector": "startup",
            "path_redacted": r"C:\Users\[REDACTED]\AppData\script.vbs",
            "exists": True,
            "is_executable": False,
            "sha256": None,
            "signature_status": "unknown",
            "publisher": None,
        }
        findings = self._rule().evaluate({"signatures": [sig]}, _SCAN_ID)
        assert findings == []
