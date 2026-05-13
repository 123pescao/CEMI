from __future__ import annotations

from unittest.mock import MagicMock

from cemi.models import CollectorHealth, Confidence, EvidenceType, Finding, Severity
from cemi.rules.suspicious_processes import SuspiciousProcessesRule
from cemi.scan_engine import ScanEngine

_SCAN_ID = "scan-proc-001"


def _mock_collector(name: str, items: list[dict]) -> MagicMock:
    mock = MagicMock()
    mock.collector_name = name
    mock.run.return_value = (items, CollectorHealth(
        collector_name=name,
        ran_successfully=True,
        privilege_level="user",
        items_collected=len(items),
        duration_seconds=0.0,
        errors=[],
    ))
    return mock


class TestSuspiciousProcessesRule:
    def _rule(self) -> SuspiciousProcessesRule:
        return SuspiciousProcessesRule()

    def test_no_findings_when_no_processes(self) -> None:
        findings = self._rule().evaluate({"processes": []}, _SCAN_ID)
        assert findings == []

    def test_proc001_fires_for_user_writable_path(self) -> None:
        proc = {
            "pid": 1234,
            "name": "malware.exe",
            "exe_path": r"C:\Users\[REDACTED]\AppData\Roaming\malware.exe",
            "cpu_percent": 10.0,
        }
        findings = self._rule().evaluate({"processes": [proc]}, _SCAN_ID)

        assert len(findings) == 1
        f = findings[0]
        assert f.id == "PROC-001"
        assert f.severity == Severity.MEDIUM
        assert f.confidence == Confidence.MEDIUM
        assert f.app == "malware.exe"
        assert f.category == "Process Behavior"
        assert f.scan_id == _SCAN_ID

        evidence_labels = {ev.label for ev in f.evidence}
        assert "process_pid" in evidence_labels
        assert "process_name" in evidence_labels
        assert "exe_path" in evidence_labels
        assert "cpu_usage" in evidence_labels

    def test_proc001_no_fire_for_system_path(self) -> None:
        proc = {
            "pid": 1234,
            "name": "legit.exe",
            "exe_path": r"C:\Program Files\[REDACTED]\legit.exe",
        }
        findings = self._rule().evaluate({"processes": [proc]}, _SCAN_ID)
        assert findings == []

    def test_proc002_fires_for_mimic_name_in_user_path(self) -> None:
        proc = {
            "pid": 5678,
            "name": "svchost.exe",
            "exe_path": r"C:\Users\[REDACTED]\Downloads\svchost.exe",
        }
        findings = self._rule().evaluate({"processes": [proc]}, _SCAN_ID)

        assert len(findings) == 2  # PROC-001 and PROC-002
        ids = {f.id for f in findings}
        assert "PROC-001" in ids
        assert "PROC-002" in ids

    def test_proc002_no_fire_for_mimic_in_system_path(self) -> None:
        proc = {
            "pid": 5678,
            "name": "svchost.exe",
            "exe_path": r"C:\Windows\[REDACTED]\svchost.exe",
        }
        findings = self._rule().evaluate({"processes": [proc]}, _SCAN_ID)
        assert findings == []

    def test_proc002_low_confidence_for_non_user_path(self) -> None:
        proc = {
            "pid": 5678,
            "name": "explorer.exe",
            "exe_path": r"C:\Malware\[REDACTED]\explorer.exe",
        }
        findings = self._rule().evaluate({"processes": [proc]}, _SCAN_ID)

        assert len(findings) == 1
        assert findings[0].id == "PROC-002"
        assert findings[0].confidence == Confidence.LOW

    def test_both_rules_can_fire_for_same_process(self) -> None:
        proc = {
            "pid": 9999,
            "name": "svchost.exe",
            "exe_path": r"C:\Users\[REDACTED]\AppData\svchost.exe",
        }
        findings = self._rule().evaluate({"processes": [proc]}, _SCAN_ID)

        assert len(findings) == 2
        ids = {f.id for f in findings}
        assert "PROC-001" in ids
        assert "PROC-002" in ids

    def test_evidence_redacted(self) -> None:
        proc = {
            "pid": 1234,
            "name": "test.exe",
            "exe_path": r"C:\Users\Alice\AppData\test.exe",
            "username": "Alice",
        }
        findings = self._rule().evaluate({"processes": [proc]}, _SCAN_ID)

        for f in findings:
            for ev in f.evidence:
                if ev.type == EvidenceType.FILE_PATH:
                    assert "Alice" not in ev.value
                assert "Alice" not in ev.value  # Username not in evidence anyway

    def test_proc001_deduplicates_multiple_same_process_instances(self) -> None:
        proc_a = {
            "pid": 1111,
            "name": "Code.exe",
            "exe_path": r"C:\Users\Alice\AppData\Local\Programs\Microsoft VS Code\Code.exe",
            "cpu_percent": 1.2,
        }
        proc_b = {
            "pid": 1112,
            "name": "Code.exe",
            "exe_path": r"C:\Users\Alice\AppData\Local\Programs\Microsoft VS Code\Code.exe",
            "cpu_percent": 1.3,
        }
        findings = self._rule().evaluate({"processes": [proc_a, proc_b]}, _SCAN_ID)

        assert len(findings) == 1
        finding = findings[0]
        assert finding.id == "PROC-001"
        assert any(ev.label == "supporting_process_count" for ev in finding.evidence)
        assert any(ev.value == "2" for ev in finding.evidence if ev.label == "supporting_process_count")


class TestScanEngineIntegration:
    def test_scan_engine_includes_processes_collector_and_rule(self) -> None:
        processes = [
            {
                "pid": 1234,
                "name": "svchost.exe",
                "exe_path": r"C:\Users\[REDACTED]\AppData\svchost.exe",
            }
        ]

        processes_collector = _mock_collector("processes", processes)

        engine = ScanEngine([processes_collector])
        result = engine.run_scan()

        proc_findings = [f for f in result.findings if f.id in ("PROC-001", "PROC-002")]
        assert len(proc_findings) == 2  # Both rules fire