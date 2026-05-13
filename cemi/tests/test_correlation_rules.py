from __future__ import annotations

from cemi.models import Confidence, Severity
from cemi.rules.correlation_rules import CorrelationSignalsRule

_SCAN_ID = "scan-corr-001"


class TestCorrelationSignalsRule:
    def _rule(self) -> CorrelationSignalsRule:
        return CorrelationSignalsRule()

    def test_no_findings_empty_inputs(self) -> None:
        findings = self._rule().evaluate(
            {
                "startup": [],
                "network_connections": [],
                "processes": [],
                "signatures": [],
            },
            _SCAN_ID,
        )
        assert findings == []

    def test_corr002_fires_for_persistence_and_network(self) -> None:
        startup = {
            "name": "MalApp",
            "source": "registry",
            "scope": "user",
            "command": r"C:\Users\[REDACTED]\AppData\malware.exe",
            "path_redacted": r"c:\users\[redacted]\appdata\malware.exe",  # normalized
        }
        conn = {
            "pid": 1234,
            "process_name": "malware.exe",
            "local_address": "127.0.0.1",
            "local_port": 54321,
            "remote_address": "192.0.2.1",
            "remote_port": 80,
            "status": "ESTABLISHED",
            "exe_path_redacted": r"c:\users\[redacted]\appdata\malware.exe",  # normalized
        }
        findings = self._rule().evaluate(
            {
                "startup": [startup],
                "network_connections": [conn],
                "processes": [],
                "signatures": [],
            },
            _SCAN_ID,
        )

        corr002 = [f for f in findings if f.id == "CORR-002"]
        assert len(corr002) == 1
        assert corr002[0].severity == Severity.HIGH  # user-writable is still suspicious but not critical

    def test_corr003_fires_for_untrusted_process_with_network(self) -> None:
        proc = {
            "pid": 5678,
            "name": "suspicious.exe",
            "exe_path": r"C:\Users\[REDACTED]\Downloads\suspicious.exe",
            "cpu_percent": 25.0,
        }
        sig = {
            "source_collector": "processes",
            "path_redacted": r"c:\users\[redacted]\downloads\suspicious.exe",  # normalized
            "exists": True,
            "is_executable": True,
            "sha256": "cafebabe" * 8,
            "signature_status": "unknown",
            "publisher": None,
        }
        conn = {
            "pid": 5678,
            "process_name": "suspicious.exe",
            "local_address": "192.168.1.1",
            "local_port": 49152,
            "remote_address": "10.0.0.1",
            "remote_port": 443,
            "status": "ESTABLISHED",
            "exe_path_redacted": r"c:\users\[redacted]\downloads\suspicious.exe",  # normalized
        }
        findings = self._rule().evaluate(
            {
                "startup": [],
                "network_connections": [conn],
                "processes": [proc],
                "signatures": [sig],
            },
            _SCAN_ID,
        )

        corr003 = [f for f in findings if f.id == "CORR-003"]
        assert len(corr003) == 1
        assert corr003[0].severity == Severity.CRITICAL  # user-writable

    def test_no_corr002_without_matching_paths(self) -> None:
        startup = {
            "name": "App1",
            "source": "registry",
            "scope": "user",
            "command": r"C:\Program Files\app1.exe",
            "path_redacted": r"C:\Program Files\app1.exe",
        }
        conn = {
            "pid": 1234,
            "process_name": "app2.exe",
            "local_address": "127.0.0.1",
            "local_port": 54321,
            "remote_address": "192.0.2.1",
            "remote_port": 80,
            "status": "ESTABLISHED",
            "exe_path_redacted": r"C:\Program Files\app2.exe",
        }
        findings = self._rule().evaluate(
            {
                "startup": [startup],
                "network_connections": [conn],
                "processes": [],
                "signatures": [],
            },
            _SCAN_ID,
        )

        corr002 = [f for f in findings if f.id == "CORR-002"]
        assert len(corr002) == 0

    def test_corr002_deduplicates_same_startup_process(self) -> None:
        startup = {
            "name": "Chrome",
            "source": "registry",
            "scope": "user",
            "command": r"C:\Program Files\Google\Chrome\chrome.exe",
            "path_redacted": r"c:\program files\google\chrome\chrome.exe",
        }
        conn_a = {
            "pid": 1111,
            "process_name": "chrome.exe",
            "local_address": "127.0.0.1",
            "local_port": 54321,
            "remote_address": "198.51.100.1",
            "remote_port": 443,
            "status": "ESTABLISHED",
            "exe_path_redacted": r"c:\program files\google\chrome\chrome.exe",
        }
        conn_b = {
            "pid": 1112,
            "process_name": "chrome.exe",
            "local_address": "127.0.0.1",
            "local_port": 54322,
            "remote_address": "203.0.113.2",
            "remote_port": 80,
            "status": "ESTABLISHED",
            "exe_path_redacted": r"c:\program files\google\chrome\chrome.exe",
        }
        findings = self._rule().evaluate(
            {
                "startup": [startup],
                "network_connections": [conn_a, conn_b],
                "processes": [],
                "signatures": [],
            },
            _SCAN_ID,
        )

        corr002 = [f for f in findings if f.id == "CORR-002"]
        assert len(corr002) == 1
        assert corr002[0].severity == Severity.MEDIUM

    def test_evidence_includes_all_signals(self) -> None:
        startup = {
            "name": "PersistApp",
            "source": "registry",
            "scope": "user",
            "command": r"C:\Users\[REDACTED]\AppData\persist.exe",
            "path_redacted": r"c:\users\[redacted]\appdata\persist.exe",
        }
        conn = {
            "pid": 9999,
            "process_name": "persist.exe",
            "local_address": "127.0.0.1",
            "local_port": 54321,
            "remote_address": "1.2.3.4",
            "remote_port": 8080,
            "status": "ESTABLISHED",
            "exe_path_redacted": r"c:\users\[redacted]\appdata\persist.exe",
        }
        findings = self._rule().evaluate(
            {
                "startup": [startup],
                "network_connections": [conn],
                "processes": [],
                "signatures": [],
            },
            _SCAN_ID,
        )

        corr002 = [f for f in findings if f.id == "CORR-002"][0]
        labels = {ev.label for ev in corr002.evidence}
        assert "startup_entry_name" in labels
        assert "startup_path" in labels
        assert "network_process_name" in labels
        assert "network_target" in labels
