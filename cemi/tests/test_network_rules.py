from __future__ import annotations

from cemi.models import CollectorHealth, Confidence, Severity
from cemi.rules.network_rules import NetworkConnectionsRule

_SCAN_ID = "scan-net-001"


class TestNetworkConnectionsRule:
    def _rule(self) -> NetworkConnectionsRule:
        return NetworkConnectionsRule()

    def test_no_findings_when_no_connections(self) -> None:
        findings = self._rule().evaluate({"network_connections": []}, _SCAN_ID)
        assert findings == []

    def test_net001_fires_for_external_connection(self) -> None:
        conn = {
            "pid": 1234,
            "process_name": "chrome.exe",
            "local_port": 54321,
            "remote_address": "8.8.8.8",
            "remote_port": 443,
            "status": "ESTABLISHED",
            "exe_path_redacted": r"C:\Program Files\Google\Chrome\chrome.exe",
        }
        findings = self._rule().evaluate({"network_connections": [conn]}, _SCAN_ID)

        assert len(findings) >= 1
        net001 = [f for f in findings if f.id == "NET-001"][0]
        assert net001.severity == Severity.LOW
        assert net001.confidence == Confidence.HIGH

    def test_net002_fires_for_user_writable_path_with_connection(self) -> None:
        conn = {
            "pid": 5678,
            "process_name": "malware.exe",
            "local_port": 49152,
            "remote_address": "10.0.0.1",
            "remote_port": 80,
            "status": "ESTABLISHED",
            "exe_path_redacted": r"C:\Users\[REDACTED]\AppData\malware.exe",
        }
        findings = self._rule().evaluate({"network_connections": [conn]}, _SCAN_ID)

        assert len(findings) >= 2
        ids = {f.id for f in findings}
        assert "NET-001" in ids
        assert "NET-002" in ids

        net002 = [f for f in findings if f.id == "NET-002"][0]
        assert net002.severity == Severity.HIGH

    def test_no_findings_for_listen_connection(self) -> None:
        conn = {
            "pid": 1234,
            "process_name": "explorer.exe",
            "local_port": 49152,
            "remote_address": None,
            "remote_port": None,
            "status": "LISTEN",
            "exe_path_redacted": r"C:\Windows\explorer.exe",
        }
        findings = self._rule().evaluate({"network_connections": [conn]}, _SCAN_ID)
        assert findings == []

    def test_evidence_includes_remote_target(self) -> None:
        conn = {
            "pid": 1234,
            "process_name": "test.exe",
            "local_port": 54321,
            "remote_address": "93.184.216.34",
            "remote_port": 443,
            "status": "ESTABLISHED",
            "exe_path_redacted": r"C:\Program Files\test\test.exe",
        }
        findings = self._rule().evaluate({"network_connections": [conn]}, _SCAN_ID)

        net001 = [f for f in findings if f.id == "NET-001"][0]
        evidence_values = {ev.value for ev in net001.evidence}
        assert "remote port 443" in evidence_values
        assert all("93.184.216.34" not in val for val in evidence_values)

    def test_net001_deduplicates_same_process_connections(self) -> None:
        conn_a = {
            "pid": 1234,
            "process_name": "chrome.exe",
            "local_port": 54321,
            "remote_address": "8.8.8.8",
            "remote_port": 443,
            "status": "ESTABLISHED",
            "exe_path_redacted": r"C:\Program Files\Google\Chrome\chrome.exe",
        }
        conn_b = {
            "pid": 1235,
            "process_name": "chrome.exe",
            "local_port": 54322,
            "remote_address": "1.1.1.1",
            "remote_port": 80,
            "status": "ESTABLISHED",
            "exe_path_redacted": r"C:\Program Files\Google\Chrome\chrome.exe",
        }
        findings = self._rule().evaluate({"network_connections": [conn_a, conn_b]}, _SCAN_ID)

        net001 = [f for f in findings if f.id == "NET-001"]
        assert len(net001) == 1

    def test_net001_evidence_does_not_include_ips(self) -> None:
        conn = {
            "pid": 2222,
            "process_name": "chrome.exe",
            "local_port": 54321,
            "remote_address": "203.0.113.10",
            "remote_port": 443,
            "status": "ESTABLISHED",
            "exe_path_redacted": r"C:\Program Files\Google\Chrome\chrome.exe",
        }
        findings = self._rule().evaluate({"network_connections": [conn]}, _SCAN_ID)

        net001 = [f for f in findings if f.id == "NET-001"][0]
        evidence_values = {ev.value for ev in net001.evidence}
        assert all("203.0.113.10" not in val for val in evidence_values)
        assert all("127.0.0.1" not in val for val in evidence_values)
