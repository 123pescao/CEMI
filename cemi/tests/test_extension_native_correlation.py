from __future__ import annotations

from typing import Any
from unittest.mock import MagicMock

from cemi.models import CollectorHealth, Confidence, EvidenceType, Finding, Severity
from cemi.rules.extension_native_correlation import CorrelatedExtensionNativeHostRule
from cemi.scan_engine import ScanEngine

_SCAN_ID = "scan-corr-001"


def _ext(**kwargs: Any) -> dict[str, Any]:
    base: dict[str, Any] = {
        "browser": "Chrome",
        "extension_id": "aabbccddeeffgghhiijjkkllmmnnoopp",
        "name": "TrustedExtension",
        "version": "1.2.3",
        "manifest_path": r"C:\\Users\\alice\\AppData\\Local\\Google\\Chrome\\User Data\\Default\\Extensions\\aabbcc\\1.2.3\\manifest.json",
        "permissions": ["storage"],
        "host_permissions": [],
    }
    base.update(kwargs)
    return base


def _host(**kwargs: Any) -> dict[str, Any]:
    base: dict[str, Any] = {
        "browser": "Chrome",
        "scope": "user",
        "name": "com.example.host",
        "description": "Example native messaging host",
        "manifest_path": r"C:\\Program Files\\Google\\Chrome\\Application\\NativeMessagingHosts\\com.example.host.json",
        "binary_path": r"C:\\Program Files\\Example\\host.exe",
        "type": "stdio",
        "allowed_origins": ["chrome-extension://aabbccddeeffgghhiijjkkllmmnnoopp/"],
    }
    base.update(kwargs)
    return base


def _collector(name: str, items: list[dict[str, Any]]) -> MagicMock:
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


class TestCorrelatedExtensionNativeHostRule:
    def _rule(self) -> CorrelatedExtensionNativeHostRule:
        return CorrelatedExtensionNativeHostRule()

    def test_no_findings_when_missing_extension_data(self) -> None:
        findings = self._rule().evaluate(
            {"browser_extensions": [], "native_messaging_hosts": [_host()]},
            _SCAN_ID,
        )
        assert findings == []

    def test_no_findings_when_missing_native_hosts(self) -> None:
        findings = self._rule().evaluate(
            {"browser_extensions": [_ext()], "native_messaging_hosts": []},
            _SCAN_ID,
        )
        assert findings == []

    def test_no_findings_for_non_matching_allowed_origins(self) -> None:
        ext = _ext()
        host = _host(allowed_origins=["chrome-extension://otherid/"])
        findings = self._rule().evaluate(
            {"browser_extensions": [ext], "native_messaging_hosts": [host]},
            _SCAN_ID,
        )
        assert findings == []

    def test_fires_when_extension_id_matches_native_host_allowed_origin(self) -> None:
        findings = self._rule().evaluate(
            {"browser_extensions": [_ext()], "native_messaging_hosts": [_host()]},
            _SCAN_ID,
        )

        assert len(findings) == 1
        finding = findings[0]
        assert finding.id == "CORR-001"
        assert finding.severity == Severity.HIGH
        assert finding.confidence == Confidence.HIGH
        assert finding.app == "TrustedExtension"
        assert finding.category == "Browser Integration"
        assert finding.scan_id == _SCAN_ID
        assert finding.requires_admin_to_verify is False

        raw_origin = "chrome-extension://aabbccddeeffgghhiijjkkllmmnnoopp/"
        combined_evidence = " ".join(item.value for item in finding.evidence)
        assert raw_origin not in combined_evidence
        assert any(item.label == "extension_manifest_path" for item in finding.evidence)
        assert any(item.label == "native_manifest_path" for item in finding.evidence)

    def test_critical_severity_when_extension_has_all_urls_and_sensitive_permission(self) -> None:
        ext = _ext(
            host_permissions=["<all_urls>"],
            permissions=["storage", "cookies"],
        )
        findings = self._rule().evaluate(
            {"browser_extensions": [ext], "native_messaging_hosts": [_host()]},
            _SCAN_ID,
        )

        assert len(findings) == 1
        assert findings[0].severity == Severity.CRITICAL

    def test_requires_admin_to_verify_for_system_scope_hosts(self) -> None:
        findings = self._rule().evaluate(
            {"browser_extensions": [_ext()], "native_messaging_hosts": [_host(scope="system")]},
            _SCAN_ID,
        )
        assert findings[0].requires_admin_to_verify is True


class TestScanEngineIntegration:
    def test_scan_engine_includes_corr_rule(self) -> None:
        browser_extensions = [_ext()]
        native_hosts = [_host()]

        browser_collector = _collector("browser_extensions", browser_extensions)
        native_collector = _collector("native_messaging_hosts", native_hosts)

        engine = ScanEngine([browser_collector, native_collector])
        result = engine.run_scan()

        assert any(f.id == "CORR-001" for f in result.findings)
        assert result.findings
