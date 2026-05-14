"""Tests for cemi.reports.generator."""
from __future__ import annotations

import json
import tempfile
from contextlib import contextmanager
from datetime import datetime, timezone
from pathlib import Path
from typing import Any
from unittest.mock import MagicMock, patch
from uuid import uuid4

import pytest
from typer.testing import CliRunner

from cemi.main import app
from cemi.correlation_engine import CorrelatedSignal
from cemi.models import (
    CollectorHealth,
    Confidence,
    EvidenceItem,
    EvidenceType,
    Finding,
    RiskSummary,
    ScanResult,
    Severity,
)
from cemi.reports.generator import generate_html_report, save_html_report, save_json_report
from cemi.risk import calculate_risk_summary

_FAKE_REPORT_PATH = Path("reports/cemi_report_fake.html")
_FAKE_JSON_PATH = Path("reports/cemi_report_fake.json")

runner = CliRunner()


# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------


def _make_health(
    name: str = "installed_apps",
    items: int = 0,
    ran_ok: bool = True,
    skipped: str | None = None,
) -> CollectorHealth:
    return CollectorHealth(
        collector_name=name,
        ran_successfully=ran_ok,
        privilege_level="user",
        items_collected=items,
        duration_seconds=0.01,
        skipped_reason=skipped,
    )


def _make_finding(
    title: str = "Test Finding",
    severity: Severity = Severity.MEDIUM,
    app: str | None = "TestApp",
    evidence_count: int = 1,
    reasoning_notes: list[str] | None = None,
) -> Finding:
    evidence = [
        EvidenceItem(
            type=EvidenceType.FILE_PATH,
            value=r"C:\Users\[REDACTED]\AppData\evil.exe",
            label="binary path",
        )
        for _ in range(evidence_count)
    ]
    return Finding(
        id="TST-001",
        instance_id=uuid4(),
        rule_version="1.0.0",
        title=title,
        severity=severity,
        confidence=Confidence.MEDIUM,
        contextual_confidence="medium",
        reasoning_notes=reasoning_notes or [],
        app=app,
        category="Test",
        official_explanation="Official explanation of the test finding.",
        in_other_words="Plain English: this is a test finding.",
        why_this_matters="Why this test finding matters.",
        evidence=evidence,
        recommended_action="Recommended action for the test finding.",
        safe_to_ignore_when="Safe to ignore when it is a test.",
        false_positive_risk="low",
        requires_admin_to_verify=False,
        created_at=datetime.now(tz=timezone.utc),
        scan_id="scan-test-001",
    )


def _make_result(
    scan_id: str = "scan-test-001",
    findings: list[Finding] | None = None,
    collector_health: list[CollectorHealth] | None = None,
) -> ScanResult:
    now = datetime.now(tz=timezone.utc)
    resolved_findings = findings or []
    return ScanResult(
        scan_id=scan_id,
        scan_version="0.1.0",
        started_at=now,
        completed_at=now,
        hostname_redacted="a" * 64,
        privilege_level="user",
        collector_health=collector_health or [_make_health("installed_apps", items=5)],
        findings=resolved_findings,
        total_apps_scanned=5,
        risk_summary=calculate_risk_summary(resolved_findings),
    )


def test_generate_html_renders_enum_severity_values() -> None:
    finding = _make_finding(severity=Severity.LOW, reasoning_notes=["Testing severity rendering."])
    correlated = [
        CorrelatedSignal(
            id="CORR-999",
            instance_id=uuid4(),
            rule_version="1.0.0",
            title="Test Correlated Signal",
            severity=Severity.HIGH,
            confidence=Confidence.MEDIUM,
            contextual_confidence="medium",
            reasoning_notes=["Test."],
            app=None,
            category="Correlation",
            official_explanation="Official.",
            in_other_words="In other words.",
            why_this_matters="Why this matters.",
            evidence=[EvidenceItem(type=EvidenceType.METADATA, value="test", label="test")],
            recommended_action="Action.",
            safe_to_ignore_when="Safe.",
            false_positive_risk="low",
            requires_admin_to_verify=False,
            created_at=datetime.now(timezone.utc),
            scan_id="scan-report-001",
            correlation_id="CORR-999",
            status="Needs Review",
            contributing_findings=["TST-001: Test Finding"],
            evidence_count=1,
            risk_multiplier=1.0,
        )
    ]
    result = ScanResult(
        scan_id="scan-report-001",
        scan_version="0.1.0",
        started_at=datetime.now(timezone.utc),
        completed_at=datetime.now(timezone.utc),
        hostname_redacted="a" * 64,
        privilege_level="user",
        collector_health=[_make_health("installed_apps", items=1)],
        findings=[finding],
        total_apps_scanned=1,
        risk_summary=calculate_risk_summary([finding]),
        correlated_signals=correlated,
    )
    html = generate_html_report(result)
    assert "Severity.HIGH" not in html
    assert "Severity.LOW" not in html
    assert "Severity.MEDIUM" not in html
    assert "Severity.CRITICAL" not in html
    assert "HIGH" in html
    assert "LOW" in html


def test_generate_html_does_not_use_alarmist_wording() -> None:
    finding = _make_finding(
        title="Network connection",
        severity=Severity.LOW,
        app="chrome.exe",
        evidence_count=1,
    )
    result = _make_result(findings=[finding])
    html = generate_html_report(result)
    assert "hallmark of malware" not in html
    assert "strong indicator of compromise" not in html
    assert "remove the startup entry and stop the process" not in html
    assert "stop it if unknown" not in html
    assert "malware detected" not in html
    assert "spyware detected" not in html
    assert "trojan detected" not in html
    assert "intrusion detected" not in html
    assert "remove immediately" not in html
    assert "delete immediately" not in html


@contextmanager
def _patch_all_collectors():
    """Patch all four collectors and report-save functions for isolated CLI tests."""
    apps_h = _make_health("installed_apps")
    svcs_h = _make_health("services")
    nmh_h = _make_health("native_messaging_hosts")
    bext_h = _make_health("browser_extensions")

    def _mock(h: CollectorHealth) -> MagicMock:
        inst = MagicMock()
        inst.run.return_value = ([], h)
        return inst

    with (
        patch("cemi.main.InstalledAppsCollector", return_value=_mock(apps_h)),
        patch("cemi.main.ServicesCollector", return_value=_mock(svcs_h)),
        patch("cemi.main.NativeMessagingHostsCollector", return_value=_mock(nmh_h)),
        patch("cemi.main.BrowserExtensionsCollector", return_value=_mock(bext_h)),
        patch("cemi.main.save_html_report", return_value=_FAKE_REPORT_PATH),
        patch("cemi.main.save_json_report", return_value=_FAKE_JSON_PATH),
    ):
        yield


# ---------------------------------------------------------------------------
# generate_html_report — return type and basic structure
# ---------------------------------------------------------------------------


class TestGenerateHtmlReportStructure:
    def test_returns_string(self) -> None:
        result = _make_result()
        html = generate_html_report(result)
        assert isinstance(html, str)

    def test_returns_nonempty_string(self) -> None:
        result = _make_result()
        html = generate_html_report(result)
        assert len(html) > 100

    def test_is_valid_html_doctype(self) -> None:
        html = generate_html_report(_make_result())
        assert html.strip().lower().startswith("<!doctype html>")

    def test_contains_cemi_title(self) -> None:
        html = generate_html_report(_make_result())
        assert "CEMÍ" in html

    def test_contains_privacy_notice(self) -> None:
        html = generate_html_report(_make_result())
        assert "generated locally" in html
        assert "Review before sharing" in html

    def test_contains_dashboard_header(self) -> None:
        html = generate_html_report(_make_result())
        assert "CEMÍ Security Dashboard" in html
        assert "Local Only" in html

    def test_contains_executive_summary(self) -> None:
        html = generate_html_report(_make_result())
        assert "Executive Summary" in html
        assert "Overall risk" in html

    def test_contains_risk_cards(self) -> None:
        html = generate_html_report(_make_result())
        assert "Risk Score" in html
        assert "Findings Count" in html
        assert "Collectors Healthy" in html

    def test_contains_monitoring_mode_available_section(self) -> None:
        html = generate_html_report(_make_result())
        assert "Monitoring & Timeline" in html
        assert "cemi monitor --yes --interval 60 --iterations 5" in html
        assert "cemi history" in html

    def test_contains_correlated_threat_signals_section(self) -> None:
        html = generate_html_report(_make_result())
        assert "Correlated Threat Signals" in html

    def test_report_displays_correlation_reasoning_when_present(self) -> None:
        finding = _make_finding(
            title="Test Medium Finding",
            severity=Severity.MEDIUM,
            app="TestApp",
        )
        correlated = CorrelatedSignal(
            id="CORR-101",
            instance_id=uuid4(),
            rule_version="1.0.0",
            correlation_id="CORR-101",
            title="Browser Extension Can Reach Native System Access",
            severity=Severity.HIGH,
            confidence=Confidence.HIGH,
            contextual_confidence="high",
            status="High Priority",
            category="Correlation",
            official_explanation="Official explanation.",
            in_other_words="In other words.",
            why_this_matters="Why this matters.",
            evidence=[EvidenceItem(type=EvidenceType.METADATA, value="1", label="count")],
            recommended_action="Recommended action.",
            safe_to_ignore_when="Safe to ignore.",
            false_positive_risk="medium",
            reasoning_notes=["Correlation reasoning."],
            contributing_findings=["EXT-003: Extension Can Inject Scripts and Intercept Traffic"],
            evidence_count=1,
            risk_multiplier=1.4,
            requires_admin_to_verify=False,
            created_at=datetime.now(timezone.utc),
            scan_id="scan-test",
        )
        result = _make_result(findings=[finding])
        result = result.model_copy(update={"correlated_signals": [correlated]})
        html = generate_html_report(result)
        assert "Why CEMÍ correlated this" in html


# ---------------------------------------------------------------------------
# generate_html_report — scan metadata
# ---------------------------------------------------------------------------


class TestGenerateHtmlReportMetadata:
    def test_report_includes_scan_id(self) -> None:
        result = _make_result(scan_id="scan-abc-12345")
        html = generate_html_report(result)
        assert "scan-abc-12345" in html

    def test_report_includes_scan_version(self) -> None:
        html = generate_html_report(_make_result())
        assert "0.1.0" in html

    def test_report_includes_privilege_level(self) -> None:
        html = generate_html_report(_make_result())
        assert "user" in html

    def test_report_includes_total_apps_scanned(self) -> None:
        html = generate_html_report(_make_result())
        assert "5" in html


# ---------------------------------------------------------------------------
# generate_html_report — collector health
# ---------------------------------------------------------------------------


class TestGenerateHtmlReportCollectorHealth:
    def test_report_includes_collector_name(self) -> None:
        result = _make_result(collector_health=[_make_health("installed_apps")])
        html = generate_html_report(result)
        assert "installed_apps" in html

    def test_report_includes_multiple_collector_names(self) -> None:
        healths = [
            _make_health("installed_apps"),
            _make_health("services"),
            _make_health("native_messaging_hosts"),
        ]
        html = generate_html_report(_make_result(collector_health=healths))
        assert "installed_apps" in html
        assert "services" in html
        assert "native_messaging_hosts" in html

    def test_report_shows_ok_status(self) -> None:
        result = _make_result(collector_health=[_make_health("apps", ran_ok=True)])
        html = generate_html_report(result)
        assert "OK" in html

    def test_report_shows_failed_status(self) -> None:
        result = _make_result(collector_health=[_make_health("apps", ran_ok=False)])
        html = generate_html_report(result)
        assert "FAILED" in html

    def test_report_shows_skipped_reason(self) -> None:
        result = _make_result(
            collector_health=[_make_health("apps", skipped="non-Windows platform")]
        )
        html = generate_html_report(result)
        assert "SKIPPED" in html
        assert "non-Windows platform" in html


# ---------------------------------------------------------------------------
# generate_html_report — findings present
# ---------------------------------------------------------------------------


class TestGenerateHtmlReportFindings:
    def test_report_includes_finding_title(self) -> None:
        result = _make_result(findings=[_make_finding("Suspicious Service Binary")])
        html = generate_html_report(result)
        assert "Suspicious Service Binary" in html

    def test_report_includes_findings_section(self) -> None:
        result = _make_result(findings=[_make_finding()])
        html = generate_html_report(result)
        assert "Findings" in html

    def test_report_includes_official_explanation(self) -> None:
        result = _make_result(findings=[_make_finding()])
        html = generate_html_report(result)
        assert "Official explanation of the test finding." in html

    def test_report_includes_in_other_words(self) -> None:
        result = _make_result(findings=[_make_finding()])
        html = generate_html_report(result)
        assert "Plain English" in html

    def test_report_includes_why_this_matters(self) -> None:
        result = _make_result(findings=[_make_finding()])
        html = generate_html_report(result)
        assert "Why this test finding matters" in html

    def test_report_includes_recommended_action(self) -> None:
        result = _make_result(findings=[_make_finding()])
        html = generate_html_report(result)
        assert "Recommended action for the test finding" in html

    def test_finding_card_shows_status(self) -> None:
        result = _make_result(findings=[_make_finding()])
        html = generate_html_report(result)
        assert "Status:" in html
        assert "Needs Review" in html

    def test_finding_card_shows_contextual_confidence(self) -> None:
        result = _make_result(findings=[_make_finding()])
        html = generate_html_report(result)
        assert "Contextual Confidence:" in html
        assert "medium" in html

    def test_finding_card_shows_reasoning_notes(self) -> None:
        finding = _make_finding(reasoning_notes=["Matched local startup evidence."])
        result = _make_result(findings=[finding])
        html = generate_html_report(result)
        assert "Reasoning notes:" in html
        assert "Matched local startup evidence." in html

    def test_finding_card_does_not_include_raw_evidence_values(self) -> None:
        finding = _make_finding(evidence_count=2)
        result = _make_result(findings=[finding])
        html = generate_html_report(result)
        assert r"C:\\Users\\" not in html
        assert "binary path" not in html
        assert "Evidence count:" in html

    def test_report_includes_severity(self) -> None:
        result = _make_result(findings=[_make_finding(severity=Severity.HIGH)])
        html = generate_html_report(result)
        assert "HIGH" in html

    def test_report_includes_app_name(self) -> None:
        result = _make_result(findings=[_make_finding(app="MyTestApp")])
        html = generate_html_report(result)
        assert "MyTestApp" in html

    def test_report_shows_no_findings_message_when_empty(self) -> None:
        html = generate_html_report(_make_result(findings=[]))
        assert "No findings detected" in html

    def test_report_shows_finding_count(self) -> None:
        result = _make_result(findings=[_make_finding(), _make_finding(title="Second")])
        html = generate_html_report(result)
        assert "2" in html

    def test_report_includes_evidence_count(self) -> None:
        result = _make_result(findings=[_make_finding(evidence_count=3)])
        html = generate_html_report(result)
        assert "3" in html
        assert "supporting item" in html


# ---------------------------------------------------------------------------
# generate_html_report — privacy / evidence isolation
# ---------------------------------------------------------------------------


class TestGenerateHtmlReportPrivacy:
    def test_report_does_not_include_evidence_path_values(self) -> None:
        finding = _make_finding()
        # Evidence value contains this redacted path — must NOT appear in HTML.
        raw_evidence_value = r"C:\Users\[REDACTED]\AppData\evil.exe"
        result = _make_result(findings=[finding])
        html = generate_html_report(result)
        assert raw_evidence_value not in html

    def test_report_does_not_include_evidence_label_values(self) -> None:
        finding = _make_finding()
        result = _make_result(findings=[finding])
        html = generate_html_report(result)
        # The label "binary path" is on the EvidenceItem but the template
        # never iterates evidence items, so it should not appear.
        assert "binary path" not in html

    def test_report_contains_privacy_promise(self) -> None:
        result = _make_result()
        html = generate_html_report(result)
        assert "Privacy Promise" in html
        assert "No telemetry is collected" in html

    def test_report_has_no_external_assets_or_cdn(self) -> None:
        result = _make_result()
        html = generate_html_report(result).lower()
        assert "https://" not in html
        assert "http://" not in html
        assert "cdn" not in html

    def test_no_javascript_in_report(self) -> None:
        result = _make_result(findings=[_make_finding()])
        html = generate_html_report(result).lower()
        assert "<script" not in html
        assert "javascript:" not in html
        assert "onerror=" not in html
        assert "onclick=" not in html


# ---------------------------------------------------------------------------
# generate_html_report — XSS / autoescape
# ---------------------------------------------------------------------------


class TestGenerateHtmlReportEscape:
    def test_malicious_finding_title_is_escaped(self) -> None:
        result = _make_result(
            findings=[_make_finding(title='<script>alert("xss")</script>')]
        )
        html = generate_html_report(result)
        assert "<script>" not in html
        assert "&lt;script&gt;" in html

    def test_malicious_app_name_is_escaped(self) -> None:
        result = _make_result(findings=[_make_finding(app='"><img src=x onerror=alert(1)>')])
        html = generate_html_report(result)
        # The injected <img tag must be escaped to &lt;img — not a live element.
        assert "<img" not in html
        assert "&lt;img" in html

    def test_html_entities_in_explanation_are_escaped(self) -> None:
        finding = Finding(
            id="TST-001",
            instance_id=uuid4(),
            rule_version="1.0.0",
            title="Safe Title",
            severity=Severity.LOW,
            confidence=Confidence.LOW,
            app=None,
            category="Test",
            official_explanation='Contains <b>bold</b> & "quotes"',
            in_other_words="Plain text.",
            why_this_matters="Matters.",
            evidence=[],
            recommended_action="Act.",
            safe_to_ignore_when=None,
            false_positive_risk="low",
            requires_admin_to_verify=False,
            created_at=datetime.now(tz=timezone.utc),
            scan_id="s1",
        )
        html = generate_html_report(_make_result(findings=[finding]))
        assert "<b>bold</b>" not in html
        assert "&lt;b&gt;bold&lt;/b&gt;" in html


# ---------------------------------------------------------------------------
# save_html_report — file writing
# ---------------------------------------------------------------------------


class TestSaveHtmlReport:
    def test_creates_output_directory(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            output_dir = Path(tmp) / "reports"
            assert not output_dir.exists()
            save_html_report("<html></html>", "scan-1", output_dir)
            assert output_dir.exists()

    def test_creates_nested_output_directory(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            output_dir = Path(tmp) / "a" / "b" / "reports"
            save_html_report("<html></html>", "scan-1", output_dir)
            assert output_dir.exists()

    def test_writes_html_file(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            path = save_html_report("<html>hello</html>", "scan-abc", Path(tmp))
            assert path.exists()

    def test_file_name_contains_scan_id(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            path = save_html_report("<html></html>", "scan-xyz-001", Path(tmp))
            assert "scan-xyz-001" in path.name

    def test_file_name_format(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            path = save_html_report("<html></html>", "abc123", Path(tmp))
            assert path.name == "cemi_report_abc123.html"

    def test_file_contains_written_content(self) -> None:
        content = "<html><body>test content áéí</body></html>"
        with tempfile.TemporaryDirectory() as tmp:
            path = save_html_report(content, "scan-c", Path(tmp))
            assert path.read_text(encoding="utf-8") == content

    def test_returns_path_object(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            result = save_html_report("<html></html>", "scan-1", Path(tmp))
            assert isinstance(result, Path)

    def test_does_not_overwrite_existing_file(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            out = Path(tmp)
            p1 = save_html_report("<html>first</html>", "s1", out)
            p2 = save_html_report("<html>second</html>", "s1", out)
            assert p1 != p2
            assert p1.read_text(encoding="utf-8") == "<html>first</html>"
            assert p2.read_text(encoding="utf-8") == "<html>second</html>"

    def test_collision_suffix_is_underscore_one(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            out = Path(tmp)
            p1 = save_html_report("<html>1</html>", "s1", out)
            p2 = save_html_report("<html>2</html>", "s1", out)
            assert p1.name == "cemi_report_s1.html"
            assert p2.name == "cemi_report_s1_1.html"

    def test_second_collision_increments_counter(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            out = Path(tmp)
            save_html_report("<html>1</html>", "s1", out)
            save_html_report("<html>2</html>", "s1", out)
            p3 = save_html_report("<html>3</html>", "s1", out)
            assert p3.name == "cemi_report_s1_2.html"

    def test_utf8_encoding_preserved(self) -> None:
        content = "<html><p>CEMÍ — naïve café résumé</p></html>"
        with tempfile.TemporaryDirectory() as tmp:
            path = save_html_report(content, "utf8-scan", Path(tmp))
            assert path.read_text(encoding="utf-8") == content

    def test_different_scan_ids_do_not_collide(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            out = Path(tmp)
            p1 = save_html_report("<html>a</html>", "scan-1", out)
            p2 = save_html_report("<html>b</html>", "scan-2", out)
            assert p1.name == "cemi_report_scan-1.html"
            assert p2.name == "cemi_report_scan-2.html"


# ---------------------------------------------------------------------------
# save_json_report — file writing
# ---------------------------------------------------------------------------


class TestSaveJsonReport:
    def test_creates_output_directory(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            output_dir = Path(tmp) / "reports"
            assert not output_dir.exists()
            save_json_report(_make_result(scan_id="s1"), output_dir)
            assert output_dir.exists()

    def test_creates_nested_output_directory(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            output_dir = Path(tmp) / "a" / "b" / "reports"
            save_json_report(_make_result(scan_id="s1"), output_dir)
            assert output_dir.exists()

    def test_writes_json_file(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            path = save_json_report(_make_result(scan_id="scan-1"), Path(tmp))
            assert path.exists()

    def test_file_extension_is_json(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            path = save_json_report(_make_result(scan_id="scan-1"), Path(tmp))
            assert path.suffix == ".json"

    def test_file_name_format(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            path = save_json_report(_make_result(scan_id="abc123"), Path(tmp))
            assert path.name == "cemi_report_abc123.json"

    def test_returns_path_object(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            result = save_json_report(_make_result(scan_id="s1"), Path(tmp))
            assert isinstance(result, Path)

    def test_json_includes_scan_id(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            path = save_json_report(_make_result(scan_id="scan-unique-99"), Path(tmp))
            import json
            data = json.loads(path.read_text(encoding="utf-8"))
        assert data["scan_id"] == "scan-unique-99"

    def test_json_includes_collector_health(self) -> None:
        health = [_make_health("installed_apps", items=7)]
        with tempfile.TemporaryDirectory() as tmp:
            path = save_json_report(_make_result(collector_health=health), Path(tmp))
            import json
            data = json.loads(path.read_text(encoding="utf-8"))
        assert "collector_health" in data
        assert data["collector_health"][0]["collector_name"] == "installed_apps"
        assert data["collector_health"][0]["items_collected"] == 7

    def test_json_includes_findings(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            path = save_json_report(
                _make_result(findings=[_make_finding("My Finding")]), Path(tmp)
            )
            import json
            data = json.loads(path.read_text(encoding="utf-8"))
        assert "findings" in data
        assert data["findings"][0]["title"] == "My Finding"

    def test_json_sanitizes_raw_paths_and_field_labels(self) -> None:
        finding = Finding(
            id="TEST-001",
            instance_id=uuid4(),
            rule_version="1.0.0",
            title="Test Finding",
            severity=Severity.LOW,
            confidence=Confidence.HIGH,
            app="test.exe",
            category="Test",
            official_explanation="Test",
            in_other_words="Test",
            why_this_matters="Test",
            evidence=[
                EvidenceItem(
                    type=EvidenceType.FILE_PATH,
                    value="/home/batman/.vscode-server/bin/node",
                    label="exe_path",
                ),
                EvidenceItem(
                    type=EvidenceType.FILE_PATH,
                    value="powershell.exe -File C:\\Users\\batman\\script.ps1",
                    label="command",
                ),
            ],
            recommended_action="Review",
            safe_to_ignore_when=None,
            false_positive_risk="medium",
            requires_admin_to_verify=False,
            created_at=datetime(2024, 1, 1, tzinfo=timezone.utc),
            scan_id="s1",
        )
        result = _make_result(findings=[finding])
        with tempfile.TemporaryDirectory() as tmp:
            path = save_json_report(result, Path(tmp))
            content = path.read_text(encoding="utf-8")
            data = json.loads(content)
        assert "/home/batman" not in content
        assert "C:\\Users\\batman" not in content
        labels = [ev["label"] for finding in data["findings"] for ev in finding["evidence"]]
        assert "exe_path" not in labels
        assert "command" not in labels
        assert "exe_path_redacted" in labels
        assert "command_redacted" in labels

    def test_json_does_not_include_raw_collector_items(self) -> None:
        # ScanResult structurally cannot hold raw collector items — the model
        # uses extra="forbid" and ScanEngine deletes raw items before building
        # the result.  Verify by asserting no service-dict-only keys appear.
        sentinel = "RAW_COLLECTOR_SENTINEL_VALUE"
        result = _make_result(scan_id="s1")
        with tempfile.TemporaryDirectory() as tmp:
            path = save_json_report(result, Path(tmp))
            text = path.read_text(encoding="utf-8")
        assert sentinel not in text
        # Service dicts have keys like "state" and "start_type" that would
        # only appear if raw items leaked into the output.
        import json
        data = json.loads(text)
        top_keys = set(data.keys())
        assert top_keys == {
            "scan_id", "scan_version", "started_at", "completed_at",
            "hostname_redacted", "privilege_level", "collector_health",
            "findings", "correlated_signals", "total_apps_scanned", "risk_summary",
        }

    def test_json_is_valid(self) -> None:
        import json
        with tempfile.TemporaryDirectory() as tmp:
            path = save_json_report(
                _make_result(findings=[_make_finding()]), Path(tmp)
            )
            data = json.loads(path.read_text(encoding="utf-8"))
        assert isinstance(data, dict)

    def test_utf8_encoding_preserved(self) -> None:
        import json
        result = _make_result(scan_id="utf8-scan")
        with tempfile.TemporaryDirectory() as tmp:
            path = save_json_report(result, Path(tmp))
            text = path.read_text(encoding="utf-8")
        # Round-trip check: json loads without error
        json.loads(text)

    def test_does_not_overwrite_existing_file(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            out = Path(tmp)
            p1 = save_json_report(_make_result(scan_id="s1"), out)
            p2 = save_json_report(_make_result(scan_id="s1"), out)
            assert p1 != p2
            assert p1.exists()
            assert p2.exists()

    def test_collision_suffix_is_underscore_one(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            out = Path(tmp)
            p1 = save_json_report(_make_result(scan_id="s1"), out)
            p2 = save_json_report(_make_result(scan_id="s1"), out)
            assert p1.name == "cemi_report_s1.json"
            assert p2.name == "cemi_report_s1_1.json"

    def test_second_collision_increments_counter(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            out = Path(tmp)
            save_json_report(_make_result(scan_id="s1"), out)
            save_json_report(_make_result(scan_id="s1"), out)
            p3 = save_json_report(_make_result(scan_id="s1"), out)
            assert p3.name == "cemi_report_s1_2.json"

    def test_different_scan_ids_do_not_collide(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            out = Path(tmp)
            p1 = save_json_report(_make_result(scan_id="scan-a"), out)
            p2 = save_json_report(_make_result(scan_id="scan-b"), out)
            assert p1.name == "cemi_report_scan-a.json"
            assert p2.name == "cemi_report_scan-b.json"


# ---------------------------------------------------------------------------
# CLI — --output html and --output json behaviour
# ---------------------------------------------------------------------------


class TestCliOutputBehaviour:
    def test_html_output_prints_saved_path(self) -> None:
        with _patch_all_collectors():
            result = runner.invoke(app, ["--output", "html", "--yes"])
        assert result.exit_code == 0
        assert "HTML report saved to:" in result.output

    def test_html_output_printed_path_matches_returned_path(self) -> None:
        with _patch_all_collectors():
            result = runner.invoke(app, ["--output", "html", "--yes"])
        assert str(_FAKE_REPORT_PATH) in result.output

    def test_json_output_prints_saved_path(self) -> None:
        with _patch_all_collectors():
            result = runner.invoke(app, ["--output", "json", "--yes"])
        assert result.exit_code == 0
        assert "JSON report saved to:" in result.output

    def test_json_output_printed_path_matches_returned_path(self) -> None:
        with _patch_all_collectors():
            result = runner.invoke(app, ["--output", "json", "--yes"])
        assert str(_FAKE_JSON_PATH) in result.output

    def test_html_output_calls_generator(self) -> None:
        with _patch_all_collectors():
            with patch("cemi.main.generate_html_report") as mock_gen:
                mock_gen.return_value = "<html></html>"
                result = runner.invoke(app, ["--output", "html", "--yes"])
        assert result.exit_code == 0
        mock_gen.assert_called_once()

    def test_html_output_calls_save(self) -> None:
        with _patch_all_collectors():
            with patch("cemi.main.save_html_report") as mock_save:
                mock_save.return_value = _FAKE_REPORT_PATH
                result = runner.invoke(app, ["--output", "html", "--yes"])
        assert result.exit_code == 0
        mock_save.assert_called_once()

    def test_html_output_save_receives_scan_id(self) -> None:
        with _patch_all_collectors():
            with patch("cemi.main.save_html_report") as mock_save:
                mock_save.return_value = _FAKE_REPORT_PATH
                runner.invoke(app, ["--output", "html", "--yes"])
        _, kwargs = mock_save.call_args
        positional = mock_save.call_args.args
        # scan_id is the second positional argument
        assert isinstance(positional[1], str)
        assert len(positional[1]) > 0

    def test_html_output_generator_receives_scan_result(self) -> None:
        with _patch_all_collectors():
            with patch("cemi.main.generate_html_report") as mock_gen:
                mock_gen.return_value = "<html></html>"
                runner.invoke(app, ["--output", "html", "--yes"])
        args, _ = mock_gen.call_args
        assert isinstance(args[0], ScanResult)

    def test_json_output_calls_save_json_report(self) -> None:
        with _patch_all_collectors():
            with patch("cemi.main.save_json_report") as mock_save:
                mock_save.return_value = _FAKE_JSON_PATH
                result = runner.invoke(app, ["--output", "json", "--yes"])
        assert result.exit_code == 0
        mock_save.assert_called_once()

    def test_json_output_save_receives_scan_result(self) -> None:
        with _patch_all_collectors():
            with patch("cemi.main.save_json_report") as mock_save:
                mock_save.return_value = _FAKE_JSON_PATH
                runner.invoke(app, ["--output", "json", "--yes"])
        args, _ = mock_save.call_args
        assert isinstance(args[0], ScanResult)

    def test_json_output_does_not_call_html_generator(self) -> None:
        with _patch_all_collectors():
            with patch("cemi.main.generate_html_report") as mock_gen:
                runner.invoke(app, ["--output", "json", "--yes"])
        mock_gen.assert_not_called()

    def test_json_output_does_not_call_html_save(self) -> None:
        with _patch_all_collectors():
            with patch("cemi.main.save_html_report") as mock_html_save:
                runner.invoke(app, ["--output", "json", "--yes"])
        mock_html_save.assert_not_called()


# ---------------------------------------------------------------------------
# HTML report — risk summary section
# ---------------------------------------------------------------------------


class TestGenerateHtmlReportRiskSummary:
    def test_risk_summary_section_present(self) -> None:
        html = generate_html_report(_make_result())
        assert "Risk Summary" in html

    def test_risk_score_zero_present_for_no_findings(self) -> None:
        html = generate_html_report(_make_result(findings=[]))
        assert "0/100" in html

    def test_risk_level_none_present_for_no_findings(self) -> None:
        html = generate_html_report(_make_result(findings=[]))
        assert "NONE" in html

    def test_risk_score_shown_for_medium_finding(self) -> None:
        result = _make_result(findings=[_make_finding(severity=Severity.MEDIUM)])
        html = generate_html_report(result)
        assert "15/100" in html

    def test_risk_level_low_shown_for_medium_finding(self) -> None:
        result = _make_result(findings=[_make_finding(severity=Severity.MEDIUM)])
        html = generate_html_report(result)
        assert "LOW" in html

    def test_risk_score_shown_for_high_finding(self) -> None:
        result = _make_result(findings=[_make_finding(severity=Severity.HIGH)])
        html = generate_html_report(result)
        assert "30/100" in html

    def test_risk_level_medium_shown_for_high_finding(self) -> None:
        result = _make_result(findings=[_make_finding(severity=Severity.HIGH)])
        html = generate_html_report(result)
        assert "MEDIUM" in html

    def test_finding_counts_shown_when_present(self) -> None:
        result = _make_result(findings=[
            _make_finding(severity=Severity.HIGH),
            _make_finding(severity=Severity.HIGH),
            _make_finding(severity=Severity.MEDIUM),
        ])
        html = generate_html_report(result)
        assert "HIGH" in html
        assert "MEDIUM" in html

    def test_finding_counts_absent_when_no_findings(self) -> None:
        html = generate_html_report(_make_result(findings=[]))
        assert "Findings by Severity" not in html

    def test_risk_summary_in_json_output(self) -> None:
        import json
        with tempfile.TemporaryDirectory() as tmp:
            result = _make_result(findings=[_make_finding(severity=Severity.HIGH)])
            path = save_json_report(result, Path(tmp))
            data = json.loads(path.read_text(encoding="utf-8"))
        assert "risk_summary" in data
        assert data["risk_summary"]["score"] == 30
        assert data["risk_summary"]["level"] == "medium"
        assert data["risk_summary"]["finding_counts"] == {"HIGH": 1}


# ---------------------------------------------------------------------------
# HTML report — top banner
# ---------------------------------------------------------------------------


class TestGenerateHtmlReportBanner:
    def test_banner_present_in_html(self) -> None:
        html = generate_html_report(_make_result())
        assert "risk-banner" in html

    def test_banner_none_class_for_no_findings(self) -> None:
        html = generate_html_report(_make_result(findings=[]))
        assert "risk-banner-none" in html

    def test_banner_low_class_for_low_risk(self) -> None:
        result = _make_result(findings=[_make_finding(severity=Severity.LOW)])
        html = generate_html_report(result)
        assert "risk-banner-low" in html

    def test_banner_medium_class_for_medium_risk(self) -> None:
        # HIGH finding → score 30 → level "medium"
        result = _make_result(findings=[_make_finding(severity=Severity.HIGH)])
        html = generate_html_report(result)
        assert "risk-banner-medium" in html

    def test_banner_high_class_for_high_risk(self) -> None:
        # 2×HIGH → score 60 → level "high"
        result = _make_result(findings=[
            _make_finding(severity=Severity.HIGH),
            _make_finding(severity=Severity.HIGH),
        ])
        html = generate_html_report(result)
        assert "risk-banner-high" in html

    def test_banner_critical_class_for_critical_risk(self) -> None:
        # CRITICAL finding → score 81 → level "critical"
        result = _make_result(findings=[_make_finding(severity=Severity.CRITICAL)])
        html = generate_html_report(result)
        assert "risk-banner-critical" in html

    def test_banner_shows_risk_level_text(self) -> None:
        html = generate_html_report(_make_result(findings=[]))
        assert "NONE" in html

    def test_banner_shows_score(self) -> None:
        html = generate_html_report(_make_result(findings=[]))
        assert "0/100" in html


# ---------------------------------------------------------------------------
# HTML report — "Why This Matters" risk explanation
# ---------------------------------------------------------------------------


class TestGenerateHtmlReportRiskWhyThisMatters:
    def test_why_this_matters_label_in_risk_summary(self) -> None:
        html = generate_html_report(_make_result(findings=[]))
        assert "Why This Matters" in html

    def test_none_level_explanation_present(self) -> None:
        html = generate_html_report(_make_result(findings=[]))
        assert "No security concerns" in html

    def test_low_level_explanation_present(self) -> None:
        result = _make_result(findings=[_make_finding(severity=Severity.LOW)])
        html = generate_html_report(result)
        assert "Minor concerns" in html

    def test_medium_level_explanation_present(self) -> None:
        # HIGH finding → score 30 → level "medium"
        result = _make_result(findings=[_make_finding(severity=Severity.HIGH)])
        html = generate_html_report(result)
        assert "warrant attention" in html

    def test_high_level_explanation_present(self) -> None:
        # 2×HIGH → score 60 → level "high"
        result = _make_result(findings=[
            _make_finding(severity=Severity.HIGH),
            _make_finding(severity=Severity.HIGH),
        ])
        html = generate_html_report(result)
        assert "promptly" in html

    def test_critical_level_explanation_present(self) -> None:
        # CRITICAL finding → score 81 → level "critical" → "immediate action" text
        result = _make_result(findings=[_make_finding(severity=Severity.CRITICAL)])
        html = generate_html_report(result)
        assert "immediate action" in html.lower()


# ---------------------------------------------------------------------------
# HTML report — findings grouped by severity
# ---------------------------------------------------------------------------


class TestGenerateHtmlReportFindingsGrouped:
    def test_severity_group_header_present_with_high_finding(self) -> None:
        result = _make_result(findings=[_make_finding(severity=Severity.HIGH)])
        html = generate_html_report(result)
        assert "severity-group-HIGH" in html

    def test_severity_group_header_present_with_medium_finding(self) -> None:
        result = _make_result(findings=[_make_finding(severity=Severity.MEDIUM)])
        html = generate_html_report(result)
        assert "severity-group-MEDIUM" in html

    def test_high_finding_rendered_before_low_finding(self) -> None:
        result = _make_result(findings=[
            _make_finding(title="Low Finding", severity=Severity.LOW),
            _make_finding(title="High Finding", severity=Severity.HIGH),
        ])
        html = generate_html_report(result)
        assert html.index("High Finding") < html.index("Low Finding")

    def test_no_severity_group_headers_when_no_findings(self) -> None:
        html = generate_html_report(_make_result(findings=[]))
        assert '<h3 class="severity-group-header' not in html

    def test_findings_summary_badge_present_with_findings(self) -> None:
        result = _make_result(findings=[_make_finding(severity=Severity.HIGH)])
        html = generate_html_report(result)
        assert '<p class="findings-summary">' in html

    def test_findings_summary_absent_when_no_findings(self) -> None:
        html = generate_html_report(_make_result(findings=[]))
        assert '<p class="findings-summary">' not in html

    def test_findings_summary_shows_severity_count(self) -> None:
        result = _make_result(findings=[
            _make_finding(severity=Severity.HIGH),
            _make_finding(severity=Severity.HIGH),
            _make_finding(severity=Severity.MEDIUM),
        ])
        html = generate_html_report(result)
        assert "HIGH: 2" in html
        assert "MEDIUM: 1" in html
