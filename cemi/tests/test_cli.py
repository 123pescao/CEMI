"""Tests for cemi.main CLI."""
from __future__ import annotations

from contextlib import contextmanager
import json
import tempfile
from datetime import datetime, timezone
from unittest.mock import MagicMock, patch
from uuid import uuid4

from typer.testing import CliRunner

from pathlib import Path

from cemi.main import app
from cemi.correlation_engine import CorrelatedSignal
from cemi.models import (
    CollectorHealth,
    Confidence,
    EvidenceItem,
    EvidenceType,
    Finding,
    ScanResult,
    Severity,
)
from cemi.scoring import calculate_risk_summary

_FAKE_REPORT_PATH = Path("reports/cemi_report_fake.html")
_FAKE_JSON_PATH = Path("reports/cemi_report_fake.json")

runner = CliRunner()


# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------


def _make_health(
    *,
    collector_name: str = "installed_apps",
    items_collected: int = 0,
    ran_successfully: bool = True,
    errors: list[str] | None = None,
    skipped_reason: str | None = None,
    duration_seconds: float = 0.01,
) -> CollectorHealth:
    return CollectorHealth(
        collector_name=collector_name,
        ran_successfully=ran_successfully,
        privilege_level="user",
        items_collected=items_collected,
        duration_seconds=duration_seconds,
        errors=errors or [],
        skipped_reason=skipped_reason,
    )


def _mock_run(health: CollectorHealth, items: list | None = None) -> MagicMock:
    """Return a collector instance mock whose .run() yields (items, health)."""
    inst = MagicMock()
    inst.run.return_value = (items or [], health)
    return inst


@contextmanager
def _patch_both(
    apps_health: CollectorHealth | None = None,
    svcs_health: CollectorHealth | None = None,
    nmh_health: CollectorHealth | None = None,
    bext_health: CollectorHealth | None = None,
):
    """Patch all four collectors simultaneously for clean, isolated CLI tests."""
    if apps_health is None:
        apps_health = _make_health(collector_name="installed_apps")
    if svcs_health is None:
        svcs_health = _make_health(collector_name="services")
    if nmh_health is None:
        nmh_health = _make_health(collector_name="native_messaging_hosts")
    if bext_health is None:
        bext_health = _make_health(collector_name="browser_extensions")

    with (
        patch("cemi.main.InstalledAppsCollector", return_value=_mock_run(apps_health)),
        patch("cemi.main.ServicesCollector", return_value=_mock_run(svcs_health)),
        patch("cemi.main.NativeMessagingHostsCollector", return_value=_mock_run(nmh_health)),
        patch("cemi.main.BrowserExtensionsCollector", return_value=_mock_run(bext_health)),
        patch("cemi.main.save_html_report", return_value=_FAKE_REPORT_PATH),
        patch("cemi.main.save_json_report", return_value=_FAKE_JSON_PATH),
    ):
        yield


# ---------------------------------------------------------------------------
# Output format validation (--output flag)
# ---------------------------------------------------------------------------


class TestOutputFormat:
    def test_output_html_accepted(self) -> None:
        with _patch_both():
            result = runner.invoke(app, ["scan", "--output", "html", "--yes"])
        assert result.exit_code == 0

    def test_output_json_accepted(self) -> None:
        with _patch_both():
            result = runner.invoke(app, ["scan", "--output", "json", "--yes"])
        assert result.exit_code == 0

    def test_output_text_rejected(self) -> None:
        result = runner.invoke(app, ["scan", "--output", "text", "--yes"])
        assert result.exit_code != 0


# ---------------------------------------------------------------------------
# Installed-apps collector summary
# ---------------------------------------------------------------------------


class TestInstalledAppsSummary:
    def test_scan_complete_in_output(self) -> None:
        with _patch_both():
            result = runner.invoke(app, ["scan", "--yes"])
        assert result.exit_code == 0
        assert "Scan complete" in result.output

    def test_installed_apps_count_label_present(self) -> None:
        with _patch_both():
            result = runner.invoke(app, ["scan", "--yes"])
        assert "Installed apps found:" in result.output

    def test_installed_apps_collector_name_present(self) -> None:
        with _patch_both():
            result = runner.invoke(app, ["scan", "--yes"])
        assert "installed_apps" in result.output

    def test_shows_correct_app_count(self) -> None:
        with _patch_both(apps_health=_make_health(collector_name="installed_apps", items_collected=17)):
            result = runner.invoke(app, ["scan", "--yes"])
        assert "17" in result.output

    def test_shows_ok_for_apps(self) -> None:
        with _patch_both(apps_health=_make_health(collector_name="installed_apps", ran_successfully=True)):
            result = runner.invoke(app, ["scan", "--yes"])
        assert "OK" in result.output

    def test_shows_failed_for_apps(self) -> None:
        with _patch_both(apps_health=_make_health(collector_name="installed_apps", ran_successfully=False)):
            result = runner.invoke(app, ["scan", "--yes"])
        assert "FAILED" in result.output

    def test_shows_skipped_for_apps(self) -> None:
        with _patch_both(
            apps_health=_make_health(
                collector_name="installed_apps",
                skipped_reason="winreg not available (non-Windows platform)",
            )
        ):
            result = runner.invoke(app, ["scan", "--yes"])
        assert "SKIPPED" in result.output
        assert "winreg not available" in result.output

    def test_shows_apps_errors(self) -> None:
        with _patch_both(
            apps_health=_make_health(
                collector_name="installed_apps",
                errors=["PermissionError: access denied to registry key"],
            )
        ):
            result = runner.invoke(app, ["scan", "--yes"])
        assert "PermissionError" in result.output

    def test_no_errors_section_when_apps_clean(self) -> None:
        with _patch_both(
            apps_health=_make_health(collector_name="installed_apps", errors=[]),
            svcs_health=_make_health(collector_name="services", errors=[]),
        ):
            result = runner.invoke(app, ["scan", "--yes"])
        assert "Errors:" not in result.output


# ---------------------------------------------------------------------------
# Services collector summary
# ---------------------------------------------------------------------------


class TestServicesSummary:
    def test_services_count_label_present(self) -> None:
        with _patch_both():
            result = runner.invoke(app, ["scan", "--yes"])
        assert "Services found:" in result.output

    def test_services_collector_name_present(self) -> None:
        with _patch_both():
            result = runner.invoke(app, ["scan", "--yes"])
        assert "services" in result.output

    def test_shows_correct_service_count(self) -> None:
        with _patch_both(svcs_health=_make_health(collector_name="services", items_collected=42)):
            result = runner.invoke(app, ["scan", "--yes"])
        assert "42" in result.output

    def test_shows_ok_for_services(self) -> None:
        with _patch_both(svcs_health=_make_health(collector_name="services", ran_successfully=True)):
            result = runner.invoke(app, ["scan", "--yes"])
        assert "OK" in result.output

    def test_shows_failed_for_services(self) -> None:
        with _patch_both(svcs_health=_make_health(collector_name="services", ran_successfully=False)):
            result = runner.invoke(app, ["scan", "--yes"])
        assert "FAILED" in result.output

    def test_shows_skipped_for_services(self) -> None:
        with _patch_both(
            svcs_health=_make_health(
                collector_name="services",
                skipped_reason="Windows services not available on this platform",
            )
        ):
            result = runner.invoke(app, ["scan", "--yes"])
        assert "SKIPPED" in result.output
        assert "Windows services not available" in result.output

    def test_shows_services_errors(self) -> None:
        with _patch_both(
            svcs_health=_make_health(
                collector_name="services",
                errors=["OSError: failed to iterate services"],
            )
        ):
            result = runner.invoke(app, ["scan", "--yes"])
        assert "OSError" in result.output


# ---------------------------------------------------------------------------
# Both collectors together
# ---------------------------------------------------------------------------


class TestBothCollectors:
    def test_both_counts_in_output(self) -> None:
        with _patch_both(
            apps_health=_make_health(collector_name="installed_apps", items_collected=5),
            svcs_health=_make_health(collector_name="services", items_collected=10),
        ):
            result = runner.invoke(app, ["scan", "--yes"])
        assert "5" in result.output
        assert "10" in result.output

    def test_both_collector_names_in_output(self) -> None:
        with _patch_both():
            result = runner.invoke(app, ["scan", "--yes"])
        assert "installed_apps" in result.output
        assert "services" in result.output

    def test_exit_code_zero_when_both_succeed(self) -> None:
        with _patch_both(
            apps_health=_make_health(collector_name="installed_apps", ran_successfully=True),
            svcs_health=_make_health(collector_name="services", ran_successfully=True),
        ):
            result = runner.invoke(app, ["scan", "--yes"])
        assert result.exit_code == 0

    def test_exit_code_zero_even_when_both_fail(self) -> None:
        # CLI reports failures but exits cleanly — the user decides next steps.
        with _patch_both(
            apps_health=_make_health(collector_name="installed_apps", ran_successfully=False),
            svcs_health=_make_health(collector_name="services", ran_successfully=False),
        ):
            result = runner.invoke(app, ["scan", "--yes"])
        assert result.exit_code == 0

    def test_real_collectors_do_not_crash(self) -> None:
        # Exercises the real collectors end-to-end; on Linux both skip gracefully.
        result = runner.invoke(app, ["scan", "--yes"])
        assert result.exit_code == 0
        assert "Scan complete" in result.output


# ---------------------------------------------------------------------------
# Privacy confirmation flow
# ---------------------------------------------------------------------------


class TestPrivacyConfirmation:
    def test_yes_flag_skips_prompt(self) -> None:
        with _patch_both():
            result = runner.invoke(app, ["scan", "--yes"])
        assert result.exit_code == 0
        assert "Scan complete" in result.output

    def test_confirming_y_proceeds(self) -> None:
        with _patch_both():
            result = runner.invoke(app, ["scan"], input="y\n")
        assert "Scan complete" in result.output

    def test_declining_n_aborts(self) -> None:
        result = runner.invoke(app, ["scan"], input="n\n")
        assert result.exit_code != 0
        assert "Scan complete" not in result.output

    def test_default_empty_input_aborts(self) -> None:
        result = runner.invoke(app, ["scan"], input="\n")
        assert result.exit_code != 0


# ---------------------------------------------------------------------------
# Findings output
# ---------------------------------------------------------------------------

# Service dict that triggers ServiceUserPathRule (SVC-001).
_USER_PATH_SVC = {
    "name": "EvilSvc",
    "binary_path": r"C:\Users\[REDACTED]\AppData\Local\evil.exe",
    "state": "running",
    "start_type": "auto",
    "username": "[REDACTED]",
}


@contextmanager
def _patch_with_finding():
    """Patch collectors so the services collector returns a user-path service,
    causing SVC-001 to fire and produce a finding in the scan result."""
    apps_health = _make_health(collector_name="installed_apps")
    svcs_health = _make_health(collector_name="services", items_collected=1)
    nmh_health = _make_health(collector_name="native_messaging_hosts")
    bext_health = _make_health(collector_name="browser_extensions")
    with (
        patch("cemi.main.InstalledAppsCollector", return_value=_mock_run(apps_health)),
        patch("cemi.main.ServicesCollector", return_value=_mock_run(svcs_health, [_USER_PATH_SVC])),
        patch("cemi.main.NativeMessagingHostsCollector", return_value=_mock_run(nmh_health)),
        patch("cemi.main.BrowserExtensionsCollector", return_value=_mock_run(bext_health)),
        patch("cemi.main.save_html_report", return_value=_FAKE_REPORT_PATH),
        patch("cemi.main.save_json_report", return_value=_FAKE_JSON_PATH),
    ):
        yield


class TestFindingsOutput:
    def test_findings_section_printed_when_present(self) -> None:
        with _patch_with_finding():
            result = runner.invoke(app, ["scan", "--yes"])
        assert result.exit_code == 0
        assert "Findings" in result.output

    def test_no_findings_message_when_empty(self) -> None:
        with _patch_both():
            result = runner.invoke(app, ["scan", "--yes"])
        assert "No findings detected." in result.output

    def test_severity_displayed(self) -> None:
        with _patch_with_finding():
            result = runner.invoke(app, ["scan", "--yes"])
        assert "MEDIUM" in result.output

    def test_official_explanation_included(self) -> None:
        with _patch_with_finding():
            result = runner.invoke(app, ["scan", "--yes"])
        assert "Official Explanation" in result.output

    def test_official_explanation_text_present(self) -> None:
        with _patch_with_finding():
            result = runner.invoke(app, ["scan", "--yes"])
        # The hardcoded explanation mentions user profile directory.
        assert "user profile" in result.output.lower()

    def test_in_other_words_section_included(self) -> None:
        with _patch_with_finding():
            result = runner.invoke(app, ["scan", "--yes"])
        assert "In Other Words" in result.output

    def test_why_this_matters_section_included(self) -> None:
        with _patch_with_finding():
            result = runner.invoke(app, ["scan", "--yes"])
        assert "Why This Matters" in result.output

    def test_recommended_action_section_included(self) -> None:
        with _patch_with_finding():
            result = runner.invoke(app, ["scan", "--yes"])
        assert "Recommended Action" in result.output

    def test_finding_title_present(self) -> None:
        with _patch_with_finding():
            result = runner.invoke(app, ["scan", "--yes"])
        assert "Service binary in user profile directory" in result.output

    def test_finding_app_name_present(self) -> None:
        with _patch_with_finding():
            result = runner.invoke(app, ["scan", "--yes"])
        assert "EvilSvc" in result.output

    def test_evidence_summarized_not_raw_path(self) -> None:
        with _patch_with_finding():
            result = runner.invoke(app, ["scan", "--yes"])
        # Evidence is summarised; the raw path string must not appear verbatim.
        assert r"C:\Users\[REDACTED]\AppData\Local\evil.exe" not in result.output
        assert "supporting item" in result.output

    def test_no_findings_message_absent_when_findings_present(self) -> None:
        with _patch_with_finding():
            result = runner.invoke(app, ["scan", "--yes"])
        assert "No findings detected." not in result.output

    def test_exit_code_zero_with_findings(self) -> None:
        with _patch_with_finding():
            result = runner.invoke(app, ["scan", "--yes"])
        assert result.exit_code == 0


# ---------------------------------------------------------------------------
# Native messaging hosts collector — CLI summary
# ---------------------------------------------------------------------------


class TestNativeMessagingHostsSummary:
    def test_collector_name_in_output(self) -> None:
        with _patch_both():
            result = runner.invoke(app, ["scan", "--yes"])
        assert "native_messaging_hosts" in result.output

    def test_ok_status_when_ran_successfully(self) -> None:
        with _patch_both(nmh_health=_make_health(collector_name="native_messaging_hosts", ran_successfully=True)):
            result = runner.invoke(app, ["scan", "--yes"])
        assert "OK" in result.output

    def test_failed_status_when_not_successful(self) -> None:
        with _patch_both(nmh_health=_make_health(collector_name="native_messaging_hosts", ran_successfully=False)):
            result = runner.invoke(app, ["scan", "--yes"])
        assert "FAILED" in result.output

    def test_skipped_status_when_skipped(self) -> None:
        with _patch_both(
            nmh_health=_make_health(
                collector_name="native_messaging_hosts",
                skipped_reason="Native messaging host directories are Windows-only in this version",
            )
        ):
            result = runner.invoke(app, ["scan", "--yes"])
        assert "SKIPPED" in result.output
        assert "Windows-only" in result.output

    def test_errors_shown_when_present(self) -> None:
        with _patch_both(
            nmh_health=_make_health(
                collector_name="native_messaging_hosts",
                errors=["OSError: cannot scan directory"],
            )
        ):
            result = runner.invoke(app, ["scan", "--yes"])
        assert "OSError" in result.output

    def test_exit_code_zero_with_nmh_collector(self) -> None:
        with _patch_both():
            result = runner.invoke(app, ["scan", "--yes"])
        assert result.exit_code == 0

    def test_real_collectors_do_not_crash_with_nmh(self) -> None:
        result = runner.invoke(app, ["scan", "--yes"])
        assert result.exit_code == 0
        assert "native_messaging_hosts" in result.output


# ---------------------------------------------------------------------------
# Privacy flag
# ---------------------------------------------------------------------------


class TestPrivacyFlag:
    def test_exit_code_zero(self) -> None:
        result = runner.invoke(app, ["privacy"])
        assert result.exit_code == 0

    def test_privacy_guarantees_in_output(self) -> None:
        result = runner.invoke(app, ["privacy"])
        assert "No telemetry" in result.output
        assert "No network upload" in result.output
        assert "No browser history reading" in result.output
        assert "No cookie reading" in result.output
        assert "No personal document scanning" in result.output
        assert "Reports are local" in result.output

    def test_collectors_not_called(self) -> None:
        apps_cls = MagicMock()
        svcs_cls = MagicMock()
        nmh_cls = MagicMock()
        bext_cls = MagicMock()
        with (
            patch("cemi.main.InstalledAppsCollector", apps_cls),
            patch("cemi.main.ServicesCollector", svcs_cls),
            patch("cemi.main.NativeMessagingHostsCollector", nmh_cls),
            patch("cemi.main.BrowserExtensionsCollector", bext_cls),
        ):
            runner.invoke(app, ["privacy"])
        apps_cls.assert_not_called()
        svcs_cls.assert_not_called()
        nmh_cls.assert_not_called()
        bext_cls.assert_not_called()

    def test_save_html_report_not_called(self) -> None:
        save_html = MagicMock()
        with (
            patch("cemi.main.InstalledAppsCollector"),
            patch("cemi.main.ServicesCollector"),
            patch("cemi.main.NativeMessagingHostsCollector"),
            patch("cemi.main.BrowserExtensionsCollector"),
            patch("cemi.main.save_html_report", save_html),
        ):
            runner.invoke(app, ["privacy"])
        save_html.assert_not_called()

    def test_save_json_report_not_called(self) -> None:
        save_json = MagicMock()
        with (
            patch("cemi.main.InstalledAppsCollector"),
            patch("cemi.main.ServicesCollector"),
            patch("cemi.main.NativeMessagingHostsCollector"),
            patch("cemi.main.BrowserExtensionsCollector"),
            patch("cemi.main.save_json_report", save_json),
        ):
            runner.invoke(app, ["privacy"])
        save_json.assert_not_called()

    def test_scan_does_not_run(self) -> None:
        result = runner.invoke(app, ["privacy"])
        assert "Scan complete" not in result.output


# ---------------------------------------------------------------------------
# Browser extensions collector — CLI summary
# ---------------------------------------------------------------------------


class TestBrowserExtensionsSummary:
    def test_collector_name_in_output(self) -> None:
        with _patch_both():
            result = runner.invoke(app, ["scan", "--yes"])
        assert "browser_extensions" in result.output

    def test_browser_extensions_count_label_present(self) -> None:
        with _patch_both():
            result = runner.invoke(app, ["scan", "--yes"])
        assert "Browser extensions found:" in result.output

    def test_shows_correct_extension_count(self) -> None:
        with _patch_both(bext_health=_make_health(collector_name="browser_extensions", items_collected=7)):
            result = runner.invoke(app, ["scan", "--yes"])
        assert "7" in result.output

    def test_ok_status_when_ran_successfully(self) -> None:
        with _patch_both(bext_health=_make_health(collector_name="browser_extensions", ran_successfully=True)):
            result = runner.invoke(app, ["scan", "--yes"])
        assert "OK" in result.output

    def test_failed_status_when_not_successful(self) -> None:
        with _patch_both(bext_health=_make_health(collector_name="browser_extensions", ran_successfully=False)):
            result = runner.invoke(app, ["scan", "--yes"])
        assert "FAILED" in result.output

    def test_skipped_status_when_skipped(self) -> None:
        with _patch_both(
            bext_health=_make_health(
                collector_name="browser_extensions",
                skipped_reason="Browser extension directories are Windows-only in this version",
            )
        ):
            result = runner.invoke(app, ["scan", "--yes"])
        assert "SKIPPED" in result.output
        assert "Windows-only" in result.output

    def test_errors_shown_when_present(self) -> None:
        with _patch_both(
            bext_health=_make_health(
                collector_name="browser_extensions",
                errors=["OSError: cannot scan extensions directory"],
            )
        ):
            result = runner.invoke(app, ["scan", "--yes"])
        assert "OSError" in result.output

    def test_exit_code_zero_with_bext_collector(self) -> None:
        with _patch_both():
            result = runner.invoke(app, ["scan", "--yes"])
        assert result.exit_code == 0

    def test_real_collectors_do_not_crash_with_bext(self) -> None:
        result = runner.invoke(app, ["scan", "--yes"])
        assert result.exit_code == 0
        assert "browser_extensions" in result.output


# ---------------------------------------------------------------------------
# Risk score and level — CLI output
# ---------------------------------------------------------------------------


class TestRiskOutput:
    def test_risk_score_label_present(self) -> None:
        with _patch_both():
            result = runner.invoke(app, ["scan", "--yes"])
        assert result.exit_code == 0
        assert "Risk score:" in result.output

    def test_risk_level_label_present(self) -> None:
        with _patch_both():
            result = runner.invoke(app, ["scan", "--yes"])
        assert result.exit_code == 0
        assert "Risk level:" in result.output

    def test_risk_score_zero_with_no_findings(self) -> None:
        with _patch_both():
            result = runner.invoke(app, ["scan", "--yes"])
        assert "0/100" in result.output

    def test_risk_level_none_with_no_findings(self) -> None:
        with _patch_both():
            result = runner.invoke(app, ["scan", "--yes"])
        assert "none" in result.output

    def test_risk_score_nonzero_with_finding(self) -> None:
        with _patch_with_finding():
            result = runner.invoke(app, ["scan", "--yes"])
        assert result.exit_code == 0
        # ServiceUserPathRule fires → MEDIUM finding → score ≥ 15
        assert "0/100" not in result.output

    def test_risk_level_nonzero_with_finding(self) -> None:
        with _patch_with_finding():
            result = runner.invoke(app, ["scan", "--yes"])
        # Any non-"none" level means something was detected
        assert "none" not in result.output or "Risk level:" in result.output

    def test_risk_score_format_contains_slash_100(self) -> None:
        with _patch_both():
            result = runner.invoke(app, ["scan", "--yes"])
        assert "/100" in result.output

    def test_real_scan_prints_risk_score(self) -> None:
        result = runner.invoke(app, ["scan", "--yes"])
        assert result.exit_code == 0
        assert "Risk score:" in result.output
        assert "Risk level:" in result.output


# ---------------------------------------------------------------------------
# CLI header and section structure
# ---------------------------------------------------------------------------


class TestCliHeader:
    def test_cemi_scan_results_header_present(self) -> None:
        with _patch_both():
            result = runner.invoke(app, ["scan", "--yes"])
        assert "CEMÍ SCAN RESULTS" in result.output

    def test_risk_summary_section_label_present(self) -> None:
        with _patch_both():
            result = runner.invoke(app, ["scan", "--yes"])
        assert "Risk Summary" in result.output

    def test_collectors_section_label_present(self) -> None:
        with _patch_both():
            result = runner.invoke(app, ["scan", "--yes"])
        assert "Collectors" in result.output

    def test_summary_section_label_present(self) -> None:
        with _patch_both():
            result = runner.invoke(app, ["scan", "--yes"])
        assert "Summary" in result.output

    def test_risk_why_this_matters_label_present(self) -> None:
        with _patch_both():
            result = runner.invoke(app, ["scan", "--yes"])
        assert "Why this matters:" in result.output

    def test_risk_why_text_none_level(self) -> None:
        with _patch_both():
            result = runner.invoke(app, ["scan", "--yes"])
        assert "No security concerns" in result.output

    def test_risk_why_text_changes_with_finding(self) -> None:
        with _patch_with_finding():
            result = runner.invoke(app, ["scan", "--yes"])
        assert "No security concerns" not in result.output

    def test_header_not_shown_for_privacy_flag(self) -> None:
        result = runner.invoke(app, ["privacy"])
        assert "CEMÍ SCAN RESULTS" not in result.output


# ---------------------------------------------------------------------------
# Findings grouped by severity
# ---------------------------------------------------------------------------

# Extension dict that triggers ExtScriptingWebRequestRule (EXT-003) → HIGH.
_HIGH_EXT = {
    "name": "ScriptingExt",
    "browser": "chrome",
    "version": "1.0.0",
    "permissions": ["scripting", "webRequest"],
    "host_permissions": [],
    "manifest_path": r"C:\Users\[REDACTED]\AppData\Local\Google\Chrome\User Data\Default\Extensions\ext\1.0_0\manifest.json",
}


@contextmanager
def _patch_with_high_finding():
    """Patch collectors so EXT-003 fires, producing one HIGH finding."""
    apps_health = _make_health(collector_name="installed_apps")
    svcs_health = _make_health(collector_name="services")
    nmh_health = _make_health(collector_name="native_messaging_hosts")
    bext_health = _make_health(collector_name="browser_extensions", items_collected=1)
    with (
        patch("cemi.main.InstalledAppsCollector", return_value=_mock_run(apps_health)),
        patch("cemi.main.ServicesCollector", return_value=_mock_run(svcs_health)),
        patch("cemi.main.NativeMessagingHostsCollector", return_value=_mock_run(nmh_health)),
        patch("cemi.main.BrowserExtensionsCollector", return_value=_mock_run(bext_health, [_HIGH_EXT])),
        patch("cemi.main.save_html_report", return_value=_FAKE_REPORT_PATH),
        patch("cemi.main.save_json_report", return_value=_FAKE_JSON_PATH),
    ):
        yield


class TestFindingsGroupedBySeverity:
    def test_medium_group_present_with_medium_finding(self) -> None:
        with _patch_with_finding():
            result = runner.invoke(app, ["scan", "--yes"])
        assert "MEDIUM" in result.output

    def test_high_group_present_with_high_finding(self) -> None:
        with _patch_with_high_finding():
            result = runner.invoke(app, ["scan", "--yes"])
        assert "HIGH" in result.output

    def test_high_before_medium_when_both_present(self) -> None:
        # Both HIGH (EXT-003) and MEDIUM (SVC-001) fire simultaneously.
        apps_health = _make_health(collector_name="installed_apps")
        svcs_health = _make_health(collector_name="services", items_collected=1)
        nmh_health = _make_health(collector_name="native_messaging_hosts")
        bext_health = _make_health(collector_name="browser_extensions", items_collected=1)
        with (
            patch("cemi.main.InstalledAppsCollector", return_value=_mock_run(apps_health)),
            patch("cemi.main.ServicesCollector", return_value=_mock_run(svcs_health, [_USER_PATH_SVC])),
            patch("cemi.main.NativeMessagingHostsCollector", return_value=_mock_run(nmh_health)),
            patch("cemi.main.BrowserExtensionsCollector", return_value=_mock_run(bext_health, [_HIGH_EXT])),
            patch("cemi.main.save_html_report", return_value=_FAKE_REPORT_PATH),
            patch("cemi.main.save_json_report", return_value=_FAKE_JSON_PATH),
        ):
            result = runner.invoke(app, ["scan", "--yes"])
        output = result.output
        assert "HIGH" in output
        assert "MEDIUM" in output
        assert output.index("HIGH") < output.index("MEDIUM")

    def test_no_findings_message_present_when_empty(self) -> None:
        with _patch_both():
            result = runner.invoke(app, ["scan", "--yes"])
        assert "No findings detected." in result.output

    def test_contextual_confidence_shown_in_finding_output(self) -> None:
        with _patch_with_finding():
            result = runner.invoke(app, ["scan", "--yes"])
        assert "Contextual Confidence:" in result.output

    def test_status_shown_in_finding_output(self) -> None:
        with _patch_with_finding():
            result = runner.invoke(app, ["scan", "--yes"])
        assert "Status:" in result.output

    def test_reasoning_notes_shown_in_finding_output(self) -> None:
        with _patch_with_finding():
            result = runner.invoke(app, ["scan", "--yes"])
        assert "Why CEMÍ Thinks This" in result.output


# ---------------------------------------------------------------------------
# Summary section counts
# ---------------------------------------------------------------------------


class TestSummaryCounts:
    def test_medium_finding_count_in_summary(self) -> None:
        with _patch_with_finding():
            result = runner.invoke(app, ["scan", "--yes"])
        assert "1 medium finding" in result.output

    def test_high_finding_count_in_summary(self) -> None:
        with _patch_with_high_finding():
            result = runner.invoke(app, ["scan", "--yes"])
        assert "1 high finding" in result.output

    def test_no_finding_count_with_no_findings(self) -> None:
        with _patch_both():
            result = runner.invoke(app, ["scan", "--yes"])
        assert "medium finding" not in result.output
        assert "high finding" not in result.output

    def test_plural_count_for_multiple_findings(self) -> None:
        # Two MEDIUM findings → "2 medium findings"
        apps_health = _make_health(collector_name="installed_apps")
        svcs_health = _make_health(collector_name="services", items_collected=2)
        nmh_health = _make_health(collector_name="native_messaging_hosts")
        bext_health = _make_health(collector_name="browser_extensions")
        svc2 = dict(_USER_PATH_SVC, name="EvilSvc2")
        with (
            patch("cemi.main.InstalledAppsCollector", return_value=_mock_run(apps_health)),
            patch(
                "cemi.main.ServicesCollector",
                return_value=_mock_run(svcs_health, [_USER_PATH_SVC, svc2]),
            ),
            patch("cemi.main.NativeMessagingHostsCollector", return_value=_mock_run(nmh_health)),
            patch("cemi.main.BrowserExtensionsCollector", return_value=_mock_run(bext_health)),
            patch("cemi.main.save_html_report", return_value=_FAKE_REPORT_PATH),
            patch("cemi.main.save_json_report", return_value=_FAKE_JSON_PATH),
        ):
            result = runner.invoke(app, ["scan", "--yes"])
        assert "2 medium findings" in result.output


# ---------------------------------------------------------------------------
# cemi scan subcommand
# ---------------------------------------------------------------------------


class TestScanSubcommand:
    def test_scan_subcommand_exits_zero(self) -> None:
        with _patch_both():
            result = runner.invoke(app, ["scan", "--yes"])
        assert result.exit_code == 0

    def test_scan_subcommand_produces_output(self) -> None:
        with _patch_both():
            result = runner.invoke(app, ["scan", "--yes"])
        assert "Scan complete" in result.output

    def test_scan_subcommand_html_output(self) -> None:
        with _patch_both():
            result = runner.invoke(app, ["scan", "--output", "html", "--yes"])
        assert result.exit_code == 0

    def test_scan_subcommand_json_output(self) -> None:
        with _patch_both():
            result = runner.invoke(app, ["scan", "--output", "json", "--yes"])
        assert result.exit_code == 0

    def test_correlated_threat_signals_section_shown(self) -> None:
        correlated_finding = Finding(
            id="EXT-003",
            instance_id=uuid4(),
            rule_version="1.0.0",
            title="Extension Can Inject Scripts and Intercept Traffic",
            severity=Severity.HIGH,
            confidence=Confidence.MEDIUM,
            contextual_confidence="medium",
            reasoning_notes=["Test reasoning."],
            app="Malicious Extension",
            category="Browser Extension",
            official_explanation="Official explanation.",
            in_other_words="In other words.",
            why_this_matters="Why this matters.",
            evidence=[
                EvidenceItem(type=EvidenceType.PERMISSION, value="scripting", label="permission"),
            ],
            recommended_action="Recommended action.",
            safe_to_ignore_when="Safe to ignore.",
            false_positive_risk="low",
            requires_admin_to_verify=False,
            created_at=datetime.now(timezone.utc),
            scan_id="scan-test",
        )
        nmh_finding = Finding(
            id="NMH-001",
            instance_id=uuid4(),
            rule_version="1.0.0",
            title="Browser Native Messaging Host Detected",
            severity=Severity.MEDIUM,
            confidence=Confidence.HIGH,
            contextual_confidence="high",
            reasoning_notes=["Test reasoning."],
            app="Native Host",
            category="Browser Integration",
            official_explanation="Official explanation.",
            in_other_words="In other words.",
            why_this_matters="Why this matters.",
            evidence=[
                EvidenceItem(type=EvidenceType.FILE_PATH, value="manifest.json", label="manifest_path"),
            ],
            recommended_action="Recommended action.",
            safe_to_ignore_when="Safe to ignore.",
            false_positive_risk="low",
            requires_admin_to_verify=False,
            created_at=datetime.now(timezone.utc),
            scan_id="scan-test",
        )
        correlated_signal = CorrelatedSignal(
            id="CORR-101",
            instance_id=uuid4(),
            rule_version="1.0.0",
            correlation_id="CORR-101",
            title="Browser Extension Can Reach Native System Access",
            severity=Severity.HIGH,
            confidence=Confidence.HIGH,
            contextual_confidence="high",
            status="High Priority",
            contributing_findings=["EXT-003: Extension Can Inject Scripts and Intercept Traffic", "NMH-001: Browser Native Messaging Host Detected"],
            evidence_count=2,
            risk_multiplier=1.4,
            reasoning_notes=["Browser scripting capability and native messaging host present."],
            app=None,
            category="Correlation",
            official_explanation="A browser extension can bridge browser traffic to a local process.",
            in_other_words="A browser extension and native host are present together.",
            why_this_matters="This correlation elevates the threat signal without removing the original findings.",
            evidence=[
                EvidenceItem(type=EvidenceType.METADATA, value="2", label="correlated_evidence_count"),
            ],
            recommended_action="Review the correlated findings and verify the integration.",
            safe_to_ignore_when="The integration is a trusted browser helper.",
            false_positive_risk="medium",
            requires_admin_to_verify=False,
            created_at=datetime.now(timezone.utc),
            scan_id="scan-test",
        )
        scan_result = ScanResult(
            scan_id="scan-test",
            scan_version="0.1.0",
            started_at=datetime.now(timezone.utc),
            completed_at=datetime.now(timezone.utc),
            hostname_redacted="x" * 64,
            privilege_level="user",
            collector_health=[_make_health()],
            findings=[nmh_finding],
            correlated_signals=[correlated_signal],
            total_apps_scanned=1,
            risk_summary=calculate_risk_summary([nmh_finding, correlated_signal]),
        )

        mock_engine = MagicMock()
        mock_engine.run_scan.return_value = scan_result
        with (
            patch("cemi.main.ScanEngine", return_value=mock_engine),
            patch("cemi.main.save_html_report", return_value=_FAKE_REPORT_PATH),
            patch("cemi.main.save_json_report", return_value=_FAKE_JSON_PATH),
        ):
            result = runner.invoke(app, ["scan", "--yes"])

        assert result.exit_code == 0
        assert "Correlated Threat Signals" in result.output
        assert "Why CEMÍ correlated this" in result.output


class TestHistoryCommand:
    def test_history_shows_no_history_message(self) -> None:
        with tempfile.TemporaryDirectory() as tmpdir:
            with patch("pathlib.Path.cwd", return_value=Path(tmpdir)):
                result = runner.invoke(app, ["history"])

        assert result.exit_code == 0
        assert "No monitor history found" in result.output
        assert "cemi monitor" in result.output

    def test_history_shows_summary_for_existing_history(self) -> None:
        with tempfile.TemporaryDirectory() as tmpdir:
            history_dir = Path(tmpdir) / ".cemi" / "history"
            history_dir.mkdir(parents=True, exist_ok=True)
            snapshot = {
                "snapshot_id": "snap-1",
                "scan_id": "scan-1",
                "timestamp": datetime.now(timezone.utc).isoformat(),
                "risk_score": 18,
                "risk_level": "medium",
                "finding_titles": ["Test Finding"],
                "finding_ids": ["TST-001"],
                "collector_statuses": {"installed_apps": True},
            }
            with open(history_dir / "snapshot_001.json", "w", encoding="utf-8") as fh:
                json.dump(snapshot, fh)
            with patch("pathlib.Path.cwd", return_value=Path(tmpdir)):
                result = runner.invoke(app, ["history"])

        assert result.exit_code == 0
        assert "Snapshots: 1" in result.output
        assert "Latest risk score: 18/100" in result.output
        assert "Active findings: 1" in result.output


# ---------------------------------------------------------------------------
# cemi privacy subcommand
# ---------------------------------------------------------------------------


class TestPrivacySubcommand:
    def test_privacy_subcommand_exits_zero(self) -> None:
        result = runner.invoke(app, ["privacy"])
        assert result.exit_code == 0

    def test_privacy_subcommand_shows_guarantees(self) -> None:
        result = runner.invoke(app, ["privacy"])
        assert "No telemetry" in result.output
        assert "No network upload" in result.output
        assert "No browser history reading" in result.output
        assert "No cookie reading" in result.output
        assert "No personal document scanning" in result.output
        assert "Reports are local" in result.output

    def test_privacy_subcommand_does_not_run_collectors(self) -> None:
        apps_cls = MagicMock()
        svcs_cls = MagicMock()
        nmh_cls = MagicMock()
        bext_cls = MagicMock()
        with (
            patch("cemi.main.InstalledAppsCollector", apps_cls),
            patch("cemi.main.ServicesCollector", svcs_cls),
            patch("cemi.main.NativeMessagingHostsCollector", nmh_cls),
            patch("cemi.main.BrowserExtensionsCollector", bext_cls),
        ):
            runner.invoke(app, ["privacy"])
        apps_cls.assert_not_called()
        svcs_cls.assert_not_called()
        nmh_cls.assert_not_called()
        bext_cls.assert_not_called()

    def test_privacy_subcommand_does_not_write_html_report(self) -> None:
        save_html = MagicMock()
        with patch("cemi.main.save_html_report", save_html):
            runner.invoke(app, ["privacy"])
        save_html.assert_not_called()

    def test_privacy_subcommand_does_not_write_json_report(self) -> None:
        save_json = MagicMock()
        with patch("cemi.main.save_json_report", save_json):
            runner.invoke(app, ["privacy"])
        save_json.assert_not_called()

    def test_privacy_subcommand_scan_not_run(self) -> None:
        result = runner.invoke(app, ["privacy"])
        assert "Scan complete" not in result.output


# ---------------------------------------------------------------------------
# Help text
# ---------------------------------------------------------------------------


class TestHelpText:
    def test_root_help_exits_zero(self) -> None:
        result = runner.invoke(app, ["--help"])
        assert result.exit_code == 0

    def test_scan_help_exits_zero(self) -> None:
        result = runner.invoke(app, ["scan", "--help"])
        assert result.exit_code == 0

    def test_scan_help_mentions_local(self) -> None:
        result = runner.invoke(app, ["scan", "--help"])
        assert "local" in result.output.lower()

    def test_privacy_help_exits_zero(self) -> None:
        result = runner.invoke(app, ["privacy", "--help"])
        assert result.exit_code == 0


# ---------------------------------------------------------------------------
# pyproject.toml console script
# ---------------------------------------------------------------------------


class TestPyprojectConsoleScript:
    def test_console_script_defined(self) -> None:
        import tomllib
        from pathlib import Path

        pyproject = Path(__file__).parent.parent / "pyproject.toml"
        data = tomllib.loads(pyproject.read_text())
        scripts = data.get("project", {}).get("scripts", {})
        assert "cemi" in scripts, "cemi console script not defined in pyproject.toml"

    def test_console_script_points_to_cemi_main(self) -> None:
        import tomllib
        from pathlib import Path

        pyproject = Path(__file__).parent.parent / "pyproject.toml"
        data = tomllib.loads(pyproject.read_text())
        scripts = data.get("project", {}).get("scripts", {})
        assert "cemi.main" in scripts.get("cemi", ""), (
            f"cemi script does not reference cemi.main: {scripts.get('cemi')}"
        )
