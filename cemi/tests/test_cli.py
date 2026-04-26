"""Tests for cemi.main CLI."""
from __future__ import annotations

from contextlib import contextmanager
from unittest.mock import MagicMock, patch

from typer.testing import CliRunner

from pathlib import Path

from cemi.main import app
from cemi.models import CollectorHealth, ScanResult

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
            result = runner.invoke(app, ["--output", "html", "--yes"])
        assert result.exit_code == 0

    def test_output_json_accepted(self) -> None:
        with _patch_both():
            result = runner.invoke(app, ["--output", "json", "--yes"])
        assert result.exit_code == 0

    def test_output_text_rejected(self) -> None:
        result = runner.invoke(app, ["--output", "text", "--yes"])
        assert result.exit_code != 0


# ---------------------------------------------------------------------------
# Installed-apps collector summary
# ---------------------------------------------------------------------------


class TestInstalledAppsSummary:
    def test_scan_complete_in_output(self) -> None:
        with _patch_both():
            result = runner.invoke(app, ["--yes"])
        assert result.exit_code == 0
        assert "Scan complete" in result.output

    def test_installed_apps_count_label_present(self) -> None:
        with _patch_both():
            result = runner.invoke(app, ["--yes"])
        assert "Installed apps found:" in result.output

    def test_installed_apps_collector_name_present(self) -> None:
        with _patch_both():
            result = runner.invoke(app, ["--yes"])
        assert "installed_apps" in result.output

    def test_shows_correct_app_count(self) -> None:
        with _patch_both(apps_health=_make_health(collector_name="installed_apps", items_collected=17)):
            result = runner.invoke(app, ["--yes"])
        assert "17" in result.output

    def test_shows_ok_for_apps(self) -> None:
        with _patch_both(apps_health=_make_health(collector_name="installed_apps", ran_successfully=True)):
            result = runner.invoke(app, ["--yes"])
        assert "OK" in result.output

    def test_shows_failed_for_apps(self) -> None:
        with _patch_both(apps_health=_make_health(collector_name="installed_apps", ran_successfully=False)):
            result = runner.invoke(app, ["--yes"])
        assert "FAILED" in result.output

    def test_shows_skipped_for_apps(self) -> None:
        with _patch_both(
            apps_health=_make_health(
                collector_name="installed_apps",
                skipped_reason="winreg not available (non-Windows platform)",
            )
        ):
            result = runner.invoke(app, ["--yes"])
        assert "SKIPPED" in result.output
        assert "winreg not available" in result.output

    def test_shows_apps_errors(self) -> None:
        with _patch_both(
            apps_health=_make_health(
                collector_name="installed_apps",
                errors=["PermissionError: access denied to registry key"],
            )
        ):
            result = runner.invoke(app, ["--yes"])
        assert "PermissionError" in result.output

    def test_no_errors_section_when_apps_clean(self) -> None:
        with _patch_both(
            apps_health=_make_health(collector_name="installed_apps", errors=[]),
            svcs_health=_make_health(collector_name="services", errors=[]),
        ):
            result = runner.invoke(app, ["--yes"])
        assert "Errors:" not in result.output


# ---------------------------------------------------------------------------
# Services collector summary
# ---------------------------------------------------------------------------


class TestServicesSummary:
    def test_services_count_label_present(self) -> None:
        with _patch_both():
            result = runner.invoke(app, ["--yes"])
        assert "Services found:" in result.output

    def test_services_collector_name_present(self) -> None:
        with _patch_both():
            result = runner.invoke(app, ["--yes"])
        assert "services" in result.output

    def test_shows_correct_service_count(self) -> None:
        with _patch_both(svcs_health=_make_health(collector_name="services", items_collected=42)):
            result = runner.invoke(app, ["--yes"])
        assert "42" in result.output

    def test_shows_ok_for_services(self) -> None:
        with _patch_both(svcs_health=_make_health(collector_name="services", ran_successfully=True)):
            result = runner.invoke(app, ["--yes"])
        assert "OK" in result.output

    def test_shows_failed_for_services(self) -> None:
        with _patch_both(svcs_health=_make_health(collector_name="services", ran_successfully=False)):
            result = runner.invoke(app, ["--yes"])
        assert "FAILED" in result.output

    def test_shows_skipped_for_services(self) -> None:
        with _patch_both(
            svcs_health=_make_health(
                collector_name="services",
                skipped_reason="Windows services not available on this platform",
            )
        ):
            result = runner.invoke(app, ["--yes"])
        assert "SKIPPED" in result.output
        assert "Windows services not available" in result.output

    def test_shows_services_errors(self) -> None:
        with _patch_both(
            svcs_health=_make_health(
                collector_name="services",
                errors=["OSError: failed to iterate services"],
            )
        ):
            result = runner.invoke(app, ["--yes"])
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
            result = runner.invoke(app, ["--yes"])
        assert "5" in result.output
        assert "10" in result.output

    def test_both_collector_names_in_output(self) -> None:
        with _patch_both():
            result = runner.invoke(app, ["--yes"])
        assert "installed_apps" in result.output
        assert "services" in result.output

    def test_exit_code_zero_when_both_succeed(self) -> None:
        with _patch_both(
            apps_health=_make_health(collector_name="installed_apps", ran_successfully=True),
            svcs_health=_make_health(collector_name="services", ran_successfully=True),
        ):
            result = runner.invoke(app, ["--yes"])
        assert result.exit_code == 0

    def test_exit_code_zero_even_when_both_fail(self) -> None:
        # CLI reports failures but exits cleanly — the user decides next steps.
        with _patch_both(
            apps_health=_make_health(collector_name="installed_apps", ran_successfully=False),
            svcs_health=_make_health(collector_name="services", ran_successfully=False),
        ):
            result = runner.invoke(app, ["--yes"])
        assert result.exit_code == 0

    def test_real_collectors_do_not_crash(self) -> None:
        # Exercises the real collectors end-to-end; on Linux both skip gracefully.
        result = runner.invoke(app, ["--yes"])
        assert result.exit_code == 0
        assert "Scan complete" in result.output


# ---------------------------------------------------------------------------
# Privacy confirmation flow
# ---------------------------------------------------------------------------


class TestPrivacyConfirmation:
    def test_yes_flag_skips_prompt(self) -> None:
        with _patch_both():
            result = runner.invoke(app, ["--yes"])
        assert result.exit_code == 0
        assert "Scan complete" in result.output

    def test_confirming_y_proceeds(self) -> None:
        with _patch_both():
            result = runner.invoke(app, [], input="y\n")
        assert "Scan complete" in result.output

    def test_declining_n_aborts(self) -> None:
        result = runner.invoke(app, [], input="n\n")
        assert result.exit_code != 0
        assert "Scan complete" not in result.output

    def test_default_empty_input_aborts(self) -> None:
        result = runner.invoke(app, [], input="\n")
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
            result = runner.invoke(app, ["--yes"])
        assert result.exit_code == 0
        assert "Findings" in result.output

    def test_no_findings_message_when_empty(self) -> None:
        with _patch_both():
            result = runner.invoke(app, ["--yes"])
        assert "No findings detected." in result.output

    def test_severity_displayed(self) -> None:
        with _patch_with_finding():
            result = runner.invoke(app, ["--yes"])
        assert "MEDIUM" in result.output

    def test_official_explanation_included(self) -> None:
        with _patch_with_finding():
            result = runner.invoke(app, ["--yes"])
        assert "Official Explanation" in result.output

    def test_official_explanation_text_present(self) -> None:
        with _patch_with_finding():
            result = runner.invoke(app, ["--yes"])
        # The hardcoded explanation mentions user profile directory.
        assert "user profile" in result.output.lower()

    def test_in_other_words_section_included(self) -> None:
        with _patch_with_finding():
            result = runner.invoke(app, ["--yes"])
        assert "In Other Words" in result.output

    def test_why_this_matters_section_included(self) -> None:
        with _patch_with_finding():
            result = runner.invoke(app, ["--yes"])
        assert "Why This Matters" in result.output

    def test_recommended_action_section_included(self) -> None:
        with _patch_with_finding():
            result = runner.invoke(app, ["--yes"])
        assert "Recommended Action" in result.output

    def test_finding_title_present(self) -> None:
        with _patch_with_finding():
            result = runner.invoke(app, ["--yes"])
        assert "Service binary in user profile directory" in result.output

    def test_finding_app_name_present(self) -> None:
        with _patch_with_finding():
            result = runner.invoke(app, ["--yes"])
        assert "EvilSvc" in result.output

    def test_evidence_summarized_not_raw_path(self) -> None:
        with _patch_with_finding():
            result = runner.invoke(app, ["--yes"])
        # Evidence is summarised; the raw path string must not appear verbatim.
        assert r"C:\Users\[REDACTED]\AppData\Local\evil.exe" not in result.output
        assert "supporting item" in result.output

    def test_no_findings_message_absent_when_findings_present(self) -> None:
        with _patch_with_finding():
            result = runner.invoke(app, ["--yes"])
        assert "No findings detected." not in result.output

    def test_exit_code_zero_with_findings(self) -> None:
        with _patch_with_finding():
            result = runner.invoke(app, ["--yes"])
        assert result.exit_code == 0


# ---------------------------------------------------------------------------
# Native messaging hosts collector — CLI summary
# ---------------------------------------------------------------------------


class TestNativeMessagingHostsSummary:
    def test_collector_name_in_output(self) -> None:
        with _patch_both():
            result = runner.invoke(app, ["--yes"])
        assert "native_messaging_hosts" in result.output

    def test_ok_status_when_ran_successfully(self) -> None:
        with _patch_both(nmh_health=_make_health(collector_name="native_messaging_hosts", ran_successfully=True)):
            result = runner.invoke(app, ["--yes"])
        assert "OK" in result.output

    def test_failed_status_when_not_successful(self) -> None:
        with _patch_both(nmh_health=_make_health(collector_name="native_messaging_hosts", ran_successfully=False)):
            result = runner.invoke(app, ["--yes"])
        assert "FAILED" in result.output

    def test_skipped_status_when_skipped(self) -> None:
        with _patch_both(
            nmh_health=_make_health(
                collector_name="native_messaging_hosts",
                skipped_reason="Native messaging host directories are Windows-only in this version",
            )
        ):
            result = runner.invoke(app, ["--yes"])
        assert "SKIPPED" in result.output
        assert "Windows-only" in result.output

    def test_errors_shown_when_present(self) -> None:
        with _patch_both(
            nmh_health=_make_health(
                collector_name="native_messaging_hosts",
                errors=["OSError: cannot scan directory"],
            )
        ):
            result = runner.invoke(app, ["--yes"])
        assert "OSError" in result.output

    def test_exit_code_zero_with_nmh_collector(self) -> None:
        with _patch_both():
            result = runner.invoke(app, ["--yes"])
        assert result.exit_code == 0

    def test_real_collectors_do_not_crash_with_nmh(self) -> None:
        result = runner.invoke(app, ["--yes"])
        assert result.exit_code == 0
        assert "native_messaging_hosts" in result.output


# ---------------------------------------------------------------------------
# Privacy flag
# ---------------------------------------------------------------------------


class TestPrivacyFlag:
    def test_exit_code_zero(self) -> None:
        result = runner.invoke(app, ["--privacy"])
        assert result.exit_code == 0

    def test_privacy_guarantees_in_output(self) -> None:
        result = runner.invoke(app, ["--privacy"])
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
            runner.invoke(app, ["--privacy"])
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
            runner.invoke(app, ["--privacy"])
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
            runner.invoke(app, ["--privacy"])
        save_json.assert_not_called()

    def test_scan_does_not_run(self) -> None:
        result = runner.invoke(app, ["--privacy"])
        assert "Scan complete" not in result.output


# ---------------------------------------------------------------------------
# Browser extensions collector — CLI summary
# ---------------------------------------------------------------------------


class TestBrowserExtensionsSummary:
    def test_collector_name_in_output(self) -> None:
        with _patch_both():
            result = runner.invoke(app, ["--yes"])
        assert "browser_extensions" in result.output

    def test_browser_extensions_count_label_present(self) -> None:
        with _patch_both():
            result = runner.invoke(app, ["--yes"])
        assert "Browser extensions found:" in result.output

    def test_shows_correct_extension_count(self) -> None:
        with _patch_both(bext_health=_make_health(collector_name="browser_extensions", items_collected=7)):
            result = runner.invoke(app, ["--yes"])
        assert "7" in result.output

    def test_ok_status_when_ran_successfully(self) -> None:
        with _patch_both(bext_health=_make_health(collector_name="browser_extensions", ran_successfully=True)):
            result = runner.invoke(app, ["--yes"])
        assert "OK" in result.output

    def test_failed_status_when_not_successful(self) -> None:
        with _patch_both(bext_health=_make_health(collector_name="browser_extensions", ran_successfully=False)):
            result = runner.invoke(app, ["--yes"])
        assert "FAILED" in result.output

    def test_skipped_status_when_skipped(self) -> None:
        with _patch_both(
            bext_health=_make_health(
                collector_name="browser_extensions",
                skipped_reason="Browser extension directories are Windows-only in this version",
            )
        ):
            result = runner.invoke(app, ["--yes"])
        assert "SKIPPED" in result.output
        assert "Windows-only" in result.output

    def test_errors_shown_when_present(self) -> None:
        with _patch_both(
            bext_health=_make_health(
                collector_name="browser_extensions",
                errors=["OSError: cannot scan extensions directory"],
            )
        ):
            result = runner.invoke(app, ["--yes"])
        assert "OSError" in result.output

    def test_exit_code_zero_with_bext_collector(self) -> None:
        with _patch_both():
            result = runner.invoke(app, ["--yes"])
        assert result.exit_code == 0

    def test_real_collectors_do_not_crash_with_bext(self) -> None:
        result = runner.invoke(app, ["--yes"])
        assert result.exit_code == 0
        assert "browser_extensions" in result.output
