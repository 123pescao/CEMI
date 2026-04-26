"""Tests for cemi.scan_engine.ScanEngine."""
from __future__ import annotations

import socket
from unittest.mock import MagicMock

import pytest

from cemi.models import CollectorHealth, RiskSummary, ScanResult
from cemi.scan_engine import ScanEngine, _effective_privilege, _hash_hostname


# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------


def _make_health(
    name: str = "test_collector",
    items: int = 0,
    privilege: str = "user",
    ran_ok: bool = True,
) -> CollectorHealth:
    return CollectorHealth(
        collector_name=name,
        ran_successfully=ran_ok,
        privilege_level=privilege,  # type: ignore[arg-type]
        items_collected=items,
        duration_seconds=0.01,
    )


def _mock_collector(health: CollectorHealth) -> MagicMock:
    """Return a mock collector whose .run() returns ([], health)."""
    inst = MagicMock()
    inst.run.return_value = ([], health)
    return inst


# ---------------------------------------------------------------------------
# ScanEngine.run_scan — structure
# ---------------------------------------------------------------------------


class TestRunScanStructure:
    def test_returns_scan_result(self) -> None:
        result = ScanEngine([]).run_scan()
        assert isinstance(result, ScanResult)

    def test_scan_id_is_nonempty_string(self) -> None:
        result = ScanEngine([]).run_scan()
        assert isinstance(result.scan_id, str)
        assert len(result.scan_id) > 0

    def test_scan_id_is_unique_per_run(self) -> None:
        engine = ScanEngine([])
        r1 = engine.run_scan()
        r2 = engine.run_scan()
        assert r1.scan_id != r2.scan_id

    def test_started_at_not_after_completed_at(self) -> None:
        result = ScanEngine([]).run_scan()
        assert result.started_at <= result.completed_at

    def test_findings_is_empty(self) -> None:
        result = ScanEngine([]).run_scan()
        assert result.findings == []

    def test_scan_version_populated(self) -> None:
        result = ScanEngine([]).run_scan()
        assert result.scan_version  # non-empty


# ---------------------------------------------------------------------------
# Collector execution
# ---------------------------------------------------------------------------


class TestCollectorExecution:
    def test_single_collector_is_called(self) -> None:
        col = _mock_collector(_make_health("col"))
        ScanEngine([col]).run_scan()
        col.run.assert_called_once()

    def test_all_collectors_are_called(self) -> None:
        cols = [_mock_collector(_make_health(f"col{i}")) for i in range(4)]
        ScanEngine(cols).run_scan()
        for col in cols:
            col.run.assert_called_once()

    def test_collector_health_list_length_matches(self) -> None:
        cols = [_mock_collector(_make_health(f"col{i}")) for i in range(3)]
        result = ScanEngine(cols).run_scan()
        assert len(result.collector_health) == 3

    def test_collector_health_names_preserved(self) -> None:
        names = ["alpha", "beta", "gamma"]
        cols = [_mock_collector(_make_health(n)) for n in names]
        result = ScanEngine(cols).run_scan()
        found = [h.collector_name for h in result.collector_health]
        assert found == names

    def test_empty_collector_list_returns_empty_health(self) -> None:
        result = ScanEngine([]).run_scan()
        assert result.collector_health == []


# ---------------------------------------------------------------------------
# total_apps_scanned
# ---------------------------------------------------------------------------


class TestTotalAppsScanned:
    def test_total_apps_from_installed_apps_collector(self) -> None:
        apps_col = _mock_collector(_make_health("installed_apps", items=42))
        svcs_col = _mock_collector(_make_health("services", items=99))
        result = ScanEngine([apps_col, svcs_col]).run_scan()
        assert result.total_apps_scanned == 42

    def test_total_apps_zero_without_installed_apps_collector(self) -> None:
        svcs_col = _mock_collector(_make_health("services", items=10))
        result = ScanEngine([svcs_col]).run_scan()
        assert result.total_apps_scanned == 0

    def test_total_apps_zero_with_no_collectors(self) -> None:
        result = ScanEngine([]).run_scan()
        assert result.total_apps_scanned == 0

    def test_other_collector_items_not_counted_as_apps(self) -> None:
        col = _mock_collector(_make_health("services", items=500))
        result = ScanEngine([col]).run_scan()
        assert result.total_apps_scanned == 0


# ---------------------------------------------------------------------------
# privilege_level
# ---------------------------------------------------------------------------


class TestPrivilegeLevel:
    def test_all_user_yields_user(self) -> None:
        cols = [
            _mock_collector(_make_health("a", privilege="user")),
            _mock_collector(_make_health("b", privilege="user")),
        ]
        result = ScanEngine(cols).run_scan()
        assert result.privilege_level == "user"

    def test_any_partial_yields_partial(self) -> None:
        cols = [
            _mock_collector(_make_health("a", privilege="user")),
            _mock_collector(_make_health("b", privilege="partial")),
        ]
        result = ScanEngine(cols).run_scan()
        assert result.privilege_level == "partial"

    def test_no_collectors_yields_user(self) -> None:
        result = ScanEngine([]).run_scan()
        assert result.privilege_level == "user"

    def test_admin_privilege_propagated(self) -> None:
        cols = [
            _mock_collector(_make_health("a", privilege="user")),
            _mock_collector(_make_health("b", privilege="admin")),
        ]
        result = ScanEngine(cols).run_scan()
        assert result.privilege_level == "admin"


# ---------------------------------------------------------------------------
# hostname redaction
# ---------------------------------------------------------------------------


class TestHostnameRedaction:
    def test_hostname_redacted_is_64_char_hex(self) -> None:
        result = ScanEngine([]).run_scan()
        h = result.hostname_redacted
        assert len(h) == 64
        assert all(c in "0123456789abcdef" for c in h)

    def test_raw_hostname_not_present(self) -> None:
        raw = socket.gethostname()
        result = ScanEngine([]).run_scan()
        assert raw not in result.hostname_redacted

    def test_hostname_hash_is_deterministic(self) -> None:
        h1 = _hash_hostname()
        h2 = _hash_hostname()
        assert h1 == h2

    def test_different_hostnames_produce_different_hashes(self) -> None:
        import hashlib
        h1 = hashlib.sha256(b"host-a").hexdigest()
        h2 = hashlib.sha256(b"host-b").hexdigest()
        assert h1 != h2


# ---------------------------------------------------------------------------
# _effective_privilege unit tests
# ---------------------------------------------------------------------------


class TestEffectivePrivilege:
    def test_empty_list_returns_user(self) -> None:
        assert _effective_privilege([]) == "user"

    def test_all_user_returns_user(self) -> None:
        h = [_make_health(privilege="user"), _make_health(privilege="user")]
        assert _effective_privilege(h) == "user"

    def test_any_partial_returns_partial(self) -> None:
        h = [_make_health(privilege="user"), _make_health(privilege="partial")]
        assert _effective_privilege(h) == "partial"

    def test_any_admin_returns_admin(self) -> None:
        h = [_make_health(privilege="partial"), _make_health(privilege="admin")]
        assert _effective_privilege(h) == "admin"

    def test_admin_beats_partial(self) -> None:
        h = [_make_health(privilege="admin"), _make_health(privilege="partial")]
        assert _effective_privilege(h) == "admin"


# ---------------------------------------------------------------------------
# No exceptions thrown
# ---------------------------------------------------------------------------


class TestNoExceptions:
    def test_run_scan_no_exception_with_no_collectors(self) -> None:
        ScanEngine([]).run_scan()

    def test_run_scan_no_exception_with_real_collectors(self) -> None:
        from cemi.collectors.installed_apps import InstalledAppsCollector
        from cemi.collectors.services import ServicesCollector
        ScanEngine([InstalledAppsCollector(), ServicesCollector()]).run_scan()


# ---------------------------------------------------------------------------
# risk_summary population
# ---------------------------------------------------------------------------


class TestRiskSummaryPopulation:
    def test_risk_summary_present_on_result(self) -> None:
        result = ScanEngine([]).run_scan()
        assert isinstance(result.risk_summary, RiskSummary)

    def test_risk_summary_score_zero_with_no_findings(self) -> None:
        result = ScanEngine([]).run_scan()
        assert result.risk_summary.score == 0

    def test_risk_summary_level_none_with_no_findings(self) -> None:
        result = ScanEngine([]).run_scan()
        assert result.risk_summary.level == "none"

    def test_risk_summary_empty_counts_with_no_findings(self) -> None:
        result = ScanEngine([]).run_scan()
        assert result.risk_summary.finding_counts == {}

    def test_risk_summary_reflects_findings(self) -> None:
        from unittest.mock import MagicMock
        # ServiceUserPathRule fires on a user-path service → MEDIUM finding (score 15)
        svc = {
            "name": "EvilSvc",
            "binary_path": r"C:\Users\[REDACTED]\AppData\Local\evil.exe",
            "state": "running",
            "start_type": "auto",
            "username": "[REDACTED]",
        }
        health = CollectorHealth(
            collector_name="services",
            ran_successfully=True,
            privilege_level="user",
            items_collected=1,
            duration_seconds=0.01,
        )
        col = MagicMock()
        col.run.return_value = ([svc], health)
        result = ScanEngine([col]).run_scan()
        assert result.risk_summary.score > 0
        assert result.risk_summary.level != "none"

    def test_risk_summary_score_in_scan_result_serialization(self) -> None:
        result = ScanEngine([]).run_scan()
        data = result.model_dump()
        assert "risk_summary" in data
        assert "score" in data["risk_summary"]
        assert "level" in data["risk_summary"]
        assert "finding_counts" in data["risk_summary"]
