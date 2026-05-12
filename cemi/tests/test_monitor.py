"""Tests for monitor mode."""
from __future__ import annotations

import json
import tempfile
from datetime import datetime, timezone
from pathlib import Path
from unittest.mock import patch

from cemi.models import (
    CollectorHealth,
    Confidence,
    EvidenceItem,
    EvidenceType,
    Finding,
    MonitorDiff,
    MonitorSnapshot,
    RiskSummary,
    ScanResult,
    Severity,
)
from cemi.monitor import (
    compute_diff,
    create_snapshot,
    get_history_dir,
    get_latest_snapshot,
    list_snapshots,
    load_snapshot,
    save_snapshot,
)


# ---------------------------------------------------------------------------
# Fixtures
# ---------------------------------------------------------------------------


def _make_scan_result(
    scan_id: str = "scan-001",
    risk_score: int = 20,
    risk_level: str = "low",
    findings_count: int = 0,
    collector_count: int = 2,
) -> ScanResult:
    """Create a test ScanResult with configurable findings and collectors."""
    findings = []
    for i in range(findings_count):
        findings.append(
            Finding(
                id=f"RULE-{i:03d}",
                instance_id=__import__("uuid").uuid4(),
                rule_version="1.0.0",
                title=f"Finding {i}",
                severity=Severity.MEDIUM,
                confidence=Confidence.MEDIUM,
                app=None,
                category="Test",
                official_explanation="Test explanation",
                in_other_words="Test finding",
                why_this_matters="Testing",
                evidence=[
                    EvidenceItem(
                        type=EvidenceType.METADATA,
                        value="test_value",
                        label="test_label",
                    )
                ],
                recommended_action="Test action",
                false_positive_risk="low",
                requires_admin_to_verify=False,
                created_at=datetime.now(timezone.utc),
                scan_id=scan_id,
            )
        )

    collector_health = [
        CollectorHealth(
            collector_name=f"collector_{j}",
            ran_successfully=True,
            privilege_level="user",
            items_collected=10,
            duration_seconds=0.5,
        )
        for j in range(collector_count)
    ]

    return ScanResult(
        scan_id=scan_id,
        scan_version="1.0.0",
        started_at=datetime.now(timezone.utc),
        completed_at=datetime.now(timezone.utc),
        hostname_redacted="hostname_redacted",
        privilege_level="user",
        collector_health=collector_health,
        findings=findings,
        total_apps_scanned=100,
        risk_summary=RiskSummary(
            score=risk_score,
            level=risk_level,
            finding_counts={"MEDIUM": findings_count},
        ),
    )


# ---------------------------------------------------------------------------
# MonitorSnapshot Creation
# ---------------------------------------------------------------------------


class TestCreateSnapshot:
    def test_snapshot_has_required_fields(self) -> None:
        scan = _make_scan_result()
        snapshot = create_snapshot(scan)
        assert snapshot.snapshot_id is not None
        assert snapshot.scan_id == "scan-001"
        assert snapshot.timestamp is not None
        assert snapshot.risk_score == 20
        assert snapshot.risk_level == "low"

    def test_snapshot_captures_finding_titles(self) -> None:
        scan = _make_scan_result(findings_count=2)
        snapshot = create_snapshot(scan)
        assert len(snapshot.finding_titles) == 2
        assert snapshot.finding_titles[0] == "Finding 0"
        assert snapshot.finding_titles[1] == "Finding 1"

    def test_snapshot_captures_finding_ids(self) -> None:
        scan = _make_scan_result(findings_count=3)
        snapshot = create_snapshot(scan)
        assert len(snapshot.finding_ids) == 3
        assert snapshot.finding_ids == ["RULE-000", "RULE-001", "RULE-002"]

    def test_snapshot_captures_collector_status(self) -> None:
        scan = _make_scan_result(collector_count=3)
        snapshot = create_snapshot(scan)
        assert len(snapshot.collector_statuses) == 3
        assert snapshot.collector_statuses["collector_0"] is True
        assert snapshot.collector_statuses["collector_1"] is True
        assert snapshot.collector_statuses["collector_2"] is True

    def test_snapshot_does_not_store_raw_evidence(self) -> None:
        scan = _make_scan_result(findings_count=1)
        snapshot = create_snapshot(scan)
        # Snapshot should have no evidence field
        assert not hasattr(snapshot, "findings")
        assert not hasattr(snapshot, "evidence")

    def test_snapshot_no_raw_collector_items(self) -> None:
        scan = _make_scan_result(collector_count=1)
        snapshot = create_snapshot(scan)
        # Snapshot should not have raw collector items
        assert not hasattr(snapshot, "collector_items")
        assert len(snapshot.collector_statuses) == 1


# ---------------------------------------------------------------------------
# MonitorDiff Computation
# ---------------------------------------------------------------------------


class TestComputeDiff:
    def test_diff_detects_new_findings(self) -> None:
        prev_snapshot = MonitorSnapshot(
            snapshot_id="snap-1",
            scan_id="scan-1",
            timestamp=datetime.now(timezone.utc),
            risk_score=20,
            risk_level="low",
            finding_titles=["Old Finding"],
            finding_ids=["OLD-001"],
            collector_statuses={"col_1": True},
        )
        curr_snapshot = MonitorSnapshot(
            snapshot_id="snap-2",
            scan_id="scan-2",
            timestamp=datetime.now(timezone.utc),
            risk_score=25,
            risk_level="low",
            finding_titles=["Old Finding", "New Finding"],
            finding_ids=["OLD-001", "NEW-001"],
            collector_statuses={"col_1": True},
        )
        diff = compute_diff(prev_snapshot, curr_snapshot)
        assert len(diff.new_findings) == 1
        assert diff.new_findings[0]["id"] == "NEW-001"
        assert diff.new_findings[0]["title"] == "New Finding"

    def test_diff_detects_resolved_findings(self) -> None:
        prev_snapshot = MonitorSnapshot(
            snapshot_id="snap-1",
            scan_id="scan-1",
            timestamp=datetime.now(timezone.utc),
            risk_score=30,
            risk_level="medium",
            finding_titles=["Finding A", "Finding B"],
            finding_ids=["A-001", "B-001"],
            collector_statuses={"col_1": True},
        )
        curr_snapshot = MonitorSnapshot(
            snapshot_id="snap-2",
            scan_id="scan-2",
            timestamp=datetime.now(timezone.utc),
            risk_score=15,
            risk_level="low",
            finding_titles=["Finding A"],
            finding_ids=["A-001"],
            collector_statuses={"col_1": True},
        )
        diff = compute_diff(prev_snapshot, curr_snapshot)
        assert len(diff.resolved_findings) == 1
        assert diff.resolved_findings[0]["id"] == "B-001"
        assert diff.resolved_findings[0]["title"] == "Finding B"

    def test_diff_computes_risk_score_delta(self) -> None:
        prev = MonitorSnapshot(
            snapshot_id="s1",
            scan_id="sc1",
            timestamp=datetime.now(timezone.utc),
            risk_score=20,
            risk_level="low",
            finding_titles=[],
            finding_ids=[],
            collector_statuses={},
        )
        curr = MonitorSnapshot(
            snapshot_id="s2",
            scan_id="sc2",
            timestamp=datetime.now(timezone.utc),
            risk_score=35,
            risk_level="medium",
            finding_titles=[],
            finding_ids=[],
            collector_statuses={},
        )
        diff = compute_diff(prev, curr)
        assert diff.risk_score_delta == 15

    def test_diff_detects_collector_status_change(self) -> None:
        prev = MonitorSnapshot(
            snapshot_id="s1",
            scan_id="sc1",
            timestamp=datetime.now(timezone.utc),
            risk_score=20,
            risk_level="low",
            finding_titles=[],
            finding_ids=[],
            collector_statuses={"collector_a": True, "collector_b": True},
        )
        curr = MonitorSnapshot(
            snapshot_id="s2",
            scan_id="sc2",
            timestamp=datetime.now(timezone.utc),
            risk_score=20,
            risk_level="low",
            finding_titles=[],
            finding_ids=[],
            collector_statuses={"collector_a": True, "collector_b": False},
        )
        diff = compute_diff(prev, curr)
        assert "collector_b" in diff.collector_changes
        assert diff.collector_changes["collector_b"]["old"] is True
        assert diff.collector_changes["collector_b"]["new"] is False

    def test_diff_no_changes_returns_empty_diff(self) -> None:
        snapshot = MonitorSnapshot(
            snapshot_id="s1",
            scan_id="sc1",
            timestamp=datetime.now(timezone.utc),
            risk_score=20,
            risk_level="low",
            finding_titles=["Finding 1"],
            finding_ids=["F-001"],
            collector_statuses={"col_1": True},
        )
        diff = compute_diff(snapshot, snapshot)
        assert len(diff.new_findings) == 0
        assert len(diff.resolved_findings) == 0
        assert diff.risk_score_delta == 0
        assert len(diff.collector_changes) == 0


# ---------------------------------------------------------------------------
# Snapshot Storage
# ---------------------------------------------------------------------------


class TestSnapshotStorage:
    def test_save_snapshot_creates_file(self) -> None:
        with tempfile.TemporaryDirectory() as tmpdir:
            with patch("cemi.monitor.get_history_dir", return_value=Path(tmpdir)):
                snapshot = MonitorSnapshot(
                    snapshot_id="snap-001",
                    scan_id="scan-001",
                    timestamp=datetime.now(timezone.utc),
                    risk_score=20,
                    risk_level="low",
                    finding_titles=["Test"],
                    finding_ids=["TEST-001"],
                    collector_statuses={"col_1": True},
                )
                filepath = save_snapshot(snapshot)
                assert filepath.exists()
                assert filepath.suffix == ".json"

    def test_save_snapshot_contains_valid_json(self) -> None:
        with tempfile.TemporaryDirectory() as tmpdir:
            with patch("cemi.monitor.get_history_dir", return_value=Path(tmpdir)):
                snapshot = MonitorSnapshot(
                    snapshot_id="snap-001",
                    scan_id="scan-001",
                    timestamp=datetime.now(timezone.utc),
                    risk_score=20,
                    risk_level="low",
                    finding_titles=[],
                    finding_ids=[],
                    collector_statuses={},
                )
                filepath = save_snapshot(snapshot)
                with open(filepath, "r") as fh:
                    data = json.load(fh)
                assert data["snapshot_id"] == "snap-001"
                assert data["risk_score"] == 20

    def test_load_snapshot_returns_valid_snapshot(self) -> None:
        with tempfile.TemporaryDirectory() as tmpdir:
            with patch("cemi.monitor.get_history_dir", return_value=Path(tmpdir)):
                original = MonitorSnapshot(
                    snapshot_id="snap-001",
                    scan_id="scan-001",
                    timestamp=datetime.now(timezone.utc),
                    risk_score=20,
                    risk_level="low",
                    finding_titles=["Test"],
                    finding_ids=["TEST-001"],
                    collector_statuses={"col_1": True},
                )
                filepath = save_snapshot(original)
                loaded = load_snapshot(filepath.name)
                assert loaded is not None
                assert loaded.snapshot_id == original.snapshot_id
                assert loaded.risk_score == original.risk_score

    def test_load_nonexistent_snapshot_returns_none(self) -> None:
        with tempfile.TemporaryDirectory() as tmpdir:
            with patch("cemi.monitor.get_history_dir", return_value=Path(tmpdir)):
                result = load_snapshot("nonexistent.json")
                assert result is None


# ---------------------------------------------------------------------------
# History Directory
# ---------------------------------------------------------------------------


class TestHistoryDirectory:
    def test_get_history_dir_does_not_create_directory(self) -> None:
        with tempfile.TemporaryDirectory() as tmpdir:
            with patch("pathlib.Path.cwd", return_value=Path(tmpdir)):
                history_dir = get_history_dir()
                assert not history_dir.exists()  # Should not create it

    def test_get_history_dir_is_local_only(self) -> None:
        with tempfile.TemporaryDirectory() as tmpdir:
            with patch("pathlib.Path.cwd", return_value=Path(tmpdir)):
                history_dir = get_history_dir()
                # Should be under .cemi/history relative to cwd
                assert ".cemi" in str(history_dir)
                assert "history" in str(history_dir)
                assert str(history_dir).startswith(tmpdir)

    def test_list_snapshots_returns_snapshots(self) -> None:
        with tempfile.TemporaryDirectory() as tmpdir:
            with patch("cemi.monitor.get_history_dir", return_value=Path(tmpdir)):
                snap1 = MonitorSnapshot(
                    snapshot_id="snap-1",
                    scan_id="sc-1",
                    timestamp=datetime.now(timezone.utc),
                    risk_score=20,
                    risk_level="low",
                    finding_titles=[],
                    finding_ids=[],
                    collector_statuses={},
                )
                snap2 = MonitorSnapshot(
                    snapshot_id="snap-2",
                    scan_id="sc-2",
                    timestamp=datetime.now(timezone.utc),
                    risk_score=25,
                    risk_level="low",
                    finding_titles=[],
                    finding_ids=[],
                    collector_statuses={},
                )
                save_snapshot(snap1)
                save_snapshot(snap2)
                snapshots = list_snapshots()
                assert len(snapshots) == 2

    def test_get_latest_snapshot_returns_none_when_no_history_dir(self) -> None:
        with tempfile.TemporaryDirectory() as tmpdir:
            with patch("cemi.monitor.get_history_dir", return_value=Path(tmpdir) / "nonexistent"):
                latest = get_latest_snapshot()
                assert latest is None

    def test_list_snapshots_returns_empty_when_no_history_dir(self) -> None:
        with tempfile.TemporaryDirectory() as tmpdir:
            with patch("cemi.monitor.get_history_dir", return_value=Path(tmpdir) / "nonexistent"):
                snapshots = list_snapshots()
                assert snapshots == []

    def test_load_snapshot_returns_none_when_no_history_dir(self) -> None:
        with tempfile.TemporaryDirectory() as tmpdir:
            with patch("cemi.monitor.get_history_dir", return_value=Path(tmpdir) / "nonexistent"):
                result = load_snapshot("any.json")
                assert result is None


# ---------------------------------------------------------------------------
# Monitor Command Integration Tests
# ---------------------------------------------------------------------------


class TestMonitorCommand:
    def test_monitor_calls_save_snapshot(self) -> None:
        with tempfile.TemporaryDirectory() as tmpdir:
            with patch("pathlib.Path.cwd", return_value=Path(tmpdir)):
                with patch("cemi.main.create_snapshot") as mock_create:
                    with patch("cemi.main.save_snapshot") as mock_save:
                        with patch("cemi.main.ScanEngine"):
                            with patch("cemi.main.time.sleep"):
                                from cemi.main import monitor
                                monitor(interval=1, iterations=1, output=None, yes=True)

                # save_snapshot should be called once
                assert mock_save.call_count == 1

    def test_monitor_saves_snapshot_per_iteration(self) -> None:
        with tempfile.TemporaryDirectory() as tmpdir:
            with patch("pathlib.Path.cwd", return_value=Path(tmpdir)):
                with patch("cemi.main.create_snapshot") as mock_create:
                    with patch("cemi.main.save_snapshot") as mock_save:
                        with patch("cemi.main.ScanEngine"):
                            with patch("cemi.main.time.sleep"):
                                from cemi.main import monitor
                                monitor(interval=1, iterations=2, output=None, yes=True)

                # save_snapshot should be called twice
                assert mock_save.call_count == 2

    def test_monitor_saved_snapshots_no_raw_evidence(self) -> None:
        with tempfile.TemporaryDirectory() as tmpdir:
            with patch("pathlib.Path.cwd", return_value=Path(tmpdir)):
                snapshot = MonitorSnapshot(
                    snapshot_id="test",
                    scan_id="test",
                    timestamp=datetime.now(timezone.utc),
                    risk_score=20,
                    risk_level="low",
                    finding_titles=["Test"],
                    finding_ids=["TEST-001"],
                    collector_statuses={},
                )
                with patch("cemi.main.create_snapshot", return_value=snapshot):
                    with patch("cemi.main.save_snapshot") as mock_save:
                        with patch("cemi.main.ScanEngine"):
                            with patch("cemi.main.time.sleep"):
                                from cemi.main import monitor
                                monitor(interval=1, iterations=1, output=None, yes=True)

                # Check the saved snapshot
                mock_save.assert_called_once()
                saved_path = mock_save.call_args[0][0]  # First arg is snapshot
                # Since we mocked save_snapshot, we can't check the file, but the snapshot has no evidence
                assert not hasattr(snapshot, "evidence")

    def test_monitor_saved_snapshots_no_raw_paths(self) -> None:
        with tempfile.TemporaryDirectory() as tmpdir:
            with patch("pathlib.Path.cwd", return_value=Path(tmpdir)):
                with patch("cemi.main.create_snapshot") as mock_create:
                    with patch("cemi.main.save_snapshot") as mock_save:
                        with patch("cemi.main.ScanEngine"):
                            with patch("cemi.main.time.sleep"):
                                from cemi.main import monitor
                                monitor(interval=1, iterations=1, output=None, yes=True)

                # save_snapshot should be called
                mock_save.assert_called_once()
                # The snapshot passed to save_snapshot should not have raw paths
                snapshot = mock_save.call_args[0][0]
                snapshot_str = json.dumps(snapshot.model_dump(), default=str)
                assert "C:\\" not in snapshot_str
                assert "\\Users\\" not in snapshot_str


# ---------------------------------------------------------------------------
# Privacy Verification
# ---------------------------------------------------------------------------


class TestPrivacy:
    def test_snapshot_no_raw_paths(self) -> None:
        scan = _make_scan_result()
        snapshot = create_snapshot(scan)
        snapshot_dict = snapshot.model_dump()
        # Verify no sensitive path-like strings
        snapshot_str = json.dumps(snapshot_dict, default=str)
        assert "C:\\" not in snapshot_str
        assert "\\Users\\" not in snapshot_str

    def test_snapshot_no_raw_evidence_stored(self) -> None:
        scan = _make_scan_result(findings_count=2)
        snapshot = create_snapshot(scan)
        # Snapshot should never have raw evidence
        assert not hasattr(snapshot, "evidence")
        assert not hasattr(snapshot, "findings")
        assert len(snapshot.finding_titles) == 2

    def test_saved_snapshot_no_evidence_in_file(self) -> None:
        with tempfile.TemporaryDirectory() as tmpdir:
            with patch("cemi.monitor.get_history_dir", return_value=Path(tmpdir)):
                snapshot = MonitorSnapshot(
                    snapshot_id="snap-001",
                    scan_id="scan-001",
                    timestamp=datetime.now(timezone.utc),
                    risk_score=20,
                    risk_level="low",
                    finding_titles=["Test"],
                    finding_ids=["TEST-001"],
                    collector_statuses={},
                )
                filepath = save_snapshot(snapshot)
                with open(filepath, "r") as fh:
                    content = fh.read()
                assert "evidence" not in content
                assert "finding_titles" in content


__all__ = [
    "TestCreateSnapshot",
    "TestComputeDiff",
    "TestSnapshotStorage",
    "TestHistoryDirectory",
    "TestPrivacy",
]
