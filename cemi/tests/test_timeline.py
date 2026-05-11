"""Tests for timeline utilities and history summaries."""
from __future__ import annotations

import json
import tempfile
from datetime import datetime, timedelta, timezone
from pathlib import Path

from cemi.models import MonitorSnapshot
from cemi.timeline import compare_first_to_latest, get_timeline_summary, load_history


def _make_snapshot(
    snapshot_id: str,
    scan_id: str,
    timestamp: datetime,
    risk_score: int,
    risk_level: str,
    finding_titles: list[str],
    finding_ids: list[str],
    collector_statuses: dict[str, bool],
) -> MonitorSnapshot:
    return MonitorSnapshot(
        snapshot_id=snapshot_id,
        scan_id=scan_id,
        timestamp=timestamp,
        risk_score=risk_score,
        risk_level=risk_level,
        finding_titles=finding_titles,
        finding_ids=finding_ids,
        collector_statuses=collector_statuses,
    )


class TestLoadHistory:
    def test_load_history_returns_empty_when_missing(self) -> None:
        with tempfile.TemporaryDirectory() as tmpdir:
            history_dir = Path(tmpdir) / ".cemi" / "history"
            snapshots = load_history(history_dir)
            assert snapshots == []

    def test_load_history_skips_invalid_files_and_sorts(self) -> None:
        with tempfile.TemporaryDirectory() as tmpdir:
            history_dir = Path(tmpdir) / ".cemi" / "history"
            history_dir.mkdir(parents=True, exist_ok=True)

            snapshot_a = _make_snapshot(
                "snap-a",
                "scan-a",
                datetime.now(tz=timezone.utc),
                10,
                "low",
                ["A"],
                ["A-1"],
                {"installed_apps": True},
            )
            snapshot_b = _make_snapshot(
                "snap-b",
                "scan-b",
                datetime.now(tz=timezone.utc) + timedelta(seconds=1),
                15,
                "low",
                ["B"],
                ["B-1"],
                {"installed_apps": True},
            )

            with open(history_dir / "snapshot_b.json", "w", encoding="utf-8") as fh:
                json.dump(snapshot_b.model_dump(), fh, default=str)
            with open(history_dir / "snapshot_invalid.json", "w", encoding="utf-8") as fh:
                fh.write("not valid json")
            with open(history_dir / "snapshot_a.json", "w", encoding="utf-8") as fh:
                json.dump(snapshot_a.model_dump(), fh, default=str)

            snapshots = load_history(history_dir)
            assert [snapshot.snapshot_id for snapshot in snapshots] == ["snap-a", "snap-b"]


class TestTimelineSummary:
    def test_compare_first_to_latest_reports_new_and_resolved_findings(self) -> None:
        first = _make_snapshot(
            "snap-1",
            "scan-1",
            datetime.now(tz=timezone.utc),
            12,
            "low",
            ["A", "B"],
            ["A-1", "B-1"],
            {"installed_apps": True},
        )
        latest = _make_snapshot(
            "snap-2",
            "scan-2",
            datetime.now(tz=timezone.utc) + timedelta(seconds=30),
            18,
            "medium",
            ["B", "C"],
            ["B-1", "C-1"],
            {"installed_apps": True},
        )

        diff = compare_first_to_latest([first, latest])
        assert diff.new_findings == [{"id": "C-1", "title": "C"}]
        assert diff.resolved_findings == [{"id": "A-1", "title": "A"}]
        assert diff.risk_score_delta == 6

    def test_get_timeline_summary_computes_counts_and_scores(self) -> None:
        first = _make_snapshot(
            "snap-1",
            "scan-1",
            datetime.now(tz=timezone.utc),
            10,
            "low",
            ["First"],
            ["F-1"],
            {"installed_apps": True},
        )
        latest = _make_snapshot(
            "snap-2",
            "scan-2",
            datetime.now(tz=timezone.utc) + timedelta(minutes=1),
            25,
            "medium",
            ["First", "Second"],
            ["F-1", "F-2"],
            {"installed_apps": True},
        )

        summary = get_timeline_summary([first, latest])
        assert summary.total_snapshots == 2
        assert summary.first_seen_at == first.timestamp
        assert summary.last_seen_at == latest.timestamp
        assert summary.latest_risk_score == 25
        assert summary.latest_risk_level == "medium"
        assert summary.highest_risk_score == 25
        assert summary.risk_score_delta == 15
        assert summary.new_findings_since_first == ["Second"]
        assert summary.resolved_findings_since_first == []
        assert summary.active_findings == ["First", "Second"]

    def test_get_timeline_summary_returns_empty_with_no_snapshots(self) -> None:
        summary = get_timeline_summary([])
        assert summary.total_snapshots == 0
        assert summary.first_seen_at is None
        assert summary.last_seen_at is None
        assert summary.latest_risk_score == 0
        assert summary.latest_risk_level == "none"
        assert summary.active_findings == []
