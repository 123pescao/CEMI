"""Timeline utilities for local monitor history."""
from __future__ import annotations

import json
from dataclasses import dataclass
from datetime import datetime
from pathlib import Path
from typing import Optional

from cemi.monitor import compute_diff
from cemi.models import MonitorDiff, MonitorSnapshot


@dataclass(frozen=True)
class TimelineSummary:
    total_snapshots: int
    first_seen_at: Optional[datetime]
    last_seen_at: Optional[datetime]
    latest_risk_score: int
    latest_risk_level: str
    highest_risk_score: int
    risk_score_delta: int
    new_findings_since_first: list[str]
    resolved_findings_since_first: list[str]
    active_findings: list[str]


def load_history(history_dir: Optional[Path] = None) -> list[MonitorSnapshot]:
    if history_dir is None:
        history_dir = Path.cwd() / ".cemi" / "history"

    if not history_dir.exists() or not history_dir.is_dir():
        return []

    snapshots: list[MonitorSnapshot] = []
    for filepath in sorted(history_dir.glob("snapshot_*.json")):
        try:
            with filepath.open("r", encoding="utf-8") as fh:
                data = json.load(fh)
            snapshot = MonitorSnapshot(**data)
            snapshots.append(snapshot)
        except (json.JSONDecodeError, ValueError, TypeError):
            continue

    snapshots.sort(key=lambda snapshot: snapshot.timestamp)
    return snapshots


def compare_first_to_latest(snapshots: list[MonitorSnapshot]) -> MonitorDiff:
    if not snapshots:
        return MonitorDiff(new_findings=[], resolved_findings=[], risk_score_delta=0, collector_changes={})

    first_snapshot = snapshots[0]
    latest_snapshot = snapshots[-1]
    return compute_diff(first_snapshot, latest_snapshot)


def get_timeline_summary(snapshots: list[MonitorSnapshot]) -> TimelineSummary:
    if not snapshots:
        return TimelineSummary(
            total_snapshots=0,
            first_seen_at=None,
            last_seen_at=None,
            latest_risk_score=0,
            latest_risk_level="none",
            highest_risk_score=0,
            risk_score_delta=0,
            new_findings_since_first=[],
            resolved_findings_since_first=[],
            active_findings=[],
        )

    first_snapshot = snapshots[0]
    latest_snapshot = snapshots[-1]
    diff = compare_first_to_latest(snapshots)
    highest_risk_score = max(snapshot.risk_score for snapshot in snapshots)

    return TimelineSummary(
        total_snapshots=len(snapshots),
        first_seen_at=first_snapshot.timestamp,
        last_seen_at=latest_snapshot.timestamp,
        latest_risk_score=latest_snapshot.risk_score,
        latest_risk_level=latest_snapshot.risk_level,
        highest_risk_score=highest_risk_score,
        risk_score_delta=diff.risk_score_delta,
        new_findings_since_first=[item["title"] for item in diff.new_findings],
        resolved_findings_since_first=[item["title"] for item in diff.resolved_findings],
        active_findings=latest_snapshot.finding_titles,
    )
