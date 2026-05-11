"""Monitoring mode for CEMÍ.

Repeatedly runs scans and tracks changes over time. Stores only
summarized results to maintain privacy-first design. No raw evidence,
no collector items, no telemetry.

Snapshots are saved locally in .cemi/history/ for trend analysis.
"""
from __future__ import annotations

import json
import os
from datetime import datetime, timezone
from pathlib import Path
from typing import Any, Optional
from uuid import uuid4

from cemi.models import MonitorDiff, MonitorSnapshot, ScanResult


def get_history_dir() -> Path:
    """Return the local history directory, creating it if needed."""
    cwd = Path.cwd()
    history_dir = cwd / ".cemi" / "history"
    history_dir.mkdir(parents=True, exist_ok=True)
    return history_dir


def create_snapshot(scan_result: ScanResult) -> MonitorSnapshot:
    """Create a summary snapshot from a scan result.

    Extracts only essential metadata:
    - Risk score and level
    - Finding titles and IDs
    - Collector status (success/failure)

    Does NOT store:
    - Raw evidence values
    - Raw collector items
    - Raw paths or sensitive data
    """
    finding_titles = [f.title for f in scan_result.findings]
    finding_ids = [f.id for f in scan_result.findings]
    collector_statuses = {
        h.collector_name: h.ran_successfully
        for h in scan_result.collector_health
    }

    return MonitorSnapshot(
        snapshot_id=str(uuid4()),
        scan_id=scan_result.scan_id,
        timestamp=datetime.now(timezone.utc),
        risk_score=scan_result.risk_summary.score,
        risk_level=scan_result.risk_summary.level,
        finding_titles=finding_titles,
        finding_ids=finding_ids,
        collector_statuses=collector_statuses,
    )


def compute_diff(previous: MonitorSnapshot, current: MonitorSnapshot) -> MonitorDiff:
    """Compare two snapshots to detect changes.

    Returns:
    - new_findings: titles and IDs of findings in current but not previous
    - resolved_findings: titles and IDs of findings in previous but not current
    - risk_score_delta: change in risk score (current - previous)
    - collector_changes: collectors that changed status
    """
    # New findings: in current but not in previous
    new_finding_ids = set(current.finding_ids) - set(previous.finding_ids)
    new_finding_titles = [
        current.finding_titles[i]
        for i, fid in enumerate(current.finding_ids)
        if fid in new_finding_ids
    ]
    new_findings = [
        {"id": fid, "title": title}
        for fid, title in zip(
            [current.finding_ids[i] for i, _ in enumerate(current.finding_ids) if current.finding_ids[i] in new_finding_ids],
            new_finding_titles,
        )
    ]

    # Resolved findings: in previous but not in current
    resolved_finding_ids = set(previous.finding_ids) - set(current.finding_ids)
    resolved_finding_titles = [
        previous.finding_titles[i]
        for i, fid in enumerate(previous.finding_ids)
        if fid in resolved_finding_ids
    ]
    resolved_findings = [
        {"id": fid, "title": title}
        for fid, title in zip(
            [previous.finding_ids[i] for i, _ in enumerate(previous.finding_ids) if previous.finding_ids[i] in resolved_finding_ids],
            resolved_finding_titles,
        )
    ]

    # Risk score delta
    risk_score_delta = current.risk_score - previous.risk_score

    # Collector changes
    collector_changes: dict[str, dict[str, bool]] = {}
    all_collectors = set(previous.collector_statuses.keys()) | set(
        current.collector_statuses.keys()
    )
    for collector_name in all_collectors:
        prev_status = previous.collector_statuses.get(collector_name, False)
        curr_status = current.collector_statuses.get(collector_name, False)
        if prev_status != curr_status:
            collector_changes[collector_name] = {"old": prev_status, "new": curr_status}

    return MonitorDiff(
        new_findings=new_findings,
        resolved_findings=resolved_findings,
        risk_score_delta=risk_score_delta,
        collector_changes=collector_changes,
    )


def save_snapshot(snapshot: MonitorSnapshot) -> Path:
    """Save snapshot to local history directory.

    Returns the path where the snapshot was saved.
    """
    history_dir = get_history_dir()
    timestamp_str = snapshot.timestamp.strftime("%Y%m%d_%H%M%S")
    filename = f"snapshot_{timestamp_str}_{snapshot.snapshot_id[:8]}.json"
    filepath = history_dir / filename

    with open(filepath, "w", encoding="utf-8") as fh:
        json.dump(snapshot.model_dump(), fh, indent=2, default=str)

    return filepath


def load_snapshot(filename: str) -> Optional[MonitorSnapshot]:
    """Load a snapshot from history by filename.

    Returns None if file does not exist or is invalid.
    """
    history_dir = get_history_dir()
    filepath = history_dir / filename

    if not filepath.exists():
        return None

    try:
        with open(filepath, "r", encoding="utf-8") as fh:
            data = json.load(fh)
        return MonitorSnapshot(**data)
    except (json.JSONDecodeError, ValueError, TypeError):
        return None


def get_latest_snapshot() -> Optional[MonitorSnapshot]:
    """Return the most recent snapshot from history, or None if none exist."""
    history_dir = get_history_dir()
    if not history_dir.exists():
        return None

    snapshot_files = sorted(history_dir.glob("snapshot_*.json"), reverse=True)
    if not snapshot_files:
        return None

    return load_snapshot(snapshot_files[0].name)


def list_snapshots() -> list[tuple[str, MonitorSnapshot]]:
    """Return all snapshots in reverse chronological order (newest first).

    Returns list of (filename, snapshot) tuples.
    """
    history_dir = get_history_dir()
    if not history_dir.exists():
        return []

    snapshot_files = sorted(history_dir.glob("snapshot_*.json"), reverse=True)
    snapshots = []
    for filepath in snapshot_files:
        snapshot = load_snapshot(filepath.name)
        if snapshot:
            snapshots.append((filepath.name, snapshot))

    return snapshots


__all__ = [
    "create_snapshot",
    "compute_diff",
    "get_history_dir",
    "get_latest_snapshot",
    "list_snapshots",
    "load_snapshot",
    "save_snapshot",
]
