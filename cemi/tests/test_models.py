"""Tests for cemi.models."""
from __future__ import annotations

from datetime import datetime, timezone
from uuid import uuid4

import pytest
from pydantic import ValidationError

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


# --- enums --------------------------------------------------------------------


def test_severity_values() -> None:
    assert Severity.INFO.value == "INFO"
    assert Severity.LOW.value == "LOW"
    assert Severity.MEDIUM.value == "MEDIUM"
    assert Severity.HIGH.value == "HIGH"
    assert Severity.CRITICAL.value == "CRITICAL"


def test_confidence_values() -> None:
    assert {c.value for c in Confidence} == {"LOW", "MEDIUM", "HIGH"}


def test_evidence_type_values() -> None:
    assert {t.value for t in EvidenceType} == {
        "FILE_PATH",
        "REGISTRY_KEY",
        "PROCESS",
        "NETWORK_CONNECTION",
        "PERMISSION",
        "HASH",
        "SIGNATURE_STATUS",
        "METADATA",
    }


# --- EvidenceItem -------------------------------------------------------------


def test_evidence_item_creation() -> None:
    item = EvidenceItem(
        type=EvidenceType.FILE_PATH,
        value=r"C:\Users\[REDACTED]\file.txt",
        label="file path",
    )
    assert item.type is EvidenceType.FILE_PATH
    assert item.label == "file path"


def test_evidence_item_is_frozen() -> None:
    item = EvidenceItem(
        type=EvidenceType.FILE_PATH,
        value="x",
        label="y",
    )
    with pytest.raises(ValidationError):
        item.value = "changed"  # type: ignore[misc]


def test_evidence_item_forbids_extra_fields() -> None:
    with pytest.raises(ValidationError):
        EvidenceItem(  # type: ignore[call-arg]
            type=EvidenceType.FILE_PATH,
            value="x",
            label="y",
            extra_field="nope",
        )


# --- CollectorHealth ----------------------------------------------------------


def test_collector_health_defaults() -> None:
    health = CollectorHealth(
        collector_name="installed_apps",
        ran_successfully=True,
        privilege_level="user",
        items_collected=12,
        duration_seconds=0.42,
    )
    assert health.errors == []
    assert health.skipped_reason is None


def test_collector_health_rejects_bad_privilege_level() -> None:
    with pytest.raises(ValidationError):
        CollectorHealth(
            collector_name="x",
            ran_successfully=True,
            privilege_level="root",  # type: ignore[arg-type]
            items_collected=0,
            duration_seconds=0.0,
        )


def test_collector_health_is_frozen() -> None:
    health = CollectorHealth(
        collector_name="x",
        ran_successfully=True,
        privilege_level="user",
        items_collected=0,
        duration_seconds=0.0,
    )
    with pytest.raises(ValidationError):
        health.items_collected = 99  # type: ignore[misc]


# --- Finding ------------------------------------------------------------------


def _make_finding() -> Finding:
    return Finding(
        id="FND-0001",
        instance_id=uuid4(),
        rule_version="1.0.0",
        title="Example finding",
        severity=Severity.HIGH,
        confidence=Confidence.HIGH,
        app="ExampleApp",
        category="startup",
        official_explanation="An example explanation.",
        in_other_words="Plain language explanation.",
        why_this_matters="Why a user would care.",
        evidence=[
            EvidenceItem(
                type=EvidenceType.FILE_PATH,
                value=r"C:\Users\[REDACTED]\AppData\example",
                label="install path",
            )
        ],
        recommended_action="Review the app and remove if unneeded.",
        safe_to_ignore_when="This app is known to be required.",
        false_positive_risk="low",
        requires_admin_to_verify=False,
        created_at=datetime.now(tz=timezone.utc),
        scan_id="scan-abc",
    )


def test_finding_creation() -> None:
    finding = _make_finding()
    assert finding.severity is Severity.HIGH
    assert finding.confidence is Confidence.HIGH
    assert len(finding.evidence) == 1


def test_finding_is_frozen() -> None:
    finding = _make_finding()
    with pytest.raises(ValidationError):
        finding.title = "changed"  # type: ignore[misc]


# --- ScanResult ---------------------------------------------------------------


_EMPTY_RISK = RiskSummary(score=0, level="none", finding_counts={})


def test_scan_result_creation() -> None:
    now = datetime.now(tz=timezone.utc)
    result = ScanResult(
        scan_id="scan-abc",
        scan_version="0.1.0",
        started_at=now,
        completed_at=now,
        hostname_redacted="0" * 64,
        privilege_level="user",
        collector_health=[],
        findings=[],
        total_apps_scanned=0,
        risk_summary=_EMPTY_RISK,
    )
    assert result.scan_id == "scan-abc"
    assert result.total_apps_scanned == 0


def test_scan_result_is_frozen() -> None:
    now = datetime.now(tz=timezone.utc)
    result = ScanResult(
        scan_id="scan-abc",
        scan_version="0.1.0",
        started_at=now,
        completed_at=now,
        hostname_redacted="0" * 64,
        privilege_level="user",
        collector_health=[],
        findings=[],
        total_apps_scanned=0,
        risk_summary=_EMPTY_RISK,
    )
    with pytest.raises(ValidationError):
        result.total_apps_scanned = 5  # type: ignore[misc]


# --- RiskSummary --------------------------------------------------------------


def test_risk_summary_creation() -> None:
    rs = RiskSummary(score=30, level="medium", finding_counts={"HIGH": 1})
    assert rs.score == 30
    assert rs.level == "medium"
    assert rs.finding_counts == {"HIGH": 1}


def test_risk_summary_is_frozen() -> None:
    rs = RiskSummary(score=0, level="none", finding_counts={})
    with pytest.raises(ValidationError):
        rs.score = 99  # type: ignore[misc]


def test_risk_summary_forbids_extra_fields() -> None:
    with pytest.raises(ValidationError):
        RiskSummary(  # type: ignore[call-arg]
            score=0,
            level="none",
            finding_counts={},
            extra="bad",
        )


def test_risk_summary_empty_finding_counts() -> None:
    rs = RiskSummary(score=0, level="none", finding_counts={})
    assert rs.finding_counts == {}


def test_risk_summary_multiple_severity_counts() -> None:
    rs = RiskSummary(score=50, level="medium", finding_counts={"HIGH": 1, "MEDIUM": 2})
    assert rs.finding_counts["HIGH"] == 1
    assert rs.finding_counts["MEDIUM"] == 2
