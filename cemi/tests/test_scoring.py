"""Tests for CEMÍ scoring modifiers and risk summary generation."""
from __future__ import annotations

from datetime import datetime, timezone
from uuid import uuid4

from cemi.models import Confidence, EvidenceItem, EvidenceType, Finding, RiskSummary, Severity
from cemi.scoring import calculate_risk_summary


def _make_finding(category: str, severity: Severity) -> Finding:
    return Finding(
        id="TST-001",
        instance_id=uuid4(),
        rule_version="1.0.0",
        title="Test Finding",
        severity=severity,
        confidence=Confidence.HIGH,
        app=None,
        category=category,
        official_explanation="Explanation.",
        in_other_words="Plain English.",
        why_this_matters="Matters.",
        evidence=[EvidenceItem(type=EvidenceType.METADATA, value="test", label="label")],
        recommended_action="Act.",
        safe_to_ignore_when=None,
        false_positive_risk="low",
        requires_admin_to_verify=False,
        created_at=datetime.now(tz=timezone.utc),
        scan_id="scan-test-001",
    )


def test_browser_extension_findings_weight_less_heavily() -> None:
    finding = _make_finding("Browser Extension", Severity.HIGH)
    summary = calculate_risk_summary([finding])
    assert summary.score == 12
    assert summary.level == "low"


def test_startup_persistence_findings_have_moderate_weight() -> None:
    finding = _make_finding("Persistence", Severity.HIGH)
    summary = calculate_risk_summary([finding])
    assert summary.score == 14
    assert summary.level == "low"


def test_correlation_findings_weight_more_heavily() -> None:
    finding = _make_finding("Correlation", Severity.MEDIUM)
    summary = calculate_risk_summary([finding])
    assert summary.score == 14
    assert summary.level == "low"


def test_unknown_category_uses_default_weight() -> None:
    finding = _make_finding("Unknown", Severity.MEDIUM)
    summary = calculate_risk_summary([finding])
    assert summary.score == 8
    assert summary.level == "low"
