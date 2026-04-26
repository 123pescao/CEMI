"""Tests for cemi.risk — deterministic risk scoring."""
from __future__ import annotations

from datetime import datetime, timezone
from typing import Any
from uuid import uuid4

import pytest

from cemi.models import (
    Confidence,
    EvidenceItem,
    EvidenceType,
    Finding,
    RiskSummary,
    Severity,
)
from cemi.risk import calculate_risk_summary


# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------

_SCAN_ID = "test-risk-scan-001"


def _finding(severity: Severity, title: str = "Test Finding") -> Finding:
    return Finding(
        id="TST-001",
        instance_id=uuid4(),
        rule_version="1.0.0",
        title=title,
        severity=severity,
        confidence=Confidence.HIGH,
        app=None,
        category="Test",
        official_explanation="Explanation.",
        in_other_words="Plain text.",
        why_this_matters="Matters.",
        evidence=[],
        recommended_action="Act.",
        safe_to_ignore_when=None,
        false_positive_risk="low",
        requires_admin_to_verify=False,
        created_at=datetime.now(tz=timezone.utc),
        scan_id=_SCAN_ID,
    )


# ---------------------------------------------------------------------------
# Return type
# ---------------------------------------------------------------------------


class TestReturnType:
    def test_returns_risk_summary_instance(self) -> None:
        result = calculate_risk_summary([])
        assert isinstance(result, RiskSummary)

    def test_result_is_frozen(self) -> None:
        from pydantic import ValidationError
        rs = calculate_risk_summary([])
        with pytest.raises(ValidationError):
            rs.score = 99  # type: ignore[misc]


# ---------------------------------------------------------------------------
# Empty findings
# ---------------------------------------------------------------------------


class TestEmptyFindings:
    def test_empty_score_is_zero(self) -> None:
        assert calculate_risk_summary([]).score == 0

    def test_empty_level_is_none(self) -> None:
        assert calculate_risk_summary([]).level == "none"

    def test_empty_finding_counts_is_empty_dict(self) -> None:
        assert calculate_risk_summary([]).finding_counts == {}


# ---------------------------------------------------------------------------
# Single-finding score and level
# ---------------------------------------------------------------------------


class TestSingleFindingScores:
    def test_info_score_is_zero(self) -> None:
        rs = calculate_risk_summary([_finding(Severity.INFO)])
        assert rs.score == 0

    def test_info_level_is_none(self) -> None:
        rs = calculate_risk_summary([_finding(Severity.INFO)])
        assert rs.level == "none"

    def test_low_score_is_five(self) -> None:
        rs = calculate_risk_summary([_finding(Severity.LOW)])
        assert rs.score == 5

    def test_low_level_is_low(self) -> None:
        rs = calculate_risk_summary([_finding(Severity.LOW)])
        assert rs.level == "low"

    def test_medium_score_is_fifteen(self) -> None:
        rs = calculate_risk_summary([_finding(Severity.MEDIUM)])
        assert rs.score == 15

    def test_medium_level_is_low(self) -> None:
        # 15 falls in the 1-20 bracket → "low"
        rs = calculate_risk_summary([_finding(Severity.MEDIUM)])
        assert rs.level == "low"

    def test_high_score_is_thirty(self) -> None:
        rs = calculate_risk_summary([_finding(Severity.HIGH)])
        assert rs.score == 30

    def test_high_level_is_medium(self) -> None:
        # 30 falls in the 21-50 bracket → "medium"
        rs = calculate_risk_summary([_finding(Severity.HIGH)])
        assert rs.level == "medium"

    def test_critical_score_is_fifty(self) -> None:
        rs = calculate_risk_summary([_finding(Severity.CRITICAL)])
        assert rs.score == 50

    def test_critical_level_is_medium(self) -> None:
        # 50 falls in the 21-50 bracket → "medium"
        rs = calculate_risk_summary([_finding(Severity.CRITICAL)])
        assert rs.level == "medium"


# ---------------------------------------------------------------------------
# Multi-finding summation
# ---------------------------------------------------------------------------


class TestMultipleFindingSums:
    def test_two_low_findings_sum_to_ten(self) -> None:
        findings = [_finding(Severity.LOW), _finding(Severity.LOW)]
        assert calculate_risk_summary(findings).score == 10

    def test_low_plus_medium_is_twenty(self) -> None:
        findings = [_finding(Severity.LOW), _finding(Severity.MEDIUM)]
        assert calculate_risk_summary(findings).score == 20

    def test_medium_plus_high_is_forty_five(self) -> None:
        findings = [_finding(Severity.MEDIUM), _finding(Severity.HIGH)]
        assert calculate_risk_summary(findings).score == 45

    def test_two_high_findings_sum_to_sixty(self) -> None:
        findings = [_finding(Severity.HIGH), _finding(Severity.HIGH)]
        assert calculate_risk_summary(findings).score == 60

    def test_two_high_level_is_high(self) -> None:
        # 60 in 51-80 bracket → "high"
        findings = [_finding(Severity.HIGH), _finding(Severity.HIGH)]
        assert calculate_risk_summary(findings).level == "high"

    def test_three_high_findings_is_ninety(self) -> None:
        findings = [_finding(Severity.HIGH)] * 3
        assert calculate_risk_summary(findings).score == 90

    def test_three_high_level_is_critical(self) -> None:
        # 90 in 81-100 bracket → "critical"
        findings = [_finding(Severity.HIGH)] * 3
        assert calculate_risk_summary(findings).level == "critical"

    def test_mixed_severities_sum_correctly(self) -> None:
        # LOW(5) + MEDIUM(15) + HIGH(30) + CRITICAL(50) = 100
        findings = [
            _finding(Severity.LOW),
            _finding(Severity.MEDIUM),
            _finding(Severity.HIGH),
            _finding(Severity.CRITICAL),
        ]
        assert calculate_risk_summary(findings).score == 100


# ---------------------------------------------------------------------------
# Score cap at 100
# ---------------------------------------------------------------------------


class TestScoreCap:
    def test_two_criticals_cap_at_one_hundred(self) -> None:
        findings = [_finding(Severity.CRITICAL), _finding(Severity.CRITICAL)]
        assert calculate_risk_summary(findings).score == 100

    def test_many_highs_cap_at_one_hundred(self) -> None:
        findings = [_finding(Severity.HIGH)] * 10
        assert calculate_risk_summary(findings).score == 100

    def test_score_never_exceeds_one_hundred(self) -> None:
        findings = [_finding(Severity.CRITICAL)] * 5
        assert calculate_risk_summary(findings).score <= 100

    def test_capped_level_is_critical(self) -> None:
        findings = [_finding(Severity.CRITICAL)] * 5
        assert calculate_risk_summary(findings).level == "critical"


# ---------------------------------------------------------------------------
# Finding counts
# ---------------------------------------------------------------------------


class TestFindingCounts:
    def test_single_medium_count(self) -> None:
        rs = calculate_risk_summary([_finding(Severity.MEDIUM)])
        assert rs.finding_counts == {"MEDIUM": 1}

    def test_two_medium_count(self) -> None:
        rs = calculate_risk_summary([_finding(Severity.MEDIUM), _finding(Severity.MEDIUM)])
        assert rs.finding_counts == {"MEDIUM": 2}

    def test_mixed_counts(self) -> None:
        findings = [
            _finding(Severity.HIGH),
            _finding(Severity.HIGH),
            _finding(Severity.MEDIUM),
            _finding(Severity.LOW),
        ]
        rs = calculate_risk_summary(findings)
        assert rs.finding_counts["HIGH"] == 2
        assert rs.finding_counts["MEDIUM"] == 1
        assert rs.finding_counts["LOW"] == 1

    def test_info_counted_separately(self) -> None:
        findings = [_finding(Severity.INFO), _finding(Severity.LOW)]
        rs = calculate_risk_summary(findings)
        assert rs.finding_counts.get("INFO") == 1
        assert rs.finding_counts.get("LOW") == 1

    def test_absent_severity_not_in_counts(self) -> None:
        rs = calculate_risk_summary([_finding(Severity.HIGH)])
        assert "MEDIUM" not in rs.finding_counts
        assert "LOW" not in rs.finding_counts
        assert "CRITICAL" not in rs.finding_counts

    def test_empty_findings_empty_counts(self) -> None:
        assert calculate_risk_summary([]).finding_counts == {}


# ---------------------------------------------------------------------------
# Level boundary values
# ---------------------------------------------------------------------------


class TestLevelBoundaries:
    """Verify every bracket edge deterministically."""

    def _score_level(self, score: int) -> str:
        """Drive calculate_risk_summary with exactly the right number of LOW (5pt) findings."""
        # Use only LOW findings — 1 LOW = 5pts.
        count = score // 5
        remainder = score % 5
        findings: list[Finding] = [_finding(Severity.LOW)] * count
        # Add INFO findings to hit exact odd scores (INFO = 0pts, won't raise score).
        # Instead construct a synthetic single-HIGH if we need a non-multiple-of-5.
        # For boundary testing we'll only hit exact multiples of 5 or use MEDIUM.
        # Actually the simplest approach: construct the risk summary directly.
        from cemi.risk import _score_to_level  # type: ignore[attr-defined]
        return _score_to_level(score)

    def test_score_zero_is_none(self) -> None:
        from cemi.risk import _score_to_level  # type: ignore[attr-defined]
        assert _score_to_level(0) == "none"

    def test_score_one_is_low(self) -> None:
        from cemi.risk import _score_to_level  # type: ignore[attr-defined]
        assert _score_to_level(1) == "low"

    def test_score_twenty_is_low(self) -> None:
        from cemi.risk import _score_to_level  # type: ignore[attr-defined]
        assert _score_to_level(20) == "low"

    def test_score_twenty_one_is_medium(self) -> None:
        from cemi.risk import _score_to_level  # type: ignore[attr-defined]
        assert _score_to_level(21) == "medium"

    def test_score_fifty_is_medium(self) -> None:
        from cemi.risk import _score_to_level  # type: ignore[attr-defined]
        assert _score_to_level(50) == "medium"

    def test_score_fifty_one_is_high(self) -> None:
        from cemi.risk import _score_to_level  # type: ignore[attr-defined]
        assert _score_to_level(51) == "high"

    def test_score_eighty_is_high(self) -> None:
        from cemi.risk import _score_to_level  # type: ignore[attr-defined]
        assert _score_to_level(80) == "high"

    def test_score_eighty_one_is_critical(self) -> None:
        from cemi.risk import _score_to_level  # type: ignore[attr-defined]
        assert _score_to_level(81) == "critical"

    def test_score_one_hundred_is_critical(self) -> None:
        from cemi.risk import _score_to_level  # type: ignore[attr-defined]
        assert _score_to_level(100) == "critical"

    def test_full_range_via_calculate(self) -> None:
        # 4×HIGH(30) = 120 → capped to 100 → "critical"
        findings = [_finding(Severity.HIGH)] * 4
        rs = calculate_risk_summary(findings)
        assert rs.score == 100
        assert rs.level == "critical"


# ---------------------------------------------------------------------------
# Determinism
# ---------------------------------------------------------------------------


class TestDeterminism:
    def test_same_findings_same_score_twice(self) -> None:
        findings = [_finding(Severity.HIGH), _finding(Severity.MEDIUM)]
        r1 = calculate_risk_summary(findings)
        r2 = calculate_risk_summary(findings)
        assert r1.score == r2.score
        assert r1.level == r2.level
        assert r1.finding_counts == r2.finding_counts

    def test_order_does_not_affect_score(self) -> None:
        f1 = [_finding(Severity.HIGH), _finding(Severity.LOW)]
        f2 = [_finding(Severity.LOW), _finding(Severity.HIGH)]
        assert calculate_risk_summary(f1).score == calculate_risk_summary(f2).score

    def test_order_does_not_affect_counts(self) -> None:
        f1 = [_finding(Severity.HIGH), _finding(Severity.LOW)]
        f2 = [_finding(Severity.LOW), _finding(Severity.HIGH)]
        assert calculate_risk_summary(f1).finding_counts == calculate_risk_summary(f2).finding_counts
