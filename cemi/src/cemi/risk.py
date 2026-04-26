"""Deterministic risk scoring for CEMÍ scan results.

:func:`calculate_risk_summary` converts a list of :class:`~cemi.models.Finding`
objects into a :class:`~cemi.models.RiskSummary` by assigning a fixed point
value to each severity level, summing the values, and capping at 100.

No AI, no heuristics, no network, no I/O.  The mapping is intentionally
simple so users can reproduce it mentally.

Severity point values
---------------------
CRITICAL  50
HIGH      30
MEDIUM    15
LOW        5
INFO       0

Risk levels (score brackets)
-----------------------------
0          → none
1  – 20    → low
21 – 50    → medium
51 – 80    → high
81 – 100   → critical
"""
from __future__ import annotations

from cemi.models import Finding, RiskSummary, Severity

_SEVERITY_SCORES: dict[Severity, int] = {
    Severity.INFO: 0,
    Severity.LOW: 5,
    Severity.MEDIUM: 15,
    Severity.HIGH: 30,
    Severity.CRITICAL: 50,
}


def _score_to_level(score: int) -> str:
    if score == 0:
        return "none"
    if score <= 20:
        return "low"
    if score <= 50:
        return "medium"
    if score <= 80:
        return "high"
    return "critical"


def calculate_risk_summary(findings: list[Finding]) -> RiskSummary:
    """Compute a :class:`~cemi.models.RiskSummary` from *findings*.

    Scores are summed across all findings and capped at 100.  Severity
    levels with zero findings are omitted from *finding_counts*.
    """
    raw_score = sum(_SEVERITY_SCORES.get(f.severity, 0) for f in findings)
    score = min(100, raw_score)

    finding_counts: dict[str, int] = {}
    for f in findings:
        key = f.severity.value
        finding_counts[key] = finding_counts.get(key, 0) + 1

    return RiskSummary(
        score=score,
        level=_score_to_level(score),
        finding_counts=finding_counts,
    )


__all__ = ["calculate_risk_summary"]
