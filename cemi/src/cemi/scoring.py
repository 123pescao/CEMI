"""Deterministic weighted risk scoring for CEMÍ.

This module applies category-specific modifiers to the existing severity-based
risk score so that capability and known-vendor findings do not inflate the
overall risk score as aggressively as higher-confidence compromise signals.
"""
from __future__ import annotations

from typing import Iterable

from cemi.correlation_engine import CorrelatedSignal
from cemi.models import Finding, RiskSummary, Severity

_SEVERITY_BASE_SCORES: dict[Severity, int] = {
    Severity.INFO: 0,
    Severity.LOW: 3,
    Severity.MEDIUM: 8,
    Severity.HIGH: 18,
    Severity.CRITICAL: 35,
}

_LEGACY_SEVERITY_SCORES: dict[Severity, int] = {
    Severity.INFO: 0,
    Severity.LOW: 5,
    Severity.MEDIUM: 15,
    Severity.HIGH: 30,
    Severity.CRITICAL: 50,
}

_CATEGORY_MODIFIERS: dict[str, float] = {
    "correlation": 1.75,
    "service": 1.5,
    "trust": 1.5,
    "network": 1.2,
    "persistence": 0.8,
    "execution": 1.0,
    "browser extension": 2 / 3,
    "browser": 0.4,
    "capability": 0.4,
}

_DEFAULT_CATEGORY_MODIFIER = 1.0


def _normalize_category(category: str) -> str:
    return category.strip().lower()


def _category_modifier(category: str, finding: Finding) -> float:
    if isinstance(finding, CorrelatedSignal):
        return finding.risk_multiplier

    normalized = _normalize_category(category)
    for key, modifier in _CATEGORY_MODIFIERS.items():
        if key == normalized or key in normalized:
            return modifier
    return _DEFAULT_CATEGORY_MODIFIER


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


def calculate_risk_summary(findings: list[Finding], *, legacy: bool = False) -> RiskSummary:
    """Compute a :class:`~cemi.models.RiskSummary` from *findings*.

    When ``legacy`` is False, each finding is scored by severity and adjusted by
    a category modifier. When ``legacy`` is True, the original fixed severity
    scores are used instead for backward compatibility.
    """
    if legacy:
        raw_score = sum(_LEGACY_SEVERITY_SCORES.get(finding.severity, 0) for finding in findings)
    else:
        raw_score = 0.0
        for finding in findings:
            base = _SEVERITY_BASE_SCORES.get(finding.severity, 0)
            modifier = _category_modifier(finding.category, finding)
            raw_score += base * modifier

    score = min(100, int(round(raw_score)))

    finding_counts: dict[str, int] = {}
    for finding in findings:
        key = finding.severity.value
        finding_counts[key] = finding_counts.get(key, 0) + 1

    return RiskSummary(
        score=score,
        level=_score_to_level(score),
        finding_counts=finding_counts,
    )


__all__ = ["calculate_risk_summary"]
