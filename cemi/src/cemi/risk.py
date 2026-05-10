"""Deterministic risk scoring for CEMÍ scan results.

This module delegates to :mod:`cemi.scoring` while preserving the legacy
risk thresholds and single-severity base values for compatibility.
"""
from __future__ import annotations

from cemi.models import Finding, RiskSummary
from cemi.scoring import calculate_risk_summary as _weighted_risk_summary

__all__ = ["calculate_risk_summary", "_score_to_level"]


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
    """Compute a legacy-compatible :class:`~cemi.models.RiskSummary`.

    This wrapper delegates to ``cemi.scoring`` but preserves the original
    severity base scores used by the rest of the project tests.
    """
    return _weighted_risk_summary(findings, legacy=True)
