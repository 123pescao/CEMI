"""Correlation engine for CEMÍ.

This module identifies higher-confidence threat signals by linking existing
findings together. It does not introduce new detectors or collect raw data.
"""
from __future__ import annotations

from datetime import datetime, timezone
from typing import Iterable
from uuid import uuid4

from pydantic import ConfigDict

from cemi.models import Confidence, EvidenceItem, EvidenceType, Finding, Severity


class CorrelatedSignal(Finding):
    """A derived threat signal produced by combining multiple findings."""

    model_config = ConfigDict(frozen=True, extra="forbid")

    correlation_id: str
    status: str
    contributing_findings: list[str]
    evidence_count: int
    risk_multiplier: float


def _contributing_titles(findings: list[Finding]) -> list[str]:
    return [f"{finding.id}: {finding.title}" for finding in findings]


def _combine_evidence_count(findings: list[Finding]) -> int:
    return sum(len(finding.evidence) for finding in findings)


def _known_safe_browser_native_combo(ext_finding: Finding, nmh_finding: Finding) -> bool:
    combined = " ".join(
        [ext_finding.app or "", nmh_finding.app or "", ext_finding.title, nmh_finding.title]
    ).lower()
    return "onedrive" in combined and "foxyproxy" in combined


def _make_correlated_signal(
    correlation_id: str,
    title: str,
    severity: Severity,
    confidence: Confidence,
    contextual_confidence: str,
    status: str,
    category: str,
    official_explanation: str,
    in_other_words: str,
    why_this_matters: str,
    recommended_action: str,
    contributing_findings: list[Finding],
    scan_id: str,
    risk_multiplier: float,
) -> CorrelatedSignal:
    contributing_titles = _contributing_titles(contributing_findings)
    evidence_count = _combine_evidence_count(contributing_findings)
    evidence: list[EvidenceItem] = [
        EvidenceItem(
            type=EvidenceType.METADATA,
            value=str(evidence_count),
            label="correlated_evidence_count",
        )
    ]

    return CorrelatedSignal(
        id=correlation_id,
        instance_id=uuid4(),
        rule_version="1.0.0",
        title=title,
        severity=severity,
        confidence=confidence,
        contextual_confidence=contextual_confidence,
        app=None,
        category=category,
        official_explanation=official_explanation,
        in_other_words=in_other_words,
        why_this_matters=why_this_matters,
        evidence=evidence,
        recommended_action=recommended_action,
        safe_to_ignore_when="This correlated signal is based on deterministic findings analysis.",
        false_positive_risk="medium",
        reasoning_notes=[
            "Deterministic correlation of multiple weak signals produces a higher-confidence threat signal."
        ],
        requires_admin_to_verify=False,
        created_at=datetime.now(timezone.utc),
        scan_id=scan_id,
        correlation_id=correlation_id,
        status=status,
        contributing_findings=contributing_titles,
        evidence_count=evidence_count,
        risk_multiplier=risk_multiplier,
    )


def _find_findings_by_ids(findings: list[Finding], ids: Iterable[str]) -> list[Finding]:
    ids_set = set(ids)
    return [finding for finding in findings if finding.id in ids_set]


def _find_findings_by_category(findings: list[Finding], category: str) -> list[Finding]:
    normalized = category.strip().lower()
    return [finding for finding in findings if finding.category.strip().lower() == normalized]


def _find_matching_path_findings(findings: list[Finding], source_ids: Iterable[str], target_ids: Iterable[str]) -> list[tuple[Finding, Finding]]:
    source_paths = {}
    target_paths = {}

    for finding in findings:
        paths = [item.value for item in finding.evidence if item.type == EvidenceType.FILE_PATH]
        if not paths:
            continue
        if finding.id in source_ids:
            for path in paths:
                source_paths.setdefault(path.lower(), []).append(finding)
        if finding.id in target_ids:
            for path in paths:
                target_paths.setdefault(path.lower(), []).append(finding)

    matches: list[tuple[Finding, Finding]] = []
    for path, sources in source_paths.items():
        targets = target_paths.get(path)
        if not targets:
            continue
        for source in sources:
            for target in targets:
                matches.append((source, target))
    return matches


def generate_correlated_signals(findings: list[Finding], scan_id: str) -> list[CorrelatedSignal]:
    correlated: list[CorrelatedSignal] = []

    ext_findings = _find_findings_by_ids(findings, ["EXT-003", "EXT-004"])
    nmh_findings = _find_findings_by_ids(findings, ["NMH-001"])
    if ext_findings and nmh_findings:
        for ext in ext_findings:
            for nmh in nmh_findings:
                if _known_safe_browser_native_combo(ext, nmh):
                    continue
                correlated.append(
                    _make_correlated_signal(
                        correlation_id="CORR-101",
                        title="Browser Extension Can Reach Native System Access",
                        severity=Severity.HIGH,
                        confidence=Confidence.HIGH,
                        contextual_confidence="high",
                        status="High Priority",
                        category="Correlation",
                        official_explanation=(
                            "A browser extension with scripting or native bridge capability is present "
                            "alongside a native messaging host. This creates a potential browser-to-system bridge."
                        ),
                        in_other_words=(
                            "An extension may be able to pass data from web pages to a local program on this machine."
                        ),
                        why_this_matters=(
                            "The combination of browser scripting capability and native messaging access is a strong "
                            "indicator of a bridge that could be abused for data exfiltration or covert local control."
                        ),
                        recommended_action=(
                            "Review the extension and the associated native messaging host. Remove the extension or "
                            "native host manifest if this integration is unexpected."
                        ),
                        contributing_findings=[ext, nmh],
                        scan_id=scan_id,
                        risk_multiplier=1.4,
                    )
                )

    startup_findings = _find_findings_by_ids(findings, ["STARTUP-001", "PERSIST-002"])
    startup_strong = [f for f in startup_findings if f.contextual_confidence.lower() != "low"]
    if startup_strong:
        correlated.append(
            _make_correlated_signal(
                correlation_id="CORR-102",
                title="High-Risk Startup Persistence Path",
                severity=Severity.HIGH,
                confidence=Confidence.HIGH,
                contextual_confidence="high",
                status="High Priority",
                category="Correlation",
                official_explanation=(
                    "A startup persistence signal was found in a user-writable location and was not identified as a trusted vendor."
                ),
                in_other_words=(
                    "A program that starts automatically is located in a risky user folder and is not known to be trusted."
                ),
                why_this_matters=(
                    "Persistence in user-writable folders is a common malware technique, especially when the software is not clearly trusted."
                ),
                recommended_action=(
                    "Inspect the startup entry and executable. Remove the entry if you cannot verify the software's legitimacy."
                ),
                contributing_findings=startup_strong,
                scan_id=scan_id,
                risk_multiplier=1.5,
            )
        )

    unsigned_network_matches = _find_matching_path_findings(findings, ["PERSIST-001"], ["NET-001", "NET-002"])
    if unsigned_network_matches:
        source, target = unsigned_network_matches[0]
        correlated.append(
            _make_correlated_signal(
                correlation_id="CORR-103",
                title="Unsigned Executable with Active Network Connection",
                severity=Severity.HIGH,
                confidence=Confidence.HIGH,
                contextual_confidence="high",
                status="Critical Investigation",
                category="Correlation",
                official_explanation=(
                    "An unsigned or unknown executable is actively making network connections."
                ),
                in_other_words=(
                    "A program that may not be digitally trusted is communicating with external systems."
                ),
                why_this_matters=(
                    "Unsigned executables that connect to the network are more likely to be malware or unwanted software."
                ),
                recommended_action=(
                    "Stop the executable and review its origin. Quarantine or remove it if you cannot verify it."
                ),
                contributing_findings=[source, target],
                scan_id=scan_id,
                risk_multiplier=1.6,
            )
        )

    medium_signals = [f for f in findings if f.severity == Severity.MEDIUM]
    if len(medium_signals) >= 3:
        correlated.append(
            _make_correlated_signal(
                correlation_id="CORR-104",
                title="Multiple Suspicious Behaviors Detected",
                severity=Severity.HIGH,
                confidence=Confidence.MEDIUM,
                contextual_confidence="medium",
                status="Needs Review",
                category="Correlation",
                official_explanation=(
                    "Three or more medium-severity signals were detected together, increasing the likelihood of a meaningful threat."
                ),
                in_other_words=(
                    "Several suspicious behaviors were observed at once, which is more concerning than any one alone."
                ),
                why_this_matters=(
                    "Multiple weak or medium-level signals often compound into a stronger indicator of compromise."
                ),
                recommended_action=(
                    "Review the contributing findings together and prioritise the highest-risk items for investigation."
                ),
                contributing_findings=medium_signals,
                scan_id=scan_id,
                risk_multiplier=1.3,
            )
        )

    return correlated
