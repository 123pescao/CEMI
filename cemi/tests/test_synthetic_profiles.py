"""Synthetic profile tests for CEMÍ noise reduction.

Tests that simulate realistic system configurations to validate
finding quality and noise reduction.
"""
from __future__ import annotations

from datetime import datetime, timezone
from uuid import uuid4

from cemi.correlation_engine import generate_correlated_signals
from cemi.models import (
    Confidence,
    EvidenceItem,
    EvidenceType,
    Finding,
    Severity,
)
from cemi.scan_engine import ScanEngine
from cemi.scoring import calculate_risk_summary


def _make_finding(
    finding_id: str,
    title: str,
    severity: Severity,
    confidence: Confidence,
    contextual_confidence: str,
    category: str,
    app: str | None = None,
    evidence: list[EvidenceItem] | None = None,
) -> Finding:
    return Finding(
        id=finding_id,
        instance_id=uuid4(),
        rule_version="1.0.0",
        title=title,
        severity=severity,
        confidence=confidence,
        contextual_confidence=contextual_confidence,
        reasoning_notes=["Synthetic test finding."],
        app=app,
        category=category,
        official_explanation="Test explanation.",
        in_other_words="Test in other words.",
        why_this_matters="Test why it matters.",
        evidence=evidence or [],
        recommended_action="Test action.",
        safe_to_ignore_when="Test safe to ignore.",
        false_positive_risk="low",
        requires_admin_to_verify=False,
        created_at=datetime.now(timezone.utc),
        scan_id="synthetic-test",
    )


class TestSyntheticProfiles:
    def test_clean_synthetic_profile_no_high_critical_findings(self) -> None:
        """Clean profile should generate no HIGH/CRITICAL findings."""
        # Simulate a clean system with only legitimate findings
        findings = [
            # Some LOW/INFO level findings that are normal
            _make_finding(
                finding_id="NET-001",
                title="Process Has Active External Network Connection",
                severity=Severity.LOW,
                confidence=Confidence.HIGH,
                contextual_confidence="high",
                category="Network Activity",
                app="chrome.exe",
            ),
            _make_finding(
                finding_id="EXT-002",
                title="Extension Can Access Cookies",
                severity=Severity.LOW,  # Tuned down
                confidence=Confidence.MEDIUM,
                contextual_confidence="medium",
                category="Browser Extension",
                app="Password Manager",
            ),
        ]

        correlated = generate_correlated_signals(findings, "synthetic-test")
        all_findings = findings + correlated

        risk_summary = calculate_risk_summary(all_findings)

        # Should be low or none risk
        assert risk_summary.level in ["none", "low"]
        # No high/critical findings
        high_critical = [f for f in all_findings if f.severity in [Severity.HIGH, Severity.CRITICAL]]
        assert len(high_critical) == 0

    def test_suspicious_synthetic_profile_generates_high_findings(self) -> None:
        """Suspicious profile should generate HIGH findings with clear explanations."""
        findings = [
            # Suspicious PowerShell startup
            _make_finding(
                finding_id="WINPERSIST-002",
                title="Suspicious PowerShell Startup Command",
                severity=Severity.HIGH,
                confidence=Confidence.HIGH,
                contextual_confidence="high",
                category="Persistence",
                app="powershell.exe",
            ),
            # LOLBin in startup
            _make_finding(
                finding_id="WINPERSIST-003",
                title="LOLBin Startup or Scheduled Task Command",
                severity=Severity.HIGH,
                confidence=Confidence.MEDIUM,
                contextual_confidence="high",
                category="Persistence",
                app="rundll32.exe",
            ),
            # Suspicious extension combo
            _make_finding(
                finding_id="EXT-003",
                title="Extension Can Inject Scripts and Intercept Traffic",
                severity=Severity.HIGH,
                confidence=Confidence.MEDIUM,
                contextual_confidence="medium",
                category="Browser Extension",
                app="Suspicious Extension",
            ),
            _make_finding(
                finding_id="NMH-001",
                title="Browser Native Messaging Host Detected",
                severity=Severity.MEDIUM,
                confidence=Confidence.HIGH,
                contextual_confidence="high",
                category="Browser Integration",
                app="Suspicious Host",
            ),
        ]

        correlated = generate_correlated_signals(findings, "synthetic-test")
        all_findings = findings + correlated

        risk_summary = calculate_risk_summary(all_findings)

        # Should be high risk
        assert risk_summary.level == "high"
        # Should have HIGH findings
        high_findings = [f for f in all_findings if f.severity == Severity.HIGH]
        assert len(high_findings) >= 2  # Original + correlated
        # Should have CORR-101
        corr101 = [f for f in correlated if f.correlation_id == "CORR-101"]
        assert len(corr101) == 1

    def test_noisy_legitimate_profile_avoids_correlation_explosion(self) -> None:
        """Profile with many browser extension findings should not create correlation explosion."""
        findings = [
            # Multiple browser extension findings (should be excluded from CORR-104)
            _make_finding(
                finding_id="EXT-001",
                title="Extension Has Access to All Websites",
                severity=Severity.MEDIUM,
                confidence=Confidence.MEDIUM,
                contextual_confidence="medium",
                category="Browser Extension",
            ) for _ in range(10)
        ] + [
            # Some non-browser medium findings
            _make_finding(
                finding_id="PROC-001",
                title="Process Running from User-Writable Location",
                severity=Severity.MEDIUM,
                confidence=Confidence.MEDIUM,
                contextual_confidence="medium",
                category="Process Behavior",
            ) for _ in range(3)
        ]

        correlated = generate_correlated_signals(findings, "synthetic-test")

        # Should not create CORR-104 (only 3 non-browser medium findings)
        corr104 = [f for f in correlated if f.correlation_id == "CORR-104"]
        assert len(corr104) == 0

        # Add 2 more non-browser to trigger CORR-104
        additional_findings = [
            _make_finding(
                finding_id="STARTUP-001",
                title="Auto-Start Entry From User-Writable Location",
                severity=Severity.MEDIUM,
                confidence=Confidence.MEDIUM,
                contextual_confidence="medium",
                category="Persistence",
            ) for _ in range(2)
        ]

        all_findings = findings + additional_findings
        correlated = generate_correlated_signals(all_findings, "synthetic-test")

        # Now should create CORR-104 (5 non-browser medium findings)
        corr104 = [f for f in correlated if f.correlation_id == "CORR-104"]
        assert len(corr104) == 1