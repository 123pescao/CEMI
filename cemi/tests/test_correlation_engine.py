"""Tests for the CEMÍ correlation engine."""
from __future__ import annotations

from datetime import datetime, timezone
from uuid import uuid4

from cemi.correlation_engine import CorrelatedSignal, generate_correlated_signals
from cemi.models import Confidence, EvidenceItem, EvidenceType, Finding, Severity


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
        reasoning_notes=["Test reasoning."],
        app=app,
        category=category,
        official_explanation="Official explanation.",
        in_other_words="In other words.",
        why_this_matters="Why this matters.",
        evidence=evidence or [],
        recommended_action="Recommended action.",
        safe_to_ignore_when="Safe to ignore.",
        false_positive_risk="low",
        requires_admin_to_verify=False,
        created_at=datetime.now(timezone.utc),
        scan_id="scan-test",
    )


class TestCorrelationEngine:
    def test_extension_native_messaging_correlation(self) -> None:
        ext = _make_finding(
            finding_id="EXT-003",
            title="Extension Can Inject Scripts and Intercept Traffic",
            severity=Severity.HIGH,
            confidence=Confidence.MEDIUM,
            contextual_confidence="medium",
            category="Browser Extension",
            app="Suspicious Extension",
            evidence=[
                EvidenceItem(type=EvidenceType.PERMISSION, value="scripting", label="permission"),
            ],
        )
        nmh = _make_finding(
            finding_id="NMH-001",
            title="Browser Native Messaging Host Detected",
            severity=Severity.MEDIUM,
            confidence=Confidence.HIGH,
            contextual_confidence="high",
            category="Browser Integration",
            app="Native Host",
            evidence=[
                EvidenceItem(type=EvidenceType.FILE_PATH, value="manifest.json", label="manifest_path"),
            ],
        )

        correlated = generate_correlated_signals([ext, nmh], "scan-test")

        assert len(correlated) == 1
        assert correlated[0].title == "Browser Extension Can Reach Native System Access"
        assert correlated[0].severity == Severity.HIGH
        assert correlated[0].status == "High Priority"
        assert "EXT-003" in correlated[0].contributing_findings[0]
        assert "NMH-001" in correlated[0].contributing_findings[1]

    def test_persistence_user_writable_path_correlation(self) -> None:
        startup = _make_finding(
            finding_id="STARTUP-001",
            title="Auto-Start Entry From User-Writable Location",
            severity=Severity.HIGH,
            confidence=Confidence.MEDIUM,
            contextual_confidence="medium",
            category="Persistence",
            app="Suspicious Startup",
            evidence=[
                EvidenceItem(type=EvidenceType.FILE_PATH, value="C:\\Users\\Example\\app.exe", label="path"),
            ],
        )

        correlated = generate_correlated_signals([startup], "scan-test")

        assert any(signal.correlation_id == "CORR-102" for signal in correlated)
        assert correlated[0].status == "High Priority"
        assert correlated[0].severity == Severity.HIGH

    def test_unsigned_network_activity_correlation(self) -> None:
        persist = _make_finding(
            finding_id="PERSIST-001",
            title="Unsigned or Unknown Executable in User-Writable Location",
            severity=Severity.HIGH,
            confidence=Confidence.MEDIUM,
            contextual_confidence="medium",
            category="Persistence",
            evidence=[
                EvidenceItem(type=EvidenceType.FILE_PATH, value="C:\\Users\\Example\\evil.exe", label="executable path"),
            ],
        )
        net = _make_finding(
            finding_id="NET-001",
            title="Process Has Active External Network Connection",
            severity=Severity.LOW,
            confidence=Confidence.HIGH,
            contextual_confidence="high",
            category="Network Activity",
            evidence=[
                EvidenceItem(type=EvidenceType.FILE_PATH, value="C:\\Users\\Example\\evil.exe", label="exe_path"),
            ],
        )

        correlated = generate_correlated_signals([persist, net], "scan-test")

        assert len(correlated) == 1
        assert correlated[0].title == "Unsigned Executable with Active Network Connection"
        assert correlated[0].status == "Critical Investigation"
        assert correlated[0].severity == Severity.HIGH

    def test_multiple_medium_signals_correlation(self) -> None:
        signals = [
            _make_finding(
                finding_id=f"MED-{i}",
                title=f"Medium Signal {i}",
                severity=Severity.MEDIUM,
                confidence=Confidence.MEDIUM,
                contextual_confidence="medium",
                category="Suspicious",
            )
            for i in range(5)
        ]

        correlated = generate_correlated_signals(signals, "scan-test")

        assert len(correlated) == 1
        assert correlated[0].title == "Multiple Suspicious Behaviors Detected"
        assert correlated[0].status == "Needs Review"

    def test_one_drive_foxyproxy_safe_combo_does_not_correlate(self) -> None:
        ext = _make_finding(
            finding_id="EXT-004",
            title="Extension Has Browser-to-App Bridge Capability",
            severity=Severity.HIGH,
            confidence=Confidence.MEDIUM,
            contextual_confidence="medium",
            category="Browser Extension",
            app="FoxyProxy",
        )
        nmh = _make_finding(
            finding_id="NMH-001",
            title="Browser Native Messaging Host Detected",
            severity=Severity.MEDIUM,
            confidence=Confidence.HIGH,
            contextual_confidence="high",
            category="Browser Integration",
            app="OneDrive",
        )

        correlated = generate_correlated_signals([ext, nmh], "scan-test")

        assert all(signal.title != "Browser Extension Can Reach Native System Access" for signal in correlated)

    def test_corr101_emits_at_most_one_signal_with_multiple_pairs(self) -> None:
        """Test that CORR-101 creates at most one signal even with multiple extension/native host pairs."""
        ext1 = _make_finding(
            finding_id="EXT-003",
            title="Extension Can Inject Scripts and Intercept Traffic",
            severity=Severity.HIGH,
            confidence=Confidence.MEDIUM,
            contextual_confidence="medium",
            category="Browser Extension",
            app="Extension 1",
        )
        ext2 = _make_finding(
            finding_id="EXT-004",
            title="Extension Has Browser-to-App Bridge Capability",
            severity=Severity.HIGH,
            confidence=Confidence.MEDIUM,
            contextual_confidence="medium",
            category="Browser Extension",
            app="Extension 2",
        )
        nmh1 = _make_finding(
            finding_id="NMH-001",
            title="Browser Native Messaging Host Detected",
            severity=Severity.MEDIUM,
            confidence=Confidence.HIGH,
            contextual_confidence="high",
            category="Browser Integration",
            app="Host 1",
        )
        nmh2 = _make_finding(
            finding_id="NMH-001",
            title="Browser Native Messaging Host Detected",
            severity=Severity.MEDIUM,
            confidence=Confidence.HIGH,
            contextual_confidence="high",
            category="Browser Integration",
            app="Host 2",
        )

        correlated = generate_correlated_signals([ext1, ext2, nmh1, nmh2], "scan-test")

        # Should emit exactly one CORR-101 signal, not 4 (2×2)
        corr101_signals = [s for s in correlated if s.correlation_id == "CORR-101"]
        assert len(corr101_signals) == 1
        assert len(corr101_signals[0].contributing_findings) == 4  # All four findings listed

    def test_corr104_does_not_fire_with_three_medium_browser_findings(self) -> None:
        """Test that CORR-104 does not fire with only 3 medium browser extension findings."""
        findings = [
            _make_finding(
                finding_id="EXT-001",
                title="Extension Has Access to All Websites",
                severity=Severity.MEDIUM,
                confidence=Confidence.MEDIUM,
                contextual_confidence="medium",
                category="Browser Extension",
            )
            for i in range(3)
        ]

        correlated = generate_correlated_signals(findings, "scan-test")

        # Should not create CORR-104 since browser extension findings are excluded
        corr104_signals = [s for s in correlated if s.correlation_id == "CORR-104"]
        assert len(corr104_signals) == 0

    def test_corr104_fires_with_five_medium_non_browser_findings(self) -> None:
        """Test that CORR-104 fires with 5+ medium findings from non-browser categories."""
        findings = [
            _make_finding(
                finding_id="PROC-001",
                title="Process Running from User-Writable Location",
                severity=Severity.MEDIUM,
                confidence=Confidence.MEDIUM,
                contextual_confidence="medium",
                category="Process Behavior",
            )
            for i in range(5)
        ]

        correlated = generate_correlated_signals(findings, "scan-test")

        # Should create CORR-104
        corr104_signals = [s for s in correlated if s.correlation_id == "CORR-104"]
        assert len(corr104_signals) == 1

    def test_correlated_signal_evidence_is_high_level_only(self) -> None:
        ext = _make_finding(
            finding_id="EXT-003",
            title="Extension Can Inject Scripts and Intercept Traffic",
            severity=Severity.HIGH,
            confidence=Confidence.MEDIUM,
            contextual_confidence="medium",
            category="Browser Extension",
            app="Suspicious Extension",
            evidence=[
                EvidenceItem(type=EvidenceType.PERMISSION, value="scripting", label="permission"),
            ],
        )
        nmh = _make_finding(
            finding_id="NMH-001",
            title="Browser Native Messaging Host Detected",
            severity=Severity.MEDIUM,
            confidence=Confidence.HIGH,
            contextual_confidence="high",
            category="Browser Integration",
            app="Native Host",
            evidence=[
                EvidenceItem(type=EvidenceType.FILE_PATH, value="manifest.json", label="manifest_path"),
            ],
        )

        correlated = generate_correlated_signals([ext, nmh], "scan-test")

        assert correlated
        assert correlated[0].evidence[0].type == EvidenceType.METADATA
        assert correlated[0].evidence[0].value == "2"
        assert "manifest.json" not in correlated[0].evidence[0].value
