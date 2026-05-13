"""Trust/signature-based compromise signal rules for CEMÍ.

TRUST-001: Unknown trust executable in user-writable location
"""
from __future__ import annotations

from datetime import datetime, timezone
from typing import Any
from uuid import uuid4

from cemi.models import (
    Confidence,
    EvidenceItem,
    EvidenceType,
    Finding,
    Severity,
)
from cemi.rules.engine import BaseRule

RULE_ID = "TRUST-001"
RULE_VERSION = "1.0.0"

_TITLE = "Unknown Trust Executable in User-Writable Location"

_OFFICIAL_EXPLANATION = (
    "An executable file with unknown or missing digital signature trust status "
    "is located in a user-writable directory. Legitimate Windows executables are usually "
    "signed by their publishers. Unsigned executables in user folders may indicate malware."
)

_IN_OTHER_WORDS = (
    "A program that isn't signed by a trusted publisher is in a suspicious location."
)

_WHY_THIS_MATTERS = (
    "Legitimate software is digitally signed to prove authenticity. Some unwanted software avoids "
    "signing or uses stolen certificates. Finding unsigned executables in user folders is a risk indicator."
)

_RECOMMENDED_ACTION = (
    "Verify the program's source, publisher, and install location. If the software is unexpected, do not disable, delete, or remove it until you have confirmed its purpose."
)

_SAFE_TO_IGNORE_WHEN = (
    "This is a custom or open-source program you compiled or installed intentionally."
)

_FALSE_POSITIVE_RISK = "medium"


def _is_user_writable_path(path: str) -> bool:
    """Check if path is in a user-writable location."""
    if not path:
        return False
    lower_path = path.lower()
    return any(keyword in lower_path for keyword in ["c:\\users\\", "appdata", "temp", "downloads"])


def _is_unknown_trust_status(status: str | None) -> bool:
    """Check if signature status indicates unknown/unsigned trust."""
    if not status:
        return True
    return status.lower() in ["unknown", "unsigned", "error", "none"]


def _build_evidence(sig: dict[str, Any]) -> list[EvidenceItem]:
    evidence = [
        EvidenceItem(
            type=EvidenceType.FILE_PATH,
            value=sig.get("path_redacted", "[unknown]"),
            label="executable_path",
        ),
        EvidenceItem(
            type=EvidenceType.SIGNATURE_STATUS,
            value=sig.get("signature_status", "[unknown]"),
            label="signature_status",
        ),
    ]
    if sig.get("publisher"):
        evidence.append(
            EvidenceItem(
                type=EvidenceType.METADATA,
                value=sig["publisher"],
                label="publisher",
            )
        )
    if sig.get("sha256"):
        evidence.append(
            EvidenceItem(
                type=EvidenceType.HASH,
                value=sig["sha256"],
                label="sha256",
            )
        )
    return evidence


class TrustSignatureRule(BaseRule):
    """TRUST-001: Detect unsigned/unknown-trust executables in user-writable locations."""

    def evaluate(
        self,
        items_by_collector: dict[str, list[Any]],
        scan_id: str,
    ) -> list[Finding]:
        findings: list[Finding] = []
        signatures = items_by_collector.get("signatures", [])

        for sig in signatures:
            path = sig.get("path_redacted", "")
            if not sig.get("is_executable"):
                continue
            if not _is_user_writable_path(path):
                continue
            if not _is_unknown_trust_status(sig.get("signature_status")):
                continue

            findings.append(self._make_finding(sig, scan_id))

        return findings

    def _make_finding(
        self,
        sig: dict[str, Any],
        scan_id: str,
    ) -> Finding:
        return Finding(
            id=RULE_ID,
            instance_id=uuid4(),
            rule_version=RULE_VERSION,
            title=_TITLE,
            severity=Severity.HIGH,
            confidence=Confidence.MEDIUM,
            app=None,
            category="Trust",
            official_explanation=_OFFICIAL_EXPLANATION,
            in_other_words=_IN_OTHER_WORDS,
            why_this_matters=_WHY_THIS_MATTERS,
            evidence=_build_evidence(sig),
            recommended_action=_RECOMMENDED_ACTION,
            safe_to_ignore_when=_SAFE_TO_IGNORE_WHEN,
            false_positive_risk=_FALSE_POSITIVE_RISK,
            requires_admin_to_verify=False,
            created_at=datetime.now(timezone.utc),
            scan_id=scan_id,
        )


__all__ = ["TrustSignatureRule", "RULE_ID", "RULE_VERSION"]
