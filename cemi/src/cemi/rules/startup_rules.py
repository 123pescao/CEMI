"""Startup persistence compromise signal rules for CEMÍ.

STARTUP-001: Auto-start entry from user-writable location
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
from cemi.trust.software_reputation import assess_software_reputation

RULE_ID = "STARTUP-001"
RULE_VERSION = "1.0.0"

_TITLE = "Auto-Start Entry From User-Writable Location"

_OFFICIAL_EXPLANATION = (
    "An entry in Windows startup configuration points to a location where users "
    "can write files (AppData, Temp, Downloads, or C:\\Users\\). This may be used by "
    "unwanted software or by legitimate installers."
)

_IN_OTHER_WORDS = (
    "A program set to start automatically is located in a folder where it might not belong."
)

_WHY_THIS_MATTERS = (
    "User-writable folders are less protected than system directories. Startup entries there "
    "should be reviewed before making changes."
)

_RECOMMENDED_ACTION = (
    "Verify the publisher, install location, and whether this behavior is expected before making changes. "
    "Do not disable, delete, or remove items until confirmed."
)

_SAFE_TO_IGNORE_WHEN = (
    "You intentionally installed a program in a user folder that starts automatically."
)

_FALSE_POSITIVE_RISK = "medium"


def _is_user_writable_path(path: str) -> bool:
    """Check if path is in a user-writable location."""
    if not path:
        return False
    lower_path = path.lower()
    return any(keyword in lower_path for keyword in ["c:\\users\\", "appdata", "temp", "downloads"])


def _build_evidence(item: dict[str, Any]) -> list[EvidenceItem]:
    evidence = [
        EvidenceItem(
            type=EvidenceType.METADATA,
            value=item.get("name", "[unknown]"),
            label="entry_name",
        ),
        EvidenceItem(
            type=EvidenceType.METADATA,
            value=item.get("source", "[unknown]"),
            label="source",
        ),
        EvidenceItem(
            type=EvidenceType.METADATA,
            value=item.get("scope", "[unknown]"),
            label="scope",
        ),
    ]
    if item.get("path_redacted"):
        evidence.append(
            EvidenceItem(
                type=EvidenceType.FILE_PATH,
                value=item["path_redacted"],
                label="command_path",
            )
        )
    return evidence


class StartupPersistenceRule(BaseRule):
    """STARTUP-001: Detect auto-start entries from user-writable locations."""

    def evaluate(
        self,
        items_by_collector: dict[str, list[Any]],
        scan_id: str,
    ) -> list[Finding]:
        findings: list[Finding] = []
        startup_items = items_by_collector.get("startup", [])

        for item in startup_items:
            command_or_path = item.get("path_redacted") or item.get("command", "")
            if _is_user_writable_path(command_or_path):
                findings.append(self._make_finding(item, scan_id))

        return findings

    def _make_finding(
        self,
        item: dict[str, Any],
        scan_id: str,
    ) -> Finding:
        # Assess reputation
        reputation = assess_software_reputation(
            name=item.get("name"),
            publisher=None,  # Startup items may not have publisher
            path=item.get("path_redacted") or item.get("command"),
        )
        is_known_vendor = reputation.get("known_vendor", False)
        contextual_confidence = "low" if is_known_vendor else "medium"
        reasoning_notes = (
            ["Known vendor or common Windows-integrated software detected."]
            if is_known_vendor
            else ["Matched deterministic local rule evidence."]
        )

        return Finding(
            id=RULE_ID,
            instance_id=uuid4(),
            rule_version=RULE_VERSION,
            title=_TITLE,
            severity=Severity.MEDIUM,
            confidence=Confidence.MEDIUM,
            contextual_confidence=contextual_confidence,
            app=item.get("name"),
            category="Persistence",
            official_explanation=_OFFICIAL_EXPLANATION,
            in_other_words=_IN_OTHER_WORDS,
            why_this_matters=_WHY_THIS_MATTERS,
            evidence=_build_evidence(item),
            recommended_action=_RECOMMENDED_ACTION,
            safe_to_ignore_when=_SAFE_TO_IGNORE_WHEN,
            false_positive_risk=_FALSE_POSITIVE_RISK,
            reasoning_notes=reasoning_notes,
            requires_admin_to_verify=(item.get("scope") == "system"),
            created_at=datetime.now(timezone.utc),
            scan_id=scan_id,
        )


__all__ = ["StartupPersistenceRule", "RULE_ID", "RULE_VERSION"]
