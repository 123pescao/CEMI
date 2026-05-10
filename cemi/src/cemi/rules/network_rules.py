"""Network-based compromise signal rules for CEMÍ.

NET-001: Active network connection from any process
NET-002: Suspicious process location with network activity
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

RULE_ID_NET001 = "NET-001"
RULE_ID_NET002 = "NET-002"
RULE_VERSION = "1.0.0"

_TITLE_NET001 = "Process Has Active External Network Connection"
_TITLE_NET002 = "Suspicious Process Location With Network Activity"

_OFFICIAL_EXPLANATION_NET001 = (
    "A running process has an active connection to a remote system."
)

_OFFICIAL_EXPLANATION_NET002 = (
    "A process running from a user-writable location has an active network connection."
)

_IN_OTHER_WORDS_NET001 = (
    "A program on your computer is connecting to something outside your machine."
)

_IN_OTHER_WORDS_NET002 = (
    "A program from a suspicious location is actively communicating over the network."
)

_WHY_THIS_MATTERS_NET001 = (
    "Network connections are normal, but connections from unusual places may require review."
)

_WHY_THIS_MATTERS_NET002 = (
    "Malware often runs from user folders and communicates externally to exfiltrate data or receive commands."
)

_RECOMMENDED_ACTION_NET001 = (
    "Check what program this is and verify it needs network access. Stop it if unknown."
)

_RECOMMENDED_ACTION_NET002 = (
    "This combination suggests higher risk. Verify the program's legitimacy and purpose."
)

_SAFE_TO_IGNORE_WHEN_NET001 = (
    "This is a legitimate program that requires network access (e.g., browser, email client)."
)

_SAFE_TO_IGNORE_WHEN_NET002 = (
    "You intentionally installed a program in a user folder that requires network access."
)

_FALSE_POSITIVE_RISK_NET001 = "very_high"
_FALSE_POSITIVE_RISK_NET002 = "medium"


def _is_user_writable_path(path: str) -> bool:
    """Check if path is in a user-writable location."""
    if not path:
        return False
    lower_path = path.lower()
    return any(keyword in lower_path for keyword in ["c:\\users\\", "appdata", "temp", "downloads"])


def _build_evidence_net001(conn: dict[str, Any]) -> list[EvidenceItem]:
    evidence = [
        EvidenceItem(
            type=EvidenceType.METADATA,
            value=conn.get("process_name", "") or "[unknown]",
            label="process_name",
        ),
        EvidenceItem(
            type=EvidenceType.METADATA,
            value=str(conn.get("pid", "[unknown]")),
            label="process_pid",
        ),
        EvidenceItem(
            type=EvidenceType.NETWORK_CONNECTION,
            value=f"{conn.get('remote_address', '[unknown]')}:{conn.get('remote_port', '[unknown]')}",
            label="remote_connection",
        ),
        EvidenceItem(
            type=EvidenceType.METADATA,
            value=conn.get("status", "[unknown]"),
            label="connection_status",
        ),
    ]
    if conn.get("exe_path_redacted"):
        evidence.append(
            EvidenceItem(
                type=EvidenceType.FILE_PATH,
                value=conn["exe_path_redacted"],
                label="exe_path",
            )
        )
    return evidence


class NetworkConnectionsRule(BaseRule):
    """NET-001 and NET-002: Detect network activity from processes."""

    def evaluate(
        self,
        items_by_collector: dict[str, list[Any]],
        scan_id: str,
    ) -> list[Finding]:
        findings: list[Finding] = []
        connections = items_by_collector.get("network_connections", [])

        if not connections:
            return []

        for conn in connections:
            if not conn.get("remote_address") or not conn.get("remote_port"):
                continue

            exe_path = conn.get("exe_path_redacted", "")
            is_user_writable = _is_user_writable_path(exe_path)

            # NET-001: basic connection
            findings.append(self._make_finding_net001(conn, scan_id))

            # NET-002: upgrade if user-writable path
            if is_user_writable:
                findings.append(self._make_finding_net002(conn, scan_id))

        return findings

    def _make_finding_net001(
        self,
        conn: dict[str, Any],
        scan_id: str,
    ) -> Finding:
        return Finding(
            id=RULE_ID_NET001,
            instance_id=uuid4(),
            rule_version=RULE_VERSION,
            title=_TITLE_NET001,
            severity=Severity.LOW,
            confidence=Confidence.HIGH,
            app=conn.get("process_name"),
            category="Network Activity",
            official_explanation=_OFFICIAL_EXPLANATION_NET001,
            in_other_words=_IN_OTHER_WORDS_NET001,
            why_this_matters=_WHY_THIS_MATTERS_NET001,
            evidence=_build_evidence_net001(conn),
            recommended_action=_RECOMMENDED_ACTION_NET001,
            safe_to_ignore_when=_SAFE_TO_IGNORE_WHEN_NET001,
            false_positive_risk=_FALSE_POSITIVE_RISK_NET001,
            requires_admin_to_verify=False,
            created_at=datetime.now(timezone.utc),
            scan_id=scan_id,
        )

    def _make_finding_net002(
        self,
        conn: dict[str, Any],
        scan_id: str,
    ) -> Finding:
        return Finding(
            id=RULE_ID_NET002,
            instance_id=uuid4(),
            rule_version=RULE_VERSION,
            title=_TITLE_NET002,
            severity=Severity.HIGH,
            confidence=Confidence.MEDIUM,
            app=conn.get("process_name"),
            category="Network Activity",
            official_explanation=_OFFICIAL_EXPLANATION_NET002,
            in_other_words=_IN_OTHER_WORDS_NET002,
            why_this_matters=_WHY_THIS_MATTERS_NET002,
            evidence=_build_evidence_net001(conn),
            recommended_action=_RECOMMENDED_ACTION_NET002,
            safe_to_ignore_when=_SAFE_TO_IGNORE_WHEN_NET002,
            false_positive_risk=_FALSE_POSITIVE_RISK_NET002,
            requires_admin_to_verify=False,
            created_at=datetime.now(timezone.utc),
            scan_id=scan_id,
        )


__all__ = ["NetworkConnectionsRule", "RULE_ID_NET001", "RULE_ID_NET002", "RULE_VERSION"]
