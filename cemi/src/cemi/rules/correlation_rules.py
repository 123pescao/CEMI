"""Correlation rules linking multiple signals for CEMÍ.

CORR-002: Suspicious persistence and network activity correlation
CORR-003: Suspicious process with weak trust and network activity correlation
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
from cemi.trust.software_reputation import assess_software_reputation
from cemi.rules.engine import BaseRule

RULE_ID_CORR002 = "CORR-002"
RULE_ID_CORR003 = "CORR-003"
RULE_VERSION = "1.0.0"

_TITLE_CORR002 = "Suspicious Persistence and Network Activity Correlation"
_TITLE_CORR003 = "Suspicious Process With Weak Trust and Network Activity"

_OFFICIAL_EXPLANATION_CORR002 = (
    "The same executable appears in both startup persistence entries and active network connections. "
    "This may be seen in unwanted or malicious software, but can also be legitimate."
)

_OFFICIAL_EXPLANATION_CORR003 = (
    "The same executable is running, has unknown or unsigned trust status, and is making network connections. "
    "This combination increases the need for review."
)

_IN_OTHER_WORDS_CORR002 = (
    "A program that starts automatically is also actively talking to other computers."
)

_IN_OTHER_WORDS_CORR003 = (
    "An untrusted program is running and communicating with external systems."
)

_WHY_THIS_MATTERS_CORR002 = (
    "Combining startup persistence with network activity may require review because it can occur in both benign and malicious scenarios."
)

_WHY_THIS_MATTERS_CORR003 = (
    "Multiple red flags together (unsigned, running, networking) suggest higher risk than any single signal alone."
)

_RECOMMENDED_ACTION_CORR002 = (
    "Verify publisher, install location, and whether the behavior is expected. Do not disable or delete it until confirmed."
)

_RECOMMENDED_ACTION_CORR003 = (
    "Review the process, startup entries, and network connections. Do not disable or delete until you confirm the software's purpose."
)

_SAFE_TO_IGNORE_WHEN_CORR002 = (
    "This is a legitimate application you intentionally configured to start automatically."
)

_SAFE_TO_IGNORE_WHEN_CORR003 = (
    "This is an open-source or self-signed application you trust that requires network access."
)

_FALSE_POSITIVE_RISK_CORR002 = "low"
_FALSE_POSITIVE_RISK_CORR003 = "low"


def _is_user_writable_path(path: str) -> bool:
    """Check if path is in a user-writable location."""
    if not path:
        return False
    lower_path = path.lower()
    return any(keyword in lower_path for keyword in ["c:\\users\\", "appdata", "temp", "downloads"])


def _normalize_path(path: str) -> str:
    """Normalize path for comparison (lowercase, no extra spaces)."""
    return path.lower().strip() if path else ""


def _is_unknown_trust(status: str | None) -> bool:
    """Check if status is unknown/unsigned."""
    if not status:
        return True
    return status.lower() in ["unknown", "unsigned", "error", "none"]


def _build_evidence_corr002(startup: dict[str, Any], conn: dict[str, Any]) -> list[EvidenceItem]:
    evidence = [
        EvidenceItem(
            type=EvidenceType.METADATA,
            value=startup.get("name", "[unknown]"),
            label="startup_entry_name",
        ),
        EvidenceItem(
            type=EvidenceType.FILE_PATH,
            value=startup.get("path_redacted", "[unknown]"),
            label="startup_path",
        ),
        EvidenceItem(
            type=EvidenceType.METADATA,
            value=conn.get("process_name", "[unknown]"),
            label="network_process_name",
        ),
        EvidenceItem(
            type=EvidenceType.NETWORK_CONNECTION,
            value=f"remote port {conn.get('remote_port', '[unknown]')}",
            label="network_target",
        ),
    ]
    return evidence


def _build_evidence_corr003(proc: dict[str, Any], sig: dict[str, Any], conn: dict[str, Any]) -> list[EvidenceItem]:
    evidence = [
        EvidenceItem(
            type=EvidenceType.METADATA,
            value=proc.get("name", "[unknown]"),
            label="process_name",
        ),
        EvidenceItem(
            type=EvidenceType.FILE_PATH,
            value=sig.get("path_redacted", "[unknown]"),
            label="executable_path",
        ),
        EvidenceItem(
            type=EvidenceType.SIGNATURE_STATUS,
            value=sig.get("signature_status", "[unknown]"),
            label="trust_status",
        ),
        EvidenceItem(
            type=EvidenceType.NETWORK_CONNECTION,
            value=f"remote port {conn.get('remote_port', '[unknown]')}",
            label="network_connection",
        ),
    ]
    return evidence


class CorrelationSignalsRule(BaseRule):
    """CORR-002 and CORR-003: Detect correlated compromise signals across collectors."""

    def evaluate(
        self,
        items_by_collector: dict[str, list[Any]],
        scan_id: str,
    ) -> list[Finding]:
        findings: list[Finding] = []

        startup_items = items_by_collector.get("startup", [])
        network_conns = items_by_collector.get("network_connections", [])
        processes = items_by_collector.get("processes", [])
        signatures = items_by_collector.get("signatures", [])

        # CORR-002: startup + network activity
        findings.extend(self._eval_corr002(startup_items, network_conns, scan_id))

        # CORR-003: process + signature + network
        findings.extend(self._eval_corr003(processes, signatures, network_conns, scan_id))

        return findings

    def _eval_corr002(
        self,
        startup_items: list[dict[str, Any]],
        network_conns: list[dict[str, Any]],
        scan_id: str,
    ) -> list[Finding]:
        """Detect startup entries that match network-active processes."""
        findings: list[Finding] = []
        seen_pairs: set[tuple[str, str]] = set()

        for startup in startup_items:
            startup_path = _normalize_path(startup.get("path_redacted", ""))
            if not startup_path:
                continue

            for conn in network_conns:
                if not conn.get("remote_address") or not conn.get("remote_port"):
                    continue

                conn_exe_path = _normalize_path(conn.get("exe_path_redacted", ""))
                if startup_path == conn_exe_path or startup_path in conn_exe_path:
                    process_name = (conn.get("process_name") or "").strip().lower()
                    dedupe_key = (startup_path, process_name)
                    if dedupe_key in seen_pairs:
                        continue
                    seen_pairs.add(dedupe_key)

                    is_user_writable = _is_user_writable_path(startup.get("path_redacted", ""))
                    # Check if this is from a known vendor; if so, keep MEDIUM despite user-writable
                    reputation = assess_software_reputation(
                        name=conn.get("process_name"),
                        publisher=None,
                        path=startup_path,
                    )
                    is_known_vendor = reputation.get("known_vendor", False)
                    severity = Severity.MEDIUM if (is_known_vendor or not is_user_writable) else Severity.HIGH

                    findings.append(
                        Finding(
                            id=RULE_ID_CORR002,
                            instance_id=uuid4(),
                            rule_version=RULE_VERSION,
                            title=_TITLE_CORR002,
                            severity=severity,
                            confidence=Confidence.MEDIUM,
                            app=conn.get("process_name"),
                            category="Correlation",
                            official_explanation=_OFFICIAL_EXPLANATION_CORR002,
                            in_other_words=_IN_OTHER_WORDS_CORR002,
                            why_this_matters=_WHY_THIS_MATTERS_CORR002,
                            evidence=_build_evidence_corr002(startup, conn),
                            recommended_action=_RECOMMENDED_ACTION_CORR002,
                            safe_to_ignore_when=_SAFE_TO_IGNORE_WHEN_CORR002,
                            false_positive_risk=_FALSE_POSITIVE_RISK_CORR002,
                            requires_admin_to_verify=(startup.get("scope") == "system"),
                            created_at=datetime.now(timezone.utc),
                            scan_id=scan_id,
                        )
                    )

        return findings

    def _eval_corr003(
        self,
        processes: list[dict[str, Any]],
        signatures: list[dict[str, Any]],
        network_conns: list[dict[str, Any]],
        scan_id: str,
    ) -> list[Finding]:
        """Detect untrusted processes making network connections."""
        findings: list[Finding] = []

        seen_keys: set[tuple[str, str]] = set()
        for proc in processes:
            proc_path = _normalize_path(proc.get("exe_path", ""))
            if not proc_path:
                continue

            for sig in signatures:
                sig_path = _normalize_path(sig.get("path_redacted", ""))
                if proc_path != sig_path:
                    continue

                if not sig.get("is_executable"):
                    continue

                if not _is_unknown_trust(sig.get("signature_status")):
                    continue

                for conn in network_conns:
                    if not conn.get("remote_address") or not conn.get("remote_port"):
                        continue

                    conn_exe_path = _normalize_path(conn.get("exe_path_redacted", ""))
                    if conn_exe_path == proc_path:
                        process_name = (proc.get("name") or "").strip().lower()
                        dedupe_key = (proc_path, process_name)
                        if dedupe_key in seen_keys:
                            continue
                        seen_keys.add(dedupe_key)

                        is_user_writable = _is_user_writable_path(proc_path)
                        # Check if this is from a known vendor; if so, keep MEDIUM despite unsigned
                        reputation = assess_software_reputation(
                            name=proc.get("name"),
                            publisher=sig.get("publisher"),
                            path=proc_path,
                        )
                        is_known_vendor = reputation.get("known_vendor", False)
                        severity = Severity.MEDIUM if is_known_vendor else (Severity.HIGH if is_user_writable else Severity.MEDIUM)

                        findings.append(
                            Finding(
                                id=RULE_ID_CORR003,
                                instance_id=uuid4(),
                                rule_version=RULE_VERSION,
                                title=_TITLE_CORR003,
                                severity=severity,
                                confidence=Confidence.HIGH,
                                app=proc.get("name"),
                                category="Correlation",
                                official_explanation=_OFFICIAL_EXPLANATION_CORR003,
                                in_other_words=_IN_OTHER_WORDS_CORR003,
                                why_this_matters=_WHY_THIS_MATTERS_CORR003,
                                evidence=_build_evidence_corr003(proc, sig, conn),
                                recommended_action=_RECOMMENDED_ACTION_CORR003,
                                safe_to_ignore_when=_SAFE_TO_IGNORE_WHEN_CORR003,
                                false_positive_risk=_FALSE_POSITIVE_RISK_CORR003,
                                requires_admin_to_verify=False,
                                created_at=datetime.now(timezone.utc),
                                scan_id=scan_id,
                            )
                        )

        return findings


__all__ = ["CorrelationSignalsRule", "RULE_ID_CORR002", "RULE_ID_CORR003", "RULE_VERSION"]
