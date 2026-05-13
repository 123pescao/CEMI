"""Suspicious processes rules for CEMÍ.

Detects processes running from user-writable locations or mimicking system binaries.
"""
from __future__ import annotations

from datetime import datetime, timezone
from typing import Any
from uuid import uuid4
import os

from cemi.models import (
    Confidence,
    EvidenceItem,
    EvidenceType,
    Finding,
    Severity,
)
from cemi.rules.engine import BaseRule
from cemi.utils.redact import redact_path

RULE_ID_PROC001 = "PROC-001"
RULE_ID_PROC002 = "PROC-002"
RULE_VERSION = "1.0.0"

_TITLE_PROC001 = "Process Running from User-Writable Location"
_TITLE_PROC002 = "Process Name Mimics System Binary"

_OFFICIAL_EXPLANATION_PROC001 = (
    "Processes running from user-writable directories like AppData, Temp, or Downloads "
    "may indicate unauthorized software installation or malware persistence."
)

_OFFICIAL_EXPLANATION_PROC002 = (
    "A process with a name that mimics a system binary (e.g., svchost.exe) but located "
    "outside expected system directories could be a disguised malicious executable."
)

_IN_OTHER_WORDS_PROC001 = (
    "This program is running from a folder where users can save files, which might be risky."
)

_IN_OTHER_WORDS_PROC002 = (
    "This program has the same name as a Windows system program but isn't in the right place."
)

_WHY_THIS_MATTERS_PROC001 = (
    "Unwanted or malicious software can use user-writable folders, but legitimate software may also run from these locations."
)

_WHY_THIS_MATTERS_PROC002 = (
    "Executable names matching system binaries but located outside trusted folders are worth reviewing."
)

_RECOMMENDED_ACTION_PROC001 = (
    "Verify the publisher, install location, and whether this behavior is expected before making changes."
)

_RECOMMENDED_ACTION_PROC002 = (
    "Verify the program's location and publisher. Do not disable, delete, or remove it until confirmed."
)

_SAFE_TO_IGNORE_WHEN_PROC001 = (
    "You intentionally installed this program and trust its source."
)

_SAFE_TO_IGNORE_WHEN_PROC002 = (
    "This is a legitimate program with the same name as a system binary."
)

_FALSE_POSITIVE_RISK_PROC001 = "medium"
_FALSE_POSITIVE_RISK_PROC002 = "high"


def _is_user_writable_path(exe_path: str) -> bool:
    """Check if exe_path indicates a user-writable location."""
    if not exe_path:
        return False
    lower_path = exe_path.lower()
    return any(keyword in lower_path for keyword in ["c:\\users\\", "appdata", "temp", "downloads"])


def _is_system_binary_mimic(name: str, exe_path: str) -> bool:
    """Check if process name mimics system binary but path is not system."""
    if not name or not exe_path:
        return False
    mimic_names = {"svchost.exe", "explorer.exe", "chrome.exe"}
    if name.lower() not in mimic_names:
        return False
    lower_path = exe_path.lower()
    # Expected system locations
    system_paths = ["c:\\windows\\", "c:\\program files\\", "c:\\program files (x86)\\"]
    return not any(sys_path in lower_path for sys_path in system_paths)


def _confidence_proc002(exe_path: str) -> Confidence:
    """Determine confidence for PROC-002 based on path deviation."""
    if exe_path and "c:\\users\\" in exe_path.lower():
        return Confidence.MEDIUM
    return Confidence.LOW


def _normalize_proc_key(name: str, exe_path: str) -> tuple[str, str]:
    return (name.strip().lower(), os.path.normpath(exe_path).lower() if exe_path else "")


def _build_evidence_proc001(proc: dict[str, Any], supporting_count: int = 1) -> list[EvidenceItem]:
    evidence = [
        EvidenceItem(
            type=EvidenceType.METADATA,
            value=str(proc.get("pid", "")),
            label="process_pid",
        ),
        EvidenceItem(
            type=EvidenceType.METADATA,
            value=proc.get("name", ""),
            label="process_name",
        ),
    ]
    exe_path = proc.get("exe_path")
    if exe_path:
        evidence.append(
            EvidenceItem(
                type=EvidenceType.FILE_PATH,
                value=redact_path(exe_path),
                label="exe_path",
            )
        )
    cpu = proc.get("cpu_percent")
    if cpu is not None:
        evidence.append(
            EvidenceItem(
                type=EvidenceType.METADATA,
                value=f"{cpu:.1f}%",
                label="cpu_usage",
            )
        )
    if supporting_count > 1:
        evidence.append(
            EvidenceItem(
                type=EvidenceType.METADATA,
                value=str(supporting_count),
                label="supporting_process_count",
            )
        )
    return evidence


def _build_evidence_proc002(proc: dict[str, Any]) -> list[EvidenceItem]:
    return _build_evidence_proc001(proc)  # Same structure


class SuspiciousProcessesRule(BaseRule):
    """PROC-001 and PROC-002: detect suspicious process locations and mimics."""

    def evaluate(
        self,
        items_by_collector: dict[str, list[Any]],
        scan_id: str,
    ) -> list[Finding]:
        findings: list[Finding] = []
        processes = items_by_collector.get("processes", [])

        proc001_groups: dict[tuple[str, str], dict[str, Any]] = {}

        for proc in processes:
            exe_path = proc.get("exe_path", "")
            name = proc.get("name", "")

            if _is_user_writable_path(exe_path):
                key = _normalize_proc_key(name, exe_path)
                if key not in proc001_groups:
                    proc001_groups[key] = {"proc": proc, "count": 1}
                else:
                    proc001_groups[key]["count"] += 1

            if _is_system_binary_mimic(name, exe_path):
                findings.append(self._make_finding_proc002(proc, scan_id))

        for group in proc001_groups.values():
            findings.append(
                self._make_finding_proc001(
                    group["proc"],
                    scan_id,
                    supporting_count=group["count"],
                )
            )

        return findings

    def _make_finding_proc001(
        self,
        proc: dict[str, Any],
        scan_id: str,
        supporting_count: int = 1,
    ) -> Finding:
        return Finding(
            id=RULE_ID_PROC001,
            instance_id=uuid4(),
            rule_version=RULE_VERSION,
            title=_TITLE_PROC001,
            severity=Severity.MEDIUM,
            confidence=Confidence.MEDIUM,
            app=proc.get("name"),
            category="Process Behavior",
            official_explanation=_OFFICIAL_EXPLANATION_PROC001,
            in_other_words=_IN_OTHER_WORDS_PROC001,
            why_this_matters=_WHY_THIS_MATTERS_PROC001,
            evidence=_build_evidence_proc001(proc, supporting_count=supporting_count),
            recommended_action=_RECOMMENDED_ACTION_PROC001,
            safe_to_ignore_when=_SAFE_TO_IGNORE_WHEN_PROC001,
            false_positive_risk=_FALSE_POSITIVE_RISK_PROC001,
            requires_admin_to_verify=False,
            created_at=datetime.now(timezone.utc),
            scan_id=scan_id,
        )

    def _make_finding_proc002(
        self,
        proc: dict[str, Any],
        scan_id: str,
    ) -> Finding:
        return Finding(
            id=RULE_ID_PROC002,
            instance_id=uuid4(),
            rule_version=RULE_VERSION,
            title=_TITLE_PROC002,
            severity=Severity.HIGH,
            confidence=_confidence_proc002(proc.get("exe_path", "")),
            app=proc.get("name"),
            category="Process Behavior",
            official_explanation=_OFFICIAL_EXPLANATION_PROC002,
            in_other_words=_IN_OTHER_WORDS_PROC002,
            why_this_matters=_WHY_THIS_MATTERS_PROC002,
            evidence=_build_evidence_proc002(proc),
            recommended_action=_RECOMMENDED_ACTION_PROC002,
            safe_to_ignore_when=_SAFE_TO_IGNORE_WHEN_PROC002,
            false_positive_risk=_FALSE_POSITIVE_RISK_PROC002,
            requires_admin_to_verify=False,
            created_at=datetime.now(timezone.utc),
            scan_id=scan_id,
        )


__all__ = ["SuspiciousProcessesRule", "RULE_ID_PROC001", "RULE_ID_PROC002", "RULE_VERSION"]