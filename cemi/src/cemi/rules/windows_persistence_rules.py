"""Windows persistence rules for startup and scheduled task metadata."""
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

RULE_ID_RUNONCE = "WINPERSIST-001"
RULE_ID_SUSPICIOUS_POWERSHELL = "WINPERSIST-002"
RULE_ID_LOLBIN = "WINPERSIST-003"
RULE_VERSION = "1.0.0"

_SUSPICIOUS_POWERSHELL_FLAGS = [
    "-enc",
    "-encodedcommand",
    "-nop",
    "-noprofile",
    "-w hidden",
    "-windowstyle hidden",
    "bypass",
    "downloadstring",
    "invoke-expression",
    "iex",
]

_LOLBIN_COMMANDS = [
    "rundll32",
    "regsvr32",
    "mshta",
    "wscript",
    "cscript",
    "certutil",
    "bitsadmin",
    "powershell",
    "pwsh",
]

_FALSE_POSITIVE_RISK = "medium"

_TITLE_RUNONCE = "RunOnce Persistence Entry Detected"
_OFFICIAL_EXPLANATION_RUNONCE = (
    "A Windows RunOnce startup entry is configured. RunOnce can be used by installers or malware "
    "to execute code once after the next login or reboot."
)
_IN_OTHER_WORDS_RUNONCE = "A program is configured to execute once at the next login or startup."
_WHY_THIS_MATTERS_RUNONCE = (
    "RunOnce entries are a legitimate persistence mechanism, but they are also used by malware "
    "and post-install setup routines to execute after reboot."
)
_RECOMMENDED_ACTION_RUNONCE = (
    "Review the RunOnce entry. If it is not part of a trusted installer or upgrade process, disable or remove it."
)

_TITLE_POWERSHELL = "Suspicious PowerShell Startup Command"
_OFFICIAL_EXPLANATION_POWERSHELL = (
    "A startup or scheduled task command uses PowerShell with options commonly seen in malicious scripts."
)
_IN_OTHER_WORDS_POWERSHELL = (
    "Detected PowerShell execution at startup with suspicious flags or encoded payloads."
)
_WHY_THIS_MATTERS_POWERSHELL = (
    "PowerShell is a legitimate system tool, but certain startup uses with encoded commands, hidden windows, "
    "or execution bypass are strongly associated with malware and attacker tooling."
)
_RECOMMENDED_ACTION_POWERSHELL = (
    "Inspect the startup command and verify whether the PowerShell invocation is expected."
)

_TITLE_LOLBIN = "LOLBin Startup or Scheduled Task Command"
_OFFICIAL_EXPLANATION_LOLBIN = (
    "A startup or scheduled task action references a living-off-the-land binary (LOLBin) often abused by attackers."
)
_IN_OTHER_WORDS_LOLBIN = (
    "A built-in Windows command or scripting host is being used in startup metadata."
)
_WHY_THIS_MATTERS_LOLBIN = (
    "Attackers frequently use legitimate Windows binaries such as rundll32, regsvr32, and mshta for persistence and execution."
)
_RECOMMENDED_ACTION_LOLBIN = (
    "Review the command and determine whether the use of a LOLBin at startup is expected."
)


def _normalize_text(value: Any) -> str:
    return str(value or "").strip().lower()


def _is_user_writable_path(value: str) -> bool:
    if not value:
        return False
    lower_value = value.lower()
    return any(keyword in lower_value for keyword in ["c:\\users\\", "appdata", "temp", "downloads"])


def _build_evidence(item: dict[str, Any]) -> list[EvidenceItem]:
    evidence: list[EvidenceItem] = [
        EvidenceItem(type=EvidenceType.METADATA, value=item.get("name", "[unknown]"), label="entry_name"),
        EvidenceItem(type=EvidenceType.METADATA, value=item.get("source", "[unknown]"), label="source"),
        EvidenceItem(type=EvidenceType.METADATA, value=item.get("scope", "[unknown]"), label="scope"),
    ]

    if "command" in item and item.get("command"):
        evidence.append(
            EvidenceItem(
                type=EvidenceType.FILE_PATH,
                value=item["command"],
                label="command",
            )
        )
    if "action_command_redacted" in item and item.get("action_command_redacted"):
        evidence.append(
            EvidenceItem(
                type=EvidenceType.FILE_PATH,
                value=item["action_command_redacted"],
                label="action_command_redacted",
            )
        )
    if "action_arguments_redacted" in item and item.get("action_arguments_redacted"):
        evidence.append(
            EvidenceItem(
                type=EvidenceType.METADATA,
                value=item["action_arguments_redacted"],
                label="action_arguments_redacted",
            )
        )
    return evidence


def _has_suspicious_powershell_flags(text: str) -> bool:
    return any(flag in text for flag in _SUSPICIOUS_POWERSHELL_FLAGS)


def _contains_lolbin(text: str) -> bool:
    return any(command in text for command in _LOLBIN_COMMANDS)


def _extract_command_text(item: dict[str, Any]) -> str:
    if item.get("command"):
        return _normalize_text(item["command"])
    return _normalize_text(f"{item.get('action_command_redacted', '')} {item.get('action_arguments_redacted', '')}")


def _build_finding(
    id: str,
    title: str,
    official_explanation: str,
    in_other_words: str,
    why_this_matters: str,
    recommended_action: str,
    item: dict[str, Any],
    scan_id: str,
    severity: Severity,
    contextual_confidence: str,
) -> Finding:
    return Finding(
        id=id,
        instance_id=uuid4(),
        rule_version=RULE_VERSION,
        title=title,
        severity=severity,
        confidence=Confidence.MEDIUM,
        contextual_confidence=contextual_confidence,
        app=item.get("name"),
        category="Persistence",
        official_explanation=official_explanation,
        in_other_words=in_other_words,
        why_this_matters=why_this_matters,
        evidence=_build_evidence(item),
        recommended_action=recommended_action,
        safe_to_ignore_when=(
            "You installed a one-time launcher intentionally."
            if id == RULE_ID_RUNONCE
            else None
        ),
        false_positive_risk=_FALSE_POSITIVE_RISK,
        requires_admin_to_verify=(item.get("scope") == "system"),
        created_at=datetime.now(timezone.utc),
        scan_id=scan_id,
    )


class RunOncePersistenceRule(BaseRule):
    """WINPERSIST-001: Detect RunOnce persistence entries."""

    def evaluate(self, items_by_collector: dict[str, list[Any]], scan_id: str) -> list[Finding]:
        findings: list[Finding] = []
        startup_items = items_by_collector.get("startup", [])

        for item in startup_items:
            if "runonce" in _normalize_text(item.get("source")):
                findings.append(
                    _build_finding(
                        RULE_ID_RUNONCE,
                        _TITLE_RUNONCE,
                        _OFFICIAL_EXPLANATION_RUNONCE,
                        _IN_OTHER_WORDS_RUNONCE,
                        _WHY_THIS_MATTERS_RUNONCE,
                        _RECOMMENDED_ACTION_RUNONCE,
                        item,
                        scan_id,
                        Severity.MEDIUM,
                        "medium",
                    )
                )
        return findings


class SuspiciousPowerShellStartupRule(BaseRule):
    """WINPERSIST-002: Detect suspicious PowerShell commands in startup metadata."""

    def evaluate(self, items_by_collector: dict[str, list[Any]], scan_id: str) -> list[Finding]:
        findings: list[Finding] = []
        candidates = []
        candidates.extend(items_by_collector.get("startup", []))
        candidates.extend(items_by_collector.get("scheduled_tasks", []))

        for item in candidates:
            text = _extract_command_text(item)
            if any(marker in text for marker in ("powershell", "pwsh")) and _has_suspicious_powershell_flags(text):
                findings.append(
                    _build_finding(
                        RULE_ID_SUSPICIOUS_POWERSHELL,
                        _TITLE_POWERSHELL,
                        _OFFICIAL_EXPLANATION_POWERSHELL,
                        _IN_OTHER_WORDS_POWERSHELL,
                        _WHY_THIS_MATTERS_POWERSHELL,
                        _RECOMMENDED_ACTION_POWERSHELL,
                        item,
                        scan_id,
                        Severity.HIGH,
                        "high",
                    )
                )
        return findings


class LolbinStartupTaskRule(BaseRule):
    """WINPERSIST-003: Detect LOLBin command usage in startup or scheduled task metadata."""

    def evaluate(self, items_by_collector: dict[str, list[Any]], scan_id: str) -> list[Finding]:
        findings: list[Finding] = []
        candidates = []
        candidates.extend(items_by_collector.get("startup", []))
        candidates.extend(items_by_collector.get("scheduled_tasks", []))

        for item in candidates:
            text = _extract_command_text(item)
            if not _contains_lolbin(text):
                continue

            severity = Severity.MEDIUM
            if _has_suspicious_powershell_flags(text) or _is_user_writable_path(text):
                severity = Severity.HIGH

            findings.append(
                _build_finding(
                    RULE_ID_LOLBIN,
                    _TITLE_LOLBIN,
                    _OFFICIAL_EXPLANATION_LOLBIN,
                    _IN_OTHER_WORDS_LOLBIN,
                    _WHY_THIS_MATTERS_LOLBIN,
                    _RECOMMENDED_ACTION_LOLBIN,
                    item,
                    scan_id,
                    severity,
                    "medium" if severity == Severity.MEDIUM else "high",
                )
            )
        return findings


__all__ = [
    "RunOncePersistenceRule",
    "SuspiciousPowerShellStartupRule",
    "LolbinStartupTaskRule",
    "RULE_ID_RUNONCE",
    "RULE_ID_SUSPICIOUS_POWERSHELL",
    "RULE_ID_LOLBIN",
    "RULE_VERSION",
]
