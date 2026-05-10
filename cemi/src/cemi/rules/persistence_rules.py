"""Persistence and malware-style behavior rules for CEMÍ.

Three rules covering suspicious persistence mechanisms and spyware-like capabilities.
All rules operate on items collected by various collectors.

PERSIST-001  Unsigned executable in user-writable location
PERSIST-002  Auto-start from user-writable location
PERSIST-003  Browser extension with spyware-like permissions
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
from cemi.utils.redact import redact_path

# ===========================================================================
# PERSIST-001 — Unsigned Executable in User-Writable Location
# ===========================================================================

_PERSIST001_ID = "PERSIST-001"
_PERSIST001_VERSION = "1.0.0"

_PERSIST001_TITLE = "Unsigned or Unknown Executable in User-Writable Location"

_PERSIST001_OFFICIAL_EXPLANATION = (
    "An executable with unknown trust status was found in a user-writable location. "
    "This could indicate malware or unauthorized software installation."
)

_PERSIST001_IN_OTHER_WORDS = (
    "A program that Windows may not fully trust is sitting in a place where normal apps and malware often hide."
)

_PERSIST001_WHY_THIS_MATTERS = (
    "Malware often runs from user folders because those locations are easier to write to than Program Files or Windows system directories."
)

_PERSIST001_RECOMMENDED_ACTION = (
    "Verify the app publisher, scan the file with trusted security tools, and remove or quarantine only if you understand the impact."
)

_USER_WRITABLE_PATH_PATTERNS = [
    "c:\\users\\",
    "\\appdata\\",
    "\\temp\\",
    "\\localappdata\\",
    "\\downloads\\",
]


class PersistUnsignedUserWritableRule(BaseRule):
    """Rule for unsigned executables in user-writable locations."""

    def evaluate(
        self,
        items_by_collector: dict[str, list[Any]],
        scan_id: str,
    ) -> list[Finding]:
        findings = []

        # Get signature items
        sig_items = items_by_collector.get("signatures", [])

        for sig in sig_items:
            if not sig.get("exists", False) or not sig.get("is_executable", False):
                continue

            path = sig.get("path", "")
            if not _is_user_writable_path(path):
                continue

            sig_status = sig.get("signature_status")
            if sig_status not in ("unknown", "unsigned", None):
                continue

            evidence = [
                EvidenceItem(
                    type=EvidenceType.FILE_PATH,
                    value=sig.get("path_redacted", ""),
                    label="executable path",
                ),
                EvidenceItem(
                    type=EvidenceType.SIGNATURE_STATUS,
                    value=sig_status or "unknown",
                    label="signature status",
                ),
            ]

            findings.append(Finding(
                id=_PERSIST001_ID,
                instance_id=uuid4(),
                rule_version=_PERSIST001_VERSION,
                title=_PERSIST001_TITLE,
                severity=Severity.HIGH,
                confidence=Confidence.MEDIUM,
                app=None,
                category="Persistence",
                official_explanation=_PERSIST001_OFFICIAL_EXPLANATION,
                in_other_words=_PERSIST001_IN_OTHER_WORDS,
                why_this_matters=_PERSIST001_WHY_THIS_MATTERS,
                evidence=evidence,
                recommended_action=_PERSIST001_RECOMMENDED_ACTION,
                safe_to_ignore_when="The executable is from a trusted source and has been verified.",
                false_positive_risk="low",
                requires_admin_to_verify=False,
                created_at=datetime.now(timezone.utc),
                scan_id=scan_id,
            ))

        return findings


# ===========================================================================
# PERSIST-002 — Auto-Start Entry from User-Writable Location
# ===========================================================================

_PERSIST002_ID = "PERSIST-002"
_PERSIST002_VERSION = "1.0.0"

_PERSIST002_TITLE = "Auto-Start Entry from User-Writable Location"

_PERSIST002_OFFICIAL_EXPLANATION = (
    "A startup entry points to an executable in a user-writable location. "
    "This could allow persistence for malware or unauthorized software."
)

_PERSIST002_IN_OTHER_WORDS = (
    "A program from a user folder made itself start when your computer starts."
)

_PERSIST002_WHY_THIS_MATTERS = (
    "Legitimate software usually installs to protected system directories. "
    "User folders are common hiding places for malware."
)

_PERSIST002_RECOMMENDED_ACTION = (
    "Verify the startup entry and executable. Remove suspicious entries from startup."
)


class PersistStartupUserWritableRule(BaseRule):
    """Rule for startup entries from user-writable locations."""

    def evaluate(
        self,
        items_by_collector: dict[str, list[Any]],
        scan_id: str,
    ) -> list[Finding]:
        findings = []

        startup_items = items_by_collector.get("startup", [])

        for item in startup_items:
            path_redacted = item.get("path_redacted")
            if not path_redacted:
                continue

            # Check if path is user-writable (simplified check on redacted path)
            if not any(uw in path_redacted for uw in ["Users", "AppData", "Temp", "Downloads"]):
                continue

            evidence = [
                EvidenceItem(
                    type=EvidenceType.REGISTRY_KEY,
                    value=item.get("name", ""),
                    label="startup entry name",
                ),
                EvidenceItem(
                    type=EvidenceType.FILE_PATH,
                    value=path_redacted,
                    label="executable path",
                ),
            ]

            findings.append(Finding(
                id=_PERSIST002_ID,
                instance_id=uuid4(),
                rule_version=_PERSIST002_VERSION,
                title=_PERSIST002_TITLE,
                severity=Severity.HIGH,
                confidence=Confidence.MEDIUM,
                app=None,
                category="Persistence",
                official_explanation=_PERSIST002_OFFICIAL_EXPLANATION,
                in_other_words=_PERSIST002_IN_OTHER_WORDS,
                why_this_matters=_PERSIST002_WHY_THIS_MATTERS,
                evidence=evidence,
                recommended_action=_PERSIST002_RECOMMENDED_ACTION,
                safe_to_ignore_when="The startup entry is from a trusted application.",
                false_positive_risk="medium",
                requires_admin_to_verify=False,
                created_at=datetime.now(timezone.utc),
                scan_id=scan_id,
            ))

        return findings


# ===========================================================================
# PERSIST-003 — Browser Extension with Spyware-Like Permissions
# ===========================================================================

_PERSIST003_ID = "PERSIST-003"
_PERSIST003_VERSION = "1.0.0"

_PERSIST003_TITLE = "Browser Extension with Spyware-Like Permissions"

_PERSIST003_OFFICIAL_EXPLANATION = (
    "A browser extension has permissions that could enable broad monitoring if abused."
)

_PERSIST003_IN_OTHER_WORDS = (
    "This browser extension could spy on everything you do online if it wanted to."
)

_PERSIST003_WHY_THIS_MATTERS = (
    "Extensions with these permissions have the technical capability to monitor your browsing, steal data, or inject malware."
)

_PERSIST003_RECOMMENDED_ACTION = (
    "Review the extension's permissions and publisher. Remove if unnecessary or suspicious."
)


class PersistExtensionSpywareRule(BaseRule):
    """Rule for browser extensions with spyware-like permissions."""

    def evaluate(
        self,
        items_by_collector: dict[str, list[Any]],
        scan_id: str,
    ) -> list[Finding]:
        findings = []

        ext_items = items_by_collector.get("browser_extensions", [])

        for ext in ext_items:
            permissions = ext.get("permissions", [])
            host_permissions = ext.get("host_permissions", [])

            has_all_urls = "<all_urls>" in host_permissions
            has_cookies = "cookies" in permissions
            has_scripting = "scripting" in permissions
            has_web_request = "webRequest" in permissions
            has_native_messaging = "nativeMessaging" in permissions

            if not has_all_urls:
                continue

            # Check for dangerous combinations
            dangerous = has_cookies or has_scripting or has_web_request or has_native_messaging

            if not dangerous:
                continue

            severity = Severity.HIGH
            if has_native_messaging:
                severity = Severity.CRITICAL

            evidence = [
                EvidenceItem(
                    type=EvidenceType.METADATA,
                    value=ext.get("name", ""),
                    label="extension name",
                ),
                EvidenceItem(
                    type=EvidenceType.METADATA,
                    value=str(len(permissions)),
                    label="permissions count",
                ),
            ]

            findings.append(Finding(
                id=_PERSIST003_ID,
                instance_id=uuid4(),
                rule_version=_PERSIST003_VERSION,
                title=_PERSIST003_TITLE,
                severity=severity,
                confidence=Confidence.MEDIUM,
                app=ext.get("name"),
                category="Browser",
                official_explanation=_PERSIST003_OFFICIAL_EXPLANATION,
                in_other_words=_PERSIST003_IN_OTHER_WORDS,
                why_this_matters=_PERSIST003_WHY_THIS_MATTERS,
                evidence=evidence,
                recommended_action=_PERSIST003_RECOMMENDED_ACTION,
                safe_to_ignore_when="The extension is from a trusted publisher and you understand its purpose.",
                false_positive_risk="low",
                requires_admin_to_verify=False,
                created_at=datetime.now(timezone.utc),
                scan_id=scan_id,
            ))

        return findings


def _is_user_writable_path(path: str) -> bool:
    """Check if path is in user-writable location."""
    path_lower = path.lower().replace("/", "\\")
    return any(pattern in path_lower for pattern in _USER_WRITABLE_PATH_PATTERNS)