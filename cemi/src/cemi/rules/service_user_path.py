"""Rule: Service binary located in a user profile directory.

A Windows service whose binary path falls inside ``C:\\Users\\<user>\\``
is unusual and warrants investigation.  Because ``ServicesCollector``
already redacts usernames, the rule matches against the already-redacted
path pattern ``C:\\Users\\[REDACTED]\\`` (or the forward-slash equivalent).

No I/O, no network, no subprocess.  All explanatory text is hardcoded.
"""
from __future__ import annotations

import re
from datetime import datetime, timezone
from typing import Any
from uuid import uuid4

from CEMI.cemi.src.cemi.models import (
    Confidence,
    EvidenceItem,
    EvidenceType,
    Finding,
    Severity,
)
from CEMI.cemi.src.cemi.rules.engine import BaseRule
from CEMI.cemi.src.cemi.utils.redact import redact_path

# ---------------------------------------------------------------------------
# Rule identity
# ---------------------------------------------------------------------------

RULE_ID = "SVC-001"
RULE_VERSION = "1.1.0"

# ---------------------------------------------------------------------------
# Detection
# ---------------------------------------------------------------------------

# Matches C:\Users\<any-username>\ or C:/Users/<any-username>/ (any slash mix).
# Accepts both already-redacted paths (C:\Users\[REDACTED]\) and raw paths
# (C:\Users\john\) so the rule is correct regardless of whether the collector
# applied redaction before evaluation.  Evidence values are always re-redacted
# by _make_finding() before being stored in the Finding.
_USER_PATH_RE: re.Pattern[str] = re.compile(
    r"(?i)C:[/\\]Users[/\\][^/\\]+[/\\]"
)

# ---------------------------------------------------------------------------
# Hardcoded explanatory text
# ---------------------------------------------------------------------------

_TITLE = "Service binary in user profile directory"

_OFFICIAL_EXPLANATION = (
    "A Windows service is configured to execute a binary stored inside a "
    "user profile directory (C:\\Users\\...).  Service binaries are "
    "conventionally located in system directories such as "
    "C:\\Windows\\System32 or C:\\Program Files.  A binary in a personal "
    "user folder may indicate a persistence mechanism installed by malware, "
    "a poorly packaged third-party tool, or a developer utility that was "
    "never cleaned up."
)

_IN_OTHER_WORDS = (
    "A background service is running a program from a personal user folder "
    "instead of a standard system location.  This is uncommon for "
    "legitimate software and is worth investigating."
)

_WHY_THIS_MATTERS = (
    "Malware frequently writes persistence components into user profile "
    "directories because doing so does not require administrator privileges.  "
    "A service located here could survive a partial cleanup and restart "
    "automatically on next login or reboot."
)

_RECOMMENDED_ACTION = (
    "Identify the service by name and determine the associated application.  "
    "If the software is unknown or unwanted, stop and disable the service "
    "using the Services snap-in (services.msc) or an elevated terminal, "
    "then investigate the binary with an antivirus or sandboxing tool."
)

_SAFE_TO_IGNORE_WHEN = (
    "The service belongs to a known developer or testing tool (for example "
    "a local development server or test agent) that you deliberately "
    "installed for personal use and that is fully under your control."
)

_FALSE_POSITIVE_RISK = "medium"


# ---------------------------------------------------------------------------
# Rule implementation
# ---------------------------------------------------------------------------


class ServiceUserPathRule(BaseRule):
    """Emit a finding for every service whose binary path is inside C:\\Users\\."""

    def evaluate(
        self,
        items_by_collector: dict[str, list[Any]],
        scan_id: str,
    ) -> list[Finding]:
        findings: list[Finding] = []
        for svc in items_by_collector.get("services", []):
            binary_path: str = svc.get("binary_path") or ""
            if _USER_PATH_RE.search(binary_path):
                findings.append(self._make_finding(svc, binary_path, scan_id))
        return findings

    def _make_finding(
        self,
        svc: dict[str, Any],
        binary_path: str,
        scan_id: str,
    ) -> Finding:
        return Finding(
            id=RULE_ID,
            instance_id=uuid4(),
            rule_version=RULE_VERSION,
            title=_TITLE,
            severity=Severity.MEDIUM,
            confidence=Confidence.MEDIUM,
            app=svc.get("name"),
            category="Service",
            official_explanation=_OFFICIAL_EXPLANATION,
            in_other_words=_IN_OTHER_WORDS,
            why_this_matters=_WHY_THIS_MATTERS,
            evidence=[
                EvidenceItem(
                    type=EvidenceType.FILE_PATH,
                    value=redact_path(binary_path),
                    label="service binary path",
                )
            ],
            recommended_action=_RECOMMENDED_ACTION,
            safe_to_ignore_when=_SAFE_TO_IGNORE_WHEN,
            false_positive_risk=_FALSE_POSITIVE_RISK,
            requires_admin_to_verify=True,
            created_at=datetime.now(timezone.utc),
            scan_id=scan_id,
        )


__all__ = ["ServiceUserPathRule", "RULE_ID", "RULE_VERSION"]
