"""Rule: Native messaging host manifest detected.

Any JSON manifest registered in a Chromium native messaging hosts directory
creates a bridge between a browser extension and a local executable.
Presence alone is worth surfacing — the host may be legitimate, but it is
also a vector used by malware and adware for persistence and data exfiltration.

Evidence values are already redacted by NativeMessagingHostsCollector.
This rule applies redact_path() a second time (defence-in-depth) before
storing paths in EvidenceItem.value.

No I/O, no network, no subprocess.  All explanatory text is hardcoded.
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

# ---------------------------------------------------------------------------
# Rule identity
# ---------------------------------------------------------------------------

RULE_ID = "NMH-001"
RULE_VERSION = "1.0.0"

# ---------------------------------------------------------------------------
# Hardcoded explanatory text
# ---------------------------------------------------------------------------

_TITLE = "Browser Native Messaging Host Detected"

_OFFICIAL_EXPLANATION = (
    "Chromium-based browsers support Native Messaging — a mechanism that allows "
    "a browser extension to communicate with a locally installed executable "
    "program (the 'native host').  The browser reads a JSON manifest file from a "
    "known system or user directory that declares the host's name, the path to "
    "its binary, and which extensions are permitted to connect to it.  The browser "
    "then launches the binary as a subprocess and exchanges messages over stdin/stdout."
)

_IN_OTHER_WORDS = (
    "A browser extension on this machine has permission to run and communicate "
    "with a local program.  Every time a web page uses that extension, the browser "
    "can silently start the local program in the background."
)

_WHY_THIS_MATTERS = (
    "Native messaging creates a bridge between web content and local system "
    "resources.  A malicious or compromised browser extension could use this "
    "channel to exfiltrate data, execute commands, or persist on the system "
    "without requiring administrator privileges.  Unlike browser extensions, the "
    "native host binary runs with full user-level OS permissions and is not "
    "sandboxed by the browser."
)

_RECOMMENDED_ACTION = (
    "Identify the extension listed in the manifest's allowed origins and the "
    "application associated with the binary path.  If you do not recognise the "
    "extension or the application, disable or remove the browser extension and "
    "delete the manifest file.  If the application is known and trusted, verify "
    "that the binary has not been tampered with by checking its digital signature."
)

_SAFE_TO_IGNORE_WHEN = (
    "The native host belongs to a trusted, recognised application — for example "
    "a password manager, a VPN client, or a developer tool — that you deliberately "
    "installed and that requires browser integration to function correctly."
)

_FALSE_POSITIVE_RISK = "medium"

# ---------------------------------------------------------------------------
# Severity / confidence helpers
# ---------------------------------------------------------------------------


def _severity(host: dict[str, Any]) -> Severity:
    """Escalate to HIGH for any manifest anomaly that warrants immediate review."""
    if not host.get("binary_path"):
        return Severity.HIGH
    if not host.get("allowed_origins"):
        return Severity.HIGH
    if host.get("type") != "stdio":
        return Severity.HIGH
    return Severity.MEDIUM


def _confidence(host: dict[str, Any]) -> Confidence:
    """HIGH when we have both key artefacts; MEDIUM when data is incomplete."""
    if host.get("manifest_path") and host.get("binary_path"):
        return Confidence.HIGH
    return Confidence.MEDIUM


# ---------------------------------------------------------------------------
# Rule implementation
# ---------------------------------------------------------------------------


class NativeMessagingHostRule(BaseRule):
    """Emit one finding per native messaging host manifest discovered."""

    def evaluate(
        self,
        items_by_collector: dict[str, list[Any]],
        scan_id: str,
    ) -> list[Finding]:
        findings: list[Finding] = []
        for host in items_by_collector.get("native_messaging_hosts", []):
            findings.append(self._make_finding(host, scan_id))
        return findings

    def _make_finding(self, host: dict[str, Any], scan_id: str) -> Finding:
        is_system = host.get("scope") == "system"
        evidence = self._build_evidence(host)

        return Finding(
            id=RULE_ID,
            instance_id=uuid4(),
            rule_version=RULE_VERSION,
            title=_TITLE,
            severity=_severity(host),
            confidence=_confidence(host),
            app=host.get("name"),
            category="Browser Integration",
            official_explanation=_OFFICIAL_EXPLANATION,
            in_other_words=_IN_OTHER_WORDS,
            why_this_matters=_WHY_THIS_MATTERS,
            evidence=evidence,
            recommended_action=_RECOMMENDED_ACTION,
            safe_to_ignore_when=_SAFE_TO_IGNORE_WHEN,
            false_positive_risk=_FALSE_POSITIVE_RISK,
            requires_admin_to_verify=is_system,
            created_at=datetime.now(timezone.utc),
            scan_id=scan_id,
        )

    def _build_evidence(self, host: dict[str, Any]) -> list[EvidenceItem]:
        items: list[EvidenceItem] = [
            EvidenceItem(
                type=EvidenceType.METADATA,
                value=host.get("browser") or "",
                label="browser",
            ),
            EvidenceItem(
                type=EvidenceType.METADATA,
                value=host.get("scope") or "",
                label="scope",
            ),
            EvidenceItem(
                type=EvidenceType.METADATA,
                value=host.get("name") or "",
                label="host name",
            ),
            EvidenceItem(
                type=EvidenceType.FILE_PATH,
                value=redact_path(host.get("manifest_path") or ""),
                label="manifest path",
            ),
        ]

        binary = host.get("binary_path")
        if binary:
            items.append(
                EvidenceItem(
                    type=EvidenceType.FILE_PATH,
                    value=redact_path(binary),
                    label="binary path",
                )
            )

        # Store only the count — raw allowed_origins values are not included
        # in evidence to limit report detail and avoid surfacing extension IDs.
        origins = host.get("allowed_origins")
        count = len(origins) if isinstance(origins, list) else 0
        items.append(
            EvidenceItem(
                type=EvidenceType.METADATA,
                value=str(count),
                label="allowed origins count",
            )
        )

        return items


__all__ = ["NativeMessagingHostRule", "RULE_ID", "RULE_VERSION"]
