"""Extension-to-native-host correlation rule for CEMÍ.

Detects when a Chromium extension ID is explicitly listed in a native messaging
host manifest's allowlist. This is a stronger signal than the broad bridge
capability rule, because it identifies a direct, named browser-to-local-app
integration.
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

RULE_ID = "CORR-001"
RULE_VERSION = "1.0.0"

_TITLE = "Extension Can Communicate With Local Application"

_OFFICIAL_EXPLANATION = (
    "Chromium Native Messaging allows approved browser extensions to communicate "
    "with a locally installed native application through a manifest allowlist. "
    "This rule flags explicit extension-to-host mappings where the extension ID "
    "is listed in the native host's allowed_origins."
)

_IN_OTHER_WORDS = (
    "This browser extension is specifically allowed to talk to a program "
    "installed on your computer."
)

_WHY_THIS_MATTERS = (
    "If the extension is compromised or overly broad, it may bridge website "
    "activity to a local executable outside the normal browser sandbox."
)

_RECOMMENDED_ACTION = (
    "Verify the extension, host application, and vendor. Remove the extension "
    "or native host if this connection is unexpected."
)

_SAFE_TO_IGNORE_WHEN = (
    "You intentionally installed a trusted app that requires browser integration, "
    "such as a password manager, developer tool, or trusted AI assistant."
)

_FALSE_POSITIVE_RISK = "medium"


def _severity(ext: dict[str, Any], host: dict[str, Any]) -> Severity:
    host_permissions = ext.get("host_permissions") or []
    permissions = ext.get("permissions") or []
    if "<all_urls>" in host_permissions and any(
        perm in permissions for perm in ("cookies", "scripting", "webRequest")
    ):
        return Severity.CRITICAL
    return Severity.HIGH


def _confidence(ext: dict[str, Any], host: dict[str, Any]) -> Confidence:
    if ext.get("extension_id") and host.get("name") and host.get("manifest_path"):
        return Confidence.HIGH
    return Confidence.MEDIUM


def _matches_allowed_origin(extension_id: str, origin: str) -> bool:
    if not extension_id or not origin:
        return False
    normalized = origin.strip()
    exact = f"chrome-extension://{extension_id}"
    return normalized == exact or normalized == f"{exact}/"


def _build_evidence(ext: dict[str, Any], host: dict[str, Any]) -> list[EvidenceItem]:
    evidence: list[EvidenceItem] = [
        EvidenceItem(
            type=EvidenceType.METADATA,
            value=ext.get("browser") or "",
            label="browser",
        ),
        EvidenceItem(
            type=EvidenceType.METADATA,
            value=ext.get("extension_id") or "",
            label="extension_id",
        ),
        EvidenceItem(
            type=EvidenceType.METADATA,
            value=ext.get("name") or "",
            label="extension_name",
        ),
        EvidenceItem(
            type=EvidenceType.METADATA,
            value=host.get("name") or "",
            label="native_host_name",
        ),
        EvidenceItem(
            type=EvidenceType.METADATA,
            value=host.get("scope") or "",
            label="native_host_scope",
        ),
    ]

    extension_manifest_path = ext.get("manifest_path") or ""
    if extension_manifest_path:
        evidence.append(
            EvidenceItem(
                type=EvidenceType.FILE_PATH,
                value=redact_path(extension_manifest_path),
                label="extension_manifest_path",
            )
        )

    native_manifest_path = host.get("manifest_path") or ""
    if native_manifest_path:
        evidence.append(
            EvidenceItem(
                type=EvidenceType.FILE_PATH,
                value=redact_path(native_manifest_path),
                label="native_manifest_path",
            )
        )

    native_binary_path = host.get("binary_path")
    if native_binary_path:
        evidence.append(
            EvidenceItem(
                type=EvidenceType.FILE_PATH,
                value=redact_path(native_binary_path),
                label="native_binary_path",
            )
        )

    return evidence


class CorrelatedExtensionNativeHostRule(BaseRule):
    """CORR-001: detect explicit extension-to-native-host allowlist links."""

    def evaluate(
        self,
        items_by_collector: dict[str, list[Any]],
        scan_id: str,
    ) -> list[Finding]:
        findings: list[Finding] = []
        extensions = items_by_collector.get("browser_extensions", [])
        native_hosts = items_by_collector.get("native_messaging_hosts", [])

        if not extensions or not native_hosts:
            return []

        for ext in extensions:
            extension_id = ext.get("extension_id")
            if not extension_id:
                continue

            for host in native_hosts:
                allowed_origins = host.get("allowed_origins") or []
                if any(_matches_allowed_origin(extension_id, origin) for origin in allowed_origins):
                    findings.append(self._make_finding(ext, host, scan_id))

        return findings

    def _make_finding(
        self,
        ext: dict[str, Any],
        host: dict[str, Any],
        scan_id: str,
    ) -> Finding:
        is_system = host.get("scope") == "system"
        return Finding(
            id=RULE_ID,
            instance_id=uuid4(),
            rule_version=RULE_VERSION,
            title=_TITLE,
            severity=_severity(ext, host),
            confidence=_confidence(ext, host),
            app=ext.get("name"),
            category="Browser Integration",
            official_explanation=_OFFICIAL_EXPLANATION,
            in_other_words=_IN_OTHER_WORDS,
            why_this_matters=_WHY_THIS_MATTERS,
            evidence=_build_evidence(ext, host),
            recommended_action=_RECOMMENDED_ACTION,
            safe_to_ignore_when=_SAFE_TO_IGNORE_WHEN,
            false_positive_risk=_FALSE_POSITIVE_RISK,
            requires_admin_to_verify=is_system,
            created_at=datetime.now(timezone.utc),
            scan_id=scan_id,
        )


__all__ = ["CorrelatedExtensionNativeHostRule", "RULE_ID", "RULE_VERSION"]
