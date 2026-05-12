"""Browser extension risk rules for CEMÍ.

Four rules covering the most common privilege-abuse patterns seen in Chromium
extensions.  All rules operate on items collected by BrowserExtensionsCollector
(collector name: ``"browser_extensions"``).

EXT-001  Extension has access to all websites          (<all_urls> host permission)
EXT-002  Extension can access cookies                  (cookies permission)
EXT-003  Extension can inject scripts & intercept      (scripting + webRequest)
EXT-004  Extension has browser-to-app bridge           (scripting + native hosts present)

Evidence constraints:
* No raw permission strings are stored in evidence — only counts and descriptive
  labels are included.
* manifest_path is already redacted by the collector; redact_path() is applied
  a second time as defence-in-depth.
* No I/O, no network, no subprocess.
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
# Shared helpers
# ---------------------------------------------------------------------------


def _ext_evidence(ext: dict[str, Any]) -> list[EvidenceItem]:
    """Return non-sensitive metadata evidence items common to all four rules.

    Includes browser name, extension display name (if any), permission counts,
    and the already-redacted manifest path — no raw permission strings.
    """
    items: list[EvidenceItem] = [
        EvidenceItem(
            type=EvidenceType.METADATA,
            value=ext.get("browser") or "",
            label="browser",
        ),
        EvidenceItem(
            type=EvidenceType.METADATA,
            value=ext.get("name") or "",
            label="extension name",
        ),
        EvidenceItem(
            type=EvidenceType.METADATA,
            value=str(len(ext.get("permissions") or [])),
            label="permissions count",
        ),
        EvidenceItem(
            type=EvidenceType.METADATA,
            value=str(len(ext.get("host_permissions") or [])),
            label="host permissions count",
        ),
    ]
    manifest_path = ext.get("manifest_path") or ""
    if manifest_path:
        items.append(
            EvidenceItem(
                type=EvidenceType.FILE_PATH,
                value=redact_path(manifest_path),
                label="manifest path",
            )
        )
    return items


# ===========================================================================
# EXT-001 — Extension Has Access to All Websites
# ===========================================================================

_EXT001_ID = "EXT-001"
_EXT001_VERSION = "1.0.0"

_EXT001_TITLE = "Extension Has Access to All Websites"

_EXT001_OFFICIAL_EXPLANATION = (
    "The extension declares the '<all_urls>' pattern in its host_permissions "
    "field, granting it the ability to read and modify content on every "
    "website the user visits.  This is the broadest possible host-permission "
    "scope available to a Chromium extension."
)

_EXT001_IN_OTHER_WORDS = (
    "This browser extension can see and change the content of every single "
    "website you open — your banking site, your email, any web app.  Most "
    "legitimate extensions only need access to specific domains, not everything."
)

_EXT001_WHY_IT_MATTERS = (
    "A malicious or compromised extension with all-URL access can silently "
    "harvest form data (passwords, credit card numbers), modify pages to "
    "inject ads or phishing prompts, and exfiltrate session cookies — all "
    "without any visible change to the browser."
)

_EXT001_RECOMMENDED_ACTION = (
    "Identify the extension by name and verify it is published by a trusted "
    "developer.  If the extension does not have a clear, legitimate reason to "
    "access all websites, consider removing it from the browser.  Check "
    "browser extension settings for recent additions you do not recognise."
)

_EXT001_SAFE_TO_IGNORE_WHEN = (
    "The extension is a well-known, widely-audited tool — such as an "
    "ad-blocker, a password manager, or a developer utility — whose "
    "all-URL access is documented, expected, and required for its "
    "core functionality."
)

_EXT001_FP_RISK = "medium"


class ExtAllUrlsRule(BaseRule):
    """EXT-001: fire for every extension that requests '<all_urls>' host access."""

    def evaluate(
        self,
        items_by_collector: dict[str, list[Any]],
        scan_id: str,
    ) -> list[Finding]:
        findings: list[Finding] = []
        for ext in items_by_collector.get("browser_extensions", []):
            host_perms = ext.get("host_permissions") or []
            if "<all_urls>" in host_perms:
                findings.append(self._make_finding(ext, scan_id))
        return findings

    def _make_finding(self, ext: dict[str, Any], scan_id: str) -> Finding:
        return Finding(
            id=_EXT001_ID,
            instance_id=uuid4(),
            rule_version=_EXT001_VERSION,
            title=_EXT001_TITLE,
            severity=Severity.MEDIUM,
            confidence=Confidence.MEDIUM,
            app=ext.get("name"),
            category="Browser Extension",
            official_explanation=_EXT001_OFFICIAL_EXPLANATION,
            in_other_words=_EXT001_IN_OTHER_WORDS,
            why_this_matters=_EXT001_WHY_IT_MATTERS,
            evidence=_ext_evidence(ext),
            recommended_action=_EXT001_RECOMMENDED_ACTION,
            safe_to_ignore_when=_EXT001_SAFE_TO_IGNORE_WHEN,
            false_positive_risk=_EXT001_FP_RISK,
            requires_admin_to_verify=False,
            created_at=datetime.now(timezone.utc),
            scan_id=scan_id,
        )


# ===========================================================================
# EXT-002 — Extension Can Access Cookies
# ===========================================================================

_EXT002_ID = "EXT-002"
_EXT002_VERSION = "1.0.0"

_EXT002_TITLE = "Extension Can Access Cookies"

_EXT002_OFFICIAL_EXPLANATION = (
    "The extension declares the 'cookies' permission, allowing it to read, "
    "create, modify, and delete cookies for any origin it also has host access "
    "to.  This permission is required for legitimate session-management tools "
    "but is also a primary vector for session-hijacking attacks."
)

_EXT002_IN_OTHER_WORDS = (
    "This extension can read the login cookies that keep you signed in to "
    "websites. Most password managers and some other tools legitimately need this access."
)

_EXT002_WHY_IT_MATTERS = (
    "Session cookies are high-value targets.  A stolen cookie bypasses "
    "multi-factor authentication and grants immediate access to the "
    "victim's accounts.  Malware distributed through browser extension "
    "stores frequently abuses cookie access for account takeover."
)

_EXT002_RECOMMENDED_ACTION = (
    "Check if the extension genuinely needs cookie access for its stated "
    "purpose (such as a password manager). If you don't recognize the extension or it doesn't "
    "need cookies, consider removing it and changing passwords for any accounts you "
    "accessed recently in that browser."
)

_EXT002_SAFE_TO_IGNORE_WHEN = (
    "The extension is a known password manager, developer tool, or session "
    "management utility whose cookie access is documented and expected."
)

_EXT002_FP_RISK = "medium"


class ExtCookiesRule(BaseRule):
    """EXT-002: fire for every extension that requests the 'cookies' permission."""

    def evaluate(
        self,
        items_by_collector: dict[str, list[Any]],
        scan_id: str,
    ) -> list[Finding]:
        findings: list[Finding] = []
        for ext in items_by_collector.get("browser_extensions", []):
            perms = ext.get("permissions") or []
            if "cookies" in perms:
                findings.append(self._make_finding(ext, scan_id))
        return findings

    def _make_finding(self, ext: dict[str, Any], scan_id: str) -> Finding:
        return Finding(
            id=_EXT002_ID,
            instance_id=uuid4(),
            rule_version=_EXT002_VERSION,
            title=_EXT002_TITLE,
            severity=Severity.LOW,
            confidence=Confidence.MEDIUM,
            app=ext.get("name"),
            category="Browser Extension",
            official_explanation=_EXT002_OFFICIAL_EXPLANATION,
            in_other_words=_EXT002_IN_OTHER_WORDS,
            why_this_matters=_EXT002_WHY_IT_MATTERS,
            evidence=_ext_evidence(ext),
            recommended_action=_EXT002_RECOMMENDED_ACTION,
            safe_to_ignore_when=_EXT002_SAFE_TO_IGNORE_WHEN,
            false_positive_risk=_EXT002_FP_RISK,
            requires_admin_to_verify=False,
            created_at=datetime.now(timezone.utc),
            scan_id=scan_id,
        )


# ===========================================================================
# EXT-003 — Extension Can Inject Scripts and Intercept Traffic
# ===========================================================================

_EXT003_ID = "EXT-003"
_EXT003_VERSION = "1.0.0"

_EXT003_TITLE = "Extension Can Inject Scripts and Intercept Traffic"

_EXT003_OFFICIAL_EXPLANATION = (
    "The extension declares both the 'scripting' and 'webRequest' permissions. "
    "'scripting' allows the extension to inject and execute arbitrary JavaScript "
    "in any tab it has host access to.  'webRequest' allows it to observe, block, "
    "and modify every HTTP/HTTPS request and response the browser makes.  "
    "Together these two permissions represent the maximum possible network and "
    "DOM-level surveillance capability available to an extension."
)

_EXT003_IN_OTHER_WORDS = (
    "This extension can run its own code inside every webpage you visit and "
    "can intercept, read, or alter every network request your browser sends — "
    "including logins, form submissions, and API calls."
)

_EXT003_WHY_IT_MATTERS = (
    "The scripting + webRequest combination is a powerful surveillance toolkit. "
    "It enables keylogging on web forms, credential theft, ad injection, "
    "real-time traffic analysis, and man-in-the-browser attacks.  This "
    "combination should be present only in well-audited security tools or "
    "developer utilities."
)

_EXT003_RECOMMENDED_ACTION = (
    "Scrutinise this extension carefully.  Verify the publisher's identity and "
    "check independent security reviews.  Unless you deliberately installed a "
    "security or developer tool that requires these capabilities, remove the "
    "extension from your browser."
)

_EXT003_SAFE_TO_IGNORE_WHEN = (
    "The extension is a known and trusted web security tool, developer proxy, "
    "or ad-blocker with a published, independently-reviewed open-source "
    "codebase that requires both capabilities to function."
)

_EXT003_FP_RISK = "low"


class ExtScriptingWebRequestRule(BaseRule):
    """EXT-003: fire when an extension has both 'scripting' and 'webRequest'."""

    def evaluate(
        self,
        items_by_collector: dict[str, list[Any]],
        scan_id: str,
    ) -> list[Finding]:
        findings: list[Finding] = []
        for ext in items_by_collector.get("browser_extensions", []):
            perms = ext.get("permissions") or []
            if "scripting" in perms and "webRequest" in perms:
                findings.append(self._make_finding(ext, scan_id))
        return findings

    def _make_finding(self, ext: dict[str, Any], scan_id: str) -> Finding:
        return Finding(
            id=_EXT003_ID,
            instance_id=uuid4(),
            rule_version=_EXT003_VERSION,
            title=_EXT003_TITLE,
            severity=Severity.HIGH,
            confidence=Confidence.MEDIUM,
            app=ext.get("name"),
            category="Browser Extension",
            official_explanation=_EXT003_OFFICIAL_EXPLANATION,
            in_other_words=_EXT003_IN_OTHER_WORDS,
            why_this_matters=_EXT003_WHY_IT_MATTERS,
            evidence=_ext_evidence(ext),
            recommended_action=_EXT003_RECOMMENDED_ACTION,
            safe_to_ignore_when=_EXT003_SAFE_TO_IGNORE_WHEN,
            false_positive_risk=_EXT003_FP_RISK,
            requires_admin_to_verify=False,
            created_at=datetime.now(timezone.utc),
            scan_id=scan_id,
        )


# ===========================================================================
# EXT-004 — Extension Has Browser-to-App Bridge Capability
# ===========================================================================

_EXT004_ID = "EXT-004"
_EXT004_VERSION = "1.0.0"

_EXT004_TITLE = "Extension Has Browser-to-App Bridge Capability"

_EXT004_OFFICIAL_EXPLANATION = (
    "An installed browser extension has the 'scripting' permission, and at "
    "least one native messaging host manifest is also present on this machine. "
    "'scripting' lets an extension inject code into web pages; native messaging "
    "lets a browser extension communicate with a local executable outside the "
    "browser sandbox.  When both are present together, an extension that can "
    "manipulate web pages can also relay data to or from a local process."
)

_EXT004_IN_OTHER_WORDS = (
    "A browser extension that can modify web pages is installed alongside a "
    "program that can act as a silent bridge between your browser and your "
    "local system.  If the extension is malicious, it could use that bridge to "
    "send stolen data — or receive commands — without ever touching the network "
    "in an obvious way."
)

_EXT004_WHY_IT_MATTERS = (
    "Combining DOM-level script injection with native messaging creates a "
    "covert channel: web content is exfiltrated to a local process that can "
    "then forward it via any mechanism (file write, named pipe, OS API) without "
    "appearing in the browser's network log.  This is a pattern used by "
    "sophisticated browser-based malware and adware."
)

_EXT004_RECOMMENDED_ACTION = (
    "Review both the extension and the native messaging host manifest flagged "
    "by the accompanying NMH-001 finding.  Confirm they belong to the same "
    "trusted application and that the combination is expected.  If either is "
    "unrecognised, remove the extension and delete the native messaging host "
    "manifest file."
)

_EXT004_SAFE_TO_IGNORE_WHEN = (
    "Both the extension and the native messaging host belong to a single, "
    "trusted application — such as a password manager or a VPN client — "
    "where the browser integration is a deliberate, documented feature."
)

_EXT004_FP_RISK = "low"


class ExtBridgeCapabilityRule(BaseRule):
    """EXT-004: fire when a scripting extension co-exists with native hosts."""

    def evaluate(
        self,
        items_by_collector: dict[str, list[Any]],
        scan_id: str,
    ) -> list[Finding]:
        native_hosts = items_by_collector.get("native_messaging_hosts") or []
        if not native_hosts:
            return []

        native_host_count = len(native_hosts)
        findings: list[Finding] = []
        for ext in items_by_collector.get("browser_extensions", []):
            perms = ext.get("permissions") or []
            if "scripting" in perms:
                findings.append(self._make_finding(ext, native_host_count, scan_id))
        return findings

    def _make_finding(
        self,
        ext: dict[str, Any],
        native_host_count: int,
        scan_id: str,
    ) -> Finding:
        evidence = _ext_evidence(ext) + [
            EvidenceItem(
                type=EvidenceType.METADATA,
                value=str(native_host_count),
                label="native messaging hosts count",
            ),
        ]
        return Finding(
            id=_EXT004_ID,
            instance_id=uuid4(),
            rule_version=_EXT004_VERSION,
            title=_EXT004_TITLE,
            severity=Severity.HIGH,
            confidence=Confidence.MEDIUM,
            app=ext.get("name"),
            category="Browser Extension",
            official_explanation=_EXT004_OFFICIAL_EXPLANATION,
            in_other_words=_EXT004_IN_OTHER_WORDS,
            why_this_matters=_EXT004_WHY_IT_MATTERS,
            evidence=evidence,
            recommended_action=_EXT004_RECOMMENDED_ACTION,
            safe_to_ignore_when=_EXT004_SAFE_TO_IGNORE_WHEN,
            false_positive_risk=_EXT004_FP_RISK,
            requires_admin_to_verify=False,
            created_at=datetime.now(timezone.utc),
            scan_id=scan_id,
        )


__all__ = [
    "ExtAllUrlsRule",
    "ExtCookiesRule",
    "ExtScriptingWebRequestRule",
    "ExtBridgeCapabilityRule",
    "_EXT001_ID",
    "_EXT001_VERSION",
    "_EXT002_ID",
    "_EXT002_VERSION",
    "_EXT003_ID",
    "_EXT003_VERSION",
    "_EXT004_ID",
    "_EXT004_VERSION",
]
