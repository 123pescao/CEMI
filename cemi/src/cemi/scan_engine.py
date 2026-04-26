"""Scan orchestration for CEMÍ.

:class:`ScanEngine` accepts a list of collectors, runs them in sequence,
passes the raw items to the rule engine for finding generation, then
assembles the results into a :class:`~cemi.models.ScanResult`.

Privacy invariants:
* Raw collected items live only as a local variable inside :meth:`ScanEngine.run_scan`.
  They are passed to the rule engine and then explicitly deleted — they never
  reach :class:`~cemi.models.ScanResult`.
* :class:`~cemi.models.ScanResult` holds only counts, health metadata,
  and findings whose evidence values are already redacted.
* The hostname is SHA-256 hashed before storage; the raw value is never
  written anywhere.
* No network I/O, no subprocess, no file writes.
"""
from __future__ import annotations

import hashlib
import socket
from datetime import datetime, timezone
from typing import Any
from uuid import uuid4

from cemi.collectors.base import BaseCollector
from cemi.config import SCAN_VERSION
from cemi.models import CollectorHealth, Finding, PrivilegeLevel, ScanResult
from cemi.rules.browser_extension_rules import (
    ExtAllUrlsRule,
    ExtBridgeCapabilityRule,
    ExtCookiesRule,
    ExtScriptingWebRequestRule,
)
from cemi.rules.engine import RuleEngine
from cemi.rules.native_messaging_host import NativeMessagingHostRule
from cemi.rules.service_user_path import ServiceUserPathRule

#: Name used by InstalledAppsCollector to identify itself in health records.
_INSTALLED_APPS_NAME = "installed_apps"


def _build_rule_engine() -> RuleEngine:
    """Return a RuleEngine loaded with all active rules."""
    return RuleEngine([
        ServiceUserPathRule(),
        NativeMessagingHostRule(),
        ExtAllUrlsRule(),
        ExtCookiesRule(),
        ExtScriptingWebRequestRule(),
        ExtBridgeCapabilityRule(),
    ])


def _hash_hostname() -> str:
    """Return the SHA-256 hex digest of the local hostname.

    The raw hostname is never stored or logged — only the digest leaves
    this function.
    """
    raw = socket.gethostname()
    return hashlib.sha256(raw.encode()).hexdigest()


def _effective_privilege(health_list: list[CollectorHealth]) -> PrivilegeLevel:
    """Derive the scan-wide privilege level from individual collector reports.

    Rules (highest-privilege wins):
    * Any collector with ``"admin"``  → ``"admin"``
    * Any collector with ``"partial"`` → ``"partial"``
    * Otherwise                        → ``"user"``
    * Empty list                       → ``"user"``
    """
    levels = {h.privilege_level for h in health_list}
    if "admin" in levels:
        return "admin"
    if "partial" in levels:
        return "partial"
    return "user"


class ScanEngine:
    """Orchestrate a CEMÍ scan: run collectors, evaluate rules, produce ScanResult."""

    def __init__(self, collectors: list[BaseCollector]) -> None:
        self._collectors = collectors

    def run_scan(self) -> ScanResult:
        """Execute all collectors, evaluate rules, and return a ScanResult.

        Raw items returned by each collector are kept in a local variable
        only long enough for the rule engine to inspect them.  They are
        explicitly deleted before the :class:`~cemi.models.ScanResult` is
        constructed — the result carries findings (with redacted evidence)
        and health metadata only.
        """
        scan_id = str(uuid4())
        started_at = datetime.now(timezone.utc)

        health_list: list[CollectorHealth] = []
        items_by_collector: dict[str, list[Any]] = {}
        total_apps_scanned = 0

        for collector in self._collectors:
            items, health = collector.run()
            health_list.append(health)
            items_by_collector[health.collector_name] = items
            if health.collector_name == _INSTALLED_APPS_NAME:
                total_apps_scanned = health.items_collected

        # Evaluate rules against raw items — fail closed if anything goes wrong.
        findings: list[Finding] = []
        try:
            findings = _build_rule_engine().evaluate(items_by_collector, scan_id)
        except Exception:  # noqa: BLE001 — rule failures must not kill the scan
            findings = []

        # Raw items have served their purpose; discard before building ScanResult.
        del items_by_collector

        completed_at = datetime.now(timezone.utc)

        return ScanResult(
            scan_id=scan_id,
            scan_version=SCAN_VERSION,
            started_at=started_at,
            completed_at=completed_at,
            hostname_redacted=_hash_hostname(),
            privilege_level=_effective_privilege(health_list),
            collector_health=health_list,
            findings=findings,
            total_apps_scanned=total_apps_scanned,
        )


__all__ = ["ScanEngine"]
