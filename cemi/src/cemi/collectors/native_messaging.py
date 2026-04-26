"""Native Messaging Hosts collector for Chromium-based browsers.

Reads native messaging host manifest JSON files from known configuration
directories for Chrome, Edge, Brave, and Chromium on Windows.

On non-Windows platforms the collector skips gracefully.

No subprocess, no network, no browser history, no cookies, no binary execution.
Only .json manifest files inside the known NativeMessagingHosts directories are
read; the collector never follows unknown directories.
"""
from __future__ import annotations

import json
import os
import sys
import time
from typing import Any, ClassVar, Optional

from CEMI.cemi.src.cemi.collectors.base import BaseCollector
from CEMI.cemi.src.cemi.models import CollectorHealth, PrivilegeLevel
from CEMI.cemi.src.cemi.utils.redact import redact_path, redact_string

# Platform gate — patchable in tests.
_IS_WINDOWS: bool = sys.platform == "win32"


def _redact_err(msg: str) -> str:
    return redact_string(redact_path(msg))


# ---------------------------------------------------------------------------
# Directory catalogue
# ---------------------------------------------------------------------------

# (browser_label, scope, relative_path_parts_from_base_env_var)
_USER_BROWSERS: list[tuple[str, list[str]]] = [
    ("Chrome",   ["Google", "Chrome", "User Data", "NativeMessagingHosts"]),
    ("Edge",     ["Microsoft", "Edge", "User Data", "NativeMessagingHosts"]),
    ("Brave",    ["BraveSoftware", "Brave-Browser", "User Data", "NativeMessagingHosts"]),
    ("Chromium", ["Chromium", "User Data", "NativeMessagingHosts"]),
]

_SYSTEM_BROWSERS: list[tuple[str, list[str]]] = [
    ("Chrome", ["Google", "Chrome", "Application", "NativeMessagingHosts"]),
    ("Edge",   ["Microsoft", "Edge", "Application", "NativeMessagingHosts"]),
    ("Brave",  ["BraveSoftware", "Brave-Browser", "Application", "NativeMessagingHosts"]),
]


def _candidate_dirs() -> list[tuple[str, str, str]]:
    """Return (browser, scope, absolute_path) for every candidate directory.

    Resolves paths from environment variables at call time so that tests can
    patch ``os.environ`` to point at a temporary directory.
    """
    candidates: list[tuple[str, str, str]] = []

    local_app_data = os.environ.get("LOCALAPPDATA", "")
    if local_app_data:
        for browser, parts in _USER_BROWSERS:
            candidates.append((browser, "user", os.path.join(local_app_data, *parts)))

    for env_var in ("PROGRAMFILES", "PROGRAMFILES(X86)"):
        base = os.environ.get(env_var, "")
        if base:
            for browser, parts in _SYSTEM_BROWSERS:
                candidates.append((browser, "system", os.path.join(base, *parts)))

    return candidates


# ---------------------------------------------------------------------------
# Manifest reading
# ---------------------------------------------------------------------------


def _read_manifest(
    manifest_path: str,
    browser: str,
    scope: str,
    errors: list[str],
) -> Optional[dict[str, Any]]:
    """Parse one manifest file and return the structured host dict, or None."""
    redacted_mp = redact_path(manifest_path)
    try:
        with open(manifest_path, encoding="utf-8") as fh:
            data = json.load(fh)
    except json.JSONDecodeError as exc:
        errors.append(_redact_err(f"Invalid JSON in {redacted_mp}: {exc}"))
        return None
    except OSError as exc:
        errors.append(_redact_err(f"Cannot read {redacted_mp}: {exc}"))
        return None

    raw_binary = data.get("path")
    allowed: Any = data.get("allowed_origins")

    return {
        "browser": browser,
        "scope": scope,
        "name": data.get("name"),
        "description": data.get("description"),
        "manifest_path": redacted_mp,
        "binary_path": redact_path(raw_binary) if raw_binary else None,
        "type": data.get("type"),
        "allowed_origins": list(allowed) if isinstance(allowed, list) else [],
    }


# ---------------------------------------------------------------------------
# Directory scanning
# ---------------------------------------------------------------------------


def _scan_directory(
    directory: str,
    browser: str,
    scope: str,
    hosts: list[dict[str, Any]],
    errors: list[str],
) -> bool:
    """Scan one NativeMessagingHosts directory for .json manifests.

    Returns True when a PermissionError is raised (caller decides whether
    to escalate the privilege level).  Missing directories are silently
    skipped (returns False).
    """
    try:
        scan_iter = os.scandir(directory)
    except FileNotFoundError:
        return False
    except PermissionError:
        return True
    except OSError as exc:
        errors.append(_redact_err(f"Cannot scan {redact_path(directory)}: {exc}"))
        return False

    with scan_iter:
        for entry in scan_iter:
            if not entry.name.lower().endswith(".json"):
                continue
            try:
                if not entry.is_file():
                    continue
            except OSError:
                continue
            host = _read_manifest(entry.path, browser, scope, errors)
            if host is not None:
                hosts.append(host)

    return False


# ---------------------------------------------------------------------------
# Collector
# ---------------------------------------------------------------------------


class NativeMessagingHostsCollector(BaseCollector):
    """Collect native messaging host manifests for Chromium-based browsers."""

    name: ClassVar[str] = "native_messaging_hosts"
    privilege_level: ClassVar[PrivilegeLevel] = "user"

    def collect(self) -> tuple[list[Any], CollectorHealth]:
        start = time.perf_counter()

        if not _IS_WINDOWS:
            return [], CollectorHealth(
                collector_name=self.name,
                ran_successfully=True,
                privilege_level=self.privilege_level,
                items_collected=0,
                skipped_reason="Native messaging host directories are Windows-only in this version",
                duration_seconds=time.perf_counter() - start,
                errors=[],
            )

        hosts: list[dict[str, Any]] = []
        errors: list[str] = []
        had_permission_error = False

        for browser, scope, directory in _candidate_dirs():
            perm_err = _scan_directory(directory, browser, scope, hosts, errors)
            if perm_err and scope == "system":
                had_permission_error = True

        privilege: PrivilegeLevel = "partial" if had_permission_error else "user"

        return hosts, CollectorHealth(
            collector_name=self.name,
            ran_successfully=True,
            privilege_level=privilege,
            items_collected=len(hosts),
            skipped_reason=None,
            duration_seconds=time.perf_counter() - start,
            errors=errors,
        )


__all__ = ["NativeMessagingHostsCollector"]
