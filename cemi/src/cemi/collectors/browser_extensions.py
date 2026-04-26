"""Browser Extensions collector for Chromium-based browsers.

Reads extension manifest.json files from the known Extensions directories
for Chrome, Edge, and Brave on Windows.

On non-Windows platforms the collector skips gracefully.

No subprocess, no network, no browser history, no cookies, no profile data.
Only manifest.json files inside known extension directories are read; the
collector descends exactly two levels (extension_id / version) and no further.
"""
from __future__ import annotations

import json
import os
import sys
import time
from typing import Any, ClassVar, Optional

from cemi.collectors.base import BaseCollector
from cemi.models import CollectorHealth, PrivilegeLevel
from cemi.utils.redact import redact_path, redact_string

# Platform gate — patchable in tests.
_IS_WINDOWS: bool = sys.platform == "win32"


def _redact_err(msg: str) -> str:
    return redact_string(redact_path(msg))


# ---------------------------------------------------------------------------
# Directory catalogue
# ---------------------------------------------------------------------------

_USER_BROWSERS: list[tuple[str, list[str]]] = [
    ("Chrome", ["Google", "Chrome", "User Data", "Default", "Extensions"]),
    ("Edge",   ["Microsoft", "Edge", "User Data", "Default", "Extensions"]),
    ("Brave",  ["BraveSoftware", "Brave-Browser", "User Data", "Default", "Extensions"]),
]


def _candidate_dirs() -> list[tuple[str, str]]:
    """Return (browser, absolute_path) for each candidate extensions directory.

    Resolved from environment variables at call time so tests can patch
    ``os.environ`` to point at a temporary directory.
    """
    candidates: list[tuple[str, str]] = []
    local_app_data = os.environ.get("LOCALAPPDATA", "")
    if local_app_data:
        for browser, parts in _USER_BROWSERS:
            candidates.append((browser, os.path.join(local_app_data, *parts)))
    return candidates


# ---------------------------------------------------------------------------
# Manifest reading
# ---------------------------------------------------------------------------


def _read_extension_manifest(
    manifest_path: str,
    browser: str,
    extension_id: str,
    errors: list[str],
) -> Optional[dict[str, Any]]:
    """Parse one manifest.json and return the structured extension dict, or None."""
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

    if not isinstance(data, dict):
        errors.append(_redact_err(f"Unexpected manifest format in {redacted_mp}"))
        return None

    raw_perms = data.get("permissions", [])
    raw_host = data.get("host_permissions", [])
    permissions = [str(p) for p in raw_perms if isinstance(p, str)] if isinstance(raw_perms, list) else []
    host_permissions = [str(p) for p in raw_host if isinstance(p, str)] if isinstance(raw_host, list) else []

    raw_name = data.get("name")
    raw_version = data.get("version", "")

    return {
        "browser": browser,
        "extension_id": extension_id,
        "name": str(raw_name) if isinstance(raw_name, str) else None,
        "version": str(raw_version) if raw_version else "",
        "manifest_path": redacted_mp,
        "permissions": permissions,
        "host_permissions": host_permissions,
    }


# ---------------------------------------------------------------------------
# Directory scanning
# ---------------------------------------------------------------------------


def _scan_extensions_dir(
    directory: str,
    browser: str,
    extensions: list[dict[str, Any]],
    errors: list[str],
) -> bool:
    """Scan one Extensions directory for extension manifests.

    Descends exactly two levels: ``<extension_id>/<version>/manifest.json``.
    Returns True when a PermissionError is raised at the top level.
    Missing directories are silently skipped (returns False).
    """
    try:
        id_iter = os.scandir(directory)
    except FileNotFoundError:
        return False
    except PermissionError:
        return True
    except OSError as exc:
        errors.append(_redact_err(f"Cannot scan {redact_path(directory)}: {exc}"))
        return False

    with id_iter:
        for id_entry in id_iter:
            try:
                if not id_entry.is_dir():
                    continue
            except OSError:
                continue

            extension_id = id_entry.name

            try:
                ver_iter = os.scandir(id_entry.path)
            except (PermissionError, OSError) as exc:
                if not isinstance(exc, PermissionError):
                    errors.append(_redact_err(f"Cannot scan extension {extension_id}: {exc}"))
                continue

            with ver_iter:
                for ver_entry in ver_iter:
                    try:
                        if not ver_entry.is_dir():
                            continue
                    except OSError:
                        continue

                    manifest_path = os.path.join(ver_entry.path, "manifest.json")
                    if not os.path.isfile(manifest_path):
                        continue

                    ext = _read_extension_manifest(manifest_path, browser, extension_id, errors)
                    if ext is not None:
                        extensions.append(ext)

    return False


# ---------------------------------------------------------------------------
# Collector
# ---------------------------------------------------------------------------


class BrowserExtensionsCollector(BaseCollector):
    """Collect browser extension metadata for Chromium-based browsers."""

    name: ClassVar[str] = "browser_extensions"
    privilege_level: ClassVar[PrivilegeLevel] = "user"

    def collect(self) -> tuple[list[Any], CollectorHealth]:
        start = time.perf_counter()

        if not _IS_WINDOWS:
            return [], CollectorHealth(
                collector_name=self.name,
                ran_successfully=True,
                privilege_level=self.privilege_level,
                items_collected=0,
                skipped_reason="Browser extension directories are Windows-only in this version",
                duration_seconds=time.perf_counter() - start,
                errors=[],
            )

        extensions: list[dict[str, Any]] = []
        errors: list[str] = []
        had_permission_error = False

        for browser, directory in _candidate_dirs():
            perm_err = _scan_extensions_dir(directory, browser, extensions, errors)
            if perm_err:
                had_permission_error = True

        privilege: PrivilegeLevel = "partial" if had_permission_error else "user"

        return extensions, CollectorHealth(
            collector_name=self.name,
            ran_successfully=True,
            privilege_level=privilege,
            items_collected=len(extensions),
            skipped_reason=None,
            duration_seconds=time.perf_counter() - start,
            errors=errors,
        )


__all__ = ["BrowserExtensionsCollector"]
