"""Installed-applications collector for Windows.

Reads installed-app metadata from the three standard Uninstall registry hives
using ``winreg`` (Windows standard library only). On non-Windows platforms the
collector skips gracefully and reports a ``skipped_reason`` in its health record.

No subprocess, no network, no personal files.
"""
from __future__ import annotations

import time
from typing import Any, ClassVar, Optional

from cemi.collectors.base import BaseCollector
from cemi.models import CollectorHealth, PrivilegeLevel
from cemi.utils.redact import redact_path, redact_string

try:
    import winreg as _winreg  # type: ignore[import]
    _WINREG_AVAILABLE = True
except ImportError:
    _winreg = None  # type: ignore[assignment]
    _WINREG_AVAILABLE = False

_UNINSTALL_SUBKEY = r"Software\Microsoft\Windows\CurrentVersion\Uninstall"
_WOW_SUBKEY = r"Software\WOW6432Node\Microsoft\Windows\CurrentVersion\Uninstall"


def _redact_err(msg: str) -> str:
    """Apply both path and token redaction to an error message."""
    return redact_string(redact_path(msg))


class InstalledAppsCollector(BaseCollector):
    """Collect installed applications from the Windows Registry."""

    name: ClassVar[str] = "installed_apps"
    privilege_level: ClassVar[PrivilegeLevel] = "user"

    def collect(self) -> tuple[list[Any], CollectorHealth]:
        start = time.perf_counter()

        if not _WINREG_AVAILABLE:
            return [], CollectorHealth(
                collector_name=self.name,
                ran_successfully=True,
                privilege_level=self.privilege_level,
                items_collected=0,
                skipped_reason="winreg not available (non-Windows platform)",
                duration_seconds=time.perf_counter() - start,
                errors=[],
            )

        apps: list[dict[str, Any]] = []
        errors: list[str] = []

        hive_keys = [
            (_winreg.HKEY_LOCAL_MACHINE, _UNINSTALL_SUBKEY),
            (_winreg.HKEY_LOCAL_MACHINE, _WOW_SUBKEY),
            (_winreg.HKEY_CURRENT_USER, _UNINSTALL_SUBKEY),
        ]

        for hive, subkey_path in hive_keys:
            try:
                with _winreg.OpenKey(hive, subkey_path) as root_key:
                    _collect_from_key(root_key, apps, errors)
            except OSError as exc:
                errors.append(_redact_err(f"Cannot open {subkey_path!r}: {exc}"))

        return apps, CollectorHealth(
            collector_name=self.name,
            ran_successfully=True,
            privilege_level=self.privilege_level,
            items_collected=len(apps),
            skipped_reason=None,
            duration_seconds=time.perf_counter() - start,
            errors=errors,
        )


def _collect_from_key(
    root_key: Any,
    apps: list[dict[str, Any]],
    errors: list[str],
) -> None:
    """Enumerate subkeys of root_key and append parsed app dicts to apps."""
    idx = 0
    while True:
        try:
            subkey_name = _winreg.EnumKey(root_key, idx)
        except OSError:
            break
        idx += 1
        try:
            with _winreg.OpenKey(root_key, subkey_name) as app_key:
                app = _read_app_key(app_key)
                if app is not None:
                    apps.append(app)
        except OSError as exc:
            errors.append(_redact_err(f"Cannot read {subkey_name!r}: {exc}"))


def _read_app_key(app_key: Any) -> Optional[dict[str, Any]]:
    """Read one app's fields from an open registry key.

    Returns None when no DisplayName is present (entry is skipped).
    """

    def _get(name: str) -> Optional[str]:
        try:
            value, _ = _winreg.QueryValueEx(app_key, name)
            return str(value) if value is not None else None
        except OSError:
            return None

    display_name = _get("DisplayName")
    if not display_name:
        return None

    install_location = _get("InstallLocation")
    uninstall_string = _get("UninstallString")

    return {
        "name": display_name,
        "publisher": _get("Publisher"),
        "version": _get("DisplayVersion"),
        "install_location": redact_path(install_location) if install_location else None,
        "install_date": _get("InstallDate"),
        "uninstall_string": redact_path(uninstall_string) if uninstall_string else None,
    }


__all__ = ["InstalledAppsCollector"]
