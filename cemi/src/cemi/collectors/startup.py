"""Startup entries collector for CEMÍ.

Collects Windows startup entries from registry and startup folders.
On non-Windows platforms, skips gracefully.
No subprocess, no network, no personal files.
"""
from __future__ import annotations

import os
from pathlib import Path
from typing import Any, ClassVar, Optional

from cemi.collectors.base import BaseCollector
from cemi.models import CollectorHealth, PrivilegeLevel
from cemi.utils.redact import redact_path

try:
    import winreg as _winreg  # type: ignore[import]
    _WINREG_AVAILABLE = True
except ImportError:
    _winreg = None  # type: ignore[assignment]
    _WINREG_AVAILABLE = False

_RUN_KEY = r"Software\Microsoft\Windows\CurrentVersion\Run"


def _redact_cmd(cmd: str) -> str:
    """Redact paths in command strings."""
    return redact_path(cmd)


class StartupCollector(BaseCollector):
    """Collect startup entries from Windows registry and folders."""

    name: ClassVar[str] = "startup"
    privilege_level: ClassVar[PrivilegeLevel] = "partial"  # May need admin for system registry

    def collect(self) -> tuple[list[Any], CollectorHealth]:
        import time
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

        entries: list[dict[str, Any]] = []
        errors: list[str] = []

        # Collect from registry
        self._collect_from_registry(entries, errors)

        # Collect from startup folders
        self._collect_from_folders(entries, errors)

        # Determine privilege level
        privilege = "user"
        if any(e.get("scope") == "system" for e in entries):
            privilege = "partial"

        return entries, CollectorHealth(
            collector_name=self.name,
            ran_successfully=True,
            privilege_level=privilege,
            items_collected=len(entries),
            skipped_reason=None,
            duration_seconds=time.perf_counter() - start,
            errors=errors,
        )

    def _collect_from_registry(self, entries: list[dict[str, Any]], errors: list[str]) -> None:
        """Collect startup entries from registry."""
        hives = [
            (_winreg.HKEY_CURRENT_USER, _RUN_KEY, "user"),
            (_winreg.HKEY_LOCAL_MACHINE, _RUN_KEY, "system"),
        ]

        for hive, subkey, scope in hives:
            try:
                with _winreg.OpenKey(hive, subkey) as key:
                    self._read_run_key(key, scope, entries)
            except OSError as exc:
                if scope == "system":
                    errors.append(f"Cannot access system registry: {exc}")
                else:
                    errors.append(f"Cannot access user registry: {exc}")

    def _read_run_key(self, key: Any, scope: str, entries: list[dict[str, Any]]) -> None:
        """Read values from a Run key."""
        idx = 0
        while True:
            try:
                name, command, _ = _winreg.EnumValue(key, idx)
                path_redacted = _extract_path_from_command(command)
                entries.append({
                    "name": name,
                    "source": "registry",
                    "command": _redact_cmd(command),
                    "path_redacted": path_redacted,
                    "scope": scope,
                })
                idx += 1
            except OSError:
                break

    def _collect_from_folders(self, entries: list[dict[str, Any]], errors: list[str]) -> None:
        """Collect startup entries from startup folders."""
        from pathlib import Path

        # User startup folder
        user_startup = Path(os.environ.get("APPDATA", "")) / "Microsoft" / "Windows" / "Start Menu" / "Programs" / "Startup"
        self._read_startup_folder(user_startup, "user", entries, errors)

        # Common startup folder (system)
        common_startup = Path(os.environ.get("ALLUSERSPROFILE", "")) / "Microsoft" / "Windows" / "Start Menu" / "Programs" / "Startup"
        self._read_startup_folder(common_startup, "system", entries, errors)

    def _read_startup_folder(self, folder: Path, scope: str, entries: list[dict[str, Any]], errors: list[str]) -> None:
        """Read .lnk and .exe files from startup folder."""
        if not folder.exists():
            if scope == "system":
                errors.append(f"System startup folder not accessible: {folder}")
            return

        try:
            for item in folder.iterdir():
                if item.suffix.lower() in (".lnk", ".exe"):
                    # For .lnk, we'd need to resolve the target, but to avoid subprocess, just record the path
                    command = str(item)
                    path_redacted = redact_path(command)
                    entries.append({
                        "name": item.stem,
                        "source": "folder",
                        "command": _redact_cmd(command),
                        "path_redacted": path_redacted,
                        "scope": scope,
                    })
        except OSError as exc:
            errors.append(f"Cannot read startup folder {folder}: {exc}")


def _extract_path_from_command(command: str) -> Optional[str]:
    """Extract the executable path from a command string."""
    command = command.strip()
    if command.startswith('"'):
        end = command.find('"', 1)
        if end > 0:
            return redact_path(command[1:end])
    else:
        space = command.find(' ')
        if space > 0:
            return redact_path(command[:space])
        else:
            return redact_path(command)
    return None