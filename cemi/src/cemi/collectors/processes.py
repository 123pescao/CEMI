"""Processes collector for CEMÍ.

Collects running process information using psutil on Windows.
Focuses on basic metadata without invasive inspection.

No memory access, no file reading, no network capture.
Handles permission errors gracefully.
"""
from __future__ import annotations

import sys
from typing import Any, ClassVar, Optional

from cemi.collectors.base import BaseCollector
from cemi.models import CollectorHealth, PrivilegeLevel
from cemi.utils.redact import redact_path, redact_string, REDACTED

# Platform gate — patchable in tests.
try:
    import psutil
    _PSUTIL_AVAILABLE = True
except ImportError:
    _PSUTIL_AVAILABLE = False

_IS_WINDOWS = sys.platform == "win32"


def _redact_err(msg: str) -> str:
    return redact_string(redact_path(msg))


def _redact_username(username: str) -> str:
    """Redact username to prevent privacy leaks."""
    return REDACTED if username else ""


class ProcessesCollector(BaseCollector):
    """Collect basic process information from running system."""

    name: ClassVar[str] = "processes"
    privilege_level: ClassVar[PrivilegeLevel] = "user"

    def collect(self) -> tuple[list[Any], CollectorHealth]:
        if not _IS_WINDOWS:
            return [], CollectorHealth(
                collector_name=self.name,
                ran_successfully=True,
                privilege_level=self.privilege_level,
                items_collected=0,
                skipped_reason="Processes collection is Windows-only in this version",
                duration_seconds=0.0,
                errors=[],
            )

        if not _PSUTIL_AVAILABLE:
            return [], CollectorHealth(
                collector_name=self.name,
                ran_successfully=False,
                privilege_level=self.privilege_level,
                items_collected=0,
                skipped_reason="psutil library not available",
                duration_seconds=0.0,
                errors=["psutil import failed"],
            )

        import time
        start = time.perf_counter()

        processes: list[dict[str, Any]] = []
        errors: list[str] = []
        had_access_denied = False

        try:
            for proc in psutil.process_iter(attrs=['pid', 'name', 'exe', 'cpu_percent', 'memory_percent', 'username']):
                try:
                    info = proc.info
                    exe_path = info.get('exe')
                    username = info.get('username')

                    process_data = {
                        "pid": info.get('pid'),
                        "name": info.get('name'),
                        "exe_path": redact_path(exe_path) if exe_path else None,
                        "cpu_percent": info.get('cpu_percent'),
                        "memory_percent": info.get('memory_percent'),
                        "username": _redact_username(username) if username else None,
                    }
                    processes.append(process_data)
                except psutil.AccessDenied:
                    had_access_denied = True
                    continue
                except (OSError, PermissionError):
                    had_access_denied = True
                    continue
                except Exception as exc:
                    errors.append(_redact_err(f"Error collecting process {proc.pid}: {exc}"))
                    continue
        except Exception as exc:
            errors.append(_redact_err(f"Error iterating processes: {exc}"))

        privilege: PrivilegeLevel = "partial" if had_access_denied else "user"

        return processes, CollectorHealth(
            collector_name=self.name,
            ran_successfully=True,
            privilege_level=privilege,
            items_collected=len(processes),
            skipped_reason=None,
            duration_seconds=time.perf_counter() - start,
            errors=errors,
        )


__all__ = ["ProcessesCollector"]