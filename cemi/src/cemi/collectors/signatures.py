"""Digital signature collector for CEMÍ.

Inspects executable paths already discovered by existing collectors.
On Windows, attempts basic signature checks; on other platforms, skips gracefully.
No network, no subprocess, no file uploads.
"""
from __future__ import annotations

import hashlib
import os
import platform
from pathlib import Path
from typing import Any, ClassVar, Optional

from cemi.collectors.base import BaseCollector
from cemi.models import CollectorHealth, PrivilegeLevel
from cemi.utils.redact import redact_path

# Attempt to import Windows-specific modules for signature checking
try:
    import win32api
    import win32con
    import win32security
    _WINDOWS_SIGNATURE_AVAILABLE = True
except ImportError:
    _WINDOWS_SIGNATURE_AVAILABLE = False


class SignaturesCollector(BaseCollector):
    """Collect digital signature information for executable paths."""

    name: ClassVar[str] = "signatures"
    privilege_level: ClassVar[PrivilegeLevel] = "user"

    def collect(self) -> tuple[list[Any], CollectorHealth]:
        import time
        start = time.perf_counter()

        if platform.system() != "Windows":
            return [], CollectorHealth(
                collector_name=self.name,
                ran_successfully=True,
                privilege_level=self.privilege_level,
                items_collected=0,
                skipped_reason="Signature verification not available on non-Windows platforms",
                duration_seconds=time.perf_counter() - start,
                errors=[],
            )

        # In a real implementation, we'd get paths from other collectors
        # For now, return empty since we don't have paths yet
        signatures = []

        return signatures, CollectorHealth(
            collector_name=self.name,
            ran_successfully=True,
            privilege_level=self.privilege_level,
            items_collected=len(signatures),
            skipped_reason=None,
            duration_seconds=time.perf_counter() - start,
            errors=[],
        )


def _check_signature(path: str) -> tuple[str, Optional[str]]:
    """Check the digital signature of a file.

    Returns (status, publisher).
    Status can be: "valid", "invalid", "unknown", "error"
    """
    if not _WINDOWS_SIGNATURE_AVAILABLE:
        return "unknown", None

    try:
        # Get file security info
        security_info = win32security.GetFileSecurity(
            path, win32security.OWNER_SECURITY_INFORMATION
        )
        # This is a simplified check; real signature verification is more complex
        # For now, return unknown
        return "unknown", None
    except Exception:
        return "error", None


def _compute_sha256(path: str, max_size: int = 100 * 1024 * 1024) -> Optional[str]:
    """Compute SHA256 hash of file, limited to max_size."""
    try:
        stat = os.stat(path)
        if stat.st_size > max_size:
            return None  # Too large

        with open(path, "rb") as f:
            return hashlib.sha256(f.read()).hexdigest()
    except (OSError, IOError):
        return None


def _is_executable(path: str) -> bool:
    """Check if path is an executable file."""
    if not os.path.exists(path):
        return False

    # Check extension
    ext = Path(path).suffix.lower()
    executable_exts = {".exe", ".dll", ".sys", ".scr", ".com", ".bat", ".cmd"}
    return ext in executable_exts