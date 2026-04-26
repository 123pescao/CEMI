"""Windows services collector using psutil.

Uses ``psutil.win_service_iter()`` (Windows only). On non-Windows platforms,
or when psutil is not installed, the collector skips gracefully.

No subprocess, no direct Windows API calls, no network, no file reads.
"""
from __future__ import annotations

import time
from typing import Any, ClassVar, Optional

from CEMI.cemi.src.cemi.collectors.base import BaseCollector
from CEMI.cemi.src.cemi.models import CollectorHealth, PrivilegeLevel
from CEMI.cemi.src.cemi.utils.redact import redact_path, redact_string

try:
    import psutil as _psutil  # type: ignore[import]
    _PSUTIL_AVAILABLE = True
except ImportError:
    _psutil = None  # type: ignore[assignment]
    _PSUTIL_AVAILABLE = False

# Well-known Windows service/system accounts that are not user-identifiable.
_SYSTEM_ACCOUNTS: frozenset[str] = frozenset({
    "localsystem",
    "local system",
    "localservice",
    "local service",
    "networkservice",
    "network service",
    "nt authority\\system",
    "nt authority\\localservice",
    "nt authority\\networkservice",
    "nt authority\\local service",
    "nt authority\\network service",
})


def _redact_err(msg: str) -> str:
    """Apply both path and token redaction to an error message."""
    return redact_string(redact_path(msg))


def _redact_service_username(username: Optional[str]) -> Optional[str]:
    """Redact user accounts while preserving well-known system accounts.

    * Known system/service accounts (LocalSystem, NT AUTHORITY\\*,
      NT SERVICE\\*) are returned unchanged.
    * Accounts with a domain separator (``DOMAIN\\user`` or ``.\\user``)
      have the user part replaced with ``[REDACTED]``.
    * Any other non-empty value is fully replaced with ``[REDACTED]``.
    """
    if not username:
        return username
    lower = username.lower()
    if lower in _SYSTEM_ACCOUNTS:
        return username
    # NT SERVICE\<svc_name> accounts are also safe (virtual service accounts).
    if lower.startswith("nt service\\"):
        return username
    # Domain or local account: redact the user part after the backslash.
    if "\\" in username:
        domain, _, _ = username.partition("\\")
        return f"{domain}\\[REDACTED]"
    # Bare username with no domain separator.
    return "[REDACTED]"


class ServicesCollector(BaseCollector):
    """Collect Windows service metadata via psutil."""

    name: ClassVar[str] = "services"
    privilege_level: ClassVar[PrivilegeLevel] = "user"

    def collect(self) -> tuple[list[Any], CollectorHealth]:
        start = time.perf_counter()

        if not _PSUTIL_AVAILABLE:
            return [], CollectorHealth(
                collector_name=self.name,
                ran_successfully=True,
                privilege_level=self.privilege_level,
                items_collected=0,
                skipped_reason="psutil not available",
                duration_seconds=time.perf_counter() - start,
                errors=[],
            )

        if not hasattr(_psutil, "win_service_iter"):
            return [], CollectorHealth(
                collector_name=self.name,
                ran_successfully=True,
                privilege_level=self.privilege_level,
                items_collected=0,
                skipped_reason="Windows services not available on this platform",
                duration_seconds=time.perf_counter() - start,
                errors=[],
            )

        services: list[dict[str, Any]] = []
        errors: list[str] = []
        had_access_denied = False

        try:
            for svc in _psutil.win_service_iter():
                try:
                    entry, access_denied = _read_service(svc, errors)
                    if entry is not None:
                        services.append(entry)
                    if access_denied:
                        had_access_denied = True
                except Exception as exc:
                    errors.append(_redact_err(f"Error processing service: {exc}"))
        except Exception as exc:
            errors.append(_redact_err(f"Failed to iterate services: {exc}"))

        privilege: PrivilegeLevel = "partial" if had_access_denied else "user"

        return services, CollectorHealth(
            collector_name=self.name,
            ran_successfully=True,
            privilege_level=privilege,
            items_collected=len(services),
            skipped_reason=None,
            duration_seconds=time.perf_counter() - start,
            errors=errors,
        )


def _read_service(
    svc: Any,
    errors: list[str],
) -> tuple[Optional[dict[str, Any]], bool]:
    """Extract fields from a single psutil WindowsService object.

    Returns ``(service_dict, had_access_denied)``.
    Returns ``(None, ...)`` when the service has no name (entry is skipped).
    """
    access_denied = False

    def _get(method_name: str) -> Optional[str]:
        nonlocal access_denied
        try:
            result = getattr(svc, method_name)()
            return str(result) if result is not None else None
        except _psutil.AccessDenied:
            access_denied = True
            return None
        except _psutil.NoSuchProcess:
            return None
        except Exception as exc:
            errors.append(_redact_err(f"service.{method_name}() failed: {exc}"))
            return None

    name = _get("name")
    if not name:
        return None, access_denied

    binary_path = _get("binpath")
    username = _get("username")

    return {
        "name": name,
        "display_name": _get("display_name"),
        "status": _get("status"),
        "start_type": _get("start_type"),
        "binary_path": redact_path(binary_path) if binary_path else None,
        "username": _redact_service_username(username),
    }, access_denied


__all__ = ["ServicesCollector"]
