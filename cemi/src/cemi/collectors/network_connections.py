"""Network connections collector for CEMÍ.

Collects active network connections using psutil.
No packet capture, no payload inspection, no DNS lookups, no network requests.
Only connection metadata.
"""
from __future__ import annotations

import sys
from typing import Any, ClassVar, Optional

from cemi.collectors.base import BaseCollector
from cemi.models import CollectorHealth, PrivilegeLevel
from cemi.utils.redact import redact_path

_IS_WINDOWS = sys.platform == "win32"

try:
    import psutil
    _PSUTIL_AVAILABLE = True
except ImportError:
    _PSUTIL_AVAILABLE = False


class NetworkConnectionsCollector(BaseCollector):
    """Collect active network connections from running processes."""

    name: ClassVar[str] = "network_connections"
    privilege_level: ClassVar[PrivilegeLevel] = "user"

    def collect(self) -> tuple[list[Any], CollectorHealth]:
        if not _PSUTIL_AVAILABLE:
            return [], CollectorHealth(
                collector_name=self.name,
                ran_successfully=False,
                privilege_level=self.privilege_level,
                items_collected=0,
                skipped_reason="psutil library not available",
                duration_seconds=0.0,
                errors=[],
            )

        import time
        start = time.perf_counter()

        connections: list[dict[str, Any]] = []
        errors: list[str] = []
        had_access_denied = False

        try:
            for conn in psutil.net_connections(kind="inet"):
                try:
                    conn_data = {
                        "pid": conn.pid,
                        "process_name": None,
                        "local_address": conn.laddr.ip if conn.laddr else None,
                        "local_port": conn.laddr.port if conn.laddr else None,
                        "remote_address": conn.raddr.ip if conn.raddr else None,
                        "remote_port": conn.raddr.port if conn.raddr else None,
                        "status": conn.status,
                        "exe_path": None,
                        "exe_path_redacted": None,
                    }

                    if conn.pid:
                        try:
                            proc = psutil.Process(conn.pid)
                            conn_data["process_name"] = proc.name()
                            exe = proc.exe()
                            if exe:
                                conn_data["exe_path"] = exe
                                conn_data["exe_path_redacted"] = redact_path(exe)
                        except Exception as exc:
                            error_text = str(exc).lower()
                            if "access" in error_text or "permission" in error_text:
                                had_access_denied = True
                            # Keep the connection metadata even when process details are unavailable.

                    connections.append(conn_data)
                except Exception as exc:
                    errors.append(f"Error collecting connection: {exc}")
                    continue
        except Exception as exc:
            errors.append(f"Error iterating connections: {exc}")

        privilege: PrivilegeLevel = "partial" if had_access_denied else "user"

        return connections, CollectorHealth(
            collector_name=self.name,
            ran_successfully=True,
            privilege_level=privilege,
            items_collected=len(connections),
            skipped_reason=None,
            duration_seconds=time.perf_counter() - start,
            errors=errors,
        )


__all__ = ["NetworkConnectionsCollector"]
