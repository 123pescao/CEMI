"""Scheduled tasks collector for CEMÍ.

Scheduled task collection requires pywin32 or subprocess, which are not safe without justification.
This collector skips gracefully.
"""
from __future__ import annotations

from typing import Any, ClassVar

from cemi.collectors.base import BaseCollector
from cemi.models import CollectorHealth, PrivilegeLevel


class ScheduledTasksCollector(BaseCollector):
    """Collect scheduled tasks (scaffold only)."""

    name: ClassVar[str] = "scheduled_tasks"
    privilege_level: ClassVar[PrivilegeLevel] = "admin"  # Would need admin

    def collect(self) -> tuple[list[Any], CollectorHealth]:
        import time
        start = time.perf_counter()

        return [], CollectorHealth(
            collector_name=self.name,
            ran_successfully=True,
            privilege_level=self.privilege_level,
            items_collected=0,
            skipped_reason="Scheduled task collection requires pywin32 or subprocess, not implemented safely yet",
            duration_seconds=time.perf_counter() - start,
            errors=[],
        )