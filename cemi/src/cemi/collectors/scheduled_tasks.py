"""Scheduled tasks collector for CEMÍ.

This collector uses optional pywin32 COM support to enumerate scheduled task metadata
on Windows. It never executes tasks, never invokes subprocesses, and only returns
redacted task metadata.
"""
from __future__ import annotations

import os
from typing import Any, ClassVar

from cemi.collectors.base import BaseCollector
from cemi.models import CollectorHealth, PrivilegeLevel
from cemi.utils.redact import redact_path, redact_string

try:
    import win32com.client  # type: ignore[import]
    _PYWIN32_AVAILABLE = True
except ImportError:
    win32com = None  # type: ignore[assignment]
    _PYWIN32_AVAILABLE = False


def _redact_task_value(value: str) -> str:
    if not value:
        return ""
    return redact_string(redact_path(value))


class ScheduledTasksCollector(BaseCollector):
    """Collect scheduled tasks using optional Windows COM support."""

    name: ClassVar[str] = "scheduled_tasks"
    privilege_level: ClassVar[PrivilegeLevel] = "admin"

    def collect(self) -> tuple[list[Any], CollectorHealth]:
        import time
        start = time.perf_counter()

        if os.name != "nt" or not _PYWIN32_AVAILABLE:
            skipped_reason = (
                "Windows scheduled task collection is only available when pywin32 is installed "
                "and running on Windows"
            )
            return [], CollectorHealth(
                collector_name=self.name,
                ran_successfully=True,
                privilege_level=self.privilege_level,
                items_collected=0,
                skipped_reason=skipped_reason,
                duration_seconds=time.perf_counter() - start,
                errors=[],
            )

        items: list[dict[str, Any]] = []
        errors: list[str] = []

        try:
            items = self._collect_scheduled_tasks(errors)
        except Exception as exc:
            errors.append(f"Scheduled tasks inspection failed: {exc}")

        return items, CollectorHealth(
            collector_name=self.name,
            ran_successfully=True,
            privilege_level=self.privilege_level,
            items_collected=len(items),
            skipped_reason=None,
            duration_seconds=time.perf_counter() - start,
            errors=errors,
        )

    def _collect_scheduled_tasks(self, errors: list[str]) -> list[dict[str, Any]]:
        items: list[dict[str, Any]] = []

        try:
            scheduler = win32com.client.Dispatch("Schedule.Service")
            scheduler.Connect()
            root_folder = scheduler.GetFolder("\\")
            self._walk_folder(root_folder, items)
        except Exception as exc:
            errors.append(f"Scheduled task COM enumeration failed: {exc}")

        return items

    def _walk_folder(self, folder: Any, items: list[dict[str, Any]]) -> None:
        tasks = getattr(folder, "GetTasks", lambda flags: [])(0)
        task_count = getattr(tasks, "Count", 0)
        for idx in range(1, int(task_count) + 1):
            try:
                task = tasks.Item(idx)
                self._collect_task(task, items)
            except Exception:
                continue

        subfolders = getattr(folder, "GetFolders", lambda flags: [])(0)
        folder_count = getattr(subfolders, "Count", 0)
        for idx in range(1, int(folder_count) + 1):
            try:
                subfolder = subfolders.Item(idx)
                self._walk_folder(subfolder, items)
            except Exception:
                continue

    def _collect_task(self, task: Any, items: list[dict[str, Any]]) -> None:
        try:
            definition = task.Definition
            actions = getattr(definition, "Actions", None)
            trigger_count = int(getattr(getattr(definition, "Triggers", None), "Count", 0) or 0)
            principal = getattr(definition, "Principal", None)
            principal_user = getattr(principal, "UserId", "") if principal is not None else ""
            scope = "system" if not principal_user or str(principal_user).lower() == "system" else "user"
            task_name = getattr(task, "Name", "[unknown]")
            task_path = _redact_task_value(str(getattr(task, "Path", task_name) or task_name))
            enabled = bool(getattr(task, "Enabled", False))

            if actions is None:
                items.append({
                    "task_name": task_name,
                    "task_path": task_path,
                    "enabled": enabled,
                    "action_command_redacted": "",
                    "action_arguments_redacted": "",
                    "trigger_count": trigger_count,
                    "scope": scope,
                })
                return

            action_count = int(getattr(actions, "Count", 0) or 0)
            for action_index in range(1, action_count + 1):
                try:
                    action = actions.Item(action_index)
                    action_path = _redact_task_value(str(getattr(action, "Path", "") or ""))
                    action_args = redact_string(str(getattr(action, "Arguments", "") or ""))
                    items.append({
                        "task_name": task_name,
                        "task_path": task_path,
                        "enabled": enabled,
                        "action_command_redacted": action_path,
                        "action_arguments_redacted": action_args,
                        "trigger_count": trigger_count,
                        "scope": scope,
                    })
                except Exception:
                    continue
        except Exception:
            pass
