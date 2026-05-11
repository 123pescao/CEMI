"""Tests for scheduled tasks collector."""
from __future__ import annotations

import inspect
import platform

import pytest

from cemi.collectors import scheduled_tasks as scheduled_tasks_module
from cemi.collectors.scheduled_tasks import ScheduledTasksCollector


class TestScheduledTasksCollector:
    def test_name(self) -> None:
        collector = ScheduledTasksCollector()
        assert collector.name == "scheduled_tasks"

    def test_privilege_level(self) -> None:
        collector = ScheduledTasksCollector()
        assert collector.privilege_level == "admin"

    def test_collect(self) -> None:
        collector = ScheduledTasksCollector()
        items, health = collector.collect()

        assert items == []
        assert health.collector_name == "scheduled_tasks"
        assert health.ran_successfully is True
        assert health.items_collected == 0
        assert "only available" in health.skipped_reason

    def test_subprocess_is_not_used(self) -> None:
        source = inspect.getsource(scheduled_tasks_module)
        assert "import subprocess" not in source

    def test_pywin32_unavailable_skips(self) -> None:
        if platform.system() == "Windows":
            pytest.skip("This test is only meaningful on non-Windows environments")

        collector = ScheduledTasksCollector()
        items, health = collector.collect()

        assert items == []
        assert health.ran_successfully is True
        assert health.items_collected == 0
        assert "pywin32" in health.skipped_reason.lower()
